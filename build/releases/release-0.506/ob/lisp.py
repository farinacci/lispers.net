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
lisp_default_secondary_iid = 0
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
LISP_IGMP_TTL = 150
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
 if 57 - 57: I1IiiI % I11i - OOooOOo . I1IiiI / Oo0Ooo % iII111i
 if 56 - 56: oO0o . iII111i . IiII * OoOoOO00 . ooOoO0o / O0
def lprint ( * args ) :
 IiI1I1 = ( "force" in args )
 if ( lisp_debug_logging == False and IiI1I1 == False ) : return
 if 45 - 45: OoOoOO00
 lisp_process_logfile ( )
 I11i1II = datetime . datetime . now ( ) . strftime ( "%m/%d/%y %H:%M:%S.%f" )
 I11i1II = I11i1II [ : - 3 ]
 print "{}: {}:" . format ( I11i1II , lisp_log_id ) ,
 if 66 - 66: OoO0O00
 for oOO in args :
  if ( oOO == "force" ) : continue
  print oOO ,
  if 31 - 31: OOooOOo / Oo0Ooo * i1IIi . OoOoOO00
 print ""
 if 57 - 57: OOooOOo + iIii1I11I1II1 % i1IIi % I1IiiI
 try : sys . stdout . flush ( )
 except : pass
 return
 if 83 - 83: o0oOOo0O0Ooo / i11iIiiIii % iIii1I11I1II1 . I11i % oO0o . OoooooooOO
 if 94 - 94: Ii1I + iIii1I11I1II1 % OoO0O00
 if 93 - 93: Ii1I - OOooOOo + iIii1I11I1II1 * o0oOOo0O0Ooo + I1Ii111 . iII111i
 if 49 - 49: OoooooooOO * I11i - Oo0Ooo . oO0o
 if 89 - 89: ooOoO0o + Ii1I * ooOoO0o / ooOoO0o
 if 46 - 46: OoO0O00
 if 71 - 71: I11i / I11i * oO0o * oO0o / II111iiii
 if 35 - 35: OOooOOo * o0oOOo0O0Ooo * I1IiiI % Oo0Ooo . OoOoOO00
def dprint ( * args ) :
 if ( lisp_data_plane_logging ) : lprint ( * args )
 return
 if 58 - 58: I11i + II111iiii * iII111i * i11iIiiIii - iIii1I11I1II1
 if 68 - 68: OoooooooOO % II111iiii
 if 26 - 26: II111iiii % i11iIiiIii % iIii1I11I1II1 % I11i * I11i * I1ii11iIi11i
 if 24 - 24: II111iiii % I1Ii111 - ooOoO0o + I1IiiI * I1ii11iIi11i
 if 2 - 2: Ii1I - IiII
 if 83 - 83: oO0o % o0oOOo0O0Ooo % Ii1I - II111iiii * OOooOOo / OoooooooOO
 if 18 - 18: OoO0O00 + iIii1I11I1II1 - II111iiii - I1IiiI
 if 71 - 71: OoooooooOO
def debug ( * args ) :
 lisp_process_logfile ( )
 if 33 - 33: I1Ii111
 I11i1II = datetime . datetime . now ( ) . strftime ( "%m/%d/%y %H:%M:%S.%f" )
 I11i1II = I11i1II [ : - 3 ]
 if 62 - 62: I1ii11iIi11i + Ii1I + i1IIi / OoooooooOO
 print red ( ">>>" , False ) ,
 print "{}:" . format ( I11i1II ) ,
 for oOO in args : print oOO ,
 print red ( "<<<\n" , False )
 try : sys . stdout . flush ( )
 except : pass
 return
 if 7 - 7: o0oOOo0O0Ooo + i1IIi . I1IiiI / Oo0Ooo
 if 22 - 22: ooOoO0o - ooOoO0o % OOooOOo . I1Ii111 + oO0o
 if 63 - 63: I1IiiI % I1Ii111 * o0oOOo0O0Ooo + I1Ii111 / Oo0Ooo % iII111i
 if 45 - 45: IiII
 if 20 - 20: OoooooooOO * o0oOOo0O0Ooo * O0 . OOooOOo
 if 78 - 78: iIii1I11I1II1 + I11i - Ii1I * I1Ii111 - OoooooooOO % OoOoOO00
 if 34 - 34: O0
def lisp_print_banner ( string ) :
 global lisp_version , lisp_hostname
 if 80 - 80: i1IIi - Oo0Ooo / OoO0O00 - i11iIiiIii
 if ( lisp_version == "" ) :
  lisp_version = commands . getoutput ( "cat lisp-version.txt" )
  if 68 - 68: oO0o - I1ii11iIi11i % O0 % I1Ii111
 Ii1II = bold ( lisp_hostname , False )
 lprint ( "lispers.net LISP {} {}, version {}, hostname {}" . format ( string ,
 datetime . datetime . now ( ) , lisp_version , Ii1II ) )
 return
 if 67 - 67: iIii1I11I1II1 - Ii1I + o0oOOo0O0Ooo
 if 97 - 97: OOooOOo
 if 92 - 92: Oo0Ooo % I1ii11iIi11i * iIii1I11I1II1 - I1ii11iIi11i . o0oOOo0O0Ooo
 if 95 - 95: I1Ii111 % I1IiiI
 if 42 - 42: OoooooooOO - iII111i / OoooooooOO / Ii1I
 if 86 - 86: ooOoO0o * o0oOOo0O0Ooo + O0 / I11i . I1IiiI + iIii1I11I1II1
 if 66 - 66: oO0o
def green ( string , html ) :
 if ( html ) : return ( '<font color="green"><b>{}</b></font>' . format ( string ) )
 return ( bold ( "\033[92m" + string + "\033[0m" , html ) )
 if 91 - 91: oO0o + I1IiiI
 if 59 - 59: I1IiiI + i11iIiiIii + i1IIi / I11i
 if 44 - 44: I11i . OoOoOO00 * I1IiiI + OoooooooOO - iII111i - IiII
 if 15 - 15: IiII / O0 . o0oOOo0O0Ooo . i11iIiiIii
 if 59 - 59: I1Ii111 - o0oOOo0O0Ooo - ooOoO0o
 if 48 - 48: i1IIi + I11i % OoOoOO00 / Oo0Ooo - o0oOOo0O0Ooo
 if 67 - 67: oO0o % o0oOOo0O0Ooo . OoooooooOO + OOooOOo * I11i * OoOoOO00
def green_last_sec ( string ) :
 return ( green ( string , True ) )
 if 36 - 36: O0 + Oo0Ooo
 if 5 - 5: Oo0Ooo * OoOoOO00
 if 46 - 46: ooOoO0o
 if 33 - 33: iII111i - II111iiii * OoooooooOO - Oo0Ooo - OOooOOo
 if 84 - 84: I1Ii111 + Oo0Ooo - OoOoOO00 * OoOoOO00
 if 61 - 61: OoooooooOO . oO0o . OoooooooOO / Oo0Ooo
 if 72 - 72: i1IIi
def green_last_min ( string ) :
 return ( '<font color="#58D68D"><b>{}</b></font>' . format ( string ) )
 if 82 - 82: OoOoOO00 + OoooooooOO / i11iIiiIii * I1ii11iIi11i . OoooooooOO
 if 63 - 63: I1ii11iIi11i
 if 6 - 6: ooOoO0o / I1ii11iIi11i
 if 57 - 57: I11i
 if 67 - 67: OoO0O00 . ooOoO0o
 if 87 - 87: oO0o % Ii1I
 if 83 - 83: II111iiii - I11i
def red ( string , html ) :
 if ( html ) : return ( '<font color="red"><b>{}</b></font>' . format ( string ) )
 return ( bold ( "\033[91m" + string + "\033[0m" , html ) )
 if 35 - 35: i1IIi - iIii1I11I1II1 + i1IIi
 if 86 - 86: iIii1I11I1II1 + OoOoOO00 . i11iIiiIii - Ii1I
 if 51 - 51: OoOoOO00
 if 14 - 14: IiII % oO0o % Oo0Ooo - i11iIiiIii
 if 53 - 53: Ii1I % Oo0Ooo
 if 59 - 59: OOooOOo % iIii1I11I1II1 . i1IIi + II111iiii * IiII
 if 41 - 41: Ii1I % I1ii11iIi11i
def blue ( string , html ) :
 if ( html ) : return ( '<font color="blue"><b>{}</b></font>' . format ( string ) )
 return ( bold ( "\033[94m" + string + "\033[0m" , html ) )
 if 12 - 12: OOooOOo
 if 69 - 69: OoooooooOO + OOooOOo
 if 26 - 26: Oo0Ooo + OOooOOo / OoO0O00 % OoOoOO00 % I1ii11iIi11i + II111iiii
 if 31 - 31: I11i % OOooOOo * I11i
 if 45 - 45: i1IIi . I1IiiI + OOooOOo - OoooooooOO % ooOoO0o
 if 1 - 1: iIii1I11I1II1
 if 93 - 93: i1IIi . i11iIiiIii . Oo0Ooo
def bold ( string , html ) :
 if ( html ) : return ( "<b>{}</b>" . format ( string ) )
 return ( "\033[1m" + string + "\033[0m" )
 if 99 - 99: I11i - I1Ii111 - oO0o % OoO0O00
 if 21 - 21: II111iiii % I1ii11iIi11i . i1IIi - OoooooooOO
 if 4 - 4: OoooooooOO . ooOoO0o
 if 78 - 78: I1ii11iIi11i + I11i - O0
 if 10 - 10: I1Ii111 % I1IiiI
 if 97 - 97: OoooooooOO - I1Ii111
 if 58 - 58: iIii1I11I1II1 + O0
def convert_font ( string ) :
 I111I11I111 = [ [ "[91m" , red ] , [ "[92m" , green ] , [ "[94m" , blue ] , [ "[1m" , bold ] ]
 iiiiI11ii = "[0m"
 if 96 - 96: iII111i . O0 / iII111i % O0
 for o0o000 in I111I11I111 :
  i1iiiIii11 = o0o000 [ 0 ]
  OOoOOO000O0 = o0o000 [ 1 ]
  oOo0 = len ( i1iiiIii11 )
  ii = string . find ( i1iiiIii11 )
  if ( ii != - 1 ) : break
  if 48 - 48: Oo0Ooo - OoooooooOO % OOooOOo * OoOoOO00
  if 69 - 69: i1IIi
 while ( ii != - 1 ) :
  ooOoOOOOo = string [ ii : : ] . find ( iiiiI11ii )
  ooooOooooOOo = string [ ii + oOo0 : ii + ooOoOOOOo ]
  string = string [ : ii ] + OOoOOO000O0 ( ooooOooooOOo , True ) + string [ ii + ooOoOOOOo + oOo0 : : ]
  if 96 - 96: iII111i
  ii = string . find ( i1iiiIii11 )
  if 18 - 18: iII111i * I11i - Ii1I
  if 31 - 31: Oo0Ooo - O0 % OoOoOO00 % oO0o
  if 45 - 45: I1ii11iIi11i + II111iiii * i11iIiiIii
  if 13 - 13: OoooooooOO * oO0o - Ii1I / OOooOOo + I11i + IiII
  if 39 - 39: iIii1I11I1II1 - OoooooooOO
 if ( string . find ( "[1m" ) != - 1 ) : string = convert_font ( string )
 return ( string )
 if 81 - 81: I1ii11iIi11i - O0 * OoooooooOO
 if 23 - 23: II111iiii / oO0o
 if 28 - 28: Oo0Ooo * ooOoO0o - OoO0O00
 if 19 - 19: I11i
 if 67 - 67: O0 % iIii1I11I1II1 / IiII . i11iIiiIii - Ii1I + O0
 if 27 - 27: OOooOOo
 if 89 - 89: II111iiii / oO0o
def lisp_space ( num ) :
 II = ""
 for o0OoO00 in range ( num ) : II += "&#160;"
 return ( II )
 if 18 - 18: oO0o - o0oOOo0O0Ooo - I1IiiI - I1IiiI
 if 54 - 54: Oo0Ooo + I1IiiI / iII111i . I1IiiI * OoOoOO00
 if 1 - 1: OoOoOO00 * OoO0O00 . i1IIi / Oo0Ooo . I1ii11iIi11i + Oo0Ooo
 if 17 - 17: Oo0Ooo + OoO0O00 / Ii1I / iII111i * OOooOOo
 if 29 - 29: OoO0O00 % OoooooooOO * oO0o / II111iiii - oO0o
 if 19 - 19: i11iIiiIii
 if 54 - 54: II111iiii . I11i
def lisp_button ( string , url ) :
 oOOII1i11i1iIi11 = '<button style="background-color:transparent;border-radius:10px; ' + 'type="button">'
 if 83 - 83: Ii1I
 if 25 - 25: I11i + OoOoOO00 . o0oOOo0O0Ooo % OoOoOO00 * OOooOOo
 if ( url == None ) :
  ii1IiIi11 = oOOII1i11i1iIi11 + string + "</button>"
 else :
  iiiii1ii1 = '<a href="{}">' . format ( url )
  IiiiI1 = lisp_space ( 2 )
  ii1IiIi11 = IiiiI1 + iiiii1ii1 + oOOII1i11i1iIi11 + string + "</button></a>" + IiiiI1
  if 100 - 100: oO0o . Ii1I % i1IIi . ooOoO0o
 return ( ii1IiIi11 )
 if 79 - 79: OoO0O00 % OOooOOo / iIii1I11I1II1 + OoOoOO00 * OoO0O00
 if 30 - 30: OoooooooOO / I11i + iII111i / I1ii11iIi11i * O0
 if 16 - 16: Oo0Ooo / i11iIiiIii
 if 64 - 64: i11iIiiIii / Ii1I * i1IIi
 if 73 - 73: Oo0Ooo - OoOoOO00 - oO0o - I1IiiI
 if 65 - 65: o0oOOo0O0Ooo
 if 7 - 7: IiII . OoOoOO00 / I1ii11iIi11i . OOooOOo * I11i - II111iiii
def lisp_print_cour ( string ) :
 II = '<font face="Courier New">{}</font>' . format ( string )
 return ( II )
 if 37 - 37: I1Ii111 . OoOoOO00 / O0 * iII111i
 if 7 - 7: OoO0O00 * I11i + II111iiii % i11iIiiIii
 if 8 - 8: ooOoO0o * O0
 if 73 - 73: o0oOOo0O0Ooo / oO0o / I11i / OoO0O00
 if 11 - 11: OoOoOO00 + IiII - OoooooooOO / OoO0O00
 if 34 - 34: ooOoO0o
 if 45 - 45: ooOoO0o / Oo0Ooo / Ii1I
def lisp_print_sans ( string ) :
 II = '<font face="Sans-Serif">{}</font>' . format ( string )
 return ( II )
 if 44 - 44: I1ii11iIi11i - Ii1I / II111iiii * OoO0O00 * Oo0Ooo
 if 73 - 73: o0oOOo0O0Ooo - I1IiiI * i1IIi / i11iIiiIii * OOooOOo % II111iiii
 if 56 - 56: OoooooooOO * Oo0Ooo . Oo0Ooo . I1ii11iIi11i
 if 24 - 24: Oo0Ooo . I11i * Ii1I % iII111i / OOooOOo
 if 58 - 58: I1IiiI - I1ii11iIi11i % O0 . I1IiiI % OoO0O00 % IiII
 if 87 - 87: oO0o - i11iIiiIii
 if 78 - 78: i11iIiiIii / iIii1I11I1II1 - o0oOOo0O0Ooo
def lisp_span ( string , hover_string ) :
 II = '<span title="{}">{}</span>' . format ( hover_string , string )
 return ( II )
 if 23 - 23: I11i
 if 40 - 40: o0oOOo0O0Ooo - II111iiii / Oo0Ooo
 if 14 - 14: I1ii11iIi11i
 if 5 - 5: o0oOOo0O0Ooo . iIii1I11I1II1 % iIii1I11I1II1
 if 56 - 56: OoooooooOO - I11i - i1IIi
 if 8 - 8: I1Ii111 / OOooOOo . I1IiiI + I1ii11iIi11i / i11iIiiIii
 if 31 - 31: ooOoO0o - iIii1I11I1II1 + iII111i . Oo0Ooo / IiII % iIii1I11I1II1
def lisp_eid_help_hover ( output ) :
 I11i1iIiiIiIi = '''Unicast EID format:
  For longest match lookups: 
    <address> or [<iid>]<address>
  For exact match lookups: 
    <prefix> or [<iid>]<prefix>
Multicast EID format:
  For longest match lookups:
    <address>-><group> or
    [<iid>]<address>->[<iid>]<group>'''
 if 49 - 49: OOooOOo . I1ii11iIi11i . i11iIiiIii - II111iiii / Ii1I
 if 62 - 62: OOooOOo
 i1I1i = lisp_span ( output , I11i1iIiiIiIi )
 return ( i1I1i )
 if 87 - 87: Oo0Ooo / O0 * IiII / o0oOOo0O0Ooo
 if 19 - 19: I1Ii111 + i1IIi . I1IiiI - Oo0Ooo
 if 16 - 16: oO0o + ooOoO0o / o0oOOo0O0Ooo
 if 82 - 82: IiII * i11iIiiIii % II111iiii - OoooooooOO
 if 90 - 90: Oo0Ooo . oO0o * i1IIi - i1IIi
 if 16 - 16: I1IiiI * i1IIi - o0oOOo0O0Ooo . IiII % I11i / o0oOOo0O0Ooo
 if 14 - 14: iIii1I11I1II1 * I1Ii111 * I1ii11iIi11i / iIii1I11I1II1 * IiII / I11i
def lisp_geo_help_hover ( output ) :
 I11i1iIiiIiIi = '''EID format:
    <address> or [<iid>]<address>
    '<name>' or [<iid>]'<name>'
Geo-Point format:
    d-m-s-<N|S>-d-m-s-<W|E> or 
    [<iid>]d-m-s-<N|S>-d-m-s-<W|E>
Geo-Prefix format:
    d-m-s-<N|S>-d-m-s-<W|E>/<km> or
    [<iid>]d-m-s-<N|S>-d-m-s-<W|E>/<km>'''
 if 77 - 77: OoO0O00 + I1Ii111 + I1Ii111 * Ii1I / OoooooooOO . Ii1I
 if 62 - 62: i1IIi - i1IIi
 i1I1i = lisp_span ( output , I11i1iIiiIiIi )
 return ( i1I1i )
 if 69 - 69: OoOoOO00 % oO0o - I11i
 if 38 - 38: iIii1I11I1II1 + i11iIiiIii / i11iIiiIii % OoO0O00 / ooOoO0o % Ii1I
 if 7 - 7: IiII * I1IiiI + i1IIi + i11iIiiIii + Oo0Ooo % I1IiiI
 if 62 - 62: o0oOOo0O0Ooo - Ii1I * OoOoOO00 - i11iIiiIii % ooOoO0o
 if 52 - 52: I1ii11iIi11i % oO0o - i11iIiiIii
 if 30 - 30: iII111i / OoO0O00 + oO0o
 if 6 - 6: iII111i . I11i + Ii1I . I1Ii111
def space ( num ) :
 II = ""
 for o0OoO00 in range ( num ) : II += "&#160;"
 return ( II )
 if 70 - 70: OoO0O00
 if 46 - 46: I11i - i1IIi
 if 46 - 46: I1Ii111 % Ii1I
 if 72 - 72: iIii1I11I1II1
 if 45 - 45: Oo0Ooo - o0oOOo0O0Ooo % I1Ii111
 if 38 - 38: I1Ii111 % OOooOOo - OoooooooOO
 if 87 - 87: OoO0O00 % I1IiiI
 if 77 - 77: iIii1I11I1II1 - i1IIi . oO0o
def lisp_get_ephemeral_port ( ) :
 return ( random . randrange ( 32768 , 65535 ) )
 if 26 - 26: o0oOOo0O0Ooo * IiII . i1IIi
 if 59 - 59: O0 + i1IIi - o0oOOo0O0Ooo
 if 62 - 62: i11iIiiIii % OOooOOo . IiII . OOooOOo
 if 84 - 84: i11iIiiIii * OoO0O00
 if 18 - 18: OOooOOo - Ii1I - OoOoOO00 / I1Ii111 - O0
 if 30 - 30: O0 + I1ii11iIi11i + II111iiii
 if 14 - 14: o0oOOo0O0Ooo / OOooOOo - iIii1I11I1II1 - oO0o % ooOoO0o
def lisp_get_data_nonce ( ) :
 return ( random . randint ( 0 , 0xffffff ) )
 if 49 - 49: ooOoO0o * oO0o / o0oOOo0O0Ooo / Oo0Ooo * iIii1I11I1II1
 if 57 - 57: OoOoOO00 - oO0o / ooOoO0o % i11iIiiIii
 if 3 - 3: iII111i . ooOoO0o % I1IiiI + I1ii11iIi11i
 if 64 - 64: i1IIi
 if 29 - 29: o0oOOo0O0Ooo / i11iIiiIii / I1IiiI % oO0o % i11iIiiIii
 if 18 - 18: OOooOOo + I1Ii111
 if 80 - 80: oO0o + o0oOOo0O0Ooo * Ii1I + OoO0O00
def lisp_get_control_nonce ( ) :
 return ( random . randint ( 0 , ( 2 ** 64 ) - 1 ) )
 if 75 - 75: I11i / o0oOOo0O0Ooo / OOooOOo / IiII % ooOoO0o + II111iiii
 if 4 - 4: iII111i - Oo0Ooo - IiII - I11i % i11iIiiIii / OoO0O00
 if 50 - 50: ooOoO0o + i1IIi
 if 31 - 31: Ii1I
 if 78 - 78: i11iIiiIii + o0oOOo0O0Ooo + I1Ii111 / o0oOOo0O0Ooo % iIii1I11I1II1 % IiII
 if 83 - 83: iIii1I11I1II1 % OoOoOO00 % o0oOOo0O0Ooo % I1Ii111 . I1ii11iIi11i % O0
 if 47 - 47: o0oOOo0O0Ooo
 if 66 - 66: I1IiiI - IiII
 if 33 - 33: I1IiiI / OoO0O00
def lisp_hex_string ( integer_value ) :
 iiIIi = hex ( integer_value ) [ 2 : : ]
 if ( iiIIi [ - 1 ] == "L" ) : iiIIi = iiIIi [ 0 : - 1 ]
 return ( iiIIi )
 if 36 - 36: I11i . II111iiii
 if 25 - 25: oO0o
 if 34 - 34: OoOoOO00 . iIii1I11I1II1 % O0
 if 43 - 43: I1ii11iIi11i - iII111i
 if 70 - 70: iII111i / OOooOOo % ooOoO0o - Ii1I
 if 47 - 47: iII111i
 if 92 - 92: OOooOOo + OoOoOO00 % i1IIi
def lisp_get_timestamp ( ) :
 return ( time . time ( ) )
 if 23 - 23: I1Ii111 - OOooOOo + Ii1I - OoOoOO00 * OoOoOO00 . Oo0Ooo
 if 47 - 47: oO0o % iIii1I11I1II1
 if 11 - 11: I1IiiI % Ii1I - OoO0O00 - oO0o + o0oOOo0O0Ooo
 if 98 - 98: iII111i + Ii1I - OoO0O00
 if 79 - 79: OOooOOo / I1Ii111 . OoOoOO00 - I1ii11iIi11i
 if 47 - 47: OoooooooOO % O0 * iII111i . Ii1I
 if 38 - 38: O0 - IiII % I1Ii111
def lisp_set_timestamp ( seconds ) :
 return ( time . time ( ) + seconds )
 if 64 - 64: iIii1I11I1II1
 if 15 - 15: I1ii11iIi11i + OOooOOo / I1ii11iIi11i / I1Ii111
 if 31 - 31: ooOoO0o + O0 + ooOoO0o . iIii1I11I1II1 + Oo0Ooo / o0oOOo0O0Ooo
 if 6 - 6: Oo0Ooo % IiII * I11i / I1IiiI + Oo0Ooo
 if 39 - 39: OoOoOO00 - Oo0Ooo / iII111i * OoooooooOO
 if 100 - 100: O0 . I11i . OoO0O00 + O0 * oO0o
 if 42 - 42: oO0o % OoooooooOO + o0oOOo0O0Ooo
def lisp_print_elapsed ( ts ) :
 if ( ts == 0 or ts == None ) : return ( "never" )
 ooOO0o = time . time ( ) - ts
 ooOO0o = round ( ooOO0o , 0 )
 return ( str ( datetime . timedelta ( seconds = ooOO0o ) ) )
 if 51 - 51: Oo0Ooo - I1ii11iIi11i * I11i
 if 12 - 12: iIii1I11I1II1 % ooOoO0o % ooOoO0o
 if 78 - 78: IiII . OoOoOO00 . I11i
 if 97 - 97: oO0o
 if 80 - 80: I1IiiI . Ii1I
 if 47 - 47: I11i + ooOoO0o + II111iiii % i11iIiiIii
 if 93 - 93: I1ii11iIi11i % OoOoOO00 . O0 / iII111i * oO0o
def lisp_print_future ( ts ) :
 if ( ts == 0 ) : return ( "never" )
 i1iii1ii = ts - time . time ( )
 if ( i1iii1ii < 0 ) : return ( "expired" )
 i1iii1ii = round ( i1iii1ii , 0 )
 return ( str ( datetime . timedelta ( seconds = i1iii1ii ) ) )
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
 if 93 - 93: I1Ii111 + Ii1I
 if 33 - 33: O0
def lisp_print_eid_tuple ( eid , group ) :
 oo0oO = eid . print_prefix ( )
 if ( group . is_null ( ) ) : return ( oo0oO )
 if 50 - 50: OoooooooOO - iIii1I11I1II1 + i1IIi % I1Ii111 - iIii1I11I1II1 % O0
 o0oO0Oo = group . print_prefix ( )
 OO0OO000 = group . instance_id
 if 55 - 55: ooOoO0o
 if ( eid . is_null ( ) or eid . is_exact_match ( group ) ) :
  ii = o0oO0Oo . find ( "]" ) + 1
  return ( "[{}](*, {})" . format ( OO0OO000 , o0oO0Oo [ ii : : ] ) )
  if 82 - 82: I1Ii111 - OOooOOo + OoO0O00
  if 64 - 64: o0oOOo0O0Ooo . O0 * Ii1I + OoooooooOO - Oo0Ooo . OoooooooOO
 OOoO0oo0O = eid . print_sg ( group )
 return ( OOoO0oo0O )
 if 49 - 49: o0oOOo0O0Ooo
 if 31 - 31: OoO0O00 * i11iIiiIii * Ii1I . i11iIiiIii
 if 12 - 12: OoOoOO00 % IiII % I1ii11iIi11i . i11iIiiIii * iIii1I11I1II1
 if 66 - 66: i11iIiiIii * iIii1I11I1II1 % OoooooooOO
 if 5 - 5: OoOoOO00 % OoooooooOO
 if 60 - 60: OoOoOO00 . i1IIi % OoO0O00 % ooOoO0o % OOooOOo
 if 33 - 33: iIii1I11I1II1 - Ii1I * I1ii11iIi11i % iIii1I11I1II1 + OoO0O00 . OOooOOo
 if 56 - 56: i11iIiiIii * iII111i . oO0o
def lisp_convert_6to4 ( addr_str ) :
 if ( addr_str . find ( "::ffff:" ) == - 1 ) : return ( addr_str )
 ooooO0O = addr_str . split ( ":" )
 return ( ooooO0O [ - 1 ] )
 if 81 - 81: i1IIi % o0oOOo0O0Ooo - I1Ii111 + i11iIiiIii - OoooooooOO
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
def lisp_convert_4to6 ( addr_str ) :
 ooooO0O = lisp_address ( LISP_AFI_IPV6 , "" , 128 , 0 )
 if ( ooooO0O . is_ipv4_string ( addr_str ) ) : addr_str = "::ffff:" + addr_str
 ooooO0O . store_address ( addr_str )
 return ( ooooO0O )
 if 79 - 79: OoooooooOO - IiII * IiII . OoOoOO00
 if 100 - 100: II111iiii * I11i % I1IiiI / I1ii11iIi11i
 if 90 - 90: I1ii11iIi11i . ooOoO0o . OoOoOO00 . Ii1I
 if 4 - 4: Ii1I + OoOoOO00 % I1ii11iIi11i / i11iIiiIii
 if 74 - 74: II111iiii . O0 - I1IiiI + IiII % i11iIiiIii % OoOoOO00
 if 78 - 78: Ii1I + OoOoOO00 + IiII - IiII . i11iIiiIii / OoO0O00
 if 27 - 27: Ii1I - O0 % I11i * I1Ii111 . IiII % iIii1I11I1II1
 if 37 - 37: OoooooooOO + O0 - i1IIi % ooOoO0o
 if 24 - 24: OoOoOO00
def lisp_gethostbyname ( string ) :
 Oo0oOo0ooOOOo = string . split ( "." )
 OoO0000o = string . split ( ":" )
 o0 = string . split ( "-" )
 if 29 - 29: II111iiii . OoOoOO00 % o0oOOo0O0Ooo * II111iiii - o0oOOo0O0Ooo * iIii1I11I1II1
 if ( len ( Oo0oOo0ooOOOo ) > 1 ) :
  if ( Oo0oOo0ooOOOo [ 0 ] . isdigit ( ) ) : return ( string )
  if 35 - 35: II111iiii - IiII . i1IIi
 if ( len ( OoO0000o ) > 1 ) :
  try :
   int ( OoO0000o [ 0 ] , 16 )
   return ( string )
  except :
   pass
   if 95 - 95: I1IiiI + I1IiiI - OOooOOo - iII111i
   if 45 - 45: Ii1I . OoooooooOO
   if 27 - 27: Ii1I * Oo0Ooo . OoOoOO00
   if 17 - 17: II111iiii % iII111i * OOooOOo % i1IIi . I1IiiI . iIii1I11I1II1
   if 27 - 27: i11iIiiIii - I1IiiI
   if 35 - 35: OoooooooOO - I1Ii111 / OoO0O00
   if 50 - 50: OoOoOO00
 if ( len ( o0 ) == 3 ) :
  for o0OoO00 in range ( 3 ) :
   try : int ( o0 [ o0OoO00 ] , 16 )
   except : break
   if 33 - 33: I11i
   if 98 - 98: OoOoOO00 % II111iiii
   if 95 - 95: iIii1I11I1II1 - I1Ii111 - OOooOOo + I1Ii111 % I1ii11iIi11i . I1IiiI
 try :
  ooooO0O = socket . gethostbyname ( string )
  return ( ooooO0O )
 except :
  if ( lisp_is_alpine ( ) == False ) : return ( "" )
  if 41 - 41: O0 + oO0o . i1IIi - II111iiii * o0oOOo0O0Ooo . OoO0O00
  if 68 - 68: o0oOOo0O0Ooo
  if 20 - 20: I1Ii111 - I1Ii111
  if 37 - 37: IiII
  if 37 - 37: Oo0Ooo / IiII * O0
 try :
  ooooO0O = socket . getaddrinfo ( string , 0 ) [ 0 ]
  if ( ooooO0O [ 3 ] != string ) : return ( "" )
  ooooO0O = ooooO0O [ 4 ] [ 0 ]
 except :
  ooooO0O = ""
  if 73 - 73: iII111i * iII111i / ooOoO0o
 return ( ooooO0O )
 if 43 - 43: I1ii11iIi11i . i1IIi . IiII + O0 * Ii1I * O0
 if 41 - 41: I1ii11iIi11i + Ii1I % OoooooooOO . I1ii11iIi11i + iII111i . iII111i
 if 31 - 31: i11iIiiIii + II111iiii . iII111i * OoOoOO00
 if 66 - 66: OoOoOO00 + i1IIi % II111iiii . O0 * I1ii11iIi11i % I1ii11iIi11i
 if 87 - 87: OOooOOo + o0oOOo0O0Ooo . iII111i - OoooooooOO
 if 6 - 6: iIii1I11I1II1 * OoooooooOO
 if 28 - 28: Oo0Ooo * o0oOOo0O0Ooo / I1Ii111
 if 52 - 52: O0 / o0oOOo0O0Ooo % iII111i * I1IiiI % OOooOOo
def lisp_ip_checksum ( data ) :
 if ( len ( data ) < 20 ) :
  lprint ( "IPv4 packet too short, length {}" . format ( len ( data ) ) )
  return ( data )
  if 69 - 69: I1ii11iIi11i
  if 83 - 83: o0oOOo0O0Ooo
 i1iiii = binascii . hexlify ( data )
 if 90 - 90: o0oOOo0O0Ooo % I1ii11iIi11i - iIii1I11I1II1 % OoOoOO00
 if 8 - 8: OoOoOO00 * Oo0Ooo / IiII % Ii1I - I1IiiI
 if 71 - 71: iII111i
 if 23 - 23: i1IIi . iIii1I11I1II1 . OOooOOo . O0 % Ii1I % i11iIiiIii
 Iiiii111 = 0
 for o0OoO00 in range ( 0 , 40 , 4 ) :
  Iiiii111 += int ( i1iiii [ o0OoO00 : o0OoO00 + 4 ] , 16 )
  if 93 - 93: OoooooooOO * Oo0Ooo
  if 10 - 10: I1Ii111 * OoooooooOO + I11i - I1ii11iIi11i / I1ii11iIi11i . i11iIiiIii
  if 22 - 22: I1Ii111 / o0oOOo0O0Ooo
  if 98 - 98: i1IIi
  if 51 - 51: I1ii11iIi11i + ooOoO0o + Oo0Ooo / i1IIi + i1IIi
 Iiiii111 = ( Iiiii111 >> 16 ) + ( Iiiii111 & 0xffff )
 Iiiii111 += Iiiii111 >> 16
 Iiiii111 = socket . htons ( ~ Iiiii111 & 0xffff )
 if 12 - 12: iIii1I11I1II1 . Ii1I . I1ii11iIi11i % I1IiiI . II111iiii . oO0o
 if 32 - 32: I1ii11iIi11i + IiII / O0 / OoOoOO00 * OoooooooOO % ooOoO0o
 if 50 - 50: OoO0O00
 if 66 - 66: iIii1I11I1II1
 Iiiii111 = struct . pack ( "H" , Iiiii111 )
 i1iiii = data [ 0 : 10 ] + Iiiii111 + data [ 12 : : ]
 return ( i1iiii )
 if 41 - 41: I1Ii111 . O0 * I1IiiI * I1ii11iIi11i
 if 100 - 100: iII111i
 if 73 - 73: I1ii11iIi11i % II111iiii
 if 79 - 79: OoOoOO00 + OoO0O00 - II111iiii + Ii1I
 if 11 - 11: oO0o + iIii1I11I1II1
 if 10 - 10: O0
 if 68 - 68: OOooOOo + oO0o . O0 . Ii1I % i1IIi % OOooOOo
 if 50 - 50: IiII + o0oOOo0O0Ooo
def lisp_icmp_checksum ( data ) :
 if ( len ( data ) < 36 ) :
  lprint ( "ICMP packet too short, length {}" . format ( len ( data ) ) )
  return ( data )
  if 96 - 96: OoO0O00
  if 92 - 92: Oo0Ooo / i11iIiiIii + I1ii11iIi11i
 oOo0Oo0O0O = binascii . hexlify ( data )
 if 48 - 48: Oo0Ooo - ooOoO0o + Oo0Ooo - I1IiiI * i11iIiiIii . iII111i
 if 35 - 35: IiII . O0 + Oo0Ooo + OOooOOo + i1IIi
 if 65 - 65: O0 * I1IiiI / I1IiiI . OoOoOO00
 if 87 - 87: II111iiii * I1ii11iIi11i % Oo0Ooo * Oo0Ooo
 Iiiii111 = 0
 for o0OoO00 in range ( 0 , 36 , 4 ) :
  Iiiii111 += int ( oOo0Oo0O0O [ o0OoO00 : o0OoO00 + 4 ] , 16 )
  if 58 - 58: OOooOOo . o0oOOo0O0Ooo + I1IiiI % Oo0Ooo - OoO0O00
  if 50 - 50: iII111i % II111iiii - ooOoO0o . i1IIi + O0 % iII111i
  if 10 - 10: iII111i . i1IIi + Ii1I
  if 66 - 66: OoO0O00 % o0oOOo0O0Ooo
  if 21 - 21: OoOoOO00 - OoooooooOO % i11iIiiIii
 Iiiii111 = ( Iiiii111 >> 16 ) + ( Iiiii111 & 0xffff )
 Iiiii111 += Iiiii111 >> 16
 Iiiii111 = socket . htons ( ~ Iiiii111 & 0xffff )
 if 71 - 71: i1IIi - I11i * I1Ii111 + oO0o - OoO0O00 % I1ii11iIi11i
 if 63 - 63: iIii1I11I1II1 + OOooOOo . OoO0O00 / I1IiiI
 if 84 - 84: i1IIi
 if 42 - 42: II111iiii - OoO0O00 - OoooooooOO . iII111i / OoOoOO00
 Iiiii111 = struct . pack ( "H" , Iiiii111 )
 oOo0Oo0O0O = data [ 0 : 2 ] + Iiiii111 + data [ 4 : : ]
 return ( oOo0Oo0O0O )
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
 if 91 - 91: OoOoOO00 % iIii1I11I1II1 . I1IiiI
 if 70 - 70: I11i % II111iiii % O0 . i1IIi / I1Ii111
 if 100 - 100: I1ii11iIi11i * i11iIiiIii % oO0o / Oo0Ooo / ooOoO0o + I1ii11iIi11i
 if 59 - 59: I1Ii111 - IiII
 if 14 - 14: iIii1I11I1II1 - iIii1I11I1II1
 if 5 - 5: IiII
 if 84 - 84: II111iiii * oO0o * II111iiii % IiII / I1IiiI
 if 100 - 100: IiII . Ii1I - iIii1I11I1II1 . i11iIiiIii / II111iiii
 if 71 - 71: I1Ii111 * Oo0Ooo . I11i
 if 49 - 49: IiII * O0 . IiII
 if 19 - 19: II111iiii - IiII
 if 59 - 59: o0oOOo0O0Ooo * OoO0O00 - Ii1I . OOooOOo
 if 89 - 89: OOooOOo
 if 69 - 69: ooOoO0o - OoooooooOO * O0
 if 84 - 84: ooOoO0o + i11iIiiIii - OOooOOo * ooOoO0o
 if 33 - 33: ooOoO0o % i1IIi - oO0o . O0 / O0
 if 96 - 96: OoooooooOO + IiII * O0
def lisp_udp_checksum ( source , dest , data ) :
 if 86 - 86: Ii1I
 if 29 - 29: iIii1I11I1II1 - OoO0O00 + I1IiiI % iIii1I11I1II1 % OOooOOo
 if 84 - 84: IiII + I1ii11iIi11i + Ii1I + iII111i
 if 62 - 62: i11iIiiIii + OoOoOO00 + i1IIi
 IiiiI1 = lisp_address ( LISP_AFI_IPV6 , source , LISP_IPV6_HOST_MASK_LEN , 0 )
 oOOoO0O = lisp_address ( LISP_AFI_IPV6 , dest , LISP_IPV6_HOST_MASK_LEN , 0 )
 i1IiiiiiIiII = socket . htonl ( len ( data ) )
 iI = socket . htonl ( LISP_UDP_PROTOCOL )
 IiIi = IiiiI1 . pack_address ( )
 IiIi += oOOoO0O . pack_address ( )
 IiIi += struct . pack ( "II" , i1IiiiiiIiII , iI )
 if 88 - 88: OoOoOO00 - OOooOOo
 if 63 - 63: IiII * OoooooooOO
 if 19 - 19: IiII - o0oOOo0O0Ooo . iIii1I11I1II1 . OoOoOO00 / OOooOOo
 if 87 - 87: OoOoOO00 - ooOoO0o - OOooOOo + Oo0Ooo % iIii1I11I1II1 / i11iIiiIii
 i1iIIII1iiIIi = binascii . hexlify ( IiIi + data )
 i1I1IiI1ii = len ( i1iIIII1iiIIi ) % 4
 for o0OoO00 in range ( 0 , i1I1IiI1ii ) : i1iIIII1iiIIi += "0"
 if 64 - 64: iII111i * I1ii11iIi11i % II111iiii - OoOoOO00 + I1ii11iIi11i
 if 62 - 62: OoOoOO00 % o0oOOo0O0Ooo % I1IiiI + IiII . OoO0O00
 if 48 - 48: I1IiiI * i11iIiiIii % II111iiii
 if 20 - 20: i1IIi / I1IiiI * oO0o
 Iiiii111 = 0
 for o0OoO00 in range ( 0 , len ( i1iIIII1iiIIi ) , 4 ) :
  Iiiii111 += int ( i1iIIII1iiIIi [ o0OoO00 : o0OoO00 + 4 ] , 16 )
  if 85 - 85: II111iiii . ooOoO0o % OOooOOo % I11i
  if 80 - 80: oO0o * I11i / iIii1I11I1II1 % oO0o / iIii1I11I1II1
  if 42 - 42: i1IIi / i11iIiiIii . Oo0Ooo * iII111i . i11iIiiIii * O0
  if 44 - 44: i1IIi . I1IiiI / i11iIiiIii + IiII
  if 27 - 27: OOooOOo
 Iiiii111 = ( Iiiii111 >> 16 ) + ( Iiiii111 & 0xffff )
 Iiiii111 += Iiiii111 >> 16
 Iiiii111 = socket . htons ( ~ Iiiii111 & 0xffff )
 if 52 - 52: I1Ii111 % OoOoOO00 + iIii1I11I1II1 * oO0o . Ii1I
 if 95 - 95: iIii1I11I1II1 . IiII - OoooooooOO * OoO0O00 / o0oOOo0O0Ooo
 if 74 - 74: oO0o
 if 34 - 34: iII111i
 Iiiii111 = struct . pack ( "H" , Iiiii111 )
 i1iIIII1iiIIi = data [ 0 : 6 ] + Iiiii111 + data [ 8 : : ]
 return ( i1iIIII1iiIIi )
 if 44 - 44: i1IIi % I1IiiI % o0oOOo0O0Ooo
 if 9 - 9: Oo0Ooo % OoooooooOO - Ii1I
 if 43 - 43: OoO0O00 % OoO0O00
 if 46 - 46: Oo0Ooo % iIii1I11I1II1 . iII111i . O0 * ooOoO0o / OoooooooOO
 if 7 - 7: oO0o - O0 * I11i - o0oOOo0O0Ooo - II111iiii
 if 41 - 41: I1IiiI - I1Ii111 % II111iiii . I1Ii111 - I11i
 if 45 - 45: Ii1I - OOooOOo
def lisp_get_interface_address ( device ) :
 if 70 - 70: OoO0O00 % I1IiiI / I1IiiI . I11i % ooOoO0o . II111iiii
 if 10 - 10: Ii1I - i11iIiiIii . I1ii11iIi11i % i1IIi
 if 78 - 78: iIii1I11I1II1 * Oo0Ooo . Oo0Ooo - OOooOOo . iIii1I11I1II1
 if 30 - 30: ooOoO0o + ooOoO0o % IiII - o0oOOo0O0Ooo - I1ii11iIi11i
 if ( device not in netifaces . interfaces ( ) ) : return ( None )
 if 36 - 36: I11i % OOooOOo
 if 72 - 72: I1IiiI / iII111i - O0 + I11i
 if 83 - 83: O0
 if 89 - 89: Oo0Ooo + I1ii11iIi11i - o0oOOo0O0Ooo
 iII1I11 = netifaces . ifaddresses ( device )
 if ( iII1I11 . has_key ( netifaces . AF_INET ) == False ) : return ( None )
 if 15 - 15: I11i
 if 13 - 13: iIii1I11I1II1 * OoOoOO00 / I1Ii111 % ooOoO0o + oO0o
 if 41 - 41: I1ii11iIi11i
 if 5 - 5: Oo0Ooo
 o0oOo00 = lisp_address ( LISP_AFI_IPV4 , "" , 32 , 0 )
 if 22 - 22: iIii1I11I1II1 + IiII + I1ii11iIi11i + I1Ii111 - Ii1I
 for ooooO0O in iII1I11 [ netifaces . AF_INET ] :
  I1IIII1i1 = ooooO0O [ "addr" ]
  o0oOo00 . store_address ( I1IIII1i1 )
  return ( o0oOo00 )
  if 67 - 67: Oo0Ooo / ooOoO0o - IiII
 return ( None )
 if 74 - 74: I11i * Ii1I - I1ii11iIi11i % iIii1I11I1II1
 if 56 - 56: I1ii11iIi11i - O0
 if 58 - 58: IiII + iIii1I11I1II1
 if 94 - 94: Ii1I . i1IIi
 if 71 - 71: iII111i + OoO0O00 - IiII . OoO0O00 . IiII + I1IiiI
 if 26 - 26: O0
 if 17 - 17: II111iiii
 if 9 - 9: OoooooooOO + oO0o
 if 33 - 33: O0
 if 39 - 39: I1IiiI + Oo0Ooo
 if 83 - 83: i1IIi
 if 76 - 76: Ii1I + iIii1I11I1II1 + OoOoOO00 . OoO0O00
def lisp_get_input_interface ( packet ) :
 i1i1 = lisp_format_packet ( packet [ 0 : 12 ] ) . replace ( " " , "" )
 o0oOoOo0 = i1i1 [ 0 : 12 ]
 III1IiI1i1i = i1i1 [ 12 : : ]
 if 94 - 94: iII111i - Oo0Ooo + oO0o
 try : O0oooOoO = lisp_mymacs . has_key ( III1IiI1i1i )
 except : O0oooOoO = False
 if 62 - 62: OOooOOo / II111iiii + OoOoOO00 % ooOoO0o / OoOoOO00 + I1ii11iIi11i
 if ( lisp_mymacs . has_key ( o0oOoOo0 ) ) : return ( lisp_mymacs [ o0oOoOo0 ] , III1IiI1i1i , o0oOoOo0 , O0oooOoO )
 if ( O0oooOoO ) : return ( lisp_mymacs [ III1IiI1i1i ] , III1IiI1i1i , o0oOoOo0 , O0oooOoO )
 return ( [ "?" ] , III1IiI1i1i , o0oOoOo0 , O0oooOoO )
 if 2 - 2: i11iIiiIii - I1Ii111 + OoO0O00 % I11i * Ii1I
 if 54 - 54: O0 - iII111i . OOooOOo % iII111i + iII111i
 if 36 - 36: OOooOOo % i11iIiiIii
 if 47 - 47: i1IIi + II111iiii . Oo0Ooo * oO0o . I11i / i1IIi
 if 50 - 50: I1Ii111 / i1IIi % OoooooooOO
 if 83 - 83: I1ii11iIi11i * I1ii11iIi11i + OOooOOo
 if 57 - 57: O0 - O0 . I1ii11iIi11i / o0oOOo0O0Ooo / Ii1I
 if 20 - 20: OOooOOo * II111iiii - OoOoOO00 - oO0o * I1Ii111
def lisp_get_local_interfaces ( ) :
 for I1i1II1 in netifaces . interfaces ( ) :
  oOOoo = lisp_interface ( I1i1II1 )
  oOOoo . add_interface ( )
  if 9 - 9: I11i . OoO0O00 * i1IIi . OoooooooOO
 return
 if 32 - 32: OoOoOO00 . I1ii11iIi11i % I1IiiI - II111iiii
 if 11 - 11: O0 + I1IiiI
 if 80 - 80: oO0o % oO0o % O0 - i11iIiiIii . iII111i / O0
 if 13 - 13: I1IiiI + O0 - I1ii11iIi11i % Oo0Ooo / Ii1I . i1IIi
 if 60 - 60: Oo0Ooo . IiII % I1IiiI - I1Ii111
 if 79 - 79: OoooooooOO / I1ii11iIi11i . O0
 if 79 - 79: oO0o - II111iiii
def lisp_get_loopback_address ( ) :
 for ooooO0O in netifaces . ifaddresses ( "lo" ) [ netifaces . AF_INET ] :
  if ( ooooO0O [ "peer" ] == "127.0.0.1" ) : continue
  return ( ooooO0O [ "peer" ] )
  if 43 - 43: i1IIi + O0 % OoO0O00 / Ii1I * I1IiiI
 return ( None )
 if 89 - 89: I1IiiI . Oo0Ooo + I1ii11iIi11i . O0 % o0oOOo0O0Ooo
 if 84 - 84: OoooooooOO + I1Ii111 / I1IiiI % OOooOOo % I1ii11iIi11i * I1IiiI
 if 58 - 58: OoO0O00 - OoOoOO00 . i11iIiiIii % i11iIiiIii / i1IIi / oO0o
 if 24 - 24: I1IiiI * i1IIi % ooOoO0o / O0 + i11iIiiIii
 if 12 - 12: I1ii11iIi11i / Ii1I
 if 5 - 5: OoooooooOO
 if 18 - 18: I1IiiI % OoooooooOO - iII111i . i11iIiiIii * Oo0Ooo % Ii1I
 if 12 - 12: i1IIi / OOooOOo % ooOoO0o * IiII * O0 * iIii1I11I1II1
def lisp_is_mac_string ( mac_str ) :
 o0 = mac_str . split ( "/" )
 if ( len ( o0 ) == 2 ) : mac_str = o0 [ 0 ]
 return ( len ( mac_str ) == 14 and mac_str . count ( "-" ) == 2 )
 if 93 - 93: Oo0Ooo / I1ii11iIi11i + i1IIi * oO0o . OoooooooOO
 if 54 - 54: O0 / IiII % ooOoO0o * i1IIi * O0
 if 48 - 48: o0oOOo0O0Ooo . oO0o % OoOoOO00 - OoOoOO00
 if 33 - 33: I11i % II111iiii + OoO0O00
 if 93 - 93: i1IIi . IiII / I1IiiI + IiII
 if 58 - 58: I1ii11iIi11i + O0 . Oo0Ooo + OoOoOO00 - OoO0O00 - OoOoOO00
 if 41 - 41: Oo0Ooo / i1IIi / Oo0Ooo - iII111i . o0oOOo0O0Ooo
 if 65 - 65: O0 * i11iIiiIii . OoooooooOO / I1IiiI / iII111i
def lisp_get_local_macs ( ) :
 for I1i1II1 in netifaces . interfaces ( ) :
  if 69 - 69: ooOoO0o % ooOoO0o
  if 76 - 76: i11iIiiIii * iII111i / OoO0O00 % I1ii11iIi11i + OOooOOo
  if 48 - 48: iIii1I11I1II1 % i1IIi + OoOoOO00 % o0oOOo0O0Ooo
  if 79 - 79: OoOoOO00 % I1IiiI % Ii1I / i1IIi % OoO0O00
  if 56 - 56: iIii1I11I1II1 - i11iIiiIii * iII111i
  oOOoO0O = I1i1II1 . replace ( ":" , "" )
  oOOoO0O = I1i1II1 . replace ( "-" , "" )
  if ( oOOoO0O . isalnum ( ) == False ) : continue
  if 84 - 84: OOooOOo + Ii1I + o0oOOo0O0Ooo
  if 33 - 33: Ii1I
  if 93 - 93: ooOoO0o
  if 34 - 34: oO0o - ooOoO0o * Oo0Ooo / o0oOOo0O0Ooo
  if 19 - 19: I1ii11iIi11i
  try :
   IiI = netifaces . ifaddresses ( I1i1II1 )
  except :
   continue
   if 4 - 4: OoooooooOO + ooOoO0o . i1IIi / O0 - O0
  if ( IiI . has_key ( netifaces . AF_LINK ) == False ) : continue
  o0 = IiI [ netifaces . AF_LINK ] [ 0 ] [ "addr" ]
  o0 = o0 . replace ( ":" , "" )
  if 52 - 52: OoO0O00 * OoooooooOO
  if 12 - 12: O0 + IiII * i1IIi . OoO0O00
  if 71 - 71: I1Ii111 - o0oOOo0O0Ooo - OOooOOo
  if 28 - 28: iIii1I11I1II1
  if 7 - 7: o0oOOo0O0Ooo % IiII * OoOoOO00
  if ( len ( o0 ) < 12 ) : continue
  if 58 - 58: IiII / I11i + II111iiii % iII111i - OoooooooOO
  if ( lisp_mymacs . has_key ( o0 ) == False ) : lisp_mymacs [ o0 ] = [ ]
  lisp_mymacs [ o0 ] . append ( I1i1II1 )
  if 25 - 25: OoOoOO00 % OoooooooOO * Oo0Ooo - i1IIi * II111iiii * oO0o
  if 30 - 30: I11i % OoOoOO00 / I1ii11iIi11i * O0 * Ii1I . I1IiiI
 lprint ( "Local MACs are: {}" . format ( lisp_mymacs ) )
 return
 if 46 - 46: OoOoOO00 - O0
 if 70 - 70: I11i + Oo0Ooo * iIii1I11I1II1 . I1IiiI * I11i
 if 49 - 49: o0oOOo0O0Ooo
 if 25 - 25: iII111i . OoooooooOO * iIii1I11I1II1 . o0oOOo0O0Ooo / O0 + Ii1I
 if 68 - 68: Oo0Ooo
 if 22 - 22: OOooOOo
 if 22 - 22: iII111i * I11i - Oo0Ooo * O0 / i11iIiiIii
 if 78 - 78: Oo0Ooo * O0 / ooOoO0o + OoooooooOO + OOooOOo
def lisp_get_local_rloc ( ) :
 I1iiIiiIiiI = commands . getoutput ( "netstat -rn | egrep 'default|0.0.0.0'" )
 if ( I1iiIiiIiiI == "" ) : return ( lisp_address ( LISP_AFI_IPV4 , "" , 32 , 0 ) )
 if 94 - 94: i1IIi
 if 36 - 36: I1IiiI + Oo0Ooo
 if 46 - 46: iII111i
 if 65 - 65: i1IIi . I1ii11iIi11i / ooOoO0o
 I1iiIiiIiiI = I1iiIiiIiiI . split ( "\n" ) [ 0 ]
 I1i1II1 = I1iiIiiIiiI . split ( ) [ - 1 ]
 if 11 - 11: IiII * ooOoO0o / ooOoO0o - OOooOOo
 ooooO0O = ""
 OoO0o0OOOO = lisp_is_macos ( )
 if ( OoO0o0OOOO ) :
  I1iiIiiIiiI = commands . getoutput ( "ifconfig {} | egrep 'inet '" . format ( I1i1II1 ) )
  if ( I1iiIiiIiiI == "" ) : return ( lisp_address ( LISP_AFI_IPV4 , "" , 32 , 0 ) )
 else :
  II1i = 'ip addr show | egrep "inet " | egrep "{}"' . format ( I1i1II1 )
  I1iiIiiIiiI = commands . getoutput ( II1i )
  if ( I1iiIiiIiiI == "" ) :
   II1i = 'ip addr show | egrep "inet " | egrep "global lo"'
   I1iiIiiIiiI = commands . getoutput ( II1i )
   if 62 - 62: I11i / oO0o % Oo0Ooo . OoooooooOO / i11iIiiIii / I1Ii111
  if ( I1iiIiiIiiI == "" ) : return ( lisp_address ( LISP_AFI_IPV4 , "" , 32 , 0 ) )
  if 60 - 60: I1IiiI % oO0o / o0oOOo0O0Ooo % oO0o * i11iIiiIii / iII111i
  if 34 - 34: I1Ii111 - OOooOOo
  if 25 - 25: oO0o % I1IiiI + i11iIiiIii + O0 * OoooooooOO
  if 64 - 64: i1IIi
  if 10 - 10: I1Ii111 % O0 / I1IiiI % I11i
  if 25 - 25: II111iiii / OoO0O00
 ooooO0O = ""
 I1iiIiiIiiI = I1iiIiiIiiI . split ( "\n" )
 if 64 - 64: O0 % ooOoO0o
 for iI1111i in I1iiIiiIiiI :
  iiiii1ii1 = iI1111i . split ( ) [ 1 ]
  if ( OoO0o0OOOO == False ) : iiiii1ii1 = iiiii1ii1 . split ( "/" ) [ 0 ]
  I1Ii1iIIIIi = lisp_address ( LISP_AFI_IPV4 , iiiii1ii1 , 32 , 0 )
  return ( I1Ii1iIIIIi )
  if 14 - 14: OoooooooOO . o0oOOo0O0Ooo . I11i
 return ( lisp_address ( LISP_AFI_IPV4 , ooooO0O , 32 , 0 ) )
 if 50 - 50: ooOoO0o * OoOoOO00 + I1ii11iIi11i - i11iIiiIii + Oo0Ooo * I1ii11iIi11i
 if 20 - 20: I1Ii111 / o0oOOo0O0Ooo % OoOoOO00
 if 69 - 69: I1Ii111 - i1IIi % iII111i . OOooOOo - OOooOOo
 if 65 - 65: OOooOOo + II111iiii
 if 61 - 61: i11iIiiIii * oO0o % Oo0Ooo * I1Ii111 - OoooooooOO - OoO0O00
 if 83 - 83: ooOoO0o / OOooOOo
 if 39 - 39: IiII + I11i
 if 9 - 9: I1IiiI % I11i . Oo0Ooo * I1IiiI
 if 99 - 99: O0 . o0oOOo0O0Ooo % I11i - Oo0Ooo / I11i
 if 20 - 20: OoOoOO00 * iII111i
 if 19 - 19: OoooooooOO
def lisp_get_local_addresses ( ) :
 global lisp_myrlocs
 if 76 - 76: OoO0O00 * oO0o
 if 63 - 63: II111iiii . II111iiii + I1ii11iIi11i + OOooOOo + O0 . Ii1I
 if 1 - 1: O0 * i11iIiiIii - ooOoO0o - Ii1I
 if 94 - 94: OoO0O00 + IiII + ooOoO0o
 if 82 - 82: Oo0Ooo - Oo0Ooo . iIii1I11I1II1 / OOooOOo + IiII % iIii1I11I1II1
 if 61 - 61: OOooOOo / Oo0Ooo % OOooOOo - OoO0O00 + ooOoO0o / ooOoO0o
 if 82 - 82: Oo0Ooo
 if 5 - 5: OoO0O00 / OoO0O00 - O0 - I1Ii111 + I1Ii111
 if 99 - 99: I11i * OoooooooOO / o0oOOo0O0Ooo . IiII - iIii1I11I1II1 - Ii1I
 if 31 - 31: IiII - OoO0O00 / OOooOOo . i1IIi / Ii1I
 o0o000o = None
 ii = 1
 iiiI1i1111II = os . getenv ( "LISP_ADDR_SELECT" )
 if ( iiiI1i1111II != None and iiiI1i1111II != "" ) :
  iiiI1i1111II = iiiI1i1111II . split ( ":" )
  if ( len ( iiiI1i1111II ) == 2 ) :
   o0o000o = iiiI1i1111II [ 0 ]
   ii = iiiI1i1111II [ 1 ]
  else :
   if ( iiiI1i1111II [ 0 ] . isdigit ( ) ) :
    ii = iiiI1i1111II [ 0 ]
   else :
    o0o000o = iiiI1i1111II [ 0 ]
    if 38 - 38: Oo0Ooo % I1ii11iIi11i - iII111i * iIii1I11I1II1 / O0
    if 9 - 9: I11i * Oo0Ooo . ooOoO0o * i11iIiiIii - O0
  ii = 1 if ( ii == "" ) else int ( ii )
  if 54 - 54: I1IiiI * OOooOOo + o0oOOo0O0Ooo % i1IIi - o0oOOo0O0Ooo + OoOoOO00
  if 15 - 15: OoOoOO00 * oO0o + OOooOOo . I11i % I1IiiI - ooOoO0o
 II1I1I1i1i = [ None , None , None ]
 Oo0oOO0O00 = lisp_address ( LISP_AFI_IPV4 , "" , 32 , 0 )
 o00OOo0o0O = lisp_address ( LISP_AFI_IPV6 , "" , 128 , 0 )
 I111Iii1 = None
 if 30 - 30: i1IIi
 for I1i1II1 in netifaces . interfaces ( ) :
  if ( o0o000o != None and o0o000o != I1i1II1 ) : continue
  iII1I11 = netifaces . ifaddresses ( I1i1II1 )
  if ( iII1I11 == { } ) : continue
  if 75 - 75: I11i . OOooOOo - iIii1I11I1II1 * OoO0O00 * iII111i
  if 93 - 93: ooOoO0o
  if 18 - 18: ooOoO0o
  if 66 - 66: oO0o * i11iIiiIii + OoOoOO00 / OOooOOo
  I111Iii1 = lisp_get_interface_instance_id ( I1i1II1 , None )
  if 96 - 96: OOooOOo + OOooOOo % IiII % OOooOOo
  if 28 - 28: iIii1I11I1II1 + OoOoOO00 . o0oOOo0O0Ooo % i11iIiiIii
  if 58 - 58: I11i / OoooooooOO % oO0o + OoO0O00
  if 58 - 58: O0
  if ( iII1I11 . has_key ( netifaces . AF_INET ) ) :
   Oo0oOo0ooOOOo = iII1I11 [ netifaces . AF_INET ]
   O0oO = 0
   for ooooO0O in Oo0oOo0ooOOOo :
    Oo0oOO0O00 . store_address ( ooooO0O [ "addr" ] )
    if ( Oo0oOO0O00 . is_ipv4_loopback ( ) ) : continue
    if ( Oo0oOO0O00 . is_ipv4_link_local ( ) ) : continue
    if ( Oo0oOO0O00 . address == 0 ) : continue
    O0oO += 1
    Oo0oOO0O00 . instance_id = I111Iii1
    if ( o0o000o == None and
 lisp_db_for_lookups . lookup_cache ( Oo0oOO0O00 , False ) ) : continue
    II1I1I1i1i [ 0 ] = Oo0oOO0O00
    if ( O0oO == ii ) : break
    if 54 - 54: o0oOOo0O0Ooo + I11i - iIii1I11I1II1 % ooOoO0o % IiII
    if 19 - 19: I1ii11iIi11i / iIii1I11I1II1 % i1IIi . OoooooooOO
  if ( iII1I11 . has_key ( netifaces . AF_INET6 ) ) :
   OoO0000o = iII1I11 [ netifaces . AF_INET6 ]
   O0oO = 0
   for ooooO0O in OoO0000o :
    I1IIII1i1 = ooooO0O [ "addr" ]
    o00OOo0o0O . store_address ( I1IIII1i1 )
    if ( o00OOo0o0O . is_ipv6_string_link_local ( I1IIII1i1 ) ) : continue
    if ( o00OOo0o0O . is_ipv6_loopback ( ) ) : continue
    O0oO += 1
    o00OOo0o0O . instance_id = I111Iii1
    if ( o0o000o == None and
 lisp_db_for_lookups . lookup_cache ( o00OOo0o0O , False ) ) : continue
    II1I1I1i1i [ 1 ] = o00OOo0o0O
    if ( O0oO == ii ) : break
    if 57 - 57: ooOoO0o . Oo0Ooo - OoO0O00 - i11iIiiIii * I1Ii111 / o0oOOo0O0Ooo
    if 79 - 79: I1ii11iIi11i + o0oOOo0O0Ooo % Oo0Ooo * o0oOOo0O0Ooo
    if 21 - 21: iII111i
    if 24 - 24: iII111i / ooOoO0o
    if 61 - 61: iIii1I11I1II1 + oO0o
    if 8 - 8: I1Ii111 + OoO0O00
  if ( II1I1I1i1i [ 0 ] == None ) : continue
  if 9 - 9: OOooOOo + o0oOOo0O0Ooo
  II1I1I1i1i [ 2 ] = I1i1II1
  break
  if 8 - 8: OOooOOo * Oo0Ooo / iII111i - OoO0O00 - OoooooooOO
  if 100 - 100: oO0o . iIii1I11I1II1 . iIii1I11I1II1
 oOOo0ooO0 = II1I1I1i1i [ 0 ] . print_address_no_iid ( ) if II1I1I1i1i [ 0 ] else "none"
 ii1i1II11II1i = II1I1I1i1i [ 1 ] . print_address_no_iid ( ) if II1I1I1i1i [ 1 ] else "none"
 I1i1II1 = II1I1I1i1i [ 2 ] if II1I1I1i1i [ 2 ] else "none"
 if 95 - 95: I11i + o0oOOo0O0Ooo * I1ii11iIi11i
 o0o000o = " (user selected)" if o0o000o != None else ""
 if 85 - 85: i11iIiiIii . OoooooooOO - iIii1I11I1II1
 oOOo0ooO0 = red ( oOOo0ooO0 , False )
 ii1i1II11II1i = red ( ii1i1II11II1i , False )
 I1i1II1 = bold ( I1i1II1 , False )
 lprint ( "Local addresses are IPv4: {}, IPv6: {} from device {}{}, iid {}" . format ( oOOo0ooO0 , ii1i1II11II1i , I1i1II1 , o0o000o , I111Iii1 ) )
 if 38 - 38: I11i . I11i * oO0o / OoooooooOO % ooOoO0o
 if 80 - 80: OoO0O00 / IiII * I1IiiI % IiII
 lisp_myrlocs = II1I1I1i1i
 return ( ( II1I1I1i1i [ 0 ] != None ) )
 if 95 - 95: O0 / I11i . I1Ii111
 if 17 - 17: I11i
 if 56 - 56: ooOoO0o * o0oOOo0O0Ooo + I11i
 if 48 - 48: IiII * OoO0O00 % I1Ii111 - I11i
 if 72 - 72: i1IIi % ooOoO0o % IiII % oO0o - oO0o
 if 97 - 97: o0oOOo0O0Ooo * O0 / o0oOOo0O0Ooo * OoO0O00 * Oo0Ooo
 if 38 - 38: I1Ii111
 if 25 - 25: iIii1I11I1II1 % II111iiii / I11i / I1ii11iIi11i
 if 22 - 22: oO0o * iII111i
def lisp_get_all_addresses ( ) :
 iIIIiIi1i = [ ]
 for oOOoo in netifaces . interfaces ( ) :
  try : iiIiiIi = netifaces . ifaddresses ( oOOoo )
  except : continue
  if 66 - 66: II111iiii + OoO0O00
  if ( iiIiiIi . has_key ( netifaces . AF_INET ) ) :
   for ooooO0O in iiIiiIi [ netifaces . AF_INET ] :
    iiiii1ii1 = ooooO0O [ "addr" ]
    if ( iiiii1ii1 . find ( "127.0.0.1" ) != - 1 ) : continue
    iIIIiIi1i . append ( iiiii1ii1 )
    if 19 - 19: OoO0O00 . OoooooooOO * OoO0O00 + IiII + OoooooooOO
    if 19 - 19: Oo0Ooo
  if ( iiIiiIi . has_key ( netifaces . AF_INET6 ) ) :
   for ooooO0O in iiIiiIi [ netifaces . AF_INET6 ] :
    iiiii1ii1 = ooooO0O [ "addr" ]
    if ( iiiii1ii1 == "::1" ) : continue
    if ( iiiii1ii1 [ 0 : 5 ] == "fe80:" ) : continue
    iIIIiIi1i . append ( iiiii1ii1 )
    if 75 - 75: OoooooooOO . OOooOOo + OoO0O00 / Ii1I - I1IiiI % Ii1I
    if 89 - 89: iII111i * iIii1I11I1II1 + i11iIiiIii . OoooooooOO
    if 51 - 51: OOooOOo / ooOoO0o + OoO0O00 % OoOoOO00 / Ii1I
 return ( iIIIiIi1i )
 if 25 - 25: o0oOOo0O0Ooo
 if 25 - 25: ooOoO0o * iII111i / I11i / I11i % o0oOOo0O0Ooo
 if 19 - 19: oO0o - iIii1I11I1II1 / ooOoO0o . OoO0O00 * O0 - O0
 if 41 - 41: i1IIi - I1IiiI
 if 48 - 48: I1IiiI - II111iiii / OoO0O00 + I1IiiI
 if 5 - 5: O0
 if 75 - 75: I1Ii111 + iIii1I11I1II1
 if 19 - 19: I1IiiI + i11iIiiIii . IiII - I11i / Ii1I + o0oOOo0O0Ooo
def lisp_get_all_multicast_rles ( ) :
 II1io0Oo00oOO = [ ]
 I1iiIiiIiiI = commands . getoutput ( 'egrep "rle-address =" ./lisp.config' )
 if ( I1iiIiiIiiI == "" ) : return ( II1io0Oo00oOO )
 if 73 - 73: I11i / OoooooooOO . II111iiii - IiII * ooOoO0o * IiII
 IiI1IiI1iiI1 = I1iiIiiIiiI . split ( "\n" )
 for iI1111i in IiI1IiI1iiI1 :
  if ( iI1111i [ 0 ] == "#" ) : continue
  O000o0 = iI1111i . split ( "rle-address = " ) [ 1 ]
  Iiiii1 = int ( O000o0 . split ( "." ) [ 0 ] )
  if ( Iiiii1 >= 224 and Iiiii1 < 240 ) : II1io0Oo00oOO . append ( O000o0 )
  if 88 - 88: I11i + I1IiiI - I11i / OoooooooOO - i11iIiiIii
 return ( II1io0Oo00oOO )
 if 24 - 24: iIii1I11I1II1
 if 89 - 89: Ii1I / i1IIi - o0oOOo0O0Ooo % I1IiiI . Oo0Ooo - O0
 if 71 - 71: OoO0O00 % I1IiiI - iII111i . iII111i
 if 22 - 22: ooOoO0o / ooOoO0o - Ii1I % I11i . OOooOOo + IiII
 if 64 - 64: i1IIi % I1ii11iIi11i / Ii1I % OoooooooOO
 if 24 - 24: I1Ii111 + OoooooooOO . IiII / OoOoOO00 / I11i
 if 65 - 65: OoooooooOO
 if 18 - 18: O0 - i1IIi . I1Ii111
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
  if 98 - 98: o0oOOo0O0Ooo
  if 73 - 73: Oo0Ooo - iII111i . oO0o % i1IIi . O0
 def encode ( self , nonce ) :
  if 15 - 15: ooOoO0o . iIii1I11I1II1 * I1IiiI % I11i
  if 21 - 21: OoO0O00 - I1IiiI . OoooooooOO
  if 6 - 6: iIii1I11I1II1 - iIii1I11I1II1 % o0oOOo0O0Ooo / iIii1I11I1II1 * I1Ii111
  if 3 - 3: OOooOOo . IiII / Oo0Ooo
  if 89 - 89: OoooooooOO . iIii1I11I1II1 . Oo0Ooo * iIii1I11I1II1 - I1Ii111
  if ( self . outer_source . is_null ( ) ) : return ( None )
  if 92 - 92: OoooooooOO - I1ii11iIi11i - OoooooooOO % I1IiiI % I1IiiI % iIii1I11I1II1
  if 92 - 92: iII111i * O0 % I1Ii111 . iIii1I11I1II1
  if 66 - 66: I11i + Ii1I
  if 48 - 48: I1ii11iIi11i
  if 96 - 96: ooOoO0o . OoooooooOO
  if 39 - 39: OOooOOo + OoO0O00
  if ( nonce == None ) :
   self . lisp_header . nonce ( lisp_get_data_nonce ( ) )
  elif ( self . lisp_header . is_request_nonce ( nonce ) ) :
   self . lisp_header . request_nonce ( nonce )
  else :
   self . lisp_header . nonce ( nonce )
   if 80 - 80: OOooOOo % OoO0O00 / OoOoOO00
  self . lisp_header . instance_id ( self . inner_dest . instance_id )
  if 54 - 54: Oo0Ooo % OoO0O00 - OOooOOo - I11i
  if 71 - 71: ooOoO0o . i11iIiiIii
  if 56 - 56: O0 * iII111i + iII111i * iIii1I11I1II1 / ooOoO0o * I1Ii111
  if 25 - 25: iIii1I11I1II1 . I11i * i11iIiiIii + Oo0Ooo * I11i
  if 67 - 67: iII111i
  if 88 - 88: Oo0Ooo
  self . lisp_header . key_id ( 0 )
  i1ii111i = ( self . lisp_header . get_instance_id ( ) == 0xffffff )
  if ( lisp_data_plane_security and i1ii111i == False ) :
   I1IIII1i1 = self . outer_dest . print_address_no_iid ( ) + ":" + str ( self . encap_port )
   if 42 - 42: OOooOOo % OoooooooOO / IiII
   if ( lisp_crypto_keys_by_rloc_encap . has_key ( I1IIII1i1 ) ) :
    Ii111I11 = lisp_crypto_keys_by_rloc_encap [ I1IIII1i1 ]
    if ( Ii111I11 [ 1 ] ) :
     Ii111I11 [ 1 ] . use_count += 1
     Oo0O0oo , o0O0 = self . encrypt ( Ii111I11 [ 1 ] , I1IIII1i1 )
     if ( o0O0 ) : self . packet = Oo0O0oo
     if 82 - 82: oO0o / OoooooooOO % iII111i
     if 65 - 65: O0 . oO0o
     if 85 - 85: II111iiii
     if 55 - 55: I1ii11iIi11i
     if 76 - 76: oO0o - i11iIiiIii
     if 27 - 27: I1ii11iIi11i - i11iIiiIii % I1Ii111 / Oo0Ooo . Oo0Ooo / OoooooooOO
     if 76 - 76: I11i * OoO0O00 . iIii1I11I1II1 % OoooooooOO % I1ii11iIi11i
     if 39 - 39: II111iiii * OoOoOO00 . O0 * I11i
  self . udp_checksum = 0
  if ( self . encap_port == LISP_DATA_PORT ) :
   if ( lisp_crypto_ephem_port == None ) :
    if ( self . gleaned_dest ) :
     self . udp_sport = LISP_DATA_PORT
    else :
     self . hash_packet ( )
     if 89 - 89: Ii1I - ooOoO0o . I11i - I1Ii111 - I1IiiI
   else :
    self . udp_sport = lisp_crypto_ephem_port
    if 79 - 79: IiII + IiII + Ii1I
  else :
   self . udp_sport = LISP_DATA_PORT
   if 39 - 39: O0 - OoooooooOO
  self . udp_dport = self . encap_port
  self . udp_length = len ( self . packet ) + 16
  if 63 - 63: iIii1I11I1II1 % o0oOOo0O0Ooo * ooOoO0o
  if 79 - 79: O0
  if 32 - 32: II111iiii . O0 + Ii1I / OoOoOO00 / IiII / OOooOOo
  if 15 - 15: I1ii11iIi11i
  if ( self . outer_version == 4 ) :
   I11iI1 = socket . htons ( self . udp_sport )
   oOo00OO0o0 = socket . htons ( self . udp_dport )
  else :
   I11iI1 = self . udp_sport
   oOo00OO0o0 = self . udp_dport
   if 1 - 1: OoooooooOO / O0 + OoOoOO00 + OoOoOO00 . I1Ii111 - OoOoOO00
   if 9 - 9: I1Ii111 * OoooooooOO % I1IiiI / OoOoOO00 * I11i
  oOo00OO0o0 = socket . htons ( self . udp_dport ) if self . outer_version == 4 else self . udp_dport
  if 48 - 48: OoooooooOO . OoOoOO00
  if 65 - 65: oO0o . Oo0Ooo
  i1iIIII1iiIIi = struct . pack ( "HHHH" , I11iI1 , oOo00OO0o0 , socket . htons ( self . udp_length ) ,
 self . udp_checksum )
  if 94 - 94: OoOoOO00 + IiII . ooOoO0o
  if 69 - 69: O0 - O0
  if 41 - 41: IiII % o0oOOo0O0Ooo
  if 67 - 67: O0 % I1Ii111
  III = self . lisp_header . encode ( )
  if 48 - 48: OOooOOo . OOooOOo + i11iIiiIii + I1ii11iIi11i % O0
  if 67 - 67: ooOoO0o / I11i * I1IiiI % OoooooooOO
  if 46 - 46: IiII
  if 12 - 12: o0oOOo0O0Ooo + OoOoOO00 . iIii1I11I1II1 % ooOoO0o + i1IIi . ooOoO0o
  if 43 - 43: Oo0Ooo . ooOoO0o + I1ii11iIi11i * i11iIiiIii
  if ( self . outer_version == 4 ) :
   oO00OOOOOO0o = socket . htons ( self . udp_length + 20 )
   iIII = socket . htons ( 0x4000 )
   OoO0000 = struct . pack ( "BBHHHBBH" , 0x45 , self . outer_tos , oO00OOOOOO0o , 0xdfdf ,
 iIII , self . outer_ttl , 17 , 0 )
   OoO0000 += self . outer_source . pack_address ( )
   OoO0000 += self . outer_dest . pack_address ( )
   OoO0000 = lisp_ip_checksum ( OoO0000 )
  elif ( self . outer_version == 6 ) :
   OoO0000 = ""
   if 11 - 11: OoO0O00 - Ii1I + O0 * OoO0O00
   if 59 - 59: II111iiii
   if 43 - 43: Oo0Ooo + OoooooooOO
   if 47 - 47: ooOoO0o
   if 92 - 92: I11i % i11iIiiIii % Oo0Ooo
   if 23 - 23: II111iiii * iII111i
   if 80 - 80: I1Ii111 / i11iIiiIii + OoooooooOO
  else :
   return ( None )
   if 38 - 38: I1ii11iIi11i % ooOoO0o + i1IIi * OoooooooOO * oO0o
   if 83 - 83: iIii1I11I1II1 - ooOoO0o - I1Ii111 / OoO0O00 - O0
  self . packet = OoO0000 + i1iIIII1iiIIi + III + self . packet
  return ( self )
  if 81 - 81: Ii1I - oO0o * I1ii11iIi11i / I1Ii111
  if 21 - 21: OoO0O00
 def cipher_pad ( self , packet ) :
  O0o0oOOO = len ( packet )
  if ( ( O0o0oOOO % 16 ) != 0 ) :
   IIi11 = ( ( O0o0oOOO / 16 ) + 1 ) * 16
   packet = packet . ljust ( IIi11 )
   if 78 - 78: I1Ii111 / oO0o - iIii1I11I1II1 - OoOoOO00
  return ( packet )
  if 60 - 60: II111iiii
  if 90 - 90: OoOoOO00
 def encrypt ( self , key , addr_str ) :
  if ( key == None or key . shared_key == None ) :
   return ( [ self . packet , False ] )
   if 37 - 37: OoOoOO00 + O0 . O0 * Oo0Ooo % I1Ii111 / iII111i
   if 18 - 18: OoooooooOO
   if 57 - 57: ooOoO0o . OoOoOO00 * o0oOOo0O0Ooo - OoooooooOO
   if 75 - 75: i11iIiiIii / o0oOOo0O0Ooo . IiII . i1IIi . i1IIi / I11i
   if 94 - 94: ooOoO0o + I1IiiI
  Oo0O0oo = self . cipher_pad ( self . packet )
  oOOOoo00oO = key . get_iv ( )
  if 59 - 59: Ii1I / OoOoOO00 * OoO0O00 * iII111i % oO0o
  I11i1II = lisp_get_timestamp ( )
  oOOoooOO = None
  if ( key . cipher_suite == LISP_CS_25519_CHACHA ) :
   I1Iiii1Ii = chacha . ChaCha ( key . encrypt_key , oOOOoo00oO ) . encrypt
  elif ( key . cipher_suite == LISP_CS_25519_GCM ) :
   oooooO00OOO = binascii . unhexlify ( key . encrypt_key )
   try :
    oO00o = AES . new ( oooooO00OOO , AES . MODE_GCM , oOOOoo00oO )
    I1Iiii1Ii = oO00o . encrypt
    oOOoooOO = oO00o . digest
   except :
    lprint ( "You need AES-GCM, do a 'pip install pycryptodome'" )
    return ( [ self . packet , False ] )
    if 90 - 90: I1IiiI % OoooooooOO / iII111i
  else :
   oooooO00OOO = binascii . unhexlify ( key . encrypt_key )
   I1Iiii1Ii = AES . new ( oooooO00OOO , AES . MODE_CBC , oOOOoo00oO ) . encrypt
   if 50 - 50: iIii1I11I1II1 + I1IiiI / I1ii11iIi11i + oO0o / ooOoO0o * I1Ii111
   if 29 - 29: IiII + i11iIiiIii * O0 - iII111i . II111iiii % Ii1I
  III1I = I1Iiii1Ii ( Oo0O0oo )
  if 85 - 85: Oo0Ooo . i11iIiiIii - i11iIiiIii . I1IiiI . OoO0O00 % OoooooooOO
  if ( III1I == None ) : return ( [ self . packet , False ] )
  I11i1II = int ( str ( time . time ( ) - I11i1II ) . split ( "." ) [ 1 ] [ 0 : 6 ] )
  if 20 - 20: I1Ii111 + I1Ii111 * II111iiii * iIii1I11I1II1 % O0 * I1IiiI
  if 62 - 62: OoooooooOO / OoOoOO00 . IiII . IiII % ooOoO0o
  if 42 - 42: o0oOOo0O0Ooo . OOooOOo - ooOoO0o
  if 33 - 33: II111iiii / O0 / IiII - I11i - i1IIi
  if 8 - 8: i11iIiiIii . iII111i / iIii1I11I1II1 / I1ii11iIi11i / IiII - Ii1I
  if 32 - 32: o0oOOo0O0Ooo . i1IIi * Oo0Ooo
  if ( oOOoooOO != None ) : III1I += oOOoooOO ( )
  if 98 - 98: Ii1I - II111iiii / I1IiiI . oO0o * IiII . I11i
  if 25 - 25: i11iIiiIii / OoOoOO00 - I1Ii111 / OoO0O00 . o0oOOo0O0Ooo . o0oOOo0O0Ooo
  if 6 - 6: oO0o . I11i
  if 43 - 43: I1ii11iIi11i + o0oOOo0O0Ooo
  if 50 - 50: oO0o % i1IIi * O0
  self . lisp_header . key_id ( key . key_id )
  III = self . lisp_header . encode ( )
  if 4 - 4: iIii1I11I1II1 . i1IIi
  Oo00oo = key . do_icv ( III + oOOOoo00oO + III1I , oOOOoo00oO )
  if 79 - 79: I1ii11iIi11i / O0 % o0oOOo0O0Ooo
  o0ooo = 4 if ( key . do_poly ) else 8
  if 19 - 19: i11iIiiIii . I1IiiI + II111iiii / OOooOOo . I1ii11iIi11i * ooOoO0o
  oo0O = bold ( "Encrypt" , False )
  Ooooo0O0 = bold ( key . cipher_suite_string , False )
  addr_str = "RLOC: " + red ( addr_str , False )
  oOoO000 = "poly" if key . do_poly else "sha256"
  oOoO000 = bold ( oOoO000 , False )
  Oo00o00Oo = "ICV({}): 0x{}...{}" . format ( oOoO000 , Oo00oo [ 0 : o0ooo ] , Oo00oo [ - o0ooo : : ] )
  dprint ( "{} for key-id: {}, {}, {}, {}-time: {} usec" . format ( oo0O , key . key_id , addr_str , Oo00o00Oo , Ooooo0O0 , I11i1II ) )
  if 50 - 50: ooOoO0o % Oo0Ooo
  if 75 - 75: oO0o * ooOoO0o
  Oo00oo = int ( Oo00oo , 16 )
  if ( key . do_poly ) :
   OO0Oo00OO0oo = byte_swap_64 ( ( Oo00oo >> 64 ) & LISP_8_64_MASK )
   oOO00o0O0 = byte_swap_64 ( Oo00oo & LISP_8_64_MASK )
   Oo00oo = struct . pack ( "QQ" , OO0Oo00OO0oo , oOO00o0O0 )
  else :
   OO0Oo00OO0oo = byte_swap_64 ( ( Oo00oo >> 96 ) & LISP_8_64_MASK )
   oOO00o0O0 = byte_swap_64 ( ( Oo00oo >> 32 ) & LISP_8_64_MASK )
   iIIii1iiiIiiI = socket . htonl ( Oo00oo & 0xffffffff )
   Oo00oo = struct . pack ( "QQI" , OO0Oo00OO0oo , oOO00o0O0 , iIIii1iiiIiiI )
   if 67 - 67: II111iiii
   if 36 - 36: OOooOOo * Ii1I
  return ( [ oOOOoo00oO + III1I + Oo00oo , True ] )
  if 16 - 16: II111iiii
  if 100 - 100: O0 - i1IIi
 def decrypt ( self , packet , header_length , key , addr_str ) :
  if 48 - 48: oO0o % ooOoO0o + O0
  if 27 - 27: I1ii11iIi11i / OOooOOo
  if 33 - 33: OoooooooOO % I1ii11iIi11i . O0 / I1ii11iIi11i
  if 63 - 63: IiII + iIii1I11I1II1 + I1IiiI + I1Ii111
  if 72 - 72: OoO0O00 + i11iIiiIii + I1ii11iIi11i
  if 96 - 96: oO0o % i1IIi / o0oOOo0O0Ooo
  if ( key . do_poly ) :
   OO0Oo00OO0oo , oOO00o0O0 = struct . unpack ( "QQ" , packet [ - 16 : : ] )
   Ii1IIi11 = byte_swap_64 ( OO0Oo00OO0oo ) << 64
   Ii1IIi11 |= byte_swap_64 ( oOO00o0O0 )
   Ii1IIi11 = lisp_hex_string ( Ii1IIi11 ) . zfill ( 32 )
   packet = packet [ 0 : - 16 ]
   o0ooo = 4
   i1 = bold ( "poly" , False )
  else :
   OO0Oo00OO0oo , oOO00o0O0 , iIIii1iiiIiiI = struct . unpack ( "QQI" , packet [ - 20 : : ] )
   Ii1IIi11 = byte_swap_64 ( OO0Oo00OO0oo ) << 96
   Ii1IIi11 |= byte_swap_64 ( oOO00o0O0 ) << 32
   Ii1IIi11 |= socket . htonl ( iIIii1iiiIiiI )
   Ii1IIi11 = lisp_hex_string ( Ii1IIi11 ) . zfill ( 40 )
   packet = packet [ 0 : - 20 ]
   o0ooo = 8
   i1 = bold ( "sha" , False )
   if 65 - 65: II111iiii . I1IiiI + O0
  III = self . lisp_header . encode ( )
  if 75 - 75: O0 % iIii1I11I1II1 / OoOoOO00 % OOooOOo / IiII
  if 31 - 31: i11iIiiIii * OoOoOO00
  if 69 - 69: i11iIiiIii
  if 61 - 61: O0
  if ( key . cipher_suite == LISP_CS_25519_CHACHA ) :
   iIiiI111I11 = 8
   Ooooo0O0 = bold ( "chacha" , False )
  elif ( key . cipher_suite == LISP_CS_25519_GCM ) :
   iIiiI111I11 = 12
   Ooooo0O0 = bold ( "aes-gcm" , False )
  else :
   iIiiI111I11 = 16
   Ooooo0O0 = bold ( "aes-cbc" , False )
   if 86 - 86: oO0o + iII111i / OoooooooOO - I11i
  oOOOoo00oO = packet [ 0 : iIiiI111I11 ]
  if 55 - 55: OOooOOo / OoOoOO00 * OOooOOo
  if 40 - 40: OoO0O00 . i11iIiiIii + I1ii11iIi11i + I1IiiI . oO0o
  if 90 - 90: I1Ii111 . OoOoOO00 * II111iiii % ooOoO0o
  if 36 - 36: I1IiiI - Oo0Ooo % OOooOOo . I11i + I11i + Ii1I
  II1II = key . do_icv ( III + packet , oOOOoo00oO )
  if 48 - 48: I1Ii111 - o0oOOo0O0Ooo % I1IiiI . ooOoO0o
  Ii1iii = "0x{}...{}" . format ( Ii1IIi11 [ 0 : o0ooo ] , Ii1IIi11 [ - o0ooo : : ] )
  o000o0o00Oo = "0x{}...{}" . format ( II1II [ 0 : o0ooo ] , II1II [ - o0ooo : : ] )
  if 62 - 62: iII111i
  if ( II1II != Ii1IIi11 ) :
   self . packet_error = "ICV-error"
   I11i1I1Ii = Ooooo0O0 + "/" + i1
   iii11 = bold ( "ICV failed ({})" . format ( I11i1I1Ii ) , False )
   Oo00o00Oo = "packet-ICV {} != computed-ICV {}" . format ( Ii1iii , o000o0o00Oo )
   dprint ( ( "{} from RLOC {}, receive-port: {}, key-id: {}, " + "packet dropped, {}" ) . format ( iii11 , red ( addr_str , False ) ,
   # oO0o - OOooOOo
 self . udp_sport , key . key_id , Oo00o00Oo ) )
   dprint ( "{}" . format ( key . print_keys ( ) ) )
   if 21 - 21: Oo0Ooo * o0oOOo0O0Ooo + OoooooooOO . I1Ii111 % oO0o
   if 50 - 50: OoOoOO00 - oO0o + iIii1I11I1II1 - OoO0O00 . Oo0Ooo
   if 8 - 8: Ii1I
   if 30 - 30: i1IIi
   if 61 - 61: I1Ii111 / I1Ii111
   if 26 - 26: IiII . O0 * IiII - o0oOOo0O0Ooo * Oo0Ooo
   lisp_retry_decap_keys ( addr_str , III + packet , oOOOoo00oO , Ii1IIi11 )
   return ( [ None , False ] )
   if 6 - 6: OoOoOO00 . II111iiii * I1IiiI . I1IiiI / Ii1I
   if 14 - 14: I1Ii111 % IiII - O0 / I1Ii111
   if 91 - 91: i11iIiiIii % I1Ii111 * oO0o - I1ii11iIi11i . I1Ii111
   if 28 - 28: i11iIiiIii
   if 51 - 51: I1IiiI + ooOoO0o * O0 . Ii1I
  packet = packet [ iIiiI111I11 : : ]
  if 82 - 82: OOooOOo * I1ii11iIi11i % Ii1I . OOooOOo
  if 43 - 43: OoO0O00 . ooOoO0o * Oo0Ooo
  if 20 - 20: i1IIi . i1IIi - I11i
  if 89 - 89: ooOoO0o - I11i . O0 % OoooooooOO . i11iIiiIii
  I11i1II = lisp_get_timestamp ( )
  if ( key . cipher_suite == LISP_CS_25519_CHACHA ) :
   IiIIiII1I = chacha . ChaCha ( key . encrypt_key , oOOOoo00oO ) . decrypt
  elif ( key . cipher_suite == LISP_CS_25519_GCM ) :
   oooooO00OOO = binascii . unhexlify ( key . encrypt_key )
   try :
    IiIIiII1I = AES . new ( oooooO00OOO , AES . MODE_GCM , oOOOoo00oO ) . decrypt
   except :
    self . packet_error = "no-decrypt-key"
    lprint ( "You need AES-GCM, do a 'pip install pycryptodome'" )
    return ( [ None , False ] )
    if 92 - 92: I1Ii111 % Ii1I
  else :
   if ( ( len ( packet ) % 16 ) != 0 ) :
    dprint ( "Ciphertext not multiple of 16 bytes, packet dropped" )
    return ( [ None , False ] )
    if 30 - 30: II111iiii - o0oOOo0O0Ooo % I1Ii111 . I11i
   oooooO00OOO = binascii . unhexlify ( key . encrypt_key )
   IiIIiII1I = AES . new ( oooooO00OOO , AES . MODE_CBC , oOOOoo00oO ) . decrypt
   if 63 - 63: iIii1I11I1II1 / ooOoO0o
   if 24 - 24: Oo0Ooo / iIii1I11I1II1 % OOooOOo * OoOoOO00 - iIii1I11I1II1
  iI1ii = IiIIiII1I ( packet )
  I11i1II = int ( str ( time . time ( ) - I11i1II ) . split ( "." ) [ 1 ] [ 0 : 6 ] )
  if 61 - 61: Oo0Ooo * i1IIi . OoooooooOO
  if 44 - 44: I1IiiI
  if 55 - 55: oO0o . I1Ii111 * I1Ii111
  if 82 - 82: I1IiiI % OoO0O00 % I11i + I11i
  oo0O = bold ( "Decrypt" , False )
  addr_str = "RLOC: " + red ( addr_str , False )
  oOoO000 = "poly" if key . do_poly else "sha256"
  oOoO000 = bold ( oOoO000 , False )
  Oo00o00Oo = "ICV({}): {}" . format ( oOoO000 , Ii1iii )
  dprint ( "{} for key-id: {}, {}, {} (good), {}-time: {} usec" . format ( oo0O , key . key_id , addr_str , Oo00o00Oo , Ooooo0O0 , I11i1II ) )
  if 6 - 6: Oo0Ooo
  if 73 - 73: I1Ii111 * I1ii11iIi11i + o0oOOo0O0Ooo - Oo0Ooo . I11i
  if 93 - 93: i11iIiiIii
  if 80 - 80: i1IIi . I1IiiI - oO0o + OOooOOo + iII111i % oO0o
  if 13 - 13: II111iiii / OoOoOO00 / OoOoOO00 + ooOoO0o
  if 49 - 49: O0 / II111iiii * I1IiiI - OoooooooOO . II111iiii % IiII
  if 13 - 13: oO0o . iIii1I11I1II1 . OOooOOo . IiII
  self . packet = self . packet [ 0 : header_length ]
  return ( [ iI1ii , True ] )
  if 58 - 58: I11i
  if 7 - 7: II111iiii / IiII % I11i + I1IiiI - O0
 def fragment_outer ( self , outer_hdr , inner_packet ) :
  IiI1 = 1000
  if 42 - 42: iIii1I11I1II1 * Ii1I / OoO0O00 + OOooOOo
  if 48 - 48: OoooooooOO - I1Ii111 . i11iIiiIii * iII111i - Ii1I - o0oOOo0O0Ooo
  if 59 - 59: iII111i / I11i . Oo0Ooo
  if 100 - 100: O0
  if 94 - 94: I1ii11iIi11i - o0oOOo0O0Ooo
  IIiIIIi1iii1 = [ ]
  oOo0 = 0
  O0o0oOOO = len ( inner_packet )
  while ( oOo0 < O0o0oOOO ) :
   iIII = inner_packet [ oOo0 : : ]
   if ( len ( iIII ) > IiI1 ) : iIII = iIII [ 0 : IiI1 ]
   IIiIIIi1iii1 . append ( iIII )
   oOo0 += len ( iIII )
   if 37 - 37: iIii1I11I1II1 % I11i / IiII
   if 37 - 37: I1Ii111 - oO0o - OoO0O00
   if 42 - 42: iIii1I11I1II1 % Ii1I - I1ii11iIi11i + iIii1I11I1II1
   if 27 - 27: O0 / OoO0O00
   if 99 - 99: Ii1I - IiII * iIii1I11I1II1 . II111iiii
   if 56 - 56: iIii1I11I1II1 % OoO0O00 . ooOoO0o % IiII . I1Ii111 * Oo0Ooo
  Ii11II1i1I = [ ]
  oOo0 = 0
  for iIII in IIiIIIi1iii1 :
   if 45 - 45: iII111i + OoOoOO00 / iIii1I11I1II1
   if 19 - 19: I1Ii111 * IiII . Oo0Ooo - Oo0Ooo - OoO0O00
   if 51 - 51: O0 * I1IiiI / IiII - I1ii11iIi11i
   if 85 - 85: I1IiiI / iIii1I11I1II1 / iII111i
   OOOO = oOo0 if ( iIII == IIiIIIi1iii1 [ - 1 ] ) else 0x2000 + oOo0
   OOOO = socket . htons ( OOOO )
   outer_hdr = outer_hdr [ 0 : 6 ] + struct . pack ( "H" , OOOO ) + outer_hdr [ 8 : : ]
   if 10 - 10: II111iiii . OoO0O00
   if 89 - 89: ooOoO0o * Ii1I
   if 93 - 93: i1IIi . Ii1I * I1Ii111 . ooOoO0o
   if 54 - 54: iII111i . i1IIi . I1ii11iIi11i * o0oOOo0O0Ooo % iII111i
   i1IIi111iI = socket . htons ( len ( iIII ) + 20 )
   outer_hdr = outer_hdr [ 0 : 2 ] + struct . pack ( "H" , i1IIi111iI ) + outer_hdr [ 4 : : ]
   outer_hdr = lisp_ip_checksum ( outer_hdr )
   Ii11II1i1I . append ( outer_hdr + iIII )
   oOo0 += len ( iIII ) / 8
   if 8 - 8: I1IiiI % II111iiii - o0oOOo0O0Ooo - I11i % I1IiiI
  return ( Ii11II1i1I )
  if 93 - 93: Ii1I * iII111i / OOooOOo
  if 88 - 88: oO0o
 def send_icmp_too_big ( self , inner_packet ) :
  global lisp_last_icmp_too_big_sent
  global lisp_icmp_raw_socket
  if 1 - 1: Oo0Ooo
  ooOO0o = time . time ( ) - lisp_last_icmp_too_big_sent
  if ( ooOO0o < LISP_ICMP_TOO_BIG_RATE_LIMIT ) :
   lprint ( "Rate limit sending ICMP Too-Big to {}" . format ( self . inner_source . print_address_no_iid ( ) ) )
   if 95 - 95: OoooooooOO / I11i % OoooooooOO / ooOoO0o * IiII
   return ( False )
   if 75 - 75: O0
   if 56 - 56: OoO0O00 / II111iiii
   if 39 - 39: OoOoOO00 - OoooooooOO - i1IIi / II111iiii
   if 49 - 49: Oo0Ooo + O0 + IiII . II111iiii % ooOoO0o
   if 33 - 33: OoOoOO00 . iIii1I11I1II1 / I11i % Ii1I
   if 49 - 49: OoO0O00 + II111iiii / IiII - O0 % Ii1I
   if 27 - 27: OoO0O00 + Oo0Ooo
   if 92 - 92: I1IiiI % iII111i
   if 31 - 31: OoooooooOO - oO0o / I1Ii111
   if 62 - 62: i11iIiiIii - I11i
   if 81 - 81: I11i
   if 92 - 92: OOooOOo - Oo0Ooo - OoooooooOO / IiII - i1IIi
   if 81 - 81: i1IIi / I1Ii111 % i11iIiiIii . iIii1I11I1II1 * OoOoOO00 + OoooooooOO
   if 31 - 31: i1IIi % II111iiii
   if 13 - 13: iIii1I11I1II1 - II111iiii % O0 . Ii1I % OoO0O00
  Ii11iIiiI = socket . htons ( 1400 )
  oOo0Oo0O0O = struct . pack ( "BBHHH" , 3 , 4 , 0 , 0 , Ii11iIiiI )
  oOo0Oo0O0O += inner_packet [ 0 : 20 + 8 ]
  oOo0Oo0O0O = lisp_icmp_checksum ( oOo0Oo0O0O )
  if 3 - 3: II111iiii / OOooOOo
  if 48 - 48: ooOoO0o . I1ii11iIi11i
  if 49 - 49: i1IIi - OoOoOO00 . Oo0Ooo + iIii1I11I1II1 - ooOoO0o / Oo0Ooo
  if 24 - 24: oO0o - iII111i / ooOoO0o
  if 10 - 10: OoOoOO00 * i1IIi
  if 15 - 15: I11i + i1IIi - II111iiii % I1IiiI
  if 34 - 34: I1IiiI
  o0OoOo0O00 = inner_packet [ 12 : 16 ]
  iI1i1iI1iI = self . inner_source . print_address_no_iid ( )
  I1IIiIi = self . outer_source . pack_address ( )
  if 93 - 93: oO0o - OOooOOo + o0oOOo0O0Ooo . oO0o / I11i
  if 52 - 52: I1Ii111 + I1Ii111
  if 73 - 73: o0oOOo0O0Ooo . i11iIiiIii % OoooooooOO + ooOoO0o . OoooooooOO / OOooOOo
  if 54 - 54: OoOoOO00 . OoooooooOO
  if 36 - 36: oO0o / II111iiii * IiII % I1ii11iIi11i
  if 31 - 31: II111iiii + OOooOOo - OoooooooOO . I11i
  if 28 - 28: Ii1I . I1ii11iIi11i
  if 77 - 77: I1ii11iIi11i % II111iiii
  oO00OOOOOO0o = socket . htons ( 20 + 36 )
  i1iiii = struct . pack ( "BBHHHBBH" , 0x45 , 0 , oO00OOOOOO0o , 0 , 0 , 32 , 1 , 0 ) + I1IIiIi + o0OoOo0O00
  i1iiii = lisp_ip_checksum ( i1iiii )
  i1iiii = self . fix_outer_header ( i1iiii )
  i1iiii += oOo0Oo0O0O
  OOo00o0oo0 = bold ( "Too-Big" , False )
  lprint ( "Send ICMP {} to {}, mtu 1400: {}" . format ( OOo00o0oo0 , iI1i1iI1iI ,
 lisp_format_packet ( i1iiii ) ) )
  if 33 - 33: o0oOOo0O0Ooo . OOooOOo + o0oOOo0O0Ooo / I1ii11iIi11i . Oo0Ooo + OoOoOO00
  try :
   lisp_icmp_raw_socket . sendto ( i1iiii , ( iI1i1iI1iI , 0 ) )
  except socket . error , o0o000 :
   lprint ( "lisp_icmp_raw_socket.sendto() failed: {}" . format ( o0o000 ) )
   return ( False )
   if 32 - 32: IiII - ooOoO0o * iII111i * I11i
   if 84 - 84: Ii1I + I1ii11iIi11i % I1IiiI + i11iIiiIii
   if 37 - 37: I11i % I1ii11iIi11i / ooOoO0o
   if 94 - 94: I11i / OoO0O00 . o0oOOo0O0Ooo
   if 1 - 1: Oo0Ooo . II111iiii
   if 93 - 93: II111iiii . i11iIiiIii + II111iiii % oO0o
  lisp_last_icmp_too_big_sent = lisp_get_timestamp ( )
  return ( True )
  if 98 - 98: I1Ii111 * oO0o * OoOoOO00 + Ii1I * iII111i
 def fragment ( self ) :
  global lisp_icmp_raw_socket
  global lisp_ignore_df_bit
  if 4 - 4: IiII
  Oo0O0oo = self . fix_outer_header ( self . packet )
  if 16 - 16: iIii1I11I1II1 * iII111i + oO0o . O0 . o0oOOo0O0Ooo
  if 99 - 99: i11iIiiIii - iII111i
  if 85 - 85: I1Ii111 % I1ii11iIi11i
  if 95 - 95: OoO0O00 * OOooOOo * iII111i . o0oOOo0O0Ooo
  if 73 - 73: OoO0O00
  if 28 - 28: OoooooooOO - I11i
  O0o0oOOO = len ( Oo0O0oo )
  if ( O0o0oOOO <= 1500 ) : return ( [ Oo0O0oo ] , "Fragment-None" )
  if 84 - 84: II111iiii
  Oo0O0oo = self . packet
  if 36 - 36: OOooOOo - OoOoOO00 - iIii1I11I1II1
  if 10 - 10: I1ii11iIi11i / Ii1I * i1IIi % O0 + I11i
  if 25 - 25: I1Ii111 - Ii1I / O0 . OoooooooOO % I1IiiI . i1IIi
  if 19 - 19: II111iiii / II111iiii % I1ii11iIi11i + oO0o + oO0o + iII111i
  if 4 - 4: o0oOOo0O0Ooo + I11i / iII111i + i1IIi % o0oOOo0O0Ooo % iII111i
  if ( self . inner_version != 4 ) :
   ooOooOooOOO = random . randint ( 0 , 0xffff )
   oO0oOOOo0o = Oo0O0oo [ 0 : 4 ] + struct . pack ( "H" , ooOooOooOOO ) + Oo0O0oo [ 6 : 20 ]
   i1II1iII1 = Oo0O0oo [ 20 : : ]
   Ii11II1i1I = self . fragment_outer ( oO0oOOOo0o , i1II1iII1 )
   return ( Ii11II1i1I , "Fragment-Outer" )
   if 31 - 31: Ii1I * o0oOOo0O0Ooo * Ii1I + OoO0O00 * o0oOOo0O0Ooo . I1Ii111
   if 89 - 89: OoooooooOO * Ii1I * I1IiiI . ooOoO0o * Ii1I / iII111i
   if 46 - 46: i11iIiiIii
   if 15 - 15: O0 / i1IIi / i1IIi . iII111i % OoOoOO00 + I1IiiI
   if 48 - 48: I1Ii111 % iII111i % Ii1I % iIii1I11I1II1 . Ii1I
  I11IIiI1IiI1 = 56 if ( self . outer_version == 6 ) else 36
  oO0oOOOo0o = Oo0O0oo [ 0 : I11IIiI1IiI1 ]
  iI11IiiiIII = Oo0O0oo [ I11IIiI1IiI1 : I11IIiI1IiI1 + 20 ]
  i1II1iII1 = Oo0O0oo [ I11IIiI1IiI1 + 20 : : ]
  if 43 - 43: iII111i + i11iIiiIii
  if 96 - 96: OOooOOo . OoOoOO00 * O0
  if 69 - 69: IiII
  if 81 - 81: I1IiiI
  if 58 - 58: OoOoOO00 + OoO0O00 * Ii1I
  iI1IIIIII = struct . unpack ( "H" , iI11IiiiIII [ 6 : 8 ] ) [ 0 ]
  iI1IIIIII = socket . ntohs ( iI1IIIIII )
  if ( iI1IIIIII & 0x4000 ) :
   if ( lisp_icmp_raw_socket != None ) :
    OO0oO0Oo = Oo0O0oo [ I11IIiI1IiI1 : : ]
    if ( self . send_icmp_too_big ( OO0oO0Oo ) ) : return ( [ ] , None )
    if 82 - 82: i11iIiiIii + iIii1I11I1II1 / Oo0Ooo + OOooOOo * II111iiii
   if ( lisp_ignore_df_bit ) :
    iI1IIIIII &= ~ 0x4000
   else :
    iIiIiiIIIi1 = bold ( "DF-bit set" , False )
    dprint ( "{} in inner header, packet discarded" . format ( iIiIiiIIIi1 ) )
    return ( [ ] , "Fragment-None-DF-bit" )
    if 25 - 25: O0
    if 73 - 73: II111iiii + OOooOOo * iII111i / iII111i
    if 74 - 74: O0 + iIii1I11I1II1 + oO0o * IiII
  oOo0 = 0
  O0o0oOOO = len ( i1II1iII1 )
  Ii11II1i1I = [ ]
  while ( oOo0 < O0o0oOOO ) :
   Ii11II1i1I . append ( i1II1iII1 [ oOo0 : oOo0 + 1400 ] )
   oOo0 += 1400
   if 39 - 39: I1Ii111 . OoO0O00 % ooOoO0o . OOooOOo / iII111i * OoO0O00
   if 12 - 12: I1IiiI / o0oOOo0O0Ooo
   if 86 - 86: Oo0Ooo % OoOoOO00
   if 77 - 77: Ii1I % OOooOOo / oO0o
   if 91 - 91: OoO0O00 / OoO0O00 . II111iiii . ooOoO0o - I1IiiI
  IIiIIIi1iii1 = Ii11II1i1I
  Ii11II1i1I = [ ]
  iii11OO0oO = True if iI1IIIIII & 0x2000 else False
  iI1IIIIII = ( iI1IIIIII & 0x1fff ) * 8
  for iIII in IIiIIIi1iii1 :
   if 35 - 35: I11i + OOooOOo / OOooOOo
   if 26 - 26: IiII
   if 97 - 97: I1IiiI - ooOoO0o / II111iiii + I1IiiI
   if 68 - 68: oO0o
   i1i1IIi = iI1IIIIII / 8
   if ( iii11OO0oO ) :
    i1i1IIi |= 0x2000
   elif ( iIII != IIiIIIi1iii1 [ - 1 ] ) :
    i1i1IIi |= 0x2000
    if 93 - 93: oO0o
   i1i1IIi = socket . htons ( i1i1IIi )
   iI11IiiiIII = iI11IiiiIII [ 0 : 6 ] + struct . pack ( "H" , i1i1IIi ) + iI11IiiiIII [ 8 : : ]
   if 85 - 85: i1IIi
   if 100 - 100: OoooooooOO / I11i % OoO0O00 + Ii1I
   if 42 - 42: Oo0Ooo / IiII . Ii1I * I1IiiI
   if 54 - 54: OoOoOO00 * iII111i + OoO0O00
   if 93 - 93: o0oOOo0O0Ooo / I1IiiI
   if 47 - 47: Oo0Ooo * OOooOOo
   O0o0oOOO = len ( iIII )
   iI1IIIIII += O0o0oOOO
   i1IIi111iI = socket . htons ( O0o0oOOO + 20 )
   iI11IiiiIII = iI11IiiiIII [ 0 : 2 ] + struct . pack ( "H" , i1IIi111iI ) + iI11IiiiIII [ 4 : 10 ] + struct . pack ( "H" , 0 ) + iI11IiiiIII [ 12 : : ]
   if 98 - 98: oO0o - oO0o . ooOoO0o
   iI11IiiiIII = lisp_ip_checksum ( iI11IiiiIII )
   OooOOoO00OO00 = iI11IiiiIII + iIII
   if 17 - 17: OoooooooOO * I1Ii111 * I1IiiI
   if 30 - 30: OoOoOO00 / oO0o / Ii1I * o0oOOo0O0Ooo * oO0o . I1IiiI
   if 93 - 93: OoOoOO00
   if 97 - 97: i11iIiiIii
   if 68 - 68: IiII * OoO0O00 . I11i / Ii1I . o0oOOo0O0Ooo - i11iIiiIii
   O0o0oOOO = len ( OooOOoO00OO00 )
   if ( self . outer_version == 4 ) :
    i1IIi111iI = O0o0oOOO + I11IIiI1IiI1
    O0o0oOOO += 16
    oO0oOOOo0o = oO0oOOOo0o [ 0 : 2 ] + struct . pack ( "H" , i1IIi111iI ) + oO0oOOOo0o [ 4 : : ]
    if 49 - 49: Oo0Ooo / Ii1I % I11i + oO0o - OoO0O00
    oO0oOOOo0o = lisp_ip_checksum ( oO0oOOOo0o )
    OooOOoO00OO00 = oO0oOOOo0o + OooOOoO00OO00
    OooOOoO00OO00 = self . fix_outer_header ( OooOOoO00OO00 )
    if 13 - 13: II111iiii
    if 83 - 83: OoooooooOO . I1IiiI + Ii1I * O0 / oO0o
    if 8 - 8: i1IIi + II111iiii / Ii1I + I1ii11iIi11i % Ii1I - iIii1I11I1II1
    if 29 - 29: Oo0Ooo + II111iiii
    if 95 - 95: oO0o
   i11ii = I11IIiI1IiI1 - 12
   i1IIi111iI = socket . htons ( O0o0oOOO )
   OooOOoO00OO00 = OooOOoO00OO00 [ 0 : i11ii ] + struct . pack ( "H" , i1IIi111iI ) + OooOOoO00OO00 [ i11ii + 2 : : ]
   if 39 - 39: i1IIi . I1ii11iIi11i / I11i / I11i
   Ii11II1i1I . append ( OooOOoO00OO00 )
   if 100 - 100: OoooooooOO - OoooooooOO + IiII
  return ( Ii11II1i1I , "Fragment-Inner" )
  if 32 - 32: OoOoOO00 * o0oOOo0O0Ooo / OoooooooOO
  if 90 - 90: I1Ii111
 def fix_outer_header ( self , packet ) :
  if 35 - 35: II111iiii / Ii1I
  if 79 - 79: OoOoOO00 + I1Ii111 * iII111i * Ii1I
  if 53 - 53: OOooOOo / Oo0Ooo
  if 10 - 10: I1ii11iIi11i . o0oOOo0O0Ooo
  if 75 - 75: O0 * i1IIi - I11i / OOooOOo % OOooOOo / OoOoOO00
  if 5 - 5: O0 - iII111i / I1Ii111 . o0oOOo0O0Ooo
  if 7 - 7: I1ii11iIi11i - OoOoOO00
  if 54 - 54: oO0o / iIii1I11I1II1 / OoooooooOO . i1IIi - OoOoOO00
  if ( self . outer_version == 4 or self . inner_version == 4 ) :
   if ( lisp_is_macos ( ) ) :
    packet = packet [ 0 : 2 ] + packet [ 3 ] + packet [ 2 ] + packet [ 4 : 6 ] + packet [ 7 ] + packet [ 6 ] + packet [ 8 : : ]
    if 57 - 57: iIii1I11I1II1 * Ii1I * iII111i / oO0o
   else :
    packet = packet [ 0 : 2 ] + packet [ 3 ] + packet [ 2 ] + packet [ 4 : : ]
    if 46 - 46: Ii1I
    if 61 - 61: o0oOOo0O0Ooo / ooOoO0o - II111iiii
  return ( packet )
  if 87 - 87: I1ii11iIi11i / I1IiiI
  if 45 - 45: OoOoOO00 * ooOoO0o / OoooooooOO + OoO0O00 . I1Ii111 / OoO0O00
 def send_packet ( self , lisp_raw_socket , dest ) :
  if ( lisp_flow_logging and dest != self . inner_dest ) : self . log_flow ( True )
  if 64 - 64: Ii1I / i1IIi % I1IiiI - o0oOOo0O0Ooo
  dest = dest . print_address_no_iid ( )
  Ii11II1i1I , iIii111Ii = self . fragment ( )
  if 96 - 96: Ii1I - II111iiii % OoOoOO00 * I1IiiI * I1IiiI . Oo0Ooo
  for OooOOoO00OO00 in Ii11II1i1I :
   if ( len ( Ii11II1i1I ) != 1 ) :
    self . packet = OooOOoO00OO00
    self . print_packet ( iIii111Ii , True )
    if 75 - 75: Oo0Ooo + Ii1I + OoO0O00
    if 97 - 97: ooOoO0o % i11iIiiIii % I11i
   try : lisp_raw_socket . sendto ( OooOOoO00OO00 , ( dest , 0 ) )
   except socket . error , o0o000 :
    lprint ( "socket.sendto() failed: {}" . format ( o0o000 ) )
    if 21 - 21: Oo0Ooo / Ii1I / I1ii11iIi11i / i1IIi / o0oOOo0O0Ooo
    if 86 - 86: i1IIi
    if 33 - 33: OoOoOO00 % i11iIiiIii * OOooOOo
    if 69 - 69: II111iiii + Oo0Ooo - oO0o . Oo0Ooo / iIii1I11I1II1 * iIii1I11I1II1
 def send_l2_packet ( self , l2_socket , mac_header ) :
  if ( l2_socket == None ) :
   lprint ( "No layer-2 socket, drop IPv6 packet" )
   return
   if 75 - 75: OoO0O00 % OoooooooOO
  if ( mac_header == None ) :
   lprint ( "Could not build MAC header, drop IPv6 packet" )
   return
   if 16 - 16: O0 / i1IIi
   if 58 - 58: o0oOOo0O0Ooo / i11iIiiIii / O0 % I11i % I1IiiI
  Oo0O0oo = mac_header + self . packet
  if 86 - 86: IiII + OoOoOO00 / I1IiiI + I11i % I11i / i11iIiiIii
  if 12 - 12: OoOoOO00 + o0oOOo0O0Ooo . I1Ii111
  if 52 - 52: OoO0O00
  if 4 - 4: Ii1I % I1ii11iIi11i + I11i - I1ii11iIi11i
  if 98 - 98: Ii1I - O0 * oO0o * Ii1I * Ii1I
  if 44 - 44: IiII + I11i
  if 66 - 66: oO0o
  if 34 - 34: iII111i % i11iIiiIii + i11iIiiIii - iII111i
  if 2 - 2: II111iiii + i1IIi
  if 68 - 68: OOooOOo + Ii1I
  if 58 - 58: IiII * Ii1I . i1IIi
  l2_socket . write ( Oo0O0oo )
  return
  if 19 - 19: oO0o
  if 85 - 85: ooOoO0o - I1IiiI / i1IIi / OoO0O00 / II111iiii
 def bridge_l2_packet ( self , eid , db ) :
  try : oo0O0O = db . dynamic_eids [ eid . print_address_no_iid ( ) ]
  except : return
  try : oOOoo = lisp_myinterfaces [ oo0O0O . interface ]
  except : return
  try :
   socket = oOOoo . get_bridge_socket ( )
   if ( socket == None ) : return
  except : return
  if 45 - 45: Oo0Ooo % Oo0Ooo + Oo0Ooo / O0 % OoooooooOO
  try : socket . send ( self . packet )
  except socket . error , o0o000 :
   lprint ( "bridge_l2_packet(): socket.send() failed: {}" . format ( o0o000 ) )
   if 92 - 92: Ii1I . OoOoOO00 . I11i - OoooooooOO / ooOoO0o
   if 80 - 80: iIii1I11I1II1 / i11iIiiIii + iII111i
   if 41 - 41: I1Ii111 + OoO0O00 * I1IiiI * O0 * Oo0Ooo - OoOoOO00
 def is_lisp_packet ( self , packet ) :
  i1iIIII1iiIIi = ( struct . unpack ( "B" , packet [ 9 ] ) [ 0 ] == LISP_UDP_PROTOCOL )
  if ( i1iIIII1iiIIi == False ) : return ( False )
  if 96 - 96: I1IiiI - iIii1I11I1II1
  Ii1 = struct . unpack ( "H" , packet [ 22 : 24 ] ) [ 0 ]
  if ( socket . ntohs ( Ii1 ) == LISP_DATA_PORT ) : return ( True )
  Ii1 = struct . unpack ( "H" , packet [ 20 : 22 ] ) [ 0 ]
  if ( socket . ntohs ( Ii1 ) == LISP_DATA_PORT ) : return ( True )
  return ( False )
  if 77 - 77: iII111i
  if 87 - 87: OoO0O00 + OoooooooOO . ooOoO0o * I11i
 def decode ( self , is_lisp_packet , lisp_ipc_socket , stats ) :
  self . packet_error = ""
  Oo0O0oo = self . packet
  oooOoO0oo0o0 = len ( Oo0O0oo )
  IiIIIii1i1iI = OoOOoO0o = True
  if 66 - 66: I11i - I11i + IiII
  if 20 - 20: I1Ii111 . i1IIi
  if 9 - 9: OoO0O00
  if 89 - 89: i1IIi
  I11II = 0
  OO0OO000 = 0
  if ( is_lisp_packet ) :
   OO0OO000 = self . lisp_header . get_instance_id ( )
   OOO = struct . unpack ( "B" , Oo0O0oo [ 0 : 1 ] ) [ 0 ]
   self . outer_version = OOO >> 4
   if ( self . outer_version == 4 ) :
    if 58 - 58: I1Ii111 . i11iIiiIii + OoooooooOO / i11iIiiIii . OoooooooOO % I1IiiI
    if 58 - 58: oO0o + I1ii11iIi11i % OoOoOO00
    if 22 - 22: iIii1I11I1II1 - Ii1I / I1IiiI * IiII
    if 26 - 26: o0oOOo0O0Ooo + OOooOOo - o0oOOo0O0Ooo + Oo0Ooo . oO0o
    if 97 - 97: i1IIi
    ii1iI1i1 = struct . unpack ( "H" , Oo0O0oo [ 10 : 12 ] ) [ 0 ]
    Oo0O0oo = lisp_ip_checksum ( Oo0O0oo )
    Iiiii111 = struct . unpack ( "H" , Oo0O0oo [ 10 : 12 ] ) [ 0 ]
    if ( Iiiii111 != 0 ) :
     if ( ii1iI1i1 != 0 or lisp_is_macos ( ) == False ) :
      self . packet_error = "checksum-error"
      if ( stats ) :
       stats [ self . packet_error ] . increment ( oooOoO0oo0o0 )
       if 51 - 51: ooOoO0o * iII111i / i1IIi
       if 2 - 2: oO0o + IiII . iII111i - i1IIi + I1Ii111
      lprint ( "IPv4 header checksum failed for outer header" )
      if ( lisp_flow_logging ) : self . log_flow ( False )
      return ( None )
      if 54 - 54: OoooooooOO . oO0o - iII111i
      if 76 - 76: I1Ii111
      if 61 - 61: ooOoO0o / II111iiii * ooOoO0o * OoOoOO00 * I1Ii111 . i11iIiiIii
    I1I1i = LISP_AFI_IPV4
    oOo0 = 12
    self . outer_tos = struct . unpack ( "B" , Oo0O0oo [ 1 : 2 ] ) [ 0 ]
    self . outer_ttl = struct . unpack ( "B" , Oo0O0oo [ 8 : 9 ] ) [ 0 ]
    I11II = 20
   elif ( self . outer_version == 6 ) :
    I1I1i = LISP_AFI_IPV6
    oOo0 = 8
    i111i1IIi1i = struct . unpack ( "H" , Oo0O0oo [ 0 : 2 ] ) [ 0 ]
    self . outer_tos = ( socket . ntohs ( i111i1IIi1i ) >> 4 ) & 0xff
    self . outer_ttl = struct . unpack ( "B" , Oo0O0oo [ 7 : 8 ] ) [ 0 ]
    I11II = 40
   else :
    self . packet_error = "outer-header-error"
    if ( stats ) : stats [ self . packet_error ] . increment ( oooOoO0oo0o0 )
    lprint ( "Cannot decode outer header" )
    return ( None )
    if 97 - 97: iIii1I11I1II1 * I11i
    if 95 - 95: OoO0O00
   self . outer_source . afi = I1I1i
   self . outer_dest . afi = I1I1i
   Oo = self . outer_source . addr_length ( )
   if 32 - 32: oO0o
   self . outer_source . unpack_address ( Oo0O0oo [ oOo0 : oOo0 + Oo ] )
   oOo0 += Oo
   self . outer_dest . unpack_address ( Oo0O0oo [ oOo0 : oOo0 + Oo ] )
   Oo0O0oo = Oo0O0oo [ I11II : : ]
   self . outer_source . mask_len = self . outer_source . host_mask_len ( )
   self . outer_dest . mask_len = self . outer_dest . host_mask_len ( )
   if 48 - 48: iIii1I11I1II1 / OoOoOO00 % ooOoO0o . I1Ii111
   if 35 - 35: Oo0Ooo * IiII
   if 12 - 12: IiII - Ii1I % Ii1I
   if 23 - 23: ooOoO0o
   O0O00O = struct . unpack ( "H" , Oo0O0oo [ 0 : 2 ] ) [ 0 ]
   self . udp_sport = socket . ntohs ( O0O00O )
   O0O00O = struct . unpack ( "H" , Oo0O0oo [ 2 : 4 ] ) [ 0 ]
   self . udp_dport = socket . ntohs ( O0O00O )
   O0O00O = struct . unpack ( "H" , Oo0O0oo [ 4 : 6 ] ) [ 0 ]
   self . udp_length = socket . ntohs ( O0O00O )
   O0O00O = struct . unpack ( "H" , Oo0O0oo [ 6 : 8 ] ) [ 0 ]
   self . udp_checksum = socket . ntohs ( O0O00O )
   Oo0O0oo = Oo0O0oo [ 8 : : ]
   if 64 - 64: I11i / II111iiii / OoO0O00 - ooOoO0o * iIii1I11I1II1 . iII111i
   if 25 - 25: OOooOOo - Ii1I . I11i
   if 57 - 57: o0oOOo0O0Ooo + Oo0Ooo * I1ii11iIi11i - ooOoO0o % iIii1I11I1II1 - Ii1I
   if 37 - 37: OoO0O00 * I11i + Ii1I + I1ii11iIi11i * o0oOOo0O0Ooo
   IiIIIii1i1iI = ( self . udp_dport == LISP_DATA_PORT or
 self . udp_sport == LISP_DATA_PORT )
   OoOOoO0o = ( self . udp_dport in ( LISP_L2_DATA_PORT , LISP_VXLAN_DATA_PORT ) )
   if 95 - 95: Ii1I - i11iIiiIii % i11iIiiIii - O0 * I1Ii111
   if 81 - 81: II111iiii * I1IiiI % i1IIi * i11iIiiIii + OoOoOO00
   if 100 - 100: i1IIi % Ii1I
   if 55 - 55: I1IiiI + iII111i
   if ( self . lisp_header . decode ( Oo0O0oo ) == False ) :
    self . packet_error = "lisp-header-error"
    if ( stats ) : stats [ self . packet_error ] . increment ( oooOoO0oo0o0 )
    if 85 - 85: oO0o + iII111i % iII111i / I11i . I1IiiI - OoOoOO00
    if ( lisp_flow_logging ) : self . log_flow ( False )
    lprint ( "Cannot decode LISP header" )
    return ( None )
    if 19 - 19: I11i / iII111i + IiII
   Oo0O0oo = Oo0O0oo [ 8 : : ]
   OO0OO000 = self . lisp_header . get_instance_id ( )
   I11II += 16
   if 76 - 76: iIii1I11I1II1 / I1Ii111 - I1ii11iIi11i % o0oOOo0O0Ooo % OOooOOo + OoooooooOO
  if ( OO0OO000 == 0xffffff ) : OO0OO000 = 0
  if 10 - 10: OoO0O00 * I11i / Oo0Ooo - I1Ii111
  if 11 - 11: IiII % I1ii11iIi11i / ooOoO0o . i11iIiiIii + OOooOOo - II111iiii
  if 50 - 50: i1IIi * oO0o / i11iIiiIii / i11iIiiIii / oO0o
  if 84 - 84: I1ii11iIi11i - iII111i + I1ii11iIi11i
  O0000oO00oO0o = False
  OOo0 = self . lisp_header . k_bits
  if ( OOo0 ) :
   I1IIII1i1 = lisp_get_crypto_decap_lookup_key ( self . outer_source ,
 self . udp_sport )
   if ( I1IIII1i1 == None ) :
    self . packet_error = "no-decrypt-key"
    if ( stats ) : stats [ self . packet_error ] . increment ( oooOoO0oo0o0 )
    if 79 - 79: I1IiiI + oO0o % I11i % oO0o
    self . print_packet ( "Receive" , is_lisp_packet )
    OOoOOO0 = bold ( "No key available" , False )
    dprint ( "{} for key-id {} to decrypt packet" . format ( OOoOOO0 , OOo0 ) )
    if ( lisp_flow_logging ) : self . log_flow ( False )
    return ( None )
    if 18 - 18: O0 - IiII + OOooOOo . O0
    if 72 - 72: I11i * OoOoOO00 % I1Ii111 % ooOoO0o
   i1iI11iI = lisp_crypto_keys_by_rloc_decap [ I1IIII1i1 ] [ OOo0 ]
   if ( i1iI11iI == None ) :
    self . packet_error = "no-decrypt-key"
    if ( stats ) : stats [ self . packet_error ] . increment ( oooOoO0oo0o0 )
    if 69 - 69: oO0o . I11i
    self . print_packet ( "Receive" , is_lisp_packet )
    OOoOOO0 = bold ( "No key available" , False )
    dprint ( "{} to decrypt packet from RLOC {}" . format ( OOoOOO0 ,
 red ( I1IIII1i1 , False ) ) )
    if ( lisp_flow_logging ) : self . log_flow ( False )
    return ( None )
    if 36 - 36: ooOoO0o
    if 62 - 62: I11i % oO0o / OoooooooOO % OoooooooOO
    if 65 - 65: O0 . I1ii11iIi11i * I1Ii111
    if 39 - 39: iIii1I11I1II1 % O0 + Oo0Ooo
    if 71 - 71: OoooooooOO + i1IIi + oO0o * Ii1I + i11iIiiIii - oO0o
   i1iI11iI . use_count += 1
   Oo0O0oo , O0000oO00oO0o = self . decrypt ( Oo0O0oo , I11II , i1iI11iI ,
 I1IIII1i1 )
   if ( O0000oO00oO0o == False ) :
    if ( stats ) : stats [ self . packet_error ] . increment ( oooOoO0oo0o0 )
    if ( lisp_flow_logging ) : self . log_flow ( False )
    return ( None )
    if 99 - 99: Oo0Ooo
    if 17 - 17: i11iIiiIii - i11iIiiIii + I1ii11iIi11i * ooOoO0o * oO0o / OoooooooOO
    if 22 - 22: I1Ii111 * I1ii11iIi11i - IiII
    if 71 - 71: iIii1I11I1II1 / i11iIiiIii % o0oOOo0O0Ooo . I1Ii111 * I1IiiI % II111iiii
    if 35 - 35: I1Ii111 - OoOoOO00
    if 61 - 61: I1Ii111 * o0oOOo0O0Ooo * OoO0O00 + I1ii11iIi11i . Oo0Ooo + i1IIi
  OOO = struct . unpack ( "B" , Oo0O0oo [ 0 : 1 ] ) [ 0 ]
  self . inner_version = OOO >> 4
  if ( IiIIIii1i1iI and self . inner_version == 4 and OOO >= 0x45 ) :
   oO0000 = socket . ntohs ( struct . unpack ( "H" , Oo0O0oo [ 2 : 4 ] ) [ 0 ] )
   self . inner_tos = struct . unpack ( "B" , Oo0O0oo [ 1 : 2 ] ) [ 0 ]
   self . inner_ttl = struct . unpack ( "B" , Oo0O0oo [ 8 : 9 ] ) [ 0 ]
   self . inner_protocol = struct . unpack ( "B" , Oo0O0oo [ 9 : 10 ] ) [ 0 ]
   self . inner_source . afi = LISP_AFI_IPV4
   self . inner_dest . afi = LISP_AFI_IPV4
   self . inner_source . unpack_address ( Oo0O0oo [ 12 : 16 ] )
   self . inner_dest . unpack_address ( Oo0O0oo [ 16 : 20 ] )
   iI1IIIIII = socket . ntohs ( struct . unpack ( "H" , Oo0O0oo [ 6 : 8 ] ) [ 0 ] )
   self . inner_is_fragment = ( iI1IIIIII & 0x2000 or iI1IIIIII != 0 )
   if ( self . inner_protocol == LISP_UDP_PROTOCOL ) :
    self . inner_sport = struct . unpack ( "H" , Oo0O0oo [ 20 : 22 ] ) [ 0 ]
    self . inner_sport = socket . ntohs ( self . inner_sport )
    self . inner_dport = struct . unpack ( "H" , Oo0O0oo [ 22 : 24 ] ) [ 0 ]
    self . inner_dport = socket . ntohs ( self . inner_dport )
    if 71 - 71: o0oOOo0O0Ooo . I1IiiI - I1ii11iIi11i - Oo0Ooo - i1IIi - I1IiiI
  elif ( IiIIIii1i1iI and self . inner_version == 6 and OOO >= 0x60 ) :
   oO0000 = socket . ntohs ( struct . unpack ( "H" , Oo0O0oo [ 4 : 6 ] ) [ 0 ] ) + 40
   i111i1IIi1i = struct . unpack ( "H" , Oo0O0oo [ 0 : 2 ] ) [ 0 ]
   self . inner_tos = ( socket . ntohs ( i111i1IIi1i ) >> 4 ) & 0xff
   self . inner_ttl = struct . unpack ( "B" , Oo0O0oo [ 7 : 8 ] ) [ 0 ]
   self . inner_protocol = struct . unpack ( "B" , Oo0O0oo [ 6 : 7 ] ) [ 0 ]
   self . inner_source . afi = LISP_AFI_IPV6
   self . inner_dest . afi = LISP_AFI_IPV6
   self . inner_source . unpack_address ( Oo0O0oo [ 8 : 24 ] )
   self . inner_dest . unpack_address ( Oo0O0oo [ 24 : 40 ] )
   if ( self . inner_protocol == LISP_UDP_PROTOCOL ) :
    self . inner_sport = struct . unpack ( "H" , Oo0O0oo [ 40 : 42 ] ) [ 0 ]
    self . inner_sport = socket . ntohs ( self . inner_sport )
    self . inner_dport = struct . unpack ( "H" , Oo0O0oo [ 42 : 44 ] ) [ 0 ]
    self . inner_dport = socket . ntohs ( self . inner_dport )
    if 45 - 45: OoO0O00 * OoO0O00
  elif ( OoOOoO0o ) :
   oO0000 = len ( Oo0O0oo )
   self . inner_tos = 0
   self . inner_ttl = 0
   self . inner_protocol = 0
   self . inner_source . afi = LISP_AFI_MAC
   self . inner_dest . afi = LISP_AFI_MAC
   self . inner_dest . unpack_address ( self . swap_mac ( Oo0O0oo [ 0 : 6 ] ) )
   self . inner_source . unpack_address ( self . swap_mac ( Oo0O0oo [ 6 : 12 ] ) )
  elif ( self . lisp_header . get_instance_id ( ) == 0xffffff ) :
   if ( lisp_flow_logging ) : self . log_flow ( False )
   return ( self )
  else :
   self . packet_error = "bad-inner-version"
   if ( stats ) : stats [ self . packet_error ] . increment ( oooOoO0oo0o0 )
   if 9 - 9: iIii1I11I1II1
   lprint ( "Cannot decode encapsulation, header version {}" . format ( hex ( OOO ) ) )
   if 57 - 57: ooOoO0o / Ii1I % o0oOOo0O0Ooo % i11iIiiIii
   Oo0O0oo = lisp_format_packet ( Oo0O0oo [ 0 : 20 ] )
   lprint ( "Packet header: {}" . format ( Oo0O0oo ) )
   if ( lisp_flow_logging and is_lisp_packet ) : self . log_flow ( False )
   return ( None )
   if 95 - 95: I1Ii111 - o0oOOo0O0Ooo
  self . inner_source . mask_len = self . inner_source . host_mask_len ( )
  self . inner_dest . mask_len = self . inner_dest . host_mask_len ( )
  self . inner_source . instance_id = OO0OO000
  self . inner_dest . instance_id = OO0OO000
  if 65 - 65: i11iIiiIii - OoooooooOO / O0 * IiII % I11i
  if 53 - 53: OOooOOo + I1Ii111
  if 10 - 10: I11i * i1IIi . oO0o / I1Ii111 . OOooOOo / I1Ii111
  if 1 - 1: iII111i % ooOoO0o
  if 99 - 99: iII111i + iIii1I11I1II1 . OOooOOo / OoO0O00 * I1ii11iIi11i
  if ( lisp_nonce_echoing and is_lisp_packet ) :
   O00o = lisp_get_echo_nonce ( self . outer_source , None )
   if ( O00o == None ) :
    oo00OO = self . outer_source . print_address_no_iid ( )
    O00o = lisp_echo_nonce ( oo00OO )
    if 63 - 63: OoO0O00 % i1IIi - oO0o
   Iii1i11 = self . lisp_header . get_nonce ( )
   if ( self . lisp_header . is_e_bit_set ( ) ) :
    O00o . receive_request ( lisp_ipc_socket , Iii1i11 )
   elif ( O00o . request_nonce_sent ) :
    O00o . receive_echo ( lisp_ipc_socket , Iii1i11 )
    if 40 - 40: I1ii11iIi11i / iIii1I11I1II1 . IiII % ooOoO0o
    if 56 - 56: ooOoO0o . iIii1I11I1II1 + i1IIi
    if 84 - 84: iII111i % i1IIi
    if 62 - 62: I1ii11iIi11i . I1Ii111 . Ii1I
    if 19 - 19: I1ii11iIi11i / I1Ii111
    if 35 - 35: Oo0Ooo * oO0o / OoooooooOO + O0 / OoooooooOO / OOooOOo
    if 44 - 44: i1IIi . I1ii11iIi11i - ooOoO0o . OOooOOo . o0oOOo0O0Ooo + oO0o
  if ( O0000oO00oO0o ) : self . packet += Oo0O0oo [ : oO0000 ]
  if 17 - 17: iIii1I11I1II1 + i1IIi . I1ii11iIi11i + Ii1I % i1IIi . oO0o
  if 57 - 57: oO0o
  if 92 - 92: II111iiii - OoO0O00 - OOooOOo % I1IiiI - OoOoOO00 * I1Ii111
  if 16 - 16: iIii1I11I1II1 + OoooooooOO - ooOoO0o * IiII
  if ( lisp_flow_logging and is_lisp_packet ) : self . log_flow ( False )
  return ( self )
  if 37 - 37: iII111i
  if 15 - 15: o0oOOo0O0Ooo % OoO0O00 / iII111i
 def swap_mac ( self , mac ) :
  return ( mac [ 1 ] + mac [ 0 ] + mac [ 3 ] + mac [ 2 ] + mac [ 5 ] + mac [ 4 ] )
  if 36 - 36: OoO0O00 + OoO0O00 % Oo0Ooo + Oo0Ooo / i1IIi % i1IIi
  if 20 - 20: OOooOOo * oO0o
 def strip_outer_headers ( self ) :
  oOo0 = 16
  oOo0 += 20 if ( self . outer_version == 4 ) else 40
  self . packet = self . packet [ oOo0 : : ]
  return ( self )
  if 91 - 91: OoO0O00 % i1IIi - iIii1I11I1II1 . OOooOOo
  if 31 - 31: oO0o % i1IIi . OoooooooOO - o0oOOo0O0Ooo + OoooooooOO
 def hash_ports ( self ) :
  Oo0O0oo = self . packet
  OOO = self . inner_version
  I1i1Ii = 0
  if ( OOO == 4 ) :
   III1 = struct . unpack ( "B" , Oo0O0oo [ 9 ] ) [ 0 ]
   if ( self . inner_is_fragment ) : return ( III1 )
   if ( III1 in [ 6 , 17 ] ) :
    I1i1Ii = III1
    I1i1Ii += struct . unpack ( "I" , Oo0O0oo [ 20 : 24 ] ) [ 0 ]
    I1i1Ii = ( I1i1Ii >> 16 ) ^ ( I1i1Ii & 0xffff )
    if 14 - 14: I1Ii111 / I11i - OOooOOo * O0 % IiII . O0
    if 86 - 86: i1IIi * OoooooooOO
  if ( OOO == 6 ) :
   III1 = struct . unpack ( "B" , Oo0O0oo [ 6 ] ) [ 0 ]
   if ( III1 in [ 6 , 17 ] ) :
    I1i1Ii = III1
    I1i1Ii += struct . unpack ( "I" , Oo0O0oo [ 40 : 44 ] ) [ 0 ]
    I1i1Ii = ( I1i1Ii >> 16 ) ^ ( I1i1Ii & 0xffff )
    if 22 - 22: I1Ii111 + iII111i - I11i + iIii1I11I1II1 / I1Ii111 - OoooooooOO
    if 42 - 42: OoooooooOO - OoOoOO00 - OOooOOo * I1Ii111
  return ( I1i1Ii )
  if 98 - 98: OoO0O00 . iIii1I11I1II1 % Oo0Ooo + OoooooooOO
  if 2 - 2: I1Ii111 % OoooooooOO - ooOoO0o * I1ii11iIi11i * IiII
 def hash_packet ( self ) :
  I1i1Ii = self . inner_source . address ^ self . inner_dest . address
  I1i1Ii += self . hash_ports ( )
  if ( self . inner_version == 4 ) :
   I1i1Ii = ( I1i1Ii >> 16 ) ^ ( I1i1Ii & 0xffff )
  elif ( self . inner_version == 6 ) :
   I1i1Ii = ( I1i1Ii >> 64 ) ^ ( I1i1Ii & 0xffffffffffffffff )
   I1i1Ii = ( I1i1Ii >> 32 ) ^ ( I1i1Ii & 0xffffffff )
   I1i1Ii = ( I1i1Ii >> 16 ) ^ ( I1i1Ii & 0xffff )
   if 99 - 99: iIii1I11I1II1 . Oo0Ooo / ooOoO0o . OOooOOo % I1IiiI * I11i
  self . udp_sport = 0xf000 | ( I1i1Ii & 0xfff )
  if 95 - 95: oO0o
  if 80 - 80: IiII
 def print_packet ( self , s_or_r , is_lisp_packet ) :
  if ( is_lisp_packet == False ) :
   iiiI1I1iiiII = "{} -> {}" . format ( self . inner_source . print_address ( ) ,
 self . inner_dest . print_address ( ) )
   dprint ( ( "{} {}, tos/ttl: {}/{}, length: {}, packet: {} ..." ) . format ( bold ( s_or_r , False ) ,
   # I11i
 green ( iiiI1I1iiiII , False ) , self . inner_tos ,
 self . inner_ttl , len ( self . packet ) ,
 lisp_format_packet ( self . packet [ 0 : 60 ] ) ) )
   return
   if 76 - 76: I1ii11iIi11i . ooOoO0o . oO0o
   if 74 - 74: Oo0Ooo
  if ( s_or_r . find ( "Receive" ) != - 1 ) :
   o0o00OO00OOo0 = "decap"
   o0o00OO00OOo0 += "-vxlan" if self . udp_dport == LISP_VXLAN_DATA_PORT else ""
  else :
   o0o00OO00OOo0 = s_or_r
   if ( o0o00OO00OOo0 in [ "Send" , "Replicate" ] or o0o00OO00OOo0 . find ( "Fragment" ) != - 1 ) :
    o0o00OO00OOo0 = "encap"
    if 92 - 92: OOooOOo
    if 32 - 32: iII111i . iIii1I11I1II1 % Oo0Ooo . OoooooooOO
  Ooo00OoO0O00 = "{} -> {}" . format ( self . outer_source . print_address_no_iid ( ) ,
 self . outer_dest . print_address_no_iid ( ) )
  if 11 - 11: I11i
  if 20 - 20: O0 . i11iIiiIii * i1IIi % O0 . I1IiiI
  if 53 - 53: ooOoO0o / OoooooooOO - II111iiii
  if 68 - 68: OoooooooOO . OoooooooOO . iIii1I11I1II1 / ooOoO0o - I11i % O0
  if 19 - 19: OoooooooOO * oO0o
  if ( self . lisp_header . get_instance_id ( ) == 0xffffff ) :
   iI1111i = ( "{} LISP packet, outer RLOCs: {}, outer tos/ttl: " + "{}/{}, outer UDP: {} -> {}, " )
   if 60 - 60: II111iiii - iII111i + o0oOOo0O0Ooo % OOooOOo
   iI1111i += bold ( "control-packet" , False ) + ": {} ..."
   if 97 - 97: O0 % O0
   dprint ( iI1111i . format ( bold ( s_or_r , False ) , red ( Ooo00OoO0O00 , False ) ,
 self . outer_tos , self . outer_ttl , self . udp_sport ,
 self . udp_dport , lisp_format_packet ( self . packet [ 0 : 56 ] ) ) )
   return
  else :
   iI1111i = ( "{} LISP packet, outer RLOCs: {}, outer tos/ttl: " + "{}/{}, outer UDP: {} -> {}, inner EIDs: {}, " + "inner tos/ttl: {}/{}, length: {}, {}, packet: {} ..." )
   if 35 - 35: iII111i - Ii1I . i11iIiiIii % O0 % I1ii11iIi11i
   if 92 - 92: OOooOOo % II111iiii . iII111i
   if 46 - 46: OoOoOO00 + I1IiiI % OoooooooOO * i11iIiiIii - Oo0Ooo
   if 47 - 47: iII111i * OoOoOO00 * IiII
  if ( self . lisp_header . k_bits ) :
   if ( o0o00OO00OOo0 == "encap" ) : o0o00OO00OOo0 = "encrypt/encap"
   if ( o0o00OO00OOo0 == "decap" ) : o0o00OO00OOo0 = "decap/decrypt"
   if 46 - 46: Ii1I
   if 42 - 42: iIii1I11I1II1
  iiiI1I1iiiII = "{} -> {}" . format ( self . inner_source . print_address ( ) ,
 self . inner_dest . print_address ( ) )
  if 32 - 32: Oo0Ooo - Ii1I . OoooooooOO - OoooooooOO - Oo0Ooo . iIii1I11I1II1
  dprint ( iI1111i . format ( bold ( s_or_r , False ) , red ( Ooo00OoO0O00 , False ) ,
 self . outer_tos , self . outer_ttl , self . udp_sport , self . udp_dport ,
 green ( iiiI1I1iiiII , False ) , self . inner_tos , self . inner_ttl ,
 len ( self . packet ) , self . lisp_header . print_header ( o0o00OO00OOo0 ) ,
 lisp_format_packet ( self . packet [ 0 : 56 ] ) ) )
  if 34 - 34: Oo0Ooo
  if 31 - 31: i1IIi - I11i + I1Ii111 + ooOoO0o . ooOoO0o . O0
 def print_eid_tuple ( self ) :
  return ( lisp_print_eid_tuple ( self . inner_source , self . inner_dest ) )
  if 33 - 33: i1IIi / iII111i * OoO0O00
  if 2 - 2: oO0o . OOooOOo
 def get_raw_socket ( self ) :
  OO0OO000 = str ( self . lisp_header . get_instance_id ( ) )
  if ( OO0OO000 == "0" ) : return ( None )
  if ( lisp_iid_to_interface . has_key ( OO0OO000 ) == False ) : return ( None )
  if 43 - 43: iIii1I11I1II1
  oOOoo = lisp_iid_to_interface [ OO0OO000 ]
  IiiiI1 = oOOoo . get_socket ( )
  if ( IiiiI1 == None ) :
   oo0O = bold ( "SO_BINDTODEVICE" , False )
   I1I1iIIiii1 = ( os . getenv ( "LISP_ENFORCE_BINDTODEVICE" ) != None )
   lprint ( "{} required for multi-tenancy support, {} packet" . format ( oo0O , "drop" if I1I1iIIiii1 else "forward" ) )
   if 32 - 32: Ii1I * I1ii11iIi11i - OoooooooOO / I1IiiI . ooOoO0o - i1IIi
   if ( I1I1iIIiii1 ) : return ( None )
   if 60 - 60: OoOoOO00 % OoOoOO00
   if 2 - 2: Ii1I . O0 - oO0o + IiII
  OO0OO000 = bold ( OO0OO000 , False )
  oOOoO0O = bold ( oOOoo . device , False )
  dprint ( "Send packet on instance-id {} interface {}" . format ( OO0OO000 , oOOoO0O ) )
  return ( IiiiI1 )
  if 96 - 96: Ii1I + Ii1I
  if 28 - 28: iII111i
 def log_flow ( self , encap ) :
  global lisp_flow_log
  if 6 - 6: I1IiiI - iII111i
  ii1II = os . path . exists ( "./log-flows" )
  if ( len ( lisp_flow_log ) == LISP_FLOW_LOG_SIZE or ii1II ) :
   OOo00o0o0O0oo = [ lisp_flow_log ]
   lisp_flow_log = [ ]
   threading . Thread ( target = lisp_write_flow_log , args = OOo00o0o0O0oo ) . start ( )
   if ( ii1II ) : os . system ( "rm ./log-flows" )
   return
   if 15 - 15: OOooOOo
   if 77 - 77: OoOoOO00
  I11i1II = datetime . datetime . now ( )
  lisp_flow_log . append ( [ I11i1II , encap , self . packet , self ] )
  if 91 - 91: oO0o
  if 56 - 56: iIii1I11I1II1 % II111iiii / OoOoOO00 % OoooooooOO
 def print_flow ( self , ts , encap , packet ) :
  ts = ts . strftime ( "%m/%d/%y %H:%M:%S.%f" ) [ : - 3 ]
  I1I = "{}: {}" . format ( ts , "encap" if encap else "decap" )
  if 37 - 37: I1ii11iIi11i % oO0o
  o0ooO = red ( self . outer_source . print_address_no_iid ( ) , False )
  O0ii = red ( self . outer_dest . print_address_no_iid ( ) , False )
  O00O = green ( self . inner_source . print_address ( ) , False )
  IIIIIi1 = green ( self . inner_dest . print_address ( ) , False )
  if 82 - 82: I1Ii111 . i1IIi / oO0o
  if ( self . lisp_header . get_instance_id ( ) == 0xffffff ) :
   I1I += " {}:{} -> {}:{}, LISP control message type {}\n"
   I1I = I1I . format ( o0ooO , self . udp_sport , O0ii , self . udp_dport ,
 self . inner_version )
   return ( I1I )
   if 56 - 56: iII111i
   if 23 - 23: i1IIi
  if ( self . outer_dest . is_null ( ) == False ) :
   I1I += " {}:{} -> {}:{}, len/tos/ttl {}/{}/{}"
   I1I = I1I . format ( o0ooO , self . udp_sport , O0ii , self . udp_dport ,
 len ( packet ) , self . outer_tos , self . outer_ttl )
   if 24 - 24: IiII
   if 51 - 51: OOooOOo % i11iIiiIii
   if 77 - 77: OOooOOo % i11iIiiIii - I1ii11iIi11i
   if 21 - 21: I11i . Oo0Ooo - OoooooooOO * i1IIi
   if 54 - 54: II111iiii % o0oOOo0O0Ooo - i1IIi . I1IiiI - II111iiii / iIii1I11I1II1
  if ( self . lisp_header . k_bits != 0 ) :
   iIIIii111 = "\n"
   if ( self . packet_error != "" ) :
    iIIIii111 = " ({})" . format ( self . packet_error ) + iIIIii111
    if 21 - 21: iII111i % IiII % Oo0Ooo % O0
   I1I += ", encrypted" + iIIIii111
   return ( I1I )
   if 63 - 63: II111iiii * I1IiiI - OoooooooOO / I1IiiI
   if 50 - 50: OoOoOO00 % Ii1I + OoOoOO00 * Ii1I - OOooOOo
   if 94 - 94: iIii1I11I1II1
   if 1 - 1: O0
   if 2 - 2: OoO0O00 . I11i
  if ( self . outer_dest . is_null ( ) == False ) :
   packet = packet [ 36 : : ] if self . outer_version == 4 else packet [ 56 : : ]
   if 97 - 97: Oo0Ooo
   if 65 - 65: Oo0Ooo % OOooOOo / i11iIiiIii / iIii1I11I1II1 . I1Ii111 + ooOoO0o
  III1 = packet [ 9 ] if self . inner_version == 4 else packet [ 6 ]
  III1 = struct . unpack ( "B" , III1 ) [ 0 ]
  if 92 - 92: oO0o
  I1I += " {} -> {}, len/tos/ttl/prot {}/{}/{}/{}"
  I1I = I1I . format ( O00O , IIIIIi1 , len ( packet ) , self . inner_tos ,
 self . inner_ttl , III1 )
  if 96 - 96: I1Ii111 * iIii1I11I1II1 / OoOoOO00 % OOooOOo * II111iiii
  if 3 - 3: OOooOOo . Oo0Ooo / i11iIiiIii + OoO0O00
  if 47 - 47: IiII . OOooOOo
  if 96 - 96: I11i % II111iiii / ooOoO0o % OOooOOo / ooOoO0o % i11iIiiIii
  if ( III1 in [ 6 , 17 ] ) :
   O0000ooO = packet [ 20 : 24 ] if self . inner_version == 4 else packet [ 40 : 44 ]
   if ( len ( O0000ooO ) == 4 ) :
    O0000ooO = socket . ntohl ( struct . unpack ( "I" , O0000ooO ) [ 0 ] )
    I1I += ", ports {} -> {}" . format ( O0000ooO >> 16 , O0000ooO & 0xffff )
    if 83 - 83: I1Ii111 + o0oOOo0O0Ooo % oO0o / OoO0O00
  elif ( III1 == 1 ) :
   o0o000O0ooo0O = packet [ 26 : 28 ] if self . inner_version == 4 else packet [ 46 : 48 ]
   if ( len ( o0o000O0ooo0O ) == 2 ) :
    o0o000O0ooo0O = socket . ntohs ( struct . unpack ( "H" , o0o000O0ooo0O ) [ 0 ] )
    I1I += ", icmp-seq {}" . format ( o0o000O0ooo0O )
    if 46 - 46: IiII % I1Ii111 + iIii1I11I1II1 * I1IiiI
    if 64 - 64: I1ii11iIi11i * Ii1I * Oo0Ooo % IiII % ooOoO0o
  if ( self . packet_error != "" ) :
   I1I += " ({})" . format ( self . packet_error )
   if 55 - 55: II111iiii - I1Ii111 - OOooOOo % Ii1I
  I1I += "\n"
  return ( I1I )
  if 49 - 49: Oo0Ooo * I1Ii111
  if 53 - 53: Oo0Ooo / Ii1I + oO0o . iII111i + IiII
 def is_trace ( self ) :
  O0000ooO = [ self . inner_sport , self . inner_dport ]
  return ( self . inner_protocol == LISP_UDP_PROTOCOL and
 LISP_TRACE_PORT in O0000ooO )
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
  if 70 - 70: II111iiii * II111iiii . I1IiiI
  if 11 - 11: iII111i
  if 20 - 20: Ii1I . I1Ii111 % Ii1I
  if 5 - 5: OOooOOo + iII111i
  if 23 - 23: I1Ii111 % iIii1I11I1II1 . I11i
  if 95 - 95: Oo0Ooo + i11iIiiIii % OOooOOo - oO0o
LISP_N_BIT = 0x80000000
LISP_L_BIT = 0x40000000
LISP_E_BIT = 0x20000000
LISP_V_BIT = 0x10000000
LISP_I_BIT = 0x08000000
LISP_P_BIT = 0x04000000
LISP_K_BITS = 0x03000000
if 11 - 11: I1ii11iIi11i / O0 + II111iiii
class lisp_data_header ( ) :
 def __init__ ( self ) :
  self . first_long = 0
  self . second_long = 0
  self . k_bits = 0
  if 95 - 95: I1Ii111 + IiII * iIii1I11I1II1
  if 17 - 17: OoO0O00 - Oo0Ooo * O0 / Ii1I
 def print_header ( self , e_or_d ) :
  iiii1ii1 = lisp_hex_string ( self . first_long & 0xffffff )
  Ii1i111iI = lisp_hex_string ( self . second_long ) . zfill ( 8 )
  if 48 - 48: Oo0Ooo
  iI1111i = ( "{} LISP-header -> flags: {}{}{}{}{}{}{}{}, nonce: {}, " + "iid/lsb: {}" )
  if 64 - 64: iIii1I11I1II1 % o0oOOo0O0Ooo . O0 * o0oOOo0O0Ooo
  return ( iI1111i . format ( bold ( e_or_d , False ) ,
 "N" if ( self . first_long & LISP_N_BIT ) else "n" ,
 "L" if ( self . first_long & LISP_L_BIT ) else "l" ,
 "E" if ( self . first_long & LISP_E_BIT ) else "e" ,
 "V" if ( self . first_long & LISP_V_BIT ) else "v" ,
 "I" if ( self . first_long & LISP_I_BIT ) else "i" ,
 "P" if ( self . first_long & LISP_P_BIT ) else "p" ,
 "K" if ( self . k_bits in [ 2 , 3 ] ) else "k" ,
 "K" if ( self . k_bits in [ 1 , 3 ] ) else "k" ,
 iiii1ii1 , Ii1i111iI ) )
  if 99 - 99: Ii1I / Oo0Ooo * II111iiii / O0
  if 44 - 44: i11iIiiIii % I1Ii111 % oO0o + I11i * oO0o . Ii1I
 def encode ( self ) :
  OoOo0Oooo0o = "II"
  iiii1ii1 = socket . htonl ( self . first_long )
  Ii1i111iI = socket . htonl ( self . second_long )
  if 65 - 65: OoOoOO00 + I1Ii111 % I1IiiI
  o0OO0 = struct . pack ( OoOo0Oooo0o , iiii1ii1 , Ii1i111iI )
  return ( o0OO0 )
  if 69 - 69: oO0o * I1ii11iIi11i - O0 + I1IiiI + o0oOOo0O0Ooo
  if 64 - 64: II111iiii / II111iiii
 def decode ( self , packet ) :
  OoOo0Oooo0o = "II"
  o0OOo0OOoOO0 = struct . calcsize ( OoOo0Oooo0o )
  if ( len ( packet ) < o0OOo0OOoOO0 ) : return ( False )
  if 90 - 90: Ii1I
  iiii1ii1 , Ii1i111iI = struct . unpack ( OoOo0Oooo0o , packet [ : o0OOo0OOoOO0 ] )
  if 30 - 30: o0oOOo0O0Ooo + Ii1I / OoooooooOO - IiII % oO0o
  if 21 - 21: OoooooooOO % OoOoOO00 - OoOoOO00 / I1ii11iIi11i / o0oOOo0O0Ooo
  self . first_long = socket . ntohl ( iiii1ii1 )
  self . second_long = socket . ntohl ( Ii1i111iI )
  self . k_bits = ( self . first_long & LISP_K_BITS ) >> 24
  return ( True )
  if 15 - 15: ooOoO0o / ooOoO0o % OoooooooOO . I1Ii111
  if 93 - 93: I1ii11iIi11i * I1ii11iIi11i / OoooooooOO
 def key_id ( self , key_id ) :
  self . first_long &= ~ ( 0x3 << 24 )
  self . first_long |= ( ( key_id & 0x3 ) << 24 )
  self . k_bits = key_id
  if 6 - 6: I1ii11iIi11i * Oo0Ooo + iIii1I11I1II1
  if 19 - 19: O0 % II111iiii * o0oOOo0O0Ooo
 def nonce ( self , nonce ) :
  self . first_long |= LISP_N_BIT
  self . first_long |= nonce
  if 27 - 27: OOooOOo * IiII / i11iIiiIii - oO0o + II111iiii
  if 43 - 43: I1ii11iIi11i - II111iiii
 def map_version ( self , version ) :
  self . first_long |= LISP_V_BIT
  self . first_long |= version
  if 56 - 56: I1ii11iIi11i . i1IIi / iII111i % oO0o / O0 * I11i
  if 98 - 98: O0 + iII111i
 def instance_id ( self , iid ) :
  if ( iid == 0 ) : return
  self . first_long |= LISP_I_BIT
  self . second_long &= 0xff
  self . second_long |= ( iid << 8 )
  if 23 - 23: OoooooooOO . iIii1I11I1II1 / i1IIi
  if 31 - 31: Oo0Ooo - iIii1I11I1II1 / I11i . OoO0O00
 def get_instance_id ( self ) :
  return ( ( self . second_long >> 8 ) & 0xffffff )
  if 74 - 74: Oo0Ooo - II111iiii - IiII
  if 50 - 50: I1IiiI - oO0o + oO0o * I11i + oO0o
 def locator_status_bits ( self , lsbs ) :
  self . first_long |= LISP_L_BIT
  self . second_long &= 0xffffff00
  self . second_long |= ( lsbs & 0xff )
  if 70 - 70: i1IIi % OoO0O00 / i1IIi
  if 30 - 30: OoOoOO00 - i11iIiiIii
 def is_request_nonce ( self , nonce ) :
  return ( nonce & 0x80000000 )
  if 94 - 94: OoOoOO00 % iII111i
  if 39 - 39: OoOoOO00 + I1Ii111 % O0
 def request_nonce ( self , nonce ) :
  self . first_long |= LISP_E_BIT
  self . first_long |= LISP_N_BIT
  self . first_long |= ( nonce & 0xffffff )
  if 26 - 26: ooOoO0o + OoOoOO00
  if 17 - 17: I1ii11iIi11i - iII111i % Oo0Ooo * O0 % O0 * OOooOOo
 def is_e_bit_set ( self ) :
  return ( self . first_long & LISP_E_BIT )
  if 6 - 6: I1Ii111
  if 46 - 46: II111iiii * I1Ii111
 def get_nonce ( self ) :
  return ( self . first_long & 0xffffff )
  if 23 - 23: i1IIi - O0
  if 6 - 6: ooOoO0o % OoooooooOO * I1Ii111 - IiII
  if 24 - 24: I11i / iIii1I11I1II1 . OoooooooOO % OoOoOO00 . Ii1I
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
  if 73 - 73: I1Ii111
  if 25 - 25: IiII
 def send_ipc ( self , ipc_socket , ipc ) :
  OO = "lisp-itr" if lisp_i_am_itr else "lisp-etr"
  iI1i1iI1iI = "lisp-etr" if lisp_i_am_itr else "lisp-itr"
  ipc = lisp_command_ipc ( ipc , OO )
  lisp_ipc ( ipc , ipc_socket , iI1i1iI1iI )
  if 6 - 6: i11iIiiIii
  if 16 - 16: IiII
 def send_request_ipc ( self , ipc_socket , nonce ) :
  nonce = lisp_hex_string ( nonce )
  Ooooo = "nonce%R%{}%{}" . format ( self . rloc_str , nonce )
  self . send_ipc ( ipc_socket , Ooooo )
  if 65 - 65: Oo0Ooo . OoOoOO00 . OOooOOo % o0oOOo0O0Ooo + OoO0O00
  if 53 - 53: Oo0Ooo * I11i - Ii1I % OoO0O00 - OoOoOO00 - iII111i
 def send_echo_ipc ( self , ipc_socket , nonce ) :
  nonce = lisp_hex_string ( nonce )
  Ooooo = "nonce%E%{}%{}" . format ( self . rloc_str , nonce )
  self . send_ipc ( ipc_socket , Ooooo )
  if 21 - 21: II111iiii + OoO0O00 - Oo0Ooo + I1IiiI
  if 20 - 20: OoO0O00
 def receive_request ( self , ipc_socket , nonce ) :
  o00OooooOOOO = self . request_nonce_rcvd
  self . request_nonce_rcvd = nonce
  self . last_request_nonce_rcvd = lisp_get_timestamp ( )
  if ( lisp_i_am_rtr ) : return
  if ( o00OooooOOOO != nonce ) : self . send_request_ipc ( ipc_socket , nonce )
  if 89 - 89: O0 + IiII * I1Ii111
  if 30 - 30: OoOoOO00
 def receive_echo ( self , ipc_socket , nonce ) :
  if ( self . request_nonce_sent != nonce ) : return
  self . last_echo_nonce_rcvd = lisp_get_timestamp ( )
  if ( self . echo_nonce_rcvd == nonce ) : return
  if 39 - 39: I1ii11iIi11i + o0oOOo0O0Ooo + I1Ii111 + IiII
  self . echo_nonce_rcvd = nonce
  if ( lisp_i_am_rtr ) : return
  self . send_echo_ipc ( ipc_socket , nonce )
  if 48 - 48: I1Ii111 / ooOoO0o . iIii1I11I1II1
  if 72 - 72: i1IIi . o0oOOo0O0Ooo
 def get_request_or_echo_nonce ( self , ipc_socket , remote_rloc ) :
  if 3 - 3: OoOoOO00 % II111iiii - O0
  if 52 - 52: OoO0O00
  if 49 - 49: Ii1I . I1ii11iIi11i % ooOoO0o . Oo0Ooo * OOooOOo
  if 44 - 44: iIii1I11I1II1 / O0 * Oo0Ooo + I1IiiI . ooOoO0o
  if 20 - 20: iII111i + o0oOOo0O0Ooo . I1Ii111 / i11iIiiIii
  if ( self . request_nonce_sent and self . echo_nonce_sent and remote_rloc ) :
   IIiI1 = lisp_myrlocs [ 0 ] if remote_rloc . is_ipv4 ( ) else lisp_myrlocs [ 1 ]
   if 93 - 93: OoOoOO00 . oO0o * ooOoO0o
   if 86 - 86: I1ii11iIi11i / iII111i * OOooOOo / OOooOOo - I1ii11iIi11i * OOooOOo
   if ( remote_rloc . address > IIiI1 . address ) :
    iiiii1ii1 = "exit"
    self . request_nonce_sent = None
   else :
    iiiii1ii1 = "stay in"
    self . echo_nonce_sent = None
    if 81 - 81: iII111i / II111iiii + I1IiiI * ooOoO0o * O0
    if 60 - 60: iII111i / iII111i - ooOoO0o / OoooooooOO + O0
   oOoooO0oo0 = bold ( "collision" , False )
   i1IIi111iI = red ( IIiI1 . print_address_no_iid ( ) , False )
   IIi = red ( remote_rloc . print_address_no_iid ( ) , False )
   lprint ( "Echo nonce {}, {} -> {}, {} request-nonce mode" . format ( oOoooO0oo0 ,
 i1IIi111iI , IIi , iiiii1ii1 ) )
   if 94 - 94: i1IIi
   if 88 - 88: I1ii11iIi11i * iII111i + II111iiii
   if 62 - 62: OoooooooOO
   if 33 - 33: O0 . i11iIiiIii % o0oOOo0O0Ooo
   if 50 - 50: ooOoO0o
  if ( self . echo_nonce_sent != None ) :
   Iii1i11 = self . echo_nonce_sent
   o0o000 = bold ( "Echoing" , False )
   lprint ( "{} nonce 0x{} to {}" . format ( o0o000 ,
 lisp_hex_string ( Iii1i11 ) , red ( self . rloc_str , False ) ) )
   self . last_echo_nonce_sent = lisp_get_timestamp ( )
   self . echo_nonce_sent = None
   return ( Iii1i11 )
   if 81 - 81: i11iIiiIii * iIii1I11I1II1 / Oo0Ooo * OOooOOo
   if 83 - 83: i11iIiiIii - I1IiiI * i11iIiiIii
   if 59 - 59: iII111i - OoooooooOO / ooOoO0o + I1ii11iIi11i . o0oOOo0O0Ooo - iII111i
   if 29 - 29: oO0o
   if 26 - 26: O0 % OOooOOo - IiII . OOooOOo
   if 70 - 70: o0oOOo0O0Ooo + I11i / iII111i + ooOoO0o / I1IiiI
   if 33 - 33: OoooooooOO . O0
  Iii1i11 = self . request_nonce_sent
  oOo = self . last_request_nonce_sent
  if ( Iii1i11 and oOo != None ) :
   if ( time . time ( ) - oOo >= LISP_NONCE_ECHO_INTERVAL ) :
    self . request_nonce_sent = None
    lprint ( "Stop request-nonce mode for {}, nonce 0x{}" . format ( red ( self . rloc_str , False ) , lisp_hex_string ( Iii1i11 ) ) )
    if 8 - 8: I1ii11iIi11i % OoO0O00 % oO0o . I1ii11iIi11i * I1ii11iIi11i
    return ( None )
    if 94 - 94: i11iIiiIii + OoooooooOO
    if 20 - 20: i11iIiiIii
    if 86 - 86: OoOoOO00 / OOooOOo
    if 40 - 40: iIii1I11I1II1 / ooOoO0o / I1IiiI + I1ii11iIi11i * OOooOOo
    if 1 - 1: OoO0O00 * ooOoO0o + IiII . oO0o / ooOoO0o
    if 91 - 91: Ii1I + I11i - Oo0Ooo % OoOoOO00 . iII111i
    if 51 - 51: OOooOOo / I11i
    if 51 - 51: ooOoO0o * oO0o - I1Ii111 + iII111i
    if 46 - 46: o0oOOo0O0Ooo - i11iIiiIii % OoO0O00 / Ii1I - OoOoOO00
  if ( Iii1i11 == None ) :
   Iii1i11 = lisp_get_data_nonce ( )
   if ( self . recently_requested ( ) ) : return ( Iii1i11 )
   if 88 - 88: oO0o * I1IiiI / OoO0O00 - OOooOOo / i1IIi . I1Ii111
   self . request_nonce_sent = Iii1i11
   lprint ( "Start request-nonce mode for {}, nonce 0x{}" . format ( red ( self . rloc_str , False ) , lisp_hex_string ( Iii1i11 ) ) )
   if 26 - 26: i11iIiiIii - ooOoO0o
   self . last_new_request_nonce_sent = lisp_get_timestamp ( )
   if 45 - 45: ooOoO0o + II111iiii % iII111i
   if 55 - 55: ooOoO0o - oO0o % I1IiiI
   if 61 - 61: ooOoO0o
   if 22 - 22: iIii1I11I1II1 / ooOoO0o / I1IiiI - o0oOOo0O0Ooo
   if 21 - 21: oO0o . i11iIiiIii * I11i . OOooOOo / OOooOOo
   if ( lisp_i_am_itr == False ) : return ( Iii1i11 | 0x80000000 )
   self . send_request_ipc ( ipc_socket , Iii1i11 )
  else :
   lprint ( "Continue request-nonce mode for {}, nonce 0x{}" . format ( red ( self . rloc_str , False ) , lisp_hex_string ( Iii1i11 ) ) )
   if 42 - 42: OoooooooOO / I1Ii111 . o0oOOo0O0Ooo / O0 - IiII * IiII
   if 1 - 1: Ii1I % I1Ii111
   if 97 - 97: OoOoOO00
   if 13 - 13: OoOoOO00 % OOooOOo . O0 / Oo0Ooo % Oo0Ooo
   if 19 - 19: I1Ii111 % ooOoO0o - ooOoO0o % I1IiiI . OOooOOo - OoooooooOO
   if 100 - 100: I1IiiI + Ii1I + o0oOOo0O0Ooo . i1IIi % OoooooooOO
   if 64 - 64: O0 % i1IIi * I1Ii111 - Ii1I + Oo0Ooo
  self . last_request_nonce_sent = lisp_get_timestamp ( )
  return ( Iii1i11 | 0x80000000 )
  if 65 - 65: OoOoOO00 . i11iIiiIii
  if 36 - 36: oO0o * iII111i + IiII * iII111i . I1ii11iIi11i - iIii1I11I1II1
 def request_nonce_timeout ( self ) :
  if ( self . request_nonce_sent == None ) : return ( False )
  if ( self . request_nonce_sent == self . echo_nonce_rcvd ) : return ( False )
  if 14 - 14: I11i * oO0o + i11iIiiIii
  ooOO0o = time . time ( ) - self . last_request_nonce_sent
  o0o0o = self . last_echo_nonce_rcvd
  return ( ooOO0o >= LISP_NONCE_ECHO_INTERVAL and o0o0o == None )
  if 31 - 31: II111iiii . OoooooooOO + OoO0O00 + o0oOOo0O0Ooo . I1IiiI . II111iiii
  if 3 - 3: I11i / I1Ii111 * IiII - O0 + I1IiiI / IiII
 def recently_requested ( self ) :
  o0o0o = self . last_request_nonce_sent
  if ( o0o0o == None ) : return ( False )
  if 19 - 19: i1IIi % II111iiii
  ooOO0o = time . time ( ) - o0o0o
  return ( ooOO0o <= LISP_NONCE_ECHO_INTERVAL )
  if 85 - 85: IiII - o0oOOo0O0Ooo % OOooOOo - II111iiii
  if 56 - 56: Ii1I * i11iIiiIii
 def recently_echoed ( self ) :
  if ( self . request_nonce_sent == None ) : return ( True )
  if 92 - 92: II111iiii - O0 . I1Ii111
  if 59 - 59: OoOoOO00
  if 47 - 47: II111iiii - I1ii11iIi11i - Ii1I
  if 9 - 9: I1ii11iIi11i - IiII
  o0o0o = self . last_good_echo_nonce_rcvd
  if ( o0o0o == None ) : o0o0o = 0
  ooOO0o = time . time ( ) - o0o0o
  if ( ooOO0o <= LISP_NONCE_ECHO_INTERVAL ) : return ( True )
  if 64 - 64: i1IIi
  if 71 - 71: IiII * o0oOOo0O0Ooo
  if 99 - 99: o0oOOo0O0Ooo
  if 28 - 28: OoooooooOO % O0 - OOooOOo / o0oOOo0O0Ooo / I1IiiI
  if 41 - 41: II111iiii * IiII / OoO0O00 . oO0o
  if 50 - 50: OoooooooOO + iIii1I11I1II1 / oO0o / OOooOOo . i11iIiiIii . ooOoO0o
  o0o0o = self . last_new_request_nonce_sent
  if ( o0o0o == None ) : o0o0o = 0
  ooOO0o = time . time ( ) - o0o0o
  return ( ooOO0o <= LISP_NONCE_ECHO_INTERVAL )
  if 75 - 75: iIii1I11I1II1 % ooOoO0o / OOooOOo - iII111i % i11iIiiIii
  if 11 - 11: I11i . Ii1I
 def change_state ( self , rloc ) :
  if ( rloc . up_state ( ) and self . recently_echoed ( ) == False ) :
   oO0OoO = bold ( "down" , False )
   i1II1IiIi111 = lisp_print_elapsed ( self . last_good_echo_nonce_rcvd )
   lprint ( "Take {} {}, last good echo: {}" . format ( red ( self . rloc_str , False ) , oO0OoO , i1II1IiIi111 ) )
   if 53 - 53: II111iiii . II111iiii
   rloc . state = LISP_RLOC_NO_ECHOED_NONCE_STATE
   rloc . last_state_change = lisp_get_timestamp ( )
   return
   if 18 - 18: Ii1I + OoOoOO00 . i1IIi / IiII / iII111i
   if 97 - 97: OoO0O00 + iIii1I11I1II1
  if ( rloc . no_echoed_nonce_state ( ) == False ) : return
  if 79 - 79: ooOoO0o + oO0o - II111iiii . Oo0Ooo
  if ( self . recently_requested ( ) == False ) :
   iIiIi1i1ii11 = bold ( "up" , False )
   lprint ( "Bring {} {}, retry request-nonce mode" . format ( red ( self . rloc_str , False ) , iIiIi1i1ii11 ) )
   if 86 - 86: I1Ii111 * ooOoO0o - ooOoO0o . I1IiiI
   rloc . state = LISP_RLOC_UP_STATE
   rloc . last_state_change = lisp_get_timestamp ( )
   if 69 - 69: i11iIiiIii - iIii1I11I1II1 / Ii1I / II111iiii
   if 81 - 81: OOooOOo - I1ii11iIi11i * Oo0Ooo + oO0o
   if 90 - 90: Oo0Ooo * Ii1I
 def print_echo_nonce ( self ) :
  oO0o0o0 = lisp_print_elapsed ( self . last_request_nonce_sent )
  ii11Ii1iii1I1 = lisp_print_elapsed ( self . last_good_echo_nonce_rcvd )
  if 65 - 65: O0 * oO0o * II111iiii . I11i - i1IIi * OoOoOO00
  i11I111iIiI = lisp_print_elapsed ( self . last_echo_nonce_sent )
  I1Ii11I1i1iii = lisp_print_elapsed ( self . last_request_nonce_rcvd )
  IiiiI1 = space ( 4 )
  if 83 - 83: O0 / OoO0O00
  II = "Nonce-Echoing:\n"
  II += ( "{}Last request-nonce sent: {}\n{}Last echo-nonce " + "received: {}\n" ) . format ( IiiiI1 , oO0o0o0 , IiiiI1 , ii11Ii1iii1I1 )
  if 62 - 62: I11i
  II += ( "{}Last request-nonce received: {}\n{}Last echo-nonce " + "sent: {}" ) . format ( IiiiI1 , I1Ii11I1i1iii , IiiiI1 , i11I111iIiI )
  if 73 - 73: Ii1I % OoO0O00 * OOooOOo
  if 84 - 84: Oo0Ooo
  return ( II )
  if 18 - 18: OoooooooOO
  if 85 - 85: OoooooooOO . OoO0O00 . OoO0O00
  if 70 - 70: I11i
  if 72 - 72: I1Ii111 - ooOoO0o - I1IiiI - iII111i + OOooOOo - i1IIi
  if 45 - 45: OoO0O00 * I1IiiI
  if 61 - 61: iII111i % II111iiii / OoOoOO00 % I1ii11iIi11i . iIii1I11I1II1 % O0
  if 74 - 74: I1ii11iIi11i * oO0o + iII111i % O0
  if 18 - 18: i1IIi % IiII . O0 - O0 - O0 - II111iiii
  if 55 - 55: OoOoOO00 . iIii1I11I1II1 * OOooOOo % iIii1I11I1II1 . OoO0O00
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
    if 43 - 43: Ii1I . OOooOOo + I1IiiI * i11iIiiIii
   self . local_private_key = random . randint ( 0 , 2 ** 128 - 1 )
   i1iI11iI = lisp_hex_string ( self . local_private_key ) . zfill ( 32 )
   self . curve25519 = curve25519 . Private ( i1iI11iI )
  else :
   self . local_private_key = random . randint ( 0 , 0x1fff )
   if 2 - 2: OOooOOo
  self . local_public_key = self . compute_public_key ( )
  self . remote_public_key = None
  self . shared_key = None
  self . encrypt_key = None
  self . icv_key = None
  self . icv = poly1305 if do_poly else hashlib . sha256
  self . iv = None
  self . get_iv ( )
  self . do_poly = do_poly
  if 3 - 3: I1IiiI . iII111i % O0 - ooOoO0o / O0
  if 79 - 79: Ii1I + oO0o % ooOoO0o % I1IiiI
 def copy_keypair ( self , key ) :
  self . local_private_key = key . local_private_key
  self . local_public_key = key . local_public_key
  self . curve25519 = key . curve25519
  if 68 - 68: II111iiii - OoooooooOO / iIii1I11I1II1 - o0oOOo0O0Ooo % II111iiii
  if 53 - 53: iII111i . oO0o / Oo0Ooo . OoO0O00 . i11iIiiIii
 def get_iv ( self ) :
  if ( self . iv == None ) :
   self . iv = random . randint ( 0 , LISP_16_128_MASK )
  else :
   self . iv += 1
   if 60 - 60: II111iiii
  oOOOoo00oO = self . iv
  if ( self . cipher_suite == LISP_CS_25519_CHACHA ) :
   oOOOoo00oO = struct . pack ( "Q" , oOOOoo00oO & LISP_8_64_MASK )
  elif ( self . cipher_suite == LISP_CS_25519_GCM ) :
   iIIIII = struct . pack ( "I" , ( oOOOoo00oO >> 64 ) & LISP_4_32_MASK )
   iiiII = struct . pack ( "Q" , oOOOoo00oO & LISP_8_64_MASK )
   oOOOoo00oO = iIIIII + iiiII
  else :
   oOOOoo00oO = struct . pack ( "QQ" , oOOOoo00oO >> 64 , oOOOoo00oO & LISP_8_64_MASK )
  return ( oOOOoo00oO )
  if 83 - 83: i11iIiiIii + oO0o % i1IIi . IiII + I1ii11iIi11i
  if 62 - 62: oO0o . I1Ii111 - OoooooooOO * II111iiii . i11iIiiIii
 def key_length ( self , key ) :
  if ( type ( key ) != str ) : key = self . normalize_pub_key ( key )
  return ( len ( key ) / 2 )
  if 13 - 13: iIii1I11I1II1 * o0oOOo0O0Ooo - i11iIiiIii
  if 63 - 63: OoooooooOO * I1Ii111
 def print_key ( self , key ) :
  oooooO00OOO = self . normalize_pub_key ( key )
  return ( "0x{}...{}({})" . format ( oooooO00OOO [ 0 : 4 ] , oooooO00OOO [ - 4 : : ] , self . key_length ( oooooO00OOO ) ) )
  if 50 - 50: Oo0Ooo - o0oOOo0O0Ooo % II111iiii . O0 . oO0o % II111iiii
  if 18 - 18: I11i % OoooooooOO + OoO0O00 / I11i
 def normalize_pub_key ( self , key ) :
  if ( type ( key ) == str ) :
   if ( self . curve25519 ) : return ( binascii . hexlify ( key ) )
   return ( key )
   if 37 - 37: i1IIi - Ii1I / IiII . II111iiii % ooOoO0o
  key = lisp_hex_string ( key ) . zfill ( 256 )
  return ( key )
  if 39 - 39: Ii1I % i11iIiiIii * OoO0O00
  if 23 - 23: OOooOOo + ooOoO0o / i11iIiiIii * Oo0Ooo . OoO0O00
 def print_keys ( self , do_bold = True ) :
  i1IIi111iI = bold ( "local-key: " , False ) if do_bold else "local-key: "
  if ( self . local_public_key == None ) :
   i1IIi111iI += "none"
  else :
   i1IIi111iI += self . print_key ( self . local_public_key )
   if 28 - 28: iII111i - o0oOOo0O0Ooo
  IIi = bold ( "remote-key: " , False ) if do_bold else "remote-key: "
  if ( self . remote_public_key == None ) :
   IIi += "none"
  else :
   IIi += self . print_key ( self . remote_public_key )
   if 92 - 92: Oo0Ooo % o0oOOo0O0Ooo - ooOoO0o / ooOoO0o / OoOoOO00
  oo0o0o0o0O = "ECDH" if ( self . curve25519 ) else "DH"
  o0Ooo = self . cipher_suite
  return ( "{} cipher-suite: {}, {}, {}" . format ( oo0o0o0o0O , o0Ooo , i1IIi111iI , IIi ) )
  if 11 - 11: I1ii11iIi11i
  if 53 - 53: o0oOOo0O0Ooo % OoooooooOO - oO0o - i1IIi / OoO0O00
 def compare_keys ( self , keys ) :
  if ( self . dh_g_value != keys . dh_g_value ) : return ( False )
  if ( self . dh_p_value != keys . dh_p_value ) : return ( False )
  if ( self . remote_public_key != keys . remote_public_key ) : return ( False )
  return ( True )
  if 33 - 33: IiII * I11i
  if 96 - 96: o0oOOo0O0Ooo - I1IiiI % OoOoOO00 + OoO0O00 - IiII - IiII
 def compute_public_key ( self ) :
  if ( self . curve25519 ) : return ( self . curve25519 . get_public ( ) . public )
  if 2 - 2: ooOoO0o % i11iIiiIii
  i1iI11iI = self . local_private_key
  IiIoO0oo0 = self . dh_g_value
  IiIiI1 = self . dh_p_value
  return ( int ( ( IiIoO0oo0 ** i1iI11iI ) % IiIiI1 ) )
  if 14 - 14: I1IiiI
  if 8 - 8: o0oOOo0O0Ooo
 def compute_shared_key ( self , ed , print_shared = False ) :
  i1iI11iI = self . local_private_key
  ooOO0O0O = self . remote_public_key
  if 18 - 18: oO0o * O0 - I1IiiI + O0 + I1Ii111
  OOO00 = bold ( "Compute {} shared-key" . format ( ed ) , False )
  lprint ( "{}, key-material: {}" . format ( OOO00 , self . print_keys ( ) ) )
  if 64 - 64: OoOoOO00 + OoO0O00 + i11iIiiIii % iIii1I11I1II1 % iIii1I11I1II1
  if ( self . curve25519 ) :
   oo = curve25519 . Public ( ooOO0O0O )
   self . shared_key = self . curve25519 . get_shared_key ( oo )
  else :
   IiIiI1 = self . dh_p_value
   self . shared_key = ( ooOO0O0O ** i1iI11iI ) % IiIiI1
   if 100 - 100: Oo0Ooo / O0 * i11iIiiIii * OoooooooOO
   if 46 - 46: O0 % OoooooooOO
   if 22 - 22: iII111i + OoooooooOO - OoOoOO00 - OoO0O00 * I1Ii111 - oO0o
   if 99 - 99: ooOoO0o / I1IiiI . Ii1I - Ii1I * I1IiiI
   if 24 - 24: I11i * OoO0O00 - oO0o / iIii1I11I1II1 - Oo0Ooo . OOooOOo
   if 2 - 2: ooOoO0o - O0 - I1ii11iIi11i / I11i * OoOoOO00
   if 26 - 26: I1ii11iIi11i + I1Ii111 - oO0o + IiII % OOooOOo
  if ( print_shared ) :
   oooooO00OOO = self . print_key ( self . shared_key )
   lprint ( "Computed shared-key: {}" . format ( oooooO00OOO ) )
   if 84 - 84: I11i % Ii1I % O0 * o0oOOo0O0Ooo
   if 15 - 15: oO0o - iIii1I11I1II1 - II111iiii - IiII % I1ii11iIi11i
   if 80 - 80: IiII * iII111i . i1IIi % Ii1I % I1ii11iIi11i + ooOoO0o
   if 6 - 6: I1ii11iIi11i . oO0o . OoO0O00 + IiII
   if 65 - 65: I1ii11iIi11i / ooOoO0o
  self . compute_encrypt_icv_keys ( )
  if 23 - 23: OOooOOo / OOooOOo * o0oOOo0O0Ooo * OOooOOo
  if 57 - 57: iII111i
  if 29 - 29: I1IiiI
  if 41 - 41: I1Ii111 * OoO0O00 - iII111i . Ii1I
  self . rekey_count += 1
  self . last_rekey = lisp_get_timestamp ( )
  if 41 - 41: iIii1I11I1II1 - O0 - I1ii11iIi11i - oO0o + I1Ii111
  if 22 - 22: O0 % IiII % iII111i % I1IiiI
 def compute_encrypt_icv_keys ( self ) :
  I11 = hashlib . sha256
  if ( self . curve25519 ) :
   i11i111i1 = self . shared_key
  else :
   i11i111i1 = lisp_hex_string ( self . shared_key )
   if 1 - 1: oO0o - Oo0Ooo * iIii1I11I1II1 * Oo0Ooo * i1IIi
   if 9 - 9: iII111i - iII111i
   if 3 - 3: O0 + O0 - O0 - O0 % OoooooooOO + oO0o
   if 20 - 20: OoO0O00 + I11i . II111iiii / i11iIiiIii
   if 50 - 50: OoooooooOO / OoO0O00 % iIii1I11I1II1
  i1IIi111iI = self . local_public_key
  if ( type ( i1IIi111iI ) != long ) : i1IIi111iI = int ( binascii . hexlify ( i1IIi111iI ) , 16 )
  IIi = self . remote_public_key
  if ( type ( IIi ) != long ) : IIi = int ( binascii . hexlify ( IIi ) , 16 )
  IIIIi11111 = "0001" + "lisp-crypto" + lisp_hex_string ( i1IIi111iI ^ IIi ) + "0100"
  if 99 - 99: O0 * i11iIiiIii % OOooOOo * II111iiii
  ooo0O0o = hmac . new ( IIIIi11111 , i11i111i1 , I11 ) . hexdigest ( )
  ooo0O0o = int ( ooo0O0o , 16 )
  if 92 - 92: I1Ii111 + i1IIi + ooOoO0o
  if 91 - 91: OoooooooOO . i1IIi + iII111i + I1IiiI * OoOoOO00
  if 55 - 55: OoooooooOO + IiII + I1IiiI - I11i - I1ii11iIi11i / i11iIiiIii
  if 87 - 87: iII111i . OoO0O00
  i11II11 = ( ooo0O0o >> 128 ) & LISP_16_128_MASK
  o0o0O00O = ooo0O0o & LISP_16_128_MASK
  self . encrypt_key = lisp_hex_string ( i11II11 ) . zfill ( 32 )
  oO0oO0OoO00 = 32 if self . do_poly else 40
  self . icv_key = lisp_hex_string ( o0o0O00O ) . zfill ( oO0oO0OoO00 )
  if 54 - 54: OoooooooOO * I1IiiI % i1IIi . ooOoO0o % Ii1I . I1ii11iIi11i
  if 72 - 72: ooOoO0o % I11i + OoO0O00
 def do_icv ( self , packet , nonce ) :
  if ( self . icv_key == None ) : return ( "" )
  if ( self . do_poly ) :
   o0o0Oo = self . icv . poly1305aes
   ooOoo00OoO00 = self . icv . binascii . hexlify
   nonce = ooOoo00OoO00 ( nonce )
   ooO = o0o0Oo ( self . encrypt_key , self . icv_key , nonce , packet )
   ooO = ooOoo00OoO00 ( ooO )
  else :
   i1iI11iI = binascii . unhexlify ( self . icv_key )
   ooO = hmac . new ( i1iI11iI , packet , self . icv ) . hexdigest ( )
   ooO = ooO [ 0 : 40 ]
   if 94 - 94: I1ii11iIi11i
  return ( ooO )
  if 33 - 33: I1ii11iIi11i + I1ii11iIi11i . Ii1I
  if 27 - 27: II111iiii - i11iIiiIii - OoooooooOO
 def add_key_by_nonce ( self , nonce ) :
  if ( lisp_crypto_keys_by_nonce . has_key ( nonce ) == False ) :
   lisp_crypto_keys_by_nonce [ nonce ] = [ None , None , None , None ]
   if 90 - 90: I1IiiI
  lisp_crypto_keys_by_nonce [ nonce ] [ self . key_id ] = self
  if 4 - 4: OOooOOo % ooOoO0o - OOooOOo - o0oOOo0O0Ooo
  if 30 - 30: IiII
 def delete_key_by_nonce ( self , nonce ) :
  if ( lisp_crypto_keys_by_nonce . has_key ( nonce ) == False ) : return
  lisp_crypto_keys_by_nonce . pop ( nonce )
  if 34 - 34: oO0o - II111iiii - o0oOOo0O0Ooo + iII111i + I1Ii111
  if 70 - 70: OoooooooOO + OoO0O00 * Oo0Ooo
 def add_key_by_rloc ( self , addr_str , encap ) :
  IiIi11iI1 = lisp_crypto_keys_by_rloc_encap if encap else lisp_crypto_keys_by_rloc_decap
  if 50 - 50: iIii1I11I1II1 + I1Ii111 - I11i - OoooooooOO
  if 84 - 84: OoOoOO00 - I11i
  if ( IiIi11iI1 . has_key ( addr_str ) == False ) :
   IiIi11iI1 [ addr_str ] = [ None , None , None , None ]
   if 80 - 80: i11iIiiIii % OOooOOo - Oo0Ooo % OOooOOo
  IiIi11iI1 [ addr_str ] [ self . key_id ] = self
  if 89 - 89: Ii1I * I11i + OoOoOO00 / i11iIiiIii
  if 68 - 68: OoooooooOO * I11i
  if 86 - 86: o0oOOo0O0Ooo / OoOoOO00
  if 40 - 40: iII111i
  if 62 - 62: ooOoO0o / OOooOOo
  if ( encap == False ) :
   lisp_write_ipc_decap_key ( addr_str , IiIi11iI1 [ addr_str ] )
   if 74 - 74: iII111i % I1Ii111 / I1Ii111 - iIii1I11I1II1 - II111iiii + OOooOOo
   if 92 - 92: I11i % I1Ii111
   if 18 - 18: ooOoO0o + I1Ii111 / OOooOOo / oO0o + iIii1I11I1II1 % IiII
 def encode_lcaf ( self , rloc_addr ) :
  oOoOO00Ooo = self . normalize_pub_key ( self . local_public_key )
  IiiIi1II1iI = self . key_length ( oOoOO00Ooo )
  i1Iii1ii = ( 6 + IiiIi1II1iI + 2 )
  if ( rloc_addr != None ) : i1Iii1ii += rloc_addr . addr_length ( )
  if 33 - 33: I1IiiI / I11i . Oo0Ooo
  Oo0O0oo = struct . pack ( "HBBBBHBB" , socket . htons ( LISP_AFI_LCAF ) , 0 , 0 ,
 LISP_LCAF_SECURITY_TYPE , 0 , socket . htons ( i1Iii1ii ) , 1 , 0 )
  if 89 - 89: iII111i + i1IIi - IiII + ooOoO0o . II111iiii
  if 85 - 85: iIii1I11I1II1 - Ii1I * Oo0Ooo . oO0o + I1Ii111
  if 13 - 13: O0 + iIii1I11I1II1 % II111iiii + iIii1I11I1II1
  if 85 - 85: I1IiiI * iIii1I11I1II1 . iII111i / iII111i
  if 43 - 43: I1IiiI
  if 78 - 78: OoO0O00 % II111iiii + OoOoOO00 / I1IiiI
  o0Ooo = self . cipher_suite
  Oo0O0oo += struct . pack ( "BBH" , o0Ooo , 0 , socket . htons ( IiiIi1II1iI ) )
  if 34 - 34: o0oOOo0O0Ooo % I1ii11iIi11i + Ii1I * I11i / oO0o
  if 18 - 18: ooOoO0o
  if 92 - 92: OoO0O00 % iIii1I11I1II1 / IiII * iII111i . i1IIi + oO0o
  if 24 - 24: IiII . iII111i * IiII % i11iIiiIii . i11iIiiIii + i1IIi
  for o0OoO00 in range ( 0 , IiiIi1II1iI * 2 , 16 ) :
   i1iI11iI = int ( oOoOO00Ooo [ o0OoO00 : o0OoO00 + 16 ] , 16 )
   Oo0O0oo += struct . pack ( "Q" , byte_swap_64 ( i1iI11iI ) )
   if 64 - 64: iIii1I11I1II1 / IiII / Oo0Ooo - I1ii11iIi11i
   if 100 - 100: IiII + i1IIi * OoO0O00
   if 64 - 64: oO0o * i11iIiiIii . Oo0Ooo
   if 52 - 52: Oo0Ooo / ooOoO0o / iII111i - o0oOOo0O0Ooo / iII111i
   if 74 - 74: i1IIi . iIii1I11I1II1
  if ( rloc_addr ) :
   Oo0O0oo += struct . pack ( "H" , socket . htons ( rloc_addr . afi ) )
   Oo0O0oo += rloc_addr . pack_address ( )
   if 85 - 85: I1IiiI
  return ( Oo0O0oo )
  if 10 - 10: O0 . II111iiii / OoooooooOO
  if 72 - 72: OoooooooOO . o0oOOo0O0Ooo + O0
 def decode_lcaf ( self , packet , lcaf_len ) :
  if 46 - 46: OoOoOO00 * I11i / oO0o + Oo0Ooo + IiII
  if 95 - 95: o0oOOo0O0Ooo - Ii1I
  if 67 - 67: I1ii11iIi11i * Oo0Ooo % o0oOOo0O0Ooo
  if 19 - 19: OoOoOO00 . OOooOOo . OoooooooOO
  if ( lcaf_len == 0 ) :
   OoOo0Oooo0o = "HHBBH"
   o0OOo0OOoOO0 = struct . calcsize ( OoOo0Oooo0o )
   if ( len ( packet ) < o0OOo0OOoOO0 ) : return ( None )
   if 79 - 79: OOooOOo * ooOoO0o * I1IiiI * I1ii11iIi11i / I1ii11iIi11i
   I1I1i , O000OOOoOooO , o0oOoOOO , O000OOOoOooO , lcaf_len = struct . unpack ( OoOo0Oooo0o , packet [ : o0OOo0OOoOO0 ] )
   if 74 - 74: iII111i / I1Ii111 / II111iiii - iII111i / oO0o % I11i
   if 19 - 19: IiII % OoooooooOO + OoooooooOO
   if ( o0oOoOOO != LISP_LCAF_SECURITY_TYPE ) :
    packet = packet [ lcaf_len + 6 : : ]
    return ( packet )
    if 7 - 7: i1IIi
   lcaf_len = socket . ntohs ( lcaf_len )
   packet = packet [ o0OOo0OOoOO0 : : ]
   if 91 - 91: OoOoOO00 - OoOoOO00 . IiII
   if 33 - 33: I1Ii111 - iIii1I11I1II1 / Ii1I % O0
   if 80 - 80: IiII % OoooooooOO - IiII
   if 27 - 27: I1Ii111 - o0oOOo0O0Ooo * I1ii11iIi11i - I1IiiI
   if 22 - 22: Oo0Ooo % OoooooooOO - Oo0Ooo - iII111i . Ii1I
   if 100 - 100: II111iiii / I1Ii111 / iII111i - I1ii11iIi11i * iIii1I11I1II1
  o0oOoOOO = LISP_LCAF_SECURITY_TYPE
  OoOo0Oooo0o = "BBBBH"
  o0OOo0OOoOO0 = struct . calcsize ( OoOo0Oooo0o )
  if ( len ( packet ) < o0OOo0OOoOO0 ) : return ( None )
  if 7 - 7: i1IIi . IiII % i11iIiiIii * I1ii11iIi11i . I11i % I1ii11iIi11i
  iII1i , O000OOOoOooO , o0Ooo , O000OOOoOooO , IiiIi1II1iI = struct . unpack ( OoOo0Oooo0o ,
 packet [ : o0OOo0OOoOO0 ] )
  if 62 - 62: OoO0O00 . OoOoOO00
  if 22 - 22: ooOoO0o . i11iIiiIii . OoooooooOO . i1IIi
  if 12 - 12: OoOoOO00 % OOooOOo + oO0o . O0 % iIii1I11I1II1
  if 41 - 41: OoooooooOO
  if 13 - 13: I11i + I1Ii111 - I1Ii111 % oO0o / I11i
  if 4 - 4: I1IiiI + OOooOOo - IiII + iII111i
  packet = packet [ o0OOo0OOoOO0 : : ]
  IiiIi1II1iI = socket . ntohs ( IiiIi1II1iI )
  if ( len ( packet ) < IiiIi1II1iI ) : return ( None )
  if 78 - 78: Ii1I
  if 29 - 29: II111iiii
  if 79 - 79: iIii1I11I1II1 - i11iIiiIii + ooOoO0o - II111iiii . iIii1I11I1II1
  if 84 - 84: Oo0Ooo % I11i * O0 * I11i
  O0Oo = [ LISP_CS_25519_CBC , LISP_CS_25519_GCM , LISP_CS_25519_CHACHA ,
 LISP_CS_1024 ]
  if ( o0Ooo not in O0Oo ) :
   lprint ( "Cipher-suites {} supported, received {}" . format ( O0Oo ,
 o0Ooo ) )
   packet = packet [ IiiIi1II1iI : : ]
   return ( packet )
   if 70 - 70: O0 . iIii1I11I1II1 * II111iiii
   if 43 - 43: Oo0Ooo / I1Ii111 / i1IIi
  self . cipher_suite = o0Ooo
  if 3 - 3: Ii1I * ooOoO0o . OoO0O00 * OoooooooOO + OoOoOO00 / O0
  if 60 - 60: I11i
  if 97 - 97: i11iIiiIii * iIii1I11I1II1 / II111iiii
  if 66 - 66: II111iiii + iII111i * oO0o % I11i / i1IIi / iIii1I11I1II1
  if 62 - 62: OoOoOO00 + oO0o * IiII + O0 / OOooOOo + ooOoO0o
  oOoOO00Ooo = 0
  for o0OoO00 in range ( 0 , IiiIi1II1iI , 8 ) :
   i1iI11iI = byte_swap_64 ( struct . unpack ( "Q" , packet [ o0OoO00 : o0OoO00 + 8 ] ) [ 0 ] )
   oOoOO00Ooo <<= 64
   oOoOO00Ooo |= i1iI11iI
   if 38 - 38: i1IIi / iIii1I11I1II1 + iII111i
  self . remote_public_key = oOoOO00Ooo
  if 26 - 26: I1ii11iIi11i . Ii1I % o0oOOo0O0Ooo
  if 4 - 4: I1Ii111
  if 80 - 80: Oo0Ooo . O0 % o0oOOo0O0Ooo . o0oOOo0O0Ooo
  if 52 - 52: OoO0O00 % i11iIiiIii . ooOoO0o % OoOoOO00 % OoooooooOO
  if 5 - 5: OoOoOO00 / O0 / i11iIiiIii
  if ( self . curve25519 ) :
   i1iI11iI = lisp_hex_string ( self . remote_public_key )
   i1iI11iI = i1iI11iI . zfill ( 64 )
   ooo0o0oO = ""
   for o0OoO00 in range ( 0 , len ( i1iI11iI ) , 2 ) :
    ooo0o0oO += chr ( int ( i1iI11iI [ o0OoO00 : o0OoO00 + 2 ] , 16 ) )
    if 19 - 19: Oo0Ooo - OoO0O00 + i11iIiiIii / iIii1I11I1II1
   self . remote_public_key = ooo0o0oO
   if 1 - 1: IiII % i1IIi
   if 41 - 41: OoO0O00 * OoO0O00 / iII111i + I1ii11iIi11i . o0oOOo0O0Ooo
  packet = packet [ IiiIi1II1iI : : ]
  return ( packet )
  if 84 - 84: i11iIiiIii + OoO0O00 * I1IiiI + I1ii11iIi11i / Ii1I
  if 80 - 80: I1ii11iIi11i
  if 67 - 67: II111iiii
  if 2 - 2: o0oOOo0O0Ooo - O0 * Ii1I % IiII
  if 64 - 64: i1IIi . ooOoO0o
  if 7 - 7: oO0o . iII111i - iII111i / I1Ii111 % Oo0Ooo
  if 61 - 61: oO0o - I1ii11iIi11i / iII111i % I1ii11iIi11i + OoO0O00 / Oo0Ooo
  if 10 - 10: i11iIiiIii / OoOoOO00
class lisp_thread ( ) :
 def __init__ ( self , name ) :
  self . thread_name = name
  self . thread_number = - 1
  self . number_of_pcap_threads = 0
  self . number_of_worker_threads = 0
  self . input_queue = Queue . Queue ( )
  self . input_stats = lisp_stats ( )
  self . lisp_packet = lisp_packet ( None )
  if 27 - 27: I1IiiI / OoooooooOO
  if 74 - 74: I1ii11iIi11i % I1Ii111 - OoO0O00 * I11i . OoooooooOO * OoO0O00
  if 99 - 99: OoOoOO00 . iII111i - OoooooooOO - O0
  if 6 - 6: OOooOOo
  if 3 - 3: O0 - I1Ii111 * Ii1I * OOooOOo / Ii1I
  if 58 - 58: Ii1I * iIii1I11I1II1 + ooOoO0o . ooOoO0o
  if 74 - 74: ooOoO0o - o0oOOo0O0Ooo * IiII % ooOoO0o
  if 93 - 93: iIii1I11I1II1 / OoOoOO00 % Oo0Ooo * I1Ii111 - OoO0O00 - o0oOOo0O0Ooo
  if 44 - 44: OoooooooOO
  if 82 - 82: OoOoOO00 . OoOoOO00
  if 10 - 10: Oo0Ooo * I1ii11iIi11i . oO0o . OoooooooOO . OOooOOo * I1ii11iIi11i
  if 80 - 80: I1Ii111 + I11i . I1Ii111 + OOooOOo
  if 85 - 85: i11iIiiIii . I11i + Ii1I / Ii1I
  if 43 - 43: IiII . OoooooooOO - II111iiii
  if 90 - 90: I1IiiI - iIii1I11I1II1 + I1ii11iIi11i * OOooOOo * oO0o
  if 19 - 19: I1Ii111 * II111iiii % Oo0Ooo - i1IIi
  if 27 - 27: OoOoOO00 . O0 / I1ii11iIi11i . iIii1I11I1II1
  if 15 - 15: Ii1I + OoO0O00 % iIii1I11I1II1 - I1ii11iIi11i - i1IIi % o0oOOo0O0Ooo
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
  if 54 - 54: IiII - II111iiii . ooOoO0o + Ii1I
  if 45 - 45: oO0o + II111iiii . iII111i / I1ii11iIi11i
 def decode ( self , packet ) :
  OoOo0Oooo0o = "BBBBQ"
  o0OOo0OOoOO0 = struct . calcsize ( OoOo0Oooo0o )
  if ( len ( packet ) < o0OOo0OOoOO0 ) : return ( False )
  if 76 - 76: Ii1I + iII111i - IiII * iIii1I11I1II1 % i1IIi
  O0ooOo , Ii , ooooo , self . record_count , self . nonce = struct . unpack ( OoOo0Oooo0o , packet [ : o0OOo0OOoOO0 ] )
  if 4 - 4: i11iIiiIii / I1ii11iIi11i
  if 41 - 41: Ii1I
  self . type = O0ooOo >> 4
  if ( self . type == LISP_MAP_REQUEST ) :
   self . smr_bit = True if ( O0ooOo & 0x01 ) else False
   self . rloc_probe = True if ( O0ooOo & 0x02 ) else False
   self . smr_invoked_bit = True if ( Ii & 0x40 ) else False
   if 49 - 49: Ii1I % II111iiii . Ii1I - o0oOOo0O0Ooo - I11i * IiII
  if ( self . type == LISP_ECM ) :
   self . ddt_bit = True if ( O0ooOo & 0x04 ) else False
   self . to_etr = True if ( O0ooOo & 0x02 ) else False
   self . to_ms = True if ( O0ooOo & 0x01 ) else False
   if 47 - 47: O0 . o0oOOo0O0Ooo / Ii1I * iII111i
  if ( self . type == LISP_NAT_INFO ) :
   self . info_reply = True if ( O0ooOo & 0x08 ) else False
   if 63 - 63: I1Ii111 - oO0o - iII111i - ooOoO0o / oO0o + OoO0O00
  return ( True )
  if 94 - 94: IiII / I1IiiI . II111iiii
  if 32 - 32: oO0o . OOooOOo % OOooOOo . OoOoOO00
 def is_info_request ( self ) :
  return ( ( self . type == LISP_NAT_INFO and self . is_info_reply ( ) == False ) )
  if 37 - 37: OOooOOo + O0 + OOooOOo . iII111i . o0oOOo0O0Ooo
  if 78 - 78: I1IiiI / I11i + o0oOOo0O0Ooo . Oo0Ooo / O0
 def is_info_reply ( self ) :
  return ( True if self . info_reply else False )
  if 49 - 49: I1ii11iIi11i
  if 66 - 66: o0oOOo0O0Ooo . I1ii11iIi11i
 def is_rloc_probe ( self ) :
  return ( True if self . rloc_probe else False )
  if 18 - 18: Oo0Ooo + IiII
  if 79 - 79: OoO0O00 - O0 + II111iiii % Ii1I . I1IiiI
 def is_smr ( self ) :
  return ( True if self . smr_bit else False )
  if 43 - 43: I1IiiI % I1ii11iIi11i * Ii1I
  if 31 - 31: Ii1I / iII111i
 def is_smr_invoked ( self ) :
  return ( True if self . smr_invoked_bit else False )
  if 3 - 3: IiII
  if 37 - 37: Ii1I * OoooooooOO * I11i + Oo0Ooo . I1IiiI
 def is_ddt ( self ) :
  return ( True if self . ddt_bit else False )
  if 61 - 61: OOooOOo . OOooOOo
  if 17 - 17: II111iiii / ooOoO0o
 def is_to_etr ( self ) :
  return ( True if self . to_etr else False )
  if 80 - 80: OOooOOo * OoO0O00 + Ii1I
  if 62 - 62: OoooooooOO . O0 % Oo0Ooo
 def is_to_ms ( self ) :
  return ( True if self . to_ms else False )
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
  if 69 - 69: OOooOOo * O0 + i11iIiiIii
  if 65 - 65: O0 / iII111i . i1IIi * iII111i / iIii1I11I1II1 - oO0o
  if 93 - 93: OoOoOO00 % i11iIiiIii - Ii1I % OoO0O00
  if 55 - 55: o0oOOo0O0Ooo . I1ii11iIi11i
  if 63 - 63: oO0o
  if 79 - 79: I1ii11iIi11i - oO0o - o0oOOo0O0Ooo . OOooOOo
  if 65 - 65: i11iIiiIii . OoO0O00 % iII111i + IiII - i11iIiiIii
  if 60 - 60: I1Ii111
  if 14 - 14: Oo0Ooo % oO0o * iII111i - i11iIiiIii / I1ii11iIi11i * i11iIiiIii
  if 95 - 95: iIii1I11I1II1 + OoOoOO00 . I1IiiI + OoOoOO00 * I11i + OOooOOo
  if 14 - 14: Ii1I - O0
  if 68 - 68: II111iiii - I1ii11iIi11i - OoO0O00 * iIii1I11I1II1 / I1IiiI * I1ii11iIi11i
  if 45 - 45: I1Ii111 * I11i / iIii1I11I1II1 / I1IiiI % II111iiii
  if 49 - 49: Ii1I / iII111i . iII111i . iII111i + i11iIiiIii % I11i
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
  if 7 - 7: IiII * ooOoO0o + OoOoOO00
  if 22 - 22: iII111i
 def print_map_register ( self ) :
  iIi = lisp_hex_string ( self . xtr_id )
  if 73 - 73: O0 . I1Ii111 - OoooooooOO % I11i % i1IIi
  iI1111i = ( "{} -> flags: {}{}{}{}{}{}{}{}{}, record-count: " +
 "{}, nonce: 0x{}, key/alg-id: {}/{}{}, auth-len: {}, xtr-id: " +
 "0x{}, site-id: {}" )
  if 14 - 14: I1Ii111 + Ii1I * Oo0Ooo
  lprint ( iI1111i . format ( bold ( "Map-Register" , False ) , "P" if self . proxy_reply_requested else "p" ,
  # Oo0Ooo . OOooOOo - I1Ii111
 "S" if self . lisp_sec_present else "s" ,
 "I" if self . xtr_id_present else "i" ,
 "T" if self . use_ttl_for_timeout else "t" ,
 "R" if self . merge_register_requested else "r" ,
 "M" if self . mobile_node else "m" ,
 "N" if self . map_notify_requested else "n" ,
 "F" if self . map_register_refresh else "f" ,
 "E" if self . encrypt_bit else "e" ,
 self . record_count , lisp_hex_string ( self . nonce ) , self . key_id ,
 self . alg_id , " (sha1)" if ( self . key_id == LISP_SHA_1_96_ALG_ID ) else ( " (sha2)" if ( self . key_id == LISP_SHA_256_128_ALG_ID ) else "" ) , self . auth_len , iIi , self . site_id ) )
  if 10 - 10: oO0o * IiII * iII111i . O0
  if 19 - 19: IiII
  if 75 - 75: Ii1I % O0
  if 57 - 57: O0 . OoO0O00
 def encode ( self ) :
  iiii1ii1 = ( LISP_MAP_REGISTER << 28 ) | self . record_count
  if ( self . proxy_reply_requested ) : iiii1ii1 |= 0x08000000
  if ( self . lisp_sec_present ) : iiii1ii1 |= 0x04000000
  if ( self . xtr_id_present ) : iiii1ii1 |= 0x02000000
  if ( self . map_register_refresh ) : iiii1ii1 |= 0x1000
  if ( self . use_ttl_for_timeout ) : iiii1ii1 |= 0x800
  if ( self . merge_register_requested ) : iiii1ii1 |= 0x400
  if ( self . mobile_node ) : iiii1ii1 |= 0x200
  if ( self . map_notify_requested ) : iiii1ii1 |= 0x100
  if ( self . encryption_key_id != None ) :
   iiii1ii1 |= 0x2000
   iiii1ii1 |= self . encryption_key_id << 14
   if 32 - 32: ooOoO0o
   if 26 - 26: O0 * Ii1I - I1IiiI - iII111i / iIii1I11I1II1
   if 57 - 57: I1ii11iIi11i - OoO0O00 * iIii1I11I1II1
   if 26 - 26: OoO0O00 % ooOoO0o % o0oOOo0O0Ooo % OoOoOO00 . iII111i % O0
   if 91 - 91: II111iiii . Oo0Ooo . oO0o - OoooooooOO / OoOoOO00
  if ( self . alg_id == LISP_NONE_ALG_ID ) :
   self . auth_len = 0
  else :
   if ( self . alg_id == LISP_SHA_1_96_ALG_ID ) :
    self . auth_len = LISP_SHA1_160_AUTH_DATA_LEN
    if 30 - 30: I11i % o0oOOo0O0Ooo + i1IIi * OoooooooOO * OoO0O00 - II111iiii
   if ( self . alg_id == LISP_SHA_256_128_ALG_ID ) :
    self . auth_len = LISP_SHA2_256_AUTH_DATA_LEN
    if 55 - 55: OoO0O00
    if 20 - 20: ooOoO0o * I1Ii111 * o0oOOo0O0Ooo - ooOoO0o
    if 32 - 32: Ii1I * oO0o
  Oo0O0oo = struct . pack ( "I" , socket . htonl ( iiii1ii1 ) )
  Oo0O0oo += struct . pack ( "QBBH" , self . nonce , self . key_id , self . alg_id ,
 socket . htons ( self . auth_len ) )
  if 85 - 85: i11iIiiIii . OoO0O00 + OoO0O00
  Oo0O0oo = self . zero_auth ( Oo0O0oo )
  return ( Oo0O0oo )
  if 28 - 28: Oo0Ooo
  if 62 - 62: Oo0Ooo + OoooooooOO / iII111i
 def zero_auth ( self , packet ) :
  oOo0 = struct . calcsize ( "I" ) + struct . calcsize ( "QHH" )
  O0oO0 = ""
  O0ooo00o0 = 0
  if ( self . alg_id == LISP_NONE_ALG_ID ) : return ( packet )
  if ( self . alg_id == LISP_SHA_1_96_ALG_ID ) :
   O0oO0 = struct . pack ( "QQI" , 0 , 0 , 0 )
   O0ooo00o0 = struct . calcsize ( "QQI" )
   if 2 - 2: I1Ii111 / OOooOOo
  if ( self . alg_id == LISP_SHA_256_128_ALG_ID ) :
   O0oO0 = struct . pack ( "QQQQ" , 0 , 0 , 0 , 0 )
   O0ooo00o0 = struct . calcsize ( "QQQQ" )
   if 6 - 6: i11iIiiIii / Oo0Ooo % iII111i / OOooOOo * O0
  packet = packet [ 0 : oOo0 ] + O0oO0 + packet [ oOo0 + O0ooo00o0 : : ]
  return ( packet )
  if 18 - 18: O0
  if 14 - 14: Ii1I / IiII - O0
 def encode_auth ( self , packet ) :
  oOo0 = struct . calcsize ( "I" ) + struct . calcsize ( "QHH" )
  O0ooo00o0 = self . auth_len
  O0oO0 = self . auth_data
  packet = packet [ 0 : oOo0 ] + O0oO0 + packet [ oOo0 + O0ooo00o0 : : ]
  return ( packet )
  if 16 - 16: I1Ii111 % iIii1I11I1II1 . i1IIi
  if 72 - 72: ooOoO0o * OOooOOo
 def decode ( self , packet ) :
  oOoo0O000 = packet
  OoOo0Oooo0o = "I"
  o0OOo0OOoOO0 = struct . calcsize ( OoOo0Oooo0o )
  if ( len ( packet ) < o0OOo0OOoOO0 ) : return ( [ None , None ] )
  if 47 - 47: I11i * Oo0Ooo - i1IIi . Ii1I
  iiii1ii1 = struct . unpack ( OoOo0Oooo0o , packet [ : o0OOo0OOoOO0 ] )
  iiii1ii1 = socket . ntohl ( iiii1ii1 [ 0 ] )
  packet = packet [ o0OOo0OOoOO0 : : ]
  if 7 - 7: Oo0Ooo
  OoOo0Oooo0o = "QBBH"
  o0OOo0OOoOO0 = struct . calcsize ( OoOo0Oooo0o )
  if ( len ( packet ) < o0OOo0OOoOO0 ) : return ( [ None , None ] )
  if 96 - 96: Ii1I * OOooOOo . i11iIiiIii - I1IiiI
  self . nonce , self . key_id , self . alg_id , self . auth_len = struct . unpack ( OoOo0Oooo0o , packet [ : o0OOo0OOoOO0 ] )
  if 94 - 94: o0oOOo0O0Ooo + Ii1I % o0oOOo0O0Ooo . I1Ii111 - ooOoO0o * I1IiiI
  if 62 - 62: Oo0Ooo * i1IIi % I1ii11iIi11i + Oo0Ooo . O0 . ooOoO0o
  self . auth_len = socket . ntohs ( self . auth_len )
  self . proxy_reply_requested = True if ( iiii1ii1 & 0x08000000 ) else False
  if 57 - 57: Oo0Ooo - I1Ii111 + O0 % o0oOOo0O0Ooo
  self . lisp_sec_present = True if ( iiii1ii1 & 0x04000000 ) else False
  self . xtr_id_present = True if ( iiii1ii1 & 0x02000000 ) else False
  self . use_ttl_for_timeout = True if ( iiii1ii1 & 0x800 ) else False
  self . map_register_refresh = True if ( iiii1ii1 & 0x1000 ) else False
  self . merge_register_requested = True if ( iiii1ii1 & 0x400 ) else False
  self . mobile_node = True if ( iiii1ii1 & 0x200 ) else False
  self . map_notify_requested = True if ( iiii1ii1 & 0x100 ) else False
  self . record_count = iiii1ii1 & 0xff
  if 72 - 72: OOooOOo . OoOoOO00 / II111iiii
  if 69 - 69: OOooOOo * II111iiii - ooOoO0o - i1IIi + i11iIiiIii
  if 50 - 50: OoooooooOO * i1IIi / oO0o
  if 83 - 83: i1IIi
  self . encrypt_bit = True if iiii1ii1 & 0x2000 else False
  if ( self . encrypt_bit ) :
   self . encryption_key_id = ( iiii1ii1 >> 14 ) & 0x7
   if 38 - 38: OoooooooOO * iIii1I11I1II1
   if 54 - 54: OoooooooOO . I1Ii111
   if 71 - 71: Ii1I
   if 31 - 31: I11i . i11iIiiIii . OoO0O00 * Oo0Ooo % Ii1I . o0oOOo0O0Ooo
   if 92 - 92: OoooooooOO / O0 * i1IIi + iIii1I11I1II1
  if ( self . xtr_id_present ) :
   if ( self . decode_xtr_id ( oOoo0O000 ) == False ) : return ( [ None , None ] )
   if 93 - 93: ooOoO0o % I1Ii111
   if 46 - 46: I1ii11iIi11i * OoOoOO00 * IiII * I1ii11iIi11i . I1ii11iIi11i
  packet = packet [ o0OOo0OOoOO0 : : ]
  if 43 - 43: ooOoO0o . i1IIi
  if 68 - 68: IiII % Oo0Ooo . O0 - OoOoOO00 + I1ii11iIi11i . i11iIiiIii
  if 45 - 45: I1IiiI
  if 17 - 17: OoooooooOO - ooOoO0o + Ii1I . OoooooooOO % Oo0Ooo
  if ( self . auth_len != 0 ) :
   if ( len ( packet ) < self . auth_len ) : return ( [ None , None ] )
   if 92 - 92: I1Ii111 - OOooOOo % OoO0O00 - o0oOOo0O0Ooo % i1IIi
   if ( self . alg_id not in ( LISP_NONE_ALG_ID , LISP_SHA_1_96_ALG_ID ,
 LISP_SHA_256_128_ALG_ID ) ) :
    lprint ( "Invalid authentication alg-id: {}" . format ( self . alg_id ) )
    return ( [ None , None ] )
    if 38 - 38: I1ii11iIi11i . I11i / OoOoOO00 % I11i
    if 10 - 10: O0 . I1IiiI * o0oOOo0O0Ooo / iII111i
   O0ooo00o0 = self . auth_len
   if ( self . alg_id == LISP_SHA_1_96_ALG_ID ) :
    o0OOo0OOoOO0 = struct . calcsize ( "QQI" )
    if ( O0ooo00o0 < o0OOo0OOoOO0 ) :
     lprint ( "Invalid sha1-96 authentication length" )
     return ( [ None , None ] )
     if 61 - 61: Oo0Ooo - I1Ii111
    O0o0oooOo0oo , OO0oOooo , ii1I = struct . unpack ( "QQI" , packet [ : O0ooo00o0 ] )
    iIIiiiIiiii11 = ""
   elif ( self . alg_id == LISP_SHA_256_128_ALG_ID ) :
    o0OOo0OOoOO0 = struct . calcsize ( "QQQQ" )
    if ( O0ooo00o0 < o0OOo0OOoOO0 ) :
     lprint ( "Invalid sha2-256 authentication length" )
     return ( [ None , None ] )
     if 22 - 22: I11i
    O0o0oooOo0oo , OO0oOooo , ii1I , iIIiiiIiiii11 = struct . unpack ( "QQQQ" ,
 packet [ : O0ooo00o0 ] )
   else :
    lprint ( "Unsupported authentication alg-id value {}" . format ( self . alg_id ) )
    if 50 - 50: IiII . I11i / Ii1I . O0 . i11iIiiIii + II111iiii
    return ( [ None , None ] )
    if 20 - 20: I1IiiI % i1IIi % OoOoOO00 % I1Ii111 + O0
   self . auth_data = lisp_concat_auth_data ( self . alg_id , O0o0oooOo0oo , OO0oOooo ,
 ii1I , iIIiiiIiiii11 )
   oOoo0O000 = self . zero_auth ( oOoo0O000 )
   packet = packet [ self . auth_len : : ]
   if 54 - 54: O0
  return ( [ oOoo0O000 , packet ] )
  if 3 - 3: I1ii11iIi11i
  if 42 - 42: I11i % Oo0Ooo + IiII - I11i . iIii1I11I1II1 - Ii1I
 def encode_xtr_id ( self , packet ) :
  I1iIiI1iiI = self . xtr_id >> 64
  oO000O00 = self . xtr_id & 0xffffffffffffffff
  I1iIiI1iiI = byte_swap_64 ( I1iIiI1iiI )
  oO000O00 = byte_swap_64 ( oO000O00 )
  IiIIIii1iIII1 = byte_swap_64 ( self . site_id )
  packet += struct . pack ( "QQQ" , I1iIiI1iiI , oO000O00 , IiIIIii1iIII1 )
  return ( packet )
  if 69 - 69: i1IIi / i11iIiiIii + Oo0Ooo - OoOoOO00
  if 13 - 13: IiII . iIii1I11I1II1
 def decode_xtr_id ( self , packet ) :
  o0OOo0OOoOO0 = struct . calcsize ( "QQQ" )
  if ( len ( packet ) < o0OOo0OOoOO0 ) : return ( [ None , None ] )
  packet = packet [ len ( packet ) - o0OOo0OOoOO0 : : ]
  I1iIiI1iiI , oO000O00 , IiIIIii1iIII1 = struct . unpack ( "QQQ" ,
 packet [ : o0OOo0OOoOO0 ] )
  I1iIiI1iiI = byte_swap_64 ( I1iIiI1iiI )
  oO000O00 = byte_swap_64 ( oO000O00 )
  self . xtr_id = ( I1iIiI1iiI << 64 ) | oO000O00
  self . site_id = byte_swap_64 ( IiIIIii1iIII1 )
  return ( True )
  if 30 - 30: i1IIi
  if 42 - 42: iII111i
  if 35 - 35: II111iiii % OOooOOo . oO0o * ooOoO0o
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
  if 80 - 80: i1IIi % OoOoOO00 + OoO0O00 - OoooooooOO / iIii1I11I1II1 + I1Ii111
  if 65 - 65: Ii1I
  if 71 - 71: I1Ii111 % I1Ii111 . oO0o + i11iIiiIii - i11iIiiIii
  if 16 - 16: iIii1I11I1II1 / I1IiiI / I1Ii111 - i11iIiiIii . ooOoO0o / OOooOOo
  if 13 - 13: o0oOOo0O0Ooo % O0 - I1Ii111 * OoooooooOO / Oo0Ooo - OoooooooOO
  if 78 - 78: oO0o % OoooooooOO
  if 73 - 73: I1IiiI % ooOoO0o % IiII + i1IIi - OoooooooOO / oO0o
  if 78 - 78: OoooooooOO % oO0o - i11iIiiIii
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
  if 37 - 37: IiII % Ii1I % i1IIi
  if 23 - 23: ooOoO0o - O0 + i11iIiiIii
 def print_notify ( self ) :
  O0oO0 = binascii . hexlify ( self . auth_data )
  if ( self . alg_id == LISP_SHA_1_96_ALG_ID and len ( O0oO0 ) != 40 ) :
   O0oO0 = self . auth_data
  elif ( self . alg_id == LISP_SHA_256_128_ALG_ID and len ( O0oO0 ) != 64 ) :
   O0oO0 = self . auth_data
   if 98 - 98: OoooooooOO
  iI1111i = ( "{} -> record-count: {}, nonce: 0x{}, key/alg-id: " +
 "{}{}{}, auth-len: {}, auth-data: {}" )
  lprint ( iI1111i . format ( bold ( "Map-Notify-Ack" , False ) if self . map_notify_ack else bold ( "Map-Notify" , False ) ,
  # iIii1I11I1II1 % OoooooooOO - Oo0Ooo * O0
 self . record_count , lisp_hex_string ( self . nonce ) , self . key_id ,
 self . alg_id , " (sha1)" if ( self . key_id == LISP_SHA_1_96_ALG_ID ) else ( " (sha2)" if ( self . key_id == LISP_SHA_256_128_ALG_ID ) else "" ) , self . auth_len , O0oO0 ) )
  if 50 - 50: O0
  if 65 - 65: i1IIi * OOooOOo * OoooooooOO - IiII . iII111i - OoO0O00
  if 71 - 71: Ii1I * OoOoOO00
  if 33 - 33: i1IIi . i1IIi * OoooooooOO % I1Ii111 * o0oOOo0O0Ooo
 def zero_auth ( self , packet ) :
  if ( self . alg_id == LISP_NONE_ALG_ID ) : return ( packet )
  if ( self . alg_id == LISP_SHA_1_96_ALG_ID ) :
   O0oO0 = struct . pack ( "QQI" , 0 , 0 , 0 )
   if 64 - 64: ooOoO0o / ooOoO0o + I1ii11iIi11i * OOooOOo % OOooOOo
  if ( self . alg_id == LISP_SHA_256_128_ALG_ID ) :
   O0oO0 = struct . pack ( "QQQQ" , 0 , 0 , 0 , 0 )
   if 87 - 87: OoO0O00 * Oo0Ooo
  packet += O0oO0
  return ( packet )
  if 83 - 83: i1IIi * I1Ii111 - IiII / Ii1I
  if 48 - 48: oO0o . II111iiii - OoOoOO00 % i1IIi . OoOoOO00
 def encode ( self , eid_records , password ) :
  if ( self . map_notify_ack ) :
   iiii1ii1 = ( LISP_MAP_NOTIFY_ACK << 28 ) | self . record_count
  else :
   iiii1ii1 = ( LISP_MAP_NOTIFY << 28 ) | self . record_count
   if 32 - 32: Ii1I * I1IiiI - OOooOOo . Oo0Ooo / O0 + Ii1I
  Oo0O0oo = struct . pack ( "I" , socket . htonl ( iiii1ii1 ) )
  Oo0O0oo += struct . pack ( "QBBH" , self . nonce , self . key_id , self . alg_id ,
 socket . htons ( self . auth_len ) )
  if 67 - 67: OoOoOO00 % Oo0Ooo
  if ( self . alg_id == LISP_NONE_ALG_ID ) :
   self . packet = Oo0O0oo + eid_records
   return ( self . packet )
   if 7 - 7: i11iIiiIii % I1ii11iIi11i / I1Ii111 % Oo0Ooo - OoO0O00
   if 73 - 73: I1ii11iIi11i
   if 92 - 92: i11iIiiIii + O0 * I11i
   if 60 - 60: o0oOOo0O0Ooo / Oo0Ooo
   if 19 - 19: iIii1I11I1II1 . OoO0O00 / OoooooooOO
  Oo0O0oo = self . zero_auth ( Oo0O0oo )
  Oo0O0oo += eid_records
  if 2 - 2: O0 - O0 % I1Ii111 / I1ii11iIi11i
  I1i1Ii = lisp_hash_me ( Oo0O0oo , self . alg_id , password , False )
  if 76 - 76: OoO0O00 * oO0o - OoO0O00
  oOo0 = struct . calcsize ( "I" ) + struct . calcsize ( "QHH" )
  O0ooo00o0 = self . auth_len
  self . auth_data = I1i1Ii
  Oo0O0oo = Oo0O0oo [ 0 : oOo0 ] + I1i1Ii + Oo0O0oo [ oOo0 + O0ooo00o0 : : ]
  self . packet = Oo0O0oo
  return ( Oo0O0oo )
  if 57 - 57: OoooooooOO / OoOoOO00 + oO0o . Ii1I
  if 14 - 14: i11iIiiIii % OOooOOo * o0oOOo0O0Ooo * OoOoOO00
 def decode ( self , packet ) :
  oOoo0O000 = packet
  OoOo0Oooo0o = "I"
  o0OOo0OOoOO0 = struct . calcsize ( OoOo0Oooo0o )
  if ( len ( packet ) < o0OOo0OOoOO0 ) : return ( None )
  if 55 - 55: I1Ii111 * OOooOOo * I1Ii111
  iiii1ii1 = struct . unpack ( OoOo0Oooo0o , packet [ : o0OOo0OOoOO0 ] )
  iiii1ii1 = socket . ntohl ( iiii1ii1 [ 0 ] )
  self . map_notify_ack = ( ( iiii1ii1 >> 28 ) == LISP_MAP_NOTIFY_ACK )
  self . record_count = iiii1ii1 & 0xff
  packet = packet [ o0OOo0OOoOO0 : : ]
  if 70 - 70: O0 . Ii1I
  OoOo0Oooo0o = "QBBH"
  o0OOo0OOoOO0 = struct . calcsize ( OoOo0Oooo0o )
  if ( len ( packet ) < o0OOo0OOoOO0 ) : return ( None )
  if 33 - 33: OOooOOo * Ii1I
  self . nonce , self . key_id , self . alg_id , self . auth_len = struct . unpack ( OoOo0Oooo0o , packet [ : o0OOo0OOoOO0 ] )
  if 64 - 64: i11iIiiIii . iIii1I11I1II1
  self . nonce_key = lisp_hex_string ( self . nonce )
  self . auth_len = socket . ntohs ( self . auth_len )
  packet = packet [ o0OOo0OOoOO0 : : ]
  self . eid_records = packet [ self . auth_len : : ]
  if 7 - 7: OoOoOO00 % ooOoO0o + OoOoOO00 - OoOoOO00 * i11iIiiIii % OoO0O00
  if ( self . auth_len == 0 ) : return ( self . eid_records )
  if 57 - 57: OOooOOo / OoO0O00 + I1ii11iIi11i
  if 60 - 60: O0 * Oo0Ooo % OOooOOo + IiII . OoO0O00 . Oo0Ooo
  if 70 - 70: I11i . I1ii11iIi11i * oO0o
  if 97 - 97: oO0o . iIii1I11I1II1 - OOooOOo
  if ( len ( packet ) < self . auth_len ) : return ( None )
  if 23 - 23: I1ii11iIi11i % I11i
  O0ooo00o0 = self . auth_len
  if ( self . alg_id == LISP_SHA_1_96_ALG_ID ) :
   O0o0oooOo0oo , OO0oOooo , ii1I = struct . unpack ( "QQI" , packet [ : O0ooo00o0 ] )
   iIIiiiIiiii11 = ""
   if 18 - 18: OoooooooOO . i1IIi + II111iiii
  if ( self . alg_id == LISP_SHA_256_128_ALG_ID ) :
   O0o0oooOo0oo , OO0oOooo , ii1I , iIIiiiIiiii11 = struct . unpack ( "QQQQ" ,
 packet [ : O0ooo00o0 ] )
   if 99 - 99: I1Ii111 - I1ii11iIi11i - I1IiiI - I1Ii111 + OoO0O00 + II111iiii
  self . auth_data = lisp_concat_auth_data ( self . alg_id , O0o0oooOo0oo , OO0oOooo ,
 ii1I , iIIiiiIiiii11 )
  if 34 - 34: I1Ii111 * I11i
  o0OOo0OOoOO0 = struct . calcsize ( "I" ) + struct . calcsize ( "QHH" )
  packet = self . zero_auth ( oOoo0O000 [ : o0OOo0OOoOO0 ] )
  o0OOo0OOoOO0 += O0ooo00o0
  packet += oOoo0O000 [ o0OOo0OOoOO0 : : ]
  return ( packet )
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
  if 17 - 17: OoO0O00 . I1IiiI * O0
  if 81 - 81: OOooOOo
  if 58 - 58: II111iiii . I1Ii111 . Ii1I * OoooooooOO / Ii1I / I11i
  if 41 - 41: I11i + OoO0O00 . iII111i
  if 73 - 73: i11iIiiIii * I1IiiI + o0oOOo0O0Ooo / oO0o
  if 56 - 56: i1IIi
  if 11 - 11: i11iIiiIii % o0oOOo0O0Ooo / I11i * OoooooooOO
  if 82 - 82: IiII
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
  if 10 - 10: Oo0Ooo % OOooOOo / I11i * IiII - o0oOOo0O0Ooo
  if 54 - 54: i11iIiiIii / iIii1I11I1II1 % I1ii11iIi11i / I1IiiI . iIii1I11I1II1 / iII111i
 def print_prefix ( self ) :
  if ( self . target_group . is_null ( ) ) :
   return ( green ( self . target_eid . print_prefix ( ) , False ) )
   if 1 - 1: I1Ii111 / OoOoOO00 * OoOoOO00 - o0oOOo0O0Ooo % Ii1I
  return ( green ( self . target_eid . print_sg ( self . target_group ) , False ) )
  if 96 - 96: IiII / Ii1I % OoO0O00 . iIii1I11I1II1
  if 30 - 30: I11i - OoO0O00
 def print_map_request ( self ) :
  iIi = ""
  if ( self . xtr_id != None and self . subscribe_bit ) :
   iIi = "subscribe, xtr-id: 0x{}, " . format ( lisp_hex_string ( self . xtr_id ) )
   if 15 - 15: OoooooooOO
   if 31 - 31: II111iiii
   if 62 - 62: iIii1I11I1II1 % I1Ii111 % I1ii11iIi11i * IiII
  iI1111i = ( "{} -> flags: {}{}{}{}{}{}{}{}{}{}, itr-rloc-" +
 "count: {} (+1), record-count: {}, nonce: 0x{}, source-eid: " +
 "afi {}, {}{}, target-eid: afi {}, {}, {}ITR-RLOCs:" )
  if 87 - 87: IiII
  lprint ( iI1111i . format ( bold ( "Map-Request" , False ) , "A" if self . auth_bit else "a" ,
  # OoO0O00 % ooOoO0o - II111iiii
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
 self . target_eid . afi , green ( self . print_prefix ( ) , False ) , iIi ) )
  if 70 - 70: OoooooooOO
  Ii111I11 = self . keys
  for oo0Oo0oo in self . itr_rlocs :
   lprint ( "  itr-rloc: afi {} {}{}" . format ( oo0Oo0oo . afi ,
 red ( oo0Oo0oo . print_address_no_iid ( ) , False ) ,
 "" if ( Ii111I11 == None ) else ", " + Ii111I11 [ 1 ] . print_keys ( ) ) )
   Ii111I11 = None
   if 1 - 1: o0oOOo0O0Ooo % Oo0Ooo / i11iIiiIii * I1IiiI - i1IIi / o0oOOo0O0Ooo
   if 24 - 24: I1ii11iIi11i * OoO0O00 . OoooooooOO % Ii1I % O0
   if 46 - 46: iII111i + I1Ii111 % OoooooooOO * I1ii11iIi11i
 def sign_map_request ( self , privkey ) :
  O000o0O0 = self . signature_eid . print_address ( )
  O0000oOoO0o0 = self . source_eid . print_address ( )
  IiiIiII1Ii1 = self . target_eid . print_address ( )
  o000o0O = lisp_hex_string ( self . nonce ) + O0000oOoO0o0 + IiiIiII1Ii1
  self . map_request_signature = privkey . sign ( o000o0O )
  IIIIi1I = binascii . b2a_base64 ( self . map_request_signature )
  IIIIi1I = { "source-eid" : O0000oOoO0o0 , "signature-eid" : O000o0O0 ,
 "signature" : IIIIi1I }
  return ( json . dumps ( IIIIi1I ) )
  if 11 - 11: Ii1I / OoOoOO00 - OoO0O00 + OoOoOO00
  if 51 - 51: ooOoO0o
 def verify_map_request_sig ( self , pubkey ) :
  IIiIi111i = green ( self . signature_eid . print_address ( ) , False )
  if ( pubkey == None ) :
   lprint ( "Public-key not found for signature-EID {}" . format ( IIiIi111i ) )
   return ( False )
   if 40 - 40: Oo0Ooo * OoooooooOO + IiII
   if 58 - 58: I1IiiI
  O0000oOoO0o0 = self . source_eid . print_address ( )
  IiiIiII1Ii1 = self . target_eid . print_address ( )
  o000o0O = lisp_hex_string ( self . nonce ) + O0000oOoO0o0 + IiiIiII1Ii1
  pubkey = binascii . a2b_base64 ( pubkey )
  if 21 - 21: IiII - I1IiiI . OOooOOo - oO0o
  ii1ii = True
  try :
   i1iI11iI = ecdsa . VerifyingKey . from_pem ( pubkey )
  except :
   lprint ( "Invalid public-key in mapping system for sig-eid {}" . format ( self . signature_eid . print_address_no_iid ( ) ) )
   if 48 - 48: I1ii11iIi11i + O0 * oO0o + I1ii11iIi11i + I1ii11iIi11i
   ii1ii = False
   if 60 - 60: II111iiii % Oo0Ooo
   if 62 - 62: O0 + iII111i - iII111i % iIii1I11I1II1
  if ( ii1ii ) :
   try :
    ii1ii = i1iI11iI . verify ( self . map_request_signature , o000o0O )
   except :
    ii1ii = False
    if 47 - 47: I1Ii111 + I1IiiI
    if 40 - 40: iIii1I11I1II1 % Ii1I + II111iiii - I1IiiI
    if 80 - 80: oO0o
  Oo00o = bold ( "passed" if ii1ii else "failed" , False )
  lprint ( "Signature verification {} for EID {}" . format ( Oo00o , IIiIi111i ) )
  return ( ii1ii )
  if 14 - 14: II111iiii + O0 - iII111i
  if 18 - 18: o0oOOo0O0Ooo / i11iIiiIii % I1ii11iIi11i * OoooooooOO
 def encode ( self , probe_dest , probe_port ) :
  iiii1ii1 = ( LISP_MAP_REQUEST << 28 ) | self . record_count
  iiii1ii1 = iiii1ii1 | ( self . itr_rloc_count << 8 )
  if ( self . auth_bit ) : iiii1ii1 |= 0x08000000
  if ( self . map_data_present ) : iiii1ii1 |= 0x04000000
  if ( self . rloc_probe ) : iiii1ii1 |= 0x02000000
  if ( self . smr_bit ) : iiii1ii1 |= 0x01000000
  if ( self . pitr_bit ) : iiii1ii1 |= 0x00800000
  if ( self . smr_invoked_bit ) : iiii1ii1 |= 0x00400000
  if ( self . mobile_node ) : iiii1ii1 |= 0x00200000
  if ( self . xtr_id_present ) : iiii1ii1 |= 0x00100000
  if ( self . local_xtr ) : iiii1ii1 |= 0x00004000
  if ( self . dont_reply_bit ) : iiii1ii1 |= 0x00002000
  if 67 - 67: OoOoOO00
  Oo0O0oo = struct . pack ( "I" , socket . htonl ( iiii1ii1 ) )
  Oo0O0oo += struct . pack ( "Q" , self . nonce )
  if 67 - 67: I1ii11iIi11i / iII111i + iIii1I11I1II1 % I1IiiI
  if 99 - 99: ooOoO0o . Ii1I
  if 92 - 92: i1IIi
  if 68 - 68: OoO0O00 % IiII - oO0o - ooOoO0o . Oo0Ooo
  if 30 - 30: OoooooooOO % o0oOOo0O0Ooo + ooOoO0o * OoO0O00
  if 57 - 57: I11i + iIii1I11I1II1 . OoO0O00 + oO0o
  iI1ii1i1iIi = False
  II11Iiii1i1II = self . privkey_filename
  if ( II11Iiii1i1II != None and os . path . exists ( II11Iiii1i1II ) ) :
   ii1iIii = open ( II11Iiii1i1II , "r" ) ; i1iI11iI = ii1iIii . read ( ) ; ii1iIii . close ( )
   try :
    i1iI11iI = ecdsa . SigningKey . from_pem ( i1iI11iI )
   except :
    return ( None )
    if 64 - 64: i11iIiiIii + OoOoOO00 + o0oOOo0O0Ooo + OOooOOo
   Iii1iii11 = self . sign_map_request ( i1iI11iI )
   iI1ii1i1iIi = True
  elif ( self . map_request_signature != None ) :
   IIIIi1I = binascii . b2a_base64 ( self . map_request_signature )
   Iii1iii11 = { "source-eid" : self . source_eid . print_address ( ) ,
 "signature-eid" : self . signature_eid . print_address ( ) ,
 "signature" : IIIIi1I }
   Iii1iii11 = json . dumps ( Iii1iii11 )
   iI1ii1i1iIi = True
   if 29 - 29: OoooooooOO / IiII % I11i . OOooOOo + I1Ii111
  if ( iI1ii1i1iIi ) :
   o0oOoOOO = LISP_LCAF_JSON_TYPE
   oO0OOOo0OO = socket . htons ( LISP_AFI_LCAF )
   i1IiI = socket . htons ( len ( Iii1iii11 ) + 2 )
   I1iI1i = socket . htons ( len ( Iii1iii11 ) )
   Oo0O0oo += struct . pack ( "HBBBBHH" , oO0OOOo0OO , 0 , 0 , o0oOoOOO , 0 ,
 i1IiI , I1iI1i )
   Oo0O0oo += Iii1iii11
   Oo0O0oo += struct . pack ( "H" , 0 )
  else :
   if ( self . source_eid . instance_id != 0 ) :
    Oo0O0oo += struct . pack ( "H" , socket . htons ( LISP_AFI_LCAF ) )
    Oo0O0oo += self . source_eid . lcaf_encode_iid ( )
   else :
    Oo0O0oo += struct . pack ( "H" , socket . htons ( self . source_eid . afi ) )
    Oo0O0oo += self . source_eid . pack_address ( )
    if 37 - 37: O0
    if 34 - 34: IiII
    if 5 - 5: OoO0O00 . I1IiiI
    if 48 - 48: Oo0Ooo - OoO0O00 . I11i - iIii1I11I1II1 % Ii1I
    if 47 - 47: iII111i / OoooooooOO - II111iiii
    if 91 - 91: OoOoOO00 + o0oOOo0O0Ooo
    if 23 - 23: i1IIi
  if ( probe_dest ) :
   if ( probe_port == 0 ) : probe_port = LISP_DATA_PORT
   I1IIII1i1 = probe_dest . print_address_no_iid ( ) + ":" + str ( probe_port )
   if 9 - 9: i1IIi % I1Ii111 - OoO0O00 * OoOoOO00 . o0oOOo0O0Ooo
   if ( lisp_crypto_keys_by_rloc_encap . has_key ( I1IIII1i1 ) ) :
    self . keys = lisp_crypto_keys_by_rloc_encap [ I1IIII1i1 ]
    if 18 - 18: Ii1I . OoOoOO00 + iII111i . I1IiiI + OoooooooOO . OoO0O00
    if 31 - 31: I1Ii111 - I11i
    if 49 - 49: iIii1I11I1II1 - iIii1I11I1II1 - OoOoOO00 + IiII / OoOoOO00
    if 74 - 74: OoooooooOO + I1ii11iIi11i % O0
    if 32 - 32: I1ii11iIi11i + I1ii11iIi11i
    if 89 - 89: ooOoO0o + oO0o + Ii1I - OOooOOo
    if 12 - 12: OoOoOO00 - o0oOOo0O0Ooo - I1Ii111 / I11i
  for oo0Oo0oo in self . itr_rlocs :
   if ( lisp_data_plane_security and self . itr_rlocs . index ( oo0Oo0oo ) == 0 ) :
    if ( self . keys == None or self . keys [ 1 ] == None ) :
     Ii111I11 = lisp_keys ( 1 )
     self . keys = [ None , Ii111I11 , None , None ]
     if 17 - 17: OoO0O00 - I1Ii111 - II111iiii / I1Ii111 / Ii1I
    Ii111I11 = self . keys [ 1 ]
    Ii111I11 . add_key_by_nonce ( self . nonce )
    Oo0O0oo += Ii111I11 . encode_lcaf ( oo0Oo0oo )
   else :
    Oo0O0oo += struct . pack ( "H" , socket . htons ( oo0Oo0oo . afi ) )
    Oo0O0oo += oo0Oo0oo . pack_address ( )
    if 30 - 30: OOooOOo * I1ii11iIi11i % I1ii11iIi11i + iII111i * IiII
    if 33 - 33: o0oOOo0O0Ooo + I11i * O0 * OoO0O00 . I1ii11iIi11i
    if 74 - 74: iII111i * iII111i * o0oOOo0O0Ooo / oO0o
  ooI1111 = 0 if self . target_eid . is_binary ( ) == False else self . target_eid . mask_len
  if 80 - 80: IiII + o0oOOo0O0Ooo
  if 40 - 40: I11i . i1IIi - Ii1I - iII111i
  i1II = 0
  if ( self . subscribe_bit ) :
   i1II = 0x80
   self . xtr_id_present = True
   if ( self . xtr_id == None ) :
    self . xtr_id = random . randint ( 0 , ( 2 ** 128 ) - 1 )
    if 28 - 28: IiII - Ii1I . IiII - I1ii11iIi11i * iII111i * OoO0O00
    if 58 - 58: IiII . I1ii11iIi11i * i1IIi
    if 79 - 79: iII111i
  OoOo0Oooo0o = "BB"
  Oo0O0oo += struct . pack ( OoOo0Oooo0o , i1II , ooI1111 )
  if 32 - 32: Ii1I % I11i + OOooOOo % OoooooooOO
  if ( self . target_group . is_null ( ) == False ) :
   Oo0O0oo += struct . pack ( "H" , socket . htons ( LISP_AFI_LCAF ) )
   Oo0O0oo += self . target_eid . lcaf_encode_sg ( self . target_group )
  elif ( self . target_eid . instance_id != 0 or
 self . target_eid . is_geo_prefix ( ) ) :
   Oo0O0oo += struct . pack ( "H" , socket . htons ( LISP_AFI_LCAF ) )
   Oo0O0oo += self . target_eid . lcaf_encode_iid ( )
  else :
   Oo0O0oo += struct . pack ( "H" , socket . htons ( self . target_eid . afi ) )
   Oo0O0oo += self . target_eid . pack_address ( )
   if 68 - 68: I11i
   if 13 - 13: i11iIiiIii - ooOoO0o
   if 54 - 54: I1IiiI * I1IiiI - I11i . O0 . iII111i - Ii1I
   if 86 - 86: I1IiiI . II111iiii * i1IIi % I1IiiI . OOooOOo
   if 79 - 79: OoO0O00 + O0 * OOooOOo
  if ( self . subscribe_bit ) : Oo0O0oo = self . encode_xtr_id ( Oo0O0oo )
  return ( Oo0O0oo )
  if 51 - 51: i1IIi - oO0o / oO0o % o0oOOo0O0Ooo
  if 98 - 98: OoO0O00 * ooOoO0o + i1IIi + IiII - i1IIi % OoOoOO00
 def lcaf_decode_json ( self , packet ) :
  OoOo0Oooo0o = "BBBBHH"
  o0OOo0OOoOO0 = struct . calcsize ( OoOo0Oooo0o )
  if ( len ( packet ) < o0OOo0OOoOO0 ) : return ( None )
  if 19 - 19: iIii1I11I1II1 * Oo0Ooo / OOooOOo
  iiII1II1 , iiIIii1Iii1I , o0oOoOOO , OO00 , i1IiI , I1iI1i = struct . unpack ( OoOo0Oooo0o , packet [ : o0OOo0OOoOO0 ] )
  if 41 - 41: ooOoO0o * i11iIiiIii
  if 67 - 67: ooOoO0o . iIii1I11I1II1 . OoO0O00 + I1Ii111
  if ( o0oOoOOO != LISP_LCAF_JSON_TYPE ) : return ( packet )
  if 51 - 51: oO0o
  if 68 - 68: I1ii11iIi11i - Ii1I - I1Ii111
  if 58 - 58: OoOoOO00 . Ii1I / IiII * oO0o
  if 70 - 70: OoooooooOO
  i1IiI = socket . ntohs ( i1IiI )
  I1iI1i = socket . ntohs ( I1iI1i )
  packet = packet [ o0OOo0OOoOO0 : : ]
  if ( len ( packet ) < i1IiI ) : return ( None )
  if ( i1IiI != I1iI1i + 2 ) : return ( None )
  if 51 - 51: oO0o / II111iiii + ooOoO0o / I11i . iII111i
  if 77 - 77: iIii1I11I1II1 * OoOoOO00 + i11iIiiIii * ooOoO0o
  if 81 - 81: Ii1I * iII111i % Ii1I % i11iIiiIii % i1IIi / o0oOOo0O0Ooo
  if 53 - 53: OoOoOO00
  try :
   Iii1iii11 = json . loads ( packet [ 0 : I1iI1i ] )
  except :
   return ( None )
   if 55 - 55: ooOoO0o % i1IIi / OoO0O00
  packet = packet [ I1iI1i : : ]
  if 77 - 77: O0 % oO0o % oO0o
  if 12 - 12: iII111i / ooOoO0o * iIii1I11I1II1 / II111iiii . i11iIiiIii / II111iiii
  if 66 - 66: IiII * oO0o
  if 73 - 73: i11iIiiIii + O0 % O0
  OoOo0Oooo0o = "H"
  o0OOo0OOoOO0 = struct . calcsize ( OoOo0Oooo0o )
  I1I1i = struct . unpack ( OoOo0Oooo0o , packet [ : o0OOo0OOoOO0 ] ) [ 0 ]
  packet = packet [ o0OOo0OOoOO0 : : ]
  if ( I1I1i != 0 ) : return ( packet )
  if 70 - 70: II111iiii * OoooooooOO - Ii1I + oO0o * O0
  if 49 - 49: oO0o . Ii1I . OoOoOO00 - I1ii11iIi11i
  if 74 - 74: ooOoO0o % I1ii11iIi11i * i1IIi
  if 18 - 18: OoOoOO00
  if ( Iii1iii11 . has_key ( "source-eid" ) == False ) : return ( packet )
  ii1Ii = Iii1iii11 [ "source-eid" ]
  I1I1i = LISP_AFI_IPV4 if ii1Ii . count ( "." ) == 3 else LISP_AFI_IPV6 if ii1Ii . count ( ":" ) == 7 else None
  if 42 - 42: iII111i
  if ( I1I1i == None ) :
   lprint ( "Bad JSON 'source-eid' value: {}" . format ( ii1Ii ) )
   return ( None )
   if 6 - 6: OoO0O00 + OOooOOo
   if 22 - 22: Oo0Ooo . OoooooooOO % I1Ii111
  self . source_eid . afi = I1I1i
  self . source_eid . store_address ( ii1Ii )
  if 16 - 16: I1ii11iIi11i
  if ( Iii1iii11 . has_key ( "signature-eid" ) == False ) : return ( packet )
  ii1Ii = Iii1iii11 [ "signature-eid" ]
  if ( ii1Ii . count ( ":" ) != 7 ) :
   lprint ( "Bad JSON 'signature-eid' value: {}" . format ( ii1Ii ) )
   return ( None )
   if 78 - 78: OoO0O00 * iIii1I11I1II1
   if 58 - 58: I1ii11iIi11i * i11iIiiIii
  self . signature_eid . afi = LISP_AFI_IPV6
  self . signature_eid . store_address ( ii1Ii )
  if 47 - 47: O0 . I1IiiI / ooOoO0o % i11iIiiIii
  if ( Iii1iii11 . has_key ( "signature" ) == False ) : return ( packet )
  IIIIi1I = binascii . a2b_base64 ( Iii1iii11 [ "signature" ] )
  self . map_request_signature = IIIIi1I
  return ( packet )
  if 47 - 47: Ii1I . OoOoOO00 . iIii1I11I1II1 . o0oOOo0O0Ooo
  if 39 - 39: o0oOOo0O0Ooo
 def decode ( self , packet , source , port ) :
  OoOo0Oooo0o = "I"
  o0OOo0OOoOO0 = struct . calcsize ( OoOo0Oooo0o )
  if ( len ( packet ) < o0OOo0OOoOO0 ) : return ( None )
  if 89 - 89: OoooooooOO + iII111i . I1Ii111 / Ii1I
  iiii1ii1 = struct . unpack ( OoOo0Oooo0o , packet [ : o0OOo0OOoOO0 ] )
  iiii1ii1 = iiii1ii1 [ 0 ]
  packet = packet [ o0OOo0OOoOO0 : : ]
  if 75 - 75: iIii1I11I1II1 * iII111i / OoOoOO00 * II111iiii . i1IIi
  OoOo0Oooo0o = "Q"
  o0OOo0OOoOO0 = struct . calcsize ( OoOo0Oooo0o )
  if ( len ( packet ) < o0OOo0OOoOO0 ) : return ( None )
  if 6 - 6: Ii1I % Ii1I / OoooooooOO * oO0o . I1IiiI . i1IIi
  Iii1i11 = struct . unpack ( OoOo0Oooo0o , packet [ : o0OOo0OOoOO0 ] )
  packet = packet [ o0OOo0OOoOO0 : : ]
  if 59 - 59: I11i . I11i * I1IiiI - Ii1I % OoOoOO00
  iiii1ii1 = socket . ntohl ( iiii1ii1 )
  self . auth_bit = True if ( iiii1ii1 & 0x08000000 ) else False
  self . map_data_present = True if ( iiii1ii1 & 0x04000000 ) else False
  self . rloc_probe = True if ( iiii1ii1 & 0x02000000 ) else False
  self . smr_bit = True if ( iiii1ii1 & 0x01000000 ) else False
  self . pitr_bit = True if ( iiii1ii1 & 0x00800000 ) else False
  self . smr_invoked_bit = True if ( iiii1ii1 & 0x00400000 ) else False
  self . mobile_node = True if ( iiii1ii1 & 0x00200000 ) else False
  self . xtr_id_present = True if ( iiii1ii1 & 0x00100000 ) else False
  self . local_xtr = True if ( iiii1ii1 & 0x00004000 ) else False
  self . dont_reply_bit = True if ( iiii1ii1 & 0x00002000 ) else False
  self . itr_rloc_count = ( ( iiii1ii1 >> 8 ) & 0x1f ) + 1
  self . record_count = iiii1ii1 & 0xff
  self . nonce = Iii1i11 [ 0 ]
  if 19 - 19: OoooooooOO / Oo0Ooo - I1Ii111 . OoOoOO00
  if 8 - 8: I11i % ooOoO0o . iIii1I11I1II1
  if 95 - 95: o0oOOo0O0Ooo + i11iIiiIii . I1ii11iIi11i . ooOoO0o . o0oOOo0O0Ooo
  if 93 - 93: iII111i
  if ( self . xtr_id_present ) :
   if ( self . decode_xtr_id ( packet ) == False ) : return ( None )
   if 55 - 55: II111iiii % o0oOOo0O0Ooo - OoO0O00
   if 48 - 48: ooOoO0o * iIii1I11I1II1 % OoOoOO00
  o0OOo0OOoOO0 = struct . calcsize ( "H" )
  if ( len ( packet ) < o0OOo0OOoOO0 ) : return ( None )
  if 100 - 100: II111iiii - i11iIiiIii + OoO0O00 % ooOoO0o - iIii1I11I1II1 * i11iIiiIii
  I1I1i = struct . unpack ( "H" , packet [ : o0OOo0OOoOO0 ] )
  self . source_eid . afi = socket . ntohs ( I1I1i [ 0 ] )
  packet = packet [ o0OOo0OOoOO0 : : ]
  if 30 - 30: OoO0O00 . OoO0O00 . Ii1I % Ii1I * i1IIi * oO0o
  if ( self . source_eid . afi == LISP_AFI_LCAF ) :
   oooO = packet
   packet = self . source_eid . lcaf_decode_iid ( packet )
   if ( packet == None ) :
    packet = self . lcaf_decode_json ( oooO )
    if ( packet == None ) : return ( None )
    if 51 - 51: i11iIiiIii * OoooooooOO
  elif ( self . source_eid . afi != LISP_AFI_NONE ) :
   packet = self . source_eid . unpack_address ( packet )
   if ( packet == None ) : return ( None )
   if 23 - 23: II111iiii + I11i / O0 . I11i . I1Ii111 + iIii1I11I1II1
  self . source_eid . mask_len = self . source_eid . host_mask_len ( )
  if 2 - 2: i1IIi . O0 / o0oOOo0O0Ooo . II111iiii / OoO0O00 % i1IIi
  iI11ii1i = ( os . getenv ( "LISP_NO_CRYPTO" ) != None )
  self . itr_rlocs = [ ]
  while ( self . itr_rloc_count != 0 ) :
   o0OOo0OOoOO0 = struct . calcsize ( "H" )
   if ( len ( packet ) < o0OOo0OOoOO0 ) : return ( None )
   if 96 - 96: Ii1I + iII111i - OoOoOO00 . I11i * o0oOOo0O0Ooo - Ii1I
   I1I1i = struct . unpack ( "H" , packet [ : o0OOo0OOoOO0 ] ) [ 0 ]
   if 73 - 73: Oo0Ooo - I11i - ooOoO0o / I1Ii111 * IiII
   oo0Oo0oo = lisp_address ( LISP_AFI_NONE , "" , 32 , 0 )
   oo0Oo0oo . afi = socket . ntohs ( I1I1i )
   if 55 - 55: i1IIi / I1Ii111 . iII111i
   if 98 - 98: i1IIi % O0 . ooOoO0o * O0
   if 10 - 10: OOooOOo / Oo0Ooo - o0oOOo0O0Ooo / ooOoO0o % ooOoO0o / OoooooooOO
   if 26 - 26: Oo0Ooo . i1IIi / i11iIiiIii + I1Ii111 / II111iiii - I1ii11iIi11i
   if 71 - 71: iIii1I11I1II1 + O0 . IiII . iII111i % o0oOOo0O0Ooo % O0
   if ( oo0Oo0oo . afi != LISP_AFI_LCAF ) :
    if ( len ( packet ) < oo0Oo0oo . addr_length ( ) ) : return ( None )
    packet = oo0Oo0oo . unpack_address ( packet [ o0OOo0OOoOO0 : : ] )
    if ( packet == None ) : return ( None )
    if 51 - 51: o0oOOo0O0Ooo - Ii1I - iIii1I11I1II1 * iIii1I11I1II1 * o0oOOo0O0Ooo - O0
    if ( iI11ii1i ) :
     self . itr_rlocs . append ( oo0Oo0oo )
     self . itr_rloc_count -= 1
     continue
     if 27 - 27: i1IIi . I1Ii111
     if 64 - 64: ooOoO0o / i1IIi
    I1IIII1i1 = lisp_build_crypto_decap_lookup_key ( oo0Oo0oo , port )
    if 100 - 100: II111iiii
    if 16 - 16: Ii1I
    if 96 - 96: o0oOOo0O0Ooo / I1Ii111 % Ii1I - ooOoO0o
    if 35 - 35: OOooOOo
    if 90 - 90: i11iIiiIii
    if ( lisp_nat_traversal and oo0Oo0oo . is_private_address ( ) and source ) : oo0Oo0oo = source
    if 47 - 47: OoO0O00 . i11iIiiIii
    IIi11i1i = lisp_crypto_keys_by_rloc_decap
    if ( IIi11i1i . has_key ( I1IIII1i1 ) ) : IIi11i1i . pop ( I1IIII1i1 )
    if 74 - 74: Oo0Ooo + OOooOOo . o0oOOo0O0Ooo / OoOoOO00 + Ii1I + i1IIi
    if 82 - 82: Ii1I * I11i / I1IiiI * iIii1I11I1II1 / ooOoO0o + IiII
    if 30 - 30: oO0o . i11iIiiIii / I11i + i1IIi - I11i
    if 50 - 50: i1IIi
    if 56 - 56: OoO0O00 + I1Ii111 / Ii1I
    if 75 - 75: OoOoOO00
    lisp_write_ipc_decap_key ( I1IIII1i1 , None )
   else :
    oOoo0O000 = packet
    oO00OO0Ooo00O = lisp_keys ( 1 )
    packet = oO00OO0Ooo00O . decode_lcaf ( oOoo0O000 , 0 )
    if ( packet == None ) : return ( None )
    if 45 - 45: OoO0O00 * II111iiii * OoOoOO00 - OOooOOo % oO0o - Oo0Ooo
    if 4 - 4: o0oOOo0O0Ooo . OoOoOO00 - iIii1I11I1II1 / IiII / I1IiiI % I1IiiI
    if 42 - 42: OoooooooOO + O0 . OoO0O00 % I11i / Oo0Ooo
    if 36 - 36: ooOoO0o / II111iiii - iII111i / Ii1I
    O0Oo = [ LISP_CS_25519_CBC , LISP_CS_25519_GCM ,
 LISP_CS_25519_CHACHA ]
    if ( oO00OO0Ooo00O . cipher_suite in O0Oo ) :
     if ( oO00OO0Ooo00O . cipher_suite == LISP_CS_25519_CBC or
 oO00OO0Ooo00O . cipher_suite == LISP_CS_25519_GCM ) :
      i1iI11iI = lisp_keys ( 1 , do_poly = False , do_chacha = False )
      if 11 - 11: OoooooooOO + o0oOOo0O0Ooo - i11iIiiIii + i1IIi % i1IIi
     if ( oO00OO0Ooo00O . cipher_suite == LISP_CS_25519_CHACHA ) :
      i1iI11iI = lisp_keys ( 1 , do_poly = True , do_chacha = True )
      if 68 - 68: IiII - I11i % II111iiii - o0oOOo0O0Ooo % ooOoO0o
    else :
     i1iI11iI = lisp_keys ( 1 , do_poly = False , do_curve = False ,
 do_chacha = False )
     if 41 - 41: iII111i . ooOoO0o % OoooooooOO / I1IiiI * II111iiii - iII111i
    packet = i1iI11iI . decode_lcaf ( oOoo0O000 , 0 )
    if ( packet == None ) : return ( None )
    if 19 - 19: OoO0O00 . I11i / i11iIiiIii - OoOoOO00 * I11i . IiII
    if ( len ( packet ) < o0OOo0OOoOO0 ) : return ( None )
    I1I1i = struct . unpack ( "H" , packet [ : o0OOo0OOoOO0 ] ) [ 0 ]
    oo0Oo0oo . afi = socket . ntohs ( I1I1i )
    if ( len ( packet ) < oo0Oo0oo . addr_length ( ) ) : return ( None )
    if 39 - 39: O0 / iIii1I11I1II1 % iII111i + I1Ii111 - O0 . II111iiii
    packet = oo0Oo0oo . unpack_address ( packet [ o0OOo0OOoOO0 : : ] )
    if ( packet == None ) : return ( None )
    if 94 - 94: OoOoOO00 * iIii1I11I1II1
    if ( iI11ii1i ) :
     self . itr_rlocs . append ( oo0Oo0oo )
     self . itr_rloc_count -= 1
     continue
     if 11 - 11: I1ii11iIi11i % OOooOOo + Ii1I + oO0o . Oo0Ooo
     if 93 - 93: OOooOOo * Ii1I - o0oOOo0O0Ooo . oO0o . iII111i
    I1IIII1i1 = lisp_build_crypto_decap_lookup_key ( oo0Oo0oo , port )
    if 64 - 64: Oo0Ooo / iIii1I11I1II1 . OoO0O00 / o0oOOo0O0Ooo / I11i
    I11IiiI1 = None
    if ( lisp_nat_traversal and oo0Oo0oo . is_private_address ( ) and source ) : oo0Oo0oo = source
    if 72 - 72: iIii1I11I1II1 * OOooOOo . iIii1I11I1II1
    if 62 - 62: IiII . IiII % ooOoO0o - OoOoOO00 / OoooooooOO . I1IiiI
    if ( lisp_crypto_keys_by_rloc_decap . has_key ( I1IIII1i1 ) ) :
     Ii111I11 = lisp_crypto_keys_by_rloc_decap [ I1IIII1i1 ]
     I11IiiI1 = Ii111I11 [ 1 ] if Ii111I11 and Ii111I11 [ 1 ] else None
     if 23 - 23: IiII + i11iIiiIii * Ii1I
     if 55 - 55: Oo0Ooo % IiII + i11iIiiIii - OOooOOo - II111iiii
    o0o0Oo0O0O0o = True
    if ( I11IiiI1 ) :
     if ( I11IiiI1 . compare_keys ( i1iI11iI ) ) :
      self . keys = [ None , I11IiiI1 , None , None ]
      lprint ( "Maintain stored decap-keys for RLOC {}" . format ( red ( I1IIII1i1 , False ) ) )
      if 67 - 67: iII111i
     else :
      o0o0Oo0O0O0o = False
      o0o00O0 = bold ( "Remote decap-rekeying" , False )
      lprint ( "{} for RLOC {}" . format ( o0o00O0 , red ( I1IIII1i1 ,
 False ) ) )
      i1iI11iI . copy_keypair ( I11IiiI1 )
      i1iI11iI . uptime = I11IiiI1 . uptime
      I11IiiI1 = None
      if 88 - 88: I1IiiI
      if 74 - 74: iII111i * i11iIiiIii + i1IIi * ooOoO0o + oO0o * Ii1I
      if 90 - 90: iII111i
    if ( I11IiiI1 == None ) :
     self . keys = [ None , i1iI11iI , None , None ]
     if ( lisp_i_am_etr == False and lisp_i_am_rtr == False ) :
      i1iI11iI . local_public_key = None
      lprint ( "{} for {}" . format ( bold ( "Ignoring decap-keys" ,
 False ) , red ( I1IIII1i1 , False ) ) )
     elif ( i1iI11iI . remote_public_key != None ) :
      if ( o0o0Oo0O0O0o ) :
       lprint ( "{} for RLOC {}" . format ( bold ( "New decap-keying" , False ) ,
       # oO0o % I1ii11iIi11i * IiII / i1IIi - i11iIiiIii
 red ( I1IIII1i1 , False ) ) )
       if 92 - 92: iII111i - I1IiiI % iIii1I11I1II1 / O0 + OoOoOO00
      i1iI11iI . compute_shared_key ( "decap" )
      i1iI11iI . add_key_by_rloc ( I1IIII1i1 , False )
      if 37 - 37: Oo0Ooo - I11i / OOooOOo / IiII * i1IIi
      if 55 - 55: I1IiiI
      if 83 - 83: OoOoOO00 / ooOoO0o / iII111i + OoO0O00 - I1IiiI * i1IIi
      if 34 - 34: iIii1I11I1II1 * O0 - OoOoOO00 + iIii1I11I1II1 % I1ii11iIi11i
   self . itr_rlocs . append ( oo0Oo0oo )
   self . itr_rloc_count -= 1
   if 77 - 77: Oo0Ooo . IiII . oO0o
   if 77 - 77: i1IIi + OoooooooOO + OoO0O00 % ooOoO0o % Ii1I
  o0OOo0OOoOO0 = struct . calcsize ( "BBH" )
  if ( len ( packet ) < o0OOo0OOoOO0 ) : return ( None )
  if 43 - 43: Oo0Ooo . i11iIiiIii + i1IIi
  i1II , ooI1111 , I1I1i = struct . unpack ( "BBH" , packet [ : o0OOo0OOoOO0 ] )
  self . subscribe_bit = ( i1II & 0x80 )
  self . target_eid . afi = socket . ntohs ( I1I1i )
  packet = packet [ o0OOo0OOoOO0 : : ]
  if 83 - 83: iII111i + OoOoOO00 % ooOoO0o
  self . target_eid . mask_len = ooI1111
  if ( self . target_eid . afi == LISP_AFI_LCAF ) :
   packet , ooOooooO00 = self . target_eid . lcaf_decode_eid ( packet )
   if ( packet == None ) : return ( None )
   if ( ooOooooO00 ) : self . target_group = ooOooooO00
  else :
   packet = self . target_eid . unpack_address ( packet )
   if ( packet == None ) : return ( None )
   packet = packet [ o0OOo0OOoOO0 : : ]
   if 51 - 51: OoooooooOO + i11iIiiIii
  return ( packet )
  if 57 - 57: Oo0Ooo % o0oOOo0O0Ooo
  if 99 - 99: o0oOOo0O0Ooo / i11iIiiIii / II111iiii + OOooOOo . i1IIi + OoOoOO00
 def print_eid_tuple ( self ) :
  return ( lisp_print_eid_tuple ( self . target_eid , self . target_group ) )
  if 7 - 7: I1IiiI / ooOoO0o % OoO0O00 + oO0o . o0oOOo0O0Ooo / I11i
  if 84 - 84: OOooOOo + II111iiii . o0oOOo0O0Ooo * Oo0Ooo
 def encode_xtr_id ( self , packet ) :
  I1iIiI1iiI = self . xtr_id >> 64
  oO000O00 = self . xtr_id & 0xffffffffffffffff
  I1iIiI1iiI = byte_swap_64 ( I1iIiI1iiI )
  oO000O00 = byte_swap_64 ( oO000O00 )
  packet += struct . pack ( "QQ" , I1iIiI1iiI , oO000O00 )
  return ( packet )
  if 68 - 68: Ii1I % Ii1I
  if 26 - 26: o0oOOo0O0Ooo . Ii1I * OoOoOO00
 def decode_xtr_id ( self , packet ) :
  o0OOo0OOoOO0 = struct . calcsize ( "QQ" )
  if ( len ( packet ) < o0OOo0OOoOO0 ) : return ( None )
  packet = packet [ len ( packet ) - o0OOo0OOoOO0 : : ]
  I1iIiI1iiI , oO000O00 = struct . unpack ( "QQ" , packet [ : o0OOo0OOoOO0 ] )
  I1iIiI1iiI = byte_swap_64 ( I1iIiI1iiI )
  oO000O00 = byte_swap_64 ( oO000O00 )
  self . xtr_id = ( I1iIiI1iiI << 64 ) | oO000O00
  return ( True )
  if 58 - 58: I1IiiI * OoO0O00 * i11iIiiIii / OOooOOo / I1IiiI
  if 46 - 46: IiII - I1IiiI + OoO0O00 / I11i . i11iIiiIii
  if 84 - 84: OoooooooOO . OoO0O00 / OoOoOO00 * i1IIi
  if 6 - 6: iIii1I11I1II1 * iIii1I11I1II1
  if 77 - 77: OOooOOo % oO0o + iIii1I11I1II1 * Ii1I . IiII . Oo0Ooo
  if 29 - 29: I1ii11iIi11i + OoooooooOO . OoO0O00 . i1IIi - OoooooooOO * i11iIiiIii
  if 19 - 19: I1ii11iIi11i * O0 - ooOoO0o
  if 27 - 27: iII111i / o0oOOo0O0Ooo . OoOoOO00 * Ii1I * I1Ii111
  if 81 - 81: I1Ii111
  if 45 - 45: OOooOOo * II111iiii * OoooooooOO / OoooooooOO * I1Ii111
  if 38 - 38: iII111i . OoooooooOO
  if 28 - 28: I1Ii111 * i1IIi . I1ii11iIi11i
  if 75 - 75: O0 / oO0o * ooOoO0o - OOooOOo / i1IIi
  if 61 - 61: I11i
  if 100 - 100: O0 - iIii1I11I1II1 * Oo0Ooo
  if 35 - 35: ooOoO0o
  if 57 - 57: OoO0O00 . Oo0Ooo + I1IiiI
  if 18 - 18: I1IiiI - I1ii11iIi11i * I11i / i11iIiiIii - o0oOOo0O0Ooo % o0oOOo0O0Ooo
  if 31 - 31: I11i
  if 100 - 100: i11iIiiIii * i11iIiiIii . iIii1I11I1II1 % iII111i * I1ii11iIi11i
  if 17 - 17: Ii1I * IiII * i11iIiiIii / I1ii11iIi11i / i11iIiiIii
  if 23 - 23: OoooooooOO + i11iIiiIii / Oo0Ooo / iII111i . iII111i * I1IiiI
  if 98 - 98: IiII
  if 23 - 23: I11i / i1IIi * OoO0O00
  if 51 - 51: OOooOOo - OoooooooOO / OoooooooOO % OoooooooOO
  if 85 - 85: OoO0O00 . o0oOOo0O0Ooo . I1IiiI
  if 75 - 75: iIii1I11I1II1 - Ii1I % O0 % IiII
  if 6 - 6: Oo0Ooo % oO0o * ooOoO0o - i1IIi . OoOoOO00
  if 20 - 20: Oo0Ooo / I1Ii111 . Oo0Ooo
  if 60 - 60: I1ii11iIi11i - I1IiiI * O0 * Oo0Ooo . i1IIi . OoOoOO00
  if 24 - 24: IiII * I1IiiI / OOooOOo
  if 51 - 51: iIii1I11I1II1 / I11i * OoO0O00 * Ii1I + I1ii11iIi11i . OoooooooOO
class lisp_map_reply ( ) :
 def __init__ ( self ) :
  self . rloc_probe = False
  self . echo_nonce_capable = False
  self . security = False
  self . record_count = 0
  self . hop_count = 0
  self . nonce = 0
  self . keys = None
  if 75 - 75: IiII / OoooooooOO / O0 % OOooOOo
  if 87 - 87: II111iiii / iIii1I11I1II1 % I1ii11iIi11i
 def print_map_reply ( self ) :
  iI1111i = "{} -> flags: {}{}{}, hop-count: {}, record-count: {}, " + "nonce: 0x{}"
  if 11 - 11: o0oOOo0O0Ooo * OoO0O00
  lprint ( iI1111i . format ( bold ( "Map-Reply" , False ) , "R" if self . rloc_probe else "r" ,
  # iIii1I11I1II1 + ooOoO0o + I11i + OoooooooOO * o0oOOo0O0Ooo . I11i
 "E" if self . echo_nonce_capable else "e" ,
 "S" if self . security else "s" , self . hop_count , self . record_count ,
 lisp_hex_string ( self . nonce ) ) )
  if 26 - 26: I1Ii111 / I1ii11iIi11i % ooOoO0o % o0oOOo0O0Ooo / OoOoOO00
  if 44 - 44: OoooooooOO % i1IIi / I1ii11iIi11i / I1ii11iIi11i
 def encode ( self ) :
  iiii1ii1 = ( LISP_MAP_REPLY << 28 ) | self . record_count
  iiii1ii1 |= self . hop_count << 8
  if ( self . rloc_probe ) : iiii1ii1 |= 0x08000000
  if ( self . echo_nonce_capable ) : iiii1ii1 |= 0x04000000
  if ( self . security ) : iiii1ii1 |= 0x02000000
  if 36 - 36: O0 - I11i + OOooOOo
  Oo0O0oo = struct . pack ( "I" , socket . htonl ( iiii1ii1 ) )
  Oo0O0oo += struct . pack ( "Q" , self . nonce )
  return ( Oo0O0oo )
  if 97 - 97: I1IiiI * o0oOOo0O0Ooo
  if 79 - 79: iII111i - ooOoO0o - OoO0O00 / iIii1I11I1II1 % Ii1I
 def decode ( self , packet ) :
  OoOo0Oooo0o = "I"
  o0OOo0OOoOO0 = struct . calcsize ( OoOo0Oooo0o )
  if ( len ( packet ) < o0OOo0OOoOO0 ) : return ( None )
  if 2 - 2: iIii1I11I1II1 + OoooooooOO - i1IIi / Ii1I
  iiii1ii1 = struct . unpack ( OoOo0Oooo0o , packet [ : o0OOo0OOoOO0 ] )
  iiii1ii1 = iiii1ii1 [ 0 ]
  packet = packet [ o0OOo0OOoOO0 : : ]
  if 88 - 88: I1ii11iIi11i . OoooooooOO / Oo0Ooo / o0oOOo0O0Ooo % Oo0Ooo
  OoOo0Oooo0o = "Q"
  o0OOo0OOoOO0 = struct . calcsize ( OoOo0Oooo0o )
  if ( len ( packet ) < o0OOo0OOoOO0 ) : return ( None )
  if 80 - 80: Ii1I + OoO0O00 * OoooooooOO - IiII % O0 - I1Ii111
  Iii1i11 = struct . unpack ( OoOo0Oooo0o , packet [ : o0OOo0OOoOO0 ] )
  packet = packet [ o0OOo0OOoOO0 : : ]
  if 80 - 80: II111iiii / I1ii11iIi11i
  iiii1ii1 = socket . ntohl ( iiii1ii1 )
  self . rloc_probe = True if ( iiii1ii1 & 0x08000000 ) else False
  self . echo_nonce_capable = True if ( iiii1ii1 & 0x04000000 ) else False
  self . security = True if ( iiii1ii1 & 0x02000000 ) else False
  self . hop_count = ( iiii1ii1 >> 8 ) & 0xff
  self . record_count = iiii1ii1 & 0xff
  self . nonce = Iii1i11 [ 0 ]
  if 60 - 60: OOooOOo - iII111i + iIii1I11I1II1 + II111iiii + iII111i
  if ( lisp_crypto_keys_by_nonce . has_key ( self . nonce ) ) :
   self . keys = lisp_crypto_keys_by_nonce [ self . nonce ]
   self . keys [ 1 ] . delete_key_by_nonce ( self . nonce )
   if 35 - 35: Oo0Ooo * O0 / oO0o * i1IIi . I11i . O0
  return ( packet )
  if 22 - 22: oO0o / II111iiii . OoOoOO00
  if 9 - 9: i11iIiiIii + ooOoO0o . iIii1I11I1II1 * OoOoOO00
  if 4 - 4: I1Ii111 + iII111i % O0
  if 98 - 98: i1IIi + I1Ii111 - I1ii11iIi11i . OoooooooOO / O0 / iII111i
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
  if 34 - 34: IiII + I1Ii111 + Oo0Ooo / II111iiii
  if 33 - 33: Ii1I . i1IIi - II111iiii - OoO0O00
  if 31 - 31: I11i - OoOoOO00 / o0oOOo0O0Ooo * OoOoOO00 / Oo0Ooo + o0oOOo0O0Ooo
  if 46 - 46: IiII * OoO0O00 / OOooOOo + Oo0Ooo
  if 24 - 24: ooOoO0o % OOooOOo . O0 * Oo0Ooo
  if 52 - 52: O0 . I1Ii111 + iII111i / i11iIiiIii
  if 52 - 52: oO0o % Oo0Ooo * II111iiii
  if 24 - 24: i11iIiiIii * i1IIi * i1IIi
  if 27 - 27: i1IIi - oO0o + OOooOOo
  if 3 - 3: IiII % I1Ii111 . OoooooooOO
  if 19 - 19: I1Ii111 * Ii1I - oO0o
  if 78 - 78: OoO0O00 - Ii1I / OOooOOo
  if 81 - 81: OoOoOO00
  if 21 - 21: iII111i / OOooOOo % IiII
  if 51 - 51: I11i + ooOoO0o / I1IiiI
  if 3 - 3: iIii1I11I1II1 / OOooOOo % oO0o . Ii1I - Ii1I
  if 55 - 55: i11iIiiIii % OoooooooOO + O0
  if 7 - 7: ooOoO0o - i11iIiiIii * iII111i / Ii1I - o0oOOo0O0Ooo
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
  if 62 - 62: o0oOOo0O0Ooo - iIii1I11I1II1 . I11i . Ii1I * Ii1I
  if 24 - 24: I11i
 def print_prefix ( self ) :
  if ( self . group . is_null ( ) ) :
   return ( green ( self . eid . print_prefix ( ) , False ) )
   if 93 - 93: I1IiiI % OoO0O00 / i11iIiiIii / I11i
  return ( green ( self . eid . print_sg ( self . group ) , False ) )
  if 60 - 60: ooOoO0o - Ii1I . I1IiiI * oO0o * i11iIiiIii
  if 29 - 29: OoO0O00 - Oo0Ooo . oO0o / OoO0O00 % i11iIiiIii
 def print_ttl ( self ) :
  I1i = self . record_ttl
  if ( self . record_ttl & 0x80000000 ) :
   I1i = str ( self . record_ttl & 0x7fffffff ) + " secs"
  elif ( ( I1i % 60 ) == 0 ) :
   I1i = str ( I1i / 60 ) + " hours"
  else :
   I1i = str ( I1i ) + " mins"
   if 92 - 92: Ii1I / OOooOOo % OOooOOo % O0 % I11i
  return ( I1i )
  if 12 - 12: i11iIiiIii * ooOoO0o - II111iiii
  if 23 - 23: IiII
 def store_ttl ( self ) :
  I1i = self . record_ttl * 60
  if ( self . record_ttl & 0x80000000 ) : I1i = self . record_ttl & 0x7fffffff
  return ( I1i )
  if 53 - 53: I1Ii111 % OOooOOo . Ii1I / OOooOOo * OOooOOo * O0
  if 1 - 1: iIii1I11I1II1 % I1ii11iIi11i . oO0o . IiII . o0oOOo0O0Ooo / o0oOOo0O0Ooo
 def print_record ( self , indent , ddt ) :
  Ooooo0OO000o0 = ""
  oOOIIiiIIIiI = ""
  OOOo = bold ( "invalid-action" , False )
  if ( ddt ) :
   if ( self . action < len ( lisp_map_referral_action_string ) ) :
    OOOo = lisp_map_referral_action_string [ self . action ]
    OOOo = bold ( OOOo , False )
    Ooooo0OO000o0 = ( ", " + bold ( "ddt-incomplete" , False ) ) if self . ddt_incomplete else ""
    if 4 - 4: i11iIiiIii
    oOOIIiiIIIiI = ( ", sig-count: " + str ( self . signature_count ) ) if ( self . signature_count != 0 ) else ""
    if 63 - 63: iII111i - OoO0O00 * OOooOOo
    if 89 - 89: iII111i / Oo0Ooo
  else :
   if ( self . action < len ( lisp_map_reply_action_string ) ) :
    OOOo = lisp_map_reply_action_string [ self . action ]
    if ( self . action != LISP_NO_ACTION ) :
     OOOo = bold ( OOOo , False )
     if 66 - 66: o0oOOo0O0Ooo + OoOoOO00 % OoooooooOO . I11i
     if 30 - 30: II111iiii - Oo0Ooo - i11iIiiIii + O0
     if 93 - 93: i1IIi + I1Ii111 / OoO0O00 - I11i % Oo0Ooo / Ii1I
     if 1 - 1: Oo0Ooo / Ii1I . i11iIiiIii % OOooOOo + o0oOOo0O0Ooo + O0
  I1I1i = LISP_AFI_LCAF if ( self . eid . afi < 0 ) else self . eid . afi
  iI1111i = ( "{}EID-record -> record-ttl: {}, rloc-count: {}, action: " +
 "{}, {}{}{}, map-version: {}, afi: {}, [iid]eid/ml: {}" )
  if 54 - 54: I1Ii111 + ooOoO0o % IiII
  lprint ( iI1111i . format ( indent , self . print_ttl ( ) , self . rloc_count ,
 OOOo , "auth" if ( self . authoritative is True ) else "non-auth" ,
 Ooooo0OO000o0 , oOOIIiiIIIiI , self . map_version , I1I1i ,
 green ( self . print_prefix ( ) , False ) ) )
  if 83 - 83: o0oOOo0O0Ooo * iIii1I11I1II1
  if 36 - 36: OoOoOO00 + II111iiii - OoO0O00 % ooOoO0o * i1IIi
 def encode ( self ) :
  i11IIiI = self . action << 13
  if ( self . authoritative ) : i11IIiI |= 0x1000
  if ( self . ddt_incomplete ) : i11IIiI |= 0x800
  if 57 - 57: IiII * iIii1I11I1II1 * O0
  if 26 - 26: OoooooooOO + oO0o + OoO0O00 . O0
  if 46 - 46: OoooooooOO - Oo0Ooo * I1Ii111 * OOooOOo * I1Ii111 . oO0o
  if 96 - 96: Ii1I / IiII % o0oOOo0O0Ooo + I11i
  I1I1i = self . eid . afi if ( self . eid . instance_id == 0 ) else LISP_AFI_LCAF
  if ( I1I1i < 0 ) : I1I1i = LISP_AFI_LCAF
  iIiiIi1111ii = ( self . group . is_null ( ) == False )
  if ( iIiiIi1111ii ) : I1I1i = LISP_AFI_LCAF
  if 53 - 53: O0 % ooOoO0o
  iii111iI1i11 = ( self . signature_count << 12 ) | self . map_version
  ooI1111 = 0 if self . eid . is_binary ( ) == False else self . eid . mask_len
  if 67 - 67: I11i * i1IIi - i1IIi . OoOoOO00 % oO0o . o0oOOo0O0Ooo
  Oo0O0oo = struct . pack ( "IBBHHH" , socket . htonl ( self . record_ttl ) ,
 self . rloc_count , ooI1111 , socket . htons ( i11IIiI ) ,
 socket . htons ( iii111iI1i11 ) , socket . htons ( I1I1i ) )
  if 14 - 14: oO0o - Oo0Ooo % Ii1I . I1Ii111
  if 14 - 14: ooOoO0o / O0 - I1IiiI / I1ii11iIi11i / OoO0O00 + oO0o
  if 81 - 81: I1Ii111 / I1Ii111 + ooOoO0o - Ii1I
  if 93 - 93: ooOoO0o . o0oOOo0O0Ooo + O0 * i1IIi - OoO0O00 * OoO0O00
  if ( iIiiIi1111ii ) :
   Oo0O0oo += self . eid . lcaf_encode_sg ( self . group )
   return ( Oo0O0oo )
   if 11 - 11: ooOoO0o - Ii1I . oO0o * Ii1I
   if 85 - 85: i1IIi
   if 94 - 94: OoooooooOO . O0 / OoooooooOO
   if 67 - 67: i11iIiiIii + OoOoOO00
   if 50 - 50: ooOoO0o . i1IIi + I1ii11iIi11i . OOooOOo
  if ( self . eid . afi == LISP_AFI_GEO_COORD and self . eid . instance_id == 0 ) :
   Oo0O0oo = Oo0O0oo [ 0 : - 2 ]
   Oo0O0oo += self . eid . address . encode_geo ( )
   return ( Oo0O0oo )
   if 97 - 97: I1IiiI
   if 63 - 63: O0 - OoOoOO00 / i11iIiiIii / OoooooooOO / ooOoO0o / II111iiii
   if 45 - 45: II111iiii . OoO0O00 + OoO0O00 * iIii1I11I1II1
   if 23 - 23: IiII * OoOoOO00 % Ii1I / Ii1I - ooOoO0o - OOooOOo
   if 86 - 86: OOooOOo . OoooooooOO * I1IiiI - Oo0Ooo / i11iIiiIii * iII111i
  if ( I1I1i == LISP_AFI_LCAF ) :
   Oo0O0oo += self . eid . lcaf_encode_iid ( )
   return ( Oo0O0oo )
   if 56 - 56: I1IiiI . I11i % iII111i
   if 33 - 33: I11i / OOooOOo - OOooOOo / i11iIiiIii * OoOoOO00 + O0
   if 2 - 2: i11iIiiIii % I1IiiI
   if 90 - 90: II111iiii
   if 2 - 2: Ii1I - OoooooooOO - i11iIiiIii % Oo0Ooo / Ii1I
  Oo0O0oo += self . eid . pack_address ( )
  return ( Oo0O0oo )
  if 77 - 77: o0oOOo0O0Ooo . o0oOOo0O0Ooo * I1Ii111 + OOooOOo - i11iIiiIii
  if 45 - 45: I1IiiI . I1IiiI - Oo0Ooo * OOooOOo
 def decode ( self , packet ) :
  OoOo0Oooo0o = "IBBHHH"
  o0OOo0OOoOO0 = struct . calcsize ( OoOo0Oooo0o )
  if ( len ( packet ) < o0OOo0OOoOO0 ) : return ( None )
  if 71 - 71: i1IIi / I11i
  self . record_ttl , self . rloc_count , self . eid . mask_len , i11IIiI , self . map_version , self . eid . afi = struct . unpack ( OoOo0Oooo0o , packet [ : o0OOo0OOoOO0 ] )
  if 14 - 14: OoooooooOO
  if 99 - 99: o0oOOo0O0Ooo * o0oOOo0O0Ooo
  if 6 - 6: i11iIiiIii + oO0o % ooOoO0o + i11iIiiIii - OOooOOo
  self . record_ttl = socket . ntohl ( self . record_ttl )
  i11IIiI = socket . ntohs ( i11IIiI )
  self . action = ( i11IIiI >> 13 ) & 0x7
  self . authoritative = True if ( ( i11IIiI >> 12 ) & 1 ) else False
  self . ddt_incomplete = True if ( ( i11IIiI >> 11 ) & 1 ) else False
  self . map_version = socket . ntohs ( self . map_version )
  self . signature_count = self . map_version >> 12
  self . map_version = self . map_version & 0xfff
  self . eid . afi = socket . ntohs ( self . eid . afi )
  self . eid . instance_id = 0
  packet = packet [ o0OOo0OOoOO0 : : ]
  if 12 - 12: iII111i . oO0o % IiII * OoooooooOO . IiII
  if 15 - 15: I1IiiI . I1IiiI / i11iIiiIii
  if 17 - 17: iIii1I11I1II1 / OoO0O00 - II111iiii
  if 46 - 46: iIii1I11I1II1 * oO0o / i11iIiiIii + II111iiii + I11i
  if ( self . eid . afi == LISP_AFI_LCAF ) :
   packet , IiI1111i1i11I = self . eid . lcaf_decode_eid ( packet )
   if ( IiI1111i1i11I ) : self . group = IiI1111i1i11I
   self . group . instance_id = self . eid . instance_id
   return ( packet )
   if 73 - 73: Ii1I + ooOoO0o % OoO0O00 . i1IIi
   if 71 - 71: Oo0Ooo * iIii1I11I1II1 * I11i + I1IiiI
  packet = self . eid . unpack_address ( packet )
  return ( packet )
  if 13 - 13: OoO0O00 - Oo0Ooo / OoO0O00
  if 34 - 34: i11iIiiIii + OoO0O00 + i11iIiiIii . IiII % O0
 def print_eid_tuple ( self ) :
  return ( lisp_print_eid_tuple ( self . eid , self . group ) )
  if 64 - 64: o0oOOo0O0Ooo . iIii1I11I1II1
  if 86 - 86: ooOoO0o - I11i . iIii1I11I1II1 - iIii1I11I1II1
  if 61 - 61: Ii1I % Oo0Ooo + OoOoOO00
  if 60 - 60: oO0o . OoooooooOO
  if 40 - 40: I11i
  if 44 - 44: ooOoO0o
  if 35 - 35: II111iiii + iII111i / I1ii11iIi11i * I1IiiI . I11i
  if 97 - 97: I1IiiI / o0oOOo0O0Ooo
  if 13 - 13: I1ii11iIi11i
  if 72 - 72: Oo0Ooo + IiII / Ii1I * Oo0Ooo
  if 41 - 41: OOooOOo - OoOoOO00 . I1IiiI + i11iIiiIii + OoO0O00 * iII111i
  if 85 - 85: OoO0O00 + II111iiii
  if 87 - 87: OoO0O00
  if 93 - 93: OoooooooOO
  if 80 - 80: o0oOOo0O0Ooo
  if 3 - 3: i11iIiiIii / OOooOOo + oO0o
  if 10 - 10: OoO0O00 . OoO0O00 + O0
  if 13 - 13: i1IIi . I1IiiI
  if 45 - 45: ooOoO0o % I11i
  if 37 - 37: iII111i
  if 70 - 70: O0 + iIii1I11I1II1 % O0 * o0oOOo0O0Ooo - Oo0Ooo - ooOoO0o
  if 94 - 94: i1IIi + IiII / OoooooooOO - oO0o / OOooOOo / OoOoOO00
  if 55 - 55: OOooOOo
  if 5 - 5: I11i / OoOoOO00
  if 48 - 48: i1IIi - oO0o . OoooooooOO - OoO0O00 - i1IIi
  if 19 - 19: oO0o % Ii1I + I1ii11iIi11i . II111iiii * i11iIiiIii
  if 87 - 87: Ii1I / I1Ii111 % OoOoOO00 * I1ii11iIi11i - OoooooooOO / OoOoOO00
  if 24 - 24: I11i . OOooOOo * i1IIi . I1ii11iIi11i / ooOoO0o / O0
  if 62 - 62: o0oOOo0O0Ooo % II111iiii
  if 22 - 22: oO0o - o0oOOo0O0Ooo
  if 89 - 89: OOooOOo
LISP_UDP_PROTOCOL = 17
LISP_DEFAULT_ECM_TTL = 128
if 34 - 34: iII111i . OOooOOo
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
  if 13 - 13: OoO0O00 * OOooOOo + oO0o
  if 21 - 21: i11iIiiIii . Ii1I % i1IIi * Ii1I . oO0o + Ii1I
 def print_ecm ( self ) :
  iI1111i = ( "{} -> flags: {}{}{}{}, " + "inner IP: {} -> {}, inner UDP: {} -> {}" )
  if 92 - 92: i1IIi + OoO0O00 * I11i
  lprint ( iI1111i . format ( bold ( "ECM" , False ) , "S" if self . security else "s" ,
 "D" if self . ddt else "d" , "E" if self . to_etr else "e" ,
 "M" if self . to_ms else "m" ,
 green ( self . source . print_address ( ) , False ) ,
 green ( self . dest . print_address ( ) , False ) , self . udp_sport ,
 self . udp_dport ) )
  if 70 - 70: Oo0Ooo
 def encode ( self , packet , inner_source , inner_dest ) :
  self . udp_length = len ( packet ) + 8
  self . source = inner_source
  self . dest = inner_dest
  if ( inner_dest . is_ipv4 ( ) ) :
   self . afi = LISP_AFI_IPV4
   self . length = self . udp_length + 20
   if 93 - 93: iII111i . I1ii11iIi11i . Oo0Ooo . oO0o . OoooooooOO
  if ( inner_dest . is_ipv6 ( ) ) :
   self . afi = LISP_AFI_IPV6
   self . length = self . udp_length
   if 51 - 51: O0 - iII111i
   if 65 - 65: O0 / II111iiii * IiII % Ii1I + o0oOOo0O0Ooo
   if 43 - 43: I1Ii111 + OoO0O00 * OoooooooOO
   if 85 - 85: iII111i + OOooOOo
   if 36 - 36: OoO0O00 % II111iiii * O0 + II111iiii - oO0o - i1IIi
   if 53 - 53: Ii1I - OOooOOo
  iiii1ii1 = ( LISP_ECM << 28 )
  if ( self . security ) : iiii1ii1 |= 0x08000000
  if ( self . ddt ) : iiii1ii1 |= 0x04000000
  if ( self . to_etr ) : iiii1ii1 |= 0x02000000
  if ( self . to_ms ) : iiii1ii1 |= 0x01000000
  if 75 - 75: iII111i % O0 - I11i - I1ii11iIi11i + I1IiiI - I1IiiI
  Oo00OoooO0o = struct . pack ( "I" , socket . htonl ( iiii1ii1 ) )
  if 11 - 11: I1Ii111 - OOooOOo - I1Ii111 - II111iiii / I1Ii111
  i1iiii = ""
  if ( self . afi == LISP_AFI_IPV4 ) :
   i1iiii = struct . pack ( "BBHHHBBH" , 0x45 , 0 , socket . htons ( self . length ) ,
 0 , 0 , self . ttl , self . protocol , socket . htons ( self . ip_checksum ) )
   i1iiii += self . source . pack_address ( )
   i1iiii += self . dest . pack_address ( )
   i1iiii = lisp_ip_checksum ( i1iiii )
   if 23 - 23: OOooOOo
  if ( self . afi == LISP_AFI_IPV6 ) :
   i1iiii = struct . pack ( "BBHHBB" , 0x60 , 0 , 0 , socket . htons ( self . length ) ,
 self . protocol , self . ttl )
   i1iiii += self . source . pack_address ( )
   i1iiii += self . dest . pack_address ( )
   if 19 - 19: ooOoO0o % iIii1I11I1II1 * OoooooooOO
   if 60 - 60: I1Ii111 * iII111i / OoooooooOO * Oo0Ooo
  IiiiI1 = socket . htons ( self . udp_sport )
  oOOoO0O = socket . htons ( self . udp_dport )
  i1IIi111iI = socket . htons ( self . udp_length )
  oOoooO0oo0 = socket . htons ( self . udp_checksum )
  i1iIIII1iiIIi = struct . pack ( "HHHH" , IiiiI1 , oOOoO0O , i1IIi111iI , oOoooO0oo0 )
  return ( Oo00OoooO0o + i1iiii + i1iIIII1iiIIi )
  if 47 - 47: iII111i + o0oOOo0O0Ooo % iIii1I11I1II1 * OoOoOO00
  if 65 - 65: OOooOOo . II111iiii * i11iIiiIii + OOooOOo
 def decode ( self , packet ) :
  if 99 - 99: I1ii11iIi11i % Oo0Ooo
  if 31 - 31: o0oOOo0O0Ooo - II111iiii * OOooOOo . OOooOOo - oO0o
  if 57 - 57: OOooOOo / i11iIiiIii / I1Ii111 - Oo0Ooo . iIii1I11I1II1
  if 84 - 84: IiII
  OoOo0Oooo0o = "I"
  o0OOo0OOoOO0 = struct . calcsize ( OoOo0Oooo0o )
  if ( len ( packet ) < o0OOo0OOoOO0 ) : return ( None )
  if 42 - 42: O0 . I1Ii111 / I11i
  iiii1ii1 = struct . unpack ( OoOo0Oooo0o , packet [ : o0OOo0OOoOO0 ] )
  if 69 - 69: OoOoOO00 / I1Ii111 * I1IiiI
  iiii1ii1 = socket . ntohl ( iiii1ii1 [ 0 ] )
  self . security = True if ( iiii1ii1 & 0x08000000 ) else False
  self . ddt = True if ( iiii1ii1 & 0x04000000 ) else False
  self . to_etr = True if ( iiii1ii1 & 0x02000000 ) else False
  self . to_ms = True if ( iiii1ii1 & 0x01000000 ) else False
  packet = packet [ o0OOo0OOoOO0 : : ]
  if 76 - 76: O0 + II111iiii * OoO0O00
  if 1 - 1: o0oOOo0O0Ooo
  if 34 - 34: o0oOOo0O0Ooo + OOooOOo . OoO0O00 + I1IiiI + OoooooooOO
  if 90 - 90: Ii1I / OoOoOO00 - iIii1I11I1II1 / i1IIi * I1Ii111 - ooOoO0o
  if ( len ( packet ) < 1 ) : return ( None )
  OOO = struct . unpack ( "B" , packet [ 0 : 1 ] ) [ 0 ]
  OOO = OOO >> 4
  if 2 - 2: iII111i * I11i * ooOoO0o + i11iIiiIii + oO0o
  if ( OOO == 4 ) :
   o0OOo0OOoOO0 = struct . calcsize ( "HHIBBH" )
   if ( len ( packet ) < o0OOo0OOoOO0 ) : return ( None )
   if 81 - 81: o0oOOo0O0Ooo * OoO0O00
   IiIIi , i1IIi111iI , IiIIi , Oo0o0O0OO0 , IiIiI1 , oOoooO0oo0 = struct . unpack ( "HHIBBH" , packet [ : o0OOo0OOoOO0 ] )
   self . length = socket . ntohs ( i1IIi111iI )
   self . ttl = Oo0o0O0OO0
   self . protocol = IiIiI1
   self . ip_checksum = socket . ntohs ( oOoooO0oo0 )
   self . source . afi = self . dest . afi = LISP_AFI_IPV4
   if 83 - 83: iII111i + OoooooooOO + i1IIi / Oo0Ooo
   if 28 - 28: I1IiiI
   if 5 - 5: Oo0Ooo % OOooOOo
   if 30 - 30: I1ii11iIi11i * oO0o + II111iiii / i11iIiiIii
   IiIiI1 = struct . pack ( "H" , 0 )
   IiIIiIiI1ii = struct . calcsize ( "HHIBB" )
   I1ii1iiii = struct . calcsize ( "H" )
   packet = packet [ : IiIIiIiI1ii ] + IiIiI1 + packet [ IiIIiIiI1ii + I1ii1iiii : ]
   if 10 - 10: OoOoOO00 - OoOoOO00 - ooOoO0o - I1IiiI . o0oOOo0O0Ooo
   packet = packet [ o0OOo0OOoOO0 : : ]
   packet = self . source . unpack_address ( packet )
   if ( packet == None ) : return ( None )
   packet = self . dest . unpack_address ( packet )
   if ( packet == None ) : return ( None )
   if 43 - 43: o0oOOo0O0Ooo * OoooooooOO
   if 1 - 1: iII111i % oO0o / OOooOOo * iII111i
  if ( OOO == 6 ) :
   o0OOo0OOoOO0 = struct . calcsize ( "IHBB" )
   if ( len ( packet ) < o0OOo0OOoOO0 ) : return ( None )
   if 28 - 28: oO0o . ooOoO0o / I11i + Oo0Ooo
   IiIIi , i1IIi111iI , IiIiI1 , Oo0o0O0OO0 = struct . unpack ( "IHBB" , packet [ : o0OOo0OOoOO0 ] )
   self . length = socket . ntohs ( i1IIi111iI )
   self . protocol = IiIiI1
   self . ttl = Oo0o0O0OO0
   self . source . afi = self . dest . afi = LISP_AFI_IPV6
   if 55 - 55: OoooooooOO % OoOoOO00 + i1IIi * OoO0O00 * OOooOOo
   packet = packet [ o0OOo0OOoOO0 : : ]
   packet = self . source . unpack_address ( packet )
   if ( packet == None ) : return ( None )
   packet = self . dest . unpack_address ( packet )
   if ( packet == None ) : return ( None )
   if 39 - 39: OOooOOo - oO0o
   if 69 - 69: o0oOOo0O0Ooo * Ii1I * OoOoOO00
  self . source . mask_len = self . source . host_mask_len ( )
  self . dest . mask_len = self . dest . host_mask_len ( )
  if 51 - 51: Oo0Ooo . Oo0Ooo
  o0OOo0OOoOO0 = struct . calcsize ( "HHHH" )
  if ( len ( packet ) < o0OOo0OOoOO0 ) : return ( None )
  if 34 - 34: I1ii11iIi11i - i11iIiiIii
  IiiiI1 , oOOoO0O , i1IIi111iI , oOoooO0oo0 = struct . unpack ( "HHHH" , packet [ : o0OOo0OOoOO0 ] )
  self . udp_sport = socket . ntohs ( IiiiI1 )
  self . udp_dport = socket . ntohs ( oOOoO0O )
  self . udp_length = socket . ntohs ( i1IIi111iI )
  self . udp_checksum = socket . ntohs ( oOoooO0oo0 )
  packet = packet [ o0OOo0OOoOO0 : : ]
  return ( packet )
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
  if 88 - 88: iIii1I11I1II1 / Ii1I * IiII / I1Ii111
  if 31 - 31: O0 . I1IiiI
  if 8 - 8: OoOoOO00
  if 99 - 99: iII111i
  if 93 - 93: I1Ii111
  if 39 - 39: Ii1I
  if 10 - 10: OoOoOO00 . iIii1I11I1II1 / I1ii11iIi11i % iII111i / i11iIiiIii
  if 14 - 14: i11iIiiIii % o0oOOo0O0Ooo * O0 % iIii1I11I1II1 . IiII - II111iiii
  if 14 - 14: Ii1I % ooOoO0o - OoOoOO00
  if 52 - 52: OoO0O00 / i1IIi - Ii1I
  if 8 - 8: oO0o + ooOoO0o . I1ii11iIi11i . i1IIi / I1IiiI . IiII
  if 8 - 8: i1IIi * O0
  if 60 - 60: Oo0Ooo - II111iiii + I1IiiI
  if 17 - 17: OoOoOO00 % I1IiiI
  if 8 - 8: Oo0Ooo
  if 49 - 49: OoOoOO00 * I11i - o0oOOo0O0Ooo / OoO0O00 * oO0o
  if 51 - 51: ooOoO0o - iIii1I11I1II1 . I11i * OoOoOO00 + I1Ii111 * i1IIi
  if 37 - 37: IiII * oO0o / OoooooooOO . OoO0O00
  if 77 - 77: II111iiii + OoOoOO00 * OOooOOo
  if 9 - 9: II111iiii - i11iIiiIii * o0oOOo0O0Ooo % OoO0O00 * i11iIiiIii / I11i
  if 45 - 45: i11iIiiIii * iII111i - I1ii11iIi11i + ooOoO0o % iII111i
  if 11 - 11: iIii1I11I1II1
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
  if 48 - 48: iIii1I11I1II1 - Oo0Ooo
  if 80 - 80: i1IIi
 def print_rloc_name ( self , cour = False ) :
  if ( self . rloc_name == None ) : return ( "" )
  ooOO0OOO = self . rloc_name
  if ( cour ) : ooOO0OOO = lisp_print_cour ( ooOO0OOO )
  return ( 'rloc-name: {}' . format ( blue ( ooOO0OOO , cour ) ) )
  if 60 - 60: II111iiii
  if 4 - 4: oO0o / Oo0Ooo . I11i % I1IiiI * i11iIiiIii
 def print_record ( self , indent ) :
  oo00OO = self . print_rloc_name ( )
  if ( oo00OO != "" ) : oo00OO = ", " + oo00OO
  O000 = ""
  if ( self . geo ) :
   I1i1iI1II = ""
   if ( self . geo . geo_name ) : I1i1iI1II = "'{}' " . format ( self . geo . geo_name )
   O000 = ", geo: {}{}" . format ( I1i1iI1II , self . geo . print_geo ( ) )
   if 99 - 99: i1IIi + o0oOOo0O0Ooo . i11iIiiIii * I1IiiI
  OooO0o00oO = ""
  if ( self . elp ) :
   I1i1iI1II = ""
   if ( self . elp . elp_name ) : I1i1iI1II = "'{}' " . format ( self . elp . elp_name )
   OooO0o00oO = ", elp: {}{}" . format ( I1i1iI1II , self . elp . print_elp ( True ) )
   if 29 - 29: II111iiii % iIii1I11I1II1 * O0 . o0oOOo0O0Ooo
  OoI1i1IIii = ""
  if ( self . rle ) :
   I1i1iI1II = ""
   if ( self . rle . rle_name ) : I1i1iI1II = "'{}' " . format ( self . rle . rle_name )
   OoI1i1IIii = ", rle: {}{}" . format ( I1i1iI1II , self . rle . print_rle ( False ) )
   if 23 - 23: I11i % I1Ii111 / I11i / I1ii11iIi11i
  I111Ii1I = ""
  if ( self . json ) :
   I1i1iI1II = ""
   if ( self . json . json_name ) :
    I1i1iI1II = "'{}' " . format ( self . json . json_name )
    if 28 - 28: iII111i % OoO0O00 - OOooOOo - Oo0Ooo
   I111Ii1I = ", json: {}" . format ( self . json . print_json ( False ) )
   if 16 - 16: i11iIiiIii - i11iIiiIii . OoOoOO00 / i1IIi
   if 76 - 76: O0 * OoO0O00 / O0
  IIoooO = ""
  if ( self . rloc . is_null ( ) == False and self . keys and self . keys [ 1 ] ) :
   IIoooO = ", " + self . keys [ 1 ] . print_keys ( )
   if 40 - 40: iII111i - I1IiiI / OoOoOO00 % I1Ii111
   if 33 - 33: II111iiii . I11i / OoooooooOO * i11iIiiIii / O0 . I11i
  iI1111i = ( "{}RLOC-record -> flags: {}, {}/{}/{}/{}, afi: {}, rloc: "
 + "{}{}{}{}{}{}{}" )
  lprint ( iI1111i . format ( indent , self . print_flags ( ) , self . priority ,
 self . weight , self . mpriority , self . mweight , self . rloc . afi ,
 red ( self . rloc . print_address_no_iid ( ) , False ) , oo00OO , O000 ,
 OooO0o00oO , OoI1i1IIii , I111Ii1I , IIoooO ) )
  if 31 - 31: I1Ii111 + iIii1I11I1II1 + I1IiiI - ooOoO0o / I1Ii111
  if 39 - 39: Oo0Ooo - OoooooooOO . i1IIi + i1IIi % Ii1I . OOooOOo
 def print_flags ( self ) :
  return ( "{}{}{}" . format ( "L" if self . local_bit else "l" , "P" if self . probe_bit else "p" , "R" if self . reach_bit else "r" ) )
  if 30 - 30: O0 / oO0o
  if 93 - 93: Oo0Ooo
  if 5 - 5: iII111i
 def store_rloc_entry ( self , rloc_entry ) :
  o0OOooooooOO = rloc_entry . rloc if ( rloc_entry . translated_rloc . is_null ( ) ) else rloc_entry . translated_rloc
  if 77 - 77: i1IIi + OoO0O00 / OoOoOO00 - i11iIiiIii * iIii1I11I1II1 / Oo0Ooo
  self . rloc . copy_address ( o0OOooooooOO )
  if 4 - 4: I1ii11iIi11i * o0oOOo0O0Ooo
  if ( rloc_entry . rloc_name ) :
   self . rloc_name = rloc_entry . rloc_name
   if 31 - 31: i11iIiiIii % OoO0O00 . i11iIiiIii % oO0o - i1IIi
   if 62 - 62: oO0o + oO0o . OoooooooOO
  if ( rloc_entry . geo ) :
   self . geo = rloc_entry . geo
  else :
   I1i1iI1II = rloc_entry . geo_name
   if ( I1i1iI1II and lisp_geo_list . has_key ( I1i1iI1II ) ) :
    self . geo = lisp_geo_list [ I1i1iI1II ]
    if 59 - 59: iIii1I11I1II1 . Oo0Ooo * I11i
    if 29 - 29: Oo0Ooo - I1IiiI * I11i
  if ( rloc_entry . elp ) :
   self . elp = rloc_entry . elp
  else :
   I1i1iI1II = rloc_entry . elp_name
   if ( I1i1iI1II and lisp_elp_list . has_key ( I1i1iI1II ) ) :
    self . elp = lisp_elp_list [ I1i1iI1II ]
    if 58 - 58: i1IIi * Ii1I / ooOoO0o % iIii1I11I1II1
    if 24 - 24: OoOoOO00 - o0oOOo0O0Ooo * I1IiiI . I11i / OoO0O00 * Ii1I
  if ( rloc_entry . rle ) :
   self . rle = rloc_entry . rle
  else :
   I1i1iI1II = rloc_entry . rle_name
   if ( I1i1iI1II and lisp_rle_list . has_key ( I1i1iI1II ) ) :
    self . rle = lisp_rle_list [ I1i1iI1II ]
    if 12 - 12: OoooooooOO % oO0o
    if 92 - 92: ooOoO0o % OoO0O00 + O0 + OoOoOO00 / OoO0O00 * iIii1I11I1II1
  if ( rloc_entry . json ) :
   self . json = rloc_entry . json
  else :
   I1i1iI1II = rloc_entry . json_name
   if ( I1i1iI1II and lisp_json_list . has_key ( I1i1iI1II ) ) :
    self . json = lisp_json_list [ I1i1iI1II ]
    if 79 - 79: O0
    if 71 - 71: OoO0O00 - O0
  self . priority = rloc_entry . priority
  self . weight = rloc_entry . weight
  self . mpriority = rloc_entry . mpriority
  self . mweight = rloc_entry . mweight
  if 73 - 73: iIii1I11I1II1
  if 7 - 7: OoOoOO00
 def encode_lcaf ( self ) :
  oO0OOOo0OO = socket . htons ( LISP_AFI_LCAF )
  OOiiiIII = ""
  if ( self . geo ) :
   OOiiiIII = self . geo . encode_geo ( )
   if 8 - 8: iII111i
   if 52 - 52: OoO0O00 - I1Ii111
  iii = ""
  if ( self . elp ) :
   II1II1i = ""
   for IiIIooO00oOo0 in self . elp . elp_nodes :
    I1I1i = socket . htons ( IiIIooO00oOo0 . address . afi )
    iiIIii1Iii1I = 0
    if ( IiIIooO00oOo0 . eid ) : iiIIii1Iii1I |= 0x4
    if ( IiIIooO00oOo0 . probe ) : iiIIii1Iii1I |= 0x2
    if ( IiIIooO00oOo0 . strict ) : iiIIii1Iii1I |= 0x1
    iiIIii1Iii1I = socket . htons ( iiIIii1Iii1I )
    II1II1i += struct . pack ( "HH" , iiIIii1Iii1I , I1I1i )
    II1II1i += IiIIooO00oOo0 . address . pack_address ( )
    if 42 - 42: I1IiiI * o0oOOo0O0Ooo / O0 . II111iiii
    if 88 - 88: OoooooooOO % II111iiii + IiII + IiII * Oo0Ooo
   ooO00O00o0O0o = socket . htons ( len ( II1II1i ) )
   iii = struct . pack ( "HBBBBH" , oO0OOOo0OO , 0 , 0 , LISP_LCAF_ELP_TYPE ,
 0 , ooO00O00o0O0o )
   iii += II1II1i
   if 45 - 45: OoooooooOO + iII111i
   if 58 - 58: i11iIiiIii % iIii1I11I1II1 + OoO0O00 . I1ii11iIi11i . I1IiiI
  o0o = ""
  if ( self . rle ) :
   iIIIiii = ""
   for I11iI in self . rle . rle_nodes :
    I1I1i = socket . htons ( I11iI . address . afi )
    iIIIiii += struct . pack ( "HBBH" , 0 , 0 , I11iI . level , I1I1i )
    iIIIiii += I11iI . address . pack_address ( )
    if ( I11iI . rloc_name ) :
     iIIIiii += struct . pack ( "H" , socket . htons ( LISP_AFI_NAME ) )
     iIIIiii += I11iI . rloc_name + "\0"
     if 31 - 31: I1Ii111 - Ii1I / OoOoOO00 / IiII - OOooOOo * I11i
     if 1 - 1: I11i * IiII + IiII + OOooOOo / i1IIi + oO0o
     if 53 - 53: OoOoOO00
   OooO0ooO0o0OO = socket . htons ( len ( iIIIiii ) )
   o0o = struct . pack ( "HBBBBH" , oO0OOOo0OO , 0 , 0 , LISP_LCAF_RLE_TYPE ,
 0 , OooO0ooO0o0OO )
   o0o += iIIIiii
   if 73 - 73: OoooooooOO
   if 64 - 64: Ii1I * OoO0O00 % O0 . Ii1I . OoooooooOO
  O0OOoOo0Oo0O = ""
  if ( self . json ) :
   i1IiI = socket . htons ( len ( self . json . json_string ) + 2 )
   I1iI1i = socket . htons ( len ( self . json . json_string ) )
   O0OOoOo0Oo0O = struct . pack ( "HBBBBHH" , oO0OOOo0OO , 0 , 0 , LISP_LCAF_JSON_TYPE ,
 0 , i1IiI , I1iI1i )
   O0OOoOo0Oo0O += self . json . json_string
   O0OOoOo0Oo0O += struct . pack ( "H" , 0 )
   if 46 - 46: Ii1I . ooOoO0o . OoO0O00 - I11i
   if 64 - 64: IiII + II111iiii - IiII * I1ii11iIi11i * i11iIiiIii
  O0o0o = ""
  if ( self . rloc . is_null ( ) == False and self . keys and self . keys [ 1 ] ) :
   O0o0o = self . keys [ 1 ] . encode_lcaf ( self . rloc )
   if 63 - 63: I1ii11iIi11i . i11iIiiIii / IiII - iIii1I11I1II1 . I1IiiI
   if 40 - 40: o0oOOo0O0Ooo % I11i % O0
  oOO0oooo = ""
  if ( self . rloc_name ) :
   oOO0oooo += struct . pack ( "H" , socket . htons ( LISP_AFI_NAME ) )
   oOO0oooo += self . rloc_name + "\0"
   if 28 - 28: OoO0O00
   if 90 - 90: iII111i % oO0o / iIii1I11I1II1
  ooOoO = len ( OOiiiIII ) + len ( iii ) + len ( o0o ) + len ( O0o0o ) + 2 + len ( O0OOoOo0Oo0O ) + self . rloc . addr_length ( ) + len ( oOO0oooo )
  if 2 - 2: I1IiiI - iIii1I11I1II1 / OoOoOO00 * O0 / i11iIiiIii * IiII
  ooOoO = socket . htons ( ooOoO )
  OO0Oo0 = struct . pack ( "HBBBBHH" , oO0OOOo0OO , 0 , 0 , LISP_LCAF_AFI_LIST_TYPE ,
 0 , ooOoO , socket . htons ( self . rloc . afi ) )
  OO0Oo0 += self . rloc . pack_address ( )
  return ( OO0Oo0 + oOO0oooo + OOiiiIII + iii + o0o + O0o0o + O0OOoOo0Oo0O )
  if 44 - 44: o0oOOo0O0Ooo
  if 39 - 39: OoO0O00 - I1ii11iIi11i . Oo0Ooo % I11i + OOooOOo - OoooooooOO
 def encode ( self ) :
  iiIIii1Iii1I = 0
  if ( self . local_bit ) : iiIIii1Iii1I |= 0x0004
  if ( self . probe_bit ) : iiIIii1Iii1I |= 0x0002
  if ( self . reach_bit ) : iiIIii1Iii1I |= 0x0001
  if 7 - 7: IiII % ooOoO0o / OoooooooOO / o0oOOo0O0Ooo + OoO0O00 - OoO0O00
  Oo0O0oo = struct . pack ( "BBBBHH" , self . priority , self . weight ,
 self . mpriority , self . mweight , socket . htons ( iiIIii1Iii1I ) ,
 socket . htons ( self . rloc . afi ) )
  if 15 - 15: i1IIi + OOooOOo / Ii1I
  if ( self . geo or self . elp or self . rle or self . keys or self . rloc_name or self . json ) :
   if 51 - 51: OOooOOo + O0
   Oo0O0oo = Oo0O0oo [ 0 : - 2 ] + self . encode_lcaf ( )
  else :
   Oo0O0oo += self . rloc . pack_address ( )
   if 91 - 91: i11iIiiIii + o0oOOo0O0Ooo % OoO0O00 / oO0o - i1IIi
  return ( Oo0O0oo )
  if 82 - 82: Ii1I . OoooooooOO + OoooooooOO % OoO0O00 % I1ii11iIi11i
  if 65 - 65: Oo0Ooo . I11i
 def decode_lcaf ( self , packet , nonce ) :
  OoOo0Oooo0o = "HBBBBH"
  o0OOo0OOoOO0 = struct . calcsize ( OoOo0Oooo0o )
  if ( len ( packet ) < o0OOo0OOoOO0 ) : return ( None )
  if 7 - 7: Oo0Ooo * II111iiii
  I1I1i , iiII1II1 , iiIIii1Iii1I , o0oOoOOO , OO00 , i1IiI = struct . unpack ( OoOo0Oooo0o , packet [ : o0OOo0OOoOO0 ] )
  if 11 - 11: OoOoOO00 % OoooooooOO
  if 92 - 92: OoOoOO00 - iII111i * Ii1I - i1IIi
  i1IiI = socket . ntohs ( i1IiI )
  packet = packet [ o0OOo0OOoOO0 : : ]
  if ( i1IiI > len ( packet ) ) : return ( None )
  if 87 - 87: Ii1I * I1Ii111 + iIii1I11I1II1 * o0oOOo0O0Ooo * iIii1I11I1II1 . I11i
  if 66 - 66: Ii1I / OoO0O00 . O0 . I11i % OoooooooOO / OOooOOo
  if 49 - 49: I1IiiI * iII111i - OoO0O00 % Ii1I + Ii1I * I1Ii111
  if 94 - 94: OoOoOO00 - I11i + Ii1I + OoOoOO00 + II111iiii
  if ( o0oOoOOO == LISP_LCAF_AFI_LIST_TYPE ) :
   while ( i1IiI > 0 ) :
    OoOo0Oooo0o = "H"
    o0OOo0OOoOO0 = struct . calcsize ( OoOo0Oooo0o )
    if ( i1IiI < o0OOo0OOoOO0 ) : return ( None )
    if 61 - 61: IiII + Ii1I / oO0o . OoooooooOO + iII111i
    oO0000 = len ( packet )
    I1I1i = struct . unpack ( OoOo0Oooo0o , packet [ : o0OOo0OOoOO0 ] ) [ 0 ]
    I1I1i = socket . ntohs ( I1I1i )
    if 29 - 29: OOooOOo
    if ( I1I1i == LISP_AFI_LCAF ) :
     packet = self . decode_lcaf ( packet , nonce )
     if ( packet == None ) : return ( None )
    else :
     packet = packet [ o0OOo0OOoOO0 : : ]
     self . rloc_name = None
     if ( I1I1i == LISP_AFI_NAME ) :
      packet , ooOO0OOO = lisp_decode_dist_name ( packet )
      self . rloc_name = ooOO0OOO
     else :
      self . rloc . afi = I1I1i
      packet = self . rloc . unpack_address ( packet )
      if ( packet == None ) : return ( None )
      self . rloc . mask_len = self . rloc . host_mask_len ( )
      if 69 - 69: oO0o % OoooooooOO * iII111i
      if 58 - 58: oO0o / i11iIiiIii . OoOoOO00 % O0 / iIii1I11I1II1
      if 50 - 50: I1Ii111 . I11i / O0 . I11i
    i1IiI -= oO0000 - len ( packet )
    if 91 - 91: i11iIiiIii . I1ii11iIi11i + I11i
    if 67 - 67: I1ii11iIi11i * I1Ii111 * I1IiiI / I11i - IiII + oO0o
  elif ( o0oOoOOO == LISP_LCAF_GEO_COORD_TYPE ) :
   if 11 - 11: O0 + i1IIi / o0oOOo0O0Ooo * OoO0O00
   if 64 - 64: i1IIi % IiII . ooOoO0o . iIii1I11I1II1 + OoO0O00 - iIii1I11I1II1
   if 52 - 52: II111iiii - IiII
   if 91 - 91: iIii1I11I1II1 + iII111i . I11i % i11iIiiIii - i11iIiiIii + I1IiiI
   OOOOo = lisp_geo ( "" )
   packet = OOOOo . decode_geo ( packet , i1IiI , OO00 )
   if ( packet == None ) : return ( None )
   self . geo = OOOOo
   if 15 - 15: OOooOOo + IiII % OoooooooOO % IiII / I1Ii111 * Oo0Ooo
  elif ( o0oOoOOO == LISP_LCAF_JSON_TYPE ) :
   if 72 - 72: i11iIiiIii / O0 * O0 . I1ii11iIi11i % O0
   if 45 - 45: i11iIiiIii
   if 95 - 95: i11iIiiIii - ooOoO0o - OOooOOo / I1IiiI / oO0o * OoooooooOO
   if 69 - 69: I1Ii111 / oO0o % O0 + Ii1I
   OoOo0Oooo0o = "H"
   o0OOo0OOoOO0 = struct . calcsize ( OoOo0Oooo0o )
   if ( i1IiI < o0OOo0OOoOO0 ) : return ( None )
   if 40 - 40: o0oOOo0O0Ooo - iIii1I11I1II1 % oO0o . o0oOOo0O0Ooo
   I1iI1i = struct . unpack ( OoOo0Oooo0o , packet [ : o0OOo0OOoOO0 ] ) [ 0 ]
   I1iI1i = socket . ntohs ( I1iI1i )
   if ( i1IiI < o0OOo0OOoOO0 + I1iI1i ) : return ( None )
   if 35 - 35: I1IiiI % OOooOOo + OoOoOO00 / I1IiiI . O0 % iII111i
   packet = packet [ o0OOo0OOoOO0 : : ]
   self . json = lisp_json ( "" , packet [ 0 : I1iI1i ] )
   packet = packet [ I1iI1i : : ]
   if 100 - 100: I1IiiI
  elif ( o0oOoOOO == LISP_LCAF_ELP_TYPE ) :
   if 55 - 55: i1IIi % IiII
   if 44 - 44: oO0o - iIii1I11I1II1 / ooOoO0o - iIii1I11I1II1 % i1IIi + ooOoO0o
   if 74 - 74: I11i . OoOoOO00 + OoOoOO00
   if 87 - 87: IiII + o0oOOo0O0Ooo . i1IIi % I1Ii111
   IIiI11i1i = lisp_elp ( None )
   IIiI11i1i . elp_nodes = [ ]
   while ( i1IiI > 0 ) :
    iiIIii1Iii1I , I1I1i = struct . unpack ( "HH" , packet [ : 4 ] )
    if 16 - 16: o0oOOo0O0Ooo + i11iIiiIii % OOooOOo
    I1I1i = socket . ntohs ( I1I1i )
    if ( I1I1i == LISP_AFI_LCAF ) : return ( None )
    if 20 - 20: Oo0Ooo . OoooooooOO % oO0o - OOooOOo
    IiIIooO00oOo0 = lisp_elp_node ( )
    IIiI11i1i . elp_nodes . append ( IiIIooO00oOo0 )
    if 72 - 72: II111iiii . iII111i - iIii1I11I1II1 - oO0o / OoooooooOO + I1IiiI
    iiIIii1Iii1I = socket . ntohs ( iiIIii1Iii1I )
    IiIIooO00oOo0 . eid = ( iiIIii1Iii1I & 0x4 )
    IiIIooO00oOo0 . probe = ( iiIIii1Iii1I & 0x2 )
    IiIIooO00oOo0 . strict = ( iiIIii1Iii1I & 0x1 )
    IiIIooO00oOo0 . address . afi = I1I1i
    IiIIooO00oOo0 . address . mask_len = IiIIooO00oOo0 . address . host_mask_len ( )
    packet = IiIIooO00oOo0 . address . unpack_address ( packet [ 4 : : ] )
    i1IiI -= IiIIooO00oOo0 . address . addr_length ( ) + 4
    if 61 - 61: o0oOOo0O0Ooo / I1ii11iIi11i / ooOoO0o
   IIiI11i1i . select_elp_node ( )
   self . elp = IIiI11i1i
   if 54 - 54: I1Ii111 * I1Ii111
  elif ( o0oOoOOO == LISP_LCAF_RLE_TYPE ) :
   if 30 - 30: I1Ii111 . OoOoOO00 + I1ii11iIi11i - iIii1I11I1II1 * ooOoO0o
   if 87 - 87: O0 + O0 - ooOoO0o . i11iIiiIii - Oo0Ooo * i11iIiiIii
   if 72 - 72: I11i / OoooooooOO
   if 95 - 95: I1IiiI * i11iIiiIii + i11iIiiIii / iIii1I11I1II1
   O000o0 = lisp_rle ( None )
   O000o0 . rle_nodes = [ ]
   while ( i1IiI > 0 ) :
    IiIIi , iiIiI1iiI1 , I1i1IiI1i1Ii , I1I1i = struct . unpack ( "HBBH" , packet [ : 6 ] )
    if 14 - 14: Oo0Ooo / I11i
    I1I1i = socket . ntohs ( I1I1i )
    if ( I1I1i == LISP_AFI_LCAF ) : return ( None )
    if 14 - 14: Oo0Ooo - Ii1I + ooOoO0o - I1IiiI % IiII
    I11iI = lisp_rle_node ( )
    O000o0 . rle_nodes . append ( I11iI )
    if 70 - 70: I1IiiI % ooOoO0o * OoO0O00 + OoOoOO00 % i11iIiiIii
    I11iI . level = I1i1IiI1i1Ii
    I11iI . address . afi = I1I1i
    I11iI . address . mask_len = I11iI . address . host_mask_len ( )
    packet = I11iI . address . unpack_address ( packet [ 6 : : ] )
    if 39 - 39: Oo0Ooo % I1Ii111 / I1IiiI / Oo0Ooo . o0oOOo0O0Ooo + o0oOOo0O0Ooo
    i1IiI -= I11iI . address . addr_length ( ) + 6
    if ( i1IiI >= 2 ) :
     I1I1i = struct . unpack ( "H" , packet [ : 2 ] ) [ 0 ]
     if ( socket . ntohs ( I1I1i ) == LISP_AFI_NAME ) :
      packet = packet [ 2 : : ]
      packet , I11iI . rloc_name = lisp_decode_dist_name ( packet )
      if 83 - 83: OoooooooOO * II111iiii % OoooooooOO
      if ( packet == None ) : return ( None )
      i1IiI -= len ( I11iI . rloc_name ) + 1 + 2
      if 30 - 30: I1Ii111 / o0oOOo0O0Ooo + OoooooooOO + OoOoOO00 + OoO0O00
      if 40 - 40: OoooooooOO / IiII
      if 82 - 82: i11iIiiIii - oO0o - i1IIi
   self . rle = O000o0
   self . rle . build_forwarding_list ( )
   if 78 - 78: oO0o % iII111i / i1IIi / ooOoO0o
  elif ( o0oOoOOO == LISP_LCAF_SECURITY_TYPE ) :
   if 44 - 44: o0oOOo0O0Ooo + Ii1I + I1IiiI % O0
   if 100 - 100: OoooooooOO
   if 27 - 27: i11iIiiIii % II111iiii + I1Ii111
   if 76 - 76: OOooOOo - I1Ii111 + iIii1I11I1II1 + I1IiiI * oO0o
   if 93 - 93: i11iIiiIii * i11iIiiIii - I1IiiI + iIii1I11I1II1 * i11iIiiIii
   oOoo0O000 = packet
   oO00OO0Ooo00O = lisp_keys ( 1 )
   packet = oO00OO0Ooo00O . decode_lcaf ( oOoo0O000 , i1IiI )
   if ( packet == None ) : return ( None )
   if 14 - 14: ooOoO0o . OoooooooOO . I1IiiI - IiII + iIii1I11I1II1
   if 47 - 47: OOooOOo % i1IIi
   if 23 - 23: Ii1I * Ii1I / I11i
   if 11 - 11: OOooOOo
   O0Oo = [ LISP_CS_25519_CBC , LISP_CS_25519_CHACHA ]
   if ( oO00OO0Ooo00O . cipher_suite in O0Oo ) :
    if ( oO00OO0Ooo00O . cipher_suite == LISP_CS_25519_CBC ) :
     i1iI11iI = lisp_keys ( 1 , do_poly = False , do_chacha = False )
     if 58 - 58: OoO0O00 * OoooooooOO
    if ( oO00OO0Ooo00O . cipher_suite == LISP_CS_25519_CHACHA ) :
     i1iI11iI = lisp_keys ( 1 , do_poly = True , do_chacha = True )
     if 47 - 47: iII111i - Oo0Ooo
   else :
    i1iI11iI = lisp_keys ( 1 , do_poly = False , do_chacha = False )
    if 19 - 19: O0 . i1IIi + I11i / II111iiii + ooOoO0o
   packet = i1iI11iI . decode_lcaf ( oOoo0O000 , i1IiI )
   if ( packet == None ) : return ( None )
   if 26 - 26: Ii1I * oO0o % I1IiiI - OOooOOo . I1Ii111
   if ( len ( packet ) < 2 ) : return ( None )
   I1I1i = struct . unpack ( "H" , packet [ : 2 ] ) [ 0 ]
   self . rloc . afi = socket . ntohs ( I1I1i )
   if ( len ( packet ) < self . rloc . addr_length ( ) ) : return ( None )
   packet = self . rloc . unpack_address ( packet [ 2 : : ] )
   if ( packet == None ) : return ( None )
   self . rloc . mask_len = self . rloc . host_mask_len ( )
   if 35 - 35: i1IIi % i11iIiiIii + Ii1I
   if 14 - 14: OoO0O00 * OoooooooOO
   if 45 - 45: iIii1I11I1II1 * I1IiiI . OoOoOO00
   if 97 - 97: I11i % II111iiii % Ii1I . II111iiii . iIii1I11I1II1
   if 98 - 98: i11iIiiIii + O0 - O0 - iII111i
   if 25 - 25: oO0o / O0 + I1Ii111 % i11iIiiIii / I1IiiI
   if ( self . rloc . is_null ( ) ) : return ( packet )
   if 62 - 62: iII111i . I11i * i1IIi + iII111i
   O00OOO0OO = self . rloc_name
   if ( O00OOO0OO ) : O00OOO0OO = blue ( self . rloc_name , False )
   if 6 - 6: OoO0O00 % IiII + iIii1I11I1II1
   if 18 - 18: II111iiii . Ii1I + OoOoOO00 + O0 - I11i
   if 30 - 30: II111iiii
   if 26 - 26: I11i - i1IIi - Oo0Ooo * O0 * OOooOOo . OoooooooOO
   if 99 - 99: oO0o . OoO0O00 / OOooOOo
   if 12 - 12: iIii1I11I1II1 + ooOoO0o * I1Ii111 % OoooooooOO / iIii1I11I1II1
   I11IiiI1 = self . keys [ 1 ] if self . keys else None
   if ( I11IiiI1 == None ) :
    if ( i1iI11iI . remote_public_key == None ) :
     oo0O = bold ( "No remote encap-public-key supplied" , False )
     lprint ( "    {} for {}" . format ( oo0O , O00OOO0OO ) )
     i1iI11iI = None
    else :
     oo0O = bold ( "New encap-keying with new state" , False )
     lprint ( "    {} for {}" . format ( oo0O , O00OOO0OO ) )
     i1iI11iI . compute_shared_key ( "encap" )
     if 43 - 43: O0 . i1IIi - OoooooooOO - i1IIi - I1ii11iIi11i
     if 8 - 8: OoOoOO00 / Ii1I
     if 12 - 12: iIii1I11I1II1
     if 52 - 52: oO0o . I1ii11iIi11i + oO0o
     if 73 - 73: II111iiii / i11iIiiIii / ooOoO0o
     if 1 - 1: iII111i + OoOoOO00 / IiII - I1IiiI % I1IiiI
     if 6 - 6: OoOoOO00 - i1IIi + II111iiii % oO0o
     if 72 - 72: OOooOOo + OOooOOo
     if 30 - 30: I11i
     if 15 - 15: O0 - i1IIi . iIii1I11I1II1 - i11iIiiIii / Ii1I
   if ( I11IiiI1 ) :
    if ( i1iI11iI . remote_public_key == None ) :
     i1iI11iI = None
     o0o00O0 = bold ( "Remote encap-unkeying occurred" , False )
     lprint ( "    {} for {}" . format ( o0o00O0 , O00OOO0OO ) )
    elif ( I11IiiI1 . compare_keys ( i1iI11iI ) ) :
     i1iI11iI = I11IiiI1
     lprint ( "    Maintain stored encap-keys for {}" . format ( O00OOO0OO ) )
     if 11 - 11: iIii1I11I1II1 + I1IiiI
    else :
     if ( I11IiiI1 . remote_public_key == None ) :
      oo0O = "New encap-keying for existing state"
     else :
      oo0O = "Remote encap-rekeying"
      if 15 - 15: o0oOOo0O0Ooo
     lprint ( "    {} for {}" . format ( bold ( oo0O , False ) ,
 O00OOO0OO ) )
     I11IiiI1 . remote_public_key = i1iI11iI . remote_public_key
     I11IiiI1 . compute_shared_key ( "encap" )
     i1iI11iI = I11IiiI1
     if 55 - 55: i11iIiiIii / OoooooooOO - I11i
     if 89 - 89: I11i - i1IIi - i1IIi * OOooOOo - O0
   self . keys = [ None , i1iI11iI , None , None ]
   if 94 - 94: Oo0Ooo / I11i . I1ii11iIi11i
  else :
   if 31 - 31: i11iIiiIii + iIii1I11I1II1 . II111iiii
   if 72 - 72: I1Ii111 * OoO0O00 + Oo0Ooo / Ii1I % OOooOOo
   if 84 - 84: OoOoOO00 / o0oOOo0O0Ooo
   if 9 - 9: Ii1I
   packet = packet [ i1IiI : : ]
   if 76 - 76: I1IiiI % Oo0Ooo / iIii1I11I1II1 - Oo0Ooo
  return ( packet )
  if 34 - 34: OoOoOO00 - i1IIi + OOooOOo + Ii1I . o0oOOo0O0Ooo
  if 42 - 42: OoO0O00
 def decode ( self , packet , nonce ) :
  OoOo0Oooo0o = "BBBBHH"
  o0OOo0OOoOO0 = struct . calcsize ( OoOo0Oooo0o )
  if ( len ( packet ) < o0OOo0OOoOO0 ) : return ( None )
  if 59 - 59: OoO0O00 . I1Ii111 % OoO0O00
  self . priority , self . weight , self . mpriority , self . mweight , iiIIii1Iii1I , I1I1i = struct . unpack ( OoOo0Oooo0o , packet [ : o0OOo0OOoOO0 ] )
  if 22 - 22: Oo0Ooo
  if 21 - 21: o0oOOo0O0Ooo
  iiIIii1Iii1I = socket . ntohs ( iiIIii1Iii1I )
  I1I1i = socket . ntohs ( I1I1i )
  self . local_bit = True if ( iiIIii1Iii1I & 0x0004 ) else False
  self . probe_bit = True if ( iiIIii1Iii1I & 0x0002 ) else False
  self . reach_bit = True if ( iiIIii1Iii1I & 0x0001 ) else False
  if 86 - 86: ooOoO0o / iIii1I11I1II1 . OOooOOo
  if ( I1I1i == LISP_AFI_LCAF ) :
   packet = packet [ o0OOo0OOoOO0 - 2 : : ]
   packet = self . decode_lcaf ( packet , nonce )
  else :
   self . rloc . afi = I1I1i
   packet = packet [ o0OOo0OOoOO0 : : ]
   packet = self . rloc . unpack_address ( packet )
   if 93 - 93: Oo0Ooo / II111iiii . Oo0Ooo + i1IIi + i1IIi
  self . rloc . mask_len = self . rloc . host_mask_len ( )
  return ( packet )
  if 30 - 30: OoOoOO00 . OOooOOo % OOooOOo / II111iiii + i1IIi
  if 61 - 61: i1IIi % II111iiii * II111iiii . o0oOOo0O0Ooo / I1ii11iIi11i - I1Ii111
 def end_of_rlocs ( self , packet , rloc_count ) :
  for o0OoO00 in range ( rloc_count ) :
   packet = self . decode ( packet , None )
   if ( packet == None ) : return ( None )
   if 93 - 93: Ii1I - i1IIi
  return ( packet )
  if 3 - 3: oO0o + OoO0O00 - iII111i / Ii1I
  if 58 - 58: Ii1I * I11i
  if 95 - 95: oO0o
  if 49 - 49: I1IiiI
  if 23 - 23: I1Ii111
  if 5 - 5: I1ii11iIi11i % OoOoOO00 . OoooooooOO . o0oOOo0O0Ooo + i11iIiiIii
  if 54 - 54: ooOoO0o - O0 + iII111i
  if 34 - 34: Ii1I - OOooOOo % iII111i
  if 48 - 48: oO0o - O0
  if 17 - 17: iIii1I11I1II1 . IiII / ooOoO0o % I11i + o0oOOo0O0Ooo - iIii1I11I1II1
  if 95 - 95: OoOoOO00 + OOooOOo - I11i * i1IIi + i1IIi * O0
  if 60 - 60: Oo0Ooo + I11i % iIii1I11I1II1 % oO0o - I1Ii111 / o0oOOo0O0Ooo
  if 9 - 9: IiII / oO0o % O0 * I1Ii111 - iIii1I11I1II1 % i1IIi
  if 83 - 83: OoOoOO00 + OOooOOo / OoooooooOO
  if 39 - 39: OoO0O00 % iII111i . oO0o . II111iiii - i11iIiiIii
  if 85 - 85: O0 - OoOoOO00
  if 17 - 17: o0oOOo0O0Ooo / i1IIi / OOooOOo
  if 91 - 91: I1ii11iIi11i / Ii1I - OoOoOO00 . I11i / oO0o
  if 16 - 16: IiII % iII111i . oO0o . I1IiiI % O0 * I11i
  if 99 - 99: OoOoOO00 / OoooooooOO + iII111i * I11i * i11iIiiIii + OOooOOo
  if 40 - 40: II111iiii / I11i % I1IiiI - O0
  if 39 - 39: i11iIiiIii - OoOoOO00 % OOooOOo + ooOoO0o + i11iIiiIii
  if 59 - 59: IiII / OoOoOO00 - I1Ii111 - ooOoO0o . oO0o
  if 87 - 87: oO0o + I1IiiI * I1Ii111 * o0oOOo0O0Ooo + O0
  if 21 - 21: I1Ii111 + OoOoOO00 + OoOoOO00 . II111iiii / I1Ii111 . I1IiiI
  if 66 - 66: I1Ii111 % oO0o . iII111i * i1IIi
  if 81 - 81: OoooooooOO * I1IiiI / I1Ii111
  if 10 - 10: I1IiiI - II111iiii / IiII * II111iiii
  if 67 - 67: II111iiii . Ii1I % oO0o . Oo0Ooo + IiII
  if 10 - 10: OOooOOo - OoO0O00 * oO0o / iIii1I11I1II1 - OoOoOO00
class lisp_map_referral ( ) :
 def __init__ ( self ) :
  self . record_count = 0
  self . nonce = 0
  if 20 - 20: IiII % I1IiiI + iIii1I11I1II1 % iII111i
  if 100 - 100: o0oOOo0O0Ooo - Oo0Ooo % I1Ii111 . i11iIiiIii % OoooooooOO
 def print_map_referral ( self ) :
  lprint ( "{} -> record-count: {}, nonce: 0x{}" . format ( bold ( "Map-Referral" , False ) , self . record_count ,
  # OoooooooOO - ooOoO0o - i11iIiiIii
 lisp_hex_string ( self . nonce ) ) )
  if 96 - 96: Oo0Ooo + I1ii11iIi11i
  if 94 - 94: OoooooooOO / i1IIi + Oo0Ooo
 def encode ( self ) :
  iiii1ii1 = ( LISP_MAP_REFERRAL << 28 ) | self . record_count
  Oo0O0oo = struct . pack ( "I" , socket . htonl ( iiii1ii1 ) )
  Oo0O0oo += struct . pack ( "Q" , self . nonce )
  return ( Oo0O0oo )
  if 57 - 57: O0
  if 83 - 83: OOooOOo / Ii1I * I1IiiI % oO0o / iIii1I11I1II1
 def decode ( self , packet ) :
  OoOo0Oooo0o = "I"
  o0OOo0OOoOO0 = struct . calcsize ( OoOo0Oooo0o )
  if ( len ( packet ) < o0OOo0OOoOO0 ) : return ( None )
  if 1 - 1: I11i / OoooooooOO / iII111i
  iiii1ii1 = struct . unpack ( OoOo0Oooo0o , packet [ : o0OOo0OOoOO0 ] )
  iiii1ii1 = socket . ntohl ( iiii1ii1 [ 0 ] )
  self . record_count = iiii1ii1 & 0xff
  packet = packet [ o0OOo0OOoOO0 : : ]
  if 68 - 68: i1IIi / Oo0Ooo / I11i * Oo0Ooo
  OoOo0Oooo0o = "Q"
  o0OOo0OOoOO0 = struct . calcsize ( OoOo0Oooo0o )
  if ( len ( packet ) < o0OOo0OOoOO0 ) : return ( None )
  if 91 - 91: OoO0O00 . iII111i
  self . nonce = struct . unpack ( OoOo0Oooo0o , packet [ : o0OOo0OOoOO0 ] ) [ 0 ]
  packet = packet [ o0OOo0OOoOO0 : : ]
  return ( packet )
  if 82 - 82: I1ii11iIi11i / Oo0Ooo
  if 63 - 63: I1IiiI
  if 3 - 3: iII111i + I1ii11iIi11i
  if 35 - 35: oO0o * iII111i * oO0o * I1Ii111 * IiII * i1IIi
  if 43 - 43: OoO0O00 * I1IiiI / IiII . i11iIiiIii + iII111i + o0oOOo0O0Ooo
  if 1 - 1: I1IiiI % o0oOOo0O0Ooo . I1Ii111 + I11i * oO0o
  if 41 - 41: OoO0O00 * oO0o - II111iiii
  if 2 - 2: IiII + IiII - OoO0O00 * iII111i . oO0o
class lisp_ddt_entry ( ) :
 def __init__ ( self ) :
  self . eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . group = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . uptime = lisp_get_timestamp ( )
  self . delegation_set = [ ]
  self . source_cache = None
  self . map_referrals_sent = 0
  if 91 - 91: ooOoO0o
  if 22 - 22: ooOoO0o % OoO0O00 * OoOoOO00 + Oo0Ooo
 def is_auth_prefix ( self ) :
  if ( len ( self . delegation_set ) != 0 ) : return ( False )
  if ( self . is_star_g ( ) ) : return ( False )
  return ( True )
  if 44 - 44: O0 - I11i
  if 43 - 43: O0
 def is_ms_peer_entry ( self ) :
  if ( len ( self . delegation_set ) == 0 ) : return ( False )
  return ( self . delegation_set [ 0 ] . is_ms_peer ( ) )
  if 50 - 50: I11i - OoooooooOO
  if 29 - 29: oO0o * oO0o
 def print_referral_type ( self ) :
  if ( len ( self . delegation_set ) == 0 ) : return ( "unknown" )
  I1 = self . delegation_set [ 0 ]
  return ( I1 . print_node_type ( ) )
  if 93 - 93: oO0o * Ii1I
  if 41 - 41: i1IIi % i11iIiiIii + I11i % OoooooooOO / I1ii11iIi11i
 def print_eid_tuple ( self ) :
  return ( lisp_print_eid_tuple ( self . eid , self . group ) )
  if 8 - 8: OoooooooOO - OoO0O00 / i11iIiiIii / O0 . IiII
  if 86 - 86: ooOoO0o * OoooooooOO + iII111i + o0oOOo0O0Ooo
 def add_cache ( self ) :
  if ( self . group . is_null ( ) ) :
   lisp_ddt_cache . add_cache ( self . eid , self )
  else :
   OoOO0OOoOoO = lisp_ddt_cache . lookup_cache ( self . group , True )
   if ( OoOO0OOoOoO == None ) :
    OoOO0OOoOoO = lisp_ddt_entry ( )
    OoOO0OOoOoO . eid . copy_address ( self . group )
    OoOO0OOoOoO . group . copy_address ( self . group )
    lisp_ddt_cache . add_cache ( self . group , OoOO0OOoOoO )
    if 2 - 2: O0 . OoO0O00 % oO0o - iII111i . i11iIiiIii - II111iiii
   if ( self . eid . is_null ( ) ) : self . eid . make_default_route ( OoOO0OOoOoO . group )
   OoOO0OOoOoO . add_source_entry ( self )
   if 93 - 93: IiII . OoOoOO00 % Ii1I - i1IIi . iIii1I11I1II1 / I1Ii111
   if 75 - 75: II111iiii / oO0o
   if 26 - 26: I11i - i1IIi % OOooOOo - OoooooooOO
 def add_source_entry ( self , source_ddt ) :
  if ( self . source_cache == None ) : self . source_cache = lisp_cache ( )
  self . source_cache . add_cache ( source_ddt . eid , source_ddt )
  if 23 - 23: OoOoOO00 + I1Ii111 * OoO0O00
  if 22 - 22: OoO0O00
 def lookup_source_cache ( self , source , exact ) :
  if ( self . source_cache == None ) : return ( None )
  return ( self . source_cache . lookup_cache ( source , exact ) )
  if 28 - 28: OoO0O00 + IiII % Oo0Ooo
  if 95 - 95: i11iIiiIii / I1Ii111 - I1Ii111
 def is_star_g ( self ) :
  if ( self . group . is_null ( ) ) : return ( False )
  return ( self . eid . is_exact_match ( self . group ) )
  if 61 - 61: OoOoOO00 / Oo0Ooo % II111iiii / II111iiii / o0oOOo0O0Ooo
  if 34 - 34: OoO0O00 * II111iiii + i11iIiiIii % Ii1I
  if 25 - 25: OoOoOO00 + IiII . i11iIiiIii
class lisp_ddt_node ( ) :
 def __init__ ( self ) :
  self . delegate_address = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . public_key = ""
  self . map_server_peer = False
  self . map_server_child = False
  self . priority = 0
  self . weight = 0
  if 87 - 87: I1IiiI + OoooooooOO + O0
  if 32 - 32: Ii1I / I1ii11iIi11i . Ii1I
 def print_node_type ( self ) :
  if ( self . is_ddt_child ( ) ) : return ( "ddt-child" )
  if ( self . is_ms_child ( ) ) : return ( "map-server-child" )
  if ( self . is_ms_peer ( ) ) : return ( "map-server-peer" )
  if 65 - 65: IiII
  if 74 - 74: Oo0Ooo + i1IIi - II111iiii / ooOoO0o / iII111i
 def is_ddt_child ( self ) :
  if ( self . map_server_child ) : return ( False )
  if ( self . map_server_peer ) : return ( False )
  return ( True )
  if 66 - 66: ooOoO0o / IiII * iIii1I11I1II1
  if 42 - 42: I1Ii111 - i11iIiiIii % II111iiii * ooOoO0o . O0 % I11i
 def is_ms_child ( self ) :
  return ( self . map_server_child )
  if 82 - 82: Oo0Ooo % O0 + I1ii11iIi11i % I1ii11iIi11i
  if 74 - 74: O0 * IiII . I11i - I1Ii111 + O0 + I11i
 def is_ms_peer ( self ) :
  return ( self . map_server_peer )
  if 48 - 48: oO0o . o0oOOo0O0Ooo - OOooOOo
  if 29 - 29: Oo0Ooo - Ii1I - Oo0Ooo
  if 89 - 89: Oo0Ooo . OoO0O00 . I1ii11iIi11i * oO0o . O0
  if 72 - 72: i11iIiiIii % I11i / I1Ii111 + I1IiiI * iII111i
  if 69 - 69: I1Ii111 + O0 . IiII . o0oOOo0O0Ooo
  if 38 - 38: IiII / i1IIi
  if 60 - 60: OoOoOO00
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
  if 75 - 75: II111iiii / iIii1I11I1II1 / OoooooooOO
  if 61 - 61: IiII . IiII
 def print_ddt_map_request ( self ) :
  lprint ( "Queued Map-Request from {}ITR {}->{}, nonce 0x{}" . format ( "P" if self . from_pitr else "" ,
  # I11i
 red ( self . itr . print_address ( ) , False ) ,
 green ( self . eid . print_address ( ) , False ) , self . nonce ) )
  if 79 - 79: Oo0Ooo / I1Ii111 . OOooOOo
  if 76 - 76: IiII / I1IiiI + i1IIi
 def queue_map_request ( self ) :
  self . retransmit_timer = threading . Timer ( LISP_DDT_MAP_REQUEST_INTERVAL ,
 lisp_retransmit_ddt_map_request , [ self ] )
  self . retransmit_timer . start ( )
  lisp_ddt_map_requestQ [ str ( self . nonce ) ] = self
  if 97 - 97: OOooOOo . Oo0Ooo . II111iiii + OoO0O00 * iII111i / I1IiiI
  if 96 - 96: Oo0Ooo % iIii1I11I1II1 / I1IiiI - iII111i * I1ii11iIi11i . I1IiiI
 def dequeue_map_request ( self ) :
  self . retransmit_timer . cancel ( )
  if ( lisp_ddt_map_requestQ . has_key ( str ( self . nonce ) ) ) :
   lisp_ddt_map_requestQ . pop ( str ( self . nonce ) )
   if 89 - 89: OoooooooOO . ooOoO0o * iII111i / ooOoO0o * iIii1I11I1II1
   if 47 - 47: o0oOOo0O0Ooo / O0 * o0oOOo0O0Ooo / O0 * IiII
   if 77 - 77: ooOoO0o * II111iiii . II111iiii + ooOoO0o % OoooooooOO
 def print_eid_tuple ( self ) :
  return ( lisp_print_eid_tuple ( self . eid , self . group ) )
  if 92 - 92: oO0o
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
LISP_DDT_ACTION_SITE_NOT_FOUND = - 2
LISP_DDT_ACTION_NULL = - 1
LISP_DDT_ACTION_NODE_REFERRAL = 0
LISP_DDT_ACTION_MS_REFERRAL = 1
LISP_DDT_ACTION_MS_ACK = 2
LISP_DDT_ACTION_MS_NOT_REG = 3
LISP_DDT_ACTION_DELEGATION_HOLE = 4
LISP_DDT_ACTION_NOT_AUTH = 5
LISP_DDT_ACTION_MAX = LISP_DDT_ACTION_NOT_AUTH
if 34 - 34: i1IIi % Oo0Ooo . oO0o
lisp_map_referral_action_string = [
 "node-referral" , "ms-referral" , "ms-ack" , "ms-not-registered" ,
 "delegation-hole" , "not-authoritative" ]
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
if 44 - 44: iII111i * I11i + i11iIiiIii + i1IIi / IiII * II111iiii
if 58 - 58: OOooOOo
if 72 - 72: OoO0O00 + OOooOOo - Oo0Ooo % ooOoO0o . IiII
if 95 - 95: iII111i % OOooOOo - IiII - OoOoOO00 % o0oOOo0O0Ooo * O0
if 16 - 16: I1Ii111 / Oo0Ooo
if 48 - 48: Oo0Ooo / oO0o + iII111i % iII111i
if 9 - 9: I1ii11iIi11i - o0oOOo0O0Ooo . Oo0Ooo + I1ii11iIi11i . OOooOOo
if 30 - 30: OoooooooOO - iIii1I11I1II1 / oO0o * Ii1I / Ii1I
if 52 - 52: OoOoOO00 - OoO0O00 + I1IiiI + IiII
if 49 - 49: oO0o / I11i - oO0o
if 31 - 31: OoOoOO00 + I1IiiI + I1ii11iIi11i + I11i * II111iiii % oO0o
if 90 - 90: OOooOOo * iIii1I11I1II1 / i1IIi
if 60 - 60: OOooOOo * I1Ii111 . oO0o
if 47 - 47: oO0o % OOooOOo / OOooOOo % OoOoOO00 % I1Ii111 / OoOoOO00
if 51 - 51: I1IiiI . I11i - OoOoOO00
if 10 - 10: Oo0Ooo * OOooOOo / IiII . o0oOOo0O0Ooo
if 97 - 97: Ii1I . Ii1I % iII111i
if 49 - 49: Oo0Ooo % OOooOOo - OoooooooOO + IiII
if 54 - 54: iIii1I11I1II1 - OoooooooOO / I11i / oO0o % I1IiiI + OoOoOO00
if 26 - 26: OoO0O00 * II111iiii % OOooOOo * iII111i + iII111i
if 25 - 25: I11i - I1ii11iIi11i
if 100 - 100: I1Ii111 / Ii1I + OoOoOO00 . OoooooooOO
if 83 - 83: O0
if 35 - 35: i11iIiiIii - I11i . OoOoOO00 * II111iiii % i11iIiiIii
if 55 - 55: o0oOOo0O0Ooo / O0 / OoooooooOO * Oo0Ooo % iII111i
if 24 - 24: I1ii11iIi11i % OOooOOo + OoooooooOO + OoO0O00
if 100 - 100: Oo0Ooo % OoO0O00 - OoOoOO00
if 46 - 46: o0oOOo0O0Ooo
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
  if 28 - 28: i1IIi
  if 81 - 81: oO0o % OoooooooOO . I1Ii111 - OoOoOO00 / I1IiiI
 def print_info ( self ) :
  if ( self . info_reply ) :
   o0o00O000o0o = "Info-Reply"
   o0OOooooooOO = ( ", ms-port: {}, etr-port: {}, global-rloc: {}, " + "ms-rloc: {}, private-rloc: {}, RTR-list: " ) . format ( self . ms_port , self . etr_port ,
   # OOooOOo * I1Ii111 - i1IIi % oO0o + iII111i
   # iII111i . ooOoO0o - I1Ii111 + OOooOOo
 red ( self . global_etr_rloc . print_address_no_iid ( ) , False ) ,
 red ( self . global_ms_rloc . print_address_no_iid ( ) , False ) ,
 red ( self . private_etr_rloc . print_address_no_iid ( ) , False ) )
   if ( len ( self . rtr_list ) == 0 ) : o0OOooooooOO += "empty, "
   for I111iI1I1i1 in self . rtr_list :
    o0OOooooooOO += red ( I111iI1I1i1 . print_address_no_iid ( ) , False ) + ", "
    if 68 - 68: OoooooooOO % OOooOOo / OoooooooOO / I1Ii111 + Ii1I - o0oOOo0O0Ooo
   o0OOooooooOO = o0OOooooooOO [ 0 : - 2 ]
  else :
   o0o00O000o0o = "Info-Request"
   oOo00 = "<none>" if self . hostname == None else self . hostname
   o0OOooooooOO = ", hostname: {}" . format ( blue ( oOo00 , False ) )
   if 46 - 46: Oo0Ooo - Oo0Ooo
  lprint ( "{} -> nonce: 0x{}{}" . format ( bold ( o0o00O000o0o , False ) ,
 lisp_hex_string ( self . nonce ) , o0OOooooooOO ) )
  if 22 - 22: II111iiii % iIii1I11I1II1 * O0
  if 78 - 78: I1Ii111 * i1IIi + OoooooooOO * ooOoO0o
 def encode ( self ) :
  iiii1ii1 = ( LISP_NAT_INFO << 28 )
  if ( self . info_reply ) : iiii1ii1 |= ( 1 << 27 )
  if 69 - 69: i1IIi
  if 83 - 83: I1ii11iIi11i . ooOoO0o + I1IiiI + O0
  if 78 - 78: O0 + Oo0Ooo
  if 14 - 14: O0
  if 67 - 67: II111iiii / O0
  Oo0O0oo = struct . pack ( "I" , socket . htonl ( iiii1ii1 ) )
  Oo0O0oo += struct . pack ( "Q" , self . nonce )
  Oo0O0oo += struct . pack ( "III" , 0 , 0 , 0 )
  if 10 - 10: i1IIi / Oo0Ooo
  if 20 - 20: Oo0Ooo * I1Ii111 / I1ii11iIi11i . ooOoO0o
  if 67 - 67: o0oOOo0O0Ooo . Oo0Ooo % I11i
  if 38 - 38: OOooOOo - OoO0O00 . ooOoO0o
  if ( self . info_reply == False ) :
   if ( self . hostname == None ) :
    Oo0O0oo += struct . pack ( "H" , 0 )
   else :
    Oo0O0oo += struct . pack ( "H" , socket . htons ( LISP_AFI_NAME ) )
    Oo0O0oo += self . hostname + "\0"
    if 50 - 50: o0oOOo0O0Ooo
   return ( Oo0O0oo )
   if 85 - 85: II111iiii . iII111i - i1IIi
   if 23 - 23: iII111i . Ii1I - OoO0O00 / I1ii11iIi11i / O0
   if 4 - 4: i1IIi % Oo0Ooo % Ii1I * ooOoO0o - I11i
   if 76 - 76: iIii1I11I1II1 / ooOoO0o % I1ii11iIi11i % OOooOOo
   if 13 - 13: IiII
  I1I1i = socket . htons ( LISP_AFI_LCAF )
  o0oOoOOO = LISP_LCAF_NAT_TYPE
  i1IiI = socket . htons ( 16 )
  oOOOoo = socket . htons ( self . ms_port )
  iIIIIIiiI11IIIii1 = socket . htons ( self . etr_port )
  Oo0O0oo += struct . pack ( "HHBBHHHH" , I1I1i , 0 , o0oOoOOO , 0 , i1IiI ,
 oOOOoo , iIIIIIiiI11IIIii1 , socket . htons ( self . global_etr_rloc . afi ) )
  Oo0O0oo += self . global_etr_rloc . pack_address ( )
  Oo0O0oo += struct . pack ( "HH" , 0 , socket . htons ( self . private_etr_rloc . afi ) )
  Oo0O0oo += self . private_etr_rloc . pack_address ( )
  if ( len ( self . rtr_list ) == 0 ) : Oo0O0oo += struct . pack ( "H" , 0 )
  if 93 - 93: Oo0Ooo % i1IIi
  if 51 - 51: oO0o % O0
  if 41 - 41: I1IiiI * I1IiiI . I1Ii111
  if 38 - 38: I1IiiI % i11iIiiIii
  for I111iI1I1i1 in self . rtr_list :
   Oo0O0oo += struct . pack ( "H" , socket . htons ( I111iI1I1i1 . afi ) )
   Oo0O0oo += I111iI1I1i1 . pack_address ( )
   if 17 - 17: i11iIiiIii
  return ( Oo0O0oo )
  if 81 - 81: I1Ii111
  if 25 - 25: I1IiiI
 def decode ( self , packet ) :
  oOoo0O000 = packet
  OoOo0Oooo0o = "I"
  o0OOo0OOoOO0 = struct . calcsize ( OoOo0Oooo0o )
  if ( len ( packet ) < o0OOo0OOoOO0 ) : return ( None )
  if 52 - 52: I1ii11iIi11i % i1IIi . IiII % OoOoOO00
  iiii1ii1 = struct . unpack ( OoOo0Oooo0o , packet [ : o0OOo0OOoOO0 ] )
  iiii1ii1 = iiii1ii1 [ 0 ]
  packet = packet [ o0OOo0OOoOO0 : : ]
  if 50 - 50: OOooOOo * I1IiiI / o0oOOo0O0Ooo
  OoOo0Oooo0o = "Q"
  o0OOo0OOoOO0 = struct . calcsize ( OoOo0Oooo0o )
  if ( len ( packet ) < o0OOo0OOoOO0 ) : return ( None )
  if 91 - 91: iIii1I11I1II1 / OOooOOo * O0 . o0oOOo0O0Ooo + oO0o / I1ii11iIi11i
  Iii1i11 = struct . unpack ( OoOo0Oooo0o , packet [ : o0OOo0OOoOO0 ] )
  if 33 - 33: II111iiii + Ii1I
  iiii1ii1 = socket . ntohl ( iiii1ii1 )
  self . nonce = Iii1i11 [ 0 ]
  self . info_reply = iiii1ii1 & 0x08000000
  self . hostname = None
  packet = packet [ o0OOo0OOoOO0 : : ]
  if 46 - 46: IiII + O0 + i1IIi + ooOoO0o / iII111i
  if 94 - 94: oO0o + iII111i * OoOoOO00 - i1IIi / OoooooooOO
  if 59 - 59: I11i % Ii1I / OoOoOO00
  if 99 - 99: Ii1I + II111iiii / i11iIiiIii - IiII / iII111i + iII111i
  if 55 - 55: IiII + OoooooooOO * I1ii11iIi11i . IiII * I1ii11iIi11i + IiII
  OoOo0Oooo0o = "HH"
  o0OOo0OOoOO0 = struct . calcsize ( OoOo0Oooo0o )
  if ( len ( packet ) < o0OOo0OOoOO0 ) : return ( None )
  if 81 - 81: iIii1I11I1II1 . ooOoO0o + OoOoOO00
  if 31 - 31: I11i / OoOoOO00 + o0oOOo0O0Ooo
  if 80 - 80: Oo0Ooo
  if 58 - 58: I1Ii111 + OOooOOo
  if 76 - 76: II111iiii - o0oOOo0O0Ooo % OoO0O00 + iII111i
  OOo0 , O0ooo00o0 = struct . unpack ( OoOo0Oooo0o , packet [ : o0OOo0OOoOO0 ] )
  if ( O0ooo00o0 != 0 ) : return ( None )
  if 38 - 38: I1Ii111 - I11i * i1IIi + iIii1I11I1II1
  packet = packet [ o0OOo0OOoOO0 : : ]
  OoOo0Oooo0o = "IBBH"
  o0OOo0OOoOO0 = struct . calcsize ( OoOo0Oooo0o )
  if ( len ( packet ) < o0OOo0OOoOO0 ) : return ( None )
  if 41 - 41: Ii1I . OoO0O00 + I1ii11iIi11i + OoOoOO00
  I1i , O000OOOoOooO , o0ooOo00 , I11oOo0O0Oo = struct . unpack ( OoOo0Oooo0o ,
 packet [ : o0OOo0OOoOO0 ] )
  if 21 - 21: Ii1I % O0
  if ( I11oOo0O0Oo != 0 ) : return ( None )
  packet = packet [ o0OOo0OOoOO0 : : ]
  if 15 - 15: II111iiii * Ii1I + IiII % iII111i
  if 96 - 96: II111iiii * I1Ii111 / Oo0Ooo
  if 35 - 35: I1IiiI
  if 54 - 54: I1ii11iIi11i % o0oOOo0O0Ooo . i1IIi
  if ( self . info_reply == False ) :
   OoOo0Oooo0o = "H"
   o0OOo0OOoOO0 = struct . calcsize ( OoOo0Oooo0o )
   if ( len ( packet ) >= o0OOo0OOoOO0 ) :
    I1I1i = struct . unpack ( OoOo0Oooo0o , packet [ : o0OOo0OOoOO0 ] ) [ 0 ]
    if ( socket . ntohs ( I1I1i ) == LISP_AFI_NAME ) :
     packet = packet [ o0OOo0OOoOO0 : : ]
     packet , self . hostname = lisp_decode_dist_name ( packet )
     if 72 - 72: Ii1I
     if 87 - 87: iII111i - I1IiiI
   return ( oOoo0O000 )
   if 54 - 54: iIii1I11I1II1 + oO0o * o0oOOo0O0Ooo % OoooooooOO . Oo0Ooo
   if 32 - 32: iII111i
   if 33 - 33: ooOoO0o + Oo0Ooo * OoOoOO00 % ooOoO0o * oO0o - OoO0O00
   if 40 - 40: I11i . OoooooooOO * O0 / I1Ii111 + O0
   if 97 - 97: ooOoO0o - ooOoO0o * OOooOOo % OoOoOO00 - OoOoOO00 - I1Ii111
  OoOo0Oooo0o = "HHBBHHH"
  o0OOo0OOoOO0 = struct . calcsize ( OoOo0Oooo0o )
  if ( len ( packet ) < o0OOo0OOoOO0 ) : return ( None )
  if 52 - 52: O0 % iII111i
  I1I1i , IiIIi , o0oOoOOO , O000OOOoOooO , i1IiI , oOOOoo , iIIIIIiiI11IIIii1 = struct . unpack ( OoOo0Oooo0o , packet [ : o0OOo0OOoOO0 ] )
  if 81 - 81: OoooooooOO % OoOoOO00 % Oo0Ooo - I1IiiI
  if 43 - 43: o0oOOo0O0Ooo % o0oOOo0O0Ooo
  if ( socket . ntohs ( I1I1i ) != LISP_AFI_LCAF ) : return ( None )
  if 48 - 48: O0
  self . ms_port = socket . ntohs ( oOOOoo )
  self . etr_port = socket . ntohs ( iIIIIIiiI11IIIii1 )
  packet = packet [ o0OOo0OOoOO0 : : ]
  if 5 - 5: OOooOOo / i11iIiiIii . I11i % OOooOOo
  if 1 - 1: II111iiii + O0 * OoOoOO00 / IiII . O0
  if 87 - 87: IiII + I1IiiI
  if 74 - 74: OoO0O00 + OoO0O00 % iII111i / I11i / O0
  OoOo0Oooo0o = "H"
  o0OOo0OOoOO0 = struct . calcsize ( OoOo0Oooo0o )
  if ( len ( packet ) < o0OOo0OOoOO0 ) : return ( None )
  if 54 - 54: o0oOOo0O0Ooo / OoooooooOO * ooOoO0o . OoOoOO00 - I1Ii111
  if 69 - 69: oO0o - OoO0O00
  if 80 - 80: ooOoO0o + iIii1I11I1II1 . II111iiii + I1IiiI - oO0o % OoOoOO00
  if 10 - 10: iIii1I11I1II1
  I1I1i = struct . unpack ( OoOo0Oooo0o , packet [ : o0OOo0OOoOO0 ] ) [ 0 ]
  packet = packet [ o0OOo0OOoOO0 : : ]
  if ( I1I1i != 0 ) :
   self . global_etr_rloc . afi = socket . ntohs ( I1I1i )
   packet = self . global_etr_rloc . unpack_address ( packet )
   if ( packet == None ) : return ( None )
   self . global_etr_rloc . mask_len = self . global_etr_rloc . host_mask_len ( )
   if 44 - 44: OoOoOO00 * oO0o . I1ii11iIi11i + i11iIiiIii
   if 85 - 85: I11i
   if 36 - 36: ooOoO0o % OoO0O00
   if 1 - 1: OoooooooOO - OoOoOO00
   if 35 - 35: I1Ii111
   if 35 - 35: Oo0Ooo - iIii1I11I1II1 / i1IIi + OoO0O00 - OoooooooOO / i11iIiiIii
  if ( len ( packet ) < o0OOo0OOoOO0 ) : return ( oOoo0O000 )
  if 79 - 79: I1IiiI * ooOoO0o * ooOoO0o
  I1I1i = struct . unpack ( OoOo0Oooo0o , packet [ : o0OOo0OOoOO0 ] ) [ 0 ]
  packet = packet [ o0OOo0OOoOO0 : : ]
  if ( I1I1i != 0 ) :
   self . global_ms_rloc . afi = socket . ntohs ( I1I1i )
   packet = self . global_ms_rloc . unpack_address ( packet )
   if ( packet == None ) : return ( oOoo0O000 )
   self . global_ms_rloc . mask_len = self . global_ms_rloc . host_mask_len ( )
   if 92 - 92: iII111i % I1ii11iIi11i
   if 16 - 16: oO0o
   if 52 - 52: OoooooooOO % ooOoO0o - I1Ii111 * I11i
   if 24 - 24: Ii1I + IiII + OoooooooOO / oO0o / I1IiiI + IiII
   if 52 - 52: ooOoO0o
  if ( len ( packet ) < o0OOo0OOoOO0 ) : return ( oOoo0O000 )
  if 38 - 38: OoO0O00 + I1IiiI % IiII
  I1I1i = struct . unpack ( OoOo0Oooo0o , packet [ : o0OOo0OOoOO0 ] ) [ 0 ]
  packet = packet [ o0OOo0OOoOO0 : : ]
  if ( I1I1i != 0 ) :
   self . private_etr_rloc . afi = socket . ntohs ( I1I1i )
   packet = self . private_etr_rloc . unpack_address ( packet )
   if ( packet == None ) : return ( oOoo0O000 )
   self . private_etr_rloc . mask_len = self . private_etr_rloc . host_mask_len ( )
   if 87 - 87: oO0o * Ii1I - I1Ii111 / oO0o
   if 65 - 65: OoOoOO00
   if 87 - 87: I11i - i11iIiiIii - OOooOOo . OoOoOO00 + IiII . OoO0O00
   if 70 - 70: iIii1I11I1II1 % OoooooooOO / OoO0O00 . O0 - I11i % II111iiii
   if 84 - 84: OOooOOo * i1IIi . iIii1I11I1II1 * iII111i + I1Ii111 + II111iiii
   if 97 - 97: Ii1I - IiII
  while ( len ( packet ) >= o0OOo0OOoOO0 ) :
   I1I1i = struct . unpack ( OoOo0Oooo0o , packet [ : o0OOo0OOoOO0 ] ) [ 0 ]
   packet = packet [ o0OOo0OOoOO0 : : ]
   if ( I1I1i == 0 ) : continue
   I111iI1I1i1 = lisp_address ( socket . ntohs ( I1I1i ) , "" , 0 , 0 )
   packet = I111iI1I1i1 . unpack_address ( packet )
   if ( packet == None ) : return ( oOoo0O000 )
   I111iI1I1i1 . mask_len = I111iI1I1i1 . host_mask_len ( )
   self . rtr_list . append ( I111iI1I1i1 )
   if 64 - 64: oO0o . ooOoO0o / ooOoO0o - II111iiii
  return ( oOoo0O000 )
  if 81 - 81: I1ii11iIi11i
  if 64 - 64: oO0o * OoO0O00 / OOooOOo + Ii1I % Oo0Ooo . IiII
  if 2 - 2: I1Ii111 + I11i
class lisp_nat_info ( ) :
 def __init__ ( self , addr_str , hostname , port ) :
  self . address = addr_str
  self . hostname = hostname
  self . port = port
  self . uptime = lisp_get_timestamp ( )
  if 47 - 47: i11iIiiIii + iIii1I11I1II1 % I1ii11iIi11i - oO0o % OoO0O00
  if 85 - 85: oO0o * OoOoOO00 / OoOoOO00
 def timed_out ( self ) :
  ooOO0o = time . time ( ) - self . uptime
  return ( ooOO0o >= ( LISP_INFO_INTERVAL * 2 ) )
  if 85 - 85: OOooOOo / I1Ii111 . i1IIi / OoOoOO00 + iIii1I11I1II1
  if 71 - 71: OoO0O00
  if 96 - 96: I1ii11iIi11i / I1IiiI - I1ii11iIi11i / II111iiii - IiII
class lisp_info_source ( ) :
 def __init__ ( self , hostname , addr_str , port ) :
  self . address = lisp_address ( LISP_AFI_IPV4 , addr_str , 32 , 0 )
  self . port = port
  self . uptime = lisp_get_timestamp ( )
  self . nonce = None
  self . hostname = hostname
  self . no_timeout = False
  if 74 - 74: Ii1I * OoooooooOO % OOooOOo + OoooooooOO + iII111i
  if 83 - 83: i1IIi
 def cache_address_for_info_source ( self ) :
  i1iI11iI = self . address . print_address_no_iid ( ) + self . hostname
  lisp_info_sources_by_address [ i1iI11iI ] = self
  if 2 - 2: i1IIi / OOooOOo * O0
  if 99 - 99: OoooooooOO . OoOoOO00 / II111iiii
 def cache_nonce_for_info_source ( self , nonce ) :
  self . nonce = nonce
  lisp_info_sources_by_nonce [ nonce ] = self
  if 64 - 64: iII111i / i1IIi . I1IiiI + O0
  if 5 - 5: O0 . i11iIiiIii
  if 71 - 71: o0oOOo0O0Ooo + iII111i + ooOoO0o
  if 27 - 27: OoooooooOO . iII111i * I1Ii111 % O0 + OoooooooOO - iII111i
  if 86 - 86: i1IIi
  if 81 - 81: OoOoOO00
  if 52 - 52: iII111i * IiII % I1IiiI * I11i
  if 73 - 73: I1Ii111 * ooOoO0o
  if 62 - 62: OOooOOo . I1IiiI * iIii1I11I1II1 + OoO0O00 * ooOoO0o / oO0o
  if 14 - 14: iII111i / OoO0O00
  if 75 - 75: IiII
def lisp_concat_auth_data ( alg_id , auth1 , auth2 , auth3 , auth4 ) :
 if 68 - 68: IiII - i1IIi % IiII . OoO0O00 . i11iIiiIii . OoooooooOO
 if ( lisp_is_x86 ( ) ) :
  if ( auth1 != "" ) : auth1 = byte_swap_64 ( auth1 )
  if ( auth2 != "" ) : auth2 = byte_swap_64 ( auth2 )
  if ( auth3 != "" ) :
   if ( alg_id == LISP_SHA_1_96_ALG_ID ) : auth3 = socket . ntohl ( auth3 )
   else : auth3 = byte_swap_64 ( auth3 )
   if 32 - 32: iII111i + OoO0O00 % IiII + I1IiiI
  if ( auth4 != "" ) : auth4 = byte_swap_64 ( auth4 )
  if 69 - 69: I1Ii111 + I11i - iIii1I11I1II1 - II111iiii . Ii1I
  if 74 - 74: I1ii11iIi11i % o0oOOo0O0Ooo + O0 - i11iIiiIii - IiII % OOooOOo
 if ( alg_id == LISP_SHA_1_96_ALG_ID ) :
  auth1 = lisp_hex_string ( auth1 )
  auth1 = auth1 . zfill ( 16 )
  auth2 = lisp_hex_string ( auth2 )
  auth2 = auth2 . zfill ( 16 )
  auth3 = lisp_hex_string ( auth3 )
  auth3 = auth3 . zfill ( 8 )
  O0oO0 = auth1 + auth2 + auth3
  if 39 - 39: OoO0O00 - o0oOOo0O0Ooo
 if ( alg_id == LISP_SHA_256_128_ALG_ID ) :
  auth1 = lisp_hex_string ( auth1 )
  auth1 = auth1 . zfill ( 16 )
  auth2 = lisp_hex_string ( auth2 )
  auth2 = auth2 . zfill ( 16 )
  auth3 = lisp_hex_string ( auth3 )
  auth3 = auth3 . zfill ( 16 )
  auth4 = lisp_hex_string ( auth4 )
  auth4 = auth4 . zfill ( 16 )
  O0oO0 = auth1 + auth2 + auth3 + auth4
  if 71 - 71: iII111i . OoO0O00 + ooOoO0o - OOooOOo - Oo0Ooo
 return ( O0oO0 )
 if 100 - 100: OoooooooOO - o0oOOo0O0Ooo + I1Ii111 . OoooooooOO % i11iIiiIii
 if 64 - 64: I1Ii111 % OoooooooOO / i1IIi / OoO0O00
 if 2 - 2: I11i % o0oOOo0O0Ooo . OoO0O00 . OoO0O00
 if 89 - 89: ooOoO0o - oO0o + II111iiii + OoO0O00 - IiII
 if 27 - 27: I1Ii111 - o0oOOo0O0Ooo + OoO0O00
 if 38 - 38: OoOoOO00 + OoO0O00 . i11iIiiIii + Ii1I % i1IIi % I1IiiI
 if 93 - 93: i11iIiiIii
 if 63 - 63: iIii1I11I1II1 - iIii1I11I1II1 % o0oOOo0O0Ooo
 if 97 - 97: i1IIi % I11i % OoOoOO00
 if 25 - 25: OoOoOO00 . iIii1I11I1II1 - iII111i % II111iiii . OoOoOO00
def lisp_open_listen_socket ( local_addr , port ) :
 if ( port . isdigit ( ) ) :
  if ( local_addr . find ( "." ) != - 1 ) :
   IIiIiiIIi = socket . socket ( socket . AF_INET , socket . SOCK_DGRAM )
   if 100 - 100: I1ii11iIi11i - i1IIi - OoO0O00 * o0oOOo0O0Ooo + OoOoOO00
  if ( local_addr . find ( ":" ) != - 1 ) :
   if ( lisp_is_raspbian ( ) ) : return ( None )
   IIiIiiIIi = socket . socket ( socket . AF_INET6 , socket . SOCK_DGRAM )
   if 31 - 31: i1IIi
  IIiIiiIIi . bind ( ( local_addr , int ( port ) ) )
 else :
  I1i1iI1II = port
  if ( os . path . exists ( I1i1iI1II ) ) :
   os . system ( "rm " + I1i1iI1II )
   time . sleep ( 1 )
   if 21 - 21: o0oOOo0O0Ooo / O0 % O0 . OoooooooOO / I1IiiI
  IIiIiiIIi = socket . socket ( socket . AF_UNIX , socket . SOCK_DGRAM )
  IIiIiiIIi . bind ( I1i1iI1II )
  if 94 - 94: ooOoO0o + OoO0O00 / ooOoO0o - ooOoO0o + Oo0Ooo + o0oOOo0O0Ooo
 return ( IIiIiiIIi )
 if 50 - 50: oO0o . Oo0Ooo
 if 15 - 15: Ii1I
 if 64 - 64: OoooooooOO
 if 25 - 25: IiII
 if 29 - 29: OoOoOO00 % ooOoO0o * OoooooooOO
 if 8 - 8: i11iIiiIii - I1Ii111 / IiII
 if 17 - 17: i11iIiiIii * OoO0O00 . o0oOOo0O0Ooo . OoooooooOO . OoOoOO00 - I1ii11iIi11i
def lisp_open_send_socket ( internal_name , afi ) :
 if ( internal_name == "" ) :
  if ( afi == LISP_AFI_IPV4 ) :
   IIiIiiIIi = socket . socket ( socket . AF_INET , socket . SOCK_DGRAM )
   if 78 - 78: I1ii11iIi11i - OoooooooOO + O0
  if ( afi == LISP_AFI_IPV6 ) :
   if ( lisp_is_raspbian ( ) ) : return ( None )
   IIiIiiIIi = socket . socket ( socket . AF_INET6 , socket . SOCK_DGRAM )
   if 15 - 15: I1ii11iIi11i / IiII % I1IiiI
 else :
  if ( os . path . exists ( internal_name ) ) : os . system ( "rm " + internal_name )
  IIiIiiIIi = socket . socket ( socket . AF_UNIX , socket . SOCK_DGRAM )
  IIiIiiIIi . bind ( internal_name )
  if 16 - 16: Ii1I
 return ( IIiIiiIIi )
 if 26 - 26: o0oOOo0O0Ooo / I11i + OoOoOO00 / OoOoOO00
 if 31 - 31: I1Ii111
 if 84 - 84: i11iIiiIii * OOooOOo . iII111i - Ii1I * i1IIi - I1ii11iIi11i
 if 1 - 1: II111iiii
 if 94 - 94: I1ii11iIi11i * iII111i % iII111i % I11i - iII111i
 if 38 - 38: IiII - OoO0O00 % Ii1I - II111iiii
 if 97 - 97: O0 . Ii1I
def lisp_close_socket ( sock , internal_name ) :
 sock . close ( )
 if ( os . path . exists ( internal_name ) ) : os . system ( "rm " + internal_name )
 return
 if 52 - 52: IiII
 if 86 - 86: I1Ii111 / O0 + OoooooooOO % oO0o
 if 45 - 45: I1IiiI . Oo0Ooo . I11i . Ii1I
 if 81 - 81: II111iiii + OoOoOO00 % i11iIiiIii / iII111i . I1Ii111 + II111iiii
 if 48 - 48: I1IiiI . I1ii11iIi11i * OoOoOO00 % i1IIi / I1Ii111 * II111iiii
 if 62 - 62: o0oOOo0O0Ooo * I1Ii111 . iIii1I11I1II1 / i1IIi
 if 75 - 75: OoooooooOO / ooOoO0o - iII111i . OoooooooOO . OoOoOO00 % i1IIi
 if 7 - 7: OoOoOO00 . i1IIi * i11iIiiIii % i11iIiiIii
def lisp_is_running ( node ) :
 return ( True if ( os . path . exists ( node ) ) else False )
 if 54 - 54: OoO0O00 / I1IiiI . Oo0Ooo
 if 39 - 39: OoO0O00 . ooOoO0o
 if 41 - 41: Oo0Ooo * I1ii11iIi11i - II111iiii - II111iiii
 if 7 - 7: oO0o
 if 41 - 41: ooOoO0o
 if 93 - 93: Ii1I + I1Ii111 + Ii1I
 if 23 - 23: I1IiiI - i1IIi / ooOoO0o
 if 4 - 4: IiII . I1ii11iIi11i + iII111i % ooOoO0o
 if 28 - 28: I1Ii111
def lisp_packet_ipc ( packet , source , sport ) :
 return ( ( "packet@" + str ( len ( packet ) ) + "@" + source + "@" + str ( sport ) + "@" + packet ) )
 if 27 - 27: iII111i * I1IiiI
 if 60 - 60: i1IIi / I1IiiI - I1ii11iIi11i
 if 41 - 41: I1Ii111 + ooOoO0o / OOooOOo + I11i % Oo0Ooo
 if 91 - 91: I1IiiI % I1ii11iIi11i % oO0o / i1IIi * iIii1I11I1II1 + I11i
 if 48 - 48: ooOoO0o / I1ii11iIi11i / OoO0O00 / II111iiii * OoOoOO00
 if 73 - 73: I11i / I1IiiI - IiII - i1IIi * IiII - OOooOOo
 if 39 - 39: I11i . ooOoO0o * II111iiii
 if 21 - 21: Ii1I
 if 92 - 92: OoO0O00 * I1ii11iIi11i + iIii1I11I1II1
def lisp_control_packet_ipc ( packet , source , dest , dport ) :
 return ( "control-packet@" + dest + "@" + str ( dport ) + "@" + packet )
 if 88 - 88: iIii1I11I1II1 + iIii1I11I1II1 * i11iIiiIii . I1ii11iIi11i % oO0o
 if 94 - 94: I1IiiI / I1ii11iIi11i / OOooOOo
 if 45 - 45: II111iiii
 if 98 - 98: i11iIiiIii + I1ii11iIi11i * OOooOOo / OoOoOO00
 if 84 - 84: o0oOOo0O0Ooo
 if 40 - 40: OoooooooOO - oO0o / O0 * I1Ii111 . O0 + i11iIiiIii
 if 9 - 9: OOooOOo % O0 % O0 / I1ii11iIi11i . II111iiii / II111iiii
def lisp_data_packet_ipc ( packet , source ) :
 return ( "data-packet@" + str ( len ( packet ) ) + "@" + source + "@@" + packet )
 if 78 - 78: iIii1I11I1II1 - i1IIi . I11i . o0oOOo0O0Ooo
 if 66 - 66: OOooOOo * Oo0Ooo
 if 58 - 58: OOooOOo
 if 96 - 96: IiII % OoooooooOO + O0 * II111iiii / OOooOOo . I1Ii111
 if 47 - 47: OoO0O00 - Oo0Ooo * OoO0O00 / oO0o
 if 13 - 13: ooOoO0o
 if 55 - 55: i1IIi . I11i . II111iiii + O0 + ooOoO0o - i1IIi
 if 3 - 3: iIii1I11I1II1 / oO0o
 if 61 - 61: I1Ii111 / O0 - iII111i
def lisp_command_ipc ( packet , source ) :
 return ( "command@" + str ( len ( packet ) ) + "@" + source + "@@" + packet )
 if 44 - 44: i1IIi
 if 23 - 23: I1ii11iIi11i . OoooooooOO / Ii1I + o0oOOo0O0Ooo
 if 89 - 89: OoOoOO00 + Oo0Ooo . OoOoOO00 - II111iiii
 if 85 - 85: OoooooooOO * OoooooooOO / Ii1I - II111iiii
 if 69 - 69: iII111i * I11i
 if 43 - 43: o0oOOo0O0Ooo - IiII * Ii1I . i11iIiiIii / II111iiii
 if 61 - 61: OoOoOO00 / I1IiiI . I1ii11iIi11i % OOooOOo
 if 70 - 70: OOooOOo * OoOoOO00 / oO0o + Oo0Ooo / O0
 if 16 - 16: Oo0Ooo / OoooooooOO / IiII + Oo0Ooo * i11iIiiIii
def lisp_api_ipc ( source , data ) :
 return ( "api@" + str ( len ( data ) ) + "@" + source + "@@" + data )
 if 15 - 15: o0oOOo0O0Ooo / i11iIiiIii
 if 63 - 63: I1ii11iIi11i - Ii1I + I11i
 if 98 - 98: iII111i / IiII * I1IiiI / oO0o - iIii1I11I1II1
 if 72 - 72: O0 . OOooOOo
 if 99 - 99: i1IIi + iIii1I11I1II1 - ooOoO0o + OoO0O00 + Oo0Ooo . I1ii11iIi11i
 if 74 - 74: i1IIi
 if 80 - 80: ooOoO0o + I1Ii111 . I1ii11iIi11i % OoooooooOO
 if 26 - 26: OoOoOO00 . iII111i * iIii1I11I1II1 / IiII
 if 69 - 69: OoooooooOO / I11i + Ii1I * II111iiii
def lisp_ipc ( packet , send_socket , node ) :
 if 35 - 35: i11iIiiIii + oO0o
 if 85 - 85: OoOoOO00 . O0 % OoooooooOO % oO0o
 if 43 - 43: I1IiiI - I11i . I1IiiI / i11iIiiIii % IiII * i11iIiiIii
 if 12 - 12: II111iiii - iIii1I11I1II1
 if ( lisp_is_running ( node ) == False ) :
  lprint ( "Suppress sending IPC to {}" . format ( node ) )
  return
  if 43 - 43: i11iIiiIii % OoO0O00
  if 100 - 100: i1IIi
 Ii1111Ii = 1500 if ( packet . find ( "control-packet" ) == - 1 ) else 9000
 if 46 - 46: ooOoO0o - iIii1I11I1II1 % i11iIiiIii * IiII - I11i
 oOo0 = 0
 O0o0oOOO = len ( packet )
 iIII1ii1iii1 = 0
 iIiIi = .001
 while ( O0o0oOOO > 0 ) :
  O0o = min ( O0o0oOOO , Ii1111Ii )
  i1iiiiIiiI1I1 = packet [ oOo0 : O0o + oOo0 ]
  if 42 - 42: iIii1I11I1II1 % I11i * OOooOOo + iIii1I11I1II1 % Ii1I
  try :
   send_socket . sendto ( i1iiiiIiiI1I1 , node )
   lprint ( "Send IPC {}-out-of-{} byte to {} succeeded" . format ( len ( i1iiiiIiiI1I1 ) , len ( packet ) , node ) )
   if 56 - 56: o0oOOo0O0Ooo
   iIII1ii1iii1 = 0
   iIiIi = .001
   if 55 - 55: oO0o - I1Ii111 / ooOoO0o % I1IiiI * OoooooooOO * I1IiiI
  except socket . error , o0o000 :
   if ( iIII1ii1iii1 == 12 ) :
    lprint ( "Giving up on {}, consider it down" . format ( node ) )
    break
    if 88 - 88: Ii1I + O0
    if 92 - 92: I1IiiI % iII111i % I11i + OoooooooOO - i11iIiiIii
   lprint ( "Send IPC {}-out-of-{} byte to {} failed: {}" . format ( len ( i1iiiiIiiI1I1 ) , len ( packet ) , node , o0o000 ) )
   if 9 - 9: i11iIiiIii - II111iiii / ooOoO0o
   if 81 - 81: i11iIiiIii % OoOoOO00 % OoO0O00 * Ii1I
   iIII1ii1iii1 += 1
   time . sleep ( iIiIi )
   if 85 - 85: OoooooooOO * ooOoO0o
   lprint ( "Retrying after {} ms ..." . format ( iIiIi * 1000 ) )
   iIiIi *= 2
   continue
   if 23 - 23: OOooOOo / I11i / OoooooooOO - Ii1I / OoO0O00 - OoO0O00
   if 60 - 60: OOooOOo . ooOoO0o % i1IIi % Ii1I % ooOoO0o + OoO0O00
  oOo0 += O0o
  O0o0oOOO -= O0o
  if 26 - 26: O0 % o0oOOo0O0Ooo + iII111i * I1ii11iIi11i * I1Ii111
 return
 if 4 - 4: OOooOOo * OoooooooOO * i1IIi % I1ii11iIi11i % Oo0Ooo
 if 1 - 1: OoO0O00 / iIii1I11I1II1 % I1ii11iIi11i - o0oOOo0O0Ooo
 if 62 - 62: I1Ii111 % II111iiii
 if 91 - 91: I11i % Ii1I - IiII + iIii1I11I1II1 * iIii1I11I1II1
 if 91 - 91: i11iIiiIii + Ii1I
 if 85 - 85: I11i % IiII
 if 68 - 68: Oo0Ooo . I1Ii111 - o0oOOo0O0Ooo * iIii1I11I1II1 - II111iiii % i1IIi
def lisp_format_packet ( packet ) :
 packet = binascii . hexlify ( packet )
 oOo0 = 0
 o0o0Oo0O0O0o = ""
 O0o0oOOO = len ( packet ) * 2
 while ( oOo0 < O0o0oOOO ) :
  o0o0Oo0O0O0o += packet [ oOo0 : oOo0 + 8 ] + " "
  oOo0 += 8
  O0o0oOOO -= 4
  if 58 - 58: I11i / i11iIiiIii * i11iIiiIii
 return ( o0o0Oo0O0O0o )
 if 24 - 24: ooOoO0o - I1Ii111 * II111iiii - II111iiii
 if 47 - 47: IiII - iIii1I11I1II1 / OoOoOO00 * iII111i - iIii1I11I1II1 % oO0o
 if 93 - 93: Ii1I / iII111i
 if 100 - 100: Oo0Ooo
 if 94 - 94: I1ii11iIi11i / i1IIi * I1IiiI - I11i - I1ii11iIi11i
 if 6 - 6: I1ii11iIi11i % o0oOOo0O0Ooo + o0oOOo0O0Ooo / OOooOOo / I1IiiI
 if 67 - 67: OoOoOO00 . iII111i / OOooOOo * ooOoO0o + i1IIi
def lisp_send ( lisp_sockets , dest , port , packet ) :
 O0O = lisp_sockets [ 0 ] if dest . is_ipv4 ( ) else lisp_sockets [ 1 ]
 if 96 - 96: I1Ii111
 if 64 - 64: oO0o - i11iIiiIii
 if 51 - 51: iIii1I11I1II1 - OoooooooOO
 if 72 - 72: I1Ii111 . OoO0O00
 if 59 - 59: I1IiiI * I11i % i1IIi
 if 77 - 77: OOooOOo * OoooooooOO + I1IiiI + I1IiiI % oO0o . OoooooooOO
 if 60 - 60: iIii1I11I1II1
 if 13 - 13: II111iiii + Ii1I
 if 33 - 33: i1IIi
 if 36 - 36: ooOoO0o % ooOoO0o . i11iIiiIii
 if 42 - 42: OoO0O00 . I1Ii111 / Ii1I
 if 57 - 57: iIii1I11I1II1 % I1ii11iIi11i . OOooOOo / oO0o . OoOoOO00
 I1Ii1iIIIIi = dest . print_address_no_iid ( )
 if ( I1Ii1iIIIIi . find ( "::ffff:" ) != - 1 and I1Ii1iIIIIi . count ( "." ) == 3 ) :
  if ( lisp_i_am_rtr ) : O0O = lisp_sockets [ 0 ]
  if ( O0O == None ) :
   O0O = lisp_sockets [ 0 ]
   I1Ii1iIIIIi = I1Ii1iIIIIi . split ( "::ffff:" ) [ - 1 ]
   if 74 - 74: I1IiiI * OoO0O00 + OoooooooOO * ooOoO0o . oO0o
   if 66 - 66: II111iiii + OOooOOo + i11iIiiIii / II111iiii
   if 37 - 37: I1IiiI + OoO0O00 . OoO0O00 % OoOoOO00 + o0oOOo0O0Ooo
 lprint ( "{} {} bytes {} {}, packet: {}" . format ( bold ( "Send" , False ) ,
 len ( packet ) , bold ( "to " + I1Ii1iIIIIi , False ) , port ,
 lisp_format_packet ( packet ) ) )
 if 81 - 81: i1IIi % iIii1I11I1II1
 if 41 - 41: oO0o - iII111i / o0oOOo0O0Ooo . iII111i % Oo0Ooo + OOooOOo
 if 82 - 82: ooOoO0o
 if 89 - 89: OOooOOo / I1ii11iIi11i . I1IiiI + i11iIiiIii
 IIo00ooOoooO = ( LISP_RLOC_PROBE_TTL == 255 )
 if ( IIo00ooOoooO ) :
  iiiO0OO00o00Oo = struct . unpack ( "B" , packet [ 0 ] ) [ 0 ]
  IIo00ooOoooO = ( iiiO0OO00o00Oo in [ 0x12 , 0x28 ] )
  if ( IIo00ooOoooO ) : lisp_set_ttl ( O0O , LISP_RLOC_PROBE_TTL )
  if 86 - 86: OoooooooOO + I1Ii111
  if 5 - 5: I1ii11iIi11i
 try : O0O . sendto ( packet , ( I1Ii1iIIIIi , port ) )
 except socket . error , o0o000 :
  lprint ( "socket.sendto() failed: {}" . format ( o0o000 ) )
  if 89 - 89: OoO0O00 - OoOoOO00 / II111iiii . I1ii11iIi11i
  if 50 - 50: Ii1I * I1Ii111 * OoooooooOO . OoooooooOO
  if 67 - 67: i11iIiiIii % ooOoO0o . I1ii11iIi11i + II111iiii . OoO0O00
  if 42 - 42: I11i / OoO0O00 / OoO0O00 * OOooOOo
  if 2 - 2: II111iiii % oO0o . I1Ii111
 if ( IIo00ooOoooO ) : lisp_set_ttl ( O0O , 64 )
 return
 if 100 - 100: OoOoOO00 + OoOoOO00
 if 26 - 26: II111iiii * iII111i + OOooOOo
 if 28 - 28: Ii1I + O0
 if 44 - 44: oO0o
 if 51 - 51: o0oOOo0O0Ooo * o0oOOo0O0Ooo . Ii1I
 if 14 - 14: OoO0O00 . I11i % II111iiii % i11iIiiIii + OoooooooOO
 if 50 - 50: i11iIiiIii * I11i + i11iIiiIii - i1IIi
 if 69 - 69: I1IiiI + IiII + oO0o * I1ii11iIi11i . iIii1I11I1II1 / OoooooooOO
def lisp_receive_segments ( lisp_socket , packet , source , total_length ) :
 if 77 - 77: Oo0Ooo - ooOoO0o
 if 68 - 68: Ii1I * O0
 if 61 - 61: II111iiii - OoO0O00 . iIii1I11I1II1 * o0oOOo0O0Ooo . OoO0O00 % IiII
 if 11 - 11: oO0o + I11i
 if 6 - 6: i1IIi . o0oOOo0O0Ooo + OoO0O00 + OOooOOo + oO0o
 O0o = total_length - len ( packet )
 if ( O0o == 0 ) : return ( [ True , packet ] )
 if 30 - 30: O0
 lprint ( "Received {}-out-of-{} byte segment from {}" . format ( len ( packet ) ,
 total_length , source ) )
 if 98 - 98: I1Ii111
 if 58 - 58: OOooOOo
 if 6 - 6: I1ii11iIi11i
 if 37 - 37: i11iIiiIii . II111iiii + OOooOOo + i1IIi * OOooOOo
 if 18 - 18: ooOoO0o
 O0o0oOOO = O0o
 while ( O0o0oOOO > 0 ) :
  try : i1iiiiIiiI1I1 = lisp_socket . recvfrom ( 9000 )
  except : return ( [ False , None ] )
  if 18 - 18: I1Ii111 + OoOoOO00 % OOooOOo - IiII - i1IIi + I1ii11iIi11i
  i1iiiiIiiI1I1 = i1iiiiIiiI1I1 [ 0 ]
  if 33 - 33: I11i * Ii1I / Oo0Ooo + oO0o % OOooOOo % OoooooooOO
  if 29 - 29: Ii1I . II111iiii / I1Ii111
  if 79 - 79: IiII . OoOoOO00 / oO0o % OoO0O00 / Ii1I + I11i
  if 78 - 78: o0oOOo0O0Ooo + I1Ii111 % i11iIiiIii % I1IiiI - Ii1I
  if 81 - 81: i11iIiiIii - II111iiii + I11i
  if ( i1iiiiIiiI1I1 . find ( "packet@" ) == 0 ) :
   oOOo0 = i1iiiiIiiI1I1 . split ( "@" )
   lprint ( "Received new message ({}-out-of-{}) while receiving " + "fragments, old message discarded" , len ( i1iiiiIiiI1I1 ) ,
   # II111iiii + Oo0Ooo . II111iiii
 oOOo0 [ 1 ] if len ( oOOo0 ) > 2 else "?" )
   return ( [ False , i1iiiiIiiI1I1 ] )
   if 34 - 34: OoO0O00 - Oo0Ooo / iIii1I11I1II1 / OoO0O00
   if 60 - 60: iIii1I11I1II1
  O0o0oOOO -= len ( i1iiiiIiiI1I1 )
  packet += i1iiiiIiiI1I1
  if 70 - 70: I11i
  lprint ( "Received {}-out-of-{} byte segment from {}" . format ( len ( i1iiiiIiiI1I1 ) , total_length , source ) )
  if 38 - 38: o0oOOo0O0Ooo . OoO0O00 + I1ii11iIi11i - I1IiiI * i1IIi
  if 17 - 17: OoO0O00 % o0oOOo0O0Ooo
 return ( [ True , packet ] )
 if 21 - 21: OOooOOo + OOooOOo - i11iIiiIii * IiII % iIii1I11I1II1
 if 86 - 86: ooOoO0o + OoOoOO00
 if 94 - 94: IiII
 if 30 - 30: o0oOOo0O0Ooo % OoOoOO00 * IiII % iIii1I11I1II1 % O0
 if 76 - 76: II111iiii * I11i
 if 29 - 29: OoooooooOO . i1IIi
 if 46 - 46: I11i
 if 92 - 92: IiII * OoO0O00 . OoOoOO00 + iII111i - I1IiiI
def lisp_bit_stuff ( payload ) :
 lprint ( "Bit-stuffing, found {} segments" . format ( len ( payload ) ) )
 Oo0O0oo = ""
 for i1iiiiIiiI1I1 in payload : Oo0O0oo += i1iiiiIiiI1I1 + "\x40"
 return ( Oo0O0oo [ : - 1 ] )
 if 15 - 15: OoO0O00 / OoO0O00 * o0oOOo0O0Ooo * I1ii11iIi11i - o0oOOo0O0Ooo
 if 47 - 47: I1IiiI / OoOoOO00 / II111iiii
 if 7 - 7: oO0o . ooOoO0o
 if 73 - 73: i1IIi % I1Ii111 * ooOoO0o % OoO0O00
 if 70 - 70: ooOoO0o * I1ii11iIi11i
 if 26 - 26: i11iIiiIii - II111iiii . II111iiii * oO0o / Ii1I + I1IiiI
 if 12 - 12: OoO0O00 * iIii1I11I1II1 % I1Ii111 . O0 * OoOoOO00 * OOooOOo
 if 34 - 34: I1IiiI . i1IIi
 if 38 - 38: iIii1I11I1II1
 if 64 - 64: i1IIi / OoO0O00
 if 68 - 68: I11i * O0 * oO0o + OoOoOO00 / IiII
 if 42 - 42: iIii1I11I1II1 % i1IIi - OoOoOO00 % I1ii11iIi11i * Ii1I + i11iIiiIii
 if 40 - 40: OOooOOo
 if 30 - 30: o0oOOo0O0Ooo - Oo0Ooo + iII111i / O0
 if 94 - 94: IiII
 if 69 - 69: I1Ii111 . I1Ii111
 if 53 - 53: i11iIiiIii + iII111i * Oo0Ooo - I1Ii111
 if 61 - 61: o0oOOo0O0Ooo / OOooOOo . II111iiii - I1IiiI * i11iIiiIii
 if 8 - 8: iII111i % o0oOOo0O0Ooo
 if 87 - 87: Ii1I % I11i / I1Ii111
def lisp_receive ( lisp_socket , internal ) :
 while ( True ) :
  if 21 - 21: OoO0O00 + Ii1I / I1Ii111
  if 75 - 75: I1Ii111 . Ii1I % iIii1I11I1II1 / OoOoOO00
  if 38 - 38: i1IIi
  if 1 - 1: I1ii11iIi11i + OoO0O00 % I11i . OOooOOo + i1IIi / oO0o
  try : I11IIIiI11I = lisp_socket . recvfrom ( 9000 )
  except : return ( [ "" , "" , "" , "" ] )
  if 65 - 65: I1IiiI . Oo0Ooo + i1IIi - Ii1I * i1IIi
  if 64 - 64: I1IiiI / OoO0O00 * I1IiiI * II111iiii . Ii1I
  if 98 - 98: I1Ii111 + o0oOOo0O0Ooo
  if 73 - 73: I1ii11iIi11i / I1Ii111 + i11iIiiIii + OoO0O00 . ooOoO0o
  if 54 - 54: I1ii11iIi11i + IiII - oO0o + Oo0Ooo / IiII % Oo0Ooo
  if 2 - 2: OOooOOo / I11i * I11i + I11i / O0 - OOooOOo
  if ( internal == False ) :
   Oo0O0oo = I11IIIiI11I [ 0 ]
   OO = lisp_convert_6to4 ( I11IIIiI11I [ 1 ] [ 0 ] )
   Ii1 = I11IIIiI11I [ 1 ] [ 1 ]
   if 29 - 29: OoOoOO00 + i11iIiiIii % OoO0O00 - OoooooooOO
   if ( Ii1 == LISP_DATA_PORT ) :
    o00oo = lisp_data_plane_logging
    iIi1i = lisp_format_packet ( Oo0O0oo [ 0 : 60 ] ) + " ..."
   else :
    o00oo = True
    iIi1i = lisp_format_packet ( Oo0O0oo )
    if 96 - 96: iIii1I11I1II1 . o0oOOo0O0Ooo % Ii1I . iIii1I11I1II1
    if 23 - 23: O0 - o0oOOo0O0Ooo * ooOoO0o
   if ( o00oo ) :
    lprint ( "{} {} bytes {} {}, packet: {}" . format ( bold ( "Receive" ,
 False ) , len ( Oo0O0oo ) , bold ( "from " + OO , False ) , Ii1 ,
 iIi1i ) )
    if 4 - 4: Oo0Ooo * OoOoOO00 / OoooooooOO * i11iIiiIii + oO0o
   return ( [ "packet" , OO , Ii1 , Oo0O0oo ] )
   if 45 - 45: Ii1I
   if 8 - 8: oO0o + OOooOOo
   if 37 - 37: IiII - OoOoOO00 + oO0o - Oo0Ooo + IiII
   if 33 - 33: Oo0Ooo % oO0o - I1IiiI + Oo0Ooo
   if 90 - 90: I1ii11iIi11i * I1Ii111 - iIii1I11I1II1 % IiII * I1Ii111 . I1Ii111
   if 90 - 90: o0oOOo0O0Ooo - O0 % O0 - oO0o . OoooooooOO
  I1iii1I = False
  i11i111i1 = I11IIIiI11I [ 0 ]
  iiiI1i1i1 = False
  if 69 - 69: O0 % OoooooooOO
  while ( I1iii1I == False ) :
   i11i111i1 = i11i111i1 . split ( "@" )
   if 100 - 100: I11i / i1IIi / i1IIi % Ii1I - II111iiii . OoooooooOO
   if ( len ( i11i111i1 ) < 4 ) :
    lprint ( "Possible fragment (length {}), from old message, " + "discarding" , len ( i11i111i1 [ 0 ] ) )
    if 72 - 72: Oo0Ooo * OoooooooOO % I1IiiI + I11i - II111iiii
    iiiI1i1i1 = True
    break
    if 82 - 82: iIii1I11I1II1 / i1IIi * I1IiiI . i11iIiiIii
    if 56 - 56: Ii1I * I1IiiI / ooOoO0o * II111iiii
   ooO0OOoo0ooo = i11i111i1 [ 0 ]
   try :
    iiiiiIiiI1 = int ( i11i111i1 [ 1 ] )
   except :
    IiII1iiI = bold ( "Internal packet reassembly error" , False )
    lprint ( "{}: {}" . format ( IiII1iiI , I11IIIiI11I ) )
    iiiI1i1i1 = True
    break
    if 68 - 68: OoooooooOO . OoooooooOO % I1ii11iIi11i + i1IIi % OoooooooOO + Ii1I
   OO = i11i111i1 [ 2 ]
   Ii1 = i11i111i1 [ 3 ]
   if 89 - 89: ooOoO0o + I11i * O0 % OoOoOO00
   if 2 - 2: I1Ii111 % iIii1I11I1II1 . Ii1I - II111iiii
   if 33 - 33: I11i . i11iIiiIii % i1IIi * II111iiii * i11iIiiIii + OoOoOO00
   if 26 - 26: I1IiiI % OoOoOO00 % I11i + Oo0Ooo
   if 86 - 86: iII111i / i1IIi % Oo0Ooo
   if 84 - 84: o0oOOo0O0Ooo * OOooOOo . I11i * Ii1I
   if 32 - 32: ooOoO0o % ooOoO0o * I1ii11iIi11i % Ii1I + Oo0Ooo . OoOoOO00
   if 2 - 2: I1Ii111 / ooOoO0o * oO0o + IiII
   if ( len ( i11i111i1 ) > 5 ) :
    Oo0O0oo = lisp_bit_stuff ( i11i111i1 [ 4 : : ] )
   else :
    Oo0O0oo = i11i111i1 [ 4 ]
    if 14 - 14: OoOoOO00 / iIii1I11I1II1 . o0oOOo0O0Ooo % i11iIiiIii . OoOoOO00
    if 92 - 92: OoO0O00 . i1IIi
    if 22 - 22: Ii1I . I1IiiI
    if 54 - 54: OOooOOo / I1ii11iIi11i % oO0o
    if 66 - 66: I11i + iII111i
    if 50 - 50: IiII
   I1iii1I , Oo0O0oo = lisp_receive_segments ( lisp_socket , Oo0O0oo ,
 OO , iiiiiIiiI1 )
   if ( Oo0O0oo == None ) : return ( [ "" , "" , "" , "" ] )
   if 33 - 33: OOooOOo % I1IiiI - I1IiiI / IiII
   if 22 - 22: ooOoO0o * ooOoO0o % o0oOOo0O0Ooo * Ii1I . OoO0O00
   if 55 - 55: OoOoOO00 - I1ii11iIi11i + iIii1I11I1II1 - i11iIiiIii / i1IIi / II111iiii
   if 37 - 37: Ii1I + o0oOOo0O0Ooo
   if 74 - 74: Oo0Ooo / O0 + i1IIi . I1IiiI + OoO0O00 / Oo0Ooo
   if ( I1iii1I == False ) :
    i11i111i1 = Oo0O0oo
    continue
    if 13 - 13: o0oOOo0O0Ooo / Ii1I . II111iiii
    if 8 - 8: I11i - I11i % IiII
   if ( Ii1 == "" ) : Ii1 = "no-port"
   if ( ooO0OOoo0ooo == "command" and lisp_i_am_core == False ) :
    ii = Oo0O0oo . find ( " {" )
    Ii1OO = Oo0O0oo if ii == - 1 else Oo0O0oo [ : ii ]
    Ii1OO = ": '" + Ii1OO + "'"
   else :
    Ii1OO = ""
    if 17 - 17: I1IiiI . oO0o + Oo0Ooo + I11i / o0oOOo0O0Ooo
    if 25 - 25: iII111i / iII111i % OoOoOO00 / ooOoO0o
   lprint ( "{} {} bytes {} {}, {}{}" . format ( bold ( "Receive" , False ) ,
 len ( Oo0O0oo ) , bold ( "from " + OO , False ) , Ii1 , ooO0OOoo0ooo ,
 Ii1OO if ( ooO0OOoo0ooo in [ "command" , "api" ] ) else ": ... " if ( ooO0OOoo0ooo == "data-packet" ) else ": " + lisp_format_packet ( Oo0O0oo ) ) )
   if 81 - 81: OOooOOo * oO0o
   if 32 - 32: Oo0Ooo * OoO0O00 + ooOoO0o . O0 * oO0o * iIii1I11I1II1
   if 50 - 50: i1IIi
   if 53 - 53: II111iiii + O0 . ooOoO0o * IiII + i1IIi
   if 80 - 80: Ii1I + O0
  if ( iiiI1i1i1 ) : continue
  return ( [ ooO0OOoo0ooo , OO , Ii1 , Oo0O0oo ] )
  if 59 - 59: i11iIiiIii - OoooooooOO % I11i . OoO0O00 - Oo0Ooo * o0oOOo0O0Ooo
  if 7 - 7: II111iiii % Ii1I * i11iIiiIii
  if 28 - 28: II111iiii / ooOoO0o * i11iIiiIii % OOooOOo
  if 18 - 18: I11i - IiII - iIii1I11I1II1
  if 82 - 82: II111iiii + OoO0O00 % iIii1I11I1II1 / O0
  if 75 - 75: OOooOOo * OoO0O00 + OoooooooOO + i11iIiiIii . OoO0O00
  if 94 - 94: I11i * ooOoO0o . I1IiiI / Ii1I - I1IiiI % OoooooooOO
  if 32 - 32: OoO0O00
def lisp_parse_packet ( lisp_sockets , packet , source , udp_sport , ttl = - 1 ) :
 ii1 = False
 if 61 - 61: OOooOOo % O0 . I1ii11iIi11i . iIii1I11I1II1 * I11i
 o0OO0 = lisp_control_header ( )
 if ( o0OO0 . decode ( packet ) == None ) :
  lprint ( "Could not decode control header" )
  return ( ii1 )
  if 29 - 29: ooOoO0o + i1IIi % IiII * Ii1I
  if 94 - 94: OOooOOo / IiII
  if 18 - 18: IiII - I11i / Ii1I % IiII * i1IIi
  if 22 - 22: OoOoOO00 - Oo0Ooo
  if 41 - 41: iIii1I11I1II1 * I1Ii111 / OoO0O00
 i1iiIi1 = source
 if ( source . find ( "lisp" ) == - 1 ) :
  IiiiI1 = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  IiiiI1 . string_to_afi ( source )
  IiiiI1 . store_address ( source )
  source = IiiiI1
  if 99 - 99: ooOoO0o * OOooOOo * I1ii11iIi11i - I11i . I11i . iIii1I11I1II1
  if 99 - 99: I1IiiI
 if ( o0OO0 . type == LISP_MAP_REQUEST ) :
  lisp_process_map_request ( lisp_sockets , packet , None , 0 , source ,
 udp_sport , False , ttl )
  if 41 - 41: O0 % iIii1I11I1II1
 elif ( o0OO0 . type == LISP_MAP_REPLY ) :
  lisp_process_map_reply ( lisp_sockets , packet , source , ttl )
  if 59 - 59: I1ii11iIi11i . I1IiiI + I1IiiI % I1Ii111
 elif ( o0OO0 . type == LISP_MAP_REGISTER ) :
  lisp_process_map_register ( lisp_sockets , packet , source , udp_sport )
  if 22 - 22: o0oOOo0O0Ooo % OOooOOo - I11i + ooOoO0o / OOooOOo
 elif ( o0OO0 . type == LISP_MAP_NOTIFY ) :
  if ( i1iiIi1 == "lisp-etr" ) :
   lisp_process_multicast_map_notify ( packet , source )
  else :
   if ( lisp_is_running ( "lisp-rtr" ) ) :
    lisp_process_multicast_map_notify ( packet , source )
    if 98 - 98: I11i * O0 + IiII - oO0o
   lisp_process_map_notify ( lisp_sockets , packet , source )
   if 35 - 35: OoooooooOO * Ii1I
   if 73 - 73: ooOoO0o . OoO0O00 % I1ii11iIi11i - oO0o
 elif ( o0OO0 . type == LISP_MAP_NOTIFY_ACK ) :
  lisp_process_map_notify_ack ( packet , source )
  if 67 - 67: o0oOOo0O0Ooo . I11i + i1IIi
 elif ( o0OO0 . type == LISP_MAP_REFERRAL ) :
  lisp_process_map_referral ( lisp_sockets , packet , source )
  if 100 - 100: Oo0Ooo - I1IiiI . OOooOOo % iIii1I11I1II1 . I11i
 elif ( o0OO0 . type == LISP_NAT_INFO and o0OO0 . is_info_reply ( ) ) :
  IiIIi , iiIiI1iiI1 , ii1 = lisp_process_info_reply ( source , packet , True )
  if 83 - 83: OoOoOO00 * iII111i
 elif ( o0OO0 . type == LISP_NAT_INFO and o0OO0 . is_info_reply ( ) == False ) :
  I1IIII1i1 = source . print_address_no_iid ( )
  lisp_process_info_request ( lisp_sockets , packet , I1IIII1i1 , udp_sport ,
 None )
  if 75 - 75: i11iIiiIii . o0oOOo0O0Ooo / oO0o . OoO0O00 % Ii1I % Ii1I
 elif ( o0OO0 . type == LISP_ECM ) :
  lisp_process_ecm ( lisp_sockets , packet , source , udp_sport )
  if 94 - 94: iII111i . Ii1I
 else :
  lprint ( "Invalid LISP control packet type {}" . format ( o0OO0 . type ) )
  if 71 - 71: o0oOOo0O0Ooo * II111iiii / OOooOOo . OoO0O00
 return ( ii1 )
 if 73 - 73: I1Ii111 * OoO0O00 / OoOoOO00 . II111iiii
 if 87 - 87: OoO0O00 + Oo0Ooo + O0 % OoooooooOO - iIii1I11I1II1
 if 100 - 100: Oo0Ooo + IiII
 if 81 - 81: iIii1I11I1II1 + iIii1I11I1II1
 if 19 - 19: ooOoO0o + i1IIi / Oo0Ooo * II111iiii * I1Ii111 / ooOoO0o
 if 23 - 23: I1Ii111
 if 76 - 76: Ii1I + Ii1I / i1IIi % o0oOOo0O0Ooo . iIii1I11I1II1 . OoOoOO00
def lisp_process_rloc_probe_request ( lisp_sockets , map_request , source , port ,
 ttl ) :
 if 75 - 75: I11i . Ii1I / I1ii11iIi11i
 IiIiI1 = bold ( "RLOC-probe" , False )
 if 99 - 99: Ii1I
 if ( lisp_i_am_etr ) :
  lprint ( "Received {} Map-Request, send RLOC-probe Map-Reply" . format ( IiIiI1 ) )
  lisp_etr_process_map_request ( lisp_sockets , map_request , source , port ,
 ttl )
  return
  if 85 - 85: I1Ii111 + I1Ii111 + OoOoOO00 / ooOoO0o / o0oOOo0O0Ooo . Oo0Ooo
  if 41 - 41: i1IIi % Ii1I . i1IIi * OoooooooOO % Ii1I
 if ( lisp_i_am_rtr ) :
  lprint ( "Received {} Map-Request, send RLOC-probe Map-Reply" . format ( IiIiI1 ) )
  lisp_rtr_process_map_request ( lisp_sockets , map_request , source , port ,
 ttl )
  return
  if 21 - 21: iII111i
  if 72 - 72: I11i % o0oOOo0O0Ooo . iIii1I11I1II1 - I1Ii111 / i11iIiiIii
 lprint ( "Ignoring received {} Map-Request, not an ETR or RTR" . format ( IiIiI1 ) )
 return
 if 75 - 75: OoooooooOO
 if 24 - 24: oO0o % iII111i - II111iiii / Ii1I + O0
 if 37 - 37: I1Ii111 - i1IIi / iIii1I11I1II1
 if 53 - 53: Ii1I - iIii1I11I1II1 % I1ii11iIi11i * i11iIiiIii + ooOoO0o
 if 63 - 63: Oo0Ooo * I1IiiI
def lisp_process_smr ( map_request ) :
 lprint ( "Received SMR-based Map-Request" )
 return
 if 84 - 84: Oo0Ooo
 if 67 - 67: oO0o / II111iiii . I11i / oO0o
 if 46 - 46: oO0o * Oo0Ooo - I11i / iIii1I11I1II1
 if 100 - 100: i11iIiiIii % oO0o
 if 62 - 62: OOooOOo * i1IIi - OOooOOo / i11iIiiIii
def lisp_process_smr_invoked_request ( map_request ) :
 lprint ( "Received SMR-invoked Map-Request" )
 return
 if 17 - 17: I1ii11iIi11i + ooOoO0o % Ii1I % OOooOOo
 if 73 - 73: i11iIiiIii
 if 44 - 44: o0oOOo0O0Ooo % Ii1I - OoOoOO00 + OoOoOO00 * IiII + iII111i
 if 58 - 58: I1ii11iIi11i / oO0o + i11iIiiIii * o0oOOo0O0Ooo
 if 19 - 19: OoOoOO00
 if 17 - 17: Oo0Ooo
 if 76 - 76: II111iiii % I1ii11iIi11i
def lisp_build_map_reply ( eid , group , rloc_set , nonce , action , ttl , rloc_probe ,
 keys , enc , auth , mr_ttl = - 1 ) :
 oO0ooOo0O = lisp_map_reply ( )
 oO0ooOo0O . rloc_probe = rloc_probe
 oO0ooOo0O . echo_nonce_capable = enc
 oO0ooOo0O . hop_count = 0 if ( mr_ttl == - 1 ) else mr_ttl
 oO0ooOo0O . record_count = 1
 oO0ooOo0O . nonce = nonce
 Oo0O0oo = oO0ooOo0O . encode ( )
 oO0ooOo0O . print_map_reply ( )
 if 44 - 44: O0 + OoOoOO00 . iIii1I11I1II1 . IiII
 iIi1i1i1II1 = lisp_eid_record ( )
 iIi1i1i1II1 . rloc_count = len ( rloc_set )
 iIi1i1i1II1 . authoritative = auth
 iIi1i1i1II1 . record_ttl = ttl
 iIi1i1i1II1 . action = action
 iIi1i1i1II1 . eid = eid
 iIi1i1i1II1 . group = group
 if 83 - 83: II111iiii % o0oOOo0O0Ooo
 Oo0O0oo += iIi1i1i1II1 . encode ( )
 iIi1i1i1II1 . print_record ( "  " , False )
 if 27 - 27: OoO0O00 * Oo0Ooo
 Ooo00o0oo0O0 = lisp_get_all_addresses ( ) + lisp_get_all_translated_rlocs ( )
 if 89 - 89: OoOoOO00 / Oo0Ooo + O0 * ooOoO0o
 for OoooO00OO in rloc_set :
  o000O = lisp_rloc_record ( )
  I1IIII1i1 = OoooO00OO . rloc . print_address_no_iid ( )
  if ( I1IIII1i1 in Ooo00o0oo0O0 ) :
   o000O . local_bit = True
   o000O . probe_bit = rloc_probe
   o000O . keys = keys
   if ( OoooO00OO . priority == 254 and lisp_i_am_rtr ) :
    o000O . rloc_name = "RTR"
    if 97 - 97: OoOoOO00 / ooOoO0o / OoO0O00 / O0 - IiII % I11i
    if 14 - 14: I1IiiI . I1Ii111 + OoooooooOO . IiII - OoO0O00 % I1ii11iIi11i
  o000O . store_rloc_entry ( OoooO00OO )
  o000O . reach_bit = True
  o000O . print_record ( "    " )
  Oo0O0oo += o000O . encode ( )
  if 93 - 93: OoO0O00 / II111iiii / iII111i . o0oOOo0O0Ooo
 return ( Oo0O0oo )
 if 62 - 62: I11i + i1IIi . I1ii11iIi11i - I1ii11iIi11i
 if 68 - 68: ooOoO0o % OoooooooOO
 if 94 - 94: Oo0Ooo * o0oOOo0O0Ooo
 if 60 - 60: iII111i . OOooOOo
 if 39 - 39: O0 - i11iIiiIii - I1IiiI / Oo0Ooo - i11iIiiIii
 if 30 - 30: OoO0O00 / OoOoOO00 + I1ii11iIi11i % IiII - OoO0O00
 if 19 - 19: I1IiiI
def lisp_build_map_referral ( eid , group , ddt_entry , action , ttl , nonce ) :
 o000OOO0 = lisp_map_referral ( )
 o000OOO0 . record_count = 1
 o000OOO0 . nonce = nonce
 Oo0O0oo = o000OOO0 . encode ( )
 o000OOO0 . print_map_referral ( )
 if 8 - 8: i11iIiiIii - iIii1I11I1II1 % i1IIi - i1IIi
 iIi1i1i1II1 = lisp_eid_record ( )
 if 14 - 14: OOooOOo % iII111i . I1IiiI - i11iIiiIii
 o0oOo0 = 0
 if ( ddt_entry == None ) :
  iIi1i1i1II1 . eid = eid
  iIi1i1i1II1 . group = group
 else :
  o0oOo0 = len ( ddt_entry . delegation_set )
  iIi1i1i1II1 . eid = ddt_entry . eid
  iIi1i1i1II1 . group = ddt_entry . group
  ddt_entry . map_referrals_sent += 1
  if 4 - 4: Oo0Ooo / OoOoOO00
 iIi1i1i1II1 . rloc_count = o0oOo0
 iIi1i1i1II1 . authoritative = True
 if 97 - 97: Oo0Ooo
 if 6 - 6: O0 - I1ii11iIi11i / OoooooooOO - Ii1I + Oo0Ooo
 if 88 - 88: OOooOOo - I1ii11iIi11i % iII111i
 if 58 - 58: OoO0O00 . O0 - i11iIiiIii . I1IiiI
 if 95 - 95: OoooooooOO / ooOoO0o * I11i - Ii1I
 Ooooo0OO000o0 = False
 if ( action == LISP_DDT_ACTION_NULL ) :
  if ( o0oOo0 == 0 ) :
   action = LISP_DDT_ACTION_NODE_REFERRAL
  else :
   I1 = ddt_entry . delegation_set [ 0 ]
   if ( I1 . is_ddt_child ( ) ) :
    action = LISP_DDT_ACTION_NODE_REFERRAL
    if 94 - 94: I1Ii111 + OoO0O00 . OoooooooOO
   if ( I1 . is_ms_child ( ) ) :
    action = LISP_DDT_ACTION_MS_REFERRAL
    if 60 - 60: Ii1I . II111iiii
    if 36 - 36: IiII . iII111i * O0 . i1IIi * O0 * I1Ii111
    if 50 - 50: OoooooooOO + o0oOOo0O0Ooo + iIii1I11I1II1 + OOooOOo
    if 90 - 90: Ii1I * I11i % I1Ii111 - I1ii11iIi11i * I1Ii111 % OoO0O00
    if 50 - 50: iIii1I11I1II1
    if 56 - 56: oO0o
    if 55 - 55: iIii1I11I1II1 % oO0o % OOooOOo / I1Ii111 * OoooooooOO / Oo0Ooo
 if ( action == LISP_DDT_ACTION_NOT_AUTH ) : Ooooo0OO000o0 = True
 if ( action in ( LISP_DDT_ACTION_MS_REFERRAL , LISP_DDT_ACTION_MS_ACK ) ) :
  Ooooo0OO000o0 = ( lisp_i_am_ms and I1 . is_ms_peer ( ) == False )
  if 88 - 88: I11i + OoO0O00 . iIii1I11I1II1 . II111iiii
  if 67 - 67: OOooOOo - ooOoO0o % iII111i % IiII
 iIi1i1i1II1 . action = action
 iIi1i1i1II1 . ddt_incomplete = Ooooo0OO000o0
 iIi1i1i1II1 . record_ttl = ttl
 if 71 - 71: OoO0O00 - ooOoO0o - I1IiiI + O0
 Oo0O0oo += iIi1i1i1II1 . encode ( )
 iIi1i1i1II1 . print_record ( "  " , True )
 if 15 - 15: i1IIi
 if ( o0oOo0 == 0 ) : return ( Oo0O0oo )
 if 43 - 43: II111iiii + OOooOOo . i11iIiiIii - II111iiii
 for I1 in ddt_entry . delegation_set :
  o000O = lisp_rloc_record ( )
  o000O . rloc = I1 . delegate_address
  o000O . priority = I1 . priority
  o000O . weight = I1 . weight
  o000O . mpriority = 255
  o000O . mweight = 0
  o000O . reach_bit = True
  Oo0O0oo += o000O . encode ( )
  o000O . print_record ( "    " )
  if 80 - 80: o0oOOo0O0Ooo . oO0o . I1Ii111
 return ( Oo0O0oo )
 if 26 - 26: i1IIi - I1IiiI + IiII / OoO0O00 . I1ii11iIi11i
 if 82 - 82: I1Ii111 % iII111i . OoOoOO00 % OoO0O00 + I1ii11iIi11i
 if 69 - 69: I1IiiI * OoOoOO00 - ooOoO0o . O0
 if 15 - 15: oO0o . IiII + I1Ii111 - OoooooooOO
 if 85 - 85: II111iiii - Oo0Ooo + oO0o . i11iIiiIii + Oo0Ooo
 if 86 - 86: ooOoO0o . OoO0O00
 if 47 - 47: IiII % I1IiiI
def lisp_etr_process_map_request ( lisp_sockets , map_request , source , sport ,
 ttl ) :
 if 91 - 91: Ii1I
 if ( map_request . target_group . is_null ( ) ) :
  o0o0O0OO0oO = lisp_db_for_lookups . lookup_cache ( map_request . target_eid , False )
 else :
  o0o0O0OO0oO = lisp_db_for_lookups . lookup_cache ( map_request . target_group , False )
  if ( o0o0O0OO0oO ) : o0o0O0OO0oO = o0o0O0OO0oO . lookup_source_cache ( map_request . target_eid , False )
  if 28 - 28: I1ii11iIi11i * Ii1I - OOooOOo + Oo0Ooo . OoOoOO00 . OoOoOO00
 oo0oO = map_request . print_prefix ( )
 if 69 - 69: O0
 if ( o0o0O0OO0oO == None ) :
  lprint ( "Database-mapping entry not found for requested EID {}" . format ( green ( oo0oO , False ) ) )
  if 37 - 37: i1IIi * iIii1I11I1II1 % OoooooooOO . OoooooooOO / Oo0Ooo % i11iIiiIii
  return
  if 53 - 53: oO0o - IiII - iIii1I11I1II1 + O0 * Ii1I
  if 1 - 1: i1IIi % O0 / I11i
 oo0Ooo = o0o0O0OO0oO . print_eid_tuple ( )
 if 15 - 15: i11iIiiIii % iIii1I11I1II1 . II111iiii * I11i / I11i
 lprint ( "Found database-mapping EID-prefix {} for requested EID {}" . format ( green ( oo0Ooo , False ) , green ( oo0oO , False ) ) )
 if 80 - 80: Ii1I % II111iiii
 if 4 - 4: OoOoOO00 * OOooOOo / OoooooooOO % OoOoOO00 * I1ii11iIi11i * o0oOOo0O0Ooo
 if 69 - 69: O0 % iIii1I11I1II1
 if 94 - 94: O0
 if 50 - 50: I1Ii111 * o0oOOo0O0Ooo - ooOoO0o - I1ii11iIi11i % I1IiiI . ooOoO0o
 i1IiiIIi1Ii = map_request . itr_rlocs [ 0 ]
 if ( i1IiiIIi1Ii . is_private_address ( ) and lisp_nat_traversal ) :
  i1IiiIIi1Ii = source
  if 22 - 22: ooOoO0o - I11i . iII111i * I1IiiI . I11i
  if 13 - 13: O0 / OoOoOO00
 Iii1i11 = map_request . nonce
 Oooo = lisp_nonce_echoing
 Ii111I11 = map_request . keys
 if 34 - 34: OoooooooOO % ooOoO0o
 o0o0O0OO0oO . map_replies_sent += 1
 if 16 - 16: OoOoOO00 + Oo0Ooo + iIii1I11I1II1 . OoOoOO00 - OOooOOo / o0oOOo0O0Ooo
 Oo0O0oo = lisp_build_map_reply ( o0o0O0OO0oO . eid , o0o0O0OO0oO . group , o0o0O0OO0oO . rloc_set , Iii1i11 ,
 LISP_NO_ACTION , 1440 , map_request . rloc_probe , Ii111I11 , Oooo , True , ttl )
 if 8 - 8: OoOoOO00 . OOooOOo / I11i % Oo0Ooo
 if 36 - 36: Ii1I + iIii1I11I1II1
 if 13 - 13: iII111i . I1Ii111 % ooOoO0o / i1IIi
 if 64 - 64: iII111i
 if 9 - 9: I1ii11iIi11i + Oo0Ooo * I11i / I1Ii111 / I1ii11iIi11i / oO0o
 if 48 - 48: Oo0Ooo % i1IIi / I1ii11iIi11i / oO0o + iII111i
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
 if ( map_request . rloc_probe and len ( lisp_sockets ) == 4 ) :
  oo = ( i1IiiIIi1Ii . is_private_address ( ) == False )
  I111iI1I1i1 = i1IiiIIi1Ii . print_address_no_iid ( )
  if ( ( oo and lisp_rtr_list . has_key ( I111iI1I1i1 ) ) or sport == 0 ) :
   lisp_encapsulate_rloc_probe ( lisp_sockets , i1IiiIIi1Ii , None , Oo0O0oo )
   return
   if 77 - 77: ooOoO0o . I11i + OoooooooOO
   if 100 - 100: ooOoO0o . oO0o % I1ii11iIi11i . IiII * IiII - o0oOOo0O0Ooo
   if 49 - 49: iIii1I11I1II1 % Ii1I / OoooooooOO - II111iiii . Ii1I
   if 65 - 65: OoooooooOO + I1Ii111 % ooOoO0o + II111iiii . i1IIi + OoooooooOO
   if 26 - 26: I1IiiI / II111iiii % I1ii11iIi11i * o0oOOo0O0Ooo . IiII / OoO0O00
   if 10 - 10: i11iIiiIii / i1IIi + O0 - i11iIiiIii % I11i - i1IIi
 lisp_send_map_reply ( lisp_sockets , Oo0O0oo , i1IiiIIi1Ii , sport )
 return
 if 38 - 38: O0 - I1IiiI + Oo0Ooo + ooOoO0o
 if 56 - 56: I1Ii111 + oO0o / Ii1I + I1Ii111
 if 21 - 21: OOooOOo / OoOoOO00 + OoOoOO00 + OoOoOO00 - i1IIi + Ii1I
 if 43 - 43: O0 % II111iiii
 if 60 - 60: iII111i / ooOoO0o - Ii1I - OoooooooOO
 if 79 - 79: oO0o / iII111i . iIii1I11I1II1 * i11iIiiIii * i1IIi . iIii1I11I1II1
 if 31 - 31: OoooooooOO / ooOoO0o / OoooooooOO + ooOoO0o . O0 - IiII
def lisp_rtr_process_map_request ( lisp_sockets , map_request , source , sport ,
 ttl ) :
 if 53 - 53: Oo0Ooo % iII111i % iII111i
 if 71 - 71: iII111i
 if 99 - 99: O0 - OoOoOO00 * I1Ii111 - Oo0Ooo
 if 62 - 62: i1IIi + ooOoO0o + Oo0Ooo - i11iIiiIii
 i1IiiIIi1Ii = map_request . itr_rlocs [ 0 ]
 if ( i1IiiIIi1Ii . is_private_address ( ) ) : i1IiiIIi1Ii = source
 Iii1i11 = map_request . nonce
 if 19 - 19: I1IiiI / OOooOOo
 ii1Ii = map_request . target_eid
 IiI1111i1i11I = map_request . target_group
 if 6 - 6: I1ii11iIi11i + IiII * oO0o * OoOoOO00
 O0Oo0O = [ ]
 for i1i11i in [ lisp_myrlocs [ 0 ] , lisp_myrlocs [ 1 ] ] :
  if ( i1i11i == None ) : continue
  o0OOooooooOO = lisp_rloc ( )
  o0OOooooooOO . rloc . copy_address ( i1i11i )
  o0OOooooooOO . priority = 254
  O0Oo0O . append ( o0OOooooooOO )
  if 81 - 81: i11iIiiIii * OoO0O00 * o0oOOo0O0Ooo + IiII % OOooOOo
  if 43 - 43: I1Ii111
 Oooo = lisp_nonce_echoing
 Ii111I11 = map_request . keys
 if 53 - 53: I1Ii111 + ooOoO0o - iII111i + I1ii11iIi11i * iII111i
 Oo0O0oo = lisp_build_map_reply ( ii1Ii , IiI1111i1i11I , O0Oo0O , Iii1i11 , LISP_NO_ACTION ,
 1440 , True , Ii111I11 , Oooo , True , ttl )
 lisp_send_map_reply ( lisp_sockets , Oo0O0oo , i1IiiIIi1Ii , sport )
 return
 if 95 - 95: OoO0O00 * OoOoOO00 / i1IIi / iII111i + IiII - Ii1I
 if 36 - 36: II111iiii * OoO0O00 + I11i
 if 39 - 39: II111iiii - OoO0O00
 if 8 - 8: I11i - OoO0O00 / II111iiii
 if 32 - 32: oO0o
 if 26 - 26: OoOoOO00 / i11iIiiIii - OOooOOo % oO0o % I1IiiI
 if 23 - 23: i11iIiiIii / iII111i + IiII / i11iIiiIii
 if 97 - 97: o0oOOo0O0Ooo + o0oOOo0O0Ooo / I1ii11iIi11i * OoooooooOO
 if 61 - 61: I1IiiI - I11i
 if 5 - 5: i11iIiiIii % i1IIi / IiII * i11iIiiIii . i1IIi * iII111i
def lisp_get_private_rloc_set ( target_site_eid , seid , group ) :
 O0Oo0O = target_site_eid . registered_rlocs
 if 71 - 71: i11iIiiIii / iIii1I11I1II1 % i1IIi + oO0o - i1IIi + II111iiii
 i111IIi = lisp_site_eid_lookup ( seid , group , False )
 if ( i111IIi == None ) : return ( O0Oo0O )
 if 22 - 22: OoOoOO00 . I1ii11iIi11i % iIii1I11I1II1 + Ii1I - Ii1I % II111iiii
 if 82 - 82: O0
 if 18 - 18: iII111i . IiII . I1IiiI
 if 40 - 40: IiII / oO0o + OoooooooOO / iII111i / II111iiii + i1IIi
 I1II1i = None
 oOoo0oOOO0o = [ ]
 for OoooO00OO in O0Oo0O :
  if ( OoooO00OO . is_rtr ( ) ) : continue
  if ( OoooO00OO . rloc . is_private_address ( ) ) :
   I1iii1Iiii = copy . deepcopy ( OoooO00OO )
   oOoo0oOOO0o . append ( I1iii1Iiii )
   continue
   if 19 - 19: oO0o + II111iiii - OOooOOo
  I1II1i = OoooO00OO
  break
  if 70 - 70: i1IIi * o0oOOo0O0Ooo + I1Ii111 . ooOoO0o - O0 + i11iIiiIii
 if ( I1II1i == None ) : return ( O0Oo0O )
 I1II1i = I1II1i . rloc . print_address_no_iid ( )
 if 81 - 81: iIii1I11I1II1 - OoO0O00 . i11iIiiIii
 if 4 - 4: o0oOOo0O0Ooo / OoO0O00 - I11i
 if 52 - 52: II111iiii . iII111i
 if 36 - 36: I1IiiI * II111iiii
 OOOOOo0O0oOO = None
 for OoooO00OO in i111IIi . registered_rlocs :
  if ( OoooO00OO . is_rtr ( ) ) : continue
  if ( OoooO00OO . rloc . is_private_address ( ) ) : continue
  OOOOOo0O0oOO = OoooO00OO
  break
  if 99 - 99: OoO0O00 * I11i
 if ( OOOOOo0O0oOO == None ) : return ( O0Oo0O )
 OOOOOo0O0oOO = OOOOOo0O0oOO . rloc . print_address_no_iid ( )
 if 33 - 33: I1Ii111 % IiII * OOooOOo - I1Ii111
 if 100 - 100: ooOoO0o . i11iIiiIii * Oo0Ooo - i11iIiiIii
 if 72 - 72: oO0o + I11i . OoooooooOO
 if 84 - 84: oO0o * oO0o - i1IIi + ooOoO0o
 IiIIIii1iIII1 = target_site_eid . site_id
 if ( IiIIIii1iIII1 == 0 ) :
  if ( OOOOOo0O0oOO == I1II1i ) :
   lprint ( "Return private RLOCs for sites behind {}" . format ( I1II1i ) )
   if 83 - 83: i1IIi
   return ( oOoo0oOOO0o )
   if 85 - 85: i11iIiiIii / OoO0O00 / oO0o
  return ( O0Oo0O )
  if 12 - 12: iII111i % OOooOOo % i1IIi
  if 17 - 17: IiII
  if 63 - 63: ooOoO0o . i11iIiiIii / iIii1I11I1II1
  if 8 - 8: i11iIiiIii . IiII * iIii1I11I1II1 * I1IiiI * Ii1I * i11iIiiIii
  if 24 - 24: I1IiiI * I11i - o0oOOo0O0Ooo / iII111i + IiII - I1ii11iIi11i
  if 53 - 53: I11i / I1IiiI - iIii1I11I1II1 - o0oOOo0O0Ooo * OoOoOO00
  if 86 - 86: iIii1I11I1II1 - I1Ii111
 if ( IiIIIii1iIII1 == i111IIi . site_id ) :
  lprint ( "Return private RLOCs for sites in site-id {}" . format ( IiIIIii1iIII1 ) )
  return ( oOoo0oOOO0o )
  if 86 - 86: O0 * IiII + OoOoOO00 + OoO0O00
 return ( O0Oo0O )
 if 53 - 53: I1IiiI % i11iIiiIii + o0oOOo0O0Ooo . I1ii11iIi11i
 if 73 - 73: iII111i - o0oOOo0O0Ooo / OOooOOo + iII111i + o0oOOo0O0Ooo % II111iiii
 if 74 - 74: I11i * iIii1I11I1II1 - OoO0O00 / i1IIi / OoO0O00 / IiII
 if 60 - 60: oO0o % I1Ii111 % Oo0Ooo
 if 34 - 34: o0oOOo0O0Ooo * OOooOOo % Ii1I + I1IiiI
 if 77 - 77: OoOoOO00 + IiII + Oo0Ooo
 if 88 - 88: i1IIi
 if 45 - 45: iII111i % I1ii11iIi11i / i11iIiiIii - II111iiii . Oo0Ooo / ooOoO0o
 if 55 - 55: OoO0O00 % IiII
def lisp_get_partial_rloc_set ( registered_rloc_set , mr_source , multicast ) :
 OOo = [ ]
 O0Oo0O = [ ]
 if 57 - 57: OoOoOO00 - Oo0Ooo . I1Ii111 / Ii1I * OoO0O00
 if 27 - 27: I1IiiI . I1Ii111 % OoOoOO00 * Oo0Ooo % OoooooooOO
 if 7 - 7: iIii1I11I1II1 + oO0o
 if 28 - 28: iII111i * II111iiii . Oo0Ooo
 if 56 - 56: oO0o + iII111i + iII111i * OoO0O00 * I1ii11iIi11i
 if 97 - 97: ooOoO0o + OOooOOo
 OOO0Oo = False
 OO0 = False
 for OoooO00OO in registered_rloc_set :
  if ( OoooO00OO . priority != 254 ) : continue
  OO0 |= True
  if ( OoooO00OO . rloc . is_exact_match ( mr_source ) == False ) : continue
  OOO0Oo = True
  break
  if 6 - 6: Oo0Ooo + I1IiiI
  if 48 - 48: oO0o . I1ii11iIi11i
  if 59 - 59: IiII - Ii1I
  if 62 - 62: OOooOOo * o0oOOo0O0Ooo + IiII * o0oOOo0O0Ooo * i11iIiiIii - O0
  if 37 - 37: I1ii11iIi11i - Oo0Ooo . i11iIiiIii / i11iIiiIii + oO0o
  if 19 - 19: i1IIi / i1IIi - OoooooooOO - OOooOOo . i1IIi
  if 57 - 57: OOooOOo / I1ii11iIi11i * oO0o
 if ( OO0 == False ) : return ( registered_rloc_set )
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
 O0oIII = ( os . getenv ( "LISP_RTR_BEHIND_NAT" ) != None )
 if 98 - 98: I1ii11iIi11i / I1Ii111 . i1IIi / OoOoOO00
 if 56 - 56: OOooOOo * O0
 if 52 - 52: IiII / I1IiiI - o0oOOo0O0Ooo
 if 6 - 6: I1ii11iIi11i / OOooOOo
 if 92 - 92: OOooOOo % OOooOOo
 for OoooO00OO in registered_rloc_set :
  if ( O0oIII and OoooO00OO . rloc . is_private_address ( ) ) : continue
  if ( multicast == False and OoooO00OO . priority == 255 ) : continue
  if ( multicast and OoooO00OO . mpriority == 255 ) : continue
  if ( OoooO00OO . priority == 254 ) :
   OOo . append ( OoooO00OO )
  else :
   O0Oo0O . append ( OoooO00OO )
   if 67 - 67: iII111i + I1ii11iIi11i - IiII . iII111i + iIii1I11I1II1
   if 40 - 40: II111iiii - oO0o / OoO0O00 / OoOoOO00 / Oo0Ooo
   if 11 - 11: IiII + OoooooooOO % OoooooooOO . o0oOOo0O0Ooo * OoOoOO00 + O0
   if 37 - 37: I1IiiI
   if 64 - 64: ooOoO0o
   if 35 - 35: I1IiiI . iIii1I11I1II1 + IiII / i11iIiiIii - II111iiii . OoooooooOO
 if ( OOO0Oo ) : return ( O0Oo0O )
 if 19 - 19: IiII - OoOoOO00
 if 43 - 43: IiII / OOooOOo % II111iiii . o0oOOo0O0Ooo / i11iIiiIii
 if 5 - 5: oO0o % iII111i . Oo0Ooo . O0 . OoOoOO00 / iII111i
 if 78 - 78: Ii1I - I1ii11iIi11i + iIii1I11I1II1 + OoooooooOO . OoO0O00 - ooOoO0o
 if 81 - 81: o0oOOo0O0Ooo * OoooooooOO
 if 32 - 32: OoOoOO00 - I11i * i11iIiiIii . I1ii11iIi11i . IiII . iIii1I11I1II1
 if 41 - 41: iII111i / OoOoOO00 / OoO0O00 / ooOoO0o
 if 16 - 16: iIii1I11I1II1 . II111iiii
 if 80 - 80: Oo0Ooo + IiII
 if 18 - 18: OoO0O00 . Oo0Ooo
 O0Oo0O = [ ]
 for OoooO00OO in registered_rloc_set :
  if ( OoooO00OO . rloc . is_private_address ( ) ) : O0Oo0O . append ( OoooO00OO )
  if 52 - 52: OoOoOO00 . iIii1I11I1II1 / OoOoOO00
 O0Oo0O += OOo
 return ( O0Oo0O )
 if 14 - 14: i1IIi
 if 63 - 63: OoOoOO00 . i11iIiiIii / IiII
 if 36 - 36: OOooOOo * OoOoOO00 + i11iIiiIii + O0 + O0
 if 18 - 18: Oo0Ooo . I1ii11iIi11i * ooOoO0o % Ii1I + I1ii11iIi11i
 if 23 - 23: oO0o / o0oOOo0O0Ooo + I11i % IiII * OoO0O00
 if 48 - 48: OoO0O00
 if 30 - 30: iIii1I11I1II1
 if 53 - 53: II111iiii
 if 40 - 40: Ii1I % oO0o
 if 69 - 69: iIii1I11I1II1 - O0 . I1Ii111 % I1IiiI / o0oOOo0O0Ooo
def lisp_store_pubsub_state ( reply_eid , itr_rloc , mr_sport , nonce , ttl , xtr_id ) :
 ooOOo0ooo = lisp_pubsub ( itr_rloc , mr_sport , nonce , ttl , xtr_id )
 ooOOo0ooo . add ( reply_eid )
 return
 if 71 - 71: OoOoOO00 / i11iIiiIii * iII111i
 if 90 - 90: Ii1I
 if 27 - 27: oO0o + Ii1I . i11iIiiIii
 if 97 - 97: iII111i . I1IiiI
 if 71 - 71: OOooOOo - IiII % oO0o * I1ii11iIi11i
 if 48 - 48: o0oOOo0O0Ooo * iIii1I11I1II1 + Oo0Ooo
 if 45 - 45: oO0o
 if 50 - 50: Ii1I * Ii1I / O0 . Oo0Ooo + iII111i
 if 9 - 9: OoooooooOO % O0 % I1ii11iIi11i
 if 100 - 100: i11iIiiIii - iII111i - I11i
 if 5 - 5: oO0o % IiII * iII111i
 if 98 - 98: iII111i / OOooOOo + IiII
 if 100 - 100: II111iiii . i11iIiiIii / oO0o - OOooOOo + OoOoOO00 % I1ii11iIi11i
 if 82 - 82: ooOoO0o % OOooOOo % Ii1I
 if 82 - 82: I1ii11iIi11i
def lisp_convert_reply_to_notify ( packet ) :
 if 52 - 52: i11iIiiIii % I1Ii111 - iII111i / O0 - I1ii11iIi11i / iII111i
 if 7 - 7: OoooooooOO . OOooOOo . OOooOOo
 if 53 - 53: OOooOOo * OoOoOO00 % iII111i
 if 86 - 86: OOooOOo . OOooOOo + IiII - I1ii11iIi11i . OoO0O00
 OooOooOO0000 = struct . unpack ( "I" , packet [ 0 : 4 ] ) [ 0 ]
 OooOooOO0000 = socket . ntohl ( OooOooOO0000 ) & 0xff
 Iii1i11 = packet [ 4 : 12 ]
 packet = packet [ 12 : : ]
 if 15 - 15: iII111i % Oo0Ooo * i1IIi
 if 93 - 93: OOooOOo * I11i % oO0o % i11iIiiIii + OoO0O00 + I11i
 if 88 - 88: OoOoOO00 + iIii1I11I1II1 + iIii1I11I1II1 . II111iiii % OoO0O00
 if 99 - 99: Oo0Ooo - I1Ii111 * OOooOOo
 iiii1ii1 = ( LISP_MAP_NOTIFY << 28 ) | OooOooOO0000
 o0OO0 = struct . pack ( "I" , socket . htonl ( iiii1ii1 ) )
 oOoO000 = struct . pack ( "I" , 0 )
 if 95 - 95: o0oOOo0O0Ooo / oO0o + Ii1I - OoooooooOO
 if 15 - 15: O0
 if 21 - 21: OoO0O00 * iIii1I11I1II1 - iIii1I11I1II1 % OoO0O00 . I1ii11iIi11i
 if 19 - 19: i1IIi % Ii1I . OoOoOO00
 packet = o0OO0 + Iii1i11 + oOoO000 + packet
 return ( packet )
 if 22 - 22: iIii1I11I1II1 + Ii1I
 if 73 - 73: I1IiiI / OoO0O00 / OoooooooOO
 if 14 - 14: ooOoO0o % o0oOOo0O0Ooo / I1ii11iIi11i . IiII + I1ii11iIi11i
 if 30 - 30: I1ii11iIi11i + iIii1I11I1II1 . I1ii11iIi11i
 if 9 - 9: I1IiiI - Ii1I * II111iiii - I11i
 if 85 - 85: oO0o % ooOoO0o / OOooOOo
 if 50 - 50: O0 * O0 / iIii1I11I1II1
 if 31 - 31: I1IiiI / o0oOOo0O0Ooo
def lisp_notify_subscribers ( lisp_sockets , eid_record , eid , site ) :
 oo0oO = eid . print_prefix ( )
 if ( lisp_pubsub_cache . has_key ( oo0oO ) == False ) : return
 if 70 - 70: I1IiiI
 for ooOOo0ooo in lisp_pubsub_cache [ oo0oO ] . values ( ) :
  oo0Oo0oo = ooOOo0ooo . itr
  Ii1 = ooOOo0ooo . port
  I1iOoO0OOO0oo = red ( oo0Oo0oo . print_address_no_iid ( ) , False )
  I111IiI1i1Ii = bold ( "subscriber" , False )
  iIi = "0x" + lisp_hex_string ( ooOOo0ooo . xtr_id )
  Iii1i11 = "0x" + lisp_hex_string ( ooOOo0ooo . nonce )
  if 81 - 81: I11i
  lprint ( "    Notify {} {}:{} xtr-id {} for {}, nonce {}" . format ( I111IiI1i1Ii , I1iOoO0OOO0oo , Ii1 , iIi , green ( oo0oO , False ) , Iii1i11 ) )
  if 2 - 2: OoOoOO00
  if 75 - 75: I1IiiI - OoooooooOO * I1Ii111
  lisp_build_map_notify ( lisp_sockets , eid_record , [ oo0oO ] , 1 , oo0Oo0oo ,
 Ii1 , ooOOo0ooo . nonce , 0 , 0 , 0 , site , False )
  ooOOo0ooo . map_notify_count += 1
  if 1 - 1: o0oOOo0O0Ooo % oO0o * I1Ii111 - i1IIi - iII111i . oO0o
 return
 if 25 - 25: i1IIi * o0oOOo0O0Ooo / oO0o
 if 11 - 11: IiII + II111iiii
 if 37 - 37: O0
 if 98 - 98: IiII * OoooooooOO . iII111i
 if 34 - 34: OoooooooOO + I1Ii111
 if 97 - 97: II111iiii + I11i + OOooOOo / i11iIiiIii - iII111i
 if 9 - 9: i1IIi - I1Ii111 + I1Ii111
def lisp_process_pubsub ( lisp_sockets , packet , reply_eid , itr_rloc , port , nonce ,
 ttl , xtr_id ) :
 if 81 - 81: II111iiii % I11i % O0 . I1Ii111 % ooOoO0o - O0
 if 58 - 58: OoooooooOO . II111iiii . O0 % I1Ii111 / OoooooooOO
 if 64 - 64: Oo0Ooo + oO0o . OoO0O00
 if 67 - 67: I11i
 lisp_store_pubsub_state ( reply_eid , itr_rloc , port , nonce , ttl , xtr_id )
 if 91 - 91: OOooOOo / OoO0O00
 ii1Ii = green ( reply_eid . print_prefix ( ) , False )
 oo0Oo0oo = red ( itr_rloc . print_address_no_iid ( ) , False )
 II1 = bold ( "Map-Notify" , False )
 xtr_id = "0x" + lisp_hex_string ( xtr_id )
 lprint ( "{} pubsub request for {} to ack ITR {} xtr-id: {}" . format ( II1 ,
 ii1Ii , oo0Oo0oo , xtr_id ) )
 if 81 - 81: I1Ii111
 if 70 - 70: OoO0O00 - OOooOOo - o0oOOo0O0Ooo % I11i - iII111i / I1ii11iIi11i
 if 18 - 18: oO0o * II111iiii . I1Ii111 - iIii1I11I1II1 / iIii1I11I1II1
 if 1 - 1: iII111i
 packet = lisp_convert_reply_to_notify ( packet )
 lisp_send_map_notify ( lisp_sockets , packet , itr_rloc , port )
 return
 if 97 - 97: I1ii11iIi11i + iIii1I11I1II1 / OoO0O00 * I1Ii111 . iII111i
 if 83 - 83: OoOoOO00
 if 90 - 90: oO0o
 if 51 - 51: oO0o / o0oOOo0O0Ooo
 if 97 - 97: II111iiii + o0oOOo0O0Ooo . OoOoOO00
 if 94 - 94: Oo0Ooo / I1IiiI * iIii1I11I1II1 - OoO0O00
 if 96 - 96: ooOoO0o - OoooooooOO * iIii1I11I1II1 . IiII - O0
 if 7 - 7: iIii1I11I1II1 . OoO0O00
def lisp_ms_process_map_request ( lisp_sockets , packet , map_request , mr_source ,
 mr_sport , ecm_source ) :
 if 88 - 88: i1IIi * II111iiii / i11iIiiIii % IiII . IiII
 if 93 - 93: OoOoOO00 * i1IIi . Ii1I
 if 2 - 2: i1IIi
 if 84 - 84: i1IIi / Ii1I + OoOoOO00 % Ii1I . oO0o
 if 74 - 74: OOooOOo - o0oOOo0O0Ooo - I1Ii111 - OoO0O00
 if 40 - 40: o0oOOo0O0Ooo . IiII * OoOoOO00
 ii1Ii = map_request . target_eid
 IiI1111i1i11I = map_request . target_group
 oo0oO = lisp_print_eid_tuple ( ii1Ii , IiI1111i1i11I )
 i1IiiIIi1Ii = map_request . itr_rlocs [ 0 ]
 iIi = map_request . xtr_id
 Iii1i11 = map_request . nonce
 i11IIiI = LISP_NO_ACTION
 ooOOo0ooo = map_request . subscribe_bit
 if 14 - 14: OOooOOo
 if 18 - 18: i11iIiiIii % iII111i
 if 70 - 70: O0 + iII111i % I11i % I1Ii111 + OoOoOO00 / ooOoO0o
 if 35 - 35: IiII + OoO0O00
 if 82 - 82: i1IIi - ooOoO0o / I11i + I11i % I1IiiI - OoooooooOO
 o0OoOo0o = True
 Oo00oo0 = ( lisp_get_eid_hash ( ii1Ii ) != None )
 if ( Oo00oo0 ) :
  IIIIi1I = map_request . map_request_signature
  if ( IIIIi1I == None ) :
   o0OoOo0o = False
   lprint ( ( "EID-crypto-hash signature verification {}, " + "no signature found" ) . format ( bold ( "failed" , False ) ) )
   if 36 - 36: i1IIi % oO0o - O0 - OoO0O00 . OoooooooOO - O0
  else :
   O000o0O0 = map_request . signature_eid
   i1I111iIiI , OOO0O0OO , o0OoOo0o = lisp_lookup_public_key ( O000o0O0 )
   if ( o0OoOo0o ) :
    o0OoOo0o = map_request . verify_map_request_sig ( OOO0O0OO )
   else :
    lprint ( "Public-key lookup failed for sig-eid {}, hash-eid {}" . format ( O000o0O0 . print_address ( ) , i1I111iIiI . print_address ( ) ) )
    if 71 - 71: i1IIi % iII111i * I1Ii111
    if 36 - 36: I1ii11iIi11i % II111iiii % I1Ii111 / I1ii11iIi11i
   iiiiiiIi1i11 = bold ( "passed" , False ) if o0OoOo0o else bold ( "failed" , False )
   lprint ( "EID-crypto-hash signature verification {}" . format ( iiiiiiIi1i11 ) )
   if 10 - 10: I1IiiI + ooOoO0o % OoO0O00 % OoO0O00
   if 36 - 36: I1IiiI * O0 . IiII / I1Ii111
   if 15 - 15: I11i + iII111i
 if ( ooOOo0ooo and o0OoOo0o == False ) :
  ooOOo0ooo = False
  lprint ( "Suppress creating pubsub state due to signature failure" )
  if 79 - 79: i11iIiiIii * IiII % iII111i
  if 18 - 18: iIii1I11I1II1 - O0 . o0oOOo0O0Ooo % oO0o
  if 73 - 73: IiII + I11i % I1IiiI * iII111i . O0
  if 17 - 17: OoO0O00 * OoOoOO00 % O0 % iII111i / i1IIi
  if 100 - 100: i11iIiiIii
  if 54 - 54: O0 * Ii1I + Ii1I
  if 59 - 59: i11iIiiIii % iII111i
  if 54 - 54: I11i . ooOoO0o / OOooOOo % I1Ii111
  if 13 - 13: I11i / O0 . o0oOOo0O0Ooo . ooOoO0o
  if 7 - 7: OoO0O00 + OoooooooOO % II111iiii % oO0o
  if 48 - 48: OOooOOo . II111iiii * OOooOOo - I11i / iIii1I11I1II1 / i11iIiiIii
  if 37 - 37: II111iiii % O0 + iIii1I11I1II1 - I1IiiI . I11i + I1ii11iIi11i
  if 14 - 14: ooOoO0o % iIii1I11I1II1 % ooOoO0o / IiII + OOooOOo
  if 14 - 14: Oo0Ooo
 OO00O000OOO = i1IiiIIi1Ii if ( i1IiiIIi1Ii . afi == ecm_source . afi ) else ecm_source
 if 38 - 38: o0oOOo0O0Ooo
 iIi1iIIiiIi = lisp_site_eid_lookup ( ii1Ii , IiI1111i1i11I , False )
 if 37 - 37: I11i / o0oOOo0O0Ooo + oO0o % Ii1I
 if ( iIi1iIIiiIi == None or iIi1iIIiiIi . is_star_g ( ) ) :
  oO0 = bold ( "Site not found" , False )
  lprint ( "{} for requested EID {}" . format ( oO0 ,
 green ( oo0oO , False ) ) )
  if 50 - 50: Ii1I - i11iIiiIii % Ii1I - OoOoOO00 + I1IiiI / OoooooooOO
  if 57 - 57: I1IiiI - I11i - I1Ii111 . oO0o % Ii1I
  if 59 - 59: I1IiiI % OoO0O00 . o0oOOo0O0Ooo
  if 85 - 85: ooOoO0o . ooOoO0o % Oo0Ooo . OOooOOo + OOooOOo / I1IiiI
  lisp_send_negative_map_reply ( lisp_sockets , ii1Ii , IiI1111i1i11I , Iii1i11 , i1IiiIIi1Ii ,
 mr_sport , 15 , iIi , ooOOo0ooo )
  if 69 - 69: i1IIi + II111iiii / Ii1I
  return ( [ ii1Ii , IiI1111i1i11I , LISP_DDT_ACTION_SITE_NOT_FOUND ] )
  if 4 - 4: I11i * OoOoOO00 % o0oOOo0O0Ooo % ooOoO0o - I1ii11iIi11i
  if 88 - 88: iIii1I11I1II1 * iIii1I11I1II1 * I11i * OoOoOO00
 oo0Ooo = iIi1iIIiiIi . print_eid_tuple ( )
 Ii1i1iiiI1II1 = iIi1iIIiiIi . site . site_name
 if 90 - 90: i11iIiiIii * OOooOOo
 if 32 - 32: o0oOOo0O0Ooo + II111iiii / ooOoO0o
 if 13 - 13: ooOoO0o % O0
 if 26 - 26: iIii1I11I1II1 + iIii1I11I1II1 . Ii1I + i1IIi
 if 16 - 16: II111iiii . Ii1I / i11iIiiIii
 if ( Oo00oo0 == False and iIi1iIIiiIi . require_signature ) :
  IIIIi1I = map_request . map_request_signature
  O000o0O0 = map_request . signature_eid
  if ( IIIIi1I == None or O000o0O0 . is_null ( ) ) :
   lprint ( "Signature required for site {}" . format ( Ii1i1iiiI1II1 ) )
   o0OoOo0o = False
  else :
   O000o0O0 = map_request . signature_eid
   i1I111iIiI , OOO0O0OO , o0OoOo0o = lisp_lookup_public_key ( O000o0O0 )
   if ( o0OoOo0o ) :
    o0OoOo0o = map_request . verify_map_request_sig ( OOO0O0OO )
   else :
    lprint ( "Public-key lookup failed for sig-eid {}, hash-eid {}" . format ( O000o0O0 . print_address ( ) , i1I111iIiI . print_address ( ) ) )
    if 25 - 25: OoO0O00 + o0oOOo0O0Ooo
    if 100 - 100: II111iiii - OOooOOo % oO0o % Ii1I . ooOoO0o / iII111i
   iiiiiiIi1i11 = bold ( "passed" , False ) if o0OoOo0o else bold ( "failed" , False )
   lprint ( "Required signature verification {}" . format ( iiiiiiIi1i11 ) )
   if 45 - 45: I1Ii111 % II111iiii - OoooooooOO * OoOoOO00
   if 29 - 29: I1Ii111 . O0 / ooOoO0o + i1IIi
   if 25 - 25: OOooOOo * O0 % OoooooooOO % O0 + iII111i
   if 6 - 6: Ii1I / II111iiii
   if 73 - 73: IiII
   if 81 - 81: iII111i . OOooOOo * i1IIi
 if ( o0OoOo0o and iIi1iIIiiIi . registered == False ) :
  lprint ( "Site '{}' with EID-prefix {} is not registered for EID {}" . format ( Ii1i1iiiI1II1 , green ( oo0Ooo , False ) , green ( oo0oO , False ) ) )
  if 14 - 14: oO0o
  if 16 - 16: iII111i
  if 26 - 26: iII111i . oO0o * i11iIiiIii . iIii1I11I1II1
  if 74 - 74: Ii1I / iIii1I11I1II1 + OOooOOo . II111iiii
  if 65 - 65: OOooOOo * I11i * Oo0Ooo
  if 21 - 21: Ii1I . iIii1I11I1II1
  if ( iIi1iIIiiIi . accept_more_specifics == False ) :
   ii1Ii = iIi1iIIiiIi . eid
   IiI1111i1i11I = iIi1iIIiiIi . group
   if 84 - 84: OOooOOo
   if 67 - 67: I1IiiI % OoO0O00 % o0oOOo0O0Ooo % IiII
   if 33 - 33: ooOoO0o % I1IiiI
   if 98 - 98: oO0o . o0oOOo0O0Ooo + II111iiii
   if 62 - 62: ooOoO0o - OoooooooOO / I1ii11iIi11i / iII111i - o0oOOo0O0Ooo
  I1i = 1
  if ( iIi1iIIiiIi . force_ttl != None ) :
   I1i = iIi1iIIiiIi . force_ttl | 0x80000000
   if 70 - 70: oO0o % OoooooooOO * I1IiiI - OoOoOO00 * OoOoOO00 . OOooOOo
   if 9 - 9: iII111i * Oo0Ooo % iII111i % Oo0Ooo * II111iiii
   if 71 - 71: II111iiii + I1ii11iIi11i * II111iiii
   if 59 - 59: OoO0O00
   if 81 - 81: i11iIiiIii
  lisp_send_negative_map_reply ( lisp_sockets , ii1Ii , IiI1111i1i11I , Iii1i11 , i1IiiIIi1Ii ,
 mr_sport , I1i , iIi , ooOOo0ooo )
  if 57 - 57: Oo0Ooo * iIii1I11I1II1 - OoOoOO00 % iII111i % I1ii11iIi11i + Ii1I
  return ( [ ii1Ii , IiI1111i1i11I , LISP_DDT_ACTION_MS_NOT_REG ] )
  if 82 - 82: IiII * Oo0Ooo - iIii1I11I1II1 - i11iIiiIii
  if 85 - 85: OoooooooOO
  if 37 - 37: OoooooooOO + O0 + I1ii11iIi11i + IiII * iII111i
  if 15 - 15: i11iIiiIii / Oo0Ooo - OOooOOo . IiII
  if 11 - 11: OOooOOo / i1IIi % Oo0Ooo
 o0OoOOO00O = False
 oO0O0O0O0O0OO = ""
 Oo00O0000Ooo = False
 if ( iIi1iIIiiIi . force_nat_proxy_reply ) :
  oO0O0O0O0O0OO = ", nat-forced"
  o0OoOOO00O = True
  Oo00O0000Ooo = True
 elif ( iIi1iIIiiIi . force_proxy_reply ) :
  oO0O0O0O0O0OO = ", forced"
  Oo00O0000Ooo = True
 elif ( iIi1iIIiiIi . proxy_reply_requested ) :
  oO0O0O0O0O0OO = ", requested"
  Oo00O0000Ooo = True
 elif ( map_request . pitr_bit and iIi1iIIiiIi . pitr_proxy_reply_drop ) :
  oO0O0O0O0O0OO = ", drop-to-pitr"
  i11IIiI = LISP_DROP_ACTION
 elif ( iIi1iIIiiIi . proxy_reply_action != "" ) :
  i11IIiI = iIi1iIIiiIi . proxy_reply_action
  oO0O0O0O0O0OO = ", forced, action {}" . format ( i11IIiI )
  i11IIiI = LISP_DROP_ACTION if ( i11IIiI == "drop" ) else LISP_NATIVE_FORWARD_ACTION
  if 86 - 86: i11iIiiIii / ooOoO0o / OOooOOo + Oo0Ooo . I1Ii111 + II111iiii
  if 4 - 4: II111iiii * I1IiiI * O0 + I1ii11iIi11i
  if 24 - 24: iIii1I11I1II1
  if 2 - 2: iIii1I11I1II1
  if 87 - 87: I11i
  if 17 - 17: OOooOOo - Oo0Ooo + Ii1I
  if 94 - 94: OoO0O00 * OoO0O00 * II111iiii + i1IIi / i1IIi % Ii1I
 O0oO0O0 = False
 oooOO0ooOo0O0 = None
 if ( Oo00O0000Ooo and lisp_policies . has_key ( iIi1iIIiiIi . policy ) ) :
  IiIiI1 = lisp_policies [ iIi1iIIiiIi . policy ]
  if ( IiIiI1 . match_policy_map_request ( map_request , mr_source ) ) : oooOO0ooOo0O0 = IiIiI1
  if 57 - 57: I1Ii111 * IiII + I1Ii111 . iIii1I11I1II1 + i11iIiiIii
  if ( oooOO0ooOo0O0 ) :
   o0ooo = bold ( "matched" , False )
   lprint ( "Map-Request {} policy '{}', set-action '{}'" . format ( o0ooo ,
 IiIiI1 . policy_name , IiIiI1 . set_action ) )
  else :
   o0ooo = bold ( "no match" , False )
   lprint ( "Map-Request {} for policy '{}', implied drop" . format ( o0ooo ,
 IiIiI1 . policy_name ) )
   O0oO0O0 = True
   if 19 - 19: O0 - i11iIiiIii + ooOoO0o % O0
   if 63 - 63: iII111i + iIii1I11I1II1 * OoOoOO00 . I1Ii111 / I11i * o0oOOo0O0Ooo
   if 6 - 6: OOooOOo . ooOoO0o % iII111i - o0oOOo0O0Ooo % I11i + i11iIiiIii
 if ( oO0O0O0O0O0OO != "" ) :
  lprint ( "Proxy-replying for EID {}, found site '{}' EID-prefix {}{}" . format ( green ( oo0oO , False ) , Ii1i1iiiI1II1 , green ( oo0Ooo , False ) ,
  # OoooooooOO
 oO0O0O0O0O0OO ) )
  if 3 - 3: IiII + iIii1I11I1II1 * Ii1I - II111iiii
  O0Oo0O = iIi1iIIiiIi . registered_rlocs
  I1i = 1440
  if ( o0OoOOO00O ) :
   if ( iIi1iIIiiIi . site_id != 0 ) :
    IiIiiiiI1 = map_request . source_eid
    O0Oo0O = lisp_get_private_rloc_set ( iIi1iIIiiIi , IiIiiiiI1 , IiI1111i1i11I )
    if 63 - 63: iIii1I11I1II1 * Ii1I + OoooooooOO . I1Ii111 . o0oOOo0O0Ooo
   if ( O0Oo0O == iIi1iIIiiIi . registered_rlocs ) :
    iIo0 = ( iIi1iIIiiIi . group . is_null ( ) == False )
    oOoo0oOOO0o = lisp_get_partial_rloc_set ( O0Oo0O , OO00O000OOO , iIo0 )
    if ( oOoo0oOOO0o != O0Oo0O ) :
     I1i = 15
     O0Oo0O = oOoo0oOOO0o
     if 74 - 74: i1IIi
     if 3 - 3: OoO0O00 - o0oOOo0O0Ooo - Ii1I
     if 33 - 33: ooOoO0o + I1ii11iIi11i - I1IiiI . iII111i / OoO0O00
     if 91 - 91: OOooOOo - OoooooooOO . OoO0O00
     if 34 - 34: Ii1I . I1IiiI . i1IIi * I1ii11iIi11i
     if 77 - 77: ooOoO0o . II111iiii
     if 41 - 41: IiII
     if 27 - 27: IiII / IiII
  if ( iIi1iIIiiIi . force_ttl != None ) :
   I1i = iIi1iIIiiIi . force_ttl | 0x80000000
   if 91 - 91: Ii1I
   if 93 - 93: OoO0O00 * OoO0O00 * I1ii11iIi11i * OoO0O00 * o0oOOo0O0Ooo
   if 84 - 84: I1Ii111 * OoO0O00 - ooOoO0o - Oo0Ooo . OoO0O00 % oO0o
   if 98 - 98: OoO0O00 . i1IIi
   if 58 - 58: i1IIi * O0 + I1ii11iIi11i . IiII
   if 11 - 11: OOooOOo + iIii1I11I1II1 - ooOoO0o * OoO0O00 * i11iIiiIii
  if ( oooOO0ooOo0O0 ) :
   if ( oooOO0ooOo0O0 . set_record_ttl ) :
    I1i = oooOO0ooOo0O0 . set_record_ttl
    lprint ( "Policy set-record-ttl to {}" . format ( I1i ) )
    if 45 - 45: I1ii11iIi11i + Oo0Ooo
   if ( oooOO0ooOo0O0 . set_action == "drop" ) :
    lprint ( "Policy set-action drop, send negative Map-Reply" )
    i11IIiI = LISP_POLICY_DENIED_ACTION
    O0Oo0O = [ ]
   else :
    o0OOooooooOO = oooOO0ooOo0O0 . set_policy_map_reply ( )
    if ( o0OOooooooOO ) : O0Oo0O = [ o0OOooooooOO ]
    if 7 - 7: Oo0Ooo + ooOoO0o - I1Ii111 * iIii1I11I1II1
    if 6 - 6: ooOoO0o % I1Ii111 % ooOoO0o . Ii1I * Oo0Ooo . IiII
    if 100 - 100: i1IIi . Ii1I . o0oOOo0O0Ooo + Ii1I - i1IIi . I11i
  if ( O0oO0O0 ) :
   lprint ( "Implied drop action, send negative Map-Reply" )
   i11IIiI = LISP_POLICY_DENIED_ACTION
   O0Oo0O = [ ]
   if 19 - 19: i11iIiiIii + I11i - IiII . iII111i * i1IIi
   if 66 - 66: ooOoO0o
  Oooo = iIi1iIIiiIi . echo_nonce_capable
  if 4 - 4: iII111i / iII111i * OOooOOo + o0oOOo0O0Ooo . I1Ii111 + II111iiii
  if 90 - 90: IiII * iII111i % OoOoOO00 . i11iIiiIii
  if 5 - 5: O0 * i1IIi / IiII
  if 4 - 4: II111iiii
  if ( o0OoOo0o ) :
   O00oOOOO0 = iIi1iIIiiIi . eid
   II1111111i = iIi1iIIiiIi . group
  else :
   O00oOOOO0 = ii1Ii
   II1111111i = IiI1111i1i11I
   i11IIiI = LISP_AUTH_FAILURE_ACTION
   O0Oo0O = [ ]
   if 38 - 38: o0oOOo0O0Ooo + o0oOOo0O0Ooo / O0 + OoooooooOO
   if 51 - 51: II111iiii - oO0o % OoooooooOO - II111iiii / O0 - OoooooooOO
   if 21 - 21: iII111i * o0oOOo0O0Ooo
   if 85 - 85: I1ii11iIi11i . OoOoOO00 . i1IIi % OOooOOo * I11i . I1Ii111
   if 26 - 26: I1Ii111 + Oo0Ooo + II111iiii % OoOoOO00 % OOooOOo
   if 40 - 40: I1ii11iIi11i + i1IIi
  packet = lisp_build_map_reply ( O00oOOOO0 , II1111111i , O0Oo0O ,
 Iii1i11 , i11IIiI , I1i , False , None , Oooo , False )
  if 9 - 9: OOooOOo
  if ( ooOOo0ooo ) :
   lisp_process_pubsub ( lisp_sockets , packet , O00oOOOO0 , i1IiiIIi1Ii ,
 mr_sport , Iii1i11 , I1i , iIi )
  else :
   lisp_send_map_reply ( lisp_sockets , packet , i1IiiIIi1Ii , mr_sport )
   if 74 - 74: OoOoOO00 - OOooOOo % OoOoOO00
   if 82 - 82: I11i % IiII + Oo0Ooo + iIii1I11I1II1 - I11i - I1IiiI
  return ( [ iIi1iIIiiIi . eid , iIi1iIIiiIi . group , LISP_DDT_ACTION_MS_ACK ] )
  if 65 - 65: IiII / O0 * II111iiii + oO0o
  if 52 - 52: o0oOOo0O0Ooo - OoOoOO00 * II111iiii / OoooooooOO
  if 44 - 44: OOooOOo - oO0o + o0oOOo0O0Ooo - i1IIi % o0oOOo0O0Ooo
  if 79 - 79: iII111i . iIii1I11I1II1
  if 42 - 42: i11iIiiIii / IiII . O0 / OOooOOo . iII111i * i1IIi
 o0oOo0 = len ( iIi1iIIiiIi . registered_rlocs )
 if ( o0oOo0 == 0 ) :
  lprint ( "Requested EID {} found site '{}' with EID-prefix {} with " + "no registered RLOCs" . format ( green ( oo0oO , False ) , Ii1i1iiiI1II1 ,
  # iIii1I11I1II1 * IiII . i11iIiiIii / o0oOOo0O0Ooo + I1IiiI
 green ( oo0Ooo , False ) ) )
  return ( [ iIi1iIIiiIi . eid , iIi1iIIiiIi . group , LISP_DDT_ACTION_MS_ACK ] )
  if 53 - 53: II111iiii . OoooooooOO
  if 40 - 40: OoO0O00 / II111iiii + OoOoOO00
  if 96 - 96: OoOoOO00 . I1ii11iIi11i
  if 55 - 55: I1Ii111 + I1IiiI - ooOoO0o * I1Ii111
  if 44 - 44: i1IIi - I11i * I11i - OoO0O00 % OoOoOO00 / o0oOOo0O0Ooo
 IiiIIi = map_request . target_eid if map_request . source_eid . is_null ( ) else map_request . source_eid
 if 83 - 83: IiII . I1IiiI * I11i + OoooooooOO / iII111i
 I1i1Ii = map_request . target_eid . hash_address ( IiiIIi )
 I1i1Ii %= o0oOo0
 OOOIII11i1 = iIi1iIIiiIi . registered_rlocs [ I1i1Ii ]
 if 1 - 1: iII111i * oO0o % Ii1I . oO0o
 if ( OOOIII11i1 . rloc . is_null ( ) ) :
  lprint ( ( "Suppress forwarding Map-Request for EID {} at site '{}' " + "EID-prefix {}, no RLOC address" ) . format ( green ( oo0oO , False ) ,
  # IiII % OoooooooOO * OoOoOO00 * iIii1I11I1II1 . iII111i % oO0o
 Ii1i1iiiI1II1 , green ( oo0Ooo , False ) ) )
 else :
  lprint ( ( "Forwarding Map-Request for EID {} to ETR {} at site '{}' " + "EID-prefix {}" ) . format ( green ( oo0oO , False ) ,
  # IiII - Oo0Ooo % iII111i % I11i
 red ( OOOIII11i1 . rloc . print_address ( ) , False ) , Ii1i1iiiI1II1 ,
 green ( oo0Ooo , False ) ) )
  if 42 - 42: Oo0Ooo . OoO0O00
  if 22 - 22: ooOoO0o - o0oOOo0O0Ooo + I11i / I1IiiI + OOooOOo
  if 10 - 10: oO0o / I1IiiI
  if 95 - 95: II111iiii - IiII % IiII . o0oOOo0O0Ooo
  lisp_send_ecm ( lisp_sockets , packet , map_request . source_eid , mr_sport ,
 map_request . target_eid , OOOIII11i1 . rloc , to_etr = True )
  if 19 - 19: II111iiii . ooOoO0o . I11i - OoooooooOO / I1ii11iIi11i . I1Ii111
 return ( [ iIi1iIIiiIi . eid , iIi1iIIiiIi . group , LISP_DDT_ACTION_MS_ACK ] )
 if 57 - 57: II111iiii . I1Ii111 . i11iIiiIii / OoOoOO00 - O0
 if 56 - 56: OOooOOo / I1Ii111
 if 13 - 13: oO0o + Oo0Ooo + Oo0Ooo / OoO0O00 + i1IIi + I1IiiI
 if 56 - 56: OoOoOO00
 if 10 - 10: iIii1I11I1II1 + i1IIi * Ii1I / iIii1I11I1II1 % OoOoOO00 / O0
 if 14 - 14: O0
 if 65 - 65: IiII / oO0o
def lisp_ddt_process_map_request ( lisp_sockets , map_request , ecm_source , port ) :
 if 57 - 57: IiII + oO0o - IiII
 if 51 - 51: OoOoOO00 % IiII / iII111i - oO0o - OoO0O00 . iIii1I11I1II1
 if 61 - 61: OoO0O00
 if 60 - 60: I1IiiI % O0 % OoooooooOO / Ii1I
 ii1Ii = map_request . target_eid
 IiI1111i1i11I = map_request . target_group
 oo0oO = lisp_print_eid_tuple ( ii1Ii , IiI1111i1i11I )
 Iii1i11 = map_request . nonce
 i11IIiI = LISP_DDT_ACTION_NULL
 if 9 - 9: OoooooooOO / I11i % I11i * O0 / II111iiii . II111iiii
 if 40 - 40: II111iiii + OoooooooOO / iII111i % O0 + OOooOOo . ooOoO0o
 if 71 - 71: OoooooooOO + ooOoO0o * o0oOOo0O0Ooo + I1IiiI
 if 47 - 47: oO0o
 if 91 - 91: I1IiiI * O0 + OoooooooOO * i1IIi % I1ii11iIi11i . IiII
 oO0O000oOOOOo = None
 if ( lisp_i_am_ms ) :
  iIi1iIIiiIi = lisp_site_eid_lookup ( ii1Ii , IiI1111i1i11I , False )
  if ( iIi1iIIiiIi == None ) : return
  if 47 - 47: II111iiii
  if ( iIi1iIIiiIi . registered ) :
   i11IIiI = LISP_DDT_ACTION_MS_ACK
   I1i = 1440
  else :
   ii1Ii , IiI1111i1i11I , i11IIiI = lisp_ms_compute_neg_prefix ( ii1Ii , IiI1111i1i11I )
   i11IIiI = LISP_DDT_ACTION_MS_NOT_REG
   I1i = 1
   if 81 - 81: I11i / Oo0Ooo % Ii1I % OoO0O00
 else :
  oO0O000oOOOOo = lisp_ddt_cache_lookup ( ii1Ii , IiI1111i1i11I , False )
  if ( oO0O000oOOOOo == None ) :
   i11IIiI = LISP_DDT_ACTION_NOT_AUTH
   I1i = 0
   lprint ( "DDT delegation entry not found for EID {}" . format ( green ( oo0oO , False ) ) )
   if 87 - 87: O0 % II111iiii
  elif ( oO0O000oOOOOo . is_auth_prefix ( ) ) :
   if 42 - 42: I1IiiI . i1IIi
   if 98 - 98: o0oOOo0O0Ooo % I11i . Oo0Ooo * Oo0Ooo % iII111i
   if 37 - 37: OoO0O00 / I1Ii111 . I1Ii111 * i1IIi
   if 22 - 22: I1ii11iIi11i . II111iiii + iIii1I11I1II1 / OoooooooOO . ooOoO0o
   i11IIiI = LISP_DDT_ACTION_DELEGATION_HOLE
   I1i = 15
   iI1I1 = oO0O000oOOOOo . print_eid_tuple ( )
   lprint ( ( "DDT delegation entry not found but auth-prefix {} " + "found for EID {}" ) . format ( iI1I1 ,
   # i1IIi - Oo0Ooo
 green ( oo0oO , False ) ) )
   if 5 - 5: iIii1I11I1II1
   if ( IiI1111i1i11I . is_null ( ) ) :
    ii1Ii = lisp_ddt_compute_neg_prefix ( ii1Ii , oO0O000oOOOOo ,
 lisp_ddt_cache )
   else :
    IiI1111i1i11I = lisp_ddt_compute_neg_prefix ( IiI1111i1i11I , oO0O000oOOOOo ,
 lisp_ddt_cache )
    ii1Ii = lisp_ddt_compute_neg_prefix ( ii1Ii , oO0O000oOOOOo ,
 oO0O000oOOOOo . source_cache )
    if 43 - 43: iII111i / i11iIiiIii
   oO0O000oOOOOo = None
  else :
   iI1I1 = oO0O000oOOOOo . print_eid_tuple ( )
   lprint ( "DDT delegation entry {} found for EID {}" . format ( iI1I1 , green ( oo0oO , False ) ) )
   if 8 - 8: I1ii11iIi11i . i11iIiiIii . Oo0Ooo % I1IiiI % ooOoO0o
   I1i = 1440
   if 20 - 20: oO0o
   if 37 - 37: ooOoO0o
   if 67 - 67: IiII - i11iIiiIii - OOooOOo % iII111i % O0 / o0oOOo0O0Ooo
   if 54 - 54: II111iiii * OoOoOO00
   if 46 - 46: ooOoO0o . I1IiiI - ooOoO0o + Oo0Ooo
   if 31 - 31: OOooOOo + ooOoO0o . i1IIi - OoO0O00
 Oo0O0oo = lisp_build_map_referral ( ii1Ii , IiI1111i1i11I , oO0O000oOOOOo , i11IIiI , I1i , Iii1i11 )
 Iii1i11 = map_request . nonce >> 32
 if ( map_request . nonce != 0 and Iii1i11 != 0xdfdf0e1d ) : port = LISP_CTRL_PORT
 lisp_send_map_referral ( lisp_sockets , Oo0O0oo , ecm_source , port )
 return
 if 16 - 16: I11i + I1IiiI - Ii1I / I1ii11iIi11i + Ii1I
 if 38 - 38: i1IIi * iIii1I11I1II1 * iII111i + OoOoOO00
 if 64 - 64: OoO0O00 % o0oOOo0O0Ooo
 if 72 - 72: O0 + OoOoOO00 % OOooOOo / oO0o / IiII
 if 98 - 98: Oo0Ooo . II111iiii * I11i
 if 39 - 39: IiII * o0oOOo0O0Ooo + Ii1I - I11i
 if 70 - 70: oO0o * ooOoO0o / ooOoO0o - Ii1I * Ii1I % OOooOOo
 if 91 - 91: OoO0O00 - OoO0O00 % O0
 if 67 - 67: ooOoO0o * i1IIi
 if 66 - 66: o0oOOo0O0Ooo - I1ii11iIi11i . OoOoOO00 / iII111i - Ii1I - i1IIi
 if 97 - 97: oO0o % iII111i - OOooOOo . OoooooooOO
 if 94 - 94: Oo0Ooo
 if 10 - 10: i11iIiiIii / I1ii11iIi11i . i1IIi + i1IIi * iII111i
def lisp_find_negative_mask_len ( eid , entry_prefix , neg_prefix ) :
 OooOoOooOO = eid . hash_address ( entry_prefix )
 IIi1 = eid . addr_length ( ) * 8
 ooI1111 = 0
 if 25 - 25: oO0o + I1ii11iIi11i + i11iIiiIii % i11iIiiIii
 if 11 - 11: I11i * Oo0Ooo * ooOoO0o + i1IIi
 if 76 - 76: o0oOOo0O0Ooo * i1IIi / I1Ii111 * Oo0Ooo + II111iiii . OoOoOO00
 if 44 - 44: OoOoOO00
 for ooI1111 in range ( IIi1 ) :
  OOoo000oOO = 1 << ( IIi1 - ooI1111 - 1 )
  if ( OooOoOooOO & OOoo000oOO ) : break
  if 74 - 74: o0oOOo0O0Ooo * II111iiii % oO0o % OoooooooOO
  if 21 - 21: OOooOOo
 if ( ooI1111 > neg_prefix . mask_len ) : neg_prefix . mask_len = ooI1111
 return
 if 2 - 2: I11i - OOooOOo / o0oOOo0O0Ooo
 if 14 - 14: I11i + Oo0Ooo + i11iIiiIii - i1IIi . O0
 if 47 - 47: o0oOOo0O0Ooo / i1IIi * IiII
 if 50 - 50: I11i
 if 9 - 9: iII111i . OoOoOO00 * iII111i
 if 54 - 54: i11iIiiIii * I1IiiI / IiII - OoO0O00 % i1IIi
 if 2 - 2: II111iiii - OoOoOO00
 if 81 - 81: IiII / OOooOOo / OoooooooOO + II111iiii - OOooOOo . i11iIiiIii
 if 33 - 33: o0oOOo0O0Ooo - OoooooooOO
 if 30 - 30: i1IIi + II111iiii + OoOoOO00 + I1ii11iIi11i % ooOoO0o % OOooOOo
def lisp_neg_prefix_walk ( entry , parms ) :
 ii1Ii , IIIi1iIiiI1 , IIi11iIi = parms
 if 16 - 16: OoO0O00 / Oo0Ooo / IiII . Oo0Ooo - OoooooooOO
 if ( IIIi1iIiiI1 == None ) :
  if ( entry . eid . instance_id != ii1Ii . instance_id ) :
   return ( [ True , parms ] )
   if 5 - 5: OoOoOO00 . I11i
  if ( entry . eid . afi != ii1Ii . afi ) : return ( [ True , parms ] )
 else :
  if ( entry . eid . is_more_specific ( IIIi1iIiiI1 ) == False ) :
   return ( [ True , parms ] )
   if 28 - 28: I11i % OOooOOo + Oo0Ooo / OoO0O00 % o0oOOo0O0Ooo + OoO0O00
   if 20 - 20: ooOoO0o . iII111i % OOooOOo + i11iIiiIii
   if 64 - 64: i1IIi . o0oOOo0O0Ooo * I1Ii111 - O0
   if 76 - 76: I1IiiI % Ii1I + OoO0O00 + I1ii11iIi11i * II111iiii + Oo0Ooo
   if 3 - 3: Ii1I - I1IiiI + O0
   if 90 - 90: Ii1I + OoooooooOO . i11iIiiIii / Oo0Ooo % OoOoOO00 / IiII
 lisp_find_negative_mask_len ( ii1Ii , entry . eid , IIi11iIi )
 return ( [ True , parms ] )
 if 45 - 45: OoooooooOO / oO0o . I1ii11iIi11i + OOooOOo
 if 54 - 54: Ii1I - o0oOOo0O0Ooo + OoOoOO00 / OoooooooOO
 if 61 - 61: I11i / IiII % OoooooooOO - i11iIiiIii * i1IIi % o0oOOo0O0Ooo
 if 67 - 67: o0oOOo0O0Ooo - Ii1I
 if 29 - 29: OoOoOO00 . I1ii11iIi11i
 if 24 - 24: OOooOOo + i1IIi . I11i . OoOoOO00 + OoooooooOO
 if 98 - 98: ooOoO0o + i1IIi / I1IiiI
 if 1 - 1: IiII . OoooooooOO + II111iiii
def lisp_ddt_compute_neg_prefix ( eid , ddt_entry , cache ) :
 if 6 - 6: O0 * Oo0Ooo
 if 20 - 20: OoooooooOO * i1IIi * IiII / OoooooooOO - Oo0Ooo / i11iIiiIii
 if 28 - 28: iIii1I11I1II1 % OOooOOo * I1IiiI
 if 28 - 28: O0 . OoOoOO00
 if ( eid . is_binary ( ) == False ) : return ( eid )
 if 27 - 27: I1ii11iIi11i / II111iiii + O0 % I1ii11iIi11i
 IIi11iIi = lisp_address ( eid . afi , "" , 0 , 0 )
 IIi11iIi . copy_address ( eid )
 IIi11iIi . mask_len = 0
 if 72 - 72: I1IiiI - i1IIi
 ii1IiiIiIIIi = ddt_entry . print_eid_tuple ( )
 IIIi1iIiiI1 = ddt_entry . eid
 if 73 - 73: oO0o - o0oOOo0O0Ooo
 if 50 - 50: iIii1I11I1II1 - i11iIiiIii / iII111i + ooOoO0o / OOooOOo
 if 80 - 80: IiII / OoooooooOO
 if 69 - 69: OoOoOO00 + IiII
 if 18 - 18: O0 / I11i
 eid , IIIi1iIiiI1 , IIi11iIi = cache . walk_cache ( lisp_neg_prefix_walk ,
 ( eid , IIIi1iIiiI1 , IIi11iIi ) )
 if 10 - 10: I1Ii111 * i1IIi
 if 48 - 48: Oo0Ooo % i1IIi / iII111i . O0
 if 27 - 27: I11i + iIii1I11I1II1 - i11iIiiIii
 if 81 - 81: I11i + oO0o * iIii1I11I1II1 * IiII
 IIi11iIi . mask_address ( IIi11iIi . mask_len )
 if 7 - 7: I11i - I1IiiI . iII111i + O0 / iIii1I11I1II1 - I1Ii111
 lprint ( ( "Least specific prefix computed from ddt-cache for EID {} " + "using auth-prefix {} is {}" ) . format ( green ( eid . print_address ( ) , False ) ,
 # ooOoO0o . O0
 ii1IiiIiIIIi , IIi11iIi . print_prefix ( ) ) )
 return ( IIi11iIi )
 if 5 - 5: OoooooooOO % OoooooooOO * oO0o * ooOoO0o + ooOoO0o * oO0o
 if 12 - 12: IiII - II111iiii
 if 71 - 71: i11iIiiIii . Oo0Ooo + oO0o + oO0o
 if 97 - 97: i11iIiiIii / O0 . iII111i . iIii1I11I1II1
 if 40 - 40: OoOoOO00 / iII111i / O0 * ooOoO0o
 if 58 - 58: iII111i % I11i
 if 71 - 71: I1IiiI + OoO0O00 + IiII * I11i
 if 61 - 61: I1IiiI / OoOoOO00
def lisp_ms_compute_neg_prefix ( eid , group ) :
 IIi11iIi = lisp_address ( eid . afi , "" , 0 , 0 )
 IIi11iIi . copy_address ( eid )
 IIi11iIi . mask_len = 0
 OO0OOO0oO = lisp_address ( group . afi , "" , 0 , 0 )
 OO0OOO0oO . copy_address ( group )
 OO0OOO0oO . mask_len = 0
 IIIi1iIiiI1 = None
 if 22 - 22: iIii1I11I1II1 % i11iIiiIii
 if 29 - 29: ooOoO0o - iII111i + IiII % Ii1I - oO0o - ooOoO0o
 if 43 - 43: oO0o
 if 22 - 22: I1Ii111 + i11iIiiIii
 if 49 - 49: O0 % II111iiii . OOooOOo + iII111i + iIii1I11I1II1 / i11iIiiIii
 if ( group . is_null ( ) ) :
  oO0O000oOOOOo = lisp_ddt_cache . lookup_cache ( eid , False )
  if ( oO0O000oOOOOo == None ) :
   IIi11iIi . mask_len = IIi11iIi . host_mask_len ( )
   OO0OOO0oO . mask_len = OO0OOO0oO . host_mask_len ( )
   return ( [ IIi11iIi , OO0OOO0oO , LISP_DDT_ACTION_NOT_AUTH ] )
   if 79 - 79: II111iiii + ooOoO0o - i1IIi - i1IIi + II111iiii . i1IIi
  Oo00O0O0Oo0o0 = lisp_sites_by_eid
  if ( oO0O000oOOOOo . is_auth_prefix ( ) ) : IIIi1iIiiI1 = oO0O000oOOOOo . eid
 else :
  oO0O000oOOOOo = lisp_ddt_cache . lookup_cache ( group , False )
  if ( oO0O000oOOOOo == None ) :
   IIi11iIi . mask_len = IIi11iIi . host_mask_len ( )
   OO0OOO0oO . mask_len = OO0OOO0oO . host_mask_len ( )
   return ( [ IIi11iIi , OO0OOO0oO , LISP_DDT_ACTION_NOT_AUTH ] )
   if 80 - 80: OoooooooOO * OoooooooOO . I1IiiI
  if ( oO0O000oOOOOo . is_auth_prefix ( ) ) : IIIi1iIiiI1 = oO0O000oOOOOo . group
  if 82 - 82: OoOoOO00 / oO0o - OoOoOO00 . I1IiiI
  group , IIIi1iIiiI1 , OO0OOO0oO = lisp_sites_by_eid . walk_cache ( lisp_neg_prefix_walk , ( group , IIIi1iIiiI1 , OO0OOO0oO ) )
  if 17 - 17: OoOoOO00
  if 76 - 76: I1ii11iIi11i - ooOoO0o % OoooooooOO / Oo0Ooo % IiII / ooOoO0o
  OO0OOO0oO . mask_address ( OO0OOO0oO . mask_len )
  if 57 - 57: O0
  lprint ( ( "Least specific prefix computed from site-cache for " + "group EID {} using auth-prefix {} is {}" ) . format ( group . print_address ( ) , IIIi1iIiiI1 . print_prefix ( ) if ( IIIi1iIiiI1 != None ) else "'not found'" ,
  # II111iiii - OoO0O00
  # II111iiii
  # I1ii11iIi11i
 OO0OOO0oO . print_prefix ( ) ) )
  if 9 - 9: iIii1I11I1II1
  Oo00O0O0Oo0o0 = oO0O000oOOOOo . source_cache
  if 57 - 57: i1IIi * OOooOOo
  if 35 - 35: I1Ii111 / Oo0Ooo * OoooooooOO / O0 / iIii1I11I1II1
  if 44 - 44: o0oOOo0O0Ooo / iIii1I11I1II1
  if 40 - 40: OoO0O00 / O0
  if 60 - 60: iIii1I11I1II1 / Oo0Ooo / oO0o + iII111i
 i11IIiI = LISP_DDT_ACTION_DELEGATION_HOLE if ( IIIi1iIiiI1 != None ) else LISP_DDT_ACTION_NOT_AUTH
 if 66 - 66: iIii1I11I1II1 . O0 * IiII . ooOoO0o + i1IIi
 if 83 - 83: o0oOOo0O0Ooo / II111iiii + I1IiiI - iII111i + OoO0O00
 if 67 - 67: I1Ii111 - OoOoOO00 . i11iIiiIii - I1Ii111 . i11iIiiIii
 if 25 - 25: I11i % I1Ii111 + Ii1I
 if 46 - 46: ooOoO0o + Oo0Ooo + oO0o / II111iiii . iIii1I11I1II1 * I1IiiI
 if 87 - 87: I11i + iIii1I11I1II1
 eid , IIIi1iIiiI1 , IIi11iIi = Oo00O0O0Oo0o0 . walk_cache ( lisp_neg_prefix_walk ,
 ( eid , IIIi1iIiiI1 , IIi11iIi ) )
 if 91 - 91: oO0o
 if 58 - 58: i11iIiiIii / Ii1I - OoooooooOO
 if 25 - 25: i1IIi * ooOoO0o % OOooOOo / I1IiiI
 if 75 - 75: i11iIiiIii
 IIi11iIi . mask_address ( IIi11iIi . mask_len )
 if 38 - 38: iIii1I11I1II1
 lprint ( ( "Least specific prefix computed from site-cache for EID {} " + "using auth-prefix {} is {}" ) . format ( green ( eid . print_address ( ) , False ) ,
 # OoO0O00 . I1IiiI % I11i * iII111i / OoOoOO00
 # I1Ii111
 IIIi1iIiiI1 . print_prefix ( ) if ( IIIi1iIiiI1 != None ) else "'not found'" , IIi11iIi . print_prefix ( ) ) )
 if 91 - 91: ooOoO0o / II111iiii % iIii1I11I1II1
 if 70 - 70: i1IIi - II111iiii / I1IiiI + OoooooooOO + i11iIiiIii / i1IIi
 return ( [ IIi11iIi , OO0OOO0oO , i11IIiI ] )
 if 80 - 80: i1IIi - iIii1I11I1II1 + OoooooooOO + ooOoO0o / IiII - I1ii11iIi11i
 if 90 - 90: I1IiiI * ooOoO0o - I11i + O0 - I11i
 if 59 - 59: OOooOOo % II111iiii
 if 30 - 30: i1IIi / I1ii11iIi11i
 if 4 - 4: Oo0Ooo
 if 31 - 31: IiII
 if 86 - 86: Oo0Ooo + IiII / o0oOOo0O0Ooo % OoOoOO00
 if 49 - 49: iIii1I11I1II1 % Oo0Ooo % I11i * Ii1I - OoO0O00
def lisp_ms_send_map_referral ( lisp_sockets , map_request , ecm_source , port ,
 action , eid_prefix , group_prefix ) :
 if 15 - 15: i11iIiiIii + o0oOOo0O0Ooo . Ii1I . I1IiiI
 ii1Ii = map_request . target_eid
 IiI1111i1i11I = map_request . target_group
 Iii1i11 = map_request . nonce
 if 8 - 8: iII111i % II111iiii + IiII
 if ( action == LISP_DDT_ACTION_MS_ACK ) : I1i = 1440
 if 5 - 5: i1IIi + II111iiii
 if 75 - 75: OOooOOo . IiII . I1IiiI + OoooooooOO
 if 35 - 35: I11i % i1IIi - I1ii11iIi11i . Oo0Ooo
 if 69 - 69: ooOoO0o * OoO0O00 % o0oOOo0O0Ooo * o0oOOo0O0Ooo
 o000OOO0 = lisp_map_referral ( )
 o000OOO0 . record_count = 1
 o000OOO0 . nonce = Iii1i11
 Oo0O0oo = o000OOO0 . encode ( )
 o000OOO0 . print_map_referral ( )
 if 35 - 35: I1IiiI . OOooOOo * OoO0O00 . I1ii11iIi11i - I1IiiI
 Ooooo0OO000o0 = False
 if 5 - 5: i1IIi * II111iiii
 if 64 - 64: I1IiiI * iIii1I11I1II1 % I1Ii111
 if 22 - 22: OoooooooOO + I1Ii111 . o0oOOo0O0Ooo * Oo0Ooo
 if 61 - 61: iIii1I11I1II1
 if 95 - 95: I1ii11iIi11i + IiII * Ii1I - IiII
 if 58 - 58: I1ii11iIi11i - oO0o % I11i * O0
 if ( action == LISP_DDT_ACTION_SITE_NOT_FOUND ) :
  eid_prefix , group_prefix , action = lisp_ms_compute_neg_prefix ( ii1Ii ,
 IiI1111i1i11I )
  I1i = 15
  if 43 - 43: OoOoOO00 + O0
 if ( action == LISP_DDT_ACTION_MS_NOT_REG ) : I1i = 1
 if ( action == LISP_DDT_ACTION_MS_ACK ) : I1i = 1440
 if ( action == LISP_DDT_ACTION_DELEGATION_HOLE ) : I1i = 15
 if ( action == LISP_DDT_ACTION_NOT_AUTH ) : I1i = 0
 if 71 - 71: ooOoO0o * I1IiiI / I1ii11iIi11i
 i1ii = False
 o0oOo0 = 0
 oO0O000oOOOOo = lisp_ddt_cache_lookup ( ii1Ii , IiI1111i1i11I , False )
 if ( oO0O000oOOOOo != None ) :
  o0oOo0 = len ( oO0O000oOOOOo . delegation_set )
  i1ii = oO0O000oOOOOo . is_ms_peer_entry ( )
  oO0O000oOOOOo . map_referrals_sent += 1
  if 59 - 59: OoOoOO00 . iIii1I11I1II1 / I1ii11iIi11i - OoO0O00 - OoOoOO00
  if 69 - 69: o0oOOo0O0Ooo
  if 67 - 67: OoO0O00 + iIii1I11I1II1
  if 20 - 20: OoOoOO00 + Oo0Ooo - OoOoOO00
  if 40 - 40: oO0o . O0 / IiII % I11i * i1IIi
 if ( action == LISP_DDT_ACTION_NOT_AUTH ) : Ooooo0OO000o0 = True
 if ( action in ( LISP_DDT_ACTION_MS_REFERRAL , LISP_DDT_ACTION_MS_ACK ) ) :
  Ooooo0OO000o0 = ( i1ii == False )
  if 75 - 75: Ii1I . o0oOOo0O0Ooo / I11i
  if 31 - 31: I11i + OOooOOo / I1IiiI / iIii1I11I1II1 + o0oOOo0O0Ooo
  if 76 - 76: i1IIi
  if 98 - 98: iII111i
  if 86 - 86: I1IiiI % OoO0O00 - O0 . I1Ii111 + ooOoO0o
 iIi1i1i1II1 = lisp_eid_record ( )
 iIi1i1i1II1 . rloc_count = o0oOo0
 iIi1i1i1II1 . authoritative = True
 iIi1i1i1II1 . action = action
 iIi1i1i1II1 . ddt_incomplete = Ooooo0OO000o0
 iIi1i1i1II1 . eid = eid_prefix
 iIi1i1i1II1 . group = group_prefix
 iIi1i1i1II1 . record_ttl = I1i
 if 88 - 88: I1Ii111 . O0 - oO0o + i1IIi % Oo0Ooo
 Oo0O0oo += iIi1i1i1II1 . encode ( )
 iIi1i1i1II1 . print_record ( "  " , True )
 if 39 - 39: I1Ii111 - I1IiiI
 if 18 - 18: i1IIi
 if 42 - 42: II111iiii - i1IIi . oO0o % OOooOOo % ooOoO0o - i11iIiiIii
 if 23 - 23: OOooOOo + iIii1I11I1II1 - i1IIi
 if ( o0oOo0 != 0 ) :
  for I1 in oO0O000oOOOOo . delegation_set :
   o000O = lisp_rloc_record ( )
   o000O . rloc = I1 . delegate_address
   o000O . priority = I1 . priority
   o000O . weight = I1 . weight
   o000O . mpriority = 255
   o000O . mweight = 0
   o000O . reach_bit = True
   Oo0O0oo += o000O . encode ( )
   o000O . print_record ( "    " )
   if 72 - 72: OOooOOo . I1IiiI * O0 + i11iIiiIii - iII111i
   if 79 - 79: o0oOOo0O0Ooo + I1ii11iIi11i
   if 46 - 46: I11i
   if 78 - 78: IiII / II111iiii
   if 55 - 55: Oo0Ooo
   if 80 - 80: o0oOOo0O0Ooo - I1Ii111 * O0 * iIii1I11I1II1
   if 59 - 59: I1ii11iIi11i + I11i / OoO0O00
 if ( map_request . nonce != 0 ) : port = LISP_CTRL_PORT
 lisp_send_map_referral ( lisp_sockets , Oo0O0oo , ecm_source , port )
 return
 if 36 - 36: o0oOOo0O0Ooo + ooOoO0o * I11i
 if 81 - 81: OOooOOo * I11i - I1ii11iIi11i
 if 82 - 82: I1ii11iIi11i * II111iiii - OoooooooOO % iII111i * I1IiiI % OoOoOO00
 if 81 - 81: I11i + o0oOOo0O0Ooo / iII111i
 if 35 - 35: ooOoO0o % I11i * I1ii11iIi11i
 if 10 - 10: OoO0O00 + OoooooooOO + I1Ii111
 if 57 - 57: Ii1I % Ii1I * Oo0Ooo % i11iIiiIii
 if 12 - 12: oO0o . Oo0Ooo . I1IiiI - i11iIiiIii / o0oOOo0O0Ooo
def lisp_send_negative_map_reply ( sockets , eid , group , nonce , dest , port , ttl ,
 xtr_id , pubsub ) :
 if 54 - 54: i11iIiiIii + I1Ii111 . I1Ii111 * I1ii11iIi11i % I1Ii111 - OoooooooOO
 lprint ( "Build negative Map-Reply EID-prefix {}, nonce 0x{} to ITR {}" . format ( lisp_print_eid_tuple ( eid , group ) , lisp_hex_string ( nonce ) ,
 # OoO0O00 - OoO0O00 * OoooooooOO / oO0o . i1IIi
 red ( dest . print_address ( ) , False ) ) )
 if 78 - 78: Oo0Ooo * i11iIiiIii + I1ii11iIi11i - OOooOOo
 i11IIiI = LISP_NATIVE_FORWARD_ACTION if group . is_null ( ) else LISP_DROP_ACTION
 if 35 - 35: iII111i / iII111i * OoOoOO00 - i11iIiiIii
 if 27 - 27: i1IIi / I11i + I1Ii111 . II111iiii * OoO0O00
 if 55 - 55: i1IIi % Ii1I - o0oOOo0O0Ooo - o0oOOo0O0Ooo
 if 6 - 6: i1IIi
 if 10 - 10: OoO0O00 % iIii1I11I1II1 * OoOoOO00 / i11iIiiIii - I1IiiI . O0
 if ( lisp_get_eid_hash ( eid ) != None ) :
  i11IIiI = LISP_SEND_MAP_REQUEST_ACTION
  if 2 - 2: II111iiii
  if 13 - 13: Ii1I % i11iIiiIii
 Oo0O0oo = lisp_build_map_reply ( eid , group , [ ] , nonce , i11IIiI , ttl , False ,
 None , False , False )
 if 3 - 3: ooOoO0o % OoOoOO00 * I1Ii111 - OoO0O00 / i1IIi % I1IiiI
 if 50 - 50: I1ii11iIi11i + iII111i
 if 64 - 64: oO0o
 if 11 - 11: o0oOOo0O0Ooo
 if ( pubsub ) :
  lisp_process_pubsub ( sockets , Oo0O0oo , eid , dest , port , nonce , ttl ,
 xtr_id )
 else :
  lisp_send_map_reply ( sockets , Oo0O0oo , dest , port )
  if 95 - 95: i1IIi . ooOoO0o . Oo0Ooo
 return
 if 13 - 13: OOooOOo - Oo0Ooo % O0 . I1Ii111
 if 66 - 66: I1IiiI + I11i
 if 58 - 58: I1ii11iIi11i
 if 7 - 7: oO0o - I11i
 if 59 - 59: Ii1I / o0oOOo0O0Ooo / OoO0O00 + IiII + i11iIiiIii
 if 64 - 64: o0oOOo0O0Ooo * IiII * IiII * iII111i % i11iIiiIii
 if 22 - 22: I1ii11iIi11i * II111iiii - OOooOOo % i11iIiiIii
def lisp_retransmit_ddt_map_request ( mr ) :
 i1Ii = mr . mr_source . print_address ( )
 OoOOO0O = mr . print_eid_tuple ( )
 Iii1i11 = mr . nonce
 if 35 - 35: I1IiiI . i1IIi
 if 83 - 83: iII111i
 if 51 - 51: OoO0O00
 if 45 - 45: I1ii11iIi11i + Ii1I * I1ii11iIi11i % Ii1I - O0 * OoooooooOO
 if 98 - 98: OoO0O00 / o0oOOo0O0Ooo . OoooooooOO % i11iIiiIii % Oo0Ooo + OoOoOO00
 if ( mr . last_request_sent_to ) :
  IiIIii1Ii = mr . last_request_sent_to . print_address ( )
  I11i1i = lisp_referral_cache_lookup ( mr . last_cached_prefix [ 0 ] ,
 mr . last_cached_prefix [ 1 ] , True )
  if ( I11i1i and I11i1i . referral_set . has_key ( IiIIii1Ii ) ) :
   I11i1i . referral_set [ IiIIii1Ii ] . no_responses += 1
   if 46 - 46: I11i + II111iiii * iII111i % ooOoO0o - I1IiiI
   if 73 - 73: I1ii11iIi11i * iIii1I11I1II1 . I1Ii111 - Ii1I
   if 11 - 11: I11i
   if 48 - 48: IiII / O0
   if 46 - 46: ooOoO0o + oO0o
   if 7 - 7: ooOoO0o * oO0o . i1IIi
   if 74 - 74: i1IIi * I11i + OoOoOO00 / OoO0O00 - oO0o / I11i
 if ( mr . retry_count == LISP_MAX_MAP_NOTIFY_RETRIES ) :
  lprint ( "DDT Map-Request retry limit reached for EID {}, nonce 0x{}" . format ( green ( OoOOO0O , False ) , lisp_hex_string ( Iii1i11 ) ) )
  if 90 - 90: IiII % I1ii11iIi11i % i1IIi
  mr . dequeue_map_request ( )
  return
  if 63 - 63: Ii1I . I1IiiI + IiII / OoOoOO00 + ooOoO0o - iIii1I11I1II1
  if 20 - 20: i1IIi % II111iiii . IiII % iIii1I11I1II1
 mr . retry_count += 1
 if 9 - 9: o0oOOo0O0Ooo
 IiiiI1 = green ( i1Ii , False )
 oOOoO0O = green ( OoOOO0O , False )
 lprint ( "Retransmit DDT {} from {}ITR {} EIDs: {} -> {}, nonce 0x{}" . format ( bold ( "Map-Request" , False ) , "P" if mr . from_pitr else "" ,
 # I11i % I1Ii111 % I1Ii111 + II111iiii * OoO0O00
 red ( mr . itr . print_address ( ) , False ) , IiiiI1 , oOOoO0O ,
 lisp_hex_string ( Iii1i11 ) ) )
 if 81 - 81: oO0o * OOooOOo . ooOoO0o + Ii1I + OOooOOo % OoO0O00
 if 10 - 10: iIii1I11I1II1 / OoooooooOO - II111iiii - I11i % ooOoO0o / i1IIi
 if 52 - 52: Ii1I * OoooooooOO * I1ii11iIi11i / O0 * o0oOOo0O0Ooo
 if 28 - 28: o0oOOo0O0Ooo . o0oOOo0O0Ooo . o0oOOo0O0Ooo
 lisp_send_ddt_map_request ( mr , False )
 if 93 - 93: i11iIiiIii / IiII
 if 35 - 35: I1Ii111 / o0oOOo0O0Ooo
 if 44 - 44: IiII % i11iIiiIii
 if 99 - 99: ooOoO0o % iIii1I11I1II1 + o0oOOo0O0Ooo % I11i
 mr . retransmit_timer = threading . Timer ( LISP_DDT_MAP_REQUEST_INTERVAL ,
 lisp_retransmit_ddt_map_request , [ mr ] )
 mr . retransmit_timer . start ( )
 return
 if 66 - 66: iIii1I11I1II1
 if 74 - 74: OoooooooOO - I1Ii111 - I1IiiI
 if 30 - 30: Oo0Ooo / o0oOOo0O0Ooo % o0oOOo0O0Ooo * i1IIi
 if 58 - 58: OoooooooOO - OOooOOo - OoOoOO00 / i1IIi * Oo0Ooo / i1IIi
 if 86 - 86: OoOoOO00 . I11i
 if 97 - 97: Ii1I
 if 24 - 24: I1IiiI * i11iIiiIii
 if 83 - 83: OoOoOO00 * I1ii11iIi11i
def lisp_get_referral_node ( referral , source_eid , dest_eid ) :
 if 64 - 64: II111iiii * i1IIi - ooOoO0o
 if 4 - 4: ooOoO0o . OoO0O00 . OoO0O00 % ooOoO0o * Oo0Ooo - I1IiiI
 if 8 - 8: I1IiiI - I1Ii111 - OoooooooOO * Oo0Ooo * Ii1I
 if 11 - 11: I1IiiI
 i1111iIiIi = [ ]
 for ii1I111ii in referral . referral_set . values ( ) :
  if ( ii1I111ii . updown == False ) : continue
  if ( len ( i1111iIiIi ) == 0 or i1111iIiIi [ 0 ] . priority == ii1I111ii . priority ) :
   i1111iIiIi . append ( ii1I111ii )
  elif ( i1111iIiIi [ 0 ] . priority > ii1I111ii . priority ) :
   i1111iIiIi = [ ]
   i1111iIiIi . append ( ii1I111ii )
   if 8 - 8: Oo0Ooo
   if 50 - 50: OoOoOO00 / iII111i * O0 . I1IiiI
   if 88 - 88: IiII / I1ii11iIi11i % I11i + i11iIiiIii * O0 . I1Ii111
 OOoOoO0oO = len ( i1111iIiIi )
 if ( OOoOoO0oO == 0 ) : return ( None )
 if 45 - 45: I1Ii111 + OOooOOo
 I1i1Ii = dest_eid . hash_address ( source_eid )
 I1i1Ii = I1i1Ii % OOoOoO0oO
 return ( i1111iIiIi [ I1i1Ii ] )
 if 78 - 78: OoOoOO00 . Oo0Ooo % I11i
 if 7 - 7: I1ii11iIi11i % Ii1I . OoooooooOO - iII111i
 if 18 - 18: O0 * OoooooooOO % IiII - iIii1I11I1II1 % IiII * o0oOOo0O0Ooo
 if 13 - 13: OoO0O00 + i11iIiiIii + O0 / ooOoO0o % iIii1I11I1II1
 if 75 - 75: oO0o / i1IIi / Ii1I * Oo0Ooo
 if 75 - 75: Oo0Ooo / OoooooooOO
 if 98 - 98: II111iiii - I1Ii111 . ooOoO0o * iII111i
def lisp_send_ddt_map_request ( mr , send_to_root ) :
 iIIi1 = mr . lisp_sockets
 Iii1i11 = mr . nonce
 oo0Oo0oo = mr . itr
 OoiiII1 = mr . mr_source
 oo0oO = mr . print_eid_tuple ( )
 if 60 - 60: I1IiiI
 if 3 - 3: II111iiii % IiII % I1IiiI - I1IiiI . I1Ii111 - OoOoOO00
 if 18 - 18: O0
 if 26 - 26: i1IIi - iIii1I11I1II1
 if 8 - 8: I1Ii111
 if ( mr . send_count == 8 ) :
  lprint ( "Giving up on map-request-queue entry {}, nonce 0x{}" . format ( green ( oo0oO , False ) , lisp_hex_string ( Iii1i11 ) ) )
  if 86 - 86: i1IIi
  mr . dequeue_map_request ( )
  return
  if 26 - 26: o0oOOo0O0Ooo % I1Ii111 / Oo0Ooo
  if 68 - 68: II111iiii / Oo0Ooo / Oo0Ooo
  if 1 - 1: Oo0Ooo
  if 73 - 73: Ii1I * iIii1I11I1II1 / o0oOOo0O0Ooo - o0oOOo0O0Ooo / i1IIi
  if 64 - 64: Ii1I * I1ii11iIi11i % II111iiii
  if 31 - 31: iIii1I11I1II1 % Oo0Ooo . I1IiiI % ooOoO0o
 if ( send_to_root ) :
  II11i1I = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  Ii1IiiI = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  mr . tried_root = True
  lprint ( "Jumping up to root for EID {}" . format ( green ( oo0oO , False ) ) )
 else :
  II11i1I = mr . eid
  Ii1IiiI = mr . group
  if 27 - 27: o0oOOo0O0Ooo * i1IIi % oO0o / ooOoO0o
  if 25 - 25: IiII % o0oOOo0O0Ooo + o0oOOo0O0Ooo
  if 35 - 35: iII111i % IiII
  if 30 - 30: II111iiii . OoOoOO00 % OoOoOO00 % I11i / IiII / OoO0O00
  if 47 - 47: oO0o - I1ii11iIi11i
 II11IIIIi = lisp_referral_cache_lookup ( II11i1I , Ii1IiiI , False )
 if ( II11IIIIi == None ) :
  lprint ( "No referral cache entry found" )
  lisp_send_negative_map_reply ( iIIi1 , II11i1I , Ii1IiiI ,
 Iii1i11 , oo0Oo0oo , mr . sport , 15 , None , False )
  return
  if 93 - 93: II111iiii % i1IIi + o0oOOo0O0Ooo * iII111i
  if 59 - 59: I11i - iIii1I11I1II1 / ooOoO0o % oO0o / i1IIi / OoOoOO00
 o0O = II11IIIIi . print_eid_tuple ( )
 lprint ( "Found referral cache entry {}, referral-type: {}" . format ( o0O ,
 II11IIIIi . print_referral_type ( ) ) )
 if 51 - 51: OOooOOo % I1Ii111 + Oo0Ooo - o0oOOo0O0Ooo
 ii1I111ii = lisp_get_referral_node ( II11IIIIi , OoiiII1 , mr . eid )
 if ( ii1I111ii == None ) :
  lprint ( "No reachable referral-nodes found" )
  mr . dequeue_map_request ( )
  lisp_send_negative_map_reply ( iIIi1 , II11IIIIi . eid ,
 II11IIIIi . group , Iii1i11 , oo0Oo0oo , mr . sport , 1 , None , False )
  return
  if 19 - 19: O0 / o0oOOo0O0Ooo . I1IiiI
  if 100 - 100: I1Ii111 + iIii1I11I1II1 . OoOoOO00 / iII111i . iIii1I11I1II1 - Ii1I
 lprint ( "Send DDT Map-Request to {} {} for EID {}, nonce 0x{}" . format ( ii1I111ii . referral_address . print_address ( ) ,
 # OoOoOO00 . oO0o - Oo0Ooo - II111iiii - I1ii11iIi11i * oO0o
 II11IIIIi . print_referral_type ( ) , green ( oo0oO , False ) ,
 lisp_hex_string ( Iii1i11 ) ) )
 if 41 - 41: I11i / ooOoO0o + IiII % OoooooooOO
 if 72 - 72: Ii1I
 if 22 - 22: o0oOOo0O0Ooo / OoO0O00 + OoOoOO00 + Ii1I . II111iiii * I11i
 if 85 - 85: i11iIiiIii / I11i
 Iii1i1 = ( II11IIIIi . referral_type == LISP_DDT_ACTION_MS_REFERRAL or
 II11IIIIi . referral_type == LISP_DDT_ACTION_MS_ACK )
 lisp_send_ecm ( iIIi1 , mr . packet , OoiiII1 , mr . sport , mr . eid ,
 ii1I111ii . referral_address , to_ms = Iii1i1 , ddt = True )
 if 32 - 32: ooOoO0o + I1ii11iIi11i + OoooooooOO - o0oOOo0O0Ooo % IiII
 if 75 - 75: i1IIi + II111iiii
 if 100 - 100: I11i - IiII . IiII . OoOoOO00 * OoooooooOO
 if 42 - 42: ooOoO0o * I1Ii111 + iII111i - iII111i
 mr . last_request_sent_to = ii1I111ii . referral_address
 mr . last_sent = lisp_get_timestamp ( )
 mr . send_count += 1
 ii1I111ii . map_requests_sent += 1
 return
 if 71 - 71: i1IIi * I1Ii111 % iII111i * ooOoO0o / iIii1I11I1II1 % oO0o
 if 60 - 60: OoOoOO00 % I1IiiI . i11iIiiIii % OoOoOO00 - I1Ii111
 if 71 - 71: OoooooooOO * Oo0Ooo
 if 80 - 80: iIii1I11I1II1
 if 91 - 91: OoOoOO00 + OoOoOO00 + ooOoO0o
 if 44 - 44: I1ii11iIi11i * OOooOOo % OoO0O00 . I1IiiI % Ii1I + II111iiii
 if 100 - 100: oO0o - II111iiii . o0oOOo0O0Ooo
 if 63 - 63: OoOoOO00 % IiII . iII111i
def lisp_mr_process_map_request ( lisp_sockets , packet , map_request , ecm_source ,
 sport , mr_source ) :
 if 44 - 44: I1IiiI
 ii1Ii = map_request . target_eid
 IiI1111i1i11I = map_request . target_group
 OoOOO0O = map_request . print_eid_tuple ( )
 i1Ii = mr_source . print_address ( )
 Iii1i11 = map_request . nonce
 if 25 - 25: oO0o
 IiiiI1 = green ( i1Ii , False )
 oOOoO0O = green ( OoOOO0O , False )
 lprint ( "Received Map-Request from {}ITR {} EIDs: {} -> {}, nonce 0x{}" . format ( "P" if map_request . pitr_bit else "" ,
 # I1IiiI - OoO0O00 / iIii1I11I1II1 * iII111i + OoOoOO00 + IiII
 red ( ecm_source . print_address ( ) , False ) , IiiiI1 , oOOoO0O ,
 lisp_hex_string ( Iii1i11 ) ) )
 if 16 - 16: OoO0O00 % OOooOOo . I11i . I11i
 if 4 - 4: O0 + I11i / OoOoOO00 * iIii1I11I1II1 . Ii1I
 if 68 - 68: Oo0Ooo % ooOoO0o + i11iIiiIii / oO0o / II111iiii
 if 63 - 63: OoO0O00 % i1IIi - OoooooooOO / ooOoO0o
 OOO0o0o = lisp_ddt_map_request ( lisp_sockets , packet , ii1Ii , IiI1111i1i11I , Iii1i11 )
 OOO0o0o . packet = packet
 OOO0o0o . itr = ecm_source
 OOO0o0o . mr_source = mr_source
 OOO0o0o . sport = sport
 OOO0o0o . from_pitr = map_request . pitr_bit
 OOO0o0o . queue_map_request ( )
 if 34 - 34: Oo0Ooo . iII111i
 lisp_send_ddt_map_request ( OOO0o0o , False )
 return
 if 86 - 86: I1ii11iIi11i * I1IiiI / OoO0O00 + i11iIiiIii / i11iIiiIii
 if 74 - 74: i11iIiiIii * OoooooooOO * i11iIiiIii * Oo0Ooo
 if 50 - 50: iIii1I11I1II1 / I1Ii111 / iII111i - o0oOOo0O0Ooo * OoO0O00
 if 18 - 18: I1ii11iIi11i - i1IIi * i11iIiiIii + I1IiiI - Oo0Ooo + OoOoOO00
 if 77 - 77: OOooOOo % IiII + IiII / II111iiii
 if 34 - 34: ooOoO0o
 if 46 - 46: II111iiii % IiII
def lisp_process_map_request ( lisp_sockets , packet , ecm_source , ecm_port ,
 mr_source , mr_port , ddt_request , ttl ) :
 if 53 - 53: O0
 oOoo0O000 = packet
 ooo = lisp_map_request ( )
 packet = ooo . decode ( packet , mr_source , mr_port )
 if ( packet == None ) :
  lprint ( "Could not decode Map-Request packet" )
  return
  if 77 - 77: O0 % OOooOOo . I1Ii111
  if 78 - 78: iIii1I11I1II1 % OOooOOo
 ooo . print_map_request ( )
 if 27 - 27: I11i + ooOoO0o - II111iiii . OoooooooOO % O0 % I1ii11iIi11i
 if 28 - 28: IiII - i1IIi - I1Ii111 % Ii1I - IiII
 if 73 - 73: iIii1I11I1II1 . iIii1I11I1II1 + oO0o % i11iIiiIii . IiII
 if 33 - 33: IiII - OOooOOo / i11iIiiIii * iIii1I11I1II1
 if ( ooo . rloc_probe ) :
  lisp_process_rloc_probe_request ( lisp_sockets , ooo ,
 mr_source , mr_port , ttl )
  return
  if 2 - 2: i11iIiiIii % ooOoO0o
  if 56 - 56: IiII % ooOoO0o + I1IiiI % I11i - OOooOOo
  if 82 - 82: OoooooooOO . i1IIi . OoO0O00 . OoO0O00
  if 31 - 31: iIii1I11I1II1
  if 64 - 64: ooOoO0o
 if ( ooo . smr_bit ) :
  lisp_process_smr ( ooo )
  if 30 - 30: OoO0O00 + o0oOOo0O0Ooo / iIii1I11I1II1
  if 69 - 69: IiII - OoooooooOO + iII111i + iII111i - Ii1I
  if 27 - 27: I1ii11iIi11i % Oo0Ooo * iIii1I11I1II1 * O0 / I11i * Oo0Ooo
  if 97 - 97: IiII % Oo0Ooo % OoOoOO00
  if 87 - 87: i11iIiiIii . oO0o * I1IiiI * I1Ii111
 if ( ooo . smr_invoked_bit ) :
  lisp_process_smr_invoked_request ( ooo )
  if 57 - 57: iIii1I11I1II1 / i11iIiiIii / IiII + I1ii11iIi11i % I1IiiI
  if 80 - 80: iIii1I11I1II1
  if 23 - 23: II111iiii . ooOoO0o % I1Ii111
  if 39 - 39: OoooooooOO
  if 10 - 10: Oo0Ooo * iII111i
 if ( lisp_i_am_etr ) :
  lisp_etr_process_map_request ( lisp_sockets , ooo , mr_source ,
 mr_port , ttl )
  if 78 - 78: Oo0Ooo / i11iIiiIii - I1IiiI
  if 51 - 51: ooOoO0o / Oo0Ooo - I1Ii111 - iII111i
  if 68 - 68: I1ii11iIi11i - iIii1I11I1II1 * OoooooooOO
  if 44 - 44: OoooooooOO + I1Ii111 + OoO0O00
  if 15 - 15: iIii1I11I1II1 % i1IIi + iII111i
 if ( lisp_i_am_ms ) :
  packet = oOoo0O000
  ii1Ii , IiI1111i1i11I , iIII1 = lisp_ms_process_map_request ( lisp_sockets ,
 oOoo0O000 , ooo , mr_source , mr_port , ecm_source )
  if ( ddt_request ) :
   lisp_ms_send_map_referral ( lisp_sockets , ooo , ecm_source ,
 ecm_port , iIII1 , ii1Ii , IiI1111i1i11I )
   if 35 - 35: iII111i * Ii1I % i11iIiiIii
  return
  if 91 - 91: iII111i % i11iIiiIii * OoOoOO00 * i11iIiiIii % iIii1I11I1II1
  if 30 - 30: I11i . I1ii11iIi11i - i1IIi / i1IIi + IiII . oO0o
  if 70 - 70: i1IIi . I11i * o0oOOo0O0Ooo . iII111i
  if 75 - 75: oO0o * OoO0O00 * I11i + oO0o + O0 . I1Ii111
  if 8 - 8: I1ii11iIi11i / i1IIi - I1ii11iIi11i + Ii1I + OoO0O00 - I11i
 if ( lisp_i_am_mr and not ddt_request ) :
  lisp_mr_process_map_request ( lisp_sockets , oOoo0O000 , ooo ,
 ecm_source , mr_port , mr_source )
  if 79 - 79: OoooooooOO - I1Ii111 * I1IiiI . I1Ii111 - iIii1I11I1II1
  if 27 - 27: OoOoOO00 % OoOoOO00 % II111iiii
  if 45 - 45: iIii1I11I1II1 . o0oOOo0O0Ooo % I1IiiI
  if 10 - 10: I1IiiI / i1IIi * o0oOOo0O0Ooo + Oo0Ooo - OoOoOO00 % iII111i
  if 88 - 88: Ii1I % Ii1I
 if ( lisp_i_am_ddt or ddt_request ) :
  packet = oOoo0O000
  lisp_ddt_process_map_request ( lisp_sockets , ooo , ecm_source ,
 ecm_port )
  if 29 - 29: OOooOOo % I1ii11iIi11i
 return
 if 57 - 57: I1ii11iIi11i - OoOoOO00 + IiII
 if 58 - 58: OOooOOo % I1IiiI / oO0o . ooOoO0o . OoO0O00 / IiII
 if 72 - 72: ooOoO0o + ooOoO0o + o0oOOo0O0Ooo - o0oOOo0O0Ooo % Ii1I
 if 52 - 52: I11i % i1IIi . I1ii11iIi11i
 if 62 - 62: ooOoO0o - I1ii11iIi11i
 if 71 - 71: I11i
 if 34 - 34: oO0o / O0 * oO0o
 if 47 - 47: iIii1I11I1II1 - o0oOOo0O0Ooo % Ii1I
def lisp_store_mr_stats ( source , nonce ) :
 OOO0o0o = lisp_get_map_resolver ( source , None )
 if ( OOO0o0o == None ) : return
 if 38 - 38: ooOoO0o / IiII * I1ii11iIi11i % I1ii11iIi11i % oO0o
 if 82 - 82: I1ii11iIi11i . i11iIiiIii - I11i . iII111i / OOooOOo
 if 60 - 60: I1IiiI / I1IiiI / II111iiii
 if 59 - 59: OOooOOo . oO0o + ooOoO0o % o0oOOo0O0Ooo . i11iIiiIii
 OOO0o0o . neg_map_replies_received += 1
 OOO0o0o . last_reply = lisp_get_timestamp ( )
 if 27 - 27: OoOoOO00 - OoooooooOO / IiII / II111iiii * OOooOOo * ooOoO0o
 if 43 - 43: II111iiii . IiII - I1IiiI * I1ii11iIi11i + OoooooooOO
 if 34 - 34: I1Ii111 / i1IIi
 if 95 - 95: OoOoOO00 * OOooOOo
 if ( ( OOO0o0o . neg_map_replies_received % 100 ) == 0 ) : OOO0o0o . total_rtt = 0
 if 68 - 68: I1Ii111 / iIii1I11I1II1 % Ii1I
 if 77 - 77: i11iIiiIii + i11iIiiIii - I1ii11iIi11i % I1ii11iIi11i
 if 26 - 26: oO0o + OoooooooOO % o0oOOo0O0Ooo
 if 96 - 96: ooOoO0o * OoOoOO00 - II111iiii
 if ( OOO0o0o . last_nonce == nonce ) :
  OOO0o0o . total_rtt += ( time . time ( ) - OOO0o0o . last_used )
  OOO0o0o . last_nonce = 0
  if 40 - 40: oO0o * OOooOOo + Ii1I + I11i * Ii1I + OoooooooOO
 if ( ( OOO0o0o . neg_map_replies_received % 10 ) == 0 ) : OOO0o0o . last_nonce = 0
 return
 if 77 - 77: OOooOOo + ooOoO0o / O0
 if 16 - 16: ooOoO0o + Oo0Ooo * Oo0Ooo . I11i - IiII
 if 49 - 49: ooOoO0o . Ii1I
 if 75 - 75: OOooOOo / II111iiii - Oo0Ooo + I1Ii111
 if 42 - 42: OoooooooOO * II111iiii + Ii1I % OoO0O00 / I1Ii111
 if 11 - 11: ooOoO0o / Oo0Ooo + i1IIi / IiII
 if 4 - 4: iII111i - Oo0Ooo
def lisp_process_map_reply ( lisp_sockets , packet , source , ttl ) :
 global lisp_map_cache
 if 100 - 100: OOooOOo . i1IIi
 oO0ooOo0O = lisp_map_reply ( )
 packet = oO0ooOo0O . decode ( packet )
 if ( packet == None ) :
  lprint ( "Could not decode Map-Reply packet" )
  return
  if 15 - 15: O0 % Oo0Ooo % o0oOOo0O0Ooo . ooOoO0o * iII111i % O0
 oO0ooOo0O . print_map_reply ( )
 if 31 - 31: i1IIi . Ii1I - OoooooooOO * I11i * ooOoO0o % oO0o
 if 61 - 61: I1Ii111 . Ii1I * I1ii11iIi11i
 if 59 - 59: OoOoOO00 + Oo0Ooo . I1ii11iIi11i - Ii1I
 if 48 - 48: I1Ii111 % Ii1I + I1IiiI * OoooooooOO % OoOoOO00 % i11iIiiIii
 i1iiIi1Iii1 = None
 for o0OoO00 in range ( oO0ooOo0O . record_count ) :
  iIi1i1i1II1 = lisp_eid_record ( )
  packet = iIi1i1i1II1 . decode ( packet )
  if ( packet == None ) :
   lprint ( "Could not decode EID-record in Map-Reply packet" )
   return
   if 85 - 85: OoOoOO00 + OOooOOo
  iIi1i1i1II1 . print_record ( "  " , False )
  if 75 - 75: OoooooooOO - Oo0Ooo - Oo0Ooo % O0 + ooOoO0o + Oo0Ooo
  if 56 - 56: i1IIi
  if 37 - 37: I1IiiI % i11iIiiIii + OoO0O00 * OOooOOo . o0oOOo0O0Ooo % IiII
  if 18 - 18: Oo0Ooo % IiII . OoOoOO00 - IiII + I1Ii111 + oO0o
  if 31 - 31: OOooOOo + OoOoOO00 * OOooOOo + OoOoOO00 / o0oOOo0O0Ooo . iIii1I11I1II1
  if ( iIi1i1i1II1 . rloc_count == 0 ) :
   lisp_store_mr_stats ( source , oO0ooOo0O . nonce )
   if 1 - 1: I1Ii111 * i11iIiiIii % I1Ii111 - OoO0O00 + I1Ii111 / Oo0Ooo
   if 3 - 3: OOooOOo - i11iIiiIii / I1Ii111 . OOooOOo - OoO0O00
  OOooO = ( iIi1i1i1II1 . group . is_null ( ) == False )
  if 78 - 78: OoooooooOO + oO0o + I1IiiI + I1Ii111
  if 24 - 24: I11i + i1IIi + I1ii11iIi11i * OoooooooOO * IiII
  if 70 - 70: iIii1I11I1II1 / I1IiiI * OoOoOO00 / IiII / II111iiii + I1IiiI
  if 33 - 33: oO0o
  if 1 - 1: OoOoOO00 . i11iIiiIii % I1Ii111 + OoooooooOO - Oo0Ooo . I1ii11iIi11i
  if ( lisp_decent_push_configured ) :
   i11IIiI = iIi1i1i1II1 . action
   if ( OOooO and i11IIiI == LISP_DROP_ACTION ) :
    if ( iIi1i1i1II1 . eid . is_local ( ) ) : continue
    if 46 - 46: i11iIiiIii + I11i - iIii1I11I1II1 / OoO0O00 - ooOoO0o / i1IIi
    if 44 - 44: o0oOOo0O0Ooo + Oo0Ooo
    if 46 - 46: OOooOOo % I1IiiI
    if 66 - 66: iIii1I11I1II1 . o0oOOo0O0Ooo - ooOoO0o
    if 27 - 27: Oo0Ooo - i1IIi * OoooooooOO - OoOoOO00 + OoOoOO00
    if 24 - 24: i1IIi . OoOoOO00 / I1Ii111 + O0
    if 86 - 86: Ii1I * OoOoOO00 % I1ii11iIi11i + OOooOOo
  if ( iIi1i1i1II1 . eid . is_null ( ) ) : continue
  if 85 - 85: iII111i % i11iIiiIii
  if 78 - 78: i11iIiiIii / I11i / Oo0Ooo + II111iiii - I1ii11iIi11i / I1ii11iIi11i
  if 28 - 28: iIii1I11I1II1 / IiII - iIii1I11I1II1 . i1IIi - O0 * ooOoO0o
  if 41 - 41: Ii1I + IiII
  if 37 - 37: I1Ii111 / o0oOOo0O0Ooo - ooOoO0o - OoooooooOO . I1ii11iIi11i % I1Ii111
  if ( OOooO ) :
   OoOOO000O0o = lisp_map_cache_lookup ( iIi1i1i1II1 . eid , iIi1i1i1II1 . group )
  else :
   OoOOO000O0o = lisp_map_cache . lookup_cache ( iIi1i1i1II1 . eid , True )
   if 59 - 59: oO0o / i1IIi - OoO0O00
  iII1111 = ( OoOOO000O0o == None )
  if 76 - 76: ooOoO0o / OoO0O00 - Oo0Ooo . IiII * I11i
  if 98 - 98: i11iIiiIii % i1IIi + I1Ii111 / iIii1I11I1II1 + o0oOOo0O0Ooo
  if 35 - 35: oO0o . I11i % OoO0O00
  if 13 - 13: I1ii11iIi11i / ooOoO0o * I1Ii111
  O0Oo0O = [ ]
  for iI1I1I111 in range ( iIi1i1i1II1 . rloc_count ) :
   o000O = lisp_rloc_record ( )
   o000O . keys = oO0ooOo0O . keys
   packet = o000O . decode ( packet , oO0ooOo0O . nonce )
   if ( packet == None ) :
    lprint ( "Could not decode RLOC-record in Map-Reply packet" )
    return
    if 31 - 31: Ii1I % iII111i % Oo0Ooo
   o000O . print_record ( "    " )
   if 75 - 75: iIii1I11I1II1 - IiII - I1Ii111
   iiiiiIIiii = None
   if ( OoOOO000O0o ) : iiiiiIIiii = OoOOO000O0o . get_rloc ( o000O . rloc )
   if ( iiiiiIIiii ) :
    o0OOooooooOO = iiiiiIIiii
   else :
    o0OOooooooOO = lisp_rloc ( )
    if 39 - 39: i11iIiiIii + I1Ii111
    if 49 - 49: i1IIi * iII111i - iIii1I11I1II1 % I11i * O0 / OoOoOO00
    if 48 - 48: IiII
    if 69 - 69: o0oOOo0O0Ooo % i11iIiiIii - OOooOOo - o0oOOo0O0Ooo
    if 98 - 98: o0oOOo0O0Ooo * OoO0O00 . OoooooooOO
    if 40 - 40: I1Ii111 + Oo0Ooo + I1Ii111
    if 57 - 57: I1Ii111 / II111iiii % iII111i
   Ii1 = o0OOooooooOO . store_rloc_from_record ( o000O , oO0ooOo0O . nonce ,
 source )
   o0OOooooooOO . echo_nonce_capable = oO0ooOo0O . echo_nonce_capable
   if 32 - 32: IiII - OOooOOo + i11iIiiIii + I1IiiI . iII111i
   if ( o0OOooooooOO . echo_nonce_capable ) :
    I1IIII1i1 = o0OOooooooOO . rloc . print_address_no_iid ( )
    if ( lisp_get_echo_nonce ( None , I1IIII1i1 ) == None ) :
     lisp_echo_nonce ( I1IIII1i1 )
     if 75 - 75: o0oOOo0O0Ooo % o0oOOo0O0Ooo . I1IiiI / OoO0O00
     if 22 - 22: Oo0Ooo / iIii1I11I1II1 + o0oOOo0O0Ooo
     if 16 - 16: II111iiii . Ii1I + I1Ii111 % i1IIi / i11iIiiIii + OOooOOo
     if 43 - 43: I1IiiI . Oo0Ooo + i1IIi + I11i / OoO0O00
     if 66 - 66: i11iIiiIii
     if 83 - 83: I1Ii111 / iIii1I11I1II1 - oO0o
     if 3 - 3: OOooOOo - Oo0Ooo * I1IiiI - OoO0O00 / OOooOOo + IiII
   if ( OoOOO000O0o and OoOOO000O0o . gleaned ) :
    o0OOooooooOO = OoOOO000O0o . rloc_set [ 0 ]
    Ii1 = o0OOooooooOO . translated_port
    if 83 - 83: i1IIi * i1IIi - II111iiii / OoooooooOO . Ii1I + I1Ii111
    if 10 - 10: I11i
    if 24 - 24: Ii1I
    if 30 - 30: II111iiii / Ii1I - I11i - OoO0O00
    if 25 - 25: I11i % i1IIi / I11i * i11iIiiIii
    if 71 - 71: IiII % I11i - OoooooooOO + I1IiiI / Oo0Ooo % I11i
    if 6 - 6: i1IIi * i11iIiiIii + ooOoO0o - IiII
    if 97 - 97: iIii1I11I1II1 * i1IIi * II111iiii - OOooOOo - Oo0Ooo - iIii1I11I1II1
    if 26 - 26: ooOoO0o + Oo0Ooo
   if ( oO0ooOo0O . rloc_probe and o000O . probe_bit ) :
    if ( o0OOooooooOO . rloc . afi == source . afi ) :
     lisp_process_rloc_probe_reply ( o0OOooooooOO . rloc , source , Ii1 ,
 oO0ooOo0O . nonce , oO0ooOo0O . hop_count , ttl )
     if 24 - 24: I1IiiI
     if 43 - 43: OoO0O00
     if 51 - 51: OoooooooOO % IiII % Oo0Ooo
     if 50 - 50: I1IiiI - i11iIiiIii / I1ii11iIi11i . Ii1I - iIii1I11I1II1
     if 91 - 91: I1IiiI . I1Ii111 + II111iiii . Oo0Ooo
     if 95 - 95: iII111i
   O0Oo0O . append ( o0OOooooooOO )
   if 77 - 77: I1IiiI * II111iiii * iIii1I11I1II1
   if 19 - 19: OOooOOo * o0oOOo0O0Ooo
   if 64 - 64: I11i % ooOoO0o / OOooOOo / iII111i
   if 80 - 80: i1IIi
   if ( lisp_data_plane_security and o0OOooooooOO . rloc_recent_rekey ( ) ) :
    i1iiIi1Iii1 = o0OOooooooOO
    if 74 - 74: I1ii11iIi11i . OoO0O00 + i11iIiiIii
    if 19 - 19: i1IIi / I1IiiI + IiII . iII111i
    if 68 - 68: iII111i
    if 29 - 29: II111iiii / II111iiii % OoO0O00 % Oo0Ooo . II111iiii
    if 33 - 33: OoooooooOO . OoO0O00 % OoooooooOO
    if 9 - 9: IiII * O0 + OOooOOo . II111iiii
    if 14 - 14: iIii1I11I1II1 + i11iIiiIii + o0oOOo0O0Ooo + o0oOOo0O0Ooo - IiII / I1Ii111
    if 70 - 70: OoooooooOO + I1IiiI / OOooOOo
    if 19 - 19: I1Ii111 + i1IIi % OoooooooOO + i1IIi
    if 16 - 16: I1Ii111 + II111iiii + IiII
    if 34 - 34: iIii1I11I1II1 - II111iiii - ooOoO0o + oO0o
  if ( oO0ooOo0O . rloc_probe == False and lisp_nat_traversal ) :
   oOoo0oOOO0o = [ ]
   i1iIiiII1i = [ ]
   for o0OOooooooOO in O0Oo0O :
    if 87 - 87: OoO0O00 * iII111i / i11iIiiIii * i1IIi % oO0o
    if 90 - 90: OoooooooOO / Oo0Ooo / I11i * i1IIi
    if 11 - 11: i1IIi . i1IIi . OOooOOo
    if 23 - 23: Ii1I - OOooOOo
    if 89 - 89: i11iIiiIii
    if ( o0OOooooooOO . rloc . is_private_address ( ) ) :
     o0OOooooooOO . priority = 1
     o0OOooooooOO . state = LISP_RLOC_UNREACH_STATE
     oOoo0oOOO0o . append ( o0OOooooooOO )
     i1iIiiII1i . append ( o0OOooooooOO . rloc . print_address_no_iid ( ) )
     continue
     if 40 - 40: OoooooooOO % OoO0O00
     if 54 - 54: i1IIi * OOooOOo - oO0o * OoooooooOO + II111iiii . IiII
     if 90 - 90: O0 - II111iiii + I1IiiI . iII111i
     if 3 - 3: o0oOOo0O0Ooo + i1IIi * Oo0Ooo
     if 6 - 6: OoO0O00 * OoooooooOO * iIii1I11I1II1
     if 87 - 87: iIii1I11I1II1 - ooOoO0o * iIii1I11I1II1
    if ( o0OOooooooOO . priority == 254 and lisp_i_am_rtr == False ) :
     oOoo0oOOO0o . append ( o0OOooooooOO )
     i1iIiiII1i . append ( o0OOooooooOO . rloc . print_address_no_iid ( ) )
     if 79 - 79: ooOoO0o . oO0o + Ii1I * ooOoO0o + O0 . II111iiii
    if ( o0OOooooooOO . priority != 254 and lisp_i_am_rtr ) :
     oOoo0oOOO0o . append ( o0OOooooooOO )
     i1iIiiII1i . append ( o0OOooooooOO . rloc . print_address_no_iid ( ) )
     if 8 - 8: IiII * OOooOOo + I11i + O0 * oO0o - oO0o
     if 19 - 19: OoO0O00 - ooOoO0o + I1ii11iIi11i / I1ii11iIi11i % I1Ii111 % iIii1I11I1II1
     if 5 - 5: OoooooooOO + ooOoO0o - II111iiii . i11iIiiIii / oO0o - ooOoO0o
   if ( i1iIiiII1i != [ ] ) :
    O0Oo0O = oOoo0oOOO0o
    lprint ( "NAT-traversal optimized RLOC-set: {}" . format ( i1iIiiII1i ) )
    if 3 - 3: iII111i
    if 74 - 74: i11iIiiIii + OoooooooOO . OOooOOo
    if 29 - 29: IiII % OoO0O00
    if 53 - 53: OoooooooOO - OoOoOO00 / IiII - I1Ii111
    if 16 - 16: iIii1I11I1II1 / OOooOOo + I1IiiI * II111iiii . OOooOOo
    if 68 - 68: IiII * IiII + oO0o / o0oOOo0O0Ooo
    if 41 - 41: OoOoOO00 - O0
  oOoo0oOOO0o = [ ]
  for o0OOooooooOO in O0Oo0O :
   if ( o0OOooooooOO . json != None ) : continue
   oOoo0oOOO0o . append ( o0OOooooooOO )
   if 48 - 48: OoooooooOO % Ii1I * OoO0O00 / I1ii11iIi11i
  if ( oOoo0oOOO0o != [ ] ) :
   O0oO = len ( O0Oo0O ) - len ( oOoo0oOOO0o )
   lprint ( "Pruning {} no-address RLOC-records for map-cache" . format ( O0oO ) )
   if 53 - 53: ooOoO0o + oO0o - II111iiii
   O0Oo0O = oOoo0oOOO0o
   if 92 - 92: Oo0Ooo - I11i . ooOoO0o % oO0o
   if 6 - 6: iIii1I11I1II1 + oO0o
   if 8 - 8: I1ii11iIi11i + o0oOOo0O0Ooo
   if 29 - 29: Ii1I . OOooOOo
   if 59 - 59: O0 . OoO0O00
   if 10 - 10: I1Ii111 / OoooooooOO / OoO0O00 * ooOoO0o
   if 81 - 81: i1IIi % I11i * iIii1I11I1II1
   if 39 - 39: iIii1I11I1II1 / O0 . OoooooooOO - O0 . OoO0O00 . oO0o
  if ( oO0ooOo0O . rloc_probe and OoOOO000O0o != None ) : O0Oo0O = OoOOO000O0o . rloc_set
  if 59 - 59: II111iiii * I1IiiI
  if 12 - 12: i11iIiiIii - IiII . iII111i . Ii1I
  if 34 - 34: i1IIi % iII111i + Oo0Ooo * OoOoOO00 + OoO0O00
  if 37 - 37: I1Ii111 / OoooooooOO
  if 19 - 19: Ii1I - O0 + I1IiiI + OoooooooOO + ooOoO0o - Oo0Ooo
  iiiiiI111 = iII1111
  if ( OoOOO000O0o and O0Oo0O != OoOOO000O0o . rloc_set ) :
   OoOOO000O0o . delete_rlocs_from_rloc_probe_list ( )
   iiiiiI111 = True
   if 50 - 50: OoooooooOO % I1IiiI * I1Ii111 + I1Ii111 - I1Ii111
   if 60 - 60: I11i + O0 * I1IiiI * O0 * II111iiii
   if 73 - 73: II111iiii
   if 81 - 81: I1IiiI + OoO0O00
   if 22 - 22: OoO0O00 * OoOoOO00 * I11i * IiII . OoO0O00 . I1ii11iIi11i
  III1iii1i = OoOOO000O0o . uptime if ( OoOOO000O0o ) else None
  if ( OoOOO000O0o == None or OoOOO000O0o . gleaned == False ) :
   OoOOO000O0o = lisp_mapping ( iIi1i1i1II1 . eid , iIi1i1i1II1 . group , O0Oo0O )
   OoOOO000O0o . mapping_source = source
   OoOOO000O0o . map_cache_ttl = iIi1i1i1II1 . store_ttl ( )
   OoOOO000O0o . action = iIi1i1i1II1 . action
   OoOOO000O0o . add_cache ( iiiiiI111 )
   if 50 - 50: i11iIiiIii . OOooOOo . iIii1I11I1II1 . i1IIi . O0 / ooOoO0o
   if 64 - 64: i11iIiiIii + I1IiiI / Oo0Ooo - iII111i
  iI111iiI = "Add"
  if ( III1iii1i ) :
   OoOOO000O0o . uptime = III1iii1i
   OoOOO000O0o . refresh_time = lisp_get_timestamp ( )
   iI111iiI = "Replace"
   if 6 - 6: iII111i + II111iiii . IiII . Ii1I / ooOoO0o / I11i
   if 85 - 85: ooOoO0o / II111iiii / OoO0O00 + Ii1I / i1IIi . iII111i
  lprint ( "{} {} map-cache with {} RLOCs" . format ( iI111iiI ,
 green ( OoOOO000O0o . print_eid_tuple ( ) , False ) , len ( O0Oo0O ) ) )
  if 65 - 65: iIii1I11I1II1 * O0 . II111iiii * o0oOOo0O0Ooo . I1ii11iIi11i * I1IiiI
  if 63 - 63: II111iiii . Oo0Ooo % iIii1I11I1II1
  if 85 - 85: I1IiiI + i1IIi % I1Ii111
  if 76 - 76: i11iIiiIii % i11iIiiIii
  if 33 - 33: OOooOOo . ooOoO0o / iIii1I11I1II1 * OOooOOo / oO0o
  if ( lisp_ipc_dp_socket and i1iiIi1Iii1 != None ) :
   lisp_write_ipc_keys ( i1iiIi1Iii1 )
   if 75 - 75: Ii1I - OoOoOO00 . OOooOOo - o0oOOo0O0Ooo - I1ii11iIi11i
   if 69 - 69: O0 % I1ii11iIi11i
   if 77 - 77: iIii1I11I1II1 . OOooOOo
   if 64 - 64: OoOoOO00 - i1IIi * i1IIi / iII111i * OoOoOO00 * OoO0O00
   if 61 - 61: OOooOOo
   if 51 - 51: Oo0Ooo * OOooOOo / iII111i
   if 49 - 49: ooOoO0o . i1IIi % I1Ii111 . I1IiiI . I1ii11iIi11i + OoO0O00
  if ( iII1111 ) :
   OOo00o = bold ( "RLOC-probe" , False )
   for o0OOooooooOO in OoOOO000O0o . best_rloc_set :
    I1IIII1i1 = red ( o0OOooooooOO . rloc . print_address_no_iid ( ) , False )
    lprint ( "Trigger {} to {}" . format ( OOo00o , I1IIII1i1 ) )
    lisp_send_map_request ( lisp_sockets , 0 , OoOOO000O0o . eid , OoOOO000O0o . group , o0OOooooooOO )
    if 36 - 36: O0 . I11i / o0oOOo0O0Ooo + i1IIi + oO0o * IiII
    if 29 - 29: O0 - II111iiii + iII111i
    if 73 - 73: I1Ii111 - I11i + IiII - o0oOOo0O0Ooo - I11i - OOooOOo
 return
 if 40 - 40: iIii1I11I1II1 . iII111i * I1ii11iIi11i + IiII - iIii1I11I1II1
 if 83 - 83: i1IIi
 if 9 - 9: iIii1I11I1II1 + i11iIiiIii
 if 70 - 70: I1IiiI - OoO0O00 % OOooOOo + ooOoO0o % II111iiii
 if 19 - 19: I11i + i1IIi / i1IIi - II111iiii + I1Ii111
 if 11 - 11: i11iIiiIii % i11iIiiIii / IiII - Oo0Ooo / O0 - I11i
 if 29 - 29: OOooOOo * iIii1I11I1II1 * ooOoO0o
 if 80 - 80: oO0o * I1Ii111
def lisp_compute_auth ( packet , map_register , password ) :
 if ( map_register . alg_id == LISP_NONE_ALG_ID ) : return ( packet )
 if 87 - 87: iII111i + OoOoOO00 % ooOoO0o - oO0o
 packet = map_register . zero_auth ( packet )
 I1i1Ii = lisp_hash_me ( packet , map_register . alg_id , password , False )
 if 40 - 40: i1IIi / OoOoOO00 - I11i / ooOoO0o . Ii1I
 if 8 - 8: I1IiiI . IiII . OOooOOo . O0
 if 3 - 3: Ii1I + i11iIiiIii
 if 87 - 87: ooOoO0o - iII111i % I11i
 map_register . auth_data = I1i1Ii
 packet = map_register . encode_auth ( packet )
 return ( packet )
 if 88 - 88: I11i . OoooooooOO
 if 86 - 86: Ii1I - I1IiiI - iII111i % Ii1I . I1ii11iIi11i % i1IIi
 if 84 - 84: OoOoOO00
 if 99 - 99: OoO0O00 - OoOoOO00 - i1IIi / OoO0O00 * I1ii11iIi11i * iIii1I11I1II1
 if 65 - 65: iII111i - O0 / i1IIi . I1Ii111
 if 85 - 85: o0oOOo0O0Ooo % Ii1I
 if 81 - 81: oO0o / OoO0O00 * i1IIi % iIii1I11I1II1
def lisp_hash_me ( packet , alg_id , password , do_hex ) :
 if ( alg_id == LISP_NONE_ALG_ID ) : return ( True )
 if 23 - 23: II111iiii . II111iiii
 if ( alg_id == LISP_SHA_1_96_ALG_ID ) :
  Ii11i = hashlib . sha1
  if 33 - 33: OOooOOo + o0oOOo0O0Ooo
 if ( alg_id == LISP_SHA_256_128_ALG_ID ) :
  Ii11i = hashlib . sha256
  if 14 - 14: I11i / OOooOOo
  if 78 - 78: I1ii11iIi11i
 if ( do_hex ) :
  I1i1Ii = hmac . new ( password , packet , Ii11i ) . hexdigest ( )
 else :
  I1i1Ii = hmac . new ( password , packet , Ii11i ) . digest ( )
  if 18 - 18: ooOoO0o / I1Ii111 . o0oOOo0O0Ooo % OoOoOO00
 return ( I1i1Ii )
 if 60 - 60: I1IiiI . Oo0Ooo + ooOoO0o + OoO0O00
 if 30 - 30: I1Ii111 * i1IIi
 if 4 - 4: OoO0O00 + O0 * OOooOOo * I1Ii111 / O0
 if 58 - 58: OOooOOo % ooOoO0o * I1IiiI - I1ii11iIi11i / I11i + iII111i
 if 26 - 26: OoOoOO00
 if 63 - 63: I1Ii111 . oO0o + OoO0O00 / I1ii11iIi11i % IiII * II111iiii
 if 92 - 92: iIii1I11I1II1 . OoooooooOO . ooOoO0o / II111iiii
 if 30 - 30: i1IIi * Ii1I + Ii1I / I1Ii111
def lisp_verify_auth ( packet , alg_id , auth_data , password ) :
 if ( alg_id == LISP_NONE_ALG_ID ) : return ( True )
 if 84 - 84: I1IiiI - Oo0Ooo * OoO0O00 * oO0o
 I1i1Ii = lisp_hash_me ( packet , alg_id , password , True )
 I11iIIII1i1i1 = ( I1i1Ii == auth_data )
 if 54 - 54: Ii1I % o0oOOo0O0Ooo * I1Ii111 % II111iiii
 if 33 - 33: ooOoO0o % I11i
 if 72 - 72: OoO0O00 % OoooooooOO / II111iiii * oO0o * I1Ii111
 if 98 - 98: OOooOOo * Ii1I + I1ii11iIi11i / iIii1I11I1II1 / OoOoOO00 + I1IiiI
 if ( I11iIIII1i1i1 == False ) :
  lprint ( "Hashed value: {} does not match packet value: {}" . format ( I1i1Ii , auth_data ) )
  if 74 - 74: ooOoO0o . IiII . O0 * I1IiiI * oO0o
  if 6 - 6: O0 . Ii1I / Oo0Ooo * o0oOOo0O0Ooo
 return ( I11iIIII1i1i1 )
 if 1 - 1: i11iIiiIii
 if 30 - 30: I11i
 if 26 - 26: Oo0Ooo - II111iiii % ooOoO0o
 if 81 - 81: i11iIiiIii + I1ii11iIi11i * oO0o
 if 86 - 86: OoO0O00 . ooOoO0o . o0oOOo0O0Ooo
 if 70 - 70: O0 % OoooooooOO - Ii1I * Oo0Ooo
 if 18 - 18: OOooOOo . I1IiiI + i1IIi . I1IiiI
def lisp_retransmit_map_notify ( map_notify ) :
 iI1i1iI1iI = map_notify . etr
 Ii1 = map_notify . etr_port
 if 3 - 3: O0 * O0 + II111iiii + OoOoOO00 * I11i % Oo0Ooo
 if 19 - 19: oO0o % IiII % OoooooooOO % I1ii11iIi11i / OoO0O00
 if 6 - 6: O0 * I1Ii111 - II111iiii
 if 60 - 60: oO0o % oO0o
 if 76 - 76: I1Ii111 / o0oOOo0O0Ooo
 if ( map_notify . retry_count == LISP_MAX_MAP_NOTIFY_RETRIES ) :
  lprint ( "Map-Notify with nonce 0x{} retry limit reached for ETR {}" . format ( map_notify . nonce_key , red ( iI1i1iI1iI . print_address ( ) , False ) ) )
  if 19 - 19: O0 . i1IIi % iIii1I11I1II1 + OOooOOo * OoOoOO00 / I11i
  if 82 - 82: I1ii11iIi11i
  i1iI11iI = map_notify . nonce_key
  if ( lisp_map_notify_queue . has_key ( i1iI11iI ) ) :
   map_notify . retransmit_timer . cancel ( )
   lprint ( "Dequeue Map-Notify from retransmit queue, key is: {}" . format ( i1iI11iI ) )
   if 75 - 75: I11i - II111iiii
   try :
    lisp_map_notify_queue . pop ( i1iI11iI )
   except :
    lprint ( "Key not found in Map-Notify queue" )
    if 84 - 84: I1ii11iIi11i * IiII / I1IiiI - Ii1I + IiII - i1IIi
    if 98 - 98: II111iiii - iII111i % i11iIiiIii + ooOoO0o
  return
  if 76 - 76: OOooOOo - iII111i + IiII
  if 48 - 48: I1IiiI - II111iiii
 iIIi1 = map_notify . lisp_sockets
 map_notify . retry_count += 1
 if 15 - 15: O0
 lprint ( "Retransmit {} with nonce 0x{} to xTR {}, retry {}" . format ( bold ( "Map-Notify" , False ) , map_notify . nonce_key ,
 # iIii1I11I1II1 . OoO0O00 - iII111i + OoO0O00
 red ( iI1i1iI1iI . print_address ( ) , False ) , map_notify . retry_count ) )
 if 70 - 70: oO0o . oO0o - IiII
 lisp_send_map_notify ( iIIi1 , map_notify . packet , iI1i1iI1iI , Ii1 )
 if ( map_notify . site ) : map_notify . site . map_notifies_sent += 1
 if 17 - 17: I1ii11iIi11i . i1IIi - IiII + I1Ii111 + Ii1I . OoO0O00
 if 86 - 86: oO0o . iII111i
 if 44 - 44: I11i % iII111i - i11iIiiIii + II111iiii / OoO0O00
 if 97 - 97: II111iiii * OoOoOO00 + I1Ii111 * ooOoO0o . I11i * OOooOOo
 map_notify . retransmit_timer = threading . Timer ( LISP_MAP_NOTIFY_INTERVAL ,
 lisp_retransmit_map_notify , [ map_notify ] )
 map_notify . retransmit_timer . start ( )
 return
 if 36 - 36: II111iiii / Ii1I - IiII % iII111i / Oo0Ooo . oO0o
 if 50 - 50: I11i / I1IiiI / OOooOOo + I1Ii111 + OOooOOo * i1IIi
 if 83 - 83: i11iIiiIii * I1IiiI * IiII * Ii1I * OOooOOo
 if 17 - 17: o0oOOo0O0Ooo + Ii1I % I1ii11iIi11i + IiII % I1Ii111 + I1ii11iIi11i
 if 100 - 100: I11i * OoO0O00 - i1IIi + iII111i * Ii1I - OoooooooOO
 if 47 - 47: o0oOOo0O0Ooo / Ii1I - iII111i * OOooOOo / i11iIiiIii
 if 97 - 97: iIii1I11I1II1 + OoOoOO00 + OoOoOO00 * o0oOOo0O0Ooo
def lisp_send_merged_map_notify ( lisp_sockets , parent , map_register ,
 eid_record ) :
 if 14 - 14: II111iiii + I1ii11iIi11i * Oo0Ooo
 if 95 - 95: IiII + iII111i % I1IiiI
 if 18 - 18: Oo0Ooo
 if 8 - 8: O0 + iIii1I11I1II1 - O0
 eid_record . rloc_count = len ( parent . registered_rlocs )
 ooooo0oo0O00 = eid_record . encode ( )
 eid_record . print_record ( "Merged Map-Notify " , False )
 if 28 - 28: O0 - Oo0Ooo
 if 58 - 58: iIii1I11I1II1 - OoooooooOO - iII111i
 if 43 - 43: ooOoO0o / o0oOOo0O0Ooo
 if 56 - 56: II111iiii * I1ii11iIi11i * O0 . iII111i . I1ii11iIi11i % I1Ii111
 for OOOOOoO00 in parent . registered_rlocs :
  o000O = lisp_rloc_record ( )
  o000O . store_rloc_entry ( OOOOOoO00 )
  ooooo0oo0O00 += o000O . encode ( )
  o000O . print_record ( "  " )
  del ( o000O )
  if 56 - 56: IiII + OOooOOo
  if 89 - 89: o0oOOo0O0Ooo . Oo0Ooo
  if 48 - 48: o0oOOo0O0Ooo / O0 % i1IIi
  if 82 - 82: OoOoOO00 * Ii1I . I1ii11iIi11i * OoO0O00 % Oo0Ooo
  if 95 - 95: OoO0O00 / oO0o
 for OOOOOoO00 in parent . registered_rlocs :
  iI1i1iI1iI = OOOOOoO00 . rloc
  Ii1I1i111 = lisp_map_notify ( lisp_sockets )
  Ii1I1i111 . record_count = 1
  OOo0 = map_register . key_id
  Ii1I1i111 . key_id = OOo0
  Ii1I1i111 . alg_id = map_register . alg_id
  Ii1I1i111 . auth_len = map_register . auth_len
  Ii1I1i111 . nonce = map_register . nonce
  Ii1I1i111 . nonce_key = lisp_hex_string ( Ii1I1i111 . nonce )
  Ii1I1i111 . etr . copy_address ( iI1i1iI1iI )
  Ii1I1i111 . etr_port = map_register . sport
  Ii1I1i111 . site = parent . site
  Oo0O0oo = Ii1I1i111 . encode ( ooooo0oo0O00 , parent . site . auth_key [ OOo0 ] )
  Ii1I1i111 . print_notify ( )
  if 49 - 49: IiII % iII111i - O0 * o0oOOo0O0Ooo / OoooooooOO + OoOoOO00
  if 26 - 26: oO0o + i11iIiiIii . IiII + I1ii11iIi11i % IiII
  if 96 - 96: I11i / I1IiiI . i1IIi
  if 67 - 67: i11iIiiIii
  i1iI11iI = Ii1I1i111 . nonce_key
  if ( lisp_map_notify_queue . has_key ( i1iI11iI ) ) :
   iIiiI1i1I1iI = lisp_map_notify_queue [ i1iI11iI ]
   iIiiI1i1I1iI . retransmit_timer . cancel ( )
   del ( iIiiI1i1I1iI )
   if 53 - 53: oO0o
  lisp_map_notify_queue [ i1iI11iI ] = Ii1I1i111
  if 23 - 23: I1ii11iIi11i . I1Ii111 + OOooOOo
  if 4 - 4: I1IiiI
  if 31 - 31: ooOoO0o * i1IIi . O0
  if 5 - 5: OOooOOo . I1ii11iIi11i + ooOoO0o . ooOoO0o + iII111i
  lprint ( "Send merged Map-Notify to ETR {}" . format ( red ( iI1i1iI1iI . print_address ( ) , False ) ) )
  if 100 - 100: I1Ii111
  lisp_send ( lisp_sockets , iI1i1iI1iI , LISP_CTRL_PORT , Oo0O0oo )
  if 71 - 71: ooOoO0o * i1IIi / OoOoOO00 * i11iIiiIii - iII111i
  parent . site . map_notifies_sent += 1
  if 88 - 88: IiII
  if 29 - 29: iII111i . ooOoO0o
  if 62 - 62: IiII
  if 95 - 95: ooOoO0o / i1IIi + II111iiii + OoO0O00 % OoO0O00
  Ii1I1i111 . retransmit_timer = threading . Timer ( LISP_MAP_NOTIFY_INTERVAL ,
 lisp_retransmit_map_notify , [ Ii1I1i111 ] )
  Ii1I1i111 . retransmit_timer . start ( )
  if 18 - 18: ooOoO0o * I1IiiI / iII111i % iII111i
 return
 if 9 - 9: i11iIiiIii % ooOoO0o % O0 + i1IIi / O0
 if 12 - 12: I1Ii111 - iII111i * iII111i + OoO0O00 . Ii1I % I11i
 if 28 - 28: ooOoO0o % OoO0O00 - II111iiii * IiII - I1IiiI + I1IiiI
 if 84 - 84: IiII / Ii1I
 if 39 - 39: OOooOOo - iIii1I11I1II1 + OoOoOO00 % IiII * OoooooooOO % Ii1I
 if 11 - 11: I1ii11iIi11i
 if 83 - 83: O0
def lisp_build_map_notify ( lisp_sockets , eid_records , eid_list , record_count ,
 source , port , nonce , key_id , alg_id , auth_len , site , map_register_ack ) :
 if 97 - 97: O0
 i1iI11iI = lisp_hex_string ( nonce ) + source . print_address ( )
 if 50 - 50: I1Ii111 / OoooooooOO . o0oOOo0O0Ooo + I1IiiI * i11iIiiIii
 if 28 - 28: I1Ii111 * II111iiii
 if 14 - 14: iIii1I11I1II1 / Ii1I + o0oOOo0O0Ooo . iII111i % iII111i . i1IIi
 if 67 - 67: IiII * II111iiii + ooOoO0o - i11iIiiIii
 if 15 - 15: I11i
 if 67 - 67: iIii1I11I1II1
 lisp_remove_eid_from_map_notify_queue ( eid_list )
 if ( lisp_map_notify_queue . has_key ( i1iI11iI ) ) :
  Ii1I1i111 = lisp_map_notify_queue [ i1iI11iI ]
  IiiiI1 = red ( source . print_address_no_iid ( ) , False )
  lprint ( "Map-Notify with nonce 0x{} pending for xTR {}" . format ( lisp_hex_string ( Ii1I1i111 . nonce ) , IiiiI1 ) )
  if 91 - 91: ooOoO0o
  return
  if 66 - 66: OOooOOo
  if 5 - 5: i1IIi * OoOoOO00 + i1IIi % I11i
 Ii1I1i111 = lisp_map_notify ( lisp_sockets )
 Ii1I1i111 . record_count = record_count
 key_id = key_id
 Ii1I1i111 . key_id = key_id
 Ii1I1i111 . alg_id = alg_id
 Ii1I1i111 . auth_len = auth_len
 Ii1I1i111 . nonce = nonce
 Ii1I1i111 . nonce_key = lisp_hex_string ( nonce )
 Ii1I1i111 . etr . copy_address ( source )
 Ii1I1i111 . etr_port = port
 Ii1I1i111 . site = site
 Ii1I1i111 . eid_list = eid_list
 if 79 - 79: OOooOOo % iIii1I11I1II1 / OoOoOO00
 if 9 - 9: Ii1I
 if 44 - 44: iII111i
 if 46 - 46: I11i . i11iIiiIii * OoOoOO00 + o0oOOo0O0Ooo / ooOoO0o
 if ( map_register_ack == False ) :
  i1iI11iI = Ii1I1i111 . nonce_key
  lisp_map_notify_queue [ i1iI11iI ] = Ii1I1i111
  if 37 - 37: OoO0O00 - Ii1I + OoO0O00
  if 49 - 49: OoooooooOO - I1ii11iIi11i % I1ii11iIi11i / i1IIi . ooOoO0o
 if ( map_register_ack ) :
  lprint ( "Send Map-Notify to ack Map-Register" )
 else :
  lprint ( "Send Map-Notify for RLOC-set change" )
  if 60 - 60: Oo0Ooo
  if 46 - 46: OoOoOO00 + i1IIi
  if 43 - 43: II111iiii * IiII % iIii1I11I1II1 % i11iIiiIii % I1ii11iIi11i
  if 81 - 81: oO0o % I1ii11iIi11i % ooOoO0o * O0 - OOooOOo
  if 17 - 17: O0 % O0 / I1ii11iIi11i . Oo0Ooo . iII111i
 Oo0O0oo = Ii1I1i111 . encode ( eid_records , site . auth_key [ key_id ] )
 Ii1I1i111 . print_notify ( )
 if 4 - 4: OoO0O00
 if ( map_register_ack == False ) :
  iIi1i1i1II1 = lisp_eid_record ( )
  iIi1i1i1II1 . decode ( eid_records )
  iIi1i1i1II1 . print_record ( "  " , False )
  if 65 - 65: Oo0Ooo % O0 / I1Ii111 * IiII - oO0o
  if 32 - 32: Ii1I * OoO0O00 + ooOoO0o
  if 41 - 41: IiII + I11i * ooOoO0o + Oo0Ooo . ooOoO0o
  if 38 - 38: iII111i * OoooooooOO - IiII
  if 36 - 36: I1Ii111 * II111iiii + I1ii11iIi11i - iII111i * iII111i
 lisp_send_map_notify ( lisp_sockets , Oo0O0oo , Ii1I1i111 . etr , port )
 site . map_notifies_sent += 1
 if 91 - 91: O0 + I1Ii111 * II111iiii - O0 . i11iIiiIii . Oo0Ooo
 if ( map_register_ack ) : return
 if 54 - 54: ooOoO0o * I11i / I1ii11iIi11i % ooOoO0o
 if 76 - 76: I11i . I1IiiI
 if 66 - 66: oO0o % oO0o * IiII
 if 39 - 39: i1IIi * Ii1I + OoOoOO00 / oO0o
 if 6 - 6: I1ii11iIi11i / II111iiii / OoOoOO00 . i11iIiiIii - iII111i
 if 43 - 43: i11iIiiIii * i11iIiiIii * I1Ii111
 Ii1I1i111 . retransmit_timer = threading . Timer ( LISP_MAP_NOTIFY_INTERVAL ,
 lisp_retransmit_map_notify , [ Ii1I1i111 ] )
 Ii1I1i111 . retransmit_timer . start ( )
 return
 if 80 - 80: oO0o . I1IiiI * II111iiii + o0oOOo0O0Ooo / o0oOOo0O0Ooo % OoooooooOO
 if 31 - 31: o0oOOo0O0Ooo - OoO0O00 % I1IiiI
 if 23 - 23: OOooOOo
 if 97 - 97: Oo0Ooo / OoooooooOO . OoooooooOO
 if 47 - 47: OoO0O00
 if 52 - 52: I1IiiI * iIii1I11I1II1 % oO0o * IiII % oO0o
 if 9 - 9: I11i
 if 83 - 83: i11iIiiIii
def lisp_send_map_notify_ack ( lisp_sockets , eid_records , map_notify , ms ) :
 map_notify . map_notify_ack = True
 if 72 - 72: oO0o + II111iiii . O0 * oO0o + iII111i
 if 22 - 22: I11i + Ii1I . IiII - OoO0O00 - o0oOOo0O0Ooo
 if 84 - 84: OoooooooOO - Oo0Ooo
 if 86 - 86: O0 + OoO0O00 + O0 . I1IiiI
 Oo0O0oo = map_notify . encode ( eid_records , ms . password )
 map_notify . print_notify ( )
 if 82 - 82: OoOoOO00
 if 61 - 61: oO0o . o0oOOo0O0Ooo
 if 82 - 82: Oo0Ooo * OoooooooOO / ooOoO0o / I1IiiI
 if 70 - 70: I1IiiI
 iI1i1iI1iI = ms . map_server
 lprint ( "Send Map-Notify-Ack to {}" . format (
 red ( iI1i1iI1iI . print_address ( ) , False ) ) )
 lisp_send ( lisp_sockets , iI1i1iI1iI , LISP_CTRL_PORT , Oo0O0oo )
 return
 if 74 - 74: ooOoO0o * II111iiii
 if 96 - 96: i11iIiiIii . I1IiiI - II111iiii . I11i
 if 79 - 79: OoO0O00 . OoOoOO00 - i1IIi + Ii1I * i11iIiiIii . OoooooooOO
 if 83 - 83: o0oOOo0O0Ooo / oO0o
 if 24 - 24: Ii1I + oO0o / OoooooooOO % i11iIiiIii
 if 1 - 1: iII111i / I1Ii111 * I1IiiI + OoOoOO00 . OoooooooOO
 if 5 - 5: I1IiiI
 if 74 - 74: i1IIi * Oo0Ooo - OoOoOO00 * o0oOOo0O0Ooo
def lisp_send_multicast_map_notify ( lisp_sockets , site_eid , eid_list , xtr ) :
 if 85 - 85: iIii1I11I1II1 * IiII / i11iIiiIii - ooOoO0o - o0oOOo0O0Ooo
 Ii1I1i111 = lisp_map_notify ( lisp_sockets )
 Ii1I1i111 . record_count = 1
 Ii1I1i111 . nonce = lisp_get_control_nonce ( )
 Ii1I1i111 . nonce_key = lisp_hex_string ( Ii1I1i111 . nonce )
 Ii1I1i111 . etr . copy_address ( xtr )
 Ii1I1i111 . etr_port = LISP_CTRL_PORT
 Ii1I1i111 . eid_list = eid_list
 i1iI11iI = Ii1I1i111 . nonce_key
 if 30 - 30: OoOoOO00 - OOooOOo . Oo0Ooo
 if 11 - 11: IiII - I1Ii111 - OoO0O00 * o0oOOo0O0Ooo
 if 99 - 99: O0 - OoO0O00
 if 95 - 95: Ii1I . IiII * o0oOOo0O0Ooo
 if 91 - 91: I1Ii111
 if 49 - 49: I11i
 lisp_remove_eid_from_map_notify_queue ( Ii1I1i111 . eid_list )
 if ( lisp_map_notify_queue . has_key ( i1iI11iI ) ) :
  Ii1I1i111 = lisp_map_notify_queue [ i1iI11iI ]
  lprint ( "Map-Notify with nonce 0x{} pending for ITR {}" . format ( Ii1I1i111 . nonce , red ( xtr . print_address_no_iid ( ) , False ) ) )
  if 17 - 17: Oo0Ooo % o0oOOo0O0Ooo
  return
  if 3 - 3: OoO0O00 . oO0o . oO0o . Ii1I
  if 100 - 100: i11iIiiIii / i1IIi . I1ii11iIi11i
  if 1 - 1: IiII * I1Ii111 / I1ii11iIi11i * i11iIiiIii
  if 82 - 82: o0oOOo0O0Ooo * OoO0O00 / o0oOOo0O0Ooo % OoOoOO00 * iIii1I11I1II1 % O0
  if 10 - 10: ooOoO0o
 lisp_map_notify_queue [ i1iI11iI ] = Ii1I1i111
 if 69 - 69: I11i + I1IiiI / oO0o
 if 89 - 89: i1IIi % OoOoOO00 . I1ii11iIi11i
 if 85 - 85: I1Ii111 - oO0o
 if 34 - 34: iIii1I11I1II1 / IiII + OoOoOO00 - IiII / ooOoO0o + OoOoOO00
 oO0oo000O = site_eid . rtrs_in_rloc_set ( )
 if ( oO0oo000O ) :
  if ( site_eid . is_rtr_in_rloc_set ( xtr ) ) : oO0oo000O = False
  if 14 - 14: ooOoO0o - OoooooooOO / iIii1I11I1II1
  if 98 - 98: i1IIi
  if 81 - 81: OoOoOO00 * i11iIiiIii + I1IiiI
  if 2 - 2: I11i - IiII + I1IiiI % OoO0O00 + iIii1I11I1II1 + oO0o
  if 49 - 49: I1IiiI * I1Ii111 . I1IiiI - II111iiii
 iIi1i1i1II1 = lisp_eid_record ( )
 iIi1i1i1II1 . record_ttl = 1440
 iIi1i1i1II1 . eid . copy_address ( site_eid . eid )
 iIi1i1i1II1 . group . copy_address ( site_eid . group )
 iIi1i1i1II1 . rloc_count = 0
 for OoooO00OO in site_eid . registered_rlocs :
  if ( oO0oo000O ^ OoooO00OO . is_rtr ( ) ) : continue
  iIi1i1i1II1 . rloc_count += 1
  if 57 - 57: oO0o + O0 - OoOoOO00
 Oo0O0oo = iIi1i1i1II1 . encode ( )
 if 14 - 14: II111iiii + i11iIiiIii + Ii1I / o0oOOo0O0Ooo . OoO0O00
 if 93 - 93: o0oOOo0O0Ooo + i1IIi
 if 24 - 24: i1IIi
 if 54 - 54: iIii1I11I1II1 - IiII + o0oOOo0O0Ooo + I1ii11iIi11i + IiII
 Ii1I1i111 . print_notify ( )
 iIi1i1i1II1 . print_record ( "  " , False )
 if 99 - 99: Oo0Ooo
 if 38 - 38: I1ii11iIi11i - I1IiiI
 if 50 - 50: iII111i % OoO0O00 - oO0o + Oo0Ooo . O0 . iII111i
 if 42 - 42: iII111i + I1ii11iIi11i
 for OoooO00OO in site_eid . registered_rlocs :
  if ( oO0oo000O ^ OoooO00OO . is_rtr ( ) ) : continue
  o000O = lisp_rloc_record ( )
  o000O . store_rloc_entry ( OoooO00OO )
  Oo0O0oo += o000O . encode ( )
  o000O . print_record ( "    " )
  if 44 - 44: I1ii11iIi11i % IiII
  if 1 - 1: Oo0Ooo + IiII - I1Ii111 / I1Ii111
  if 25 - 25: OoOoOO00
  if 52 - 52: OOooOOo + IiII
  if 73 - 73: OoooooooOO - I1Ii111 % iII111i / OOooOOo . o0oOOo0O0Ooo - IiII
 Oo0O0oo = Ii1I1i111 . encode ( Oo0O0oo , "" )
 if ( Oo0O0oo == None ) : return
 if 69 - 69: Ii1I . iIii1I11I1II1 / Oo0Ooo * Oo0Ooo % IiII
 if 5 - 5: OOooOOo - I1Ii111 + IiII
 if 82 - 82: OOooOOo
 if 26 - 26: ooOoO0o + OoooooooOO + ooOoO0o * I1Ii111
 lisp_send_map_notify ( lisp_sockets , Oo0O0oo , xtr , LISP_CTRL_PORT )
 if 26 - 26: I1IiiI - OOooOOo
 if 34 - 34: I1Ii111 % I1IiiI . OoOoOO00 / iII111i + ooOoO0o . i11iIiiIii
 if 51 - 51: OoooooooOO * I1Ii111 * I11i - I1ii11iIi11i + I1Ii111
 if 50 - 50: OoooooooOO * II111iiii
 Ii1I1i111 . retransmit_timer = threading . Timer ( LISP_MAP_NOTIFY_INTERVAL ,
 lisp_retransmit_map_notify , [ Ii1I1i111 ] )
 Ii1I1i111 . retransmit_timer . start ( )
 return
 if 7 - 7: ooOoO0o / I11i * iII111i
 if 17 - 17: O0 % I1Ii111
 if 28 - 28: i1IIi * ooOoO0o
 if 14 - 14: II111iiii + II111iiii - I11i / I11i . OoOoOO00 + OoO0O00
 if 92 - 92: II111iiii - II111iiii % IiII
 if 48 - 48: oO0o / II111iiii + oO0o
 if 16 - 16: o0oOOo0O0Ooo % II111iiii - i11iIiiIii - IiII + O0 - i11iIiiIii
def lisp_queue_multicast_map_notify ( lisp_sockets , rle_list ) :
 OoOOo = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
 if 38 - 38: o0oOOo0O0Ooo . OoO0O00
 for iIiiIi1111ii in rle_list :
  O000oOo = lisp_site_eid_lookup ( iIiiIi1111ii [ 0 ] , iIiiIi1111ii [ 1 ] , True )
  if ( O000oOo == None ) : continue
  if 35 - 35: I1ii11iIi11i - iII111i + o0oOOo0O0Ooo
  if 27 - 27: IiII * Oo0Ooo
  if 12 - 12: Ii1I
  if 29 - 29: I11i / i11iIiiIii + OoO0O00 % O0 - I1ii11iIi11i % oO0o
  if 30 - 30: I11i + OOooOOo
  if 27 - 27: OoOoOO00 . ooOoO0o
  if 73 - 73: o0oOOo0O0Ooo
  iIooo00OoO0 = O000oOo . registered_rlocs
  if ( len ( iIooo00OoO0 ) == 0 ) :
   iII11I1IiIii = { }
   for OoOo0OOoOOO00 in O000oOo . individual_registrations . values ( ) :
    for OoooO00OO in OoOo0OOoOOO00 . registered_rlocs :
     if ( OoooO00OO . is_rtr ( ) == False ) : continue
     iII11I1IiIii [ OoooO00OO . rloc . print_address ( ) ] = OoooO00OO
     if 25 - 25: OoOoOO00 - I11i / oO0o - oO0o
     if 84 - 84: iIii1I11I1II1 - o0oOOo0O0Ooo
   iIooo00OoO0 = iII11I1IiIii . values ( )
   if 37 - 37: iII111i * o0oOOo0O0Ooo
   if 23 - 23: ooOoO0o + OoooooooOO * iII111i . I11i
   if 2 - 2: iIii1I11I1II1 * I1ii11iIi11i - OoooooooOO
   if 93 - 93: iII111i % ooOoO0o * Oo0Ooo
   if 34 - 34: O0 * oO0o
   if 58 - 58: OOooOOo . iII111i - Oo0Ooo / iII111i . I11i
  oo000oOoO = [ ]
  O000oooooOO = False
  if ( O000oOo . eid . address == 0 and O000oOo . eid . mask_len == 0 ) :
   OOo0OOoOO0 = [ ]
   OO000o00Ooo0o = [ ] if len ( iIooo00OoO0 ) == 0 else iIooo00OoO0 [ 0 ] . rle . rle_nodes
   if 27 - 27: iIii1I11I1II1 - OoO0O00 - OoooooooOO + IiII . II111iiii
   for I11iI in OO000o00Ooo0o :
    oo000oOoO . append ( I11iI . address )
    OOo0OOoOO0 . append ( I11iI . address . print_address_no_iid ( ) )
    if 66 - 66: iIii1I11I1II1 % I11i
   lprint ( "Notify existing RLE-nodes {}" . format ( OOo0OOoOO0 ) )
  else :
   if 38 - 38: I1ii11iIi11i * ooOoO0o
   if 77 - 77: OOooOOo - i11iIiiIii - I1ii11iIi11i
   if 94 - 94: OoO0O00 % iII111i - I1Ii111 + OoO0O00 - I1IiiI
   if 65 - 65: OOooOOo
   if 90 - 90: O0
   for OoooO00OO in iIooo00OoO0 :
    if ( OoooO00OO . is_rtr ( ) ) : oo000oOoO . append ( OoooO00OO . rloc )
    if 91 - 91: O0 * OoOoOO00 - OoOoOO00 * II111iiii - iII111i
    if 38 - 38: oO0o * I11i % OOooOOo
    if 80 - 80: O0 % II111iiii / O0 . Oo0Ooo * OoOoOO00 + OOooOOo
    if 47 - 47: Ii1I - Oo0Ooo * OoOoOO00
    if 20 - 20: oO0o
   O000oooooOO = ( len ( oo000oOoO ) != 0 )
   if ( O000oooooOO == False ) :
    iIi1iIIiiIi = lisp_site_eid_lookup ( iIiiIi1111ii [ 0 ] , OoOOo , False )
    if ( iIi1iIIiiIi == None ) : continue
    if 48 - 48: I1IiiI % OoO0O00
    for OoooO00OO in iIi1iIIiiIi . registered_rlocs :
     if ( OoooO00OO . rloc . is_null ( ) ) : continue
     oo000oOoO . append ( OoooO00OO . rloc )
     if 33 - 33: Ii1I
     if 73 - 73: Ii1I . IiII
     if 43 - 43: I11i . IiII - iII111i * I1IiiI * iII111i
     if 90 - 90: i11iIiiIii * i1IIi
     if 88 - 88: i11iIiiIii - OoOoOO00
     if 53 - 53: iIii1I11I1II1 % I1Ii111 / Oo0Ooo % Oo0Ooo
   if ( len ( oo000oOoO ) == 0 ) :
    lprint ( "No ITRs or RTRs found for {}, Map-Notify suppressed" . format ( green ( O000oOo . print_eid_tuple ( ) , False ) ) )
    if 6 - 6: iII111i
    continue
    if 44 - 44: oO0o
    if 23 - 23: I1IiiI + iIii1I11I1II1 . iII111i + OOooOOo - OoO0O00 + i1IIi
    if 60 - 60: i11iIiiIii + Oo0Ooo * OoOoOO00 . iII111i - iIii1I11I1II1 * IiII
    if 52 - 52: OOooOOo
    if 50 - 50: OoOoOO00 % o0oOOo0O0Ooo - II111iiii - i1IIi
    if 35 - 35: Oo0Ooo - ooOoO0o % OoO0O00
  for OOOOOoO00 in oo000oOoO :
   lprint ( "Build Map-Notify to {}TR {} for {}" . format ( "R" if O000oooooOO else "x" , red ( OOOOOoO00 . print_address_no_iid ( ) , False ) ,
   # I1Ii111 - i1IIi
 green ( O000oOo . print_eid_tuple ( ) , False ) ) )
   if 88 - 88: OoO0O00 - II111iiii * I1ii11iIi11i % iIii1I11I1II1 + IiII * iII111i
   iIii1iI1ii1iI = [ O000oOo . print_eid_tuple ( ) ]
   lisp_send_multicast_map_notify ( lisp_sockets , O000oOo , iIii1iI1ii1iI , OOOOOoO00 )
   time . sleep ( .001 )
   if 83 - 83: oO0o % OoO0O00 + I1ii11iIi11i / OoooooooOO % iII111i
   if 22 - 22: I1Ii111
 return
 if 41 - 41: O0 * i1IIi
 if 89 - 89: iIii1I11I1II1 . I11i % I1ii11iIi11i + II111iiii . OoO0O00
 if 5 - 5: I1ii11iIi11i / I1IiiI . iII111i
 if 7 - 7: Ii1I
 if 62 - 62: I1ii11iIi11i + IiII . O0 - OoooooooOO * o0oOOo0O0Ooo % O0
 if 63 - 63: OOooOOo + iII111i - IiII - I1IiiI % IiII . OoO0O00
 if 73 - 73: OoOoOO00
 if 47 - 47: oO0o
def lisp_find_sig_in_rloc_set ( packet , rloc_count ) :
 for o0OoO00 in range ( rloc_count ) :
  o000O = lisp_rloc_record ( )
  packet = o000O . decode ( packet , None )
  iIIi11Ii1iII = o000O . json
  if ( iIIi11Ii1iII == None ) : continue
  if 72 - 72: I11i % ooOoO0o / O0 . O0
  try :
   iIIi11Ii1iII = json . loads ( iIIi11Ii1iII . json_string )
  except :
   lprint ( "Found corrupted JSON signature" )
   continue
   if 7 - 7: O0 * I1ii11iIi11i + Ii1I + oO0o % oO0o
   if 47 - 47: oO0o * I1ii11iIi11i
  if ( iIIi11Ii1iII . has_key ( "signature" ) == False ) : continue
  return ( o000O )
  if 85 - 85: OoooooooOO * I1ii11iIi11i + i11iIiiIii . iII111i * II111iiii / oO0o
 return ( None )
 if 14 - 14: I1Ii111
 if 49 - 49: I1IiiI . OOooOOo / OoooooooOO + I11i - I11i
 if 27 - 27: Ii1I / o0oOOo0O0Ooo . iIii1I11I1II1 . I1IiiI - OoO0O00
 if 28 - 28: ooOoO0o
 if 88 - 88: oO0o
 if 77 - 77: ooOoO0o + I1Ii111 . OoOoOO00
 if 2 - 2: i1IIi - IiII + iIii1I11I1II1 % i1IIi * II111iiii
 if 26 - 26: I11i
 if 57 - 57: I1ii11iIi11i + I1Ii111 + i11iIiiIii . i1IIi / i11iIiiIii
 if 43 - 43: Ii1I % I11i
 if 5 - 5: OoooooooOO % i11iIiiIii * o0oOOo0O0Ooo * OoooooooOO - o0oOOo0O0Ooo % I11i
 if 58 - 58: i11iIiiIii % Ii1I + Oo0Ooo - OoOoOO00 - i11iIiiIii / O0
 if 36 - 36: OOooOOo
 if 42 - 42: OOooOOo * ooOoO0o * i11iIiiIii + OoooooooOO . iIii1I11I1II1
 if 95 - 95: i1IIi * O0 / II111iiii * OoOoOO00 * I1IiiI
 if 38 - 38: OOooOOo - OoOoOO00 / OoO0O00 / o0oOOo0O0Ooo - i11iIiiIii
 if 4 - 4: I1IiiI * o0oOOo0O0Ooo - I11i - OoooooooOO . OoooooooOO
 if 79 - 79: oO0o - iII111i
 if 34 - 34: OoooooooOO + Ii1I - iII111i + OoooooooOO / I1IiiI
def lisp_get_eid_hash ( eid ) :
 II1iii1I1 = None
 for iiO0 in lisp_eid_hashes :
  if 58 - 58: I1ii11iIi11i / i11iIiiIii + iII111i + I11i / oO0o
  if 8 - 8: I1ii11iIi11i
  if 100 - 100: OoooooooOO / I11i - Ii1I
  if 11 - 11: OoO0O00
  OO0OO000 = iiO0 . instance_id
  if ( OO0OO000 == - 1 ) : iiO0 . instance_id = eid . instance_id
  if 20 - 20: Oo0Ooo
  I1iiIIiiiII = eid . is_more_specific ( iiO0 )
  iiO0 . instance_id = OO0OO000
  if ( I1iiIIiiiII ) :
   II1iii1I1 = 128 - iiO0 . mask_len
   break
   if 68 - 68: I1Ii111 % Ii1I * Oo0Ooo - O0 . IiII
   if 1 - 1: I1ii11iIi11i
 if ( II1iii1I1 == None ) : return ( None )
 if 18 - 18: i11iIiiIii % OoO0O00 % OOooOOo . OOooOOo * Ii1I / II111iiii
 I1Ii1iIIIIi = eid . address
 o0o00OOO00o = ""
 for o0OoO00 in range ( 0 , II1iii1I1 / 16 ) :
  ooooO0O = I1Ii1iIIIIi & 0xffff
  ooooO0O = hex ( ooooO0O ) [ 2 : - 1 ]
  o0o00OOO00o = ooooO0O . zfill ( 4 ) + ":" + o0o00OOO00o
  I1Ii1iIIIIi >>= 16
  if 95 - 95: I1Ii111 . I1IiiI . II111iiii - Ii1I / ooOoO0o
 if ( II1iii1I1 % 16 != 0 ) :
  ooooO0O = I1Ii1iIIIIi & 0xff
  ooooO0O = hex ( ooooO0O ) [ 2 : - 1 ]
  o0o00OOO00o = ooooO0O . zfill ( 2 ) + ":" + o0o00OOO00o
  if 57 - 57: Oo0Ooo * II111iiii % iIii1I11I1II1
 return ( o0o00OOO00o [ 0 : - 1 ] )
 if 13 - 13: iII111i . OoOoOO00 * I1ii11iIi11i + OOooOOo % i1IIi
 if 13 - 13: OOooOOo + i11iIiiIii / OOooOOo . O0 . OoO0O00 - Ii1I
 if 31 - 31: OoOoOO00 * o0oOOo0O0Ooo / O0 . iII111i / i11iIiiIii
 if 22 - 22: I1IiiI . OoooooooOO * I1ii11iIi11i + i11iIiiIii - O0 + i11iIiiIii
 if 98 - 98: OOooOOo + I1IiiI / IiII / OoooooooOO / OOooOOo
 if 8 - 8: OoooooooOO * OOooOOo * iII111i - iII111i
 if 32 - 32: I1Ii111
 if 28 - 28: I11i . i11iIiiIii % iIii1I11I1II1 + OoOoOO00
 if 4 - 4: OOooOOo + I1ii11iIi11i - iII111i + OOooOOo / IiII
 if 23 - 23: iIii1I11I1II1 + OoooooooOO + ooOoO0o . iII111i . Oo0Ooo - iIii1I11I1II1
 if 25 - 25: O0 + I1IiiI % OOooOOo / Oo0Ooo . IiII / I1Ii111
def lisp_lookup_public_key ( eid ) :
 OO0OO000 = eid . instance_id
 if 84 - 84: ooOoO0o . O0 + I1IiiI * OoO0O00 - I1IiiI
 if 24 - 24: Ii1I
 if 23 - 23: Oo0Ooo * i1IIi / I1IiiI . I11i - I1ii11iIi11i . iIii1I11I1II1
 if 15 - 15: O0 + o0oOOo0O0Ooo / oO0o
 if 27 - 27: Ii1I * II111iiii / oO0o
 O000O0 = lisp_get_eid_hash ( eid )
 if ( O000O0 == None ) : return ( [ None , None , False ] )
 if 65 - 65: o0oOOo0O0Ooo
 O000O0 = "hash-" + O000O0
 i1I111iIiI = lisp_address ( LISP_AFI_NAME , O000O0 , len ( O000O0 ) , OO0OO000 )
 IiI1111i1i11I = lisp_address ( LISP_AFI_NONE , "" , 0 , OO0OO000 )
 if 77 - 77: i1IIi . Oo0Ooo . oO0o + oO0o - i11iIiiIii + I1ii11iIi11i
 if 86 - 86: ooOoO0o . ooOoO0o . OoooooooOO - OoOoOO00 % oO0o
 if 81 - 81: Oo0Ooo . OoooooooOO
 if 15 - 15: I1Ii111 - I11i * I1IiiI % o0oOOo0O0Ooo
 iIi1iIIiiIi = lisp_site_eid_lookup ( i1I111iIiI , IiI1111i1i11I , True )
 if ( iIi1iIIiiIi == None ) : return ( [ i1I111iIiI , None , False ] )
 if 75 - 75: oO0o % OoooooooOO % i11iIiiIii . iII111i
 if 95 - 95: i11iIiiIii . Ii1I / II111iiii + II111iiii + Ii1I / I11i
 if 72 - 72: I1Ii111 . I1Ii111 * O0 + I1ii11iIi11i / Oo0Ooo
 if 96 - 96: oO0o . ooOoO0o * Oo0Ooo % ooOoO0o + I1Ii111 + iIii1I11I1II1
 OOO0O0OO = None
 for o0OOooooooOO in iIi1iIIiiIi . registered_rlocs :
  iIi1I = o0OOooooooOO . json
  if ( iIi1I == None ) : continue
  try :
   iIi1I = json . loads ( iIi1I . json_string )
  except :
   lprint ( "Registered RLOC JSON format is invalid for {}" . format ( O000O0 ) )
   if 57 - 57: O0 / II111iiii - II111iiii + iII111i . OoO0O00 + iIii1I11I1II1
   return ( [ i1I111iIiI , None , False ] )
   if 6 - 6: Oo0Ooo / I1Ii111 + i1IIi
  if ( iIi1I . has_key ( "public-key" ) == False ) : continue
  OOO0O0OO = iIi1I [ "public-key" ]
  break
  if 66 - 66: OoOoOO00 % OoooooooOO
 return ( [ i1I111iIiI , OOO0O0OO , True ] )
 if 19 - 19: I1ii11iIi11i
 if 30 - 30: Oo0Ooo
 if 68 - 68: i1IIi
 if 98 - 98: o0oOOo0O0Ooo + I1ii11iIi11i - oO0o + i1IIi
 if 85 - 85: I1Ii111 - I1Ii111 . ooOoO0o % I1ii11iIi11i . OOooOOo
 if 98 - 98: iII111i . I1Ii111 % II111iiii
 if 28 - 28: OoOoOO00 * I1ii11iIi11i / Oo0Ooo
 if 17 - 17: I1Ii111 - OOooOOo . ooOoO0o - i1IIi * ooOoO0o * I1ii11iIi11i
def lisp_verify_cga_sig ( eid , rloc_record ) :
 if 16 - 16: I1ii11iIi11i . o0oOOo0O0Ooo * iIii1I11I1II1
 if 15 - 15: iII111i + o0oOOo0O0Ooo / IiII
 if 33 - 33: OoooooooOO . IiII * o0oOOo0O0Ooo
 if 41 - 41: Ii1I . iII111i . o0oOOo0O0Ooo % OoooooooOO % IiII
 if 81 - 81: IiII * i11iIiiIii + i1IIi + OOooOOo . i1IIi
 IIIIi1I = json . loads ( rloc_record . json . json_string )
 if 6 - 6: i11iIiiIii - oO0o % OoO0O00 + iIii1I11I1II1
 if ( lisp_get_eid_hash ( eid ) ) :
  O000o0O0 = eid
 elif ( IIIIi1I . has_key ( "signature-eid" ) ) :
  ooooOoOO0o0o = IIIIi1I [ "signature-eid" ]
  O000o0O0 = lisp_address ( LISP_AFI_IPV6 , ooooOoOO0o0o , 0 , 0 )
 else :
  lprint ( "  No signature-eid found in RLOC-record" )
  return ( False )
  if 94 - 94: I1ii11iIi11i * ooOoO0o
  if 12 - 12: Ii1I - OoOoOO00
  if 56 - 56: OOooOOo . oO0o
  if 75 - 75: oO0o + OoOoOO00 - OoooooooOO
  if 38 - 38: I11i / ooOoO0o / OoOoOO00 * OOooOOo . oO0o
 i1I111iIiI , OOO0O0OO , IIO0o0ooOO0oOOO = lisp_lookup_public_key ( O000o0O0 )
 if ( i1I111iIiI == None ) :
  oo0oO = green ( O000o0O0 . print_address ( ) , False )
  lprint ( "  Could not parse hash in EID {}" . format ( oo0oO ) )
  return ( False )
  if 70 - 70: oO0o
  if 44 - 44: oO0o % OoOoOO00 - OOooOOo . i1IIi / OoO0O00 % I11i
 iiIiI1 = "found" if IIO0o0ooOO0oOOO else bold ( "not found" , False )
 oo0oO = green ( i1I111iIiI . print_address ( ) , False )
 lprint ( "  Lookup for crypto-hashed EID {} {}" . format ( oo0oO , iiIiI1 ) )
 if ( IIO0o0ooOO0oOOO == False ) : return ( False )
 if 72 - 72: iIii1I11I1II1 % iIii1I11I1II1 . OoOoOO00 * OoooooooOO * OoO0O00
 if ( OOO0O0OO == None ) :
  lprint ( "  RLOC-record with public-key not found" )
  return ( False )
  if 26 - 26: Ii1I * I1IiiI % ooOoO0o / I1Ii111
  if 80 - 80: I1Ii111 / O0 * O0
 IIiIiII1i = OOO0O0OO [ 0 : 8 ] + "..." + OOO0O0OO [ - 8 : : ]
 lprint ( "  RLOC-record with public-key '{}' found" . format ( IIiIiII1i ) )
 if 55 - 55: II111iiii
 if 67 - 67: IiII % I1Ii111 + i11iIiiIii
 if 53 - 53: OOooOOo
 if 95 - 95: oO0o - OOooOOo % I1Ii111 / OoooooooOO % OoooooooOO - O0
 if 21 - 21: I1Ii111 . i1IIi - iII111i % I1ii11iIi11i . OOooOOo
 o0Oo0oOOo0O0 = IIIIi1I [ "signature" ]
 if 28 - 28: O0
 try :
  IIIIi1I = binascii . a2b_base64 ( o0Oo0oOOo0O0 )
 except :
  lprint ( "  Incorrect padding in signature string" )
  return ( False )
  if 29 - 29: I11i - OOooOOo / OoO0O00
  if 81 - 81: I11i / oO0o
 o0OOO0O = len ( IIIIi1I )
 if ( o0OOO0O & 1 ) :
  lprint ( "  Signature length is odd, length {}" . format ( o0OOO0O ) )
  return ( False )
  if 19 - 19: i11iIiiIii - i1IIi / OoO0O00 + i1IIi - I1IiiI
  if 92 - 92: OoO0O00 - OoOoOO00 . I1ii11iIi11i
  if 2 - 2: I1Ii111
  if 69 - 69: I1IiiI . I1ii11iIi11i . o0oOOo0O0Ooo + OoooooooOO
  if 52 - 52: i1IIi - oO0o
 o000o0O = O000o0O0 . print_address ( )
 if 33 - 33: Ii1I / I1ii11iIi11i . ooOoO0o . OoooooooOO
 if 45 - 45: OoO0O00 . I1ii11iIi11i + Ii1I / I11i - ooOoO0o / OoooooooOO
 if 44 - 44: OoO0O00 % O0 * IiII + iII111i
 if 79 - 79: ooOoO0o
 OOO0O0OO = binascii . a2b_base64 ( OOO0O0OO )
 try :
  i1iI11iI = ecdsa . VerifyingKey . from_pem ( OOO0O0OO )
 except :
  ooOOoo0o = bold ( "Bad public-key" , False )
  lprint ( "  {}, not in PEM format" . format ( ooOOoo0o ) )
  return ( False )
  if 16 - 16: II111iiii . ooOoO0o . i11iIiiIii * Ii1I - o0oOOo0O0Ooo . I1IiiI
  if 33 - 33: o0oOOo0O0Ooo % ooOoO0o
  if 43 - 43: I1Ii111
  if 81 - 81: OoOoOO00
  if 97 - 97: OoO0O00
  if 76 - 76: I1IiiI - i1IIi . IiII - i11iIiiIii
  if 36 - 36: OoO0O00 . oO0o - ooOoO0o
  if 42 - 42: i1IIi / iII111i % O0 + II111iiii * OoOoOO00 / OoOoOO00
  if 50 - 50: OOooOOo - I1IiiI / O0 / ooOoO0o
  if 93 - 93: OoO0O00 % IiII / OoooooooOO * oO0o
  if 99 - 99: iIii1I11I1II1
 try :
  ii1ii = i1iI11iI . verify ( IIIIi1I , o000o0O , hashfunc = hashlib . sha256 )
 except :
  lprint ( "  Signature library failed for signature data '{}'" . format ( o000o0O ) )
  if 27 - 27: Oo0Ooo
  lprint ( "  Signature used '{}'" . format ( o0Oo0oOOo0O0 ) )
  return ( False )
  if 85 - 85: iIii1I11I1II1 . o0oOOo0O0Ooo + oO0o
 return ( ii1ii )
 if 79 - 79: O0 - iIii1I11I1II1 + i1IIi . I11i
 if 21 - 21: II111iiii
 if 23 - 23: I11i * i1IIi . oO0o / IiII + o0oOOo0O0Ooo
 if 1 - 1: IiII / OoO0O00 . oO0o * I1Ii111 - i11iIiiIii
 if 50 - 50: oO0o - O0 / I1IiiI . OoOoOO00 . Oo0Ooo
 if 30 - 30: IiII . OoO0O00 + Oo0Ooo
 if 48 - 48: iIii1I11I1II1 / i11iIiiIii . OoOoOO00 * I11i
 if 1 - 1: IiII . OoOoOO00 * o0oOOo0O0Ooo
 if 63 - 63: O0 / Ii1I + I1Ii111 % OoO0O00 % OOooOOo * O0
 if 35 - 35: OoO0O00 + OoooooooOO % Oo0Ooo / I11i - O0 . i1IIi
def lisp_remove_eid_from_map_notify_queue ( eid_list ) :
 if 76 - 76: IiII % I1IiiI * Ii1I / Ii1I / OoooooooOO + Ii1I
 if 19 - 19: OoooooooOO
 if 88 - 88: I1IiiI % ooOoO0o % Oo0Ooo - O0
 if 71 - 71: OOooOOo % Ii1I - i11iIiiIii - oO0o . ooOoO0o / I1Ii111
 if 53 - 53: iII111i . Oo0Ooo
 OO0o0O0O0o0o = [ ]
 for I1i1I in eid_list :
  for OOO00O0 in lisp_map_notify_queue :
   Ii1I1i111 = lisp_map_notify_queue [ OOO00O0 ]
   if ( I1i1I not in Ii1I1i111 . eid_list ) : continue
   if 6 - 6: I1IiiI * ooOoO0o * O0 + OOooOOo
   OO0o0O0O0o0o . append ( OOO00O0 )
   IiIII = Ii1I1i111 . retransmit_timer
   if ( IiIII ) : IiIII . cancel ( )
   if 49 - 49: OOooOOo - iIii1I11I1II1 / ooOoO0o
   lprint ( "Remove from Map-Notify queue nonce 0x{} for EID {}" . format ( Ii1I1i111 . nonce_key , green ( I1i1I , False ) ) )
   if 28 - 28: OoOoOO00 + OoOoOO00 - OoOoOO00 / ooOoO0o
   if 81 - 81: oO0o
   if 34 - 34: o0oOOo0O0Ooo * OOooOOo - i1IIi * o0oOOo0O0Ooo * Oo0Ooo
   if 59 - 59: iIii1I11I1II1 / Oo0Ooo % II111iiii
   if 55 - 55: ooOoO0o - IiII + o0oOOo0O0Ooo
   if 48 - 48: O0 - iIii1I11I1II1 * OOooOOo
   if 33 - 33: I11i
 for OOO00O0 in OO0o0O0O0o0o : lisp_map_notify_queue . pop ( OOO00O0 )
 return
 if 63 - 63: Ii1I % II111iiii / OoOoOO00 + Oo0Ooo
 if 28 - 28: OoO0O00 + I1IiiI . oO0o + II111iiii - O0
 if 32 - 32: oO0o
 if 62 - 62: i11iIiiIii + OoooooooOO + IiII - OoO0O00 / oO0o * iIii1I11I1II1
 if 91 - 91: o0oOOo0O0Ooo - i11iIiiIii + Oo0Ooo % iIii1I11I1II1
 if 58 - 58: iII111i / ooOoO0o - I1Ii111 + I1Ii111 * ooOoO0o
 if 48 - 48: iII111i % O0 % Ii1I * OoO0O00 . OoO0O00
 if 74 - 74: OoO0O00 * i1IIi + I1ii11iIi11i / o0oOOo0O0Ooo / i1IIi
def lisp_decrypt_map_register ( packet ) :
 if 94 - 94: Ii1I
 if 13 - 13: OoO0O00 - II111iiii . iII111i + OoOoOO00 / i11iIiiIii
 if 32 - 32: ooOoO0o / II111iiii / I1ii11iIi11i
 if 34 - 34: iIii1I11I1II1
 if 47 - 47: OOooOOo * iII111i
 o0OO0 = socket . ntohl ( struct . unpack ( "I" , packet [ 0 : 4 ] ) [ 0 ] )
 O00ooo0oo = ( o0OO0 >> 13 ) & 0x1
 if ( O00ooo0oo == 0 ) : return ( packet )
 if 25 - 25: oO0o . OoO0O00 + OoO0O00
 I1i1i1ii1 = ( o0OO0 >> 14 ) & 0x7
 if 93 - 93: OOooOOo / iIii1I11I1II1 % OoO0O00 + iII111i
 if 66 - 66: I1Ii111 + ooOoO0o
 if 58 - 58: i1IIi % OoO0O00 % I1IiiI * O0 . Ii1I / OoO0O00
 if 97 - 97: IiII
 try :
  O000oOooOoO0 = lisp_ms_encryption_keys [ I1i1i1ii1 ]
  O000oOooOoO0 = O000oOooOoO0 . zfill ( 32 )
  oOOOoo00oO = "0" * 8
 except :
  lprint ( "Cannot decrypt Map-Register with key-id {}" . format ( I1i1i1ii1 ) )
  return ( None )
  if 49 - 49: OoO0O00 / iII111i
  if 22 - 22: I11i + II111iiii * iIii1I11I1II1 % OOooOOo
 oOOoO0O = bold ( "Decrypt" , False )
 lprint ( "{} Map-Register with key-id {}" . format ( oOOoO0O , I1i1i1ii1 ) )
 if 7 - 7: I11i - OOooOOo + I1IiiI + IiII . I1Ii111
 iI1ii = chacha . ChaCha ( O000oOooOoO0 , oOOOoo00oO ) . decrypt ( packet [ 4 : : ] )
 return ( packet [ 0 : 4 ] + iI1ii )
 if 76 - 76: o0oOOo0O0Ooo % IiII - iII111i % ooOoO0o
 if 34 - 34: OoooooooOO / ooOoO0o - iII111i + IiII - iII111i
 if 65 - 65: O0 * Ii1I % ooOoO0o
 if 29 - 29: iII111i % Ii1I / OoOoOO00 % O0 / IiII
 if 32 - 32: IiII * II111iiii . Ii1I
 if 68 - 68: I11i / O0
 if 6 - 6: oO0o - oO0o . I1IiiI % I1ii11iIi11i
def lisp_process_map_register ( lisp_sockets , packet , source , sport ) :
 global lisp_registered_count
 if 22 - 22: Ii1I / I1IiiI / II111iiii
 if 31 - 31: II111iiii - Ii1I * OOooOOo - i11iIiiIii / OoooooooOO - I1Ii111
 if 76 - 76: Oo0Ooo
 if 93 - 93: i1IIi - I1IiiI * i11iIiiIii / Ii1I . Ii1I - i1IIi
 if 19 - 19: iIii1I11I1II1 * OOooOOo * Oo0Ooo % I1IiiI
 if 93 - 93: IiII % OoOoOO00 / I1IiiI + o0oOOo0O0Ooo * ooOoO0o / i1IIi
 packet = lisp_decrypt_map_register ( packet )
 if ( packet == None ) : return
 if 25 - 25: O0 / Oo0Ooo - o0oOOo0O0Ooo * Oo0Ooo
 i1I11II11iIi1 = lisp_map_register ( )
 oOoo0O000 , packet = i1I11II11iIi1 . decode ( packet )
 if ( packet == None ) :
  lprint ( "Could not decode Map-Register packet" )
  return
  if 8 - 8: Oo0Ooo + IiII - II111iiii % Ii1I
 i1I11II11iIi1 . sport = sport
 if 64 - 64: Ii1I % OoO0O00 + OOooOOo % OoOoOO00 + IiII
 i1I11II11iIi1 . print_map_register ( )
 if 92 - 92: iII111i * Oo0Ooo - OoOoOO00
 if 33 - 33: i11iIiiIii - OoOoOO00 . OOooOOo * II111iiii . Ii1I
 if 59 - 59: OoOoOO00
 if 29 - 29: iII111i - II111iiii * OoooooooOO * OoooooooOO
 I1i1i = True
 if ( i1I11II11iIi1 . auth_len == LISP_SHA1_160_AUTH_DATA_LEN ) :
  I1i1i = True
  if 11 - 11: OOooOOo * i11iIiiIii % O0
 if ( i1I11II11iIi1 . alg_id == LISP_SHA_256_128_ALG_ID ) :
  I1i1i = False
  if 6 - 6: I1Ii111 + oO0o
  if 98 - 98: Oo0Ooo
  if 81 - 81: OoO0O00 . ooOoO0o
  if 78 - 78: II111iiii - i11iIiiIii . OOooOOo
  if 22 - 22: Oo0Ooo + ooOoO0o
 O00 = [ ]
 if 76 - 76: i11iIiiIii
 if 74 - 74: IiII
 if 23 - 23: OoooooooOO
 if 57 - 57: iII111i
 i11i1IiiII = None
 i1i1iI1 = packet
 iIIIIiiii = [ ]
 OooOooOO0000 = i1I11II11iIi1 . record_count
 for o0OoO00 in range ( OooOooOO0000 ) :
  iIi1i1i1II1 = lisp_eid_record ( )
  o000O = lisp_rloc_record ( )
  packet = iIi1i1i1II1 . decode ( packet )
  if ( packet == None ) :
   lprint ( "Could not decode EID-record in Map-Register packet" )
   return
   if 17 - 17: II111iiii - I1Ii111 - i11iIiiIii - iIii1I11I1II1
  iIi1i1i1II1 . print_record ( "  " , False )
  if 10 - 10: I1IiiI
  if 40 - 40: OoO0O00 * oO0o / OoOoOO00
  if 37 - 37: iII111i * oO0o / I1IiiI * I1ii11iIi11i
  if 73 - 73: oO0o + O0
  iIi1iIIiiIi = lisp_site_eid_lookup ( iIi1i1i1II1 . eid , iIi1i1i1II1 . group ,
 False )
  if 98 - 98: I11i % oO0o - I1Ii111 % o0oOOo0O0Ooo - IiII
  iiiii1i = iIi1iIIiiIi . print_eid_tuple ( ) if iIi1iIIiiIi else None
  if 79 - 79: OoooooooOO . OoOoOO00 * OoO0O00 + I11i / iII111i - Ii1I
  if 9 - 9: I1IiiI - IiII . iIii1I11I1II1
  if 99 - 99: iII111i / o0oOOo0O0Ooo
  if 9 - 9: Oo0Ooo / i1IIi / Ii1I . I1Ii111 . I1Ii111
  if 56 - 56: ooOoO0o % IiII . OoO0O00 - iIii1I11I1II1 % o0oOOo0O0Ooo % I1IiiI
  if 71 - 71: I1IiiI + iII111i
  if 47 - 47: iIii1I11I1II1 . OoO0O00 . iIii1I11I1II1
  if ( iIi1iIIiiIi and iIi1iIIiiIi . accept_more_specifics == False ) :
   if ( iIi1iIIiiIi . eid_record_matches ( iIi1i1i1II1 ) == False ) :
    O000000oO0O0O = iIi1iIIiiIi . parent_for_more_specifics
    if ( O000000oO0O0O ) : iIi1iIIiiIi = O000000oO0O0O
    if 8 - 8: Oo0Ooo . oO0o + II111iiii
    if 100 - 100: OoOoOO00 . IiII / OoO0O00 * OoooooooOO - OoOoOO00
    if 98 - 98: OoO0O00 / I1ii11iIi11i + I1ii11iIi11i
    if 70 - 70: i1IIi % Oo0Ooo % I1Ii111 + I11i . ooOoO0o
    if 66 - 66: i11iIiiIii % I11i / Oo0Ooo * oO0o
    if 7 - 7: O0 - Ii1I - oO0o
    if 95 - 95: i1IIi - OOooOOo / OoOoOO00 + I1ii11iIi11i + O0
    if 10 - 10: ooOoO0o - OOooOOo + i1IIi * Ii1I
  o00 = ( iIi1iIIiiIi and iIi1iIIiiIi . accept_more_specifics )
  if ( o00 ) :
   Ooo0Oo0Oo00o = lisp_site_eid ( iIi1iIIiiIi . site )
   Ooo0Oo0Oo00o . dynamic = True
   Ooo0Oo0Oo00o . eid . copy_address ( iIi1i1i1II1 . eid )
   Ooo0Oo0Oo00o . group . copy_address ( iIi1i1i1II1 . group )
   Ooo0Oo0Oo00o . parent_for_more_specifics = iIi1iIIiiIi
   Ooo0Oo0Oo00o . add_cache ( )
   Ooo0Oo0Oo00o . inherit_from_ams_parent ( )
   iIi1iIIiiIi . more_specific_registrations . append ( Ooo0Oo0Oo00o )
   iIi1iIIiiIi = Ooo0Oo0Oo00o
  else :
   iIi1iIIiiIi = lisp_site_eid_lookup ( iIi1i1i1II1 . eid , iIi1i1i1II1 . group ,
 True )
   if 94 - 94: O0 + II111iiii - iII111i / i1IIi
   if 25 - 25: ooOoO0o . OoO0O00 - oO0o
  oo0oO = iIi1i1i1II1 . print_eid_tuple ( )
  if 76 - 76: iIii1I11I1II1 / II111iiii * OoOoOO00 % iII111i . II111iiii + i11iIiiIii
  if ( iIi1iIIiiIi == None ) :
   oO0 = bold ( "Site not found" , False )
   lprint ( "  {} for EID {}{}" . format ( oO0 , green ( oo0oO , False ) ,
 ", matched non-ams {}" . format ( green ( iiiii1i , False ) if iiiii1i else "" ) ) )
   if 41 - 41: oO0o . o0oOOo0O0Ooo . I11i
   if 53 - 53: I11i
   if 64 - 64: OoO0O00 + I11i / I1IiiI . II111iiii
   if 79 - 79: I1Ii111 + IiII / OoooooooOO
   if 53 - 53: Ii1I
   packet = o000O . end_of_rlocs ( packet , iIi1i1i1II1 . rloc_count )
   if ( packet == None ) :
    lprint ( "  Could not decode RLOC-record in Map-Register packet" )
    return
    if 85 - 85: OoO0O00 + II111iiii / OoO0O00 . II111iiii * OoOoOO00 * I1IiiI
   continue
   if 19 - 19: iII111i / Ii1I + iIii1I11I1II1 * O0 - Oo0Ooo
   if 47 - 47: iIii1I11I1II1 % I1ii11iIi11i
  i11i1IiiII = iIi1iIIiiIi . site
  if 33 - 33: oO0o . oO0o / IiII + II111iiii
  if ( o00 ) :
   o0o000 = iIi1iIIiiIi . parent_for_more_specifics . print_eid_tuple ( )
   lprint ( "  Found ams {} for site '{}' for registering prefix {}" . format ( green ( o0o000 , False ) , i11i1IiiII . site_name , green ( oo0oO , False ) ) )
   if 34 - 34: OoO0O00 . OoOoOO00 / i1IIi / OOooOOo
  else :
   o0o000 = green ( iIi1iIIiiIi . print_eid_tuple ( ) , False )
   lprint ( "  Found {} for site '{}' for registering prefix {}" . format ( o0o000 , i11i1IiiII . site_name , green ( oo0oO , False ) ) )
   if 12 - 12: o0oOOo0O0Ooo . Oo0Ooo / II111iiii
   if 18 - 18: I1Ii111 % II111iiii + Ii1I * Oo0Ooo - OoooooooOO . Oo0Ooo
   if 25 - 25: OoO0O00
   if 83 - 83: II111iiii . iIii1I11I1II1
   if 77 - 77: O0 . OoOoOO00 % oO0o / OOooOOo
   if 8 - 8: iII111i - i1IIi
  if ( i11i1IiiII . shutdown ) :
   lprint ( ( "  Rejecting registration for site '{}', configured in " +
 "admin-shutdown state" ) . format ( i11i1IiiII . site_name ) )
   packet = o000O . end_of_rlocs ( packet , iIi1i1i1II1 . rloc_count )
   continue
   if 81 - 81: ooOoO0o / OOooOOo % OoOoOO00 . iIii1I11I1II1
   if 45 - 45: I1IiiI . ooOoO0o - OoooooooOO
   if 84 - 84: I1ii11iIi11i
   if 69 - 69: I1Ii111 + II111iiii
   if 92 - 92: OoooooooOO
   if 80 - 80: I1ii11iIi11i % I1ii11iIi11i . OoO0O00 . oO0o % I1IiiI % I11i
   if 4 - 4: OoO0O00 / iII111i / I1ii11iIi11i - o0oOOo0O0Ooo * I1Ii111
   if 24 - 24: OoooooooOO / ooOoO0o + Oo0Ooo - OOooOOo - o0oOOo0O0Ooo . I1ii11iIi11i
  OOo0 = i1I11II11iIi1 . key_id
  if ( i11i1IiiII . auth_key . has_key ( OOo0 ) == False ) : OOo0 = 0
  IiIIIIi11i = i11i1IiiII . auth_key [ OOo0 ]
  if 91 - 91: O0 . o0oOOo0O0Ooo * OoO0O00 * I1Ii111 % I11i / OoOoOO00
  ooOoOO00o0O = lisp_verify_auth ( oOoo0O000 , i1I11II11iIi1 . alg_id ,
 i1I11II11iIi1 . auth_data , IiIIIIi11i )
  I11IIi1iI = "dynamic " if iIi1iIIiiIi . dynamic else ""
  if 71 - 71: Ii1I - o0oOOo0O0Ooo - oO0o
  Oo00o = bold ( "passed" if ooOoOO00o0O else "failed" , False )
  OOo0 = "key-id {}" . format ( OOo0 ) if OOo0 == i1I11II11iIi1 . key_id else "bad key-id {}" . format ( i1I11II11iIi1 . key_id )
  if 27 - 27: O0 - iIii1I11I1II1
  lprint ( "  Authentication {} for {}EID-prefix {}, {}" . format ( Oo00o , I11IIi1iI , green ( oo0oO , False ) , OOo0 ) )
  if 78 - 78: Oo0Ooo / o0oOOo0O0Ooo
  if 35 - 35: o0oOOo0O0Ooo . OoO0O00 / o0oOOo0O0Ooo / IiII - I1ii11iIi11i . Oo0Ooo
  if 97 - 97: i11iIiiIii + I1ii11iIi11i - I11i . oO0o
  if 76 - 76: IiII * II111iiii * I1ii11iIi11i + OoooooooOO - OoOoOO00 . Ii1I
  if 51 - 51: II111iiii % I1Ii111 * O0 . ooOoO0o * OoOoOO00
  if 17 - 17: I1IiiI % I11i
  iIii1II111Ii = True
  iiIiII11I = ( lisp_get_eid_hash ( iIi1i1i1II1 . eid ) != None )
  if ( iiIiII11I or iIi1iIIiiIi . require_signature ) :
   oOOo0000Oo = "Required " if iIi1iIIiiIi . require_signature else ""
   oo0oO = green ( oo0oO , False )
   o0OOooooooOO = lisp_find_sig_in_rloc_set ( packet , iIi1i1i1II1 . rloc_count )
   if ( o0OOooooooOO == None ) :
    iIii1II111Ii = False
    lprint ( ( "  {}EID-crypto-hash signature verification {} " + "for EID-prefix {}, no signature found" ) . format ( oOOo0000Oo ,
    # iII111i / i11iIiiIii % OOooOOo + Ii1I . Oo0Ooo
 bold ( "failed" , False ) , oo0oO ) )
   else :
    iIii1II111Ii = lisp_verify_cga_sig ( iIi1i1i1II1 . eid , o0OOooooooOO )
    Oo00o = bold ( "passed" if iIii1II111Ii else "failed" , False )
    lprint ( ( "  {}EID-crypto-hash signature verification {} " + "for EID-prefix {}" ) . format ( oOOo0000Oo , Oo00o , oo0oO ) )
    if 16 - 16: oO0o / Ii1I % i11iIiiIii % I1IiiI * I1ii11iIi11i
    if 4 - 4: iIii1I11I1II1 + Ii1I % I1Ii111 . OoOoOO00 % OoooooooOO + II111iiii
    if 48 - 48: ooOoO0o + ooOoO0o
    if 95 - 95: iIii1I11I1II1 / i11iIiiIii - IiII - OOooOOo
  if ( ooOoOO00o0O == False or iIii1II111Ii == False ) :
   packet = o000O . end_of_rlocs ( packet , iIi1i1i1II1 . rloc_count )
   if ( packet == None ) :
    lprint ( "  Could not decode RLOC-record in Map-Register packet" )
    return
    if 4 - 4: II111iiii + oO0o + o0oOOo0O0Ooo % IiII % iIii1I11I1II1
   continue
   if 68 - 68: i11iIiiIii
   if 79 - 79: OoOoOO00 * Ii1I / I1ii11iIi11i + OOooOOo
   if 19 - 19: I1IiiI + I11i + I1IiiI + OoO0O00
   if 33 - 33: i11iIiiIii - Ii1I * II111iiii
   if 97 - 97: OoO0O00 / o0oOOo0O0Ooo * iIii1I11I1II1
   if 5 - 5: I1IiiI
  if ( i1I11II11iIi1 . merge_register_requested ) :
   O000000oO0O0O = iIi1iIIiiIi
   O000000oO0O0O . inconsistent_registration = False
   if 27 - 27: i1IIi + oO0o / I1ii11iIi11i + oO0o
   if 98 - 98: II111iiii + iIii1I11I1II1
   if 70 - 70: I11i / OoooooooOO / i11iIiiIii
   if 61 - 61: O0 . Oo0Ooo . iIii1I11I1II1
   if 54 - 54: OOooOOo * I1ii11iIi11i + OoooooooOO
   if ( iIi1iIIiiIi . group . is_null ( ) ) :
    if ( O000000oO0O0O . site_id != i1I11II11iIi1 . site_id ) :
     O000000oO0O0O . site_id = i1I11II11iIi1 . site_id
     O000000oO0O0O . registered = False
     O000000oO0O0O . individual_registrations = { }
     O000000oO0O0O . registered_rlocs = [ ]
     lisp_registered_count -= 1
     if 58 - 58: i1IIi - OoooooooOO * OOooOOo . ooOoO0o + O0 + o0oOOo0O0Ooo
     if 87 - 87: OOooOOo + I1Ii111 + O0 / oO0o / i11iIiiIii
     if 60 - 60: O0 . II111iiii
   i1iI11iI = source . address + i1I11II11iIi1 . xtr_id
   if ( iIi1iIIiiIi . individual_registrations . has_key ( i1iI11iI ) ) :
    iIi1iIIiiIi = iIi1iIIiiIi . individual_registrations [ i1iI11iI ]
   else :
    iIi1iIIiiIi = lisp_site_eid ( i11i1IiiII )
    iIi1iIIiiIi . eid . copy_address ( O000000oO0O0O . eid )
    iIi1iIIiiIi . group . copy_address ( O000000oO0O0O . group )
    O000000oO0O0O . individual_registrations [ i1iI11iI ] = iIi1iIIiiIi
    if 69 - 69: II111iiii / ooOoO0o - OoOoOO00 / OOooOOo
  else :
   iIi1iIIiiIi . inconsistent_registration = iIi1iIIiiIi . merge_register_requested
   if 52 - 52: OoO0O00 % I11i + o0oOOo0O0Ooo % OoOoOO00
   if 46 - 46: o0oOOo0O0Ooo % O0
   if 30 - 30: oO0o
  iIi1iIIiiIi . map_registers_received += 1
  if 64 - 64: O0
  if 70 - 70: oO0o % I1IiiI . iIii1I11I1II1 - Oo0Ooo + OoOoOO00 % O0
  if 91 - 91: I1Ii111 - oO0o * ooOoO0o - I1ii11iIi11i + IiII + O0
  if 18 - 18: OoOoOO00 / IiII / o0oOOo0O0Ooo . OOooOOo
  if 35 - 35: I11i . ooOoO0o % I11i / iII111i / O0 % I11i
  ooOOoo0o = ( iIi1iIIiiIi . is_rloc_in_rloc_set ( source ) == False )
  if ( iIi1i1i1II1 . record_ttl == 0 and ooOOoo0o ) :
   lprint ( "  Ignore deregistration request from {}" . format ( red ( source . print_address_no_iid ( ) , False ) ) )
   if 29 - 29: I1Ii111 + Ii1I
   continue
   if 100 - 100: Ii1I + I1Ii111 / iIii1I11I1II1 / i1IIi % OoOoOO00
   if 6 - 6: oO0o + ooOoO0o
   if 13 - 13: Oo0Ooo . IiII % iII111i + i1IIi / OOooOOo
   if 1 - 1: I11i * i1IIi * Oo0Ooo % O0
   if 41 - 41: OOooOOo % OoOoOO00
   if 82 - 82: I11i . IiII
  I11iiiIIi1 = iIi1iIIiiIi . registered_rlocs
  iIi1iIIiiIi . registered_rlocs = [ ]
  if 80 - 80: Oo0Ooo + oO0o
  if 76 - 76: I1IiiI * OoooooooOO - i11iIiiIii / I11i / Oo0Ooo
  if 82 - 82: IiII % ooOoO0o
  if 100 - 100: Oo0Ooo . oO0o - iII111i + OoooooooOO
  IIOoO0OOOo0O0O0 = packet
  for iI1I1I111 in range ( iIi1i1i1II1 . rloc_count ) :
   o000O = lisp_rloc_record ( )
   packet = o000O . decode ( packet , None )
   if ( packet == None ) :
    lprint ( "  Could not decode RLOC-record in Map-Register packet" )
    return
    if 30 - 30: i11iIiiIii - I11i * ooOoO0o + iII111i % I1Ii111
   o000O . print_record ( "    " )
   if 1 - 1: iIii1I11I1II1 % i11iIiiIii - i11iIiiIii % II111iiii
   if 89 - 89: iII111i . OoO0O00 . iII111i
   if 35 - 35: oO0o - ooOoO0o
   if 4 - 4: Oo0Ooo - IiII - I11i
   if ( len ( i11i1IiiII . allowed_rlocs ) > 0 ) :
    I1IIII1i1 = o000O . rloc . print_address ( )
    if ( i11i1IiiII . allowed_rlocs . has_key ( I1IIII1i1 ) == False ) :
     lprint ( ( "  Reject registration, RLOC {} not " + "configured in allowed RLOC-set" ) . format ( red ( I1IIII1i1 , False ) ) )
     if 72 - 72: OoooooooOO
     if 19 - 19: Oo0Ooo . OOooOOo
     iIi1iIIiiIi . registered = False
     packet = o000O . end_of_rlocs ( packet ,
 iIi1i1i1II1 . rloc_count - iI1I1I111 - 1 )
     break
     if 58 - 58: IiII % iII111i + i1IIi % I1IiiI % OOooOOo . iII111i
     if 85 - 85: i11iIiiIii . o0oOOo0O0Ooo * iII111i . I1ii11iIi11i / I1Ii111 % Ii1I
     if 27 - 27: II111iiii . iIii1I11I1II1 / I1ii11iIi11i / i1IIi / iIii1I11I1II1
     if 70 - 70: i11iIiiIii . OoO0O00 / OoooooooOO * OoooooooOO - OOooOOo
     if 34 - 34: I1ii11iIi11i * i1IIi % OoooooooOO / I1IiiI
     if 39 - 39: OoO0O00 + IiII - II111iiii % I11i
   o0OOooooooOO = lisp_rloc ( )
   o0OOooooooOO . store_rloc_from_record ( o000O , None , source )
   if 80 - 80: o0oOOo0O0Ooo * ooOoO0o
   if 87 - 87: I1Ii111 + O0 / I1ii11iIi11i / OoOoOO00 . Oo0Ooo - IiII
   if 24 - 24: OoOoOO00
   if 19 - 19: ooOoO0o
   if 43 - 43: O0 . I1Ii111 % OoooooooOO / I1IiiI . o0oOOo0O0Ooo - OoOoOO00
   if 46 - 46: I11i - OoooooooOO % o0oOOo0O0Ooo
   if ( source . is_exact_match ( o0OOooooooOO . rloc ) ) :
    o0OOooooooOO . map_notify_requested = i1I11II11iIi1 . map_notify_requested
    if 7 - 7: OoooooooOO - I1Ii111 * IiII
    if 20 - 20: o0oOOo0O0Ooo . OoooooooOO * I1IiiI . Oo0Ooo * OoOoOO00
    if 3 - 3: I1Ii111 % i11iIiiIii % O0 % II111iiii
    if 8 - 8: OoooooooOO * ooOoO0o
    if 26 - 26: i11iIiiIii + oO0o - i1IIi
   iIi1iIIiiIi . registered_rlocs . append ( o0OOooooooOO )
   if 71 - 71: I1IiiI % I1Ii111 / oO0o % oO0o / iIii1I11I1II1 + I1Ii111
   if 86 - 86: IiII % i1IIi * o0oOOo0O0Ooo - I1Ii111
  I1II1I1III = ( iIi1iIIiiIi . do_rloc_sets_match ( I11iiiIIi1 ) == False )
  if 6 - 6: iII111i / i1IIi + OOooOOo % OoOoOO00 . I1ii11iIi11i
  if 88 - 88: OoO0O00
  if 82 - 82: OOooOOo / I11i / OoooooooOO % oO0o
  if 27 - 27: oO0o + IiII
  if 5 - 5: iIii1I11I1II1 + OoOoOO00 * I1Ii111 * i11iIiiIii
  if 18 - 18: Oo0Ooo % OOooOOo % oO0o / I11i % O0
  if ( i1I11II11iIi1 . map_register_refresh and I1II1I1III and
 iIi1iIIiiIi . registered ) :
   lprint ( "  Reject registration, refreshes cannot change RLOC-set" )
   iIi1iIIiiIi . registered_rlocs = I11iiiIIi1
   continue
   if 76 - 76: OoooooooOO % O0 / OoO0O00
   if 41 - 41: i11iIiiIii - I1ii11iIi11i - II111iiii
   if 5 - 5: OoOoOO00 + i1IIi
   if 43 - 43: iII111i * I1IiiI
   if 20 - 20: I1IiiI . I11i * OoO0O00 . ooOoO0o . II111iiii
   if 6 - 6: Ii1I * OoOoOO00 % IiII + I11i
  if ( iIi1iIIiiIi . registered == False ) :
   iIi1iIIiiIi . first_registered = lisp_get_timestamp ( )
   lisp_registered_count += 1
   if 20 - 20: oO0o
  iIi1iIIiiIi . last_registered = lisp_get_timestamp ( )
  iIi1iIIiiIi . registered = ( iIi1i1i1II1 . record_ttl != 0 )
  iIi1iIIiiIi . last_registerer = source
  if 34 - 34: i1IIi + oO0o * Oo0Ooo * I1Ii111 % OoooooooOO % ooOoO0o
  if 17 - 17: I1ii11iIi11i + o0oOOo0O0Ooo / OoO0O00 . Oo0Ooo - o0oOOo0O0Ooo / oO0o
  if 87 - 87: ooOoO0o
  if 74 - 74: i11iIiiIii . i11iIiiIii . iIii1I11I1II1
  iIi1iIIiiIi . auth_sha1_or_sha2 = I1i1i
  iIi1iIIiiIi . proxy_reply_requested = i1I11II11iIi1 . proxy_reply_requested
  iIi1iIIiiIi . lisp_sec_present = i1I11II11iIi1 . lisp_sec_present
  iIi1iIIiiIi . map_notify_requested = i1I11II11iIi1 . map_notify_requested
  iIi1iIIiiIi . mobile_node_requested = i1I11II11iIi1 . mobile_node
  iIi1iIIiiIi . merge_register_requested = i1I11II11iIi1 . merge_register_requested
  if 100 - 100: i11iIiiIii - oO0o + iIii1I11I1II1 * OoOoOO00 % OOooOOo % i11iIiiIii
  iIi1iIIiiIi . use_register_ttl_requested = i1I11II11iIi1 . use_ttl_for_timeout
  if ( iIi1iIIiiIi . use_register_ttl_requested ) :
   iIi1iIIiiIi . register_ttl = iIi1i1i1II1 . store_ttl ( )
  else :
   iIi1iIIiiIi . register_ttl = LISP_SITE_TIMEOUT_CHECK_INTERVAL * 3
   if 26 - 26: O0
  iIi1iIIiiIi . xtr_id_present = i1I11II11iIi1 . xtr_id_present
  if ( iIi1iIIiiIi . xtr_id_present ) :
   iIi1iIIiiIi . xtr_id = i1I11II11iIi1 . xtr_id
   iIi1iIIiiIi . site_id = i1I11II11iIi1 . site_id
   if 97 - 97: OOooOOo + I11i % I1Ii111 % i11iIiiIii / I1ii11iIi11i
   if 21 - 21: O0 + iIii1I11I1II1 / i11iIiiIii . OOooOOo * i1IIi
   if 3 - 3: i1IIi % o0oOOo0O0Ooo + OoOoOO00
   if 32 - 32: OoO0O00 . Oo0Ooo * iIii1I11I1II1
   if 12 - 12: O0 + I1ii11iIi11i + I11i . I1Ii111
  if ( i1I11II11iIi1 . merge_register_requested ) :
   if ( O000000oO0O0O . merge_in_site_eid ( iIi1iIIiiIi ) ) :
    O00 . append ( [ iIi1i1i1II1 . eid , iIi1i1i1II1 . group ] )
    if 48 - 48: Ii1I . iIii1I11I1II1 - iIii1I11I1II1 * I11i . OoooooooOO
   if ( i1I11II11iIi1 . map_notify_requested ) :
    lisp_send_merged_map_notify ( lisp_sockets , O000000oO0O0O , i1I11II11iIi1 ,
 iIi1i1i1II1 )
    if 73 - 73: Ii1I / II111iiii - iIii1I11I1II1 . ooOoO0o * II111iiii . OOooOOo
    if 50 - 50: iIii1I11I1II1 + OoOoOO00 % O0 + OoO0O00 . i11iIiiIii / oO0o
    if 31 - 31: I1IiiI % o0oOOo0O0Ooo . i11iIiiIii % OOooOOo - iIii1I11I1II1
  if ( I1II1I1III == False ) : continue
  if ( len ( O00 ) != 0 ) : continue
  if 77 - 77: i11iIiiIii / OOooOOo
  iIIIIiiii . append ( iIi1iIIiiIi . print_eid_tuple ( ) )
  if 93 - 93: I1ii11iIi11i - iII111i % O0 - Ii1I
  if 84 - 84: I1ii11iIi11i . iIii1I11I1II1 % IiII * I11i + ooOoO0o
  if 59 - 59: oO0o * OoO0O00 - I11i * I1IiiI
  if 60 - 60: iII111i - OoooooooOO / iII111i % OoO0O00 . OoOoOO00 - o0oOOo0O0Ooo
  if 71 - 71: iII111i * o0oOOo0O0Ooo * i11iIiiIii * O0
  if 77 - 77: OOooOOo % iII111i + I11i / OoOoOO00
  if 50 - 50: OoOoOO00 - i11iIiiIii - OOooOOo . iIii1I11I1II1
  iIi1i1i1II1 = iIi1i1i1II1 . encode ( )
  iIi1i1i1II1 += IIOoO0OOOo0O0O0
  iIii1iI1ii1iI = [ iIi1iIIiiIi . print_eid_tuple ( ) ]
  lprint ( "    Changed RLOC-set, Map-Notifying old RLOC-set" )
  if 97 - 97: oO0o % OOooOOo . OoooooooOO * Ii1I
  for o0OOooooooOO in I11iiiIIi1 :
   if ( o0OOooooooOO . map_notify_requested == False ) : continue
   if ( o0OOooooooOO . rloc . is_exact_match ( source ) ) : continue
   lisp_build_map_notify ( lisp_sockets , iIi1i1i1II1 , iIii1iI1ii1iI , 1 , o0OOooooooOO . rloc ,
 LISP_CTRL_PORT , i1I11II11iIi1 . nonce , i1I11II11iIi1 . key_id ,
 i1I11II11iIi1 . alg_id , i1I11II11iIi1 . auth_len , i11i1IiiII , False )
   if 100 - 100: I1ii11iIi11i / Ii1I % Oo0Ooo
   if 83 - 83: O0 . I1Ii111 % I1ii11iIi11i
   if 97 - 97: Oo0Ooo % OoO0O00 * I1ii11iIi11i * ooOoO0o * OoO0O00
   if 12 - 12: ooOoO0o
   if 56 - 56: i1IIi
  lisp_notify_subscribers ( lisp_sockets , iIi1i1i1II1 , iIi1iIIiiIi . eid , i11i1IiiII )
  if 3 - 3: OOooOOo - Oo0Ooo * Ii1I + i11iIiiIii
  if 53 - 53: i1IIi % I1ii11iIi11i
  if 65 - 65: I11i + OoOoOO00 - i11iIiiIii
  if 72 - 72: i11iIiiIii - iII111i . i11iIiiIii
  if 61 - 61: oO0o . i11iIiiIii / Ii1I % iII111i
 if ( len ( O00 ) != 0 ) :
  lisp_queue_multicast_map_notify ( lisp_sockets , O00 )
  if 36 - 36: OoO0O00 + Ii1I / I11i - iII111i % OoO0O00 / Oo0Ooo
  if 38 - 38: Ii1I - ooOoO0o - O0 + oO0o . iIii1I11I1II1
  if 90 - 90: i1IIi * OoOoOO00
  if 27 - 27: iIii1I11I1II1
  if 95 - 95: iII111i / ooOoO0o % Ii1I
  if 44 - 44: OOooOOo . OOooOOo
 if ( i1I11II11iIi1 . merge_register_requested ) : return
 if 5 - 5: oO0o + OoooooooOO
 if 88 - 88: oO0o + OOooOOo
 if 14 - 14: I11i / i1IIi
 if 56 - 56: OoooooooOO
 if 59 - 59: I1ii11iIi11i + OoO0O00
 if ( i1I11II11iIi1 . map_notify_requested and i11i1IiiII != None ) :
  lisp_build_map_notify ( lisp_sockets , i1i1iI1 , iIIIIiiii ,
 i1I11II11iIi1 . record_count , source , sport , i1I11II11iIi1 . nonce ,
 i1I11II11iIi1 . key_id , i1I11II11iIi1 . alg_id , i1I11II11iIi1 . auth_len ,
 i11i1IiiII , True )
  if 37 - 37: IiII * I1IiiI % O0
 return
 if 32 - 32: ooOoO0o % II111iiii
 if 60 - 60: i11iIiiIii
 if 11 - 11: o0oOOo0O0Ooo
 if 77 - 77: o0oOOo0O0Ooo / iIii1I11I1II1 * iIii1I11I1II1 / o0oOOo0O0Ooo * iII111i
 if 26 - 26: Ii1I
 if 1 - 1: OoOoOO00 . o0oOOo0O0Ooo + Oo0Ooo % Oo0Ooo * I1ii11iIi11i
 if 50 - 50: IiII / i1IIi . I1ii11iIi11i
 if 75 - 75: I11i * oO0o + OoooooooOO . iII111i + OoO0O00
 if 44 - 44: II111iiii
 if 65 - 65: I11i . iII111i . I1IiiI - Oo0Ooo % iIii1I11I1II1 / O0
def lisp_process_multicast_map_notify ( packet , source ) :
 Ii1I1i111 = lisp_map_notify ( "" )
 packet = Ii1I1i111 . decode ( packet )
 if ( packet == None ) :
  lprint ( "Could not decode Map-Notify packet" )
  return
  if 54 - 54: iII111i - I1Ii111
  if 88 - 88: iII111i * OoO0O00 % OoooooooOO / oO0o
 Ii1I1i111 . print_notify ( )
 if ( Ii1I1i111 . record_count == 0 ) : return
 if 7 - 7: i1IIi
 iIiI1Ii = Ii1I1i111 . eid_records
 if 78 - 78: iII111i - OoO0O00 - I11i / oO0o
 for o0OoO00 in range ( Ii1I1i111 . record_count ) :
  iIi1i1i1II1 = lisp_eid_record ( )
  iIiI1Ii = iIi1i1i1II1 . decode ( iIiI1Ii )
  if ( packet == None ) : return
  iIi1i1i1II1 . print_record ( "  " , False )
  if 45 - 45: I11i . OoooooooOO - i11iIiiIii - I1ii11iIi11i / oO0o
  if 54 - 54: i1IIi . ooOoO0o + O0 . ooOoO0o * iIii1I11I1II1
  if 82 - 82: iII111i % OoO0O00 * O0
  if 38 - 38: o0oOOo0O0Ooo * o0oOOo0O0Ooo - I1IiiI . iII111i % iIii1I11I1II1 + I1ii11iIi11i
  OoOOO000O0o = lisp_map_cache_lookup ( iIi1i1i1II1 . eid , iIi1i1i1II1 . group )
  if ( OoOOO000O0o == None ) :
   OoOOO000O0o = lisp_mapping ( iIi1i1i1II1 . eid , iIi1i1i1II1 . group , [ ] )
   OoOOO000O0o . add_cache ( )
   if 56 - 56: I1Ii111 % oO0o
   if 31 - 31: OOooOOo + IiII
   if 56 - 56: OoooooooOO * II111iiii
   if 99 - 99: i11iIiiIii - II111iiii . Oo0Ooo - oO0o . I1IiiI + i1IIi
   if 69 - 69: O0 / i1IIi - OoOoOO00 + ooOoO0o - oO0o
   if 80 - 80: o0oOOo0O0Ooo % O0 * I11i . i1IIi - ooOoO0o
   if 93 - 93: OoooooooOO / o0oOOo0O0Ooo
  if ( OoOOO000O0o . gleaned ) :
   lprint ( "Suppress Map-Notify for gleaned {}" . format ( green ( OoOOO000O0o . print_eid_tuple ( ) , False ) ) )
   if 61 - 61: II111iiii / i1IIi . I1ii11iIi11i % iIii1I11I1II1
   continue
   if 66 - 66: iIii1I11I1II1 % OoOoOO00 + i1IIi * i11iIiiIii * OoooooooOO
   if 36 - 36: iII111i - OoO0O00 + I1IiiI + Ii1I . OoooooooOO
  OoOOO000O0o . mapping_source = None if source == "lisp-etr" else source
  OoOOO000O0o . map_cache_ttl = iIi1i1i1II1 . store_ttl ( )
  if 75 - 75: oO0o * Oo0Ooo * O0
  if 22 - 22: ooOoO0o / OoooooooOO . II111iiii / Ii1I * OoO0O00 . i1IIi
  if 62 - 62: oO0o % Ii1I - Ii1I
  if 16 - 16: OoO0O00 - O0 - OOooOOo - I11i % OoOoOO00
  if 7 - 7: I1Ii111 / OoOoOO00 . II111iiii
  if ( len ( OoOOO000O0o . rloc_set ) != 0 and iIi1i1i1II1 . rloc_count == 0 ) :
   OoOOO000O0o . rloc_set = [ ]
   OoOOO000O0o . build_best_rloc_set ( )
   lisp_write_ipc_map_cache ( True , OoOOO000O0o )
   lprint ( "Update {} map-cache entry with no RLOC-set" . format ( green ( OoOOO000O0o . print_eid_tuple ( ) , False ) ) )
   if 9 - 9: I11i . I11i . OoooooooOO
   continue
   if 42 - 42: iII111i / oO0o / iII111i * OoO0O00
   if 25 - 25: OoOoOO00 - II111iiii + II111iiii . Ii1I * II111iiii
  i11I1 = OoOOO000O0o . rtrs_in_rloc_set ( )
  if 42 - 42: Ii1I % OoooooooOO * i1IIi
  if 67 - 67: OoOoOO00 + I1IiiI % iII111i
  if 2 - 2: ooOoO0o - ooOoO0o % OoO0O00 / I1IiiI - Oo0Ooo
  if 30 - 30: i11iIiiIii / OoO0O00 - IiII / Oo0Ooo + I11i - i1IIi
  if 67 - 67: i11iIiiIii * I11i * Ii1I + OoooooooOO * OoO0O00
  for iI1I1I111 in range ( iIi1i1i1II1 . rloc_count ) :
   o000O = lisp_rloc_record ( )
   iIiI1Ii = o000O . decode ( iIiI1Ii , None )
   o000O . print_record ( "    " )
   if ( iIi1i1i1II1 . group . is_null ( ) ) : continue
   if ( o000O . rle == None ) : continue
   if 28 - 28: I1Ii111 - iIii1I11I1II1
   if 88 - 88: Oo0Ooo * i1IIi % OOooOOo
   if 65 - 65: iII111i . oO0o
   if 67 - 67: I1IiiI / iII111i / O0 % ooOoO0o - IiII / Ii1I
   if 31 - 31: I11i - oO0o * ooOoO0o
   oO000ooOOo = OoOOO000O0o . rloc_set [ 0 ] . stats if len ( OoOOO000O0o . rloc_set ) != 0 else None
   if 45 - 45: I1Ii111 + IiII . iIii1I11I1II1
   if 89 - 89: I11i
   if 22 - 22: i1IIi * OoOoOO00 - i11iIiiIii . i1IIi - OOooOOo . iIii1I11I1II1
   if 43 - 43: OoO0O00 % OOooOOo / I11i + I1ii11iIi11i - OoOoOO00 % I1Ii111
   o0OOooooooOO = lisp_rloc ( )
   o0OOooooooOO . store_rloc_from_record ( o000O , None , OoOOO000O0o . mapping_source )
   if ( oO000ooOOo != None ) : o0OOooooooOO . stats = copy . deepcopy ( oO000ooOOo )
   if 18 - 18: OoooooooOO - ooOoO0o + iIii1I11I1II1 - OOooOOo + IiII
   if ( i11I1 and o0OOooooooOO . is_rtr ( ) == False ) : continue
   if 56 - 56: OoOoOO00 * OoO0O00 + oO0o
   OoOOO000O0o . rloc_set = [ o0OOooooooOO ]
   OoOOO000O0o . build_best_rloc_set ( )
   lisp_write_ipc_map_cache ( True , OoOOO000O0o )
   if 52 - 52: iIii1I11I1II1 + Oo0Ooo + ooOoO0o / ooOoO0o
   lprint ( "Update {} map-cache entry with RLE {}" . format ( green ( OoOOO000O0o . print_eid_tuple ( ) , False ) , o0OOooooooOO . rle . print_rle ( False ) ) )
   if 60 - 60: ooOoO0o
   if 79 - 79: i1IIi % OoO0O00
   if 26 - 26: OoOoOO00 * IiII
 return
 if 76 - 76: I1IiiI + IiII * I1ii11iIi11i * I1IiiI % Ii1I + ooOoO0o
 if 46 - 46: OoOoOO00
 if 66 - 66: iII111i - O0 . I1Ii111 * i1IIi / OoO0O00 / II111iiii
 if 35 - 35: ooOoO0o * OOooOOo / I11i % I11i / OoooooooOO . I1Ii111
 if 70 - 70: I1ii11iIi11i % I1ii11iIi11i / oO0o
 if 85 - 85: OoOoOO00 % I11i / Oo0Ooo + I11i - Oo0Ooo
 if 20 - 20: IiII
 if 81 - 81: Oo0Ooo / I1Ii111
def lisp_process_map_notify ( lisp_sockets , orig_packet , source ) :
 Ii1I1i111 = lisp_map_notify ( "" )
 Oo0O0oo = Ii1I1i111 . decode ( orig_packet )
 if ( Oo0O0oo == None ) :
  lprint ( "Could not decode Map-Notify packet" )
  return
  if 20 - 20: o0oOOo0O0Ooo + ooOoO0o % i1IIi
  if 51 - 51: iII111i - ooOoO0o
 Ii1I1i111 . print_notify ( )
 if 32 - 32: IiII - i11iIiiIii
 if 41 - 41: Ii1I % Ii1I * oO0o - I11i + iIii1I11I1II1 . ooOoO0o
 if 30 - 30: Ii1I * iII111i . II111iiii / i1IIi
 if 77 - 77: oO0o . IiII + I1ii11iIi11i . i1IIi
 if 49 - 49: I1Ii111 . OoooooooOO / o0oOOo0O0Ooo - iII111i - iII111i - i11iIiiIii
 IiiiI1 = source . print_address ( )
 if ( Ii1I1i111 . alg_id != 0 or Ii1I1i111 . auth_len != 0 ) :
  I1iiIIiiiII = None
  for i1iI11iI in lisp_map_servers_list :
   if ( i1iI11iI . find ( IiiiI1 ) == - 1 ) : continue
   I1iiIIiiiII = lisp_map_servers_list [ i1iI11iI ]
   if 37 - 37: OOooOOo
  if ( I1iiIIiiiII == None ) :
   lprint ( ( "  Could not find Map-Server {} to authenticate " + "Map-Notify" ) . format ( IiiiI1 ) )
   if 79 - 79: I1Ii111 - OoO0O00 + ooOoO0o + oO0o . i11iIiiIii + i1IIi
   return
   if 32 - 32: IiII . ooOoO0o / OoO0O00 / iII111i . iIii1I11I1II1 % IiII
   if 28 - 28: I1Ii111 + OoooooooOO + IiII . ooOoO0o . I1IiiI / oO0o
  I1iiIIiiiII . map_notifies_received += 1
  if 66 - 66: Ii1I - I11i + Oo0Ooo . ooOoO0o
  ooOoOO00o0O = lisp_verify_auth ( Oo0O0oo , Ii1I1i111 . alg_id ,
 Ii1I1i111 . auth_data , I1iiIIiiiII . password )
  if 89 - 89: IiII . II111iiii / OoO0O00 + I1ii11iIi11i * i11iIiiIii
  lprint ( "  Authentication {} for Map-Notify" . format ( "succeeded" if ooOoOO00o0O else "failed" ) )
  if 85 - 85: o0oOOo0O0Ooo - Oo0Ooo / I1Ii111
  if ( ooOoOO00o0O == False ) : return
 else :
  I1iiIIiiiII = lisp_ms ( IiiiI1 , None , "" , 0 , "" , False , False , False , False , 0 , 0 , 0 ,
 None )
  if 100 - 100: OoO0O00 * iIii1I11I1II1 - IiII . i1IIi % i11iIiiIii % Oo0Ooo
  if 22 - 22: ooOoO0o - OOooOOo
  if 90 - 90: i11iIiiIii . i11iIiiIii - iIii1I11I1II1
  if 20 - 20: ooOoO0o - i11iIiiIii
  if 23 - 23: OoO0O00 + I1IiiI / I1ii11iIi11i * I1ii11iIi11i % ooOoO0o
  if 83 - 83: I1IiiI * i11iIiiIii - I1ii11iIi11i + I11i
 iIiI1Ii = Ii1I1i111 . eid_records
 if ( Ii1I1i111 . record_count == 0 ) :
  lisp_send_map_notify_ack ( lisp_sockets , iIiI1Ii , Ii1I1i111 , I1iiIIiiiII )
  return
  if 33 - 33: OoO0O00 . OoooooooOO % iII111i / oO0o * Ii1I + ooOoO0o
  if 29 - 29: oO0o
  if 21 - 21: i11iIiiIii . o0oOOo0O0Ooo
  if 78 - 78: Oo0Ooo
  if 77 - 77: oO0o % Oo0Ooo % O0
  if 51 - 51: IiII % IiII + OOooOOo . II111iiii / I1ii11iIi11i
  if 4 - 4: o0oOOo0O0Ooo % I1IiiI * o0oOOo0O0Ooo * OoOoOO00 - Ii1I
  if 61 - 61: OoooooooOO - OoOoOO00 . O0 / ooOoO0o . Ii1I
 iIi1i1i1II1 = lisp_eid_record ( )
 Oo0O0oo = iIi1i1i1II1 . decode ( iIiI1Ii )
 if ( Oo0O0oo == None ) : return
 if 41 - 41: Oo0Ooo / OoOoOO00 % I1Ii111 - O0
 iIi1i1i1II1 . print_record ( "  " , False )
 if 19 - 19: I1IiiI % I1Ii111 - O0 . iIii1I11I1II1 . I11i % O0
 for iI1I1I111 in range ( iIi1i1i1II1 . rloc_count ) :
  o000O = lisp_rloc_record ( )
  Oo0O0oo = o000O . decode ( Oo0O0oo , None )
  if ( Oo0O0oo == None ) :
   lprint ( "  Could not decode RLOC-record in Map-Notify packet" )
   return
   if 88 - 88: ooOoO0o
  o000O . print_record ( "    " )
  if 52 - 52: iIii1I11I1II1 % ooOoO0o * iIii1I11I1II1
  if 20 - 20: i11iIiiIii * I11i
  if 29 - 29: IiII / OOooOOo
  if 39 - 39: O0 + II111iiii
  if 94 - 94: OOooOOo % I1ii11iIi11i % O0 + iII111i
 if ( iIi1i1i1II1 . group . is_null ( ) == False ) :
  if 62 - 62: iIii1I11I1II1 . OoOoOO00 / iIii1I11I1II1 + IiII
  if 31 - 31: Ii1I . OoO0O00 . Ii1I + OoO0O00 * iIii1I11I1II1 . iII111i
  if 42 - 42: O0 / oO0o % O0 . i1IIi % OOooOOo
  if 13 - 13: I1IiiI % ooOoO0o + OOooOOo
  if 91 - 91: oO0o - ooOoO0o
  lprint ( "Send {} Map-Notify IPC message to ITR process" . format ( green ( iIi1i1i1II1 . print_eid_tuple ( ) , False ) ) )
  if 20 - 20: i1IIi . IiII / o0oOOo0O0Ooo / I11i
  if 27 - 27: ooOoO0o . ooOoO0o - Ii1I % i11iIiiIii
  Ooooo = lisp_control_packet_ipc ( orig_packet , IiiiI1 , "lisp-itr" , 0 )
  lisp_ipc ( Ooooo , lisp_sockets [ 2 ] , "lisp-core-pkt" )
  if 74 - 74: I1Ii111 - II111iiii % o0oOOo0O0Ooo
  if 7 - 7: I1IiiI + OoooooooOO + o0oOOo0O0Ooo . OoooooooOO
  if 29 - 29: iII111i * O0 + I1IiiI * IiII + iII111i - IiII
  if 38 - 38: I1ii11iIi11i - Ii1I % OoooooooOO
  if 43 - 43: iIii1I11I1II1 / OoOoOO00
 lisp_send_map_notify_ack ( lisp_sockets , iIiI1Ii , Ii1I1i111 , I1iiIIiiiII )
 return
 if 13 - 13: o0oOOo0O0Ooo / I1Ii111
 if 67 - 67: OoooooooOO . oO0o * OoOoOO00 - OoooooooOO
 if 32 - 32: oO0o
 if 72 - 72: I1IiiI
 if 34 - 34: ooOoO0o % II111iiii / ooOoO0o
 if 87 - 87: Oo0Ooo
 if 7 - 7: iIii1I11I1II1
 if 85 - 85: iIii1I11I1II1 . O0
def lisp_process_map_notify_ack ( packet , source ) :
 Ii1I1i111 = lisp_map_notify ( "" )
 packet = Ii1I1i111 . decode ( packet )
 if ( packet == None ) :
  lprint ( "Could not decode Map-Notify-Ack packet" )
  return
  if 43 - 43: II111iiii / OoOoOO00 + OOooOOo % Oo0Ooo * OOooOOo
  if 62 - 62: ooOoO0o * OOooOOo . I11i + Oo0Ooo - I1Ii111
 Ii1I1i111 . print_notify ( )
 if 48 - 48: I1Ii111 * Oo0Ooo % OoO0O00 % Ii1I
 if 8 - 8: OoO0O00 . OoO0O00
 if 29 - 29: I11i + OoooooooOO % o0oOOo0O0Ooo - I1Ii111
 if 45 - 45: II111iiii - OOooOOo / oO0o % O0 . iII111i . iII111i
 if 82 - 82: iIii1I11I1II1 % Oo0Ooo * i1IIi - I1Ii111 - I1ii11iIi11i / iII111i
 if ( Ii1I1i111 . record_count < 1 ) :
  lprint ( "No EID-prefix found, cannot authenticate Map-Notify-Ack" )
  return
  if 24 - 24: IiII
  if 95 - 95: IiII + OoOoOO00 * OOooOOo
 iIi1i1i1II1 = lisp_eid_record ( )
 if 92 - 92: OoOoOO00 + ooOoO0o . iII111i
 if ( iIi1i1i1II1 . decode ( Ii1I1i111 . eid_records ) == None ) :
  lprint ( "Could not decode EID-record, cannot authenticate " +
 "Map-Notify-Ack" )
  return
  if 59 - 59: iIii1I11I1II1 % I1Ii111 + I1ii11iIi11i . OoOoOO00 * Oo0Ooo / I1Ii111
 iIi1i1i1II1 . print_record ( "  " , False )
 if 41 - 41: i1IIi / IiII
 oo0oO = iIi1i1i1II1 . print_eid_tuple ( )
 if 73 - 73: o0oOOo0O0Ooo % ooOoO0o
 if 72 - 72: OoO0O00 * OoOoOO00 % I1IiiI - OOooOOo . Oo0Ooo
 if 70 - 70: ooOoO0o . o0oOOo0O0Ooo * II111iiii - O0
 if 74 - 74: oO0o % I1IiiI / oO0o / Oo0Ooo / ooOoO0o
 if ( Ii1I1i111 . alg_id != LISP_NONE_ALG_ID and Ii1I1i111 . auth_len != 0 ) :
  iIi1iIIiiIi = lisp_sites_by_eid . lookup_cache ( iIi1i1i1II1 . eid , True )
  if ( iIi1iIIiiIi == None ) :
   oO0 = bold ( "Site not found" , False )
   lprint ( ( "{} for EID {}, cannot authenticate Map-Notify-Ack" ) . format ( oO0 , green ( oo0oO , False ) ) )
   if 29 - 29: ooOoO0o + iIii1I11I1II1 + OoO0O00 - o0oOOo0O0Ooo
   return
   if 74 - 74: II111iiii - II111iiii + ooOoO0o + Oo0Ooo % iIii1I11I1II1
  i11i1IiiII = iIi1iIIiiIi . site
  if 90 - 90: oO0o / o0oOOo0O0Ooo . o0oOOo0O0Ooo % OoOoOO00 / IiII
  if 13 - 13: oO0o + IiII
  if 36 - 36: oO0o - OoOoOO00 . O0 % IiII
  if 65 - 65: Oo0Ooo - i11iIiiIii * OoOoOO00 . I1Ii111 . iIii1I11I1II1
  i11i1IiiII . map_notify_acks_received += 1
  if 48 - 48: iIii1I11I1II1 - oO0o / OoO0O00 + O0 . Ii1I + I1Ii111
  OOo0 = Ii1I1i111 . key_id
  if ( i11i1IiiII . auth_key . has_key ( OOo0 ) == False ) : OOo0 = 0
  IiIIIIi11i = i11i1IiiII . auth_key [ OOo0 ]
  if 17 - 17: OoOoOO00 . Oo0Ooo - I1Ii111 / I1Ii111 + I11i % i1IIi
  ooOoOO00o0O = lisp_verify_auth ( packet , Ii1I1i111 . alg_id ,
 Ii1I1i111 . auth_data , IiIIIIi11i )
  if 31 - 31: OoooooooOO . O0 / OoO0O00 . I1Ii111
  OOo0 = "key-id {}" . format ( OOo0 ) if OOo0 == Ii1I1i111 . key_id else "bad key-id {}" . format ( Ii1I1i111 . key_id )
  if 41 - 41: OoooooooOO + iII111i . OOooOOo
  if 73 - 73: oO0o + i1IIi + i11iIiiIii / I1ii11iIi11i
  lprint ( "  Authentication {} for Map-Notify-Ack, {}" . format ( "succeeded" if ooOoOO00o0O else "failed" , OOo0 ) )
  if 100 - 100: I1IiiI % ooOoO0o % OoooooooOO / i11iIiiIii + i11iIiiIii % IiII
  if ( ooOoOO00o0O == False ) : return
  if 39 - 39: Ii1I % o0oOOo0O0Ooo + OOooOOo / iIii1I11I1II1
  if 40 - 40: iIii1I11I1II1 / iII111i % OOooOOo % i11iIiiIii
  if 57 - 57: II111iiii % OoO0O00 * i1IIi
  if 19 - 19: ooOoO0o . iIii1I11I1II1 + I1ii11iIi11i + I1ii11iIi11i / o0oOOo0O0Ooo . Oo0Ooo
  if 9 - 9: II111iiii % OoooooooOO
 if ( Ii1I1i111 . retransmit_timer ) : Ii1I1i111 . retransmit_timer . cancel ( )
 if 4 - 4: i1IIi * i11iIiiIii % OoooooooOO + OoOoOO00 . oO0o
 OOOIII11i1 = source . print_address ( )
 i1iI11iI = Ii1I1i111 . nonce_key
 if 95 - 95: I1ii11iIi11i * OoOoOO00 % o0oOOo0O0Ooo / O0 + ooOoO0o % OOooOOo
 if ( lisp_map_notify_queue . has_key ( i1iI11iI ) ) :
  Ii1I1i111 = lisp_map_notify_queue . pop ( i1iI11iI )
  if ( Ii1I1i111 . retransmit_timer ) : Ii1I1i111 . retransmit_timer . cancel ( )
  lprint ( "Dequeue Map-Notify from retransmit queue, key is: {}" . format ( i1iI11iI ) )
  if 48 - 48: i1IIi + IiII - iIii1I11I1II1 . i11iIiiIii % OOooOOo + I1ii11iIi11i
 else :
  lprint ( "Map-Notify with nonce 0x{} queue entry not found for {}" . format ( Ii1I1i111 . nonce_key , red ( OOOIII11i1 , False ) ) )
  if 95 - 95: ooOoO0o + OoOoOO00 . II111iiii + Ii1I
  if 81 - 81: OoooooooOO / OOooOOo / Oo0Ooo
 return
 if 26 - 26: iII111i
 if 93 - 93: Oo0Ooo + I1IiiI % OoOoOO00 / OOooOOo / I1ii11iIi11i
 if 6 - 6: IiII
 if 68 - 68: Oo0Ooo
 if 83 - 83: OOooOOo / iIii1I11I1II1 . OoO0O00 - oO0o % Oo0Ooo
 if 30 - 30: Ii1I . OoOoOO00 / oO0o . OoO0O00
 if 93 - 93: i11iIiiIii
 if 33 - 33: i1IIi % OoooooooOO + Oo0Ooo % I1IiiI / ooOoO0o
def lisp_map_referral_loop ( mr , eid , group , action , s ) :
 if ( action not in ( LISP_DDT_ACTION_NODE_REFERRAL ,
 LISP_DDT_ACTION_MS_REFERRAL ) ) : return ( False )
 if 40 - 40: IiII % IiII
 if ( mr . last_cached_prefix [ 0 ] == None ) : return ( False )
 if 9 - 9: I1IiiI * i1IIi + OOooOOo * OoOoOO00
 if 8 - 8: iII111i
 if 51 - 51: I1IiiI
 if 72 - 72: ooOoO0o / I1ii11iIi11i . Ii1I * iII111i . iIii1I11I1II1
 iiiI1i1i1 = False
 if ( group . is_null ( ) == False ) :
  iiiI1i1i1 = mr . last_cached_prefix [ 1 ] . is_more_specific ( group )
  if 35 - 35: OoO0O00 . OoOoOO00 % O0 * OoO0O00
 if ( iiiI1i1i1 == False ) :
  iiiI1i1i1 = mr . last_cached_prefix [ 0 ] . is_more_specific ( eid )
  if 68 - 68: OOooOOo
  if 87 - 87: IiII * IiII - OoO0O00 / I1ii11iIi11i + OOooOOo / i11iIiiIii
 if ( iiiI1i1i1 ) :
  oo0Ooo = lisp_print_eid_tuple ( eid , group )
  IIII = lisp_print_eid_tuple ( mr . last_cached_prefix [ 0 ] ,
 mr . last_cached_prefix [ 1 ] )
  if 36 - 36: Oo0Ooo / Oo0Ooo - o0oOOo0O0Ooo - i11iIiiIii
  lprint ( ( "Map-Referral prefix {} from {} is not more-specific " + "than cached prefix {}" ) . format ( green ( oo0Ooo , False ) , s ,
  # i1IIi + OoooooooOO . ooOoO0o . i11iIiiIii
 IIII ) )
  if 21 - 21: II111iiii % oO0o * I1ii11iIi11i
 return ( iiiI1i1i1 )
 if 24 - 24: II111iiii % OOooOOo
 if 22 - 22: OoooooooOO + i1IIi % OoooooooOO
 if 15 - 15: o0oOOo0O0Ooo % I1ii11iIi11i / II111iiii
 if 50 - 50: oO0o * Ii1I % I1Ii111
 if 74 - 74: iIii1I11I1II1 - OOooOOo / I1Ii111 / ooOoO0o . oO0o % iIii1I11I1II1
 if 91 - 91: o0oOOo0O0Ooo . o0oOOo0O0Ooo - Ii1I
 if 60 - 60: i11iIiiIii . Oo0Ooo / iIii1I11I1II1 / II111iiii
def lisp_process_map_referral ( lisp_sockets , packet , source ) :
 if 31 - 31: Oo0Ooo / Oo0Ooo / iIii1I11I1II1 / I11i % OoooooooOO
 o000OOO0 = lisp_map_referral ( )
 packet = o000OOO0 . decode ( packet )
 if ( packet == None ) :
  lprint ( "Could not decode Map-Referral packet" )
  return
  if 90 - 90: I1IiiI
 o000OOO0 . print_map_referral ( )
 if 35 - 35: O0
 IiiiI1 = source . print_address ( )
 Iii1i11 = o000OOO0 . nonce
 if 10 - 10: Ii1I - I1Ii111 / Oo0Ooo + O0
 if 67 - 67: Ii1I % i11iIiiIii . Oo0Ooo
 if 78 - 78: I1IiiI - iIii1I11I1II1
 if 20 - 20: i11iIiiIii % I1IiiI % OoOoOO00
 for o0OoO00 in range ( o000OOO0 . record_count ) :
  iIi1i1i1II1 = lisp_eid_record ( )
  packet = iIi1i1i1II1 . decode ( packet )
  if ( packet == None ) :
   lprint ( "Could not decode EID-record in Map-Referral packet" )
   return
   if 85 - 85: I11i + OoOoOO00 * O0 * O0
  iIi1i1i1II1 . print_record ( "  " , True )
  if 92 - 92: i11iIiiIii
  if 16 - 16: I11i . ooOoO0o - Oo0Ooo / OoO0O00 . i1IIi
  if 59 - 59: ooOoO0o - ooOoO0o % I11i + OoO0O00
  if 88 - 88: Ii1I - ooOoO0o . Oo0Ooo
  i1iI11iI = str ( Iii1i11 )
  if ( i1iI11iI not in lisp_ddt_map_requestQ ) :
   lprint ( ( "Map-Referral nonce 0x{} from {} not found in " + "Map-Request queue, EID-record ignored" ) . format ( lisp_hex_string ( Iii1i11 ) , IiiiI1 ) )
   if 83 - 83: I11i + Oo0Ooo . I1ii11iIi11i * I1ii11iIi11i
   if 80 - 80: i1IIi * I11i - OOooOOo / II111iiii * iIii1I11I1II1
   continue
   if 42 - 42: OoOoOO00 . I11i % II111iiii
  OOO0o0o = lisp_ddt_map_requestQ [ i1iI11iI ]
  if ( OOO0o0o == None ) :
   lprint ( ( "No Map-Request queue entry found for Map-Referral " +
 "nonce 0x{} from {}, EID-record ignored" ) . format ( lisp_hex_string ( Iii1i11 ) , IiiiI1 ) )
   if 19 - 19: OoooooooOO
   continue
   if 31 - 31: I11i . OoOoOO00 - O0 * iII111i % I1Ii111 - II111iiii
   if 21 - 21: OOooOOo . Oo0Ooo - i1IIi
   if 56 - 56: I11i
   if 24 - 24: I1IiiI . I1IiiI % ooOoO0o
   if 32 - 32: OOooOOo / i1IIi / OOooOOo
   if 97 - 97: ooOoO0o * Oo0Ooo * OoooooooOO * I1IiiI
  if ( lisp_map_referral_loop ( OOO0o0o , iIi1i1i1II1 . eid , iIi1i1i1II1 . group ,
 iIi1i1i1II1 . action , IiiiI1 ) ) :
   OOO0o0o . dequeue_map_request ( )
   continue
   if 45 - 45: Oo0Ooo
   if 27 - 27: oO0o / IiII - iIii1I11I1II1 / o0oOOo0O0Ooo % OOooOOo * iIii1I11I1II1
  OOO0o0o . last_cached_prefix [ 0 ] = iIi1i1i1II1 . eid
  OOO0o0o . last_cached_prefix [ 1 ] = iIi1i1i1II1 . group
  if 40 - 40: oO0o - II111iiii * OOooOOo % OoooooooOO
  if 52 - 52: OOooOOo + OoO0O00
  if 96 - 96: OOooOOo % O0 - Oo0Ooo % oO0o / I1IiiI . i1IIi
  if 42 - 42: i1IIi
  iI111iiI = False
  II11IIIIi = lisp_referral_cache_lookup ( iIi1i1i1II1 . eid , iIi1i1i1II1 . group ,
 True )
  if ( II11IIIIi == None ) :
   iI111iiI = True
   II11IIIIi = lisp_referral ( )
   II11IIIIi . eid = iIi1i1i1II1 . eid
   II11IIIIi . group = iIi1i1i1II1 . group
   if ( iIi1i1i1II1 . ddt_incomplete == False ) : II11IIIIi . add_cache ( )
  elif ( II11IIIIi . referral_source . not_set ( ) ) :
   lprint ( "Do not replace static referral entry {}" . format ( green ( II11IIIIi . print_eid_tuple ( ) , False ) ) )
   if 52 - 52: OoO0O00 % iII111i % O0
   OOO0o0o . dequeue_map_request ( )
   continue
   if 11 - 11: i1IIi / i11iIiiIii + Ii1I % Oo0Ooo % O0
   if 50 - 50: oO0o . I1Ii111
  i11IIiI = iIi1i1i1II1 . action
  II11IIIIi . referral_source = source
  II11IIIIi . referral_type = i11IIiI
  I1i = iIi1i1i1II1 . store_ttl ( )
  II11IIIIi . referral_ttl = I1i
  II11IIIIi . expires = lisp_set_timestamp ( I1i )
  if 38 - 38: iIii1I11I1II1 . Ii1I
  if 82 - 82: OOooOOo * Ii1I + I1ii11iIi11i . OoO0O00
  if 15 - 15: O0
  if 44 - 44: Ii1I . Oo0Ooo . I1Ii111 + oO0o
  I1Ii11Ii = II11IIIIi . is_referral_negative ( )
  if ( II11IIIIi . referral_set . has_key ( IiiiI1 ) ) :
   ii1I111ii = II11IIIIi . referral_set [ IiiiI1 ]
   if 37 - 37: ooOoO0o . I1IiiI
   if ( ii1I111ii . updown == False and I1Ii11Ii == False ) :
    ii1I111ii . updown = True
    lprint ( "Change up/down status for referral-node {} to up" . format ( IiiiI1 ) )
    if 1 - 1: iIii1I11I1II1 . o0oOOo0O0Ooo % I11i
   elif ( ii1I111ii . updown == True and I1Ii11Ii == True ) :
    ii1I111ii . updown = False
    lprint ( ( "Change up/down status for referral-node {} " + "to down, received negative referral" ) . format ( IiiiI1 ) )
    if 94 - 94: oO0o
    if 47 - 47: II111iiii + iII111i + I1ii11iIi11i - iIii1I11I1II1 . Ii1I * oO0o
    if 40 - 40: i1IIi % I1IiiI / o0oOOo0O0Ooo
    if 53 - 53: iIii1I11I1II1 * oO0o
    if 43 - 43: IiII * Oo0Ooo / OOooOOo % oO0o
    if 11 - 11: OoOoOO00 * Oo0Ooo / I11i * OOooOOo
    if 15 - 15: ooOoO0o - OOooOOo / OoooooooOO
    if 41 - 41: OoOoOO00 . iII111i . i1IIi + oO0o
  oO00OOOOOOOo0 = { }
  for i1iI11iI in II11IIIIi . referral_set : oO00OOOOOOOo0 [ i1iI11iI ] = None
  if 61 - 61: o0oOOo0O0Ooo % oO0o / I1ii11iIi11i . Ii1I % II111iiii
  if 22 - 22: iIii1I11I1II1 - OoooooooOO
  if 8 - 8: ooOoO0o % i11iIiiIii
  if 41 - 41: I1Ii111 . ooOoO0o - i11iIiiIii + Ii1I . OOooOOo . OoOoOO00
  for o0OoO00 in range ( iIi1i1i1II1 . rloc_count ) :
   o000O = lisp_rloc_record ( )
   packet = o000O . decode ( packet , None )
   if ( packet == None ) :
    lprint ( "Could not decode RLOC-record in Map-Referral packet" )
    return
    if 70 - 70: i1IIi % OoOoOO00 / iII111i + i11iIiiIii % ooOoO0o + IiII
   o000O . print_record ( "    " )
   if 58 - 58: OOooOOo / i11iIiiIii . Oo0Ooo % iII111i
   if 92 - 92: OoOoOO00 / ooOoO0o % iII111i / iIii1I11I1II1
   if 73 - 73: O0 % i11iIiiIii
   if 16 - 16: O0
   I1IIII1i1 = o000O . rloc . print_address ( )
   if ( II11IIIIi . referral_set . has_key ( I1IIII1i1 ) == False ) :
    ii1I111ii = lisp_referral_node ( )
    ii1I111ii . referral_address . copy_address ( o000O . rloc )
    II11IIIIi . referral_set [ I1IIII1i1 ] = ii1I111ii
    if ( IiiiI1 == I1IIII1i1 and I1Ii11Ii ) : ii1I111ii . updown = False
   else :
    ii1I111ii = II11IIIIi . referral_set [ I1IIII1i1 ]
    if ( oO00OOOOOOOo0 . has_key ( I1IIII1i1 ) ) : oO00OOOOOOOo0 . pop ( I1IIII1i1 )
    if 15 - 15: i1IIi % i11iIiiIii
   ii1I111ii . priority = o000O . priority
   ii1I111ii . weight = o000O . weight
   if 18 - 18: Ii1I . OoO0O00 . iII111i * oO0o + O0
   if 35 - 35: OoOoOO00 . oO0o / II111iiii
   if 97 - 97: Ii1I + I1Ii111 / II111iiii
   if 14 - 14: iII111i / IiII / oO0o
   if 55 - 55: OoO0O00 % O0
  for i1iI11iI in oO00OOOOOOOo0 : II11IIIIi . referral_set . pop ( i1iI11iI )
  if 92 - 92: OoooooooOO / O0
  oo0oO = II11IIIIi . print_eid_tuple ( )
  if 14 - 14: i11iIiiIii
  if ( iI111iiI ) :
   if ( iIi1i1i1II1 . ddt_incomplete ) :
    lprint ( "Suppress add {} to referral-cache" . format ( green ( oo0oO , False ) ) )
    if 43 - 43: OOooOOo
   else :
    lprint ( "Add {}, referral-count {} to referral-cache" . format ( green ( oo0oO , False ) , iIi1i1i1II1 . rloc_count ) )
    if 79 - 79: iII111i % Oo0Ooo . i1IIi % ooOoO0o
    if 93 - 93: OoOoOO00
  else :
   lprint ( "Replace {}, referral-count: {} in referral-cache" . format ( green ( oo0oO , False ) , iIi1i1i1II1 . rloc_count ) )
   if 49 - 49: i1IIi * OOooOOo % I11i * Ii1I . I1Ii111 * iIii1I11I1II1
   if 72 - 72: ooOoO0o
   if 63 - 63: Oo0Ooo . OoO0O00 . OoooooooOO / i1IIi
   if 53 - 53: OOooOOo * O0 . iII111i
   if 3 - 3: OoooooooOO * I1Ii111 * IiII - OOooOOo * I1Ii111
   if 78 - 78: iII111i
  if ( i11IIiI == LISP_DDT_ACTION_DELEGATION_HOLE ) :
   lisp_send_negative_map_reply ( OOO0o0o . lisp_sockets , II11IIIIi . eid ,
 II11IIIIi . group , OOO0o0o . nonce , OOO0o0o . itr , OOO0o0o . sport , 15 , None , False )
   OOO0o0o . dequeue_map_request ( )
   if 80 - 80: i1IIi * I1IiiI + OOooOOo
   if 91 - 91: I1IiiI % OoOoOO00 * Oo0Ooo / I1ii11iIi11i
  if ( i11IIiI == LISP_DDT_ACTION_NOT_AUTH ) :
   if ( OOO0o0o . tried_root ) :
    lisp_send_negative_map_reply ( OOO0o0o . lisp_sockets , II11IIIIi . eid ,
 II11IIIIi . group , OOO0o0o . nonce , OOO0o0o . itr , OOO0o0o . sport , 0 , None , False )
    OOO0o0o . dequeue_map_request ( )
   else :
    lisp_send_ddt_map_request ( OOO0o0o , True )
    if 57 - 57: i11iIiiIii / o0oOOo0O0Ooo . II111iiii
    if 63 - 63: O0
    if 64 - 64: i11iIiiIii / oO0o . oO0o - Oo0Ooo
  if ( i11IIiI == LISP_DDT_ACTION_MS_NOT_REG ) :
   if ( II11IIIIi . referral_set . has_key ( IiiiI1 ) ) :
    ii1I111ii = II11IIIIi . referral_set [ IiiiI1 ]
    ii1I111ii . updown = False
    if 48 - 48: i1IIi + I1ii11iIi11i + I1Ii111 - iII111i
   if ( len ( II11IIIIi . referral_set ) == 0 ) :
    OOO0o0o . dequeue_map_request ( )
   else :
    lisp_send_ddt_map_request ( OOO0o0o , False )
    if 3 - 3: i1IIi + OoooooooOO * ooOoO0o + I1Ii111 % OOooOOo / IiII
    if 70 - 70: oO0o + i1IIi % o0oOOo0O0Ooo - I11i
    if 74 - 74: i11iIiiIii
  if ( i11IIiI in ( LISP_DDT_ACTION_NODE_REFERRAL ,
 LISP_DDT_ACTION_MS_REFERRAL ) ) :
   if ( OOO0o0o . eid . is_exact_match ( iIi1i1i1II1 . eid ) ) :
    if ( not OOO0o0o . tried_root ) :
     lisp_send_ddt_map_request ( OOO0o0o , True )
    else :
     lisp_send_negative_map_reply ( OOO0o0o . lisp_sockets ,
 II11IIIIi . eid , II11IIIIi . group , OOO0o0o . nonce , OOO0o0o . itr ,
 OOO0o0o . sport , 15 , None , False )
     OOO0o0o . dequeue_map_request ( )
     if 93 - 93: I1Ii111 % OOooOOo * I1IiiI % iII111i / iIii1I11I1II1 + OoO0O00
   else :
    lisp_send_ddt_map_request ( OOO0o0o , False )
    if 6 - 6: I11i
    if 70 - 70: ooOoO0o + OoooooooOO % OoOoOO00 % oO0o / Ii1I . I11i
    if 63 - 63: I1ii11iIi11i - ooOoO0o . OOooOOo / O0 . iIii1I11I1II1 - Ii1I
  if ( i11IIiI == LISP_DDT_ACTION_MS_ACK ) : OOO0o0o . dequeue_map_request ( )
  if 6 - 6: Ii1I
 return
 if 60 - 60: iII111i + I1IiiI
 if 36 - 36: i1IIi . O0 . OoO0O00 % OOooOOo * I11i / Ii1I
 if 16 - 16: Oo0Ooo
 if 44 - 44: iIii1I11I1II1 - II111iiii . IiII . i1IIi
 if 37 - 37: OoooooooOO + Oo0Ooo - Oo0Ooo + I1ii11iIi11i . I1Ii111 / I1IiiI
 if 60 - 60: I1IiiI % Ii1I / I1Ii111 + Ii1I
 if 43 - 43: I1ii11iIi11i + I11i
 if 83 - 83: II111iiii + o0oOOo0O0Ooo - I1Ii111
def lisp_process_ecm ( lisp_sockets , packet , source , ecm_port ) :
 Oo00OoooO0o = lisp_ecm ( 0 )
 packet = Oo00OoooO0o . decode ( packet )
 if ( packet == None ) :
  lprint ( "Could not decode ECM packet" )
  return
  if 100 - 100: IiII - OoOoOO00 / I11i
  if 33 - 33: I1Ii111 * OoOoOO00 . I1ii11iIi11i % I1Ii111
 Oo00OoooO0o . print_ecm ( )
 if 87 - 87: Oo0Ooo
 o0OO0 = lisp_control_header ( )
 if ( o0OO0 . decode ( packet ) == None ) :
  lprint ( "Could not decode control header" )
  return
  if 65 - 65: ooOoO0o . I1IiiI
  if 51 - 51: IiII
 iIi1i11Ii = o0OO0 . type
 del ( o0OO0 )
 if 96 - 96: Ii1I - o0oOOo0O0Ooo % i11iIiiIii
 if ( iIi1i11Ii != LISP_MAP_REQUEST ) :
  lprint ( "Received ECM without Map-Request inside" )
  return
  if 30 - 30: I1IiiI % oO0o * OoooooooOO
  if 64 - 64: I1IiiI
  if 11 - 11: I1ii11iIi11i % iII111i / II111iiii % ooOoO0o % IiII
  if 14 - 14: ooOoO0o / IiII . o0oOOo0O0Ooo
  if 27 - 27: I1IiiI - OOooOOo . II111iiii * I1ii11iIi11i % ooOoO0o / I1IiiI
 OOOOO0OO00OOO = Oo00OoooO0o . udp_sport
 lisp_process_map_request ( lisp_sockets , packet , source , ecm_port ,
 Oo00OoooO0o . source , OOOOO0OO00OOO , Oo00OoooO0o . ddt , - 1 )
 return
 if 14 - 14: I1IiiI - i11iIiiIii . O0 % OOooOOo . Ii1I
 if 46 - 46: II111iiii . i1IIi - i11iIiiIii + I11i - I1Ii111
 if 6 - 6: ooOoO0o / Ii1I / iIii1I11I1II1 - IiII - ooOoO0o
 if 7 - 7: OoOoOO00 + i1IIi % ooOoO0o * I11i + i11iIiiIii / II111iiii
 if 2 - 2: O0 / o0oOOo0O0Ooo - OoO0O00 * II111iiii
 if 4 - 4: I1IiiI + Oo0Ooo . iIii1I11I1II1
 if 100 - 100: i11iIiiIii
 if 21 - 21: OoOoOO00 + iII111i . OoO0O00
 if 79 - 79: i11iIiiIii - OoO0O00 * OoO0O00 * i1IIi / iIii1I11I1II1 + iII111i
 if 27 - 27: iII111i / Ii1I / iII111i + OoooooooOO - O0 + OoO0O00
def lisp_send_map_register ( lisp_sockets , packet , map_register , ms ) :
 if 62 - 62: iIii1I11I1II1
 if 60 - 60: Oo0Ooo % IiII % OoO0O00 - i11iIiiIii
 if 53 - 53: i11iIiiIii + OoooooooOO
 if 23 - 23: i11iIiiIii - IiII - I1ii11iIi11i + I1ii11iIi11i % I1IiiI
 if 79 - 79: II111iiii / OoooooooOO
 if 35 - 35: i1IIi + IiII + II111iiii % OOooOOo
 if 25 - 25: I11i + i11iIiiIii + O0 - Ii1I
 iI1i1iI1iI = ms . map_server
 if ( lisp_decent_push_configured and iI1i1iI1iI . is_multicast_address ( ) and
 ( ms . map_registers_multicast_sent == 1 or ms . map_registers_sent == 1 ) ) :
  iI1i1iI1iI = copy . deepcopy ( iI1i1iI1iI )
  iI1i1iI1iI . address = 0x7f000001
  oOOII1i11i1iIi11 = bold ( "Bootstrap" , False )
  IiIoO0oo0 = ms . map_server . print_address_no_iid ( )
  lprint ( "{} mapping system for peer-group {}" . format ( oOOII1i11i1iIi11 , IiIoO0oo0 ) )
  if 69 - 69: I11i . OoOoOO00 / OOooOOo / i1IIi . II111iiii
  if 17 - 17: I1Ii111
  if 2 - 2: O0 % OoOoOO00 + oO0o
  if 24 - 24: iII111i + iII111i - OoooooooOO % OoooooooOO * O0
  if 51 - 51: IiII
  if 31 - 31: I11i - iIii1I11I1II1 * Ii1I + Ii1I
 packet = lisp_compute_auth ( packet , map_register , ms . password )
 if 10 - 10: OoOoOO00 - i11iIiiIii % iIii1I11I1II1 / ooOoO0o * i11iIiiIii - Ii1I
 if 64 - 64: II111iiii . i11iIiiIii . iII111i . OOooOOo
 if 95 - 95: O0 - OoOoOO00
 if 68 - 68: ooOoO0o . I1Ii111
 if 84 - 84: OoooooooOO + oO0o % i1IIi + o0oOOo0O0Ooo * i1IIi
 if ( ms . ekey != None ) :
  O000oOooOoO0 = ms . ekey . zfill ( 32 )
  oOOOoo00oO = "0" * 8
  III1I = chacha . ChaCha ( O000oOooOoO0 , oOOOoo00oO ) . encrypt ( packet [ 4 : : ] )
  packet = packet [ 0 : 4 ] + III1I
  o0o000 = bold ( "Encrypt" , False )
  lprint ( "{} Map-Register with key-id {}" . format ( o0o000 , ms . ekey_id ) )
  if 51 - 51: oO0o . OoooooooOO + OOooOOo * I1ii11iIi11i - ooOoO0o
  if 41 - 41: Oo0Ooo
 Iiiiii1 = ""
 if ( lisp_decent_pull_xtr_configured ( ) ) :
  Iiiiii1 = ", decent-index {}" . format ( bold ( ms . dns_name , False ) )
  if 66 - 66: oO0o % i1IIi % OoooooooOO
  if 58 - 58: OOooOOo
 lprint ( "Send Map-Register to map-server {}{}{}" . format ( iI1i1iI1iI . print_address ( ) , ", ms-name '{}'" . format ( ms . ms_name ) , Iiiiii1 ) )
 if 89 - 89: iIii1I11I1II1 - i1IIi
 lisp_send ( lisp_sockets , iI1i1iI1iI , LISP_CTRL_PORT , packet )
 return
 if 26 - 26: OOooOOo - iII111i * I1ii11iIi11i / iII111i
 if 9 - 9: I1Ii111 / II111iiii * I1Ii111 / I11i - OoO0O00
 if 36 - 36: IiII . OoOoOO00 . Ii1I
 if 31 - 31: iIii1I11I1II1
 if 84 - 84: I1ii11iIi11i - iII111i * I1IiiI
 if 88 - 88: OOooOOo / Oo0Ooo
 if 31 - 31: II111iiii
 if 32 - 32: o0oOOo0O0Ooo % o0oOOo0O0Ooo
def lisp_send_ipc_to_core ( lisp_socket , packet , dest , port ) :
 OO = lisp_socket . getsockname ( )
 dest = dest . print_address_no_iid ( )
 if 67 - 67: IiII + oO0o * IiII
 lprint ( "Send IPC {} bytes to {} {}, control-packet: {}" . format ( len ( packet ) , dest , port , lisp_format_packet ( packet ) ) )
 if 26 - 26: I1ii11iIi11i + i1IIi . i1IIi - oO0o + I1IiiI * o0oOOo0O0Ooo
 if 62 - 62: ooOoO0o + ooOoO0o % I11i
 packet = lisp_control_packet_ipc ( packet , OO , dest , port )
 lisp_ipc ( packet , lisp_socket , "lisp-core-pkt" )
 return
 if 100 - 100: II111iiii . OoooooooOO
 if 32 - 32: I11i % OOooOOo * O0 / iIii1I11I1II1 / i1IIi
 if 87 - 87: OoO0O00 . I1ii11iIi11i * I1IiiI
 if 83 - 83: OOooOOo
 if 86 - 86: I1Ii111 / oO0o
 if 67 - 67: OoOoOO00 + Oo0Ooo / i11iIiiIii . I1IiiI
 if 53 - 53: Oo0Ooo + IiII * ooOoO0o % OoooooooOO * oO0o . iII111i
 if 78 - 78: O0 . Ii1I - I1ii11iIi11i
def lisp_send_map_reply ( lisp_sockets , packet , dest , port ) :
 lprint ( "Send Map-Reply to {}" . format ( dest . print_address_no_iid ( ) ) )
 lisp_send_ipc_to_core ( lisp_sockets [ 2 ] , packet , dest , port )
 return
 if 69 - 69: O0 % O0 . oO0o * OoooooooOO
 if 13 - 13: i1IIi % oO0o . OoooooooOO + I1ii11iIi11i - OOooOOo
 if 99 - 99: OoooooooOO % OOooOOo / I11i
 if 77 - 77: II111iiii - IiII % OOooOOo
 if 22 - 22: OoooooooOO / oO0o
 if 78 - 78: oO0o * I11i . i1IIi % i1IIi + i1IIi / OOooOOo
 if 66 - 66: OoooooooOO % o0oOOo0O0Ooo / I11i * I1Ii111
 if 12 - 12: I1Ii111
def lisp_send_map_referral ( lisp_sockets , packet , dest , port ) :
 lprint ( "Send Map-Referral to {}" . format ( dest . print_address ( ) ) )
 lisp_send_ipc_to_core ( lisp_sockets [ 2 ] , packet , dest , port )
 return
 if 17 - 17: I1Ii111 % oO0o + O0
 if 15 - 15: o0oOOo0O0Ooo - OoooooooOO % ooOoO0o % oO0o / i11iIiiIii / Oo0Ooo
 if 59 - 59: iII111i + O0 - I1ii11iIi11i * I1ii11iIi11i + iIii1I11I1II1
 if 41 - 41: iIii1I11I1II1 . O0 - ooOoO0o / OoOoOO00 % iIii1I11I1II1 + IiII
 if 23 - 23: OoOoOO00 + ooOoO0o . i11iIiiIii
 if 39 - 39: OoOoOO00 - I1ii11iIi11i / I1Ii111
 if 48 - 48: IiII - oO0o + I11i % o0oOOo0O0Ooo
 if 81 - 81: Oo0Ooo . I1Ii111 * iIii1I11I1II1
def lisp_send_map_notify ( lisp_sockets , packet , dest , port ) :
 lprint ( "Send Map-Notify to xTR {}" . format ( dest . print_address ( ) ) )
 lisp_send_ipc_to_core ( lisp_sockets [ 2 ] , packet , dest , port )
 return
 if 60 - 60: OoooooooOO
 if 41 - 41: iIii1I11I1II1 + O0 % o0oOOo0O0Ooo - IiII . I11i * O0
 if 39 - 39: i11iIiiIii . Ii1I
 if 68 - 68: OOooOOo * ooOoO0o . I1IiiI - iII111i
 if 81 - 81: I11i % Oo0Ooo / iII111i
 if 44 - 44: Oo0Ooo
 if 90 - 90: Oo0Ooo . ooOoO0o / IiII * I1Ii111 . ooOoO0o + II111iiii
def lisp_send_ecm ( lisp_sockets , packet , inner_source , inner_sport , inner_dest ,
 outer_dest , to_etr = False , to_ms = False , ddt = False ) :
 if 43 - 43: iIii1I11I1II1 % OOooOOo + OoOoOO00 + I1ii11iIi11i - Oo0Ooo / Ii1I
 if ( inner_source == None or inner_source . is_null ( ) ) :
  inner_source = inner_dest
  if 94 - 94: Ii1I / Oo0Ooo % II111iiii % Oo0Ooo * oO0o
  if 54 - 54: O0 / ooOoO0o * I1Ii111
  if 5 - 5: Ii1I / OoOoOO00 - O0 * OoO0O00
  if 13 - 13: IiII + Oo0Ooo - I1Ii111
  if 10 - 10: OOooOOo % OoooooooOO / I1IiiI . II111iiii % iII111i
  if 47 - 47: o0oOOo0O0Ooo . i11iIiiIii * i1IIi % I11i - ooOoO0o * oO0o
 if ( lisp_nat_traversal ) :
  I11iI1 = lisp_get_any_translated_port ( )
  if ( I11iI1 != None ) : inner_sport = I11iI1
  if 95 - 95: oO0o / Ii1I + OoO0O00
 Oo00OoooO0o = lisp_ecm ( inner_sport )
 if 57 - 57: iIii1I11I1II1 + I1Ii111 % oO0o - Ii1I . I1IiiI
 Oo00OoooO0o . to_etr = to_etr if lisp_is_running ( "lisp-etr" ) else False
 Oo00OoooO0o . to_ms = to_ms if lisp_is_running ( "lisp-ms" ) else False
 Oo00OoooO0o . ddt = ddt
 iIi11Ii = Oo00OoooO0o . encode ( packet , inner_source , inner_dest )
 if ( iIi11Ii == None ) :
  lprint ( "Could not encode ECM message" )
  return
  if 70 - 70: oO0o - iII111i + Ii1I * Ii1I / o0oOOo0O0Ooo . o0oOOo0O0Ooo
 Oo00OoooO0o . print_ecm ( )
 if 41 - 41: I1Ii111 % Oo0Ooo - iIii1I11I1II1
 packet = iIi11Ii + packet
 if 96 - 96: I1Ii111 / II111iiii . oO0o + oO0o
 I1IIII1i1 = outer_dest . print_address_no_iid ( )
 lprint ( "Send Encapsulated-Control-Message to {}" . format ( I1IIII1i1 ) )
 iI1i1iI1iI = lisp_convert_4to6 ( I1IIII1i1 )
 lisp_send ( lisp_sockets , iI1i1iI1iI , LISP_CTRL_PORT , packet )
 return
 if 62 - 62: I1IiiI
 if 22 - 22: i11iIiiIii . Ii1I . Oo0Ooo * Oo0Ooo - iII111i / I1ii11iIi11i
 if 49 - 49: iII111i + I11i . Oo0Ooo
 if 23 - 23: I1IiiI . Ii1I + ooOoO0o . OoooooooOO
 if 57 - 57: OOooOOo / OoOoOO00 / i11iIiiIii - I11i - I11i . Ii1I
 if 53 - 53: ooOoO0o . iII111i + Ii1I * I1Ii111
 if 49 - 49: II111iiii . I1ii11iIi11i * OoOoOO00 - OOooOOo
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
if 48 - 48: OoO0O00 . iIii1I11I1II1 - OoooooooOO + I1Ii111 / i11iIiiIii . Oo0Ooo
LISP_RLOC_UNKNOWN_STATE = 0
LISP_RLOC_UP_STATE = 1
LISP_RLOC_DOWN_STATE = 2
LISP_RLOC_UNREACH_STATE = 3
LISP_RLOC_NO_ECHOED_NONCE_STATE = 4
LISP_RLOC_ADMIN_DOWN_STATE = 5
if 61 - 61: II111iiii + OOooOOo . o0oOOo0O0Ooo . iIii1I11I1II1
LISP_AUTH_NONE = 0
LISP_AUTH_MD5 = 1
LISP_AUTH_SHA1 = 2
LISP_AUTH_SHA2 = 3
if 63 - 63: I11i + i11iIiiIii . o0oOOo0O0Ooo . i1IIi + OoOoOO00
if 1 - 1: i11iIiiIii
if 1 - 1: iIii1I11I1II1
if 73 - 73: iII111i + IiII
if 95 - 95: O0
if 75 - 75: ooOoO0o
if 8 - 8: O0 - OoooooooOO + I1ii11iIi11i / Oo0Ooo . oO0o + I1Ii111
LISP_IPV4_HOST_MASK_LEN = 32
LISP_IPV6_HOST_MASK_LEN = 128
LISP_MAC_HOST_MASK_LEN = 48
LISP_E164_HOST_MASK_LEN = 60
if 85 - 85: ooOoO0o
if 29 - 29: iII111i . Ii1I
if 43 - 43: I11i - I1ii11iIi11i + iIii1I11I1II1 / I1ii11iIi11i * oO0o / iIii1I11I1II1
if 45 - 45: IiII
if 49 - 49: I1IiiI . Ii1I * I1IiiI - OoooooooOO . I11i / I1Ii111
if 9 - 9: iIii1I11I1II1 * Ii1I / O0 - OOooOOo
def byte_swap_64 ( address ) :
 ooooO0O = ( ( address & 0x00000000000000ff ) << 56 ) | ( ( address & 0x000000000000ff00 ) << 40 ) | ( ( address & 0x0000000000ff0000 ) << 24 ) | ( ( address & 0x00000000ff000000 ) << 8 ) | ( ( address & 0x000000ff00000000 ) >> 8 ) | ( ( address & 0x0000ff0000000000 ) >> 24 ) | ( ( address & 0x00ff000000000000 ) >> 40 ) | ( ( address & 0xff00000000000000 ) >> 56 )
 if 95 - 95: i11iIiiIii * II111iiii * OOooOOo * iIii1I11I1II1
 if 22 - 22: iIii1I11I1II1 / I1IiiI + OoOoOO00 - OOooOOo . i11iIiiIii / i11iIiiIii
 if 10 - 10: iIii1I11I1II1 % i1IIi
 if 78 - 78: I11i + II111iiii % o0oOOo0O0Ooo
 if 17 - 17: i11iIiiIii + oO0o * iII111i . II111iiii
 if 44 - 44: I1ii11iIi11i
 if 39 - 39: iII111i + Oo0Ooo / oO0o
 if 95 - 95: I1Ii111 * oO0o / ooOoO0o . Ii1I . OoOoOO00
 return ( ooooO0O )
 if 99 - 99: I1IiiI * II111iiii
 if 84 - 84: II111iiii - I1IiiI
 if 41 - 41: iIii1I11I1II1 % I1Ii111 % OoOoOO00
 if 35 - 35: I11i + i1IIi
 if 85 - 85: Ii1I * Ii1I . OoOoOO00 / Oo0Ooo
 if 97 - 97: oO0o % iIii1I11I1II1
 if 87 - 87: II111iiii % I1IiiI + oO0o - I11i / I11i
 if 16 - 16: I1IiiI
 if 39 - 39: ooOoO0o * II111iiii
 if 90 - 90: OoooooooOO * ooOoO0o
 if 14 - 14: I1IiiI % i1IIi
 if 35 - 35: ooOoO0o % o0oOOo0O0Ooo % ooOoO0o
 if 77 - 77: OOooOOo % I1Ii111 / i11iIiiIii . i1IIi % OOooOOo
 if 55 - 55: i1IIi
 if 64 - 64: oO0o . OOooOOo * i11iIiiIii + I1Ii111
class lisp_cache_entries ( ) :
 def __init__ ( self ) :
  self . entries = { }
  self . entries_sorted = [ ]
  if 88 - 88: O0
  if 75 - 75: iII111i - Oo0Ooo / OoooooooOO - O0
  if 36 - 36: OoO0O00 % Ii1I . Oo0Ooo
class lisp_cache ( ) :
 def __init__ ( self ) :
  self . cache = { }
  self . cache_sorted = [ ]
  self . cache_count = 0
  if 90 - 90: i11iIiiIii - iII111i * oO0o
  if 79 - 79: IiII
 def cache_size ( self ) :
  return ( self . cache_count )
  if 38 - 38: I1Ii111
  if 56 - 56: i11iIiiIii
 def build_key ( self , prefix ) :
  if ( prefix . afi == LISP_AFI_ULTIMATE_ROOT ) :
   o0ooOo00 = 0
  elif ( prefix . afi == LISP_AFI_IID_RANGE ) :
   o0ooOo00 = prefix . mask_len
  else :
   o0ooOo00 = prefix . mask_len + 48
   if 58 - 58: i11iIiiIii / OoOoOO00
   if 23 - 23: I1IiiI % iIii1I11I1II1 - oO0o - iII111i - o0oOOo0O0Ooo
  OO0OO000 = lisp_hex_string ( prefix . instance_id ) . zfill ( 8 )
  I1I1i = lisp_hex_string ( prefix . afi ) . zfill ( 4 )
  if 39 - 39: Oo0Ooo . OoO0O00
  if ( prefix . afi > 0 ) :
   if ( prefix . is_binary ( ) ) :
    O0o0oOOO = prefix . addr_length ( ) * 2
    ooooO0O = lisp_hex_string ( prefix . address ) . zfill ( O0o0oOOO )
   else :
    ooooO0O = prefix . address
    if 74 - 74: I1IiiI . O0 . IiII + IiII - IiII
  elif ( prefix . afi == LISP_AFI_GEO_COORD ) :
   I1I1i = "8003"
   ooooO0O = prefix . address . print_geo ( )
  else :
   I1I1i = ""
   ooooO0O = ""
   if 100 - 100: ooOoO0o / OoooooooOO
   if 73 - 73: i11iIiiIii - Oo0Ooo
  i1iI11iI = OO0OO000 + I1I1i + ooooO0O
  return ( [ o0ooOo00 , i1iI11iI ] )
  if 100 - 100: iIii1I11I1II1 + I1Ii111
  if 51 - 51: o0oOOo0O0Ooo * I11i
 def add_cache ( self , prefix , entry ) :
  if ( prefix . is_binary ( ) ) : prefix . zero_host_bits ( )
  o0ooOo00 , i1iI11iI = self . build_key ( prefix )
  if ( self . cache . has_key ( o0ooOo00 ) == False ) :
   self . cache [ o0ooOo00 ] = lisp_cache_entries ( )
   self . cache [ o0ooOo00 ] . entries = { }
   self . cache [ o0ooOo00 ] . entries_sorted = [ ]
   self . cache_sorted = sorted ( self . cache )
   if 42 - 42: OOooOOo % I11i
  if ( self . cache [ o0ooOo00 ] . entries . has_key ( i1iI11iI ) == False ) :
   self . cache_count += 1
   if 84 - 84: Oo0Ooo * OoOoOO00 / Ii1I / IiII / o0oOOo0O0Ooo . I1ii11iIi11i
  self . cache [ o0ooOo00 ] . entries [ i1iI11iI ] = entry
  self . cache [ o0ooOo00 ] . entries_sorted = sorted ( self . cache [ o0ooOo00 ] . entries )
  if 81 - 81: I1IiiI
  if 82 - 82: I1Ii111 - OoooooooOO - Ii1I
 def lookup_cache ( self , prefix , exact ) :
  IIii , i1iI11iI = self . build_key ( prefix )
  if ( exact ) :
   if ( self . cache . has_key ( IIii ) == False ) : return ( None )
   if ( self . cache [ IIii ] . entries . has_key ( i1iI11iI ) == False ) : return ( None )
   return ( self . cache [ IIii ] . entries [ i1iI11iI ] )
   if 60 - 60: iII111i . o0oOOo0O0Ooo + iII111i
   if 38 - 38: i11iIiiIii * I11i + Oo0Ooo - iIii1I11I1II1
  iiIiI1 = None
  for o0ooOo00 in self . cache_sorted :
   if ( IIii < o0ooOo00 ) : return ( iiIiI1 )
   for OoO000o0OoOO in self . cache [ o0ooOo00 ] . entries_sorted :
    i1I1I11ii = self . cache [ o0ooOo00 ] . entries
    if ( OoO000o0OoOO in i1I1I11ii ) :
     iiIiiIi = i1I1I11ii [ OoO000o0OoOO ]
     if ( iiIiiIi == None ) : continue
     if ( prefix . is_more_specific ( iiIiiIi . eid ) ) : iiIiI1 = iiIiiIi
     if 36 - 36: iII111i - iII111i
     if 13 - 13: iIii1I11I1II1 % iIii1I11I1II1 + i1IIi / OoO0O00 - iII111i * oO0o
     if 13 - 13: OoO0O00
  return ( iiIiI1 )
  if 31 - 31: o0oOOo0O0Ooo + O0
  if 94 - 94: IiII * i1IIi
 def delete_cache ( self , prefix ) :
  o0ooOo00 , i1iI11iI = self . build_key ( prefix )
  if ( self . cache . has_key ( o0ooOo00 ) == False ) : return
  if ( self . cache [ o0ooOo00 ] . entries . has_key ( i1iI11iI ) == False ) : return
  self . cache [ o0ooOo00 ] . entries . pop ( i1iI11iI )
  self . cache [ o0ooOo00 ] . entries_sorted . remove ( i1iI11iI )
  self . cache_count -= 1
  if 90 - 90: O0 % I1IiiI . o0oOOo0O0Ooo % ooOoO0o % I1IiiI
  if 16 - 16: OoO0O00 / OOooOOo / iIii1I11I1II1 / OoooooooOO . oO0o - I1Ii111
 def walk_cache ( self , function , parms ) :
  for o0ooOo00 in self . cache_sorted :
   for i1iI11iI in self . cache [ o0ooOo00 ] . entries_sorted :
    iiIiiIi = self . cache [ o0ooOo00 ] . entries [ i1iI11iI ]
    IIiIIiiIIi , parms = function ( iiIiiIi , parms )
    if ( IIiIIiiIIi == False ) : return ( parms )
    if 70 - 70: I1Ii111 * Oo0Ooo . oO0o
    if 11 - 11: I11i . IiII / I1IiiI + II111iiii * iII111i + i1IIi
  return ( parms )
  if 10 - 10: Oo0Ooo . o0oOOo0O0Ooo - i11iIiiIii / iII111i + i11iIiiIii . I11i
  if 66 - 66: i1IIi
 def print_cache ( self ) :
  lprint ( "Printing contents of {}: " . format ( self ) )
  if ( self . cache_size ( ) == 0 ) :
   lprint ( "  Cache is empty" )
   return
   if 98 - 98: Oo0Ooo / iIii1I11I1II1
  for o0ooOo00 in self . cache_sorted :
   for i1iI11iI in self . cache [ o0ooOo00 ] . entries_sorted :
    iiIiiIi = self . cache [ o0ooOo00 ] . entries [ i1iI11iI ]
    lprint ( "  Mask-length: {}, key: {}, entry: {}" . format ( o0ooOo00 , i1iI11iI ,
 iiIiiIi ) )
    if 33 - 33: O0 - iII111i
    if 40 - 40: iII111i * I11i
    if 25 - 25: O0 * o0oOOo0O0Ooo % ooOoO0o % I1IiiI
    if 87 - 87: OoOoOO00
    if 30 - 30: IiII % OoOoOO00 + I1Ii111
    if 13 - 13: iII111i * Ii1I % o0oOOo0O0Ooo * i1IIi . IiII % i1IIi
    if 79 - 79: OoooooooOO % I11i / o0oOOo0O0Ooo + IiII + O0 + iII111i
    if 87 - 87: I11i
lisp_referral_cache = lisp_cache ( )
lisp_ddt_cache = lisp_cache ( )
lisp_sites_by_eid = lisp_cache ( )
lisp_map_cache = lisp_cache ( )
lisp_db_for_lookups = lisp_cache ( )
if 39 - 39: I1ii11iIi11i * i11iIiiIii % I1Ii111
if 72 - 72: OoO0O00 * Oo0Ooo - IiII
if 74 - 74: Ii1I
if 26 - 26: I11i . O0
if 68 - 68: Ii1I
if 26 - 26: o0oOOo0O0Ooo - I1ii11iIi11i / O0 % i11iIiiIii
if 7 - 7: I1Ii111 . Oo0Ooo + IiII / iIii1I11I1II1
def lisp_map_cache_lookup ( source , dest ) :
 if 22 - 22: iIii1I11I1II1 - O0 . iII111i - IiII - ooOoO0o
 OOooO = dest . is_multicast_address ( )
 if 54 - 54: OoO0O00 . iII111i . OoOoOO00 * OoO0O00 + o0oOOo0O0Ooo . ooOoO0o
 if 44 - 44: I11i * iIii1I11I1II1 . I1ii11iIi11i
 if 9 - 9: o0oOOo0O0Ooo
 if 23 - 23: ooOoO0o * OoO0O00 + O0 % I1Ii111
 OoOOO000O0o = lisp_map_cache . lookup_cache ( dest , False )
 if ( OoOOO000O0o == None ) :
  oo0oO = source . print_sg ( dest ) if OOooO else dest . print_address ( )
  oo0oO = green ( oo0oO , False )
  dprint ( "Lookup for EID {} not found in map-cache" . format ( oo0oO ) )
  return ( None )
  if 21 - 21: Ii1I * OoOoOO00
  if 29 - 29: iIii1I11I1II1 / ooOoO0o
  if 75 - 75: OoooooooOO + I1IiiI % OoOoOO00 / O0 - IiII
  if 88 - 88: OoO0O00 % Ii1I
  if 12 - 12: OoooooooOO . O0
 if ( OOooO == False ) :
  iIo0 = green ( OoOOO000O0o . eid . print_prefix ( ) , False )
  dprint ( "Lookup for EID {} found map-cache entry {}" . format ( green ( dest . print_address ( ) , False ) , iIo0 ) )
  if 33 - 33: OoooooooOO / I11i . II111iiii * i1IIi
  return ( OoOOO000O0o )
  if 34 - 34: i11iIiiIii / OoOoOO00
  if 100 - 100: o0oOOo0O0Ooo - I1IiiI / I11i
  if 43 - 43: o0oOOo0O0Ooo % iIii1I11I1II1
  if 85 - 85: oO0o + OoooooooOO - IiII % o0oOOo0O0Ooo * ooOoO0o * II111iiii
  if 4 - 4: Ii1I . i1IIi + Oo0Ooo % I11i . OoO0O00
 OoOOO000O0o = OoOOO000O0o . lookup_source_cache ( source , False )
 if ( OoOOO000O0o == None ) :
  oo0oO = source . print_sg ( dest )
  dprint ( "Lookup for EID {} not found in map-cache" . format ( oo0oO ) )
  return ( None )
  if 70 - 70: OOooOOo * OoOoOO00 / OoOoOO00 / OoOoOO00
  if 23 - 23: I1IiiI
  if 24 - 24: I1Ii111 * i1IIi % O0 * Ii1I + iII111i
  if 14 - 14: oO0o * iII111i + Ii1I + Ii1I * IiII
  if 82 - 82: IiII * ooOoO0o / OOooOOo + OoOoOO00
 iIo0 = green ( OoOOO000O0o . print_eid_tuple ( ) , False )
 dprint ( "Lookup for EID {} found map-cache entry {}" . format ( green ( source . print_sg ( dest ) , False ) , iIo0 ) )
 if 32 - 32: IiII
 return ( OoOOO000O0o )
 if 90 - 90: I1ii11iIi11i / I11i * o0oOOo0O0Ooo % O0 * i11iIiiIii
 if 68 - 68: I11i . Ii1I + I11i / IiII . I11i / iIii1I11I1II1
 if 96 - 96: O0
 if 2 - 2: OoO0O00 / iII111i + o0oOOo0O0Ooo
 if 27 - 27: I11i - OoOoOO00 - ooOoO0o - I1IiiI
 if 51 - 51: I11i + I11i + O0 + O0 * I1Ii111
 if 61 - 61: IiII . O0
def lisp_referral_cache_lookup ( eid , group , exact ) :
 if ( group and group . is_null ( ) ) :
  I11i1i = lisp_referral_cache . lookup_cache ( eid , exact )
  return ( I11i1i )
  if 38 - 38: Ii1I * I1ii11iIi11i - i11iIiiIii + ooOoO0o * I11i
  if 74 - 74: OoOoOO00 . o0oOOo0O0Ooo
  if 40 - 40: ooOoO0o + I1ii11iIi11i * i11iIiiIii / i1IIi
  if 95 - 95: oO0o / IiII * II111iiii * Ii1I . OoO0O00 . OoO0O00
  if 85 - 85: I1IiiI / II111iiii * OoO0O00 + ooOoO0o / OoO0O00 % OOooOOo
 if ( eid == None or eid . is_null ( ) ) : return ( None )
 if 100 - 100: I1Ii111 % OoooooooOO % OoOoOO00 % I1IiiI
 if 32 - 32: OoO0O00 + OOooOOo . OoO0O00 - Oo0Ooo
 if 12 - 12: I1IiiI * OoO0O00 - II111iiii . i1IIi
 if 86 - 86: OOooOOo / OoooooooOO - IiII
 if 56 - 56: I1ii11iIi11i - i1IIi * OoooooooOO * O0 * I1IiiI - I1Ii111
 if 32 - 32: OoooooooOO . OOooOOo . OoO0O00 . IiII / I11i % i1IIi
 I11i1i = lisp_referral_cache . lookup_cache ( group , exact )
 if ( I11i1i == None ) : return ( None )
 if 21 - 21: O0 . OoO0O00 * I1ii11iIi11i % iII111i + OoooooooOO
 iI111ii1Ii1I = I11i1i . lookup_source_cache ( eid , exact )
 if ( iI111ii1Ii1I ) : return ( iI111ii1Ii1I )
 if 50 - 50: O0 % I1IiiI
 if ( exact ) : I11i1i = None
 return ( I11i1i )
 if 9 - 9: i11iIiiIii + OOooOOo * OoO0O00
 if 9 - 9: OOooOOo
 if 67 - 67: Oo0Ooo / I1Ii111 . ooOoO0o % oO0o / Oo0Ooo
 if 49 - 49: ooOoO0o + I1IiiI
 if 70 - 70: o0oOOo0O0Ooo + Ii1I . OoO0O00 * Ii1I + OOooOOo + ooOoO0o
 if 13 - 13: I1ii11iIi11i
 if 97 - 97: oO0o - Oo0Ooo . i11iIiiIii % ooOoO0o * i11iIiiIii - OoooooooOO
def lisp_ddt_cache_lookup ( eid , group , exact ) :
 if ( group . is_null ( ) ) :
  OoOO0OOoOoO = lisp_ddt_cache . lookup_cache ( eid , exact )
  return ( OoOO0OOoOoO )
  if 44 - 44: I11i % OoooooooOO / iII111i - i11iIiiIii * i1IIi * o0oOOo0O0Ooo
  if 51 - 51: Ii1I + IiII / I1ii11iIi11i + O0 % Ii1I
  if 55 - 55: iII111i % o0oOOo0O0Ooo - oO0o % OoooooooOO
  if 18 - 18: OoooooooOO - I1ii11iIi11i
  if 94 - 94: OOooOOo . Oo0Ooo + Ii1I * o0oOOo0O0Ooo
 if ( eid . is_null ( ) ) : return ( None )
 if 79 - 79: OOooOOo + Oo0Ooo
 if 33 - 33: iIii1I11I1II1
 if 75 - 75: I1Ii111 / iIii1I11I1II1 . OoooooooOO
 if 98 - 98: iIii1I11I1II1 / I1IiiI + i1IIi
 if 80 - 80: II111iiii . Oo0Ooo * oO0o % II111iiii / I1ii11iIi11i
 if 66 - 66: iII111i / OoO0O00 / i11iIiiIii
 OoOO0OOoOoO = lisp_ddt_cache . lookup_cache ( group , exact )
 if ( OoOO0OOoOoO == None ) : return ( None )
 if 99 - 99: OOooOOo
 ooII1iIIiIIIi1 = OoOO0OOoOoO . lookup_source_cache ( eid , exact )
 if ( ooII1iIIiIIIi1 ) : return ( ooII1iIIiIIIi1 )
 if 79 - 79: oO0o % o0oOOo0O0Ooo / o0oOOo0O0Ooo % iII111i
 if ( exact ) : OoOO0OOoOoO = None
 return ( OoOO0OOoOoO )
 if 56 - 56: Oo0Ooo % I1ii11iIi11i
 if 53 - 53: OoO0O00 . I11i - ooOoO0o
 if 11 - 11: I11i + i11iIiiIii / oO0o % oO0o * o0oOOo0O0Ooo / OoOoOO00
 if 74 - 74: oO0o . I1Ii111 . II111iiii
 if 92 - 92: I1Ii111 % OoooooooOO * I1Ii111
 if 78 - 78: Oo0Ooo . I11i . oO0o + O0 / O0
 if 41 - 41: iII111i * OoO0O00 - OoO0O00
def lisp_site_eid_lookup ( eid , group , exact ) :
 if 72 - 72: o0oOOo0O0Ooo + oO0o . I1ii11iIi11i + OoO0O00 / I1Ii111
 if ( group . is_null ( ) ) :
  iIi1iIIiiIi = lisp_sites_by_eid . lookup_cache ( eid , exact )
  return ( iIi1iIIiiIi )
  if 58 - 58: Oo0Ooo / II111iiii % OoooooooOO % II111iiii
  if 39 - 39: i1IIi
  if 16 - 16: OoOoOO00 % iIii1I11I1II1 + Ii1I - o0oOOo0O0Ooo . Oo0Ooo + i1IIi
  if 59 - 59: i1IIi
  if 37 - 37: OoO0O00 / I1ii11iIi11i / OoOoOO00
 if ( eid . is_null ( ) ) : return ( None )
 if 15 - 15: I1IiiI % iIii1I11I1II1 . I1Ii111
 if 71 - 71: I11i - Ii1I + i11iIiiIii % I1ii11iIi11i - OoO0O00 - OOooOOo
 if 71 - 71: OOooOOo
 if 27 - 27: OOooOOo * O0 * i11iIiiIii / OoOoOO00 - i1IIi
 if 73 - 73: iII111i / I1IiiI * ooOoO0o
 if 85 - 85: I11i + I11i + oO0o - OoOoOO00
 iIi1iIIiiIi = lisp_sites_by_eid . lookup_cache ( group , exact )
 if ( iIi1iIIiiIi == None ) : return ( None )
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
 IiIiiiiI1 = iIi1iIIiiIi . lookup_source_cache ( eid , exact )
 if ( IiIiiiiI1 ) : return ( IiIiiiiI1 )
 if 53 - 53: Oo0Ooo
 if ( exact ) :
  iIi1iIIiiIi = None
 else :
  O000000oO0O0O = iIi1iIIiiIi . parent_for_more_specifics
  if ( O000000oO0O0O and O000000oO0O0O . accept_more_specifics ) :
   if ( group . is_more_specific ( O000000oO0O0O . group ) ) : iIi1iIIiiIi = O000000oO0O0O
   if 16 - 16: Ii1I
   if 73 - 73: i11iIiiIii + I1IiiI - IiII - IiII + IiII . Ii1I
 return ( iIi1iIIiiIi )
 if 78 - 78: OoO0O00 + oO0o
 if 86 - 86: ooOoO0o . ooOoO0o + oO0o
 if 84 - 84: OOooOOo - OoOoOO00 + i1IIi * I1ii11iIi11i % I1ii11iIi11i * I1Ii111
 if 31 - 31: IiII + iII111i
 if 5 - 5: O0 * Ii1I
 if 78 - 78: iII111i * iIii1I11I1II1 . OoO0O00 . OoOoOO00 % I1Ii111
 if 77 - 77: OOooOOo / OoooooooOO
 if 11 - 11: iIii1I11I1II1 - Ii1I - OoOoOO00 . oO0o / I1ii11iIi11i
 if 79 - 79: i11iIiiIii % o0oOOo0O0Ooo * II111iiii . i1IIi * Ii1I - i11iIiiIii
 if 31 - 31: IiII / o0oOOo0O0Ooo
 if 27 - 27: Oo0Ooo
 if 32 - 32: Oo0Ooo * i11iIiiIii % I1IiiI - i11iIiiIii - I1Ii111 % I1ii11iIi11i
 if 35 - 35: o0oOOo0O0Ooo % iII111i / O0 * I1IiiI . o0oOOo0O0Ooo / OOooOOo
 if 81 - 81: I1ii11iIi11i - i11iIiiIii
 if 49 - 49: iII111i * I11i - II111iiii . o0oOOo0O0Ooo
 if 52 - 52: Ii1I + Ii1I - II111iiii . O0 + I1ii11iIi11i
 if 60 - 60: i11iIiiIii + IiII
 if 41 - 41: I1Ii111 * o0oOOo0O0Ooo + Oo0Ooo
 if 86 - 86: Ii1I / oO0o
 if 40 - 40: OoO0O00 % oO0o + Oo0Ooo
 if 60 - 60: II111iiii / Ii1I
 if 14 - 14: iII111i - Oo0Ooo / o0oOOo0O0Ooo * oO0o / Oo0Ooo - I1IiiI
 if 89 - 89: i1IIi / I1Ii111 + Ii1I - i1IIi
 if 66 - 66: OoooooooOO
 if 68 - 68: iII111i + I1Ii111
 if 90 - 90: o0oOOo0O0Ooo
class lisp_address ( ) :
 def __init__ ( self , afi , addr_str , mask_len , iid ) :
  self . afi = afi
  self . mask_len = mask_len
  self . instance_id = iid
  self . iid_list = [ ]
  self . address = 0
  if ( addr_str != "" ) : self . store_address ( addr_str )
  if 48 - 48: iII111i + Ii1I
  if 45 - 45: oO0o / iIii1I11I1II1 % O0 % IiII % I1ii11iIi11i
 def copy_address ( self , addr ) :
  if ( addr == None ) : return
  self . afi = addr . afi
  self . address = addr . address
  self . mask_len = addr . mask_len
  self . instance_id = addr . instance_id
  self . iid_list = addr . iid_list
  if 89 - 89: OOooOOo - I1Ii111 - iII111i
  if 67 - 67: oO0o
 def make_default_route ( self , addr ) :
  self . afi = addr . afi
  self . instance_id = addr . instance_id
  self . mask_len = 0
  self . address = 0
  if 76 - 76: I1IiiI % I1IiiI - IiII / OoOoOO00 / I1ii11iIi11i
  if 42 - 42: I1IiiI + I1ii11iIi11i + Oo0Ooo * i1IIi - II111iiii
 def make_default_multicast_route ( self , addr ) :
  self . afi = addr . afi
  self . instance_id = addr . instance_id
  if ( self . afi == LISP_AFI_IPV4 ) :
   self . address = 0xe0000000
   self . mask_len = 4
   if 15 - 15: o0oOOo0O0Ooo
  if ( self . afi == LISP_AFI_IPV6 ) :
   self . address = 0xff << 120
   self . mask_len = 8
   if 60 - 60: I1ii11iIi11i / I1Ii111
  if ( self . afi == LISP_AFI_MAC ) :
   self . address = 0xffffffffffff
   self . mask_len = 48
   if 13 - 13: I1Ii111
   if 52 - 52: II111iiii / OoO0O00 . Ii1I
   if 68 - 68: iII111i
 def not_set ( self ) :
  return ( self . afi == LISP_AFI_NONE )
  if 67 - 67: I1IiiI * I1IiiI
  if 100 - 100: iII111i * iII111i . Oo0Ooo
 def is_private_address ( self ) :
  if ( self . is_ipv4 ( ) == False ) : return ( False )
  ooooO0O = self . address
  if ( ( ( ooooO0O & 0xff000000 ) >> 24 ) == 10 ) : return ( True )
  if ( ( ( ooooO0O & 0xff000000 ) >> 24 ) == 172 ) :
   iI11IIiI1i = ( ooooO0O & 0x00ff0000 ) >> 16
   if ( iI11IIiI1i >= 16 and iI11IIiI1i <= 31 ) : return ( True )
   if 73 - 73: II111iiii
  if ( ( ( ooooO0O & 0xffff0000 ) >> 16 ) == 0xc0a8 ) : return ( True )
  return ( False )
  if 63 - 63: i11iIiiIii . Oo0Ooo . OOooOOo - II111iiii
  if 35 - 35: II111iiii + IiII
 def is_multicast_address ( self ) :
  if ( self . is_ipv4 ( ) ) : return ( self . is_ipv4_multicast ( ) )
  if ( self . is_ipv6 ( ) ) : return ( self . is_ipv6_multicast ( ) )
  if ( self . is_mac ( ) ) : return ( self . is_mac_multicast ( ) )
  return ( False )
  if 66 - 66: o0oOOo0O0Ooo % IiII
  if 39 - 39: IiII
 def host_mask_len ( self ) :
  if ( self . afi == LISP_AFI_IPV4 ) : return ( LISP_IPV4_HOST_MASK_LEN )
  if ( self . afi == LISP_AFI_IPV6 ) : return ( LISP_IPV6_HOST_MASK_LEN )
  if ( self . afi == LISP_AFI_MAC ) : return ( LISP_MAC_HOST_MASK_LEN )
  if ( self . afi == LISP_AFI_E164 ) : return ( LISP_E164_HOST_MASK_LEN )
  if ( self . afi == LISP_AFI_NAME ) : return ( len ( self . address ) * 8 )
  if ( self . afi == LISP_AFI_GEO_COORD ) :
   return ( len ( self . address . print_geo ( ) ) * 8 )
   if 18 - 18: iII111i % o0oOOo0O0Ooo - i1IIi
  return ( 0 )
  if 53 - 53: o0oOOo0O0Ooo + IiII - ooOoO0o % i11iIiiIii - i11iIiiIii - I1Ii111
  if 79 - 79: II111iiii + i11iIiiIii . OOooOOo . I11i / iIii1I11I1II1
 def is_iana_eid ( self ) :
  if ( self . is_ipv6 ( ) == False ) : return ( False )
  ooooO0O = self . address >> 96
  return ( ooooO0O == 0x20010005 )
  if 62 - 62: O0
  if 52 - 52: OoooooooOO . oO0o
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
   if 38 - 38: ooOoO0o . i1IIi / iII111i + I1IiiI - II111iiii
  return ( 0 )
  if 21 - 21: i11iIiiIii + II111iiii - i1IIi / OoooooooOO * OOooOOo % Oo0Ooo
  if 59 - 59: Ii1I
 def afi_to_version ( self ) :
  if ( self . afi == LISP_AFI_IPV4 ) : return ( 4 )
  if ( self . afi == LISP_AFI_IPV6 ) : return ( 6 )
  return ( 0 )
  if 77 - 77: I1ii11iIi11i * Ii1I * O0 * I1IiiI % OoO0O00 - iIii1I11I1II1
  if 6 - 6: i11iIiiIii . I11i - OoooooooOO
 def packet_format ( self ) :
  if 26 - 26: I1IiiI
  if 26 - 26: IiII . Ii1I / IiII - OoO0O00 % OoO0O00
  if 72 - 72: OoooooooOO * II111iiii + OoO0O00 % iIii1I11I1II1 . I1ii11iIi11i % OoooooooOO
  if 19 - 19: OoOoOO00 + I1Ii111
  if 19 - 19: I1ii11iIi11i / I1Ii111 + OoooooooOO - O0
  if ( self . afi == LISP_AFI_IPV4 ) : return ( "I" )
  if ( self . afi == LISP_AFI_IPV6 ) : return ( "QQ" )
  if ( self . afi == LISP_AFI_MAC ) : return ( "HHH" )
  if ( self . afi == LISP_AFI_E164 ) : return ( "II" )
  if ( self . afi == LISP_AFI_LCAF ) : return ( "I" )
  return ( "" )
  if 49 - 49: I1ii11iIi11i / OoOoOO00 - I1IiiI + iII111i . OOooOOo % oO0o
  if 34 - 34: OoO0O00 - I1IiiI + OoOoOO00
 def pack_address ( self ) :
  OoOo0Oooo0o = self . packet_format ( )
  Oo0O0oo = ""
  if ( self . is_ipv4 ( ) ) :
   Oo0O0oo = struct . pack ( OoOo0Oooo0o , socket . htonl ( self . address ) )
  elif ( self . is_ipv6 ( ) ) :
   oOOo0ooO0 = byte_swap_64 ( self . address >> 64 )
   ii1i1II11II1i = byte_swap_64 ( self . address & 0xffffffffffffffff )
   Oo0O0oo = struct . pack ( OoOo0Oooo0o , oOOo0ooO0 , ii1i1II11II1i )
  elif ( self . is_mac ( ) ) :
   ooooO0O = self . address
   oOOo0ooO0 = ( ooooO0O >> 32 ) & 0xffff
   ii1i1II11II1i = ( ooooO0O >> 16 ) & 0xffff
   Iii1IIi11ii1i = ooooO0O & 0xffff
   Oo0O0oo = struct . pack ( OoOo0Oooo0o , oOOo0ooO0 , ii1i1II11II1i , Iii1IIi11ii1i )
  elif ( self . is_e164 ( ) ) :
   ooooO0O = self . address
   oOOo0ooO0 = ( ooooO0O >> 32 ) & 0xffffffff
   ii1i1II11II1i = ( ooooO0O & 0xffffffff )
   Oo0O0oo = struct . pack ( OoOo0Oooo0o , oOOo0ooO0 , ii1i1II11II1i )
  elif ( self . is_dist_name ( ) ) :
   Oo0O0oo += self . address + "\0"
   if 80 - 80: I1IiiI % Ii1I
  return ( Oo0O0oo )
  if 29 - 29: i1IIi % o0oOOo0O0Ooo + OOooOOo / Oo0Ooo
  if 38 - 38: IiII . I1Ii111
 def unpack_address ( self , packet ) :
  OoOo0Oooo0o = self . packet_format ( )
  o0OOo0OOoOO0 = struct . calcsize ( OoOo0Oooo0o )
  if ( len ( packet ) < o0OOo0OOoOO0 ) : return ( None )
  if 69 - 69: ooOoO0o + OoOoOO00 + II111iiii % I1Ii111 + Ii1I . ooOoO0o
  ooooO0O = struct . unpack ( OoOo0Oooo0o , packet [ : o0OOo0OOoOO0 ] )
  if 73 - 73: I11i % I11i . ooOoO0o + OoOoOO00
  if ( self . is_ipv4 ( ) ) :
   self . address = socket . ntohl ( ooooO0O [ 0 ] )
   if 33 - 33: i11iIiiIii . i11iIiiIii * i11iIiiIii / iIii1I11I1II1 / I1ii11iIi11i . ooOoO0o
  elif ( self . is_ipv6 ( ) ) :
   if 11 - 11: iII111i
   if 60 - 60: I1ii11iIi11i / I1Ii111
   if 10 - 10: OoO0O00 * iIii1I11I1II1 / I11i % II111iiii . OoOoOO00 / I1IiiI
   if 4 - 4: Oo0Ooo * o0oOOo0O0Ooo
   if 45 - 45: Ii1I % OOooOOo * Ii1I - iIii1I11I1II1
   if 18 - 18: I1Ii111 / Oo0Ooo % Ii1I + OoO0O00
   if 69 - 69: iII111i % I1ii11iIi11i
   if 19 - 19: IiII
   if ( ooooO0O [ 0 ] <= 0xffff and ( ooooO0O [ 0 ] & 0xff ) == 0 ) :
    ii1iiII = ( ooooO0O [ 0 ] << 48 ) << 64
   else :
    ii1iiII = byte_swap_64 ( ooooO0O [ 0 ] ) << 64
    if 99 - 99: oO0o + Oo0Ooo . IiII * I1IiiI
   IiIIIIi1 = byte_swap_64 ( ooooO0O [ 1 ] )
   self . address = ii1iiII | IiIIIIi1
   if 2 - 2: I1Ii111 + I1ii11iIi11i * i1IIi - iIii1I11I1II1 - I1ii11iIi11i
  elif ( self . is_mac ( ) ) :
   Oo00OOo0o = ooooO0O [ 0 ]
   ooOIIi1Iii1 = ooooO0O [ 1 ]
   IIIII1I11ii = ooooO0O [ 2 ]
   self . address = ( Oo00OOo0o << 32 ) + ( ooOIIi1Iii1 << 16 ) + IIIII1I11ii
   if 39 - 39: OOooOOo . IiII + I1IiiI % iII111i - oO0o / OoO0O00
  elif ( self . is_e164 ( ) ) :
   self . address = ( ooooO0O [ 0 ] << 32 ) + ooooO0O [ 1 ]
   if 37 - 37: O0 % OoO0O00 + i11iIiiIii . O0 / OOooOOo
  elif ( self . is_dist_name ( ) ) :
   packet , self . address = lisp_decode_dist_name ( packet )
   self . mask_len = len ( self . address ) * 8
   o0OOo0OOoOO0 = 0
   if 15 - 15: I1ii11iIi11i + oO0o
  packet = packet [ o0OOo0OOoOO0 : : ]
  return ( packet )
  if 99 - 99: oO0o - ooOoO0o - II111iiii * OoooooooOO / O0
  if 57 - 57: iIii1I11I1II1 / IiII + OoO0O00 * oO0o + Ii1I
 def is_ipv4 ( self ) :
  return ( True if ( self . afi == LISP_AFI_IPV4 ) else False )
  if 76 - 76: i11iIiiIii . OOooOOo / I11i * oO0o % iIii1I11I1II1 . ooOoO0o
  if 75 - 75: O0 + I1IiiI
 def is_ipv4_link_local ( self ) :
  if ( self . is_ipv4 ( ) == False ) : return ( False )
  return ( ( ( self . address >> 16 ) & 0xffff ) == 0xa9fe )
  if 67 - 67: OoOoOO00 % OoooooooOO / OoO0O00 - OoO0O00 / O0
  if 19 - 19: iIii1I11I1II1 / OOooOOo % I11i % I1IiiI / I1ii11iIi11i
 def is_ipv4_loopback ( self ) :
  if ( self . is_ipv4 ( ) == False ) : return ( False )
  return ( self . address == 0x7f000001 )
  if 73 - 73: II111iiii
  if 26 - 26: II111iiii . iIii1I11I1II1 - I1Ii111 % OOooOOo
 def is_ipv4_multicast ( self ) :
  if ( self . is_ipv4 ( ) == False ) : return ( False )
  return ( ( ( self . address >> 24 ) & 0xf0 ) == 0xe0 )
  if 83 - 83: OOooOOo + OoooooooOO % I1Ii111 % IiII + i11iIiiIii
  if 10 - 10: OoooooooOO . Ii1I % I1Ii111 + IiII
 def is_ipv4_string ( self , addr_str ) :
  return ( addr_str . find ( "." ) != - 1 )
  if 78 - 78: OoOoOO00 - oO0o . I1ii11iIi11i * i11iIiiIii
  if 44 - 44: iIii1I11I1II1 * iII111i
 def is_ipv6 ( self ) :
  return ( True if ( self . afi == LISP_AFI_IPV6 ) else False )
  if 32 - 32: OoOoOO00
  if 65 - 65: iIii1I11I1II1 + iII111i
 def is_ipv6_link_local ( self ) :
  if ( self . is_ipv6 ( ) == False ) : return ( False )
  return ( ( ( self . address >> 112 ) & 0xffff ) == 0xfe80 )
  if 90 - 90: i11iIiiIii - Oo0Ooo
  if 31 - 31: OoOoOO00 + OoOoOO00 + OoooooooOO % O0
 def is_ipv6_string_link_local ( self , addr_str ) :
  return ( addr_str . find ( "fe80::" ) != - 1 )
  if 14 - 14: i1IIi / OoooooooOO . I1IiiI * I1Ii111 + OoO0O00
  if 45 - 45: OoooooooOO * I1Ii111
 def is_ipv6_loopback ( self ) :
  if ( self . is_ipv6 ( ) == False ) : return ( False )
  return ( self . address == 1 )
  if 7 - 7: O0
  if 42 - 42: o0oOOo0O0Ooo / Ii1I
 def is_ipv6_multicast ( self ) :
  if ( self . is_ipv6 ( ) == False ) : return ( False )
  return ( ( ( self . address >> 120 ) & 0xff ) == 0xff )
  if 31 - 31: OOooOOo
  if 20 - 20: i11iIiiIii * oO0o * ooOoO0o
 def is_ipv6_string ( self , addr_str ) :
  return ( addr_str . find ( ":" ) != - 1 )
  if 65 - 65: I1ii11iIi11i / Oo0Ooo / I1IiiI + IiII
  if 71 - 71: OoO0O00 . I1Ii111 + OoooooooOO
 def is_mac ( self ) :
  return ( True if ( self . afi == LISP_AFI_MAC ) else False )
  if 9 - 9: OoooooooOO / iIii1I11I1II1 % I1IiiI . I1IiiI / I11i - iII111i
  if 60 - 60: I11i - OoO0O00 - OoOoOO00 * ooOoO0o - i1IIi
 def is_mac_multicast ( self ) :
  if ( self . is_mac ( ) == False ) : return ( False )
  return ( ( self . address & 0x010000000000 ) != 0 )
  if 18 - 18: ooOoO0o + i11iIiiIii + O0 + OOooOOo / Ii1I
  if 65 - 65: I1IiiI . ooOoO0o
 def is_mac_broadcast ( self ) :
  if ( self . is_mac ( ) == False ) : return ( False )
  return ( self . address == 0xffffffffffff )
  if 51 - 51: I1Ii111
  if 89 - 89: Oo0Ooo
 def is_mac_string ( self , addr_str ) :
  return ( len ( addr_str ) == 15 and addr_str . find ( "-" ) != - 1 )
  if 15 - 15: OOooOOo * II111iiii - OOooOOo * iIii1I11I1II1
  if 95 - 95: I1Ii111 / OoooooooOO * I11i * OoooooooOO
 def is_link_local_multicast ( self ) :
  if ( self . is_ipv4 ( ) ) :
   return ( ( 0xe0ffff00 & self . address ) == 0xe0000000 )
   if 88 - 88: I1IiiI / Oo0Ooo / oO0o + oO0o % OOooOOo + Oo0Ooo
  if ( self . is_ipv6 ( ) ) :
   return ( ( self . address >> 112 ) & 0xffff == 0xff02 )
   if 63 - 63: o0oOOo0O0Ooo + i11iIiiIii % OOooOOo % iIii1I11I1II1 / I1ii11iIi11i - iII111i
  return ( False )
  if 72 - 72: iII111i % oO0o . IiII + I1ii11iIi11i . IiII . II111iiii
  if 10 - 10: I11i . ooOoO0o + I11i * Ii1I
 def is_null ( self ) :
  return ( True if ( self . afi == LISP_AFI_NONE ) else False )
  if 55 - 55: OOooOOo / iII111i + OoooooooOO - OoooooooOO
  if 51 - 51: O0 % Ii1I % Oo0Ooo - O0
 def is_ultimate_root ( self ) :
  return ( True if self . afi == LISP_AFI_ULTIMATE_ROOT else False )
  if 94 - 94: OoooooooOO - ooOoO0o % I1ii11iIi11i + I1Ii111
  if 51 - 51: I1ii11iIi11i . iII111i / i1IIi * ooOoO0o % I11i
 def is_iid_range ( self ) :
  return ( True if self . afi == LISP_AFI_IID_RANGE else False )
  if 82 - 82: O0 % OoOoOO00 . iII111i . i1IIi . iII111i - Oo0Ooo
  if 58 - 58: O0 * OOooOOo
 def is_e164 ( self ) :
  return ( True if ( self . afi == LISP_AFI_E164 ) else False )
  if 60 - 60: ooOoO0o
  if 47 - 47: i11iIiiIii
 def is_dist_name ( self ) :
  return ( True if ( self . afi == LISP_AFI_NAME ) else False )
  if 21 - 21: i1IIi - oO0o - Oo0Ooo
  if 11 - 11: i1IIi
 def is_geo_prefix ( self ) :
  return ( True if ( self . afi == LISP_AFI_GEO_COORD ) else False )
  if 77 - 77: I11i + i1IIi * OoOoOO00 % OoooooooOO
  if 56 - 56: I1Ii111 * i1IIi % i11iIiiIii
 def is_binary ( self ) :
  if ( self . is_dist_name ( ) ) : return ( False )
  if ( self . is_geo_prefix ( ) ) : return ( False )
  return ( True )
  if 56 - 56: Ii1I . iII111i
  if 76 - 76: I1IiiI / Ii1I % OoOoOO00 + IiII / i11iIiiIii . o0oOOo0O0Ooo
 def store_address ( self , addr_str ) :
  if ( self . afi == LISP_AFI_NONE ) : self . string_to_afi ( addr_str )
  if 31 - 31: oO0o * oO0o % o0oOOo0O0Ooo . O0 + iII111i
  if 52 - 52: i11iIiiIii
  if 1 - 1: i1IIi * iIii1I11I1II1
  if 29 - 29: I11i
  o0OoO00 = addr_str . find ( "[" )
  iI1I1I111 = addr_str . find ( "]" )
  if ( o0OoO00 != - 1 and iI1I1I111 != - 1 ) :
   self . instance_id = int ( addr_str [ o0OoO00 + 1 : iI1I1I111 ] )
   addr_str = addr_str [ iI1I1I111 + 1 : : ]
   if ( self . is_dist_name ( ) == False ) :
    addr_str = addr_str . replace ( " " , "" )
    if 12 - 12: oO0o % i1IIi - oO0o / ooOoO0o * II111iiii % ooOoO0o
    if 6 - 6: IiII / OoO0O00
    if 83 - 83: IiII - iIii1I11I1II1 * ooOoO0o - oO0o
    if 77 - 77: Ii1I
    if 9 - 9: OOooOOo / OoooooooOO + iII111i
    if 52 - 52: IiII / OOooOOo * iIii1I11I1II1 + o0oOOo0O0Ooo
  if ( self . is_ipv4 ( ) ) :
   ii1iiI1i1Ii1 = addr_str . split ( "." )
   iiIIi = int ( ii1iiI1i1Ii1 [ 0 ] ) << 24
   iiIIi += int ( ii1iiI1i1Ii1 [ 1 ] ) << 16
   iiIIi += int ( ii1iiI1i1Ii1 [ 2 ] ) << 8
   iiIIi += int ( ii1iiI1i1Ii1 [ 3 ] )
   self . address = iiIIi
  elif ( self . is_ipv6 ( ) ) :
   if 13 - 13: i1IIi % iII111i + OoOoOO00 / Ii1I . Ii1I + II111iiii
   if 44 - 44: OoOoOO00 / OoooooooOO % O0 * Ii1I * IiII
   if 84 - 84: o0oOOo0O0Ooo * IiII * OOooOOo * iII111i
   if 56 - 56: iII111i * II111iiii . OoooooooOO . I11i
   if 25 - 25: ooOoO0o % o0oOOo0O0Ooo - i11iIiiIii
   if 79 - 79: iII111i - I1IiiI % O0 / Oo0Ooo + OoOoOO00 . Oo0Ooo
   if 59 - 59: I1ii11iIi11i * OoOoOO00 / Ii1I
   if 80 - 80: IiII - ooOoO0o / OoOoOO00 / I11i * O0 + oO0o
   if 77 - 77: ooOoO0o + I1ii11iIi11i * o0oOOo0O0Ooo / i1IIi * I11i
   if 70 - 70: oO0o / iII111i * i1IIi / II111iiii / OoOoOO00 + oO0o
   if 30 - 30: i1IIi - iII111i - i11iIiiIii . OoOoOO00 . o0oOOo0O0Ooo
   if 74 - 74: i11iIiiIii / II111iiii
   if 62 - 62: O0
   if 63 - 63: Oo0Ooo + Oo0Ooo
   if 48 - 48: Oo0Ooo * I1ii11iIi11i % II111iiii
   if 42 - 42: I1Ii111 - ooOoO0o % o0oOOo0O0Ooo * I1IiiI . o0oOOo0O0Ooo
   if 84 - 84: iIii1I11I1II1
   i1i = ( addr_str [ 2 : 4 ] == "::" )
   try :
    addr_str = socket . inet_pton ( socket . AF_INET6 , addr_str )
   except :
    addr_str = socket . inet_pton ( socket . AF_INET6 , "0::0" )
    if 26 - 26: IiII + I1IiiI
   addr_str = binascii . hexlify ( addr_str )
   if 76 - 76: Ii1I % OoO0O00
   if ( i1i ) :
    addr_str = addr_str [ 2 : 4 ] + addr_str [ 0 : 2 ] + addr_str [ 4 : : ]
    if 20 - 20: I11i . OoO0O00 - ooOoO0o * I1Ii111 - OoOoOO00 * I11i
   self . address = int ( addr_str , 16 )
   if 87 - 87: oO0o
  elif ( self . is_geo_prefix ( ) ) :
   OOOOo = lisp_geo ( None )
   OOOOo . name = "geo-prefix-{}" . format ( OOOOo )
   OOOOo . parse_geo_string ( addr_str )
   self . address = OOOOo
  elif ( self . is_mac ( ) ) :
   addr_str = addr_str . replace ( "-" , "" )
   iiIIi = int ( addr_str , 16 )
   self . address = iiIIi
  elif ( self . is_e164 ( ) ) :
   addr_str = addr_str [ 1 : : ]
   iiIIi = int ( addr_str , 16 )
   self . address = iiIIi << 4
  elif ( self . is_dist_name ( ) ) :
   self . address = addr_str . replace ( "'" , "" )
   if 7 - 7: iII111i
  self . mask_len = self . host_mask_len ( )
  if 43 - 43: i1IIi * O0 + Oo0Ooo - i1IIi - I1IiiI
  if 95 - 95: OOooOOo * I1IiiI % IiII . OoOoOO00 + iII111i
 def store_prefix ( self , prefix_str ) :
  if ( self . is_geo_string ( prefix_str ) ) :
   ii = prefix_str . find ( "]" )
   ooI1111 = len ( prefix_str [ ii + 1 : : ] ) * 8
  elif ( prefix_str . find ( "/" ) != - 1 ) :
   prefix_str , ooI1111 = prefix_str . split ( "/" )
  else :
   i1iiiIii11 = prefix_str . find ( "'" )
   if ( i1iiiIii11 == - 1 ) : return
   iiiiI11ii = prefix_str . find ( "'" , i1iiiIii11 + 1 )
   if ( iiiiI11ii == - 1 ) : return
   ooI1111 = len ( prefix_str [ i1iiiIii11 + 1 : iiiiI11ii ] ) * 8
   if 81 - 81: ooOoO0o / I1Ii111 + OOooOOo / Oo0Ooo / OoOoOO00
   if 34 - 34: ooOoO0o * iIii1I11I1II1 % i11iIiiIii * OOooOOo - OOooOOo
  self . string_to_afi ( prefix_str )
  self . store_address ( prefix_str )
  self . mask_len = int ( ooI1111 )
  if 63 - 63: Oo0Ooo / oO0o + iII111i % OoooooooOO * I11i
  if 34 - 34: I1IiiI + I1Ii111 % ooOoO0o
 def zero_host_bits ( self ) :
  if ( self . mask_len < 0 ) : return
  i1IiiIiI11I = ( 2 ** self . mask_len ) - 1
  Oo0oOOOOo00 = self . addr_length ( ) * 8 - self . mask_len
  i1IiiIiI11I <<= Oo0oOOOOo00
  self . address &= i1IiiIiI11I
  if 1 - 1: I1ii11iIi11i / i1IIi - II111iiii - OoOoOO00 . iII111i
  if 43 - 43: I1Ii111 * OOooOOo - IiII . i11iIiiIii
 def is_geo_string ( self , addr_str ) :
  ii = addr_str . find ( "]" )
  if ( ii != - 1 ) : addr_str = addr_str [ ii + 1 : : ]
  if 34 - 34: iII111i . OoOoOO00
  OOOOo = addr_str . split ( "/" )
  if ( len ( OOOOo ) == 2 ) :
   if ( OOOOo [ 1 ] . isdigit ( ) == False ) : return ( False )
   if 49 - 49: I1ii11iIi11i % oO0o - I1Ii111 . I1ii11iIi11i % II111iiii
  OOOOo = OOOOo [ 0 ]
  OOOOo = OOOOo . split ( "-" )
  IIo0Oo0ooO0o0 = len ( OOOOo )
  if ( IIo0Oo0ooO0o0 < 8 or IIo0Oo0ooO0o0 > 9 ) : return ( False )
  if 39 - 39: IiII * I11i + I1IiiI
  for O0000OOoOO in range ( 0 , IIo0Oo0ooO0o0 ) :
   if ( O0000OOoOO == 3 ) :
    if ( OOOOo [ O0000OOoOO ] in [ "N" , "S" ] ) : continue
    return ( False )
    if 93 - 93: oO0o . iIii1I11I1II1 . OoooooooOO / OoO0O00
   if ( O0000OOoOO == 7 ) :
    if ( OOOOo [ O0000OOoOO ] in [ "W" , "E" ] ) : continue
    return ( False )
    if 83 - 83: i11iIiiIii
   if ( OOOOo [ O0000OOoOO ] . isdigit ( ) == False ) : return ( False )
   if 54 - 54: I1IiiI + OoooooooOO / iII111i / I11i . I11i % I11i
  return ( True )
  if 54 - 54: OoO0O00 * I11i * iIii1I11I1II1 * IiII
  if 12 - 12: O0 - iII111i * IiII . i11iIiiIii
 def string_to_afi ( self , addr_str ) :
  if ( addr_str . count ( "'" ) == 2 ) :
   self . afi = LISP_AFI_NAME
   return
   if 25 - 25: Ii1I % i1IIi * I11i * Ii1I - IiII . i11iIiiIii
  if ( addr_str . find ( ":" ) != - 1 ) : self . afi = LISP_AFI_IPV6
  elif ( addr_str . find ( "." ) != - 1 ) : self . afi = LISP_AFI_IPV4
  elif ( addr_str . find ( "+" ) != - 1 ) : self . afi = LISP_AFI_E164
  elif ( self . is_geo_string ( addr_str ) ) : self . afi = LISP_AFI_GEO_COORD
  elif ( addr_str . find ( "-" ) != - 1 ) : self . afi = LISP_AFI_MAC
  else : self . afi = LISP_AFI_NONE
  if 40 - 40: OOooOOo - OoooooooOO
  if 36 - 36: i1IIi % OoOoOO00 - i1IIi
 def print_address ( self ) :
  ooooO0O = self . print_address_no_iid ( )
  OO0OO000 = "[" + str ( self . instance_id )
  for o0OoO00 in self . iid_list : OO0OO000 += "," + str ( o0OoO00 )
  OO0OO000 += "]"
  ooooO0O = "{}{}" . format ( OO0OO000 , ooooO0O )
  return ( ooooO0O )
  if 5 - 5: I1IiiI . I1IiiI % II111iiii - I1Ii111
  if 97 - 97: I11i . ooOoO0o
 def print_address_no_iid ( self ) :
  if ( self . is_ipv4 ( ) ) :
   ooooO0O = self . address
   OOOoO = ooooO0O >> 24
   oO0Oo0OO0O0 = ( ooooO0O >> 16 ) & 0xff
   OoOooOo0o0O0o = ( ooooO0O >> 8 ) & 0xff
   o0oO000Oo0 = ooooO0O & 0xff
   return ( "{}.{}.{}.{}" . format ( OOOoO , oO0Oo0OO0O0 , OoOooOo0o0O0o , o0oO000Oo0 ) )
  elif ( self . is_ipv6 ( ) ) :
   I1IIII1i1 = lisp_hex_string ( self . address ) . zfill ( 32 )
   I1IIII1i1 = binascii . unhexlify ( I1IIII1i1 )
   I1IIII1i1 = socket . inet_ntop ( socket . AF_INET6 , I1IIII1i1 )
   return ( "{}" . format ( I1IIII1i1 ) )
  elif ( self . is_geo_prefix ( ) ) :
   return ( "{}" . format ( self . address . print_geo ( ) ) )
  elif ( self . is_mac ( ) ) :
   I1IIII1i1 = lisp_hex_string ( self . address ) . zfill ( 12 )
   I1IIII1i1 = "{}-{}-{}" . format ( I1IIII1i1 [ 0 : 4 ] , I1IIII1i1 [ 4 : 8 ] ,
 I1IIII1i1 [ 8 : 12 ] )
   return ( "{}" . format ( I1IIII1i1 ) )
  elif ( self . is_e164 ( ) ) :
   I1IIII1i1 = lisp_hex_string ( self . address ) . zfill ( 15 )
   return ( "+{}" . format ( I1IIII1i1 ) )
  elif ( self . is_dist_name ( ) ) :
   return ( "'{}'" . format ( self . address ) )
  elif ( self . is_null ( ) ) :
   return ( "no-address" )
   if 77 - 77: OoO0O00 . iII111i
  return ( "unknown-afi:{}" . format ( self . afi ) )
  if 77 - 77: I1Ii111 . IiII % OoO0O00 + I1Ii111 % OoooooooOO
  if 17 - 17: OoooooooOO - i1IIi * I11i
 def print_prefix ( self ) :
  if ( self . is_ultimate_root ( ) ) : return ( "[*]" )
  if ( self . is_iid_range ( ) ) :
   if ( self . mask_len == 32 ) : return ( "[{}]" . format ( self . instance_id ) )
   iiI = self . instance_id + ( 2 ** ( 32 - self . mask_len ) - 1 )
   return ( "[{}-{}]" . format ( self . instance_id , iiI ) )
   if 40 - 40: OOooOOo * OOooOOo / IiII / ooOoO0o / OoooooooOO
  ooooO0O = self . print_address ( )
  if ( self . is_dist_name ( ) ) : return ( ooooO0O )
  if ( self . is_geo_prefix ( ) ) : return ( ooooO0O )
  if 78 - 78: I1Ii111 + I1Ii111
  ii = ooooO0O . find ( "no-address" )
  if ( ii == - 1 ) :
   ooooO0O = "{}/{}" . format ( ooooO0O , str ( self . mask_len ) )
  else :
   ooooO0O = ooooO0O [ 0 : ii ]
   if 43 - 43: I1Ii111 * o0oOOo0O0Ooo + i1IIi
  return ( ooooO0O )
  if 19 - 19: Ii1I
  if 51 - 51: oO0o
 def print_prefix_no_iid ( self ) :
  ooooO0O = self . print_address_no_iid ( )
  if ( self . is_dist_name ( ) ) : return ( ooooO0O )
  if ( self . is_geo_prefix ( ) ) : return ( ooooO0O )
  return ( "{}/{}" . format ( ooooO0O , str ( self . mask_len ) ) )
  if 57 - 57: i11iIiiIii - Oo0Ooo + I1Ii111 * OoO0O00
  if 35 - 35: o0oOOo0O0Ooo % II111iiii + O0
 def print_prefix_url ( self ) :
  if ( self . is_ultimate_root ( ) ) : return ( "0--0" )
  ooooO0O = self . print_address ( )
  ii = ooooO0O . find ( "]" )
  if ( ii != - 1 ) : ooooO0O = ooooO0O [ ii + 1 : : ]
  if ( self . is_geo_prefix ( ) ) :
   ooooO0O = ooooO0O . replace ( "/" , "-" )
   return ( "{}-{}" . format ( self . instance_id , ooooO0O ) )
   if 70 - 70: I1ii11iIi11i . II111iiii
  return ( "{}-{}-{}" . format ( self . instance_id , ooooO0O , self . mask_len ) )
  if 54 - 54: OOooOOo
  if 67 - 67: I1IiiI . o0oOOo0O0Ooo / i1IIi * I1ii11iIi11i . Oo0Ooo + II111iiii
 def print_sg ( self , g ) :
  IiiiI1 = self . print_prefix ( )
  oOOo00OO = IiiiI1 . find ( "]" ) + 1
  g = g . print_prefix ( )
  IiO0oOOOoOO00O0 = g . find ( "]" ) + 1
  OOoO0oo0O = "[{}]({}, {})" . format ( self . instance_id , IiiiI1 [ oOOo00OO : : ] , g [ IiO0oOOOoOO00O0 : : ] )
  return ( OOoO0oo0O )
  if 29 - 29: I1IiiI * OOooOOo % OoOoOO00 * OoO0O00 * O0 . i1IIi
  if 78 - 78: OoO0O00 - I1IiiI
 def hash_address ( self , addr ) :
  oOOo0ooO0 = self . address
  ii1i1II11II1i = addr . address
  if 12 - 12: II111iiii . O0
  if ( self . is_geo_prefix ( ) ) : oOOo0ooO0 = self . address . print_geo ( )
  if ( addr . is_geo_prefix ( ) ) : ii1i1II11II1i = addr . address . print_geo ( )
  if 86 - 86: oO0o . OoOoOO00 - I11i . OOooOOo % OoO0O00
  if ( type ( oOOo0ooO0 ) == str ) :
   oOOo0ooO0 = int ( binascii . hexlify ( oOOo0ooO0 [ 0 : 1 ] ) )
   if 79 - 79: iII111i / Ii1I % i11iIiiIii . I1IiiI % OoO0O00 / i11iIiiIii
  if ( type ( ii1i1II11II1i ) == str ) :
   ii1i1II11II1i = int ( binascii . hexlify ( ii1i1II11II1i [ 0 : 1 ] ) )
   if 100 - 100: OOooOOo + Oo0Ooo . iIii1I11I1II1 . ooOoO0o * Oo0Ooo
  return ( oOOo0ooO0 ^ ii1i1II11II1i )
  if 16 - 16: Oo0Ooo % OoOoOO00 + I1Ii111 % I1Ii111
  if 12 - 12: I1Ii111 . Ii1I / iIii1I11I1II1 + i1IIi
  if 9 - 9: iIii1I11I1II1
  if 75 - 75: I11i . II111iiii * I1IiiI * IiII
  if 36 - 36: OOooOOo / I1ii11iIi11i / oO0o / ooOoO0o / I11i
  if 7 - 7: OoO0O00 - I11i - o0oOOo0O0Ooo / o0oOOo0O0Ooo + i11iIiiIii
 def is_more_specific ( self , prefix ) :
  if ( prefix . afi == LISP_AFI_ULTIMATE_ROOT ) : return ( True )
  if 28 - 28: OoOoOO00 % ooOoO0o . I1IiiI + II111iiii
  ooI1111 = prefix . mask_len
  if ( prefix . afi == LISP_AFI_IID_RANGE ) :
   iII = 2 ** ( 32 - ooI1111 )
   o0OOO = prefix . instance_id
   iiI = o0OOO + iII
   return ( self . instance_id in range ( o0OOO , iiI ) )
   if 62 - 62: O0
   if 40 - 40: OoOoOO00 - O0 / I1Ii111 + OoO0O00 + ooOoO0o
  if ( self . instance_id != prefix . instance_id ) : return ( False )
  if ( self . afi != prefix . afi ) :
   if ( prefix . afi != LISP_AFI_NONE ) : return ( False )
   if 51 - 51: I1ii11iIi11i - II111iiii / Oo0Ooo % ooOoO0o
   if 25 - 25: o0oOOo0O0Ooo
   if 29 - 29: I1Ii111
   if 58 - 58: i1IIi / I1ii11iIi11i
   if 5 - 5: iIii1I11I1II1 % ooOoO0o . OOooOOo . ooOoO0o
  if ( self . is_binary ( ) == False ) :
   if ( prefix . afi == LISP_AFI_NONE ) : return ( True )
   if ( type ( self . address ) != type ( prefix . address ) ) : return ( False )
   ooooO0O = self . address
   OOi11iii11IIii = prefix . address
   if ( self . is_geo_prefix ( ) ) :
    ooooO0O = self . address . print_geo ( )
    OOi11iii11IIii = prefix . address . print_geo ( )
    if 5 - 5: OoO0O00 * OoOoOO00
   if ( len ( ooooO0O ) < len ( OOi11iii11IIii ) ) : return ( False )
   return ( ooooO0O . find ( OOi11iii11IIii ) == 0 )
   if 29 - 29: II111iiii - OoOoOO00 . o0oOOo0O0Ooo / ooOoO0o + Ii1I / iII111i
   if 99 - 99: ooOoO0o
   if 55 - 55: II111iiii + OoO0O00 + i1IIi * I11i
   if 55 - 55: OoO0O00 . Ii1I % oO0o - o0oOOo0O0Ooo
   if 14 - 14: OOooOOo * IiII
  if ( self . mask_len < ooI1111 ) : return ( False )
  if 15 - 15: o0oOOo0O0Ooo + OoooooooOO - OOooOOo - o0oOOo0O0Ooo . iIii1I11I1II1 / Ii1I
  Oo0oOOOOo00 = ( prefix . addr_length ( ) * 8 ) - ooI1111
  i1IiiIiI11I = ( 2 ** ooI1111 - 1 ) << Oo0oOOOOo00
  return ( ( self . address & i1IiiIiI11I ) == prefix . address )
  if 33 - 33: OoO0O00
  if 91 - 91: I11i % I11i % iII111i
 def mask_address ( self , mask_len ) :
  Oo0oOOOOo00 = ( self . addr_length ( ) * 8 ) - mask_len
  i1IiiIiI11I = ( 2 ** mask_len - 1 ) << Oo0oOOOOo00
  self . address &= i1IiiIiI11I
  if 19 - 19: I11i / I11i + I1IiiI * OoO0O00 - iII111i . Oo0Ooo
  if 76 - 76: iII111i % OOooOOo / OoooooooOO . I1IiiI % OoO0O00 % i1IIi
 def is_exact_match ( self , prefix ) :
  if ( self . instance_id != prefix . instance_id ) : return ( False )
  OOoooOoO = self . print_prefix ( )
  OO00Ooo = prefix . print_prefix ( ) if prefix else ""
  return ( OOoooOoO == OO00Ooo )
  if 64 - 64: OoooooooOO + OoooooooOO % OoO0O00 - OoooooooOO
  if 86 - 86: OoOoOO00 - OoO0O00 + Ii1I % I1ii11iIi11i - Oo0Ooo + oO0o
 def is_local ( self ) :
  if ( self . is_ipv4 ( ) ) :
   I1OOo00o = lisp_myrlocs [ 0 ]
   if ( I1OOo00o == None ) : return ( False )
   I1OOo00o = I1OOo00o . print_address_no_iid ( )
   return ( self . print_address_no_iid ( ) == I1OOo00o )
   if 42 - 42: i11iIiiIii / O0
  if ( self . is_ipv6 ( ) ) :
   I1OOo00o = lisp_myrlocs [ 1 ]
   if ( I1OOo00o == None ) : return ( False )
   I1OOo00o = I1OOo00o . print_address_no_iid ( )
   return ( self . print_address_no_iid ( ) == I1OOo00o )
   if 8 - 8: I1Ii111
  return ( False )
  if 51 - 51: i11iIiiIii
  if 1 - 1: iIii1I11I1II1 . i1IIi . i11iIiiIii % I1ii11iIi11i
 def store_iid_range ( self , iid , mask_len ) :
  if ( self . afi == LISP_AFI_NONE ) :
   if ( iid is 0 and mask_len is 0 ) : self . afi = LISP_AFI_ULTIMATE_ROOT
   else : self . afi = LISP_AFI_IID_RANGE
   if 58 - 58: i11iIiiIii * i11iIiiIii - OoO0O00
  self . instance_id = iid
  self . mask_len = mask_len
  if 8 - 8: i11iIiiIii * OoOoOO00 . o0oOOo0O0Ooo
  if 27 - 27: I1ii11iIi11i + Ii1I % I1Ii111
 def lcaf_length ( self , lcaf_type ) :
  O0o0oOOO = self . addr_length ( ) + 2
  if ( lcaf_type == LISP_LCAF_AFI_LIST_TYPE ) : O0o0oOOO += 4
  if ( lcaf_type == LISP_LCAF_INSTANCE_ID_TYPE ) : O0o0oOOO += 4
  if ( lcaf_type == LISP_LCAF_ASN_TYPE ) : O0o0oOOO += 4
  if ( lcaf_type == LISP_LCAF_APP_DATA_TYPE ) : O0o0oOOO += 8
  if ( lcaf_type == LISP_LCAF_GEO_COORD_TYPE ) : O0o0oOOO += 12
  if ( lcaf_type == LISP_LCAF_OPAQUE_TYPE ) : O0o0oOOO += 0
  if ( lcaf_type == LISP_LCAF_NAT_TYPE ) : O0o0oOOO += 4
  if ( lcaf_type == LISP_LCAF_NONCE_LOC_TYPE ) : O0o0oOOO += 4
  if ( lcaf_type == LISP_LCAF_MCAST_INFO_TYPE ) : O0o0oOOO = O0o0oOOO * 2 + 8
  if ( lcaf_type == LISP_LCAF_ELP_TYPE ) : O0o0oOOO += 0
  if ( lcaf_type == LISP_LCAF_SECURITY_TYPE ) : O0o0oOOO += 6
  if ( lcaf_type == LISP_LCAF_SOURCE_DEST_TYPE ) : O0o0oOOO += 4
  if ( lcaf_type == LISP_LCAF_RLE_TYPE ) : O0o0oOOO += 4
  return ( O0o0oOOO )
  if 20 - 20: Oo0Ooo
  if 33 - 33: oO0o - OoOoOO00 - i11iIiiIii + I1Ii111 + iIii1I11I1II1
  if 2 - 2: OoooooooOO + IiII / iII111i . iIii1I11I1II1 * OoOoOO00
  if 84 - 84: OOooOOo
  if 68 - 68: I1Ii111
  if 92 - 92: oO0o * Ii1I / OoO0O00 % II111iiii
  if 54 - 54: oO0o + I11i - OoO0O00
  if 86 - 86: OoooooooOO
  if 51 - 51: i11iIiiIii
  if 91 - 91: OOooOOo
  if 22 - 22: OoooooooOO + OoOoOO00 - Ii1I . iII111i / OoooooooOO / I1IiiI
  if 73 - 73: i1IIi - Ii1I + oO0o * iIii1I11I1II1
  if 100 - 100: i11iIiiIii / iIii1I11I1II1 + Oo0Ooo + OoO0O00 - iII111i
  if 8 - 8: i11iIiiIii . O0 + o0oOOo0O0Ooo * oO0o + II111iiii
  if 61 - 61: ooOoO0o / ooOoO0o
  if 51 - 51: iIii1I11I1II1 / oO0o * I1Ii111 + i1IIi
  if 96 - 96: Oo0Ooo + oO0o - Oo0Ooo - OoOoOO00 % OOooOOo . iIii1I11I1II1
 def lcaf_encode_iid ( self ) :
  o0oOoOOO = LISP_LCAF_INSTANCE_ID_TYPE
  Oo = socket . htons ( self . lcaf_length ( o0oOoOOO ) )
  OO0OO000 = self . instance_id
  I1I1i = self . afi
  o0ooOo00 = 0
  if ( I1I1i < 0 ) :
   if ( self . afi == LISP_AFI_GEO_COORD ) :
    I1I1i = LISP_AFI_LCAF
    o0ooOo00 = 0
   else :
    I1I1i = 0
    o0ooOo00 = self . mask_len
    if 93 - 93: iIii1I11I1II1 % OoooooooOO
    if 6 - 6: II111iiii / oO0o - OOooOOo . O0 - o0oOOo0O0Ooo
    if 72 - 72: iIii1I11I1II1 / OoooooooOO * ooOoO0o / ooOoO0o % O0 + IiII
  O0OoiI11Ii = struct . pack ( "BBBBH" , 0 , 0 , o0oOoOOO , o0ooOo00 , Oo )
  O0OoiI11Ii += struct . pack ( "IH" , socket . htonl ( OO0OO000 ) , socket . htons ( I1I1i ) )
  if ( I1I1i == 0 ) : return ( O0OoiI11Ii )
  if 58 - 58: i11iIiiIii
  if ( self . afi == LISP_AFI_GEO_COORD ) :
   O0OoiI11Ii = O0OoiI11Ii [ 0 : - 2 ]
   O0OoiI11Ii += self . address . encode_geo ( )
   return ( O0OoiI11Ii )
   if 16 - 16: OoOoOO00 - iII111i / I1Ii111
   if 60 - 60: OoO0O00 % iIii1I11I1II1 . iII111i + ooOoO0o . Oo0Ooo
  O0OoiI11Ii += self . pack_address ( )
  return ( O0OoiI11Ii )
  if 87 - 87: iII111i
  if 86 - 86: IiII - I11i
 def lcaf_decode_iid ( self , packet ) :
  OoOo0Oooo0o = "BBBBH"
  o0OOo0OOoOO0 = struct . calcsize ( OoOo0Oooo0o )
  if ( len ( packet ) < o0OOo0OOoOO0 ) : return ( None )
  if 99 - 99: i1IIi + I1ii11iIi11i
  IiIIi , iiIiI1iiI1 , o0oOoOOO , I11i1 , O0o0oOOO = struct . unpack ( OoOo0Oooo0o ,
 packet [ : o0OOo0OOoOO0 ] )
  packet = packet [ o0OOo0OOoOO0 : : ]
  if 58 - 58: oO0o . I1ii11iIi11i + OoO0O00 - I1IiiI - OoO0O00 + II111iiii
  if ( o0oOoOOO != LISP_LCAF_INSTANCE_ID_TYPE ) : return ( None )
  if 32 - 32: Oo0Ooo - II111iiii
  OoOo0Oooo0o = "IH"
  o0OOo0OOoOO0 = struct . calcsize ( OoOo0Oooo0o )
  if ( len ( packet ) < o0OOo0OOoOO0 ) : return ( None )
  if 69 - 69: iII111i + I1ii11iIi11i
  OO0OO000 , I1I1i = struct . unpack ( OoOo0Oooo0o , packet [ : o0OOo0OOoOO0 ] )
  packet = packet [ o0OOo0OOoOO0 : : ]
  if 77 - 77: I1IiiI + O0 % iII111i / o0oOOo0O0Ooo
  O0o0oOOO = socket . ntohs ( O0o0oOOO )
  self . instance_id = socket . ntohl ( OO0OO000 )
  I1I1i = socket . ntohs ( I1I1i )
  self . afi = I1I1i
  if ( I11i1 != 0 and I1I1i == 0 ) : self . mask_len = I11i1
  if ( I1I1i == 0 ) :
   self . afi = LISP_AFI_IID_RANGE if I11i1 else LISP_AFI_ULTIMATE_ROOT
   if 67 - 67: Oo0Ooo % ooOoO0o - II111iiii / IiII . i11iIiiIii
   if 52 - 52: I1ii11iIi11i / I1Ii111 - iII111i * OoO0O00 * I1Ii111 * iII111i
   if 82 - 82: II111iiii % iII111i + oO0o
   if 19 - 19: I1Ii111 - OOooOOo . ooOoO0o . O0 + II111iiii . OoooooooOO
   if 97 - 97: O0 / OoOoOO00 / ooOoO0o
  if ( I1I1i == 0 ) : return ( packet )
  if 11 - 11: II111iiii . i11iIiiIii - Ii1I . IiII
  if 10 - 10: OOooOOo * OoooooooOO
  if 12 - 12: II111iiii - O0 . i1IIi % oO0o % OoooooooOO
  if 36 - 36: IiII * OoOoOO00 - iIii1I11I1II1 + II111iiii
  if ( self . is_dist_name ( ) ) :
   packet , self . address = lisp_decode_dist_name ( packet )
   self . mask_len = len ( self . address ) * 8
   return ( packet )
   if 65 - 65: I1IiiI * I11i . I1Ii111 % I1ii11iIi11i + O0
   if 91 - 91: OoooooooOO % I1Ii111 * OoO0O00 - OoOoOO00
   if 5 - 5: iIii1I11I1II1 * I11i - oO0o % oO0o % o0oOOo0O0Ooo . i1IIi
   if 95 - 95: Oo0Ooo * I1ii11iIi11i + iII111i - o0oOOo0O0Ooo - Oo0Ooo . OoO0O00
   if 62 - 62: I11i
  if ( I1I1i == LISP_AFI_LCAF ) :
   OoOo0Oooo0o = "BBBBH"
   o0OOo0OOoOO0 = struct . calcsize ( OoOo0Oooo0o )
   if ( len ( packet ) < o0OOo0OOoOO0 ) : return ( None )
   if 58 - 58: I11i . OoOoOO00 + iII111i . iII111i
   iiII1II1 , iiIIii1Iii1I , o0oOoOOO , OO00 , i1IiI = struct . unpack ( OoOo0Oooo0o , packet [ : o0OOo0OOoOO0 ] )
   if 43 - 43: I1Ii111 + I1Ii111 % Oo0Ooo % OoO0O00 - ooOoO0o
   if 61 - 61: OoOoOO00 + Ii1I % i11iIiiIii - I1IiiI * OoO0O00 % iIii1I11I1II1
   if ( o0oOoOOO != LISP_LCAF_GEO_COORD_TYPE ) : return ( None )
   if 66 - 66: iII111i + i1IIi
   i1IiI = socket . ntohs ( i1IiI )
   packet = packet [ o0OOo0OOoOO0 : : ]
   if ( i1IiI > len ( packet ) ) : return ( None )
   if 24 - 24: O0 / OoooooooOO - OoOoOO00
   OOOOo = lisp_geo ( "" )
   self . afi = LISP_AFI_GEO_COORD
   self . address = OOOOo
   packet = OOOOo . decode_geo ( packet , i1IiI , OO00 )
   self . mask_len = self . host_mask_len ( )
   return ( packet )
   if 51 - 51: OoO0O00 + o0oOOo0O0Ooo - II111iiii * I11i + Ii1I
   if 16 - 16: I1Ii111 * i1IIi . I1IiiI . OOooOOo % Ii1I - o0oOOo0O0Ooo
  Oo = self . addr_length ( )
  if ( len ( packet ) < Oo ) : return ( None )
  if 89 - 89: Ii1I * I1ii11iIi11i * I1IiiI % iII111i % Ii1I + O0
  packet = self . unpack_address ( packet )
  return ( packet )
  if 53 - 53: i11iIiiIii % I1ii11iIi11i
  if 59 - 59: OOooOOo
  if 61 - 61: OoooooooOO + O0 - i1IIi % oO0o / I1ii11iIi11i
  if 50 - 50: oO0o + II111iiii * OoOoOO00 % OoO0O00 . II111iiii % o0oOOo0O0Ooo
  if 32 - 32: i1IIi / Ii1I + i11iIiiIii % oO0o
  if 11 - 11: Ii1I - ooOoO0o % i11iIiiIii / OoooooooOO - O0 - IiII
  if 25 - 25: IiII + O0 + oO0o % iIii1I11I1II1 - II111iiii . I1IiiI
  if 62 - 62: IiII . O0 + oO0o - ooOoO0o * iIii1I11I1II1
  if 8 - 8: I1ii11iIi11i
  if 65 - 65: i11iIiiIii
  if 92 - 92: oO0o * II111iiii + I1Ii111
  if 49 - 49: II111iiii * I1IiiI * O0 / ooOoO0o * IiII
  if 94 - 94: OoO0O00 - I1IiiI * oO0o
  if 35 - 35: OOooOOo / i1IIi + OoO0O00
  if 31 - 31: OoO0O00 . i1IIi / OoooooooOO
  if 81 - 81: ooOoO0o . Oo0Ooo . OoOoOO00 + OOooOOo % iII111i - oO0o
  if 68 - 68: iII111i - O0 / Ii1I
  if 15 - 15: I1Ii111 / I1ii11iIi11i / I1IiiI % i11iIiiIii + II111iiii . ooOoO0o
  if 74 - 74: o0oOOo0O0Ooo
  if 4 - 4: I1ii11iIi11i * II111iiii - Oo0Ooo % i1IIi % O0 * i11iIiiIii
  if 62 - 62: OoO0O00 * I1Ii111 * Ii1I / ooOoO0o
 def lcaf_encode_sg ( self , group ) :
  o0oOoOOO = LISP_LCAF_MCAST_INFO_TYPE
  OO0OO000 = socket . htonl ( self . instance_id )
  Oo = socket . htons ( self . lcaf_length ( o0oOoOOO ) )
  O0OoiI11Ii = struct . pack ( "BBBBHIHBB" , 0 , 0 , o0oOoOOO , 0 , Oo , OO0OO000 ,
 0 , self . mask_len , group . mask_len )
  if 27 - 27: oO0o . iII111i . oO0o
  O0OoiI11Ii += struct . pack ( "H" , socket . htons ( self . afi ) )
  O0OoiI11Ii += self . pack_address ( )
  O0OoiI11Ii += struct . pack ( "H" , socket . htons ( group . afi ) )
  O0OoiI11Ii += group . pack_address ( )
  return ( O0OoiI11Ii )
  if 37 - 37: Oo0Ooo . I1ii11iIi11i / OoooooooOO % ooOoO0o / I1IiiI + ooOoO0o
  if 14 - 14: I11i + ooOoO0o . oO0o * I11i
 def lcaf_decode_sg ( self , packet ) :
  OoOo0Oooo0o = "BBBBHIHBB"
  o0OOo0OOoOO0 = struct . calcsize ( OoOo0Oooo0o )
  if ( len ( packet ) < o0OOo0OOoOO0 ) : return ( [ None , None ] )
  if 98 - 98: Ii1I . i1IIi * OoO0O00 * Ii1I * iIii1I11I1II1
  IiIIi , iiIiI1iiI1 , o0oOoOOO , O000OOOoOooO , O0o0oOOO , OO0OO000 , IiIIIII1I , IIIo0oo , oO = struct . unpack ( OoOo0Oooo0o , packet [ : o0OOo0OOoOO0 ] )
  if 36 - 36: IiII % I11i
  packet = packet [ o0OOo0OOoOO0 : : ]
  if 72 - 72: oO0o % I11i % OOooOOo * iIii1I11I1II1 - OOooOOo % O0
  if ( o0oOoOOO != LISP_LCAF_MCAST_INFO_TYPE ) : return ( [ None , None ] )
  if 84 - 84: oO0o - o0oOOo0O0Ooo / II111iiii . o0oOOo0O0Ooo
  self . instance_id = socket . ntohl ( OO0OO000 )
  O0o0oOOO = socket . ntohs ( O0o0oOOO ) - 8
  if 82 - 82: OoooooooOO
  if 14 - 14: OoO0O00 / oO0o - OOooOOo
  if 100 - 100: IiII - I11i . iIii1I11I1II1 / iIii1I11I1II1
  if 16 - 16: IiII + Oo0Ooo % I11i
  if 16 - 16: ooOoO0o / I1Ii111
  OoOo0Oooo0o = "H"
  o0OOo0OOoOO0 = struct . calcsize ( OoOo0Oooo0o )
  if ( len ( packet ) < o0OOo0OOoOO0 ) : return ( [ None , None ] )
  if ( O0o0oOOO < o0OOo0OOoOO0 ) : return ( [ None , None ] )
  if 78 - 78: OoOoOO00 - II111iiii - OOooOOo + I1IiiI + O0 / I1IiiI
  I1I1i = struct . unpack ( OoOo0Oooo0o , packet [ : o0OOo0OOoOO0 ] ) [ 0 ]
  packet = packet [ o0OOo0OOoOO0 : : ]
  O0o0oOOO -= o0OOo0OOoOO0
  self . afi = socket . ntohs ( I1I1i )
  self . mask_len = IIIo0oo
  Oo = self . addr_length ( )
  if ( O0o0oOOO < Oo ) : return ( [ None , None ] )
  if 59 - 59: OOooOOo . I1IiiI / i1IIi / II111iiii . II111iiii
  packet = self . unpack_address ( packet )
  if ( packet == None ) : return ( [ None , None ] )
  if 54 - 54: iIii1I11I1II1 % ooOoO0o
  O0o0oOOO -= Oo
  if 37 - 37: OOooOOo % OoOoOO00 - II111iiii * o0oOOo0O0Ooo . I1IiiI . OoOoOO00
  if 92 - 92: I11i + OoO0O00 . OoooooooOO
  if 3 - 3: OoO0O00 % iIii1I11I1II1
  if 62 - 62: OoooooooOO * o0oOOo0O0Ooo
  if 59 - 59: iIii1I11I1II1
  OoOo0Oooo0o = "H"
  o0OOo0OOoOO0 = struct . calcsize ( OoOo0Oooo0o )
  if ( len ( packet ) < o0OOo0OOoOO0 ) : return ( [ None , None ] )
  if ( O0o0oOOO < o0OOo0OOoOO0 ) : return ( [ None , None ] )
  if 18 - 18: ooOoO0o % I1IiiI / iIii1I11I1II1 + O0
  I1I1i = struct . unpack ( OoOo0Oooo0o , packet [ : o0OOo0OOoOO0 ] ) [ 0 ]
  packet = packet [ o0OOo0OOoOO0 : : ]
  O0o0oOOO -= o0OOo0OOoOO0
  IiI1111i1i11I = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  IiI1111i1i11I . afi = socket . ntohs ( I1I1i )
  IiI1111i1i11I . mask_len = oO
  IiI1111i1i11I . instance_id = self . instance_id
  Oo = self . addr_length ( )
  if ( O0o0oOOO < Oo ) : return ( [ None , None ] )
  if 99 - 99: i11iIiiIii - o0oOOo0O0Ooo + o0oOOo0O0Ooo . OoooooooOO * iII111i . Oo0Ooo
  packet = IiI1111i1i11I . unpack_address ( packet )
  if ( packet == None ) : return ( [ None , None ] )
  if 63 - 63: I11i
  return ( [ packet , IiI1111i1i11I ] )
  if 60 - 60: I1IiiI / I1ii11iIi11i / I11i / Ii1I + iIii1I11I1II1
  if 85 - 85: O0 / OOooOOo . OoOoOO00 / I1ii11iIi11i
 def lcaf_decode_eid ( self , packet ) :
  OoOo0Oooo0o = "BBB"
  o0OOo0OOoOO0 = struct . calcsize ( OoOo0Oooo0o )
  if ( len ( packet ) < o0OOo0OOoOO0 ) : return ( [ None , None ] )
  if 80 - 80: I1ii11iIi11i * iII111i % i1IIi * OOooOOo % II111iiii % i1IIi
  if 44 - 44: OoooooooOO
  if 18 - 18: i11iIiiIii
  if 65 - 65: i1IIi . iIii1I11I1II1 % iIii1I11I1II1
  if 35 - 35: iIii1I11I1II1 - o0oOOo0O0Ooo + I1ii11iIi11i * iII111i - OOooOOo . o0oOOo0O0Ooo
  O000OOOoOooO , iiIIii1Iii1I , o0oOoOOO = struct . unpack ( OoOo0Oooo0o ,
 packet [ : o0OOo0OOoOO0 ] )
  if 12 - 12: iIii1I11I1II1 % OoO0O00 * Oo0Ooo
  if ( o0oOoOOO == LISP_LCAF_INSTANCE_ID_TYPE ) :
   return ( [ self . lcaf_decode_iid ( packet ) , None ] )
  elif ( o0oOoOOO == LISP_LCAF_MCAST_INFO_TYPE ) :
   packet , IiI1111i1i11I = self . lcaf_decode_sg ( packet )
   return ( [ packet , IiI1111i1i11I ] )
  elif ( o0oOoOOO == LISP_LCAF_GEO_COORD_TYPE ) :
   OoOo0Oooo0o = "BBBBH"
   o0OOo0OOoOO0 = struct . calcsize ( OoOo0Oooo0o )
   if ( len ( packet ) < o0OOo0OOoOO0 ) : return ( None )
   if 5 - 5: I11i - II111iiii * iIii1I11I1II1 / iIii1I11I1II1 % IiII * i1IIi
   iiII1II1 , iiIIii1Iii1I , o0oOoOOO , OO00 , i1IiI = struct . unpack ( OoOo0Oooo0o , packet [ : o0OOo0OOoOO0 ] )
   if 30 - 30: i1IIi % I1IiiI . OOooOOo % iIii1I11I1II1 . I1ii11iIi11i / o0oOOo0O0Ooo
   if 53 - 53: OOooOOo % ooOoO0o
   if ( o0oOoOOO != LISP_LCAF_GEO_COORD_TYPE ) : return ( None )
   if 94 - 94: OOooOOo - O0 - I1Ii111 / OoooooooOO - iII111i
   i1IiI = socket . ntohs ( i1IiI )
   packet = packet [ o0OOo0OOoOO0 : : ]
   if ( i1IiI > len ( packet ) ) : return ( None )
   if 83 - 83: OOooOOo * I1ii11iIi11i * iII111i * I1ii11iIi11i . OoO0O00
   OOOOo = lisp_geo ( "" )
   self . instance_id = 0
   self . afi = LISP_AFI_GEO_COORD
   self . address = OOOOo
   packet = OOOOo . decode_geo ( packet , i1IiI , OO00 )
   self . mask_len = self . host_mask_len ( )
   if 87 - 87: ooOoO0o . O0 - oO0o
  return ( [ packet , None ] )
  if 75 - 75: Oo0Ooo
  if 22 - 22: oO0o * I1Ii111 . II111iiii / Ii1I * O0
  if 33 - 33: oO0o * i1IIi + ooOoO0o * OOooOOo - O0 - iIii1I11I1II1
  if 35 - 35: I1Ii111
  if 12 - 12: Ii1I % I1IiiI - I11i / iIii1I11I1II1 . I1IiiI % I1ii11iIi11i
  if 12 - 12: Oo0Ooo + I1IiiI
class lisp_elp_node ( ) :
 def __init__ ( self ) :
  self . address = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . probe = False
  self . strict = False
  self . eid = False
  self . we_are_last = False
  if 12 - 12: OoOoOO00 / II111iiii
  if 100 - 100: I1ii11iIi11i % iIii1I11I1II1 . IiII . OoooooooOO / II111iiii
 def copy_elp_node ( self ) :
  IiIIooO00oOo0 = lisp_elp_node ( )
  IiIIooO00oOo0 . copy_address ( self . address )
  IiIIooO00oOo0 . probe = self . probe
  IiIIooO00oOo0 . strict = self . strict
  IiIIooO00oOo0 . eid = self . eid
  IiIIooO00oOo0 . we_are_last = self . we_are_last
  return ( IiIIooO00oOo0 )
  if 28 - 28: I1IiiI
  if 27 - 27: I1IiiI % oO0o - iIii1I11I1II1 - o0oOOo0O0Ooo - IiII - O0
  if 46 - 46: II111iiii
class lisp_elp ( ) :
 def __init__ ( self , name ) :
  self . elp_name = name
  self . elp_nodes = [ ]
  self . use_elp_node = None
  self . we_are_last = False
  if 24 - 24: i11iIiiIii * i1IIi - I11i + o0oOOo0O0Ooo
  if 60 - 60: ooOoO0o
 def copy_elp ( self ) :
  IIiI11i1i = lisp_elp ( self . elp_name )
  IIiI11i1i . use_elp_node = self . use_elp_node
  IIiI11i1i . we_are_last = self . we_are_last
  for IiIIooO00oOo0 in self . elp_nodes :
   IIiI11i1i . elp_nodes . append ( IiIIooO00oOo0 . copy_elp_node ( ) )
   if 62 - 62: i11iIiiIii
  return ( IIiI11i1i )
  if 88 - 88: i11iIiiIii
  if 59 - 59: oO0o - OoooooooOO % ooOoO0o
 def print_elp ( self , want_marker ) :
  OooO0o00oO = ""
  for IiIIooO00oOo0 in self . elp_nodes :
   o0o0o00 = ""
   if ( want_marker ) :
    if ( IiIIooO00oOo0 == self . use_elp_node ) :
     o0o0o00 = "*"
    elif ( IiIIooO00oOo0 . we_are_last ) :
     o0o0o00 = "x"
     if 24 - 24: I1IiiI
     if 34 - 34: OOooOOo - i11iIiiIii + Oo0Ooo . I1ii11iIi11i . OoO0O00
   OooO0o00oO += "{}{}({}{}{}), " . format ( o0o0o00 ,
 IiIIooO00oOo0 . address . print_address_no_iid ( ) ,
 "r" if IiIIooO00oOo0 . eid else "R" , "P" if IiIIooO00oOo0 . probe else "p" ,
 "S" if IiIIooO00oOo0 . strict else "s" )
   if 38 - 38: iII111i
  return ( OooO0o00oO [ 0 : - 2 ] if OooO0o00oO != "" else "" )
  if 100 - 100: i11iIiiIii % i1IIi + I1ii11iIi11i + Oo0Ooo
  if 36 - 36: O0 - iII111i + I11i + I1IiiI
 def select_elp_node ( self ) :
  OOO00IiI111111i , iiI1i1i1i , I1i1II1 = lisp_myrlocs
  ii = None
  if 34 - 34: oO0o . oO0o % I11i . OoOoOO00
  for IiIIooO00oOo0 in self . elp_nodes :
   if ( OOO00IiI111111i and IiIIooO00oOo0 . address . is_exact_match ( OOO00IiI111111i ) ) :
    ii = self . elp_nodes . index ( IiIIooO00oOo0 )
    break
    if 10 - 10: i11iIiiIii . IiII * I1IiiI
   if ( iiI1i1i1i and IiIIooO00oOo0 . address . is_exact_match ( iiI1i1i1i ) ) :
    ii = self . elp_nodes . index ( IiIIooO00oOo0 )
    break
    if 27 - 27: Ii1I % II111iiii . OOooOOo
    if 14 - 14: IiII - O0 / II111iiii + I1IiiI + I1ii11iIi11i * ooOoO0o
    if 36 - 36: I1ii11iIi11i . i11iIiiIii * ooOoO0o * OOooOOo
    if 27 - 27: i11iIiiIii - oO0o / I1ii11iIi11i / I11i / Oo0Ooo
    if 83 - 83: I1Ii111 / iII111i - ooOoO0o
    if 75 - 75: Ii1I * OoOoOO00 % I11i + I11i + iII111i
    if 65 - 65: i1IIi * iII111i
  if ( ii == None ) :
   self . use_elp_node = self . elp_nodes [ 0 ]
   IiIIooO00oOo0 . we_are_last = False
   return
   if 77 - 77: i11iIiiIii - I1IiiI * I1ii11iIi11i
   if 11 - 11: Oo0Ooo
   if 6 - 6: OoO0O00 - OOooOOo / oO0o
   if 74 - 74: iIii1I11I1II1
   if 14 - 14: iIii1I11I1II1
   if 78 - 78: I1Ii111 / Oo0Ooo - I1Ii111
  if ( self . elp_nodes [ - 1 ] == self . elp_nodes [ ii ] ) :
   self . use_elp_node = None
   IiIIooO00oOo0 . we_are_last = True
   return
   if 1 - 1: OoO0O00 - I1IiiI * o0oOOo0O0Ooo
   if 84 - 84: OoO0O00 % OoooooooOO
   if 66 - 66: OoOoOO00 . iII111i
   if 1 - 1: iII111i * i1IIi . iIii1I11I1II1 % O0 - OoooooooOO
   if 87 - 87: iII111i . Oo0Ooo * i11iIiiIii % o0oOOo0O0Ooo + Ii1I
  self . use_elp_node = self . elp_nodes [ ii + 1 ]
  return
  if 72 - 72: Ii1I / II111iiii + o0oOOo0O0Ooo
  if 33 - 33: I1Ii111 * OoOoOO00 - OoooooooOO
  if 11 - 11: I1Ii111 - Oo0Ooo / iIii1I11I1II1 - OoooooooOO
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
  if 71 - 71: Oo0Ooo + Ii1I - OoooooooOO + I11i - iIii1I11I1II1 / O0
  if 76 - 76: i11iIiiIii % o0oOOo0O0Ooo . O0 * I11i
 def copy_geo ( self ) :
  OOOOo = lisp_geo ( self . geo_name )
  OOOOo . latitude = self . latitude
  OOOOo . lat_mins = self . lat_mins
  OOOOo . lat_secs = self . lat_secs
  OOOOo . longitude = self . longitude
  OOOOo . long_mins = self . long_mins
  OOOOo . long_secs = self . long_secs
  OOOOo . altitude = self . altitude
  OOOOo . radius = self . radius
  return ( OOOOo )
  if 90 - 90: II111iiii + OOooOOo % I1Ii111 * iIii1I11I1II1 % iIii1I11I1II1
  if 55 - 55: II111iiii % O0 * O0 - II111iiii * I1IiiI % Oo0Ooo
 def no_geo_altitude ( self ) :
  return ( self . altitude == - 1 )
  if 48 - 48: I1ii11iIi11i + OoooooooOO % i1IIi
  if 46 - 46: OoOoOO00
 def parse_geo_string ( self , geo_str ) :
  ii = geo_str . find ( "]" )
  if ( ii != - 1 ) : geo_str = geo_str [ ii + 1 : : ]
  if 75 - 75: I1IiiI
  if 37 - 37: iIii1I11I1II1 % OoO0O00 * ooOoO0o + I11i % ooOoO0o / i11iIiiIii
  if 14 - 14: i1IIi / ooOoO0o
  if 10 - 10: ooOoO0o / OoooooooOO - ooOoO0o % O0 + oO0o - oO0o
  if 16 - 16: O0
  if ( geo_str . find ( "/" ) != - 1 ) :
   geo_str , I1iOoo0Ooo00o = geo_str . split ( "/" )
   self . radius = int ( I1iOoo0Ooo00o )
   if 78 - 78: OOooOOo % O0 * O0
   if 62 - 62: ooOoO0o
  geo_str = geo_str . split ( "-" )
  if ( len ( geo_str ) < 8 ) : return ( False )
  if 77 - 77: I1IiiI . i11iIiiIii - I1ii11iIi11i
  OOOoOOo0 = geo_str [ 0 : 4 ]
  iI111iIiiI = geo_str [ 4 : 8 ]
  if 55 - 55: ooOoO0o + I11i - OoOoOO00 + I1IiiI % Oo0Ooo / I1ii11iIi11i
  if 17 - 17: i1IIi / IiII . I1IiiI % i1IIi
  if 46 - 46: IiII % O0 . o0oOOo0O0Ooo . OOooOOo
  if 47 - 47: OoooooooOO . oO0o . II111iiii / II111iiii - OoOoOO00
  if ( len ( geo_str ) > 8 ) : self . altitude = int ( geo_str [ 8 ] )
  if 81 - 81: o0oOOo0O0Ooo - Oo0Ooo % IiII - ooOoO0o / O0
  if 27 - 27: Oo0Ooo
  if 15 - 15: iIii1I11I1II1 . OoOoOO00 % Ii1I / i1IIi . o0oOOo0O0Ooo
  if 45 - 45: iIii1I11I1II1 - i1IIi % I1IiiI - I1Ii111 + oO0o
  self . latitude = int ( OOOoOOo0 [ 0 ] )
  self . lat_mins = int ( OOOoOOo0 [ 1 ] )
  self . lat_secs = int ( OOOoOOo0 [ 2 ] )
  if ( OOOoOOo0 [ 3 ] == "N" ) : self . latitude = - self . latitude
  if 15 - 15: iIii1I11I1II1 - OoooooooOO / ooOoO0o
  if 83 - 83: IiII + I1Ii111 / OoOoOO00 * IiII . oO0o
  if 22 - 22: O0 + ooOoO0o + I1Ii111
  if 57 - 57: OOooOOo . ooOoO0o - OoooooooOO - I1ii11iIi11i * O0
  self . longitude = int ( iI111iIiiI [ 0 ] )
  self . long_mins = int ( iI111iIiiI [ 1 ] )
  self . long_secs = int ( iI111iIiiI [ 2 ] )
  if ( iI111iIiiI [ 3 ] == "E" ) : self . longitude = - self . longitude
  return ( True )
  if 85 - 85: I1IiiI * OoO0O00
  if 63 - 63: I1IiiI - i11iIiiIii
 def print_geo ( self ) :
  I1ii1I = "N" if self . latitude < 0 else "S"
  OO0O0ooOo0oO0 = "E" if self . longitude < 0 else "W"
  if 99 - 99: iII111i
  O000 = "{}-{}-{}-{}-{}-{}-{}-{}" . format ( abs ( self . latitude ) ,
 self . lat_mins , self . lat_secs , I1ii1I , abs ( self . longitude ) ,
 self . long_mins , self . long_secs , OO0O0ooOo0oO0 )
  if 27 - 27: OOooOOo + II111iiii . i1IIi % II111iiii
  if ( self . no_geo_altitude ( ) == False ) :
   O000 += "-" + str ( self . altitude )
   if 33 - 33: iIii1I11I1II1 . O0 . oO0o
   if 69 - 69: II111iiii * O0 . ooOoO0o * IiII
   if 25 - 25: I11i - I1ii11iIi11i . I1Ii111 . OoooooooOO
   if 4 - 4: IiII * OoO0O00 % I1ii11iIi11i * Ii1I . iII111i
   if 41 - 41: OoooooooOO % I11i . O0 + I1Ii111
  if ( self . radius != 0 ) : O000 += "/{}" . format ( self . radius )
  return ( O000 )
  if 67 - 67: OoOoOO00 * OOooOOo / OOooOOo / OoooooooOO
  if 67 - 67: I11i - i1IIi . OoooooooOO / iIii1I11I1II1
 def geo_url ( self ) :
  iIiIiiIiIiiiI = os . getenv ( "LISP_GEO_ZOOM_LEVEL" )
  iIiIiiIiIiiiI = "10" if ( iIiIiiIiIiiiI == "" or iIiIiiIiIiiiI . isdigit ( ) == False ) else iIiIiiIiIiiiI
  i1i11i1Iii , I111Ii1ii1I1i = self . dms_to_decimal ( )
  Ooo0O0O0O0 = ( "http://maps.googleapis.com/maps/api/staticmap?center={},{}" + "&markers=color:blue%7Clabel:lisp%7C{},{}" + "&zoom={}&size=1024x1024&sensor=false" ) . format ( i1i11i1Iii , I111Ii1ii1I1i , i1i11i1Iii , I111Ii1ii1I1i ,
  # I1ii11iIi11i - OoO0O00 % I1ii11iIi11i + i11iIiiIii . oO0o
  # IiII % I1IiiI / ooOoO0o
 iIiIiiIiIiiiI )
  return ( Ooo0O0O0O0 )
  if 74 - 74: OoooooooOO
  if 22 - 22: II111iiii . O0 * I1Ii111 % OoO0O00 / OoooooooOO + I1Ii111
 def print_geo_url ( self ) :
  OOOOo = self . print_geo ( )
  if ( self . radius == 0 ) :
   Ooo0O0O0O0 = self . geo_url ( )
   oo0O = "<a href='{}'>{}</a>" . format ( Ooo0O0O0O0 , OOOOo )
  else :
   Ooo0O0O0O0 = OOOOo . replace ( "/" , "-" )
   oo0O = "<a href='/lisp/geo-map/{}'>{}</a>" . format ( Ooo0O0O0O0 , OOOOo )
   if 71 - 71: ooOoO0o . oO0o * OoooooooOO + iII111i - I1Ii111 . I1ii11iIi11i
  return ( oo0O )
  if 100 - 100: I11i + O0 - o0oOOo0O0Ooo * I1ii11iIi11i
  if 94 - 94: Oo0Ooo . IiII / Ii1I / oO0o - I1IiiI
 def dms_to_decimal ( self ) :
  ooOO000o0O , o0oOOOOO0 , iiiI1I = self . latitude , self . lat_mins , self . lat_secs
  Iii = float ( abs ( ooOO000o0O ) )
  Iii += float ( o0oOOOOO0 * 60 + iiiI1I ) / 3600
  if ( ooOO000o0O > 0 ) : Iii = - Iii
  O0oO0O0OoO0 = Iii
  if 28 - 28: ooOoO0o + iII111i - i1IIi
  ooOO000o0O , o0oOOOOO0 , iiiI1I = self . longitude , self . long_mins , self . long_secs
  Iii = float ( abs ( ooOO000o0O ) )
  Iii += float ( o0oOOOOO0 * 60 + iiiI1I ) / 3600
  if ( ooOO000o0O > 0 ) : Iii = - Iii
  ii1i = Iii
  return ( ( O0oO0O0OoO0 , ii1i ) )
  if 96 - 96: iII111i + iIii1I11I1II1 * OoOoOO00 . OoOoOO00 + OoOoOO00
  if 17 - 17: I11i / I1IiiI / i11iIiiIii
 def get_distance ( self , geo_point ) :
  o0Oooo0oo = self . dms_to_decimal ( )
  IiiI11I = geo_point . dms_to_decimal ( )
  I1iIiii1Ii1 = vincenty ( o0Oooo0oo , IiiI11I )
  return ( I1iIiii1Ii1 . km )
  if 75 - 75: OoOoOO00 . OoOoOO00 - Oo0Ooo - II111iiii
  if 20 - 20: II111iiii . OOooOOo % OoooooooOO . iIii1I11I1II1 - I1IiiI
 def point_in_circle ( self , geo_point ) :
  oOo0O0 = self . get_distance ( geo_point )
  return ( oOo0O0 <= self . radius )
  if 58 - 58: Ii1I
  if 78 - 78: o0oOOo0O0Ooo % i11iIiiIii + I1Ii111 * iII111i / I1IiiI
 def encode_geo ( self ) :
  oO0OOOo0OO = socket . htons ( LISP_AFI_LCAF )
  IIo0Oo0ooO0o0 = socket . htons ( 20 + 2 )
  iiIIii1Iii1I = 0
  if 74 - 74: I1Ii111 - i11iIiiIii * OoooooooOO
  i1i11i1Iii = abs ( self . latitude )
  oO0O = ( ( self . lat_mins * 60 ) + self . lat_secs ) * 1000
  if ( self . latitude < 0 ) : iiIIii1Iii1I |= 0x40
  if 86 - 86: I1ii11iIi11i * I1Ii111 / o0oOOo0O0Ooo . OoO0O00
  I111Ii1ii1I1i = abs ( self . longitude )
  i1i1i111IiiiI = ( ( self . long_mins * 60 ) + self . long_secs ) * 1000
  if ( self . longitude < 0 ) : iiIIii1Iii1I |= 0x20
  if 90 - 90: IiII / Ii1I . o0oOOo0O0Ooo . Ii1I
  I1iooO0OOO = 0
  if ( self . no_geo_altitude ( ) == False ) :
   I1iooO0OOO = socket . htonl ( self . altitude )
   iiIIii1Iii1I |= 0x10
   if 64 - 64: iIii1I11I1II1 - ooOoO0o
  I1iOoo0Ooo00o = socket . htons ( self . radius )
  if ( I1iOoo0Ooo00o != 0 ) : iiIIii1Iii1I |= 0x06
  if 13 - 13: oO0o . ooOoO0o / iII111i % Ii1I
  Oooi1 = struct . pack ( "HBBBBH" , oO0OOOo0OO , 0 , 0 , LISP_LCAF_GEO_COORD_TYPE ,
 0 , IIo0Oo0ooO0o0 )
  Oooi1 += struct . pack ( "BBHBBHBBHIHHH" , iiIIii1Iii1I , 0 , 0 , i1i11i1Iii , oO0O >> 16 ,
 socket . htons ( oO0O & 0x0ffff ) , I111Ii1ii1I1i , i1i1i111IiiiI >> 16 ,
 socket . htons ( i1i1i111IiiiI & 0xffff ) , I1iooO0OOO , I1iOoo0Ooo00o , 0 , 0 )
  if 40 - 40: i1IIi
  return ( Oooi1 )
  if 53 - 53: Ii1I . I1ii11iIi11i - OOooOOo - ooOoO0o
  if 17 - 17: OoooooooOO / I1IiiI * ooOoO0o % I1ii11iIi11i . OoO0O00
 def decode_geo ( self , packet , lcaf_len , radius_hi ) :
  OoOo0Oooo0o = "BBHBBHBBHIHHH"
  o0OOo0OOoOO0 = struct . calcsize ( OoOo0Oooo0o )
  if ( lcaf_len < o0OOo0OOoOO0 ) : return ( None )
  if 5 - 5: OoO0O00 % I1Ii111 . oO0o . Ii1I + I1IiiI
  iiIIii1Iii1I , OoOoO00 , OO000ooO0OoOO , i1i11i1Iii , O0Ooo000 , oO0O , I111Ii1ii1I1i , oOoO00O00OO0000 , i1i1i111IiiiI , I1iooO0OOO , I1iOoo0Ooo00o , Iiii , I1I1i = struct . unpack ( OoOo0Oooo0o ,
  # i11iIiiIii - I11i / I1ii11iIi11i * Ii1I * O0
 packet [ : o0OOo0OOoOO0 ] )
  if 44 - 44: OoOoOO00 % ooOoO0o % I1Ii111 / iIii1I11I1II1 * I11i
  if 91 - 91: OoooooooOO - IiII - Ii1I
  if 36 - 36: OOooOOo
  if 76 - 76: OoO0O00 . i1IIi
  I1I1i = socket . ntohs ( I1I1i )
  if ( I1I1i == LISP_AFI_LCAF ) : return ( None )
  if 98 - 98: O0
  if ( iiIIii1Iii1I & 0x40 ) : i1i11i1Iii = - i1i11i1Iii
  self . latitude = i1i11i1Iii
  OoOOoOOooo0Oo = ( ( O0Ooo000 << 16 ) | socket . ntohs ( oO0O ) ) / 1000
  self . lat_mins = OoOOoOOooo0Oo / 60
  self . lat_secs = OoOOoOOooo0Oo % 60
  if 30 - 30: Ii1I % i11iIiiIii - I1Ii111 % OoOoOO00 % OoOoOO00
  if ( iiIIii1Iii1I & 0x20 ) : I111Ii1ii1I1i = - I111Ii1ii1I1i
  self . longitude = I111Ii1ii1I1i
  Oo000Oo0 = ( ( oOoO00O00OO0000 << 16 ) | socket . ntohs ( i1i1i111IiiiI ) ) / 1000
  self . long_mins = Oo000Oo0 / 60
  self . long_secs = Oo000Oo0 % 60
  if 74 - 74: i1IIi . IiII / ooOoO0o + I11i % i11iIiiIii % iII111i
  self . altitude = socket . ntohl ( I1iooO0OOO ) if ( iiIIii1Iii1I & 0x10 ) else - 1
  I1iOoo0Ooo00o = socket . ntohs ( I1iOoo0Ooo00o )
  self . radius = I1iOoo0Ooo00o if ( iiIIii1Iii1I & 0x02 ) else I1iOoo0Ooo00o * 1000
  if 62 - 62: i1IIi % I1Ii111
  self . geo_name = None
  packet = packet [ o0OOo0OOoOO0 : : ]
  if 94 - 94: i1IIi + iII111i
  if ( I1I1i != 0 ) :
   self . rloc . afi = I1I1i
   packet = self . rloc . unpack_address ( packet )
   self . rloc . mask_len = self . rloc . host_mask_len ( )
   if 25 - 25: I1Ii111 . Ii1I - Ii1I . o0oOOo0O0Ooo - IiII
  return ( packet )
  if 91 - 91: o0oOOo0O0Ooo % I1ii11iIi11i % OoOoOO00 * iIii1I11I1II1
  if 18 - 18: OoOoOO00 * I1ii11iIi11i . i1IIi * iII111i
  if 67 - 67: IiII + i11iIiiIii . II111iiii / OoOoOO00 + OoooooooOO + i11iIiiIii
  if 23 - 23: Oo0Ooo
  if 7 - 7: Oo0Ooo / oO0o . I1Ii111 % I11i
  if 85 - 85: II111iiii / o0oOOo0O0Ooo . iIii1I11I1II1 . OoooooooOO / Ii1I
class lisp_rle_node ( ) :
 def __init__ ( self ) :
  self . address = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . level = 0
  self . translated_port = 0
  self . rloc_name = None
  if 18 - 18: i11iIiiIii + o0oOOo0O0Ooo . i11iIiiIii
  if 50 - 50: IiII / OoooooooOO . I11i
 def copy_rle_node ( self ) :
  I11iI = lisp_rle_node ( )
  I11iI . address . copy_address ( self . address )
  I11iI . level = self . level
  I11iI . translated_port = self . translated_port
  I11iI . rloc_name = self . rloc_name
  return ( I11iI )
  if 93 - 93: OOooOOo / OoooooooOO % iII111i % Ii1I / I1Ii111 % OOooOOo
  if 25 - 25: i1IIi % Oo0Ooo . i1IIi * OoOoOO00 . Ii1I % OoO0O00
 def store_translated_rloc ( self , rloc , port ) :
  self . address . copy_address ( rloc )
  self . translated_port = port
  if 47 - 47: o0oOOo0O0Ooo - i11iIiiIii / OoooooooOO
  if 93 - 93: I1IiiI * II111iiii * O0 % o0oOOo0O0Ooo + oO0o / ooOoO0o
 def get_encap_keys ( self ) :
  Ii1 = "4341" if self . translated_port == 0 else str ( self . translated_port )
  if 79 - 79: OoO0O00 + ooOoO0o / oO0o % I1ii11iIi11i
  I1IIII1i1 = self . address . print_address_no_iid ( ) + ":" + Ii1
  if 77 - 77: Ii1I / Ii1I / I1ii11iIi11i
  try :
   Ii111I11 = lisp_crypto_keys_by_rloc_encap [ I1IIII1i1 ]
   if ( Ii111I11 [ 1 ] ) : return ( Ii111I11 [ 1 ] . encrypt_key , Ii111I11 [ 1 ] . icv_key )
   return ( None , None )
  except :
   return ( None , None )
   if 92 - 92: O0 * i11iIiiIii . OoOoOO00 * IiII / o0oOOo0O0Ooo * ooOoO0o
   if 74 - 74: O0 - o0oOOo0O0Ooo
   if 68 - 68: I1Ii111
   if 19 - 19: o0oOOo0O0Ooo
class lisp_rle ( ) :
 def __init__ ( self , name ) :
  self . rle_name = name
  self . rle_nodes = [ ]
  self . rle_forwarding_list = [ ]
  if 63 - 63: OoooooooOO % ooOoO0o
  if 26 - 26: OOooOOo + Oo0Ooo
 def copy_rle ( self ) :
  O000o0 = lisp_rle ( self . rle_name )
  for I11iI in self . rle_nodes :
   O000o0 . rle_nodes . append ( I11iI . copy_rle_node ( ) )
   if 97 - 97: I1Ii111 * I1Ii111 + iII111i % Ii1I / iII111i
  O000o0 . build_forwarding_list ( )
  return ( O000o0 )
  if 73 - 73: OoOoOO00 % I1Ii111 . I1ii11iIi11i
  if 45 - 45: iIii1I11I1II1 % Ii1I . OoOoOO00 . o0oOOo0O0Ooo - OoooooooOO
 def print_rle ( self , html ) :
  OoI1i1IIii = ""
  for I11iI in self . rle_nodes :
   Ii1 = I11iI . translated_port
   ii111iiI = blue ( I11iI . rloc_name , html ) if I11iI . rloc_name != None else ""
   if 86 - 86: O0 . O0 - I1Ii111
   I1IIII1i1 = I11iI . address . print_address_no_iid ( )
   if ( I11iI . address . is_local ( ) ) : I1IIII1i1 = red ( I1IIII1i1 , html )
   OoI1i1IIii += "{}{}(L{}){}, " . format ( I1IIII1i1 , "" if Ii1 == 0 else ":" + str ( Ii1 ) , I11iI . level ,
   # i1IIi * ooOoO0o % iIii1I11I1II1 % O0 + I1Ii111 / OoooooooOO
 "" if I11iI . rloc_name == None else ii111iiI )
   if 71 - 71: oO0o % OoO0O00 / Ii1I % II111iiii * OoOoOO00
  return ( OoI1i1IIii [ 0 : - 2 ] if OoI1i1IIii != "" else "" )
  if 19 - 19: o0oOOo0O0Ooo * IiII . Oo0Ooo * OOooOOo
  if 6 - 6: I1ii11iIi11i / O0
 def build_forwarding_list ( self ) :
  I1i1IiI1i1Ii = - 1
  for I11iI in self . rle_nodes :
   if ( I1i1IiI1i1Ii == - 1 ) :
    if ( I11iI . address . is_local ( ) ) : I1i1IiI1i1Ii = I11iI . level
   else :
    if ( I11iI . level > I1i1IiI1i1Ii ) : break
    if 16 - 16: II111iiii . Oo0Ooo * I1Ii111 + o0oOOo0O0Ooo - i11iIiiIii
    if 98 - 98: II111iiii - i1IIi - ooOoO0o
  I1i1IiI1i1Ii = 0 if I1i1IiI1i1Ii == - 1 else I11iI . level
  if 36 - 36: IiII + o0oOOo0O0Ooo
  self . rle_forwarding_list = [ ]
  for I11iI in self . rle_nodes :
   if ( I11iI . level == I1i1IiI1i1Ii or ( I1i1IiI1i1Ii == 0 and
 I11iI . level == 128 ) ) :
    if ( lisp_i_am_rtr == False and I11iI . address . is_local ( ) ) :
     I1IIII1i1 = I11iI . address . print_address_no_iid ( )
     lprint ( "Exclude local RLE RLOC {}" . format ( I1IIII1i1 ) )
     continue
     if 81 - 81: OOooOOo / I11i % oO0o + ooOoO0o
    self . rle_forwarding_list . append ( I11iI )
    if 10 - 10: oO0o / i11iIiiIii
    if 73 - 73: OoO0O00 - i1IIi
    if 52 - 52: I1ii11iIi11i
    if 4 - 4: Ii1I - iII111i + i1IIi - I1Ii111 / iII111i . Oo0Ooo
    if 18 - 18: oO0o % iIii1I11I1II1 + ooOoO0o
class lisp_json ( ) :
 def __init__ ( self , name , string ) :
  self . json_name = name
  self . json_string = string
  if 34 - 34: I1IiiI - OoooooooOO . IiII - OOooOOo % IiII
  if 19 - 19: IiII + I1ii11iIi11i % Oo0Ooo
 def add ( self ) :
  self . delete ( )
  lisp_json_list [ self . json_name ] = self
  if 32 - 32: OOooOOo
  if 46 - 46: II111iiii . OoO0O00
 def delete ( self ) :
  if ( lisp_json_list . has_key ( self . json_name ) ) :
   del ( lisp_json_list [ self . json_name ] )
   lisp_json_list [ self . json_name ] = None
   if 97 - 97: oO0o
   if 45 - 45: i11iIiiIii / IiII + OoO0O00
   if 55 - 55: Ii1I / II111iiii - oO0o
 def print_json ( self , html ) :
  OoooOOooO0oo0O0 = self . json_string
  ooOOoo0o = "***"
  if ( html ) : ooOOoo0o = red ( ooOOoo0o , html )
  o0o0ooo = ooOOoo0o + self . json_string + ooOOoo0o
  if ( self . valid_json ( ) ) : return ( OoooOOooO0oo0O0 )
  return ( o0o0ooo )
  if 23 - 23: I11i + iIii1I11I1II1
  if 60 - 60: O0 * I1IiiI + o0oOOo0O0Ooo * OoO0O00 + o0oOOo0O0Ooo / i11iIiiIii
 def valid_json ( self ) :
  try :
   json . loads ( self . json_string )
  except :
   return ( False )
   if 54 - 54: i11iIiiIii . iII111i * i1IIi
  return ( True )
  if 68 - 68: Oo0Ooo
  if 20 - 20: IiII + i11iIiiIii * OOooOOo
  if 27 - 27: O0 * OoO0O00 * I1ii11iIi11i
  if 40 - 40: O0 + oO0o - ooOoO0o + I1IiiI - IiII
  if 60 - 60: I1Ii111 * OoO0O00 * oO0o + oO0o
  if 34 - 34: o0oOOo0O0Ooo
class lisp_stats ( ) :
 def __init__ ( self ) :
  self . packet_count = 0
  self . byte_count = 0
  self . last_rate_check = 0
  self . last_packet_count = 0
  self . last_byte_count = 0
  self . last_increment = None
  if 76 - 76: oO0o + OoooooooOO % OoOoOO00 / OoOoOO00
  if 51 - 51: II111iiii / OoOoOO00
 def increment ( self , octets ) :
  self . packet_count += 1
  self . byte_count += octets
  self . last_increment = lisp_get_timestamp ( )
  if 69 - 69: i11iIiiIii
  if 77 - 77: I1ii11iIi11i % OoooooooOO - Oo0Ooo - Ii1I + I11i
 def recent_packet_sec ( self ) :
  if ( self . last_increment == None ) : return ( False )
  ooOO0o = time . time ( ) - self . last_increment
  return ( ooOO0o <= 1 )
  if 93 - 93: I1IiiI % O0 * OoO0O00 % OoOoOO00 . I1Ii111 * I1IiiI
  if 95 - 95: IiII + o0oOOo0O0Ooo - o0oOOo0O0Ooo
 def recent_packet_min ( self ) :
  if ( self . last_increment == None ) : return ( False )
  ooOO0o = time . time ( ) - self . last_increment
  return ( ooOO0o <= 60 )
  if 83 - 83: ooOoO0o
  if 59 - 59: I1ii11iIi11i
 def stat_colors ( self , c1 , c2 , html ) :
  if ( self . recent_packet_sec ( ) ) :
   return ( green_last_sec ( c1 ) , green_last_sec ( c2 ) )
   if 26 - 26: I11i . Ii1I
  if ( self . recent_packet_min ( ) ) :
   return ( green_last_min ( c1 ) , green_last_min ( c2 ) )
   if 94 - 94: ooOoO0o . I1IiiI + IiII % I1IiiI / o0oOOo0O0Ooo % o0oOOo0O0Ooo
  return ( c1 , c2 )
  if 21 - 21: O0 / OOooOOo - II111iiii + I1ii11iIi11i / OoooooooOO
  if 81 - 81: i11iIiiIii / Oo0Ooo * i1IIi + OoO0O00 + O0 % I1ii11iIi11i
 def normalize ( self , count ) :
  count = str ( count )
  Iii11I1Ii111i = len ( count )
  if ( Iii11I1Ii111i > 12 ) :
   count = count [ 0 : - 10 ] + "." + count [ - 10 : - 7 ] + "T"
   return ( count )
   if 63 - 63: Oo0Ooo * ooOoO0o * Ii1I % iIii1I11I1II1 + I11i
  if ( Iii11I1Ii111i > 9 ) :
   count = count [ 0 : - 9 ] + "." + count [ - 9 : - 7 ] + "B"
   return ( count )
   if 77 - 77: O0 . iIii1I11I1II1 . iIii1I11I1II1 * Oo0Ooo * ooOoO0o + ooOoO0o
  if ( Iii11I1Ii111i > 6 ) :
   count = count [ 0 : - 6 ] + "." + count [ - 6 ] + "M"
   return ( count )
   if 16 - 16: OoOoOO00 * Oo0Ooo + iIii1I11I1II1
  return ( count )
  if 17 - 17: Ii1I
  if 19 - 19: OOooOOo . OoOoOO00 % iIii1I11I1II1 % OoOoOO00
 def get_stats ( self , summary , html ) :
  oOoOOO = self . last_rate_check
  i11iiii = self . last_packet_count
  IIi1i = self . last_byte_count
  self . last_rate_check = lisp_get_timestamp ( )
  self . last_packet_count = self . packet_count
  self . last_byte_count = self . byte_count
  if 64 - 64: i1IIi * II111iiii + I1ii11iIi11i + OOooOOo % I1ii11iIi11i - OoooooooOO
  O0oOOOo = self . last_rate_check - oOoOOO
  if ( O0oOOOo == 0 ) :
   O0O0OOOooO0Oo = 0
   Ooo0Ooo0O = 0
  else :
   O0O0OOOooO0Oo = int ( ( self . packet_count - i11iiii ) / O0oOOOo )
   Ooo0Ooo0O = ( self . byte_count - IIi1i ) / O0oOOOo
   Ooo0Ooo0O = ( Ooo0Ooo0O * 8 ) / 1000000
   Ooo0Ooo0O = round ( Ooo0Ooo0O , 2 )
   if 28 - 28: Ii1I . II111iiii - OOooOOo / iIii1I11I1II1 - I1IiiI
   if 78 - 78: iIii1I11I1II1
   if 64 - 64: OoOoOO00 - oO0o
   if 8 - 8: i11iIiiIii - iIii1I11I1II1 / I1Ii111 . i11iIiiIii % o0oOOo0O0Ooo / oO0o
   if 36 - 36: IiII
  Oo0oO = self . normalize ( self . packet_count )
  oooo0Oo0 = self . normalize ( self . byte_count )
  if 39 - 39: oO0o % OOooOOo
  if 81 - 81: i11iIiiIii - iII111i * II111iiii
  if 52 - 52: I1IiiI % Ii1I - Ii1I
  if 73 - 73: I1ii11iIi11i - IiII * IiII . O0 - i11iIiiIii + I1IiiI
  if 20 - 20: I1Ii111
  if ( summary ) :
   iiII = "<br>" if html else ""
   Oo0oO , oooo0Oo0 = self . stat_colors ( Oo0oO , oooo0Oo0 , html )
   Ii1IOO0ooo = "packet-count: {}{}byte-count: {}" . format ( Oo0oO , iiII , oooo0Oo0 )
   oO000ooOOo = "packet-rate: {} pps\nbit-rate: {} Mbps" . format ( O0O0OOOooO0Oo , Ooo0Ooo0O )
   if 75 - 75: i1IIi * II111iiii . II111iiii * I1Ii111 + I1Ii111
   if ( html != "" ) : oO000ooOOo = lisp_span ( Ii1IOO0ooo , oO000ooOOo )
  else :
   iii1I1iIi = str ( O0O0OOOooO0Oo )
   Ii1ii1IiI1 = str ( Ooo0Ooo0O )
   if ( html ) :
    Oo0oO = lisp_print_cour ( Oo0oO )
    iii1I1iIi = lisp_print_cour ( iii1I1iIi )
    oooo0Oo0 = lisp_print_cour ( oooo0Oo0 )
    Ii1ii1IiI1 = lisp_print_cour ( Ii1ii1IiI1 )
    if 25 - 25: iII111i - OOooOOo
   iiII = "<br>" if html else ", "
   if 6 - 6: ooOoO0o + OOooOOo - I1IiiI + OOooOOo
   oO000ooOOo = ( "packet-count: {}{}packet-rate: {} pps{}byte-count: " + "{}{}bit-rate: {} mbps" ) . format ( Oo0oO , iiII , iii1I1iIi , iiII , oooo0Oo0 , iiII ,
   # Oo0Ooo
 Ii1ii1IiI1 )
   if 85 - 85: OoOoOO00 - OoO0O00 + Ii1I
  return ( oO000ooOOo )
  if 30 - 30: OoOoOO00 - O0 + iII111i / OoO0O00 . oO0o + iIii1I11I1II1
  if 19 - 19: Oo0Ooo . IiII - o0oOOo0O0Ooo / II111iiii . O0 - II111iiii
  if 75 - 75: OOooOOo % OoOoOO00 + iIii1I11I1II1 - II111iiii / i1IIi
  if 39 - 39: Ii1I + I1Ii111 * Oo0Ooo + OoOoOO00 / I1Ii111 - ooOoO0o
  if 66 - 66: I11i * OoO0O00
  if 98 - 98: IiII . Oo0Ooo + I1Ii111
  if 63 - 63: oO0o * I1IiiI * oO0o
  if 56 - 56: oO0o - Ii1I % I1Ii111
lisp_decap_stats = {
 "good-packets" : lisp_stats ( ) , "ICV-error" : lisp_stats ( ) ,
 "checksum-error" : lisp_stats ( ) , "lisp-header-error" : lisp_stats ( ) ,
 "no-decrypt-key" : lisp_stats ( ) , "bad-inner-version" : lisp_stats ( ) ,
 "outer-header-error" : lisp_stats ( )
 }
if 100 - 100: OOooOOo * IiII % IiII / o0oOOo0O0Ooo * OoO0O00 % OoOoOO00
if 12 - 12: I1IiiI
if 32 - 32: I1Ii111
if 35 - 35: O0 + II111iiii + o0oOOo0O0Ooo - OoO0O00 - Ii1I
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
  if 88 - 88: I1ii11iIi11i . O0 - o0oOOo0O0Ooo . I1ii11iIi11i * iII111i * I11i
  if ( recurse == False ) : return
  if 89 - 89: Oo0Ooo - oO0o + O0 / i11iIiiIii
  if 64 - 64: OoO0O00 % OoOoOO00 % I1IiiI - Ii1I / IiII * Ii1I
  if 74 - 74: IiII - O0 % OOooOOo % OoooooooOO - I11i
  if 4 - 4: i1IIi + OoOoOO00 + iIii1I11I1II1 - i1IIi * i11iIiiIii
  if 99 - 99: I1ii11iIi11i - O0 % II111iiii + ooOoO0o % OoO0O00 * Ii1I
  if 8 - 8: OOooOOo
  ooo0000OOO0 = lisp_get_default_route_next_hops ( )
  if ( ooo0000OOO0 == [ ] or len ( ooo0000OOO0 ) == 1 ) : return
  if 21 - 21: I1IiiI
  self . rloc_next_hop = ooo0000OOO0 [ 0 ]
  oOo = self
  for oOoo in ooo0000OOO0 [ 1 : : ] :
   I1ooO00oo0O0O = lisp_rloc ( False )
   I1ooO00oo0O0O = copy . deepcopy ( self )
   I1ooO00oo0O0O . rloc_next_hop = oOoo
   oOo . next_rloc = I1ooO00oo0O0O
   oOo = I1ooO00oo0O0O
   if 65 - 65: iIii1I11I1II1 + OoooooooOO - iIii1I11I1II1 - IiII . I1Ii111 * Ii1I
   if 29 - 29: iII111i % iII111i % o0oOOo0O0Ooo + II111iiii
   if 89 - 89: I1IiiI - OoooooooOO / I11i . ooOoO0o
 def up_state ( self ) :
  return ( self . state == LISP_RLOC_UP_STATE )
  if 69 - 69: I1ii11iIi11i
  if 6 - 6: iIii1I11I1II1 * I1ii11iIi11i / I11i % I1Ii111 / Oo0Ooo
 def unreach_state ( self ) :
  return ( self . state == LISP_RLOC_UNREACH_STATE )
  if 94 - 94: OoO0O00 - oO0o + iII111i . ooOoO0o * OoooooooOO
  if 42 - 42: iII111i / i11iIiiIii + II111iiii % IiII / ooOoO0o
 def no_echoed_nonce_state ( self ) :
  return ( self . state == LISP_RLOC_NO_ECHOED_NONCE_STATE )
  if 100 - 100: ooOoO0o / I1IiiI
  if 69 - 69: ooOoO0o + OoO0O00 * o0oOOo0O0Ooo - ooOoO0o
 def down_state ( self ) :
  return ( self . state in [ LISP_RLOC_DOWN_STATE , LISP_RLOC_ADMIN_DOWN_STATE ] )
  if 66 - 66: OoooooooOO / iII111i / I1IiiI % ooOoO0o / OoO0O00 + OOooOOo
  if 64 - 64: i1IIi
  if 26 - 26: OoOoOO00 / o0oOOo0O0Ooo . OOooOOo + I1IiiI + Ii1I . iII111i
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
  if 89 - 89: I1Ii111 * I1IiiI . i1IIi - iIii1I11I1II1 * I1Ii111
  if 5 - 5: OoOoOO00 % i1IIi
 def print_rloc ( self , indent ) :
  I11i1II = lisp_print_elapsed ( self . uptime )
  lprint ( "{}rloc {}, uptime {}, {}, parms {}/{}/{}/{}" . format ( indent ,
 red ( self . rloc . print_address ( ) , False ) , I11i1II , self . print_state ( ) ,
 self . priority , self . weight , self . mpriority , self . mweight ) )
  if 31 - 31: Oo0Ooo * O0 . OOooOOo . o0oOOo0O0Ooo + OoO0O00 + II111iiii
  if 76 - 76: Oo0Ooo + I1IiiI - O0
 def print_rloc_name ( self , cour = False ) :
  if ( self . rloc_name == None ) : return ( "" )
  ooOO0OOO = self . rloc_name
  if ( cour ) : ooOO0OOO = lisp_print_cour ( ooOO0OOO )
  return ( 'rloc-name: {}' . format ( blue ( ooOO0OOO , cour ) ) )
  if 58 - 58: IiII * i1IIi . I1IiiI - iII111i
  if 73 - 73: Oo0Ooo . OoOoOO00
 def store_rloc_from_record ( self , rloc_record , nonce , source ) :
  Ii1 = LISP_DATA_PORT
  self . rloc . copy_address ( rloc_record . rloc )
  self . rloc_name = rloc_record . rloc_name
  if 50 - 50: IiII / o0oOOo0O0Ooo
  if 9 - 9: Oo0Ooo - OoO0O00 + iII111i / OoooooooOO
  if 52 - 52: O0
  if 34 - 34: OoooooooOO + OoOoOO00 - Oo0Ooo . OOooOOo * iIii1I11I1II1
  o0OOooooooOO = self . rloc
  if ( o0OOooooooOO . is_null ( ) == False ) :
   Oo0Oo = lisp_get_nat_info ( o0OOooooooOO , self . rloc_name )
   if ( Oo0Oo ) :
    Ii1 = Oo0Oo . port
    i1I11111I1Iii = lisp_nat_state_info [ self . rloc_name ] [ 0 ]
    I1IIII1i1 = o0OOooooooOO . print_address_no_iid ( )
    oo00OO = red ( I1IIII1i1 , False )
    oooOOoOOo0o = "" if self . rloc_name == None else blue ( self . rloc_name , False )
    if 6 - 6: OoO0O00 / OoO0O00 + I11i + Ii1I + O0
    if 28 - 28: i1IIi % II111iiii * OoOoOO00 / Oo0Ooo - Ii1I % o0oOOo0O0Ooo
    if 15 - 15: iIii1I11I1II1 * I1ii11iIi11i / ooOoO0o * oO0o % OOooOOo
    if 62 - 62: Ii1I / Oo0Ooo . OoO0O00 - OOooOOo
    if 89 - 89: o0oOOo0O0Ooo % OoO0O00
    if 53 - 53: OoOoOO00 . ooOoO0o - OoO0O00
    if ( Oo0Oo . timed_out ( ) ) :
     lprint ( ( "    Matched stored NAT state timed out for " + "RLOC {}:{}, {}" ) . format ( oo00OO , Ii1 , oooOOoOOo0o ) )
     if 26 - 26: ooOoO0o - oO0o + OOooOOo * Ii1I - I11i % I1IiiI
     if 73 - 73: ooOoO0o + Ii1I . O0 . iII111i
     Oo0Oo = None if ( Oo0Oo == i1I11111I1Iii ) else i1I11111I1Iii
     if ( Oo0Oo and Oo0Oo . timed_out ( ) ) :
      Ii1 = Oo0Oo . port
      oo00OO = red ( Oo0Oo . address , False )
      lprint ( ( "    Youngest stored NAT state timed out " + " for RLOC {}:{}, {}" ) . format ( oo00OO , Ii1 ,
      # I11i - o0oOOo0O0Ooo % Ii1I / I1Ii111 * II111iiii
 oooOOoOOo0o ) )
      Oo0Oo = None
      if 40 - 40: OoO0O00 . i11iIiiIii
      if 36 - 36: o0oOOo0O0Ooo * iII111i / I1ii11iIi11i % i1IIi % I1ii11iIi11i + i11iIiiIii
      if 24 - 24: I1Ii111 / ooOoO0o - i11iIiiIii
      if 32 - 32: II111iiii * Ii1I . ooOoO0o * Oo0Ooo - I1ii11iIi11i % I11i
      if 96 - 96: Ii1I / OOooOOo / O0
      if 8 - 8: iII111i + OOooOOo / I1ii11iIi11i . iII111i
      if 45 - 45: i1IIi
    if ( Oo0Oo ) :
     if ( Oo0Oo . address != I1IIII1i1 ) :
      lprint ( "RLOC conflict, RLOC-record {}, NAT state {}" . format ( oo00OO , red ( Oo0Oo . address , False ) ) )
      if 28 - 28: iII111i
      self . rloc . store_address ( Oo0Oo . address )
      if 28 - 28: i1IIi - iII111i + o0oOOo0O0Ooo / Oo0Ooo * oO0o
     oo00OO = red ( Oo0Oo . address , False )
     Ii1 = Oo0Oo . port
     lprint ( "    Use NAT translated RLOC {}:{} for {}" . format ( oo00OO , Ii1 , oooOOoOOo0o ) )
     if 8 - 8: ooOoO0o + OOooOOo * ooOoO0o / i1IIi . I1ii11iIi11i
     self . store_translated_rloc ( o0OOooooooOO , Ii1 )
     if 4 - 4: Ii1I - Oo0Ooo . i1IIi + iIii1I11I1II1
     if 28 - 28: O0 / ooOoO0o / IiII - I11i + IiII + OoO0O00
     if 84 - 84: Oo0Ooo + OoOoOO00 / iII111i . I1ii11iIi11i
     if 26 - 26: Oo0Ooo
  self . geo = rloc_record . geo
  self . elp = rloc_record . elp
  self . json = rloc_record . json
  if 61 - 61: Ii1I * oO0o * i11iIiiIii + OoO0O00
  if 43 - 43: OoO0O00 * OoO0O00 * oO0o
  if 24 - 24: oO0o
  if 77 - 77: i11iIiiIii - I1Ii111 - I1ii11iIi11i * Oo0Ooo / i11iIiiIii
  self . rle = rloc_record . rle
  if ( self . rle ) :
   for I11iI in self . rle . rle_nodes :
    ooOO0OOO = I11iI . rloc_name
    Oo0Oo = lisp_get_nat_info ( I11iI . address , ooOO0OOO )
    if ( Oo0Oo == None ) : continue
    if 79 - 79: Oo0Ooo % Oo0Ooo . oO0o + ooOoO0o * iII111i * I11i
    Ii1 = Oo0Oo . port
    O00OOO0OO = ooOO0OOO
    if ( O00OOO0OO ) : O00OOO0OO = blue ( ooOO0OOO , False )
    if 87 - 87: o0oOOo0O0Ooo + OoOoOO00 % o0oOOo0O0Ooo + I1IiiI
    lprint ( ( "      Store translated encap-port {} for RLE-" + "node {}, rloc-name '{}'" ) . format ( Ii1 ,
    # II111iiii . iIii1I11I1II1 + II111iiii . I1IiiI + OoO0O00 + i1IIi
 I11iI . address . print_address_no_iid ( ) , O00OOO0OO ) )
    I11iI . translated_port = Ii1
    if 39 - 39: ooOoO0o + Ii1I - oO0o / iII111i % IiII
    if 22 - 22: II111iiii
    if 76 - 76: i1IIi
  self . priority = rloc_record . priority
  self . mpriority = rloc_record . mpriority
  self . weight = rloc_record . weight
  self . mweight = rloc_record . mweight
  if ( rloc_record . reach_bit and rloc_record . local_bit and
 rloc_record . probe_bit == False ) : self . state = LISP_RLOC_UP_STATE
  if 60 - 60: iII111i - I1IiiI * I1ii11iIi11i - i1IIi % I1Ii111 % O0
  if 24 - 24: I11i + I11i % I11i
  if 63 - 63: i11iIiiIii + iIii1I11I1II1 / oO0o % IiII - O0
  if 21 - 21: II111iiii
  OO0o0OoO0o = source . is_exact_match ( rloc_record . rloc ) if source != None else None
  if 23 - 23: iIii1I11I1II1
  if ( rloc_record . keys != None and OO0o0OoO0o ) :
   i1iI11iI = rloc_record . keys [ 1 ]
   if ( i1iI11iI != None ) :
    I1IIII1i1 = rloc_record . rloc . print_address_no_iid ( ) + ":" + str ( Ii1 )
    if 88 - 88: I1IiiI + iII111i / Ii1I
    i1iI11iI . add_key_by_rloc ( I1IIII1i1 , True )
    lprint ( "    Store encap-keys for nonce 0x{}, RLOC {}" . format ( lisp_hex_string ( nonce ) , red ( I1IIII1i1 , False ) ) )
    if 57 - 57: o0oOOo0O0Ooo
    if 69 - 69: i1IIi / i1IIi / OoOoOO00 + ooOoO0o % I1Ii111
    if 41 - 41: II111iiii * OOooOOo
  return ( Ii1 )
  if 8 - 8: I1Ii111 + O0
  if 67 - 67: iIii1I11I1II1 . O0
 def store_translated_rloc ( self , rloc , port ) :
  self . rloc . copy_address ( rloc )
  self . translated_rloc . copy_address ( rloc )
  self . translated_port = port
  if 40 - 40: OOooOOo - ooOoO0o . OoooooooOO % O0 * I11i - I1ii11iIi11i
  if 92 - 92: ooOoO0o % oO0o / i11iIiiIii
 def is_rloc_translated ( self ) :
  return ( self . translated_rloc . is_null ( ) == False )
  if 91 - 91: OOooOOo
  if 60 - 60: i11iIiiIii . iIii1I11I1II1 . OOooOOo % IiII
 def rloc_exists ( self ) :
  if ( self . rloc . is_null ( ) == False ) : return ( True )
  if ( self . rle_name or self . geo_name or self . elp_name or self . json_name ) :
   return ( False )
   if 68 - 68: I11i / iII111i - IiII . iIii1I11I1II1 / o0oOOo0O0Ooo
  return ( True )
  if 54 - 54: II111iiii * I1IiiI
  if 49 - 49: I1ii11iIi11i
 def is_rtr ( self ) :
  return ( ( self . priority == 254 and self . mpriority == 255 and self . weight == 0 and self . mweight == 0 ) )
  if 31 - 31: o0oOOo0O0Ooo - OoOoOO00 + I1ii11iIi11i . oO0o - O0
  if 61 - 61: I1ii11iIi11i * II111iiii . i1IIi
  if 60 - 60: OoooooooOO % ooOoO0o * i11iIiiIii * OoooooooOO % IiII
 def print_state_change ( self , new_state ) :
  iIi11IIii = self . print_state ( )
  oo0O = "{} -> {}" . format ( iIi11IIii , new_state )
  if ( new_state == "up" and self . unreach_state ( ) ) :
   oo0O = bold ( oo0O , False )
   if 55 - 55: OoO0O00 + o0oOOo0O0Ooo % OOooOOo + oO0o * OoO0O00
  return ( oo0O )
  if 19 - 19: IiII . Ii1I / Ii1I + O0 - OOooOOo * IiII
  if 7 - 7: I1Ii111 - I1ii11iIi11i + i11iIiiIii / iIii1I11I1II1 + OoO0O00
 def print_rloc_probe_rtt ( self ) :
  if ( self . rloc_probe_rtt == - 1 ) : return ( "none" )
  return ( self . rloc_probe_rtt )
  if 17 - 17: I1IiiI * Ii1I . i11iIiiIii - oO0o . i11iIiiIii + Oo0Ooo
  if 42 - 42: iII111i
 def print_recent_rloc_probe_rtts ( self ) :
  OO0O00ooo = str ( self . recent_rloc_probe_rtts )
  OO0O00ooo = OO0O00ooo . replace ( "-1" , "?" )
  return ( OO0O00ooo )
  if 22 - 22: o0oOOo0O0Ooo
  if 45 - 45: I1Ii111 + OoooooooOO + o0oOOo0O0Ooo * II111iiii
 def compute_rloc_probe_rtt ( self ) :
  oOo = self . rloc_probe_rtt
  self . rloc_probe_rtt = - 1
  if ( self . last_rloc_probe_reply == None ) : return
  if ( self . last_rloc_probe == None ) : return
  self . rloc_probe_rtt = self . last_rloc_probe_reply - self . last_rloc_probe
  self . rloc_probe_rtt = round ( self . rloc_probe_rtt , 3 )
  iIii = self . recent_rloc_probe_rtts
  self . recent_rloc_probe_rtts = [ oOo ] + iIii [ 0 : - 1 ]
  if 93 - 93: OoOoOO00
  if 48 - 48: i1IIi
 def print_rloc_probe_hops ( self ) :
  return ( self . rloc_probe_hops )
  if 22 - 22: iII111i / OoO0O00 * OOooOOo + I11i
  if 84 - 84: IiII * IiII * o0oOOo0O0Ooo
 def print_recent_rloc_probe_hops ( self ) :
  IiIiIi1i11II = str ( self . recent_rloc_probe_hops )
  return ( IiIiIi1i11II )
  if 16 - 16: I1IiiI + I11i
  if 66 - 66: OoooooooOO % II111iiii / I1Ii111 . i11iIiiIii
 def store_rloc_probe_hops ( self , to_hops , from_ttl ) :
  if ( to_hops == 0 ) :
   to_hops = "?"
  elif ( to_hops < LISP_RLOC_PROBE_TTL / 2 ) :
   to_hops = "!"
  else :
   to_hops = str ( LISP_RLOC_PROBE_TTL - to_hops )
   if 67 - 67: Ii1I + Oo0Ooo - I1IiiI - IiII + oO0o + Oo0Ooo
  if ( from_ttl < LISP_RLOC_PROBE_TTL / 2 ) :
   OOOO0O00Oo = "!"
  else :
   OOOO0O00Oo = str ( LISP_RLOC_PROBE_TTL - from_ttl )
   if 22 - 22: oO0o * i1IIi
   if 54 - 54: I1IiiI * I1IiiI % IiII - i11iIiiIii * o0oOOo0O0Ooo
  oOo = self . rloc_probe_hops
  self . rloc_probe_hops = to_hops + "/" + OOOO0O00Oo
  iIii = self . recent_rloc_probe_hops
  self . recent_rloc_probe_hops = [ oOo ] + iIii [ 0 : - 1 ]
  if 38 - 38: OoOoOO00 / OOooOOo % OoooooooOO * I1ii11iIi11i
  if 7 - 7: I11i * O0 + Oo0Ooo / O0 * oO0o + i11iIiiIii
 def process_rloc_probe_reply ( self , nonce , eid , group , hop_count , ttl ) :
  o0OOooooooOO = self
  while ( True ) :
   if ( o0OOooooooOO . last_rloc_probe_nonce == nonce ) : break
   o0OOooooooOO = o0OOooooooOO . next_rloc
   if ( o0OOooooooOO == None ) :
    lprint ( "    No matching nonce state found for nonce 0x{}" . format ( lisp_hex_string ( nonce ) ) )
    if 74 - 74: OoOoOO00
    return
    if 91 - 91: i11iIiiIii / Ii1I % OOooOOo % O0 - I11i . I11i
    if 78 - 78: i1IIi + I11i % OoooooooOO + i1IIi + iII111i % Ii1I
    if 87 - 87: ooOoO0o . iIii1I11I1II1
  o0OOooooooOO . last_rloc_probe_reply = lisp_get_timestamp ( )
  o0OOooooooOO . compute_rloc_probe_rtt ( )
  O00o00 = o0OOooooooOO . print_state_change ( "up" )
  if ( o0OOooooooOO . state != LISP_RLOC_UP_STATE ) :
   lisp_update_rtr_updown ( o0OOooooooOO . rloc , True )
   o0OOooooooOO . state = LISP_RLOC_UP_STATE
   o0OOooooooOO . last_state_change = lisp_get_timestamp ( )
   OoOOO000O0o = lisp_map_cache . lookup_cache ( eid , True )
   if ( OoOOO000O0o ) : lisp_write_ipc_map_cache ( True , OoOOO000O0o )
   if 65 - 65: iIii1I11I1II1
   if 58 - 58: IiII % i1IIi . i11iIiiIii
  o0OOooooooOO . store_rloc_probe_hops ( hop_count , ttl )
  if 5 - 5: OoOoOO00
  OOo00o = bold ( "RLOC-probe reply" , False )
  I1IIII1i1 = o0OOooooooOO . rloc . print_address_no_iid ( )
  oOOO0Ooooo = bold ( str ( o0OOooooooOO . print_rloc_probe_rtt ( ) ) , False )
  IiIiI1 = ":{}" . format ( self . translated_port ) if self . translated_port != 0 else ""
  if 57 - 57: OoooooooOO % OoooooooOO + I1ii11iIi11i - I11i * II111iiii
  oOoo = ""
  if ( o0OOooooooOO . rloc_next_hop != None ) :
   oOOoO0O , iiiIIiII111I = o0OOooooooOO . rloc_next_hop
   oOoo = ", nh {}({})" . format ( iiiIIiII111I , oOOoO0O )
   if 86 - 86: I1IiiI
   if 83 - 83: I11i % Ii1I + IiII % I11i / i1IIi . oO0o
  o0o000 = green ( lisp_print_eid_tuple ( eid , group ) , False )
  lprint ( ( "    Received {} from {}{} for {}, {}, rtt {}{}, " + "to-ttl/from-ttl {}" ) . format ( OOo00o , red ( I1IIII1i1 , False ) , IiIiI1 , o0o000 ,
  # I1ii11iIi11i + iII111i * o0oOOo0O0Ooo % II111iiii
 O00o00 , oOOO0Ooooo , oOoo , str ( hop_count ) + "/" + str ( ttl ) ) )
  if 23 - 23: i1IIi * oO0o * oO0o . i11iIiiIii / o0oOOo0O0Ooo
  if ( o0OOooooooOO . rloc_next_hop == None ) : return
  if 80 - 80: O0 / II111iiii . Oo0Ooo + o0oOOo0O0Ooo - OoO0O00
  if 8 - 8: o0oOOo0O0Ooo / I1Ii111 % i1IIi
  if 6 - 6: I1Ii111 * oO0o
  if 48 - 48: Ii1I + i1IIi . iIii1I11I1II1
  o0OOooooooOO = None
  Oo0OOoO0oo0oO = None
  while ( True ) :
   o0OOooooooOO = self if o0OOooooooOO == None else o0OOooooooOO . next_rloc
   if ( o0OOooooooOO == None ) : break
   if ( o0OOooooooOO . up_state ( ) == False ) : continue
   if ( o0OOooooooOO . rloc_probe_rtt == - 1 ) : continue
   if 31 - 31: iIii1I11I1II1 + I1IiiI
   if ( Oo0OOoO0oo0oO == None ) : Oo0OOoO0oo0oO = o0OOooooooOO
   if ( o0OOooooooOO . rloc_probe_rtt < Oo0OOoO0oo0oO . rloc_probe_rtt ) : Oo0OOoO0oo0oO = o0OOooooooOO
   if 82 - 82: I1Ii111 / Ii1I % OoooooooOO - IiII / OoooooooOO
   if 23 - 23: iIii1I11I1II1
  if ( Oo0OOoO0oo0oO != None ) :
   oOOoO0O , iiiIIiII111I = Oo0OOoO0oo0oO . rloc_next_hop
   oOoo = bold ( "nh {}({})" . format ( iiiIIiII111I , oOOoO0O ) , False )
   lprint ( "    Install host-route via best {}" . format ( oOoo ) )
   lisp_install_host_route ( I1IIII1i1 , None , False )
   lisp_install_host_route ( I1IIII1i1 , iiiIIiII111I , True )
   if 7 - 7: IiII / OOooOOo + Oo0Ooo . I1IiiI
   if 33 - 33: I1Ii111 + OoooooooOO
   if 73 - 73: O0 . Oo0Ooo
 def add_to_rloc_probe_list ( self , eid , group ) :
  I1IIII1i1 = self . rloc . print_address_no_iid ( )
  Ii1 = self . translated_port
  if ( Ii1 != 0 ) : I1IIII1i1 += ":" + str ( Ii1 )
  if 28 - 28: I1IiiI . O0 % o0oOOo0O0Ooo / I11i
  if ( lisp_rloc_probe_list . has_key ( I1IIII1i1 ) == False ) :
   lisp_rloc_probe_list [ I1IIII1i1 ] = [ ]
   if 48 - 48: II111iiii % I1ii11iIi11i - II111iiii
   if 29 - 29: I1Ii111 - I1Ii111 - I11i * iIii1I11I1II1 % OoO0O00 % IiII
  if ( group . is_null ( ) ) : group . instance_id = 0
  for IIi , o0o000 , IiIoO0oo0 in lisp_rloc_probe_list [ I1IIII1i1 ] :
   if ( o0o000 . is_exact_match ( eid ) and IiIoO0oo0 . is_exact_match ( group ) ) :
    if ( IIi == self ) :
     if ( lisp_rloc_probe_list [ I1IIII1i1 ] == [ ] ) :
      lisp_rloc_probe_list . pop ( I1IIII1i1 )
      if 73 - 73: i1IIi . OoooooooOO / OoOoOO00 % Ii1I / Ii1I / Ii1I
     return
     if 40 - 40: I1Ii111 - iIii1I11I1II1
    lisp_rloc_probe_list [ I1IIII1i1 ] . remove ( [ IIi , o0o000 , IiIoO0oo0 ] )
    break
    if 88 - 88: OOooOOo * O0 * OoOoOO00
    if 26 - 26: Ii1I
  lisp_rloc_probe_list [ I1IIII1i1 ] . append ( [ self , eid , group ] )
  if 65 - 65: iII111i / iIii1I11I1II1 + I11i - iIii1I11I1II1 - Ii1I . I1Ii111
  if 77 - 77: OoOoOO00 / I1IiiI + IiII
  if 66 - 66: i11iIiiIii * OoooooooOO + iII111i / Ii1I
  if 42 - 42: Ii1I / iIii1I11I1II1 / Oo0Ooo . O0 . oO0o * I1IiiI
  if 21 - 21: OoooooooOO
  o0OOooooooOO = lisp_rloc_probe_list [ I1IIII1i1 ] [ 0 ] [ 0 ]
  if ( o0OOooooooOO . state == LISP_RLOC_UNREACH_STATE ) :
   self . state = LISP_RLOC_UNREACH_STATE
   self . last_state_change = lisp_get_timestamp ( )
   if 76 - 76: i1IIi * i11iIiiIii / OOooOOo + I1Ii111
   if 50 - 50: oO0o % OoOoOO00 + I1IiiI
   if 15 - 15: II111iiii - iII111i / I1ii11iIi11i
 def delete_from_rloc_probe_list ( self , eid , group ) :
  I1IIII1i1 = self . rloc . print_address_no_iid ( )
  Ii1 = self . translated_port
  if ( Ii1 != 0 ) : I1IIII1i1 += ":" + str ( Ii1 )
  if ( lisp_rloc_probe_list . has_key ( I1IIII1i1 ) == False ) : return
  if 81 - 81: Ii1I - i1IIi % oO0o * Oo0Ooo * OoOoOO00
  OO0OO0 = [ ]
  for iiIiiIi in lisp_rloc_probe_list [ I1IIII1i1 ] :
   if ( iiIiiIi [ 0 ] != self ) : continue
   if ( iiIiiIi [ 1 ] . is_exact_match ( eid ) == False ) : continue
   if ( iiIiiIi [ 2 ] . is_exact_match ( group ) == False ) : continue
   OO0OO0 = iiIiiIi
   break
   if 75 - 75: OoO0O00 % iII111i
  if ( OO0OO0 == [ ] ) : return
  if 46 - 46: o0oOOo0O0Ooo
  try :
   lisp_rloc_probe_list [ I1IIII1i1 ] . remove ( OO0OO0 )
   if ( lisp_rloc_probe_list [ I1IIII1i1 ] == [ ] ) :
    lisp_rloc_probe_list . pop ( I1IIII1i1 )
    if 61 - 61: OoO0O00 . O0 + I1ii11iIi11i + OoO0O00
  except :
   return
   if 44 - 44: I11i . oO0o
   if 65 - 65: I1ii11iIi11i * II111iiii % I11i + II111iiii . i1IIi / ooOoO0o
   if 74 - 74: OoOoOO00 % OoO0O00 . OoOoOO00
 def print_rloc_probe_state ( self , trailing_linefeed ) :
  II = ""
  o0OOooooooOO = self
  while ( True ) :
   II11 = o0OOooooooOO . last_rloc_probe
   if ( II11 == None ) : II11 = 0
   iI1ii11 = o0OOooooooOO . last_rloc_probe_reply
   if ( iI1ii11 == None ) : iI1ii11 = 0
   oOOO0Ooooo = o0OOooooooOO . print_rloc_probe_rtt ( )
   IiiiI1 = space ( 4 )
   if 59 - 59: o0oOOo0O0Ooo
   if ( o0OOooooooOO . rloc_next_hop == None ) :
    II += "RLOC-Probing:\n"
   else :
    oOOoO0O , iiiIIiII111I = o0OOooooooOO . rloc_next_hop
    II += "RLOC-Probing for nh {}({}):\n" . format ( iiiIIiII111I , oOOoO0O )
    if 76 - 76: OoO0O00 + O0 - OoOoOO00 - IiII
    if 11 - 11: ooOoO0o + OoOoOO00 - i1IIi
   II += ( "{}RLOC-probe request sent: {}\n{}RLOC-probe reply " + "received: {}, rtt {}" ) . format ( IiiiI1 , lisp_print_elapsed ( II11 ) ,
   # i11iIiiIii . Ii1I * OoOoOO00 - Ii1I / OoO0O00
 IiiiI1 , lisp_print_elapsed ( iI1ii11 ) , oOOO0Ooooo )
   if 35 - 35: II111iiii . II111iiii - Ii1I % I1ii11iIi11i - Oo0Ooo * ooOoO0o
   if ( trailing_linefeed ) : II += "\n"
   if 85 - 85: IiII
   o0OOooooooOO = o0OOooooooOO . next_rloc
   if ( o0OOooooooOO == None ) : break
   II += "\n"
   if 87 - 87: oO0o % OoO0O00 . iIii1I11I1II1 * ooOoO0o + oO0o + IiII
  return ( II )
  if 74 - 74: i1IIi % i1IIi + Oo0Ooo
  if 48 - 48: iII111i . i11iIiiIii + i11iIiiIii
 def get_encap_keys ( self ) :
  Ii1 = "4341" if self . translated_port == 0 else str ( self . translated_port )
  if 56 - 56: OoooooooOO
  I1IIII1i1 = self . rloc . print_address_no_iid ( ) + ":" + Ii1
  if 52 - 52: O0 - I1Ii111 + oO0o % ooOoO0o . oO0o
  try :
   Ii111I11 = lisp_crypto_keys_by_rloc_encap [ I1IIII1i1 ]
   if ( Ii111I11 [ 1 ] ) : return ( Ii111I11 [ 1 ] . encrypt_key , Ii111I11 [ 1 ] . icv_key )
   return ( None , None )
  except :
   return ( None , None )
   if 60 - 60: oO0o + o0oOOo0O0Ooo - OOooOOo % o0oOOo0O0Ooo . I11i + OoO0O00
   if 27 - 27: i11iIiiIii - I1ii11iIi11i * I1Ii111 . I1IiiI / OoO0O00 * ooOoO0o
   if 42 - 42: OOooOOo
 def rloc_recent_rekey ( self ) :
  Ii1 = "4341" if self . translated_port == 0 else str ( self . translated_port )
  if 36 - 36: OoooooooOO + ooOoO0o + iII111i
  I1IIII1i1 = self . rloc . print_address_no_iid ( ) + ":" + Ii1
  if 30 - 30: i1IIi % Ii1I
  try :
   i1iI11iI = lisp_crypto_keys_by_rloc_encap [ I1IIII1i1 ] [ 1 ]
   if ( i1iI11iI == None ) : return ( False )
   if ( i1iI11iI . last_rekey == None ) : return ( True )
   return ( time . time ( ) - i1iI11iI . last_rekey < 1 )
  except :
   return ( False )
   if 18 - 18: o0oOOo0O0Ooo % I1ii11iIi11i . Ii1I . O0 * II111iiii + I1ii11iIi11i
   if 45 - 45: OoO0O00 / I1ii11iIi11i * ooOoO0o * OOooOOo % i11iIiiIii * iII111i
   if 33 - 33: oO0o . iII111i + Oo0Ooo
   if 33 - 33: ooOoO0o
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
  if 46 - 46: OoOoOO00 / iII111i - OoO0O00 . o0oOOo0O0Ooo
  if 50 - 50: I1Ii111 . O0 . OoOoOO00 + I1Ii111 + OoooooooOO . i11iIiiIii
 def print_mapping ( self , eid_indent , rloc_indent ) :
  I11i1II = lisp_print_elapsed ( self . uptime )
  IiI1111i1i11I = "" if self . group . is_null ( ) else ", group {}" . format ( self . group . print_prefix ( ) )
  if 65 - 65: I1IiiI % iIii1I11I1II1
  lprint ( "{}eid {}{}, uptime {}, {} rlocs:" . format ( eid_indent ,
 green ( self . eid . print_prefix ( ) , False ) , IiI1111i1i11I , I11i1II ,
 len ( self . rloc_set ) ) )
  for o0OOooooooOO in self . rloc_set : o0OOooooooOO . print_rloc ( rloc_indent )
  if 52 - 52: I1IiiI
  if 19 - 19: I1IiiI
 def print_eid_tuple ( self ) :
  return ( lisp_print_eid_tuple ( self . eid , self . group ) )
  if 17 - 17: I11i + OoooooooOO
  if 63 - 63: IiII
 def print_ttl ( self ) :
  I1i = self . map_cache_ttl
  if ( I1i == None ) : return ( "forever" )
  if 3 - 3: oO0o * II111iiii . O0
  if ( I1i >= 3600 ) :
   if ( ( I1i % 3600 ) == 0 ) :
    I1i = str ( I1i / 3600 ) + " hours"
   else :
    I1i = str ( I1i * 60 ) + " mins"
    if 19 - 19: I1IiiI / I1IiiI / Oo0Ooo + oO0o + i1IIi
  elif ( I1i >= 60 ) :
   if ( ( I1i % 60 ) == 0 ) :
    I1i = str ( I1i / 60 ) + " mins"
   else :
    I1i = str ( I1i ) + " secs"
    if 31 - 31: iII111i / OoooooooOO - I1Ii111 . iII111i
  else :
   I1i = str ( I1i ) + " secs"
   if 38 - 38: ooOoO0o . OoooooooOO - II111iiii * i11iIiiIii / i1IIi . OoooooooOO
  return ( I1i )
  if 51 - 51: oO0o - I1ii11iIi11i + I1ii11iIi11i
  if 100 - 100: I11i - I1ii11iIi11i . i1IIi
 def has_ttl_elapsed ( self ) :
  if ( self . map_cache_ttl == None ) : return ( False )
  ooOO0o = time . time ( ) - self . last_refresh_time
  if ( ooOO0o >= self . map_cache_ttl ) : return ( True )
  if 85 - 85: II111iiii
  if 58 - 58: i1IIi - OoO0O00 + ooOoO0o
  if 6 - 6: IiII % I1IiiI + OoooooooOO * oO0o . iII111i + oO0o
  if 4 - 4: I11i % I1IiiI
  if 72 - 72: I1IiiI % II111iiii % iII111i / OoOoOO00
  oO0OoO0oo0 = self . map_cache_ttl - ( self . map_cache_ttl / 10 )
  if ( ooOO0o >= oO0OoO0oo0 ) : return ( True )
  return ( False )
  if 82 - 82: I1Ii111
  if 78 - 78: I1Ii111 % oO0o * iIii1I11I1II1
 def is_active ( self ) :
  if ( self . stats . last_increment == None ) : return ( False )
  ooOO0o = time . time ( ) - self . stats . last_increment
  return ( ooOO0o <= 60 )
  if 1 - 1: i1IIi . iIii1I11I1II1
  if 2 - 2: OOooOOo % Oo0Ooo * OOooOOo + I1Ii111 % OoOoOO00 / O0
 def match_eid_tuple ( self , db ) :
  if ( self . eid . is_exact_match ( db . eid ) == False ) : return ( False )
  if ( self . group . is_exact_match ( db . group ) == False ) : return ( False )
  return ( True )
  if 23 - 23: O0 * oO0o / I1IiiI + i1IIi * O0 % oO0o
  if 11 - 11: I1Ii111 . OoooooooOO * iIii1I11I1II1 / I1ii11iIi11i - ooOoO0o . iII111i
 def sort_rloc_set ( self ) :
  self . rloc_set . sort ( key = operator . attrgetter ( 'rloc.address' ) )
  if 71 - 71: i11iIiiIii + I11i / i11iIiiIii % Oo0Ooo / iIii1I11I1II1 * OoO0O00
  if 49 - 49: iII111i + OoOoOO00
 def delete_rlocs_from_rloc_probe_list ( self ) :
  for o0OOooooooOO in self . best_rloc_set :
   o0OOooooooOO . delete_from_rloc_probe_list ( self . eid , self . group )
   if 33 - 33: ooOoO0o
   if 19 - 19: I1Ii111 % IiII
   if 94 - 94: I1Ii111 * I1ii11iIi11i * I1ii11iIi11i - o0oOOo0O0Ooo . i11iIiiIii
 def build_best_rloc_set ( self ) :
  i1i1oO0OOoOOo = self . best_rloc_set
  self . best_rloc_set = [ ]
  if ( self . rloc_set == None ) : return
  if 28 - 28: I1ii11iIi11i
  if 83 - 83: ooOoO0o % I1IiiI - OoOoOO00 - I11i
  if 12 - 12: I1Ii111 . OoO0O00 + I11i * OoO0O00 - IiII + I11i
  if 98 - 98: iII111i . I1Ii111 * IiII - Ii1I * OoooooooOO
  i1iIiII11I1 = 256
  for o0OOooooooOO in self . rloc_set :
   if ( o0OOooooooOO . up_state ( ) ) : i1iIiII11I1 = min ( o0OOooooooOO . priority , i1iIiII11I1 )
   if 22 - 22: ooOoO0o
   if 83 - 83: OOooOOo - i11iIiiIii - i1IIi / oO0o
   if 33 - 33: OoO0O00 + OOooOOo
   if 36 - 36: o0oOOo0O0Ooo . o0oOOo0O0Ooo / oO0o * ooOoO0o * Ii1I * IiII
   if 39 - 39: i1IIi
   if 79 - 79: ooOoO0o - II111iiii - oO0o
   if 55 - 55: iII111i % iIii1I11I1II1 + Ii1I + oO0o . i11iIiiIii - OOooOOo
   if 14 - 14: oO0o - i11iIiiIii / OoOoOO00 % o0oOOo0O0Ooo / IiII * I1IiiI
   if 2 - 2: i1IIi / I1Ii111 + I1IiiI + I1ii11iIi11i - o0oOOo0O0Ooo + iIii1I11I1II1
   if 78 - 78: I1ii11iIi11i % i1IIi . I1Ii111 + Oo0Ooo . o0oOOo0O0Ooo % II111iiii
  for o0OOooooooOO in self . rloc_set :
   if ( o0OOooooooOO . priority <= i1iIiII11I1 ) :
    if ( o0OOooooooOO . unreach_state ( ) and o0OOooooooOO . last_rloc_probe == None ) :
     o0OOooooooOO . last_rloc_probe = lisp_get_timestamp ( )
     if 65 - 65: Ii1I . OoOoOO00 + O0 / iIii1I11I1II1 % Ii1I % I1Ii111
    self . best_rloc_set . append ( o0OOooooooOO )
    if 31 - 31: o0oOOo0O0Ooo - Oo0Ooo
    if 15 - 15: O0 + OOooOOo
    if 8 - 8: i11iIiiIii . IiII . I1ii11iIi11i + i1IIi % I1Ii111
    if 64 - 64: I1IiiI . Oo0Ooo * OoO0O00
    if 87 - 87: i1IIi / OoooooooOO
    if 68 - 68: I1Ii111 / iIii1I11I1II1
    if 8 - 8: ooOoO0o * IiII * OOooOOo / I1IiiI
    if 40 - 40: i11iIiiIii + OoooooooOO
  for o0OOooooooOO in i1i1oO0OOoOOo :
   if ( o0OOooooooOO . priority < i1iIiII11I1 ) : continue
   o0OOooooooOO . delete_from_rloc_probe_list ( self . eid , self . group )
   if 2 - 2: o0oOOo0O0Ooo * OoO0O00
  for o0OOooooooOO in self . best_rloc_set :
   if ( o0OOooooooOO . rloc . is_null ( ) ) : continue
   o0OOooooooOO . add_to_rloc_probe_list ( self . eid , self . group )
   if 88 - 88: Oo0Ooo + oO0o + iII111i
   if 51 - 51: i1IIi + i11iIiiIii * I11i / iII111i + OoooooooOO
   if 89 - 89: i11iIiiIii - I1Ii111 - O0 % iIii1I11I1II1 / IiII - O0
 def select_rloc ( self , lisp_packet , ipc_socket ) :
  Oo0O0oo = lisp_packet . packet
  ooOoOOoo0O = lisp_packet . inner_version
  O0o0oOOO = len ( self . best_rloc_set )
  if ( O0o0oOOO is 0 ) :
   self . stats . increment ( len ( Oo0O0oo ) )
   return ( [ None , None , None , self . action , None , None ] )
   if 16 - 16: o0oOOo0O0Ooo - iIii1I11I1II1 / OoooooooOO / I1ii11iIi11i + IiII
   if 73 - 73: OOooOOo % I1Ii111 + OoooooooOO / I1ii11iIi11i * oO0o % oO0o
  i1iIIiiI1iI1i = 4 if lisp_load_split_pings else 0
  I1i1Ii = lisp_packet . hash_ports ( )
  if ( ooOoOOoo0O == 4 ) :
   for o0OoO00 in range ( 8 + i1iIIiiI1iI1i ) :
    I1i1Ii = I1i1Ii ^ struct . unpack ( "B" , Oo0O0oo [ o0OoO00 + 12 ] ) [ 0 ]
    if 37 - 37: OOooOOo - O0 / OoO0O00 * OoooooooOO - ooOoO0o
  elif ( ooOoOOoo0O == 6 ) :
   for o0OoO00 in range ( 0 , 32 + i1iIIiiI1iI1i , 4 ) :
    I1i1Ii = I1i1Ii ^ struct . unpack ( "I" , Oo0O0oo [ o0OoO00 + 8 : o0OoO00 + 12 ] ) [ 0 ]
    if 63 - 63: OoooooooOO % I1Ii111 + IiII / OoooooooOO
   I1i1Ii = ( I1i1Ii >> 16 ) + ( I1i1Ii & 0xffff )
   I1i1Ii = ( I1i1Ii >> 8 ) + ( I1i1Ii & 0xff )
  else :
   for o0OoO00 in range ( 0 , 12 + i1iIIiiI1iI1i , 4 ) :
    I1i1Ii = I1i1Ii ^ struct . unpack ( "I" , Oo0O0oo [ o0OoO00 : o0OoO00 + 4 ] ) [ 0 ]
    if 60 - 60: II111iiii + II111iiii
    if 30 - 30: OOooOOo / OoO0O00
    if 38 - 38: O0 * i1IIi + IiII
  if ( lisp_data_plane_logging ) :
   iII11I1 = [ ]
   for IIi in self . best_rloc_set :
    if ( IIi . rloc . is_null ( ) ) : continue
    iII11I1 . append ( [ IIi . rloc . print_address_no_iid ( ) , IIi . print_state ( ) ] )
    if 8 - 8: Ii1I % i1IIi
   dprint ( "Packet hash {}, index {}, best-rloc-list: {}" . format ( hex ( I1i1Ii ) , I1i1Ii % O0o0oOOO , red ( str ( iII11I1 ) , False ) ) )
   if 29 - 29: oO0o % OoOoOO00 / OoOoOO00
   if 79 - 79: IiII % OoooooooOO
   if 51 - 51: iII111i . oO0o % ooOoO0o % Ii1I . o0oOOo0O0Ooo
   if 43 - 43: II111iiii
   if 72 - 72: OoOoOO00 * oO0o - ooOoO0o / iII111i
   if 8 - 8: OoO0O00 * I1ii11iIi11i
  o0OOooooooOO = self . best_rloc_set [ I1i1Ii % O0o0oOOO ]
  if 18 - 18: O0 + I1Ii111 . I1ii11iIi11i
  if 48 - 48: Ii1I . o0oOOo0O0Ooo * O0 / OoooooooOO + I1Ii111 + Oo0Ooo
  if 92 - 92: Ii1I - o0oOOo0O0Ooo % I1IiiI + I1Ii111
  if 3 - 3: iIii1I11I1II1 + i11iIiiIii
  if 49 - 49: OoOoOO00 % iIii1I11I1II1 + I1Ii111
  O00o = lisp_get_echo_nonce ( o0OOooooooOO . rloc , None )
  if ( O00o ) :
   O00o . change_state ( o0OOooooooOO )
   if ( o0OOooooooOO . no_echoed_nonce_state ( ) ) :
    O00o . request_nonce_sent = None
    if 38 - 38: i11iIiiIii
    if 75 - 75: iIii1I11I1II1 / OoO0O00 * OOooOOo % O0
    if 82 - 82: Oo0Ooo / i1IIi . i1IIi / oO0o
    if 7 - 7: Oo0Ooo . iII111i % I1ii11iIi11i / iII111i
    if 93 - 93: iII111i
    if 5 - 5: iII111i . I11i % I11i * Ii1I - I1ii11iIi11i . i11iIiiIii
  if ( o0OOooooooOO . up_state ( ) == False ) :
   iI1II = I1i1Ii % O0o0oOOO
   ii = ( iI1II + 1 ) % O0o0oOOO
   while ( ii != iI1II ) :
    o0OOooooooOO = self . best_rloc_set [ ii ]
    if ( o0OOooooooOO . up_state ( ) ) : break
    ii = ( ii + 1 ) % O0o0oOOO
    if 53 - 53: I1Ii111 . O0 % OoO0O00 . I11i
   if ( ii == iI1II ) :
    self . build_best_rloc_set ( )
    return ( [ None , None , None , None , None , None ] )
    if 41 - 41: iII111i . I1Ii111 - IiII / O0
    if 62 - 62: IiII * I1ii11iIi11i * iII111i * OoOoOO00
    if 12 - 12: Oo0Ooo * Ii1I / ooOoO0o % I11i % O0
    if 25 - 25: Oo0Ooo * oO0o
    if 78 - 78: OoOoOO00 / II111iiii
    if 6 - 6: I1Ii111 . OoOoOO00
  o0OOooooooOO . stats . increment ( len ( Oo0O0oo ) )
  if 75 - 75: Oo0Ooo + I11i
  if 87 - 87: I1IiiI
  if 36 - 36: OoO0O00 . ooOoO0o . O0 / OoO0O00
  if 50 - 50: Ii1I . OoOoOO00 * o0oOOo0O0Ooo
  if ( o0OOooooooOO . rle_name and o0OOooooooOO . rle == None ) :
   if ( lisp_rle_list . has_key ( o0OOooooooOO . rle_name ) ) :
    o0OOooooooOO . rle = lisp_rle_list [ o0OOooooooOO . rle_name ]
    if 68 - 68: IiII * oO0o / OoOoOO00 / I1Ii111
    if 72 - 72: I1ii11iIi11i
  if ( o0OOooooooOO . rle ) : return ( [ None , None , None , None , o0OOooooooOO . rle , None ] )
  if 74 - 74: I1Ii111 * iIii1I11I1II1 / oO0o - IiII - I1IiiI
  if 84 - 84: iIii1I11I1II1 % Oo0Ooo / I1ii11iIi11i + o0oOOo0O0Ooo * II111iiii
  if 81 - 81: I1IiiI / I1ii11iIi11i / OOooOOo
  if 89 - 89: Oo0Ooo % IiII
  if ( o0OOooooooOO . elp and o0OOooooooOO . elp . use_elp_node ) :
   return ( [ o0OOooooooOO . elp . use_elp_node . address , None , None , None , None ,
 None ] )
   if 36 - 36: IiII % OoOoOO00 % I1ii11iIi11i
   if 7 - 7: I1ii11iIi11i % OoOoOO00 - O0 . I1Ii111
   if 9 - 9: Ii1I . OoooooooOO / ooOoO0o + i1IIi
   if 90 - 90: oO0o - OoOoOO00 % ooOoO0o
   if 83 - 83: OOooOOo - I1ii11iIi11i + OoO0O00
  o00O0oOo = None if ( o0OOooooooOO . rloc . is_null ( ) ) else o0OOooooooOO . rloc
  Ii1 = o0OOooooooOO . translated_port
  i11IIiI = self . action if ( o00O0oOo == None ) else None
  if 64 - 64: Ii1I - iIii1I11I1II1 * I1IiiI % iII111i * II111iiii / OoO0O00
  if 16 - 16: iIii1I11I1II1
  if 39 - 39: oO0o / OoO0O00 - Ii1I + ooOoO0o + OOooOOo
  if 84 - 84: iII111i / Oo0Ooo
  if 21 - 21: OoO0O00 . I1IiiI - OoO0O00
  Iii1i11 = None
  if ( O00o and O00o . request_nonce_timeout ( ) == False ) :
   Iii1i11 = O00o . get_request_or_echo_nonce ( ipc_socket , o00O0oOo )
   if 51 - 51: iIii1I11I1II1
   if 5 - 5: oO0o - OoOoOO00 . ooOoO0o
   if 97 - 97: I11i - ooOoO0o + oO0o . I1Ii111
   if 22 - 22: Ii1I - II111iiii % Oo0Ooo * OoOoOO00 + iIii1I11I1II1
   if 5 - 5: Oo0Ooo % o0oOOo0O0Ooo * I1Ii111
  return ( [ o00O0oOo , Ii1 , Iii1i11 , i11IIiI , None , o0OOooooooOO ] )
  if 6 - 6: OOooOOo + o0oOOo0O0Ooo
  if 41 - 41: OoooooooOO + iIii1I11I1II1 . O0 % I1Ii111 % OOooOOo + I1Ii111
 def do_rloc_sets_match ( self , rloc_address_set ) :
  if ( len ( self . rloc_set ) != len ( rloc_address_set ) ) : return ( False )
  if 65 - 65: II111iiii . oO0o
  if 9 - 9: I1Ii111 . i11iIiiIii * I11i + o0oOOo0O0Ooo
  if 85 - 85: i11iIiiIii * iII111i
  if 43 - 43: Ii1I + iII111i * I1ii11iIi11i * Ii1I
  if 62 - 62: O0
  for OoooO00OO in self . rloc_set :
   for o0OOooooooOO in rloc_address_set :
    if ( o0OOooooooOO . is_exact_match ( OoooO00OO . rloc ) == False ) : continue
    o0OOooooooOO = None
    break
    if 44 - 44: i1IIi
   if ( o0OOooooooOO == rloc_address_set [ - 1 ] ) : return ( False )
   if 27 - 27: ooOoO0o - Oo0Ooo + i11iIiiIii - oO0o % O0
  return ( True )
  if 68 - 68: iIii1I11I1II1 % Ii1I / I11i
  if 17 - 17: IiII * Oo0Ooo . i11iIiiIii . IiII . Oo0Ooo % IiII
 def get_rloc ( self , rloc ) :
  for OoooO00OO in self . rloc_set :
   IIi = OoooO00OO . rloc
   if ( rloc . is_exact_match ( IIi ) ) : return ( OoooO00OO )
   if 93 - 93: II111iiii - IiII - O0 - i11iIiiIii / OOooOOo
  return ( None )
  if 76 - 76: OOooOOo
  if 31 - 31: OOooOOo + i1IIi / Ii1I / OoOoOO00 % OoO0O00 + Oo0Ooo
 def get_rloc_by_interface ( self , interface ) :
  for OoooO00OO in self . rloc_set :
   if ( OoooO00OO . interface == interface ) : return ( OoooO00OO )
   if 84 - 84: i1IIi / i1IIi * oO0o * i11iIiiIii
  return ( None )
  if 92 - 92: iII111i - Ii1I . iIii1I11I1II1 . iII111i + ooOoO0o % OoOoOO00
  if 38 - 38: OOooOOo . I11i - oO0o
 def add_db ( self ) :
  if ( self . group . is_null ( ) ) :
   lisp_db_for_lookups . add_cache ( self . eid , self )
  else :
   o0o0O0OO0oO = lisp_db_for_lookups . lookup_cache ( self . group , True )
   if ( o0o0O0OO0oO == None ) :
    o0o0O0OO0oO = lisp_mapping ( self . group , self . group , [ ] )
    lisp_db_for_lookups . add_cache ( self . group , o0o0O0OO0oO )
    if 85 - 85: O0 * I1IiiI . Oo0Ooo - IiII
   o0o0O0OO0oO . add_source_entry ( self )
   if 84 - 84: I1Ii111 . iIii1I11I1II1 . O0 * I1ii11iIi11i
   if 59 - 59: i1IIi . o0oOOo0O0Ooo . Oo0Ooo * I1Ii111 + OoooooooOO
   if 11 - 11: I11i * ooOoO0o % iIii1I11I1II1 - O0
 def add_cache ( self , do_ipc = True ) :
  if ( self . group . is_null ( ) ) :
   lisp_map_cache . add_cache ( self . eid , self )
   if ( lisp_program_hardware ) : lisp_program_vxlan_hardware ( self )
  else :
   OoOOO000O0o = lisp_map_cache . lookup_cache ( self . group , True )
   if ( OoOOO000O0o == None ) :
    OoOOO000O0o = lisp_mapping ( self . group , self . group , [ ] )
    OoOOO000O0o . eid . copy_address ( self . group )
    OoOOO000O0o . group . copy_address ( self . group )
    lisp_map_cache . add_cache ( self . group , OoOOO000O0o )
    if 68 - 68: ooOoO0o * OoooooooOO - OoooooooOO
   if ( self . eid . is_null ( ) ) : self . eid . make_default_route ( OoOOO000O0o . group )
   OoOOO000O0o . add_source_entry ( self )
   if 59 - 59: Ii1I / I11i / I1Ii111 + IiII * I1ii11iIi11i
  if ( do_ipc ) : lisp_write_ipc_map_cache ( True , self )
  if 18 - 18: O0
  if 60 - 60: II111iiii % O0 - I1Ii111 / iII111i / I1IiiI
 def delete_cache ( self ) :
  self . delete_rlocs_from_rloc_probe_list ( )
  lisp_write_ipc_map_cache ( False , self )
  if 59 - 59: O0 / iIii1I11I1II1
  if ( self . group . is_null ( ) ) :
   lisp_map_cache . delete_cache ( self . eid )
   if ( lisp_program_hardware ) :
    iiIIiI = self . eid . print_prefix_no_iid ( )
    os . system ( "ip route delete {}" . format ( iiIIiI ) )
    if 56 - 56: ooOoO0o
  else :
   OoOOO000O0o = lisp_map_cache . lookup_cache ( self . group , True )
   if ( OoOOO000O0o == None ) : return
   if 94 - 94: OoOoOO00
   i1Ii1ii11I1II = OoOOO000O0o . lookup_source_cache ( self . eid , True )
   if ( i1Ii1ii11I1II == None ) : return
   if 38 - 38: OoOoOO00 + OoooooooOO
   OoOOO000O0o . source_cache . delete_cache ( self . eid )
   if ( OoOOO000O0o . source_cache . cache_size ( ) == 0 ) :
    lisp_map_cache . delete_cache ( self . group )
    if 89 - 89: OoooooooOO % II111iiii . I1ii11iIi11i + o0oOOo0O0Ooo % I1Ii111 * IiII
    if 89 - 89: OoO0O00
    if 92 - 92: O0 / I11i % O0 + I1Ii111
    if 48 - 48: iIii1I11I1II1 . i11iIiiIii / OoooooooOO . i1IIi . o0oOOo0O0Ooo
 def add_source_entry ( self , source_mc ) :
  if ( self . source_cache == None ) : self . source_cache = lisp_cache ( )
  self . source_cache . add_cache ( source_mc . eid , source_mc )
  if 84 - 84: Ii1I
  if 92 - 92: I11i
 def lookup_source_cache ( self , source , exact ) :
  if ( self . source_cache == None ) : return ( None )
  return ( self . source_cache . lookup_cache ( source , exact ) )
  if 64 - 64: iII111i / iII111i * iII111i % O0 / IiII . I1ii11iIi11i
  if 23 - 23: i1IIi / I1ii11iIi11i + o0oOOo0O0Ooo
 def dynamic_eid_configured ( self ) :
  return ( self . dynamic_eids != None )
  if 82 - 82: O0 * ooOoO0o * iIii1I11I1II1 . i1IIi
  if 47 - 47: I11i * I11i . OoOoOO00
 def star_secondary_iid ( self , prefix ) :
  if ( self . secondary_iid == None ) : return ( prefix )
  OO0OO000 = "," + str ( self . secondary_iid )
  return ( prefix . replace ( OO0OO000 , OO0OO000 + "*" ) )
  if 68 - 68: OoooooooOO + OoOoOO00 + i11iIiiIii
  if 89 - 89: Oo0Ooo + Ii1I * O0 - I1Ii111
 def increment_decap_stats ( self , packet ) :
  Ii1 = packet . udp_dport
  if ( Ii1 == LISP_DATA_PORT ) :
   o0OOooooooOO = self . get_rloc ( packet . outer_dest )
  else :
   if 33 - 33: iIii1I11I1II1 . I11i
   if 63 - 63: oO0o - iII111i
   if 13 - 13: I1Ii111 / i1IIi % OoooooooOO / I11i
   if 66 - 66: I1Ii111 % o0oOOo0O0Ooo . iII111i . ooOoO0o + OOooOOo * II111iiii
   for o0OOooooooOO in self . rloc_set :
    if ( o0OOooooooOO . translated_port != 0 ) : break
    if 33 - 33: oO0o
    if 64 - 64: OoO0O00 % Oo0Ooo % I11i . iII111i % I1IiiI
  if ( o0OOooooooOO != None ) : o0OOooooooOO . stats . increment ( len ( packet . packet ) )
  self . stats . increment ( len ( packet . packet ) )
  if 50 - 50: i1IIi + ooOoO0o - iIii1I11I1II1
  if 45 - 45: OoooooooOO / o0oOOo0O0Ooo / iII111i
 def rtrs_in_rloc_set ( self ) :
  for o0OOooooooOO in self . rloc_set :
   if ( o0OOooooooOO . is_rtr ( ) ) : return ( True )
   if 72 - 72: I1Ii111
  return ( False )
  if 94 - 94: ooOoO0o . IiII - Ii1I + I1ii11iIi11i / ooOoO0o
  if 10 - 10: ooOoO0o . OOooOOo * O0 % II111iiii
  if 12 - 12: oO0o + I1IiiI * Oo0Ooo - iII111i
class lisp_dynamic_eid ( ) :
 def __init__ ( self ) :
  self . dynamic_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . uptime = lisp_get_timestamp ( )
  self . interface = None
  self . last_packet = None
  self . timeout = LISP_DEFAULT_DYN_EID_TIMEOUT
  if 88 - 88: OOooOOo . OoO0O00
  if 86 - 86: OoOoOO00 . o0oOOo0O0Ooo / ooOoO0o * I1IiiI . OoO0O00 / I1Ii111
 def get_timeout ( self , interface ) :
  try :
   I1OOoO0OoOOo0 = lisp_myinterfaces [ interface ]
   self . timeout = I1OOoO0OoOOo0 . dynamic_eid_timeout
  except :
   self . timeout = LISP_DEFAULT_DYN_EID_TIMEOUT
   if 97 - 97: IiII - iII111i
   if 37 - 37: i1IIi * I1Ii111 / I11i * II111iiii + OoooooooOO . OoO0O00
   if 22 - 22: OoOoOO00 + OoooooooOO - I1Ii111
   if 82 - 82: Ii1I % I1Ii111 / ooOoO0o
class lisp_group_mapping ( ) :
 def __init__ ( self , group_name , ms_name , group_prefix , sources , rle_addr ) :
  self . group_name = group_name
  self . group_prefix = group_prefix
  self . use_ms_name = ms_name
  self . sources = sources
  self . rle_address = rle_addr
  if 86 - 86: II111iiii - iIii1I11I1II1 + oO0o + I1IiiI
  if 29 - 29: Ii1I % OoooooooOO * II111iiii
 def add_group ( self ) :
  lisp_group_mapping_list [ self . group_name ] = self
  if 88 - 88: I1Ii111 + I11i + I1Ii111 % OoO0O00 / I1ii11iIi11i - I11i
  if 15 - 15: Oo0Ooo - i1IIi
  if 87 - 87: O0 . o0oOOo0O0Ooo % OOooOOo / I11i - I1Ii111 % i11iIiiIii
  if 3 - 3: oO0o + iII111i + OOooOOo
  if 54 - 54: i11iIiiIii + OoO0O00 - IiII - iII111i / I11i
  if 85 - 85: OOooOOo * OOooOOo * I1Ii111 - ooOoO0o . O0 % iII111i
  if 5 - 5: i1IIi * iII111i . o0oOOo0O0Ooo - I1ii11iIi11i
  if 84 - 84: i1IIi
  if 17 - 17: IiII + iII111i * OoO0O00 / iII111i
  if 67 - 67: i1IIi * IiII . OoOoOO00 % iIii1I11I1II1 - iIii1I11I1II1 * I1ii11iIi11i
def lisp_is_group_more_specific ( group_str , group_mapping ) :
 OO0OO000 = group_mapping . group_prefix . instance_id
 ooI1111 = group_mapping . group_prefix . mask_len
 IiI1111i1i11I = lisp_address ( LISP_AFI_IPV4 , group_str , 32 , OO0OO000 )
 if ( IiI1111i1i11I . is_more_specific ( group_mapping . group_prefix ) ) : return ( ooI1111 )
 return ( - 1 )
 if 96 - 96: iII111i / i11iIiiIii / oO0o + Oo0Ooo
 if 65 - 65: OoOoOO00
 if 87 - 87: I11i % i1IIi + i11iIiiIii * II111iiii
 if 58 - 58: OoO0O00 * I1IiiI - II111iiii / Ii1I - I1IiiI % OoooooooOO
 if 33 - 33: IiII / i1IIi + I1Ii111
 if 5 - 5: O0 / iII111i % II111iiii . Oo0Ooo - I11i
 if 84 - 84: oO0o * iII111i % i11iIiiIii - O0 . iIii1I11I1II1 - OoOoOO00
def lisp_lookup_group ( group ) :
 iII11I1 = None
 for oOoOOOo in lisp_group_mapping_list . values ( ) :
  ooI1111 = lisp_is_group_more_specific ( group , oOoOOOo )
  if ( ooI1111 == - 1 ) : continue
  if ( iII11I1 == None or ooI1111 > iII11I1 . group_prefix . mask_len ) : iII11I1 = oOoOOOo
  if 5 - 5: II111iiii
 return ( iII11I1 )
 if 70 - 70: Ii1I + Oo0Ooo + Oo0Ooo / i1IIi
 if 33 - 33: OoooooooOO + o0oOOo0O0Ooo . OoOoOO00 % Oo0Ooo * O0
lisp_site_flags = {
 "P" : "ETR is {}Requesting Map-Server to Proxy Map-Reply" ,
 "S" : "ETR is {}LISP-SEC capable" ,
 "I" : "xTR-ID and site-ID are {}included in Map-Register" ,
 "T" : "Use Map-Register TTL field to timeout registration is {}set" ,
 "R" : "Merging registrations are {}requested" ,
 "M" : "ETR is {}a LISP Mobile-Node" ,
 "N" : "ETR is {}requesting Map-Notify messages from Map-Server"
 }
if 49 - 49: I1ii11iIi11i * I1Ii111 - OoooooooOO . i1IIi . I1ii11iIi11i
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
  if 37 - 37: IiII - oO0o
  if 92 - 92: I1IiiI
  if 51 - 51: OoO0O00 + Oo0Ooo - OOooOOo + I1ii11iIi11i
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
  if 32 - 32: I1ii11iIi11i % OoOoOO00 + Oo0Ooo
  if 92 - 92: II111iiii . O0 . iIii1I11I1II1 % IiII - i11iIiiIii
 def print_eid_tuple ( self ) :
  return ( lisp_print_eid_tuple ( self . eid , self . group ) )
  if 9 - 9: OoO0O00
  if 60 - 60: O0 / OoOoOO00 % i11iIiiIii % II111iiii / OoooooooOO
 def print_flags ( self , html ) :
  if ( html == False ) :
   II = "{}-{}-{}-{}-{}-{}-{}" . format ( "P" if self . proxy_reply_requested else "p" ,
   # ooOoO0o . OOooOOo * Oo0Ooo - OoOoOO00
 "S" if self . lisp_sec_present else "s" ,
 "I" if self . xtr_id_present else "i" ,
 "T" if self . use_register_ttl_requested else "t" ,
 "R" if self . merge_register_requested else "r" ,
 "M" if self . mobile_node_requested else "m" ,
 "N" if self . map_notify_requested else "n" )
  else :
   Ii = self . print_flags ( False )
   Ii = Ii . split ( "-" )
   II = ""
   for o00iiIIIiIiI1 in Ii :
    o00oO00o0Ooo = lisp_site_flags [ o00iiIIIiIiI1 . upper ( ) ]
    o00oO00o0Ooo = o00oO00o0Ooo . format ( "" if o00iiIIIiIiI1 . isupper ( ) else "not " )
    II += lisp_span ( o00iiIIIiIiI1 , o00oO00o0Ooo )
    if ( o00iiIIIiIiI1 . lower ( ) != "n" ) : II += "-"
    if 97 - 97: II111iiii * o0oOOo0O0Ooo
    if 13 - 13: o0oOOo0O0Ooo . II111iiii
  return ( II )
  if 76 - 76: II111iiii + I1Ii111 . OoooooooOO / IiII % i11iIiiIii
  if 87 - 87: Ii1I / OoOoOO00 / OOooOOo
 def copy_state_to_parent ( self , child ) :
  self . xtr_id = child . xtr_id
  self . site_id = child . site_id
  self . first_registered = child . first_registered
  self . last_registered = child . last_registered
  self . last_registerer = child . last_registerer
  self . register_ttl = child . register_ttl
  if ( self . registered == False ) :
   self . first_registered = lisp_get_timestamp ( )
   if 11 - 11: o0oOOo0O0Ooo * OoO0O00 . o0oOOo0O0Ooo - I1IiiI / IiII - OOooOOo
  self . auth_sha1_or_sha2 = child . auth_sha1_or_sha2
  self . registered = child . registered
  self . proxy_reply_requested = child . proxy_reply_requested
  self . lisp_sec_present = child . lisp_sec_present
  self . xtr_id_present = child . xtr_id_present
  self . use_register_ttl_requested = child . use_register_ttl_requested
  self . merge_register_requested = child . merge_register_requested
  self . mobile_node_requested = child . mobile_node_requested
  self . map_notify_requested = child . map_notify_requested
  if 19 - 19: i1IIi + IiII . OoO0O00 / O0 - I1Ii111 - Oo0Ooo
  if 24 - 24: iII111i + i1IIi
 def build_sort_key ( self ) :
  iII1ii1 = lisp_cache ( )
  o0ooOo00 , i1iI11iI = iII1ii1 . build_key ( self . eid )
  oOoOooooO = ""
  if ( self . group . is_null ( ) == False ) :
   oO , oOoOooooO = iII1ii1 . build_key ( self . group )
   oOoOooooO = "-" + oOoOooooO [ 0 : 12 ] + "-" + str ( oO ) + "-" + oOoOooooO [ 12 : : ]
   if 76 - 76: iII111i - II111iiii % Oo0Ooo . I1Ii111
  i1iI11iI = i1iI11iI [ 0 : 12 ] + "-" + str ( o0ooOo00 ) + "-" + i1iI11iI [ 12 : : ] + oOoOooooO
  del ( iII1ii1 )
  return ( i1iI11iI )
  if 64 - 64: OoO0O00 - OoO0O00
  if 93 - 93: Oo0Ooo . O0
 def merge_in_site_eid ( self , child ) :
  o0OoOoOooo00o = False
  if ( self . group . is_null ( ) ) :
   self . merge_rlocs_in_site_eid ( )
  else :
   o0OoOoOooo00o = self . merge_rles_in_site_eid ( )
   if 70 - 70: I1ii11iIi11i % ooOoO0o . o0oOOo0O0Ooo . I1Ii111 + ooOoO0o
   if 92 - 92: i11iIiiIii
   if 45 - 45: oO0o * O0 % I1ii11iIi11i
   if 41 - 41: i11iIiiIii + IiII * o0oOOo0O0Ooo * I1Ii111 - iII111i
   if 94 - 94: o0oOOo0O0Ooo . o0oOOo0O0Ooo / OOooOOo
   if 50 - 50: i11iIiiIii - II111iiii * OoooooooOO + II111iiii - ooOoO0o
  if ( child != None ) :
   self . copy_state_to_parent ( child )
   self . map_registers_received += 1
   if 52 - 52: i1IIi + i1IIi * i1IIi / OoOoOO00
  return ( o0OoOoOooo00o )
  if 98 - 98: iII111i . i1IIi + o0oOOo0O0Ooo * OoooooooOO - i11iIiiIii
  if 21 - 21: i11iIiiIii . oO0o * o0oOOo0O0Ooo + Oo0Ooo * OoOoOO00 * o0oOOo0O0Ooo
 def copy_rloc_records ( self ) :
  iIIi11 = [ ]
  for OoooO00OO in self . registered_rlocs :
   iIIi11 . append ( copy . deepcopy ( OoooO00OO ) )
   if 85 - 85: O0 * Ii1I . I1IiiI . OoOoOO00 + iII111i % oO0o
  return ( iIIi11 )
  if 70 - 70: o0oOOo0O0Ooo
  if 6 - 6: Oo0Ooo - iIii1I11I1II1 / OOooOOo * iII111i + I1ii11iIi11i * I1Ii111
 def merge_rlocs_in_site_eid ( self ) :
  self . registered_rlocs = [ ]
  for iIi1iIIiiIi in self . individual_registrations . values ( ) :
   if ( self . site_id != iIi1iIIiiIi . site_id ) : continue
   if ( iIi1iIIiiIi . registered == False ) : continue
   self . registered_rlocs += iIi1iIIiiIi . copy_rloc_records ( )
   if 27 - 27: I11i + OoOoOO00 . I1ii11iIi11i
   if 8 - 8: OoooooooOO / I1IiiI + i1IIi
   if 21 - 21: iII111i / o0oOOo0O0Ooo
   if 61 - 61: iII111i . I1Ii111 % OoooooooOO / I1Ii111
   if 8 - 8: OoOoOO00
   if 80 - 80: IiII + I1ii11iIi11i + ooOoO0o
  iIIi11 = [ ]
  for OoooO00OO in self . registered_rlocs :
   if ( OoooO00OO . rloc . is_null ( ) or len ( iIIi11 ) == 0 ) :
    iIIi11 . append ( OoooO00OO )
    continue
    if 48 - 48: O0 / I1IiiI % II111iiii
   for I1i1 in iIIi11 :
    if ( I1i1 . rloc . is_null ( ) ) : continue
    if ( OoooO00OO . rloc . is_exact_match ( I1i1 . rloc ) ) : break
    if 64 - 64: I11i
   if ( I1i1 == iIIi11 [ - 1 ] ) : iIIi11 . append ( OoooO00OO )
   if 26 - 26: ooOoO0o * I11i + OOooOOo * i1IIi
  self . registered_rlocs = iIIi11
  if 48 - 48: o0oOOo0O0Ooo - I1ii11iIi11i / iII111i
  if 63 - 63: O0 - IiII . OOooOOo % IiII . I1IiiI / oO0o
  if 79 - 79: OoOoOO00
  if 88 - 88: oO0o * o0oOOo0O0Ooo
  if ( len ( self . registered_rlocs ) == 0 ) : self . registered = False
  return
  if 5 - 5: I11i - I1Ii111 * I11i - II111iiii + OOooOOo + II111iiii
  if 91 - 91: i1IIi + Oo0Ooo - I1ii11iIi11i + I1ii11iIi11i * O0 / O0
 def merge_rles_in_site_eid ( self ) :
  if 78 - 78: OoooooooOO
  if 8 - 8: Oo0Ooo - Oo0Ooo % O0 - Ii1I / o0oOOo0O0Ooo % Oo0Ooo
  if 51 - 51: iIii1I11I1II1 / iIii1I11I1II1 * I1ii11iIi11i / I11i
  if 18 - 18: Ii1I - i11iIiiIii + OoO0O00 . O0 - iII111i
  IiI1Ii1II = { }
  for OoooO00OO in self . registered_rlocs :
   if ( OoooO00OO . rle == None ) : continue
   for I11iI in OoooO00OO . rle . rle_nodes :
    ooooO0O = I11iI . address . print_address_no_iid ( )
    IiI1Ii1II [ ooooO0O ] = I11iI . address
    if 28 - 28: iII111i / OOooOOo + ooOoO0o
   break
   if 45 - 45: OoooooooOO % I1IiiI . iII111i * Oo0Ooo + ooOoO0o - Oo0Ooo
   if 57 - 57: ooOoO0o * I1IiiI % OOooOOo
   if 10 - 10: Oo0Ooo % Ii1I . OoO0O00
   if 90 - 90: I1Ii111 . OoooooooOO * ooOoO0o
   if 82 - 82: ooOoO0o
  self . merge_rlocs_in_site_eid ( )
  if 80 - 80: I1Ii111 / I11i - Oo0Ooo / IiII % O0
  if 67 - 67: i11iIiiIii / I11i - iII111i - OOooOOo . II111iiii
  if 16 - 16: Ii1I * iIii1I11I1II1 + i11iIiiIii - OoOoOO00 - o0oOOo0O0Ooo
  if 60 - 60: O0 - iIii1I11I1II1
  if 56 - 56: OOooOOo * o0oOOo0O0Ooo - O0
  if 45 - 45: OOooOOo - OoO0O00
  if 49 - 49: OoOoOO00 / o0oOOo0O0Ooo % OoO0O00
  if 50 - 50: iIii1I11I1II1 - OoooooooOO + I1ii11iIi11i / Oo0Ooo * OOooOOo
  Ii11i1I1I1I = [ ]
  for OoooO00OO in self . registered_rlocs :
   if ( self . registered_rlocs . index ( OoooO00OO ) == 0 ) :
    Ii11i1I1I1I . append ( OoooO00OO )
    continue
    if 9 - 9: O0 - Ii1I % iII111i + OoOoOO00
   if ( OoooO00OO . rle == None ) : Ii11i1I1I1I . append ( OoooO00OO )
   if 28 - 28: I1IiiI - oO0o % OoO0O00 + OOooOOo + Oo0Ooo % I1IiiI
  self . registered_rlocs = Ii11i1I1I1I
  if 3 - 3: ooOoO0o * Ii1I
  if 29 - 29: OoooooooOO + OOooOOo
  if 68 - 68: O0 + IiII / iII111i - OoOoOO00
  if 5 - 5: I1IiiI * OoooooooOO - II111iiii
  if 64 - 64: i1IIi
  if 77 - 77: OOooOOo - i1IIi / II111iiii . I1Ii111 + O0
  if 1 - 1: OoooooooOO % iIii1I11I1II1 * I1ii11iIi11i
  O000o0 = lisp_rle ( "" )
  i11iIiiI1i1i1 = { }
  ooOO0OOO = None
  for iIi1iIIiiIi in self . individual_registrations . values ( ) :
   if ( iIi1iIIiiIi . registered == False ) : continue
   oOoOo0 = iIi1iIIiiIi . registered_rlocs [ 0 ] . rle
   if ( oOoOo0 == None ) : continue
   if 50 - 50: I1IiiI / Ii1I / Ii1I + O0 % I11i - i1IIi
   ooOO0OOO = iIi1iIIiiIi . registered_rlocs [ 0 ] . rloc_name
   for OooIIIii in oOoOo0 . rle_nodes :
    ooooO0O = OooIIIii . address . print_address_no_iid ( )
    if ( i11iIiiI1i1i1 . has_key ( ooooO0O ) ) : break
    if 45 - 45: I1ii11iIi11i . I1Ii111 . i1IIi * OOooOOo
    I11iI = lisp_rle_node ( )
    I11iI . address . copy_address ( OooIIIii . address )
    I11iI . level = OooIIIii . level
    I11iI . rloc_name = ooOO0OOO
    O000o0 . rle_nodes . append ( I11iI )
    i11iIiiI1i1i1 [ ooooO0O ] = OooIIIii . address
    if 53 - 53: Ii1I . i11iIiiIii + o0oOOo0O0Ooo % I11i - I1ii11iIi11i * I1ii11iIi11i
    if 87 - 87: I1Ii111 % i11iIiiIii + O0
    if 67 - 67: OoooooooOO / i1IIi / ooOoO0o . i1IIi - i11iIiiIii . i1IIi
    if 41 - 41: i11iIiiIii / ooOoO0o - Ii1I + I11i
    if 15 - 15: I1ii11iIi11i
    if 22 - 22: iIii1I11I1II1 - i1IIi - i11iIiiIii / I1IiiI + o0oOOo0O0Ooo
  if ( len ( O000o0 . rle_nodes ) == 0 ) : O000o0 = None
  if ( len ( self . registered_rlocs ) != 0 ) :
   self . registered_rlocs [ 0 ] . rle = O000o0
   if ( ooOO0OOO ) : self . registered_rlocs [ 0 ] . rloc_name = None
   if 56 - 56: I1IiiI . ooOoO0o
   if 35 - 35: iIii1I11I1II1 % Oo0Ooo + o0oOOo0O0Ooo * o0oOOo0O0Ooo % ooOoO0o
   if 10 - 10: I1ii11iIi11i / II111iiii % II111iiii - OoooooooOO * o0oOOo0O0Ooo / ooOoO0o
   if 26 - 26: OoO0O00 . O0 * iII111i % OoOoOO00 % iIii1I11I1II1
   if 37 - 37: iII111i - ooOoO0o * Ii1I + II111iiii * i11iIiiIii
  if ( IiI1Ii1II . keys ( ) == i11iIiiI1i1i1 . keys ( ) ) : return ( False )
  if 8 - 8: OoooooooOO % I11i - iII111i * OOooOOo . O0
  lprint ( "{} {} from {} to {}" . format ( green ( self . print_eid_tuple ( ) , False ) , bold ( "RLE change" , False ) ,
  # i11iIiiIii % Oo0Ooo * oO0o
 IiI1Ii1II . keys ( ) , i11iIiiI1i1i1 . keys ( ) ) )
  if 73 - 73: Oo0Ooo / OoooooooOO / i11iIiiIii
  return ( True )
  if 5 - 5: O0 % i11iIiiIii
  if 60 - 60: I1ii11iIi11i / I11i
 def add_cache ( self ) :
  if ( self . group . is_null ( ) ) :
   lisp_sites_by_eid . add_cache ( self . eid , self )
  else :
   OoOo0OOoOOO00 = lisp_sites_by_eid . lookup_cache ( self . group , True )
   if ( OoOo0OOoOOO00 == None ) :
    OoOo0OOoOOO00 = lisp_site_eid ( self . site )
    OoOo0OOoOOO00 . eid . copy_address ( self . group )
    OoOo0OOoOOO00 . group . copy_address ( self . group )
    lisp_sites_by_eid . add_cache ( self . group , OoOo0OOoOOO00 )
    if 100 - 100: I1IiiI
    if 44 - 44: iIii1I11I1II1 + Oo0Ooo - I1Ii111 . OoooooooOO
    if 28 - 28: Ii1I + OOooOOo % IiII . i11iIiiIii - I1IiiI * Oo0Ooo
    if 2 - 2: I11i * I1ii11iIi11i + O0
    if 44 - 44: iIii1I11I1II1 / II111iiii - ooOoO0o
    OoOo0OOoOOO00 . parent_for_more_specifics = self . parent_for_more_specifics
    if 10 - 10: OOooOOo
   if ( self . eid . is_null ( ) ) : self . eid . make_default_route ( OoOo0OOoOOO00 . group )
   OoOo0OOoOOO00 . add_source_entry ( self )
   if 78 - 78: OOooOOo * I1ii11iIi11i % i11iIiiIii % o0oOOo0O0Ooo . I1ii11iIi11i / OoooooooOO
   if 12 - 12: iIii1I11I1II1 % OoO0O00 + OOooOOo * iIii1I11I1II1 - iIii1I11I1II1
   if 70 - 70: OoO0O00 % i11iIiiIii * IiII . I11i * Oo0Ooo
 def delete_cache ( self ) :
  if ( self . group . is_null ( ) ) :
   lisp_sites_by_eid . delete_cache ( self . eid )
  else :
   OoOo0OOoOOO00 = lisp_sites_by_eid . lookup_cache ( self . group , True )
   if ( OoOo0OOoOOO00 == None ) : return
   if 17 - 17: i1IIi
   iIi1iIIiiIi = OoOo0OOoOOO00 . lookup_source_cache ( self . eid , True )
   if ( iIi1iIIiiIi == None ) : return
   if 29 - 29: OOooOOo % OoO0O00 + oO0o + o0oOOo0O0Ooo . iII111i
   if ( OoOo0OOoOOO00 . source_cache == None ) : return
   if 14 - 14: i1IIi + OoOoOO00 * oO0o - II111iiii + IiII + OoOoOO00
   OoOo0OOoOOO00 . source_cache . delete_cache ( self . eid )
   if ( OoOo0OOoOOO00 . source_cache . cache_size ( ) == 0 ) :
    lisp_sites_by_eid . delete_cache ( self . group )
    if 42 - 42: Oo0Ooo + iII111i * ooOoO0o
    if 72 - 72: iIii1I11I1II1 % I1Ii111
    if 77 - 77: I1Ii111 * I1IiiI / iIii1I11I1II1 . II111iiii * Oo0Ooo
    if 71 - 71: ooOoO0o / iIii1I11I1II1 % O0 / I1ii11iIi11i . I1Ii111 / i11iIiiIii
 def add_source_entry ( self , source_se ) :
  if ( self . source_cache == None ) : self . source_cache = lisp_cache ( )
  self . source_cache . add_cache ( source_se . eid , source_se )
  if 6 - 6: oO0o . OoO0O00 - II111iiii . I1IiiI - o0oOOo0O0Ooo - i1IIi
  if 42 - 42: Ii1I + i11iIiiIii
 def lookup_source_cache ( self , source , exact ) :
  if ( self . source_cache == None ) : return ( None )
  return ( self . source_cache . lookup_cache ( source , exact ) )
  if 46 - 46: O0 % OoOoOO00 - I1Ii111 . I1IiiI
  if 66 - 66: II111iiii * iIii1I11I1II1 * ooOoO0o * I11i . II111iiii - ooOoO0o
 def is_star_g ( self ) :
  if ( self . group . is_null ( ) ) : return ( False )
  return ( self . eid . is_exact_match ( self . group ) )
  if 15 - 15: I1ii11iIi11i - i11iIiiIii - Ii1I / Ii1I . iII111i
  if 36 - 36: oO0o + Oo0Ooo * I1Ii111 % OOooOOo . Oo0Ooo . I1IiiI
 def eid_record_matches ( self , eid_record ) :
  if ( self . eid . is_exact_match ( eid_record . eid ) == False ) : return ( False )
  if ( eid_record . group . is_null ( ) ) : return ( True )
  return ( eid_record . group . is_exact_match ( self . group ) )
  if 81 - 81: o0oOOo0O0Ooo . OoOoOO00 . i11iIiiIii
  if 13 - 13: i1IIi
 def inherit_from_ams_parent ( self ) :
  O000000oO0O0O = self . parent_for_more_specifics
  if ( O000000oO0O0O == None ) : return
  self . force_proxy_reply = O000000oO0O0O . force_proxy_reply
  self . force_nat_proxy_reply = O000000oO0O0O . force_nat_proxy_reply
  self . force_ttl = O000000oO0O0O . force_ttl
  self . pitr_proxy_reply_drop = O000000oO0O0O . pitr_proxy_reply_drop
  self . proxy_reply_action = O000000oO0O0O . proxy_reply_action
  self . echo_nonce_capable = O000000oO0O0O . echo_nonce_capable
  self . policy = O000000oO0O0O . policy
  self . require_signature = O000000oO0O0O . require_signature
  if 70 - 70: O0 / II111iiii
  if 98 - 98: OoOoOO00 - O0 . O0 + ooOoO0o * iIii1I11I1II1
 def rtrs_in_rloc_set ( self ) :
  for OoooO00OO in self . registered_rlocs :
   if ( OoooO00OO . is_rtr ( ) ) : return ( True )
   if 7 - 7: IiII * OoOoOO00 + iIii1I11I1II1 / OoOoOO00 + Oo0Ooo / o0oOOo0O0Ooo
  return ( False )
  if 77 - 77: i1IIi . I1IiiI
  if 59 - 59: O0 + OoooooooOO - i1IIi
 def is_rtr_in_rloc_set ( self , rtr_rloc ) :
  for OoooO00OO in self . registered_rlocs :
   if ( OoooO00OO . rloc . is_exact_match ( rtr_rloc ) == False ) : continue
   if ( OoooO00OO . is_rtr ( ) ) : return ( True )
   if 87 - 87: IiII * OoooooooOO / Oo0Ooo % iIii1I11I1II1 % oO0o
  return ( False )
  if 97 - 97: ooOoO0o % i1IIi . IiII / Oo0Ooo . I1Ii111 . OoO0O00
  if 12 - 12: I1IiiI
 def is_rloc_in_rloc_set ( self , rloc ) :
  for OoooO00OO in self . registered_rlocs :
   if ( OoooO00OO . rle ) :
    for O000o0 in OoooO00OO . rle . rle_nodes :
     if ( O000o0 . address . is_exact_match ( rloc ) ) : return ( True )
     if 99 - 99: II111iiii - OoOoOO00
     if 22 - 22: i11iIiiIii * II111iiii
   if ( OoooO00OO . rloc . is_exact_match ( rloc ) ) : return ( True )
   if 11 - 11: Oo0Ooo % i1IIi
  return ( False )
  if 70 - 70: II111iiii * Oo0Ooo * OOooOOo - I1IiiI + iIii1I11I1II1 + ooOoO0o
  if 27 - 27: I1ii11iIi11i - I1Ii111 * O0 % ooOoO0o / I1IiiI
 def do_rloc_sets_match ( self , prev_rloc_set ) :
  if ( len ( self . registered_rlocs ) != len ( prev_rloc_set ) ) : return ( False )
  if 53 - 53: i11iIiiIii * i11iIiiIii % O0 % IiII
  for OoooO00OO in prev_rloc_set :
   iiiiiIIiii = OoooO00OO . rloc
   if ( self . is_rloc_in_rloc_set ( iiiiiIIiii ) == False ) : return ( False )
   if 57 - 57: I1IiiI % i1IIi * OoO0O00 + I1Ii111 . I11i % I11i
  return ( True )
  if 69 - 69: I1ii11iIi11i / OoOoOO00 + iIii1I11I1II1
  if 8 - 8: OoooooooOO
  if 72 - 72: OoooooooOO % I1ii11iIi11i - OoO0O00 . OoooooooOO
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
   if 83 - 83: o0oOOo0O0Ooo * Ii1I - Oo0Ooo * iII111i - i11iIiiIii
  self . last_used = 0
  self . last_reply = 0
  self . last_nonce = 0
  self . map_requests_sent = 0
  self . neg_map_replies_received = 0
  self . total_rtt = 0
  if 6 - 6: I1IiiI + i11iIiiIii + O0 / i1IIi
  if 50 - 50: iII111i . II111iiii % I1Ii111 % I1IiiI / o0oOOo0O0Ooo . I1IiiI
 def resolve_dns_name ( self ) :
  if ( self . dns_name == None ) : return
  if ( self . last_dns_resolve and
 time . time ( ) - self . last_dns_resolve < 30 ) : return
  if 76 - 76: OOooOOo % iII111i
  try :
   iII1I11 = socket . gethostbyname_ex ( self . dns_name )
   self . last_dns_resolve = lisp_get_timestamp ( )
   ooOOoO = iII1I11 [ 2 ]
  except :
   return
   if 60 - 60: OOooOOo + OOooOOo - Ii1I / iII111i
   if 42 - 42: IiII % oO0o - o0oOOo0O0Ooo * iII111i - Oo0Ooo
   if 19 - 19: I1IiiI - iII111i - oO0o / II111iiii
   if 98 - 98: IiII * OoOoOO00
   if 13 - 13: O0 + oO0o - iIii1I11I1II1 - Oo0Ooo % I1IiiI
   if 45 - 45: O0
  if ( len ( ooOOoO ) <= self . a_record_index ) :
   self . delete_mr ( )
   return
   if 55 - 55: i11iIiiIii * Ii1I % OOooOOo + ooOoO0o - I1ii11iIi11i . Oo0Ooo
   if 48 - 48: o0oOOo0O0Ooo
  ooooO0O = ooOOoO [ self . a_record_index ]
  if ( ooooO0O != self . map_resolver . print_address_no_iid ( ) ) :
   self . delete_mr ( )
   self . map_resolver . store_address ( ooooO0O )
   self . insert_mr ( )
   if 55 - 55: OOooOOo - OoooooooOO * iIii1I11I1II1 + iII111i % II111iiii
   if 33 - 33: I1Ii111 * oO0o * OoooooooOO + OOooOOo - I1IiiI + I1Ii111
   if 92 - 92: ooOoO0o * I11i % iIii1I11I1II1 + Ii1I - OoOoOO00
   if 31 - 31: OoooooooOO
   if 87 - 87: OoooooooOO - Ii1I . I11i / I1Ii111 . i1IIi
   if 86 - 86: i1IIi . oO0o % OOooOOo
  if ( lisp_is_decent_dns_suffix ( self . dns_name ) == False ) : return
  if ( self . a_record_index != 0 ) : return
  if 99 - 99: oO0o / I1Ii111 * oO0o * I11i
  for ooooO0O in ooOOoO [ 1 : : ] :
   iiiii1ii1 = lisp_address ( LISP_AFI_NONE , ooooO0O , 0 , 0 )
   OOO0o0o = lisp_get_map_resolver ( iiiii1ii1 , None )
   if ( OOO0o0o != None and OOO0o0o . a_record_index == ooOOoO . index ( ooooO0O ) ) :
    continue
    if 38 - 38: o0oOOo0O0Ooo + OoOoOO00
   OOO0o0o = lisp_mr ( ooooO0O , None , None )
   OOO0o0o . a_record_index = ooOOoO . index ( ooooO0O )
   OOO0o0o . dns_name = self . dns_name
   OOO0o0o . last_dns_resolve = lisp_get_timestamp ( )
   if 24 - 24: Ii1I - OOooOOo - o0oOOo0O0Ooo - I1Ii111 / OoooooooOO
   if 17 - 17: OoO0O00
   if 79 - 79: Ii1I - II111iiii
   if 57 - 57: II111iiii / OoooooooOO
   if 4 - 4: I11i * OoOoOO00
  IiII1IIiI1i = [ ]
  for OOO0o0o in lisp_map_resolvers_list . values ( ) :
   if ( self . dns_name != OOO0o0o . dns_name ) : continue
   iiiii1ii1 = OOO0o0o . map_resolver . print_address_no_iid ( )
   if ( iiiii1ii1 in ooOOoO ) : continue
   IiII1IIiI1i . append ( OOO0o0o )
   if 3 - 3: iIii1I11I1II1 % oO0o . oO0o + IiII
  for OOO0o0o in IiII1IIiI1i : OOO0o0o . delete_mr ( )
  if 36 - 36: OoOoOO00 * iIii1I11I1II1 + oO0o * IiII . IiII . OOooOOo
  if 64 - 64: I1ii11iIi11i / OoOoOO00 + O0 % i1IIi - ooOoO0o + o0oOOo0O0Ooo
 def insert_mr ( self ) :
  i1iI11iI = self . mr_name + self . map_resolver . print_address ( )
  lisp_map_resolvers_list [ i1iI11iI ] = self
  if 67 - 67: Oo0Ooo
  if 52 - 52: I1IiiI % I1Ii111 - i1IIi . o0oOOo0O0Ooo % I1ii11iIi11i
 def delete_mr ( self ) :
  i1iI11iI = self . mr_name + self . map_resolver . print_address ( )
  if ( lisp_map_resolvers_list . has_key ( i1iI11iI ) == False ) : return
  lisp_map_resolvers_list . pop ( i1iI11iI )
  if 34 - 34: o0oOOo0O0Ooo / OoOoOO00
  if 74 - 74: IiII + i1IIi . II111iiii
  if 1 - 1: Ii1I - o0oOOo0O0Ooo / i11iIiiIii
class lisp_ddt_root ( ) :
 def __init__ ( self ) :
  self . root_address = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . public_key = ""
  self . priority = 0
  self . weight = 0
  if 24 - 24: O0
  if 59 - 59: OoO0O00 % iII111i + oO0o * II111iiii . OOooOOo
  if 26 - 26: OOooOOo % OoooooooOO . Ii1I / iIii1I11I1II1 * I1IiiI
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
  if 85 - 85: IiII / Ii1I - I1ii11iIi11i * OOooOOo
  if 19 - 19: I1ii11iIi11i
 def print_referral ( self , eid_indent , referral_indent ) :
  I11IiiIII1i1 = lisp_print_elapsed ( self . uptime )
  Ii1i1Ii1Ii1i = lisp_print_future ( self . expires )
  lprint ( "{}Referral EID {}, uptime/expires {}/{}, {} referrals:" . format ( eid_indent , green ( self . eid . print_prefix ( ) , False ) , I11IiiIII1i1 ,
  # Oo0Ooo % OOooOOo + O0 - OoO0O00 % I11i * O0
 Ii1i1Ii1Ii1i , len ( self . referral_set ) ) )
  if 42 - 42: O0
  for ii1I111ii in self . referral_set . values ( ) :
   ii1I111ii . print_ref_node ( referral_indent )
   if 55 - 55: i11iIiiIii % OOooOOo
   if 10 - 10: OoOoOO00 / i11iIiiIii
   if 21 - 21: Ii1I - i1IIi / I11i + IiII
 def print_referral_type ( self ) :
  if ( self . eid . afi == LISP_AFI_ULTIMATE_ROOT ) : return ( "root" )
  if ( self . referral_type == LISP_DDT_ACTION_NULL ) :
   return ( "null-referral" )
   if 44 - 44: OoooooooOO % I11i / O0
  if ( self . referral_type == LISP_DDT_ACTION_SITE_NOT_FOUND ) :
   return ( "no-site-action" )
   if 94 - 94: IiII
  if ( self . referral_type > LISP_DDT_ACTION_MAX ) :
   return ( "invalid-action" )
   if 83 - 83: OoO0O00
  return ( lisp_map_referral_action_string [ self . referral_type ] )
  if 55 - 55: iII111i
  if 37 - 37: oO0o / o0oOOo0O0Ooo + I11i * OoO0O00 * o0oOOo0O0Ooo
 def print_eid_tuple ( self ) :
  return ( lisp_print_eid_tuple ( self . eid , self . group ) )
  if 33 - 33: I1Ii111
  if 97 - 97: Ii1I / iII111i - ooOoO0o + IiII * OoOoOO00 - OOooOOo
 def print_ttl ( self ) :
  I1i = self . referral_ttl
  if ( I1i < 60 ) : return ( str ( I1i ) + " secs" )
  if 43 - 43: oO0o / II111iiii - iII111i / oO0o
  if ( ( I1i % 60 ) == 0 ) :
   I1i = str ( I1i / 60 ) + " mins"
  else :
   I1i = str ( I1i ) + " secs"
   if 98 - 98: OoOoOO00 / OOooOOo
  return ( I1i )
  if 31 - 31: II111iiii % I11i - I11i
  if 17 - 17: iII111i . IiII + OOooOOo % I1Ii111 % i11iIiiIii
 def is_referral_negative ( self ) :
  return ( self . referral_type in ( LISP_DDT_ACTION_MS_NOT_REG , LISP_DDT_ACTION_DELEGATION_HOLE ,
  # I1ii11iIi11i * O0 . i1IIi . oO0o + o0oOOo0O0Ooo . Ii1I
 LISP_DDT_ACTION_NOT_AUTH ) )
  if 90 - 90: OOooOOo - OoOoOO00 % iIii1I11I1II1 . i11iIiiIii / OOooOOo
  if 27 - 27: I1IiiI / Ii1I * iIii1I11I1II1 * iIii1I11I1II1 + ooOoO0o
 def add_cache ( self ) :
  if ( self . group . is_null ( ) ) :
   lisp_referral_cache . add_cache ( self . eid , self )
  else :
   I11i1i = lisp_referral_cache . lookup_cache ( self . group , True )
   if ( I11i1i == None ) :
    I11i1i = lisp_referral ( )
    I11i1i . eid . copy_address ( self . group )
    I11i1i . group . copy_address ( self . group )
    lisp_referral_cache . add_cache ( self . group , I11i1i )
    if 92 - 92: OOooOOo
   if ( self . eid . is_null ( ) ) : self . eid . make_default_route ( I11i1i . group )
   I11i1i . add_source_entry ( self )
   if 34 - 34: I1ii11iIi11i . OOooOOo + OoO0O00 % o0oOOo0O0Ooo * O0 * I1IiiI
   if 9 - 9: IiII / i11iIiiIii . o0oOOo0O0Ooo - OOooOOo % I1Ii111
   if 65 - 65: I1IiiI % OoOoOO00
 def delete_cache ( self ) :
  if ( self . group . is_null ( ) ) :
   lisp_referral_cache . delete_cache ( self . eid )
  else :
   I11i1i = lisp_referral_cache . lookup_cache ( self . group , True )
   if ( I11i1i == None ) : return
   if 45 - 45: o0oOOo0O0Ooo
   iI111ii1Ii1I = I11i1i . lookup_source_cache ( self . eid , True )
   if ( iI111ii1Ii1I == None ) : return
   if 33 - 33: ooOoO0o % O0 % I1ii11iIi11i % o0oOOo0O0Ooo + i11iIiiIii . I1Ii111
   I11i1i . source_cache . delete_cache ( self . eid )
   if ( I11i1i . source_cache . cache_size ( ) == 0 ) :
    lisp_referral_cache . delete_cache ( self . group )
    if 21 - 21: I1Ii111 * I1ii11iIi11i * ooOoO0o
    if 73 - 73: OoOoOO00 * O0
    if 1 - 1: OOooOOo * OoooooooOO
    if 46 - 46: I1ii11iIi11i * I1Ii111 / OOooOOo / I1IiiI
 def add_source_entry ( self , source_ref ) :
  if ( self . source_cache == None ) : self . source_cache = lisp_cache ( )
  self . source_cache . add_cache ( source_ref . eid , source_ref )
  if 7 - 7: OOooOOo / OoOoOO00
  if 93 - 93: iIii1I11I1II1 * Ii1I - iII111i
 def lookup_source_cache ( self , source , exact ) :
  if ( self . source_cache == None ) : return ( None )
  return ( self . source_cache . lookup_cache ( source , exact ) )
  if 94 - 94: iIii1I11I1II1 * iIii1I11I1II1 * I11i % i11iIiiIii
  if 38 - 38: I1IiiI % I1ii11iIi11i * I1IiiI + OOooOOo - OoOoOO00
  if 78 - 78: OOooOOo + I1Ii111
class lisp_referral_node ( ) :
 def __init__ ( self ) :
  self . referral_address = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . priority = 0
  self . weight = 0
  self . updown = True
  self . map_requests_sent = 0
  self . no_responses = 0
  self . uptime = lisp_get_timestamp ( )
  if 41 - 41: I11i + Oo0Ooo . Oo0Ooo / iII111i . OoOoOO00
  if 1 - 1: ooOoO0o + iII111i % i11iIiiIii / OoOoOO00
 def print_ref_node ( self , indent ) :
  I11i1II = lisp_print_elapsed ( self . uptime )
  lprint ( "{}referral {}, uptime {}, {}, priority/weight: {}/{}" . format ( indent , red ( self . referral_address . print_address ( ) , False ) , I11i1II ,
  # IiII . iII111i % OoooooooOO % IiII + Ii1I - OoooooooOO
 "up" if self . updown else "down" , self . priority , self . weight ) )
  if 23 - 23: O0 - iII111i
  if 18 - 18: II111iiii % i11iIiiIii + I11i - OOooOOo
  if 100 - 100: o0oOOo0O0Ooo / Ii1I - iIii1I11I1II1 / oO0o
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
   if 68 - 68: I11i / II111iiii * oO0o . II111iiii * OOooOOo
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
   if 78 - 78: I11i * OoO0O00 / II111iiii
   if 86 - 86: I1Ii111 % II111iiii
   if 90 - 90: OoO0O00 / I11i - Oo0Ooo
 def resolve_dns_name ( self ) :
  if ( self . dns_name == None ) : return
  if ( self . last_dns_resolve and
 time . time ( ) - self . last_dns_resolve < 30 ) : return
  if 76 - 76: O0 + OoO0O00 / ooOoO0o . II111iiii * iIii1I11I1II1 . I1Ii111
  try :
   iII1I11 = socket . gethostbyname_ex ( self . dns_name )
   self . last_dns_resolve = lisp_get_timestamp ( )
   ooOOoO = iII1I11 [ 2 ]
  except :
   return
   if 43 - 43: Oo0Ooo + o0oOOo0O0Ooo % o0oOOo0O0Ooo % I1ii11iIi11i / iIii1I11I1II1 . I1ii11iIi11i
   if 59 - 59: IiII . OoO0O00 - OoooooooOO . O0
   if 33 - 33: Ii1I
   if 95 - 95: OoooooooOO + OoO0O00 * ooOoO0o
   if 40 - 40: I1IiiI / OOooOOo * Ii1I
   if 98 - 98: I1IiiI
  if ( len ( ooOOoO ) <= self . a_record_index ) :
   self . delete_ms ( )
   return
   if 4 - 4: I1IiiI % O0 / Oo0Ooo / O0
   if 90 - 90: ooOoO0o - O0 . IiII - O0 . iIii1I11I1II1
  ooooO0O = ooOOoO [ self . a_record_index ]
  if ( ooooO0O != self . map_server . print_address_no_iid ( ) ) :
   self . delete_ms ( )
   self . map_server . store_address ( ooooO0O )
   self . insert_ms ( )
   if 42 - 42: I1ii11iIi11i
   if 51 - 51: iII111i % i11iIiiIii . OoO0O00 . IiII - OoOoOO00 * i1IIi
   if 14 - 14: I1ii11iIi11i . OoO0O00
   if 26 - 26: iII111i / ooOoO0o / Oo0Ooo / Oo0Ooo . I1ii11iIi11i * OOooOOo
   if 25 - 25: IiII % I1IiiI / O0 % OOooOOo - OoooooooOO
   if 29 - 29: O0 + iII111i
  if ( lisp_is_decent_dns_suffix ( self . dns_name ) == False ) : return
  if ( self . a_record_index != 0 ) : return
  if 4 - 4: I11i * I11i - Ii1I * oO0o . I1ii11iIi11i % o0oOOo0O0Ooo
  for ooooO0O in ooOOoO [ 1 : : ] :
   iiiii1ii1 = lisp_address ( LISP_AFI_NONE , ooooO0O , 0 , 0 )
   I1iiIIiiiII = lisp_get_map_server ( iiiii1ii1 )
   if ( I1iiIIiiiII != None and I1iiIIiiiII . a_record_index == ooOOoO . index ( ooooO0O ) ) :
    continue
    if 33 - 33: Ii1I * i11iIiiIii / O0 . Oo0Ooo + i1IIi . OoOoOO00
   I1iiIIiiiII = copy . deepcopy ( self )
   I1iiIIiiiII . map_server . store_address ( ooooO0O )
   I1iiIIiiiII . a_record_index = ooOOoO . index ( ooooO0O )
   I1iiIIiiiII . last_dns_resolve = lisp_get_timestamp ( )
   I1iiIIiiiII . insert_ms ( )
   if 76 - 76: OoooooooOO - O0
   if 17 - 17: Oo0Ooo % I1Ii111 . oO0o - O0
   if 32 - 32: O0 % O0
   if 66 - 66: iII111i / i1IIi - Oo0Ooo . Ii1I
   if 65 - 65: I1ii11iIi11i % ooOoO0o - OoOoOO00 + ooOoO0o + Oo0Ooo
  IiII1IIiI1i = [ ]
  for I1iiIIiiiII in lisp_map_servers_list . values ( ) :
   if ( self . dns_name != I1iiIIiiiII . dns_name ) : continue
   iiiii1ii1 = I1iiIIiiiII . map_server . print_address_no_iid ( )
   if ( iiiii1ii1 in ooOOoO ) : continue
   IiII1IIiI1i . append ( I1iiIIiiiII )
   if 95 - 95: I1Ii111 * i11iIiiIii - I1IiiI - OoOoOO00 . ooOoO0o
  for I1iiIIiiiII in IiII1IIiI1i : I1iiIIiiiII . delete_ms ( )
  if 34 - 34: OoooooooOO % I1ii11iIi11i + OoooooooOO % i11iIiiIii / IiII - ooOoO0o
  if 74 - 74: iIii1I11I1II1 % II111iiii + IiII
 def insert_ms ( self ) :
  i1iI11iI = self . ms_name + self . map_server . print_address ( )
  lisp_map_servers_list [ i1iI11iI ] = self
  if 71 - 71: I1IiiI / O0 * i1IIi . i1IIi + Oo0Ooo
  if 32 - 32: i1IIi * I1Ii111 % I1IiiI / IiII . I1Ii111
 def delete_ms ( self ) :
  i1iI11iI = self . ms_name + self . map_server . print_address ( )
  if ( lisp_map_servers_list . has_key ( i1iI11iI ) == False ) : return
  lisp_map_servers_list . pop ( i1iI11iI )
  if 11 - 11: OOooOOo
  if 25 - 25: i1IIi
  if 99 - 99: OOooOOo + OoooooooOO . I1Ii111 * Oo0Ooo % oO0o
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
  if 75 - 75: iII111i
  if 8 - 8: I1ii11iIi11i . I11i / I1ii11iIi11i - i1IIi
 def add_interface ( self ) :
  lisp_myinterfaces [ self . device ] = self
  if 22 - 22: OOooOOo
  if 7 - 7: O0 - I1ii11iIi11i - OoO0O00 * I1Ii111
 def get_instance_id ( self ) :
  return ( self . instance_id )
  if 17 - 17: o0oOOo0O0Ooo % OoO0O00 - I11i * o0oOOo0O0Ooo - i1IIi / I1IiiI
  if 100 - 100: OoO0O00 * i1IIi * o0oOOo0O0Ooo * Oo0Ooo - o0oOOo0O0Ooo
 def get_socket ( self ) :
  return ( self . raw_socket )
  if 100 - 100: iII111i - i11iIiiIii + OoO0O00
  if 50 - 50: II111iiii
 def get_bridge_socket ( self ) :
  return ( self . bridge_socket )
  if 42 - 42: OOooOOo * I1Ii111
  if 53 - 53: II111iiii % OOooOOo / I1ii11iIi11i * OoOoOO00 % I1ii11iIi11i * iII111i
 def does_dynamic_eid_match ( self , eid ) :
  if ( self . dynamic_eid . is_null ( ) ) : return ( False )
  return ( eid . is_more_specific ( self . dynamic_eid ) )
  if 91 - 91: iII111i . OoooooooOO
  if 90 - 90: i11iIiiIii - I1IiiI
 def set_socket ( self , device ) :
  IiiiI1 = socket . socket ( socket . AF_INET , socket . SOCK_RAW , socket . IPPROTO_RAW )
  IiiiI1 . setsockopt ( socket . SOL_IP , socket . IP_HDRINCL , 1 )
  try :
   IiiiI1 . setsockopt ( socket . SOL_SOCKET , socket . SO_BINDTODEVICE , device )
  except :
   IiiiI1 . close ( )
   IiiiI1 = None
   if 39 - 39: iII111i % OoooooooOO % Ii1I % I1IiiI
  self . raw_socket = IiiiI1
  if 63 - 63: OoO0O00 - I1Ii111 - II111iiii
  if 79 - 79: II111iiii - II111iiii + OoOoOO00 / iII111i % OoooooooOO - OoO0O00
 def set_bridge_socket ( self , device ) :
  IiiiI1 = socket . socket ( socket . PF_PACKET , socket . SOCK_RAW )
  try :
   IiiiI1 = IiiiI1 . bind ( ( device , 0 ) )
   self . bridge_socket = IiiiI1
  except :
   return
   if 22 - 22: o0oOOo0O0Ooo + I1Ii111 . Oo0Ooo
   if 84 - 84: O0 + I1IiiI % Oo0Ooo + OOooOOo
   if 94 - 94: OOooOOo
   if 81 - 81: i11iIiiIii + iIii1I11I1II1 . i11iIiiIii / OOooOOo / iII111i
class lisp_datetime ( ) :
 def __init__ ( self , datetime_str ) :
  self . datetime_name = datetime_str
  self . datetime = None
  self . parse_datetime ( )
  if 34 - 34: i11iIiiIii - o0oOOo0O0Ooo * OoooooooOO * I1ii11iIi11i * Oo0Ooo % I1ii11iIi11i
  if 31 - 31: I11i . o0oOOo0O0Ooo
 def valid_datetime ( self ) :
  o0O0OOo0O = self . datetime_name
  if ( o0O0OOo0O . find ( ":" ) == - 1 ) : return ( False )
  if ( o0O0OOo0O . find ( "-" ) == - 1 ) : return ( False )
  o0O0O0OO0 , III1i1ii1I1 , ii11i11i1ii , time = o0O0OOo0O [ 0 : 4 ] , o0O0OOo0O [ 5 : 7 ] , o0O0OOo0O [ 8 : 10 ] , o0O0OOo0O [ 11 : : ]
  if 77 - 77: OoOoOO00 * I1Ii111 / O0 % Oo0Ooo * I11i
  if ( ( o0O0O0OO0 + III1i1ii1I1 + ii11i11i1ii ) . isdigit ( ) == False ) : return ( False )
  if ( III1i1ii1I1 < "01" and III1i1ii1I1 > "12" ) : return ( False )
  if ( ii11i11i1ii < "01" and ii11i11i1ii > "31" ) : return ( False )
  if 3 - 3: IiII
  oOo0O , oO0OOOOO0Ooo0oO0 , iiiI = time . split ( ":" )
  if 10 - 10: OoO0O00 % o0oOOo0O0Ooo / o0oOOo0O0Ooo . IiII
  if ( ( oOo0O + oO0OOOOO0Ooo0oO0 + iiiI ) . isdigit ( ) == False ) : return ( False )
  if ( oOo0O < "00" and oOo0O > "23" ) : return ( False )
  if ( oO0OOOOO0Ooo0oO0 < "00" and oO0OOOOO0Ooo0oO0 > "59" ) : return ( False )
  if ( iiiI < "00" and iiiI > "59" ) : return ( False )
  return ( True )
  if 47 - 47: Ii1I * Ii1I * I1ii11iIi11i % o0oOOo0O0Ooo
  if 75 - 75: OoO0O00 . i1IIi / OoO0O00 - Oo0Ooo
 def parse_datetime ( self ) :
  OOO0oo00oO = self . datetime_name
  OOO0oo00oO = OOO0oo00oO . replace ( "-" , "" )
  OOO0oo00oO = OOO0oo00oO . replace ( ":" , "" )
  self . datetime = int ( OOO0oo00oO )
  if 32 - 32: OoooooooOO % OOooOOo / I1Ii111 + OOooOOo . iII111i
  if 54 - 54: OoooooooOO . iIii1I11I1II1 + iIii1I11I1II1
 def now ( self ) :
  I11i1II = datetime . datetime . now ( ) . strftime ( "%Y-%m-%d-%H:%M:%S" )
  I11i1II = lisp_datetime ( I11i1II )
  return ( I11i1II )
  if 11 - 11: Ii1I * OoO0O00 % I1ii11iIi11i
  if 60 - 60: i11iIiiIii % II111iiii % I11i
 def print_datetime ( self ) :
  return ( self . datetime_name )
  if 92 - 92: O0 * OoooooooOO + I1ii11iIi11i / IiII
  if 97 - 97: o0oOOo0O0Ooo . Ii1I + I1Ii111
 def future ( self ) :
  return ( self . datetime > self . now ( ) . datetime )
  if 72 - 72: i11iIiiIii . iII111i . Ii1I * I1ii11iIi11i
  if 49 - 49: OoOoOO00 - O0 % I11i - ooOoO0o * OOooOOo
 def past ( self ) :
  return ( self . future ( ) == False )
  if 58 - 58: OoooooooOO - OOooOOo * oO0o / Ii1I . IiII
  if 50 - 50: IiII . OOooOOo + I1ii11iIi11i - OoooooooOO
 def now_in_range ( self , upper ) :
  return ( self . past ( ) and upper . future ( ) )
  if 2 - 2: o0oOOo0O0Ooo % ooOoO0o / O0 / i11iIiiIii
  if 91 - 91: II111iiii * o0oOOo0O0Ooo
 def this_year ( self ) :
  Ii1I1I11I11 = str ( self . now ( ) . datetime ) [ 0 : 4 ]
  I11i1II = str ( self . datetime ) [ 0 : 4 ]
  return ( I11i1II == Ii1I1I11I11 )
  if 84 - 84: oO0o
  if 74 - 74: I1IiiI
 def this_month ( self ) :
  Ii1I1I11I11 = str ( self . now ( ) . datetime ) [ 0 : 6 ]
  I11i1II = str ( self . datetime ) [ 0 : 6 ]
  return ( I11i1II == Ii1I1I11I11 )
  if 39 - 39: iII111i * IiII / iII111i * IiII % I1ii11iIi11i
  if 27 - 27: iIii1I11I1II1 . ooOoO0o
 def today ( self ) :
  Ii1I1I11I11 = str ( self . now ( ) . datetime ) [ 0 : 8 ]
  I11i1II = str ( self . datetime ) [ 0 : 8 ]
  return ( I11i1II == Ii1I1I11I11 )
  if 74 - 74: i1IIi % OoOoOO00
  if 98 - 98: IiII * OOooOOo / O0 - I1Ii111 . I1Ii111 + OOooOOo
  if 61 - 61: iII111i * Ii1I % Ii1I + I1IiiI
  if 23 - 23: oO0o + I1Ii111 / OoooooooOO / O0 + IiII
  if 80 - 80: i11iIiiIii - OoooooooOO + II111iiii / i1IIi - oO0o
  if 100 - 100: Ii1I
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
  if 73 - 73: IiII - O0
  if 54 - 54: OOooOOo
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
  if 28 - 28: i1IIi - Oo0Ooo * OoO0O00 + OoooooooOO - Ii1I * i11iIiiIii
  if 71 - 71: iII111i - OOooOOo / iIii1I11I1II1 % i11iIiiIii
 def match_policy_map_request ( self , mr , srloc ) :
  for iIo0 in self . match_clauses :
   IiIiI1 = iIo0 . source_eid
   Oo0o0O0OO0 = mr . source_eid
   if ( IiIiI1 and Oo0o0O0OO0 and Oo0o0O0OO0 . is_more_specific ( IiIiI1 ) == False ) : continue
   if 39 - 39: o0oOOo0O0Ooo
   IiIiI1 = iIo0 . dest_eid
   Oo0o0O0OO0 = mr . target_eid
   if ( IiIiI1 and Oo0o0O0OO0 and Oo0o0O0OO0 . is_more_specific ( IiIiI1 ) == False ) : continue
   if 32 - 32: iIii1I11I1II1 . II111iiii / IiII % O0 / iII111i
   IiIiI1 = iIo0 . source_rloc
   Oo0o0O0OO0 = srloc
   if ( IiIiI1 and Oo0o0O0OO0 and Oo0o0O0OO0 . is_more_specific ( IiIiI1 ) == False ) : continue
   i1IIi111iI = iIo0 . datetime_lower
   oooOOoooo000o = iIo0 . datetime_upper
   if ( i1IIi111iI and oooOOoooo000o and i1IIi111iI . now_in_range ( oooOOoooo000o ) == False ) : continue
   return ( True )
   if 57 - 57: I11i . IiII / iIii1I11I1II1 - ooOoO0o
  return ( False )
  if 50 - 50: O0 / II111iiii
  if 94 - 94: O0 + O0 % I1ii11iIi11i % i1IIi
 def set_policy_map_reply ( self ) :
  iII11 = ( self . set_rloc_address == None and
 self . set_rloc_record_name == None and self . set_geo_name == None and
 self . set_elp_name == None and self . set_rle_name == None )
  if ( iII11 ) : return ( None )
  if 82 - 82: O0 - OOooOOo / I1IiiI / OOooOOo . OOooOOo - iIii1I11I1II1
  o0OOooooooOO = lisp_rloc ( )
  if ( self . set_rloc_address ) :
   o0OOooooooOO . rloc . copy_address ( self . set_rloc_address )
   ooooO0O = o0OOooooooOO . rloc . print_address_no_iid ( )
   lprint ( "Policy set-rloc-address to {}" . format ( ooooO0O ) )
   if 86 - 86: o0oOOo0O0Ooo - OoO0O00 . i11iIiiIii
  if ( self . set_rloc_record_name ) :
   o0OOooooooOO . rloc_name = self . set_rloc_record_name
   I1i1iI1II = blue ( o0OOooooooOO . rloc_name , False )
   lprint ( "Policy set-rloc-record-name to {}" . format ( I1i1iI1II ) )
   if 11 - 11: iII111i % I1IiiI . i1IIi % OoO0O00 . OoO0O00
  if ( self . set_geo_name ) :
   o0OOooooooOO . geo_name = self . set_geo_name
   I1i1iI1II = o0OOooooooOO . geo_name
   I11OOoooO0OooOO = "" if lisp_geo_list . has_key ( I1i1iI1II ) else "(not configured)"
   if 71 - 71: iIii1I11I1II1 % OOooOOo
   lprint ( "Policy set-geo-name '{}' {}" . format ( I1i1iI1II , I11OOoooO0OooOO ) )
   if 57 - 57: Oo0Ooo + oO0o
  if ( self . set_elp_name ) :
   o0OOooooooOO . elp_name = self . set_elp_name
   I1i1iI1II = o0OOooooooOO . elp_name
   I11OOoooO0OooOO = "" if lisp_elp_list . has_key ( I1i1iI1II ) else "(not configured)"
   if 71 - 71: ooOoO0o
   lprint ( "Policy set-elp-name '{}' {}" . format ( I1i1iI1II , I11OOoooO0OooOO ) )
   if 32 - 32: OoOoOO00 % IiII % OoO0O00
  if ( self . set_rle_name ) :
   o0OOooooooOO . rle_name = self . set_rle_name
   I1i1iI1II = o0OOooooooOO . rle_name
   I11OOoooO0OooOO = "" if lisp_rle_list . has_key ( I1i1iI1II ) else "(not configured)"
   if 95 - 95: ooOoO0o
   lprint ( "Policy set-rle-name '{}' {}" . format ( I1i1iI1II , I11OOoooO0OooOO ) )
   if 47 - 47: I1IiiI * i11iIiiIii / I1IiiI / iIii1I11I1II1 - Ii1I
  if ( self . set_json_name ) :
   o0OOooooooOO . json_name = self . set_json_name
   I1i1iI1II = o0OOooooooOO . json_name
   I11OOoooO0OooOO = "" if lisp_json_list . has_key ( I1i1iI1II ) else "(not configured)"
   if 25 - 25: oO0o / i11iIiiIii + i11iIiiIii % IiII - o0oOOo0O0Ooo
   lprint ( "Policy set-json-name '{}' {}" . format ( I1i1iI1II , I11OOoooO0OooOO ) )
   if 97 - 97: I1ii11iIi11i % iII111i * ooOoO0o % OOooOOo . I1IiiI - i11iIiiIii
  return ( o0OOooooooOO )
  if 2 - 2: IiII . o0oOOo0O0Ooo % II111iiii
  if 69 - 69: Ii1I
 def save_policy ( self ) :
  lisp_policies [ self . policy_name ] = self
  if 75 - 75: I1IiiI
  if 55 - 55: i11iIiiIii - I1IiiI . oO0o - OoooooooOO
  if 44 - 44: I1Ii111
class lisp_pubsub ( ) :
 def __init__ ( self , itr , port , nonce , ttl , xtr_id ) :
  self . itr = itr
  self . port = port
  self . nonce = nonce
  self . uptime = lisp_get_timestamp ( )
  self . ttl = ttl
  self . xtr_id = xtr_id
  self . map_notify_count = 0
  if 98 - 98: I1IiiI % OOooOOo % iII111i
  if 15 - 15: OoO0O00
 def add ( self , eid_prefix ) :
  I1i = self . ttl
  ii1Ii = eid_prefix . print_prefix ( )
  if ( lisp_pubsub_cache . has_key ( ii1Ii ) == False ) :
   lisp_pubsub_cache [ ii1Ii ] = { }
   if 52 - 52: II111iiii / ooOoO0o
  ooOOo0ooo = lisp_pubsub_cache [ ii1Ii ]
  if 23 - 23: i11iIiiIii % OoO0O00 - o0oOOo0O0Ooo + OoooooooOO
  I1iI = "Add"
  if ( ooOOo0ooo . has_key ( self . xtr_id ) ) :
   I1iI = "Replace"
   del ( ooOOo0ooo [ self . xtr_id ] )
   if 16 - 16: I1IiiI + ooOoO0o - O0 / o0oOOo0O0Ooo
  ooOOo0ooo [ self . xtr_id ] = self
  if 36 - 36: Oo0Ooo - OoOoOO00 - II111iiii
  ii1Ii = green ( ii1Ii , False )
  oo0Oo0oo = red ( self . itr . print_address_no_iid ( ) , False )
  iIi = "0x" + lisp_hex_string ( self . xtr_id )
  lprint ( "{} pubsub state {} for {}, xtr-id: {}, ttl {}" . format ( I1iI , ii1Ii ,
 oo0Oo0oo , iIi , I1i ) )
  if 25 - 25: i11iIiiIii + II111iiii * OOooOOo % OOooOOo
  if 87 - 87: I11i % Ii1I % Oo0Ooo . II111iiii / oO0o
 def delete ( self , eid_prefix ) :
  ii1Ii = eid_prefix . print_prefix ( )
  oo0Oo0oo = red ( self . itr . print_address_no_iid ( ) , False )
  iIi = "0x" + lisp_hex_string ( self . xtr_id )
  if ( lisp_pubsub_cache . has_key ( ii1Ii ) ) :
   ooOOo0ooo = lisp_pubsub_cache [ ii1Ii ]
   if ( ooOOo0ooo . has_key ( self . xtr_id ) ) :
    ooOOo0ooo . pop ( self . xtr_id )
    lprint ( "Remove pubsub state {} for {}, xtr-id: {}" . format ( ii1Ii ,
 oo0Oo0oo , iIi ) )
    if 19 - 19: O0 . OOooOOo + I1Ii111 * I1ii11iIi11i
    if 91 - 91: o0oOOo0O0Ooo / oO0o . o0oOOo0O0Ooo + IiII + ooOoO0o . I1Ii111
    if 90 - 90: i1IIi + oO0o * oO0o / ooOoO0o . IiII
    if 98 - 98: I11i % OoO0O00 . iII111i - o0oOOo0O0Ooo
    if 92 - 92: I11i
    if 34 - 34: I1IiiI % iIii1I11I1II1 . I1ii11iIi11i * Oo0Ooo * iIii1I11I1II1 / O0
    if 98 - 98: iII111i % IiII + OoO0O00
    if 23 - 23: OOooOOo
    if 83 - 83: I1ii11iIi11i / O0 * II111iiii + IiII + Oo0Ooo
    if 99 - 99: II111iiii + O0
    if 94 - 94: ooOoO0o * ooOoO0o + o0oOOo0O0Ooo . iII111i % iIii1I11I1II1 + Ii1I
    if 88 - 88: Oo0Ooo . iII111i
    if 89 - 89: OOooOOo + I1Ii111 % i11iIiiIii + Oo0Ooo / Oo0Ooo + OoO0O00
    if 9 - 9: OoOoOO00 % i1IIi + IiII
    if 19 - 19: I1Ii111 - II111iiii / I1Ii111 + I1IiiI - OoooooooOO + o0oOOo0O0Ooo
    if 100 - 100: OoO0O00 / OoOoOO00 / OOooOOo / OoO0O00
    if 95 - 95: ooOoO0o
    if 95 - 95: Ii1I + i1IIi . I1IiiI % I1Ii111 / Ii1I * O0
    if 68 - 68: I1Ii111 - IiII - oO0o - Oo0Ooo - o0oOOo0O0Ooo
    if 32 - 32: OoOoOO00 % i11iIiiIii
    if 53 - 53: I1Ii111 * Ii1I / IiII . i1IIi * II111iiii / o0oOOo0O0Ooo
    if 44 - 44: I1Ii111 + ooOoO0o
class lisp_trace ( ) :
 def __init__ ( self ) :
  self . nonce = lisp_get_control_nonce ( )
  self . packet_json = [ ]
  self . local_rloc = None
  self . local_port = None
  self . lisp_socket = None
  if 15 - 15: I11i + OoO0O00 + OoOoOO00
  if 100 - 100: I1Ii111
 def print_trace ( self ) :
  oo000OO = self . packet_json
  lprint ( "LISP-Trace JSON: '{}'" . format ( oo000OO ) )
  if 72 - 72: OoOoOO00 * Oo0Ooo + iII111i
  if 99 - 99: II111iiii . OoooooooOO * iIii1I11I1II1
 def encode ( self ) :
  iiii1ii1 = socket . htonl ( 0x90000000 )
  Oo0O0oo = struct . pack ( "II" , iiii1ii1 , 0 )
  Oo0O0oo += struct . pack ( "Q" , self . nonce )
  Oo0O0oo += json . dumps ( self . packet_json )
  return ( Oo0O0oo )
  if 72 - 72: OoooooooOO . I1ii11iIi11i * I1Ii111 / OoooooooOO % OOooOOo
  if 60 - 60: OoO0O00
 def decode ( self , packet ) :
  OoOo0Oooo0o = "I"
  o0OOo0OOoOO0 = struct . calcsize ( OoOo0Oooo0o )
  if ( len ( packet ) < o0OOo0OOoOO0 ) : return ( False )
  iiii1ii1 = struct . unpack ( OoOo0Oooo0o , packet [ : o0OOo0OOoOO0 ] ) [ 0 ]
  packet = packet [ o0OOo0OOoOO0 : : ]
  iiii1ii1 = socket . ntohl ( iiii1ii1 )
  if ( ( iiii1ii1 & 0xff000000 ) != 0x90000000 ) : return ( False )
  if 54 - 54: I1IiiI + O0 - I1Ii111 - oO0o + O0 - I1ii11iIi11i
  if ( len ( packet ) < o0OOo0OOoOO0 ) : return ( False )
  ooooO0O = struct . unpack ( OoOo0Oooo0o , packet [ : o0OOo0OOoOO0 ] ) [ 0 ]
  packet = packet [ o0OOo0OOoOO0 : : ]
  if 21 - 21: ooOoO0o . i1IIi / Oo0Ooo . OoO0O00
  ooooO0O = socket . ntohl ( ooooO0O )
  iI1i1iIIIII = ooooO0O >> 24
  IIIIi1iI = ( ooooO0O >> 16 ) & 0xff
  oOOOooOOO = ( ooooO0O >> 8 ) & 0xff
  OOO00IiI111111i = ooooO0O & 0xff
  self . local_rloc = "{}.{}.{}.{}" . format ( iI1i1iIIIII , IIIIi1iI , oOOOooOOO , OOO00IiI111111i )
  self . local_port = str ( iiii1ii1 & 0xffff )
  if 64 - 64: Ii1I . I1IiiI + OoooooooOO - O0 * Ii1I % I1Ii111
  OoOo0Oooo0o = "Q"
  o0OOo0OOoOO0 = struct . calcsize ( OoOo0Oooo0o )
  if ( len ( packet ) < o0OOo0OOoOO0 ) : return ( False )
  self . nonce = struct . unpack ( OoOo0Oooo0o , packet [ : o0OOo0OOoOO0 ] ) [ 0 ]
  packet = packet [ o0OOo0OOoOO0 : : ]
  if ( len ( packet ) == 0 ) : return ( True )
  if 30 - 30: I1ii11iIi11i . iII111i . II111iiii + IiII
  try :
   self . packet_json = json . loads ( packet )
  except :
   return ( False )
   if 59 - 59: o0oOOo0O0Ooo + Ii1I * OoooooooOO * i1IIi % OoOoOO00
  return ( True )
  if 83 - 83: iIii1I11I1II1 - i1IIi - Ii1I % iII111i
  if 69 - 69: I1Ii111 * oO0o * I1IiiI
 def myeid ( self , eid ) :
  return ( lisp_is_myeid ( eid ) )
  if 74 - 74: O0 / I11i . Oo0Ooo / I11i % OoO0O00 % o0oOOo0O0Ooo
  if 83 - 83: OoO0O00 - i11iIiiIii + iIii1I11I1II1
 def return_to_sender ( self , lisp_socket , rts_rloc , packet ) :
  o0OOooooooOO , Ii1 = self . rtr_cache_nat_trace_find ( rts_rloc )
  if ( o0OOooooooOO == None ) :
   o0OOooooooOO , Ii1 = rts_rloc . split ( ":" )
   Ii1 = int ( Ii1 )
   lprint ( "Send LISP-Trace to address {}:{}" . format ( o0OOooooooOO , Ii1 ) )
  else :
   lprint ( "Send LISP-Trace to translated address {}:{}" . format ( o0OOooooooOO ,
 Ii1 ) )
   if 52 - 52: OoooooooOO
   if 44 - 44: O0 / OoooooooOO + ooOoO0o * I1ii11iIi11i
  if ( lisp_socket == None ) :
   IiiiI1 = socket . socket ( socket . AF_INET , socket . SOCK_DGRAM )
   IiiiI1 . bind ( ( "0.0.0.0" , LISP_TRACE_PORT ) )
   IiiiI1 . sendto ( packet , ( o0OOooooooOO , Ii1 ) )
   IiiiI1 . close ( )
  else :
   lisp_socket . sendto ( packet , ( o0OOooooooOO , Ii1 ) )
   if 36 - 36: I1ii11iIi11i / OoO0O00 - oO0o % O0
   if 12 - 12: i1IIi * ooOoO0o / oO0o + I1IiiI / OoooooooOO
   if 86 - 86: Oo0Ooo / OoO0O00
 def packet_length ( self ) :
  i1iIIII1iiIIi = 8 ; oooooOOOoO00 = 4 + 4 + 8
  return ( i1iIIII1iiIIi + oooooOOOoO00 + len ( json . dumps ( self . packet_json ) ) )
  if 67 - 67: II111iiii . Ii1I + I1IiiI
  if 77 - 77: O0 % I1ii11iIi11i + i11iIiiIii . OOooOOo % o0oOOo0O0Ooo + OoO0O00
 def rtr_cache_nat_trace ( self , translated_rloc , translated_port ) :
  i1iI11iI = self . local_rloc + ":" + self . local_port
  iiIIi = ( translated_rloc , translated_port )
  lisp_rtr_nat_trace_cache [ i1iI11iI ] = iiIIi
  lprint ( "Cache NAT Trace addresses {} -> {}" . format ( i1iI11iI , iiIIi ) )
  if 31 - 31: ooOoO0o * I1ii11iIi11i
  if 23 - 23: OoOoOO00 - I11i . iIii1I11I1II1
 def rtr_cache_nat_trace_find ( self , local_rloc_and_port ) :
  i1iI11iI = local_rloc_and_port
  try : iiIIi = lisp_rtr_nat_trace_cache [ i1iI11iI ]
  except : iiIIi = ( None , None )
  return ( iiIIi )
  if 87 - 87: OoO0O00 - i11iIiiIii / O0 % OOooOOo % OOooOOo * i1IIi
  if 18 - 18: IiII
  if 50 - 50: i1IIi / o0oOOo0O0Ooo * OoO0O00
  if 98 - 98: I11i . II111iiii
  if 13 - 13: oO0o - I11i % II111iiii
  if 30 - 30: ooOoO0o / O0 . I11i + I1ii11iIi11i % O0 . I1IiiI
  if 25 - 25: o0oOOo0O0Ooo - ooOoO0o / I11i
  if 98 - 98: ooOoO0o * I11i + o0oOOo0O0Ooo
  if 62 - 62: i11iIiiIii
  if 49 - 49: o0oOOo0O0Ooo / OoOoOO00 + iII111i
  if 85 - 85: I1IiiI - o0oOOo0O0Ooo
def lisp_get_map_server ( address ) :
 for I1iiIIiiiII in lisp_map_servers_list . values ( ) :
  if ( I1iiIIiiiII . map_server . is_exact_match ( address ) ) : return ( I1iiIIiiiII )
  if 86 - 86: II111iiii + Ii1I * Ii1I
 return ( None )
 if 26 - 26: o0oOOo0O0Ooo + oO0o * i11iIiiIii / II111iiii
 if 86 - 86: Ii1I
 if 69 - 69: oO0o % o0oOOo0O0Ooo / o0oOOo0O0Ooo
 if 1 - 1: Ii1I
 if 43 - 43: o0oOOo0O0Ooo
 if 78 - 78: I1Ii111 % i1IIi * I11i
 if 59 - 59: OoOoOO00 % OoO0O00 % i11iIiiIii . II111iiii % I1ii11iIi11i + i1IIi
def lisp_get_any_map_server ( ) :
 for I1iiIIiiiII in lisp_map_servers_list . values ( ) : return ( I1iiIIiiiII )
 return ( None )
 if 99 - 99: I11i + IiII * I1Ii111 - OOooOOo - i1IIi
 if 77 - 77: I11i . IiII / OoO0O00 / I1Ii111
 if 8 - 8: o0oOOo0O0Ooo + iII111i / OoO0O00 * ooOoO0o - oO0o . iII111i
 if 32 - 32: OoooooooOO . I1Ii111 - I1ii11iIi11i
 if 29 - 29: OoO0O00
 if 33 - 33: I1ii11iIi11i - O0
 if 72 - 72: Oo0Ooo * iII111i - I11i
 if 81 - 81: I1Ii111
 if 85 - 85: O0 % OoOoOO00 . I1ii11iIi11i
 if 46 - 46: OOooOOo * iIii1I11I1II1
def lisp_get_map_resolver ( address , eid ) :
 if ( address != None ) :
  ooooO0O = address . print_address ( )
  OOO0o0o = None
  for i1iI11iI in lisp_map_resolvers_list :
   if ( i1iI11iI . find ( ooooO0O ) == - 1 ) : continue
   OOO0o0o = lisp_map_resolvers_list [ i1iI11iI ]
   if 33 - 33: OoO0O00 * II111iiii / i1IIi
  return ( OOO0o0o )
  if 93 - 93: I1Ii111 % I11i
  if 64 - 64: I1IiiI % OoOoOO00 / Oo0Ooo
  if 40 - 40: Ii1I + iIii1I11I1II1 / oO0o . II111iiii % O0 - IiII
  if 49 - 49: IiII - OOooOOo * OOooOOo . O0
  if 60 - 60: OoOoOO00 % iIii1I11I1II1 + IiII % o0oOOo0O0Ooo
  if 64 - 64: OoOoOO00 * I1ii11iIi11i . OoooooooOO . i1IIi
  if 61 - 61: OoO0O00
 if ( eid == "" ) :
  o0oo0Oo = ""
 elif ( eid == None ) :
  o0oo0Oo = "all"
 else :
  o0o0O0OO0oO = lisp_db_for_lookups . lookup_cache ( eid , False )
  o0oo0Oo = "all" if o0o0O0OO0oO == None else o0o0O0OO0oO . use_mr_name
  if 55 - 55: OoO0O00 . Oo0Ooo + iII111i % OoO0O00 * O0
  if 37 - 37: OOooOOo
 oOoo0OOOO0OO = None
 for OOO0o0o in lisp_map_resolvers_list . values ( ) :
  if ( o0oo0Oo == "" ) : return ( OOO0o0o )
  if ( OOO0o0o . mr_name != o0oo0Oo ) : continue
  if ( oOoo0OOOO0OO == None or OOO0o0o . last_used < oOoo0OOOO0OO . last_used ) : oOoo0OOOO0OO = OOO0o0o
  if 79 - 79: I11i
 return ( oOoo0OOOO0OO )
 if 7 - 7: i1IIi
 if 72 - 72: OOooOOo * iIii1I11I1II1 . iII111i - IiII % i1IIi
 if 67 - 67: I1ii11iIi11i - oO0o / I1IiiI + I1Ii111 * I1IiiI - I1Ii111
 if 30 - 30: Ii1I / I1Ii111 - OoOoOO00 / OOooOOo * I1IiiI + Ii1I
 if 41 - 41: ooOoO0o . i1IIi * iIii1I11I1II1 - I1IiiI
 if 9 - 9: I11i % i1IIi / ooOoO0o % iII111i - oO0o - II111iiii
 if 29 - 29: ooOoO0o . II111iiii . i1IIi % oO0o
 if 11 - 11: OoOoOO00 . OoO0O00 % I11i * iII111i % I1Ii111 . O0
def lisp_get_decent_map_resolver ( eid ) :
 ii = lisp_get_decent_index ( eid )
 I1Iii = str ( ii ) + "." + lisp_decent_dns_suffix
 if 5 - 5: II111iiii
 lprint ( "Use LISP-Decent map-resolver {} for EID {}" . format ( bold ( I1Iii , False ) , eid . print_prefix ( ) ) )
 if 100 - 100: O0 * iIii1I11I1II1 - OoooooooOO
 if 41 - 41: OoO0O00 / OoooooooOO
 oOoo0OOOO0OO = None
 for OOO0o0o in lisp_map_resolvers_list . values ( ) :
  if ( I1Iii != OOO0o0o . dns_name ) : continue
  if ( oOoo0OOOO0OO == None or OOO0o0o . last_used < oOoo0OOOO0OO . last_used ) : oOoo0OOOO0OO = OOO0o0o
  if 61 - 61: ooOoO0o
 return ( oOoo0OOOO0OO )
 if 4 - 4: Oo0Ooo + oO0o + oO0o
 if 79 - 79: OoooooooOO
 if 98 - 98: O0 . ooOoO0o * I1Ii111
 if 98 - 98: ooOoO0o + o0oOOo0O0Ooo / I11i - Ii1I * II111iiii + i1IIi
 if 10 - 10: oO0o
 if 8 - 8: I1ii11iIi11i * OOooOOo * iIii1I11I1II1 + I11i . iII111i
 if 55 - 55: I1IiiI + Ii1I % I1ii11iIi11i + iIii1I11I1II1
def lisp_ipv4_input ( packet ) :
 if 64 - 64: i1IIi / O0 - oO0o
 if 7 - 7: IiII . IiII * Ii1I
 if 1 - 1: i11iIiiIii
 if 91 - 91: I1ii11iIi11i . OoO0O00 / OoO0O00 / I1ii11iIi11i + iII111i
 if ( ord ( packet [ 9 ] ) == 2 ) : return ( [ True , packet ] )
 if 20 - 20: o0oOOo0O0Ooo . I1Ii111 + O0
 if 99 - 99: O0 / IiII . oO0o
 if 18 - 18: OoooooooOO * OoO0O00 * I1Ii111
 if 12 - 12: i11iIiiIii / iIii1I11I1II1 . I11i % I1Ii111 * ooOoO0o % ooOoO0o
 Iiiii111 = struct . unpack ( "H" , packet [ 10 : 12 ] ) [ 0 ]
 if ( Iiiii111 == 0 ) :
  dprint ( "Packet arrived with checksum of 0!" )
 else :
  packet = lisp_ip_checksum ( packet )
  Iiiii111 = struct . unpack ( "H" , packet [ 10 : 12 ] ) [ 0 ]
  if ( Iiiii111 != 0 ) :
   dprint ( "IPv4 header checksum failed for inner header" )
   packet = lisp_format_packet ( packet [ 0 : 20 ] )
   dprint ( "Packet header: {}" . format ( packet ) )
   return ( [ False , None ] )
   if 13 - 13: i1IIi . ooOoO0o . ooOoO0o
   if 24 - 24: iIii1I11I1II1
   if 72 - 72: i11iIiiIii + o0oOOo0O0Ooo % ooOoO0o * I1ii11iIi11i . i1IIi
   if 59 - 59: OoooooooOO - OoooooooOO - o0oOOo0O0Ooo + i1IIi % I1Ii111
   if 74 - 74: IiII * iIii1I11I1II1 - I1IiiI
   if 62 - 62: o0oOOo0O0Ooo
   if 54 - 54: iIii1I11I1II1 / OoooooooOO + o0oOOo0O0Ooo . i1IIi - OoooooooOO
 I1i = struct . unpack ( "B" , packet [ 8 : 9 ] ) [ 0 ]
 if ( I1i == 0 ) :
  dprint ( "IPv4 packet arrived with ttl 0, packet discarded" )
  return ( [ False , None ] )
 elif ( I1i == 1 ) :
  dprint ( "IPv4 packet {}, packet discarded" . format ( bold ( "ttl expiry" , False ) ) )
  if 70 - 70: Ii1I / OoOoOO00 * Oo0Ooo
  return ( [ False , None ] )
  if 32 - 32: I1Ii111 . OoOoOO00 % OoooooooOO + I1Ii111 * OoO0O00
  if 84 - 84: OoOoOO00
 I1i -= 1
 packet = packet [ 0 : 8 ] + struct . pack ( "B" , I1i ) + packet [ 9 : : ]
 packet = packet [ 0 : 10 ] + struct . pack ( "H" , 0 ) + packet [ 12 : : ]
 packet = lisp_ip_checksum ( packet )
 return ( [ False , packet ] )
 if 80 - 80: oO0o
 if 59 - 59: iIii1I11I1II1 / IiII % I1ii11iIi11i + OoO0O00 - I11i % OOooOOo
 if 92 - 92: iII111i
 if 96 - 96: OoOoOO00 / OoOoOO00 / OoOoOO00 + OoooooooOO + Oo0Ooo
 if 91 - 91: OoOoOO00 + II111iiii / I11i * iIii1I11I1II1
 if 92 - 92: I1Ii111 - IiII / IiII
 if 42 - 42: IiII
def lisp_ipv6_input ( packet ) :
 iI1i1iI1iI = packet . inner_dest
 packet = packet . packet
 if 7 - 7: iIii1I11I1II1
 if 35 - 35: IiII + O0 % I1Ii111 - I1ii11iIi11i - i1IIi
 if 100 - 100: I1Ii111 + i11iIiiIii - IiII / I1ii11iIi11i / iII111i
 if 56 - 56: iII111i
 if 91 - 91: Oo0Ooo . I11i . I1ii11iIi11i
 I1i = struct . unpack ( "B" , packet [ 7 : 8 ] ) [ 0 ]
 if ( I1i == 0 ) :
  dprint ( "IPv6 packet arrived with hop-limit 0, packet discarded" )
  return ( None )
 elif ( I1i == 1 ) :
  dprint ( "IPv6 packet {}, packet discarded" . format ( bold ( "ttl expiry" , False ) ) )
  if 60 - 60: i11iIiiIii - OOooOOo
  return ( None )
  if 78 - 78: I1IiiI * ooOoO0o % iIii1I11I1II1 / I1ii11iIi11i
  if 61 - 61: I1Ii111 . Ii1I + OoooooooOO
  if 98 - 98: OOooOOo . ooOoO0o . OoOoOO00 - I1Ii111 . i1IIi - iIii1I11I1II1
  if 89 - 89: II111iiii * I1ii11iIi11i - I1IiiI
  if 58 - 58: Ii1I / Oo0Ooo % IiII
 if ( iI1i1iI1iI . is_ipv6_link_local ( ) ) :
  dprint ( "Do not encapsulate IPv6 link-local packets" )
  return ( None )
  if 33 - 33: II111iiii . OOooOOo % iIii1I11I1II1 - Oo0Ooo - OoOoOO00 % i11iIiiIii
  if 60 - 60: iII111i . o0oOOo0O0Ooo
 I1i -= 1
 packet = packet [ 0 : 7 ] + struct . pack ( "B" , I1i ) + packet [ 8 : : ]
 return ( packet )
 if 56 - 56: I1ii11iIi11i
 if 89 - 89: Oo0Ooo + I1ii11iIi11i * o0oOOo0O0Ooo * oO0o % O0 % OoO0O00
 if 70 - 70: o0oOOo0O0Ooo + O0 % I1IiiI
 if 56 - 56: Ii1I
 if 84 - 84: iII111i
 if 21 - 21: i11iIiiIii
 if 30 - 30: OoO0O00 + OoooooooOO
 if 98 - 98: I1ii11iIi11i % I1IiiI
def lisp_mac_input ( packet ) :
 return ( packet )
 if 9 - 9: o0oOOo0O0Ooo / I1Ii111 % i1IIi - OOooOOo % I1IiiI / I1ii11iIi11i
 if 66 - 66: IiII
 if 56 - 56: oO0o + OoooooooOO
 if 75 - 75: O0 % Ii1I
 if 47 - 47: OoooooooOO - OoooooooOO + OoO0O00 / iIii1I11I1II1
 if 23 - 23: iII111i / iIii1I11I1II1
 if 5 - 5: O0
 if 64 - 64: i1IIi * i1IIi . iII111i - O0 - oO0o % OoooooooOO
 if 14 - 14: Ii1I % OoO0O00 % I1Ii111 * O0
def lisp_rate_limit_map_request ( source , dest ) :
 if ( lisp_last_map_request_sent == None ) : return ( False )
 Ii1I1I11I11 = lisp_get_timestamp ( )
 ooOO0o = Ii1I1I11I11 - lisp_last_map_request_sent
 ii1iIiIIi = ( ooOO0o < LISP_MAP_REQUEST_RATE_LIMIT )
 if 63 - 63: i11iIiiIii / oO0o % O0
 if ( ii1iIiIIi ) :
  if ( source != None ) : source = source . print_address ( )
  dest = dest . print_address ( )
  dprint ( "Rate-limiting Map-Request for {} -> {}" . format ( source , dest ) )
  if 70 - 70: IiII * I11i . iII111i . I1IiiI % iIii1I11I1II1 * OoooooooOO
 return ( ii1iIiIIi )
 if 51 - 51: O0 * Oo0Ooo - OoooooooOO % OoOoOO00 . I1ii11iIi11i
 if 44 - 44: ooOoO0o / IiII + O0 . II111iiii
 if 12 - 12: Oo0Ooo
 if 54 - 54: OoOoOO00 . O0 % I1ii11iIi11i - II111iiii % I11i
 if 34 - 34: OoOoOO00 % ooOoO0o * I1IiiI % IiII
 if 62 - 62: OoooooooOO . OoooooooOO / I11i % OoOoOO00
 if 2 - 2: IiII % I1ii11iIi11i * OoO0O00 + Oo0Ooo * iII111i
def lisp_send_map_request ( lisp_sockets , lisp_ephem_port , seid , deid , rloc ) :
 global lisp_last_map_request_sent
 if 85 - 85: OOooOOo * I1IiiI - iIii1I11I1II1 - OoOoOO00 + ooOoO0o . OoO0O00
 if 46 - 46: OoO0O00 * I1Ii111 . O0
 if 86 - 86: i11iIiiIii . Ii1I / OoOoOO00 / I11i * i1IIi
 if 40 - 40: o0oOOo0O0Ooo
 if 33 - 33: i11iIiiIii + I1Ii111 % I1ii11iIi11i - I1Ii111 * OoO0O00
 if 1 - 1: II111iiii / I1IiiI + II111iiii % II111iiii - I1Ii111
 I1iII = I1Iooo0Ooo00O0O = None
 if ( rloc ) :
  I1iII = rloc . rloc
  I1Iooo0Ooo00O0O = rloc . translated_port if lisp_i_am_rtr else LISP_DATA_PORT
  if 47 - 47: O0 % oO0o + ooOoO0o
  if 65 - 65: iII111i
  if 3 - 3: iIii1I11I1II1
  if 25 - 25: OOooOOo * OoO0O00 + o0oOOo0O0Ooo % Ii1I - o0oOOo0O0Ooo - iII111i
  if 17 - 17: O0 . ooOoO0o % I1IiiI . iII111i / oO0o . IiII
 O0Ii11II111 , OO0OOOoOooo0 , I1i1II1 = lisp_myrlocs
 if ( O0Ii11II111 == None ) :
  lprint ( "Suppress sending Map-Request, IPv4 RLOC not found" )
  return
  if 83 - 83: I1Ii111 % ooOoO0o + OoooooooOO
 if ( OO0OOOoOooo0 == None and I1iII != None and I1iII . is_ipv6 ( ) ) :
  lprint ( "Suppress sending Map-Request, IPv6 RLOC not found" )
  return
  if 50 - 50: i11iIiiIii % I1IiiI * iII111i / Ii1I
  if 12 - 12: iII111i / OoO0O00 - II111iiii + Oo0Ooo
 ooo = lisp_map_request ( )
 ooo . record_count = 1
 ooo . nonce = lisp_get_control_nonce ( )
 ooo . rloc_probe = ( I1iII != None )
 if 78 - 78: i1IIi
 if 25 - 25: Ii1I * II111iiii / OoOoOO00
 if 86 - 86: i1IIi + I1IiiI + I1Ii111 % II111iiii . IiII - iIii1I11I1II1
 if 54 - 54: i11iIiiIii . Ii1I % I1IiiI . I1Ii111 . OoooooooOO
 if 49 - 49: OOooOOo % I11i - OOooOOo + Ii1I . I1ii11iIi11i + ooOoO0o
 if 15 - 15: i11iIiiIii
 if 85 - 85: I1Ii111 + iII111i - oO0o
 if ( rloc ) : rloc . last_rloc_probe_nonce = ooo . nonce
 if 59 - 59: IiII . oO0o / i11iIiiIii . I1Ii111
 iIiiIi1111ii = deid . is_multicast_address ( )
 if ( iIiiIi1111ii ) :
  ooo . target_eid = seid
  ooo . target_group = deid
 else :
  ooo . target_eid = deid
  if 64 - 64: OoOoOO00
  if 20 - 20: OoOoOO00 / O0 * OOooOOo % I11i + OoO0O00 + o0oOOo0O0Ooo
  if 51 - 51: Ii1I - OoOoOO00 / i11iIiiIii + O0
  if 71 - 71: ooOoO0o
  if 35 - 35: OoOoOO00
  if 55 - 55: iII111i - o0oOOo0O0Ooo + IiII * II111iiii
  if 6 - 6: I1Ii111 / i1IIi / IiII . o0oOOo0O0Ooo
  if 69 - 69: ooOoO0o - OoOoOO00 . I1IiiI . I11i + OoOoOO00 / i11iIiiIii
  if 20 - 20: OoO0O00 . OoooooooOO - ooOoO0o . I11i / Oo0Ooo
 if ( ooo . rloc_probe == False ) :
  o0o0O0OO0oO = lisp_get_signature_eid ( )
  if ( o0o0O0OO0oO ) :
   ooo . signature_eid . copy_address ( o0o0O0OO0oO . eid )
   ooo . privkey_filename = "./lisp-sig.pem"
   if 89 - 89: iIii1I11I1II1 . ooOoO0o
   if 82 - 82: OoOoOO00 - II111iiii . OoO0O00 * ooOoO0o
   if 78 - 78: OoOoOO00 % oO0o
   if 39 - 39: iIii1I11I1II1
   if 72 - 72: II111iiii + I1Ii111 / Ii1I * iIii1I11I1II1
   if 95 - 95: OoooooooOO + OOooOOo + II111iiii + IiII + OoO0O00
 if ( seid == None or iIiiIi1111ii ) :
  ooo . source_eid . afi = LISP_AFI_NONE
 else :
  ooo . source_eid = seid
  if 86 - 86: II111iiii / iII111i - I1ii11iIi11i
  if 65 - 65: I1ii11iIi11i + OoOoOO00
  if 43 - 43: O0 + I11i % II111iiii
  if 56 - 56: IiII + Oo0Ooo . IiII % iIii1I11I1II1 % ooOoO0o % ooOoO0o
  if 70 - 70: ooOoO0o / i1IIi - I11i - i11iIiiIii
  if 79 - 79: OoO0O00 - OoooooooOO % iII111i . O0
  if 93 - 93: I1Ii111
  if 3 - 3: OoO0O00 / IiII - oO0o / oO0o
  if 50 - 50: II111iiii + OoOoOO00
  if 17 - 17: ooOoO0o + I1ii11iIi11i
  if 34 - 34: Ii1I / II111iiii + OoOoOO00 . II111iiii + OoooooooOO * o0oOOo0O0Ooo
  if 48 - 48: O0
 if ( I1iII != None and lisp_nat_traversal and lisp_i_am_rtr == False ) :
  if ( I1iII . is_private_address ( ) == False ) :
   O0Ii11II111 = lisp_get_any_translated_rloc ( )
   if 99 - 99: II111iiii * oO0o / I1ii11iIi11i - i1IIi
  if ( O0Ii11II111 == None ) :
   lprint ( "Suppress sending Map-Request, translated RLOC not found" )
   return
   if 84 - 84: i11iIiiIii . OoooooooOO
   if 69 - 69: I1Ii111 * II111iiii % I1Ii111 * i11iIiiIii . ooOoO0o / Oo0Ooo
   if 5 - 5: Ii1I
   if 19 - 19: oO0o
   if 61 - 61: OoOoOO00 + iIii1I11I1II1 / I1ii11iIi11i - i1IIi
   if 11 - 11: oO0o * o0oOOo0O0Ooo . I1IiiI
   if 12 - 12: I1IiiI % OoO0O00 / I1Ii111 / O0 % o0oOOo0O0Ooo
   if 1 - 1: OoOoOO00 / I11i
 if ( I1iII == None or I1iII . is_ipv4 ( ) ) :
  if ( lisp_nat_traversal and I1iII == None ) :
   IIiii1IIi = lisp_get_any_translated_rloc ( )
   if ( IIiii1IIi != None ) : O0Ii11II111 = IIiii1IIi
   if 69 - 69: i11iIiiIii - iIii1I11I1II1
  ooo . itr_rlocs . append ( O0Ii11II111 )
  if 40 - 40: I1IiiI / oO0o + ooOoO0o
 if ( I1iII == None or I1iII . is_ipv6 ( ) ) :
  if ( OO0OOOoOooo0 == None or OO0OOOoOooo0 . is_ipv6_link_local ( ) ) :
   OO0OOOoOooo0 = None
  else :
   ooo . itr_rloc_count = 1 if ( I1iII == None ) else 0
   ooo . itr_rlocs . append ( OO0OOOoOooo0 )
   if 100 - 100: OoOoOO00 % iII111i * ooOoO0o . O0
   if 37 - 37: I1ii11iIi11i
   if 24 - 24: O0 . I1Ii111 * i11iIiiIii
   if 84 - 84: ooOoO0o / I1ii11iIi11i - o0oOOo0O0Ooo . OoooooooOO * iIii1I11I1II1
   if 16 - 16: I11i % O0
   if 56 - 56: Ii1I * OoOoOO00 . i1IIi
   if 15 - 15: I1Ii111
   if 64 - 64: OOooOOo * Oo0Ooo
   if 96 - 96: Oo0Ooo / I1ii11iIi11i * iIii1I11I1II1 / iII111i
 if ( I1iII != None and ooo . itr_rlocs != [ ] ) :
  i1IiiIIi1Ii = ooo . itr_rlocs [ 0 ]
 else :
  if ( deid . is_ipv4 ( ) ) :
   i1IiiIIi1Ii = O0Ii11II111
  elif ( deid . is_ipv6 ( ) ) :
   i1IiiIIi1Ii = OO0OOOoOooo0
  else :
   i1IiiIIi1Ii = O0Ii11II111
   if 18 - 18: I1Ii111
   if 29 - 29: i1IIi - I1IiiI / i1IIi
   if 64 - 64: IiII
   if 69 - 69: OOooOOo . I1IiiI
   if 11 - 11: I1Ii111 * I1IiiI - I1Ii111 / iII111i
   if 22 - 22: iII111i % I11i % O0 - I11i
 Oo0O0oo = ooo . encode ( I1iII , I1Iooo0Ooo00O0O )
 ooo . print_map_request ( )
 if 71 - 71: I1Ii111 / II111iiii - OoooooooOO % i1IIi + OoOoOO00 % OoooooooOO
 if 52 - 52: Ii1I . OoOoOO00 / o0oOOo0O0Ooo / iII111i
 if 83 - 83: OoO0O00 - Oo0Ooo + I1Ii111 . I1IiiI
 if 78 - 78: I11i / ooOoO0o . OoOoOO00 * i1IIi
 if 15 - 15: i1IIi . II111iiii * OoOoOO00 / Oo0Ooo
 if 99 - 99: iII111i - o0oOOo0O0Ooo / O0
 if ( I1iII != None ) :
  if ( rloc . is_rloc_translated ( ) ) :
   Oo0Oo = lisp_get_nat_info ( I1iII , rloc . rloc_name )
   if 97 - 97: iIii1I11I1II1 * I1Ii111
   if 39 - 39: I1Ii111 . II111iiii
   if 94 - 94: OoO0O00 - OoO0O00 + iIii1I11I1II1 + O0 * oO0o
   if 9 - 9: Ii1I * Oo0Ooo / oO0o / Ii1I
   if ( Oo0Oo == None ) :
    IIi = rloc . rloc . print_address_no_iid ( )
    IiIoO0oo0 = "gleaned-{}" . format ( IIi )
    IiIiI1 = rloc . translated_port
    Oo0Oo = lisp_nat_info ( IIi , IiIoO0oo0 , IiIiI1 )
    if 34 - 34: I1IiiI
   lisp_encapsulate_rloc_probe ( lisp_sockets , I1iII , Oo0Oo ,
 Oo0O0oo )
   return
   if 56 - 56: Ii1I
   if 71 - 71: O0 / i1IIi
  I1IIII1i1 = I1iII . print_address_no_iid ( )
  iI1i1iI1iI = lisp_convert_4to6 ( I1IIII1i1 )
  lisp_send ( lisp_sockets , iI1i1iI1iI , LISP_CTRL_PORT , Oo0O0oo )
  return
  if 20 - 20: OOooOOo . iIii1I11I1II1 - I1Ii111 . i1IIi
  if 82 - 82: oO0o * i11iIiiIii % o0oOOo0O0Ooo % IiII - I11i - OoO0O00
  if 24 - 24: oO0o . II111iiii + OoO0O00 * I1ii11iIi11i / oO0o
  if 86 - 86: I1Ii111 + I1ii11iIi11i
  if 63 - 63: ooOoO0o - i11iIiiIii . o0oOOo0O0Ooo - i1IIi - IiII
  if 32 - 32: I1Ii111 / iIii1I11I1II1 + oO0o % I11i * OoooooooOO
 ooo0oOoooO = None if lisp_i_am_rtr else seid
 if ( lisp_decent_pull_xtr_configured ( ) ) :
  OOO0o0o = lisp_get_decent_map_resolver ( deid )
 else :
  OOO0o0o = lisp_get_map_resolver ( None , ooo0oOoooO )
  if 96 - 96: O0 * I1ii11iIi11i . IiII + ooOoO0o % ooOoO0o + Oo0Ooo
 if ( OOO0o0o == None ) :
  lprint ( "Cannot find Map-Resolver for source-EID {}" . format ( green ( seid . print_address ( ) , False ) ) )
  if 83 - 83: I1Ii111 % oO0o % oO0o . I1Ii111 % I1ii11iIi11i
  return
  if 57 - 57: o0oOOo0O0Ooo . OoOoOO00 . OoooooooOO
 OOO0o0o . last_used = lisp_get_timestamp ( )
 OOO0o0o . map_requests_sent += 1
 if ( OOO0o0o . last_nonce == 0 ) : OOO0o0o . last_nonce = ooo . nonce
 if 17 - 17: i11iIiiIii
 if 53 - 53: IiII - I1Ii111 - OOooOOo . OoOoOO00 / iIii1I11I1II1
 if 89 - 89: Oo0Ooo
 if 57 - 57: i1IIi - oO0o % IiII . I11i
 if ( seid == None ) : seid = i1IiiIIi1Ii
 lisp_send_ecm ( lisp_sockets , Oo0O0oo , seid , lisp_ephem_port , deid ,
 OOO0o0o . map_resolver )
 if 17 - 17: i1IIi % OoO0O00 + i11iIiiIii % I1Ii111 * ooOoO0o . I1ii11iIi11i
 if 64 - 64: O0 - iII111i
 if 82 - 82: O0
 if 37 - 37: I1Ii111
 lisp_last_map_request_sent = lisp_get_timestamp ( )
 if 98 - 98: iII111i - OoOoOO00 / I1Ii111 . OOooOOo - OOooOOo - ooOoO0o
 if 84 - 84: OOooOOo * ooOoO0o / O0
 if 96 - 96: I11i . I11i % II111iiii
 if 14 - 14: iII111i / OoooooooOO
 OOO0o0o . resolve_dns_name ( )
 return
 if 8 - 8: OOooOOo + I1IiiI - Oo0Ooo + i1IIi . Ii1I . I1Ii111
 if 38 - 38: I1IiiI / II111iiii * OoOoOO00 / I1Ii111
 if 80 - 80: I1ii11iIi11i / ooOoO0o * ooOoO0o . Oo0Ooo
 if 44 - 44: Ii1I * i1IIi % OoOoOO00 . OoOoOO00
 if 16 - 16: Oo0Ooo / i1IIi / iIii1I11I1II1 / iIii1I11I1II1 % o0oOOo0O0Ooo / I1ii11iIi11i
 if 11 - 11: I1IiiI
 if 45 - 45: OOooOOo / i1IIi * IiII * I1Ii111
 if 34 - 34: ooOoO0o / iIii1I11I1II1 . iII111i
def lisp_send_info_request ( lisp_sockets , dest , port , device_name ) :
 if 91 - 91: OoO0O00
 if 8 - 8: oO0o
 if 96 - 96: IiII
 if 37 - 37: Ii1I % i11iIiiIii + iIii1I11I1II1 % Oo0Ooo - iIii1I11I1II1
 iIiO00OooOoOO0o0 = lisp_info ( )
 iIiO00OooOoOO0o0 . nonce = lisp_get_control_nonce ( )
 if ( device_name ) : iIiO00OooOoOO0o0 . hostname += "-" + device_name
 if 67 - 67: I11i + oO0o + iII111i . ooOoO0o + I11i
 I1IIII1i1 = dest . print_address_no_iid ( )
 if 43 - 43: OoOoOO00
 if 81 - 81: ooOoO0o * OOooOOo / OoO0O00 + I1ii11iIi11i % I1Ii111
 if 37 - 37: i11iIiiIii - OoooooooOO - OoOoOO00 * oO0o / Ii1I
 if 100 - 100: II111iiii / Oo0Ooo / iII111i / OOooOOo
 if 100 - 100: iIii1I11I1II1
 if 50 - 50: I1Ii111 / ooOoO0o * I11i
 if 53 - 53: II111iiii . IiII
 if 5 - 5: i1IIi % IiII
 if 16 - 16: ooOoO0o - iII111i % Ii1I . OoOoOO00
 if 56 - 56: i11iIiiIii % i11iIiiIii % OoooooooOO . Ii1I . iII111i + I11i
 if 64 - 64: O0
 if 37 - 37: o0oOOo0O0Ooo / O0
 if 58 - 58: I1Ii111 + OoooooooOO + iIii1I11I1II1
 if 13 - 13: o0oOOo0O0Ooo . I11i / O0
 if 39 - 39: I11i + oO0o + ooOoO0o % ooOoO0o - I1IiiI % Oo0Ooo
 if 9 - 9: IiII / iII111i * II111iiii + O0 % Oo0Ooo / i1IIi
 IIiiII1iIiI = False
 if ( device_name ) :
  i1iiii1iiIiII = lisp_get_host_route_next_hop ( I1IIII1i1 )
  if 13 - 13: i11iIiiIii - i1IIi / iII111i + O0 . iII111i
  if 65 - 65: oO0o + Oo0Ooo / OoO0O00
  if 5 - 5: I11i % II111iiii - ooOoO0o
  if 98 - 98: O0 % OOooOOo
  if 9 - 9: I1ii11iIi11i / I1ii11iIi11i - OOooOOo . iIii1I11I1II1
  if 33 - 33: I1IiiI + oO0o % I1IiiI / iII111i - ooOoO0o - i11iIiiIii
  if 39 - 39: i11iIiiIii / oO0o
  if 71 - 71: I1Ii111 * iIii1I11I1II1 - I1Ii111
  if 87 - 87: I1IiiI / Ii1I
  if ( port == LISP_CTRL_PORT and i1iiii1iiIiII != None ) :
   while ( True ) :
    time . sleep ( .01 )
    i1iiii1iiIiII = lisp_get_host_route_next_hop ( I1IIII1i1 )
    if ( i1iiii1iiIiII == None ) : break
    if 54 - 54: OoooooooOO / Ii1I
    if 26 - 26: o0oOOo0O0Ooo + OoO0O00
    if 59 - 59: Ii1I * IiII
  o0OiiI1iiI11 = lisp_get_default_route_next_hops ( )
  for I1i1II1 , oOoo in o0OiiI1iiI11 :
   if ( I1i1II1 != device_name ) : continue
   if 3 - 3: I11i
   if 55 - 55: OoO0O00 . i11iIiiIii . o0oOOo0O0Ooo % iIii1I11I1II1 . I1ii11iIi11i * I11i
   if 7 - 7: OoOoOO00 * iII111i - i11iIiiIii
   if 79 - 79: OOooOOo
   if 2 - 2: I11i % I1Ii111 - OoO0O00 % OoO0O00 % OOooOOo - OoO0O00
   if 3 - 3: iIii1I11I1II1 + iIii1I11I1II1 + OoO0O00
   if ( i1iiii1iiIiII != oOoo ) :
    if ( i1iiii1iiIiII != None ) :
     lisp_install_host_route ( I1IIII1i1 , i1iiii1iiIiII , False )
     if 59 - 59: iII111i
    lisp_install_host_route ( I1IIII1i1 , oOoo , True )
    IIiiII1iIiI = True
    if 7 - 7: o0oOOo0O0Ooo * OoooooooOO - Ii1I * II111iiii % I1Ii111
   break
   if 82 - 82: OoOoOO00 - OoOoOO00 + iIii1I11I1II1 + o0oOOo0O0Ooo + IiII - o0oOOo0O0Ooo
   if 65 - 65: I1Ii111 + OOooOOo
   if 97 - 97: oO0o % OoOoOO00 * oO0o % II111iiii + iIii1I11I1II1
   if 11 - 11: ooOoO0o . o0oOOo0O0Ooo
   if 94 - 94: ooOoO0o . oO0o * OoooooooOO % oO0o
   if 77 - 77: ooOoO0o % I1IiiI
 Oo0O0oo = iIiO00OooOoOO0o0 . encode ( )
 iIiO00OooOoOO0o0 . print_info ( )
 if 26 - 26: o0oOOo0O0Ooo
 if 72 - 72: I1IiiI
 if 90 - 90: ooOoO0o
 if 67 - 67: iIii1I11I1II1 + i1IIi * I1IiiI * OoooooooOO
 ii1II11iIIII = "(for control)" if port == LISP_CTRL_PORT else "(for data)"
 ii1II11iIIII = bold ( ii1II11iIIII , False )
 IiIiI1 = bold ( "{}" . format ( port ) , False )
 iiiii1ii1 = red ( I1IIII1i1 , False )
 I111iI1I1i1 = "RTR " if port == LISP_DATA_PORT else "MS "
 lprint ( "Send Info-Request to {}{}, port {} {}" . format ( I111iI1I1i1 , iiiii1ii1 , IiIiI1 , ii1II11iIIII ) )
 if 52 - 52: Ii1I / OoooooooOO % i11iIiiIii + iII111i
 if 59 - 59: Ii1I / o0oOOo0O0Ooo / oO0o + iII111i * I1ii11iIi11i - o0oOOo0O0Ooo
 if 70 - 70: O0 / I1ii11iIi11i + ooOoO0o . OoO0O00 - OoO0O00 / i11iIiiIii
 if 1 - 1: iIii1I11I1II1 % I1ii11iIi11i
 if 49 - 49: iII111i + o0oOOo0O0Ooo % I1ii11iIi11i . O0 % OoooooooOO . o0oOOo0O0Ooo
 if 3 - 3: i11iIiiIii - i1IIi * o0oOOo0O0Ooo / OoOoOO00 % Oo0Ooo
 if ( port == LISP_CTRL_PORT ) :
  lisp_send ( lisp_sockets , dest , LISP_CTRL_PORT , Oo0O0oo )
 else :
  o0OO0 = lisp_data_header ( )
  o0OO0 . instance_id ( 0xffffff )
  o0OO0 = o0OO0 . encode ( )
  if ( o0OO0 ) :
   Oo0O0oo = o0OO0 + Oo0O0oo
   if 65 - 65: OoooooooOO + iII111i - i11iIiiIii - IiII + oO0o
   if 67 - 67: i1IIi * I1Ii111 * O0
   if 16 - 16: OoO0O00 + iII111i + i1IIi + I1ii11iIi11i - I1IiiI
   if 88 - 88: oO0o % iII111i + I1ii11iIi11i - II111iiii . I11i
   if 18 - 18: I1ii11iIi11i - i1IIi - IiII * II111iiii % I1Ii111 . II111iiii
   if 80 - 80: oO0o + OoO0O00 + o0oOOo0O0Ooo . OoOoOO00
   if 75 - 75: i11iIiiIii
   if 58 - 58: iII111i
   if 48 - 48: OoO0O00 * OOooOOo / iII111i
   lisp_send ( lisp_sockets , dest , LISP_DATA_PORT , Oo0O0oo )
   if 90 - 90: I1IiiI * i11iIiiIii . OOooOOo / o0oOOo0O0Ooo
   if 82 - 82: Oo0Ooo
   if 50 - 50: I1Ii111 * OOooOOo * OoOoOO00 / OoooooooOO % iII111i
   if 80 - 80: I1Ii111
   if 35 - 35: Ii1I . O0 % i11iIiiIii * oO0o - OoooooooOO
   if 87 - 87: iII111i * ooOoO0o - OOooOOo . O0
   if 20 - 20: OoOoOO00 - IiII
 if ( IIiiII1iIiI ) :
  lisp_install_host_route ( I1IIII1i1 , None , False )
  if ( i1iiii1iiIiII != None ) : lisp_install_host_route ( I1IIII1i1 , i1iiii1iiIiII , True )
  if 9 - 9: O0 . I11i % I1ii11iIi11i * oO0o - I1Ii111 - i1IIi
 return
 if 66 - 66: II111iiii / Oo0Ooo
 if 93 - 93: iII111i + I11i * OoooooooOO . OoO0O00
 if 40 - 40: ooOoO0o * I1Ii111 + iII111i
 if 52 - 52: iII111i % I11i
 if 95 - 95: IiII + Ii1I / OoO0O00 - iII111i / I1IiiI
 if 27 - 27: Oo0Ooo + i1IIi + i11iIiiIii . OoO0O00 . OoO0O00
 if 56 - 56: I1Ii111 / OoO0O00 + o0oOOo0O0Ooo . OoooooooOO * Oo0Ooo
def lisp_process_info_request ( lisp_sockets , packet , addr_str , sport , rtr_list ) :
 if 14 - 14: OoO0O00
 if 21 - 21: II111iiii + i11iIiiIii + I11i % I1IiiI
 if 65 - 65: IiII + I1ii11iIi11i / iII111i / I1IiiI + Ii1I
 if 88 - 88: IiII % iIii1I11I1II1
 iIiO00OooOoOO0o0 = lisp_info ( )
 packet = iIiO00OooOoOO0o0 . decode ( packet )
 if ( packet == None ) : return
 iIiO00OooOoOO0o0 . print_info ( )
 if 3 - 3: ooOoO0o / I1Ii111 % iIii1I11I1II1 % I11i * oO0o / iIii1I11I1II1
 if 75 - 75: i11iIiiIii . iII111i
 if 68 - 68: OOooOOo . I1ii11iIi11i % I1ii11iIi11i . i11iIiiIii
 if 45 - 45: oO0o % I1ii11iIi11i * I1Ii111
 if 21 - 21: O0 + i11iIiiIii
 iIiO00OooOoOO0o0 . info_reply = True
 iIiO00OooOoOO0o0 . global_etr_rloc . store_address ( addr_str )
 iIiO00OooOoOO0o0 . etr_port = sport
 if 72 - 72: OoOoOO00 * OoooooooOO % O0 / I1ii11iIi11i % Ii1I - I11i
 if 65 - 65: iIii1I11I1II1 + II111iiii * OoO0O00 * i11iIiiIii / IiII
 if 15 - 15: OoOoOO00 % O0 - OOooOOo - oO0o . iII111i . OoO0O00
 if 52 - 52: II111iiii * o0oOOo0O0Ooo
 if 95 - 95: I1Ii111 - OoooooooOO
 if ( iIiO00OooOoOO0o0 . hostname != None ) :
  iIiO00OooOoOO0o0 . private_etr_rloc . afi = LISP_AFI_NAME
  iIiO00OooOoOO0o0 . private_etr_rloc . store_address ( iIiO00OooOoOO0o0 . hostname )
  if 99 - 99: OoooooooOO % IiII . I11i + OoooooooOO
  if 57 - 57: Ii1I / I1IiiI * i1IIi
 if ( rtr_list != None ) : iIiO00OooOoOO0o0 . rtr_list = rtr_list
 packet = iIiO00OooOoOO0o0 . encode ( )
 iIiO00OooOoOO0o0 . print_info ( )
 if 21 - 21: I11i . O0 * OoooooooOO + ooOoO0o * oO0o % i11iIiiIii
 if 30 - 30: ooOoO0o * I1Ii111 + OoO0O00
 if 30 - 30: Ii1I / iII111i * Ii1I
 if 11 - 11: OoOoOO00 - OoOoOO00 % oO0o
 if 3 - 3: I1IiiI - OoooooooOO % iIii1I11I1II1 + I1Ii111 + OoOoOO00
 lprint ( "Send Info-Reply to {}" . format ( red ( addr_str , False ) ) )
 iI1i1iI1iI = lisp_convert_4to6 ( addr_str )
 lisp_send ( lisp_sockets , iI1i1iI1iI , sport , packet )
 if 71 - 71: i1IIi % O0 % ooOoO0o
 if 24 - 24: O0
 if 88 - 88: OoooooooOO / Oo0Ooo / oO0o
 if 99 - 99: I1Ii111 % OoOoOO00 % IiII - Ii1I
 if 79 - 79: ooOoO0o + Oo0Ooo
 OOoO0O0Ooo = lisp_info_source ( iIiO00OooOoOO0o0 . hostname , addr_str , sport )
 OOoO0O0Ooo . cache_address_for_info_source ( )
 return
 if 38 - 38: II111iiii
 if 44 - 44: OOooOOo + i11iIiiIii - I1Ii111 + ooOoO0o
 if 92 - 92: O0 . iIii1I11I1II1 % iIii1I11I1II1 % OoO0O00 - i11iIiiIii - iII111i
 if 76 - 76: OoO0O00 . II111iiii / I1ii11iIi11i
 if 15 - 15: OoOoOO00 . O0 + iII111i + I1IiiI . ooOoO0o + iIii1I11I1II1
 if 2 - 2: I11i
 if 52 - 52: i11iIiiIii / oO0o / IiII
 if 84 - 84: I11i . oO0o + ooOoO0o
def lisp_get_signature_eid ( ) :
 for o0o0O0OO0oO in lisp_db_list :
  if ( o0o0O0OO0oO . signature_eid ) : return ( o0o0O0OO0oO )
  if 75 - 75: I1Ii111
 return ( None )
 if 97 - 97: ooOoO0o % Oo0Ooo . o0oOOo0O0Ooo
 if 22 - 22: O0 % I11i + OoO0O00 - iII111i + I1IiiI . O0
 if 73 - 73: ooOoO0o + O0 - I11i . I1IiiI + OOooOOo
 if 36 - 36: I11i % OoO0O00 * OoOoOO00 - I1Ii111
 if 16 - 16: ooOoO0o % OOooOOo . OoO0O00 % II111iiii . iIii1I11I1II1
 if 21 - 21: oO0o + II111iiii / OoOoOO00 * I11i
 if 90 - 90: OoOoOO00 % OoOoOO00 + I11i
 if 70 - 70: I1IiiI . ooOoO0o / I11i / OoO0O00
def lisp_get_any_translated_port ( ) :
 for o0o0O0OO0oO in lisp_db_list :
  for OoooO00OO in o0o0O0OO0oO . rloc_set :
   if ( OoooO00OO . translated_rloc . is_null ( ) ) : continue
   return ( OoooO00OO . translated_port )
   if 40 - 40: oO0o % iIii1I11I1II1 * iIii1I11I1II1 / Oo0Ooo * OoO0O00
   if 61 - 61: OOooOOo
 return ( None )
 if 80 - 80: I1ii11iIi11i
 if 6 - 6: I1ii11iIi11i + OOooOOo % ooOoO0o
 if 65 - 65: iIii1I11I1II1 % i1IIi / I1IiiI / oO0o % ooOoO0o / I11i
 if 2 - 2: I1ii11iIi11i
 if 90 - 90: II111iiii * I1Ii111 . ooOoO0o - I1ii11iIi11i % I11i * o0oOOo0O0Ooo
 if 85 - 85: iIii1I11I1II1
 if 76 - 76: i11iIiiIii % I1IiiI / I11i
 if 42 - 42: o0oOOo0O0Ooo . I1IiiI + I11i . OoOoOO00 - O0 / Ii1I
 if 66 - 66: IiII + OoOoOO00 + I1IiiI + i1IIi + OoooooooOO % I1IiiI
def lisp_get_any_translated_rloc ( ) :
 for o0o0O0OO0oO in lisp_db_list :
  for OoooO00OO in o0o0O0OO0oO . rloc_set :
   if ( OoooO00OO . translated_rloc . is_null ( ) ) : continue
   return ( OoooO00OO . translated_rloc )
   if 80 - 80: iII111i / O0 % OoooooooOO / Oo0Ooo
   if 75 - 75: ooOoO0o
 return ( None )
 if 72 - 72: oO0o . OoooooooOO % ooOoO0o % OoO0O00 * oO0o * OoO0O00
 if 14 - 14: I11i / I11i
 if 90 - 90: O0 * OOooOOo / oO0o . Oo0Ooo * I11i
 if 93 - 93: oO0o / ooOoO0o - I1Ii111
 if 70 - 70: OOooOOo / Ii1I - ooOoO0o + OoooooooOO / OoO0O00 - i11iIiiIii
 if 26 - 26: O0 + Oo0Ooo
 if 30 - 30: IiII
def lisp_get_all_translated_rlocs ( ) :
 i1I1i1Iiiiiii = [ ]
 for o0o0O0OO0oO in lisp_db_list :
  for OoooO00OO in o0o0O0OO0oO . rloc_set :
   if ( OoooO00OO . is_rloc_translated ( ) == False ) : continue
   ooooO0O = OoooO00OO . translated_rloc . print_address_no_iid ( )
   i1I1i1Iiiiiii . append ( ooooO0O )
   if 19 - 19: Ii1I . I1IiiI - i1IIi * ooOoO0o . iIii1I11I1II1
   if 87 - 87: ooOoO0o % I1ii11iIi11i . I1IiiI
 return ( i1I1i1Iiiiiii )
 if 42 - 42: iII111i % i11iIiiIii % o0oOOo0O0Ooo . O0 % iII111i
 if 72 - 72: Oo0Ooo . Oo0Ooo . IiII . Oo0Ooo
 if 80 - 80: I1Ii111 + IiII + O0 - I1Ii111 . iIii1I11I1II1
 if 53 - 53: OoO0O00 / i11iIiiIii * I1Ii111
 if 62 - 62: oO0o / Oo0Ooo / IiII + I11i * ooOoO0o
 if 84 - 84: ooOoO0o + OoOoOO00 * I1ii11iIi11i % OoooooooOO . O0
 if 27 - 27: OoO0O00 * OoooooooOO - II111iiii / o0oOOo0O0Ooo
 if 76 - 76: I11i % I1Ii111 % iII111i + IiII * iII111i + OoOoOO00
def lisp_update_default_routes ( map_resolver , iid , rtr_list ) :
 O0oIII = ( os . getenv ( "LISP_RTR_BEHIND_NAT" ) != None )
 if 83 - 83: OOooOOo . ooOoO0o / IiII
 O0O0OOOo0 = { }
 for o0OOooooooOO in rtr_list :
  if ( o0OOooooooOO == None ) : continue
  ooooO0O = rtr_list [ o0OOooooooOO ]
  if ( O0oIII and ooooO0O . is_private_address ( ) ) : continue
  O0O0OOOo0 [ o0OOooooooOO ] = ooooO0O
  if 73 - 73: O0 - I1IiiI + I1Ii111 . OoOoOO00 . IiII - OOooOOo
 rtr_list = O0O0OOOo0
 if 13 - 13: i11iIiiIii
 IIi1I1Ii = [ ]
 for I1I1i in [ LISP_AFI_IPV4 , LISP_AFI_IPV6 , LISP_AFI_MAC ] :
  if ( I1I1i == LISP_AFI_MAC and lisp_l2_overlay == False ) : break
  if 37 - 37: ooOoO0o + OOooOOo / I1IiiI + ooOoO0o + I11i - iII111i
  if 46 - 46: OOooOOo - I11i * iIii1I11I1II1 - I1Ii111 % i11iIiiIii
  if 32 - 32: Oo0Ooo * i1IIi . iII111i . iII111i
  if 77 - 77: OOooOOo
  if 74 - 74: O0
  iiIIiI = lisp_address ( I1I1i , "" , 0 , iid )
  iiIIiI . make_default_route ( iiIIiI )
  OoOOO000O0o = lisp_map_cache . lookup_cache ( iiIIiI , True )
  if ( OoOOO000O0o ) :
   if ( OoOOO000O0o . checkpoint_entry ) :
    lprint ( "Updating checkpoint entry for {}" . format ( green ( OoOOO000O0o . print_eid_tuple ( ) , False ) ) )
    if 86 - 86: OoOoOO00
   elif ( OoOOO000O0o . do_rloc_sets_match ( rtr_list . values ( ) ) ) :
    continue
    if 4 - 4: OoooooooOO * OoO0O00
   OoOOO000O0o . delete_cache ( )
   if 93 - 93: OoO0O00 - I1Ii111 - OoO0O00
   if 1 - 1: o0oOOo0O0Ooo . oO0o * i11iIiiIii * IiII - OoO0O00 - OoooooooOO
  IIi1I1Ii . append ( [ iiIIiI , "" ] )
  if 29 - 29: iIii1I11I1II1 + OoO0O00 * II111iiii * Ii1I * iII111i . O0
  if 6 - 6: I1IiiI - OoOoOO00
  if 63 - 63: OOooOOo - oO0o * I1IiiI
  if 60 - 60: II111iiii - Oo0Ooo
  IiI1111i1i11I = lisp_address ( I1I1i , "" , 0 , iid )
  IiI1111i1i11I . make_default_multicast_route ( IiI1111i1i11I )
  iII11iIi = lisp_map_cache . lookup_cache ( IiI1111i1i11I , True )
  if ( iII11iIi ) : iII11iIi = iII11iIi . source_cache . lookup_cache ( iiIIiI , True )
  if ( iII11iIi ) : iII11iIi . delete_cache ( )
  if 94 - 94: i1IIi * O0 * Oo0Ooo . Oo0Ooo
  IIi1I1Ii . append ( [ iiIIiI , IiI1111i1i11I ] )
  if 27 - 27: Oo0Ooo
 if ( len ( IIi1I1Ii ) == 0 ) : return
 if 94 - 94: i1IIi * ooOoO0o / I1IiiI
 if 7 - 7: Oo0Ooo - iIii1I11I1II1 / I1ii11iIi11i * I1IiiI + Ii1I
 if 99 - 99: i11iIiiIii - I1ii11iIi11i
 if 64 - 64: IiII . OoOoOO00 . Oo0Ooo . I1Ii111 / I11i / Ii1I
 O0Oo0O = [ ]
 for I111iI1I1i1 in rtr_list :
  Oo0 = rtr_list [ I111iI1I1i1 ]
  OoooO00OO = lisp_rloc ( )
  OoooO00OO . rloc . copy_address ( Oo0 )
  OoooO00OO . priority = 254
  OoooO00OO . mpriority = 255
  OoooO00OO . rloc_name = "RTR"
  O0Oo0O . append ( OoooO00OO )
  if 80 - 80: iII111i - IiII % I1ii11iIi11i + OoOoOO00
  if 48 - 48: Oo0Ooo - i11iIiiIii / iII111i / Ii1I - Ii1I - OoooooooOO
 for iiIIiI in IIi1I1Ii :
  OoOOO000O0o = lisp_mapping ( iiIIiI [ 0 ] , iiIIiI [ 1 ] , O0Oo0O )
  OoOOO000O0o . mapping_source = map_resolver
  OoOOO000O0o . map_cache_ttl = LISP_MR_TTL * 60
  OoOOO000O0o . add_cache ( )
  lprint ( "Add {} to map-cache with RTR RLOC-set: {}" . format ( green ( OoOOO000O0o . print_eid_tuple ( ) , False ) , rtr_list . keys ( ) ) )
  if 60 - 60: i1IIi
  O0Oo0O = copy . deepcopy ( O0Oo0O )
  if 68 - 68: Ii1I + i1IIi / I1Ii111
 return
 if 49 - 49: OoooooooOO / i1IIi + O0 % i11iIiiIii
 if 20 - 20: Ii1I
 if 100 - 100: OoooooooOO . I1Ii111
 if 32 - 32: iIii1I11I1II1 . iIii1I11I1II1 % II111iiii / Oo0Ooo . iIii1I11I1II1 . O0
 if 63 - 63: I1IiiI . iIii1I11I1II1 . Oo0Ooo % OOooOOo - iII111i + ooOoO0o
 if 64 - 64: o0oOOo0O0Ooo / Ii1I % I1Ii111 % iII111i + OOooOOo * IiII
 if 87 - 87: I1ii11iIi11i . i1IIi - I11i + OoOoOO00 . O0
 if 37 - 37: IiII
 if 65 - 65: ooOoO0o * Ii1I / I1IiiI . i1IIi % ooOoO0o . OoooooooOO
 if 17 - 17: ooOoO0o / OoO0O00 / I1IiiI / OOooOOo % IiII
def lisp_process_info_reply ( source , packet , store ) :
 if 88 - 88: i1IIi - OoOoOO00
 if 66 - 66: OoooooooOO - OoooooooOO * I11i / II111iiii + oO0o / Ii1I
 if 7 - 7: Ii1I / iIii1I11I1II1
 if 36 - 36: iIii1I11I1II1 % i11iIiiIii
 iIiO00OooOoOO0o0 = lisp_info ( )
 packet = iIiO00OooOoOO0o0 . decode ( packet )
 if ( packet == None ) : return ( [ None , None , False ] )
 if 35 - 35: Oo0Ooo + I1IiiI - O0 - I1Ii111
 iIiO00OooOoOO0o0 . print_info ( )
 if 64 - 64: i1IIi * OoOoOO00 / II111iiii * oO0o
 if 35 - 35: i1IIi - Ii1I - Ii1I . O0 % iII111i * iII111i
 if 15 - 15: OoooooooOO . Ii1I * I1Ii111 . ooOoO0o % OoO0O00 * Oo0Ooo
 if 10 - 10: iII111i + i11iIiiIii . OOooOOo % iII111i - i1IIi
 iiIiiI11IIII1 = False
 for I111iI1I1i1 in iIiO00OooOoOO0o0 . rtr_list :
  I1IIII1i1 = I111iI1I1i1 . print_address_no_iid ( )
  if ( lisp_rtr_list . has_key ( I1IIII1i1 ) ) :
   if ( lisp_register_all_rtrs == False ) : continue
   if ( lisp_rtr_list [ I1IIII1i1 ] != None ) : continue
   if 36 - 36: Ii1I . iII111i * O0 * I1Ii111
  iiIiiI11IIII1 = True
  lisp_rtr_list [ I1IIII1i1 ] = I111iI1I1i1
  if 41 - 41: O0 * iII111i
  if 63 - 63: iIii1I11I1II1 + Ii1I * ooOoO0o * Ii1I + II111iiii - OOooOOo
  if 44 - 44: I1ii11iIi11i * i11iIiiIii * I1IiiI
  if 56 - 56: i1IIi + oO0o + OoO0O00
  if 67 - 67: OoOoOO00 . OoO0O00 + OoooooooOO . I1Ii111
 if ( lisp_i_am_itr and iiIiiI11IIII1 ) :
  if ( lisp_iid_to_interface == { } ) :
   lisp_update_default_routes ( source , lisp_default_iid , lisp_rtr_list )
  else :
   for OO0OO000 in lisp_iid_to_interface . keys ( ) :
    lisp_update_default_routes ( source , int ( OO0OO000 ) , lisp_rtr_list )
    if 4 - 4: iIii1I11I1II1 + IiII * i11iIiiIii + i11iIiiIii
    if 14 - 14: IiII
    if 29 - 29: o0oOOo0O0Ooo * iIii1I11I1II1 . iIii1I11I1II1
    if 32 - 32: IiII - OoOoOO00
    if 88 - 88: OOooOOo - II111iiii + i1IIi * Oo0Ooo
    if 48 - 48: I1Ii111 + IiII % iII111i * iII111i + I1Ii111
    if 83 - 83: OoO0O00 . I11i * I1ii11iIi11i - II111iiii
 if ( store == False ) :
  return ( [ iIiO00OooOoOO0o0 . global_etr_rloc , iIiO00OooOoOO0o0 . etr_port , iiIiiI11IIII1 ] )
  if 41 - 41: OoooooooOO . OoOoOO00 * iIii1I11I1II1
  if 18 - 18: IiII / I1Ii111 % i1IIi * i11iIiiIii
  if 16 - 16: Oo0Ooo
  if 24 - 24: o0oOOo0O0Ooo . OoOoOO00
  if 50 - 50: I1ii11iIi11i / iIii1I11I1II1 - Oo0Ooo - i11iIiiIii % o0oOOo0O0Ooo - ooOoO0o
  if 92 - 92: OoooooooOO - I1ii11iIi11i . I11i / O0 % iII111i
 for o0o0O0OO0oO in lisp_db_list :
  for OoooO00OO in o0o0O0OO0oO . rloc_set :
   o0OOooooooOO = OoooO00OO . rloc
   oOOoo = OoooO00OO . interface
   if ( oOOoo == None ) :
    if ( o0OOooooooOO . is_null ( ) ) : continue
    if ( o0OOooooooOO . is_local ( ) == False ) : continue
    if ( iIiO00OooOoOO0o0 . private_etr_rloc . is_null ( ) == False and
 o0OOooooooOO . is_exact_match ( iIiO00OooOoOO0o0 . private_etr_rloc ) == False ) :
     continue
     if 96 - 96: I1IiiI . oO0o % O0
   elif ( iIiO00OooOoOO0o0 . private_etr_rloc . is_dist_name ( ) ) :
    ooOO0OOO = iIiO00OooOoOO0o0 . private_etr_rloc . address
    if ( ooOO0OOO != OoooO00OO . rloc_name ) : continue
    if 19 - 19: iIii1I11I1II1 + I1Ii111 / OoooooooOO % OOooOOo - i1IIi + I11i
    if 87 - 87: OoooooooOO
   oo0oO = green ( o0o0O0OO0oO . eid . print_prefix ( ) , False )
   oo00OO = red ( o0OOooooooOO . print_address_no_iid ( ) , False )
   if 97 - 97: ooOoO0o * IiII / iIii1I11I1II1
   OoOo0OOO = iIiO00OooOoOO0o0 . global_etr_rloc . is_exact_match ( o0OOooooooOO )
   if ( OoooO00OO . translated_port == 0 and OoOo0OOO ) :
    lprint ( "No NAT for {} ({}), EID-prefix {}" . format ( oo00OO ,
 oOOoo , oo0oO ) )
    continue
    if 74 - 74: i1IIi * i11iIiiIii - o0oOOo0O0Ooo
    if 62 - 62: iIii1I11I1II1 / oO0o - OoO0O00 * I1Ii111
    if 1 - 1: I1ii11iIi11i . OoOoOO00 % o0oOOo0O0Ooo * i11iIiiIii - OOooOOo % oO0o
    if 35 - 35: I1ii11iIi11i / II111iiii * OoO0O00 - i11iIiiIii / iII111i / o0oOOo0O0Ooo
    if 39 - 39: II111iiii * iII111i
   I1iI1ii = iIiO00OooOoOO0o0 . global_etr_rloc
   IIIIi = OoooO00OO . translated_rloc
   if ( IIIIi . is_exact_match ( I1iI1ii ) and
 iIiO00OooOoOO0o0 . etr_port == OoooO00OO . translated_port ) : continue
   if 60 - 60: i11iIiiIii . II111iiii - oO0o
   lprint ( "Store translation {}:{} for {} ({}), EID-prefix {}" . format ( red ( iIiO00OooOoOO0o0 . global_etr_rloc . print_address_no_iid ( ) , False ) ,
   # Oo0Ooo % i1IIi * o0oOOo0O0Ooo * IiII
 iIiO00OooOoOO0o0 . etr_port , oo00OO , oOOoo , oo0oO ) )
   if 24 - 24: i11iIiiIii / iIii1I11I1II1 / iII111i
   OoooO00OO . store_translated_rloc ( iIiO00OooOoOO0o0 . global_etr_rloc ,
 iIiO00OooOoOO0o0 . etr_port )
   if 31 - 31: OOooOOo . iIii1I11I1II1 - oO0o
   if 36 - 36: O0
 return ( [ iIiO00OooOoOO0o0 . global_etr_rloc , iIiO00OooOoOO0o0 . etr_port , iiIiiI11IIII1 ] )
 if 30 - 30: i11iIiiIii * Oo0Ooo . IiII
 if 65 - 65: oO0o * IiII * OOooOOo / OoooooooOO % I11i / I1Ii111
 if 21 - 21: i1IIi * iII111i + OoO0O00
 if 27 - 27: I11i / oO0o . iII111i + o0oOOo0O0Ooo - OOooOOo
 if 85 - 85: OoooooooOO
 if 83 - 83: iII111i * I11i . OOooOOo - OoO0O00 % IiII
 if 8 - 8: I1Ii111
 if 86 - 86: ooOoO0o + iII111i * O0 % OoO0O00 + OoOoOO00
def lisp_test_mr ( lisp_sockets , port ) :
 return
 lprint ( "Test Map-Resolvers" )
 if 49 - 49: OOooOOo / i1IIi - II111iiii . iIii1I11I1II1 + I11i . OOooOOo
 ii1Ii = lisp_address ( LISP_AFI_IPV4 , "" , 0 , 0 )
 iiI111I = lisp_address ( LISP_AFI_IPV6 , "" , 0 , 0 )
 if 37 - 37: i11iIiiIii + O0 + II111iiii
 if 13 - 13: OOooOOo / O0
 if 19 - 19: iIii1I11I1II1 + IiII * I11i * II111iiii + o0oOOo0O0Ooo + i11iIiiIii
 if 69 - 69: iIii1I11I1II1 . II111iiii
 ii1Ii . store_address ( "10.0.0.1" )
 lisp_send_map_request ( lisp_sockets , port , None , ii1Ii , None )
 ii1Ii . store_address ( "192.168.0.1" )
 lisp_send_map_request ( lisp_sockets , port , None , ii1Ii , None )
 if 36 - 36: I1IiiI * i1IIi + OoOoOO00
 if 63 - 63: OoOoOO00 - iII111i
 if 83 - 83: i1IIi / iII111i % ooOoO0o % i11iIiiIii + I1ii11iIi11i
 if 82 - 82: iIii1I11I1II1 / OOooOOo
 iiI111I . store_address ( "0100::1" )
 lisp_send_map_request ( lisp_sockets , port , None , iiI111I , None )
 iiI111I . store_address ( "8000::1" )
 lisp_send_map_request ( lisp_sockets , port , None , iiI111I , None )
 if 7 - 7: OoooooooOO
 if 71 - 71: OOooOOo * Oo0Ooo . Oo0Ooo % iIii1I11I1II1
 if 56 - 56: IiII * iIii1I11I1II1 - iIii1I11I1II1 . O0
 if 56 - 56: I1Ii111 / iIii1I11I1II1 % IiII * iIii1I11I1II1 . I1ii11iIi11i . OOooOOo
 I1OoO0OO = threading . Timer ( LISP_TEST_MR_INTERVAL , lisp_test_mr ,
 [ lisp_sockets , port ] )
 I1OoO0OO . start ( )
 return
 if 20 - 20: OoO0O00 / I1ii11iIi11i / iII111i / o0oOOo0O0Ooo
 if 37 - 37: o0oOOo0O0Ooo - ooOoO0o + OoOoOO00
 if 50 - 50: I1IiiI
 if 30 - 30: i1IIi + II111iiii . Oo0Ooo + iIii1I11I1II1
 if 54 - 54: o0oOOo0O0Ooo / i11iIiiIii - I11i - oO0o
 if 16 - 16: I1ii11iIi11i / OoO0O00
 if 2 - 2: i11iIiiIii . iII111i
 if 35 - 35: Ii1I
 if 54 - 54: OOooOOo
 if 83 - 83: i1IIi / II111iiii - I1IiiI + I1ii11iIi11i . IiII * oO0o
 if 92 - 92: OoOoOO00 + oO0o % Ii1I / Ii1I - iII111i
 if 11 - 11: Oo0Ooo % II111iiii * Ii1I + II111iiii
 if 9 - 9: I1Ii111
def lisp_update_local_rloc ( rloc ) :
 if ( rloc . interface == None ) : return
 if 69 - 69: i1IIi + ooOoO0o + Ii1I
 ooooO0O = lisp_get_interface_address ( rloc . interface )
 if ( ooooO0O == None ) : return
 if 88 - 88: OoOoOO00 + iII111i % O0 + OOooOOo / OoooooooOO / OOooOOo
 O0o00o000 = rloc . rloc . print_address_no_iid ( )
 o0o0Oo0O0O0o = ooooO0O . print_address_no_iid ( )
 if 70 - 70: o0oOOo0O0Ooo - O0 % I1ii11iIi11i
 if ( O0o00o000 == o0o0Oo0O0O0o ) : return
 if 28 - 28: I1Ii111 % iII111i
 lprint ( "Local interface address changed on {} from {} to {}" . format ( rloc . interface , O0o00o000 , o0o0Oo0O0O0o ) )
 if 18 - 18: OoOoOO00
 if 42 - 42: Ii1I . OOooOOo / O0 / i1IIi . i11iIiiIii
 rloc . rloc . copy_address ( ooooO0O )
 lisp_myrlocs [ 0 ] = ooooO0O
 return
 if 62 - 62: OoOoOO00
 if 6 - 6: OoO0O00 * ooOoO0o . oO0o
 if 77 - 77: iIii1I11I1II1
 if 96 - 96: iII111i * I1ii11iIi11i
 if 77 - 77: i11iIiiIii / iIii1I11I1II1 . I1ii11iIi11i
 if 90 - 90: I1IiiI + I1IiiI % oO0o
 if 95 - 95: OOooOOo + OoooooooOO . i11iIiiIii * OoO0O00 * I1IiiI / I1Ii111
 if 5 - 5: Ii1I . oO0o / o0oOOo0O0Ooo - OoooooooOO
def lisp_update_encap_port ( mc ) :
 for o0OOooooooOO in mc . rloc_set :
  Oo0Oo = lisp_get_nat_info ( o0OOooooooOO . rloc , o0OOooooooOO . rloc_name )
  if ( Oo0Oo == None ) : continue
  if ( o0OOooooooOO . translated_port == Oo0Oo . port ) : continue
  if 67 - 67: I1Ii111 + i1IIi - OOooOOo + OoooooooOO / II111iiii - I1Ii111
  lprint ( ( "Encap-port changed from {} to {} for RLOC {}, " + "EID-prefix {}" ) . format ( o0OOooooooOO . translated_port , Oo0Oo . port ,
  # OOooOOo
 red ( o0OOooooooOO . rloc . print_address_no_iid ( ) , False ) ,
 green ( mc . print_eid_tuple ( ) , False ) ) )
  if 55 - 55: I11i
  o0OOooooooOO . store_translated_rloc ( o0OOooooooOO . rloc , Oo0Oo . port )
  if 7 - 7: I1Ii111 + ooOoO0o % o0oOOo0O0Ooo
 return
 if 53 - 53: i1IIi / iII111i % Ii1I % OoooooooOO
 if 63 - 63: OOooOOo + I1ii11iIi11i . i1IIi . Ii1I - I1ii11iIi11i * o0oOOo0O0Ooo
 if 79 - 79: ooOoO0o - O0
 if 20 - 20: OOooOOo
 if 22 - 22: iIii1I11I1II1 / I1Ii111
 if 6 - 6: iII111i . i11iIiiIii / Oo0Ooo
 if 86 - 86: I11i % I1Ii111 % oO0o - ooOoO0o / i1IIi
 if 68 - 68: i1IIi % O0 % iII111i
 if 55 - 55: I1ii11iIi11i % OOooOOo - o0oOOo0O0Ooo - II111iiii
 if 52 - 52: I1Ii111
 if 34 - 34: II111iiii + iII111i / IiII
 if 47 - 47: OoO0O00
def lisp_timeout_map_cache_entry ( mc , delete_list ) :
 if ( mc . map_cache_ttl == None ) :
  lisp_update_encap_port ( mc )
  return ( [ True , delete_list ] )
  if 40 - 40: o0oOOo0O0Ooo / iII111i . o0oOOo0O0Ooo
  if 63 - 63: o0oOOo0O0Ooo * iIii1I11I1II1 * II111iiii . OoO0O00 - oO0o / OoOoOO00
 Ii1I1I11I11 = lisp_get_timestamp ( )
 if 78 - 78: i11iIiiIii / OoO0O00 / i1IIi . i11iIiiIii
 if 100 - 100: II111iiii . IiII . I11i
 if 60 - 60: OoOoOO00 % OOooOOo * i1IIi
 if 3 - 3: OoooooooOO
 if 75 - 75: OoooooooOO * I1Ii111 * o0oOOo0O0Ooo + I1ii11iIi11i . iIii1I11I1II1 / O0
 if 23 - 23: oO0o - O0 * IiII + i11iIiiIii * Ii1I
 if ( mc . last_refresh_time + mc . map_cache_ttl > Ii1I1I11I11 ) :
  if ( mc . action == LISP_NO_ACTION ) : lisp_update_encap_port ( mc )
  return ( [ True , delete_list ] )
  if 8 - 8: ooOoO0o / II111iiii . I1ii11iIi11i * ooOoO0o % oO0o
  if 36 - 36: I1ii11iIi11i % OOooOOo - ooOoO0o - I11i + I1IiiI
  if 37 - 37: I1ii11iIi11i * IiII
  if 65 - 65: OOooOOo / O0 . I1ii11iIi11i % i1IIi % Oo0Ooo
  if 36 - 36: i11iIiiIii - OOooOOo + iII111i + iII111i * I11i * oO0o
 ooOO0o = lisp_print_elapsed ( mc . last_refresh_time )
 oo0Ooo = mc . print_eid_tuple ( )
 lprint ( "Map-cache entry for EID-prefix {} has {}, had uptime of {}" . format ( green ( oo0Ooo , False ) , bold ( "timed out" , False ) , ooOO0o ) )
 if 14 - 14: O0 - iII111i * I1Ii111 - I1IiiI + IiII
 if 46 - 46: OoooooooOO * OoO0O00 . I1Ii111
 if 95 - 95: ooOoO0o . I1ii11iIi11i . ooOoO0o / I1IiiI * OoOoOO00 . O0
 if 78 - 78: oO0o
 if 33 - 33: oO0o + i1IIi
 delete_list . append ( mc )
 return ( [ True , delete_list ] )
 if 32 - 32: iIii1I11I1II1
 if 71 - 71: Ii1I * I1IiiI
 if 62 - 62: II111iiii / I1IiiI . I1ii11iIi11i
 if 49 - 49: IiII / OoOoOO00 / O0 * i11iIiiIii
 if 47 - 47: i11iIiiIii + iII111i + i11iIiiIii
 if 66 - 66: o0oOOo0O0Ooo . I1IiiI + OoooooooOO . iII111i / OoooooooOO - IiII
 if 47 - 47: o0oOOo0O0Ooo / II111iiii * i11iIiiIii * OoO0O00 . iIii1I11I1II1
 if 34 - 34: I11i / o0oOOo0O0Ooo * OOooOOo * OOooOOo
def lisp_timeout_map_cache_walk ( mc , parms ) :
 IiII1IIiI1i = parms [ 0 ]
 oOIIiiI = parms [ 1 ]
 if 74 - 74: OoOoOO00 . I1Ii111 - Oo0Ooo / I11i . OoOoOO00 * o0oOOo0O0Ooo
 if 43 - 43: I11i
 if 18 - 18: OoooooooOO + OoooooooOO - i11iIiiIii / II111iiii
 if 41 - 41: Oo0Ooo . OoOoOO00 . iII111i / i11iIiiIii
 if ( mc . group . is_null ( ) ) :
  IIiIIiiIIi , IiII1IIiI1i = lisp_timeout_map_cache_entry ( mc , IiII1IIiI1i )
  if ( IiII1IIiI1i == [ ] or mc != IiII1IIiI1i [ - 1 ] ) :
   oOIIiiI = lisp_write_checkpoint_entry ( oOIIiiI , mc )
   if 65 - 65: iII111i * o0oOOo0O0Ooo * OoooooooOO + I11i + oO0o % OoO0O00
  return ( [ IIiIIiiIIi , parms ] )
  if 1 - 1: I1ii11iIi11i . ooOoO0o
  if 54 - 54: OoOoOO00 % I1IiiI . ooOoO0o + IiII / i11iIiiIii / o0oOOo0O0Ooo
 if ( mc . source_cache == None ) : return ( [ True , parms ] )
 if 51 - 51: OoOoOO00 / Ii1I . I1IiiI / Ii1I . II111iiii - iIii1I11I1II1
 if 78 - 78: I11i
 if 42 - 42: Ii1I
 if 50 - 50: iIii1I11I1II1 / Ii1I . ooOoO0o / ooOoO0o * OoOoOO00 * iII111i
 if 15 - 15: o0oOOo0O0Ooo % II111iiii + I1IiiI
 parms = mc . source_cache . walk_cache ( lisp_timeout_map_cache_entry , parms )
 return ( [ True , parms ] )
 if 21 - 21: I1ii11iIi11i - ooOoO0o
 if 81 - 81: iII111i / i11iIiiIii / I1Ii111
 if 70 - 70: I1ii11iIi11i / i11iIiiIii
 if 90 - 90: II111iiii / OoOoOO00 . Ii1I . OoooooooOO
 if 76 - 76: OoooooooOO
 if 78 - 78: IiII % i11iIiiIii
 if 23 - 23: iIii1I11I1II1 - o0oOOo0O0Ooo - Ii1I % OOooOOo
def lisp_timeout_map_cache ( lisp_map_cache ) :
 IiI = [ [ ] , [ ] ]
 IiI = lisp_map_cache . walk_cache ( lisp_timeout_map_cache_walk , IiI )
 if 100 - 100: oO0o . OoO0O00 . i11iIiiIii % II111iiii * IiII
 if 81 - 81: OOooOOo - OOooOOo + OoOoOO00
 if 19 - 19: o0oOOo0O0Ooo
 if 20 - 20: I1Ii111 + iIii1I11I1II1 % I1IiiI + ooOoO0o
 if 86 - 86: o0oOOo0O0Ooo * i11iIiiIii - I11i
 IiII1IIiI1i = IiI [ 0 ]
 for OoOOO000O0o in IiII1IIiI1i : OoOOO000O0o . delete_cache ( )
 if 71 - 71: OoO0O00 - I11i
 if 96 - 96: I1Ii111 / Ii1I
 if 65 - 65: I1ii11iIi11i * O0 . IiII
 if 11 - 11: I11i / Ii1I % oO0o
 oOIIiiI = IiI [ 1 ]
 lisp_checkpoint ( oOIIiiI )
 return
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
 if 50 - 50: I11i / I1ii11iIi11i
 if 60 - 60: II111iiii / Ii1I + OoO0O00 % I1IiiI * i1IIi / II111iiii
 if 91 - 91: I1IiiI * I1Ii111 * i11iIiiIii - oO0o - IiII + I1ii11iIi11i
 if 99 - 99: OoO0O00 % o0oOOo0O0Ooo
def lisp_store_nat_info ( hostname , rloc , port ) :
 I1IIII1i1 = rloc . print_address_no_iid ( )
 i11Ii = "{} NAT state for {}, RLOC {}, port {}" . format ( "{}" ,
 blue ( hostname , False ) , red ( I1IIII1i1 , False ) , port )
 if 47 - 47: ooOoO0o . i11iIiiIii / OoO0O00
 i1Oo = lisp_nat_info ( I1IIII1i1 , hostname , port )
 if 45 - 45: OoO0O00 + OoOoOO00 + o0oOOo0O0Ooo
 if ( lisp_nat_state_info . has_key ( hostname ) == False ) :
  lisp_nat_state_info [ hostname ] = [ i1Oo ]
  lprint ( i11Ii . format ( "Store initial" ) )
  return ( True )
  if 70 - 70: OOooOOo % OoOoOO00
  if 86 - 86: OoooooooOO + OOooOOo + OOooOOo + I1Ii111 + OoooooooOO + ooOoO0o
  if 84 - 84: OoOoOO00 * OoOoOO00 % ooOoO0o % II111iiii / iII111i + Oo0Ooo
  if 95 - 95: iII111i . oO0o % iIii1I11I1II1 - I1IiiI
  if 38 - 38: ooOoO0o % iIii1I11I1II1 - OOooOOo
  if 13 - 13: OOooOOo . i11iIiiIii
 Oo0Oo = lisp_nat_state_info [ hostname ] [ 0 ]
 if ( Oo0Oo . address == I1IIII1i1 and Oo0Oo . port == port ) :
  Oo0Oo . uptime = lisp_get_timestamp ( )
  lprint ( i11Ii . format ( "Refresh existing" ) )
  return ( False )
  if 71 - 71: oO0o + I1ii11iIi11i * I1ii11iIi11i
  if 79 - 79: oO0o
  if 47 - 47: OoooooooOO - i1IIi * OOooOOo
  if 11 - 11: I11i / OOooOOo . o0oOOo0O0Ooo - O0 * OoooooooOO % iII111i
  if 7 - 7: OoOoOO00 . IiII + OoooooooOO - I1Ii111 / oO0o
  if 32 - 32: iIii1I11I1II1 + I11i + OOooOOo - OoooooooOO + i11iIiiIii * o0oOOo0O0Ooo
  if 8 - 8: iII111i
 iI1II1II1i = None
 for Oo0Oo in lisp_nat_state_info [ hostname ] :
  if ( Oo0Oo . address == I1IIII1i1 and Oo0Oo . port == port ) :
   iI1II1II1i = Oo0Oo
   break
   if 21 - 21: i1IIi + OoO0O00 . I1IiiI - Oo0Ooo
   if 99 - 99: OoOoOO00
   if 46 - 46: I1ii11iIi11i / II111iiii / OoooooooOO / Ii1I
 if ( iI1II1II1i == None ) :
  lprint ( i11Ii . format ( "Store new" ) )
 else :
  lisp_nat_state_info [ hostname ] . remove ( iI1II1II1i )
  lprint ( i11Ii . format ( "Use previous" ) )
  if 37 - 37: I1ii11iIi11i - Ii1I / oO0o . I1IiiI % I1Ii111
  if 8 - 8: oO0o
 I1I1ii = lisp_nat_state_info [ hostname ]
 lisp_nat_state_info [ hostname ] = [ i1Oo ] + I1I1ii
 return ( True )
 if 36 - 36: ooOoO0o . Ii1I * ooOoO0o - OoOoOO00
 if 20 - 20: ooOoO0o
 if 13 - 13: i11iIiiIii + i11iIiiIii
 if 21 - 21: OoooooooOO
 if 76 - 76: Ii1I . i11iIiiIii * I1IiiI % o0oOOo0O0Ooo * OoO0O00
 if 79 - 79: O0 % iIii1I11I1II1 * iII111i - II111iiii % Oo0Ooo + i11iIiiIii
 if 36 - 36: OOooOOo / o0oOOo0O0Ooo . OoOoOO00 - I11i
 if 89 - 89: i1IIi - iIii1I11I1II1 / II111iiii
def lisp_get_nat_info ( rloc , hostname ) :
 if ( lisp_nat_state_info . has_key ( hostname ) == False ) : return ( None )
 if 61 - 61: I1Ii111
 I1IIII1i1 = rloc . print_address_no_iid ( )
 for Oo0Oo in lisp_nat_state_info [ hostname ] :
  if ( Oo0Oo . address == I1IIII1i1 ) : return ( Oo0Oo )
  if 56 - 56: I1ii11iIi11i - OoooooooOO
 return ( None )
 if 52 - 52: Oo0Ooo - I11i - IiII - OoOoOO00
 if 21 - 21: oO0o % o0oOOo0O0Ooo + I1Ii111 . OOooOOo / OOooOOo
 if 41 - 41: Oo0Ooo . ooOoO0o * oO0o
 if 31 - 31: Oo0Ooo * IiII / IiII
 if 3 - 3: I1Ii111
 if 65 - 65: iIii1I11I1II1 % Oo0Ooo % I11i / OoooooooOO
 if 82 - 82: o0oOOo0O0Ooo
 if 33 - 33: OoOoOO00 / i11iIiiIii - I1IiiI - OoooooooOO + i1IIi * I1Ii111
 if 92 - 92: iII111i + OoO0O00
 if 70 - 70: iIii1I11I1II1
 if 100 - 100: OOooOOo . oO0o % ooOoO0o * ooOoO0o . I1Ii111 - oO0o
 if 33 - 33: Oo0Ooo . i1IIi - OoooooooOO
 if 14 - 14: I1Ii111 + Oo0Ooo
 if 35 - 35: i11iIiiIii * Ii1I
 if 100 - 100: O0 . iII111i / iIii1I11I1II1
 if 47 - 47: ooOoO0o + OoOoOO00
 if 67 - 67: IiII - I1ii11iIi11i * i1IIi - ooOoO0o
 if 91 - 91: I11i
 if 54 - 54: I1ii11iIi11i / i1IIi
 if 14 - 14: iIii1I11I1II1 * I11i . I11i * ooOoO0o * iII111i
def lisp_build_info_requests ( lisp_sockets , dest , port ) :
 if ( lisp_nat_traversal == False ) : return
 if 60 - 60: iIii1I11I1II1 + i1IIi + oO0o - iIii1I11I1II1 . i11iIiiIii * OoooooooOO
 if 23 - 23: iII111i - IiII % i11iIiiIii
 if 81 - 81: OoooooooOO % OoOoOO00 / IiII / OoooooooOO + i1IIi - O0
 if 60 - 60: OOooOOo - I1Ii111 * Oo0Ooo
 if 9 - 9: OoooooooOO * OOooOOo % OoO0O00 - ooOoO0o + Ii1I
 if 39 - 39: iIii1I11I1II1 / i1IIi % I11i % I1ii11iIi11i * IiII
 iiiii1 = [ ]
 Ii1iiI = [ ]
 if ( dest == None ) :
  for OOO0o0o in lisp_map_resolvers_list . values ( ) :
   Ii1iiI . append ( OOO0o0o . map_resolver )
   if 37 - 37: OoooooooOO . o0oOOo0O0Ooo - o0oOOo0O0Ooo - Oo0Ooo / I1IiiI
  iiiii1 = Ii1iiI
  if ( iiiii1 == [ ] ) :
   for I1iiIIiiiII in lisp_map_servers_list . values ( ) :
    iiiii1 . append ( I1iiIIiiiII . map_server )
    if 87 - 87: IiII
    if 68 - 68: I1Ii111 + I1ii11iIi11i * IiII . OoO0O00 / I11i
  if ( iiiii1 == [ ] ) : return
 else :
  iiiii1 . append ( dest )
  if 39 - 39: Oo0Ooo + OOooOOo . I1IiiI + OoO0O00 . OoooooooOO
  if 31 - 31: OoO0O00
  if 55 - 55: OoOoOO00 + I1Ii111 * o0oOOo0O0Ooo - I1ii11iIi11i + OoOoOO00
  if 6 - 6: II111iiii % iIii1I11I1II1 * I1Ii111
  if 2 - 2: IiII - I1Ii111 . iIii1I11I1II1 - Ii1I * I11i
 i1I1i1Iiiiiii = { }
 for o0o0O0OO0oO in lisp_db_list :
  for OoooO00OO in o0o0O0OO0oO . rloc_set :
   lisp_update_local_rloc ( OoooO00OO )
   if ( OoooO00OO . rloc . is_null ( ) ) : continue
   if ( OoooO00OO . interface == None ) : continue
   if 58 - 58: i1IIi % iIii1I11I1II1 % i11iIiiIii - o0oOOo0O0Ooo + ooOoO0o
   ooooO0O = OoooO00OO . rloc . print_address_no_iid ( )
   if ( ooooO0O in i1I1i1Iiiiiii ) : continue
   i1I1i1Iiiiiii [ ooooO0O ] = OoooO00OO . interface
   if 23 - 23: Oo0Ooo % Oo0Ooo / IiII
   if 63 - 63: I11i % Oo0Ooo * I1Ii111 - Oo0Ooo % i11iIiiIii . II111iiii
 if ( i1I1i1Iiiiiii == { } ) :
  lprint ( 'Suppress Info-Request, no "interface = <device>" RLOC ' + "found in any database-mappings" )
  if 44 - 44: I11i . I1Ii111 . I1ii11iIi11i . oO0o
  return
  if 1 - 1: I11i % II111iiii / OoO0O00 + OoO0O00
  if 46 - 46: Oo0Ooo * Ii1I / IiII % O0 * iII111i
  if 74 - 74: OoooooooOO + Ii1I
  if 100 - 100: I1IiiI
  if 59 - 59: I1IiiI - OoOoOO00 * ooOoO0o / O0
  if 54 - 54: Oo0Ooo % iIii1I11I1II1 * Oo0Ooo
 for ooooO0O in i1I1i1Iiiiiii :
  oOOoo = i1I1i1Iiiiiii [ ooooO0O ]
  iiiii1ii1 = red ( ooooO0O , False )
  lprint ( "Build Info-Request for private address {} ({})" . format ( iiiii1ii1 ,
 oOOoo ) )
  I1i1II1 = oOOoo if len ( i1I1i1Iiiiiii ) > 1 else None
  for dest in iiiii1 :
   lisp_send_info_request ( lisp_sockets , dest , port , I1i1II1 )
   if 80 - 80: I1ii11iIi11i - I1ii11iIi11i
   if 26 - 26: I1ii11iIi11i - I1IiiI * I1Ii111 % iIii1I11I1II1
   if 77 - 77: o0oOOo0O0Ooo + I1Ii111 . OOooOOo . i1IIi . I1IiiI
   if 100 - 100: ooOoO0o . i11iIiiIii + Ii1I - OOooOOo - i11iIiiIii - OoooooooOO
   if 42 - 42: OoOoOO00 . I1IiiI / OoOoOO00 / I1ii11iIi11i . OoO0O00
   if 67 - 67: Ii1I - O0 . OoooooooOO . I1Ii111 . o0oOOo0O0Ooo
 if ( Ii1iiI != [ ] ) :
  for OOO0o0o in lisp_map_resolvers_list . values ( ) :
   OOO0o0o . resolve_dns_name ( )
   if 73 - 73: I11i - oO0o . I1Ii111 + oO0o
   if 48 - 48: IiII . IiII * o0oOOo0O0Ooo * II111iiii % ooOoO0o
 return
 if 40 - 40: I1ii11iIi11i
 if 76 - 76: Oo0Ooo - I11i
 if 82 - 82: OoO0O00 % oO0o . I11i / O0 - I1Ii111
 if 39 - 39: I1IiiI
 if 8 - 8: IiII * i1IIi * i1IIi * O0
 if 69 - 69: Oo0Ooo
 if 48 - 48: iII111i
 if 11 - 11: i11iIiiIii * OoOoOO00 . OoO0O00
def lisp_valid_address_format ( kw , value ) :
 if ( kw != "address" ) : return ( True )
 if 47 - 47: Oo0Ooo % I1Ii111 + ooOoO0o
 if 89 - 89: iII111i
 if 29 - 29: I1ii11iIi11i . ooOoO0o * II111iiii / iII111i . OoooooooOO - OoOoOO00
 if 99 - 99: IiII % O0 - I1Ii111 * OoO0O00
 if 77 - 77: OoooooooOO - I11i / I1IiiI % OoOoOO00 - OOooOOo
 if ( value [ 0 ] == "'" and value [ - 1 ] == "'" ) : return ( True )
 if 37 - 37: ooOoO0o
 if 22 - 22: I1ii11iIi11i + II111iiii / OoooooooOO % o0oOOo0O0Ooo * OoOoOO00 . Oo0Ooo
 if 26 - 26: OoO0O00 % oO0o * Ii1I % OoooooooOO - oO0o
 if 46 - 46: I1IiiI + OoO0O00 - O0 * O0
 if ( value . find ( "." ) != - 1 ) :
  ooooO0O = value . split ( "." )
  if ( len ( ooooO0O ) != 4 ) : return ( False )
  if 75 - 75: OOooOOo + iIii1I11I1II1 * OOooOOo
  for o0O0O00oO in ooooO0O :
   if ( o0O0O00oO . isdigit ( ) == False ) : return ( False )
   if ( int ( o0O0O00oO ) > 255 ) : return ( False )
   if 67 - 67: o0oOOo0O0Ooo - I1IiiI * iIii1I11I1II1
  return ( True )
  if 29 - 29: i1IIi / Ii1I / oO0o * iII111i
  if 44 - 44: O0
  if 95 - 95: OOooOOo + OOooOOo - OoOoOO00
  if 83 - 83: II111iiii * ooOoO0o - O0 - i11iIiiIii
  if 62 - 62: I1IiiI + II111iiii * iIii1I11I1II1 % iII111i + IiII / ooOoO0o
 if ( value . find ( "-" ) != - 1 ) :
  ooooO0O = value . split ( "-" )
  for o0OoO00 in [ "N" , "S" , "W" , "E" ] :
   if ( o0OoO00 in ooooO0O ) :
    if ( len ( ooooO0O ) < 8 ) : return ( False )
    return ( True )
    if 14 - 14: iIii1I11I1II1 * I1ii11iIi11i + OOooOOo + O0
    if 79 - 79: II111iiii - iII111i
    if 89 - 89: O0 - OoO0O00
    if 8 - 8: I1ii11iIi11i / oO0o - OoooooooOO + ooOoO0o + o0oOOo0O0Ooo % i11iIiiIii
    if 32 - 32: O0 + IiII
    if 93 - 93: OoOoOO00 - I11i / iII111i - iIii1I11I1II1 + I11i % oO0o
    if 24 - 24: Ii1I / iIii1I11I1II1 + o0oOOo0O0Ooo
 if ( value . find ( "-" ) != - 1 ) :
  ooooO0O = value . split ( "-" )
  if ( len ( ooooO0O ) != 3 ) : return ( False )
  if 17 - 17: OOooOOo
  for O00oIIi1iI1i111 in ooooO0O :
   try : int ( O00oIIi1iI1i111 , 16 )
   except : return ( False )
   if 85 - 85: OoO0O00 * I1Ii111 - OoooooooOO / iIii1I11I1II1 - i1IIi + Ii1I
  return ( True )
  if 76 - 76: iII111i * OoooooooOO
  if 49 - 49: II111iiii - OOooOOo + II111iiii + OoOoOO00
  if 51 - 51: i11iIiiIii
  if 39 - 39: o0oOOo0O0Ooo % I1Ii111 % i1IIi - II111iiii + i11iIiiIii
  if 62 - 62: I1ii11iIi11i - I1IiiI * i11iIiiIii % oO0o
 if ( value . find ( ":" ) != - 1 ) :
  ooooO0O = value . split ( ":" )
  if ( len ( ooooO0O ) < 2 ) : return ( False )
  if 63 - 63: II111iiii - Oo0Ooo
  Oo0o = False
  O0oO = 0
  for O00oIIi1iI1i111 in ooooO0O :
   O0oO += 1
   if ( O00oIIi1iI1i111 == "" ) :
    if ( Oo0o ) :
     if ( len ( ooooO0O ) == O0oO ) : break
     if ( O0oO > 2 ) : return ( False )
     if 91 - 91: ooOoO0o
    Oo0o = True
    continue
    if 4 - 4: iII111i * iIii1I11I1II1
   try : int ( O00oIIi1iI1i111 , 16 )
   except : return ( False )
   if 27 - 27: OOooOOo / OoOoOO00
  return ( True )
  if 99 - 99: i1IIi % Ii1I + o0oOOo0O0Ooo / IiII
  if 35 - 35: OoO0O00 % o0oOOo0O0Ooo - OOooOOo / IiII
  if 76 - 76: I11i . OoO0O00 . Ii1I % II111iiii + I1IiiI
  if 53 - 53: i1IIi / i1IIi + IiII - I1Ii111 % OoO0O00 . ooOoO0o
  if 94 - 94: OoOoOO00 - i1IIi + I1IiiI - Ii1I / O0 / iII111i
 if ( value [ 0 ] == "+" ) :
  ooooO0O = value [ 1 : : ]
  for iiiI11I in ooooO0O :
   if ( iiiI11I . isdigit ( ) == False ) : return ( False )
   if 25 - 25: I1Ii111 . Oo0Ooo % II111iiii . IiII - O0
  return ( True )
  if 18 - 18: oO0o * OOooOOo
 return ( False )
 if 19 - 19: iIii1I11I1II1 / I1ii11iIi11i - I1ii11iIi11i / iIii1I11I1II1
 if 42 - 42: iIii1I11I1II1 / OOooOOo - O0 * OoooooooOO / i1IIi
 if 33 - 33: OOooOOo . o0oOOo0O0Ooo % OoO0O00 - I1Ii111 . OoooooooOO
 if 96 - 96: II111iiii % I11i / Ii1I - i11iIiiIii
 if 63 - 63: I1IiiI
 if 15 - 15: iIii1I11I1II1 - I1ii11iIi11i % OoO0O00 * II111iiii / I11i + I11i
 if 23 - 23: I1IiiI
 if 51 - 51: i11iIiiIii / ooOoO0o - OoooooooOO + OoOoOO00 + oO0o
 if 57 - 57: iIii1I11I1II1
 if 19 - 19: Ii1I / o0oOOo0O0Ooo + O0 / iIii1I11I1II1 + II111iiii
 if 3 - 3: oO0o % OoO0O00 % OOooOOo
 if 64 - 64: o0oOOo0O0Ooo . II111iiii * IiII % Oo0Ooo + I11i - OoooooooOO
def lisp_process_api ( process , lisp_socket , data_structure ) :
 oo00o00O000Oo , IiI = data_structure . split ( "%" )
 if 69 - 69: O0 . ooOoO0o * iII111i - iII111i % oO0o
 lprint ( "Process API request '{}', parameters: '{}'" . format ( oo00o00O000Oo ,
 IiI ) )
 if 24 - 24: I1Ii111
 i11i111i1 = [ ]
 if ( oo00o00O000Oo == "map-cache" ) :
  if ( IiI == "" ) :
   i11i111i1 = lisp_map_cache . walk_cache ( lisp_process_api_map_cache , i11i111i1 )
  else :
   i11i111i1 = lisp_process_api_map_cache_entry ( json . loads ( IiI ) )
   if 72 - 72: Oo0Ooo - I1ii11iIi11i
   if 75 - 75: OoOoOO00 . OOooOOo . I1IiiI - iIii1I11I1II1 * OoOoOO00 % i11iIiiIii
 if ( oo00o00O000Oo == "site-cache" ) :
  if ( IiI == "" ) :
   i11i111i1 = lisp_sites_by_eid . walk_cache ( lisp_process_api_site_cache ,
 i11i111i1 )
  else :
   i11i111i1 = lisp_process_api_site_cache_entry ( json . loads ( IiI ) )
   if 41 - 41: o0oOOo0O0Ooo / ooOoO0o - i11iIiiIii
   if 63 - 63: ooOoO0o % OoO0O00 % ooOoO0o
 if ( oo00o00O000Oo == "map-server" ) :
  IiI = { } if ( IiI == "" ) else json . loads ( IiI )
  i11i111i1 = lisp_process_api_ms_or_mr ( True , IiI )
  if 28 - 28: IiII * I1Ii111 * o0oOOo0O0Ooo + ooOoO0o - IiII / IiII
 if ( oo00o00O000Oo == "map-resolver" ) :
  IiI = { } if ( IiI == "" ) else json . loads ( IiI )
  i11i111i1 = lisp_process_api_ms_or_mr ( False , IiI )
  if 73 - 73: iIii1I11I1II1 . I1ii11iIi11i + OOooOOo
 if ( oo00o00O000Oo == "database-mapping" ) :
  i11i111i1 = lisp_process_api_database_mapping ( )
  if 51 - 51: I11i % Oo0Ooo * OOooOOo % OoooooooOO - OoOoOO00 % Ii1I
  if 60 - 60: OoOoOO00 - IiII + OoO0O00
  if 77 - 77: iIii1I11I1II1
  if 92 - 92: IiII
  if 68 - 68: OOooOOo . IiII / iIii1I11I1II1 % i11iIiiIii
 i11i111i1 = json . dumps ( i11i111i1 )
 Ooooo = lisp_api_ipc ( process , i11i111i1 )
 lisp_ipc ( Ooooo , lisp_socket , "lisp-core" )
 return
 if 74 - 74: iII111i + i11iIiiIii
 if 95 - 95: Ii1I
 if 49 - 49: I1ii11iIi11i . i1IIi + OoO0O00 % O0 + OoO0O00
 if 21 - 21: ooOoO0o * oO0o / OoooooooOO % ooOoO0o / O0
 if 24 - 24: OoO0O00 - i11iIiiIii / i11iIiiIii * I1Ii111
 if 20 - 20: IiII % iIii1I11I1II1 . iII111i + iIii1I11I1II1 + O0
 if 96 - 96: I1ii11iIi11i - IiII % OoooooooOO . iII111i
def lisp_process_api_map_cache ( mc , data ) :
 if 30 - 30: Oo0Ooo . OoooooooOO / Oo0Ooo / oO0o
 if 44 - 44: I1ii11iIi11i % o0oOOo0O0Ooo / iIii1I11I1II1 - o0oOOo0O0Ooo / I11i * I1Ii111
 if 49 - 49: iII111i / iII111i - OoOoOO00
 if 89 - 89: ooOoO0o
 if ( mc . group . is_null ( ) ) : return ( lisp_gather_map_cache_data ( mc , data ) )
 if 16 - 16: oO0o + oO0o + i1IIi + iIii1I11I1II1
 if ( mc . source_cache == None ) : return ( [ True , data ] )
 if 93 - 93: I1IiiI - i11iIiiIii * I1Ii111 - O0 + iII111i
 if 11 - 11: iII111i
 if 100 - 100: OoooooooOO / ooOoO0o . OoO0O00
 if 89 - 89: I11i % II111iiii
 if 35 - 35: oO0o
 data = mc . source_cache . walk_cache ( lisp_gather_map_cache_data , data )
 return ( [ True , data ] )
 if 65 - 65: II111iiii
 if 87 - 87: oO0o / OoO0O00 - oO0o
 if 69 - 69: i11iIiiIii
 if 29 - 29: IiII . ooOoO0o / iII111i - OOooOOo / OOooOOo % Oo0Ooo
 if 42 - 42: OoO0O00 . I1Ii111 . I1IiiI + Oo0Ooo * O0
 if 35 - 35: Oo0Ooo / iII111i - O0 - OOooOOo * Oo0Ooo . i11iIiiIii
 if 43 - 43: OoOoOO00 % oO0o % OoO0O00 / Ii1I . I11i
def lisp_gather_map_cache_data ( mc , data ) :
 iiIiiIi = { }
 iiIiiIi [ "instance-id" ] = str ( mc . eid . instance_id )
 iiIiiIi [ "eid-prefix" ] = mc . eid . print_prefix_no_iid ( )
 if ( mc . group . is_null ( ) == False ) :
  iiIiiIi [ "group-prefix" ] = mc . group . print_prefix_no_iid ( )
  if 86 - 86: I1Ii111 * i1IIi + IiII - OoOoOO00
 iiIiiIi [ "uptime" ] = lisp_print_elapsed ( mc . uptime )
 iiIiiIi [ "expires" ] = lisp_print_elapsed ( mc . uptime )
 iiIiiIi [ "action" ] = lisp_map_reply_action_string [ mc . action ]
 iiIiiIi [ "ttl" ] = "--" if mc . map_cache_ttl == None else str ( mc . map_cache_ttl / 60 )
 if 14 - 14: I1ii11iIi11i / i11iIiiIii * I11i % o0oOOo0O0Ooo + IiII / I1ii11iIi11i
 if 82 - 82: OOooOOo . oO0o
 if 12 - 12: i11iIiiIii + II111iiii
 if 49 - 49: OoooooooOO
 if 48 - 48: i1IIi . IiII - O0 + OoooooooOO
 O0Oo0O = [ ]
 for o0OOooooooOO in mc . rloc_set :
  IIi = { }
  if ( o0OOooooooOO . rloc_exists ( ) ) :
   IIi [ "address" ] = o0OOooooooOO . rloc . print_address_no_iid ( )
   if 6 - 6: I1Ii111 * OOooOOo + o0oOOo0O0Ooo . I1ii11iIi11i * I1Ii111
   if 6 - 6: oO0o / II111iiii
  if ( o0OOooooooOO . translated_port != 0 ) :
   IIi [ "encap-port" ] = str ( o0OOooooooOO . translated_port )
   if 23 - 23: IiII - OoooooooOO / oO0o
  IIi [ "state" ] = o0OOooooooOO . print_state ( )
  if ( o0OOooooooOO . geo ) : IIi [ "geo" ] = o0OOooooooOO . geo . print_geo ( )
  if ( o0OOooooooOO . elp ) : IIi [ "elp" ] = o0OOooooooOO . elp . print_elp ( False )
  if ( o0OOooooooOO . rle ) : IIi [ "rle" ] = o0OOooooooOO . rle . print_rle ( False )
  if ( o0OOooooooOO . json ) : IIi [ "json" ] = o0OOooooooOO . json . print_json ( False )
  if ( o0OOooooooOO . rloc_name ) : IIi [ "rloc-name" ] = o0OOooooooOO . rloc_name
  oO000ooOOo = o0OOooooooOO . stats . get_stats ( False , False )
  if ( oO000ooOOo ) : IIi [ "stats" ] = oO000ooOOo
  IIi [ "uptime" ] = lisp_print_elapsed ( o0OOooooooOO . uptime )
  IIi [ "upriority" ] = str ( o0OOooooooOO . priority )
  IIi [ "uweight" ] = str ( o0OOooooooOO . weight )
  IIi [ "mpriority" ] = str ( o0OOooooooOO . mpriority )
  IIi [ "mweight" ] = str ( o0OOooooooOO . mweight )
  oooo0oOOo = o0OOooooooOO . last_rloc_probe_reply
  if ( oooo0oOOo ) :
   IIi [ "last-rloc-probe-reply" ] = lisp_print_elapsed ( oooo0oOOo )
   IIi [ "rloc-probe-rtt" ] = str ( o0OOooooooOO . rloc_probe_rtt )
   if 70 - 70: i1IIi - iIii1I11I1II1
  IIi [ "rloc-hop-count" ] = o0OOooooooOO . rloc_probe_hops
  IIi [ "recent-rloc-hop-counts" ] = o0OOooooooOO . recent_rloc_probe_hops
  if 50 - 50: IiII - OOooOOo % OoOoOO00
  o0oOOoo000o0 = [ ]
  for oOOO0Ooooo in o0OOooooooOO . recent_rloc_probe_rtts : o0oOOoo000o0 . append ( str ( oOOO0Ooooo ) )
  IIi [ "recent-rloc-probe-rtts" ] = o0oOOoo000o0
  if 56 - 56: o0oOOo0O0Ooo + ooOoO0o + OoooooooOO
  O0Oo0O . append ( IIi )
  if 64 - 64: OOooOOo / OoOoOO00
 iiIiiIi [ "rloc-set" ] = O0Oo0O
 if 30 - 30: OOooOOo % I1Ii111 - i11iIiiIii
 data . append ( iiIiiIi )
 return ( [ True , data ] )
 if 20 - 20: i1IIi * I11i / OoO0O00 / i1IIi / I1Ii111 * O0
 if 95 - 95: Ii1I + Ii1I % IiII - IiII / OOooOOo
 if 46 - 46: IiII + iII111i + II111iiii . iII111i - i11iIiiIii % OoO0O00
 if 24 - 24: oO0o + IiII . o0oOOo0O0Ooo . OoooooooOO . i11iIiiIii / I1ii11iIi11i
 if 49 - 49: IiII
 if 1 - 1: oO0o / I11i
 if 99 - 99: OoO0O00 % IiII + I1Ii111 - oO0o
def lisp_process_api_map_cache_entry ( parms ) :
 OO0OO000 = parms [ "instance-id" ]
 OO0OO000 = 0 if ( OO0OO000 == "" ) else int ( OO0OO000 )
 if 28 - 28: OOooOOo - O0 - O0 % i11iIiiIii * OoooooooOO
 if 60 - 60: OoooooooOO / i1IIi / i1IIi / Ii1I . IiII
 if 24 - 24: O0
 if 6 - 6: I1IiiI . i11iIiiIii . OoooooooOO . I1IiiI . o0oOOo0O0Ooo
 ii1Ii = lisp_address ( LISP_AFI_NONE , "" , 0 , OO0OO000 )
 ii1Ii . store_prefix ( parms [ "eid-prefix" ] )
 iI1i1iI1iI = ii1Ii
 OO = ii1Ii
 if 65 - 65: i11iIiiIii
 if 46 - 46: i11iIiiIii
 if 70 - 70: i1IIi + o0oOOo0O0Ooo
 if 44 - 44: iII111i . II111iiii % o0oOOo0O0Ooo
 if 29 - 29: i11iIiiIii * i1IIi
 IiI1111i1i11I = lisp_address ( LISP_AFI_NONE , "" , 0 , OO0OO000 )
 if ( parms . has_key ( "group-prefix" ) ) :
  IiI1111i1i11I . store_prefix ( parms [ "group-prefix" ] )
  iI1i1iI1iI = IiI1111i1i11I
  if 36 - 36: OoO0O00 * I11i . ooOoO0o
  if 50 - 50: oO0o * OoOoOO00 / OoO0O00 / ooOoO0o + II111iiii
 i11i111i1 = [ ]
 OoOOO000O0o = lisp_map_cache_lookup ( OO , iI1i1iI1iI )
 if ( OoOOO000O0o ) : IIiIIiiIIi , i11i111i1 = lisp_process_api_map_cache ( OoOOO000O0o , i11i111i1 )
 return ( i11i111i1 )
 if 55 - 55: II111iiii - IiII
 if 24 - 24: oO0o % Ii1I / i1IIi
 if 84 - 84: i1IIi
 if 53 - 53: OoooooooOO - i1IIi - Ii1I
 if 73 - 73: I1ii11iIi11i - Ii1I * o0oOOo0O0Ooo
 if 29 - 29: o0oOOo0O0Ooo % IiII % OOooOOo + OoooooooOO - o0oOOo0O0Ooo
 if 34 - 34: Ii1I
def lisp_process_api_site_cache ( se , data ) :
 if 5 - 5: II111iiii . I1ii11iIi11i
 if 85 - 85: I1Ii111 . IiII + II111iiii
 if 92 - 92: iII111i / o0oOOo0O0Ooo * oO0o . I11i % o0oOOo0O0Ooo
 if 87 - 87: Ii1I / Oo0Ooo % iIii1I11I1II1 / iII111i
 if ( se . group . is_null ( ) ) : return ( lisp_gather_site_cache_data ( se , data ) )
 if 42 - 42: OoO0O00 . I1IiiI . OOooOOo + ooOoO0o
 if ( se . source_cache == None ) : return ( [ True , data ] )
 if 87 - 87: OOooOOo
 if 44 - 44: Oo0Ooo + iIii1I11I1II1
 if 67 - 67: iII111i . OOooOOo / ooOoO0o * iIii1I11I1II1
 if 29 - 29: I1Ii111 / OoOoOO00 % I1ii11iIi11i * IiII / II111iiii
 if 10 - 10: O0 / I11i
 data = se . source_cache . walk_cache ( lisp_gather_site_cache_data , data )
 return ( [ True , data ] )
 if 29 - 29: i11iIiiIii % I11i
 if 49 - 49: I11i
 if 69 - 69: o0oOOo0O0Ooo . O0 * I11i
 if 92 - 92: OoO0O00 . O0 / Ii1I % Oo0Ooo . Ii1I
 if 40 - 40: o0oOOo0O0Ooo - Ii1I . iII111i - O0
 if 53 - 53: Oo0Ooo - I1IiiI * O0 . II111iiii
 if 72 - 72: ooOoO0o - Ii1I . Ii1I . I11i / OoooooooOO + Ii1I
def lisp_process_api_ms_or_mr ( ms_or_mr , data ) :
 I1Ii1iIIIIi = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
 I1Iii = data [ "dns-name" ] if data . has_key ( "dns-name" ) else None
 if ( data . has_key ( "address" ) ) :
  I1Ii1iIIIIi . store_address ( data [ "address" ] )
  if 32 - 32: O0
  if 42 - 42: i1IIi * I1ii11iIi11i * OoOoOO00
 iiIIi = { }
 if ( ms_or_mr ) :
  for I1iiIIiiiII in lisp_map_servers_list . values ( ) :
   if ( I1Iii ) :
    if ( I1Iii != I1iiIIiiiII . dns_name ) : continue
   else :
    if ( I1Ii1iIIIIi . is_exact_match ( I1iiIIiiiII . map_server ) == False ) : continue
    if 43 - 43: I1ii11iIi11i % I1ii11iIi11i % i1IIi
    if 56 - 56: I1IiiI - OoO0O00 - iII111i . o0oOOo0O0Ooo . I1Ii111
   iiIIi [ "dns-name" ] = I1iiIIiiiII . dns_name
   iiIIi [ "address" ] = I1iiIIiiiII . map_server . print_address_no_iid ( )
   iiIIi [ "ms-name" ] = "" if I1iiIIiiiII . ms_name == None else I1iiIIiiiII . ms_name
   return ( [ iiIIi ] )
   if 70 - 70: iIii1I11I1II1 - I11i
 else :
  for OOO0o0o in lisp_map_resolvers_list . values ( ) :
   if ( I1Iii ) :
    if ( I1Iii != OOO0o0o . dns_name ) : continue
   else :
    if ( I1Ii1iIIIIi . is_exact_match ( OOO0o0o . map_resolver ) == False ) : continue
    if 2 - 2: oO0o / II111iiii * OoO0O00
    if 71 - 71: i1IIi + I11i * OoO0O00 . OOooOOo + oO0o
   iiIIi [ "dns-name" ] = OOO0o0o . dns_name
   iiIIi [ "address" ] = OOO0o0o . map_resolver . print_address_no_iid ( )
   iiIIi [ "mr-name" ] = "" if OOO0o0o . mr_name == None else OOO0o0o . mr_name
   return ( [ iiIIi ] )
   if 40 - 40: OOooOOo
   if 14 - 14: OoooooooOO - OoooooooOO % i11iIiiIii % ooOoO0o / ooOoO0o
 return ( [ ] )
 if 33 - 33: iII111i / i1IIi . II111iiii % I1ii11iIi11i
 if 74 - 74: iII111i / OOooOOo / O0 / iIii1I11I1II1 + IiII
 if 26 - 26: OOooOOo % i1IIi . I1Ii111 / O0 + I1Ii111
 if 39 - 39: I1ii11iIi11i * I1IiiI * II111iiii . Oo0Ooo % I1IiiI
 if 100 - 100: iIii1I11I1II1 - OoooooooOO * OoooooooOO - iII111i / ooOoO0o
 if 98 - 98: OoO0O00 + oO0o - II111iiii
 if 84 - 84: Oo0Ooo . OoOoOO00 - iII111i
 if 5 - 5: OoooooooOO . O0 / OOooOOo + I11i - Ii1I
def lisp_process_api_database_mapping ( ) :
 i11i111i1 = [ ]
 if 77 - 77: iIii1I11I1II1 * Oo0Ooo . IiII / oO0o + O0
 for o0o0O0OO0oO in lisp_db_list :
  iiIiiIi = { }
  iiIiiIi [ "eid-prefix" ] = o0o0O0OO0oO . eid . print_prefix ( )
  if ( o0o0O0OO0oO . group . is_null ( ) == False ) :
   iiIiiIi [ "group-prefix" ] = o0o0O0OO0oO . group . print_prefix ( )
   if 76 - 76: iII111i + o0oOOo0O0Ooo - OoooooooOO * oO0o % OoooooooOO - O0
   if 18 - 18: Ii1I
  II1I1I1i1i = [ ]
  for IIi in o0o0O0OO0oO . rloc_set :
   o0OOooooooOO = { }
   if ( IIi . rloc . is_null ( ) == False ) :
    o0OOooooooOO [ "rloc" ] = IIi . rloc . print_address_no_iid ( )
    if 82 - 82: OoOoOO00 + OoO0O00 - IiII / ooOoO0o
   if ( IIi . rloc_name != None ) : o0OOooooooOO [ "rloc-name" ] = IIi . rloc_name
   if ( IIi . interface != None ) : o0OOooooooOO [ "interface" ] = IIi . interface
   oOOO0O = IIi . translated_rloc
   if ( oOOO0O . is_null ( ) == False ) :
    o0OOooooooOO [ "translated-rloc" ] = oOOO0O . print_address_no_iid ( )
    if 67 - 67: I1IiiI / i11iIiiIii - I1Ii111 % OoooooooOO
   if ( o0OOooooooOO != { } ) : II1I1I1i1i . append ( o0OOooooooOO )
   if 36 - 36: oO0o % iII111i % oO0o
   if 56 - 56: ooOoO0o - O0 + iII111i % I11i / i1IIi
   if 78 - 78: i1IIi . iIii1I11I1II1
   if 70 - 70: O0 + II111iiii % IiII / I1Ii111 - IiII
   if 58 - 58: II111iiii * oO0o - i1IIi . I11i
  iiIiiIi [ "rlocs" ] = II1I1I1i1i
  if 23 - 23: OoO0O00 - I1IiiI * i11iIiiIii
  if 62 - 62: OoO0O00 . i11iIiiIii / i1IIi
  if 3 - 3: OoO0O00 + O0 % Oo0Ooo * Oo0Ooo % i11iIiiIii
  if 29 - 29: ooOoO0o / iII111i / OOooOOo - iIii1I11I1II1
  i11i111i1 . append ( iiIiiIi )
  if 31 - 31: i1IIi * Ii1I
 return ( i11i111i1 )
 if 94 - 94: oO0o / Ii1I % iIii1I11I1II1 + i1IIi / O0 - iII111i
 if 77 - 77: o0oOOo0O0Ooo - IiII . i1IIi
 if 70 - 70: i1IIi . I1Ii111 . iII111i - OoOoOO00 + II111iiii + OOooOOo
 if 52 - 52: OOooOOo . OoOoOO00 - ooOoO0o % i1IIi
 if 15 - 15: oO0o
 if 6 - 6: oO0o . iIii1I11I1II1 - I1ii11iIi11i % IiII
 if 58 - 58: iII111i * oO0o / iII111i - Oo0Ooo / I1Ii111 * oO0o
def lisp_gather_site_cache_data ( se , data ) :
 iiIiiIi = { }
 iiIiiIi [ "site-name" ] = se . site . site_name
 iiIiiIi [ "instance-id" ] = str ( se . eid . instance_id )
 iiIiiIi [ "eid-prefix" ] = se . eid . print_prefix_no_iid ( )
 if ( se . group . is_null ( ) == False ) :
  iiIiiIi [ "group-prefix" ] = se . group . print_prefix_no_iid ( )
  if 63 - 63: oO0o . IiII . o0oOOo0O0Ooo
 iiIiiIi [ "registered" ] = "yes" if se . registered else "no"
 iiIiiIi [ "first-registered" ] = lisp_print_elapsed ( se . first_registered )
 iiIiiIi [ "last-registered" ] = lisp_print_elapsed ( se . last_registered )
 if 16 - 16: iII111i . I11i - Oo0Ooo / I1IiiI + OoOoOO00
 ooooO0O = se . last_registerer
 ooooO0O = "none" if ooooO0O . is_null ( ) else ooooO0O . print_address ( )
 iiIiiIi [ "last-registerer" ] = ooooO0O
 iiIiiIi [ "ams" ] = "yes" if ( se . accept_more_specifics ) else "no"
 iiIiiIi [ "dynamic" ] = "yes" if ( se . dynamic ) else "no"
 iiIiiIi [ "site-id" ] = str ( se . site_id )
 if ( se . xtr_id_present ) :
  iiIiiIi [ "xtr-id" ] = "0x" + lisp_hex_string ( se . xtr_id )
  if 14 - 14: iIii1I11I1II1 / i11iIiiIii - o0oOOo0O0Ooo . iII111i * OoO0O00
  if 5 - 5: Ii1I + OoOoOO00 % I11i + IiII
  if 55 - 55: OoooooooOO + oO0o . o0oOOo0O0Ooo % iIii1I11I1II1 - I1Ii111
  if 40 - 40: I1IiiI . o0oOOo0O0Ooo - Oo0Ooo
  if 44 - 44: Ii1I % OoO0O00 * oO0o * OoO0O00
 O0Oo0O = [ ]
 for o0OOooooooOO in se . registered_rlocs :
  IIi = { }
  IIi [ "address" ] = o0OOooooooOO . rloc . print_address_no_iid ( ) if o0OOooooooOO . rloc_exists ( ) else "none"
  if 7 - 7: I1Ii111 % i1IIi . I11i . O0 / i1IIi
  if 56 - 56: Oo0Ooo
  if ( o0OOooooooOO . geo ) : IIi [ "geo" ] = o0OOooooooOO . geo . print_geo ( )
  if ( o0OOooooooOO . elp ) : IIi [ "elp" ] = o0OOooooooOO . elp . print_elp ( False )
  if ( o0OOooooooOO . rle ) : IIi [ "rle" ] = o0OOooooooOO . rle . print_rle ( False )
  if ( o0OOooooooOO . json ) : IIi [ "json" ] = o0OOooooooOO . json . print_json ( False )
  if ( o0OOooooooOO . rloc_name ) : IIi [ "rloc-name" ] = o0OOooooooOO . rloc_name
  IIi [ "uptime" ] = lisp_print_elapsed ( o0OOooooooOO . uptime )
  IIi [ "upriority" ] = str ( o0OOooooooOO . priority )
  IIi [ "uweight" ] = str ( o0OOooooooOO . weight )
  IIi [ "mpriority" ] = str ( o0OOooooooOO . mpriority )
  IIi [ "mweight" ] = str ( o0OOooooooOO . mweight )
  if 21 - 21: i11iIiiIii * o0oOOo0O0Ooo + Oo0Ooo
  O0Oo0O . append ( IIi )
  if 20 - 20: IiII / OoooooooOO / O0 / I1Ii111 * ooOoO0o
 iiIiiIi [ "registered-rlocs" ] = O0Oo0O
 if 45 - 45: ooOoO0o / Oo0Ooo % o0oOOo0O0Ooo . ooOoO0o
 data . append ( iiIiiIi )
 return ( [ True , data ] )
 if 19 - 19: o0oOOo0O0Ooo % I11i . I1ii11iIi11i
 if 70 - 70: Oo0Ooo - I11i / I1ii11iIi11i % OoO0O00 % II111iiii
 if 72 - 72: i11iIiiIii * I11i
 if 69 - 69: I1Ii111 . Ii1I * I1ii11iIi11i % I11i - o0oOOo0O0Ooo
 if 30 - 30: ooOoO0o / Oo0Ooo * iII111i % OoooooooOO / I1ii11iIi11i
 if 64 - 64: OoooooooOO
 if 41 - 41: Ii1I . I11i / oO0o * OoooooooOO
def lisp_process_api_site_cache_entry ( parms ) :
 OO0OO000 = parms [ "instance-id" ]
 OO0OO000 = 0 if ( OO0OO000 == "" ) else int ( OO0OO000 )
 if 98 - 98: I1ii11iIi11i - O0 + i11iIiiIii
 if 71 - 71: O0 - OoooooooOO
 if 82 - 82: i11iIiiIii * II111iiii % IiII
 if 80 - 80: Ii1I . i11iIiiIii % oO0o * o0oOOo0O0Ooo
 ii1Ii = lisp_address ( LISP_AFI_NONE , "" , 0 , OO0OO000 )
 ii1Ii . store_prefix ( parms [ "eid-prefix" ] )
 if 56 - 56: I1Ii111 % iII111i / II111iiii - Oo0Ooo - Oo0Ooo - iIii1I11I1II1
 if 67 - 67: iII111i
 if 80 - 80: Ii1I . iII111i * I1IiiI * Ii1I
 if 82 - 82: OoO0O00 % OoOoOO00 * i11iIiiIii . OoO0O00 . I1ii11iIi11i + Ii1I
 if 60 - 60: i1IIi / iII111i
 IiI1111i1i11I = lisp_address ( LISP_AFI_NONE , "" , 0 , OO0OO000 )
 if ( parms . has_key ( "group-prefix" ) ) :
  IiI1111i1i11I . store_prefix ( parms [ "group-prefix" ] )
  if 10 - 10: I1Ii111 / OoOoOO00 * Ii1I % o0oOOo0O0Ooo . OoOoOO00 / I1ii11iIi11i
  if 2 - 2: iIii1I11I1II1
 i11i111i1 = [ ]
 OoOo0OOoOOO00 = lisp_site_eid_lookup ( ii1Ii , IiI1111i1i11I , False )
 if ( OoOo0OOoOOO00 ) : lisp_gather_site_cache_data ( OoOo0OOoOOO00 , i11i111i1 )
 return ( i11i111i1 )
 if 85 - 85: O0 - ooOoO0o
 if 35 - 35: o0oOOo0O0Ooo - I1IiiI
 if 47 - 47: i11iIiiIii * iII111i . OoOoOO00 * I1Ii111 % i11iIiiIii + Ii1I
 if 65 - 65: Ii1I % i11iIiiIii
 if 98 - 98: iII111i * o0oOOo0O0Ooo % Oo0Ooo
 if 7 - 7: oO0o * OoooooooOO % o0oOOo0O0Ooo . I1Ii111 + O0
 if 14 - 14: I11i * II111iiii % o0oOOo0O0Ooo / iII111i . OoooooooOO % iII111i
def lisp_get_interface_instance_id ( device , source_eid ) :
 oOOoo = None
 if ( lisp_myinterfaces . has_key ( device ) ) :
  oOOoo = lisp_myinterfaces [ device ]
  if 88 - 88: iII111i
  if 94 - 94: OoooooooOO
  if 32 - 32: I1ii11iIi11i
  if 8 - 8: I11i * i11iIiiIii - ooOoO0o
  if 47 - 47: ooOoO0o . I1IiiI / i11iIiiIii * iII111i * I1IiiI
  if 8 - 8: oO0o % oO0o . iII111i / i1IIi % IiII
 if ( oOOoo == None or oOOoo . instance_id == None ) :
  return ( lisp_default_iid )
  if 71 - 71: OoOoOO00 + oO0o % O0 + Oo0Ooo
  if 62 - 62: i1IIi . Ii1I * i1IIi * O0 . I1IiiI % o0oOOo0O0Ooo
  if 16 - 16: I11i . Ii1I - ooOoO0o . OOooOOo % O0 / oO0o
  if 42 - 42: II111iiii . iII111i
  if 67 - 67: i1IIi - i11iIiiIii / ooOoO0o * oO0o
  if 64 - 64: oO0o / IiII
  if 86 - 86: I11i
  if 36 - 36: o0oOOo0O0Ooo / OoO0O00
  if 6 - 6: I11i % I1IiiI + iII111i * OoooooooOO . O0
 OO0OO000 = oOOoo . get_instance_id ( )
 if ( source_eid == None ) : return ( OO0OO000 )
 if 87 - 87: ooOoO0o / Ii1I % O0 . OoO0O00
 OoOoooOo = source_eid . instance_id
 iII11I1 = None
 for oOOoo in lisp_multi_tenant_interfaces :
  if ( oOOoo . device != device ) : continue
  iiIIiI = oOOoo . multi_tenant_eid
  source_eid . instance_id = iiIIiI . instance_id
  if ( source_eid . is_more_specific ( iiIIiI ) == False ) : continue
  if ( iII11I1 == None or iII11I1 . multi_tenant_eid . mask_len < iiIIiI . mask_len ) :
   iII11I1 = oOOoo
   if 82 - 82: iII111i * iIii1I11I1II1 * ooOoO0o + OoooooooOO / OoO0O00 . i11iIiiIii
   if 32 - 32: Oo0Ooo % O0 * I1ii11iIi11i . oO0o - iII111i
 source_eid . instance_id = OoOoooOo
 if 61 - 61: ooOoO0o % II111iiii
 if ( iII11I1 == None ) : return ( OO0OO000 )
 return ( iII11I1 . get_instance_id ( ) )
 if 62 - 62: i11iIiiIii . Oo0Ooo / Oo0Ooo . IiII . OoooooooOO
 if 86 - 86: I1ii11iIi11i * OoOoOO00 + iII111i
 if 79 - 79: I11i - II111iiii
 if 27 - 27: I1IiiI + o0oOOo0O0Ooo * oO0o % I1IiiI
 if 66 - 66: OoO0O00 + IiII . o0oOOo0O0Ooo . IiII
 if 88 - 88: oO0o + oO0o % OoO0O00 . OoooooooOO - OoooooooOO . Oo0Ooo
 if 44 - 44: I1IiiI * IiII . OoooooooOO
 if 62 - 62: I11i - Ii1I / i11iIiiIii * I1IiiI + ooOoO0o + o0oOOo0O0Ooo
 if 10 - 10: i1IIi + o0oOOo0O0Ooo
def lisp_allow_dynamic_eid ( device , eid ) :
 if ( lisp_myinterfaces . has_key ( device ) == False ) : return ( None )
 if 47 - 47: OOooOOo * IiII % I1Ii111 . OoOoOO00 - OoooooooOO / OoooooooOO
 oOOoo = lisp_myinterfaces [ device ]
 O00ooo0ooO0 = device if oOOoo . dynamic_eid_device == None else oOOoo . dynamic_eid_device
 if 14 - 14: iIii1I11I1II1 / I11i - o0oOOo0O0Ooo / IiII / o0oOOo0O0Ooo . OoO0O00
 if 2 - 2: I11i
 if ( oOOoo . does_dynamic_eid_match ( eid ) ) : return ( O00ooo0ooO0 )
 return ( None )
 if 12 - 12: i1IIi . I1Ii111
 if 99 - 99: Oo0Ooo / i11iIiiIii
 if 81 - 81: Ii1I . i1IIi % iII111i . OoO0O00 % IiII
 if 42 - 42: iII111i / Oo0Ooo
 if 14 - 14: O0 . Oo0Ooo
 if 8 - 8: i11iIiiIii
 if 80 - 80: I1ii11iIi11i + Ii1I
def lisp_start_rloc_probe_timer ( interval , lisp_sockets ) :
 global lisp_rloc_probe_timer
 if 16 - 16: i11iIiiIii * Oo0Ooo
 if ( lisp_rloc_probe_timer != None ) : lisp_rloc_probe_timer . cancel ( )
 if 76 - 76: iII111i . oO0o - i1IIi
 oo00o0o00Oo = lisp_process_rloc_probe_timer
 IiIII = threading . Timer ( interval , oo00o0o00Oo , [ lisp_sockets ] )
 lisp_rloc_probe_timer = IiIII
 IiIII . start ( )
 return
 if 47 - 47: I1ii11iIi11i
 if 69 - 69: oO0o + Ii1I
 if 46 - 46: I1IiiI + OoO0O00 - Oo0Ooo
 if 13 - 13: OoOoOO00
 if 72 - 72: II111iiii * iII111i . II111iiii + iII111i * IiII
 if 90 - 90: oO0o * I1Ii111 / O0
 if 15 - 15: o0oOOo0O0Ooo * O0 . OOooOOo / Oo0Ooo
def lisp_show_rloc_probe_list ( ) :
 lprint ( bold ( "----- RLOC-probe-list -----" , False ) )
 for i1iI11iI in lisp_rloc_probe_list :
  iiii1i1 = lisp_rloc_probe_list [ i1iI11iI ]
  lprint ( "RLOC {}:" . format ( i1iI11iI ) )
  for IIi , o0o000 , IiIoO0oo0 in iiii1i1 :
   lprint ( "  [{}, {}, {}, {}]" . format ( hex ( id ( IIi ) ) , o0o000 . print_prefix ( ) ,
 IiIoO0oo0 . print_prefix ( ) , IIi . translated_port ) )
   if 31 - 31: OoooooooOO - OoO0O00 . iIii1I11I1II1 % I1IiiI
   if 98 - 98: I1IiiI + Ii1I
 lprint ( bold ( "---------------------------" , False ) )
 return
 if 7 - 7: o0oOOo0O0Ooo . OoooooooOO
 if 32 - 32: I1ii11iIi11i
 if 46 - 46: Ii1I . i11iIiiIii / I1Ii111 - I1ii11iIi11i
 if 13 - 13: IiII % I1Ii111
 if 9 - 9: OoooooooOO * ooOoO0o % I1ii11iIi11i . I1IiiI % O0
 if 91 - 91: OOooOOo * OoooooooOO * I1IiiI . i1IIi
 if 9 - 9: oO0o / i11iIiiIii + IiII / IiII - I11i
 if 87 - 87: iII111i
 if 37 - 37: oO0o + OoO0O00
def lisp_mark_rlocs_for_other_eids ( eid_list ) :
 if 66 - 66: iIii1I11I1II1 * iIii1I11I1II1 + IiII % I1IiiI
 if 60 - 60: I1Ii111 . IiII / Oo0Ooo
 if 32 - 32: OoOoOO00 + Ii1I * iII111i % Oo0Ooo
 if 61 - 61: OoooooooOO % iII111i - O0
 o0OOooooooOO , o0o000 , IiIoO0oo0 = eid_list [ 0 ]
 oooOoo0OO0 = [ lisp_print_eid_tuple ( o0o000 , IiIoO0oo0 ) ]
 if 24 - 24: iIii1I11I1II1 . I11i
 for o0OOooooooOO , o0o000 , IiIoO0oo0 in eid_list [ 1 : : ] :
  o0OOooooooOO . state = LISP_RLOC_UNREACH_STATE
  o0OOooooooOO . last_state_change = lisp_get_timestamp ( )
  oooOoo0OO0 . append ( lisp_print_eid_tuple ( o0o000 , IiIoO0oo0 ) )
  if 47 - 47: i11iIiiIii
  if 92 - 92: I1Ii111 + OoO0O00 - iIii1I11I1II1 / iIii1I11I1II1
 I1IiI1I11iI1i = bold ( "unreachable" , False )
 oo00OO = red ( o0OOooooooOO . rloc . print_address_no_iid ( ) , False )
 if 27 - 27: OOooOOo - o0oOOo0O0Ooo % OOooOOo
 for ii1Ii in oooOoo0OO0 :
  o0o000 = green ( ii1Ii , False )
  lprint ( "RLOC {} went {} for EID {}" . format ( oo00OO , I1IiI1I11iI1i , o0o000 ) )
  if 79 - 79: iIii1I11I1II1 / I1Ii111 + I11i % II111iiii - Oo0Ooo
  if 51 - 51: II111iiii * OoO0O00 . OoOoOO00 * OoO0O00
  if 95 - 95: I1Ii111 * OoooooooOO + iII111i
  if 10 - 10: i1IIi - O0 / Oo0Ooo
  if 54 - 54: OoO0O00
  if 38 - 38: II111iiii + o0oOOo0O0Ooo * I11i + I1Ii111 - II111iiii . OOooOOo
 for o0OOooooooOO , o0o000 , IiIoO0oo0 in eid_list :
  OoOOO000O0o = lisp_map_cache . lookup_cache ( o0o000 , True )
  if ( OoOOO000O0o ) : lisp_write_ipc_map_cache ( True , OoOOO000O0o )
  if 38 - 38: I1ii11iIi11i % OOooOOo + iII111i / Oo0Ooo / IiII / oO0o
 return
 if 2 - 2: iIii1I11I1II1
 if 9 - 9: I1Ii111 / IiII
 if 33 - 33: o0oOOo0O0Ooo + oO0o . o0oOOo0O0Ooo . I11i * OoooooooOO + iIii1I11I1II1
 if 64 - 64: OoooooooOO . Ii1I
 if 38 - 38: Oo0Ooo
 if 64 - 64: ooOoO0o % i11iIiiIii
 if 10 - 10: Ii1I % oO0o + oO0o * OoOoOO00 % iII111i / o0oOOo0O0Ooo
 if 17 - 17: iII111i / I1IiiI . II111iiii - OoO0O00 + iII111i
 if 22 - 22: Oo0Ooo - I1ii11iIi11i + I11i . oO0o
 if 85 - 85: iIii1I11I1II1 / Ii1I
def lisp_process_rloc_probe_timer ( lisp_sockets ) :
 lisp_set_exception ( )
 if 43 - 43: I1IiiI % I1Ii111 - oO0o . II111iiii / iIii1I11I1II1
 lisp_start_rloc_probe_timer ( LISP_RLOC_PROBE_INTERVAL , lisp_sockets )
 if ( lisp_rloc_probing == False ) : return
 if 97 - 97: I1Ii111 + I1ii11iIi11i
 if 21 - 21: O0 + o0oOOo0O0Ooo * OoooooooOO % IiII % I1ii11iIi11i
 if 80 - 80: I11i
 if 28 - 28: OoOoOO00 * OoooooooOO * i11iIiiIii
 if ( lisp_print_rloc_probe_list ) : lisp_show_rloc_probe_list ( )
 if 88 - 88: ooOoO0o + ooOoO0o / I1Ii111
 if 69 - 69: O0 * o0oOOo0O0Ooo + i1IIi * ooOoO0o . o0oOOo0O0Ooo
 if 46 - 46: Oo0Ooo / Oo0Ooo * IiII
 if 65 - 65: iIii1I11I1II1 * o0oOOo0O0Ooo - iII111i % II111iiii - I1ii11iIi11i
 o0Oo0O00oo = lisp_get_default_route_next_hops ( )
 if 11 - 11: I1ii11iIi11i + iIii1I11I1II1 - I1Ii111 * iIii1I11I1II1 * IiII + oO0o
 lprint ( "---------- Start RLOC Probing for {} entries ----------" . format ( len ( lisp_rloc_probe_list ) ) )
 if 6 - 6: I1Ii111 * OOooOOo + i1IIi - Ii1I / oO0o
 if 81 - 81: I1Ii111 % oO0o * i1IIi * OoooooooOO / Oo0Ooo
 if 70 - 70: I1IiiI
 if 35 - 35: i11iIiiIii
 if 59 - 59: ooOoO0o . iII111i - II111iiii
 O0oO = 0
 OOo00o = bold ( "RLOC-probe" , False )
 for iII1ii1IiII in lisp_rloc_probe_list . values ( ) :
  if 26 - 26: Ii1I * Oo0Ooo + II111iiii + Ii1I
  if 70 - 70: I1ii11iIi11i + i1IIi
  if 54 - 54: I1IiiI - i11iIiiIii - i11iIiiIii / oO0o
  if 43 - 43: I11i / OOooOOo + OOooOOo
  if 62 - 62: OOooOOo . iIii1I11I1II1 + I1IiiI / OOooOOo
  oo0OOoOOOO = None
  for iiIiII1iiI1i1 , ii1Ii , IiI1111i1i11I in iII1ii1IiII :
   I1IIII1i1 = iiIiII1iiI1i1 . rloc . print_address_no_iid ( )
   if 63 - 63: iIii1I11I1II1 . OoooooooOO
   if 78 - 78: I1IiiI / iIii1I11I1II1 / I1IiiI
   if 21 - 21: oO0o - IiII
   if 61 - 61: o0oOOo0O0Ooo
   o0oO , OOoOOo0o0 = lisp_allow_gleaning ( ii1Ii , iiIiII1iiI1i1 )
   if ( o0oO and OOoOOo0o0 == False ) :
    o0o000 = green ( ii1Ii . print_address ( ) , False )
    I1IIII1i1 += ":{}" . format ( iiIiII1iiI1i1 . translated_port )
    lprint ( "Suppress probe to RLOC {} for gleaned EID {}" . format ( red ( I1IIII1i1 , False ) , o0o000 ) )
    if 1 - 1: OoOoOO00
    continue
    if 19 - 19: i11iIiiIii - Oo0Ooo
    if 12 - 12: I1IiiI % OoOoOO00
    if 42 - 42: i1IIi . OoooooooOO . OoOoOO00 . I1ii11iIi11i % OOooOOo / oO0o
    if 33 - 33: O0 / OoO0O00 / OOooOOo / II111iiii * ooOoO0o
    if 25 - 25: O0 * o0oOOo0O0Ooo - iII111i % OoO0O00
    if 6 - 6: ooOoO0o % Oo0Ooo / I1Ii111 % i11iIiiIii * OoooooooOO + I1ii11iIi11i
    if 21 - 21: o0oOOo0O0Ooo - iII111i / OoO0O00
   if ( iiIiII1iiI1i1 . down_state ( ) ) : continue
   if 12 - 12: I1ii11iIi11i - I11i * O0 % I1IiiI + O0 - II111iiii
   if 13 - 13: iII111i / OOooOOo * i11iIiiIii / oO0o / OoooooooOO
   if 89 - 89: Ii1I * Oo0Ooo / I1Ii111 * I1ii11iIi11i + O0 * Oo0Ooo
   if 74 - 74: I11i . I11i
   if 74 - 74: OoOoOO00 * ooOoO0o * I1Ii111
   if 56 - 56: iIii1I11I1II1 * OoO0O00 - oO0o * Ii1I
   if 62 - 62: i1IIi + I11i / OOooOOo - OoooooooOO % i1IIi . I1IiiI
   if 13 - 13: O0 * iII111i
   if 26 - 26: i1IIi - I1Ii111 - ooOoO0o
   if 73 - 73: o0oOOo0O0Ooo . OoooooooOO
   if 96 - 96: i1IIi - OOooOOo / I11i % OoOoOO00 - i11iIiiIii % II111iiii
   if ( oo0OOoOOOO ) :
    iiIiII1iiI1i1 . last_rloc_probe_nonce = oo0OOoOOOO . last_rloc_probe_nonce
    if 47 - 47: I1Ii111 * iII111i
    if ( oo0OOoOOOO . translated_port == iiIiII1iiI1i1 . translated_port and oo0OOoOOOO . rloc_name == iiIiII1iiI1i1 . rloc_name ) :
     if 90 - 90: i1IIi * Ii1I . OoO0O00 % I11i * ooOoO0o . OOooOOo
     o0o000 = green ( lisp_print_eid_tuple ( ii1Ii , IiI1111i1i11I ) , False )
     lprint ( "Suppress probe to duplicate RLOC {} for {}" . format ( red ( I1IIII1i1 , False ) , o0o000 ) )
     if 76 - 76: iIii1I11I1II1 . i11iIiiIii * II111iiii - iII111i
     continue
     if 51 - 51: I1IiiI
     if 52 - 52: I1Ii111
     if 82 - 82: iII111i + II111iiii
   oOoo = None
   o0OOooooooOO = None
   while ( True ) :
    o0OOooooooOO = iiIiII1iiI1i1 if o0OOooooooOO == None else o0OOooooooOO . next_rloc
    if ( o0OOooooooOO == None ) : break
    if 29 - 29: O0 % Ii1I * ooOoO0o % O0
    if 83 - 83: oO0o
    if 95 - 95: Oo0Ooo * O0 % i1IIi / iII111i + oO0o
    if 85 - 85: iIii1I11I1II1 / I11i
    if 65 - 65: I11i / i1IIi * OoOoOO00 * Ii1I * OoO0O00
    if ( o0OOooooooOO . rloc_next_hop != None ) :
     if ( o0OOooooooOO . rloc_next_hop not in o0Oo0O00oo ) :
      if ( o0OOooooooOO . up_state ( ) ) :
       oOOoO0O , iiiIIiII111I = o0OOooooooOO . rloc_next_hop
       o0OOooooooOO . state = LISP_RLOC_UNREACH_STATE
       o0OOooooooOO . last_state_change = lisp_get_timestamp ( )
       lisp_update_rtr_updown ( o0OOooooooOO . rloc , False )
       if 74 - 74: I1ii11iIi11i . I1ii11iIi11i % IiII + OOooOOo . OoO0O00 * I11i
      I1IiI1I11iI1i = bold ( "unreachable" , False )
      lprint ( "Next-hop {}({}) for RLOC {} is {}" . format ( iiiIIiII111I , oOOoO0O ,
 red ( I1IIII1i1 , False ) , I1IiI1I11iI1i ) )
      continue
      if 20 - 20: OOooOOo % i1IIi * Ii1I / i11iIiiIii
      if 89 - 89: ooOoO0o
      if 83 - 83: I11i . I11i * OOooOOo - OOooOOo
      if 46 - 46: iIii1I11I1II1 . I1Ii111 % I1IiiI
      if 22 - 22: i1IIi * I11i + II111iiii + II111iiii
      if 20 - 20: I11i
    oOo = o0OOooooooOO . last_rloc_probe
    ii1iIi1iiI1II = 0 if oOo == None else time . time ( ) - oOo
    if ( o0OOooooooOO . unreach_state ( ) and ii1iIi1iiI1II < LISP_RLOC_PROBE_INTERVAL ) :
     lprint ( "Waiting for probe-reply from RLOC {}" . format ( red ( I1IIII1i1 , False ) ) )
     if 3 - 3: i11iIiiIii * I1IiiI + I11i . II111iiii % I1Ii111
     continue
     if 97 - 97: OoO0O00 / I1IiiI + OOooOOo . i1IIi . ooOoO0o . o0oOOo0O0Ooo
     if 21 - 21: OOooOOo - II111iiii * I1IiiI / i11iIiiIii * I1IiiI
     if 65 - 65: o0oOOo0O0Ooo - IiII
     if 3 - 3: OOooOOo * ooOoO0o / i11iIiiIii . OoO0O00 * ooOoO0o
     if 58 - 58: i1IIi - OoO0O00 * II111iiii
     if 92 - 92: ooOoO0o / I1Ii111 . iII111i
    O00o = lisp_get_echo_nonce ( None , I1IIII1i1 )
    if ( O00o and O00o . request_nonce_timeout ( ) ) :
     o0OOooooooOO . state = LISP_RLOC_NO_ECHOED_NONCE_STATE
     o0OOooooooOO . last_state_change = lisp_get_timestamp ( )
     I1IiI1I11iI1i = bold ( "unreachable" , False )
     lprint ( "RLOC {} went {}, nonce-echo failed" . format ( red ( I1IIII1i1 , False ) , I1IiI1I11iI1i ) )
     if 59 - 59: Ii1I - OoO0O00 % iII111i + I1ii11iIi11i * iII111i
     lisp_update_rtr_updown ( o0OOooooooOO . rloc , False )
     continue
     if 51 - 51: ooOoO0o - Oo0Ooo / iII111i . I11i - Ii1I / OOooOOo
     if 4 - 4: II111iiii + OoOoOO00 . ooOoO0o - I11i . I1IiiI
     if 46 - 46: II111iiii
     if 38 - 38: OOooOOo % II111iiii
     if 82 - 82: i11iIiiIii . OoooooooOO % OoOoOO00 * O0 - I1Ii111
     if 78 - 78: OoOoOO00 % Ii1I % OOooOOo % Oo0Ooo % I11i . Ii1I
    if ( O00o and O00o . recently_echoed ( ) ) :
     lprint ( ( "Suppress RLOC-probe to {}, nonce-echo " + "received" ) . format ( red ( I1IIII1i1 , False ) ) )
     if 73 - 73: OoooooooOO / i1IIi . iIii1I11I1II1
     continue
     if 89 - 89: I1Ii111
     if 29 - 29: I11i * ooOoO0o - OoooooooOO
     if 92 - 92: O0 % i1IIi / OOooOOo - oO0o
     if 83 - 83: o0oOOo0O0Ooo . OoO0O00 % iIii1I11I1II1 % OoOoOO00 - i11iIiiIii
     if 71 - 71: I1ii11iIi11i - II111iiii / O0 % i1IIi + oO0o
     if 73 - 73: OoooooooOO
    if ( o0OOooooooOO . last_rloc_probe != None ) :
     oOo = o0OOooooooOO . last_rloc_probe_reply
     if ( oOo == None ) : oOo = 0
     ii1iIi1iiI1II = time . time ( ) - oOo
     if ( o0OOooooooOO . up_state ( ) and ii1iIi1iiI1II >= LISP_RLOC_PROBE_REPLY_WAIT ) :
      if 25 - 25: i1IIi . II111iiii . I1Ii111
      o0OOooooooOO . state = LISP_RLOC_UNREACH_STATE
      o0OOooooooOO . last_state_change = lisp_get_timestamp ( )
      lisp_update_rtr_updown ( o0OOooooooOO . rloc , False )
      I1IiI1I11iI1i = bold ( "unreachable" , False )
      lprint ( "RLOC {} went {}, probe it" . format ( red ( I1IIII1i1 , False ) , I1IiI1I11iI1i ) )
      if 81 - 81: II111iiii + OoOoOO00 * II111iiii / iIii1I11I1II1 - Oo0Ooo % oO0o
      if 66 - 66: ooOoO0o % O0 + iIii1I11I1II1 * I1Ii111 - I1Ii111
      lisp_mark_rlocs_for_other_eids ( iII1ii1IiII )
      if 61 - 61: I1ii11iIi11i
      if 12 - 12: OoO0O00
      if 97 - 97: OOooOOo . Oo0Ooo . oO0o * i1IIi
    o0OOooooooOO . last_rloc_probe = lisp_get_timestamp ( )
    if 7 - 7: Oo0Ooo
    iIIi111iI = "" if o0OOooooooOO . unreach_state ( ) == False else " unreachable"
    if 1 - 1: II111iiii % oO0o . IiII
    if 85 - 85: oO0o % iII111i + IiII + I1Ii111
    if 5 - 5: O0 . I11i % i11iIiiIii - i1IIi . OOooOOo
    if 25 - 25: OOooOOo / II111iiii % OoO0O00 / Oo0Ooo * Ii1I
    if 40 - 40: IiII * Oo0Ooo . OoooooooOO * I1Ii111 / I1Ii111
    if 17 - 17: oO0o * OOooOOo . II111iiii - I11i - i11iIiiIii % I1Ii111
    if 38 - 38: OoOoOO00
    I1iIi11I1 = ""
    iiiIIiII111I = None
    if ( o0OOooooooOO . rloc_next_hop != None ) :
     oOOoO0O , iiiIIiII111I = o0OOooooooOO . rloc_next_hop
     lisp_install_host_route ( I1IIII1i1 , iiiIIiII111I , True )
     I1iIi11I1 = ", send on nh {}({})" . format ( iiiIIiII111I , oOOoO0O )
     if 38 - 38: I11i + I11i - Oo0Ooo . oO0o * OoooooooOO
     if 72 - 72: Oo0Ooo / II111iiii
     if 66 - 66: I11i / ooOoO0o / OOooOOo % ooOoO0o
     if 6 - 6: o0oOOo0O0Ooo / ooOoO0o + OOooOOo / I1ii11iIi11i % I1Ii111
     if 68 - 68: OOooOOo % OOooOOo
    oOOO0Ooooo = o0OOooooooOO . print_rloc_probe_rtt ( )
    oOoOOOOo = I1IIII1i1
    if ( o0OOooooooOO . translated_port != 0 ) :
     oOoOOOOo += ":{}" . format ( o0OOooooooOO . translated_port )
     if 72 - 72: OoooooooOO % I1IiiI . OoO0O00
    oOoOOOOo = red ( oOoOOOOo , False )
    if ( o0OOooooooOO . rloc_name != None ) :
     oOoOOOOo += " (" + blue ( o0OOooooooOO . rloc_name , False ) + ")"
     if 28 - 28: II111iiii / iIii1I11I1II1 / iII111i - o0oOOo0O0Ooo . I1IiiI / O0
    lprint ( "Send {}{} {}, last rtt: {}{}" . format ( OOo00o , iIIi111iI ,
 oOoOOOOo , oOOO0Ooooo , I1iIi11I1 ) )
    if 16 - 16: ooOoO0o * oO0o . OoooooooOO
    if 44 - 44: iIii1I11I1II1 * OOooOOo + OoO0O00 - OoooooooOO
    if 13 - 13: Oo0Ooo . I11i . II111iiii
    if 6 - 6: OOooOOo . IiII / OoO0O00 * oO0o - I1Ii111 . OoOoOO00
    if 85 - 85: i11iIiiIii + OoOoOO00
    if 4 - 4: OOooOOo . OoO0O00 * II111iiii + OoO0O00 % Oo0Ooo
    if 60 - 60: OOooOOo . Ii1I
    if 13 - 13: i1IIi . iII111i / OoOoOO00 . I1Ii111
    if ( o0OOooooooOO . rloc_next_hop != None ) :
     oOoo = lisp_get_host_route_next_hop ( I1IIII1i1 )
     if ( oOoo ) : lisp_install_host_route ( I1IIII1i1 , oOoo , False )
     if 65 - 65: oO0o % I1Ii111 % OoO0O00 . iIii1I11I1II1
     if 38 - 38: IiII / I11i / IiII * iII111i
     if 30 - 30: oO0o
     if 30 - 30: IiII / OoO0O00
     if 89 - 89: oO0o . OoOoOO00 . IiII / iIii1I11I1II1 . iIii1I11I1II1 / OoOoOO00
     if 86 - 86: OoooooooOO - iIii1I11I1II1 . OoO0O00 * Ii1I / I1Ii111 + I1Ii111
    if ( o0OOooooooOO . rloc . is_null ( ) ) :
     o0OOooooooOO . rloc . copy_address ( iiIiII1iiI1i1 . rloc )
     if 52 - 52: iIii1I11I1II1 % OoO0O00 - IiII % i11iIiiIii - o0oOOo0O0Ooo
     if 25 - 25: Oo0Ooo - OOooOOo . i1IIi * OoOoOO00 / I11i / o0oOOo0O0Ooo
     if 54 - 54: OoOoOO00 / i1IIi + OOooOOo - I1ii11iIi11i - I1IiiI * I1Ii111
     if 91 - 91: OoooooooOO * OoooooooOO
     if 27 - 27: ooOoO0o / I1IiiI * I1ii11iIi11i . o0oOOo0O0Ooo
    IiIiiiiI1 = None if ( IiI1111i1i11I . is_null ( ) ) else ii1Ii
    iIiiIi1i1I1I1 = ii1Ii if ( IiI1111i1i11I . is_null ( ) ) else IiI1111i1i11I
    lisp_send_map_request ( lisp_sockets , 0 , IiIiiiiI1 , iIiiIi1i1I1I1 , o0OOooooooOO )
    oo0OOoOOOO = iiIiII1iiI1i1
    if 97 - 97: OOooOOo % I1ii11iIi11i + I1Ii111 + I1IiiI + iIii1I11I1II1
    if 77 - 77: O0
    if 53 - 53: ooOoO0o . ooOoO0o
    if 80 - 80: i11iIiiIii % I1Ii111 % I1IiiI / I1IiiI + oO0o + iII111i
    if ( iiiIIiII111I ) : lisp_install_host_route ( I1IIII1i1 , iiiIIiII111I , False )
    if 18 - 18: OoO0O00 * ooOoO0o
    if 32 - 32: oO0o . OoooooooOO - o0oOOo0O0Ooo + II111iiii
    if 4 - 4: OOooOOo * I1IiiI - I11i - I11i
    if 67 - 67: I1IiiI
    if 32 - 32: oO0o * i11iIiiIii - I11i % Oo0Ooo * I1ii11iIi11i
   if ( oOoo ) : lisp_install_host_route ( I1IIII1i1 , oOoo , True )
   if 79 - 79: II111iiii / Oo0Ooo / I1ii11iIi11i
   if 30 - 30: I11i . o0oOOo0O0Ooo / II111iiii
   if 59 - 59: i11iIiiIii
   if 5 - 5: i11iIiiIii + o0oOOo0O0Ooo . OoO0O00 % OoOoOO00 + I11i
   O0oO += 1
   if ( ( O0oO % 10 ) == 0 ) : time . sleep ( 0.020 )
   if 59 - 59: I1ii11iIi11i
   if 47 - 47: I1IiiI + Oo0Ooo
   if 78 - 78: i1IIi / I1ii11iIi11i % ooOoO0o * OoO0O00
 lprint ( "---------- End RLOC Probing ----------" )
 return
 if 10 - 10: i1IIi % ooOoO0o / iII111i
 if 98 - 98: IiII / o0oOOo0O0Ooo - i1IIi - OOooOOo
 if 65 - 65: Ii1I + OoOoOO00 * Oo0Ooo . O0 . IiII
 if 33 - 33: i11iIiiIii . i1IIi . I1Ii111 - OoOoOO00 + OOooOOo
 if 34 - 34: I1ii11iIi11i . i1IIi * O0 / OoooooooOO
 if 22 - 22: OOooOOo % o0oOOo0O0Ooo - i11iIiiIii
 if 58 - 58: IiII . Ii1I + II111iiii
 if 31 - 31: i11iIiiIii + i11iIiiIii + I11i * Oo0Ooo . I11i
def lisp_update_rtr_updown ( rtr , updown ) :
 global lisp_ipc_socket
 if 28 - 28: OOooOOo * iIii1I11I1II1 * OoOoOO00
 if 75 - 75: Oo0Ooo % IiII + II111iiii + oO0o
 if 35 - 35: I1ii11iIi11i - oO0o - O0 / iII111i % IiII
 if 10 - 10: OOooOOo + oO0o - I1Ii111 . I1IiiI
 if ( lisp_i_am_itr == False ) : return
 if 11 - 11: I1ii11iIi11i . I1Ii111 / o0oOOo0O0Ooo + IiII
 if 73 - 73: OoO0O00 . i11iIiiIii * OoO0O00 * i1IIi + I11i
 if 27 - 27: i11iIiiIii / OoOoOO00 % O0 / II111iiii . I11i - ooOoO0o
 if 54 - 54: oO0o * II111iiii
 if 79 - 79: o0oOOo0O0Ooo . ooOoO0o . Oo0Ooo * OoooooooOO
 if ( lisp_register_all_rtrs ) : return
 if 98 - 98: ooOoO0o
 o0O0OO0O0OOo0 = rtr . print_address_no_iid ( )
 if 39 - 39: o0oOOo0O0Ooo / IiII - iII111i * iIii1I11I1II1 % Ii1I * OoO0O00
 if 80 - 80: i11iIiiIii
 if 19 - 19: O0 * ooOoO0o . OoOoOO00 . iIii1I11I1II1
 if 83 - 83: I11i - OoooooooOO + Ii1I - ooOoO0o * iIii1I11I1II1
 if 37 - 37: O0
 if ( lisp_rtr_list . has_key ( o0O0OO0O0OOo0 ) == False ) : return
 if 76 - 76: iII111i * OOooOOo
 updown = "up" if updown else "down"
 lprint ( "Send ETR IPC message, RTR {} has done {}" . format (
 red ( o0O0OO0O0OOo0 , False ) , bold ( updown , False ) ) )
 if 7 - 7: ooOoO0o + o0oOOo0O0Ooo + o0oOOo0O0Ooo
 if 73 - 73: IiII % I11i % i11iIiiIii + ooOoO0o
 if 83 - 83: Ii1I * I1Ii111 * i11iIiiIii / iIii1I11I1II1 % I1ii11iIi11i
 if 40 - 40: iII111i
 Ooooo = "rtr%{}%{}" . format ( o0O0OO0O0OOo0 , updown )
 Ooooo = lisp_command_ipc ( Ooooo , "lisp-itr" )
 lisp_ipc ( Ooooo , lisp_ipc_socket , "lisp-etr" )
 return
 if 21 - 21: I1Ii111 / iII111i + Oo0Ooo / I1ii11iIi11i / I1Ii111
 if 33 - 33: OoooooooOO
 if 59 - 59: i11iIiiIii - OoooooooOO . ooOoO0o / i11iIiiIii % iIii1I11I1II1 * I1ii11iIi11i
 if 45 - 45: I1ii11iIi11i * I1ii11iIi11i
 if 31 - 31: OoO0O00 - OOooOOo . iII111i * I1Ii111 * iII111i + I1ii11iIi11i
 if 5 - 5: Oo0Ooo . I1Ii111
 if 77 - 77: i11iIiiIii / I1Ii111 / I1ii11iIi11i % oO0o
def lisp_process_rloc_probe_reply ( rloc , source , port , nonce , hop_count , ttl ) :
 OOo00o = bold ( "RLOC-probe reply" , False )
 O0ooOO0ooOo = rloc . print_address_no_iid ( )
 Iiii1iIII1IiI = source . print_address_no_iid ( )
 oo0ooOo = lisp_rloc_probe_list
 if 14 - 14: i1IIi - ooOoO0o + ooOoO0o
 if 93 - 93: oO0o - I1IiiI / I1ii11iIi11i % o0oOOo0O0Ooo / OoooooooOO + II111iiii
 if 10 - 10: o0oOOo0O0Ooo - iII111i . O0 + OoO0O00 - Oo0Ooo - i11iIiiIii
 if 37 - 37: iIii1I11I1II1
 if 37 - 37: II111iiii % OoOoOO00 . IiII * ooOoO0o . I1IiiI
 if 25 - 25: OoooooooOO % i1IIi . I1Ii111 / OoOoOO00 - I1ii11iIi11i
 ooooO0O = O0ooOO0ooOo
 if ( oo0ooOo . has_key ( ooooO0O ) == False ) :
  ooooO0O += ":" + str ( port )
  if ( oo0ooOo . has_key ( ooooO0O ) == False ) :
   ooooO0O = Iiii1iIII1IiI
   if ( oo0ooOo . has_key ( ooooO0O ) == False ) :
    ooooO0O += ":" + str ( port )
    lprint ( "    Received unsolicited {} from {}/{}, port {}" . format ( OOo00o , red ( O0ooOO0ooOo , False ) , red ( Iiii1iIII1IiI ,
    # OoooooooOO
 False ) , port ) )
    return
    if 11 - 11: i11iIiiIii - IiII + o0oOOo0O0Ooo * I1IiiI % iII111i
    if 63 - 63: oO0o
    if 52 - 52: Ii1I . ooOoO0o + iII111i * I1Ii111 % i1IIi
    if 54 - 54: iII111i + OoO0O00
    if 41 - 41: Oo0Ooo . oO0o / O0
    if 42 - 42: ooOoO0o / IiII * Ii1I
    if 2 - 2: OoO0O00 - O0 * II111iiii * OOooOOo
    if 44 - 44: I1IiiI
 for rloc , ii1Ii , IiI1111i1i11I in lisp_rloc_probe_list [ ooooO0O ] :
  if ( lisp_i_am_rtr and rloc . translated_port != 0 and
 rloc . translated_port != port ) : continue
  if 66 - 66: o0oOOo0O0Ooo
  rloc . process_rloc_probe_reply ( nonce , ii1Ii , IiI1111i1i11I , hop_count , ttl )
  if 40 - 40: OOooOOo * Ii1I
 return
 if 38 - 38: ooOoO0o
 if 5 - 5: OoooooooOO + iII111i - I11i
 if 95 - 95: OOooOOo / i11iIiiIii - Ii1I + I1ii11iIi11i
 if 7 - 7: I1ii11iIi11i
 if 37 - 37: O0 . II111iiii
 if 70 - 70: o0oOOo0O0Ooo / iII111i + i1IIi + I11i % iIii1I11I1II1 % Oo0Ooo
 if 1 - 1: O0 + OoO0O00 . i11iIiiIii + I1Ii111 - OoO0O00 - IiII
 if 1 - 1: I1ii11iIi11i / i1IIi . I1IiiI / Ii1I
def lisp_db_list_length ( ) :
 O0oO = 0
 for o0o0O0OO0oO in lisp_db_list :
  O0oO += len ( o0o0O0OO0oO . dynamic_eids ) if o0o0O0OO0oO . dynamic_eid_configured ( ) else 1
  O0oO += len ( o0o0O0OO0oO . eid . iid_list )
  if 19 - 19: iIii1I11I1II1 / Oo0Ooo . O0 - Oo0Ooo
 return ( O0oO )
 if 74 - 74: I1ii11iIi11i * OoooooooOO . iII111i
 if 45 - 45: I1IiiI - IiII % ooOoO0o - IiII . Oo0Ooo - o0oOOo0O0Ooo
 if 27 - 27: iII111i
 if 64 - 64: iIii1I11I1II1 - OOooOOo . iII111i % o0oOOo0O0Ooo / II111iiii % OoooooooOO
 if 87 - 87: OoooooooOO
 if 70 - 70: o0oOOo0O0Ooo % OoooooooOO % I1IiiI . OoOoOO00 * I1IiiI - ooOoO0o
 if 92 - 92: I1IiiI . I11i
 if 66 - 66: I1Ii111 / I11i / OoooooooOO % OoOoOO00 . oO0o * iII111i
def lisp_is_myeid ( eid ) :
 for o0o0O0OO0oO in lisp_db_list :
  if ( eid . is_more_specific ( o0o0O0OO0oO . eid ) ) : return ( True )
  if 34 - 34: I1ii11iIi11i * I1ii11iIi11i % I11i / OOooOOo % oO0o . OoOoOO00
 return ( False )
 if 25 - 25: I1ii11iIi11i / I11i + i1IIi . I1IiiI + ooOoO0o
 if 29 - 29: IiII + I1ii11iIi11i
 if 8 - 8: IiII % I1IiiI
 if 10 - 10: OoooooooOO / OoOoOO00
 if 77 - 77: OoOoOO00
 if 10 - 10: IiII / i11iIiiIii
 if 19 - 19: OoO0O00
 if 100 - 100: I1ii11iIi11i - I1ii11iIi11i
 if 38 - 38: I1Ii111
def lisp_format_macs ( sa , da ) :
 sa = sa [ 0 : 4 ] + "-" + sa [ 4 : 8 ] + "-" + sa [ 8 : 12 ]
 da = da [ 0 : 4 ] + "-" + da [ 4 : 8 ] + "-" + da [ 8 : 12 ]
 return ( "{} -> {}" . format ( sa , da ) )
 if 23 - 23: Ii1I . I1ii11iIi11i + I1Ii111 + i1IIi * o0oOOo0O0Ooo - i11iIiiIii
 if 92 - 92: I1Ii111 - I1IiiI + Ii1I / iII111i % OOooOOo
 if 32 - 32: i1IIi . iII111i - Ii1I % iII111i % II111iiii - oO0o
 if 36 - 36: OoooooooOO * OoooooooOO . ooOoO0o . O0
 if 5 - 5: I11i % I1IiiI - OoO0O00 . Oo0Ooo
 if 79 - 79: iII111i + IiII % I11i . Oo0Ooo / IiII * iII111i
 if 40 - 40: iII111i - I1IiiI + OoOoOO00
def lisp_get_echo_nonce ( rloc , rloc_str ) :
 if ( lisp_nonce_echoing == False ) : return ( None )
 if 2 - 2: I11i - II111iiii / I1Ii111
 if ( rloc ) : rloc_str = rloc . print_address_no_iid ( )
 O00o = None
 if ( lisp_nonce_echo_list . has_key ( rloc_str ) ) :
  O00o = lisp_nonce_echo_list [ rloc_str ]
  if 27 - 27: OoO0O00 - I1ii11iIi11i * i11iIiiIii + Oo0Ooo
 return ( O00o )
 if 29 - 29: I1ii11iIi11i / IiII . I1Ii111 + Ii1I + OoO0O00
 if 76 - 76: ooOoO0o . I11i * OoO0O00
 if 53 - 53: II111iiii / OoOoOO00 / IiII * oO0o
 if 52 - 52: O0 % iII111i * iIii1I11I1II1 / I11i / I1IiiI * ooOoO0o
 if 93 - 93: iIii1I11I1II1 . II111iiii * OOooOOo - iIii1I11I1II1 . oO0o % Oo0Ooo
 if 92 - 92: OoO0O00
 if 42 - 42: I1ii11iIi11i - iIii1I11I1II1 % ooOoO0o
 if 7 - 7: Oo0Ooo / ooOoO0o + o0oOOo0O0Ooo
def lisp_decode_dist_name ( packet ) :
 O0oO = 0
 IIII11iI11 = ""
 if 12 - 12: i11iIiiIii
 while ( packet [ 0 : 1 ] != "\0" ) :
  if ( O0oO == 255 ) : return ( [ None , None ] )
  IIII11iI11 += packet [ 0 : 1 ]
  packet = packet [ 1 : : ]
  O0oO += 1
  if 50 - 50: o0oOOo0O0Ooo / I1ii11iIi11i
  if 84 - 84: i11iIiiIii % OOooOOo
 packet = packet [ 1 : : ]
 return ( packet , IIII11iI11 )
 if 100 - 100: o0oOOo0O0Ooo - OoOoOO00
 if 91 - 91: II111iiii / i11iIiiIii . Oo0Ooo * iIii1I11I1II1
 if 6 - 6: ooOoO0o * Oo0Ooo . OoO0O00
 if 24 - 24: O0 * oO0o % O0 * iIii1I11I1II1 - OoO0O00
 if 18 - 18: Ii1I + I1ii11iIi11i % I1ii11iIi11i + II111iiii
 if 86 - 86: iII111i . O0 - iIii1I11I1II1 - iIii1I11I1II1
 if 79 - 79: OoOoOO00 + Ii1I - oO0o - iIii1I11I1II1 + OoooooooOO
 if 87 - 87: ooOoO0o
def lisp_write_flow_log ( flow_log ) :
 ii1iIii = open ( "./logs/lisp-flow.log" , "a" )
 if 74 - 74: o0oOOo0O0Ooo - o0oOOo0O0Ooo % OoooooooOO . o0oOOo0O0Ooo - I1IiiI - I1ii11iIi11i
 O0oO = 0
 for I1I in flow_log :
  Oo0O0oo = I1I [ 3 ]
  ii1IIIiIIiII = Oo0O0oo . print_flow ( I1I [ 0 ] , I1I [ 1 ] , I1I [ 2 ] )
  ii1iIii . write ( ii1IIIiIIiII )
  O0oO += 1
  if 36 - 36: I1IiiI % O0 + OoO0O00
 ii1iIii . close ( )
 del ( flow_log )
 if 37 - 37: II111iiii / I1ii11iIi11i * I1IiiI - OoooooooOO
 O0oO = bold ( str ( O0oO ) , False )
 lprint ( "Wrote {} flow entries to ./logs/lisp-flow.log" . format ( O0oO ) )
 return
 if 55 - 55: IiII / ooOoO0o * I1IiiI / I1Ii111 - Oo0Ooo % o0oOOo0O0Ooo
 if 82 - 82: OoO0O00 - iIii1I11I1II1 . Oo0Ooo / IiII . OoO0O00
 if 47 - 47: OOooOOo + IiII
 if 11 - 11: Oo0Ooo + I1IiiI % i11iIiiIii % Oo0Ooo + ooOoO0o + i1IIi
 if 100 - 100: II111iiii - OOooOOo + iII111i - i11iIiiIii . O0 / iII111i
 if 64 - 64: Ii1I
 if 4 - 4: OoOoOO00
def lisp_policy_command ( kv_pair ) :
 IiIiI1 = lisp_policy ( "" )
 OoO0Oo0o = None
 if 52 - 52: OoooooooOO * I1Ii111 % II111iiii
 I1i1iiI11ii = [ ]
 for o0OoO00 in range ( len ( kv_pair [ "datetime-range" ] ) ) :
  I1i1iiI11ii . append ( lisp_policy_match ( ) )
  if 51 - 51: OoO0O00 - Oo0Ooo . I11i / oO0o . II111iiii * I1Ii111
  if 40 - 40: I1Ii111
 for OooooooOo00o in kv_pair . keys ( ) :
  iiIIi = kv_pair [ OooooooOo00o ]
  if 96 - 96: oO0o
  if 80 - 80: IiII - oO0o % Ii1I - iIii1I11I1II1 . OoO0O00
  if 64 - 64: I1IiiI % i11iIiiIii / oO0o
  if 78 - 78: II111iiii - Oo0Ooo . iIii1I11I1II1 - ooOoO0o . oO0o
  if ( OooooooOo00o == "instance-id" ) :
   for o0OoO00 in range ( len ( I1i1iiI11ii ) ) :
    O0OOoO00O0o0o0 = iiIIi [ o0OoO00 ]
    if ( O0OOoO00O0o0o0 == "" ) : continue
    IiI1i = I1i1iiI11ii [ o0OoO00 ]
    if ( IiI1i . source_eid == None ) :
     IiI1i . source_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
     if 29 - 29: I1IiiI - OOooOOo
    if ( IiI1i . dest_eid == None ) :
     IiI1i . dest_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
     if 83 - 83: OoOoOO00 * oO0o . OOooOOo - OoO0O00
    IiI1i . source_eid . instance_id = int ( O0OOoO00O0o0o0 )
    IiI1i . dest_eid . instance_id = int ( O0OOoO00O0o0o0 )
    if 73 - 73: I1ii11iIi11i / iII111i / Oo0Ooo
    if 85 - 85: Ii1I
  if ( OooooooOo00o == "source-eid" ) :
   for o0OoO00 in range ( len ( I1i1iiI11ii ) ) :
    O0OOoO00O0o0o0 = iiIIi [ o0OoO00 ]
    if ( O0OOoO00O0o0o0 == "" ) : continue
    IiI1i = I1i1iiI11ii [ o0OoO00 ]
    if ( IiI1i . source_eid == None ) :
     IiI1i . source_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
     if 67 - 67: i11iIiiIii / II111iiii . i11iIiiIii * i11iIiiIii / ooOoO0o . oO0o
    OO0OO000 = IiI1i . source_eid . instance_id
    IiI1i . source_eid . store_prefix ( O0OOoO00O0o0o0 )
    IiI1i . source_eid . instance_id = OO0OO000
    if 46 - 46: oO0o . OoO0O00 - iIii1I11I1II1 . IiII
    if 52 - 52: i11iIiiIii / O0 + oO0o . I11i
  if ( OooooooOo00o == "destination-eid" ) :
   for o0OoO00 in range ( len ( I1i1iiI11ii ) ) :
    O0OOoO00O0o0o0 = iiIIi [ o0OoO00 ]
    if ( O0OOoO00O0o0o0 == "" ) : continue
    IiI1i = I1i1iiI11ii [ o0OoO00 ]
    if ( IiI1i . dest_eid == None ) :
     IiI1i . dest_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
     if 73 - 73: OoooooooOO / I1IiiI % Oo0Ooo . oO0o + OoooooooOO
    OO0OO000 = IiI1i . dest_eid . instance_id
    IiI1i . dest_eid . store_prefix ( O0OOoO00O0o0o0 )
    IiI1i . dest_eid . instance_id = OO0OO000
    if 84 - 84: I1ii11iIi11i - OOooOOo * II111iiii
    if 28 - 28: I1ii11iIi11i . oO0o / o0oOOo0O0Ooo - iII111i
  if ( OooooooOo00o == "source-rloc" ) :
   for o0OoO00 in range ( len ( I1i1iiI11ii ) ) :
    O0OOoO00O0o0o0 = iiIIi [ o0OoO00 ]
    if ( O0OOoO00O0o0o0 == "" ) : continue
    IiI1i = I1i1iiI11ii [ o0OoO00 ]
    IiI1i . source_rloc = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
    IiI1i . source_rloc . store_prefix ( O0OOoO00O0o0o0 )
    if 65 - 65: I1ii11iIi11i * OOooOOo * ooOoO0o + oO0o - OOooOOo
    if 100 - 100: iII111i
  if ( OooooooOo00o == "destination-rloc" ) :
   for o0OoO00 in range ( len ( I1i1iiI11ii ) ) :
    O0OOoO00O0o0o0 = iiIIi [ o0OoO00 ]
    if ( O0OOoO00O0o0o0 == "" ) : continue
    IiI1i = I1i1iiI11ii [ o0OoO00 ]
    IiI1i . dest_rloc = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
    IiI1i . dest_rloc . store_prefix ( O0OOoO00O0o0o0 )
    if 12 - 12: OoooooooOO - I1ii11iIi11i * iII111i / ooOoO0o
    if 99 - 99: I1ii11iIi11i + I11i
  if ( OooooooOo00o == "rloc-record-name" ) :
   for o0OoO00 in range ( len ( I1i1iiI11ii ) ) :
    O0OOoO00O0o0o0 = iiIIi [ o0OoO00 ]
    if ( O0OOoO00O0o0o0 == "" ) : continue
    IiI1i = I1i1iiI11ii [ o0OoO00 ]
    IiI1i . rloc_record_name = O0OOoO00O0o0o0
    if 29 - 29: I1ii11iIi11i / oO0o
    if 2 - 2: Oo0Ooo / IiII - OoooooooOO
  if ( OooooooOo00o == "geo-name" ) :
   for o0OoO00 in range ( len ( I1i1iiI11ii ) ) :
    O0OOoO00O0o0o0 = iiIIi [ o0OoO00 ]
    if ( O0OOoO00O0o0o0 == "" ) : continue
    IiI1i = I1i1iiI11ii [ o0OoO00 ]
    IiI1i . geo_name = O0OOoO00O0o0o0
    if 65 - 65: OoO0O00 - Ii1I
    if 98 - 98: OoOoOO00 * I1Ii111 * iIii1I11I1II1 * OoOoOO00
  if ( OooooooOo00o == "elp-name" ) :
   for o0OoO00 in range ( len ( I1i1iiI11ii ) ) :
    O0OOoO00O0o0o0 = iiIIi [ o0OoO00 ]
    if ( O0OOoO00O0o0o0 == "" ) : continue
    IiI1i = I1i1iiI11ii [ o0OoO00 ]
    IiI1i . elp_name = O0OOoO00O0o0o0
    if 15 - 15: Oo0Ooo
    if 100 - 100: IiII + I1ii11iIi11i + iII111i . i1IIi . I1ii11iIi11i / OoooooooOO
  if ( OooooooOo00o == "rle-name" ) :
   for o0OoO00 in range ( len ( I1i1iiI11ii ) ) :
    O0OOoO00O0o0o0 = iiIIi [ o0OoO00 ]
    if ( O0OOoO00O0o0o0 == "" ) : continue
    IiI1i = I1i1iiI11ii [ o0OoO00 ]
    IiI1i . rle_name = O0OOoO00O0o0o0
    if 84 - 84: o0oOOo0O0Ooo * I11i
    if 22 - 22: i1IIi + OOooOOo % OoooooooOO
  if ( OooooooOo00o == "json-name" ) :
   for o0OoO00 in range ( len ( I1i1iiI11ii ) ) :
    O0OOoO00O0o0o0 = iiIIi [ o0OoO00 ]
    if ( O0OOoO00O0o0o0 == "" ) : continue
    IiI1i = I1i1iiI11ii [ o0OoO00 ]
    IiI1i . json_name = O0OOoO00O0o0o0
    if 34 - 34: oO0o / O0 - II111iiii % Oo0Ooo + I11i
    if 23 - 23: o0oOOo0O0Ooo + i11iIiiIii . I1IiiI + iIii1I11I1II1
  if ( OooooooOo00o == "datetime-range" ) :
   for o0OoO00 in range ( len ( I1i1iiI11ii ) ) :
    O0OOoO00O0o0o0 = iiIIi [ o0OoO00 ]
    IiI1i = I1i1iiI11ii [ o0OoO00 ]
    if ( O0OOoO00O0o0o0 == "" ) : continue
    i1IIi111iI = lisp_datetime ( O0OOoO00O0o0o0 [ 0 : 19 ] )
    oooOOoooo000o = lisp_datetime ( O0OOoO00O0o0o0 [ 19 : : ] )
    if ( i1IIi111iI . valid_datetime ( ) and oooOOoooo000o . valid_datetime ( ) ) :
     IiI1i . datetime_lower = i1IIi111iI
     IiI1i . datetime_upper = oooOOoooo000o
     if 18 - 18: o0oOOo0O0Ooo . O0 + I1Ii111
     if 66 - 66: OoooooooOO
     if 90 - 90: IiII - OoOoOO00
     if 98 - 98: Oo0Ooo / oO0o . Ii1I
     if 56 - 56: ooOoO0o % OoO0O00 * i11iIiiIii % IiII % I1IiiI - oO0o
     if 37 - 37: iII111i - Ii1I . oO0o
     if 47 - 47: IiII / I1ii11iIi11i . o0oOOo0O0Ooo . ooOoO0o + OOooOOo . OOooOOo
  if ( OooooooOo00o == "set-action" ) :
   IiIiI1 . set_action = iiIIi
   if 25 - 25: oO0o
  if ( OooooooOo00o == "set-record-ttl" ) :
   IiIiI1 . set_record_ttl = int ( iiIIi )
   if 43 - 43: Ii1I - o0oOOo0O0Ooo % oO0o - O0
  if ( OooooooOo00o == "set-instance-id" ) :
   if ( IiIiI1 . set_source_eid == None ) :
    IiIiI1 . set_source_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
    if 20 - 20: OoO0O00 . ooOoO0o / OoOoOO00 - OoOoOO00 . iII111i / OOooOOo
   if ( IiIiI1 . set_dest_eid == None ) :
    IiIiI1 . set_dest_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
    if 39 - 39: iIii1I11I1II1 % ooOoO0o
   OoO0Oo0o = int ( iiIIi )
   IiIiI1 . set_source_eid . instance_id = OoO0Oo0o
   IiIiI1 . set_dest_eid . instance_id = OoO0Oo0o
   if 75 - 75: i1IIi * II111iiii * O0 * i11iIiiIii % iII111i / iII111i
  if ( OooooooOo00o == "set-source-eid" ) :
   if ( IiIiI1 . set_source_eid == None ) :
    IiIiI1 . set_source_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
    if 36 - 36: IiII / I1IiiI % iII111i / iII111i
   IiIiI1 . set_source_eid . store_prefix ( iiIIi )
   if ( OoO0Oo0o != None ) : IiIiI1 . set_source_eid . instance_id = OoO0Oo0o
   if 38 - 38: OOooOOo * I1ii11iIi11i * I1Ii111 + I11i
  if ( OooooooOo00o == "set-destination-eid" ) :
   if ( IiIiI1 . set_dest_eid == None ) :
    IiIiI1 . set_dest_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
    if 65 - 65: O0 + O0 * I1Ii111
   IiIiI1 . set_dest_eid . store_prefix ( iiIIi )
   if ( OoO0Oo0o != None ) : IiIiI1 . set_dest_eid . instance_id = OoO0Oo0o
   if 66 - 66: OOooOOo / O0 + i1IIi . O0 % I1ii11iIi11i - OoooooooOO
  if ( OooooooOo00o == "set-rloc-address" ) :
   IiIiI1 . set_rloc_address = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
   IiIiI1 . set_rloc_address . store_address ( iiIIi )
   if 16 - 16: I11i % iII111i
  if ( OooooooOo00o == "set-rloc-record-name" ) :
   IiIiI1 . set_rloc_record_name = iiIIi
   if 29 - 29: I1IiiI - ooOoO0o * OoO0O00 . i11iIiiIii % OoOoOO00 * o0oOOo0O0Ooo
  if ( OooooooOo00o == "set-elp-name" ) :
   IiIiI1 . set_elp_name = iiIIi
   if 43 - 43: OoO0O00 * OOooOOo / I1Ii111 % OoOoOO00 . oO0o / OOooOOo
  if ( OooooooOo00o == "set-geo-name" ) :
   IiIiI1 . set_geo_name = iiIIi
   if 62 - 62: O0 * I1ii11iIi11i - O0 / I11i % ooOoO0o
  if ( OooooooOo00o == "set-rle-name" ) :
   IiIiI1 . set_rle_name = iiIIi
   if 1 - 1: O0 / iIii1I11I1II1
  if ( OooooooOo00o == "set-json-name" ) :
   IiIiI1 . set_json_name = iiIIi
   if 17 - 17: OoOoOO00 + ooOoO0o * II111iiii * OoOoOO00 + I1IiiI + i11iIiiIii
  if ( OooooooOo00o == "policy-name" ) :
   IiIiI1 . policy_name = iiIIi
   if 46 - 46: i1IIi - II111iiii . I1IiiI . i11iIiiIii
   if 54 - 54: O0 * I1ii11iIi11i / OOooOOo / IiII * IiII
   if 69 - 69: Oo0Ooo * OoooooooOO / I1IiiI
   if 16 - 16: o0oOOo0O0Ooo
   if 3 - 3: i11iIiiIii . I1ii11iIi11i
   if 65 - 65: II111iiii * iII111i - OoO0O00 + oO0o % OoO0O00
 IiIiI1 . match_clauses = I1i1iiI11ii
 IiIiI1 . save_policy ( )
 return
 if 83 - 83: OoooooooOO % I1ii11iIi11i . IiII + OOooOOo . iII111i - ooOoO0o
 if 100 - 100: o0oOOo0O0Ooo
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
if 95 - 95: iII111i * oO0o * i1IIi
if 100 - 100: iII111i . o0oOOo0O0Ooo - I1Ii111 % oO0o
if 11 - 11: o0oOOo0O0Ooo . OoooooooOO - i1IIi
if 71 - 71: I1IiiI . OOooOOo . I1ii11iIi11i
if 90 - 90: i11iIiiIii + I1Ii111 % II111iiii
if 67 - 67: OoOoOO00 / iII111i * OoO0O00 % i11iIiiIii
if 76 - 76: OoO0O00
def lisp_send_to_arista ( command , interface ) :
 interface = "" if ( interface == None ) else "interface " + interface
 if 92 - 92: iIii1I11I1II1 * O0 % I11i
 oOO000 = command
 if ( interface != "" ) : oOO000 = interface + ": " + oOO000
 lprint ( "Send CLI command '{}' to hardware" . format ( oOO000 ) )
 if 88 - 88: iIii1I11I1II1 * iIii1I11I1II1
 commands = '''
        enable
        configure
        {}
        {}
    ''' . format ( interface , command )
 if 2 - 2: Oo0Ooo + II111iiii * O0 / iIii1I11I1II1 / iIii1I11I1II1
 os . system ( "FastCli -c '{}'" . format ( commands ) )
 return
 if 33 - 33: OOooOOo * OOooOOo . II111iiii % O0 % O0 % o0oOOo0O0Ooo
 if 45 - 45: OoooooooOO * oO0o
 if 74 - 74: ooOoO0o * I11i / oO0o - IiII + OoOoOO00
 if 16 - 16: Oo0Ooo
 if 29 - 29: Oo0Ooo . I1ii11iIi11i / II111iiii / oO0o / o0oOOo0O0Ooo + I11i
 if 4 - 4: OoooooooOO % I1ii11iIi11i . OoO0O00 * o0oOOo0O0Ooo + I1ii11iIi11i * IiII
 if 67 - 67: I1IiiI
def lisp_arista_is_alive ( prefix ) :
 II1i = "enable\nsh plat trident l3 software routes {}\n" . format ( prefix )
 II = commands . getoutput ( "FastCli -c '{}'" . format ( II1i ) )
 if 93 - 93: ooOoO0o . Ii1I + IiII / Oo0Ooo % I11i
 if 40 - 40: Oo0Ooo % OoOoOO00 . IiII / I1IiiI % OoooooooOO
 if 33 - 33: OOooOOo - OoooooooOO . iII111i
 if 2 - 2: I11i + i1IIi
 II = II . split ( "\n" ) [ 1 ]
 O00Oo000 = II . split ( " " )
 O00Oo000 = O00Oo000 [ - 1 ] . replace ( "\r" , "" )
 if 96 - 96: I1IiiI . IiII + I11i / iIii1I11I1II1
 if 27 - 27: I11i - Ii1I * OoOoOO00 % iIii1I11I1II1
 if 69 - 69: Ii1I . II111iiii + o0oOOo0O0Ooo * iII111i
 if 95 - 95: II111iiii / iII111i + i1IIi
 return ( O00Oo000 == "Y" )
 if 70 - 70: IiII . I1Ii111
 if 29 - 29: Oo0Ooo . i11iIiiIii + OoOoOO00 - Oo0Ooo
 if 13 - 13: ooOoO0o
 if 56 - 56: I1Ii111 / I1ii11iIi11i . i1IIi + I1ii11iIi11i / OoooooooOO - I1IiiI
 if 3 - 3: ooOoO0o
 if 68 - 68: o0oOOo0O0Ooo
 if 36 - 36: Oo0Ooo . I11i + I1IiiI * i1IIi % Ii1I + OOooOOo
 if 5 - 5: o0oOOo0O0Ooo % oO0o / OoO0O00
 if 17 - 17: OoooooooOO - I1ii11iIi11i / OoO0O00 - I1Ii111 + i1IIi
 if 6 - 6: Oo0Ooo - II111iiii
 if 33 - 33: I1Ii111 - I1IiiI + iII111i . OoOoOO00
 if 91 - 91: OOooOOo / Ii1I / IiII * OOooOOo
 if 68 - 68: I11i
 if 91 - 91: I11i
 if 24 - 24: ooOoO0o . i1IIi - O0 + I11i
 if 71 - 71: OoOoOO00
 if 29 - 29: O0 . i11iIiiIii
 if 51 - 51: IiII
 if 53 - 53: O0
 if 19 - 19: o0oOOo0O0Ooo / iII111i % OoOoOO00
 if 65 - 65: o0oOOo0O0Ooo
 if 89 - 89: iIii1I11I1II1 + OoooooooOO + i1IIi + OoooooooOO % IiII * OoO0O00
 if 53 - 53: OOooOOo . IiII % I11i - OoO0O00 - Oo0Ooo
 if 58 - 58: I1Ii111 / OoooooooOO . I11i % I1Ii111
 if 8 - 8: Oo0Ooo % ooOoO0o / i11iIiiIii
 if 54 - 54: IiII
 if 85 - 85: OOooOOo - i1IIi
 if 10 - 10: I1ii11iIi11i
 if 3 - 3: ooOoO0o * O0 / o0oOOo0O0Ooo
 if 22 - 22: OoOoOO00 + OOooOOo . iII111i % iIii1I11I1II1 - I11i
 if 23 - 23: OoOoOO00 * I1Ii111
 if 18 - 18: o0oOOo0O0Ooo % i11iIiiIii . Ii1I . O0
 if 85 - 85: I1ii11iIi11i * iIii1I11I1II1 + o0oOOo0O0Ooo * OoO0O00
 if 25 - 25: o0oOOo0O0Ooo / Ii1I / Oo0Ooo . ooOoO0o - ooOoO0o * O0
 if 14 - 14: O0 - Ii1I + iIii1I11I1II1 + II111iiii . ooOoO0o + Ii1I
 if 25 - 25: OoO0O00 * oO0o
 if 29 - 29: OOooOOo - I1Ii111 - i11iIiiIii % i1IIi
 if 2 - 2: i11iIiiIii % iIii1I11I1II1 * OOooOOo
 if 45 - 45: oO0o + i1IIi + iII111i + o0oOOo0O0Ooo * OOooOOo + ooOoO0o
 if 83 - 83: OoO0O00 - ooOoO0o / OoooooooOO % iIii1I11I1II1 - II111iiii
 if 73 - 73: Oo0Ooo + II111iiii - IiII
 if 60 - 60: i1IIi . i11iIiiIii / i1IIi . I11i % OOooOOo
 if 47 - 47: oO0o + IiII * I1Ii111 % o0oOOo0O0Ooo - O0 % IiII
 if 66 - 66: II111iiii * I1IiiI . Oo0Ooo * OoooooooOO % OoOoOO00 . II111iiii
def lisp_program_vxlan_hardware ( mc ) :
 if 4 - 4: iII111i + I1Ii111 % OoOoOO00 / Ii1I
 if 94 - 94: OoO0O00
 if 35 - 35: I1ii11iIi11i % OoO0O00 + II111iiii % II111iiii / IiII - iII111i
 if 9 - 9: I1ii11iIi11i * o0oOOo0O0Ooo . oO0o
 if 48 - 48: IiII . I1Ii111 + OoooooooOO - I1Ii111 . Ii1I . I1Ii111
 if 24 - 24: ooOoO0o * iIii1I11I1II1
 if ( os . path . exists ( "/persist/local/lispers.net" ) == False ) : return
 if 1 - 1: I1ii11iIi11i . O0
 if 3 - 3: iIii1I11I1II1 * ooOoO0o - OoOoOO00 * I1ii11iIi11i % OoOoOO00 - OoooooooOO
 if 42 - 42: I1Ii111 - i1IIi
 if 91 - 91: iII111i . OOooOOo / iIii1I11I1II1 . Oo0Ooo . II111iiii . OoOoOO00
 if ( len ( mc . best_rloc_set ) == 0 ) : return
 if 31 - 31: OoO0O00 . I1ii11iIi11i % I11i - II111iiii
 if 70 - 70: ooOoO0o - IiII - OoO0O00 / I11i
 if 59 - 59: IiII % ooOoO0o . iII111i / Ii1I * Ii1I
 if 73 - 73: I1ii11iIi11i . oO0o % I11i . I1ii11iIi11i / I1Ii111 / II111iiii
 iiO0 = mc . eid . print_prefix_no_iid ( )
 o0OOooooooOO = mc . best_rloc_set [ 0 ] . rloc . print_address_no_iid ( )
 if 23 - 23: OoooooooOO . o0oOOo0O0Ooo
 if 76 - 76: I1Ii111
 if 91 - 91: iIii1I11I1II1 / Ii1I . I1IiiI
 if 63 - 63: ooOoO0o . Ii1I - I1Ii111 - oO0o * I1Ii111 + ooOoO0o
 ooOoo0o = commands . getoutput ( "ip route get {} | egrep vlan4094" . format ( iiO0 ) )
 if 44 - 44: OoooooooOO . i1IIi + Ii1I * O0 % i1IIi % I11i
 if ( ooOoo0o != "" ) :
  lprint ( "Route {} already in hardware: '{}'" . format ( green ( iiO0 , False ) , ooOoo0o ) )
  if 98 - 98: I1IiiI - II111iiii % II111iiii % OOooOOo
  return
  if 6 - 6: OOooOOo
  if 21 - 21: I1Ii111 - Ii1I - i1IIi % oO0o
  if 55 - 55: OOooOOo + oO0o - II111iiii
  if 5 - 5: iII111i * OoooooooOO . OoO0O00 % ooOoO0o + Ii1I
  if 59 - 59: OoOoOO00
  if 96 - 96: I1IiiI
  if 3 - 3: OoooooooOO
 I11ii1iIi111i = commands . getoutput ( "ifconfig | egrep 'vxlan|vlan4094'" )
 if ( I11ii1iIi111i . find ( "vxlan" ) == - 1 ) :
  lprint ( "No VXLAN interface found, cannot program hardware" )
  return
  if 96 - 96: IiII
 if ( I11ii1iIi111i . find ( "vlan4094" ) == - 1 ) :
  lprint ( "No vlan4094 interface found, cannot program hardware" )
  return
  if 55 - 55: iIii1I11I1II1 + II111iiii . I1ii11iIi11i + Oo0Ooo . Ii1I * IiII
 ooO0O = commands . getoutput ( "ip addr | egrep vlan4094 | egrep inet" )
 if ( ooO0O == "" ) :
  lprint ( "No IP address found on vlan4094, cannot program hardware" )
  return
  if 92 - 92: OoOoOO00 . I1IiiI - ooOoO0o / OoooooooOO
 ooO0O = ooO0O . split ( "inet " ) [ 1 ]
 ooO0O = ooO0O . split ( "/" ) [ 0 ]
 if 71 - 71: OOooOOo + I11i * O0 / o0oOOo0O0Ooo + I1IiiI + Ii1I
 if 41 - 41: ooOoO0o * I1Ii111
 if 40 - 40: OoOoOO00
 if 60 - 60: IiII . i11iIiiIii * II111iiii . Ii1I
 if 10 - 10: O0
 if 65 - 65: I11i % i11iIiiIii + i11iIiiIii % II111iiii
 if 95 - 95: I1Ii111 - I11i . II111iiii . i1IIi / II111iiii + Oo0Ooo
 Ooo000Oooo0o0 = [ ]
 o00OoO0 = commands . getoutput ( "arp -i vlan4094" ) . split ( "\n" )
 for iI1111i in o00OoO0 :
  if ( iI1111i . find ( "vlan4094" ) == - 1 ) : continue
  if ( iI1111i . find ( "(incomplete)" ) == - 1 ) : continue
  oOoo = iI1111i . split ( " " ) [ 0 ]
  Ooo000Oooo0o0 . append ( oOoo )
  if 83 - 83: I11i
  if 39 - 39: o0oOOo0O0Ooo * iIii1I11I1II1
 oOoo = None
 I1OOo00o = ooO0O
 ooO0O = ooO0O . split ( "." )
 for o0OoO00 in range ( 1 , 255 ) :
  ooO0O [ 3 ] = str ( o0OoO00 )
  ooooO0O = "." . join ( ooO0O )
  if ( ooooO0O in Ooo000Oooo0o0 ) : continue
  if ( ooooO0O == I1OOo00o ) : continue
  oOoo = ooooO0O
  break
  if 13 - 13: iII111i + Oo0Ooo / oO0o / OOooOOo
 if ( oOoo == None ) :
  lprint ( "Address allocation failed for vlan4094, cannot program " + "hardware" )
  if 58 - 58: oO0o * I1ii11iIi11i % I1ii11iIi11i
  return
  if 16 - 16: I11i / I1IiiI % I1IiiI
  if 78 - 78: O0 % i11iIiiIii / IiII
  if 87 - 87: IiII % iIii1I11I1II1 * I1ii11iIi11i
  if 43 - 43: Ii1I - IiII / i11iIiiIii + OoOoOO00 + I1ii11iIi11i - o0oOOo0O0Ooo
  if 39 - 39: OoOoOO00 - i1IIi / oO0o % I11i * o0oOOo0O0Ooo * I1IiiI
  if 79 - 79: Ii1I
  if 56 - 56: I1ii11iIi11i
 i1iI = o0OOooooooOO . split ( "." )
 Oo00o0oOooO = lisp_hex_string ( i1iI [ 1 ] ) . zfill ( 2 )
 OoOo0OoOO0o = lisp_hex_string ( i1iI [ 2 ] ) . zfill ( 2 )
 iIi1I1i = lisp_hex_string ( i1iI [ 3 ] ) . zfill ( 2 )
 o0 = "00:00:00:{}:{}:{}" . format ( Oo00o0oOooO , OoOo0OoOO0o , iIi1I1i )
 I111iII1I11II = "0000.00{}.{}{}" . format ( Oo00o0oOooO , OoOo0OoOO0o , iIi1I1i )
 O00OO = "arp -i vlan4094 -s {} {}" . format ( oOoo , o0 )
 os . system ( O00OO )
 if 33 - 33: IiII
 if 76 - 76: iII111i . OOooOOo . OoOoOO00 + O0
 if 32 - 32: O0 * iIii1I11I1II1 - O0 % Ii1I
 if 31 - 31: ooOoO0o
 oOiIi1IIiIi1I11 = ( "mac address-table static {} vlan 4094 " + "interface vxlan 1 vtep {}" ) . format ( I111iII1I11II , o0OOooooooOO )
 if 40 - 40: I1IiiI + I1ii11iIi11i * I1IiiI % Ii1I
 lisp_send_to_arista ( oOiIi1IIiIi1I11 , None )
 if 27 - 27: O0 / Oo0Ooo . oO0o
 if 34 - 34: I1Ii111 % Ii1I / Oo0Ooo % ooOoO0o / i11iIiiIii * I1IiiI
 if 36 - 36: i11iIiiIii * i1IIi % iII111i . Oo0Ooo
 if 54 - 54: o0oOOo0O0Ooo % i1IIi % I1ii11iIi11i . o0oOOo0O0Ooo / OoOoOO00
 if 55 - 55: O0 / OoooooooOO % Ii1I * O0 + iIii1I11I1II1 . iIii1I11I1II1
 O00i1IiIiiIiii = "ip route add {} via {}" . format ( iiO0 , oOoo )
 os . system ( O00i1IiIiiIiii )
 if 59 - 59: iIii1I11I1II1 . OoOoOO00 + ooOoO0o . OoooooooOO
 lprint ( "Hardware programmed with commands:" )
 O00i1IiIiiIiii = O00i1IiIiiIiii . replace ( iiO0 , green ( iiO0 , False ) )
 lprint ( "  " + O00i1IiIiiIiii )
 lprint ( "  " + O00OO )
 oOiIi1IIiIi1I11 = oOiIi1IIiIi1I11 . replace ( o0OOooooooOO , red ( o0OOooooooOO , False ) )
 lprint ( "  " + oOiIi1IIiIi1I11 )
 return
 if 27 - 27: IiII . Oo0Ooo
 if 70 - 70: ooOoO0o + OoooooooOO
 if 17 - 17: iIii1I11I1II1
 if 25 - 25: I1ii11iIi11i * I11i
 if 33 - 33: oO0o / II111iiii
 if 90 - 90: o0oOOo0O0Ooo - iIii1I11I1II1 + i1IIi - OoO0O00 + IiII
 if 40 - 40: i11iIiiIii . i11iIiiIii - OoOoOO00 - oO0o
def lisp_clear_hardware_walk ( mc , parms ) :
 iiIIiI = mc . eid . print_prefix_no_iid ( )
 os . system ( "ip route delete {}" . format ( iiIIiI ) )
 return ( [ True , None ] )
 if 42 - 42: IiII + OoooooooOO / OoooooooOO . ooOoO0o / i11iIiiIii / II111iiii
 if 10 - 10: iII111i . I1IiiI
 if 74 - 74: II111iiii * O0
 if 57 - 57: OoO0O00
 if 12 - 12: o0oOOo0O0Ooo . I1Ii111 . oO0o % Oo0Ooo * OoooooooOO
 if 25 - 25: OoO0O00
 if 54 - 54: O0
 if 20 - 20: ooOoO0o + Oo0Ooo - Oo0Ooo
def lisp_clear_map_cache ( ) :
 global lisp_map_cache , lisp_rloc_probe_list
 global lisp_crypto_keys_by_rloc_encap , lisp_crypto_keys_by_rloc_decap
 global lisp_rtr_list
 if 2 - 2: i1IIi - IiII . I1ii11iIi11i / i1IIi
 o000o0O0O = bold ( "User cleared" , False )
 O0oO = lisp_map_cache . cache_count
 lprint ( "{} map-cache with {} entries" . format ( o000o0O0O , O0oO ) )
 if 8 - 8: o0oOOo0O0Ooo
 if ( lisp_program_hardware ) :
  lisp_map_cache . walk_cache ( lisp_clear_hardware_walk , None )
  if 52 - 52: IiII * OoooooooOO . oO0o + Oo0Ooo
 lisp_map_cache = lisp_cache ( )
 if 95 - 95: OoO0O00 * I1IiiI - Oo0Ooo . IiII
 if 82 - 82: I11i
 if 89 - 89: iIii1I11I1II1 . I11i + OOooOOo / i11iIiiIii / I1ii11iIi11i * i11iIiiIii
 if 20 - 20: I1Ii111 . II111iiii % II111iiii
 if 79 - 79: II111iiii . I11i + o0oOOo0O0Ooo % I1ii11iIi11i + I1ii11iIi11i
 lisp_rloc_probe_list = { }
 if 4 - 4: I1ii11iIi11i % OoooooooOO
 if 43 - 43: IiII - I1Ii111 % ooOoO0o
 if 49 - 49: OoOoOO00
 if 43 - 43: I1Ii111 - Oo0Ooo % i1IIi . II111iiii
 lisp_crypto_keys_by_rloc_encap = { }
 lisp_crypto_keys_by_rloc_decap = { }
 if 80 - 80: IiII . iII111i + I1Ii111 + iII111i % Oo0Ooo
 if 98 - 98: i11iIiiIii . II111iiii + OoOoOO00
 if 25 - 25: I1IiiI + i11iIiiIii . I1Ii111 - I1ii11iIi11i
 if 67 - 67: OOooOOo - OOooOOo * I1IiiI - II111iiii . i1IIi + Oo0Ooo
 if 97 - 97: O0 / i11iIiiIii - o0oOOo0O0Ooo - OoOoOO00 . oO0o
 lisp_rtr_list = { }
 if 77 - 77: oO0o * oO0o . OoOoOO00 . i1IIi
 if 90 - 90: OOooOOo . Ii1I . II111iiii + Ii1I
 if 2 - 2: I1Ii111 * OOooOOo + II111iiii - OoOoOO00
 if 94 - 94: Ii1I - iII111i . I1ii11iIi11i - Oo0Ooo % o0oOOo0O0Ooo + I1Ii111
 lisp_process_data_plane_restart ( True )
 return
 if 58 - 58: oO0o . ooOoO0o . I1IiiI . Oo0Ooo * iIii1I11I1II1 - iII111i
 if 96 - 96: OOooOOo % o0oOOo0O0Ooo / iIii1I11I1II1
 if 60 - 60: i1IIi / iIii1I11I1II1 + I11i % iII111i
 if 64 - 64: I11i . i11iIiiIii / iIii1I11I1II1 . I11i
 if 73 - 73: OoO0O00 % iIii1I11I1II1 + IiII * I1Ii111 % II111iiii
 if 20 - 20: I11i % I1ii11iIi11i . OoO0O00 % OoOoOO00
 if 84 - 84: OoooooooOO / i11iIiiIii . IiII / I1IiiI
 if 62 - 62: iII111i - I1IiiI + OoooooooOO
 if 59 - 59: iIii1I11I1II1 + i11iIiiIii * oO0o . Oo0Ooo . I1Ii111
 if 49 - 49: II111iiii
 if 99 - 99: Oo0Ooo . OOooOOo
def lisp_encapsulate_rloc_probe ( lisp_sockets , rloc , nat_info , packet ) :
 if ( len ( lisp_sockets ) != 4 ) : return
 if 85 - 85: OoOoOO00 . IiII + oO0o - II111iiii
 oo0oO0OoO00 = lisp_myrlocs [ 0 ]
 if 89 - 89: Ii1I / Oo0Ooo * o0oOOo0O0Ooo / OoO0O00 + I11i
 if 4 - 4: I11i
 if 59 - 59: OoOoOO00 * I1ii11iIi11i / I1IiiI * II111iiii + OoOoOO00
 if 6 - 6: OoOoOO00 % oO0o + I11i * Ii1I
 if 13 - 13: I1ii11iIi11i / Oo0Ooo - I1Ii111 * OoOoOO00
 O0o0oOOO = len ( packet ) + 28
 i1iiii = struct . pack ( "BBHIBBHII" , 0x45 , 0 , socket . htons ( O0o0oOOO ) , 0 , 64 ,
 17 , 0 , socket . htonl ( oo0oO0OoO00 . address ) , socket . htonl ( rloc . address ) )
 i1iiii = lisp_ip_checksum ( i1iiii )
 if 47 - 47: IiII
 i1iIIII1iiIIi = struct . pack ( "HHHH" , 0 , socket . htons ( LISP_CTRL_PORT ) ,
 socket . htons ( O0o0oOOO - 20 ) , 0 )
 if 76 - 76: iII111i / II111iiii / I11i
 if 62 - 62: I1ii11iIi11i
 if 100 - 100: iII111i / ooOoO0o / IiII % II111iiii
 if 6 - 6: OoooooooOO - I1IiiI + OoooooooOO
 packet = lisp_packet ( i1iiii + i1iIIII1iiIIi + packet )
 if 89 - 89: oO0o % Oo0Ooo . O0 . ooOoO0o
 if 46 - 46: IiII * I11i - OoO0O00 - Ii1I
 if 93 - 93: iIii1I11I1II1 / o0oOOo0O0Ooo - I11i - OOooOOo % ooOoO0o
 if 16 - 16: ooOoO0o * o0oOOo0O0Ooo - IiII + I1ii11iIi11i / o0oOOo0O0Ooo - O0
 packet . inner_dest . copy_address ( rloc )
 packet . inner_dest . instance_id = 0xffffff
 packet . inner_source . copy_address ( oo0oO0OoO00 )
 packet . inner_ttl = 64
 packet . outer_dest . copy_address ( rloc )
 packet . outer_source . copy_address ( oo0oO0OoO00 )
 packet . outer_version = packet . outer_dest . afi_to_version ( )
 packet . outer_ttl = 64
 packet . encap_port = nat_info . port if nat_info else LISP_DATA_PORT
 if 71 - 71: i1IIi
 oo00OO = red ( rloc . print_address_no_iid ( ) , False )
 if ( nat_info ) :
  oOo00 = " {}" . format ( blue ( nat_info . hostname , False ) )
  OOo00o = bold ( "RLOC-probe request" , False )
 else :
  oOo00 = ""
  OOo00o = bold ( "RLOC-probe reply" , False )
  if 79 - 79: iII111i * O0 / Ii1I / O0 % i1IIi
  if 52 - 52: OoooooooOO % oO0o - I11i % OoOoOO00 . II111iiii
 lprint ( ( "Data encapsulate {} to {}{} port {} for " + "NAT-traversal" ) . format ( OOo00o , oo00OO , oOo00 , packet . encap_port ) )
 if 62 - 62: Ii1I . I1ii11iIi11i . iII111i + I11i * o0oOOo0O0Ooo
 if 56 - 56: oO0o * iIii1I11I1II1 . II111iiii - II111iiii + II111iiii - i11iIiiIii
 if 79 - 79: iII111i
 if 29 - 29: Ii1I * I1Ii111 / OoO0O00 - O0 - i11iIiiIii * I1IiiI
 if 2 - 2: OoOoOO00 . I1ii11iIi11i * I1ii11iIi11i
 if ( packet . encode ( None ) == None ) : return
 packet . print_packet ( "Send" , True )
 if 42 - 42: OoO0O00 . OoO0O00 + II111iiii - IiII - OOooOOo * Oo0Ooo
 iIIi111II = lisp_sockets [ 3 ]
 packet . send_packet ( iIIi111II , packet . outer_dest )
 del ( packet )
 return
 if 78 - 78: oO0o + I1ii11iIi11i
 if 68 - 68: i1IIi . ooOoO0o . Oo0Ooo + iII111i . I1IiiI * i1IIi
 if 88 - 88: iII111i + i11iIiiIii
 if 42 - 42: I1Ii111 * O0 / OoO0O00 + iII111i
 if 86 - 86: OOooOOo
 if 6 - 6: oO0o % iII111i * Oo0Ooo - i11iIiiIii . OoooooooOO
 if 85 - 85: O0 * i1IIi
 if 29 - 29: i11iIiiIii
def lisp_get_default_route_next_hops ( ) :
 if 34 - 34: OoOoOO00
 if 17 - 17: oO0o * OoOoOO00 % OoO0O00 % I1IiiI * I11i
 if 78 - 78: OoooooooOO . I1Ii111 + Ii1I - II111iiii - IiII / iIii1I11I1II1
 if 92 - 92: Ii1I
 if ( lisp_is_macos ( ) ) :
  II1i = "route -n get default"
  iIiiIIii11iII = commands . getoutput ( II1i ) . split ( "\n" )
  O00o0OO0OOo0o = oOOoo = None
  for ii1iIii in iIiiIIii11iII :
   if ( ii1iIii . find ( "gateway: " ) != - 1 ) : O00o0OO0OOo0o = ii1iIii . split ( ": " ) [ 1 ]
   if ( ii1iIii . find ( "interface: " ) != - 1 ) : oOOoo = ii1iIii . split ( ": " ) [ 1 ]
   if 86 - 86: Ii1I % oO0o - i11iIiiIii - O0 + IiII + iII111i
  return ( [ [ oOOoo , O00o0OO0OOo0o ] ] )
  if 100 - 100: OoO0O00 . Oo0Ooo
  if 29 - 29: OoO0O00
  if 34 - 34: O0 - o0oOOo0O0Ooo % OOooOOo . OoO0O00 % IiII
  if 63 - 63: O0 % iIii1I11I1II1 . o0oOOo0O0Ooo . I1IiiI * Ii1I % i1IIi
  if 47 - 47: II111iiii * I1ii11iIi11i
 II1i = "ip route | egrep 'default via'"
 o0OiiI1iiI11 = commands . getoutput ( II1i ) . split ( "\n" )
 if 70 - 70: I1ii11iIi11i - o0oOOo0O0Ooo
 ooo0000OOO0 = [ ]
 for ooOoo0o in o0OiiI1iiI11 :
  if ( ooOoo0o . find ( " metric " ) != - 1 ) : continue
  IIi = ooOoo0o . split ( " " )
  try :
   oOoO00OoOo0o0 = IIi . index ( "via" ) + 1
   if ( oOoO00OoOo0o0 >= len ( IIi ) ) : continue
   iI1ii1II = IIi . index ( "dev" ) + 1
   if ( iI1ii1II >= len ( IIi ) ) : continue
  except :
   continue
   if 57 - 57: OOooOOo . I11i % OoOoOO00
   if 68 - 68: iIii1I11I1II1 % I1ii11iIi11i % II111iiii / O0 + iII111i
  ooo0000OOO0 . append ( [ IIi [ iI1ii1II ] , IIi [ oOoO00OoOo0o0 ] ] )
  if 78 - 78: iII111i - OOooOOo / I1Ii111
 return ( ooo0000OOO0 )
 if 38 - 38: I11i % i1IIi + o0oOOo0O0Ooo + I1ii11iIi11i + I1IiiI
 if 1 - 1: II111iiii * o0oOOo0O0Ooo . O0 - Ii1I / oO0o
 if 17 - 17: OoooooooOO % OoooooooOO + Oo0Ooo + I1Ii111
 if 56 - 56: I11i % OoOoOO00 - OoO0O00
 if 31 - 31: iII111i % i11iIiiIii - Ii1I / OOooOOo - I1Ii111
 if 60 - 60: o0oOOo0O0Ooo + Oo0Ooo . O0
 if 51 - 51: i11iIiiIii / iIii1I11I1II1 . I1IiiI - Ii1I * I1Ii111 . iII111i
def lisp_get_host_route_next_hop ( rloc ) :
 II1i = "ip route | egrep '{} via'" . format ( rloc )
 ooOoo0o = commands . getoutput ( II1i ) . split ( " " )
 if 72 - 72: Ii1I . I11i / i1IIi % i1IIi + I1ii11iIi11i
 try : ii = ooOoo0o . index ( "via" ) + 1
 except : return ( None )
 if 56 - 56: OoO0O00 - OoOoOO00 - II111iiii * o0oOOo0O0Ooo
 if ( ii >= len ( ooOoo0o ) ) : return ( None )
 return ( ooOoo0o [ ii ] )
 if 87 - 87: ooOoO0o * OoooooooOO % O0 * OoooooooOO . I1Ii111
 if 66 - 66: OoO0O00 * Ii1I . OoO0O00
 if 90 - 90: II111iiii % Ii1I
 if 67 - 67: I1IiiI - I11i - i11iIiiIii
 if 45 - 45: ooOoO0o - IiII / OoO0O00 / IiII
 if 63 - 63: ooOoO0o . i11iIiiIii + iII111i . OoO0O00 / ooOoO0o % iII111i
 if 23 - 23: iIii1I11I1II1 - ooOoO0o / I11i * I11i
def lisp_install_host_route ( dest , nh , install ) :
 install = "add" if install else "delete"
 I1iIi11I1 = "none" if nh == None else nh
 if 62 - 62: OOooOOo - I1IiiI * oO0o + O0 / ooOoO0o * iIii1I11I1II1
 lprint ( "{} host-route {}, nh {}" . format ( install . title ( ) , dest , I1iIi11I1 ) )
 if 25 - 25: I1Ii111 % Oo0Ooo + OoO0O00 % OOooOOo
 if ( nh == None ) :
  I1iI = "ip route {} {}/32" . format ( install , dest )
 else :
  I1iI = "ip route {} {}/32 via {}" . format ( install , dest , nh )
  if 85 - 85: I1IiiI . i11iIiiIii - ooOoO0o * I11i * OoOoOO00 * I11i
 os . system ( I1iI )
 return
 if 29 - 29: I1Ii111 * I1Ii111 . iII111i + o0oOOo0O0Ooo
 if 57 - 57: I1Ii111 - IiII
 if 89 - 89: oO0o + iII111i
 if 52 - 52: OOooOOo % O0 * I1ii11iIi11i . I1ii11iIi11i / IiII
 if 7 - 7: II111iiii
 if 7 - 7: iIii1I11I1II1 . O0 + Ii1I % I1IiiI * O0 + OoO0O00
 if 3 - 3: Oo0Ooo * OoooooooOO * oO0o % OoOoOO00 * OoOoOO00 . ooOoO0o
 if 16 - 16: ooOoO0o / o0oOOo0O0Ooo - O0 * I1IiiI
def lisp_checkpoint ( checkpoint_list ) :
 if ( lisp_checkpoint_map_cache == False ) : return
 if 13 - 13: iII111i . iII111i % O0 % o0oOOo0O0Ooo
 ii1iIii = open ( lisp_checkpoint_filename , "w" )
 for iiIiiIi in checkpoint_list :
  ii1iIii . write ( iiIiiIi + "\n" )
  if 99 - 99: OoO0O00 - OoOoOO00 + OoO0O00
 ii1iIii . close ( )
 lprint ( "{} {} entries to file '{}'" . format ( bold ( "Checkpoint" , False ) ,
 len ( checkpoint_list ) , lisp_checkpoint_filename ) )
 return
 if 67 - 67: I1Ii111
 if 31 - 31: OoO0O00 * Oo0Ooo % O0 * II111iiii + ooOoO0o * I1IiiI
 if 77 - 77: ooOoO0o
 if 98 - 98: I1Ii111 + I1ii11iIi11i % OoO0O00 * Ii1I + iII111i
 if 6 - 6: iII111i / iII111i . i11iIiiIii
 if 12 - 12: I11i - OoO0O00
 if 68 - 68: IiII - OoOoOO00
 if 22 - 22: i1IIi . IiII
def lisp_load_checkpoint ( ) :
 if ( lisp_checkpoint_map_cache == False ) : return
 if ( os . path . exists ( lisp_checkpoint_filename ) == False ) : return
 if 8 - 8: IiII % o0oOOo0O0Ooo . i11iIiiIii
 ii1iIii = open ( lisp_checkpoint_filename , "r" )
 if 69 - 69: I1Ii111 / Ii1I - ooOoO0o
 O0oO = 0
 for iiIiiIi in ii1iIii :
  O0oO += 1
  o0o000 = iiIiiIi . split ( " rloc " )
  II1I1I1i1i = [ ] if ( o0o000 [ 1 ] in [ "native-forward\n" , "\n" ] ) else o0o000 [ 1 ] . split ( ", " )
  if 38 - 38: II111iiii % OoooooooOO / OoooooooOO . Ii1I . Ii1I
  if 13 - 13: oO0o - i1IIi / i1IIi + OoooooooOO
  O0Oo0O = [ ]
  for o0OOooooooOO in II1I1I1i1i :
   OoooO00OO = lisp_rloc ( False )
   IIi = o0OOooooooOO . split ( " " )
   OoooO00OO . rloc . store_address ( IIi [ 0 ] )
   OoooO00OO . priority = int ( IIi [ 1 ] )
   OoooO00OO . weight = int ( IIi [ 2 ] )
   O0Oo0O . append ( OoooO00OO )
   if 57 - 57: OoooooooOO / O0 + I1ii11iIi11i % I11i * oO0o / Ii1I
   if 49 - 49: I1IiiI * ooOoO0o * OOooOOo + OoO0O00 + ooOoO0o
  OoOOO000O0o = lisp_mapping ( "" , "" , O0Oo0O )
  if ( OoOOO000O0o != None ) :
   OoOOO000O0o . eid . store_prefix ( o0o000 [ 0 ] )
   OoOOO000O0o . checkpoint_entry = True
   OoOOO000O0o . map_cache_ttl = LISP_NMR_TTL * 60
   if ( O0Oo0O == [ ] ) : OoOOO000O0o . action = LISP_NATIVE_FORWARD_ACTION
   OoOOO000O0o . add_cache ( )
   continue
   if 42 - 42: i1IIi . OoO0O00 % iII111i
   if 57 - 57: I1ii11iIi11i / I1IiiI
  O0oO -= 1
  if 69 - 69: iII111i - iII111i . OoO0O00 / oO0o - OoO0O00 + I1Ii111
  if 98 - 98: iII111i . oO0o - O0 % I1IiiI . I1ii11iIi11i / i1IIi
 ii1iIii . close ( )
 lprint ( "{} {} map-cache entries from file '{}'" . format (
 bold ( "Loaded" , False ) , O0oO , lisp_checkpoint_filename ) )
 return
 if 72 - 72: I1IiiI / Oo0Ooo % IiII - O0 / O0 * O0
 if 83 - 83: O0 / I1Ii111 - OoooooooOO
 if 42 - 42: Ii1I / i1IIi - IiII / I1Ii111
 if 39 - 39: OoooooooOO
 if 4 - 4: iIii1I11I1II1 - Oo0Ooo / OOooOOo % OoooooooOO . Oo0Ooo - Oo0Ooo
 if 41 - 41: II111iiii . o0oOOo0O0Ooo
 if 92 - 92: Ii1I - O0 - i11iIiiIii + IiII % I1Ii111 + II111iiii
 if 71 - 71: ooOoO0o * I1Ii111 + i11iIiiIii + i1IIi . I1IiiI
 if 15 - 15: OoO0O00
 if 37 - 37: OoO0O00 . OoooooooOO - OOooOOo
 if 34 - 34: o0oOOo0O0Ooo + iIii1I11I1II1 / o0oOOo0O0Ooo / ooOoO0o
 if 53 - 53: II111iiii / iIii1I11I1II1
 if 25 - 25: I1Ii111
 if 58 - 58: OoOoOO00 * i1IIi
def lisp_write_checkpoint_entry ( checkpoint_list , mc ) :
 if ( lisp_checkpoint_map_cache == False ) : return
 if 20 - 20: IiII
 iiIiiIi = "{} rloc " . format ( mc . eid . print_prefix ( ) )
 if 81 - 81: I1Ii111 . i1IIi / o0oOOo0O0Ooo
 for OoooO00OO in mc . rloc_set :
  if ( OoooO00OO . rloc . is_null ( ) ) : continue
  iiIiiIi += "{} {} {}, " . format ( OoooO00OO . rloc . print_address_no_iid ( ) ,
 OoooO00OO . priority , OoooO00OO . weight )
  if 30 - 30: i11iIiiIii . I1IiiI
  if 5 - 5: Ii1I / O0 + iIii1I11I1II1
 if ( mc . rloc_set != [ ] ) :
  iiIiiIi = iiIiiIi [ 0 : - 2 ]
 elif ( mc . action == LISP_NATIVE_FORWARD_ACTION ) :
  iiIiiIi += "native-forward"
  if 22 - 22: ooOoO0o . ooOoO0o * OOooOOo % OoOoOO00
  if 51 - 51: OoOoOO00 . oO0o - OoOoOO00
 checkpoint_list . append ( iiIiiIi )
 return
 if 79 - 79: iII111i
 if 71 - 71: i1IIi / OoO0O00 / OOooOOo + I1Ii111
 if 80 - 80: Oo0Ooo . iIii1I11I1II1 . OoooooooOO % iII111i . oO0o
 if 10 - 10: i11iIiiIii * OoooooooOO . i11iIiiIii
 if 35 - 35: OOooOOo * OOooOOo + o0oOOo0O0Ooo / i1IIi - I11i
 if 12 - 12: I1ii11iIi11i - i11iIiiIii + I1IiiI . Oo0Ooo
 if 26 - 26: oO0o + I1Ii111 + IiII * o0oOOo0O0Ooo . oO0o
def lisp_check_dp_socket ( ) :
 OOI1 = lisp_ipc_dp_socket_name
 if ( os . path . exists ( OOI1 ) == False ) :
  OoOo0o = bold ( "does not exist" , False )
  lprint ( "Socket '{}' {}" . format ( OOI1 , OoOo0o ) )
  return ( False )
  if 35 - 35: OoooooooOO / I1IiiI . OOooOOo / OoooooooOO
 return ( True )
 if 7 - 7: II111iiii - ooOoO0o
 if 72 - 72: Ii1I
 if 27 - 27: ooOoO0o / IiII + OoO0O00 + Ii1I % I1Ii111
 if 86 - 86: O0 % i11iIiiIii - Ii1I * oO0o % OOooOOo * i1IIi
 if 87 - 87: II111iiii
 if 53 - 53: OoOoOO00 * i11iIiiIii / I1Ii111
 if 100 - 100: ooOoO0o + I1IiiI * oO0o + ooOoO0o
def lisp_write_to_dp_socket ( entry ) :
 try :
  ii11I1 = json . dumps ( entry )
  OO000oooO0 = bold ( "Write IPC" , False )
  lprint ( "{} record to named socket: '{}'" . format ( OO000oooO0 , ii11I1 ) )
  lisp_ipc_dp_socket . sendto ( ii11I1 , lisp_ipc_dp_socket_name )
 except :
  lprint ( "Failed to write IPC record to named socket: '{}'" . format ( ii11I1 ) )
  if 76 - 76: OOooOOo * iIii1I11I1II1 . i11iIiiIii
 return
 if 78 - 78: ooOoO0o * I11i / I1IiiI * O0
 if 78 - 78: OOooOOo / Oo0Ooo % Oo0Ooo % iII111i
 if 15 - 15: OoO0O00 * IiII % ooOoO0o * Ii1I / I1ii11iIi11i * OoO0O00
 if 18 - 18: OoooooooOO
 if 19 - 19: Ii1I / o0oOOo0O0Ooo / i11iIiiIii
 if 3 - 3: II111iiii / Oo0Ooo
 if 94 - 94: I11i + iII111i % OoOoOO00 - II111iiii + i1IIi
 if 27 - 27: II111iiii % Ii1I * II111iiii
 if 24 - 24: I1Ii111 * I1ii11iIi11i . OOooOOo . I1IiiI - I1ii11iIi11i
def lisp_write_ipc_keys ( rloc ) :
 I1IIII1i1 = rloc . rloc . print_address_no_iid ( )
 Ii1 = rloc . translated_port
 if ( Ii1 != 0 ) : I1IIII1i1 += ":" + str ( Ii1 )
 if ( lisp_rloc_probe_list . has_key ( I1IIII1i1 ) == False ) : return
 if 56 - 56: I1IiiI * Oo0Ooo + OoO0O00 - oO0o * I1Ii111
 for IIi , o0o000 , IiIoO0oo0 in lisp_rloc_probe_list [ I1IIII1i1 ] :
  OoOOO000O0o = lisp_map_cache . lookup_cache ( o0o000 , True )
  if ( OoOOO000O0o == None ) : continue
  lisp_write_ipc_map_cache ( True , OoOOO000O0o )
  if 68 - 68: ooOoO0o * i11iIiiIii * OOooOOo % iII111i
 return
 if 10 - 10: Ii1I / Oo0Ooo - i1IIi
 if 11 - 11: I11i * iII111i
 if 28 - 28: II111iiii + IiII / Oo0Ooo * I1IiiI - OOooOOo
 if 2 - 2: oO0o + I11i / I1Ii111 . I11i
 if 59 - 59: Ii1I
 if 47 - 47: iII111i % iII111i
 if 81 - 81: oO0o / I1ii11iIi11i . OoooooooOO % II111iiii / oO0o
def lisp_write_ipc_map_cache ( add_or_delete , mc , dont_send = False ) :
 if ( lisp_i_am_etr ) : return
 if ( lisp_ipc_dp_socket == None ) : return
 if ( lisp_check_dp_socket ( ) == False ) : return
 if 23 - 23: IiII + oO0o + o0oOOo0O0Ooo . I1ii11iIi11i / i11iIiiIii + iIii1I11I1II1
 if 74 - 74: I11i % OOooOOo
 if 57 - 57: O0 + I1IiiI + i11iIiiIii
 if 90 - 90: I1ii11iIi11i . OoO0O00 * iIii1I11I1II1 - Oo0Ooo
 i1I1IiI1ii = "add" if add_or_delete else "delete"
 iiIiiIi = { "type" : "map-cache" , "opcode" : i1I1IiI1ii }
 if 28 - 28: I1IiiI . ooOoO0o - ooOoO0o * OOooOOo . IiII
 OOooO = ( mc . group . is_null ( ) == False )
 if ( OOooO ) :
  iiIiiIi [ "eid-prefix" ] = mc . group . print_prefix_no_iid ( )
  iiIiiIi [ "rles" ] = [ ]
 else :
  iiIiiIi [ "eid-prefix" ] = mc . eid . print_prefix_no_iid ( )
  iiIiiIi [ "rlocs" ] = [ ]
  if 16 - 16: iIii1I11I1II1 % i11iIiiIii / Ii1I % iIii1I11I1II1 / iII111i
 iiIiiIi [ "instance-id" ] = str ( mc . eid . instance_id )
 if 27 - 27: II111iiii * OoooooooOO / Oo0Ooo % O0
 if ( OOooO ) :
  if ( len ( mc . rloc_set ) >= 1 and mc . rloc_set [ 0 ] . rle ) :
   for I11iI in mc . rloc_set [ 0 ] . rle . rle_forwarding_list :
    ooooO0O = I11iI . address . print_address_no_iid ( )
    Ii1 = str ( 4341 ) if I11iI . translated_port == 0 else str ( I11iI . translated_port )
    if 41 - 41: oO0o / iIii1I11I1II1 % iII111i - I1Ii111 % I11i * i11iIiiIii
    IIi = { "rle" : ooooO0O , "port" : Ii1 }
    O000oOooOoO0 , iiiII1I111iI1I = I11iI . get_encap_keys ( )
    IIi = lisp_build_json_keys ( IIi , O000oOooOoO0 , iiiII1I111iI1I , "encrypt-key" )
    iiIiiIi [ "rles" ] . append ( IIi )
    if 95 - 95: Oo0Ooo * IiII - I1IiiI
    if 37 - 37: Oo0Ooo - oO0o / I1ii11iIi11i . o0oOOo0O0Ooo * Ii1I
 else :
  for o0OOooooooOO in mc . rloc_set :
   if ( o0OOooooooOO . rloc . is_ipv4 ( ) == False and o0OOooooooOO . rloc . is_ipv6 ( ) == False ) :
    continue
    if 95 - 95: i11iIiiIii - ooOoO0o / I11i / I1Ii111
   if ( o0OOooooooOO . up_state ( ) == False ) : continue
   if 59 - 59: iII111i
   Ii1 = str ( 4341 ) if o0OOooooooOO . translated_port == 0 else str ( o0OOooooooOO . translated_port )
   if 59 - 59: Oo0Ooo - IiII
   IIi = { "rloc" : o0OOooooooOO . rloc . print_address_no_iid ( ) , "priority" :
 str ( o0OOooooooOO . priority ) , "weight" : str ( o0OOooooooOO . weight ) , "port" :
 Ii1 }
   O000oOooOoO0 , iiiII1I111iI1I = o0OOooooooOO . get_encap_keys ( )
   IIi = lisp_build_json_keys ( IIi , O000oOooOoO0 , iiiII1I111iI1I , "encrypt-key" )
   iiIiiIi [ "rlocs" ] . append ( IIi )
   if 6 - 6: OOooOOo - I1IiiI . IiII
   if 40 - 40: II111iiii
   if 13 - 13: OoOoOO00
 if ( dont_send == False ) : lisp_write_to_dp_socket ( iiIiiIi )
 return ( iiIiiIi )
 if 23 - 23: Oo0Ooo / II111iiii % OOooOOo % iII111i - Oo0Ooo / OoO0O00
 if 7 - 7: Ii1I / I11i / II111iiii % I11i * I11i + iIii1I11I1II1
 if 6 - 6: iIii1I11I1II1 * oO0o - iIii1I11I1II1 . O0 . O0
 if 96 - 96: I1Ii111 * II111iiii % i11iIiiIii - oO0o
 if 32 - 32: i11iIiiIii * o0oOOo0O0Ooo . OoooooooOO / O0
 if 14 - 14: i11iIiiIii . I1Ii111 % I1ii11iIi11i . I1ii11iIi11i % IiII
 if 93 - 93: iIii1I11I1II1 / IiII
def lisp_write_ipc_decap_key ( rloc_addr , keys ) :
 if ( lisp_i_am_itr ) : return
 if ( lisp_ipc_dp_socket == None ) : return
 if ( lisp_check_dp_socket ( ) == False ) : return
 if 91 - 91: i11iIiiIii % ooOoO0o - iII111i * I1Ii111 . i11iIiiIii
 if 1 - 1: IiII + iIii1I11I1II1 * I1ii11iIi11i - IiII - i1IIi
 if 75 - 75: II111iiii * o0oOOo0O0Ooo / I1ii11iIi11i
 if 46 - 46: OOooOOo
 if ( keys == None or len ( keys ) == 0 or keys [ 1 ] == None ) : return
 if 67 - 67: OoO0O00 . I11i % OOooOOo + Oo0Ooo
 O000oOooOoO0 = keys [ 1 ] . encrypt_key
 iiiII1I111iI1I = keys [ 1 ] . icv_key
 if 40 - 40: OoO0O00 / I11i % iIii1I11I1II1 - ooOoO0o
 if 51 - 51: Oo0Ooo % iIii1I11I1II1 % oO0o + o0oOOo0O0Ooo
 if 32 - 32: I1Ii111 * I1IiiI + Ii1I
 if 30 - 30: OoooooooOO / I1IiiI . iIii1I11I1II1 / ooOoO0o
 ii11II1iiI1i = rloc_addr . split ( ":" )
 if ( len ( ii11II1iiI1i ) == 1 ) :
  iiIiiIi = { "type" : "decap-keys" , "rloc" : ii11II1iiI1i [ 0 ] }
 else :
  iiIiiIi = { "type" : "decap-keys" , "rloc" : ii11II1iiI1i [ 0 ] , "port" : ii11II1iiI1i [ 1 ] }
  if 28 - 28: I1Ii111 * O0
 iiIiiIi = lisp_build_json_keys ( iiIiiIi , O000oOooOoO0 , iiiII1I111iI1I , "decrypt-key" )
 if 94 - 94: ooOoO0o / ooOoO0o
 lisp_write_to_dp_socket ( iiIiiIi )
 return
 if 74 - 74: i11iIiiIii - oO0o % II111iiii . iIii1I11I1II1
 if 94 - 94: OOooOOo + oO0o / OoooooooOO + o0oOOo0O0Ooo - o0oOOo0O0Ooo . OOooOOo
 if 15 - 15: i11iIiiIii * O0 % iIii1I11I1II1 . OoooooooOO % oO0o + o0oOOo0O0Ooo
 if 37 - 37: oO0o + O0 . IiII * I1ii11iIi11i
 if 2 - 2: O0 . ooOoO0o
 if 97 - 97: i1IIi . Oo0Ooo
 if 81 - 81: OoOoOO00
 if 81 - 81: O0
def lisp_build_json_keys ( entry , ekey , ikey , key_type ) :
 if ( ekey == None ) : return ( entry )
 if 57 - 57: oO0o - o0oOOo0O0Ooo % i11iIiiIii / OoOoOO00 . iIii1I11I1II1
 entry [ "keys" ] = [ ]
 i1iI11iI = { "key-id" : "1" , key_type : ekey , "icv-key" : ikey }
 entry [ "keys" ] . append ( i1iI11iI )
 return ( entry )
 if 68 - 68: iII111i
 if 59 - 59: O0 - i11iIiiIii + OoooooooOO - iII111i - Oo0Ooo . OoooooooOO
 if 60 - 60: O0 * iIii1I11I1II1 - Ii1I * II111iiii . ooOoO0o
 if 61 - 61: I1IiiI . iII111i
 if 19 - 19: iIii1I11I1II1 * Oo0Ooo - I1IiiI - I1IiiI + O0 - I1Ii111
 if 56 - 56: I1Ii111 - i1IIi + I11i . i1IIi / II111iiii * oO0o
 if 70 - 70: ooOoO0o - II111iiii . I11i
def lisp_write_ipc_database_mappings ( ephem_port ) :
 if ( lisp_i_am_etr == False ) : return
 if ( lisp_ipc_dp_socket == None ) : return
 if ( lisp_check_dp_socket ( ) == False ) : return
 if 70 - 70: OOooOOo / iII111i - I11i + OoOoOO00 % Ii1I * IiII
 if 26 - 26: O0 / oO0o
 if 96 - 96: ooOoO0o * iII111i . IiII
 if 77 - 77: OOooOOo - I11i % o0oOOo0O0Ooo
 iiIiiIi = { "type" : "database-mappings" , "database-mappings" : [ ] }
 if 46 - 46: I1IiiI % oO0o . OoooooooOO . IiII / I11i - i1IIi
 if 43 - 43: OoOoOO00 - o0oOOo0O0Ooo
 if 22 - 22: i1IIi
 if 33 - 33: O0
 for o0o0O0OO0oO in lisp_db_list :
  if ( o0o0O0OO0oO . eid . is_ipv4 ( ) == False and o0o0O0OO0oO . eid . is_ipv6 ( ) == False ) : continue
  i11 = { "instance-id" : str ( o0o0O0OO0oO . eid . instance_id ) ,
 "eid-prefix" : o0o0O0OO0oO . eid . print_prefix_no_iid ( ) }
  iiIiiIi [ "database-mappings" ] . append ( i11 )
  if 87 - 87: I1IiiI * OOooOOo % i11iIiiIii . o0oOOo0O0Ooo % i11iIiiIii * OoOoOO00
 lisp_write_to_dp_socket ( iiIiiIi )
 if 79 - 79: o0oOOo0O0Ooo . I11i . I1ii11iIi11i
 if 56 - 56: o0oOOo0O0Ooo . i11iIiiIii - i1IIi * o0oOOo0O0Ooo
 if 64 - 64: I11i
 if 23 - 23: i11iIiiIii / OoooooooOO + I1ii11iIi11i + O0 + I1ii11iIi11i / i11iIiiIii
 if 14 - 14: OoOoOO00 . II111iiii / iII111i / oO0o - oO0o
 iiIiiIi = { "type" : "etr-nat-port" , "port" : ephem_port }
 lisp_write_to_dp_socket ( iiIiiIi )
 return
 if 12 - 12: O0
 if 77 - 77: oO0o % o0oOOo0O0Ooo % iII111i
 if 28 - 28: OoOoOO00 . O0 - II111iiii - I1IiiI / OOooOOo % O0
 if 49 - 49: ooOoO0o % Ii1I
 if 86 - 86: o0oOOo0O0Ooo - I1IiiI . II111iiii . I1Ii111
 if 22 - 22: IiII
 if 63 - 63: I1IiiI . OOooOOo . O0
def lisp_write_ipc_interfaces ( ) :
 if ( lisp_i_am_etr ) : return
 if ( lisp_ipc_dp_socket == None ) : return
 if ( lisp_check_dp_socket ( ) == False ) : return
 if 32 - 32: Ii1I / OOooOOo * i1IIi / i1IIi + I1IiiI % o0oOOo0O0Ooo
 if 61 - 61: o0oOOo0O0Ooo
 if 39 - 39: I1ii11iIi11i / o0oOOo0O0Ooo / Oo0Ooo * II111iiii - OoO0O00
 if 66 - 66: OoO0O00 / oO0o / I1ii11iIi11i - oO0o
 iiIiiIi = { "type" : "interfaces" , "interfaces" : [ ] }
 if 9 - 9: ooOoO0o * iIii1I11I1II1 * OoooooooOO
 for oOOoo in lisp_myinterfaces . values ( ) :
  if ( oOOoo . instance_id == None ) : continue
  i11 = { "interface" : oOOoo . device ,
 "instance-id" : str ( oOOoo . instance_id ) }
  iiIiiIi [ "interfaces" ] . append ( i11 )
  if 13 - 13: iII111i . i11iIiiIii * o0oOOo0O0Ooo . iII111i
  if 96 - 96: Ii1I
 lisp_write_to_dp_socket ( iiIiiIi )
 return
 if 90 - 90: II111iiii
 if 93 - 93: i11iIiiIii / Ii1I * Oo0Ooo . iII111i % iII111i / IiII
 if 15 - 15: OoOoOO00 % I1Ii111 - iIii1I11I1II1
 if 52 - 52: i11iIiiIii * ooOoO0o
 if 15 - 15: OoooooooOO . oO0o . i11iIiiIii / o0oOOo0O0Ooo
 if 91 - 91: ooOoO0o
 if 47 - 47: II111iiii + I11i + ooOoO0o % Oo0Ooo / iII111i
 if 9 - 9: O0 + IiII
 if 69 - 69: I1IiiI
 if 11 - 11: I11i % I1Ii111 + O0 . Ii1I . I1ii11iIi11i % I1Ii111
 if 28 - 28: IiII . o0oOOo0O0Ooo + iII111i - OoOoOO00 / OOooOOo
 if 86 - 86: ooOoO0o * OoOoOO00 + oO0o / II111iiii % OOooOOo
 if 89 - 89: O0 * Ii1I / OoO0O00 / OoOoOO00 % iII111i * iIii1I11I1II1
 if 72 - 72: iIii1I11I1II1 / iIii1I11I1II1 * I11i
def lisp_parse_auth_key ( value ) :
 iII1ii1IiII = value . split ( "[" )
 iIiiI1II = { }
 if ( len ( iII1ii1IiII ) == 1 ) :
  iIiiI1II [ 0 ] = value
  return ( iIiiI1II )
  if 57 - 57: ooOoO0o * ooOoO0o + I11i + i11iIiiIii % I1Ii111 * I1IiiI
  if 73 - 73: Oo0Ooo * iIii1I11I1II1 - II111iiii
 for O0OOoO00O0o0o0 in iII1ii1IiII :
  if ( O0OOoO00O0o0o0 == "" ) : continue
  ii = O0OOoO00O0o0o0 . find ( "]" )
  OOo0 = O0OOoO00O0o0o0 [ 0 : ii ]
  try : OOo0 = int ( OOo0 )
  except : return
  if 16 - 16: iIii1I11I1II1 / O0 - o0oOOo0O0Ooo + ooOoO0o * I1IiiI / i1IIi
  iIiiI1II [ OOo0 ] = O0OOoO00O0o0o0 [ ii + 1 : : ]
  if 28 - 28: I1Ii111 . OoooooooOO
 return ( iIiiI1II )
 if 56 - 56: I1ii11iIi11i + i1IIi * I1Ii111 / ooOoO0o - I1ii11iIi11i . I11i
 if 25 - 25: Oo0Ooo / o0oOOo0O0Ooo + I1IiiI - I11i / i11iIiiIii
 if 89 - 89: II111iiii
 if 2 - 2: OoOoOO00 . i11iIiiIii
 if 11 - 11: Ii1I
 if 82 - 82: I11i - i1IIi . Oo0Ooo * I1Ii111
 if 44 - 44: iII111i
 if 56 - 56: II111iiii / Oo0Ooo % IiII * II111iiii - iIii1I11I1II1 + ooOoO0o
 if 33 - 33: o0oOOo0O0Ooo . I11i / I1IiiI
 if 29 - 29: o0oOOo0O0Ooo - ooOoO0o
 if 59 - 59: I11i / IiII * OoO0O00 / IiII . I1Ii111
 if 82 - 82: OOooOOo . iIii1I11I1II1 + I1Ii111
 if 14 - 14: IiII . i11iIiiIii
 if 17 - 17: ooOoO0o % ooOoO0o * oO0o
 if 8 - 8: ooOoO0o + OoO0O00 . II111iiii / iIii1I11I1II1 - OOooOOo
 if 87 - 87: iIii1I11I1II1 . IiII % I1IiiI . OoO0O00 - I1Ii111
def lisp_reassemble ( packet ) :
 OOOO = socket . ntohs ( struct . unpack ( "H" , packet [ 6 : 8 ] ) [ 0 ] )
 if 53 - 53: I1Ii111 % i11iIiiIii
 if 99 - 99: I1IiiI - i1IIi * i11iIiiIii + OoO0O00
 if 80 - 80: o0oOOo0O0Ooo . I11i % iIii1I11I1II1 + OoOoOO00
 if 87 - 87: I1Ii111 + II111iiii / I1ii11iIi11i + OoOoOO00
 if ( OOOO == 0 or OOOO == 0x4000 ) : return ( packet )
 if 71 - 71: I1IiiI + iIii1I11I1II1 + O0 * iII111i % IiII
 if 42 - 42: OOooOOo - I1ii11iIi11i
 if 93 - 93: I1Ii111 + OOooOOo % ooOoO0o / I1Ii111 % OOooOOo . IiII
 if 37 - 37: iII111i * oO0o / oO0o / Ii1I % I11i
 ooOooOooOOO = socket . ntohs ( struct . unpack ( "H" , packet [ 4 : 6 ] ) [ 0 ] )
 iIoO0OOooOO = socket . ntohs ( struct . unpack ( "H" , packet [ 2 : 4 ] ) [ 0 ] )
 if 88 - 88: ooOoO0o + ooOoO0o + oO0o * o0oOOo0O0Ooo . Ii1I
 o000o = ( OOOO & 0x2000 == 0 and ( OOOO & 0x1fff ) != 0 )
 iiIiiIi = [ ( OOOO & 0x1fff ) * 8 , iIoO0OOooOO - 20 , packet , o000o ]
 if 79 - 79: ooOoO0o / i11iIiiIii
 if 36 - 36: OoOoOO00 - OoOoOO00
 if 7 - 7: OoOoOO00 - OoO0O00 % OoOoOO00 . I1ii11iIi11i % Oo0Ooo * iII111i
 if 90 - 90: IiII - OOooOOo + iIii1I11I1II1
 if 88 - 88: ooOoO0o . o0oOOo0O0Ooo . OOooOOo - I11i
 if 76 - 76: IiII % I1IiiI . iII111i
 if 5 - 5: ooOoO0o . oO0o - OoOoOO00 - OoooooooOO
 if 2 - 2: OOooOOo
 if ( OOOO == 0x2000 ) :
  I11iI1 , oOo00OO0o0 = struct . unpack ( "HH" , packet [ 20 : 24 ] )
  I11iI1 = socket . ntohs ( I11iI1 )
  oOo00OO0o0 = socket . ntohs ( oOo00OO0o0 )
  if ( oOo00OO0o0 not in [ 4341 , 8472 , 4789 ] and I11iI1 != 4341 ) :
   lisp_reassembly_queue [ ooOooOooOOO ] = [ ]
   iiIiiIi [ 2 ] = None
   if 37 - 37: IiII - iIii1I11I1II1 * i11iIiiIii . ooOoO0o
   if 78 - 78: OOooOOo - I1ii11iIi11i + iII111i % OoOoOO00
   if 28 - 28: I11i + i1IIi / i11iIiiIii * OOooOOo * II111iiii
   if 78 - 78: OoO0O00 - i1IIi % I1Ii111
   if 87 - 87: I11i
   if 37 - 37: iII111i . I1Ii111 - iII111i - I11i - iIii1I11I1II1 - II111iiii
 if ( lisp_reassembly_queue . has_key ( ooOooOooOOO ) == False ) :
  lisp_reassembly_queue [ ooOooOooOOO ] = [ ]
  if 80 - 80: I1Ii111 % O0 - IiII / II111iiii + i1IIi
  if 4 - 4: OOooOOo + II111iiii
  if 1 - 1: OoooooooOO * I1Ii111 - I11i / IiII
  if 43 - 43: i11iIiiIii * I1IiiI
  if 48 - 48: Oo0Ooo - OOooOOo / iII111i % I1ii11iIi11i . OoOoOO00
 iIOOo00ooO = lisp_reassembly_queue [ ooOooOooOOO ]
 if 34 - 34: O0 * iIii1I11I1II1 . o0oOOo0O0Ooo . I1Ii111 . iIii1I11I1II1 * iIii1I11I1II1
 if 38 - 38: iIii1I11I1II1
 if 83 - 83: iII111i - Ii1I . oO0o - I1Ii111 * o0oOOo0O0Ooo
 if 70 - 70: i11iIiiIii - OoO0O00 / i11iIiiIii
 if 46 - 46: II111iiii + O0 * OoooooooOO
 if ( len ( iIOOo00ooO ) == 1 and iIOOo00ooO [ 0 ] [ 2 ] == None ) :
  dprint ( "Drop non-LISP encapsulated fragment 0x{}" . format ( lisp_hex_string ( ooOooOooOOO ) . zfill ( 4 ) ) )
  if 39 - 39: OoooooooOO % II111iiii . o0oOOo0O0Ooo
  return ( None )
  if 29 - 29: I11i . o0oOOo0O0Ooo . i1IIi . o0oOOo0O0Ooo
  if 77 - 77: iIii1I11I1II1 + iIii1I11I1II1
  if 52 - 52: I1ii11iIi11i - IiII % I1IiiI % i1IIi
  if 98 - 98: I1Ii111 + II111iiii % OoO0O00 % iII111i
  if 54 - 54: II111iiii . ooOoO0o . iII111i - I1IiiI
 iIOOo00ooO . append ( iiIiiIi )
 iIOOo00ooO = sorted ( iIOOo00ooO )
 if 97 - 97: oO0o - O0 / II111iiii * II111iiii - oO0o * IiII
 if 97 - 97: IiII % OoO0O00 . OoOoOO00 - Ii1I
 if 28 - 28: O0 . I11i . I1IiiI - Ii1I - iII111i - iIii1I11I1II1
 if 14 - 14: OOooOOo + ooOoO0o
 ooooO0O = lisp_address ( LISP_AFI_IPV4 , "" , 32 , 0 )
 ooooO0O . address = socket . ntohl ( struct . unpack ( "I" , packet [ 12 : 16 ] ) [ 0 ] )
 oOOO0OoO = ooooO0O . print_address_no_iid ( )
 ooooO0O . address = socket . ntohl ( struct . unpack ( "I" , packet [ 16 : 20 ] ) [ 0 ] )
 iiiI1i1Iii1ii = ooooO0O . print_address_no_iid ( )
 ooooO0O = red ( "{} -> {}" . format ( oOOO0OoO , iiiI1i1Iii1ii ) , False )
 if 72 - 72: iIii1I11I1II1 - I1IiiI * OoO0O00 * o0oOOo0O0Ooo - I1IiiI . I1ii11iIi11i
 dprint ( "{}{} fragment, RLOCs: {}, packet 0x{}, frag-offset: 0x{}" . format ( bold ( "Received" , False ) , " non-LISP encapsulated" if iiIiiIi [ 2 ] == None else "" , ooooO0O , lisp_hex_string ( ooOooOooOOO ) . zfill ( 4 ) ,
 # iIii1I11I1II1 + i11iIiiIii / OoOoOO00
 # I1ii11iIi11i % OoOoOO00 * OoOoOO00 % o0oOOo0O0Ooo * II111iiii / OoOoOO00
 lisp_hex_string ( OOOO ) . zfill ( 4 ) ) )
 if 73 - 73: OoOoOO00 + OOooOOo * II111iiii . OOooOOo % I1Ii111 % oO0o
 if 79 - 79: I1ii11iIi11i % I11i
 if 78 - 78: i11iIiiIii % I1Ii111 + iIii1I11I1II1 + iII111i
 if 66 - 66: I1IiiI - o0oOOo0O0Ooo
 if 67 - 67: oO0o . iII111i * Ii1I - OOooOOo / oO0o
 if ( iIOOo00ooO [ 0 ] [ 0 ] != 0 or iIOOo00ooO [ - 1 ] [ 3 ] == False ) : return ( None )
 oOoOOoO00Oo0 = iIOOo00ooO [ 0 ]
 for iIII in iIOOo00ooO [ 1 : : ] :
  OOOO = iIII [ 0 ]
  IiiO00o0OoO00ooo , oOooii111 = oOoOOoO00Oo0 [ 0 ] , oOoOOoO00Oo0 [ 1 ]
  if ( IiiO00o0OoO00ooo + oOooii111 != OOOO ) : return ( None )
  oOoOOoO00Oo0 = iIII
  if 90 - 90: iII111i . Oo0Ooo * o0oOOo0O0Ooo % I11i . OoOoOO00
 lisp_reassembly_queue . pop ( ooOooOooOOO )
 if 63 - 63: I1ii11iIi11i + OoOoOO00 - Ii1I + OoO0O00 - II111iiii
 if 47 - 47: I1IiiI * O0 + I1ii11iIi11i - OOooOOo
 if 24 - 24: i1IIi / i1IIi + I11i * II111iiii / IiII
 if 8 - 8: I11i . I11i + I11i % OoooooooOO / ooOoO0o
 if 25 - 25: I1IiiI / OoO0O00
 packet = iIOOo00ooO [ 0 ] [ 2 ]
 for iIII in iIOOo00ooO [ 1 : : ] : packet += iIII [ 2 ] [ 20 : : ]
 if 92 - 92: oO0o % I1IiiI / OoO0O00 - I11i
 dprint ( "{} fragments arrived for packet 0x{}, length {}" . format ( bold ( "All" , False ) , lisp_hex_string ( ooOooOooOOO ) . zfill ( 4 ) , len ( packet ) ) )
 if 36 - 36: i1IIi * iIii1I11I1II1 + I1ii11iIi11i + iII111i - II111iiii
 if 48 - 48: oO0o + OoOoOO00 - OoO0O00 . II111iiii * i11iIiiIii . OoooooooOO
 if 37 - 37: OoooooooOO + O0 . I11i % OoOoOO00
 if 57 - 57: I1Ii111 . OOooOOo + I1Ii111 . iIii1I11I1II1 / oO0o / O0
 if 88 - 88: I1Ii111
 O0o0oOOO = socket . htons ( len ( packet ) )
 o0OO0 = packet [ 0 : 2 ] + struct . pack ( "H" , O0o0oOOO ) + packet [ 4 : 6 ] + struct . pack ( "H" , 0 ) + packet [ 8 : 10 ] + struct . pack ( "H" , 0 ) + packet [ 12 : 20 ]
 if 16 - 16: Oo0Ooo . ooOoO0o / OoO0O00 / o0oOOo0O0Ooo . OoooooooOO * OoO0O00
 if 50 - 50: II111iiii + I11i . OoooooooOO . I1Ii111 - OOooOOo
 o0OO0 = lisp_ip_checksum ( o0OO0 )
 return ( o0OO0 + packet [ 20 : : ] )
 if 83 - 83: oO0o
 if 100 - 100: I1Ii111 + o0oOOo0O0Ooo * oO0o / oO0o . oO0o + iII111i
 if 71 - 71: II111iiii + iII111i + O0 % Oo0Ooo / I1IiiI
 if 52 - 52: Oo0Ooo . I1Ii111 * i1IIi / Oo0Ooo / OoO0O00
 if 29 - 29: iII111i
 if 91 - 91: Oo0Ooo - IiII
 if 47 - 47: iII111i / OOooOOo + iII111i
 if 69 - 69: I1IiiI . I1ii11iIi11i
def lisp_get_crypto_decap_lookup_key ( addr , port ) :
 I1IIII1i1 = addr . print_address_no_iid ( ) + ":" + str ( port )
 if ( lisp_crypto_keys_by_rloc_decap . has_key ( I1IIII1i1 ) ) : return ( I1IIII1i1 )
 if 18 - 18: I11i * I1IiiI
 I1IIII1i1 = addr . print_address_no_iid ( )
 if ( lisp_crypto_keys_by_rloc_decap . has_key ( I1IIII1i1 ) ) : return ( I1IIII1i1 )
 if 42 - 42: i1IIi . I1Ii111 - ooOoO0o + I11i / oO0o
 if 60 - 60: i1IIi + OoooooooOO % i11iIiiIii / IiII % Oo0Ooo + I1IiiI
 if 87 - 87: Ii1I % OoooooooOO % I1Ii111 * i11iIiiIii * OoOoOO00
 if 78 - 78: I11i
 if 62 - 62: iIii1I11I1II1 . o0oOOo0O0Ooo . ooOoO0o % oO0o % O0 % oO0o
 for oOO0O in lisp_crypto_keys_by_rloc_decap :
  iiiii1ii1 = oOO0O . split ( ":" )
  if ( len ( iiiii1ii1 ) == 1 ) : continue
  iiiii1ii1 = iiiii1ii1 [ 0 ] if len ( iiiii1ii1 ) == 2 else ":" . join ( iiiii1ii1 [ 0 : - 1 ] )
  if ( iiiii1ii1 == I1IIII1i1 ) :
   Ii111I11 = lisp_crypto_keys_by_rloc_decap [ oOO0O ]
   lisp_crypto_keys_by_rloc_decap [ I1IIII1i1 ] = Ii111I11
   return ( I1IIII1i1 )
   if 71 - 71: I11i * I1ii11iIi11i * OOooOOo * o0oOOo0O0Ooo
   if 53 - 53: I1IiiI % I1IiiI
 return ( None )
 if 80 - 80: OoO0O00 - i11iIiiIii / iII111i * I1ii11iIi11i / I1IiiI - I1Ii111
 if 85 - 85: IiII
 if 72 - 72: iII111i * OoOoOO00
 if 65 - 65: iIii1I11I1II1 / iIii1I11I1II1 % O0 / II111iiii . OOooOOo . O0
 if 65 - 65: I11i
 if 35 - 35: o0oOOo0O0Ooo - i11iIiiIii
 if 78 - 78: ooOoO0o - II111iiii - i1IIi
 if 18 - 18: OoooooooOO % OoOoOO00 - IiII / oO0o . OOooOOo . I1IiiI
 if 77 - 77: I1ii11iIi11i . OoO0O00 / OoOoOO00 / O0
 if 67 - 67: ooOoO0o % I11i % oO0o
 if 74 - 74: II111iiii
def lisp_build_crypto_decap_lookup_key ( addr , port ) :
 addr = addr . print_address_no_iid ( )
 IIIIII = addr + ":" + str ( port )
 if 32 - 32: i1IIi % iIii1I11I1II1 . O0 % i11iIiiIii / i11iIiiIii
 if ( lisp_i_am_rtr ) :
  if ( lisp_rloc_probe_list . has_key ( addr ) ) : return ( addr )
  if 75 - 75: I1ii11iIi11i - IiII . II111iiii / i1IIi
  if 76 - 76: II111iiii * O0 - Oo0Ooo + OoooooooOO
  if 37 - 37: OoooooooOO + i11iIiiIii
  if 20 - 20: I1IiiI + iII111i + O0 * O0
  if 18 - 18: I11i - I11i . OoOoOO00 . ooOoO0o
  if 31 - 31: ooOoO0o
  for Oo0Oo in lisp_nat_state_info . values ( ) :
   for o0OoOOO00O in Oo0Oo :
    if ( addr == o0OoOOO00O . address ) : return ( IIIIII )
    if 87 - 87: OoooooooOO + OOooOOo - I1ii11iIi11i / I1IiiI + ooOoO0o - Oo0Ooo
    if 19 - 19: ooOoO0o + I1ii11iIi11i - ooOoO0o
  return ( addr )
  if 17 - 17: I11i * i1IIi + iIii1I11I1II1 % I1IiiI
 return ( IIIIII )
 if 44 - 44: IiII + I1IiiI . Ii1I % Oo0Ooo
 if 97 - 97: O0
 if 95 - 95: OoO0O00 % iII111i / I1IiiI * OoooooooOO
 if 31 - 31: iIii1I11I1II1
 if 62 - 62: o0oOOo0O0Ooo - iII111i / II111iiii . o0oOOo0O0Ooo
 if 20 - 20: iIii1I11I1II1 % OOooOOo
 if 91 - 91: ooOoO0o
def lisp_set_ttl ( lisp_socket , ttl ) :
 try :
  lisp_socket . setsockopt ( socket . SOL_IP , socket . IP_TTL , ttl )
 except :
  lprint ( "socket.setsockopt(IP_TTL) not supported" )
  pass
  if 96 - 96: I1IiiI . OOooOOo
 return
 if 94 - 94: OoooooooOO + II111iiii % ooOoO0o - II111iiii / O0
 if 34 - 34: IiII % oO0o
 if 54 - 54: I1IiiI
 if 80 - 80: OoOoOO00 . I1IiiI / I1ii11iIi11i . iII111i
 if 31 - 31: I11i * o0oOOo0O0Ooo
 if 17 - 17: Ii1I * iIii1I11I1II1
 if 9 - 9: o0oOOo0O0Ooo - IiII
def lisp_is_rloc_probe_request ( lisp_type ) :
 lisp_type = struct . unpack ( "B" , lisp_type ) [ 0 ]
 return ( lisp_type == 0x12 )
 if 78 - 78: i11iIiiIii . o0oOOo0O0Ooo
 if 72 - 72: Oo0Ooo % II111iiii + O0 * OoOoOO00 - OOooOOo + I1Ii111
 if 23 - 23: I1IiiI - O0 - iII111i . II111iiii / oO0o
 if 1 - 1: I11i . OOooOOo / oO0o % I11i * Oo0Ooo + Oo0Ooo
 if 23 - 23: Ii1I % i1IIi - I1Ii111
 if 95 - 95: OoOoOO00 - ooOoO0o . i1IIi . OoooooooOO
 if 38 - 38: I1IiiI + I1ii11iIi11i - Oo0Ooo . i11iIiiIii - i1IIi
def lisp_is_rloc_probe_reply ( lisp_type ) :
 lisp_type = struct . unpack ( "B" , lisp_type ) [ 0 ]
 return ( lisp_type == 0x28 )
 if 11 - 11: IiII / I1IiiI . I1IiiI
 if 87 - 87: OoooooooOO * OoO0O00 * iIii1I11I1II1
 if 16 - 16: o0oOOo0O0Ooo * I11i + OoooooooOO + O0 / iIii1I11I1II1
 if 60 - 60: Ii1I % IiII * OoooooooOO * ooOoO0o * Ii1I
 if 8 - 8: I1Ii111 - o0oOOo0O0Ooo
 if 52 - 52: OoOoOO00 % O0 + I1ii11iIi11i . i11iIiiIii
 if 59 - 59: Ii1I - I1Ii111 . ooOoO0o - OoOoOO00 + oO0o . OoO0O00
 if 88 - 88: OOooOOo - ooOoO0o * o0oOOo0O0Ooo . OoooooooOO
 if 3 - 3: I1Ii111
 if 24 - 24: Ii1I + i11iIiiIii * I1Ii111 - OoOoOO00 / Ii1I - OoOoOO00
 if 69 - 69: I11i - I1IiiI . oO0o - OoooooooOO
 if 33 - 33: o0oOOo0O0Ooo - o0oOOo0O0Ooo
 if 55 - 55: OoooooooOO / IiII + i1IIi
 if 54 - 54: ooOoO0o * Ii1I / Ii1I
 if 15 - 15: oO0o * I1Ii111
 if 11 - 11: Ii1I + o0oOOo0O0Ooo * OoooooooOO % iIii1I11I1II1
 if 87 - 87: OoO0O00 + o0oOOo0O0Ooo
 if 46 - 46: oO0o + OoOoOO00
 if 17 - 17: Ii1I . Oo0Ooo - oO0o % OOooOOo
def lisp_is_rloc_probe ( packet , rr ) :
 i1iIIII1iiIIi = ( struct . unpack ( "B" , packet [ 9 ] ) [ 0 ] == 17 )
 if ( i1iIIII1iiIIi == False ) : return ( [ packet , None , None , None ] )
 if 59 - 59: O0
 I11iI1 = struct . unpack ( "H" , packet [ 20 : 22 ] ) [ 0 ]
 oOo00OO0o0 = struct . unpack ( "H" , packet [ 22 : 24 ] ) [ 0 ]
 OOoo = ( socket . htons ( LISP_CTRL_PORT ) in [ I11iI1 , oOo00OO0o0 ] )
 if ( OOoo == False ) : return ( [ packet , None , None , None ] )
 if 96 - 96: oO0o * I11i / OoooooooOO / OoO0O00
 if ( rr == 0 ) :
  OOo00o = lisp_is_rloc_probe_request ( packet [ 28 ] )
  if ( OOo00o == False ) : return ( [ packet , None , None , None ] )
 elif ( rr == 1 ) :
  OOo00o = lisp_is_rloc_probe_reply ( packet [ 28 ] )
  if ( OOo00o == False ) : return ( [ packet , None , None , None ] )
 elif ( rr == - 1 ) :
  OOo00o = lisp_is_rloc_probe_request ( packet [ 28 ] )
  if ( OOo00o == False ) :
   OOo00o = lisp_is_rloc_probe_reply ( packet [ 28 ] )
   if ( OOo00o == False ) : return ( [ packet , None , None , None ] )
   if 84 - 84: I1ii11iIi11i + Ii1I % i11iIiiIii % Ii1I / OoooooooOO
   if 8 - 8: i1IIi
   if 61 - 61: i11iIiiIii * Ii1I % iII111i - Ii1I * O0
   if 39 - 39: iII111i + i1IIi * iII111i - iIii1I11I1II1
   if 5 - 5: Ii1I / i1IIi - iIii1I11I1II1 * I1ii11iIi11i - O0 % OOooOOo
   if 17 - 17: I1Ii111 . ooOoO0o
 OO = lisp_address ( LISP_AFI_IPV4 , "" , 32 , 0 )
 OO . address = socket . ntohl ( struct . unpack ( "I" , packet [ 12 : 16 ] ) [ 0 ] )
 if 34 - 34: o0oOOo0O0Ooo / OOooOOo + Ii1I % Oo0Ooo % I1ii11iIi11i
 if 72 - 72: IiII / II111iiii
 if 25 - 25: i1IIi + OoOoOO00 + oO0o + OoooooooOO
 if 21 - 21: I1ii11iIi11i
 if ( OO . is_local ( ) ) : return ( [ None , None , None , None ] )
 if 60 - 60: i1IIi / OoO0O00 . Ii1I
 if 16 - 16: i11iIiiIii + OoOoOO00 % Oo0Ooo + I1ii11iIi11i * Ii1I / I1Ii111
 if 26 - 26: iII111i
 if 31 - 31: iII111i
 OO = OO . print_address_no_iid ( )
 Ii1 = socket . ntohs ( struct . unpack ( "H" , packet [ 20 : 22 ] ) [ 0 ] )
 I1i = struct . unpack ( "B" , packet [ 8 ] ) [ 0 ] - 1
 packet = packet [ 28 : : ]
 if 45 - 45: OoO0O00
 IIi = bold ( "Receive(pcap)" , False )
 ii1iIii = bold ( "from " + OO , False )
 IiIiI1 = lisp_format_packet ( packet )
 lprint ( "{} {} bytes {} {}, packet: {}" . format ( IIi , len ( packet ) , ii1iIii , Ii1 , IiIiI1 ) )
 if 55 - 55: iIii1I11I1II1 % iIii1I11I1II1 + I11i - ooOoO0o + I1IiiI * O0
 return ( [ packet , OO , Ii1 , I1i ] )
 if 47 - 47: ooOoO0o + iIii1I11I1II1 * OOooOOo . I1IiiI . o0oOOo0O0Ooo
 if 49 - 49: Oo0Ooo . OoOoOO00 * OOooOOo
 if 86 - 86: IiII * OOooOOo + Ii1I
 if 62 - 62: I11i
 if 86 - 86: Oo0Ooo % II111iiii + I1Ii111 / I1ii11iIi11i
 if 15 - 15: I1IiiI / I1Ii111 % iII111i
 if 57 - 57: I1Ii111 . iIii1I11I1II1 / Oo0Ooo / IiII / iII111i * OoOoOO00
 if 35 - 35: i1IIi + I1Ii111 - ooOoO0o . I1ii11iIi11i + Oo0Ooo
 if 43 - 43: oO0o . OoO0O00 * i1IIi
 if 1 - 1: ooOoO0o / i1IIi
 if 42 - 42: I1ii11iIi11i * ooOoO0o + OoOoOO00 % I1ii11iIi11i . IiII
def lisp_ipc_write_xtr_parameters ( cp , dp ) :
 if ( lisp_ipc_dp_socket == None ) : return
 if 75 - 75: OoO0O00 * i1IIi - OOooOOo % II111iiii % OoO0O00 - OoOoOO00
 Ooooo = { "type" : "xtr-parameters" , "control-plane-logging" : cp ,
 "data-plane-logging" : dp , "rtr" : lisp_i_am_rtr }
 if 75 - 75: I11i * IiII * ooOoO0o
 lisp_write_to_dp_socket ( Ooooo )
 return
 if 31 - 31: Ii1I
 if 72 - 72: OOooOOo * Ii1I % OoO0O00
 if 72 - 72: OoOoOO00 + o0oOOo0O0Ooo - i1IIi - OoO0O00 % OoOoOO00
 if 42 - 42: oO0o / i1IIi . IiII
 if 12 - 12: i11iIiiIii . ooOoO0o
 if 80 - 80: O0 / iIii1I11I1II1 % iII111i * ooOoO0o / i11iIiiIii . OoOoOO00
 if 88 - 88: OoooooooOO . I1IiiI
 if 6 - 6: I1Ii111 - i11iIiiIii - oO0o
def lisp_external_data_plane ( ) :
 II1i = 'egrep "ipc-data-plane = yes" ./lisp.config'
 if ( commands . getoutput ( II1i ) != "" ) : return ( True )
 if 7 - 7: i1IIi
 if ( os . getenv ( "LISP_RUN_LISP_XTR" ) != None ) : return ( True )
 return ( False )
 if 6 - 6: OoooooooOO - Oo0Ooo - I1ii11iIi11i
 if 34 - 34: iII111i + i11iIiiIii . IiII
 if 54 - 54: Oo0Ooo + I11i - iII111i * ooOoO0o % i11iIiiIii . IiII
 if 29 - 29: II111iiii % i11iIiiIii % O0
 if 38 - 38: o0oOOo0O0Ooo * IiII
 if 51 - 51: OoooooooOO . Ii1I % OoooooooOO - I1IiiI + I1Ii111 % oO0o
 if 28 - 28: i11iIiiIii - I1IiiI * OoO0O00
 if 19 - 19: OoooooooOO
 if 34 - 34: OoOoOO00 . oO0o
 if 53 - 53: oO0o + OoooooooOO * ooOoO0o
 if 85 - 85: I1ii11iIi11i - o0oOOo0O0Ooo % o0oOOo0O0Ooo % iII111i * OoOoOO00
 if 50 - 50: I1Ii111 + I1Ii111 + I11i - OoOoOO00
 if 65 - 65: oO0o / I11i + iII111i - I1ii11iIi11i
 if 80 - 80: II111iiii . i11iIiiIii
def lisp_process_data_plane_restart ( do_clear = False ) :
 os . system ( "touch ./lisp.config" )
 if 66 - 66: ooOoO0o * iII111i * OOooOOo % OoO0O00 / I1ii11iIi11i
 iIii1 = { "type" : "entire-map-cache" , "entries" : [ ] }
 if 88 - 88: iIii1I11I1II1 % iII111i
 if ( do_clear == False ) :
  i1I1I11ii = iIii1 [ "entries" ]
  lisp_map_cache . walk_cache ( lisp_ipc_walk_map_cache , i1I1I11ii )
  if 25 - 25: O0 % i11iIiiIii
  if 67 - 67: I1ii11iIi11i / OoO0O00 + OoO0O00 % o0oOOo0O0Ooo / II111iiii . I1IiiI
 lisp_write_to_dp_socket ( iIii1 )
 return
 if 72 - 72: I1Ii111 * I1ii11iIi11i * Ii1I % II111iiii * Ii1I / O0
 if 6 - 6: oO0o * ooOoO0o . I1Ii111 / OOooOOo . OoOoOO00
 if 4 - 4: Ii1I / II111iiii + o0oOOo0O0Ooo / IiII
 if 9 - 9: ooOoO0o + i1IIi / ooOoO0o / I11i * I1ii11iIi11i / OoooooooOO
 if 28 - 28: o0oOOo0O0Ooo
 if 97 - 97: I1Ii111 - I1Ii111 * OoO0O00 % II111iiii * IiII
 if 2 - 2: I1Ii111 % iII111i . OoooooooOO - o0oOOo0O0Ooo
 if 30 - 30: i1IIi / I1Ii111 * oO0o - oO0o / oO0o
 if 9 - 9: IiII / o0oOOo0O0Ooo . IiII * O0 % i11iIiiIii % OoOoOO00
 if 29 - 29: I1ii11iIi11i % ooOoO0o . OOooOOo . Ii1I . IiII
 if 69 - 69: o0oOOo0O0Ooo . i11iIiiIii * I11i + IiII / I11i
 if 66 - 66: I1ii11iIi11i % I1Ii111 - i11iIiiIii % I11i
 if 62 - 62: i11iIiiIii % iIii1I11I1II1 / IiII . I1IiiI * O0
 if 17 - 17: I1ii11iIi11i - I1Ii111 % II111iiii + OOooOOo
def lisp_process_data_plane_stats ( msg , lisp_sockets , lisp_port ) :
 if ( msg . has_key ( "entries" ) == False ) :
  lprint ( "No 'entries' in stats IPC message" )
  return
  if 45 - 45: I1Ii111 + iII111i - iIii1I11I1II1 / Oo0Ooo
 if ( type ( msg [ "entries" ] ) != list ) :
  lprint ( "'entries' in stats IPC message must be an array" )
  return
  if 92 - 92: iIii1I11I1II1 . OoO0O00 - I11i % I1ii11iIi11i / i11iIiiIii
  if 4 - 4: Oo0Ooo / I1IiiI * i1IIi . II111iiii
 for msg in msg [ "entries" ] :
  if ( msg . has_key ( "eid-prefix" ) == False ) :
   lprint ( "No 'eid-prefix' in stats IPC message" )
   continue
   if 13 - 13: i1IIi
  oo0oO = msg [ "eid-prefix" ]
  if 39 - 39: OOooOOo
  if ( msg . has_key ( "instance-id" ) == False ) :
   lprint ( "No 'instance-id' in stats IPC message" )
   continue
   if 73 - 73: OoO0O00 . ooOoO0o
  OO0OO000 = int ( msg [ "instance-id" ] )
  if 13 - 13: o0oOOo0O0Ooo - OoOoOO00
  if 60 - 60: OoO0O00
  if 17 - 17: i11iIiiIii % i1IIi % I1IiiI % ooOoO0o + I1Ii111 + Oo0Ooo
  if 16 - 16: iII111i . I1ii11iIi11i . oO0o . OoO0O00
  ii1Ii = lisp_address ( LISP_AFI_NONE , "" , 0 , OO0OO000 )
  ii1Ii . store_prefix ( oo0oO )
  OoOOO000O0o = lisp_map_cache_lookup ( None , ii1Ii )
  if ( OoOOO000O0o == None ) :
   lprint ( "Map-cache entry for {} not found for stats update" . format ( oo0oO ) )
   if 90 - 90: i1IIi . ooOoO0o + i11iIiiIii * OoooooooOO
   continue
   if 30 - 30: iII111i . OoO0O00 . i11iIiiIii / I1ii11iIi11i * Oo0Ooo
   if 38 - 38: IiII + II111iiii
  if ( msg . has_key ( "rlocs" ) == False ) :
   lprint ( "No 'rlocs' in stats IPC message for {}" . format ( oo0oO ) )
   if 20 - 20: iII111i * I1IiiI * iII111i - o0oOOo0O0Ooo + i1IIi + ooOoO0o
   continue
   if 49 - 49: II111iiii * I1IiiI / oO0o
  if ( type ( msg [ "rlocs" ] ) != list ) :
   lprint ( "'rlocs' in stats IPC message must be an array" )
   continue
   if 50 - 50: Ii1I + O0 . I1IiiI * Oo0Ooo
  iI11ii = msg [ "rlocs" ]
  if 9 - 9: Ii1I % OoO0O00 * OOooOOo * I11i * I1Ii111 % iIii1I11I1II1
  if 50 - 50: Ii1I * Ii1I % I11i / iIii1I11I1II1 / ooOoO0o / iII111i
  if 91 - 91: Ii1I - O0 . I11i - OoooooooOO * IiII . II111iiii
  if 38 - 38: I1IiiI + OoO0O00
  for Ii1iI1I in iI11ii :
   if ( Ii1iI1I . has_key ( "rloc" ) == False ) : continue
   if 66 - 66: I1Ii111 . Ii1I / I1ii11iIi11i / iIii1I11I1II1 + O0 / i1IIi
   oo00OO = Ii1iI1I [ "rloc" ]
   if ( oo00OO == "no-address" ) : continue
   if 72 - 72: ooOoO0o . II111iiii
   o0OOooooooOO = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
   o0OOooooooOO . store_address ( oo00OO )
   if 32 - 32: I1Ii111 - oO0o + OoooooooOO . OoOoOO00 + i11iIiiIii / i1IIi
   OoooO00OO = OoOOO000O0o . get_rloc ( o0OOooooooOO )
   if ( OoooO00OO == None ) : continue
   if 26 - 26: I1IiiI + OoooooooOO % OoOoOO00 . IiII - II111iiii . OoOoOO00
   if 37 - 37: OoO0O00 % O0 + OoOoOO00 * I11i . Ii1I * OoO0O00
   if 18 - 18: o0oOOo0O0Ooo / OOooOOo
   if 28 - 28: O0 / Ii1I - oO0o % I1ii11iIi11i % O0 . OoO0O00
   ooO0oOO0oOo00 = 0 if Ii1iI1I . has_key ( "packet-count" ) == False else Ii1iI1I [ "packet-count" ]
   if 44 - 44: O0
   oooo0Oo0 = 0 if Ii1iI1I . has_key ( "byte-count" ) == False else Ii1iI1I [ "byte-count" ]
   if 12 - 12: I1ii11iIi11i
   I11i1II = 0 if Ii1iI1I . has_key ( "seconds-last-packet" ) == False else Ii1iI1I [ "seconds-last-packet" ]
   if 80 - 80: oO0o / i1IIi * iIii1I11I1II1
   if 38 - 38: Ii1I
   OoooO00OO . stats . packet_count += ooO0oOO0oOo00
   OoooO00OO . stats . byte_count += oooo0Oo0
   OoooO00OO . stats . last_increment = lisp_get_timestamp ( ) - I11i1II
   if 20 - 20: iIii1I11I1II1 + Oo0Ooo - Ii1I / i11iIiiIii . OoO0O00
   lprint ( "Update stats {}/{}/{}s for {} RLOC {}" . format ( ooO0oOO0oOo00 , oooo0Oo0 ,
 I11i1II , oo0oO , oo00OO ) )
   if 66 - 66: OoooooooOO - Ii1I / iII111i . I1IiiI + I1ii11iIi11i - I1Ii111
   if 36 - 36: I1Ii111 - OoO0O00 . I1ii11iIi11i * I1ii11iIi11i
   if 9 - 9: OOooOOo - oO0o - iIii1I11I1II1 * i11iIiiIii / I11i
   if 2 - 2: i1IIi % iII111i * ooOoO0o / OoOoOO00 + Oo0Ooo
   if 59 - 59: i11iIiiIii / I1IiiI * iII111i
  if ( OoOOO000O0o . group . is_null ( ) and OoOOO000O0o . has_ttl_elapsed ( ) ) :
   oo0oO = green ( OoOOO000O0o . print_eid_tuple ( ) , False )
   lprint ( "Refresh map-cache entry {}" . format ( oo0oO ) )
   lisp_send_map_request ( lisp_sockets , lisp_port , None , OoOOO000O0o . eid , None )
   if 16 - 16: i11iIiiIii * II111iiii - ooOoO0o
   if 80 - 80: iIii1I11I1II1 + iIii1I11I1II1 + I1Ii111 - IiII * iII111i - Ii1I
 return
 if 89 - 89: O0 * ooOoO0o
 if 36 - 36: I1ii11iIi11i * II111iiii * iII111i + I1IiiI + OoO0O00 + oO0o
 if 28 - 28: Ii1I - i11iIiiIii . oO0o / II111iiii
 if 82 - 82: iII111i * iII111i . IiII * II111iiii
 if 17 - 17: OoooooooOO % I1Ii111 * I1Ii111 / II111iiii . OoOoOO00 * iII111i
 if 80 - 80: IiII % i11iIiiIii
 if 6 - 6: II111iiii + i11iIiiIii - Oo0Ooo % OOooOOo + Oo0Ooo
 if 46 - 46: iII111i
 if 31 - 31: OoO0O00 + I1Ii111 / iIii1I11I1II1
 if 11 - 11: ooOoO0o - OoOoOO00
 if 19 - 19: O0 . OoOoOO00 - i1IIi . oO0o
 if 96 - 96: o0oOOo0O0Ooo % o0oOOo0O0Ooo - OoO0O00 * iIii1I11I1II1 + ooOoO0o - ooOoO0o
 if 4 - 4: OoO0O00 - OOooOOo
 if 21 - 21: I1Ii111 * i11iIiiIii
 if 63 - 63: oO0o + OoOoOO00
 if 50 - 50: o0oOOo0O0Ooo / Oo0Ooo * ooOoO0o * Ii1I
 if 97 - 97: I1IiiI / oO0o + I1Ii111 + I1Ii111
 if 86 - 86: o0oOOo0O0Ooo % ooOoO0o + OoOoOO00 * ooOoO0o
 if 20 - 20: Ii1I * iII111i / ooOoO0o
 if 18 - 18: Oo0Ooo * Ii1I / i11iIiiIii . OoO0O00 + OoooooooOO
 if 23 - 23: I1IiiI - I1ii11iIi11i . O0 . OoOoOO00 . OoO0O00
 if 81 - 81: IiII * I11i - iIii1I11I1II1
 if 41 - 41: oO0o * I11i + I1IiiI - OoO0O00
def lisp_process_data_plane_decap_stats ( msg , lisp_ipc_socket ) :
 if 63 - 63: Oo0Ooo * Ii1I - Ii1I
 if 76 - 76: OoO0O00 . IiII % iIii1I11I1II1 / I1IiiI + iIii1I11I1II1 . I1IiiI
 if 57 - 57: IiII - i1IIi * ooOoO0o
 if 5 - 5: oO0o . O0 * IiII / Ii1I + OoO0O00
 if 75 - 75: OOooOOo * OoOoOO00
 if ( lisp_i_am_itr ) :
  lprint ( "Send decap-stats IPC message to lisp-etr process" )
  Ooooo = "stats%{}" . format ( json . dumps ( msg ) )
  Ooooo = lisp_command_ipc ( Ooooo , "lisp-itr" )
  lisp_ipc ( Ooooo , lisp_ipc_socket , "lisp-etr" )
  return
  if 82 - 82: Ii1I
  if 83 - 83: I1IiiI
  if 22 - 22: IiII / Ii1I + I1Ii111 % iIii1I11I1II1
  if 75 - 75: OoOoOO00 % OoOoOO00 % o0oOOo0O0Ooo % I1ii11iIi11i + IiII
  if 45 - 45: I11i - iIii1I11I1II1
  if 20 - 20: OoOoOO00
  if 84 - 84: OoOoOO00
  if 59 - 59: Ii1I / I1Ii111 + i11iIiiIii
 Ooooo = bold ( "IPC" , False )
 lprint ( "Process decap-stats {} message: '{}'" . format ( Ooooo , msg ) )
 if 20 - 20: O0 / I1Ii111 - OOooOOo % iIii1I11I1II1
 if ( lisp_i_am_etr ) : msg = json . loads ( msg )
 if 89 - 89: O0 * OoOoOO00 . ooOoO0o
 IiiI1IiIi1i1 = [ "good-packets" , "ICV-error" , "checksum-error" ,
 "lisp-header-error" , "no-decrypt-key" , "bad-inner-version" ,
 "outer-header-error" ]
 if 7 - 7: i1IIi - o0oOOo0O0Ooo - I1IiiI
 for OOOOoO0OO0OOO in IiiI1IiIi1i1 :
  ooO0oOO0oOo00 = 0 if msg . has_key ( OOOOoO0OO0OOO ) == False else msg [ OOOOoO0OO0OOO ] [ "packet-count" ]
  if 47 - 47: OOooOOo
  lisp_decap_stats [ OOOOoO0OO0OOO ] . packet_count += ooO0oOO0oOo00
  if 58 - 58: Ii1I . ooOoO0o / IiII
  oooo0Oo0 = 0 if msg . has_key ( OOOOoO0OO0OOO ) == False else msg [ OOOOoO0OO0OOO ] [ "byte-count" ]
  if 8 - 8: IiII - O0 + OOooOOo
  lisp_decap_stats [ OOOOoO0OO0OOO ] . byte_count += oooo0Oo0
  if 16 - 16: II111iiii - I1Ii111
  I11i1II = 0 if msg . has_key ( OOOOoO0OO0OOO ) == False else msg [ OOOOoO0OO0OOO ] [ "seconds-last-packet" ]
  if 55 - 55: OoOoOO00 + I1ii11iIi11i + OoO0O00 - OoOoOO00 / o0oOOo0O0Ooo
  lisp_decap_stats [ OOOOoO0OO0OOO ] . last_increment = lisp_get_timestamp ( ) - I11i1II
  if 76 - 76: I1ii11iIi11i / oO0o + Ii1I - O0
 return
 if 95 - 95: OoOoOO00
 if 69 - 69: iII111i / Ii1I
 if 83 - 83: oO0o
 if 1 - 1: oO0o * iIii1I11I1II1 % iIii1I11I1II1 % iIii1I11I1II1 / oO0o + IiII
 if 29 - 29: OoooooooOO
 if 55 - 55: O0 - o0oOOo0O0Ooo % I1ii11iIi11i * I11i * oO0o
 if 83 - 83: iIii1I11I1II1
 if 92 - 92: OoO0O00 - iII111i
 if 97 - 97: ooOoO0o / I11i . IiII + I1Ii111 . iIii1I11I1II1
 if 24 - 24: ooOoO0o - oO0o % OoOoOO00 * Oo0Ooo
 if 54 - 54: Ii1I - OoooooooOO % I1IiiI + oO0o
 if 70 - 70: I1Ii111 % iIii1I11I1II1
 if 74 - 74: i1IIi % i11iIiiIii + oO0o
 if 94 - 94: OoO0O00 * I1IiiI / O0 + I1Ii111 / i11iIiiIii
 if 34 - 34: Oo0Ooo . i1IIi
 if 97 - 97: I11i
 if 89 - 89: iII111i % OoOoOO00 . Oo0Ooo
def lisp_process_punt ( punt_socket , lisp_send_sockets , lisp_ephem_port ) :
 iII1III11ii , OO = punt_socket . recvfrom ( 4000 )
 if 24 - 24: OOooOOo . oO0o / I1Ii111 / IiII - iII111i
 i11Ii = json . loads ( iII1III11ii )
 if ( type ( i11Ii ) != dict ) :
  lprint ( "Invalid punt message from {}, not in JSON format" . format ( OO ) )
  if 23 - 23: iIii1I11I1II1 * ooOoO0o * iII111i * i11iIiiIii * i1IIi
  return
  if 25 - 25: O0 / OoO0O00 - oO0o - I1IiiI * OoOoOO00
 OOOo0ooOOO = bold ( "Punt" , False )
 lprint ( "{} message from '{}': '{}'" . format ( OOOo0ooOOO , OO , i11Ii ) )
 if 55 - 55: iII111i / OoO0O00
 if ( i11Ii . has_key ( "type" ) == False ) :
  lprint ( "Punt IPC message has no 'type' key" )
  return
  if 49 - 49: i1IIi
  if 49 - 49: IiII - i1IIi % OoooooooOO
  if 72 - 72: II111iiii % OOooOOo - o0oOOo0O0Ooo % oO0o + Oo0Ooo
  if 55 - 55: Oo0Ooo . o0oOOo0O0Ooo / OOooOOo + I11i . Ii1I
  if 89 - 89: OoO0O00 % iIii1I11I1II1 * oO0o . O0 + iIii1I11I1II1 / IiII
 if ( i11Ii [ "type" ] == "statistics" ) :
  lisp_process_data_plane_stats ( i11Ii , lisp_send_sockets , lisp_ephem_port )
  return
  if 86 - 86: iIii1I11I1II1 + OOooOOo % IiII . o0oOOo0O0Ooo % Oo0Ooo
 if ( i11Ii [ "type" ] == "decap-statistics" ) :
  lisp_process_data_plane_decap_stats ( i11Ii , punt_socket )
  return
  if 96 - 96: O0
  if 15 - 15: i1IIi . iIii1I11I1II1
  if 3 - 3: II111iiii * i11iIiiIii * i1IIi - i1IIi
  if 11 - 11: I1IiiI % Ii1I * i11iIiiIii % OOooOOo + II111iiii
  if 61 - 61: I1Ii111 + I11i + I1IiiI
 if ( i11Ii [ "type" ] == "restart" ) :
  lisp_process_data_plane_restart ( )
  return
  if 48 - 48: I11i
  if 67 - 67: o0oOOo0O0Ooo
  if 36 - 36: IiII - I11i - Ii1I / OoOoOO00 % OoO0O00 * iIii1I11I1II1
  if 61 - 61: i11iIiiIii / Ii1I - OOooOOo . I1ii11iIi11i
  if 89 - 89: ooOoO0o % i11iIiiIii
 if ( i11Ii [ "type" ] != "discovery" ) :
  lprint ( "Punt IPC message has wrong format" )
  return
  if 57 - 57: Oo0Ooo / ooOoO0o - O0 . ooOoO0o
 if ( i11Ii . has_key ( "interface" ) == False ) :
  lprint ( "Invalid punt message from {}, required keys missing" . format ( OO ) )
  if 61 - 61: o0oOOo0O0Ooo / OoooooooOO . I1ii11iIi11i + Oo0Ooo
  return
  if 75 - 75: Ii1I
  if 79 - 79: i1IIi . I1ii11iIi11i * o0oOOo0O0Ooo / I11i . I11i / ooOoO0o
  if 99 - 99: oO0o + I11i % i1IIi . iII111i
  if 58 - 58: Oo0Ooo % i11iIiiIii . Oo0Ooo / Oo0Ooo - I1IiiI . Ii1I
  if 65 - 65: OoO0O00
 I1i1II1 = i11Ii [ "interface" ]
 if ( I1i1II1 == "" ) :
  OO0OO000 = int ( i11Ii [ "instance-id" ] )
  if ( OO0OO000 == - 1 ) : return
 else :
  OO0OO000 = lisp_get_interface_instance_id ( I1i1II1 , None )
  if 16 - 16: IiII % I1IiiI % iIii1I11I1II1 . I1IiiI . I1ii11iIi11i - IiII
  if 6 - 6: I1Ii111 + OoO0O00 + O0 * OoOoOO00 . iIii1I11I1II1 . I1Ii111
  if 93 - 93: ooOoO0o % iIii1I11I1II1 + I1ii11iIi11i
  if 74 - 74: OoOoOO00 + I1ii11iIi11i
  if 82 - 82: II111iiii
 IiIiiiiI1 = None
 if ( i11Ii . has_key ( "source-eid" ) ) :
  O0000oOoO0o0 = i11Ii [ "source-eid" ]
  IiIiiiiI1 = lisp_address ( LISP_AFI_NONE , O0000oOoO0o0 , 0 , OO0OO000 )
  if ( IiIiiiiI1 . is_null ( ) ) :
   lprint ( "Invalid source-EID format '{}'" . format ( O0000oOoO0o0 ) )
   return
   if 55 - 55: I11i . iIii1I11I1II1 / Ii1I - OoO0O00 * I1ii11iIi11i % iIii1I11I1II1
   if 48 - 48: ooOoO0o + Oo0Ooo / Oo0Ooo
 iIiiIi1i1I1I1 = None
 if ( i11Ii . has_key ( "dest-eid" ) ) :
  Ii1O0o = i11Ii [ "dest-eid" ]
  iIiiIi1i1I1I1 = lisp_address ( LISP_AFI_NONE , Ii1O0o , 0 , OO0OO000 )
  if ( iIiiIi1i1I1I1 . is_null ( ) ) :
   lprint ( "Invalid dest-EID format '{}'" . format ( Ii1O0o ) )
   return
   if 69 - 69: Ii1I . OoooooooOO - I11i % OoOoOO00
   if 46 - 46: iIii1I11I1II1 . II111iiii / OoooooooOO - ooOoO0o * iII111i
   if 52 - 52: I11i + iII111i
   if 9 - 9: OoOoOO00 % II111iiii . I11i * Oo0Ooo
   if 53 - 53: II111iiii / i1IIi + OoooooooOO * O0
   if 62 - 62: IiII . O0
   if 87 - 87: I1ii11iIi11i / oO0o / IiII . OOooOOo
   if 91 - 91: OOooOOo % oO0o . OoOoOO00 . I1IiiI - OoOoOO00
 if ( IiIiiiiI1 ) :
  o0o000 = green ( IiIiiiiI1 . print_address ( ) , False )
  o0o0O0OO0oO = lisp_db_for_lookups . lookup_cache ( IiIiiiiI1 , False )
  if ( o0o0O0OO0oO != None ) :
   if 18 - 18: O0 - I1IiiI + i1IIi % i11iIiiIii
   if 97 - 97: iII111i * OoooooooOO + I1Ii111 + ooOoO0o - ooOoO0o
   if 63 - 63: o0oOOo0O0Ooo * OOooOOo + iIii1I11I1II1 + Oo0Ooo
   if 25 - 25: oO0o + IiII % o0oOOo0O0Ooo
   if 24 - 24: OoOoOO00
   if ( o0o0O0OO0oO . dynamic_eid_configured ( ) ) :
    oOOoo = lisp_allow_dynamic_eid ( I1i1II1 , IiIiiiiI1 )
    if ( oOOoo != None and lisp_i_am_itr ) :
     lisp_itr_discover_eid ( o0o0O0OO0oO , IiIiiiiI1 , I1i1II1 , oOOoo )
    else :
     lprint ( ( "Disallow dynamic source-EID {} " + "on interface {}" ) . format ( o0o000 , I1i1II1 ) )
     if 87 - 87: I1ii11iIi11i / ooOoO0o * i1IIi
     if 71 - 71: OoOoOO00 - I11i
     if 83 - 83: oO0o + oO0o - Oo0Ooo . Oo0Ooo - iII111i . OOooOOo
  else :
   lprint ( "Punt from non-EID source {}" . format ( o0o000 ) )
   if 56 - 56: OoOoOO00 * IiII + i1IIi
   if 40 - 40: I1ii11iIi11i / O0
   if 87 - 87: ooOoO0o
   if 100 - 100: iII111i + II111iiii * Oo0Ooo * OOooOOo
   if 6 - 6: IiII % OOooOOo
   if 3 - 3: OoOoOO00 / OoOoOO00 - II111iiii
 if ( iIiiIi1i1I1I1 ) :
  OoOOO000O0o = lisp_map_cache_lookup ( IiIiiiiI1 , iIiiIi1i1I1I1 )
  if ( OoOOO000O0o == None or OoOOO000O0o . action == LISP_SEND_MAP_REQUEST_ACTION ) :
   if 41 - 41: oO0o
   if 12 - 12: I1IiiI + I1Ii111
   if 66 - 66: I1Ii111 + OOooOOo + I1Ii111 . OoooooooOO * oO0o / OoO0O00
   if 74 - 74: O0 % OOooOOo * OoOoOO00 / oO0o - Oo0Ooo
   if 79 - 79: Ii1I + IiII
   if ( lisp_rate_limit_map_request ( IiIiiiiI1 , iIiiIi1i1I1I1 ) ) : return
   lisp_send_map_request ( lisp_send_sockets , lisp_ephem_port ,
 IiIiiiiI1 , iIiiIi1i1I1I1 , None )
  else :
   o0o000 = green ( iIiiIi1i1I1I1 . print_address ( ) , False )
   lprint ( "Map-cache entry for {} already exists" . format ( o0o000 ) )
   if 21 - 21: o0oOOo0O0Ooo * iII111i * o0oOOo0O0Ooo * o0oOOo0O0Ooo . Oo0Ooo
   if 98 - 98: I1ii11iIi11i
 return
 if 58 - 58: IiII / i11iIiiIii % I11i
 if 74 - 74: OoooooooOO - I1ii11iIi11i + OOooOOo % IiII . o0oOOo0O0Ooo
 if 21 - 21: Ii1I
 if 72 - 72: I1Ii111 . OoooooooOO / I1Ii111 - Ii1I / I1ii11iIi11i * I1ii11iIi11i
 if 72 - 72: IiII . Ii1I + OoooooooOO * OoOoOO00 + Oo0Ooo . iII111i
 if 92 - 92: O0 * Ii1I - I1ii11iIi11i - IiII . OoO0O00 + I1IiiI
 if 59 - 59: i1IIi * OOooOOo % Oo0Ooo
def lisp_ipc_map_cache_entry ( mc , jdata ) :
 iiIiiIi = lisp_write_ipc_map_cache ( True , mc , dont_send = True )
 jdata . append ( iiIiiIi )
 return ( [ True , jdata ] )
 if 44 - 44: iIii1I11I1II1 . OOooOOo
 if 57 - 57: II111iiii + I1Ii111
 if 42 - 42: OoOoOO00 % O0
 if 70 - 70: iIii1I11I1II1 * Oo0Ooo - I1IiiI / OoO0O00 + OoOoOO00
 if 94 - 94: OoooooooOO + O0 * iIii1I11I1II1 * II111iiii
 if 90 - 90: I11i + O0 / I1IiiI . oO0o / O0
 if 46 - 46: O0 . O0 - oO0o . II111iiii * I1IiiI * Ii1I
 if 10 - 10: i1IIi + i1IIi . i1IIi - I1IiiI - I1IiiI
def lisp_ipc_walk_map_cache ( mc , jdata ) :
 if 26 - 26: Ii1I * I11i / I11i
 if 79 - 79: ooOoO0o / oO0o - oO0o / OoooooooOO
 if 91 - 91: iIii1I11I1II1 - O0 * o0oOOo0O0Ooo * o0oOOo0O0Ooo . II111iiii
 if 69 - 69: II111iiii - Oo0Ooo + i1IIi . II111iiii + o0oOOo0O0Ooo
 if ( mc . group . is_null ( ) ) : return ( lisp_ipc_map_cache_entry ( mc , jdata ) )
 if 20 - 20: OoooooooOO - OoO0O00 * ooOoO0o * OoOoOO00 / OOooOOo
 if ( mc . source_cache == None ) : return ( [ True , jdata ] )
 if 64 - 64: O0 + iII111i / I11i * OoOoOO00 + o0oOOo0O0Ooo + I1Ii111
 if 16 - 16: I11i
 if 9 - 9: Ii1I / IiII * I11i - i11iIiiIii * I1ii11iIi11i / iII111i
 if 61 - 61: O0 % iII111i
 if 41 - 41: I1Ii111 * OoooooooOO
 jdata = mc . source_cache . walk_cache ( lisp_ipc_map_cache_entry , jdata )
 return ( [ True , jdata ] )
 if 76 - 76: OoooooooOO * II111iiii . II111iiii / o0oOOo0O0Ooo - iII111i
 if 49 - 49: O0 . I1ii11iIi11i . OoOoOO00 . I1Ii111 % O0 . iIii1I11I1II1
 if 19 - 19: iIii1I11I1II1
 if 97 - 97: Ii1I . I11i / ooOoO0o + Oo0Ooo
 if 100 - 100: iII111i / I1Ii111 % OoOoOO00 . O0 / OoOoOO00
 if 81 - 81: OoO0O00 % i11iIiiIii / OoO0O00 + ooOoO0o
 if 100 - 100: O0 . Oo0Ooo % Oo0Ooo % O0 / i11iIiiIii
def lisp_itr_discover_eid ( db , eid , input_interface , routed_interface ,
 lisp_ipc_listen_socket ) :
 oo0oO = eid . print_address ( )
 if ( db . dynamic_eids . has_key ( oo0oO ) ) :
  db . dynamic_eids [ oo0oO ] . last_packet = lisp_get_timestamp ( )
  return
  if 56 - 56: IiII - OOooOOo - OoOoOO00 - I11i
  if 57 - 57: i1IIi
  if 41 - 41: I11i / Ii1I
  if 1 - 1: II111iiii / iII111i
  if 83 - 83: OoO0O00 / iII111i
 oo0O0O = lisp_dynamic_eid ( )
 oo0O0O . dynamic_eid . copy_address ( eid )
 oo0O0O . interface = routed_interface
 oo0O0O . last_packet = lisp_get_timestamp ( )
 oo0O0O . get_timeout ( routed_interface )
 db . dynamic_eids [ oo0oO ] = oo0O0O
 if 59 - 59: I1Ii111 % OOooOOo . I1IiiI + I1ii11iIi11i % oO0o
 oOoOOOO = ""
 if ( input_interface != routed_interface ) :
  oOoOOOO = ", routed-interface " + routed_interface
  if 27 - 27: OoOoOO00 . I11i - Ii1I
  if 82 - 82: I1IiiI + OoOoOO00 . II111iiii / OoOoOO00 % OoOoOO00 . I1ii11iIi11i
 IiIIII1ii1Ii = green ( oo0oO , False ) + bold ( " discovered" , False )
 lprint ( "Dynamic-EID {} on interface {}{}, timeout {}" . format ( IiIIII1ii1Ii , input_interface , oOoOOOO , oo0O0O . timeout ) )
 if 88 - 88: Ii1I - OoO0O00 * OoooooooOO - I1IiiI * I1ii11iIi11i
 if 52 - 52: oO0o % iII111i - I1IiiI - o0oOOo0O0Ooo
 if 66 - 66: o0oOOo0O0Ooo - Oo0Ooo - OoooooooOO * o0oOOo0O0Ooo + I1Ii111
 if 82 - 82: I11i * i1IIi / Ii1I + O0
 if 85 - 85: O0 + oO0o / I1Ii111
 Ooooo = "learn%{}%{}" . format ( oo0oO , routed_interface )
 Ooooo = lisp_command_ipc ( Ooooo , "lisp-itr" )
 lisp_ipc ( Ooooo , lisp_ipc_listen_socket , "lisp-etr" )
 return
 if 65 - 65: o0oOOo0O0Ooo . Oo0Ooo . i1IIi / IiII . I11i . O0
 if 69 - 69: Oo0Ooo - i11iIiiIii
 if 87 - 87: Oo0Ooo % OOooOOo - Ii1I
 if 34 - 34: iII111i / Ii1I / I1IiiI * i11iIiiIii
 if 41 - 41: Ii1I / Oo0Ooo . OoO0O00 . iIii1I11I1II1 % IiII . I11i
 if 59 - 59: O0 + II111iiii + IiII % Oo0Ooo
 if 71 - 71: oO0o
 if 75 - 75: Oo0Ooo * oO0o + iIii1I11I1II1 / Oo0Ooo
 if 51 - 51: Ii1I * Ii1I + iII111i * oO0o / OOooOOo - ooOoO0o
 if 16 - 16: I1Ii111 + O0 - O0 * iIii1I11I1II1 / iII111i
 if 4 - 4: iII111i
 if 75 - 75: I1IiiI * IiII % OoO0O00 - ooOoO0o * iII111i
 if 32 - 32: iII111i
def lisp_retry_decap_keys ( addr_str , packet , iv , packet_icv ) :
 if ( lisp_search_decap_keys == False ) : return
 if 59 - 59: OoOoOO00 - I1Ii111
 if 34 - 34: ooOoO0o . OoooooooOO / ooOoO0o + OoooooooOO
 if 24 - 24: OoooooooOO * I1ii11iIi11i / O0 / Oo0Ooo * I1IiiI / ooOoO0o
 if 33 - 33: Ii1I
 if ( addr_str . find ( ":" ) != - 1 ) : return
 if 20 - 20: Ii1I + I11i
 O000000oO0O0O = lisp_crypto_keys_by_rloc_decap [ addr_str ]
 if 98 - 98: OOooOOo
 for i1iI11iI in lisp_crypto_keys_by_rloc_decap :
  if 58 - 58: i11iIiiIii / OoOoOO00
  if 18 - 18: ooOoO0o + O0 - OOooOOo + iIii1I11I1II1 . OOooOOo * iIii1I11I1II1
  if 83 - 83: OoO0O00 - Oo0Ooo * I1IiiI % Oo0Ooo % oO0o
  if 64 - 64: OoOoOO00 + oO0o / OoooooooOO . i11iIiiIii / II111iiii
  if ( i1iI11iI . find ( addr_str ) == - 1 ) : continue
  if 55 - 55: ooOoO0o . i11iIiiIii . o0oOOo0O0Ooo
  if 52 - 52: IiII . oO0o + i11iIiiIii % IiII
  if 45 - 45: i1IIi - I1IiiI / IiII - I1IiiI
  if 21 - 21: IiII
  if ( i1iI11iI == addr_str ) : continue
  if 43 - 43: IiII
  if 9 - 9: OOooOOo * ooOoO0o + ooOoO0o . I1Ii111
  if 8 - 8: IiII * iIii1I11I1II1
  if 7 - 7: I1Ii111 / OoooooooOO % O0 - I1ii11iIi11i
  iiIiiIi = lisp_crypto_keys_by_rloc_decap [ i1iI11iI ]
  if ( iiIiiIi == O000000oO0O0O ) : continue
  if 49 - 49: OoooooooOO . I1ii11iIi11i / OoooooooOO * oO0o
  if 81 - 81: I1ii11iIi11i . ooOoO0o + I1ii11iIi11i
  if 84 - 84: OoooooooOO
  if 95 - 95: o0oOOo0O0Ooo
  I1IIi = iiIiiIi [ 1 ]
  if ( packet_icv != I1IIi . do_icv ( packet , iv ) ) :
   lprint ( "Test ICV with key {} failed" . format ( red ( i1iI11iI , False ) ) )
   continue
   if 18 - 18: II111iiii + OOooOOo * i1IIi + i11iIiiIii
   if 61 - 61: i11iIiiIii + I1ii11iIi11i
  lprint ( "Changing decap crypto key to {}" . format ( red ( i1iI11iI , False ) ) )
  lisp_crypto_keys_by_rloc_decap [ addr_str ] = iiIiiIi
  if 5 - 5: Oo0Ooo
 return
 if 23 - 23: i11iIiiIii / I11i + i1IIi % I1Ii111
 if 100 - 100: Oo0Ooo
 if 13 - 13: I1IiiI + ooOoO0o * II111iiii
 if 32 - 32: iIii1I11I1II1 + O0 + i1IIi
 if 28 - 28: IiII + I11i
 if 1 - 1: OoooooooOO - i11iIiiIii . OoooooooOO - o0oOOo0O0Ooo - OOooOOo * I1Ii111
 if 56 - 56: Ii1I . OoO0O00
 if 43 - 43: iII111i * iII111i
def lisp_decent_pull_xtr_configured ( ) :
 return ( lisp_decent_modulus != 0 and lisp_decent_dns_suffix != None )
 if 31 - 31: O0 - iIii1I11I1II1 . I11i . oO0o
 if 96 - 96: OoooooooOO * iIii1I11I1II1 * Oo0Ooo
 if 76 - 76: OoO0O00 / i11iIiiIii % ooOoO0o % I11i * O0
 if 84 - 84: II111iiii - iII111i / IiII . O0 % i1IIi / I1ii11iIi11i
 if 2 - 2: OoooooooOO . OoO0O00 . II111iiii / Ii1I - OOooOOo % Oo0Ooo
 if 47 - 47: OOooOOo * oO0o
 if 41 - 41: OoooooooOO * I1IiiI
 if 3 - 3: IiII
def lisp_is_decent_dns_suffix ( dns_name ) :
 if ( lisp_decent_dns_suffix == None ) : return ( False )
 I1i1iI1II = dns_name . split ( "." )
 I1i1iI1II = "." . join ( I1i1iI1II [ 1 : : ] )
 return ( I1i1iI1II == lisp_decent_dns_suffix )
 if 96 - 96: I11i - OOooOOo + I11i
 if 71 - 71: Oo0Ooo
 if 48 - 48: o0oOOo0O0Ooo / II111iiii / OoOoOO00 * o0oOOo0O0Ooo + I1IiiI . OoOoOO00
 if 52 - 52: Ii1I / OoOoOO00 . OOooOOo * IiII . OoooooooOO
 if 6 - 6: i1IIi . oO0o % IiII . Oo0Ooo % I11i
 if 86 - 86: OoooooooOO + IiII % o0oOOo0O0Ooo . i1IIi . iII111i
 if 25 - 25: iII111i * I1ii11iIi11i + I11i - I1ii11iIi11i
def lisp_get_decent_index ( eid ) :
 oo0oO = eid . print_prefix ( )
 o0oOOo0O0oOo = hashlib . sha256 ( oo0oO ) . hexdigest ( )
 ii = int ( o0oOOo0O0oOo , 16 ) % lisp_decent_modulus
 return ( ii )
 if 8 - 8: i1IIi / I1ii11iIi11i * O0 . i11iIiiIii . oO0o * I1IiiI
 if 100 - 100: O0 / OOooOOo
 if 1 - 1: I1ii11iIi11i + iII111i
 if 61 - 61: oO0o - OOooOOo % II111iiii + IiII + O0 / o0oOOo0O0Ooo
 if 78 - 78: I11i
 if 32 - 32: II111iiii / II111iiii + o0oOOo0O0Ooo + OoooooooOO
 if 34 - 34: i11iIiiIii + iIii1I11I1II1 - i11iIiiIii * o0oOOo0O0Ooo - iII111i
def lisp_get_decent_dns_name ( eid ) :
 ii = lisp_get_decent_index ( eid )
 return ( str ( ii ) + "." + lisp_decent_dns_suffix )
 if 87 - 87: OOooOOo * OoO0O00
 if 61 - 61: iII111i - II111iiii . I1Ii111 % II111iiii / I11i
 if 86 - 86: II111iiii
 if 94 - 94: o0oOOo0O0Ooo % Ii1I * Ii1I % Oo0Ooo / I1ii11iIi11i
 if 40 - 40: Oo0Ooo . II111iiii / II111iiii - i1IIi
 if 91 - 91: Ii1I
 if 45 - 45: I1ii11iIi11i + Oo0Ooo
 if 72 - 72: I1ii11iIi11i
def lisp_get_decent_dns_name_from_str ( iid , eid_str ) :
 ii1Ii = lisp_address ( LISP_AFI_NONE , eid_str , 0 , iid )
 ii = lisp_get_decent_index ( ii1Ii )
 return ( str ( ii ) + "." + lisp_decent_dns_suffix )
 if 5 - 5: i1IIi
 if 31 - 31: iII111i - OoooooooOO + oO0o / OoooooooOO + I1ii11iIi11i
 if 93 - 93: o0oOOo0O0Ooo * I1ii11iIi11i % I1IiiI * ooOoO0o
 if 37 - 37: OoO0O00 * OoooooooOO / oO0o * I11i * I1ii11iIi11i
 if 42 - 42: OoooooooOO - ooOoO0o . OOooOOo + OoOoOO00
 if 53 - 53: o0oOOo0O0Ooo
 if 55 - 55: ooOoO0o . i1IIi - ooOoO0o + O0 + I1IiiI
 if 31 - 31: OoO0O00 % I1Ii111
 if 62 - 62: oO0o / O0 - I1Ii111 . IiII
 if 81 - 81: i11iIiiIii
def lisp_trace_append ( packet , reason = None , ed = "encap" , lisp_socket = None ,
 rloc_entry = None ) :
 if 57 - 57: O0
 oOo0 = 28 if packet . inner_version == 4 else 48
 OoOooOOoo = packet . packet [ oOo0 : : ]
 oooooOOOoO00 = lisp_trace ( )
 if ( oooooOOOoO00 . decode ( OoOooOOoo ) == False ) :
  lprint ( "Could not decode JSON portion of a LISP-Trace packet" )
  return ( False )
  if 4 - 4: I1ii11iIi11i * O0 / OoO0O00 * II111iiii . iIii1I11I1II1 / OOooOOo
  if 97 - 97: i1IIi - OoOoOO00 . OoooooooOO
 Ii11111 = "?" if packet . outer_dest . is_null ( ) else packet . outer_dest . print_address_no_iid ( )
 if 90 - 90: Ii1I - IiII . I1ii11iIi11i - oO0o
 if 53 - 53: OoooooooOO * Ii1I * iIii1I11I1II1
 if 85 - 85: OoOoOO00 - I11i * o0oOOo0O0Ooo
 if 45 - 45: ooOoO0o + I11i * O0
 if 30 - 30: I1ii11iIi11i + I1ii11iIi11i - OoO0O00 / OoO0O00 - iIii1I11I1II1
 if 80 - 80: OOooOOo . ooOoO0o + i1IIi * I1ii11iIi11i % O0
 if ( Ii11111 != "?" and packet . encap_port != LISP_DATA_PORT ) :
  if ( ed == "encap" ) : Ii11111 += ":{}" . format ( packet . encap_port )
  if 77 - 77: OoOoOO00 % II111iiii % I1Ii111 . i1IIi - I11i - I1IiiI
  if 95 - 95: OoOoOO00 + I1IiiI + iII111i
  if 15 - 15: Oo0Ooo - I1IiiI % OoO0O00 % iIii1I11I1II1 + O0 - II111iiii
  if 96 - 96: OoooooooOO
  if 1 - 1: oO0o * II111iiii + i1IIi * oO0o % I1IiiI
 iiIiiIi = { }
 iiIiiIi [ "node" ] = "ITR" if lisp_i_am_itr else "ETR" if lisp_i_am_etr else "RTR" if lisp_i_am_rtr else "?"
 if 53 - 53: i11iIiiIii . I1ii11iIi11i - OOooOOo - OOooOOo
 OO00ooo0oo = packet . outer_source
 if ( OO00ooo0oo . is_null ( ) ) : OO00ooo0oo = lisp_myrlocs [ 0 ]
 iiIiiIi [ "srloc" ] = OO00ooo0oo . print_address_no_iid ( )
 if 49 - 49: I1IiiI . o0oOOo0O0Ooo * i1IIi % IiII + I1Ii111
 if 59 - 59: iII111i - oO0o . ooOoO0o / IiII * i11iIiiIii
 if 61 - 61: I11i - Oo0Ooo * II111iiii + iIii1I11I1II1
 if 37 - 37: OoooooooOO % II111iiii / o0oOOo0O0Ooo . OOooOOo * I1ii11iIi11i . iIii1I11I1II1
 if 73 - 73: OoOoOO00
 if ( iiIiiIi [ "node" ] == "ITR" and packet . inner_sport != LISP_TRACE_PORT ) :
  iiIiiIi [ "srloc" ] += ":{}" . format ( packet . inner_sport )
  if 44 - 44: Oo0Ooo / oO0o
  if 9 - 9: i1IIi % I1IiiI + OoO0O00 * ooOoO0o / iIii1I11I1II1 / iII111i
 iiIiiIi [ "hn" ] = lisp_hostname
 i1iI11iI = ed + "-ts"
 iiIiiIi [ i1iI11iI ] = lisp_get_timestamp ( )
 if 80 - 80: OOooOOo / O0 % IiII * OoOoOO00
 if 53 - 53: OOooOOo + i11iIiiIii
 if 25 - 25: i11iIiiIii
 if 51 - 51: iII111i . ooOoO0o
 if 70 - 70: I11i / O0 - I11i + o0oOOo0O0Ooo . ooOoO0o . o0oOOo0O0Ooo
 if 6 - 6: I11i + II111iiii - I1Ii111
 if ( Ii11111 == "?" and iiIiiIi [ "node" ] == "ETR" ) :
  o0o0O0OO0oO = lisp_db_for_lookups . lookup_cache ( packet . inner_dest , False )
  if ( o0o0O0OO0oO != None and len ( o0o0O0OO0oO . rloc_set ) >= 1 ) :
   Ii11111 = o0o0O0OO0oO . rloc_set [ 0 ] . rloc . print_address_no_iid ( )
   if 45 - 45: i1IIi / iII111i + i11iIiiIii * I11i + ooOoO0o / OoooooooOO
   if 56 - 56: I11i + I1Ii111
 iiIiiIi [ "drloc" ] = Ii11111
 if 80 - 80: II111iiii . Ii1I + o0oOOo0O0Ooo / II111iiii / OoO0O00 + iIii1I11I1II1
 if 29 - 29: o0oOOo0O0Ooo + OoOoOO00 + ooOoO0o - I1ii11iIi11i
 if 64 - 64: O0 / OoooooooOO
 if 28 - 28: I1ii11iIi11i + oO0o . Oo0Ooo % iIii1I11I1II1 / I1Ii111
 if ( Ii11111 == "?" and reason != None ) :
  iiIiiIi [ "drloc" ] += " ({})" . format ( reason )
  if 8 - 8: O0 . I1IiiI * o0oOOo0O0Ooo + I1IiiI
  if 44 - 44: i1IIi % iII111i . i11iIiiIii / I11i + OoooooooOO
  if 21 - 21: OoOoOO00 . OoO0O00 . OoOoOO00 + OoOoOO00
  if 30 - 30: I1IiiI - iII111i - OOooOOo + oO0o
  if 51 - 51: Ii1I % O0 / II111iiii . Oo0Ooo
 if ( rloc_entry != None ) :
  iiIiiIi [ "rtts" ] = rloc_entry . recent_rloc_probe_rtts
  iiIiiIi [ "hops" ] = rloc_entry . recent_rloc_probe_hops
  if 90 - 90: i11iIiiIii * II111iiii % iIii1I11I1II1 . I1ii11iIi11i / Oo0Ooo . OOooOOo
  if 77 - 77: OoO0O00
  if 95 - 95: II111iiii
  if 59 - 59: iIii1I11I1II1 % OOooOOo / OoOoOO00 * I1Ii111 * OoooooooOO * O0
  if 43 - 43: OoO0O00 * I1IiiI * OOooOOo * O0 - O0 / o0oOOo0O0Ooo
  if 77 - 77: I11i % I1Ii111 . IiII % OoooooooOO * o0oOOo0O0Ooo
 IiIiiiiI1 = packet . inner_source . print_address ( )
 iIiiIi1i1I1I1 = packet . inner_dest . print_address ( )
 if ( oooooOOOoO00 . packet_json == [ ] ) :
  ii11I1 = { }
  ii11I1 [ "seid" ] = IiIiiiiI1
  ii11I1 [ "deid" ] = iIiiIi1i1I1I1
  ii11I1 [ "paths" ] = [ ]
  oooooOOOoO00 . packet_json . append ( ii11I1 )
  if 87 - 87: iII111i + IiII / ooOoO0o * ooOoO0o * OOooOOo
  if 97 - 97: I1Ii111
  if 47 - 47: iII111i / I1ii11iIi11i - Ii1I . II111iiii
  if 56 - 56: O0 - i1IIi % o0oOOo0O0Ooo + IiII
  if 42 - 42: o0oOOo0O0Ooo . OOooOOo % I11i - OoOoOO00
  if 38 - 38: OoooooooOO
 for ii11I1 in oooooOOOoO00 . packet_json :
  if ( ii11I1 [ "deid" ] != iIiiIi1i1I1I1 ) : continue
  ii11I1 [ "paths" ] . append ( iiIiiIi )
  break
  if 27 - 27: O0 + I1ii11iIi11i % Ii1I . i1IIi + OoO0O00 + OoOoOO00
  if 22 - 22: II111iiii / I1IiiI + o0oOOo0O0Ooo * I1IiiI . OoooooooOO * OOooOOo
  if 49 - 49: I1ii11iIi11i * I1IiiI + OOooOOo + i11iIiiIii * I1ii11iIi11i . o0oOOo0O0Ooo
  if 36 - 36: o0oOOo0O0Ooo - i11iIiiIii
  if 37 - 37: O0 + IiII + I1IiiI
  if 50 - 50: OoooooooOO . I1Ii111
  if 100 - 100: ooOoO0o * ooOoO0o - Ii1I
  if 13 - 13: iII111i . I11i * OoO0O00 . i1IIi . iIii1I11I1II1 - o0oOOo0O0Ooo
 O0oOOoO000 = False
 if ( len ( oooooOOOoO00 . packet_json ) == 1 and iiIiiIi [ "node" ] == "ETR" and
 oooooOOOoO00 . myeid ( packet . inner_dest ) ) :
  ii11I1 = { }
  ii11I1 [ "seid" ] = iIiiIi1i1I1I1
  ii11I1 [ "deid" ] = IiIiiiiI1
  ii11I1 [ "paths" ] = [ ]
  oooooOOOoO00 . packet_json . append ( ii11I1 )
  O0oOOoO000 = True
  if 30 - 30: IiII / i11iIiiIii
  if 79 - 79: Ii1I . IiII . oO0o * O0
  if 99 - 99: OOooOOo * iIii1I11I1II1 - iII111i / O0 % OoooooooOO + iIii1I11I1II1
  if 87 - 87: II111iiii * iIii1I11I1II1 - i11iIiiIii . Ii1I . Ii1I % OOooOOo
  if 27 - 27: o0oOOo0O0Ooo
  if 27 - 27: I1Ii111 % i1IIi
 oooooOOOoO00 . print_trace ( )
 OoOooOOoo = oooooOOOoO00 . encode ( )
 if 93 - 93: I1Ii111 / o0oOOo0O0Ooo
 if 33 - 33: OOooOOo * IiII * OoO0O00 - I1ii11iIi11i % OoO0O00
 if 16 - 16: OoO0O00 * I1IiiI
 if 58 - 58: oO0o * II111iiii * O0
 if 89 - 89: I1Ii111 + IiII % I1ii11iIi11i
 if 80 - 80: Oo0Ooo + ooOoO0o + IiII
 if 76 - 76: I1Ii111
 if 23 - 23: O0 % I1ii11iIi11i % iIii1I11I1II1
 i111IIiooOooooO0ooO = oooooOOOoO00 . packet_json [ 0 ] [ "paths" ] [ 0 ] [ "srloc" ]
 if ( Ii11111 == "?" ) :
  lprint ( "LISP-Trace return to sender RLOC {}" . format ( i111IIiooOooooO0ooO ) )
  oooooOOOoO00 . return_to_sender ( lisp_socket , i111IIiooOooooO0ooO , OoOooOOoo )
  return ( False )
  if 61 - 61: ooOoO0o - OOooOOo
  if 45 - 45: O0 . OoO0O00
  if 80 - 80: IiII + OoO0O00
  if 2 - 2: IiII + OoOoOO00 % oO0o
  if 76 - 76: o0oOOo0O0Ooo
  if 25 - 25: OoooooooOO
 i1IiiiiiIiII = oooooOOOoO00 . packet_length ( )
 if 78 - 78: oO0o / i11iIiiIii * O0 / OOooOOo % i11iIiiIii % O0
 if 86 - 86: IiII
 if 26 - 26: IiII - I1Ii111 + i11iIiiIii % ooOoO0o * i11iIiiIii + Oo0Ooo
 if 39 - 39: Ii1I - i1IIi + i11iIiiIii
 if 21 - 21: IiII
 if 76 - 76: o0oOOo0O0Ooo % Oo0Ooo + OoO0O00
 i1I = packet . packet [ 0 : oOo0 ]
 IiIiI1 = struct . pack ( "HH" , socket . htons ( i1IiiiiiIiII ) , 0 )
 i1I = i1I [ 0 : oOo0 - 4 ] + IiIiI1
 if ( packet . inner_version == 6 and iiIiiIi [ "node" ] == "ETR" and
 len ( oooooOOOoO00 . packet_json ) == 2 ) :
  i1iIIII1iiIIi = i1I [ oOo0 - 8 : : ] + OoOooOOoo
  i1iIIII1iiIIi = lisp_udp_checksum ( IiIiiiiI1 , iIiiIi1i1I1I1 , i1iIIII1iiIIi )
  i1I = i1I [ 0 : oOo0 - 8 ] + i1iIIII1iiIIi [ 0 : 8 ]
  if 15 - 15: I1IiiI + ooOoO0o - o0oOOo0O0Ooo
  if 62 - 62: Ii1I - OOooOOo
  if 88 - 88: iIii1I11I1II1 * Oo0Ooo / II111iiii / IiII / OoO0O00 % ooOoO0o
  if 19 - 19: I11i * iII111i . O0 * iII111i % I1ii11iIi11i - OoOoOO00
  if 68 - 68: I1Ii111 - OoO0O00 % Ii1I + i1IIi . ooOoO0o
  if 36 - 36: oO0o * iIii1I11I1II1 - O0 - IiII * O0 + i11iIiiIii
 if ( O0oOOoO000 ) :
  if ( packet . inner_version == 4 ) :
   i1I = i1I [ 0 : 12 ] + i1I [ 16 : 20 ] + i1I [ 12 : 16 ] + i1I [ 22 : 24 ] + i1I [ 20 : 22 ] + i1I [ 24 : : ]
   if 76 - 76: OoO0O00 % O0 / Ii1I + I1IiiI
  else :
   i1I = i1I [ 0 : 8 ] + i1I [ 24 : 40 ] + i1I [ 8 : 24 ] + i1I [ 42 : 44 ] + i1I [ 40 : 42 ] + i1I [ 44 : : ]
   if 23 - 23: I1IiiI % IiII . o0oOOo0O0Ooo
   if 2 - 2: I1ii11iIi11i
  oOOoO0O = packet . inner_dest
  packet . inner_dest = packet . inner_source
  packet . inner_source = oOOoO0O
  if 51 - 51: iIii1I11I1II1 / II111iiii / iIii1I11I1II1 / oO0o % i1IIi
  if 54 - 54: ooOoO0o
  if 47 - 47: I11i * I1IiiI / oO0o
  if 98 - 98: Ii1I / oO0o * O0 + I1Ii111 - I1Ii111 + iII111i
  if 4 - 4: i1IIi
 oOo0 = 2 if packet . inner_version == 4 else 4
 iII111iiI1iI = 20 + i1IiiiiiIiII if packet . inner_version == 4 else i1IiiiiiIiII
 iiII = struct . pack ( "H" , socket . htons ( iII111iiI1iI ) )
 i1I = i1I [ 0 : oOo0 ] + iiII + i1I [ oOo0 + 2 : : ]
 if 68 - 68: OOooOOo
 if 99 - 99: OoooooooOO
 if 2 - 2: Oo0Ooo + iIii1I11I1II1 - II111iiii % OoOoOO00 / i11iIiiIii
 if 6 - 6: oO0o + iII111i * i1IIi * i11iIiiIii
 if ( packet . inner_version == 4 ) :
  oOoooO0oo0 = struct . pack ( "H" , 0 )
  i1I = i1I [ 0 : 10 ] + oOoooO0oo0 + i1I [ 12 : : ]
  iiII = lisp_ip_checksum ( i1I [ 0 : 20 ] )
  i1I = iiII + i1I [ 20 : : ]
  if 10 - 10: IiII / i1IIi . OoOoOO00 . Oo0Ooo
  if 21 - 21: oO0o
  if 41 - 41: oO0o . O0 * Oo0Ooo - o0oOOo0O0Ooo * ooOoO0o + OoOoOO00
  if 40 - 40: I1Ii111
  if 58 - 58: oO0o . OoO0O00 / ooOoO0o
 packet . packet = i1I + OoOooOOoo
 return ( True )
 if 61 - 61: I11i + I1Ii111
 if 27 - 27: ooOoO0o / i1IIi . oO0o - OoooooooOO
 if 48 - 48: ooOoO0o % ooOoO0o / OoooooooOO + i1IIi * oO0o + ooOoO0o
 if 69 - 69: iII111i . iII111i
 if 46 - 46: IiII * Oo0Ooo + I1Ii111
 if 79 - 79: IiII
 if 89 - 89: IiII * I11i + I1ii11iIi11i * oO0o - II111iiii
 if 58 - 58: ooOoO0o . I1Ii111 / i1IIi % I1ii11iIi11i + o0oOOo0O0Ooo
 if 94 - 94: i11iIiiIii + I1Ii111 . iII111i - ooOoO0o % I1Ii111
 if 94 - 94: i11iIiiIii - OOooOOo - O0 * OoooooooOO - ooOoO0o
def lisp_allow_gleaning ( eid , rloc ) :
 if ( lisp_glean_mappings == [ ] ) : return ( False , False )
 if 35 - 35: iII111i . i11iIiiIii - OOooOOo % Oo0Ooo + Ii1I . iIii1I11I1II1
 for iiIiiIi in lisp_glean_mappings :
  if ( iiIiiIi . has_key ( "instance-id" ) ) :
   OO0OO000 = eid . instance_id
   IiIIIIi1 , ii1iiII = iiIiiIi [ "instance-id" ]
   if ( OO0OO000 < IiIIIIi1 or OO0OO000 > ii1iiII ) : continue
   if 91 - 91: o0oOOo0O0Ooo / OoO0O00 + I1IiiI % i11iIiiIii % i1IIi
  if ( iiIiiIi . has_key ( "eid-prefix" ) ) :
   o0o000 = copy . deepcopy ( iiIiiIi [ "eid-prefix" ] )
   o0o000 . instance_id = eid . instance_id
   if ( eid . is_more_specific ( o0o000 ) == False ) : continue
   if 22 - 22: I1Ii111 * O0 % OoO0O00 * I1ii11iIi11i
  if ( iiIiiIi . has_key ( "rloc-prefix" ) ) :
   if ( rloc != None and rloc . is_more_specific ( iiIiiIi [ "rloc-prefix" ] )
 == False ) : continue
   if 47 - 47: OoO0O00 / OOooOOo / OoOoOO00 % i11iIiiIii / OoOoOO00
  return ( True , iiIiiIi [ "rloc-probe" ] )
  if 52 - 52: ooOoO0o / I11i % i11iIiiIii - I1Ii111 % ooOoO0o - o0oOOo0O0Ooo
 return ( False , False )
 if 67 - 67: OoOoOO00 / I1Ii111 + i11iIiiIii - IiII
 if 79 - 79: I11i . I11i - OoOoOO00
 if 86 - 86: OoO0O00 * Oo0Ooo . iIii1I11I1II1 * O0
 if 52 - 52: iII111i - i11iIiiIii + o0oOOo0O0Ooo + i1IIi
 if 58 - 58: OOooOOo - Ii1I * I1Ii111 - O0 . oO0o
 if 72 - 72: i1IIi * iII111i * Ii1I / o0oOOo0O0Ooo . I1Ii111 + i11iIiiIii
 if 33 - 33: I11i / OoO0O00 * ooOoO0o + iIii1I11I1II1
def lisp_build_gleaned_multicast ( seid , geid , rloc , port ) :
 if 54 - 54: Oo0Ooo / IiII + i11iIiiIii . O0
 if 94 - 94: OoooooooOO + iII111i * OoooooooOO / o0oOOo0O0Ooo
 if 12 - 12: iIii1I11I1II1 / iIii1I11I1II1 / II111iiii
 if 93 - 93: oO0o
 OoOOO000O0o = lisp_map_cache_lookup ( seid , geid )
 if ( OoOOO000O0o == None ) :
  OoOOO000O0o = lisp_mapping ( "" , "" , [ ] )
  OoOOO000O0o . group . copy_address ( geid )
  OoOOO000O0o . eid . copy_address ( geid )
  OoOOO000O0o . eid . address = 0
  OoOOO000O0o . eid . mask_len = 0
  OoOOO000O0o . mapping_source . copy_address ( rloc )
  OoOOO000O0o . map_cache_ttl = LISP_IGMP_TTL
  OoOOO000O0o . gleaned = True
  o0o000 = green ( "(*, {})" . format ( geid . print_address ( ) ) , False )
  IIi = red ( rloc . print_address_no_iid ( ) + ":" + str ( port ) , False )
  lprint ( "Add gleaned EID {} to map-cache with RLE {}" . format ( o0o000 , IIi ) )
  OoOOO000O0o . add_cache ( )
  if 53 - 53: OoO0O00 * i1IIi / Oo0Ooo / OoO0O00 * ooOoO0o
  if 77 - 77: iIii1I11I1II1 % I1IiiI + o0oOOo0O0Ooo + I1Ii111 * Oo0Ooo * i1IIi
  if 14 - 14: iIii1I11I1II1 * iIii1I11I1II1 - OOooOOo . iII111i / ooOoO0o
  if 54 - 54: OoOoOO00 - I1IiiI - iII111i
  if 49 - 49: i11iIiiIii * Oo0Ooo
  if 100 - 100: Oo0Ooo * oO0o
 OoooO00OO = OoI1i = I11iI = None
 if ( OoOOO000O0o . rloc_set != [ ] ) :
  OoooO00OO = OoOOO000O0o . rloc_set [ 0 ]
  if ( OoooO00OO . rle ) :
   OoI1i = OoooO00OO . rle
   for OoOOOOoOO000 in OoI1i . rle_nodes :
    if ( OoOOOOoOO000 . address . is_exact_match ( rloc ) == False ) : continue
    I11iI = OoOOOOoOO000
    break
    if 87 - 87: I1Ii111 - iII111i / Ii1I
    if 73 - 73: I1IiiI + OoOoOO00 - oO0o
    if 32 - 32: Oo0Ooo % iII111i % I1IiiI
    if 85 - 85: OoO0O00 - Ii1I / O0
    if 45 - 45: IiII + I1Ii111 / I11i
    if 84 - 84: iII111i % II111iiii
    if 86 - 86: IiII % II111iiii / i1IIi * I1ii11iIi11i - O0 * OOooOOo
 if ( OoooO00OO == None ) :
  OoooO00OO = lisp_rloc ( )
  OoOOO000O0o . rloc_set = [ OoooO00OO ]
  OoooO00OO . priority = 253
  OoooO00OO . mpriority = 255
  OoOOO000O0o . build_best_rloc_set ( )
  if 53 - 53: OOooOOo * oO0o + i1IIi % Oo0Ooo + II111iiii
 if ( OoI1i == None ) :
  OoI1i = lisp_rle ( geid . print_address ( ) )
  OoooO00OO . rle = OoI1i
  if 34 - 34: oO0o % iII111i / IiII . IiII + i11iIiiIii
 if ( I11iI == None ) :
  I11iI = lisp_rle_node ( )
  I11iI . rloc_name = seid . print_address_no_iid ( )
  OoI1i . rle_nodes . append ( I11iI )
  OoI1i . build_forwarding_list ( )
  if 68 - 68: O0 % oO0o * IiII % O0
  if 55 - 55: O0 % I1IiiI % O0
  if 27 - 27: I1IiiI + I1ii11iIi11i * I1Ii111 % Ii1I - Oo0Ooo
  if 87 - 87: i11iIiiIii % OOooOOo - OoOoOO00 * ooOoO0o / Oo0Ooo
  if 74 - 74: OoooooooOO * ooOoO0o - I11i / I1ii11iIi11i % iIii1I11I1II1
 I11iI . store_translated_rloc ( rloc , port )
 o0o000 = green ( "(*, {})" . format ( geid . print_address ( ) ) , False )
 IIi = red ( rloc . print_address_no_iid ( ) + ":" + str ( port ) , False )
 lprint ( "Gleaned EID {} RLE changed to {}" . format ( o0o000 , IIi ) )
 if 94 - 94: Ii1I * I1Ii111 + OoOoOO00 . iIii1I11I1II1
 if 44 - 44: Oo0Ooo . Oo0Ooo * Oo0Ooo
 if 23 - 23: I1Ii111 / iII111i . O0 % II111iiii
 if 67 - 67: I11i / iIii1I11I1II1 / ooOoO0o
 if 90 - 90: II111iiii % I1Ii111 - IiII . Oo0Ooo % OOooOOo - OoOoOO00
 if 89 - 89: Oo0Ooo - I1ii11iIi11i . I1Ii111
 if 65 - 65: ooOoO0o % OOooOOo + OOooOOo % I1Ii111 . I1IiiI % O0
def lisp_remove_gleaned_multicast ( seid , geid , rloc , port ) :
 if 46 - 46: OoO0O00 * I1Ii111 + iII111i . oO0o % OOooOOo / i11iIiiIii
 if 1 - 1: I1ii11iIi11i % O0 - I1ii11iIi11i / OoooooooOO / OoO0O00
 if 82 - 82: i1IIi % Ii1I
 if 85 - 85: I1Ii111 * i11iIiiIii * iIii1I11I1II1 % iIii1I11I1II1
 OoOOO000O0o = lisp_map_cache_lookup ( seid , geid )
 if ( OoOOO000O0o == None ) : return
 if 64 - 64: OoO0O00 / Ii1I
 O000o0 = OoOOO000O0o . rloc_set [ 0 ] . rle
 if ( O000o0 == None ) : return
 if 79 - 79: Ii1I % OOooOOo
 ooOO0OOO = seid . print_address_no_iid ( )
 iiIiI1 = False
 for I11iI in O000o0 . rle_nodes :
  if ( I11iI . rloc_name == ooOO0OOO ) :
   iiIiI1 = True
   break
   if 39 - 39: I1ii11iIi11i / Ii1I - II111iiii . i1IIi
   if 59 - 59: II111iiii
 if ( iiIiI1 == False ) : return
 if 36 - 36: ooOoO0o . II111iiii - OoOoOO00 % I1ii11iIi11i * O0
 if 91 - 91: iII111i + Oo0Ooo / OoooooooOO * iIii1I11I1II1 - OoO0O00
 if 73 - 73: iIii1I11I1II1 % I1Ii111 % II111iiii * Oo0Ooo * OoO0O00
 if 48 - 48: OOooOOo * i11iIiiIii - i11iIiiIii + iIii1I11I1II1 + I1IiiI % OoooooooOO
 O000o0 . rle_nodes . remove ( I11iI )
 O000o0 . build_forwarding_list ( )
 if 61 - 61: i1IIi
 o0o000 = green ( "(*, {})" . format ( geid . print_address ( ) ) , False )
 IIi = red ( rloc . print_address_no_iid ( ) + ":" + str ( port ) , False )
 lprint ( "Gleaned EID {} RLE {} removed" . format ( o0o000 , IIi ) )
 if 56 - 56: iIii1I11I1II1 / I11i * iII111i * I11i * OoooooooOO
 if 44 - 44: I1ii11iIi11i - OOooOOo % I11i - I1Ii111 / iIii1I11I1II1 - OOooOOo
 if 38 - 38: iIii1I11I1II1 - OoooooooOO * II111iiii . OoooooooOO + OOooOOo
 if 59 - 59: OoooooooOO
 if ( O000o0 . rle_nodes == [ ] ) :
  OoOOO000O0o . delete_cache ( )
  lprint ( "Gleaned EID {} removed, no more RLEs" . format ( o0o000 , IIi ) )
  if 22 - 22: II111iiii
  if 85 - 85: I1Ii111 + I1ii11iIi11i * I11i % o0oOOo0O0Ooo + Ii1I
  if 23 - 23: IiII * OoO0O00
  if 42 - 42: IiII
  if 83 - 83: i1IIi * o0oOOo0O0Ooo / OoO0O00 / o0oOOo0O0Ooo
  if 55 - 55: Oo0Ooo % O0 - OoO0O00
  if 42 - 42: OoooooooOO * OOooOOo
  if 93 - 93: OOooOOo + II111iiii . oO0o * Oo0Ooo - O0 + I1Ii111
  if 99 - 99: OoO0O00 * o0oOOo0O0Ooo + OoOoOO00 * iIii1I11I1II1
  if 38 - 38: I1ii11iIi11i - OOooOOo * O0 - I1ii11iIi11i
  if 95 - 95: OoO0O00 . oO0o . OoooooooOO - iIii1I11I1II1
  if 35 - 35: o0oOOo0O0Ooo / OoooooooOO - i1IIi * iIii1I11I1II1 + ooOoO0o
  if 66 - 66: Oo0Ooo - OoOoOO00 . I1Ii111 + O0 + o0oOOo0O0Ooo
  if 36 - 36: II111iiii % IiII . i11iIiiIii
  if 88 - 88: Oo0Ooo . IiII * Oo0Ooo
  if 92 - 92: I1IiiI % IiII
  if 95 - 95: OoooooooOO / OoO0O00 % O0 / I1Ii111 * Ii1I + I1ii11iIi11i
  if 7 - 7: ooOoO0o
  if 83 - 83: oO0o / I1Ii111 + I1Ii111 * I1ii11iIi11i
  if 8 - 8: I11i . I1ii11iIi11i % i1IIi + Ii1I
  if 63 - 63: I1IiiI / OoooooooOO
  if 16 - 16: OoOoOO00
  if 67 - 67: O0 . I1Ii111
  if 42 - 42: OoOoOO00 % I1ii11iIi11i * I1Ii111 * i1IIi . i1IIi % OOooOOo
  if 90 - 90: oO0o * Oo0Ooo * oO0o . Ii1I * i1IIi
  if 47 - 47: OOooOOo
  if 38 - 38: I11i
  if 15 - 15: OoO0O00 / ooOoO0o . OoO0O00 - iIii1I11I1II1 + OoooooooOO - OoO0O00
  if 44 - 44: O0 . OOooOOo . o0oOOo0O0Ooo . I1ii11iIi11i - II111iiii
  if 71 - 71: I1ii11iIi11i + o0oOOo0O0Ooo . i11iIiiIii * oO0o . i1IIi
  if 40 - 40: OoO0O00 - IiII
  if 43 - 43: I1Ii111 + i11iIiiIii % iII111i % I1Ii111 - ooOoO0o
  if 85 - 85: IiII % iIii1I11I1II1 . I1Ii111
  if 38 - 38: iII111i - I1IiiI / ooOoO0o
  if 46 - 46: OOooOOo . O0 / i11iIiiIii . OOooOOo
  if 19 - 19: I11i / Oo0Ooo + I1Ii111
  if 43 - 43: I1ii11iIi11i
  if 18 - 18: I11i / OOooOOo % I11i - o0oOOo0O0Ooo
  if 22 - 22: iII111i
  if 88 - 88: I11i + OoOoOO00 % IiII % OoO0O00 * O0 / OoooooooOO
  if 83 - 83: IiII + I1Ii111 . I1ii11iIi11i * iIii1I11I1II1
  if 9 - 9: ooOoO0o % IiII - OoOoOO00
  if 66 - 66: oO0o % Oo0Ooo
  if 40 - 40: i11iIiiIii . O0 * I11i - oO0o / OOooOOo . oO0o
  if 86 - 86: OOooOOo - I1Ii111 * IiII - i1IIi + ooOoO0o + I11i
  if 32 - 32: IiII
  if 99 - 99: II111iiii
  if 34 - 34: OOooOOo + OoOoOO00 * o0oOOo0O0Ooo + I1ii11iIi11i + IiII * i1IIi
  if 73 - 73: I1ii11iIi11i - IiII - O0 . oO0o + Oo0Ooo % iII111i
  if 68 - 68: I1ii11iIi11i - OoooooooOO
  if 5 - 5: I1ii11iIi11i * I1IiiI + OoooooooOO / Oo0Ooo
  if 18 - 18: OoO0O00 * iII111i % I1IiiI . OOooOOo * o0oOOo0O0Ooo
  if 58 - 58: iII111i . IiII + iIii1I11I1II1
  if 13 - 13: oO0o * I1Ii111 / I1Ii111 . I1IiiI
  if 93 - 93: I11i % OoOoOO00 - OOooOOo + iIii1I11I1II1 / OoooooooOO % i11iIiiIii
  if 90 - 90: oO0o % iIii1I11I1II1 + o0oOOo0O0Ooo - I11i / i11iIiiIii
  if 57 - 57: I1IiiI . Oo0Ooo / I1IiiI / II111iiii - I1Ii111
  if 68 - 68: I1IiiI
  if 97 - 97: Ii1I + o0oOOo0O0Ooo / OoO0O00
  if 97 - 97: i11iIiiIii % iIii1I11I1II1 + II111iiii
  if 90 - 90: OOooOOo / I1IiiI
  if 28 - 28: OoooooooOO + i1IIi
  if 29 - 29: Oo0Ooo
  if 98 - 98: OOooOOo / Oo0Ooo % Ii1I * OoooooooOO - oO0o
  if 64 - 64: I1IiiI - I1IiiI
  if 90 - 90: iII111i - I1IiiI - II111iiii / OOooOOo + Ii1I
  if 34 - 34: i11iIiiIii + I1Ii111 / O0 / iIii1I11I1II1 * OoooooooOO % Ii1I
  if 32 - 32: i11iIiiIii - OoOoOO00 / iIii1I11I1II1 * o0oOOo0O0Ooo % I1IiiI + O0
  if 36 - 36: I1ii11iIi11i + I1ii11iIi11i % I1Ii111 * ooOoO0o * OoOoOO00
  if 54 - 54: Oo0Ooo - I1IiiI % OOooOOo . I1ii11iIi11i / I1IiiI
  if 75 - 75: OOooOOo - O0 % iII111i . Ii1I % I1ii11iIi11i + I1ii11iIi11i
  if 32 - 32: Ii1I + II111iiii * IiII
  if 9 - 9: I1Ii111
  if 96 - 96: I1Ii111 / iIii1I11I1II1
  if 48 - 48: iII111i * IiII + OoooooooOO
  if 63 - 63: I1IiiI / Ii1I
  if 31 - 31: i1IIi - oO0o
igmp_types = { 17 : "IGMP-query" , 18 : "IGMPv1-report" , 19 : "DVMRP" ,
 20 : "PIMv1" , 22 : "IGMPv2-report" , 23 : "IGMPv2-leave" ,
 30 : "mtrace-response" , 31 : "mtrace-request" , 34 : "IGMPv3-report" }
if 99 - 99: iII111i - i11iIiiIii + oO0o
lisp_igmp_record_types = { 1 : "include-mode" , 2 : "exclude-mode" ,
 3 : "change-to-include" , 4 : "change-to-exclude" , 5 : "allow-new-source" ,
 6 : "block-old-sources" }
if 66 - 66: Oo0Ooo * I11i . iIii1I11I1II1 - OoO0O00
def lisp_process_igmp_packet ( packet ) :
 IIi = bold ( "Receive" , False )
 lprint ( "{} {}-byte IGMP packet: {}" . format ( IIi , len ( packet ) ,
 lisp_format_packet ( packet ) ) )
 if 11 - 11: I1Ii111 + iIii1I11I1II1 * O0 * Oo0Ooo
 if 66 - 66: OoooooooOO % OoO0O00 + i11iIiiIii + I1Ii111 % OoO0O00
 if 80 - 80: Oo0Ooo - Ii1I
 if 54 - 54: O0 - iIii1I11I1II1 . OoO0O00 . IiII % OoO0O00
 Ii1iiIiIIi1 = ( struct . unpack ( "B" , packet [ 0 ] ) [ 0 ] & 0x0f ) * 4
 if 50 - 50: o0oOOo0O0Ooo + iII111i / i1IIi % II111iiii
 if 61 - 61: IiII
 if 5 - 5: OOooOOo % iIii1I11I1II1 % O0 * i11iIiiIii / I1Ii111
 if 48 - 48: IiII * oO0o
 oooo00000O0o0 = packet [ Ii1iiIiIIi1 : : ]
 I1IIi1iI = struct . unpack ( "B" , oooo00000O0o0 [ 0 ] ) [ 0 ]
 IiI1111i1i11I = lisp_address ( LISP_AFI_IPV4 , "" , 32 , 0 )
 if 80 - 80: I11i
 Oo0Oo0oOO = ( I1IIi1iI in ( 0x12 , 0x16 , 0x17 , 0x22 ) )
 if ( Oo0Oo0oOO == False ) :
  oO0O0o0OO0oo = "{} ({})" . format ( I1IIi1iI , igmp_types [ I1IIi1iI ] ) if igmp_types . has_key ( I1IIi1iI ) else I1IIi1iI
  if 4 - 4: ooOoO0o
  lprint ( "IGMP type {} not supported" . format ( oO0O0o0OO0oo ) )
  return ( [ ] )
  if 37 - 37: IiII + IiII
  if 98 - 98: OoooooooOO + II111iiii / iII111i + i11iIiiIii / OoooooooOO * ooOoO0o
 if ( len ( oooo00000O0o0 ) < 8 ) :
  lprint ( "IGMP message too small" )
  return ( [ ] )
  if 74 - 74: I1ii11iIi11i - IiII
  if 16 - 16: OOooOOo % I11i
  if 18 - 18: Ii1I
  if 48 - 48: Ii1I + iII111i
  if 1 - 1: oO0o - i1IIi + OoooooooOO - Oo0Ooo
  if 4 - 4: II111iiii . OOooOOo - Ii1I - i11iIiiIii
 IiI1111i1i11I . address = socket . ntohl ( struct . unpack ( "II" , oooo00000O0o0 [ : 8 ] ) [ 1 ] )
 o0oO0Oo = IiI1111i1i11I . print_address_no_iid ( )
 if 27 - 27: iII111i * iII111i - OoO0O00 % o0oOOo0O0Ooo . o0oOOo0O0Ooo
 if 64 - 64: I1ii11iIi11i * ooOoO0o - OoooooooOO - I1IiiI
 if 59 - 59: I1ii11iIi11i . I1Ii111 - OOooOOo / Oo0Ooo + OOooOOo . I1ii11iIi11i
 if 69 - 69: Oo0Ooo
 if ( I1IIi1iI == 0x17 ) :
  lprint ( "IGMPv2 leave (*, {})" . format ( bold ( o0oO0Oo , False ) ) )
  return ( [ [ None , o0oO0Oo , False ] ] )
  if 34 - 34: I1Ii111 - ooOoO0o . o0oOOo0O0Ooo
 if ( I1IIi1iI in ( 0x12 , 0x16 ) ) :
  lprint ( "IGMPv{} join (*, {})" . format ( 1 if ( I1IIi1iI == 0x12 ) else 2 , bold ( o0oO0Oo , False ) ) )
  if 52 - 52: o0oOOo0O0Ooo % I11i * I11i / iIii1I11I1II1
  if 77 - 77: OoOoOO00
  if 67 - 67: OoooooooOO / OoooooooOO + IiII - ooOoO0o
  if 72 - 72: Ii1I
  if 21 - 21: ooOoO0o + iII111i
  if ( o0oO0Oo . find ( "224.0.0." ) != - 1 ) :
   lprint ( "Suppress registration for link-local groups" )
  else :
   return ( [ [ None , o0oO0Oo , True ] ] )
   if 39 - 39: o0oOOo0O0Ooo % I1Ii111 - o0oOOo0O0Ooo % Oo0Ooo
   if 78 - 78: OoO0O00 / o0oOOo0O0Ooo / O0 % OOooOOo % i1IIi
   if 78 - 78: o0oOOo0O0Ooo - oO0o . II111iiii
   if 67 - 67: iII111i + I11i - OoO0O00 . OOooOOo * iIii1I11I1II1
   if 44 - 44: OoooooooOO * i1IIi % i1IIi - i11iIiiIii % OOooOOo - OoO0O00
  return ( [ ] )
  if 62 - 62: OOooOOo + OoooooooOO / I1Ii111 % iIii1I11I1II1
  if 59 - 59: i11iIiiIii . IiII
  if 91 - 91: Oo0Ooo / iII111i + I1Ii111
  if 32 - 32: i1IIi - iII111i + o0oOOo0O0Ooo * I1Ii111 % I1ii11iIi11i / i11iIiiIii
  if 91 - 91: IiII / OoooooooOO . OoooooooOO + OoooooooOO * I1ii11iIi11i . OoOoOO00
 OooOooOO0000 = IiI1111i1i11I . address
 oooo00000O0o0 = oooo00000O0o0 [ 8 : : ]
 if 22 - 22: iIii1I11I1II1 - OoO0O00
 OoO0OO0 = "BBHI"
 oo0OO = struct . calcsize ( OoO0OO0 )
 OoiiiiI111II = "I"
 Ii11II1IIi = struct . calcsize ( OoiiiiI111II )
 OO = lisp_address ( LISP_AFI_IPV4 , "" , 32 , 0 )
 if 13 - 13: i1IIi / IiII / I11i - OOooOOo
 if 5 - 5: I11i . I11i * II111iiii * Oo0Ooo + Ii1I
 if 67 - 67: ooOoO0o % OoOoOO00
 if 43 - 43: iIii1I11I1II1 . Ii1I
 ooo00oOo0OO0O = [ ]
 for o0OoO00 in range ( OooOooOO0000 ) :
  if ( len ( oooo00000O0o0 ) < oo0OO ) : return
  IiI111IIiiIII , IiIIi , iiIIi1I1I1ii , I1Ii1iIIIIi = struct . unpack ( OoO0OO0 ,
 oooo00000O0o0 [ : oo0OO ] )
  if 4 - 4: OOooOOo % oO0o
  oooo00000O0o0 = oooo00000O0o0 [ oo0OO : : ]
  if 18 - 18: Ii1I * I11i
  if ( lisp_igmp_record_types . has_key ( IiI111IIiiIII ) == False ) :
   lprint ( "Invalid record type {}" . format ( IiI111IIiiIII ) )
   continue
   if 14 - 14: ooOoO0o . ooOoO0o * OoOoOO00 * o0oOOo0O0Ooo - iII111i - I1Ii111
   if 53 - 53: Oo0Ooo * OoOoOO00 * II111iiii % IiII - I1ii11iIi11i
  OOOooo0 = lisp_igmp_record_types [ IiI111IIiiIII ]
  iiIIi1I1I1ii = socket . ntohs ( iiIIi1I1I1ii )
  IiI1111i1i11I . address = socket . ntohl ( I1Ii1iIIIIi )
  o0oO0Oo = IiI1111i1i11I . print_address_no_iid ( )
  if 28 - 28: OoooooooOO + I1IiiI / oO0o . iIii1I11I1II1 - oO0o
  lprint ( "Record type: {}, group: {}, source-count: {}" . format ( OOOooo0 , o0oO0Oo , iiIIi1I1I1ii ) )
  if 64 - 64: I1Ii111 + Oo0Ooo / iII111i
  if 61 - 61: Ii1I * Ii1I . OoOoOO00 + OoO0O00 * i11iIiiIii * OoO0O00
  if 4 - 4: OoooooooOO % iII111i % Oo0Ooo * IiII % o0oOOo0O0Ooo . o0oOOo0O0Ooo
  if 66 - 66: I1IiiI . Oo0Ooo - oO0o
  if 53 - 53: oO0o / Ii1I + oO0o + II111iiii
  if 70 - 70: OoooooooOO - I1Ii111 + OoOoOO00
  if 61 - 61: I1IiiI * I1Ii111 * i11iIiiIii
  oOO0oO0O0 = False
  if ( IiI111IIiiIII in ( 1 , 5 ) ) : oOO0oO0O0 = True
  if ( IiI111IIiiIII == 4 and iiIIi1I1I1ii == 0 ) : oOO0oO0O0 = True
  Ii1IIii1i1i1i1I = "join" if ( oOO0oO0O0 ) else "leave"
  if 29 - 29: II111iiii * oO0o - iIii1I11I1II1 / II111iiii % IiII - i11iIiiIii
  if 3 - 3: i11iIiiIii - o0oOOo0O0Ooo / oO0o . OoO0O00 * I11i + o0oOOo0O0Ooo
  if 18 - 18: OoooooooOO % oO0o / IiII - ooOoO0o
  if 80 - 80: I11i
  if ( o0oO0Oo . find ( "224.0.0." ) != - 1 ) :
   lprint ( "Suppress registration for link-local groups" )
   continue
   if 98 - 98: iII111i / I1ii11iIi11i
   if 87 - 87: iII111i - O0 * ooOoO0o / II111iiii % OoooooooOO . o0oOOo0O0Ooo
   if 55 - 55: OOooOOo - o0oOOo0O0Ooo * I1IiiI / o0oOOo0O0Ooo + I1Ii111 + iIii1I11I1II1
   if 3 - 3: II111iiii % iII111i / IiII * ooOoO0o . OoooooooOO
   if 56 - 56: IiII * II111iiii + Oo0Ooo - O0 - OoO0O00 . I1Ii111
   if 53 - 53: i1IIi + IiII
   if 90 - 90: II111iiii / oO0o / oO0o . OoOoOO00 / OoO0O00 / iIii1I11I1II1
   if 96 - 96: iIii1I11I1II1 % I1ii11iIi11i
  if ( iiIIi1I1I1ii == 0 ) :
   ooo00oOo0OO0O . append ( [ None , o0oO0Oo , oOO0oO0O0 ] )
   lprint ( "IGMPv3 {} (*, {})" . format ( bold ( Ii1IIii1i1i1i1I , False ) ,
 bold ( o0oO0Oo , False ) ) )
   if 35 - 35: i1IIi - OoooooooOO * Ii1I / OOooOOo % I11i
   if 72 - 72: I1Ii111 / OoO0O00 + II111iiii
   if 40 - 40: Ii1I + O0 . i11iIiiIii % I11i / Oo0Ooo
   if 25 - 25: IiII * IiII
   if 54 - 54: I1Ii111
  for iI1I1I111 in range ( iiIIi1I1I1ii ) :
   if ( len ( oooo00000O0o0 ) < Ii11II1IIi ) : return
   I1Ii1iIIIIi = struct . unpack ( OoiiiiI111II , oooo00000O0o0 [ : Ii11II1IIi ] ) [ 0 ]
   OO . address = socket . ntohl ( I1Ii1iIIIIi )
   oO0OOO = OO . print_address_no_iid ( )
   ooo00oOo0OO0O . append ( [ oO0OOO , o0oO0Oo , oOO0oO0O0 ] )
   lprint ( "{} ({}, {})" . format ( Ii1IIii1i1i1i1I ,
 green ( oO0OOO , False ) , bold ( o0oO0Oo , False ) ) )
   oooo00000O0o0 = oooo00000O0o0 [ Ii11II1IIi : : ]
   if 71 - 71: oO0o
   if 20 - 20: i1IIi / OOooOOo + Ii1I * OoOoOO00 / IiII
   if 80 - 80: OOooOOo / O0 + I1Ii111 - OoOoOO00
   if 6 - 6: iIii1I11I1II1 + I11i . o0oOOo0O0Ooo / i1IIi / I1Ii111
   if 71 - 71: iII111i . OOooOOo / IiII
   if 76 - 76: Oo0Ooo - OOooOOo * ooOoO0o / oO0o
   if 46 - 46: oO0o % iII111i - i11iIiiIii
   if 93 - 93: O0
 return ( ooo00oOo0OO0O )
 if 11 - 11: OoooooooOO . I1ii11iIi11i + I1ii11iIi11i
 if 73 - 73: OoooooooOO
 if 2 - 2: o0oOOo0O0Ooo % IiII + I1ii11iIi11i - i11iIiiIii
 if 100 - 100: II111iiii + oO0o
 if 85 - 85: I1ii11iIi11i % I1ii11iIi11i . Ii1I
 if 42 - 42: oO0o + OoO0O00
 if 16 - 16: Ii1I
 if 67 - 67: I1ii11iIi11i . OoooooooOO * I1Ii111 + Ii1I * OOooOOo
lisp_geid = lisp_address ( LISP_AFI_IPV4 , "" , 32 , 0 )
if 84 - 84: OOooOOo
def lisp_glean_map_cache ( seid , rloc , encap_port , igmp ) :
 if 78 - 78: O0 % O0
 if 72 - 72: o0oOOo0O0Ooo * IiII / II111iiii / iIii1I11I1II1
 if 41 - 41: iII111i / Ii1I
 if 11 - 11: Oo0Ooo % OOooOOo . ooOoO0o
 if 24 - 24: IiII / Oo0Ooo
 if 90 - 90: ooOoO0o . OOooOOo - Ii1I
 OoOOO000O0o = lisp_map_cache . lookup_cache ( seid , True )
 if ( OoOOO000O0o and len ( OoOOO000O0o . rloc_set ) != 0 ) :
  OoOOO000O0o . last_refresh_time = lisp_get_timestamp ( )
  if 60 - 60: i11iIiiIii % iII111i . I1IiiI * I1ii11iIi11i
  I1iiI1I = OoOOO000O0o . rloc_set [ 0 ]
  if ( igmp == None and I1iiI1I . rloc . is_exact_match ( rloc ) and
 I1iiI1I . translated_port == encap_port ) : return
  if 54 - 54: OOooOOo - ooOoO0o - iIii1I11I1II1
  o0o000 = green ( seid . print_address ( ) , False )
  IIi = red ( rloc . print_address_no_iid ( ) + ":" + str ( encap_port ) , False )
  lprint ( "Gleaned EID {} RLOC changed to {}" . format ( o0o000 , IIi ) )
  I1iiI1I . delete_from_rloc_probe_list ( OoOOO000O0o . eid , OoOOO000O0o . group )
 else :
  OoOOO000O0o = lisp_mapping ( "" , "" , [ ] )
  OoOOO000O0o . eid . copy_address ( seid )
  OoOOO000O0o . mapping_source . copy_address ( rloc )
  OoOOO000O0o . map_cache_ttl = LISP_GLEAN_TTL
  OoOOO000O0o . gleaned = True
  o0o000 = green ( seid . print_address ( ) , False )
  IIi = red ( rloc . print_address_no_iid ( ) + ":" + str ( encap_port ) , False )
  lprint ( "Add gleaned EID {} to map-cache with RLOC {}" . format ( o0o000 , IIi ) )
  OoOOO000O0o . add_cache ( )
  if 29 - 29: ooOoO0o
  if 31 - 31: o0oOOo0O0Ooo / IiII - oO0o / OoOoOO00 * IiII * i1IIi
  if 45 - 45: OoOoOO00 + iII111i % iIii1I11I1II1 - IiII * OOooOOo
  if 62 - 62: Ii1I / Oo0Ooo / I1ii11iIi11i . OoOoOO00 % ooOoO0o * IiII
  if 97 - 97: ooOoO0o
 OoooO00OO = lisp_rloc ( )
 OoooO00OO . store_translated_rloc ( rloc , encap_port )
 OoooO00OO . add_to_rloc_probe_list ( OoOOO000O0o . eid , OoOOO000O0o . group )
 OoooO00OO . priority = 253
 OoooO00OO . mpriority = 255
 O0Oo0O = [ OoooO00OO ]
 OoOOO000O0o . rloc_set = O0Oo0O
 OoOOO000O0o . build_best_rloc_set ( )
 if 14 - 14: iII111i + iII111i
 if 62 - 62: ooOoO0o / OOooOOo * I1ii11iIi11i + Oo0Ooo - OoooooooOO - OoooooooOO
 if 19 - 19: Ii1I . oO0o
 if 26 - 26: OOooOOo + II111iiii
 if ( igmp == None ) : return
 if 67 - 67: IiII + OoOoOO00 * I1ii11iIi11i % o0oOOo0O0Ooo / oO0o
 if 31 - 31: ooOoO0o / Ii1I . Ii1I - I1IiiI - Oo0Ooo . II111iiii
 if 82 - 82: Oo0Ooo % Oo0Ooo
 if 17 - 17: OOooOOo % Oo0Ooo . I1IiiI * O0 * oO0o % OoOoOO00
 if 99 - 99: Oo0Ooo - ooOoO0o . OoO0O00 - Oo0Ooo / O0
 lisp_geid . instance_id = seid . instance_id
 if 42 - 42: Ii1I - OoOoOO00 . OoOoOO00
 if 88 - 88: o0oOOo0O0Ooo . Ii1I . iII111i * iII111i + i11iIiiIii
 if 68 - 68: OoooooooOO
 if 5 - 5: OoOoOO00 . i11iIiiIii . OOooOOo / I11i * Oo0Ooo % Oo0Ooo
 if 44 - 44: I1ii11iIi11i + oO0o % i1IIi + OoooooooOO
 i1I1I11ii = lisp_process_igmp_packet ( igmp )
 for OO , IiI1111i1i11I , oOO0oO0O0 in i1I1I11ii :
  if ( OO != None ) : continue
  lisp_geid . store_address ( IiI1111i1i11I )
  if ( oOO0oO0O0 ) :
   lisp_build_gleaned_multicast ( seid , lisp_geid , rloc , encap_port )
  else :
   lisp_remove_gleaned_multicast ( seid , lisp_geid , rloc , encap_port )
   if 42 - 42: I1Ii111 / I1Ii111 - O0
   if 79 - 79: i11iIiiIii
   if 96 - 96: iIii1I11I1II1 . OoOoOO00 . OOooOOo / iII111i
   if 59 - 59: Oo0Ooo + OOooOOo / Oo0Ooo
   if 49 - 49: OoO0O00 / Oo0Ooo % OoOoOO00 % i1IIi
# dd678faae9ac167bc83abf78e5cb2f3f0688d3a3
