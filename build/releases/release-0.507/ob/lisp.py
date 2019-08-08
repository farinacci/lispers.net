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
if 37 - 37: OoooooooOO - O0 - o0oOOo0O0Ooo
lisp_glean_mappings = [ ]
if 77 - 77: OOooOOo * iIii1I11I1II1
if 98 - 98: I1IiiI % Ii1I * OoooooooOO
if 51 - 51: iIii1I11I1II1 . OoOoOO00 / oO0o + o0oOOo0O0Ooo
if 33 - 33: ooOoO0o . II111iiii % iII111i + o0oOOo0O0Ooo
if 71 - 71: Oo0Ooo % OOooOOo
lisp_icmp_raw_socket = None
if ( os . getenv ( "LISP_SEND_ICMP_TOO_BIG" ) != None ) :
 lisp_icmp_raw_socket = socket . socket ( socket . AF_INET , socket . SOCK_RAW ,
 socket . IPPROTO_ICMP )
 lisp_icmp_raw_socket . setsockopt ( socket . SOL_IP , socket . IP_HDRINCL , 1 )
 if 98 - 98: I11i % i11iIiiIii % ooOoO0o + Ii1I
 if 78 - 78: I1ii11iIi11i % oO0o / iII111i - iIii1I11I1II1
lisp_ignore_df_bit = ( os . getenv ( "LISP_IGNORE_DF_BIT" ) != None )
if 69 - 69: I1Ii111
if 11 - 11: I1IiiI
if 16 - 16: Ii1I + IiII * O0 % i1IIi . I1IiiI
if 67 - 67: OoooooooOO / I1IiiI * Ii1I + I11i
if 65 - 65: OoooooooOO - I1ii11iIi11i / ooOoO0o / II111iiii / i1IIi
if 71 - 71: I1Ii111 + Ii1I
LISP_DATA_PORT = 4341
LISP_CTRL_PORT = 4342
LISP_L2_DATA_PORT = 8472
LISP_VXLAN_DATA_PORT = 4789
LISP_VXLAN_GPE_PORT = 4790
LISP_TRACE_PORT = 2434
if 28 - 28: OOooOOo
if 38 - 38: ooOoO0o % II111iiii % I11i / OoO0O00 + OoOoOO00 / i1IIi
if 54 - 54: iIii1I11I1II1 % I1ii11iIi11i - OOooOOo / oO0o - OoO0O00 . I11i
if 11 - 11: I1ii11iIi11i . OoO0O00 * IiII * OoooooooOO + ooOoO0o
LISP_MAP_REQUEST = 1
LISP_MAP_REPLY = 2
LISP_MAP_REGISTER = 3
LISP_MAP_NOTIFY = 4
LISP_MAP_NOTIFY_ACK = 5
LISP_MAP_REFERRAL = 6
LISP_NAT_INFO = 7
LISP_ECM = 8
LISP_TRACE = 9
if 33 - 33: O0 * o0oOOo0O0Ooo - I1Ii111 % I1Ii111
if 18 - 18: I1Ii111 / Oo0Ooo * I1Ii111 + I1Ii111 * i11iIiiIii * I1ii11iIi11i
if 11 - 11: ooOoO0o / OoOoOO00 - IiII * OoooooooOO + OoooooooOO . OoOoOO00
if 26 - 26: Ii1I % I1ii11iIi11i
LISP_NO_ACTION = 0
LISP_NATIVE_FORWARD_ACTION = 1
LISP_SEND_MAP_REQUEST_ACTION = 2
LISP_DROP_ACTION = 3
LISP_POLICY_DENIED_ACTION = 4
LISP_AUTH_FAILURE_ACTION = 5
if 76 - 76: IiII * iII111i
lisp_map_reply_action_string = [ "no-action" , "native-forward" ,
 "send-map-request" , "drop-action" , "policy-denied" , "auth-failure" ]
if 52 - 52: OOooOOo
if 19 - 19: I1IiiI
if 25 - 25: Ii1I / ooOoO0o
if 31 - 31: OOooOOo . O0 % I1IiiI . o0oOOo0O0Ooo + IiII
LISP_NONE_ALG_ID = 0
LISP_SHA_1_96_ALG_ID = 1
LISP_SHA_256_128_ALG_ID = 2
LISP_MD5_AUTH_DATA_LEN = 16
LISP_SHA1_160_AUTH_DATA_LEN = 20
LISP_SHA2_256_AUTH_DATA_LEN = 32
if 71 - 71: I1Ii111 . II111iiii
if 62 - 62: OoooooooOO . I11i
if 61 - 61: OoOoOO00 - OOooOOo - i1IIi
if 25 - 25: O0 * I11i + I1ii11iIi11i . o0oOOo0O0Ooo . o0oOOo0O0Ooo
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
if 58 - 58: I1IiiI
if 53 - 53: i1IIi
if 59 - 59: o0oOOo0O0Ooo
if 81 - 81: OoOoOO00 - OoOoOO00 . iII111i
LISP_MR_TTL = ( 24 * 60 )
LISP_REGISTER_TTL = 3
LISP_SHORT_TTL = 1
LISP_NMR_TTL = 15
LISP_GLEAN_TTL = 15
LISP_IGMP_TTL = 150
if 73 - 73: I11i % i11iIiiIii - I1IiiI
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
if 7 - 7: O0 * i11iIiiIii * Ii1I + ooOoO0o % OoO0O00 - ooOoO0o
LISP_RLOC_PROBE_TTL = 64
LISP_RLOC_PROBE_INTERVAL = 10
LISP_RLOC_PROBE_REPLY_WAIT = 15
if 39 - 39: Oo0Ooo * OOooOOo % OOooOOo - OoooooooOO + o0oOOo0O0Ooo - I11i
LISP_DEFAULT_DYN_EID_TIMEOUT = 15
LISP_NONCE_ECHO_INTERVAL = 10
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
if 56 - 56: OoO0O00 / oO0o / i11iIiiIii + OoooooooOO - Oo0Ooo - I11i
LISP_CS_1024 = 0
LISP_CS_1024_G = 2
LISP_CS_1024_P = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF
if 21 - 21: O0 % IiII . I1IiiI / II111iiii + IiII
LISP_CS_2048_CBC = 1
LISP_CS_2048_CBC_G = 2
LISP_CS_2048_CBC_P = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF
if 53 - 53: oO0o - I1IiiI - oO0o * iII111i
LISP_CS_25519_CBC = 2
LISP_CS_2048_GCM = 3
if 71 - 71: O0 - iIii1I11I1II1
LISP_CS_3072 = 4
LISP_CS_3072_G = 2
LISP_CS_3072_P = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF
if 12 - 12: OOooOOo / o0oOOo0O0Ooo
LISP_CS_25519_GCM = 5
LISP_CS_25519_CHACHA = 6
if 42 - 42: Oo0Ooo
LISP_4_32_MASK = 0xFFFFFFFF
LISP_8_64_MASK = 0xFFFFFFFFFFFFFFFF
LISP_16_128_MASK = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
if 19 - 19: oO0o % I1ii11iIi11i * iIii1I11I1II1 + I1IiiI
if 46 - 46: Oo0Ooo
if 1 - 1: iII111i
if 97 - 97: OOooOOo + iII111i + O0 + i11iIiiIii
if 77 - 77: o0oOOo0O0Ooo / OoooooooOO
if 46 - 46: o0oOOo0O0Ooo % iIii1I11I1II1 . iII111i % iII111i + i11iIiiIii
if 72 - 72: iIii1I11I1II1 * Ii1I % ooOoO0o / OoO0O00
if 35 - 35: ooOoO0o + i1IIi % I1ii11iIi11i % I11i + oO0o
def lisp_record_traceback ( * args ) :
 iiiI = datetime . datetime . now ( ) . strftime ( "%m/%d/%y %H:%M:%S.%f" ) [ : - 3 ]
 I1ii1 = open ( "./logs/lisp-traceback.log" , "a" )
 I1ii1 . write ( "---------- Exception occurred: {} ----------\n" . format ( iiiI ) )
 try :
  traceback . print_last ( file = I1ii1 )
 except :
  I1ii1 . write ( "traceback.print_last(file=fd) failed" )
  if 99 - 99: ooOoO0o . I1Ii111 % IiII * IiII . i1IIi
 try :
  traceback . print_last ( )
 except :
  print ( "traceback.print_last() failed" )
  if 72 - 72: OOooOOo % I1ii11iIi11i + OoO0O00 / oO0o + IiII
 I1ii1 . close ( )
 return
 if 10 - 10: I1Ii111 / ooOoO0o + i11iIiiIii / Ii1I
 if 74 - 74: OOooOOo + O0 + i1IIi - i1IIi + II111iiii
 if 83 - 83: I1ii11iIi11i - I1IiiI + OOooOOo
 if 5 - 5: Ii1I
 if 46 - 46: IiII
 if 45 - 45: ooOoO0o
 if 21 - 21: oO0o . I1Ii111 . OOooOOo / Oo0Ooo / I1Ii111
def lisp_set_exception ( ) :
 sys . excepthook = lisp_record_traceback
 return
 if 17 - 17: OOooOOo / OOooOOo / I11i
 if 1 - 1: i1IIi . i11iIiiIii % OOooOOo
 if 82 - 82: iIii1I11I1II1 + Oo0Ooo . iIii1I11I1II1 % IiII / Ii1I . Ii1I
 if 14 - 14: o0oOOo0O0Ooo . OOooOOo . I11i + OoooooooOO - OOooOOo + IiII
 if 9 - 9: Ii1I
 if 59 - 59: I1IiiI * II111iiii . O0
 if 56 - 56: Ii1I - iII111i % I1IiiI - o0oOOo0O0Ooo
def lisp_is_raspbian ( ) :
 if ( platform . dist ( ) [ 0 ] != "debian" ) : return ( False )
 return ( platform . machine ( ) in [ "armv6l" , "armv7l" ] )
 if 51 - 51: O0 / ooOoO0o * iIii1I11I1II1 + I1ii11iIi11i + o0oOOo0O0Ooo
 if 98 - 98: iIii1I11I1II1 * I1ii11iIi11i * OOooOOo + ooOoO0o % i11iIiiIii % O0
 if 27 - 27: O0
 if 79 - 79: o0oOOo0O0Ooo - I11i + o0oOOo0O0Ooo . oO0o
 if 28 - 28: i1IIi - iII111i
 if 54 - 54: iII111i - O0 % OOooOOo
 if 73 - 73: O0 . OoOoOO00 + I1IiiI - I11i % I11i . I11i
def lisp_is_ubuntu ( ) :
 return ( platform . dist ( ) [ 0 ] == "Ubuntu" )
 if 17 - 17: Ii1I - OoooooooOO % Ii1I . IiII / i11iIiiIii % iII111i
 if 28 - 28: I11i
 if 58 - 58: OoOoOO00
 if 37 - 37: Oo0Ooo - iIii1I11I1II1 / I1ii11iIi11i
 if 73 - 73: i11iIiiIii - IiII
 if 25 - 25: OoooooooOO + IiII * I1ii11iIi11i
 if 92 - 92: I1IiiI + I11i + O0 / o0oOOo0O0Ooo + I1Ii111
def lisp_is_fedora ( ) :
 return ( platform . dist ( ) [ 0 ] == "fedora" )
 if 18 - 18: ooOoO0o * OoOoOO00 . iII111i / I1ii11iIi11i / i11iIiiIii
 if 21 - 21: oO0o / I1ii11iIi11i + Ii1I + OoooooooOO
 if 91 - 91: i11iIiiIii / i1IIi + iII111i + ooOoO0o * i11iIiiIii
 if 66 - 66: iIii1I11I1II1 % i1IIi - O0 + I11i * I1Ii111 . IiII
 if 52 - 52: ooOoO0o + O0 . iII111i . I1ii11iIi11i . OoO0O00
 if 97 - 97: I1IiiI / iII111i
 if 71 - 71: II111iiii / i1IIi . I1ii11iIi11i % OoooooooOO . OoOoOO00
def lisp_is_centos ( ) :
 return ( platform . dist ( ) [ 0 ] == "centos" )
 if 41 - 41: i1IIi * II111iiii / OoooooooOO . OOooOOo
 if 83 - 83: iII111i . O0 / Oo0Ooo / OOooOOo - II111iiii
 if 100 - 100: OoO0O00
 if 46 - 46: OoOoOO00 / iIii1I11I1II1 % iII111i . iIii1I11I1II1 * iII111i
 if 38 - 38: I1ii11iIi11i - iII111i / O0 . I1Ii111
 if 45 - 45: I1Ii111
 if 83 - 83: OoOoOO00 . OoooooooOO
def lisp_is_debian ( ) :
 return ( platform . dist ( ) [ 0 ] == "debian" )
 if 58 - 58: i11iIiiIii + OoooooooOO % OoooooooOO / IiII / i11iIiiIii
 if 62 - 62: OoO0O00 / I1ii11iIi11i
 if 7 - 7: OoooooooOO . IiII
 if 53 - 53: Ii1I % Ii1I * o0oOOo0O0Ooo + OoOoOO00
 if 92 - 92: OoooooooOO + i1IIi / Ii1I * O0
 if 100 - 100: ooOoO0o % iIii1I11I1II1 * II111iiii - iII111i
 if 92 - 92: ooOoO0o
def lisp_is_debian_kali ( ) :
 return ( platform . dist ( ) [ 0 ] == "Kali" )
 if 22 - 22: Oo0Ooo % iII111i * I1ii11iIi11i / OOooOOo % i11iIiiIii * I11i
 if 95 - 95: OoooooooOO - IiII * I1IiiI + OoOoOO00
 if 10 - 10: o0oOOo0O0Ooo / i11iIiiIii
 if 92 - 92: I11i . I1Ii111
 if 85 - 85: I1ii11iIi11i . I1Ii111
 if 78 - 78: ooOoO0o * I1Ii111 + iIii1I11I1II1 + iIii1I11I1II1 / I1Ii111 . Ii1I
 if 97 - 97: ooOoO0o / I1Ii111 % i1IIi % I1ii11iIi11i
def lisp_is_macos ( ) :
 return ( platform . uname ( ) [ 0 ] == "Darwin" )
 if 18 - 18: iIii1I11I1II1 % I11i
 if 95 - 95: ooOoO0o + i11iIiiIii * I1Ii111 - i1IIi * I1Ii111 - iIii1I11I1II1
 if 75 - 75: OoooooooOO * IiII
 if 9 - 9: IiII - II111iiii + O0 / iIii1I11I1II1 / i11iIiiIii
 if 39 - 39: IiII * Oo0Ooo + iIii1I11I1II1 - IiII + OOooOOo
 if 69 - 69: O0
 if 85 - 85: ooOoO0o / O0
def lisp_is_alpine ( ) :
 return ( os . path . exists ( "/etc/alpine-release" ) )
 if 18 - 18: o0oOOo0O0Ooo % O0 * I1ii11iIi11i
 if 62 - 62: I1Ii111 . IiII . OoooooooOO
 if 11 - 11: OOooOOo / I11i
 if 73 - 73: i1IIi / i11iIiiIii
 if 58 - 58: Oo0Ooo . II111iiii + oO0o - i11iIiiIii / II111iiii / O0
 if 85 - 85: OoOoOO00 + OOooOOo
 if 10 - 10: IiII / OoO0O00 + OoOoOO00 / i1IIi
def lisp_is_x86 ( ) :
 i1iII1II11I = platform . machine ( )
 return ( i1iII1II11I in ( "x86" , "i686" , "x86_64" ) )
 if 54 - 54: IiII + O0 + I11i * I1Ii111 - OOooOOo % oO0o
 if 13 - 13: ooOoO0o / iII111i * OoO0O00 . OoO0O00 * ooOoO0o
 if 63 - 63: I1Ii111 / O0 * Oo0Ooo + II111iiii / IiII + Ii1I
 if 63 - 63: OoO0O00 + I1ii11iIi11i . I1Ii111 % I1Ii111
 if 57 - 57: II111iiii
 if 54 - 54: Oo0Ooo + oO0o + i11iIiiIii
 if 28 - 28: oO0o
def lisp_is_linux ( ) :
 return ( platform . uname ( ) [ 0 ] == "Linux" )
 if 70 - 70: IiII
 if 34 - 34: I1Ii111 % IiII
 if 3 - 3: II111iiii / OOooOOo + IiII . ooOoO0o . OoO0O00
 if 83 - 83: oO0o + OoooooooOO
 if 22 - 22: Ii1I % iII111i * OoooooooOO - o0oOOo0O0Ooo / iIii1I11I1II1
 if 86 - 86: OoooooooOO . iII111i % OoOoOO00 / I11i * iII111i / o0oOOo0O0Ooo
 if 64 - 64: i11iIiiIii
def lisp_on_aws ( ) :
 I1II = commands . getoutput ( "sudo dmidecode -s bios-version" )
 return ( I1II . lower ( ) . find ( "amazon" ) != - 1 )
 if 17 - 17: OOooOOo % Oo0Ooo / I1ii11iIi11i . IiII * OOooOOo - II111iiii
 if 41 - 41: Ii1I
 if 77 - 77: I1Ii111
 if 65 - 65: II111iiii . I1IiiI % oO0o * OoO0O00
 if 38 - 38: OoOoOO00 / iII111i % Oo0Ooo
 if 11 - 11: iII111i - oO0o + II111iiii - iIii1I11I1II1
 if 7 - 7: IiII - I11i / II111iiii * Ii1I . iII111i * iII111i
def lisp_on_gcp ( ) :
 I1II = commands . getoutput ( "sudo dmidecode -s bios-version" )
 return ( I1II . lower ( ) . find ( "google" ) != - 1 )
 if 61 - 61: I11i % ooOoO0o - OoO0O00 / Oo0Ooo
 if 4 - 4: OoooooooOO - i1IIi % Ii1I - OOooOOo * o0oOOo0O0Ooo
 if 85 - 85: OoooooooOO * iIii1I11I1II1 . iII111i / OoooooooOO % I1IiiI % O0
 if 36 - 36: Ii1I / II111iiii / IiII / IiII + I1ii11iIi11i
 if 95 - 95: IiII
 if 51 - 51: II111iiii + IiII . i1IIi . I1ii11iIi11i + OoOoOO00 * I1IiiI
 if 72 - 72: oO0o + oO0o / II111iiii . OoooooooOO % Ii1I
 if 49 - 49: oO0o . OoO0O00 - Oo0Ooo * OoooooooOO . Oo0Ooo
def lisp_process_logfile ( ) :
 ii1Ii1IiIIi = "./logs/lisp-{}.log" . format ( lisp_log_id )
 if ( os . path . exists ( ii1Ii1IiIIi ) ) : return
 if 83 - 83: I11i / I1ii11iIi11i
 sys . stdout . close ( )
 sys . stdout = open ( ii1Ii1IiIIi , "a" )
 if 34 - 34: I1IiiI * Oo0Ooo * I1Ii111 / OoO0O00 * I11i / iIii1I11I1II1
 lisp_print_banner ( bold ( "logfile rotation" , False ) )
 return
 if 74 - 74: Oo0Ooo / i11iIiiIii - II111iiii * o0oOOo0O0Ooo
 if 5 - 5: OOooOOo - OOooOOo . Oo0Ooo + OoOoOO00 - OOooOOo . oO0o
 if 31 - 31: II111iiii - iIii1I11I1II1 - iIii1I11I1II1 % I11i
 if 12 - 12: iIii1I11I1II1
 if 20 - 20: o0oOOo0O0Ooo / i1IIi
 if 71 - 71: OoOoOO00 . i1IIi
 if 94 - 94: OOooOOo . I1Ii111
 if 84 - 84: O0 . I11i - II111iiii . ooOoO0o / II111iiii
def lisp_i_am ( name ) :
 global lisp_log_id , lisp_i_am_itr , lisp_i_am_etr , lisp_i_am_rtr
 global lisp_i_am_mr , lisp_i_am_ms , lisp_i_am_ddt , lisp_i_am_core
 global lisp_hostname
 if 47 - 47: OoooooooOO
 lisp_log_id = name
 if ( name == "itr" ) : lisp_i_am_itr = True
 if ( name == "etr" ) : lisp_i_am_etr = True
 if ( name == "rtr" ) : lisp_i_am_rtr = True
 if ( name == "mr" ) : lisp_i_am_mr = True
 if ( name == "ms" ) : lisp_i_am_ms = True
 if ( name == "ddt" ) : lisp_i_am_ddt = True
 if ( name == "core" ) : lisp_i_am_core = True
 if 4 - 4: I1IiiI % I11i
 if 10 - 10: IiII . OoooooooOO - OoO0O00 + IiII - O0
 if 82 - 82: ooOoO0o + II111iiii
 if 39 - 39: oO0o % iIii1I11I1II1 % O0 % OoooooooOO * I1ii11iIi11i + iII111i
 if 68 - 68: Oo0Ooo + i11iIiiIii
 lisp_hostname = socket . gethostname ( )
 Oo0oOooo000OO = lisp_hostname . find ( "." )
 if ( Oo0oOooo000OO != - 1 ) : lisp_hostname = lisp_hostname [ 0 : Oo0oOooo000OO ]
 return
 if 98 - 98: o0oOOo0O0Ooo + O0 % i1IIi - OOooOOo + Oo0Ooo
 if 84 - 84: O0 * OoooooooOO - IiII * IiII
 if 8 - 8: ooOoO0o / i1IIi . oO0o
 if 41 - 41: iII111i + OoO0O00
 if 86 - 86: OoOoOO00 . iIii1I11I1II1 - OoO0O00
 if 56 - 56: O0
 if 61 - 61: o0oOOo0O0Ooo / OOooOOo / Oo0Ooo * O0
 if 23 - 23: oO0o - OOooOOo + I11i
 if 12 - 12: I1IiiI / ooOoO0o % o0oOOo0O0Ooo / i11iIiiIii % OoooooooOO
def lprint ( * args ) :
 IiIi1II11i = ( "force" in args )
 if ( lisp_debug_logging == False and IiIi1II11i == False ) : return
 if 42 - 42: I1ii11iIi11i * OoOoOO00 % ooOoO0o - OoOoOO00 . i11iIiiIii - I1Ii111
 lisp_process_logfile ( )
 iiiI = datetime . datetime . now ( ) . strftime ( "%m/%d/%y %H:%M:%S.%f" )
 iiiI = iiiI [ : - 3 ]
 print "{}: {}:" . format ( iiiI , lisp_log_id ) ,
 if 84 - 84: I1Ii111 - I1ii11iIi11i / I11i
 for i1II111i1 in args :
  if ( i1II111i1 == "force" ) : continue
  print i1II111i1 ,
  if 98 - 98: OoO0O00 . I11i % II111iiii
 print ""
 if 71 - 71: I1Ii111 % i1IIi - II111iiii - OOooOOo + OOooOOo * ooOoO0o
 try : sys . stdout . flush ( )
 except : pass
 return
 if 51 - 51: iIii1I11I1II1 / OoOoOO00 + OOooOOo - I11i + iII111i
 if 29 - 29: o0oOOo0O0Ooo % iIii1I11I1II1 . OoooooooOO % OoooooooOO % II111iiii / iII111i
 if 70 - 70: i11iIiiIii % iII111i
 if 11 - 11: IiII % I1ii11iIi11i % Ii1I / II111iiii % I1Ii111 - Oo0Ooo
 if 96 - 96: I1ii11iIi11i / II111iiii . Ii1I - iII111i * I11i * oO0o
 if 76 - 76: Ii1I - II111iiii * OOooOOo / OoooooooOO
 if 18 - 18: OoO0O00 + iIii1I11I1II1 - II111iiii - I1IiiI
 if 71 - 71: OoooooooOO
def dprint ( * args ) :
 if ( lisp_data_plane_logging ) : lprint ( * args )
 return
 if 33 - 33: I1Ii111
 if 62 - 62: I1ii11iIi11i + Ii1I + i1IIi / OoooooooOO
 if 7 - 7: o0oOOo0O0Ooo + i1IIi . I1IiiI / Oo0Ooo
 if 22 - 22: ooOoO0o - ooOoO0o % OOooOOo . I1Ii111 + oO0o
 if 63 - 63: I1IiiI % I1Ii111 * o0oOOo0O0Ooo + I1Ii111 / Oo0Ooo % iII111i
 if 45 - 45: IiII
 if 20 - 20: OoooooooOO * o0oOOo0O0Ooo * O0 . OOooOOo
 if 78 - 78: iIii1I11I1II1 + I11i - Ii1I * I1Ii111 - OoooooooOO % OoOoOO00
def debug ( * args ) :
 lisp_process_logfile ( )
 if 34 - 34: O0
 iiiI = datetime . datetime . now ( ) . strftime ( "%m/%d/%y %H:%M:%S.%f" )
 iiiI = iiiI [ : - 3 ]
 if 80 - 80: i1IIi - Oo0Ooo / OoO0O00 - i11iIiiIii
 print red ( ">>>" , False ) ,
 print "{}:" . format ( iiiI ) ,
 for i1II111i1 in args : print i1II111i1 ,
 print red ( "<<<\n" , False )
 try : sys . stdout . flush ( )
 except : pass
 return
 if 68 - 68: oO0o - I1ii11iIi11i % O0 % I1Ii111
 if 11 - 11: O0 / OoO0O00 % OOooOOo + o0oOOo0O0Ooo + iIii1I11I1II1
 if 40 - 40: ooOoO0o - OOooOOo . Ii1I * Oo0Ooo % I1Ii111
 if 56 - 56: i11iIiiIii . o0oOOo0O0Ooo - I1IiiI * I11i
 if 91 - 91: oO0o + OoooooooOO - i1IIi
 if 84 - 84: Ii1I / IiII
 if 86 - 86: OoOoOO00 * II111iiii - O0 . OoOoOO00 % iIii1I11I1II1 / OOooOOo
def lisp_print_banner ( string ) :
 global lisp_version , lisp_hostname
 if 11 - 11: I1IiiI * oO0o + I1ii11iIi11i / I1ii11iIi11i
 if ( lisp_version == "" ) :
  lisp_version = commands . getoutput ( "cat lisp-version.txt" )
  if 37 - 37: i11iIiiIii + i1IIi
 I1i11II = bold ( lisp_hostname , False )
 lprint ( "lispers.net LISP {} {}, version {}, hostname {}" . format ( string ,
 datetime . datetime . now ( ) , lisp_version , I1i11II ) )
 return
 if 31 - 31: oO0o / IiII * o0oOOo0O0Ooo . II111iiii
 if 89 - 89: O0
 if 2 - 2: I1ii11iIi11i . I1ii11iIi11i + I1ii11iIi11i * o0oOOo0O0Ooo
 if 100 - 100: Oo0Ooo % Ii1I / I11i
 if 30 - 30: Oo0Ooo - OOooOOo - iII111i
 if 81 - 81: o0oOOo0O0Ooo . OoooooooOO + OOooOOo * ooOoO0o
 if 74 - 74: i1IIi + O0 + Oo0Ooo
def green ( string , html ) :
 if ( html ) : return ( '<font color="green"><b>{}</b></font>' . format ( string ) )
 return ( bold ( "\033[92m" + string + "\033[0m" , html ) )
 if 5 - 5: Oo0Ooo * OoOoOO00
 if 46 - 46: ooOoO0o
 if 33 - 33: iII111i - II111iiii * OoooooooOO - Oo0Ooo - OOooOOo
 if 84 - 84: I1Ii111 + Oo0Ooo - OoOoOO00 * OoOoOO00
 if 61 - 61: OoooooooOO . oO0o . OoooooooOO / Oo0Ooo
 if 72 - 72: i1IIi
 if 82 - 82: OoOoOO00 + OoooooooOO / i11iIiiIii * I1ii11iIi11i . OoooooooOO
def green_last_sec ( string ) :
 return ( green ( string , True ) )
 if 63 - 63: I1ii11iIi11i
 if 6 - 6: ooOoO0o / I1ii11iIi11i
 if 57 - 57: I11i
 if 67 - 67: OoO0O00 . ooOoO0o
 if 87 - 87: oO0o % Ii1I
 if 83 - 83: II111iiii - I11i
 if 35 - 35: i1IIi - iIii1I11I1II1 + i1IIi
def green_last_min ( string ) :
 return ( '<font color="#58D68D"><b>{}</b></font>' . format ( string ) )
 if 86 - 86: iIii1I11I1II1 + OoOoOO00 . i11iIiiIii - Ii1I
 if 51 - 51: OoOoOO00
 if 14 - 14: IiII % oO0o % Oo0Ooo - i11iIiiIii
 if 53 - 53: Ii1I % Oo0Ooo
 if 59 - 59: OOooOOo % iIii1I11I1II1 . i1IIi + II111iiii * IiII
 if 41 - 41: Ii1I % I1ii11iIi11i
 if 12 - 12: OOooOOo
def red ( string , html ) :
 if ( html ) : return ( '<font color="red"><b>{}</b></font>' . format ( string ) )
 return ( bold ( "\033[91m" + string + "\033[0m" , html ) )
 if 69 - 69: OoooooooOO + OOooOOo
 if 26 - 26: Oo0Ooo + OOooOOo / OoO0O00 % OoOoOO00 % I1ii11iIi11i + II111iiii
 if 31 - 31: I11i % OOooOOo * I11i
 if 45 - 45: i1IIi . I1IiiI + OOooOOo - OoooooooOO % ooOoO0o
 if 1 - 1: iIii1I11I1II1
 if 93 - 93: i1IIi . i11iIiiIii . Oo0Ooo
 if 99 - 99: I11i - I1Ii111 - oO0o % OoO0O00
def blue ( string , html ) :
 if ( html ) : return ( '<font color="blue"><b>{}</b></font>' . format ( string ) )
 return ( bold ( "\033[94m" + string + "\033[0m" , html ) )
 if 21 - 21: II111iiii % I1ii11iIi11i . i1IIi - OoooooooOO
 if 4 - 4: OoooooooOO . ooOoO0o
 if 78 - 78: I1ii11iIi11i + I11i - O0
 if 10 - 10: I1Ii111 % I1IiiI
 if 97 - 97: OoooooooOO - I1Ii111
 if 58 - 58: iIii1I11I1II1 + O0
 if 30 - 30: ooOoO0o % iII111i * OOooOOo - I1ii11iIi11i * Ii1I % ooOoO0o
def bold ( string , html ) :
 if ( html ) : return ( "<b>{}</b>" . format ( string ) )
 return ( "\033[1m" + string + "\033[0m" )
 if 46 - 46: i11iIiiIii - O0 . oO0o
 if 100 - 100: I1IiiI / o0oOOo0O0Ooo * iII111i . O0 / OOooOOo
 if 83 - 83: I1Ii111
 if 48 - 48: II111iiii * OOooOOo * I1Ii111
 if 50 - 50: IiII % i1IIi
 if 21 - 21: OoooooooOO - iIii1I11I1II1
 if 93 - 93: oO0o - o0oOOo0O0Ooo % OoOoOO00 . OoOoOO00 - ooOoO0o
def convert_font ( string ) :
 O00ooOo = [ [ "[91m" , red ] , [ "[92m" , green ] , [ "[94m" , blue ] , [ "[1m" , bold ] ]
 oOO0o00O = "[0m"
 if 69 - 69: i1IIi
 for ooOoOOOOo in O00ooOo :
  ooooOooooOOo = ooOoOOOOo [ 0 ]
  ooO00O00oOO = ooOoOOOOo [ 1 ]
  I1 = len ( ooooOooooOOo )
  Oo0oOooo000OO = string . find ( ooooOooooOOo )
  if ( Oo0oOooo000OO != - 1 ) : break
  if 48 - 48: I1IiiI + I1ii11iIi11i + II111iiii * i11iIiiIii
  if 13 - 13: OoooooooOO * oO0o - Ii1I / OOooOOo + I11i + IiII
 while ( Oo0oOooo000OO != - 1 ) :
  iii1III1i = string [ Oo0oOooo000OO : : ] . find ( oOO0o00O )
  iiiIi = string [ Oo0oOooo000OO + I1 : Oo0oOooo000OO + iii1III1i ]
  string = string [ : Oo0oOooo000OO ] + ooO00O00oOO ( iiiIi , True ) + string [ Oo0oOooo000OO + iii1III1i + I1 : : ]
  if 45 - 45: I1ii11iIi11i + OoO0O00 * i11iIiiIii / OOooOOo % I11i * O0
  Oo0oOooo000OO = string . find ( ooooOooooOOo )
  if 17 - 17: O0
  if 88 - 88: Oo0Ooo . O0 % OoooooooOO / OOooOOo
  if 89 - 89: II111iiii / oO0o
  if 14 - 14: OOooOOo . I1IiiI * ooOoO0o + II111iiii - ooOoO0o + OOooOOo
  if 18 - 18: oO0o - o0oOOo0O0Ooo - I1IiiI - I1IiiI
 if ( string . find ( "[1m" ) != - 1 ) : string = convert_font ( string )
 return ( string )
 if 54 - 54: Oo0Ooo + I1IiiI / iII111i . I1IiiI * OoOoOO00
 if 1 - 1: OoOoOO00 * OoO0O00 . i1IIi / Oo0Ooo . I1ii11iIi11i + Oo0Ooo
 if 17 - 17: Oo0Ooo + OoO0O00 / Ii1I / iII111i * OOooOOo
 if 29 - 29: OoO0O00 % OoooooooOO * oO0o / II111iiii - oO0o
 if 19 - 19: i11iIiiIii
 if 54 - 54: II111iiii . I11i
 if 73 - 73: OoOoOO00 . I1IiiI
def lisp_space ( num ) :
 II1i11i1iIi11 = ""
 for oo0O0oO0O0O in range ( num ) : II1i11i1iIi11 += "&#160;"
 return ( II1i11i1iIi11 )
 if 69 - 69: oO0o / i11iIiiIii
 if 94 - 94: oO0o / IiII / i1IIi * iIii1I11I1II1
 if 64 - 64: II111iiii / iIii1I11I1II1
 if 79 - 79: i11iIiiIii
 if 79 - 79: Oo0Ooo - OoooooooOO . O0
 if 62 - 62: oO0o * oO0o . Ii1I % i1IIi . Ii1I * Ii1I
 if 81 - 81: OOooOOo / iIii1I11I1II1 + IiII
def lisp_button ( string , url ) :
 i1iiI = '<button style="background-color:transparent;border-radius:10px; ' + 'type="button">'
 if 74 - 74: I1Ii111 % I1ii11iIi11i
 if 7 - 7: II111iiii
 if ( url == None ) :
  iI = i1iiI + string + "</button>"
 else :
  i1 = '<a href="{}">' . format ( url )
  oOOOOOOOoO = lisp_space ( 2 )
  iI = oOOOOOOOoO + i1 + i1iiI + string + "</button></a>" + oOOOOOOOoO
  if 12 - 12: iII111i . IiII . OoOoOO00 / O0
 return ( iI )
 if 58 - 58: o0oOOo0O0Ooo - II111iiii % oO0o + I1Ii111 . OoOoOO00 / IiII
 if 8 - 8: I1ii11iIi11i . OoO0O00 * I11i + II111iiii % i11iIiiIii
 if 8 - 8: ooOoO0o * O0
 if 73 - 73: o0oOOo0O0Ooo / oO0o / I11i / OoO0O00
 if 11 - 11: OoOoOO00 + IiII - OoooooooOO / OoO0O00
 if 34 - 34: ooOoO0o
 if 45 - 45: ooOoO0o / Oo0Ooo / Ii1I
def lisp_print_cour ( string ) :
 II1i11i1iIi11 = '<font face="Courier New">{}</font>' . format ( string )
 return ( II1i11i1iIi11 )
 if 44 - 44: I1ii11iIi11i - Ii1I / II111iiii * OoO0O00 * Oo0Ooo
 if 73 - 73: o0oOOo0O0Ooo - I1IiiI * i1IIi / i11iIiiIii * OOooOOo % II111iiii
 if 56 - 56: OoooooooOO * Oo0Ooo . Oo0Ooo . I1ii11iIi11i
 if 24 - 24: Oo0Ooo . I11i * Ii1I % iII111i / OOooOOo
 if 58 - 58: I1IiiI - I1ii11iIi11i % O0 . I1IiiI % OoO0O00 % IiII
 if 87 - 87: oO0o - i11iIiiIii
 if 78 - 78: i11iIiiIii / iIii1I11I1II1 - o0oOOo0O0Ooo
def lisp_print_sans ( string ) :
 II1i11i1iIi11 = '<font face="Sans-Serif">{}</font>' . format ( string )
 return ( II1i11i1iIi11 )
 if 23 - 23: I11i
 if 40 - 40: o0oOOo0O0Ooo - II111iiii / Oo0Ooo
 if 14 - 14: I1ii11iIi11i
 if 5 - 5: o0oOOo0O0Ooo . iIii1I11I1II1 % iIii1I11I1II1
 if 56 - 56: OoooooooOO - I11i - i1IIi
 if 8 - 8: I1Ii111 / OOooOOo . I1IiiI + I1ii11iIi11i / i11iIiiIii
 if 31 - 31: ooOoO0o - iIii1I11I1II1 + iII111i . Oo0Ooo / IiII % iIii1I11I1II1
def lisp_span ( string , hover_string ) :
 II1i11i1iIi11 = '<span title="{}">{}</span>' . format ( hover_string , string )
 return ( II1i11i1iIi11 )
 if 6 - 6: IiII * i11iIiiIii % iIii1I11I1II1 % i11iIiiIii + o0oOOo0O0Ooo / i1IIi
 if 53 - 53: I11i + iIii1I11I1II1
 if 70 - 70: I1ii11iIi11i
 if 67 - 67: OoooooooOO
 if 29 - 29: O0 - i11iIiiIii - II111iiii + OOooOOo * IiII
 if 2 - 2: i1IIi - ooOoO0o + I1IiiI . o0oOOo0O0Ooo * o0oOOo0O0Ooo / OoOoOO00
 if 93 - 93: i1IIi
def lisp_eid_help_hover ( output ) :
 ooOOOo = '''Unicast EID format:
  For longest match lookups: 
    <address> or [<iid>]<address>
  For exact match lookups: 
    <prefix> or [<iid>]<prefix>
Multicast EID format:
  For longest match lookups:
    <address>-><group> or
    [<iid>]<address>->[<iid>]<group>'''
 if 98 - 98: oO0o % IiII * i11iIiiIii % I1ii11iIi11i
 if 29 - 29: IiII
 o0OOoo = lisp_span ( output , ooOOOo )
 return ( o0OOoo )
 if 16 - 16: I1IiiI * i1IIi - o0oOOo0O0Ooo . IiII % I11i / o0oOOo0O0Ooo
 if 14 - 14: iIii1I11I1II1 * I1Ii111 * I1ii11iIi11i / iIii1I11I1II1 * IiII / I11i
 if 77 - 77: OoO0O00 + I1Ii111 + I1Ii111 * Ii1I / OoooooooOO . Ii1I
 if 62 - 62: i1IIi - i1IIi
 if 69 - 69: OoOoOO00 % oO0o - I11i
 if 38 - 38: iIii1I11I1II1 + i11iIiiIii / i11iIiiIii % OoO0O00 / ooOoO0o % Ii1I
 if 7 - 7: IiII * I1IiiI + i1IIi + i11iIiiIii + Oo0Ooo % I1IiiI
def lisp_geo_help_hover ( output ) :
 ooOOOo = '''EID format:
    <address> or [<iid>]<address>
    '<name>' or [<iid>]'<name>'
Geo-Point format:
    d-m-s-<N|S>-d-m-s-<W|E> or 
    [<iid>]d-m-s-<N|S>-d-m-s-<W|E>
Geo-Prefix format:
    d-m-s-<N|S>-d-m-s-<W|E>/<km> or
    [<iid>]d-m-s-<N|S>-d-m-s-<W|E>/<km>'''
 if 62 - 62: o0oOOo0O0Ooo - Ii1I * OoOoOO00 - i11iIiiIii % ooOoO0o
 if 52 - 52: I1ii11iIi11i % oO0o - i11iIiiIii
 o0OOoo = lisp_span ( output , ooOOOo )
 return ( o0OOoo )
 if 30 - 30: iII111i / OoO0O00 + oO0o
 if 6 - 6: iII111i . I11i + Ii1I . I1Ii111
 if 70 - 70: OoO0O00
 if 46 - 46: I11i - i1IIi
 if 46 - 46: I1Ii111 % Ii1I
 if 72 - 72: iIii1I11I1II1
 if 45 - 45: Oo0Ooo - o0oOOo0O0Ooo % I1Ii111
def space ( num ) :
 II1i11i1iIi11 = ""
 for oo0O0oO0O0O in range ( num ) : II1i11i1iIi11 += "&#160;"
 return ( II1i11i1iIi11 )
 if 38 - 38: I1Ii111 % OOooOOo - OoooooooOO
 if 87 - 87: OoO0O00 % I1IiiI
 if 77 - 77: iIii1I11I1II1 - i1IIi . oO0o
 if 26 - 26: o0oOOo0O0Ooo * IiII . i1IIi
 if 59 - 59: O0 + i1IIi - o0oOOo0O0Ooo
 if 62 - 62: i11iIiiIii % OOooOOo . IiII . OOooOOo
 if 84 - 84: i11iIiiIii * OoO0O00
 if 18 - 18: OOooOOo - Ii1I - OoOoOO00 / I1Ii111 - O0
def lisp_get_ephemeral_port ( ) :
 return ( random . randrange ( 32768 , 65535 ) )
 if 30 - 30: O0 + I1ii11iIi11i + II111iiii
 if 14 - 14: o0oOOo0O0Ooo / OOooOOo - iIii1I11I1II1 - oO0o % ooOoO0o
 if 49 - 49: ooOoO0o * oO0o / o0oOOo0O0Ooo / Oo0Ooo * iIii1I11I1II1
 if 57 - 57: OoOoOO00 - oO0o / ooOoO0o % i11iIiiIii
 if 3 - 3: iII111i . ooOoO0o % I1IiiI + I1ii11iIi11i
 if 64 - 64: i1IIi
 if 29 - 29: o0oOOo0O0Ooo / i11iIiiIii / I1IiiI % oO0o % i11iIiiIii
def lisp_get_data_nonce ( ) :
 return ( random . randint ( 0 , 0xffffff ) )
 if 18 - 18: OOooOOo + I1Ii111
 if 80 - 80: oO0o + o0oOOo0O0Ooo * Ii1I + OoO0O00
 if 75 - 75: I11i / o0oOOo0O0Ooo / OOooOOo / IiII % ooOoO0o + II111iiii
 if 4 - 4: iII111i - Oo0Ooo - IiII - I11i % i11iIiiIii / OoO0O00
 if 50 - 50: ooOoO0o + i1IIi
 if 31 - 31: Ii1I
 if 78 - 78: i11iIiiIii + o0oOOo0O0Ooo + I1Ii111 / o0oOOo0O0Ooo % iIii1I11I1II1 % IiII
def lisp_get_control_nonce ( ) :
 return ( random . randint ( 0 , ( 2 ** 64 ) - 1 ) )
 if 83 - 83: iIii1I11I1II1 % OoOoOO00 % o0oOOo0O0Ooo % I1Ii111 . I1ii11iIi11i % O0
 if 47 - 47: o0oOOo0O0Ooo
 if 66 - 66: I1IiiI - IiII
 if 33 - 33: I1IiiI / OoO0O00
 if 12 - 12: II111iiii
 if 2 - 2: i1IIi - I1IiiI + I11i . II111iiii
 if 25 - 25: oO0o
 if 34 - 34: OoOoOO00 . iIii1I11I1II1 % O0
 if 43 - 43: I1ii11iIi11i - iII111i
def lisp_hex_string ( integer_value ) :
 O000O = hex ( integer_value ) [ 2 : : ]
 if ( O000O [ - 1 ] == "L" ) : O000O = O000O [ 0 : - 1 ]
 return ( O000O )
 if 98 - 98: iIii1I11I1II1 + I1Ii111 % OoOoOO00 + I11i % OoOoOO00
 if 24 - 24: oO0o * I1Ii111
 if 40 - 40: Ii1I - OoOoOO00 * OoOoOO00 . OoOoOO00 + OoooooooOO
 if 77 - 77: iIii1I11I1II1 . Ii1I % oO0o / Ii1I
 if 54 - 54: oO0o + ooOoO0o - Oo0Ooo
 if 35 - 35: Ii1I - Ii1I + i1IIi - O0 - I1Ii111
 if 58 - 58: OoOoOO00 - iII111i - OoooooooOO
def lisp_get_timestamp ( ) :
 return ( time . time ( ) )
 if 96 - 96: iIii1I11I1II1
 if 82 - 82: OoOoOO00 + O0 - IiII % oO0o * i11iIiiIii
 if 15 - 15: o0oOOo0O0Ooo
 if 39 - 39: OOooOOo / I1ii11iIi11i / I1IiiI * I1Ii111
 if 44 - 44: O0 + ooOoO0o . iIii1I11I1II1 + Oo0Ooo / O0 - I11i
 if 83 - 83: IiII * I11i / Oo0Ooo
 if 32 - 32: o0oOOo0O0Ooo + OoOoOO00 - OoooooooOO
def lisp_set_timestamp ( seconds ) :
 return ( time . time ( ) + seconds )
 if 39 - 39: OoooooooOO * OOooOOo * O0 . I11i . OoO0O00 + ooOoO0o
 if 9 - 9: OoOoOO00 + oO0o % OoooooooOO + o0oOOo0O0Ooo
 if 56 - 56: OoooooooOO + I1ii11iIi11i - iII111i
 if 24 - 24: o0oOOo0O0Ooo + ooOoO0o + I11i - iIii1I11I1II1
 if 49 - 49: I11i . ooOoO0o * OoOoOO00 % IiII . O0
 if 48 - 48: O0 * Ii1I - O0 / Ii1I + OoOoOO00
 if 52 - 52: OoO0O00 % Ii1I * II111iiii
def lisp_print_elapsed ( ts ) :
 if ( ts == 0 or ts == None ) : return ( "never" )
 I1IiIii11I = time . time ( ) - ts
 I1IiIii11I = round ( I1IiIii11I , 0 )
 return ( str ( datetime . timedelta ( seconds = I1IiIii11I ) ) )
 if 29 - 29: o0oOOo0O0Ooo
 if 86 - 86: II111iiii . IiII
 if 2 - 2: OoooooooOO
 if 60 - 60: OoO0O00
 if 81 - 81: OoOoOO00 % Ii1I
 if 87 - 87: iIii1I11I1II1 . OoooooooOO * OoOoOO00
 if 100 - 100: OoO0O00 / i1IIi - I1IiiI % Ii1I - iIii1I11I1II1
def lisp_print_future ( ts ) :
 if ( ts == 0 ) : return ( "never" )
 i11II = ts - time . time ( )
 if ( i11II < 0 ) : return ( "expired" )
 i11II = round ( i11II , 0 )
 return ( str ( datetime . timedelta ( seconds = i11II ) ) )
 if 71 - 71: IiII . I1Ii111 . OoO0O00
 if 68 - 68: i11iIiiIii % oO0o * OoO0O00 * IiII * II111iiii + O0
 if 66 - 66: I11i % I1ii11iIi11i % OoooooooOO
 if 34 - 34: o0oOOo0O0Ooo / iII111i % O0 . OoO0O00 . i1IIi
 if 29 - 29: O0 . I1Ii111
 if 66 - 66: oO0o * iIii1I11I1II1 % iIii1I11I1II1 * IiII - ooOoO0o - IiII
 if 70 - 70: I1Ii111 + oO0o
 if 93 - 93: I1Ii111 + Ii1I
 if 33 - 33: O0
 if 78 - 78: O0 / II111iiii * OoO0O00
 if 50 - 50: OoooooooOO - iIii1I11I1II1 + i1IIi % I1Ii111 - iIii1I11I1II1 % O0
 if 58 - 58: IiII + iIii1I11I1II1
 if 65 - 65: II111iiii - I1Ii111 % o0oOOo0O0Ooo - OoOoOO00 * iII111i + Ii1I
def lisp_print_eid_tuple ( eid , group ) :
 O0o0O0OO0o = eid . print_prefix ( )
 if ( group . is_null ( ) ) : return ( O0o0O0OO0o )
 if 54 - 54: OoOoOO00 . oO0o % i11iIiiIii / OoooooooOO + IiII % oO0o
 i1ii1IIiI = group . print_prefix ( )
 II1ii1ii11I1 = group . instance_id
 if 88 - 88: I1ii11iIi11i
 if ( eid . is_null ( ) or eid . is_exact_match ( group ) ) :
  Oo0oOooo000OO = i1ii1IIiI . find ( "]" ) + 1
  return ( "[{}](*, {})" . format ( II1ii1ii11I1 , i1ii1IIiI [ Oo0oOooo000OO : : ] ) )
  if 93 - 93: iIii1I11I1II1
  if 66 - 66: i11iIiiIii * iIii1I11I1II1 % OoooooooOO
 iIiI1iI1i1I = eid . print_sg ( group )
 return ( iIiI1iI1i1I )
 if 82 - 82: I1IiiI % I1ii11iIi11i * iII111i . Ii1I % I1IiiI - iIii1I11I1II1
 if 15 - 15: I1ii11iIi11i % I1Ii111 + i11iIiiIii
 if 10 - 10: Ii1I - OoOoOO00 . OoooooooOO . OOooOOo . OoO0O00 * iII111i
 if 78 - 78: oO0o / OoO0O00 - oO0o * OoooooooOO . OoOoOO00
 if 96 - 96: I1IiiI % i1IIi . o0oOOo0O0Ooo . O0
 if 37 - 37: i1IIi - OOooOOo % OoooooooOO / OOooOOo % ooOoO0o
 if 48 - 48: i11iIiiIii % oO0o
 if 29 - 29: iII111i + i11iIiiIii % I11i
def lisp_convert_6to4 ( addr_str ) :
 if ( addr_str . find ( "::ffff:" ) == - 1 ) : return ( addr_str )
 oOo00Ooo0o0 = addr_str . split ( ":" )
 return ( oOo00Ooo0o0 [ - 1 ] )
 if 33 - 33: I11i
 if 87 - 87: OoOoOO00 / IiII + iIii1I11I1II1
 if 93 - 93: iIii1I11I1II1 + oO0o % ooOoO0o
 if 21 - 21: OOooOOo
 if 6 - 6: IiII
 if 46 - 46: IiII + oO0o
 if 79 - 79: OoooooooOO - IiII * IiII . OoOoOO00
 if 100 - 100: II111iiii * I11i % I1IiiI / I1ii11iIi11i
 if 90 - 90: I1ii11iIi11i . ooOoO0o . OoOoOO00 . Ii1I
 if 4 - 4: Ii1I + OoOoOO00 % I1ii11iIi11i / i11iIiiIii
 if 74 - 74: II111iiii . O0 - I1IiiI + IiII % i11iIiiIii % OoOoOO00
def lisp_convert_4to6 ( addr_str ) :
 oOo00Ooo0o0 = lisp_address ( LISP_AFI_IPV6 , "" , 128 , 0 )
 if ( oOo00Ooo0o0 . is_ipv4_string ( addr_str ) ) : addr_str = "::ffff:" + addr_str
 oOo00Ooo0o0 . store_address ( addr_str )
 return ( oOo00Ooo0o0 )
 if 78 - 78: Ii1I + OoOoOO00 + IiII - IiII . i11iIiiIii / OoO0O00
 if 27 - 27: Ii1I - O0 % I11i * I1Ii111 . IiII % iIii1I11I1II1
 if 37 - 37: OoooooooOO + O0 - i1IIi % ooOoO0o
 if 24 - 24: OoOoOO00
 if 94 - 94: i1IIi * i1IIi % II111iiii + OOooOOo
 if 28 - 28: I1IiiI
 if 49 - 49: I11i . o0oOOo0O0Ooo % oO0o / Ii1I
 if 95 - 95: O0 * OoOoOO00 * IiII . ooOoO0o / iIii1I11I1II1
 if 28 - 28: IiII + oO0o - ooOoO0o / iIii1I11I1II1 - I1IiiI
def lisp_gethostbyname ( string ) :
 Ii1i1 = string . split ( "." )
 oOoO00 = string . split ( ":" )
 i1i = string . split ( "-" )
 if 27 - 27: Ii1I * Oo0Ooo . OoOoOO00
 if ( len ( Ii1i1 ) > 1 ) :
  if ( Ii1i1 [ 0 ] . isdigit ( ) ) : return ( string )
  if 17 - 17: II111iiii % iII111i * OOooOOo % i1IIi . I1IiiI . iIii1I11I1II1
 if ( len ( oOoO00 ) > 1 ) :
  try :
   int ( oOoO00 [ 0 ] , 16 )
   return ( string )
  except :
   pass
   if 27 - 27: i11iIiiIii - I1IiiI
   if 35 - 35: OoooooooOO - I1Ii111 / OoO0O00
   if 50 - 50: OoOoOO00
   if 33 - 33: I11i
   if 98 - 98: OoOoOO00 % II111iiii
   if 95 - 95: iIii1I11I1II1 - I1Ii111 - OOooOOo + I1Ii111 % I1ii11iIi11i . I1IiiI
   if 41 - 41: O0 + oO0o . i1IIi - II111iiii * o0oOOo0O0Ooo . OoO0O00
 if ( len ( i1i ) == 3 ) :
  for oo0O0oO0O0O in range ( 3 ) :
   try : int ( i1i [ oo0O0oO0O0O ] , 16 )
   except : break
   if 68 - 68: o0oOOo0O0Ooo
   if 20 - 20: I1Ii111 - I1Ii111
   if 37 - 37: IiII
 try :
  oOo00Ooo0o0 = socket . gethostbyname ( string )
  return ( oOo00Ooo0o0 )
 except :
  if ( lisp_is_alpine ( ) == False ) : return ( "" )
  if 37 - 37: Oo0Ooo / IiII * O0
  if 73 - 73: iII111i * iII111i / ooOoO0o
  if 43 - 43: I1ii11iIi11i . i1IIi . IiII + O0 * Ii1I * O0
  if 41 - 41: I1ii11iIi11i + Ii1I % OoooooooOO . I1ii11iIi11i + iII111i . iII111i
  if 31 - 31: i11iIiiIii + II111iiii . iII111i * OoOoOO00
 try :
  oOo00Ooo0o0 = socket . getaddrinfo ( string , 0 ) [ 0 ]
  if ( oOo00Ooo0o0 [ 3 ] != string ) : return ( "" )
  oOo00Ooo0o0 = oOo00Ooo0o0 [ 4 ] [ 0 ]
 except :
  oOo00Ooo0o0 = ""
  if 66 - 66: OoOoOO00 + i1IIi % II111iiii . O0 * I1ii11iIi11i % I1ii11iIi11i
 return ( oOo00Ooo0o0 )
 if 87 - 87: OOooOOo + o0oOOo0O0Ooo . iII111i - OoooooooOO
 if 6 - 6: iIii1I11I1II1 * OoooooooOO
 if 28 - 28: Oo0Ooo * o0oOOo0O0Ooo / I1Ii111
 if 52 - 52: O0 / o0oOOo0O0Ooo % iII111i * I1IiiI % OOooOOo
 if 69 - 69: I1ii11iIi11i
 if 83 - 83: o0oOOo0O0Ooo
 if 38 - 38: I1Ii111 + OoooooooOO . i1IIi
 if 19 - 19: iII111i - o0oOOo0O0Ooo - Ii1I - OoOoOO00 . iII111i . I1Ii111
def lisp_ip_checksum ( data ) :
 if ( len ( data ) < 20 ) :
  lprint ( "IPv4 packet too short, length {}" . format ( len ( data ) ) )
  return ( data )
  if 48 - 48: iII111i + IiII
  if 60 - 60: I11i + iII111i . IiII / i1IIi . iIii1I11I1II1
 i1i11ii1Ii = binascii . hexlify ( data )
 if 12 - 12: OOooOOo . Ii1I
 if 79 - 79: I1Ii111 / Oo0Ooo / iII111i . I1Ii111 * OoooooooOO + o0oOOo0O0Ooo
 if 73 - 73: O0 - I1ii11iIi11i
 if 2 - 2: II111iiii / I1Ii111
 OoO = 0
 for oo0O0oO0O0O in range ( 0 , 40 , 4 ) :
  OoO += int ( i1i11ii1Ii [ oo0O0oO0O0O : oo0O0oO0O0O + 4 ] , 16 )
  if 71 - 71: OoO0O00 - OoooooooOO * Oo0Ooo
  if 38 - 38: iIii1I11I1II1 / ooOoO0o
  if 13 - 13: iIii1I11I1II1
  if 77 - 77: i11iIiiIii - iIii1I11I1II1 / oO0o / ooOoO0o / OoO0O00
  if 56 - 56: OoooooooOO * O0
 OoO = ( OoO >> 16 ) + ( OoO & 0xffff )
 OoO += OoO >> 16
 OoO = socket . htons ( ~ OoO & 0xffff )
 if 85 - 85: OoooooooOO % OoOoOO00 * iIii1I11I1II1
 if 44 - 44: iIii1I11I1II1 . I1ii11iIi11i + I1Ii111 . ooOoO0o
 if 7 - 7: I1ii11iIi11i + iIii1I11I1II1 * I11i * I11i / II111iiii - Ii1I
 if 65 - 65: oO0o + OoOoOO00 + II111iiii
 OoO = struct . pack ( "H" , OoO )
 i1i11ii1Ii = data [ 0 : 10 ] + OoO + data [ 12 : : ]
 return ( i1i11ii1Ii )
 if 77 - 77: II111iiii
 if 50 - 50: O0 . O0 . ooOoO0o % Oo0Ooo
 if 68 - 68: oO0o
 if 10 - 10: Ii1I
 if 77 - 77: OOooOOo / II111iiii + IiII + ooOoO0o - i11iIiiIii
 if 44 - 44: I1IiiI + OoOoOO00 + I1ii11iIi11i . I1IiiI * OoOoOO00 % iIii1I11I1II1
 if 72 - 72: OOooOOo . OOooOOo - I1ii11iIi11i
 if 48 - 48: Oo0Ooo - ooOoO0o + Oo0Ooo - I1IiiI * i11iIiiIii . iII111i
def lisp_icmp_checksum ( data ) :
 if ( len ( data ) < 36 ) :
  lprint ( "ICMP packet too short, length {}" . format ( len ( data ) ) )
  return ( data )
  if 35 - 35: IiII . O0 + Oo0Ooo + OOooOOo + i1IIi
  if 65 - 65: O0 * I1IiiI / I1IiiI . OoOoOO00
 Oo0O0OOO0o0O = binascii . hexlify ( data )
 if 51 - 51: oO0o + OoO0O00 + iII111i + iII111i % o0oOOo0O0Ooo
 if 29 - 29: ooOoO0o
 if 41 - 41: O0 % iII111i
 if 10 - 10: iII111i . i1IIi + Ii1I
 OoO = 0
 for oo0O0oO0O0O in range ( 0 , 36 , 4 ) :
  OoO += int ( Oo0O0OOO0o0O [ oo0O0oO0O0O : oo0O0oO0O0O + 4 ] , 16 )
  if 66 - 66: OoO0O00 % o0oOOo0O0Ooo
  if 21 - 21: OoOoOO00 - OoooooooOO % i11iIiiIii
  if 71 - 71: i1IIi - I11i * I1Ii111 + oO0o - OoO0O00 % I1ii11iIi11i
  if 63 - 63: iIii1I11I1II1 + OOooOOo . OoO0O00 / I1IiiI
  if 84 - 84: i1IIi
 OoO = ( OoO >> 16 ) + ( OoO & 0xffff )
 OoO += OoO >> 16
 OoO = socket . htons ( ~ OoO & 0xffff )
 if 42 - 42: II111iiii - OoO0O00 - OoooooooOO . iII111i / OoOoOO00
 if 56 - 56: i11iIiiIii - iIii1I11I1II1 . II111iiii
 if 81 - 81: IiII / OoOoOO00 * IiII . O0
 if 61 - 61: OoO0O00 * OOooOOo + I1Ii111 . iIii1I11I1II1 % I11i . I1Ii111
 OoO = struct . pack ( "H" , OoO )
 Oo0O0OOO0o0O = data [ 0 : 2 ] + OoO + data [ 4 : : ]
 return ( Oo0O0OOO0o0O )
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
 if 86 - 86: Ii1I
 if 29 - 29: iIii1I11I1II1 - OoO0O00 + I1IiiI % iIii1I11I1II1 % OOooOOo
 if 84 - 84: IiII + I1ii11iIi11i + Ii1I + iII111i
def lisp_udp_checksum ( source , dest , data ) :
 if 62 - 62: i11iIiiIii + OoOoOO00 + i1IIi
 if 69 - 69: OoOoOO00
 if 63 - 63: OoO0O00 / OoOoOO00 * iIii1I11I1II1 . I1Ii111
 if 85 - 85: i11iIiiIii / i11iIiiIii . OoO0O00 . O0
 oOOOOOOOoO = lisp_address ( LISP_AFI_IPV6 , source , LISP_IPV6_HOST_MASK_LEN , 0 )
 OooOo = lisp_address ( LISP_AFI_IPV6 , dest , LISP_IPV6_HOST_MASK_LEN , 0 )
 oOo0 = socket . htonl ( len ( data ) )
 I1Ii11i = socket . htonl ( LISP_UDP_PROTOCOL )
 I1iIiiiI1 = oOOOOOOOoO . pack_address ( )
 I1iIiiiI1 += OooOo . pack_address ( )
 I1iIiiiI1 += struct . pack ( "II" , oOo0 , I1Ii11i )
 if 87 - 87: OoOoOO00 - ooOoO0o - OOooOOo + Oo0Ooo % iIii1I11I1II1 / i11iIiiIii
 if 12 - 12: ooOoO0o
 if 86 - 86: oO0o - OoO0O00
 if 63 - 63: I1IiiI / OoOoOO00 + OoooooooOO . I11i . ooOoO0o
 IiI1iiI11 = binascii . hexlify ( I1iIiiiI1 + data )
 OOoOOOO00 = len ( IiI1iiI11 ) % 4
 for oo0O0oO0O0O in range ( 0 , OOoOOOO00 ) : IiI1iiI11 += "0"
 if 49 - 49: OoO0O00 - O0 / OoO0O00 * OoOoOO00 + I1Ii111
 if 35 - 35: II111iiii . I1IiiI / i1IIi / I1IiiI * oO0o
 if 85 - 85: II111iiii . ooOoO0o % OOooOOo % I11i
 if 80 - 80: oO0o * I11i / iIii1I11I1II1 % oO0o / iIii1I11I1II1
 OoO = 0
 for oo0O0oO0O0O in range ( 0 , len ( IiI1iiI11 ) , 4 ) :
  OoO += int ( IiI1iiI11 [ oo0O0oO0O0O : oo0O0oO0O0O + 4 ] , 16 )
  if 42 - 42: i1IIi / i11iIiiIii . Oo0Ooo * iII111i . i11iIiiIii * O0
  if 44 - 44: i1IIi . I1IiiI / i11iIiiIii + IiII
  if 27 - 27: OOooOOo
  if 52 - 52: I1Ii111 % OoOoOO00 + iIii1I11I1II1 * oO0o . Ii1I
  if 95 - 95: iIii1I11I1II1 . IiII - OoooooooOO * OoO0O00 / o0oOOo0O0Ooo
 OoO = ( OoO >> 16 ) + ( OoO & 0xffff )
 OoO += OoO >> 16
 OoO = socket . htons ( ~ OoO & 0xffff )
 if 74 - 74: oO0o
 if 34 - 34: iII111i
 if 44 - 44: i1IIi % I1IiiI % o0oOOo0O0Ooo
 if 9 - 9: Oo0Ooo % OoooooooOO - Ii1I
 OoO = struct . pack ( "H" , OoO )
 IiI1iiI11 = data [ 0 : 6 ] + OoO + data [ 8 : : ]
 return ( IiI1iiI11 )
 if 43 - 43: OoO0O00 % OoO0O00
 if 46 - 46: Oo0Ooo % iIii1I11I1II1 . iII111i . O0 * ooOoO0o / OoooooooOO
 if 7 - 7: oO0o - O0 * I11i - o0oOOo0O0Ooo - II111iiii
 if 41 - 41: I1IiiI - I1Ii111 % II111iiii . I1Ii111 - I11i
 if 45 - 45: Ii1I - OOooOOo
 if 70 - 70: OoO0O00 % I1IiiI / I1IiiI . I11i % ooOoO0o . II111iiii
 if 10 - 10: Ii1I - i11iIiiIii . I1ii11iIi11i % i1IIi
def lisp_get_interface_address ( device ) :
 if 78 - 78: iIii1I11I1II1 * Oo0Ooo . Oo0Ooo - OOooOOo . iIii1I11I1II1
 if 30 - 30: ooOoO0o + ooOoO0o % IiII - o0oOOo0O0Ooo - I1ii11iIi11i
 if 36 - 36: I11i % OOooOOo
 if 72 - 72: I1IiiI / iII111i - O0 + I11i
 if ( device not in netifaces . interfaces ( ) ) : return ( None )
 if 83 - 83: O0
 if 89 - 89: Oo0Ooo + I1ii11iIi11i - o0oOOo0O0Ooo
 if 40 - 40: OoO0O00 + OoO0O00
 if 94 - 94: iII111i * iIii1I11I1II1 . I11i
 IiiI11I1IIiI = netifaces . ifaddresses ( device )
 if ( IiiI11I1IIiI . has_key ( netifaces . AF_INET ) == False ) : return ( None )
 if 5 - 5: Oo0Ooo
 if 100 - 100: Ii1I + iIii1I11I1II1
 if 59 - 59: IiII
 if 89 - 89: OoOoOO00 % iIii1I11I1II1
 III11I1 = lisp_address ( LISP_AFI_IPV4 , "" , 32 , 0 )
 if 61 - 61: OoOoOO00 - OoO0O00 + I1IiiI * OOooOOo % OoO0O00
 for oOo00Ooo0o0 in IiiI11I1IIiI [ netifaces . AF_INET ] :
  i111I11I = oOo00Ooo0o0 [ "addr" ]
  III11I1 . store_address ( i111I11I )
  return ( III11I1 )
  if 80 - 80: iIii1I11I1II1 - OoooooooOO - I1ii11iIi11i - I1ii11iIi11i . OoooooooOO
 return ( None )
 if 48 - 48: I1Ii111 . i11iIiiIii / i1IIi % IiII % iII111i + oO0o
 if 41 - 41: IiII
 if 3 - 3: IiII + II111iiii / iIii1I11I1II1
 if 10 - 10: II111iiii . O0
 if 31 - 31: oO0o / i11iIiiIii / O0
 if 39 - 39: I1IiiI + Oo0Ooo
 if 83 - 83: i1IIi
 if 76 - 76: Ii1I + iIii1I11I1II1 + OoOoOO00 . OoO0O00
 if 49 - 49: IiII / ooOoO0o / OOooOOo
 if 25 - 25: I1IiiI % O0 + i1IIi - ooOoO0o
 if 38 - 38: o0oOOo0O0Ooo % I1Ii111 + i11iIiiIii + iII111i + ooOoO0o / i11iIiiIii
 if 94 - 94: iII111i - Oo0Ooo + oO0o
def lisp_get_input_interface ( packet ) :
 O0oooOoO = lisp_format_packet ( packet [ 0 : 12 ] ) . replace ( " " , "" )
 O0Oo0 = O0oooOoO [ 0 : 12 ]
 iIIIi1IiI11I1 = O0oooOoO [ 12 : : ]
 if 71 - 71: Ii1I - O0 - iII111i . OOooOOo % Oo0Ooo
 try : Oo00oO = lisp_mymacs . has_key ( iIIIi1IiI11I1 )
 except : Oo00oO = False
 if 94 - 94: i11iIiiIii / I1Ii111 / Oo0Ooo
 if ( lisp_mymacs . has_key ( O0Oo0 ) ) : return ( lisp_mymacs [ O0Oo0 ] , iIIIi1IiI11I1 , O0Oo0 , Oo00oO )
 if ( Oo00oO ) : return ( lisp_mymacs [ iIIIi1IiI11I1 ] , iIIIi1IiI11I1 , O0Oo0 , Oo00oO )
 return ( [ "?" ] , iIIIi1IiI11I1 , O0Oo0 , Oo00oO )
 if 9 - 9: I11i / OoOoOO00 / II111iiii + I1Ii111
 if 71 - 71: iII111i / Oo0Ooo
 if 87 - 87: I1ii11iIi11i + I1ii11iIi11i - I1ii11iIi11i % O0
 if 13 - 13: II111iiii
 if 57 - 57: Ii1I - OoooooooOO
 if 68 - 68: o0oOOo0O0Ooo % I1ii11iIi11i / I1Ii111 + I1Ii111 - I1Ii111 . OoO0O00
 if 100 - 100: OoOoOO00 % Oo0Ooo
 if 76 - 76: II111iiii / OoO0O00 + OoooooooOO . I1ii11iIi11i . I11i . ooOoO0o
def lisp_get_local_interfaces ( ) :
 for iiiIiIIIiiiIiI1 in netifaces . interfaces ( ) :
  O0OOoooo0 = lisp_interface ( iiiIiIIIiiiIiI1 )
  O0OOoooo0 . add_interface ( )
  if 7 - 7: I1Ii111
 return
 if 45 - 45: O0 - OOooOOo
 if 56 - 56: O0 + Ii1I
 if 24 - 24: i11iIiiIii - Ii1I + oO0o * I1IiiI
 if 94 - 94: I1IiiI + iIii1I11I1II1 / O0 - OoooooooOO % I1ii11iIi11i
 if 64 - 64: I11i + OoO0O00
 if 25 - 25: I1IiiI . ooOoO0o + I1IiiI % Ii1I * iIii1I11I1II1
 if 31 - 31: i11iIiiIii + OOooOOo - O0
def lisp_get_loopback_address ( ) :
 for oOo00Ooo0o0 in netifaces . ifaddresses ( "lo" ) [ netifaces . AF_INET ] :
  if ( oOo00Ooo0o0 [ "peer" ] == "127.0.0.1" ) : continue
  return ( oOo00Ooo0o0 [ "peer" ] )
  if 51 - 51: OoO0O00 * i1IIi / Ii1I * OOooOOo + ooOoO0o % I1ii11iIi11i
 return ( None )
 if 34 - 34: oO0o * OoooooooOO + Ii1I + i11iIiiIii
 if 22 - 22: i1IIi
 if 24 - 24: I11i / I1IiiI * i1IIi % OoooooooOO
 if 99 - 99: i11iIiiIii . II111iiii . OoooooooOO
 if 59 - 59: i11iIiiIii . OoooooooOO / I11i * I1ii11iIi11i + OoooooooOO
 if 3 - 3: i11iIiiIii * Oo0Ooo % iIii1I11I1II1 % I1IiiI * iII111i / OOooOOo
 if 95 - 95: IiII * O0 * I1Ii111 . OoooooooOO % Oo0Ooo + I1ii11iIi11i
 if 98 - 98: oO0o . OoooooooOO
def lisp_is_mac_string ( mac_str ) :
 i1i = mac_str . split ( "/" )
 if ( len ( i1i ) == 2 ) : mac_str = i1i [ 0 ]
 return ( len ( mac_str ) == 14 and mac_str . count ( "-" ) == 2 )
 if 54 - 54: O0 / IiII % ooOoO0o * i1IIi * O0
 if 48 - 48: o0oOOo0O0Ooo . oO0o % OoOoOO00 - OoOoOO00
 if 33 - 33: I11i % II111iiii + OoO0O00
 if 93 - 93: i1IIi . IiII / I1IiiI + IiII
 if 58 - 58: I1ii11iIi11i + O0 . Oo0Ooo + OoOoOO00 - OoO0O00 - OoOoOO00
 if 41 - 41: Oo0Ooo / i1IIi / Oo0Ooo - iII111i . o0oOOo0O0Ooo
 if 65 - 65: O0 * i11iIiiIii . OoooooooOO / I1IiiI / iII111i
 if 69 - 69: ooOoO0o % ooOoO0o
def lisp_get_local_macs ( ) :
 for iiiIiIIIiiiIiI1 in netifaces . interfaces ( ) :
  if 76 - 76: i11iIiiIii * iII111i / OoO0O00 % I1ii11iIi11i + OOooOOo
  if 48 - 48: iIii1I11I1II1 % i1IIi + OoOoOO00 % o0oOOo0O0Ooo
  if 79 - 79: OoOoOO00 % I1IiiI % Ii1I / i1IIi % OoO0O00
  if 56 - 56: iIii1I11I1II1 - i11iIiiIii * iII111i
  if 84 - 84: OOooOOo + Ii1I + o0oOOo0O0Ooo
  OooOo = iiiIiIIIiiiIiI1 . replace ( ":" , "" )
  OooOo = iiiIiIIIiiiIiI1 . replace ( "-" , "" )
  if ( OooOo . isalnum ( ) == False ) : continue
  if 33 - 33: Ii1I
  if 93 - 93: ooOoO0o
  if 34 - 34: oO0o - ooOoO0o * Oo0Ooo / o0oOOo0O0Ooo
  if 19 - 19: I1ii11iIi11i
  if 46 - 46: iIii1I11I1II1 . i11iIiiIii - OoOoOO00 % O0 / II111iiii * i1IIi
  try :
   oO = netifaces . ifaddresses ( iiiIiIIIiiiIiI1 )
  except :
   continue
   if 18 - 18: OoooooooOO + o0oOOo0O0Ooo . O0 + IiII * i1IIi . OoO0O00
  if ( oO . has_key ( netifaces . AF_LINK ) == False ) : continue
  i1i = oO [ netifaces . AF_LINK ] [ 0 ] [ "addr" ]
  i1i = i1i . replace ( ":" , "" )
  if 71 - 71: I1Ii111 - o0oOOo0O0Ooo - OOooOOo
  if 28 - 28: iIii1I11I1II1
  if 7 - 7: o0oOOo0O0Ooo % IiII * OoOoOO00
  if 58 - 58: IiII / I11i + II111iiii % iII111i - OoooooooOO
  if 25 - 25: OoOoOO00 % OoooooooOO * Oo0Ooo - i1IIi * II111iiii * oO0o
  if ( len ( i1i ) < 12 ) : continue
  if 30 - 30: I11i % OoOoOO00 / I1ii11iIi11i * O0 * Ii1I . I1IiiI
  if ( lisp_mymacs . has_key ( i1i ) == False ) : lisp_mymacs [ i1i ] = [ ]
  lisp_mymacs [ i1i ] . append ( iiiIiIIIiiiIiI1 )
  if 46 - 46: OoOoOO00 - O0
  if 70 - 70: I11i + Oo0Ooo * iIii1I11I1II1 . I1IiiI * I11i
 lprint ( "Local MACs are: {}" . format ( lisp_mymacs ) )
 return
 if 49 - 49: o0oOOo0O0Ooo
 if 25 - 25: iII111i . OoooooooOO * iIii1I11I1II1 . o0oOOo0O0Ooo / O0 + Ii1I
 if 68 - 68: Oo0Ooo
 if 22 - 22: OOooOOo
 if 22 - 22: iII111i * I11i - Oo0Ooo * O0 / i11iIiiIii
 if 78 - 78: Oo0Ooo * O0 / ooOoO0o + OoooooooOO + OOooOOo
 if 23 - 23: iII111i % OoooooooOO / iIii1I11I1II1 + I1ii11iIi11i / i1IIi / o0oOOo0O0Ooo
 if 94 - 94: i1IIi
def lisp_get_local_rloc ( ) :
 iiIIi1 = commands . getoutput ( "netstat -rn | egrep 'default|0.0.0.0'" )
 if ( iiIIi1 == "" ) : return ( lisp_address ( LISP_AFI_IPV4 , "" , 32 , 0 ) )
 if 65 - 65: i1IIi . I1ii11iIi11i / ooOoO0o
 if 11 - 11: IiII * ooOoO0o / ooOoO0o - OOooOOo
 if 68 - 68: I1IiiI % IiII - IiII / I1IiiI + I1ii11iIi11i - Oo0Ooo
 if 65 - 65: ooOoO0o - i1IIi
 iiIIi1 = iiIIi1 . split ( "\n" ) [ 0 ]
 iiiIiIIIiiiIiI1 = iiIIi1 . split ( ) [ - 1 ]
 if 62 - 62: I11i / oO0o % Oo0Ooo . OoooooooOO / i11iIiiIii / I1Ii111
 oOo00Ooo0o0 = ""
 OooO0O0Ooo = lisp_is_macos ( )
 if ( OooO0O0Ooo ) :
  iiIIi1 = commands . getoutput ( "ifconfig {} | egrep 'inet '" . format ( iiiIiIIIiiiIiI1 ) )
  if ( iiIIi1 == "" ) : return ( lisp_address ( LISP_AFI_IPV4 , "" , 32 , 0 ) )
 else :
  oO0O = 'ip addr show | egrep "inet " | egrep "{}"' . format ( iiiIiIIIiiiIiI1 )
  iiIIi1 = commands . getoutput ( oO0O )
  if ( iiIIi1 == "" ) :
   oO0O = 'ip addr show | egrep "inet " | egrep "global lo"'
   iiIIi1 = commands . getoutput ( oO0O )
   if 25 - 25: oO0o % I1IiiI + i11iIiiIii + O0 * OoooooooOO
  if ( iiIIi1 == "" ) : return ( lisp_address ( LISP_AFI_IPV4 , "" , 32 , 0 ) )
  if 64 - 64: i1IIi
  if 10 - 10: I1Ii111 % O0 / I1IiiI % I11i
  if 25 - 25: II111iiii / OoO0O00
  if 64 - 64: O0 % ooOoO0o
  if 40 - 40: o0oOOo0O0Ooo + I11i
  if 77 - 77: i11iIiiIii % IiII + I1Ii111 % OoooooooOO - I11i
 oOo00Ooo0o0 = ""
 iiIIi1 = iiIIi1 . split ( "\n" )
 if 26 - 26: Oo0Ooo + O0 - iIii1I11I1II1
 for iiI1 in iiIIi1 :
  i1 = iiI1 . split ( ) [ 1 ]
  if ( OooO0O0Ooo == False ) : i1 = i1 . split ( "/" ) [ 0 ]
  I1IIIIIi1IIiI = lisp_address ( LISP_AFI_IPV4 , i1 , 32 , 0 )
  return ( I1IIIIIi1IIiI )
  if 26 - 26: o0oOOo0O0Ooo % OOooOOo + OOooOOo % I11i * i11iIiiIii / iII111i
 return ( lisp_address ( LISP_AFI_IPV4 , oOo00Ooo0o0 , 32 , 0 ) )
 if 64 - 64: oO0o % OoOoOO00 / II111iiii % ooOoO0o - iII111i
 if 2 - 2: I1Ii111 - I1ii11iIi11i + o0oOOo0O0Ooo * OoO0O00 / iII111i
 if 26 - 26: OOooOOo * Oo0Ooo
 if 31 - 31: I11i * oO0o . Ii1I
 if 35 - 35: I11i
 if 94 - 94: ooOoO0o / i11iIiiIii % O0
 if 70 - 70: I11i - Oo0Ooo / OoooooooOO % OoooooooOO
 if 95 - 95: OoooooooOO % OoooooooOO . Ii1I
 if 26 - 26: oO0o + IiII - II111iiii . II111iiii + I1ii11iIi11i + OoOoOO00
 if 68 - 68: O0
 if 76 - 76: I1ii11iIi11i
def lisp_get_local_addresses ( ) :
 global lisp_myrlocs
 if 99 - 99: o0oOOo0O0Ooo
 if 1 - 1: Ii1I * OoOoOO00 * OoO0O00 + Oo0Ooo
 if 90 - 90: I1Ii111 % Oo0Ooo - Oo0Ooo . iIii1I11I1II1 / OOooOOo + I11i
 if 89 - 89: oO0o
 if 87 - 87: iII111i % Oo0Ooo
 if 62 - 62: OoO0O00 + ooOoO0o / iII111i * i11iIiiIii
 if 37 - 37: iII111i
 if 33 - 33: OoO0O00 - O0 - OoO0O00
 if 94 - 94: IiII * I11i * OoooooooOO / o0oOOo0O0Ooo . IiII - o0oOOo0O0Ooo
 if 13 - 13: OOooOOo / IiII - OoO0O00 / OOooOOo . i1IIi
 IiI1i111i = None
 Oo0oOooo000OO = 1
 iiiI1i1111II = os . getenv ( "LISP_ADDR_SELECT" )
 if ( iiiI1i1111II != None and iiiI1i1111II != "" ) :
  iiiI1i1111II = iiiI1i1111II . split ( ":" )
  if ( len ( iiiI1i1111II ) == 2 ) :
   IiI1i111i = iiiI1i1111II [ 0 ]
   Oo0oOooo000OO = iiiI1i1111II [ 1 ]
  else :
   if ( iiiI1i1111II [ 0 ] . isdigit ( ) ) :
    Oo0oOooo000OO = iiiI1i1111II [ 0 ]
   else :
    IiI1i111i = iiiI1i1111II [ 0 ]
    if 38 - 38: Oo0Ooo % I1ii11iIi11i - iII111i * iIii1I11I1II1 / O0
    if 9 - 9: I11i * Oo0Ooo . ooOoO0o * i11iIiiIii - O0
  Oo0oOooo000OO = 1 if ( Oo0oOooo000OO == "" ) else int ( Oo0oOooo000OO )
  if 54 - 54: I1IiiI * OOooOOo + o0oOOo0O0Ooo % i1IIi - o0oOOo0O0Ooo + OoOoOO00
  if 15 - 15: OoOoOO00 * oO0o + OOooOOo . I11i % I1IiiI - ooOoO0o
 II1I1I1i1i = [ None , None , None ]
 Oo0oOO0O00 = lisp_address ( LISP_AFI_IPV4 , "" , 32 , 0 )
 o00OOo0o0O = lisp_address ( LISP_AFI_IPV6 , "" , 128 , 0 )
 I111Iii1 = None
 if 30 - 30: i1IIi
 for iiiIiIIIiiiIiI1 in netifaces . interfaces ( ) :
  if ( IiI1i111i != None and IiI1i111i != iiiIiIIIiiiIiI1 ) : continue
  IiiI11I1IIiI = netifaces . ifaddresses ( iiiIiIIIiiiIiI1 )
  if ( IiiI11I1IIiI == { } ) : continue
  if 75 - 75: I11i . OOooOOo - iIii1I11I1II1 * OoO0O00 * iII111i
  if 93 - 93: ooOoO0o
  if 18 - 18: ooOoO0o
  if 66 - 66: oO0o * i11iIiiIii + OoOoOO00 / OOooOOo
  I111Iii1 = lisp_get_interface_instance_id ( iiiIiIIIiiiIiI1 , None )
  if 96 - 96: OOooOOo + OOooOOo % IiII % OOooOOo
  if 28 - 28: iIii1I11I1II1 + OoOoOO00 . o0oOOo0O0Ooo % i11iIiiIii
  if 58 - 58: I11i / OoooooooOO % oO0o + OoO0O00
  if 58 - 58: O0
  if ( IiiI11I1IIiI . has_key ( netifaces . AF_INET ) ) :
   Ii1i1 = IiiI11I1IIiI [ netifaces . AF_INET ]
   O0oO = 0
   for oOo00Ooo0o0 in Ii1i1 :
    Oo0oOO0O00 . store_address ( oOo00Ooo0o0 [ "addr" ] )
    if ( Oo0oOO0O00 . is_ipv4_loopback ( ) ) : continue
    if ( Oo0oOO0O00 . is_ipv4_link_local ( ) ) : continue
    if ( Oo0oOO0O00 . address == 0 ) : continue
    O0oO += 1
    Oo0oOO0O00 . instance_id = I111Iii1
    if ( IiI1i111i == None and
 lisp_db_for_lookups . lookup_cache ( Oo0oOO0O00 , False ) ) : continue
    II1I1I1i1i [ 0 ] = Oo0oOO0O00
    if ( O0oO == Oo0oOooo000OO ) : break
    if 54 - 54: o0oOOo0O0Ooo + I11i - iIii1I11I1II1 % ooOoO0o % IiII
    if 19 - 19: I1ii11iIi11i / iIii1I11I1II1 % i1IIi . OoooooooOO
  if ( IiiI11I1IIiI . has_key ( netifaces . AF_INET6 ) ) :
   oOoO00 = IiiI11I1IIiI [ netifaces . AF_INET6 ]
   O0oO = 0
   for oOo00Ooo0o0 in oOoO00 :
    i111I11I = oOo00Ooo0o0 [ "addr" ]
    o00OOo0o0O . store_address ( i111I11I )
    if ( o00OOo0o0O . is_ipv6_string_link_local ( i111I11I ) ) : continue
    if ( o00OOo0o0O . is_ipv6_loopback ( ) ) : continue
    O0oO += 1
    o00OOo0o0O . instance_id = I111Iii1
    if ( IiI1i111i == None and
 lisp_db_for_lookups . lookup_cache ( o00OOo0o0O , False ) ) : continue
    II1I1I1i1i [ 1 ] = o00OOo0o0O
    if ( O0oO == Oo0oOooo000OO ) : break
    if 57 - 57: ooOoO0o . Oo0Ooo - OoO0O00 - i11iIiiIii * I1Ii111 / o0oOOo0O0Ooo
    if 79 - 79: I1ii11iIi11i + o0oOOo0O0Ooo % Oo0Ooo * o0oOOo0O0Ooo
    if 21 - 21: iII111i
    if 24 - 24: iII111i / ooOoO0o
    if 61 - 61: iIii1I11I1II1 + oO0o
    if 8 - 8: I1Ii111 + OoO0O00
  if ( II1I1I1i1i [ 0 ] == None ) : continue
  if 9 - 9: OOooOOo + o0oOOo0O0Ooo
  II1I1I1i1i [ 2 ] = iiiIiIIIiiiIiI1
  break
  if 8 - 8: OOooOOo * Oo0Ooo / iII111i - OoO0O00 - OoooooooOO
  if 100 - 100: oO0o . iIii1I11I1II1 . iIii1I11I1II1
 oOOo0ooO0 = II1I1I1i1i [ 0 ] . print_address_no_iid ( ) if II1I1I1i1i [ 0 ] else "none"
 ii1i1II11II1i = II1I1I1i1i [ 1 ] . print_address_no_iid ( ) if II1I1I1i1i [ 1 ] else "none"
 iiiIiIIIiiiIiI1 = II1I1I1i1i [ 2 ] if II1I1I1i1i [ 2 ] else "none"
 if 95 - 95: I11i + o0oOOo0O0Ooo * I1ii11iIi11i
 IiI1i111i = " (user selected)" if IiI1i111i != None else ""
 if 85 - 85: i11iIiiIii . OoooooooOO - iIii1I11I1II1
 oOOo0ooO0 = red ( oOOo0ooO0 , False )
 ii1i1II11II1i = red ( ii1i1II11II1i , False )
 iiiIiIIIiiiIiI1 = bold ( iiiIiIIIiiiIiI1 , False )
 lprint ( "Local addresses are IPv4: {}, IPv6: {} from device {}{}, iid {}" . format ( oOOo0ooO0 , ii1i1II11II1i , iiiIiIIIiiiIiI1 , IiI1i111i , I111Iii1 ) )
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
 for O0OOoooo0 in netifaces . interfaces ( ) :
  try : iiIiiIi = netifaces . ifaddresses ( O0OOoooo0 )
  except : continue
  if 66 - 66: II111iiii + OoO0O00
  if ( iiIiiIi . has_key ( netifaces . AF_INET ) ) :
   for oOo00Ooo0o0 in iiIiiIi [ netifaces . AF_INET ] :
    i1 = oOo00Ooo0o0 [ "addr" ]
    if ( i1 . find ( "127.0.0.1" ) != - 1 ) : continue
    iIIIiIi1i . append ( i1 )
    if 19 - 19: OoO0O00 . OoooooooOO * OoO0O00 + IiII + OoooooooOO
    if 19 - 19: Oo0Ooo
  if ( iiIiiIi . has_key ( netifaces . AF_INET6 ) ) :
   for oOo00Ooo0o0 in iiIiiIi [ netifaces . AF_INET6 ] :
    i1 = oOo00Ooo0o0 [ "addr" ]
    if ( i1 == "::1" ) : continue
    if ( i1 [ 0 : 5 ] == "fe80:" ) : continue
    iIIIiIi1i . append ( i1 )
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
 II1i = [ ]
 iiIIi1 = commands . getoutput ( 'egrep "rle-address =" ./lisp.config' )
 if ( iiIIi1 == "" ) : return ( II1i )
 if 75 - 75: I1ii11iIi11i
 O00o = iiIIi1 . split ( "\n" )
 for iiI1 in O00o :
  if ( iiI1 [ 0 ] == "#" ) : continue
  o0o0ooOo00 = iiI1 . split ( "rle-address = " ) [ 1 ]
  OO00oO0OoO0o = int ( o0o0ooOo00 . split ( "." ) [ 0 ] )
  if ( OO00oO0OoO0o >= 224 and OO00oO0OoO0o < 240 ) : II1i . append ( o0o0ooOo00 )
  if 5 - 5: OOooOOo % Oo0Ooo % IiII % ooOoO0o
 return ( II1i )
 if 17 - 17: Ii1I + II111iiii + OoooooooOO / OOooOOo / IiII
 if 80 - 80: o0oOOo0O0Ooo % i1IIi / I11i
 if 56 - 56: i1IIi . i11iIiiIii
 if 15 - 15: II111iiii * oO0o % iII111i / i11iIiiIii - oO0o + Oo0Ooo
 if 9 - 9: I11i - oO0o + O0 / iII111i % i1IIi
 if 97 - 97: o0oOOo0O0Ooo * ooOoO0o
 if 78 - 78: I11i . OOooOOo + oO0o * iII111i - i1IIi
 if 27 - 27: Ii1I % i1IIi . Oo0Ooo % I1Ii111
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
  if 10 - 10: IiII / OoooooooOO
  if 50 - 50: i11iIiiIii - OoooooooOO . oO0o + O0 . i1IIi
 def encode ( self , nonce ) :
  if 91 - 91: o0oOOo0O0Ooo . iII111i % Oo0Ooo - iII111i . oO0o % i11iIiiIii
  if 25 - 25: iIii1I11I1II1
  if 63 - 63: ooOoO0o
  if 96 - 96: I11i
  if 34 - 34: OoOoOO00 / OoO0O00 - I1IiiI . O0 . OOooOOo
  if ( self . outer_source . is_null ( ) ) : return ( None )
  if 63 - 63: iII111i
  if 11 - 11: iII111i - iIii1I11I1II1
  if 92 - 92: OoO0O00
  if 15 - 15: IiII / IiII + iIii1I11I1II1 % OoooooooOO
  if 12 - 12: ooOoO0o
  if 36 - 36: I1Ii111 . IiII * OoooooooOO - o0oOOo0O0Ooo
  if ( nonce == None ) :
   self . lisp_header . nonce ( lisp_get_data_nonce ( ) )
  elif ( self . lisp_header . is_request_nonce ( nonce ) ) :
   self . lisp_header . request_nonce ( nonce )
  else :
   self . lisp_header . nonce ( nonce )
   if 60 - 60: OOooOOo . iII111i / iIii1I11I1II1 + OOooOOo * I1Ii111
  self . lisp_header . instance_id ( self . inner_dest . instance_id )
  if 82 - 82: i11iIiiIii . iIii1I11I1II1 * I1IiiI - I11i + Ii1I
  if 48 - 48: I1ii11iIi11i
  if 96 - 96: ooOoO0o . OoooooooOO
  if 39 - 39: OOooOOo + OoO0O00
  if 80 - 80: OOooOOo % OoO0O00 / OoOoOO00
  if 54 - 54: Oo0Ooo % OoO0O00 - OOooOOo - I11i
  self . lisp_header . key_id ( 0 )
  o0 = ( self . lisp_header . get_instance_id ( ) == 0xffffff )
  if ( lisp_data_plane_security and o0 == False ) :
   i111I11I = self . outer_dest . print_address_no_iid ( ) + ":" + str ( self . encap_port )
   if 2 - 2: I1Ii111 * I1IiiI . IiII * iII111i
   if ( lisp_crypto_keys_by_rloc_encap . has_key ( i111I11I ) ) :
    i11i1ii11Ii1 = lisp_crypto_keys_by_rloc_encap [ i111I11I ]
    if ( i11i1ii11Ii1 [ 1 ] ) :
     i11i1ii11Ii1 [ 1 ] . use_count += 1
     Ii11iIiiI , o000 = self . encrypt ( i11i1ii11Ii1 [ 1 ] , i111I11I )
     if ( o000 ) : self . packet = Ii11iIiiI
     if 30 - 30: Ii1I + II111iiii % OoooooooOO
     if 89 - 89: Ii1I
     if 51 - 51: iII111i
     if 68 - 68: iII111i - o0oOOo0O0Ooo * OoO0O00 % ooOoO0o . ooOoO0o - iIii1I11I1II1
     if 22 - 22: OoooooooOO / I1ii11iIi11i % iII111i * OoOoOO00
     if 32 - 32: OoooooooOO % oO0o % iIii1I11I1II1 / O0
     if 61 - 61: II111iiii . O0 - Ii1I - I1ii11iIi11i / i11iIiiIii - II111iiii
     if 98 - 98: Ii1I - I1IiiI . i11iIiiIii * Oo0Ooo
  self . udp_checksum = 0
  if ( self . encap_port == LISP_DATA_PORT ) :
   if ( lisp_crypto_ephem_port == None ) :
    if ( self . gleaned_dest ) :
     self . udp_sport = LISP_DATA_PORT
    else :
     self . hash_packet ( )
     if 29 - 29: Ii1I / ooOoO0o % I11i
   else :
    self . udp_sport = lisp_crypto_ephem_port
    if 10 - 10: iIii1I11I1II1 % OoooooooOO % I1ii11iIi11i
  else :
   self . udp_sport = LISP_DATA_PORT
   if 39 - 39: II111iiii * OoOoOO00 . O0 * I11i
  self . udp_dport = self . encap_port
  self . udp_length = len ( self . packet ) + 16
  if 89 - 89: Ii1I - ooOoO0o . I11i - I1Ii111 - I1IiiI
  if 79 - 79: IiII + IiII + Ii1I
  if 39 - 39: O0 - OoooooooOO
  if 63 - 63: iIii1I11I1II1 % o0oOOo0O0Ooo * ooOoO0o
  if ( self . outer_version == 4 ) :
   oo0 = socket . htons ( self . udp_sport )
   iii1iI = socket . htons ( self . udp_dport )
  else :
   oo0 = self . udp_sport
   iii1iI = self . udp_dport
   if 26 - 26: iIii1I11I1II1 - I1ii11iIi11i . IiII . IiII + iIii1I11I1II1 * Oo0Ooo
   if 85 - 85: OOooOOo + II111iiii - OOooOOo * oO0o - i1IIi % iII111i
  iii1iI = socket . htons ( self . udp_dport ) if self . outer_version == 4 else self . udp_dport
  if 1 - 1: OoooooooOO / O0 + OoOoOO00 + OoOoOO00 . I1Ii111 - OoOoOO00
  if 9 - 9: I1Ii111 * OoooooooOO % I1IiiI / OoOoOO00 * I11i
  IiI1iiI11 = struct . pack ( "HHHH" , oo0 , iii1iI , socket . htons ( self . udp_length ) ,
 self . udp_checksum )
  if 48 - 48: OoooooooOO . OoOoOO00
  if 65 - 65: oO0o . Oo0Ooo
  if 94 - 94: OoOoOO00 + IiII . ooOoO0o
  if 69 - 69: O0 - O0
  i1I1i1i1I1 = self . lisp_header . encode ( )
  if 17 - 17: OoOoOO00 + OoooooooOO % OOooOOo
  if 36 - 36: i11iIiiIii + I1ii11iIi11i % OOooOOo . I1IiiI - ooOoO0o
  if 94 - 94: I1IiiI % OoOoOO00 . IiII . ooOoO0o . OoO0O00
  if 53 - 53: OoOoOO00
  if 84 - 84: OoO0O00
  if ( self . outer_version == 4 ) :
   o0OO = socket . htons ( self . udp_length + 20 )
   i11Ii1 = socket . htons ( 0x4000 )
   I11IIIII = struct . pack ( "BBHHHBBH" , 0x45 , self . outer_tos , o0OO , 0xdfdf ,
 i11Ii1 , self . outer_ttl , 17 , 0 )
   I11IIIII += self . outer_source . pack_address ( )
   I11IIIII += self . outer_dest . pack_address ( )
   I11IIIII = lisp_ip_checksum ( I11IIIII )
  elif ( self . outer_version == 6 ) :
   I11IIIII = ""
   if 53 - 53: OoooooooOO . OoooooooOO + o0oOOo0O0Ooo - iII111i + OOooOOo
   if 44 - 44: I1Ii111 - IiII
   if 100 - 100: oO0o . OoO0O00 - Ii1I + O0 * OoO0O00
   if 59 - 59: II111iiii
   if 43 - 43: Oo0Ooo + OoooooooOO
   if 47 - 47: ooOoO0o
   if 92 - 92: I11i % i11iIiiIii % Oo0Ooo
  else :
   return ( None )
   if 23 - 23: II111iiii * iII111i
   if 80 - 80: I1Ii111 / i11iIiiIii + OoooooooOO
  self . packet = I11IIIII + IiI1iiI11 + i1I1i1i1I1 + self . packet
  return ( self )
  if 38 - 38: I1ii11iIi11i % ooOoO0o + i1IIi * OoooooooOO * oO0o
  if 83 - 83: iIii1I11I1II1 - ooOoO0o - I1Ii111 / OoO0O00 - O0
 def cipher_pad ( self , packet ) :
  O00OoO0oo = len ( packet )
  if ( ( O00OoO0oo % 16 ) != 0 ) :
   Ii11iI1iI = ( ( O00OoO0oo / 16 ) + 1 ) * 16
   packet = packet . ljust ( Ii11iI1iI )
   if 64 - 64: IiII / o0oOOo0O0Ooo / i1IIi
  return ( packet )
  if 79 - 79: OOooOOo % I1Ii111 / oO0o - iIii1I11I1II1 - OoOoOO00
  if 60 - 60: II111iiii
 def encrypt ( self , key , addr_str ) :
  if ( key == None or key . shared_key == None ) :
   return ( [ self . packet , False ] )
   if 90 - 90: OoOoOO00
   if 37 - 37: OoOoOO00 + O0 . O0 * Oo0Ooo % I1Ii111 / iII111i
   if 18 - 18: OoooooooOO
   if 57 - 57: ooOoO0o . OoOoOO00 * o0oOOo0O0Ooo - OoooooooOO
   if 75 - 75: i11iIiiIii / o0oOOo0O0Ooo . IiII . i1IIi . i1IIi / I11i
  Ii11iIiiI = self . cipher_pad ( self . packet )
  o0OOo0O = key . get_iv ( )
  if 52 - 52: OoooooooOO / IiII % II111iiii
  iiiI = lisp_get_timestamp ( )
  Ii11I1I11II = None
  if ( key . cipher_suite == LISP_CS_25519_CHACHA ) :
   IIiiiI = chacha . ChaCha ( key . encrypt_key , o0OOo0O ) . encrypt
  elif ( key . cipher_suite == LISP_CS_25519_GCM ) :
   oO0Oooo0OoO = binascii . unhexlify ( key . encrypt_key )
   try :
    Iii = AES . new ( oO0Oooo0OoO , AES . MODE_GCM , o0OOo0O )
    IIiiiI = Iii . encrypt
    Ii11I1I11II = Iii . digest
   except :
    lprint ( "You need AES-GCM, do a 'pip install pycryptodome'" )
    return ( [ self . packet , False ] )
    if 33 - 33: IiII % Oo0Ooo - oO0o
  else :
   oO0Oooo0OoO = binascii . unhexlify ( key . encrypt_key )
   IIiiiI = AES . new ( oO0Oooo0OoO , AES . MODE_CBC , o0OOo0O ) . encrypt
   if 53 - 53: II111iiii
   if 61 - 61: O0 * OoO0O00 * I1IiiI % OoooooooOO / OoOoOO00 % ooOoO0o
  iiII = IIiiiI ( Ii11iIiiI )
  if 29 - 29: ooOoO0o * II111iiii * OoO0O00 * IiII
  if ( iiII == None ) : return ( [ self . packet , False ] )
  iiiI = int ( str ( time . time ( ) - iiiI ) . split ( "." ) [ 1 ] [ 0 : 6 ] )
  if 92 - 92: oO0o
  if 7 - 7: iII111i
  if 73 - 73: OoO0O00 % I1ii11iIi11i
  if 32 - 32: OOooOOo + iII111i + iIii1I11I1II1 * Oo0Ooo
  if 62 - 62: i11iIiiIii
  if 2 - 2: I1IiiI
  if ( Ii11I1I11II != None ) : iiII += Ii11I1I11II ( )
  if 69 - 69: OoooooooOO / Oo0Ooo * I1Ii111
  if 99 - 99: II111iiii * iIii1I11I1II1 % O0 * oO0o / II111iiii % OoooooooOO
  if 14 - 14: IiII . IiII % ooOoO0o
  if 42 - 42: o0oOOo0O0Ooo . OOooOOo - ooOoO0o
  if 33 - 33: II111iiii / O0 / IiII - I11i - i1IIi
  self . lisp_header . key_id ( key . key_id )
  i1I1i1i1I1 = self . lisp_header . encode ( )
  if 8 - 8: i11iIiiIii . iII111i / iIii1I11I1II1 / I1ii11iIi11i / IiII - Ii1I
  iI1 = key . do_icv ( i1I1i1i1I1 + o0OOo0O + iiII , o0OOo0O )
  if 22 - 22: IiII * Ii1I - OoooooooOO
  i1Ii1 = 4 if ( key . do_poly ) else 8
  if 75 - 75: OoooooooOO * i11iIiiIii
  o0oOo = bold ( "Encrypt" , False )
  Oo = bold ( key . cipher_suite_string , False )
  addr_str = "RLOC: " + red ( addr_str , False )
  IIiIIIII1I = "poly" if key . do_poly else "sha256"
  IIiIIIII1I = bold ( IIiIIIII1I , False )
  oo = "ICV({}): 0x{}...{}" . format ( IIiIIIII1I , iI1 [ 0 : i1Ii1 ] , iI1 [ - i1Ii1 : : ] )
  dprint ( "{} for key-id: {}, {}, {}, {}-time: {} usec" . format ( o0oOo , key . key_id , addr_str , oo , Oo , iiiI ) )
  if 27 - 27: iIii1I11I1II1
  if 23 - 23: Oo0Ooo % I11i . II111iiii * i1IIi
  iI1 = int ( iI1 , 16 )
  if ( key . do_poly ) :
   oO0oO = byte_swap_64 ( ( iI1 >> 64 ) & LISP_8_64_MASK )
   o0ooo = byte_swap_64 ( iI1 & LISP_8_64_MASK )
   iI1 = struct . pack ( "QQ" , oO0oO , o0ooo )
  else :
   oO0oO = byte_swap_64 ( ( iI1 >> 96 ) & LISP_8_64_MASK )
   o0ooo = byte_swap_64 ( ( iI1 >> 32 ) & LISP_8_64_MASK )
   IiI = socket . htonl ( iI1 & 0xffffffff )
   iI1 = struct . pack ( "QQI" , oO0oO , o0ooo , IiI )
   if 34 - 34: O0 / OOooOOo
   if 86 - 86: I1ii11iIi11i * i1IIi + iII111i . I1ii11iIi11i
  return ( [ o0OOo0O + iiII + iI1 , True ] )
  if 100 - 100: OoooooooOO - O0 . I11i / I11i + II111iiii * OoOoOO00
  if 37 - 37: Oo0Ooo
 def decrypt ( self , packet , header_length , key , addr_str ) :
  if 72 - 72: IiII % I1ii11iIi11i * OOooOOo . i11iIiiIii % IiII * OOooOOo
  if 15 - 15: I11i / Oo0Ooo * I11i
  if 20 - 20: ooOoO0o - OOooOOo * OoO0O00 * o0oOOo0O0Ooo * OOooOOo / IiII
  if 40 - 40: I1IiiI * o0oOOo0O0Ooo . I1IiiI
  if 62 - 62: ooOoO0o + II111iiii % ooOoO0o
  if 50 - 50: OoooooooOO + oO0o * I1IiiI - Ii1I / i11iIiiIii
  if ( key . do_poly ) :
   oO0oO , o0ooo = struct . unpack ( "QQ" , packet [ - 16 : : ] )
   iiiIIiiIi = byte_swap_64 ( oO0oO ) << 64
   iiiIIiiIi |= byte_swap_64 ( o0ooo )
   iiiIIiiIi = lisp_hex_string ( iiiIIiiIi ) . zfill ( 32 )
   packet = packet [ 0 : - 16 ]
   i1Ii1 = 4
   Oooo0oOooOO = bold ( "poly" , False )
  else :
   oO0oO , o0ooo , IiI = struct . unpack ( "QQI" , packet [ - 20 : : ] )
   iiiIIiiIi = byte_swap_64 ( oO0oO ) << 96
   iiiIIiiIi |= byte_swap_64 ( o0ooo ) << 32
   iiiIIiiIi |= socket . htonl ( IiI )
   iiiIIiiIi = lisp_hex_string ( iiiIIiiIi ) . zfill ( 40 )
   packet = packet [ 0 : - 20 ]
   i1Ii1 = 8
   Oooo0oOooOO = bold ( "sha" , False )
   if 82 - 82: ooOoO0o + II111iiii . I1IiiI / I1ii11iIi11i
  i1I1i1i1I1 = self . lisp_header . encode ( )
  if 68 - 68: OOooOOo - OoooooooOO
  if 14 - 14: O0 / oO0o - Oo0Ooo - IiII
  if 44 - 44: OoO0O00
  if 32 - 32: OoOoOO00 % OoO0O00 + i11iIiiIii + ooOoO0o - Ii1I + oO0o
  if ( key . cipher_suite == LISP_CS_25519_CHACHA ) :
   iiIIi1II = 8
   Oo = bold ( "chacha" , False )
  elif ( key . cipher_suite == LISP_CS_25519_GCM ) :
   iiIIi1II = 12
   Oo = bold ( "aes-gcm" , False )
  else :
   iiIIi1II = 16
   Oo = bold ( "aes-cbc" , False )
   if 1 - 1: OoOoOO00 * O0 . oO0o % O0 + II111iiii
  o0OOo0O = packet [ 0 : iiIIi1II ]
  if 49 - 49: I11i . OOooOOo
  if 74 - 74: i1IIi
  if 15 - 15: i1IIi + IiII % I1IiiI / i11iIiiIii * OoOoOO00
  if 69 - 69: i11iIiiIii
  ooO = key . do_icv ( i1I1i1i1I1 + packet , o0OOo0O )
  if 84 - 84: iIii1I11I1II1 . ooOoO0o + iII111i
  O00OOOo0Oo0 = "0x{}...{}" . format ( iiiIIiiIi [ 0 : i1Ii1 ] , iiiIIiiIi [ - i1Ii1 : : ] )
  o00O0 = "0x{}...{}" . format ( ooO [ 0 : i1Ii1 ] , ooO [ - i1Ii1 : : ] )
  if 40 - 40: OoO0O00 . i11iIiiIii + I1ii11iIi11i + I1IiiI . oO0o
  if ( ooO != iiiIIiiIi ) :
   self . packet_error = "ICV-error"
   O0oo0O0OO0Oo = Oo + "/" + Oooo0oOooOO
   oO00o0oO0O = bold ( "ICV failed ({})" . format ( O0oo0O0OO0Oo ) , False )
   oo = "packet-ICV {} != computed-ICV {}" . format ( O00OOOo0Oo0 , o00O0 )
   dprint ( ( "{} from RLOC {}, receive-port: {}, key-id: {}, " + "packet dropped, {}" ) . format ( oO00o0oO0O , red ( addr_str , False ) ,
   # OOooOOo + I1Ii111 - Ii1I
 self . udp_sport , key . key_id , oo ) )
   dprint ( "{}" . format ( key . print_keys ( ) ) )
   if 53 - 53: I1IiiI
   if 96 - 96: OoO0O00 - IiII . OoooooooOO
   if 10 - 10: I1Ii111
   if 48 - 48: iII111i * i1IIi % OoooooooOO * Ii1I * OoO0O00
   if 7 - 7: iII111i . Ii1I . iII111i - I1Ii111
   if 33 - 33: ooOoO0o + OoooooooOO - OoO0O00 / i1IIi / OoooooooOO
   lisp_retry_decap_keys ( addr_str , i1I1i1i1I1 + packet , o0OOo0O , iiiIIiiIi )
   return ( [ None , False ] )
   if 82 - 82: I1ii11iIi11i / OOooOOo - iII111i / Oo0Ooo * OoO0O00
   if 55 - 55: OoooooooOO
   if 73 - 73: OoOoOO00 - I1ii11iIi11i % Oo0Ooo + I1ii11iIi11i - O0 . OoO0O00
   if 38 - 38: O0
   if 79 - 79: i1IIi . oO0o
  packet = packet [ iiIIi1II : : ]
  if 34 - 34: I1Ii111 * II111iiii
  if 71 - 71: IiII
  if 97 - 97: I1ii11iIi11i
  if 86 - 86: Oo0Ooo - OOooOOo . OoOoOO00 . II111iiii * I1IiiI . II111iiii
  iiiI = lisp_get_timestamp ( )
  if ( key . cipher_suite == LISP_CS_25519_CHACHA ) :
   II1 = chacha . ChaCha ( key . encrypt_key , o0OOo0O ) . decrypt
  elif ( key . cipher_suite == LISP_CS_25519_GCM ) :
   oO0Oooo0OoO = binascii . unhexlify ( key . encrypt_key )
   try :
    II1 = AES . new ( oO0Oooo0OoO , AES . MODE_GCM , o0OOo0O ) . decrypt
   except :
    self . packet_error = "no-decrypt-key"
    lprint ( "You need AES-GCM, do a 'pip install pycryptodome'" )
    return ( [ None , False ] )
    if 93 - 93: i1IIi * I1Ii111 . I11i * Ii1I
  else :
   if ( ( len ( packet ) % 16 ) != 0 ) :
    dprint ( "Ciphertext not multiple of 16 bytes, packet dropped" )
    return ( [ None , False ] )
    if 4 - 4: I1ii11iIi11i * O0 - I1Ii111 - i11iIiiIii / o0oOOo0O0Ooo . OOooOOo
   oO0Oooo0OoO = binascii . unhexlify ( key . encrypt_key )
   II1 = AES . new ( oO0Oooo0OoO , AES . MODE_CBC , o0OOo0O ) . decrypt
   if 44 - 44: ooOoO0o * i11iIiiIii
   if 6 - 6: o0oOOo0O0Ooo % OOooOOo * I1ii11iIi11i % Ii1I . OOooOOo
  iI1oOoo = II1 ( packet )
  iiiI = int ( str ( time . time ( ) - iiiI ) . split ( "." ) [ 1 ] [ 0 : 6 ] )
  if 59 - 59: IiII % Ii1I
  if 57 - 57: I11i . O0 % OoooooooOO . I1IiiI . i1IIi - II111iiii
  if 61 - 61: O0 . o0oOOo0O0Ooo / OoOoOO00
  if 74 - 74: i1IIi * I1Ii111 % Ii1I
  o0oOo = bold ( "Decrypt" , False )
  addr_str = "RLOC: " + red ( addr_str , False )
  IIiIIIII1I = "poly" if key . do_poly else "sha256"
  IIiIIIII1I = bold ( IIiIIIII1I , False )
  oo = "ICV({}): {}" . format ( IIiIIIII1I , O00OOOo0Oo0 )
  dprint ( "{} for key-id: {}, {}, {} (good), {}-time: {} usec" . format ( o0oOo , key . key_id , addr_str , oo , Oo , iiiI ) )
  if 30 - 30: II111iiii - o0oOOo0O0Ooo % I1Ii111 . I11i
  if 63 - 63: iIii1I11I1II1 / ooOoO0o
  if 24 - 24: Oo0Ooo / iIii1I11I1II1 % OOooOOo * OoOoOO00 - iIii1I11I1II1
  if 50 - 50: II111iiii
  if 39 - 39: II111iiii . OoOoOO00 - Oo0Ooo * i1IIi . OoooooooOO
  if 44 - 44: I1IiiI
  if 55 - 55: oO0o . I1Ii111 * I1Ii111
  self . packet = self . packet [ 0 : header_length ]
  return ( [ iI1oOoo , True ] )
  if 82 - 82: I1IiiI % OoO0O00 % I11i + I11i
  if 6 - 6: Oo0Ooo
 def fragment_outer ( self , outer_hdr , inner_packet ) :
  O0OOOOoO00oo = 1000
  if 80 - 80: i1IIi . I1IiiI - oO0o + OOooOOo + iII111i % oO0o
  if 13 - 13: II111iiii / OoOoOO00 / OoOoOO00 + ooOoO0o
  if 49 - 49: O0 / II111iiii * I1IiiI - OoooooooOO . II111iiii % IiII
  if 13 - 13: oO0o . iIii1I11I1II1 . OOooOOo . IiII
  if 58 - 58: I11i
  Ii11I = [ ]
  I1 = 0
  O00OoO0oo = len ( inner_packet )
  while ( I1 < O00OoO0oo ) :
   i11Ii1 = inner_packet [ I1 : : ]
   if ( len ( i11Ii1 ) > O0OOOOoO00oo ) : i11Ii1 = i11Ii1 [ 0 : O0OOOOoO00oo ]
   Ii11I . append ( i11Ii1 )
   I1 += len ( i11Ii1 )
   if 72 - 72: O0 + o0oOOo0O0Ooo + I1IiiI / Oo0Ooo
   if 83 - 83: IiII - I1IiiI . Ii1I
   if 34 - 34: OoOoOO00 - oO0o * OoooooooOO
   if 5 - 5: i11iIiiIii * iII111i - Ii1I - I1ii11iIi11i - i1IIi + iII111i
   if 4 - 4: ooOoO0o + O0 . i1IIi * I1ii11iIi11i - o0oOOo0O0Ooo
   if 42 - 42: o0oOOo0O0Ooo * OoOoOO00 . OoO0O00 - iII111i / II111iiii
  iII1ii11III = [ ]
  I1 = 0
  for i11Ii1 in Ii11I :
   if 92 - 92: OoO0O00 - I1ii11iIi11i + iIii1I11I1II1 % o0oOOo0O0Ooo
   if 78 - 78: iIii1I11I1II1 - II111iiii / I1IiiI
   if 9 - 9: I1ii11iIi11i * Ii1I - IiII
   if 88 - 88: iIii1I11I1II1
   I1iiI11i111II = I1 if ( i11Ii1 == Ii11I [ - 1 ] ) else 0x2000 + I1
   I1iiI11i111II = socket . htons ( I1iiI11i111II )
   outer_hdr = outer_hdr [ 0 : 6 ] + struct . pack ( "H" , I1iiI11i111II ) + outer_hdr [ 8 : : ]
   if 56 - 56: IiII . I1ii11iIi11i * ooOoO0o - I11i . Oo0Ooo
   if 45 - 45: iII111i + OoOoOO00 / iIii1I11I1II1
   if 19 - 19: I1Ii111 * IiII . Oo0Ooo - Oo0Ooo - OoO0O00
   if 51 - 51: O0 * I1IiiI / IiII - I1ii11iIi11i
   oooo0 = socket . htons ( len ( i11Ii1 ) + 20 )
   outer_hdr = outer_hdr [ 0 : 2 ] + struct . pack ( "H" , oooo0 ) + outer_hdr [ 4 : : ]
   outer_hdr = lisp_ip_checksum ( outer_hdr )
   iII1ii11III . append ( outer_hdr + i11Ii1 )
   I1 += len ( i11Ii1 ) / 8
   if 74 - 74: o0oOOo0O0Ooo / oO0o - II111iiii . II111iiii . IiII + II111iiii
  return ( iII1ii11III )
  if 92 - 92: I1Ii111 % iIii1I11I1II1 - iII111i / i11iIiiIii % ooOoO0o * o0oOOo0O0Ooo
  if 80 - 80: iII111i
 def send_icmp_too_big ( self , inner_packet ) :
  global lisp_last_icmp_too_big_sent
  global lisp_icmp_raw_socket
  if 3 - 3: I1ii11iIi11i * I11i
  I1IiIii11I = time . time ( ) - lisp_last_icmp_too_big_sent
  if ( I1IiIii11I < LISP_ICMP_TOO_BIG_RATE_LIMIT ) :
   lprint ( "Rate limit sending ICMP Too-Big to {}" . format ( self . inner_source . print_address_no_iid ( ) ) )
   if 53 - 53: iIii1I11I1II1 / iII111i % OoO0O00 + IiII / ooOoO0o
   return ( False )
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
   if 27 - 27: OoO0O00 + Oo0Ooo
   if 92 - 92: I1IiiI % iII111i
   if 31 - 31: OoooooooOO - oO0o / I1Ii111
  oo00o000O = socket . htons ( 1400 )
  Oo0O0OOO0o0O = struct . pack ( "BBHHH" , 3 , 4 , 0 , 0 , oo00o000O )
  Oo0O0OOO0o0O += inner_packet [ 0 : 20 + 8 ]
  Oo0O0OOO0o0O = lisp_icmp_checksum ( Oo0O0OOO0o0O )
  if 66 - 66: OoooooooOO + o0oOOo0O0Ooo . i1IIi * iII111i
  if 92 - 92: I11i / I1Ii111
  if 4 - 4: I1Ii111
  if 11 - 11: OoooooooOO + i1IIi / Ii1I
  if 25 - 25: Ii1I . OOooOOo
  if 14 - 14: O0 / I11i . OoO0O00 % iII111i . oO0o
  if 16 - 16: OoooooooOO % I1IiiI - o0oOOo0O0Ooo / II111iiii . i1IIi
  Iii1II1 = inner_packet [ 12 : 16 ]
  oOiii1IiII = self . inner_source . print_address_no_iid ( )
  o0oo0OooOO0 = self . outer_source . pack_address ( )
  if 57 - 57: II111iiii % I1IiiI
  if 34 - 34: I1IiiI
  if 57 - 57: OOooOOo . Ii1I % o0oOOo0O0Ooo
  if 32 - 32: I11i / IiII - O0 * iIii1I11I1II1
  if 70 - 70: OoooooooOO % OoooooooOO % OoO0O00
  if 98 - 98: OoO0O00
  if 18 - 18: I11i + Oo0Ooo - OoO0O00 / I1Ii111 / OOooOOo
  if 53 - 53: OOooOOo + o0oOOo0O0Ooo . oO0o / I11i
  o0OO = socket . htons ( 20 + 36 )
  i1i11ii1Ii = struct . pack ( "BBHHHBBH" , 0x45 , 0 , o0OO , 0 , 0 , 32 , 1 , 0 ) + o0oo0OooOO0 + Iii1II1
  i1i11ii1Ii = lisp_ip_checksum ( i1i11ii1Ii )
  i1i11ii1Ii = self . fix_outer_header ( i1i11ii1Ii )
  i1i11ii1Ii += Oo0O0OOO0o0O
  o0000oO = bold ( "Too-Big" , False )
  lprint ( "Send ICMP {} to {}, mtu 1400: {}" . format ( o0000oO , oOiii1IiII ,
 lisp_format_packet ( i1i11ii1Ii ) ) )
  if 83 - 83: OoO0O00
  try :
   lisp_icmp_raw_socket . sendto ( i1i11ii1Ii , ( oOiii1IiII , 0 ) )
  except socket . error , ooOoOOOOo :
   lprint ( "lisp_icmp_raw_socket.sendto() failed: {}" . format ( ooOoOOOOo ) )
   return ( False )
   if 16 - 16: ooOoO0o
   if 32 - 32: o0oOOo0O0Ooo % I1IiiI
   if 7 - 7: Oo0Ooo . i1IIi - oO0o
   if 93 - 93: IiII % I1ii11iIi11i
   if 31 - 31: II111iiii + OOooOOo - OoooooooOO . I11i
   if 28 - 28: Ii1I . I1ii11iIi11i
  lisp_last_icmp_too_big_sent = lisp_get_timestamp ( )
  return ( True )
  if 77 - 77: I1ii11iIi11i % II111iiii
 def fragment ( self ) :
  global lisp_icmp_raw_socket
  global lisp_ignore_df_bit
  if 81 - 81: OoOoOO00 % Ii1I / O0 * iIii1I11I1II1 % IiII . I1IiiI
  Ii11iIiiI = self . fix_outer_header ( self . packet )
  if 90 - 90: o0oOOo0O0Ooo
  if 44 - 44: o0oOOo0O0Ooo / I1ii11iIi11i . Oo0Ooo + OoOoOO00
  if 32 - 32: IiII - ooOoO0o * iII111i * I11i
  if 84 - 84: Ii1I + I1ii11iIi11i % I1IiiI + i11iIiiIii
  if 37 - 37: I11i % I1ii11iIi11i / ooOoO0o
  if 94 - 94: I11i / OoO0O00 . o0oOOo0O0Ooo
  O00OoO0oo = len ( Ii11iIiiI )
  if ( O00OoO0oo <= 1500 ) : return ( [ Ii11iIiiI ] , "Fragment-None" )
  if 1 - 1: Oo0Ooo . II111iiii
  Ii11iIiiI = self . packet
  if 93 - 93: II111iiii . i11iIiiIii + II111iiii % oO0o
  if 98 - 98: I1Ii111 * oO0o * OoOoOO00 + Ii1I * iII111i
  if 4 - 4: IiII
  if 16 - 16: iIii1I11I1II1 * iII111i + oO0o . O0 . o0oOOo0O0Ooo
  if 99 - 99: i11iIiiIii - iII111i
  if ( self . inner_version != 4 ) :
   o0O0O0O00o = random . randint ( 0 , 0xffff )
   OoOooOo00o = Ii11iIiiI [ 0 : 4 ] + struct . pack ( "H" , o0O0O0O00o ) + Ii11iIiiI [ 6 : 20 ]
   iI1IIi = Ii11iIiiI [ 20 : : ]
   iII1ii11III = self . fragment_outer ( OoOooOo00o , iI1IIi )
   return ( iII1ii11III , "Fragment-Outer" )
   if 10 - 10: I1ii11iIi11i / Ii1I * i1IIi % O0 + I11i
   if 25 - 25: I1Ii111 - Ii1I / O0 . OoooooooOO % I1IiiI . i1IIi
   if 19 - 19: II111iiii / II111iiii % I1ii11iIi11i + oO0o + oO0o + iII111i
   if 4 - 4: o0oOOo0O0Ooo + I11i / iII111i + i1IIi % o0oOOo0O0Ooo % iII111i
   if 80 - 80: Ii1I
  ii = 56 if ( self . outer_version == 6 ) else 36
  OoOooOo00o = Ii11iIiiI [ 0 : ii ]
  oOO = Ii11iIiiI [ ii : ii + 20 ]
  iI1IIi = Ii11iIiiI [ ii + 20 : : ]
  if 38 - 38: I11i . IiII - OoO0O00 . I1IiiI
  if 65 - 65: I1Ii111
  if 31 - 31: i11iIiiIii / OoOoOO00 % I1ii11iIi11i
  if 44 - 44: II111iiii * I1IiiI + OOooOOo
  if 31 - 31: Ii1I * o0oOOo0O0Ooo * Ii1I + OoO0O00 * o0oOOo0O0Ooo . I1Ii111
  Oo00oo00o00Oo = struct . unpack ( "H" , oOO [ 6 : 8 ] ) [ 0 ]
  Oo00oo00o00Oo = socket . ntohs ( Oo00oo00o00Oo )
  if ( Oo00oo00o00Oo & 0x4000 ) :
   if ( lisp_icmp_raw_socket != None ) :
    iiiiiii11III = Ii11iIiiI [ ii : : ]
    if ( self . send_icmp_too_big ( iiiiiii11III ) ) : return ( [ ] , None )
    if 48 - 48: I1Ii111 % iII111i % Ii1I % iIii1I11I1II1 . Ii1I
   if ( lisp_ignore_df_bit ) :
    Oo00oo00o00Oo &= ~ 0x4000
   else :
    I11IIiI1IiI1 = bold ( "DF-bit set" , False )
    dprint ( "{} in inner header, packet discarded" . format ( I11IIiI1IiI1 ) )
    return ( [ ] , "Fragment-None-DF-bit" )
    if 37 - 37: oO0o % I1Ii111 % oO0o
    if 14 - 14: OoO0O00 / I1IiiI
    if 66 - 66: Oo0Ooo / i11iIiiIii % ooOoO0o
  I1 = 0
  O00OoO0oo = len ( iI1IIi )
  iII1ii11III = [ ]
  while ( I1 < O00OoO0oo ) :
   iII1ii11III . append ( iI1IIi [ I1 : I1 + 1400 ] )
   I1 += 1400
   if 43 - 43: OOooOOo
   if 84 - 84: OOooOOo . IiII . iII111i
   if 2 - 2: Oo0Ooo - OoOoOO00
   if 49 - 49: Ii1I + II111iiii / oO0o - OoOoOO00 % OoOoOO00 + I1IiiI
   if 54 - 54: ooOoO0o % Oo0Ooo - OOooOOo
  Ii11I = iII1ii11III
  iII1ii11III = [ ]
  iIi11IiiiII11 = True if Oo00oo00o00Oo & 0x2000 else False
  Oo00oo00o00Oo = ( Oo00oo00o00Oo & 0x1fff ) * 8
  for i11Ii1 in Ii11I :
   if 26 - 26: iII111i / OoooooooOO - Oo0Ooo
   if 2 - 2: I1ii11iIi11i - Oo0Ooo
   if 4 - 4: O0 / I11i . OoO0O00 - ooOoO0o / OOooOOo
   if 25 - 25: I11i * OoOoOO00 - Oo0Ooo . ooOoO0o . oO0o
   oo00Oo0oO00Oo = Oo00oo00o00Oo / 8
   if ( iIi11IiiiII11 ) :
    oo00Oo0oO00Oo |= 0x2000
   elif ( i11Ii1 != Ii11I [ - 1 ] ) :
    oo00Oo0oO00Oo |= 0x2000
    if 20 - 20: o0oOOo0O0Ooo / IiII
   oo00Oo0oO00Oo = socket . htons ( oo00Oo0oO00Oo )
   oOO = oOO [ 0 : 6 ] + struct . pack ( "H" , oo00Oo0oO00Oo ) + oOO [ 8 : : ]
   if 25 - 25: OoOoOO00 + OoO0O00 % Ii1I % OOooOOo / oO0o
   if 91 - 91: OoO0O00 / OoO0O00 . II111iiii . ooOoO0o - I1IiiI
   if 23 - 23: I1IiiI
   if 7 - 7: iII111i % I1ii11iIi11i
   if 64 - 64: I1Ii111 + i11iIiiIii
   if 35 - 35: OoOoOO00 + i1IIi % OOooOOo
   O00OoO0oo = len ( i11Ii1 )
   Oo00oo00o00Oo += O00OoO0oo
   oooo0 = socket . htons ( O00OoO0oo + 20 )
   oOO = oOO [ 0 : 2 ] + struct . pack ( "H" , oooo0 ) + oOO [ 4 : 10 ] + struct . pack ( "H" , 0 ) + oOO [ 12 : : ]
   if 68 - 68: IiII . ooOoO0o
   oOO = lisp_ip_checksum ( oOO )
   Oo0OooooOO0o0OO = oOO + i11Ii1
   if 24 - 24: oO0o . O0 * ooOoO0o / OoooooooOO - Ii1I . I11i
   if 41 - 41: OoO0O00 % I1IiiI - Oo0Ooo
   if 11 - 11: Ii1I * o0oOOo0O0Ooo / IiII + OoOoOO00 + OoO0O00 % I1Ii111
   if 18 - 18: I1IiiI - OoOoOO00
   if 18 - 18: OOooOOo + OoO0O00 * oO0o - oO0o . I1ii11iIi11i * I11i
   O00OoO0oo = len ( Oo0OooooOO0o0OO )
   if ( self . outer_version == 4 ) :
    oooo0 = O00OoO0oo + ii
    O00OoO0oo += 16
    OoOooOo00o = OoOooOo00o [ 0 : 2 ] + struct . pack ( "H" , oooo0 ) + OoOooOo00o [ 4 : : ]
    if 95 - 95: I1ii11iIi11i / OoOoOO00
    OoOooOo00o = lisp_ip_checksum ( OoOooOo00o )
    Oo0OooooOO0o0OO = OoOooOo00o + Oo0OooooOO0o0OO
    Oo0OooooOO0o0OO = self . fix_outer_header ( Oo0OooooOO0o0OO )
    if 10 - 10: IiII % I1ii11iIi11i - IiII
    if 86 - 86: Oo0Ooo
    if 88 - 88: I1Ii111 * I1IiiI
    if 30 - 30: OoOoOO00 / oO0o / Ii1I * o0oOOo0O0Ooo * oO0o . I1IiiI
    if 93 - 93: OoOoOO00
   o0OoOo0o0OOoO0 = ii - 12
   oooo0 = socket . htons ( O00OoO0oo )
   Oo0OooooOO0o0OO = Oo0OooooOO0o0OO [ 0 : o0OoOo0o0OOoO0 ] + struct . pack ( "H" , oooo0 ) + Oo0OooooOO0o0OO [ o0OoOo0o0OOoO0 + 2 : : ]
   if 30 - 30: Ii1I % I11i + o0oOOo0O0Ooo
   iII1ii11III . append ( Oo0OooooOO0o0OO )
   if 65 - 65: iIii1I11I1II1 . iII111i / Ii1I
  return ( iII1ii11III , "Fragment-Inner" )
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
  iII1ii11III , iiIII1i1 = self . fragment ( )
  if 78 - 78: oO0o % OoOoOO00
  for Oo0OooooOO0o0OO in iII1ii11III :
   if ( len ( iII1ii11III ) != 1 ) :
    self . packet = Oo0OooooOO0o0OO
    self . print_packet ( iiIII1i1 , True )
    if 1 - 1: OoOoOO00 - o0oOOo0O0Ooo / ooOoO0o - IiII / i1IIi
    if 28 - 28: OoO0O00 / I1Ii111 * I1IiiI + ooOoO0o
   try : lisp_raw_socket . sendto ( Oo0OooooOO0o0OO , ( dest , 0 ) )
   except socket . error , ooOoOOOOo :
    lprint ( "socket.sendto() failed: {}" . format ( ooOoOOOOo ) )
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
  Ii11iIiiI = mac_header + self . packet
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
  l2_socket . write ( Ii11iIiiI )
  return
  if 4 - 4: Ii1I % I1ii11iIi11i + I11i - I1ii11iIi11i
  if 98 - 98: Ii1I - O0 * oO0o * Ii1I * Ii1I
 def bridge_l2_packet ( self , eid , db ) :
  try : i11IiII = db . dynamic_eids [ eid . print_address_no_iid ( ) ]
  except : return
  try : O0OOoooo0 = lisp_myinterfaces [ i11IiII . interface ]
  except : return
  try :
   socket = O0OOoooo0 . get_bridge_socket ( )
   if ( socket == None ) : return
  except : return
  if 53 - 53: OoO0O00 % I1ii11iIi11i . iII111i . i1IIi . OoO0O00
  try : socket . send ( self . packet )
  except socket . error , ooOoOOOOo :
   lprint ( "bridge_l2_packet(): socket.send() failed: {}" . format ( ooOoOOOOo ) )
   if 26 - 26: I1IiiI % OoOoOO00
   if 67 - 67: Oo0Ooo - IiII * Ii1I . OoooooooOO / i11iIiiIii
   if 61 - 61: o0oOOo0O0Ooo % I1IiiI * i1IIi / I1IiiI / II111iiii + I1Ii111
 def is_lisp_packet ( self , packet ) :
  IiI1iiI11 = ( struct . unpack ( "B" , packet [ 9 ] ) [ 0 ] == LISP_UDP_PROTOCOL )
  if ( IiI1iiI11 == False ) : return ( False )
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
  Ii11iIiiI = self . packet
  ooOo0 = len ( Ii11iIiiI )
  I11I1i = oOO0oOooo = True
  if 57 - 57: OoooooooOO
  if 70 - 70: iII111i . OOooOOo * OoO0O00 + OoooooooOO . I1Ii111
  if 97 - 97: OoooooooOO % iIii1I11I1II1 * OoOoOO00 . oO0o / I1Ii111
  if 27 - 27: I1IiiI % IiII
  IiIIIii1i1iI = 0
  II1ii1ii11I1 = 0
  if ( is_lisp_packet ) :
   II1ii1ii11I1 = self . lisp_header . get_instance_id ( )
   OoOOoO0o = struct . unpack ( "B" , Ii11iIiiI [ 0 : 1 ] ) [ 0 ]
   self . outer_version = OoOOoO0o >> 4
   if ( self . outer_version == 4 ) :
    if 66 - 66: I11i - I11i + IiII
    if 20 - 20: I1Ii111 . i1IIi
    if 9 - 9: OoO0O00
    if 89 - 89: i1IIi
    if 19 - 19: ooOoO0o / o0oOOo0O0Ooo % IiII - Ii1I
    iI1i1Iiii = struct . unpack ( "H" , Ii11iIiiI [ 10 : 12 ] ) [ 0 ]
    Ii11iIiiI = lisp_ip_checksum ( Ii11iIiiI )
    OoO = struct . unpack ( "H" , Ii11iIiiI [ 10 : 12 ] ) [ 0 ]
    if ( OoO != 0 ) :
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
    I1 = 12
    self . outer_tos = struct . unpack ( "B" , Ii11iIiiI [ 1 : 2 ] ) [ 0 ]
    self . outer_ttl = struct . unpack ( "B" , Ii11iIiiI [ 8 : 9 ] ) [ 0 ]
    IiIIIii1i1iI = 20
   elif ( self . outer_version == 6 ) :
    ii1iI1i1 = LISP_AFI_IPV6
    I1 = 8
    o0o0oo0OOo0O0 = struct . unpack ( "H" , Ii11iIiiI [ 0 : 2 ] ) [ 0 ]
    self . outer_tos = ( socket . ntohs ( o0o0oo0OOo0O0 ) >> 4 ) & 0xff
    self . outer_ttl = struct . unpack ( "B" , Ii11iIiiI [ 7 : 8 ] ) [ 0 ]
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
   self . outer_source . unpack_address ( Ii11iIiiI [ I1 : I1 + Oo0O0o00o00 ] )
   I1 += Oo0O0o00o00
   self . outer_dest . unpack_address ( Ii11iIiiI [ I1 : I1 + Oo0O0o00o00 ] )
   Ii11iIiiI = Ii11iIiiI [ IiIIIii1i1iI : : ]
   self . outer_source . mask_len = self . outer_source . host_mask_len ( )
   self . outer_dest . mask_len = self . outer_dest . host_mask_len ( )
   if 32 - 32: ooOoO0o - OoO0O00 . iII111i . iII111i % i1IIi * Ii1I
   if 65 - 65: iII111i / ooOoO0o . II111iiii
   if 90 - 90: I11i
   if 95 - 95: OoO0O00
   OoiIIii1Ii1 = struct . unpack ( "H" , Ii11iIiiI [ 0 : 2 ] ) [ 0 ]
   self . udp_sport = socket . ntohs ( OoiIIii1Ii1 )
   OoiIIii1Ii1 = struct . unpack ( "H" , Ii11iIiiI [ 2 : 4 ] ) [ 0 ]
   self . udp_dport = socket . ntohs ( OoiIIii1Ii1 )
   OoiIIii1Ii1 = struct . unpack ( "H" , Ii11iIiiI [ 4 : 6 ] ) [ 0 ]
   self . udp_length = socket . ntohs ( OoiIIii1Ii1 )
   OoiIIii1Ii1 = struct . unpack ( "H" , Ii11iIiiI [ 6 : 8 ] ) [ 0 ]
   self . udp_checksum = socket . ntohs ( OoiIIii1Ii1 )
   Ii11iIiiI = Ii11iIiiI [ 8 : : ]
   if 92 - 92: ooOoO0o / IiII + iIii1I11I1II1
   if 47 - 47: OOooOOo * Ii1I % iIii1I11I1II1 / ooOoO0o
   if 61 - 61: IiII + iII111i - OoO0O00 * oO0o
   if 87 - 87: II111iiii % II111iiii
   I11I1i = ( self . udp_dport == LISP_DATA_PORT or
 self . udp_sport == LISP_DATA_PORT )
   oOO0oOooo = ( self . udp_dport in ( LISP_L2_DATA_PORT , LISP_VXLAN_DATA_PORT ) )
   if 51 - 51: ooOoO0o * iIii1I11I1II1 . iII111i
   if 25 - 25: OOooOOo - Ii1I . I11i
   if 57 - 57: o0oOOo0O0Ooo + Oo0Ooo * I1ii11iIi11i - ooOoO0o % iIii1I11I1II1 - Ii1I
   if 37 - 37: OoO0O00 * I11i + Ii1I + I1ii11iIi11i * o0oOOo0O0Ooo
   if ( self . lisp_header . decode ( Ii11iIiiI ) == False ) :
    self . packet_error = "lisp-header-error"
    if ( stats ) : stats [ self . packet_error ] . increment ( ooOo0 )
    if 95 - 95: Ii1I - i11iIiiIii % i11iIiiIii - O0 * I1Ii111
    if ( lisp_flow_logging ) : self . log_flow ( False )
    lprint ( "Cannot decode LISP header" )
    return ( None )
    if 81 - 81: II111iiii * I1IiiI % i1IIi * i11iIiiIii + OoOoOO00
   Ii11iIiiI = Ii11iIiiI [ 8 : : ]
   II1ii1ii11I1 = self . lisp_header . get_instance_id ( )
   IiIIIii1i1iI += 16
   if 100 - 100: i1IIi % Ii1I
  if ( II1ii1ii11I1 == 0xffffff ) : II1ii1ii11I1 = 0
  if 55 - 55: I1IiiI + iII111i
  if 85 - 85: oO0o + iII111i % iII111i / I11i . I1IiiI - OoOoOO00
  if 19 - 19: I11i / iII111i + IiII
  if 76 - 76: iIii1I11I1II1 / I1Ii111 - I1ii11iIi11i % o0oOOo0O0Ooo % OOooOOo + OoooooooOO
  IIi1II1i111i = False
  oOoO0oO00ooOo = self . lisp_header . k_bits
  if ( oOoO0oO00ooOo ) :
   i111I11I = lisp_get_crypto_decap_lookup_key ( self . outer_source ,
 self . udp_sport )
   if ( i111I11I == None ) :
    self . packet_error = "no-decrypt-key"
    if ( stats ) : stats [ self . packet_error ] . increment ( ooOo0 )
    if 2 - 2: oO0o . iII111i
    self . print_packet ( "Receive" , is_lisp_packet )
    II1II111 = bold ( "No key available" , False )
    dprint ( "{} for key-id {} to decrypt packet" . format ( II1II111 , oOoO0oO00ooOo ) )
    if ( lisp_flow_logging ) : self . log_flow ( False )
    return ( None )
    if 71 - 71: II111iiii % I1Ii111 + I1IiiI * ooOoO0o + IiII . ooOoO0o
    if 25 - 25: ooOoO0o . o0oOOo0O0Ooo % I1IiiI + iII111i
   OOO0OOoOOO = lisp_crypto_keys_by_rloc_decap [ i111I11I ] [ oOoO0oO00ooOo ]
   if ( OOO0OOoOOO == None ) :
    self . packet_error = "no-decrypt-key"
    if ( stats ) : stats [ self . packet_error ] . increment ( ooOo0 )
    if 96 - 96: I1ii11iIi11i - O0
    self . print_packet ( "Receive" , is_lisp_packet )
    II1II111 = bold ( "No key available" , False )
    dprint ( "{} to decrypt packet from RLOC {}" . format ( II1II111 ,
 red ( i111I11I , False ) ) )
    if ( lisp_flow_logging ) : self . log_flow ( False )
    return ( None )
    if 35 - 35: OOooOOo . I11i . I1Ii111 - I11i % I11i + I1Ii111
    if 99 - 99: o0oOOo0O0Ooo + OOooOOo
    if 34 - 34: I1Ii111 * o0oOOo0O0Ooo . I1IiiI % i11iIiiIii
    if 61 - 61: iIii1I11I1II1 + oO0o * I11i - i1IIi % oO0o
    if 76 - 76: oO0o / OoOoOO00
   OOO0OOoOOO . use_count += 1
   Ii11iIiiI , IIi1II1i111i = self . decrypt ( Ii11iIiiI , IiIIIii1i1iI , OOO0OOoOOO ,
 i111I11I )
   if ( IIi1II1i111i == False ) :
    if ( stats ) : stats [ self . packet_error ] . increment ( ooOo0 )
    if ( lisp_flow_logging ) : self . log_flow ( False )
    return ( None )
    if 12 - 12: I1Ii111
    if 58 - 58: OoO0O00 + iIii1I11I1II1 % O0 + I11i + OoOoOO00 * OoooooooOO
    if 41 - 41: oO0o * I1IiiI
    if 76 - 76: oO0o . O0 * OoooooooOO + ooOoO0o
    if 53 - 53: Oo0Ooo
    if 3 - 3: IiII - OoooooooOO * OoooooooOO - I1IiiI / I1Ii111 * I1ii11iIi11i
  OoOOoO0o = struct . unpack ( "B" , Ii11iIiiI [ 0 : 1 ] ) [ 0 ]
  self . inner_version = OoOOoO0o >> 4
  if ( I11I1i and self . inner_version == 4 and OoOOoO0o >= 0x45 ) :
   O0oo0ooO00 = socket . ntohs ( struct . unpack ( "H" , Ii11iIiiI [ 2 : 4 ] ) [ 0 ] )
   self . inner_tos = struct . unpack ( "B" , Ii11iIiiI [ 1 : 2 ] ) [ 0 ]
   self . inner_ttl = struct . unpack ( "B" , Ii11iIiiI [ 8 : 9 ] ) [ 0 ]
   self . inner_protocol = struct . unpack ( "B" , Ii11iIiiI [ 9 : 10 ] ) [ 0 ]
   self . inner_source . afi = LISP_AFI_IPV4
   self . inner_dest . afi = LISP_AFI_IPV4
   self . inner_source . unpack_address ( Ii11iIiiI [ 12 : 16 ] )
   self . inner_dest . unpack_address ( Ii11iIiiI [ 16 : 20 ] )
   Oo00oo00o00Oo = socket . ntohs ( struct . unpack ( "H" , Ii11iIiiI [ 6 : 8 ] ) [ 0 ] )
   self . inner_is_fragment = ( Oo00oo00o00Oo & 0x2000 or Oo00oo00o00Oo != 0 )
   if ( self . inner_protocol == LISP_UDP_PROTOCOL ) :
    self . inner_sport = struct . unpack ( "H" , Ii11iIiiI [ 20 : 22 ] ) [ 0 ]
    self . inner_sport = socket . ntohs ( self . inner_sport )
    self . inner_dport = struct . unpack ( "H" , Ii11iIiiI [ 22 : 24 ] ) [ 0 ]
    self . inner_dport = socket . ntohs ( self . inner_dport )
    if 81 - 81: I1IiiI / OoooooooOO
  elif ( I11I1i and self . inner_version == 6 and OoOOoO0o >= 0x60 ) :
   O0oo0ooO00 = socket . ntohs ( struct . unpack ( "H" , Ii11iIiiI [ 4 : 6 ] ) [ 0 ] ) + 40
   o0o0oo0OOo0O0 = struct . unpack ( "H" , Ii11iIiiI [ 0 : 2 ] ) [ 0 ]
   self . inner_tos = ( socket . ntohs ( o0o0oo0OOo0O0 ) >> 4 ) & 0xff
   self . inner_ttl = struct . unpack ( "B" , Ii11iIiiI [ 7 : 8 ] ) [ 0 ]
   self . inner_protocol = struct . unpack ( "B" , Ii11iIiiI [ 6 : 7 ] ) [ 0 ]
   self . inner_source . afi = LISP_AFI_IPV6
   self . inner_dest . afi = LISP_AFI_IPV6
   self . inner_source . unpack_address ( Ii11iIiiI [ 8 : 24 ] )
   self . inner_dest . unpack_address ( Ii11iIiiI [ 24 : 40 ] )
   if ( self . inner_protocol == LISP_UDP_PROTOCOL ) :
    self . inner_sport = struct . unpack ( "H" , Ii11iIiiI [ 40 : 42 ] ) [ 0 ]
    self . inner_sport = socket . ntohs ( self . inner_sport )
    self . inner_dport = struct . unpack ( "H" , Ii11iIiiI [ 42 : 44 ] ) [ 0 ]
    self . inner_dport = socket . ntohs ( self . inner_dport )
    if 52 - 52: oO0o + I1Ii111 * I1Ii111 * Oo0Ooo - iIii1I11I1II1 + I1ii11iIi11i
  elif ( oOO0oOooo ) :
   O0oo0ooO00 = len ( Ii11iIiiI )
   self . inner_tos = 0
   self . inner_ttl = 0
   self . inner_protocol = 0
   self . inner_source . afi = LISP_AFI_MAC
   self . inner_dest . afi = LISP_AFI_MAC
   self . inner_dest . unpack_address ( self . swap_mac ( Ii11iIiiI [ 0 : 6 ] ) )
   self . inner_source . unpack_address ( self . swap_mac ( Ii11iIiiI [ 6 : 12 ] ) )
  elif ( self . lisp_header . get_instance_id ( ) == 0xffffff ) :
   if ( lisp_flow_logging ) : self . log_flow ( False )
   return ( self )
  else :
   self . packet_error = "bad-inner-version"
   if ( stats ) : stats [ self . packet_error ] . increment ( ooOo0 )
   if 34 - 34: iII111i / OoO0O00 / Oo0Ooo
   lprint ( "Cannot decode encapsulation, header version {}" . format ( hex ( OoOOoO0o ) ) )
   if 92 - 92: I1Ii111 % iII111i % o0oOOo0O0Ooo . I1IiiI - I1ii11iIi11i - o0oOOo0O0Ooo
   Ii11iIiiI = lisp_format_packet ( Ii11iIiiI [ 0 : 20 ] )
   lprint ( "Packet header: {}" . format ( Ii11iIiiI ) )
   if ( lisp_flow_logging and is_lisp_packet ) : self . log_flow ( False )
   return ( None )
   if 40 - 40: I1IiiI / OoooooooOO + OoO0O00 * OoO0O00
  self . inner_source . mask_len = self . inner_source . host_mask_len ( )
  self . inner_dest . mask_len = self . inner_dest . host_mask_len ( )
  self . inner_source . instance_id = II1ii1ii11I1
  self . inner_dest . instance_id = II1ii1ii11I1
  if 9 - 9: iIii1I11I1II1
  if 57 - 57: ooOoO0o / Ii1I % o0oOOo0O0Ooo % i11iIiiIii
  if 95 - 95: I1Ii111 - o0oOOo0O0Ooo
  if 65 - 65: i11iIiiIii - OoooooooOO / O0 * IiII % I11i
  if 53 - 53: OOooOOo + I1Ii111
  if ( lisp_nonce_echoing and is_lisp_packet ) :
   I1iiiIi1i11i = lisp_get_echo_nonce ( self . outer_source , None )
   if ( I1iiiIi1i11i == None ) :
    I111I1iii11 = self . outer_source . print_address_no_iid ( )
    I1iiiIi1i11i = lisp_echo_nonce ( I111I1iii11 )
    if 43 - 43: oO0o * IiII / II111iiii % OOooOOo
   i11IIoOOoOo0Ooo = self . lisp_header . get_nonce ( )
   if ( self . lisp_header . is_e_bit_set ( ) ) :
    I1iiiIi1i11i . receive_request ( lisp_ipc_socket , i11IIoOOoOo0Ooo )
   elif ( I1iiiIi1i11i . request_nonce_sent ) :
    I1iiiIi1i11i . receive_echo ( lisp_ipc_socket , i11IIoOOoOo0Ooo )
    if 95 - 95: I1Ii111 % Oo0Ooo
    if 54 - 54: iIii1I11I1II1 - iIii1I11I1II1
    if 83 - 83: I1ii11iIi11i * iIii1I11I1II1 + OoOoOO00 * i1IIi . OoooooooOO % Ii1I
    if 81 - 81: OoO0O00 - iIii1I11I1II1
    if 60 - 60: I1Ii111
    if 77 - 77: I1IiiI / I1ii11iIi11i
    if 95 - 95: I1Ii111 * i1IIi + oO0o
  if ( IIi1II1i111i ) : self . packet += Ii11iIiiI [ : O0oo0ooO00 ]
  if 40 - 40: II111iiii
  if 7 - 7: OOooOOo / OoO0O00
  if 88 - 88: i1IIi
  if 53 - 53: ooOoO0o . OOooOOo . o0oOOo0O0Ooo + oO0o
  if ( lisp_flow_logging and is_lisp_packet ) : self . log_flow ( False )
  return ( self )
  if 17 - 17: iIii1I11I1II1 + i1IIi . I1ii11iIi11i + Ii1I % i1IIi . oO0o
  if 57 - 57: oO0o
 def swap_mac ( self , mac ) :
  return ( mac [ 1 ] + mac [ 0 ] + mac [ 3 ] + mac [ 2 ] + mac [ 5 ] + mac [ 4 ] )
  if 92 - 92: II111iiii - OoO0O00 - OOooOOo % I1IiiI - OoOoOO00 * I1Ii111
  if 16 - 16: iIii1I11I1II1 + OoooooooOO - ooOoO0o * IiII
 def strip_outer_headers ( self ) :
  I1 = 16
  I1 += 20 if ( self . outer_version == 4 ) else 40
  self . packet = self . packet [ I1 : : ]
  return ( self )
  if 37 - 37: iII111i
  if 15 - 15: o0oOOo0O0Ooo % OoO0O00 / iII111i
 def hash_ports ( self ) :
  Ii11iIiiI = self . packet
  OoOOoO0o = self . inner_version
  II1IIIi = 0
  if ( OoOOoO0o == 4 ) :
   Iiii = struct . unpack ( "B" , Ii11iIiiI [ 9 ] ) [ 0 ]
   if ( self . inner_is_fragment ) : return ( Iiii )
   if ( Iiii in [ 6 , 17 ] ) :
    II1IIIi = Iiii
    II1IIIi += struct . unpack ( "I" , Ii11iIiiI [ 20 : 24 ] ) [ 0 ]
    II1IIIi = ( II1IIIi >> 16 ) ^ ( II1IIIi & 0xffff )
    if 88 - 88: I1Ii111 - Ii1I - oO0o + i1IIi
    if 15 - 15: OOooOOo
  if ( OoOOoO0o == 6 ) :
   Iiii = struct . unpack ( "B" , Ii11iIiiI [ 6 ] ) [ 0 ]
   if ( Iiii in [ 6 , 17 ] ) :
    II1IIIi = Iiii
    II1IIIi += struct . unpack ( "I" , Ii11iIiiI [ 40 : 44 ] ) [ 0 ]
    II1IIIi = ( II1IIIi >> 16 ) ^ ( II1IIIi & 0xffff )
    if 31 - 31: oO0o % i1IIi . OoooooooOO - o0oOOo0O0Ooo + OoooooooOO
    if 45 - 45: OOooOOo + I11i / OoooooooOO - Ii1I + OoooooooOO
  return ( II1IIIi )
  if 42 - 42: iIii1I11I1II1 * I1IiiI * I1Ii111
  if 62 - 62: OOooOOo * O0 % IiII . IiII . I1IiiI
 def hash_packet ( self ) :
  II1IIIi = self . inner_source . address ^ self . inner_dest . address
  II1IIIi += self . hash_ports ( )
  if ( self . inner_version == 4 ) :
   II1IIIi = ( II1IIIi >> 16 ) ^ ( II1IIIi & 0xffff )
  elif ( self . inner_version == 6 ) :
   II1IIIi = ( II1IIIi >> 64 ) ^ ( II1IIIi & 0xffffffffffffffff )
   II1IIIi = ( II1IIIi >> 32 ) ^ ( II1IIIi & 0xffffffff )
   II1IIIi = ( II1IIIi >> 16 ) ^ ( II1IIIi & 0xffff )
   if 91 - 91: i1IIi . iII111i
  self . udp_sport = 0xf000 | ( II1IIIi & 0xfff )
  if 37 - 37: iII111i - I11i + iIii1I11I1II1 / I1Ii111 - OoO0O00 . o0oOOo0O0Ooo
  if 62 - 62: I1ii11iIi11i
 def print_packet ( self , s_or_r , is_lisp_packet ) :
  if ( is_lisp_packet == False ) :
   I11IiI1iII = "{} -> {}" . format ( self . inner_source . print_address ( ) ,
 self . inner_dest . print_address ( ) )
   dprint ( ( "{} {}, tos/ttl: {}/{}, length: {}, packet: {} ..." ) . format ( bold ( s_or_r , False ) ,
   # OOooOOo . iII111i
 green ( I11IiI1iII , False ) , self . inner_tos ,
 self . inner_ttl , len ( self . packet ) ,
 lisp_format_packet ( self . packet [ 0 : 60 ] ) ) )
   return
   if 94 - 94: IiII / I1Ii111 * IiII - ooOoO0o
   if 89 - 89: iIii1I11I1II1
  if ( s_or_r . find ( "Receive" ) != - 1 ) :
   i11 = "decap"
   i11 += "-vxlan" if self . udp_dport == LISP_VXLAN_DATA_PORT else ""
  else :
   i11 = s_or_r
   if ( i11 in [ "Send" , "Replicate" ] or i11 . find ( "Fragment" ) != - 1 ) :
    i11 = "encap"
    if 67 - 67: I11i / O0 * Ii1I - IiII . OoooooooOO + IiII
    if 20 - 20: I1Ii111 - OoOoOO00
  ooOO = "{} -> {}" . format ( self . outer_source . print_address_no_iid ( ) ,
 self . outer_dest . print_address_no_iid ( ) )
  if 5 - 5: OoOoOO00 % I1ii11iIi11i . ooOoO0o . I11i - i11iIiiIii
  if 39 - 39: i11iIiiIii + OOooOOo % iII111i + Ii1I * I1IiiI + I1Ii111
  if 72 - 72: II111iiii + I1Ii111 * OOooOOo . I1IiiI
  if 51 - 51: iII111i
  if 81 - 81: O0
  if ( self . lisp_header . get_instance_id ( ) == 0xffffff ) :
   iiI1 = ( "{} LISP packet, outer RLOCs: {}, outer tos/ttl: " + "{}/{}, outer UDP: {} -> {}, " )
   if 38 - 38: iII111i
   iiI1 += bold ( "control-packet" , False ) + ": {} ..."
   if 78 - 78: i11iIiiIii . IiII % OoooooooOO - IiII - IiII + Ii1I
   dprint ( iiI1 . format ( bold ( s_or_r , False ) , red ( ooOO , False ) ,
 self . outer_tos , self . outer_ttl , self . udp_sport ,
 self . udp_dport , lisp_format_packet ( self . packet [ 0 : 56 ] ) ) )
   return
  else :
   iiI1 = ( "{} LISP packet, outer RLOCs: {}, outer tos/ttl: " + "{}/{}, outer UDP: {} -> {}, inner EIDs: {}, " + "inner tos/ttl: {}/{}, length: {}, {}, packet: {} ..." )
   if 11 - 11: I11i
   if 20 - 20: O0 . i11iIiiIii * i1IIi % O0 . I1IiiI
   if 53 - 53: ooOoO0o / OoooooooOO - II111iiii
   if 68 - 68: OoooooooOO . OoooooooOO . iIii1I11I1II1 / ooOoO0o - I11i % O0
  if ( self . lisp_header . k_bits ) :
   if ( i11 == "encap" ) : i11 = "encrypt/encap"
   if ( i11 == "decap" ) : i11 = "decap/decrypt"
   if 19 - 19: OoooooooOO * oO0o
   if 60 - 60: II111iiii - iII111i + o0oOOo0O0Ooo % OOooOOo
  I11IiI1iII = "{} -> {}" . format ( self . inner_source . print_address ( ) ,
 self . inner_dest . print_address ( ) )
  if 97 - 97: O0 % O0
  dprint ( iiI1 . format ( bold ( s_or_r , False ) , red ( ooOO , False ) ,
 self . outer_tos , self . outer_ttl , self . udp_sport , self . udp_dport ,
 green ( I11IiI1iII , False ) , self . inner_tos , self . inner_ttl ,
 len ( self . packet ) , self . lisp_header . print_header ( i11 ) ,
 lisp_format_packet ( self . packet [ 0 : 56 ] ) ) )
  if 35 - 35: iII111i - Ii1I . i11iIiiIii % O0 % I1ii11iIi11i
  if 92 - 92: OOooOOo % II111iiii . iII111i
 def print_eid_tuple ( self ) :
  return ( lisp_print_eid_tuple ( self . inner_source , self . inner_dest ) )
  if 46 - 46: OoOoOO00 + I1IiiI % OoooooooOO * i11iIiiIii - Oo0Ooo
  if 47 - 47: iII111i * OoOoOO00 * IiII
 def get_raw_socket ( self ) :
  II1ii1ii11I1 = str ( self . lisp_header . get_instance_id ( ) )
  if ( II1ii1ii11I1 == "0" ) : return ( None )
  if ( lisp_iid_to_interface . has_key ( II1ii1ii11I1 ) == False ) : return ( None )
  if 46 - 46: Ii1I
  O0OOoooo0 = lisp_iid_to_interface [ II1ii1ii11I1 ]
  oOOOOOOOoO = O0OOoooo0 . get_socket ( )
  if ( oOOOOOOOoO == None ) :
   o0oOo = bold ( "SO_BINDTODEVICE" , False )
   ii1 = ( os . getenv ( "LISP_ENFORCE_BINDTODEVICE" ) != None )
   lprint ( "{} required for multi-tenancy support, {} packet" . format ( o0oOo , "drop" if ii1 else "forward" ) )
   if 64 - 64: Ii1I . OoooooooOO - I1ii11iIi11i
   if ( ii1 ) : return ( None )
   if 19 - 19: Oo0Ooo
   if 15 - 15: Oo0Ooo . ooOoO0o / o0oOOo0O0Ooo
  II1ii1ii11I1 = bold ( II1ii1ii11I1 , False )
  OooOo = bold ( O0OOoooo0 . device , False )
  dprint ( "Send packet on instance-id {} interface {}" . format ( II1ii1ii11I1 , OooOo ) )
  return ( oOOOOOOOoO )
  if 23 - 23: OoO0O00 % OoooooooOO * ooOoO0o
  if 6 - 6: I1IiiI . II111iiii + I1Ii111 / OoO0O00 % I1IiiI . OoooooooOO
 def log_flow ( self , encap ) :
  global lisp_flow_log
  if 64 - 64: iIii1I11I1II1 + II111iiii . iII111i % Oo0Ooo * ooOoO0o
  iiii1i1 = os . path . exists ( "./log-flows" )
  if ( len ( lisp_flow_log ) == LISP_FLOW_LOG_SIZE or iiii1i1 ) :
   OOooooO0 = [ lisp_flow_log ]
   lisp_flow_log = [ ]
   threading . Thread ( target = lisp_write_flow_log , args = OOooooO0 ) . start ( )
   if ( iiii1i1 ) : os . system ( "rm ./log-flows" )
   return
   if 23 - 23: iII111i / OoOoOO00 + o0oOOo0O0Ooo . O0
   if 76 - 76: OoOoOO00 . IiII - II111iiii * OoO0O00
  iiiI = datetime . datetime . now ( )
  lisp_flow_log . append ( [ iiiI , encap , self . packet , self ] )
  if 78 - 78: iIii1I11I1II1 / O0 * oO0o / iII111i / OoOoOO00
  if 15 - 15: ooOoO0o / oO0o
 def print_flow ( self , ts , encap , packet ) :
  ts = ts . strftime ( "%m/%d/%y %H:%M:%S.%f" ) [ : - 3 ]
  O0Oo00o0o = "{}: {}" . format ( ts , "encap" if encap else "decap" )
  if 80 - 80: i11iIiiIii % iIii1I11I1II1 / i11iIiiIii
  OO = red ( self . outer_source . print_address_no_iid ( ) , False )
  oOO0ooo0O = red ( self . outer_dest . print_address_no_iid ( ) , False )
  ii1IIi1IIIIi1 = green ( self . inner_source . print_address ( ) , False )
  iI1i1iii = green ( self . inner_dest . print_address ( ) , False )
  if 16 - 16: i1IIi * ooOoO0o % OoO0O00 + Ii1I
  if ( self . lisp_header . get_instance_id ( ) == 0xffffff ) :
   O0Oo00o0o += " {}:{} -> {}:{}, LISP control message type {}\n"
   O0Oo00o0o = O0Oo00o0o . format ( OO , self . udp_sport , oOO0ooo0O , self . udp_dport ,
 self . inner_version )
   return ( O0Oo00o0o )
   if 50 - 50: oO0o - OoooooooOO + iII111i % OoO0O00
   if 12 - 12: i1IIi / I1ii11iIi11i - iII111i . i11iIiiIii / i1IIi / OoooooooOO
  if ( self . outer_dest . is_null ( ) == False ) :
   O0Oo00o0o += " {}:{} -> {}:{}, len/tos/ttl {}/{}/{}"
   O0Oo00o0o = O0Oo00o0o . format ( OO , self . udp_sport , oOO0ooo0O , self . udp_dport ,
 len ( packet ) , self . outer_tos , self . outer_ttl )
   if 88 - 88: Ii1I / i11iIiiIii % OoOoOO00 % OOooOOo
   if 70 - 70: I1ii11iIi11i . I1ii11iIi11i / I11i . I1ii11iIi11i
   if 37 - 37: i1IIi . I1Ii111 - II111iiii % o0oOOo0O0Ooo - i1IIi . oO0o
   if 34 - 34: iIii1I11I1II1 / II111iiii
   if 3 - 3: o0oOOo0O0Ooo - OoooooooOO + iII111i . I11i
  if ( self . lisp_header . k_bits != 0 ) :
   o00000Oo = "\n"
   if ( self . packet_error != "" ) :
    o00000Oo = " ({})" . format ( self . packet_error ) + o00000Oo
    if 63 - 63: II111iiii * I1IiiI - OoooooooOO / I1IiiI
   O0Oo00o0o += ", encrypted" + o00000Oo
   return ( O0Oo00o0o )
   if 50 - 50: OoOoOO00 % Ii1I + OoOoOO00 * Ii1I - OOooOOo
   if 94 - 94: iIii1I11I1II1
   if 1 - 1: O0
   if 2 - 2: OoO0O00 . I11i
   if 97 - 97: Oo0Ooo
  if ( self . outer_dest . is_null ( ) == False ) :
   packet = packet [ 36 : : ] if self . outer_version == 4 else packet [ 56 : : ]
   if 65 - 65: Oo0Ooo % OOooOOo / i11iIiiIii / iIii1I11I1II1 . I1Ii111 + ooOoO0o
   if 92 - 92: oO0o
  Iiii = packet [ 9 ] if self . inner_version == 4 else packet [ 6 ]
  Iiii = struct . unpack ( "B" , Iiii ) [ 0 ]
  if 96 - 96: I1Ii111 * iIii1I11I1II1 / OoOoOO00 % OOooOOo * II111iiii
  O0Oo00o0o += " {} -> {}, len/tos/ttl/prot {}/{}/{}/{}"
  O0Oo00o0o = O0Oo00o0o . format ( ii1IIi1IIIIi1 , iI1i1iii , len ( packet ) , self . inner_tos ,
 self . inner_ttl , Iiii )
  if 3 - 3: OOooOOo . Oo0Ooo / i11iIiiIii + OoO0O00
  if 47 - 47: IiII . OOooOOo
  if 96 - 96: I11i % II111iiii / ooOoO0o % OOooOOo / ooOoO0o % i11iIiiIii
  if 57 - 57: I11i - I11i % II111iiii % Oo0Ooo . o0oOOo0O0Ooo % Oo0Ooo
  if ( Iiii in [ 6 , 17 ] ) :
   OoOOOO00 = packet [ 20 : 24 ] if self . inner_version == 4 else packet [ 40 : 44 ]
   if ( len ( OoOOOO00 ) == 4 ) :
    OoOOOO00 = socket . ntohl ( struct . unpack ( "I" , OoOOOO00 ) [ 0 ] )
    O0Oo00o0o += ", ports {} -> {}" . format ( OoOOOO00 >> 16 , OoOOOO00 & 0xffff )
    if 15 - 15: OOooOOo * ooOoO0o + II111iiii . I1Ii111 . oO0o
  elif ( Iiii == 1 ) :
   I1I11iII11 = packet [ 26 : 28 ] if self . inner_version == 4 else packet [ 46 : 48 ]
   if ( len ( I1I11iII11 ) == 2 ) :
    I1I11iII11 = socket . ntohs ( struct . unpack ( "H" , I1I11iII11 ) [ 0 ] )
    O0Oo00o0o += ", icmp-seq {}" . format ( I1I11iII11 )
    if 58 - 58: iII111i % iII111i + ooOoO0o * o0oOOo0O0Ooo - II111iiii - I1ii11iIi11i
    if 95 - 95: Ii1I % I1IiiI + Oo0Ooo * o0oOOo0O0Ooo * iII111i
  if ( self . packet_error != "" ) :
   O0Oo00o0o += " ({})" . format ( self . packet_error )
   if 22 - 22: Ii1I + oO0o . OoOoOO00
  O0Oo00o0o += "\n"
  return ( O0Oo00o0o )
  if 84 - 84: i11iIiiIii / o0oOOo0O0Ooo % iIii1I11I1II1 . ooOoO0o . OoO0O00 / iII111i
  if 55 - 55: iII111i
 def is_trace ( self ) :
  OoOOOO00 = [ self . inner_sport , self . inner_dport ]
  return ( self . inner_protocol == LISP_UDP_PROTOCOL and
 LISP_TRACE_PORT in OoOOOO00 )
  if 3 - 3: iIii1I11I1II1
  if 19 - 19: II111iiii . OoO0O00 * OoO0O00 + I1IiiI % Oo0Ooo
  if 21 - 21: OoOoOO00 - i11iIiiIii - OoOoOO00
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
  if 11 - 11: I1ii11iIi11i / O0 + II111iiii
  if 95 - 95: I1Ii111 + IiII * iIii1I11I1II1
LISP_N_BIT = 0x80000000
LISP_L_BIT = 0x40000000
LISP_E_BIT = 0x20000000
LISP_V_BIT = 0x10000000
LISP_I_BIT = 0x08000000
LISP_P_BIT = 0x04000000
LISP_K_BITS = 0x03000000
if 17 - 17: OoO0O00 - Oo0Ooo * O0 / Ii1I
class lisp_data_header ( ) :
 def __init__ ( self ) :
  self . first_long = 0
  self . second_long = 0
  self . k_bits = 0
  if 19 - 19: i1IIi - iIii1I11I1II1 . I11i
  if 2 - 2: Ii1I
 def print_header ( self , e_or_d ) :
  Ii1i111iI = lisp_hex_string ( self . first_long & 0xffffff )
  iII1ii = lisp_hex_string ( self . second_long ) . zfill ( 8 )
  if 51 - 51: o0oOOo0O0Ooo . I1ii11iIi11i * Ii1I / Oo0Ooo * II111iiii / O0
  iiI1 = ( "{} LISP-header -> flags: {}{}{}{}{}{}{}{}, nonce: {}, " + "iid/lsb: {}" )
  if 44 - 44: i11iIiiIii % I1Ii111 % oO0o + I11i * oO0o . Ii1I
  return ( iiI1 . format ( bold ( e_or_d , False ) ,
 "N" if ( self . first_long & LISP_N_BIT ) else "n" ,
 "L" if ( self . first_long & LISP_L_BIT ) else "l" ,
 "E" if ( self . first_long & LISP_E_BIT ) else "e" ,
 "V" if ( self . first_long & LISP_V_BIT ) else "v" ,
 "I" if ( self . first_long & LISP_I_BIT ) else "i" ,
 "P" if ( self . first_long & LISP_P_BIT ) else "p" ,
 "K" if ( self . k_bits in [ 2 , 3 ] ) else "k" ,
 "K" if ( self . k_bits in [ 1 , 3 ] ) else "k" ,
 Ii1i111iI , iII1ii ) )
  if 89 - 89: OoooooooOO % II111iiii - OoO0O00 % i11iIiiIii
  if 7 - 7: IiII
 def encode ( self ) :
  III11i = "II"
  Ii1i111iI = socket . htonl ( self . first_long )
  iII1ii = socket . htonl ( self . second_long )
  if 54 - 54: I1Ii111 / o0oOOo0O0Ooo
  I11IIIIiII = struct . pack ( III11i , Ii1i111iI , iII1ii )
  return ( I11IIIIiII )
  if 52 - 52: II111iiii / II111iiii / I1IiiI - I1Ii111
  if 91 - 91: I1IiiI + o0oOOo0O0Ooo % II111iiii + OoO0O00
 def decode ( self , packet ) :
  III11i = "II"
  Oo0o0OOo0Oo0 = struct . calcsize ( III11i )
  if ( len ( packet ) < Oo0o0OOo0Oo0 ) : return ( False )
  if 88 - 88: Ii1I / OoooooooOO % OoOoOO00 - i1IIi
  Ii1i111iI , iII1ii = struct . unpack ( III11i , packet [ : Oo0o0OOo0Oo0 ] )
  if 49 - 49: o0oOOo0O0Ooo - iIii1I11I1II1
  if 61 - 61: iII111i * ooOoO0o
  self . first_long = socket . ntohl ( Ii1i111iI )
  self . second_long = socket . ntohl ( iII1ii )
  self . k_bits = ( self . first_long & LISP_K_BITS ) >> 24
  return ( True )
  if 1 - 1: I1Ii111 * OoOoOO00
  if 100 - 100: I1ii11iIi11i / O0 / ooOoO0o + I1ii11iIi11i
 def key_id ( self , key_id ) :
  self . first_long &= ~ ( 0x3 << 24 )
  self . first_long |= ( ( key_id & 0x3 ) << 24 )
  self . k_bits = key_id
  if 48 - 48: OoooooooOO . iII111i + O0
  if 85 - 85: II111iiii - Ii1I
 def nonce ( self , nonce ) :
  self . first_long |= LISP_N_BIT
  self . first_long |= nonce
  if 93 - 93: IiII / i11iIiiIii - oO0o + OoO0O00 / i1IIi
  if 62 - 62: I1ii11iIi11i / OoooooooOO * I1IiiI - i1IIi
 def map_version ( self , version ) :
  self . first_long |= LISP_V_BIT
  self . first_long |= version
  if 81 - 81: oO0o / O0 * ooOoO0o % OoOoOO00 / O0
  if 85 - 85: OoooooooOO + OoooooooOO
 def instance_id ( self , iid ) :
  if ( iid == 0 ) : return
  self . first_long |= LISP_I_BIT
  self . second_long &= 0xff
  self . second_long |= ( iid << 8 )
  if 23 - 23: i1IIi
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
  OOii = "lisp-itr" if lisp_i_am_itr else "lisp-etr"
  oOiii1IiII = "lisp-etr" if lisp_i_am_itr else "lisp-itr"
  ipc = lisp_command_ipc ( ipc , OOii )
  lisp_ipc ( ipc , ipc_socket , oOiii1IiII )
  if 14 - 14: I1ii11iIi11i * i1IIi / iIii1I11I1II1 / oO0o / O0 % Oo0Ooo
  if 1 - 1: OOooOOo % o0oOOo0O0Ooo + OoO0O00
 def send_request_ipc ( self , ipc_socket , nonce ) :
  nonce = lisp_hex_string ( nonce )
  OOO000OOOO0oO = "nonce%R%{}%{}" . format ( self . rloc_str , nonce )
  self . send_ipc ( ipc_socket , OOO000OOOO0oO )
  if 37 - 37: OoO0O00 - Oo0Ooo
  if 38 - 38: i11iIiiIii / OoO0O00
 def send_echo_ipc ( self , ipc_socket , nonce ) :
  nonce = lisp_hex_string ( nonce )
  OOO000OOOO0oO = "nonce%E%{}%{}" . format ( self . rloc_str , nonce )
  self . send_ipc ( ipc_socket , OOO000OOOO0oO )
  if 64 - 64: IiII
  if 80 - 80: I1IiiI - i11iIiiIii / OoO0O00 / OoOoOO00 + OoOoOO00
 def receive_request ( self , ipc_socket , nonce ) :
  oo000o = self . request_nonce_rcvd
  self . request_nonce_rcvd = nonce
  self . last_request_nonce_rcvd = lisp_get_timestamp ( )
  if ( lisp_i_am_rtr ) : return
  if ( oo000o != nonce ) : self . send_request_ipc ( ipc_socket , nonce )
  if 6 - 6: OOooOOo + I1ii11iIi11i + Oo0Ooo
  if 52 - 52: IiII * Oo0Ooo + OoooooooOO
 def receive_echo ( self , ipc_socket , nonce ) :
  if ( self . request_nonce_sent != nonce ) : return
  self . last_echo_nonce_rcvd = lisp_get_timestamp ( )
  if ( self . echo_nonce_rcvd == nonce ) : return
  if 93 - 93: ooOoO0o
  self . echo_nonce_rcvd = nonce
  if ( lisp_i_am_rtr ) : return
  self . send_echo_ipc ( ipc_socket , nonce )
  if 15 - 15: i11iIiiIii / o0oOOo0O0Ooo / OoO0O00 . OoOoOO00 % oO0o
  if 29 - 29: o0oOOo0O0Ooo
 def get_request_or_echo_nonce ( self , ipc_socket , remote_rloc ) :
  if 13 - 13: Ii1I + Ii1I . I11i
  if 57 - 57: ooOoO0o
  if 94 - 94: OoO0O00 - II111iiii % iIii1I11I1II1
  if 92 - 92: Oo0Ooo
  if 40 - 40: I1IiiI
  if ( self . request_nonce_sent and self . echo_nonce_sent and remote_rloc ) :
   oO0oOo0o = lisp_myrlocs [ 0 ] if remote_rloc . is_ipv4 ( ) else lisp_myrlocs [ 1 ]
   if 7 - 7: OoOoOO00 / OoOoOO00 . I1Ii111 * O0 + IiII + oO0o
   if 98 - 98: II111iiii * IiII - I1IiiI % o0oOOo0O0Ooo - iII111i % I1ii11iIi11i
   if ( remote_rloc . address > oO0oOo0o . address ) :
    i1 = "exit"
    self . request_nonce_sent = None
   else :
    i1 = "stay in"
    self . echo_nonce_sent = None
    if 69 - 69: i1IIi % OoO0O00 % I1Ii111 / ooOoO0o / ooOoO0o
    if 6 - 6: II111iiii % I1ii11iIi11i % i1IIi * ooOoO0o
   iII = bold ( "collision" , False )
   oooo0 = red ( oO0oOo0o . print_address_no_iid ( ) , False )
   oooO0 = red ( remote_rloc . print_address_no_iid ( ) , False )
   lprint ( "Echo nonce {}, {} -> {}, {} request-nonce mode" . format ( iII ,
 oooo0 , oooO0 , i1 ) )
   if 7 - 7: OoO0O00 * iII111i
   if 16 - 16: I1Ii111 . i1IIi . IiII
   if 50 - 50: OoO0O00 - II111iiii * OoooooooOO - I1IiiI . O0 + O0
   if 80 - 80: o0oOOo0O0Ooo
   if 50 - 50: ooOoO0o
  if ( self . echo_nonce_sent != None ) :
   i11IIoOOoOo0Ooo = self . echo_nonce_sent
   ooOoOOOOo = bold ( "Echoing" , False )
   lprint ( "{} nonce 0x{} to {}" . format ( ooOoOOOOo ,
 lisp_hex_string ( i11IIoOOoOo0Ooo ) , red ( self . rloc_str , False ) ) )
   self . last_echo_nonce_sent = lisp_get_timestamp ( )
   self . echo_nonce_sent = None
   return ( i11IIoOOoOo0Ooo )
   if 81 - 81: i11iIiiIii * iIii1I11I1II1 / Oo0Ooo * OOooOOo
   if 83 - 83: i11iIiiIii - I1IiiI * i11iIiiIii
   if 59 - 59: iII111i - OoooooooOO / ooOoO0o + I1ii11iIi11i . o0oOOo0O0Ooo - iII111i
   if 29 - 29: oO0o
   if 26 - 26: O0 % OOooOOo - IiII . OOooOOo
   if 70 - 70: o0oOOo0O0Ooo + I11i / iII111i + ooOoO0o / I1IiiI
   if 33 - 33: OoooooooOO . O0
  i11IIoOOoOo0Ooo = self . request_nonce_sent
  oOo = self . last_request_nonce_sent
  if ( i11IIoOOoOo0Ooo and oOo != None ) :
   if ( time . time ( ) - oOo >= LISP_NONCE_ECHO_INTERVAL ) :
    self . request_nonce_sent = None
    lprint ( "Stop request-nonce mode for {}, nonce 0x{}" . format ( red ( self . rloc_str , False ) , lisp_hex_string ( i11IIoOOoOo0Ooo ) ) )
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
  if ( i11IIoOOoOo0Ooo == None ) :
   i11IIoOOoOo0Ooo = lisp_get_data_nonce ( )
   if ( self . recently_requested ( ) ) : return ( i11IIoOOoOo0Ooo )
   if 88 - 88: oO0o * I1IiiI / OoO0O00 - OOooOOo / i1IIi . I1Ii111
   self . request_nonce_sent = i11IIoOOoOo0Ooo
   lprint ( "Start request-nonce mode for {}, nonce 0x{}" . format ( red ( self . rloc_str , False ) , lisp_hex_string ( i11IIoOOoOo0Ooo ) ) )
   if 26 - 26: i11iIiiIii - ooOoO0o
   self . last_new_request_nonce_sent = lisp_get_timestamp ( )
   if 45 - 45: ooOoO0o + II111iiii % iII111i
   if 55 - 55: ooOoO0o - oO0o % I1IiiI
   if 61 - 61: ooOoO0o
   if 22 - 22: iIii1I11I1II1 / ooOoO0o / I1IiiI - o0oOOo0O0Ooo
   if 21 - 21: oO0o . i11iIiiIii * I11i . OOooOOo / OOooOOo
   if ( lisp_i_am_itr == False ) : return ( i11IIoOOoOo0Ooo | 0x80000000 )
   self . send_request_ipc ( ipc_socket , i11IIoOOoOo0Ooo )
  else :
   lprint ( "Continue request-nonce mode for {}, nonce 0x{}" . format ( red ( self . rloc_str , False ) , lisp_hex_string ( i11IIoOOoOo0Ooo ) ) )
   if 42 - 42: OoooooooOO / I1Ii111 . o0oOOo0O0Ooo / O0 - IiII * IiII
   if 1 - 1: Ii1I % I1Ii111
   if 97 - 97: OoOoOO00
   if 13 - 13: OoOoOO00 % OOooOOo . O0 / Oo0Ooo % Oo0Ooo
   if 19 - 19: I1Ii111 % ooOoO0o - ooOoO0o % I1IiiI . OOooOOo - OoooooooOO
   if 100 - 100: I1IiiI + Ii1I + o0oOOo0O0Ooo . i1IIi % OoooooooOO
   if 64 - 64: O0 % i1IIi * I1Ii111 - Ii1I + Oo0Ooo
  self . last_request_nonce_sent = lisp_get_timestamp ( )
  return ( i11IIoOOoOo0Ooo | 0x80000000 )
  if 65 - 65: OoOoOO00 . i11iIiiIii
  if 36 - 36: oO0o * iII111i + IiII * iII111i . I1ii11iIi11i - iIii1I11I1II1
 def request_nonce_timeout ( self ) :
  if ( self . request_nonce_sent == None ) : return ( False )
  if ( self . request_nonce_sent == self . echo_nonce_rcvd ) : return ( False )
  if 14 - 14: I11i * oO0o + i11iIiiIii
  I1IiIii11I = time . time ( ) - self . last_request_nonce_sent
  o0o0o = self . last_echo_nonce_rcvd
  return ( I1IiIii11I >= LISP_NONCE_ECHO_INTERVAL and o0o0o == None )
  if 31 - 31: II111iiii . OoooooooOO + OoO0O00 + o0oOOo0O0Ooo . I1IiiI . II111iiii
  if 3 - 3: I11i / I1Ii111 * IiII - O0 + I1IiiI / IiII
 def recently_requested ( self ) :
  o0o0o = self . last_request_nonce_sent
  if ( o0o0o == None ) : return ( False )
  if 19 - 19: i1IIi % II111iiii
  I1IiIii11I = time . time ( ) - o0o0o
  return ( I1IiIii11I <= LISP_NONCE_ECHO_INTERVAL )
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
  I1IiIii11I = time . time ( ) - o0o0o
  if ( I1IiIii11I <= LISP_NONCE_ECHO_INTERVAL ) : return ( True )
  if 64 - 64: i1IIi
  if 71 - 71: IiII * o0oOOo0O0Ooo
  if 99 - 99: o0oOOo0O0Ooo
  if 28 - 28: OoooooooOO % O0 - OOooOOo / o0oOOo0O0Ooo / I1IiiI
  if 41 - 41: II111iiii * IiII / OoO0O00 . oO0o
  if 50 - 50: OoooooooOO + iIii1I11I1II1 / oO0o / OOooOOo . i11iIiiIii . ooOoO0o
  o0o0o = self . last_new_request_nonce_sent
  if ( o0o0o == None ) : o0o0o = 0
  I1IiIii11I = time . time ( ) - o0o0o
  return ( I1IiIii11I <= LISP_NONCE_ECHO_INTERVAL )
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
  oOOOOOOOoO = space ( 4 )
  if 83 - 83: O0 / OoO0O00
  II1i11i1iIi11 = "Nonce-Echoing:\n"
  II1i11i1iIi11 += ( "{}Last request-nonce sent: {}\n{}Last echo-nonce " + "received: {}\n" ) . format ( oOOOOOOOoO , oO0o0o0 , oOOOOOOOoO , ii11Ii1iii1I1 )
  if 62 - 62: I11i
  II1i11i1iIi11 += ( "{}Last request-nonce received: {}\n{}Last echo-nonce " + "sent: {}" ) . format ( oOOOOOOOoO , I1Ii11I1i1iii , oOOOOOOOoO , i11I111iIiI )
  if 73 - 73: Ii1I % OoO0O00 * OOooOOo
  if 84 - 84: Oo0Ooo
  return ( II1i11i1iIi11 )
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
   OOO0OOoOOO = lisp_hex_string ( self . local_private_key ) . zfill ( 32 )
   self . curve25519 = curve25519 . Private ( OOO0OOoOOO )
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
  o0OOo0O = self . iv
  if ( self . cipher_suite == LISP_CS_25519_CHACHA ) :
   o0OOo0O = struct . pack ( "Q" , o0OOo0O & LISP_8_64_MASK )
  elif ( self . cipher_suite == LISP_CS_25519_GCM ) :
   iIIIII = struct . pack ( "I" , ( o0OOo0O >> 64 ) & LISP_4_32_MASK )
   iiiII = struct . pack ( "Q" , o0OOo0O & LISP_8_64_MASK )
   o0OOo0O = iIIIII + iiiII
  else :
   o0OOo0O = struct . pack ( "QQ" , o0OOo0O >> 64 , o0OOo0O & LISP_8_64_MASK )
  return ( o0OOo0O )
  if 83 - 83: i11iIiiIii + oO0o % i1IIi . IiII + I1ii11iIi11i
  if 62 - 62: oO0o . I1Ii111 - OoooooooOO * II111iiii . i11iIiiIii
 def key_length ( self , key ) :
  if ( type ( key ) != str ) : key = self . normalize_pub_key ( key )
  return ( len ( key ) / 2 )
  if 13 - 13: iIii1I11I1II1 * o0oOOo0O0Ooo - i11iIiiIii
  if 63 - 63: OoooooooOO * I1Ii111
 def print_key ( self , key ) :
  oO0Oooo0OoO = self . normalize_pub_key ( key )
  return ( "0x{}...{}({})" . format ( oO0Oooo0OoO [ 0 : 4 ] , oO0Oooo0OoO [ - 4 : : ] , self . key_length ( oO0Oooo0OoO ) ) )
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
  oooo0 = bold ( "local-key: " , False ) if do_bold else "local-key: "
  if ( self . local_public_key == None ) :
   oooo0 += "none"
  else :
   oooo0 += self . print_key ( self . local_public_key )
   if 28 - 28: iII111i - o0oOOo0O0Ooo
  oooO0 = bold ( "remote-key: " , False ) if do_bold else "remote-key: "
  if ( self . remote_public_key == None ) :
   oooO0 += "none"
  else :
   oooO0 += self . print_key ( self . remote_public_key )
   if 92 - 92: Oo0Ooo % o0oOOo0O0Ooo - ooOoO0o / ooOoO0o / OoOoOO00
  oo0o0o0o0O = "ECDH" if ( self . curve25519 ) else "DH"
  o0Ooo = self . cipher_suite
  return ( "{} cipher-suite: {}, {}, {}" . format ( oo0o0o0o0O , o0Ooo , oooo0 , oooO0 ) )
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
  OOO0OOoOOO = self . local_private_key
  IiIoO0oo0 = self . dh_g_value
  IiIiI1 = self . dh_p_value
  return ( int ( ( IiIoO0oo0 ** OOO0OOoOOO ) % IiIiI1 ) )
  if 14 - 14: I1IiiI
  if 8 - 8: o0oOOo0O0Ooo
 def compute_shared_key ( self , ed , print_shared = False ) :
  OOO0OOoOOO = self . local_private_key
  ooOO0O0O = self . remote_public_key
  if 18 - 18: oO0o * O0 - I1IiiI + O0 + I1Ii111
  OOO00 = bold ( "Compute {} shared-key" . format ( ed ) , False )
  lprint ( "{}, key-material: {}" . format ( OOO00 , self . print_keys ( ) ) )
  if 64 - 64: OoOoOO00 + OoO0O00 + i11iIiiIii % iIii1I11I1II1 % iIii1I11I1II1
  if ( self . curve25519 ) :
   ooOO0o = curve25519 . Public ( ooOO0O0O )
   self . shared_key = self . curve25519 . get_shared_key ( ooOO0o )
  else :
   IiIiI1 = self . dh_p_value
   self . shared_key = ( ooOO0O0O ** OOO0OOoOOO ) % IiIiI1
   if 88 - 88: OoooooooOO
   if 46 - 46: O0 % OoooooooOO
   if 22 - 22: iII111i + OoooooooOO - OoOoOO00 - OoO0O00 * I1Ii111 - oO0o
   if 99 - 99: ooOoO0o / I1IiiI . Ii1I - Ii1I * I1IiiI
   if 24 - 24: I11i * OoO0O00 - oO0o / iIii1I11I1II1 - Oo0Ooo . OOooOOo
   if 2 - 2: ooOoO0o - O0 - I1ii11iIi11i / I11i * OoOoOO00
   if 26 - 26: I1ii11iIi11i + I1Ii111 - oO0o + IiII % OOooOOo
  if ( print_shared ) :
   oO0Oooo0OoO = self . print_key ( self . shared_key )
   lprint ( "Computed shared-key: {}" . format ( oO0Oooo0OoO ) )
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
  oooo0 = self . local_public_key
  if ( type ( oooo0 ) != long ) : oooo0 = int ( binascii . hexlify ( oooo0 ) , 16 )
  oooO0 = self . remote_public_key
  if ( type ( oooO0 ) != long ) : oooO0 = int ( binascii . hexlify ( oooO0 ) , 16 )
  IIIIi11111 = "0001" + "lisp-crypto" + lisp_hex_string ( oooo0 ^ oooO0 ) + "0100"
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
   ooOooOOOoO0 = o0o0Oo ( self . encrypt_key , self . icv_key , nonce , packet )
   ooOooOOOoO0 = ooOoo00OoO00 ( ooOooOOOoO0 )
  else :
   OOO0OOoOOO = binascii . unhexlify ( self . icv_key )
   ooOooOOOoO0 = hmac . new ( OOO0OOoOOO , packet , self . icv ) . hexdigest ( )
   ooOooOOOoO0 = ooOooOOOoO0 [ 0 : 40 ]
   if 27 - 27: II111iiii - i11iIiiIii - OoooooooOO
  return ( ooOooOOOoO0 )
  if 90 - 90: I1IiiI
  if 4 - 4: OOooOOo % ooOoO0o - OOooOOo - o0oOOo0O0Ooo
 def add_key_by_nonce ( self , nonce ) :
  if ( lisp_crypto_keys_by_nonce . has_key ( nonce ) == False ) :
   lisp_crypto_keys_by_nonce [ nonce ] = [ None , None , None , None ]
   if 30 - 30: IiII
  lisp_crypto_keys_by_nonce [ nonce ] [ self . key_id ] = self
  if 34 - 34: oO0o - II111iiii - o0oOOo0O0Ooo + iII111i + I1Ii111
  if 70 - 70: OoooooooOO + OoO0O00 * Oo0Ooo
 def delete_key_by_nonce ( self , nonce ) :
  if ( lisp_crypto_keys_by_nonce . has_key ( nonce ) == False ) : return
  lisp_crypto_keys_by_nonce . pop ( nonce )
  if 20 - 20: i11iIiiIii - II111iiii - ooOoO0o % oO0o . ooOoO0o
  if 50 - 50: iIii1I11I1II1 + I1Ii111 - I11i - OoooooooOO
 def add_key_by_rloc ( self , addr_str , encap ) :
  oO00O0oO = lisp_crypto_keys_by_rloc_encap if encap else lisp_crypto_keys_by_rloc_decap
  if 69 - 69: OOooOOo + OOooOOo * Ii1I * I11i + I1IiiI
  if 46 - 46: OOooOOo
  if ( oO00O0oO . has_key ( addr_str ) == False ) :
   oO00O0oO [ addr_str ] = [ None , None , None , None ]
   if 17 - 17: I11i / II111iiii * o0oOOo0O0Ooo / Oo0Ooo + iII111i . oO0o
  oO00O0oO [ addr_str ] [ self . key_id ] = self
  if 19 - 19: OOooOOo * I11i
  if 85 - 85: i1IIi % o0oOOo0O0Ooo * I1ii11iIi11i * OoO0O00 . II111iiii
  if 69 - 69: Ii1I / I1Ii111 % I1Ii111 / ooOoO0o + I1Ii111 / i1IIi
  if 70 - 70: OOooOOo - IiII . I1Ii111
  if 11 - 11: i11iIiiIii + o0oOOo0O0Ooo - I1Ii111 * i11iIiiIii - I1IiiI
  if ( encap == False ) :
   lisp_write_ipc_decap_key ( addr_str , oO00O0oO [ addr_str ] )
   if 49 - 49: i1IIi % oO0o / OOooOOo . I1ii11iIi11i - I1Ii111
   if 12 - 12: i11iIiiIii + I11i - I1ii11iIi11i
   if 27 - 27: iII111i
 def encode_lcaf ( self , rloc_addr ) :
  iIiii = self . normalize_pub_key ( self . local_public_key )
  o0O0OoO0o0o0 = self . key_length ( iIiii )
  O00 = ( 6 + o0O0OoO0o0o0 + 2 )
  if ( rloc_addr != None ) : O00 += rloc_addr . addr_length ( )
  if 4 - 4: oO0o + iIii1I11I1II1 * I1ii11iIi11i
  Ii11iIiiI = struct . pack ( "HBBBBHBB" , socket . htons ( LISP_AFI_LCAF ) , 0 , 0 ,
 LISP_LCAF_SECURITY_TYPE , 0 , socket . htons ( O00 ) , 1 , 0 )
  if 48 - 48: I11i
  if 14 - 14: iIii1I11I1II1 / o0oOOo0O0Ooo * IiII
  if 35 - 35: iIii1I11I1II1
  if 34 - 34: OoO0O00 % I1IiiI . o0oOOo0O0Ooo % OoO0O00 % OoO0O00
  if 30 - 30: I1IiiI + I1IiiI
  if 75 - 75: I1IiiI - ooOoO0o - I1IiiI % oO0o % OoooooooOO
  o0Ooo = self . cipher_suite
  Ii11iIiiI += struct . pack ( "BBH" , o0Ooo , 0 , socket . htons ( o0O0OoO0o0o0 ) )
  if 13 - 13: ooOoO0o * OoO0O00 % iIii1I11I1II1 / IiII * iII111i . Oo0Ooo
  if 23 - 23: ooOoO0o / IiII . iII111i * Ii1I
  if 87 - 87: i11iIiiIii
  if 34 - 34: i1IIi
  for oo0O0oO0O0O in range ( 0 , o0O0OoO0o0o0 * 2 , 16 ) :
   OOO0OOoOOO = int ( iIiii [ oo0O0oO0O0O : oo0O0oO0O0O + 16 ] , 16 )
   Ii11iIiiI += struct . pack ( "Q" , byte_swap_64 ( OOO0OOoOOO ) )
   if 64 - 64: iIii1I11I1II1 / IiII / Oo0Ooo - I1ii11iIi11i
   if 100 - 100: IiII + i1IIi * OoO0O00
   if 64 - 64: oO0o * i11iIiiIii . Oo0Ooo
   if 52 - 52: Oo0Ooo / ooOoO0o / iII111i - o0oOOo0O0Ooo / iII111i
   if 74 - 74: i1IIi . iIii1I11I1II1
  if ( rloc_addr ) :
   Ii11iIiiI += struct . pack ( "H" , socket . htons ( rloc_addr . afi ) )
   Ii11iIiiI += rloc_addr . pack_address ( )
   if 85 - 85: I1IiiI
  return ( Ii11iIiiI )
  if 10 - 10: O0 . II111iiii / OoooooooOO
  if 72 - 72: OoooooooOO . o0oOOo0O0Ooo + O0
 def decode_lcaf ( self , packet , lcaf_len ) :
  if 46 - 46: OoOoOO00 * I11i / oO0o + Oo0Ooo + IiII
  if 95 - 95: o0oOOo0O0Ooo - Ii1I
  if 67 - 67: I1ii11iIi11i * Oo0Ooo % o0oOOo0O0Ooo
  if 19 - 19: OoOoOO00 . OOooOOo . OoooooooOO
  if ( lcaf_len == 0 ) :
   III11i = "HHBBH"
   Oo0o0OOo0Oo0 = struct . calcsize ( III11i )
   if ( len ( packet ) < Oo0o0OOo0Oo0 ) : return ( None )
   if 79 - 79: OOooOOo * ooOoO0o * I1IiiI * I1ii11iIi11i / I1ii11iIi11i
   ii1iI1i1 , O000OOOoOooO , o0oOoOOO , O000OOOoOooO , lcaf_len = struct . unpack ( III11i , packet [ : Oo0o0OOo0Oo0 ] )
   if 74 - 74: iII111i / I1Ii111 / II111iiii - iII111i / oO0o % I11i
   if 19 - 19: IiII % OoooooooOO + OoooooooOO
   if ( o0oOoOOO != LISP_LCAF_SECURITY_TYPE ) :
    packet = packet [ lcaf_len + 6 : : ]
    return ( packet )
    if 7 - 7: i1IIi
   lcaf_len = socket . ntohs ( lcaf_len )
   packet = packet [ Oo0o0OOo0Oo0 : : ]
   if 91 - 91: OoOoOO00 - OoOoOO00 . IiII
   if 33 - 33: I1Ii111 - iIii1I11I1II1 / Ii1I % O0
   if 80 - 80: IiII % OoooooooOO - IiII
   if 27 - 27: I1Ii111 - o0oOOo0O0Ooo * I1ii11iIi11i - I1IiiI
   if 22 - 22: Oo0Ooo % OoooooooOO - Oo0Ooo - iII111i . Ii1I
   if 100 - 100: II111iiii / I1Ii111 / iII111i - I1ii11iIi11i * iIii1I11I1II1
  o0oOoOOO = LISP_LCAF_SECURITY_TYPE
  III11i = "BBBBH"
  Oo0o0OOo0Oo0 = struct . calcsize ( III11i )
  if ( len ( packet ) < Oo0o0OOo0Oo0 ) : return ( None )
  if 7 - 7: i1IIi . IiII % i11iIiiIii * I1ii11iIi11i . I11i % I1ii11iIi11i
  iII1i , O000OOOoOooO , o0Ooo , O000OOOoOooO , o0O0OoO0o0o0 = struct . unpack ( III11i ,
 packet [ : Oo0o0OOo0Oo0 ] )
  if 62 - 62: OoO0O00 . OoOoOO00
  if 22 - 22: ooOoO0o . i11iIiiIii . OoooooooOO . i1IIi
  if 12 - 12: OoOoOO00 % OOooOOo + oO0o . O0 % iIii1I11I1II1
  if 41 - 41: OoooooooOO
  if 13 - 13: I11i + I1Ii111 - I1Ii111 % oO0o / I11i
  if 4 - 4: I1IiiI + OOooOOo - IiII + iII111i
  packet = packet [ Oo0o0OOo0Oo0 : : ]
  o0O0OoO0o0o0 = socket . ntohs ( o0O0OoO0o0o0 )
  if ( len ( packet ) < o0O0OoO0o0o0 ) : return ( None )
  if 78 - 78: Ii1I
  if 29 - 29: II111iiii
  if 79 - 79: iIii1I11I1II1 - i11iIiiIii + ooOoO0o - II111iiii . iIii1I11I1II1
  if 84 - 84: Oo0Ooo % I11i * O0 * I11i
  O0Oo = [ LISP_CS_25519_CBC , LISP_CS_25519_GCM , LISP_CS_25519_CHACHA ,
 LISP_CS_1024 ]
  if ( o0Ooo not in O0Oo ) :
   lprint ( "Cipher-suites {} supported, received {}" . format ( O0Oo ,
 o0Ooo ) )
   packet = packet [ o0O0OoO0o0o0 : : ]
   return ( packet )
   if 70 - 70: O0 . iIii1I11I1II1 * II111iiii
   if 43 - 43: Oo0Ooo / I1Ii111 / i1IIi
  self . cipher_suite = o0Ooo
  if 3 - 3: Ii1I * ooOoO0o . OoO0O00 * OoooooooOO + OoOoOO00 / O0
  if 60 - 60: I11i
  if 97 - 97: i11iIiiIii * iIii1I11I1II1 / II111iiii
  if 66 - 66: II111iiii + iII111i * oO0o % I11i / i1IIi / iIii1I11I1II1
  if 62 - 62: OoOoOO00 + oO0o * IiII + O0 / OOooOOo + ooOoO0o
  iIiii = 0
  for oo0O0oO0O0O in range ( 0 , o0O0OoO0o0o0 , 8 ) :
   OOO0OOoOOO = byte_swap_64 ( struct . unpack ( "Q" , packet [ oo0O0oO0O0O : oo0O0oO0O0O + 8 ] ) [ 0 ] )
   iIiii <<= 64
   iIiii |= OOO0OOoOOO
   if 38 - 38: i1IIi / iIii1I11I1II1 + iII111i
  self . remote_public_key = iIiii
  if 26 - 26: I1ii11iIi11i . Ii1I % o0oOOo0O0Ooo
  if 4 - 4: I1Ii111
  if 80 - 80: Oo0Ooo . O0 % o0oOOo0O0Ooo . o0oOOo0O0Ooo
  if 52 - 52: OoO0O00 % i11iIiiIii . ooOoO0o % OoOoOO00 % OoooooooOO
  if 5 - 5: OoOoOO00 / O0 / i11iIiiIii
  if ( self . curve25519 ) :
   OOO0OOoOOO = lisp_hex_string ( self . remote_public_key )
   OOO0OOoOOO = OOO0OOoOOO . zfill ( 64 )
   ooo0o0oO = ""
   for oo0O0oO0O0O in range ( 0 , len ( OOO0OOoOOO ) , 2 ) :
    ooo0o0oO += chr ( int ( OOO0OOoOOO [ oo0O0oO0O0O : oo0O0oO0O0O + 2 ] , 16 ) )
    if 19 - 19: Oo0Ooo - OoO0O00 + i11iIiiIii / iIii1I11I1II1
   self . remote_public_key = ooo0o0oO
   if 1 - 1: IiII % i1IIi
   if 41 - 41: OoO0O00 * OoO0O00 / iII111i + I1ii11iIi11i . o0oOOo0O0Ooo
  packet = packet [ o0O0OoO0o0o0 : : ]
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
  III11i = "BBBBQ"
  Oo0o0OOo0Oo0 = struct . calcsize ( III11i )
  if ( len ( packet ) < Oo0o0OOo0Oo0 ) : return ( False )
  if 76 - 76: Ii1I + iII111i - IiII * iIii1I11I1II1 % i1IIi
  O0ooOo , Ii , ooooo , self . record_count , self . nonce = struct . unpack ( III11i , packet [ : Oo0o0OOo0Oo0 ] )
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
  iiI1 = ( "{} -> flags: {}{}{}{}{}{}{}{}{}, record-count: " +
 "{}, nonce: 0x{}, key/alg-id: {}/{}{}, auth-len: {}, xtr-id: " +
 "0x{}, site-id: {}" )
  if 14 - 14: I1Ii111 + Ii1I * Oo0Ooo
  lprint ( iiI1 . format ( bold ( "Map-Register" , False ) , "P" if self . proxy_reply_requested else "p" ,
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
  Ii1i111iI = ( LISP_MAP_REGISTER << 28 ) | self . record_count
  if ( self . proxy_reply_requested ) : Ii1i111iI |= 0x08000000
  if ( self . lisp_sec_present ) : Ii1i111iI |= 0x04000000
  if ( self . xtr_id_present ) : Ii1i111iI |= 0x02000000
  if ( self . map_register_refresh ) : Ii1i111iI |= 0x1000
  if ( self . use_ttl_for_timeout ) : Ii1i111iI |= 0x800
  if ( self . merge_register_requested ) : Ii1i111iI |= 0x400
  if ( self . mobile_node ) : Ii1i111iI |= 0x200
  if ( self . map_notify_requested ) : Ii1i111iI |= 0x100
  if ( self . encryption_key_id != None ) :
   Ii1i111iI |= 0x2000
   Ii1i111iI |= self . encryption_key_id << 14
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
  Ii11iIiiI = struct . pack ( "I" , socket . htonl ( Ii1i111iI ) )
  Ii11iIiiI += struct . pack ( "QBBH" , self . nonce , self . key_id , self . alg_id ,
 socket . htons ( self . auth_len ) )
  if 85 - 85: i11iIiiIii . OoO0O00 + OoO0O00
  Ii11iIiiI = self . zero_auth ( Ii11iIiiI )
  return ( Ii11iIiiI )
  if 28 - 28: Oo0Ooo
  if 62 - 62: Oo0Ooo + OoooooooOO / iII111i
 def zero_auth ( self , packet ) :
  I1 = struct . calcsize ( "I" ) + struct . calcsize ( "QHH" )
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
  packet = packet [ 0 : I1 ] + O0oO0 + packet [ I1 + O0ooo00o0 : : ]
  return ( packet )
  if 18 - 18: O0
  if 14 - 14: Ii1I / IiII - O0
 def encode_auth ( self , packet ) :
  I1 = struct . calcsize ( "I" ) + struct . calcsize ( "QHH" )
  O0ooo00o0 = self . auth_len
  O0oO0 = self . auth_data
  packet = packet [ 0 : I1 ] + O0oO0 + packet [ I1 + O0ooo00o0 : : ]
  return ( packet )
  if 16 - 16: I1Ii111 % iIii1I11I1II1 . i1IIi
  if 72 - 72: ooOoO0o * OOooOOo
 def decode ( self , packet ) :
  oOoo0O000 = packet
  III11i = "I"
  Oo0o0OOo0Oo0 = struct . calcsize ( III11i )
  if ( len ( packet ) < Oo0o0OOo0Oo0 ) : return ( [ None , None ] )
  if 47 - 47: I11i * Oo0Ooo - i1IIi . Ii1I
  Ii1i111iI = struct . unpack ( III11i , packet [ : Oo0o0OOo0Oo0 ] )
  Ii1i111iI = socket . ntohl ( Ii1i111iI [ 0 ] )
  packet = packet [ Oo0o0OOo0Oo0 : : ]
  if 7 - 7: Oo0Ooo
  III11i = "QBBH"
  Oo0o0OOo0Oo0 = struct . calcsize ( III11i )
  if ( len ( packet ) < Oo0o0OOo0Oo0 ) : return ( [ None , None ] )
  if 96 - 96: Ii1I * OOooOOo . i11iIiiIii - I1IiiI
  self . nonce , self . key_id , self . alg_id , self . auth_len = struct . unpack ( III11i , packet [ : Oo0o0OOo0Oo0 ] )
  if 94 - 94: o0oOOo0O0Ooo + Ii1I % o0oOOo0O0Ooo . I1Ii111 - ooOoO0o * I1IiiI
  if 62 - 62: Oo0Ooo * i1IIi % I1ii11iIi11i + Oo0Ooo . O0 . ooOoO0o
  self . auth_len = socket . ntohs ( self . auth_len )
  self . proxy_reply_requested = True if ( Ii1i111iI & 0x08000000 ) else False
  if 57 - 57: Oo0Ooo - I1Ii111 + O0 % o0oOOo0O0Ooo
  self . lisp_sec_present = True if ( Ii1i111iI & 0x04000000 ) else False
  self . xtr_id_present = True if ( Ii1i111iI & 0x02000000 ) else False
  self . use_ttl_for_timeout = True if ( Ii1i111iI & 0x800 ) else False
  self . map_register_refresh = True if ( Ii1i111iI & 0x1000 ) else False
  self . merge_register_requested = True if ( Ii1i111iI & 0x400 ) else False
  self . mobile_node = True if ( Ii1i111iI & 0x200 ) else False
  self . map_notify_requested = True if ( Ii1i111iI & 0x100 ) else False
  self . record_count = Ii1i111iI & 0xff
  if 72 - 72: OOooOOo . OoOoOO00 / II111iiii
  if 69 - 69: OOooOOo * II111iiii - ooOoO0o - i1IIi + i11iIiiIii
  if 50 - 50: OoooooooOO * i1IIi / oO0o
  if 83 - 83: i1IIi
  self . encrypt_bit = True if Ii1i111iI & 0x2000 else False
  if ( self . encrypt_bit ) :
   self . encryption_key_id = ( Ii1i111iI >> 14 ) & 0x7
   if 38 - 38: OoooooooOO * iIii1I11I1II1
   if 54 - 54: OoooooooOO . I1Ii111
   if 71 - 71: Ii1I
   if 31 - 31: I11i . i11iIiiIii . OoO0O00 * Oo0Ooo % Ii1I . o0oOOo0O0Ooo
   if 92 - 92: OoooooooOO / O0 * i1IIi + iIii1I11I1II1
  if ( self . xtr_id_present ) :
   if ( self . decode_xtr_id ( oOoo0O000 ) == False ) : return ( [ None , None ] )
   if 93 - 93: ooOoO0o % I1Ii111
   if 46 - 46: I1ii11iIi11i * OoOoOO00 * IiII * I1ii11iIi11i . I1ii11iIi11i
  packet = packet [ Oo0o0OOo0Oo0 : : ]
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
    Oo0o0OOo0Oo0 = struct . calcsize ( "QQI" )
    if ( O0ooo00o0 < Oo0o0OOo0Oo0 ) :
     lprint ( "Invalid sha1-96 authentication length" )
     return ( [ None , None ] )
     if 61 - 61: Oo0Ooo - I1Ii111
    O0o0oooOo0oo , OO0oOooo , ii1I = struct . unpack ( "QQI" , packet [ : O0ooo00o0 ] )
    iIIiiiIiiii11 = ""
   elif ( self . alg_id == LISP_SHA_256_128_ALG_ID ) :
    Oo0o0OOo0Oo0 = struct . calcsize ( "QQQQ" )
    if ( O0ooo00o0 < Oo0o0OOo0Oo0 ) :
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
  Oo0o0OOo0Oo0 = struct . calcsize ( "QQQ" )
  if ( len ( packet ) < Oo0o0OOo0Oo0 ) : return ( [ None , None ] )
  packet = packet [ len ( packet ) - Oo0o0OOo0Oo0 : : ]
  I1iIiI1iiI , oO000O00 , IiIIIii1iIII1 = struct . unpack ( "QQQ" ,
 packet [ : Oo0o0OOo0Oo0 ] )
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
  iiI1 = ( "{} -> record-count: {}, nonce: 0x{}, key/alg-id: " +
 "{}{}{}, auth-len: {}, auth-data: {}" )
  lprint ( iiI1 . format ( bold ( "Map-Notify-Ack" , False ) if self . map_notify_ack else bold ( "Map-Notify" , False ) ,
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
   Ii1i111iI = ( LISP_MAP_NOTIFY_ACK << 28 ) | self . record_count
  else :
   Ii1i111iI = ( LISP_MAP_NOTIFY << 28 ) | self . record_count
   if 32 - 32: Ii1I * I1IiiI - OOooOOo . Oo0Ooo / O0 + Ii1I
  Ii11iIiiI = struct . pack ( "I" , socket . htonl ( Ii1i111iI ) )
  Ii11iIiiI += struct . pack ( "QBBH" , self . nonce , self . key_id , self . alg_id ,
 socket . htons ( self . auth_len ) )
  if 67 - 67: OoOoOO00 % Oo0Ooo
  if ( self . alg_id == LISP_NONE_ALG_ID ) :
   self . packet = Ii11iIiiI + eid_records
   return ( self . packet )
   if 7 - 7: i11iIiiIii % I1ii11iIi11i / I1Ii111 % Oo0Ooo - OoO0O00
   if 73 - 73: I1ii11iIi11i
   if 92 - 92: i11iIiiIii + O0 * I11i
   if 60 - 60: o0oOOo0O0Ooo / Oo0Ooo
   if 19 - 19: iIii1I11I1II1 . OoO0O00 / OoooooooOO
  Ii11iIiiI = self . zero_auth ( Ii11iIiiI )
  Ii11iIiiI += eid_records
  if 2 - 2: O0 - O0 % I1Ii111 / I1ii11iIi11i
  II1IIIi = lisp_hash_me ( Ii11iIiiI , self . alg_id , password , False )
  if 76 - 76: OoO0O00 * oO0o - OoO0O00
  I1 = struct . calcsize ( "I" ) + struct . calcsize ( "QHH" )
  O0ooo00o0 = self . auth_len
  self . auth_data = II1IIIi
  Ii11iIiiI = Ii11iIiiI [ 0 : I1 ] + II1IIIi + Ii11iIiiI [ I1 + O0ooo00o0 : : ]
  self . packet = Ii11iIiiI
  return ( Ii11iIiiI )
  if 57 - 57: OoooooooOO / OoOoOO00 + oO0o . Ii1I
  if 14 - 14: i11iIiiIii % OOooOOo * o0oOOo0O0Ooo * OoOoOO00
 def decode ( self , packet ) :
  oOoo0O000 = packet
  III11i = "I"
  Oo0o0OOo0Oo0 = struct . calcsize ( III11i )
  if ( len ( packet ) < Oo0o0OOo0Oo0 ) : return ( None )
  if 55 - 55: I1Ii111 * OOooOOo * I1Ii111
  Ii1i111iI = struct . unpack ( III11i , packet [ : Oo0o0OOo0Oo0 ] )
  Ii1i111iI = socket . ntohl ( Ii1i111iI [ 0 ] )
  self . map_notify_ack = ( ( Ii1i111iI >> 28 ) == LISP_MAP_NOTIFY_ACK )
  self . record_count = Ii1i111iI & 0xff
  packet = packet [ Oo0o0OOo0Oo0 : : ]
  if 70 - 70: O0 . Ii1I
  III11i = "QBBH"
  Oo0o0OOo0Oo0 = struct . calcsize ( III11i )
  if ( len ( packet ) < Oo0o0OOo0Oo0 ) : return ( None )
  if 33 - 33: OOooOOo * Ii1I
  self . nonce , self . key_id , self . alg_id , self . auth_len = struct . unpack ( III11i , packet [ : Oo0o0OOo0Oo0 ] )
  if 64 - 64: i11iIiiIii . iIii1I11I1II1
  self . nonce_key = lisp_hex_string ( self . nonce )
  self . auth_len = socket . ntohs ( self . auth_len )
  packet = packet [ Oo0o0OOo0Oo0 : : ]
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
  Oo0o0OOo0Oo0 = struct . calcsize ( "I" ) + struct . calcsize ( "QHH" )
  packet = self . zero_auth ( oOoo0O000 [ : Oo0o0OOo0Oo0 ] )
  Oo0o0OOo0Oo0 += O0ooo00o0
  packet += oOoo0O000 [ Oo0o0OOo0Oo0 : : ]
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
  iiI1 = ( "{} -> flags: {}{}{}{}{}{}{}{}{}{}, itr-rloc-" +
 "count: {} (+1), record-count: {}, nonce: 0x{}, source-eid: " +
 "afi {}, {}{}, target-eid: afi {}, {}, {}ITR-RLOCs:" )
  if 87 - 87: IiII
  lprint ( iiI1 . format ( bold ( "Map-Request" , False ) , "A" if self . auth_bit else "a" ,
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
  i11i1ii11Ii1 = self . keys
  for oo0Oo0oo in self . itr_rlocs :
   lprint ( "  itr-rloc: afi {} {}{}" . format ( oo0Oo0oo . afi ,
 red ( oo0Oo0oo . print_address_no_iid ( ) , False ) ,
 "" if ( i11i1ii11Ii1 == None ) else ", " + i11i1ii11Ii1 [ 1 ] . print_keys ( ) ) )
   i11i1ii11Ii1 = None
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
   OOO0OOoOOO = ecdsa . VerifyingKey . from_pem ( pubkey )
  except :
   lprint ( "Invalid public-key in mapping system for sig-eid {}" . format ( self . signature_eid . print_address_no_iid ( ) ) )
   if 48 - 48: I1ii11iIi11i + O0 * oO0o + I1ii11iIi11i + I1ii11iIi11i
   ii1ii = False
   if 60 - 60: II111iiii % Oo0Ooo
   if 62 - 62: O0 + iII111i - iII111i % iIii1I11I1II1
  if ( ii1ii ) :
   try :
    ii1ii = OOO0OOoOOO . verify ( self . map_request_signature , o000o0O )
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
  Ii1i111iI = ( LISP_MAP_REQUEST << 28 ) | self . record_count
  Ii1i111iI = Ii1i111iI | ( self . itr_rloc_count << 8 )
  if ( self . auth_bit ) : Ii1i111iI |= 0x08000000
  if ( self . map_data_present ) : Ii1i111iI |= 0x04000000
  if ( self . rloc_probe ) : Ii1i111iI |= 0x02000000
  if ( self . smr_bit ) : Ii1i111iI |= 0x01000000
  if ( self . pitr_bit ) : Ii1i111iI |= 0x00800000
  if ( self . smr_invoked_bit ) : Ii1i111iI |= 0x00400000
  if ( self . mobile_node ) : Ii1i111iI |= 0x00200000
  if ( self . xtr_id_present ) : Ii1i111iI |= 0x00100000
  if ( self . local_xtr ) : Ii1i111iI |= 0x00004000
  if ( self . dont_reply_bit ) : Ii1i111iI |= 0x00002000
  if 67 - 67: OoOoOO00
  Ii11iIiiI = struct . pack ( "I" , socket . htonl ( Ii1i111iI ) )
  Ii11iIiiI += struct . pack ( "Q" , self . nonce )
  if 67 - 67: I1ii11iIi11i / iII111i + iIii1I11I1II1 % I1IiiI
  if 99 - 99: ooOoO0o . Ii1I
  if 92 - 92: i1IIi
  if 68 - 68: OoO0O00 % IiII - oO0o - ooOoO0o . Oo0Ooo
  if 30 - 30: OoooooooOO % o0oOOo0O0Ooo + ooOoO0o * OoO0O00
  if 57 - 57: I11i + iIii1I11I1II1 . OoO0O00 + oO0o
  iI1ii1i1iIi = False
  II11Iiii1i1II = self . privkey_filename
  if ( II11Iiii1i1II != None and os . path . exists ( II11Iiii1i1II ) ) :
   ii1iIii = open ( II11Iiii1i1II , "r" ) ; OOO0OOoOOO = ii1iIii . read ( ) ; ii1iIii . close ( )
   try :
    OOO0OOoOOO = ecdsa . SigningKey . from_pem ( OOO0OOoOOO )
   except :
    return ( None )
    if 64 - 64: i11iIiiIii + OoOoOO00 + o0oOOo0O0Ooo + OOooOOo
   Iii1iii11 = self . sign_map_request ( OOO0OOoOOO )
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
   Ii11iIiiI += struct . pack ( "HBBBBHH" , oO0OOOo0OO , 0 , 0 , o0oOoOOO , 0 ,
 i1IiI , I1iI1i )
   Ii11iIiiI += Iii1iii11
   Ii11iIiiI += struct . pack ( "H" , 0 )
  else :
   if ( self . source_eid . instance_id != 0 ) :
    Ii11iIiiI += struct . pack ( "H" , socket . htons ( LISP_AFI_LCAF ) )
    Ii11iIiiI += self . source_eid . lcaf_encode_iid ( )
   else :
    Ii11iIiiI += struct . pack ( "H" , socket . htons ( self . source_eid . afi ) )
    Ii11iIiiI += self . source_eid . pack_address ( )
    if 37 - 37: O0
    if 34 - 34: IiII
    if 5 - 5: OoO0O00 . I1IiiI
    if 48 - 48: Oo0Ooo - OoO0O00 . I11i - iIii1I11I1II1 % Ii1I
    if 47 - 47: iII111i / OoooooooOO - II111iiii
    if 91 - 91: OoOoOO00 + o0oOOo0O0Ooo
    if 23 - 23: i1IIi
  if ( probe_dest ) :
   if ( probe_port == 0 ) : probe_port = LISP_DATA_PORT
   i111I11I = probe_dest . print_address_no_iid ( ) + ":" + str ( probe_port )
   if 9 - 9: i1IIi % I1Ii111 - OoO0O00 * OoOoOO00 . o0oOOo0O0Ooo
   if ( lisp_crypto_keys_by_rloc_encap . has_key ( i111I11I ) ) :
    self . keys = lisp_crypto_keys_by_rloc_encap [ i111I11I ]
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
     i11i1ii11Ii1 = lisp_keys ( 1 )
     self . keys = [ None , i11i1ii11Ii1 , None , None ]
     if 17 - 17: OoO0O00 - I1Ii111 - II111iiii / I1Ii111 / Ii1I
    i11i1ii11Ii1 = self . keys [ 1 ]
    i11i1ii11Ii1 . add_key_by_nonce ( self . nonce )
    Ii11iIiiI += i11i1ii11Ii1 . encode_lcaf ( oo0Oo0oo )
   else :
    Ii11iIiiI += struct . pack ( "H" , socket . htons ( oo0Oo0oo . afi ) )
    Ii11iIiiI += oo0Oo0oo . pack_address ( )
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
  III11i = "BB"
  Ii11iIiiI += struct . pack ( III11i , i1II , ooI1111 )
  if 32 - 32: Ii1I % I11i + OOooOOo % OoooooooOO
  if ( self . target_group . is_null ( ) == False ) :
   Ii11iIiiI += struct . pack ( "H" , socket . htons ( LISP_AFI_LCAF ) )
   Ii11iIiiI += self . target_eid . lcaf_encode_sg ( self . target_group )
  elif ( self . target_eid . instance_id != 0 or
 self . target_eid . is_geo_prefix ( ) ) :
   Ii11iIiiI += struct . pack ( "H" , socket . htons ( LISP_AFI_LCAF ) )
   Ii11iIiiI += self . target_eid . lcaf_encode_iid ( )
  else :
   Ii11iIiiI += struct . pack ( "H" , socket . htons ( self . target_eid . afi ) )
   Ii11iIiiI += self . target_eid . pack_address ( )
   if 68 - 68: I11i
   if 13 - 13: i11iIiiIii - ooOoO0o
   if 54 - 54: I1IiiI * I1IiiI - I11i . O0 . iII111i - Ii1I
   if 86 - 86: I1IiiI . II111iiii * i1IIi % I1IiiI . OOooOOo
   if 79 - 79: OoO0O00 + O0 * OOooOOo
  if ( self . subscribe_bit ) : Ii11iIiiI = self . encode_xtr_id ( Ii11iIiiI )
  return ( Ii11iIiiI )
  if 51 - 51: i1IIi - oO0o / oO0o % o0oOOo0O0Ooo
  if 98 - 98: OoO0O00 * ooOoO0o + i1IIi + IiII - i1IIi % OoOoOO00
 def lcaf_decode_json ( self , packet ) :
  III11i = "BBBBHH"
  Oo0o0OOo0Oo0 = struct . calcsize ( III11i )
  if ( len ( packet ) < Oo0o0OOo0Oo0 ) : return ( None )
  if 19 - 19: iIii1I11I1II1 * Oo0Ooo / OOooOOo
  iiII1II1 , iiIIii1Iii1I , o0oOoOOO , OO00 , i1IiI , I1iI1i = struct . unpack ( III11i , packet [ : Oo0o0OOo0Oo0 ] )
  if 41 - 41: ooOoO0o * i11iIiiIii
  if 67 - 67: ooOoO0o . iIii1I11I1II1 . OoO0O00 + I1Ii111
  if ( o0oOoOOO != LISP_LCAF_JSON_TYPE ) : return ( packet )
  if 51 - 51: oO0o
  if 68 - 68: I1ii11iIi11i - Ii1I - I1Ii111
  if 58 - 58: OoOoOO00 . Ii1I / IiII * oO0o
  if 70 - 70: OoooooooOO
  i1IiI = socket . ntohs ( i1IiI )
  I1iI1i = socket . ntohs ( I1iI1i )
  packet = packet [ Oo0o0OOo0Oo0 : : ]
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
  III11i = "H"
  Oo0o0OOo0Oo0 = struct . calcsize ( III11i )
  ii1iI1i1 = struct . unpack ( III11i , packet [ : Oo0o0OOo0Oo0 ] ) [ 0 ]
  packet = packet [ Oo0o0OOo0Oo0 : : ]
  if ( ii1iI1i1 != 0 ) : return ( packet )
  if 70 - 70: II111iiii * OoooooooOO - Ii1I + oO0o * O0
  if 49 - 49: oO0o . Ii1I . OoOoOO00 - I1ii11iIi11i
  if 74 - 74: ooOoO0o % I1ii11iIi11i * i1IIi
  if 18 - 18: OoOoOO00
  if ( Iii1iii11 . has_key ( "source-eid" ) == False ) : return ( packet )
  ii1Ii = Iii1iii11 [ "source-eid" ]
  ii1iI1i1 = LISP_AFI_IPV4 if ii1Ii . count ( "." ) == 3 else LISP_AFI_IPV6 if ii1Ii . count ( ":" ) == 7 else None
  if 42 - 42: iII111i
  if ( ii1iI1i1 == None ) :
   lprint ( "Bad JSON 'source-eid' value: {}" . format ( ii1Ii ) )
   return ( None )
   if 6 - 6: OoO0O00 + OOooOOo
   if 22 - 22: Oo0Ooo . OoooooooOO % I1Ii111
  self . source_eid . afi = ii1iI1i1
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
  III11i = "I"
  Oo0o0OOo0Oo0 = struct . calcsize ( III11i )
  if ( len ( packet ) < Oo0o0OOo0Oo0 ) : return ( None )
  if 89 - 89: OoooooooOO + iII111i . I1Ii111 / Ii1I
  Ii1i111iI = struct . unpack ( III11i , packet [ : Oo0o0OOo0Oo0 ] )
  Ii1i111iI = Ii1i111iI [ 0 ]
  packet = packet [ Oo0o0OOo0Oo0 : : ]
  if 75 - 75: iIii1I11I1II1 * iII111i / OoOoOO00 * II111iiii . i1IIi
  III11i = "Q"
  Oo0o0OOo0Oo0 = struct . calcsize ( III11i )
  if ( len ( packet ) < Oo0o0OOo0Oo0 ) : return ( None )
  if 6 - 6: Ii1I % Ii1I / OoooooooOO * oO0o . I1IiiI . i1IIi
  i11IIoOOoOo0Ooo = struct . unpack ( III11i , packet [ : Oo0o0OOo0Oo0 ] )
  packet = packet [ Oo0o0OOo0Oo0 : : ]
  if 59 - 59: I11i . I11i * I1IiiI - Ii1I % OoOoOO00
  Ii1i111iI = socket . ntohl ( Ii1i111iI )
  self . auth_bit = True if ( Ii1i111iI & 0x08000000 ) else False
  self . map_data_present = True if ( Ii1i111iI & 0x04000000 ) else False
  self . rloc_probe = True if ( Ii1i111iI & 0x02000000 ) else False
  self . smr_bit = True if ( Ii1i111iI & 0x01000000 ) else False
  self . pitr_bit = True if ( Ii1i111iI & 0x00800000 ) else False
  self . smr_invoked_bit = True if ( Ii1i111iI & 0x00400000 ) else False
  self . mobile_node = True if ( Ii1i111iI & 0x00200000 ) else False
  self . xtr_id_present = True if ( Ii1i111iI & 0x00100000 ) else False
  self . local_xtr = True if ( Ii1i111iI & 0x00004000 ) else False
  self . dont_reply_bit = True if ( Ii1i111iI & 0x00002000 ) else False
  self . itr_rloc_count = ( ( Ii1i111iI >> 8 ) & 0x1f ) + 1
  self . record_count = Ii1i111iI & 0xff
  self . nonce = i11IIoOOoOo0Ooo [ 0 ]
  if 19 - 19: OoooooooOO / Oo0Ooo - I1Ii111 . OoOoOO00
  if 8 - 8: I11i % ooOoO0o . iIii1I11I1II1
  if 95 - 95: o0oOOo0O0Ooo + i11iIiiIii . I1ii11iIi11i . ooOoO0o . o0oOOo0O0Ooo
  if 93 - 93: iII111i
  if ( self . xtr_id_present ) :
   if ( self . decode_xtr_id ( packet ) == False ) : return ( None )
   if 55 - 55: II111iiii % o0oOOo0O0Ooo - OoO0O00
   if 48 - 48: ooOoO0o * iIii1I11I1II1 % OoOoOO00
  Oo0o0OOo0Oo0 = struct . calcsize ( "H" )
  if ( len ( packet ) < Oo0o0OOo0Oo0 ) : return ( None )
  if 100 - 100: II111iiii - i11iIiiIii + OoO0O00 % ooOoO0o - iIii1I11I1II1 * i11iIiiIii
  ii1iI1i1 = struct . unpack ( "H" , packet [ : Oo0o0OOo0Oo0 ] )
  self . source_eid . afi = socket . ntohs ( ii1iI1i1 [ 0 ] )
  packet = packet [ Oo0o0OOo0Oo0 : : ]
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
   Oo0o0OOo0Oo0 = struct . calcsize ( "H" )
   if ( len ( packet ) < Oo0o0OOo0Oo0 ) : return ( None )
   if 96 - 96: Ii1I + iII111i - OoOoOO00 . I11i * o0oOOo0O0Ooo - Ii1I
   ii1iI1i1 = struct . unpack ( "H" , packet [ : Oo0o0OOo0Oo0 ] ) [ 0 ]
   if 73 - 73: Oo0Ooo - I11i - ooOoO0o / I1Ii111 * IiII
   oo0Oo0oo = lisp_address ( LISP_AFI_NONE , "" , 32 , 0 )
   oo0Oo0oo . afi = socket . ntohs ( ii1iI1i1 )
   if 55 - 55: i1IIi / I1Ii111 . iII111i
   if 98 - 98: i1IIi % O0 . ooOoO0o * O0
   if 10 - 10: OOooOOo / Oo0Ooo - o0oOOo0O0Ooo / ooOoO0o % ooOoO0o / OoooooooOO
   if 26 - 26: Oo0Ooo . i1IIi / i11iIiiIii + I1Ii111 / II111iiii - I1ii11iIi11i
   if 71 - 71: iIii1I11I1II1 + O0 . IiII . iII111i % o0oOOo0O0Ooo % O0
   if ( oo0Oo0oo . afi != LISP_AFI_LCAF ) :
    if ( len ( packet ) < oo0Oo0oo . addr_length ( ) ) : return ( None )
    packet = oo0Oo0oo . unpack_address ( packet [ Oo0o0OOo0Oo0 : : ] )
    if ( packet == None ) : return ( None )
    if 51 - 51: o0oOOo0O0Ooo - Ii1I - iIii1I11I1II1 * iIii1I11I1II1 * o0oOOo0O0Ooo - O0
    if ( iI11ii1i ) :
     self . itr_rlocs . append ( oo0Oo0oo )
     self . itr_rloc_count -= 1
     continue
     if 27 - 27: i1IIi . I1Ii111
     if 64 - 64: ooOoO0o / i1IIi
    i111I11I = lisp_build_crypto_decap_lookup_key ( oo0Oo0oo , port )
    if 100 - 100: II111iiii
    if 16 - 16: Ii1I
    if 96 - 96: o0oOOo0O0Ooo / I1Ii111 % Ii1I - ooOoO0o
    if 35 - 35: OOooOOo
    if 90 - 90: i11iIiiIii
    if ( lisp_nat_traversal and oo0Oo0oo . is_private_address ( ) and source ) : oo0Oo0oo = source
    if 47 - 47: OoO0O00 . i11iIiiIii
    IIi11i1i = lisp_crypto_keys_by_rloc_decap
    if ( IIi11i1i . has_key ( i111I11I ) ) : IIi11i1i . pop ( i111I11I )
    if 74 - 74: Oo0Ooo + OOooOOo . o0oOOo0O0Ooo / OoOoOO00 + Ii1I + i1IIi
    if 82 - 82: Ii1I * I11i / I1IiiI * iIii1I11I1II1 / ooOoO0o + IiII
    if 30 - 30: oO0o . i11iIiiIii / I11i + i1IIi - I11i
    if 50 - 50: i1IIi
    if 56 - 56: OoO0O00 + I1Ii111 / Ii1I
    if 75 - 75: OoOoOO00
    lisp_write_ipc_decap_key ( i111I11I , None )
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
      OOO0OOoOOO = lisp_keys ( 1 , do_poly = False , do_chacha = False )
      if 11 - 11: OoooooooOO + o0oOOo0O0Ooo - i11iIiiIii + i1IIi % i1IIi
     if ( oO00OO0Ooo00O . cipher_suite == LISP_CS_25519_CHACHA ) :
      OOO0OOoOOO = lisp_keys ( 1 , do_poly = True , do_chacha = True )
      if 68 - 68: IiII - I11i % II111iiii - o0oOOo0O0Ooo % ooOoO0o
    else :
     OOO0OOoOOO = lisp_keys ( 1 , do_poly = False , do_curve = False ,
 do_chacha = False )
     if 41 - 41: iII111i . ooOoO0o % OoooooooOO / I1IiiI * II111iiii - iII111i
    packet = OOO0OOoOOO . decode_lcaf ( oOoo0O000 , 0 )
    if ( packet == None ) : return ( None )
    if 19 - 19: OoO0O00 . I11i / i11iIiiIii - OoOoOO00 * I11i . IiII
    if ( len ( packet ) < Oo0o0OOo0Oo0 ) : return ( None )
    ii1iI1i1 = struct . unpack ( "H" , packet [ : Oo0o0OOo0Oo0 ] ) [ 0 ]
    oo0Oo0oo . afi = socket . ntohs ( ii1iI1i1 )
    if ( len ( packet ) < oo0Oo0oo . addr_length ( ) ) : return ( None )
    if 39 - 39: O0 / iIii1I11I1II1 % iII111i + I1Ii111 - O0 . II111iiii
    packet = oo0Oo0oo . unpack_address ( packet [ Oo0o0OOo0Oo0 : : ] )
    if ( packet == None ) : return ( None )
    if 94 - 94: OoOoOO00 * iIii1I11I1II1
    if ( iI11ii1i ) :
     self . itr_rlocs . append ( oo0Oo0oo )
     self . itr_rloc_count -= 1
     continue
     if 11 - 11: I1ii11iIi11i % OOooOOo + Ii1I + oO0o . Oo0Ooo
     if 93 - 93: OOooOOo * Ii1I - o0oOOo0O0Ooo . oO0o . iII111i
    i111I11I = lisp_build_crypto_decap_lookup_key ( oo0Oo0oo , port )
    if 64 - 64: Oo0Ooo / iIii1I11I1II1 . OoO0O00 / o0oOOo0O0Ooo / I11i
    I11IiiI1 = None
    if ( lisp_nat_traversal and oo0Oo0oo . is_private_address ( ) and source ) : oo0Oo0oo = source
    if 72 - 72: iIii1I11I1II1 * OOooOOo . iIii1I11I1II1
    if 62 - 62: IiII . IiII % ooOoO0o - OoOoOO00 / OoooooooOO . I1IiiI
    if ( lisp_crypto_keys_by_rloc_decap . has_key ( i111I11I ) ) :
     i11i1ii11Ii1 = lisp_crypto_keys_by_rloc_decap [ i111I11I ]
     I11IiiI1 = i11i1ii11Ii1 [ 1 ] if i11i1ii11Ii1 and i11i1ii11Ii1 [ 1 ] else None
     if 23 - 23: IiII + i11iIiiIii * Ii1I
     if 55 - 55: Oo0Ooo % IiII + i11iIiiIii - OOooOOo - II111iiii
    o0o0Oo0O0O0o = True
    if ( I11IiiI1 ) :
     if ( I11IiiI1 . compare_keys ( OOO0OOoOOO ) ) :
      self . keys = [ None , I11IiiI1 , None , None ]
      lprint ( "Maintain stored decap-keys for RLOC {}" . format ( red ( i111I11I , False ) ) )
      if 67 - 67: iII111i
     else :
      o0o0Oo0O0O0o = False
      o0o00O0 = bold ( "Remote decap-rekeying" , False )
      lprint ( "{} for RLOC {}" . format ( o0o00O0 , red ( i111I11I ,
 False ) ) )
      OOO0OOoOOO . copy_keypair ( I11IiiI1 )
      OOO0OOoOOO . uptime = I11IiiI1 . uptime
      I11IiiI1 = None
      if 88 - 88: I1IiiI
      if 74 - 74: iII111i * i11iIiiIii + i1IIi * ooOoO0o + oO0o * Ii1I
      if 90 - 90: iII111i
    if ( I11IiiI1 == None ) :
     self . keys = [ None , OOO0OOoOOO , None , None ]
     if ( lisp_i_am_etr == False and lisp_i_am_rtr == False ) :
      OOO0OOoOOO . local_public_key = None
      lprint ( "{} for {}" . format ( bold ( "Ignoring decap-keys" ,
 False ) , red ( i111I11I , False ) ) )
     elif ( OOO0OOoOOO . remote_public_key != None ) :
      if ( o0o0Oo0O0O0o ) :
       lprint ( "{} for RLOC {}" . format ( bold ( "New decap-keying" , False ) ,
       # oO0o % I1ii11iIi11i * IiII / i1IIi - i11iIiiIii
 red ( i111I11I , False ) ) )
       if 92 - 92: iII111i - I1IiiI % iIii1I11I1II1 / O0 + OoOoOO00
      OOO0OOoOOO . compute_shared_key ( "decap" )
      OOO0OOoOOO . add_key_by_rloc ( i111I11I , False )
      if 37 - 37: Oo0Ooo - I11i / OOooOOo / IiII * i1IIi
      if 55 - 55: I1IiiI
      if 83 - 83: OoOoOO00 / ooOoO0o / iII111i + OoO0O00 - I1IiiI * i1IIi
      if 34 - 34: iIii1I11I1II1 * O0 - OoOoOO00 + iIii1I11I1II1 % I1ii11iIi11i
   self . itr_rlocs . append ( oo0Oo0oo )
   self . itr_rloc_count -= 1
   if 77 - 77: Oo0Ooo . IiII . oO0o
   if 77 - 77: i1IIi + OoooooooOO + OoO0O00 % ooOoO0o % Ii1I
  Oo0o0OOo0Oo0 = struct . calcsize ( "BBH" )
  if ( len ( packet ) < Oo0o0OOo0Oo0 ) : return ( None )
  if 43 - 43: Oo0Ooo . i11iIiiIii + i1IIi
  i1II , ooI1111 , ii1iI1i1 = struct . unpack ( "BBH" , packet [ : Oo0o0OOo0Oo0 ] )
  self . subscribe_bit = ( i1II & 0x80 )
  self . target_eid . afi = socket . ntohs ( ii1iI1i1 )
  packet = packet [ Oo0o0OOo0Oo0 : : ]
  if 83 - 83: iII111i + OoOoOO00 % ooOoO0o
  self . target_eid . mask_len = ooI1111
  if ( self . target_eid . afi == LISP_AFI_LCAF ) :
   packet , ooOooooO00 = self . target_eid . lcaf_decode_eid ( packet )
   if ( packet == None ) : return ( None )
   if ( ooOooooO00 ) : self . target_group = ooOooooO00
  else :
   packet = self . target_eid . unpack_address ( packet )
   if ( packet == None ) : return ( None )
   packet = packet [ Oo0o0OOo0Oo0 : : ]
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
  Oo0o0OOo0Oo0 = struct . calcsize ( "QQ" )
  if ( len ( packet ) < Oo0o0OOo0Oo0 ) : return ( None )
  packet = packet [ len ( packet ) - Oo0o0OOo0Oo0 : : ]
  I1iIiI1iiI , oO000O00 = struct . unpack ( "QQ" , packet [ : Oo0o0OOo0Oo0 ] )
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
  iiI1 = "{} -> flags: {}{}{}, hop-count: {}, record-count: {}, " + "nonce: 0x{}"
  if 11 - 11: o0oOOo0O0Ooo * OoO0O00
  lprint ( iiI1 . format ( bold ( "Map-Reply" , False ) , "R" if self . rloc_probe else "r" ,
  # iIii1I11I1II1 + ooOoO0o + I11i + OoooooooOO * o0oOOo0O0Ooo . I11i
 "E" if self . echo_nonce_capable else "e" ,
 "S" if self . security else "s" , self . hop_count , self . record_count ,
 lisp_hex_string ( self . nonce ) ) )
  if 26 - 26: I1Ii111 / I1ii11iIi11i % ooOoO0o % o0oOOo0O0Ooo / OoOoOO00
  if 44 - 44: OoooooooOO % i1IIi / I1ii11iIi11i / I1ii11iIi11i
 def encode ( self ) :
  Ii1i111iI = ( LISP_MAP_REPLY << 28 ) | self . record_count
  Ii1i111iI |= self . hop_count << 8
  if ( self . rloc_probe ) : Ii1i111iI |= 0x08000000
  if ( self . echo_nonce_capable ) : Ii1i111iI |= 0x04000000
  if ( self . security ) : Ii1i111iI |= 0x02000000
  if 36 - 36: O0 - I11i + OOooOOo
  Ii11iIiiI = struct . pack ( "I" , socket . htonl ( Ii1i111iI ) )
  Ii11iIiiI += struct . pack ( "Q" , self . nonce )
  return ( Ii11iIiiI )
  if 97 - 97: I1IiiI * o0oOOo0O0Ooo
  if 79 - 79: iII111i - ooOoO0o - OoO0O00 / iIii1I11I1II1 % Ii1I
 def decode ( self , packet ) :
  III11i = "I"
  Oo0o0OOo0Oo0 = struct . calcsize ( III11i )
  if ( len ( packet ) < Oo0o0OOo0Oo0 ) : return ( None )
  if 2 - 2: iIii1I11I1II1 + OoooooooOO - i1IIi / Ii1I
  Ii1i111iI = struct . unpack ( III11i , packet [ : Oo0o0OOo0Oo0 ] )
  Ii1i111iI = Ii1i111iI [ 0 ]
  packet = packet [ Oo0o0OOo0Oo0 : : ]
  if 88 - 88: I1ii11iIi11i . OoooooooOO / Oo0Ooo / o0oOOo0O0Ooo % Oo0Ooo
  III11i = "Q"
  Oo0o0OOo0Oo0 = struct . calcsize ( III11i )
  if ( len ( packet ) < Oo0o0OOo0Oo0 ) : return ( None )
  if 80 - 80: Ii1I + OoO0O00 * OoooooooOO - IiII % O0 - I1Ii111
  i11IIoOOoOo0Ooo = struct . unpack ( III11i , packet [ : Oo0o0OOo0Oo0 ] )
  packet = packet [ Oo0o0OOo0Oo0 : : ]
  if 80 - 80: II111iiii / I1ii11iIi11i
  Ii1i111iI = socket . ntohl ( Ii1i111iI )
  self . rloc_probe = True if ( Ii1i111iI & 0x08000000 ) else False
  self . echo_nonce_capable = True if ( Ii1i111iI & 0x04000000 ) else False
  self . security = True if ( Ii1i111iI & 0x02000000 ) else False
  self . hop_count = ( Ii1i111iI >> 8 ) & 0xff
  self . record_count = Ii1i111iI & 0xff
  self . nonce = i11IIoOOoOo0Ooo [ 0 ]
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
  ii1iI1i1 = LISP_AFI_LCAF if ( self . eid . afi < 0 ) else self . eid . afi
  iiI1 = ( "{}EID-record -> record-ttl: {}, rloc-count: {}, action: " +
 "{}, {}{}{}, map-version: {}, afi: {}, [iid]eid/ml: {}" )
  if 54 - 54: I1Ii111 + ooOoO0o % IiII
  lprint ( iiI1 . format ( indent , self . print_ttl ( ) , self . rloc_count ,
 OOOo , "auth" if ( self . authoritative is True ) else "non-auth" ,
 Ooooo0OO000o0 , oOOIIiiIIIiI , self . map_version , ii1iI1i1 ,
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
  ii1iI1i1 = self . eid . afi if ( self . eid . instance_id == 0 ) else LISP_AFI_LCAF
  if ( ii1iI1i1 < 0 ) : ii1iI1i1 = LISP_AFI_LCAF
  iIiiIi1111ii = ( self . group . is_null ( ) == False )
  if ( iIiiIi1111ii ) : ii1iI1i1 = LISP_AFI_LCAF
  if 53 - 53: O0 % ooOoO0o
  iii111iI1i11 = ( self . signature_count << 12 ) | self . map_version
  ooI1111 = 0 if self . eid . is_binary ( ) == False else self . eid . mask_len
  if 67 - 67: I11i * i1IIi - i1IIi . OoOoOO00 % oO0o . o0oOOo0O0Ooo
  Ii11iIiiI = struct . pack ( "IBBHHH" , socket . htonl ( self . record_ttl ) ,
 self . rloc_count , ooI1111 , socket . htons ( i11IIiI ) ,
 socket . htons ( iii111iI1i11 ) , socket . htons ( ii1iI1i1 ) )
  if 14 - 14: oO0o - Oo0Ooo % Ii1I . I1Ii111
  if 14 - 14: ooOoO0o / O0 - I1IiiI / I1ii11iIi11i / OoO0O00 + oO0o
  if 81 - 81: I1Ii111 / I1Ii111 + ooOoO0o - Ii1I
  if 93 - 93: ooOoO0o . o0oOOo0O0Ooo + O0 * i1IIi - OoO0O00 * OoO0O00
  if ( iIiiIi1111ii ) :
   Ii11iIiiI += self . eid . lcaf_encode_sg ( self . group )
   return ( Ii11iIiiI )
   if 11 - 11: ooOoO0o - Ii1I . oO0o * Ii1I
   if 85 - 85: i1IIi
   if 94 - 94: OoooooooOO . O0 / OoooooooOO
   if 67 - 67: i11iIiiIii + OoOoOO00
   if 50 - 50: ooOoO0o . i1IIi + I1ii11iIi11i . OOooOOo
  if ( self . eid . afi == LISP_AFI_GEO_COORD and self . eid . instance_id == 0 ) :
   Ii11iIiiI = Ii11iIiiI [ 0 : - 2 ]
   Ii11iIiiI += self . eid . address . encode_geo ( )
   return ( Ii11iIiiI )
   if 97 - 97: I1IiiI
   if 63 - 63: O0 - OoOoOO00 / i11iIiiIii / OoooooooOO / ooOoO0o / II111iiii
   if 45 - 45: II111iiii . OoO0O00 + OoO0O00 * iIii1I11I1II1
   if 23 - 23: IiII * OoOoOO00 % Ii1I / Ii1I - ooOoO0o - OOooOOo
   if 86 - 86: OOooOOo . OoooooooOO * I1IiiI - Oo0Ooo / i11iIiiIii * iII111i
  if ( ii1iI1i1 == LISP_AFI_LCAF ) :
   Ii11iIiiI += self . eid . lcaf_encode_iid ( )
   return ( Ii11iIiiI )
   if 56 - 56: I1IiiI . I11i % iII111i
   if 33 - 33: I11i / OOooOOo - OOooOOo / i11iIiiIii * OoOoOO00 + O0
   if 2 - 2: i11iIiiIii % I1IiiI
   if 90 - 90: II111iiii
   if 2 - 2: Ii1I - OoooooooOO - i11iIiiIii % Oo0Ooo / Ii1I
  Ii11iIiiI += self . eid . pack_address ( )
  return ( Ii11iIiiI )
  if 77 - 77: o0oOOo0O0Ooo . o0oOOo0O0Ooo * I1Ii111 + OOooOOo - i11iIiiIii
  if 45 - 45: I1IiiI . I1IiiI - Oo0Ooo * OOooOOo
 def decode ( self , packet ) :
  III11i = "IBBHHH"
  Oo0o0OOo0Oo0 = struct . calcsize ( III11i )
  if ( len ( packet ) < Oo0o0OOo0Oo0 ) : return ( None )
  if 71 - 71: i1IIi / I11i
  self . record_ttl , self . rloc_count , self . eid . mask_len , i11IIiI , self . map_version , self . eid . afi = struct . unpack ( III11i , packet [ : Oo0o0OOo0Oo0 ] )
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
  packet = packet [ Oo0o0OOo0Oo0 : : ]
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
  iiI1 = ( "{} -> flags: {}{}{}{}, " + "inner IP: {} -> {}, inner UDP: {} -> {}" )
  if 92 - 92: i1IIi + OoO0O00 * I11i
  lprint ( iiI1 . format ( bold ( "ECM" , False ) , "S" if self . security else "s" ,
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
  Ii1i111iI = ( LISP_ECM << 28 )
  if ( self . security ) : Ii1i111iI |= 0x08000000
  if ( self . ddt ) : Ii1i111iI |= 0x04000000
  if ( self . to_etr ) : Ii1i111iI |= 0x02000000
  if ( self . to_ms ) : Ii1i111iI |= 0x01000000
  if 75 - 75: iII111i % O0 - I11i - I1ii11iIi11i + I1IiiI - I1IiiI
  Oo00OoooO0o = struct . pack ( "I" , socket . htonl ( Ii1i111iI ) )
  if 11 - 11: I1Ii111 - OOooOOo - I1Ii111 - II111iiii / I1Ii111
  i1i11ii1Ii = ""
  if ( self . afi == LISP_AFI_IPV4 ) :
   i1i11ii1Ii = struct . pack ( "BBHHHBBH" , 0x45 , 0 , socket . htons ( self . length ) ,
 0 , 0 , self . ttl , self . protocol , socket . htons ( self . ip_checksum ) )
   i1i11ii1Ii += self . source . pack_address ( )
   i1i11ii1Ii += self . dest . pack_address ( )
   i1i11ii1Ii = lisp_ip_checksum ( i1i11ii1Ii )
   if 23 - 23: OOooOOo
  if ( self . afi == LISP_AFI_IPV6 ) :
   i1i11ii1Ii = struct . pack ( "BBHHBB" , 0x60 , 0 , 0 , socket . htons ( self . length ) ,
 self . protocol , self . ttl )
   i1i11ii1Ii += self . source . pack_address ( )
   i1i11ii1Ii += self . dest . pack_address ( )
   if 19 - 19: ooOoO0o % iIii1I11I1II1 * OoooooooOO
   if 60 - 60: I1Ii111 * iII111i / OoooooooOO * Oo0Ooo
  oOOOOOOOoO = socket . htons ( self . udp_sport )
  OooOo = socket . htons ( self . udp_dport )
  oooo0 = socket . htons ( self . udp_length )
  iII = socket . htons ( self . udp_checksum )
  IiI1iiI11 = struct . pack ( "HHHH" , oOOOOOOOoO , OooOo , oooo0 , iII )
  return ( Oo00OoooO0o + i1i11ii1Ii + IiI1iiI11 )
  if 47 - 47: iII111i + o0oOOo0O0Ooo % iIii1I11I1II1 * OoOoOO00
  if 65 - 65: OOooOOo . II111iiii * i11iIiiIii + OOooOOo
 def decode ( self , packet ) :
  if 99 - 99: I1ii11iIi11i % Oo0Ooo
  if 31 - 31: o0oOOo0O0Ooo - II111iiii * OOooOOo . OOooOOo - oO0o
  if 57 - 57: OOooOOo / i11iIiiIii / I1Ii111 - Oo0Ooo . iIii1I11I1II1
  if 84 - 84: IiII
  III11i = "I"
  Oo0o0OOo0Oo0 = struct . calcsize ( III11i )
  if ( len ( packet ) < Oo0o0OOo0Oo0 ) : return ( None )
  if 42 - 42: O0 . I1Ii111 / I11i
  Ii1i111iI = struct . unpack ( III11i , packet [ : Oo0o0OOo0Oo0 ] )
  if 69 - 69: OoOoOO00 / I1Ii111 * I1IiiI
  Ii1i111iI = socket . ntohl ( Ii1i111iI [ 0 ] )
  self . security = True if ( Ii1i111iI & 0x08000000 ) else False
  self . ddt = True if ( Ii1i111iI & 0x04000000 ) else False
  self . to_etr = True if ( Ii1i111iI & 0x02000000 ) else False
  self . to_ms = True if ( Ii1i111iI & 0x01000000 ) else False
  packet = packet [ Oo0o0OOo0Oo0 : : ]
  if 76 - 76: O0 + II111iiii * OoO0O00
  if 1 - 1: o0oOOo0O0Ooo
  if 34 - 34: o0oOOo0O0Ooo + OOooOOo . OoO0O00 + I1IiiI + OoooooooOO
  if 90 - 90: Ii1I / OoOoOO00 - iIii1I11I1II1 / i1IIi * I1Ii111 - ooOoO0o
  if ( len ( packet ) < 1 ) : return ( None )
  OoOOoO0o = struct . unpack ( "B" , packet [ 0 : 1 ] ) [ 0 ]
  OoOOoO0o = OoOOoO0o >> 4
  if 2 - 2: iII111i * I11i * ooOoO0o + i11iIiiIii + oO0o
  if ( OoOOoO0o == 4 ) :
   Oo0o0OOo0Oo0 = struct . calcsize ( "HHIBBH" )
   if ( len ( packet ) < Oo0o0OOo0Oo0 ) : return ( None )
   if 81 - 81: o0oOOo0O0Ooo * OoO0O00
   IiIIi , oooo0 , IiIIi , Oo0o0O0OO0 , IiIiI1 , iII = struct . unpack ( "HHIBBH" , packet [ : Oo0o0OOo0Oo0 ] )
   self . length = socket . ntohs ( oooo0 )
   self . ttl = Oo0o0O0OO0
   self . protocol = IiIiI1
   self . ip_checksum = socket . ntohs ( iII )
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
   packet = packet [ Oo0o0OOo0Oo0 : : ]
   packet = self . source . unpack_address ( packet )
   if ( packet == None ) : return ( None )
   packet = self . dest . unpack_address ( packet )
   if ( packet == None ) : return ( None )
   if 43 - 43: o0oOOo0O0Ooo * OoooooooOO
   if 1 - 1: iII111i % oO0o / OOooOOo * iII111i
  if ( OoOOoO0o == 6 ) :
   Oo0o0OOo0Oo0 = struct . calcsize ( "IHBB" )
   if ( len ( packet ) < Oo0o0OOo0Oo0 ) : return ( None )
   if 28 - 28: oO0o . ooOoO0o / I11i + Oo0Ooo
   IiIIi , oooo0 , IiIiI1 , Oo0o0O0OO0 = struct . unpack ( "IHBB" , packet [ : Oo0o0OOo0Oo0 ] )
   self . length = socket . ntohs ( oooo0 )
   self . protocol = IiIiI1
   self . ttl = Oo0o0O0OO0
   self . source . afi = self . dest . afi = LISP_AFI_IPV6
   if 55 - 55: OoooooooOO % OoOoOO00 + i1IIi * OoO0O00 * OOooOOo
   packet = packet [ Oo0o0OOo0Oo0 : : ]
   packet = self . source . unpack_address ( packet )
   if ( packet == None ) : return ( None )
   packet = self . dest . unpack_address ( packet )
   if ( packet == None ) : return ( None )
   if 39 - 39: OOooOOo - oO0o
   if 69 - 69: o0oOOo0O0Ooo * Ii1I * OoOoOO00
  self . source . mask_len = self . source . host_mask_len ( )
  self . dest . mask_len = self . dest . host_mask_len ( )
  if 51 - 51: Oo0Ooo . Oo0Ooo
  Oo0o0OOo0Oo0 = struct . calcsize ( "HHHH" )
  if ( len ( packet ) < Oo0o0OOo0Oo0 ) : return ( None )
  if 34 - 34: I1ii11iIi11i - i11iIiiIii
  oOOOOOOOoO , OooOo , oooo0 , iII = struct . unpack ( "HHHH" , packet [ : Oo0o0OOo0Oo0 ] )
  self . udp_sport = socket . ntohs ( oOOOOOOOoO )
  self . udp_dport = socket . ntohs ( OooOo )
  self . udp_length = socket . ntohs ( oooo0 )
  self . udp_checksum = socket . ntohs ( iII )
  packet = packet [ Oo0o0OOo0Oo0 : : ]
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
  I111I1iii11 = self . print_rloc_name ( )
  if ( I111I1iii11 != "" ) : I111I1iii11 = ", " + I111I1iii11
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
  II = ""
  if ( self . rloc . is_null ( ) == False and self . keys and self . keys [ 1 ] ) :
   II = ", " + self . keys [ 1 ] . print_keys ( )
   if 56 - 56: i1IIi
   if 3 - 3: Oo0Ooo + oO0o
  iiI1 = ( "{}RLOC-record -> flags: {}, {}/{}/{}/{}, afi: {}, rloc: "
 + "{}{}{}{}{}{}{}" )
  lprint ( iiI1 . format ( indent , self . print_flags ( ) , self . priority ,
 self . weight , self . mpriority , self . mweight , self . rloc . afi ,
 red ( self . rloc . print_address_no_iid ( ) , False ) , I111I1iii11 , O000 ,
 OooO0o00oO , OoI1i1IIii , I111Ii1I , II ) )
  if 65 - 65: I1IiiI / OoOoOO00 % I1IiiI * i11iIiiIii * OoooooooOO / I11i
  if 91 - 91: i11iIiiIii / i11iIiiIii
 def print_flags ( self ) :
  return ( "{}{}{}" . format ( "L" if self . local_bit else "l" , "P" if self . probe_bit else "p" , "R" if self . reach_bit else "r" ) )
  if 9 - 9: I11i / I1Ii111 + iIii1I11I1II1 + I1IiiI - II111iiii
  if 96 - 96: iII111i + Oo0Ooo - OoooooooOO . i1IIi + i1IIi % iIii1I11I1II1
  if 80 - 80: OoooooooOO / O0 / I1Ii111 - Oo0Ooo . i11iIiiIii
 def store_rloc_entry ( self , rloc_entry ) :
  II11IIiii = rloc_entry . rloc if ( rloc_entry . translated_rloc . is_null ( ) ) else rloc_entry . translated_rloc
  if 14 - 14: I1IiiI
  self . rloc . copy_address ( II11IIiii )
  if 41 - 41: I1Ii111 % i1IIi + OoO0O00 / oO0o
  if ( rloc_entry . rloc_name ) :
   self . rloc_name = rloc_entry . rloc_name
   if 48 - 48: i1IIi . Oo0Ooo . i1IIi . I1ii11iIi11i * I1IiiI - Ii1I
   if 83 - 83: OoooooooOO
  if ( rloc_entry . geo ) :
   self . geo = rloc_entry . geo
  else :
   I1i1iI1II = rloc_entry . geo_name
   if ( I1i1iI1II and lisp_geo_list . has_key ( I1i1iI1II ) ) :
    self . geo = lisp_geo_list [ I1i1iI1II ]
    if 42 - 42: I1ii11iIi11i . i1IIi - OoOoOO00 - oO0o + i11iIiiIii
    if 65 - 65: I1IiiI - O0
  if ( rloc_entry . elp ) :
   self . elp = rloc_entry . elp
  else :
   I1i1iI1II = rloc_entry . elp_name
   if ( I1i1iI1II and lisp_elp_list . has_key ( I1i1iI1II ) ) :
    self . elp = lisp_elp_list [ I1i1iI1II ]
    if 15 - 15: I11i + OoOoOO00 / Oo0Ooo - I1IiiI * I1ii11iIi11i % oO0o
    if 90 - 90: Ii1I / I11i
  if ( rloc_entry . rle ) :
   self . rle = rloc_entry . rle
  else :
   I1i1iI1II = rloc_entry . rle_name
   if ( I1i1iI1II and lisp_rle_list . has_key ( I1i1iI1II ) ) :
    self . rle = lisp_rle_list [ I1i1iI1II ]
    if 98 - 98: i1IIi
    if 97 - 97: I1Ii111 + O0 - II111iiii / I11i
  if ( rloc_entry . json ) :
   self . json = rloc_entry . json
  else :
   I1i1iI1II = rloc_entry . json_name
   if ( I1i1iI1II and lisp_json_list . has_key ( I1i1iI1II ) ) :
    self . json = lisp_json_list [ I1i1iI1II ]
    if 84 - 84: iIii1I11I1II1 % Ii1I / OoooooooOO
    if 62 - 62: OOooOOo * OoO0O00 * OoO0O00 + OoooooooOO . IiII + OoO0O00
  self . priority = rloc_entry . priority
  self . weight = rloc_entry . weight
  self . mpriority = rloc_entry . mpriority
  self . mweight = rloc_entry . mweight
  if 13 - 13: O0 . I1IiiI % OoO0O00 - I11i . O0
  if 14 - 14: iIii1I11I1II1
 def encode_lcaf ( self ) :
  oO0OOOo0OO = socket . htons ( LISP_AFI_LCAF )
  IiIIIIiiIIIii = ""
  if ( self . geo ) :
   IiIIIIiiIIIii = self . geo . encode_geo ( )
   if 82 - 82: o0oOOo0O0Ooo / I1Ii111 + II111iiii . OoooooooOO
   if 32 - 32: i11iIiiIii
  o0OO0o = ""
  if ( self . elp ) :
   IiIIooO00oOo0 = ""
   for IIiIiii111iI in self . elp . elp_nodes :
    ii1iI1i1 = socket . htons ( IIiIiii111iI . address . afi )
    iiIIii1Iii1I = 0
    if ( IIiIiii111iI . eid ) : iiIIii1Iii1I |= 0x4
    if ( IIiIiii111iI . probe ) : iiIIii1Iii1I |= 0x2
    if ( IIiIiii111iI . strict ) : iiIIii1Iii1I |= 0x1
    iiIIii1Iii1I = socket . htons ( iiIIii1Iii1I )
    IiIIooO00oOo0 += struct . pack ( "HH" , iiIIii1Iii1I , ii1iI1i1 )
    IiIIooO00oOo0 += IIiIiii111iI . address . pack_address ( )
    if 30 - 30: IiII * Oo0Ooo * iII111i
    if 49 - 49: I1IiiI / I1Ii111 * iII111i + I1IiiI % oO0o % ooOoO0o
   iIi1I = socket . htons ( len ( IiIIooO00oOo0 ) )
   o0OO0o = struct . pack ( "HBBBBH" , oO0OOOo0OO , 0 , 0 , LISP_LCAF_ELP_TYPE ,
 0 , iIi1I )
   o0OO0o += IiIIooO00oOo0
   if 71 - 71: OoO0O00 . i11iIiiIii . iIii1I11I1II1 + I1IiiI - o0oOOo0O0Ooo
   if 34 - 34: iII111i
  iIIIiiI = ""
  if ( self . rle ) :
   o0oOo0O0o0oO = ""
   for O00o000O0O0oO in self . rle . rle_nodes :
    ii1iI1i1 = socket . htons ( O00o000O0O0oO . address . afi )
    o0oOo0O0o0oO += struct . pack ( "HBBH" , 0 , 0 , O00o000O0O0oO . level , ii1iI1i1 )
    o0oOo0O0o0oO += O00o000O0O0oO . address . pack_address ( )
    if ( O00o000O0O0oO . rloc_name ) :
     o0oOo0O0o0oO += struct . pack ( "H" , socket . htons ( LISP_AFI_NAME ) )
     o0oOo0O0o0oO += O00o000O0O0oO . rloc_name + "\0"
     if 46 - 46: o0oOOo0O0Ooo - O0
     if 46 - 46: ooOoO0o * i1IIi . I11i + O0 . I1ii11iIi11i
     if 71 - 71: Oo0Ooo % OoO0O00
   oO00 = socket . htons ( len ( o0oOo0O0o0oO ) )
   iIIIiiI = struct . pack ( "HBBBBH" , oO0OOOo0OO , 0 , 0 , LISP_LCAF_RLE_TYPE ,
 0 , oO00 )
   iIIIiiI += o0oOo0O0o0oO
   if 79 - 79: i11iIiiIii + iIii1I11I1II1 . OoooooooOO % iII111i % IiII
   if 73 - 73: II111iiii - II111iiii + o0oOOo0O0Ooo * i1IIi
  oOo0o0O = ""
  if ( self . json ) :
   i1IiI = socket . htons ( len ( self . json . json_string ) + 2 )
   I1iI1i = socket . htons ( len ( self . json . json_string ) )
   oOo0o0O = struct . pack ( "HBBBBHH" , oO0OOOo0OO , 0 , 0 , LISP_LCAF_JSON_TYPE ,
 0 , i1IiI , I1iI1i )
   oOo0o0O += self . json . json_string
   oOo0o0O += struct . pack ( "H" , 0 )
   if 41 - 41: OOooOOo - IiII + II111iiii - IiII * IiII
   if 60 - 60: ooOoO0o
  oo0oO0oOoo = ""
  if ( self . rloc . is_null ( ) == False and self . keys and self . keys [ 1 ] ) :
   oo0oO0oOoo = self . keys [ 1 ] . encode_lcaf ( self . rloc )
   if 66 - 66: iIii1I11I1II1 . Oo0Ooo / Ii1I + OOooOOo - O0 % IiII
   if 22 - 22: oO0o - i11iIiiIii % O0 / II111iiii
  i1I11i = ""
  if ( self . rloc_name ) :
   i1I11i += struct . pack ( "H" , socket . htons ( LISP_AFI_NAME ) )
   i1I11i += self . rloc_name + "\0"
   if 64 - 64: o0oOOo0O0Ooo
   if 22 - 22: o0oOOo0O0Ooo / OoooooooOO
  oOooo0Ooo0o00 = len ( IiIIIIiiIIIii ) + len ( o0OO0o ) + len ( iIIIiiI ) + len ( oo0oO0oOoo ) + 2 + len ( oOo0o0O ) + self . rloc . addr_length ( ) + len ( i1I11i )
  if 66 - 66: OOooOOo - i1IIi - I11i
  oOooo0Ooo0o00 = socket . htons ( oOooo0Ooo0o00 )
  iI1IIiI1 = struct . pack ( "HBBBBHH" , oO0OOOo0OO , 0 , 0 , LISP_LCAF_AFI_LIST_TYPE ,
 0 , oOooo0Ooo0o00 , socket . htons ( self . rloc . afi ) )
  iI1IIiI1 += self . rloc . pack_address ( )
  return ( iI1IIiI1 + i1I11i + IiIIIIiiIIIii + o0OO0o + iIIIiiI + oo0oO0oOoo + oOo0o0O )
  if 39 - 39: o0oOOo0O0Ooo % OoooooooOO - O0
  if 87 - 87: I1IiiI * i1IIi * Oo0Ooo / I1ii11iIi11i - OoO0O00
 def encode ( self ) :
  iiIIii1Iii1I = 0
  if ( self . local_bit ) : iiIIii1Iii1I |= 0x0004
  if ( self . probe_bit ) : iiIIii1Iii1I |= 0x0002
  if ( self . reach_bit ) : iiIIii1Iii1I |= 0x0001
  if 44 - 44: Oo0Ooo
  Ii11iIiiI = struct . pack ( "BBBBHH" , self . priority , self . weight ,
 self . mpriority , self . mweight , socket . htons ( iiIIii1Iii1I ) ,
 socket . htons ( self . rloc . afi ) )
  if 37 - 37: OOooOOo / Ii1I
  if ( self . geo or self . elp or self . rle or self . keys or self . rloc_name or self . json ) :
   if 51 - 51: OOooOOo + O0
   Ii11iIiiI = Ii11iIiiI [ 0 : - 2 ] + self . encode_lcaf ( )
  else :
   Ii11iIiiI += self . rloc . pack_address ( )
   if 91 - 91: i11iIiiIii + o0oOOo0O0Ooo % OoO0O00 / oO0o - i1IIi
  return ( Ii11iIiiI )
  if 82 - 82: Ii1I . OoooooooOO + OoooooooOO % OoO0O00 % I1ii11iIi11i
  if 65 - 65: Oo0Ooo . I11i
 def decode_lcaf ( self , packet , nonce ) :
  III11i = "HBBBBH"
  Oo0o0OOo0Oo0 = struct . calcsize ( III11i )
  if ( len ( packet ) < Oo0o0OOo0Oo0 ) : return ( None )
  if 7 - 7: Oo0Ooo * II111iiii
  ii1iI1i1 , iiII1II1 , iiIIii1Iii1I , o0oOoOOO , OO00 , i1IiI = struct . unpack ( III11i , packet [ : Oo0o0OOo0Oo0 ] )
  if 11 - 11: OoOoOO00 % OoooooooOO
  if 92 - 92: OoOoOO00 - iII111i * Ii1I - i1IIi
  i1IiI = socket . ntohs ( i1IiI )
  packet = packet [ Oo0o0OOo0Oo0 : : ]
  if ( i1IiI > len ( packet ) ) : return ( None )
  if 87 - 87: Ii1I * I1Ii111 + iIii1I11I1II1 * o0oOOo0O0Ooo * iIii1I11I1II1 . I11i
  if 66 - 66: Ii1I / OoO0O00 . O0 . I11i % OoooooooOO / OOooOOo
  if 49 - 49: I1IiiI * iII111i - OoO0O00 % Ii1I + Ii1I * I1Ii111
  if 94 - 94: OoOoOO00 - I11i + Ii1I + OoOoOO00 + II111iiii
  if ( o0oOoOOO == LISP_LCAF_AFI_LIST_TYPE ) :
   while ( i1IiI > 0 ) :
    III11i = "H"
    Oo0o0OOo0Oo0 = struct . calcsize ( III11i )
    if ( i1IiI < Oo0o0OOo0Oo0 ) : return ( None )
    if 61 - 61: IiII + Ii1I / oO0o . OoooooooOO + iII111i
    O0oo0ooO00 = len ( packet )
    ii1iI1i1 = struct . unpack ( III11i , packet [ : Oo0o0OOo0Oo0 ] ) [ 0 ]
    ii1iI1i1 = socket . ntohs ( ii1iI1i1 )
    if 29 - 29: OOooOOo
    if ( ii1iI1i1 == LISP_AFI_LCAF ) :
     packet = self . decode_lcaf ( packet , nonce )
     if ( packet == None ) : return ( None )
    else :
     packet = packet [ Oo0o0OOo0Oo0 : : ]
     self . rloc_name = None
     if ( ii1iI1i1 == LISP_AFI_NAME ) :
      packet , ooOO0OOO = lisp_decode_dist_name ( packet )
      self . rloc_name = ooOO0OOO
     else :
      self . rloc . afi = ii1iI1i1
      packet = self . rloc . unpack_address ( packet )
      if ( packet == None ) : return ( None )
      self . rloc . mask_len = self . rloc . host_mask_len ( )
      if 69 - 69: oO0o % OoooooooOO * iII111i
      if 58 - 58: oO0o / i11iIiiIii . OoOoOO00 % O0 / iIii1I11I1II1
      if 50 - 50: I1Ii111 . I11i / O0 . I11i
    i1IiI -= O0oo0ooO00 - len ( packet )
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
   III11i = "H"
   Oo0o0OOo0Oo0 = struct . calcsize ( III11i )
   if ( i1IiI < Oo0o0OOo0Oo0 ) : return ( None )
   if 40 - 40: o0oOOo0O0Ooo - iIii1I11I1II1 % oO0o . o0oOOo0O0Ooo
   I1iI1i = struct . unpack ( III11i , packet [ : Oo0o0OOo0Oo0 ] ) [ 0 ]
   I1iI1i = socket . ntohs ( I1iI1i )
   if ( i1IiI < Oo0o0OOo0Oo0 + I1iI1i ) : return ( None )
   if 35 - 35: I1IiiI % OOooOOo + OoOoOO00 / I1IiiI . O0 % iII111i
   packet = packet [ Oo0o0OOo0Oo0 : : ]
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
    iiIIii1Iii1I , ii1iI1i1 = struct . unpack ( "HH" , packet [ : 4 ] )
    if 16 - 16: o0oOOo0O0Ooo + i11iIiiIii % OOooOOo
    ii1iI1i1 = socket . ntohs ( ii1iI1i1 )
    if ( ii1iI1i1 == LISP_AFI_LCAF ) : return ( None )
    if 20 - 20: Oo0Ooo . OoooooooOO % oO0o - OOooOOo
    IIiIiii111iI = lisp_elp_node ( )
    IIiI11i1i . elp_nodes . append ( IIiIiii111iI )
    if 72 - 72: II111iiii . iII111i - iIii1I11I1II1 - oO0o / OoooooooOO + I1IiiI
    iiIIii1Iii1I = socket . ntohs ( iiIIii1Iii1I )
    IIiIiii111iI . eid = ( iiIIii1Iii1I & 0x4 )
    IIiIiii111iI . probe = ( iiIIii1Iii1I & 0x2 )
    IIiIiii111iI . strict = ( iiIIii1Iii1I & 0x1 )
    IIiIiii111iI . address . afi = ii1iI1i1
    IIiIiii111iI . address . mask_len = IIiIiii111iI . address . host_mask_len ( )
    packet = IIiIiii111iI . address . unpack_address ( packet [ 4 : : ] )
    i1IiI -= IIiIiii111iI . address . addr_length ( ) + 4
    if 61 - 61: o0oOOo0O0Ooo / I1ii11iIi11i / ooOoO0o
   IIiI11i1i . select_elp_node ( )
   self . elp = IIiI11i1i
   if 54 - 54: I1Ii111 * I1Ii111
  elif ( o0oOoOOO == LISP_LCAF_RLE_TYPE ) :
   if 30 - 30: I1Ii111 . OoOoOO00 + I1ii11iIi11i - iIii1I11I1II1 * ooOoO0o
   if 87 - 87: O0 + O0 - ooOoO0o . i11iIiiIii - Oo0Ooo * i11iIiiIii
   if 72 - 72: I11i / OoooooooOO
   if 95 - 95: I1IiiI * i11iIiiIii + i11iIiiIii / iIii1I11I1II1
   o0o0ooOo00 = lisp_rle ( None )
   o0o0ooOo00 . rle_nodes = [ ]
   while ( i1IiI > 0 ) :
    IiIIi , iiIiI1iiI1 , I1i1Ii , ii1iI1i1 = struct . unpack ( "HBBH" , packet [ : 6 ] )
    if 12 - 12: IiII + ooOoO0o . i11iIiiIii - iIii1I11I1II1
    ii1iI1i1 = socket . ntohs ( ii1iI1i1 )
    if ( ii1iI1i1 == LISP_AFI_LCAF ) : return ( None )
    if 27 - 27: I11i + iIii1I11I1II1
    O00o000O0O0oO = lisp_rle_node ( )
    o0o0ooOo00 . rle_nodes . append ( O00o000O0O0oO )
    if 71 - 71: OoOoOO00 + oO0o % OOooOOo * I1IiiI
    O00o000O0O0oO . level = I1i1Ii
    O00o000O0O0oO . address . afi = ii1iI1i1
    O00o000O0O0oO . address . mask_len = O00o000O0O0oO . address . host_mask_len ( )
    packet = O00o000O0O0oO . address . unpack_address ( packet [ 6 : : ] )
    if 89 - 89: Ii1I % I1Ii111 / Oo0Ooo * Ii1I + OoOoOO00
    i1IiI -= O00o000O0O0oO . address . addr_length ( ) + 6
    if ( i1IiI >= 2 ) :
     ii1iI1i1 = struct . unpack ( "H" , packet [ : 2 ] ) [ 0 ]
     if ( socket . ntohs ( ii1iI1i1 ) == LISP_AFI_NAME ) :
      packet = packet [ 2 : : ]
      packet , O00o000O0O0oO . rloc_name = lisp_decode_dist_name ( packet )
      if 5 - 5: Ii1I * I1IiiI + I1Ii111
      if ( packet == None ) : return ( None )
      i1IiI -= len ( O00o000O0O0oO . rloc_name ) + 1 + 2
      if 22 - 22: Oo0Ooo . OoO0O00
      if 55 - 55: Oo0Ooo % OoooooooOO * II111iiii % OoooooooOO
      if 30 - 30: I1Ii111 / o0oOOo0O0Ooo + OoooooooOO + OoOoOO00 + OoO0O00
   self . rle = o0o0ooOo00
   self . rle . build_forwarding_list ( )
   if 40 - 40: OoooooooOO / IiII
  elif ( o0oOoOOO == LISP_LCAF_SECURITY_TYPE ) :
   if 82 - 82: i11iIiiIii - oO0o - i1IIi
   if 78 - 78: oO0o % iII111i / i1IIi / ooOoO0o
   if 44 - 44: o0oOOo0O0Ooo + Ii1I + I1IiiI % O0
   if 100 - 100: OoooooooOO
   if 27 - 27: i11iIiiIii % II111iiii + I1Ii111
   oOoo0O000 = packet
   oO00OO0Ooo00O = lisp_keys ( 1 )
   packet = oO00OO0Ooo00O . decode_lcaf ( oOoo0O000 , i1IiI )
   if ( packet == None ) : return ( None )
   if 76 - 76: OOooOOo - I1Ii111 + iIii1I11I1II1 + I1IiiI * oO0o
   if 93 - 93: i11iIiiIii * i11iIiiIii - I1IiiI + iIii1I11I1II1 * i11iIiiIii
   if 14 - 14: ooOoO0o . OoooooooOO . I1IiiI - IiII + iIii1I11I1II1
   if 47 - 47: OOooOOo % i1IIi
   O0Oo = [ LISP_CS_25519_CBC , LISP_CS_25519_CHACHA ]
   if ( oO00OO0Ooo00O . cipher_suite in O0Oo ) :
    if ( oO00OO0Ooo00O . cipher_suite == LISP_CS_25519_CBC ) :
     OOO0OOoOOO = lisp_keys ( 1 , do_poly = False , do_chacha = False )
     if 23 - 23: Ii1I * Ii1I / I11i
    if ( oO00OO0Ooo00O . cipher_suite == LISP_CS_25519_CHACHA ) :
     OOO0OOoOOO = lisp_keys ( 1 , do_poly = True , do_chacha = True )
     if 11 - 11: OOooOOo
   else :
    OOO0OOoOOO = lisp_keys ( 1 , do_poly = False , do_chacha = False )
    if 58 - 58: OoO0O00 * OoooooooOO
   packet = OOO0OOoOOO . decode_lcaf ( oOoo0O000 , i1IiI )
   if ( packet == None ) : return ( None )
   if 47 - 47: iII111i - Oo0Ooo
   if ( len ( packet ) < 2 ) : return ( None )
   ii1iI1i1 = struct . unpack ( "H" , packet [ : 2 ] ) [ 0 ]
   self . rloc . afi = socket . ntohs ( ii1iI1i1 )
   if ( len ( packet ) < self . rloc . addr_length ( ) ) : return ( None )
   packet = self . rloc . unpack_address ( packet [ 2 : : ] )
   if ( packet == None ) : return ( None )
   self . rloc . mask_len = self . rloc . host_mask_len ( )
   if 19 - 19: O0 . i1IIi + I11i / II111iiii + ooOoO0o
   if 26 - 26: Ii1I * oO0o % I1IiiI - OOooOOo . I1Ii111
   if 35 - 35: i1IIi % i11iIiiIii + Ii1I
   if 14 - 14: OoO0O00 * OoooooooOO
   if 45 - 45: iIii1I11I1II1 * I1IiiI . OoOoOO00
   if 97 - 97: I11i % II111iiii % Ii1I . II111iiii . iIii1I11I1II1
   if ( self . rloc . is_null ( ) ) : return ( packet )
   if 98 - 98: i11iIiiIii + O0 - O0 - iII111i
   IIIi = self . rloc_name
   if ( IIIi ) : IIIi = blue ( self . rloc_name , False )
   if 75 - 75: i11iIiiIii / oO0o / iIii1I11I1II1 - I1Ii111 % OoO0O00 % i1IIi
   if 81 - 81: i1IIi * iII111i % I1ii11iIi11i - I1IiiI * I1Ii111 + OOooOOo
   if 66 - 66: Oo0Ooo
   if 82 - 82: IiII + OoooooooOO . I11i
   if 11 - 11: Ii1I + OoO0O00
   if 47 - 47: I11i . i11iIiiIii / II111iiii / IiII
   I11IiiI1 = self . keys [ 1 ] if self . keys else None
   if ( I11IiiI1 == None ) :
    if ( OOO0OOoOOO . remote_public_key == None ) :
     o0oOo = bold ( "No remote encap-public-key supplied" , False )
     lprint ( "    {} for {}" . format ( o0oOo , IIIi ) )
     OOO0OOoOOO = None
    else :
     o0oOo = bold ( "New encap-keying with new state" , False )
     lprint ( "    {} for {}" . format ( o0oOo , IIIi ) )
     OOO0OOoOOO . compute_shared_key ( "encap" )
     if 53 - 53: i1IIi - Oo0Ooo * O0 * OOooOOo . OoooooooOO
     if 99 - 99: oO0o . OoO0O00 / OOooOOo
     if 12 - 12: iIii1I11I1II1 + ooOoO0o * I1Ii111 % OoooooooOO / iIii1I11I1II1
     if 43 - 43: O0 . i1IIi - OoooooooOO - i1IIi - I1ii11iIi11i
     if 8 - 8: OoOoOO00 / Ii1I
     if 12 - 12: iIii1I11I1II1
     if 52 - 52: oO0o . I1ii11iIi11i + oO0o
     if 73 - 73: II111iiii / i11iIiiIii / ooOoO0o
     if 1 - 1: iII111i + OoOoOO00 / IiII - I1IiiI % I1IiiI
     if 6 - 6: OoOoOO00 - i1IIi + II111iiii % oO0o
   if ( I11IiiI1 ) :
    if ( OOO0OOoOOO . remote_public_key == None ) :
     OOO0OOoOOO = None
     o0o00O0 = bold ( "Remote encap-unkeying occurred" , False )
     lprint ( "    {} for {}" . format ( o0o00O0 , IIIi ) )
    elif ( I11IiiI1 . compare_keys ( OOO0OOoOOO ) ) :
     OOO0OOoOOO = I11IiiI1
     lprint ( "    Maintain stored encap-keys for {}" . format ( IIIi ) )
     if 72 - 72: OOooOOo + OOooOOo
    else :
     if ( I11IiiI1 . remote_public_key == None ) :
      o0oOo = "New encap-keying for existing state"
     else :
      o0oOo = "Remote encap-rekeying"
      if 30 - 30: I11i
     lprint ( "    {} for {}" . format ( bold ( o0oOo , False ) ,
 IIIi ) )
     I11IiiI1 . remote_public_key = OOO0OOoOOO . remote_public_key
     I11IiiI1 . compute_shared_key ( "encap" )
     OOO0OOoOOO = I11IiiI1
     if 15 - 15: O0 - i1IIi . iIii1I11I1II1 - i11iIiiIii / Ii1I
     if 11 - 11: iIii1I11I1II1 + I1IiiI
   self . keys = [ None , OOO0OOoOOO , None , None ]
   if 15 - 15: o0oOOo0O0Ooo
  else :
   if 55 - 55: i11iIiiIii / OoooooooOO - I11i
   if 89 - 89: I11i - i1IIi - i1IIi * OOooOOo - O0
   if 94 - 94: Oo0Ooo / I11i . I1ii11iIi11i
   if 31 - 31: i11iIiiIii + iIii1I11I1II1 . II111iiii
   packet = packet [ i1IiI : : ]
   if 72 - 72: I1Ii111 * OoO0O00 + Oo0Ooo / Ii1I % OOooOOo
  return ( packet )
  if 84 - 84: OoOoOO00 / o0oOOo0O0Ooo
  if 9 - 9: Ii1I
 def decode ( self , packet , nonce ) :
  III11i = "BBBBHH"
  Oo0o0OOo0Oo0 = struct . calcsize ( III11i )
  if ( len ( packet ) < Oo0o0OOo0Oo0 ) : return ( None )
  if 76 - 76: I1IiiI % Oo0Ooo / iIii1I11I1II1 - Oo0Ooo
  self . priority , self . weight , self . mpriority , self . mweight , iiIIii1Iii1I , ii1iI1i1 = struct . unpack ( III11i , packet [ : Oo0o0OOo0Oo0 ] )
  if 34 - 34: OoOoOO00 - i1IIi + OOooOOo + Ii1I . o0oOOo0O0Ooo
  if 42 - 42: OoO0O00
  iiIIii1Iii1I = socket . ntohs ( iiIIii1Iii1I )
  ii1iI1i1 = socket . ntohs ( ii1iI1i1 )
  self . local_bit = True if ( iiIIii1Iii1I & 0x0004 ) else False
  self . probe_bit = True if ( iiIIii1Iii1I & 0x0002 ) else False
  self . reach_bit = True if ( iiIIii1Iii1I & 0x0001 ) else False
  if 59 - 59: OoO0O00 . I1Ii111 % OoO0O00
  if ( ii1iI1i1 == LISP_AFI_LCAF ) :
   packet = packet [ Oo0o0OOo0Oo0 - 2 : : ]
   packet = self . decode_lcaf ( packet , nonce )
  else :
   self . rloc . afi = ii1iI1i1
   packet = packet [ Oo0o0OOo0Oo0 : : ]
   packet = self . rloc . unpack_address ( packet )
   if 22 - 22: Oo0Ooo
  self . rloc . mask_len = self . rloc . host_mask_len ( )
  return ( packet )
  if 21 - 21: o0oOOo0O0Ooo
  if 86 - 86: ooOoO0o / iIii1I11I1II1 . OOooOOo
 def end_of_rlocs ( self , packet , rloc_count ) :
  for oo0O0oO0O0O in range ( rloc_count ) :
   packet = self . decode ( packet , None )
   if ( packet == None ) : return ( None )
   if 93 - 93: Oo0Ooo / II111iiii . Oo0Ooo + i1IIi + i1IIi
  return ( packet )
  if 30 - 30: OoOoOO00 . OOooOOo % OOooOOo / II111iiii + i1IIi
  if 61 - 61: i1IIi % II111iiii * II111iiii . o0oOOo0O0Ooo / I1ii11iIi11i - I1Ii111
  if 93 - 93: Ii1I - i1IIi
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
class lisp_map_referral ( ) :
 def __init__ ( self ) :
  self . record_count = 0
  self . nonce = 0
  if 10 - 10: I1IiiI - II111iiii / IiII * II111iiii
  if 67 - 67: II111iiii . Ii1I % oO0o . Oo0Ooo + IiII
 def print_map_referral ( self ) :
  lprint ( "{} -> record-count: {}, nonce: 0x{}" . format ( bold ( "Map-Referral" , False ) , self . record_count ,
  # OOooOOo
 lisp_hex_string ( self . nonce ) ) )
  if 52 - 52: OoO0O00 * oO0o / iIii1I11I1II1 - OoOoOO00
  if 20 - 20: IiII % I1IiiI + iIii1I11I1II1 % iII111i
 def encode ( self ) :
  Ii1i111iI = ( LISP_MAP_REFERRAL << 28 ) | self . record_count
  Ii11iIiiI = struct . pack ( "I" , socket . htonl ( Ii1i111iI ) )
  Ii11iIiiI += struct . pack ( "Q" , self . nonce )
  return ( Ii11iIiiI )
  if 100 - 100: o0oOOo0O0Ooo - Oo0Ooo % I1Ii111 . i11iIiiIii % OoooooooOO
  if 39 - 39: I1ii11iIi11i / i11iIiiIii * i1IIi * Oo0Ooo
 def decode ( self , packet ) :
  III11i = "I"
  Oo0o0OOo0Oo0 = struct . calcsize ( III11i )
  if ( len ( packet ) < Oo0o0OOo0Oo0 ) : return ( None )
  if 39 - 39: OoO0O00 * OoooooooOO / i1IIi + Oo0Ooo
  Ii1i111iI = struct . unpack ( III11i , packet [ : Oo0o0OOo0Oo0 ] )
  Ii1i111iI = socket . ntohl ( Ii1i111iI [ 0 ] )
  self . record_count = Ii1i111iI & 0xff
  packet = packet [ Oo0o0OOo0Oo0 : : ]
  if 57 - 57: O0
  III11i = "Q"
  Oo0o0OOo0Oo0 = struct . calcsize ( III11i )
  if ( len ( packet ) < Oo0o0OOo0Oo0 ) : return ( None )
  if 83 - 83: OOooOOo / Ii1I * I1IiiI % oO0o / iIii1I11I1II1
  self . nonce = struct . unpack ( III11i , packet [ : Oo0o0OOo0Oo0 ] ) [ 0 ]
  packet = packet [ Oo0o0OOo0Oo0 : : ]
  return ( packet )
  if 1 - 1: I11i / OoooooooOO / iII111i
  if 68 - 68: i1IIi / Oo0Ooo / I11i * Oo0Ooo
  if 91 - 91: OoO0O00 . iII111i
  if 82 - 82: I1ii11iIi11i / Oo0Ooo
  if 63 - 63: I1IiiI
  if 3 - 3: iII111i + I1ii11iIi11i
  if 35 - 35: oO0o * iII111i * oO0o * I1Ii111 * IiII * i1IIi
  if 43 - 43: OoO0O00 * I1IiiI / IiII . i11iIiiIii + iII111i + o0oOOo0O0Ooo
class lisp_ddt_entry ( ) :
 def __init__ ( self ) :
  self . eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . group = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . uptime = lisp_get_timestamp ( )
  self . delegation_set = [ ]
  self . source_cache = None
  self . map_referrals_sent = 0
  if 1 - 1: I1IiiI % o0oOOo0O0Ooo . I1Ii111 + I11i * oO0o
  if 41 - 41: OoO0O00 * oO0o - II111iiii
 def is_auth_prefix ( self ) :
  if ( len ( self . delegation_set ) != 0 ) : return ( False )
  if ( self . is_star_g ( ) ) : return ( False )
  return ( True )
  if 2 - 2: IiII + IiII - OoO0O00 * iII111i . oO0o
  if 91 - 91: ooOoO0o
 def is_ms_peer_entry ( self ) :
  if ( len ( self . delegation_set ) == 0 ) : return ( False )
  return ( self . delegation_set [ 0 ] . is_ms_peer ( ) )
  if 22 - 22: ooOoO0o % OoO0O00 * OoOoOO00 + Oo0Ooo
  if 44 - 44: O0 - I11i
 def print_referral_type ( self ) :
  if ( len ( self . delegation_set ) == 0 ) : return ( "unknown" )
  iIiOoo0 = self . delegation_set [ 0 ]
  return ( iIiOoo0 . print_node_type ( ) )
  if 62 - 62: o0oOOo0O0Ooo + ooOoO0o . I1IiiI * I1Ii111
  if 65 - 65: I11i + i1IIi % i11iIiiIii + I11i % II111iiii
 def print_eid_tuple ( self ) :
  return ( lisp_print_eid_tuple ( self . eid , self . group ) )
  if 18 - 18: iII111i . OoooooooOO - OoO0O00 / I1IiiI
  if 4 - 4: O0
 def add_cache ( self ) :
  if ( self . group . is_null ( ) ) :
   lisp_ddt_cache . add_cache ( self . eid , self )
  else :
   O00OoO0O = lisp_ddt_cache . lookup_cache ( self . group , True )
   if ( O00OoO0O == None ) :
    O00OoO0O = lisp_ddt_entry ( )
    O00OoO0O . eid . copy_address ( self . group )
    O00OoO0O . group . copy_address ( self . group )
    lisp_ddt_cache . add_cache ( self . group , O00OoO0O )
    if 79 - 79: i1IIi % I1ii11iIi11i - OoO0O00 % I1ii11iIi11i
   if ( self . eid . is_null ( ) ) : self . eid . make_default_route ( O00OoO0O . group )
   O00OoO0O . add_source_entry ( self )
   if 6 - 6: Oo0Ooo / iII111i . i11iIiiIii
   if 8 - 8: I1ii11iIi11i + O0 - oO0o % II111iiii . I1Ii111
   if 86 - 86: IiII
 def add_source_entry ( self , source_ddt ) :
  if ( self . source_cache == None ) : self . source_cache = lisp_cache ( )
  self . source_cache . add_cache ( source_ddt . eid , source_ddt )
  if 71 - 71: Ii1I - i1IIi . I1IiiI
  if 15 - 15: i1IIi % II111iiii / II111iiii - I1ii11iIi11i - I11i % i1IIi
 def lookup_source_cache ( self , source , exact ) :
  if ( self . source_cache == None ) : return ( None )
  return ( self . source_cache . lookup_cache ( source , exact ) )
  if 54 - 54: i1IIi . OoO0O00 + iII111i + OoO0O00 * i1IIi
  if 13 - 13: Oo0Ooo / OoO0O00 + OOooOOo
 def is_star_g ( self ) :
  if ( self . group . is_null ( ) ) : return ( False )
  return ( self . eid . is_exact_match ( self . group ) )
  if 90 - 90: OoO0O00 * i11iIiiIii / oO0o
  if 91 - 91: iII111i - OoOoOO00 / Oo0Ooo % II111iiii / II111iiii / o0oOOo0O0Ooo
  if 34 - 34: OoO0O00 * II111iiii + i11iIiiIii % Ii1I
class lisp_ddt_node ( ) :
 def __init__ ( self ) :
  self . delegate_address = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . public_key = ""
  self . map_server_peer = False
  self . map_server_child = False
  self . priority = 0
  self . weight = 0
  if 25 - 25: OoOoOO00 + IiII . i11iIiiIii
  if 87 - 87: I1IiiI + OoooooooOO + O0
 def print_node_type ( self ) :
  if ( self . is_ddt_child ( ) ) : return ( "ddt-child" )
  if ( self . is_ms_child ( ) ) : return ( "map-server-child" )
  if ( self . is_ms_peer ( ) ) : return ( "map-server-peer" )
  if 32 - 32: Ii1I / I1ii11iIi11i . Ii1I
  if 65 - 65: IiII
 def is_ddt_child ( self ) :
  if ( self . map_server_child ) : return ( False )
  if ( self . map_server_peer ) : return ( False )
  return ( True )
  if 74 - 74: Oo0Ooo + i1IIi - II111iiii / ooOoO0o / iII111i
  if 66 - 66: ooOoO0o / IiII * iIii1I11I1II1
 def is_ms_child ( self ) :
  return ( self . map_server_child )
  if 42 - 42: I1Ii111 - i11iIiiIii % II111iiii * ooOoO0o . O0 % I11i
  if 82 - 82: Oo0Ooo % O0 + I1ii11iIi11i % I1ii11iIi11i
 def is_ms_peer ( self ) :
  return ( self . map_server_peer )
  if 74 - 74: O0 * IiII . I11i - I1Ii111 + O0 + I11i
  if 48 - 48: oO0o . o0oOOo0O0Ooo - OOooOOo
  if 29 - 29: Oo0Ooo - Ii1I - Oo0Ooo
  if 89 - 89: Oo0Ooo . OoO0O00 . I1ii11iIi11i * oO0o . O0
  if 72 - 72: i11iIiiIii % I11i / I1Ii111 + I1IiiI * iII111i
  if 69 - 69: I1Ii111 + O0 . IiII . o0oOOo0O0Ooo
  if 38 - 38: IiII / i1IIi
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
  if 60 - 60: OoOoOO00
  if 75 - 75: II111iiii / iIii1I11I1II1 / OoooooooOO
 def print_ddt_map_request ( self ) :
  lprint ( "Queued Map-Request from {}ITR {}->{}, nonce 0x{}" . format ( "P" if self . from_pitr else "" ,
  # i11iIiiIii / IiII * I11i . Ii1I
 red ( self . itr . print_address ( ) , False ) ,
 green ( self . eid . print_address ( ) , False ) , self . nonce ) )
  if 49 - 49: O0 + I1Ii111
  if 69 - 69: I1IiiI + OoOoOO00 * i1IIi / I1Ii111 * O0
 def queue_map_request ( self ) :
  self . retransmit_timer = threading . Timer ( LISP_DDT_MAP_REQUEST_INTERVAL ,
 lisp_retransmit_ddt_map_request , [ self ] )
  self . retransmit_timer . start ( )
  lisp_ddt_map_requestQ [ str ( self . nonce ) ] = self
  if 68 - 68: Oo0Ooo
  if 38 - 38: OoO0O00 * I1IiiI
 def dequeue_map_request ( self ) :
  self . retransmit_timer . cancel ( )
  if ( lisp_ddt_map_requestQ . has_key ( str ( self . nonce ) ) ) :
   lisp_ddt_map_requestQ . pop ( str ( self . nonce ) )
   if 82 - 82: I1Ii111 * Oo0Ooo % OoooooooOO
   if 12 - 12: IiII / O0 % I1IiiI - IiII
   if 80 - 80: OoooooooOO
 def print_eid_tuple ( self ) :
  return ( lisp_print_eid_tuple ( self . eid , self . group ) )
  if 100 - 100: iII111i / ooOoO0o * OoOoOO00 . OoooooooOO % I1Ii111 - O0
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
LISP_DDT_ACTION_SITE_NOT_FOUND = - 2
LISP_DDT_ACTION_NULL = - 1
LISP_DDT_ACTION_NODE_REFERRAL = 0
LISP_DDT_ACTION_MS_REFERRAL = 1
LISP_DDT_ACTION_MS_ACK = 2
LISP_DDT_ACTION_MS_NOT_REG = 3
LISP_DDT_ACTION_DELEGATION_HOLE = 4
LISP_DDT_ACTION_NOT_AUTH = 5
LISP_DDT_ACTION_MAX = LISP_DDT_ACTION_NOT_AUTH
if 52 - 52: I11i - oO0o . i11iIiiIii - II111iiii + Ii1I . iII111i
lisp_map_referral_action_string = [
 "node-referral" , "ms-referral" , "ms-ack" , "ms-not-registered" ,
 "delegation-hole" , "not-authoritative" ]
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
  if 24 - 24: I1ii11iIi11i % OOooOOo + OoooooooOO + OoO0O00
  if 100 - 100: Oo0Ooo % OoO0O00 - OoOoOO00
 def print_info ( self ) :
  if ( self . info_reply ) :
   iiii111I = "Info-Reply"
   II11IIiii = ( ", ms-port: {}, etr-port: {}, global-rloc: {}, " + "ms-rloc: {}, private-rloc: {}, RTR-list: " ) . format ( self . ms_port , self . etr_port ,
   # OoooooooOO
   # I1IiiI * I1IiiI + OoO0O00 - IiII
 red ( self . global_etr_rloc . print_address_no_iid ( ) , False ) ,
 red ( self . global_ms_rloc . print_address_no_iid ( ) , False ) ,
 red ( self . private_etr_rloc . print_address_no_iid ( ) , False ) )
   if ( len ( self . rtr_list ) == 0 ) : II11IIiii += "empty, "
   for o0O000o0o0 in self . rtr_list :
    II11IIiii += red ( o0O000o0o0 . print_address_no_iid ( ) , False ) + ", "
    if 98 - 98: I1Ii111 - i1IIi % oO0o + I1ii11iIi11i * OoooooooOO
   II11IIiii = II11IIiii [ 0 : - 2 ]
  else :
   iiii111I = "Info-Request"
   OO00o00000oO0 = "<none>" if self . hostname == None else self . hostname
   II11IIiii = ", hostname: {}" . format ( blue ( OO00o00000oO0 , False ) )
   if 40 - 40: iII111i . ooOoO0o % OoooooooOO % OOooOOo / OoooooooOO / Oo0Ooo
  lprint ( "{} -> nonce: 0x{}{}" . format ( bold ( iiii111I , False ) ,
 lisp_hex_string ( self . nonce ) , II11IIiii ) )
  if 93 - 93: o0oOOo0O0Ooo % iIii1I11I1II1 % oO0o / I1IiiI
  if 98 - 98: II111iiii + Oo0Ooo - i1IIi + iII111i + II111iiii
 def encode ( self ) :
  Ii1i111iI = ( LISP_NAT_INFO << 28 )
  if ( self . info_reply ) : Ii1i111iI |= ( 1 << 27 )
  if 93 - 93: O0
  if 78 - 78: I1Ii111 * i1IIi + OoooooooOO * ooOoO0o
  if 69 - 69: i1IIi
  if 83 - 83: I1ii11iIi11i . ooOoO0o + I1IiiI + O0
  if 78 - 78: O0 + Oo0Ooo
  Ii11iIiiI = struct . pack ( "I" , socket . htonl ( Ii1i111iI ) )
  Ii11iIiiI += struct . pack ( "Q" , self . nonce )
  Ii11iIiiI += struct . pack ( "III" , 0 , 0 , 0 )
  if 14 - 14: O0
  if 67 - 67: II111iiii / O0
  if 10 - 10: i1IIi / Oo0Ooo
  if 20 - 20: Oo0Ooo * I1Ii111 / I1ii11iIi11i . ooOoO0o
  if ( self . info_reply == False ) :
   if ( self . hostname == None ) :
    Ii11iIiiI += struct . pack ( "H" , 0 )
   else :
    Ii11iIiiI += struct . pack ( "H" , socket . htons ( LISP_AFI_NAME ) )
    Ii11iIiiI += self . hostname + "\0"
    if 67 - 67: o0oOOo0O0Ooo . Oo0Ooo % I11i
   return ( Ii11iIiiI )
   if 38 - 38: OOooOOo - OoO0O00 . ooOoO0o
   if 50 - 50: o0oOOo0O0Ooo
   if 85 - 85: II111iiii . iII111i - i1IIi
   if 23 - 23: iII111i . Ii1I - OoO0O00 / I1ii11iIi11i / O0
   if 4 - 4: i1IIi % Oo0Ooo % Ii1I * ooOoO0o - I11i
  ii1iI1i1 = socket . htons ( LISP_AFI_LCAF )
  o0oOoOOO = LISP_LCAF_NAT_TYPE
  i1IiI = socket . htons ( 16 )
  Oo00 = socket . htons ( self . ms_port )
  Ooo0OoOOOO = socket . htons ( self . etr_port )
  Ii11iIiiI += struct . pack ( "HHBBHHHH" , ii1iI1i1 , 0 , o0oOoOOO , 0 , i1IiI ,
 Oo00 , Ooo0OoOOOO , socket . htons ( self . global_etr_rloc . afi ) )
  Ii11iIiiI += self . global_etr_rloc . pack_address ( )
  Ii11iIiiI += struct . pack ( "HH" , 0 , socket . htons ( self . private_etr_rloc . afi ) )
  Ii11iIiiI += self . private_etr_rloc . pack_address ( )
  if ( len ( self . rtr_list ) == 0 ) : Ii11iIiiI += struct . pack ( "H" , 0 )
  if 2 - 2: I1IiiI . i1IIi
  if 60 - 60: iIii1I11I1II1 + ooOoO0o * i11iIiiIii + OoooooooOO
  if 43 - 43: I1ii11iIi11i % Oo0Ooo - i11iIiiIii / I1Ii111 * i1IIi
  if 78 - 78: o0oOOo0O0Ooo / OOooOOo / oO0o
  for o0O000o0o0 in self . rtr_list :
   Ii11iIiiI += struct . pack ( "H" , socket . htons ( o0O000o0o0 . afi ) )
   Ii11iIiiI += o0O000o0o0 . pack_address ( )
   if 9 - 9: IiII + O0 / I1IiiI
  return ( Ii11iIiiI )
  if 92 - 92: OOooOOo / i11iIiiIii + OoooooooOO
  if 9 - 9: iII111i
 def decode ( self , packet ) :
  oOoo0O000 = packet
  III11i = "I"
  Oo0o0OOo0Oo0 = struct . calcsize ( III11i )
  if ( len ( packet ) < Oo0o0OOo0Oo0 ) : return ( None )
  if 9 - 9: O0 / o0oOOo0O0Ooo / I11i - i11iIiiIii - iII111i / IiII
  Ii1i111iI = struct . unpack ( III11i , packet [ : Oo0o0OOo0Oo0 ] )
  Ii1i111iI = Ii1i111iI [ 0 ]
  packet = packet [ Oo0o0OOo0Oo0 : : ]
  if 46 - 46: IiII + OoooooooOO % I1IiiI
  III11i = "Q"
  Oo0o0OOo0Oo0 = struct . calcsize ( III11i )
  if ( len ( packet ) < Oo0o0OOo0Oo0 ) : return ( None )
  if 51 - 51: I1IiiI * I1Ii111 . i11iIiiIii % Oo0Ooo . i1IIi - oO0o
  i11IIoOOoOo0Ooo = struct . unpack ( III11i , packet [ : Oo0o0OOo0Oo0 ] )
  if 56 - 56: Oo0Ooo / II111iiii
  Ii1i111iI = socket . ntohl ( Ii1i111iI )
  self . nonce = i11IIoOOoOo0Ooo [ 0 ]
  self . info_reply = Ii1i111iI & 0x08000000
  self . hostname = None
  packet = packet [ Oo0o0OOo0Oo0 : : ]
  if 76 - 76: OoOoOO00 % OoO0O00 * O0
  if 39 - 39: ooOoO0o / iII111i
  if 94 - 94: oO0o + iII111i * OoOoOO00 - i1IIi / OoooooooOO
  if 59 - 59: I11i % Ii1I / OoOoOO00
  if 99 - 99: Ii1I + II111iiii / i11iIiiIii - IiII / iII111i + iII111i
  III11i = "HH"
  Oo0o0OOo0Oo0 = struct . calcsize ( III11i )
  if ( len ( packet ) < Oo0o0OOo0Oo0 ) : return ( None )
  if 55 - 55: IiII + OoooooooOO * I1ii11iIi11i . IiII * I1ii11iIi11i + IiII
  if 81 - 81: iIii1I11I1II1 . ooOoO0o + OoOoOO00
  if 31 - 31: I11i / OoOoOO00 + o0oOOo0O0Ooo
  if 80 - 80: Oo0Ooo
  if 58 - 58: I1Ii111 + OOooOOo
  oOoO0oO00ooOo , O0ooo00o0 = struct . unpack ( III11i , packet [ : Oo0o0OOo0Oo0 ] )
  if ( O0ooo00o0 != 0 ) : return ( None )
  if 76 - 76: II111iiii - o0oOOo0O0Ooo % OoO0O00 + iII111i
  packet = packet [ Oo0o0OOo0Oo0 : : ]
  III11i = "IBBH"
  Oo0o0OOo0Oo0 = struct . calcsize ( III11i )
  if ( len ( packet ) < Oo0o0OOo0Oo0 ) : return ( None )
  if 38 - 38: I1Ii111 - I11i * i1IIi + iIii1I11I1II1
  I1i , O000OOOoOooO , I1iII1iI1 , ii11I1i = struct . unpack ( III11i ,
 packet [ : Oo0o0OOo0Oo0 ] )
  if 95 - 95: iIii1I11I1II1 * OoO0O00 - Ii1I / ooOoO0o + OOooOOo
  if ( ii11I1i != 0 ) : return ( None )
  packet = packet [ Oo0o0OOo0Oo0 : : ]
  if 17 - 17: OOooOOo / Ii1I
  if 6 - 6: oO0o
  if 93 - 93: Ii1I + iII111i
  if 89 - 89: Oo0Ooo * II111iiii * I1Ii111 / I1IiiI + I1IiiI . o0oOOo0O0Ooo
  if ( self . info_reply == False ) :
   III11i = "H"
   Oo0o0OOo0Oo0 = struct . calcsize ( III11i )
   if ( len ( packet ) >= Oo0o0OOo0Oo0 ) :
    ii1iI1i1 = struct . unpack ( III11i , packet [ : Oo0o0OOo0Oo0 ] ) [ 0 ]
    if ( socket . ntohs ( ii1iI1i1 ) == LISP_AFI_NAME ) :
     packet = packet [ Oo0o0OOo0Oo0 : : ]
     packet , self . hostname = lisp_decode_dist_name ( packet )
     if 40 - 40: O0 - i1IIi - i11iIiiIii % IiII % II111iiii
     if 54 - 54: o0oOOo0O0Ooo + I1IiiI % ooOoO0o . Ii1I - o0oOOo0O0Ooo
   return ( oOoo0O000 )
   if 1 - 1: I1IiiI + iIii1I11I1II1
   if 81 - 81: OoO0O00 * ooOoO0o
   if 98 - 98: OoOoOO00 % ooOoO0o * I1ii11iIi11i
   if 64 - 64: OOooOOo + I11i . ooOoO0o
   if 17 - 17: OoOoOO00 . I1Ii111
  III11i = "HHBBHHH"
  Oo0o0OOo0Oo0 = struct . calcsize ( III11i )
  if ( len ( packet ) < Oo0o0OOo0Oo0 ) : return ( None )
  if 10 - 10: I1ii11iIi11i * I1Ii111 * Ii1I * o0oOOo0O0Ooo - o0oOOo0O0Ooo + OoOoOO00
  ii1iI1i1 , IiIIi , o0oOoOOO , O000OOOoOooO , i1IiI , Oo00 , Ooo0OoOOOO = struct . unpack ( III11i , packet [ : Oo0o0OOo0Oo0 ] )
  if 92 - 92: Ii1I / iII111i . I1ii11iIi11i % Ii1I
  if 18 - 18: OOooOOo + I1IiiI + i1IIi + o0oOOo0O0Ooo % o0oOOo0O0Ooo
  if ( socket . ntohs ( ii1iI1i1 ) != LISP_AFI_LCAF ) : return ( None )
  if 48 - 48: O0
  self . ms_port = socket . ntohs ( Oo00 )
  self . etr_port = socket . ntohs ( Ooo0OoOOOO )
  packet = packet [ Oo0o0OOo0Oo0 : : ]
  if 5 - 5: OOooOOo / i11iIiiIii . I11i % OOooOOo
  if 1 - 1: II111iiii + O0 * OoOoOO00 / IiII . O0
  if 87 - 87: IiII + I1IiiI
  if 74 - 74: OoO0O00 + OoO0O00 % iII111i / I11i / O0
  III11i = "H"
  Oo0o0OOo0Oo0 = struct . calcsize ( III11i )
  if ( len ( packet ) < Oo0o0OOo0Oo0 ) : return ( None )
  if 54 - 54: o0oOOo0O0Ooo / OoooooooOO * ooOoO0o . OoOoOO00 - I1Ii111
  if 69 - 69: oO0o - OoO0O00
  if 80 - 80: ooOoO0o + iIii1I11I1II1 . II111iiii + I1IiiI - oO0o % OoOoOO00
  if 10 - 10: iIii1I11I1II1
  ii1iI1i1 = struct . unpack ( III11i , packet [ : Oo0o0OOo0Oo0 ] ) [ 0 ]
  packet = packet [ Oo0o0OOo0Oo0 : : ]
  if ( ii1iI1i1 != 0 ) :
   self . global_etr_rloc . afi = socket . ntohs ( ii1iI1i1 )
   packet = self . global_etr_rloc . unpack_address ( packet )
   if ( packet == None ) : return ( None )
   self . global_etr_rloc . mask_len = self . global_etr_rloc . host_mask_len ( )
   if 44 - 44: OoOoOO00 * oO0o . I1ii11iIi11i + i11iIiiIii
   if 85 - 85: I11i
   if 36 - 36: ooOoO0o % OoO0O00
   if 1 - 1: OoooooooOO - OoOoOO00
   if 35 - 35: I1Ii111
   if 35 - 35: Oo0Ooo - iIii1I11I1II1 / i1IIi + OoO0O00 - OoooooooOO / i11iIiiIii
  if ( len ( packet ) < Oo0o0OOo0Oo0 ) : return ( oOoo0O000 )
  if 79 - 79: I1IiiI * ooOoO0o * ooOoO0o
  ii1iI1i1 = struct . unpack ( III11i , packet [ : Oo0o0OOo0Oo0 ] ) [ 0 ]
  packet = packet [ Oo0o0OOo0Oo0 : : ]
  if ( ii1iI1i1 != 0 ) :
   self . global_ms_rloc . afi = socket . ntohs ( ii1iI1i1 )
   packet = self . global_ms_rloc . unpack_address ( packet )
   if ( packet == None ) : return ( oOoo0O000 )
   self . global_ms_rloc . mask_len = self . global_ms_rloc . host_mask_len ( )
   if 92 - 92: iII111i % I1ii11iIi11i
   if 16 - 16: oO0o
   if 52 - 52: OoooooooOO % ooOoO0o - I1Ii111 * I11i
   if 24 - 24: Ii1I + IiII + OoooooooOO / oO0o / I1IiiI + IiII
   if 52 - 52: ooOoO0o
  if ( len ( packet ) < Oo0o0OOo0Oo0 ) : return ( oOoo0O000 )
  if 38 - 38: OoO0O00 + I1IiiI % IiII
  ii1iI1i1 = struct . unpack ( III11i , packet [ : Oo0o0OOo0Oo0 ] ) [ 0 ]
  packet = packet [ Oo0o0OOo0Oo0 : : ]
  if ( ii1iI1i1 != 0 ) :
   self . private_etr_rloc . afi = socket . ntohs ( ii1iI1i1 )
   packet = self . private_etr_rloc . unpack_address ( packet )
   if ( packet == None ) : return ( oOoo0O000 )
   self . private_etr_rloc . mask_len = self . private_etr_rloc . host_mask_len ( )
   if 87 - 87: oO0o * Ii1I - I1Ii111 / oO0o
   if 65 - 65: OoOoOO00
   if 87 - 87: I11i - i11iIiiIii - OOooOOo . OoOoOO00 + IiII . OoO0O00
   if 70 - 70: iIii1I11I1II1 % OoooooooOO / OoO0O00 . O0 - I11i % II111iiii
   if 84 - 84: OOooOOo * i1IIi . iIii1I11I1II1 * iII111i + I1Ii111 + II111iiii
   if 97 - 97: Ii1I - IiII
  while ( len ( packet ) >= Oo0o0OOo0Oo0 ) :
   ii1iI1i1 = struct . unpack ( III11i , packet [ : Oo0o0OOo0Oo0 ] ) [ 0 ]
   packet = packet [ Oo0o0OOo0Oo0 : : ]
   if ( ii1iI1i1 == 0 ) : continue
   o0O000o0o0 = lisp_address ( socket . ntohs ( ii1iI1i1 ) , "" , 0 , 0 )
   packet = o0O000o0o0 . unpack_address ( packet )
   if ( packet == None ) : return ( oOoo0O000 )
   o0O000o0o0 . mask_len = o0O000o0o0 . host_mask_len ( )
   self . rtr_list . append ( o0O000o0o0 )
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
  I1IiIii11I = time . time ( ) - self . uptime
  return ( I1IiIii11I >= ( LISP_INFO_INTERVAL * 2 ) )
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
  OOO0OOoOOO = self . address . print_address_no_iid ( ) + self . hostname
  lisp_info_sources_by_address [ OOO0OOoOOO ] = self
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
   IIi = socket . socket ( socket . AF_INET , socket . SOCK_DGRAM )
   if 38 - 38: i11iIiiIii + I1IiiI . i11iIiiIii - I11i * OOooOOo
  if ( local_addr . find ( ":" ) != - 1 ) :
   if ( lisp_is_raspbian ( ) ) : return ( None )
   IIi = socket . socket ( socket . AF_INET6 , socket . SOCK_DGRAM )
   if 59 - 59: iII111i / OoOoOO00 + OoOoOO00 - I1IiiI
  IIi . bind ( ( local_addr , int ( port ) ) )
 else :
  I1i1iI1II = port
  if ( os . path . exists ( I1i1iI1II ) ) :
   os . system ( "rm " + I1i1iI1II )
   time . sleep ( 1 )
   if 10 - 10: Ii1I / II111iiii
  IIi = socket . socket ( socket . AF_UNIX , socket . SOCK_DGRAM )
  IIi . bind ( I1i1iI1II )
  if 53 - 53: i11iIiiIii . i1IIi . I1IiiI . ooOoO0o * OoOoOO00
 return ( IIi )
 if 98 - 98: I1ii11iIi11i + ooOoO0o
 if 42 - 42: Oo0Ooo + OoOoOO00 - O0 / Oo0Ooo - OoooooooOO . Ii1I
 if 64 - 64: OoooooooOO
 if 25 - 25: IiII
 if 29 - 29: OoOoOO00 % ooOoO0o * OoooooooOO
 if 8 - 8: i11iIiiIii - I1Ii111 / IiII
 if 17 - 17: i11iIiiIii * OoO0O00 . o0oOOo0O0Ooo . OoooooooOO . OoOoOO00 - I1ii11iIi11i
def lisp_open_send_socket ( internal_name , afi ) :
 if ( internal_name == "" ) :
  if ( afi == LISP_AFI_IPV4 ) :
   IIi = socket . socket ( socket . AF_INET , socket . SOCK_DGRAM )
   if 78 - 78: I1ii11iIi11i - OoooooooOO + O0
  if ( afi == LISP_AFI_IPV6 ) :
   if ( lisp_is_raspbian ( ) ) : return ( None )
   IIi = socket . socket ( socket . AF_INET6 , socket . SOCK_DGRAM )
   if 15 - 15: I1ii11iIi11i / IiII % I1IiiI
 else :
  if ( os . path . exists ( internal_name ) ) : os . system ( "rm " + internal_name )
  IIi = socket . socket ( socket . AF_UNIX , socket . SOCK_DGRAM )
  IIi . bind ( internal_name )
  if 16 - 16: Ii1I
 return ( IIi )
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
 I1 = 0
 O00OoO0oo = len ( packet )
 iIII1ii1iii1 = 0
 iIiIi = .001
 while ( O00OoO0oo > 0 ) :
  O0o = min ( O00OoO0oo , Ii1111Ii )
  i1iiiiIiiI1I1 = packet [ I1 : O0o + I1 ]
  if 42 - 42: iIii1I11I1II1 % I11i * OOooOOo + iIii1I11I1II1 % Ii1I
  try :
   send_socket . sendto ( i1iiiiIiiI1I1 , node )
   lprint ( "Send IPC {}-out-of-{} byte to {} succeeded" . format ( len ( i1iiiiIiiI1I1 ) , len ( packet ) , node ) )
   if 56 - 56: o0oOOo0O0Ooo
   iIII1ii1iii1 = 0
   iIiIi = .001
   if 55 - 55: oO0o - I1Ii111 / ooOoO0o % I1IiiI * OoooooooOO * I1IiiI
  except socket . error , ooOoOOOOo :
   if ( iIII1ii1iii1 == 12 ) :
    lprint ( "Giving up on {}, consider it down" . format ( node ) )
    break
    if 88 - 88: Ii1I + O0
    if 92 - 92: I1IiiI % iII111i % I11i + OoooooooOO - i11iIiiIii
   lprint ( "Send IPC {}-out-of-{} byte to {} failed: {}" . format ( len ( i1iiiiIiiI1I1 ) , len ( packet ) , node , ooOoOOOOo ) )
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
  I1 += O0o
  O00OoO0oo -= O0o
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
 I1 = 0
 o0o0Oo0O0O0o = ""
 O00OoO0oo = len ( packet ) * 2
 while ( I1 < O00OoO0oo ) :
  o0o0Oo0O0O0o += packet [ I1 : I1 + 8 ] + " "
  I1 += 8
  O00OoO0oo -= 4
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
 I1IIIIIi1IIiI = dest . print_address_no_iid ( )
 if ( I1IIIIIi1IIiI . find ( "::ffff:" ) != - 1 and I1IIIIIi1IIiI . count ( "." ) == 3 ) :
  if ( lisp_i_am_rtr ) : O0O = lisp_sockets [ 0 ]
  if ( O0O == None ) :
   O0O = lisp_sockets [ 0 ]
   I1IIIIIi1IIiI = I1IIIIIi1IIiI . split ( "::ffff:" ) [ - 1 ]
   if 74 - 74: I1IiiI * OoO0O00 + OoooooooOO * ooOoO0o . oO0o
   if 66 - 66: II111iiii + OOooOOo + i11iIiiIii / II111iiii
   if 37 - 37: I1IiiI + OoO0O00 . OoO0O00 % OoOoOO00 + o0oOOo0O0Ooo
 lprint ( "{} {} bytes {} {}, packet: {}" . format ( bold ( "Send" , False ) ,
 len ( packet ) , bold ( "to " + I1IIIIIi1IIiI , False ) , port ,
 lisp_format_packet ( packet ) ) )
 if 81 - 81: i1IIi % iIii1I11I1II1
 if 41 - 41: oO0o - iII111i / o0oOOo0O0Ooo . iII111i % Oo0Ooo + OOooOOo
 if 82 - 82: ooOoO0o
 if 89 - 89: OOooOOo / I1ii11iIi11i . I1IiiI + i11iIiiIii
 IIo00ooOoooO = ( LISP_RLOC_PROBE_TTL == 255 )
 if ( IIo00ooOoooO ) :
  iii = struct . unpack ( "B" , packet [ 0 ] ) [ 0 ]
  IIo00ooOoooO = ( iii in [ 0x12 , 0x28 ] )
  if ( IIo00ooOoooO ) : lisp_set_ttl ( O0O , LISP_RLOC_PROBE_TTL )
  if 65 - 65: iII111i % oO0o - I11i * I1Ii111 . Ii1I
  if 61 - 61: IiII
 try : O0O . sendto ( packet , ( I1IIIIIi1IIiI , port ) )
 except socket . error , ooOoOOOOo :
  lprint ( "socket.sendto() failed: {}" . format ( ooOoOOOOo ) )
  if 23 - 23: I1Ii111 . O0 . I1ii11iIi11i
  if 89 - 89: OoO0O00 - OoOoOO00 / II111iiii . I1ii11iIi11i
  if 50 - 50: Ii1I * I1Ii111 * OoooooooOO . OoooooooOO
  if 67 - 67: i11iIiiIii % ooOoO0o . I1ii11iIi11i + II111iiii . OoO0O00
  if 42 - 42: I11i / OoO0O00 / OoO0O00 * OOooOOo
 if ( IIo00ooOoooO ) : lisp_set_ttl ( O0O , 64 )
 return
 if 2 - 2: II111iiii % oO0o . I1Ii111
 if 100 - 100: OoOoOO00 + OoOoOO00
 if 26 - 26: II111iiii * iII111i + OOooOOo
 if 28 - 28: Ii1I + O0
 if 44 - 44: oO0o
 if 51 - 51: o0oOOo0O0Ooo * o0oOOo0O0Ooo . Ii1I
 if 14 - 14: OoO0O00 . I11i % II111iiii % i11iIiiIii + OoooooooOO
 if 50 - 50: i11iIiiIii * I11i + i11iIiiIii - i1IIi
def lisp_receive_segments ( lisp_socket , packet , source , total_length ) :
 if 69 - 69: I1IiiI + IiII + oO0o * I1ii11iIi11i . iIii1I11I1II1 / OoooooooOO
 if 77 - 77: Oo0Ooo - ooOoO0o
 if 68 - 68: Ii1I * O0
 if 61 - 61: II111iiii - OoO0O00 . iIii1I11I1II1 * o0oOOo0O0Ooo . OoO0O00 % IiII
 if 11 - 11: oO0o + I11i
 O0o = total_length - len ( packet )
 if ( O0o == 0 ) : return ( [ True , packet ] )
 if 6 - 6: i1IIi . o0oOOo0O0Ooo + OoO0O00 + OOooOOo + oO0o
 lprint ( "Received {}-out-of-{} byte segment from {}" . format ( len ( packet ) ,
 total_length , source ) )
 if 30 - 30: O0
 if 98 - 98: I1Ii111
 if 58 - 58: OOooOOo
 if 6 - 6: I1ii11iIi11i
 if 37 - 37: i11iIiiIii . II111iiii + OOooOOo + i1IIi * OOooOOo
 O00OoO0oo = O0o
 while ( O00OoO0oo > 0 ) :
  try : i1iiiiIiiI1I1 = lisp_socket . recvfrom ( 9000 )
  except : return ( [ False , None ] )
  if 18 - 18: ooOoO0o
  i1iiiiIiiI1I1 = i1iiiiIiiI1I1 [ 0 ]
  if 18 - 18: I1Ii111 + OoOoOO00 % OOooOOo - IiII - i1IIi + I1ii11iIi11i
  if 33 - 33: I11i * Ii1I / Oo0Ooo + oO0o % OOooOOo % OoooooooOO
  if 29 - 29: Ii1I . II111iiii / I1Ii111
  if 79 - 79: IiII . OoOoOO00 / oO0o % OoO0O00 / Ii1I + I11i
  if 78 - 78: o0oOOo0O0Ooo + I1Ii111 % i11iIiiIii % I1IiiI - Ii1I
  if ( i1iiiiIiiI1I1 . find ( "packet@" ) == 0 ) :
   ooOo0OooO = i1iiiiIiiI1I1 . split ( "@" )
   lprint ( "Received new message ({}-out-of-{}) while receiving " + "fragments, old message discarded" , len ( i1iiiiIiiI1I1 ) ,
   # iII111i / OoO0O00 + i11iIiiIii / Oo0Ooo
 ooOo0OooO [ 1 ] if len ( ooOo0OooO ) > 2 else "?" )
   return ( [ False , i1iiiiIiiI1I1 ] )
   if 26 - 26: I1ii11iIi11i - OoO0O00
   if 19 - 19: iIii1I11I1II1 / I1ii11iIi11i + O0
  O00OoO0oo -= len ( i1iiiiIiiI1I1 )
  packet += i1iiiiIiiI1I1
  if 12 - 12: I11i . OOooOOo + o0oOOo0O0Ooo . OoO0O00 + o0oOOo0O0Ooo
  lprint ( "Received {}-out-of-{} byte segment from {}" . format ( len ( i1iiiiIiiI1I1 ) , total_length , source ) )
  if 56 - 56: i1IIi / i1IIi . OoO0O00 % i1IIi - OoOoOO00 % OOooOOo
  if 66 - 66: i11iIiiIii * IiII % IiII . I1IiiI / ooOoO0o
 return ( [ True , packet ] )
 if 50 - 50: IiII . iII111i / o0oOOo0O0Ooo % OoOoOO00 * IiII % I11i
 if 15 - 15: Ii1I
 if 29 - 29: I11i / I1IiiI / OoooooooOO . OoOoOO00 / I11i . I1Ii111
 if 69 - 69: O0 * OoOoOO00 + o0oOOo0O0Ooo + I1IiiI % iII111i . OoooooooOO
 if 45 - 45: I1Ii111 + oO0o - o0oOOo0O0Ooo - OoOoOO00 + I1IiiI / II111iiii
 if 46 - 46: II111iiii . iIii1I11I1II1
 if 62 - 62: I1ii11iIi11i % i1IIi % I1Ii111 * ooOoO0o % OOooOOo + I1IiiI
 if 100 - 100: II111iiii - o0oOOo0O0Ooo * OoooooooOO . ooOoO0o / II111iiii / oO0o
def lisp_bit_stuff ( payload ) :
 lprint ( "Bit-stuffing, found {} segments" . format ( len ( payload ) ) )
 Ii11iIiiI = ""
 for i1iiiiIiiI1I1 in payload : Ii11iIiiI += i1iiiiIiiI1I1 + "\x40"
 return ( Ii11iIiiI [ : - 1 ] )
 if 43 - 43: iIii1I11I1II1 + ooOoO0o * iII111i + iIii1I11I1II1 . I1Ii111
 if 87 - 87: I1Ii111
 if 47 - 47: II111iiii + I1IiiI . Oo0Ooo / iIii1I11I1II1
 if 14 - 14: i1IIi / OoO0O00 / iII111i % I1Ii111
 if 72 - 72: OoO0O00 . II111iiii - IiII + IiII + iIii1I11I1II1 % oO0o
 if 21 - 21: iII111i + OoOoOO00 - i11iIiiIii % O0 + OOooOOo
 if 30 - 30: o0oOOo0O0Ooo - Oo0Ooo + iII111i / O0
 if 94 - 94: IiII
 if 69 - 69: I1Ii111 . I1Ii111
 if 53 - 53: i11iIiiIii + iII111i * Oo0Ooo - I1Ii111
 if 61 - 61: o0oOOo0O0Ooo / OOooOOo . II111iiii - I1IiiI * i11iIiiIii
 if 8 - 8: iII111i % o0oOOo0O0Ooo
 if 87 - 87: Ii1I % I11i / I1Ii111
 if 21 - 21: OoO0O00 + Ii1I / I1Ii111
 if 75 - 75: I1Ii111 . Ii1I % iIii1I11I1II1 / OoOoOO00
 if 38 - 38: i1IIi
 if 1 - 1: I1ii11iIi11i + OoO0O00 % I11i . OOooOOo + i1IIi / oO0o
 if 35 - 35: ooOoO0o % OoOoOO00 % OoO0O00 + OOooOOo / IiII * OoOoOO00
 if 65 - 65: I1IiiI . Oo0Ooo + i1IIi - Ii1I * i1IIi
 if 64 - 64: I1IiiI / OoO0O00 * I1IiiI * II111iiii . Ii1I
def lisp_receive ( lisp_socket , internal ) :
 while ( True ) :
  if 98 - 98: I1Ii111 + o0oOOo0O0Ooo
  if 73 - 73: I1ii11iIi11i / I1Ii111 + i11iIiiIii + OoO0O00 . ooOoO0o
  if 54 - 54: I1ii11iIi11i + IiII - oO0o + Oo0Ooo / IiII % Oo0Ooo
  if 2 - 2: OOooOOo / I11i * I11i + I11i / O0 - OOooOOo
  try : II1iII = lisp_socket . recvfrom ( 9000 )
  except : return ( [ "" , "" , "" , "" ] )
  if 17 - 17: I1IiiI / OOooOOo * OoooooooOO / OoOoOO00 / i11iIiiIii
  if 56 - 56: iIii1I11I1II1 . I11i
  if 23 - 23: i11iIiiIii - I11i . O0 - iIii1I11I1II1 % Oo0Ooo / o0oOOo0O0Ooo
  if 6 - 6: ooOoO0o - OOooOOo . Oo0Ooo * OoOoOO00 / OoooooooOO * OoO0O00
  if 3 - 3: OoooooooOO + O0 % Oo0Ooo / oO0o
  if 67 - 67: I1ii11iIi11i % Oo0Ooo * OoOoOO00
  if ( internal == False ) :
   Ii11iIiiI = II1iII [ 0 ]
   OOii = lisp_convert_6to4 ( II1iII [ 1 ] [ 0 ] )
   IIIIiI1ii1 = II1iII [ 1 ] [ 1 ]
   if 57 - 57: Oo0Ooo + I1IiiI * OOooOOo - Oo0Ooo
   if ( IIIIiI1ii1 == LISP_DATA_PORT ) :
    OoO000O = lisp_data_plane_logging
    Oo00o0000O = lisp_format_packet ( Ii11iIiiI [ 0 : 60 ] ) + " ..."
   else :
    OoO000O = True
    Oo00o0000O = lisp_format_packet ( Ii11iIiiI )
    if 51 - 51: OOooOOo . O0 . OoooooooOO - I1Ii111 / OoOoOO00
    if 72 - 72: i1IIi . Ii1I
   if ( OoO000O ) :
    lprint ( "{} {} bytes {} {}, packet: {}" . format ( bold ( "Receive" ,
 False ) , len ( Ii11iIiiI ) , bold ( "from " + OOii , False ) , IIIIiI1ii1 ,
 Oo00o0000O ) )
    if 67 - 67: oO0o + i1IIi / o0oOOo0O0Ooo
   return ( [ "packet" , OOii , IIIIiI1ii1 , Ii11iIiiI ] )
   if 78 - 78: ooOoO0o
   if 19 - 19: i1IIi % O0 % ooOoO0o / II111iiii * I11i
   if 18 - 18: i1IIi % oO0o
   if 80 - 80: II111iiii
   if 18 - 18: I1Ii111 % iII111i + OoOoOO00 . I1ii11iIi11i / I11i
   if 29 - 29: II111iiii - I1Ii111 . OoooooooOO / i11iIiiIii / I1ii11iIi11i
  Ooo00oOOoo0 = False
  i11i111i1 = II1iII [ 0 ]
  OOOoo0ooooo0 = False
  if 21 - 21: i1IIi
  while ( Ooo00oOOoo0 == False ) :
   i11i111i1 = i11i111i1 . split ( "@" )
   if 10 - 10: i11iIiiIii / ooOoO0o - o0oOOo0O0Ooo . o0oOOo0O0Ooo
   if ( len ( i11i111i1 ) < 4 ) :
    lprint ( "Possible fragment (length {}), from old message, " + "discarding" , len ( i11i111i1 [ 0 ] ) )
    if 8 - 8: iII111i + iIii1I11I1II1 . I1ii11iIi11i
    OOOoo0ooooo0 = True
    break
    if 68 - 68: OoooooooOO . OoooooooOO % I1ii11iIi11i + i1IIi % OoooooooOO + Ii1I
    if 89 - 89: ooOoO0o + I11i * O0 % OoOoOO00
   I1iiI1ii1i = i11i111i1 [ 0 ]
   try :
    O0IIiIi = int ( i11i111i1 [ 1 ] )
   except :
    O0OO0O = bold ( "Internal packet reassembly error" , False )
    lprint ( "{}: {}" . format ( O0OO0O , II1iII ) )
    OOOoo0ooooo0 = True
    break
    if 86 - 86: iII111i / i1IIi % Oo0Ooo
   OOii = i11i111i1 [ 2 ]
   IIIIiI1ii1 = i11i111i1 [ 3 ]
   if 84 - 84: o0oOOo0O0Ooo * OOooOOo . I11i * Ii1I
   if 32 - 32: ooOoO0o % ooOoO0o * I1ii11iIi11i % Ii1I + Oo0Ooo . OoOoOO00
   if 2 - 2: I1Ii111 / ooOoO0o * oO0o + IiII
   if 14 - 14: OoOoOO00 / iIii1I11I1II1 . o0oOOo0O0Ooo % i11iIiiIii . OoOoOO00
   if 92 - 92: OoO0O00 . i1IIi
   if 22 - 22: Ii1I . I1IiiI
   if 54 - 54: OOooOOo / I1ii11iIi11i % oO0o
   if 66 - 66: I11i + iII111i
   if ( len ( i11i111i1 ) > 5 ) :
    Ii11iIiiI = lisp_bit_stuff ( i11i111i1 [ 4 : : ] )
   else :
    Ii11iIiiI = i11i111i1 [ 4 ]
    if 50 - 50: IiII
    if 33 - 33: OOooOOo % I1IiiI - I1IiiI / IiII
    if 22 - 22: ooOoO0o * ooOoO0o % o0oOOo0O0Ooo * Ii1I . OoO0O00
    if 55 - 55: OoOoOO00 - I1ii11iIi11i + iIii1I11I1II1 - i11iIiiIii / i1IIi / II111iiii
    if 37 - 37: Ii1I + o0oOOo0O0Ooo
    if 74 - 74: Oo0Ooo / O0 + i1IIi . I1IiiI + OoO0O00 / Oo0Ooo
   Ooo00oOOoo0 , Ii11iIiiI = lisp_receive_segments ( lisp_socket , Ii11iIiiI ,
 OOii , O0IIiIi )
   if ( Ii11iIiiI == None ) : return ( [ "" , "" , "" , "" ] )
   if 13 - 13: o0oOOo0O0Ooo / Ii1I . II111iiii
   if 8 - 8: I11i - I11i % IiII
   if 8 - 8: I1IiiI . IiII * O0 * o0oOOo0O0Ooo
   if 17 - 17: I1IiiI . oO0o + Oo0Ooo + I11i / o0oOOo0O0Ooo
   if 25 - 25: iII111i / iII111i % OoOoOO00 / ooOoO0o
   if ( Ooo00oOOoo0 == False ) :
    i11i111i1 = Ii11iIiiI
    continue
    if 81 - 81: OOooOOo * oO0o
    if 32 - 32: Oo0Ooo * OoO0O00 + ooOoO0o . O0 * oO0o * iIii1I11I1II1
   if ( IIIIiI1ii1 == "" ) : IIIIiI1ii1 = "no-port"
   if ( I1iiI1ii1i == "command" and lisp_i_am_core == False ) :
    Oo0oOooo000OO = Ii11iIiiI . find ( " {" )
    iI1I = Ii11iIiiI if Oo0oOooo000OO == - 1 else Ii11iIiiI [ : Oo0oOooo000OO ]
    iI1I = ": '" + iI1I + "'"
   else :
    iI1I = ""
    if 27 - 27: O0
    if 86 - 86: IiII + Ii1I / Oo0Ooo / O0 % iII111i - oO0o
   lprint ( "{} {} bytes {} {}, {}{}" . format ( bold ( "Receive" , False ) ,
 len ( Ii11iIiiI ) , bold ( "from " + OOii , False ) , IIIIiI1ii1 , I1iiI1ii1i ,
 iI1I if ( I1iiI1ii1i in [ "command" , "api" ] ) else ": ... " if ( I1iiI1ii1i == "data-packet" ) else ": " + lisp_format_packet ( Ii11iIiiI ) ) )
   if 3 - 3: i11iIiiIii / I1ii11iIi11i % I1Ii111 + o0oOOo0O0Ooo + O0
   if 42 - 42: IiII / i11iIiiIii % o0oOOo0O0Ooo / II111iiii / IiII
   if 97 - 97: OOooOOo . OoOoOO00 / I11i - IiII - iIii1I11I1II1
   if 82 - 82: II111iiii + OoO0O00 % iIii1I11I1II1 / O0
   if 75 - 75: OOooOOo * OoO0O00 + OoooooooOO + i11iIiiIii . OoO0O00
  if ( OOOoo0ooooo0 ) : continue
  return ( [ I1iiI1ii1i , OOii , IIIIiI1ii1 , Ii11iIiiI ] )
  if 94 - 94: I11i * ooOoO0o . I1IiiI / Ii1I - I1IiiI % OoooooooOO
  if 32 - 32: OoO0O00
  if 22 - 22: II111iiii . I11i
  if 61 - 61: OOooOOo % O0 . I1ii11iIi11i . iIii1I11I1II1 * I11i
  if 29 - 29: ooOoO0o + i1IIi % IiII * Ii1I
  if 94 - 94: OOooOOo / IiII
  if 18 - 18: IiII - I11i / Ii1I % IiII * i1IIi
  if 22 - 22: OoOoOO00 - Oo0Ooo
def lisp_parse_packet ( lisp_sockets , packet , source , udp_sport , ttl = - 1 ) :
 iii1IiiI1iiIi = False
 if 73 - 73: IiII * ooOoO0o * o0oOOo0O0Ooo % O0 - i11iIiiIii % I11i
 I11IIIIiII = lisp_control_header ( )
 if ( I11IIIIiII . decode ( packet ) == None ) :
  lprint ( "Could not decode control header" )
  return ( iii1IiiI1iiIi )
  if 13 - 13: I1IiiI . II111iiii + O0 % I1ii11iIi11i . O0 - I1ii11iIi11i
  if 37 - 37: I1IiiI % I1Ii111
  if 22 - 22: o0oOOo0O0Ooo % OOooOOo - I11i + ooOoO0o / OOooOOo
  if 98 - 98: I11i * O0 + IiII - oO0o
  if 35 - 35: OoooooooOO * Ii1I
 O0oOOOOoOO = source
 if ( source . find ( "lisp" ) == - 1 ) :
  oOOOOOOOoO = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  oOOOOOOOoO . string_to_afi ( source )
  oOOOOOOOoO . store_address ( source )
  source = oOOOOOOOoO
  if 72 - 72: iII111i * oO0o
  if 37 - 37: I1IiiI
 if ( I11IIIIiII . type == LISP_MAP_REQUEST ) :
  lisp_process_map_request ( lisp_sockets , packet , None , 0 , source ,
 udp_sport , False , ttl )
  if 76 - 76: iIii1I11I1II1 . iII111i % ooOoO0o / iII111i + I11i
 elif ( I11IIIIiII . type == LISP_MAP_REPLY ) :
  lisp_process_map_reply ( lisp_sockets , packet , source , ttl )
  if 85 - 85: i11iIiiIii
 elif ( I11IIIIiII . type == LISP_MAP_REGISTER ) :
  lisp_process_map_register ( lisp_sockets , packet , source , udp_sport )
  if 25 - 25: oO0o . OoO0O00 % Ii1I % Ii1I
 elif ( I11IIIIiII . type == LISP_MAP_NOTIFY ) :
  if ( O0oOOOOoOO == "lisp-etr" ) :
   lisp_process_multicast_map_notify ( packet , source )
  else :
   if ( lisp_is_running ( "lisp-rtr" ) ) :
    lisp_process_multicast_map_notify ( packet , source )
    if 94 - 94: iII111i . Ii1I
   lisp_process_map_notify ( lisp_sockets , packet , source )
   if 71 - 71: o0oOOo0O0Ooo * II111iiii / OOooOOo . OoO0O00
   if 73 - 73: I1Ii111 * OoO0O00 / OoOoOO00 . II111iiii
 elif ( I11IIIIiII . type == LISP_MAP_NOTIFY_ACK ) :
  lisp_process_map_notify_ack ( packet , source )
  if 87 - 87: OoO0O00 + Oo0Ooo + O0 % OoooooooOO - iIii1I11I1II1
 elif ( I11IIIIiII . type == LISP_MAP_REFERRAL ) :
  lisp_process_map_referral ( lisp_sockets , packet , source )
  if 100 - 100: Oo0Ooo + IiII
 elif ( I11IIIIiII . type == LISP_NAT_INFO and I11IIIIiII . is_info_reply ( ) ) :
  IiIIi , iiIiI1iiI1 , iii1IiiI1iiIi = lisp_process_info_reply ( source , packet , True )
  if 81 - 81: iIii1I11I1II1 + iIii1I11I1II1
 elif ( I11IIIIiII . type == LISP_NAT_INFO and I11IIIIiII . is_info_reply ( ) == False ) :
  i111I11I = source . print_address_no_iid ( )
  lisp_process_info_request ( lisp_sockets , packet , i111I11I , udp_sport ,
 None )
  if 19 - 19: ooOoO0o + i1IIi / Oo0Ooo * II111iiii * I1Ii111 / ooOoO0o
 elif ( I11IIIIiII . type == LISP_ECM ) :
  lisp_process_ecm ( lisp_sockets , packet , source , udp_sport )
  if 23 - 23: I1Ii111
 else :
  lprint ( "Invalid LISP control packet type {}" . format ( I11IIIIiII . type ) )
  if 76 - 76: Ii1I + Ii1I / i1IIi % o0oOOo0O0Ooo . iIii1I11I1II1 . OoOoOO00
 return ( iii1IiiI1iiIi )
 if 75 - 75: I11i . Ii1I / I1ii11iIi11i
 if 99 - 99: Ii1I
 if 85 - 85: I1Ii111 + I1Ii111 + OoOoOO00 / ooOoO0o / o0oOOo0O0Ooo . Oo0Ooo
 if 41 - 41: i1IIi % Ii1I . i1IIi * OoooooooOO % Ii1I
 if 21 - 21: iII111i
 if 72 - 72: I11i % o0oOOo0O0Ooo . iIii1I11I1II1 - I1Ii111 / i11iIiiIii
 if 75 - 75: OoooooooOO
def lisp_process_rloc_probe_request ( lisp_sockets , map_request , source , port ,
 ttl ) :
 if 24 - 24: oO0o % iII111i - II111iiii / Ii1I + O0
 IiIiI1 = bold ( "RLOC-probe" , False )
 if 37 - 37: I1Ii111 - i1IIi / iIii1I11I1II1
 if ( lisp_i_am_etr ) :
  lprint ( "Received {} Map-Request, send RLOC-probe Map-Reply" . format ( IiIiI1 ) )
  lisp_etr_process_map_request ( lisp_sockets , map_request , source , port ,
 ttl )
  return
  if 53 - 53: Ii1I - iIii1I11I1II1 % I1ii11iIi11i * i11iIiiIii + ooOoO0o
  if 63 - 63: Oo0Ooo * I1IiiI
 if ( lisp_i_am_rtr ) :
  lprint ( "Received {} Map-Request, send RLOC-probe Map-Reply" . format ( IiIiI1 ) )
  lisp_rtr_process_map_request ( lisp_sockets , map_request , source , port ,
 ttl )
  return
  if 84 - 84: Oo0Ooo
  if 67 - 67: oO0o / II111iiii . I11i / oO0o
 lprint ( "Ignoring received {} Map-Request, not an ETR or RTR" . format ( IiIiI1 ) )
 return
 if 46 - 46: oO0o * Oo0Ooo - I11i / iIii1I11I1II1
 if 100 - 100: i11iIiiIii % oO0o
 if 62 - 62: OOooOOo * i1IIi - OOooOOo / i11iIiiIii
 if 17 - 17: I1ii11iIi11i + ooOoO0o % Ii1I % OOooOOo
 if 73 - 73: i11iIiiIii
def lisp_process_smr ( map_request ) :
 lprint ( "Received SMR-based Map-Request" )
 return
 if 44 - 44: o0oOOo0O0Ooo % Ii1I - OoOoOO00 + OoOoOO00 * IiII + iII111i
 if 58 - 58: I1ii11iIi11i / oO0o + i11iIiiIii * o0oOOo0O0Ooo
 if 19 - 19: OoOoOO00
 if 17 - 17: Oo0Ooo
 if 76 - 76: II111iiii % I1ii11iIi11i
def lisp_process_smr_invoked_request ( map_request ) :
 lprint ( "Received SMR-invoked Map-Request" )
 return
 if 99 - 99: oO0o - I1Ii111
 if 29 - 29: I1IiiI - I11i
 if 42 - 42: Oo0Ooo - O0 . OoOoOO00
 if 4 - 4: IiII
 if 2 - 2: iII111i
 if 47 - 47: i1IIi % I11i
 if 17 - 17: OoOoOO00 - iII111i % I11i / o0oOOo0O0Ooo / II111iiii
def lisp_build_map_reply ( eid , group , rloc_set , nonce , action , ttl , rloc_probe ,
 keys , enc , auth , mr_ttl = - 1 ) :
 II1IiiI = lisp_map_reply ( )
 II1IiiI . rloc_probe = rloc_probe
 II1IiiI . echo_nonce_capable = enc
 II1IiiI . hop_count = 0 if ( mr_ttl == - 1 ) else mr_ttl
 II1IiiI . record_count = 1
 II1IiiI . nonce = nonce
 Ii11iIiiI = II1IiiI . encode ( )
 II1IiiI . print_map_reply ( )
 if 44 - 44: I11i % IiII / I1IiiI . OoO0O00 * Ii1I
 OOOO = lisp_eid_record ( )
 OOOO . rloc_count = len ( rloc_set )
 OOOO . authoritative = auth
 OOOO . record_ttl = ttl
 OOOO . action = action
 OOOO . eid = eid
 OOOO . group = group
 if 94 - 94: ooOoO0o
 Ii11iIiiI += OOOO . encode ( )
 OOOO . print_record ( "  " , False )
 if 80 - 80: i11iIiiIii - O0 / I1Ii111 + OOooOOo % Oo0Ooo
 o000O = lisp_get_all_addresses ( ) + lisp_get_all_translated_rlocs ( )
 if 97 - 97: OoOoOO00 / ooOoO0o / OoO0O00 / O0 - IiII % I11i
 for IiIiI in rloc_set :
  OO0OoOo = lisp_rloc_record ( )
  i111I11I = IiIiI . rloc . print_address_no_iid ( )
  if ( i111I11I in o000O ) :
   OO0OoOo . local_bit = True
   OO0OoOo . probe_bit = rloc_probe
   OO0OoOo . keys = keys
   if ( IiIiI . priority == 254 and lisp_i_am_rtr ) :
    OO0OoOo . rloc_name = "RTR"
    if 27 - 27: iII111i
    if 51 - 51: Oo0Ooo - O0 % o0oOOo0O0Ooo / I1ii11iIi11i
  OO0OoOo . store_rloc_entry ( IiIiI )
  OO0OoOo . reach_bit = True
  OO0OoOo . print_record ( "    " )
  Ii11iIiiI += OO0OoOo . encode ( )
  if 60 - 60: iII111i / OoooooooOO * II111iiii * Oo0Ooo * o0oOOo0O0Ooo
 return ( Ii11iIiiI )
 if 60 - 60: iII111i . OOooOOo
 if 39 - 39: O0 - i11iIiiIii - I1IiiI / Oo0Ooo - i11iIiiIii
 if 30 - 30: OoO0O00 / OoOoOO00 + I1ii11iIi11i % IiII - OoO0O00
 if 19 - 19: I1IiiI
 if 99 - 99: OOooOOo - OOooOOo
 if 98 - 98: o0oOOo0O0Ooo + O0 * oO0o - i11iIiiIii
 if 83 - 83: o0oOOo0O0Ooo
def lisp_build_map_referral ( eid , group , ddt_entry , action , ttl , nonce ) :
 iI1oOoo0oO0oOo = lisp_map_referral ( )
 iI1oOoo0oO0oOo . record_count = 1
 iI1oOoo0oO0oOo . nonce = nonce
 Ii11iIiiI = iI1oOoo0oO0oOo . encode ( )
 iI1oOoo0oO0oOo . print_map_referral ( )
 if 88 - 88: OoooooooOO
 OOOO = lisp_eid_record ( )
 if 30 - 30: ooOoO0o + Oo0Ooo . O0
 OoOo0O0OO = 0
 if ( ddt_entry == None ) :
  OOOO . eid = eid
  OOOO . group = group
 else :
  OoOo0O0OO = len ( ddt_entry . delegation_set )
  OOOO . eid = ddt_entry . eid
  OOOO . group = ddt_entry . group
  ddt_entry . map_referrals_sent += 1
  if 68 - 68: iII111i - o0oOOo0O0Ooo - OoO0O00 . O0 - i11iIiiIii
 OOOO . rloc_count = OoOo0O0OO
 OOOO . authoritative = True
 if 2 - 2: I1ii11iIi11i * i1IIi
 if 17 - 17: I1ii11iIi11i * Ii1I % Oo0Ooo * I1Ii111 + OoO0O00 . OoooooooOO
 if 60 - 60: Ii1I . II111iiii
 if 36 - 36: IiII . iII111i * O0 . i1IIi * O0 * I1Ii111
 if 50 - 50: OoooooooOO + o0oOOo0O0Ooo + iIii1I11I1II1 + OOooOOo
 Ooooo0OO000o0 = False
 if ( action == LISP_DDT_ACTION_NULL ) :
  if ( OoOo0O0OO == 0 ) :
   action = LISP_DDT_ACTION_NODE_REFERRAL
  else :
   iIiOoo0 = ddt_entry . delegation_set [ 0 ]
   if ( iIiOoo0 . is_ddt_child ( ) ) :
    action = LISP_DDT_ACTION_NODE_REFERRAL
    if 90 - 90: Ii1I * I11i % I1Ii111 - I1ii11iIi11i * I1Ii111 % OoO0O00
   if ( iIiOoo0 . is_ms_child ( ) ) :
    action = LISP_DDT_ACTION_MS_REFERRAL
    if 50 - 50: iIii1I11I1II1
    if 56 - 56: oO0o
    if 55 - 55: iIii1I11I1II1 % oO0o % OOooOOo / I1Ii111 * OoooooooOO / Oo0Ooo
    if 88 - 88: I11i + OoO0O00 . iIii1I11I1II1 . II111iiii
    if 67 - 67: OOooOOo - ooOoO0o % iII111i % IiII
    if 71 - 71: OoO0O00 - ooOoO0o - I1IiiI + O0
    if 15 - 15: i1IIi
 if ( action == LISP_DDT_ACTION_NOT_AUTH ) : Ooooo0OO000o0 = True
 if ( action in ( LISP_DDT_ACTION_MS_REFERRAL , LISP_DDT_ACTION_MS_ACK ) ) :
  Ooooo0OO000o0 = ( lisp_i_am_ms and iIiOoo0 . is_ms_peer ( ) == False )
  if 43 - 43: II111iiii + OOooOOo . i11iIiiIii - II111iiii
  if 80 - 80: o0oOOo0O0Ooo . oO0o . I1Ii111
 OOOO . action = action
 OOOO . ddt_incomplete = Ooooo0OO000o0
 OOOO . record_ttl = ttl
 if 26 - 26: i1IIi - I1IiiI + IiII / OoO0O00 . I1ii11iIi11i
 Ii11iIiiI += OOOO . encode ( )
 OOOO . print_record ( "  " , True )
 if 82 - 82: I1Ii111 % iII111i . OoOoOO00 % OoO0O00 + I1ii11iIi11i
 if ( OoOo0O0OO == 0 ) : return ( Ii11iIiiI )
 if 69 - 69: I1IiiI * OoOoOO00 - ooOoO0o . O0
 for iIiOoo0 in ddt_entry . delegation_set :
  OO0OoOo = lisp_rloc_record ( )
  OO0OoOo . rloc = iIiOoo0 . delegate_address
  OO0OoOo . priority = iIiOoo0 . priority
  OO0OoOo . weight = iIiOoo0 . weight
  OO0OoOo . mpriority = 255
  OO0OoOo . mweight = 0
  OO0OoOo . reach_bit = True
  Ii11iIiiI += OO0OoOo . encode ( )
  OO0OoOo . print_record ( "    " )
  if 15 - 15: oO0o . IiII + I1Ii111 - OoooooooOO
 return ( Ii11iIiiI )
 if 85 - 85: II111iiii - Oo0Ooo + oO0o . i11iIiiIii + Oo0Ooo
 if 86 - 86: ooOoO0o . OoO0O00
 if 47 - 47: IiII % I1IiiI
 if 91 - 91: Ii1I
 if 69 - 69: iII111i
 if 96 - 96: Ii1I
 if 39 - 39: OoO0O00 - I1IiiI % II111iiii - IiII * I1ii11iIi11i
def lisp_etr_process_map_request ( lisp_sockets , map_request , source , sport ,
 ttl ) :
 if 64 - 64: OOooOOo + Oo0Ooo . OoOoOO00 . OOooOOo + i11iIiiIii
 if ( map_request . target_group . is_null ( ) ) :
  i1i1iiiii1IiI = lisp_db_for_lookups . lookup_cache ( map_request . target_eid , False )
 else :
  i1i1iiiii1IiI = lisp_db_for_lookups . lookup_cache ( map_request . target_group , False )
  if ( i1i1iiiii1IiI ) : i1i1iiiii1IiI = i1i1iiiii1IiI . lookup_source_cache ( map_request . target_eid , False )
  if 75 - 75: oO0o - OoOoOO00 * ooOoO0o . O0
 O0o0O0OO0o = map_request . print_prefix ( )
 if 78 - 78: Oo0Ooo
 if ( i1i1iiiii1IiI == None ) :
  lprint ( "Database-mapping entry not found for requested EID {}" . format ( green ( O0o0O0OO0o , False ) ) )
  if 74 - 74: O0 / I11i
  return
  if 52 - 52: I1IiiI + oO0o * II111iiii
  if 15 - 15: I11i
 oo0i11i11ii11 = i1i1iiiii1IiI . print_eid_tuple ( )
 if 49 - 49: iII111i % OoooooooOO
 lprint ( "Found database-mapping EID-prefix {} for requested EID {}" . format ( green ( oo0i11i11ii11 , False ) , green ( O0o0O0OO0o , False ) ) )
 if 85 - 85: I1ii11iIi11i * OOooOOo - I1IiiI
 if 76 - 76: iIii1I11I1II1
 if 94 - 94: O0
 if 50 - 50: I1Ii111 * o0oOOo0O0Ooo - ooOoO0o - I1ii11iIi11i % I1IiiI . ooOoO0o
 if 35 - 35: Ii1I % i1IIi + I1IiiI
 o0OooOo000oo0ooooO = map_request . itr_rlocs [ 0 ]
 if ( o0OooOo000oo0ooooO . is_private_address ( ) and lisp_nat_traversal ) :
  o0OooOo000oo0ooooO = source
  if 53 - 53: i11iIiiIii / i1IIi . i1IIi + I11i
  if 19 - 19: ooOoO0o . OoOoOO00 + Oo0Ooo + iIii1I11I1II1 . OoOoOO00 - I1IiiI
 i11IIoOOoOo0Ooo = map_request . nonce
 OOi111 = lisp_nonce_echoing
 i11i1ii11Ii1 = map_request . keys
 if 40 - 40: Oo0Ooo / iIii1I11I1II1 % iIii1I11I1II1
 i1i1iiiii1IiI . map_replies_sent += 1
 if 66 - 66: iII111i
 Ii11iIiiI = lisp_build_map_reply ( i1i1iiiii1IiI . eid , i1i1iiiii1IiI . group , i1i1iiiii1IiI . rloc_set , i11IIoOOoOo0Ooo ,
 LISP_NO_ACTION , 1440 , map_request . rloc_probe , i11i1ii11Ii1 , OOi111 , True , ttl )
 if 72 - 72: ooOoO0o / oO0o / iII111i . I1Ii111 . I1ii11iIi11i + IiII
 if 39 - 39: I1IiiI % I1Ii111
 if 22 - 22: OoOoOO00 - OOooOOo % i1IIi + i1IIi
 if 28 - 28: oO0o + OoOoOO00 * Ii1I . I11i
 if 80 - 80: I1ii11iIi11i / OoOoOO00
 if 74 - 74: I1ii11iIi11i + O0 + o0oOOo0O0Ooo - iII111i
 if 48 - 48: ooOoO0o * iIii1I11I1II1 % Oo0Ooo
 if 60 - 60: OoOoOO00 / i1IIi * iIii1I11I1II1
 if 91 - 91: I1Ii111 . OoooooooOO / IiII / I1IiiI
 if 56 - 56: II111iiii + iIii1I11I1II1 / I1Ii111 / I1Ii111 % Oo0Ooo / OoOoOO00
 if 46 - 46: i11iIiiIii + OoO0O00 . ooOoO0o + OoO0O00 % i11iIiiIii
 if 97 - 97: OoooooooOO % IiII * iIii1I11I1II1
 if 97 - 97: iIii1I11I1II1 - I1Ii111 - o0oOOo0O0Ooo * o0oOOo0O0Ooo * OoOoOO00
 if 80 - 80: II111iiii . I1ii11iIi11i % i11iIiiIii / Ii1I / oO0o
 if 100 - 100: Ii1I . OoO0O00 * ooOoO0o
 if 4 - 4: i1IIi + OoooooooOO
 if ( map_request . rloc_probe and len ( lisp_sockets ) == 4 ) :
  ooOO0o = ( o0OooOo000oo0ooooO . is_private_address ( ) == False )
  o0O000o0o0 = o0OooOo000oo0ooooO . print_address_no_iid ( )
  if ( ( ooOO0o and lisp_rtr_list . has_key ( o0O000o0o0 ) ) or sport == 0 ) :
   lisp_encapsulate_rloc_probe ( lisp_sockets , o0OooOo000oo0ooooO , None , Ii11iIiiI )
   return
   if 26 - 26: I1IiiI / II111iiii % I1ii11iIi11i * o0oOOo0O0Ooo . IiII / OoO0O00
   if 10 - 10: i11iIiiIii / i1IIi + O0 - i11iIiiIii % I11i - i1IIi
   if 38 - 38: O0 - I1IiiI + Oo0Ooo + ooOoO0o
   if 56 - 56: I1Ii111 + oO0o / Ii1I + I1Ii111
   if 21 - 21: OOooOOo / OoOoOO00 + OoOoOO00 + OoOoOO00 - i1IIi + Ii1I
   if 43 - 43: O0 % II111iiii
 lisp_send_map_reply ( lisp_sockets , Ii11iIiiI , o0OooOo000oo0ooooO , sport )
 return
 if 60 - 60: iII111i / ooOoO0o - Ii1I - OoooooooOO
 if 79 - 79: oO0o / iII111i . iIii1I11I1II1 * i11iIiiIii * i1IIi . iIii1I11I1II1
 if 31 - 31: OoooooooOO / ooOoO0o / OoooooooOO + ooOoO0o . O0 - IiII
 if 53 - 53: Oo0Ooo % iII111i % iII111i
 if 71 - 71: iII111i
 if 99 - 99: O0 - OoOoOO00 * I1Ii111 - Oo0Ooo
 if 62 - 62: i1IIi + ooOoO0o + Oo0Ooo - i11iIiiIii
def lisp_rtr_process_map_request ( lisp_sockets , map_request , source , sport ,
 ttl ) :
 if 19 - 19: I1IiiI / OOooOOo
 if 6 - 6: I1ii11iIi11i + IiII * oO0o * OoOoOO00
 if 67 - 67: I1Ii111 + OoooooooOO + OoOoOO00 % iIii1I11I1II1 . I1IiiI
 if 68 - 68: ooOoO0o
 o0OooOo000oo0ooooO = map_request . itr_rlocs [ 0 ]
 if ( o0OooOo000oo0ooooO . is_private_address ( ) ) : o0OooOo000oo0ooooO = source
 i11IIoOOoOo0Ooo = map_request . nonce
 if 68 - 68: I11i % IiII
 ii1Ii = map_request . target_eid
 IiI1111i1i11I = map_request . target_group
 if 1 - 1: I1IiiI + OOooOOo - OOooOOo * O0 + o0oOOo0O0Ooo * OOooOOo
 I1I11I11 = [ ]
 for OoOooO in [ lisp_myrlocs [ 0 ] , lisp_myrlocs [ 1 ] ] :
  if ( OoOooO == None ) : continue
  II11IIiii = lisp_rloc ( )
  II11IIiii . rloc . copy_address ( OoOooO )
  II11IIiii . priority = 254
  I1I11I11 . append ( II11IIiii )
  if 84 - 84: Ii1I * Oo0Ooo + II111iiii * I1IiiI
  if 45 - 45: II111iiii + II111iiii - O0 + oO0o + I11i
 OOi111 = lisp_nonce_echoing
 i11i1ii11Ii1 = map_request . keys
 if 28 - 28: I1IiiI / oO0o . II111iiii
 Ii11iIiiI = lisp_build_map_reply ( ii1Ii , IiI1111i1i11I , I1I11I11 , i11IIoOOoOo0Ooo , LISP_NO_ACTION ,
 1440 , True , i11i1ii11Ii1 , OOi111 , True , ttl )
 lisp_send_map_reply ( lisp_sockets , Ii11iIiiI , o0OooOo000oo0ooooO , sport )
 return
 if 78 - 78: oO0o + i11iIiiIii
 if 73 - 73: oO0o % i1IIi / I1IiiI - OoO0O00 . iII111i
 if 28 - 28: ooOoO0o . Oo0Ooo - OoooooooOO - I1Ii111 - OoooooooOO - oO0o
 if 25 - 25: I11i / I1Ii111 . i11iIiiIii % i1IIi
 if 21 - 21: O0 * IiII . iII111i / iII111i % i11iIiiIii / I11i
 if 15 - 15: o0oOOo0O0Ooo / OoO0O00 - i1IIi
 if 30 - 30: OoO0O00 / ooOoO0o % ooOoO0o
 if 40 - 40: i1IIi . iIii1I11I1II1 * OoOoOO00
 if 83 - 83: iIii1I11I1II1 + Ii1I - Ii1I % II111iiii
 if 82 - 82: O0
def lisp_get_private_rloc_set ( target_site_eid , seid , group ) :
 I1I11I11 = target_site_eid . registered_rlocs
 if 18 - 18: iII111i . IiII . I1IiiI
 I1IIi = lisp_site_eid_lookup ( seid , group , False )
 if ( I1IIi == None ) : return ( I1I11I11 )
 if 20 - 20: OoO0O00 * II111iiii
 if 22 - 22: Oo0Ooo * I11i
 if 48 - 48: i11iIiiIii * I1IiiI % oO0o % OoooooooOO
 if 4 - 4: OoO0O00 . I1IiiI - O0 % iII111i . OOooOOo
 oo0iiiI = None
 Ii1111iI = [ ]
 for IiIiI in I1I11I11 :
  if ( IiIiI . is_rtr ( ) ) : continue
  if ( IiIiI . rloc . is_private_address ( ) ) :
   oO0Ooo0OOooO = copy . deepcopy ( IiIiI )
   Ii1111iI . append ( oO0Ooo0OOooO )
   continue
   if 5 - 5: OoOoOO00
  oo0iiiI = IiIiI
  break
  if 21 - 21: OoO0O00 - o0oOOo0O0Ooo % i11iIiiIii / II111iiii
 if ( oo0iiiI == None ) : return ( I1I11I11 )
 oo0iiiI = oo0iiiI . rloc . print_address_no_iid ( )
 if 85 - 85: I1Ii111 / II111iiii / OOooOOo
 if 87 - 87: OoOoOO00 - oO0o - IiII / iII111i - OOooOOo / Oo0Ooo
 if 99 - 99: OoO0O00 * I11i
 if 33 - 33: I1Ii111 % IiII * OOooOOo - I1Ii111
 O0oOo0OOOo0 = None
 for IiIiI in I1IIi . registered_rlocs :
  if ( IiIiI . is_rtr ( ) ) : continue
  if ( IiIiI . rloc . is_private_address ( ) ) : continue
  O0oOo0OOOo0 = IiIiI
  break
  if 16 - 16: IiII - I1ii11iIi11i - Oo0Ooo - ooOoO0o / OoooooooOO % i1IIi
 if ( O0oOo0OOOo0 == None ) : return ( I1I11I11 )
 O0oOo0OOOo0 = O0oOo0OOOo0 . rloc . print_address_no_iid ( )
 if 85 - 85: i11iIiiIii / OoO0O00 / oO0o
 if 12 - 12: iII111i % OOooOOo % i1IIi
 if 17 - 17: IiII
 if 63 - 63: ooOoO0o . i11iIiiIii / iIii1I11I1II1
 IiIIIii1iIII1 = target_site_eid . site_id
 if ( IiIIIii1iIII1 == 0 ) :
  if ( O0oOo0OOOo0 == oo0iiiI ) :
   lprint ( "Return private RLOCs for sites behind {}" . format ( oo0iiiI ) )
   if 8 - 8: i11iIiiIii . IiII * iIii1I11I1II1 * I1IiiI * Ii1I * i11iIiiIii
   return ( Ii1111iI )
   if 24 - 24: I1IiiI * I11i - o0oOOo0O0Ooo / iII111i + IiII - I1ii11iIi11i
  return ( I1I11I11 )
  if 53 - 53: I11i / I1IiiI - iIii1I11I1II1 - o0oOOo0O0Ooo * OoOoOO00
  if 86 - 86: iIii1I11I1II1 - I1Ii111
  if 86 - 86: O0 * IiII + OoOoOO00 + OoO0O00
  if 53 - 53: I1IiiI % i11iIiiIii + o0oOOo0O0Ooo . I1ii11iIi11i
  if 73 - 73: iII111i - o0oOOo0O0Ooo / OOooOOo + iII111i + o0oOOo0O0Ooo % II111iiii
  if 74 - 74: I11i * iIii1I11I1II1 - OoO0O00 / i1IIi / OoO0O00 / IiII
  if 60 - 60: oO0o % I1Ii111 % Oo0Ooo
 if ( IiIIIii1iIII1 == I1IIi . site_id ) :
  lprint ( "Return private RLOCs for sites in site-id {}" . format ( IiIIIii1iIII1 ) )
  return ( Ii1111iI )
  if 34 - 34: o0oOOo0O0Ooo * OOooOOo % Ii1I + I1IiiI
 return ( I1I11I11 )
 if 77 - 77: OoOoOO00 + IiII + Oo0Ooo
 if 88 - 88: i1IIi
 if 45 - 45: iII111i % I1ii11iIi11i / i11iIiiIii - II111iiii . Oo0Ooo / ooOoO0o
 if 55 - 55: OoO0O00 % IiII
 if 93 - 93: OoO0O00 . I1ii11iIi11i / OOooOOo % OoooooooOO + i1IIi + I1Ii111
 if 94 - 94: II111iiii + i11iIiiIii % Ii1I / ooOoO0o * OoOoOO00
 if 68 - 68: O0 / Oo0Ooo / iIii1I11I1II1
 if 63 - 63: I1Ii111 + iII111i
 if 6 - 6: I1ii11iIi11i + Ii1I
def lisp_get_partial_rloc_set ( registered_rloc_set , mr_source , multicast ) :
 I1111I = [ ]
 I1I11I11 = [ ]
 if 56 - 56: Oo0Ooo / OOooOOo * IiII % o0oOOo0O0Ooo + Ii1I - Oo0Ooo
 if 1 - 1: O0 % Ii1I - i1IIi . Oo0Ooo + OoOoOO00 / I1IiiI
 if 16 - 16: I1ii11iIi11i - I1ii11iIi11i / Ii1I * oO0o
 if 97 - 97: OoO0O00 % ooOoO0o - ooOoO0o * oO0o - O0 . Oo0Ooo
 if 80 - 80: O0 - i1IIi + OoO0O00 . i11iIiiIii
 if 62 - 62: i1IIi % i1IIi
 ooo0oOOoO = False
 OOo0O0OOO = False
 for IiIiI in registered_rloc_set :
  if ( IiIiI . priority != 254 ) : continue
  OOo0O0OOO |= True
  if ( IiIiI . rloc . is_exact_match ( mr_source ) == False ) : continue
  ooo0oOOoO = True
  break
  if 75 - 75: iIii1I11I1II1 * i11iIiiIii
  if 24 - 24: II111iiii . OoO0O00 % II111iiii / I11i
  if 42 - 42: OoOoOO00 . I1ii11iIi11i
  if 77 - 77: I1ii11iIi11i % i1IIi + OOooOOo - OOooOOo - o0oOOo0O0Ooo
  if 45 - 45: I1ii11iIi11i / o0oOOo0O0Ooo / I1IiiI - Oo0Ooo * ooOoO0o - I1ii11iIi11i
  if 71 - 71: I1IiiI % OoO0O00
  if 32 - 32: oO0o
 if ( OOo0O0OOO == False ) : return ( registered_rloc_set )
 if 2 - 2: Oo0Ooo
 if 80 - 80: I1Ii111 * II111iiii % Oo0Ooo * ooOoO0o + o0oOOo0O0Ooo
 if 96 - 96: ooOoO0o
 if 19 - 19: Ii1I
 if 15 - 15: ooOoO0o - II111iiii - iIii1I11I1II1 - I1Ii111
 if 23 - 23: I1ii11iIi11i + II111iiii
 if 99 - 99: o0oOOo0O0Ooo . I1IiiI + o0oOOo0O0Ooo * o0oOOo0O0Ooo / O0
 if 27 - 27: OOooOOo - I1Ii111
 if 33 - 33: OOooOOo - Ii1I - iII111i + I1ii11iIi11i - i11iIiiIii
 if 89 - 89: iIii1I11I1II1 * I11i + OOooOOo
 iiIiIIi1I = ( os . getenv ( "LISP_RTR_BEHIND_NAT" ) != None )
 if 89 - 89: O0 / ooOoO0o . OoO0O00 - O0 + Oo0Ooo
 if 6 - 6: O0 - ooOoO0o
 if 35 - 35: I1IiiI . iIii1I11I1II1 + IiII / i11iIiiIii - II111iiii . OoooooooOO
 if 19 - 19: IiII - OoOoOO00
 if 43 - 43: IiII / OOooOOo % II111iiii . o0oOOo0O0Ooo / i11iIiiIii
 for IiIiI in registered_rloc_set :
  if ( iiIiIIi1I and IiIiI . rloc . is_private_address ( ) ) : continue
  if ( multicast == False and IiIiI . priority == 255 ) : continue
  if ( multicast and IiIiI . mpriority == 255 ) : continue
  if ( IiIiI . priority == 254 ) :
   I1111I . append ( IiIiI )
  else :
   I1I11I11 . append ( IiIiI )
   if 5 - 5: oO0o % iII111i . Oo0Ooo . O0 . OoOoOO00 / iII111i
   if 78 - 78: Ii1I - I1ii11iIi11i + iIii1I11I1II1 + OoooooooOO . OoO0O00 - ooOoO0o
   if 81 - 81: o0oOOo0O0Ooo * OoooooooOO
   if 32 - 32: OoOoOO00 - I11i * i11iIiiIii . I1ii11iIi11i . IiII . iIii1I11I1II1
   if 41 - 41: iII111i / OoOoOO00 / OoO0O00 / ooOoO0o
   if 16 - 16: iIii1I11I1II1 . II111iiii
 if ( ooo0oOOoO ) : return ( I1I11I11 )
 if 80 - 80: Oo0Ooo + IiII
 if 18 - 18: OoO0O00 . Oo0Ooo
 if 52 - 52: OoOoOO00 . iIii1I11I1II1 / OoOoOO00
 if 14 - 14: i1IIi
 if 63 - 63: OoOoOO00 . i11iIiiIii / IiII
 if 36 - 36: OOooOOo * OoOoOO00 + i11iIiiIii + O0 + O0
 if 18 - 18: Oo0Ooo . I1ii11iIi11i * ooOoO0o % Ii1I + I1ii11iIi11i
 if 23 - 23: oO0o / o0oOOo0O0Ooo + I11i % IiII * OoO0O00
 if 48 - 48: OoO0O00
 if 30 - 30: iIii1I11I1II1
 I1I11I11 = [ ]
 for IiIiI in registered_rloc_set :
  if ( IiIiI . rloc . is_private_address ( ) ) : I1I11I11 . append ( IiIiI )
  if 53 - 53: II111iiii
 I1I11I11 += I1111I
 return ( I1I11I11 )
 if 40 - 40: Ii1I % oO0o
 if 69 - 69: iIii1I11I1II1 - O0 . I1Ii111 % I1IiiI / o0oOOo0O0Ooo
 if 78 - 78: oO0o
 if 20 - 20: i1IIi + i1IIi * i1IIi
 if 32 - 32: I1IiiI + IiII + iII111i . iIii1I11I1II1 * Ii1I
 if 27 - 27: oO0o + Ii1I . i11iIiiIii
 if 97 - 97: iII111i . I1IiiI
 if 71 - 71: OOooOOo - IiII % oO0o * I1ii11iIi11i
 if 48 - 48: o0oOOo0O0Ooo * iIii1I11I1II1 + Oo0Ooo
 if 45 - 45: oO0o
def lisp_store_pubsub_state ( reply_eid , itr_rloc , mr_sport , nonce , ttl , xtr_id ) :
 I1i1iiII1iI1i = lisp_pubsub ( itr_rloc , mr_sport , nonce , ttl , xtr_id )
 I1i1iiII1iI1i . add ( reply_eid )
 return
 if 72 - 72: I1ii11iIi11i
 if 100 - 100: i11iIiiIii - iII111i - I11i
 if 5 - 5: oO0o % IiII * iII111i
 if 98 - 98: iII111i / OOooOOo + IiII
 if 100 - 100: II111iiii . i11iIiiIii / oO0o - OOooOOo + OoOoOO00 % I1ii11iIi11i
 if 82 - 82: ooOoO0o % OOooOOo % Ii1I
 if 82 - 82: I1ii11iIi11i
 if 52 - 52: i11iIiiIii % I1Ii111 - iII111i / O0 - I1ii11iIi11i / iII111i
 if 7 - 7: OoooooooOO . OOooOOo . OOooOOo
 if 53 - 53: OOooOOo * OoOoOO00 % iII111i
 if 86 - 86: OOooOOo . OOooOOo + IiII - I1ii11iIi11i . OoO0O00
 if 66 - 66: I1IiiI * OoOoOO00 . I1IiiI / Oo0Ooo - Ii1I
 if 69 - 69: iIii1I11I1II1 % iII111i + ooOoO0o * i1IIi + iII111i * I1Ii111
 if 67 - 67: Ii1I % Oo0Ooo - Oo0Ooo . I11i + IiII
 if 73 - 73: Oo0Ooo + iIii1I11I1II1 . iIii1I11I1II1
def lisp_convert_reply_to_notify ( packet ) :
 if 73 - 73: ooOoO0o + OoOoOO00
 if 61 - 61: I1Ii111 * I1Ii111 % OOooOOo
 if 31 - 31: oO0o + Ii1I - iIii1I11I1II1 / i11iIiiIii
 if 9 - 9: IiII % OoO0O00
 oooOOoO0oo0 = struct . unpack ( "I" , packet [ 0 : 4 ] ) [ 0 ]
 oooOOoO0oo0 = socket . ntohl ( oooOOoO0oo0 ) & 0xff
 i11IIoOOoOo0Ooo = packet [ 4 : 12 ]
 packet = packet [ 12 : : ]
 if 48 - 48: Oo0Ooo / iIii1I11I1II1
 if 80 - 80: i1IIi + I1IiiI / OoooooooOO + OOooOOo . Ii1I
 if 96 - 96: iIii1I11I1II1 - I1ii11iIi11i
 if 41 - 41: II111iiii - OoOoOO00 + OoooooooOO - I1ii11iIi11i . oO0o . o0oOOo0O0Ooo
 Ii1i111iI = ( LISP_MAP_NOTIFY << 28 ) | oooOOoO0oo0
 I11IIIIiII = struct . pack ( "I" , socket . htonl ( Ii1i111iI ) )
 IIiIIIII1I = struct . pack ( "I" , 0 )
 if 34 - 34: I1ii11iIi11i % I11i / Oo0Ooo * oO0o % ooOoO0o / OOooOOo
 if 50 - 50: O0 * O0 / iIii1I11I1II1
 if 31 - 31: I1IiiI / o0oOOo0O0Ooo
 if 70 - 70: I1IiiI
 packet = I11IIIIiII + i11IIoOOoOo0Ooo + IIiIIIII1I + packet
 return ( packet )
 if 36 - 36: ooOoO0o . oO0o . I11i - I1ii11iIi11i / OoOoOO00 * Oo0Ooo
 if 42 - 42: OoooooooOO / o0oOOo0O0Ooo . Ii1I * iII111i * I1IiiI - Oo0Ooo
 if 76 - 76: oO0o * II111iiii
 if 81 - 81: I11i
 if 2 - 2: OoOoOO00
 if 75 - 75: I1IiiI - OoooooooOO * I1Ii111
 if 1 - 1: o0oOOo0O0Ooo % oO0o * I1Ii111 - i1IIi - iII111i . oO0o
 if 25 - 25: i1IIi * o0oOOo0O0Ooo / oO0o
def lisp_notify_subscribers ( lisp_sockets , eid_record , eid , site ) :
 O0o0O0OO0o = eid . print_prefix ( )
 if ( lisp_pubsub_cache . has_key ( O0o0O0OO0o ) == False ) : return
 if 11 - 11: IiII + II111iiii
 for I1i1iiII1iI1i in lisp_pubsub_cache [ O0o0O0OO0o ] . values ( ) :
  oo0Oo0oo = I1i1iiII1iI1i . itr
  IIIIiI1ii1 = I1i1iiII1iI1i . port
  i1I = red ( oo0Oo0oo . print_address_no_iid ( ) , False )
  Oo0 = bold ( "subscriber" , False )
  iIi = "0x" + lisp_hex_string ( I1i1iiII1iI1i . xtr_id )
  i11IIoOOoOo0Ooo = "0x" + lisp_hex_string ( I1i1iiII1iI1i . nonce )
  if 34 - 34: OoooooooOO + I1Ii111
  lprint ( "    Notify {} {}:{} xtr-id {} for {}, nonce {}" . format ( Oo0 , i1I , IIIIiI1ii1 , iIi , green ( O0o0O0OO0o , False ) , i11IIoOOoOo0Ooo ) )
  if 97 - 97: II111iiii + I11i + OOooOOo / i11iIiiIii - iII111i
  if 9 - 9: i1IIi - I1Ii111 + I1Ii111
  lisp_build_map_notify ( lisp_sockets , eid_record , [ O0o0O0OO0o ] , 1 , oo0Oo0oo ,
 IIIIiI1ii1 , I1i1iiII1iI1i . nonce , 0 , 0 , 0 , site , False )
  I1i1iiII1iI1i . map_notify_count += 1
  if 81 - 81: II111iiii % I11i % O0 . I1Ii111 % ooOoO0o - O0
 return
 if 58 - 58: OoooooooOO . II111iiii . O0 % I1Ii111 / OoooooooOO
 if 64 - 64: Oo0Ooo + oO0o . OoO0O00
 if 67 - 67: I11i
 if 91 - 91: OOooOOo / OoO0O00
 if 36 - 36: I1IiiI . iII111i * I1Ii111 . IiII % I1ii11iIi11i
 if 44 - 44: I11i % I1ii11iIi11i - OoooooooOO % iII111i
 if 60 - 60: IiII % oO0o
def lisp_process_pubsub ( lisp_sockets , packet , reply_eid , itr_rloc , port , nonce ,
 ttl , xtr_id ) :
 if 11 - 11: I1Ii111 - II111iiii
 if 12 - 12: i11iIiiIii
 if 9 - 9: OOooOOo * I1ii11iIi11i + iIii1I11I1II1 / OoO0O00 * OoooooooOO
 if 91 - 91: i11iIiiIii % IiII + oO0o . I1IiiI - I1IiiI
 lisp_store_pubsub_state ( reply_eid , itr_rloc , port , nonce , ttl , xtr_id )
 if 62 - 62: Oo0Ooo * II111iiii + o0oOOo0O0Ooo . OoOoOO00
 ii1Ii = green ( reply_eid . print_prefix ( ) , False )
 oo0Oo0oo = red ( itr_rloc . print_address_no_iid ( ) , False )
 OO0o = bold ( "Map-Notify" , False )
 xtr_id = "0x" + lisp_hex_string ( xtr_id )
 lprint ( "{} pubsub request for {} to ack ITR {} xtr-id: {}" . format ( OO0o ,
 ii1Ii , oo0Oo0oo , xtr_id ) )
 if 61 - 61: OoO0O00
 if 96 - 96: ooOoO0o - OoooooooOO * iIii1I11I1II1 . IiII - O0
 if 7 - 7: iIii1I11I1II1 . OoO0O00
 if 88 - 88: i1IIi * II111iiii / i11iIiiIii % IiII . IiII
 packet = lisp_convert_reply_to_notify ( packet )
 lisp_send_map_notify ( lisp_sockets , packet , itr_rloc , port )
 return
 if 93 - 93: OoOoOO00 * i1IIi . Ii1I
 if 2 - 2: i1IIi
 if 84 - 84: i1IIi / Ii1I + OoOoOO00 % Ii1I . oO0o
 if 74 - 74: OOooOOo - o0oOOo0O0Ooo - I1Ii111 - OoO0O00
 if 40 - 40: o0oOOo0O0Ooo . IiII * OoOoOO00
 if 14 - 14: OOooOOo
 if 18 - 18: i11iIiiIii % iII111i
 if 70 - 70: O0 + iII111i % I11i % I1Ii111 + OoOoOO00 / ooOoO0o
def lisp_ms_process_map_request ( lisp_sockets , packet , map_request , mr_source ,
 mr_sport , ecm_source ) :
 if 35 - 35: IiII + OoO0O00
 if 82 - 82: i1IIi - ooOoO0o / I11i + I11i % I1IiiI - OoooooooOO
 if 56 - 56: I1ii11iIi11i
 if 80 - 80: Oo0Ooo / OOooOOo / iII111i . o0oOOo0O0Ooo
 if 43 - 43: IiII
 if 74 - 74: OoooooooOO
 ii1Ii = map_request . target_eid
 IiI1111i1i11I = map_request . target_group
 O0o0O0OO0o = lisp_print_eid_tuple ( ii1Ii , IiI1111i1i11I )
 o0OooOo000oo0ooooO = map_request . itr_rlocs [ 0 ]
 iIi = map_request . xtr_id
 i11IIoOOoOo0Ooo = map_request . nonce
 i11IIiI = LISP_NO_ACTION
 I1i1iiII1iI1i = map_request . subscribe_bit
 if 88 - 88: Ii1I * o0oOOo0O0Ooo / oO0o
 if 58 - 58: O0
 if 43 - 43: O0 / i1IIi / I11i % I1IiiI
 if 82 - 82: i11iIiiIii * i11iIiiIii + I1Ii111 - I1ii11iIi11i * oO0o - Ii1I
 if 40 - 40: o0oOOo0O0Ooo + OoO0O00 % i1IIi % iII111i * I1Ii111
 II1ii1IIi1i = True
 iioo00oOOO00 = ( lisp_get_eid_hash ( ii1Ii ) != None )
 if ( iioo00oOOO00 ) :
  IIIIi1I = map_request . map_request_signature
  if ( IIIIi1I == None ) :
   II1ii1IIi1i = False
   lprint ( ( "EID-crypto-hash signature verification {}, " + "no signature found" ) . format ( bold ( "failed" , False ) ) )
   if 81 - 81: Oo0Ooo + I1Ii111 - I1IiiI
  else :
   O000o0O0 = map_request . signature_eid
   i11i , i11I1i111i , II1ii1IIi1i = lisp_lookup_public_key ( O000o0O0 )
   if ( II1ii1IIi1i ) :
    II1ii1IIi1i = map_request . verify_map_request_sig ( i11I1i111i )
   else :
    lprint ( "Public-key lookup failed for sig-eid {}, hash-eid {}" . format ( O000o0O0 . print_address ( ) , i11i . print_address ( ) ) )
    if 64 - 64: O0 . Ii1I . oO0o - I11i
    if 76 - 76: OOooOOo * IiII % I1IiiI
   IiO0O0oo0 = bold ( "passed" , False ) if II1ii1IIi1i else bold ( "failed" , False )
   lprint ( "EID-crypto-hash signature verification {}" . format ( IiO0O0oo0 ) )
   if 21 - 21: i11iIiiIii . OoO0O00 - O0 * Ii1I + I1ii11iIi11i % II111iiii
   if 84 - 84: iII111i
   if 54 - 54: I11i . ooOoO0o / OOooOOo % I1Ii111
 if ( I1i1iiII1iI1i and II1ii1IIi1i == False ) :
  I1i1iiII1iI1i = False
  lprint ( "Suppress creating pubsub state due to signature failure" )
  if 13 - 13: I11i / O0 . o0oOOo0O0Ooo . ooOoO0o
  if 7 - 7: OoO0O00 + OoooooooOO % II111iiii % oO0o
  if 48 - 48: OOooOOo . II111iiii * OOooOOo - I11i / iIii1I11I1II1 / i11iIiiIii
  if 37 - 37: II111iiii % O0 + iIii1I11I1II1 - I1IiiI . I11i + I1ii11iIi11i
  if 14 - 14: ooOoO0o % iIii1I11I1II1 % ooOoO0o / IiII + OOooOOo
  if 14 - 14: Oo0Ooo
  if 79 - 79: I1ii11iIi11i % I1Ii111 % I11i - iII111i * OoOoOO00
  if 48 - 48: O0 + OoOoOO00 - O0
  if 79 - 79: ooOoO0o . OoOoOO00 / OoooooooOO - II111iiii
  if 48 - 48: Oo0Ooo
  if 59 - 59: OoO0O00 % o0oOOo0O0Ooo
  if 83 - 83: iII111i % iIii1I11I1II1 / OOooOOo - OoOoOO00
  if 98 - 98: I11i % oO0o . I1IiiI % OoOoOO00
  if 32 - 32: I1ii11iIi11i / Ii1I
 o0o00O0OO = o0OooOo000oo0ooooO if ( o0OooOo000oo0ooooO . afi == ecm_source . afi ) else ecm_source
 if 68 - 68: OoO0O00 . o0oOOo0O0Ooo
 O0OO = lisp_site_eid_lookup ( ii1Ii , IiI1111i1i11I , False )
 if 46 - 46: OOooOOo / OOooOOo + I1IiiI + i1IIi
 if ( O0OO == None or O0OO . is_star_g ( ) ) :
  ii1111I1II1 = bold ( "Site not found" , False )
  lprint ( "{} for requested EID {}" . format ( ii1111I1II1 ,
 green ( O0o0O0OO0o , False ) ) )
  if 59 - 59: IiII - ooOoO0o . I1Ii111 . OoOoOO00 % OOooOOo . I1Ii111
  if 3 - 3: Ii1I / iIii1I11I1II1 . OoO0O00 / Oo0Ooo % OoOoOO00
  if 70 - 70: I1Ii111 / OOooOOo . OoO0O00 / o0oOOo0O0Ooo + II111iiii / ooOoO0o
  if 13 - 13: ooOoO0o % O0
  lisp_send_negative_map_reply ( lisp_sockets , ii1Ii , IiI1111i1i11I , i11IIoOOoOo0Ooo , o0OooOo000oo0ooooO ,
 mr_sport , 15 , iIi , I1i1iiII1iI1i )
  if 26 - 26: iIii1I11I1II1 + iIii1I11I1II1 . Ii1I + i1IIi
  return ( [ ii1Ii , IiI1111i1i11I , LISP_DDT_ACTION_SITE_NOT_FOUND ] )
  if 16 - 16: II111iiii . Ii1I / i11iIiiIii
  if 25 - 25: OoO0O00 + o0oOOo0O0Ooo
 oo0i11i11ii11 = O0OO . print_eid_tuple ( )
 Oo000Oo0o = O0OO . site . site_name
 if 99 - 99: I1ii11iIi11i + I1Ii111 % II111iiii - OoooooooOO * OoOoOO00
 if 29 - 29: I1Ii111 . O0 / ooOoO0o + i1IIi
 if 25 - 25: OOooOOo * O0 % OoooooooOO % O0 + iII111i
 if 6 - 6: Ii1I / II111iiii
 if 73 - 73: IiII
 if ( iioo00oOOO00 == False and O0OO . require_signature ) :
  IIIIi1I = map_request . map_request_signature
  O000o0O0 = map_request . signature_eid
  if ( IIIIi1I == None or O000o0O0 . is_null ( ) ) :
   lprint ( "Signature required for site {}" . format ( Oo000Oo0o ) )
   II1ii1IIi1i = False
  else :
   O000o0O0 = map_request . signature_eid
   i11i , i11I1i111i , II1ii1IIi1i = lisp_lookup_public_key ( O000o0O0 )
   if ( II1ii1IIi1i ) :
    II1ii1IIi1i = map_request . verify_map_request_sig ( i11I1i111i )
   else :
    lprint ( "Public-key lookup failed for sig-eid {}, hash-eid {}" . format ( O000o0O0 . print_address ( ) , i11i . print_address ( ) ) )
    if 81 - 81: iII111i . OOooOOo * i1IIi
    if 14 - 14: oO0o
   IiO0O0oo0 = bold ( "passed" , False ) if II1ii1IIi1i else bold ( "failed" , False )
   lprint ( "Required signature verification {}" . format ( IiO0O0oo0 ) )
   if 16 - 16: iII111i
   if 26 - 26: iII111i . oO0o * i11iIiiIii . iIii1I11I1II1
   if 74 - 74: Ii1I / iIii1I11I1II1 + OOooOOo . II111iiii
   if 65 - 65: OOooOOo * I11i * Oo0Ooo
   if 21 - 21: Ii1I . iIii1I11I1II1
   if 84 - 84: OOooOOo
 if ( II1ii1IIi1i and O0OO . registered == False ) :
  lprint ( "Site '{}' with EID-prefix {} is not registered for EID {}" . format ( Oo000Oo0o , green ( oo0i11i11ii11 , False ) , green ( O0o0O0OO0o , False ) ) )
  if 67 - 67: I1IiiI % OoO0O00 % o0oOOo0O0Ooo % IiII
  if 33 - 33: ooOoO0o % I1IiiI
  if 98 - 98: oO0o . o0oOOo0O0Ooo + II111iiii
  if 62 - 62: ooOoO0o - OoooooooOO / I1ii11iIi11i / iII111i - o0oOOo0O0Ooo
  if 70 - 70: oO0o % OoooooooOO * I1IiiI - OoOoOO00 * OoOoOO00 . OOooOOo
  if 9 - 9: iII111i * Oo0Ooo % iII111i % Oo0Ooo * II111iiii
  if ( O0OO . accept_more_specifics == False ) :
   ii1Ii = O0OO . eid
   IiI1111i1i11I = O0OO . group
   if 71 - 71: II111iiii + I1ii11iIi11i * II111iiii
   if 59 - 59: OoO0O00
   if 81 - 81: i11iIiiIii
   if 57 - 57: Oo0Ooo * iIii1I11I1II1 - OoOoOO00 % iII111i % I1ii11iIi11i + Ii1I
   if 82 - 82: IiII * Oo0Ooo - iIii1I11I1II1 - i11iIiiIii
  I1i = 1
  if ( O0OO . force_ttl != None ) :
   I1i = O0OO . force_ttl | 0x80000000
   if 85 - 85: OoooooooOO
   if 37 - 37: OoooooooOO + O0 + I1ii11iIi11i + IiII * iII111i
   if 15 - 15: i11iIiiIii / Oo0Ooo - OOooOOo . IiII
   if 11 - 11: OOooOOo / i1IIi % Oo0Ooo
   if 65 - 65: OOooOOo % I1ii11iIi11i
  lisp_send_negative_map_reply ( lisp_sockets , ii1Ii , IiI1111i1i11I , i11IIoOOoOo0Ooo , o0OooOo000oo0ooooO ,
 mr_sport , I1i , iIi , I1i1iiII1iI1i )
  if 25 - 25: o0oOOo0O0Ooo - I1Ii111 * I1ii11iIi11i + OoooooooOO
  return ( [ ii1Ii , IiI1111i1i11I , LISP_DDT_ACTION_MS_NOT_REG ] )
  if 93 - 93: OoOoOO00 % I1ii11iIi11i * I11i
  if 34 - 34: I11i - oO0o + I11i * OoooooooOO * I11i
  if 73 - 73: OOooOOo * iII111i * OoO0O00
  if 11 - 11: I1Ii111 * II111iiii
  if 3 - 3: Oo0Ooo * OOooOOo
 i1iiI1i = False
 ooOooo = ""
 i1ioO0OO00 = False
 if ( O0OO . force_nat_proxy_reply ) :
  ooOooo = ", nat-forced"
  i1iiI1i = True
  i1ioO0OO00 = True
 elif ( O0OO . force_proxy_reply ) :
  ooOooo = ", forced"
  i1ioO0OO00 = True
 elif ( O0OO . proxy_reply_requested ) :
  ooOooo = ", requested"
  i1ioO0OO00 = True
 elif ( map_request . pitr_bit and O0OO . pitr_proxy_reply_drop ) :
  ooOooo = ", drop-to-pitr"
  i11IIiI = LISP_DROP_ACTION
 elif ( O0OO . proxy_reply_action != "" ) :
  i11IIiI = O0OO . proxy_reply_action
  ooOooo = ", forced, action {}" . format ( i11IIiI )
  i11IIiI = LISP_DROP_ACTION if ( i11IIiI == "drop" ) else LISP_NATIVE_FORWARD_ACTION
  if 98 - 98: I1Ii111 + OoOoOO00 + i1IIi / OOooOOo / Ii1I / iII111i
  if 100 - 100: iIii1I11I1II1 % ooOoO0o + oO0o
  if 77 - 77: ooOoO0o . i11iIiiIii . OoOoOO00 + Ii1I
  if 7 - 7: II111iiii - ooOoO0o
  if 53 - 53: Ii1I - I1Ii111 * IiII + I1Ii111 . iIii1I11I1II1 + i11iIiiIii
  if 19 - 19: O0 - i11iIiiIii + ooOoO0o % O0
  if 63 - 63: iII111i + iIii1I11I1II1 * OoOoOO00 . I1Ii111 / I11i * o0oOOo0O0Ooo
 I11O0OO0ooooOO = False
 OO0 = None
 if ( i1ioO0OO00 and lisp_policies . has_key ( O0OO . policy ) ) :
  IiIiI1 = lisp_policies [ O0OO . policy ]
  if ( IiIiI1 . match_policy_map_request ( map_request , mr_source ) ) : OO0 = IiIiI1
  if 28 - 28: oO0o - I1IiiI
  if ( OO0 ) :
   i1Ii1 = bold ( "matched" , False )
   lprint ( "Map-Request {} policy '{}', set-action '{}'" . format ( i1Ii1 ,
 IiIiI1 . policy_name , IiIiI1 . set_action ) )
  else :
   i1Ii1 = bold ( "no match" , False )
   lprint ( "Map-Request {} for policy '{}', implied drop" . format ( i1Ii1 ,
 IiIiI1 . policy_name ) )
   I11O0OO0ooooOO = True
   if 42 - 42: i1IIi
   if 8 - 8: Ii1I - oO0o
   if 73 - 73: Oo0Ooo . i11iIiiIii % i11iIiiIii / o0oOOo0O0Ooo * OoO0O00 . i11iIiiIii
 if ( ooOooo != "" ) :
  lprint ( "Proxy-replying for EID {}, found site '{}' EID-prefix {}{}" . format ( green ( O0o0O0OO0o , False ) , Oo000Oo0o , green ( oo0i11i11ii11 , False ) ,
  # OoOoOO00 * ooOoO0o . iIii1I11I1II1 % i1IIi
 ooOooo ) )
  if 3 - 3: OoO0O00 - o0oOOo0O0Ooo - Ii1I
  I1I11I11 = O0OO . registered_rlocs
  I1i = 1440
  if ( i1iiI1i ) :
   if ( O0OO . site_id != 0 ) :
    I1IIiI = map_request . source_eid
    I1I11I11 = lisp_get_private_rloc_set ( O0OO , I1IIiI , IiI1111i1i11I )
    if 30 - 30: I1Ii111 + oO0o + iIii1I11I1II1 % OoO0O00 / I1IiiI
   if ( I1I11I11 == O0OO . registered_rlocs ) :
    ooo0oO0oo0o = ( O0OO . group . is_null ( ) == False )
    Ii1111iI = lisp_get_partial_rloc_set ( I1I11I11 , o0o00O0OO , ooo0oO0oo0o )
    if ( Ii1111iI != I1I11I11 ) :
     I1i = 15
     I1I11I11 = Ii1111iI
     if 41 - 41: IiII
     if 27 - 27: IiII / IiII
     if 91 - 91: Ii1I
     if 93 - 93: OoO0O00 * OoO0O00 * I1ii11iIi11i * OoO0O00 * o0oOOo0O0Ooo
     if 84 - 84: I1Ii111 * OoO0O00 - ooOoO0o - Oo0Ooo . OoO0O00 % oO0o
     if 98 - 98: OoO0O00 . i1IIi
     if 58 - 58: i1IIi * O0 + I1ii11iIi11i . IiII
     if 11 - 11: OOooOOo + iIii1I11I1II1 - ooOoO0o * OoO0O00 * i11iIiiIii
  if ( O0OO . force_ttl != None ) :
   I1i = O0OO . force_ttl | 0x80000000
   if 45 - 45: I1ii11iIi11i + Oo0Ooo
   if 7 - 7: Oo0Ooo + ooOoO0o - I1Ii111 * iIii1I11I1II1
   if 6 - 6: ooOoO0o % I1Ii111 % ooOoO0o . Ii1I * Oo0Ooo . IiII
   if 100 - 100: i1IIi . Ii1I . o0oOOo0O0Ooo + Ii1I - i1IIi . I11i
   if 19 - 19: i11iIiiIii + I11i - IiII . iII111i * i1IIi
   if 66 - 66: ooOoO0o
  if ( OO0 ) :
   if ( OO0 . set_record_ttl ) :
    I1i = OO0 . set_record_ttl
    lprint ( "Policy set-record-ttl to {}" . format ( I1i ) )
    if 4 - 4: iII111i / iII111i * OOooOOo + o0oOOo0O0Ooo . I1Ii111 + II111iiii
   if ( OO0 . set_action == "drop" ) :
    lprint ( "Policy set-action drop, send negative Map-Reply" )
    i11IIiI = LISP_POLICY_DENIED_ACTION
    I1I11I11 = [ ]
   else :
    II11IIiii = OO0 . set_policy_map_reply ( )
    if ( II11IIiii ) : I1I11I11 = [ II11IIiii ]
    if 90 - 90: IiII * iII111i % OoOoOO00 . i11iIiiIii
    if 5 - 5: O0 * i1IIi / IiII
    if 4 - 4: II111iiii
  if ( I11O0OO0ooooOO ) :
   lprint ( "Implied drop action, send negative Map-Reply" )
   i11IIiI = LISP_POLICY_DENIED_ACTION
   I1I11I11 = [ ]
   if 60 - 60: ooOoO0o - II111iiii * OoO0O00 + oO0o - iII111i
   if 39 - 39: OoO0O00 % I1Ii111 * I11i * Ii1I
  OOi111 = O0OO . echo_nonce_capable
  if 84 - 84: Oo0Ooo / OoO0O00 - II111iiii - OoOoOO00 - O0
  if 18 - 18: oO0o * I11i / o0oOOo0O0Ooo - OoooooooOO
  if 21 - 21: O0 - OoooooooOO
  if 21 - 21: iII111i * o0oOOo0O0Ooo
  if ( II1ii1IIi1i ) :
   OOo = O0OO . eid
   I1Ii = O0OO . group
  else :
   OOo = ii1Ii
   I1Ii = IiI1111i1i11I
   i11IIiI = LISP_AUTH_FAILURE_ACTION
   I1I11I11 = [ ]
   if 72 - 72: Ii1I / I1Ii111 + Oo0Ooo + II111iiii % OoOoOO00 % OOooOOo
   if 40 - 40: I1ii11iIi11i + i1IIi
   if 9 - 9: OOooOOo
   if 74 - 74: OoOoOO00 - OOooOOo % OoOoOO00
   if 82 - 82: I11i % IiII + Oo0Ooo + iIii1I11I1II1 - I11i - I1IiiI
   if 65 - 65: IiII / O0 * II111iiii + oO0o
  packet = lisp_build_map_reply ( OOo , I1Ii , I1I11I11 ,
 i11IIoOOoOo0Ooo , i11IIiI , I1i , False , None , OOi111 , False )
  if 52 - 52: o0oOOo0O0Ooo - OoOoOO00 * II111iiii / OoooooooOO
  if ( I1i1iiII1iI1i ) :
   lisp_process_pubsub ( lisp_sockets , packet , OOo , o0OooOo000oo0ooooO ,
 mr_sport , i11IIoOOoOo0Ooo , I1i , iIi )
  else :
   lisp_send_map_reply ( lisp_sockets , packet , o0OooOo000oo0ooooO , mr_sport )
   if 44 - 44: OOooOOo - oO0o + o0oOOo0O0Ooo - i1IIi % o0oOOo0O0Ooo
   if 79 - 79: iII111i . iIii1I11I1II1
  return ( [ O0OO . eid , O0OO . group , LISP_DDT_ACTION_MS_ACK ] )
  if 42 - 42: i11iIiiIii / IiII . O0 / OOooOOo . iII111i * i1IIi
  if 83 - 83: iIii1I11I1II1 . II111iiii * Oo0Ooo . I1IiiI - I1IiiI - iIii1I11I1II1
  if 29 - 29: Oo0Ooo
  if 35 - 35: OoOoOO00 + II111iiii
  if 46 - 46: O0 / I1ii11iIi11i + OOooOOo - I1Ii111 + I1IiiI - ooOoO0o
 OoOo0O0OO = len ( O0OO . registered_rlocs )
 if ( OoOo0O0OO == 0 ) :
  lprint ( "Requested EID {} found site '{}' with EID-prefix {} with " + "no registered RLOCs" . format ( green ( O0o0O0OO0o , False ) , Oo000Oo0o ,
  # OoO0O00 * OOooOOo * iII111i / I1ii11iIi11i % I11i % OoO0O00
 green ( oo0i11i11ii11 , False ) ) )
  return ( [ O0OO . eid , O0OO . group , LISP_DDT_ACTION_MS_ACK ] )
  if 26 - 26: iIii1I11I1II1 - Oo0Ooo * i11iIiiIii
  if 13 - 13: iIii1I11I1II1 - I11i % IiII . I1Ii111
  if 31 - 31: OoooooooOO % iII111i / OOooOOo
  if 54 - 54: o0oOOo0O0Ooo
  if 37 - 37: ooOoO0o
 i11i1iI1 = map_request . target_eid if map_request . source_eid . is_null ( ) else map_request . source_eid
 if 85 - 85: O0 - oO0o % I11i * iII111i * OoooooooOO
 II1IIIi = map_request . target_eid . hash_address ( i11i1iI1 )
 II1IIIi %= OoOo0O0OO
 oo0OO00O000 = O0OO . registered_rlocs [ II1IIIi ]
 if 42 - 42: Oo0Ooo . OoO0O00
 if ( oo0OO00O000 . rloc . is_null ( ) ) :
  lprint ( ( "Suppress forwarding Map-Request for EID {} at site '{}' " + "EID-prefix {}, no RLOC address" ) . format ( green ( O0o0O0OO0o , False ) ,
  # oO0o % ooOoO0o
 Oo000Oo0o , green ( oo0i11i11ii11 , False ) ) )
 else :
  lprint ( ( "Forwarding Map-Request for EID {} to ETR {} at site '{}' " + "EID-prefix {}" ) . format ( green ( O0o0O0OO0o , False ) ,
  # II111iiii - Oo0Ooo % I1IiiI
 red ( oo0OO00O000 . rloc . print_address ( ) , False ) , Oo000Oo0o ,
 green ( oo0i11i11ii11 , False ) ) )
  if 68 - 68: II111iiii
  if 24 - 24: I1Ii111 / o0oOOo0O0Ooo - OOooOOo / IiII
  if 7 - 7: OoooooooOO - i11iIiiIii * i11iIiiIii / oO0o * i1IIi % OoooooooOO
  if 6 - 6: I1ii11iIi11i * i11iIiiIii % i11iIiiIii / I1Ii111
  lisp_send_ecm ( lisp_sockets , packet , map_request . source_eid , mr_sport ,
 map_request . target_eid , oo0OO00O000 . rloc , to_etr = True )
  if 21 - 21: oO0o
 return ( [ O0OO . eid , O0OO . group , LISP_DDT_ACTION_MS_ACK ] )
 if 47 - 47: I1ii11iIi11i
 if 24 - 24: I1Ii111 % iIii1I11I1II1
 if 87 - 87: OoOoOO00 - II111iiii + Oo0Ooo
 if 44 - 44: i1IIi + I1ii11iIi11i / iIii1I11I1II1
 if 47 - 47: I1Ii111
 if 41 - 41: IiII
 if 25 - 25: I11i % iIii1I11I1II1
def lisp_ddt_process_map_request ( lisp_sockets , map_request , ecm_source , port ) :
 if 27 - 27: iIii1I11I1II1 . O0 . oO0o
 if 21 - 21: oO0o * I1ii11iIi11i
 if 44 - 44: o0oOOo0O0Ooo * IiII - o0oOOo0O0Ooo
 if 90 - 90: i1IIi + I1ii11iIi11i * oO0o % i11iIiiIii - OoO0O00
 ii1Ii = map_request . target_eid
 IiI1111i1i11I = map_request . target_group
 O0o0O0OO0o = lisp_print_eid_tuple ( ii1Ii , IiI1111i1i11I )
 i11IIoOOoOo0Ooo = map_request . nonce
 i11IIiI = LISP_DDT_ACTION_NULL
 if 12 - 12: OoO0O00 . I1ii11iIi11i - I1IiiI % OOooOOo
 if 9 - 9: Ii1I / O0
 if 95 - 95: iII111i / I11i
 if 86 - 86: O0 / II111iiii . Oo0Ooo / Oo0Ooo * II111iiii
 if 22 - 22: Ii1I
 oo0OOo00OOoO = None
 if ( lisp_i_am_ms ) :
  O0OO = lisp_site_eid_lookup ( ii1Ii , IiI1111i1i11I , False )
  if ( O0OO == None ) : return
  if 5 - 5: I1Ii111 * I1IiiI * O0 + I1Ii111
  if ( O0OO . registered ) :
   i11IIiI = LISP_DDT_ACTION_MS_ACK
   I1i = 1440
  else :
   ii1Ii , IiI1111i1i11I , i11IIiI = lisp_ms_compute_neg_prefix ( ii1Ii , IiI1111i1i11I )
   i11IIiI = LISP_DDT_ACTION_MS_NOT_REG
   I1i = 1
   if 19 - 19: i11iIiiIii / IiII - i1IIi - I1IiiI * I11i
 else :
  oo0OOo00OOoO = lisp_ddt_cache_lookup ( ii1Ii , IiI1111i1i11I , False )
  if ( oo0OOo00OOoO == None ) :
   i11IIiI = LISP_DDT_ACTION_NOT_AUTH
   I1i = 0
   lprint ( "DDT delegation entry not found for EID {}" . format ( green ( O0o0O0OO0o , False ) ) )
   if 43 - 43: IiII * Oo0Ooo / OoOoOO00 + I1IiiI - i11iIiiIii + II111iiii
  elif ( oo0OOo00OOoO . is_auth_prefix ( ) ) :
   if 81 - 81: I11i / Oo0Ooo % Ii1I % OoO0O00
   if 87 - 87: O0 % II111iiii
   if 42 - 42: I1IiiI . i1IIi
   if 98 - 98: o0oOOo0O0Ooo % I11i . Oo0Ooo * Oo0Ooo % iII111i
   i11IIiI = LISP_DDT_ACTION_DELEGATION_HOLE
   I1i = 15
   IIi11 = oo0OOo00OOoO . print_eid_tuple ( )
   lprint ( ( "DDT delegation entry not found but auth-prefix {} " + "found for EID {}" ) . format ( IIi11 ,
   # i1IIi / OoooooooOO % Oo0Ooo - II111iiii / i11iIiiIii . OoooooooOO
 green ( O0o0O0OO0o , False ) ) )
   if 98 - 98: O0
   if ( IiI1111i1i11I . is_null ( ) ) :
    ii1Ii = lisp_ddt_compute_neg_prefix ( ii1Ii , oo0OOo00OOoO ,
 lisp_ddt_cache )
   else :
    IiI1111i1i11I = lisp_ddt_compute_neg_prefix ( IiI1111i1i11I , oo0OOo00OOoO ,
 lisp_ddt_cache )
    ii1Ii = lisp_ddt_compute_neg_prefix ( ii1Ii , oo0OOo00OOoO ,
 oo0OOo00OOoO . source_cache )
    if 27 - 27: oO0o * OoooooooOO * oO0o
   oo0OOo00OOoO = None
  else :
   IIi11 = oo0OOo00OOoO . print_eid_tuple ( )
   lprint ( "DDT delegation entry {} found for EID {}" . format ( IIi11 , green ( O0o0O0OO0o , False ) ) )
   if 23 - 23: O0 . OoO0O00 . i1IIi
   I1i = 1440
   if 19 - 19: O0 . OoooooooOO % iIii1I11I1II1 - Ii1I . Ii1I + I1IiiI
   if 98 - 98: oO0o . Oo0Ooo
   if 9 - 9: I1Ii111 % IiII - i11iIiiIii - OOooOOo % iII111i % OoooooooOO
   if 6 - 6: i1IIi - II111iiii * OoOoOO00 + oO0o
   if 6 - 6: I1IiiI - ooOoO0o + I1IiiI + OoO0O00 - i11iIiiIii % ooOoO0o
   if 64 - 64: OoooooooOO + OOooOOo
 Ii11iIiiI = lisp_build_map_referral ( ii1Ii , IiI1111i1i11I , oo0OOo00OOoO , i11IIiI , I1i , i11IIoOOoOo0Ooo )
 i11IIoOOoOo0Ooo = map_request . nonce >> 32
 if ( map_request . nonce != 0 and i11IIoOOoOo0Ooo != 0xdfdf0e1d ) : port = LISP_CTRL_PORT
 lisp_send_map_referral ( lisp_sockets , Ii11iIiiI , ecm_source , port )
 return
 if 36 - 36: I1IiiI - Ii1I / I1ii11iIi11i + Oo0Ooo % I1ii11iIi11i
 if 86 - 86: iIii1I11I1II1 * OoO0O00
 if 82 - 82: I1IiiI - OoO0O00 % o0oOOo0O0Ooo
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
  oo0OOo00OOoO = lisp_ddt_cache . lookup_cache ( eid , False )
  if ( oo0OOo00OOoO == None ) :
   IIi11iIi . mask_len = IIi11iIi . host_mask_len ( )
   OO0OOO0oO . mask_len = OO0OOO0oO . host_mask_len ( )
   return ( [ IIi11iIi , OO0OOO0oO , LISP_DDT_ACTION_NOT_AUTH ] )
   if 79 - 79: II111iiii + ooOoO0o - i1IIi - i1IIi + II111iiii . i1IIi
  Oo00O0O0Oo0o0 = lisp_sites_by_eid
  if ( oo0OOo00OOoO . is_auth_prefix ( ) ) : IIIi1iIiiI1 = oo0OOo00OOoO . eid
 else :
  oo0OOo00OOoO = lisp_ddt_cache . lookup_cache ( group , False )
  if ( oo0OOo00OOoO == None ) :
   IIi11iIi . mask_len = IIi11iIi . host_mask_len ( )
   OO0OOO0oO . mask_len = OO0OOO0oO . host_mask_len ( )
   return ( [ IIi11iIi , OO0OOO0oO , LISP_DDT_ACTION_NOT_AUTH ] )
   if 80 - 80: OoooooooOO * OoooooooOO . I1IiiI
  if ( oo0OOo00OOoO . is_auth_prefix ( ) ) : IIIi1iIiiI1 = oo0OOo00OOoO . group
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
  Oo00O0O0Oo0o0 = oo0OOo00OOoO . source_cache
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
 i11IIoOOoOo0Ooo = map_request . nonce
 if 8 - 8: iII111i % II111iiii + IiII
 if ( action == LISP_DDT_ACTION_MS_ACK ) : I1i = 1440
 if 5 - 5: i1IIi + II111iiii
 if 75 - 75: OOooOOo . IiII . I1IiiI + OoooooooOO
 if 35 - 35: I11i % i1IIi - I1ii11iIi11i . Oo0Ooo
 if 69 - 69: ooOoO0o * OoO0O00 % o0oOOo0O0Ooo * o0oOOo0O0Ooo
 iI1oOoo0oO0oOo = lisp_map_referral ( )
 iI1oOoo0oO0oOo . record_count = 1
 iI1oOoo0oO0oOo . nonce = i11IIoOOoOo0Ooo
 Ii11iIiiI = iI1oOoo0oO0oOo . encode ( )
 iI1oOoo0oO0oOo . print_map_referral ( )
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
 OoOo0O0OO = 0
 oo0OOo00OOoO = lisp_ddt_cache_lookup ( ii1Ii , IiI1111i1i11I , False )
 if ( oo0OOo00OOoO != None ) :
  OoOo0O0OO = len ( oo0OOo00OOoO . delegation_set )
  i1ii = oo0OOo00OOoO . is_ms_peer_entry ( )
  oo0OOo00OOoO . map_referrals_sent += 1
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
 OOOO = lisp_eid_record ( )
 OOOO . rloc_count = OoOo0O0OO
 OOOO . authoritative = True
 OOOO . action = action
 OOOO . ddt_incomplete = Ooooo0OO000o0
 OOOO . eid = eid_prefix
 OOOO . group = group_prefix
 OOOO . record_ttl = I1i
 if 88 - 88: I1Ii111 . O0 - oO0o + i1IIi % Oo0Ooo
 Ii11iIiiI += OOOO . encode ( )
 OOOO . print_record ( "  " , True )
 if 39 - 39: I1Ii111 - I1IiiI
 if 18 - 18: i1IIi
 if 42 - 42: II111iiii - i1IIi . oO0o % OOooOOo % ooOoO0o - i11iIiiIii
 if 23 - 23: OOooOOo + iIii1I11I1II1 - i1IIi
 if ( OoOo0O0OO != 0 ) :
  for iIiOoo0 in oo0OOo00OOoO . delegation_set :
   OO0OoOo = lisp_rloc_record ( )
   OO0OoOo . rloc = iIiOoo0 . delegate_address
   OO0OoOo . priority = iIiOoo0 . priority
   OO0OoOo . weight = iIiOoo0 . weight
   OO0OoOo . mpriority = 255
   OO0OoOo . mweight = 0
   OO0OoOo . reach_bit = True
   Ii11iIiiI += OO0OoOo . encode ( )
   OO0OoOo . print_record ( "    " )
   if 72 - 72: OOooOOo . I1IiiI * O0 + i11iIiiIii - iII111i
   if 79 - 79: o0oOOo0O0Ooo + I1ii11iIi11i
   if 46 - 46: I11i
   if 78 - 78: IiII / II111iiii
   if 55 - 55: Oo0Ooo
   if 80 - 80: o0oOOo0O0Ooo - I1Ii111 * O0 * iIii1I11I1II1
   if 59 - 59: I1ii11iIi11i + I11i / OoO0O00
 if ( map_request . nonce != 0 ) : port = LISP_CTRL_PORT
 lisp_send_map_referral ( lisp_sockets , Ii11iIiiI , ecm_source , port )
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
 Ii11iIiiI = lisp_build_map_reply ( eid , group , [ ] , nonce , i11IIiI , ttl , False ,
 None , False , False )
 if 3 - 3: ooOoO0o % OoOoOO00 * I1Ii111 - OoO0O00 / i1IIi % I1IiiI
 if 50 - 50: I1ii11iIi11i + iII111i
 if 64 - 64: oO0o
 if 11 - 11: o0oOOo0O0Ooo
 if ( pubsub ) :
  lisp_process_pubsub ( sockets , Ii11iIiiI , eid , dest , port , nonce , ttl ,
 xtr_id )
 else :
  lisp_send_map_reply ( sockets , Ii11iIiiI , dest , port )
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
 i11IIoOOoOo0Ooo = mr . nonce
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
  lprint ( "DDT Map-Request retry limit reached for EID {}, nonce 0x{}" . format ( green ( OoOOO0O , False ) , lisp_hex_string ( i11IIoOOoOo0Ooo ) ) )
  if 90 - 90: IiII % I1ii11iIi11i % i1IIi
  mr . dequeue_map_request ( )
  return
  if 63 - 63: Ii1I . I1IiiI + IiII / OoOoOO00 + ooOoO0o - iIii1I11I1II1
  if 20 - 20: i1IIi % II111iiii . IiII % iIii1I11I1II1
 mr . retry_count += 1
 if 9 - 9: o0oOOo0O0Ooo
 oOOOOOOOoO = green ( i1Ii , False )
 OooOo = green ( OoOOO0O , False )
 lprint ( "Retransmit DDT {} from {}ITR {} EIDs: {} -> {}, nonce 0x{}" . format ( bold ( "Map-Request" , False ) , "P" if mr . from_pitr else "" ,
 # I11i % I1Ii111 % I1Ii111 + II111iiii * OoO0O00
 red ( mr . itr . print_address ( ) , False ) , oOOOOOOOoO , OooOo ,
 lisp_hex_string ( i11IIoOOoOo0Ooo ) ) )
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
 II1IIIi = dest_eid . hash_address ( source_eid )
 II1IIIi = II1IIIi % OOoOoO0oO
 return ( i1111iIiIi [ II1IIIi ] )
 if 78 - 78: OoOoOO00 . Oo0Ooo % I11i
 if 7 - 7: I1ii11iIi11i % Ii1I . OoooooooOO - iII111i
 if 18 - 18: O0 * OoooooooOO % IiII - iIii1I11I1II1 % IiII * o0oOOo0O0Ooo
 if 13 - 13: OoO0O00 + i11iIiiIii + O0 / ooOoO0o % iIii1I11I1II1
 if 75 - 75: oO0o / i1IIi / Ii1I * Oo0Ooo
 if 75 - 75: Oo0Ooo / OoooooooOO
 if 98 - 98: II111iiii - I1Ii111 . ooOoO0o * iII111i
def lisp_send_ddt_map_request ( mr , send_to_root ) :
 iIIi1 = mr . lisp_sockets
 i11IIoOOoOo0Ooo = mr . nonce
 oo0Oo0oo = mr . itr
 OoiiII1 = mr . mr_source
 O0o0O0OO0o = mr . print_eid_tuple ( )
 if 60 - 60: I1IiiI
 if 3 - 3: II111iiii % IiII % I1IiiI - I1IiiI . I1Ii111 - OoOoOO00
 if 18 - 18: O0
 if 26 - 26: i1IIi - iIii1I11I1II1
 if 8 - 8: I1Ii111
 if ( mr . send_count == 8 ) :
  lprint ( "Giving up on map-request-queue entry {}, nonce 0x{}" . format ( green ( O0o0O0OO0o , False ) , lisp_hex_string ( i11IIoOOoOo0Ooo ) ) )
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
  lprint ( "Jumping up to root for EID {}" . format ( green ( O0o0O0OO0o , False ) ) )
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
 i11IIoOOoOo0Ooo , oo0Oo0oo , mr . sport , 15 , None , False )
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
 II11IIIIi . group , i11IIoOOoOo0Ooo , oo0Oo0oo , mr . sport , 1 , None , False )
  return
  if 19 - 19: O0 / o0oOOo0O0Ooo . I1IiiI
  if 100 - 100: I1Ii111 + iIii1I11I1II1 . OoOoOO00 / iII111i . iIii1I11I1II1 - Ii1I
 lprint ( "Send DDT Map-Request to {} {} for EID {}, nonce 0x{}" . format ( ii1I111ii . referral_address . print_address ( ) ,
 # OoOoOO00 . oO0o - Oo0Ooo - II111iiii - I1ii11iIi11i * oO0o
 II11IIIIi . print_referral_type ( ) , green ( O0o0O0OO0o , False ) ,
 lisp_hex_string ( i11IIoOOoOo0Ooo ) ) )
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
 i11IIoOOoOo0Ooo = map_request . nonce
 if 25 - 25: oO0o
 oOOOOOOOoO = green ( i1Ii , False )
 OooOo = green ( OoOOO0O , False )
 lprint ( "Received Map-Request from {}ITR {} EIDs: {} -> {}, nonce 0x{}" . format ( "P" if map_request . pitr_bit else "" ,
 # I1IiiI - OoO0O00 / iIii1I11I1II1 * iII111i + OoOoOO00 + IiII
 red ( ecm_source . print_address ( ) , False ) , oOOOOOOOoO , OooOo ,
 lisp_hex_string ( i11IIoOOoOo0Ooo ) ) )
 if 16 - 16: OoO0O00 % OOooOOo . I11i . I11i
 if 4 - 4: O0 + I11i / OoOoOO00 * iIii1I11I1II1 . Ii1I
 if 68 - 68: Oo0Ooo % ooOoO0o + i11iIiiIii / oO0o / II111iiii
 if 63 - 63: OoO0O00 % i1IIi - OoooooooOO / ooOoO0o
 OOO0o0o = lisp_ddt_map_request ( lisp_sockets , packet , ii1Ii , IiI1111i1i11I , i11IIoOOoOo0Ooo )
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
 II1IiiI = lisp_map_reply ( )
 packet = II1IiiI . decode ( packet )
 if ( packet == None ) :
  lprint ( "Could not decode Map-Reply packet" )
  return
  if 15 - 15: O0 % Oo0Ooo % o0oOOo0O0Ooo . ooOoO0o * iII111i % O0
 II1IiiI . print_map_reply ( )
 if 31 - 31: i1IIi . Ii1I - OoooooooOO * I11i * ooOoO0o % oO0o
 if 61 - 61: I1Ii111 . Ii1I * I1ii11iIi11i
 if 59 - 59: OoOoOO00 + Oo0Ooo . I1ii11iIi11i - Ii1I
 if 48 - 48: I1Ii111 % Ii1I + I1IiiI * OoooooooOO % OoOoOO00 % i11iIiiIii
 i1iiIi1Iii1 = None
 for oo0O0oO0O0O in range ( II1IiiI . record_count ) :
  OOOO = lisp_eid_record ( )
  packet = OOOO . decode ( packet )
  if ( packet == None ) :
   lprint ( "Could not decode EID-record in Map-Reply packet" )
   return
   if 85 - 85: OoOoOO00 + OOooOOo
  OOOO . print_record ( "  " , False )
  if 75 - 75: OoooooooOO - Oo0Ooo - Oo0Ooo % O0 + ooOoO0o + Oo0Ooo
  if 56 - 56: i1IIi
  if 37 - 37: I1IiiI % i11iIiiIii + OoO0O00 * OOooOOo . o0oOOo0O0Ooo % IiII
  if 18 - 18: Oo0Ooo % IiII . OoOoOO00 - IiII + I1Ii111 + oO0o
  if 31 - 31: OOooOOo + OoOoOO00 * OOooOOo + OoOoOO00 / o0oOOo0O0Ooo . iIii1I11I1II1
  if ( OOOO . rloc_count == 0 ) :
   lisp_store_mr_stats ( source , II1IiiI . nonce )
   if 1 - 1: I1Ii111 * i11iIiiIii % I1Ii111 - OoO0O00 + I1Ii111 / Oo0Ooo
   if 3 - 3: OOooOOo - i11iIiiIii / I1Ii111 . OOooOOo - OoO0O00
  OOooO = ( OOOO . group . is_null ( ) == False )
  if 78 - 78: OoooooooOO + oO0o + I1IiiI + I1Ii111
  if 24 - 24: I11i + i1IIi + I1ii11iIi11i * OoooooooOO * IiII
  if 70 - 70: iIii1I11I1II1 / I1IiiI * OoOoOO00 / IiII / II111iiii + I1IiiI
  if 33 - 33: oO0o
  if 1 - 1: OoOoOO00 . i11iIiiIii % I1Ii111 + OoooooooOO - Oo0Ooo . I1ii11iIi11i
  if ( lisp_decent_push_configured ) :
   i11IIiI = OOOO . action
   if ( OOooO and i11IIiI == LISP_DROP_ACTION ) :
    if ( OOOO . eid . is_local ( ) ) : continue
    if 46 - 46: i11iIiiIii + I11i - iIii1I11I1II1 / OoO0O00 - ooOoO0o / i1IIi
    if 44 - 44: o0oOOo0O0Ooo + Oo0Ooo
    if 46 - 46: OOooOOo % I1IiiI
    if 66 - 66: iIii1I11I1II1 . o0oOOo0O0Ooo - ooOoO0o
    if 27 - 27: Oo0Ooo - i1IIi * OoooooooOO - OoOoOO00 + OoOoOO00
    if 24 - 24: i1IIi . OoOoOO00 / I1Ii111 + O0
    if 86 - 86: Ii1I * OoOoOO00 % I1ii11iIi11i + OOooOOo
  if ( OOOO . eid . is_null ( ) ) : continue
  if 85 - 85: iII111i % i11iIiiIii
  if 78 - 78: i11iIiiIii / I11i / Oo0Ooo + II111iiii - I1ii11iIi11i / I1ii11iIi11i
  if 28 - 28: iIii1I11I1II1 / IiII - iIii1I11I1II1 . i1IIi - O0 * ooOoO0o
  if 41 - 41: Ii1I + IiII
  if 37 - 37: I1Ii111 / o0oOOo0O0Ooo - ooOoO0o - OoooooooOO . I1ii11iIi11i % I1Ii111
  if ( OOooO ) :
   OoOOO000O0o = lisp_map_cache_lookup ( OOOO . eid , OOOO . group )
  else :
   OoOOO000O0o = lisp_map_cache . lookup_cache ( OOOO . eid , True )
   if 59 - 59: oO0o / i1IIi - OoO0O00
  iII1111 = ( OoOOO000O0o == None )
  if 76 - 76: ooOoO0o / OoO0O00 - Oo0Ooo . IiII * I11i
  if 98 - 98: i11iIiiIii % i1IIi + I1Ii111 / iIii1I11I1II1 + o0oOOo0O0Ooo
  if 35 - 35: oO0o . I11i % OoO0O00
  if 13 - 13: I1ii11iIi11i / ooOoO0o * I1Ii111
  if 45 - 45: I1ii11iIi11i - I11i
  if ( OoOOO000O0o == None ) :
   O000oO00 , O0OOoO = lisp_allow_gleaning ( OOOO . eid , OOOO . group ,
 None )
   if ( O000oO00 ) : continue
  else :
   if ( OoOOO000O0o . gleaned ) : continue
   if 88 - 88: OoOoOO00 . i11iIiiIii % OoooooooOO . oO0o . O0 + iIii1I11I1II1
   if 11 - 11: OoO0O00 / I1Ii111 . OoOoOO00
   if 95 - 95: I1ii11iIi11i / Ii1I % ooOoO0o . OoooooooOO % OoOoOO00 . OoOoOO00
   if 1 - 1: I1ii11iIi11i % o0oOOo0O0Ooo % i11iIiiIii - OOooOOo - ooOoO0o - OoO0O00
   if 94 - 94: OoO0O00 . Oo0Ooo / OoO0O00 + I1Ii111
  I1I11I11 = [ ]
  for iIIi11i1i1I1I in range ( OOOO . rloc_count ) :
   OO0OoOo = lisp_rloc_record ( )
   OO0OoOo . keys = II1IiiI . keys
   packet = OO0OoOo . decode ( packet , II1IiiI . nonce )
   if ( packet == None ) :
    lprint ( "Could not decode RLOC-record in Map-Reply packet" )
    return
    if 66 - 66: i11iIiiIii . iII111i / I11i
   OO0OoOo . print_record ( "    " )
   if 66 - 66: i11iIiiIii - I1IiiI - OoO0O00 / OoOoOO00 / II111iiii
   iIioO000 = None
   if ( OoOOO000O0o ) : iIioO000 = OoOOO000O0o . get_rloc ( OO0OoOo . rloc )
   if ( iIioO000 ) :
    II11IIiii = iIioO000
   else :
    II11IIiii = lisp_rloc ( )
    if 31 - 31: i11iIiiIii + OOooOOo
    if 43 - 43: I1IiiI . Oo0Ooo + i1IIi + I11i / OoO0O00
    if 66 - 66: i11iIiiIii
    if 83 - 83: I1Ii111 / iIii1I11I1II1 - oO0o
    if 3 - 3: OOooOOo - Oo0Ooo * I1IiiI - OoO0O00 / OOooOOo + IiII
    if 83 - 83: i1IIi * i1IIi - II111iiii / OoooooooOO . Ii1I + I1Ii111
    if 10 - 10: I11i
   IIIIiI1ii1 = II11IIiii . store_rloc_from_record ( OO0OoOo , II1IiiI . nonce ,
 source )
   II11IIiii . echo_nonce_capable = II1IiiI . echo_nonce_capable
   if 24 - 24: Ii1I
   if ( II11IIiii . echo_nonce_capable ) :
    i111I11I = II11IIiii . rloc . print_address_no_iid ( )
    if ( lisp_get_echo_nonce ( None , i111I11I ) == None ) :
     lisp_echo_nonce ( i111I11I )
     if 30 - 30: II111iiii / Ii1I - I11i - OoO0O00
     if 25 - 25: I11i % i1IIi / I11i * i11iIiiIii
     if 71 - 71: IiII % I11i - OoooooooOO + I1IiiI / Oo0Ooo % I11i
     if 6 - 6: i1IIi * i11iIiiIii + ooOoO0o - IiII
     if 97 - 97: iIii1I11I1II1 * i1IIi * II111iiii - OOooOOo - Oo0Ooo - iIii1I11I1II1
     if 26 - 26: ooOoO0o + Oo0Ooo
     if 24 - 24: I1IiiI
     if 43 - 43: OoO0O00
     if 51 - 51: OoooooooOO % IiII % Oo0Ooo
     if 50 - 50: I1IiiI - i11iIiiIii / I1ii11iIi11i . Ii1I - iIii1I11I1II1
   if ( II1IiiI . rloc_probe and OO0OoOo . probe_bit ) :
    if ( II11IIiii . rloc . afi == source . afi ) :
     lisp_process_rloc_probe_reply ( II11IIiii . rloc , source , IIIIiI1ii1 ,
 II1IiiI . nonce , II1IiiI . hop_count , ttl )
     if 91 - 91: I1IiiI . I1Ii111 + II111iiii . Oo0Ooo
     if 95 - 95: iII111i
     if 77 - 77: I1IiiI * II111iiii * iIii1I11I1II1
     if 19 - 19: OOooOOo * o0oOOo0O0Ooo
     if 64 - 64: I11i % ooOoO0o / OOooOOo / iII111i
     if 80 - 80: i1IIi
   I1I11I11 . append ( II11IIiii )
   if 74 - 74: I1ii11iIi11i . OoO0O00 + i11iIiiIii
   if 19 - 19: i1IIi / I1IiiI + IiII . iII111i
   if 68 - 68: iII111i
   if 29 - 29: II111iiii / II111iiii % OoO0O00 % Oo0Ooo . II111iiii
   if ( lisp_data_plane_security and II11IIiii . rloc_recent_rekey ( ) ) :
    i1iiIi1Iii1 = II11IIiii
    if 33 - 33: OoooooooOO . OoO0O00 % OoooooooOO
    if 9 - 9: IiII * O0 + OOooOOo . II111iiii
    if 14 - 14: iIii1I11I1II1 + i11iIiiIii + o0oOOo0O0Ooo + o0oOOo0O0Ooo - IiII / I1Ii111
    if 70 - 70: OoooooooOO + I1IiiI / OOooOOo
    if 19 - 19: I1Ii111 + i1IIi % OoooooooOO + i1IIi
    if 16 - 16: I1Ii111 + II111iiii + IiII
    if 34 - 34: iIii1I11I1II1 - II111iiii - ooOoO0o + oO0o
    if 46 - 46: ooOoO0o % II111iiii
    if 61 - 61: OoO0O00 . I1IiiI
    if 89 - 89: IiII
    if 73 - 73: II111iiii + ooOoO0o % OOooOOo . oO0o / oO0o * i1IIi
  if ( II1IiiI . rloc_probe == False and lisp_nat_traversal ) :
   Ii1111iI = [ ]
   i11iiI = [ ]
   for II11IIiii in I1I11I11 :
    if 2 - 2: i1IIi . OOooOOo
    if 23 - 23: Ii1I - OOooOOo
    if 89 - 89: i11iIiiIii
    if 40 - 40: OoooooooOO % OoO0O00
    if 54 - 54: i1IIi * OOooOOo - oO0o * OoooooooOO + II111iiii . IiII
    if ( II11IIiii . rloc . is_private_address ( ) ) :
     II11IIiii . priority = 1
     II11IIiii . state = LISP_RLOC_UNREACH_STATE
     Ii1111iI . append ( II11IIiii )
     i11iiI . append ( II11IIiii . rloc . print_address_no_iid ( ) )
     continue
     if 90 - 90: O0 - II111iiii + I1IiiI . iII111i
     if 3 - 3: o0oOOo0O0Ooo + i1IIi * Oo0Ooo
     if 6 - 6: OoO0O00 * OoooooooOO * iIii1I11I1II1
     if 87 - 87: iIii1I11I1II1 - ooOoO0o * iIii1I11I1II1
     if 79 - 79: ooOoO0o . oO0o + Ii1I * ooOoO0o + O0 . II111iiii
     if 8 - 8: IiII * OOooOOo + I11i + O0 * oO0o - oO0o
    if ( II11IIiii . priority == 254 and lisp_i_am_rtr == False ) :
     Ii1111iI . append ( II11IIiii )
     i11iiI . append ( II11IIiii . rloc . print_address_no_iid ( ) )
     if 19 - 19: OoO0O00 - ooOoO0o + I1ii11iIi11i / I1ii11iIi11i % I1Ii111 % iIii1I11I1II1
    if ( II11IIiii . priority != 254 and lisp_i_am_rtr ) :
     Ii1111iI . append ( II11IIiii )
     i11iiI . append ( II11IIiii . rloc . print_address_no_iid ( ) )
     if 5 - 5: OoooooooOO + ooOoO0o - II111iiii . i11iIiiIii / oO0o - ooOoO0o
     if 3 - 3: iII111i
     if 74 - 74: i11iIiiIii + OoooooooOO . OOooOOo
   if ( i11iiI != [ ] ) :
    I1I11I11 = Ii1111iI
    lprint ( "NAT-traversal optimized RLOC-set: {}" . format ( i11iiI ) )
    if 29 - 29: IiII % OoO0O00
    if 53 - 53: OoooooooOO - OoOoOO00 / IiII - I1Ii111
    if 16 - 16: iIii1I11I1II1 / OOooOOo + I1IiiI * II111iiii . OOooOOo
    if 68 - 68: IiII * IiII + oO0o / o0oOOo0O0Ooo
    if 41 - 41: OoOoOO00 - O0
    if 48 - 48: OoooooooOO % Ii1I * OoO0O00 / I1ii11iIi11i
    if 53 - 53: ooOoO0o + oO0o - II111iiii
  Ii1111iI = [ ]
  for II11IIiii in I1I11I11 :
   if ( II11IIiii . json != None ) : continue
   Ii1111iI . append ( II11IIiii )
   if 92 - 92: Oo0Ooo - I11i . ooOoO0o % oO0o
  if ( Ii1111iI != [ ] ) :
   O0oO = len ( I1I11I11 ) - len ( Ii1111iI )
   lprint ( "Pruning {} no-address RLOC-records for map-cache" . format ( O0oO ) )
   if 6 - 6: iIii1I11I1II1 + oO0o
   I1I11I11 = Ii1111iI
   if 8 - 8: I1ii11iIi11i + o0oOOo0O0Ooo
   if 29 - 29: Ii1I . OOooOOo
   if 59 - 59: O0 . OoO0O00
   if 10 - 10: I1Ii111 / OoooooooOO / OoO0O00 * ooOoO0o
   if 81 - 81: i1IIi % I11i * iIii1I11I1II1
   if 39 - 39: iIii1I11I1II1 / O0 . OoooooooOO - O0 . OoO0O00 . oO0o
   if 59 - 59: II111iiii * I1IiiI
   if 12 - 12: i11iIiiIii - IiII . iII111i . Ii1I
  if ( II1IiiI . rloc_probe and OoOOO000O0o != None ) : I1I11I11 = OoOOO000O0o . rloc_set
  if 34 - 34: i1IIi % iII111i + Oo0Ooo * OoOoOO00 + OoO0O00
  if 37 - 37: I1Ii111 / OoooooooOO
  if 19 - 19: Ii1I - O0 + I1IiiI + OoooooooOO + ooOoO0o - Oo0Ooo
  if 45 - 45: I1IiiI . OoOoOO00 . OoOoOO00
  if 20 - 20: OoOoOO00
  OO00o0oO0O00 = iII1111
  if ( OoOOO000O0o and I1I11I11 != OoOOO000O0o . rloc_set ) :
   OoOOO000O0o . delete_rlocs_from_rloc_probe_list ( )
   OO00o0oO0O00 = True
   if 60 - 60: I11i + O0 * I1IiiI * O0 * II111iiii
   if 73 - 73: II111iiii
   if 81 - 81: I1IiiI + OoO0O00
   if 22 - 22: OoO0O00 * OoOoOO00 * I11i * IiII . OoO0O00 . I1ii11iIi11i
   if 32 - 32: o0oOOo0O0Ooo - iII111i + i11iIiiIii / ooOoO0o . OoOoOO00 . IiII
  iIiiii1 = OoOOO000O0o . uptime if ( OoOOO000O0o ) else None
  if ( OoOOO000O0o == None ) :
   OoOOO000O0o = lisp_mapping ( OOOO . eid , OOOO . group , I1I11I11 )
   OoOOO000O0o . mapping_source = source
   OoOOO000O0o . map_cache_ttl = OOOO . store_ttl ( )
   OoOOO000O0o . action = OOOO . action
   OoOOO000O0o . add_cache ( OO00o0oO0O00 )
   if 64 - 64: i11iIiiIii + I1IiiI / Oo0Ooo - iII111i
   if 26 - 26: I1ii11iIi11i
  O0ooOo0O0ooo0 = "Add"
  if ( iIiiii1 ) :
   OoOOO000O0o . uptime = iIiiii1
   OoOOO000O0o . refresh_time = lisp_get_timestamp ( )
   O0ooOo0O0ooo0 = "Replace"
   if 21 - 21: ooOoO0o / iII111i % II111iiii * I1IiiI * II111iiii
   if 40 - 40: Ii1I / i1IIi . iII111i
  lprint ( "{} {} map-cache with {} RLOCs" . format ( O0ooOo0O0ooo0 ,
 green ( OoOOO000O0o . print_eid_tuple ( ) , False ) , len ( I1I11I11 ) ) )
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
   for II11IIiii in OoOOO000O0o . best_rloc_set :
    i111I11I = red ( II11IIiii . rloc . print_address_no_iid ( ) , False )
    lprint ( "Trigger {} to {}" . format ( OOo00o , i111I11I ) )
    lisp_send_map_request ( lisp_sockets , 0 , OoOOO000O0o . eid , OoOOO000O0o . group , II11IIiii )
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
 II1IIIi = lisp_hash_me ( packet , map_register . alg_id , password , False )
 if 40 - 40: i1IIi / OoOoOO00 - I11i / ooOoO0o . Ii1I
 if 8 - 8: I1IiiI . IiII . OOooOOo . O0
 if 3 - 3: Ii1I + i11iIiiIii
 if 87 - 87: ooOoO0o - iII111i % I11i
 map_register . auth_data = II1IIIi
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
  II1IIIi = hmac . new ( password , packet , Ii11i ) . hexdigest ( )
 else :
  II1IIIi = hmac . new ( password , packet , Ii11i ) . digest ( )
  if 18 - 18: ooOoO0o / I1Ii111 . o0oOOo0O0Ooo % OoOoOO00
 return ( II1IIIi )
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
 II1IIIi = lisp_hash_me ( packet , alg_id , password , True )
 I11iIIII1i1i1 = ( II1IIIi == auth_data )
 if 54 - 54: Ii1I % o0oOOo0O0Ooo * I1Ii111 % II111iiii
 if 33 - 33: ooOoO0o % I11i
 if 72 - 72: OoO0O00 % OoooooooOO / II111iiii * oO0o * I1Ii111
 if 98 - 98: OOooOOo * Ii1I + I1ii11iIi11i / iIii1I11I1II1 / OoOoOO00 + I1IiiI
 if ( I11iIIII1i1i1 == False ) :
  lprint ( "Hashed value: {} does not match packet value: {}" . format ( II1IIIi , auth_data ) )
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
 oOiii1IiII = map_notify . etr
 IIIIiI1ii1 = map_notify . etr_port
 if 3 - 3: O0 * O0 + II111iiii + OoOoOO00 * I11i % Oo0Ooo
 if 19 - 19: oO0o % IiII % OoooooooOO % I1ii11iIi11i / OoO0O00
 if 6 - 6: O0 * I1Ii111 - II111iiii
 if 60 - 60: oO0o % oO0o
 if 76 - 76: I1Ii111 / o0oOOo0O0Ooo
 if ( map_notify . retry_count == LISP_MAX_MAP_NOTIFY_RETRIES ) :
  lprint ( "Map-Notify with nonce 0x{} retry limit reached for ETR {}" . format ( map_notify . nonce_key , red ( oOiii1IiII . print_address ( ) , False ) ) )
  if 19 - 19: O0 . i1IIi % iIii1I11I1II1 + OOooOOo * OoOoOO00 / I11i
  if 82 - 82: I1ii11iIi11i
  OOO0OOoOOO = map_notify . nonce_key
  if ( lisp_map_notify_queue . has_key ( OOO0OOoOOO ) ) :
   map_notify . retransmit_timer . cancel ( )
   lprint ( "Dequeue Map-Notify from retransmit queue, key is: {}" . format ( OOO0OOoOOO ) )
   if 75 - 75: I11i - II111iiii
   try :
    lisp_map_notify_queue . pop ( OOO0OOoOOO )
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
 red ( oOiii1IiII . print_address ( ) , False ) , map_notify . retry_count ) )
 if 70 - 70: oO0o . oO0o - IiII
 lisp_send_map_notify ( iIIi1 , map_notify . packet , oOiii1IiII , IIIIiI1ii1 )
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
  OO0OoOo = lisp_rloc_record ( )
  OO0OoOo . store_rloc_entry ( OOOOOoO00 )
  ooooo0oo0O00 += OO0OoOo . encode ( )
  OO0OoOo . print_record ( "  " )
  del ( OO0OoOo )
  if 56 - 56: IiII + OOooOOo
  if 89 - 89: o0oOOo0O0Ooo . Oo0Ooo
  if 48 - 48: o0oOOo0O0Ooo / O0 % i1IIi
  if 82 - 82: OoOoOO00 * Ii1I . I1ii11iIi11i * OoO0O00 % Oo0Ooo
  if 95 - 95: OoO0O00 / oO0o
 for OOOOOoO00 in parent . registered_rlocs :
  oOiii1IiII = OOOOOoO00 . rloc
  Ii1I1i111 = lisp_map_notify ( lisp_sockets )
  Ii1I1i111 . record_count = 1
  oOoO0oO00ooOo = map_register . key_id
  Ii1I1i111 . key_id = oOoO0oO00ooOo
  Ii1I1i111 . alg_id = map_register . alg_id
  Ii1I1i111 . auth_len = map_register . auth_len
  Ii1I1i111 . nonce = map_register . nonce
  Ii1I1i111 . nonce_key = lisp_hex_string ( Ii1I1i111 . nonce )
  Ii1I1i111 . etr . copy_address ( oOiii1IiII )
  Ii1I1i111 . etr_port = map_register . sport
  Ii1I1i111 . site = parent . site
  Ii11iIiiI = Ii1I1i111 . encode ( ooooo0oo0O00 , parent . site . auth_key [ oOoO0oO00ooOo ] )
  Ii1I1i111 . print_notify ( )
  if 49 - 49: IiII % iII111i - O0 * o0oOOo0O0Ooo / OoooooooOO + OoOoOO00
  if 26 - 26: oO0o + i11iIiiIii . IiII + I1ii11iIi11i % IiII
  if 96 - 96: I11i / I1IiiI . i1IIi
  if 67 - 67: i11iIiiIii
  OOO0OOoOOO = Ii1I1i111 . nonce_key
  if ( lisp_map_notify_queue . has_key ( OOO0OOoOOO ) ) :
   iIiiI1i1I1iI = lisp_map_notify_queue [ OOO0OOoOOO ]
   iIiiI1i1I1iI . retransmit_timer . cancel ( )
   del ( iIiiI1i1I1iI )
   if 53 - 53: oO0o
  lisp_map_notify_queue [ OOO0OOoOOO ] = Ii1I1i111
  if 23 - 23: I1ii11iIi11i . I1Ii111 + OOooOOo
  if 4 - 4: I1IiiI
  if 31 - 31: ooOoO0o * i1IIi . O0
  if 5 - 5: OOooOOo . I1ii11iIi11i + ooOoO0o . ooOoO0o + iII111i
  lprint ( "Send merged Map-Notify to ETR {}" . format ( red ( oOiii1IiII . print_address ( ) , False ) ) )
  if 100 - 100: I1Ii111
  lisp_send ( lisp_sockets , oOiii1IiII , LISP_CTRL_PORT , Ii11iIiiI )
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
 OOO0OOoOOO = lisp_hex_string ( nonce ) + source . print_address ( )
 if 50 - 50: I1Ii111 / OoooooooOO . o0oOOo0O0Ooo + I1IiiI * i11iIiiIii
 if 28 - 28: I1Ii111 * II111iiii
 if 14 - 14: iIii1I11I1II1 / Ii1I + o0oOOo0O0Ooo . iII111i % iII111i . i1IIi
 if 67 - 67: IiII * II111iiii + ooOoO0o - i11iIiiIii
 if 15 - 15: I11i
 if 67 - 67: iIii1I11I1II1
 lisp_remove_eid_from_map_notify_queue ( eid_list )
 if ( lisp_map_notify_queue . has_key ( OOO0OOoOOO ) ) :
  Ii1I1i111 = lisp_map_notify_queue [ OOO0OOoOOO ]
  oOOOOOOOoO = red ( source . print_address_no_iid ( ) , False )
  lprint ( "Map-Notify with nonce 0x{} pending for xTR {}" . format ( lisp_hex_string ( Ii1I1i111 . nonce ) , oOOOOOOOoO ) )
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
  OOO0OOoOOO = Ii1I1i111 . nonce_key
  lisp_map_notify_queue [ OOO0OOoOOO ] = Ii1I1i111
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
 Ii11iIiiI = Ii1I1i111 . encode ( eid_records , site . auth_key [ key_id ] )
 Ii1I1i111 . print_notify ( )
 if 4 - 4: OoO0O00
 if ( map_register_ack == False ) :
  OOOO = lisp_eid_record ( )
  OOOO . decode ( eid_records )
  OOOO . print_record ( "  " , False )
  if 65 - 65: Oo0Ooo % O0 / I1Ii111 * IiII - oO0o
  if 32 - 32: Ii1I * OoO0O00 + ooOoO0o
  if 41 - 41: IiII + I11i * ooOoO0o + Oo0Ooo . ooOoO0o
  if 38 - 38: iII111i * OoooooooOO - IiII
  if 36 - 36: I1Ii111 * II111iiii + I1ii11iIi11i - iII111i * iII111i
 lisp_send_map_notify ( lisp_sockets , Ii11iIiiI , Ii1I1i111 . etr , port )
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
 Ii11iIiiI = map_notify . encode ( eid_records , ms . password )
 map_notify . print_notify ( )
 if 82 - 82: OoOoOO00
 if 61 - 61: oO0o . o0oOOo0O0Ooo
 if 82 - 82: Oo0Ooo * OoooooooOO / ooOoO0o / I1IiiI
 if 70 - 70: I1IiiI
 oOiii1IiII = ms . map_server
 lprint ( "Send Map-Notify-Ack to {}" . format (
 red ( oOiii1IiII . print_address ( ) , False ) ) )
 lisp_send ( lisp_sockets , oOiii1IiII , LISP_CTRL_PORT , Ii11iIiiI )
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
 OOO0OOoOOO = Ii1I1i111 . nonce_key
 if 30 - 30: OoOoOO00 - OOooOOo . Oo0Ooo
 if 11 - 11: IiII - I1Ii111 - OoO0O00 * o0oOOo0O0Ooo
 if 99 - 99: O0 - OoO0O00
 if 95 - 95: Ii1I . IiII * o0oOOo0O0Ooo
 if 91 - 91: I1Ii111
 if 49 - 49: I11i
 lisp_remove_eid_from_map_notify_queue ( Ii1I1i111 . eid_list )
 if ( lisp_map_notify_queue . has_key ( OOO0OOoOOO ) ) :
  Ii1I1i111 = lisp_map_notify_queue [ OOO0OOoOOO ]
  lprint ( "Map-Notify with nonce 0x{} pending for ITR {}" . format ( Ii1I1i111 . nonce , red ( xtr . print_address_no_iid ( ) , False ) ) )
  if 17 - 17: Oo0Ooo % o0oOOo0O0Ooo
  return
  if 3 - 3: OoO0O00 . oO0o . oO0o . Ii1I
  if 100 - 100: i11iIiiIii / i1IIi . I1ii11iIi11i
  if 1 - 1: IiII * I1Ii111 / I1ii11iIi11i * i11iIiiIii
  if 82 - 82: o0oOOo0O0Ooo * OoO0O00 / o0oOOo0O0Ooo % OoOoOO00 * iIii1I11I1II1 % O0
  if 10 - 10: ooOoO0o
 lisp_map_notify_queue [ OOO0OOoOOO ] = Ii1I1i111
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
 OOOO = lisp_eid_record ( )
 OOOO . record_ttl = 1440
 OOOO . eid . copy_address ( site_eid . eid )
 OOOO . group . copy_address ( site_eid . group )
 OOOO . rloc_count = 0
 for IiIiI in site_eid . registered_rlocs :
  if ( oO0oo000O ^ IiIiI . is_rtr ( ) ) : continue
  OOOO . rloc_count += 1
  if 57 - 57: oO0o + O0 - OoOoOO00
 Ii11iIiiI = OOOO . encode ( )
 if 14 - 14: II111iiii + i11iIiiIii + Ii1I / o0oOOo0O0Ooo . OoO0O00
 if 93 - 93: o0oOOo0O0Ooo + i1IIi
 if 24 - 24: i1IIi
 if 54 - 54: iIii1I11I1II1 - IiII + o0oOOo0O0Ooo + I1ii11iIi11i + IiII
 Ii1I1i111 . print_notify ( )
 OOOO . print_record ( "  " , False )
 if 99 - 99: Oo0Ooo
 if 38 - 38: I1ii11iIi11i - I1IiiI
 if 50 - 50: iII111i % OoO0O00 - oO0o + Oo0Ooo . O0 . iII111i
 if 42 - 42: iII111i + I1ii11iIi11i
 for IiIiI in site_eid . registered_rlocs :
  if ( oO0oo000O ^ IiIiI . is_rtr ( ) ) : continue
  OO0OoOo = lisp_rloc_record ( )
  OO0OoOo . store_rloc_entry ( IiIiI )
  Ii11iIiiI += OO0OoOo . encode ( )
  OO0OoOo . print_record ( "    " )
  if 44 - 44: I1ii11iIi11i % IiII
  if 1 - 1: Oo0Ooo + IiII - I1Ii111 / I1Ii111
  if 25 - 25: OoOoOO00
  if 52 - 52: OOooOOo + IiII
  if 73 - 73: OoooooooOO - I1Ii111 % iII111i / OOooOOo . o0oOOo0O0Ooo - IiII
 Ii11iIiiI = Ii1I1i111 . encode ( Ii11iIiiI , "" )
 if ( Ii11iIiiI == None ) : return
 if 69 - 69: Ii1I . iIii1I11I1II1 / Oo0Ooo * Oo0Ooo % IiII
 if 5 - 5: OOooOOo - I1Ii111 + IiII
 if 82 - 82: OOooOOo
 if 26 - 26: ooOoO0o + OoooooooOO + ooOoO0o * I1Ii111
 lisp_send_map_notify ( lisp_sockets , Ii11iIiiI , xtr , LISP_CTRL_PORT )
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
    for IiIiI in OoOo0OOoOOO00 . registered_rlocs :
     if ( IiIiI . is_rtr ( ) == False ) : continue
     iII11I1IiIii [ IiIiI . rloc . print_address ( ) ] = IiIiI
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
   OOo0 = [ ]
   OOoOO0 = [ ] if len ( iIooo00OoO0 ) == 0 else iIooo00OoO0 [ 0 ] . rle . rle_nodes
   if 69 - 69: OoOoOO00 * Ii1I % OoooooooOO % OOooOOo * OoOoOO00
   for O00o000O0O0oO in OOoOO0 :
    oo000oOoO . append ( O00o000O0O0oO . address )
    OOo0 . append ( O00o000O0O0oO . address . print_address_no_iid ( ) )
    if 20 - 20: IiII
   lprint ( "Notify existing RLE-nodes {}" . format ( OOo0 ) )
  else :
   if 17 - 17: o0oOOo0O0Ooo % iIii1I11I1II1
   if 66 - 66: OoooooooOO + IiII . II111iiii
   if 66 - 66: iIii1I11I1II1 % I11i
   if 38 - 38: I1ii11iIi11i * ooOoO0o
   if 77 - 77: OOooOOo - i11iIiiIii - I1ii11iIi11i
   for IiIiI in iIooo00OoO0 :
    if ( IiIiI . is_rtr ( ) ) : oo000oOoO . append ( IiIiI . rloc )
    if 94 - 94: OoO0O00 % iII111i - I1Ii111 + OoO0O00 - I1IiiI
    if 65 - 65: OOooOOo
    if 90 - 90: O0
    if 91 - 91: O0 * OoOoOO00 - OoOoOO00 * II111iiii - iII111i
    if 38 - 38: oO0o * I11i % OOooOOo
   O000oooooOO = ( len ( oo000oOoO ) != 0 )
   if ( O000oooooOO == False ) :
    O0OO = lisp_site_eid_lookup ( iIiiIi1111ii [ 0 ] , OoOOo , False )
    if ( O0OO == None ) : continue
    if 80 - 80: O0 % II111iiii / O0 . Oo0Ooo * OoOoOO00 + OOooOOo
    for IiIiI in O0OO . registered_rlocs :
     if ( IiIiI . rloc . is_null ( ) ) : continue
     oo000oOoO . append ( IiIiI . rloc )
     if 47 - 47: Ii1I - Oo0Ooo * OoOoOO00
     if 20 - 20: oO0o
     if 48 - 48: I1IiiI % OoO0O00
     if 33 - 33: Ii1I
     if 73 - 73: Ii1I . IiII
     if 43 - 43: I11i . IiII - iII111i * I1IiiI * iII111i
   if ( len ( oo000oOoO ) == 0 ) :
    lprint ( "No ITRs or RTRs found for {}, Map-Notify suppressed" . format ( green ( O000oOo . print_eid_tuple ( ) , False ) ) )
    if 90 - 90: i11iIiiIii * i1IIi
    continue
    if 88 - 88: i11iIiiIii - OoOoOO00
    if 53 - 53: iIii1I11I1II1 % I1Ii111 / Oo0Ooo % Oo0Ooo
    if 6 - 6: iII111i
    if 44 - 44: oO0o
    if 23 - 23: I1IiiI + iIii1I11I1II1 . iII111i + OOooOOo - OoO0O00 + i1IIi
    if 60 - 60: i11iIiiIii + Oo0Ooo * OoOoOO00 . iII111i - iIii1I11I1II1 * IiII
  for OOOOOoO00 in oo000oOoO :
   lprint ( "Build Map-Notify to {}TR {} for {}" . format ( "R" if O000oooooOO else "x" , red ( OOOOOoO00 . print_address_no_iid ( ) , False ) ,
   # OOooOOo . o0oOOo0O0Ooo + OoOoOO00 % I1ii11iIi11i
 green ( O000oOo . print_eid_tuple ( ) , False ) ) )
   if 51 - 51: i1IIi / OoO0O00 + Oo0Ooo - OOooOOo
   oO0o0 = [ O000oOo . print_eid_tuple ( ) ]
   lisp_send_multicast_map_notify ( lisp_sockets , O000oOo , oO0o0 , OOOOOoO00 )
   time . sleep ( .001 )
   if 95 - 95: IiII + iII111i / Oo0Ooo - iIii1I11I1II1
   if 100 - 100: i1IIi % OoooooooOO + O0 - OoO0O00 / ooOoO0o % II111iiii
 return
 if 54 - 54: II111iiii / I1IiiI % iII111i - iII111i % OoO0O00 - OoO0O00
 if 33 - 33: OoooooooOO % i1IIi % I1Ii111 . OoO0O00
 if 24 - 24: i1IIi . iII111i * iIii1I11I1II1 . I11i % I1ii11iIi11i + i11iIiiIii
 if 28 - 28: OoO0O00 . I1ii11iIi11i / O0
 if 35 - 35: O0 . oO0o % OoOoOO00 * O0 - IiII
 if 63 - 63: ooOoO0o
 if 17 - 17: O0 - iII111i - OOooOOo + iII111i - o0oOOo0O0Ooo
 if 90 - 90: O0 / OoO0O00 * O0 % OoOoOO00 + OoooooooOO
def lisp_find_sig_in_rloc_set ( packet , rloc_count ) :
 for oo0O0oO0O0O in range ( rloc_count ) :
  OO0OoOo = lisp_rloc_record ( )
  packet = OO0OoOo . decode ( packet , None )
  o0I1 = OO0OoOo . json
  if ( o0I1 == None ) : continue
  if 75 - 75: ooOoO0o . oO0o . OoOoOO00
  try :
   o0I1 = json . loads ( o0I1 . json_string )
  except :
   lprint ( "Found corrupted JSON signature" )
   continue
   if 72 - 72: I11i % ooOoO0o / O0 . O0
   if 7 - 7: O0 * I1ii11iIi11i + Ii1I + oO0o % oO0o
  if ( o0I1 . has_key ( "signature" ) == False ) : continue
  return ( OO0OoOo )
  if 47 - 47: oO0o * I1ii11iIi11i
 return ( None )
 if 85 - 85: OoooooooOO * I1ii11iIi11i + i11iIiiIii . iII111i * II111iiii / oO0o
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
def lisp_get_eid_hash ( eid ) :
 IiI1I1 = None
 for iI1iI in lisp_eid_hashes :
  if 88 - 88: OoO0O00 / II111iiii
  if 27 - 27: OOooOOo - i1IIi + O0 . I1Ii111 % I11i . I1ii11iIi11i
  if 80 - 80: I1IiiI - i11iIiiIii
  if 39 - 39: I11i / O0 - I1ii11iIi11i . Oo0Ooo * OoooooooOO / o0oOOo0O0Ooo
  II1ii1ii11I1 = iI1iI . instance_id
  if ( II1ii1ii11I1 == - 1 ) : iI1iI . instance_id = eid . instance_id
  if 71 - 71: O0 . OoooooooOO + Oo0Ooo . ooOoO0o / Ii1I
  oOooOO = eid . is_more_specific ( iI1iI )
  iI1iI . instance_id = II1ii1ii11I1
  if ( oOooOO ) :
   IiI1I1 = 128 - iI1iI . mask_len
   break
   if 68 - 68: I1Ii111 % Ii1I * Oo0Ooo - O0 . IiII
   if 1 - 1: I1ii11iIi11i
 if ( IiI1I1 == None ) : return ( None )
 if 18 - 18: i11iIiiIii % OoO0O00 % OOooOOo . OOooOOo * Ii1I / II111iiii
 I1IIIIIi1IIiI = eid . address
 o0o00OOO00o = ""
 for oo0O0oO0O0O in range ( 0 , IiI1I1 / 16 ) :
  oOo00Ooo0o0 = I1IIIIIi1IIiI & 0xffff
  oOo00Ooo0o0 = hex ( oOo00Ooo0o0 ) [ 2 : - 1 ]
  o0o00OOO00o = oOo00Ooo0o0 . zfill ( 4 ) + ":" + o0o00OOO00o
  I1IIIIIi1IIiI >>= 16
  if 95 - 95: I1Ii111 . I1IiiI . II111iiii - Ii1I / ooOoO0o
 if ( IiI1I1 % 16 != 0 ) :
  oOo00Ooo0o0 = I1IIIIIi1IIiI & 0xff
  oOo00Ooo0o0 = hex ( oOo00Ooo0o0 ) [ 2 : - 1 ]
  o0o00OOO00o = oOo00Ooo0o0 . zfill ( 2 ) + ":" + o0o00OOO00o
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
 II1ii1ii11I1 = eid . instance_id
 if 84 - 84: ooOoO0o . O0 + I1IiiI * OoO0O00 - I1IiiI
 if 24 - 24: Ii1I
 if 23 - 23: Oo0Ooo * i1IIi / I1IiiI . I11i - I1ii11iIi11i . iIii1I11I1II1
 if 15 - 15: O0 + o0oOOo0O0Ooo / oO0o
 if 27 - 27: Ii1I * II111iiii / oO0o
 O000O0 = lisp_get_eid_hash ( eid )
 if ( O000O0 == None ) : return ( [ None , None , False ] )
 if 65 - 65: o0oOOo0O0Ooo
 O000O0 = "hash-" + O000O0
 i11i = lisp_address ( LISP_AFI_NAME , O000O0 , len ( O000O0 ) , II1ii1ii11I1 )
 IiI1111i1i11I = lisp_address ( LISP_AFI_NONE , "" , 0 , II1ii1ii11I1 )
 if 77 - 77: i1IIi . Oo0Ooo . oO0o + oO0o - i11iIiiIii + I1ii11iIi11i
 if 86 - 86: ooOoO0o . ooOoO0o . OoooooooOO - OoOoOO00 % oO0o
 if 81 - 81: Oo0Ooo . OoooooooOO
 if 15 - 15: I1Ii111 - I11i * I1IiiI % o0oOOo0O0Ooo
 O0OO = lisp_site_eid_lookup ( i11i , IiI1111i1i11I , True )
 if ( O0OO == None ) : return ( [ i11i , None , False ] )
 if 75 - 75: oO0o % OoooooooOO % i11iIiiIii . iII111i
 if 95 - 95: i11iIiiIii . Ii1I / II111iiii + II111iiii + Ii1I / I11i
 if 72 - 72: I1Ii111 . I1Ii111 * O0 + I1ii11iIi11i / Oo0Ooo
 if 96 - 96: oO0o . ooOoO0o * Oo0Ooo % ooOoO0o + I1Ii111 + iIii1I11I1II1
 i11I1i111i = None
 for II11IIiii in O0OO . registered_rlocs :
  iIi1IOoOoO = II11IIiii . json
  if ( iIi1IOoOoO == None ) : continue
  try :
   iIi1IOoOoO = json . loads ( iIi1IOoOoO . json_string )
  except :
   lprint ( "Registered RLOC JSON format is invalid for {}" . format ( O000O0 ) )
   if 30 - 30: iII111i
   return ( [ i11i , None , False ] )
   if 42 - 42: O0 . OoooooooOO + Oo0Ooo
  if ( iIi1IOoOoO . has_key ( "public-key" ) == False ) : continue
  i11I1i111i = iIi1IOoOoO [ "public-key" ]
  break
  if 34 - 34: OOooOOo / I11i / OoooooooOO + i11iIiiIii / II111iiii - O0
 return ( [ i11i , i11I1i111i , True ] )
 if 37 - 37: i1IIi . oO0o * o0oOOo0O0Ooo + I1ii11iIi11i - OoO0O00
 if 62 - 62: I11i * oO0o
 if 91 - 91: I1Ii111
 if 77 - 77: I1ii11iIi11i . ooOoO0o - iIii1I11I1II1 + Ii1I % II111iiii * II111iiii
 if 41 - 41: II111iiii + Oo0Ooo - IiII / I1Ii111 - OOooOOo . oO0o
 if 100 - 100: ooOoO0o / I1ii11iIi11i * OoOoOO00 . I1ii11iIi11i . o0oOOo0O0Ooo * iIii1I11I1II1
 if 15 - 15: iII111i + o0oOOo0O0Ooo / IiII
 if 33 - 33: OoooooooOO . IiII * o0oOOo0O0Ooo
def lisp_verify_cga_sig ( eid , rloc_record ) :
 if 41 - 41: Ii1I . iII111i . o0oOOo0O0Ooo % OoooooooOO % IiII
 if 81 - 81: IiII * i11iIiiIii + i1IIi + OOooOOo . i1IIi
 if 6 - 6: i11iIiiIii - oO0o % OoO0O00 + iIii1I11I1II1
 if 69 - 69: IiII
 if 13 - 13: i11iIiiIii
 IIIIi1I = json . loads ( rloc_record . json . json_string )
 if 49 - 49: OoOoOO00
 if ( lisp_get_eid_hash ( eid ) ) :
  O000o0O0 = eid
 elif ( IIIIi1I . has_key ( "signature-eid" ) ) :
  O0o0o = IIIIi1I [ "signature-eid" ]
  O000o0O0 = lisp_address ( LISP_AFI_IPV6 , O0o0o , 0 , 0 )
 else :
  lprint ( "  No signature-eid found in RLOC-record" )
  return ( False )
  if 85 - 85: iIii1I11I1II1 * o0oOOo0O0Ooo / OoOoOO00 % I1ii11iIi11i
  if 31 - 31: OOooOOo
  if 64 - 64: OoOoOO00 + I1ii11iIi11i - OoooooooOO + I11i + i1IIi
  if 72 - 72: I1Ii111 * OoOoOO00
  if 5 - 5: O0 - i11iIiiIii % Ii1I + ooOoO0o % I1Ii111
 i11i , i11I1i111i , IiII1 = lisp_lookup_public_key ( O000o0O0 )
 if ( i11i == None ) :
  O0o0O0OO0o = green ( O000o0O0 . print_address ( ) , False )
  lprint ( "  Could not parse hash in EID {}" . format ( O0o0O0OO0o ) )
  return ( False )
  if 16 - 16: Oo0Ooo - O0 % OoO0O00 - I1Ii111
  if 82 - 82: OoOoOO00 - OOooOOo . i1IIi / I11i
 IiiiIiI1 = "found" if IiII1 else bold ( "not found" , False )
 O0o0O0OO0o = green ( i11i . print_address ( ) , False )
 lprint ( "  Lookup for crypto-hashed EID {} {}" . format ( O0o0O0OO0o , IiiiIiI1 ) )
 if ( IiII1 == False ) : return ( False )
 if 72 - 72: iIii1I11I1II1 % iIii1I11I1II1 . OoOoOO00 * OoooooooOO * OoO0O00
 if ( i11I1i111i == None ) :
  lprint ( "  RLOC-record with public-key not found" )
  return ( False )
  if 26 - 26: Ii1I * I1IiiI % ooOoO0o / I1Ii111
  if 80 - 80: I1Ii111 / O0 * O0
 IIiIiII1i = i11I1i111i [ 0 : 8 ] + "..." + i11I1i111i [ - 8 : : ]
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
 i11I1i111i = binascii . a2b_base64 ( i11I1i111i )
 try :
  OOO0OOoOOO = ecdsa . VerifyingKey . from_pem ( i11I1i111i )
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
  ii1ii = OOO0OOoOOO . verify ( IIIIi1I , o000o0O , hashfunc = hashlib . sha256 )
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
 I11IIIIiII = socket . ntohl ( struct . unpack ( "I" , packet [ 0 : 4 ] ) [ 0 ] )
 O00ooo0oo = ( I11IIIIiII >> 13 ) & 0x1
 if ( O00ooo0oo == 0 ) : return ( packet )
 if 25 - 25: oO0o . OoO0O00 + OoO0O00
 I1i1i1ii1 = ( I11IIIIiII >> 14 ) & 0x7
 if 93 - 93: OOooOOo / iIii1I11I1II1 % OoO0O00 + iII111i
 if 66 - 66: I1Ii111 + ooOoO0o
 if 58 - 58: i1IIi % OoO0O00 % I1IiiI * O0 . Ii1I / OoO0O00
 if 97 - 97: IiII
 try :
  O000oOooOoO0 = lisp_ms_encryption_keys [ I1i1i1ii1 ]
  O000oOooOoO0 = O000oOooOoO0 . zfill ( 32 )
  o0OOo0O = "0" * 8
 except :
  lprint ( "Cannot decrypt Map-Register with key-id {}" . format ( I1i1i1ii1 ) )
  return ( None )
  if 49 - 49: OoO0O00 / iII111i
  if 22 - 22: I11i + II111iiii * iIii1I11I1II1 % OOooOOo
 OooOo = bold ( "Decrypt" , False )
 lprint ( "{} Map-Register with key-id {}" . format ( OooOo , I1i1i1ii1 ) )
 if 7 - 7: I11i - OOooOOo + I1IiiI + IiII . I1Ii111
 iI1oOoo = chacha . ChaCha ( O000oOooOoO0 , o0OOo0O ) . decrypt ( packet [ 4 : : ] )
 return ( packet [ 0 : 4 ] + iI1oOoo )
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
 O00o0 = [ ]
 if 9 - 9: O0 / I1ii11iIi11i . iII111i . O0 + IiII % I11i
 if 27 - 27: i11iIiiIii - I1ii11iIi11i / O0 - i1IIi + I1IiiI * iII111i
 if 26 - 26: Oo0Ooo . Ii1I
 if 7 - 7: OoOoOO00 - o0oOOo0O0Ooo + oO0o
 iiiOO0Oo = None
 iIiIiIIII11iI1 = packet
 IiIIi1111I = [ ]
 oooOOoO0oo0 = i1I11II11iIi1 . record_count
 for oo0O0oO0O0O in range ( oooOOoO0oo0 ) :
  OOOO = lisp_eid_record ( )
  OO0OoOo = lisp_rloc_record ( )
  packet = OOOO . decode ( packet )
  if ( packet == None ) :
   lprint ( "Could not decode EID-record in Map-Register packet" )
   return
   if 63 - 63: o0oOOo0O0Ooo * IiII - i1IIi / i11iIiiIii . I1IiiI
  OOOO . print_record ( "  " , False )
  if 22 - 22: II111iiii / iII111i
  if 18 - 18: i11iIiiIii * ooOoO0o . I1IiiI + i1IIi + I11i
  if 62 - 62: O0 % o0oOOo0O0Ooo + iIii1I11I1II1 + iIii1I11I1II1 * ooOoO0o
  if 21 - 21: o0oOOo0O0Ooo % O0
  O0OO = lisp_site_eid_lookup ( OOOO . eid , OOOO . group ,
 False )
  if 81 - 81: i1IIi + i1IIi
  I1O00o0OO0o0Oo0 = O0OO . print_eid_tuple ( ) if O0OO else None
  if 24 - 24: iII111i / OoOoOO00 + O0
  if 14 - 14: OoO0O00
  if 11 - 11: ooOoO0o * IiII * I1Ii111 * ooOoO0o
  if 92 - 92: I1IiiI
  if 94 - 94: OoOoOO00 % OoOoOO00 . i11iIiiIii
  if 40 - 40: II111iiii - iII111i * iIii1I11I1II1
  if 48 - 48: iII111i * OoO0O00
  if ( O0OO and O0OO . accept_more_specifics == False ) :
   if ( O0OO . eid_record_matches ( OOOO ) == False ) :
    o0OoOOO = O0OO . parent_for_more_specifics
    if ( o0OoOOO ) : O0OO = o0OoOOO
    if 57 - 57: iII111i % iII111i / Oo0Ooo + i11iIiiIii * I11i
    if 98 - 98: I11i - II111iiii . IiII % Oo0Ooo
    if 65 - 65: OoO0O00
    if 65 - 65: oO0o
    if 77 - 77: I11i * i1IIi - OOooOOo / OoOoOO00
    if 50 - 50: O0 - oO0o . oO0o
    if 98 - 98: IiII % Ii1I / Ii1I
    if 10 - 10: Ii1I
  O0oo0Oo0Oo00o = ( O0OO and O0OO . accept_more_specifics )
  if ( O0oo0Oo0Oo00o ) :
   OoOoo0 = lisp_site_eid ( O0OO . site )
   OoOoo0 . dynamic = True
   OoOoo0 . eid . copy_address ( OOOO . eid )
   OoOoo0 . group . copy_address ( OOOO . group )
   OoOoo0 . parent_for_more_specifics = O0OO
   OoOoo0 . add_cache ( )
   OoOoo0 . inherit_from_ams_parent ( )
   O0OO . more_specific_registrations . append ( OoOoo0 )
   O0OO = OoOoo0
  else :
   O0OO = lisp_site_eid_lookup ( OOOO . eid , OOOO . group ,
 True )
   if 21 - 21: O0 + ooOoO0o
   if 53 - 53: Ii1I - II111iiii * iIii1I11I1II1
  O0o0O0OO0o = OOOO . print_eid_tuple ( )
  if 91 - 91: OoOoOO00 % iIii1I11I1II1
  if ( O0OO == None ) :
   ii1111I1II1 = bold ( "Site not found" , False )
   lprint ( "  {} for EID {}{}" . format ( ii1111I1II1 , green ( O0o0O0OO0o , False ) ,
 ", matched non-ams {}" . format ( green ( I1O00o0OO0o0Oo0 , False ) if I1O00o0OO0o0Oo0 else "" ) ) )
   if 81 - 81: i11iIiiIii / OoOoOO00 + iIii1I11I1II1
   if 65 - 65: o0oOOo0O0Ooo
   if 73 - 73: I11i . I1ii11iIi11i - OoO0O00 + OoooooooOO
   if 71 - 71: I1IiiI
   if 27 - 27: OoO0O00 + i1IIi * OoooooooOO * iIii1I11I1II1 - Ii1I
   packet = OO0OoOo . end_of_rlocs ( packet , OOOO . rloc_count )
   if ( packet == None ) :
    lprint ( "  Could not decode RLOC-record in Map-Register packet" )
    return
    if 85 - 85: OoO0O00 + II111iiii / OoO0O00 . II111iiii * OoOoOO00 * I1IiiI
   continue
   if 19 - 19: iII111i / Ii1I + iIii1I11I1II1 * O0 - Oo0Ooo
   if 47 - 47: iIii1I11I1II1 % I1ii11iIi11i
  iiiOO0Oo = O0OO . site
  if 33 - 33: oO0o . oO0o / IiII + II111iiii
  if ( O0oo0Oo0Oo00o ) :
   ooOoOOOOo = O0OO . parent_for_more_specifics . print_eid_tuple ( )
   lprint ( "  Found ams {} for site '{}' for registering prefix {}" . format ( green ( ooOoOOOOo , False ) , iiiOO0Oo . site_name , green ( O0o0O0OO0o , False ) ) )
   if 34 - 34: OoO0O00 . OoOoOO00 / i1IIi / OOooOOo
  else :
   ooOoOOOOo = green ( O0OO . print_eid_tuple ( ) , False )
   lprint ( "  Found {} for site '{}' for registering prefix {}" . format ( ooOoOOOOo , iiiOO0Oo . site_name , green ( O0o0O0OO0o , False ) ) )
   if 12 - 12: o0oOOo0O0Ooo . Oo0Ooo / II111iiii
   if 18 - 18: I1Ii111 % II111iiii + Ii1I * Oo0Ooo - OoooooooOO . Oo0Ooo
   if 25 - 25: OoO0O00
   if 83 - 83: II111iiii . iIii1I11I1II1
   if 77 - 77: O0 . OoOoOO00 % oO0o / OOooOOo
   if 8 - 8: iII111i - i1IIi
  if ( iiiOO0Oo . shutdown ) :
   lprint ( ( "  Rejecting registration for site '{}', configured in " +
 "admin-shutdown state" ) . format ( iiiOO0Oo . site_name ) )
   packet = OO0OoOo . end_of_rlocs ( packet , OOOO . rloc_count )
   continue
   if 81 - 81: ooOoO0o / OOooOOo % OoOoOO00 . iIii1I11I1II1
   if 45 - 45: I1IiiI . ooOoO0o - OoooooooOO
   if 84 - 84: I1ii11iIi11i
   if 69 - 69: I1Ii111 + II111iiii
   if 92 - 92: OoooooooOO
   if 80 - 80: I1ii11iIi11i % I1ii11iIi11i . OoO0O00 . oO0o % I1IiiI % I11i
   if 4 - 4: OoO0O00 / iII111i / I1ii11iIi11i - o0oOOo0O0Ooo * I1Ii111
   if 24 - 24: OoooooooOO / ooOoO0o + Oo0Ooo - OOooOOo - o0oOOo0O0Ooo . I1ii11iIi11i
  oOoO0oO00ooOo = i1I11II11iIi1 . key_id
  if ( iiiOO0Oo . auth_key . has_key ( oOoO0oO00ooOo ) == False ) : oOoO0oO00ooOo = 0
  IiIIIIi11i = iiiOO0Oo . auth_key [ oOoO0oO00ooOo ]
  if 91 - 91: O0 . o0oOOo0O0Ooo * OoO0O00 * I1Ii111 % I11i / OoOoOO00
  ooOoOO00o0O = lisp_verify_auth ( oOoo0O000 , i1I11II11iIi1 . alg_id ,
 i1I11II11iIi1 . auth_data , IiIIIIi11i )
  I11IIi1iI = "dynamic " if O0OO . dynamic else ""
  if 71 - 71: Ii1I - o0oOOo0O0Ooo - oO0o
  Oo00o = bold ( "passed" if ooOoOO00o0O else "failed" , False )
  oOoO0oO00ooOo = "key-id {}" . format ( oOoO0oO00ooOo ) if oOoO0oO00ooOo == i1I11II11iIi1 . key_id else "bad key-id {}" . format ( i1I11II11iIi1 . key_id )
  if 27 - 27: O0 - iIii1I11I1II1
  lprint ( "  Authentication {} for {}EID-prefix {}, {}" . format ( Oo00o , I11IIi1iI , green ( O0o0O0OO0o , False ) , oOoO0oO00ooOo ) )
  if 78 - 78: Oo0Ooo / o0oOOo0O0Ooo
  if 35 - 35: o0oOOo0O0Ooo . OoO0O00 / o0oOOo0O0Ooo / IiII - I1ii11iIi11i . Oo0Ooo
  if 97 - 97: i11iIiiIii + I1ii11iIi11i - I11i . oO0o
  if 76 - 76: IiII * II111iiii * I1ii11iIi11i + OoooooooOO - OoOoOO00 . Ii1I
  if 51 - 51: II111iiii % I1Ii111 * O0 . ooOoO0o * OoOoOO00
  if 17 - 17: I1IiiI % I11i
  iIii1II111Ii = True
  iiIiII11I = ( lisp_get_eid_hash ( OOOO . eid ) != None )
  if ( iiIiII11I or O0OO . require_signature ) :
   oOOo0000Oo = "Required " if O0OO . require_signature else ""
   O0o0O0OO0o = green ( O0o0O0OO0o , False )
   II11IIiii = lisp_find_sig_in_rloc_set ( packet , OOOO . rloc_count )
   if ( II11IIiii == None ) :
    iIii1II111Ii = False
    lprint ( ( "  {}EID-crypto-hash signature verification {} " + "for EID-prefix {}, no signature found" ) . format ( oOOo0000Oo ,
    # iII111i / i11iIiiIii % OOooOOo + Ii1I . Oo0Ooo
 bold ( "failed" , False ) , O0o0O0OO0o ) )
   else :
    iIii1II111Ii = lisp_verify_cga_sig ( OOOO . eid , II11IIiii )
    Oo00o = bold ( "passed" if iIii1II111Ii else "failed" , False )
    lprint ( ( "  {}EID-crypto-hash signature verification {} " + "for EID-prefix {}" ) . format ( oOOo0000Oo , Oo00o , O0o0O0OO0o ) )
    if 16 - 16: oO0o / Ii1I % i11iIiiIii % I1IiiI * I1ii11iIi11i
    if 4 - 4: iIii1I11I1II1 + Ii1I % I1Ii111 . OoOoOO00 % OoooooooOO + II111iiii
    if 48 - 48: ooOoO0o + ooOoO0o
    if 95 - 95: iIii1I11I1II1 / i11iIiiIii - IiII - OOooOOo
  if ( ooOoOO00o0O == False or iIii1II111Ii == False ) :
   packet = OO0OoOo . end_of_rlocs ( packet , OOOO . rloc_count )
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
   o0OoOOO = O0OO
   o0OoOOO . inconsistent_registration = False
   if 27 - 27: i1IIi + oO0o / I1ii11iIi11i + oO0o
   if 98 - 98: II111iiii + iIii1I11I1II1
   if 70 - 70: I11i / OoooooooOO / i11iIiiIii
   if 61 - 61: O0 . Oo0Ooo . iIii1I11I1II1
   if 54 - 54: OOooOOo * I1ii11iIi11i + OoooooooOO
   if ( O0OO . group . is_null ( ) ) :
    if ( o0OoOOO . site_id != i1I11II11iIi1 . site_id ) :
     o0OoOOO . site_id = i1I11II11iIi1 . site_id
     o0OoOOO . registered = False
     o0OoOOO . individual_registrations = { }
     o0OoOOO . registered_rlocs = [ ]
     lisp_registered_count -= 1
     if 58 - 58: i1IIi - OoooooooOO * OOooOOo . ooOoO0o + O0 + o0oOOo0O0Ooo
     if 87 - 87: OOooOOo + I1Ii111 + O0 / oO0o / i11iIiiIii
     if 60 - 60: O0 . II111iiii
   OOO0OOoOOO = source . address + i1I11II11iIi1 . xtr_id
   if ( O0OO . individual_registrations . has_key ( OOO0OOoOOO ) ) :
    O0OO = O0OO . individual_registrations [ OOO0OOoOOO ]
   else :
    O0OO = lisp_site_eid ( iiiOO0Oo )
    O0OO . eid . copy_address ( o0OoOOO . eid )
    O0OO . group . copy_address ( o0OoOOO . group )
    o0OoOOO . individual_registrations [ OOO0OOoOOO ] = O0OO
    if 69 - 69: II111iiii / ooOoO0o - OoOoOO00 / OOooOOo
  else :
   O0OO . inconsistent_registration = O0OO . merge_register_requested
   if 52 - 52: OoO0O00 % I11i + o0oOOo0O0Ooo % OoOoOO00
   if 46 - 46: o0oOOo0O0Ooo % O0
   if 30 - 30: oO0o
  O0OO . map_registers_received += 1
  if 64 - 64: O0
  if 70 - 70: oO0o % I1IiiI . iIii1I11I1II1 - Oo0Ooo + OoOoOO00 % O0
  if 91 - 91: I1Ii111 - oO0o * ooOoO0o - I1ii11iIi11i + IiII + O0
  if 18 - 18: OoOoOO00 / IiII / o0oOOo0O0Ooo . OOooOOo
  if 35 - 35: I11i . ooOoO0o % I11i / iII111i / O0 % I11i
  ooOOoo0o = ( O0OO . is_rloc_in_rloc_set ( source ) == False )
  if ( OOOO . record_ttl == 0 and ooOOoo0o ) :
   lprint ( "  Ignore deregistration request from {}" . format ( red ( source . print_address_no_iid ( ) , False ) ) )
   if 29 - 29: I1Ii111 + Ii1I
   continue
   if 100 - 100: Ii1I + I1Ii111 / iIii1I11I1II1 / i1IIi % OoOoOO00
   if 6 - 6: oO0o + ooOoO0o
   if 13 - 13: Oo0Ooo . IiII % iII111i + i1IIi / OOooOOo
   if 1 - 1: I11i * i1IIi * Oo0Ooo % O0
   if 41 - 41: OOooOOo % OoOoOO00
   if 82 - 82: I11i . IiII
  I11iiiIIi1 = O0OO . registered_rlocs
  O0OO . registered_rlocs = [ ]
  if 80 - 80: Oo0Ooo + oO0o
  if 76 - 76: I1IiiI * OoooooooOO - i11iIiiIii / I11i / Oo0Ooo
  if 82 - 82: IiII % ooOoO0o
  if 100 - 100: Oo0Ooo . oO0o - iII111i + OoooooooOO
  IIOoO0OOOo0O0O0 = packet
  for iIIi11i1i1I1I in range ( OOOO . rloc_count ) :
   OO0OoOo = lisp_rloc_record ( )
   packet = OO0OoOo . decode ( packet , None )
   if ( packet == None ) :
    lprint ( "  Could not decode RLOC-record in Map-Register packet" )
    return
    if 30 - 30: i11iIiiIii - I11i * ooOoO0o + iII111i % I1Ii111
   OO0OoOo . print_record ( "    " )
   if 1 - 1: iIii1I11I1II1 % i11iIiiIii - i11iIiiIii % II111iiii
   if 89 - 89: iII111i . OoO0O00 . iII111i
   if 35 - 35: oO0o - ooOoO0o
   if 4 - 4: Oo0Ooo - IiII - I11i
   if ( len ( iiiOO0Oo . allowed_rlocs ) > 0 ) :
    i111I11I = OO0OoOo . rloc . print_address ( )
    if ( iiiOO0Oo . allowed_rlocs . has_key ( i111I11I ) == False ) :
     lprint ( ( "  Reject registration, RLOC {} not " + "configured in allowed RLOC-set" ) . format ( red ( i111I11I , False ) ) )
     if 72 - 72: OoooooooOO
     if 19 - 19: Oo0Ooo . OOooOOo
     O0OO . registered = False
     packet = OO0OoOo . end_of_rlocs ( packet ,
 OOOO . rloc_count - iIIi11i1i1I1I - 1 )
     break
     if 58 - 58: IiII % iII111i + i1IIi % I1IiiI % OOooOOo . iII111i
     if 85 - 85: i11iIiiIii . o0oOOo0O0Ooo * iII111i . I1ii11iIi11i / I1Ii111 % Ii1I
     if 27 - 27: II111iiii . iIii1I11I1II1 / I1ii11iIi11i / i1IIi / iIii1I11I1II1
     if 70 - 70: i11iIiiIii . OoO0O00 / OoooooooOO * OoooooooOO - OOooOOo
     if 34 - 34: I1ii11iIi11i * i1IIi % OoooooooOO / I1IiiI
     if 39 - 39: OoO0O00 + IiII - II111iiii % I11i
   II11IIiii = lisp_rloc ( )
   II11IIiii . store_rloc_from_record ( OO0OoOo , None , source )
   if 80 - 80: o0oOOo0O0Ooo * ooOoO0o
   if 87 - 87: I1Ii111 + O0 / I1ii11iIi11i / OoOoOO00 . Oo0Ooo - IiII
   if 24 - 24: OoOoOO00
   if 19 - 19: ooOoO0o
   if 43 - 43: O0 . I1Ii111 % OoooooooOO / I1IiiI . o0oOOo0O0Ooo - OoOoOO00
   if 46 - 46: I11i - OoooooooOO % o0oOOo0O0Ooo
   if ( source . is_exact_match ( II11IIiii . rloc ) ) :
    II11IIiii . map_notify_requested = i1I11II11iIi1 . map_notify_requested
    if 7 - 7: OoooooooOO - I1Ii111 * IiII
    if 20 - 20: o0oOOo0O0Ooo . OoooooooOO * I1IiiI . Oo0Ooo * OoOoOO00
    if 3 - 3: I1Ii111 % i11iIiiIii % O0 % II111iiii
    if 8 - 8: OoooooooOO * ooOoO0o
    if 26 - 26: i11iIiiIii + oO0o - i1IIi
   O0OO . registered_rlocs . append ( II11IIiii )
   if 71 - 71: I1IiiI % I1Ii111 / oO0o % oO0o / iIii1I11I1II1 + I1Ii111
   if 86 - 86: IiII % i1IIi * o0oOOo0O0Ooo - I1Ii111
  I1II1I1III = ( O0OO . do_rloc_sets_match ( I11iiiIIi1 ) == False )
  if 6 - 6: iII111i / i1IIi + OOooOOo % OoOoOO00 . I1ii11iIi11i
  if 88 - 88: OoO0O00
  if 82 - 82: OOooOOo / I11i / OoooooooOO % oO0o
  if 27 - 27: oO0o + IiII
  if 5 - 5: iIii1I11I1II1 + OoOoOO00 * I1Ii111 * i11iIiiIii
  if 18 - 18: Oo0Ooo % OOooOOo % oO0o / I11i % O0
  if ( i1I11II11iIi1 . map_register_refresh and I1II1I1III and
 O0OO . registered ) :
   lprint ( "  Reject registration, refreshes cannot change RLOC-set" )
   O0OO . registered_rlocs = I11iiiIIi1
   continue
   if 76 - 76: OoooooooOO % O0 / OoO0O00
   if 41 - 41: i11iIiiIii - I1ii11iIi11i - II111iiii
   if 5 - 5: OoOoOO00 + i1IIi
   if 43 - 43: iII111i * I1IiiI
   if 20 - 20: I1IiiI . I11i * OoO0O00 . ooOoO0o . II111iiii
   if 6 - 6: Ii1I * OoOoOO00 % IiII + I11i
  if ( O0OO . registered == False ) :
   O0OO . first_registered = lisp_get_timestamp ( )
   lisp_registered_count += 1
   if 20 - 20: oO0o
  O0OO . last_registered = lisp_get_timestamp ( )
  O0OO . registered = ( OOOO . record_ttl != 0 )
  O0OO . last_registerer = source
  if 34 - 34: i1IIi + oO0o * Oo0Ooo * I1Ii111 % OoooooooOO % ooOoO0o
  if 17 - 17: I1ii11iIi11i + o0oOOo0O0Ooo / OoO0O00 . Oo0Ooo - o0oOOo0O0Ooo / oO0o
  if 87 - 87: ooOoO0o
  if 74 - 74: i11iIiiIii . i11iIiiIii . iIii1I11I1II1
  O0OO . auth_sha1_or_sha2 = I1i1i
  O0OO . proxy_reply_requested = i1I11II11iIi1 . proxy_reply_requested
  O0OO . lisp_sec_present = i1I11II11iIi1 . lisp_sec_present
  O0OO . map_notify_requested = i1I11II11iIi1 . map_notify_requested
  O0OO . mobile_node_requested = i1I11II11iIi1 . mobile_node
  O0OO . merge_register_requested = i1I11II11iIi1 . merge_register_requested
  if 100 - 100: i11iIiiIii - oO0o + iIii1I11I1II1 * OoOoOO00 % OOooOOo % i11iIiiIii
  O0OO . use_register_ttl_requested = i1I11II11iIi1 . use_ttl_for_timeout
  if ( O0OO . use_register_ttl_requested ) :
   O0OO . register_ttl = OOOO . store_ttl ( )
  else :
   O0OO . register_ttl = LISP_SITE_TIMEOUT_CHECK_INTERVAL * 3
   if 26 - 26: O0
  O0OO . xtr_id_present = i1I11II11iIi1 . xtr_id_present
  if ( O0OO . xtr_id_present ) :
   O0OO . xtr_id = i1I11II11iIi1 . xtr_id
   O0OO . site_id = i1I11II11iIi1 . site_id
   if 97 - 97: OOooOOo + I11i % I1Ii111 % i11iIiiIii / I1ii11iIi11i
   if 21 - 21: O0 + iIii1I11I1II1 / i11iIiiIii . OOooOOo * i1IIi
   if 3 - 3: i1IIi % o0oOOo0O0Ooo + OoOoOO00
   if 32 - 32: OoO0O00 . Oo0Ooo * iIii1I11I1II1
   if 12 - 12: O0 + I1ii11iIi11i + I11i . I1Ii111
  if ( i1I11II11iIi1 . merge_register_requested ) :
   if ( o0OoOOO . merge_in_site_eid ( O0OO ) ) :
    O00o0 . append ( [ OOOO . eid , OOOO . group ] )
    if 48 - 48: Ii1I . iIii1I11I1II1 - iIii1I11I1II1 * I11i . OoooooooOO
   if ( i1I11II11iIi1 . map_notify_requested ) :
    lisp_send_merged_map_notify ( lisp_sockets , o0OoOOO , i1I11II11iIi1 ,
 OOOO )
    if 73 - 73: Ii1I / II111iiii - iIii1I11I1II1 . ooOoO0o * II111iiii . OOooOOo
    if 50 - 50: iIii1I11I1II1 + OoOoOO00 % O0 + OoO0O00 . i11iIiiIii / oO0o
    if 31 - 31: I1IiiI % o0oOOo0O0Ooo . i11iIiiIii % OOooOOo - iIii1I11I1II1
  if ( I1II1I1III == False ) : continue
  if ( len ( O00o0 ) != 0 ) : continue
  if 77 - 77: i11iIiiIii / OOooOOo
  IiIIi1111I . append ( O0OO . print_eid_tuple ( ) )
  if 93 - 93: I1ii11iIi11i - iII111i % O0 - Ii1I
  if 84 - 84: I1ii11iIi11i . iIii1I11I1II1 % IiII * I11i + ooOoO0o
  if 59 - 59: oO0o * OoO0O00 - I11i * I1IiiI
  if 60 - 60: iII111i - OoooooooOO / iII111i % OoO0O00 . OoOoOO00 - o0oOOo0O0Ooo
  if 71 - 71: iII111i * o0oOOo0O0Ooo * i11iIiiIii * O0
  if 77 - 77: OOooOOo % iII111i + I11i / OoOoOO00
  if 50 - 50: OoOoOO00 - i11iIiiIii - OOooOOo . iIii1I11I1II1
  OOOO = OOOO . encode ( )
  OOOO += IIOoO0OOOo0O0O0
  oO0o0 = [ O0OO . print_eid_tuple ( ) ]
  lprint ( "    Changed RLOC-set, Map-Notifying old RLOC-set" )
  if 97 - 97: oO0o % OOooOOo . OoooooooOO * Ii1I
  for II11IIiii in I11iiiIIi1 :
   if ( II11IIiii . map_notify_requested == False ) : continue
   if ( II11IIiii . rloc . is_exact_match ( source ) ) : continue
   lisp_build_map_notify ( lisp_sockets , OOOO , oO0o0 , 1 , II11IIiii . rloc ,
 LISP_CTRL_PORT , i1I11II11iIi1 . nonce , i1I11II11iIi1 . key_id ,
 i1I11II11iIi1 . alg_id , i1I11II11iIi1 . auth_len , iiiOO0Oo , False )
   if 100 - 100: I1ii11iIi11i / Ii1I % Oo0Ooo
   if 83 - 83: O0 . I1Ii111 % I1ii11iIi11i
   if 97 - 97: Oo0Ooo % OoO0O00 * I1ii11iIi11i * ooOoO0o * OoO0O00
   if 12 - 12: ooOoO0o
   if 56 - 56: i1IIi
  lisp_notify_subscribers ( lisp_sockets , OOOO , O0OO . eid , iiiOO0Oo )
  if 3 - 3: OOooOOo - Oo0Ooo * Ii1I + i11iIiiIii
  if 53 - 53: i1IIi % I1ii11iIi11i
  if 65 - 65: I11i + OoOoOO00 - i11iIiiIii
  if 72 - 72: i11iIiiIii - iII111i . i11iIiiIii
  if 61 - 61: oO0o . i11iIiiIii / Ii1I % iII111i
 if ( len ( O00o0 ) != 0 ) :
  lisp_queue_multicast_map_notify ( lisp_sockets , O00o0 )
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
 if ( i1I11II11iIi1 . map_notify_requested and iiiOO0Oo != None ) :
  lisp_build_map_notify ( lisp_sockets , iIiIiIIII11iI1 , IiIIi1111I ,
 i1I11II11iIi1 . record_count , source , sport , i1I11II11iIi1 . nonce ,
 i1I11II11iIi1 . key_id , i1I11II11iIi1 . alg_id , i1I11II11iIi1 . auth_len ,
 iiiOO0Oo , True )
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
 for oo0O0oO0O0O in range ( Ii1I1i111 . record_count ) :
  OOOO = lisp_eid_record ( )
  iIiI1Ii = OOOO . decode ( iIiI1Ii )
  if ( packet == None ) : return
  OOOO . print_record ( "  " , False )
  if 45 - 45: I11i . OoooooooOO - i11iIiiIii - I1ii11iIi11i / oO0o
  if 54 - 54: i1IIi . ooOoO0o + O0 . ooOoO0o * iIii1I11I1II1
  if 82 - 82: iII111i % OoO0O00 * O0
  if 38 - 38: o0oOOo0O0Ooo * o0oOOo0O0Ooo - I1IiiI . iII111i % iIii1I11I1II1 + I1ii11iIi11i
  OoOOO000O0o = lisp_map_cache_lookup ( OOOO . eid , OOOO . group )
  if ( OoOOO000O0o == None ) :
   o0OooO00Oo , O0OOoO = lisp_allow_gleaning ( OOOO . eid , OOOO . group ,
 None )
   if ( o0OooO00Oo == False ) : continue
   if 89 - 89: ooOoO0o / ooOoO0o
   OoOOO000O0o = lisp_mapping ( OOOO . eid , OOOO . group , [ ] )
   OoOOO000O0o . add_cache ( )
   if 61 - 61: iIii1I11I1II1
   if 26 - 26: i11iIiiIii + OoO0O00 - i1IIi / OOooOOo
   if 71 - 71: OOooOOo . i1IIi
   if 48 - 48: ooOoO0o - Ii1I - I11i
   if 70 - 70: O0 * I11i . i1IIi - ooOoO0o
   if 93 - 93: OoooooooOO / o0oOOo0O0Ooo
   if 61 - 61: II111iiii / i1IIi . I1ii11iIi11i % iIii1I11I1II1
  if ( OoOOO000O0o . gleaned ) :
   lprint ( "Suppress Map-Notify for gleaned {}" . format ( green ( OoOOO000O0o . print_eid_tuple ( ) , False ) ) )
   if 66 - 66: iIii1I11I1II1 % OoOoOO00 + i1IIi * i11iIiiIii * OoooooooOO
   continue
   if 36 - 36: iII111i - OoO0O00 + I1IiiI + Ii1I . OoooooooOO
   if 75 - 75: oO0o * Oo0Ooo * O0
  OoOOO000O0o . mapping_source = None if source == "lisp-etr" else source
  OoOOO000O0o . map_cache_ttl = OOOO . store_ttl ( )
  if 22 - 22: ooOoO0o / OoooooooOO . II111iiii / Ii1I * OoO0O00 . i1IIi
  if 62 - 62: oO0o % Ii1I - Ii1I
  if 16 - 16: OoO0O00 - O0 - OOooOOo - I11i % OoOoOO00
  if 7 - 7: I1Ii111 / OoOoOO00 . II111iiii
  if 9 - 9: I11i . I11i . OoooooooOO
  if ( len ( OoOOO000O0o . rloc_set ) != 0 and OOOO . rloc_count == 0 ) :
   OoOOO000O0o . rloc_set = [ ]
   OoOOO000O0o . build_best_rloc_set ( )
   lisp_write_ipc_map_cache ( True , OoOOO000O0o )
   lprint ( "Update {} map-cache entry with no RLOC-set" . format ( green ( OoOOO000O0o . print_eid_tuple ( ) , False ) ) )
   if 42 - 42: iII111i / oO0o / iII111i * OoO0O00
   continue
   if 25 - 25: OoOoOO00 - II111iiii + II111iiii . Ii1I * II111iiii
   if 12 - 12: IiII / Ii1I
  OO000oo = OoOOO000O0o . rtrs_in_rloc_set ( )
  if 67 - 67: OoOoOO00 + I1IiiI % iII111i
  if 2 - 2: ooOoO0o - ooOoO0o % OoO0O00 / I1IiiI - Oo0Ooo
  if 30 - 30: i11iIiiIii / OoO0O00 - IiII / Oo0Ooo + I11i - i1IIi
  if 67 - 67: i11iIiiIii * I11i * Ii1I + OoooooooOO * OoO0O00
  if 28 - 28: I1Ii111 - iIii1I11I1II1
  for iIIi11i1i1I1I in range ( OOOO . rloc_count ) :
   OO0OoOo = lisp_rloc_record ( )
   iIiI1Ii = OO0OoOo . decode ( iIiI1Ii , None )
   OO0OoOo . print_record ( "    " )
   if ( OOOO . group . is_null ( ) ) : continue
   if ( OO0OoOo . rle == None ) : continue
   if 88 - 88: Oo0Ooo * i1IIi % OOooOOo
   if 65 - 65: iII111i . oO0o
   if 67 - 67: I1IiiI / iII111i / O0 % ooOoO0o - IiII / Ii1I
   if 31 - 31: I11i - oO0o * ooOoO0o
   if 64 - 64: I11i
   I1iiIIiIII1i = OoOOO000O0o . rloc_set [ 0 ] . stats if len ( OoOOO000O0o . rloc_set ) != 0 else None
   if 89 - 89: IiII
   if 16 - 16: I1Ii111 / i1IIi * OoOoOO00 - i11iIiiIii . oO0o
   if 22 - 22: OOooOOo
   if 12 - 12: I11i * I1IiiI + OOooOOo
   II11IIiii = lisp_rloc ( )
   II11IIiii . store_rloc_from_record ( OO0OoOo , None , OoOOO000O0o . mapping_source )
   if ( I1iiIIiIII1i != None ) : II11IIiii . stats = copy . deepcopy ( I1iiIIiIII1i )
   if 40 - 40: I1ii11iIi11i - OoOoOO00 % OoooooooOO * o0oOOo0O0Ooo % OoooooooOO
   if ( OO000oo and II11IIiii . is_rtr ( ) == False ) : continue
   if 47 - 47: iIii1I11I1II1 - OOooOOo + I1ii11iIi11i * ooOoO0o + Oo0Ooo + OoO0O00
   OoOOO000O0o . rloc_set = [ II11IIiii ]
   OoOOO000O0o . build_best_rloc_set ( )
   lisp_write_ipc_map_cache ( True , OoOOO000O0o )
   if 64 - 64: OoOoOO00 - OoOoOO00 . OoooooooOO + ooOoO0o
   lprint ( "Update {} map-cache entry with RLE {}" . format ( green ( OoOOO000O0o . print_eid_tuple ( ) , False ) , II11IIiii . rle . print_rle ( False ) ) )
   if 100 - 100: ooOoO0o . OoooooooOO % i1IIi % OoO0O00
   if 26 - 26: OoOoOO00 * IiII
   if 76 - 76: I1IiiI + IiII * I1ii11iIi11i * I1IiiI % Ii1I + ooOoO0o
 return
 if 46 - 46: OoOoOO00
 if 66 - 66: iII111i - O0 . I1Ii111 * i1IIi / OoO0O00 / II111iiii
 if 35 - 35: ooOoO0o * OOooOOo / I11i % I11i / OoooooooOO . I1Ii111
 if 70 - 70: I1ii11iIi11i % I1ii11iIi11i / oO0o
 if 85 - 85: OoOoOO00 % I11i / Oo0Ooo + I11i - Oo0Ooo
 if 20 - 20: IiII
 if 81 - 81: Oo0Ooo / I1Ii111
 if 20 - 20: o0oOOo0O0Ooo + ooOoO0o % i1IIi
def lisp_process_map_notify ( lisp_sockets , orig_packet , source ) :
 Ii1I1i111 = lisp_map_notify ( "" )
 Ii11iIiiI = Ii1I1i111 . decode ( orig_packet )
 if ( Ii11iIiiI == None ) :
  lprint ( "Could not decode Map-Notify packet" )
  return
  if 51 - 51: iII111i - ooOoO0o
  if 32 - 32: IiII - i11iIiiIii
 Ii1I1i111 . print_notify ( )
 if 41 - 41: Ii1I % Ii1I * oO0o - I11i + iIii1I11I1II1 . ooOoO0o
 if 30 - 30: Ii1I * iII111i . II111iiii / i1IIi
 if 77 - 77: oO0o . IiII + I1ii11iIi11i . i1IIi
 if 49 - 49: I1Ii111 . OoooooooOO / o0oOOo0O0Ooo - iII111i - iII111i - i11iIiiIii
 if 37 - 37: OOooOOo
 oOOOOOOOoO = source . print_address ( )
 if ( Ii1I1i111 . alg_id != 0 or Ii1I1i111 . auth_len != 0 ) :
  oOooOO = None
  for OOO0OOoOOO in lisp_map_servers_list :
   if ( OOO0OOoOOO . find ( oOOOOOOOoO ) == - 1 ) : continue
   oOooOO = lisp_map_servers_list [ OOO0OOoOOO ]
   if 79 - 79: I1Ii111 - OoO0O00 + ooOoO0o + oO0o . i11iIiiIii + i1IIi
  if ( oOooOO == None ) :
   lprint ( ( "  Could not find Map-Server {} to authenticate " + "Map-Notify" ) . format ( oOOOOOOOoO ) )
   if 32 - 32: IiII . ooOoO0o / OoO0O00 / iII111i . iIii1I11I1II1 % IiII
   return
   if 28 - 28: I1Ii111 + OoooooooOO + IiII . ooOoO0o . I1IiiI / oO0o
   if 66 - 66: Ii1I - I11i + Oo0Ooo . ooOoO0o
  oOooOO . map_notifies_received += 1
  if 89 - 89: IiII . II111iiii / OoO0O00 + I1ii11iIi11i * i11iIiiIii
  ooOoOO00o0O = lisp_verify_auth ( Ii11iIiiI , Ii1I1i111 . alg_id ,
 Ii1I1i111 . auth_data , oOooOO . password )
  if 85 - 85: o0oOOo0O0Ooo - Oo0Ooo / I1Ii111
  lprint ( "  Authentication {} for Map-Notify" . format ( "succeeded" if ooOoOO00o0O else "failed" ) )
  if 100 - 100: OoO0O00 * iIii1I11I1II1 - IiII . i1IIi % i11iIiiIii % Oo0Ooo
  if ( ooOoOO00o0O == False ) : return
 else :
  oOooOO = lisp_ms ( oOOOOOOOoO , None , "" , 0 , "" , False , False , False , False , 0 , 0 , 0 ,
 None )
  if 22 - 22: ooOoO0o - OOooOOo
  if 90 - 90: i11iIiiIii . i11iIiiIii - iIii1I11I1II1
  if 20 - 20: ooOoO0o - i11iIiiIii
  if 23 - 23: OoO0O00 + I1IiiI / I1ii11iIi11i * I1ii11iIi11i % ooOoO0o
  if 83 - 83: I1IiiI * i11iIiiIii - I1ii11iIi11i + I11i
  if 33 - 33: OoO0O00 . OoooooooOO % iII111i / oO0o * Ii1I + ooOoO0o
 iIiI1Ii = Ii1I1i111 . eid_records
 if ( Ii1I1i111 . record_count == 0 ) :
  lisp_send_map_notify_ack ( lisp_sockets , iIiI1Ii , Ii1I1i111 , oOooOO )
  return
  if 29 - 29: oO0o
  if 21 - 21: i11iIiiIii . o0oOOo0O0Ooo
  if 78 - 78: Oo0Ooo
  if 77 - 77: oO0o % Oo0Ooo % O0
  if 51 - 51: IiII % IiII + OOooOOo . II111iiii / I1ii11iIi11i
  if 4 - 4: o0oOOo0O0Ooo % I1IiiI * o0oOOo0O0Ooo * OoOoOO00 - Ii1I
  if 61 - 61: OoooooooOO - OoOoOO00 . O0 / ooOoO0o . Ii1I
  if 41 - 41: Oo0Ooo / OoOoOO00 % I1Ii111 - O0
 OOOO = lisp_eid_record ( )
 Ii11iIiiI = OOOO . decode ( iIiI1Ii )
 if ( Ii11iIiiI == None ) : return
 if 19 - 19: I1IiiI % I1Ii111 - O0 . iIii1I11I1II1 . I11i % O0
 OOOO . print_record ( "  " , False )
 if 88 - 88: ooOoO0o
 for iIIi11i1i1I1I in range ( OOOO . rloc_count ) :
  OO0OoOo = lisp_rloc_record ( )
  Ii11iIiiI = OO0OoOo . decode ( Ii11iIiiI , None )
  if ( Ii11iIiiI == None ) :
   lprint ( "  Could not decode RLOC-record in Map-Notify packet" )
   return
   if 52 - 52: iIii1I11I1II1 % ooOoO0o * iIii1I11I1II1
  OO0OoOo . print_record ( "    " )
  if 20 - 20: i11iIiiIii * I11i
  if 29 - 29: IiII / OOooOOo
  if 39 - 39: O0 + II111iiii
  if 94 - 94: OOooOOo % I1ii11iIi11i % O0 + iII111i
  if 62 - 62: iIii1I11I1II1 . OoOoOO00 / iIii1I11I1II1 + IiII
 if ( OOOO . group . is_null ( ) == False ) :
  if 31 - 31: Ii1I . OoO0O00 . Ii1I + OoO0O00 * iIii1I11I1II1 . iII111i
  if 42 - 42: O0 / oO0o % O0 . i1IIi % OOooOOo
  if 13 - 13: I1IiiI % ooOoO0o + OOooOOo
  if 91 - 91: oO0o - ooOoO0o
  if 20 - 20: i1IIi . IiII / o0oOOo0O0Ooo / I11i
  lprint ( "Send {} Map-Notify IPC message to ITR process" . format ( green ( OOOO . print_eid_tuple ( ) , False ) ) )
  if 27 - 27: ooOoO0o . ooOoO0o - Ii1I % i11iIiiIii
  if 74 - 74: I1Ii111 - II111iiii % o0oOOo0O0Ooo
  OOO000OOOO0oO = lisp_control_packet_ipc ( orig_packet , oOOOOOOOoO , "lisp-itr" , 0 )
  lisp_ipc ( OOO000OOOO0oO , lisp_sockets [ 2 ] , "lisp-core-pkt" )
  if 7 - 7: I1IiiI + OoooooooOO + o0oOOo0O0Ooo . OoooooooOO
  if 29 - 29: iII111i * O0 + I1IiiI * IiII + iII111i - IiII
  if 38 - 38: I1ii11iIi11i - Ii1I % OoooooooOO
  if 43 - 43: iIii1I11I1II1 / OoOoOO00
  if 13 - 13: o0oOOo0O0Ooo / I1Ii111
 lisp_send_map_notify_ack ( lisp_sockets , iIiI1Ii , Ii1I1i111 , oOooOO )
 return
 if 67 - 67: OoooooooOO . oO0o * OoOoOO00 - OoooooooOO
 if 32 - 32: oO0o
 if 72 - 72: I1IiiI
 if 34 - 34: ooOoO0o % II111iiii / ooOoO0o
 if 87 - 87: Oo0Ooo
 if 7 - 7: iIii1I11I1II1
 if 85 - 85: iIii1I11I1II1 . O0
 if 43 - 43: II111iiii / OoOoOO00 + OOooOOo % Oo0Ooo * OOooOOo
def lisp_process_map_notify_ack ( packet , source ) :
 Ii1I1i111 = lisp_map_notify ( "" )
 packet = Ii1I1i111 . decode ( packet )
 if ( packet == None ) :
  lprint ( "Could not decode Map-Notify-Ack packet" )
  return
  if 62 - 62: ooOoO0o * OOooOOo . I11i + Oo0Ooo - I1Ii111
  if 48 - 48: I1Ii111 * Oo0Ooo % OoO0O00 % Ii1I
 Ii1I1i111 . print_notify ( )
 if 8 - 8: OoO0O00 . OoO0O00
 if 29 - 29: I11i + OoooooooOO % o0oOOo0O0Ooo - I1Ii111
 if 45 - 45: II111iiii - OOooOOo / oO0o % O0 . iII111i . iII111i
 if 82 - 82: iIii1I11I1II1 % Oo0Ooo * i1IIi - I1Ii111 - I1ii11iIi11i / iII111i
 if 24 - 24: IiII
 if ( Ii1I1i111 . record_count < 1 ) :
  lprint ( "No EID-prefix found, cannot authenticate Map-Notify-Ack" )
  return
  if 95 - 95: IiII + OoOoOO00 * OOooOOo
  if 92 - 92: OoOoOO00 + ooOoO0o . iII111i
 OOOO = lisp_eid_record ( )
 if 59 - 59: iIii1I11I1II1 % I1Ii111 + I1ii11iIi11i . OoOoOO00 * Oo0Ooo / I1Ii111
 if ( OOOO . decode ( Ii1I1i111 . eid_records ) == None ) :
  lprint ( "Could not decode EID-record, cannot authenticate " +
 "Map-Notify-Ack" )
  return
  if 41 - 41: i1IIi / IiII
 OOOO . print_record ( "  " , False )
 if 73 - 73: o0oOOo0O0Ooo % ooOoO0o
 O0o0O0OO0o = OOOO . print_eid_tuple ( )
 if 72 - 72: OoO0O00 * OoOoOO00 % I1IiiI - OOooOOo . Oo0Ooo
 if 70 - 70: ooOoO0o . o0oOOo0O0Ooo * II111iiii - O0
 if 74 - 74: oO0o % I1IiiI / oO0o / Oo0Ooo / ooOoO0o
 if 29 - 29: ooOoO0o + iIii1I11I1II1 + OoO0O00 - o0oOOo0O0Ooo
 if ( Ii1I1i111 . alg_id != LISP_NONE_ALG_ID and Ii1I1i111 . auth_len != 0 ) :
  O0OO = lisp_sites_by_eid . lookup_cache ( OOOO . eid , True )
  if ( O0OO == None ) :
   ii1111I1II1 = bold ( "Site not found" , False )
   lprint ( ( "{} for EID {}, cannot authenticate Map-Notify-Ack" ) . format ( ii1111I1II1 , green ( O0o0O0OO0o , False ) ) )
   if 74 - 74: II111iiii - II111iiii + ooOoO0o + Oo0Ooo % iIii1I11I1II1
   return
   if 90 - 90: oO0o / o0oOOo0O0Ooo . o0oOOo0O0Ooo % OoOoOO00 / IiII
  iiiOO0Oo = O0OO . site
  if 13 - 13: oO0o + IiII
  if 36 - 36: oO0o - OoOoOO00 . O0 % IiII
  if 65 - 65: Oo0Ooo - i11iIiiIii * OoOoOO00 . I1Ii111 . iIii1I11I1II1
  if 48 - 48: iIii1I11I1II1 - oO0o / OoO0O00 + O0 . Ii1I + I1Ii111
  iiiOO0Oo . map_notify_acks_received += 1
  if 17 - 17: OoOoOO00 . Oo0Ooo - I1Ii111 / I1Ii111 + I11i % i1IIi
  oOoO0oO00ooOo = Ii1I1i111 . key_id
  if ( iiiOO0Oo . auth_key . has_key ( oOoO0oO00ooOo ) == False ) : oOoO0oO00ooOo = 0
  IiIIIIi11i = iiiOO0Oo . auth_key [ oOoO0oO00ooOo ]
  if 31 - 31: OoooooooOO . O0 / OoO0O00 . I1Ii111
  ooOoOO00o0O = lisp_verify_auth ( packet , Ii1I1i111 . alg_id ,
 Ii1I1i111 . auth_data , IiIIIIi11i )
  if 41 - 41: OoooooooOO + iII111i . OOooOOo
  oOoO0oO00ooOo = "key-id {}" . format ( oOoO0oO00ooOo ) if oOoO0oO00ooOo == Ii1I1i111 . key_id else "bad key-id {}" . format ( Ii1I1i111 . key_id )
  if 73 - 73: oO0o + i1IIi + i11iIiiIii / I1ii11iIi11i
  if 100 - 100: I1IiiI % ooOoO0o % OoooooooOO / i11iIiiIii + i11iIiiIii % IiII
  lprint ( "  Authentication {} for Map-Notify-Ack, {}" . format ( "succeeded" if ooOoOO00o0O else "failed" , oOoO0oO00ooOo ) )
  if 39 - 39: Ii1I % o0oOOo0O0Ooo + OOooOOo / iIii1I11I1II1
  if ( ooOoOO00o0O == False ) : return
  if 40 - 40: iIii1I11I1II1 / iII111i % OOooOOo % i11iIiiIii
  if 57 - 57: II111iiii % OoO0O00 * i1IIi
  if 19 - 19: ooOoO0o . iIii1I11I1II1 + I1ii11iIi11i + I1ii11iIi11i / o0oOOo0O0Ooo . Oo0Ooo
  if 9 - 9: II111iiii % OoooooooOO
  if 4 - 4: i1IIi * i11iIiiIii % OoooooooOO + OoOoOO00 . oO0o
 if ( Ii1I1i111 . retransmit_timer ) : Ii1I1i111 . retransmit_timer . cancel ( )
 if 95 - 95: I1ii11iIi11i * OoOoOO00 % o0oOOo0O0Ooo / O0 + ooOoO0o % OOooOOo
 oo0OO00O000 = source . print_address ( )
 OOO0OOoOOO = Ii1I1i111 . nonce_key
 if 48 - 48: i1IIi + IiII - iIii1I11I1II1 . i11iIiiIii % OOooOOo + I1ii11iIi11i
 if ( lisp_map_notify_queue . has_key ( OOO0OOoOOO ) ) :
  Ii1I1i111 = lisp_map_notify_queue . pop ( OOO0OOoOOO )
  if ( Ii1I1i111 . retransmit_timer ) : Ii1I1i111 . retransmit_timer . cancel ( )
  lprint ( "Dequeue Map-Notify from retransmit queue, key is: {}" . format ( OOO0OOoOOO ) )
  if 95 - 95: ooOoO0o + OoOoOO00 . II111iiii + Ii1I
 else :
  lprint ( "Map-Notify with nonce 0x{} queue entry not found for {}" . format ( Ii1I1i111 . nonce_key , red ( oo0OO00O000 , False ) ) )
  if 81 - 81: OoooooooOO / OOooOOo / Oo0Ooo
  if 26 - 26: iII111i
 return
 if 93 - 93: Oo0Ooo + I1IiiI % OoOoOO00 / OOooOOo / I1ii11iIi11i
 if 6 - 6: IiII
 if 68 - 68: Oo0Ooo
 if 83 - 83: OOooOOo / iIii1I11I1II1 . OoO0O00 - oO0o % Oo0Ooo
 if 30 - 30: Ii1I . OoOoOO00 / oO0o . OoO0O00
 if 93 - 93: i11iIiiIii
 if 33 - 33: i1IIi % OoooooooOO + Oo0Ooo % I1IiiI / ooOoO0o
 if 40 - 40: IiII % IiII
def lisp_map_referral_loop ( mr , eid , group , action , s ) :
 if ( action not in ( LISP_DDT_ACTION_NODE_REFERRAL ,
 LISP_DDT_ACTION_MS_REFERRAL ) ) : return ( False )
 if 9 - 9: I1IiiI * i1IIi + OOooOOo * OoOoOO00
 if ( mr . last_cached_prefix [ 0 ] == None ) : return ( False )
 if 8 - 8: iII111i
 if 51 - 51: I1IiiI
 if 72 - 72: ooOoO0o / I1ii11iIi11i . Ii1I * iII111i . iIii1I11I1II1
 if 35 - 35: OoO0O00 . OoOoOO00 % O0 * OoO0O00
 OOOoo0ooooo0 = False
 if ( group . is_null ( ) == False ) :
  OOOoo0ooooo0 = mr . last_cached_prefix [ 1 ] . is_more_specific ( group )
  if 68 - 68: OOooOOo
 if ( OOOoo0ooooo0 == False ) :
  OOOoo0ooooo0 = mr . last_cached_prefix [ 0 ] . is_more_specific ( eid )
  if 87 - 87: IiII * IiII - OoO0O00 / I1ii11iIi11i + OOooOOo / i11iIiiIii
  if 21 - 21: o0oOOo0O0Ooo / oO0o + oO0o + Oo0Ooo / o0oOOo0O0Ooo
 if ( OOOoo0ooooo0 ) :
  oo0i11i11ii11 = lisp_print_eid_tuple ( eid , group )
  IiIIiiii = lisp_print_eid_tuple ( mr . last_cached_prefix [ 0 ] ,
 mr . last_cached_prefix [ 1 ] )
  if 100 - 100: i1IIi
  lprint ( ( "Map-Referral prefix {} from {} is not more-specific " + "than cached prefix {}" ) . format ( green ( oo0i11i11ii11 , False ) , s ,
  # II111iiii % oO0o * I1ii11iIi11i
 IiIIiiii ) )
  if 24 - 24: II111iiii % OOooOOo
 return ( OOOoo0ooooo0 )
 if 22 - 22: OoooooooOO + i1IIi % OoooooooOO
 if 15 - 15: o0oOOo0O0Ooo % I1ii11iIi11i / II111iiii
 if 50 - 50: oO0o * Ii1I % I1Ii111
 if 74 - 74: iIii1I11I1II1 - OOooOOo / I1Ii111 / ooOoO0o . oO0o % iIii1I11I1II1
 if 91 - 91: o0oOOo0O0Ooo . o0oOOo0O0Ooo - Ii1I
 if 60 - 60: i11iIiiIii . Oo0Ooo / iIii1I11I1II1 / II111iiii
 if 31 - 31: Oo0Ooo / Oo0Ooo / iIii1I11I1II1 / I11i % OoooooooOO
def lisp_process_map_referral ( lisp_sockets , packet , source ) :
 if 90 - 90: I1IiiI
 iI1oOoo0oO0oOo = lisp_map_referral ( )
 packet = iI1oOoo0oO0oOo . decode ( packet )
 if ( packet == None ) :
  lprint ( "Could not decode Map-Referral packet" )
  return
  if 35 - 35: O0
 iI1oOoo0oO0oOo . print_map_referral ( )
 if 10 - 10: Ii1I - I1Ii111 / Oo0Ooo + O0
 oOOOOOOOoO = source . print_address ( )
 i11IIoOOoOo0Ooo = iI1oOoo0oO0oOo . nonce
 if 67 - 67: Ii1I % i11iIiiIii . Oo0Ooo
 if 78 - 78: I1IiiI - iIii1I11I1II1
 if 20 - 20: i11iIiiIii % I1IiiI % OoOoOO00
 if 85 - 85: I11i + OoOoOO00 * O0 * O0
 for oo0O0oO0O0O in range ( iI1oOoo0oO0oOo . record_count ) :
  OOOO = lisp_eid_record ( )
  packet = OOOO . decode ( packet )
  if ( packet == None ) :
   lprint ( "Could not decode EID-record in Map-Referral packet" )
   return
   if 92 - 92: i11iIiiIii
  OOOO . print_record ( "  " , True )
  if 16 - 16: I11i . ooOoO0o - Oo0Ooo / OoO0O00 . i1IIi
  if 59 - 59: ooOoO0o - ooOoO0o % I11i + OoO0O00
  if 88 - 88: Ii1I - ooOoO0o . Oo0Ooo
  if 83 - 83: I11i + Oo0Ooo . I1ii11iIi11i * I1ii11iIi11i
  OOO0OOoOOO = str ( i11IIoOOoOo0Ooo )
  if ( OOO0OOoOOO not in lisp_ddt_map_requestQ ) :
   lprint ( ( "Map-Referral nonce 0x{} from {} not found in " + "Map-Request queue, EID-record ignored" ) . format ( lisp_hex_string ( i11IIoOOoOo0Ooo ) , oOOOOOOOoO ) )
   if 80 - 80: i1IIi * I11i - OOooOOo / II111iiii * iIii1I11I1II1
   if 42 - 42: OoOoOO00 . I11i % II111iiii
   continue
   if 19 - 19: OoooooooOO
  OOO0o0o = lisp_ddt_map_requestQ [ OOO0OOoOOO ]
  if ( OOO0o0o == None ) :
   lprint ( ( "No Map-Request queue entry found for Map-Referral " +
 "nonce 0x{} from {}, EID-record ignored" ) . format ( lisp_hex_string ( i11IIoOOoOo0Ooo ) , oOOOOOOOoO ) )
   if 31 - 31: I11i . OoOoOO00 - O0 * iII111i % I1Ii111 - II111iiii
   continue
   if 21 - 21: OOooOOo . Oo0Ooo - i1IIi
   if 56 - 56: I11i
   if 24 - 24: I1IiiI . I1IiiI % ooOoO0o
   if 32 - 32: OOooOOo / i1IIi / OOooOOo
   if 97 - 97: ooOoO0o * Oo0Ooo * OoooooooOO * I1IiiI
   if 45 - 45: Oo0Ooo
  if ( lisp_map_referral_loop ( OOO0o0o , OOOO . eid , OOOO . group ,
 OOOO . action , oOOOOOOOoO ) ) :
   OOO0o0o . dequeue_map_request ( )
   continue
   if 27 - 27: oO0o / IiII - iIii1I11I1II1 / o0oOOo0O0Ooo % OOooOOo * iIii1I11I1II1
   if 40 - 40: oO0o - II111iiii * OOooOOo % OoooooooOO
  OOO0o0o . last_cached_prefix [ 0 ] = OOOO . eid
  OOO0o0o . last_cached_prefix [ 1 ] = OOOO . group
  if 52 - 52: OOooOOo + OoO0O00
  if 96 - 96: OOooOOo % O0 - Oo0Ooo % oO0o / I1IiiI . i1IIi
  if 42 - 42: i1IIi
  if 52 - 52: OoO0O00 % iII111i % O0
  O0ooOo0O0ooo0 = False
  II11IIIIi = lisp_referral_cache_lookup ( OOOO . eid , OOOO . group ,
 True )
  if ( II11IIIIi == None ) :
   O0ooOo0O0ooo0 = True
   II11IIIIi = lisp_referral ( )
   II11IIIIi . eid = OOOO . eid
   II11IIIIi . group = OOOO . group
   if ( OOOO . ddt_incomplete == False ) : II11IIIIi . add_cache ( )
  elif ( II11IIIIi . referral_source . not_set ( ) ) :
   lprint ( "Do not replace static referral entry {}" . format ( green ( II11IIIIi . print_eid_tuple ( ) , False ) ) )
   if 11 - 11: i1IIi / i11iIiiIii + Ii1I % Oo0Ooo % O0
   OOO0o0o . dequeue_map_request ( )
   continue
   if 50 - 50: oO0o . I1Ii111
   if 38 - 38: iIii1I11I1II1 . Ii1I
  i11IIiI = OOOO . action
  II11IIIIi . referral_source = source
  II11IIIIi . referral_type = i11IIiI
  I1i = OOOO . store_ttl ( )
  II11IIIIi . referral_ttl = I1i
  II11IIIIi . expires = lisp_set_timestamp ( I1i )
  if 82 - 82: OOooOOo * Ii1I + I1ii11iIi11i . OoO0O00
  if 15 - 15: O0
  if 44 - 44: Ii1I . Oo0Ooo . I1Ii111 + oO0o
  if 32 - 32: OOooOOo - II111iiii + IiII * iIii1I11I1II1 - Oo0Ooo
  iiiIii1I11iII = II11IIIIi . is_referral_negative ( )
  if ( II11IIIIi . referral_set . has_key ( oOOOOOOOoO ) ) :
   ii1I111ii = II11IIIIi . referral_set [ oOOOOOOOoO ]
   if 85 - 85: OoO0O00 / oO0o % I1ii11iIi11i
   if ( ii1I111ii . updown == False and iiiIii1I11iII == False ) :
    ii1I111ii . updown = True
    lprint ( "Change up/down status for referral-node {} to up" . format ( oOOOOOOOoO ) )
    if 9 - 9: I1Ii111
   elif ( ii1I111ii . updown == True and iiiIii1I11iII == True ) :
    ii1I111ii . updown = False
    lprint ( ( "Change up/down status for referral-node {} " + "to down, received negative referral" ) . format ( oOOOOOOOoO ) )
    if 76 - 76: OoO0O00 + i1IIi % I1IiiI / o0oOOo0O0Ooo
    if 53 - 53: iIii1I11I1II1 * oO0o
    if 43 - 43: IiII * Oo0Ooo / OOooOOo % oO0o
    if 11 - 11: OoOoOO00 * Oo0Ooo / I11i * OOooOOo
    if 15 - 15: ooOoO0o - OOooOOo / OoooooooOO
    if 41 - 41: OoOoOO00 . iII111i . i1IIi + oO0o
    if 60 - 60: oO0o * I1Ii111
    if 81 - 81: oO0o - OOooOOo - oO0o
  oO00OoOoO00 = { }
  for OOO0OOoOOO in II11IIIIi . referral_set : oO00OoOoO00 [ OOO0OOoOOO ] = None
  if 30 - 30: I1ii11iIi11i / iIii1I11I1II1
  if 16 - 16: II111iiii
  if 73 - 73: OoO0O00 . iIii1I11I1II1 * I1ii11iIi11i * OoOoOO00 * i11iIiiIii . Ii1I
  if 16 - 16: OOooOOo + Ii1I * II111iiii / Oo0Ooo + iII111i
  for oo0O0oO0O0O in range ( OOOO . rloc_count ) :
   OO0OoOo = lisp_rloc_record ( )
   packet = OO0OoOo . decode ( packet , None )
   if ( packet == None ) :
    lprint ( "Could not decode RLOC-record in Map-Referral packet" )
    return
    if 82 - 82: OoOoOO00
   OO0OoOo . print_record ( "    " )
   if 97 - 97: oO0o - OOooOOo / i11iIiiIii . Oo0Ooo % I1Ii111 % oO0o
   if 29 - 29: ooOoO0o % iII111i / iIii1I11I1II1
   if 73 - 73: O0 % i11iIiiIii
   if 16 - 16: O0
   i111I11I = OO0OoOo . rloc . print_address ( )
   if ( II11IIIIi . referral_set . has_key ( i111I11I ) == False ) :
    ii1I111ii = lisp_referral_node ( )
    ii1I111ii . referral_address . copy_address ( OO0OoOo . rloc )
    II11IIIIi . referral_set [ i111I11I ] = ii1I111ii
    if ( oOOOOOOOoO == i111I11I and iiiIii1I11iII ) : ii1I111ii . updown = False
   else :
    ii1I111ii = II11IIIIi . referral_set [ i111I11I ]
    if ( oO00OoOoO00 . has_key ( i111I11I ) ) : oO00OoOoO00 . pop ( i111I11I )
    if 15 - 15: i1IIi % i11iIiiIii
   ii1I111ii . priority = OO0OoOo . priority
   ii1I111ii . weight = OO0OoOo . weight
   if 18 - 18: Ii1I . OoO0O00 . iII111i * oO0o + O0
   if 35 - 35: OoOoOO00 . oO0o / II111iiii
   if 97 - 97: Ii1I + I1Ii111 / II111iiii
   if 14 - 14: iII111i / IiII / oO0o
   if 55 - 55: OoO0O00 % O0
  for OOO0OOoOOO in oO00OoOoO00 : II11IIIIi . referral_set . pop ( OOO0OOoOOO )
  if 92 - 92: OoooooooOO / O0
  O0o0O0OO0o = II11IIIIi . print_eid_tuple ( )
  if 14 - 14: i11iIiiIii
  if ( O0ooOo0O0ooo0 ) :
   if ( OOOO . ddt_incomplete ) :
    lprint ( "Suppress add {} to referral-cache" . format ( green ( O0o0O0OO0o , False ) ) )
    if 43 - 43: OOooOOo
   else :
    lprint ( "Add {}, referral-count {} to referral-cache" . format ( green ( O0o0O0OO0o , False ) , OOOO . rloc_count ) )
    if 79 - 79: iII111i % Oo0Ooo . i1IIi % ooOoO0o
    if 93 - 93: OoOoOO00
  else :
   lprint ( "Replace {}, referral-count: {} in referral-cache" . format ( green ( O0o0O0OO0o , False ) , OOOO . rloc_count ) )
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
   if ( II11IIIIi . referral_set . has_key ( oOOOOOOOoO ) ) :
    ii1I111ii = II11IIIIi . referral_set [ oOOOOOOOoO ]
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
   if ( OOO0o0o . eid . is_exact_match ( OOOO . eid ) ) :
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
 I11IIIIiII = lisp_control_header ( )
 if ( I11IIIIiII . decode ( packet ) == None ) :
  lprint ( "Could not decode control header" )
  return
  if 65 - 65: ooOoO0o . I1IiiI
  if 51 - 51: IiII
 iIi1i11Ii = I11IIIIiII . type
 del ( I11IIIIiII )
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
 oOiii1IiII = ms . map_server
 if ( lisp_decent_push_configured and oOiii1IiII . is_multicast_address ( ) and
 ( ms . map_registers_multicast_sent == 1 or ms . map_registers_sent == 1 ) ) :
  oOiii1IiII = copy . deepcopy ( oOiii1IiII )
  oOiii1IiII . address = 0x7f000001
  i1iiI = bold ( "Bootstrap" , False )
  IiIoO0oo0 = ms . map_server . print_address_no_iid ( )
  lprint ( "{} mapping system for peer-group {}" . format ( i1iiI , IiIoO0oo0 ) )
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
  o0OOo0O = "0" * 8
  iiII = chacha . ChaCha ( O000oOooOoO0 , o0OOo0O ) . encrypt ( packet [ 4 : : ] )
  packet = packet [ 0 : 4 ] + iiII
  ooOoOOOOo = bold ( "Encrypt" , False )
  lprint ( "{} Map-Register with key-id {}" . format ( ooOoOOOOo , ms . ekey_id ) )
  if 51 - 51: oO0o . OoooooooOO + OOooOOo * I1ii11iIi11i - ooOoO0o
  if 41 - 41: Oo0Ooo
 Iiiiii1 = ""
 if ( lisp_decent_pull_xtr_configured ( ) ) :
  Iiiiii1 = ", decent-index {}" . format ( bold ( ms . dns_name , False ) )
  if 66 - 66: oO0o % i1IIi % OoooooooOO
  if 58 - 58: OOooOOo
 lprint ( "Send Map-Register to map-server {}{}{}" . format ( oOiii1IiII . print_address ( ) , ", ms-name '{}'" . format ( ms . ms_name ) , Iiiiii1 ) )
 if 89 - 89: iIii1I11I1II1 - i1IIi
 lisp_send ( lisp_sockets , oOiii1IiII , LISP_CTRL_PORT , packet )
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
 OOii = lisp_socket . getsockname ( )
 dest = dest . print_address_no_iid ( )
 if 67 - 67: IiII + oO0o * IiII
 lprint ( "Send IPC {} bytes to {} {}, control-packet: {}" . format ( len ( packet ) , dest , port , lisp_format_packet ( packet ) ) )
 if 26 - 26: I1ii11iIi11i + i1IIi . i1IIi - oO0o + I1IiiI * o0oOOo0O0Ooo
 if 62 - 62: ooOoO0o + ooOoO0o % I11i
 packet = lisp_control_packet_ipc ( packet , OOii , dest , port )
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
  oo0 = lisp_get_any_translated_port ( )
  if ( oo0 != None ) : inner_sport = oo0
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
 i111I11I = outer_dest . print_address_no_iid ( )
 lprint ( "Send Encapsulated-Control-Message to {}" . format ( i111I11I ) )
 oOiii1IiII = lisp_convert_4to6 ( i111I11I )
 lisp_send ( lisp_sockets , oOiii1IiII , LISP_CTRL_PORT , packet )
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
 oOo00Ooo0o0 = ( ( address & 0x00000000000000ff ) << 56 ) | ( ( address & 0x000000000000ff00 ) << 40 ) | ( ( address & 0x0000000000ff0000 ) << 24 ) | ( ( address & 0x00000000ff000000 ) << 8 ) | ( ( address & 0x000000ff00000000 ) >> 8 ) | ( ( address & 0x0000ff0000000000 ) >> 24 ) | ( ( address & 0x00ff000000000000 ) >> 40 ) | ( ( address & 0xff00000000000000 ) >> 56 )
 if 95 - 95: i11iIiiIii * II111iiii * OOooOOo * iIii1I11I1II1
 if 22 - 22: iIii1I11I1II1 / I1IiiI + OoOoOO00 - OOooOOo . i11iIiiIii / i11iIiiIii
 if 10 - 10: iIii1I11I1II1 % i1IIi
 if 78 - 78: I11i + II111iiii % o0oOOo0O0Ooo
 if 17 - 17: i11iIiiIii + oO0o * iII111i . II111iiii
 if 44 - 44: I1ii11iIi11i
 if 39 - 39: iII111i + Oo0Ooo / oO0o
 if 95 - 95: I1Ii111 * oO0o / ooOoO0o . Ii1I . OoOoOO00
 return ( oOo00Ooo0o0 )
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
   I1iII1iI1 = 0
  elif ( prefix . afi == LISP_AFI_IID_RANGE ) :
   I1iII1iI1 = prefix . mask_len
  else :
   I1iII1iI1 = prefix . mask_len + 48
   if 58 - 58: i11iIiiIii / OoOoOO00
   if 23 - 23: I1IiiI % iIii1I11I1II1 - oO0o - iII111i - o0oOOo0O0Ooo
  II1ii1ii11I1 = lisp_hex_string ( prefix . instance_id ) . zfill ( 8 )
  ii1iI1i1 = lisp_hex_string ( prefix . afi ) . zfill ( 4 )
  if 39 - 39: Oo0Ooo . OoO0O00
  if ( prefix . afi > 0 ) :
   if ( prefix . is_binary ( ) ) :
    O00OoO0oo = prefix . addr_length ( ) * 2
    oOo00Ooo0o0 = lisp_hex_string ( prefix . address ) . zfill ( O00OoO0oo )
   else :
    oOo00Ooo0o0 = prefix . address
    if 74 - 74: I1IiiI . O0 . IiII + IiII - IiII
  elif ( prefix . afi == LISP_AFI_GEO_COORD ) :
   ii1iI1i1 = "8003"
   oOo00Ooo0o0 = prefix . address . print_geo ( )
  else :
   ii1iI1i1 = ""
   oOo00Ooo0o0 = ""
   if 100 - 100: ooOoO0o / OoooooooOO
   if 73 - 73: i11iIiiIii - Oo0Ooo
  OOO0OOoOOO = II1ii1ii11I1 + ii1iI1i1 + oOo00Ooo0o0
  return ( [ I1iII1iI1 , OOO0OOoOOO ] )
  if 100 - 100: iIii1I11I1II1 + I1Ii111
  if 51 - 51: o0oOOo0O0Ooo * I11i
 def add_cache ( self , prefix , entry ) :
  if ( prefix . is_binary ( ) ) : prefix . zero_host_bits ( )
  I1iII1iI1 , OOO0OOoOOO = self . build_key ( prefix )
  if ( self . cache . has_key ( I1iII1iI1 ) == False ) :
   self . cache [ I1iII1iI1 ] = lisp_cache_entries ( )
   self . cache [ I1iII1iI1 ] . entries = { }
   self . cache [ I1iII1iI1 ] . entries_sorted = [ ]
   self . cache_sorted = sorted ( self . cache )
   if 42 - 42: OOooOOo % I11i
  if ( self . cache [ I1iII1iI1 ] . entries . has_key ( OOO0OOoOOO ) == False ) :
   self . cache_count += 1
   if 84 - 84: Oo0Ooo * OoOoOO00 / Ii1I / IiII / o0oOOo0O0Ooo . I1ii11iIi11i
  self . cache [ I1iII1iI1 ] . entries [ OOO0OOoOOO ] = entry
  self . cache [ I1iII1iI1 ] . entries_sorted = sorted ( self . cache [ I1iII1iI1 ] . entries )
  if 81 - 81: I1IiiI
  if 82 - 82: I1Ii111 - OoooooooOO - Ii1I
 def lookup_cache ( self , prefix , exact ) :
  IIii , OOO0OOoOOO = self . build_key ( prefix )
  if ( exact ) :
   if ( self . cache . has_key ( IIii ) == False ) : return ( None )
   if ( self . cache [ IIii ] . entries . has_key ( OOO0OOoOOO ) == False ) : return ( None )
   return ( self . cache [ IIii ] . entries [ OOO0OOoOOO ] )
   if 60 - 60: iII111i . o0oOOo0O0Ooo + iII111i
   if 38 - 38: i11iIiiIii * I11i + Oo0Ooo - iIii1I11I1II1
  IiiiIiI1 = None
  for I1iII1iI1 in self . cache_sorted :
   if ( IIii < I1iII1iI1 ) : return ( IiiiIiI1 )
   for OoO000o0OoOO in self . cache [ I1iII1iI1 ] . entries_sorted :
    i1I1I11ii = self . cache [ I1iII1iI1 ] . entries
    if ( OoO000o0OoOO in i1I1I11ii ) :
     iiIiiIi = i1I1I11ii [ OoO000o0OoOO ]
     if ( iiIiiIi == None ) : continue
     if ( prefix . is_more_specific ( iiIiiIi . eid ) ) : IiiiIiI1 = iiIiiIi
     if 36 - 36: iII111i - iII111i
     if 13 - 13: iIii1I11I1II1 % iIii1I11I1II1 + i1IIi / OoO0O00 - iII111i * oO0o
     if 13 - 13: OoO0O00
  return ( IiiiIiI1 )
  if 31 - 31: o0oOOo0O0Ooo + O0
  if 94 - 94: IiII * i1IIi
 def delete_cache ( self , prefix ) :
  I1iII1iI1 , OOO0OOoOOO = self . build_key ( prefix )
  if ( self . cache . has_key ( I1iII1iI1 ) == False ) : return
  if ( self . cache [ I1iII1iI1 ] . entries . has_key ( OOO0OOoOOO ) == False ) : return
  self . cache [ I1iII1iI1 ] . entries . pop ( OOO0OOoOOO )
  self . cache [ I1iII1iI1 ] . entries_sorted . remove ( OOO0OOoOOO )
  self . cache_count -= 1
  if 90 - 90: O0 % I1IiiI . o0oOOo0O0Ooo % ooOoO0o % I1IiiI
  if 16 - 16: OoO0O00 / OOooOOo / iIii1I11I1II1 / OoooooooOO . oO0o - I1Ii111
 def walk_cache ( self , function , parms ) :
  for I1iII1iI1 in self . cache_sorted :
   for OOO0OOoOOO in self . cache [ I1iII1iI1 ] . entries_sorted :
    iiIiiIi = self . cache [ I1iII1iI1 ] . entries [ OOO0OOoOOO ]
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
  for I1iII1iI1 in self . cache_sorted :
   for OOO0OOoOOO in self . cache [ I1iII1iI1 ] . entries_sorted :
    iiIiiIi = self . cache [ I1iII1iI1 ] . entries [ OOO0OOoOOO ]
    lprint ( "  Mask-length: {}, key: {}, entry: {}" . format ( I1iII1iI1 , OOO0OOoOOO ,
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
  O0o0O0OO0o = source . print_sg ( dest ) if OOooO else dest . print_address ( )
  O0o0O0OO0o = green ( O0o0O0OO0o , False )
  dprint ( "Lookup for EID {} not found in map-cache" . format ( O0o0O0OO0o ) )
  return ( None )
  if 21 - 21: Ii1I * OoOoOO00
  if 29 - 29: iIii1I11I1II1 / ooOoO0o
  if 75 - 75: OoooooooOO + I1IiiI % OoOoOO00 / O0 - IiII
  if 88 - 88: OoO0O00 % Ii1I
  if 12 - 12: OoooooooOO . O0
 if ( OOooO == False ) :
  ooo0oO0oo0o = green ( OoOOO000O0o . eid . print_prefix ( ) , False )
  dprint ( "Lookup for EID {} found map-cache entry {}" . format ( green ( dest . print_address ( ) , False ) , ooo0oO0oo0o ) )
  if 33 - 33: OoooooooOO / I11i . II111iiii * i1IIi
  return ( OoOOO000O0o )
  if 34 - 34: i11iIiiIii / OoOoOO00
  if 100 - 100: o0oOOo0O0Ooo - I1IiiI / I11i
  if 43 - 43: o0oOOo0O0Ooo % iIii1I11I1II1
  if 85 - 85: oO0o + OoooooooOO - IiII % o0oOOo0O0Ooo * ooOoO0o * II111iiii
  if 4 - 4: Ii1I . i1IIi + Oo0Ooo % I11i . OoO0O00
 OoOOO000O0o = OoOOO000O0o . lookup_source_cache ( source , False )
 if ( OoOOO000O0o == None ) :
  O0o0O0OO0o = source . print_sg ( dest )
  dprint ( "Lookup for EID {} not found in map-cache" . format ( O0o0O0OO0o ) )
  return ( None )
  if 70 - 70: OOooOOo * OoOoOO00 / OoOoOO00 / OoOoOO00
  if 23 - 23: I1IiiI
  if 24 - 24: I1Ii111 * i1IIi % O0 * Ii1I + iII111i
  if 14 - 14: oO0o * iII111i + Ii1I + Ii1I * IiII
  if 82 - 82: IiII * ooOoO0o / OOooOOo + OoOoOO00
 ooo0oO0oo0o = green ( OoOOO000O0o . print_eid_tuple ( ) , False )
 dprint ( "Lookup for EID {} found map-cache entry {}" . format ( green ( source . print_sg ( dest ) , False ) , ooo0oO0oo0o ) )
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
  O00OoO0O = lisp_ddt_cache . lookup_cache ( eid , exact )
  return ( O00OoO0O )
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
 O00OoO0O = lisp_ddt_cache . lookup_cache ( group , exact )
 if ( O00OoO0O == None ) : return ( None )
 if 99 - 99: OOooOOo
 ooII1iIIiIIIi1 = O00OoO0O . lookup_source_cache ( eid , exact )
 if ( ooII1iIIiIIIi1 ) : return ( ooII1iIIiIIIi1 )
 if 79 - 79: oO0o % o0oOOo0O0Ooo / o0oOOo0O0Ooo % iII111i
 if ( exact ) : O00OoO0O = None
 return ( O00OoO0O )
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
  O0OO = lisp_sites_by_eid . lookup_cache ( eid , exact )
  return ( O0OO )
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
 O0OO = lisp_sites_by_eid . lookup_cache ( group , exact )
 if ( O0OO == None ) : return ( None )
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
 I1IIiI = O0OO . lookup_source_cache ( eid , exact )
 if ( I1IIiI ) : return ( I1IIiI )
 if 53 - 53: Oo0Ooo
 if ( exact ) :
  O0OO = None
 else :
  o0OoOOO = O0OO . parent_for_more_specifics
  if ( o0OoOOO and o0OoOOO . accept_more_specifics ) :
   if ( group . is_more_specific ( o0OoOOO . group ) ) : O0OO = o0OoOOO
   if 16 - 16: Ii1I
   if 73 - 73: i11iIiiIii + I1IiiI - IiII - IiII + IiII . Ii1I
 return ( O0OO )
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
  oOo00Ooo0o0 = self . address
  if ( ( ( oOo00Ooo0o0 & 0xff000000 ) >> 24 ) == 10 ) : return ( True )
  if ( ( ( oOo00Ooo0o0 & 0xff000000 ) >> 24 ) == 172 ) :
   iI11IIiI1i = ( oOo00Ooo0o0 & 0x00ff0000 ) >> 16
   if ( iI11IIiI1i >= 16 and iI11IIiI1i <= 31 ) : return ( True )
   if 73 - 73: II111iiii
  if ( ( ( oOo00Ooo0o0 & 0xffff0000 ) >> 16 ) == 0xc0a8 ) : return ( True )
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
  oOo00Ooo0o0 = self . address >> 96
  return ( oOo00Ooo0o0 == 0x20010005 )
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
  III11i = self . packet_format ( )
  Ii11iIiiI = ""
  if ( self . is_ipv4 ( ) ) :
   Ii11iIiiI = struct . pack ( III11i , socket . htonl ( self . address ) )
  elif ( self . is_ipv6 ( ) ) :
   oOOo0ooO0 = byte_swap_64 ( self . address >> 64 )
   ii1i1II11II1i = byte_swap_64 ( self . address & 0xffffffffffffffff )
   Ii11iIiiI = struct . pack ( III11i , oOOo0ooO0 , ii1i1II11II1i )
  elif ( self . is_mac ( ) ) :
   oOo00Ooo0o0 = self . address
   oOOo0ooO0 = ( oOo00Ooo0o0 >> 32 ) & 0xffff
   ii1i1II11II1i = ( oOo00Ooo0o0 >> 16 ) & 0xffff
   Iii1IIi11ii1i = oOo00Ooo0o0 & 0xffff
   Ii11iIiiI = struct . pack ( III11i , oOOo0ooO0 , ii1i1II11II1i , Iii1IIi11ii1i )
  elif ( self . is_e164 ( ) ) :
   oOo00Ooo0o0 = self . address
   oOOo0ooO0 = ( oOo00Ooo0o0 >> 32 ) & 0xffffffff
   ii1i1II11II1i = ( oOo00Ooo0o0 & 0xffffffff )
   Ii11iIiiI = struct . pack ( III11i , oOOo0ooO0 , ii1i1II11II1i )
  elif ( self . is_dist_name ( ) ) :
   Ii11iIiiI += self . address + "\0"
   if 80 - 80: I1IiiI % Ii1I
  return ( Ii11iIiiI )
  if 29 - 29: i1IIi % o0oOOo0O0Ooo + OOooOOo / Oo0Ooo
  if 38 - 38: IiII . I1Ii111
 def unpack_address ( self , packet ) :
  III11i = self . packet_format ( )
  Oo0o0OOo0Oo0 = struct . calcsize ( III11i )
  if ( len ( packet ) < Oo0o0OOo0Oo0 ) : return ( None )
  if 69 - 69: ooOoO0o + OoOoOO00 + II111iiii % I1Ii111 + Ii1I . ooOoO0o
  oOo00Ooo0o0 = struct . unpack ( III11i , packet [ : Oo0o0OOo0Oo0 ] )
  if 73 - 73: I11i % I11i . ooOoO0o + OoOoOO00
  if ( self . is_ipv4 ( ) ) :
   self . address = socket . ntohl ( oOo00Ooo0o0 [ 0 ] )
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
   if ( oOo00Ooo0o0 [ 0 ] <= 0xffff and ( oOo00Ooo0o0 [ 0 ] & 0xff ) == 0 ) :
    ii1iiII = ( oOo00Ooo0o0 [ 0 ] << 48 ) << 64
   else :
    ii1iiII = byte_swap_64 ( oOo00Ooo0o0 [ 0 ] ) << 64
    if 99 - 99: oO0o + Oo0Ooo . IiII * I1IiiI
   IiIIIIi1 = byte_swap_64 ( oOo00Ooo0o0 [ 1 ] )
   self . address = ii1iiII | IiIIIIi1
   if 2 - 2: I1Ii111 + I1ii11iIi11i * i1IIi - iIii1I11I1II1 - I1ii11iIi11i
  elif ( self . is_mac ( ) ) :
   Oo00OOo0o = oOo00Ooo0o0 [ 0 ]
   ooOIIi1Iii1 = oOo00Ooo0o0 [ 1 ]
   IIIII1I11ii = oOo00Ooo0o0 [ 2 ]
   self . address = ( Oo00OOo0o << 32 ) + ( ooOIIi1Iii1 << 16 ) + IIIII1I11ii
   if 39 - 39: OOooOOo . IiII + I1IiiI % iII111i - oO0o / OoO0O00
  elif ( self . is_e164 ( ) ) :
   self . address = ( oOo00Ooo0o0 [ 0 ] << 32 ) + oOo00Ooo0o0 [ 1 ]
   if 37 - 37: O0 % OoO0O00 + i11iIiiIii . O0 / OOooOOo
  elif ( self . is_dist_name ( ) ) :
   packet , self . address = lisp_decode_dist_name ( packet )
   self . mask_len = len ( self . address ) * 8
   Oo0o0OOo0Oo0 = 0
   if 15 - 15: I1ii11iIi11i + oO0o
  packet = packet [ Oo0o0OOo0Oo0 : : ]
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
  oo0O0oO0O0O = addr_str . find ( "[" )
  iIIi11i1i1I1I = addr_str . find ( "]" )
  if ( oo0O0oO0O0O != - 1 and iIIi11i1i1I1I != - 1 ) :
   self . instance_id = int ( addr_str [ oo0O0oO0O0O + 1 : iIIi11i1i1I1I ] )
   addr_str = addr_str [ iIIi11i1i1I1I + 1 : : ]
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
   O000O = int ( ii1iiI1i1Ii1 [ 0 ] ) << 24
   O000O += int ( ii1iiI1i1Ii1 [ 1 ] ) << 16
   O000O += int ( ii1iiI1i1Ii1 [ 2 ] ) << 8
   O000O += int ( ii1iiI1i1Ii1 [ 3 ] )
   self . address = O000O
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
   i1ii1i1i11 = ( addr_str [ 2 : 4 ] == "::" )
   try :
    addr_str = socket . inet_pton ( socket . AF_INET6 , addr_str )
   except :
    addr_str = socket . inet_pton ( socket . AF_INET6 , "0::0" )
    if 41 - 41: OoooooooOO * I11i
   addr_str = binascii . hexlify ( addr_str )
   if 59 - 59: ooOoO0o * I1Ii111 - ooOoO0o
   if ( i1ii1i1i11 ) :
    addr_str = addr_str [ 2 : 4 ] + addr_str [ 0 : 2 ] + addr_str [ 4 : : ]
    if 48 - 48: O0 * O0 - iII111i . iII111i + I1Ii111
   self . address = int ( addr_str , 16 )
   if 25 - 25: o0oOOo0O0Ooo . I1ii11iIi11i + i1IIi
  elif ( self . is_geo_prefix ( ) ) :
   OOOOo = lisp_geo ( None )
   OOOOo . name = "geo-prefix-{}" . format ( OOOOo )
   OOOOo . parse_geo_string ( addr_str )
   self . address = OOOOo
  elif ( self . is_mac ( ) ) :
   addr_str = addr_str . replace ( "-" , "" )
   O000O = int ( addr_str , 16 )
   self . address = O000O
  elif ( self . is_e164 ( ) ) :
   addr_str = addr_str [ 1 : : ]
   O000O = int ( addr_str , 16 )
   self . address = O000O << 4
  elif ( self . is_dist_name ( ) ) :
   self . address = addr_str . replace ( "'" , "" )
   if 35 - 35: I1Ii111 % iII111i - i11iIiiIii / Oo0Ooo * iII111i + iII111i
  self . mask_len = self . host_mask_len ( )
  if 84 - 84: Oo0Ooo * I1Ii111
  if 28 - 28: Oo0Ooo / I1IiiI + I1Ii111 % iII111i * iIii1I11I1II1
 def store_prefix ( self , prefix_str ) :
  if ( self . is_geo_string ( prefix_str ) ) :
   Oo0oOooo000OO = prefix_str . find ( "]" )
   ooI1111 = len ( prefix_str [ Oo0oOooo000OO + 1 : : ] ) * 8
  elif ( prefix_str . find ( "/" ) != - 1 ) :
   prefix_str , ooI1111 = prefix_str . split ( "/" )
  else :
   ooooOooooOOo = prefix_str . find ( "'" )
   if ( ooooOooooOOo == - 1 ) : return
   oOO0o00O = prefix_str . find ( "'" , ooooOooooOOo + 1 )
   if ( oOO0o00O == - 1 ) : return
   ooI1111 = len ( prefix_str [ ooooOooooOOo + 1 : oOO0o00O ] ) * 8
   if 94 - 94: o0oOOo0O0Ooo
   if 66 - 66: Ii1I - Oo0Ooo / oO0o + iII111i % IiII
  self . string_to_afi ( prefix_str )
  self . store_address ( prefix_str )
  self . mask_len = int ( ooI1111 )
  if 19 - 19: I1IiiI + I1IiiI + I1Ii111 % i1IIi * I1IiiI
  if 83 - 83: II111iiii - o0oOOo0O0Ooo . OoO0O00 . OOooOOo % o0oOOo0O0Ooo
 def zero_host_bits ( self ) :
  if ( self . mask_len < 0 ) : return
  Oo0oOOOOo00 = ( 2 ** self . mask_len ) - 1
  IIIioO = self . addr_length ( ) * 8 - self . mask_len
  Oo0oOOOOo00 <<= IIIioO
  self . address &= Oo0oOOOOo00
  if 82 - 82: iII111i - OOooOOo * OOooOOo
  if 2 - 2: I1IiiI . i11iIiiIii / OoOoOO00 * OOooOOo + I1ii11iIi11i % oO0o
 def is_geo_string ( self , addr_str ) :
  Oo0oOooo000OO = addr_str . find ( "]" )
  if ( Oo0oOooo000OO != - 1 ) : addr_str = addr_str [ Oo0oOooo000OO + 1 : : ]
  if 62 - 62: I1Ii111
  OOOOo = addr_str . split ( "/" )
  if ( len ( OOOOo ) == 2 ) :
   if ( OOOOo [ 1 ] . isdigit ( ) == False ) : return ( False )
   if 74 - 74: OoooooooOO / O0 - I1ii11iIi11i - iIii1I11I1II1
  OOOOo = OOOOo [ 0 ]
  OOOOo = OOOOo . split ( "-" )
  Oo0ooO0 = len ( OOOOo )
  if ( Oo0ooO0 < 8 or Oo0ooO0 > 9 ) : return ( False )
  if 8 - 8: OoO0O00 + IiII * I11i + I1ii11iIi11i / I11i
  for O00OOoOO0OoOo in range ( 0 , Oo0ooO0 ) :
   if ( O00OOoOO0OoOo == 3 ) :
    if ( OOOOo [ O00OOoOO0OoOo ] in [ "N" , "S" ] ) : continue
    return ( False )
    if 14 - 14: OoO0O00 . iII111i
   if ( O00OOoOO0OoOo == 7 ) :
    if ( OOOOo [ O00OOoOO0OoOo ] in [ "W" , "E" ] ) : continue
    return ( False )
    if 4 - 4: o0oOOo0O0Ooo
   if ( OOOOo [ O00OOoOO0OoOo ] . isdigit ( ) == False ) : return ( False )
   if 98 - 98: I1IiiI + II111iiii . iII111i
  return ( True )
  if 9 - 9: I11i % o0oOOo0O0Ooo % I1Ii111 - ooOoO0o + I11i
  if 87 - 87: IiII
 def string_to_afi ( self , addr_str ) :
  if ( addr_str . count ( "'" ) == 2 ) :
   self . afi = LISP_AFI_NAME
   return
   if 12 - 12: O0 - iII111i * IiII . i11iIiiIii
  if ( addr_str . find ( ":" ) != - 1 ) : self . afi = LISP_AFI_IPV6
  elif ( addr_str . find ( "." ) != - 1 ) : self . afi = LISP_AFI_IPV4
  elif ( addr_str . find ( "+" ) != - 1 ) : self . afi = LISP_AFI_E164
  elif ( self . is_geo_string ( addr_str ) ) : self . afi = LISP_AFI_GEO_COORD
  elif ( addr_str . find ( "-" ) != - 1 ) : self . afi = LISP_AFI_MAC
  else : self . afi = LISP_AFI_NONE
  if 25 - 25: Ii1I % i1IIi * I11i * Ii1I - IiII . i11iIiiIii
  if 40 - 40: OOooOOo - OoooooooOO
 def print_address ( self ) :
  oOo00Ooo0o0 = self . print_address_no_iid ( )
  II1ii1ii11I1 = "[" + str ( self . instance_id )
  for oo0O0oO0O0O in self . iid_list : II1ii1ii11I1 += "," + str ( oo0O0oO0O0O )
  II1ii1ii11I1 += "]"
  oOo00Ooo0o0 = "{}{}" . format ( II1ii1ii11I1 , oOo00Ooo0o0 )
  return ( oOo00Ooo0o0 )
  if 36 - 36: i1IIi % OoOoOO00 - i1IIi
  if 5 - 5: I1IiiI . I1IiiI % II111iiii - I1Ii111
 def print_address_no_iid ( self ) :
  if ( self . is_ipv4 ( ) ) :
   oOo00Ooo0o0 = self . address
   o0OoOOoO0o0 = oOo00Ooo0o0 >> 24
   Ii1II1I1 = ( oOo00Ooo0o0 >> 16 ) & 0xff
   OoOooOo0o0O0o = ( oOo00Ooo0o0 >> 8 ) & 0xff
   o0oO000Oo0 = oOo00Ooo0o0 & 0xff
   return ( "{}.{}.{}.{}" . format ( o0OoOOoO0o0 , Ii1II1I1 , OoOooOo0o0O0o , o0oO000Oo0 ) )
  elif ( self . is_ipv6 ( ) ) :
   i111I11I = lisp_hex_string ( self . address ) . zfill ( 32 )
   i111I11I = binascii . unhexlify ( i111I11I )
   i111I11I = socket . inet_ntop ( socket . AF_INET6 , i111I11I )
   return ( "{}" . format ( i111I11I ) )
  elif ( self . is_geo_prefix ( ) ) :
   return ( "{}" . format ( self . address . print_geo ( ) ) )
  elif ( self . is_mac ( ) ) :
   i111I11I = lisp_hex_string ( self . address ) . zfill ( 12 )
   i111I11I = "{}-{}-{}" . format ( i111I11I [ 0 : 4 ] , i111I11I [ 4 : 8 ] ,
 i111I11I [ 8 : 12 ] )
   return ( "{}" . format ( i111I11I ) )
  elif ( self . is_e164 ( ) ) :
   i111I11I = lisp_hex_string ( self . address ) . zfill ( 15 )
   return ( "+{}" . format ( i111I11I ) )
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
  oOo00Ooo0o0 = self . print_address ( )
  if ( self . is_dist_name ( ) ) : return ( oOo00Ooo0o0 )
  if ( self . is_geo_prefix ( ) ) : return ( oOo00Ooo0o0 )
  if 78 - 78: I1Ii111 + I1Ii111
  Oo0oOooo000OO = oOo00Ooo0o0 . find ( "no-address" )
  if ( Oo0oOooo000OO == - 1 ) :
   oOo00Ooo0o0 = "{}/{}" . format ( oOo00Ooo0o0 , str ( self . mask_len ) )
  else :
   oOo00Ooo0o0 = oOo00Ooo0o0 [ 0 : Oo0oOooo000OO ]
   if 43 - 43: I1Ii111 * o0oOOo0O0Ooo + i1IIi
  return ( oOo00Ooo0o0 )
  if 19 - 19: Ii1I
  if 51 - 51: oO0o
 def print_prefix_no_iid ( self ) :
  oOo00Ooo0o0 = self . print_address_no_iid ( )
  if ( self . is_dist_name ( ) ) : return ( oOo00Ooo0o0 )
  if ( self . is_geo_prefix ( ) ) : return ( oOo00Ooo0o0 )
  return ( "{}/{}" . format ( oOo00Ooo0o0 , str ( self . mask_len ) ) )
  if 57 - 57: i11iIiiIii - Oo0Ooo + I1Ii111 * OoO0O00
  if 35 - 35: o0oOOo0O0Ooo % II111iiii + O0
 def print_prefix_url ( self ) :
  if ( self . is_ultimate_root ( ) ) : return ( "0--0" )
  oOo00Ooo0o0 = self . print_address ( )
  Oo0oOooo000OO = oOo00Ooo0o0 . find ( "]" )
  if ( Oo0oOooo000OO != - 1 ) : oOo00Ooo0o0 = oOo00Ooo0o0 [ Oo0oOooo000OO + 1 : : ]
  if ( self . is_geo_prefix ( ) ) :
   oOo00Ooo0o0 = oOo00Ooo0o0 . replace ( "/" , "-" )
   return ( "{}-{}" . format ( self . instance_id , oOo00Ooo0o0 ) )
   if 70 - 70: I1ii11iIi11i . II111iiii
  return ( "{}-{}-{}" . format ( self . instance_id , oOo00Ooo0o0 , self . mask_len ) )
  if 54 - 54: OOooOOo
  if 67 - 67: I1IiiI . o0oOOo0O0Ooo / i1IIi * I1ii11iIi11i . Oo0Ooo + II111iiii
 def print_sg ( self , g ) :
  oOOOOOOOoO = self . print_prefix ( )
  oOOo00OO = oOOOOOOOoO . find ( "]" ) + 1
  g = g . print_prefix ( )
  IiO0oOOOoOO00O0 = g . find ( "]" ) + 1
  iIiI1iI1i1I = "[{}]({}, {})" . format ( self . instance_id , oOOOOOOOoO [ oOOo00OO : : ] , g [ IiO0oOOOoOO00O0 : : ] )
  return ( iIiI1iI1i1I )
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
   iIIo0OOO = 2 ** ( 32 - ooI1111 )
   oOOooO0OO = prefix . instance_id
   iiI = oOOooO0OO + iIIo0OOO
   return ( self . instance_id in range ( oOOooO0OO , iiI ) )
   if 99 - 99: I1ii11iIi11i - OoooooooOO - Ii1I / Oo0Ooo
   if 96 - 96: o0oOOo0O0Ooo . II111iiii
  if ( self . instance_id != prefix . instance_id ) : return ( False )
  if ( self . afi != prefix . afi ) :
   if ( prefix . afi != LISP_AFI_NONE ) : return ( False )
   if 14 - 14: OoooooooOO - i1IIi / i11iIiiIii - OOooOOo - i11iIiiIii . ooOoO0o
   if 8 - 8: oO0o * O0 - II111iiii + I1IiiI
   if 85 - 85: OoooooooOO % i11iIiiIii / IiII % OoOoOO00 + O0
   if 6 - 6: OoooooooOO
   if 97 - 97: II111iiii + o0oOOo0O0Ooo * II111iiii
  if ( self . is_binary ( ) == False ) :
   if ( prefix . afi == LISP_AFI_NONE ) : return ( True )
   if ( type ( self . address ) != type ( prefix . address ) ) : return ( False )
   oOo00Ooo0o0 = self . address
   iII1iOo0OOOoOO0o0O = prefix . address
   if ( self . is_geo_prefix ( ) ) :
    oOo00Ooo0o0 = self . address . print_geo ( )
    iII1iOo0OOOoOO0o0O = prefix . address . print_geo ( )
    if 54 - 54: OoO0O00
   if ( len ( oOo00Ooo0o0 ) < len ( iII1iOo0OOOoOO0o0O ) ) : return ( False )
   return ( oOo00Ooo0o0 . find ( iII1iOo0OOOoOO0o0O ) == 0 )
   if 75 - 75: oO0o - iIii1I11I1II1 - I1Ii111 / IiII % iIii1I11I1II1
   if 96 - 96: oO0o - oO0o / OOooOOo
   if 3 - 3: iIii1I11I1II1 / I1IiiI % OoO0O00 . I1Ii111
   if 46 - 46: I11i % iII111i % iII111i / I11i / I1IiiI
   if 74 - 74: oO0o / iIii1I11I1II1 + Oo0Ooo * ooOoO0o % iII111i % i1IIi
  if ( self . mask_len < ooI1111 ) : return ( False )
  if 68 - 68: OoooooooOO
  IIIioO = ( prefix . addr_length ( ) * 8 ) - ooI1111
  Oo0oOOOOo00 = ( 2 ** ooI1111 - 1 ) << IIIioO
  return ( ( self . address & Oo0oOOOOo00 ) == prefix . address )
  if 81 - 81: OoO0O00 % i1IIi
  if 95 - 95: Oo0Ooo - O0 / I1ii11iIi11i . I1IiiI / o0oOOo0O0Ooo % OoOoOO00
 def mask_address ( self , mask_len ) :
  IIIioO = ( self . addr_length ( ) * 8 ) - mask_len
  Oo0oOOOOo00 = ( 2 ** mask_len - 1 ) << IIIioO
  self . address &= Oo0oOOOOo00
  if 38 - 38: OoOoOO00 % OoooooooOO . oO0o - OoooooooOO + I11i
  if 18 - 18: OoooooooOO + ooOoO0o * OoOoOO00 - OoO0O00
 def is_exact_match ( self , prefix ) :
  if ( self . instance_id != prefix . instance_id ) : return ( False )
  IIIIIIi1i1I = self . print_prefix ( )
  oo00oOooo = prefix . print_prefix ( ) if prefix else ""
  return ( IIIIIIi1i1I == oo00oOooo )
  if 8 - 8: iIii1I11I1II1
  if 94 - 94: i11iIiiIii . o0oOOo0O0Ooo . iIii1I11I1II1 . O0
 def is_local ( self ) :
  if ( self . is_ipv4 ( ) ) :
   IIooOoOoO0ooOOo = lisp_myrlocs [ 0 ]
   if ( IIooOoOoO0ooOOo == None ) : return ( False )
   IIooOoOoO0ooOOo = IIooOoOoO0ooOOo . print_address_no_iid ( )
   return ( self . print_address_no_iid ( ) == IIooOoOoO0ooOOo )
   if 47 - 47: I11i - I1Ii111 % OoooooooOO
  if ( self . is_ipv6 ( ) ) :
   IIooOoOoO0ooOOo = lisp_myrlocs [ 1 ]
   if ( IIooOoOoO0ooOOo == None ) : return ( False )
   IIooOoOoO0ooOOo = IIooOoOoO0ooOOo . print_address_no_iid ( )
   return ( self . print_address_no_iid ( ) == IIooOoOoO0ooOOo )
   if 5 - 5: I11i / oO0o - o0oOOo0O0Ooo
  return ( False )
  if 47 - 47: OoOoOO00 . iIii1I11I1II1 * i11iIiiIii
  if 83 - 83: I1IiiI . i11iIiiIii * iII111i
 def store_iid_range ( self , iid , mask_len ) :
  if ( self . afi == LISP_AFI_NONE ) :
   if ( iid is 0 and mask_len is 0 ) : self . afi = LISP_AFI_ULTIMATE_ROOT
   else : self . afi = LISP_AFI_IID_RANGE
   if 96 - 96: OoOoOO00
  self . instance_id = iid
  self . mask_len = mask_len
  if 84 - 84: OOooOOo
  if 68 - 68: I1Ii111
 def lcaf_length ( self , lcaf_type ) :
  O00OoO0oo = self . addr_length ( ) + 2
  if ( lcaf_type == LISP_LCAF_AFI_LIST_TYPE ) : O00OoO0oo += 4
  if ( lcaf_type == LISP_LCAF_INSTANCE_ID_TYPE ) : O00OoO0oo += 4
  if ( lcaf_type == LISP_LCAF_ASN_TYPE ) : O00OoO0oo += 4
  if ( lcaf_type == LISP_LCAF_APP_DATA_TYPE ) : O00OoO0oo += 8
  if ( lcaf_type == LISP_LCAF_GEO_COORD_TYPE ) : O00OoO0oo += 12
  if ( lcaf_type == LISP_LCAF_OPAQUE_TYPE ) : O00OoO0oo += 0
  if ( lcaf_type == LISP_LCAF_NAT_TYPE ) : O00OoO0oo += 4
  if ( lcaf_type == LISP_LCAF_NONCE_LOC_TYPE ) : O00OoO0oo += 4
  if ( lcaf_type == LISP_LCAF_MCAST_INFO_TYPE ) : O00OoO0oo = O00OoO0oo * 2 + 8
  if ( lcaf_type == LISP_LCAF_ELP_TYPE ) : O00OoO0oo += 0
  if ( lcaf_type == LISP_LCAF_SECURITY_TYPE ) : O00OoO0oo += 6
  if ( lcaf_type == LISP_LCAF_SOURCE_DEST_TYPE ) : O00OoO0oo += 4
  if ( lcaf_type == LISP_LCAF_RLE_TYPE ) : O00OoO0oo += 4
  return ( O00OoO0oo )
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
  if 93 - 93: iIii1I11I1II1 % OoooooooOO
  if 6 - 6: II111iiii / oO0o - OOooOOo . O0 - o0oOOo0O0Ooo
  if 72 - 72: iIii1I11I1II1 / OoooooooOO * ooOoO0o / ooOoO0o % O0 + IiII
  if 96 - 96: iII111i / i11iIiiIii + Oo0Ooo . I1IiiI + iII111i % OoOoOO00
  if 19 - 19: i11iIiiIii . Oo0Ooo . OoOoOO00 - I1IiiI
 def lcaf_encode_iid ( self ) :
  o0oOoOOO = LISP_LCAF_INSTANCE_ID_TYPE
  Oo0O0o00o00 = socket . htons ( self . lcaf_length ( o0oOoOOO ) )
  II1ii1ii11I1 = self . instance_id
  ii1iI1i1 = self . afi
  I1iII1iI1 = 0
  if ( ii1iI1i1 < 0 ) :
   if ( self . afi == LISP_AFI_GEO_COORD ) :
    ii1iI1i1 = LISP_AFI_LCAF
    I1iII1iI1 = 0
   else :
    ii1iI1i1 = 0
    I1iII1iI1 = self . mask_len
    if 85 - 85: I11i - OoO0O00 % iIii1I11I1II1 . iII111i + ooOoO0o . Oo0Ooo
    if 87 - 87: iII111i
    if 86 - 86: IiII - I11i
  ooOoOo0 = struct . pack ( "BBBBH" , 0 , 0 , o0oOoOOO , I1iII1iI1 , Oo0O0o00o00 )
  ooOoOo0 += struct . pack ( "IH" , socket . htonl ( II1ii1ii11I1 ) , socket . htons ( ii1iI1i1 ) )
  if ( ii1iI1i1 == 0 ) : return ( ooOoOo0 )
  if 70 - 70: I1ii11iIi11i * ooOoO0o
  if ( self . afi == LISP_AFI_GEO_COORD ) :
   ooOoOo0 = ooOoOo0 [ 0 : - 2 ]
   ooOoOo0 += self . address . encode_geo ( )
   return ( ooOoOo0 )
   if 14 - 14: I1ii11iIi11i + OoO0O00 - I1IiiI - Oo0Ooo
   if 44 - 44: II111iiii / I1ii11iIi11i
  ooOoOo0 += self . pack_address ( )
  return ( ooOoOo0 )
  if 39 - 39: OoooooooOO % OoO0O00
  if 83 - 83: OOooOOo % I1IiiI + O0 % OoooooooOO
 def lcaf_decode_iid ( self , packet ) :
  III11i = "BBBBH"
  Oo0o0OOo0Oo0 = struct . calcsize ( III11i )
  if ( len ( packet ) < Oo0o0OOo0Oo0 ) : return ( None )
  if 84 - 84: I11i - Oo0Ooo % ooOoO0o - II111iiii
  IiIIi , iiIiI1iiI1 , o0oOoOOO , iiI1iII1111I , O00OoO0oo = struct . unpack ( III11i ,
 packet [ : Oo0o0OOo0Oo0 ] )
  packet = packet [ Oo0o0OOo0Oo0 : : ]
  if 99 - 99: iII111i * Ii1I + OoOoOO00 / oO0o * I1Ii111 / o0oOOo0O0Ooo
  if ( o0oOoOOO != LISP_LCAF_INSTANCE_ID_TYPE ) : return ( None )
  if 94 - 94: OOooOOo
  III11i = "IH"
  Oo0o0OOo0Oo0 = struct . calcsize ( III11i )
  if ( len ( packet ) < Oo0o0OOo0Oo0 ) : return ( None )
  if 9 - 9: O0 + II111iiii . ooOoO0o / i1IIi + I1IiiI . OoOoOO00
  II1ii1ii11I1 , ii1iI1i1 = struct . unpack ( III11i , packet [ : Oo0o0OOo0Oo0 ] )
  packet = packet [ Oo0o0OOo0Oo0 : : ]
  if 100 - 100: oO0o
  O00OoO0oo = socket . ntohs ( O00OoO0oo )
  self . instance_id = socket . ntohl ( II1ii1ii11I1 )
  ii1iI1i1 = socket . ntohs ( ii1iI1i1 )
  self . afi = ii1iI1i1
  if ( iiI1iII1111I != 0 and ii1iI1i1 == 0 ) : self . mask_len = iiI1iII1111I
  if ( ii1iI1i1 == 0 ) :
   self . afi = LISP_AFI_IID_RANGE if iiI1iII1111I else LISP_AFI_ULTIMATE_ROOT
   if 7 - 7: i11iIiiIii - O0
   if 76 - 76: i1IIi . OOooOOo * iIii1I11I1II1 / I1ii11iIi11i % i11iIiiIii / O0
   if 83 - 83: oO0o % OoooooooOO
   if 36 - 36: IiII * OoOoOO00 - iIii1I11I1II1 + II111iiii
   if 65 - 65: I1IiiI * I11i . I1Ii111 % I1ii11iIi11i + O0
  if ( ii1iI1i1 == 0 ) : return ( packet )
  if 91 - 91: OoooooooOO % I1Ii111 * OoO0O00 - OoOoOO00
  if 5 - 5: iIii1I11I1II1 * I11i - oO0o % oO0o % o0oOOo0O0Ooo . i1IIi
  if 95 - 95: Oo0Ooo * I1ii11iIi11i + iII111i - o0oOOo0O0Ooo - Oo0Ooo . OoO0O00
  if 62 - 62: I11i
  if ( self . is_dist_name ( ) ) :
   packet , self . address = lisp_decode_dist_name ( packet )
   self . mask_len = len ( self . address ) * 8
   return ( packet )
   if 58 - 58: I11i . OoOoOO00 + iII111i . iII111i
   if 43 - 43: I1Ii111 + I1Ii111 % Oo0Ooo % OoO0O00 - ooOoO0o
   if 61 - 61: OoOoOO00 + Ii1I % i11iIiiIii - I1IiiI * OoO0O00 % iIii1I11I1II1
   if 66 - 66: iII111i + i1IIi
   if 24 - 24: O0 / OoooooooOO - OoOoOO00
  if ( ii1iI1i1 == LISP_AFI_LCAF ) :
   III11i = "BBBBH"
   Oo0o0OOo0Oo0 = struct . calcsize ( III11i )
   if ( len ( packet ) < Oo0o0OOo0Oo0 ) : return ( None )
   if 51 - 51: OoO0O00 + o0oOOo0O0Ooo - II111iiii * I11i + Ii1I
   iiII1II1 , iiIIii1Iii1I , o0oOoOOO , OO00 , i1IiI = struct . unpack ( III11i , packet [ : Oo0o0OOo0Oo0 ] )
   if 16 - 16: I1Ii111 * i1IIi . I1IiiI . OOooOOo % Ii1I - o0oOOo0O0Ooo
   if 89 - 89: Ii1I * I1ii11iIi11i * I1IiiI % iII111i % Ii1I + O0
   if ( o0oOoOOO != LISP_LCAF_GEO_COORD_TYPE ) : return ( None )
   if 53 - 53: i11iIiiIii % I1ii11iIi11i
   i1IiI = socket . ntohs ( i1IiI )
   packet = packet [ Oo0o0OOo0Oo0 : : ]
   if ( i1IiI > len ( packet ) ) : return ( None )
   if 59 - 59: OOooOOo
   OOOOo = lisp_geo ( "" )
   self . afi = LISP_AFI_GEO_COORD
   self . address = OOOOo
   packet = OOOOo . decode_geo ( packet , i1IiI , OO00 )
   self . mask_len = self . host_mask_len ( )
   return ( packet )
   if 61 - 61: OoooooooOO + O0 - i1IIi % oO0o / I1ii11iIi11i
   if 50 - 50: oO0o + II111iiii * OoOoOO00 % OoO0O00 . II111iiii % o0oOOo0O0Ooo
  Oo0O0o00o00 = self . addr_length ( )
  if ( len ( packet ) < Oo0O0o00o00 ) : return ( None )
  if 32 - 32: i1IIi / Ii1I + i11iIiiIii % oO0o
  packet = self . unpack_address ( packet )
  return ( packet )
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
  if 27 - 27: oO0o . iII111i . oO0o
  if 37 - 37: Oo0Ooo . I1ii11iIi11i / OoooooooOO % ooOoO0o / I1IiiI + ooOoO0o
  if 14 - 14: I11i + ooOoO0o . oO0o * I11i
  if 98 - 98: Ii1I . i1IIi * OoO0O00 * Ii1I * iIii1I11I1II1
  if 22 - 22: OoooooooOO - OoO0O00 + OoOoOO00 - OOooOOo + i11iIiiIii - oO0o
 def lcaf_encode_sg ( self , group ) :
  o0oOoOOO = LISP_LCAF_MCAST_INFO_TYPE
  II1ii1ii11I1 = socket . htonl ( self . instance_id )
  Oo0O0o00o00 = socket . htons ( self . lcaf_length ( o0oOoOOO ) )
  ooOoOo0 = struct . pack ( "BBBBHIHBB" , 0 , 0 , o0oOoOOO , 0 , Oo0O0o00o00 , II1ii1ii11I1 ,
 0 , self . mask_len , group . mask_len )
  if 9 - 9: I1Ii111 - i1IIi . ooOoO0o
  ooOoOo0 += struct . pack ( "H" , socket . htons ( self . afi ) )
  ooOoOo0 += self . pack_address ( )
  ooOoOo0 += struct . pack ( "H" , socket . htons ( group . afi ) )
  ooOoOo0 += group . pack_address ( )
  return ( ooOoOo0 )
  if 33 - 33: I11i
  if 37 - 37: Oo0Ooo
 def lcaf_decode_sg ( self , packet ) :
  III11i = "BBBBHIHBB"
  Oo0o0OOo0Oo0 = struct . calcsize ( III11i )
  if ( len ( packet ) < Oo0o0OOo0Oo0 ) : return ( [ None , None ] )
  if 36 - 36: IiII % I11i
  IiIIi , iiIiI1iiI1 , o0oOoOOO , O000OOOoOooO , O00OoO0oo , II1ii1ii11I1 , OO0000Oo0O , IIIiIiiI , ooOo = struct . unpack ( III11i , packet [ : Oo0o0OOo0Oo0 ] )
  if 44 - 44: OOooOOo - OOooOOo * IiII - iIii1I11I1II1
  packet = packet [ Oo0o0OOo0Oo0 : : ]
  if 72 - 72: iIii1I11I1II1 . OoooooooOO
  if ( o0oOoOOO != LISP_LCAF_MCAST_INFO_TYPE ) : return ( [ None , None ] )
  if 44 - 44: I11i * I11i + OoooooooOO
  self . instance_id = socket . ntohl ( II1ii1ii11I1 )
  O00OoO0oo = socket . ntohs ( O00OoO0oo ) - 8
  if 26 - 26: I1Ii111 * Ii1I
  if 95 - 95: oO0o + OoOoOO00 / OoO0O00 % I1IiiI
  if 28 - 28: I1IiiI
  if 59 - 59: OOooOOo . I1IiiI / i1IIi / II111iiii . II111iiii
  if 54 - 54: iIii1I11I1II1 % ooOoO0o
  III11i = "H"
  Oo0o0OOo0Oo0 = struct . calcsize ( III11i )
  if ( len ( packet ) < Oo0o0OOo0Oo0 ) : return ( [ None , None ] )
  if ( O00OoO0oo < Oo0o0OOo0Oo0 ) : return ( [ None , None ] )
  if 37 - 37: OOooOOo % OoOoOO00 - II111iiii * o0oOOo0O0Ooo . I1IiiI . OoOoOO00
  ii1iI1i1 = struct . unpack ( III11i , packet [ : Oo0o0OOo0Oo0 ] ) [ 0 ]
  packet = packet [ Oo0o0OOo0Oo0 : : ]
  O00OoO0oo -= Oo0o0OOo0Oo0
  self . afi = socket . ntohs ( ii1iI1i1 )
  self . mask_len = IIIiIiiI
  Oo0O0o00o00 = self . addr_length ( )
  if ( O00OoO0oo < Oo0O0o00o00 ) : return ( [ None , None ] )
  if 92 - 92: I11i + OoO0O00 . OoooooooOO
  packet = self . unpack_address ( packet )
  if ( packet == None ) : return ( [ None , None ] )
  if 3 - 3: OoO0O00 % iIii1I11I1II1
  O00OoO0oo -= Oo0O0o00o00
  if 62 - 62: OoooooooOO * o0oOOo0O0Ooo
  if 59 - 59: iIii1I11I1II1
  if 18 - 18: ooOoO0o % I1IiiI / iIii1I11I1II1 + O0
  if 99 - 99: i11iIiiIii - o0oOOo0O0Ooo + o0oOOo0O0Ooo . OoooooooOO * iII111i . Oo0Ooo
  if 63 - 63: I11i
  III11i = "H"
  Oo0o0OOo0Oo0 = struct . calcsize ( III11i )
  if ( len ( packet ) < Oo0o0OOo0Oo0 ) : return ( [ None , None ] )
  if ( O00OoO0oo < Oo0o0OOo0Oo0 ) : return ( [ None , None ] )
  if 60 - 60: I1IiiI / I1ii11iIi11i / I11i / Ii1I + iIii1I11I1II1
  ii1iI1i1 = struct . unpack ( III11i , packet [ : Oo0o0OOo0Oo0 ] ) [ 0 ]
  packet = packet [ Oo0o0OOo0Oo0 : : ]
  O00OoO0oo -= Oo0o0OOo0Oo0
  IiI1111i1i11I = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  IiI1111i1i11I . afi = socket . ntohs ( ii1iI1i1 )
  IiI1111i1i11I . mask_len = ooOo
  IiI1111i1i11I . instance_id = self . instance_id
  Oo0O0o00o00 = self . addr_length ( )
  if ( O00OoO0oo < Oo0O0o00o00 ) : return ( [ None , None ] )
  if 85 - 85: O0 / OOooOOo . OoOoOO00 / I1ii11iIi11i
  packet = IiI1111i1i11I . unpack_address ( packet )
  if ( packet == None ) : return ( [ None , None ] )
  if 80 - 80: I1ii11iIi11i * iII111i % i1IIi * OOooOOo % II111iiii % i1IIi
  return ( [ packet , IiI1111i1i11I ] )
  if 44 - 44: OoooooooOO
  if 18 - 18: i11iIiiIii
 def lcaf_decode_eid ( self , packet ) :
  III11i = "BBB"
  Oo0o0OOo0Oo0 = struct . calcsize ( III11i )
  if ( len ( packet ) < Oo0o0OOo0Oo0 ) : return ( [ None , None ] )
  if 65 - 65: i1IIi . iIii1I11I1II1 % iIii1I11I1II1
  if 35 - 35: iIii1I11I1II1 - o0oOOo0O0Ooo + I1ii11iIi11i * iII111i - OOooOOo . o0oOOo0O0Ooo
  if 12 - 12: iIii1I11I1II1 % OoO0O00 * Oo0Ooo
  if 5 - 5: I11i - II111iiii * iIii1I11I1II1 / iIii1I11I1II1 % IiII * i1IIi
  if 30 - 30: i1IIi % I1IiiI . OOooOOo % iIii1I11I1II1 . I1ii11iIi11i / o0oOOo0O0Ooo
  O000OOOoOooO , iiIIii1Iii1I , o0oOoOOO = struct . unpack ( III11i ,
 packet [ : Oo0o0OOo0Oo0 ] )
  if 53 - 53: OOooOOo % ooOoO0o
  if ( o0oOoOOO == LISP_LCAF_INSTANCE_ID_TYPE ) :
   return ( [ self . lcaf_decode_iid ( packet ) , None ] )
  elif ( o0oOoOOO == LISP_LCAF_MCAST_INFO_TYPE ) :
   packet , IiI1111i1i11I = self . lcaf_decode_sg ( packet )
   return ( [ packet , IiI1111i1i11I ] )
  elif ( o0oOoOOO == LISP_LCAF_GEO_COORD_TYPE ) :
   III11i = "BBBBH"
   Oo0o0OOo0Oo0 = struct . calcsize ( III11i )
   if ( len ( packet ) < Oo0o0OOo0Oo0 ) : return ( None )
   if 94 - 94: OOooOOo - O0 - I1Ii111 / OoooooooOO - iII111i
   iiII1II1 , iiIIii1Iii1I , o0oOoOOO , OO00 , i1IiI = struct . unpack ( III11i , packet [ : Oo0o0OOo0Oo0 ] )
   if 83 - 83: OOooOOo * I1ii11iIi11i * iII111i * I1ii11iIi11i . OoO0O00
   if 87 - 87: ooOoO0o . O0 - oO0o
   if ( o0oOoOOO != LISP_LCAF_GEO_COORD_TYPE ) : return ( None )
   if 75 - 75: Oo0Ooo
   i1IiI = socket . ntohs ( i1IiI )
   packet = packet [ Oo0o0OOo0Oo0 : : ]
   if ( i1IiI > len ( packet ) ) : return ( None )
   if 22 - 22: oO0o * I1Ii111 . II111iiii / Ii1I * O0
   OOOOo = lisp_geo ( "" )
   self . instance_id = 0
   self . afi = LISP_AFI_GEO_COORD
   self . address = OOOOo
   packet = OOOOo . decode_geo ( packet , i1IiI , OO00 )
   self . mask_len = self . host_mask_len ( )
   if 33 - 33: oO0o * i1IIi + ooOoO0o * OOooOOo - O0 - iIii1I11I1II1
  return ( [ packet , None ] )
  if 35 - 35: I1Ii111
  if 12 - 12: Ii1I % I1IiiI - I11i / iIii1I11I1II1 . I1IiiI % I1ii11iIi11i
  if 12 - 12: Oo0Ooo + I1IiiI
  if 12 - 12: OoOoOO00 / II111iiii
  if 100 - 100: I1ii11iIi11i % iIii1I11I1II1 . IiII . OoooooooOO / II111iiii
  if 28 - 28: I1IiiI
class lisp_elp_node ( ) :
 def __init__ ( self ) :
  self . address = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . probe = False
  self . strict = False
  self . eid = False
  self . we_are_last = False
  if 27 - 27: I1IiiI % oO0o - iIii1I11I1II1 - o0oOOo0O0Ooo - IiII - O0
  if 46 - 46: II111iiii
 def copy_elp_node ( self ) :
  IIiIiii111iI = lisp_elp_node ( )
  IIiIiii111iI . copy_address ( self . address )
  IIiIiii111iI . probe = self . probe
  IIiIiii111iI . strict = self . strict
  IIiIiii111iI . eid = self . eid
  IIiIiii111iI . we_are_last = self . we_are_last
  return ( IIiIiii111iI )
  if 24 - 24: i11iIiiIii * i1IIi - I11i + o0oOOo0O0Ooo
  if 60 - 60: ooOoO0o
  if 62 - 62: i11iIiiIii
class lisp_elp ( ) :
 def __init__ ( self , name ) :
  self . elp_name = name
  self . elp_nodes = [ ]
  self . use_elp_node = None
  self . we_are_last = False
  if 88 - 88: i11iIiiIii
  if 59 - 59: oO0o - OoooooooOO % ooOoO0o
 def copy_elp ( self ) :
  IIiI11i1i = lisp_elp ( self . elp_name )
  IIiI11i1i . use_elp_node = self . use_elp_node
  IIiI11i1i . we_are_last = self . we_are_last
  for IIiIiii111iI in self . elp_nodes :
   IIiI11i1i . elp_nodes . append ( IIiIiii111iI . copy_elp_node ( ) )
   if 90 - 90: OoOoOO00
  return ( IIiI11i1i )
  if 96 - 96: II111iiii % Ii1I
  if 84 - 84: I1IiiI . I1IiiI
 def print_elp ( self , want_marker ) :
  OooO0o00oO = ""
  for IIiIiii111iI in self . elp_nodes :
   OOooOoOOO = ""
   if ( want_marker ) :
    if ( IIiIiii111iI == self . use_elp_node ) :
     OOooOoOOO = "*"
    elif ( IIiIiii111iI . we_are_last ) :
     OOooOoOOO = "x"
     if 10 - 10: oO0o * i11iIiiIii % i1IIi + I1ii11iIi11i + Oo0Ooo
     if 36 - 36: O0 - iII111i + I11i + I1IiiI
   OooO0o00oO += "{}{}({}{}{}), " . format ( OOooOoOOO ,
 IIiIiii111iI . address . print_address_no_iid ( ) ,
 "r" if IIiIiii111iI . eid else "R" , "P" if IIiIiii111iI . probe else "p" ,
 "S" if IIiIiii111iI . strict else "s" )
   if 89 - 89: OoOoOO00 / Ii1I - OoO0O00 % I11i - oO0o . Ii1I
  return ( OooO0o00oO [ 0 : - 2 ] if OooO0o00oO != "" else "" )
  if 75 - 75: I11i * OoooooooOO % OoOoOO00 . i1IIi - Ii1I + iIii1I11I1II1
  if 74 - 74: ooOoO0o
 def select_elp_node ( self ) :
  iiI1Ii1I , ii1oO00o , iiiIiIIIiiiIiI1 = lisp_myrlocs
  Oo0oOooo000OO = None
  if 26 - 26: ooOoO0o . IiII - O0 / I1IiiI
  for IIiIiii111iI in self . elp_nodes :
   if ( iiI1Ii1I and IIiIiii111iI . address . is_exact_match ( iiI1Ii1I ) ) :
    Oo0oOooo000OO = self . elp_nodes . index ( IIiIiii111iI )
    break
    if 30 - 30: ooOoO0o / ooOoO0o - Oo0Ooo
   if ( ii1oO00o and IIiIiii111iI . address . is_exact_match ( ii1oO00o ) ) :
    Oo0oOooo000OO = self . elp_nodes . index ( IIiIiii111iI )
    break
    if 60 - 60: I1ii11iIi11i
    if 91 - 91: iII111i
    if 99 - 99: OOooOOo / i11iIiiIii - oO0o / I1IiiI
    if 58 - 58: Oo0Ooo % iII111i
    if 43 - 43: oO0o * iII111i
    if 96 - 96: ooOoO0o % OOooOOo % OoO0O00 + OoOoOO00 % I11i
    if 85 - 85: ooOoO0o / iII111i / OoOoOO00 % I1ii11iIi11i
  if ( Oo0oOooo000OO == None ) :
   self . use_elp_node = self . elp_nodes [ 0 ]
   IIiIiii111iI . we_are_last = False
   return
   if 1 - 1: I1ii11iIi11i + iIii1I11I1II1 . O0 + I1ii11iIi11i + I1IiiI + OOooOOo
   if 63 - 63: iIii1I11I1II1 . iIii1I11I1II1 . Ii1I . i1IIi + I1Ii111
   if 65 - 65: i11iIiiIii * oO0o + OoO0O00
   if 86 - 86: iII111i - Ii1I / OoO0O00
   if 19 - 19: iIii1I11I1II1 / iII111i + OOooOOo . ooOoO0o
   if 85 - 85: i1IIi
  if ( self . elp_nodes [ - 1 ] == self . elp_nodes [ Oo0oOooo000OO ] ) :
   self . use_elp_node = None
   IIiIiii111iI . we_are_last = True
   return
   if 78 - 78: oO0o
   if 6 - 6: IiII
   if 69 - 69: iII111i
   if 87 - 87: i11iIiiIii % o0oOOo0O0Ooo + Ii1I
   if 72 - 72: Ii1I / II111iiii + o0oOOo0O0Ooo
  self . use_elp_node = self . elp_nodes [ Oo0oOooo000OO + 1 ]
  return
  if 33 - 33: I1Ii111 * OoOoOO00 - OoooooooOO
  if 11 - 11: I1Ii111 - Oo0Ooo / iIii1I11I1II1 - OoooooooOO
  if 71 - 71: Oo0Ooo + Ii1I - OoooooooOO + I11i - iIii1I11I1II1 / O0
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
  if 76 - 76: i11iIiiIii % o0oOOo0O0Ooo . O0 * I11i
  if 90 - 90: II111iiii + OOooOOo % I1Ii111 * iIii1I11I1II1 % iIii1I11I1II1
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
  if 55 - 55: II111iiii % O0 * O0 - II111iiii * I1IiiI % Oo0Ooo
  if 48 - 48: I1ii11iIi11i + OoooooooOO % i1IIi
 def no_geo_altitude ( self ) :
  return ( self . altitude == - 1 )
  if 46 - 46: OoOoOO00
  if 75 - 75: I1IiiI
 def parse_geo_string ( self , geo_str ) :
  Oo0oOooo000OO = geo_str . find ( "]" )
  if ( Oo0oOooo000OO != - 1 ) : geo_str = geo_str [ Oo0oOooo000OO + 1 : : ]
  if 37 - 37: iIii1I11I1II1 % OoO0O00 * ooOoO0o + I11i % ooOoO0o / i11iIiiIii
  if 14 - 14: i1IIi / ooOoO0o
  if 10 - 10: ooOoO0o / OoooooooOO - ooOoO0o % O0 + oO0o - oO0o
  if 16 - 16: O0
  if 14 - 14: Ii1I . Ii1I . OOooOOo - O0 / OoO0O00 % II111iiii
  if ( geo_str . find ( "/" ) != - 1 ) :
   geo_str , Ii1I111iiI = geo_str . split ( "/" )
   self . radius = int ( Ii1I111iiI )
   if 12 - 12: Oo0Ooo % I1IiiI . i11iIiiIii - iII111i - o0oOOo0O0Ooo * OoO0O00
   if 35 - 35: o0oOOo0O0Ooo
  geo_str = geo_str . split ( "-" )
  if ( len ( geo_str ) < 8 ) : return ( False )
  if 60 - 60: OoooooooOO % OoOoOO00
  O00oOooOO0O = geo_str [ 0 : 4 ]
  OOO0ooOOoO = geo_str [ 4 : 8 ]
  if 26 - 26: IiII . Ii1I
  if 35 - 35: I1ii11iIi11i + OOooOOo
  if 88 - 88: O0
  if 4 - 4: OoOoOO00 % iIii1I11I1II1 % OoooooooOO . oO0o
  if ( len ( geo_str ) > 8 ) : self . altitude = int ( geo_str [ 8 ] )
  if 27 - 27: II111iiii - OoOoOO00
  if 81 - 81: o0oOOo0O0Ooo - Oo0Ooo % IiII - ooOoO0o / O0
  if 27 - 27: Oo0Ooo
  if 15 - 15: iIii1I11I1II1 . OoOoOO00 % Ii1I / i1IIi . o0oOOo0O0Ooo
  self . latitude = int ( O00oOooOO0O [ 0 ] )
  self . lat_mins = int ( O00oOooOO0O [ 1 ] )
  self . lat_secs = int ( O00oOooOO0O [ 2 ] )
  if ( O00oOooOO0O [ 3 ] == "N" ) : self . latitude = - self . latitude
  if 45 - 45: iIii1I11I1II1 - i1IIi % I1IiiI - I1Ii111 + oO0o
  if 15 - 15: iIii1I11I1II1 - OoooooooOO / ooOoO0o
  if 83 - 83: IiII + I1Ii111 / OoOoOO00 * IiII . oO0o
  if 22 - 22: O0 + ooOoO0o + I1Ii111
  self . longitude = int ( OOO0ooOOoO [ 0 ] )
  self . long_mins = int ( OOO0ooOOoO [ 1 ] )
  self . long_secs = int ( OOO0ooOOoO [ 2 ] )
  if ( OOO0ooOOoO [ 3 ] == "E" ) : self . longitude = - self . longitude
  return ( True )
  if 57 - 57: OOooOOo . ooOoO0o - OoooooooOO - I1ii11iIi11i * O0
  if 85 - 85: I1IiiI * OoO0O00
 def print_geo ( self ) :
  ooooOO0oo = "N" if self . latitude < 0 else "S"
  oOoO00000oo = "E" if self . longitude < 0 else "W"
  if 51 - 51: I1Ii111
  O000 = "{}-{}-{}-{}-{}-{}-{}-{}" . format ( abs ( self . latitude ) ,
 self . lat_mins , self . lat_secs , ooooOO0oo , abs ( self . longitude ) ,
 self . long_mins , self . long_secs , oOoO00000oo )
  if 27 - 27: ooOoO0o * iII111i . II111iiii
  if ( self . no_geo_altitude ( ) == False ) :
   O000 += "-" + str ( self . altitude )
   if 61 - 61: O0 - I11i / i1IIi
   if 27 - 27: i11iIiiIii + iIii1I11I1II1
   if 15 - 15: oO0o
   if 69 - 69: II111iiii * O0 . ooOoO0o * IiII
   if 25 - 25: I11i - I1ii11iIi11i . I1Ii111 . OoooooooOO
  if ( self . radius != 0 ) : O000 += "/{}" . format ( self . radius )
  return ( O000 )
  if 4 - 4: IiII * OoO0O00 % I1ii11iIi11i * Ii1I . iII111i
  if 41 - 41: OoooooooOO % I11i . O0 + I1Ii111
 def geo_url ( self ) :
  OOo0oOoOOO0oo = os . getenv ( "LISP_GEO_ZOOM_LEVEL" )
  OOo0oOoOOO0oo = "10" if ( OOo0oOoOOO0oo == "" or OOo0oOoOOO0oo . isdigit ( ) == False ) else OOo0oOoOOO0oo
  iIioOooO , iiiIiIi11i1Iiii11 = self . dms_to_decimal ( )
  OOo0oo0O0o0 = ( "http://maps.googleapis.com/maps/api/staticmap?center={},{}" + "&markers=color:blue%7Clabel:lisp%7C{},{}" + "&zoom={}&size=1024x1024&sensor=false" ) . format ( iIioOooO , iiiIiIi11i1Iiii11 , iIioOooO , iiiIiIi11i1Iiii11 ,
  # O0 % ooOoO0o . Ii1I - ooOoO0o - I1ii11iIi11i
  # oO0o % I11i - Oo0Ooo + i11iIiiIii - i11iIiiIii
 OOo0oOoOOO0oo )
  return ( OOo0oo0O0o0 )
  if 64 - 64: IiII % I1IiiI / ooOoO0o
  if 74 - 74: OoooooooOO
 def print_geo_url ( self ) :
  OOOOo = self . print_geo ( )
  if ( self . radius == 0 ) :
   OOo0oo0O0o0 = self . geo_url ( )
   o0oOo = "<a href='{}'>{}</a>" . format ( OOo0oo0O0o0 , OOOOo )
  else :
   OOo0oo0O0o0 = OOOOo . replace ( "/" , "-" )
   o0oOo = "<a href='/lisp/geo-map/{}'>{}</a>" . format ( OOo0oo0O0o0 , OOOOo )
   if 22 - 22: II111iiii . O0 * I1Ii111 % OoO0O00 / OoooooooOO + I1Ii111
  return ( o0oOo )
  if 71 - 71: ooOoO0o . oO0o * OoooooooOO + iII111i - I1Ii111 . I1ii11iIi11i
  if 100 - 100: I11i + O0 - o0oOOo0O0Ooo * I1ii11iIi11i
 def dms_to_decimal ( self ) :
  OOI1IIi , ooOO000o0O , o0oOOOOO0 = self . latitude , self . lat_mins , self . lat_secs
  iiiI1I = float ( abs ( OOI1IIi ) )
  iiiI1I += float ( ooOO000o0O * 60 + o0oOOOOO0 ) / 3600
  if ( OOI1IIi > 0 ) : iiiI1I = - iiiI1I
  IiiO0oO0O0OoO0 = iiiI1I
  if 28 - 28: ooOoO0o + iII111i - i1IIi
  OOI1IIi , ooOO000o0O , o0oOOOOO0 = self . longitude , self . long_mins , self . long_secs
  iiiI1I = float ( abs ( OOI1IIi ) )
  iiiI1I += float ( ooOO000o0O * 60 + o0oOOOOO0 ) / 3600
  if ( OOI1IIi > 0 ) : iiiI1I = - iiiI1I
  ii1i = iiiI1I
  return ( ( IiiO0oO0O0OoO0 , ii1i ) )
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
  Oo0ooO0 = socket . htons ( 20 + 2 )
  iiIIii1Iii1I = 0
  if 74 - 74: I1Ii111 - i11iIiiIii * OoooooooOO
  iIioOooO = abs ( self . latitude )
  oO0OOOo0oOOoO00o0 = ( ( self . lat_mins * 60 ) + self . lat_secs ) * 1000
  if ( self . latitude < 0 ) : iiIIii1Iii1I |= 0x40
  if 11 - 11: iII111i * O0 + I1IiiI / IiII + OoooooooOO - IiII
  iiiIiIi11i1Iiii11 = abs ( self . longitude )
  IIoo0o0oOoO0 = ( ( self . long_mins * 60 ) + self . long_secs ) * 1000
  if ( self . longitude < 0 ) : iiIIii1Iii1I |= 0x20
  if 56 - 56: oO0o + oO0o / ooOoO0o . iIii1I11I1II1
  oo000000o = 0
  if ( self . no_geo_altitude ( ) == False ) :
   oo000000o = socket . htonl ( self . altitude )
   iiIIii1Iii1I |= 0x10
   if 17 - 17: I1IiiI
  Ii1I111iiI = socket . htons ( self . radius )
  if ( Ii1I111iiI != 0 ) : iiIIii1Iii1I |= 0x06
  if 14 - 14: Ii1I
  iIIi = struct . pack ( "HBBBBH" , oO0OOOo0OO , 0 , 0 , LISP_LCAF_GEO_COORD_TYPE ,
 0 , Oo0ooO0 )
  iIIi += struct . pack ( "BBHBBHBBHIHHH" , iiIIii1Iii1I , 0 , 0 , iIioOooO , oO0OOOo0oOOoO00o0 >> 16 ,
 socket . htons ( oO0OOOo0oOOoO00o0 & 0x0ffff ) , iiiIiIi11i1Iiii11 , IIoo0o0oOoO0 >> 16 ,
 socket . htons ( IIoo0o0oOoO0 & 0xffff ) , oo000000o , Ii1I111iiI , 0 , 0 )
  if 76 - 76: o0oOOo0O0Ooo - ooOoO0o % OOooOOo . OoooooooOO
  return ( iIIi )
  if 18 - 18: Ii1I / iIii1I11I1II1 * OoO0O00 - I11i . OoO0O00 % iIii1I11I1II1
  if 92 - 92: oO0o
 def decode_geo ( self , packet , lcaf_len , radius_hi ) :
  III11i = "BBHBBHBBHIHHH"
  Oo0o0OOo0Oo0 = struct . calcsize ( III11i )
  if ( lcaf_len < Oo0o0OOo0Oo0 ) : return ( None )
  if 45 - 45: I1Ii111 / O0 * OOooOOo / II111iiii % iIii1I11I1II1
  iiIIii1Iii1I , I111I111iiI1 , iI1II1I , iIioOooO , i111IiIIi1 , oO0OOOo0oOOoO00o0 , iiiIiIi11i1Iiii11 , II11II1111 , IIoo0o0oOoO0 , oo000000o , Ii1I111iiI , IiiiOo , ii1iI1i1 = struct . unpack ( III11i ,
  # I1ii11iIi11i * Ii1I * OoO0O00 . OOooOOo % OoOoOO00
 packet [ : Oo0o0OOo0Oo0 ] )
  if 77 - 77: I1Ii111 / iIii1I11I1II1 * I1Ii111 % oO0o + o0oOOo0O0Ooo . IiII
  if 80 - 80: OOooOOo . I1IiiI % iIii1I11I1II1
  if 45 - 45: OoooooooOO * O0
  if 86 - 86: O0 * oO0o + Oo0Ooo / II111iiii + i1IIi
  ii1iI1i1 = socket . ntohs ( ii1iI1i1 )
  if ( ii1iI1i1 == LISP_AFI_LCAF ) : return ( None )
  if 12 - 12: I1IiiI + OOooOOo / Ii1I % i11iIiiIii - I1Ii111 % I11i
  if ( iiIIii1Iii1I & 0x40 ) : iIioOooO = - iIioOooO
  self . latitude = iIioOooO
  i1Ii111Ii111 = ( ( i111IiIIi1 << 16 ) | socket . ntohs ( oO0OOOo0oOOoO00o0 ) ) / 1000
  self . lat_mins = i1Ii111Ii111 / 60
  self . lat_secs = i1Ii111Ii111 % 60
  if 1 - 1: IiII / OoOoOO00
  if ( iiIIii1Iii1I & 0x20 ) : iiiIiIi11i1Iiii11 = - iiiIiIi11i1Iiii11
  self . longitude = iiiIiIi11i1Iiii11
  O0o0Oo0o00 = ( ( II11II1111 << 16 ) | socket . ntohs ( IIoo0o0oOoO0 ) ) / 1000
  self . long_mins = O0o0Oo0o00 / 60
  self . long_secs = O0o0Oo0o00 % 60
  if 20 - 20: iII111i / I11i / iIii1I11I1II1
  self . altitude = socket . ntohl ( oo000000o ) if ( iiIIii1Iii1I & 0x10 ) else - 1
  Ii1I111iiI = socket . ntohs ( Ii1I111iiI )
  self . radius = Ii1I111iiI if ( iiIIii1Iii1I & 0x02 ) else Ii1I111iiI * 1000
  if 94 - 94: i11iIiiIii % I1ii11iIi11i % IiII - I1Ii111
  self . geo_name = None
  packet = packet [ Oo0o0OOo0Oo0 : : ]
  if 55 - 55: I11i - ooOoO0o - iIii1I11I1II1 + I1ii11iIi11i / IiII
  if ( ii1iI1i1 != 0 ) :
   self . rloc . afi = ii1iI1i1
   packet = self . rloc . unpack_address ( packet )
   self . rloc . mask_len = self . rloc . host_mask_len ( )
   if 49 - 49: I1ii11iIi11i
  return ( packet )
  if 91 - 91: OOooOOo % iII111i
  if 40 - 40: i11iIiiIii . II111iiii / OoOoOO00 + OoooooooOO + i1IIi . O0
  if 39 - 39: I1ii11iIi11i
  if 26 - 26: oO0o . I1Ii111 % I11i
  if 85 - 85: II111iiii / o0oOOo0O0Ooo . iIii1I11I1II1 . OoooooooOO / Ii1I
  if 18 - 18: i11iIiiIii + o0oOOo0O0Ooo . i11iIiiIii
class lisp_rle_node ( ) :
 def __init__ ( self ) :
  self . address = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . level = 0
  self . translated_port = 0
  self . rloc_name = None
  if 50 - 50: IiII / OoooooooOO . I11i
  if 93 - 93: OOooOOo / OoooooooOO % iII111i % Ii1I / I1Ii111 % OOooOOo
 def copy_rle_node ( self ) :
  O00o000O0O0oO = lisp_rle_node ( )
  O00o000O0O0oO . address . copy_address ( self . address )
  O00o000O0O0oO . level = self . level
  O00o000O0O0oO . translated_port = self . translated_port
  O00o000O0O0oO . rloc_name = self . rloc_name
  return ( O00o000O0O0oO )
  if 25 - 25: i1IIi % Oo0Ooo . i1IIi * OoOoOO00 . Ii1I % OoO0O00
  if 47 - 47: o0oOOo0O0Ooo - i11iIiiIii / OoooooooOO
 def store_translated_rloc ( self , rloc , port ) :
  self . address . copy_address ( rloc )
  self . translated_port = port
  if 93 - 93: I1IiiI * II111iiii * O0 % o0oOOo0O0Ooo + oO0o / ooOoO0o
  if 79 - 79: OoO0O00 + ooOoO0o / oO0o % I1ii11iIi11i
 def get_encap_keys ( self ) :
  IIIIiI1ii1 = "4341" if self . translated_port == 0 else str ( self . translated_port )
  if 77 - 77: Ii1I / Ii1I / I1ii11iIi11i
  i111I11I = self . address . print_address_no_iid ( ) + ":" + IIIIiI1ii1
  if 92 - 92: O0 * i11iIiiIii . OoOoOO00 * IiII / o0oOOo0O0Ooo * ooOoO0o
  try :
   i11i1ii11Ii1 = lisp_crypto_keys_by_rloc_encap [ i111I11I ]
   if ( i11i1ii11Ii1 [ 1 ] ) : return ( i11i1ii11Ii1 [ 1 ] . encrypt_key , i11i1ii11Ii1 [ 1 ] . icv_key )
   return ( None , None )
  except :
   return ( None , None )
   if 74 - 74: O0 - o0oOOo0O0Ooo
   if 68 - 68: I1Ii111
   if 19 - 19: o0oOOo0O0Ooo
   if 63 - 63: OoooooooOO % ooOoO0o
class lisp_rle ( ) :
 def __init__ ( self , name ) :
  self . rle_name = name
  self . rle_nodes = [ ]
  self . rle_forwarding_list = [ ]
  if 26 - 26: OOooOOo + Oo0Ooo
  if 97 - 97: I1Ii111 * I1Ii111 + iII111i % Ii1I / iII111i
 def copy_rle ( self ) :
  o0o0ooOo00 = lisp_rle ( self . rle_name )
  for O00o000O0O0oO in self . rle_nodes :
   o0o0ooOo00 . rle_nodes . append ( O00o000O0O0oO . copy_rle_node ( ) )
   if 73 - 73: OoOoOO00 % I1Ii111 . I1ii11iIi11i
  o0o0ooOo00 . build_forwarding_list ( )
  return ( o0o0ooOo00 )
  if 45 - 45: iIii1I11I1II1 % Ii1I . OoOoOO00 . o0oOOo0O0Ooo - OoooooooOO
  if 46 - 46: I1ii11iIi11i
 def print_rle ( self , html ) :
  OoI1i1IIii = ""
  for O00o000O0O0oO in self . rle_nodes :
   IIIIiI1ii1 = O00o000O0O0oO . translated_port
   I1iiI1IiiIi1 = blue ( O00o000O0O0oO . rloc_name , html ) if O00o000O0O0oO . rloc_name != None else ""
   if 95 - 95: Ii1I / Ii1I * OoO0O00 . OoooooooOO . OoooooooOO * I11i
   i111I11I = O00o000O0O0oO . address . print_address_no_iid ( )
   if ( O00o000O0O0oO . address . is_local ( ) ) : i111I11I = red ( i111I11I , html )
   OoI1i1IIii += "{}{}(L{}){}, " . format ( i111I11I , "" if IIIIiI1ii1 == 0 else ":" + str ( IIIIiI1ii1 ) , O00o000O0O0oO . level ,
   # oO0o % OoO0O00 / Ii1I % II111iiii * OoOoOO00
 "" if O00o000O0O0oO . rloc_name == None else I1iiI1IiiIi1 )
   if 19 - 19: o0oOOo0O0Ooo * IiII . Oo0Ooo * OOooOOo
  return ( OoI1i1IIii [ 0 : - 2 ] if OoI1i1IIii != "" else "" )
  if 6 - 6: I1ii11iIi11i / O0
  if 16 - 16: II111iiii . Oo0Ooo * I1Ii111 + o0oOOo0O0Ooo - i11iIiiIii
 def build_forwarding_list ( self ) :
  I1i1Ii = - 1
  for O00o000O0O0oO in self . rle_nodes :
   if ( I1i1Ii == - 1 ) :
    if ( O00o000O0O0oO . address . is_local ( ) ) : I1i1Ii = O00o000O0O0oO . level
   else :
    if ( O00o000O0O0oO . level > I1i1Ii ) : break
    if 98 - 98: II111iiii - i1IIi - ooOoO0o
    if 36 - 36: IiII + o0oOOo0O0Ooo
  I1i1Ii = 0 if I1i1Ii == - 1 else O00o000O0O0oO . level
  if 81 - 81: OOooOOo / I11i % oO0o + ooOoO0o
  self . rle_forwarding_list = [ ]
  for O00o000O0O0oO in self . rle_nodes :
   if ( O00o000O0O0oO . level == I1i1Ii or ( I1i1Ii == 0 and
 O00o000O0O0oO . level == 128 ) ) :
    if ( lisp_i_am_rtr == False and O00o000O0O0oO . address . is_local ( ) ) :
     i111I11I = O00o000O0O0oO . address . print_address_no_iid ( )
     lprint ( "Exclude local RLE RLOC {}" . format ( i111I11I ) )
     continue
     if 10 - 10: oO0o / i11iIiiIii
    self . rle_forwarding_list . append ( O00o000O0O0oO )
    if 73 - 73: OoO0O00 - i1IIi
    if 52 - 52: I1ii11iIi11i
    if 4 - 4: Ii1I - iII111i + i1IIi - I1Ii111 / iII111i . Oo0Ooo
    if 18 - 18: oO0o % iIii1I11I1II1 + ooOoO0o
    if 34 - 34: I1IiiI - OoooooooOO . IiII - OOooOOo % IiII
class lisp_json ( ) :
 def __init__ ( self , name , string ) :
  self . json_name = name
  self . json_string = string
  if 19 - 19: IiII + I1ii11iIi11i % Oo0Ooo
  if 32 - 32: OOooOOo
 def add ( self ) :
  self . delete ( )
  lisp_json_list [ self . json_name ] = self
  if 46 - 46: II111iiii . OoO0O00
  if 97 - 97: oO0o
 def delete ( self ) :
  if ( lisp_json_list . has_key ( self . json_name ) ) :
   del ( lisp_json_list [ self . json_name ] )
   lisp_json_list [ self . json_name ] = None
   if 45 - 45: i11iIiiIii / IiII + OoO0O00
   if 55 - 55: Ii1I / II111iiii - oO0o
   if 58 - 58: i1IIi . OoooooooOO % iIii1I11I1II1 * o0oOOo0O0Ooo + O0 / oO0o
 def print_json ( self , html ) :
  o0OOo00oo0o = self . json_string
  ooOOoo0o = "***"
  if ( html ) : ooOOoo0o = red ( ooOOoo0o , html )
  iiI1I1iIi1IIIiIiI = ooOOoo0o + self . json_string + ooOOoo0o
  if ( self . valid_json ( ) ) : return ( o0OOo00oo0o )
  return ( iiI1I1iIi1IIIiIiI )
  if 40 - 40: i11iIiiIii
  if 95 - 95: OOooOOo / Oo0Ooo . OoO0O00 / IiII + i11iIiiIii * OOooOOo
 def valid_json ( self ) :
  try :
   json . loads ( self . json_string )
  except :
   return ( False )
   if 27 - 27: O0 * OoO0O00 * I1ii11iIi11i
  return ( True )
  if 40 - 40: O0 + oO0o - ooOoO0o + I1IiiI - IiII
  if 60 - 60: I1Ii111 * OoO0O00 * oO0o + oO0o
  if 34 - 34: o0oOOo0O0Ooo
  if 76 - 76: oO0o + OoooooooOO % OoOoOO00 / OoOoOO00
  if 51 - 51: II111iiii / OoOoOO00
  if 69 - 69: i11iIiiIii
class lisp_stats ( ) :
 def __init__ ( self ) :
  self . packet_count = 0
  self . byte_count = 0
  self . last_rate_check = 0
  self . last_packet_count = 0
  self . last_byte_count = 0
  self . last_increment = None
  if 77 - 77: I1ii11iIi11i % OoooooooOO - Oo0Ooo - Ii1I + I11i
  if 93 - 93: I1IiiI % O0 * OoO0O00 % OoOoOO00 . I1Ii111 * I1IiiI
 def increment ( self , octets ) :
  self . packet_count += 1
  self . byte_count += octets
  self . last_increment = lisp_get_timestamp ( )
  if 95 - 95: IiII + o0oOOo0O0Ooo - o0oOOo0O0Ooo
  if 83 - 83: ooOoO0o
 def recent_packet_sec ( self ) :
  if ( self . last_increment == None ) : return ( False )
  I1IiIii11I = time . time ( ) - self . last_increment
  return ( I1IiIii11I <= 1 )
  if 59 - 59: I1ii11iIi11i
  if 26 - 26: I11i . Ii1I
 def recent_packet_min ( self ) :
  if ( self . last_increment == None ) : return ( False )
  I1IiIii11I = time . time ( ) - self . last_increment
  return ( I1IiIii11I <= 60 )
  if 94 - 94: ooOoO0o . I1IiiI + IiII % I1IiiI / o0oOOo0O0Ooo % o0oOOo0O0Ooo
  if 21 - 21: O0 / OOooOOo - II111iiii + I1ii11iIi11i / OoooooooOO
 def stat_colors ( self , c1 , c2 , html ) :
  if ( self . recent_packet_sec ( ) ) :
   return ( green_last_sec ( c1 ) , green_last_sec ( c2 ) )
   if 81 - 81: i11iIiiIii / Oo0Ooo * i1IIi + OoO0O00 + O0 % I1ii11iIi11i
  if ( self . recent_packet_min ( ) ) :
   return ( green_last_min ( c1 ) , green_last_min ( c2 ) )
   if 3 - 3: i11iIiiIii * IiII . Oo0Ooo % OoOoOO00 * I11i . iII111i
  return ( c1 , c2 )
  if 80 - 80: I11i - IiII
  if 40 - 40: OOooOOo * I1IiiI % I11i . I1Ii111 % O0 . O0
 def normalize ( self , count ) :
  count = str ( count )
  I1I = len ( count )
  if ( I1I > 12 ) :
   count = count [ 0 : - 10 ] + "." + count [ - 10 : - 7 ] + "T"
   return ( count )
   if 46 - 46: OoooooooOO * ooOoO0o + Oo0Ooo + iIii1I11I1II1 + iIii1I11I1II1 / Ii1I
  if ( I1I > 9 ) :
   count = count [ 0 : - 9 ] + "." + count [ - 9 : - 7 ] + "B"
   return ( count )
   if 19 - 19: OOooOOo . OoOoOO00 % iIii1I11I1II1 % OoOoOO00
  if ( I1I > 6 ) :
   count = count [ 0 : - 6 ] + "." + count [ - 6 ] + "M"
   return ( count )
   if 92 - 92: o0oOOo0O0Ooo + II111iiii
  return ( count )
  if 56 - 56: OoOoOO00 - OoOoOO00 / Ii1I
  if 92 - 92: iIii1I11I1II1
 def get_stats ( self , summary , html ) :
  i1iIi = self . last_rate_check
  o00oOoOO0 = self . last_packet_count
  Oo0OO0oO = self . last_byte_count
  self . last_rate_check = lisp_get_timestamp ( )
  self . last_packet_count = self . packet_count
  self . last_byte_count = self . byte_count
  if 45 - 45: o0oOOo0O0Ooo . I1Ii111 % Ii1I
  IIIiiI = self . last_rate_check - i1iIi
  if ( IIIiiI == 0 ) :
   O0Oo0o0 = 0
   ii1Iii1Iii = 0
  else :
   O0Oo0o0 = int ( ( self . packet_count - o00oOoOO0 ) / IIIiiI )
   ii1Iii1Iii = ( self . byte_count - Oo0OO0oO ) / IIIiiI
   ii1Iii1Iii = ( ii1Iii1Iii * 8 ) / 1000000
   ii1Iii1Iii = round ( ii1Iii1Iii , 2 )
   if 78 - 78: iIii1I11I1II1
   if 64 - 64: OoOoOO00 - oO0o
   if 8 - 8: i11iIiiIii - iIii1I11I1II1 / I1Ii111 . i11iIiiIii % o0oOOo0O0Ooo / oO0o
   if 36 - 36: IiII
   if 53 - 53: OoooooooOO / I1IiiI % I11i + Oo0Ooo
  i1iIi1Ii1I11I = self . normalize ( self . packet_count )
  o0oOO0OO0000O = self . normalize ( self . byte_count )
  if 58 - 58: O0 * oO0o * OoOoOO00 . I1IiiI . i11iIiiIii / I1Ii111
  if 40 - 40: OoooooooOO / o0oOOo0O0Ooo + OoOoOO00
  if 73 - 73: OOooOOo / Oo0Ooo
  if 80 - 80: OoO0O00 + I1IiiI % i1IIi / I11i % i1IIi * i11iIiiIii
  if 27 - 27: OoOoOO00 / I1Ii111 * O0 / I1IiiI - IiII / o0oOOo0O0Ooo
  if ( summary ) :
   ooo00o0oo = "<br>" if html else ""
   i1iIi1Ii1I11I , o0oOO0OO0000O = self . stat_colors ( i1iIi1Ii1I11I , o0oOO0OO0000O , html )
   OOoO00o = "packet-count: {}{}byte-count: {}" . format ( i1iIi1Ii1I11I , ooo00o0oo , o0oOO0OO0000O )
   I1iiIIiIII1i = "packet-rate: {} pps\nbit-rate: {} Mbps" . format ( O0Oo0o0 , ii1Iii1Iii )
   if 53 - 53: o0oOOo0O0Ooo * Oo0Ooo % I1IiiI
   if ( html != "" ) : I1iiIIiIII1i = lisp_span ( OOoO00o , I1iiIIiIII1i )
  else :
   o0OOOO = str ( O0Oo0o0 )
   I1III = str ( ii1Iii1Iii )
   if ( html ) :
    i1iIi1Ii1I11I = lisp_print_cour ( i1iIi1Ii1I11I )
    o0OOOO = lisp_print_cour ( o0OOOO )
    o0oOO0OO0000O = lisp_print_cour ( o0oOO0OO0000O )
    I1III = lisp_print_cour ( I1III )
    if 9 - 9: iIii1I11I1II1 % OoO0O00
   ooo00o0oo = "<br>" if html else ", "
   if 45 - 45: OoooooooOO . O0 * oO0o + IiII
   I1iiIIiIII1i = ( "packet-count: {}{}packet-rate: {} pps{}byte-count: " + "{}{}bit-rate: {} mbps" ) . format ( i1iIi1Ii1I11I , ooo00o0oo , o0OOOO , ooo00o0oo , o0oOO0OO0000O , ooo00o0oo ,
   # iIii1I11I1II1 - II111iiii
 I1III )
   if 55 - 55: II111iiii
  return ( I1iiIIiIII1i )
  if 75 - 75: OOooOOo % OoOoOO00 + iIii1I11I1II1 - II111iiii / i1IIi
  if 39 - 39: Ii1I + I1Ii111 * Oo0Ooo + OoOoOO00 / I1Ii111 - ooOoO0o
  if 66 - 66: I11i * OoO0O00
  if 98 - 98: IiII . Oo0Ooo + I1Ii111
  if 63 - 63: oO0o * I1IiiI * oO0o
  if 56 - 56: oO0o - Ii1I % I1Ii111
  if 100 - 100: OOooOOo * IiII % IiII / o0oOOo0O0Ooo * OoO0O00 % OoOoOO00
  if 12 - 12: I1IiiI
lisp_decap_stats = {
 "good-packets" : lisp_stats ( ) , "ICV-error" : lisp_stats ( ) ,
 "checksum-error" : lisp_stats ( ) , "lisp-header-error" : lisp_stats ( ) ,
 "no-decrypt-key" : lisp_stats ( ) , "bad-inner-version" : lisp_stats ( ) ,
 "outer-header-error" : lisp_stats ( )
 }
if 32 - 32: I1Ii111
if 35 - 35: O0 + II111iiii + o0oOOo0O0Ooo - OoO0O00 - Ii1I
if 88 - 88: I1ii11iIi11i . O0 - o0oOOo0O0Ooo . I1ii11iIi11i * iII111i * I11i
if 89 - 89: Oo0Ooo - oO0o + O0 / i11iIiiIii
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
  if 64 - 64: OoO0O00 % OoOoOO00 % I1IiiI - Ii1I / IiII * Ii1I
  if ( recurse == False ) : return
  if 74 - 74: IiII - O0 % OOooOOo % OoooooooOO - I11i
  if 4 - 4: i1IIi + OoOoOO00 + iIii1I11I1II1 - i1IIi * i11iIiiIii
  if 99 - 99: I1ii11iIi11i - O0 % II111iiii + ooOoO0o % OoO0O00 * Ii1I
  if 8 - 8: OOooOOo
  if 85 - 85: O0 % OOooOOo . Ii1I
  if 74 - 74: I1ii11iIi11i - I1Ii111 + i11iIiiIii / I1Ii111 / OoooooooOO + o0oOOo0O0Ooo
  i1i1Ii = lisp_get_default_route_next_hops ( )
  if ( i1i1Ii == [ ] or len ( i1i1Ii ) == 1 ) : return
  if 83 - 83: iII111i - I1Ii111
  self . rloc_next_hop = i1i1Ii [ 0 ]
  oOo = self
  for iI1II1IiIiIi in i1i1Ii [ 1 : : ] :
   I11iI1111IIi = lisp_rloc ( False )
   I11iI1111IIi = copy . deepcopy ( self )
   I11iI1111IIi . rloc_next_hop = iI1II1IiIiIi
   oOo . next_rloc = I11iI1111IIi
   oOo = I11iI1111IIi
   if 89 - 89: I1IiiI - OoooooooOO / I11i . ooOoO0o
   if 69 - 69: I1ii11iIi11i
   if 6 - 6: iIii1I11I1II1 * I1ii11iIi11i / I11i % I1Ii111 / Oo0Ooo
 def up_state ( self ) :
  return ( self . state == LISP_RLOC_UP_STATE )
  if 94 - 94: OoO0O00 - oO0o + iII111i . ooOoO0o * OoooooooOO
  if 42 - 42: iII111i / i11iIiiIii + II111iiii % IiII / ooOoO0o
 def unreach_state ( self ) :
  return ( self . state == LISP_RLOC_UNREACH_STATE )
  if 100 - 100: ooOoO0o / I1IiiI
  if 69 - 69: ooOoO0o + OoO0O00 * o0oOOo0O0Ooo - ooOoO0o
 def no_echoed_nonce_state ( self ) :
  return ( self . state == LISP_RLOC_NO_ECHOED_NONCE_STATE )
  if 66 - 66: OoooooooOO / iII111i / I1IiiI % ooOoO0o / OoO0O00 + OOooOOo
  if 64 - 64: i1IIi
 def down_state ( self ) :
  return ( self . state in [ LISP_RLOC_DOWN_STATE , LISP_RLOC_ADMIN_DOWN_STATE ] )
  if 26 - 26: OoOoOO00 / o0oOOo0O0Ooo . OOooOOo + I1IiiI + Ii1I . iII111i
  if 89 - 89: I1Ii111 * I1IiiI . i1IIi - iIii1I11I1II1 * I1Ii111
  if 5 - 5: OoOoOO00 % i1IIi
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
  if 31 - 31: Oo0Ooo * O0 . OOooOOo . o0oOOo0O0Ooo + OoO0O00 + II111iiii
  if 76 - 76: Oo0Ooo + I1IiiI - O0
 def print_rloc ( self , indent ) :
  iiiI = lisp_print_elapsed ( self . uptime )
  lprint ( "{}rloc {}, uptime {}, {}, parms {}/{}/{}/{}" . format ( indent ,
 red ( self . rloc . print_address ( ) , False ) , iiiI , self . print_state ( ) ,
 self . priority , self . weight , self . mpriority , self . mweight ) )
  if 58 - 58: IiII * i1IIi . I1IiiI - iII111i
  if 73 - 73: Oo0Ooo . OoOoOO00
 def print_rloc_name ( self , cour = False ) :
  if ( self . rloc_name == None ) : return ( "" )
  ooOO0OOO = self . rloc_name
  if ( cour ) : ooOO0OOO = lisp_print_cour ( ooOO0OOO )
  return ( 'rloc-name: {}' . format ( blue ( ooOO0OOO , cour ) ) )
  if 50 - 50: IiII / o0oOOo0O0Ooo
  if 9 - 9: Oo0Ooo - OoO0O00 + iII111i / OoooooooOO
 def store_rloc_from_record ( self , rloc_record , nonce , source ) :
  IIIIiI1ii1 = LISP_DATA_PORT
  self . rloc . copy_address ( rloc_record . rloc )
  self . rloc_name = rloc_record . rloc_name
  if 52 - 52: O0
  if 34 - 34: OoooooooOO + OoOoOO00 - Oo0Ooo . OOooOOo * iIii1I11I1II1
  if 93 - 93: i11iIiiIii / Oo0Ooo * OoOoOO00 / ooOoO0o + OoO0O00 * OOooOOo
  if 81 - 81: IiII * iII111i + i1IIi + I1Ii111 / OoO0O00
  II11IIiii = self . rloc
  if ( II11IIiii . is_null ( ) == False ) :
   oOOoO = lisp_get_nat_info ( II11IIiii , self . rloc_name )
   if ( oOOoO ) :
    IIIIiI1ii1 = oOOoO . port
    ooo0oOOOO0O0o = lisp_nat_state_info [ self . rloc_name ] [ 0 ]
    i111I11I = II11IIiii . print_address_no_iid ( )
    I111I1iii11 = red ( i111I11I , False )
    Ii1iiIII11 = "" if self . rloc_name == None else blue ( self . rloc_name , False )
    if 51 - 51: OOooOOo
    if 85 - 85: II111iiii
    if 60 - 60: Ii1I * OOooOOo - o0oOOo0O0Ooo - Ii1I / Oo0Ooo . OOooOOo
    if 43 - 43: II111iiii * o0oOOo0O0Ooo % o0oOOo0O0Ooo + iIii1I11I1II1 + OoOoOO00
    if 54 - 54: II111iiii + OOooOOo * Oo0Ooo * I1Ii111 - o0oOOo0O0Ooo % Ii1I
    if 69 - 69: I11i + OoOoOO00 - i11iIiiIii * O0 % O0
    if ( oOOoO . timed_out ( ) ) :
     lprint ( ( "    Matched stored NAT state timed out for " + "RLOC {}:{}, {}" ) . format ( I111I1iii11 , IIIIiI1ii1 , Ii1iiIII11 ) )
     if 81 - 81: I11i - o0oOOo0O0Ooo % Ii1I / I1Ii111 * II111iiii
     if 40 - 40: OoO0O00 . i11iIiiIii
     oOOoO = None if ( oOOoO == ooo0oOOOO0O0o ) else ooo0oOOOO0O0o
     if ( oOOoO and oOOoO . timed_out ( ) ) :
      IIIIiI1ii1 = oOOoO . port
      I111I1iii11 = red ( oOOoO . address , False )
      lprint ( ( "    Youngest stored NAT state timed out " + " for RLOC {}:{}, {}" ) . format ( I111I1iii11 , IIIIiI1ii1 ,
      # iII111i * I1IiiI - iII111i
 Ii1iiIII11 ) )
      oOOoO = None
      if 81 - 81: i1IIi % I1ii11iIi11i + i1IIi . OoOoOO00
      if 28 - 28: ooOoO0o - I1IiiI . I1Ii111 * i11iIiiIii / IiII % ooOoO0o
      if 55 - 55: I1ii11iIi11i % ooOoO0o % OoOoOO00
      if 18 - 18: OOooOOo / O0 . OoO0O00 - II111iiii * OOooOOo
      if 13 - 13: OoO0O00 % i1IIi . i11iIiiIii / iII111i
      if 28 - 28: i1IIi - iII111i + o0oOOo0O0Ooo / Oo0Ooo * oO0o
      if 8 - 8: ooOoO0o + OOooOOo * ooOoO0o / i1IIi . I1ii11iIi11i
    if ( oOOoO ) :
     if ( oOOoO . address != i111I11I ) :
      lprint ( "RLOC conflict, RLOC-record {}, NAT state {}" . format ( I111I1iii11 , red ( oOOoO . address , False ) ) )
      if 4 - 4: Ii1I - Oo0Ooo . i1IIi + iIii1I11I1II1
      self . rloc . store_address ( oOOoO . address )
      if 28 - 28: O0 / ooOoO0o / IiII - I11i + IiII + OoO0O00
     I111I1iii11 = red ( oOOoO . address , False )
     IIIIiI1ii1 = oOOoO . port
     lprint ( "    Use NAT translated RLOC {}:{} for {}" . format ( I111I1iii11 , IIIIiI1ii1 , Ii1iiIII11 ) )
     if 84 - 84: Oo0Ooo + OoOoOO00 / iII111i . I1ii11iIi11i
     self . store_translated_rloc ( II11IIiii , IIIIiI1ii1 )
     if 26 - 26: Oo0Ooo
     if 61 - 61: Ii1I * oO0o * i11iIiiIii + OoO0O00
     if 43 - 43: OoO0O00 * OoO0O00 * oO0o
     if 24 - 24: oO0o
  self . geo = rloc_record . geo
  self . elp = rloc_record . elp
  self . json = rloc_record . json
  if 77 - 77: i11iIiiIii - I1Ii111 - I1ii11iIi11i * Oo0Ooo / i11iIiiIii
  if 79 - 79: Oo0Ooo % Oo0Ooo . oO0o + ooOoO0o * iII111i * I11i
  if 87 - 87: o0oOOo0O0Ooo + OoOoOO00 % o0oOOo0O0Ooo + I1IiiI
  if 89 - 89: II111iiii
  self . rle = rloc_record . rle
  if ( self . rle ) :
   for O00o000O0O0oO in self . rle . rle_nodes :
    ooOO0OOO = O00o000O0O0oO . rloc_name
    oOOoO = lisp_get_nat_info ( O00o000O0O0oO . address , ooOO0OOO )
    if ( oOOoO == None ) : continue
    if 41 - 41: iIii1I11I1II1
    IIIIiI1ii1 = oOOoO . port
    IIIi = ooOO0OOO
    if ( IIIi ) : IIIi = blue ( ooOO0OOO , False )
    if 26 - 26: Oo0Ooo / i1IIi + Oo0Ooo
    lprint ( ( "      Store translated encap-port {} for RLE-" + "node {}, rloc-name '{}'" ) . format ( IIIIiI1ii1 ,
    # ooOoO0o + Ii1I - oO0o / iII111i % IiII
 O00o000O0O0oO . address . print_address_no_iid ( ) , IIIi ) )
    O00o000O0O0oO . translated_port = IIIIiI1ii1
    if 22 - 22: II111iiii
    if 76 - 76: i1IIi
    if 60 - 60: iII111i - I1IiiI * I1ii11iIi11i - i1IIi % I1Ii111 % O0
  self . priority = rloc_record . priority
  self . mpriority = rloc_record . mpriority
  self . weight = rloc_record . weight
  self . mweight = rloc_record . mweight
  if ( rloc_record . reach_bit and rloc_record . local_bit and
 rloc_record . probe_bit == False ) : self . state = LISP_RLOC_UP_STATE
  if 24 - 24: I11i + I11i % I11i
  if 63 - 63: i11iIiiIii + iIii1I11I1II1 / oO0o % IiII - O0
  if 21 - 21: II111iiii
  if 89 - 89: OOooOOo % i11iIiiIii * OoOoOO00 % oO0o / O0 * i1IIi
  iIIii11IiI11 = source . is_exact_match ( rloc_record . rloc ) if source != None else None
  if 22 - 22: i1IIi / OoO0O00
  if ( rloc_record . keys != None and iIIii11IiI11 ) :
   OOO0OOoOOO = rloc_record . keys [ 1 ]
   if ( OOO0OOoOOO != None ) :
    i111I11I = rloc_record . rloc . print_address_no_iid ( ) + ":" + str ( IIIIiI1ii1 )
    if 46 - 46: I1Ii111 * II111iiii + II111iiii * O0 % II111iiii
    OOO0OOoOOO . add_key_by_rloc ( i111I11I , True )
    lprint ( "    Store encap-keys for nonce 0x{}, RLOC {}" . format ( lisp_hex_string ( nonce ) , red ( i111I11I , False ) ) )
    if 37 - 37: OOooOOo . iIii1I11I1II1 / O0 . ooOoO0o + OOooOOo - OoooooooOO
    if 96 - 96: I1Ii111 / oO0o . I1ii11iIi11i % I1IiiI * OOooOOo
    if 99 - 99: i11iIiiIii - I1Ii111
  return ( IIIIiI1ii1 )
  if 4 - 4: o0oOOo0O0Ooo - i11iIiiIii . iIii1I11I1II1 . OOooOOo % IiII
  if 68 - 68: I11i / iII111i - IiII . iIii1I11I1II1 / o0oOOo0O0Ooo
 def store_translated_rloc ( self , rloc , port ) :
  self . rloc . copy_address ( rloc )
  self . translated_rloc . copy_address ( rloc )
  self . translated_port = port
  if 54 - 54: II111iiii * I1IiiI
  if 49 - 49: I1ii11iIi11i
 def is_rloc_translated ( self ) :
  return ( self . translated_rloc . is_null ( ) == False )
  if 31 - 31: o0oOOo0O0Ooo - OoOoOO00 + I1ii11iIi11i . oO0o - O0
  if 61 - 61: I1ii11iIi11i * II111iiii . i1IIi
 def rloc_exists ( self ) :
  if ( self . rloc . is_null ( ) == False ) : return ( True )
  if ( self . rle_name or self . geo_name or self . elp_name or self . json_name ) :
   return ( False )
   if 60 - 60: OoooooooOO % ooOoO0o * i11iIiiIii * OoooooooOO % IiII
  return ( True )
  if 15 - 15: oO0o
  if 40 - 40: I1Ii111
 def is_rtr ( self ) :
  return ( ( self . priority == 254 and self . mpriority == 255 and self . weight == 0 and self . mweight == 0 ) )
  if 77 - 77: II111iiii - o0oOOo0O0Ooo . Ii1I
  if 47 - 47: o0oOOo0O0Ooo % OOooOOo + I1Ii111
  if 64 - 64: ooOoO0o / IiII . I1IiiI
 def print_state_change ( self , new_state ) :
  oOo000o0O0O = self . print_state ( )
  o0oOo = "{} -> {}" . format ( oOo000o0O0O , new_state )
  if ( new_state == "up" and self . unreach_state ( ) ) :
   o0oOo = bold ( o0oOo , False )
   if 60 - 60: I1IiiI . iIii1I11I1II1
  return ( o0oOo )
  if 42 - 42: iII111i
  if 90 - 90: Ii1I . o0oOOo0O0Ooo
 def print_rloc_probe_rtt ( self ) :
  if ( self . rloc_probe_rtt == - 1 ) : return ( "none" )
  return ( self . rloc_probe_rtt )
  if 3 - 3: oO0o
  if 42 - 42: Oo0Ooo
 def print_recent_rloc_probe_rtts ( self ) :
  iIIII1I11iii = str ( self . recent_rloc_probe_rtts )
  iIIII1I11iii = iIIII1I11iii . replace ( "-1" , "?" )
  return ( iIIII1I11iii )
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
  II11IIiii = self
  while ( True ) :
   if ( II11IIiii . last_rloc_probe_nonce == nonce ) : break
   II11IIiii = II11IIiii . next_rloc
   if ( II11IIiii == None ) :
    lprint ( "    No matching nonce state found for nonce 0x{}" . format ( lisp_hex_string ( nonce ) ) )
    if 74 - 74: OoOoOO00
    return
    if 91 - 91: i11iIiiIii / Ii1I % OOooOOo % O0 - I11i . I11i
    if 78 - 78: i1IIi + I11i % OoooooooOO + i1IIi + iII111i % Ii1I
    if 87 - 87: ooOoO0o . iIii1I11I1II1
  II11IIiii . last_rloc_probe_reply = lisp_get_timestamp ( )
  II11IIiii . compute_rloc_probe_rtt ( )
  O00o00 = II11IIiii . print_state_change ( "up" )
  if ( II11IIiii . state != LISP_RLOC_UP_STATE ) :
   lisp_update_rtr_updown ( II11IIiii . rloc , True )
   II11IIiii . state = LISP_RLOC_UP_STATE
   II11IIiii . last_state_change = lisp_get_timestamp ( )
   OoOOO000O0o = lisp_map_cache . lookup_cache ( eid , True )
   if ( OoOOO000O0o ) : lisp_write_ipc_map_cache ( True , OoOOO000O0o )
   if 65 - 65: iIii1I11I1II1
   if 58 - 58: IiII % i1IIi . i11iIiiIii
  II11IIiii . store_rloc_probe_hops ( hop_count , ttl )
  if 5 - 5: OoOoOO00
  OOo00o = bold ( "RLOC-probe reply" , False )
  i111I11I = II11IIiii . rloc . print_address_no_iid ( )
  oOOO0Ooooo = bold ( str ( II11IIiii . print_rloc_probe_rtt ( ) ) , False )
  IiIiI1 = ":{}" . format ( self . translated_port ) if self . translated_port != 0 else ""
  if 57 - 57: OoooooooOO % OoooooooOO + I1ii11iIi11i - I11i * II111iiii
  iI1II1IiIiIi = ""
  if ( II11IIiii . rloc_next_hop != None ) :
   OooOo , iiiIIiII111I = II11IIiii . rloc_next_hop
   iI1II1IiIiIi = ", nh {}({})" . format ( iiiIIiII111I , OooOo )
   if 86 - 86: I1IiiI
   if 83 - 83: I11i % Ii1I + IiII % I11i / i1IIi . oO0o
  ooOoOOOOo = green ( lisp_print_eid_tuple ( eid , group ) , False )
  lprint ( ( "    Received {} from {}{} for {}, {}, rtt {}{}, " + "to-ttl/from-ttl {}" ) . format ( OOo00o , red ( i111I11I , False ) , IiIiI1 , ooOoOOOOo ,
  # I1ii11iIi11i + iII111i * o0oOOo0O0Ooo % II111iiii
 O00o00 , oOOO0Ooooo , iI1II1IiIiIi , str ( hop_count ) + "/" + str ( ttl ) ) )
  if 23 - 23: i1IIi * oO0o * oO0o . i11iIiiIii / o0oOOo0O0Ooo
  if ( II11IIiii . rloc_next_hop == None ) : return
  if 80 - 80: O0 / II111iiii . Oo0Ooo + o0oOOo0O0Ooo - OoO0O00
  if 8 - 8: o0oOOo0O0Ooo / I1Ii111 % i1IIi
  if 6 - 6: I1Ii111 * oO0o
  if 48 - 48: Ii1I + i1IIi . iIii1I11I1II1
  II11IIiii = None
  Oo0OOoO0oo0oO = None
  while ( True ) :
   II11IIiii = self if II11IIiii == None else II11IIiii . next_rloc
   if ( II11IIiii == None ) : break
   if ( II11IIiii . up_state ( ) == False ) : continue
   if ( II11IIiii . rloc_probe_rtt == - 1 ) : continue
   if 31 - 31: iIii1I11I1II1 + I1IiiI
   if ( Oo0OOoO0oo0oO == None ) : Oo0OOoO0oo0oO = II11IIiii
   if ( II11IIiii . rloc_probe_rtt < Oo0OOoO0oo0oO . rloc_probe_rtt ) : Oo0OOoO0oo0oO = II11IIiii
   if 82 - 82: I1Ii111 / Ii1I % OoooooooOO - IiII / OoooooooOO
   if 23 - 23: iIii1I11I1II1
  if ( Oo0OOoO0oo0oO != None ) :
   OooOo , iiiIIiII111I = Oo0OOoO0oo0oO . rloc_next_hop
   iI1II1IiIiIi = bold ( "nh {}({})" . format ( iiiIIiII111I , OooOo ) , False )
   lprint ( "    Install host-route via best {}" . format ( iI1II1IiIiIi ) )
   lisp_install_host_route ( i111I11I , None , False )
   lisp_install_host_route ( i111I11I , iiiIIiII111I , True )
   if 7 - 7: IiII / OOooOOo + Oo0Ooo . I1IiiI
   if 33 - 33: I1Ii111 + OoooooooOO
   if 73 - 73: O0 . Oo0Ooo
 def add_to_rloc_probe_list ( self , eid , group ) :
  i111I11I = self . rloc . print_address_no_iid ( )
  IIIIiI1ii1 = self . translated_port
  if ( IIIIiI1ii1 != 0 ) : i111I11I += ":" + str ( IIIIiI1ii1 )
  if 28 - 28: I1IiiI . O0 % o0oOOo0O0Ooo / I11i
  if ( lisp_rloc_probe_list . has_key ( i111I11I ) == False ) :
   lisp_rloc_probe_list [ i111I11I ] = [ ]
   if 48 - 48: II111iiii % I1ii11iIi11i - II111iiii
   if 29 - 29: I1Ii111 - I1Ii111 - I11i * iIii1I11I1II1 % OoO0O00 % IiII
  if ( group . is_null ( ) ) : group . instance_id = 0
  for oooO0 , ooOoOOOOo , IiIoO0oo0 in lisp_rloc_probe_list [ i111I11I ] :
   if ( ooOoOOOOo . is_exact_match ( eid ) and IiIoO0oo0 . is_exact_match ( group ) ) :
    if ( oooO0 == self ) :
     if ( lisp_rloc_probe_list [ i111I11I ] == [ ] ) :
      lisp_rloc_probe_list . pop ( i111I11I )
      if 73 - 73: i1IIi . OoooooooOO / OoOoOO00 % Ii1I / Ii1I / Ii1I
     return
     if 40 - 40: I1Ii111 - iIii1I11I1II1
    lisp_rloc_probe_list [ i111I11I ] . remove ( [ oooO0 , ooOoOOOOo , IiIoO0oo0 ] )
    break
    if 88 - 88: OOooOOo * O0 * OoOoOO00
    if 26 - 26: Ii1I
  lisp_rloc_probe_list [ i111I11I ] . append ( [ self , eid , group ] )
  if 65 - 65: iII111i / iIii1I11I1II1 + I11i - iIii1I11I1II1 - Ii1I . I1Ii111
  if 77 - 77: OoOoOO00 / I1IiiI + IiII
  if 66 - 66: i11iIiiIii * OoooooooOO + iII111i / Ii1I
  if 42 - 42: Ii1I / iIii1I11I1II1 / Oo0Ooo . O0 . oO0o * I1IiiI
  if 21 - 21: OoooooooOO
  II11IIiii = lisp_rloc_probe_list [ i111I11I ] [ 0 ] [ 0 ]
  if ( II11IIiii . state == LISP_RLOC_UNREACH_STATE ) :
   self . state = LISP_RLOC_UNREACH_STATE
   self . last_state_change = lisp_get_timestamp ( )
   if 76 - 76: i1IIi * i11iIiiIii / OOooOOo + I1Ii111
   if 50 - 50: oO0o % OoOoOO00 + I1IiiI
   if 15 - 15: II111iiii - iII111i / I1ii11iIi11i
 def delete_from_rloc_probe_list ( self , eid , group ) :
  i111I11I = self . rloc . print_address_no_iid ( )
  IIIIiI1ii1 = self . translated_port
  if ( IIIIiI1ii1 != 0 ) : i111I11I += ":" + str ( IIIIiI1ii1 )
  if ( lisp_rloc_probe_list . has_key ( i111I11I ) == False ) : return
  if 81 - 81: Ii1I - i1IIi % oO0o * Oo0Ooo * OoOoOO00
  OO0OO0 = [ ]
  for iiIiiIi in lisp_rloc_probe_list [ i111I11I ] :
   if ( iiIiiIi [ 0 ] != self ) : continue
   if ( iiIiiIi [ 1 ] . is_exact_match ( eid ) == False ) : continue
   if ( iiIiiIi [ 2 ] . is_exact_match ( group ) == False ) : continue
   OO0OO0 = iiIiiIi
   break
   if 75 - 75: OoO0O00 % iII111i
  if ( OO0OO0 == [ ] ) : return
  if 46 - 46: o0oOOo0O0Ooo
  try :
   lisp_rloc_probe_list [ i111I11I ] . remove ( OO0OO0 )
   if ( lisp_rloc_probe_list [ i111I11I ] == [ ] ) :
    lisp_rloc_probe_list . pop ( i111I11I )
    if 61 - 61: OoO0O00 . O0 + I1ii11iIi11i + OoO0O00
  except :
   return
   if 44 - 44: I11i . oO0o
   if 65 - 65: I1ii11iIi11i * II111iiii % I11i + II111iiii . i1IIi / ooOoO0o
   if 74 - 74: OoOoOO00 % OoO0O00 . OoOoOO00
 def print_rloc_probe_state ( self , trailing_linefeed ) :
  II1i11i1iIi11 = ""
  II11IIiii = self
  while ( True ) :
   II11 = II11IIiii . last_rloc_probe
   if ( II11 == None ) : II11 = 0
   iI1ii11 = II11IIiii . last_rloc_probe_reply
   if ( iI1ii11 == None ) : iI1ii11 = 0
   oOOO0Ooooo = II11IIiii . print_rloc_probe_rtt ( )
   oOOOOOOOoO = space ( 4 )
   if 59 - 59: o0oOOo0O0Ooo
   if ( II11IIiii . rloc_next_hop == None ) :
    II1i11i1iIi11 += "RLOC-Probing:\n"
   else :
    OooOo , iiiIIiII111I = II11IIiii . rloc_next_hop
    II1i11i1iIi11 += "RLOC-Probing for nh {}({}):\n" . format ( iiiIIiII111I , OooOo )
    if 76 - 76: OoO0O00 + O0 - OoOoOO00 - IiII
    if 11 - 11: ooOoO0o + OoOoOO00 - i1IIi
   II1i11i1iIi11 += ( "{}RLOC-probe request sent: {}\n{}RLOC-probe reply " + "received: {}, rtt {}" ) . format ( oOOOOOOOoO , lisp_print_elapsed ( II11 ) ,
   # i11iIiiIii . Ii1I * OoOoOO00 - Ii1I / OoO0O00
 oOOOOOOOoO , lisp_print_elapsed ( iI1ii11 ) , oOOO0Ooooo )
   if 35 - 35: II111iiii . II111iiii - Ii1I % I1ii11iIi11i - Oo0Ooo * ooOoO0o
   if ( trailing_linefeed ) : II1i11i1iIi11 += "\n"
   if 85 - 85: IiII
   II11IIiii = II11IIiii . next_rloc
   if ( II11IIiii == None ) : break
   II1i11i1iIi11 += "\n"
   if 87 - 87: oO0o % OoO0O00 . iIii1I11I1II1 * ooOoO0o + oO0o + IiII
  return ( II1i11i1iIi11 )
  if 74 - 74: i1IIi % i1IIi + Oo0Ooo
  if 48 - 48: iII111i . i11iIiiIii + i11iIiiIii
 def get_encap_keys ( self ) :
  IIIIiI1ii1 = "4341" if self . translated_port == 0 else str ( self . translated_port )
  if 56 - 56: OoooooooOO
  i111I11I = self . rloc . print_address_no_iid ( ) + ":" + IIIIiI1ii1
  if 52 - 52: O0 - I1Ii111 + oO0o % ooOoO0o . oO0o
  try :
   i11i1ii11Ii1 = lisp_crypto_keys_by_rloc_encap [ i111I11I ]
   if ( i11i1ii11Ii1 [ 1 ] ) : return ( i11i1ii11Ii1 [ 1 ] . encrypt_key , i11i1ii11Ii1 [ 1 ] . icv_key )
   return ( None , None )
  except :
   return ( None , None )
   if 60 - 60: oO0o + o0oOOo0O0Ooo - OOooOOo % o0oOOo0O0Ooo . I11i + OoO0O00
   if 27 - 27: i11iIiiIii - I1ii11iIi11i * I1Ii111 . I1IiiI / OoO0O00 * ooOoO0o
   if 42 - 42: OOooOOo
 def rloc_recent_rekey ( self ) :
  IIIIiI1ii1 = "4341" if self . translated_port == 0 else str ( self . translated_port )
  if 36 - 36: OoooooooOO + ooOoO0o + iII111i
  i111I11I = self . rloc . print_address_no_iid ( ) + ":" + IIIIiI1ii1
  if 30 - 30: i1IIi % Ii1I
  try :
   OOO0OOoOOO = lisp_crypto_keys_by_rloc_encap [ i111I11I ] [ 1 ]
   if ( OOO0OOoOOO == None ) : return ( False )
   if ( OOO0OOoOOO . last_rekey == None ) : return ( True )
   return ( time . time ( ) - OOO0OOoOOO . last_rekey < 1 )
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
  self . gleaned_groups = [ ]
  if 46 - 46: OoOoOO00 / iII111i - OoO0O00 . o0oOOo0O0Ooo
  if 50 - 50: I1Ii111 . O0 . OoOoOO00 + I1Ii111 + OoooooooOO . i11iIiiIii
 def print_mapping ( self , eid_indent , rloc_indent ) :
  iiiI = lisp_print_elapsed ( self . uptime )
  IiI1111i1i11I = "" if self . group . is_null ( ) else ", group {}" . format ( self . group . print_prefix ( ) )
  if 65 - 65: I1IiiI % iIii1I11I1II1
  lprint ( "{}eid {}{}, uptime {}, {} rlocs:" . format ( eid_indent ,
 green ( self . eid . print_prefix ( ) , False ) , IiI1111i1i11I , iiiI ,
 len ( self . rloc_set ) ) )
  for II11IIiii in self . rloc_set : II11IIiii . print_rloc ( rloc_indent )
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
  I1IiIii11I = time . time ( ) - self . last_refresh_time
  if ( I1IiIii11I >= self . map_cache_ttl ) : return ( True )
  if 85 - 85: II111iiii
  if 58 - 58: i1IIi - OoO0O00 + ooOoO0o
  if 6 - 6: IiII % I1IiiI + OoooooooOO * oO0o . iII111i + oO0o
  if 4 - 4: I11i % I1IiiI
  if 72 - 72: I1IiiI % II111iiii % iII111i / OoOoOO00
  oO0OoO0oo0 = self . map_cache_ttl - ( self . map_cache_ttl / 10 )
  if ( I1IiIii11I >= oO0OoO0oo0 ) : return ( True )
  return ( False )
  if 82 - 82: I1Ii111
  if 78 - 78: I1Ii111 % oO0o * iIii1I11I1II1
 def is_active ( self ) :
  if ( self . stats . last_increment == None ) : return ( False )
  I1IiIii11I = time . time ( ) - self . stats . last_increment
  return ( I1IiIii11I <= 60 )
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
  for II11IIiii in self . best_rloc_set :
   II11IIiii . delete_from_rloc_probe_list ( self . eid , self . group )
   if 33 - 33: ooOoO0o
   if 19 - 19: I1Ii111 % IiII
   if 94 - 94: I1Ii111 * I1ii11iIi11i * I1ii11iIi11i - o0oOOo0O0Ooo . i11iIiiIii
 def build_best_rloc_set ( self ) :
  i1i1 = self . best_rloc_set
  self . best_rloc_set = [ ]
  if ( self . rloc_set == None ) : return
  if 79 - 79: oO0o
  if 52 - 52: oO0o + OoO0O00 / OoooooooOO - iIii1I11I1II1 / iII111i - oO0o
  if 68 - 68: I1IiiI - OoOoOO00 - iIii1I11I1II1 % i11iIiiIii * OoOoOO00 * OoO0O00
  if 97 - 97: OoO0O00 - IiII + ooOoO0o % iIii1I11I1II1 % iII111i
  O000ooo00 = 256
  for II11IIiii in self . rloc_set :
   if ( II11IIiii . up_state ( ) ) : O000ooo00 = min ( II11IIiii . priority , O000ooo00 )
   if 22 - 22: Oo0Ooo . I11i + OOooOOo
   if 62 - 62: O0 / iII111i * oO0o - o0oOOo0O0Ooo % i11iIiiIii
   if 17 - 17: I1IiiI - OoooooooOO
   if 46 - 46: Oo0Ooo % i11iIiiIii * o0oOOo0O0Ooo
   if 33 - 33: oO0o * ooOoO0o * Ii1I * IiII
   if 39 - 39: i1IIi
   if 79 - 79: ooOoO0o - II111iiii - oO0o
   if 55 - 55: iII111i % iIii1I11I1II1 + Ii1I + oO0o . i11iIiiIii - OOooOOo
   if 14 - 14: oO0o - i11iIiiIii / OoOoOO00 % o0oOOo0O0Ooo / IiII * I1IiiI
   if 2 - 2: i1IIi / I1Ii111 + I1IiiI + I1ii11iIi11i - o0oOOo0O0Ooo + iIii1I11I1II1
  for II11IIiii in self . rloc_set :
   if ( II11IIiii . priority <= O000ooo00 ) :
    if ( II11IIiii . unreach_state ( ) and II11IIiii . last_rloc_probe == None ) :
     II11IIiii . last_rloc_probe = lisp_get_timestamp ( )
     if 78 - 78: I1ii11iIi11i % i1IIi . I1Ii111 + Oo0Ooo . o0oOOo0O0Ooo % II111iiii
    self . best_rloc_set . append ( II11IIiii )
    if 65 - 65: Ii1I . OoOoOO00 + O0 / iIii1I11I1II1 % Ii1I % I1Ii111
    if 31 - 31: o0oOOo0O0Ooo - Oo0Ooo
    if 15 - 15: O0 + OOooOOo
    if 8 - 8: i11iIiiIii . IiII . I1ii11iIi11i + i1IIi % I1Ii111
    if 64 - 64: I1IiiI . Oo0Ooo * OoO0O00
    if 87 - 87: i1IIi / OoooooooOO
    if 68 - 68: I1Ii111 / iIii1I11I1II1
    if 8 - 8: ooOoO0o * IiII * OOooOOo / I1IiiI
  for II11IIiii in i1i1 :
   if ( II11IIiii . priority < O000ooo00 ) : continue
   II11IIiii . delete_from_rloc_probe_list ( self . eid , self . group )
   if 40 - 40: i11iIiiIii + OoooooooOO
  for II11IIiii in self . best_rloc_set :
   if ( II11IIiii . rloc . is_null ( ) ) : continue
   II11IIiii . add_to_rloc_probe_list ( self . eid , self . group )
   if 2 - 2: o0oOOo0O0Ooo * OoO0O00
   if 88 - 88: Oo0Ooo + oO0o + iII111i
   if 51 - 51: i1IIi + i11iIiiIii * I11i / iII111i + OoooooooOO
 def select_rloc ( self , lisp_packet , ipc_socket ) :
  Ii11iIiiI = lisp_packet . packet
  OoO00oooO = lisp_packet . inner_version
  O00OoO0oo = len ( self . best_rloc_set )
  if ( O00OoO0oo is 0 ) :
   self . stats . increment ( len ( Ii11iIiiI ) )
   return ( [ None , None , None , self . action , None , None ] )
   if 89 - 89: oO0o
   if 17 - 17: oO0o / Oo0Ooo / i1IIi - OOooOOo / Oo0Ooo
  IIiiiiII = 4 if lisp_load_split_pings else 0
  II1IIIi = lisp_packet . hash_ports ( )
  if ( OoO00oooO == 4 ) :
   for oo0O0oO0O0O in range ( 8 + IIiiiiII ) :
    II1IIIi = II1IIIi ^ struct . unpack ( "B" , Ii11iIiiI [ oo0O0oO0O0O + 12 ] ) [ 0 ]
    if 86 - 86: OOooOOo * OoOoOO00 % i1IIi * IiII . I1ii11iIi11i
  elif ( OoO00oooO == 6 ) :
   for oo0O0oO0O0O in range ( 0 , 32 + IIiiiiII , 4 ) :
    II1IIIi = II1IIIi ^ struct . unpack ( "I" , Ii11iIiiI [ oo0O0oO0O0O + 8 : oo0O0oO0O0O + 12 ] ) [ 0 ]
    if 72 - 72: i1IIi - I1Ii111 . O0 * OoO0O00
   II1IIIi = ( II1IIIi >> 16 ) + ( II1IIIi & 0xffff )
   II1IIIi = ( II1IIIi >> 8 ) + ( II1IIIi & 0xff )
  else :
   for oo0O0oO0O0O in range ( 0 , 12 + IIiiiiII , 4 ) :
    II1IIIi = II1IIIi ^ struct . unpack ( "I" , Ii11iIiiI [ oo0O0oO0O0O : oo0O0oO0O0O + 4 ] ) [ 0 ]
    if 62 - 62: Oo0Ooo . iII111i
    if 15 - 15: i11iIiiIii * I11i + oO0o
    if 67 - 67: IiII . OoO0O00
  if ( lisp_data_plane_logging ) :
   oOO0oO0o0oOoO = [ ]
   for oooO0 in self . best_rloc_set :
    if ( oooO0 . rloc . is_null ( ) ) : continue
    oOO0oO0o0oOoO . append ( [ oooO0 . rloc . print_address_no_iid ( ) , oooO0 . print_state ( ) ] )
    if 30 - 30: II111iiii / II111iiii
   dprint ( "Packet hash {}, index {}, best-rloc-list: {}" . format ( hex ( II1IIIi ) , II1IIIi % O00OoO0oo , red ( str ( oOO0oO0o0oOoO ) , False ) ) )
   if 70 - 70: OoO0O00 + O0 * OoO0O00
   if 25 - 25: OoooooooOO . Oo0Ooo + OOooOOo + Oo0Ooo * O0 % i1IIi
   if 71 - 71: II111iiii / Ii1I + i1IIi - OoOoOO00 + Ii1I
   if 31 - 31: OoooooooOO * Ii1I - iII111i . oO0o % Ii1I
   if 97 - 97: Ii1I
   if 51 - 51: II111iiii . oO0o % iII111i
  II11IIiii = self . best_rloc_set [ II1IIIi % O00OoO0oo ]
  if 47 - 47: II111iiii - iII111i * I1IiiI . IiII
  if 41 - 41: OoOoOO00 / O0 + I1Ii111 . I1ii11iIi11i
  if 48 - 48: Ii1I . o0oOOo0O0Ooo * O0 / OoooooooOO + I1Ii111 + Oo0Ooo
  if 92 - 92: Ii1I - o0oOOo0O0Ooo % I1IiiI + I1Ii111
  if 3 - 3: iIii1I11I1II1 + i11iIiiIii
  I1iiiIi1i11i = lisp_get_echo_nonce ( II11IIiii . rloc , None )
  if ( I1iiiIi1i11i ) :
   I1iiiIi1i11i . change_state ( II11IIiii )
   if ( II11IIiii . no_echoed_nonce_state ( ) ) :
    I1iiiIi1i11i . request_nonce_sent = None
    if 49 - 49: OoOoOO00 % iIii1I11I1II1 + I1Ii111
    if 38 - 38: i11iIiiIii
    if 75 - 75: iIii1I11I1II1 / OoO0O00 * OOooOOo % O0
    if 82 - 82: Oo0Ooo / i1IIi . i1IIi / oO0o
    if 7 - 7: Oo0Ooo . iII111i % I1ii11iIi11i / iII111i
    if 93 - 93: iII111i
  if ( II11IIiii . up_state ( ) == False ) :
   I1O0O0oOooooO0O = II1IIIi % O00OoO0oo
   Oo0oOooo000OO = ( I1O0O0oOooooO0O + 1 ) % O00OoO0oo
   while ( Oo0oOooo000OO != I1O0O0oOooooO0O ) :
    II11IIiii = self . best_rloc_set [ Oo0oOooo000OO ]
    if ( II11IIiii . up_state ( ) ) : break
    Oo0oOooo000OO = ( Oo0oOooo000OO + 1 ) % O00OoO0oo
    if 34 - 34: OoooooooOO - iII111i * iIii1I11I1II1 . OoO0O00
   if ( Oo0oOooo000OO == I1O0O0oOooooO0O ) :
    self . build_best_rloc_set ( )
    return ( [ None , None , None , None , None , None ] )
    if 75 - 75: i11iIiiIii - oO0o % I1Ii111
    if 19 - 19: oO0o . I1Ii111 - IiII * IiII - OoOoOO00 % iIii1I11I1II1
    if 77 - 77: II111iiii + OOooOOo % iII111i * O0 % i1IIi / I1Ii111
    if 39 - 39: II111iiii % OoOoOO00 / O0 / II111iiii
    if 15 - 15: I11i + I1IiiI / I11i + iIii1I11I1II1 * Oo0Ooo / I1ii11iIi11i
    if 8 - 8: ooOoO0o . O0 / OoO0O00
  II11IIiii . stats . increment ( len ( Ii11iIiiI ) )
  if 50 - 50: Ii1I . OoOoOO00 * o0oOOo0O0Ooo
  if 68 - 68: IiII * oO0o / OoOoOO00 / I1Ii111
  if 72 - 72: I1ii11iIi11i
  if 74 - 74: I1Ii111 * iIii1I11I1II1 / oO0o - IiII - I1IiiI
  if ( II11IIiii . rle_name and II11IIiii . rle == None ) :
   if ( lisp_rle_list . has_key ( II11IIiii . rle_name ) ) :
    II11IIiii . rle = lisp_rle_list [ II11IIiii . rle_name ]
    if 84 - 84: iIii1I11I1II1 % Oo0Ooo / I1ii11iIi11i + o0oOOo0O0Ooo * II111iiii
    if 81 - 81: I1IiiI / I1ii11iIi11i / OOooOOo
  if ( II11IIiii . rle ) : return ( [ None , None , None , None , II11IIiii . rle , None ] )
  if 89 - 89: Oo0Ooo % IiII
  if 36 - 36: IiII % OoOoOO00 % I1ii11iIi11i
  if 7 - 7: I1ii11iIi11i % OoOoOO00 - O0 . I1Ii111
  if 9 - 9: Ii1I . OoooooooOO / ooOoO0o + i1IIi
  if ( II11IIiii . elp and II11IIiii . elp . use_elp_node ) :
   return ( [ II11IIiii . elp . use_elp_node . address , None , None , None , None ,
 None ] )
   if 90 - 90: oO0o - OoOoOO00 % ooOoO0o
   if 83 - 83: OOooOOo - I1ii11iIi11i + OoO0O00
   if 99 - 99: iII111i - OoOoOO00 % ooOoO0o
   if 27 - 27: oO0o . oO0o * iII111i % iIii1I11I1II1
   if 81 - 81: iII111i * II111iiii
  iiiIIII = None if ( II11IIiii . rloc . is_null ( ) ) else II11IIiii . rloc
  IIIIiI1ii1 = II11IIiii . translated_port
  i11IIiI = self . action if ( iiiIIII == None ) else None
  if 49 - 49: ooOoO0o + iII111i % OoooooooOO / Oo0Ooo % i1IIi
  if 50 - 50: OoO0O00
  if 52 - 52: o0oOOo0O0Ooo + O0
  if 13 - 13: OoO0O00
  if 56 - 56: OoOoOO00 . ooOoO0o * oO0o - I11i
  i11IIoOOoOo0Ooo = None
  if ( I1iiiIi1i11i and I1iiiIi1i11i . request_nonce_timeout ( ) == False ) :
   i11IIoOOoOo0Ooo = I1iiiIi1i11i . get_request_or_echo_nonce ( ipc_socket , iiiIIII )
   if 47 - 47: oO0o . i1IIi * I1ii11iIi11i % OOooOOo % IiII / Oo0Ooo
   if 39 - 39: i11iIiiIii . OOooOOo + Oo0Ooo
   if 92 - 92: O0 * Oo0Ooo / o0oOOo0O0Ooo % OoO0O00
   if 87 - 87: OoooooooOO / I11i . O0
   if 77 - 77: OOooOOo + oO0o * iIii1I11I1II1 / oO0o / OOooOOo . i11iIiiIii
  return ( [ iiiIIII , IIIIiI1ii1 , i11IIoOOoOo0Ooo , i11IIiI , None , II11IIiii ] )
  if 92 - 92: Oo0Ooo . o0oOOo0O0Ooo % OoooooooOO * i11iIiiIii * OoO0O00 * o0oOOo0O0Ooo
  if 48 - 48: iII111i * I1ii11iIi11i * oO0o % O0 . OoO0O00
 def do_rloc_sets_match ( self , rloc_address_set ) :
  if ( len ( self . rloc_set ) != len ( rloc_address_set ) ) : return ( False )
  if 11 - 11: OOooOOo / o0oOOo0O0Ooo
  if 98 - 98: oO0o + I11i . oO0o
  if 10 - 10: iII111i + i1IIi . I11i % ooOoO0o / ooOoO0o
  if 86 - 86: Oo0Ooo
  if 7 - 7: iIii1I11I1II1
  for IiIiI in self . rloc_set :
   for II11IIiii in rloc_address_set :
    if ( II11IIiii . is_exact_match ( IiIiI . rloc ) == False ) : continue
    II11IIiii = None
    break
    if 86 - 86: IiII + iII111i * II111iiii - IiII - o0oOOo0O0Ooo
   if ( II11IIiii == rloc_address_set [ - 1 ] ) : return ( False )
   if 8 - 8: OOooOOo . Ii1I
  return ( True )
  if 15 - 15: ooOoO0o / OOooOOo + i1IIi / Ii1I / OOooOOo
  if 47 - 47: Oo0Ooo + oO0o % OoooooooOO
 def get_rloc ( self , rloc ) :
  for IiIiI in self . rloc_set :
   oooO0 = IiIiI . rloc
   if ( rloc . is_exact_match ( oooO0 ) ) : return ( IiIiI )
   if 23 - 23: I1Ii111 / i11iIiiIii - ooOoO0o * iII111i - Ii1I . iIii1I11I1II1
  return ( None )
  if 11 - 11: I11i % OoOoOO00 * Oo0Ooo
  if 48 - 48: OOooOOo
 def get_rloc_by_interface ( self , interface ) :
  for IiIiI in self . rloc_set :
   if ( IiIiI . interface == interface ) : return ( IiIiI )
   if 66 - 66: iII111i - I1Ii111 - i11iIiiIii . o0oOOo0O0Ooo + Oo0Ooo
  return ( None )
  if 90 - 90: O0 - i11iIiiIii * ooOoO0o . I1ii11iIi11i . Ii1I - OoooooooOO
  if 23 - 23: o0oOOo0O0Ooo
 def add_db ( self ) :
  if ( self . group . is_null ( ) ) :
   lisp_db_for_lookups . add_cache ( self . eid , self )
  else :
   i1i1iiiii1IiI = lisp_db_for_lookups . lookup_cache ( self . group , True )
   if ( i1i1iiiii1IiI == None ) :
    i1i1iiiii1IiI = lisp_mapping ( self . group , self . group , [ ] )
    lisp_db_for_lookups . add_cache ( self . group , i1i1iiiii1IiI )
    if 88 - 88: I1Ii111 + iIii1I11I1II1 / o0oOOo0O0Ooo
   i1i1iiiii1IiI . add_source_entry ( self )
   if 93 - 93: ooOoO0o % iIii1I11I1II1 - OOooOOo . IiII + ooOoO0o
   if 63 - 63: I1ii11iIi11i / OOooOOo
   if 28 - 28: I11i / I1Ii111 + IiII * OoooooooOO - iIii1I11I1II1
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
    if 6 - 6: I11i % o0oOOo0O0Ooo / OoooooooOO . I1Ii111
   if ( self . eid . is_null ( ) ) : self . eid . make_default_route ( OoOOO000O0o . group )
   OoOOO000O0o . add_source_entry ( self )
   if 17 - 17: I1ii11iIi11i + OoooooooOO / iIii1I11I1II1 . II111iiii + Oo0Ooo
  if ( do_ipc ) : lisp_write_ipc_map_cache ( True , self )
  if 7 - 7: O0 - I1ii11iIi11i - iIii1I11I1II1
  if 96 - 96: OoOoOO00 . I1IiiI . I11i * OoooooooOO + OoooooooOO * O0
 def delete_cache ( self ) :
  self . delete_rlocs_from_rloc_probe_list ( )
  lisp_write_ipc_map_cache ( False , self )
  if 90 - 90: I11i + I1ii11iIi11i + OoooooooOO + OoOoOO00 + IiII / iII111i
  if ( self . group . is_null ( ) ) :
   lisp_map_cache . delete_cache ( self . eid )
   if ( lisp_program_hardware ) :
    ooII1111iI1I = self . eid . print_prefix_no_iid ( )
    os . system ( "ip route delete {}" . format ( ooII1111iI1I ) )
    if 23 - 23: I11i
  else :
   OoOOO000O0o = lisp_map_cache . lookup_cache ( self . group , True )
   if ( OoOOO000O0o == None ) : return
   if 73 - 73: I1Ii111 . iII111i + O0
   iiiI1i = OoOOO000O0o . lookup_source_cache ( self . eid , True )
   if ( iiiI1i == None ) : return
   if 79 - 79: I11i . iII111i - iII111i / iII111i * iII111i % i1IIi
   OoOOO000O0o . source_cache . delete_cache ( self . eid )
   if ( OoOOO000O0o . source_cache . cache_size ( ) == 0 ) :
    lisp_map_cache . delete_cache ( self . group )
    if 10 - 10: IiII
    if 60 - 60: i1IIi + i1IIi
    if 47 - 47: iII111i - I1Ii111 - I1Ii111 . ooOoO0o
    if 5 - 5: i1IIi
 def add_source_entry ( self , source_mc ) :
  if ( self . source_cache == None ) : self . source_cache = lisp_cache ( )
  self . source_cache . add_cache ( source_mc . eid , source_mc )
  if 47 - 47: I11i * I11i . OoOoOO00
  if 68 - 68: OoooooooOO + OoOoOO00 + i11iIiiIii
 def lookup_source_cache ( self , source , exact ) :
  if ( self . source_cache == None ) : return ( None )
  return ( self . source_cache . lookup_cache ( source , exact ) )
  if 89 - 89: Oo0Ooo + Ii1I * O0 - I1Ii111
  if 33 - 33: iIii1I11I1II1 . I11i
 def dynamic_eid_configured ( self ) :
  return ( self . dynamic_eids != None )
  if 63 - 63: oO0o - iII111i
  if 13 - 13: I1Ii111 / i1IIi % OoooooooOO / I11i
 def star_secondary_iid ( self , prefix ) :
  if ( self . secondary_iid == None ) : return ( prefix )
  II1ii1ii11I1 = "," + str ( self . secondary_iid )
  return ( prefix . replace ( II1ii1ii11I1 , II1ii1ii11I1 + "*" ) )
  if 66 - 66: I1Ii111 % o0oOOo0O0Ooo . iII111i . ooOoO0o + OOooOOo * II111iiii
  if 33 - 33: oO0o
 def increment_decap_stats ( self , packet ) :
  IIIIiI1ii1 = packet . udp_dport
  if ( IIIIiI1ii1 == LISP_DATA_PORT ) :
   II11IIiii = self . get_rloc ( packet . outer_dest )
  else :
   if 64 - 64: OoO0O00 % Oo0Ooo % I11i . iII111i % I1IiiI
   if 50 - 50: i1IIi + ooOoO0o - iIii1I11I1II1
   if 45 - 45: OoooooooOO / o0oOOo0O0Ooo / iII111i
   if 72 - 72: I1Ii111
   for II11IIiii in self . rloc_set :
    if ( II11IIiii . translated_port != 0 ) : break
    if 94 - 94: ooOoO0o . IiII - Ii1I + I1ii11iIi11i / ooOoO0o
    if 10 - 10: ooOoO0o . OOooOOo * O0 % II111iiii
  if ( II11IIiii != None ) : II11IIiii . stats . increment ( len ( packet . packet ) )
  self . stats . increment ( len ( packet . packet ) )
  if 12 - 12: oO0o + I1IiiI * Oo0Ooo - iII111i
  if 88 - 88: OOooOOo . OoO0O00
 def rtrs_in_rloc_set ( self ) :
  for II11IIiii in self . rloc_set :
   if ( II11IIiii . is_rtr ( ) ) : return ( True )
   if 86 - 86: OoOoOO00 . o0oOOo0O0Ooo / ooOoO0o * I1IiiI . OoO0O00 / I1Ii111
  return ( False )
  if 47 - 47: I11i . iII111i * OoOoOO00 % OoooooooOO
  if 59 - 59: OoooooooOO + I1ii11iIi11i - I11i / I1IiiI * oO0o
  if 90 - 90: I1Ii111 + i1IIi * I1Ii111 / I11i * Oo0Ooo
class lisp_dynamic_eid ( ) :
 def __init__ ( self ) :
  self . dynamic_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . uptime = lisp_get_timestamp ( )
  self . interface = None
  self . last_packet = None
  self . timeout = LISP_DEFAULT_DYN_EID_TIMEOUT
  if 27 - 27: OoooooooOO
  if 42 - 42: OoO0O00 + OoOoOO00
 def get_timeout ( self , interface ) :
  try :
   o0O00o000OOoO = lisp_myinterfaces [ interface ]
   self . timeout = o0O00o000OOoO . dynamic_eid_timeout
  except :
   self . timeout = LISP_DEFAULT_DYN_EID_TIMEOUT
   if 12 - 12: I1IiiI - Oo0Ooo / I11i
   if 79 - 79: II111iiii . I1Ii111 * I1Ii111 + I11i + I1Ii111 % I1IiiI
   if 42 - 42: I11i - i1IIi . Oo0Ooo - i1IIi
   if 87 - 87: O0 . o0oOOo0O0Ooo % OOooOOo / I11i - I1Ii111 % i11iIiiIii
class lisp_group_mapping ( ) :
 def __init__ ( self , group_name , ms_name , group_prefix , sources , rle_addr ) :
  self . group_name = group_name
  self . group_prefix = group_prefix
  self . use_ms_name = ms_name
  self . sources = sources
  self . rle_address = rle_addr
  if 3 - 3: oO0o + iII111i + OOooOOo
  if 54 - 54: i11iIiiIii + OoO0O00 - IiII - iII111i / I11i
 def add_group ( self ) :
  lisp_group_mapping_list [ self . group_name ] = self
  if 85 - 85: OOooOOo * OOooOOo * I1Ii111 - ooOoO0o . O0 % iII111i
  if 5 - 5: i1IIi * iII111i . o0oOOo0O0Ooo - I1ii11iIi11i
  if 84 - 84: i1IIi
  if 17 - 17: IiII + iII111i * OoO0O00 / iII111i
  if 67 - 67: i1IIi * IiII . OoOoOO00 % iIii1I11I1II1 - iIii1I11I1II1 * I1ii11iIi11i
  if 96 - 96: iII111i / i11iIiiIii / oO0o + Oo0Ooo
  if 65 - 65: OoOoOO00
  if 87 - 87: I11i % i1IIi + i11iIiiIii * II111iiii
  if 58 - 58: OoO0O00 * I1IiiI - II111iiii / Ii1I - I1IiiI % OoooooooOO
  if 33 - 33: IiII / i1IIi + I1Ii111
def lisp_is_group_more_specific ( group_str , group_mapping ) :
 II1ii1ii11I1 = group_mapping . group_prefix . instance_id
 ooI1111 = group_mapping . group_prefix . mask_len
 IiI1111i1i11I = lisp_address ( LISP_AFI_IPV4 , group_str , 32 , II1ii1ii11I1 )
 if ( IiI1111i1i11I . is_more_specific ( group_mapping . group_prefix ) ) : return ( ooI1111 )
 return ( - 1 )
 if 5 - 5: O0 / iII111i % II111iiii . Oo0Ooo - I11i
 if 84 - 84: oO0o * iII111i % i11iIiiIii - O0 . iIii1I11I1II1 - OoOoOO00
 if 73 - 73: OoOoOO00
 if 66 - 66: Oo0Ooo
 if 42 - 42: i11iIiiIii / II111iiii . OOooOOo
 if 65 - 65: OoOoOO00 % II111iiii + Oo0Ooo
 if 24 - 24: OoO0O00 % OoooooooOO
def lisp_lookup_group ( group ) :
 oOO0oO0o0oOoO = None
 for II1IiI11II in lisp_group_mapping_list . values ( ) :
  ooI1111 = lisp_is_group_more_specific ( group , II1IiI11II )
  if ( ooI1111 == - 1 ) : continue
  if ( oOO0oO0o0oOoO == None or ooI1111 > oOO0oO0o0oOoO . group_prefix . mask_len ) : oOO0oO0o0oOoO = II1IiI11II
  if 92 - 92: OoooooooOO
 return ( oOO0oO0o0oOoO )
 if 11 - 11: Oo0Ooo - II111iiii
 if 55 - 55: I1Ii111 - I1IiiI . oO0o - OoO0O00 + Oo0Ooo - Oo0Ooo
lisp_site_flags = {
 "P" : "ETR is {}Requesting Map-Server to Proxy Map-Reply" ,
 "S" : "ETR is {}LISP-SEC capable" ,
 "I" : "xTR-ID and site-ID are {}included in Map-Register" ,
 "T" : "Use Map-Register TTL field to timeout registration is {}set" ,
 "R" : "Merging registrations are {}requested" ,
 "M" : "ETR is {}a LISP Mobile-Node" ,
 "N" : "ETR is {}requesting Map-Notify messages from Map-Server"
 }
if 68 - 68: Oo0Ooo / I1ii11iIi11i % OoOoOO00 + Oo0Ooo
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
  if 92 - 92: II111iiii . O0 . iIii1I11I1II1 % IiII - i11iIiiIii
  if 9 - 9: OoO0O00
  if 60 - 60: O0 / OoOoOO00 % i11iIiiIii % II111iiii / OoooooooOO
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
  if 52 - 52: ooOoO0o
  if 100 - 100: Oo0Ooo - o0oOOo0O0Ooo + iIii1I11I1II1 / ooOoO0o % iIii1I11I1II1
 def print_eid_tuple ( self ) :
  return ( lisp_print_eid_tuple ( self . eid , self . group ) )
  if 4 - 4: OoOoOO00 / Oo0Ooo - OoO0O00 . OoOoOO00 / I1Ii111
  if 60 - 60: OOooOOo * I1Ii111
 def print_flags ( self , html ) :
  if ( html == False ) :
   II1i11i1iIi11 = "{}-{}-{}-{}-{}-{}-{}" . format ( "P" if self . proxy_reply_requested else "p" ,
   # o0oOOo0O0Ooo
 "S" if self . lisp_sec_present else "s" ,
 "I" if self . xtr_id_present else "i" ,
 "T" if self . use_register_ttl_requested else "t" ,
 "R" if self . merge_register_requested else "r" ,
 "M" if self . mobile_node_requested else "m" ,
 "N" if self . map_notify_requested else "n" )
  else :
   Ii = self . print_flags ( False )
   Ii = Ii . split ( "-" )
   II1i11i1iIi11 = ""
   for O0Ooo in Ii :
    ooOoooOo00Ooo = lisp_site_flags [ O0Ooo . upper ( ) ]
    ooOoooOo00Ooo = ooOoooOo00Ooo . format ( "" if O0Ooo . isupper ( ) else "not " )
    II1i11i1iIi11 += lisp_span ( O0Ooo , ooOoooOo00Ooo )
    if ( O0Ooo . lower ( ) != "n" ) : II1i11i1iIi11 += "-"
    if 95 - 95: I11i . IiII
    if 5 - 5: OoooooooOO + I1IiiI % OOooOOo + ooOoO0o . o0oOOo0O0Ooo * i11iIiiIii
  return ( II1i11i1iIi11 )
  if 43 - 43: I1IiiI - oO0o + OOooOOo * OoooooooOO
  if 92 - 92: i11iIiiIii / II111iiii * OoO0O00
 def copy_state_to_parent ( self , child ) :
  self . xtr_id = child . xtr_id
  self . site_id = child . site_id
  self . first_registered = child . first_registered
  self . last_registered = child . last_registered
  self . last_registerer = child . last_registerer
  self . register_ttl = child . register_ttl
  if ( self . registered == False ) :
   self . first_registered = lisp_get_timestamp ( )
   if 51 - 51: I1ii11iIi11i
  self . auth_sha1_or_sha2 = child . auth_sha1_or_sha2
  self . registered = child . registered
  self . proxy_reply_requested = child . proxy_reply_requested
  self . lisp_sec_present = child . lisp_sec_present
  self . xtr_id_present = child . xtr_id_present
  self . use_register_ttl_requested = child . use_register_ttl_requested
  self . merge_register_requested = child . merge_register_requested
  self . mobile_node_requested = child . mobile_node_requested
  self . map_notify_requested = child . map_notify_requested
  if 95 - 95: I1IiiI / iII111i + i1IIi
  if 31 - 31: OoOoOO00
 def build_sort_key ( self ) :
  Iii1IiIIiI = lisp_cache ( )
  I1iII1iI1 , OOO0OOoOOO = Iii1IiIIiI . build_key ( self . eid )
  iiIO00ooO0Oo = ""
  if ( self . group . is_null ( ) == False ) :
   ooOo , iiIO00ooO0Oo = Iii1IiIIiI . build_key ( self . group )
   iiIO00ooO0Oo = "-" + iiIO00ooO0Oo [ 0 : 12 ] + "-" + str ( ooOo ) + "-" + iiIO00ooO0Oo [ 12 : : ]
   if 63 - 63: I1Ii111 + iIii1I11I1II1 / Oo0Ooo
  OOO0OOoOOO = OOO0OOoOOO [ 0 : 12 ] + "-" + str ( I1iII1iI1 ) + "-" + OOO0OOoOOO [ 12 : : ] + iiIO00ooO0Oo
  del ( Iii1IiIIiI )
  return ( OOO0OOoOOO )
  if 6 - 6: ooOoO0o + I1ii11iIi11i * I1IiiI / OoO0O00 / OoooooooOO
  if 23 - 23: ooOoO0o
 def merge_in_site_eid ( self , child ) :
  o00Oo0oOO0 = False
  if ( self . group . is_null ( ) ) :
   self . merge_rlocs_in_site_eid ( )
  else :
   o00Oo0oOO0 = self . merge_rles_in_site_eid ( )
   if 97 - 97: i11iIiiIii . OoOoOO00 + oO0o * O0 % OoO0O00 - Ii1I
   if 46 - 46: I1Ii111
   if 87 - 87: o0oOOo0O0Ooo - iII111i * OoO0O00 * o0oOOo0O0Ooo . o0oOOo0O0Ooo / OOooOOo
   if 50 - 50: i11iIiiIii - II111iiii * OoooooooOO + II111iiii - ooOoO0o
   if 52 - 52: i1IIi + i1IIi * i1IIi / OoOoOO00
   if 98 - 98: iII111i . i1IIi + o0oOOo0O0Ooo * OoooooooOO - i11iIiiIii
  if ( child != None ) :
   self . copy_state_to_parent ( child )
   self . map_registers_received += 1
   if 21 - 21: i11iIiiIii . oO0o * o0oOOo0O0Ooo + Oo0Ooo * OoOoOO00 * o0oOOo0O0Ooo
  return ( o00Oo0oOO0 )
  if 33 - 33: I1IiiI + O0 - I11i
  if 90 - 90: I1Ii111 * OoooooooOO . iIii1I11I1II1 % OoO0O00 / I11i + iII111i
 def copy_rloc_records ( self ) :
  OOoOoo0OO = [ ]
  for IiIiI in self . registered_rlocs :
   OOoOoo0OO . append ( copy . deepcopy ( IiIiI ) )
   if 85 - 85: I1Ii111 - Oo0Ooo / I11i + OoOoOO00 . O0 - Oo0Ooo
  return ( OOoOoo0OO )
  if 24 - 24: I1IiiI + i1IIi
  if 21 - 21: iII111i / o0oOOo0O0Ooo
 def merge_rlocs_in_site_eid ( self ) :
  self . registered_rlocs = [ ]
  for O0OO in self . individual_registrations . values ( ) :
   if ( self . site_id != O0OO . site_id ) : continue
   if ( O0OO . registered == False ) : continue
   self . registered_rlocs += O0OO . copy_rloc_records ( )
   if 61 - 61: iII111i . I1Ii111 % OoooooooOO / I1Ii111
   if 8 - 8: OoOoOO00
   if 80 - 80: IiII + I1ii11iIi11i + ooOoO0o
   if 48 - 48: O0 / I1IiiI % II111iiii
   if 10 - 10: Ii1I / I1Ii111 / O0 - II111iiii % IiII - ooOoO0o
   if 48 - 48: OOooOOo * OoOoOO00 / oO0o + II111iiii - I1ii11iIi11i
  OOoOoo0OO = [ ]
  for IiIiI in self . registered_rlocs :
   if ( IiIiI . rloc . is_null ( ) or len ( OOoOoo0OO ) == 0 ) :
    OOoOoo0OO . append ( IiIiI )
    continue
    if 85 - 85: I1ii11iIi11i * OoooooooOO . OOooOOo * OOooOOo
   for IiI1i in OOoOoo0OO :
    if ( IiI1i . rloc . is_null ( ) ) : continue
    if ( IiIiI . rloc . is_exact_match ( IiI1i . rloc ) ) : break
    if 47 - 47: IiII / o0oOOo0O0Ooo - IiII . I11i - I1Ii111 * o0oOOo0O0Ooo
   if ( IiI1i == OOoOoo0OO [ - 1 ] ) : OOoOoo0OO . append ( IiIiI )
   if 75 - 75: OoO0O00 / II111iiii - I1Ii111
  self . registered_rlocs = OOoOoo0OO
  if 95 - 95: OOooOOo / OoOoOO00 + I1ii11iIi11i
  if 86 - 86: O0 / Ii1I . OoooooooOO . O0
  if 87 - 87: Ii1I + o0oOOo0O0Ooo + OoooooooOO . Ii1I
  if 73 - 73: o0oOOo0O0Ooo + OoooooooOO - I1Ii111 . iIii1I11I1II1
  if ( len ( self . registered_rlocs ) == 0 ) : self . registered = False
  return
  if 25 - 25: OoooooooOO % I1ii11iIi11i % Oo0Ooo % i11iIiiIii
  if 8 - 8: O0 - O0 % Ii1I
 def merge_rles_in_site_eid ( self ) :
  if 22 - 22: OoOoOO00
  if 85 - 85: II111iiii - II111iiii
  if 95 - 95: II111iiii + II111iiii + iII111i
  if 38 - 38: OoO0O00 * Ii1I * O0 / I1IiiI
  OOO0OOO = { }
  for IiIiI in self . registered_rlocs :
   if ( IiIiI . rle == None ) : continue
   for O00o000O0O0oO in IiIiI . rle . rle_nodes :
    oOo00Ooo0o0 = O00o000O0O0oO . address . print_address_no_iid ( )
    OOO0OOO [ oOo00Ooo0o0 ] = O00o000O0O0oO . address
    if 94 - 94: I1IiiI % O0 % Ii1I + OoooooooOO + OoO0O00 % IiII
   break
   if 49 - 49: I1Ii111
   if 92 - 92: ooOoO0o
   if 82 - 82: ooOoO0o
   if 80 - 80: I1Ii111 / I11i - Oo0Ooo / IiII % O0
   if 67 - 67: i11iIiiIii / I11i - iII111i - OOooOOo . II111iiii
  self . merge_rlocs_in_site_eid ( )
  if 16 - 16: Ii1I * iIii1I11I1II1 + i11iIiiIii - OoOoOO00 - o0oOOo0O0Ooo
  if 60 - 60: O0 - iIii1I11I1II1
  if 56 - 56: OOooOOo * o0oOOo0O0Ooo - O0
  if 45 - 45: OOooOOo - OoO0O00
  if 49 - 49: OoOoOO00 / o0oOOo0O0Ooo % OoO0O00
  if 50 - 50: iIii1I11I1II1 - OoooooooOO + I1ii11iIi11i / Oo0Ooo * OOooOOo
  if 37 - 37: O0 % I1Ii111 * OOooOOo / OOooOOo
  if 95 - 95: I1ii11iIi11i % o0oOOo0O0Ooo . oO0o
  II1Ii1Ii1II = [ ]
  for IiIiI in self . registered_rlocs :
   if ( self . registered_rlocs . index ( IiIiI ) == 0 ) :
    II1Ii1Ii1II . append ( IiIiI )
    continue
    if 42 - 42: OOooOOo - I1IiiI + i11iIiiIii
   if ( IiIiI . rle == None ) : II1Ii1Ii1II . append ( IiIiI )
   if 20 - 20: Ii1I * OoooooooOO / OoooooooOO + OOooOOo - I1IiiI - O0
  self . registered_rlocs = II1Ii1Ii1II
  if 22 - 22: iII111i - i11iIiiIii + ooOoO0o + oO0o + II111iiii / oO0o
  if 7 - 7: iII111i % o0oOOo0O0Ooo
  if 68 - 68: iIii1I11I1II1 / II111iiii
  if 47 - 47: i11iIiiIii . OOooOOo + I1Ii111 / I1ii11iIi11i . I1IiiI . I1Ii111
  if 79 - 79: OoO0O00 / i11iIiiIii . IiII - I11i / iIii1I11I1II1
  if 81 - 81: Oo0Ooo . II111iiii + i11iIiiIii - OoOoOO00 * ooOoO0o
  if 25 - 25: Ii1I / Oo0Ooo
  o0o0ooOo00 = lisp_rle ( "" )
  OOoOoooO0oOO = { }
  ooOO0OOO = None
  for O0OO in self . individual_registrations . values ( ) :
   if ( O0OO . registered == False ) : continue
   iIiIi11 = O0OO . registered_rlocs [ 0 ] . rle
   if ( iIiIi11 == None ) : continue
   if 22 - 22: I1Ii111 - Ii1I . i11iIiiIii + o0oOOo0O0Ooo % o0oOOo0O0Ooo
   ooOO0OOO = O0OO . registered_rlocs [ 0 ] . rloc_name
   for OO0O00Oo in iIiIi11 . rle_nodes :
    oOo00Ooo0o0 = OO0O00Oo . address . print_address_no_iid ( )
    if ( OOoOoooO0oOO . has_key ( oOo00Ooo0o0 ) ) : break
    if 7 - 7: I1IiiI * II111iiii / i11iIiiIii / oO0o * i1IIi
    O00o000O0O0oO = lisp_rle_node ( )
    O00o000O0O0oO . address . copy_address ( OO0O00Oo . address )
    O00o000O0O0oO . level = OO0O00Oo . level
    O00o000O0O0oO . rloc_name = ooOO0OOO
    o0o0ooOo00 . rle_nodes . append ( O00o000O0O0oO )
    OOoOoooO0oOO [ oOo00Ooo0o0 ] = OO0O00Oo . address
    if 15 - 15: i1IIi
    if 41 - 41: i11iIiiIii / ooOoO0o - Ii1I + I11i
    if 15 - 15: I1ii11iIi11i
    if 22 - 22: iIii1I11I1II1 - i1IIi - i11iIiiIii / I1IiiI + o0oOOo0O0Ooo
    if 56 - 56: I1IiiI . ooOoO0o
    if 35 - 35: iIii1I11I1II1 % Oo0Ooo + o0oOOo0O0Ooo * o0oOOo0O0Ooo % ooOoO0o
  if ( len ( o0o0ooOo00 . rle_nodes ) == 0 ) : o0o0ooOo00 = None
  if ( len ( self . registered_rlocs ) != 0 ) :
   self . registered_rlocs [ 0 ] . rle = o0o0ooOo00
   if ( ooOO0OOO ) : self . registered_rlocs [ 0 ] . rloc_name = None
   if 10 - 10: I1ii11iIi11i / II111iiii % II111iiii - OoooooooOO * o0oOOo0O0Ooo / ooOoO0o
   if 26 - 26: OoO0O00 . O0 * iII111i % OoOoOO00 % iIii1I11I1II1
   if 37 - 37: iII111i - ooOoO0o * Ii1I + II111iiii * i11iIiiIii
   if 8 - 8: OoooooooOO % I11i - iII111i * OOooOOo . O0
   if 40 - 40: I1Ii111 . oO0o + OoO0O00 % Oo0Ooo / II111iiii
  if ( OOO0OOO . keys ( ) == OOoOoooO0oOO . keys ( ) ) : return ( False )
  if 19 - 19: i11iIiiIii
  lprint ( "{} {} from {} to {}" . format ( green ( self . print_eid_tuple ( ) , False ) , bold ( "RLE change" , False ) ,
  # O0 % i11iIiiIii
 OOO0OOO . keys ( ) , OOoOoooO0oOO . keys ( ) ) )
  if 60 - 60: I1ii11iIi11i / I11i
  return ( True )
  if 100 - 100: I1IiiI
  if 44 - 44: iIii1I11I1II1 + Oo0Ooo - I1Ii111 . OoooooooOO
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
    if 28 - 28: Ii1I + OOooOOo % IiII . i11iIiiIii - I1IiiI * Oo0Ooo
    if 2 - 2: I11i * I1ii11iIi11i + O0
    if 44 - 44: iIii1I11I1II1 / II111iiii - ooOoO0o
    if 10 - 10: OOooOOo
    if 78 - 78: OOooOOo * I1ii11iIi11i % i11iIiiIii % o0oOOo0O0Ooo . I1ii11iIi11i / OoooooooOO
    OoOo0OOoOOO00 . parent_for_more_specifics = self . parent_for_more_specifics
    if 12 - 12: iIii1I11I1II1 % OoO0O00 + OOooOOo * iIii1I11I1II1 - iIii1I11I1II1
   if ( self . eid . is_null ( ) ) : self . eid . make_default_route ( OoOo0OOoOOO00 . group )
   OoOo0OOoOOO00 . add_source_entry ( self )
   if 70 - 70: OoO0O00 % i11iIiiIii * IiII . I11i * Oo0Ooo
   if 17 - 17: i1IIi
   if 29 - 29: OOooOOo % OoO0O00 + oO0o + o0oOOo0O0Ooo . iII111i
 def delete_cache ( self ) :
  if ( self . group . is_null ( ) ) :
   lisp_sites_by_eid . delete_cache ( self . eid )
  else :
   OoOo0OOoOOO00 = lisp_sites_by_eid . lookup_cache ( self . group , True )
   if ( OoOo0OOoOOO00 == None ) : return
   if 14 - 14: i1IIi + OoOoOO00 * oO0o - II111iiii + IiII + OoOoOO00
   O0OO = OoOo0OOoOOO00 . lookup_source_cache ( self . eid , True )
   if ( O0OO == None ) : return
   if 42 - 42: Oo0Ooo + iII111i * ooOoO0o
   if ( OoOo0OOoOOO00 . source_cache == None ) : return
   if 72 - 72: iIii1I11I1II1 % I1Ii111
   OoOo0OOoOOO00 . source_cache . delete_cache ( self . eid )
   if ( OoOo0OOoOOO00 . source_cache . cache_size ( ) == 0 ) :
    lisp_sites_by_eid . delete_cache ( self . group )
    if 77 - 77: I1Ii111 * I1IiiI / iIii1I11I1II1 . II111iiii * Oo0Ooo
    if 71 - 71: ooOoO0o / iIii1I11I1II1 % O0 / I1ii11iIi11i . I1Ii111 / i11iIiiIii
    if 6 - 6: oO0o . OoO0O00 - II111iiii . I1IiiI - o0oOOo0O0Ooo - i1IIi
    if 42 - 42: Ii1I + i11iIiiIii
 def add_source_entry ( self , source_se ) :
  if ( self . source_cache == None ) : self . source_cache = lisp_cache ( )
  self . source_cache . add_cache ( source_se . eid , source_se )
  if 46 - 46: O0 % OoOoOO00 - I1Ii111 . I1IiiI
  if 66 - 66: II111iiii * iIii1I11I1II1 * ooOoO0o * I11i . II111iiii - ooOoO0o
 def lookup_source_cache ( self , source , exact ) :
  if ( self . source_cache == None ) : return ( None )
  return ( self . source_cache . lookup_cache ( source , exact ) )
  if 15 - 15: I1ii11iIi11i - i11iIiiIii - Ii1I / Ii1I . iII111i
  if 36 - 36: oO0o + Oo0Ooo * I1Ii111 % OOooOOo . Oo0Ooo . I1IiiI
 def is_star_g ( self ) :
  if ( self . group . is_null ( ) ) : return ( False )
  return ( self . eid . is_exact_match ( self . group ) )
  if 81 - 81: o0oOOo0O0Ooo . OoOoOO00 . i11iIiiIii
  if 13 - 13: i1IIi
 def eid_record_matches ( self , eid_record ) :
  if ( self . eid . is_exact_match ( eid_record . eid ) == False ) : return ( False )
  if ( eid_record . group . is_null ( ) ) : return ( True )
  return ( eid_record . group . is_exact_match ( self . group ) )
  if 70 - 70: O0 / II111iiii
  if 98 - 98: OoOoOO00 - O0 . O0 + ooOoO0o * iIii1I11I1II1
 def inherit_from_ams_parent ( self ) :
  o0OoOOO = self . parent_for_more_specifics
  if ( o0OoOOO == None ) : return
  self . force_proxy_reply = o0OoOOO . force_proxy_reply
  self . force_nat_proxy_reply = o0OoOOO . force_nat_proxy_reply
  self . force_ttl = o0OoOOO . force_ttl
  self . pitr_proxy_reply_drop = o0OoOOO . pitr_proxy_reply_drop
  self . proxy_reply_action = o0OoOOO . proxy_reply_action
  self . echo_nonce_capable = o0OoOOO . echo_nonce_capable
  self . policy = o0OoOOO . policy
  self . require_signature = o0OoOOO . require_signature
  if 7 - 7: IiII * OoOoOO00 + iIii1I11I1II1 / OoOoOO00 + Oo0Ooo / o0oOOo0O0Ooo
  if 77 - 77: i1IIi . I1IiiI
 def rtrs_in_rloc_set ( self ) :
  for IiIiI in self . registered_rlocs :
   if ( IiIiI . is_rtr ( ) ) : return ( True )
   if 59 - 59: O0 + OoooooooOO - i1IIi
  return ( False )
  if 87 - 87: IiII * OoooooooOO / Oo0Ooo % iIii1I11I1II1 % oO0o
  if 97 - 97: ooOoO0o % i1IIi . IiII / Oo0Ooo . I1Ii111 . OoO0O00
 def is_rtr_in_rloc_set ( self , rtr_rloc ) :
  for IiIiI in self . registered_rlocs :
   if ( IiIiI . rloc . is_exact_match ( rtr_rloc ) == False ) : continue
   if ( IiIiI . is_rtr ( ) ) : return ( True )
   if 12 - 12: I1IiiI
  return ( False )
  if 99 - 99: II111iiii - OoOoOO00
  if 22 - 22: i11iIiiIii * II111iiii
 def is_rloc_in_rloc_set ( self , rloc ) :
  for IiIiI in self . registered_rlocs :
   if ( IiIiI . rle ) :
    for o0o0ooOo00 in IiIiI . rle . rle_nodes :
     if ( o0o0ooOo00 . address . is_exact_match ( rloc ) ) : return ( True )
     if 11 - 11: Oo0Ooo % i1IIi
     if 70 - 70: II111iiii * Oo0Ooo * OOooOOo - I1IiiI + iIii1I11I1II1 + ooOoO0o
   if ( IiIiI . rloc . is_exact_match ( rloc ) ) : return ( True )
   if 27 - 27: I1ii11iIi11i - I1Ii111 * O0 % ooOoO0o / I1IiiI
  return ( False )
  if 53 - 53: i11iIiiIii * i11iIiiIii % O0 % IiII
  if 57 - 57: I1IiiI % i1IIi * OoO0O00 + I1Ii111 . I11i % I11i
 def do_rloc_sets_match ( self , prev_rloc_set ) :
  if ( len ( self . registered_rlocs ) != len ( prev_rloc_set ) ) : return ( False )
  if 69 - 69: I1ii11iIi11i / OoOoOO00 + iIii1I11I1II1
  for IiIiI in prev_rloc_set :
   iIioO000 = IiIiI . rloc
   if ( self . is_rloc_in_rloc_set ( iIioO000 ) == False ) : return ( False )
   if 8 - 8: OoooooooOO
  return ( True )
  if 72 - 72: OoooooooOO % I1ii11iIi11i - OoO0O00 . OoooooooOO
  if 83 - 83: o0oOOo0O0Ooo * Ii1I - Oo0Ooo * iII111i - i11iIiiIii
  if 6 - 6: I1IiiI + i11iIiiIii + O0 / i1IIi
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
   if 50 - 50: iII111i . II111iiii % I1Ii111 % I1IiiI / o0oOOo0O0Ooo . I1IiiI
  self . last_used = 0
  self . last_reply = 0
  self . last_nonce = 0
  self . map_requests_sent = 0
  self . neg_map_replies_received = 0
  self . total_rtt = 0
  if 76 - 76: OOooOOo % iII111i
  if 80 - 80: iIii1I11I1II1 + o0oOOo0O0Ooo + iIii1I11I1II1
 def resolve_dns_name ( self ) :
  if ( self . dns_name == None ) : return
  if ( self . last_dns_resolve and
 time . time ( ) - self . last_dns_resolve < 30 ) : return
  if 63 - 63: OoOoOO00 - o0oOOo0O0Ooo % II111iiii - Ii1I
  try :
   IiiI11I1IIiI = socket . gethostbyname_ex ( self . dns_name )
   self . last_dns_resolve = lisp_get_timestamp ( )
   o00OO0OO0O = IiiI11I1IIiI [ 2 ]
  except :
   return
   if 19 - 19: I1IiiI - iII111i - oO0o / II111iiii
   if 98 - 98: IiII * OoOoOO00
   if 13 - 13: O0 + oO0o - iIii1I11I1II1 - Oo0Ooo % I1IiiI
   if 45 - 45: O0
   if 55 - 55: i11iIiiIii * Ii1I % OOooOOo + ooOoO0o - I1ii11iIi11i . Oo0Ooo
   if 48 - 48: o0oOOo0O0Ooo
  if ( len ( o00OO0OO0O ) <= self . a_record_index ) :
   self . delete_mr ( )
   return
   if 55 - 55: OOooOOo - OoooooooOO * iIii1I11I1II1 + iII111i % II111iiii
   if 33 - 33: I1Ii111 * oO0o * OoooooooOO + OOooOOo - I1IiiI + I1Ii111
  oOo00Ooo0o0 = o00OO0OO0O [ self . a_record_index ]
  if ( oOo00Ooo0o0 != self . map_resolver . print_address_no_iid ( ) ) :
   self . delete_mr ( )
   self . map_resolver . store_address ( oOo00Ooo0o0 )
   self . insert_mr ( )
   if 92 - 92: ooOoO0o * I11i % iIii1I11I1II1 + Ii1I - OoOoOO00
   if 31 - 31: OoooooooOO
   if 87 - 87: OoooooooOO - Ii1I . I11i / I1Ii111 . i1IIi
   if 86 - 86: i1IIi . oO0o % OOooOOo
   if 99 - 99: oO0o / I1Ii111 * oO0o * I11i
   if 38 - 38: o0oOOo0O0Ooo + OoOoOO00
  if ( lisp_is_decent_dns_suffix ( self . dns_name ) == False ) : return
  if ( self . a_record_index != 0 ) : return
  if 24 - 24: Ii1I - OOooOOo - o0oOOo0O0Ooo - I1Ii111 / OoooooooOO
  for oOo00Ooo0o0 in o00OO0OO0O [ 1 : : ] :
   i1 = lisp_address ( LISP_AFI_NONE , oOo00Ooo0o0 , 0 , 0 )
   OOO0o0o = lisp_get_map_resolver ( i1 , None )
   if ( OOO0o0o != None and OOO0o0o . a_record_index == o00OO0OO0O . index ( oOo00Ooo0o0 ) ) :
    continue
    if 17 - 17: OoO0O00
   OOO0o0o = lisp_mr ( oOo00Ooo0o0 , None , None )
   OOO0o0o . a_record_index = o00OO0OO0O . index ( oOo00Ooo0o0 )
   OOO0o0o . dns_name = self . dns_name
   OOO0o0o . last_dns_resolve = lisp_get_timestamp ( )
   if 79 - 79: Ii1I - II111iiii
   if 57 - 57: II111iiii / OoooooooOO
   if 4 - 4: I11i * OoOoOO00
   if 18 - 18: iIii1I11I1II1 % OOooOOo - I1ii11iIi11i * i1IIi + Oo0Ooo
   if 87 - 87: oO0o . I11i
  iII1I11II = [ ]
  for OOO0o0o in lisp_map_resolvers_list . values ( ) :
   if ( self . dns_name != OOO0o0o . dns_name ) : continue
   i1 = OOO0o0o . map_resolver . print_address_no_iid ( )
   if ( i1 in o00OO0OO0O ) : continue
   iII1I11II . append ( OOO0o0o )
   if 14 - 14: iIii1I11I1II1 - iIii1I11I1II1 * OOooOOo * iII111i - I1ii11iIi11i / Oo0Ooo
  for OOO0o0o in iII1I11II : OOO0o0o . delete_mr ( )
  if 50 - 50: oO0o . Oo0Ooo / o0oOOo0O0Ooo * O0 % Oo0Ooo
  if 52 - 52: I1IiiI % I1Ii111 - i1IIi . o0oOOo0O0Ooo % I1ii11iIi11i
 def insert_mr ( self ) :
  OOO0OOoOOO = self . mr_name + self . map_resolver . print_address ( )
  lisp_map_resolvers_list [ OOO0OOoOOO ] = self
  if 34 - 34: o0oOOo0O0Ooo / OoOoOO00
  if 74 - 74: IiII + i1IIi . II111iiii
 def delete_mr ( self ) :
  OOO0OOoOOO = self . mr_name + self . map_resolver . print_address ( )
  if ( lisp_map_resolvers_list . has_key ( OOO0OOoOOO ) == False ) : return
  lisp_map_resolvers_list . pop ( OOO0OOoOOO )
  if 1 - 1: Ii1I - o0oOOo0O0Ooo / i11iIiiIii
  if 24 - 24: O0
  if 59 - 59: OoO0O00 % iII111i + oO0o * II111iiii . OOooOOo
class lisp_ddt_root ( ) :
 def __init__ ( self ) :
  self . root_address = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . public_key = ""
  self . priority = 0
  self . weight = 0
  if 26 - 26: OOooOOo % OoooooooOO . Ii1I / iIii1I11I1II1 * I1IiiI
  if 85 - 85: IiII / Ii1I - I1ii11iIi11i * OOooOOo
  if 19 - 19: I1ii11iIi11i
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
  if 12 - 12: ooOoO0o * I1ii11iIi11i * O0 / oO0o + iII111i - iIii1I11I1II1
  if 81 - 81: Ii1I
 def print_referral ( self , eid_indent , referral_indent ) :
  oo0Oo0Oo0o0 = lisp_print_elapsed ( self . uptime )
  oOOo0O0 = lisp_print_future ( self . expires )
  lprint ( "{}Referral EID {}, uptime/expires {}/{}, {} referrals:" . format ( eid_indent , green ( self . eid . print_prefix ( ) , False ) , oo0Oo0Oo0o0 ,
  # OoO0O00 . O0 . OoooooooOO - i11iIiiIii % OOooOOo
 oOOo0O0 , len ( self . referral_set ) ) )
  if 10 - 10: OoOoOO00 / i11iIiiIii
  for ii1I111ii in self . referral_set . values ( ) :
   ii1I111ii . print_ref_node ( referral_indent )
   if 21 - 21: Ii1I - i1IIi / I11i + IiII
   if 44 - 44: OoooooooOO % I11i / O0
   if 94 - 94: IiII
 def print_referral_type ( self ) :
  if ( self . eid . afi == LISP_AFI_ULTIMATE_ROOT ) : return ( "root" )
  if ( self . referral_type == LISP_DDT_ACTION_NULL ) :
   return ( "null-referral" )
   if 83 - 83: OoO0O00
  if ( self . referral_type == LISP_DDT_ACTION_SITE_NOT_FOUND ) :
   return ( "no-site-action" )
   if 55 - 55: iII111i
  if ( self . referral_type > LISP_DDT_ACTION_MAX ) :
   return ( "invalid-action" )
   if 37 - 37: oO0o / o0oOOo0O0Ooo + I11i * OoO0O00 * o0oOOo0O0Ooo
  return ( lisp_map_referral_action_string [ self . referral_type ] )
  if 33 - 33: I1Ii111
  if 97 - 97: Ii1I / iII111i - ooOoO0o + IiII * OoOoOO00 - OOooOOo
 def print_eid_tuple ( self ) :
  return ( lisp_print_eid_tuple ( self . eid , self . group ) )
  if 43 - 43: oO0o / II111iiii - iII111i / oO0o
  if 98 - 98: OoOoOO00 / OOooOOo
 def print_ttl ( self ) :
  I1i = self . referral_ttl
  if ( I1i < 60 ) : return ( str ( I1i ) + " secs" )
  if 31 - 31: II111iiii % I11i - I11i
  if ( ( I1i % 60 ) == 0 ) :
   I1i = str ( I1i / 60 ) + " mins"
  else :
   I1i = str ( I1i ) + " secs"
   if 17 - 17: iII111i . IiII + OOooOOo % I1Ii111 % i11iIiiIii
  return ( I1i )
  if 100 - 100: i11iIiiIii - O0 . OoO0O00 / O0 - Ii1I - IiII
  if 72 - 72: Ii1I % O0 + II111iiii . i11iIiiIii
 def is_referral_negative ( self ) :
  return ( self . referral_type in ( LISP_DDT_ACTION_MS_NOT_REG , LISP_DDT_ACTION_DELEGATION_HOLE ,
  # OOooOOo / I1IiiI / Ii1I * iII111i
 LISP_DDT_ACTION_NOT_AUTH ) )
  if 14 - 14: ooOoO0o . O0 * OOooOOo
  if 34 - 34: I1ii11iIi11i . OOooOOo + OoO0O00 % o0oOOo0O0Ooo * O0 * I1IiiI
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
    if 9 - 9: IiII / i11iIiiIii . o0oOOo0O0Ooo - OOooOOo % I1Ii111
   if ( self . eid . is_null ( ) ) : self . eid . make_default_route ( I11i1i . group )
   I11i1i . add_source_entry ( self )
   if 65 - 65: I1IiiI % OoOoOO00
   if 45 - 45: o0oOOo0O0Ooo
   if 33 - 33: ooOoO0o % O0 % I1ii11iIi11i % o0oOOo0O0Ooo + i11iIiiIii . I1Ii111
 def delete_cache ( self ) :
  if ( self . group . is_null ( ) ) :
   lisp_referral_cache . delete_cache ( self . eid )
  else :
   I11i1i = lisp_referral_cache . lookup_cache ( self . group , True )
   if ( I11i1i == None ) : return
   if 21 - 21: I1Ii111 * I1ii11iIi11i * ooOoO0o
   iI111ii1Ii1I = I11i1i . lookup_source_cache ( self . eid , True )
   if ( iI111ii1Ii1I == None ) : return
   if 73 - 73: OoOoOO00 * O0
   I11i1i . source_cache . delete_cache ( self . eid )
   if ( I11i1i . source_cache . cache_size ( ) == 0 ) :
    lisp_referral_cache . delete_cache ( self . group )
    if 1 - 1: OOooOOo * OoooooooOO
    if 46 - 46: I1ii11iIi11i * I1Ii111 / OOooOOo / I1IiiI
    if 7 - 7: OOooOOo / OoOoOO00
    if 93 - 93: iIii1I11I1II1 * Ii1I - iII111i
 def add_source_entry ( self , source_ref ) :
  if ( self . source_cache == None ) : self . source_cache = lisp_cache ( )
  self . source_cache . add_cache ( source_ref . eid , source_ref )
  if 94 - 94: iIii1I11I1II1 * iIii1I11I1II1 * I11i % i11iIiiIii
  if 38 - 38: I1IiiI % I1ii11iIi11i * I1IiiI + OOooOOo - OoOoOO00
 def lookup_source_cache ( self , source , exact ) :
  if ( self . source_cache == None ) : return ( None )
  return ( self . source_cache . lookup_cache ( source , exact ) )
  if 78 - 78: OOooOOo + I1Ii111
  if 41 - 41: I11i + Oo0Ooo . Oo0Ooo / iII111i . OoOoOO00
  if 1 - 1: ooOoO0o + iII111i % i11iIiiIii / OoOoOO00
class lisp_referral_node ( ) :
 def __init__ ( self ) :
  self . referral_address = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . priority = 0
  self . weight = 0
  self . updown = True
  self . map_requests_sent = 0
  self . no_responses = 0
  self . uptime = lisp_get_timestamp ( )
  if 98 - 98: IiII
  if 75 - 75: OoooooooOO % IiII + Ii1I - i1IIi / OoooooooOO
 def print_ref_node ( self , indent ) :
  iiiI = lisp_print_elapsed ( self . uptime )
  lprint ( "{}referral {}, uptime {}, {}, priority/weight: {}/{}" . format ( indent , red ( self . referral_address . print_address ( ) , False ) , iiiI ,
  # iII111i . o0oOOo0O0Ooo / II111iiii % Oo0Ooo
 "up" if self . updown else "down" , self . priority , self . weight ) )
  if 1 - 1: OOooOOo % o0oOOo0O0Ooo * o0oOOo0O0Ooo / oO0o
  if 79 - 79: oO0o . OOooOOo
  if 82 - 82: I1Ii111 % II111iiii
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
   if 10 - 10: II111iiii * Ii1I % IiII + I11i
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
   if 29 - 29: IiII / Ii1I / I1Ii111
   if 30 - 30: i1IIi + OOooOOo + Oo0Ooo % iII111i % O0 + i1IIi
   if 45 - 45: ooOoO0o
 def resolve_dns_name ( self ) :
  if ( self . dns_name == None ) : return
  if ( self . last_dns_resolve and
 time . time ( ) - self . last_dns_resolve < 30 ) : return
  if 89 - 89: iIii1I11I1II1 . I1Ii111
  try :
   IiiI11I1IIiI = socket . gethostbyname_ex ( self . dns_name )
   self . last_dns_resolve = lisp_get_timestamp ( )
   o00OO0OO0O = IiiI11I1IIiI [ 2 ]
  except :
   return
   if 43 - 43: Oo0Ooo + o0oOOo0O0Ooo % o0oOOo0O0Ooo % I1ii11iIi11i / iIii1I11I1II1 . I1ii11iIi11i
   if 59 - 59: IiII . OoO0O00 - OoooooooOO . O0
   if 33 - 33: Ii1I
   if 95 - 95: OoooooooOO + OoO0O00 * ooOoO0o
   if 40 - 40: I1IiiI / OOooOOo * Ii1I
   if 98 - 98: I1IiiI
  if ( len ( o00OO0OO0O ) <= self . a_record_index ) :
   self . delete_ms ( )
   return
   if 4 - 4: I1IiiI % O0 / Oo0Ooo / O0
   if 90 - 90: ooOoO0o - O0 . IiII - O0 . iIii1I11I1II1
  oOo00Ooo0o0 = o00OO0OO0O [ self . a_record_index ]
  if ( oOo00Ooo0o0 != self . map_server . print_address_no_iid ( ) ) :
   self . delete_ms ( )
   self . map_server . store_address ( oOo00Ooo0o0 )
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
  for oOo00Ooo0o0 in o00OO0OO0O [ 1 : : ] :
   i1 = lisp_address ( LISP_AFI_NONE , oOo00Ooo0o0 , 0 , 0 )
   oOooOO = lisp_get_map_server ( i1 )
   if ( oOooOO != None and oOooOO . a_record_index == o00OO0OO0O . index ( oOo00Ooo0o0 ) ) :
    continue
    if 33 - 33: Ii1I * i11iIiiIii / O0 . Oo0Ooo + i1IIi . OoOoOO00
   oOooOO = copy . deepcopy ( self )
   oOooOO . map_server . store_address ( oOo00Ooo0o0 )
   oOooOO . a_record_index = o00OO0OO0O . index ( oOo00Ooo0o0 )
   oOooOO . last_dns_resolve = lisp_get_timestamp ( )
   oOooOO . insert_ms ( )
   if 76 - 76: OoooooooOO - O0
   if 17 - 17: Oo0Ooo % I1Ii111 . oO0o - O0
   if 32 - 32: O0 % O0
   if 66 - 66: iII111i / i1IIi - Oo0Ooo . Ii1I
   if 65 - 65: I1ii11iIi11i % ooOoO0o - OoOoOO00 + ooOoO0o + Oo0Ooo
  iII1I11II = [ ]
  for oOooOO in lisp_map_servers_list . values ( ) :
   if ( self . dns_name != oOooOO . dns_name ) : continue
   i1 = oOooOO . map_server . print_address_no_iid ( )
   if ( i1 in o00OO0OO0O ) : continue
   iII1I11II . append ( oOooOO )
   if 95 - 95: I1Ii111 * i11iIiiIii - I1IiiI - OoOoOO00 . ooOoO0o
  for oOooOO in iII1I11II : oOooOO . delete_ms ( )
  if 34 - 34: OoooooooOO % I1ii11iIi11i + OoooooooOO % i11iIiiIii / IiII - ooOoO0o
  if 74 - 74: iIii1I11I1II1 % II111iiii + IiII
 def insert_ms ( self ) :
  OOO0OOoOOO = self . ms_name + self . map_server . print_address ( )
  lisp_map_servers_list [ OOO0OOoOOO ] = self
  if 71 - 71: I1IiiI / O0 * i1IIi . i1IIi + Oo0Ooo
  if 32 - 32: i1IIi * I1Ii111 % I1IiiI / IiII . I1Ii111
 def delete_ms ( self ) :
  OOO0OOoOOO = self . ms_name + self . map_server . print_address ( )
  if ( lisp_map_servers_list . has_key ( OOO0OOoOOO ) == False ) : return
  lisp_map_servers_list . pop ( OOO0OOoOOO )
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
  oOOOOOOOoO = socket . socket ( socket . AF_INET , socket . SOCK_RAW , socket . IPPROTO_RAW )
  oOOOOOOOoO . setsockopt ( socket . SOL_IP , socket . IP_HDRINCL , 1 )
  try :
   oOOOOOOOoO . setsockopt ( socket . SOL_SOCKET , socket . SO_BINDTODEVICE , device )
  except :
   oOOOOOOOoO . close ( )
   oOOOOOOOoO = None
   if 39 - 39: iII111i % OoooooooOO % Ii1I % I1IiiI
  self . raw_socket = oOOOOOOOoO
  if 63 - 63: OoO0O00 - I1Ii111 - II111iiii
  if 79 - 79: II111iiii - II111iiii + OoOoOO00 / iII111i % OoooooooOO - OoO0O00
 def set_bridge_socket ( self , device ) :
  oOOOOOOOoO = socket . socket ( socket . PF_PACKET , socket . SOCK_RAW )
  try :
   oOOOOOOOoO = oOOOOOOOoO . bind ( ( device , 0 ) )
   self . bridge_socket = oOOOOOOOoO
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
  o0O0O0OO0 , III1 , i1ii1I1 , time = o0O0OOo0O [ 0 : 4 ] , o0O0OOo0O [ 5 : 7 ] , o0O0OOo0O [ 8 : 10 ] , o0O0OOo0O [ 11 : : ]
  if 6 - 6: iIii1I11I1II1 % iII111i * i1IIi
  if ( ( o0O0O0OO0 + III1 + i1ii1I1 ) . isdigit ( ) == False ) : return ( False )
  if ( III1 < "01" and III1 > "12" ) : return ( False )
  if ( i1ii1I1 < "01" and i1ii1I1 > "31" ) : return ( False )
  if 82 - 82: IiII / O0 / I11i % OoOoOO00 * I1Ii111 / OOooOOo
  I1ii11 , ii1I1iiI , O0OOOO0Ooo = time . split ( ":" )
  if 70 - 70: OoO0O00
  if ( ( I1ii11 + ii1I1iiI + O0OOOO0Ooo ) . isdigit ( ) == False ) : return ( False )
  if ( I1ii11 < "00" and I1ii11 > "23" ) : return ( False )
  if ( ii1I1iiI < "00" and ii1I1iiI > "59" ) : return ( False )
  if ( O0OOOO0Ooo < "00" and O0OOOO0Ooo > "59" ) : return ( False )
  return ( True )
  if 88 - 88: i1IIi . I1IiiI
  if 8 - 8: I1ii11iIi11i . OoO0O00 % o0oOOo0O0Ooo / O0
 def parse_datetime ( self ) :
  OO00000 = self . datetime_name
  OO00000 = OO00000 . replace ( "-" , "" )
  OO00000 = OO00000 . replace ( ":" , "" )
  self . datetime = int ( OO00000 )
  if 59 - 59: I1ii11iIi11i % OoO0O00 . i1IIi / I1ii11iIi11i
  if 44 - 44: o0oOOo0O0Ooo % o0oOOo0O0Ooo % oO0o
 def now ( self ) :
  iiiI = datetime . datetime . now ( ) . strftime ( "%Y-%m-%d-%H:%M:%S" )
  iiiI = lisp_datetime ( iiiI )
  return ( iiiI )
  if 76 - 76: ooOoO0o / iII111i
  if 29 - 29: OOooOOo / OoooooooOO % II111iiii
 def print_datetime ( self ) :
  return ( self . datetime_name )
  if 68 - 68: iIii1I11I1II1 * iII111i % o0oOOo0O0Ooo
  if 45 - 45: OoooooooOO
 def future ( self ) :
  return ( self . datetime > self . now ( ) . datetime )
  if 45 - 45: iIii1I11I1II1
  if 11 - 11: Ii1I * OoO0O00 % I1ii11iIi11i
 def past ( self ) :
  return ( self . future ( ) == False )
  if 60 - 60: i11iIiiIii % II111iiii % I11i
  if 92 - 92: O0 * OoooooooOO + I1ii11iIi11i / IiII
 def now_in_range ( self , upper ) :
  return ( self . past ( ) and upper . future ( ) )
  if 97 - 97: o0oOOo0O0Ooo . Ii1I + I1Ii111
  if 72 - 72: i11iIiiIii . iII111i . Ii1I * I1ii11iIi11i
 def this_year ( self ) :
  II1iI111 = str ( self . now ( ) . datetime ) [ 0 : 4 ]
  iiiI = str ( self . datetime ) [ 0 : 4 ]
  return ( iiiI == II1iI111 )
  if 69 - 69: I1ii11iIi11i % I1Ii111 / OoooooooOO % oO0o
  if 4 - 4: OoOoOO00 * i11iIiiIii - OoOoOO00 * o0oOOo0O0Ooo % I1ii11iIi11i
 def this_month ( self ) :
  II1iI111 = str ( self . now ( ) . datetime ) [ 0 : 6 ]
  iiiI = str ( self . datetime ) [ 0 : 6 ]
  return ( iiiI == II1iI111 )
  if 19 - 19: OOooOOo
  if 73 - 73: ooOoO0o / O0 / I1Ii111 . OoooooooOO
 def today ( self ) :
  II1iI111 = str ( self . now ( ) . datetime ) [ 0 : 8 ]
  iiiI = str ( self . datetime ) [ 0 : 8 ]
  return ( iiiI == II1iI111 )
  if 88 - 88: OoooooooOO - oO0o
  if 80 - 80: ooOoO0o
  if 38 - 38: IiII + OoO0O00 * I11i * iIii1I11I1II1 * oO0o
  if 74 - 74: I1IiiI
  if 39 - 39: iII111i * IiII / iII111i * IiII % I1ii11iIi11i
  if 27 - 27: iIii1I11I1II1 . ooOoO0o
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
  if 74 - 74: i1IIi % OoOoOO00
  if 98 - 98: IiII * OOooOOo / O0 - I1Ii111 . I1Ii111 + OOooOOo
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
  if 61 - 61: iII111i * Ii1I % Ii1I + I1IiiI
  if 23 - 23: oO0o + I1Ii111 / OoooooooOO / O0 + IiII
 def match_policy_map_request ( self , mr , srloc ) :
  for ooo0oO0oo0o in self . match_clauses :
   IiIiI1 = ooo0oO0oo0o . source_eid
   Oo0o0O0OO0 = mr . source_eid
   if ( IiIiI1 and Oo0o0O0OO0 and Oo0o0O0OO0 . is_more_specific ( IiIiI1 ) == False ) : continue
   if 80 - 80: i11iIiiIii - OoooooooOO + II111iiii / i1IIi - oO0o
   IiIiI1 = ooo0oO0oo0o . dest_eid
   Oo0o0O0OO0 = mr . target_eid
   if ( IiIiI1 and Oo0o0O0OO0 and Oo0o0O0OO0 . is_more_specific ( IiIiI1 ) == False ) : continue
   if 100 - 100: Ii1I
   IiIiI1 = ooo0oO0oo0o . source_rloc
   Oo0o0O0OO0 = srloc
   if ( IiIiI1 and Oo0o0O0OO0 and Oo0o0O0OO0 . is_more_specific ( IiIiI1 ) == False ) : continue
   oooo0 = ooo0oO0oo0o . datetime_lower
   o0oOo0o0 = ooo0oO0oo0o . datetime_upper
   if ( oooo0 and o0oOo0o0 and oooo0 . now_in_range ( o0oOo0o0 ) == False ) : continue
   return ( True )
   if 58 - 58: Oo0Ooo * Oo0Ooo
  return ( False )
  if 44 - 44: ooOoO0o / i11iIiiIii % o0oOOo0O0Ooo % OOooOOo
  if 81 - 81: I11i % iIii1I11I1II1
 def set_policy_map_reply ( self ) :
  iIiooo = ( self . set_rloc_address == None and
 self . set_rloc_record_name == None and self . set_geo_name == None and
 self . set_elp_name == None and self . set_rle_name == None )
  if ( iIiooo ) : return ( None )
  if 81 - 81: O0 / ooOoO0o * iIii1I11I1II1 . iIii1I11I1II1 / IiII % I11i
  II11IIiii = lisp_rloc ( )
  if ( self . set_rloc_address ) :
   II11IIiii . rloc . copy_address ( self . set_rloc_address )
   oOo00Ooo0o0 = II11IIiii . rloc . print_address_no_iid ( )
   lprint ( "Policy set-rloc-address to {}" . format ( oOo00Ooo0o0 ) )
   if 58 - 58: i11iIiiIii
  if ( self . set_rloc_record_name ) :
   II11IIiii . rloc_name = self . set_rloc_record_name
   I1i1iI1II = blue ( II11IIiii . rloc_name , False )
   lprint ( "Policy set-rloc-record-name to {}" . format ( I1i1iI1II ) )
   if 25 - 25: I11i % Ii1I
  if ( self . set_geo_name ) :
   II11IIiii . geo_name = self . set_geo_name
   I1i1iI1II = II11IIiii . geo_name
   Ii1i1Ii1I = "" if lisp_geo_list . has_key ( I1i1iI1II ) else "(not configured)"
   if 32 - 32: II111iiii . I1Ii111
   lprint ( "Policy set-geo-name '{}' {}" . format ( I1i1iI1II , Ii1i1Ii1I ) )
   if 62 - 62: OOooOOo . iII111i . I1ii11iIi11i
  if ( self . set_elp_name ) :
   II11IIiii . elp_name = self . set_elp_name
   I1i1iI1II = II11IIiii . elp_name
   Ii1i1Ii1I = "" if lisp_elp_list . has_key ( I1i1iI1II ) else "(not configured)"
   if 23 - 23: O0
   lprint ( "Policy set-elp-name '{}' {}" . format ( I1i1iI1II , Ii1i1Ii1I ) )
   if 33 - 33: ooOoO0o - iII111i % IiII
  if ( self . set_rle_name ) :
   II11IIiii . rle_name = self . set_rle_name
   I1i1iI1II = II11IIiii . rle_name
   Ii1i1Ii1I = "" if lisp_rle_list . has_key ( I1i1iI1II ) else "(not configured)"
   if 67 - 67: II111iiii
   lprint ( "Policy set-rle-name '{}' {}" . format ( I1i1iI1II , Ii1i1Ii1I ) )
   if 66 - 66: iIii1I11I1II1 / OOooOOo
  if ( self . set_json_name ) :
   II11IIiii . json_name = self . set_json_name
   I1i1iI1II = II11IIiii . json_name
   Ii1i1Ii1I = "" if lisp_json_list . has_key ( I1i1iI1II ) else "(not configured)"
   if 65 - 65: IiII . oO0o + O0 - i11iIiiIii + iIii1I11I1II1
   lprint ( "Policy set-json-name '{}' {}" . format ( I1i1iI1II , Ii1i1Ii1I ) )
   if 82 - 82: iIii1I11I1II1 * iII111i + iIii1I11I1II1 / OoO0O00 + O0
  return ( II11IIiii )
  if 67 - 67: I1Ii111
  if 94 - 94: I1Ii111 % iIii1I11I1II1 - II111iiii . ooOoO0o + i11iIiiIii - i11iIiiIii
 def save_policy ( self ) :
  lisp_policies [ self . policy_name ] = self
  if 55 - 55: OoooooooOO % iIii1I11I1II1 % I1ii11iIi11i % i1IIi
  if 46 - 46: I11i - ooOoO0o . I1IiiI
  if 36 - 36: I11i + OoO0O00 * O0 * OoOoOO00 * iII111i
class lisp_pubsub ( ) :
 def __init__ ( self , itr , port , nonce , ttl , xtr_id ) :
  self . itr = itr
  self . port = port
  self . nonce = nonce
  self . uptime = lisp_get_timestamp ( )
  self . ttl = ttl
  self . xtr_id = xtr_id
  self . map_notify_count = 0
  if 90 - 90: i11iIiiIii / i1IIi
  if 35 - 35: Ii1I . I11i / oO0o / OoOoOO00
 def add ( self , eid_prefix ) :
  I1i = self . ttl
  ii1Ii = eid_prefix . print_prefix ( )
  if ( lisp_pubsub_cache . has_key ( ii1Ii ) == False ) :
   lisp_pubsub_cache [ ii1Ii ] = { }
   if 5 - 5: I1ii11iIi11i . o0oOOo0O0Ooo * iII111i * I1ii11iIi11i % I1Ii111
  I1i1iiII1iI1i = lisp_pubsub_cache [ ii1Ii ]
  if 83 - 83: iIii1I11I1II1 * o0oOOo0O0Ooo % i11iIiiIii + OoO0O00 . O0
  Oo0o00oO = "Add"
  if ( I1i1iiII1iI1i . has_key ( self . xtr_id ) ) :
   Oo0o00oO = "Replace"
   del ( I1i1iiII1iI1i [ self . xtr_id ] )
   if 55 - 55: i11iIiiIii - I1IiiI . oO0o - OoooooooOO
  I1i1iiII1iI1i [ self . xtr_id ] = self
  if 44 - 44: I1Ii111
  ii1Ii = green ( ii1Ii , False )
  oo0Oo0oo = red ( self . itr . print_address_no_iid ( ) , False )
  iIi = "0x" + lisp_hex_string ( self . xtr_id )
  lprint ( "{} pubsub state {} for {}, xtr-id: {}, ttl {}" . format ( Oo0o00oO , ii1Ii ,
 oo0Oo0oo , iIi , I1i ) )
  if 98 - 98: I1IiiI % OOooOOo % iII111i
  if 15 - 15: OoO0O00
 def delete ( self , eid_prefix ) :
  ii1Ii = eid_prefix . print_prefix ( )
  oo0Oo0oo = red ( self . itr . print_address_no_iid ( ) , False )
  iIi = "0x" + lisp_hex_string ( self . xtr_id )
  if ( lisp_pubsub_cache . has_key ( ii1Ii ) ) :
   I1i1iiII1iI1i = lisp_pubsub_cache [ ii1Ii ]
   if ( I1i1iiII1iI1i . has_key ( self . xtr_id ) ) :
    I1i1iiII1iI1i . pop ( self . xtr_id )
    lprint ( "Remove pubsub state {} for {}, xtr-id: {}" . format ( ii1Ii ,
 oo0Oo0oo , iIi ) )
    if 52 - 52: II111iiii / ooOoO0o
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
class lisp_trace ( ) :
 def __init__ ( self ) :
  self . nonce = lisp_get_control_nonce ( )
  self . packet_json = [ ]
  self . local_rloc = None
  self . local_port = None
  self . lisp_socket = None
  if 95 - 95: ooOoO0o
  if 95 - 95: Ii1I + i1IIi . I1IiiI % I1Ii111 / Ii1I * O0
 def print_trace ( self ) :
  O0O0OOOOO = self . packet_json
  lprint ( "LISP-Trace JSON: '{}'" . format ( O0O0OOOOO ) )
  if 32 - 32: OoOoOO00 % i11iIiiIii
  if 53 - 53: I1Ii111 * Ii1I / IiII . i1IIi * II111iiii / o0oOOo0O0Ooo
 def encode ( self ) :
  Ii1i111iI = socket . htonl ( 0x90000000 )
  Ii11iIiiI = struct . pack ( "II" , Ii1i111iI , 0 )
  Ii11iIiiI += struct . pack ( "Q" , self . nonce )
  Ii11iIiiI += json . dumps ( self . packet_json )
  return ( Ii11iIiiI )
  if 44 - 44: I1Ii111 + ooOoO0o
  if 15 - 15: I11i + OoO0O00 + OoOoOO00
 def decode ( self , packet ) :
  III11i = "I"
  Oo0o0OOo0Oo0 = struct . calcsize ( III11i )
  if ( len ( packet ) < Oo0o0OOo0Oo0 ) : return ( False )
  Ii1i111iI = struct . unpack ( III11i , packet [ : Oo0o0OOo0Oo0 ] ) [ 0 ]
  packet = packet [ Oo0o0OOo0Oo0 : : ]
  Ii1i111iI = socket . ntohl ( Ii1i111iI )
  if ( ( Ii1i111iI & 0xff000000 ) != 0x90000000 ) : return ( False )
  if 100 - 100: I1Ii111
  if ( len ( packet ) < Oo0o0OOo0Oo0 ) : return ( False )
  oOo00Ooo0o0 = struct . unpack ( III11i , packet [ : Oo0o0OOo0Oo0 ] ) [ 0 ]
  packet = packet [ Oo0o0OOo0Oo0 : : ]
  if 78 - 78: OoOoOO00
  oOo00Ooo0o0 = socket . ntohl ( oOo00Ooo0o0 )
  I1II1I1III1 = oOo00Ooo0o0 >> 24
  oo0i1ii1Ii11i = ( oOo00Ooo0o0 >> 16 ) & 0xff
  OOO = ( oOo00Ooo0o0 >> 8 ) & 0xff
  iiI1Ii1I = oOo00Ooo0o0 & 0xff
  self . local_rloc = "{}.{}.{}.{}" . format ( I1II1I1III1 , oo0i1ii1Ii11i , OOO , iiI1Ii1I )
  self . local_port = str ( Ii1i111iI & 0xffff )
  if 91 - 91: o0oOOo0O0Ooo / I1ii11iIi11i . I1Ii111
  III11i = "Q"
  Oo0o0OOo0Oo0 = struct . calcsize ( III11i )
  if ( len ( packet ) < Oo0o0OOo0Oo0 ) : return ( False )
  self . nonce = struct . unpack ( III11i , packet [ : Oo0o0OOo0Oo0 ] ) [ 0 ]
  packet = packet [ Oo0o0OOo0Oo0 : : ]
  if ( len ( packet ) == 0 ) : return ( True )
  if 35 - 35: O0 - i1IIi - i11iIiiIii - ooOoO0o
  try :
   self . packet_json = json . loads ( packet )
  except :
   return ( False )
   if 23 - 23: Oo0Ooo . OoO0O00
  return ( True )
  if 49 - 49: oO0o % i11iIiiIii * Ii1I
  if 9 - 9: Oo0Ooo - OoO0O00 + ooOoO0o / o0oOOo0O0Ooo
 def myeid ( self , eid ) :
  return ( lisp_is_myeid ( eid ) )
  if 61 - 61: O0 - i11iIiiIii * o0oOOo0O0Ooo
  if 92 - 92: Oo0Ooo + OOooOOo - i11iIiiIii
 def return_to_sender ( self , lisp_socket , rts_rloc , packet ) :
  II11IIiii , IIIIiI1ii1 = self . rtr_cache_nat_trace_find ( rts_rloc )
  if ( II11IIiii == None ) :
   II11IIiii , IIIIiI1ii1 = rts_rloc . split ( ":" )
   IIIIiI1ii1 = int ( IIIIiI1ii1 )
   lprint ( "Send LISP-Trace to address {}:{}" . format ( II11IIiii , IIIIiI1ii1 ) )
  else :
   lprint ( "Send LISP-Trace to translated address {}:{}" . format ( II11IIiii ,
 IIIIiI1ii1 ) )
   if 26 - 26: O0 % Oo0Ooo + ooOoO0o - Ii1I . Oo0Ooo
   if 33 - 33: I1Ii111 / iII111i . I1Ii111 % II111iiii
  if ( lisp_socket == None ) :
   oOOOOOOOoO = socket . socket ( socket . AF_INET , socket . SOCK_DGRAM )
   oOOOOOOOoO . bind ( ( "0.0.0.0" , LISP_TRACE_PORT ) )
   oOOOOOOOoO . sendto ( packet , ( II11IIiii , IIIIiI1ii1 ) )
   oOOOOOOOoO . close ( )
  else :
   lisp_socket . sendto ( packet , ( II11IIiii , IIIIiI1ii1 ) )
   if 52 - 52: I1ii11iIi11i
   if 1 - 1: II111iiii + I1ii11iIi11i * OoOoOO00 % ooOoO0o - iII111i % OoooooooOO
   if 77 - 77: iII111i + o0oOOo0O0Ooo
 def packet_length ( self ) :
  IiI1iiI11 = 8 ; oo0000O0 = 4 + 4 + 8
  return ( IiI1iiI11 + oo0000O0 + len ( json . dumps ( self . packet_json ) ) )
  if 91 - 91: I1IiiI - I1Ii111 % O0 / I11i . Oo0Ooo / Ii1I
  if 71 - 71: o0oOOo0O0Ooo + Oo0Ooo % OoO0O00 - i11iIiiIii + iIii1I11I1II1
 def rtr_cache_nat_trace ( self , translated_rloc , translated_port ) :
  OOO0OOoOOO = self . local_rloc + ":" + self . local_port
  O000O = ( translated_rloc , translated_port )
  lisp_rtr_nat_trace_cache [ OOO0OOoOOO ] = O000O
  lprint ( "Cache NAT Trace addresses {} -> {}" . format ( OOO0OOoOOO , O000O ) )
  if 52 - 52: OoooooooOO
  if 44 - 44: O0 / OoooooooOO + ooOoO0o * I1ii11iIi11i
 def rtr_cache_nat_trace_find ( self , local_rloc_and_port ) :
  OOO0OOoOOO = local_rloc_and_port
  try : O000O = lisp_rtr_nat_trace_cache [ OOO0OOoOOO ]
  except : O000O = ( None , None )
  return ( O000O )
  if 36 - 36: I1ii11iIi11i / OoO0O00 - oO0o % O0
  if 12 - 12: i1IIi * ooOoO0o / oO0o + I1IiiI / OoooooooOO
  if 86 - 86: Oo0Ooo / OoO0O00
  if 78 - 78: I1IiiI * I1IiiI
  if 13 - 13: oO0o
  if 43 - 43: oO0o / Ii1I % OOooOOo
  if 45 - 45: II111iiii
  if 41 - 41: Ii1I / OOooOOo * Oo0Ooo . O0 - i11iIiiIii
  if 77 - 77: o0oOOo0O0Ooo + I1IiiI + I1Ii111 / I1ii11iIi11i * i1IIi
  if 37 - 37: O0 + iIii1I11I1II1 % IiII * oO0o
  if 43 - 43: OOooOOo . O0
def lisp_get_map_server ( address ) :
 for oOooOO in lisp_map_servers_list . values ( ) :
  if ( oOooOO . map_server . is_exact_match ( address ) ) : return ( oOooOO )
  if 76 - 76: OOooOOo * OoooooooOO / IiII . OoO0O00 + II111iiii
 return ( None )
 if 23 - 23: OoO0O00 - OoooooooOO * I11i . iIii1I11I1II1 / o0oOOo0O0Ooo + oO0o
 if 74 - 74: II111iiii / I1IiiI * O0 * OoO0O00 . I11i
 if 74 - 74: O0 . i1IIi / I1ii11iIi11i + o0oOOo0O0Ooo
 if 24 - 24: ooOoO0o % I1Ii111 + OoO0O00 * o0oOOo0O0Ooo % O0 - i11iIiiIii
 if 49 - 49: o0oOOo0O0Ooo / OoOoOO00 + iII111i
 if 85 - 85: I1IiiI - o0oOOo0O0Ooo
 if 86 - 86: II111iiii + Ii1I * Ii1I
def lisp_get_any_map_server ( ) :
 for oOooOO in lisp_map_servers_list . values ( ) : return ( oOooOO )
 return ( None )
 if 26 - 26: o0oOOo0O0Ooo + oO0o * i11iIiiIii / II111iiii
 if 86 - 86: Ii1I
 if 69 - 69: oO0o % o0oOOo0O0Ooo / o0oOOo0O0Ooo
 if 1 - 1: Ii1I
 if 43 - 43: o0oOOo0O0Ooo
 if 78 - 78: I1Ii111 % i1IIi * I11i
 if 59 - 59: OoOoOO00 % OoO0O00 % i11iIiiIii . II111iiii % I1ii11iIi11i + i1IIi
 if 99 - 99: I11i + IiII * I1Ii111 - OOooOOo - i1IIi
 if 77 - 77: I11i . IiII / OoO0O00 / I1Ii111
 if 8 - 8: o0oOOo0O0Ooo + iII111i / OoO0O00 * ooOoO0o - oO0o . iII111i
def lisp_get_map_resolver ( address , eid ) :
 if ( address != None ) :
  oOo00Ooo0o0 = address . print_address ( )
  OOO0o0o = None
  for OOO0OOoOOO in lisp_map_resolvers_list :
   if ( OOO0OOoOOO . find ( oOo00Ooo0o0 ) == - 1 ) : continue
   OOO0o0o = lisp_map_resolvers_list [ OOO0OOoOOO ]
   if 32 - 32: OoooooooOO . I1Ii111 - I1ii11iIi11i
  return ( OOO0o0o )
  if 29 - 29: OoO0O00
  if 33 - 33: I1ii11iIi11i - O0
  if 72 - 72: Oo0Ooo * iII111i - I11i
  if 81 - 81: I1Ii111
  if 85 - 85: O0 % OoOoOO00 . I1ii11iIi11i
  if 46 - 46: OOooOOo * iIii1I11I1II1
  if 33 - 33: OoO0O00 * II111iiii / i1IIi
 if ( eid == "" ) :
  o00OO0OoOOO = ""
 elif ( eid == None ) :
  o00OO0OoOOO = "all"
 else :
  i1i1iiiii1IiI = lisp_db_for_lookups . lookup_cache ( eid , False )
  o00OO0OoOOO = "all" if i1i1iiiii1IiI == None else i1i1iiiii1IiI . use_mr_name
  if 91 - 91: i1IIi % O0 . oO0o
  if 72 - 72: O0 - IiII
 I111i1iI = None
 for OOO0o0o in lisp_map_resolvers_list . values ( ) :
  if ( o00OO0OoOOO == "" ) : return ( OOO0o0o )
  if ( OOO0o0o . mr_name != o00OO0OoOOO ) : continue
  if ( I111i1iI == None or OOO0o0o . last_used < I111i1iI . last_used ) : I111i1iI = OOO0o0o
  if 52 - 52: OoO0O00 + iII111i . o0oOOo0O0Ooo * o0oOOo0O0Ooo - I1Ii111
 return ( I111i1iI )
 if 49 - 49: I1ii11iIi11i
 if 2 - 2: i1IIi
 if 61 - 61: OoO0O00
 if 100 - 100: OoOoOO00
 if 97 - 97: OoooooooOO
 if 91 - 91: o0oOOo0O0Ooo / O0 % OoO0O00
 if 35 - 35: iII111i % OoO0O00 * O0
 if 37 - 37: OOooOOo
def lisp_get_decent_map_resolver ( eid ) :
 Oo0oOooo000OO = lisp_get_decent_index ( eid )
 oOoo0OOOO0OO = str ( Oo0oOooo000OO ) + "." + lisp_decent_dns_suffix
 if 79 - 79: I11i
 lprint ( "Use LISP-Decent map-resolver {} for EID {}" . format ( bold ( oOoo0OOOO0OO , False ) , eid . print_prefix ( ) ) )
 if 7 - 7: i1IIi
 if 72 - 72: OOooOOo * iIii1I11I1II1 . iII111i - IiII % i1IIi
 I111i1iI = None
 for OOO0o0o in lisp_map_resolvers_list . values ( ) :
  if ( oOoo0OOOO0OO != OOO0o0o . dns_name ) : continue
  if ( I111i1iI == None or OOO0o0o . last_used < I111i1iI . last_used ) : I111i1iI = OOO0o0o
  if 67 - 67: I1ii11iIi11i - oO0o / I1IiiI + I1Ii111 * I1IiiI - I1Ii111
 return ( I111i1iI )
 if 30 - 30: Ii1I / I1Ii111 - OoOoOO00 / OOooOOo * I1IiiI + Ii1I
 if 41 - 41: ooOoO0o . i1IIi * iIii1I11I1II1 - I1IiiI
 if 9 - 9: I11i % i1IIi / ooOoO0o % iII111i - oO0o - II111iiii
 if 29 - 29: ooOoO0o . II111iiii . i1IIi % oO0o
 if 11 - 11: OoOoOO00 . OoO0O00 % I11i * iII111i % I1Ii111 . O0
 if 17 - 17: OOooOOo / i11iIiiIii - i11iIiiIii . II111iiii . ooOoO0o
 if 38 - 38: OOooOOo . OoooooooOO . II111iiii + OoO0O00 / oO0o . OoooooooOO
def lisp_ipv4_input ( packet ) :
 if 100 - 100: OoO0O00
 if 36 - 36: oO0o + Ii1I - O0
 if 19 - 19: O0 + I1Ii111 . I1Ii111 * IiII * ooOoO0o + i1IIi
 if 51 - 51: ooOoO0o % OoOoOO00 % i1IIi / O0
 if ( ord ( packet [ 9 ] ) == 2 ) : return ( [ True , packet ] )
 if 11 - 11: OOooOOo . I1ii11iIi11i * OOooOOo * OoO0O00
 if 11 - 11: I11i
 if 85 - 85: OoOoOO00 - Ii1I / Oo0Ooo % I1ii11iIi11i
 if 12 - 12: i1IIi + o0oOOo0O0Ooo / oO0o . O0
 OoO = struct . unpack ( "H" , packet [ 10 : 12 ] ) [ 0 ]
 if ( OoO == 0 ) :
  dprint ( "Packet arrived with checksum of 0!" )
 else :
  packet = lisp_ip_checksum ( packet )
  OoO = struct . unpack ( "H" , packet [ 10 : 12 ] ) [ 0 ]
  if ( OoO != 0 ) :
   dprint ( "IPv4 header checksum failed for inner header" )
   packet = lisp_format_packet ( packet [ 0 : 20 ] )
   dprint ( "Packet header: {}" . format ( packet ) )
   return ( [ False , None ] )
   if 37 - 37: IiII
   if 99 - 99: i11iIiiIii % i11iIiiIii . I11i * I1ii11iIi11i . OoO0O00 / I1IiiI
   if 44 - 44: iII111i - OoO0O00 / i11iIiiIii
   if 55 - 55: O0 * OoO0O00 * i1IIi
   if 9 - 9: IiII
   if 64 - 64: ooOoO0o + OoooooooOO
   if 99 - 99: iIii1I11I1II1 * II111iiii * i11iIiiIii
 I1i = struct . unpack ( "B" , packet [ 8 : 9 ] ) [ 0 ]
 if ( I1i == 0 ) :
  dprint ( "IPv4 packet arrived with ttl 0, packet discarded" )
  return ( [ False , None ] )
 elif ( I1i == 1 ) :
  dprint ( "IPv4 packet {}, packet discarded" . format ( bold ( "ttl expiry" , False ) ) )
  if 10 - 10: OOooOOo
  return ( [ False , None ] )
  if 75 - 75: I11i * ooOoO0o * Oo0Ooo . i1IIi . ooOoO0o . ooOoO0o
  if 24 - 24: iIii1I11I1II1
 I1i -= 1
 packet = packet [ 0 : 8 ] + struct . pack ( "B" , I1i ) + packet [ 9 : : ]
 packet = packet [ 0 : 10 ] + struct . pack ( "H" , 0 ) + packet [ 12 : : ]
 packet = lisp_ip_checksum ( packet )
 return ( [ False , packet ] )
 if 72 - 72: i11iIiiIii + o0oOOo0O0Ooo % ooOoO0o * I1ii11iIi11i . i1IIi
 if 59 - 59: OoooooooOO - OoooooooOO - o0oOOo0O0Ooo + i1IIi % I1Ii111
 if 74 - 74: IiII * iIii1I11I1II1 - I1IiiI
 if 62 - 62: o0oOOo0O0Ooo
 if 54 - 54: iIii1I11I1II1 / OoooooooOO + o0oOOo0O0Ooo . i1IIi - OoooooooOO
 if 70 - 70: Ii1I / OoOoOO00 * Oo0Ooo
 if 32 - 32: I1Ii111 . OoOoOO00 % OoooooooOO + I1Ii111 * OoO0O00
def lisp_ipv6_input ( packet ) :
 oOiii1IiII = packet . inner_dest
 packet = packet . packet
 if 84 - 84: OoOoOO00
 if 80 - 80: oO0o
 if 59 - 59: iIii1I11I1II1 / IiII % I1ii11iIi11i + OoO0O00 - I11i % OOooOOo
 if 92 - 92: iII111i
 if 96 - 96: OoOoOO00 / OoOoOO00 / OoOoOO00 + OoooooooOO + Oo0Ooo
 I1i = struct . unpack ( "B" , packet [ 7 : 8 ] ) [ 0 ]
 if ( I1i == 0 ) :
  dprint ( "IPv6 packet arrived with hop-limit 0, packet discarded" )
  return ( None )
 elif ( I1i == 1 ) :
  dprint ( "IPv6 packet {}, packet discarded" . format ( bold ( "ttl expiry" , False ) ) )
  if 91 - 91: OoOoOO00 + II111iiii / I11i * iIii1I11I1II1
  return ( None )
  if 92 - 92: I1Ii111 - IiII / IiII
  if 42 - 42: IiII
  if 7 - 7: iIii1I11I1II1
  if 35 - 35: IiII + O0 % I1Ii111 - I1ii11iIi11i - i1IIi
  if 100 - 100: I1Ii111 + i11iIiiIii - IiII / I1ii11iIi11i / iII111i
 if ( oOiii1IiII . is_ipv6_link_local ( ) ) :
  dprint ( "Do not encapsulate IPv6 link-local packets" )
  return ( None )
  if 56 - 56: iII111i
  if 91 - 91: Oo0Ooo . I11i . I1ii11iIi11i
 I1i -= 1
 packet = packet [ 0 : 7 ] + struct . pack ( "B" , I1i ) + packet [ 8 : : ]
 return ( packet )
 if 60 - 60: i11iIiiIii - OOooOOo
 if 78 - 78: I1IiiI * ooOoO0o % iIii1I11I1II1 / I1ii11iIi11i
 if 61 - 61: I1Ii111 . Ii1I + OoooooooOO
 if 98 - 98: OOooOOo . ooOoO0o . OoOoOO00 - I1Ii111 . i1IIi - iIii1I11I1II1
 if 89 - 89: II111iiii * I1ii11iIi11i - I1IiiI
 if 58 - 58: Ii1I / Oo0Ooo % IiII
 if 33 - 33: II111iiii . OOooOOo % iIii1I11I1II1 - Oo0Ooo - OoOoOO00 % i11iIiiIii
 if 60 - 60: iII111i . o0oOOo0O0Ooo
def lisp_mac_input ( packet ) :
 return ( packet )
 if 56 - 56: I1ii11iIi11i
 if 89 - 89: Oo0Ooo + I1ii11iIi11i * o0oOOo0O0Ooo * oO0o % O0 % OoO0O00
 if 70 - 70: o0oOOo0O0Ooo + O0 % I1IiiI
 if 56 - 56: Ii1I
 if 84 - 84: iII111i
 if 21 - 21: i11iIiiIii
 if 30 - 30: OoO0O00 + OoooooooOO
 if 98 - 98: I1ii11iIi11i % I1IiiI
 if 9 - 9: o0oOOo0O0Ooo / I1Ii111 % i1IIi - OOooOOo % I1IiiI / I1ii11iIi11i
def lisp_rate_limit_map_request ( source , dest ) :
 if ( lisp_last_map_request_sent == None ) : return ( False )
 II1iI111 = lisp_get_timestamp ( )
 I1IiIii11I = II1iI111 - lisp_last_map_request_sent
 oOoOOo0o0o0O = ( I1IiIii11I < LISP_MAP_REQUEST_RATE_LIMIT )
 if 59 - 59: OoOoOO00 / i1IIi / iIii1I11I1II1 + i1IIi
 if ( oOoOOo0o0o0O ) :
  if ( source != None ) : source = source . print_address ( )
  dest = dest . print_address ( )
  dprint ( "Rate-limiting Map-Request for {} -> {}" . format ( source , dest ) )
  if 33 - 33: iIii1I11I1II1 * i11iIiiIii
 return ( oOoOOo0o0o0O )
 if 7 - 7: oO0o
 if 89 - 89: i11iIiiIii / o0oOOo0O0Ooo / I1ii11iIi11i % iII111i . OoooooooOO - iIii1I11I1II1
 if 63 - 63: Ii1I % I1Ii111 + O0 * OoO0O00 . oO0o
 if 34 - 34: I1IiiI . I1ii11iIi11i . O0 - OoOoOO00 - i11iIiiIii / iII111i
 if 63 - 63: OOooOOo
 if 84 - 84: i11iIiiIii * iIii1I11I1II1 % I11i % iII111i + OoooooooOO . o0oOOo0O0Ooo
 if 78 - 78: o0oOOo0O0Ooo . iII111i + O0 / I1ii11iIi11i + I1ii11iIi11i + II111iiii
def lisp_send_map_request ( lisp_sockets , lisp_ephem_port , seid , deid , rloc ) :
 global lisp_last_map_request_sent
 if 96 - 96: iIii1I11I1II1 * II111iiii . iIii1I11I1II1
 if 13 - 13: Ii1I - OoOoOO00 . Ii1I
 if 7 - 7: Ii1I - I11i / I1ii11iIi11i + iII111i
 if 47 - 47: I11i * IiII / oO0o - OoooooooOO . OoooooooOO / I11i
 if 73 - 73: Ii1I . IiII % IiII
 if 56 - 56: I1Ii111 + iII111i + iII111i
 OOoOoOOo0O = iIi1i11iii1iI = None
 if ( rloc ) :
  OOoOoOOo0O = rloc . rloc
  iIi1i11iii1iI = rloc . translated_port if lisp_i_am_rtr else LISP_DATA_PORT
  if 93 - 93: Oo0Ooo / o0oOOo0O0Ooo . iII111i / i11iIiiIii + I11i
  if 94 - 94: IiII - OoO0O00 * iII111i . I1IiiI
  if 27 - 27: I11i / o0oOOo0O0Ooo / II111iiii
  if 93 - 93: II111iiii - I11i
  if 17 - 17: i1IIi + O0 * ooOoO0o
 O0oo , Oo00O , iiiIiIIIiiiIiI1 = lisp_myrlocs
 if ( O0oo == None ) :
  lprint ( "Suppress sending Map-Request, IPv4 RLOC not found" )
  return
  if 85 - 85: OoOoOO00 + O0 % oO0o + ooOoO0o
 if ( Oo00O == None and OOoOoOOo0O != None and OOoOoOOo0O . is_ipv6 ( ) ) :
  lprint ( "Suppress sending Map-Request, IPv6 RLOC not found" )
  return
  if 65 - 65: iII111i
  if 3 - 3: iIii1I11I1II1
 ooo = lisp_map_request ( )
 ooo . record_count = 1
 ooo . nonce = lisp_get_control_nonce ( )
 ooo . rloc_probe = ( OOoOoOOo0O != None )
 if 25 - 25: OOooOOo * OoO0O00 + o0oOOo0O0Ooo % Ii1I - o0oOOo0O0Ooo - iII111i
 if 17 - 17: O0 . ooOoO0o % I1IiiI . iII111i / oO0o . IiII
 if 95 - 95: ooOoO0o . I11i / i11iIiiIii - IiII
 if 87 - 87: I1Ii111 - iII111i * I11i
 if 74 - 74: Ii1I - OoOoOO00 + i11iIiiIii - II111iiii - i11iIiiIii . ooOoO0o
 if 83 - 83: I1Ii111 % ooOoO0o + OoooooooOO
 if 50 - 50: i11iIiiIii % I1IiiI * iII111i / Ii1I
 if ( rloc ) : rloc . last_rloc_probe_nonce = ooo . nonce
 if 12 - 12: iII111i / OoO0O00 - II111iiii + Oo0Ooo
 iIiiIi1111ii = deid . is_multicast_address ( )
 if ( iIiiIi1111ii ) :
  ooo . target_eid = seid
  ooo . target_group = deid
 else :
  ooo . target_eid = deid
  if 78 - 78: i1IIi
  if 25 - 25: Ii1I * II111iiii / OoOoOO00
  if 86 - 86: i1IIi + I1IiiI + I1Ii111 % II111iiii . IiII - iIii1I11I1II1
  if 54 - 54: i11iIiiIii . Ii1I % I1IiiI . I1Ii111 . OoooooooOO
  if 49 - 49: OOooOOo % I11i - OOooOOo + Ii1I . I1ii11iIi11i + ooOoO0o
  if 15 - 15: i11iIiiIii
  if 85 - 85: I1Ii111 + iII111i - oO0o
  if 59 - 59: IiII . oO0o / i11iIiiIii . I1Ii111
  if 64 - 64: OoOoOO00
 if ( ooo . rloc_probe == False ) :
  i1i1iiiii1IiI = lisp_get_signature_eid ( )
  if ( i1i1iiiii1IiI ) :
   ooo . signature_eid . copy_address ( i1i1iiiii1IiI . eid )
   ooo . privkey_filename = "./lisp-sig.pem"
   if 20 - 20: OoOoOO00 / O0 * OOooOOo % I11i + OoO0O00 + o0oOOo0O0Ooo
   if 51 - 51: Ii1I - OoOoOO00 / i11iIiiIii + O0
   if 71 - 71: ooOoO0o
   if 35 - 35: OoOoOO00
   if 55 - 55: iII111i - o0oOOo0O0Ooo + IiII * II111iiii
   if 6 - 6: I1Ii111 / i1IIi / IiII . o0oOOo0O0Ooo
 if ( seid == None or iIiiIi1111ii ) :
  ooo . source_eid . afi = LISP_AFI_NONE
 else :
  ooo . source_eid = seid
  if 69 - 69: ooOoO0o - OoOoOO00 . I1IiiI . I11i + OoOoOO00 / i11iIiiIii
  if 20 - 20: OoO0O00 . OoooooooOO - ooOoO0o . I11i / Oo0Ooo
  if 89 - 89: iIii1I11I1II1 . ooOoO0o
  if 82 - 82: OoOoOO00 - II111iiii . OoO0O00 * ooOoO0o
  if 78 - 78: OoOoOO00 % oO0o
  if 39 - 39: iIii1I11I1II1
  if 72 - 72: II111iiii + I1Ii111 / Ii1I * iIii1I11I1II1
  if 95 - 95: OoooooooOO + OOooOOo + II111iiii + IiII + OoO0O00
  if 86 - 86: II111iiii / iII111i - I1ii11iIi11i
  if 65 - 65: I1ii11iIi11i + OoOoOO00
  if 43 - 43: O0 + I11i % II111iiii
  if 56 - 56: IiII + Oo0Ooo . IiII % iIii1I11I1II1 % ooOoO0o % ooOoO0o
 if ( OOoOoOOo0O != None and lisp_nat_traversal and lisp_i_am_rtr == False ) :
  if ( OOoOoOOo0O . is_private_address ( ) == False ) :
   O0oo = lisp_get_any_translated_rloc ( )
   if 70 - 70: ooOoO0o / i1IIi - I11i - i11iIiiIii
  if ( O0oo == None ) :
   lprint ( "Suppress sending Map-Request, translated RLOC not found" )
   return
   if 79 - 79: OoO0O00 - OoooooooOO % iII111i . O0
   if 93 - 93: I1Ii111
   if 3 - 3: OoO0O00 / IiII - oO0o / oO0o
   if 50 - 50: II111iiii + OoOoOO00
   if 17 - 17: ooOoO0o + I1ii11iIi11i
   if 34 - 34: Ii1I / II111iiii + OoOoOO00 . II111iiii + OoooooooOO * o0oOOo0O0Ooo
   if 48 - 48: O0
   if 99 - 99: II111iiii * oO0o / I1ii11iIi11i - i1IIi
 if ( OOoOoOOo0O == None or OOoOoOOo0O . is_ipv4 ( ) ) :
  if ( lisp_nat_traversal and OOoOoOOo0O == None ) :
   ooI111i11iii1Ii = lisp_get_any_translated_rloc ( )
   if ( ooI111i11iii1Ii != None ) : O0oo = ooI111i11iii1Ii
   if 5 - 5: iIii1I11I1II1 / oO0o - Oo0Ooo - I1IiiI + iIii1I11I1II1
  ooo . itr_rlocs . append ( O0oo )
  if 63 - 63: iIii1I11I1II1 / ooOoO0o + O0 - o0oOOo0O0Ooo
 if ( OOoOoOOo0O == None or OOoOoOOo0O . is_ipv6 ( ) ) :
  if ( Oo00O == None or Oo00O . is_ipv6_link_local ( ) ) :
   Oo00O = None
  else :
   ooo . itr_rloc_count = 1 if ( OOoOoOOo0O == None ) else 0
   ooo . itr_rlocs . append ( Oo00O )
   if 31 - 31: Ii1I
   if 76 - 76: OoO0O00 / II111iiii
   if 92 - 92: o0oOOo0O0Ooo . i1IIi . OoOoOO00 / OoO0O00 % Ii1I
   if 61 - 61: i1IIi / Ii1I . OoOoOO00 + i11iIiiIii
   if 69 - 69: i11iIiiIii - iIii1I11I1II1
   if 40 - 40: I1IiiI / oO0o + ooOoO0o
   if 100 - 100: OoOoOO00 % iII111i * ooOoO0o . O0
   if 37 - 37: I1ii11iIi11i
   if 24 - 24: O0 . I1Ii111 * i11iIiiIii
 if ( OOoOoOOo0O != None and ooo . itr_rlocs != [ ] ) :
  o0OooOo000oo0ooooO = ooo . itr_rlocs [ 0 ]
 else :
  if ( deid . is_ipv4 ( ) ) :
   o0OooOo000oo0ooooO = O0oo
  elif ( deid . is_ipv6 ( ) ) :
   o0OooOo000oo0ooooO = Oo00O
  else :
   o0OooOo000oo0ooooO = O0oo
   if 84 - 84: ooOoO0o / I1ii11iIi11i - o0oOOo0O0Ooo . OoooooooOO * iIii1I11I1II1
   if 16 - 16: I11i % O0
   if 56 - 56: Ii1I * OoOoOO00 . i1IIi
   if 15 - 15: I1Ii111
   if 64 - 64: OOooOOo * Oo0Ooo
   if 96 - 96: Oo0Ooo / I1ii11iIi11i * iIii1I11I1II1 / iII111i
 Ii11iIiiI = ooo . encode ( OOoOoOOo0O , iIi1i11iii1iI )
 ooo . print_map_request ( )
 if 18 - 18: I1Ii111
 if 29 - 29: i1IIi - I1IiiI / i1IIi
 if 64 - 64: IiII
 if 69 - 69: OOooOOo . I1IiiI
 if 11 - 11: I1Ii111 * I1IiiI - I1Ii111 / iII111i
 if 22 - 22: iII111i % I11i % O0 - I11i
 if ( OOoOoOOo0O != None ) :
  if ( rloc . is_rloc_translated ( ) ) :
   oOOoO = lisp_get_nat_info ( OOoOoOOo0O , rloc . rloc_name )
   if 71 - 71: I1Ii111 / II111iiii - OoooooooOO % i1IIi + OoOoOO00 % OoooooooOO
   if 52 - 52: Ii1I . OoOoOO00 / o0oOOo0O0Ooo / iII111i
   if 83 - 83: OoO0O00 - Oo0Ooo + I1Ii111 . I1IiiI
   if 78 - 78: I11i / ooOoO0o . OoOoOO00 * i1IIi
   if ( oOOoO == None ) :
    oooO0 = rloc . rloc . print_address_no_iid ( )
    IiIoO0oo0 = "gleaned-{}" . format ( oooO0 )
    IiIiI1 = rloc . translated_port
    oOOoO = lisp_nat_info ( oooO0 , IiIoO0oo0 , IiIiI1 )
    if 15 - 15: i1IIi . II111iiii * OoOoOO00 / Oo0Ooo
   lisp_encapsulate_rloc_probe ( lisp_sockets , OOoOoOOo0O , oOOoO ,
 Ii11iIiiI )
   return
   if 99 - 99: iII111i - o0oOOo0O0Ooo / O0
   if 97 - 97: iIii1I11I1II1 * I1Ii111
  i111I11I = OOoOoOOo0O . print_address_no_iid ( )
  oOiii1IiII = lisp_convert_4to6 ( i111I11I )
  lisp_send ( lisp_sockets , oOiii1IiII , LISP_CTRL_PORT , Ii11iIiiI )
  return
  if 39 - 39: I1Ii111 . II111iiii
  if 94 - 94: OoO0O00 - OoO0O00 + iIii1I11I1II1 + O0 * oO0o
  if 9 - 9: Ii1I * Oo0Ooo / oO0o / Ii1I
  if 34 - 34: I1IiiI
  if 56 - 56: Ii1I
  if 71 - 71: O0 / i1IIi
 IIo0 = None if lisp_i_am_rtr else seid
 if ( lisp_decent_pull_xtr_configured ( ) ) :
  OOO0o0o = lisp_get_decent_map_resolver ( deid )
 else :
  OOO0o0o = lisp_get_map_resolver ( None , IIo0 )
  if 23 - 23: IiII * Ii1I - Ii1I . oO0o - IiII
 if ( OOO0o0o == None ) :
  lprint ( "Cannot find Map-Resolver for source-EID {}" . format ( green ( seid . print_address ( ) , False ) ) )
  if 56 - 56: i1IIi + i11iIiiIii % OoO0O00 - ooOoO0o / OoO0O00
  return
  if 23 - 23: IiII - OoO0O00 / I1ii11iIi11i * oO0o
 OOO0o0o . last_used = lisp_get_timestamp ( )
 OOO0o0o . map_requests_sent += 1
 if ( OOO0o0o . last_nonce == 0 ) : OOO0o0o . last_nonce = ooo . nonce
 if 77 - 77: O0 * oO0o . I1ii11iIi11i - i1IIi
 if 87 - 87: i1IIi % I1Ii111
 if 37 - 37: I11i
 if 61 - 61: OoooooooOO % iIii1I11I1II1 % O0 % I1Ii111 / Oo0Ooo . I1IiiI
 if ( seid == None ) : seid = o0OooOo000oo0ooooO
 lisp_send_ecm ( lisp_sockets , Ii11iIiiI , seid , lisp_ephem_port , deid ,
 OOO0o0o . map_resolver )
 if 20 - 20: ooOoO0o - I1Ii111
 if 97 - 97: O0
 if 56 - 56: Ii1I * I1IiiI * ooOoO0o
 if 39 - 39: iII111i % Ii1I * iIii1I11I1II1 - Ii1I - I1Ii111
 lisp_last_map_request_sent = lisp_get_timestamp ( )
 if 60 - 60: i11iIiiIii + i11iIiiIii - OoooooooOO + OoooooooOO
 if 5 - 5: o0oOOo0O0Ooo
 if 78 - 78: OOooOOo * O0 * II111iiii % OoOoOO00
 if 12 - 12: Oo0Ooo . o0oOOo0O0Ooo - i1IIi - oO0o % IiII . I11i
 OOO0o0o . resolve_dns_name ( )
 return
 if 17 - 17: i1IIi % OoO0O00 + i11iIiiIii % I1Ii111 * ooOoO0o . I1ii11iIi11i
 if 64 - 64: O0 - iII111i
 if 82 - 82: O0
 if 37 - 37: I1Ii111
 if 98 - 98: iII111i - OoOoOO00 / I1Ii111 . OOooOOo - OOooOOo - ooOoO0o
 if 84 - 84: OOooOOo * ooOoO0o / O0
 if 96 - 96: I11i . I11i % II111iiii
 if 14 - 14: iII111i / OoooooooOO
def lisp_send_info_request ( lisp_sockets , dest , port , device_name ) :
 if 8 - 8: OOooOOo + I1IiiI - Oo0Ooo + i1IIi . Ii1I . I1Ii111
 if 38 - 38: I1IiiI / II111iiii * OoOoOO00 / I1Ii111
 if 80 - 80: I1ii11iIi11i / ooOoO0o * ooOoO0o . Oo0Ooo
 if 44 - 44: Ii1I * i1IIi % OoOoOO00 . OoOoOO00
 IIiii = lisp_info ( )
 IIiii . nonce = lisp_get_control_nonce ( )
 if ( device_name ) : IIiii . hostname += "-" + device_name
 if 12 - 12: i1IIi . I1ii11iIi11i - iIii1I11I1II1 . OoO0O00 / o0oOOo0O0Ooo
 i111I11I = dest . print_address_no_iid ( )
 if 18 - 18: i1IIi * IiII * I1IiiI * i1IIi + ooOoO0o
 if 15 - 15: iII111i
 if 91 - 91: OoO0O00
 if 8 - 8: oO0o
 if 96 - 96: IiII
 if 37 - 37: Ii1I % i11iIiiIii + iIii1I11I1II1 % Oo0Ooo - iIii1I11I1II1
 if 26 - 26: o0oOOo0O0Ooo . i1IIi
 if 62 - 62: IiII * I1ii11iIi11i % iIii1I11I1II1 / II111iiii - OoO0O00
 if 52 - 52: iII111i . I11i - I11i + oO0o + iIii1I11I1II1
 if 83 - 83: I11i * iIii1I11I1II1 + OoOoOO00
 if 81 - 81: ooOoO0o * OOooOOo / OoO0O00 + I1ii11iIi11i % I1Ii111
 if 37 - 37: i11iIiiIii - OoooooooOO - OoOoOO00 * oO0o / Ii1I
 if 100 - 100: II111iiii / Oo0Ooo / iII111i / OOooOOo
 if 100 - 100: iIii1I11I1II1
 if 50 - 50: I1Ii111 / ooOoO0o * I11i
 if 53 - 53: II111iiii . IiII
 ii1iII111i = False
 if ( device_name ) :
  o00o0ooo = lisp_get_host_route_next_hop ( i111I11I )
  if 5 - 5: iII111i + oO0o % O0 . OoooooooOO + i1IIi
  if 55 - 55: I1ii11iIi11i
  if 34 - 34: OoO0O00 * iIii1I11I1II1 . iIii1I11I1II1
  if 39 - 39: o0oOOo0O0Ooo
  if 29 - 29: Oo0Ooo . Oo0Ooo * OoO0O00 % Ii1I - ooOoO0o
  if 67 - 67: I1IiiI % O0 + I1IiiI * I1Ii111 * OoOoOO00 * II111iiii
  if 79 - 79: I1IiiI
  if 37 - 37: I1Ii111 + Ii1I
  if 50 - 50: i11iIiiIii
  if ( port == LISP_CTRL_PORT and o00o0ooo != None ) :
   while ( True ) :
    time . sleep ( .01 )
    o00o0ooo = lisp_get_host_route_next_hop ( i111I11I )
    if ( o00o0ooo == None ) : break
    if 57 - 57: O0 * i1IIi - I1IiiI
    if 48 - 48: IiII / iIii1I11I1II1
    if 20 - 20: oO0o / OoooooooOO
  oOii1Iii = lisp_get_default_route_next_hops ( )
  for iiiIiIIIiiiIiI1 , iI1II1IiIiIi in oOii1Iii :
   if ( iiiIiIIIiiiIiI1 != device_name ) : continue
   if 24 - 24: i11iIiiIii % iII111i . oO0o
   if 44 - 44: II111iiii - OoO0O00 + i11iIiiIii
   if 34 - 34: I1ii11iIi11i % ooOoO0o / II111iiii * O0 % OOooOOo
   if 9 - 9: I1ii11iIi11i / I1ii11iIi11i - OOooOOo . iIii1I11I1II1
   if 33 - 33: I1IiiI + oO0o % I1IiiI / iII111i - ooOoO0o - i11iIiiIii
   if 39 - 39: i11iIiiIii / oO0o
   if ( o00o0ooo != iI1II1IiIiIi ) :
    if ( o00o0ooo != None ) :
     lisp_install_host_route ( i111I11I , o00o0ooo , False )
     if 71 - 71: I1Ii111 * iIii1I11I1II1 - I1Ii111
    lisp_install_host_route ( i111I11I , iI1II1IiIiIi , True )
    ii1iII111i = True
    if 87 - 87: I1IiiI / Ii1I
   break
   if 54 - 54: OoooooooOO / Ii1I
   if 26 - 26: o0oOOo0O0Ooo + OoO0O00
   if 59 - 59: Ii1I * IiII
   if 64 - 64: ooOoO0o . Oo0Ooo - OoOoOO00
   if 66 - 66: OoOoOO00
   if 83 - 83: OOooOOo . IiII
 Ii11iIiiI = IIiii . encode ( )
 IIiii . print_info ( )
 if 98 - 98: i11iIiiIii
 if 74 - 74: iIii1I11I1II1 * O0 + OOooOOo . o0oOOo0O0Ooo
 if 17 - 17: I1Ii111
 if 59 - 59: OoOoOO00 . OoOoOO00 * iII111i - Ii1I . i11iIiiIii
 o00O00O0OO0O = "(for control)" if port == LISP_CTRL_PORT else "(for data)"
 o00O00O0OO0O = bold ( o00O00O0OO0O , False )
 IiIiI1 = bold ( "{}" . format ( port ) , False )
 i1 = red ( i111I11I , False )
 o0O000o0o0 = "RTR " if port == LISP_DATA_PORT else "MS "
 lprint ( "Send Info-Request to {}{}, port {} {}" . format ( o0O000o0o0 , i1 , IiIiI1 , o00O00O0OO0O ) )
 if 3 - 3: iIii1I11I1II1 + iIii1I11I1II1 + OoO0O00
 if 59 - 59: iII111i
 if 7 - 7: o0oOOo0O0Ooo * OoooooooOO - Ii1I * II111iiii % I1Ii111
 if 82 - 82: OoOoOO00 - OoOoOO00 + iIii1I11I1II1 + o0oOOo0O0Ooo + IiII - o0oOOo0O0Ooo
 if 65 - 65: I1Ii111 + OOooOOo
 if 97 - 97: oO0o % OoOoOO00 * oO0o % II111iiii + iIii1I11I1II1
 if ( port == LISP_CTRL_PORT ) :
  lisp_send ( lisp_sockets , dest , LISP_CTRL_PORT , Ii11iIiiI )
 else :
  I11IIIIiII = lisp_data_header ( )
  I11IIIIiII . instance_id ( 0xffffff )
  I11IIIIiII = I11IIIIiII . encode ( )
  if ( I11IIIIiII ) :
   Ii11iIiiI = I11IIIIiII + Ii11iIiiI
   if 11 - 11: ooOoO0o . o0oOOo0O0Ooo
   if 94 - 94: ooOoO0o . oO0o * OoooooooOO % oO0o
   if 77 - 77: ooOoO0o % I1IiiI
   if 26 - 26: o0oOOo0O0Ooo
   if 72 - 72: I1IiiI
   if 90 - 90: ooOoO0o
   if 67 - 67: iIii1I11I1II1 + i1IIi * I1IiiI * OoooooooOO
   if 23 - 23: IiII
   if 32 - 32: OoOoOO00 - iII111i % oO0o / I1ii11iIi11i - o0oOOo0O0Ooo
   lisp_send ( lisp_sockets , dest , LISP_DATA_PORT , Ii11iIiiI )
   if 52 - 52: Ii1I / OoooooooOO % i11iIiiIii + iII111i
   if 59 - 59: Ii1I / o0oOOo0O0Ooo / oO0o + iII111i * I1ii11iIi11i - o0oOOo0O0Ooo
   if 70 - 70: O0 / I1ii11iIi11i + ooOoO0o . OoO0O00 - OoO0O00 / i11iIiiIii
   if 1 - 1: iIii1I11I1II1 % I1ii11iIi11i
   if 49 - 49: iII111i + o0oOOo0O0Ooo % I1ii11iIi11i . O0 % OoooooooOO . o0oOOo0O0Ooo
   if 3 - 3: i11iIiiIii - i1IIi * o0oOOo0O0Ooo / OoOoOO00 % Oo0Ooo
   if 65 - 65: OoooooooOO + iII111i - i11iIiiIii - IiII + oO0o
 if ( ii1iII111i ) :
  lisp_install_host_route ( i111I11I , None , False )
  if ( o00o0ooo != None ) : lisp_install_host_route ( i111I11I , o00o0ooo , True )
  if 67 - 67: i1IIi * I1Ii111 * O0
 return
 if 16 - 16: OoO0O00 + iII111i + i1IIi + I1ii11iIi11i - I1IiiI
 if 88 - 88: oO0o % iII111i + I1ii11iIi11i - II111iiii . I11i
 if 18 - 18: I1ii11iIi11i - i1IIi - IiII * II111iiii % I1Ii111 . II111iiii
 if 80 - 80: oO0o + OoO0O00 + o0oOOo0O0Ooo . OoOoOO00
 if 75 - 75: i11iIiiIii
 if 58 - 58: iII111i
 if 48 - 48: OoO0O00 * OOooOOo / iII111i
def lisp_process_info_request ( lisp_sockets , packet , addr_str , sport , rtr_list ) :
 if 90 - 90: I1IiiI * i11iIiiIii . OOooOOo / o0oOOo0O0Ooo
 if 82 - 82: Oo0Ooo
 if 50 - 50: I1Ii111 * OOooOOo * OoOoOO00 / OoooooooOO % iII111i
 if 80 - 80: I1Ii111
 IIiii = lisp_info ( )
 packet = IIiii . decode ( packet )
 if ( packet == None ) : return
 IIiii . print_info ( )
 if 35 - 35: Ii1I . O0 % i11iIiiIii * oO0o - OoooooooOO
 if 87 - 87: iII111i * ooOoO0o - OOooOOo . O0
 if 20 - 20: OoOoOO00 - IiII
 if 9 - 9: O0 . I11i % I1ii11iIi11i * oO0o - I1Ii111 - i1IIi
 if 66 - 66: II111iiii / Oo0Ooo
 IIiii . info_reply = True
 IIiii . global_etr_rloc . store_address ( addr_str )
 IIiii . etr_port = sport
 if 93 - 93: iII111i + I11i * OoooooooOO . OoO0O00
 if 40 - 40: ooOoO0o * I1Ii111 + iII111i
 if 52 - 52: iII111i % I11i
 if 95 - 95: IiII + Ii1I / OoO0O00 - iII111i / I1IiiI
 if 27 - 27: Oo0Ooo + i1IIi + i11iIiiIii . OoO0O00 . OoO0O00
 if ( IIiii . hostname != None ) :
  IIiii . private_etr_rloc . afi = LISP_AFI_NAME
  IIiii . private_etr_rloc . store_address ( IIiii . hostname )
  if 56 - 56: I1Ii111 / OoO0O00 + o0oOOo0O0Ooo . OoooooooOO * Oo0Ooo
  if 14 - 14: OoO0O00
 if ( rtr_list != None ) : IIiii . rtr_list = rtr_list
 packet = IIiii . encode ( )
 IIiii . print_info ( )
 if 21 - 21: II111iiii + i11iIiiIii + I11i % I1IiiI
 if 65 - 65: IiII + I1ii11iIi11i / iII111i / I1IiiI + Ii1I
 if 88 - 88: IiII % iIii1I11I1II1
 if 3 - 3: ooOoO0o / I1Ii111 % iIii1I11I1II1 % I11i * oO0o / iIii1I11I1II1
 if 75 - 75: i11iIiiIii . iII111i
 lprint ( "Send Info-Reply to {}" . format ( red ( addr_str , False ) ) )
 oOiii1IiII = lisp_convert_4to6 ( addr_str )
 lisp_send ( lisp_sockets , oOiii1IiII , sport , packet )
 if 68 - 68: OOooOOo . I1ii11iIi11i % I1ii11iIi11i . i11iIiiIii
 if 45 - 45: oO0o % I1ii11iIi11i * I1Ii111
 if 21 - 21: O0 + i11iIiiIii
 if 72 - 72: OoOoOO00 * OoooooooOO % O0 / I1ii11iIi11i % Ii1I - I11i
 if 65 - 65: iIii1I11I1II1 + II111iiii * OoO0O00 * i11iIiiIii / IiII
 IIIiI1iIi1 = lisp_info_source ( IIiii . hostname , addr_str , sport )
 IIIiI1iIi1 . cache_address_for_info_source ( )
 return
 if 41 - 41: iII111i / o0oOOo0O0Ooo / I1IiiI * OOooOOo
 if 94 - 94: o0oOOo0O0Ooo * I11i
 if 20 - 20: IiII
 if 37 - 37: I1ii11iIi11i / I1IiiI + I1Ii111 % i1IIi / i1IIi
 if 91 - 91: I11i
 if 94 - 94: OoO0O00
 if 19 - 19: I11i * i11iIiiIii - OoO0O00 / ooOoO0o * I1Ii111 + OoO0O00
 if 30 - 30: Ii1I / iII111i * Ii1I
def lisp_get_signature_eid ( ) :
 for i1i1iiiii1IiI in lisp_db_list :
  if ( i1i1iiiii1IiI . signature_eid ) : return ( i1i1iiiii1IiI )
  if 11 - 11: OoOoOO00 - OoOoOO00 % oO0o
 return ( None )
 if 3 - 3: I1IiiI - OoooooooOO % iIii1I11I1II1 + I1Ii111 + OoOoOO00
 if 71 - 71: i1IIi % O0 % ooOoO0o
 if 24 - 24: O0
 if 88 - 88: OoooooooOO / Oo0Ooo / oO0o
 if 99 - 99: I1Ii111 % OoOoOO00 % IiII - Ii1I
 if 79 - 79: ooOoO0o + Oo0Ooo
 if 80 - 80: OoOoOO00 % OoO0O00 . OoO0O00 * OoO0O00 * O0
 if 18 - 18: II111iiii . o0oOOo0O0Ooo + OoO0O00
def lisp_get_any_translated_port ( ) :
 for i1i1iiiii1IiI in lisp_db_list :
  for IiIiI in i1i1iiiii1IiI . rloc_set :
   if ( IiIiI . translated_rloc . is_null ( ) ) : continue
   return ( IiIiI . translated_port )
   if 69 - 69: OoO0O00 . ooOoO0o * ooOoO0o * iIii1I11I1II1
   if 8 - 8: iII111i . oO0o . OOooOOo + iII111i . Ii1I
 return ( None )
 if 46 - 46: OoO0O00
 if 21 - 21: iIii1I11I1II1 - iII111i
 if 15 - 15: O0 + iII111i + i11iIiiIii
 if 31 - 31: iIii1I11I1II1 * iIii1I11I1II1 . I11i
 if 52 - 52: i11iIiiIii / oO0o / IiII
 if 84 - 84: I11i . oO0o + ooOoO0o
 if 75 - 75: I1Ii111
 if 97 - 97: ooOoO0o % Oo0Ooo . o0oOOo0O0Ooo
 if 22 - 22: O0 % I11i + OoO0O00 - iII111i + I1IiiI . O0
def lisp_get_any_translated_rloc ( ) :
 for i1i1iiiii1IiI in lisp_db_list :
  for IiIiI in i1i1iiiii1IiI . rloc_set :
   if ( IiIiI . translated_rloc . is_null ( ) ) : continue
   return ( IiIiI . translated_rloc )
   if 73 - 73: ooOoO0o + O0 - I11i . I1IiiI + OOooOOo
   if 36 - 36: I11i % OoO0O00 * OoOoOO00 - I1Ii111
 return ( None )
 if 16 - 16: ooOoO0o % OOooOOo . OoO0O00 % II111iiii . iIii1I11I1II1
 if 21 - 21: oO0o + II111iiii / OoOoOO00 * I11i
 if 90 - 90: OoOoOO00 % OoOoOO00 + I11i
 if 70 - 70: I1IiiI . ooOoO0o / I11i / OoO0O00
 if 40 - 40: oO0o % iIii1I11I1II1 * iIii1I11I1II1 / Oo0Ooo * OoO0O00
 if 61 - 61: OOooOOo
 if 80 - 80: I1ii11iIi11i
def lisp_get_all_translated_rlocs ( ) :
 iI111I = [ ]
 for i1i1iiiii1IiI in lisp_db_list :
  for IiIiI in i1i1iiiii1IiI . rloc_set :
   if ( IiIiI . is_rloc_translated ( ) == False ) : continue
   oOo00Ooo0o0 = IiIiI . translated_rloc . print_address_no_iid ( )
   iI111I . append ( oOo00Ooo0o0 )
   if 84 - 84: OoooooooOO . I1IiiI / I11i + i1IIi - ooOoO0o
   if 72 - 72: OoooooooOO
 return ( iI111I )
 if 57 - 57: I1Ii111 * O0 / o0oOOo0O0Ooo * iII111i * ooOoO0o - I11i
 if 53 - 53: iIii1I11I1II1 . OoOoOO00 % i11iIiiIii % I1IiiI / OoO0O00 % I1Ii111
 if 11 - 11: I1IiiI + I11i . OoOoOO00 - II111iiii
 if 10 - 10: iII111i - IiII + OoOoOO00 + I1IiiI + Oo0Ooo
 if 25 - 25: I1IiiI / I1ii11iIi11i % iII111i / O0 % II111iiii
 if 20 - 20: O0 % I11i * iII111i
 if 6 - 6: OoooooooOO % ooOoO0o % OoO0O00 * IiII
 if 62 - 62: i1IIi . I11i / I11i
def lisp_update_default_routes ( map_resolver , iid , rtr_list ) :
 iiIiIIi1I = ( os . getenv ( "LISP_RTR_BEHIND_NAT" ) != None )
 if 90 - 90: O0 * OOooOOo / oO0o . Oo0Ooo * I11i
 oOO00 = { }
 for II11IIiii in rtr_list :
  if ( II11IIiii == None ) : continue
  oOo00Ooo0o0 = rtr_list [ II11IIiii ]
  if ( iiIiIIi1I and oOo00Ooo0o0 . is_private_address ( ) ) : continue
  oOO00 [ II11IIiii ] = oOo00Ooo0o0
  if 70 - 70: OOooOOo / Ii1I - ooOoO0o + OoooooooOO / OoO0O00 - i11iIiiIii
 rtr_list = oOO00
 if 26 - 26: O0 + Oo0Ooo
 iiii1i111i1I = [ ]
 for ii1iI1i1 in [ LISP_AFI_IPV4 , LISP_AFI_IPV6 , LISP_AFI_MAC ] :
  if ( ii1iI1i1 == LISP_AFI_MAC and lisp_l2_overlay == False ) : break
  if 11 - 11: i1IIi . O0
  if 9 - 9: OoooooooOO % Ii1I
  if 59 - 59: i1IIi * ooOoO0o . iIii1I11I1II1
  if 87 - 87: ooOoO0o % I1ii11iIi11i . I1IiiI
  if 42 - 42: iII111i % i11iIiiIii % o0oOOo0O0Ooo . O0 % iII111i
  ooII1111iI1I = lisp_address ( ii1iI1i1 , "" , 0 , iid )
  ooII1111iI1I . make_default_route ( ooII1111iI1I )
  OoOOO000O0o = lisp_map_cache . lookup_cache ( ooII1111iI1I , True )
  if ( OoOOO000O0o ) :
   if ( OoOOO000O0o . checkpoint_entry ) :
    lprint ( "Updating checkpoint entry for {}" . format ( green ( OoOOO000O0o . print_eid_tuple ( ) , False ) ) )
    if 72 - 72: Oo0Ooo . Oo0Ooo . IiII . Oo0Ooo
   elif ( OoOOO000O0o . do_rloc_sets_match ( rtr_list . values ( ) ) ) :
    continue
    if 80 - 80: I1Ii111 + IiII + O0 - I1Ii111 . iIii1I11I1II1
   OoOOO000O0o . delete_cache ( )
   if 53 - 53: OoO0O00 / i11iIiiIii * I1Ii111
   if 62 - 62: oO0o / Oo0Ooo / IiII + I11i * ooOoO0o
  iiii1i111i1I . append ( [ ooII1111iI1I , "" ] )
  if 84 - 84: ooOoO0o + OoOoOO00 * I1ii11iIi11i % OoooooooOO . O0
  if 27 - 27: OoO0O00 * OoooooooOO - II111iiii / o0oOOo0O0Ooo
  if 76 - 76: I11i % I1Ii111 % iII111i + IiII * iII111i + OoOoOO00
  if 83 - 83: OOooOOo . ooOoO0o / IiII
  IiI1111i1i11I = lisp_address ( ii1iI1i1 , "" , 0 , iid )
  IiI1111i1i11I . make_default_multicast_route ( IiI1111i1i11I )
  O0O0OOOo0 = lisp_map_cache . lookup_cache ( IiI1111i1i11I , True )
  if ( O0O0OOOo0 ) : O0O0OOOo0 = O0O0OOOo0 . source_cache . lookup_cache ( ooII1111iI1I , True )
  if ( O0O0OOOo0 ) : O0O0OOOo0 . delete_cache ( )
  if 73 - 73: O0 - I1IiiI + I1Ii111 . OoOoOO00 . IiII - OOooOOo
  iiii1i111i1I . append ( [ ooII1111iI1I , IiI1111i1i11I ] )
  if 13 - 13: i11iIiiIii
 if ( len ( iiii1i111i1I ) == 0 ) : return
 if 42 - 42: Oo0Ooo - I11i . OOooOOo + OoO0O00
 if 10 - 10: Oo0Ooo * OoooooooOO * OOooOOo
 if 50 - 50: ooOoO0o + oO0o
 if 74 - 74: Ii1I + OOooOOo - I11i * iIii1I11I1II1 - I1Ii111 % i11iIiiIii
 I1I11I11 = [ ]
 for o0O000o0o0 in rtr_list :
  IIiii111i11ii = rtr_list [ o0O000o0o0 ]
  IiIiI = lisp_rloc ( )
  IiIiI . rloc . copy_address ( IIiii111i11ii )
  IiIiI . priority = 254
  IiIiI . mpriority = 255
  IiIiI . rloc_name = "RTR"
  I1I11I11 . append ( IiIiI )
  if 86 - 86: OoOoOO00
  if 4 - 4: OoooooooOO * OoO0O00
 for ooII1111iI1I in iiii1i111i1I :
  OoOOO000O0o = lisp_mapping ( ooII1111iI1I [ 0 ] , ooII1111iI1I [ 1 ] , I1I11I11 )
  OoOOO000O0o . mapping_source = map_resolver
  OoOOO000O0o . map_cache_ttl = LISP_MR_TTL * 60
  OoOOO000O0o . add_cache ( )
  lprint ( "Add {} to map-cache with RTR RLOC-set: {}" . format ( green ( OoOOO000O0o . print_eid_tuple ( ) , False ) , rtr_list . keys ( ) ) )
  if 93 - 93: OoO0O00 - I1Ii111 - OoO0O00
  I1I11I11 = copy . deepcopy ( I1I11I11 )
  if 1 - 1: o0oOOo0O0Ooo . oO0o * i11iIiiIii * IiII - OoO0O00 - OoooooooOO
 return
 if 29 - 29: iIii1I11I1II1 + OoO0O00 * II111iiii * Ii1I * iII111i . O0
 if 6 - 6: I1IiiI - OoOoOO00
 if 63 - 63: OOooOOo - oO0o * I1IiiI
 if 60 - 60: II111iiii - Oo0Ooo
 if 43 - 43: I1IiiI - IiII - OOooOOo
 if 19 - 19: I1Ii111 / I1Ii111 - i1IIi
 if 99 - 99: O0
 if 37 - 37: iIii1I11I1II1 / I1Ii111 + OoO0O00
 if 85 - 85: ooOoO0o / I1IiiI
 if 7 - 7: Oo0Ooo - iIii1I11I1II1 / I1ii11iIi11i * I1IiiI + Ii1I
def lisp_process_info_reply ( source , packet , store ) :
 if 99 - 99: i11iIiiIii - I1ii11iIi11i
 if 64 - 64: IiII . OoOoOO00 . Oo0Ooo . I1Ii111 / I11i / Ii1I
 if 95 - 95: iIii1I11I1II1 . Ii1I % oO0o - I11i % IiII
 if 42 - 42: OoOoOO00 + oO0o * i1IIi + i11iIiiIii
 IIiii = lisp_info ( )
 packet = IIiii . decode ( packet )
 if ( packet == None ) : return ( [ None , None , False ] )
 if 25 - 25: Ii1I - Ii1I - I1ii11iIi11i / i1IIi . OoOoOO00 % Oo0Ooo
 IIiii . print_info ( )
 if 76 - 76: I1Ii111 / OoOoOO00
 if 61 - 61: Oo0Ooo . i1IIi
 if 78 - 78: i11iIiiIii
 if 20 - 20: Ii1I
 oo0Ii = False
 for o0O000o0o0 in IIiii . rtr_list :
  i111I11I = o0O000o0o0 . print_address_no_iid ( )
  if ( lisp_rtr_list . has_key ( i111I11I ) ) :
   if ( lisp_register_all_rtrs == False ) : continue
   if ( lisp_rtr_list [ i111I11I ] != None ) : continue
   if 72 - 72: II111iiii
  oo0Ii = True
  lisp_rtr_list [ i111I11I ] = o0O000o0o0
  if 26 - 26: Oo0Ooo
  if 14 - 14: O0
  if 63 - 63: I1IiiI . iIii1I11I1II1 . Oo0Ooo % OOooOOo - iII111i + ooOoO0o
  if 64 - 64: o0oOOo0O0Ooo / Ii1I % I1Ii111 % iII111i + OOooOOo * IiII
  if 87 - 87: I1ii11iIi11i . i1IIi - I11i + OoOoOO00 . O0
 if ( lisp_i_am_itr and oo0Ii ) :
  if ( lisp_iid_to_interface == { } ) :
   lisp_update_default_routes ( source , lisp_default_iid , lisp_rtr_list )
  else :
   for II1ii1ii11I1 in lisp_iid_to_interface . keys ( ) :
    lisp_update_default_routes ( source , int ( II1ii1ii11I1 ) , lisp_rtr_list )
    if 37 - 37: IiII
    if 65 - 65: ooOoO0o * Ii1I / I1IiiI . i1IIi % ooOoO0o . OoooooooOO
    if 17 - 17: ooOoO0o / OoO0O00 / I1IiiI / OOooOOo % IiII
    if 88 - 88: i1IIi - OoOoOO00
    if 66 - 66: OoooooooOO - OoooooooOO * I11i / II111iiii + oO0o / Ii1I
    if 7 - 7: Ii1I / iIii1I11I1II1
    if 36 - 36: iIii1I11I1II1 % i11iIiiIii
 if ( store == False ) :
  return ( [ IIiii . global_etr_rloc , IIiii . etr_port , oo0Ii ] )
  if 35 - 35: Oo0Ooo + I1IiiI - O0 - I1Ii111
  if 64 - 64: i1IIi * OoOoOO00 / II111iiii * oO0o
  if 35 - 35: i1IIi - Ii1I - Ii1I . O0 % iII111i * iII111i
  if 15 - 15: OoooooooOO . Ii1I * I1Ii111 . ooOoO0o % OoO0O00 * Oo0Ooo
  if 10 - 10: iII111i + i11iIiiIii . OOooOOo % iII111i - i1IIi
  if 10 - 10: iIii1I11I1II1 * i11iIiiIii - O0
 for i1i1iiiii1IiI in lisp_db_list :
  for IiIiI in i1i1iiiii1IiI . rloc_set :
   II11IIiii = IiIiI . rloc
   O0OOoooo0 = IiIiI . interface
   if ( O0OOoooo0 == None ) :
    if ( II11IIiii . is_null ( ) ) : continue
    if ( II11IIiii . is_local ( ) == False ) : continue
    if ( IIiii . private_etr_rloc . is_null ( ) == False and
 II11IIiii . is_exact_match ( IIiii . private_etr_rloc ) == False ) :
     continue
     if 45 - 45: oO0o % OOooOOo - IiII + o0oOOo0O0Ooo + i11iIiiIii
   elif ( IIiii . private_etr_rloc . is_dist_name ( ) ) :
    ooOO0OOO = IIiii . private_etr_rloc . address
    if ( ooOO0OOO != IiIiI . rloc_name ) : continue
    if 79 - 79: IiII % I1Ii111 . I1IiiI + O0 * oO0o * ooOoO0o
    if 38 - 38: IiII
   O0o0O0OO0o = green ( i1i1iiiii1IiI . eid . print_prefix ( ) , False )
   I111I1iii11 = red ( II11IIiii . print_address_no_iid ( ) , False )
   if 78 - 78: Oo0Ooo * I1ii11iIi11i % OOooOOo / Oo0Ooo + I1ii11iIi11i * IiII
   iIIiIIII = IIiii . global_etr_rloc . is_exact_match ( II11IIiii )
   if ( IiIiI . translated_port == 0 and iIIiIIII ) :
    lprint ( "No NAT for {} ({}), EID-prefix {}" . format ( I111I1iii11 ,
 O0OOoooo0 , O0o0O0OO0o ) )
    continue
    if 62 - 62: OoOoOO00
    if 48 - 48: OoooooooOO . i11iIiiIii * oO0o
    if 41 - 41: ooOoO0o
    if 89 - 89: i11iIiiIii . i11iIiiIii . IiII
    if 29 - 29: o0oOOo0O0Ooo * iIii1I11I1II1 . iIii1I11I1II1
   i1I1IIIIi = IIiii . global_etr_rloc
   oO0O00 = IiIiI . translated_rloc
   if ( oO0O00 . is_exact_match ( i1I1IIIIi ) and
 IIiii . etr_port == IiIiI . translated_port ) : continue
   if 88 - 88: OoO0O00 % I1Ii111 % I1ii11iIi11i % OoO0O00 . I11i * I1ii11iIi11i
   lprint ( "Store translation {}:{} for {} ({}), EID-prefix {}" . format ( red ( IIiii . global_etr_rloc . print_address_no_iid ( ) , False ) ,
   # OoO0O00 / i11iIiiIii + ooOoO0o / OoOoOO00
 IIiii . etr_port , I111I1iii11 , O0OOoooo0 , O0o0O0OO0o ) )
   if 15 - 15: II111iiii - IiII
   IiIiI . store_translated_rloc ( IIiii . global_etr_rloc ,
 IIiii . etr_port )
   if 74 - 74: i1IIi * OoooooooOO . Oo0Ooo . I1IiiI / o0oOOo0O0Ooo . OoOoOO00
   if 50 - 50: I1ii11iIi11i / iIii1I11I1II1 - Oo0Ooo - i11iIiiIii % o0oOOo0O0Ooo - ooOoO0o
 return ( [ IIiii . global_etr_rloc , IIiii . etr_port , oo0Ii ] )
 if 92 - 92: OoooooooOO - I1ii11iIi11i . I11i / O0 % iII111i
 if 96 - 96: I1IiiI . oO0o % O0
 if 19 - 19: iIii1I11I1II1 + I1Ii111 / OoooooooOO % OOooOOo - i1IIi + I11i
 if 87 - 87: OoooooooOO
 if 97 - 97: ooOoO0o * IiII / iIii1I11I1II1
 if 65 - 65: i1IIi - i11iIiiIii + oO0o % I1IiiI - OoO0O00 % ooOoO0o
 if 23 - 23: o0oOOo0O0Ooo . o0oOOo0O0Ooo - iIii1I11I1II1 / o0oOOo0O0Ooo
 if 65 - 65: I1Ii111 + I1Ii111 . I1ii11iIi11i . OoOoOO00 % o0oOOo0O0Ooo * o0oOOo0O0Ooo
def lisp_test_mr ( lisp_sockets , port ) :
 return
 lprint ( "Test Map-Resolvers" )
 if 2 - 2: oO0o % iII111i + I1ii11iIi11i / II111iiii * I1ii11iIi11i
 ii1Ii = lisp_address ( LISP_AFI_IPV4 , "" , 0 , 0 )
 iiOo0o0o = lisp_address ( LISP_AFI_IPV6 , "" , 0 , 0 )
 if 98 - 98: O0 % iII111i + II111iiii
 if 13 - 13: I1IiiI * oO0o - o0oOOo0O0Ooo
 if 23 - 23: iIii1I11I1II1 + oO0o . oO0o / o0oOOo0O0Ooo
 if 77 - 77: i1IIi * o0oOOo0O0Ooo * IiII
 ii1Ii . store_address ( "10.0.0.1" )
 lisp_send_map_request ( lisp_sockets , port , None , ii1Ii , None )
 ii1Ii . store_address ( "192.168.0.1" )
 lisp_send_map_request ( lisp_sockets , port , None , ii1Ii , None )
 if 24 - 24: i11iIiiIii / iIii1I11I1II1 / iII111i
 if 31 - 31: OOooOOo . iIii1I11I1II1 - oO0o
 if 36 - 36: O0
 if 30 - 30: i11iIiiIii * Oo0Ooo . IiII
 iiOo0o0o . store_address ( "0100::1" )
 lisp_send_map_request ( lisp_sockets , port , None , iiOo0o0o , None )
 iiOo0o0o . store_address ( "8000::1" )
 lisp_send_map_request ( lisp_sockets , port , None , iiOo0o0o , None )
 if 65 - 65: oO0o * IiII * OOooOOo / OoooooooOO % I11i / I1Ii111
 if 21 - 21: i1IIi * iII111i + OoO0O00
 if 27 - 27: I11i / oO0o . iII111i + o0oOOo0O0Ooo - OOooOOo
 if 85 - 85: OoooooooOO
 O0o0O00O0oo00 = threading . Timer ( LISP_TEST_MR_INTERVAL , lisp_test_mr ,
 [ lisp_sockets , port ] )
 O0o0O00O0oo00 . start ( )
 return
 if 73 - 73: ooOoO0o * iII111i % O0
 if 46 - 46: OoOoOO00 + OoooooooOO * OOooOOo
 if 52 - 52: II111iiii . Oo0Ooo
 if 14 - 14: I11i
 if 67 - 67: OoOoOO00
 if 50 - 50: Oo0Ooo
 if 80 - 80: OoOoOO00 * OoO0O00 + i11iIiiIii + O0 + II111iiii
 if 13 - 13: OOooOOo / O0
 if 19 - 19: iIii1I11I1II1 + IiII * I11i * II111iiii + o0oOOo0O0Ooo + i11iIiiIii
 if 69 - 69: iIii1I11I1II1 . II111iiii
 if 36 - 36: I1IiiI * i1IIi + OoOoOO00
 if 63 - 63: OoOoOO00 - iII111i
 if 83 - 83: i1IIi / iII111i % ooOoO0o % i11iIiiIii + I1ii11iIi11i
def lisp_update_local_rloc ( rloc ) :
 if ( rloc . interface == None ) : return
 if 82 - 82: iIii1I11I1II1 / OOooOOo
 oOo00Ooo0o0 = lisp_get_interface_address ( rloc . interface )
 if ( oOo00Ooo0o0 == None ) : return
 if 7 - 7: OoooooooOO
 O0oO0OoOO00O = rloc . rloc . print_address_no_iid ( )
 o0o0Oo0O0O0o = oOo00Ooo0o0 . print_address_no_iid ( )
 if 13 - 13: iIii1I11I1II1
 if ( O0oO0OoOO00O == o0o0Oo0O0O0o ) : return
 if 10 - 10: I1IiiI * iII111i * ooOoO0o . IiII
 lprint ( "Local interface address changed on {} from {} to {}" . format ( rloc . interface , O0oO0OoOO00O , o0o0Oo0O0O0o ) )
 if 7 - 7: iIii1I11I1II1
 if 60 - 60: OOooOOo . Ii1I . Ii1I % II111iiii + OoO0O00
 rloc . rloc . copy_address ( oOo00Ooo0o0 )
 lisp_myrlocs [ 0 ] = oOo00Ooo0o0
 return
 if 71 - 71: OoooooooOO - OoooooooOO - OoO0O00
 if 24 - 24: iII111i / Oo0Ooo - I1ii11iIi11i + o0oOOo0O0Ooo
 if 44 - 44: OoOoOO00 + I1IiiI . I1ii11iIi11i / i1IIi + II111iiii . Oo0Ooo
 if 39 - 39: o0oOOo0O0Ooo
 if 64 - 64: oO0o - i11iIiiIii
 if 62 - 62: OoooooooOO - OoooooooOO / OoO0O00 - II111iiii . iIii1I11I1II1
 if 2 - 2: O0 + o0oOOo0O0Ooo % OOooOOo . ooOoO0o % i1IIi
 if 21 - 21: OoOoOO00 / OoooooooOO + I1Ii111 - IiII
def lisp_update_encap_port ( mc ) :
 for II11IIiii in mc . rloc_set :
  oOOoO = lisp_get_nat_info ( II11IIiii . rloc , II11IIiii . rloc_name )
  if ( oOOoO == None ) : continue
  if ( II11IIiii . translated_port == oOOoO . port ) : continue
  if 62 - 62: Oo0Ooo % iII111i + OoooooooOO - I1ii11iIi11i % iII111i % iIii1I11I1II1
  lprint ( ( "Encap-port changed from {} to {} for RLOC {}, " + "EID-prefix {}" ) . format ( II11IIiii . translated_port , oOOoO . port ,
  # Oo0Ooo % II111iiii * Ii1I + II111iiii
 red ( II11IIiii . rloc . print_address_no_iid ( ) , False ) ,
 green ( mc . print_eid_tuple ( ) , False ) ) )
  if 9 - 9: I1Ii111
  II11IIiii . store_translated_rloc ( II11IIiii . rloc , oOOoO . port )
  if 69 - 69: i1IIi + ooOoO0o + Ii1I
 return
 if 88 - 88: OoOoOO00 + iII111i % O0 + OOooOOo / OoooooooOO / OOooOOo
 if 95 - 95: ooOoO0o . Oo0Ooo % IiII + iII111i
 if 16 - 16: I11i * OoO0O00 % o0oOOo0O0Ooo - O0 % II111iiii - I1IiiI
 if 72 - 72: OoooooooOO * OoOoOO00 . OOooOOo + Ii1I . OOooOOo / II111iiii
 if 8 - 8: i1IIi
 if 1 - 1: OoOoOO00 . OoO0O00 . OoO0O00 * O0
 if 97 - 97: OoooooooOO % ooOoO0o . I1Ii111 / iII111i
 if 59 - 59: II111iiii + O0 . I1ii11iIi11i . Oo0Ooo * OoO0O00
 if 35 - 35: oO0o / I1Ii111 * OOooOOo + OoooooooOO . IiII
 if 1 - 1: I1IiiI + I1Ii111 / OOooOOo . Ii1I . oO0o / I1ii11iIi11i
 if 54 - 54: OOooOOo
 if 86 - 86: oO0o * Oo0Ooo / OOooOOo
def lisp_timeout_map_cache_entry ( mc , delete_list ) :
 if ( mc . map_cache_ttl == None ) :
  lisp_update_encap_port ( mc )
  return ( [ True , delete_list ] )
  if 18 - 18: II111iiii - I1Ii111
  if 13 - 13: i11iIiiIii - O0 % OoOoOO00 + OOooOOo * ooOoO0o
 II1iI111 = lisp_get_timestamp ( )
 if 55 - 55: i1IIi - OOooOOo / I11i * Ii1I
 if 20 - 20: OoOoOO00 * iIii1I11I1II1 % O0 - i1IIi
 if 51 - 51: I1ii11iIi11i * Ii1I - oO0o / O0 * OoooooooOO
 if 12 - 12: i1IIi / iIii1I11I1II1 / O0 * OoO0O00
 if 15 - 15: i11iIiiIii / IiII + Ii1I % OOooOOo % I1ii11iIi11i * oO0o
 if 24 - 24: OOooOOo / OOooOOo + I11i / iII111i . oO0o - iII111i
 if ( mc . last_refresh_time + mc . map_cache_ttl > II1iI111 ) :
  if ( mc . action == LISP_NO_ACTION ) : lisp_update_encap_port ( mc )
  return ( [ True , delete_list ] )
  if 59 - 59: I1ii11iIi11i % II111iiii - i11iIiiIii - I1Ii111
  if 34 - 34: II111iiii + iII111i / IiII
  if 47 - 47: OoO0O00
  if 40 - 40: o0oOOo0O0Ooo / iII111i . o0oOOo0O0Ooo
  if 63 - 63: o0oOOo0O0Ooo * iIii1I11I1II1 * II111iiii . OoO0O00 - oO0o / OoOoOO00
 I1IiIii11I = lisp_print_elapsed ( mc . last_refresh_time )
 oo0i11i11ii11 = mc . print_eid_tuple ( )
 lprint ( "Map-cache entry for EID-prefix {} has {}, had uptime of {}" . format ( green ( oo0i11i11ii11 , False ) , bold ( "timed out" , False ) , I1IiIii11I ) )
 if 78 - 78: i11iIiiIii / OoO0O00 / i1IIi . i11iIiiIii
 if 100 - 100: II111iiii . IiII . I11i
 if 60 - 60: OoOoOO00 % OOooOOo * i1IIi
 if 3 - 3: OoooooooOO
 if 75 - 75: OoooooooOO * I1Ii111 * o0oOOo0O0Ooo + I1ii11iIi11i . iIii1I11I1II1 / O0
 delete_list . append ( mc )
 return ( [ True , delete_list ] )
 if 23 - 23: oO0o - O0 * IiII + i11iIiiIii * Ii1I
 if 8 - 8: ooOoO0o / II111iiii . I1ii11iIi11i * ooOoO0o % oO0o
 if 36 - 36: I1ii11iIi11i % OOooOOo - ooOoO0o - I11i + I1IiiI
 if 37 - 37: I1ii11iIi11i * IiII
 if 65 - 65: OOooOOo / O0 . I1ii11iIi11i % i1IIi % Oo0Ooo
 if 36 - 36: i11iIiiIii - OOooOOo + iII111i + iII111i * I11i * oO0o
 if 14 - 14: O0 - iII111i * I1Ii111 - I1IiiI + IiII
 if 46 - 46: OoooooooOO * OoO0O00 . I1Ii111
def lisp_timeout_map_cache_walk ( mc , parms ) :
 iII1I11II = parms [ 0 ]
 O0oo0OoOo0oOooOO = parms [ 1 ]
 if 22 - 22: iIii1I11I1II1 . I11i
 if 21 - 21: I1IiiI % Oo0Ooo - II111iiii / I1IiiI . OoOoOO00 - o0oOOo0O0Ooo
 if 23 - 23: OoOoOO00 / O0 * OoOoOO00 . I1IiiI + Oo0Ooo . iII111i
 if 1 - 1: i11iIiiIii * OoO0O00 - OoooooooOO + OoooooooOO
 if ( mc . group . is_null ( ) ) :
  IIiIIiiIIi , iII1I11II = lisp_timeout_map_cache_entry ( mc , iII1I11II )
  if ( iII1I11II == [ ] or mc != iII1I11II [ - 1 ] ) :
   O0oo0OoOo0oOooOO = lisp_write_checkpoint_entry ( O0oo0OoOo0oOooOO , mc )
   if 31 - 31: OoooooooOO - OoOoOO00 * II111iiii % ooOoO0o - ooOoO0o / i11iIiiIii
  return ( [ IIiIIiiIIi , parms ] )
  if 8 - 8: I1IiiI . i1IIi - I11i
  if 85 - 85: OOooOOo * IiII % O0 / I1ii11iIi11i
 if ( mc . source_cache == None ) : return ( [ True , parms ] )
 if 17 - 17: Oo0Ooo / i11iIiiIii / I11i - I1Ii111
 if 3 - 3: I1Ii111 - Oo0Ooo / iIii1I11I1II1
 if 71 - 71: o0oOOo0O0Ooo + i11iIiiIii + OoooooooOO % OoOoOO00 - I1ii11iIi11i / OoooooooOO
 if 26 - 26: II111iiii
 if 41 - 41: Oo0Ooo . OoOoOO00 . iII111i / i11iIiiIii
 parms = mc . source_cache . walk_cache ( lisp_timeout_map_cache_entry , parms )
 return ( [ True , parms ] )
 if 65 - 65: iII111i * o0oOOo0O0Ooo * OoooooooOO + I11i + oO0o % OoO0O00
 if 1 - 1: I1ii11iIi11i . ooOoO0o
 if 54 - 54: OoOoOO00 % I1IiiI . ooOoO0o + IiII / i11iIiiIii / o0oOOo0O0Ooo
 if 51 - 51: OoOoOO00 / Ii1I . I1IiiI / Ii1I . II111iiii - iIii1I11I1II1
 if 78 - 78: I11i
 if 42 - 42: Ii1I
 if 50 - 50: iIii1I11I1II1 / Ii1I . ooOoO0o / ooOoO0o * OoOoOO00 * iII111i
def lisp_timeout_map_cache ( lisp_map_cache ) :
 oO = [ [ ] , [ ] ]
 oO = lisp_map_cache . walk_cache ( lisp_timeout_map_cache_walk , oO )
 if 15 - 15: o0oOOo0O0Ooo % II111iiii + I1IiiI
 if 21 - 21: I1ii11iIi11i - ooOoO0o
 if 81 - 81: iII111i / i11iIiiIii / I1Ii111
 if 70 - 70: I1ii11iIi11i / i11iIiiIii
 if 90 - 90: II111iiii / OoOoOO00 . Ii1I . OoooooooOO
 iII1I11II = oO [ 0 ]
 for OoOOO000O0o in iII1I11II : OoOOO000O0o . delete_cache ( )
 if 76 - 76: OoooooooOO
 if 78 - 78: IiII % i11iIiiIii
 if 23 - 23: iIii1I11I1II1 - o0oOOo0O0Ooo - Ii1I % OOooOOo
 if 100 - 100: oO0o . OoO0O00 . i11iIiiIii % II111iiii * IiII
 O0oo0OoOo0oOooOO = oO [ 1 ]
 lisp_checkpoint ( O0oo0OoOo0oOooOO )
 return
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
def lisp_store_nat_info ( hostname , rloc , port ) :
 i111I11I = rloc . print_address_no_iid ( )
 iIIiO00o0o = "{} NAT state for {}, RLOC {}, port {}" . format ( "{}" ,
 blue ( hostname , False ) , red ( i111I11I , False ) , port )
 if 92 - 92: iIii1I11I1II1 - Oo0Ooo - I1IiiI - OOooOOo * I1Ii111
 i1ii1Iii1 = lisp_nat_info ( i111I11I , hostname , port )
 if 59 - 59: i1IIi * Oo0Ooo / Ii1I % OoO0O00
 if ( lisp_nat_state_info . has_key ( hostname ) == False ) :
  lisp_nat_state_info [ hostname ] = [ i1ii1Iii1 ]
  lprint ( iIIiO00o0o . format ( "Store initial" ) )
  return ( True )
  if 88 - 88: i1IIi / II111iiii
  if 91 - 91: I1IiiI * I1Ii111 * i11iIiiIii - oO0o - IiII + I1ii11iIi11i
  if 99 - 99: OoO0O00 % o0oOOo0O0Ooo
  if 3 - 3: OOooOOo / OoOoOO00 % iIii1I11I1II1
  if 47 - 47: ooOoO0o . i11iIiiIii / OoO0O00
  if 48 - 48: O0
 oOOoO = lisp_nat_state_info [ hostname ] [ 0 ]
 if ( oOOoO . address == i111I11I and oOOoO . port == port ) :
  oOOoO . uptime = lisp_get_timestamp ( )
  lprint ( iIIiO00o0o . format ( "Refresh existing" ) )
  return ( False )
  if 89 - 89: i11iIiiIii % OoO0O00 . OoOoOO00 + Oo0Ooo + OoOoOO00
  if 53 - 53: Ii1I / OoOoOO00 % iII111i * OoooooooOO + Oo0Ooo
  if 70 - 70: OoO0O00 % OoO0O00 * OoooooooOO
  if 96 - 96: ooOoO0o * Ii1I + I11i + II111iiii * I1IiiI / iII111i
  if 40 - 40: OoooooooOO - I11i % OOooOOo - I1IiiI . I1IiiI + Ii1I
  if 97 - 97: OOooOOo . OoooooooOO . OOooOOo . i11iIiiIii
  if 71 - 71: oO0o + I1ii11iIi11i * I1ii11iIi11i
 oOOOo0o0o = None
 for oOOoO in lisp_nat_state_info [ hostname ] :
  if ( oOOoO . address == i111I11I and oOOoO . port == port ) :
   oOOOo0o0o = oOOoO
   break
   if 92 - 92: i11iIiiIii % OOooOOo
   if 61 - 61: O0 * OoooooooOO % O0 * Ii1I
   if 3 - 3: IiII + OoooooooOO - i1IIi
 if ( oOOOo0o0o == None ) :
  lprint ( iIIiO00o0o . format ( "Store new" ) )
 else :
  lisp_nat_state_info [ hostname ] . remove ( oOOOo0o0o )
  lprint ( iIIiO00o0o . format ( "Use previous" ) )
  if 94 - 94: ooOoO0o / iIii1I11I1II1 + I11i + I1ii11iIi11i
  if 67 - 67: IiII / o0oOOo0O0Ooo . O0
 Ii1 = lisp_nat_state_info [ hostname ]
 lisp_nat_state_info [ hostname ] = [ i1ii1Iii1 ] + Ii1
 return ( True )
 if 48 - 48: Oo0Ooo + oO0o % ooOoO0o + i1IIi / o0oOOo0O0Ooo
 if 46 - 46: OoO0O00 . oO0o
 if 31 - 31: O0 * OoOoOO00 + oO0o
 if 25 - 25: II111iiii / OoooooooOO / Oo0Ooo % iII111i
 if 57 - 57: Ii1I / oO0o . I1IiiI % I1Ii111
 if 8 - 8: oO0o
 if 46 - 46: I1Ii111 + IiII + II111iiii . o0oOOo0O0Ooo + i11iIiiIii
 if 97 - 97: o0oOOo0O0Ooo % OoOoOO00 * O0 / iIii1I11I1II1 * OoO0O00 / i11iIiiIii
def lisp_get_nat_info ( rloc , hostname ) :
 if ( lisp_nat_state_info . has_key ( hostname ) == False ) : return ( None )
 if 1 - 1: OoooooooOO . Ii1I
 i111I11I = rloc . print_address_no_iid ( )
 for oOOoO in lisp_nat_state_info [ hostname ] :
  if ( oOOoO . address == i111I11I ) : return ( oOOoO )
  if 68 - 68: Ii1I
 return ( None )
 if 98 - 98: iII111i
 if 33 - 33: OoO0O00 - ooOoO0o % O0 % iIii1I11I1II1 * iII111i - iII111i
 if 27 - 27: i11iIiiIii + I1ii11iIi11i + i1IIi
 if 67 - 67: o0oOOo0O0Ooo
 if 58 - 58: IiII % o0oOOo0O0Ooo + i1IIi
 if 33 - 33: II111iiii
 if 61 - 61: I1Ii111
 if 56 - 56: I1ii11iIi11i - OoooooooOO
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
def lisp_build_info_requests ( lisp_sockets , dest , port ) :
 if ( lisp_nat_traversal == False ) : return
 if 14 - 14: I1Ii111 + Oo0Ooo
 if 35 - 35: i11iIiiIii * Ii1I
 if 100 - 100: O0 . iII111i / iIii1I11I1II1
 if 47 - 47: ooOoO0o + OoOoOO00
 if 67 - 67: IiII - I1ii11iIi11i * i1IIi - ooOoO0o
 if 91 - 91: I11i
 oOoo0 = [ ]
 o00 = [ ]
 if ( dest == None ) :
  for OOO0o0o in lisp_map_resolvers_list . values ( ) :
   o00 . append ( OOO0o0o . map_resolver )
   if 75 - 75: iII111i * IiII - iIii1I11I1II1 + i1IIi + oO0o - O0
  oOoo0 = o00
  if ( oOoo0 == [ ] ) :
   for oOooOO in lisp_map_servers_list . values ( ) :
    oOoo0 . append ( oOooOO . map_server )
    if 15 - 15: OoooooooOO . OoOoOO00 / iII111i - IiII % iII111i . ooOoO0o
    if 78 - 78: OoOoOO00 / i1IIi
  if ( oOoo0 == [ ] ) : return
 else :
  oOoo0 . append ( dest )
  if 87 - 87: I1ii11iIi11i . O0 / I1ii11iIi11i
  if 35 - 35: IiII % Oo0Ooo * Ii1I . IiII
  if 16 - 16: I1ii11iIi11i % I1IiiI + Ii1I * I11i + i1IIi
  if 14 - 14: iII111i / ooOoO0o % IiII - I1IiiI . Oo0Ooo
  if 30 - 30: O0 . OOooOOo
 iI111I = { }
 for i1i1iiiii1IiI in lisp_db_list :
  for IiIiI in i1i1iiiii1IiI . rloc_set :
   lisp_update_local_rloc ( IiIiI )
   if ( IiIiI . rloc . is_null ( ) ) : continue
   if ( IiIiI . interface == None ) : continue
   if 23 - 23: i1IIi + OoooooooOO * OOooOOo . Oo0Ooo
   oOo00Ooo0o0 = IiIiI . rloc . print_address_no_iid ( )
   if ( oOo00Ooo0o0 in iI111I ) : continue
   iI111I [ oOo00Ooo0o0 ] = IiIiI . interface
   if 83 - 83: OoooooooOO
   if 53 - 53: o0oOOo0O0Ooo - Oo0Ooo / IiII + O0
 if ( iI111I == { } ) :
  lprint ( 'Suppress Info-Request, no "interface = <device>" RLOC ' + "found in any database-mappings" )
  if 88 - 88: Oo0Ooo % I1Ii111 * O0 - i1IIi * OoO0O00
  return
  if 74 - 74: Oo0Ooo % iIii1I11I1II1 + OOooOOo
  if 50 - 50: OoO0O00 . OoooooooOO
  if 31 - 31: OoO0O00
  if 55 - 55: OoOoOO00 + I1Ii111 * o0oOOo0O0Ooo - I1ii11iIi11i + OoOoOO00
  if 6 - 6: II111iiii % iIii1I11I1II1 * I1Ii111
  if 2 - 2: IiII - I1Ii111 . iIii1I11I1II1 - Ii1I * I11i
 for oOo00Ooo0o0 in iI111I :
  O0OOoooo0 = iI111I [ oOo00Ooo0o0 ]
  i1 = red ( oOo00Ooo0o0 , False )
  lprint ( "Build Info-Request for private address {} ({})" . format ( i1 ,
 O0OOoooo0 ) )
  iiiIiIIIiiiIiI1 = O0OOoooo0 if len ( iI111I ) > 1 else None
  for dest in oOoo0 :
   lisp_send_info_request ( lisp_sockets , dest , port , iiiIiIIIiiiIiI1 )
   if 58 - 58: i1IIi % iIii1I11I1II1 % i11iIiiIii - o0oOOo0O0Ooo + ooOoO0o
   if 23 - 23: Oo0Ooo % Oo0Ooo / IiII
   if 63 - 63: I11i % Oo0Ooo * I1Ii111 - Oo0Ooo % i11iIiiIii . II111iiii
   if 44 - 44: I11i . I1Ii111 . I1ii11iIi11i . oO0o
   if 1 - 1: I11i % II111iiii / OoO0O00 + OoO0O00
   if 46 - 46: Oo0Ooo * Ii1I / IiII % O0 * iII111i
 if ( o00 != [ ] ) :
  for OOO0o0o in lisp_map_resolvers_list . values ( ) :
   OOO0o0o . resolve_dns_name ( )
   if 74 - 74: OoooooooOO + Ii1I
   if 100 - 100: I1IiiI
 return
 if 59 - 59: I1IiiI - OoOoOO00 * ooOoO0o / O0
 if 54 - 54: Oo0Ooo % iIii1I11I1II1 * Oo0Ooo
 if 80 - 80: I1ii11iIi11i - I1ii11iIi11i
 if 26 - 26: I1ii11iIi11i - I1IiiI * I1Ii111 % iIii1I11I1II1
 if 77 - 77: o0oOOo0O0Ooo + I1Ii111 . OOooOOo . i1IIi . I1IiiI
 if 100 - 100: ooOoO0o . i11iIiiIii + Ii1I - OOooOOo - i11iIiiIii - OoooooooOO
 if 42 - 42: OoOoOO00 . I1IiiI / OoOoOO00 / I1ii11iIi11i . OoO0O00
 if 67 - 67: Ii1I - O0 . OoooooooOO . I1Ii111 . o0oOOo0O0Ooo
def lisp_valid_address_format ( kw , value ) :
 if ( kw != "address" ) : return ( True )
 if 73 - 73: I11i - oO0o . I1Ii111 + oO0o
 if 48 - 48: IiII . IiII * o0oOOo0O0Ooo * II111iiii % ooOoO0o
 if 40 - 40: I1ii11iIi11i
 if 76 - 76: Oo0Ooo - I11i
 if 82 - 82: OoO0O00 % oO0o . I11i / O0 - I1Ii111
 if ( value [ 0 ] == "'" and value [ - 1 ] == "'" ) : return ( True )
 if 39 - 39: I1IiiI
 if 8 - 8: IiII * i1IIi * i1IIi * O0
 if 69 - 69: Oo0Ooo
 if 48 - 48: iII111i
 if ( value . find ( "." ) != - 1 ) :
  oOo00Ooo0o0 = value . split ( "." )
  if ( len ( oOo00Ooo0o0 ) != 4 ) : return ( False )
  if 11 - 11: i11iIiiIii * OoOoOO00 . OoO0O00
  for iII111i1i1 in oOo00Ooo0o0 :
   if ( iII111i1i1 . isdigit ( ) == False ) : return ( False )
   if ( int ( iII111i1i1 ) > 255 ) : return ( False )
   if 6 - 6: ooOoO0o * II111iiii / iII111i . o0oOOo0O0Ooo
  return ( True )
  if 18 - 18: oO0o * IiII % oO0o
  if 8 - 8: OoO0O00 * iII111i % OoooooooOO - I11i / I1IiiI % oO0o
  if 50 - 50: iIii1I11I1II1 + i1IIi * Oo0Ooo * OoooooooOO - II111iiii
  if 79 - 79: o0oOOo0O0Ooo * O0
  if 49 - 49: I11i / OoO0O00 % IiII
 if ( value . find ( "-" ) != - 1 ) :
  oOo00Ooo0o0 = value . split ( "-" )
  for oo0O0oO0O0O in [ "N" , "S" , "W" , "E" ] :
   if ( oo0O0oO0O0O in oOo00Ooo0o0 ) :
    if ( len ( oOo00Ooo0o0 ) < 8 ) : return ( False )
    return ( True )
    if 62 - 62: oO0o % oO0o / o0oOOo0O0Ooo + I1IiiI + OOooOOo
    if 45 - 45: O0 . OoO0O00 % OOooOOo + iIii1I11I1II1 * iII111i % OoO0O00
    if 62 - 62: I1Ii111 - ooOoO0o + iIii1I11I1II1 % OOooOOo + Oo0Ooo
    if 59 - 59: I1IiiI * II111iiii . i1IIi - i1IIi
    if 23 - 23: oO0o * OoO0O00 % O0 . OoOoOO00 * Oo0Ooo
    if 69 - 69: OoOoOO00 % I1ii11iIi11i % II111iiii * oO0o
    if 100 - 100: i11iIiiIii . IiII - I1IiiI + I1Ii111
 if ( value . find ( "-" ) != - 1 ) :
  oOo00Ooo0o0 = value . split ( "-" )
  if ( len ( oOo00Ooo0o0 ) != 3 ) : return ( False )
  if 29 - 29: Oo0Ooo . I1IiiI % ooOoO0o * I1ii11iIi11i . iII111i
  for iI1i1iIi1 in oOo00Ooo0o0 :
   try : int ( iI1i1iIi1 , 16 )
   except : return ( False )
   if 89 - 89: O0 - OoO0O00
  return ( True )
  if 8 - 8: I1ii11iIi11i / oO0o - OoooooooOO + ooOoO0o + o0oOOo0O0Ooo % i11iIiiIii
  if 32 - 32: O0 + IiII
  if 93 - 93: OoOoOO00 - I11i / iII111i - iIii1I11I1II1 + I11i % oO0o
  if 24 - 24: Ii1I / iIii1I11I1II1 + o0oOOo0O0Ooo
  if 17 - 17: OOooOOo
 if ( value . find ( ":" ) != - 1 ) :
  oOo00Ooo0o0 = value . split ( ":" )
  if ( len ( oOo00Ooo0o0 ) < 2 ) : return ( False )
  if 75 - 75: Ii1I / i1IIi % I1ii11iIi11i . Ii1I
  iiI1i111111II = False
  O0oO = 0
  for iI1i1iIi1 in oOo00Ooo0o0 :
   O0oO += 1
   if ( iI1i1iIi1 == "" ) :
    if ( iiI1i111111II ) :
     if ( len ( oOo00Ooo0o0 ) == O0oO ) : break
     if ( O0oO > 2 ) : return ( False )
     if 94 - 94: o0oOOo0O0Ooo . iIii1I11I1II1
    iiI1i111111II = True
    continue
    if 47 - 47: Ii1I % II111iiii
   try : int ( iI1i1iIi1 , 16 )
   except : return ( False )
   if 88 - 88: OoOoOO00 / oO0o - OoOoOO00 / OoOoOO00 % II111iiii
  return ( True )
  if 47 - 47: i11iIiiIii . iII111i + o0oOOo0O0Ooo % iII111i
  if 93 - 93: OoO0O00 / i11iIiiIii / oO0o - o0oOOo0O0Ooo
  if 56 - 56: I11i + oO0o . i1IIi - II111iiii - o0oOOo0O0Ooo + OOooOOo
  if 24 - 24: ooOoO0o
  if 7 - 7: ooOoO0o . OoooooooOO . iII111i * II111iiii . II111iiii / OOooOOo
 if ( value [ 0 ] == "+" ) :
  oOo00Ooo0o0 = value [ 1 : : ]
  for I1iI1iI1I in oOo00Ooo0o0 :
   if ( I1iI1iI1I . isdigit ( ) == False ) : return ( False )
   if 59 - 59: oO0o + i1IIi - IiII % OOooOOo % iIii1I11I1II1
  return ( True )
  if 71 - 71: OoO0O00
 return ( False )
 if 72 - 72: II111iiii + o0oOOo0O0Ooo / i1IIi * Oo0Ooo / i1IIi
 if 52 - 52: I1Ii111 % OoO0O00 . I1Ii111 * I1ii11iIi11i * OoOoOO00 + i1IIi
 if 54 - 54: Ii1I / I1IiiI
 if 7 - 7: iIii1I11I1II1 . O0 + OOooOOo . Ii1I * Oo0Ooo
 if 25 - 25: I1Ii111 . Oo0Ooo % II111iiii . IiII - O0
 if 18 - 18: oO0o * OOooOOo
 if 19 - 19: iIii1I11I1II1 / I1ii11iIi11i - I1ii11iIi11i / iIii1I11I1II1
 if 42 - 42: iIii1I11I1II1 / OOooOOo - O0 * OoooooooOO / i1IIi
 if 33 - 33: OOooOOo . o0oOOo0O0Ooo % OoO0O00 - I1Ii111 . OoooooooOO
 if 96 - 96: II111iiii % I11i / Ii1I - i11iIiiIii
 if 63 - 63: I1IiiI
 if 15 - 15: iIii1I11I1II1 - I1ii11iIi11i % OoO0O00 * II111iiii / I11i + I11i
def lisp_process_api ( process , lisp_socket , data_structure ) :
 iI1ii , oO = data_structure . split ( "%" )
 if 61 - 61: OoooooooOO + OoOoOO00 + I1ii11iIi11i - iIii1I11I1II1 . I11i / II111iiii
 lprint ( "Process API request '{}', parameters: '{}'" . format ( iI1ii ,
 oO ) )
 if 79 - 79: II111iiii - OoO0O00 . iIii1I11I1II1
 i11i111i1 = [ ]
 if ( iI1ii == "map-cache" ) :
  if ( oO == "" ) :
   i11i111i1 = lisp_map_cache . walk_cache ( lisp_process_api_map_cache , i11i111i1 )
  else :
   i11i111i1 = lisp_process_api_map_cache_entry ( json . loads ( oO ) )
   if 30 - 30: OoO0O00
   if 73 - 73: OoO0O00 % oO0o - O0 * o0oOOo0O0Ooo
 if ( iI1ii == "site-cache" ) :
  if ( oO == "" ) :
   i11i111i1 = lisp_sites_by_eid . walk_cache ( lisp_process_api_site_cache ,
 i11i111i1 )
  else :
   i11i111i1 = lisp_process_api_site_cache_entry ( json . loads ( oO ) )
   if 94 - 94: IiII % OoO0O00
   if 39 - 39: OoooooooOO % i11iIiiIii - iIii1I11I1II1 * I1Ii111
 if ( iI1ii == "map-server" ) :
  oO = { } if ( oO == "" ) else json . loads ( oO )
  i11i111i1 = lisp_process_api_ms_or_mr ( True , oO )
  if 92 - 92: ooOoO0o
 if ( iI1ii == "map-resolver" ) :
  oO = { } if ( oO == "" ) else json . loads ( oO )
  i11i111i1 = lisp_process_api_ms_or_mr ( False , oO )
  if 68 - 68: IiII % I1IiiI % OoooooooOO
 if ( iI1ii == "database-mapping" ) :
  i11i111i1 = lisp_process_api_database_mapping ( )
  if 69 - 69: O0 . ooOoO0o * iII111i - iII111i % oO0o
  if 24 - 24: I1Ii111
  if 72 - 72: Oo0Ooo - I1ii11iIi11i
  if 75 - 75: OoOoOO00 . OOooOOo . I1IiiI - iIii1I11I1II1 * OoOoOO00 % i11iIiiIii
  if 41 - 41: o0oOOo0O0Ooo / ooOoO0o - i11iIiiIii
 i11i111i1 = json . dumps ( i11i111i1 )
 OOO000OOOO0oO = lisp_api_ipc ( process , i11i111i1 )
 lisp_ipc ( OOO000OOOO0oO , lisp_socket , "lisp-core" )
 return
 if 63 - 63: ooOoO0o % OoO0O00 % ooOoO0o
 if 28 - 28: IiII * I1Ii111 * o0oOOo0O0Ooo + ooOoO0o - IiII / IiII
 if 73 - 73: iIii1I11I1II1 . I1ii11iIi11i + OOooOOo
 if 51 - 51: I11i % Oo0Ooo * OOooOOo % OoooooooOO - OoOoOO00 % Ii1I
 if 60 - 60: OoOoOO00 - IiII + OoO0O00
 if 77 - 77: iIii1I11I1II1
 if 92 - 92: IiII
def lisp_process_api_map_cache ( mc , data ) :
 if 68 - 68: OOooOOo . IiII / iIii1I11I1II1 % i11iIiiIii
 if 74 - 74: iII111i + i11iIiiIii
 if 95 - 95: Ii1I
 if 49 - 49: I1ii11iIi11i . i1IIi + OoO0O00 % O0 + OoO0O00
 if ( mc . group . is_null ( ) ) : return ( lisp_gather_map_cache_data ( mc , data ) )
 if 21 - 21: ooOoO0o * oO0o / OoooooooOO % ooOoO0o / O0
 if ( mc . source_cache == None ) : return ( [ True , data ] )
 if 24 - 24: OoO0O00 - i11iIiiIii / i11iIiiIii * I1Ii111
 if 20 - 20: IiII % iIii1I11I1II1 . iII111i + iIii1I11I1II1 + O0
 if 96 - 96: I1ii11iIi11i - IiII % OoooooooOO . iII111i
 if 30 - 30: Oo0Ooo . OoooooooOO / Oo0Ooo / oO0o
 if 44 - 44: I1ii11iIi11i % o0oOOo0O0Ooo / iIii1I11I1II1 - o0oOOo0O0Ooo / I11i * I1Ii111
 data = mc . source_cache . walk_cache ( lisp_gather_map_cache_data , data )
 return ( [ True , data ] )
 if 49 - 49: iII111i / iII111i - OoOoOO00
 if 89 - 89: ooOoO0o
 if 16 - 16: oO0o + oO0o + i1IIi + iIii1I11I1II1
 if 93 - 93: I1IiiI - i11iIiiIii * I1Ii111 - O0 + iII111i
 if 11 - 11: iII111i
 if 100 - 100: OoooooooOO / ooOoO0o . OoO0O00
 if 89 - 89: I11i % II111iiii
def lisp_gather_map_cache_data ( mc , data ) :
 iiIiiIi = { }
 iiIiiIi [ "instance-id" ] = str ( mc . eid . instance_id )
 iiIiiIi [ "eid-prefix" ] = mc . eid . print_prefix_no_iid ( )
 if ( mc . group . is_null ( ) == False ) :
  iiIiiIi [ "group-prefix" ] = mc . group . print_prefix_no_iid ( )
  if 35 - 35: oO0o
 iiIiiIi [ "uptime" ] = lisp_print_elapsed ( mc . uptime )
 iiIiiIi [ "expires" ] = lisp_print_elapsed ( mc . uptime )
 iiIiiIi [ "action" ] = lisp_map_reply_action_string [ mc . action ]
 iiIiiIi [ "ttl" ] = "--" if mc . map_cache_ttl == None else str ( mc . map_cache_ttl / 60 )
 if 65 - 65: II111iiii
 if 87 - 87: oO0o / OoO0O00 - oO0o
 if 69 - 69: i11iIiiIii
 if 29 - 29: IiII . ooOoO0o / iII111i - OOooOOo / OOooOOo % Oo0Ooo
 if 42 - 42: OoO0O00 . I1Ii111 . I1IiiI + Oo0Ooo * O0
 I1I11I11 = [ ]
 for II11IIiii in mc . rloc_set :
  oooO0 = { }
  if ( II11IIiii . rloc_exists ( ) ) :
   oooO0 [ "address" ] = II11IIiii . rloc . print_address_no_iid ( )
   if 35 - 35: Oo0Ooo / iII111i - O0 - OOooOOo * Oo0Ooo . i11iIiiIii
   if 43 - 43: OoOoOO00 % oO0o % OoO0O00 / Ii1I . I11i
  if ( II11IIiii . translated_port != 0 ) :
   oooO0 [ "encap-port" ] = str ( II11IIiii . translated_port )
   if 86 - 86: I1Ii111 * i1IIi + IiII - OoOoOO00
  oooO0 [ "state" ] = II11IIiii . print_state ( )
  if ( II11IIiii . geo ) : oooO0 [ "geo" ] = II11IIiii . geo . print_geo ( )
  if ( II11IIiii . elp ) : oooO0 [ "elp" ] = II11IIiii . elp . print_elp ( False )
  if ( II11IIiii . rle ) : oooO0 [ "rle" ] = II11IIiii . rle . print_rle ( False )
  if ( II11IIiii . json ) : oooO0 [ "json" ] = II11IIiii . json . print_json ( False )
  if ( II11IIiii . rloc_name ) : oooO0 [ "rloc-name" ] = II11IIiii . rloc_name
  I1iiIIiIII1i = II11IIiii . stats . get_stats ( False , False )
  if ( I1iiIIiIII1i ) : oooO0 [ "stats" ] = I1iiIIiIII1i
  oooO0 [ "uptime" ] = lisp_print_elapsed ( II11IIiii . uptime )
  oooO0 [ "upriority" ] = str ( II11IIiii . priority )
  oooO0 [ "uweight" ] = str ( II11IIiii . weight )
  oooO0 [ "mpriority" ] = str ( II11IIiii . mpriority )
  oooO0 [ "mweight" ] = str ( II11IIiii . mweight )
  II1iOOo0O0o = II11IIiii . last_rloc_probe_reply
  if ( II1iOOo0O0o ) :
   oooO0 [ "last-rloc-probe-reply" ] = lisp_print_elapsed ( II1iOOo0O0o )
   oooO0 [ "rloc-probe-rtt" ] = str ( II11IIiii . rloc_probe_rtt )
   if 1 - 1: iIii1I11I1II1 - OoO0O00 / II111iiii . OoOoOO00
  oooO0 [ "rloc-hop-count" ] = II11IIiii . rloc_probe_hops
  oooO0 [ "recent-rloc-hop-counts" ] = II11IIiii . recent_rloc_probe_hops
  if 11 - 11: OOooOOo + i11iIiiIii
  IIiii111IIiI = [ ]
  for oOOO0Ooooo in II11IIiii . recent_rloc_probe_rtts : IIiii111IIiI . append ( str ( oOOO0Ooooo ) )
  oooO0 [ "recent-rloc-probe-rtts" ] = IIiii111IIiI
  if 95 - 95: O0 * OoooooooOO / II111iiii - i1IIi
  I1I11I11 . append ( oooO0 )
  if 36 - 36: i1IIi * oO0o / i1IIi % oO0o
 iiIiiIi [ "rloc-set" ] = I1I11I11
 if 9 - 9: Ii1I / iIii1I11I1II1
 data . append ( iiIiiIi )
 return ( [ True , data ] )
 if 52 - 52: OOooOOo / oO0o / iIii1I11I1II1 / OoOoOO00
 if 43 - 43: iII111i * OoOoOO00 % II111iiii - I1Ii111
 if 87 - 87: oO0o
 if 52 - 52: i11iIiiIii
 if 75 - 75: i11iIiiIii % I1ii11iIi11i % Oo0Ooo + I1IiiI - OoooooooOO * oO0o
 if 20 - 20: OoOoOO00 % II111iiii
 if 46 - 46: o0oOOo0O0Ooo % i11iIiiIii * ooOoO0o / i1IIi * i1IIi
def lisp_process_api_map_cache_entry ( parms ) :
 II1ii1ii11I1 = parms [ "instance-id" ]
 II1ii1ii11I1 = 0 if ( II1ii1ii11I1 == "" ) else int ( II1ii1ii11I1 )
 if 71 - 71: I1IiiI + i1IIi
 if 96 - 96: I1Ii111 . Oo0Ooo % I11i % I1ii11iIi11i % II111iiii * IiII
 if 69 - 69: OoO0O00 * Oo0Ooo * iII111i
 if 2 - 2: iII111i - Ii1I
 ii1Ii = lisp_address ( LISP_AFI_NONE , "" , 0 , II1ii1ii11I1 )
 ii1Ii . store_prefix ( parms [ "eid-prefix" ] )
 oOiii1IiII = ii1Ii
 OOii = ii1Ii
 if 1 - 1: I1Ii111 / oO0o + iIii1I11I1II1
 if 88 - 88: o0oOOo0O0Ooo
 if 3 - 3: i11iIiiIii / I1ii11iIi11i
 if 49 - 49: IiII
 if 1 - 1: oO0o / I11i
 IiI1111i1i11I = lisp_address ( LISP_AFI_NONE , "" , 0 , II1ii1ii11I1 )
 if ( parms . has_key ( "group-prefix" ) ) :
  IiI1111i1i11I . store_prefix ( parms [ "group-prefix" ] )
  oOiii1IiII = IiI1111i1i11I
  if 99 - 99: OoO0O00 % IiII + I1Ii111 - oO0o
  if 28 - 28: OOooOOo - O0 - O0 % i11iIiiIii * OoooooooOO
 i11i111i1 = [ ]
 OoOOO000O0o = lisp_map_cache_lookup ( OOii , oOiii1IiII )
 if ( OoOOO000O0o ) : IIiIIiiIIi , i11i111i1 = lisp_process_api_map_cache ( OoOOO000O0o , i11i111i1 )
 return ( i11i111i1 )
 if 60 - 60: OoooooooOO / i1IIi / i1IIi / Ii1I . IiII
 if 24 - 24: O0
 if 6 - 6: I1IiiI . i11iIiiIii . OoooooooOO . I1IiiI . o0oOOo0O0Ooo
 if 65 - 65: i11iIiiIii
 if 46 - 46: i11iIiiIii
 if 70 - 70: i1IIi + o0oOOo0O0Ooo
 if 44 - 44: iII111i . II111iiii % o0oOOo0O0Ooo
def lisp_process_api_site_cache ( se , data ) :
 if 29 - 29: i11iIiiIii * i1IIi
 if 36 - 36: OoO0O00 * I11i . ooOoO0o
 if 50 - 50: oO0o * OoOoOO00 / OoO0O00 / ooOoO0o + II111iiii
 if 55 - 55: II111iiii - IiII
 if ( se . group . is_null ( ) ) : return ( lisp_gather_site_cache_data ( se , data ) )
 if 24 - 24: oO0o % Ii1I / i1IIi
 if ( se . source_cache == None ) : return ( [ True , data ] )
 if 84 - 84: i1IIi
 if 53 - 53: OoooooooOO - i1IIi - Ii1I
 if 73 - 73: I1ii11iIi11i - Ii1I * o0oOOo0O0Ooo
 if 29 - 29: o0oOOo0O0Ooo % IiII % OOooOOo + OoooooooOO - o0oOOo0O0Ooo
 if 34 - 34: Ii1I
 data = se . source_cache . walk_cache ( lisp_gather_site_cache_data , data )
 return ( [ True , data ] )
 if 5 - 5: II111iiii . I1ii11iIi11i
 if 85 - 85: I1Ii111 . IiII + II111iiii
 if 92 - 92: iII111i / o0oOOo0O0Ooo * oO0o . I11i % o0oOOo0O0Ooo
 if 87 - 87: Ii1I / Oo0Ooo % iIii1I11I1II1 / iII111i
 if 42 - 42: OoO0O00 . I1IiiI . OOooOOo + ooOoO0o
 if 87 - 87: OOooOOo
 if 44 - 44: Oo0Ooo + iIii1I11I1II1
def lisp_process_api_ms_or_mr ( ms_or_mr , data ) :
 I1IIIIIi1IIiI = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
 oOoo0OOOO0OO = data [ "dns-name" ] if data . has_key ( "dns-name" ) else None
 if ( data . has_key ( "address" ) ) :
  I1IIIIIi1IIiI . store_address ( data [ "address" ] )
  if 67 - 67: iII111i . OOooOOo / ooOoO0o * iIii1I11I1II1
  if 29 - 29: I1Ii111 / OoOoOO00 % I1ii11iIi11i * IiII / II111iiii
 O000O = { }
 if ( ms_or_mr ) :
  for oOooOO in lisp_map_servers_list . values ( ) :
   if ( oOoo0OOOO0OO ) :
    if ( oOoo0OOOO0OO != oOooOO . dns_name ) : continue
   else :
    if ( I1IIIIIi1IIiI . is_exact_match ( oOooOO . map_server ) == False ) : continue
    if 10 - 10: O0 / I11i
    if 29 - 29: i11iIiiIii % I11i
   O000O [ "dns-name" ] = oOooOO . dns_name
   O000O [ "address" ] = oOooOO . map_server . print_address_no_iid ( )
   O000O [ "ms-name" ] = "" if oOooOO . ms_name == None else oOooOO . ms_name
   return ( [ O000O ] )
   if 49 - 49: I11i
 else :
  for OOO0o0o in lisp_map_resolvers_list . values ( ) :
   if ( oOoo0OOOO0OO ) :
    if ( oOoo0OOOO0OO != OOO0o0o . dns_name ) : continue
   else :
    if ( I1IIIIIi1IIiI . is_exact_match ( OOO0o0o . map_resolver ) == False ) : continue
    if 69 - 69: o0oOOo0O0Ooo . O0 * I11i
    if 92 - 92: OoO0O00 . O0 / Ii1I % Oo0Ooo . Ii1I
   O000O [ "dns-name" ] = OOO0o0o . dns_name
   O000O [ "address" ] = OOO0o0o . map_resolver . print_address_no_iid ( )
   O000O [ "mr-name" ] = "" if OOO0o0o . mr_name == None else OOO0o0o . mr_name
   return ( [ O000O ] )
   if 40 - 40: o0oOOo0O0Ooo - Ii1I . iII111i - O0
   if 53 - 53: Oo0Ooo - I1IiiI * O0 . II111iiii
 return ( [ ] )
 if 72 - 72: ooOoO0o - Ii1I . Ii1I . I11i / OoooooooOO + Ii1I
 if 32 - 32: O0
 if 42 - 42: i1IIi * I1ii11iIi11i * OoOoOO00
 if 43 - 43: I1ii11iIi11i % I1ii11iIi11i % i1IIi
 if 56 - 56: I1IiiI - OoO0O00 - iII111i . o0oOOo0O0Ooo . I1Ii111
 if 70 - 70: iIii1I11I1II1 - I11i
 if 2 - 2: oO0o / II111iiii * OoO0O00
 if 71 - 71: i1IIi + I11i * OoO0O00 . OOooOOo + oO0o
def lisp_process_api_database_mapping ( ) :
 i11i111i1 = [ ]
 if 40 - 40: OOooOOo
 for i1i1iiiii1IiI in lisp_db_list :
  iiIiiIi = { }
  iiIiiIi [ "eid-prefix" ] = i1i1iiiii1IiI . eid . print_prefix ( )
  if ( i1i1iiiii1IiI . group . is_null ( ) == False ) :
   iiIiiIi [ "group-prefix" ] = i1i1iiiii1IiI . group . print_prefix ( )
   if 14 - 14: OoooooooOO - OoooooooOO % i11iIiiIii % ooOoO0o / ooOoO0o
   if 33 - 33: iII111i / i1IIi . II111iiii % I1ii11iIi11i
  II1I1I1i1i = [ ]
  for oooO0 in i1i1iiiii1IiI . rloc_set :
   II11IIiii = { }
   if ( oooO0 . rloc . is_null ( ) == False ) :
    II11IIiii [ "rloc" ] = oooO0 . rloc . print_address_no_iid ( )
    if 74 - 74: iII111i / OOooOOo / O0 / iIii1I11I1II1 + IiII
   if ( oooO0 . rloc_name != None ) : II11IIiii [ "rloc-name" ] = oooO0 . rloc_name
   if ( oooO0 . interface != None ) : II11IIiii [ "interface" ] = oooO0 . interface
   I1iii1Ii1I = oooO0 . translated_rloc
   if ( I1iii1Ii1I . is_null ( ) == False ) :
    II11IIiii [ "translated-rloc" ] = I1iii1Ii1I . print_address_no_iid ( )
    if 68 - 68: ooOoO0o - O0 + Ii1I / I1IiiI + Ii1I * OOooOOo
   if ( II11IIiii != { } ) : II1I1I1i1i . append ( II11IIiii )
   if 14 - 14: I1ii11iIi11i / i1IIi . ooOoO0o % OoO0O00 * OoO0O00 + oO0o
   if 65 - 65: Oo0Ooo % iIii1I11I1II1
   if 40 - 40: iII111i + Ii1I . OoooooooOO . i1IIi
   if 7 - 7: I1ii11iIi11i - Ii1I % Ii1I
   if 75 - 75: O0 . II111iiii + Oo0Ooo * O0 - IiII % OoOoOO00
  iiIiiIi [ "rlocs" ] = II1I1I1i1i
  if 85 - 85: I1Ii111 - Ii1I . I1ii11iIi11i - OoooooooOO
  if 10 - 10: Ii1I . iII111i
  if 62 - 62: o0oOOo0O0Ooo + OoooooooOO + IiII
  if 98 - 98: OoO0O00 . o0oOOo0O0Ooo + ooOoO0o + OOooOOo + oO0o
  i11i111i1 . append ( iiIiiIi )
  if 29 - 29: i11iIiiIii - I11i
 return ( i11i111i1 )
 if 94 - 94: Oo0Ooo
 if 39 - 39: I11i - oO0o % iII111i - ooOoO0o - OoOoOO00
 if 8 - 8: i1IIi % i1IIi % OoooooooOO % i1IIi . iIii1I11I1II1
 if 70 - 70: O0 + II111iiii % IiII / I1Ii111 - IiII
 if 58 - 58: II111iiii * oO0o - i1IIi . I11i
 if 23 - 23: OoO0O00 - I1IiiI * i11iIiiIii
 if 62 - 62: OoO0O00 . i11iIiiIii / i1IIi
def lisp_gather_site_cache_data ( se , data ) :
 iiIiiIi = { }
 iiIiiIi [ "site-name" ] = se . site . site_name
 iiIiiIi [ "instance-id" ] = str ( se . eid . instance_id )
 iiIiiIi [ "eid-prefix" ] = se . eid . print_prefix_no_iid ( )
 if ( se . group . is_null ( ) == False ) :
  iiIiiIi [ "group-prefix" ] = se . group . print_prefix_no_iid ( )
  if 3 - 3: OoO0O00 + O0 % Oo0Ooo * Oo0Ooo % i11iIiiIii
 iiIiiIi [ "registered" ] = "yes" if se . registered else "no"
 iiIiiIi [ "first-registered" ] = lisp_print_elapsed ( se . first_registered )
 iiIiiIi [ "last-registered" ] = lisp_print_elapsed ( se . last_registered )
 if 29 - 29: ooOoO0o / iII111i / OOooOOo - iIii1I11I1II1
 oOo00Ooo0o0 = se . last_registerer
 oOo00Ooo0o0 = "none" if oOo00Ooo0o0 . is_null ( ) else oOo00Ooo0o0 . print_address ( )
 iiIiiIi [ "last-registerer" ] = oOo00Ooo0o0
 iiIiiIi [ "ams" ] = "yes" if ( se . accept_more_specifics ) else "no"
 iiIiiIi [ "dynamic" ] = "yes" if ( se . dynamic ) else "no"
 iiIiiIi [ "site-id" ] = str ( se . site_id )
 if ( se . xtr_id_present ) :
  iiIiiIi [ "xtr-id" ] = "0x" + lisp_hex_string ( se . xtr_id )
  if 31 - 31: i1IIi * Ii1I
  if 94 - 94: oO0o / Ii1I % iIii1I11I1II1 + i1IIi / O0 - iII111i
  if 77 - 77: o0oOOo0O0Ooo - IiII . i1IIi
  if 70 - 70: i1IIi . I1Ii111 . iII111i - OoOoOO00 + II111iiii + OOooOOo
  if 52 - 52: OOooOOo . OoOoOO00 - ooOoO0o % i1IIi
 I1I11I11 = [ ]
 for II11IIiii in se . registered_rlocs :
  oooO0 = { }
  oooO0 [ "address" ] = II11IIiii . rloc . print_address_no_iid ( ) if II11IIiii . rloc_exists ( ) else "none"
  if 15 - 15: oO0o
  if 6 - 6: oO0o . iIii1I11I1II1 - I1ii11iIi11i % IiII
  if ( II11IIiii . geo ) : oooO0 [ "geo" ] = II11IIiii . geo . print_geo ( )
  if ( II11IIiii . elp ) : oooO0 [ "elp" ] = II11IIiii . elp . print_elp ( False )
  if ( II11IIiii . rle ) : oooO0 [ "rle" ] = II11IIiii . rle . print_rle ( False )
  if ( II11IIiii . json ) : oooO0 [ "json" ] = II11IIiii . json . print_json ( False )
  if ( II11IIiii . rloc_name ) : oooO0 [ "rloc-name" ] = II11IIiii . rloc_name
  oooO0 [ "uptime" ] = lisp_print_elapsed ( II11IIiii . uptime )
  oooO0 [ "upriority" ] = str ( II11IIiii . priority )
  oooO0 [ "uweight" ] = str ( II11IIiii . weight )
  oooO0 [ "mpriority" ] = str ( II11IIiii . mpriority )
  oooO0 [ "mweight" ] = str ( II11IIiii . mweight )
  if 58 - 58: iII111i * oO0o / iII111i - Oo0Ooo / I1Ii111 * oO0o
  I1I11I11 . append ( oooO0 )
  if 63 - 63: oO0o . IiII . o0oOOo0O0Ooo
 iiIiiIi [ "registered-rlocs" ] = I1I11I11
 if 16 - 16: iII111i . I11i - Oo0Ooo / I1IiiI + OoOoOO00
 data . append ( iiIiiIi )
 return ( [ True , data ] )
 if 14 - 14: iIii1I11I1II1 / i11iIiiIii - o0oOOo0O0Ooo . iII111i * OoO0O00
 if 5 - 5: Ii1I + OoOoOO00 % I11i + IiII
 if 55 - 55: OoooooooOO + oO0o . o0oOOo0O0Ooo % iIii1I11I1II1 - I1Ii111
 if 40 - 40: I1IiiI . o0oOOo0O0Ooo - Oo0Ooo
 if 44 - 44: Ii1I % OoO0O00 * oO0o * OoO0O00
 if 7 - 7: I1Ii111 % i1IIi . I11i . O0 / i1IIi
 if 56 - 56: Oo0Ooo
def lisp_process_api_site_cache_entry ( parms ) :
 II1ii1ii11I1 = parms [ "instance-id" ]
 II1ii1ii11I1 = 0 if ( II1ii1ii11I1 == "" ) else int ( II1ii1ii11I1 )
 if 21 - 21: i11iIiiIii * o0oOOo0O0Ooo + Oo0Ooo
 if 20 - 20: IiII / OoooooooOO / O0 / I1Ii111 * ooOoO0o
 if 45 - 45: ooOoO0o / Oo0Ooo % o0oOOo0O0Ooo . ooOoO0o
 if 19 - 19: o0oOOo0O0Ooo % I11i . I1ii11iIi11i
 ii1Ii = lisp_address ( LISP_AFI_NONE , "" , 0 , II1ii1ii11I1 )
 ii1Ii . store_prefix ( parms [ "eid-prefix" ] )
 if 70 - 70: Oo0Ooo - I11i / I1ii11iIi11i % OoO0O00 % II111iiii
 if 72 - 72: i11iIiiIii * I11i
 if 69 - 69: I1Ii111 . Ii1I * I1ii11iIi11i % I11i - o0oOOo0O0Ooo
 if 30 - 30: ooOoO0o / Oo0Ooo * iII111i % OoooooooOO / I1ii11iIi11i
 if 64 - 64: OoooooooOO
 IiI1111i1i11I = lisp_address ( LISP_AFI_NONE , "" , 0 , II1ii1ii11I1 )
 if ( parms . has_key ( "group-prefix" ) ) :
  IiI1111i1i11I . store_prefix ( parms [ "group-prefix" ] )
  if 41 - 41: Ii1I . I11i / oO0o * OoooooooOO
  if 98 - 98: I1ii11iIi11i - O0 + i11iIiiIii
 i11i111i1 = [ ]
 OoOo0OOoOOO00 = lisp_site_eid_lookup ( ii1Ii , IiI1111i1i11I , False )
 if ( OoOo0OOoOOO00 ) : lisp_gather_site_cache_data ( OoOo0OOoOOO00 , i11i111i1 )
 return ( i11i111i1 )
 if 71 - 71: O0 - OoooooooOO
 if 82 - 82: i11iIiiIii * II111iiii % IiII
 if 80 - 80: Ii1I . i11iIiiIii % oO0o * o0oOOo0O0Ooo
 if 56 - 56: I1Ii111 % iII111i / II111iiii - Oo0Ooo - Oo0Ooo - iIii1I11I1II1
 if 67 - 67: iII111i
 if 80 - 80: Ii1I . iII111i * I1IiiI * Ii1I
 if 82 - 82: OoO0O00 % OoOoOO00 * i11iIiiIii . OoO0O00 . I1ii11iIi11i + Ii1I
def lisp_get_interface_instance_id ( device , source_eid ) :
 O0OOoooo0 = None
 if ( lisp_myinterfaces . has_key ( device ) ) :
  O0OOoooo0 = lisp_myinterfaces [ device ]
  if 60 - 60: i1IIi / iII111i
  if 10 - 10: I1Ii111 / OoOoOO00 * Ii1I % o0oOOo0O0Ooo . OoOoOO00 / I1ii11iIi11i
  if 2 - 2: iIii1I11I1II1
  if 85 - 85: O0 - ooOoO0o
  if 35 - 35: o0oOOo0O0Ooo - I1IiiI
  if 47 - 47: i11iIiiIii * iII111i . OoOoOO00 * I1Ii111 % i11iIiiIii + Ii1I
 if ( O0OOoooo0 == None or O0OOoooo0 . instance_id == None ) :
  return ( lisp_default_iid )
  if 65 - 65: Ii1I % i11iIiiIii
  if 98 - 98: iII111i * o0oOOo0O0Ooo % Oo0Ooo
  if 7 - 7: oO0o * OoooooooOO % o0oOOo0O0Ooo . I1Ii111 + O0
  if 14 - 14: I11i * II111iiii % o0oOOo0O0Ooo / iII111i . OoooooooOO % iII111i
  if 88 - 88: iII111i
  if 94 - 94: OoooooooOO
  if 32 - 32: I1ii11iIi11i
  if 8 - 8: I11i * i11iIiiIii - ooOoO0o
  if 47 - 47: ooOoO0o . I1IiiI / i11iIiiIii * iII111i * I1IiiI
 II1ii1ii11I1 = O0OOoooo0 . get_instance_id ( )
 if ( source_eid == None ) : return ( II1ii1ii11I1 )
 if 8 - 8: oO0o % oO0o . iII111i / i1IIi % IiII
 OO0OOoO = source_eid . instance_id
 oOO0oO0o0oOoO = None
 for O0OOoooo0 in lisp_multi_tenant_interfaces :
  if ( O0OOoooo0 . device != device ) : continue
  ooII1111iI1I = O0OOoooo0 . multi_tenant_eid
  source_eid . instance_id = ooII1111iI1I . instance_id
  if ( source_eid . is_more_specific ( ooII1111iI1I ) == False ) : continue
  if ( oOO0oO0o0oOoO == None or oOO0oO0o0oOoO . multi_tenant_eid . mask_len < ooII1111iI1I . mask_len ) :
   oOO0oO0o0oOoO = O0OOoooo0
   if 62 - 62: i1IIi . Ii1I * i1IIi * O0 . I1IiiI % o0oOOo0O0Ooo
   if 16 - 16: I11i . Ii1I - ooOoO0o . OOooOOo % O0 / oO0o
 source_eid . instance_id = OO0OOoO
 if 42 - 42: II111iiii . iII111i
 if ( oOO0oO0o0oOoO == None ) : return ( II1ii1ii11I1 )
 return ( oOO0oO0o0oOoO . get_instance_id ( ) )
 if 67 - 67: i1IIi - i11iIiiIii / ooOoO0o * oO0o
 if 64 - 64: oO0o / IiII
 if 86 - 86: I11i
 if 36 - 36: o0oOOo0O0Ooo / OoO0O00
 if 6 - 6: I11i % I1IiiI + iII111i * OoooooooOO . O0
 if 87 - 87: ooOoO0o / Ii1I % O0 . OoO0O00
 if 55 - 55: i1IIi . o0oOOo0O0Ooo % OoooooooOO + II111iiii . OoOoOO00
 if 32 - 32: IiII * I1Ii111 * Oo0Ooo . i1IIi * OoooooooOO
 if 12 - 12: I1IiiI . OOooOOo % Oo0Ooo
def lisp_allow_dynamic_eid ( device , eid ) :
 if ( lisp_myinterfaces . has_key ( device ) == False ) : return ( None )
 if 86 - 86: i11iIiiIii
 O0OOoooo0 = lisp_myinterfaces [ device ]
 O0Oo00oO0 = device if O0OOoooo0 . dynamic_eid_device == None else O0OOoooo0 . dynamic_eid_device
 if 2 - 2: II111iiii
 if 38 - 38: Oo0Ooo
 if ( O0OOoooo0 . does_dynamic_eid_match ( eid ) ) : return ( O0Oo00oO0 )
 return ( None )
 if 14 - 14: IiII . I1Ii111 + Oo0Ooo - iII111i + I1IiiI % OOooOOo
 if 73 - 73: I1ii11iIi11i / OoO0O00
 if 31 - 31: iII111i - I1IiiI - o0oOOo0O0Ooo - OoO0O00 + IiII . iIii1I11I1II1
 if 53 - 53: iII111i * oO0o + oO0o % OoO0O00 . OoooooooOO - i11iIiiIii
 if 19 - 19: OoOoOO00 + I1IiiI * iIii1I11I1II1
 if 88 - 88: I1Ii111 - oO0o
 if 74 - 74: I1Ii111 % i11iIiiIii
def lisp_start_rloc_probe_timer ( interval , lisp_sockets ) :
 global lisp_rloc_probe_timer
 if 44 - 44: ooOoO0o + o0oOOo0O0Ooo
 if ( lisp_rloc_probe_timer != None ) : lisp_rloc_probe_timer . cancel ( )
 if 10 - 10: i1IIi + o0oOOo0O0Ooo
 I111i1IIiii11 = lisp_process_rloc_probe_timer
 IiIII = threading . Timer ( interval , I111i1IIiii11 , [ lisp_sockets ] )
 lisp_rloc_probe_timer = IiIII
 IiIII . start ( )
 return
 if 79 - 79: i11iIiiIii % I1IiiI . OoooooooOO * oO0o . Ii1I
 if 14 - 14: iIii1I11I1II1 / I11i - o0oOOo0O0Ooo / IiII / o0oOOo0O0Ooo . OoO0O00
 if 2 - 2: I11i
 if 12 - 12: i1IIi . I1Ii111
 if 99 - 99: Oo0Ooo / i11iIiiIii
 if 81 - 81: Ii1I . i1IIi % iII111i . OoO0O00 % IiII
 if 42 - 42: iII111i / Oo0Ooo
def lisp_show_rloc_probe_list ( ) :
 lprint ( bold ( "----- RLOC-probe-list -----" , False ) )
 for OOO0OOoOOO in lisp_rloc_probe_list :
  iiii = lisp_rloc_probe_list [ OOO0OOoOOO ]
  lprint ( "RLOC {}:" . format ( OOO0OOoOOO ) )
  for oooO0 , ooOoOOOOo , IiIoO0oo0 in iiii :
   lprint ( "  [{}, {}, {}, {}]" . format ( hex ( id ( oooO0 ) ) , ooOoOOOOo . print_prefix ( ) ,
 IiIoO0oo0 . print_prefix ( ) , oooO0 . translated_port ) )
   if 80 - 80: I1ii11iIi11i + Ii1I
   if 16 - 16: i11iIiiIii * Oo0Ooo
 lprint ( bold ( "---------------------------" , False ) )
 return
 if 76 - 76: iII111i . oO0o - i1IIi
 if 94 - 94: O0 % iII111i
 if 90 - 90: IiII
 if 1 - 1: I1ii11iIi11i % OoOoOO00 . I1ii11iIi11i . OoooooooOO % oO0o + Ii1I
 if 46 - 46: I1IiiI + OoO0O00 - Oo0Ooo
 if 13 - 13: OoOoOO00
 if 72 - 72: II111iiii * iII111i . II111iiii + iII111i * IiII
 if 90 - 90: oO0o * I1Ii111 / O0
 if 15 - 15: o0oOOo0O0Ooo * O0 . OOooOOo / Oo0Ooo
def lisp_mark_rlocs_for_other_eids ( eid_list ) :
 if 28 - 28: OoooooooOO + OoooooooOO
 if 27 - 27: I11i . oO0o / OoooooooOO - OoO0O00 . I11i
 if 15 - 15: II111iiii * OoO0O00
 if 33 - 33: OoooooooOO . o0oOOo0O0Ooo . I1IiiI / I1ii11iIi11i . OoOoOO00
 II11IIiii , ooOoOOOOo , IiIoO0oo0 = eid_list [ 0 ]
 oooO0Ooo000 = [ lisp_print_eid_tuple ( ooOoOOOOo , IiIoO0oo0 ) ]
 if 9 - 9: OoooooooOO * ooOoO0o % I1ii11iIi11i . I1IiiI % O0
 for II11IIiii , ooOoOOOOo , IiIoO0oo0 in eid_list [ 1 : : ] :
  II11IIiii . state = LISP_RLOC_UNREACH_STATE
  II11IIiii . last_state_change = lisp_get_timestamp ( )
  oooO0Ooo000 . append ( lisp_print_eid_tuple ( ooOoOOOOo , IiIoO0oo0 ) )
  if 91 - 91: OOooOOo * OoooooooOO * I1IiiI . i1IIi
  if 9 - 9: oO0o / i11iIiiIii + IiII / IiII - I11i
 oOoOOOOO0oO = bold ( "unreachable" , False )
 I111I1iii11 = red ( II11IIiii . rloc . print_address_no_iid ( ) , False )
 if 12 - 12: I1IiiI * OoO0O00 - I1Ii111 . IiII / Oo0Ooo
 for ii1Ii in oooO0Ooo000 :
  ooOoOOOOo = green ( ii1Ii , False )
  lprint ( "RLOC {} went {} for EID {}" . format ( I111I1iii11 , oOoOOOOO0oO , ooOoOOOOo ) )
  if 32 - 32: OoOoOO00 + Ii1I * iII111i % Oo0Ooo
  if 61 - 61: OoooooooOO % iII111i - O0
  if 62 - 62: iIii1I11I1II1
  if 14 - 14: I1Ii111
  if 95 - 95: II111iiii / o0oOOo0O0Ooo * OOooOOo
  if 81 - 81: i11iIiiIii / iIii1I11I1II1
 for II11IIiii , ooOoOOOOo , IiIoO0oo0 in eid_list :
  OoOOO000O0o = lisp_map_cache . lookup_cache ( ooOoOOOOo , True )
  if ( OoOOO000O0o ) : lisp_write_ipc_map_cache ( True , OoOOO000O0o )
  if 73 - 73: i11iIiiIii . I1ii11iIi11i * OoOoOO00
 return
 if 95 - 95: i1IIi + iIii1I11I1II1 . I1Ii111 / I1Ii111
 if 84 - 84: Oo0Ooo . OoO0O00 * IiII
 if 95 - 95: OoO0O00
 if 100 - 100: II111iiii
 if 34 - 34: I11i % OOooOOo - iII111i % II111iiii
 if 14 - 14: I11i * o0oOOo0O0Ooo % II111iiii
 if 36 - 36: ooOoO0o - iIii1I11I1II1 / IiII + OoOoOO00
 if 42 - 42: ooOoO0o + I1IiiI * iII111i / OoOoOO00 . i1IIi - OoooooooOO
 if 8 - 8: iIii1I11I1II1 - Oo0Ooo + iII111i
 if 40 - 40: o0oOOo0O0Ooo * I1IiiI
def lisp_process_rloc_probe_timer ( lisp_sockets ) :
 lisp_set_exception ( )
 if 75 - 75: O0 * OOooOOo / ooOoO0o + I11i
 lisp_start_rloc_probe_timer ( LISP_RLOC_PROBE_INTERVAL , lisp_sockets )
 if ( lisp_rloc_probing == False ) : return
 if 56 - 56: I1IiiI % OoooooooOO % Oo0Ooo
 if 19 - 19: i11iIiiIii - iIii1I11I1II1 . i1IIi . I1Ii111 / I1IiiI * I1Ii111
 if 41 - 41: oO0o . o0oOOo0O0Ooo . I11i * OoOoOO00
 if 16 - 16: oO0o
 if ( lisp_print_rloc_probe_list ) : lisp_show_rloc_probe_list ( )
 if 32 - 32: OoooooooOO
 if 77 - 77: Oo0Ooo . i1IIi - I11i
 if 98 - 98: O0
 if 87 - 87: OoO0O00 % I1Ii111 - OOooOOo - II111iiii + iII111i
 oo0ooOoOO0 = lisp_get_default_route_next_hops ( )
 if 22 - 22: Oo0Ooo - I1ii11iIi11i + I11i . oO0o
 lprint ( "---------- Start RLOC Probing for {} entries ----------" . format ( len ( lisp_rloc_probe_list ) ) )
 if 85 - 85: iIii1I11I1II1 / Ii1I
 if 43 - 43: I1IiiI % I1Ii111 - oO0o . II111iiii / iIii1I11I1II1
 if 97 - 97: I1Ii111 + I1ii11iIi11i
 if 21 - 21: O0 + o0oOOo0O0Ooo * OoooooooOO % IiII % I1ii11iIi11i
 if 80 - 80: I11i
 O0oO = 0
 OOo00o = bold ( "RLOC-probe" , False )
 for iI1ii1II1i111 in lisp_rloc_probe_list . values ( ) :
  if 80 - 80: OoOoOO00 . ooOoO0o - iIii1I11I1II1 / o0oOOo0O0Ooo * I1IiiI + II111iiii
  if 37 - 37: IiII + OOooOOo - iIii1I11I1II1 * o0oOOo0O0Ooo - iII111i % oO0o
  if 26 - 26: iIii1I11I1II1 - I1Ii111 % iIii1I11I1II1 - iII111i
  if 37 - 37: i1IIi % iIii1I11I1II1 / OoOoOO00 * o0oOOo0O0Ooo - ooOoO0o . I1Ii111
  if 91 - 91: OoOoOO00
  O0O0Ooo0O = None
  for O00O0oooO0 , ii1Ii , IiI1111i1i11I in iI1ii1II1i111 :
   i111I11I = O00O0oooO0 . rloc . print_address_no_iid ( )
   if 6 - 6: O0 + i11iIiiIii
   if 59 - 59: ooOoO0o . iII111i - II111iiii
   if 30 - 30: o0oOOo0O0Ooo % iII111i - i11iIiiIii
   if 25 - 25: i11iIiiIii + OoOoOO00 + oO0o / Ii1I * Oo0Ooo + Oo0Ooo
   IiIIiIIIiI , iIi1II = lisp_allow_gleaning ( ii1Ii , None , O00O0oooO0 )
   if ( IiIIiIIIiI and iIi1II == False ) :
    ooOoOOOOo = green ( ii1Ii . print_address ( ) , False )
    i111I11I += ":{}" . format ( O00O0oooO0 . translated_port )
    lprint ( "Suppress probe to RLOC {} for gleaned EID {}" . format ( red ( i111I11I , False ) , ooOoOOOOo ) )
    if 69 - 69: iIii1I11I1II1 - OoOoOO00 % i1IIi . I1IiiI
    continue
    if 66 - 66: OOooOOo . I1Ii111 / OoOoOO00 - I1IiiI / oO0o + OoO0O00
    if 38 - 38: O0 * iIii1I11I1II1 - oO0o
    if 38 - 38: iIii1I11I1II1 / I1Ii111 + ooOoO0o . II111iiii - iIii1I11I1II1
    if 13 - 13: Ii1I
    if 34 - 34: I1IiiI / iIii1I11I1II1
    if 35 - 35: oO0o / oO0o
    if 86 - 86: o0oOOo0O0Ooo . Oo0Ooo - Ii1I / i11iIiiIii
   if ( O00O0oooO0 . down_state ( ) ) : continue
   if 63 - 63: oO0o - O0 + I1ii11iIi11i + Ii1I / i1IIi
   if 77 - 77: O0
   if 49 - 49: o0oOOo0O0Ooo / i11iIiiIii
   if 36 - 36: II111iiii
   if 78 - 78: OoO0O00 + iIii1I11I1II1 * i1IIi
   if 7 - 7: i11iIiiIii
   if 49 - 49: I1IiiI - oO0o % OOooOOo / O0 / II111iiii
   if 41 - 41: IiII % II111iiii
   if 99 - 99: IiII - O0
   if 59 - 59: iII111i % O0 + OOooOOo * ooOoO0o
   if 27 - 27: I1Ii111 % i11iIiiIii * I1IiiI
   if ( O0O0Ooo0O ) :
    O00O0oooO0 . last_rloc_probe_nonce = O0O0Ooo0O . last_rloc_probe_nonce
    if 19 - 19: OoOoOO00 / o0oOOo0O0Ooo - iII111i / OoO0O00
    if ( O0O0Ooo0O . translated_port == O00O0oooO0 . translated_port and O0O0Ooo0O . rloc_name == O00O0oooO0 . rloc_name ) :
     if 12 - 12: I1ii11iIi11i - I11i * O0 % I1IiiI + O0 - II111iiii
     ooOoOOOOo = green ( lisp_print_eid_tuple ( ii1Ii , IiI1111i1i11I ) , False )
     lprint ( "Suppress probe to duplicate RLOC {} for {}" . format ( red ( i111I11I , False ) , ooOoOOOOo ) )
     if 13 - 13: iII111i / OOooOOo * i11iIiiIii / oO0o / OoooooooOO
     continue
     if 89 - 89: Ii1I * Oo0Ooo / I1Ii111 * I1ii11iIi11i + O0 * Oo0Ooo
     if 74 - 74: I11i . I11i
     if 74 - 74: OoOoOO00 * ooOoO0o * I1Ii111
   iI1II1IiIiIi = None
   II11IIiii = None
   while ( True ) :
    II11IIiii = O00O0oooO0 if II11IIiii == None else II11IIiii . next_rloc
    if ( II11IIiii == None ) : break
    if 56 - 56: iIii1I11I1II1 * OoO0O00 - oO0o * Ii1I
    if 62 - 62: i1IIi + I11i / OOooOOo - OoooooooOO % i1IIi . I1IiiI
    if 13 - 13: O0 * iII111i
    if 26 - 26: i1IIi - I1Ii111 - ooOoO0o
    if 73 - 73: o0oOOo0O0Ooo . OoooooooOO
    if ( II11IIiii . rloc_next_hop != None ) :
     if ( II11IIiii . rloc_next_hop not in oo0ooOoOO0 ) :
      if ( II11IIiii . up_state ( ) ) :
       OooOo , iiiIIiII111I = II11IIiii . rloc_next_hop
       II11IIiii . state = LISP_RLOC_UNREACH_STATE
       II11IIiii . last_state_change = lisp_get_timestamp ( )
       lisp_update_rtr_updown ( II11IIiii . rloc , False )
       if 96 - 96: i1IIi - OOooOOo / I11i % OoOoOO00 - i11iIiiIii % II111iiii
      oOoOOOOO0oO = bold ( "unreachable" , False )
      lprint ( "Next-hop {}({}) for RLOC {} is {}" . format ( iiiIIiII111I , OooOo ,
 red ( i111I11I , False ) , oOoOOOOO0oO ) )
      continue
      if 47 - 47: I1Ii111 * iII111i
      if 90 - 90: i1IIi * Ii1I . OoO0O00 % I11i * ooOoO0o . OOooOOo
      if 76 - 76: iIii1I11I1II1 . i11iIiiIii * II111iiii - iII111i
      if 51 - 51: I1IiiI
      if 52 - 52: I1Ii111
      if 82 - 82: iII111i + II111iiii
    oOo = II11IIiii . last_rloc_probe
    Ii1111i1iI1 = 0 if oOo == None else time . time ( ) - oOo
    if ( II11IIiii . unreach_state ( ) and Ii1111i1iI1 < LISP_RLOC_PROBE_INTERVAL ) :
     lprint ( "Waiting for probe-reply from RLOC {}" . format ( red ( i111I11I , False ) ) )
     if 75 - 75: iII111i + i1IIi . I1IiiI / oO0o * II111iiii * i1IIi
     continue
     if 14 - 14: Ii1I - I11i / i1IIi * OoOoOO00 * ooOoO0o
     if 78 - 78: iII111i % I1ii11iIi11i . I11i
     if 58 - 58: OoooooooOO * I1Ii111 % OoO0O00
     if 75 - 75: I11i - OOooOOo
     if 88 - 88: Ii1I / i11iIiiIii
     if 89 - 89: ooOoO0o
    I1iiiIi1i11i = lisp_get_echo_nonce ( None , i111I11I )
    if ( I1iiiIi1i11i and I1iiiIi1i11i . request_nonce_timeout ( ) ) :
     II11IIiii . state = LISP_RLOC_NO_ECHOED_NONCE_STATE
     II11IIiii . last_state_change = lisp_get_timestamp ( )
     oOoOOOOO0oO = bold ( "unreachable" , False )
     lprint ( "RLOC {} went {}, nonce-echo failed" . format ( red ( i111I11I , False ) , oOoOOOOO0oO ) )
     if 83 - 83: I11i . I11i * OOooOOo - OOooOOo
     lisp_update_rtr_updown ( II11IIiii . rloc , False )
     continue
     if 46 - 46: iIii1I11I1II1 . I1Ii111 % I1IiiI
     if 22 - 22: i1IIi * I11i + II111iiii + II111iiii
     if 20 - 20: I11i
     if 37 - 37: I1Ii111
     if 19 - 19: I1ii11iIi11i / OOooOOo . I1IiiI / ooOoO0o + OoO0O00 + i11iIiiIii
     if 80 - 80: OoO0O00 . O0 / Ii1I % I1Ii111 / iII111i * I1IiiI
    if ( I1iiiIi1i11i and I1iiiIi1i11i . recently_echoed ( ) ) :
     lprint ( ( "Suppress RLOC-probe to {}, nonce-echo " + "received" ) . format ( red ( i111I11I , False ) ) )
     if 41 - 41: O0 / OoooooooOO - i1IIi
     continue
     if 6 - 6: i1IIi - I1ii11iIi11i % I1Ii111 - II111iiii / ooOoO0o / i11iIiiIii
     if 32 - 32: oO0o / IiII - I11i . ooOoO0o
     if 69 - 69: i11iIiiIii * i11iIiiIii
     if 100 - 100: I1ii11iIi11i * I1ii11iIi11i + i1IIi
     if 96 - 96: I1Ii111 / I1IiiI + ooOoO0o
     if 16 - 16: I1ii11iIi11i % o0oOOo0O0Ooo % OOooOOo % OoOoOO00 + ooOoO0o % I1ii11iIi11i
    if ( II11IIiii . last_rloc_probe != None ) :
     oOo = II11IIiii . last_rloc_probe_reply
     if ( oOo == None ) : oOo = 0
     Ii1111i1iI1 = time . time ( ) - oOo
     if ( II11IIiii . up_state ( ) and Ii1111i1iI1 >= LISP_RLOC_PROBE_REPLY_WAIT ) :
      if 85 - 85: oO0o * OoooooooOO * iIii1I11I1II1 + iII111i
      II11IIiii . state = LISP_RLOC_UNREACH_STATE
      II11IIiii . last_state_change = lisp_get_timestamp ( )
      lisp_update_rtr_updown ( II11IIiii . rloc , False )
      oOoOOOOO0oO = bold ( "unreachable" , False )
      lprint ( "RLOC {} went {}, probe it" . format ( red ( i111I11I , False ) , oOoOOOOO0oO ) )
      if 67 - 67: Ii1I / i11iIiiIii % OoOoOO00 % O0 / OoOoOO00
      if 54 - 54: I11i . OoOoOO00 / II111iiii . i1IIi + OOooOOo % II111iiii
      lisp_mark_rlocs_for_other_eids ( iI1ii1II1i111 )
      if 82 - 82: i11iIiiIii . OoooooooOO % OoOoOO00 * O0 - I1Ii111
      if 78 - 78: OoOoOO00 % Ii1I % OOooOOo % Oo0Ooo % I11i . Ii1I
      if 73 - 73: OoooooooOO / i1IIi . iIii1I11I1II1
    II11IIiii . last_rloc_probe = lisp_get_timestamp ( )
    if 89 - 89: I1Ii111
    i1I1i1I1iiiII = "" if II11IIiii . unreach_state ( ) == False else " unreachable"
    if 65 - 65: O0 % Ii1I - I11i + o0oOOo0O0Ooo . OoOoOO00
    if 3 - 3: OOooOOo % II111iiii - OOooOOo / Oo0Ooo . i1IIi
    if 65 - 65: OoooooooOO . OoO0O00 / i1IIi . II111iiii . I1Ii111
    if 81 - 81: II111iiii + OoOoOO00 * II111iiii / iIii1I11I1II1 - Oo0Ooo % oO0o
    if 66 - 66: ooOoO0o % O0 + iIii1I11I1II1 * I1Ii111 - I1Ii111
    if 61 - 61: I1ii11iIi11i
    if 12 - 12: OoO0O00
    OOoIiiiIIiII = ""
    iiiIIiII111I = None
    if ( II11IIiii . rloc_next_hop != None ) :
     OooOo , iiiIIiII111I = II11IIiii . rloc_next_hop
     lisp_install_host_route ( i111I11I , iiiIIiII111I , True )
     OOoIiiiIIiII = ", send on nh {}({})" . format ( iiiIIiII111I , OooOo )
     if 60 - 60: ooOoO0o % Ii1I
     if 33 - 33: OoO0O00 . II111iiii % iIii1I11I1II1
     if 61 - 61: I1ii11iIi11i * oO0o % iII111i + IiII + i11iIiiIii * I11i
     if 3 - 3: Ii1I
     if 71 - 71: iIii1I11I1II1 . OOooOOo / I11i / i1IIi
    oOOO0Ooooo = II11IIiii . print_rloc_probe_rtt ( )
    OoO0O = i111I11I
    if ( II11IIiii . translated_port != 0 ) :
     OoO0O += ":{}" . format ( II11IIiii . translated_port )
     if 80 - 80: IiII % O0 * Oo0Ooo
    OoO0O = red ( OoO0O , False )
    if ( II11IIiii . rloc_name != None ) :
     OoO0O += " (" + blue ( II11IIiii . rloc_name , False ) + ")"
     if 97 - 97: I1IiiI
    lprint ( "Send {}{} {}, last rtt: {}{}" . format ( OOo00o , i1I1i1I1iiiII ,
 OoO0O , oOOO0Ooooo , OOoIiiiIIiII ) )
    if 91 - 91: ooOoO0o / oO0o * OOooOOo . II111iiii - I11i - I11i
    if 5 - 5: O0 + OoooooooOO + i11iIiiIii * Oo0Ooo * OoOoOO00 . oO0o
    if 6 - 6: OoO0O00 % Oo0Ooo % I1IiiI % o0oOOo0O0Ooo % O0 % Oo0Ooo
    if 94 - 94: I11i . i1IIi / II111iiii + OOooOOo
    if 64 - 64: I1IiiI % ooOoO0o
    if 72 - 72: O0 * II111iiii % OoO0O00 - I1IiiI * OOooOOo
    if 80 - 80: OOooOOo * I11i / OOooOOo - oO0o
    if 18 - 18: i1IIi - OOooOOo - o0oOOo0O0Ooo - iIii1I11I1II1
    if ( II11IIiii . rloc_next_hop != None ) :
     iI1II1IiIiIi = lisp_get_host_route_next_hop ( i111I11I )
     if ( iI1II1IiIiIi ) : lisp_install_host_route ( i111I11I , iI1II1IiIiIi , False )
     if 72 - 72: OoooooooOO % I1IiiI . OoO0O00
     if 28 - 28: II111iiii / iIii1I11I1II1 / iII111i - o0oOOo0O0Ooo . I1IiiI / O0
     if 16 - 16: ooOoO0o * oO0o . OoooooooOO
     if 44 - 44: iIii1I11I1II1 * OOooOOo + OoO0O00 - OoooooooOO
     if 13 - 13: Oo0Ooo . I11i . II111iiii
     if 6 - 6: OOooOOo . IiII / OoO0O00 * oO0o - I1Ii111 . OoOoOO00
    if ( II11IIiii . rloc . is_null ( ) ) :
     II11IIiii . rloc . copy_address ( O00O0oooO0 . rloc )
     if 85 - 85: i11iIiiIii + OoOoOO00
     if 4 - 4: OOooOOo . OoO0O00 * II111iiii + OoO0O00 % Oo0Ooo
     if 60 - 60: OOooOOo . Ii1I
     if 13 - 13: i1IIi . iII111i / OoOoOO00 . I1Ii111
     if 65 - 65: oO0o % I1Ii111 % OoO0O00 . iIii1I11I1II1
    I1IIiI = None if ( IiI1111i1i11I . is_null ( ) ) else ii1Ii
    I1i1 = ii1Ii if ( IiI1111i1i11I . is_null ( ) ) else IiI1111i1i11I
    lisp_send_map_request ( lisp_sockets , 0 , I1IIiI , I1i1 , II11IIiii )
    O0O0Ooo0O = O00O0oooO0
    if 89 - 89: II111iiii * oO0o . OoooooooOO / IiII / IiII + iII111i
    if 15 - 15: OoOoOO00 . IiII / iIii1I11I1II1 . OoooooooOO
    if 14 - 14: IiII * OoooooooOO - iIii1I11I1II1
    if 11 - 11: I1IiiI + Oo0Ooo % I1Ii111 * Ii1I - iIii1I11I1II1 % I1ii11iIi11i
    if ( iiiIIiII111I ) : lisp_install_host_route ( i111I11I , iiiIIiII111I , False )
    if 43 - 43: o0oOOo0O0Ooo * o0oOOo0O0Ooo . iII111i / Oo0Ooo - i11iIiiIii
    if 66 - 66: I1IiiI / i1IIi + o0oOOo0O0Ooo % IiII - OoOoOO00 / Oo0Ooo
    if 22 - 22: oO0o % I1Ii111 - I1Ii111 / I1Ii111
    if 25 - 25: OoooooooOO / oO0o / ooOoO0o / I1IiiI * I1ii11iIi11i . o0oOOo0O0Ooo
    if 30 - 30: o0oOOo0O0Ooo / i11iIiiIii
   if ( iI1II1IiIiIi ) : lisp_install_host_route ( i111I11I , iI1II1IiIiIi , True )
   if 33 - 33: OOooOOo % OoooooooOO
   if 98 - 98: Ii1I
   if 38 - 38: ooOoO0o - iII111i * OOooOOo % I1ii11iIi11i + Oo0Ooo
   if 95 - 95: iIii1I11I1II1 / O0 % O0
   O0oO += 1
   if ( ( O0oO % 10 ) == 0 ) : time . sleep ( 0.020 )
   if 53 - 53: ooOoO0o . ooOoO0o
   if 80 - 80: i11iIiiIii % I1Ii111 % I1IiiI / I1IiiI + oO0o + iII111i
   if 18 - 18: OoO0O00 * ooOoO0o
 lprint ( "---------- End RLOC Probing ----------" )
 return
 if 32 - 32: oO0o . OoooooooOO - o0oOOo0O0Ooo + II111iiii
 if 4 - 4: OOooOOo * I1IiiI - I11i - I11i
 if 67 - 67: I1IiiI
 if 32 - 32: oO0o * i11iIiiIii - I11i % Oo0Ooo * I1ii11iIi11i
 if 79 - 79: II111iiii / Oo0Ooo / I1ii11iIi11i
 if 30 - 30: I11i . o0oOOo0O0Ooo / II111iiii
 if 59 - 59: i11iIiiIii
 if 5 - 5: i11iIiiIii + o0oOOo0O0Ooo . OoO0O00 % OoOoOO00 + I11i
def lisp_update_rtr_updown ( rtr , updown ) :
 global lisp_ipc_socket
 if 59 - 59: I1ii11iIi11i
 if 47 - 47: I1IiiI + Oo0Ooo
 if 78 - 78: i1IIi / I1ii11iIi11i % ooOoO0o * OoO0O00
 if 10 - 10: i1IIi % ooOoO0o / iII111i
 if ( lisp_i_am_itr == False ) : return
 if 98 - 98: IiII / o0oOOo0O0Ooo - i1IIi - OOooOOo
 if 65 - 65: Ii1I + OoOoOO00 * Oo0Ooo . O0 . IiII
 if 33 - 33: i11iIiiIii . i1IIi . I1Ii111 - OoOoOO00 + OOooOOo
 if 34 - 34: I1ii11iIi11i . i1IIi * O0 / OoooooooOO
 if 22 - 22: OOooOOo % o0oOOo0O0Ooo - i11iIiiIii
 if ( lisp_register_all_rtrs ) : return
 if 58 - 58: IiII . Ii1I + II111iiii
 IiIi11 = rtr . print_address_no_iid ( )
 if 1 - 1: II111iiii % IiII + OOooOOo
 if 92 - 92: OoOoOO00
 if 75 - 75: Oo0Ooo % IiII + II111iiii + oO0o
 if 35 - 35: I1ii11iIi11i - oO0o - O0 / iII111i % IiII
 if 10 - 10: OOooOOo + oO0o - I1Ii111 . I1IiiI
 if ( lisp_rtr_list . has_key ( IiIi11 ) == False ) : return
 if 11 - 11: I1ii11iIi11i . I1Ii111 / o0oOOo0O0Ooo + IiII
 updown = "up" if updown else "down"
 lprint ( "Send ETR IPC message, RTR {} has done {}" . format (
 red ( IiIi11 , False ) , bold ( updown , False ) ) )
 if 73 - 73: OoO0O00 . i11iIiiIii * OoO0O00 * i1IIi + I11i
 if 27 - 27: i11iIiiIii / OoOoOO00 % O0 / II111iiii . I11i - ooOoO0o
 if 54 - 54: oO0o * II111iiii
 if 79 - 79: o0oOOo0O0Ooo . ooOoO0o . Oo0Ooo * OoooooooOO
 OOO000OOOO0oO = "rtr%{}%{}" . format ( IiIi11 , updown )
 OOO000OOOO0oO = lisp_command_ipc ( OOO000OOOO0oO , "lisp-itr" )
 lisp_ipc ( OOO000OOOO0oO , lisp_ipc_socket , "lisp-etr" )
 return
 if 98 - 98: ooOoO0o
 if 73 - 73: I1Ii111
 if 97 - 97: OoO0O00 * Ii1I + Oo0Ooo
 if 83 - 83: II111iiii - Oo0Ooo % II111iiii * o0oOOo0O0Ooo
 if 51 - 51: iII111i * iIii1I11I1II1 % Ii1I * Ii1I + i11iIiiIii . OoooooooOO
 if 54 - 54: i11iIiiIii . iIii1I11I1II1 * iIii1I11I1II1 + Ii1I % I11i - OoO0O00
 if 16 - 16: IiII % iIii1I11I1II1 * i11iIiiIii + O0
def lisp_process_rloc_probe_reply ( rloc , source , port , nonce , hop_count , ttl ) :
 OOo00o = bold ( "RLOC-probe reply" , False )
 o00oOO0OOO0O0 = rloc . print_address_no_iid ( )
 OOo0000000 = source . print_address_no_iid ( )
 iiIIi1i1i1 = lisp_rloc_probe_list
 if 49 - 49: Oo0Ooo / I1ii11iIi11i / I1IiiI * OoooooooOO . I1ii11iIi11i
 if 100 - 100: iIii1I11I1II1 . i1IIi / OOooOOo * i11iIiiIii
 if 93 - 93: I1ii11iIi11i
 if 45 - 45: I1ii11iIi11i * I1ii11iIi11i
 if 31 - 31: OoO0O00 - OOooOOo . iII111i * I1Ii111 * iII111i + I1ii11iIi11i
 if 5 - 5: Oo0Ooo . I1Ii111
 oOo00Ooo0o0 = o00oOO0OOO0O0
 if ( iiIIi1i1i1 . has_key ( oOo00Ooo0o0 ) == False ) :
  oOo00Ooo0o0 += ":" + str ( port )
  if ( iiIIi1i1i1 . has_key ( oOo00Ooo0o0 ) == False ) :
   oOo00Ooo0o0 = OOo0000000
   if ( iiIIi1i1i1 . has_key ( oOo00Ooo0o0 ) == False ) :
    oOo00Ooo0o0 += ":" + str ( port )
    lprint ( "    Received unsolicited {} from {}/{}, port {}" . format ( OOo00o , red ( o00oOO0OOO0O0 , False ) , red ( OOo0000000 ,
    # OoooooooOO - II111iiii . OOooOOo * oO0o - iII111i
 False ) , port ) )
    return
    if 62 - 62: II111iiii % OoOoOO00 . I11i - I1IiiI / oO0o
    if 11 - 11: I1Ii111 - OoooooooOO
    if 17 - 17: O0 * I1ii11iIi11i
    if 55 - 55: o0oOOo0O0Ooo * Oo0Ooo . ooOoO0o
    if 25 - 25: IiII . O0 / OoOoOO00
    if 33 - 33: OoO0O00
    if 55 - 55: ooOoO0o + ooOoO0o
    if 93 - 93: oO0o - I1IiiI / I1ii11iIi11i % o0oOOo0O0Ooo / OoooooooOO + II111iiii
 for rloc , ii1Ii , IiI1111i1i11I in lisp_rloc_probe_list [ oOo00Ooo0o0 ] :
  if ( lisp_i_am_rtr and rloc . translated_port != 0 and
 rloc . translated_port != port ) : continue
  if 10 - 10: o0oOOo0O0Ooo - iII111i . O0 + OoO0O00 - Oo0Ooo - i11iIiiIii
  rloc . process_rloc_probe_reply ( nonce , ii1Ii , IiI1111i1i11I , hop_count , ttl )
  if 37 - 37: iIii1I11I1II1
 return
 if 37 - 37: II111iiii % OoOoOO00 . IiII * ooOoO0o . I1IiiI
 if 25 - 25: OoooooooOO % i1IIi . I1Ii111 / OoOoOO00 - I1ii11iIi11i
 if 15 - 15: iIii1I11I1II1
 if 72 - 72: OoO0O00 . IiII * Ii1I - I1IiiI
 if 81 - 81: oO0o . OOooOOo - Ii1I . OoOoOO00
 if 100 - 100: Ii1I * i1IIi * i1IIi - iII111i + OoO0O00 + OoO0O00
 if 9 - 9: oO0o / OoO0O00 . I1IiiI
 if 24 - 24: IiII * i11iIiiIii % o0oOOo0O0Ooo - ooOoO0o + ooOoO0o . II111iiii
def lisp_db_list_length ( ) :
 O0oO = 0
 for i1i1iiiii1IiI in lisp_db_list :
  O0oO += len ( i1i1iiiii1IiI . dynamic_eids ) if i1i1iiiii1IiI . dynamic_eid_configured ( ) else 1
  O0oO += len ( i1i1iiiii1IiI . eid . iid_list )
  if 69 - 69: I1IiiI . i11iIiiIii - o0oOOo0O0Ooo
 return ( O0oO )
 if 40 - 40: OOooOOo * Ii1I
 if 38 - 38: ooOoO0o
 if 5 - 5: OoooooooOO + iII111i - I11i
 if 95 - 95: OOooOOo / i11iIiiIii - Ii1I + I1ii11iIi11i
 if 7 - 7: I1ii11iIi11i
 if 37 - 37: O0 . II111iiii
 if 70 - 70: o0oOOo0O0Ooo / iII111i + i1IIi + I11i % iIii1I11I1II1 % Oo0Ooo
 if 1 - 1: O0 + OoO0O00 . i11iIiiIii + I1Ii111 - OoO0O00 - IiII
def lisp_is_myeid ( eid ) :
 for i1i1iiiii1IiI in lisp_db_list :
  if ( eid . is_more_specific ( i1i1iiiii1IiI . eid ) ) : return ( True )
  if 1 - 1: I1ii11iIi11i / i1IIi . I1IiiI / Ii1I
 return ( False )
 if 19 - 19: iIii1I11I1II1 / Oo0Ooo . O0 - Oo0Ooo
 if 74 - 74: I1ii11iIi11i * OoooooooOO . iII111i
 if 45 - 45: I1IiiI - IiII % ooOoO0o - IiII . Oo0Ooo - o0oOOo0O0Ooo
 if 27 - 27: iII111i
 if 64 - 64: iIii1I11I1II1 - OOooOOo . iII111i % o0oOOo0O0Ooo / II111iiii % OoooooooOO
 if 87 - 87: OoooooooOO
 if 70 - 70: o0oOOo0O0Ooo % OoooooooOO % I1IiiI . OoOoOO00 * I1IiiI - ooOoO0o
 if 92 - 92: I1IiiI . I11i
 if 66 - 66: I1Ii111 / I11i / OoooooooOO % OoOoOO00 . oO0o * iII111i
def lisp_format_macs ( sa , da ) :
 sa = sa [ 0 : 4 ] + "-" + sa [ 4 : 8 ] + "-" + sa [ 8 : 12 ]
 da = da [ 0 : 4 ] + "-" + da [ 4 : 8 ] + "-" + da [ 8 : 12 ]
 return ( "{} -> {}" . format ( sa , da ) )
 if 34 - 34: I1ii11iIi11i * I1ii11iIi11i % I11i / OOooOOo % oO0o . OoOoOO00
 if 25 - 25: I1ii11iIi11i / I11i + i1IIi . I1IiiI + ooOoO0o
 if 29 - 29: IiII + I1ii11iIi11i
 if 8 - 8: IiII % I1IiiI
 if 10 - 10: OoooooooOO / OoOoOO00
 if 77 - 77: OoOoOO00
 if 10 - 10: IiII / i11iIiiIii
def lisp_get_echo_nonce ( rloc , rloc_str ) :
 if ( lisp_nonce_echoing == False ) : return ( None )
 if 19 - 19: OoO0O00
 if ( rloc ) : rloc_str = rloc . print_address_no_iid ( )
 I1iiiIi1i11i = None
 if ( lisp_nonce_echo_list . has_key ( rloc_str ) ) :
  I1iiiIi1i11i = lisp_nonce_echo_list [ rloc_str ]
  if 100 - 100: I1ii11iIi11i - I1ii11iIi11i
 return ( I1iiiIi1i11i )
 if 38 - 38: I1Ii111
 if 23 - 23: Ii1I . I1ii11iIi11i + I1Ii111 + i1IIi * o0oOOo0O0Ooo - i11iIiiIii
 if 92 - 92: I1Ii111 - I1IiiI + Ii1I / iII111i % OOooOOo
 if 32 - 32: i1IIi . iII111i - Ii1I % iII111i % II111iiii - oO0o
 if 36 - 36: OoooooooOO * OoooooooOO . ooOoO0o . O0
 if 5 - 5: I11i % I1IiiI - OoO0O00 . Oo0Ooo
 if 79 - 79: iII111i + IiII % I11i . Oo0Ooo / IiII * iII111i
 if 40 - 40: iII111i - I1IiiI + OoOoOO00
def lisp_decode_dist_name ( packet ) :
 O0oO = 0
 i1ii1iIII = ""
 if 90 - 90: i11iIiiIii + II111iiii + I1IiiI % I1ii11iIi11i
 while ( packet [ 0 : 1 ] != "\0" ) :
  if ( O0oO == 255 ) : return ( [ None , None ] )
  i1ii1iIII += packet [ 0 : 1 ]
  packet = packet [ 1 : : ]
  O0oO += 1
  if 3 - 3: I1Ii111 + Ii1I + Ii1I + iIii1I11I1II1 + I1Ii111 * I11i
  if 44 - 44: i1IIi - I1IiiI / IiII + IiII
 packet = packet [ 1 : : ]
 return ( packet , i1ii1iIII )
 if 65 - 65: OOooOOo * I1Ii111 . i1IIi % iIii1I11I1II1
 if 31 - 31: I1IiiI * I1Ii111 * O0 * I1Ii111 . II111iiii
 if 52 - 52: iIii1I11I1II1 . oO0o % I1Ii111 + i11iIiiIii
 if 43 - 43: I1ii11iIi11i + I11i - iIii1I11I1II1
 if 100 - 100: OoOoOO00
 if 28 - 28: ooOoO0o + Oo0Ooo - I1ii11iIi11i
 if 16 - 16: O0 - OoO0O00 % Ii1I % O0
 if 51 - 51: iIii1I11I1II1 * i11iIiiIii . I1IiiI + o0oOOo0O0Ooo / iII111i - I1IiiI
def lisp_write_flow_log ( flow_log ) :
 ii1iIii = open ( "./logs/lisp-flow.log" , "a" )
 if 73 - 73: OOooOOo
 O0oO = 0
 for O0Oo00o0o in flow_log :
  Ii11iIiiI = O0Oo00o0o [ 3 ]
  oOO0Ooooo = Ii11iIiiI . print_flow ( O0Oo00o0o [ 0 ] , O0Oo00o0o [ 1 ] , O0Oo00o0o [ 2 ] )
  ii1iIii . write ( oOO0Ooooo )
  O0oO += 1
  if 93 - 93: O0 . iII111i + ooOoO0o
 ii1iIii . close ( )
 del ( flow_log )
 if 5 - 5: i1IIi + ooOoO0o % O0
 O0oO = bold ( str ( O0oO ) , False )
 lprint ( "Wrote {} flow entries to ./logs/lisp-flow.log" . format ( O0oO ) )
 return
 if 70 - 70: O0 * iIii1I11I1II1 - OoooooooOO + o0oOOo0O0Ooo
 if 38 - 38: I1ii11iIi11i % I1ii11iIi11i + IiII / OoooooooOO - iII111i
 if 53 - 53: oO0o
 if 13 - 13: Ii1I
 if 83 - 83: o0oOOo0O0Ooo + oO0o % oO0o
 if 44 - 44: OoooooooOO
 if 87 - 87: ooOoO0o
def lisp_policy_command ( kv_pair ) :
 IiIiI1 = lisp_policy ( "" )
 OO0OooOOO = None
 if 33 - 33: OoO0O00 + II111iiii . Oo0Ooo * I1Ii111
 ooOOoOO = [ ]
 for oo0O0oO0O0O in range ( len ( kv_pair [ "datetime-range" ] ) ) :
  ooOOoOO . append ( lisp_policy_match ( ) )
  if 36 - 36: I1IiiI % O0 + OoO0O00
  if 37 - 37: II111iiii / I1ii11iIi11i * I1IiiI - OoooooooOO
 for O000i11II11I in kv_pair . keys ( ) :
  O000O = kv_pair [ O000i11II11I ]
  if 43 - 43: iIii1I11I1II1
  if 29 - 29: IiII . OoOoOO00 + I1IiiI
  if 42 - 42: iIii1I11I1II1 * OoOoOO00 * I11i + iII111i / i11iIiiIii
  if 46 - 46: ooOoO0o + ooOoO0o / IiII
  if ( O000i11II11I == "instance-id" ) :
   for oo0O0oO0O0O in range ( len ( ooOOoOO ) ) :
    oOO0ooo = O000O [ oo0O0oO0O0O ]
    if ( oOO0ooo == "" ) : continue
    Ii1iiI11I = ooOOoOO [ oo0O0oO0O0O ]
    if ( Ii1iiI11I . source_eid == None ) :
     Ii1iiI11I . source_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
     if 24 - 24: o0oOOo0O0Ooo * I11i . I1IiiI
    if ( Ii1iiI11I . dest_eid == None ) :
     Ii1iiI11I . dest_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
     if 52 - 52: OoooooooOO * I1Ii111 % II111iiii
    Ii1iiI11I . source_eid . instance_id = int ( oOO0ooo )
    Ii1iiI11I . dest_eid . instance_id = int ( oOO0ooo )
    if 40 - 40: I11i / ooOoO0o . OoO0O00 + i1IIi + iII111i - Ii1I
    if 9 - 9: o0oOOo0O0Ooo
  if ( O000i11II11I == "source-eid" ) :
   for oo0O0oO0O0O in range ( len ( ooOOoOO ) ) :
    oOO0ooo = O000O [ oo0O0oO0O0O ]
    if ( oOO0ooo == "" ) : continue
    Ii1iiI11I = ooOOoOO [ oo0O0oO0O0O ]
    if ( Ii1iiI11I . source_eid == None ) :
     Ii1iiI11I . source_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
     if 92 - 92: i11iIiiIii + OoooooooOO + O0 % oO0o
    II1ii1ii11I1 = Ii1iiI11I . source_eid . instance_id
    Ii1iiI11I . source_eid . store_prefix ( oOO0ooo )
    Ii1iiI11I . source_eid . instance_id = II1ii1ii11I1
    if 90 - 90: Oo0Ooo * i11iIiiIii
    if 95 - 95: I1Ii111 % i11iIiiIii . i11iIiiIii . i11iIiiIii . OoooooooOO - I1Ii111
  if ( O000i11II11I == "destination-eid" ) :
   for oo0O0oO0O0O in range ( len ( ooOOoOO ) ) :
    oOO0ooo = O000O [ oo0O0oO0O0O ]
    if ( oOO0ooo == "" ) : continue
    Ii1iiI11I = ooOOoOO [ oo0O0oO0O0O ]
    if ( Ii1iiI11I . dest_eid == None ) :
     Ii1iiI11I . dest_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
     if 69 - 69: iIii1I11I1II1 * oO0o
    II1ii1ii11I1 = Ii1iiI11I . dest_eid . instance_id
    Ii1iiI11I . dest_eid . store_prefix ( oOO0ooo )
    Ii1iiI11I . dest_eid . instance_id = II1ii1ii11I1
    if 80 - 80: IiII - oO0o % Ii1I - iIii1I11I1II1 . OoO0O00
    if 64 - 64: I1IiiI % i11iIiiIii / oO0o
  if ( O000i11II11I == "source-rloc" ) :
   for oo0O0oO0O0O in range ( len ( ooOOoOO ) ) :
    oOO0ooo = O000O [ oo0O0oO0O0O ]
    if ( oOO0ooo == "" ) : continue
    Ii1iiI11I = ooOOoOO [ oo0O0oO0O0O ]
    Ii1iiI11I . source_rloc = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
    Ii1iiI11I . source_rloc . store_prefix ( oOO0ooo )
    if 78 - 78: II111iiii - Oo0Ooo . iIii1I11I1II1 - ooOoO0o . oO0o
    if 84 - 84: iII111i . ooOoO0o * I1IiiI * Oo0Ooo / I1Ii111
  if ( O000i11II11I == "destination-rloc" ) :
   for oo0O0oO0O0O in range ( len ( ooOOoOO ) ) :
    oOO0ooo = O000O [ oo0O0oO0O0O ]
    if ( oOO0ooo == "" ) : continue
    Ii1iiI11I = ooOOoOO [ oo0O0oO0O0O ]
    Ii1iiI11I . dest_rloc = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
    Ii1iiI11I . dest_rloc . store_prefix ( oOO0ooo )
    if 93 - 93: i1IIi * i11iIiiIii % OoOoOO00 % iII111i
    if 31 - 31: OoO0O00
  if ( O000i11II11I == "rloc-record-name" ) :
   for oo0O0oO0O0O in range ( len ( ooOOoOO ) ) :
    oOO0ooo = O000O [ oo0O0oO0O0O ]
    if ( oOO0ooo == "" ) : continue
    Ii1iiI11I = ooOOoOO [ oo0O0oO0O0O ]
    Ii1iiI11I . rloc_record_name = oOO0ooo
    if 89 - 89: II111iiii
    if 33 - 33: OOooOOo / oO0o % OoOoOO00 * O0
  if ( O000i11II11I == "geo-name" ) :
   for oo0O0oO0O0O in range ( len ( ooOOoOO ) ) :
    oOO0ooo = O000O [ oo0O0oO0O0O ]
    if ( oOO0ooo == "" ) : continue
    Ii1iiI11I = ooOOoOO [ oo0O0oO0O0O ]
    Ii1iiI11I . geo_name = oOO0ooo
    if 65 - 65: OoO0O00 % OoOoOO00 % I1ii11iIi11i / OoooooooOO
    if 85 - 85: O0 * OOooOOo % I1Ii111
  if ( O000i11II11I == "elp-name" ) :
   for oo0O0oO0O0O in range ( len ( ooOOoOO ) ) :
    oOO0ooo = O000O [ oo0O0oO0O0O ]
    if ( oOO0ooo == "" ) : continue
    Ii1iiI11I = ooOOoOO [ oo0O0oO0O0O ]
    Ii1iiI11I . elp_name = oOO0ooo
    if 33 - 33: O0
    if 30 - 30: II111iiii . O0 . oO0o * I1ii11iIi11i + oO0o . o0oOOo0O0Ooo
  if ( O000i11II11I == "rle-name" ) :
   for oo0O0oO0O0O in range ( len ( ooOOoOO ) ) :
    oOO0ooo = O000O [ oo0O0oO0O0O ]
    if ( oOO0ooo == "" ) : continue
    Ii1iiI11I = ooOOoOO [ oo0O0oO0O0O ]
    Ii1iiI11I . rle_name = oOO0ooo
    if 43 - 43: iIii1I11I1II1
    if 88 - 88: I1IiiI - OoO0O00 . O0 . oO0o
  if ( O000i11II11I == "json-name" ) :
   for oo0O0oO0O0O in range ( len ( ooOOoOO ) ) :
    oOO0ooo = O000O [ oo0O0oO0O0O ]
    if ( oOO0ooo == "" ) : continue
    Ii1iiI11I = ooOOoOO [ oo0O0oO0O0O ]
    Ii1iiI11I . json_name = oOO0ooo
    if 75 - 75: II111iiii % OOooOOo / iIii1I11I1II1 / OoO0O00 + oO0o
    if 16 - 16: oO0o + I1Ii111 - II111iiii - o0oOOo0O0Ooo / i11iIiiIii
  if ( O000i11II11I == "datetime-range" ) :
   for oo0O0oO0O0O in range ( len ( ooOOoOO ) ) :
    oOO0ooo = O000O [ oo0O0oO0O0O ]
    Ii1iiI11I = ooOOoOO [ oo0O0oO0O0O ]
    if ( oOO0ooo == "" ) : continue
    oooo0 = lisp_datetime ( oOO0ooo [ 0 : 19 ] )
    o0oOo0o0 = lisp_datetime ( oOO0ooo [ 19 : : ] )
    if ( oooo0 . valid_datetime ( ) and o0oOo0o0 . valid_datetime ( ) ) :
     Ii1iiI11I . datetime_lower = oooo0
     Ii1iiI11I . datetime_upper = o0oOo0o0
     if 59 - 59: OOooOOo - o0oOOo0O0Ooo
     if 82 - 82: IiII % ooOoO0o - OoO0O00 % ooOoO0o
     if 51 - 51: ooOoO0o % iII111i . o0oOOo0O0Ooo . o0oOOo0O0Ooo
     if 20 - 20: i1IIi - ooOoO0o % OoooooooOO * I1ii11iIi11i + II111iiii % i1IIi
     if 30 - 30: i11iIiiIii - I1IiiI + o0oOOo0O0Ooo + IiII
     if 16 - 16: I1ii11iIi11i / Ii1I + I1ii11iIi11i * I1Ii111
     if 49 - 49: ooOoO0o * OoOoOO00 . OoooooooOO . ooOoO0o + Oo0Ooo * IiII
  if ( O000i11II11I == "set-action" ) :
   IiIiI1 . set_action = O000O
   if 47 - 47: iII111i . i1IIi . I1ii11iIi11i / OoooooooOO
  if ( O000i11II11I == "set-record-ttl" ) :
   IiIiI1 . set_record_ttl = int ( O000O )
   if 84 - 84: o0oOOo0O0Ooo * I11i
  if ( O000i11II11I == "set-instance-id" ) :
   if ( IiIiI1 . set_source_eid == None ) :
    IiIiI1 . set_source_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
    if 22 - 22: i1IIi + OOooOOo % OoooooooOO
   if ( IiIiI1 . set_dest_eid == None ) :
    IiIiI1 . set_dest_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
    if 34 - 34: oO0o / O0 - II111iiii % Oo0Ooo + I11i
   OO0OooOOO = int ( O000O )
   IiIiI1 . set_source_eid . instance_id = OO0OooOOO
   IiIiI1 . set_dest_eid . instance_id = OO0OooOOO
   if 23 - 23: o0oOOo0O0Ooo + i11iIiiIii . I1IiiI + iIii1I11I1II1
  if ( O000i11II11I == "set-source-eid" ) :
   if ( IiIiI1 . set_source_eid == None ) :
    IiIiI1 . set_source_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
    if 18 - 18: o0oOOo0O0Ooo . O0 + I1Ii111
   IiIiI1 . set_source_eid . store_prefix ( O000O )
   if ( OO0OooOOO != None ) : IiIiI1 . set_source_eid . instance_id = OO0OooOOO
   if 66 - 66: OoooooooOO
  if ( O000i11II11I == "set-destination-eid" ) :
   if ( IiIiI1 . set_dest_eid == None ) :
    IiIiI1 . set_dest_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
    if 90 - 90: IiII - OoOoOO00
   IiIiI1 . set_dest_eid . store_prefix ( O000O )
   if ( OO0OooOOO != None ) : IiIiI1 . set_dest_eid . instance_id = OO0OooOOO
   if 98 - 98: Oo0Ooo / oO0o . Ii1I
  if ( O000i11II11I == "set-rloc-address" ) :
   IiIiI1 . set_rloc_address = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
   IiIiI1 . set_rloc_address . store_address ( O000O )
   if 56 - 56: ooOoO0o % OoO0O00 * i11iIiiIii % IiII % I1IiiI - oO0o
  if ( O000i11II11I == "set-rloc-record-name" ) :
   IiIiI1 . set_rloc_record_name = O000O
   if 37 - 37: iII111i - Ii1I . oO0o
  if ( O000i11II11I == "set-elp-name" ) :
   IiIiI1 . set_elp_name = O000O
   if 47 - 47: IiII / I1ii11iIi11i . o0oOOo0O0Ooo . ooOoO0o + OOooOOo . OOooOOo
  if ( O000i11II11I == "set-geo-name" ) :
   IiIiI1 . set_geo_name = O000O
   if 25 - 25: oO0o
  if ( O000i11II11I == "set-rle-name" ) :
   IiIiI1 . set_rle_name = O000O
   if 43 - 43: Ii1I - o0oOOo0O0Ooo % oO0o - O0
  if ( O000i11II11I == "set-json-name" ) :
   IiIiI1 . set_json_name = O000O
   if 20 - 20: OoO0O00 . ooOoO0o / OoOoOO00 - OoOoOO00 . iII111i / OOooOOo
  if ( O000i11II11I == "policy-name" ) :
   IiIiI1 . policy_name = O000O
   if 39 - 39: iIii1I11I1II1 % ooOoO0o
   if 75 - 75: i1IIi * II111iiii * O0 * i11iIiiIii % iII111i / iII111i
   if 36 - 36: IiII / I1IiiI % iII111i / iII111i
   if 38 - 38: OOooOOo * I1ii11iIi11i * I1Ii111 + I11i
   if 65 - 65: O0 + O0 * I1Ii111
   if 66 - 66: OOooOOo / O0 + i1IIi . O0 % I1ii11iIi11i - OoooooooOO
 IiIiI1 . match_clauses = ooOOoOO
 IiIiI1 . save_policy ( )
 return
 if 16 - 16: I11i % iII111i
 if 29 - 29: I1IiiI - ooOoO0o * OoO0O00 . i11iIiiIii % OoOoOO00 * o0oOOo0O0Ooo
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
if 43 - 43: OoO0O00 * OOooOOo / I1Ii111 % OoOoOO00 . oO0o / OOooOOo
if 62 - 62: O0 * I1ii11iIi11i - O0 / I11i % ooOoO0o
if 1 - 1: O0 / iIii1I11I1II1
if 17 - 17: OoOoOO00 + ooOoO0o * II111iiii * OoOoOO00 + I1IiiI + i11iIiiIii
if 46 - 46: i1IIi - II111iiii . I1IiiI . i11iIiiIii
if 54 - 54: O0 * I1ii11iIi11i / OOooOOo / IiII * IiII
if 69 - 69: Oo0Ooo * OoooooooOO / I1IiiI
def lisp_send_to_arista ( command , interface ) :
 interface = "" if ( interface == None ) else "interface " + interface
 if 16 - 16: o0oOOo0O0Ooo
 iiIOoO0OO0OO000o = command
 if ( interface != "" ) : iiIOoO0OO0OO000o = interface + ": " + iiIOoO0OO0OO000o
 lprint ( "Send CLI command '{}' to hardware" . format ( iiIOoO0OO0OO000o ) )
 if 10 - 10: IiII + OOooOOo . iII111i - ooOoO0o
 commands = '''
        enable
        configure
        {}
        {}
    ''' . format ( interface , command )
 if 100 - 100: o0oOOo0O0Ooo
 os . system ( "FastCli -c '{}'" . format ( commands ) )
 return
 if 95 - 95: iII111i * oO0o * i1IIi
 if 100 - 100: iII111i . o0oOOo0O0Ooo - I1Ii111 % oO0o
 if 11 - 11: o0oOOo0O0Ooo . OoooooooOO - i1IIi
 if 71 - 71: I1IiiI . OOooOOo . I1ii11iIi11i
 if 90 - 90: i11iIiiIii + I1Ii111 % II111iiii
 if 67 - 67: OoOoOO00 / iII111i * OoO0O00 % i11iIiiIii
 if 76 - 76: OoO0O00
def lisp_arista_is_alive ( prefix ) :
 oO0O = "enable\nsh plat trident l3 software routes {}\n" . format ( prefix )
 II1i11i1iIi11 = commands . getoutput ( "FastCli -c '{}'" . format ( oO0O ) )
 if 92 - 92: iIii1I11I1II1 * O0 % I11i
 if 92 - 92: OoOoOO00 + oO0o
 if 89 - 89: IiII % iII111i / iIii1I11I1II1 . Ii1I . Oo0Ooo + ooOoO0o
 if 28 - 28: I1IiiI . iIii1I11I1II1
 II1i11i1iIi11 = II1i11i1iIi11 . split ( "\n" ) [ 1 ]
 i1IiI1i1i1iII = II1i11i1iIi11 . split ( " " )
 i1IiI1i1i1iII = i1IiI1i1i1iII [ - 1 ] . replace ( "\r" , "" )
 if 33 - 33: oO0o / I11i % ooOoO0o * I11i / oO0o - OoOoOO00
 if 89 - 89: iIii1I11I1II1 . II111iiii + IiII
 if 8 - 8: I1ii11iIi11i / II111iiii / II111iiii
 if 62 - 62: I11i - iII111i . Ii1I
 return ( i1IiI1i1i1iII == "Y" )
 if 20 - 20: I1ii11iIi11i
 if 99 - 99: o0oOOo0O0Ooo + I1ii11iIi11i * IiII
 if 67 - 67: I1IiiI
 if 93 - 93: ooOoO0o . Ii1I + IiII / Oo0Ooo % I11i
 if 40 - 40: Oo0Ooo % OoOoOO00 . IiII / I1IiiI % OoooooooOO
 if 33 - 33: OOooOOo - OoooooooOO . iII111i
 if 2 - 2: I11i + i1IIi
 if 52 - 52: I11i - OoO0O00 % I1Ii111 . OOooOOo
 if 90 - 90: O0 - Oo0Ooo / i1IIi * iIii1I11I1II1 % o0oOOo0O0Ooo / oO0o
 if 73 - 73: iII111i % iIii1I11I1II1 + o0oOOo0O0Ooo % Ii1I . II111iiii + IiII
 if 55 - 55: OoOoOO00 * II111iiii / iII111i + OOooOOo / OoooooooOO
 if 12 - 12: II111iiii * O0 - Oo0Ooo + o0oOOo0O0Ooo . Oo0Ooo + iIii1I11I1II1
 if 4 - 4: I1Ii111 - I1Ii111 / I1ii11iIi11i . i1IIi + I1ii11iIi11i / oO0o
 if 18 - 18: iIii1I11I1II1 . ooOoO0o
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
def lisp_program_vxlan_hardware ( mc ) :
 if 25 - 25: OoO0O00 * oO0o
 if 29 - 29: OOooOOo - I1Ii111 - i11iIiiIii % i1IIi
 if 2 - 2: i11iIiiIii % iIii1I11I1II1 * OOooOOo
 if 45 - 45: oO0o + i1IIi + iII111i + o0oOOo0O0Ooo * OOooOOo + ooOoO0o
 if 83 - 83: OoO0O00 - ooOoO0o / OoooooooOO % iIii1I11I1II1 - II111iiii
 if 73 - 73: Oo0Ooo + II111iiii - IiII
 if ( os . path . exists ( "/persist/local/lispers.net" ) == False ) : return
 if 60 - 60: i1IIi . i11iIiiIii / i1IIi . I11i % OOooOOo
 if 47 - 47: oO0o + IiII * I1Ii111 % o0oOOo0O0Ooo - O0 % IiII
 if 66 - 66: II111iiii * I1IiiI . Oo0Ooo * OoooooooOO % OoOoOO00 . II111iiii
 if 4 - 4: iII111i + I1Ii111 % OoOoOO00 / Ii1I
 if ( len ( mc . best_rloc_set ) == 0 ) : return
 if 94 - 94: OoO0O00
 if 35 - 35: I1ii11iIi11i % OoO0O00 + II111iiii % II111iiii / IiII - iII111i
 if 9 - 9: I1ii11iIi11i * o0oOOo0O0Ooo . oO0o
 if 48 - 48: IiII . I1Ii111 + OoooooooOO - I1Ii111 . Ii1I . I1Ii111
 iI1iI = mc . eid . print_prefix_no_iid ( )
 II11IIiii = mc . best_rloc_set [ 0 ] . rloc . print_address_no_iid ( )
 if 24 - 24: ooOoO0o * iIii1I11I1II1
 if 1 - 1: I1ii11iIi11i . O0
 if 3 - 3: iIii1I11I1II1 * ooOoO0o - OoOoOO00 * I1ii11iIi11i % OoOoOO00 - OoooooooOO
 if 42 - 42: I1Ii111 - i1IIi
 O0Iii = commands . getoutput ( "ip route get {} | egrep vlan4094" . format ( iI1iI ) )
 if 39 - 39: II111iiii
 if ( O0Iii != "" ) :
  lprint ( "Route {} already in hardware: '{}'" . format ( green ( iI1iI , False ) , O0Iii ) )
  if 49 - 49: i11iIiiIii - OoO0O00
  return
  if 81 - 81: I11i - OOooOOo / oO0o - ooOoO0o
  if 60 - 60: OoO0O00 / I1ii11iIi11i % iII111i % i11iIiiIii * OoooooooOO * iII111i
  if 92 - 92: I11i % iIii1I11I1II1 * iII111i - OoooooooOO - I11i
  if 34 - 34: I1Ii111 / i1IIi / O0 / OoooooooOO
  if 55 - 55: I1Ii111 . I1IiiI * iIii1I11I1II1 / Ii1I . I1IiiI
  if 63 - 63: ooOoO0o . Ii1I - I1Ii111 - oO0o * I1Ii111 + ooOoO0o
  if 85 - 85: II111iiii + I1ii11iIi11i
 iiI1iiIi111i = commands . getoutput ( "ifconfig | egrep 'vxlan|vlan4094'" )
 if ( iiI1iiIi111i . find ( "vxlan" ) == - 1 ) :
  lprint ( "No VXLAN interface found, cannot program hardware" )
  return
  if 67 - 67: ooOoO0o % oO0o
 if ( iiI1iiIi111i . find ( "vlan4094" ) == - 1 ) :
  lprint ( "No vlan4094 interface found, cannot program hardware" )
  return
  if 62 - 62: II111iiii % Ii1I
 IioO0O00oOO = commands . getoutput ( "ip addr | egrep vlan4094 | egrep inet" )
 if ( IioO0O00oOO == "" ) :
  lprint ( "No IP address found on vlan4094, cannot program hardware" )
  return
  if 48 - 48: OOooOOo - II111iiii - i11iIiiIii
 IioO0O00oOO = IioO0O00oOO . split ( "inet " ) [ 1 ]
 IioO0O00oOO = IioO0O00oOO . split ( "/" ) [ 0 ]
 if 82 - 82: i11iIiiIii % I11i . OoOoOO00 + Ii1I * iIii1I11I1II1 - OoOoOO00
 if 96 - 96: I1IiiI
 if 3 - 3: OoooooooOO
 if 3 - 3: IiII / O0 * i11iIiiIii . iII111i - iIii1I11I1II1
 if 56 - 56: ooOoO0o
 if 82 - 82: ooOoO0o . IiII . I1Ii111 - iIii1I11I1II1 + II111iiii . OoOoOO00
 if 59 - 59: Oo0Ooo
 O0oooO0O0OoO = [ ]
 o0o00 = commands . getoutput ( "arp -i vlan4094" ) . split ( "\n" )
 for iiI1 in o0o00 :
  if ( iiI1 . find ( "vlan4094" ) == - 1 ) : continue
  if ( iiI1 . find ( "(incomplete)" ) == - 1 ) : continue
  iI1II1IiIiIi = iiI1 . split ( " " ) [ 0 ]
  O0oooO0O0OoO . append ( iI1II1IiIiIi )
  if 36 - 36: I11i * O0 / o0oOOo0O0Ooo + OoOoOO00
  if 32 - 32: OoooooooOO + ooOoO0o * Oo0Ooo * OoOoOO00 . I1ii11iIi11i
 iI1II1IiIiIi = None
 IIooOoOoO0ooOOo = IioO0O00oOO
 IioO0O00oOO = IioO0O00oOO . split ( "." )
 for oo0O0oO0O0O in range ( 1 , 255 ) :
  IioO0O00oOO [ 3 ] = str ( oo0O0oO0O0O )
  oOo00Ooo0o0 = "." . join ( IioO0O00oOO )
  if ( oOo00Ooo0o0 in O0oooO0O0OoO ) : continue
  if ( oOo00Ooo0o0 == IIooOoOoO0ooOOo ) : continue
  iI1II1IiIiIi = oOo00Ooo0o0
  break
  if 52 - 52: IiII
 if ( iI1II1IiIiIi == None ) :
  lprint ( "Address allocation failed for vlan4094, cannot program " + "hardware" )
  if 84 - 84: iIii1I11I1II1
  return
  if 30 - 30: i11iIiiIii . oO0o . I11i - OoOoOO00 % i11iIiiIii
  if 72 - 72: II111iiii
  if 95 - 95: I1Ii111 - I11i . II111iiii . i1IIi / II111iiii + Oo0Ooo
  if 96 - 96: iIii1I11I1II1 * iII111i / OOooOOo * iIii1I11I1II1 - O0
  if 28 - 28: I11i / I1IiiI - I1Ii111 + I1ii11iIi11i % iIii1I11I1II1
  if 35 - 35: iIii1I11I1II1 % Oo0Ooo % iII111i / iIii1I11I1II1 - I1ii11iIi11i . Oo0Ooo
  if 81 - 81: II111iiii + oO0o
 O0O0OOo = II11IIiii . split ( "." )
 i1Ii1I1iii = lisp_hex_string ( O0O0OOo [ 1 ] ) . zfill ( 2 )
 O000oO = lisp_hex_string ( O0O0OOo [ 2 ] ) . zfill ( 2 )
 I1i1IiII = lisp_hex_string ( O0O0OOo [ 3 ] ) . zfill ( 2 )
 i1i = "00:00:00:{}:{}:{}" . format ( i1Ii1I1iii , O000oO , I1i1IiII )
 OO0OOoo0 = "0000.00{}.{}{}" . format ( i1Ii1I1iii , O000oO , I1i1IiII )
 O0OO0o0OoO = "arp -i vlan4094 -s {} {}" . format ( iI1II1IiIiIi , i1i )
 os . system ( O0OO0o0OoO )
 if 40 - 40: OoooooooOO
 if 100 - 100: IiII - I11i
 if 79 - 79: iII111i % O0
 if 73 - 73: Oo0Ooo
 iI1ii11I = ( "mac address-table static {} vlan 4094 " + "interface vxlan 1 vtep {}" ) . format ( OO0OOoo0 , II11IIiii )
 if 19 - 19: O0 + OoO0O00 - i1IIi % OoOoOO00 / Oo0Ooo + OoooooooOO
 lisp_send_to_arista ( iI1ii11I , None )
 if 93 - 93: i11iIiiIii % OOooOOo . I11i * ooOoO0o
 if 90 - 90: OoO0O00
 if 54 - 54: OOooOOo + Oo0Ooo * o0oOOo0O0Ooo - iIii1I11I1II1 * ooOoO0o
 if 76 - 76: i11iIiiIii * I1IiiI - IiII . o0oOOo0O0Ooo % iII111i . i11iIiiIii
 if 69 - 69: O0 + o0oOOo0O0Ooo / ooOoO0o
 I1io00 = "ip route add {} via {}" . format ( iI1iI , iI1II1IiIiIi )
 os . system ( I1io00 )
 if 8 - 8: OoO0O00
 lprint ( "Hardware programmed with commands:" )
 I1io00 = I1io00 . replace ( iI1iI , green ( iI1iI , False ) )
 lprint ( "  " + I1io00 )
 lprint ( "  " + O0OO0o0OoO )
 iI1ii11I = iI1ii11I . replace ( II11IIiii , red ( II11IIiii , False ) )
 lprint ( "  " + iI1ii11I )
 return
 if 39 - 39: OoO0O00 * I11i . OoOoOO00
 if 53 - 53: Oo0Ooo
 if 28 - 28: ooOoO0o + Oo0Ooo % I1IiiI - ooOoO0o / iII111i - I1IiiI
 if 76 - 76: I1IiiI + O0
 if 4 - 4: I1IiiI - OOooOOo * I1Ii111
 if 26 - 26: Oo0Ooo % ooOoO0o / i11iIiiIii * Oo0Ooo / oO0o
 if 87 - 87: Ii1I
def lisp_clear_hardware_walk ( mc , parms ) :
 ooII1111iI1I = mc . eid . print_prefix_no_iid ( )
 os . system ( "ip route delete {}" . format ( ooII1111iI1I ) )
 return ( [ True , None ] )
 if 21 - 21: iII111i
 if 38 - 38: OOooOOo % Ii1I - O0 / I1ii11iIi11i
 if 20 - 20: o0oOOo0O0Ooo + II111iiii * Ii1I . OoooooooOO
 if 88 - 88: O0 + iIii1I11I1II1 . o0oOOo0O0Ooo . iIii1I11I1II1 - Ii1I
 if 74 - 74: Ii1I . IiII
 if 67 - 67: oO0o
 if 12 - 12: I1IiiI + OoooooooOO
 if 25 - 25: iIii1I11I1II1 - I1IiiI . i11iIiiIii + ooOoO0o
def lisp_clear_map_cache ( ) :
 global lisp_map_cache , lisp_rloc_probe_list
 global lisp_crypto_keys_by_rloc_encap , lisp_crypto_keys_by_rloc_decap
 global lisp_rtr_list
 if 19 - 19: OoooooooOO / IiII
 II1ii = bold ( "User cleared" , False )
 O0oO = lisp_map_cache . cache_count
 lprint ( "{} map-cache with {} entries" . format ( II1ii , O0oO ) )
 if 13 - 13: i1IIi
 if ( lisp_program_hardware ) :
  lisp_map_cache . walk_cache ( lisp_clear_hardware_walk , None )
  if 19 - 19: I11i - I1IiiI / oO0o / IiII / oO0o % o0oOOo0O0Ooo
 lisp_map_cache = lisp_cache ( )
 if 42 - 42: I1ii11iIi11i
 if 22 - 22: IiII + I1ii11iIi11i + i11iIiiIii
 if 3 - 3: o0oOOo0O0Ooo . oO0o + IiII + OoO0O00
 if 89 - 89: iIii1I11I1II1 / OoooooooOO
 if 28 - 28: i11iIiiIii / O0 / iIii1I11I1II1 / I1IiiI % OoooooooOO % ooOoO0o
 lisp_rloc_probe_list = { }
 if 29 - 29: I1ii11iIi11i
 if 12 - 12: I11i . o0oOOo0O0Ooo . iIii1I11I1II1
 if 93 - 93: ooOoO0o - OoooooooOO + iIii1I11I1II1 / o0oOOo0O0Ooo + iIii1I11I1II1
 if 9 - 9: OoOoOO00 + ooOoO0o
 lisp_crypto_keys_by_rloc_encap = { }
 lisp_crypto_keys_by_rloc_decap = { }
 if 61 - 61: i11iIiiIii + OOooOOo - i1IIi
 if 2 - 2: I1ii11iIi11i / I1Ii111 / I1ii11iIi11i / iII111i * i11iIiiIii % iII111i
 if 48 - 48: O0 + o0oOOo0O0Ooo . oO0o - IiII * OoooooooOO . OoO0O00
 if 63 - 63: oO0o * OoO0O00 * oO0o
 if 31 - 31: Oo0Ooo
 lisp_rtr_list = { }
 if 90 - 90: I11i . IiII * iIii1I11I1II1 . I11i + i1IIi
 if 67 - 67: I1Ii111 . I1ii11iIi11i
 if 2 - 2: O0 + I1Ii111
 if 82 - 82: Ii1I / iII111i
 lisp_process_data_plane_restart ( True )
 return
 if 13 - 13: I11i + iII111i
 if 54 - 54: I1ii11iIi11i - I1IiiI . Ii1I
 if 59 - 59: Oo0Ooo + I1ii11iIi11i
 if 87 - 87: ooOoO0o * OoooooooOO + OoO0O00 + oO0o - I1Ii111
 if 70 - 70: i1IIi . Ii1I / Ii1I
 if 9 - 9: iII111i + I1Ii111 + iII111i % ooOoO0o + i11iIiiIii + i11iIiiIii
 if 45 - 45: i1IIi + I1ii11iIi11i
 if 49 - 49: i11iIiiIii . I1ii11iIi11i
 if 91 - 91: ooOoO0o - OOooOOo - OOooOOo * o0oOOo0O0Ooo
 if 33 - 33: II111iiii
 if 39 - 39: ooOoO0o + I11i
def lisp_encapsulate_rloc_probe ( lisp_sockets , rloc , nat_info , packet ) :
 if ( len ( lisp_sockets ) != 4 ) : return
 if 24 - 24: o0oOOo0O0Ooo
 IiII1I1I = lisp_myrlocs [ 0 ]
 if 13 - 13: OoOoOO00 . IiII / i11iIiiIii - OOooOOo
 if 9 - 9: II111iiii + i11iIiiIii % I1Ii111 - Oo0Ooo * OOooOOo
 if 55 - 55: I1Ii111 + ooOoO0o
 if 58 - 58: iII111i . I1ii11iIi11i - Oo0Ooo % o0oOOo0O0Ooo + I1Ii111
 if 58 - 58: oO0o . ooOoO0o . I1IiiI . Oo0Ooo * iIii1I11I1II1 - iII111i
 O00OoO0oo = len ( packet ) + 28
 i1i11ii1Ii = struct . pack ( "BBHIBBHII" , 0x45 , 0 , socket . htons ( O00OoO0oo ) , 0 , 64 ,
 17 , 0 , socket . htonl ( IiII1I1I . address ) , socket . htonl ( rloc . address ) )
 i1i11ii1Ii = lisp_ip_checksum ( i1i11ii1Ii )
 if 96 - 96: OOooOOo % o0oOOo0O0Ooo / iIii1I11I1II1
 IiI1iiI11 = struct . pack ( "HHHH" , 0 , socket . htons ( LISP_CTRL_PORT ) ,
 socket . htons ( O00OoO0oo - 20 ) , 0 )
 if 60 - 60: i1IIi / iIii1I11I1II1 + I11i % iII111i
 if 64 - 64: I11i . i11iIiiIii / iIii1I11I1II1 . I11i
 if 73 - 73: OoO0O00 % iIii1I11I1II1 + IiII * I1Ii111 % II111iiii
 if 20 - 20: I11i % I1ii11iIi11i . OoO0O00 % OoOoOO00
 packet = lisp_packet ( i1i11ii1Ii + IiI1iiI11 + packet )
 if 84 - 84: OoooooooOO / i11iIiiIii . IiII / I1IiiI
 if 62 - 62: iII111i - I1IiiI + OoooooooOO
 if 59 - 59: iIii1I11I1II1 + i11iIiiIii * oO0o . Oo0Ooo . I1Ii111
 if 49 - 49: II111iiii
 packet . inner_dest . copy_address ( rloc )
 packet . inner_dest . instance_id = 0xffffff
 packet . inner_source . copy_address ( IiII1I1I )
 packet . inner_ttl = 64
 packet . outer_dest . copy_address ( rloc )
 packet . outer_source . copy_address ( IiII1I1I )
 packet . outer_version = packet . outer_dest . afi_to_version ( )
 packet . outer_ttl = 64
 packet . encap_port = nat_info . port if nat_info else LISP_DATA_PORT
 if 99 - 99: Oo0Ooo . OOooOOo
 I111I1iii11 = red ( rloc . print_address_no_iid ( ) , False )
 if ( nat_info ) :
  OO00o00000oO0 = " {}" . format ( blue ( nat_info . hostname , False ) )
  OOo00o = bold ( "RLOC-probe request" , False )
 else :
  OO00o00000oO0 = ""
  OOo00o = bold ( "RLOC-probe reply" , False )
  if 85 - 85: OoOoOO00 . IiII + oO0o - II111iiii
  if 70 - 70: O0 % I1Ii111
 lprint ( ( "Data encapsulate {} to {}{} port {} for " + "NAT-traversal" ) . format ( OOo00o , I111I1iii11 , OO00o00000oO0 , packet . encap_port ) )
 if 13 - 13: I1ii11iIi11i % OoO0O00 / Ii1I * IiII
 if 82 - 82: ooOoO0o % Oo0Ooo
 if 26 - 26: OoO0O00 + i11iIiiIii % I11i . I1ii11iIi11i
 if 76 - 76: i1IIi + ooOoO0o - Oo0Ooo + OoOoOO00 / I1ii11iIi11i . OOooOOo
 if 50 - 50: IiII - Ii1I % iIii1I11I1II1
 if ( packet . encode ( None ) == None ) : return
 packet . print_packet ( "Send" , True )
 if 60 - 60: o0oOOo0O0Ooo - Oo0Ooo
 OOo00Oo = lisp_sockets [ 3 ]
 packet . send_packet ( OOo00Oo , packet . outer_dest )
 del ( packet )
 return
 if 82 - 82: I11i / oO0o
 if 9 - 9: I1ii11iIi11i * iII111i / ooOoO0o / Ii1I
 if 90 - 90: I1IiiI . oO0o
 if 17 - 17: OoooooooOO / oO0o * I11i
 if 63 - 63: Oo0Ooo
 if 4 - 4: ooOoO0o
 if 46 - 46: IiII * I11i - OoO0O00 - Ii1I
 if 93 - 93: iIii1I11I1II1 / o0oOOo0O0Ooo - I11i - OOooOOo % ooOoO0o
def lisp_get_default_route_next_hops ( ) :
 if 16 - 16: ooOoO0o * o0oOOo0O0Ooo - IiII + I1ii11iIi11i / o0oOOo0O0Ooo - O0
 if 71 - 71: i1IIi
 if 79 - 79: iII111i * O0 / Ii1I / O0 % i1IIi
 if 52 - 52: OoooooooOO % oO0o - I11i % OoOoOO00 . II111iiii
 if ( lisp_is_macos ( ) ) :
  oO0O = "route -n get default"
  O0oo00OO00OooO = commands . getoutput ( oO0O ) . split ( "\n" )
  iIii1 = O0OOoooo0 = None
  for ii1iIii in O0oo00OO00OooO :
   if ( ii1iIii . find ( "gateway: " ) != - 1 ) : iIii1 = ii1iIii . split ( ": " ) [ 1 ]
   if ( ii1iIii . find ( "interface: " ) != - 1 ) : O0OOoooo0 = ii1iIii . split ( ": " ) [ 1 ]
   if 10 - 10: I1Ii111 / Ii1I * I1Ii111 / OoO0O00 - I1ii11iIi11i
  return ( [ [ O0OOoooo0 , iIii1 ] ] )
  if 7 - 7: I1IiiI . OoO0O00 . OoOoOO00 . I1ii11iIi11i * OoO0O00 - IiII
  if 6 - 6: OoO0O00 + II111iiii - oO0o
  if 90 - 90: Oo0Ooo % Oo0Ooo + oO0o - OoooooooOO + OOooOOo % I11i
  if 61 - 61: I1IiiI % oO0o + OOooOOo - I1Ii111
  if 5 - 5: ooOoO0o . OoO0O00
 oO0O = "ip route | egrep 'default via'"
 oOii1Iii = commands . getoutput ( oO0O ) . split ( "\n" )
 if 40 - 40: iII111i
 i1i1Ii = [ ]
 for O0Iii in oOii1Iii :
  if ( O0Iii . find ( " metric " ) != - 1 ) : continue
  oooO0 = O0Iii . split ( " " )
  try :
   o0oO = oooO0 . index ( "via" ) + 1
   if ( o0oO >= len ( oooO0 ) ) : continue
   oO00ooO = oooO0 . index ( "dev" ) + 1
   if ( oO00ooO >= len ( oooO0 ) ) : continue
  except :
   continue
   if 44 - 44: iIii1I11I1II1 * O0 % I11i % I1Ii111 - I1ii11iIi11i * Oo0Ooo
   if 11 - 11: OoooooooOO
  i1i1Ii . append ( [ oooO0 [ oO00ooO ] , oooO0 [ o0oO ] ] )
  if 85 - 85: O0 * i1IIi
 return ( i1i1Ii )
 if 29 - 29: i11iIiiIii
 if 34 - 34: OoOoOO00
 if 17 - 17: oO0o * OoOoOO00 % OoO0O00 % I1IiiI * I11i
 if 78 - 78: OoooooooOO . I1Ii111 + Ii1I - II111iiii - IiII / iIii1I11I1II1
 if 92 - 92: Ii1I
 if 34 - 34: OOooOOo * OoooooooOO / I1ii11iIi11i
 if 41 - 41: i1IIi
def lisp_get_host_route_next_hop ( rloc ) :
 oO0O = "ip route | egrep '{} via'" . format ( rloc )
 O0Iii = commands . getoutput ( oO0O ) . split ( " " )
 if 75 - 75: o0oOOo0O0Ooo . I1Ii111 - I1Ii111 % Ii1I * OoooooooOO
 try : Oo0oOooo000OO = O0Iii . index ( "via" ) + 1
 except : return ( None )
 if 99 - 99: OOooOOo + o0oOOo0O0Ooo - OOooOOo . i1IIi
 if ( Oo0oOooo000OO >= len ( O0Iii ) ) : return ( None )
 return ( O0Iii [ Oo0oOooo000OO ] )
 if 86 - 86: Ii1I % oO0o - i11iIiiIii - O0 + IiII + iII111i
 if 100 - 100: OoO0O00 . Oo0Ooo
 if 29 - 29: OoO0O00
 if 34 - 34: O0 - o0oOOo0O0Ooo % OOooOOo . OoO0O00 % IiII
 if 63 - 63: O0 % iIii1I11I1II1 . o0oOOo0O0Ooo . I1IiiI * Ii1I % i1IIi
 if 47 - 47: II111iiii * I1ii11iIi11i
 if 70 - 70: I1ii11iIi11i - o0oOOo0O0Ooo
def lisp_install_host_route ( dest , nh , install ) :
 install = "add" if install else "delete"
 OOoIiiiIIiII = "none" if nh == None else nh
 if 71 - 71: I1ii11iIi11i * i1IIi
 lprint ( "{} host-route {}, nh {}" . format ( install . title ( ) , dest , OOoIiiiIIiII ) )
 if 67 - 67: I1ii11iIi11i % OoOoOO00 . iII111i / Ii1I . I1IiiI
 if ( nh == None ) :
  Oo0o00oO = "ip route {} {}/32" . format ( install , dest )
 else :
  Oo0o00oO = "ip route {} {}/32 via {}" . format ( install , dest , nh )
  if 48 - 48: IiII + II111iiii . I1IiiI % o0oOOo0O0Ooo
 os . system ( Oo0o00oO )
 return
 if 57 - 57: OOooOOo . I11i % OoOoOO00
 if 68 - 68: iIii1I11I1II1 % I1ii11iIi11i % II111iiii / O0 + iII111i
 if 78 - 78: iII111i - OOooOOo / I1Ii111
 if 38 - 38: I11i % i1IIi + o0oOOo0O0Ooo + I1ii11iIi11i + I1IiiI
 if 1 - 1: II111iiii * o0oOOo0O0Ooo . O0 - Ii1I / oO0o
 if 17 - 17: OoooooooOO % OoooooooOO + Oo0Ooo + I1Ii111
 if 56 - 56: I11i % OoOoOO00 - OoO0O00
 if 31 - 31: iII111i % i11iIiiIii - Ii1I / OOooOOo - I1Ii111
def lisp_checkpoint ( checkpoint_list ) :
 if ( lisp_checkpoint_map_cache == False ) : return
 if 60 - 60: o0oOOo0O0Ooo + Oo0Ooo . O0
 ii1iIii = open ( lisp_checkpoint_filename , "w" )
 for iiIiiIi in checkpoint_list :
  ii1iIii . write ( iiIiiIi + "\n" )
  if 51 - 51: i11iIiiIii / iIii1I11I1II1 . I1IiiI - Ii1I * I1Ii111 . iII111i
 ii1iIii . close ( )
 lprint ( "{} {} entries to file '{}'" . format ( bold ( "Checkpoint" , False ) ,
 len ( checkpoint_list ) , lisp_checkpoint_filename ) )
 return
 if 72 - 72: Ii1I . I11i / i1IIi % i1IIi + I1ii11iIi11i
 if 56 - 56: OoO0O00 - OoOoOO00 - II111iiii * o0oOOo0O0Ooo
 if 87 - 87: ooOoO0o * OoooooooOO % O0 * OoooooooOO . I1Ii111
 if 66 - 66: OoO0O00 * Ii1I . OoO0O00
 if 90 - 90: II111iiii % Ii1I
 if 67 - 67: I1IiiI - I11i - i11iIiiIii
 if 45 - 45: ooOoO0o - IiII / OoO0O00 / IiII
 if 63 - 63: ooOoO0o . i11iIiiIii + iII111i . OoO0O00 / ooOoO0o % iII111i
def lisp_load_checkpoint ( ) :
 if ( lisp_checkpoint_map_cache == False ) : return
 if ( os . path . exists ( lisp_checkpoint_filename ) == False ) : return
 if 23 - 23: iIii1I11I1II1 - ooOoO0o / I11i * I11i
 ii1iIii = open ( lisp_checkpoint_filename , "r" )
 if 62 - 62: OOooOOo - I1IiiI * oO0o + O0 / ooOoO0o * iIii1I11I1II1
 O0oO = 0
 for iiIiiIi in ii1iIii :
  O0oO += 1
  ooOoOOOOo = iiIiiIi . split ( " rloc " )
  II1I1I1i1i = [ ] if ( ooOoOOOOo [ 1 ] in [ "native-forward\n" , "\n" ] ) else ooOoOOOOo [ 1 ] . split ( ", " )
  if 25 - 25: I1Ii111 % Oo0Ooo + OoO0O00 % OOooOOo
  if 85 - 85: I1IiiI . i11iIiiIii - ooOoO0o * I11i * OoOoOO00 * I11i
  I1I11I11 = [ ]
  for II11IIiii in II1I1I1i1i :
   IiIiI = lisp_rloc ( False )
   oooO0 = II11IIiii . split ( " " )
   IiIiI . rloc . store_address ( oooO0 [ 0 ] )
   IiIiI . priority = int ( oooO0 [ 1 ] )
   IiIiI . weight = int ( oooO0 [ 2 ] )
   I1I11I11 . append ( IiIiI )
   if 29 - 29: I1Ii111 * I1Ii111 . iII111i + o0oOOo0O0Ooo
   if 57 - 57: I1Ii111 - IiII
  OoOOO000O0o = lisp_mapping ( "" , "" , I1I11I11 )
  if ( OoOOO000O0o != None ) :
   OoOOO000O0o . eid . store_prefix ( ooOoOOOOo [ 0 ] )
   OoOOO000O0o . checkpoint_entry = True
   OoOOO000O0o . map_cache_ttl = LISP_NMR_TTL * 60
   if ( I1I11I11 == [ ] ) : OoOOO000O0o . action = LISP_NATIVE_FORWARD_ACTION
   OoOOO000O0o . add_cache ( )
   continue
   if 89 - 89: oO0o + iII111i
   if 52 - 52: OOooOOo % O0 * I1ii11iIi11i . I1ii11iIi11i / IiII
  O0oO -= 1
  if 7 - 7: II111iiii
  if 7 - 7: iIii1I11I1II1 . O0 + Ii1I % I1IiiI * O0 + OoO0O00
 ii1iIii . close ( )
 lprint ( "{} {} map-cache entries from file '{}'" . format (
 bold ( "Loaded" , False ) , O0oO , lisp_checkpoint_filename ) )
 return
 if 3 - 3: Oo0Ooo * OoooooooOO * oO0o % OoOoOO00 * OoOoOO00 . ooOoO0o
 if 16 - 16: ooOoO0o / o0oOOo0O0Ooo - O0 * I1IiiI
 if 13 - 13: iII111i . iII111i % O0 % o0oOOo0O0Ooo
 if 99 - 99: OoO0O00 - OoOoOO00 + OoO0O00
 if 67 - 67: I1Ii111
 if 31 - 31: OoO0O00 * Oo0Ooo % O0 * II111iiii + ooOoO0o * I1IiiI
 if 77 - 77: ooOoO0o
 if 98 - 98: I1Ii111 + I1ii11iIi11i % OoO0O00 * Ii1I + iII111i
 if 6 - 6: iII111i / iII111i . i11iIiiIii
 if 12 - 12: I11i - OoO0O00
 if 68 - 68: IiII - OoOoOO00
 if 22 - 22: i1IIi . IiII
 if 8 - 8: IiII % o0oOOo0O0Ooo . i11iIiiIii
 if 69 - 69: I1Ii111 / Ii1I - ooOoO0o
def lisp_write_checkpoint_entry ( checkpoint_list , mc ) :
 if ( lisp_checkpoint_map_cache == False ) : return
 if 38 - 38: II111iiii % OoooooooOO / OoooooooOO . Ii1I . Ii1I
 iiIiiIi = "{} rloc " . format ( mc . eid . print_prefix ( ) )
 if 13 - 13: oO0o - i1IIi / i1IIi + OoooooooOO
 for IiIiI in mc . rloc_set :
  if ( IiIiI . rloc . is_null ( ) ) : continue
  iiIiiIi += "{} {} {}, " . format ( IiIiI . rloc . print_address_no_iid ( ) ,
 IiIiI . priority , IiIiI . weight )
  if 57 - 57: OoooooooOO / O0 + I1ii11iIi11i % I11i * oO0o / Ii1I
  if 49 - 49: I1IiiI * ooOoO0o * OOooOOo + OoO0O00 + ooOoO0o
 if ( mc . rloc_set != [ ] ) :
  iiIiiIi = iiIiiIi [ 0 : - 2 ]
 elif ( mc . action == LISP_NATIVE_FORWARD_ACTION ) :
  iiIiiIi += "native-forward"
  if 42 - 42: i1IIi . OoO0O00 % iII111i
  if 57 - 57: I1ii11iIi11i / I1IiiI
 checkpoint_list . append ( iiIiiIi )
 return
 if 69 - 69: iII111i - iII111i . OoO0O00 / oO0o - OoO0O00 + I1Ii111
 if 98 - 98: iII111i . oO0o - O0 % I1IiiI . I1ii11iIi11i / i1IIi
 if 72 - 72: I1IiiI / Oo0Ooo % IiII - O0 / O0 * O0
 if 83 - 83: O0 / I1Ii111 - OoooooooOO
 if 42 - 42: Ii1I / i1IIi - IiII / I1Ii111
 if 39 - 39: OoooooooOO
 if 4 - 4: iIii1I11I1II1 - Oo0Ooo / OOooOOo % OoooooooOO . Oo0Ooo - Oo0Ooo
def lisp_check_dp_socket ( ) :
 iiOO0OoOo00O0o = lisp_ipc_dp_socket_name
 if ( os . path . exists ( iiOO0OoOo00O0o ) == False ) :
  O0O0OooooooOO = bold ( "does not exist" , False )
  lprint ( "Socket '{}' {}" . format ( iiOO0OoOo00O0o , O0O0OooooooOO ) )
  return ( False )
  if 40 - 40: OoO0O00
 return ( True )
 if 65 - 65: I1IiiI % o0oOOo0O0Ooo
 if 36 - 36: iIii1I11I1II1 / o0oOOo0O0Ooo / o0oOOo0O0Ooo * i1IIi
 if 33 - 33: i1IIi . O0
 if 92 - 92: IiII / i1IIi + iIii1I11I1II1 / IiII
 if 81 - 81: I1Ii111 . i1IIi / o0oOOo0O0Ooo
 if 30 - 30: i11iIiiIii . I1IiiI
 if 5 - 5: Ii1I / O0 + iIii1I11I1II1
def lisp_write_to_dp_socket ( entry ) :
 try :
  I1O0OOOoOOOO0 = json . dumps ( entry )
  IIiiiIII11 = bold ( "Write IPC" , False )
  lprint ( "{} record to named socket: '{}'" . format ( IIiiiIII11 , I1O0OOOoOOOO0 ) )
  lisp_ipc_dp_socket . sendto ( I1O0OOOoOOOO0 , lisp_ipc_dp_socket_name )
 except :
  lprint ( "Failed to write IPC record to named socket: '{}'" . format ( I1O0OOOoOOOO0 ) )
  if 78 - 78: Oo0Ooo
 return
 if 14 - 14: OOooOOo
 if 16 - 16: iII111i
 if 63 - 63: OoOoOO00
 if 96 - 96: O0
 if 18 - 18: I1IiiI
 if 73 - 73: OoOoOO00 % II111iiii - I1ii11iIi11i - I11i / I1ii11iIi11i . I1ii11iIi11i
 if 56 - 56: iIii1I11I1II1 . Oo0Ooo / II111iiii
 if 75 - 75: Oo0Ooo - I1Ii111 * IiII
 if 2 - 2: I1Ii111 - O0 % OoooooooOO + I1Ii111
def lisp_write_ipc_keys ( rloc ) :
 i111I11I = rloc . rloc . print_address_no_iid ( )
 IIIIiI1ii1 = rloc . translated_port
 if ( IIIIiI1ii1 != 0 ) : i111I11I += ":" + str ( IIIIiI1ii1 )
 if ( lisp_rloc_probe_list . has_key ( i111I11I ) == False ) : return
 if 1 - 1: I1Ii111 % OoooooooOO + OoooooooOO - I1IiiI % I1IiiI
 for oooO0 , ooOoOOOOo , IiIoO0oo0 in lisp_rloc_probe_list [ i111I11I ] :
  OoOOO000O0o = lisp_map_cache . lookup_cache ( ooOoOOOOo , True )
  if ( OoOOO000O0o == None ) : continue
  lisp_write_ipc_map_cache ( True , OoOOO000O0o )
  if 51 - 51: iIii1I11I1II1 / I1IiiI
 return
 if 27 - 27: O0 . o0oOOo0O0Ooo / ooOoO0o / OoooooooOO % Ii1I
 if 27 - 27: ooOoO0o / IiII + OoO0O00 + Ii1I % I1Ii111
 if 86 - 86: O0 % i11iIiiIii - Ii1I * oO0o % OOooOOo * i1IIi
 if 87 - 87: II111iiii
 if 53 - 53: OoOoOO00 * i11iIiiIii / I1Ii111
 if 100 - 100: ooOoO0o + I1IiiI * oO0o + ooOoO0o
 if 24 - 24: i11iIiiIii + ooOoO0o
def lisp_write_ipc_map_cache ( add_or_delete , mc , dont_send = False ) :
 if ( lisp_i_am_etr ) : return
 if ( lisp_ipc_dp_socket == None ) : return
 if ( lisp_check_dp_socket ( ) == False ) : return
 if 80 - 80: IiII % I11i % oO0o
 if 97 - 97: i1IIi * i11iIiiIii / Ii1I - I1IiiI % IiII
 if 70 - 70: iIii1I11I1II1
 if 2 - 2: IiII - i1IIi * IiII % O0 / Ii1I
 OOoOOOO00 = "add" if add_or_delete else "delete"
 iiIiiIi = { "type" : "map-cache" , "opcode" : OOoOOOO00 }
 if 64 - 64: iII111i - Oo0Ooo
 OOooO = ( mc . group . is_null ( ) == False )
 if ( OOooO ) :
  iiIiiIi [ "eid-prefix" ] = mc . group . print_prefix_no_iid ( )
  iiIiiIi [ "rles" ] = [ ]
 else :
  iiIiiIi [ "eid-prefix" ] = mc . eid . print_prefix_no_iid ( )
  iiIiiIi [ "rlocs" ] = [ ]
  if 73 - 73: iIii1I11I1II1 * I1Ii111 * OoO0O00
 iiIiiIi [ "instance-id" ] = str ( mc . eid . instance_id )
 if 68 - 68: ooOoO0o * Ii1I / I1ii11iIi11i * OoooooooOO + OoooooooOO . OoooooooOO
 if ( OOooO ) :
  if ( len ( mc . rloc_set ) >= 1 and mc . rloc_set [ 0 ] . rle ) :
   for O00o000O0O0oO in mc . rloc_set [ 0 ] . rle . rle_forwarding_list :
    oOo00Ooo0o0 = O00o000O0O0oO . address . print_address_no_iid ( )
    IIIIiI1ii1 = str ( 4341 ) if O00o000O0O0oO . translated_port == 0 else str ( O00o000O0O0oO . translated_port )
    if 50 - 50: I1IiiI % o0oOOo0O0Ooo
    oooO0 = { "rle" : oOo00Ooo0o0 , "port" : IIIIiI1ii1 }
    O000oOooOoO0 , iiiI1 = O00o000O0O0oO . get_encap_keys ( )
    oooO0 = lisp_build_json_keys ( oooO0 , O000oOooOoO0 , iiiI1 , "encrypt-key" )
    iiIiiIi [ "rles" ] . append ( oooO0 )
    if 83 - 83: iII111i % o0oOOo0O0Ooo * OoOoOO00
    if 49 - 49: II111iiii / OoO0O00
 else :
  for II11IIiii in mc . rloc_set :
   if ( II11IIiii . rloc . is_ipv4 ( ) == False and II11IIiii . rloc . is_ipv6 ( ) == False ) :
    continue
    if 69 - 69: Ii1I * II111iiii
   if ( II11IIiii . up_state ( ) == False ) : continue
   if 24 - 24: I1Ii111 * I1ii11iIi11i . OOooOOo . I1IiiI - I1ii11iIi11i
   IIIIiI1ii1 = str ( 4341 ) if II11IIiii . translated_port == 0 else str ( II11IIiii . translated_port )
   if 56 - 56: I1IiiI * Oo0Ooo + OoO0O00 - oO0o * I1Ii111
   oooO0 = { "rloc" : II11IIiii . rloc . print_address_no_iid ( ) , "priority" :
 str ( II11IIiii . priority ) , "weight" : str ( II11IIiii . weight ) , "port" :
 IIIIiI1ii1 }
   O000oOooOoO0 , iiiI1 = II11IIiii . get_encap_keys ( )
   oooO0 = lisp_build_json_keys ( oooO0 , O000oOooOoO0 , iiiI1 , "encrypt-key" )
   iiIiiIi [ "rlocs" ] . append ( oooO0 )
   if 68 - 68: ooOoO0o * i11iIiiIii * OOooOOo % iII111i
   if 10 - 10: Ii1I / Oo0Ooo - i1IIi
   if 11 - 11: I11i * iII111i
 if ( dont_send == False ) : lisp_write_to_dp_socket ( iiIiiIi )
 return ( iiIiiIi )
 if 28 - 28: II111iiii + IiII / Oo0Ooo * I1IiiI - OOooOOo
 if 2 - 2: oO0o + I11i / I1Ii111 . I11i
 if 59 - 59: Ii1I
 if 47 - 47: iII111i % iII111i
 if 81 - 81: oO0o / I1ii11iIi11i . OoooooooOO % II111iiii / oO0o
 if 23 - 23: IiII + oO0o + o0oOOo0O0Ooo . I1ii11iIi11i / i11iIiiIii + iIii1I11I1II1
 if 74 - 74: I11i % OOooOOo
def lisp_write_ipc_decap_key ( rloc_addr , keys ) :
 if ( lisp_i_am_itr ) : return
 if ( lisp_ipc_dp_socket == None ) : return
 if ( lisp_check_dp_socket ( ) == False ) : return
 if 57 - 57: O0 + I1IiiI + i11iIiiIii
 if 90 - 90: I1ii11iIi11i . OoO0O00 * iIii1I11I1II1 - Oo0Ooo
 if 28 - 28: I1IiiI . ooOoO0o - ooOoO0o * OOooOOo . IiII
 if 16 - 16: iIii1I11I1II1 % i11iIiiIii / Ii1I % iIii1I11I1II1 / iII111i
 if ( keys == None or len ( keys ) == 0 or keys [ 1 ] == None ) : return
 if 27 - 27: II111iiii * OoooooooOO / Oo0Ooo % O0
 O000oOooOoO0 = keys [ 1 ] . encrypt_key
 iiiI1 = keys [ 1 ] . icv_key
 if 41 - 41: oO0o / iIii1I11I1II1 % iII111i - I1Ii111 % I11i * i11iIiiIii
 if 21 - 21: O0
 if 14 - 14: IiII / I1ii11iIi11i + Ii1I
 if 48 - 48: I1Ii111 * oO0o / o0oOOo0O0Ooo * OoOoOO00 * ooOoO0o
 IiI1IIiIiI1I = rloc_addr . split ( ":" )
 if ( len ( IiI1IIiIiI1I ) == 1 ) :
  iiIiiIi = { "type" : "decap-keys" , "rloc" : IiI1IIiIiI1I [ 0 ] }
 else :
  iiIiiIi = { "type" : "decap-keys" , "rloc" : IiI1IIiIiI1I [ 0 ] , "port" : IiI1IIiIiI1I [ 1 ] }
  if 78 - 78: oO0o - II111iiii . II111iiii * I1Ii111 % O0 - iII111i
 iiIiiIi = lisp_build_json_keys ( iiIiiIi , O000oOooOoO0 , iiiI1 , "decrypt-key" )
 if 59 - 59: Oo0Ooo - IiII
 lisp_write_to_dp_socket ( iiIiiIi )
 return
 if 6 - 6: OOooOOo - I1IiiI . IiII
 if 40 - 40: II111iiii
 if 13 - 13: OoOoOO00
 if 23 - 23: Oo0Ooo / II111iiii % OOooOOo % iII111i - Oo0Ooo / OoO0O00
 if 7 - 7: Ii1I / I11i / II111iiii % I11i * I11i + iIii1I11I1II1
 if 6 - 6: iIii1I11I1II1 * oO0o - iIii1I11I1II1 . O0 . O0
 if 96 - 96: I1Ii111 * II111iiii % i11iIiiIii - oO0o
 if 32 - 32: i11iIiiIii * o0oOOo0O0Ooo . OoooooooOO / O0
def lisp_build_json_keys ( entry , ekey , ikey , key_type ) :
 if ( ekey == None ) : return ( entry )
 if 14 - 14: i11iIiiIii . I1Ii111 % I1ii11iIi11i . I1ii11iIi11i % IiII
 entry [ "keys" ] = [ ]
 OOO0OOoOOO = { "key-id" : "1" , key_type : ekey , "icv-key" : ikey }
 entry [ "keys" ] . append ( OOO0OOoOOO )
 return ( entry )
 if 93 - 93: iIii1I11I1II1 / IiII
 if 91 - 91: i11iIiiIii % ooOoO0o - iII111i * I1Ii111 . i11iIiiIii
 if 1 - 1: IiII + iIii1I11I1II1 * I1ii11iIi11i - IiII - i1IIi
 if 75 - 75: II111iiii * o0oOOo0O0Ooo / I1ii11iIi11i
 if 46 - 46: OOooOOo
 if 67 - 67: OoO0O00 . I11i % OOooOOo + Oo0Ooo
 if 40 - 40: OoO0O00 / I11i % iIii1I11I1II1 - ooOoO0o
def lisp_write_ipc_database_mappings ( ephem_port ) :
 if ( lisp_i_am_etr == False ) : return
 if ( lisp_ipc_dp_socket == None ) : return
 if ( lisp_check_dp_socket ( ) == False ) : return
 if 51 - 51: Oo0Ooo % iIii1I11I1II1 % oO0o + o0oOOo0O0Ooo
 if 32 - 32: I1Ii111 * I1IiiI + Ii1I
 if 30 - 30: OoooooooOO / I1IiiI . iIii1I11I1II1 / ooOoO0o
 if 20 - 20: OoooooooOO * OOooOOo
 iiIiiIi = { "type" : "database-mappings" , "database-mappings" : [ ] }
 if 77 - 77: Ii1I - OoooooooOO . OoOoOO00
 if 93 - 93: OoooooooOO / I1Ii111
 if 91 - 91: I1Ii111
 if 18 - 18: ooOoO0o * I11i
 for i1i1iiiii1IiI in lisp_db_list :
  if ( i1i1iiiii1IiI . eid . is_ipv4 ( ) == False and i1i1iiiii1IiI . eid . is_ipv6 ( ) == False ) : continue
  O0oo00O = { "instance-id" : str ( i1i1iiiii1IiI . eid . instance_id ) ,
 "eid-prefix" : i1i1iiiii1IiI . eid . print_prefix_no_iid ( ) }
  iiIiiIi [ "database-mappings" ] . append ( O0oo00O )
  if 68 - 68: OoO0O00 - OoooooooOO
 lisp_write_to_dp_socket ( iiIiiIi )
 if 63 - 63: o0oOOo0O0Ooo . iIii1I11I1II1 % IiII * i11iIiiIii
 if 70 - 70: iIii1I11I1II1
 if 12 - 12: OoOoOO00 / o0oOOo0O0Ooo - I1ii11iIi11i + oO0o + O0
 if 9 - 9: I1ii11iIi11i * OoooooooOO . O0 . ooOoO0o * i11iIiiIii / i1IIi
 if 38 - 38: OoOoOO00 . OoooooooOO % I1ii11iIi11i . oO0o % oO0o
 iiIiiIi = { "type" : "etr-nat-port" , "port" : ephem_port }
 lisp_write_to_dp_socket ( iiIiiIi )
 return
 if 80 - 80: i11iIiiIii / OoOoOO00 . OOooOOo . iIii1I11I1II1
 if 81 - 81: I1ii11iIi11i * OoO0O00 . o0oOOo0O0Ooo . OoooooooOO
 if 64 - 64: Oo0Ooo . I1ii11iIi11i / ooOoO0o % oO0o . iIii1I11I1II1
 if 84 - 84: II111iiii . oO0o * O0 / iII111i + OoooooooOO
 if 99 - 99: I1ii11iIi11i . oO0o + Oo0Ooo + I1ii11iIi11i / I1Ii111 . I1ii11iIi11i
 if 95 - 95: OoOoOO00 * iIii1I11I1II1 / OoooooooOO % i1IIi
 if 91 - 91: OOooOOo - OoOoOO00
def lisp_write_ipc_interfaces ( ) :
 if ( lisp_i_am_etr ) : return
 if ( lisp_ipc_dp_socket == None ) : return
 if ( lisp_check_dp_socket ( ) == False ) : return
 if 58 - 58: II111iiii . OOooOOo % II111iiii * oO0o % OoO0O00 % I11i
 if 71 - 71: Ii1I * II111iiii * I1IiiI
 if 22 - 22: oO0o
 if 96 - 96: ooOoO0o * iII111i . IiII
 iiIiiIi = { "type" : "interfaces" , "interfaces" : [ ] }
 if 77 - 77: OOooOOo - I11i % o0oOOo0O0Ooo
 for O0OOoooo0 in lisp_myinterfaces . values ( ) :
  if ( O0OOoooo0 . instance_id == None ) : continue
  O0oo00O = { "interface" : O0OOoooo0 . device ,
 "instance-id" : str ( O0OOoooo0 . instance_id ) }
  iiIiiIi [ "interfaces" ] . append ( O0oo00O )
  if 46 - 46: I1IiiI % oO0o . OoooooooOO . IiII / I11i - i1IIi
  if 43 - 43: OoOoOO00 - o0oOOo0O0Ooo
 lisp_write_to_dp_socket ( iiIiiIi )
 return
 if 22 - 22: i1IIi
 if 33 - 33: O0
 if 34 - 34: I1Ii111 . IiII % iII111i
 if 94 - 94: OOooOOo % i11iIiiIii . OOooOOo
 if 55 - 55: OoOoOO00 . OoOoOO00 % o0oOOo0O0Ooo . I11i . I1ii11iIi11i - o0oOOo0O0Ooo
 if 1 - 1: i11iIiiIii - i1IIi * oO0o - iIii1I11I1II1
 if 75 - 75: i1IIi * i11iIiiIii
 if 40 - 40: I1ii11iIi11i + OoO0O00
 if 8 - 8: i11iIiiIii - iIii1I11I1II1
 if 73 - 73: OoOoOO00
 if 25 - 25: iII111i / oO0o
 if 61 - 61: OoooooooOO . Ii1I . I11i + oO0o
 if 73 - 73: II111iiii % i11iIiiIii * I1ii11iIi11i + O0
 if 61 - 61: I1IiiI / OOooOOo
def lisp_parse_auth_key ( value ) :
 iI1ii1II1i111 = value . split ( "[" )
 oo0000O = { }
 if ( len ( iI1ii1II1i111 ) == 1 ) :
  oo0000O [ 0 ] = value
  return ( oo0000O )
  if 57 - 57: I1IiiI . II111iiii . i1IIi * O0
  if 90 - 90: i11iIiiIii + iIii1I11I1II1 + O0 % I1IiiI
 for oOO0ooo in iI1ii1II1i111 :
  if ( oOO0ooo == "" ) : continue
  Oo0oOooo000OO = oOO0ooo . find ( "]" )
  oOoO0oO00ooOo = oOO0ooo [ 0 : Oo0oOooo000OO ]
  try : oOoO0oO00ooOo = int ( oOoO0oO00ooOo )
  except : return
  if 95 - 95: ooOoO0o % OOooOOo
  oo0000O [ oOoO0oO00ooOo ] = oOO0ooo [ Oo0oOooo000OO + 1 : : ]
  if 17 - 17: i1IIi + Ii1I
 return ( oo0000O )
 if 35 - 35: iIii1I11I1II1 - Oo0Ooo - OoooooooOO % I1ii11iIi11i
 if 27 - 27: Oo0Ooo * II111iiii - OOooOOo + o0oOOo0O0Ooo
 if 26 - 26: oO0o / I1ii11iIi11i - oO0o
 if 9 - 9: ooOoO0o * iIii1I11I1II1 * OoooooooOO
 if 13 - 13: iII111i . i11iIiiIii * o0oOOo0O0Ooo . iII111i
 if 96 - 96: Ii1I
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
def lisp_reassemble ( packet ) :
 I1iiI11i111II = socket . ntohs ( struct . unpack ( "H" , packet [ 6 : 8 ] ) [ 0 ] )
 if 28 - 28: IiII . o0oOOo0O0Ooo + iII111i - OoOoOO00 / OOooOOo
 if 86 - 86: ooOoO0o * OoOoOO00 + oO0o / II111iiii % OOooOOo
 if 89 - 89: O0 * Ii1I / OoO0O00 / OoOoOO00 % iII111i * iIii1I11I1II1
 if 72 - 72: iIii1I11I1II1 / iIii1I11I1II1 * I11i
 if ( I1iiI11i111II == 0 or I1iiI11i111II == 0x4000 ) : return ( packet )
 if 19 - 19: I1ii11iIi11i
 if 42 - 42: OoOoOO00 / IiII
 if 65 - 65: ooOoO0o - ooOoO0o * OoO0O00
 if 99 - 99: I11i % ooOoO0o . I1Ii111
 o0O0O0O00o = socket . ntohs ( struct . unpack ( "H" , packet [ 4 : 6 ] ) [ 0 ] )
 I1IIii = socket . ntohs ( struct . unpack ( "H" , packet [ 2 : 4 ] ) [ 0 ] )
 if 16 - 16: iIii1I11I1II1 / O0 - o0oOOo0O0Ooo + ooOoO0o * I1IiiI / i1IIi
 i1iOO0oo0O = ( I1iiI11i111II & 0x2000 == 0 and ( I1iiI11i111II & 0x1fff ) != 0 )
 iiIiiIi = [ ( I1iiI11i111II & 0x1fff ) * 8 , I1IIii - 20 , packet , i1iOO0oo0O ]
 if 99 - 99: I1ii11iIi11i
 if 71 - 71: II111iiii % Oo0Ooo
 if 38 - 38: I1IiiI - I11i / IiII . O0
 if 26 - 26: II111iiii
 if 8 - 8: iIii1I11I1II1 . Ii1I . iII111i
 if 59 - 59: O0 % I1Ii111 / I1Ii111 + OoO0O00
 if 2 - 2: IiII - II111iiii / Oo0Ooo % IiII * I1ii11iIi11i
 if 26 - 26: ooOoO0o . OoOoOO00 / iIii1I11I1II1
 if ( I1iiI11i111II == 0x2000 ) :
  oo0 , iii1iI = struct . unpack ( "HH" , packet [ 20 : 24 ] )
  oo0 = socket . ntohs ( oo0 )
  iii1iI = socket . ntohs ( iii1iI )
  if ( iii1iI not in [ 4341 , 8472 , 4789 ] and oo0 != 4341 ) :
   lisp_reassembly_queue [ o0O0O0O00o ] = [ ]
   iiIiiIi [ 2 ] = None
   if 54 - 54: I1IiiI % II111iiii
   if 29 - 29: ooOoO0o - OOooOOo - I11i / I1Ii111
   if 88 - 88: O0 + IiII
   if 91 - 91: OoooooooOO + OoO0O00 % I1Ii111 . I1IiiI . iIii1I11I1II1
   if 88 - 88: OoooooooOO
   if 40 - 40: ooOoO0o * oO0o * Ii1I . ooOoO0o + i11iIiiIii
 if ( lisp_reassembly_queue . has_key ( o0O0O0O00o ) == False ) :
  lisp_reassembly_queue [ o0O0O0O00o ] = [ ]
  if 44 - 44: o0oOOo0O0Ooo / iIii1I11I1II1
  if 66 - 66: O0 % I11i . O0 * o0oOOo0O0Ooo / I1Ii111 + o0oOOo0O0Ooo
  if 24 - 24: i11iIiiIii * oO0o * I1IiiI - i1IIi * OoOoOO00
  if 5 - 5: I1ii11iIi11i % o0oOOo0O0Ooo . iII111i
  if 73 - 73: OoOoOO00 . o0oOOo0O0Ooo * OoOoOO00
 oOOO0 = lisp_reassembly_queue [ o0O0O0O00o ]
 if 82 - 82: I1IiiI + I1Ii111 . O0
 if 83 - 83: OoO0O00 * oO0o / I1ii11iIi11i % IiII * I1Ii111 + Ii1I
 if 70 - 70: iII111i * I1Ii111
 if 5 - 5: Oo0Ooo * ooOoO0o % II111iiii % II111iiii - oO0o
 if 71 - 71: iIii1I11I1II1 % i11iIiiIii . o0oOOo0O0Ooo - oO0o + Oo0Ooo
 if ( len ( oOOO0 ) == 1 and oOOO0 [ 0 ] [ 2 ] == None ) :
  dprint ( "Drop non-LISP encapsulated fragment 0x{}" . format ( lisp_hex_string ( o0O0O0O00o ) . zfill ( 4 ) ) )
  if 69 - 69: I1IiiI - OoOoOO00 . I1ii11iIi11i
  return ( None )
  if 88 - 88: ooOoO0o + ooOoO0o + oO0o * o0oOOo0O0Ooo . Ii1I
  if 72 - 72: I11i / I11i
  if 78 - 78: I1IiiI % II111iiii
  if 99 - 99: Oo0Ooo
  if 30 - 30: OoOoOO00 + I1Ii111 . OoOoOO00 - I11i
 oOOO0 . append ( iiIiiIi )
 oOOO0 = sorted ( oOOO0 )
 if 42 - 42: OoOoOO00
 if 77 - 77: Oo0Ooo * IiII * I1ii11iIi11i + IiII
 if 37 - 37: IiII . OoooooooOO - i11iIiiIii * I1ii11iIi11i - OOooOOo
 if 74 - 74: Ii1I + i11iIiiIii * iII111i / o0oOOo0O0Ooo . i11iIiiIii
 oOo00Ooo0o0 = lisp_address ( LISP_AFI_IPV4 , "" , 32 , 0 )
 oOo00Ooo0o0 . address = socket . ntohl ( struct . unpack ( "I" , packet [ 12 : 16 ] ) [ 0 ] )
 OOOooo0OO = oOo00Ooo0o0 . print_address_no_iid ( )
 oOo00Ooo0o0 . address = socket . ntohl ( struct . unpack ( "I" , packet [ 16 : 20 ] ) [ 0 ] )
 Oooo00OO0OO0 = oOo00Ooo0o0 . print_address_no_iid ( )
 oOo00Ooo0o0 = red ( "{} -> {}" . format ( OOOooo0OO , Oooo00OO0OO0 ) , False )
 if 82 - 82: iII111i / I11i + OoooooooOO
 dprint ( "{}{} fragment, RLOCs: {}, packet 0x{}, frag-offset: 0x{}" . format ( bold ( "Received" , False ) , " non-LISP encapsulated" if iiIiiIi [ 2 ] == None else "" , oOo00Ooo0o0 , lisp_hex_string ( o0O0O0O00o ) . zfill ( 4 ) ,
 # i11iIiiIii * ooOoO0o
 # Ii1I / I1ii11iIi11i + OOooOOo + I1Ii111 / IiII
 lisp_hex_string ( I1iiI11i111II ) . zfill ( 4 ) ) )
 if 13 - 13: IiII + iII111i . I1Ii111 - iII111i - o0oOOo0O0Ooo
 if 72 - 72: II111iiii . I11i % I1Ii111 % I1ii11iIi11i
 if 9 - 9: OoOoOO00 * II111iiii
 if 21 - 21: OoooooooOO
 if 34 - 34: i11iIiiIii / I1Ii111 - o0oOOo0O0Ooo / i1IIi * I11i
 if ( oOOO0 [ 0 ] [ 0 ] != 0 or oOOO0 [ - 1 ] [ 3 ] == False ) : return ( None )
 o0ooO = oOOO0 [ 0 ]
 for i11Ii1 in oOOO0 [ 1 : : ] :
  I1iiI11i111II = i11Ii1 [ 0 ]
  Oo000o , ooIIIIi11iiII1 = o0ooO [ 0 ] , o0ooO [ 1 ]
  if ( Oo000o + ooIIIIi11iiII1 != I1iiI11i111II ) : return ( None )
  o0ooO = i11Ii1
  if 91 - 91: O0
 lisp_reassembly_queue . pop ( o0O0O0O00o )
 if 13 - 13: o0oOOo0O0Ooo
 if 15 - 15: iIii1I11I1II1 * Oo0Ooo . iIii1I11I1II1 . Ii1I % iII111i - i11iIiiIii
 if 77 - 77: ooOoO0o - o0oOOo0O0Ooo * OoOoOO00 % oO0o
 if 4 - 4: i11iIiiIii + OoOoOO00
 if 45 - 45: ooOoO0o / OoooooooOO . Oo0Ooo
 packet = oOOO0 [ 0 ] [ 2 ]
 for i11Ii1 in oOOO0 [ 1 : : ] : packet += i11Ii1 [ 2 ] [ 20 : : ]
 if 35 - 35: i11iIiiIii / o0oOOo0O0Ooo / oO0o / I11i . O0
 dprint ( "{} fragments arrived for packet 0x{}, length {}" . format ( bold ( "All" , False ) , lisp_hex_string ( o0O0O0O00o ) . zfill ( 4 ) , len ( packet ) ) )
 if 53 - 53: i1IIi
 if 51 - 51: OoOoOO00 / iIii1I11I1II1 . oO0o - I1ii11iIi11i - OOooOOo
 if 90 - 90: i1IIi / oO0o * I1Ii111 + II111iiii % I11i
 if 41 - 41: o0oOOo0O0Ooo - II111iiii . ooOoO0o . iII111i - ooOoO0o / iII111i
 if 59 - 59: O0 / II111iiii * II111iiii - ooOoO0o
 O00OoO0oo = socket . htons ( len ( packet ) )
 I11IIIIiII = packet [ 0 : 2 ] + struct . pack ( "H" , O00OoO0oo ) + packet [ 4 : 6 ] + struct . pack ( "H" , 0 ) + packet [ 8 : 10 ] + struct . pack ( "H" , 0 ) + packet [ 12 : 20 ]
 if 63 - 63: I1ii11iIi11i * IiII % OoO0O00 . OoOoOO00 - II111iiii % IiII
 if 8 - 8: iIii1I11I1II1
 I11IIIIiII = lisp_ip_checksum ( I11IIIIiII )
 return ( I11IIIIiII + packet [ 20 : : ] )
 if 71 - 71: oO0o / o0oOOo0O0Ooo % iIii1I11I1II1 * iIii1I11I1II1
 if 29 - 29: ooOoO0o - OoOoOO00 - o0oOOo0O0Ooo
 if 54 - 54: Ii1I + i11iIiiIii + i1IIi - OoooooooOO
 if 100 - 100: oO0o . ooOoO0o
 if 14 - 14: OoooooooOO + iII111i / iIii1I11I1II1 / ooOoO0o % iIii1I11I1II1 - IiII
 if 34 - 34: I1ii11iIi11i + i11iIiiIii - I1ii11iIi11i / OoOoOO00 + i1IIi . i11iIiiIii
 if 48 - 48: I1ii11iIi11i % OoOoOO00 * OoOoOO00 % o0oOOo0O0Ooo * II111iiii / OoOoOO00
 if 73 - 73: OoOoOO00 + OOooOOo * II111iiii . OOooOOo % I1Ii111 % oO0o
def lisp_get_crypto_decap_lookup_key ( addr , port ) :
 i111I11I = addr . print_address_no_iid ( ) + ":" + str ( port )
 if ( lisp_crypto_keys_by_rloc_decap . has_key ( i111I11I ) ) : return ( i111I11I )
 if 79 - 79: I1ii11iIi11i % I11i
 i111I11I = addr . print_address_no_iid ( )
 if ( lisp_crypto_keys_by_rloc_decap . has_key ( i111I11I ) ) : return ( i111I11I )
 if 78 - 78: i11iIiiIii % I1Ii111 + iIii1I11I1II1 + iII111i
 if 66 - 66: I1IiiI - o0oOOo0O0Ooo
 if 67 - 67: oO0o . iII111i * Ii1I - OOooOOo / oO0o
 if 98 - 98: OoOoOO00 * OoO0O00 . Oo0Ooo
 if 6 - 6: I11i % iIii1I11I1II1 + I1Ii111
 for IiiO00o0OoO00ooo in lisp_crypto_keys_by_rloc_decap :
  i1 = IiiO00o0OoO00ooo . split ( ":" )
  if ( len ( i1 ) == 1 ) : continue
  i1 = i1 [ 0 ] if len ( i1 ) == 2 else ":" . join ( i1 [ 0 : - 1 ] )
  if ( i1 == i111I11I ) :
   i11i1ii11Ii1 = lisp_crypto_keys_by_rloc_decap [ IiiO00o0OoO00ooo ]
   lisp_crypto_keys_by_rloc_decap [ i111I11I ] = i11i1ii11Ii1
   return ( i111I11I )
   if 89 - 89: Oo0Ooo / iIii1I11I1II1 . OoOoOO00
   if 6 - 6: Ii1I / iII111i
 return ( None )
 if 69 - 69: iIii1I11I1II1 % I1Ii111 % OOooOOo + O0 - OoOoOO00 % oO0o
 if 70 - 70: oO0o - I1IiiI + Ii1I
 if 54 - 54: OoOoOO00 / ooOoO0o - I1IiiI
 if 37 - 37: o0oOOo0O0Ooo
 if 57 - 57: iII111i / i1IIi / i1IIi + IiII
 if 75 - 75: IiII / O0
 if 72 - 72: I11i
 if 35 - 35: I11i % OoooooooOO / i1IIi * i1IIi / I1IiiI
 if 42 - 42: I11i - i1IIi - oO0o / I11i + Ii1I + ooOoO0o
 if 23 - 23: OoOoOO00 . oO0o - iII111i
 if 27 - 27: Oo0Ooo * OOooOOo - OoOoOO00
def lisp_build_crypto_decap_lookup_key ( addr , port ) :
 addr = addr . print_address_no_iid ( )
 iiiiiIIIiii11 = addr + ":" + str ( port )
 if 48 - 48: OoooooooOO * OoO0O00 * iIii1I11I1II1 % I1Ii111
 if ( lisp_i_am_rtr ) :
  if ( lisp_rloc_probe_list . has_key ( addr ) ) : return ( addr )
  if 22 - 22: i1IIi
  if 61 - 61: IiII
  if 3 - 3: ooOoO0o . Oo0Ooo . ooOoO0o / OoO0O00 / o0oOOo0O0Ooo . I1Ii111
  if 20 - 20: iII111i + II111iiii + i11iIiiIii
  if 75 - 75: OoooooooOO
  if 63 - 63: iII111i % oO0o . ooOoO0o * I1Ii111 + o0oOOo0O0Ooo * II111iiii
  for oOOoO in lisp_nat_state_info . values ( ) :
   for i1iiI1i in oOOoO :
    if ( addr == i1iiI1i . address ) : return ( iiiiiIIIiii11 )
    if 61 - 61: oO0o
    if 45 - 45: I11i * OoOoOO00 % Oo0Ooo / iII111i
  return ( addr )
  if 78 - 78: II111iiii
 return ( iiiiiIIIiii11 )
 if 38 - 38: I11i - i11iIiiIii
 if 38 - 38: I1IiiI * i1IIi / OoO0O00 + iIii1I11I1II1 / I1Ii111 % II111iiii
 if 62 - 62: OoOoOO00 * i1IIi + iII111i
 if 43 - 43: OOooOOo % i11iIiiIii / I1ii11iIi11i + i1IIi / ooOoO0o
 if 74 - 74: Ii1I + iIii1I11I1II1
 if 23 - 23: OoO0O00 * i1IIi * oO0o % I1ii11iIi11i
 if 92 - 92: iII111i / I1IiiI / i11iIiiIii
def lisp_set_ttl ( lisp_socket , ttl ) :
 try :
  lisp_socket . setsockopt ( socket . SOL_IP , socket . IP_TTL , ttl )
 except :
  lprint ( "socket.setsockopt(IP_TTL) not supported" )
  pass
  if 75 - 75: Oo0Ooo + IiII / I11i % I11i % IiII / I1Ii111
 return
 if 95 - 95: OoOoOO00
 if 78 - 78: I11i
 if 62 - 62: iIii1I11I1II1 . o0oOOo0O0Ooo . ooOoO0o % oO0o % O0 % oO0o
 if 51 - 51: Oo0Ooo / IiII - Oo0Ooo
 if 71 - 71: I11i * I1ii11iIi11i * OOooOOo * o0oOOo0O0Ooo
 if 53 - 53: I1IiiI % I1IiiI
 if 80 - 80: OoO0O00 - i11iIiiIii / iII111i * I1ii11iIi11i / I1IiiI - I1Ii111
def lisp_is_rloc_probe_request ( lisp_type ) :
 lisp_type = struct . unpack ( "B" , lisp_type ) [ 0 ]
 return ( lisp_type == 0x12 )
 if 85 - 85: IiII
 if 72 - 72: iII111i * OoOoOO00
 if 65 - 65: iIii1I11I1II1 / iIii1I11I1II1 % O0 / II111iiii . OOooOOo . O0
 if 65 - 65: I11i
 if 35 - 35: o0oOOo0O0Ooo - i11iIiiIii
 if 78 - 78: ooOoO0o - II111iiii - i1IIi
 if 18 - 18: OoooooooOO % OoOoOO00 - IiII / oO0o . OOooOOo . I1IiiI
def lisp_is_rloc_probe_reply ( lisp_type ) :
 lisp_type = struct . unpack ( "B" , lisp_type ) [ 0 ]
 return ( lisp_type == 0x28 )
 if 77 - 77: I1ii11iIi11i . OoO0O00 / OoOoOO00 / O0
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
 if 17 - 17: I11i * i1IIi + iIii1I11I1II1 % I1IiiI
 if 44 - 44: IiII + I1IiiI . Ii1I % Oo0Ooo
 if 97 - 97: O0
 if 95 - 95: OoO0O00 % iII111i / I1IiiI * OoooooooOO
 if 31 - 31: iIii1I11I1II1
 if 62 - 62: o0oOOo0O0Ooo - iII111i / II111iiii . o0oOOo0O0Ooo
 if 20 - 20: iIii1I11I1II1 % OOooOOo
def lisp_is_rloc_probe ( packet , rr ) :
 IiI1iiI11 = ( struct . unpack ( "B" , packet [ 9 ] ) [ 0 ] == 17 )
 if ( IiI1iiI11 == False ) : return ( [ packet , None , None , None ] )
 if 91 - 91: ooOoO0o
 oo0 = struct . unpack ( "H" , packet [ 20 : 22 ] ) [ 0 ]
 iii1iI = struct . unpack ( "H" , packet [ 22 : 24 ] ) [ 0 ]
 oO0 = ( socket . htons ( LISP_CTRL_PORT ) in [ oo0 , iii1iI ] )
 if ( oO0 == False ) : return ( [ packet , None , None , None ] )
 if 94 - 94: OoooooooOO + II111iiii % ooOoO0o - II111iiii / O0
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
   if 34 - 34: IiII % oO0o
   if 54 - 54: I1IiiI
   if 80 - 80: OoOoOO00 . I1IiiI / I1ii11iIi11i . iII111i
   if 31 - 31: I11i * o0oOOo0O0Ooo
   if 17 - 17: Ii1I * iIii1I11I1II1
   if 9 - 9: o0oOOo0O0Ooo - IiII
 OOii = lisp_address ( LISP_AFI_IPV4 , "" , 32 , 0 )
 OOii . address = socket . ntohl ( struct . unpack ( "I" , packet [ 12 : 16 ] ) [ 0 ] )
 if 78 - 78: i11iIiiIii . o0oOOo0O0Ooo
 if 72 - 72: Oo0Ooo % II111iiii + O0 * OoOoOO00 - OOooOOo + I1Ii111
 if 23 - 23: I1IiiI - O0 - iII111i . II111iiii / oO0o
 if 1 - 1: I11i . OOooOOo / oO0o % I11i * Oo0Ooo + Oo0Ooo
 if ( OOii . is_local ( ) ) : return ( [ None , None , None , None ] )
 if 23 - 23: Ii1I % i1IIi - I1Ii111
 if 95 - 95: OoOoOO00 - ooOoO0o . i1IIi . OoooooooOO
 if 38 - 38: I1IiiI + I1ii11iIi11i - Oo0Ooo . i11iIiiIii - i1IIi
 if 11 - 11: IiII / I1IiiI . I1IiiI
 OOii = OOii . print_address_no_iid ( )
 IIIIiI1ii1 = socket . ntohs ( struct . unpack ( "H" , packet [ 20 : 22 ] ) [ 0 ] )
 I1i = struct . unpack ( "B" , packet [ 8 ] ) [ 0 ] - 1
 packet = packet [ 28 : : ]
 if 87 - 87: OoooooooOO * OoO0O00 * iIii1I11I1II1
 oooO0 = bold ( "Receive(pcap)" , False )
 ii1iIii = bold ( "from " + OOii , False )
 IiIiI1 = lisp_format_packet ( packet )
 lprint ( "{} {} bytes {} {}, packet: {}" . format ( oooO0 , len ( packet ) , ii1iIii , IIIIiI1ii1 , IiIiI1 ) )
 if 16 - 16: o0oOOo0O0Ooo * I11i + OoooooooOO + O0 / iIii1I11I1II1
 return ( [ packet , OOii , IIIIiI1ii1 , I1i ] )
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
def lisp_ipc_write_xtr_parameters ( cp , dp ) :
 if ( lisp_ipc_dp_socket == None ) : return
 if 15 - 15: oO0o * I1Ii111
 OOO000OOOO0oO = { "type" : "xtr-parameters" , "control-plane-logging" : cp ,
 "data-plane-logging" : dp , "rtr" : lisp_i_am_rtr }
 if 11 - 11: Ii1I + o0oOOo0O0Ooo * OoooooooOO % iIii1I11I1II1
 lisp_write_to_dp_socket ( OOO000OOOO0oO )
 return
 if 87 - 87: OoO0O00 + o0oOOo0O0Ooo
 if 46 - 46: oO0o + OoOoOO00
 if 17 - 17: Ii1I . Oo0Ooo - oO0o % OOooOOo
 if 59 - 59: O0
 if 75 - 75: o0oOOo0O0Ooo / OoooooooOO . I1ii11iIi11i * oO0o * I11i / OoooooooOO
 if 17 - 17: Ii1I % I1ii11iIi11i + I11i
 if 80 - 80: i1IIi . OoooooooOO % OoooooooOO . oO0o / OOooOOo
 if 85 - 85: OOooOOo
def lisp_external_data_plane ( ) :
 oO0O = 'egrep "ipc-data-plane = yes" ./lisp.config'
 if ( commands . getoutput ( oO0O ) != "" ) : return ( True )
 if 80 - 80: ooOoO0o % O0 % I1ii11iIi11i + Oo0Ooo
 if ( os . getenv ( "LISP_RUN_LISP_XTR" ) != None ) : return ( True )
 return ( False )
 if 82 - 82: oO0o / iIii1I11I1II1 % ooOoO0o . Ii1I / i1IIi - I1Ii111
 if 15 - 15: I11i - OOooOOo . II111iiii . iIii1I11I1II1
 if 93 - 93: I11i + o0oOOo0O0Ooo / OOooOOo + Ii1I % Oo0Ooo % I1ii11iIi11i
 if 72 - 72: IiII / II111iiii
 if 25 - 25: i1IIi + OoOoOO00 + oO0o + OoooooooOO
 if 21 - 21: I1ii11iIi11i
 if 60 - 60: i1IIi / OoO0O00 . Ii1I
 if 16 - 16: i11iIiiIii + OoOoOO00 % Oo0Ooo + I1ii11iIi11i * Ii1I / I1Ii111
 if 26 - 26: iII111i
 if 31 - 31: iII111i
 if 45 - 45: OoO0O00
 if 55 - 55: iIii1I11I1II1 % iIii1I11I1II1 + I11i - ooOoO0o + I1IiiI * O0
 if 47 - 47: ooOoO0o + iIii1I11I1II1 * OOooOOo . I1IiiI . o0oOOo0O0Ooo
 if 49 - 49: Oo0Ooo . OoOoOO00 * OOooOOo
def lisp_process_data_plane_restart ( do_clear = False ) :
 os . system ( "touch ./lisp.config" )
 if 86 - 86: IiII * OOooOOo + Ii1I
 o0O0OOoo0O = { "type" : "entire-map-cache" , "entries" : [ ] }
 if 15 - 15: I1IiiI / I1Ii111 % iII111i
 if ( do_clear == False ) :
  i1I1I11ii = o0O0OOoo0O [ "entries" ]
  lisp_map_cache . walk_cache ( lisp_ipc_walk_map_cache , i1I1I11ii )
  if 57 - 57: I1Ii111 . iIii1I11I1II1 / Oo0Ooo / IiII / iII111i * OoOoOO00
  if 35 - 35: i1IIi + I1Ii111 - ooOoO0o . I1ii11iIi11i + Oo0Ooo
 lisp_write_to_dp_socket ( o0O0OOoo0O )
 return
 if 43 - 43: oO0o . OoO0O00 * i1IIi
 if 1 - 1: ooOoO0o / i1IIi
 if 42 - 42: I1ii11iIi11i * ooOoO0o + OoOoOO00 % I1ii11iIi11i . IiII
 if 75 - 75: OoO0O00 * i1IIi - OOooOOo % II111iiii % OoO0O00 - OoOoOO00
 if 75 - 75: I11i * IiII * ooOoO0o
 if 31 - 31: Ii1I
 if 72 - 72: OOooOOo * Ii1I % OoO0O00
 if 72 - 72: OoOoOO00 + o0oOOo0O0Ooo - i1IIi - OoO0O00 % OoOoOO00
 if 42 - 42: oO0o / i1IIi . IiII
 if 12 - 12: i11iIiiIii . ooOoO0o
 if 80 - 80: O0 / iIii1I11I1II1 % iII111i * ooOoO0o / i11iIiiIii . OoOoOO00
 if 88 - 88: OoooooooOO . I1IiiI
 if 6 - 6: I1Ii111 - i11iIiiIii - oO0o
 if 7 - 7: i1IIi
def lisp_process_data_plane_stats ( msg , lisp_sockets , lisp_port ) :
 if ( msg . has_key ( "entries" ) == False ) :
  lprint ( "No 'entries' in stats IPC message" )
  return
  if 6 - 6: OoooooooOO - Oo0Ooo - I1ii11iIi11i
 if ( type ( msg [ "entries" ] ) != list ) :
  lprint ( "'entries' in stats IPC message must be an array" )
  return
  if 34 - 34: iII111i + i11iIiiIii . IiII
  if 54 - 54: Oo0Ooo + I11i - iII111i * ooOoO0o % i11iIiiIii . IiII
 for msg in msg [ "entries" ] :
  if ( msg . has_key ( "eid-prefix" ) == False ) :
   lprint ( "No 'eid-prefix' in stats IPC message" )
   continue
   if 29 - 29: II111iiii % i11iIiiIii % O0
  O0o0O0OO0o = msg [ "eid-prefix" ]
  if 38 - 38: o0oOOo0O0Ooo * IiII
  if ( msg . has_key ( "instance-id" ) == False ) :
   lprint ( "No 'instance-id' in stats IPC message" )
   continue
   if 51 - 51: OoooooooOO . Ii1I % OoooooooOO - I1IiiI + I1Ii111 % oO0o
  II1ii1ii11I1 = int ( msg [ "instance-id" ] )
  if 28 - 28: i11iIiiIii - I1IiiI * OoO0O00
  if 19 - 19: OoooooooOO
  if 34 - 34: OoOoOO00 . oO0o
  if 53 - 53: oO0o + OoooooooOO * ooOoO0o
  ii1Ii = lisp_address ( LISP_AFI_NONE , "" , 0 , II1ii1ii11I1 )
  ii1Ii . store_prefix ( O0o0O0OO0o )
  OoOOO000O0o = lisp_map_cache_lookup ( None , ii1Ii )
  if ( OoOOO000O0o == None ) :
   lprint ( "Map-cache entry for {} not found for stats update" . format ( O0o0O0OO0o ) )
   if 85 - 85: I1ii11iIi11i - o0oOOo0O0Ooo % o0oOOo0O0Ooo % iII111i * OoOoOO00
   continue
   if 50 - 50: I1Ii111 + I1Ii111 + I11i - OoOoOO00
   if 65 - 65: oO0o / I11i + iII111i - I1ii11iIi11i
  if ( msg . has_key ( "rlocs" ) == False ) :
   lprint ( "No 'rlocs' in stats IPC message for {}" . format ( O0o0O0OO0o ) )
   if 80 - 80: II111iiii . i11iIiiIii
   continue
   if 66 - 66: ooOoO0o * iII111i * OOooOOo % OoO0O00 / I1ii11iIi11i
  if ( type ( msg [ "rlocs" ] ) != list ) :
   lprint ( "'rlocs' in stats IPC message must be an array" )
   continue
   if 33 - 33: iIii1I11I1II1
  ooo00o0 = msg [ "rlocs" ]
  if 13 - 13: I1IiiI / O0 % OOooOOo . I1IiiI * I1ii11iIi11i
  if 40 - 40: OoO0O00 % o0oOOo0O0Ooo / O0
  if 29 - 29: iII111i % I1Ii111
  if 95 - 95: OOooOOo - ooOoO0o % i1IIi / O0 % I11i . IiII
  for oo0o0OoOo0Ooo in ooo00o0 :
   if ( oo0o0OoOo0Ooo . has_key ( "rloc" ) == False ) : continue
   if 55 - 55: IiII . ooOoO0o + i1IIi / ooOoO0o / I11i * I1IiiI
   I111I1iii11 = oo0o0OoOo0Ooo [ "rloc" ]
   if ( I111I1iii11 == "no-address" ) : continue
   if 59 - 59: II111iiii
   II11IIiii = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
   II11IIiii . store_address ( I111I1iii11 )
   if 11 - 11: OOooOOo * I1Ii111 - I1Ii111 * Ii1I
   IiIiI = OoOOO000O0o . get_rloc ( II11IIiii )
   if ( IiIiI == None ) : continue
   if 43 - 43: IiII / o0oOOo0O0Ooo . I1Ii111 % iII111i . OoooooooOO - o0oOOo0O0Ooo
   if 30 - 30: i1IIi / I1Ii111 * oO0o - oO0o / oO0o
   if 9 - 9: IiII / o0oOOo0O0Ooo . IiII * O0 % i11iIiiIii % OoOoOO00
   if 29 - 29: I1ii11iIi11i % ooOoO0o . OOooOOo . Ii1I . IiII
   OO0ii11II1II1 = 0 if oo0o0OoOo0Ooo . has_key ( "packet-count" ) == False else oo0o0OoOo0Ooo [ "packet-count" ]
   if 68 - 68: I11i
   o0oOO0OO0000O = 0 if oo0o0OoOo0Ooo . has_key ( "byte-count" ) == False else oo0o0OoOo0Ooo [ "byte-count" ]
   if 62 - 62: i11iIiiIii % iIii1I11I1II1 / IiII . I1IiiI * O0
   iiiI = 0 if oo0o0OoOo0Ooo . has_key ( "seconds-last-packet" ) == False else oo0o0OoOo0Ooo [ "seconds-last-packet" ]
   if 17 - 17: I1ii11iIi11i - I1Ii111 % II111iiii + OOooOOo
   if 45 - 45: I1Ii111 + iII111i - iIii1I11I1II1 / Oo0Ooo
   IiIiI . stats . packet_count += OO0ii11II1II1
   IiIiI . stats . byte_count += o0oOO0OO0000O
   IiIiI . stats . last_increment = lisp_get_timestamp ( ) - iiiI
   if 92 - 92: iIii1I11I1II1 . OoO0O00 - I11i % I1ii11iIi11i / i11iIiiIii
   lprint ( "Update stats {}/{}/{}s for {} RLOC {}" . format ( OO0ii11II1II1 , o0oOO0OO0000O ,
 iiiI , O0o0O0OO0o , I111I1iii11 ) )
   if 4 - 4: Oo0Ooo / I1IiiI * i1IIi . II111iiii
   if 13 - 13: i1IIi
   if 39 - 39: OOooOOo
   if 73 - 73: OoO0O00 . ooOoO0o
   if 13 - 13: o0oOOo0O0Ooo - OoOoOO00
  if ( OoOOO000O0o . group . is_null ( ) and OoOOO000O0o . has_ttl_elapsed ( ) ) :
   O0o0O0OO0o = green ( OoOOO000O0o . print_eid_tuple ( ) , False )
   lprint ( "Refresh map-cache entry {}" . format ( O0o0O0OO0o ) )
   lisp_send_map_request ( lisp_sockets , lisp_port , None , OoOOO000O0o . eid , None )
   if 60 - 60: OoO0O00
   if 17 - 17: i11iIiiIii % i1IIi % I1IiiI % ooOoO0o + I1Ii111 + Oo0Ooo
 return
 if 16 - 16: iII111i . I1ii11iIi11i . oO0o . OoO0O00
 if 90 - 90: i1IIi . ooOoO0o + i11iIiiIii * OoooooooOO
 if 30 - 30: iII111i . OoO0O00 . i11iIiiIii / I1ii11iIi11i * Oo0Ooo
 if 38 - 38: IiII + II111iiii
 if 20 - 20: iII111i * I1IiiI * iII111i - o0oOOo0O0Ooo + i1IIi + ooOoO0o
 if 49 - 49: II111iiii * I1IiiI / oO0o
 if 50 - 50: Ii1I + O0 . I1IiiI * Oo0Ooo
 if 15 - 15: Oo0Ooo
 if 53 - 53: OoooooooOO * O0 / iII111i * ooOoO0o % I1Ii111 + OOooOOo
 if 95 - 95: I1Ii111 % OoOoOO00 . IiII * iII111i % Ii1I
 if 18 - 18: iIii1I11I1II1 / ooOoO0o / I1Ii111 % oO0o * Ii1I
 if 14 - 14: oO0o
 if 72 - 72: iIii1I11I1II1 / II111iiii * II111iiii + I1IiiI + iIii1I11I1II1 + oO0o
 if 46 - 46: I1Ii111
 if 23 - 23: Oo0Ooo * IiII - I1Ii111 . OoooooooOO
 if 78 - 78: OoOoOO00 - iIii1I11I1II1
 if 20 - 20: i1IIi
 if 72 - 72: ooOoO0o . II111iiii
 if 32 - 32: I1Ii111 - oO0o + OoooooooOO . OoOoOO00 + i11iIiiIii / i1IIi
 if 26 - 26: I1IiiI + OoooooooOO % OoOoOO00 . IiII - II111iiii . OoOoOO00
 if 37 - 37: OoO0O00 % O0 + OoOoOO00 * I11i . Ii1I * OoO0O00
 if 18 - 18: o0oOOo0O0Ooo / OOooOOo
 if 28 - 28: O0 / Ii1I - oO0o % I1ii11iIi11i % O0 . OoO0O00
def lisp_process_data_plane_decap_stats ( msg , lisp_ipc_socket ) :
 if 100 - 100: O0
 if 19 - 19: Ii1I * iIii1I11I1II1 * Oo0Ooo - i11iIiiIii * i11iIiiIii - OOooOOo
 if 88 - 88: O0 . iIii1I11I1II1 . I1ii11iIi11i
 if 80 - 80: oO0o / i1IIi * iIii1I11I1II1
 if 38 - 38: Ii1I
 if ( lisp_i_am_itr ) :
  lprint ( "Send decap-stats IPC message to lisp-etr process" )
  OOO000OOOO0oO = "stats%{}" . format ( json . dumps ( msg ) )
  OOO000OOOO0oO = lisp_command_ipc ( OOO000OOOO0oO , "lisp-itr" )
  lisp_ipc ( OOO000OOOO0oO , lisp_ipc_socket , "lisp-etr" )
  return
  if 20 - 20: iIii1I11I1II1 + Oo0Ooo - Ii1I / i11iIiiIii . OoO0O00
  if 66 - 66: OoooooooOO - Ii1I / iII111i . I1IiiI + I1ii11iIi11i - I1Ii111
  if 36 - 36: I1Ii111 - OoO0O00 . I1ii11iIi11i * I1ii11iIi11i
  if 9 - 9: OOooOOo - oO0o - iIii1I11I1II1 * i11iIiiIii / I11i
  if 2 - 2: i1IIi % iII111i * ooOoO0o / OoOoOO00 + Oo0Ooo
  if 59 - 59: i11iIiiIii / I1IiiI * iII111i
  if 16 - 16: i11iIiiIii * II111iiii - ooOoO0o
  if 80 - 80: iIii1I11I1II1 + iIii1I11I1II1 + I1Ii111 - IiII * iII111i - Ii1I
 OOO000OOOO0oO = bold ( "IPC" , False )
 lprint ( "Process decap-stats {} message: '{}'" . format ( OOO000OOOO0oO , msg ) )
 if 89 - 89: O0 * ooOoO0o
 if ( lisp_i_am_etr ) : msg = json . loads ( msg )
 if 36 - 36: I1ii11iIi11i * II111iiii * iII111i + I1IiiI + OoO0O00 + oO0o
 I1iiiIi1 = [ "good-packets" , "ICV-error" , "checksum-error" ,
 "lisp-header-error" , "no-decrypt-key" , "bad-inner-version" ,
 "outer-header-error" ]
 if 59 - 59: i11iIiiIii % I1Ii111 % II111iiii * ooOoO0o . OoooooooOO % ooOoO0o
 for ooo0O00o00oo0 in I1iiiIi1 :
  OO0ii11II1II1 = 0 if msg . has_key ( ooo0O00o00oo0 ) == False else msg [ ooo0O00o00oo0 ] [ "packet-count" ]
  if 47 - 47: i11iIiiIii - I11i
  lisp_decap_stats [ ooo0O00o00oo0 ] . packet_count += OO0ii11II1II1
  if 38 - 38: Oo0Ooo % OoooooooOO + iII111i
  o0oOO0OO0000O = 0 if msg . has_key ( ooo0O00o00oo0 ) == False else msg [ ooo0O00o00oo0 ] [ "byte-count" ]
  if 31 - 31: OoO0O00 + I1Ii111 / iIii1I11I1II1
  lisp_decap_stats [ ooo0O00o00oo0 ] . byte_count += o0oOO0OO0000O
  if 11 - 11: ooOoO0o - OoOoOO00
  iiiI = 0 if msg . has_key ( ooo0O00o00oo0 ) == False else msg [ ooo0O00o00oo0 ] [ "seconds-last-packet" ]
  if 19 - 19: O0 . OoOoOO00 - i1IIi . oO0o
  lisp_decap_stats [ ooo0O00o00oo0 ] . last_increment = lisp_get_timestamp ( ) - iiiI
  if 96 - 96: o0oOOo0O0Ooo % o0oOOo0O0Ooo - OoO0O00 * iIii1I11I1II1 + ooOoO0o - ooOoO0o
 return
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
 if 63 - 63: Oo0Ooo * Ii1I - Ii1I
 if 76 - 76: OoO0O00 . IiII % iIii1I11I1II1 / I1IiiI + iIii1I11I1II1 . I1IiiI
 if 57 - 57: IiII - i1IIi * ooOoO0o
 if 5 - 5: oO0o . O0 * IiII / Ii1I + OoO0O00
 if 75 - 75: OOooOOo * OoOoOO00
 if 82 - 82: Ii1I
def lisp_process_punt ( punt_socket , lisp_send_sockets , lisp_ephem_port ) :
 ooOo0O , OOii = punt_socket . recvfrom ( 4000 )
 if 76 - 76: iIii1I11I1II1 * OOooOOo % OoOoOO00 % OoOoOO00 % Ii1I
 iIIiO00o0o = json . loads ( ooOo0O )
 if ( type ( iIIiO00o0o ) != dict ) :
  lprint ( "Invalid punt message from {}, not in JSON format" . format ( OOii ) )
  if 53 - 53: IiII - i1IIi + I1ii11iIi11i
  return
  if 75 - 75: OoooooooOO
 iiIIIi1I1ii = bold ( "Punt" , False )
 lprint ( "{} message from '{}': '{}'" . format ( iiIIIi1I1ii , OOii , iIIiO00o0o ) )
 if 64 - 64: I1ii11iIi11i . I1Ii111
 if ( iIIiO00o0o . has_key ( "type" ) == False ) :
  lprint ( "Punt IPC message has no 'type' key" )
  return
  if 81 - 81: IiII . ooOoO0o + O0 . ooOoO0o + iIii1I11I1II1
  if 68 - 68: i11iIiiIii . iII111i + OoooooooOO + II111iiii + iIii1I11I1II1 % I11i
  if 7 - 7: i1IIi - o0oOOo0O0Ooo - I1IiiI
  if 62 - 62: OoOoOO00 * oO0o - I1IiiI / Ii1I
  if 48 - 48: o0oOOo0O0Ooo % o0oOOo0O0Ooo - OoOoOO00
 if ( iIIiO00o0o [ "type" ] == "statistics" ) :
  lisp_process_data_plane_stats ( iIIiO00o0o , lisp_send_sockets , lisp_ephem_port )
  return
  if 13 - 13: OoO0O00 - Ii1I . ooOoO0o / O0 * OoOoOO00
 if ( iIIiO00o0o [ "type" ] == "decap-statistics" ) :
  lisp_process_data_plane_decap_stats ( iIIiO00o0o , punt_socket )
  return
  if 57 - 57: O0 + OoooooooOO % o0oOOo0O0Ooo / I1Ii111 / OOooOOo - OoOoOO00
  if 48 - 48: o0oOOo0O0Ooo - II111iiii + OoOoOO00
  if 54 - 54: II111iiii - OoO0O00 - o0oOOo0O0Ooo - O0 % I1Ii111
  if 9 - 9: i1IIi % iII111i / Ii1I
  if 83 - 83: oO0o
 if ( iIIiO00o0o [ "type" ] == "restart" ) :
  lisp_process_data_plane_restart ( )
  return
  if 1 - 1: oO0o * iIii1I11I1II1 % iIii1I11I1II1 % iIii1I11I1II1 / oO0o + IiII
  if 29 - 29: OoooooooOO
  if 55 - 55: O0 - o0oOOo0O0Ooo % I1ii11iIi11i * I11i * oO0o
  if 83 - 83: iIii1I11I1II1
  if 92 - 92: OoO0O00 - iII111i
 if ( iIIiO00o0o [ "type" ] != "discovery" ) :
  lprint ( "Punt IPC message has wrong format" )
  return
  if 97 - 97: ooOoO0o / I11i . IiII + I1Ii111 . iIii1I11I1II1
 if ( iIIiO00o0o . has_key ( "interface" ) == False ) :
  lprint ( "Invalid punt message from {}, required keys missing" . format ( OOii ) )
  if 24 - 24: ooOoO0o - oO0o % OoOoOO00 * Oo0Ooo
  return
  if 54 - 54: Ii1I - OoooooooOO % I1IiiI + oO0o
  if 70 - 70: I1Ii111 % iIii1I11I1II1
  if 74 - 74: i1IIi % i11iIiiIii + oO0o
  if 94 - 94: OoO0O00 * I1IiiI / O0 + I1Ii111 / i11iIiiIii
  if 34 - 34: Oo0Ooo . i1IIi
 iiiIiIIIiiiIiI1 = iIIiO00o0o [ "interface" ]
 if ( iiiIiIIIiiiIiI1 == "" ) :
  II1ii1ii11I1 = int ( iIIiO00o0o [ "instance-id" ] )
  if ( II1ii1ii11I1 == - 1 ) : return
 else :
  II1ii1ii11I1 = lisp_get_interface_instance_id ( iiiIiIIIiiiIiI1 , None )
  if 97 - 97: I11i
  if 89 - 89: iII111i % OoOoOO00 . Oo0Ooo
  if 20 - 20: oO0o % OoOoOO00
  if 93 - 93: I1ii11iIi11i - Ii1I % i1IIi / i1IIi
  if 82 - 82: OOooOOo
 I1IIiI = None
 if ( iIIiO00o0o . has_key ( "source-eid" ) ) :
  O0000oOoO0o0 = iIIiO00o0o [ "source-eid" ]
  I1IIiI = lisp_address ( LISP_AFI_NONE , O0000oOoO0o0 , 0 , II1ii1ii11I1 )
  if ( I1IIiI . is_null ( ) ) :
   lprint ( "Invalid source-EID format '{}'" . format ( O0000oOoO0o0 ) )
   return
   if 27 - 27: I1Ii111 / IiII - i1IIi * Ii1I
   if 90 - 90: ooOoO0o
 I1i1 = None
 if ( iIIiO00o0o . has_key ( "dest-eid" ) ) :
  O0ooo0ooOOOO = iIIiO00o0o [ "dest-eid" ]
  I1i1 = lisp_address ( LISP_AFI_NONE , O0ooo0ooOOOO , 0 , II1ii1ii11I1 )
  if ( I1i1 . is_null ( ) ) :
   lprint ( "Invalid dest-EID format '{}'" . format ( O0ooo0ooOOOO ) )
   return
   if 84 - 84: ooOoO0o + OOooOOo * OoO0O00
   if 39 - 39: OoooooooOO * OoooooooOO
   if 49 - 49: o0oOOo0O0Ooo + i1IIi / iII111i
   if 43 - 43: i1IIi . OoO0O00 + I1ii11iIi11i
   if 88 - 88: OoooooooOO / I11i % II111iiii % OOooOOo - I11i
   if 55 - 55: Oo0Ooo - OOooOOo - O0
   if 40 - 40: OoOoOO00 - OOooOOo
   if 3 - 3: IiII % I11i * I1Ii111 + iIii1I11I1II1 . oO0o
 if ( I1IIiI ) :
  ooOoOOOOo = green ( I1IIiI . print_address ( ) , False )
  i1i1iiiii1IiI = lisp_db_for_lookups . lookup_cache ( I1IIiI , False )
  if ( i1i1iiiii1IiI != None ) :
   if 35 - 35: II111iiii
   if 15 - 15: I11i * iIii1I11I1II1 + OOooOOo % IiII . o0oOOo0O0Ooo % Oo0Ooo
   if 96 - 96: O0
   if 15 - 15: i1IIi . iIii1I11I1II1
   if 3 - 3: II111iiii * i11iIiiIii * i1IIi - i1IIi
   if ( i1i1iiiii1IiI . dynamic_eid_configured ( ) ) :
    O0OOoooo0 = lisp_allow_dynamic_eid ( iiiIiIIIiiiIiI1 , I1IIiI )
    if ( O0OOoooo0 != None and lisp_i_am_itr ) :
     lisp_itr_discover_eid ( i1i1iiiii1IiI , I1IIiI , iiiIiIIIiiiIiI1 , O0OOoooo0 )
    else :
     lprint ( ( "Disallow dynamic source-EID {} " + "on interface {}" ) . format ( ooOoOOOOo , iiiIiIIIiiiIiI1 ) )
     if 11 - 11: I1IiiI % Ii1I * i11iIiiIii % OOooOOo + II111iiii
     if 61 - 61: I1Ii111 + I11i + I1IiiI
     if 48 - 48: I11i
  else :
   lprint ( "Punt from non-EID source {}" . format ( ooOoOOOOo ) )
   if 67 - 67: o0oOOo0O0Ooo
   if 36 - 36: IiII - I11i - Ii1I / OoOoOO00 % OoO0O00 * iIii1I11I1II1
   if 61 - 61: i11iIiiIii / Ii1I - OOooOOo . I1ii11iIi11i
   if 89 - 89: ooOoO0o % i11iIiiIii
   if 57 - 57: Oo0Ooo / ooOoO0o - O0 . ooOoO0o
   if 61 - 61: o0oOOo0O0Ooo / OoooooooOO . I1ii11iIi11i + Oo0Ooo
 if ( I1i1 ) :
  OoOOO000O0o = lisp_map_cache_lookup ( I1IIiI , I1i1 )
  if ( OoOOO000O0o == None or OoOOO000O0o . action == LISP_SEND_MAP_REQUEST_ACTION ) :
   if 75 - 75: Ii1I
   if 79 - 79: i1IIi . I1ii11iIi11i * o0oOOo0O0Ooo / I11i . I11i / ooOoO0o
   if 99 - 99: oO0o + I11i % i1IIi . iII111i
   if 58 - 58: Oo0Ooo % i11iIiiIii . Oo0Ooo / Oo0Ooo - I1IiiI . Ii1I
   if 65 - 65: OoO0O00
   if ( lisp_rate_limit_map_request ( I1IIiI , I1i1 ) ) : return
   lisp_send_map_request ( lisp_send_sockets , lisp_ephem_port ,
 I1IIiI , I1i1 , None )
  else :
   ooOoOOOOo = green ( I1i1 . print_address ( ) , False )
   lprint ( "Map-cache entry for {} already exists" . format ( ooOoOOOOo ) )
   if 16 - 16: IiII % I1IiiI % iIii1I11I1II1 . I1IiiI . I1ii11iIi11i - IiII
   if 6 - 6: I1Ii111 + OoO0O00 + O0 * OoOoOO00 . iIii1I11I1II1 . I1Ii111
 return
 if 93 - 93: ooOoO0o % iIii1I11I1II1 + I1ii11iIi11i
 if 74 - 74: OoOoOO00 + I1ii11iIi11i
 if 82 - 82: II111iiii
 if 55 - 55: I11i . iIii1I11I1II1 / Ii1I - OoO0O00 * I1ii11iIi11i % iIii1I11I1II1
 if 48 - 48: ooOoO0o + Oo0Ooo / Oo0Ooo
 if 15 - 15: iIii1I11I1II1 . I1Ii111 * OoooooooOO * O0 % OOooOOo
 if 53 - 53: Ii1I
def lisp_ipc_map_cache_entry ( mc , jdata ) :
 iiIiiIi = lisp_write_ipc_map_cache ( True , mc , dont_send = True )
 jdata . append ( iiIiiIi )
 return ( [ True , jdata ] )
 if 63 - 63: I11i % OoOoOO00
 if 46 - 46: iIii1I11I1II1 . II111iiii / OoooooooOO - ooOoO0o * iII111i
 if 52 - 52: I11i + iII111i
 if 9 - 9: OoOoOO00 % II111iiii . I11i * Oo0Ooo
 if 53 - 53: II111iiii / i1IIi + OoooooooOO * O0
 if 62 - 62: IiII . O0
 if 87 - 87: I1ii11iIi11i / oO0o / IiII . OOooOOo
 if 91 - 91: OOooOOo % oO0o . OoOoOO00 . I1IiiI - OoOoOO00
def lisp_ipc_walk_map_cache ( mc , jdata ) :
 if 18 - 18: O0 - I1IiiI + i1IIi % i11iIiiIii
 if 97 - 97: iII111i * OoooooooOO + I1Ii111 + ooOoO0o - ooOoO0o
 if 63 - 63: o0oOOo0O0Ooo * OOooOOo + iIii1I11I1II1 + Oo0Ooo
 if 25 - 25: oO0o + IiII % o0oOOo0O0Ooo
 if ( mc . group . is_null ( ) ) : return ( lisp_ipc_map_cache_entry ( mc , jdata ) )
 if 24 - 24: OoOoOO00
 if ( mc . source_cache == None ) : return ( [ True , jdata ] )
 if 87 - 87: I1ii11iIi11i / ooOoO0o * i1IIi
 if 71 - 71: OoOoOO00 - I11i
 if 83 - 83: oO0o + oO0o - Oo0Ooo . Oo0Ooo - iII111i . OOooOOo
 if 56 - 56: OoOoOO00 * IiII + i1IIi
 if 40 - 40: I1ii11iIi11i / O0
 jdata = mc . source_cache . walk_cache ( lisp_ipc_map_cache_entry , jdata )
 return ( [ True , jdata ] )
 if 87 - 87: ooOoO0o
 if 100 - 100: iII111i + II111iiii * Oo0Ooo * OOooOOo
 if 6 - 6: IiII % OOooOOo
 if 3 - 3: OoOoOO00 / OoOoOO00 - II111iiii
 if 41 - 41: oO0o
 if 12 - 12: I1IiiI + I1Ii111
 if 66 - 66: I1Ii111 + OOooOOo + I1Ii111 . OoooooooOO * oO0o / OoO0O00
def lisp_itr_discover_eid ( db , eid , input_interface , routed_interface ,
 lisp_ipc_listen_socket ) :
 O0o0O0OO0o = eid . print_address ( )
 if ( db . dynamic_eids . has_key ( O0o0O0OO0o ) ) :
  db . dynamic_eids [ O0o0O0OO0o ] . last_packet = lisp_get_timestamp ( )
  return
  if 74 - 74: O0 % OOooOOo * OoOoOO00 / oO0o - Oo0Ooo
  if 79 - 79: Ii1I + IiII
  if 21 - 21: o0oOOo0O0Ooo * iII111i * o0oOOo0O0Ooo * o0oOOo0O0Ooo . Oo0Ooo
  if 98 - 98: I1ii11iIi11i
  if 58 - 58: IiII / i11iIiiIii % I11i
 i11IiII = lisp_dynamic_eid ( )
 i11IiII . dynamic_eid . copy_address ( eid )
 i11IiII . interface = routed_interface
 i11IiII . last_packet = lisp_get_timestamp ( )
 i11IiII . get_timeout ( routed_interface )
 db . dynamic_eids [ O0o0O0OO0o ] = i11IiII
 if 74 - 74: OoooooooOO - I1ii11iIi11i + OOooOOo % IiII . o0oOOo0O0Ooo
 i11i1iiI1i1 = ""
 if ( input_interface != routed_interface ) :
  i11i1iiI1i1 = ", routed-interface " + routed_interface
  if 100 - 100: I11i - O0 * Oo0Ooo * Ii1I
  if 86 - 86: OoOoOO00
 i1111i = green ( O0o0O0OO0o , False ) + bold ( " discovered" , False )
 lprint ( "Dynamic-EID {} on interface {}{}, timeout {}" . format ( i1111i , input_interface , i11i1iiI1i1 , i11IiII . timeout ) )
 if 54 - 54: I1ii11iIi11i - IiII . OoO0O00 + I1ii11iIi11i / I1IiiI
 if 91 - 91: OOooOOo % Oo0Ooo
 if 44 - 44: iIii1I11I1II1 . OOooOOo
 if 57 - 57: II111iiii + I1Ii111
 if 42 - 42: OoOoOO00 % O0
 OOO000OOOO0oO = "learn%{}%{}" . format ( O0o0O0OO0o , routed_interface )
 OOO000OOOO0oO = lisp_command_ipc ( OOO000OOOO0oO , "lisp-itr" )
 lisp_ipc ( OOO000OOOO0oO , lisp_ipc_listen_socket , "lisp-etr" )
 return
 if 70 - 70: iIii1I11I1II1 * Oo0Ooo - I1IiiI / OoO0O00 + OoOoOO00
 if 94 - 94: OoooooooOO + O0 * iIii1I11I1II1 * II111iiii
 if 90 - 90: I11i + O0 / I1IiiI . oO0o / O0
 if 46 - 46: O0 . O0 - oO0o . II111iiii * I1IiiI * Ii1I
 if 10 - 10: i1IIi + i1IIi . i1IIi - I1IiiI - I1IiiI
 if 26 - 26: Ii1I * I11i / I11i
 if 79 - 79: ooOoO0o / oO0o - oO0o / OoooooooOO
 if 91 - 91: iIii1I11I1II1 - O0 * o0oOOo0O0Ooo * o0oOOo0O0Ooo . II111iiii
 if 69 - 69: II111iiii - Oo0Ooo + i1IIi . II111iiii + o0oOOo0O0Ooo
 if 20 - 20: OoooooooOO - OoO0O00 * ooOoO0o * OoOoOO00 / OOooOOo
 if 64 - 64: O0 + iII111i / I11i * OoOoOO00 + o0oOOo0O0Ooo + I1Ii111
 if 16 - 16: I11i
 if 9 - 9: Ii1I / IiII * I11i - i11iIiiIii * I1ii11iIi11i / iII111i
def lisp_retry_decap_keys ( addr_str , packet , iv , packet_icv ) :
 if ( lisp_search_decap_keys == False ) : return
 if 61 - 61: O0 % iII111i
 if 41 - 41: I1Ii111 * OoooooooOO
 if 76 - 76: OoooooooOO * II111iiii . II111iiii / o0oOOo0O0Ooo - iII111i
 if 49 - 49: O0 . I1ii11iIi11i . OoOoOO00 . I1Ii111 % O0 . iIii1I11I1II1
 if ( addr_str . find ( ":" ) != - 1 ) : return
 if 19 - 19: iIii1I11I1II1
 o0OoOOO = lisp_crypto_keys_by_rloc_decap [ addr_str ]
 if 97 - 97: Ii1I . I11i / ooOoO0o + Oo0Ooo
 for OOO0OOoOOO in lisp_crypto_keys_by_rloc_decap :
  if 100 - 100: iII111i / I1Ii111 % OoOoOO00 . O0 / OoOoOO00
  if 81 - 81: OoO0O00 % i11iIiiIii / OoO0O00 + ooOoO0o
  if 100 - 100: O0 . Oo0Ooo % Oo0Ooo % O0 / i11iIiiIii
  if 56 - 56: IiII - OOooOOo - OoOoOO00 - I11i
  if ( OOO0OOoOOO . find ( addr_str ) == - 1 ) : continue
  if 57 - 57: i1IIi
  if 41 - 41: I11i / Ii1I
  if 1 - 1: II111iiii / iII111i
  if 83 - 83: OoO0O00 / iII111i
  if ( OOO0OOoOOO == addr_str ) : continue
  if 59 - 59: I1Ii111 % OOooOOo . I1IiiI + I1ii11iIi11i % oO0o
  if 96 - 96: OoO0O00
  if 53 - 53: oO0o + OoO0O00
  if 58 - 58: iIii1I11I1II1 + OoOoOO00
  iiIiiIi = lisp_crypto_keys_by_rloc_decap [ OOO0OOoOOO ]
  if ( iiIiiIi == o0OoOOO ) : continue
  if 65 - 65: iII111i % Oo0Ooo * iIii1I11I1II1 + I1IiiI + II111iiii
  if 72 - 72: OoOoOO00 . OoooooooOO - OOooOOo
  if 15 - 15: OoOoOO00
  if 13 - 13: I1ii11iIi11i - OOooOOo - i11iIiiIii / IiII
  o0O00OOo0oOO = iiIiiIi [ 1 ]
  if ( packet_icv != o0O00OOo0oOO . do_icv ( packet , iv ) ) :
   lprint ( "Test ICV with key {} failed" . format ( red ( OOO0OOoOOO , False ) ) )
   continue
   if 63 - 63: o0oOOo0O0Ooo - o0oOOo0O0Ooo % o0oOOo0O0Ooo / I11i - o0oOOo0O0Ooo
   if 52 - 52: IiII + OoO0O00 . I1Ii111 - iII111i
  lprint ( "Changing decap crypto key to {}" . format ( red ( OOO0OOoOOO , False ) ) )
  lisp_crypto_keys_by_rloc_decap [ addr_str ] = iiIiiIi
  if 67 - 67: I1IiiI % I1IiiI / O0 % Oo0Ooo * O0 + i1IIi
 return
 if 65 - 65: I1Ii111 - o0oOOo0O0Ooo . Oo0Ooo . i1IIi / IiII . O0
 if 72 - 72: OOooOOo
 if 20 - 20: i11iIiiIii + Oo0Ooo * Oo0Ooo % OOooOOo
 if 66 - 66: I1ii11iIi11i + iII111i / Ii1I / I1IiiI * i11iIiiIii
 if 41 - 41: Ii1I / Oo0Ooo . OoO0O00 . iIii1I11I1II1 % IiII . I11i
 if 59 - 59: O0 + II111iiii + IiII % Oo0Ooo
 if 71 - 71: oO0o
 if 75 - 75: Oo0Ooo * oO0o + iIii1I11I1II1 / Oo0Ooo
def lisp_decent_pull_xtr_configured ( ) :
 return ( lisp_decent_modulus != 0 and lisp_decent_dns_suffix != None )
 if 51 - 51: Ii1I * Ii1I + iII111i * oO0o / OOooOOo - ooOoO0o
 if 16 - 16: I1Ii111 + O0 - O0 * iIii1I11I1II1 / iII111i
 if 4 - 4: iII111i
 if 75 - 75: I1IiiI * IiII % OoO0O00 - ooOoO0o * iII111i
 if 32 - 32: iII111i
 if 59 - 59: OoOoOO00 - I1Ii111
 if 34 - 34: ooOoO0o . OoooooooOO / ooOoO0o + OoooooooOO
 if 24 - 24: OoooooooOO * I1ii11iIi11i / O0 / Oo0Ooo * I1IiiI / ooOoO0o
def lisp_is_decent_dns_suffix ( dns_name ) :
 if ( lisp_decent_dns_suffix == None ) : return ( False )
 I1i1iI1II = dns_name . split ( "." )
 I1i1iI1II = "." . join ( I1i1iI1II [ 1 : : ] )
 return ( I1i1iI1II == lisp_decent_dns_suffix )
 if 33 - 33: Ii1I
 if 20 - 20: Ii1I + I11i
 if 98 - 98: OOooOOo
 if 58 - 58: i11iIiiIii / OoOoOO00
 if 18 - 18: ooOoO0o + O0 - OOooOOo + iIii1I11I1II1 . OOooOOo * iIii1I11I1II1
 if 83 - 83: OoO0O00 - Oo0Ooo * I1IiiI % Oo0Ooo % oO0o
 if 64 - 64: OoOoOO00 + oO0o / OoooooooOO . i11iIiiIii / II111iiii
def lisp_get_decent_index ( eid ) :
 O0o0O0OO0o = eid . print_prefix ( )
 o0o = hashlib . sha256 ( O0o0O0OO0o ) . hexdigest ( )
 Oo0oOooo000OO = int ( o0o , 16 ) % lisp_decent_modulus
 return ( Oo0oOooo000OO )
 if 3 - 3: oO0o - IiII . oO0o + Ii1I
 if 2 - 2: o0oOOo0O0Ooo + i1IIi - I1IiiI / IiII - i1IIi + iIii1I11I1II1
 if 89 - 89: IiII . oO0o . IiII
 if 70 - 70: O0 * I1Ii111 * O0
 if 27 - 27: iIii1I11I1II1 * OOooOOo . I1Ii111 / OoooooooOO % O0 - I1ii11iIi11i
 if 49 - 49: OoooooooOO . I1ii11iIi11i / OoooooooOO * oO0o
 if 81 - 81: I1ii11iIi11i . ooOoO0o + I1ii11iIi11i
def lisp_get_decent_dns_name ( eid ) :
 Oo0oOooo000OO = lisp_get_decent_index ( eid )
 return ( str ( Oo0oOooo000OO ) + "." + lisp_decent_dns_suffix )
 if 84 - 84: OoooooooOO
 if 95 - 95: o0oOOo0O0Ooo
 if 22 - 22: ooOoO0o / o0oOOo0O0Ooo - OoooooooOO / Oo0Ooo - I1Ii111 / OOooOOo
 if 41 - 41: oO0o . II111iiii
 if 47 - 47: I1ii11iIi11i
 if 5 - 5: Oo0Ooo
 if 23 - 23: i11iIiiIii / I11i + i1IIi % I1Ii111
 if 100 - 100: Oo0Ooo
def lisp_get_decent_dns_name_from_str ( iid , eid_str ) :
 ii1Ii = lisp_address ( LISP_AFI_NONE , eid_str , 0 , iid )
 Oo0oOooo000OO = lisp_get_decent_index ( ii1Ii )
 return ( str ( Oo0oOooo000OO ) + "." + lisp_decent_dns_suffix )
 if 13 - 13: I1IiiI + ooOoO0o * II111iiii
 if 32 - 32: iIii1I11I1II1 + O0 + i1IIi
 if 28 - 28: IiII + I11i
 if 1 - 1: OoooooooOO - i11iIiiIii . OoooooooOO - o0oOOo0O0Ooo - OOooOOo * I1Ii111
 if 56 - 56: Ii1I . OoO0O00
 if 43 - 43: iII111i * iII111i
 if 31 - 31: O0 - iIii1I11I1II1 . I11i . oO0o
 if 96 - 96: OoooooooOO * iIii1I11I1II1 * Oo0Ooo
 if 76 - 76: OoO0O00 / i11iIiiIii % ooOoO0o % I11i * O0
 if 84 - 84: II111iiii - iII111i / IiII . O0 % i1IIi / I1ii11iIi11i
def lisp_trace_append ( packet , reason = None , ed = "encap" , lisp_socket = None ,
 rloc_entry = None ) :
 if 2 - 2: OoooooooOO . OoO0O00 . II111iiii / Ii1I - OOooOOo % Oo0Ooo
 I1 = 28 if packet . inner_version == 4 else 48
 iIIIi1iiii11 = packet . packet [ I1 : : ]
 oo0000O0 = lisp_trace ( )
 if ( oo0000O0 . decode ( iIIIi1iiii11 ) == False ) :
  lprint ( "Could not decode JSON portion of a LISP-Trace packet" )
  return ( False )
  if 46 - 46: OoOoOO00 % I11i - iIii1I11I1II1 % Oo0Ooo
  if 48 - 48: o0oOOo0O0Ooo / II111iiii / OoOoOO00 * o0oOOo0O0Ooo + I1IiiI . OoOoOO00
 O0oOO0o = "?" if packet . outer_dest . is_null ( ) else packet . outer_dest . print_address_no_iid ( )
 if 6 - 6: i1IIi . oO0o % IiII . Oo0Ooo % I11i
 if 86 - 86: OoooooooOO + IiII % o0oOOo0O0Ooo . i1IIi . iII111i
 if 25 - 25: iII111i * I1ii11iIi11i + I11i - I1ii11iIi11i
 if 75 - 75: IiII
 if 74 - 74: o0oOOo0O0Ooo - iIii1I11I1II1
 if 92 - 92: i11iIiiIii * iIii1I11I1II1 - I1Ii111 . i1IIi
 if ( O0oOO0o != "?" and packet . encap_port != LISP_DATA_PORT ) :
  if ( ed == "encap" ) : O0oOO0o += ":{}" . format ( packet . encap_port )
  if 23 - 23: O0 - O0 . I1Ii111 . I1IiiI - I1IiiI * i1IIi
  if 8 - 8: I1IiiI . I1ii11iIi11i + oO0o % oO0o * oO0o
  if 70 - 70: II111iiii + IiII + O0 / Ii1I - i11iIiiIii
  if 72 - 72: II111iiii - II111iiii
  if 44 - 44: o0oOOo0O0Ooo + OoooooooOO
 iiIiiIi = { }
 iiIiiIi [ "node" ] = "ITR" if lisp_i_am_itr else "ETR" if lisp_i_am_etr else "RTR" if lisp_i_am_rtr else "?"
 if 34 - 34: i11iIiiIii + iIii1I11I1II1 - i11iIiiIii * o0oOOo0O0Ooo - iII111i
 o0OO0O0oo00oo = packet . outer_source
 if ( o0OO0O0oo00oo . is_null ( ) ) : o0OO0O0oo00oo = lisp_myrlocs [ 0 ]
 iiIiiIi [ "srloc" ] = o0OO0O0oo00oo . print_address_no_iid ( )
 if 75 - 75: II111iiii . I11i * o0oOOo0O0Ooo % Ii1I * Ii1I % II111iiii
 if 36 - 36: o0oOOo0O0Ooo + Oo0Ooo . II111iiii / oO0o
 if 28 - 28: iIii1I11I1II1 * Ii1I
 if 45 - 45: I1ii11iIi11i + Oo0Ooo
 if 72 - 72: I1ii11iIi11i
 if ( iiIiiIi [ "node" ] == "ITR" and packet . inner_sport != LISP_TRACE_PORT ) :
  iiIiiIi [ "srloc" ] += ":{}" . format ( packet . inner_sport )
  if 5 - 5: i1IIi
  if 31 - 31: iII111i - OoooooooOO + oO0o / OoooooooOO + I1ii11iIi11i
 iiIiiIi [ "hn" ] = lisp_hostname
 OOO0OOoOOO = ed + "-ts"
 iiIiiIi [ OOO0OOoOOO ] = lisp_get_timestamp ( )
 if 93 - 93: o0oOOo0O0Ooo * I1ii11iIi11i % I1IiiI * ooOoO0o
 if 37 - 37: OoO0O00 * OoooooooOO / oO0o * I11i * I1ii11iIi11i
 if 42 - 42: OoooooooOO - ooOoO0o . OOooOOo + OoOoOO00
 if 53 - 53: o0oOOo0O0Ooo
 if 55 - 55: ooOoO0o . i1IIi - ooOoO0o + O0 + I1IiiI
 if 31 - 31: OoO0O00 % I1Ii111
 if ( O0oOO0o == "?" and iiIiiIi [ "node" ] == "ETR" ) :
  i1i1iiiii1IiI = lisp_db_for_lookups . lookup_cache ( packet . inner_dest , False )
  if ( i1i1iiiii1IiI != None and len ( i1i1iiiii1IiI . rloc_set ) >= 1 ) :
   O0oOO0o = i1i1iiiii1IiI . rloc_set [ 0 ] . rloc . print_address_no_iid ( )
   if 62 - 62: oO0o / O0 - I1Ii111 . IiII
   if 81 - 81: i11iIiiIii
 iiIiiIi [ "drloc" ] = O0oOO0o
 if 57 - 57: O0
 if 85 - 85: i11iIiiIii - i11iIiiIii - OoOoOO00 / II111iiii - II111iiii
 if 4 - 4: I1ii11iIi11i * O0 / OoO0O00 * II111iiii . iIii1I11I1II1 / OOooOOo
 if 97 - 97: i1IIi - OoOoOO00 . OoooooooOO
 if ( O0oOO0o == "?" and reason != None ) :
  iiIiiIi [ "drloc" ] += " ({})" . format ( reason )
  if 24 - 24: iIii1I11I1II1 + OOooOOo * iII111i % IiII % OOooOOo
  if 64 - 64: IiII . I1ii11iIi11i - o0oOOo0O0Ooo - ooOoO0o + OoooooooOO
  if 95 - 95: iII111i . I1ii11iIi11i + ooOoO0o + o0oOOo0O0Ooo % OoO0O00
  if 50 - 50: iII111i * O0 % II111iiii
  if 80 - 80: OOooOOo - II111iiii - OoO0O00
 if ( rloc_entry != None ) :
  iiIiiIi [ "rtts" ] = rloc_entry . recent_rloc_probe_rtts
  iiIiiIi [ "hops" ] = rloc_entry . recent_rloc_probe_hops
  if 62 - 62: Ii1I . i11iIiiIii % OOooOOo
  if 44 - 44: i1IIi * I1ii11iIi11i % Ii1I . Ii1I * I11i + II111iiii
  if 15 - 15: i1IIi - I11i - I1Ii111 / OoO0O00 + Oo0Ooo + I1IiiI
  if 81 - 81: IiII
  if 54 - 54: I1IiiI % OoO0O00 % OoOoOO00
  if 12 - 12: II111iiii . O0 * i11iIiiIii . I11i
 I1IIiI = packet . inner_source . print_address ( )
 I1i1 = packet . inner_dest . print_address ( )
 if ( oo0000O0 . packet_json == [ ] ) :
  I1O0OOOoOOOO0 = { }
  I1O0OOOoOOOO0 [ "seid" ] = I1IIiI
  I1O0OOOoOOOO0 [ "deid" ] = I1i1
  I1O0OOOoOOOO0 [ "paths" ] = [ ]
  oo0000O0 . packet_json . append ( I1O0OOOoOOOO0 )
  if 98 - 98: II111iiii + i1IIi * oO0o % I1IiiI
  if 53 - 53: i11iIiiIii . I1ii11iIi11i - OOooOOo - OOooOOo
  if 97 - 97: I1IiiI % iII111i % OoooooooOO / ooOoO0o / i11iIiiIii
  if 7 - 7: O0 % IiII / o0oOOo0O0Ooo
  if 79 - 79: IiII + I1Ii111
  if 59 - 59: iII111i - oO0o . ooOoO0o / IiII * i11iIiiIii
 for I1O0OOOoOOOO0 in oo0000O0 . packet_json :
  if ( I1O0OOOoOOOO0 [ "deid" ] != I1i1 ) : continue
  I1O0OOOoOOOO0 [ "paths" ] . append ( iiIiiIi )
  break
  if 61 - 61: I11i - Oo0Ooo * II111iiii + iIii1I11I1II1
  if 37 - 37: OoooooooOO % II111iiii / o0oOOo0O0Ooo . OOooOOo * I1ii11iIi11i . iIii1I11I1II1
  if 73 - 73: OoOoOO00
  if 44 - 44: Oo0Ooo / oO0o
  if 9 - 9: i1IIi % I1IiiI + OoO0O00 * ooOoO0o / iIii1I11I1II1 / iII111i
  if 80 - 80: OOooOOo / O0 % IiII * OoOoOO00
  if 53 - 53: OOooOOo + i11iIiiIii
  if 25 - 25: i11iIiiIii
 o00O0Oo = False
 if ( len ( oo0000O0 . packet_json ) == 1 and iiIiiIi [ "node" ] == "ETR" and
 oo0000O0 . myeid ( packet . inner_dest ) ) :
  I1O0OOOoOOOO0 = { }
  I1O0OOOoOOOO0 [ "seid" ] = I1i1
  I1O0OOOoOOOO0 [ "deid" ] = I1IIiI
  I1O0OOOoOOOO0 [ "paths" ] = [ ]
  oo0000O0 . packet_json . append ( I1O0OOOoOOOO0 )
  o00O0Oo = True
  if 43 - 43: o0oOOo0O0Ooo . ooOoO0o . O0 - OoOoOO00 + I11i
  if 57 - 57: OoO0O00 * IiII
  if 18 - 18: iII111i + I1Ii111
  if 1 - 1: OoooooooOO % OoooooooOO * I1ii11iIi11i
  if 24 - 24: I1Ii111 % I1Ii111 % iIii1I11I1II1
  if 29 - 29: i1IIi % i1IIi - II111iiii
 oo0000O0 . print_trace ( )
 iIIIi1iiii11 = oo0000O0 . encode ( )
 if 44 - 44: II111iiii . Oo0Ooo - o0oOOo0O0Ooo
 if 45 - 45: ooOoO0o - oO0o - I1IiiI
 if 21 - 21: OoooooooOO
 if 28 - 28: I1ii11iIi11i + oO0o . Oo0Ooo % iIii1I11I1II1 / I1Ii111
 if 8 - 8: O0 . I1IiiI * o0oOOo0O0Ooo + I1IiiI
 if 44 - 44: i1IIi % iII111i . i11iIiiIii / I11i + OoooooooOO
 if 21 - 21: OoOoOO00 . OoO0O00 . OoOoOO00 + OoOoOO00
 if 30 - 30: I1IiiI - iII111i - OOooOOo + oO0o
 O0ooooO000 = oo0000O0 . packet_json [ 0 ] [ "paths" ] [ 0 ] [ "srloc" ]
 if ( O0oOO0o == "?" ) :
  lprint ( "LISP-Trace return to sender RLOC {}" . format ( O0ooooO000 ) )
  oo0000O0 . return_to_sender ( lisp_socket , O0ooooO000 , iIIIi1iiii11 )
  return ( False )
  if 4 - 4: O0 / I1IiiI . i11iIiiIii - OOooOOo + Ii1I
  if 9 - 9: O0 * I1ii11iIi11i / I1Ii111
  if 70 - 70: i1IIi
  if 69 - 69: IiII + I1Ii111 * O0 . iII111i + OoO0O00 * I1Ii111
  if 31 - 31: oO0o % OoooooooOO . o0oOOo0O0Ooo . iII111i % I11i % iIii1I11I1II1
  if 93 - 93: ooOoO0o * o0oOOo0O0Ooo / I11i * iII111i + OoooooooOO
 oOo0 = oo0000O0 . packet_length ( )
 if 89 - 89: ooOoO0o * OOooOOo * i11iIiiIii * OoOoOO00 * II111iiii - iII111i
 if 65 - 65: Ii1I . I1ii11iIi11i / I1ii11iIi11i - O0
 if 74 - 74: o0oOOo0O0Ooo + IiII
 if 42 - 42: o0oOOo0O0Ooo . OOooOOo % I11i - OoOoOO00
 if 38 - 38: OoooooooOO
 if 27 - 27: O0 + I1ii11iIi11i % Ii1I . i1IIi + OoO0O00 + OoOoOO00
 IiIi1 = packet . packet [ 0 : I1 ]
 IiIiI1 = struct . pack ( "HH" , socket . htons ( oOo0 ) , 0 )
 IiIi1 = IiIi1 [ 0 : I1 - 4 ] + IiIiI1
 if ( packet . inner_version == 6 and iiIiiIi [ "node" ] == "ETR" and
 len ( oo0000O0 . packet_json ) == 2 ) :
  IiI1iiI11 = IiIi1 [ I1 - 8 : : ] + iIIIi1iiii11
  IiI1iiI11 = lisp_udp_checksum ( I1IIiI , I1i1 , IiI1iiI11 )
  IiIi1 = IiIi1 [ 0 : I1 - 8 ] + IiI1iiI11 [ 0 : 8 ]
  if 52 - 52: I1IiiI
  if 93 - 93: OOooOOo
  if 49 - 49: I1ii11iIi11i * I1IiiI + OOooOOo + i11iIiiIii * I1ii11iIi11i . o0oOOo0O0Ooo
  if 36 - 36: o0oOOo0O0Ooo - i11iIiiIii
  if 37 - 37: O0 + IiII + I1IiiI
  if 50 - 50: OoooooooOO . I1Ii111
 if ( o00O0Oo ) :
  if ( packet . inner_version == 4 ) :
   IiIi1 = IiIi1 [ 0 : 12 ] + IiIi1 [ 16 : 20 ] + IiIi1 [ 12 : 16 ] + IiIi1 [ 22 : 24 ] + IiIi1 [ 20 : 22 ] + IiIi1 [ 24 : : ]
   if 100 - 100: ooOoO0o * ooOoO0o - Ii1I
  else :
   IiIi1 = IiIi1 [ 0 : 8 ] + IiIi1 [ 24 : 40 ] + IiIi1 [ 8 : 24 ] + IiIi1 [ 42 : 44 ] + IiIi1 [ 40 : 42 ] + IiIi1 [ 44 : : ]
   if 13 - 13: iII111i . I11i * OoO0O00 . i1IIi . iIii1I11I1II1 - o0oOOo0O0Ooo
   if 68 - 68: Ii1I % o0oOOo0O0Ooo / OoooooooOO + Ii1I - Ii1I
  OooOo = packet . inner_dest
  packet . inner_dest = packet . inner_source
  packet . inner_source = OooOo
  if 79 - 79: II111iiii / IiII
  if 4 - 4: O0 - i11iIiiIii % ooOoO0o * O0 - ooOoO0o
  if 96 - 96: oO0o % II111iiii . Ii1I % OoO0O00 . iIii1I11I1II1 / IiII
  if 96 - 96: o0oOOo0O0Ooo / O0 . iIii1I11I1II1 . Ii1I % OOooOOo % II111iiii
  if 5 - 5: OoooooooOO / I1Ii111 % I1Ii111 / I1IiiI
 I1 = 2 if packet . inner_version == 4 else 4
 Ii11I11I = 20 + oOo0 if packet . inner_version == 4 else oOo0
 ooo00o0oo = struct . pack ( "H" , socket . htons ( Ii11I11I ) )
 IiIi1 = IiIi1 [ 0 : I1 ] + ooo00o0oo + IiIi1 [ I1 + 2 : : ]
 if 45 - 45: OoO0O00 - i1IIi . OoO0O00 * I1ii11iIi11i / OoOoOO00
 if 88 - 88: II111iiii * IiII . Oo0Ooo + I1Ii111
 if 75 - 75: Ii1I - OoOoOO00 + OoO0O00 + IiII * iIii1I11I1II1 % I1Ii111
 if 23 - 23: O0 % I1ii11iIi11i % iIii1I11I1II1
 if ( packet . inner_version == 4 ) :
  iII = struct . pack ( "H" , 0 )
  IiIi1 = IiIi1 [ 0 : 10 ] + iII + IiIi1 [ 12 : : ]
  ooo00o0oo = lisp_ip_checksum ( IiIi1 [ 0 : 20 ] )
  IiIi1 = ooo00o0oo + IiIi1 [ 20 : : ]
  if 49 - 49: iII111i + I1Ii111 % OoOoOO00
  if 67 - 67: Ii1I
  if 27 - 27: Oo0Ooo / i11iIiiIii / II111iiii . Ii1I - II111iiii / OoO0O00
  if 61 - 61: ooOoO0o - OOooOOo
  if 45 - 45: O0 . OoO0O00
 packet . packet = IiIi1 + iIIIi1iiii11
 return ( True )
 if 80 - 80: IiII + OoO0O00
 if 2 - 2: IiII + OoOoOO00 % oO0o
 if 76 - 76: o0oOOo0O0Ooo
 if 25 - 25: OoooooooOO
 if 78 - 78: oO0o / i11iIiiIii * O0 / OOooOOo % i11iIiiIii % O0
 if 86 - 86: IiII
 if 26 - 26: IiII - I1Ii111 + i11iIiiIii % ooOoO0o * i11iIiiIii + Oo0Ooo
 if 39 - 39: Ii1I - i1IIi + i11iIiiIii
 if 21 - 21: IiII
 if 76 - 76: o0oOOo0O0Ooo % Oo0Ooo + OoO0O00
def lisp_allow_gleaning ( eid , group , rloc ) :
 if ( lisp_glean_mappings == [ ] ) : return ( False , False )
 if 36 - 36: OOooOOo . oO0o
 for iiIiiIi in lisp_glean_mappings :
  if ( iiIiiIi . has_key ( "instance-id" ) ) :
   II1ii1ii11I1 = eid . instance_id
   IiIIIIi1 , ii1iiII = iiIiiIi [ "instance-id" ]
   if ( II1ii1ii11I1 < IiIIIIi1 or II1ii1ii11I1 > ii1iiII ) : continue
   if 15 - 15: I1IiiI + ooOoO0o - o0oOOo0O0Ooo
  if ( iiIiiIi . has_key ( "eid-prefix" ) ) :
   ooOoOOOOo = copy . deepcopy ( iiIiiIi [ "eid-prefix" ] )
   ooOoOOOOo . instance_id = eid . instance_id
   if ( eid . is_more_specific ( ooOoOOOOo ) == False ) : continue
   if 62 - 62: Ii1I - OOooOOo
  if ( iiIiiIi . has_key ( "group-prefix" ) ) :
   if ( group == None ) : continue
   IiIoO0oo0 = copy . deepcopy ( iiIiiIi [ "group-prefix" ] )
   IiIoO0oo0 . instance_id = group . instance_id
   if ( group . is_more_specific ( IiIoO0oo0 ) == False ) : continue
   if 88 - 88: iIii1I11I1II1 * Oo0Ooo / II111iiii / IiII / OoO0O00 % ooOoO0o
  if ( iiIiiIi . has_key ( "rloc-prefix" ) ) :
   if ( rloc != None and rloc . is_more_specific ( iiIiiIi [ "rloc-prefix" ] )
 == False ) : continue
   if 19 - 19: I11i * iII111i . O0 * iII111i % I1ii11iIi11i - OoOoOO00
  return ( True , iiIiiIi [ "rloc-probe" ] )
  if 68 - 68: I1Ii111 - OoO0O00 % Ii1I + i1IIi . ooOoO0o
 return ( False , False )
 if 36 - 36: oO0o * iIii1I11I1II1 - O0 - IiII * O0 + i11iIiiIii
 if 76 - 76: OoO0O00 % O0 / Ii1I + I1IiiI
 if 23 - 23: I1IiiI % IiII . o0oOOo0O0Ooo
 if 2 - 2: I1ii11iIi11i
 if 51 - 51: iIii1I11I1II1 / II111iiii / iIii1I11I1II1 / oO0o % i1IIi
 if 54 - 54: ooOoO0o
 if 47 - 47: I11i * I1IiiI / oO0o
def lisp_build_gleaned_multicast ( seid , geid , rloc , port ) :
 ooOoOOOOo = green ( "(*, {})" . format ( geid . print_address ( ) ) , False )
 oooO0 = red ( rloc . print_address_no_iid ( ) + ":" + str ( port ) , False )
 if 98 - 98: Ii1I / oO0o * O0 + I1Ii111 - I1Ii111 + iII111i
 if 4 - 4: i1IIi
 if 43 - 43: oO0o * ooOoO0o - I11i
 if 70 - 70: oO0o / Ii1I
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
  OoOOO000O0o . add_cache ( )
  lprint ( "Add gleaned EID {} to map-cache" . format ( ooOoOOOOo ) )
  if 15 - 15: iIii1I11I1II1 % ooOoO0o % i11iIiiIii
  if 16 - 16: iII111i
 ii1iiIiiI = seid . print_address_no_iid ( )
 if 40 - 40: iII111i * i1IIi * O0 . oO0o
 if 29 - 29: i1IIi . OoOoOO00 . i1IIi + oO0o . I1Ii111 + O0
 if 62 - 62: I1ii11iIi11i . IiII + OoO0O00 - OoOoOO00 * O0 + I1Ii111
 if 58 - 58: oO0o . OoO0O00 / ooOoO0o
 if 61 - 61: I11i + I1Ii111
 IiIiI = I1iiI = O00o000O0O0oO = None
 if ( OoOOO000O0o . rloc_set != [ ] ) :
  IiIiI = OoOOO000O0o . rloc_set [ 0 ]
  if ( IiIiI . rle ) :
   I1iiI = IiIiI . rle
   for o000o0OIII1 in I1iiI . rle_nodes :
    if ( o000o0OIII1 . rloc_name != ii1iiIiiI ) : continue
    O00o000O0O0oO = o000o0OIII1
    break
    if 69 - 69: iII111i . iII111i
    if 46 - 46: IiII * Oo0Ooo + I1Ii111
    if 79 - 79: IiII
    if 89 - 89: IiII * I11i + I1ii11iIi11i * oO0o - II111iiii
    if 58 - 58: ooOoO0o . I1Ii111 / i1IIi % I1ii11iIi11i + o0oOOo0O0Ooo
    if 94 - 94: i11iIiiIii + I1Ii111 . iII111i - ooOoO0o % I1Ii111
    if 94 - 94: i11iIiiIii - OOooOOo - O0 * OoooooooOO - ooOoO0o
 if ( IiIiI == None ) :
  IiIiI = lisp_rloc ( )
  OoOOO000O0o . rloc_set = [ IiIiI ]
  IiIiI . priority = 253
  IiIiI . mpriority = 255
  OoOOO000O0o . build_best_rloc_set ( )
  if 35 - 35: iII111i . i11iIiiIii - OOooOOo % Oo0Ooo + Ii1I . iIii1I11I1II1
 if ( I1iiI == None ) :
  I1iiI = lisp_rle ( geid . print_address ( ) )
  IiIiI . rle = I1iiI
  if 91 - 91: o0oOOo0O0Ooo / OoO0O00 + I1IiiI % i11iIiiIii % i1IIi
 if ( O00o000O0O0oO == None ) :
  O00o000O0O0oO = lisp_rle_node ( )
  O00o000O0O0oO . rloc_name = ii1iiIiiI
  I1iiI . rle_nodes . append ( O00o000O0O0oO )
  I1iiI . build_forwarding_list ( )
  lprint ( "Add RLE {} for gleaned EID {}" . format ( oooO0 , ooOoOOOOo ) )
 elif ( rloc . is_exact_match ( O00o000O0O0oO . address ) == False or
 port != O00o000O0O0oO . translated_port ) :
  lprint ( "Changed RLE {} for gleaned EID {}" . format ( oooO0 , ooOoOOOOo ) )
  if 22 - 22: I1Ii111 * O0 % OoO0O00 * I1ii11iIi11i
  if 47 - 47: OoO0O00 / OOooOOo / OoOoOO00 % i11iIiiIii / OoOoOO00
  if 52 - 52: ooOoO0o / I11i % i11iIiiIii - I1Ii111 % ooOoO0o - o0oOOo0O0Ooo
  if 67 - 67: OoOoOO00 / I1Ii111 + i11iIiiIii - IiII
  if 79 - 79: I11i . I11i - OoOoOO00
 O00o000O0O0oO . store_translated_rloc ( rloc , port )
 if 86 - 86: OoO0O00 * Oo0Ooo . iIii1I11I1II1 * O0
 if 52 - 52: iII111i - i11iIiiIii + o0oOOo0O0Ooo + i1IIi
 if 58 - 58: OOooOOo - Ii1I * I1Ii111 - O0 . oO0o
 if 72 - 72: i1IIi * iII111i * Ii1I / o0oOOo0O0Ooo . I1Ii111 + i11iIiiIii
 if 33 - 33: I11i / OoO0O00 * ooOoO0o + iIii1I11I1II1
 if 54 - 54: Oo0Ooo / IiII + i11iIiiIii . O0
 if 94 - 94: OoooooooOO + iII111i * OoooooooOO / o0oOOo0O0Ooo
def lisp_remove_gleaned_multicast ( seid , geid , rloc , port ) :
 if 12 - 12: iIii1I11I1II1 / iIii1I11I1II1 / II111iiii
 if 93 - 93: oO0o
 if 53 - 53: OoO0O00 * i1IIi / Oo0Ooo / OoO0O00 * ooOoO0o
 if 77 - 77: iIii1I11I1II1 % I1IiiI + o0oOOo0O0Ooo + I1Ii111 * Oo0Ooo * i1IIi
 OoOOO000O0o = lisp_map_cache_lookup ( seid , geid )
 if ( OoOOO000O0o == None ) : return
 if 14 - 14: iIii1I11I1II1 * iIii1I11I1II1 - OOooOOo . iII111i / ooOoO0o
 o0o0ooOo00 = OoOOO000O0o . rloc_set [ 0 ] . rle
 if ( o0o0ooOo00 == None ) : return
 if 54 - 54: OoOoOO00 - I1IiiI - iII111i
 ooOO0OOO = seid . print_address_no_iid ( )
 IiiiIiI1 = False
 for O00o000O0O0oO in o0o0ooOo00 . rle_nodes :
  if ( O00o000O0O0oO . rloc_name == ooOO0OOO ) :
   IiiiIiI1 = True
   break
   if 49 - 49: i11iIiiIii * Oo0Ooo
   if 100 - 100: Oo0Ooo * oO0o
 if ( IiiiIiI1 == False ) : return
 if 85 - 85: OoooooooOO . IiII / IiII . ooOoO0o . IiII % II111iiii
 if 65 - 65: oO0o - OoO0O00 / iII111i + ooOoO0o
 if 80 - 80: o0oOOo0O0Ooo + II111iiii * Ii1I % OoOoOO00 % I1IiiI + I1ii11iIi11i
 if 46 - 46: Oo0Ooo / Oo0Ooo % iII111i % I1IiiI
 o0o0ooOo00 . rle_nodes . remove ( O00o000O0O0oO )
 o0o0ooOo00 . build_forwarding_list ( )
 if 85 - 85: OoO0O00 - Ii1I / O0
 ooOoOOOOo = green ( "(*, {})" . format ( geid . print_address ( ) ) , False )
 oooO0 = red ( rloc . print_address_no_iid ( ) + ":" + str ( port ) , False )
 lprint ( "Gleaned EID {} RLE {} removed" . format ( ooOoOOOOo , oooO0 ) )
 if 45 - 45: IiII + I1Ii111 / I11i
 if 84 - 84: iII111i % II111iiii
 if 86 - 86: IiII % II111iiii / i1IIi * I1ii11iIi11i - O0 * OOooOOo
 if 53 - 53: OOooOOo * oO0o + i1IIi % Oo0Ooo + II111iiii
 if ( o0o0ooOo00 . rle_nodes == [ ] ) :
  OoOOO000O0o . delete_cache ( )
  lprint ( "Gleaned EID {} removed, no more RLEs" . format ( ooOoOOOOo , oooO0 ) )
  if 34 - 34: oO0o % iII111i / IiII . IiII + i11iIiiIii
  if 68 - 68: O0 % oO0o * IiII % O0
  if 55 - 55: O0 % I1IiiI % O0
  if 27 - 27: I1IiiI + I1ii11iIi11i * I1Ii111 % Ii1I - Oo0Ooo
  if 87 - 87: i11iIiiIii % OOooOOo - OoOoOO00 * ooOoO0o / Oo0Ooo
  if 74 - 74: OoooooooOO * ooOoO0o - I11i / I1ii11iIi11i % iIii1I11I1II1
  if 94 - 94: Ii1I * I1Ii111 + OoOoOO00 . iIii1I11I1II1
  if 44 - 44: Oo0Ooo . Oo0Ooo * Oo0Ooo
  if 23 - 23: I1Ii111 / iII111i . O0 % II111iiii
  if 67 - 67: I11i / iIii1I11I1II1 / ooOoO0o
  if 90 - 90: II111iiii % I1Ii111 - IiII . Oo0Ooo % OOooOOo - OoOoOO00
  if 89 - 89: Oo0Ooo - I1ii11iIi11i . I1Ii111
  if 65 - 65: ooOoO0o % OOooOOo + OOooOOo % I1Ii111 . I1IiiI % O0
  if 46 - 46: OoO0O00 * I1Ii111 + iII111i . oO0o % OOooOOo / i11iIiiIii
  if 1 - 1: I1ii11iIi11i % O0 - I1ii11iIi11i / OoooooooOO / OoO0O00
  if 82 - 82: i1IIi % Ii1I
  if 85 - 85: I1Ii111 * i11iIiiIii * iIii1I11I1II1 % iIii1I11I1II1
  if 64 - 64: OoO0O00 / Ii1I
  if 79 - 79: Ii1I % OOooOOo
  if 39 - 39: I1ii11iIi11i / Ii1I - II111iiii . i1IIi
  if 59 - 59: II111iiii
  if 36 - 36: ooOoO0o . II111iiii - OoOoOO00 % I1ii11iIi11i * O0
  if 91 - 91: iII111i + Oo0Ooo / OoooooooOO * iIii1I11I1II1 - OoO0O00
  if 73 - 73: iIii1I11I1II1 % I1Ii111 % II111iiii * Oo0Ooo * OoO0O00
  if 48 - 48: OOooOOo * i11iIiiIii - i11iIiiIii + iIii1I11I1II1 + I1IiiI % OoooooooOO
  if 61 - 61: i1IIi
  if 56 - 56: iIii1I11I1II1 / I11i * iII111i * I11i * OoooooooOO
  if 44 - 44: I1ii11iIi11i - OOooOOo % I11i - I1Ii111 / iIii1I11I1II1 - OOooOOo
  if 38 - 38: iIii1I11I1II1 - OoooooooOO * II111iiii . OoooooooOO + OOooOOo
  if 59 - 59: OoooooooOO
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
igmp_types = { 17 : "IGMP-query" , 18 : "IGMPv1-report" , 19 : "DVMRP" ,
 20 : "PIMv1" , 22 : "IGMPv2-report" , 23 : "IGMPv2-leave" ,
 30 : "mtrace-response" , 31 : "mtrace-request" , 34 : "IGMPv3-report" }
if 34 - 34: OOooOOo + OoOoOO00 * o0oOOo0O0Ooo + I1ii11iIi11i + IiII * i1IIi
lisp_igmp_record_types = { 1 : "include-mode" , 2 : "exclude-mode" ,
 3 : "change-to-include" , 4 : "change-to-exclude" , 5 : "allow-new-source" ,
 6 : "block-old-sources" }
if 73 - 73: I1ii11iIi11i - IiII - O0 . oO0o + Oo0Ooo % iII111i
def lisp_process_igmp_packet ( packet ) :
 oooO0 = bold ( "Receive" , False )
 lprint ( "{} {}-byte IGMP packet: {}" . format ( oooO0 , len ( packet ) ,
 lisp_format_packet ( packet ) ) )
 if 68 - 68: I1ii11iIi11i - OoooooooOO
 if 5 - 5: I1ii11iIi11i * I1IiiI + OoooooooOO / Oo0Ooo
 if 18 - 18: OoO0O00 * iII111i % I1IiiI . OOooOOo * o0oOOo0O0Ooo
 if 58 - 58: iII111i . IiII + iIii1I11I1II1
 IIi1i1i1111II = ( struct . unpack ( "B" , packet [ 0 ] ) [ 0 ] & 0x0f ) * 4
 if 40 - 40: iIii1I11I1II1 / OoooooooOO % IiII . Ii1I
 if 83 - 83: iIii1I11I1II1 + o0oOOo0O0Ooo - I11i / i11iIiiIii
 if 57 - 57: I1IiiI . Oo0Ooo / I1IiiI / II111iiii - I1Ii111
 if 68 - 68: I1IiiI
 o0oOO0O = packet [ IIi1i1i1111II : : ]
 ooo0oo = struct . unpack ( "B" , o0oOO0O [ 0 ] ) [ 0 ]
 IiI1111i1i11I = lisp_address ( LISP_AFI_IPV4 , "" , 32 , 0 )
 if 66 - 66: II111iiii / Oo0Ooo
 iiI11 = ( ooo0oo in ( 0x12 , 0x16 , 0x17 , 0x22 ) )
 if ( iiI11 == False ) :
  II11IiIIiIi = "{} ({})" . format ( ooo0oo , igmp_types [ ooo0oo ] ) if igmp_types . has_key ( ooo0oo ) else ooo0oo
  if 35 - 35: o0oOOo0O0Ooo % oO0o * OoooooooOO + I1IiiI / Ii1I % I1IiiI
  lprint ( "IGMP type {} not supported" . format ( II11IiIIiIi ) )
  return ( [ ] )
  if 86 - 86: OoooooooOO . II111iiii * O0
  if 100 - 100: Ii1I
 if ( len ( o0oOO0O ) < 8 ) :
  lprint ( "IGMP message too small" )
  return ( [ ] )
  if 20 - 20: ooOoO0o / i11iIiiIii - OoOoOO00 / iIii1I11I1II1 * iII111i
  if 53 - 53: O0 / I11i + Oo0Ooo
  if 56 - 56: I1Ii111 - I1Ii111 * OoOoOO00 * iII111i - I1ii11iIi11i
  if 38 - 38: iIii1I11I1II1 + i1IIi % I1IiiI - I1Ii111 % oO0o
  if 69 - 69: OoooooooOO . OOooOOo * Oo0Ooo % I1ii11iIi11i - I1IiiI
  if 35 - 35: I1Ii111 % IiII / O0
 IiI1111i1i11I . address = socket . ntohl ( struct . unpack ( "II" , o0oOO0O [ : 8 ] ) [ 1 ] )
 i1ii1IIiI = IiI1111i1i11I . print_address_no_iid ( )
 if 11 - 11: i1IIi * I1Ii111 / OoOoOO00 . I1Ii111 + OoOoOO00 % IiII
 if 18 - 18: OoooooooOO / Ii1I / i1IIi / oO0o
 if 24 - 24: OoO0O00 * iII111i - i11iIiiIii + oO0o
 if 66 - 66: Oo0Ooo * I11i . iIii1I11I1II1 - OoO0O00
 if ( ooo0oo == 0x17 ) :
  lprint ( "IGMPv2 leave (*, {})" . format ( bold ( i1ii1IIiI , False ) ) )
  return ( [ [ None , i1ii1IIiI , False ] ] )
  if 11 - 11: I1Ii111 + iIii1I11I1II1 * O0 * Oo0Ooo
 if ( ooo0oo in ( 0x12 , 0x16 ) ) :
  lprint ( "IGMPv{} join (*, {})" . format ( 1 if ( ooo0oo == 0x12 ) else 2 , bold ( i1ii1IIiI , False ) ) )
  if 66 - 66: OoooooooOO % OoO0O00 + i11iIiiIii + I1Ii111 % OoO0O00
  if 80 - 80: Oo0Ooo - Ii1I
  if 54 - 54: O0 - iIii1I11I1II1 . OoO0O00 . IiII % OoO0O00
  if 28 - 28: O0 % i1IIi % OoO0O00 / o0oOOo0O0Ooo . iIii1I11I1II1 - iII111i
  if 50 - 50: o0oOOo0O0Ooo + iII111i / i1IIi % II111iiii
  if ( i1ii1IIiI . find ( "224.0.0." ) != - 1 ) :
   lprint ( "Suppress registration for link-local groups" )
  else :
   return ( [ [ None , i1ii1IIiI , True ] ] )
   if 61 - 61: IiII
   if 5 - 5: OOooOOo % iIii1I11I1II1 % O0 * i11iIiiIii / I1Ii111
   if 48 - 48: IiII * oO0o
   if 53 - 53: i1IIi * iIii1I11I1II1 . OOooOOo
   if 68 - 68: IiII % IiII - iII111i . IiII + OoooooooOO
  return ( [ ] )
  if 82 - 82: Ii1I . II111iiii / i1IIi * OoO0O00
  if 80 - 80: I11i
  if 96 - 96: i1IIi - I1ii11iIi11i * iII111i . OOooOOo . OoO0O00
  if 93 - 93: oO0o * Oo0Ooo * IiII
  if 26 - 26: o0oOOo0O0Ooo + O0 % i11iIiiIii . ooOoO0o . I1IiiI + Oo0Ooo
 oooOOoO0oo0 = IiI1111i1i11I . address
 o0oOO0O = o0oOO0O [ 8 : : ]
 if 90 - 90: IiII * OoooooooOO + II111iiii / iII111i + i11iIiiIii / ooOoO0o
 IiII1ii1I1 = "BBHI"
 iIiI11iIIII = struct . calcsize ( IiII1ii1I1 )
 IIioOOO0 = "I"
 i11I11IiIII = struct . calcsize ( IIioOOO0 )
 OOii = lisp_address ( LISP_AFI_IPV4 , "" , 32 , 0 )
 if 63 - 63: o0oOOo0O0Ooo - oO0o * I1IiiI / ooOoO0o - I1ii11iIi11i . o0oOOo0O0Ooo
 if 91 - 91: I1IiiI % Oo0Ooo
 if 10 - 10: OOooOOo - Oo0Ooo . I1IiiI + o0oOOo0O0Ooo
 if 91 - 91: ooOoO0o
 O0O00o0o = [ ]
 for oo0O0oO0O0O in range ( oooOOoO0oo0 ) :
  if ( len ( o0oOO0O ) < iIiI11iIIII ) : return
  o0OooOo , IiIIi , O0o0ooO00OO0O , I1IIIIIi1IIiI = struct . unpack ( IiII1ii1I1 ,
 o0oOO0O [ : iIiI11iIIII ] )
  if 54 - 54: o0oOOo0O0Ooo % Ii1I + I1IiiI % II111iiii + I11i - O0
  o0oOO0O = o0oOO0O [ iIiI11iIIII : : ]
  if 70 - 70: Ii1I / oO0o + i11iIiiIii - oO0o
  if ( lisp_igmp_record_types . has_key ( o0OooOo ) == False ) :
   lprint ( "Invalid record type {}" . format ( o0OooOo ) )
   continue
   if 26 - 26: OoO0O00 % I1ii11iIi11i * O0 % OoO0O00
   if 98 - 98: OoO0O00 . ooOoO0o * I11i / i1IIi
  ooOOOOOO0o = lisp_igmp_record_types [ o0OooOo ]
  O0o0ooO00OO0O = socket . ntohs ( O0o0ooO00OO0O )
  IiI1111i1i11I . address = socket . ntohl ( I1IIIIIi1IIiI )
  i1ii1IIiI = IiI1111i1i11I . print_address_no_iid ( )
  if 19 - 19: iIii1I11I1II1 * OoooooooOO - i11iIiiIii . I1Ii111 * OoO0O00
  lprint ( "Record type: {}, group: {}, source-count: {}" . format ( ooOOOOOO0o , i1ii1IIiI , O0o0ooO00OO0O ) )
  if 30 - 30: iII111i + I1IiiI * ooOoO0o
  if 53 - 53: iII111i + IiII
  if 52 - 52: II111iiii * i11iIiiIii - IiII * IiII / OoooooooOO
  if 18 - 18: IiII / O0 / I1ii11iIi11i
  if 47 - 47: oO0o / iIii1I11I1II1
  if 45 - 45: OoOoOO00 * o0oOOo0O0Ooo / I1ii11iIi11i * iII111i - I1ii11iIi11i
  if 48 - 48: Ii1I / OoO0O00
  IiiIi1iiiI111 = False
  if ( o0OooOo in ( 1 , 5 ) ) : IiiIi1iiiI111 = True
  if ( o0OooOo == 4 and O0o0ooO00OO0O == 0 ) : IiiIi1iiiI111 = True
  o0o0OO0OOooO = "join" if ( IiiIi1iiiI111 ) else "leave"
  if 33 - 33: IiII / o0oOOo0O0Ooo
  if 75 - 75: OOooOOo . I11i . I11i * II111iiii * Oo0Ooo
  if 39 - 39: i1IIi - ooOoO0o % OoO0O00 + O0 / iIii1I11I1II1
  if 78 - 78: ooOoO0o / i1IIi . OOooOOo * o0oOOo0O0Ooo . I1IiiI
  if ( i1ii1IIiI . find ( "224.0.0." ) != - 1 ) :
   lprint ( "Suppress registration for link-local groups" )
   continue
   if 81 - 81: I11i - OoO0O00 - o0oOOo0O0Ooo
   if 95 - 95: I11i + Ii1I
   if 68 - 68: i11iIiiIii + I1IiiI / o0oOOo0O0Ooo
   if 63 - 63: I1IiiI
   if 20 - 20: oO0o + OoOoOO00
   if 32 - 32: o0oOOo0O0Ooo % oO0o % I1IiiI * OoooooooOO
   if 4 - 4: OOooOOo % oO0o
   if 18 - 18: Ii1I * I11i
  if ( O0o0ooO00OO0O == 0 ) :
   O0O00o0o . append ( [ None , i1ii1IIiI , IiiIi1iiiI111 ] )
   lprint ( "IGMPv3 {} (*, {})" . format ( bold ( o0o0OO0OOooO , False ) ,
 bold ( i1ii1IIiI , False ) ) )
   if 14 - 14: ooOoO0o . ooOoO0o * OoOoOO00 * o0oOOo0O0Ooo - iII111i - I1Ii111
   if 53 - 53: Oo0Ooo * OoOoOO00 * II111iiii % IiII - I1ii11iIi11i
   if 56 - 56: Oo0Ooo . I1ii11iIi11i - i11iIiiIii / iIii1I11I1II1 . ooOoO0o
   if 28 - 28: OoooooooOO + I1IiiI / oO0o . iIii1I11I1II1 - oO0o
   if 64 - 64: I1Ii111 + Oo0Ooo / iII111i
  for iIIi11i1i1I1I in range ( O0o0ooO00OO0O ) :
   if ( len ( o0oOO0O ) < i11I11IiIII ) : return
   I1IIIIIi1IIiI = struct . unpack ( IIioOOO0 , o0oOO0O [ : i11I11IiIII ] ) [ 0 ]
   OOii . address = socket . ntohl ( I1IIIIIi1IIiI )
   O0o0OO0O0oOo0 = OOii . print_address_no_iid ( )
   O0O00o0o . append ( [ O0o0OO0O0oOo0 , i1ii1IIiI , IiiIi1iiiI111 ] )
   lprint ( "{} ({}, {})" . format ( o0o0OO0OOooO ,
 green ( O0o0OO0O0oOo0 , False ) , bold ( i1ii1IIiI , False ) ) )
   o0oOO0O = o0oOO0O [ i11I11IiIII : : ]
   if 71 - 71: Ii1I
   if 83 - 83: iII111i + OoooooooOO * o0oOOo0O0Ooo - OoOoOO00 - I1IiiI . o0oOOo0O0Ooo
   if 38 - 38: o0oOOo0O0Ooo - oO0o / Ii1I + I1IiiI
   if 61 - 61: Oo0Ooo % I1ii11iIi11i
   if 18 - 18: OoOoOO00 * OoOoOO00 - I1Ii111
   if 33 - 33: i11iIiiIii * Oo0Ooo % OoOoOO00 - iII111i - Oo0Ooo / iII111i
   if 67 - 67: I1Ii111 + i1IIi / o0oOOo0O0Ooo % iII111i / iII111i
   if 8 - 8: i1IIi % I11i
 return ( O0O00o0o )
 if 12 - 12: ooOoO0o / II111iiii + ooOoO0o * I1ii11iIi11i / i1IIi - iIii1I11I1II1
 if 71 - 71: IiII - i11iIiiIii
 if 3 - 3: i11iIiiIii - o0oOOo0O0Ooo / oO0o . OoO0O00 * I11i + o0oOOo0O0Ooo
 if 18 - 18: OoooooooOO % oO0o / IiII - ooOoO0o
 if 80 - 80: I11i
 if 98 - 98: iII111i / I1ii11iIi11i
 if 87 - 87: iII111i - O0 * ooOoO0o / II111iiii % OoooooooOO . o0oOOo0O0Ooo
 if 55 - 55: OOooOOo - o0oOOo0O0Ooo * I1IiiI / o0oOOo0O0Ooo + I1Ii111 + iIii1I11I1II1
lisp_geid = lisp_address ( LISP_AFI_IPV4 , "" , 32 , 0 )
if 3 - 3: II111iiii % iII111i / IiII * ooOoO0o . OoooooooOO
def lisp_glean_map_cache ( seid , rloc , encap_port , igmp ) :
 if 56 - 56: IiII * II111iiii + Oo0Ooo - O0 - OoO0O00 . I1Ii111
 if 53 - 53: i1IIi + IiII
 if 90 - 90: II111iiii / oO0o / oO0o . OoOoOO00 / OoO0O00 / iIii1I11I1II1
 if 96 - 96: iIii1I11I1II1 % I1ii11iIi11i
 if 35 - 35: i1IIi - OoooooooOO * Ii1I / OOooOOo % I11i
 if 72 - 72: I1Ii111 / OoO0O00 + II111iiii
 I1ii1i = True
 OoOOO000O0o = lisp_map_cache . lookup_cache ( seid , True )
 if ( OoOOO000O0o and len ( OoOOO000O0o . rloc_set ) != 0 ) :
  OoOOO000O0o . last_refresh_time = lisp_get_timestamp ( )
  if 23 - 23: i1IIi + I1Ii111 / IiII * O0 - I1Ii111
  oO0OOO = OoOOO000O0o . rloc_set [ 0 ]
  oo0ooO000 = oO0OOO . rloc
  i1Ii1IiI1Ii1 = oO0OOO . translated_port
  I1ii1i = ( oo0ooO000 . is_exact_match ( rloc ) == False or
 i1Ii1IiI1Ii1 != encap_port )
  if 34 - 34: iIii1I11I1II1
  if ( I1ii1i ) :
   ooOoOOOOo = green ( seid . print_address ( ) , False )
   oooO0 = red ( rloc . print_address_no_iid ( ) + ":" + str ( encap_port ) , False )
   lprint ( "Change gleaned EID {} to RLOC {}" . format ( ooOoOOOOo , oooO0 ) )
   oO0OOO . delete_from_rloc_probe_list ( OoOOO000O0o . eid , OoOOO000O0o . group )
   if 74 - 74: II111iiii - i1IIi
   if 93 - 93: O0 + OoooooooOO % IiII % oO0o % I1ii11iIi11i
   if 36 - 36: I1IiiI - oO0o * Oo0Ooo + oO0o % iII111i - i11iIiiIii
   if 93 - 93: O0
   for IiI1111i1i11I in OoOOO000O0o . gleaned_groups :
    lisp_geid . store_address ( IiI1111i1i11I )
    lisp_build_gleaned_multicast ( seid , lisp_geid , rloc , encap_port )
    if 11 - 11: OoooooooOO . I1ii11iIi11i + I1ii11iIi11i
    if 73 - 73: OoooooooOO
 else :
  OoOOO000O0o = lisp_mapping ( "" , "" , [ ] )
  OoOOO000O0o . eid . copy_address ( seid )
  OoOOO000O0o . mapping_source . copy_address ( rloc )
  OoOOO000O0o . map_cache_ttl = LISP_GLEAN_TTL
  OoOOO000O0o . gleaned = True
  ooOoOOOOo = green ( seid . print_address ( ) , False )
  oooO0 = red ( rloc . print_address_no_iid ( ) + ":" + str ( encap_port ) , False )
  lprint ( "Add gleaned EID {} to map-cache with RLOC {}" . format ( ooOoOOOOo , oooO0 ) )
  OoOOO000O0o . add_cache ( )
  if 2 - 2: o0oOOo0O0Ooo % IiII + I1ii11iIi11i - i11iIiiIii
  if 100 - 100: II111iiii + oO0o
  if 85 - 85: I1ii11iIi11i % I1ii11iIi11i . Ii1I
  if 42 - 42: oO0o + OoO0O00
  if 16 - 16: Ii1I
 if ( I1ii1i ) :
  IiIiI = lisp_rloc ( )
  IiIiI . store_translated_rloc ( rloc , encap_port )
  IiIiI . add_to_rloc_probe_list ( OoOOO000O0o . eid , OoOOO000O0o . group )
  IiIiI . priority = 253
  IiIiI . mpriority = 255
  I1I11I11 = [ IiIiI ]
  OoOOO000O0o . rloc_set = I1I11I11
  OoOOO000O0o . build_best_rloc_set ( )
  if 67 - 67: I1ii11iIi11i . OoooooooOO * I1Ii111 + Ii1I * OOooOOo
  if 84 - 84: OOooOOo
  if 78 - 78: O0 % O0
  if 72 - 72: o0oOOo0O0Ooo * IiII / II111iiii / iIii1I11I1II1
  if 41 - 41: iII111i / Ii1I
 if ( igmp == None ) : return
 if 11 - 11: Oo0Ooo % OOooOOo . ooOoO0o
 if 24 - 24: IiII / Oo0Ooo
 if 90 - 90: ooOoO0o . OOooOOo - Ii1I
 if 60 - 60: i11iIiiIii % iII111i . I1IiiI * I1ii11iIi11i
 if 30 - 30: Ii1I + i11iIiiIii . I11i + o0oOOo0O0Ooo - OoO0O00
 lisp_geid . instance_id = seid . instance_id
 if 55 - 55: ooOoO0o - II111iiii . ooOoO0o . iII111i / OoooooooOO
 if 51 - 51: I1IiiI * I1Ii111 - ooOoO0o + IiII
 if 22 - 22: OoOoOO00 % Ii1I + iII111i
 if 64 - 64: ooOoO0o
 if 87 - 87: IiII - Ii1I / Oo0Ooo / I1ii11iIi11i . iII111i
 i1I1I11ii = lisp_process_igmp_packet ( igmp )
 for OOii , IiI1111i1i11I , IiiIi1iiiI111 in i1I1I11ii :
  if ( OOii != None ) : continue
  if 49 - 49: IiII * OoooooooOO * iIii1I11I1II1 * Oo0Ooo / iII111i % oO0o
  if 88 - 88: I1Ii111 * OOooOOo
  if 38 - 38: Oo0Ooo - OoooooooOO - OoooooooOO / II111iiii
  if 10 - 10: II111iiii - OoO0O00 / II111iiii % Ii1I - OoOoOO00
  lisp_geid . store_address ( IiI1111i1i11I )
  o0OooO00Oo , O0OOoO = lisp_allow_gleaning ( seid , lisp_geid , rloc )
  if ( o0OooO00Oo == False ) : continue
  if 90 - 90: I11i + II111iiii - oO0o - ooOoO0o / ooOoO0o / i11iIiiIii
  if ( IiiIi1iiiI111 ) :
   lisp_build_gleaned_multicast ( seid , lisp_geid , rloc , encap_port )
   if ( IiI1111i1i11I in OoOOO000O0o . gleaned_groups ) : continue
   OoOOO000O0o . gleaned_groups . append ( IiI1111i1i11I )
  else :
   lisp_remove_gleaned_multicast ( seid , lisp_geid , rloc , encap_port )
   if ( IiI1111i1i11I in OoOOO000O0o . gleaned_groups ) : OoOOO000O0o . gleaned_groups . remove ( IiI1111i1i11I )
   if 80 - 80: I1ii11iIi11i % O0 / II111iiii + iII111i
   if 22 - 22: Oo0Ooo + ooOoO0o . OOooOOo % Oo0Ooo . IiII
   if 34 - 34: Ii1I . OoOoOO00 - OOooOOo * Oo0Ooo - ooOoO0o . oO0o
   if 42 - 42: O0 + OoO0O00
   if 47 - 47: O0 % OoOoOO00 + Ii1I * iIii1I11I1II1
# dd678faae9ac167bc83abf78e5cb2f3f0688d3a3
