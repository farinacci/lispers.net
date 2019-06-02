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
LISP_FLOW_LOG_SIZE = 100
lisp_flow_log = [ ]
if 67 - 67: I1Ii111 . iII111i . O0
if 10 - 10: I1ii11iIi11i % I1ii11iIi11i - iIii1I11I1II1 / OOooOOo + Ii1I
if 87 - 87: oO0o * I1ii11iIi11i + OOooOOo / iIii1I11I1II1 / iII111i
if 37 - 37: iII111i - ooOoO0o * oO0o % i11iIiiIii - I1Ii111
lisp_policies = { }
if 83 - 83: I11i / I1IiiI
if 34 - 34: IiII
if 57 - 57: oO0o . I11i . i1IIi
if 42 - 42: I11i + I1ii11iIi11i % O0
if 6 - 6: oO0o
lisp_load_split_pings = False
if 68 - 68: OoOoOO00 - OoO0O00
if 28 - 28: OoO0O00 . OOooOOo / OOooOOo + Oo0Ooo . I1ii11iIi11i
if 1 - 1: iIii1I11I1II1 / II111iiii
if 33 - 33: I11i
if 18 - 18: o0oOOo0O0Ooo % iII111i * O0
if 87 - 87: i11iIiiIii
lisp_eid_hashes = [ ]
if 93 - 93: I1ii11iIi11i - OoO0O00 % i11iIiiIii . iII111i / iII111i - I1Ii111
if 9 - 9: I1ii11iIi11i / Oo0Ooo - I1IiiI / OoooooooOO / iIii1I11I1II1 - o0oOOo0O0Ooo
if 91 - 91: iII111i % i1IIi % iIii1I11I1II1
if 20 - 20: OOooOOo % Ii1I / Ii1I + Ii1I
if 45 - 45: oO0o - IiII - OoooooooOO - OoO0O00 . II111iiii / O0
if 51 - 51: O0 + iII111i
if 8 - 8: oO0o * OoOoOO00 - Ii1I - OoO0O00 * OOooOOo % I1IiiI
if 48 - 48: O0
lisp_reassembly_queue = { }
if 11 - 11: I11i + OoooooooOO - OoO0O00 / o0oOOo0O0Ooo + Oo0Ooo . II111iiii
if 41 - 41: Ii1I - O0 - O0
if 68 - 68: OOooOOo % I1Ii111
if 88 - 88: iIii1I11I1II1 - ooOoO0o + OOooOOo
if 40 - 40: I1IiiI * Ii1I + OOooOOo % iII111i
if 74 - 74: oO0o - Oo0Ooo + OoooooooOO + I1Ii111 / OoOoOO00
if 23 - 23: O0
lisp_pubsub_cache = { }
if 85 - 85: Ii1I
if 84 - 84: I1IiiI . iIii1I11I1II1 % OoooooooOO + Ii1I % OoooooooOO % OoO0O00
if 42 - 42: OoO0O00 / I11i / o0oOOo0O0Ooo + iII111i / OoOoOO00
if 84 - 84: ooOoO0o * II111iiii + Oo0Ooo
if 53 - 53: iII111i % II111iiii . IiII - iIii1I11I1II1 - IiII * II111iiii
if 77 - 77: iIii1I11I1II1 * OoO0O00
lisp_decent_push_configured = False
if 95 - 95: I1IiiI + i11iIiiIii
if 6 - 6: ooOoO0o / i11iIiiIii + iII111i * oO0o
if 80 - 80: II111iiii
if 83 - 83: I11i . i11iIiiIii + II111iiii . o0oOOo0O0Ooo * I11i
if 53 - 53: II111iiii
if 31 - 31: OoO0O00
lisp_decent_modulus = 0
lisp_decent_dns_suffix = None
if 80 - 80: I1Ii111 . i11iIiiIii - o0oOOo0O0Ooo
if 25 - 25: OoO0O00
if 62 - 62: OOooOOo + O0
if 98 - 98: o0oOOo0O0Ooo
if 51 - 51: Oo0Ooo - oO0o + II111iiii * Ii1I . I11i + oO0o
if 78 - 78: i11iIiiIii / iII111i - Ii1I / OOooOOo + oO0o
lisp_ipc_socket = None
if 82 - 82: Ii1I
if 46 - 46: OoooooooOO . i11iIiiIii
if 94 - 94: o0oOOo0O0Ooo * Ii1I / Oo0Ooo / Ii1I
if 87 - 87: Oo0Ooo . IiII
lisp_ms_encryption_keys = { }
if 75 - 75: ooOoO0o + OoOoOO00 + o0oOOo0O0Ooo * I11i % oO0o . iII111i
if 55 - 55: OOooOOo . I1IiiI
if 61 - 61: Oo0Ooo % IiII . Oo0Ooo
if 100 - 100: I1Ii111 * O0
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
lisp_rtr_nat_trace_cache = { }
if 88 - 88: OoooooooOO - OoO0O00 * O0 * OoooooooOO . OoooooooOO
if 33 - 33: I1Ii111 + iII111i * oO0o / iIii1I11I1II1 - I1IiiI
if 54 - 54: I1Ii111 / OOooOOo . oO0o % iII111i
if 57 - 57: i11iIiiIii . I1ii11iIi11i - Ii1I - oO0o + OoOoOO00
if 63 - 63: OoOoOO00 * iII111i
if 69 - 69: O0 . OoO0O00
if 49 - 49: I1IiiI - I11i
if 74 - 74: iIii1I11I1II1 * I1ii11iIi11i + OoOoOO00 / i1IIi / II111iiii . Oo0Ooo
if 62 - 62: OoooooooOO * I1IiiI
lisp_glean_mappings = [ ]
if 58 - 58: OoOoOO00 % o0oOOo0O0Ooo
if 50 - 50: I1Ii111 . o0oOOo0O0Ooo
if 97 - 97: O0 + OoOoOO00
if 89 - 89: o0oOOo0O0Ooo + OoO0O00 * I11i * Ii1I
if 37 - 37: OoooooooOO - O0 - o0oOOo0O0Ooo
if 77 - 77: OOooOOo * iIii1I11I1II1
LISP_DATA_PORT = 4341
LISP_CTRL_PORT = 4342
LISP_L2_DATA_PORT = 8472
LISP_VXLAN_DATA_PORT = 4789
LISP_VXLAN_GPE_PORT = 4790
LISP_TRACE_PORT = 2434
if 98 - 98: I1IiiI % Ii1I * OoooooooOO
if 51 - 51: iIii1I11I1II1 . OoOoOO00 / oO0o + o0oOOo0O0Ooo
if 33 - 33: ooOoO0o . II111iiii % iII111i + o0oOOo0O0Ooo
if 71 - 71: Oo0Ooo % OOooOOo
LISP_MAP_REQUEST = 1
LISP_MAP_REPLY = 2
LISP_MAP_REGISTER = 3
LISP_MAP_NOTIFY = 4
LISP_MAP_NOTIFY_ACK = 5
LISP_MAP_REFERRAL = 6
LISP_NAT_INFO = 7
LISP_ECM = 8
LISP_TRACE = 9
if 98 - 98: I11i % i11iIiiIii % ooOoO0o + Ii1I
if 78 - 78: I1ii11iIi11i % oO0o / iII111i - iIii1I11I1II1
if 69 - 69: I1Ii111
if 11 - 11: I1IiiI
LISP_NO_ACTION = 0
LISP_NATIVE_FORWARD_ACTION = 1
LISP_SEND_MAP_REQUEST_ACTION = 2
LISP_DROP_ACTION = 3
LISP_POLICY_DENIED_ACTION = 4
LISP_AUTH_FAILURE_ACTION = 5
if 16 - 16: Ii1I + IiII * O0 % i1IIi . I1IiiI
lisp_map_reply_action_string = [ "no-action" , "native-forward" ,
 "send-map-request" , "drop-action" , "policy-denied" , "auth-failure" ]
if 67 - 67: OoooooooOO / I1IiiI * Ii1I + I11i
if 65 - 65: OoooooooOO - I1ii11iIi11i / ooOoO0o / II111iiii / i1IIi
if 71 - 71: I1Ii111 + Ii1I
if 28 - 28: OOooOOo
LISP_NONE_ALG_ID = 0
LISP_SHA_1_96_ALG_ID = 1
LISP_SHA_256_128_ALG_ID = 2
LISP_MD5_AUTH_DATA_LEN = 16
LISP_SHA1_160_AUTH_DATA_LEN = 20
LISP_SHA2_256_AUTH_DATA_LEN = 32
if 38 - 38: ooOoO0o % II111iiii % I11i / OoO0O00 + OoOoOO00 / i1IIi
if 54 - 54: iIii1I11I1II1 % I1ii11iIi11i - OOooOOo / oO0o - OoO0O00 . I11i
if 11 - 11: I1ii11iIi11i . OoO0O00 * IiII * OoooooooOO + ooOoO0o
if 33 - 33: O0 * o0oOOo0O0Ooo - I1Ii111 % I1Ii111
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
if 18 - 18: I1Ii111 / Oo0Ooo * I1Ii111 + I1Ii111 * i11iIiiIii * I1ii11iIi11i
if 11 - 11: ooOoO0o / OoOoOO00 - IiII * OoooooooOO + OoooooooOO . OoOoOO00
if 26 - 26: Ii1I % I1ii11iIi11i
if 76 - 76: IiII * iII111i
LISP_MR_TTL = ( 24 * 60 )
LISP_REGISTER_TTL = 3
LISP_SHORT_TTL = 1
LISP_NMR_TTL = 15
LISP_GLEAN_TTL = 15
if 52 - 52: OOooOOo
LISP_SITE_TIMEOUT_CHECK_INTERVAL = 60
LISP_PUBSUB_TIMEOUT_CHECK_INTERVAL = 60
LISP_REFERRAL_TIMEOUT_CHECK_INTERVAL = 60
LISP_TEST_MR_INTERVAL = 60
LISP_MAP_NOTIFY_INTERVAL = 2
LISP_DDT_MAP_REQUEST_INTERVAL = 2
LISP_MAX_MAP_NOTIFY_RETRIES = 3
LISP_INFO_INTERVAL = 15
LISP_MAP_REQUEST_RATE_LIMIT = 5
if 19 - 19: I1IiiI
LISP_RLOC_PROBE_TTL = 64
LISP_RLOC_PROBE_INTERVAL = 10
LISP_RLOC_PROBE_REPLY_WAIT = 15
if 25 - 25: Ii1I / ooOoO0o
LISP_DEFAULT_DYN_EID_TIMEOUT = 15
LISP_NONCE_ECHO_INTERVAL = 10
if 31 - 31: OOooOOo . O0 % I1IiiI . o0oOOo0O0Ooo + IiII
if 71 - 71: I1Ii111 . II111iiii
if 62 - 62: OoooooooOO . I11i
if 61 - 61: OoOoOO00 - OOooOOo - i1IIi
if 25 - 25: O0 * I11i + I1ii11iIi11i . o0oOOo0O0Ooo . o0oOOo0O0Ooo
if 58 - 58: I1IiiI
if 53 - 53: i1IIi
if 59 - 59: o0oOOo0O0Ooo
if 81 - 81: OoOoOO00 - OoOoOO00 . iII111i
if 73 - 73: I11i % i11iIiiIii - I1IiiI
if 7 - 7: O0 * i11iIiiIii * Ii1I + ooOoO0o % OoO0O00 - ooOoO0o
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
LISP_CS_1024 = 0
LISP_CS_1024_G = 2
LISP_CS_1024_P = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF
if 95 - 95: ooOoO0o / ooOoO0o
LISP_CS_2048_CBC = 1
LISP_CS_2048_CBC_G = 2
LISP_CS_2048_CBC_P = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF
if 30 - 30: I1ii11iIi11i + Oo0Ooo / Oo0Ooo % I1ii11iIi11i . I1ii11iIi11i
LISP_CS_25519_CBC = 2
LISP_CS_2048_GCM = 3
if 55 - 55: ooOoO0o - I11i + II111iiii + iII111i % Ii1I
LISP_CS_3072 = 4
LISP_CS_3072_G = 2
LISP_CS_3072_P = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF
if 41 - 41: i1IIi - I11i - Ii1I
LISP_CS_25519_GCM = 5
LISP_CS_25519_CHACHA = 6
if 8 - 8: OoO0O00 + I1Ii111 - o0oOOo0O0Ooo % Oo0Ooo % o0oOOo0O0Ooo * oO0o
LISP_4_32_MASK = 0xFFFFFFFF
LISP_8_64_MASK = 0xFFFFFFFFFFFFFFFF
LISP_16_128_MASK = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
if 9 - 9: Oo0Ooo - i11iIiiIii - OOooOOo * Ii1I + ooOoO0o
if 44 - 44: II111iiii
if 52 - 52: I1ii11iIi11i - Oo0Ooo + I1ii11iIi11i % o0oOOo0O0Ooo
if 35 - 35: iIii1I11I1II1
if 42 - 42: I1Ii111 . I1IiiI . i1IIi + OoOoOO00 + OOooOOo + I1IiiI
if 31 - 31: iII111i . OOooOOo - ooOoO0o . OoooooooOO / OoooooooOO
if 56 - 56: OoO0O00 / oO0o / i11iIiiIii + OoooooooOO - Oo0Ooo - I11i
if 21 - 21: O0 % IiII . I1IiiI / II111iiii + IiII
def lisp_record_traceback ( * args ) :
 OOOO0O00o = datetime . datetime . now ( ) . strftime ( "%m/%d/%y %H:%M:%S.%f" ) [ : - 3 ]
 ooo = open ( "./logs/lisp-traceback.log" , "a" )
 ooo . write ( "---------- Exception occurred: {} ----------\n" . format ( OOOO0O00o ) )
 try :
  traceback . print_last ( file = ooo )
 except :
  ooo . write ( "traceback.print_last(file=fd) failed" )
  if 19 - 19: OoO0O00 - Oo0Ooo . oO0o / oO0o % ooOoO0o
 try :
  traceback . print_last ( )
 except :
  print ( "traceback.print_last() failed" )
  if 56 - 56: I1IiiI . O0 + Oo0Ooo
 ooo . close ( )
 return
 if 1 - 1: iII111i
 if 97 - 97: OOooOOo + iII111i + O0 + i11iIiiIii
 if 77 - 77: o0oOOo0O0Ooo / OoooooooOO
 if 46 - 46: o0oOOo0O0Ooo % iIii1I11I1II1 . iII111i % iII111i + i11iIiiIii
 if 72 - 72: iIii1I11I1II1 * Ii1I % ooOoO0o / OoO0O00
 if 35 - 35: ooOoO0o + i1IIi % I1ii11iIi11i % I11i + oO0o
 if 17 - 17: i1IIi
def lisp_set_exception ( ) :
 sys . excepthook = lisp_record_traceback
 return
 if 21 - 21: Oo0Ooo
 if 29 - 29: I11i / II111iiii / ooOoO0o * OOooOOo
 if 10 - 10: I1Ii111 % IiII * IiII . I11i / Ii1I % OOooOOo
 if 49 - 49: OoO0O00 / oO0o + O0 * o0oOOo0O0Ooo
 if 28 - 28: ooOoO0o + i11iIiiIii / I11i % OoOoOO00 % Oo0Ooo - O0
 if 54 - 54: i1IIi + II111iiii
 if 83 - 83: I1ii11iIi11i - I1IiiI + OOooOOo
def lisp_is_raspbian ( ) :
 if ( platform . dist ( ) [ 0 ] != "debian" ) : return ( False )
 return ( platform . machine ( ) in [ "armv6l" , "armv7l" ] )
 if 5 - 5: Ii1I
 if 46 - 46: IiII
 if 45 - 45: ooOoO0o
 if 21 - 21: oO0o . I1Ii111 . OOooOOo / Oo0Ooo / I1Ii111
 if 17 - 17: OOooOOo / OOooOOo / I11i
 if 1 - 1: i1IIi . i11iIiiIii % OOooOOo
 if 82 - 82: iIii1I11I1II1 + Oo0Ooo . iIii1I11I1II1 % IiII / Ii1I . Ii1I
def lisp_is_ubuntu ( ) :
 return ( platform . dist ( ) [ 0 ] == "Ubuntu" )
 if 14 - 14: o0oOOo0O0Ooo . OOooOOo . I11i + OoooooooOO - OOooOOo + IiII
 if 9 - 9: Ii1I
 if 59 - 59: I1IiiI * II111iiii . O0
 if 56 - 56: Ii1I - iII111i % I1IiiI - o0oOOo0O0Ooo
 if 51 - 51: O0 / ooOoO0o * iIii1I11I1II1 + I1ii11iIi11i + o0oOOo0O0Ooo
 if 98 - 98: iIii1I11I1II1 * I1ii11iIi11i * OOooOOo + ooOoO0o % i11iIiiIii % O0
 if 27 - 27: O0
def lisp_is_fedora ( ) :
 return ( platform . dist ( ) [ 0 ] == "fedora" )
 if 79 - 79: o0oOOo0O0Ooo - I11i + o0oOOo0O0Ooo . oO0o
 if 28 - 28: i1IIi - iII111i
 if 54 - 54: iII111i - O0 % OOooOOo
 if 73 - 73: O0 . OoOoOO00 + I1IiiI - I11i % I11i . I11i
 if 17 - 17: Ii1I - OoooooooOO % Ii1I . IiII / i11iIiiIii % iII111i
 if 28 - 28: I11i
 if 58 - 58: OoOoOO00
def lisp_is_centos ( ) :
 return ( platform . dist ( ) [ 0 ] == "centos" )
 if 37 - 37: Oo0Ooo - iIii1I11I1II1 / I1ii11iIi11i
 if 73 - 73: i11iIiiIii - IiII
 if 25 - 25: OoooooooOO + IiII * I1ii11iIi11i
 if 92 - 92: I1IiiI + I11i + O0 / o0oOOo0O0Ooo + I1Ii111
 if 18 - 18: ooOoO0o * OoOoOO00 . iII111i / I1ii11iIi11i / i11iIiiIii
 if 21 - 21: oO0o / I1ii11iIi11i + Ii1I + OoooooooOO
 if 91 - 91: i11iIiiIii / i1IIi + iII111i + ooOoO0o * i11iIiiIii
def lisp_is_debian ( ) :
 return ( platform . dist ( ) [ 0 ] == "debian" )
 if 66 - 66: iIii1I11I1II1 % i1IIi - O0 + I11i * I1Ii111 . IiII
 if 52 - 52: ooOoO0o + O0 . iII111i . I1ii11iIi11i . OoO0O00
 if 97 - 97: I1IiiI / iII111i
 if 71 - 71: II111iiii / i1IIi . I1ii11iIi11i % OoooooooOO . OoOoOO00
 if 41 - 41: i1IIi * II111iiii / OoooooooOO . OOooOOo
 if 83 - 83: iII111i . O0 / Oo0Ooo / OOooOOo - II111iiii
 if 100 - 100: OoO0O00
def lisp_is_debian_kali ( ) :
 return ( platform . dist ( ) [ 0 ] == "Kali" )
 if 46 - 46: OoOoOO00 / iIii1I11I1II1 % iII111i . iIii1I11I1II1 * iII111i
 if 38 - 38: I1ii11iIi11i - iII111i / O0 . I1Ii111
 if 45 - 45: I1Ii111
 if 83 - 83: OoOoOO00 . OoooooooOO
 if 58 - 58: i11iIiiIii + OoooooooOO % OoooooooOO / IiII / i11iIiiIii
 if 62 - 62: OoO0O00 / I1ii11iIi11i
 if 7 - 7: OoooooooOO . IiII
def lisp_is_macos ( ) :
 return ( platform . uname ( ) [ 0 ] == "Darwin" )
 if 53 - 53: Ii1I % Ii1I * o0oOOo0O0Ooo + OoOoOO00
 if 92 - 92: OoooooooOO + i1IIi / Ii1I * O0
 if 100 - 100: ooOoO0o % iIii1I11I1II1 * II111iiii - iII111i
 if 92 - 92: ooOoO0o
 if 22 - 22: Oo0Ooo % iII111i * I1ii11iIi11i / OOooOOo % i11iIiiIii * I11i
 if 95 - 95: OoooooooOO - IiII * I1IiiI + OoOoOO00
 if 10 - 10: o0oOOo0O0Ooo / i11iIiiIii
def lisp_is_alpine ( ) :
 return ( os . path . exists ( "/etc/alpine-release" ) )
 if 92 - 92: I11i . I1Ii111
 if 85 - 85: I1ii11iIi11i . I1Ii111
 if 78 - 78: ooOoO0o * I1Ii111 + iIii1I11I1II1 + iIii1I11I1II1 / I1Ii111 . Ii1I
 if 97 - 97: ooOoO0o / I1Ii111 % i1IIi % I1ii11iIi11i
 if 18 - 18: iIii1I11I1II1 % I11i
 if 95 - 95: ooOoO0o + i11iIiiIii * I1Ii111 - i1IIi * I1Ii111 - iIii1I11I1II1
 if 75 - 75: OoooooooOO * IiII
def lisp_is_x86 ( ) :
 I1Iiiiiii = platform . machine ( )
 return ( I1Iiiiiii in ( "x86" , "i686" , "x86_64" ) )
 if 39 - 39: IiII * Oo0Ooo + iIii1I11I1II1 - IiII + OOooOOo
 if 69 - 69: O0
 if 85 - 85: ooOoO0o / O0
 if 18 - 18: o0oOOo0O0Ooo % O0 * I1ii11iIi11i
 if 62 - 62: I1Ii111 . IiII . OoooooooOO
 if 11 - 11: OOooOOo / I11i
 if 73 - 73: i1IIi / i11iIiiIii
def lisp_is_linux ( ) :
 return ( platform . uname ( ) [ 0 ] == "Linux" )
 if 58 - 58: Oo0Ooo . II111iiii + oO0o - i11iIiiIii / II111iiii / O0
 if 85 - 85: OoOoOO00 + OOooOOo
 if 10 - 10: IiII / OoO0O00 + OoOoOO00 / i1IIi
 if 27 - 27: Ii1I
 if 67 - 67: I1IiiI
 if 55 - 55: I1ii11iIi11i - iII111i * o0oOOo0O0Ooo + OoOoOO00 * OoOoOO00 * O0
 if 91 - 91: I1Ii111 - OOooOOo % iIii1I11I1II1 - OoooooooOO % ooOoO0o
 if 98 - 98: OoO0O00 . OoO0O00 * oO0o * II111iiii * I1Ii111
def lisp_process_logfile ( ) :
 oOooO0 = "./logs/lisp-{}.log" . format ( lisp_log_id )
 if ( os . path . exists ( oOooO0 ) ) : return
 if 79 - 79: OoO0O00 - iIii1I11I1II1 + Ii1I - I1Ii111
 sys . stdout . close ( )
 sys . stdout = open ( oOooO0 , "a" )
 if 93 - 93: II111iiii . I1IiiI - Oo0Ooo + OoOoOO00
 lisp_print_banner ( bold ( "logfile rotation" , False ) )
 return
 if 61 - 61: II111iiii
 if 15 - 15: i11iIiiIii % I1IiiI * I11i / I1Ii111
 if 90 - 90: iII111i
 if 31 - 31: OOooOOo + O0
 if 87 - 87: ooOoO0o
 if 45 - 45: OoO0O00 / OoooooooOO - iII111i / Ii1I % IiII
 if 83 - 83: I1IiiI . iIii1I11I1II1 - IiII * i11iIiiIii
 if 20 - 20: i1IIi * I1Ii111 + II111iiii % o0oOOo0O0Ooo % oO0o
def lisp_i_am ( name ) :
 global lisp_log_id , lisp_i_am_itr , lisp_i_am_etr , lisp_i_am_rtr
 global lisp_i_am_mr , lisp_i_am_ms , lisp_i_am_ddt , lisp_i_am_core
 global lisp_hostname
 if 13 - 13: Oo0Ooo
 lisp_log_id = name
 if ( name == "itr" ) : lisp_i_am_itr = True
 if ( name == "etr" ) : lisp_i_am_etr = True
 if ( name == "rtr" ) : lisp_i_am_rtr = True
 if ( name == "mr" ) : lisp_i_am_mr = True
 if ( name == "ms" ) : lisp_i_am_ms = True
 if ( name == "ddt" ) : lisp_i_am_ddt = True
 if ( name == "core" ) : lisp_i_am_core = True
 if 60 - 60: I1ii11iIi11i * I1IiiI
 if 17 - 17: OOooOOo % Oo0Ooo / I1ii11iIi11i . IiII * OOooOOo - II111iiii
 if 41 - 41: Ii1I
 if 77 - 77: I1Ii111
 if 65 - 65: II111iiii . I1IiiI % oO0o * OoO0O00
 lisp_hostname = socket . gethostname ( )
 iI11I = lisp_hostname . find ( "." )
 if ( iI11I != - 1 ) : lisp_hostname = lisp_hostname [ 0 : iI11I ]
 return
 if 11 - 11: iII111i - oO0o + II111iiii - iIii1I11I1II1
 if 7 - 7: IiII - I11i / II111iiii * Ii1I . iII111i * iII111i
 if 61 - 61: I11i % ooOoO0o - OoO0O00 / Oo0Ooo
 if 4 - 4: OoooooooOO - i1IIi % Ii1I - OOooOOo * o0oOOo0O0Ooo
 if 85 - 85: OoooooooOO * iIii1I11I1II1 . iII111i / OoooooooOO % I1IiiI % O0
 if 36 - 36: Ii1I / II111iiii / IiII / IiII + I1ii11iIi11i
 if 95 - 95: IiII
def lprint ( * args ) :
 if ( lisp_debug_logging == False ) : return
 if 51 - 51: II111iiii + IiII . i1IIi . I1ii11iIi11i + OoOoOO00 * I1IiiI
 lisp_process_logfile ( )
 OOOO0O00o = datetime . datetime . now ( ) . strftime ( "%m/%d/%y %H:%M:%S.%f" )
 OOOO0O00o = OOOO0O00o [ : - 3 ]
 print "{}: {}:" . format ( OOOO0O00o , lisp_log_id ) ,
 for OOoOoo0 in args : print OOoOoo0 ,
 print ""
 try : sys . stdout . flush ( )
 except : pass
 return
 if 17 - 17: Ii1I + oO0o . OoO0O00 - Oo0Ooo * i11iIiiIii
 if 20 - 20: I1IiiI . OoooooooOO % OOooOOo
 if 63 - 63: I1IiiI % iIii1I11I1II1
 if 39 - 39: iII111i / II111iiii / I1ii11iIi11i % I1IiiI
 if 89 - 89: I1Ii111 + OoooooooOO + I1Ii111 * i1IIi + iIii1I11I1II1 % I11i
 if 59 - 59: OOooOOo + i11iIiiIii
 if 88 - 88: i11iIiiIii - ooOoO0o
 if 67 - 67: OOooOOo . Oo0Ooo + OoOoOO00 - OoooooooOO
def dprint ( * args ) :
 if ( lisp_data_plane_logging ) : lprint ( * args )
 return
 if 70 - 70: OOooOOo / II111iiii - iIii1I11I1II1 - iII111i
 if 11 - 11: iIii1I11I1II1 . OoooooooOO . II111iiii / i1IIi - I11i
 if 30 - 30: OoOoOO00
 if 21 - 21: i11iIiiIii / I1Ii111 % OOooOOo * O0 . I11i - iIii1I11I1II1
 if 26 - 26: II111iiii * OoOoOO00
 if 10 - 10: II111iiii . iII111i
 if 32 - 32: Ii1I . IiII . OoooooooOO - OoO0O00 + oO0o
 if 88 - 88: iII111i
def debug ( * args ) :
 lisp_process_logfile ( )
 if 19 - 19: II111iiii * IiII + Ii1I
 OOOO0O00o = datetime . datetime . now ( ) . strftime ( "%m/%d/%y %H:%M:%S.%f" )
 OOOO0O00o = OOOO0O00o [ : - 3 ]
 if 65 - 65: OOooOOo . I1Ii111 . OoO0O00 . iII111i - OOooOOo
 print red ( ">>>" , False ) ,
 print "{}:" . format ( OOOO0O00o ) ,
 for OOoOoo0 in args : print OOoOoo0 ,
 print red ( "<<<\n" , False )
 try : sys . stdout . flush ( )
 except : pass
 return
 if 19 - 19: i11iIiiIii + iII111i % ooOoO0o
 if 14 - 14: OoO0O00 . II111iiii . I11i / Ii1I % I1ii11iIi11i - ooOoO0o
 if 67 - 67: I11i - OOooOOo . i1IIi
 if 35 - 35: iII111i + ooOoO0o - oO0o . iII111i . IiII
 if 87 - 87: OoOoOO00
 if 25 - 25: i1IIi . OoO0O00 - OoOoOO00 / OoO0O00 % OoO0O00 * iIii1I11I1II1
 if 50 - 50: OoO0O00 . i11iIiiIii - oO0o . oO0o
def lisp_print_banner ( string ) :
 global lisp_version , lisp_hostname
 if 31 - 31: OOooOOo / Oo0Ooo * i1IIi . OoOoOO00
 if ( lisp_version == "" ) :
  lisp_version = commands . getoutput ( "cat lisp-version.txt" )
  if 57 - 57: OOooOOo + iIii1I11I1II1 % i1IIi % I1IiiI
 OO0oo = bold ( lisp_hostname , False )
 lprint ( "lispers.net LISP {} {}, version {}, hostname {}" . format ( string ,
 datetime . datetime . now ( ) , lisp_version , OO0oo ) )
 return
 if 15 - 15: iIii1I11I1II1 % OoooooooOO - Oo0Ooo * Ii1I + I11i
 if 11 - 11: iII111i * Ii1I - OoOoOO00
 if 66 - 66: OoOoOO00 . i11iIiiIii - iII111i * o0oOOo0O0Ooo + OoooooooOO * I1ii11iIi11i
 if 74 - 74: Oo0Ooo
 if 61 - 61: Oo0Ooo - I1Ii111 * II111iiii % ooOoO0o * iIii1I11I1II1 + OoO0O00
 if 71 - 71: I11i / I11i * oO0o * oO0o / II111iiii
 if 35 - 35: OOooOOo * o0oOOo0O0Ooo * I1IiiI % Oo0Ooo . OoOoOO00
def green ( string , html ) :
 if ( html ) : return ( '<font color="green"><b>{}</b></font>' . format ( string ) )
 return ( bold ( "\033[92m" + string + "\033[0m" , html ) )
 if 58 - 58: I11i + II111iiii * iII111i * i11iIiiIii - iIii1I11I1II1
 if 68 - 68: OoooooooOO % II111iiii
 if 26 - 26: II111iiii % i11iIiiIii % iIii1I11I1II1 % I11i * I11i * I1ii11iIi11i
 if 24 - 24: II111iiii % I1Ii111 - ooOoO0o + I1IiiI * I1ii11iIi11i
 if 2 - 2: Ii1I - IiII
 if 83 - 83: oO0o % o0oOOo0O0Ooo % Ii1I - II111iiii * OOooOOo / OoooooooOO
 if 18 - 18: OoO0O00 + iIii1I11I1II1 - II111iiii - I1IiiI
def green_last_sec ( string ) :
 return ( green ( string , True ) )
 if 71 - 71: OoooooooOO
 if 33 - 33: I1Ii111
 if 62 - 62: I1ii11iIi11i + Ii1I + i1IIi / OoooooooOO
 if 7 - 7: o0oOOo0O0Ooo + i1IIi . I1IiiI / Oo0Ooo
 if 22 - 22: ooOoO0o - ooOoO0o % OOooOOo . I1Ii111 + oO0o
 if 63 - 63: I1IiiI % I1Ii111 * o0oOOo0O0Ooo + I1Ii111 / Oo0Ooo % iII111i
 if 45 - 45: IiII
def green_last_min ( string ) :
 return ( '<font color="#58D68D"><b>{}</b></font>' . format ( string ) )
 if 20 - 20: OoooooooOO * o0oOOo0O0Ooo * O0 . OOooOOo
 if 78 - 78: iIii1I11I1II1 + I11i - Ii1I * I1Ii111 - OoooooooOO % OoOoOO00
 if 34 - 34: O0
 if 80 - 80: i1IIi - Oo0Ooo / OoO0O00 - i11iIiiIii
 if 68 - 68: oO0o - I1ii11iIi11i % O0 % I1Ii111
 if 11 - 11: O0 / OoO0O00 % OOooOOo + o0oOOo0O0Ooo + iIii1I11I1II1
 if 40 - 40: ooOoO0o - OOooOOo . Ii1I * Oo0Ooo % I1Ii111
def red ( string , html ) :
 if ( html ) : return ( '<font color="red"><b>{}</b></font>' . format ( string ) )
 return ( bold ( "\033[91m" + string + "\033[0m" , html ) )
 if 56 - 56: i11iIiiIii . o0oOOo0O0Ooo - I1IiiI * I11i
 if 91 - 91: oO0o + OoooooooOO - i1IIi
 if 84 - 84: Ii1I / IiII
 if 86 - 86: OoOoOO00 * II111iiii - O0 . OoOoOO00 % iIii1I11I1II1 / OOooOOo
 if 11 - 11: I1IiiI * oO0o + I1ii11iIi11i / I1ii11iIi11i
 if 37 - 37: i11iIiiIii + i1IIi
 if 23 - 23: iII111i + I11i . OoOoOO00 * I1IiiI + I1ii11iIi11i
def blue ( string , html ) :
 if ( html ) : return ( '<font color="blue"><b>{}</b></font>' . format ( string ) )
 return ( bold ( "\033[94m" + string + "\033[0m" , html ) )
 if 18 - 18: IiII * o0oOOo0O0Ooo . IiII / O0
 if 8 - 8: o0oOOo0O0Ooo
 if 4 - 4: I1ii11iIi11i + I1ii11iIi11i * ooOoO0o - OoOoOO00
 if 78 - 78: Ii1I / II111iiii % OoOoOO00
 if 52 - 52: OOooOOo - iII111i * oO0o
 if 17 - 17: OoooooooOO + OOooOOo * I11i * OoOoOO00
 if 36 - 36: O0 + Oo0Ooo
def bold ( string , html ) :
 if ( html ) : return ( "<b>{}</b>" . format ( string ) )
 return ( "\033[1m" + string + "\033[0m" )
 if 5 - 5: Oo0Ooo * OoOoOO00
 if 46 - 46: ooOoO0o
 if 33 - 33: iII111i - II111iiii * OoooooooOO - Oo0Ooo - OOooOOo
 if 84 - 84: I1Ii111 + Oo0Ooo - OoOoOO00 * OoOoOO00
 if 61 - 61: OoooooooOO . oO0o . OoooooooOO / Oo0Ooo
 if 72 - 72: i1IIi
 if 82 - 82: OoOoOO00 + OoooooooOO / i11iIiiIii * I1ii11iIi11i . OoooooooOO
def convert_font ( string ) :
 oooo0OOo = [ [ "[91m" , red ] , [ "[92m" , green ] , [ "[94m" , blue ] , [ "[1m" , bold ] ]
 OoO00 = "[0m"
 if 18 - 18: Ii1I - OoooooooOO % II111iiii - I1IiiI % OoOoOO00
 for ooo0OO in oooo0OOo :
  iIi1IiI = ooo0OO [ 0 ]
  I11IIIiIi11 = ooo0OO [ 1 ]
  I11iiIi1i1 = len ( iIi1IiI )
  iI11I = string . find ( iIi1IiI )
  if ( iI11I != - 1 ) : break
  if 41 - 41: Ii1I % I1ii11iIi11i
  if 12 - 12: OOooOOo
 while ( iI11I != - 1 ) :
  ooOo0O = string [ iI11I : : ] . find ( OoO00 )
  i1I1IIIiiI = string [ iI11I + I11iiIi1i1 : iI11I + ooOo0O ]
  string = string [ : iI11I ] + I11IIIiIi11 ( i1I1IIIiiI , True ) + string [ iI11I + ooOo0O + I11iiIi1i1 : : ]
  if 71 - 71: OOooOOo * OoO0O00 % OoooooooOO % OoO0O00 / I1IiiI
  iI11I = string . find ( iIi1IiI )
  if 56 - 56: OoooooooOO % i11iIiiIii * iIii1I11I1II1 . OoO0O00 * O0
  if 23 - 23: i11iIiiIii
  if 39 - 39: o0oOOo0O0Ooo - I1ii11iIi11i % iII111i * OoO0O00 - OOooOOo / iII111i
  if 29 - 29: I1ii11iIi11i
  if 52 - 52: i11iIiiIii / i1IIi
 if ( string . find ( "[1m" ) != - 1 ) : string = convert_font ( string )
 return ( string )
 if 1 - 1: ooOoO0o
 if 78 - 78: I1ii11iIi11i + I11i - O0
 if 10 - 10: I1Ii111 % I1IiiI
 if 97 - 97: OoooooooOO - I1Ii111
 if 58 - 58: iIii1I11I1II1 + O0
 if 30 - 30: ooOoO0o % iII111i * OOooOOo - I1ii11iIi11i * Ii1I % ooOoO0o
 if 46 - 46: i11iIiiIii - O0 . oO0o
def lisp_space ( num ) :
 Oo0O = ""
 for Ii11 in range ( num ) : Oo0O += "&#160;"
 return ( Oo0O )
 if 8 - 8: Oo0Ooo + II111iiii * OOooOOo * OoOoOO00 * I11i / IiII
 if 21 - 21: oO0o / OoooooooOO
 if 11 - 11: OOooOOo % Ii1I - i11iIiiIii - oO0o + ooOoO0o + IiII
 if 87 - 87: I1Ii111 * i1IIi / I1ii11iIi11i
 if 6 - 6: o0oOOo0O0Ooo + Oo0Ooo - OoooooooOO % OOooOOo * OoOoOO00
 if 69 - 69: i1IIi
 if 59 - 59: II111iiii - o0oOOo0O0Ooo
def lisp_button ( string , url ) :
 iIIi1I1ii = '<button style="background-color:transparent;border-radius:10px; ' + 'type="button">'
 if 14 - 14: O0 / i1IIi / Oo0Ooo + iIii1I11I1II1
 if 96 - 96: iII111i
 if ( url == None ) :
  i1I11iIII1i1I = iIIi1I1ii + string + "</button>"
 else :
  oOO0oo = '<a href="{}">' . format ( url )
  IiIIi1I1I11Ii = lisp_space ( 2 )
  i1I11iIII1i1I = IiIIi1I1I11Ii + oOO0oo + iIIi1I1ii + string + "</button></a>" + IiIIi1I1I11Ii
  if 64 - 64: OoooooooOO
 return ( i1I11iIII1i1I )
 if 81 - 81: I1ii11iIi11i - O0 * OoooooooOO
 if 23 - 23: II111iiii / oO0o
 if 28 - 28: Oo0Ooo * ooOoO0o - OoO0O00
 if 19 - 19: I11i
 if 67 - 67: O0 % iIii1I11I1II1 / IiII . i11iIiiIii - Ii1I + O0
 if 27 - 27: OOooOOo
 if 89 - 89: II111iiii / oO0o
def lisp_print_cour ( string ) :
 Oo0O = '<font face="Courier New">{}</font>' . format ( string )
 return ( Oo0O )
 if 14 - 14: OOooOOo . I1IiiI * ooOoO0o + II111iiii - ooOoO0o + OOooOOo
 if 18 - 18: oO0o - o0oOOo0O0Ooo - I1IiiI - I1IiiI
 if 54 - 54: Oo0Ooo + I1IiiI / iII111i . I1IiiI * OoOoOO00
 if 1 - 1: OoOoOO00 * OoO0O00 . i1IIi / Oo0Ooo . I1ii11iIi11i + Oo0Ooo
 if 17 - 17: Oo0Ooo + OoO0O00 / Ii1I / iII111i * OOooOOo
 if 29 - 29: OoO0O00 % OoooooooOO * oO0o / II111iiii - oO0o
 if 19 - 19: i11iIiiIii
def lisp_print_sans ( string ) :
 Oo0O = '<font face="Sans-Serif">{}</font>' . format ( string )
 return ( Oo0O )
 if 54 - 54: II111iiii . I11i
 if 73 - 73: OoOoOO00 . I1IiiI
 if 32 - 32: OoOoOO00 * I1IiiI % ooOoO0o * Ii1I . O0
 if 48 - 48: iII111i * iII111i
 if 13 - 13: Ii1I / I11i + OoOoOO00 . o0oOOo0O0Ooo % ooOoO0o
 if 48 - 48: I1IiiI / i11iIiiIii - o0oOOo0O0Ooo * oO0o / OoooooooOO
 if 89 - 89: iIii1I11I1II1 / I1IiiI - II111iiii / Ii1I . i11iIiiIii . Ii1I
def lisp_span ( string , hover_string ) :
 Oo0O = '<span title="{}">{}</span>' . format ( hover_string , string )
 return ( Oo0O )
 if 48 - 48: O0 + O0 . I1Ii111 - ooOoO0o
 if 63 - 63: oO0o
 if 71 - 71: i1IIi . Ii1I * iII111i % OoooooooOO + OOooOOo
 if 36 - 36: IiII
 if 49 - 49: OOooOOo / OoooooooOO / I1IiiI
 if 74 - 74: I1Ii111 % I1ii11iIi11i
 if 7 - 7: II111iiii
def lisp_eid_help_hover ( output ) :
 iI = '''Unicast EID format:
  For longest match lookups: 
    <address> or [<iid>]<address>
  For exact match lookups: 
    <prefix> or [<iid>]<prefix>
Multicast EID format:
  For longest match lookups:
    <address>-><group> or
    [<iid>]<address>->[<iid>]<group>'''
 if 38 - 38: IiII . Ii1I
 if 24 - 24: o0oOOo0O0Ooo - o0oOOo0O0Ooo + I1ii11iIi11i + I1IiiI - oO0o
 I1 = lisp_span ( output , iI )
 return ( I1 )
 if 13 - 13: OoOoOO00 / I1ii11iIi11i . OOooOOo * I11i - Oo0Ooo / oO0o
 if 8 - 8: OoOoOO00 / O0 * O0 % I1Ii111 - Oo0Ooo + I11i
 if 83 - 83: O0 . I1IiiI
 if 95 - 95: I11i . OoooooooOO - i1IIi - OoooooooOO - OoO0O00 % iIii1I11I1II1
 if 64 - 64: OOooOOo + OoooooooOO * OoooooooOO
 if 41 - 41: ooOoO0o . Oo0Ooo + I1IiiI
 if 100 - 100: Ii1I + OoO0O00
def lisp_geo_help_hover ( output ) :
 iI = '''EID format:
    <address> or [<iid>]<address>
    '<name>' or [<iid>]'<name>'
Geo-Point format:
    d-m-s-<N|S>-d-m-s-<W|E> or 
    [<iid>]d-m-s-<N|S>-d-m-s-<W|E>
Geo-Prefix format:
    d-m-s-<N|S>-d-m-s-<W|E>/<km> or
    [<iid>]d-m-s-<N|S>-d-m-s-<W|E>/<km>'''
 if 73 - 73: i1IIi - I1Ii111 % ooOoO0o / OoO0O00
 if 40 - 40: I1ii11iIi11i * ooOoO0o - I1IiiI / IiII / i11iIiiIii
 I1 = lisp_span ( output , iI )
 return ( I1 )
 if 83 - 83: I1ii11iIi11i / I1Ii111 - i11iIiiIii . iIii1I11I1II1 + Oo0Ooo
 if 59 - 59: O0 % Oo0Ooo
 if 92 - 92: Ii1I % iII111i / I1ii11iIi11i % I1ii11iIi11i * I1IiiI
 if 74 - 74: O0 . I1IiiI % OoO0O00 % IiII
 if 87 - 87: oO0o - i11iIiiIii
 if 78 - 78: i11iIiiIii / iIii1I11I1II1 - o0oOOo0O0Ooo
 if 23 - 23: I11i
def space ( num ) :
 Oo0O = ""
 for Ii11 in range ( num ) : Oo0O += "&#160;"
 return ( Oo0O )
 if 40 - 40: o0oOOo0O0Ooo - II111iiii / Oo0Ooo
 if 14 - 14: I1ii11iIi11i
 if 5 - 5: o0oOOo0O0Ooo . iIii1I11I1II1 % iIii1I11I1II1
 if 56 - 56: OoooooooOO - I11i - i1IIi
 if 8 - 8: I1Ii111 / OOooOOo . I1IiiI + I1ii11iIi11i / i11iIiiIii
 if 31 - 31: ooOoO0o - iIii1I11I1II1 + iII111i . Oo0Ooo / IiII % iIii1I11I1II1
 if 6 - 6: IiII * i11iIiiIii % iIii1I11I1II1 % i11iIiiIii + o0oOOo0O0Ooo / i1IIi
 if 53 - 53: I11i + iIii1I11I1II1
def lisp_get_ephemeral_port ( ) :
 return ( random . randrange ( 32768 , 65535 ) )
 if 70 - 70: I1ii11iIi11i
 if 67 - 67: OoooooooOO
 if 29 - 29: O0 - i11iIiiIii - II111iiii + OOooOOo * IiII
 if 2 - 2: i1IIi - ooOoO0o + I1IiiI . o0oOOo0O0Ooo * o0oOOo0O0Ooo / OoOoOO00
 if 93 - 93: i1IIi
 if 53 - 53: OoooooooOO + Oo0Ooo + oO0o
 if 24 - 24: iII111i - IiII - iII111i * I1ii11iIi11i . OoooooooOO / IiII
def lisp_get_data_nonce ( ) :
 return ( random . randint ( 0 , 0xffffff ) )
 if 66 - 66: Oo0Ooo
 if 97 - 97: i1IIi - OoooooooOO / I1Ii111 * I1IiiI
 if 55 - 55: o0oOOo0O0Ooo . iII111i
 if 87 - 87: o0oOOo0O0Ooo % iIii1I11I1II1
 if 100 - 100: I1Ii111 . I1IiiI * I1Ii111 - I1IiiI . I11i * Ii1I
 if 89 - 89: OoO0O00 + IiII * I1Ii111
 if 28 - 28: OoooooooOO . oO0o % I1ii11iIi11i / i1IIi / OOooOOo
def lisp_get_control_nonce ( ) :
 return ( random . randint ( 0 , ( 2 ** 64 ) - 1 ) )
 if 36 - 36: o0oOOo0O0Ooo + I11i - IiII + iIii1I11I1II1 + OoooooooOO
 if 4 - 4: II111iiii . I11i + Ii1I * I1Ii111 . ooOoO0o
 if 87 - 87: OoOoOO00 / OoO0O00 / i11iIiiIii
 if 74 - 74: oO0o / I1ii11iIi11i % o0oOOo0O0Ooo
 if 88 - 88: OoOoOO00 - i11iIiiIii % o0oOOo0O0Ooo * I11i + I1ii11iIi11i
 if 52 - 52: II111iiii . I1IiiI + OoOoOO00 % OoO0O00
 if 62 - 62: o0oOOo0O0Ooo
 if 15 - 15: I11i + Ii1I . OOooOOo * OoO0O00 . OoOoOO00
 if 18 - 18: i1IIi % II111iiii + I1Ii111 % Ii1I
def lisp_hex_string ( integer_value ) :
 oOO = hex ( integer_value ) [ 2 : : ]
 if ( oOO [ - 1 ] == "L" ) : oOO = oOO [ 0 : - 1 ]
 return ( oOO )
 if 53 - 53: o0oOOo0O0Ooo % Oo0Ooo * Oo0Ooo
 if 77 - 77: OOooOOo - IiII . I11i / I1IiiI + OoO0O00 % oO0o
 if 12 - 12: i1IIi
 if 63 - 63: IiII + o0oOOo0O0Ooo
 if 1 - 1: I1ii11iIi11i / OoO0O00 + oO0o . o0oOOo0O0Ooo / I1ii11iIi11i - iII111i
 if 5 - 5: OOooOOo
 if 4 - 4: iII111i % I1Ii111 / OoO0O00 . OOooOOo / OOooOOo - I1ii11iIi11i
def lisp_get_timestamp ( ) :
 return ( time . time ( ) )
 if 79 - 79: I1ii11iIi11i + I1Ii111
 if 10 - 10: Oo0Ooo + O0
 if 43 - 43: iIii1I11I1II1 / II111iiii % o0oOOo0O0Ooo - OOooOOo
 if 62 - 62: I11i
 if 63 - 63: OOooOOo + ooOoO0o * oO0o / o0oOOo0O0Ooo / Oo0Ooo * iIii1I11I1II1
 if 57 - 57: OoOoOO00 - oO0o / ooOoO0o % i11iIiiIii
 if 3 - 3: iII111i . ooOoO0o % I1IiiI + I1ii11iIi11i
def lisp_set_timestamp ( seconds ) :
 return ( time . time ( ) + seconds )
 if 64 - 64: i1IIi
 if 29 - 29: o0oOOo0O0Ooo / i11iIiiIii / I1IiiI % oO0o % i11iIiiIii
 if 18 - 18: OOooOOo + I1Ii111
 if 80 - 80: oO0o + o0oOOo0O0Ooo * Ii1I + OoO0O00
 if 75 - 75: I11i / o0oOOo0O0Ooo / OOooOOo / IiII % ooOoO0o + II111iiii
 if 4 - 4: iII111i - Oo0Ooo - IiII - I11i % i11iIiiIii / OoO0O00
 if 50 - 50: ooOoO0o + i1IIi
def lisp_print_elapsed ( ts ) :
 if ( ts == 0 or ts == None ) : return ( "never" )
 i11IiIIi11I = time . time ( ) - ts
 i11IiIIi11I = round ( i11IiIIi11I , 0 )
 return ( str ( datetime . timedelta ( seconds = i11IiIIi11I ) ) )
 if 78 - 78: IiII
 if 83 - 83: iIii1I11I1II1 % OoOoOO00 % o0oOOo0O0Ooo % I1Ii111 . I1ii11iIi11i % O0
 if 47 - 47: o0oOOo0O0Ooo
 if 66 - 66: I1IiiI - IiII
 if 33 - 33: I1IiiI / OoO0O00
 if 12 - 12: II111iiii
 if 2 - 2: i1IIi - I1IiiI + I11i . II111iiii
def lisp_print_future ( ts ) :
 if ( ts == 0 ) : return ( "never" )
 iIIiI1iiI = ts - time . time ( )
 if ( iIIiI1iiI < 0 ) : return ( "expired" )
 iIIiI1iiI = round ( iIIiI1iiI , 0 )
 return ( str ( datetime . timedelta ( seconds = iIIiI1iiI ) ) )
 if 18 - 18: iII111i - oO0o % iII111i / I11i
 if 68 - 68: Ii1I * iIii1I11I1II1 + I1Ii111 % OoOoOO00
 if 46 - 46: OoOoOO00 % i1IIi / oO0o * Oo0Ooo * OOooOOo
 if 67 - 67: OoOoOO00 * OoOoOO00 . OoOoOO00 + Ii1I / oO0o
 if 13 - 13: iII111i
 if 80 - 80: Ii1I - o0oOOo0O0Ooo
 if 41 - 41: o0oOOo0O0Ooo - Oo0Ooo * I1IiiI
 if 82 - 82: OoO0O00 % o0oOOo0O0Ooo % OOooOOo / O0
 if 94 - 94: I1ii11iIi11i + I1ii11iIi11i + OoooooooOO % ooOoO0o
 if 7 - 7: iII111i
 if 78 - 78: OOooOOo + iII111i . IiII
 if 91 - 91: iIii1I11I1II1 . o0oOOo0O0Ooo . I1ii11iIi11i + OoooooooOO
 if 69 - 69: I1Ii111 - I1IiiI
def lisp_print_eid_tuple ( eid , group ) :
 oOoo0OooOOo00 = eid . print_prefix ( )
 if ( group . is_null ( ) ) : return ( oOoo0OooOOo00 )
 if 36 - 36: i1IIi * Oo0Ooo % Oo0Ooo / o0oOOo0O0Ooo + OoOoOO00 - OoooooooOO
 Ii11iii1II1i = group . print_prefix ( )
 o0OOoOO = group . instance_id
 if 46 - 46: oO0o / iII111i - i1IIi
 if ( eid . is_null ( ) or eid . is_exact_match ( group ) ) :
  iI11I = Ii11iii1II1i . find ( "]" ) + 1
  return ( "[{}](*, {})" . format ( o0OOoOO , Ii11iii1II1i [ iI11I : : ] ) )
  if 51 - 51: Oo0Ooo - I1ii11iIi11i * I11i
  if 12 - 12: iIii1I11I1II1 % ooOoO0o % ooOoO0o
 o0 = eid . print_sg ( group )
 return ( o0 )
 if 9 - 9: ooOoO0o % oO0o . Ii1I
 if 32 - 32: I1IiiI
 if 78 - 78: OoOoOO00 - OoO0O00 % ooOoO0o
 if 80 - 80: I1Ii111 . I11i
 if 73 - 73: OoOoOO00 . O0 / iII111i * oO0o
 if 29 - 29: o0oOOo0O0Ooo
 if 86 - 86: II111iiii . IiII
 if 2 - 2: OoooooooOO
def lisp_convert_6to4 ( addr_str ) :
 if ( addr_str . find ( "::ffff:" ) == - 1 ) : return ( addr_str )
 o0o0O00 = addr_str . split ( ":" )
 return ( o0o0O00 [ - 1 ] )
 if 35 - 35: iIii1I11I1II1
 if 94 - 94: OoOoOO00
 if 100 - 100: OoO0O00 / i1IIi - I1IiiI % Ii1I - iIii1I11I1II1
 if 17 - 17: I11i / o0oOOo0O0Ooo % Oo0Ooo
 if 71 - 71: IiII . I1Ii111 . OoO0O00
 if 68 - 68: i11iIiiIii % oO0o * OoO0O00 * IiII * II111iiii + O0
 if 66 - 66: I11i % I1ii11iIi11i % OoooooooOO
 if 34 - 34: o0oOOo0O0Ooo / iII111i % O0 . OoO0O00 . i1IIi
 if 29 - 29: O0 . I1Ii111
 if 66 - 66: oO0o * iIii1I11I1II1 % iIii1I11I1II1 * IiII - ooOoO0o - IiII
 if 70 - 70: I1Ii111 + oO0o
def lisp_convert_4to6 ( addr_str ) :
 o0o0O00 = lisp_address ( LISP_AFI_IPV6 , "" , 128 , 0 )
 if ( o0o0O00 . is_ipv4_string ( addr_str ) ) : addr_str = "::ffff:" + addr_str
 o0o0O00 . store_address ( addr_str )
 return ( o0o0O00 )
 if 93 - 93: I1Ii111 + Ii1I
 if 33 - 33: O0
 if 78 - 78: O0 / II111iiii * OoO0O00
 if 50 - 50: OoooooooOO - iIii1I11I1II1 + i1IIi % I1Ii111 - iIii1I11I1II1 % O0
 if 58 - 58: IiII + iIii1I11I1II1
 if 65 - 65: II111iiii - I1Ii111 % o0oOOo0O0Ooo - OoOoOO00 * iII111i + Ii1I
 if 79 - 79: ooOoO0o . OoOoOO00 % I1Ii111 - Oo0Ooo
 if 69 - 69: ooOoO0o - o0oOOo0O0Ooo . ooOoO0o
 if 9 - 9: oO0o % i11iIiiIii / Oo0Ooo
def lisp_gethostbyname ( string ) :
 IIIiI1ii1IIi = string . split ( "." )
 o0O0oo0o = string . split ( ":" )
 II11iI1iiI = string . split ( "-" )
 if 48 - 48: I11i . OoooooooOO . I1IiiI . OoOoOO00 % I1ii11iIi11i / iII111i
 if ( len ( IIIiI1ii1IIi ) > 1 ) :
  if ( IIIiI1ii1IIi [ 0 ] . isdigit ( ) ) : return ( string )
  if 11 - 11: i1IIi % OoO0O00 % iII111i
 if ( len ( o0O0oo0o ) > 1 ) :
  try :
   int ( o0O0oo0o [ 0 ] , 16 )
   return ( string )
  except :
   pass
   if 99 - 99: ooOoO0o / iIii1I11I1II1 - Ii1I * I1ii11iIi11i % I1IiiI
   if 13 - 13: OoO0O00
   if 70 - 70: I1Ii111 + O0 . oO0o * Ii1I
   if 2 - 2: OoooooooOO . OOooOOo . IiII
   if 42 - 42: OOooOOo % oO0o / OoO0O00 - oO0o * i11iIiiIii
   if 19 - 19: oO0o * I1IiiI % i11iIiiIii
   if 24 - 24: o0oOOo0O0Ooo
 if ( len ( II11iI1iiI ) == 3 ) :
  for Ii11 in range ( 3 ) :
   try : int ( II11iI1iiI [ Ii11 ] , 16 )
   except : break
   if 10 - 10: o0oOOo0O0Ooo % Ii1I / OOooOOo
   if 28 - 28: OOooOOo % ooOoO0o
   if 48 - 48: i11iIiiIii % oO0o
 try :
  o0o0O00 = socket . gethostbyname ( string )
  return ( o0o0O00 )
 except :
  if ( lisp_is_alpine ( ) == False ) : return ( "" )
  if 29 - 29: iII111i + i11iIiiIii % I11i
  if 93 - 93: OoOoOO00 % iIii1I11I1II1
  if 90 - 90: I1IiiI - OOooOOo / Ii1I / O0 / I11i
  if 87 - 87: OoOoOO00 / IiII + iIii1I11I1II1
  if 93 - 93: iIii1I11I1II1 + oO0o % ooOoO0o
 try :
  o0o0O00 = socket . getaddrinfo ( string , 0 ) [ 0 ]
  if ( o0o0O00 [ 3 ] != string ) : return ( "" )
  o0o0O00 = o0o0O00 [ 4 ] [ 0 ]
 except :
  o0o0O00 = ""
  if 21 - 21: OOooOOo
 return ( o0o0O00 )
 if 6 - 6: IiII
 if 46 - 46: IiII + oO0o
 if 79 - 79: OoooooooOO - IiII * IiII . OoOoOO00
 if 100 - 100: II111iiii * I11i % I1IiiI / I1ii11iIi11i
 if 90 - 90: I1ii11iIi11i . ooOoO0o . OoOoOO00 . Ii1I
 if 4 - 4: Ii1I + OoOoOO00 % I1ii11iIi11i / i11iIiiIii
 if 74 - 74: II111iiii . O0 - I1IiiI + IiII % i11iIiiIii % OoOoOO00
 if 78 - 78: Ii1I + OoOoOO00 + IiII - IiII . i11iIiiIii / OoO0O00
def lisp_ip_checksum ( data ) :
 if ( len ( data ) < 20 ) :
  lprint ( "IPv4 packet too short, length {}" . format ( len ( data ) ) )
  return ( data )
  if 27 - 27: Ii1I - O0 % I11i * I1Ii111 . IiII % iIii1I11I1II1
  if 37 - 37: OoooooooOO + O0 - i1IIi % ooOoO0o
 i1I1i1i = binascii . hexlify ( data )
 if 36 - 36: II111iiii % O0
 if 35 - 35: iIii1I11I1II1 - OOooOOo % o0oOOo0O0Ooo
 if 30 - 30: I1Ii111 % I1Ii111 % IiII . OoOoOO00
 if 9 - 9: ooOoO0o / II111iiii . OoOoOO00 % o0oOOo0O0Ooo * II111iiii - ooOoO0o
 oOOoo0 = 0
 for Ii11 in range ( 0 , 40 , 4 ) :
  oOOoo0 += int ( i1I1i1i [ Ii11 : Ii11 + 4 ] , 16 )
  if 24 - 24: OoO0O00 - oO0o + I1ii11iIi11i / iII111i % I1IiiI + iIii1I11I1II1
  if 79 - 79: OoOoOO00 / ooOoO0o
  if 77 - 77: Oo0Ooo
  if 46 - 46: I1Ii111
  if 72 - 72: iII111i * OOooOOo
 oOOoo0 = ( oOOoo0 >> 16 ) + ( oOOoo0 & 0xffff )
 oOOoo0 += oOOoo0 >> 16
 oOOoo0 = socket . htons ( ~ oOOoo0 & 0xffff )
 if 67 - 67: i1IIi
 if 5 - 5: II111iiii . OoooooooOO
 if 57 - 57: I1IiiI
 if 35 - 35: OoooooooOO - I1Ii111 / OoO0O00
 oOOoo0 = struct . pack ( "H" , oOOoo0 )
 i1I1i1i = data [ 0 : 10 ] + oOOoo0 + data [ 12 : : ]
 return ( i1I1i1i )
 if 50 - 50: OoOoOO00
 if 33 - 33: I11i
 if 98 - 98: OoOoOO00 % II111iiii
 if 95 - 95: iIii1I11I1II1 - I1Ii111 - OOooOOo + I1Ii111 % I1ii11iIi11i . I1IiiI
 if 41 - 41: O0 + oO0o . i1IIi - II111iiii * o0oOOo0O0Ooo . OoO0O00
 if 68 - 68: o0oOOo0O0Ooo
 if 20 - 20: I1Ii111 - I1Ii111
 if 37 - 37: IiII
 if 37 - 37: Oo0Ooo / IiII * O0
 if 73 - 73: iII111i * iII111i / ooOoO0o
 if 43 - 43: I1ii11iIi11i . i1IIi . IiII + O0 * Ii1I * O0
 if 41 - 41: I1ii11iIi11i + Ii1I % OoooooooOO . I1ii11iIi11i + iII111i . iII111i
 if 31 - 31: i11iIiiIii + II111iiii . iII111i * OoOoOO00
 if 66 - 66: OoOoOO00 + i1IIi % II111iiii . O0 * I1ii11iIi11i % I1ii11iIi11i
 if 87 - 87: OOooOOo + o0oOOo0O0Ooo . iII111i - OoooooooOO
 if 6 - 6: iIii1I11I1II1 * OoooooooOO
 if 28 - 28: Oo0Ooo * o0oOOo0O0Ooo / I1Ii111
 if 52 - 52: O0 / o0oOOo0O0Ooo % iII111i * I1IiiI % OOooOOo
 if 69 - 69: I1ii11iIi11i
 if 83 - 83: o0oOOo0O0Ooo
 if 38 - 38: I1Ii111 + OoooooooOO . i1IIi
 if 19 - 19: iII111i - o0oOOo0O0Ooo - Ii1I - OoOoOO00 . iII111i . I1Ii111
 if 48 - 48: iII111i + IiII
 if 60 - 60: I11i + iII111i . IiII / i1IIi . iIii1I11I1II1
 if 14 - 14: OOooOOo
 if 79 - 79: Ii1I
 if 76 - 76: iIii1I11I1II1
 if 80 - 80: iIii1I11I1II1 . O0 / Ii1I % Ii1I
 if 93 - 93: OoooooooOO * Oo0Ooo
 if 10 - 10: I1Ii111 * OoooooooOO + I11i - I1ii11iIi11i / I1ii11iIi11i . i11iIiiIii
 if 22 - 22: I1Ii111 / o0oOOo0O0Ooo
 if 98 - 98: i1IIi
 if 51 - 51: I1ii11iIi11i + ooOoO0o + Oo0Ooo / i1IIi + i1IIi
 if 12 - 12: iIii1I11I1II1 . Ii1I . I1ii11iIi11i % I1IiiI . II111iiii . oO0o
 if 32 - 32: I1ii11iIi11i + IiII / O0 / OoOoOO00 * OoooooooOO % ooOoO0o
def lisp_udp_checksum ( source , dest , data ) :
 if 50 - 50: OoO0O00
 if 66 - 66: iIii1I11I1II1
 if 41 - 41: I1Ii111 . O0 * I1IiiI * I1ii11iIi11i
 if 100 - 100: iII111i
 IiIIi1I1I11Ii = lisp_address ( LISP_AFI_IPV6 , source , LISP_IPV6_HOST_MASK_LEN , 0 )
 oOo0OOOOOO = lisp_address ( LISP_AFI_IPV6 , dest , LISP_IPV6_HOST_MASK_LEN , 0 )
 IiI = socket . htonl ( len ( data ) )
 oooO0oOoo = socket . htonl ( LISP_UDP_PROTOCOL )
 OoOOoO0O0oO = IiIIi1I1I11Ii . pack_address ( )
 OoOOoO0O0oO += oOo0OOOOOO . pack_address ( )
 OoOOoO0O0oO += struct . pack ( "II" , IiI , oooO0oOoo )
 if 92 - 92: Oo0Ooo / i11iIiiIii + I1ii11iIi11i
 if 87 - 87: OoOoOO00 % iIii1I11I1II1
 if 72 - 72: OOooOOo . OOooOOo - I1ii11iIi11i
 if 48 - 48: Oo0Ooo - ooOoO0o + Oo0Ooo - I1IiiI * i11iIiiIii . iII111i
 I1iIIIiI = binascii . hexlify ( OoOOoO0O0oO + data )
 Oo = len ( I1iIIIiI ) % 4
 for Ii11 in range ( 0 , Oo ) : I1iIIIiI += "0"
 if 34 - 34: I1IiiI
 if 47 - 47: I1Ii111 - OOooOOo / ooOoO0o - Oo0Ooo + iII111i - iIii1I11I1II1
 if 68 - 68: Ii1I - oO0o + Oo0Ooo
 if 44 - 44: Ii1I * o0oOOo0O0Ooo * II111iiii
 oOOoo0 = 0
 for Ii11 in range ( 0 , len ( I1iIIIiI ) , 4 ) :
  oOOoo0 += int ( I1iIIIiI [ Ii11 : Ii11 + 4 ] , 16 )
  if 5 - 5: i1IIi + O0 % O0 * O0 + OoOoOO00 % i1IIi
  if 80 - 80: iII111i / o0oOOo0O0Ooo + OoO0O00 / oO0o
  if 46 - 46: i11iIiiIii / IiII % i1IIi - I11i * OoOoOO00
  if 94 - 94: Ii1I - I1ii11iIi11i + o0oOOo0O0Ooo - Oo0Ooo
  if 15 - 15: OOooOOo
 oOOoo0 = ( oOOoo0 >> 16 ) + ( oOOoo0 & 0xffff )
 oOOoo0 += oOOoo0 >> 16
 oOOoo0 = socket . htons ( ~ oOOoo0 & 0xffff )
 if 31 - 31: iII111i / i1IIi . OoO0O00
 if 83 - 83: oO0o / iIii1I11I1II1 + i1IIi / iII111i
 if 47 - 47: oO0o + OoooooooOO . II111iiii . iII111i
 if 66 - 66: ooOoO0o * OoOoOO00
 oOOoo0 = struct . pack ( "H" , oOOoo0 )
 I1iIIIiI = data [ 0 : 6 ] + oOOoo0 + data [ 8 : : ]
 return ( I1iIIIiI )
 if 2 - 2: oO0o . I1Ii111 * Oo0Ooo + O0 - I11i * iIii1I11I1II1
 if 12 - 12: o0oOOo0O0Ooo * I1Ii111 % II111iiii * i1IIi * iIii1I11I1II1
 if 81 - 81: Oo0Ooo - I11i
 if 24 - 24: OoooooooOO . OoO0O00 * II111iiii
 if 59 - 59: I1Ii111 + OoO0O00 / OOooOOo
 if 97 - 97: Oo0Ooo * iII111i % ooOoO0o . iII111i - I1Ii111 - OOooOOo
 if 79 - 79: I1IiiI - ooOoO0o
def lisp_get_interface_address ( device ) :
 if 37 - 37: IiII . Oo0Ooo * Oo0Ooo * II111iiii * O0
 if 83 - 83: IiII / I1Ii111
 if 64 - 64: OoO0O00 % IiII . I1Ii111 % OoO0O00 + I11i * IiII
 if 83 - 83: o0oOOo0O0Ooo % oO0o + I11i % i11iIiiIii + O0
 if ( device not in netifaces . interfaces ( ) ) : return ( None )
 if 65 - 65: iIii1I11I1II1 % oO0o + O0 / OoooooooOO
 if 52 - 52: Ii1I % OOooOOo * I1IiiI % I11i + OOooOOo / iII111i
 if 80 - 80: OoooooooOO + IiII
 if 95 - 95: I1Ii111 / oO0o * I1Ii111 - OoooooooOO * OoooooooOO % OoO0O00
 iI1 = netifaces . ifaddresses ( device )
 if ( iI1 . has_key ( netifaces . AF_INET ) == False ) : return ( None )
 if 12 - 12: I1Ii111 + OOooOOo + I11i . IiII / Ii1I
 if 29 - 29: IiII . ooOoO0o - II111iiii
 if 68 - 68: iIii1I11I1II1 + II111iiii / oO0o
 if 91 - 91: OoOoOO00 % iIii1I11I1II1 . I1IiiI
 O00ooooo00 = lisp_address ( LISP_AFI_IPV4 , "" , 32 , 0 )
 if 94 - 94: I11i - II111iiii . I1IiiI - Oo0Ooo + I1ii11iIi11i * I1ii11iIi11i
 for o0o0O00 in iI1 [ netifaces . AF_INET ] :
  I1iiIiiii1111 = o0o0O00 [ "addr" ]
  O00ooooo00 . store_address ( I1iiIiiii1111 )
  return ( O00ooooo00 )
  if 29 - 29: Ii1I - I1IiiI / I1IiiI * Ii1I * IiII . OOooOOo
 return ( None )
 if 80 - 80: iIii1I11I1II1
 if 23 - 23: II111iiii
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
def lisp_get_input_interface ( packet ) :
 IiII1i1iI = lisp_format_packet ( packet [ 0 : 12 ] ) . replace ( " " , "" )
 O0OOO00 = IiII1i1iI [ 0 : 12 ]
 ooOOo0o = IiII1i1iI [ 12 : : ]
 if 50 - 50: II111iiii - I1Ii111 + iIii1I11I1II1 + iIii1I11I1II1
 try : OoooooOo = lisp_mymacs . has_key ( ooOOo0o )
 except : OoooooOo = False
 if 67 - 67: II111iiii / o0oOOo0O0Ooo . OOooOOo . OoooooooOO
 if ( lisp_mymacs . has_key ( O0OOO00 ) ) : return ( lisp_mymacs [ O0OOO00 ] , ooOOo0o , O0OOO00 , OoooooOo )
 if ( OoooooOo ) : return ( lisp_mymacs [ ooOOo0o ] , ooOOo0o , O0OOO00 , OoooooOo )
 return ( [ "?" ] , ooOOo0o , O0OOO00 , OoooooOo )
 if 19 - 19: IiII . I1ii11iIi11i / OoOoOO00
 if 68 - 68: ooOoO0o / OoooooooOO * I11i / oO0o
 if 88 - 88: o0oOOo0O0Ooo
 if 1 - 1: OoooooooOO
 if 48 - 48: ooOoO0o * OoOoOO00 - ooOoO0o - OOooOOo + OOooOOo
 if 40 - 40: i11iIiiIii . iIii1I11I1II1
 if 2 - 2: i1IIi * oO0o - oO0o + OoooooooOO % OoOoOO00 / OoOoOO00
 if 3 - 3: OoooooooOO
def lisp_get_local_interfaces ( ) :
 for O0OoO0o in netifaces . interfaces ( ) :
  I111IIiIII = lisp_interface ( O0OoO0o )
  I111IIiIII . add_interface ( )
  if 62 - 62: OoOoOO00 % o0oOOo0O0Ooo % I1IiiI + IiII . OoO0O00
 return
 if 48 - 48: I1IiiI * i11iIiiIii % II111iiii
 if 20 - 20: i1IIi / I1IiiI * oO0o
 if 85 - 85: II111iiii . ooOoO0o % OOooOOo % I11i
 if 80 - 80: oO0o * I11i / iIii1I11I1II1 % oO0o / iIii1I11I1II1
 if 42 - 42: i1IIi / i11iIiiIii . Oo0Ooo * iII111i . i11iIiiIii * O0
 if 44 - 44: i1IIi . I1IiiI / i11iIiiIii + IiII
 if 27 - 27: OOooOOo
def lisp_get_loopback_address ( ) :
 for o0o0O00 in netifaces . ifaddresses ( "lo" ) [ netifaces . AF_INET ] :
  if ( o0o0O00 [ "peer" ] == "127.0.0.1" ) : continue
  return ( o0o0O00 [ "peer" ] )
  if 52 - 52: I1Ii111 % OoOoOO00 + iIii1I11I1II1 * oO0o . Ii1I
 return ( None )
 if 95 - 95: iIii1I11I1II1 . IiII - OoooooooOO * OoO0O00 / o0oOOo0O0Ooo
 if 74 - 74: oO0o
 if 34 - 34: iII111i
 if 44 - 44: i1IIi % I1IiiI % o0oOOo0O0Ooo
 if 9 - 9: Oo0Ooo % OoooooooOO - Ii1I
 if 43 - 43: OoO0O00 % OoO0O00
 if 46 - 46: Oo0Ooo % iIii1I11I1II1 . iII111i . O0 * ooOoO0o / OoooooooOO
 if 7 - 7: oO0o - O0 * I11i - o0oOOo0O0Ooo - II111iiii
def lisp_is_mac_string ( mac_str ) :
 II11iI1iiI = mac_str . split ( "/" )
 if ( len ( II11iI1iiI ) == 2 ) : mac_str = II11iI1iiI [ 0 ]
 return ( len ( mac_str ) == 14 and mac_str . count ( "-" ) == 2 )
 if 41 - 41: I1IiiI - I1Ii111 % II111iiii . I1Ii111 - I11i
 if 45 - 45: Ii1I - OOooOOo
 if 70 - 70: OoO0O00 % I1IiiI / I1IiiI . I11i % ooOoO0o . II111iiii
 if 10 - 10: Ii1I - i11iIiiIii . I1ii11iIi11i % i1IIi
 if 78 - 78: iIii1I11I1II1 * Oo0Ooo . Oo0Ooo - OOooOOo . iIii1I11I1II1
 if 30 - 30: ooOoO0o + ooOoO0o % IiII - o0oOOo0O0Ooo - I1ii11iIi11i
 if 36 - 36: I11i % OOooOOo
 if 72 - 72: I1IiiI / iII111i - O0 + I11i
def lisp_get_local_macs ( ) :
 for O0OoO0o in netifaces . interfaces ( ) :
  if 83 - 83: O0
  if 89 - 89: Oo0Ooo + I1ii11iIi11i - o0oOOo0O0Ooo
  if 40 - 40: OoO0O00 + OoO0O00
  if 94 - 94: iII111i * iIii1I11I1II1 . I11i
  if 13 - 13: iIii1I11I1II1 * OoOoOO00 / I1Ii111 % ooOoO0o + oO0o
  oOo0OOOOOO = O0OoO0o . replace ( ":" , "" )
  oOo0OOOOOO = O0OoO0o . replace ( "-" , "" )
  if ( oOo0OOOOOO . isalnum ( ) == False ) : continue
  if 41 - 41: I1ii11iIi11i
  if 5 - 5: Oo0Ooo
  if 100 - 100: Ii1I + iIii1I11I1II1
  if 59 - 59: IiII
  if 89 - 89: OoOoOO00 % iIii1I11I1II1
  try :
   III11I1 = netifaces . ifaddresses ( O0OoO0o )
  except :
   continue
   if 61 - 61: OoOoOO00 - OoO0O00 + I1IiiI * OOooOOo % OoO0O00
  if ( III11I1 . has_key ( netifaces . AF_LINK ) == False ) : continue
  II11iI1iiI = III11I1 [ netifaces . AF_LINK ] [ 0 ] [ "addr" ]
  II11iI1iiI = II11iI1iiI . replace ( ":" , "" )
  if 24 - 24: ooOoO0o - I11i * oO0o
  if 87 - 87: Ii1I - I1ii11iIi11i % I1ii11iIi11i . oO0o / I1ii11iIi11i
  if 6 - 6: OoOoOO00 / iIii1I11I1II1 * OoooooooOO * i11iIiiIii
  if 79 - 79: IiII % OoO0O00
  if 81 - 81: i11iIiiIii + i11iIiiIii * OoO0O00 + IiII
  if ( len ( II11iI1iiI ) < 12 ) : continue
  if 32 - 32: O0 . OoooooooOO
  if ( lisp_mymacs . has_key ( II11iI1iiI ) == False ) : lisp_mymacs [ II11iI1iiI ] = [ ]
  lisp_mymacs [ II11iI1iiI ] . append ( O0OoO0o )
  if 15 - 15: I1IiiI . OoO0O00
  if 17 - 17: i11iIiiIii / Oo0Ooo . OoO0O00 / I1IiiI
 lprint ( "Local MACs are: {}" . format ( lisp_mymacs ) )
 return
 if 38 - 38: i1IIi . I1ii11iIi11i % Ii1I + iIii1I11I1II1 + O0
 if 47 - 47: OoO0O00 + IiII / II111iiii
 if 97 - 97: I1ii11iIi11i / I1IiiI % O0 + i1IIi - ooOoO0o
 if 38 - 38: o0oOOo0O0Ooo % I1Ii111 + i11iIiiIii + iII111i + ooOoO0o / i11iIiiIii
 if 94 - 94: iII111i - Oo0Ooo + oO0o
 if 59 - 59: I11i . I1IiiI - iIii1I11I1II1 + iIii1I11I1II1
 if 56 - 56: oO0o + ooOoO0o
 if 32 - 32: II111iiii + OoOoOO00 % ooOoO0o / OoOoOO00 + I1ii11iIi11i
def lisp_get_local_rloc ( ) :
 IiI11I111 = commands . getoutput ( "netstat -rn | egrep 'default|0.0.0.0'" )
 if ( IiI11I111 == "" ) : return ( lisp_address ( LISP_AFI_IPV4 , "" , 32 , 0 ) )
 if 54 - 54: O0 - iII111i . OOooOOo % iII111i + iII111i
 if 36 - 36: OOooOOo % i11iIiiIii
 if 47 - 47: i1IIi + II111iiii . Oo0Ooo * oO0o . I11i / i1IIi
 if 50 - 50: I1Ii111 / i1IIi % OoooooooOO
 IiI11I111 = IiI11I111 . split ( "\n" ) [ 0 ]
 O0OoO0o = IiI11I111 . split ( ) [ - 1 ]
 if 83 - 83: I1ii11iIi11i * I1ii11iIi11i + OOooOOo
 o0o0O00 = ""
 OooooOoO = lisp_is_macos ( )
 if ( OooooOoO ) :
  IiI11I111 = commands . getoutput ( "ifconfig {} | egrep 'inet '" . format ( O0OoO0o ) )
  if ( IiI11I111 == "" ) : return ( lisp_address ( LISP_AFI_IPV4 , "" , 32 , 0 ) )
 else :
  o00OoOO0O0 = 'ip addr show | egrep "inet " | egrep "{}"' . format ( O0OoO0o )
  IiI11I111 = commands . getoutput ( o00OoOO0O0 )
  if ( IiI11I111 == "" ) :
   o00OoOO0O0 = 'ip addr show | egrep "inet " | egrep "global lo"'
   IiI11I111 = commands . getoutput ( o00OoOO0O0 )
   if 6 - 6: ooOoO0o + OOooOOo / Oo0Ooo + IiII % II111iiii / OoO0O00
  if ( IiI11I111 == "" ) : return ( lisp_address ( LISP_AFI_IPV4 , "" , 32 , 0 ) )
  if 45 - 45: OoooooooOO
  if 9 - 9: I11i . OoO0O00 * i1IIi . OoooooooOO
  if 32 - 32: OoOoOO00 . I1ii11iIi11i % I1IiiI - II111iiii
  if 11 - 11: O0 + I1IiiI
  if 80 - 80: oO0o % oO0o % O0 - i11iIiiIii . iII111i / O0
  if 13 - 13: I1IiiI + O0 - I1ii11iIi11i % Oo0Ooo / Ii1I . i1IIi
 o0o0O00 = ""
 IiI11I111 = IiI11I111 . split ( "\n" )
 if 60 - 60: Oo0Ooo . IiII % I1IiiI - I1Ii111
 for oooOo in IiI11I111 :
  oOO0oo = oooOo . split ( ) [ 1 ]
  if ( OooooOoO == False ) : oOO0oo = oOO0oo . split ( "/" ) [ 0 ]
  oOoO0Oo0 = lisp_address ( LISP_AFI_IPV4 , oOO0oo , 32 , 0 )
  return ( oOoO0Oo0 )
  if 7 - 7: ooOoO0o + Ii1I
 return ( lisp_address ( LISP_AFI_IPV4 , o0o0O00 , 32 , 0 ) )
 if 32 - 32: iIii1I11I1II1 % I1IiiI / i11iIiiIii + OOooOOo - o0oOOo0O0Ooo . iII111i
 if 86 - 86: i1IIi / Ii1I * I1IiiI
 if 67 - 67: I1ii11iIi11i * I1ii11iIi11i / oO0o * OoooooooOO + OoOoOO00
 if 79 - 79: i1IIi
 if 1 - 1: oO0o / i1IIi
 if 74 - 74: I11i / OoooooooOO / Oo0Ooo * i11iIiiIii . II111iiii . OoooooooOO
 if 59 - 59: i11iIiiIii . OoooooooOO / I11i * I1ii11iIi11i + OoooooooOO
 if 3 - 3: i11iIiiIii * Oo0Ooo % iIii1I11I1II1 % I1IiiI * iII111i / OOooOOo
 if 95 - 95: IiII * O0 * I1Ii111 . OoooooooOO % Oo0Ooo + I1ii11iIi11i
 if 98 - 98: oO0o . OoooooooOO
 if 54 - 54: O0 / IiII % ooOoO0o * i1IIi * O0
def lisp_get_local_addresses ( ) :
 global lisp_myrlocs
 if 48 - 48: o0oOOo0O0Ooo . oO0o % OoOoOO00 - OoOoOO00
 if 33 - 33: I11i % II111iiii + OoO0O00
 if 93 - 93: i1IIi . IiII / I1IiiI + IiII
 if 58 - 58: I1ii11iIi11i + O0 . Oo0Ooo + OoOoOO00 - OoO0O00 - OoOoOO00
 if 41 - 41: Oo0Ooo / i1IIi / Oo0Ooo - iII111i . o0oOOo0O0Ooo
 if 65 - 65: O0 * i11iIiiIii . OoooooooOO / I1IiiI / iII111i
 if 69 - 69: ooOoO0o % ooOoO0o
 if 76 - 76: i11iIiiIii * iII111i / OoO0O00 % I1ii11iIi11i + OOooOOo
 if 48 - 48: iIii1I11I1II1 % i1IIi + OoOoOO00 % o0oOOo0O0Ooo
 if 79 - 79: OoOoOO00 % I1IiiI % Ii1I / i1IIi % OoO0O00
 oo0o00OO = None
 iI11I = 1
 oOoo00o0oOO = os . getenv ( "LISP_ADDR_SELECT" )
 if ( oOoo00o0oOO != None and oOoo00o0oOO != "" ) :
  oOoo00o0oOO = oOoo00o0oOO . split ( ":" )
  if ( len ( oOoo00o0oOO ) == 2 ) :
   oo0o00OO = oOoo00o0oOO [ 0 ]
   iI11I = oOoo00o0oOO [ 1 ]
  else :
   if ( oOoo00o0oOO [ 0 ] . isdigit ( ) ) :
    iI11I = oOoo00o0oOO [ 0 ]
   else :
    oo0o00OO = oOoo00o0oOO [ 0 ]
    if 61 - 61: i1IIi * o0oOOo0O0Ooo + iIii1I11I1II1 / OoOoOO00 - O0 * iIii1I11I1II1
    if 56 - 56: OOooOOo
  iI11I = 1 if ( iI11I == "" ) else int ( iI11I )
  if 49 - 49: ooOoO0o . II111iiii
  if 24 - 24: O0 . OoooooooOO - OoO0O00 * OoooooooOO
 Ii11iiI = [ None , None , None ]
 o0OO0oooo = lisp_address ( LISP_AFI_IPV4 , "" , 32 , 0 )
 I11II1i1 = lisp_address ( LISP_AFI_IPV6 , "" , 128 , 0 )
 IiI1ii11I1 = None
 if 19 - 19: I1Ii111 + IiII / oO0o / II111iiii
 for O0OoO0o in netifaces . interfaces ( ) :
  if ( oo0o00OO != None and oo0o00OO != O0OoO0o ) : continue
  iI1 = netifaces . ifaddresses ( O0OoO0o )
  if ( iI1 == { } ) : continue
  if 92 - 92: i1IIi % ooOoO0o + ooOoO0o - iIii1I11I1II1 . Ii1I
  if 33 - 33: o0oOOo0O0Ooo / O0 + OOooOOo
  if 75 - 75: IiII % i11iIiiIii + iIii1I11I1II1
  if 92 - 92: OoOoOO00 % O0
  IiI1ii11I1 = lisp_get_interface_instance_id ( O0OoO0o , None )
  if 55 - 55: iIii1I11I1II1 * iII111i
  if 85 - 85: iIii1I11I1II1 . II111iiii
  if 54 - 54: Ii1I . OoooooooOO % Oo0Ooo
  if 22 - 22: OOooOOo
  if ( iI1 . has_key ( netifaces . AF_INET ) ) :
   IIIiI1ii1IIi = iI1 [ netifaces . AF_INET ]
   I1I11Iiii111 = 0
   for o0o0O00 in IIIiI1ii1IIi :
    o0OO0oooo . store_address ( o0o0O00 [ "addr" ] )
    if ( o0OO0oooo . is_ipv4_loopback ( ) ) : continue
    if ( o0OO0oooo . is_ipv4_link_local ( ) ) : continue
    if ( o0OO0oooo . address == 0 ) : continue
    I1I11Iiii111 += 1
    o0OO0oooo . instance_id = IiI1ii11I1
    if ( oo0o00OO == None and
 lisp_db_for_lookups . lookup_cache ( o0OO0oooo , False ) ) : continue
    Ii11iiI [ 0 ] = o0OO0oooo
    if ( I1I11Iiii111 == iI11I ) : break
    if 38 - 38: OoO0O00 . ooOoO0o
    if 34 - 34: i1IIi % IiII
  if ( iI1 . has_key ( netifaces . AF_INET6 ) ) :
   o0O0oo0o = iI1 [ netifaces . AF_INET6 ]
   I1I11Iiii111 = 0
   for o0o0O00 in o0O0oo0o :
    I1iiIiiii1111 = o0o0O00 [ "addr" ]
    I11II1i1 . store_address ( I1iiIiiii1111 )
    if ( I11II1i1 . is_ipv6_string_link_local ( I1iiIiiii1111 ) ) : continue
    if ( I11II1i1 . is_ipv6_loopback ( ) ) : continue
    I1I11Iiii111 += 1
    I11II1i1 . instance_id = IiI1ii11I1
    if ( oo0o00OO == None and
 lisp_db_for_lookups . lookup_cache ( I11II1i1 , False ) ) : continue
    Ii11iiI [ 1 ] = I11II1i1
    if ( I1I11Iiii111 == iI11I ) : break
    if 80 - 80: OoooooooOO / iIii1I11I1II1 + I1ii11iIi11i / i1IIi / o0oOOo0O0Ooo
    if 94 - 94: i1IIi
    if 36 - 36: I1IiiI + Oo0Ooo
    if 46 - 46: iII111i
    if 65 - 65: i1IIi . I1ii11iIi11i / ooOoO0o
    if 11 - 11: IiII * ooOoO0o / ooOoO0o - OOooOOo
  if ( Ii11iiI [ 0 ] == None ) : continue
  if 68 - 68: I1IiiI % IiII - IiII / I1IiiI + I1ii11iIi11i - Oo0Ooo
  Ii11iiI [ 2 ] = O0OoO0o
  break
  if 65 - 65: ooOoO0o - i1IIi
  if 62 - 62: I11i / oO0o % Oo0Ooo . OoooooooOO / i11iIiiIii / I1Ii111
 OooO0O0Ooo = Ii11iiI [ 0 ] . print_address_no_iid ( ) if Ii11iiI [ 0 ] else "none"
 oO0O = Ii11iiI [ 1 ] . print_address_no_iid ( ) if Ii11iiI [ 1 ] else "none"
 O0OoO0o = Ii11iiI [ 2 ] if Ii11iiI [ 2 ] else "none"
 if 25 - 25: oO0o % I1IiiI + i11iIiiIii + O0 * OoooooooOO
 oo0o00OO = " (user selected)" if oo0o00OO != None else ""
 if 64 - 64: i1IIi
 OooO0O0Ooo = red ( OooO0O0Ooo , False )
 oO0O = red ( oO0O , False )
 O0OoO0o = bold ( O0OoO0o , False )
 lprint ( "Local addresses are IPv4: {}, IPv6: {} from device {}{}, iid {}" . format ( OooO0O0Ooo , oO0O , O0OoO0o , oo0o00OO , IiI1ii11I1 ) )
 if 10 - 10: I1Ii111 % O0 / I1IiiI % I11i
 if 25 - 25: II111iiii / OoO0O00
 lisp_myrlocs = Ii11iiI
 return ( ( Ii11iiI [ 0 ] != None ) )
 if 64 - 64: O0 % ooOoO0o
 if 40 - 40: o0oOOo0O0Ooo + I11i
 if 77 - 77: i11iIiiIii % IiII + I1Ii111 % OoooooooOO - I11i
 if 26 - 26: Oo0Ooo + O0 - iIii1I11I1II1
 if 47 - 47: OoooooooOO
 if 2 - 2: OoOoOO00 % I1Ii111 * Oo0Ooo * OoOoOO00
 if 65 - 65: i11iIiiIii + Oo0Ooo * OoooooooOO - OoO0O00
 if 26 - 26: o0oOOo0O0Ooo % OOooOOo + OOooOOo % I11i * i11iIiiIii / iII111i
 if 64 - 64: oO0o % OoOoOO00 / II111iiii % ooOoO0o - iII111i
def lisp_get_all_addresses ( ) :
 I1II1IiI1 = [ ]
 for I111IIiIII in netifaces . interfaces ( ) :
  try : iIIiI11iI1Ii1 = netifaces . ifaddresses ( I111IIiIII )
  except : continue
  if 94 - 94: ooOoO0o / i11iIiiIii % O0
  if ( iIIiI11iI1Ii1 . has_key ( netifaces . AF_INET ) ) :
   for o0o0O00 in iIIiI11iI1Ii1 [ netifaces . AF_INET ] :
    oOO0oo = o0o0O00 [ "addr" ]
    if ( oOO0oo . find ( "127.0.0.1" ) != - 1 ) : continue
    I1II1IiI1 . append ( oOO0oo )
    if 70 - 70: I11i - Oo0Ooo / OoooooooOO % OoooooooOO
    if 95 - 95: OoooooooOO % OoooooooOO . Ii1I
  if ( iIIiI11iI1Ii1 . has_key ( netifaces . AF_INET6 ) ) :
   for o0o0O00 in iIIiI11iI1Ii1 [ netifaces . AF_INET6 ] :
    oOO0oo = o0o0O00 [ "addr" ]
    if ( oOO0oo == "::1" ) : continue
    if ( oOO0oo [ 0 : 5 ] == "fe80:" ) : continue
    I1II1IiI1 . append ( oOO0oo )
    if 26 - 26: oO0o + IiII - II111iiii . II111iiii + I1ii11iIi11i + OoOoOO00
    if 68 - 68: O0
    if 76 - 76: I1ii11iIi11i
 return ( I1II1IiI1 )
 if 99 - 99: o0oOOo0O0Ooo
 if 1 - 1: Ii1I * OoOoOO00 * OoO0O00 + Oo0Ooo
 if 90 - 90: I1Ii111 % Oo0Ooo - Oo0Ooo . iIii1I11I1II1 / OOooOOo + I11i
 if 89 - 89: oO0o
 if 87 - 87: iII111i % Oo0Ooo
 if 62 - 62: OoO0O00 + ooOoO0o / iII111i * i11iIiiIii
 if 37 - 37: iII111i
 if 33 - 33: OoO0O00 - O0 - OoO0O00
def lisp_get_all_multicast_rles ( ) :
 O000oooOO0Oo0 = [ ]
 IiI11I111 = commands . getoutput ( 'egrep "rle-address =" ./lisp.config' )
 if ( IiI11I111 == "" ) : return ( O000oooOO0Oo0 )
 if 31 - 31: IiII - OoO0O00 / OOooOOo . i1IIi / Ii1I
 o0o000o = IiI11I111 . split ( "\n" )
 for oooOo in o0o000o :
  if ( oooOo [ 0 ] == "#" ) : continue
  iiiI1i1111II = oooOo . split ( "rle-address = " ) [ 1 ]
  IIII11iiii = int ( iiiI1i1111II . split ( "." ) [ 0 ] )
  if ( IIII11iiii >= 224 and IIII11iiii < 240 ) : O000oooOO0Oo0 . append ( iiiI1i1111II )
  if 75 - 75: iIii1I11I1II1 % IiII + I1ii11iIi11i * O0 . iII111i - ooOoO0o
 return ( O000oooOO0Oo0 )
 if 32 - 32: Ii1I % oO0o - i1IIi
 if 40 - 40: iIii1I11I1II1 + iII111i * OoOoOO00 + oO0o
 if 15 - 15: I11i % I1IiiI - iIii1I11I1II1 * ooOoO0o
 if 71 - 71: OoOoOO00 % Oo0Ooo % ooOoO0o
 if 34 - 34: I11i / I11i % IiII . OoOoOO00 / Oo0Ooo
 if 99 - 99: ooOoO0o * I1IiiI - ooOoO0o % Ii1I
 if 40 - 40: OOooOOo / IiII / iIii1I11I1II1 + Ii1I
 if 59 - 59: I11i * OoooooooOO + OOooOOo . iIii1I11I1II1 / i1IIi
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
  if 75 - 75: I11i . OOooOOo - iIii1I11I1II1 * OoO0O00 * iII111i
  if 93 - 93: ooOoO0o
 def encode ( self , nonce ) :
  if 18 - 18: ooOoO0o
  if 66 - 66: oO0o * i11iIiiIii + OoOoOO00 / OOooOOo
  if 96 - 96: OOooOOo + OOooOOo % IiII % OOooOOo
  if 28 - 28: iIii1I11I1II1 + OoOoOO00 . o0oOOo0O0Ooo % i11iIiiIii
  if 58 - 58: I11i / OoooooooOO % oO0o + OoO0O00
  if ( self . outer_source . is_null ( ) ) : return ( None )
  if 58 - 58: O0
  if 91 - 91: iII111i / I1ii11iIi11i . iII111i - o0oOOo0O0Ooo + I1ii11iIi11i
  if 72 - 72: Ii1I . IiII * I1ii11iIi11i / I1ii11iIi11i / iII111i
  if 13 - 13: i1IIi
  if 17 - 17: i11iIiiIii * o0oOOo0O0Ooo * o0oOOo0O0Ooo + OoO0O00
  if 95 - 95: I1IiiI
  if ( nonce == None ) :
   self . lisp_header . nonce ( lisp_get_data_nonce ( ) )
  elif ( self . lisp_header . is_request_nonce ( nonce ) ) :
   self . lisp_header . request_nonce ( nonce )
  else :
   self . lisp_header . nonce ( nonce )
   if 95 - 95: OOooOOo % I1ii11iIi11i + o0oOOo0O0Ooo % ooOoO0o
  self . lisp_header . instance_id ( self . inner_dest . instance_id )
  if 36 - 36: O0 / i1IIi % II111iiii / iII111i
  if 96 - 96: Oo0Ooo / oO0o . II111iiii . Oo0Ooo
  if 91 - 91: II111iiii . OOooOOo + o0oOOo0O0Ooo
  if 8 - 8: OOooOOo * Oo0Ooo / iII111i - OoO0O00 - OoooooooOO
  if 100 - 100: oO0o . iIii1I11I1II1 . iIii1I11I1II1
  if 55 - 55: oO0o
  self . lisp_header . key_id ( 0 )
  i1iiI = ( self . lisp_header . get_instance_id ( ) == 0xffffff )
  if ( lisp_data_plane_security and i1iiI == False ) :
   I1iiIiiii1111 = self . outer_dest . print_address_no_iid ( ) + ":" + str ( self . encap_port )
   if 97 - 97: I1Ii111 . I11i / I1IiiI
   if ( lisp_crypto_keys_by_rloc_encap . has_key ( I1iiIiiii1111 ) ) :
    o00OO0o0 = lisp_crypto_keys_by_rloc_encap [ I1iiIiiii1111 ]
    if ( o00OO0o0 [ 1 ] ) :
     o00OO0o0 [ 1 ] . use_count += 1
     i1II1IiiIi , ii111iI1i1 = self . encrypt ( o00OO0o0 [ 1 ] , I1iiIiiii1111 )
     if ( ii111iI1i1 ) : self . packet = i1II1IiiIi
     if 80 - 80: OoO0O00 / IiII * I1IiiI % IiII
     if 95 - 95: O0 / I11i . I1Ii111
     if 17 - 17: I11i
     if 56 - 56: ooOoO0o * o0oOOo0O0Ooo + I11i
     if 48 - 48: IiII * OoO0O00 % I1Ii111 - I11i
     if 72 - 72: i1IIi % ooOoO0o % IiII % oO0o - oO0o
     if 97 - 97: o0oOOo0O0Ooo * O0 / o0oOOo0O0Ooo * OoO0O00 * Oo0Ooo
     if 38 - 38: I1Ii111
  self . udp_checksum = 0
  if ( self . encap_port == LISP_DATA_PORT ) :
   if ( lisp_crypto_ephem_port == None ) :
    self . hash_packet ( )
   else :
    self . udp_sport = lisp_crypto_ephem_port
    if 25 - 25: iIii1I11I1II1 % II111iiii / I11i / I1ii11iIi11i
  else :
   self . udp_sport = LISP_DATA_PORT
   if 22 - 22: oO0o * iII111i
  self . udp_dport = self . encap_port
  self . udp_length = len ( self . packet ) + 16
  if 4 - 4: OoOoOO00 - oO0o + I1IiiI
  if 36 - 36: IiII
  if 19 - 19: OoOoOO00 . o0oOOo0O0Ooo . OoooooooOO
  if 13 - 13: OOooOOo . Oo0Ooo / II111iiii
  if ( self . outer_version == 4 ) :
   iiI1iIII1ii = socket . htons ( self . udp_sport )
   i1iiIIiII1 = socket . htons ( self . udp_dport )
  else :
   iiI1iIII1ii = self . udp_sport
   i1iiIIiII1 = self . udp_dport
   if 72 - 72: IiII % o0oOOo0O0Ooo
   if 93 - 93: iIii1I11I1II1 + i11iIiiIii . o0oOOo0O0Ooo . i1IIi % I1IiiI % ooOoO0o
  i1iiIIiII1 = socket . htons ( self . udp_dport ) if self . outer_version == 4 else self . udp_dport
  if 74 - 74: OoOoOO00 / i1IIi % OoooooooOO
  if 52 - 52: IiII % ooOoO0o
  I1iIIIiI = struct . pack ( "HHHH" , iiI1iIII1ii , i1iiIIiII1 , socket . htons ( self . udp_length ) ,
 self . udp_checksum )
  if 25 - 25: I11i / I11i % OoooooooOO - I1ii11iIi11i * oO0o
  if 23 - 23: i11iIiiIii
  if 100 - 100: oO0o + O0 . I1IiiI + i1IIi - OoOoOO00 + o0oOOo0O0Ooo
  if 65 - 65: II111iiii / Oo0Ooo
  ii = self . lisp_header . encode ( )
  if 6 - 6: OoOoOO00 / iIii1I11I1II1 * I1Ii111 / I1IiiI + O0
  if 2 - 2: I1IiiI * Oo0Ooo % o0oOOo0O0Ooo % Oo0Ooo
  if 66 - 66: IiII + iIii1I11I1II1
  if 75 - 75: I1ii11iIi11i
  if 92 - 92: I11i / O0 * I1IiiI - I11i
  if ( self . outer_version == 4 ) :
   oooOo00000 = socket . htons ( self . udp_length + 20 )
   IiI1IiI1iiI1 = socket . htons ( 0x4000 )
   O000o0 = struct . pack ( "BBHHHBBH" , 0x45 , self . outer_tos , oooOo00000 , 0xdfdf ,
 IiI1IiI1iiI1 , self . outer_ttl , 17 , 0 )
   O000o0 += self . outer_source . pack_address ( )
   O000o0 += self . outer_dest . pack_address ( )
   O000o0 = lisp_ip_checksum ( O000o0 )
  elif ( self . outer_version == 6 ) :
   O000o0 = ""
   if 39 - 39: II111iiii + OoooooooOO / OOooOOo / Ii1I * OoOoOO00
   if 71 - 71: i1IIi / I1ii11iIi11i % i11iIiiIii / i1IIi
   if 4 - 4: IiII
   if 93 - 93: oO0o % i1IIi
   if 83 - 83: I1IiiI . Oo0Ooo - I11i . o0oOOo0O0Ooo
   if 73 - 73: I1IiiI - iII111i . iII111i
   if 22 - 22: ooOoO0o / ooOoO0o - Ii1I % I11i . OOooOOo + IiII
  else :
   return ( None )
   if 64 - 64: i1IIi % I1ii11iIi11i / Ii1I % OoooooooOO
   if 24 - 24: I1Ii111 + OoooooooOO . IiII / OoOoOO00 / I11i
  self . packet = O000o0 + I1iIIIiI + ii + self . packet
  return ( self )
  if 65 - 65: OoooooooOO
  if 18 - 18: O0 - i1IIi . I1Ii111
 def cipher_pad ( self , packet ) :
  o00OOo00 = len ( packet )
  if ( ( o00OOo00 % 16 ) != 0 ) :
   oooO = ( ( o00OOo00 / 16 ) + 1 ) * 16
   packet = packet . ljust ( oooO )
   if 2 - 2: iIii1I11I1II1 * I1IiiI % i1IIi % I1ii11iIi11i + OoooooooOO + I1IiiI
  return ( packet )
  if 16 - 16: OOooOOo
  if 63 - 63: iII111i
 def encrypt ( self , key , addr_str ) :
  if ( key == None or key . shared_key == None ) :
   return ( [ self . packet , False ] )
   if 11 - 11: iII111i - iIii1I11I1II1
   if 92 - 92: OoO0O00
   if 15 - 15: IiII / IiII + iIii1I11I1II1 % OoooooooOO
   if 12 - 12: ooOoO0o
   if 36 - 36: I1Ii111 . IiII * OoooooooOO - o0oOOo0O0Ooo
  i1II1IiiIi = self . cipher_pad ( self . packet )
  O0o = key . get_iv ( )
  if 82 - 82: I1Ii111 . I1Ii111 - iII111i
  OOOO0O00o = lisp_get_timestamp ( )
  o0II11I = None
  if ( key . cipher_suite == LISP_CS_25519_CHACHA ) :
   Iii1iIiI1I1I1 = chacha . ChaCha ( key . encrypt_key , O0o ) . encrypt
  elif ( key . cipher_suite == LISP_CS_25519_GCM ) :
   oOOO0OO = binascii . unhexlify ( key . encrypt_key )
   try :
    I11ii1iI11 = AES . new ( oOOO0OO , AES . MODE_GCM , O0o )
    Iii1iIiI1I1I1 = I11ii1iI11 . encrypt
    o0II11I = I11ii1iI11 . digest
   except :
    lprint ( "You need AES-GCM, do a 'pip install pycryptodome'" )
    return ( [ self . packet , False ] )
    if 6 - 6: IiII * II111iiii % iIii1I11I1II1
  else :
   oOOO0OO = binascii . unhexlify ( key . encrypt_key )
   Iii1iIiI1I1I1 = AES . new ( oOOO0OO , AES . MODE_CBC , O0o ) . encrypt
   if 86 - 86: i1IIi * O0 % ooOoO0o . Oo0Ooo % ooOoO0o . Oo0Ooo
   if 71 - 71: iII111i . i11iIiiIii * O0 + O0
  Oo0 = Iii1iIiI1I1I1 ( i1II1IiiIi )
  if 75 - 75: OoO0O00 / Ii1I + II111iiii % IiII . i11iIiiIii
  if ( Oo0 == None ) : return ( [ self . packet , False ] )
  OOOO0O00o = int ( str ( time . time ( ) - OOOO0O00o ) . split ( "." ) [ 1 ] [ 0 : 6 ] )
  if 76 - 76: iII111i . IiII % iII111i - I1Ii111
  if 51 - 51: OoooooooOO + o0oOOo0O0Ooo * iIii1I11I1II1 * oO0o / i1IIi
  if 19 - 19: iII111i - OoOoOO00 % oO0o / OoooooooOO % iII111i
  if 65 - 65: O0 . oO0o
  if 85 - 85: II111iiii
  if 55 - 55: I1ii11iIi11i
  if ( o0II11I != None ) : Oo0 += o0II11I ( )
  if 76 - 76: oO0o - i11iIiiIii
  if 27 - 27: I1ii11iIi11i - i11iIiiIii % I1Ii111 / Oo0Ooo . Oo0Ooo / OoooooooOO
  if 76 - 76: I11i * OoO0O00 . iIii1I11I1II1 % OoooooooOO % I1ii11iIi11i
  if 39 - 39: II111iiii * OoOoOO00 . O0 * I11i
  if 89 - 89: Ii1I - ooOoO0o . I11i - I1Ii111 - I1IiiI
  self . lisp_header . key_id ( key . key_id )
  ii = self . lisp_header . encode ( )
  if 79 - 79: IiII + IiII + Ii1I
  iiiII1i1I = key . do_icv ( ii + O0o + Oo0 , O0o )
  if 97 - 97: O0 . I1Ii111 / II111iiii . O0 + OoooooooOO
  oo0OooO = 4 if ( key . do_poly ) else 8
  if 4 - 4: IiII + iIii1I11I1II1 * iII111i + Oo0Ooo * o0oOOo0O0Ooo % II111iiii
  OO0o0o0oo = bold ( "Encrypt" , False )
  iIiII1 = bold ( key . cipher_suite_string , False )
  addr_str = "RLOC: " + red ( addr_str , False )
  i111iii1I1 = "poly" if key . do_poly else "sha256"
  i111iii1I1 = bold ( i111iii1I1 , False )
  iiIiII1 = "ICV({}): 0x{}...{}" . format ( i111iii1I1 , iiiII1i1I [ 0 : oo0OooO ] , iiiII1i1I [ - oo0OooO : : ] )
  dprint ( "{} for key-id: {}, {}, {}, {}-time: {} usec" . format ( OO0o0o0oo , key . key_id , addr_str , iiIiII1 , iIiII1 , OOOO0O00o ) )
  if 37 - 37: O0 + ooOoO0o * OOooOOo
  if 27 - 27: O0 . II111iiii + IiII % o0oOOo0O0Ooo
  iiiII1i1I = int ( iiiII1i1I , 16 )
  if ( key . do_poly ) :
   oo0O0oOOO0o = byte_swap_64 ( ( iiiII1i1I >> 64 ) & LISP_8_64_MASK )
   oOo0Oo0Oo0 = byte_swap_64 ( iiiII1i1I & LISP_8_64_MASK )
   iiiII1i1I = struct . pack ( "QQ" , oo0O0oOOO0o , oOo0Oo0Oo0 )
  else :
   oo0O0oOOO0o = byte_swap_64 ( ( iiiII1i1I >> 96 ) & LISP_8_64_MASK )
   oOo0Oo0Oo0 = byte_swap_64 ( ( iiiII1i1I >> 32 ) & LISP_8_64_MASK )
   OooOo0o0OO = socket . htonl ( iiiII1i1I & 0xffffffff )
   iiiII1i1I = struct . pack ( "QQI" , oo0O0oOOO0o , oOo0Oo0Oo0 , OooOo0o0OO )
   if 1 - 1: iIii1I11I1II1 % ooOoO0o + O0
   if 22 - 22: o0oOOo0O0Ooo + Oo0Ooo . ooOoO0o + I1ii11iIi11i * iII111i . i11iIiiIii
  return ( [ O0o + Oo0 + iiiII1i1I , True ] )
  if 90 - 90: OOooOOo * OoOoOO00 - Oo0Ooo + o0oOOo0O0Ooo
  if 53 - 53: OoooooooOO . OoooooooOO + o0oOOo0O0Ooo - iII111i + OOooOOo
 def decrypt ( self , packet , header_length , key , addr_str ) :
  if 44 - 44: I1Ii111 - IiII
  if 100 - 100: oO0o . OoO0O00 - Ii1I + O0 * OoO0O00
  if 59 - 59: II111iiii
  if 43 - 43: Oo0Ooo + OoooooooOO
  if 47 - 47: ooOoO0o
  if 92 - 92: I11i % i11iIiiIii % Oo0Ooo
  if ( key . do_poly ) :
   oo0O0oOOO0o , oOo0Oo0Oo0 = struct . unpack ( "QQ" , packet [ - 16 : : ] )
   ii11Ii1IiiI1 = byte_swap_64 ( oo0O0oOOO0o ) << 64
   ii11Ii1IiiI1 |= byte_swap_64 ( oOo0Oo0Oo0 )
   ii11Ii1IiiI1 = lisp_hex_string ( ii11Ii1IiiI1 ) . zfill ( 32 )
   packet = packet [ 0 : - 16 ]
   oo0OooO = 4
   O00o0o = bold ( "poly" , False )
  else :
   oo0O0oOOO0o , oOo0Oo0Oo0 , OooOo0o0OO = struct . unpack ( "QQI" , packet [ - 20 : : ] )
   ii11Ii1IiiI1 = byte_swap_64 ( oo0O0oOOO0o ) << 96
   ii11Ii1IiiI1 |= byte_swap_64 ( oOo0Oo0Oo0 ) << 32
   ii11Ii1IiiI1 |= socket . htonl ( OooOo0o0OO )
   ii11Ii1IiiI1 = lisp_hex_string ( ii11Ii1IiiI1 ) . zfill ( 40 )
   packet = packet [ 0 : - 20 ]
   oo0OooO = 8
   O00o0o = bold ( "sha" , False )
   if 65 - 65: I1ii11iIi11i % oO0o . OoooooooOO * o0oOOo0O0Ooo * OoO0O00
  ii = self . lisp_header . encode ( )
  if 10 - 10: oO0o - iII111i % II111iiii - I1Ii111 - i1IIi
  if 10 - 10: I1ii11iIi11i - I11i . I1Ii111
  if 8 - 8: iIii1I11I1II1 % oO0o + Oo0Ooo
  if 24 - 24: o0oOOo0O0Ooo / Ii1I / Ii1I % II111iiii - oO0o * oO0o
  if ( key . cipher_suite == LISP_CS_25519_CHACHA ) :
   oOoo0oO = 8
   iIiII1 = bold ( "chacha" , False )
  elif ( key . cipher_suite == LISP_CS_25519_GCM ) :
   oOoo0oO = 12
   iIiII1 = bold ( "aes-gcm" , False )
  else :
   oOoo0oO = 16
   iIiII1 = bold ( "aes-cbc" , False )
   if 37 - 37: OoOoOO00 + O0 . O0 * Oo0Ooo % I1Ii111 / iII111i
  O0o = packet [ 0 : oOoo0oO ]
  if 18 - 18: OoooooooOO
  if 57 - 57: ooOoO0o . OoOoOO00 * o0oOOo0O0Ooo - OoooooooOO
  if 75 - 75: i11iIiiIii / o0oOOo0O0Ooo . IiII . i1IIi . i1IIi / I11i
  if 94 - 94: ooOoO0o + I1IiiI
  oOOOoo00oO = key . do_icv ( ii + packet , O0o )
  if 59 - 59: Ii1I / OoOoOO00 * OoO0O00 * iII111i % oO0o
  oOOoooOO = "0x{}...{}" . format ( ii11Ii1IiiI1 [ 0 : oo0OooO ] , ii11Ii1IiiI1 [ - oo0OooO : : ] )
  I1Iiii1Ii = "0x{}...{}" . format ( oOOOoo00oO [ 0 : oo0OooO ] , oOOOoo00oO [ - oo0OooO : : ] )
  if 66 - 66: iIii1I11I1II1 % i11iIiiIii / I1IiiI
  if ( oOOOoo00oO != ii11Ii1IiiI1 ) :
   self . packet_error = "ICV-error"
   IIIIIiiI11i1 = iIiII1 + "/" + O00o0o
   Iii1I = bold ( "ICV failed ({})" . format ( IIIIIiiI11i1 ) , False )
   iiIiII1 = "packet-ICV {} != computed-ICV {}" . format ( oOOoooOO , I1Iiii1Ii )
   dprint ( ( "{} from RLOC {}, receive-port: {}, key-id: {}, " + "packet dropped, {}" ) . format ( Iii1I , red ( addr_str , False ) ,
   # iIii1I11I1II1 + I1IiiI / I1ii11iIi11i + oO0o / ooOoO0o * I1Ii111
 self . udp_sport , key . key_id , iiIiII1 ) )
   dprint ( "{}" . format ( key . print_keys ( ) ) )
   if 29 - 29: IiII + i11iIiiIii * O0 - iII111i . II111iiii % Ii1I
   if 41 - 41: oO0o / OOooOOo + iII111i + ooOoO0o
   if 13 - 13: i11iIiiIii - i11iIiiIii . iIii1I11I1II1
   if 33 - 33: OoooooooOO + I1Ii111 / I1Ii111 + I1Ii111 * IiII
   if 26 - 26: I1Ii111 . I1IiiI . iII111i - OoooooooOO / iIii1I11I1II1
   if 47 - 47: IiII
   lisp_retry_decap_keys ( addr_str , ii + packet , O0o , ii11Ii1IiiI1 )
   return ( [ None , False ] )
   if 76 - 76: OoO0O00 * iIii1I11I1II1 + I1ii11iIi11i - ooOoO0o - I11i / i1IIi
   if 27 - 27: I1ii11iIi11i . IiII
   if 66 - 66: O0 / O0 * i1IIi . OoooooooOO % iIii1I11I1II1
   if 21 - 21: IiII - I1IiiI % OoooooooOO + o0oOOo0O0Ooo
   if 92 - 92: ooOoO0o + IiII
  packet = packet [ oOoo0oO : : ]
  if 52 - 52: II111iiii / I1IiiI . oO0o * IiII . I11i
  if 25 - 25: i11iIiiIii / OoOoOO00 - I1Ii111 / OoO0O00 . o0oOOo0O0Ooo . o0oOOo0O0Ooo
  if 6 - 6: oO0o . I11i
  if 43 - 43: I1ii11iIi11i + o0oOOo0O0Ooo
  OOOO0O00o = lisp_get_timestamp ( )
  if ( key . cipher_suite == LISP_CS_25519_CHACHA ) :
   iI1iiiiiii = chacha . ChaCha ( key . encrypt_key , O0o ) . decrypt
  elif ( key . cipher_suite == LISP_CS_25519_GCM ) :
   oOOO0OO = binascii . unhexlify ( key . encrypt_key )
   try :
    iI1iiiiiii = AES . new ( oOOO0OO , AES . MODE_GCM , O0o ) . decrypt
   except :
    self . packet_error = "no-decrypt-key"
    lprint ( "You need AES-GCM, do a 'pip install pycryptodome'" )
    return ( [ None , False ] )
    if 63 - 63: iIii1I11I1II1 + IiII % i1IIi / I1IiiI % II111iiii
  else :
   if ( ( len ( packet ) % 16 ) != 0 ) :
    dprint ( "Ciphertext not multiple of 16 bytes, packet dropped" )
    return ( [ None , False ] )
    if 60 - 60: o0oOOo0O0Ooo . OoOoOO00 % I1Ii111 / I1IiiI / O0
   oOOO0OO = binascii . unhexlify ( key . encrypt_key )
   iI1iiiiiii = AES . new ( oOOO0OO , AES . MODE_CBC , O0o ) . decrypt
   if 19 - 19: i11iIiiIii . I1IiiI + II111iiii / OOooOOo . I1ii11iIi11i * ooOoO0o
   if 59 - 59: iIii1I11I1II1 / I1ii11iIi11i % ooOoO0o
  Oooo = iI1iiiiiii ( packet )
  OOOO0O00o = int ( str ( time . time ( ) - OOOO0O00o ) . split ( "." ) [ 1 ] [ 0 : 6 ] )
  if 74 - 74: ooOoO0o % OoOoOO00 / Oo0Ooo
  if 2 - 2: IiII % IiII % I1Ii111
  if 60 - 60: OOooOOo
  if 73 - 73: ooOoO0o
  OO0o0o0oo = bold ( "Decrypt" , False )
  addr_str = "RLOC: " + red ( addr_str , False )
  i111iii1I1 = "poly" if key . do_poly else "sha256"
  i111iii1I1 = bold ( i111iii1I1 , False )
  iiIiII1 = "ICV({}): {}" . format ( i111iii1I1 , oOOoooOO )
  dprint ( "{} for key-id: {}, {}, {} (good), {}-time: {} usec" . format ( OO0o0o0oo , key . key_id , addr_str , iiIiII1 , iIiII1 , OOOO0O00o ) )
  if 86 - 86: OoOoOO00 . I11i / Oo0Ooo * I11i
  if 20 - 20: ooOoO0o - OOooOOo * OoO0O00 * o0oOOo0O0Ooo * OOooOOo / IiII
  if 40 - 40: I1IiiI * o0oOOo0O0Ooo . I1IiiI
  if 62 - 62: ooOoO0o + II111iiii % ooOoO0o
  if 50 - 50: OoooooooOO + oO0o * I1IiiI - Ii1I / i11iIiiIii
  if 5 - 5: O0 - I1IiiI
  if 44 - 44: II111iiii . II111iiii + OOooOOo * Ii1I
  self . packet = self . packet [ 0 : header_length ]
  return ( [ Oooo , True ] )
  if 16 - 16: II111iiii
  if 100 - 100: O0 - i1IIi
 def fragment_outer ( self , outer_hdr , inner_packet ) :
  iII1iiiiI1i = 1000
  if 58 - 58: iIii1I11I1II1 / I1IiiI - I1ii11iIi11i . o0oOOo0O0Ooo - Oo0Ooo
  if 88 - 88: OoO0O00 . I1Ii111 / I11i
  if 47 - 47: OoO0O00 + I1ii11iIi11i . ooOoO0o
  if 43 - 43: I1IiiI - o0oOOo0O0Ooo / o0oOOo0O0Ooo . II111iiii - Ii1I
  if 40 - 40: iII111i . OoOoOO00 * O0
  IIiiIii11 = [ ]
  I11iiIi1i1 = 0
  o00OOo00 = len ( inner_packet )
  while ( I11iiIi1i1 < o00OOo00 ) :
   IiI1IiI1iiI1 = inner_packet [ I11iiIi1i1 : : ]
   if ( len ( IiI1IiI1iiI1 ) > iII1iiiiI1i ) : IiI1IiI1iiI1 = IiI1IiI1iiI1 [ 0 : iII1iiiiI1i ]
   IIiiIii11 . append ( IiI1IiI1iiI1 )
   I11iiIi1i1 += len ( IiI1IiI1iiI1 )
   if 74 - 74: i1IIi
   if 15 - 15: i1IIi + IiII % I1IiiI / i11iIiiIii * OoOoOO00
   if 69 - 69: i11iIiiIii
   if 61 - 61: O0
   if 21 - 21: OoO0O00 % iIii1I11I1II1 . OoO0O00
   if 99 - 99: o0oOOo0O0Ooo * OOooOOo % oO0o * oO0o + OoooooooOO
  O0OO = [ ]
  I11iiIi1i1 = 0
  for IiI1IiI1iiI1 in IIiiIii11 :
   if 30 - 30: OoOoOO00 * Oo0Ooo % iIii1I11I1II1 % OoO0O00 + i11iIiiIii
   if 46 - 46: I1IiiI . IiII - i11iIiiIii - I1Ii111
   if 97 - 97: II111iiii % Oo0Ooo * IiII
   if 51 - 51: Oo0Ooo % OOooOOo . Oo0Ooo
   o0o0oO0OOO = I11iiIi1i1 if ( IiI1IiI1iiI1 == IIiiIii11 [ - 1 ] ) else 0x2000 + I11iiIi1i1
   o0o0oO0OOO = socket . htons ( o0o0oO0OOO )
   outer_hdr = outer_hdr [ 0 : 6 ] + struct . pack ( "H" , o0o0oO0OOO ) + outer_hdr [ 8 : : ]
   if 66 - 66: Ii1I * iIii1I11I1II1 - ooOoO0o / I1IiiI
   if 62 - 62: IiII . O0 . iIii1I11I1II1
   if 94 - 94: ooOoO0o % I11i % i1IIi
   if 90 - 90: Ii1I * OoO0O00
   I1i = socket . htons ( len ( IiI1IiI1iiI1 ) + 20 )
   outer_hdr = outer_hdr [ 0 : 2 ] + struct . pack ( "H" , I1i ) + outer_hdr [ 4 : : ]
   outer_hdr = lisp_ip_checksum ( outer_hdr )
   O0OO . append ( outer_hdr + IiI1IiI1iiI1 )
   I11iiIi1i1 += len ( IiI1IiI1iiI1 ) / 8
   if 77 - 77: I1Ii111 * OOooOOo / ooOoO0o + I1ii11iIi11i
  return ( O0OO )
  if 20 - 20: II111iiii + i1IIi
  if 17 - 17: OoooooooOO % oO0o - i1IIi % IiII % Oo0Ooo
 def fragment ( self ) :
  i1II1IiiIi = self . fix_outer_header ( self . packet )
  if 41 - 41: OoooooooOO . I1Ii111 % OoOoOO00 - iII111i
  if 58 - 58: oO0o + iIii1I11I1II1 - O0
  if 43 - 43: O0 . II111iiii % iIii1I11I1II1
  if 24 - 24: i1IIi / I1Ii111 * I11i / O0
  if 88 - 88: I1ii11iIi11i . I1Ii111 * Oo0Ooo - OOooOOo . OoOoOO00 . I1Ii111
  if 27 - 27: I1IiiI
  o00OOo00 = len ( i1II1IiiIi )
  if ( o00OOo00 <= 1500 ) : return ( [ i1II1IiiIi ] , "Fragment-None" )
  if 27 - 27: iIii1I11I1II1 % I11i - I1Ii111
  i1II1IiiIi = self . packet
  if 67 - 67: O0 / I1Ii111 * Ii1I % ooOoO0o . I1ii11iIi11i * oO0o
  if 9 - 9: II111iiii * i11iIiiIii . OOooOOo - OoO0O00
  if 31 - 31: i11iIiiIii * Ii1I . o0oOOo0O0Ooo % OOooOOo * I1ii11iIi11i % O0
  if 77 - 77: OoO0O00 + OoO0O00 . ooOoO0o * OoooooooOO + OoO0O00
  if 6 - 6: i1IIi - I11i
  if ( self . inner_version != 4 ) :
   O0o00ooo = random . randint ( 0 , 0xffff )
   iiiIIiiiI = i1II1IiiIi [ 0 : 4 ] + struct . pack ( "H" , O0o00ooo ) + i1II1IiiIi [ 6 : 20 ]
   I1i111 = i1II1IiiIi [ 20 : : ]
   O0OO = self . fragment_outer ( iiiIIiiiI , I1i111 )
   return ( O0OO , "Fragment-Outer" )
   if 30 - 30: II111iiii - o0oOOo0O0Ooo % I1Ii111 . I11i
   if 63 - 63: iIii1I11I1II1 / ooOoO0o
   if 24 - 24: Oo0Ooo / iIii1I11I1II1 % OOooOOo * OoOoOO00 - iIii1I11I1II1
   if 50 - 50: II111iiii
   if 39 - 39: II111iiii . OoOoOO00 - Oo0Ooo * i1IIi . OoooooooOO
  iIIiI = 56 if ( self . outer_version == 6 ) else 36
  iiiIIiiiI = i1II1IiiIi [ 0 : iIIiI ]
  O0O0O0OO00oo = i1II1IiiIi [ iIIiI : iIIiI + 20 ]
  I1i111 = i1II1IiiIi [ iIIiI + 20 : : ]
  if 39 - 39: IiII % OoOoOO00 * I1ii11iIi11i - OoooooooOO - Oo0Ooo
  if 75 - 75: i11iIiiIii . ooOoO0o % i1IIi . I1IiiI - oO0o + Oo0Ooo
  if 66 - 66: oO0o % I1ii11iIi11i . II111iiii / OoOoOO00 / OoO0O00
  if 47 - 47: iII111i + O0 / II111iiii * I1IiiI - OoooooooOO . Ii1I
  IIi = struct . unpack ( "H" , O0O0O0OO00oo [ 6 : 8 ] ) [ 0 ]
  IIi = socket . ntohs ( IIi )
  if ( IIi & 0x4000 ) :
   oo0 = bold ( "DF-bit set" , False )
   dprint ( "{} in inner header, packet discarded" . format ( oo0 ) )
   return ( [ ] , "Fragment-None-DF-bit" )
   if 87 - 87: I11i . I11i . II111iiii / OOooOOo
   if 86 - 86: oO0o % O0 + OoO0O00
  I11iiIi1i1 = 0
  o00OOo00 = len ( I1i111 )
  O0OO = [ ]
  while ( I11iiIi1i1 < o00OOo00 ) :
   O0OO . append ( I1i111 [ I11iiIi1i1 : I11iiIi1i1 + 1400 ] )
   I11iiIi1i1 += 1400
   if 52 - 52: Oo0Ooo / iII111i
   if 42 - 42: iIii1I11I1II1 * Ii1I / OoO0O00 + OOooOOo
   if 48 - 48: OoooooooOO - I1Ii111 . i11iIiiIii * iII111i - Ii1I - o0oOOo0O0Ooo
   if 59 - 59: iII111i / I11i . Oo0Ooo
   if 100 - 100: O0
  IIiiIii11 = O0OO
  O0OO = [ ]
  oOOO00Oo = True if IIi & 0x2000 else False
  IIi = ( IIi & 0x1fff ) * 8
  for IiI1IiI1iiI1 in IIiiIii11 :
   if 48 - 48: II111iiii + II111iiii * i1IIi / Ii1I
   if 37 - 37: iIii1I11I1II1 % I11i / IiII
   if 37 - 37: I1Ii111 - oO0o - OoO0O00
   if 42 - 42: iIii1I11I1II1 % Ii1I - I1ii11iIi11i + iIii1I11I1II1
   iiI1I = IIi / 8
   if ( oOOO00Oo ) :
    iiI1I |= 0x2000
   elif ( IiI1IiI1iiI1 != IIiiIii11 [ - 1 ] ) :
    iiI1I |= 0x2000
    if 64 - 64: IiII * iIii1I11I1II1 . I1ii11iIi11i / I11i * iIii1I11I1II1
   iiI1I = socket . htons ( iiI1I )
   O0O0O0OO00oo = O0O0O0OO00oo [ 0 : 6 ] + struct . pack ( "H" , iiI1I ) + O0O0O0OO00oo [ 8 : : ]
   if 4 - 4: ooOoO0o % IiII . I1Ii111
   if 91 - 91: I1ii11iIi11i + iIii1I11I1II1 % IiII
   if 90 - 90: ooOoO0o - I11i . OoO0O00 + OoO0O00
   if 45 - 45: OoOoOO00 / OoooooooOO . I1Ii111 % O0 * I1ii11iIi11i * Oo0Ooo
   if 65 - 65: o0oOOo0O0Ooo + I1Ii111 - O0
   if 30 - 30: IiII - iII111i - OoO0O00
   o00OOo00 = len ( IiI1IiI1iiI1 )
   IIi += o00OOo00
   I1i = socket . htons ( o00OOo00 + 20 )
   O0O0O0OO00oo = O0O0O0OO00oo [ 0 : 2 ] + struct . pack ( "H" , I1i ) + O0O0O0OO00oo [ 4 : 10 ] + struct . pack ( "H" , 0 ) + O0O0O0OO00oo [ 12 : : ]
   if 33 - 33: iIii1I11I1II1 / iII111i
   O0O0O0OO00oo = lisp_ip_checksum ( O0O0O0OO00oo )
   OOOO = O0O0O0OO00oo + IiI1IiI1iiI1
   if 10 - 10: II111iiii . OoO0O00
   if 89 - 89: ooOoO0o * Ii1I
   if 93 - 93: i1IIi . Ii1I * I1Ii111 . ooOoO0o
   if 54 - 54: iII111i . i1IIi . I1ii11iIi11i * o0oOOo0O0Ooo % iII111i
   if 30 - 30: I11i
   o00OOo00 = len ( OOOO )
   if ( self . outer_version == 4 ) :
    I1i = o00OOo00 + iIIiI
    o00OOo00 += 16
    iiiIIiiiI = iiiIIiiiI [ 0 : 2 ] + struct . pack ( "H" , I1i ) + iiiIIiiiI [ 4 : : ]
    if 85 - 85: II111iiii + ooOoO0o * I11i
    iiiIIiiiI = lisp_ip_checksum ( iiiIIiiiI )
    OOOO = iiiIIiiiI + OOOO
    OOOO = self . fix_outer_header ( OOOO )
    if 12 - 12: Ii1I . I1IiiI % o0oOOo0O0Ooo
    if 28 - 28: Ii1I - I1IiiI % OoO0O00 * I1Ii111
    if 80 - 80: OOooOOo * IiII
    if 4 - 4: iIii1I11I1II1 . I1Ii111 + II111iiii % OoooooooOO
    if 82 - 82: OoooooooOO / ooOoO0o * I11i * O0 . I1ii11iIi11i
   iiIIIII = iIIiI - 12
   I1i = socket . htons ( o00OOo00 )
   OOOO = OOOO [ 0 : iiIIIII ] + struct . pack ( "H" , I1i ) + OOOO [ iiIIIII + 2 : : ]
   if 19 - 19: II111iiii / OoOoOO00
   O0OO . append ( OOOO )
   if 80 - 80: OoOoOO00 + iIii1I11I1II1 . IiII
  return ( O0OO , "Fragment-Inner" )
  if 76 - 76: I1IiiI * OOooOOo
  if 12 - 12: iIii1I11I1II1 / I11i % Ii1I
 def fix_outer_header ( self , packet ) :
  if 49 - 49: OoO0O00 + II111iiii / IiII - O0 % Ii1I
  if 27 - 27: OoO0O00 + Oo0Ooo
  if 92 - 92: I1IiiI % iII111i
  if 31 - 31: OoooooooOO - oO0o / I1Ii111
  if 62 - 62: i11iIiiIii - I11i
  if 81 - 81: I11i
  if 92 - 92: OOooOOo - Oo0Ooo - OoooooooOO / IiII - i1IIi
  if 81 - 81: i1IIi / I1Ii111 % i11iIiiIii . iIii1I11I1II1 * OoOoOO00 + OoooooooOO
  if ( self . outer_version == 4 or self . inner_version == 4 ) :
   if ( lisp_is_macos ( ) ) :
    packet = packet [ 0 : 2 ] + packet [ 3 ] + packet [ 2 ] + packet [ 4 : 6 ] + packet [ 7 ] + packet [ 6 ] + packet [ 8 : : ]
    if 31 - 31: i1IIi % II111iiii
   else :
    packet = packet [ 0 : 2 ] + packet [ 3 ] + packet [ 2 ] + packet [ 4 : : ]
    if 13 - 13: iIii1I11I1II1 - II111iiii % O0 . Ii1I % OoO0O00
    if 2 - 2: OoooooooOO - Ii1I % oO0o / I1IiiI / o0oOOo0O0Ooo
  return ( packet )
  if 3 - 3: II111iiii / OOooOOo
  if 48 - 48: ooOoO0o . I1ii11iIi11i
 def send_packet ( self , lisp_raw_socket , dest ) :
  if ( lisp_flow_logging and dest != self . inner_dest ) : self . log_flow ( True )
  if 49 - 49: i1IIi - OoOoOO00 . Oo0Ooo + iIii1I11I1II1 - ooOoO0o / Oo0Ooo
  dest = dest . print_address_no_iid ( )
  O0OO , iIi11ii1 = self . fragment ( )
  if 49 - 49: oO0o . OoOoOO00
  for OOOO in O0OO :
   if ( len ( O0OO ) != 1 ) :
    self . packet = OOOO
    self . print_packet ( iIi11ii1 , True )
    if 73 - 73: Ii1I / I1IiiI / OoooooooOO + I1IiiI
    if 57 - 57: OOooOOo . Ii1I % o0oOOo0O0Ooo
   try : lisp_raw_socket . sendto ( OOOO , ( dest , 0 ) )
   except socket . error , ooo0OO :
    lprint ( "socket.sendto() failed: {}" . format ( ooo0OO ) )
    if 32 - 32: I11i / IiII - O0 * iIii1I11I1II1
    if 70 - 70: OoooooooOO % OoooooooOO % OoO0O00
    if 98 - 98: OoO0O00
    if 18 - 18: I11i + Oo0Ooo - OoO0O00 / I1Ii111 / OOooOOo
 def send_l2_packet ( self , l2_socket , mac_header ) :
  if ( l2_socket == None ) :
   lprint ( "No layer-2 socket, drop IPv6 packet" )
   return
   if 53 - 53: OOooOOo + o0oOOo0O0Ooo . oO0o / I11i
  if ( mac_header == None ) :
   lprint ( "Could not build MAC header, drop IPv6 packet" )
   return
   if 52 - 52: I1Ii111 + I1Ii111
   if 73 - 73: o0oOOo0O0Ooo . i11iIiiIii % OoooooooOO + ooOoO0o . OoooooooOO / OOooOOo
  i1II1IiiIi = mac_header + self . packet
  if 54 - 54: OoOoOO00 . OoooooooOO
  if 36 - 36: oO0o / II111iiii * IiII % I1ii11iIi11i
  if 31 - 31: II111iiii + OOooOOo - OoooooooOO . I11i
  if 28 - 28: Ii1I . I1ii11iIi11i
  if 77 - 77: I1ii11iIi11i % II111iiii
  if 81 - 81: OoOoOO00 % Ii1I / O0 * iIii1I11I1II1 % IiII . I1IiiI
  if 90 - 90: o0oOOo0O0Ooo
  if 44 - 44: o0oOOo0O0Ooo / I1ii11iIi11i . Oo0Ooo + OoOoOO00
  if 32 - 32: IiII - ooOoO0o * iII111i * I11i
  if 84 - 84: Ii1I + I1ii11iIi11i % I1IiiI + i11iIiiIii
  if 37 - 37: I11i % I1ii11iIi11i / ooOoO0o
  l2_socket . write ( i1II1IiiIi )
  return
  if 94 - 94: I11i / OoO0O00 . o0oOOo0O0Ooo
  if 1 - 1: Oo0Ooo . II111iiii
 def bridge_l2_packet ( self , eid , db ) :
  try : OoiiI11111II = db . dynamic_eids [ eid . print_address_no_iid ( ) ]
  except : return
  try : I111IIiIII = lisp_myinterfaces [ OoiiI11111II . interface ]
  except : return
  try :
   socket = I111IIiIII . get_bridge_socket ( )
   if ( socket == None ) : return
  except : return
  if 48 - 48: iII111i % i11iIiiIii . OoooooooOO * IiII % OoO0O00 . iII111i
  try : socket . send ( self . packet )
  except socket . error , ooo0OO :
   lprint ( "bridge_l2_packet(): socket.send() failed: {}" . format ( ooo0OO ) )
   if 6 - 6: O0 . ooOoO0o - oO0o / i11iIiiIii
   if 84 - 84: I11i / I1ii11iIi11i * o0oOOo0O0Ooo * OoO0O00 * OOooOOo * O0
   if 83 - 83: O0 % II111iiii + o0oOOo0O0Ooo / OoooooooOO
 def decode ( self , is_lisp_packet , lisp_ipc_socket , stats ) :
  self . packet_error = ""
  i1II1IiiIi = self . packet
  Ooi1IIii1i = len ( i1II1IiiIi )
  O0oOo0o0O0o = o0iii1i = True
  if 30 - 30: OoOoOO00 / I1IiiI - OoO0O00 - iII111i - i11iIiiIii
  if 84 - 84: i1IIi - I1IiiI % iII111i
  if 80 - 80: o0oOOo0O0Ooo % iII111i
  if 80 - 80: Ii1I
  iioOO = 0
  o0OOoOO = self . lisp_header . get_instance_id ( )
  if ( is_lisp_packet ) :
   I1OO = struct . unpack ( "B" , i1II1IiiIi [ 0 : 1 ] ) [ 0 ]
   self . outer_version = I1OO >> 4
   if ( self . outer_version == 4 ) :
    if 34 - 34: I1Ii111 . OoOoOO00 / i11iIiiIii / iII111i
    if 46 - 46: Oo0Ooo + II111iiii * I1IiiI + OOooOOo
    if 31 - 31: Ii1I * o0oOOo0O0Ooo * Ii1I + OoO0O00 * o0oOOo0O0Ooo . I1Ii111
    if 89 - 89: OoooooooOO * Ii1I * I1IiiI . ooOoO0o * Ii1I / iII111i
    if 46 - 46: i11iIiiIii
    Iiiii = struct . unpack ( "H" , i1II1IiiIi [ 10 : 12 ] ) [ 0 ]
    i1II1IiiIi = lisp_ip_checksum ( i1II1IiiIi )
    oOOoo0 = struct . unpack ( "H" , i1II1IiiIi [ 10 : 12 ] ) [ 0 ]
    if ( oOOoo0 != 0 ) :
     if ( Iiiii != 0 or lisp_is_macos ( ) == False ) :
      self . packet_error = "checksum-error"
      if ( stats ) :
       stats [ self . packet_error ] . increment ( Ooi1IIii1i )
       if 25 - 25: Oo0Ooo * I1IiiI + OOooOOo + I1Ii111 % OOooOOo
       if 84 - 84: O0 % Ii1I . Ii1I . iII111i * I11i
      lprint ( "IPv4 header checksum failed for outer header" )
      if ( lisp_flow_logging ) : self . log_flow ( False )
      return ( None )
      if 43 - 43: OoOoOO00 . I1ii11iIi11i % i1IIi
      if 61 - 61: I1IiiI + oO0o % I1Ii111 % iIii1I11I1II1 - OoooooooOO
      if 22 - 22: OOooOOo + II111iiii + Oo0Ooo
    oOo00Oo0o00oo = LISP_AFI_IPV4
    I11iiIi1i1 = 12
    self . outer_tos = struct . unpack ( "B" , i1II1IiiIi [ 1 : 2 ] ) [ 0 ]
    self . outer_ttl = struct . unpack ( "B" , i1II1IiiIi [ 8 : 9 ] ) [ 0 ]
    iioOO = 20
   elif ( self . outer_version == 6 ) :
    oOo00Oo0o00oo = LISP_AFI_IPV6
    I11iiIi1i1 = 8
    oO0O0oo = struct . unpack ( "H" , i1II1IiiIi [ 0 : 2 ] ) [ 0 ]
    self . outer_tos = ( socket . ntohs ( oO0O0oo ) >> 4 ) & 0xff
    self . outer_ttl = struct . unpack ( "B" , i1II1IiiIi [ 7 : 8 ] ) [ 0 ]
    iioOO = 40
   else :
    self . packet_error = "outer-header-error"
    if ( stats ) : stats [ self . packet_error ] . increment ( Ooi1IIii1i )
    lprint ( "Cannot decode outer header" )
    return ( None )
    if 64 - 64: OoOoOO00 % OoOoOO00 + o0oOOo0O0Ooo + Oo0Ooo
    if 79 - 79: Oo0Ooo - OoooooooOO % I1Ii111 + OoooooooOO - I11i % OoOoOO00
   self . outer_source . afi = oOo00Oo0o00oo
   self . outer_dest . afi = oOo00Oo0o00oo
   iII = self . outer_source . addr_length ( )
   if 89 - 89: I1IiiI / iII111i / OoooooooOO - i11iIiiIii + I1IiiI
   self . outer_source . unpack_address ( i1II1IiiIi [ I11iiIi1i1 : I11iiIi1i1 + iII ] )
   I11iiIi1i1 += iII
   self . outer_dest . unpack_address ( i1II1IiiIi [ I11iiIi1i1 : I11iiIi1i1 + iII ] )
   i1II1IiiIi = i1II1IiiIi [ iioOO : : ]
   self . outer_source . mask_len = self . outer_source . host_mask_len ( )
   self . outer_dest . mask_len = self . outer_dest . host_mask_len ( )
   if 64 - 64: i11iIiiIii + i1IIi % O0 . I11i
   if 64 - 64: ooOoO0o / i1IIi % iII111i
   if 84 - 84: OoOoOO00 - Oo0Ooo . ooOoO0o . IiII - Oo0Ooo
   if 99 - 99: I1Ii111
   o0I1IiiiiI1i1I = struct . unpack ( "H" , i1II1IiiIi [ 0 : 2 ] ) [ 0 ]
   self . udp_sport = socket . ntohs ( o0I1IiiiiI1i1I )
   o0I1IiiiiI1i1I = struct . unpack ( "H" , i1II1IiiIi [ 2 : 4 ] ) [ 0 ]
   self . udp_dport = socket . ntohs ( o0I1IiiiiI1i1I )
   o0I1IiiiiI1i1I = struct . unpack ( "H" , i1II1IiiIi [ 4 : 6 ] ) [ 0 ]
   self . udp_length = socket . ntohs ( o0I1IiiiiI1i1I )
   o0I1IiiiiI1i1I = struct . unpack ( "H" , i1II1IiiIi [ 6 : 8 ] ) [ 0 ]
   self . udp_checksum = socket . ntohs ( o0I1IiiiiI1i1I )
   i1II1IiiIi = i1II1IiiIi [ 8 : : ]
   if 48 - 48: I11i + II111iiii % oO0o % OOooOOo * II111iiii
   if 41 - 41: OoO0O00
   if 13 - 13: ooOoO0o - I1IiiI
   if 23 - 23: I1IiiI
   O0oOo0o0O0o = ( self . udp_dport == LISP_DATA_PORT or
 self . udp_sport == LISP_DATA_PORT )
   o0iii1i = ( self . udp_dport in ( LISP_L2_DATA_PORT , LISP_VXLAN_DATA_PORT ) )
   if 7 - 7: iII111i % I1ii11iIi11i
   if 64 - 64: I1Ii111 + i11iIiiIii
   if 35 - 35: OoOoOO00 + i1IIi % OOooOOo
   if 68 - 68: IiII . ooOoO0o
   if ( self . lisp_header . decode ( i1II1IiiIi ) == False ) :
    self . packet_error = "lisp-header-error"
    if ( stats ) : stats [ self . packet_error ] . increment ( Ooi1IIii1i )
    if 64 - 64: i1IIi + Oo0Ooo * I1IiiI / OOooOOo
    if ( lisp_flow_logging ) : self . log_flow ( False )
    lprint ( "Cannot decode LISP header" )
    return ( None )
    if 3 - 3: Oo0Ooo / ooOoO0o + ooOoO0o . I1ii11iIi11i
   i1II1IiiIi = i1II1IiiIi [ 8 : : ]
   o0OOoOO = self . lisp_header . get_instance_id ( )
   iioOO += 16
   if 50 - 50: iIii1I11I1II1 * oO0o
  if ( o0OOoOO == 0xffffff ) : o0OOoOO = 0
  if 85 - 85: i1IIi
  if 100 - 100: OoooooooOO / I11i % OoO0O00 + Ii1I
  if 42 - 42: Oo0Ooo / IiII . Ii1I * I1IiiI
  if 54 - 54: OoOoOO00 * iII111i + OoO0O00
  oOOOo = False
  o0OOOoO0O = self . lisp_header . k_bits
  if ( o0OOOoO0O ) :
   I1iiIiiii1111 = lisp_get_crypto_decap_lookup_key ( self . outer_source ,
 self . udp_sport )
   if ( I1iiIiiii1111 == None ) :
    self . packet_error = "no-decrypt-key"
    if ( stats ) : stats [ self . packet_error ] . increment ( Ooi1IIii1i )
    if 74 - 74: i1IIi / OoOoOO00 - Oo0Ooo . IiII % I1ii11iIi11i - IiII
    self . print_packet ( "Receive" , is_lisp_packet )
    o0o00o = bold ( "No key available" , False )
    dprint ( "{} for key-id {} to decrypt packet" . format ( o0o00o , o0OOOoO0O ) )
    if ( lisp_flow_logging ) : self . log_flow ( False )
    return ( None )
    if 30 - 30: OoOoOO00 / oO0o / Ii1I * o0oOOo0O0Ooo * oO0o . I1IiiI
    if 93 - 93: OoOoOO00
   o0OoOo0o0OOoO0 = lisp_crypto_keys_by_rloc_decap [ I1iiIiiii1111 ] [ o0OOOoO0O ]
   if ( o0OoOo0o0OOoO0 == None ) :
    self . packet_error = "no-decrypt-key"
    if ( stats ) : stats [ self . packet_error ] . increment ( Ooi1IIii1i )
    if 30 - 30: Ii1I % I11i + o0oOOo0O0Ooo
    self . print_packet ( "Receive" , is_lisp_packet )
    o0o00o = bold ( "No key available" , False )
    dprint ( "{} to decrypt packet from RLOC {}" . format ( o0o00o ,
 red ( I1iiIiiii1111 , False ) ) )
    if ( lisp_flow_logging ) : self . log_flow ( False )
    return ( None )
    if 65 - 65: iIii1I11I1II1 . iII111i / Ii1I
    if 12 - 12: I1IiiI + I1Ii111
    if 80 - 80: oO0o . O0
    if 90 - 90: II111iiii / OoO0O00 / Ii1I
    if 70 - 70: Ii1I - II111iiii . Oo0Ooo / Oo0Ooo
   o0OoOo0o0OOoO0 . use_count += 1
   i1II1IiiIi , oOOOo = self . decrypt ( i1II1IiiIi , iioOO , o0OoOo0o0OOoO0 ,
 I1iiIiiii1111 )
   if ( oOOOo == False ) :
    if ( stats ) : stats [ self . packet_error ] . increment ( Ooi1IIii1i )
    if ( lisp_flow_logging ) : self . log_flow ( False )
    return ( None )
    if 30 - 30: oO0o . OoO0O00 + I11i / iIii1I11I1II1 % Oo0Ooo / oO0o
    if 3 - 3: I1ii11iIi11i / II111iiii
    if 73 - 73: OoO0O00 * OoooooooOO - OoooooooOO + I1IiiI * Oo0Ooo
    if 87 - 87: o0oOOo0O0Ooo / IiII / i11iIiiIii
    if 95 - 95: i1IIi / Ii1I / Ii1I
    if 65 - 65: I1Ii111 + iII111i * iII111i
  I1OO = struct . unpack ( "B" , i1II1IiiIi [ 0 : 1 ] ) [ 0 ]
  self . inner_version = I1OO >> 4
  if ( O0oOo0o0O0o and self . inner_version == 4 and I1OO >= 0x45 ) :
   OoOO = socket . ntohs ( struct . unpack ( "H" , i1II1IiiIi [ 2 : 4 ] ) [ 0 ] )
   self . inner_tos = struct . unpack ( "B" , i1II1IiiIi [ 1 : 2 ] ) [ 0 ]
   self . inner_ttl = struct . unpack ( "B" , i1II1IiiIi [ 8 : 9 ] ) [ 0 ]
   self . inner_protocol = struct . unpack ( "B" , i1II1IiiIi [ 9 : 10 ] ) [ 0 ]
   self . inner_source . afi = LISP_AFI_IPV4
   self . inner_dest . afi = LISP_AFI_IPV4
   self . inner_source . unpack_address ( i1II1IiiIi [ 12 : 16 ] )
   self . inner_dest . unpack_address ( i1II1IiiIi [ 16 : 20 ] )
   IIi = socket . ntohs ( struct . unpack ( "H" , i1II1IiiIi [ 6 : 8 ] ) [ 0 ] )
   self . inner_is_fragment = ( IIi & 0x2000 or IIi != 0 )
   if ( self . inner_protocol == LISP_UDP_PROTOCOL ) :
    self . inner_sport = struct . unpack ( "H" , i1II1IiiIi [ 20 : 22 ] ) [ 0 ]
    self . inner_sport = socket . ntohs ( self . inner_sport )
    self . inner_dport = struct . unpack ( "H" , i1II1IiiIi [ 22 : 24 ] ) [ 0 ]
    self . inner_dport = socket . ntohs ( self . inner_dport )
    if 10 - 10: I1ii11iIi11i . o0oOOo0O0Ooo
  elif ( O0oOo0o0O0o and self . inner_version == 6 and I1OO >= 0x60 ) :
   OoOO = socket . ntohs ( struct . unpack ( "H" , i1II1IiiIi [ 4 : 6 ] ) [ 0 ] ) + 40
   oO0O0oo = struct . unpack ( "H" , i1II1IiiIi [ 0 : 2 ] ) [ 0 ]
   self . inner_tos = ( socket . ntohs ( oO0O0oo ) >> 4 ) & 0xff
   self . inner_ttl = struct . unpack ( "B" , i1II1IiiIi [ 7 : 8 ] ) [ 0 ]
   self . inner_protocol = struct . unpack ( "B" , i1II1IiiIi [ 6 : 7 ] ) [ 0 ]
   self . inner_source . afi = LISP_AFI_IPV6
   self . inner_dest . afi = LISP_AFI_IPV6
   self . inner_source . unpack_address ( i1II1IiiIi [ 8 : 24 ] )
   self . inner_dest . unpack_address ( i1II1IiiIi [ 24 : 40 ] )
   if ( self . inner_protocol == LISP_UDP_PROTOCOL ) :
    self . inner_sport = struct . unpack ( "H" , i1II1IiiIi [ 40 : 42 ] ) [ 0 ]
    self . inner_sport = socket . ntohs ( self . inner_sport )
    self . inner_dport = struct . unpack ( "H" , i1II1IiiIi [ 42 : 44 ] ) [ 0 ]
    self . inner_dport = socket . ntohs ( self . inner_dport )
    if 75 - 75: O0 * i1IIi - I11i / OOooOOo % OOooOOo / OoOoOO00
  elif ( o0iii1i ) :
   OoOO = len ( i1II1IiiIi )
   self . inner_tos = 0
   self . inner_ttl = 0
   self . inner_protocol = 0
   self . inner_source . afi = LISP_AFI_MAC
   self . inner_dest . afi = LISP_AFI_MAC
   self . inner_dest . unpack_address ( self . swap_mac ( i1II1IiiIi [ 0 : 6 ] ) )
   self . inner_source . unpack_address ( self . swap_mac ( i1II1IiiIi [ 6 : 12 ] ) )
  elif ( self . lisp_header . get_instance_id ( ) == 0xffffff ) :
   if ( lisp_flow_logging ) : self . log_flow ( False )
   return ( self )
  else :
   self . packet_error = "bad-inner-version"
   if ( stats ) : stats [ self . packet_error ] . increment ( Ooi1IIii1i )
   if 5 - 5: O0 - iII111i / I1Ii111 . o0oOOo0O0Ooo
   lprint ( "Cannot decode encapsulation, header version {}" . format ( hex ( I1OO ) ) )
   if 7 - 7: I1ii11iIi11i - OoOoOO00
   i1II1IiiIi = lisp_format_packet ( i1II1IiiIi [ 0 : 20 ] )
   lprint ( "Packet header: {}" . format ( i1II1IiiIi ) )
   if ( lisp_flow_logging and is_lisp_packet ) : self . log_flow ( False )
   return ( None )
   if 54 - 54: oO0o / iIii1I11I1II1 / OoooooooOO . i1IIi - OoOoOO00
  self . inner_source . mask_len = self . inner_source . host_mask_len ( )
  self . inner_dest . mask_len = self . inner_dest . host_mask_len ( )
  self . inner_source . instance_id = o0OOoOO
  self . inner_dest . instance_id = o0OOoOO
  if 57 - 57: iIii1I11I1II1 * Ii1I * iII111i / oO0o
  if 46 - 46: Ii1I
  if 61 - 61: o0oOOo0O0Ooo / ooOoO0o - II111iiii
  if 87 - 87: I1ii11iIi11i / I1IiiI
  if 45 - 45: OoOoOO00 * ooOoO0o / OoooooooOO + OoO0O00 . I1Ii111 / OoO0O00
  if ( lisp_nonce_echoing and is_lisp_packet ) :
   O00o = lisp_get_echo_nonce ( self . outer_source , None )
   if ( O00o == None ) :
    oooOOoo0 = self . outer_source . print_address_no_iid ( )
    O00o = lisp_echo_nonce ( oooOOoo0 )
    if 79 - 79: OoooooooOO - ooOoO0o * Ii1I - II111iiii % OoOoOO00 * IiII
   iI1III = self . lisp_header . get_nonce ( )
   if ( self . lisp_header . is_e_bit_set ( ) ) :
    O00o . receive_request ( lisp_ipc_socket , iI1III )
   elif ( O00o . request_nonce_sent ) :
    O00o . receive_echo ( lisp_ipc_socket , iI1III )
    if 42 - 42: ooOoO0o + iII111i + Ii1I * I11i . i1IIi
    if 72 - 72: I1IiiI + Ii1I
    if 33 - 33: i1IIi / IiII - i1IIi . I1IiiI
    if 48 - 48: ooOoO0o + OOooOOo . I1Ii111 % II111iiii + oO0o
    if 38 - 38: oO0o
    if 28 - 28: iIii1I11I1II1 * I11i . I1IiiI
    if 78 - 78: OoooooooOO . OoooooooOO / O0
  if ( oOOOo ) : self . packet += i1II1IiiIi [ : OoOO ]
  if 25 - 25: II111iiii % II111iiii - Ii1I . O0
  if 79 - 79: IiII / OoO0O00 * OoooooooOO * OoOoOO00 + I1IiiI
  if 68 - 68: I11i / iIii1I11I1II1 . Oo0Ooo + i11iIiiIii + o0oOOo0O0Ooo
  if 92 - 92: OoO0O00 . o0oOOo0O0Ooo . Ii1I % OoOoOO00
  if ( lisp_flow_logging and is_lisp_packet ) : self . log_flow ( False )
  return ( self )
  if 58 - 58: I1ii11iIi11i % Ii1I * Ii1I - iII111i
  if 9 - 9: ooOoO0o - Ii1I % II111iiii + IiII + OOooOOo % O0
 def swap_mac ( self , mac ) :
  return ( mac [ 1 ] + mac [ 0 ] + mac [ 3 ] + mac [ 2 ] + mac [ 5 ] + mac [ 4 ] )
  if 65 - 65: OOooOOo - OoO0O00 % i11iIiiIii
  if 58 - 58: iII111i
 def strip_outer_headers ( self ) :
  I11iiIi1i1 = 16
  I11iiIi1i1 += 20 if ( self . outer_version == 4 ) else 40
  self . packet = self . packet [ I11iiIi1i1 : : ]
  return ( self )
  if 2 - 2: II111iiii + i1IIi
  if 68 - 68: OOooOOo + Ii1I
 def hash_ports ( self ) :
  i1II1IiiIi = self . packet
  I1OO = self . inner_version
  o0o0oooO00O0 = 0
  if ( I1OO == 4 ) :
   iiiI = struct . unpack ( "B" , i1II1IiiIi [ 9 ] ) [ 0 ]
   if ( self . inner_is_fragment ) : return ( iiiI )
   if ( iiiI in [ 6 , 17 ] ) :
    o0o0oooO00O0 = iiiI
    o0o0oooO00O0 += struct . unpack ( "I" , i1II1IiiIi [ 20 : 24 ] ) [ 0 ]
    o0o0oooO00O0 = ( o0o0oooO00O0 >> 16 ) ^ ( o0o0oooO00O0 & 0xffff )
    if 28 - 28: Oo0Ooo / IiII . iII111i + OoO0O00 + I11i % Oo0Ooo
    if 45 - 45: Oo0Ooo / O0 % OoooooooOO
  if ( I1OO == 6 ) :
   iiiI = struct . unpack ( "B" , i1II1IiiIi [ 6 ] ) [ 0 ]
   if ( iiiI in [ 6 , 17 ] ) :
    o0o0oooO00O0 = iiiI
    o0o0oooO00O0 += struct . unpack ( "I" , i1II1IiiIi [ 40 : 44 ] ) [ 0 ]
    o0o0oooO00O0 = ( o0o0oooO00O0 >> 16 ) ^ ( o0o0oooO00O0 & 0xffff )
    if 92 - 92: Ii1I . OoOoOO00 . I11i - OoooooooOO / ooOoO0o
    if 80 - 80: iIii1I11I1II1 / i11iIiiIii + iII111i
  return ( o0o0oooO00O0 )
  if 41 - 41: I1Ii111 + OoO0O00 * I1IiiI * O0 * Oo0Ooo - OoOoOO00
  if 96 - 96: I1IiiI - iIii1I11I1II1
 def hash_packet ( self ) :
  o0o0oooO00O0 = self . inner_source . address ^ self . inner_dest . address
  o0o0oooO00O0 += self . hash_ports ( )
  if ( self . inner_version == 4 ) :
   o0o0oooO00O0 = ( o0o0oooO00O0 >> 16 ) ^ ( o0o0oooO00O0 & 0xffff )
  elif ( self . inner_version == 6 ) :
   o0o0oooO00O0 = ( o0o0oooO00O0 >> 64 ) ^ ( o0o0oooO00O0 & 0xffffffffffffffff )
   o0o0oooO00O0 = ( o0o0oooO00O0 >> 32 ) ^ ( o0o0oooO00O0 & 0xffffffff )
   o0o0oooO00O0 = ( o0o0oooO00O0 >> 16 ) ^ ( o0o0oooO00O0 & 0xffff )
   if 25 - 25: OoooooooOO . Ii1I % iII111i . IiII
  self . udp_sport = 0xf000 | ( o0o0oooO00O0 & 0xfff )
  if 67 - 67: OoooooooOO + I1Ii111 / ooOoO0o
  if 75 - 75: IiII / OoooooooOO . I1IiiI + I1Ii111 - II111iiii
 def print_packet ( self , s_or_r , is_lisp_packet ) :
  if ( is_lisp_packet == False ) :
   I1i11 = "{} -> {}" . format ( self . inner_source . print_address ( ) ,
 self . inner_dest . print_address ( ) )
   dprint ( ( "{} {}, tos/ttl: {}/{}, length: {}, packet: {} ..." ) . format ( bold ( s_or_r , False ) ,
   # Oo0Ooo
 green ( I1i11 , False ) , self . inner_tos ,
 self . inner_ttl , len ( self . packet ) ,
 lisp_format_packet ( self . packet [ 0 : 60 ] ) ) )
   return
   if 60 - 60: i11iIiiIii . O0 * iIii1I11I1II1 * OoOoOO00
   if 99 - 99: iIii1I11I1II1 - oO0o - OoOoOO00 / iIii1I11I1II1 * Oo0Ooo - oO0o
  if ( s_or_r . find ( "Receive" ) != - 1 ) :
   o0ooo0oooO = "decap"
   o0ooo0oooO += "-vxlan" if self . udp_dport == LISP_VXLAN_DATA_PORT else ""
  else :
   o0ooo0oooO = s_or_r
   if ( o0ooo0oooO in [ "Send" , "Replicate" ] or o0ooo0oooO . find ( "Fragment" ) != - 1 ) :
    o0ooo0oooO = "encap"
    if 89 - 89: i1IIi
    if 19 - 19: ooOoO0o / o0oOOo0O0Ooo % IiII - Ii1I
  iI1i1Iiii = "{} -> {}" . format ( self . outer_source . print_address_no_iid ( ) ,
 self . outer_dest . print_address_no_iid ( ) )
  if 15 - 15: Ii1I
  if 17 - 17: OoOoOO00 - I1IiiI
  if 63 - 63: OoOoOO00 - oO0o / iIii1I11I1II1 - Ii1I / I1Ii111
  if 34 - 34: iII111i / o0oOOo0O0Ooo + OOooOOo - o0oOOo0O0Ooo + Oo0Ooo . oO0o
  if 97 - 97: i1IIi
  if ( self . lisp_header . get_instance_id ( ) == 0xffffff ) :
   oooOo = ( "{} LISP packet, outer RLOCs: {}, outer tos/ttl: " + "{}/{}, outer UDP: {} -> {}, " )
   if 46 - 46: I1ii11iIi11i
   oooOo += bold ( "control-packet" , False ) + ": {} ..."
   if 30 - 30: OoO0O00 / O0 * o0oOOo0O0Ooo * I1Ii111 + OoooooooOO * iII111i
   dprint ( oooOo . format ( bold ( s_or_r , False ) , red ( iI1i1Iiii , False ) ,
 self . outer_tos , self . outer_ttl , self . udp_sport ,
 self . udp_dport , lisp_format_packet ( self . packet [ 0 : 56 ] ) ) )
   return
  else :
   oooOo = ( "{} LISP packet, outer RLOCs: {}, outer tos/ttl: " + "{}/{}, outer UDP: {} -> {}, inner EIDs: {}, " + "inner tos/ttl: {}/{}, length: {}, {}, packet: {} ..." )
   if 23 - 23: I11i
   if 36 - 36: IiII . iII111i - i1IIi + I1Ii111
   if 54 - 54: OoooooooOO . oO0o - iII111i
   if 76 - 76: I1Ii111
  if ( self . lisp_header . k_bits ) :
   if ( o0ooo0oooO == "encap" ) : o0ooo0oooO = "encrypt/encap"
   if ( o0ooo0oooO == "decap" ) : o0ooo0oooO = "decap/decrypt"
   if 61 - 61: ooOoO0o / II111iiii * ooOoO0o * OoOoOO00 * I1Ii111 . i11iIiiIii
   if 26 - 26: I1Ii111 / ooOoO0o - OoO0O00 . iIii1I11I1II1
  I1i11 = "{} -> {}" . format ( self . inner_source . print_address ( ) ,
 self . inner_dest . print_address ( ) )
  if 83 - 83: ooOoO0o % Ii1I / Oo0Ooo - iII111i / O0
  dprint ( oooOo . format ( bold ( s_or_r , False ) , red ( iI1i1Iiii , False ) ,
 self . outer_tos , self . outer_ttl , self . udp_sport , self . udp_dport ,
 green ( I1i11 , False ) , self . inner_tos , self . inner_ttl ,
 len ( self . packet ) , self . lisp_header . print_header ( o0ooo0oooO ) ,
 lisp_format_packet ( self . packet [ 0 : 56 ] ) ) )
  if 97 - 97: iIii1I11I1II1 * I11i
  if 95 - 95: OoO0O00
 def print_eid_tuple ( self ) :
  return ( lisp_print_eid_tuple ( self . inner_source , self . inner_dest ) )
  if 68 - 68: iIii1I11I1II1 . iIii1I11I1II1 / OoOoOO00 - II111iiii - iIii1I11I1II1
  if 75 - 75: ooOoO0o . I1IiiI * II111iiii
 def get_raw_socket ( self ) :
  o0OOoOO = str ( self . lisp_header . get_instance_id ( ) )
  if ( o0OOoOO == "0" ) : return ( None )
  if ( lisp_iid_to_interface . has_key ( o0OOoOO ) == False ) : return ( None )
  if 99 - 99: iIii1I11I1II1 * I1ii11iIi11i + IiII
  I111IIiIII = lisp_iid_to_interface [ o0OOoOO ]
  IiIIi1I1I11Ii = I111IIiIII . get_socket ( )
  if ( IiIIi1I1I11Ii == None ) :
   OO0o0o0oo = bold ( "SO_BINDTODEVICE" , False )
   Ooo0OOO0O00 = ( os . getenv ( "LISP_ENFORCE_BINDTODEVICE" ) != None )
   lprint ( "{} required for multi-tenancy support, {} packet" . format ( OO0o0o0oo , "drop" if Ooo0OOO0O00 else "forward" ) )
   if 43 - 43: II111iiii * II111iiii % o0oOOo0O0Ooo / OoO0O00
   if ( Ooo0OOO0O00 ) : return ( None )
   if 84 - 84: iIii1I11I1II1 . i1IIi % I1ii11iIi11i + iIii1I11I1II1 - I11i % I1ii11iIi11i
   if 84 - 84: I1Ii111 - oO0o + I1ii11iIi11i
  o0OOoOO = bold ( o0OOoOO , False )
  oOo0OOOOOO = bold ( I111IIiIII . device , False )
  dprint ( "Send packet on instance-id {} interface {}" . format ( o0OOoOO , oOo0OOOOOO ) )
  return ( IiIIi1I1I11Ii )
  if 80 - 80: iIii1I11I1II1 - Oo0Ooo % I1Ii111 % Oo0Ooo + I1IiiI % Ii1I
  if 86 - 86: I1Ii111 - oO0o % OOooOOo % i11iIiiIii
 def log_flow ( self , encap ) :
  global lisp_flow_log
  if 57 - 57: I1Ii111
  I11i1I1iIiI = os . path . exists ( "./log-flows" )
  if ( len ( lisp_flow_log ) == LISP_FLOW_LOG_SIZE or I11i1I1iIiI ) :
   oo0OoOO000O = [ lisp_flow_log ]
   lisp_flow_log = [ ]
   threading . Thread ( target = lisp_write_flow_log , args = oo0OoOO000O ) . start ( )
   if ( I11i1I1iIiI ) : os . system ( "rm ./log-flows" )
   return
   if 62 - 62: i1IIi * iIii1I11I1II1 % oO0o % OoOoOO00 / OoooooooOO
   if 39 - 39: Oo0Ooo % iII111i
  OOOO0O00o = datetime . datetime . now ( )
  lisp_flow_log . append ( [ OOOO0O00o , encap , self . packet , self ] )
  if 90 - 90: I1IiiI * I1ii11iIi11i . I11i * Ii1I - o0oOOo0O0Ooo
  if 40 - 40: O0 / IiII - II111iiii + o0oOOo0O0Ooo % Oo0Ooo
 def print_flow ( self , ts , encap , packet ) :
  ts = ts . strftime ( "%m/%d/%y %H:%M:%S.%f" ) [ : - 3 ]
  o00oOo0OoO0oO = "{}: {}" . format ( ts , "encap" if encap else "decap" )
  if 84 - 84: i1IIi / i1IIi - i1IIi . oO0o . OoO0O00 * I1ii11iIi11i
  oOO000000oO0 = red ( self . outer_source . print_address_no_iid ( ) , False )
  o0o00oo0OOo0O00OO0O = red ( self . outer_dest . print_address_no_iid ( ) , False )
  oOO0oOOoO = green ( self . inner_source . print_address ( ) , False )
  oo0O000O00 = green ( self . inner_dest . print_address ( ) , False )
  if 99 - 99: o0oOOo0O0Ooo + OOooOOo
  if ( self . lisp_header . get_instance_id ( ) == 0xffffff ) :
   o00oOo0OoO0oO += " {}:{} -> {}:{}, LISP control message type {}\n"
   o00oOo0OoO0oO = o00oOo0OoO0oO . format ( oOO000000oO0 , self . udp_sport , o0o00oo0OOo0O00OO0O , self . udp_dport ,
 self . inner_version )
   return ( o00oOo0OoO0oO )
   if 34 - 34: I1Ii111 * o0oOOo0O0Ooo . I1IiiI % i11iIiiIii
   if 61 - 61: iIii1I11I1II1 + oO0o * I11i - i1IIi % oO0o
  if ( self . outer_dest . is_null ( ) == False ) :
   o00oOo0OoO0oO += " {}:{} -> {}:{}, len/tos/ttl {}/{}/{}"
   o00oOo0OoO0oO = o00oOo0OoO0oO . format ( oOO000000oO0 , self . udp_sport , o0o00oo0OOo0O00OO0O , self . udp_dport ,
 len ( packet ) , self . outer_tos , self . outer_ttl )
   if 76 - 76: oO0o / OoOoOO00
   if 12 - 12: I1Ii111
   if 58 - 58: OoO0O00 + iIii1I11I1II1 % O0 + I11i + OoOoOO00 * OoooooooOO
   if 41 - 41: oO0o * I1IiiI
   if 76 - 76: oO0o . O0 * OoooooooOO + ooOoO0o
  if ( self . lisp_header . k_bits != 0 ) :
   oo0O00 = "\n"
   if ( self . packet_error != "" ) :
    oo0O00 = " ({})" . format ( self . packet_error ) + oo0O00
    if 19 - 19: i1IIi / IiII + I1ii11iIi11i * I1ii11iIi11i
   o00oOo0OoO0oO += ", encrypted" + oo0O00
   return ( o00oOo0OoO0oO )
   if 90 - 90: OoooooooOO * iII111i . i11iIiiIii . ooOoO0o - I1Ii111
   if 81 - 81: I1IiiI / OoooooooOO
   if 52 - 52: oO0o + I1Ii111 * I1Ii111 * Oo0Ooo - iIii1I11I1II1 + I1ii11iIi11i
   if 34 - 34: iII111i / OoO0O00 / Oo0Ooo
   if 92 - 92: I1Ii111 % iII111i % o0oOOo0O0Ooo . I1IiiI - I1ii11iIi11i - o0oOOo0O0Ooo
  if ( self . outer_dest . is_null ( ) == False ) :
   packet = packet [ 36 : : ] if self . outer_version == 4 else packet [ 56 : : ]
   if 40 - 40: I1IiiI / OoooooooOO + OoO0O00 * OoO0O00
   if 9 - 9: iIii1I11I1II1
  iiiI = packet [ 9 ] if self . inner_version == 4 else packet [ 6 ]
  iiiI = struct . unpack ( "B" , iiiI ) [ 0 ]
  if 57 - 57: ooOoO0o / Ii1I % o0oOOo0O0Ooo % i11iIiiIii
  o00oOo0OoO0oO += " {} -> {}, len/tos/ttl/prot {}/{}/{}/{}"
  o00oOo0OoO0oO = o00oOo0OoO0oO . format ( oOO0oOOoO , oo0O000O00 , len ( packet ) , self . inner_tos ,
 self . inner_ttl , iiiI )
  if 95 - 95: I1Ii111 - o0oOOo0O0Ooo
  if 65 - 65: i11iIiiIii - OoooooooOO / O0 * IiII % I11i
  if 53 - 53: OOooOOo + I1Ii111
  if 10 - 10: I11i * i1IIi . oO0o / I1Ii111 . OOooOOo / I1Ii111
  if ( iiiI in [ 6 , 17 ] ) :
   i1111I1iii1 = packet [ 20 : 24 ] if self . inner_version == 4 else packet [ 40 : 44 ]
   if ( len ( i1111I1iii1 ) == 4 ) :
    i1111I1iii1 = socket . ntohl ( struct . unpack ( "I" , i1111I1iii1 ) [ 0 ] )
    o00oOo0OoO0oO += ", ports {} -> {}" . format ( i1111I1iii1 >> 16 , i1111I1iii1 & 0xffff )
    if 89 - 89: IiII - i1IIi - IiII
  elif ( iiiI == 1 ) :
   oOOo00OOOO = packet [ 26 : 28 ] if self . inner_version == 4 else packet [ 46 : 48 ]
   if ( len ( oOOo00OOOO ) == 2 ) :
    oOOo00OOOO = socket . ntohs ( struct . unpack ( "H" , oOOo00OOOO ) [ 0 ] )
    o00oOo0OoO0oO += ", icmp-seq {}" . format ( oOOo00OOOO )
    if 70 - 70: i1IIi - iIii1I11I1II1 - I1Ii111
    if 49 - 49: I1Ii111 / II111iiii
  if ( self . packet_error != "" ) :
   o00oOo0OoO0oO += " ({})" . format ( self . packet_error )
   if 69 - 69: o0oOOo0O0Ooo + I1ii11iIi11i / iIii1I11I1II1 . IiII % I1ii11iIi11i * OoOoOO00
  o00oOo0OoO0oO += "\n"
  return ( o00oOo0OoO0oO )
  if 13 - 13: iIii1I11I1II1 + iII111i / Ii1I / i1IIi % OoO0O00 - iIii1I11I1II1
  if 60 - 60: I1Ii111
 def is_trace ( self ) :
  i1111I1iii1 = [ self . inner_sport , self . inner_dport ]
  return ( self . inner_protocol == LISP_UDP_PROTOCOL and
 LISP_TRACE_PORT in i1111I1iii1 )
  if 77 - 77: I1IiiI / I1ii11iIi11i
  if 95 - 95: I1Ii111 * i1IIi + oO0o
  if 40 - 40: II111iiii
  if 7 - 7: OOooOOo / OoO0O00
  if 88 - 88: i1IIi
  if 53 - 53: ooOoO0o . OOooOOo . o0oOOo0O0Ooo + oO0o
  if 17 - 17: iIii1I11I1II1 + i1IIi . I1ii11iIi11i + Ii1I % i1IIi . oO0o
  if 57 - 57: oO0o
  if 92 - 92: II111iiii - OoO0O00 - OOooOOo % I1IiiI - OoOoOO00 * I1Ii111
  if 16 - 16: iIii1I11I1II1 + OoooooooOO - ooOoO0o * IiII
  if 37 - 37: iII111i
  if 15 - 15: o0oOOo0O0Ooo % OoO0O00 / iII111i
  if 36 - 36: OoO0O00 + OoO0O00 % Oo0Ooo + Oo0Ooo / i1IIi % i1IIi
  if 20 - 20: OOooOOo * oO0o
  if 91 - 91: OoO0O00 % i1IIi - iIii1I11I1II1 . OOooOOo
  if 31 - 31: oO0o % i1IIi . OoooooooOO - o0oOOo0O0Ooo + OoooooooOO
LISP_N_BIT = 0x80000000
LISP_L_BIT = 0x40000000
LISP_E_BIT = 0x20000000
LISP_V_BIT = 0x10000000
LISP_I_BIT = 0x08000000
LISP_P_BIT = 0x04000000
LISP_K_BITS = 0x03000000
if 45 - 45: OOooOOo + I11i / OoooooooOO - Ii1I + OoooooooOO
class lisp_data_header ( ) :
 def __init__ ( self ) :
  self . first_long = 0
  self . second_long = 0
  self . k_bits = 0
  if 42 - 42: iIii1I11I1II1 * I1IiiI * I1Ii111
  if 62 - 62: OOooOOo * O0 % IiII . IiII . I1IiiI
 def print_header ( self , e_or_d ) :
  oo0I1I1iiI1i = lisp_hex_string ( self . first_long & 0xffffff )
  IiII1111I = lisp_hex_string ( self . second_long ) . zfill ( 8 )
  if 15 - 15: iIii1I11I1II1 % Oo0Ooo + OoooooooOO
  oooOo = ( "{} LISP-header -> flags: {}{}{}{}{}{}{}{}, nonce: {}, " + "iid/lsb: {}" )
  if 2 - 2: I1Ii111 % OoooooooOO - ooOoO0o * I1ii11iIi11i * IiII
  return ( oooOo . format ( bold ( e_or_d , False ) ,
 "N" if ( self . first_long & LISP_N_BIT ) else "n" ,
 "L" if ( self . first_long & LISP_L_BIT ) else "l" ,
 "E" if ( self . first_long & LISP_E_BIT ) else "e" ,
 "V" if ( self . first_long & LISP_V_BIT ) else "v" ,
 "I" if ( self . first_long & LISP_I_BIT ) else "i" ,
 "P" if ( self . first_long & LISP_P_BIT ) else "p" ,
 "K" if ( self . k_bits in [ 2 , 3 ] ) else "k" ,
 "K" if ( self . k_bits in [ 1 , 3 ] ) else "k" ,
 oo0I1I1iiI1i , IiII1111I ) )
  if 99 - 99: iIii1I11I1II1 . Oo0Ooo / ooOoO0o . OOooOOo % I1IiiI * I11i
  if 95 - 95: oO0o
 def encode ( self ) :
  oOo0ooO0O0oo = "II"
  oo0I1I1iiI1i = socket . htonl ( self . first_long )
  IiII1111I = socket . htonl ( self . second_long )
  if 31 - 31: i11iIiiIii + Ii1I % OoOoOO00
  I1I = struct . pack ( oOo0ooO0O0oo , oo0I1I1iiI1i , IiII1111I )
  return ( I1I )
  if 74 - 74: Oo0Ooo
  if 91 - 91: OOooOOo . I1IiiI % iII111i
 def decode ( self , packet ) :
  oOo0ooO0O0oo = "II"
  OO00OO = struct . calcsize ( oOo0ooO0O0oo )
  if ( len ( packet ) < OO00OO ) : return ( False )
  if 27 - 27: O0 * I1IiiI - iIii1I11I1II1 - iII111i % O0 . Oo0Ooo
  oo0I1I1iiI1i , IiII1111I = struct . unpack ( oOo0ooO0O0oo , packet [ : OO00OO ] )
  if 16 - 16: IiII % i11iIiiIii . IiII % OoooooooOO - oO0o
  if 88 - 88: Ii1I * iIii1I11I1II1 . I11i
  self . first_long = socket . ntohl ( oo0I1I1iiI1i )
  self . second_long = socket . ntohl ( IiII1111I )
  self . k_bits = ( self . first_long & LISP_K_BITS ) >> 24
  return ( True )
  if 20 - 20: O0 . i11iIiiIii * i1IIi % O0 . I1IiiI
  if 53 - 53: ooOoO0o / OoooooooOO - II111iiii
 def key_id ( self , key_id ) :
  self . first_long &= ~ ( 0x3 << 24 )
  self . first_long |= ( ( key_id & 0x3 ) << 24 )
  self . k_bits = key_id
  if 68 - 68: OoooooooOO . OoooooooOO . iIii1I11I1II1 / ooOoO0o - I11i % O0
  if 19 - 19: OoooooooOO * oO0o
 def nonce ( self , nonce ) :
  self . first_long |= LISP_N_BIT
  self . first_long |= nonce
  if 60 - 60: II111iiii - iII111i + o0oOOo0O0Ooo % OOooOOo
  if 97 - 97: O0 % O0
 def map_version ( self , version ) :
  self . first_long |= LISP_V_BIT
  self . first_long |= version
  if 35 - 35: iII111i - Ii1I . i11iIiiIii % O0 % I1ii11iIi11i
  if 92 - 92: OOooOOo % II111iiii . iII111i
 def instance_id ( self , iid ) :
  if ( iid == 0 ) : return
  self . first_long |= LISP_I_BIT
  self . second_long &= 0xff
  self . second_long |= ( iid << 8 )
  if 46 - 46: OoOoOO00 + I1IiiI % OoooooooOO * i11iIiiIii - Oo0Ooo
  if 47 - 47: iII111i * OoOoOO00 * IiII
 def get_instance_id ( self ) :
  return ( ( self . second_long >> 8 ) & 0xffffff )
  if 46 - 46: Ii1I
  if 42 - 42: iIii1I11I1II1
 def locator_status_bits ( self , lsbs ) :
  self . first_long |= LISP_L_BIT
  self . second_long &= 0xffffff00
  self . second_long |= ( lsbs & 0xff )
  if 32 - 32: Oo0Ooo - Ii1I . OoooooooOO - OoooooooOO - Oo0Ooo . iIii1I11I1II1
  if 34 - 34: Oo0Ooo
 def is_request_nonce ( self , nonce ) :
  return ( nonce & 0x80000000 )
  if 31 - 31: i1IIi - I11i + I1Ii111 + ooOoO0o . ooOoO0o . O0
  if 33 - 33: i1IIi / iII111i * OoO0O00
 def request_nonce ( self , nonce ) :
  self . first_long |= LISP_E_BIT
  self . first_long |= LISP_N_BIT
  self . first_long |= ( nonce & 0xffffff )
  if 2 - 2: oO0o . OOooOOo
  if 43 - 43: iIii1I11I1II1
 def is_e_bit_set ( self ) :
  return ( self . first_long & LISP_E_BIT )
  if 29 - 29: IiII % ooOoO0o + OoO0O00 . i1IIi + I1IiiI
  if 24 - 24: I1Ii111 / Ii1I * I1ii11iIi11i - OoooooooOO / I1IiiI . oO0o
 def get_nonce ( self ) :
  return ( self . first_long & 0xffffff )
  if 98 - 98: i1IIi - iII111i
  if 49 - 49: o0oOOo0O0Ooo . Ii1I . oO0o
  if 9 - 9: IiII - II111iiii * OoO0O00
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
  if 78 - 78: iIii1I11I1II1 / O0 * oO0o / iII111i / OoOoOO00
  if 15 - 15: ooOoO0o / oO0o
 def send_ipc ( self , ipc_socket , ipc ) :
  O0Oo00o0o = "lisp-itr" if lisp_i_am_itr else "lisp-etr"
  oooooO0oO0o = "lisp-etr" if lisp_i_am_itr else "lisp-itr"
  ipc = lisp_command_ipc ( ipc , O0Oo00o0o )
  lisp_ipc ( ipc , ipc_socket , oooooO0oO0o )
  if 63 - 63: Ii1I - II111iiii . I11i / OoOoOO00
  if 17 - 17: ooOoO0o
 def send_request_ipc ( self , ipc_socket , nonce ) :
  nonce = lisp_hex_string ( nonce )
  IIi1IIII = "nonce%R%{}%{}" . format ( self . rloc_str , nonce )
  self . send_ipc ( ipc_socket , IIi1IIII )
  if 33 - 33: II111iiii . I1ii11iIi11i - O0 * iIii1I11I1II1 % O0 . OoooooooOO
  if 53 - 53: Ii1I / I1IiiI * Ii1I + o0oOOo0O0Ooo + oO0o - Oo0Ooo
 def send_echo_ipc ( self , ipc_socket , nonce ) :
  nonce = lisp_hex_string ( nonce )
  IIi1IIII = "nonce%E%{}%{}" . format ( self . rloc_str , nonce )
  self . send_ipc ( ipc_socket , IIi1IIII )
  if 16 - 16: OoO0O00 % I1Ii111 . i1IIi / I1ii11iIi11i - O0
  if 85 - 85: i1IIi . i1IIi
 def receive_request ( self , ipc_socket , nonce ) :
  Ii11i1I1 = self . request_nonce_rcvd
  self . request_nonce_rcvd = nonce
  self . last_request_nonce_rcvd = lisp_get_timestamp ( )
  if ( lisp_i_am_rtr ) : return
  if ( Ii11i1I1 != nonce ) : self . send_request_ipc ( ipc_socket , nonce )
  if 70 - 70: I1ii11iIi11i . I1ii11iIi11i / I11i . I1ii11iIi11i
  if 37 - 37: i1IIi . I1Ii111 - II111iiii % o0oOOo0O0Ooo - i1IIi . oO0o
 def receive_echo ( self , ipc_socket , nonce ) :
  if ( self . request_nonce_sent != nonce ) : return
  self . last_echo_nonce_rcvd = lisp_get_timestamp ( )
  if ( self . echo_nonce_rcvd == nonce ) : return
  if 34 - 34: iIii1I11I1II1 / II111iiii
  self . echo_nonce_rcvd = nonce
  if ( lisp_i_am_rtr ) : return
  self . send_echo_ipc ( ipc_socket , nonce )
  if 3 - 3: o0oOOo0O0Ooo - OoooooooOO + iII111i . I11i
  if 88 - 88: I11i - iII111i
 def get_request_or_echo_nonce ( self , ipc_socket , remote_rloc ) :
  if 68 - 68: Oo0Ooo % oO0o . IiII - o0oOOo0O0Ooo / i1IIi / OoooooooOO
  if 34 - 34: I11i % Oo0Ooo + Ii1I
  if 93 - 93: Ii1I - I1Ii111 % O0
  if 11 - 11: i11iIiiIii
  if 6 - 6: II111iiii
  if ( self . request_nonce_sent and self . echo_nonce_sent and remote_rloc ) :
   i1iII11IiI = lisp_myrlocs [ 0 ] if remote_rloc . is_ipv4 ( ) else lisp_myrlocs [ 1 ]
   if 30 - 30: iIii1I11I1II1
   if 15 - 15: ooOoO0o * iIii1I11I1II1 * oO0o
   if ( remote_rloc . address > i1iII11IiI . address ) :
    oOO0oo = "exit"
    self . request_nonce_sent = None
   else :
    oOO0oo = "stay in"
    self . echo_nonce_sent = None
    if 96 - 96: I1Ii111 * iIii1I11I1II1 / OoOoOO00 % OOooOOo * II111iiii
    if 3 - 3: OOooOOo . Oo0Ooo / i11iIiiIii + OoO0O00
   i1 = bold ( "collision" , False )
   I1i = red ( i1iII11IiI . print_address_no_iid ( ) , False )
   O00oo00o000o = red ( remote_rloc . print_address_no_iid ( ) , False )
   lprint ( "Echo nonce {}, {} -> {}, {} request-nonce mode" . format ( i1 ,
 I1i , O00oo00o000o , oOO0oo ) )
   if 57 - 57: I11i - I11i % II111iiii % Oo0Ooo . o0oOOo0O0Ooo % Oo0Ooo
   if 91 - 91: I1IiiI - OoO0O00 - Oo0Ooo - Ii1I * iIii1I11I1II1
   if 68 - 68: OoO0O00 % O0 * iIii1I11I1II1 / oO0o * o0oOOo0O0Ooo + OOooOOo
   if 89 - 89: ooOoO0o * I1IiiI . oO0o
   if 75 - 75: ooOoO0o - iII111i % iII111i + ooOoO0o * o0oOOo0O0Ooo - I1ii11iIi11i
  if ( self . echo_nonce_sent != None ) :
   iI1III = self . echo_nonce_sent
   ooo0OO = bold ( "Echoing" , False )
   lprint ( "{} nonce 0x{} to {}" . format ( ooo0OO ,
 lisp_hex_string ( iI1III ) , red ( self . rloc_str , False ) ) )
   self . last_echo_nonce_sent = lisp_get_timestamp ( )
   self . echo_nonce_sent = None
   return ( iI1III )
   if 26 - 26: I11i * Ii1I % I1IiiI + iII111i
   if 38 - 38: iII111i - Oo0Ooo / Ii1I + oO0o . iII111i + IiII
   if 19 - 19: Ii1I
   if 51 - 51: iIii1I11I1II1
   if 8 - 8: OoO0O00 / o0oOOo0O0Ooo % iII111i . i11iIiiIii . OoooooooOO . Ii1I
   if 8 - 8: OoO0O00 * Oo0Ooo
   if 41 - 41: Oo0Ooo / OoO0O00 / OoOoOO00 - i11iIiiIii - OoOoOO00
  iI1III = self . request_nonce_sent
  i1oo0OO0Oo = self . last_request_nonce_sent
  if ( iI1III and i1oo0OO0Oo != None ) :
   if ( time . time ( ) - i1oo0OO0Oo >= LISP_NONCE_ECHO_INTERVAL ) :
    self . request_nonce_sent = None
    lprint ( "Stop request-nonce mode for {}, nonce 0x{}" . format ( red ( self . rloc_str , False ) , lisp_hex_string ( iI1III ) ) )
    if 4 - 4: OoOoOO00 * O0 - I11i
    return ( None )
    if 72 - 72: I11i + ooOoO0o / I1IiiI . IiII % OoO0O00 / i11iIiiIii
    if 13 - 13: I1Ii111 % o0oOOo0O0Ooo + OOooOOo + I1Ii111 + i11iIiiIii - I1ii11iIi11i
    if 70 - 70: II111iiii * II111iiii . I1IiiI
    if 11 - 11: iII111i
    if 20 - 20: Ii1I . I1Ii111 % Ii1I
    if 5 - 5: OOooOOo + iII111i
    if 23 - 23: I1Ii111 % iIii1I11I1II1 . I11i
    if 95 - 95: Oo0Ooo + i11iIiiIii % OOooOOo - oO0o
    if 11 - 11: I1ii11iIi11i / O0 + II111iiii
  if ( iI1III == None ) :
   iI1III = lisp_get_data_nonce ( )
   if ( self . recently_requested ( ) ) : return ( iI1III )
   if 95 - 95: I1Ii111 + IiII * iIii1I11I1II1
   self . request_nonce_sent = iI1III
   lprint ( "Start request-nonce mode for {}, nonce 0x{}" . format ( red ( self . rloc_str , False ) , lisp_hex_string ( iI1III ) ) )
   if 17 - 17: OoO0O00 - Oo0Ooo * O0 / Ii1I
   self . last_new_request_nonce_sent = lisp_get_timestamp ( )
   if 19 - 19: i1IIi - iIii1I11I1II1 . I11i
   if 2 - 2: Ii1I
   if 12 - 12: i11iIiiIii - iIii1I11I1II1 * IiII * iII111i
   if 19 - 19: O0 + oO0o + o0oOOo0O0Ooo
   if 81 - 81: iIii1I11I1II1
   if ( lisp_i_am_itr == False ) : return ( iI1III | 0x80000000 )
   self . send_request_ipc ( ipc_socket , iI1III )
  else :
   lprint ( "Continue request-nonce mode for {}, nonce 0x{}" . format ( red ( self . rloc_str , False ) , lisp_hex_string ( iI1III ) ) )
   if 51 - 51: o0oOOo0O0Ooo . I1ii11iIi11i * Ii1I / Oo0Ooo * II111iiii / O0
   if 44 - 44: i11iIiiIii % I1Ii111 % oO0o + I11i * oO0o . Ii1I
   if 89 - 89: OoooooooOO % II111iiii - OoO0O00 % i11iIiiIii
   if 7 - 7: IiII
   if 15 - 15: Oo0Ooo + iII111i + I1IiiI * o0oOOo0O0Ooo
   if 33 - 33: o0oOOo0O0Ooo * Oo0Ooo
   if 88 - 88: I1Ii111 % OOooOOo - OoOoOO00 - OoOoOO00 . I1IiiI
  self . last_request_nonce_sent = lisp_get_timestamp ( )
  return ( iI1III | 0x80000000 )
  if 52 - 52: II111iiii / II111iiii / I1IiiI - I1Ii111
  if 91 - 91: I1IiiI + o0oOOo0O0Ooo % II111iiii + OoO0O00
 def request_nonce_timeout ( self ) :
  if ( self . request_nonce_sent == None ) : return ( False )
  if ( self . request_nonce_sent == self . echo_nonce_rcvd ) : return ( False )
  if 66 - 66: iIii1I11I1II1 * II111iiii % Oo0Ooo % I1IiiI - Ii1I
  i11IiIIi11I = time . time ( ) - self . last_request_nonce_sent
  o0Oo00oOOo = self . last_echo_nonce_rcvd
  return ( i11IiIIi11I >= LISP_NONCE_ECHO_INTERVAL and o0Oo00oOOo == None )
  if 49 - 49: o0oOOo0O0Ooo - iIii1I11I1II1
  if 61 - 61: iII111i * ooOoO0o
 def recently_requested ( self ) :
  o0Oo00oOOo = self . last_request_nonce_sent
  if ( o0Oo00oOOo == None ) : return ( False )
  if 1 - 1: I1Ii111 * OoOoOO00
  i11IiIIi11I = time . time ( ) - o0Oo00oOOo
  return ( i11IiIIi11I <= LISP_NONCE_ECHO_INTERVAL )
  if 100 - 100: I1ii11iIi11i / O0 / ooOoO0o + I1ii11iIi11i
  if 48 - 48: OoooooooOO . iII111i + O0
 def recently_echoed ( self ) :
  if ( self . request_nonce_sent == None ) : return ( True )
  if 85 - 85: II111iiii - Ii1I
  if 93 - 93: IiII / i11iIiiIii - oO0o + OoO0O00 / i1IIi
  if 62 - 62: I1ii11iIi11i / OoooooooOO * I1IiiI - i1IIi
  if 81 - 81: oO0o / O0 * ooOoO0o % OoOoOO00 / O0
  o0Oo00oOOo = self . last_good_echo_nonce_rcvd
  if ( o0Oo00oOOo == None ) : o0Oo00oOOo = 0
  i11IiIIi11I = time . time ( ) - o0Oo00oOOo
  if ( i11IiIIi11I <= LISP_NONCE_ECHO_INTERVAL ) : return ( True )
  if 85 - 85: OoooooooOO + OoooooooOO
  if 23 - 23: i1IIi
  if 31 - 31: Oo0Ooo - iIii1I11I1II1 / I11i . OoO0O00
  if 74 - 74: Oo0Ooo - II111iiii - IiII
  if 50 - 50: I1IiiI - oO0o + oO0o * I11i + oO0o
  if 70 - 70: i1IIi % OoO0O00 / i1IIi
  o0Oo00oOOo = self . last_new_request_nonce_sent
  if ( o0Oo00oOOo == None ) : o0Oo00oOOo = 0
  i11IiIIi11I = time . time ( ) - o0Oo00oOOo
  return ( i11IiIIi11I <= LISP_NONCE_ECHO_INTERVAL )
  if 30 - 30: OoOoOO00 - i11iIiiIii
  if 94 - 94: OoOoOO00 % iII111i
 def change_state ( self , rloc ) :
  if ( rloc . up_state ( ) and self . recently_echoed ( ) == False ) :
   iI11ii = bold ( "down" , False )
   iIi1II111I1i1 = lisp_print_elapsed ( self . last_good_echo_nonce_rcvd )
   lprint ( "Take {} {}, last good echo: {}" . format ( red ( self . rloc_str , False ) , iI11ii , iIi1II111I1i1 ) )
   if 10 - 10: O0 . OoOoOO00 * IiII / I1Ii111 / i1IIi
   rloc . state = LISP_RLOC_NO_ECHOED_NONCE_STATE
   rloc . last_state_change = lisp_get_timestamp ( )
   return
   if 32 - 32: O0 / OOooOOo . ooOoO0o % I1Ii111
   if 18 - 18: IiII * iII111i / I11i / O0
  if ( rloc . no_echoed_nonce_state ( ) == False ) : return
  if 11 - 11: iIii1I11I1II1 / Ii1I + OoooooooOO % i1IIi * i11iIiiIii
  if ( self . recently_requested ( ) == False ) :
   OoOooooo = bold ( "up" , False )
   lprint ( "Bring {} {}, retry request-nonce mode" . format ( red ( self . rloc_str , False ) , OoOooooo ) )
   if 87 - 87: II111iiii - OoooooooOO / i1IIi . Ii1I - Oo0Ooo . i11iIiiIii
   rloc . state = LISP_RLOC_UP_STATE
   rloc . last_state_change = lisp_get_timestamp ( )
   if 47 - 47: Oo0Ooo % OoO0O00 - ooOoO0o - Oo0Ooo * oO0o
   if 72 - 72: o0oOOo0O0Ooo % o0oOOo0O0Ooo + iII111i + I1ii11iIi11i / Oo0Ooo
   if 30 - 30: Oo0Ooo + I1IiiI + i11iIiiIii / OoO0O00
 def print_echo_nonce ( self ) :
  o00OooooOOOO = lisp_print_elapsed ( self . last_request_nonce_sent )
  oo000o = lisp_print_elapsed ( self . last_good_echo_nonce_rcvd )
  if 6 - 6: OOooOOo + I1ii11iIi11i + Oo0Ooo
  o0OOo0o0o0ooo = lisp_print_elapsed ( self . last_echo_nonce_sent )
  o0OOoo = lisp_print_elapsed ( self . last_request_nonce_rcvd )
  IiIIi1I1I11Ii = space ( 4 )
  if 52 - 52: OoO0O00
  Oo0O = "Nonce-Echoing:\n"
  Oo0O += ( "{}Last request-nonce sent: {}\n{}Last echo-nonce " + "received: {}\n" ) . format ( IiIIi1I1I11Ii , o00OooooOOOO , IiIIi1I1I11Ii , oo000o )
  if 49 - 49: Ii1I . I1ii11iIi11i % ooOoO0o . Oo0Ooo * OOooOOo
  Oo0O += ( "{}Last request-nonce received: {}\n{}Last echo-nonce " + "sent: {}" ) . format ( IiIIi1I1I11Ii , o0OOoo , IiIIi1I1I11Ii , o0OOo0o0o0ooo )
  if 44 - 44: iIii1I11I1II1 / O0 * Oo0Ooo + I1IiiI . ooOoO0o
  if 20 - 20: iII111i + o0oOOo0O0Ooo . I1Ii111 / i11iIiiIii
  return ( Oo0O )
  if 7 - 7: OoOoOO00 / OoOoOO00 . I1Ii111 * O0 + IiII + oO0o
  if 98 - 98: II111iiii * IiII - I1IiiI % o0oOOo0O0Ooo - iII111i % I1ii11iIi11i
  if 69 - 69: i1IIi % OoO0O00 % I1Ii111 / ooOoO0o / ooOoO0o
  if 6 - 6: II111iiii % I1ii11iIi11i % i1IIi * ooOoO0o
  if 47 - 47: O0
  if 55 - 55: OoO0O00 % O0 / OoooooooOO
  if 49 - 49: I1IiiI . OoO0O00 * OoooooooOO % i11iIiiIii + iIii1I11I1II1 * i1IIi
  if 88 - 88: I1ii11iIi11i * iII111i + II111iiii
  if 62 - 62: OoooooooOO
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
    if 33 - 33: O0 . i11iIiiIii % o0oOOo0O0Ooo
   self . local_private_key = random . randint ( 0 , 2 ** 128 - 1 )
   o0OoOo0o0OOoO0 = lisp_hex_string ( self . local_private_key ) . zfill ( 32 )
   self . curve25519 = curve25519 . Private ( o0OoOo0o0OOoO0 )
  else :
   self . local_private_key = random . randint ( 0 , 0x1fff )
   if 50 - 50: ooOoO0o
  self . local_public_key = self . compute_public_key ( )
  self . remote_public_key = None
  self . shared_key = None
  self . encrypt_key = None
  self . icv_key = None
  self . icv = poly1305 if do_poly else hashlib . sha256
  self . iv = None
  self . get_iv ( )
  self . do_poly = do_poly
  if 81 - 81: i11iIiiIii * iIii1I11I1II1 / Oo0Ooo * OOooOOo
  if 83 - 83: i11iIiiIii - I1IiiI * i11iIiiIii
 def copy_keypair ( self , key ) :
  self . local_private_key = key . local_private_key
  self . local_public_key = key . local_public_key
  self . curve25519 = key . curve25519
  if 59 - 59: iII111i - OoooooooOO / ooOoO0o + I1ii11iIi11i . o0oOOo0O0Ooo - iII111i
  if 29 - 29: oO0o
 def get_iv ( self ) :
  if ( self . iv == None ) :
   self . iv = random . randint ( 0 , LISP_16_128_MASK )
  else :
   self . iv += 1
   if 26 - 26: O0 % OOooOOo - IiII . OOooOOo
  O0o = self . iv
  if ( self . cipher_suite == LISP_CS_25519_CHACHA ) :
   O0o = struct . pack ( "Q" , O0o & LISP_8_64_MASK )
  elif ( self . cipher_suite == LISP_CS_25519_GCM ) :
   OOo0O0 = struct . pack ( "I" , ( O0o >> 64 ) & LISP_4_32_MASK )
   IiiiiIiI = struct . pack ( "Q" , O0o & LISP_8_64_MASK )
   O0o = OOo0O0 + IiiiiIiI
  else :
   O0o = struct . pack ( "QQ" , O0o >> 64 , O0o & LISP_8_64_MASK )
  return ( O0o )
  if 15 - 15: Ii1I
  if 69 - 69: OoO0O00 % oO0o . I1ii11iIi11i * I1ii11iIi11i
 def key_length ( self , key ) :
  if ( type ( key ) != str ) : key = self . normalize_pub_key ( key )
  return ( len ( key ) / 2 )
  if 94 - 94: i11iIiiIii + OoooooooOO
  if 20 - 20: i11iIiiIii
 def print_key ( self , key ) :
  oOOO0OO = self . normalize_pub_key ( key )
  return ( "0x{}...{}({})" . format ( oOOO0OO [ 0 : 4 ] , oOOO0OO [ - 4 : : ] , self . key_length ( oOOO0OO ) ) )
  if 86 - 86: OoOoOO00 / OOooOOo
  if 40 - 40: iIii1I11I1II1 / ooOoO0o / I1IiiI + I1ii11iIi11i * OOooOOo
 def normalize_pub_key ( self , key ) :
  if ( type ( key ) == str ) :
   if ( self . curve25519 ) : return ( binascii . hexlify ( key ) )
   return ( key )
   if 1 - 1: OoO0O00 * ooOoO0o + IiII . oO0o / ooOoO0o
  key = lisp_hex_string ( key ) . zfill ( 256 )
  return ( key )
  if 91 - 91: Ii1I + I11i - Oo0Ooo % OoOoOO00 . iII111i
  if 51 - 51: OOooOOo / I11i
 def print_keys ( self , do_bold = True ) :
  I1i = bold ( "local-key: " , False ) if do_bold else "local-key: "
  if ( self . local_public_key == None ) :
   I1i += "none"
  else :
   I1i += self . print_key ( self . local_public_key )
   if 51 - 51: ooOoO0o * oO0o - I1Ii111 + iII111i
  O00oo00o000o = bold ( "remote-key: " , False ) if do_bold else "remote-key: "
  if ( self . remote_public_key == None ) :
   O00oo00o000o += "none"
  else :
   O00oo00o000o += self . print_key ( self . remote_public_key )
   if 46 - 46: o0oOOo0O0Ooo - i11iIiiIii % OoO0O00 / Ii1I - OoOoOO00
  OOooOOoOoo0o = "ECDH" if ( self . curve25519 ) else "DH"
  I1i11i1II = self . cipher_suite
  return ( "{} cipher-suite: {}, {}, {}" . format ( OOooOOoOoo0o , I1i11i1II , I1i , O00oo00o000o ) )
  if 51 - 51: oO0o % oO0o / ooOoO0o . OOooOOo / iIii1I11I1II1 / i1IIi
  if 99 - 99: o0oOOo0O0Ooo / OOooOOo / oO0o . I1Ii111
 def compare_keys ( self , keys ) :
  if ( self . dh_g_value != keys . dh_g_value ) : return ( False )
  if ( self . dh_p_value != keys . dh_p_value ) : return ( False )
  if ( self . remote_public_key != keys . remote_public_key ) : return ( False )
  return ( True )
  if 3 - 3: I11i
  if 26 - 26: OoO0O00 % i1IIi * O0 . I1Ii111
 def compute_public_key ( self ) :
  if ( self . curve25519 ) : return ( self . curve25519 . get_public ( ) . public )
  if 31 - 31: O0 - IiII * i11iIiiIii * i1IIi
  o0OoOo0o0OOoO0 = self . local_private_key
  O0oOo00Oo0oo0 = self . dh_g_value
  i111 = self . dh_p_value
  return ( int ( ( O0oOo00Oo0oo0 ** o0OoOo0o0OOoO0 ) % i111 ) )
  if 63 - 63: ooOoO0o % I1IiiI . OOooOOo - ooOoO0o / Oo0Ooo % I1IiiI
  if 39 - 39: o0oOOo0O0Ooo . i1IIi % oO0o / I11i % O0
 def compute_shared_key ( self , ed , print_shared = False ) :
  o0OoOo0o0OOoO0 = self . local_private_key
  o0O0OOooO = self . remote_public_key
  if 1 - 1: I1Ii111 * OoO0O00 - iII111i
  O0O = bold ( "Compute {} shared-key" . format ( ed ) , False )
  lprint ( "{}, key-material: {}" . format ( O0O , self . print_keys ( ) ) )
  if 57 - 57: iIii1I11I1II1
  if ( self . curve25519 ) :
   IIIi1ii1i1 = curve25519 . Public ( o0O0OOooO )
   self . shared_key = self . curve25519 . get_shared_key ( IIIi1ii1i1 )
  else :
   i111 = self . dh_p_value
   self . shared_key = ( o0O0OOooO ** o0OoOo0o0OOoO0 ) % i111
   if 6 - 6: iIii1I11I1II1 * II111iiii
   if 38 - 38: I1IiiI
   if 42 - 42: o0oOOo0O0Ooo
   if 8 - 8: i11iIiiIii / ooOoO0o
   if 33 - 33: I1Ii111 * IiII - O0 + I1IiiI / IiII
   if 19 - 19: i1IIi % II111iiii
   if 85 - 85: IiII - o0oOOo0O0Ooo % OOooOOo - II111iiii
  if ( print_shared ) :
   oOOO0OO = self . print_key ( self . shared_key )
   lprint ( "Computed shared-key: {}" . format ( oOOO0OO ) )
   if 56 - 56: Ii1I * i11iIiiIii
   if 92 - 92: II111iiii - O0 . I1Ii111
   if 59 - 59: OoOoOO00
   if 47 - 47: II111iiii - I1ii11iIi11i - Ii1I
   if 9 - 9: I1ii11iIi11i - IiII
  self . compute_encrypt_icv_keys ( )
  if 64 - 64: i1IIi
  if 71 - 71: IiII * o0oOOo0O0Ooo
  if 99 - 99: o0oOOo0O0Ooo
  if 28 - 28: OoooooooOO % O0 - OOooOOo / o0oOOo0O0Ooo / I1IiiI
  self . rekey_count += 1
  self . last_rekey = lisp_get_timestamp ( )
  if 41 - 41: II111iiii * IiII / OoO0O00 . oO0o
  if 50 - 50: OoooooooOO + iIii1I11I1II1 / oO0o / OOooOOo . i11iIiiIii . ooOoO0o
 def compute_encrypt_icv_keys ( self ) :
  Ooo0OO00oo = hashlib . sha256
  if ( self . curve25519 ) :
   i11iII1IiI = self . shared_key
  else :
   i11iII1IiI = lisp_hex_string ( self . shared_key )
   if 21 - 21: IiII * OoOoOO00 - I1Ii111
   if 44 - 44: OoooooooOO + Ii1I
   if 84 - 84: i1IIi - II111iiii . OoooooooOO / OoOoOO00 % Ii1I
   if 7 - 7: i1IIi / IiII / iII111i
   if 97 - 97: OoO0O00 + iIii1I11I1II1
  I1i = self . local_public_key
  if ( type ( I1i ) != long ) : I1i = int ( binascii . hexlify ( I1i ) , 16 )
  O00oo00o000o = self . remote_public_key
  if ( type ( O00oo00o000o ) != long ) : O00oo00o000o = int ( binascii . hexlify ( O00oo00o000o ) , 16 )
  O0OOoo = "0001" + "lisp-crypto" + lisp_hex_string ( I1i ^ O00oo00o000o ) + "0100"
  if 38 - 38: IiII . o0oOOo0O0Ooo
  i1Ii111 = hmac . new ( O0OOoo , i11iII1IiI , Ooo0OO00oo ) . hexdigest ( )
  i1Ii111 = int ( i1Ii111 , 16 )
  if 58 - 58: oO0o * i11iIiiIii * I1IiiI * I1ii11iIi11i % i11iIiiIii - OoooooooOO
  if 11 - 11: II111iiii % iII111i
  if 59 - 59: ooOoO0o % Oo0Ooo - oO0o + IiII
  if 33 - 33: Ii1I + OoOoOO00 - I1ii11iIi11i + iIii1I11I1II1 % i1IIi * IiII
  ii11Ii1iii1I1 = ( i1Ii111 >> 128 ) & LISP_16_128_MASK
  Oo0OooO00oOo = i1Ii111 & LISP_16_128_MASK
  self . encrypt_key = lisp_hex_string ( ii11Ii1iii1I1 ) . zfill ( 32 )
  I1I111iIiI = 32 if self . do_poly else 40
  self . icv_key = lisp_hex_string ( Oo0OooO00oOo ) . zfill ( I1I111iIiI )
  if 1 - 1: Ii1I * OoooooooOO - ooOoO0o % OOooOOo - OoooooooOO
  if 83 - 83: OoooooooOO . iII111i
 def do_icv ( self , packet , nonce ) :
  if ( self . icv_key == None ) : return ( "" )
  if ( self . do_poly ) :
   iIo0O000O00o = self . icv . poly1305aes
   iiooo = self . icv . binascii . hexlify
   nonce = iiooo ( nonce )
   ii111I1I1I = iIo0O000O00o ( self . encrypt_key , self . icv_key , nonce , packet )
   ii111I1I1I = iiooo ( ii111I1I1I )
  else :
   o0OoOo0o0OOoO0 = binascii . unhexlify ( self . icv_key )
   ii111I1I1I = hmac . new ( o0OoOo0o0OOoO0 , packet , self . icv ) . hexdigest ( )
   ii111I1I1I = ii111I1I1I [ 0 : 40 ]
   if 34 - 34: I1ii11iIi11i % i1IIi - OoO0O00
  return ( ii111I1I1I )
  if 18 - 18: I1IiiI + I1Ii111 - iII111i % II111iiii / OoOoOO00 % O0
  if 59 - 59: O0 . o0oOOo0O0Ooo % I1ii11iIi11i * oO0o + I11i
 def add_key_by_nonce ( self , nonce ) :
  if ( lisp_crypto_keys_by_nonce . has_key ( nonce ) == False ) :
   lisp_crypto_keys_by_nonce [ nonce ] = [ None , None , None , None ]
   if 82 - 82: OoooooooOO
  lisp_crypto_keys_by_nonce [ nonce ] [ self . key_id ] = self
  if 88 - 88: O0 / o0oOOo0O0Ooo * o0oOOo0O0Ooo . o0oOOo0O0Ooo . O0
  if 27 - 27: i11iIiiIii % iII111i + Ii1I . OOooOOo
 def delete_key_by_nonce ( self , nonce ) :
  if ( lisp_crypto_keys_by_nonce . has_key ( nonce ) == False ) : return
  lisp_crypto_keys_by_nonce . pop ( nonce )
  if 9 - 9: OoO0O00
  if 43 - 43: Ii1I . OOooOOo + I1IiiI * i11iIiiIii
 def add_key_by_rloc ( self , addr_str , encap ) :
  ii1ii11Ii = lisp_crypto_keys_by_rloc_encap if encap else lisp_crypto_keys_by_rloc_decap
  if 20 - 20: Ii1I . Oo0Ooo - I11i % I11i - I1IiiI * OOooOOo
  if 80 - 80: II111iiii / o0oOOo0O0Ooo . OOooOOo . o0oOOo0O0Ooo
  if ( ii1ii11Ii . has_key ( addr_str ) == False ) :
   ii1ii11Ii [ addr_str ] = [ None , None , None , None ]
   if 29 - 29: OoooooooOO % II111iiii % i11iIiiIii - Oo0Ooo
  ii1ii11Ii [ addr_str ] [ self . key_id ] = self
  if 5 - 5: I1ii11iIi11i . II111iiii . i1IIi
  if 35 - 35: o0oOOo0O0Ooo + OoO0O00 - I1ii11iIi11i
  if 24 - 24: II111iiii
  if 23 - 23: Oo0Ooo - iII111i
  if 79 - 79: I11i . O0 - i1IIi
  if ( encap == False ) :
   lisp_write_ipc_decap_key ( addr_str , ii1ii11Ii [ addr_str ] )
   if 42 - 42: oO0o - i11iIiiIii % oO0o - I1Ii111 * O0 / II111iiii
   if 5 - 5: Oo0Ooo
   if 84 - 84: I1ii11iIi11i
 def encode_lcaf ( self , rloc_addr ) :
  oo0o0O0OO = self . normalize_pub_key ( self . local_public_key )
  OoiIiiI11Iii = self . key_length ( oo0o0O0OO )
  I1Iii1 = ( 6 + OoiIiiI11Iii + 2 )
  if ( rloc_addr != None ) : I1Iii1 += rloc_addr . addr_length ( )
  if 9 - 9: II111iiii % Oo0Ooo * Ii1I + IiII % OoO0O00 . i1IIi
  i1II1IiiIi = struct . pack ( "HBBBBHBB" , socket . htons ( LISP_AFI_LCAF ) , 0 , 0 ,
 LISP_LCAF_SECURITY_TYPE , 0 , socket . htons ( I1Iii1 ) , 1 , 0 )
  if 68 - 68: II111iiii % I1Ii111 * i11iIiiIii
  if 9 - 9: II111iiii + I1ii11iIi11i / iII111i
  if 51 - 51: I11i % I1ii11iIi11i + OoooooooOO - I1IiiI * OoOoOO00 * iII111i
  if 7 - 7: OOooOOo . IiII . I1Ii111 / Ii1I / Oo0Ooo
  if 83 - 83: I11i / Oo0Ooo
  if 23 - 23: iIii1I11I1II1
  I1i11i1II = self . cipher_suite
  i1II1IiiIi += struct . pack ( "BBH" , I1i11i1II , 0 , socket . htons ( OoiIiiI11Iii ) )
  if 10 - 10: I11i - o0oOOo0O0Ooo % OoooooooOO - I1ii11iIi11i
  if 64 - 64: OoO0O00 / I1IiiI
  if 23 - 23: I11i * I1Ii111 * o0oOOo0O0Ooo - I1IiiI % OoOoOO00 + o0oOOo0O0Ooo
  if 41 - 41: IiII * OoooooooOO . ooOoO0o % i11iIiiIii
  for Ii11 in range ( 0 , OoiIiiI11Iii * 2 , 16 ) :
   o0OoOo0o0OOoO0 = int ( oo0o0O0OO [ Ii11 : Ii11 + 16 ] , 16 )
   i1II1IiiIi += struct . pack ( "Q" , byte_swap_64 ( o0OoOo0o0OOoO0 ) )
   if 11 - 11: iIii1I11I1II1 . I1Ii111 - Oo0Ooo / I11i + II111iiii
   if 29 - 29: I11i . i11iIiiIii + i1IIi - Ii1I + O0 . I1IiiI
   if 8 - 8: o0oOOo0O0Ooo
   if 78 - 78: i1IIi - Oo0Ooo
   if 48 - 48: Ii1I - OoooooooOO + I1Ii111 % o0oOOo0O0Ooo - OoOoOO00 . I1IiiI
  if ( rloc_addr ) :
   i1II1IiiIi += struct . pack ( "H" , socket . htons ( rloc_addr . afi ) )
   i1II1IiiIi += rloc_addr . pack_address ( )
   if 42 - 42: I1Ii111
  return ( i1II1IiiIi )
  if 70 - 70: o0oOOo0O0Ooo / I11i + oO0o % I1IiiI % Oo0Ooo + OoO0O00
  if 80 - 80: OOooOOo
 def decode_lcaf ( self , packet , lcaf_len ) :
  if 12 - 12: Ii1I
  if 2 - 2: OoooooooOO
  if 100 - 100: Oo0Ooo / O0 * i11iIiiIii * OoooooooOO
  if 46 - 46: O0 % OoooooooOO
  if ( lcaf_len == 0 ) :
   oOo0ooO0O0oo = "HHBBH"
   OO00OO = struct . calcsize ( oOo0ooO0O0oo )
   if ( len ( packet ) < OO00OO ) : return ( None )
   if 22 - 22: iII111i + OoooooooOO - OoOoOO00 - OoO0O00 * I1Ii111 - oO0o
   oOo00Oo0o00oo , O0ooO , OOo000OOoOO , O0ooO , lcaf_len = struct . unpack ( oOo0ooO0O0oo , packet [ : OO00OO ] )
   if 13 - 13: Oo0Ooo
   if 70 - 70: iII111i
   if ( OOo000OOoOO != LISP_LCAF_SECURITY_TYPE ) :
    packet = packet [ lcaf_len + 6 : : ]
    return ( packet )
    if 51 - 51: O0 - I1ii11iIi11i / I11i * II111iiii + OoO0O00 % I1ii11iIi11i
   lcaf_len = socket . ntohs ( lcaf_len )
   packet = packet [ OO00OO : : ]
   if 58 - 58: oO0o + IiII % iII111i - Ii1I - OOooOOo % Ii1I
   if 86 - 86: o0oOOo0O0Ooo
   if 15 - 15: oO0o - iIii1I11I1II1 - II111iiii - IiII % I1ii11iIi11i
   if 80 - 80: IiII * iII111i . i1IIi % Ii1I % I1ii11iIi11i + ooOoO0o
   if 6 - 6: I1ii11iIi11i . oO0o . OoO0O00 + IiII
   if 65 - 65: I1ii11iIi11i / ooOoO0o
  OOo000OOoOO = LISP_LCAF_SECURITY_TYPE
  oOo0ooO0O0oo = "BBBBH"
  OO00OO = struct . calcsize ( oOo0ooO0O0oo )
  if ( len ( packet ) < OO00OO ) : return ( None )
  if 23 - 23: OOooOOo / OOooOOo * o0oOOo0O0Ooo * OOooOOo
  oooOOO00OOo , O0ooO , I1i11i1II , O0ooO , OoiIiiI11Iii = struct . unpack ( oOo0ooO0O0oo ,
 packet [ : OO00OO ] )
  if 81 - 81: Ii1I + iIii1I11I1II1 - O0 - I1ii11iIi11i - I1IiiI
  if 64 - 64: I1ii11iIi11i / O0 % IiII % iII111i % I1IiiI / I1Ii111
  if 13 - 13: Oo0Ooo % I1ii11iIi11i . iII111i % IiII / iII111i * OoooooooOO
  if 76 - 76: OOooOOo
  if 52 - 52: Oo0Ooo * iIii1I11I1II1 * Oo0Ooo * i1IIi
  if 9 - 9: iII111i - iII111i
  packet = packet [ OO00OO : : ]
  OoiIiiI11Iii = socket . ntohs ( OoiIiiI11Iii )
  if ( len ( packet ) < OoiIiiI11Iii ) : return ( None )
  if 3 - 3: O0 + O0 - O0 - O0 % OoooooooOO + oO0o
  if 20 - 20: OoO0O00 + I11i . II111iiii / i11iIiiIii
  if 50 - 50: OoooooooOO / OoO0O00 % iIii1I11I1II1
  if 41 - 41: I1ii11iIi11i % I1ii11iIi11i + IiII . iII111i % I1Ii111 * ooOoO0o
  O0Ii1iIii1I1 = [ LISP_CS_25519_CBC , LISP_CS_25519_GCM , LISP_CS_25519_CHACHA ,
 LISP_CS_1024 ]
  if ( I1i11i1II not in O0Ii1iIii1I1 ) :
   lprint ( "Cipher-suites {} supported, received {}" . format ( O0Ii1iIii1I1 ,
 I1i11i1II ) )
   packet = packet [ OoiIiiI11Iii : : ]
   return ( packet )
   if 21 - 21: OoOoOO00 + OoOoOO00 * ooOoO0o / OOooOOo * OoooooooOO . Oo0Ooo
   if 22 - 22: ooOoO0o % OoOoOO00 / o0oOOo0O0Ooo
  self . cipher_suite = I1i11i1II
  if 98 - 98: OoO0O00 / o0oOOo0O0Ooo * I1IiiI
  if 60 - 60: I1ii11iIi11i / IiII . i11iIiiIii / OoO0O00 % II111iiii
  if 6 - 6: iII111i % o0oOOo0O0Ooo + I1Ii111
  if 91 - 91: o0oOOo0O0Ooo + O0 * oO0o * IiII * I1ii11iIi11i
  if 83 - 83: OoooooooOO
  oo0o0O0OO = 0
  for Ii11 in range ( 0 , OoiIiiI11Iii , 8 ) :
   o0OoOo0o0OOoO0 = byte_swap_64 ( struct . unpack ( "Q" , packet [ Ii11 : Ii11 + 8 ] ) [ 0 ] )
   oo0o0O0OO <<= 64
   oo0o0O0OO |= o0OoOo0o0OOoO0
   if 52 - 52: o0oOOo0O0Ooo / OoOoOO00 % oO0o % OoO0O00 / IiII % o0oOOo0O0Ooo
  self . remote_public_key = oo0o0O0OO
  if 88 - 88: OOooOOo / i11iIiiIii / Ii1I / i11iIiiIii * I1ii11iIi11i % I11i
  if 43 - 43: OoOoOO00 * OoO0O00 % i1IIi * Ii1I + iIii1I11I1II1
  if 80 - 80: o0oOOo0O0Ooo . iII111i . OoooooooOO
  if 63 - 63: ooOoO0o . OOooOOo
  if 66 - 66: I1IiiI
  if ( self . curve25519 ) :
   o0OoOo0o0OOoO0 = lisp_hex_string ( self . remote_public_key )
   o0OoOo0o0OOoO0 = o0OoOo0o0OOoO0 . zfill ( 64 )
   OOooO0oOoO = ""
   for Ii11 in range ( 0 , len ( o0OoOo0o0OOoO0 ) , 2 ) :
    OOooO0oOoO += chr ( int ( o0OoOo0o0OOoO0 [ Ii11 : Ii11 + 2 ] , 16 ) )
    if 46 - 46: I1ii11iIi11i . II111iiii % oO0o + II111iiii
   self . remote_public_key = OOooO0oOoO
   if 55 - 55: OoooooooOO
   if 90 - 90: I1IiiI
  packet = packet [ OoiIiiI11Iii : : ]
  return ( packet )
  if 4 - 4: OOooOOo % ooOoO0o - OOooOOo - o0oOOo0O0Ooo
  if 30 - 30: IiII
  if 34 - 34: oO0o - II111iiii - o0oOOo0O0Ooo + iII111i + I1Ii111
  if 70 - 70: OoooooooOO + OoO0O00 * Oo0Ooo
  if 20 - 20: i11iIiiIii - II111iiii - ooOoO0o % oO0o . ooOoO0o
  if 50 - 50: iIii1I11I1II1 + I1Ii111 - I11i - OoooooooOO
  if 84 - 84: OoOoOO00 - I11i
  if 80 - 80: i11iIiiIii % OOooOOo - Oo0Ooo % OOooOOo
class lisp_thread ( ) :
 def __init__ ( self , name ) :
  self . thread_name = name
  self . thread_number = - 1
  self . number_of_pcap_threads = 0
  self . number_of_worker_threads = 0
  self . input_queue = Queue . Queue ( )
  self . input_stats = lisp_stats ( )
  self . lisp_packet = lisp_packet ( None )
  if 89 - 89: Ii1I * I11i + OoOoOO00 / i11iIiiIii
  if 68 - 68: OoooooooOO * I11i
  if 86 - 86: o0oOOo0O0Ooo / OoOoOO00
  if 40 - 40: iII111i
  if 62 - 62: ooOoO0o / OOooOOo
  if 74 - 74: iII111i % I1Ii111 / I1Ii111 - iIii1I11I1II1 - II111iiii + OOooOOo
  if 92 - 92: I11i % I1Ii111
  if 18 - 18: ooOoO0o + I1Ii111 / OOooOOo / oO0o + iIii1I11I1II1 % IiII
  if 94 - 94: I11i
  if 37 - 37: oO0o
  if 52 - 52: I1ii11iIi11i * I1IiiI . OOooOOo + i1IIi % oO0o / iIii1I11I1II1
  if 68 - 68: I1Ii111 - OoOoOO00 . i11iIiiIii + o0oOOo0O0Ooo
  if 71 - 71: i11iIiiIii / i1IIi * I1IiiI / OoOoOO00
  if 33 - 33: I11i . Oo0Ooo
  if 89 - 89: iII111i + i1IIi - IiII + ooOoO0o . II111iiii
  if 85 - 85: iIii1I11I1II1 - Ii1I * Oo0Ooo . oO0o + I1Ii111
  if 13 - 13: O0 + iIii1I11I1II1 % II111iiii + iIii1I11I1II1
  if 85 - 85: I1IiiI * iIii1I11I1II1 . iII111i / iII111i
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
  if 43 - 43: I1IiiI
  if 78 - 78: OoO0O00 % II111iiii + OoOoOO00 / I1IiiI
 def decode ( self , packet ) :
  oOo0ooO0O0oo = "BBBBQ"
  OO00OO = struct . calcsize ( oOo0ooO0O0oo )
  if ( len ( packet ) < OO00OO ) : return ( False )
  if 34 - 34: o0oOOo0O0Ooo % I1ii11iIi11i + Ii1I * I11i / oO0o
  i111Iii11i1Ii , oo00000ooOooO , oo0o0OO00oOO , self . record_count , self . nonce = struct . unpack ( oOo0ooO0O0oo , packet [ : OO00OO ] )
  if 45 - 45: iIii1I11I1II1 - Oo0Ooo . I11i - Oo0Ooo / ooOoO0o / o0oOOo0O0Ooo
  if 81 - 81: iII111i - I11i
  self . type = i111Iii11i1Ii >> 4
  if ( self . type == LISP_MAP_REQUEST ) :
   self . smr_bit = True if ( i111Iii11i1Ii & 0x01 ) else False
   self . rloc_probe = True if ( i111Iii11i1Ii & 0x02 ) else False
   self . smr_invoked_bit = True if ( oo00000ooOooO & 0x40 ) else False
   if 20 - 20: i1IIi
  if ( self . type == LISP_ECM ) :
   self . ddt_bit = True if ( i111Iii11i1Ii & 0x04 ) else False
   self . to_etr = True if ( i111Iii11i1Ii & 0x02 ) else False
   self . to_ms = True if ( i111Iii11i1Ii & 0x01 ) else False
   if 15 - 15: I1IiiI . Oo0Ooo . O0 . II111iiii / I11i . OoOoOO00
  if ( self . type == LISP_NAT_INFO ) :
   self . info_reply = True if ( i111Iii11i1Ii & 0x08 ) else False
   if 3 - 3: OoOoOO00
  return ( True )
  if 52 - 52: OoOoOO00
  if 79 - 79: I1IiiI + Oo0Ooo % OoOoOO00 - IiII + I1IiiI * oO0o
 def is_info_request ( self ) :
  return ( ( self . type == LISP_NAT_INFO and self . is_info_reply ( ) == False ) )
  if 52 - 52: OoOoOO00 % I1ii11iIi11i * Oo0Ooo % OoooooooOO - OoO0O00
  if 13 - 13: OOooOOo . Ii1I / I11i
 def is_info_reply ( self ) :
  return ( True if self . info_reply else False )
  if 93 - 93: ooOoO0o * I1IiiI * I1ii11iIi11i / I1ii11iIi11i
  if 62 - 62: ooOoO0o * Ii1I % I1ii11iIi11i - i1IIi - I1ii11iIi11i
 def is_rloc_probe ( self ) :
  return ( True if self . rloc_probe else False )
  if 24 - 24: OOooOOo
  if 71 - 71: IiII - i1IIi
 def is_smr ( self ) :
  return ( True if self . smr_bit else False )
  if 56 - 56: OoOoOO00 + oO0o
  if 74 - 74: iII111i / I1Ii111 / II111iiii - iII111i / oO0o % I11i
 def is_smr_invoked ( self ) :
  return ( True if self . smr_invoked_bit else False )
  if 19 - 19: IiII % OoooooooOO + OoooooooOO
  if 7 - 7: i1IIi
 def is_ddt ( self ) :
  return ( True if self . ddt_bit else False )
  if 91 - 91: OoOoOO00 - OoOoOO00 . IiII
  if 33 - 33: I1Ii111 - iIii1I11I1II1 / Ii1I % O0
 def is_to_etr ( self ) :
  return ( True if self . to_etr else False )
  if 80 - 80: IiII % OoooooooOO - IiII
  if 27 - 27: I1Ii111 - o0oOOo0O0Ooo * I1ii11iIi11i - I1IiiI
 def is_to_ms ( self ) :
  return ( True if self . to_ms else False )
  if 22 - 22: Oo0Ooo % OoooooooOO - Oo0Ooo - iII111i . Ii1I
  if 100 - 100: II111iiii / I1Ii111 / iII111i - I1ii11iIi11i * iIii1I11I1II1
  if 7 - 7: i1IIi . IiII % i11iIiiIii * I1ii11iIi11i . I11i % I1ii11iIi11i
  if 35 - 35: I1IiiI
  if 48 - 48: OoooooooOO % OoooooooOO - OoO0O00 . OoOoOO00
  if 22 - 22: ooOoO0o . i11iIiiIii . OoooooooOO . i1IIi
  if 12 - 12: OoOoOO00 % OOooOOo + oO0o . O0 % iIii1I11I1II1
  if 41 - 41: OoooooooOO
  if 13 - 13: I11i + I1Ii111 - I1Ii111 % oO0o / I11i
  if 4 - 4: I1IiiI + OOooOOo - IiII + iII111i
  if 78 - 78: Ii1I
  if 29 - 29: II111iiii
  if 79 - 79: iIii1I11I1II1 - i11iIiiIii + ooOoO0o - II111iiii . iIii1I11I1II1
  if 84 - 84: Oo0Ooo % I11i * O0 * I11i
  if 66 - 66: OOooOOo / iIii1I11I1II1 - OoOoOO00 % O0 . ooOoO0o
  if 12 - 12: Oo0Ooo + I1IiiI
  if 37 - 37: i1IIi * i11iIiiIii
  if 95 - 95: i11iIiiIii % I1Ii111 * Oo0Ooo + i1IIi . O0 + I1ii11iIi11i
  if 7 - 7: OoO0O00 * i11iIiiIii * iIii1I11I1II1 / OOooOOo / I1Ii111
  if 35 - 35: iII111i * OOooOOo
  if 65 - 65: II111iiii % i1IIi
  if 13 - 13: OoO0O00 * I1Ii111 + Oo0Ooo - IiII
  if 31 - 31: OoO0O00
  if 68 - 68: OoO0O00 + i1IIi / iIii1I11I1II1 + II111iiii * iIii1I11I1II1 + I1ii11iIi11i
  if 77 - 77: i11iIiiIii - I1Ii111 . I1ii11iIi11i % Oo0Ooo . Ii1I
  if 9 - 9: o0oOOo0O0Ooo
  if 55 - 55: OOooOOo % iIii1I11I1II1 + I11i . ooOoO0o
  if 71 - 71: i11iIiiIii / i1IIi + OoOoOO00
  if 23 - 23: i11iIiiIii
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
  if 58 - 58: Ii1I * iIii1I11I1II1 + ooOoO0o . ooOoO0o
  if 74 - 74: ooOoO0o - o0oOOo0O0Ooo * IiII % ooOoO0o
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
  if 93 - 93: iIii1I11I1II1 / OoOoOO00 % Oo0Ooo * I1Ii111 - OoO0O00 - o0oOOo0O0Ooo
  if 44 - 44: OoooooooOO
 def print_map_register ( self ) :
  oO = lisp_hex_string ( self . xtr_id )
  if 48 - 48: iII111i
  oooOo = ( "{} -> flags: {}{}{}{}{}{}{}{}{}, record-count: " +
 "{}, nonce: 0x{}, key/alg-id: {}/{}{}, auth-len: {}, xtr-id: " +
 "0x{}, site-id: {}" )
  if 85 - 85: I1ii11iIi11i . oO0o . O0
  lprint ( oooOo . format ( bold ( "Map-Register" , False ) , "P" if self . proxy_reply_requested else "p" ,
  # IiII
 "S" if self . lisp_sec_present else "s" ,
 "I" if self . xtr_id_present else "i" ,
 "T" if self . use_ttl_for_timeout else "t" ,
 "R" if self . merge_register_requested else "r" ,
 "M" if self . mobile_node else "m" ,
 "N" if self . map_notify_requested else "n" ,
 "F" if self . map_register_refresh else "f" ,
 "E" if self . encrypt_bit else "e" ,
 self . record_count , lisp_hex_string ( self . nonce ) , self . key_id ,
 self . alg_id , " (sha1)" if ( self . key_id == LISP_SHA_1_96_ALG_ID ) else ( " (sha2)" if ( self . key_id == LISP_SHA_256_128_ALG_ID ) else "" ) , self . auth_len , oO , self . site_id ) )
  if 68 - 68: I1ii11iIi11i % I1Ii111 + I11i . Oo0Ooo
  if 95 - 95: OOooOOo * i11iIiiIii . I11i + Ii1I / Ii1I
  if 43 - 43: IiII . OoooooooOO - II111iiii
  if 90 - 90: I1IiiI - iIii1I11I1II1 + I1ii11iIi11i * OOooOOo * oO0o
 def encode ( self ) :
  oo0I1I1iiI1i = ( LISP_MAP_REGISTER << 28 ) | self . record_count
  if ( self . proxy_reply_requested ) : oo0I1I1iiI1i |= 0x08000000
  if ( self . lisp_sec_present ) : oo0I1I1iiI1i |= 0x04000000
  if ( self . xtr_id_present ) : oo0I1I1iiI1i |= 0x02000000
  if ( self . map_register_refresh ) : oo0I1I1iiI1i |= 0x1000
  if ( self . use_ttl_for_timeout ) : oo0I1I1iiI1i |= 0x800
  if ( self . merge_register_requested ) : oo0I1I1iiI1i |= 0x400
  if ( self . mobile_node ) : oo0I1I1iiI1i |= 0x200
  if ( self . map_notify_requested ) : oo0I1I1iiI1i |= 0x100
  if ( self . encryption_key_id != None ) :
   oo0I1I1iiI1i |= 0x2000
   oo0I1I1iiI1i |= self . encryption_key_id << 14
   if 19 - 19: I1Ii111 * II111iiii % Oo0Ooo - i1IIi
   if 27 - 27: OoOoOO00 . O0 / I1ii11iIi11i . iIii1I11I1II1
   if 15 - 15: Ii1I + OoO0O00 % iIii1I11I1II1 - I1ii11iIi11i - i1IIi % o0oOOo0O0Ooo
   if 54 - 54: IiII - II111iiii . ooOoO0o + Ii1I
   if 45 - 45: oO0o + II111iiii . iII111i / I1ii11iIi11i
  if ( self . alg_id == LISP_NONE_ALG_ID ) :
   self . auth_len = 0
  else :
   if ( self . alg_id == LISP_SHA_1_96_ALG_ID ) :
    self . auth_len = LISP_SHA1_160_AUTH_DATA_LEN
    if 76 - 76: Ii1I + iII111i - IiII * iIii1I11I1II1 % i1IIi
   if ( self . alg_id == LISP_SHA_256_128_ALG_ID ) :
    self . auth_len = LISP_SHA2_256_AUTH_DATA_LEN
    if 72 - 72: ooOoO0o + II111iiii . O0 - iII111i / OoooooooOO . I1Ii111
    if 28 - 28: iIii1I11I1II1 . O0
    if 32 - 32: OoooooooOO
  i1II1IiiIi = struct . pack ( "I" , socket . htonl ( oo0I1I1iiI1i ) )
  i1II1IiiIi += struct . pack ( "QBBH" , self . nonce , self . key_id , self . alg_id ,
 socket . htons ( self . auth_len ) )
  if 29 - 29: I1ii11iIi11i
  i1II1IiiIi = self . zero_auth ( i1II1IiiIi )
  return ( i1II1IiiIi )
  if 41 - 41: Ii1I
  if 49 - 49: Ii1I % II111iiii . Ii1I - o0oOOo0O0Ooo - I11i * IiII
 def zero_auth ( self , packet ) :
  I11iiIi1i1 = struct . calcsize ( "I" ) + struct . calcsize ( "QHH" )
  Iii = ""
  O0O0O0OOO0o = 0
  if ( self . alg_id == LISP_NONE_ALG_ID ) : return ( packet )
  if ( self . alg_id == LISP_SHA_1_96_ALG_ID ) :
   Iii = struct . pack ( "QQI" , 0 , 0 , 0 )
   O0O0O0OOO0o = struct . calcsize ( "QQI" )
   if 98 - 98: OoO0O00 - Oo0Ooo * I1IiiI
  if ( self . alg_id == LISP_SHA_256_128_ALG_ID ) :
   Iii = struct . pack ( "QQQQ" , 0 , 0 , 0 , 0 )
   O0O0O0OOO0o = struct . calcsize ( "QQQQ" )
   if 90 - 90: I1IiiI
  packet = packet [ 0 : I11iiIi1i1 ] + Iii + packet [ I11iiIi1i1 + O0O0O0OOO0o : : ]
  return ( packet )
  if 27 - 27: iIii1I11I1II1 - oO0o
  if 73 - 73: OOooOOo . Oo0Ooo + Oo0Ooo % Oo0Ooo % O0
 def encode_auth ( self , packet ) :
  I11iiIi1i1 = struct . calcsize ( "I" ) + struct . calcsize ( "QHH" )
  O0O0O0OOO0o = self . auth_len
  Iii = self . auth_data
  packet = packet [ 0 : I11iiIi1i1 ] + Iii + packet [ I11iiIi1i1 + O0O0O0OOO0o : : ]
  return ( packet )
  if 8 - 8: iII111i . Ii1I - i1IIi % OoO0O00 / I11i
  if 13 - 13: Oo0Ooo / OoOoOO00 . I1ii11iIi11i . OOooOOo
 def decode ( self , packet ) :
  iIiiII11 = packet
  oOo0ooO0O0oo = "I"
  OO00OO = struct . calcsize ( oOo0ooO0O0oo )
  if ( len ( packet ) < OO00OO ) : return ( [ None , None ] )
  if 75 - 75: OoOoOO00 + Ii1I . i11iIiiIii / Ii1I
  oo0I1I1iiI1i = struct . unpack ( oOo0ooO0O0oo , packet [ : OO00OO ] )
  oo0I1I1iiI1i = socket . ntohl ( oo0I1I1iiI1i [ 0 ] )
  packet = packet [ OO00OO : : ]
  if 32 - 32: Ii1I + IiII + I1ii11iIi11i
  oOo0ooO0O0oo = "QBBH"
  OO00OO = struct . calcsize ( oOo0ooO0O0oo )
  if ( len ( packet ) < OO00OO ) : return ( [ None , None ] )
  if 79 - 79: i1IIi / Ii1I
  self . nonce , self . key_id , self . alg_id , self . auth_len = struct . unpack ( oOo0ooO0O0oo , packet [ : OO00OO ] )
  if 81 - 81: iIii1I11I1II1
  if 86 - 86: IiII % IiII % OoooooooOO
  self . auth_len = socket . ntohs ( self . auth_len )
  self . proxy_reply_requested = True if ( oo0I1I1iiI1i & 0x08000000 ) else False
  if 42 - 42: Oo0Ooo . oO0o + O0 / OOooOOo % OoooooooOO
  self . lisp_sec_present = True if ( oo0I1I1iiI1i & 0x04000000 ) else False
  self . xtr_id_present = True if ( oo0I1I1iiI1i & 0x02000000 ) else False
  self . use_ttl_for_timeout = True if ( oo0I1I1iiI1i & 0x800 ) else False
  self . map_register_refresh = True if ( oo0I1I1iiI1i & 0x1000 ) else False
  self . merge_register_requested = True if ( oo0I1I1iiI1i & 0x400 ) else False
  self . mobile_node = True if ( oo0I1I1iiI1i & 0x200 ) else False
  self . map_notify_requested = True if ( oo0I1I1iiI1i & 0x100 ) else False
  self . record_count = oo0I1I1iiI1i & 0xff
  if 19 - 19: ooOoO0o / Ii1I
  if 43 - 43: OoOoOO00 % Ii1I + Oo0Ooo - OoooooooOO . O0 % Oo0Ooo
  if 98 - 98: o0oOOo0O0Ooo * Oo0Ooo - Ii1I . ooOoO0o
  if 2 - 2: Oo0Ooo - ooOoO0o % iIii1I11I1II1
  self . encrypt_bit = True if oo0I1I1iiI1i & 0x2000 else False
  if ( self . encrypt_bit ) :
   self . encryption_key_id = ( oo0I1I1iiI1i >> 14 ) & 0x7
   if 88 - 88: I1Ii111 - OoO0O00
   if 79 - 79: iII111i
   if 45 - 45: II111iiii + iII111i . I11i . O0 * i1IIi - Ii1I
   if 48 - 48: I1ii11iIi11i + Oo0Ooo
   if 76 - 76: I1ii11iIi11i
  if ( self . xtr_id_present ) :
   if ( self . decode_xtr_id ( iIiiII11 ) == False ) : return ( [ None , None ] )
   if 98 - 98: II111iiii + I1IiiI - I1ii11iIi11i . Ii1I
   if 51 - 51: Ii1I + i11iIiiIii * OoO0O00 % Oo0Ooo / I1IiiI - iIii1I11I1II1
  packet = packet [ OO00OO : : ]
  if 20 - 20: I1Ii111 . I11i . Ii1I + I11i - OOooOOo * oO0o
  if 82 - 82: OoO0O00
  if 78 - 78: II111iiii / I11i - i11iIiiIii + I1ii11iIi11i * Oo0Ooo
  if 17 - 17: OoOoOO00
  if ( self . auth_len != 0 ) :
   if ( len ( packet ) < self . auth_len ) : return ( [ None , None ] )
   if 72 - 72: iII111i . Oo0Ooo - i11iIiiIii / I1IiiI
   if ( self . alg_id not in ( LISP_NONE_ALG_ID , LISP_SHA_1_96_ALG_ID ,
 LISP_SHA_256_128_ALG_ID ) ) :
    lprint ( "Invalid authentication alg-id: {}" . format ( self . alg_id ) )
    return ( [ None , None ] )
    if 64 - 64: oO0o
    if 80 - 80: o0oOOo0O0Ooo % iIii1I11I1II1
   O0O0O0OOO0o = self . auth_len
   if ( self . alg_id == LISP_SHA_1_96_ALG_ID ) :
    OO00OO = struct . calcsize ( "QQI" )
    if ( O0O0O0OOO0o < OO00OO ) :
     lprint ( "Invalid sha1-96 authentication length" )
     return ( [ None , None ] )
     if 63 - 63: IiII * i11iIiiIii
    O0O0OOo00Oo , IiI1iIIiIi1Ii , O0oOoOOO000 = struct . unpack ( "QQI" , packet [ : O0O0O0OOO0o ] )
    oOo00o0oO = ""
   elif ( self . alg_id == LISP_SHA_256_128_ALG_ID ) :
    OO00OO = struct . calcsize ( "QQQQ" )
    if ( O0O0O0OOO0o < OO00OO ) :
     lprint ( "Invalid sha2-256 authentication length" )
     return ( [ None , None ] )
     if 14 - 14: OoO0O00 / Oo0Ooo . i11iIiiIii
    O0O0OOo00Oo , IiI1iIIiIi1Ii , O0oOoOOO000 , oOo00o0oO = struct . unpack ( "QQQQ" ,
 packet [ : O0O0O0OOO0o ] )
   else :
    lprint ( "Unsupported authentication alg-id value {}" . format ( self . alg_id ) )
    if 9 - 9: I11i - II111iiii + I1Ii111 / oO0o % I1ii11iIi11i
    return ( [ None , None ] )
    if 17 - 17: iIii1I11I1II1 - ooOoO0o
   self . auth_data = lisp_concat_auth_data ( self . alg_id , O0O0OOo00Oo , IiI1iIIiIi1Ii ,
 O0oOoOOO000 , oOo00o0oO )
   iIiiII11 = self . zero_auth ( iIiiII11 )
   packet = packet [ self . auth_len : : ]
   if 99 - 99: Oo0Ooo + I1Ii111 % ooOoO0o - o0oOOo0O0Ooo
  return ( [ iIiiII11 , packet ] )
  if 52 - 52: I1ii11iIi11i
  if 93 - 93: iII111i . i11iIiiIii
 def encode_xtr_id ( self , packet ) :
  I1i1I = self . xtr_id >> 64
  O0OOoooO = self . xtr_id & 0xffffffffffffffff
  I1i1I = byte_swap_64 ( I1i1I )
  O0OOoooO = byte_swap_64 ( O0OOoooO )
  ooO0OOoOoOO00 = byte_swap_64 ( self . site_id )
  packet += struct . pack ( "QQQ" , I1i1I , O0OOoooO , ooO0OOoOoOO00 )
  return ( packet )
  if 65 - 65: IiII / I1ii11iIi11i
  if 84 - 84: OoooooooOO . i11iIiiIii % OoO0O00 * Oo0Ooo / iII111i
 def decode_xtr_id ( self , packet ) :
  OO00OO = struct . calcsize ( "QQQ" )
  if ( len ( packet ) < OO00OO ) : return ( [ None , None ] )
  packet = packet [ len ( packet ) - OO00OO : : ]
  I1i1I , O0OOoooO , ooO0OOoOoOO00 = struct . unpack ( "QQQ" ,
 packet [ : OO00OO ] )
  I1i1I = byte_swap_64 ( I1i1I )
  O0OOoooO = byte_swap_64 ( O0OOoooO )
  self . xtr_id = ( I1i1I << 64 ) | O0OOoooO
  self . site_id = byte_swap_64 ( ooO0OOoOoOO00 )
  return ( True )
  if 95 - 95: OoO0O00 - i11iIiiIii . OoO0O00 % OOooOOo * O0 + i11iIiiIii
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
  if 7 - 7: IiII * ooOoO0o + OoOoOO00
  if 22 - 22: iII111i
  if 48 - 48: I1ii11iIi11i . I1IiiI
  if 73 - 73: O0 . I1Ii111 - OoooooooOO % I11i % i1IIi
  if 14 - 14: I1Ii111 + Ii1I * Oo0Ooo
  if 49 - 49: Oo0Ooo
  if 57 - 57: O0 * ooOoO0o - iII111i - iIii1I11I1II1 * iII111i
  if 9 - 9: IiII . I11i
  if 23 - 23: O0 % OoooooooOO - O0 . I1IiiI + i11iIiiIii
  if 96 - 96: ooOoO0o % O0
  if 51 - 51: I1IiiI - iII111i / I1ii11iIi11i . I1ii11iIi11i + I1ii11iIi11i
  if 87 - 87: II111iiii . Ii1I * OoO0O00
  if 74 - 74: o0oOOo0O0Ooo % OoOoOO00 . iII111i % I1Ii111 . O0 % II111iiii
  if 5 - 5: oO0o - OoooooooOO / OoOoOO00
  if 30 - 30: I11i % o0oOOo0O0Ooo + i1IIi * OoooooooOO * OoO0O00 - II111iiii
  if 55 - 55: OoO0O00
  if 20 - 20: ooOoO0o * I1Ii111 * o0oOOo0O0Ooo - ooOoO0o
  if 32 - 32: Ii1I * oO0o
  if 85 - 85: i11iIiiIii . OoO0O00 + OoO0O00
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
  if 28 - 28: Oo0Ooo
  if 62 - 62: Oo0Ooo + OoooooooOO / iII111i
 def print_notify ( self ) :
  Iii = binascii . hexlify ( self . auth_data )
  if ( self . alg_id == LISP_SHA_1_96_ALG_ID and len ( Iii ) != 40 ) :
   Iii = self . auth_data
  elif ( self . alg_id == LISP_SHA_256_128_ALG_ID and len ( Iii ) != 64 ) :
   Iii = self . auth_data
   if 60 - 60: Ii1I / OoOoOO00 . I11i % OOooOOo
  oooOo = ( "{} -> record-count: {}, nonce: 0x{}, key/alg-id: " +
 "{}{}{}, auth-len: {}, auth-data: {}" )
  lprint ( oooOo . format ( bold ( "Map-Notify-Ack" , False ) if self . map_notify_ack else bold ( "Map-Notify" , False ) ,
  # O0 * iIii1I11I1II1 . I1Ii111 % O0
 self . record_count , lisp_hex_string ( self . nonce ) , self . key_id ,
 self . alg_id , " (sha1)" if ( self . key_id == LISP_SHA_1_96_ALG_ID ) else ( " (sha2)" if ( self . key_id == LISP_SHA_256_128_ALG_ID ) else "" ) , self . auth_len , Iii ) )
  if 99 - 99: I1IiiI
  if 30 - 30: O0 % OoooooooOO % I11i . i1IIi + I1Ii111 % OOooOOo
  if 9 - 9: O0 . iIii1I11I1II1
  if 44 - 44: I1ii11iIi11i % IiII
 def zero_auth ( self , packet ) :
  if ( self . alg_id == LISP_NONE_ALG_ID ) : return ( packet )
  if ( self . alg_id == LISP_SHA_1_96_ALG_ID ) :
   Iii = struct . pack ( "QQI" , 0 , 0 , 0 )
   if 6 - 6: OoO0O00
  if ( self . alg_id == LISP_SHA_256_128_ALG_ID ) :
   Iii = struct . pack ( "QQQQ" , 0 , 0 , 0 , 0 )
   if 82 - 82: iIii1I11I1II1 . I11i / IiII / OOooOOo * II111iiii % oO0o
  packet += Iii
  return ( packet )
  if 62 - 62: II111iiii
  if 96 - 96: I11i % OoOoOO00 * I1ii11iIi11i
 def encode ( self , eid_records , password ) :
  if ( self . map_notify_ack ) :
   oo0I1I1iiI1i = ( LISP_MAP_NOTIFY_ACK << 28 ) | self . record_count
  else :
   oo0I1I1iiI1i = ( LISP_MAP_NOTIFY << 28 ) | self . record_count
   if 94 - 94: Oo0Ooo - i1IIi . O0 % Oo0Ooo . ooOoO0o
  i1II1IiiIi = struct . pack ( "I" , socket . htonl ( oo0I1I1iiI1i ) )
  i1II1IiiIi += struct . pack ( "QBBH" , self . nonce , self . key_id , self . alg_id ,
 socket . htons ( self . auth_len ) )
  if 63 - 63: i11iIiiIii % I1ii11iIi11i % I1IiiI . IiII * o0oOOo0O0Ooo + OOooOOo
  if ( self . alg_id == LISP_NONE_ALG_ID ) :
   self . packet = i1II1IiiIi + eid_records
   return ( self . packet )
   if 77 - 77: o0oOOo0O0Ooo
   if 63 - 63: ooOoO0o * oO0o + ooOoO0o * Ii1I + Oo0Ooo / I1ii11iIi11i
   if 15 - 15: O0 . I1ii11iIi11i * I1ii11iIi11i
   if 65 - 65: I1Ii111 + O0 % o0oOOo0O0Ooo
   if 72 - 72: OOooOOo . OoOoOO00 / II111iiii
  i1II1IiiIi = self . zero_auth ( i1II1IiiIi )
  i1II1IiiIi += eid_records
  if 69 - 69: OOooOOo * II111iiii - ooOoO0o - i1IIi + i11iIiiIii
  o0o0oooO00O0 = lisp_hash_me ( i1II1IiiIi , self . alg_id , password , False )
  if 50 - 50: OoooooooOO * i1IIi / oO0o
  I11iiIi1i1 = struct . calcsize ( "I" ) + struct . calcsize ( "QHH" )
  O0O0O0OOO0o = self . auth_len
  self . auth_data = o0o0oooO00O0
  i1II1IiiIi = i1II1IiiIi [ 0 : I11iiIi1i1 ] + o0o0oooO00O0 + i1II1IiiIi [ I11iiIi1i1 + O0O0O0OOO0o : : ]
  self . packet = i1II1IiiIi
  return ( i1II1IiiIi )
  if 83 - 83: i1IIi
  if 38 - 38: OoooooooOO * iIii1I11I1II1
 def decode ( self , packet ) :
  iIiiII11 = packet
  oOo0ooO0O0oo = "I"
  OO00OO = struct . calcsize ( oOo0ooO0O0oo )
  if ( len ( packet ) < OO00OO ) : return ( None )
  if 54 - 54: OoooooooOO . I1Ii111
  oo0I1I1iiI1i = struct . unpack ( oOo0ooO0O0oo , packet [ : OO00OO ] )
  oo0I1I1iiI1i = socket . ntohl ( oo0I1I1iiI1i [ 0 ] )
  self . map_notify_ack = ( ( oo0I1I1iiI1i >> 28 ) == LISP_MAP_NOTIFY_ACK )
  self . record_count = oo0I1I1iiI1i & 0xff
  packet = packet [ OO00OO : : ]
  if 71 - 71: Ii1I
  oOo0ooO0O0oo = "QBBH"
  OO00OO = struct . calcsize ( oOo0ooO0O0oo )
  if ( len ( packet ) < OO00OO ) : return ( None )
  if 31 - 31: I11i . i11iIiiIii . OoO0O00 * Oo0Ooo % Ii1I . o0oOOo0O0Ooo
  self . nonce , self . key_id , self . alg_id , self . auth_len = struct . unpack ( oOo0ooO0O0oo , packet [ : OO00OO ] )
  if 92 - 92: OoooooooOO / O0 * i1IIi + iIii1I11I1II1
  self . nonce_key = lisp_hex_string ( self . nonce )
  self . auth_len = socket . ntohs ( self . auth_len )
  packet = packet [ OO00OO : : ]
  self . eid_records = packet [ self . auth_len : : ]
  if 93 - 93: ooOoO0o % I1Ii111
  if ( self . auth_len == 0 ) : return ( self . eid_records )
  if 46 - 46: I1ii11iIi11i * OoOoOO00 * IiII * I1ii11iIi11i . I1ii11iIi11i
  if 43 - 43: ooOoO0o . i1IIi
  if 68 - 68: IiII % Oo0Ooo . O0 - OoOoOO00 + I1ii11iIi11i . i11iIiiIii
  if 45 - 45: I1IiiI
  if ( len ( packet ) < self . auth_len ) : return ( None )
  if 17 - 17: OoooooooOO - ooOoO0o + Ii1I . OoooooooOO % Oo0Ooo
  O0O0O0OOO0o = self . auth_len
  if ( self . alg_id == LISP_SHA_1_96_ALG_ID ) :
   O0O0OOo00Oo , IiI1iIIiIi1Ii , O0oOoOOO000 = struct . unpack ( "QQI" , packet [ : O0O0O0OOO0o ] )
   oOo00o0oO = ""
   if 92 - 92: I1Ii111 - OOooOOo % OoO0O00 - o0oOOo0O0Ooo % i1IIi
  if ( self . alg_id == LISP_SHA_256_128_ALG_ID ) :
   O0O0OOo00Oo , IiI1iIIiIi1Ii , O0oOoOOO000 , oOo00o0oO = struct . unpack ( "QQQQ" ,
 packet [ : O0O0O0OOO0o ] )
   if 38 - 38: I1ii11iIi11i . I11i / OoOoOO00 % I11i
  self . auth_data = lisp_concat_auth_data ( self . alg_id , O0O0OOo00Oo , IiI1iIIiIi1Ii ,
 O0oOoOOO000 , oOo00o0oO )
  if 10 - 10: O0 . I1IiiI * o0oOOo0O0Ooo / iII111i
  OO00OO = struct . calcsize ( "I" ) + struct . calcsize ( "QHH" )
  packet = self . zero_auth ( iIiiII11 [ : OO00OO ] )
  OO00OO += O0O0O0OOO0o
  packet += iIiiII11 [ OO00OO : : ]
  return ( packet )
  if 61 - 61: Oo0Ooo - I1Ii111
  if 51 - 51: iII111i * ooOoO0o / O0 / O0
  if 52 - 52: OoooooooOO % O0
  if 56 - 56: oO0o - i1IIi * OoooooooOO - II111iiii
  if 28 - 28: i1IIi / I11i . o0oOOo0O0Ooo
  if 11 - 11: Oo0Ooo * OoooooooOO - i11iIiiIii
  if 13 - 13: i11iIiiIii . O0 / OOooOOo * i1IIi
  if 14 - 14: IiII + IiII . I11i / Ii1I . iIii1I11I1II1
  if 10 - 10: II111iiii . OOooOOo / iII111i
  if 35 - 35: iII111i / Oo0Ooo + O0 * iIii1I11I1II1 - O0
  if 3 - 3: I1ii11iIi11i
  if 42 - 42: I11i % Oo0Ooo + IiII - I11i . iIii1I11I1II1 - Ii1I
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
  if 80 - 80: i1IIi % OoOoOO00 + OoO0O00 - OoooooooOO / iIii1I11I1II1 + I1Ii111
  if 65 - 65: Ii1I
  if 71 - 71: I1Ii111 % I1Ii111 . oO0o + i11iIiiIii - i11iIiiIii
  if 16 - 16: iIii1I11I1II1 / I1IiiI / I1Ii111 - i11iIiiIii . ooOoO0o / OOooOOo
  if 13 - 13: o0oOOo0O0Ooo % O0 - I1Ii111 * OoooooooOO / Oo0Ooo - OoooooooOO
  if 78 - 78: oO0o % OoooooooOO
  if 73 - 73: I1IiiI % ooOoO0o % IiII + i1IIi - OoooooooOO / oO0o
  if 78 - 78: OoooooooOO % oO0o - i11iIiiIii
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
  if 37 - 37: IiII % Ii1I % i1IIi
  if 23 - 23: ooOoO0o - O0 + i11iIiiIii
 def print_prefix ( self ) :
  if ( self . target_group . is_null ( ) ) :
   return ( green ( self . target_eid . print_prefix ( ) , False ) )
   if 98 - 98: OoooooooOO
  return ( green ( self . target_eid . print_sg ( self . target_group ) , False ) )
  if 61 - 61: o0oOOo0O0Ooo . IiII . O0 + OoooooooOO + O0
  if 65 - 65: i1IIi * OOooOOo * OoooooooOO - IiII . iII111i - OoO0O00
 def print_map_request ( self ) :
  oO = ""
  if ( self . xtr_id != None and self . subscribe_bit ) :
   oO = "subscribe, xtr-id: 0x{}, " . format ( lisp_hex_string ( self . xtr_id ) )
   if 71 - 71: Ii1I * OoOoOO00
   if 33 - 33: i1IIi . i1IIi * OoooooooOO % I1Ii111 * o0oOOo0O0Ooo
   if 64 - 64: ooOoO0o / ooOoO0o + I1ii11iIi11i * OOooOOo % OOooOOo
  oooOo = ( "{} -> flags: {}{}{}{}{}{}{}{}{}{}, itr-rloc-" +
 "count: {} (+1), record-count: {}, nonce: 0x{}, source-eid: " +
 "afi {}, {}{}, target-eid: afi {}, {}, {}ITR-RLOCs:" )
  if 87 - 87: OoO0O00 * Oo0Ooo
  lprint ( oooOo . format ( bold ( "Map-Request" , False ) , "A" if self . auth_bit else "a" ,
  # ooOoO0o - OOooOOo / i1IIi * Ii1I * OoOoOO00
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
 self . target_eid . afi , green ( self . print_prefix ( ) , False ) , oO ) )
  if 80 - 80: oO0o
  o00OO0o0 = self . keys
  for oOooOo000O in self . itr_rlocs :
   lprint ( "  itr-rloc: afi {} {}{}" . format ( oOooOo000O . afi ,
 red ( oOooOo000O . print_address_no_iid ( ) , False ) ,
 "" if ( o00OO0o0 == None ) else ", " + o00OO0o0 [ 1 ] . print_keys ( ) ) )
   o00OO0o0 = None
   if 33 - 33: OOooOOo
   if 22 - 22: O0 + OOooOOo % i1IIi
   if 83 - 83: O0 + Ii1I % i11iIiiIii
 def sign_map_request ( self , privkey ) :
  I1III1iI1II = self . signature_eid . print_address ( )
  I1IiIiIiiiI = self . source_eid . print_address ( )
  iIi1ii1I1 = self . target_eid . print_address ( )
  IIIIII = lisp_hex_string ( self . nonce ) + I1IiIiIiiiI + iIi1ii1I1
  self . map_request_signature = privkey . sign ( IIIIII )
  iIiI1iI = binascii . b2a_base64 ( self . map_request_signature )
  iIiI1iI = { "source-eid" : I1IiIiIiiiI , "signature-eid" : I1III1iI1II ,
 "signature" : iIiI1iI }
  return ( json . dumps ( iIiI1iI ) )
  if 68 - 68: ooOoO0o
  if 70 - 70: OoOoOO00 - Oo0Ooo - I1Ii111 * OOooOOo * OOooOOo * I1IiiI
 def verify_map_request_sig ( self , pubkey ) :
  iii111Iiiii = green ( self . signature_eid . print_address ( ) , False )
  if ( pubkey == None ) :
   lprint ( "Public-key not found for signature-EID {}" . format ( iii111Iiiii ) )
   return ( False )
   if 7 - 7: OoOoOO00 % ooOoO0o + OoOoOO00 - OoOoOO00 * i11iIiiIii % OoO0O00
   if 57 - 57: OOooOOo / OoO0O00 + I1ii11iIi11i
  I1IiIiIiiiI = self . source_eid . print_address ( )
  iIi1ii1I1 = self . target_eid . print_address ( )
  IIIIII = lisp_hex_string ( self . nonce ) + I1IiIiIiiiI + iIi1ii1I1
  pubkey = binascii . a2b_base64 ( pubkey )
  if 60 - 60: O0 * Oo0Ooo % OOooOOo + IiII . OoO0O00 . Oo0Ooo
  o0O0OoOOo0o = True
  try :
   o0OoOo0o0OOoO0 = ecdsa . VerifyingKey . from_pem ( pubkey )
  except :
   lprint ( "Invalid public-key in mapping system for sig-eid {}" . format ( self . signature_eid . print_address_no_iid ( ) ) )
   if 21 - 21: I11i - I1IiiI / OoooooooOO . i1IIi + II111iiii
   o0O0OoOOo0o = False
   if 99 - 99: I1Ii111 - I1ii11iIi11i - I1IiiI - I1Ii111 + OoO0O00 + II111iiii
   if 34 - 34: I1Ii111 * I11i
  if ( o0O0OoOOo0o ) :
   try :
    o0O0OoOOo0o = o0OoOo0o0OOoO0 . verify ( self . map_request_signature , IIIIII )
   except :
    o0O0OoOOo0o = False
    if 31 - 31: IiII . oO0o
    if 40 - 40: Ii1I - I11i / II111iiii * i1IIi + IiII * II111iiii
    if 53 - 53: I1ii11iIi11i - i11iIiiIii . OoO0O00 / OoOoOO00 - I1Ii111
  O0O0oooo = bold ( "passed" if o0O0OoOOo0o else "failed" , False )
  lprint ( "Signature verification {} for EID {}" . format ( O0O0oooo , iii111Iiiii ) )
  return ( o0O0OoOOo0o )
  if 90 - 90: OOooOOo . OoOoOO00 . I1IiiI . IiII
  if 52 - 52: Ii1I - Oo0Ooo
 def encode ( self , probe_dest , probe_port ) :
  oo0I1I1iiI1i = ( LISP_MAP_REQUEST << 28 ) | self . record_count
  oo0I1I1iiI1i = oo0I1I1iiI1i | ( self . itr_rloc_count << 8 )
  if ( self . auth_bit ) : oo0I1I1iiI1i |= 0x08000000
  if ( self . map_data_present ) : oo0I1I1iiI1i |= 0x04000000
  if ( self . rloc_probe ) : oo0I1I1iiI1i |= 0x02000000
  if ( self . smr_bit ) : oo0I1I1iiI1i |= 0x01000000
  if ( self . pitr_bit ) : oo0I1I1iiI1i |= 0x00800000
  if ( self . smr_invoked_bit ) : oo0I1I1iiI1i |= 0x00400000
  if ( self . mobile_node ) : oo0I1I1iiI1i |= 0x00200000
  if ( self . xtr_id_present ) : oo0I1I1iiI1i |= 0x00100000
  if ( self . local_xtr ) : oo0I1I1iiI1i |= 0x00004000
  if ( self . dont_reply_bit ) : oo0I1I1iiI1i |= 0x00002000
  if 48 - 48: iIii1I11I1II1 * i11iIiiIii / OoO0O00 / I1IiiI
  i1II1IiiIi = struct . pack ( "I" , socket . htonl ( oo0I1I1iiI1i ) )
  i1II1IiiIi += struct . pack ( "Q" , self . nonce )
  if 93 - 93: oO0o
  if 57 - 57: I11i . iIii1I11I1II1 + I11i . IiII + IiII
  if 53 - 53: I1ii11iIi11i / iII111i - I1ii11iIi11i * OoO0O00
  if 81 - 81: I1Ii111 - Oo0Ooo / II111iiii / Oo0Ooo / i1IIi . o0oOOo0O0Ooo
  if 38 - 38: OoooooooOO / OoooooooOO % iIii1I11I1II1 % OoooooooOO * OoooooooOO + OoO0O00
  if 66 - 66: i1IIi
  I11I11i1 = False
  O0Oo00o0oO = self . privkey_filename
  if ( O0Oo00o0oO != None and os . path . exists ( O0Oo00o0oO ) ) :
   Ii = open ( O0Oo00o0oO , "r" ) ; o0OoOo0o0OOoO0 = Ii . read ( ) ; Ii . close ( )
   try :
    o0OoOo0o0OOoO0 = ecdsa . SigningKey . from_pem ( o0OoOo0o0OOoO0 )
   except :
    return ( None )
    if 100 - 100: O0 * i1IIi
   Oo0OoOo0000oo = self . sign_map_request ( o0OoOo0o0OOoO0 )
   I11I11i1 = True
  elif ( self . map_request_signature != None ) :
   iIiI1iI = binascii . b2a_base64 ( self . map_request_signature )
   Oo0OoOo0000oo = { "source-eid" : self . source_eid . print_address ( ) ,
 "signature-eid" : self . signature_eid . print_address ( ) ,
 "signature" : iIiI1iI }
   Oo0OoOo0000oo = json . dumps ( Oo0OoOo0000oo )
   I11I11i1 = True
   if 100 - 100: iIii1I11I1II1 / OoO0O00 . i1IIi * IiII
  if ( I11I11i1 ) :
   OOo000OOoOO = LISP_LCAF_JSON_TYPE
   iIi11 = socket . htons ( LISP_AFI_LCAF )
   ii1iII1i1iiIi = socket . htons ( len ( Oo0OoOo0000oo ) + 2 )
   oO00 = socket . htons ( len ( Oo0OoOo0000oo ) )
   i1II1IiiIi += struct . pack ( "HBBBBHH" , iIi11 , 0 , 0 , OOo000OOoOO , 0 ,
 ii1iII1i1iiIi , oO00 )
   i1II1IiiIi += Oo0OoOo0000oo
   i1II1IiiIi += struct . pack ( "H" , 0 )
  else :
   if ( self . source_eid . instance_id != 0 ) :
    i1II1IiiIi += struct . pack ( "H" , socket . htons ( LISP_AFI_LCAF ) )
    i1II1IiiIi += self . source_eid . lcaf_encode_iid ( )
   else :
    i1II1IiiIi += struct . pack ( "H" , socket . htons ( self . source_eid . afi ) )
    i1II1IiiIi += self . source_eid . pack_address ( )
    if 18 - 18: II111iiii
    if 92 - 92: o0oOOo0O0Ooo . I1Ii111 + iII111i % I1Ii111 % i11iIiiIii
    if 46 - 46: OoooooooOO
    if 80 - 80: O0 * iII111i
    if 73 - 73: IiII / Ii1I + I1Ii111 . OOooOOo - II111iiii / iIii1I11I1II1
    if 79 - 79: I1Ii111 * Oo0Ooo . o0oOOo0O0Ooo - I1Ii111
    if 16 - 16: I1IiiI - O0 * I1ii11iIi11i . I1ii11iIi11i % OOooOOo
  if ( probe_dest ) :
   if ( probe_port == 0 ) : probe_port = LISP_DATA_PORT
   I1iiIiiii1111 = probe_dest . print_address_no_iid ( ) + ":" + str ( probe_port )
   if 39 - 39: II111iiii / I11i - OoOoOO00 * OoOoOO00 - Ii1I
   if ( lisp_crypto_keys_by_rloc_encap . has_key ( I1iiIiiii1111 ) ) :
    self . keys = lisp_crypto_keys_by_rloc_encap [ I1iiIiiii1111 ]
    if 8 - 8: O0 . i11iIiiIii
    if 54 - 54: OOooOOo . I1ii11iIi11i * I11i % I1Ii111 . O0 * IiII
    if 87 - 87: Ii1I % I1ii11iIi11i * Oo0Ooo
    if 59 - 59: Oo0Ooo / I11i - iIii1I11I1II1 * iIii1I11I1II1
    if 18 - 18: I11i * I1ii11iIi11i / i11iIiiIii / iIii1I11I1II1 * OoooooooOO . OOooOOo
    if 69 - 69: Oo0Ooo * ooOoO0o
    if 91 - 91: o0oOOo0O0Ooo . ooOoO0o / OoO0O00 / i11iIiiIii * o0oOOo0O0Ooo
  for oOooOo000O in self . itr_rlocs :
   if ( lisp_data_plane_security and self . itr_rlocs . index ( oOooOo000O ) == 0 ) :
    if ( self . keys == None or self . keys [ 1 ] == None ) :
     o00OO0o0 = lisp_keys ( 1 )
     self . keys = [ None , o00OO0o0 , None , None ]
     if 52 - 52: I1IiiI - i11iIiiIii / IiII . oO0o
    o00OO0o0 = self . keys [ 1 ]
    o00OO0o0 . add_key_by_nonce ( self . nonce )
    i1II1IiiIi += o00OO0o0 . encode_lcaf ( oOooOo000O )
   else :
    i1II1IiiIi += struct . pack ( "H" , socket . htons ( oOooOo000O . afi ) )
    i1II1IiiIi += oOooOo000O . pack_address ( )
    if 38 - 38: oO0o + OoooooooOO * OoOoOO00 % oO0o
    if 91 - 91: i1IIi - I1ii11iIi11i * I1IiiI
    if 24 - 24: OoOoOO00 * Ii1I
  iI1iiII1iii111 = 0 if self . target_eid . is_binary ( ) == False else self . target_eid . mask_len
  if 22 - 22: I1IiiI
  if 76 - 76: OoO0O00 + I11i + OoO0O00 . I11i % OOooOOo
  oOoOOO = 0
  if ( self . subscribe_bit ) :
   oOoOOO = 0x80
   self . xtr_id_present = True
   if ( self . xtr_id == None ) :
    self . xtr_id = random . randint ( 0 , ( 2 ** 128 ) - 1 )
    if 10 - 10: OOooOOo . Ii1I
    if 5 - 5: IiII - I11i
    if 16 - 16: IiII . iII111i . Oo0Ooo % OOooOOo / IiII
  oOo0ooO0O0oo = "BB"
  i1II1IiiIi += struct . pack ( oOo0ooO0O0oo , oOoOOO , iI1iiII1iii111 )
  if 72 - 72: o0oOOo0O0Ooo * ooOoO0o - i11iIiiIii / Ii1I
  if ( self . target_group . is_null ( ) == False ) :
   i1II1IiiIi += struct . pack ( "H" , socket . htons ( LISP_AFI_LCAF ) )
   i1II1IiiIi += self . target_eid . lcaf_encode_sg ( self . target_group )
  elif ( self . target_eid . instance_id != 0 or
 self . target_eid . is_geo_prefix ( ) ) :
   i1II1IiiIi += struct . pack ( "H" , socket . htons ( LISP_AFI_LCAF ) )
   i1II1IiiIi += self . target_eid . lcaf_encode_iid ( )
  else :
   i1II1IiiIi += struct . pack ( "H" , socket . htons ( self . target_eid . afi ) )
   i1II1IiiIi += self . target_eid . pack_address ( )
   if 11 - 11: O0 - I1IiiI
   if 31 - 31: iII111i
   if 1 - 1: I1Ii111 / OoOoOO00 * OoOoOO00 - o0oOOo0O0Ooo % Ii1I
   if 96 - 96: IiII / Ii1I % OoO0O00 . iIii1I11I1II1
   if 30 - 30: I11i - OoO0O00
  if ( self . subscribe_bit ) : i1II1IiiIi = self . encode_xtr_id ( i1II1IiiIi )
  return ( i1II1IiiIi )
  if 15 - 15: OoooooooOO
  if 31 - 31: II111iiii
 def lcaf_decode_json ( self , packet ) :
  oOo0ooO0O0oo = "BBBBHH"
  OO00OO = struct . calcsize ( oOo0ooO0O0oo )
  if ( len ( packet ) < OO00OO ) : return ( None )
  if 62 - 62: iIii1I11I1II1 % I1Ii111 % I1ii11iIi11i * IiII
  oO0OO0o0oo0o , oOo0ooo00OoO , OOo000OOoOO , ooooOo00O , ii1iII1i1iiIi , oO00 = struct . unpack ( oOo0ooO0O0oo , packet [ : OO00OO ] )
  if 17 - 17: OoooooooOO % Ii1I % O0
  if 46 - 46: iII111i + I1Ii111 % OoooooooOO * I1ii11iIi11i
  if ( OOo000OOoOO != LISP_LCAF_JSON_TYPE ) : return ( packet )
  if 89 - 89: IiII - IiII % iII111i / I11i + oO0o - IiII
  if 97 - 97: Ii1I % OoOoOO00 / I1ii11iIi11i / iIii1I11I1II1 * OoooooooOO * OOooOOo
  if 80 - 80: oO0o / O0
  if 55 - 55: I1IiiI * I11i / O0 % OoOoOO00
  ii1iII1i1iiIi = socket . ntohs ( ii1iII1i1iiIi )
  oO00 = socket . ntohs ( oO00 )
  packet = packet [ OO00OO : : ]
  if ( len ( packet ) < ii1iII1i1iiIi ) : return ( None )
  if ( ii1iII1i1iiIi != oO00 + 2 ) : return ( None )
  if 71 - 71: i11iIiiIii * OoOoOO00 * OOooOOo + oO0o + Oo0Ooo
  if 59 - 59: IiII
  if 54 - 54: OOooOOo
  if 27 - 27: OoOoOO00 - OoO0O00 + o0oOOo0O0Ooo + ooOoO0o . OoO0O00
  try :
   Oo0OoOo0000oo = json . loads ( packet [ 0 : oO00 ] )
  except :
   return ( None )
   if 86 - 86: II111iiii - OoooooooOO - ooOoO0o % iII111i
  packet = packet [ oO00 : : ]
  if 16 - 16: ooOoO0o + Oo0Ooo + OoooooooOO
  if 87 - 87: I1IiiI . oO0o / IiII - OoooooooOO
  if 33 - 33: oO0o % OoO0O00 . iIii1I11I1II1 / IiII
  if 3 - 3: Ii1I + OoO0O00
  oOo0ooO0O0oo = "H"
  OO00OO = struct . calcsize ( oOo0ooO0O0oo )
  oOo00Oo0o00oo = struct . unpack ( oOo0ooO0O0oo , packet [ : OO00OO ] ) [ 0 ]
  packet = packet [ OO00OO : : ]
  if ( oOo00Oo0o00oo != 0 ) : return ( packet )
  if 60 - 60: OoO0O00 . OoOoOO00 - I1ii11iIi11i - I1IiiI - II111iiii % Oo0Ooo
  if 62 - 62: O0 + iII111i - iII111i % iIii1I11I1II1
  if 47 - 47: I1Ii111 + I1IiiI
  if 40 - 40: iIii1I11I1II1 % Ii1I + II111iiii - I1IiiI
  if ( Oo0OoOo0000oo . has_key ( "source-eid" ) == False ) : return ( packet )
  o00oo00oo = Oo0OoOo0000oo [ "source-eid" ]
  oOo00Oo0o00oo = LISP_AFI_IPV4 if o00oo00oo . count ( "." ) == 3 else LISP_AFI_IPV6 if o00oo00oo . count ( ":" ) == 7 else None
  if 46 - 46: oO0o / iII111i . OoooooooOO
  if ( oOo00Oo0o00oo == None ) :
   lprint ( "Bad JSON 'source-eid' value: {}" . format ( o00oo00oo ) )
   return ( None )
   if 54 - 54: Ii1I - i11iIiiIii
   if 88 - 88: OOooOOo / OoOoOO00 . o0oOOo0O0Ooo % i1IIi
  self . source_eid . afi = oOo00Oo0o00oo
  self . source_eid . store_address ( o00oo00oo )
  if 60 - 60: I11i * I1IiiI . ooOoO0o
  if ( Oo0OoOo0000oo . has_key ( "signature-eid" ) == False ) : return ( packet )
  o00oo00oo = Oo0OoOo0000oo [ "signature-eid" ]
  if ( o00oo00oo . count ( ":" ) != 7 ) :
   lprint ( "Bad JSON 'signature-eid' value: {}" . format ( o00oo00oo ) )
   return ( None )
   if 24 - 24: ooOoO0o
   if 79 - 79: i1IIi . I11i % OoO0O00 % IiII - oO0o - i11iIiiIii
  self . signature_eid . afi = LISP_AFI_IPV6
  self . signature_eid . store_address ( o00oo00oo )
  if 97 - 97: I1ii11iIi11i / OoooooooOO % OoO0O00
  if ( Oo0OoOo0000oo . has_key ( "signature" ) == False ) : return ( packet )
  iIiI1iI = binascii . a2b_base64 ( Oo0OoOo0000oo [ "signature" ] )
  self . map_request_signature = iIiI1iI
  return ( packet )
  if 55 - 55: OoO0O00 * o0oOOo0O0Ooo - I11i + iIii1I11I1II1 . OoO0O00 + oO0o
  if 4 - 4: Ii1I
 def decode ( self , packet , source , port ) :
  oOo0ooO0O0oo = "I"
  OO00OO = struct . calcsize ( oOo0ooO0O0oo )
  if ( len ( packet ) < OO00OO ) : return ( None )
  if 43 - 43: i1IIi . I1IiiI * iIii1I11I1II1 * i11iIiiIii - OOooOOo + ooOoO0o
  oo0I1I1iiI1i = struct . unpack ( oOo0ooO0O0oo , packet [ : OO00OO ] )
  oo0I1I1iiI1i = oo0I1I1iiI1i [ 0 ]
  packet = packet [ OO00OO : : ]
  if 56 - 56: Oo0Ooo % i11iIiiIii / Ii1I . I1Ii111 . OoO0O00 - OoOoOO00
  oOo0ooO0O0oo = "Q"
  OO00OO = struct . calcsize ( oOo0ooO0O0oo )
  if ( len ( packet ) < OO00OO ) : return ( None )
  if 32 - 32: I1Ii111 / oO0o / I1IiiI
  iI1III = struct . unpack ( oOo0ooO0O0oo , packet [ : OO00OO ] )
  packet = packet [ OO00OO : : ]
  if 22 - 22: OoO0O00 - OoOoOO00 . Oo0Ooo + o0oOOo0O0Ooo
  oo0I1I1iiI1i = socket . ntohl ( oo0I1I1iiI1i )
  self . auth_bit = True if ( oo0I1I1iiI1i & 0x08000000 ) else False
  self . map_data_present = True if ( oo0I1I1iiI1i & 0x04000000 ) else False
  self . rloc_probe = True if ( oo0I1I1iiI1i & 0x02000000 ) else False
  self . smr_bit = True if ( oo0I1I1iiI1i & 0x01000000 ) else False
  self . pitr_bit = True if ( oo0I1I1iiI1i & 0x00800000 ) else False
  self . smr_invoked_bit = True if ( oo0I1I1iiI1i & 0x00400000 ) else False
  self . mobile_node = True if ( oo0I1I1iiI1i & 0x00200000 ) else False
  self . xtr_id_present = True if ( oo0I1I1iiI1i & 0x00100000 ) else False
  self . local_xtr = True if ( oo0I1I1iiI1i & 0x00004000 ) else False
  self . dont_reply_bit = True if ( oo0I1I1iiI1i & 0x00002000 ) else False
  self . itr_rloc_count = ( ( oo0I1I1iiI1i >> 8 ) & 0x1f ) + 1
  self . record_count = oo0I1I1iiI1i & 0xff
  self . nonce = iI1III [ 0 ]
  if 69 - 69: oO0o - I1IiiI
  if 10 - 10: i1IIi / iII111i . II111iiii * i1IIi % OoooooooOO
  if 83 - 83: I11i . OOooOOo + I1Ii111 * I11i . I1Ii111 + oO0o
  if 64 - 64: Ii1I . o0oOOo0O0Ooo - i1IIi
  if ( self . xtr_id_present ) :
   if ( self . decode_xtr_id ( packet ) == False ) : return ( None )
   if 35 - 35: I1ii11iIi11i % OoooooooOO
   if 59 - 59: I1IiiI % I11i
  OO00OO = struct . calcsize ( "H" )
  if ( len ( packet ) < OO00OO ) : return ( None )
  if 32 - 32: I1IiiI * O0 + O0
  oOo00Oo0o00oo = struct . unpack ( "H" , packet [ : OO00OO ] )
  self . source_eid . afi = socket . ntohs ( oOo00Oo0o00oo [ 0 ] )
  packet = packet [ OO00OO : : ]
  if 34 - 34: IiII
  if ( self . source_eid . afi == LISP_AFI_LCAF ) :
   iIi = packet
   packet = self . source_eid . lcaf_decode_iid ( packet )
   if ( packet == None ) :
    packet = self . lcaf_decode_json ( iIi )
    if ( packet == None ) : return ( None )
    if 48 - 48: Oo0Ooo - OoO0O00 . I11i - iIii1I11I1II1 % Ii1I
  elif ( self . source_eid . afi != LISP_AFI_NONE ) :
   packet = self . source_eid . unpack_address ( packet )
   if ( packet == None ) : return ( None )
   if 47 - 47: iII111i / OoooooooOO - II111iiii
  self . source_eid . mask_len = self . source_eid . host_mask_len ( )
  if 91 - 91: OoOoOO00 + o0oOOo0O0Ooo
  ii11 = ( os . getenv ( "LISP_NO_CRYPTO" ) != None )
  self . itr_rlocs = [ ]
  while ( self . itr_rloc_count != 0 ) :
   OO00OO = struct . calcsize ( "H" )
   if ( len ( packet ) < OO00OO ) : return ( None )
   if 24 - 24: ooOoO0o * i11iIiiIii + o0oOOo0O0Ooo + OoooooooOO
   oOo00Oo0o00oo = struct . unpack ( "H" , packet [ : OO00OO ] ) [ 0 ]
   if 92 - 92: Ii1I
   oOooOo000O = lisp_address ( LISP_AFI_NONE , "" , 32 , 0 )
   oOooOo000O . afi = socket . ntohs ( oOo00Oo0o00oo )
   if 48 - 48: iII111i . I1IiiI + O0
   if 19 - 19: I1IiiI / I1Ii111 - I11i
   if 49 - 49: iIii1I11I1II1 - iIii1I11I1II1 - OoOoOO00 + IiII / OoOoOO00
   if 74 - 74: OoooooooOO + I1ii11iIi11i % O0
   if 32 - 32: I1ii11iIi11i + I1ii11iIi11i
   if ( oOooOo000O . afi != LISP_AFI_LCAF ) :
    if ( len ( packet ) < oOooOo000O . addr_length ( ) ) : return ( None )
    packet = oOooOo000O . unpack_address ( packet [ OO00OO : : ] )
    if ( packet == None ) : return ( None )
    if 89 - 89: ooOoO0o + oO0o + Ii1I - OOooOOo
    if ( ii11 ) :
     self . itr_rlocs . append ( oOooOo000O )
     self . itr_rloc_count -= 1
     continue
     if 12 - 12: OoOoOO00 - o0oOOo0O0Ooo - I1Ii111 / I11i
     if 17 - 17: OoO0O00 - I1Ii111 - II111iiii / I1Ii111 / Ii1I
    I1iiIiiii1111 = lisp_build_crypto_decap_lookup_key ( oOooOo000O , port )
    if 30 - 30: OOooOOo * I1ii11iIi11i % I1ii11iIi11i + iII111i * IiII
    if 33 - 33: o0oOOo0O0Ooo + I11i * O0 * OoO0O00 . I1ii11iIi11i
    if 74 - 74: iII111i * iII111i * o0oOOo0O0Ooo / oO0o
    if 91 - 91: i11iIiiIii . I1ii11iIi11i / II111iiii
    if 97 - 97: Ii1I % i1IIi % IiII + Oo0Ooo - O0 - I11i
    if ( lisp_nat_traversal and oOooOo000O . is_private_address ( ) and source ) : oOooOo000O = source
    if 64 - 64: Ii1I - iII111i
    i1II = lisp_crypto_keys_by_rloc_decap
    if ( i1II . has_key ( I1iiIiiii1111 ) ) : i1II . pop ( I1iiIiiii1111 )
    if 28 - 28: IiII - Ii1I . IiII - I1ii11iIi11i * iII111i * OoO0O00
    if 58 - 58: IiII . I1ii11iIi11i * i1IIi
    if 79 - 79: iII111i
    if 32 - 32: Ii1I % I11i + OOooOOo % OoooooooOO
    if 68 - 68: I11i
    if 13 - 13: i11iIiiIii - ooOoO0o
    lisp_write_ipc_decap_key ( I1iiIiiii1111 , None )
   else :
    iIiiII11 = packet
    OoOoo0ooO0000 = lisp_keys ( 1 )
    packet = OoOoo0ooO0000 . decode_lcaf ( iIiiII11 , 0 )
    if ( packet == None ) : return ( None )
    if 5 - 5: II111iiii * I11i
    if 21 - 21: I1IiiI
    if 70 - 70: Oo0Ooo + I1Ii111 + OOooOOo . I1ii11iIi11i - I1ii11iIi11i
    if 21 - 21: I11i - oO0o
    O0Ii1iIii1I1 = [ LISP_CS_25519_CBC , LISP_CS_25519_GCM ,
 LISP_CS_25519_CHACHA ]
    if ( OoOoo0ooO0000 . cipher_suite in O0Ii1iIii1I1 ) :
     if ( OoOoo0ooO0000 . cipher_suite == LISP_CS_25519_CBC or
 OoOoo0ooO0000 . cipher_suite == LISP_CS_25519_GCM ) :
      o0OoOo0o0OOoO0 = lisp_keys ( 1 , do_poly = False , do_chacha = False )
      if 55 - 55: iII111i * Oo0Ooo + OoOoOO00 * OOooOOo / iII111i * i1IIi
     if ( OoOoo0ooO0000 . cipher_suite == LISP_CS_25519_CHACHA ) :
      o0OoOo0o0OOoO0 = lisp_keys ( 1 , do_poly = True , do_chacha = True )
      if 49 - 49: IiII + iIii1I11I1II1
    else :
     o0OoOo0o0OOoO0 = lisp_keys ( 1 , do_poly = False , do_curve = False ,
 do_chacha = False )
     if 30 - 30: i11iIiiIii % o0oOOo0O0Ooo . i1IIi
    packet = o0OoOo0o0OOoO0 . decode_lcaf ( iIiiII11 , 0 )
    if ( packet == None ) : return ( None )
    if 49 - 49: o0oOOo0O0Ooo * Ii1I + Oo0Ooo
    if ( len ( packet ) < OO00OO ) : return ( None )
    oOo00Oo0o00oo = struct . unpack ( "H" , packet [ : OO00OO ] ) [ 0 ]
    oOooOo000O . afi = socket . ntohs ( oOo00Oo0o00oo )
    if ( len ( packet ) < oOooOo000O . addr_length ( ) ) : return ( None )
    if 1 - 1: o0oOOo0O0Ooo / II111iiii + I11i . i11iIiiIii + ooOoO0o . OoOoOO00
    packet = oOooOo000O . unpack_address ( packet [ OO00OO : : ] )
    if ( packet == None ) : return ( None )
    if 95 - 95: o0oOOo0O0Ooo / I1Ii111 % II111iiii + ooOoO0o
    if ( ii11 ) :
     self . itr_rlocs . append ( oOooOo000O )
     self . itr_rloc_count -= 1
     continue
     if 97 - 97: OOooOOo
     if 55 - 55: ooOoO0o
    I1iiIiiii1111 = lisp_build_crypto_decap_lookup_key ( oOooOo000O , port )
    if 1 - 1: OoO0O00
    IiI1IIII = None
    if ( lisp_nat_traversal and oOooOo000O . is_private_address ( ) and source ) : oOooOo000O = source
    if 80 - 80: I1ii11iIi11i - OoOoOO00 . Ii1I / IiII * OOooOOo - i11iIiiIii
    if 18 - 18: II111iiii % OoOoOO00 - I1IiiI / ooOoO0o
    if ( lisp_crypto_keys_by_rloc_decap . has_key ( I1iiIiiii1111 ) ) :
     o00OO0o0 = lisp_crypto_keys_by_rloc_decap [ I1iiIiiii1111 ]
     IiI1IIII = o00OO0o0 [ 1 ] if o00OO0o0 and o00OO0o0 [ 1 ] else None
     if 12 - 12: Ii1I % IiII - OoOoOO00 . IiII + i11iIiiIii
     if 97 - 97: ooOoO0o * Ii1I % iII111i * Ii1I % i11iIiiIii
    iIiIII11 = True
    if ( IiI1IIII ) :
     if ( IiI1IIII . compare_keys ( o0OoOo0o0OOoO0 ) ) :
      self . keys = [ None , IiI1IIII , None , None ]
      lprint ( "Maintain stored decap-keys for RLOC {}" . format ( red ( I1iiIiiii1111 , False ) ) )
      if 23 - 23: Ii1I + OoO0O00
     else :
      iIiIII11 = False
      oOOo0o000o = bold ( "Remote decap-rekeying" , False )
      lprint ( "{} for RLOC {}" . format ( oOOo0o000o , red ( I1iiIiiii1111 ,
 False ) ) )
      o0OoOo0o0OOoO0 . copy_keypair ( IiI1IIII )
      o0OoOo0o0OOoO0 . uptime = IiI1IIII . uptime
      IiI1IIII = None
      if 13 - 13: II111iiii
      if 17 - 17: II111iiii
      if 66 - 66: IiII * oO0o
    if ( IiI1IIII == None ) :
     self . keys = [ None , o0OoOo0o0OOoO0 , None , None ]
     if ( lisp_i_am_etr == False and lisp_i_am_rtr == False ) :
      o0OoOo0o0OOoO0 . local_public_key = None
      lprint ( "{} for {}" . format ( bold ( "Ignoring decap-keys" ,
 False ) , red ( I1iiIiiii1111 , False ) ) )
     elif ( o0OoOo0o0OOoO0 . remote_public_key != None ) :
      if ( iIiIII11 ) :
       lprint ( "{} for RLOC {}" . format ( bold ( "New decap-keying" , False ) ,
       # OoOoOO00 + Ii1I . O0 . OOooOOo % iII111i
 red ( I1iiIiiii1111 , False ) ) )
       if 28 - 28: Oo0Ooo . iII111i % O0 - OoOoOO00
      o0OoOo0o0OOoO0 . compute_shared_key ( "decap" )
      o0OoOo0o0OOoO0 . add_key_by_rloc ( I1iiIiiii1111 , False )
      if 62 - 62: oO0o
      if 15 - 15: OoOoOO00 - I11i - I11i + IiII * I1ii11iIi11i
      if 21 - 21: OoOoOO00 . II111iiii
      if 15 - 15: IiII / oO0o
   self . itr_rlocs . append ( oOooOo000O )
   self . itr_rloc_count -= 1
   if 22 - 22: iII111i . OoooooooOO . Oo0Ooo
   if 44 - 44: OoOoOO00 / Oo0Ooo . OoooooooOO % OoooooooOO * i11iIiiIii
  OO00OO = struct . calcsize ( "BBH" )
  if ( len ( packet ) < OO00OO ) : return ( None )
  if 60 - 60: IiII / iIii1I11I1II1 + OoooooooOO - I1ii11iIi11i * i11iIiiIii
  oOoOOO , iI1iiII1iii111 , oOo00Oo0o00oo = struct . unpack ( "BBH" , packet [ : OO00OO ] )
  self . subscribe_bit = ( oOoOOO & 0x80 )
  self . target_eid . afi = socket . ntohs ( oOo00Oo0o00oo )
  packet = packet [ OO00OO : : ]
  if 47 - 47: O0 . I1IiiI / ooOoO0o % i11iIiiIii
  self . target_eid . mask_len = iI1iiII1iii111
  if ( self . target_eid . afi == LISP_AFI_LCAF ) :
   packet , I1iiII = self . target_eid . lcaf_decode_eid ( packet )
   if ( packet == None ) : return ( None )
   if ( I1iiII ) : self . target_group = I1iiII
  else :
   packet = self . target_eid . unpack_address ( packet )
   if ( packet == None ) : return ( None )
   packet = packet [ OO00OO : : ]
   if 5 - 5: OOooOOo * OoooooooOO + iII111i . I1IiiI
  return ( packet )
  if 93 - 93: Ii1I % iIii1I11I1II1 * iII111i / OoOoOO00 * i11iIiiIii
  if 26 - 26: ooOoO0o . iII111i
 def print_eid_tuple ( self ) :
  return ( lisp_print_eid_tuple ( self . target_eid , self . target_group ) )
  if 76 - 76: I1Ii111 % OoooooooOO
  if 15 - 15: I1IiiI . I1ii11iIi11i / iIii1I11I1II1 % I11i
 def encode_xtr_id ( self , packet ) :
  I1i1I = self . xtr_id >> 64
  O0OOoooO = self . xtr_id & 0xffffffffffffffff
  I1i1I = byte_swap_64 ( I1i1I )
  O0OOoooO = byte_swap_64 ( O0OOoooO )
  packet += struct . pack ( "QQ" , I1i1I , O0OOoooO )
  return ( packet )
  if 94 - 94: I1IiiI - Ii1I % OoooooooOO + i1IIi - OoooooooOO
  if 65 - 65: I1Ii111 . O0 + OoOoOO00
 def decode_xtr_id ( self , packet ) :
  OO00OO = struct . calcsize ( "QQ" )
  if ( len ( packet ) < OO00OO ) : return ( None )
  packet = packet [ len ( packet ) - OO00OO : : ]
  I1i1I , O0OOoooO = struct . unpack ( "QQ" , packet [ : OO00OO ] )
  I1i1I = byte_swap_64 ( I1i1I )
  O0OOoooO = byte_swap_64 ( O0OOoooO )
  self . xtr_id = ( I1i1I << 64 ) | O0OOoooO
  return ( True )
  if 82 - 82: ooOoO0o . I1Ii111 . Oo0Ooo % iIii1I11I1II1 - i11iIiiIii
  if 11 - 11: ooOoO0o . I1Ii111 - iII111i . o0oOOo0O0Ooo
  if 41 - 41: oO0o / OoO0O00 - OoO0O00 + ooOoO0o * OOooOOo
  if 13 - 13: I1Ii111 * II111iiii - OoOoOO00
  if 3 - 3: OOooOOo + ooOoO0o * i11iIiiIii . iII111i / iIii1I11I1II1
  if 44 - 44: OoO0O00
  if 74 - 74: Ii1I * i1IIi * I11i - OoooooooOO . I1IiiI
  if 24 - 24: II111iiii - i11iIiiIii * i1IIi . ooOoO0o
  if 42 - 42: I11i / i11iIiiIii
  if 7 - 7: I11i
  if 50 - 50: i11iIiiIii . i11iIiiIii * i1IIi / i11iIiiIii . i1IIi - II111iiii
  if 72 - 72: iIii1I11I1II1 / o0oOOo0O0Ooo . I1ii11iIi11i
  if 78 - 78: iIii1I11I1II1 . i11iIiiIii % IiII * Ii1I + iII111i - iIii1I11I1II1
  if 50 - 50: I1ii11iIi11i % Ii1I - I11i % Oo0Ooo - I11i - I1IiiI
  if 99 - 99: IiII * OoOoOO00 - i1IIi / I1Ii111 . ooOoO0o % o0oOOo0O0Ooo
  if 69 - 69: O0 . iII111i
  if 96 - 96: O0
  if 89 - 89: I1ii11iIi11i - Oo0Ooo
  if 26 - 26: ooOoO0o % ooOoO0o / II111iiii / iII111i
  if 2 - 2: i1IIi / i11iIiiIii + I1IiiI
  if 95 - 95: I1ii11iIi11i / IiII % iIii1I11I1II1 + O0
  if 6 - 6: IiII
  if 73 - 73: o0oOOo0O0Ooo % o0oOOo0O0Ooo . OOooOOo * I1ii11iIi11i - Ii1I
  if 97 - 97: IiII
  if 15 - 15: O0 - I1IiiI / i1IIi . I1Ii111
  if 64 - 64: ooOoO0o / i1IIi
  if 100 - 100: II111iiii
  if 16 - 16: Ii1I
  if 96 - 96: o0oOOo0O0Ooo / I1Ii111 % Ii1I - ooOoO0o
  if 35 - 35: OOooOOo
  if 90 - 90: i11iIiiIii
  if 47 - 47: OoO0O00 . i11iIiiIii
class lisp_map_reply ( ) :
 def __init__ ( self ) :
  self . rloc_probe = False
  self . echo_nonce_capable = False
  self . security = False
  self . record_count = 0
  self . hop_count = 0
  self . nonce = 0
  self . keys = None
  if 9 - 9: OoOoOO00 - I11i . OoooooooOO % ooOoO0o
  if 13 - 13: OoO0O00 * iIii1I11I1II1 + II111iiii - Oo0Ooo - OoOoOO00
 def print_map_reply ( self ) :
  oooOo = "{} -> flags: {}{}{}, hop-count: {}, record-count: {}, " + "nonce: 0x{}"
  if 43 - 43: iII111i / I1Ii111 * I1IiiI % ooOoO0o % I1IiiI
  lprint ( oooOo . format ( bold ( "Map-Reply" , False ) , "R" if self . rloc_probe else "r" ,
  # OoO0O00 . ooOoO0o
 "E" if self . echo_nonce_capable else "e" ,
 "S" if self . security else "s" , self . hop_count , self . record_count ,
 lisp_hex_string ( self . nonce ) ) )
  if 86 - 86: i11iIiiIii % oO0o
  if 34 - 34: OoOoOO00
 def encode ( self ) :
  oo0I1I1iiI1i = ( LISP_MAP_REPLY << 28 ) | self . record_count
  oo0I1I1iiI1i |= self . hop_count << 8
  if ( self . rloc_probe ) : oo0I1I1iiI1i |= 0x08000000
  if ( self . echo_nonce_capable ) : oo0I1I1iiI1i |= 0x04000000
  if ( self . security ) : oo0I1I1iiI1i |= 0x02000000
  if 75 - 75: I11i / iIii1I11I1II1 + I1ii11iIi11i / OoO0O00
  i1II1IiiIi = struct . pack ( "I" , socket . htonl ( oo0I1I1iiI1i ) )
  i1II1IiiIi += struct . pack ( "Q" , self . nonce )
  return ( i1II1IiiIi )
  if 50 - 50: I1Ii111 / I11i % iIii1I11I1II1
  if 46 - 46: ooOoO0o + iII111i - Oo0Ooo % OOooOOo + OoooooooOO + iIii1I11I1II1
 def decode ( self , packet ) :
  oOo0ooO0O0oo = "I"
  OO00OO = struct . calcsize ( oOo0ooO0O0oo )
  if ( len ( packet ) < OO00OO ) : return ( None )
  if 99 - 99: OoO0O00 - IiII * IiII + oO0o / iII111i + OOooOOo
  oo0I1I1iiI1i = struct . unpack ( oOo0ooO0O0oo , packet [ : OO00OO ] )
  oo0I1I1iiI1i = oo0I1I1iiI1i [ 0 ]
  packet = packet [ OO00OO : : ]
  if 58 - 58: i11iIiiIii + iIii1I11I1II1 * o0oOOo0O0Ooo - OoOoOO00
  oOo0ooO0O0oo = "Q"
  OO00OO = struct . calcsize ( oOo0ooO0O0oo )
  if ( len ( packet ) < OO00OO ) : return ( None )
  if 31 - 31: i1IIi
  iI1III = struct . unpack ( oOo0ooO0O0oo , packet [ : OO00OO ] )
  packet = packet [ OO00OO : : ]
  if 87 - 87: I1IiiI / I11i + OoooooooOO + O0 . Ii1I
  oo0I1I1iiI1i = socket . ntohl ( oo0I1I1iiI1i )
  self . rloc_probe = True if ( oo0I1I1iiI1i & 0x08000000 ) else False
  self . echo_nonce_capable = True if ( oo0I1I1iiI1i & 0x04000000 ) else False
  self . security = True if ( oo0I1I1iiI1i & 0x02000000 ) else False
  self . hop_count = ( oo0I1I1iiI1i >> 8 ) & 0xff
  self . record_count = oo0I1I1iiI1i & 0xff
  self . nonce = iI1III [ 0 ]
  if 44 - 44: Oo0Ooo % Oo0Ooo
  if ( lisp_crypto_keys_by_nonce . has_key ( self . nonce ) ) :
   self . keys = lisp_crypto_keys_by_nonce [ self . nonce ]
   self . keys [ 1 ] . delete_key_by_nonce ( self . nonce )
   if 58 - 58: OOooOOo * II111iiii
  return ( packet )
  if 29 - 29: iIii1I11I1II1 % OoOoOO00 % I1ii11iIi11i / OoOoOO00 - i11iIiiIii
  if 67 - 67: OOooOOo / Ii1I
  if 51 - 51: I11i % II111iiii - o0oOOo0O0Ooo % OoO0O00 * i11iIiiIii * iII111i
  if 82 - 82: OoooooooOO / I1IiiI * II111iiii - OoooooooOO % iIii1I11I1II1 * OoO0O00
  if 32 - 32: i11iIiiIii - OoOoOO00 * I11i . Oo0Ooo * ooOoO0o
  if 21 - 21: OOooOOo
  if 11 - 11: oO0o % i11iIiiIii * O0
  if 28 - 28: I1Ii111 / iIii1I11I1II1 + OOooOOo . I1ii11iIi11i % OOooOOo + OoO0O00
  if 79 - 79: oO0o
  if 39 - 39: I1Ii111 % oO0o % O0 % O0 - iII111i - oO0o
  if 83 - 83: i11iIiiIii + iIii1I11I1II1
  if 21 - 21: o0oOOo0O0Ooo / i11iIiiIii % I1Ii111
  if 56 - 56: o0oOOo0O0Ooo * iIii1I11I1II1 . Ii1I + OoOoOO00 % I1Ii111
  if 11 - 11: OOooOOo
  if 12 - 12: OoooooooOO * OOooOOo * I1ii11iIi11i * ooOoO0o
  if 26 - 26: OoooooooOO . i1IIi + OoO0O00
  if 42 - 42: i11iIiiIii * o0oOOo0O0Ooo % I11i % Oo0Ooo + o0oOOo0O0Ooo * i11iIiiIii
  if 66 - 66: Ii1I / IiII . OoooooooOO * Oo0Ooo % i11iIiiIii
  if 100 - 100: I1ii11iIi11i % II111iiii * i11iIiiIii - iII111i
  if 69 - 69: OOooOOo + iII111i / I1Ii111
  if 37 - 37: iIii1I11I1II1 * I11i / IiII * Oo0Ooo % i11iIiiIii
  if 93 - 93: ooOoO0o + ooOoO0o
  if 65 - 65: OoooooooOO * I11i * oO0o % I1ii11iIi11i * II111iiii
  if 86 - 86: i11iIiiIii / I11i * iII111i - iII111i
  if 32 - 32: Oo0Ooo . O0
  if 48 - 48: I1ii11iIi11i % II111iiii + I11i
  if 25 - 25: IiII * o0oOOo0O0Ooo / I1IiiI . IiII % II111iiii
  if 50 - 50: OoOoOO00 * iII111i
  if 59 - 59: I1IiiI * I1IiiI / I11i
  if 92 - 92: o0oOOo0O0Ooo
  if 8 - 8: iII111i + I1ii11iIi11i . Ii1I
  if 50 - 50: Oo0Ooo
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
  if 16 - 16: Ii1I - OoOoOO00 % Oo0Ooo / Ii1I . I11i + ooOoO0o
  if 78 - 78: iIii1I11I1II1 + OoO0O00 + i11iIiiIii
 def print_prefix ( self ) :
  if ( self . group . is_null ( ) ) :
   return ( green ( self . eid . print_prefix ( ) , False ) )
   if 21 - 21: Oo0Ooo + Ii1I % ooOoO0o + OoOoOO00 % I11i
  return ( green ( self . eid . print_sg ( self . group ) , False ) )
  if 22 - 22: i1IIi / OoooooooOO . OoO0O00
  if 83 - 83: I1IiiI - OoooooooOO + I1ii11iIi11i . Ii1I / o0oOOo0O0Ooo + ooOoO0o
 def print_ttl ( self ) :
  oooOooOO = self . record_ttl
  if ( self . record_ttl & 0x80000000 ) :
   oooOooOO = str ( self . record_ttl & 0x7fffffff ) + " secs"
  elif ( ( oooOooOO % 60 ) == 0 ) :
   oooOooOO = str ( oooOooOO / 60 ) + " hours"
  else :
   oooOooOO = str ( oooOooOO ) + " mins"
   if 21 - 21: iII111i . I1IiiI / I11i
  return ( oooOooOO )
  if 97 - 97: iIii1I11I1II1 + i1IIi - o0oOOo0O0Ooo
  if 73 - 73: OoO0O00 - i11iIiiIii % I1Ii111 / Oo0Ooo - OoooooooOO % OOooOOo
 def store_ttl ( self ) :
  oooOooOO = self . record_ttl * 60
  if ( self . record_ttl & 0x80000000 ) : oooOooOO = self . record_ttl & 0x7fffffff
  return ( oooOooOO )
  if 79 - 79: I1IiiI / o0oOOo0O0Ooo . Ii1I * I1ii11iIi11i + I11i
  if 96 - 96: OoO0O00 * II111iiii
 def print_record ( self , indent , ddt ) :
  iiI1I1IIi = ""
  ii1IiiiI1I = ""
  i1ii = bold ( "invalid-action" , False )
  if ( ddt ) :
   if ( self . action < len ( lisp_map_referral_action_string ) ) :
    i1ii = lisp_map_referral_action_string [ self . action ]
    i1ii = bold ( i1ii , False )
    iiI1I1IIi = ( ", " + bold ( "ddt-incomplete" , False ) ) if self . ddt_incomplete else ""
    if 77 - 77: OOooOOo % oO0o + iIii1I11I1II1 * Ii1I . IiII . Oo0Ooo
    ii1IiiiI1I = ( ", sig-count: " + str ( self . signature_count ) ) if ( self . signature_count != 0 ) else ""
    if 29 - 29: I1ii11iIi11i + OoooooooOO . OoO0O00 . i1IIi - OoooooooOO * i11iIiiIii
    if 19 - 19: I1ii11iIi11i * O0 - ooOoO0o
  else :
   if ( self . action < len ( lisp_map_reply_action_string ) ) :
    i1ii = lisp_map_reply_action_string [ self . action ]
    if ( self . action != LISP_NO_ACTION ) :
     i1ii = bold ( i1ii , False )
     if 27 - 27: iII111i / o0oOOo0O0Ooo . OoOoOO00 * Ii1I * I1Ii111
     if 81 - 81: I1Ii111
     if 45 - 45: OOooOOo * II111iiii * OoooooooOO / OoooooooOO * I1Ii111
     if 38 - 38: iII111i . OoooooooOO
  oOo00Oo0o00oo = LISP_AFI_LCAF if ( self . eid . afi < 0 ) else self . eid . afi
  oooOo = ( "{}EID-record -> record-ttl: {}, rloc-count: {}, action: " +
 "{}, {}{}{}, map-version: {}, afi: {}, [iid]eid/ml: {}" )
  if 28 - 28: I1Ii111 * i1IIi . I1ii11iIi11i
  lprint ( oooOo . format ( indent , self . print_ttl ( ) , self . rloc_count ,
 i1ii , "auth" if ( self . authoritative is True ) else "non-auth" ,
 iiI1I1IIi , ii1IiiiI1I , self . map_version , oOo00Oo0o00oo ,
 green ( self . print_prefix ( ) , False ) ) )
  if 75 - 75: O0 / oO0o * ooOoO0o - OOooOOo / i1IIi
  if 61 - 61: I11i
 def encode ( self ) :
  oo0oOOo0 = self . action << 13
  if ( self . authoritative ) : oo0oOOo0 |= 0x1000
  if ( self . ddt_incomplete ) : oo0oOOo0 |= 0x800
  if 57 - 57: OoO0O00 . Oo0Ooo + I1IiiI
  if 18 - 18: I1IiiI - I1ii11iIi11i * I11i / i11iIiiIii - o0oOOo0O0Ooo % o0oOOo0O0Ooo
  if 31 - 31: I11i
  if 100 - 100: i11iIiiIii * i11iIiiIii . iIii1I11I1II1 % iII111i * I1ii11iIi11i
  oOo00Oo0o00oo = self . eid . afi if ( self . eid . instance_id == 0 ) else LISP_AFI_LCAF
  if ( oOo00Oo0o00oo < 0 ) : oOo00Oo0o00oo = LISP_AFI_LCAF
  I111iiiIii1I = ( self . group . is_null ( ) == False )
  if ( I111iiiIii1I ) : oOo00Oo0o00oo = LISP_AFI_LCAF
  if 20 - 20: OoooooooOO . Oo0Ooo
  I1I1i1iIi11i = ( self . signature_count << 12 ) | self . map_version
  iI1iiII1iii111 = 0 if self . eid . is_binary ( ) == False else self . eid . mask_len
  if 41 - 41: I1ii11iIi11i - i1IIi % Ii1I / OoooooooOO
  i1II1IiiIi = struct . pack ( "IBBHHH" , socket . htonl ( self . record_ttl ) ,
 self . rloc_count , iI1iiII1iii111 , socket . htons ( oo0oOOo0 ) ,
 socket . htons ( I1I1i1iIi11i ) , socket . htons ( oOo00Oo0o00oo ) )
  if 17 - 17: OoooooooOO + i11iIiiIii + I1IiiI - o0oOOo0O0Ooo % iIii1I11I1II1 - iII111i
  if 79 - 79: IiII . Ii1I . Oo0Ooo % oO0o * oO0o
  if 96 - 96: i1IIi
  if 50 - 50: I1IiiI + Oo0Ooo
  if ( I111iiiIii1I ) :
   i1II1IiiIi += self . eid . lcaf_encode_sg ( self . group )
   return ( i1II1IiiIi )
   if 17 - 17: I1ii11iIi11i + oO0o * I1Ii111 - ooOoO0o + iIii1I11I1II1 . Oo0Ooo
   if 8 - 8: i1IIi + OoO0O00
   if 95 - 95: I1IiiI / o0oOOo0O0Ooo % II111iiii * I1Ii111 . IiII % OoO0O00
   if 45 - 45: I1ii11iIi11i . I11i . II111iiii - II111iiii * OoooooooOO
   if 71 - 71: OOooOOo
  if ( self . eid . afi == LISP_AFI_GEO_COORD and self . eid . instance_id == 0 ) :
   i1II1IiiIi = i1II1IiiIi [ 0 : - 2 ]
   i1II1IiiIi += self . eid . address . encode_geo ( )
   return ( i1II1IiiIi )
   if 87 - 87: II111iiii / iIii1I11I1II1 % I1ii11iIi11i
   if 11 - 11: o0oOOo0O0Ooo * OoO0O00
   if 92 - 92: OoOoOO00 . Oo0Ooo * I11i
   if 86 - 86: O0
   if 55 - 55: Ii1I / I1Ii111 / I1ii11iIi11i % ooOoO0o % I1IiiI
  if ( oOo00Oo0o00oo == LISP_AFI_LCAF ) :
   i1II1IiiIi += self . eid . lcaf_encode_iid ( )
   return ( i1II1IiiIi )
   if 55 - 55: oO0o + OoooooooOO % i1IIi
   if 24 - 24: I1ii11iIi11i - Oo0Ooo
   if 36 - 36: I1IiiI . OOooOOo % II111iiii * IiII
   if 34 - 34: I11i % iII111i - ooOoO0o - I1IiiI
   if 44 - 44: Ii1I . o0oOOo0O0Ooo . iIii1I11I1II1 + OoooooooOO - I1IiiI
  i1II1IiiIi += self . eid . pack_address ( )
  return ( i1II1IiiIi )
  if 22 - 22: I11i * I1ii11iIi11i . OoooooooOO / Oo0Ooo / Ii1I
  if 54 - 54: I1Ii111 % Ii1I + ooOoO0o
 def decode ( self , packet ) :
  oOo0ooO0O0oo = "IBBHHH"
  OO00OO = struct . calcsize ( oOo0ooO0O0oo )
  if ( len ( packet ) < OO00OO ) : return ( None )
  if 45 - 45: Ii1I / oO0o * I1Ii111 . Ii1I
  self . record_ttl , self . rloc_count , self . eid . mask_len , oo0oOOo0 , self . map_version , self . eid . afi = struct . unpack ( oOo0ooO0O0oo , packet [ : OO00OO ] )
  if 25 - 25: I1ii11iIi11i / I1ii11iIi11i
  if 79 - 79: Oo0Ooo - OoO0O00 % Oo0Ooo . II111iiii
  if 84 - 84: ooOoO0o * OoooooooOO + O0
  self . record_ttl = socket . ntohl ( self . record_ttl )
  oo0oOOo0 = socket . ntohs ( oo0oOOo0 )
  self . action = ( oo0oOOo0 >> 13 ) & 0x7
  self . authoritative = True if ( ( oo0oOOo0 >> 12 ) & 1 ) else False
  self . ddt_incomplete = True if ( ( oo0oOOo0 >> 11 ) & 1 ) else False
  self . map_version = socket . ntohs ( self . map_version )
  self . signature_count = self . map_version >> 12
  self . map_version = self . map_version & 0xfff
  self . eid . afi = socket . ntohs ( self . eid . afi )
  self . eid . instance_id = 0
  packet = packet [ OO00OO : : ]
  if 84 - 84: i1IIi . I11i . i1IIi . Oo0Ooo
  if 21 - 21: II111iiii . O0 + Oo0Ooo - i11iIiiIii
  if 5 - 5: iIii1I11I1II1 * i11iIiiIii + OoO0O00 + I11i * O0 % ooOoO0o
  if 88 - 88: o0oOOo0O0Ooo / i11iIiiIii * I1ii11iIi11i
  if ( self . eid . afi == LISP_AFI_LCAF ) :
   packet , ii1I1 = self . eid . lcaf_decode_eid ( packet )
   if ( ii1I1 ) : self . group = ii1I1
   self . group . instance_id = self . eid . instance_id
   return ( packet )
   if 68 - 68: OoooooooOO * OoO0O00
   if 2 - 2: II111iiii - OoO0O00 . i1IIi . I1IiiI . II111iiii * I1Ii111
  packet = self . eid . unpack_address ( packet )
  return ( packet )
  if 20 - 20: IiII + o0oOOo0O0Ooo
  if 48 - 48: i11iIiiIii * i1IIi * II111iiii
 def print_eid_tuple ( self ) :
  return ( lisp_print_eid_tuple ( self . eid , self . group ) )
  if 30 - 30: II111iiii . O0 + I1IiiI / o0oOOo0O0Ooo
  if 45 - 45: OoOoOO00 * OoooooooOO - OoooooooOO / II111iiii * I1IiiI / Ii1I
  if 8 - 8: I1IiiI / Ii1I % o0oOOo0O0Ooo
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
  if 62 - 62: o0oOOo0O0Ooo - iIii1I11I1II1 . I11i . Ii1I * Ii1I
  if 24 - 24: I11i
  if 93 - 93: I1IiiI % OoO0O00 / i11iIiiIii / I11i
  if 60 - 60: ooOoO0o - Ii1I . I1IiiI * oO0o * i11iIiiIii
  if 29 - 29: OoO0O00 - Oo0Ooo . oO0o / OoO0O00 % i11iIiiIii
  if 26 - 26: ooOoO0o . I1Ii111 / II111iiii % Ii1I
  if 82 - 82: OOooOOo % O0 % iIii1I11I1II1 % IiII + i11iIiiIii
LISP_UDP_PROTOCOL = 17
LISP_DEFAULT_ECM_TTL = 128
if 64 - 64: i1IIi / IiII . IiII - I1Ii111 % OOooOOo . II111iiii
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
  if 78 - 78: I1Ii111 - O0 - I1Ii111 . iIii1I11I1II1 % I1ii11iIi11i . OoooooooOO
  if 64 - 64: IiII
 def print_ecm ( self ) :
  oooOo = ( "{} -> flags: {}{}{}{}, " + "inner IP: {} -> {}, inner UDP: {} -> {}" )
  if 21 - 21: o0oOOo0O0Ooo - ooOoO0o * OoooooooOO . OoooooooOO
  lprint ( oooOo . format ( bold ( "ECM" , False ) , "S" if self . security else "s" ,
 "D" if self . ddt else "d" , "E" if self . to_etr else "e" ,
 "M" if self . to_ms else "m" ,
 green ( self . source . print_address ( ) , False ) ,
 green ( self . dest . print_address ( ) , False ) , self . udp_sport ,
 self . udp_dport ) )
  if 17 - 17: OOooOOo - iII111i % I1IiiI * OOooOOo * iIii1I11I1II1 . o0oOOo0O0Ooo
 def encode ( self , packet , inner_source , inner_dest ) :
  self . udp_length = len ( packet ) + 8
  self . source = inner_source
  self . dest = inner_dest
  if ( inner_dest . is_ipv4 ( ) ) :
   self . afi = LISP_AFI_IPV4
   self . length = self . udp_length + 20
   if 58 - 58: oO0o - II111iiii + O0
  if ( inner_dest . is_ipv6 ( ) ) :
   self . afi = LISP_AFI_IPV6
   self . length = self . udp_length
   if 54 - 54: iIii1I11I1II1 - IiII - IiII
   if 18 - 18: i11iIiiIii + iIii1I11I1II1 . i11iIiiIii
   if 63 - 63: iII111i - OoO0O00 * OOooOOo
   if 89 - 89: iII111i / Oo0Ooo
   if 66 - 66: o0oOOo0O0Ooo + OoOoOO00 % OoooooooOO . I11i
   if 30 - 30: II111iiii - Oo0Ooo - i11iIiiIii + O0
  oo0I1I1iiI1i = ( LISP_ECM << 28 )
  if ( self . security ) : oo0I1I1iiI1i |= 0x08000000
  if ( self . ddt ) : oo0I1I1iiI1i |= 0x04000000
  if ( self . to_etr ) : oo0I1I1iiI1i |= 0x02000000
  if ( self . to_ms ) : oo0I1I1iiI1i |= 0x01000000
  if 93 - 93: i1IIi + I1Ii111 / OoO0O00 - I11i % Oo0Ooo / Ii1I
  IIi11 = struct . pack ( "I" , socket . htonl ( oo0I1I1iiI1i ) )
  if 5 - 5: OoO0O00 % O0 - o0oOOo0O0Ooo
  i1I1i1i = ""
  if ( self . afi == LISP_AFI_IPV4 ) :
   i1I1i1i = struct . pack ( "BBHHHBBH" , 0x45 , 0 , socket . htons ( self . length ) ,
 0 , 0 , self . ttl , self . protocol , socket . htons ( self . ip_checksum ) )
   i1I1i1i += self . source . pack_address ( )
   i1I1i1i += self . dest . pack_address ( )
   i1I1i1i = lisp_ip_checksum ( i1I1i1i )
   if 44 - 44: OOooOOo * IiII * iII111i
  if ( self . afi == LISP_AFI_IPV6 ) :
   i1I1i1i = struct . pack ( "BBHHBB" , 0x60 , 0 , 0 , socket . htons ( self . length ) ,
 self . protocol , self . ttl )
   i1I1i1i += self . source . pack_address ( )
   i1I1i1i += self . dest . pack_address ( )
   if 28 - 28: iIii1I11I1II1 - I11i + OoOoOO00 + II111iiii - OoO0O00 % ooOoO0o
   if 97 - 97: OoO0O00 . OoOoOO00
  IiIIi1I1I11Ii = socket . htons ( self . udp_sport )
  oOo0OOOOOO = socket . htons ( self . udp_dport )
  I1i = socket . htons ( self . udp_length )
  i1 = socket . htons ( self . udp_checksum )
  I1iIIIiI = struct . pack ( "HHHH" , IiIIi1I1I11Ii , oOo0OOOOOO , I1i , i1 )
  return ( IIi11 + i1I1i1i + I1iIIIiI )
  if 78 - 78: I1ii11iIi11i + I1ii11iIi11i . OoOoOO00 - IiII * iIii1I11I1II1 * O0
  if 26 - 26: OoooooooOO + oO0o + OoO0O00 . O0
 def decode ( self , packet ) :
  if 46 - 46: OoooooooOO - Oo0Ooo * I1Ii111 * OOooOOo * I1Ii111 . oO0o
  if 96 - 96: Ii1I / IiII % o0oOOo0O0Ooo + I11i
  if 46 - 46: OoO0O00 * I1IiiI
  if 25 - 25: I1Ii111 . IiII % O0 % i1IIi
  oOo0ooO0O0oo = "I"
  OO00OO = struct . calcsize ( oOo0ooO0O0oo )
  if ( len ( packet ) < OO00OO ) : return ( None )
  if 53 - 53: O0 % ooOoO0o
  oo0I1I1iiI1i = struct . unpack ( oOo0ooO0O0oo , packet [ : OO00OO ] )
  if 41 - 41: IiII
  oo0I1I1iiI1i = socket . ntohl ( oo0I1I1iiI1i [ 0 ] )
  self . security = True if ( oo0I1I1iiI1i & 0x08000000 ) else False
  self . ddt = True if ( oo0I1I1iiI1i & 0x04000000 ) else False
  self . to_etr = True if ( oo0I1I1iiI1i & 0x02000000 ) else False
  self . to_ms = True if ( oo0I1I1iiI1i & 0x01000000 ) else False
  packet = packet [ OO00OO : : ]
  if 29 - 29: ooOoO0o
  if 70 - 70: oO0o . O0 % I11i % IiII - I11i * I1ii11iIi11i
  if 22 - 22: i1IIi
  if 82 - 82: oO0o . iIii1I11I1II1 - I1ii11iIi11i
  if ( len ( packet ) < 1 ) : return ( None )
  I1OO = struct . unpack ( "B" , packet [ 0 : 1 ] ) [ 0 ]
  I1OO = I1OO >> 4
  if 55 - 55: Oo0Ooo % Ii1I . iIii1I11I1II1 * I1Ii111
  if ( I1OO == 4 ) :
   OO00OO = struct . calcsize ( "HHIBBH" )
   if ( len ( packet ) < OO00OO ) : return ( None )
   if 33 - 33: O0 - I1IiiI / I1ii11iIi11i / OoO0O00 + iII111i - oO0o
   I1I111 , I1i , I1I111 , oOO0oOo0OOoOO , i111 , i1 = struct . unpack ( "HHIBBH" , packet [ : OO00OO ] )
   self . length = socket . ntohs ( I1i )
   self . ttl = oOO0oOo0OOoOO
   self . protocol = i111
   self . ip_checksum = socket . ntohs ( i1 )
   self . source . afi = self . dest . afi = LISP_AFI_IPV4
   if 98 - 98: Ii1I
   if 92 - 92: iII111i % i1IIi . OoOoOO00 * iIii1I11I1II1
   if 17 - 17: OoooooooOO . OOooOOo
   if 32 - 32: OoOoOO00 . oO0o + O0
   i111 = struct . pack ( "H" , 0 )
   ooOO = struct . calcsize ( "HHIBB" )
   oO0Ooo = struct . calcsize ( "H" )
   packet = packet [ : ooOO ] + i111 + packet [ ooOO + oO0Ooo : ]
   if 49 - 49: II111iiii . OoooooooOO
   packet = packet [ OO00OO : : ]
   packet = self . source . unpack_address ( packet )
   if ( packet == None ) : return ( None )
   packet = self . dest . unpack_address ( packet )
   if ( packet == None ) : return ( None )
   if 30 - 30: OoO0O00 / i11iIiiIii - OoO0O00 / ooOoO0o + iIii1I11I1II1 + i1IIi
   if 99 - 99: OOooOOo * I1IiiI + oO0o % oO0o % OOooOOo * IiII
  if ( I1OO == 6 ) :
   OO00OO = struct . calcsize ( "IHBB" )
   if ( len ( packet ) < OO00OO ) : return ( None )
   if 98 - 98: OOooOOo
   I1I111 , I1i , i111 , oOO0oOo0OOoOO = struct . unpack ( "IHBB" , packet [ : OO00OO ] )
   self . length = socket . ntohs ( I1i )
   self . protocol = i111
   self . ttl = oOO0oOo0OOoOO
   self . source . afi = self . dest . afi = LISP_AFI_IPV6
   if 97 - 97: o0oOOo0O0Ooo
   packet = packet [ OO00OO : : ]
   packet = self . source . unpack_address ( packet )
   if ( packet == None ) : return ( None )
   packet = self . dest . unpack_address ( packet )
   if ( packet == None ) : return ( None )
   if 35 - 35: ooOoO0o + i11iIiiIii
   if 82 - 82: i11iIiiIii + I11i + iII111i % I1IiiI
  self . source . mask_len = self . source . host_mask_len ( )
  self . dest . mask_len = self . dest . host_mask_len ( )
  if 84 - 84: oO0o % OOooOOo
  OO00OO = struct . calcsize ( "HHHH" )
  if ( len ( packet ) < OO00OO ) : return ( None )
  if 25 - 25: i11iIiiIii * OoOoOO00 + i11iIiiIii . i1IIi
  IiIIi1I1I11Ii , oOo0OOOOOO , I1i , i1 = struct . unpack ( "HHHH" , packet [ : OO00OO ] )
  self . udp_sport = socket . ntohs ( IiIIi1I1I11Ii )
  self . udp_dport = socket . ntohs ( oOo0OOOOOO )
  self . udp_length = socket . ntohs ( I1i )
  self . udp_checksum = socket . ntohs ( i1 )
  packet = packet [ OO00OO : : ]
  return ( packet )
  if 83 - 83: I1IiiI
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
  if 34 - 34: iII111i . OOooOOo
  if 13 - 13: OoO0O00 * OOooOOo + oO0o
  if 21 - 21: i11iIiiIii . Ii1I % i1IIi * Ii1I . oO0o + Ii1I
  if 92 - 92: i1IIi + OoO0O00 * I11i
  if 70 - 70: Oo0Ooo
  if 93 - 93: iII111i . I1ii11iIi11i . Oo0Ooo . oO0o . OoooooooOO
  if 51 - 51: O0 - iII111i
  if 65 - 65: O0 / II111iiii * IiII % Ii1I + o0oOOo0O0Ooo
  if 43 - 43: I1Ii111 + OoO0O00 * OoooooooOO
  if 85 - 85: iII111i + OOooOOo
  if 36 - 36: OoO0O00 % II111iiii * O0 + II111iiii - oO0o - i1IIi
  if 53 - 53: Ii1I - OOooOOo
  if 75 - 75: iII111i % O0 - I11i - I1ii11iIi11i + I1IiiI - I1IiiI
  if 87 - 87: i1IIi % Ii1I % i1IIi + iIii1I11I1II1
  if 23 - 23: iIii1I11I1II1 * I11i . I1Ii111 - o0oOOo0O0Ooo
  if 66 - 66: I1IiiI * I1Ii111 / i11iIiiIii / OOooOOo
  if 19 - 19: ooOoO0o % iIii1I11I1II1 * OoooooooOO
  if 60 - 60: I1Ii111 * iII111i / OoooooooOO * Oo0Ooo
  if 47 - 47: iII111i + o0oOOo0O0Ooo % iIii1I11I1II1 * OoOoOO00
  if 65 - 65: OOooOOo . II111iiii * i11iIiiIii + OOooOOo
  if 99 - 99: I1ii11iIi11i % Oo0Ooo
  if 31 - 31: o0oOOo0O0Ooo - II111iiii * OOooOOo . OOooOOo - oO0o
  if 57 - 57: OOooOOo / i11iIiiIii / I1Ii111 - Oo0Ooo . iIii1I11I1II1
  if 84 - 84: IiII
  if 42 - 42: O0 . I1Ii111 / I11i
  if 69 - 69: OoOoOO00 / I1Ii111 * I1IiiI
  if 76 - 76: O0 + II111iiii * OoO0O00
  if 1 - 1: o0oOOo0O0Ooo
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
  if 31 - 31: I1Ii111 . OoooooooOO . i1IIi
  if 65 - 65: OoO0O00 . ooOoO0o
 def print_rloc_name ( self , cour = False ) :
  if ( self . rloc_name == None ) : return ( "" )
  I1IiiIoo0o00O = self . rloc_name
  if ( cour ) : I1IiiIoo0o00O = lisp_print_cour ( I1IiiIoo0o00O )
  return ( 'rloc-name: {}' . format ( blue ( I1IiiIoo0o00O , cour ) ) )
  if 36 - 36: ooOoO0o / II111iiii - ooOoO0o * iII111i
  if 43 - 43: iII111i * i1IIi . I1IiiI . OoOoOO00 / IiII - Oo0Ooo
 def print_record ( self , indent ) :
  oooOOoo0 = self . print_rloc_name ( )
  if ( oooOOoo0 != "" ) : oooOOoo0 = ", " + oooOOoo0
  oo00OoO00o = ""
  if ( self . geo ) :
   II1 = ""
   if ( self . geo . geo_name ) : II1 = "'{}' " . format ( self . geo . geo_name )
   oo00OoO00o = ", geo: {}{}" . format ( II1 , self . geo . print_geo ( ) )
   if 67 - 67: i1IIi * O0 / I11i * O0
  II1iIiiI = ""
  if ( self . elp ) :
   II1 = ""
   if ( self . elp . elp_name ) : II1 = "'{}' " . format ( self . elp . elp_name )
   II1iIiiI = ", elp: {}{}" . format ( II1 , self . elp . print_elp ( True ) )
   if 48 - 48: iIii1I11I1II1 / I11i
  O0O00OOOO = ""
  if ( self . rle ) :
   II1 = ""
   if ( self . rle . rle_name ) : II1 = "'{}' " . format ( self . rle . rle_name )
   O0O00OOOO = ", rle: {}{}" . format ( II1 , self . rle . print_rle ( False ) )
   if 95 - 95: OOooOOo . I1ii11iIi11i + I1Ii111 - O0 * II111iiii % II111iiii
  II = ""
  if ( self . json ) :
   II1 = ""
   if ( self . json . json_name ) :
    II1 = "'{}' " . format ( self . json . json_name )
    if 82 - 82: OoO0O00 + i11iIiiIii
   II = ", json: {}" . format ( self . json . print_json ( False ) )
   if 100 - 100: iIii1I11I1II1 % OOooOOo + ooOoO0o * Ii1I
   if 3 - 3: ooOoO0o
  OOOO0o0OOo = ""
  if ( self . rloc . is_null ( ) == False and self . keys and self . keys [ 1 ] ) :
   OOOO0o0OOo = ", " + self . keys [ 1 ] . print_keys ( )
   if 75 - 75: ooOoO0o + ooOoO0o . I1Ii111 % iII111i / iIii1I11I1II1 * iII111i
   if 13 - 13: II111iiii * i11iIiiIii - i1IIi * OoO0O00 + i1IIi
  oooOo = ( "{}RLOC-record -> flags: {}, {}/{}/{}/{}, afi: {}, rloc: "
 + "{}{}{}{}{}{}{}" )
  lprint ( oooOo . format ( indent , self . print_flags ( ) , self . priority ,
 self . weight , self . mpriority , self . mweight , self . rloc . afi ,
 red ( self . rloc . print_address_no_iid ( ) , False ) , oooOOoo0 , oo00OoO00o ,
 II1iIiiI , O0O00OOOO , II , OOOO0o0OOo ) )
  if 43 - 43: O0 % oO0o * I1IiiI
  if 64 - 64: II111iiii + i11iIiiIii
 def print_flags ( self ) :
  return ( "{}{}{}" . format ( "L" if self . local_bit else "l" , "P" if self . probe_bit else "p" , "R" if self . reach_bit else "r" ) )
  if 17 - 17: O0 * I1IiiI
  if 40 - 40: iIii1I11I1II1 * iII111i % iIii1I11I1II1
  if 39 - 39: i1IIi . Ii1I - Oo0Ooo
 def store_rloc_entry ( self , rloc_entry ) :
  oOOoo0O00 = rloc_entry . rloc if ( rloc_entry . translated_rloc . is_null ( ) ) else rloc_entry . translated_rloc
  if 30 - 30: i1IIi
  self . rloc . copy_address ( oOOoo0O00 )
  if 86 - 86: I1IiiI % I11i * O0 + i1IIi % I1Ii111
  if ( rloc_entry . rloc_name ) :
   self . rloc_name = rloc_entry . rloc_name
   if 97 - 97: II111iiii * OoOoOO00 - I1Ii111 / i11iIiiIii / OoOoOO00
   if 25 - 25: Oo0Ooo / Oo0Ooo
  if ( rloc_entry . geo ) :
   self . geo = rloc_entry . geo
  else :
   II1 = rloc_entry . geo_name
   if ( II1 and lisp_geo_list . has_key ( II1 ) ) :
    self . geo = lisp_geo_list [ II1 ]
    if 74 - 74: OOooOOo
    if 30 - 30: O0 . Ii1I / o0oOOo0O0Ooo + I1IiiI - O0
  if ( rloc_entry . elp ) :
   self . elp = rloc_entry . elp
  else :
   II1 = rloc_entry . elp_name
   if ( II1 and lisp_elp_list . has_key ( II1 ) ) :
    self . elp = lisp_elp_list [ II1 ]
    if 88 - 88: i11iIiiIii
    if 33 - 33: OoO0O00 + O0
  if ( rloc_entry . rle ) :
   self . rle = rloc_entry . rle
  else :
   II1 = rloc_entry . rle_name
   if ( II1 and lisp_rle_list . has_key ( II1 ) ) :
    self . rle = lisp_rle_list [ II1 ]
    if 20 - 20: o0oOOo0O0Ooo % I11i . ooOoO0o - i1IIi . O0
    if 10 - 10: i1IIi
  if ( rloc_entry . json ) :
   self . json = rloc_entry . json
  else :
   II1 = rloc_entry . json_name
   if ( II1 and lisp_json_list . has_key ( II1 ) ) :
    self . json = lisp_json_list [ II1 ]
    if 49 - 49: I1Ii111 - Ii1I . O0
    if 46 - 46: OOooOOo
  self . priority = rloc_entry . priority
  self . weight = rloc_entry . weight
  self . mpriority = rloc_entry . mpriority
  self . mweight = rloc_entry . mweight
  if 64 - 64: I1IiiI / OoOoOO00
  if 6 - 6: i11iIiiIii - iII111i * i1IIi - iII111i
 def encode_lcaf ( self ) :
  iIi11 = socket . htons ( LISP_AFI_LCAF )
  I1ii = ""
  if ( self . geo ) :
   I1ii = self . geo . encode_geo ( )
   if 19 - 19: ooOoO0o
   if 44 - 44: I1Ii111 - i11iIiiIii * I1IiiI
  oo0oOooo0O = ""
  if ( self . elp ) :
   I1i1ii = ""
   for ii1iIiIIiIIii in self . elp . elp_nodes :
    oOo00Oo0o00oo = socket . htons ( ii1iIiIIiIIii . address . afi )
    oOo0ooo00OoO = 0
    if ( ii1iIiIIiIIii . eid ) : oOo0ooo00OoO |= 0x4
    if ( ii1iIiIIiIIii . probe ) : oOo0ooo00OoO |= 0x2
    if ( ii1iIiIIiIIii . strict ) : oOo0ooo00OoO |= 0x1
    oOo0ooo00OoO = socket . htons ( oOo0ooo00OoO )
    I1i1ii += struct . pack ( "HH" , oOo0ooo00OoO , oOo00Oo0o00oo )
    I1i1ii += ii1iIiIIiIIii . address . pack_address ( )
    if 76 - 76: i1IIi / iIii1I11I1II1
    if 23 - 23: Oo0Ooo / ooOoO0o
   oo0OoooOo0 = socket . htons ( len ( I1i1ii ) )
   oo0oOooo0O = struct . pack ( "HBBBBH" , iIi11 , 0 , 0 , LISP_LCAF_ELP_TYPE ,
 0 , oo0OoooOo0 )
   oo0oOooo0O += I1i1ii
   if 61 - 61: II111iiii . OoO0O00 - II111iiii
   if 75 - 75: Oo0Ooo - OoOoOO00 + oO0o % i1IIi * OOooOOo
  OOoO = ""
  if ( self . rle ) :
   oO0OI1Ii1 = ""
   for OOoo0Oo00 in self . rle . rle_nodes :
    oOo00Oo0o00oo = socket . htons ( OOoo0Oo00 . address . afi )
    oO0OI1Ii1 += struct . pack ( "HBBH" , 0 , 0 , OOoo0Oo00 . level , oOo00Oo0o00oo )
    oO0OI1Ii1 += OOoo0Oo00 . address . pack_address ( )
    if ( OOoo0Oo00 . rloc_name ) :
     oO0OI1Ii1 += struct . pack ( "H" , socket . htons ( LISP_AFI_NAME ) )
     oO0OI1Ii1 += OOoo0Oo00 . rloc_name + "\0"
     if 16 - 16: I1Ii111 % Oo0Ooo * OOooOOo % I1ii11iIi11i + OOooOOo % OoO0O00
     if 77 - 77: IiII - OoooooooOO % I1Ii111 / Oo0Ooo % OoooooooOO * iIii1I11I1II1
     if 48 - 48: OoOoOO00
   O0Ooo0oOOO0o0 = socket . htons ( len ( oO0OI1Ii1 ) )
   OOoO = struct . pack ( "HBBBBH" , iIi11 , 0 , 0 , LISP_LCAF_RLE_TYPE ,
 0 , O0Ooo0oOOO0o0 )
   OOoO += oO0OI1Ii1
   if 40 - 40: OoOoOO00 / oO0o - Ii1I % Ii1I
   if 8 - 8: IiII
  O0Oii = ""
  if ( self . json ) :
   ii1iII1i1iiIi = socket . htons ( len ( self . json . json_string ) + 2 )
   oO00 = socket . htons ( len ( self . json . json_string ) )
   O0Oii = struct . pack ( "HBBBBHH" , iIi11 , 0 , 0 , LISP_LCAF_JSON_TYPE ,
 0 , ii1iII1i1iiIi , oO00 )
   O0Oii += self . json . json_string
   O0Oii += struct . pack ( "H" , 0 )
   if 81 - 81: OoOoOO00 + iII111i . i11iIiiIii
   if 10 - 10: OoOoOO00 + I11i - iIii1I11I1II1 - I11i
  o0Oo00OoO000O = ""
  if ( self . rloc . is_null ( ) == False and self . keys and self . keys [ 1 ] ) :
   o0Oo00OoO000O = self . keys [ 1 ] . encode_lcaf ( self . rloc )
   if 39 - 39: OoO0O00 + OoooooooOO * iIii1I11I1II1 . IiII * I1ii11iIi11i
   if 90 - 90: Oo0Ooo
  O0oO0OoOO = ""
  if ( self . rloc_name ) :
   O0oO0OoOO += struct . pack ( "H" , socket . htons ( LISP_AFI_NAME ) )
   O0oO0OoOO += self . rloc_name + "\0"
   if 46 - 46: IiII + I1IiiI / i11iIiiIii - iIii1I11I1II1 * I1IiiI
   if 78 - 78: OoO0O00
  OO0ooiI1Ii1I = len ( I1ii ) + len ( oo0oOooo0O ) + len ( OOoO ) + len ( o0Oo00OoO000O ) + 2 + len ( O0Oii ) + self . rloc . addr_length ( ) + len ( O0oO0OoOO )
  if 11 - 11: I1ii11iIi11i
  OO0ooiI1Ii1I = socket . htons ( OO0ooiI1Ii1I )
  o00OoooOoo = struct . pack ( "HBBBBHH" , iIi11 , 0 , 0 , LISP_LCAF_AFI_LIST_TYPE ,
 0 , OO0ooiI1Ii1I , socket . htons ( self . rloc . afi ) )
  o00OoooOoo += self . rloc . pack_address ( )
  return ( o00OoooOoo + O0oO0OoOO + I1ii + oo0oOooo0O + OOoO + o0Oo00OoO000O + O0Oii )
  if 29 - 29: OOooOOo - i11iIiiIii % IiII / OoooooooOO
  if 92 - 92: I1ii11iIi11i
 def encode ( self ) :
  oOo0ooo00OoO = 0
  if ( self . local_bit ) : oOo0ooo00OoO |= 0x0004
  if ( self . probe_bit ) : oOo0ooo00OoO |= 0x0002
  if ( self . reach_bit ) : oOo0ooo00OoO |= 0x0001
  if 89 - 89: OoO0O00 * i11iIiiIii - IiII * i1IIi - ooOoO0o . Ii1I
  i1II1IiiIi = struct . pack ( "BBBBHH" , self . priority , self . weight ,
 self . mpriority , self . mweight , socket . htons ( oOo0ooo00OoO ) ,
 socket . htons ( self . rloc . afi ) )
  if 26 - 26: I1IiiI * OoooooooOO / I1IiiI . O0 . ooOoO0o + O0
  if ( self . geo or self . elp or self . rle or self . keys or self . rloc_name or self . json ) :
   if 84 - 84: I1Ii111 . O0 + O0 % O0 % i1IIi + iIii1I11I1II1
   i1II1IiiIi = i1II1IiiIi [ 0 : - 2 ] + self . encode_lcaf ( )
  else :
   i1II1IiiIi += self . rloc . pack_address ( )
   if 71 - 71: iII111i / iIii1I11I1II1 . OOooOOo * i11iIiiIii
  return ( i1II1IiiIi )
  if 98 - 98: O0 % iIii1I11I1II1 . IiII - II111iiii
  if 14 - 14: Ii1I % ooOoO0o - OoOoOO00
 def decode_lcaf ( self , packet , nonce ) :
  oOo0ooO0O0oo = "HBBBBH"
  OO00OO = struct . calcsize ( oOo0ooO0O0oo )
  if ( len ( packet ) < OO00OO ) : return ( None )
  if 52 - 52: OoO0O00 / i1IIi - Ii1I
  oOo00Oo0o00oo , oO0OO0o0oo0o , oOo0ooo00OoO , OOo000OOoOO , ooooOo00O , ii1iII1i1iiIi = struct . unpack ( oOo0ooO0O0oo , packet [ : OO00OO ] )
  if 8 - 8: oO0o + ooOoO0o . I1ii11iIi11i . i1IIi / I1IiiI . IiII
  if 8 - 8: i1IIi * O0
  ii1iII1i1iiIi = socket . ntohs ( ii1iII1i1iiIi )
  packet = packet [ OO00OO : : ]
  if ( ii1iII1i1iiIi > len ( packet ) ) : return ( None )
  if 60 - 60: Oo0Ooo - II111iiii + I1IiiI
  if 17 - 17: OoOoOO00 % I1IiiI
  if 8 - 8: Oo0Ooo
  if 49 - 49: OoOoOO00 * I11i - o0oOOo0O0Ooo / OoO0O00 * oO0o
  if ( OOo000OOoOO == LISP_LCAF_AFI_LIST_TYPE ) :
   while ( ii1iII1i1iiIi > 0 ) :
    oOo0ooO0O0oo = "H"
    OO00OO = struct . calcsize ( oOo0ooO0O0oo )
    if ( ii1iII1i1iiIi < OO00OO ) : return ( None )
    if 51 - 51: ooOoO0o - iIii1I11I1II1 . I11i * OoOoOO00 + I1Ii111 * i1IIi
    OoOO = len ( packet )
    oOo00Oo0o00oo = struct . unpack ( oOo0ooO0O0oo , packet [ : OO00OO ] ) [ 0 ]
    oOo00Oo0o00oo = socket . ntohs ( oOo00Oo0o00oo )
    if 37 - 37: IiII * oO0o / OoooooooOO . OoO0O00
    if ( oOo00Oo0o00oo == LISP_AFI_LCAF ) :
     packet = self . decode_lcaf ( packet , nonce )
     if ( packet == None ) : return ( None )
    else :
     packet = packet [ OO00OO : : ]
     self . rloc_name = None
     if ( oOo00Oo0o00oo == LISP_AFI_NAME ) :
      packet , I1IiiIoo0o00O = lisp_decode_dist_name ( packet )
      self . rloc_name = I1IiiIoo0o00O
     else :
      self . rloc . afi = oOo00Oo0o00oo
      packet = self . rloc . unpack_address ( packet )
      if ( packet == None ) : return ( None )
      self . rloc . mask_len = self . rloc . host_mask_len ( )
      if 77 - 77: II111iiii + OoOoOO00 * OOooOOo
      if 9 - 9: II111iiii - i11iIiiIii * o0oOOo0O0Ooo % OoO0O00 * i11iIiiIii / I11i
      if 45 - 45: i11iIiiIii * iII111i - I1ii11iIi11i + ooOoO0o % iII111i
    ii1iII1i1iiIi -= OoOO - len ( packet )
    if 11 - 11: iIii1I11I1II1
    if 48 - 48: iIii1I11I1II1 - Oo0Ooo
  elif ( OOo000OOoOO == LISP_LCAF_GEO_COORD_TYPE ) :
   if 80 - 80: i1IIi
   if 56 - 56: II111iiii - o0oOOo0O0Ooo
   if 48 - 48: Oo0Ooo - I1ii11iIi11i - II111iiii . Ii1I . oO0o / iIii1I11I1II1
   if 38 - 38: I1Ii111 % i11iIiiIii + Ii1I * ooOoO0o / I1Ii111
   oO0o0oO0O = lisp_geo ( "" )
   packet = oO0o0oO0O . decode_geo ( packet , ii1iII1i1iiIi , ooooOo00O )
   if ( packet == None ) : return ( None )
   self . geo = oO0o0oO0O
   if 49 - 49: OoOoOO00 - iIii1I11I1II1 / IiII - I1IiiI . I1Ii111 - I11i
  elif ( OOo000OOoOO == LISP_LCAF_JSON_TYPE ) :
   if 33 - 33: IiII - iIii1I11I1II1
   if 77 - 77: OOooOOo . I1ii11iIi11i / II111iiii % iIii1I11I1II1 * i11iIiiIii
   if 9 - 9: oO0o - i1IIi . ooOoO0o + I1ii11iIi11i
   if 72 - 72: ooOoO0o
   oOo0ooO0O0oo = "H"
   OO00OO = struct . calcsize ( oOo0ooO0O0oo )
   if ( ii1iII1i1iiIi < OO00OO ) : return ( None )
   if 47 - 47: iIii1I11I1II1 . OOooOOo / I11i % II111iiii
   oO00 = struct . unpack ( oOo0ooO0O0oo , packet [ : OO00OO ] ) [ 0 ]
   oO00 = socket . ntohs ( oO00 )
   if ( ii1iII1i1iiIi < OO00OO + oO00 ) : return ( None )
   if 92 - 92: I1ii11iIi11i % i11iIiiIii
   packet = packet [ OO00OO : : ]
   self . json = lisp_json ( "" , packet [ 0 : oO00 ] )
   packet = packet [ oO00 : : ]
   if 82 - 82: I1Ii111 * I1ii11iIi11i % Ii1I / o0oOOo0O0Ooo
  elif ( OOo000OOoOO == LISP_LCAF_ELP_TYPE ) :
   if 28 - 28: iII111i % OoO0O00 - OOooOOo - Oo0Ooo
   if 16 - 16: i11iIiiIii - i11iIiiIii . OoOoOO00 / i1IIi
   if 76 - 76: O0 * OoO0O00 / O0
   if 23 - 23: I1ii11iIi11i . iIii1I11I1II1 - i11iIiiIii / II111iiii
   iI1ii1I1i = lisp_elp ( None )
   iI1ii1I1i . elp_nodes = [ ]
   while ( ii1iII1i1iiIi > 0 ) :
    oOo0ooo00OoO , oOo00Oo0o00oo = struct . unpack ( "HH" , packet [ : 4 ] )
    if 88 - 88: II111iiii
    oOo00Oo0o00oo = socket . ntohs ( oOo00Oo0o00oo )
    if ( oOo00Oo0o00oo == LISP_AFI_LCAF ) : return ( None )
    if 19 - 19: OoooooooOO * i11iIiiIii / O0 . I1IiiI % I11i
    ii1iIiIIiIIii = lisp_elp_node ( )
    iI1ii1I1i . elp_nodes . append ( ii1iIiIIiIIii )
    if 35 - 35: iIii1I11I1II1 + I1IiiI - ooOoO0o / Oo0Ooo * I1ii11iIi11i * Oo0Ooo
    oOo0ooo00OoO = socket . ntohs ( oOo0ooo00OoO )
    ii1iIiIIiIIii . eid = ( oOo0ooo00OoO & 0x4 )
    ii1iIiIIiIIii . probe = ( oOo0ooo00OoO & 0x2 )
    ii1iIiIIiIIii . strict = ( oOo0ooo00OoO & 0x1 )
    ii1iIiIIiIIii . address . afi = oOo00Oo0o00oo
    ii1iIiIIiIIii . address . mask_len = ii1iIiIIiIIii . address . host_mask_len ( )
    packet = ii1iIiIIiIIii . address . unpack_address ( packet [ 4 : : ] )
    ii1iII1i1iiIi -= ii1iIiIIiIIii . address . addr_length ( ) + 4
    if 17 - 17: OoOoOO00
   iI1ii1I1i . select_elp_node ( )
   self . elp = iI1ii1I1i
   if 24 - 24: iIii1I11I1II1 / OOooOOo % OoooooooOO / O0 / oO0o
  elif ( OOo000OOoOO == LISP_LCAF_RLE_TYPE ) :
   if 93 - 93: Oo0Ooo
   if 5 - 5: iII111i
   if 61 - 61: OOooOOo * OoO0O00 - O0
   if 30 - 30: iIii1I11I1II1
   iiiI1i1111II = lisp_rle ( None )
   iiiI1i1111II . rle_nodes = [ ]
   while ( ii1iII1i1iiIi > 0 ) :
    I1I111 , iI11Ii , iI1iiiIii , oOo00Oo0o00oo = struct . unpack ( "HBBH" , packet [ : 6 ] )
    if 84 - 84: I1IiiI - iII111i % OoooooooOO . OoO0O00
    oOo00Oo0o00oo = socket . ntohs ( oOo00Oo0o00oo )
    if ( oOo00Oo0o00oo == LISP_AFI_LCAF ) : return ( None )
    if 68 - 68: I1ii11iIi11i
    OOoo0Oo00 = lisp_rle_node ( )
    iiiI1i1111II . rle_nodes . append ( OOoo0Oo00 )
    if 65 - 65: OoOoOO00 - OoOoOO00
    OOoo0Oo00 . level = iI1iiiIii
    OOoo0Oo00 . address . afi = oOo00Oo0o00oo
    OOoo0Oo00 . address . mask_len = OOoo0Oo00 . address . host_mask_len ( )
    packet = OOoo0Oo00 . address . unpack_address ( packet [ 6 : : ] )
    if 61 - 61: oO0o
    ii1iII1i1iiIi -= OOoo0Oo00 . address . addr_length ( ) + 6
    if ( ii1iII1i1iiIi >= 2 ) :
     oOo00Oo0o00oo = struct . unpack ( "H" , packet [ : 2 ] ) [ 0 ]
     if ( socket . ntohs ( oOo00Oo0o00oo ) == LISP_AFI_NAME ) :
      packet = packet [ 2 : : ]
      packet , OOoo0Oo00 . rloc_name = lisp_decode_dist_name ( packet )
      if 19 - 19: O0 + iII111i . I11i + II111iiii
      if ( packet == None ) : return ( None )
      ii1iII1i1iiIi -= len ( OOoo0Oo00 . rloc_name ) + 1 + 2
      if 50 - 50: ooOoO0o + I11i / oO0o - IiII
      if 23 - 23: I11i % ooOoO0o
      if 14 - 14: OOooOOo * OoOoOO00
   self . rle = iiiI1i1111II
   self . rle . build_forwarding_list ( )
   if 92 - 92: I1IiiI . I11i / OoO0O00 * Ii1I
  elif ( OOo000OOoOO == LISP_LCAF_SECURITY_TYPE ) :
   if 12 - 12: OoooooooOO % oO0o
   if 92 - 92: ooOoO0o % OoO0O00 + O0 + OoOoOO00 / OoO0O00 * iIii1I11I1II1
   if 79 - 79: O0
   if 71 - 71: OoO0O00 - O0
   if 73 - 73: iIii1I11I1II1
   iIiiII11 = packet
   OoOoo0ooO0000 = lisp_keys ( 1 )
   packet = OoOoo0ooO0000 . decode_lcaf ( iIiiII11 , ii1iII1i1iiIi )
   if ( packet == None ) : return ( None )
   if 7 - 7: OoOoOO00
   if 55 - 55: oO0o . OoO0O00 + iIii1I11I1II1 + OoOoOO00 / I1ii11iIi11i - O0
   if 14 - 14: II111iiii - OoO0O00 - O0 * OoooooooOO / I1IiiI
   if 3 - 3: I11i
   O0Ii1iIii1I1 = [ LISP_CS_25519_CBC , LISP_CS_25519_CHACHA ]
   if ( OoOoo0ooO0000 . cipher_suite in O0Ii1iIii1I1 ) :
    if ( OoOoo0ooO0000 . cipher_suite == LISP_CS_25519_CBC ) :
     o0OoOo0o0OOoO0 = lisp_keys ( 1 , do_poly = False , do_chacha = False )
     if 46 - 46: I1ii11iIi11i * I1Ii111 - iIii1I11I1II1
    if ( OoOoo0ooO0000 . cipher_suite == LISP_CS_25519_CHACHA ) :
     o0OoOo0o0OOoO0 = lisp_keys ( 1 , do_poly = True , do_chacha = True )
     if 25 - 25: II111iiii / OOooOOo + Oo0Ooo - iIii1I11I1II1 - OoOoOO00
   else :
    o0OoOo0o0OOoO0 = lisp_keys ( 1 , do_poly = False , do_chacha = False )
    if 97 - 97: OOooOOo . OOooOOo / I1ii11iIi11i + I1IiiI * i1IIi
   packet = o0OoOo0o0OOoO0 . decode_lcaf ( iIiiII11 , ii1iII1i1iiIi )
   if ( packet == None ) : return ( None )
   if 53 - 53: O0
   if ( len ( packet ) < 2 ) : return ( None )
   oOo00Oo0o00oo = struct . unpack ( "H" , packet [ : 2 ] ) [ 0 ]
   self . rloc . afi = socket . ntohs ( oOo00Oo0o00oo )
   if ( len ( packet ) < self . rloc . addr_length ( ) ) : return ( None )
   packet = self . rloc . unpack_address ( packet [ 2 : : ] )
   if ( packet == None ) : return ( None )
   self . rloc . mask_len = self . rloc . host_mask_len ( )
   if 28 - 28: iII111i % OoO0O00 . OoO0O00 / IiII * Oo0Ooo * iII111i
   if 49 - 49: I1IiiI / I1Ii111 * iII111i + I1IiiI % oO0o % ooOoO0o
   if 27 - 27: OoO0O00 / iII111i . I1ii11iIi11i
   if 71 - 71: OoO0O00 . i11iIiiIii . iIii1I11I1II1 + I1IiiI - o0oOOo0O0Ooo
   if 34 - 34: iII111i
   if 6 - 6: OoO0O00 . OoOoOO00 + I1ii11iIi11i
   if ( self . rloc . is_null ( ) ) : return ( packet )
   if 24 - 24: OoO0O00 . Ii1I
   IiIi1I1i1iII = self . rloc_name
   if ( IiIi1I1i1iII ) : IiIi1I1i1iII = blue ( self . rloc_name , False )
   if 86 - 86: I11i % I1Ii111 . I11i * IiII + IiII + II111iiii
   if 66 - 66: oO0o / O0 - OoOoOO00
   if 69 - 69: iIii1I11I1II1 * OoO0O00 / OoooooooOO % I1ii11iIi11i . I1IiiI % I11i
   if 40 - 40: i11iIiiIii % oO0o / OOooOOo
   if 85 - 85: OoO0O00 % O0 . Ii1I . iII111i . iII111i
   if 90 - 90: o0oOOo0O0Ooo - Oo0Ooo / ooOoO0o / i1IIi - Ii1I
   IiI1IIII = self . keys [ 1 ] if self . keys else None
   if ( IiI1IIII == None ) :
    if ( o0OoOo0o0OOoO0 . remote_public_key == None ) :
     OO0o0o0oo = bold ( "No remote encap-public-key supplied" , False )
     lprint ( "    {} for {}" . format ( OO0o0o0oo , IiIi1I1i1iII ) )
     o0OoOo0o0OOoO0 = None
    else :
     OO0o0o0oo = bold ( "New encap-keying with new state" , False )
     lprint ( "    {} for {}" . format ( OO0o0o0oo , IiIi1I1i1iII ) )
     o0OoOo0o0OOoO0 . compute_shared_key ( "encap" )
     if 43 - 43: i11iIiiIii - OoooooooOO % ooOoO0o
     if 55 - 55: oO0o % Oo0Ooo % IiII
     if 65 - 65: IiII * IiII
     if 60 - 60: ooOoO0o
     if 92 - 92: O0 % IiII
     if 15 - 15: O0 % i1IIi - OOooOOo . IiII
     if 1 - 1: I1IiiI
     if 40 - 40: o0oOOo0O0Ooo % I11i % O0
     if 88 - 88: o0oOOo0O0Ooo - oO0o
     if 73 - 73: II111iiii
   if ( IiI1IIII ) :
    if ( o0OoOo0o0OOoO0 . remote_public_key == None ) :
     o0OoOo0o0OOoO0 = None
     oOOo0o000o = bold ( "Remote encap-unkeying occurred" , False )
     lprint ( "    {} for {}" . format ( oOOo0o000o , IiIi1I1i1iII ) )
    elif ( IiI1IIII . compare_keys ( o0OoOo0o0OOoO0 ) ) :
     o0OoOo0o0OOoO0 = IiI1IIII
     lprint ( "    Maintain stored encap-keys for {}" . format ( IiIi1I1i1iII ) )
     if 7 - 7: O0 / OoO0O00
    else :
     if ( IiI1IIII . remote_public_key == None ) :
      OO0o0o0oo = "New encap-keying for existing state"
     else :
      OO0o0o0oo = "Remote encap-rekeying"
      if 90 - 90: iII111i % oO0o / iIii1I11I1II1
     lprint ( "    {} for {}" . format ( bold ( OO0o0o0oo , False ) ,
 IiIi1I1i1iII ) )
     IiI1IIII . remote_public_key = o0OoOo0o0OOoO0 . remote_public_key
     IiI1IIII . compute_shared_key ( "encap" )
     o0OoOo0o0OOoO0 = IiI1IIII
     if 52 - 52: I1IiiI / o0oOOo0O0Ooo
     if 20 - 20: I1Ii111 . I1IiiI - iIii1I11I1II1 / iII111i
   self . keys = [ None , o0OoOo0o0OOoO0 , None , None ]
   if 46 - 46: I1Ii111 . i11iIiiIii
  else :
   if 89 - 89: OoO0O00 - OOooOOo - i1IIi - OoO0O00 % iIii1I11I1II1
   if 52 - 52: o0oOOo0O0Ooo * O0 + I1ii11iIi11i
   if 83 - 83: I11i + OOooOOo - OoooooooOO
   if 7 - 7: IiII % ooOoO0o / OoooooooOO / o0oOOo0O0Ooo + OoO0O00 - OoO0O00
   packet = packet [ ii1iII1i1iiIi : : ]
   if 15 - 15: i1IIi + OOooOOo / Ii1I
  return ( packet )
  if 51 - 51: OOooOOo + O0
  if 91 - 91: i11iIiiIii + o0oOOo0O0Ooo % OoO0O00 / oO0o - i1IIi
 def decode ( self , packet , nonce ) :
  oOo0ooO0O0oo = "BBBBHH"
  OO00OO = struct . calcsize ( oOo0ooO0O0oo )
  if ( len ( packet ) < OO00OO ) : return ( None )
  if 82 - 82: Ii1I . OoooooooOO + OoooooooOO % OoO0O00 % I1ii11iIi11i
  self . priority , self . weight , self . mpriority , self . mweight , oOo0ooo00OoO , oOo00Oo0o00oo = struct . unpack ( oOo0ooO0O0oo , packet [ : OO00OO ] )
  if 65 - 65: Oo0Ooo . I11i
  if 7 - 7: Oo0Ooo * II111iiii
  oOo0ooo00OoO = socket . ntohs ( oOo0ooo00OoO )
  oOo00Oo0o00oo = socket . ntohs ( oOo00Oo0o00oo )
  self . local_bit = True if ( oOo0ooo00OoO & 0x0004 ) else False
  self . probe_bit = True if ( oOo0ooo00OoO & 0x0002 ) else False
  self . reach_bit = True if ( oOo0ooo00OoO & 0x0001 ) else False
  if 11 - 11: OoOoOO00 % OoooooooOO
  if ( oOo00Oo0o00oo == LISP_AFI_LCAF ) :
   packet = packet [ OO00OO - 2 : : ]
   packet = self . decode_lcaf ( packet , nonce )
  else :
   self . rloc . afi = oOo00Oo0o00oo
   packet = packet [ OO00OO : : ]
   packet = self . rloc . unpack_address ( packet )
   if 92 - 92: OoOoOO00 - iII111i * Ii1I - i1IIi
  self . rloc . mask_len = self . rloc . host_mask_len ( )
  return ( packet )
  if 87 - 87: Ii1I * I1Ii111 + iIii1I11I1II1 * o0oOOo0O0Ooo * iIii1I11I1II1 . I11i
  if 66 - 66: Ii1I / OoO0O00 . O0 . I11i % OoooooooOO / OOooOOo
 def end_of_rlocs ( self , packet , rloc_count ) :
  for Ii11 in range ( rloc_count ) :
   packet = self . decode ( packet , None )
   if ( packet == None ) : return ( None )
   if 49 - 49: I1IiiI * iII111i - OoO0O00 % Ii1I + Ii1I * I1Ii111
  return ( packet )
  if 94 - 94: OoOoOO00 - I11i + Ii1I + OoOoOO00 + II111iiii
  if 61 - 61: IiII + Ii1I / oO0o . OoooooooOO + iII111i
  if 29 - 29: OOooOOo
  if 69 - 69: oO0o % OoooooooOO * iII111i
  if 58 - 58: oO0o / i11iIiiIii . OoOoOO00 % O0 / iIii1I11I1II1
  if 50 - 50: I1Ii111 . I11i / O0 . I11i
  if 91 - 91: i11iIiiIii . I1ii11iIi11i + I11i
  if 67 - 67: I1ii11iIi11i * I1Ii111 * I1IiiI / I11i - IiII + oO0o
  if 11 - 11: O0 + i1IIi / o0oOOo0O0Ooo * OoO0O00
  if 64 - 64: i1IIi % IiII . ooOoO0o . iIii1I11I1II1 + OoO0O00 - iIii1I11I1II1
  if 52 - 52: II111iiii - IiII
  if 91 - 91: iIii1I11I1II1 + iII111i . I11i % i11iIiiIii - i11iIiiIii + I1IiiI
  if 75 - 75: I1ii11iIi11i / I1IiiI - iIii1I11I1II1 / OoO0O00 * OOooOOo
  if 73 - 73: OoooooooOO % IiII / I1Ii111 * I11i + i1IIi % i11iIiiIii
  if 91 - 91: i11iIiiIii
  if 6 - 6: O0 - iIii1I11I1II1 + I1Ii111 . o0oOOo0O0Ooo * i11iIiiIii
  if 53 - 53: OOooOOo / I1IiiI / oO0o * OOooOOo / i1IIi - I1Ii111
  if 71 - 71: O0 + Oo0Ooo % oO0o - o0oOOo0O0Ooo
  if 82 - 82: iIii1I11I1II1
  if 64 - 64: ooOoO0o + I1IiiI % OOooOOo + II111iiii
  if 46 - 46: I1IiiI
  if 72 - 72: iII111i
  if 100 - 100: I1IiiI
  if 55 - 55: i1IIi % IiII
  if 44 - 44: oO0o - iIii1I11I1II1 / ooOoO0o - iIii1I11I1II1 % i1IIi + ooOoO0o
  if 74 - 74: I11i . OoOoOO00 + OoOoOO00
  if 87 - 87: IiII + o0oOOo0O0Ooo . i1IIi % I1Ii111
  if 44 - 44: Oo0Ooo - OOooOOo . Ii1I * OoooooooOO
  if 93 - 93: OoO0O00 . OoO0O00
  if 52 - 52: OOooOOo . oO0o / Oo0Ooo . OoooooooOO % I1ii11iIi11i
class lisp_map_referral ( ) :
 def __init__ ( self ) :
  self . record_count = 0
  self . nonce = 0
  if 65 - 65: ooOoO0o % II111iiii . iII111i - iIii1I11I1II1 - I1IiiI
  if 63 - 63: I1IiiI . OoOoOO00 - II111iiii
 def print_map_referral ( self ) :
  lprint ( "{} -> record-count: {}, nonce: 0x{}" . format ( bold ( "Map-Referral" , False ) , self . record_count ,
  # I1ii11iIi11i / o0oOOo0O0Ooo * I1Ii111 / I1Ii111
 lisp_hex_string ( self . nonce ) ) )
  if 95 - 95: iIii1I11I1II1 % I1Ii111
  if 39 - 39: I1ii11iIi11i - iIii1I11I1II1 * ooOoO0o
 def encode ( self ) :
  oo0I1I1iiI1i = ( LISP_MAP_REFERRAL << 28 ) | self . record_count
  i1II1IiiIi = struct . pack ( "I" , socket . htonl ( oo0I1I1iiI1i ) )
  i1II1IiiIi += struct . pack ( "Q" , self . nonce )
  return ( i1II1IiiIi )
  if 87 - 87: O0 + O0 - ooOoO0o . i11iIiiIii - Oo0Ooo * i11iIiiIii
  if 72 - 72: I11i / OoooooooOO
 def decode ( self , packet ) :
  oOo0ooO0O0oo = "I"
  OO00OO = struct . calcsize ( oOo0ooO0O0oo )
  if ( len ( packet ) < OO00OO ) : return ( None )
  if 95 - 95: I1IiiI * i11iIiiIii + i11iIiiIii / iIii1I11I1II1
  oo0I1I1iiI1i = struct . unpack ( oOo0ooO0O0oo , packet [ : OO00OO ] )
  oo0I1I1iiI1i = socket . ntohl ( oo0I1I1iiI1i [ 0 ] )
  self . record_count = oo0I1I1iiI1i & 0xff
  packet = packet [ OO00OO : : ]
  if 20 - 20: I11i
  oOo0ooO0O0oo = "Q"
  OO00OO = struct . calcsize ( oOo0ooO0O0oo )
  if ( len ( packet ) < OO00OO ) : return ( None )
  if 15 - 15: o0oOOo0O0Ooo . i11iIiiIii * I1ii11iIi11i / ooOoO0o
  self . nonce = struct . unpack ( oOo0ooO0O0oo , packet [ : OO00OO ] ) [ 0 ]
  packet = packet [ OO00OO : : ]
  return ( packet )
  if 41 - 41: ooOoO0o + IiII . i1IIi + iIii1I11I1II1
  if 57 - 57: i11iIiiIii * oO0o * i11iIiiIii
  if 14 - 14: Oo0Ooo / I11i
  if 14 - 14: Oo0Ooo - Ii1I + ooOoO0o - I1IiiI % IiII
  if 70 - 70: I1IiiI % ooOoO0o * OoO0O00 + OoOoOO00 % i11iIiiIii
  if 39 - 39: Oo0Ooo % I1Ii111 / I1IiiI / Oo0Ooo . o0oOOo0O0Ooo + o0oOOo0O0Ooo
  if 83 - 83: OoooooooOO * II111iiii % OoooooooOO
  if 30 - 30: I1Ii111 / o0oOOo0O0Ooo + OoooooooOO + OoOoOO00 + OoO0O00
class lisp_ddt_entry ( ) :
 def __init__ ( self ) :
  self . eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . group = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . uptime = lisp_get_timestamp ( )
  self . delegation_set = [ ]
  self . source_cache = None
  self . map_referrals_sent = 0
  if 40 - 40: OoooooooOO / IiII
  if 82 - 82: i11iIiiIii - oO0o - i1IIi
 def is_auth_prefix ( self ) :
  if ( len ( self . delegation_set ) != 0 ) : return ( False )
  if ( self . is_star_g ( ) ) : return ( False )
  return ( True )
  if 78 - 78: oO0o % iII111i / i1IIi / ooOoO0o
  if 44 - 44: o0oOOo0O0Ooo + Ii1I + I1IiiI % O0
 def is_ms_peer_entry ( self ) :
  if ( len ( self . delegation_set ) == 0 ) : return ( False )
  return ( self . delegation_set [ 0 ] . is_ms_peer ( ) )
  if 100 - 100: OoooooooOO
  if 27 - 27: i11iIiiIii % II111iiii + I1Ii111
 def print_referral_type ( self ) :
  if ( len ( self . delegation_set ) == 0 ) : return ( "unknown" )
  O0O0Oo0o = self . delegation_set [ 0 ]
  return ( O0O0Oo0o . print_node_type ( ) )
  if 64 - 64: ooOoO0o % I1ii11iIi11i . OoO0O00 . ooOoO0o + i11iIiiIii . iIii1I11I1II1
  if 70 - 70: ooOoO0o
 def print_eid_tuple ( self ) :
  return ( lisp_print_eid_tuple ( self . eid , self . group ) )
  if 3 - 3: I1IiiI - I1IiiI
  if 89 - 89: OoOoOO00
 def add_cache ( self ) :
  if ( self . group . is_null ( ) ) :
   lisp_ddt_cache . add_cache ( self . eid , self )
  else :
   IiiI11i11i = lisp_ddt_cache . lookup_cache ( self . group , True )
   if ( IiiI11i11i == None ) :
    IiiI11i11i = lisp_ddt_entry ( )
    IiiI11i11i . eid . copy_address ( self . group )
    IiiI11i11i . group . copy_address ( self . group )
    lisp_ddt_cache . add_cache ( self . group , IiiI11i11i )
    if 15 - 15: II111iiii - OoO0O00 * OoOoOO00 / II111iiii
   if ( self . eid . is_null ( ) ) : self . eid . make_default_route ( IiiI11i11i . group )
   IiiI11i11i . add_source_entry ( self )
   if 56 - 56: OoooooooOO + iIii1I11I1II1 % Oo0Ooo . OoooooooOO / Oo0Ooo % II111iiii
   if 96 - 96: ooOoO0o % Ii1I
   if 83 - 83: I1IiiI - OOooOOo . I1IiiI * Oo0Ooo
 def add_source_entry ( self , source_ddt ) :
  if ( self . source_cache == None ) : self . source_cache = lisp_cache ( )
  self . source_cache . add_cache ( source_ddt . eid , source_ddt )
  if 76 - 76: i11iIiiIii + Ii1I
  if 14 - 14: OoO0O00 * OoooooooOO
 def lookup_source_cache ( self , source , exact ) :
  if ( self . source_cache == None ) : return ( None )
  return ( self . source_cache . lookup_cache ( source , exact ) )
  if 45 - 45: iIii1I11I1II1 * I1IiiI . OoOoOO00
  if 97 - 97: I11i % II111iiii % Ii1I . II111iiii . iIii1I11I1II1
 def is_star_g ( self ) :
  if ( self . group . is_null ( ) ) : return ( False )
  return ( self . eid . is_exact_match ( self . group ) )
  if 98 - 98: i11iIiiIii + O0 - O0 - iII111i
  if 25 - 25: oO0o / O0 + I1Ii111 % i11iIiiIii / I1IiiI
  if 62 - 62: iII111i . I11i * i1IIi + iII111i
class lisp_ddt_node ( ) :
 def __init__ ( self ) :
  self . delegate_address = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . public_key = ""
  self . map_server_peer = False
  self . map_server_child = False
  self . priority = 0
  self . weight = 0
  if 95 - 95: Ii1I / o0oOOo0O0Ooo % ooOoO0o - I1IiiI / OOooOOo * OOooOOo
  if 6 - 6: OoO0O00 % IiII + iIii1I11I1II1
 def print_node_type ( self ) :
  if ( self . is_ddt_child ( ) ) : return ( "ddt-child" )
  if ( self . is_ms_child ( ) ) : return ( "map-server-child" )
  if ( self . is_ms_peer ( ) ) : return ( "map-server-peer" )
  if 18 - 18: II111iiii . Ii1I + OoOoOO00 + O0 - I11i
  if 30 - 30: II111iiii
 def is_ddt_child ( self ) :
  if ( self . map_server_child ) : return ( False )
  if ( self . map_server_peer ) : return ( False )
  return ( True )
  if 26 - 26: I11i - i1IIi - Oo0Ooo * O0 * OOooOOo . OoooooooOO
  if 99 - 99: oO0o . OoO0O00 / OOooOOo
 def is_ms_child ( self ) :
  return ( self . map_server_child )
  if 12 - 12: iIii1I11I1II1 + ooOoO0o * I1Ii111 % OoooooooOO / iIii1I11I1II1
  if 43 - 43: O0 . i1IIi - OoooooooOO - i1IIi - I1ii11iIi11i
 def is_ms_peer ( self ) :
  return ( self . map_server_peer )
  if 8 - 8: OoOoOO00 / Ii1I
  if 12 - 12: iIii1I11I1II1
  if 52 - 52: oO0o . I1ii11iIi11i + oO0o
  if 73 - 73: II111iiii / i11iIiiIii / ooOoO0o
  if 1 - 1: iII111i + OoOoOO00 / IiII - I1IiiI % I1IiiI
  if 6 - 6: OoOoOO00 - i1IIi + II111iiii % oO0o
  if 72 - 72: OOooOOo + OOooOOo
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
  if 30 - 30: I11i
  if 15 - 15: O0 - i1IIi . iIii1I11I1II1 - i11iIiiIii / Ii1I
 def print_ddt_map_request ( self ) :
  lprint ( "Queued Map-Request from {}ITR {}->{}, nonce 0x{}" . format ( "P" if self . from_pitr else "" ,
  # i1IIi
 red ( self . itr . print_address ( ) , False ) ,
 green ( self . eid . print_address ( ) , False ) , self . nonce ) )
  if 38 - 38: I1IiiI
  if 15 - 15: o0oOOo0O0Ooo
 def queue_map_request ( self ) :
  self . retransmit_timer = threading . Timer ( LISP_DDT_MAP_REQUEST_INTERVAL ,
 lisp_retransmit_ddt_map_request , [ self ] )
  self . retransmit_timer . start ( )
  lisp_ddt_map_requestQ [ str ( self . nonce ) ] = self
  if 55 - 55: i11iIiiIii / OoooooooOO - I11i
  if 89 - 89: I11i - i1IIi - i1IIi * OOooOOo - O0
 def dequeue_map_request ( self ) :
  self . retransmit_timer . cancel ( )
  if ( lisp_ddt_map_requestQ . has_key ( str ( self . nonce ) ) ) :
   lisp_ddt_map_requestQ . pop ( str ( self . nonce ) )
   if 94 - 94: Oo0Ooo / I11i . I1ii11iIi11i
   if 31 - 31: i11iIiiIii + iIii1I11I1II1 . II111iiii
   if 72 - 72: I1Ii111 * OoO0O00 + Oo0Ooo / Ii1I % OOooOOo
 def print_eid_tuple ( self ) :
  return ( lisp_print_eid_tuple ( self . eid , self . group ) )
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
  if 5 - 5: I1ii11iIi11i % OoOoOO00 . OoooooooOO . o0oOOo0O0Ooo + i11iIiiIii
  if 54 - 54: ooOoO0o - O0 + iII111i
LISP_DDT_ACTION_SITE_NOT_FOUND = - 2
LISP_DDT_ACTION_NULL = - 1
LISP_DDT_ACTION_NODE_REFERRAL = 0
LISP_DDT_ACTION_MS_REFERRAL = 1
LISP_DDT_ACTION_MS_ACK = 2
LISP_DDT_ACTION_MS_NOT_REG = 3
LISP_DDT_ACTION_DELEGATION_HOLE = 4
LISP_DDT_ACTION_NOT_AUTH = 5
LISP_DDT_ACTION_MAX = LISP_DDT_ACTION_NOT_AUTH
if 34 - 34: Ii1I - OOooOOo % iII111i
lisp_map_referral_action_string = [
 "node-referral" , "ms-referral" , "ms-ack" , "ms-not-registered" ,
 "delegation-hole" , "not-authoritative" ]
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
if 20 - 20: IiII % I1IiiI + iIii1I11I1II1 % iII111i
if 100 - 100: o0oOOo0O0Ooo - Oo0Ooo % I1Ii111 . i11iIiiIii % OoooooooOO
if 39 - 39: I1ii11iIi11i / i11iIiiIii * i1IIi * Oo0Ooo
if 39 - 39: OoO0O00 * OoooooooOO / i1IIi + Oo0Ooo
if 57 - 57: O0
if 83 - 83: OOooOOo / Ii1I * I1IiiI % oO0o / iIii1I11I1II1
if 1 - 1: I11i / OoooooooOO / iII111i
if 68 - 68: i1IIi / Oo0Ooo / I11i * Oo0Ooo
if 91 - 91: OoO0O00 . iII111i
if 82 - 82: I1ii11iIi11i / Oo0Ooo
if 63 - 63: I1IiiI
if 3 - 3: iII111i + I1ii11iIi11i
if 35 - 35: oO0o * iII111i * oO0o * I1Ii111 * IiII * i1IIi
if 43 - 43: OoO0O00 * I1IiiI / IiII . i11iIiiIii + iII111i + o0oOOo0O0Ooo
if 1 - 1: I1IiiI % o0oOOo0O0Ooo . I1Ii111 + I11i * oO0o
if 41 - 41: OoO0O00 * oO0o - II111iiii
if 2 - 2: IiII + IiII - OoO0O00 * iII111i . oO0o
if 91 - 91: ooOoO0o
if 22 - 22: ooOoO0o % OoO0O00 * OoOoOO00 + Oo0Ooo
if 44 - 44: O0 - I11i
if 43 - 43: O0
if 50 - 50: I11i - OoooooooOO
if 29 - 29: oO0o * oO0o
if 44 - 44: ooOoO0o . I1IiiI * oO0o * Ii1I
if 41 - 41: i1IIi % i11iIiiIii + I11i % OoooooooOO / I1ii11iIi11i
if 8 - 8: OoooooooOO - OoO0O00 / i11iIiiIii / O0 . IiII
if 86 - 86: ooOoO0o * OoooooooOO + iII111i + o0oOOo0O0Ooo
if 79 - 79: i1IIi % I1ii11iIi11i - OoO0O00 % I1ii11iIi11i
if 6 - 6: Oo0Ooo / iII111i . i11iIiiIii
if 8 - 8: I1ii11iIi11i + O0 - oO0o % II111iiii . I1Ii111
if 86 - 86: IiII
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
  if 71 - 71: Ii1I - i1IIi . I1IiiI
  if 15 - 15: i1IIi % II111iiii / II111iiii - I1ii11iIi11i - I11i % i1IIi
 def print_info ( self ) :
  if ( self . info_reply ) :
   OoO = "Info-Reply"
   oOOoo0O00 = ( ", ms-port: {}, etr-port: {}, global-rloc: {}, " + "ms-rloc: {}, private-rloc: {}, RTR-list: " ) . format ( self . ms_port , self . etr_port ,
   # iII111i + OoO0O00 * i1IIi
   # OoO0O00
 red ( self . global_etr_rloc . print_address_no_iid ( ) , False ) ,
 red ( self . global_ms_rloc . print_address_no_iid ( ) , False ) ,
 red ( self . private_etr_rloc . print_address_no_iid ( ) , False ) )
   if ( len ( self . rtr_list ) == 0 ) : oOOoo0O00 += "empty, "
   for iI11I1I in self . rtr_list :
    oOOoo0O00 += red ( iI11I1I . print_address_no_iid ( ) , False ) + ", "
    if 32 - 32: oO0o
   oOOoo0O00 = oOOoo0O00 [ 0 : - 2 ]
  else :
   OoO = "Info-Request"
   O0oO0Oooo = "<none>" if self . hostname == None else self . hostname
   oOOoo0O00 = ", hostname: {}" . format ( blue ( O0oO0Oooo , False ) )
   if 29 - 29: I1ii11iIi11i + OoO0O00 * II111iiii + iII111i
  lprint ( "{} -> nonce: 0x{}{}" . format ( bold ( OoO , False ) ,
 lisp_hex_string ( self . nonce ) , oOOoo0O00 ) )
  if 3 - 3: Oo0Ooo / OoOoOO00 + IiII . IiII . OoO0O00
  if 36 - 36: OoooooooOO + O0
 def encode ( self ) :
  oo0I1I1iiI1i = ( LISP_NAT_INFO << 28 )
  if ( self . info_reply ) : oo0I1I1iiI1i |= ( 1 << 27 )
  if 32 - 32: Ii1I / I1ii11iIi11i . Ii1I
  if 65 - 65: IiII
  if 74 - 74: Oo0Ooo + i1IIi - II111iiii / ooOoO0o / iII111i
  if 66 - 66: ooOoO0o / IiII * iIii1I11I1II1
  if 42 - 42: I1Ii111 - i11iIiiIii % II111iiii * ooOoO0o . O0 % I11i
  i1II1IiiIi = struct . pack ( "I" , socket . htonl ( oo0I1I1iiI1i ) )
  i1II1IiiIi += struct . pack ( "Q" , self . nonce )
  i1II1IiiIi += struct . pack ( "III" , 0 , 0 , 0 )
  if 82 - 82: Oo0Ooo % O0 + I1ii11iIi11i % I1ii11iIi11i
  if 74 - 74: O0 * IiII . I11i - I1Ii111 + O0 + I11i
  if 48 - 48: oO0o . o0oOOo0O0Ooo - OOooOOo
  if 29 - 29: Oo0Ooo - Ii1I - Oo0Ooo
  if ( self . info_reply == False ) :
   if ( self . hostname == None ) :
    i1II1IiiIi += struct . pack ( "H" , 0 )
   else :
    i1II1IiiIi += struct . pack ( "H" , socket . htons ( LISP_AFI_NAME ) )
    i1II1IiiIi += self . hostname + "\0"
    if 89 - 89: Oo0Ooo . OoO0O00 . I1ii11iIi11i * oO0o . O0
   return ( i1II1IiiIi )
   if 72 - 72: i11iIiiIii % I11i / I1Ii111 + I1IiiI * iII111i
   if 69 - 69: I1Ii111 + O0 . IiII . o0oOOo0O0Ooo
   if 38 - 38: IiII / i1IIi
   if 60 - 60: OoOoOO00
   if 75 - 75: II111iiii / iIii1I11I1II1 / OoooooooOO
  oOo00Oo0o00oo = socket . htons ( LISP_AFI_LCAF )
  OOo000OOoOO = LISP_LCAF_NAT_TYPE
  ii1iII1i1iiIi = socket . htons ( 16 )
  o0o0OoOo000O = socket . htons ( self . ms_port )
  Iii11i1 = socket . htons ( self . etr_port )
  i1II1IiiIi += struct . pack ( "HHBBHHHH" , oOo00Oo0o00oo , 0 , OOo000OOoOO , 0 , ii1iII1i1iiIi ,
 o0o0OoOo000O , Iii11i1 , socket . htons ( self . global_etr_rloc . afi ) )
  i1II1IiiIi += self . global_etr_rloc . pack_address ( )
  i1II1IiiIi += struct . pack ( "HH" , 0 , socket . htons ( self . private_etr_rloc . afi ) )
  i1II1IiiIi += self . private_etr_rloc . pack_address ( )
  if ( len ( self . rtr_list ) == 0 ) : i1II1IiiIi += struct . pack ( "H" , 0 )
  if 1 - 1: II111iiii + OoO0O00 * I1IiiI
  if 82 - 82: I1Ii111 * Oo0Ooo % OoooooooOO
  if 12 - 12: IiII / O0 % I1IiiI - IiII
  if 80 - 80: OoooooooOO
  for iI11I1I in self . rtr_list :
   i1II1IiiIi += struct . pack ( "H" , socket . htons ( iI11I1I . afi ) )
   i1II1IiiIi += iI11I1I . pack_address ( )
   if 100 - 100: iII111i / ooOoO0o * OoOoOO00 . OoooooooOO % I1Ii111 - O0
  return ( i1II1IiiIi )
  if 23 - 23: O0 * Ii1I * ooOoO0o % ooOoO0o
  if 7 - 7: II111iiii + I11i
 def decode ( self , packet ) :
  iIiiII11 = packet
  oOo0ooO0O0oo = "I"
  OO00OO = struct . calcsize ( oOo0ooO0O0oo )
  if ( len ( packet ) < OO00OO ) : return ( None )
  if 99 - 99: iIii1I11I1II1 * oO0o
  oo0I1I1iiI1i = struct . unpack ( oOo0ooO0O0oo , packet [ : OO00OO ] )
  oo0I1I1iiI1i = oo0I1I1iiI1i [ 0 ]
  packet = packet [ OO00OO : : ]
  if 37 - 37: ooOoO0o * iII111i * I11i
  oOo0ooO0O0oo = "Q"
  OO00OO = struct . calcsize ( oOo0ooO0O0oo )
  if ( len ( packet ) < OO00OO ) : return ( None )
  if 11 - 11: I1IiiI
  iI1III = struct . unpack ( oOo0ooO0O0oo , packet [ : OO00OO ] )
  if 48 - 48: O0 . I11i
  oo0I1I1iiI1i = socket . ntohl ( oo0I1I1iiI1i )
  self . nonce = iI1III [ 0 ]
  self . info_reply = oo0I1I1iiI1i & 0x08000000
  self . hostname = None
  packet = packet [ OO00OO : : ]
  if 9 - 9: oO0o / Oo0Ooo
  if 85 - 85: i11iIiiIii / I1IiiI . OoO0O00 . I11i . oO0o * IiII
  if 41 - 41: Ii1I / OoO0O00 / OoO0O00 * I11i
  if 31 - 31: Ii1I / OoooooooOO % iIii1I11I1II1 - IiII * I1IiiI - O0
  if 31 - 31: oO0o
  oOo0ooO0O0oo = "HH"
  OO00OO = struct . calcsize ( oOo0ooO0O0oo )
  if ( len ( packet ) < OO00OO ) : return ( None )
  if 74 - 74: OoO0O00
  if 11 - 11: oO0o + O0 % Ii1I . I11i * o0oOOo0O0Ooo
  if 14 - 14: I11i . iIii1I11I1II1 + I1Ii111 % OoooooooOO
  if 9 - 9: oO0o + Ii1I / I1ii11iIi11i * iIii1I11I1II1 + o0oOOo0O0Ooo
  if 64 - 64: I11i % i11iIiiIii % I1ii11iIi11i
  o0OOOoO0O , O0O0O0OOO0o = struct . unpack ( oOo0ooO0O0oo , packet [ : OO00OO ] )
  if ( O0O0O0OOO0o != 0 ) : return ( None )
  if 14 - 14: I1Ii111 - OoOoOO00 - I1ii11iIi11i % I11i + OoooooooOO
  packet = packet [ OO00OO : : ]
  oOo0ooO0O0oo = "IBBH"
  OO00OO = struct . calcsize ( oOo0ooO0O0oo )
  if ( len ( packet ) < OO00OO ) : return ( None )
  if 4 - 4: I1Ii111 - I1IiiI / iIii1I11I1II1 + I1ii11iIi11i % iIii1I11I1II1 * I1IiiI
  oooOooOO , O0ooO , ii1I1I1iII , ii11i = struct . unpack ( oOo0ooO0O0oo ,
 packet [ : OO00OO ] )
  if 42 - 42: OoOoOO00 / iII111i + OOooOOo
  if ( ii11i != 0 ) : return ( None )
  packet = packet [ OO00OO : : ]
  if 61 - 61: i11iIiiIii % oO0o * ooOoO0o
  if 59 - 59: OOooOOo + i1IIi
  if 10 - 10: Oo0Ooo - i1IIi % I1ii11iIi11i
  if 54 - 54: IiII + OOooOOo + oO0o * O0 % ooOoO0o + OoO0O00
  if ( self . info_reply == False ) :
   oOo0ooO0O0oo = "H"
   OO00OO = struct . calcsize ( oOo0ooO0O0oo )
   if ( len ( packet ) >= OO00OO ) :
    oOo00Oo0o00oo = struct . unpack ( oOo0ooO0O0oo , packet [ : OO00OO ] ) [ 0 ]
    if ( socket . ntohs ( oOo00Oo0o00oo ) == LISP_AFI_NAME ) :
     packet = packet [ OO00OO : : ]
     packet , self . hostname = lisp_decode_dist_name ( packet )
     if 13 - 13: i11iIiiIii * O0 . OoooooooOO % I1Ii111 + I1ii11iIi11i + OOooOOo
     if 45 - 45: oO0o % i11iIiiIii / Ii1I / IiII % Ii1I - Ii1I
   return ( iIiiII11 )
   if 73 - 73: I1ii11iIi11i * I1ii11iIi11i / II111iiii % iII111i
   if 74 - 74: OoO0O00 / I1ii11iIi11i - ooOoO0o * i1IIi + I1ii11iIi11i . I11i
   if 13 - 13: iII111i + o0oOOo0O0Ooo / iII111i - Ii1I - iII111i
   if 34 - 34: IiII . OOooOOo + OOooOOo - OoooooooOO * I1Ii111
   if 72 - 72: iIii1I11I1II1 % i1IIi / OoO0O00 / I1IiiI - II111iiii - I1Ii111
  oOo0ooO0O0oo = "HHBBHHH"
  OO00OO = struct . calcsize ( oOo0ooO0O0oo )
  if ( len ( packet ) < OO00OO ) : return ( None )
  if 43 - 43: o0oOOo0O0Ooo - Oo0Ooo - I1ii11iIi11i / II111iiii + I1IiiI / I1ii11iIi11i
  oOo00Oo0o00oo , I1I111 , OOo000OOoOO , O0ooO , ii1iII1i1iiIi , o0o0OoOo000O , Iii11i1 = struct . unpack ( oOo0ooO0O0oo , packet [ : OO00OO ] )
  if 34 - 34: Oo0Ooo
  if 21 - 21: I1IiiI / I1IiiI % I1Ii111 - OoOoOO00 % OoOoOO00 - II111iiii
  if ( socket . ntohs ( oOo00Oo0o00oo ) != LISP_AFI_LCAF ) : return ( None )
  if 97 - 97: oO0o
  self . ms_port = socket . ntohs ( o0o0OoOo000O )
  self . etr_port = socket . ntohs ( Iii11i1 )
  packet = packet [ OO00OO : : ]
  if 98 - 98: I1Ii111 * I1IiiI + iIii1I11I1II1
  if 75 - 75: oO0o
  if 50 - 50: oO0o / Oo0Ooo
  if 32 - 32: OoO0O00 % oO0o * I1ii11iIi11i + I11i / I1Ii111
  oOo0ooO0O0oo = "H"
  OO00OO = struct . calcsize ( oOo0ooO0O0oo )
  if ( len ( packet ) < OO00OO ) : return ( None )
  if 5 - 5: o0oOOo0O0Ooo + iII111i / OoooooooOO + Ii1I . OoOoOO00 / oO0o
  if 18 - 18: II111iiii . o0oOOo0O0Ooo
  if 75 - 75: OoooooooOO - Oo0Ooo
  if 56 - 56: II111iiii - i11iIiiIii - oO0o . o0oOOo0O0Ooo
  oOo00Oo0o00oo = struct . unpack ( oOo0ooO0O0oo , packet [ : OO00OO ] ) [ 0 ]
  packet = packet [ OO00OO : : ]
  if ( oOo00Oo0o00oo != 0 ) :
   self . global_etr_rloc . afi = socket . ntohs ( oOo00Oo0o00oo )
   packet = self . global_etr_rloc . unpack_address ( packet )
   if ( packet == None ) : return ( None )
   self . global_etr_rloc . mask_len = self . global_etr_rloc . host_mask_len ( )
   if 4 - 4: i1IIi
   if 91 - 91: IiII . OoO0O00 * Ii1I / o0oOOo0O0Ooo
   if 41 - 41: I1IiiI . OoO0O00 / i1IIi . Oo0Ooo . oO0o
   if 44 - 44: iII111i * I11i + i11iIiiIii + i1IIi / IiII * II111iiii
   if 58 - 58: OOooOOo
   if 72 - 72: OoO0O00 + OOooOOo - Oo0Ooo % ooOoO0o . IiII
  if ( len ( packet ) < OO00OO ) : return ( iIiiII11 )
  if 95 - 95: iII111i % OOooOOo - IiII - OoOoOO00 % o0oOOo0O0Ooo * O0
  oOo00Oo0o00oo = struct . unpack ( oOo0ooO0O0oo , packet [ : OO00OO ] ) [ 0 ]
  packet = packet [ OO00OO : : ]
  if ( oOo00Oo0o00oo != 0 ) :
   self . global_ms_rloc . afi = socket . ntohs ( oOo00Oo0o00oo )
   packet = self . global_ms_rloc . unpack_address ( packet )
   if ( packet == None ) : return ( iIiiII11 )
   self . global_ms_rloc . mask_len = self . global_ms_rloc . host_mask_len ( )
   if 16 - 16: I1Ii111 / Oo0Ooo
   if 48 - 48: Oo0Ooo / oO0o + iII111i % iII111i
   if 9 - 9: I1ii11iIi11i - o0oOOo0O0Ooo . Oo0Ooo + I1ii11iIi11i . OOooOOo
   if 30 - 30: OoooooooOO - iIii1I11I1II1 / oO0o * Ii1I / Ii1I
   if 52 - 52: OoOoOO00 - OoO0O00 + I1IiiI + IiII
  if ( len ( packet ) < OO00OO ) : return ( iIiiII11 )
  if 49 - 49: oO0o / I11i - oO0o
  oOo00Oo0o00oo = struct . unpack ( oOo0ooO0O0oo , packet [ : OO00OO ] ) [ 0 ]
  packet = packet [ OO00OO : : ]
  if ( oOo00Oo0o00oo != 0 ) :
   self . private_etr_rloc . afi = socket . ntohs ( oOo00Oo0o00oo )
   packet = self . private_etr_rloc . unpack_address ( packet )
   if ( packet == None ) : return ( iIiiII11 )
   self . private_etr_rloc . mask_len = self . private_etr_rloc . host_mask_len ( )
   if 31 - 31: OoOoOO00 + I1IiiI + I1ii11iIi11i + I11i * II111iiii % oO0o
   if 90 - 90: OOooOOo * iIii1I11I1II1 / i1IIi
   if 60 - 60: OOooOOo * I1Ii111 . oO0o
   if 47 - 47: oO0o % OOooOOo / OOooOOo % OoOoOO00 % I1Ii111 / OoOoOO00
   if 51 - 51: I1IiiI . I11i - OoOoOO00
   if 10 - 10: Oo0Ooo * OOooOOo / IiII . o0oOOo0O0Ooo
  while ( len ( packet ) >= OO00OO ) :
   oOo00Oo0o00oo = struct . unpack ( oOo0ooO0O0oo , packet [ : OO00OO ] ) [ 0 ]
   packet = packet [ OO00OO : : ]
   if ( oOo00Oo0o00oo == 0 ) : continue
   iI11I1I = lisp_address ( socket . ntohs ( oOo00Oo0o00oo ) , "" , 0 , 0 )
   packet = iI11I1I . unpack_address ( packet )
   if ( packet == None ) : return ( iIiiII11 )
   iI11I1I . mask_len = iI11I1I . host_mask_len ( )
   self . rtr_list . append ( iI11I1I )
   if 97 - 97: Ii1I . Ii1I % iII111i
  return ( iIiiII11 )
  if 49 - 49: Oo0Ooo % OOooOOo - OoooooooOO + IiII
  if 54 - 54: iIii1I11I1II1 - OoooooooOO / I11i / oO0o % I1IiiI + OoOoOO00
  if 26 - 26: OoO0O00 * II111iiii % OOooOOo * iII111i + iII111i
class lisp_nat_info ( ) :
 def __init__ ( self , addr_str , hostname , port ) :
  self . address = addr_str
  self . hostname = hostname
  self . port = port
  self . uptime = lisp_get_timestamp ( )
  if 25 - 25: I11i - I1ii11iIi11i
  if 100 - 100: I1Ii111 / Ii1I + OoOoOO00 . OoooooooOO
 def timed_out ( self ) :
  i11IiIIi11I = time . time ( ) - self . uptime
  return ( i11IiIIi11I >= ( LISP_INFO_INTERVAL * 2 ) )
  if 83 - 83: O0
  if 35 - 35: i11iIiiIii - I11i . OoOoOO00 * II111iiii % i11iIiiIii
  if 55 - 55: o0oOOo0O0Ooo / O0 / OoooooooOO * Oo0Ooo % iII111i
class lisp_info_source ( ) :
 def __init__ ( self , hostname , addr_str , port ) :
  self . address = lisp_address ( LISP_AFI_IPV4 , addr_str , 32 , 0 )
  self . port = port
  self . uptime = lisp_get_timestamp ( )
  self . nonce = None
  self . hostname = hostname
  self . no_timeout = False
  if 24 - 24: I1ii11iIi11i % OOooOOo + OoooooooOO + OoO0O00
  if 100 - 100: Oo0Ooo % OoO0O00 - OoOoOO00
 def cache_address_for_info_source ( self ) :
  o0OoOo0o0OOoO0 = self . address . print_address_no_iid ( ) + self . hostname
  lisp_info_sources_by_address [ o0OoOo0o0OOoO0 ] = self
  if 46 - 46: o0oOOo0O0Ooo
  if 28 - 28: i1IIi
 def cache_nonce_for_info_source ( self , nonce ) :
  self . nonce = nonce
  lisp_info_sources_by_nonce [ nonce ] = self
  if 81 - 81: oO0o % OoooooooOO . I1Ii111 - OoOoOO00 / I1IiiI
  if 62 - 62: I1Ii111 * I11i / I11i
  if 42 - 42: ooOoO0o * ooOoO0o / Ii1I / OOooOOo * OOooOOo
  if 92 - 92: Oo0Ooo / iII111i - OoooooooOO - o0oOOo0O0Ooo % ooOoO0o
  if 35 - 35: i1IIi % iII111i % I11i * iIii1I11I1II1 % Ii1I - Oo0Ooo
  if 94 - 94: iII111i
  if 68 - 68: OoooooooOO % OOooOOo / OoooooooOO / I1Ii111 + Ii1I - o0oOOo0O0Ooo
  if 81 - 81: I1IiiI
  if 62 - 62: Ii1I * OoOoOO00
  if 27 - 27: Oo0Ooo + Oo0Ooo / II111iiii % I1Ii111
  if 11 - 11: Ii1I
def lisp_concat_auth_data ( alg_id , auth1 , auth2 , auth3 , auth4 ) :
 if 54 - 54: I1IiiI * I1Ii111 / ooOoO0o / iIii1I11I1II1 % iII111i / oO0o
 if ( lisp_is_x86 ( ) ) :
  if ( auth1 != "" ) : auth1 = byte_swap_64 ( auth1 )
  if ( auth2 != "" ) : auth2 = byte_swap_64 ( auth2 )
  if ( auth3 != "" ) :
   if ( alg_id == LISP_SHA_1_96_ALG_ID ) : auth3 = socket . ntohl ( auth3 )
   else : auth3 = byte_swap_64 ( auth3 )
   if 11 - 11: ooOoO0o + I1IiiI + Ii1I . II111iiii
  if ( auth4 != "" ) : auth4 = byte_swap_64 ( auth4 )
  if 50 - 50: Oo0Ooo
  if 14 - 14: O0
 if ( alg_id == LISP_SHA_1_96_ALG_ID ) :
  auth1 = lisp_hex_string ( auth1 )
  auth1 = auth1 . zfill ( 16 )
  auth2 = lisp_hex_string ( auth2 )
  auth2 = auth2 . zfill ( 16 )
  auth3 = lisp_hex_string ( auth3 )
  auth3 = auth3 . zfill ( 8 )
  Iii = auth1 + auth2 + auth3
  if 67 - 67: II111iiii / O0
 if ( alg_id == LISP_SHA_256_128_ALG_ID ) :
  auth1 = lisp_hex_string ( auth1 )
  auth1 = auth1 . zfill ( 16 )
  auth2 = lisp_hex_string ( auth2 )
  auth2 = auth2 . zfill ( 16 )
  auth3 = lisp_hex_string ( auth3 )
  auth3 = auth3 . zfill ( 16 )
  auth4 = lisp_hex_string ( auth4 )
  auth4 = auth4 . zfill ( 16 )
  Iii = auth1 + auth2 + auth3 + auth4
  if 10 - 10: i1IIi / Oo0Ooo
 return ( Iii )
 if 20 - 20: Oo0Ooo * I1Ii111 / I1ii11iIi11i . ooOoO0o
 if 67 - 67: o0oOOo0O0Ooo . Oo0Ooo % I11i
 if 38 - 38: OOooOOo - OoO0O00 . ooOoO0o
 if 50 - 50: o0oOOo0O0Ooo
 if 85 - 85: II111iiii . iII111i - i1IIi
 if 23 - 23: iII111i . Ii1I - OoO0O00 / I1ii11iIi11i / O0
 if 4 - 4: i1IIi % Oo0Ooo % Ii1I * ooOoO0o - I11i
 if 76 - 76: iIii1I11I1II1 / ooOoO0o % I1ii11iIi11i % OOooOOo
 if 13 - 13: IiII
 if 56 - 56: Oo0Ooo
def lisp_open_listen_socket ( local_addr , port ) :
 if ( port . isdigit ( ) ) :
  if ( local_addr . find ( "." ) != - 1 ) :
   OoooooO = socket . socket ( socket . AF_INET , socket . SOCK_DGRAM )
   if 64 - 64: IiII . OoO0O00 * i11iIiiIii
  if ( local_addr . find ( ":" ) != - 1 ) :
   if ( lisp_is_raspbian ( ) ) : return ( None )
   OoooooO = socket . socket ( socket . AF_INET6 , socket . SOCK_DGRAM )
   if 18 - 18: Ii1I % o0oOOo0O0Ooo - Oo0Ooo
  OoooooO . bind ( ( local_addr , int ( port ) ) )
 else :
  II1 = port
  if ( os . path . exists ( II1 ) ) :
   os . system ( "rm " + II1 )
   time . sleep ( 1 )
   if 28 - 28: IiII
  OoooooO = socket . socket ( socket . AF_UNIX , socket . SOCK_DGRAM )
  OoooooO . bind ( II1 )
  if 93 - 93: Oo0Ooo % i1IIi
 return ( OoooooO )
 if 51 - 51: oO0o % O0
 if 41 - 41: I1IiiI * I1IiiI . I1Ii111
 if 38 - 38: I1IiiI % i11iIiiIii
 if 17 - 17: i11iIiiIii
 if 81 - 81: I1Ii111
 if 25 - 25: I1IiiI
 if 52 - 52: I1ii11iIi11i % i1IIi . IiII % OoOoOO00
def lisp_open_send_socket ( internal_name , afi ) :
 if ( internal_name == "" ) :
  if ( afi == LISP_AFI_IPV4 ) :
   OoooooO = socket . socket ( socket . AF_INET , socket . SOCK_DGRAM )
   if 50 - 50: OOooOOo * I1IiiI / o0oOOo0O0Ooo
  if ( afi == LISP_AFI_IPV6 ) :
   if ( lisp_is_raspbian ( ) ) : return ( None )
   OoooooO = socket . socket ( socket . AF_INET6 , socket . SOCK_DGRAM )
   if 91 - 91: iIii1I11I1II1 / OOooOOo * O0 . o0oOOo0O0Ooo + oO0o / I1ii11iIi11i
 else :
  if ( os . path . exists ( internal_name ) ) : os . system ( "rm " + internal_name )
  OoooooO = socket . socket ( socket . AF_UNIX , socket . SOCK_DGRAM )
  OoooooO . bind ( internal_name )
  if 33 - 33: II111iiii + Ii1I
 return ( OoooooO )
 if 46 - 46: IiII + O0 + i1IIi + ooOoO0o / iII111i
 if 94 - 94: oO0o + iII111i * OoOoOO00 - i1IIi / OoooooooOO
 if 59 - 59: I11i % Ii1I / OoOoOO00
 if 99 - 99: Ii1I + II111iiii / i11iIiiIii - IiII / iII111i + iII111i
 if 55 - 55: IiII + OoooooooOO * I1ii11iIi11i . IiII * I1ii11iIi11i + IiII
 if 81 - 81: iIii1I11I1II1 . ooOoO0o + OoOoOO00
 if 31 - 31: I11i / OoOoOO00 + o0oOOo0O0Ooo
def lisp_close_socket ( sock , internal_name ) :
 sock . close ( )
 if ( os . path . exists ( internal_name ) ) : os . system ( "rm " + internal_name )
 return
 if 80 - 80: Oo0Ooo
 if 58 - 58: I1Ii111 + OOooOOo
 if 76 - 76: II111iiii - o0oOOo0O0Ooo % OoO0O00 + iII111i
 if 38 - 38: I1Ii111 - I11i * i1IIi + iIii1I11I1II1
 if 41 - 41: Ii1I . OoO0O00 + I1ii11iIi11i + OoOoOO00
 if 76 - 76: iII111i - iIii1I11I1II1
 if 23 - 23: I11i / OoO0O00 % OOooOOo
 if 9 - 9: ooOoO0o % I1ii11iIi11i . OoooooooOO + OoO0O00 % OOooOOo * OoooooooOO
def lisp_is_running ( node ) :
 return ( True if ( os . path . exists ( node ) ) else False )
 if 21 - 21: Ii1I % O0
 if 15 - 15: II111iiii * Ii1I + IiII % iII111i
 if 96 - 96: II111iiii * I1Ii111 / Oo0Ooo
 if 35 - 35: I1IiiI
 if 54 - 54: I1ii11iIi11i % o0oOOo0O0Ooo . i1IIi
 if 72 - 72: Ii1I
 if 87 - 87: iII111i - I1IiiI
 if 54 - 54: iIii1I11I1II1 + oO0o * o0oOOo0O0Ooo % OoooooooOO . Oo0Ooo
 if 32 - 32: iII111i
def lisp_packet_ipc ( packet , source , sport ) :
 return ( ( "packet@" + str ( len ( packet ) ) + "@" + source + "@" + str ( sport ) + "@" + packet ) )
 if 33 - 33: ooOoO0o + Oo0Ooo * OoOoOO00 % ooOoO0o * oO0o - OoO0O00
 if 40 - 40: I11i . OoooooooOO * O0 / I1Ii111 + O0
 if 97 - 97: ooOoO0o - ooOoO0o * OOooOOo % OoOoOO00 - OoOoOO00 - I1Ii111
 if 52 - 52: O0 % iII111i
 if 81 - 81: OoooooooOO % OoOoOO00 % Oo0Ooo - I1IiiI
 if 43 - 43: o0oOOo0O0Ooo % o0oOOo0O0Ooo
 if 48 - 48: O0
 if 5 - 5: OOooOOo / i11iIiiIii . I11i % OOooOOo
 if 1 - 1: II111iiii + O0 * OoOoOO00 / IiII . O0
def lisp_control_packet_ipc ( packet , source , dest , dport ) :
 return ( "control-packet@" + dest + "@" + str ( dport ) + "@" + packet )
 if 87 - 87: IiII + I1IiiI
 if 74 - 74: OoO0O00 + OoO0O00 % iII111i / I11i / O0
 if 54 - 54: o0oOOo0O0Ooo / OoooooooOO * ooOoO0o . OoOoOO00 - I1Ii111
 if 69 - 69: oO0o - OoO0O00
 if 80 - 80: ooOoO0o + iIii1I11I1II1 . II111iiii + I1IiiI - oO0o % OoOoOO00
 if 10 - 10: iIii1I11I1II1
 if 44 - 44: OoOoOO00 * oO0o . I1ii11iIi11i + i11iIiiIii
def lisp_data_packet_ipc ( packet , source ) :
 return ( "data-packet@" + str ( len ( packet ) ) + "@" + source + "@@" + packet )
 if 85 - 85: I11i
 if 36 - 36: ooOoO0o % OoO0O00
 if 1 - 1: OoooooooOO - OoOoOO00
 if 35 - 35: I1Ii111
 if 35 - 35: Oo0Ooo - iIii1I11I1II1 / i1IIi + OoO0O00 - OoooooooOO / i11iIiiIii
 if 79 - 79: I1IiiI * ooOoO0o * ooOoO0o
 if 92 - 92: iII111i % I1ii11iIi11i
 if 16 - 16: oO0o
 if 52 - 52: OoooooooOO % ooOoO0o - I1Ii111 * I11i
def lisp_command_ipc ( packet , source ) :
 return ( "command@" + str ( len ( packet ) ) + "@" + source + "@@" + packet )
 if 24 - 24: Ii1I + IiII + OoooooooOO / oO0o / I1IiiI + IiII
 if 52 - 52: ooOoO0o
 if 38 - 38: OoO0O00 + I1IiiI % IiII
 if 87 - 87: oO0o * Ii1I - I1Ii111 / oO0o
 if 65 - 65: OoOoOO00
 if 87 - 87: I11i - i11iIiiIii - OOooOOo . OoOoOO00 + IiII . OoO0O00
 if 70 - 70: iIii1I11I1II1 % OoooooooOO / OoO0O00 . O0 - I11i % II111iiii
 if 84 - 84: OOooOOo * i1IIi . iIii1I11I1II1 * iII111i + I1Ii111 + II111iiii
 if 97 - 97: Ii1I - IiII
def lisp_api_ipc ( source , data ) :
 return ( "api@" + str ( len ( data ) ) + "@" + source + "@@" + data )
 if 64 - 64: oO0o . ooOoO0o / ooOoO0o - II111iiii
 if 81 - 81: I1ii11iIi11i
 if 64 - 64: oO0o * OoO0O00 / OOooOOo + Ii1I % Oo0Ooo . IiII
 if 2 - 2: I1Ii111 + I11i
 if 47 - 47: i11iIiiIii + iIii1I11I1II1 % I1ii11iIi11i - oO0o % OoO0O00
 if 85 - 85: oO0o * OoOoOO00 / OoOoOO00
 if 85 - 85: OOooOOo / I1Ii111 . i1IIi / OoOoOO00 + iIii1I11I1II1
 if 71 - 71: OoO0O00
 if 96 - 96: I1ii11iIi11i / I1IiiI - I1ii11iIi11i / II111iiii - IiII
def lisp_ipc ( packet , send_socket , node ) :
 if 74 - 74: Ii1I * OoooooooOO % OOooOOo + OoooooooOO + iII111i
 if 83 - 83: i1IIi
 if 2 - 2: i1IIi / OOooOOo * O0
 if 99 - 99: OoooooooOO . OoOoOO00 / II111iiii
 if ( lisp_is_running ( node ) == False ) :
  lprint ( "Suppress sending IPC to {}" . format ( node ) )
  return
  if 64 - 64: iII111i / i1IIi . I1IiiI + O0
  if 5 - 5: O0 . i11iIiiIii
 oOO00o = 1500 if ( packet . find ( "control-packet" ) == - 1 ) else 9000
 if 100 - 100: OoooooooOO
 I11iiIi1i1 = 0
 o00OOo00 = len ( packet )
 O0OoOo00oo = 0
 oOO0000 = .001
 while ( o00OOo00 > 0 ) :
  o0o000O0o0 = min ( o00OOo00 , oOO00o )
  oo0Oo0O = packet [ I11iiIi1i1 : o0o000O0o0 + I11iiIi1i1 ]
  if 14 - 14: iII111i / OoO0O00
  try :
   send_socket . sendto ( oo0Oo0O , node )
   lprint ( "Send IPC {}-out-of-{} byte to {} succeeded" . format ( len ( oo0Oo0O ) , len ( packet ) , node ) )
   if 75 - 75: IiII
   O0OoOo00oo = 0
   oOO0000 = .001
   if 68 - 68: IiII - i1IIi % IiII . OoO0O00 . i11iIiiIii . OoooooooOO
  except socket . error , ooo0OO :
   if ( O0OoOo00oo == 12 ) :
    lprint ( "Giving up on {}, consider it down" . format ( node ) )
    break
    if 32 - 32: iII111i + OoO0O00 % IiII + I1IiiI
    if 69 - 69: I1Ii111 + I11i - iIii1I11I1II1 - II111iiii . Ii1I
   lprint ( "Send IPC {}-out-of-{} byte to {} failed: {}" . format ( len ( oo0Oo0O ) , len ( packet ) , node , ooo0OO ) )
   if 74 - 74: I1ii11iIi11i % o0oOOo0O0Ooo + O0 - i11iIiiIii - IiII % OOooOOo
   if 39 - 39: OoO0O00 - o0oOOo0O0Ooo
   O0OoOo00oo += 1
   time . sleep ( oOO0000 )
   if 71 - 71: iII111i . OoO0O00 + ooOoO0o - OOooOOo - Oo0Ooo
   lprint ( "Retrying after {} ms ..." . format ( oOO0000 * 1000 ) )
   oOO0000 *= 2
   continue
   if 100 - 100: OoooooooOO - o0oOOo0O0Ooo + I1Ii111 . OoooooooOO % i11iIiiIii
   if 64 - 64: I1Ii111 % OoooooooOO / i1IIi / OoO0O00
  I11iiIi1i1 += o0o000O0o0
  o00OOo00 -= o0o000O0o0
  if 2 - 2: I11i % o0oOOo0O0Ooo . OoO0O00 . OoO0O00
 return
 if 89 - 89: ooOoO0o - oO0o + II111iiii + OoO0O00 - IiII
 if 27 - 27: I1Ii111 - o0oOOo0O0Ooo + OoO0O00
 if 38 - 38: OoOoOO00 + OoO0O00 . i11iIiiIii + Ii1I % i1IIi % I1IiiI
 if 93 - 93: i11iIiiIii
 if 63 - 63: iIii1I11I1II1 - iIii1I11I1II1 % o0oOOo0O0Ooo
 if 97 - 97: i1IIi % I11i % OoOoOO00
 if 25 - 25: OoOoOO00 . iIii1I11I1II1 - iII111i % II111iiii . OoOoOO00
def lisp_format_packet ( packet ) :
 packet = binascii . hexlify ( packet )
 I11iiIi1i1 = 0
 iIiIII11 = ""
 o00OOo00 = len ( packet ) * 2
 while ( I11iiIi1i1 < o00OOo00 ) :
  iIiIII11 += packet [ I11iiIi1i1 : I11iiIi1i1 + 8 ] + " "
  I11iiIi1i1 += 8
  o00OOo00 -= 4
  if 16 - 16: OOooOOo . Oo0Ooo . I1IiiI % O0 . I1ii11iIi11i + i11iIiiIii
 return ( iIiIII11 )
 if 100 - 100: I1ii11iIi11i - i1IIi - OoO0O00 * o0oOOo0O0Ooo + OoOoOO00
 if 31 - 31: i1IIi
 if 21 - 21: o0oOOo0O0Ooo / O0 % O0 . OoooooooOO / I1IiiI
 if 94 - 94: ooOoO0o + OoO0O00 / ooOoO0o - ooOoO0o + Oo0Ooo + o0oOOo0O0Ooo
 if 50 - 50: oO0o . Oo0Ooo
 if 15 - 15: Ii1I
 if 64 - 64: OoooooooOO
def lisp_send ( lisp_sockets , dest , port , packet ) :
 iiI1I11iiIIi = lisp_sockets [ 0 ] if dest . is_ipv4 ( ) else lisp_sockets [ 1 ]
 if 27 - 27: OoooooooOO * IiII * O0 . i11iIiiIii + iIii1I11I1II1 - OoooooooOO
 if 58 - 58: Ii1I - oO0o + I1ii11iIi11i
 if 39 - 39: iIii1I11I1II1 . Oo0Ooo
 if 33 - 33: IiII % OoooooooOO / Ii1I . II111iiii
 if 56 - 56: Oo0Ooo - I11i
 if 25 - 25: I1IiiI + I1Ii111 . iII111i
 if 88 - 88: OoooooooOO . oO0o % I1Ii111 % oO0o % I1ii11iIi11i / i11iIiiIii
 if 9 - 9: Ii1I * IiII
 if 57 - 57: iII111i % oO0o % iII111i % OOooOOo + I1ii11iIi11i
 if 89 - 89: I1ii11iIi11i + II111iiii % i1IIi * O0 . Ii1I
 if 52 - 52: IiII
 if 86 - 86: I1Ii111 / O0 + OoooooooOO % oO0o
 oOoO0Oo0 = dest . print_address_no_iid ( )
 if ( oOoO0Oo0 . find ( "::ffff:" ) != - 1 and oOoO0Oo0 . count ( "." ) == 3 ) :
  if ( lisp_i_am_rtr ) : iiI1I11iiIIi = lisp_sockets [ 0 ]
  if ( iiI1I11iiIIi == None ) :
   iiI1I11iiIIi = lisp_sockets [ 0 ]
   oOoO0Oo0 = oOoO0Oo0 . split ( "::ffff:" ) [ - 1 ]
   if 45 - 45: I1IiiI . Oo0Ooo . I11i . Ii1I
   if 81 - 81: II111iiii + OoOoOO00 % i11iIiiIii / iII111i . I1Ii111 + II111iiii
   if 48 - 48: I1IiiI . I1ii11iIi11i * OoOoOO00 % i1IIi / I1Ii111 * II111iiii
 lprint ( "{} {} bytes {} {}, packet: {}" . format ( bold ( "Send" , False ) ,
 len ( packet ) , bold ( "to " + oOoO0Oo0 , False ) , port ,
 lisp_format_packet ( packet ) ) )
 if 62 - 62: o0oOOo0O0Ooo * I1Ii111 . iIii1I11I1II1 / i1IIi
 if 75 - 75: OoooooooOO / ooOoO0o - iII111i . OoooooooOO . OoOoOO00 % i1IIi
 if 7 - 7: OoOoOO00 . i1IIi * i11iIiiIii % i11iIiiIii
 if 54 - 54: OoO0O00 / I1IiiI . Oo0Ooo
 iIo0OOOOooo = ( LISP_RLOC_PROBE_TTL == 255 )
 if ( iIo0OOOOooo ) :
  Ii11II = struct . unpack ( "B" , packet [ 0 ] ) [ 0 ]
  iIo0OOOOooo = ( Ii11II in [ 0x12 , 0x28 ] )
  if ( iIo0OOOOooo ) : lisp_set_ttl ( iiI1I11iiIIi , LISP_RLOC_PROBE_TTL )
  if 76 - 76: Ii1I * OoOoOO00 / I1ii11iIi11i
  if 31 - 31: ooOoO0o / i11iIiiIii
 try : iiI1I11iiIIi . sendto ( packet , ( oOoO0Oo0 , port ) )
 except socket . error , ooo0OO :
  lprint ( "socket.sendto() failed: {}" . format ( ooo0OO ) )
  if 53 - 53: IiII
  if 45 - 45: iII111i % II111iiii * I1Ii111 . II111iiii
  if 30 - 30: I1IiiI % OoO0O00 - i1IIi / I1IiiI - OoO0O00 - I11i
  if 35 - 35: ooOoO0o / OOooOOo + I11i % I1Ii111 + Ii1I * I1IiiI
  if 70 - 70: oO0o / i1IIi * iIii1I11I1II1 + I11i
 if ( iIo0OOOOooo ) : lisp_set_ttl ( iiI1I11iiIIi , 64 )
 return
 if 48 - 48: ooOoO0o / I1ii11iIi11i / OoO0O00 / II111iiii * OoOoOO00
 if 73 - 73: I11i / I1IiiI - IiII - i1IIi * IiII - OOooOOo
 if 39 - 39: I11i . ooOoO0o * II111iiii
 if 21 - 21: Ii1I
 if 92 - 92: OoO0O00 * I1ii11iIi11i + iIii1I11I1II1
 if 88 - 88: iIii1I11I1II1 + iIii1I11I1II1 * i11iIiiIii . I1ii11iIi11i % oO0o
 if 94 - 94: I1IiiI / I1ii11iIi11i / OOooOOo
 if 45 - 45: II111iiii
def lisp_receive_segments ( lisp_socket , packet , source , total_length ) :
 if 98 - 98: i11iIiiIii + I1ii11iIi11i * OOooOOo / OoOoOO00
 if 84 - 84: o0oOOo0O0Ooo
 if 40 - 40: OoooooooOO - oO0o / O0 * I1Ii111 . O0 + i11iIiiIii
 if 9 - 9: OOooOOo % O0 % O0 / I1ii11iIi11i . II111iiii / II111iiii
 if 78 - 78: iIii1I11I1II1 - i1IIi . I11i . o0oOOo0O0Ooo
 o0o000O0o0 = total_length - len ( packet )
 if ( o0o000O0o0 == 0 ) : return ( [ True , packet ] )
 if 66 - 66: OOooOOo * Oo0Ooo
 lprint ( "Received {}-out-of-{} byte segment from {}" . format ( len ( packet ) ,
 total_length , source ) )
 if 58 - 58: OOooOOo
 if 96 - 96: IiII % OoooooooOO + O0 * II111iiii / OOooOOo . I1Ii111
 if 47 - 47: OoO0O00 - Oo0Ooo * OoO0O00 / oO0o
 if 13 - 13: ooOoO0o
 if 55 - 55: i1IIi . I11i . II111iiii + O0 + ooOoO0o - i1IIi
 o00OOo00 = o0o000O0o0
 while ( o00OOo00 > 0 ) :
  try : oo0Oo0O = lisp_socket . recvfrom ( 9000 )
  except : return ( [ False , None ] )
  if 3 - 3: iIii1I11I1II1 / oO0o
  oo0Oo0O = oo0Oo0O [ 0 ]
  if 61 - 61: I1Ii111 / O0 - iII111i
  if 44 - 44: i1IIi
  if 23 - 23: I1ii11iIi11i . OoooooooOO / Ii1I + o0oOOo0O0Ooo
  if 89 - 89: OoOoOO00 + Oo0Ooo . OoOoOO00 - II111iiii
  if 85 - 85: OoooooooOO * OoooooooOO / Ii1I - II111iiii
  if ( oo0Oo0O . find ( "packet@" ) == 0 ) :
   o00O0OO00o0oo = oo0Oo0O . split ( "@" )
   lprint ( "Received new message ({}-out-of-{}) while receiving " + "fragments, old message discarded" , len ( oo0Oo0O ) ,
   # o0oOOo0O0Ooo - I1IiiI
 o00O0OO00o0oo [ 1 ] if len ( o00O0OO00o0oo ) > 2 else "?" )
   return ( [ False , oo0Oo0O ] )
   if 50 - 50: I1IiiI
   if 71 - 71: OOooOOo - I1Ii111 % OoooooooOO % OoOoOO00
  o00OOo00 -= len ( oo0Oo0O )
  packet += oo0Oo0O
  if 48 - 48: Oo0Ooo / OoooooooOO . II111iiii % Oo0Ooo
  lprint ( "Received {}-out-of-{} byte segment from {}" . format ( len ( oo0Oo0O ) , total_length , source ) )
  if 24 - 24: IiII + ooOoO0o
  if 40 - 40: iIii1I11I1II1
 return ( [ True , packet ] )
 if 33 - 33: i11iIiiIii - oO0o
 if 35 - 35: OoOoOO00 - I11i % Ii1I * OoooooooOO
 if 84 - 84: I1IiiI * I1ii11iIi11i + iIii1I11I1II1 - II111iiii % O0 . OOooOOo
 if 99 - 99: i1IIi + iIii1I11I1II1 - ooOoO0o + OoO0O00 + Oo0Ooo . I1ii11iIi11i
 if 74 - 74: i1IIi
 if 80 - 80: ooOoO0o + I1Ii111 . I1ii11iIi11i % OoooooooOO
 if 26 - 26: OoOoOO00 . iII111i * iIii1I11I1II1 / IiII
 if 69 - 69: OoooooooOO / I11i + Ii1I * II111iiii
def lisp_bit_stuff ( payload ) :
 lprint ( "Bit-stuffing, found {} segments" . format ( len ( payload ) ) )
 i1II1IiiIi = ""
 for oo0Oo0O in payload : i1II1IiiIi += oo0Oo0O + "\x40"
 return ( i1II1IiiIi [ : - 1 ] )
 if 35 - 35: i11iIiiIii + oO0o
 if 85 - 85: OoOoOO00 . O0 % OoooooooOO % oO0o
 if 43 - 43: I1IiiI - I11i . I1IiiI / i11iIiiIii % IiII * i11iIiiIii
 if 12 - 12: II111iiii - iIii1I11I1II1
 if 43 - 43: i11iIiiIii % OoO0O00
 if 100 - 100: i1IIi
 if 4 - 4: i11iIiiIii - OOooOOo * IiII % OoooooooOO - OoOoOO00
 if 81 - 81: Ii1I * ooOoO0o . oO0o . IiII
 if 71 - 71: IiII + OoO0O00
 if 39 - 39: I1IiiI % IiII / II111iiii / II111iiii
 if 95 - 95: II111iiii + i11iIiiIii + o0oOOo0O0Ooo
 if 30 - 30: O0 - O0 % iIii1I11I1II1 + iII111i * OoooooooOO
 if 1 - 1: O0
 if 36 - 36: oO0o . iII111i
 if 62 - 62: I11i + iIii1I11I1II1 % I11i * OOooOOo + iIii1I11I1II1 % Ii1I
 if 56 - 56: o0oOOo0O0Ooo
 if 55 - 55: oO0o - I1Ii111 / ooOoO0o % I1IiiI * OoooooooOO * I1IiiI
 if 88 - 88: Ii1I + O0
 if 92 - 92: I1IiiI % iII111i % I11i + OoooooooOO - i11iIiiIii
 if 9 - 9: i11iIiiIii - II111iiii / ooOoO0o
def lisp_receive ( lisp_socket , internal ) :
 while ( True ) :
  if 81 - 81: i11iIiiIii % OoOoOO00 % OoO0O00 * Ii1I
  if 85 - 85: OoooooooOO * ooOoO0o
  if 23 - 23: OOooOOo / I11i / OoooooooOO - Ii1I / OoO0O00 - OoO0O00
  if 60 - 60: OOooOOo . ooOoO0o % i1IIi % Ii1I % ooOoO0o + OoO0O00
  try : IiII111I1i = lisp_socket . recvfrom ( 9000 )
  except : return ( [ "" , "" , "" , "" ] )
  if 76 - 76: ooOoO0o - Ii1I / I11i / Oo0Ooo - o0oOOo0O0Ooo . II111iiii
  if 44 - 44: o0oOOo0O0Ooo . o0oOOo0O0Ooo - i1IIi - I1Ii111 % II111iiii
  if 91 - 91: I11i % Ii1I - IiII + iIii1I11I1II1 * iIii1I11I1II1
  if 91 - 91: i11iIiiIii + Ii1I
  if 85 - 85: I11i % IiII
  if 68 - 68: Oo0Ooo . I1Ii111 - o0oOOo0O0Ooo * iIii1I11I1II1 - II111iiii % i1IIi
  if ( internal == False ) :
   i1II1IiiIi = IiII111I1i [ 0 ]
   O0Oo00o0o = lisp_convert_6to4 ( IiII111I1i [ 1 ] [ 0 ] )
   o00o = IiII111I1i [ 1 ] [ 1 ]
   if 1 - 1: oO0o - ooOoO0o
   if ( o00o == LISP_DATA_PORT ) :
    OooO0O0oo = lisp_data_plane_logging
    o00oO0oo = lisp_format_packet ( i1II1IiiIi [ 0 : 60 ] ) + " ..."
   else :
    OooO0O0oo = True
    o00oO0oo = lisp_format_packet ( i1II1IiiIi )
    if 77 - 77: iIii1I11I1II1 * I1Ii111 + i1IIi % I1Ii111 - i1IIi
    if 62 - 62: I11i - I1ii11iIi11i
   if ( OooO0O0oo ) :
    lprint ( "{} {} bytes {} {}, packet: {}" . format ( bold ( "Receive" ,
 False ) , len ( i1II1IiiIi ) , bold ( "from " + O0Oo00o0o , False ) , o00o ,
 o00oO0oo ) )
    if 6 - 6: I1ii11iIi11i % o0oOOo0O0Ooo + o0oOOo0O0Ooo / OOooOOo / I1IiiI
   return ( [ "packet" , O0Oo00o0o , o00o , i1II1IiiIi ] )
   if 67 - 67: OoOoOO00 . iII111i / OOooOOo * ooOoO0o + i1IIi
   if 100 - 100: OOooOOo . ooOoO0o + I1Ii111 . oO0o
   if 20 - 20: i11iIiiIii - i1IIi - iIii1I11I1II1 - OoooooooOO
   if 72 - 72: I1Ii111 . OoO0O00
   if 59 - 59: I1IiiI * I11i % i1IIi
   if 77 - 77: OOooOOo * OoooooooOO + I1IiiI + I1IiiI % oO0o . OoooooooOO
  oooiiiiII11i1i = False
  i11iII1IiI = IiII111I1i [ 0 ]
  iIII11iiIiIiI = False
  if 48 - 48: iII111i % OoO0O00 / I1Ii111 + iIii1I11I1II1 / ooOoO0o
  while ( oooiiiiII11i1i == False ) :
   i11iII1IiI = i11iII1IiI . split ( "@" )
   if 65 - 65: Oo0Ooo - OoO0O00 / i1IIi % i11iIiiIii
   if ( len ( i11iII1IiI ) < 4 ) :
    lprint ( "Possible fragment (length {}), from old message, " + "discarding" , len ( i11iII1IiI [ 0 ] ) )
    if 26 - 26: I1IiiI % iIii1I11I1II1 / OoO0O00
    iIII11iiIiIiI = True
    break
    if 71 - 71: OoOoOO00 + iII111i - I1IiiI
    if 80 - 80: OoO0O00 . ooOoO0o
   O0oO0 = i11iII1IiI [ 0 ]
   try :
    oO0o00 = int ( i11iII1IiI [ 1 ] )
   except :
    ooOOOoo0oO = bold ( "Internal packet reassembly error" , False )
    lprint ( "{}: {}" . format ( ooOOOoo0oO , IiII111I1i ) )
    iIII11iiIiIiI = True
    break
    if 92 - 92: I11i
   O0Oo00o0o = i11iII1IiI [ 2 ]
   o00o = i11iII1IiI [ 3 ]
   if 96 - 96: O0 / i1IIi - i11iIiiIii / OoOoOO00 + OoooooooOO
   if 12 - 12: oO0o . OOooOOo
   if 76 - 76: oO0o - I11i * I1Ii111 . oO0o % iIii1I11I1II1
   if 86 - 86: OoooooooOO + I1Ii111
   if 5 - 5: I1ii11iIi11i
   if 89 - 89: OoO0O00 - OoOoOO00 / II111iiii . I1ii11iIi11i
   if 50 - 50: Ii1I * I1Ii111 * OoooooooOO . OoooooooOO
   if 67 - 67: i11iIiiIii % ooOoO0o . I1ii11iIi11i + II111iiii . OoO0O00
   if ( len ( i11iII1IiI ) > 5 ) :
    i1II1IiiIi = lisp_bit_stuff ( i11iII1IiI [ 4 : : ] )
   else :
    i1II1IiiIi = i11iII1IiI [ 4 ]
    if 42 - 42: I11i / OoO0O00 / OoO0O00 * OOooOOo
    if 2 - 2: II111iiii % oO0o . I1Ii111
    if 100 - 100: OoOoOO00 + OoOoOO00
    if 26 - 26: II111iiii * iII111i + OOooOOo
    if 28 - 28: Ii1I + O0
    if 44 - 44: oO0o
   oooiiiiII11i1i , i1II1IiiIi = lisp_receive_segments ( lisp_socket , i1II1IiiIi ,
 O0Oo00o0o , oO0o00 )
   if ( i1II1IiiIi == None ) : return ( [ "" , "" , "" , "" ] )
   if 51 - 51: o0oOOo0O0Ooo * o0oOOo0O0Ooo . Ii1I
   if 14 - 14: OoO0O00 . I11i % II111iiii % i11iIiiIii + OoooooooOO
   if 50 - 50: i11iIiiIii * I11i + i11iIiiIii - i1IIi
   if 69 - 69: I1IiiI + IiII + oO0o * I1ii11iIi11i . iIii1I11I1II1 / OoooooooOO
   if 77 - 77: Oo0Ooo - ooOoO0o
   if ( oooiiiiII11i1i == False ) :
    i11iII1IiI = i1II1IiiIi
    continue
    if 68 - 68: Ii1I * O0
    if 61 - 61: II111iiii - OoO0O00 . iIii1I11I1II1 * o0oOOo0O0Ooo . OoO0O00 % IiII
   if ( o00o == "" ) : o00o = "no-port"
   if ( O0oO0 == "command" and lisp_i_am_core == False ) :
    iI11I = i1II1IiiIi . find ( " {" )
    iI1i1ii = i1II1IiiIi if iI11I == - 1 else i1II1IiiIi [ : iI11I ]
    iI1i1ii = ": '" + iI1i1ii + "'"
   else :
    iI1i1ii = ""
    if 43 - 43: OoO0O00 + OOooOOo + II111iiii - O0
    if 6 - 6: I1Ii111 . i11iIiiIii - O0 % I1ii11iIi11i . I11i + i11iIiiIii
   lprint ( "{} {} bytes {} {}, {}{}" . format ( bold ( "Receive" , False ) ,
 len ( i1II1IiiIi ) , bold ( "from " + O0Oo00o0o , False ) , o00o , O0oO0 ,
 iI1i1ii if ( O0oO0 in [ "command" , "api" ] ) else ": ... " if ( O0oO0 == "data-packet" ) else ": " + lisp_format_packet ( i1II1IiiIi ) ) )
   if 5 - 5: OoOoOO00 / I1Ii111 % i1IIi
   if 69 - 69: ooOoO0o . OoooooooOO
   if 91 - 91: Ii1I * oO0o + OOooOOo
   if 66 - 66: i1IIi + I1IiiI - ooOoO0o * II111iiii % I1IiiI % Oo0Ooo
   if 68 - 68: OOooOOo % II111iiii . iIii1I11I1II1 + Ii1I
  if ( iIII11iiIiIiI ) : continue
  return ( [ O0oO0 , O0Oo00o0o , o00o , i1II1IiiIi ] )
  if 22 - 22: Ii1I * IiII
  if 10 - 10: OoOoOO00 / oO0o % OoO0O00 / Ii1I + Ii1I % OOooOOo
  if 45 - 45: I1Ii111 % i11iIiiIii % I1IiiI - Ii1I
  if 81 - 81: i11iIiiIii - II111iiii + I11i
  if 52 - 52: II111iiii
  if 62 - 62: iII111i / OoO0O00 + i11iIiiIii / Oo0Ooo
  if 26 - 26: I1ii11iIi11i - OoO0O00
  if 19 - 19: iIii1I11I1II1 / I1ii11iIi11i + O0
def lisp_parse_packet ( lisp_sockets , packet , source , udp_sport , ttl = - 1 ) :
 I1II = False
 if 42 - 42: I1ii11iIi11i - I1IiiI * i1IIi
 I1I = lisp_control_header ( )
 if ( I1I . decode ( packet ) == None ) :
  lprint ( "Could not decode control header" )
  return ( I1II )
  if 17 - 17: OoO0O00 % o0oOOo0O0Ooo
  if 21 - 21: OOooOOo + OOooOOo - i11iIiiIii * IiII % iIii1I11I1II1
  if 86 - 86: ooOoO0o + OoOoOO00
  if 94 - 94: IiII
  if 30 - 30: o0oOOo0O0Ooo % OoOoOO00 * IiII % iIii1I11I1II1 % O0
 oo0oooooOo000 = source
 if ( source . find ( "lisp" ) == - 1 ) :
  IiIIi1I1I11Ii = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  IiIIi1I1I11Ii . string_to_afi ( source )
  IiIIi1I1I11Ii . store_address ( source )
  source = IiIIi1I1I11Ii
  if 99 - 99: OoO0O00 . OoOoOO00 + iII111i - iIii1I11I1II1 + OoooooooOO % OoO0O00
  if 95 - 95: o0oOOo0O0Ooo * I1ii11iIi11i - o0oOOo0O0Ooo
 if ( I1I . type == LISP_MAP_REQUEST ) :
  lisp_process_map_request ( lisp_sockets , packet , None , 0 , source ,
 udp_sport , False , ttl )
  if 47 - 47: I1IiiI / OoOoOO00 / II111iiii
 elif ( I1I . type == LISP_MAP_REPLY ) :
  lisp_process_map_reply ( lisp_sockets , packet , source , ttl )
  if 7 - 7: oO0o . ooOoO0o
 elif ( I1I . type == LISP_MAP_REGISTER ) :
  lisp_process_map_register ( lisp_sockets , packet , source , udp_sport )
  if 73 - 73: i1IIi % I1Ii111 * ooOoO0o % OoO0O00
 elif ( I1I . type == LISP_MAP_NOTIFY ) :
  if ( oo0oooooOo000 == "lisp-etr" ) :
   lisp_process_multicast_map_notify ( packet , source )
  else :
   if ( lisp_is_running ( "lisp-rtr" ) ) :
    lisp_process_multicast_map_notify ( packet , source )
    if 70 - 70: ooOoO0o * I1ii11iIi11i
   lisp_process_map_notify ( lisp_sockets , packet , source )
   if 26 - 26: i11iIiiIii - II111iiii . II111iiii * oO0o / Ii1I + I1IiiI
   if 12 - 12: OoO0O00 * iIii1I11I1II1 % I1Ii111 . O0 * OoOoOO00 * OOooOOo
 elif ( I1I . type == LISP_MAP_NOTIFY_ACK ) :
  lisp_process_map_notify_ack ( packet , source )
  if 34 - 34: I1IiiI . i1IIi
 elif ( I1I . type == LISP_MAP_REFERRAL ) :
  lisp_process_map_referral ( lisp_sockets , packet , source )
  if 38 - 38: iIii1I11I1II1
 elif ( I1I . type == LISP_NAT_INFO and I1I . is_info_reply ( ) ) :
  I1I111 , iI11Ii , I1II = lisp_process_info_reply ( source , packet , True )
  if 64 - 64: i1IIi / OoO0O00
 elif ( I1I . type == LISP_NAT_INFO and I1I . is_info_reply ( ) == False ) :
  I1iiIiiii1111 = source . print_address_no_iid ( )
  lisp_process_info_request ( lisp_sockets , packet , I1iiIiiii1111 , udp_sport ,
 None )
  if 68 - 68: I11i * O0 * oO0o + OoOoOO00 / IiII
 elif ( I1I . type == LISP_ECM ) :
  lisp_process_ecm ( lisp_sockets , packet , source , udp_sport )
  if 42 - 42: iIii1I11I1II1 % i1IIi - OoOoOO00 % I1ii11iIi11i * Ii1I + i11iIiiIii
 else :
  lprint ( "Invalid LISP control packet type {}" . format ( I1I . type ) )
  if 40 - 40: OOooOOo
 return ( I1II )
 if 30 - 30: o0oOOo0O0Ooo - Oo0Ooo + iII111i / O0
 if 94 - 94: IiII
 if 69 - 69: I1Ii111 . I1Ii111
 if 53 - 53: i11iIiiIii + iII111i * Oo0Ooo - I1Ii111
 if 61 - 61: o0oOOo0O0Ooo / OOooOOo . II111iiii - I1IiiI * i11iIiiIii
 if 8 - 8: iII111i % o0oOOo0O0Ooo
 if 87 - 87: Ii1I % I11i / I1Ii111
def lisp_process_rloc_probe_request ( lisp_sockets , map_request , source , port ,
 ttl ) :
 if 21 - 21: OoO0O00 + Ii1I / I1Ii111
 i111 = bold ( "RLOC-probe" , False )
 if 75 - 75: I1Ii111 . Ii1I % iIii1I11I1II1 / OoOoOO00
 if ( lisp_i_am_etr ) :
  lprint ( "Received {} Map-Request, send RLOC-probe Map-Reply" . format ( i111 ) )
  lisp_etr_process_map_request ( lisp_sockets , map_request , source , port ,
 ttl )
  return
  if 38 - 38: i1IIi
  if 1 - 1: I1ii11iIi11i + OoO0O00 % I11i . OOooOOo + i1IIi / oO0o
 if ( lisp_i_am_rtr ) :
  lprint ( "Received {} Map-Request, send RLOC-probe Map-Reply" . format ( i111 ) )
  lisp_rtr_process_map_request ( lisp_sockets , map_request , source , port ,
 ttl )
  return
  if 35 - 35: ooOoO0o % OoOoOO00 % OoO0O00 + OOooOOo / IiII * OoOoOO00
  if 65 - 65: I1IiiI . Oo0Ooo + i1IIi - Ii1I * i1IIi
 lprint ( "Ignoring received {} Map-Request, not an ETR or RTR" . format ( i111 ) )
 return
 if 64 - 64: I1IiiI / OoO0O00 * I1IiiI * II111iiii . Ii1I
 if 98 - 98: I1Ii111 + o0oOOo0O0Ooo
 if 73 - 73: I1ii11iIi11i / I1Ii111 + i11iIiiIii + OoO0O00 . ooOoO0o
 if 54 - 54: I1ii11iIi11i + IiII - oO0o + Oo0Ooo / IiII % Oo0Ooo
 if 2 - 2: OOooOOo / I11i * I11i + I11i / O0 - OOooOOo
def lisp_process_smr ( map_request ) :
 lprint ( "Received SMR-based Map-Request" )
 return
 if 29 - 29: OoOoOO00 + i11iIiiIii % OoO0O00 - OoooooooOO
 if 68 - 68: iII111i / OOooOOo
 if 28 - 28: II111iiii
 if 49 - 49: I1ii11iIi11i
 if 33 - 33: iIii1I11I1II1
def lisp_process_smr_invoked_request ( map_request ) :
 lprint ( "Received SMR-invoked Map-Request" )
 return
 if 72 - 72: I1ii11iIi11i * i11iIiiIii
 if 12 - 12: O0 - iIii1I11I1II1 % Oo0Ooo / O0 - IiII
 if 55 - 55: OOooOOo . Oo0Ooo * OoOoOO00 / OoooooooOO * i11iIiiIii + oO0o
 if 45 - 45: Ii1I
 if 8 - 8: oO0o + OOooOOo
 if 37 - 37: IiII - OoOoOO00 + oO0o - Oo0Ooo + IiII
 if 33 - 33: Oo0Ooo % oO0o - I1IiiI + Oo0Ooo
def lisp_build_map_reply ( eid , group , rloc_set , nonce , action , ttl , rloc_probe ,
 keys , enc , auth , mr_ttl = - 1 ) :
 OOO00o00o000 = lisp_map_reply ( )
 OOO00o00o000 . rloc_probe = rloc_probe
 OOO00o00o000 . echo_nonce_capable = enc
 OOO00o00o000 . hop_count = 0 if ( mr_ttl == - 1 ) else mr_ttl
 OOO00o00o000 . record_count = 1
 OOO00o00o000 . nonce = nonce
 i1II1IiiIi = OOO00o00o000 . encode ( )
 OOO00o00o000 . print_map_reply ( )
 if 78 - 78: Ii1I - OOooOOo . O0 . oO0o
 iI1iii1IIIIi = lisp_eid_record ( )
 iI1iii1IIIIi . rloc_count = len ( rloc_set )
 iI1iii1IIIIi . authoritative = auth
 iI1iii1IIIIi . record_ttl = ttl
 iI1iii1IIIIi . action = action
 iI1iii1IIIIi . eid = eid
 iI1iii1IIIIi . group = group
 if 21 - 21: iIii1I11I1II1 % OoooooooOO * OOooOOo % i1IIi
 i1II1IiiIi += iI1iii1IIIIi . encode ( )
 iI1iii1IIIIi . print_record ( "  " , False )
 if 73 - 73: OoooooooOO
 O0oo0 = lisp_get_all_addresses ( ) + lisp_get_all_translated_rlocs ( )
 if 24 - 24: i11iIiiIii % OoooooooOO / iII111i % I1Ii111
 for IIiO0Ooo in rloc_set :
  oooO0oo00oOOoo0O = lisp_rloc_record ( )
  I1iiIiiii1111 = IIiO0Ooo . rloc . print_address_no_iid ( )
  if ( I1iiIiiii1111 in O0oo0 ) :
   oooO0oo00oOOoo0O . local_bit = True
   oooO0oo00oOOoo0O . probe_bit = rloc_probe
   oooO0oo00oOOoo0O . keys = keys
   if ( IIiO0Ooo . priority == 254 and lisp_i_am_rtr ) :
    oooO0oo00oOOoo0O . rloc_name = "RTR"
    if 70 - 70: OoO0O00 + i1IIi / iIii1I11I1II1 % i11iIiiIii . O0 . OOooOOo
    if 21 - 21: i1IIi
  oooO0oo00oOOoo0O . store_rloc_entry ( IIiO0Ooo )
  oooO0oo00oOOoo0O . reach_bit = True
  oooO0oo00oOOoo0O . print_record ( "    " )
  i1II1IiiIi += oooO0oo00oOOoo0O . encode ( )
  if 10 - 10: i11iIiiIii / ooOoO0o - o0oOOo0O0Ooo . o0oOOo0O0Ooo
 return ( i1II1IiiIi )
 if 8 - 8: iII111i + iIii1I11I1II1 . I1ii11iIi11i
 if 68 - 68: OoooooooOO . OoooooooOO % I1ii11iIi11i + i1IIi % OoooooooOO + Ii1I
 if 89 - 89: ooOoO0o + I11i * O0 % OoOoOO00
 if 2 - 2: I1Ii111 % iIii1I11I1II1 . Ii1I - II111iiii
 if 33 - 33: I11i . i11iIiiIii % i1IIi * II111iiii * i11iIiiIii + OoOoOO00
 if 26 - 26: I1IiiI % OoOoOO00 % I11i + Oo0Ooo
 if 86 - 86: iII111i / i1IIi % Oo0Ooo
def lisp_build_map_referral ( eid , group , ddt_entry , action , ttl , nonce ) :
 OOoO000o00000 = lisp_map_referral ( )
 OOoO000o00000 . record_count = 1
 OOoO000o00000 . nonce = nonce
 i1II1IiiIi = OOoO000o00000 . encode ( )
 OOoO000o00000 . print_map_referral ( )
 if 76 - 76: Ii1I + Oo0Ooo . i11iIiiIii + I1ii11iIi11i
 iI1iii1IIIIi = lisp_eid_record ( )
 if 29 - 29: ooOoO0o * oO0o + iIii1I11I1II1 * i1IIi % i11iIiiIii + iIii1I11I1II1
 OoIiIii = 0
 if ( ddt_entry == None ) :
  iI1iii1IIIIi . eid = eid
  iI1iii1IIIIi . group = group
 else :
  OoIiIii = len ( ddt_entry . delegation_set )
  iI1iii1IIIIi . eid = ddt_entry . eid
  iI1iii1IIIIi . group = ddt_entry . group
  ddt_entry . map_referrals_sent += 1
  if 22 - 22: Ii1I
 iI1iii1IIIIi . rloc_count = OoIiIii
 iI1iii1IIIIi . authoritative = True
 if 34 - 34: II111iiii + OOooOOo % oO0o - OOooOOo
 if 25 - 25: iII111i % iIii1I11I1II1 + IiII
 if 33 - 33: OOooOOo % I1IiiI - I1IiiI / IiII
 if 22 - 22: ooOoO0o * ooOoO0o % o0oOOo0O0Ooo * Ii1I . OoO0O00
 if 55 - 55: OoOoOO00 - I1ii11iIi11i + iIii1I11I1II1 - i11iIiiIii / i1IIi / II111iiii
 iiI1I1IIi = False
 if ( action == LISP_DDT_ACTION_NULL ) :
  if ( OoIiIii == 0 ) :
   action = LISP_DDT_ACTION_NODE_REFERRAL
  else :
   O0O0Oo0o = ddt_entry . delegation_set [ 0 ]
   if ( O0O0Oo0o . is_ddt_child ( ) ) :
    action = LISP_DDT_ACTION_NODE_REFERRAL
    if 37 - 37: Ii1I + o0oOOo0O0Ooo
   if ( O0O0Oo0o . is_ms_child ( ) ) :
    action = LISP_DDT_ACTION_MS_REFERRAL
    if 74 - 74: Oo0Ooo / O0 + i1IIi . I1IiiI + OoO0O00 / Oo0Ooo
    if 13 - 13: o0oOOo0O0Ooo / Ii1I . II111iiii
    if 8 - 8: I11i - I11i % IiII
    if 8 - 8: I1IiiI . IiII * O0 * o0oOOo0O0Ooo
    if 17 - 17: I1IiiI . oO0o + Oo0Ooo + I11i / o0oOOo0O0Ooo
    if 25 - 25: iII111i / iII111i % OoOoOO00 / ooOoO0o
    if 81 - 81: OOooOOo * oO0o
 if ( action == LISP_DDT_ACTION_NOT_AUTH ) : iiI1I1IIi = True
 if ( action in ( LISP_DDT_ACTION_MS_REFERRAL , LISP_DDT_ACTION_MS_ACK ) ) :
  iiI1I1IIi = ( lisp_i_am_ms and O0O0Oo0o . is_ms_peer ( ) == False )
  if 32 - 32: Oo0Ooo * OoO0O00 + ooOoO0o . O0 * oO0o * iIii1I11I1II1
  if 50 - 50: i1IIi
 iI1iii1IIIIi . action = action
 iI1iii1IIIIi . ddt_incomplete = iiI1I1IIi
 iI1iii1IIIIi . record_ttl = ttl
 if 53 - 53: II111iiii + O0 . ooOoO0o * IiII + i1IIi
 i1II1IiiIi += iI1iii1IIIIi . encode ( )
 iI1iii1IIIIi . print_record ( "  " , True )
 if 80 - 80: Ii1I + O0
 if ( OoIiIii == 0 ) : return ( i1II1IiiIi )
 if 59 - 59: i11iIiiIii - OoooooooOO % I11i . OoO0O00 - Oo0Ooo * o0oOOo0O0Ooo
 for O0O0Oo0o in ddt_entry . delegation_set :
  oooO0oo00oOOoo0O = lisp_rloc_record ( )
  oooO0oo00oOOoo0O . rloc = O0O0Oo0o . delegate_address
  oooO0oo00oOOoo0O . priority = O0O0Oo0o . priority
  oooO0oo00oOOoo0O . weight = O0O0Oo0o . weight
  oooO0oo00oOOoo0O . mpriority = 255
  oooO0oo00oOOoo0O . mweight = 0
  oooO0oo00oOOoo0O . reach_bit = True
  i1II1IiiIi += oooO0oo00oOOoo0O . encode ( )
  oooO0oo00oOOoo0O . print_record ( "    " )
  if 7 - 7: II111iiii % Ii1I * i11iIiiIii
 return ( i1II1IiiIi )
 if 28 - 28: II111iiii / ooOoO0o * i11iIiiIii % OOooOOo
 if 18 - 18: I11i - IiII - iIii1I11I1II1
 if 82 - 82: II111iiii + OoO0O00 % iIii1I11I1II1 / O0
 if 75 - 75: OOooOOo * OoO0O00 + OoooooooOO + i11iIiiIii . OoO0O00
 if 94 - 94: I11i * ooOoO0o . I1IiiI / Ii1I - I1IiiI % OoooooooOO
 if 32 - 32: OoO0O00
 if 22 - 22: II111iiii . I11i
def lisp_etr_process_map_request ( lisp_sockets , map_request , source , sport ,
 ttl ) :
 if 61 - 61: OOooOOo % O0 . I1ii11iIi11i . iIii1I11I1II1 * I11i
 if ( map_request . target_group . is_null ( ) ) :
  I11i111 = lisp_db_for_lookups . lookup_cache ( map_request . target_eid , False )
 else :
  I11i111 = lisp_db_for_lookups . lookup_cache ( map_request . target_group , False )
  if ( I11i111 ) : I11i111 = I11i111 . lookup_source_cache ( map_request . target_eid , False )
  if 94 - 94: OOooOOo / IiII
 oOoo0OooOOo00 = map_request . print_prefix ( )
 if 18 - 18: IiII - I11i / Ii1I % IiII * i1IIi
 if ( I11i111 == None ) :
  lprint ( "Database-mapping entry not found for requested EID {}" . format ( green ( oOoo0OooOOo00 , False ) ) )
  if 22 - 22: OoOoOO00 - Oo0Ooo
  return
  if 41 - 41: iIii1I11I1II1 * I1Ii111 / OoO0O00
  if 33 - 33: I11i + O0
 I11 = I11i111 . print_eid_tuple ( )
 if 84 - 84: ooOoO0o * o0oOOo0O0Ooo % O0 - i11iIiiIii % iIii1I11I1II1 % ooOoO0o
 lprint ( "Found database-mapping EID-prefix {} for requested EID {}" . format ( green ( I11 , False ) , green ( oOoo0OooOOo00 , False ) ) )
 if 12 - 12: II111iiii + I11i
 if 9 - 9: I1ii11iIi11i
 if 51 - 51: I1ii11iIi11i
 if 37 - 37: I1IiiI % I1Ii111
 if 22 - 22: o0oOOo0O0Ooo % OOooOOo - I11i + ooOoO0o / OOooOOo
 O0OoO0OOo0o0 = map_request . itr_rlocs [ 0 ]
 if ( O0OoO0OOo0o0 . is_private_address ( ) and lisp_nat_traversal ) :
  O0OoO0OOo0o0 = source
  if 73 - 73: ooOoO0o . OoO0O00 % I1ii11iIi11i - oO0o
  if 67 - 67: o0oOOo0O0Ooo . I11i + i1IIi
 iI1III = map_request . nonce
 OOoo00oo0 = lisp_nonce_echoing
 o00OO0o0 = map_request . keys
 if 83 - 83: OoOoOO00 * iII111i
 I11i111 . map_replies_sent += 1
 if 75 - 75: i11iIiiIii . o0oOOo0O0Ooo / oO0o . OoO0O00 % Ii1I % Ii1I
 i1II1IiiIi = lisp_build_map_reply ( I11i111 . eid , I11i111 . group , I11i111 . rloc_set , iI1III ,
 LISP_NO_ACTION , 1440 , map_request . rloc_probe , o00OO0o0 , OOoo00oo0 , True , ttl )
 if 94 - 94: iII111i . Ii1I
 if 71 - 71: o0oOOo0O0Ooo * II111iiii / OOooOOo . OoO0O00
 if 73 - 73: I1Ii111 * OoO0O00 / OoOoOO00 . II111iiii
 if 87 - 87: OoO0O00 + Oo0Ooo + O0 % OoooooooOO - iIii1I11I1II1
 if 100 - 100: Oo0Ooo + IiII
 if 81 - 81: iIii1I11I1II1 + iIii1I11I1II1
 if 19 - 19: ooOoO0o + i1IIi / Oo0Ooo * II111iiii * I1Ii111 / ooOoO0o
 if 23 - 23: I1Ii111
 if 76 - 76: Ii1I + Ii1I / i1IIi % o0oOOo0O0Ooo . iIii1I11I1II1 . OoOoOO00
 if 75 - 75: I11i . Ii1I / I1ii11iIi11i
 if 99 - 99: Ii1I
 if 85 - 85: I1Ii111 + I1Ii111 + OoOoOO00 / ooOoO0o / o0oOOo0O0Ooo . Oo0Ooo
 if 41 - 41: i1IIi % Ii1I . i1IIi * OoooooooOO % Ii1I
 if 21 - 21: iII111i
 if 72 - 72: I11i % o0oOOo0O0Ooo . iIii1I11I1II1 - I1Ii111 / i11iIiiIii
 if 75 - 75: OoooooooOO
 if ( map_request . rloc_probe and len ( lisp_sockets ) == 4 ) :
  IIIi1ii1i1 = ( O0OoO0OOo0o0 . is_private_address ( ) == False )
  iI11I1I = O0OoO0OOo0o0 . print_address_no_iid ( )
  if ( ( IIIi1ii1i1 and lisp_rtr_list . has_key ( iI11I1I ) ) or sport == 0 ) :
   lisp_encapsulate_rloc_probe ( lisp_sockets , O0OoO0OOo0o0 , None , i1II1IiiIi )
   return
   if 24 - 24: oO0o % iII111i - II111iiii / Ii1I + O0
   if 37 - 37: I1Ii111 - i1IIi / iIii1I11I1II1
   if 53 - 53: Ii1I - iIii1I11I1II1 % I1ii11iIi11i * i11iIiiIii + ooOoO0o
   if 63 - 63: Oo0Ooo * I1IiiI
   if 84 - 84: Oo0Ooo
   if 67 - 67: oO0o / II111iiii . I11i / oO0o
 lisp_send_map_reply ( lisp_sockets , i1II1IiiIi , O0OoO0OOo0o0 , sport )
 return
 if 46 - 46: oO0o * Oo0Ooo - I11i / iIii1I11I1II1
 if 100 - 100: i11iIiiIii % oO0o
 if 62 - 62: OOooOOo * i1IIi - OOooOOo / i11iIiiIii
 if 17 - 17: I1ii11iIi11i + ooOoO0o % Ii1I % OOooOOo
 if 73 - 73: i11iIiiIii
 if 44 - 44: o0oOOo0O0Ooo % Ii1I - OoOoOO00 + OoOoOO00 * IiII + iII111i
 if 58 - 58: I1ii11iIi11i / oO0o + i11iIiiIii * o0oOOo0O0Ooo
def lisp_rtr_process_map_request ( lisp_sockets , map_request , source , sport ,
 ttl ) :
 if 19 - 19: OoOoOO00
 if 17 - 17: Oo0Ooo
 if 76 - 76: II111iiii % I1ii11iIi11i
 if 99 - 99: oO0o - I1Ii111
 O0OoO0OOo0o0 = map_request . itr_rlocs [ 0 ]
 if ( O0OoO0OOo0o0 . is_private_address ( ) ) : O0OoO0OOo0o0 = source
 iI1III = map_request . nonce
 if 29 - 29: I1IiiI - I11i
 o00oo00oo = map_request . target_eid
 ii1I1 = map_request . target_group
 if 42 - 42: Oo0Ooo - O0 . OoOoOO00
 iii1Ii1i1i1I = [ ]
 for Ii1iIii1II1 in [ lisp_myrlocs [ 0 ] , lisp_myrlocs [ 1 ] ] :
  if ( Ii1iIii1II1 == None ) : continue
  oOOoo0O00 = lisp_rloc ( )
  oOOoo0O00 . rloc . copy_address ( Ii1iIii1II1 )
  oOOoo0O00 . priority = 254
  iii1Ii1i1i1I . append ( oOOoo0O00 )
  if 59 - 59: i11iIiiIii
  if 55 - 55: I11i % i1IIi % IiII
 OOoo00oo0 = lisp_nonce_echoing
 o00OO0o0 = map_request . keys
 if 16 - 16: OoO0O00 * Ii1I
 i1II1IiiIi = lisp_build_map_reply ( o00oo00oo , ii1I1 , iii1Ii1i1i1I , iI1III , LISP_NO_ACTION ,
 1440 , True , o00OO0o0 , OOoo00oo0 , True , ttl )
 lisp_send_map_reply ( lisp_sockets , i1II1IiiIi , O0OoO0OOo0o0 , sport )
 return
 if 89 - 89: OoOoOO00 / Oo0Ooo + O0 * ooOoO0o
 if 80 - 80: i11iIiiIii - O0 / I1Ii111 + OOooOOo % Oo0Ooo
 if 95 - 95: II111iiii
 if 76 - 76: OoO0O00 % iII111i * OoOoOO00 / ooOoO0o / i1IIi
 if 45 - 45: Ii1I . I11i * I1Ii111 . i11iIiiIii
 if 34 - 34: O0 * o0oOOo0O0Ooo / IiII
 if 75 - 75: I1Ii111 - i1IIi - OoO0O00
 if 25 - 25: iII111i . o0oOOo0O0Ooo
 if 62 - 62: I11i + i1IIi . I1ii11iIi11i - I1ii11iIi11i
 if 68 - 68: ooOoO0o % OoooooooOO
def lisp_get_private_rloc_set ( target_site_eid , seid , group ) :
 iii1Ii1i1i1I = target_site_eid . registered_rlocs
 if 94 - 94: Oo0Ooo * o0oOOo0O0Ooo
 o00 = lisp_site_eid_lookup ( seid , group , False )
 if ( o00 == None ) : return ( iii1Ii1i1i1I )
 if 39 - 39: O0 - i11iIiiIii - I1IiiI / Oo0Ooo - i11iIiiIii
 if 30 - 30: OoO0O00 / OoOoOO00 + I1ii11iIi11i % IiII - OoO0O00
 if 19 - 19: I1IiiI
 if 99 - 99: OOooOOo - OOooOOo
 OO0oOO = None
 IIii1Ii1Iii = [ ]
 for IIiO0Ooo in iii1Ii1i1i1I :
  if ( IIiO0Ooo . is_rtr ( ) ) : continue
  if ( IIiO0Ooo . rloc . is_private_address ( ) ) :
   o0oOo0 = copy . deepcopy ( IIiO0Ooo )
   IIii1Ii1Iii . append ( o0oOo0 )
   continue
   if 4 - 4: Oo0Ooo / OoOoOO00
  OO0oOO = IIiO0Ooo
  break
  if 97 - 97: Oo0Ooo
 if ( OO0oOO == None ) : return ( iii1Ii1i1i1I )
 OO0oOO = OO0oOO . rloc . print_address_no_iid ( )
 if 6 - 6: O0 - I1ii11iIi11i / OoooooooOO - Ii1I + Oo0Ooo
 if 88 - 88: OOooOOo - I1ii11iIi11i % iII111i
 if 58 - 58: OoO0O00 . O0 - i11iIiiIii . I1IiiI
 if 95 - 95: OoooooooOO / ooOoO0o * I11i - Ii1I
 o0oOoOo = None
 for IIiO0Ooo in o00 . registered_rlocs :
  if ( IIiO0Ooo . is_rtr ( ) ) : continue
  if ( IIiO0Ooo . rloc . is_private_address ( ) ) : continue
  o0oOoOo = IIiO0Ooo
  break
  if 15 - 15: Oo0Ooo / i11iIiiIii * IiII * i11iIiiIii % O0
 if ( o0oOoOo == None ) : return ( iii1Ii1i1i1I )
 o0oOoOo = o0oOoOo . rloc . print_address_no_iid ( )
 if 100 - 100: O0 * I1Ii111
 if 50 - 50: OoooooooOO + o0oOOo0O0Ooo + iIii1I11I1II1 + OOooOOo
 if 90 - 90: Ii1I * I11i % I1Ii111 - I1ii11iIi11i * I1Ii111 % OoO0O00
 if 50 - 50: iIii1I11I1II1
 ooO0OOoOoOO00 = target_site_eid . site_id
 if ( ooO0OOoOoOO00 == 0 ) :
  if ( o0oOoOo == OO0oOO ) :
   lprint ( "Return private RLOCs for sites behind {}" . format ( OO0oOO ) )
   if 56 - 56: oO0o
   return ( IIii1Ii1Iii )
   if 55 - 55: iIii1I11I1II1 % oO0o % OOooOOo / I1Ii111 * OoooooooOO / Oo0Ooo
  return ( iii1Ii1i1i1I )
  if 88 - 88: I11i + OoO0O00 . iIii1I11I1II1 . II111iiii
  if 67 - 67: OOooOOo - ooOoO0o % iII111i % IiII
  if 71 - 71: OoO0O00 - ooOoO0o - I1IiiI + O0
  if 15 - 15: i1IIi
  if 43 - 43: II111iiii + OOooOOo . i11iIiiIii - II111iiii
  if 80 - 80: o0oOOo0O0Ooo . oO0o . I1Ii111
  if 26 - 26: i1IIi - I1IiiI + IiII / OoO0O00 . I1ii11iIi11i
 if ( ooO0OOoOoOO00 == o00 . site_id ) :
  lprint ( "Return private RLOCs for sites in site-id {}" . format ( ooO0OOoOoOO00 ) )
  return ( IIii1Ii1Iii )
  if 82 - 82: I1Ii111 % iII111i . OoOoOO00 % OoO0O00 + I1ii11iIi11i
 return ( iii1Ii1i1i1I )
 if 69 - 69: I1IiiI * OoOoOO00 - ooOoO0o . O0
 if 15 - 15: oO0o . IiII + I1Ii111 - OoooooooOO
 if 85 - 85: II111iiii - Oo0Ooo + oO0o . i11iIiiIii + Oo0Ooo
 if 86 - 86: ooOoO0o . OoO0O00
 if 47 - 47: IiII % I1IiiI
 if 91 - 91: Ii1I
 if 69 - 69: iII111i
 if 96 - 96: Ii1I
 if 39 - 39: OoO0O00 - I1IiiI % II111iiii - IiII * I1ii11iIi11i
def lisp_get_partial_rloc_set ( registered_rloc_set , mr_source , multicast ) :
 OOoOoO = [ ]
 iii1Ii1i1i1I = [ ]
 if 50 - 50: O0 . I1Ii111 + i1IIi * iIii1I11I1II1 % iIii1I11I1II1
 if 18 - 18: iII111i . Oo0Ooo
 if 4 - 4: o0oOOo0O0Ooo % oO0o - OoOoOO00 * iIii1I11I1II1
 if 96 - 96: Ii1I
 if 1 - 1: i1IIi % O0 / I11i
 if 52 - 52: I1IiiI + oO0o * II111iiii
 i1iii1ii11 = False
 o0oo00Oo00 = False
 for IIiO0Ooo in registered_rloc_set :
  if ( IIiO0Ooo . priority != 254 ) : continue
  o0oo00Oo00 |= True
  if ( IIiO0Ooo . rloc . is_exact_match ( mr_source ) == False ) : continue
  i1iii1ii11 = True
  break
  if 20 - 20: iII111i + o0oOOo0O0Ooo - I1IiiI % O0 % I1Ii111 . iIii1I11I1II1
  if 10 - 10: IiII * o0oOOo0O0Ooo * o0oOOo0O0Ooo
  if 66 - 66: I1ii11iIi11i % I1IiiI . I1IiiI * Ii1I + OoO0O00 % i1IIi
  if 34 - 34: II111iiii + I1IiiI * i1IIi . I11i
  if 51 - 51: I11i . iII111i * I1IiiI . iIii1I11I1II1 % I1IiiI / O0
  if 47 - 47: OoooooooOO - i11iIiiIii . I1IiiI / i1IIi
  if 74 - 74: OoooooooOO * ooOoO0o
 if ( o0oo00Oo00 == False ) : return ( registered_rloc_set )
 if 45 - 45: Oo0Ooo + iIii1I11I1II1 . o0oOOo0O0Ooo
 if 50 - 50: o0oOOo0O0Ooo % O0
 if 67 - 67: OoOoOO00
 if 21 - 21: I11i % Oo0Ooo + Oo0Ooo / iIii1I11I1II1 % iIii1I11I1II1
 if 66 - 66: iII111i
 if 72 - 72: ooOoO0o / oO0o / iII111i . I1Ii111 . I1ii11iIi11i + IiII
 if 39 - 39: I1IiiI % I1Ii111
 if 22 - 22: OoOoOO00 - OOooOOo % i1IIi + i1IIi
 if 28 - 28: oO0o + OoOoOO00 * Ii1I . I11i
 if 80 - 80: I1ii11iIi11i / OoOoOO00
 OOOoOO = ( os . getenv ( "LISP_RTR_BEHIND_NAT" ) != None )
 if 84 - 84: I1Ii111 + iII111i * iIii1I11I1II1
 if 37 - 37: II111iiii + ooOoO0o + iIii1I11I1II1 / I1Ii111
 if 59 - 59: I1Ii111
 if 22 - 22: OoooooooOO
 if 88 - 88: I1Ii111 - OoO0O00
 for IIiO0Ooo in registered_rloc_set :
  if ( OOOoOO and IIiO0Ooo . rloc . is_private_address ( ) ) : continue
  if ( multicast == False and IIiO0Ooo . priority == 255 ) : continue
  if ( multicast and IIiO0Ooo . mpriority == 255 ) : continue
  if ( IIiO0Ooo . priority == 254 ) :
   OOoOoO . append ( IIiO0Ooo )
  else :
   iii1Ii1i1i1I . append ( IIiO0Ooo )
   if 29 - 29: I1IiiI . I1Ii111
   if 74 - 74: Oo0Ooo / OoOoOO00 + OoOoOO00 % i11iIiiIii . OoO0O00 + ooOoO0o
   if 77 - 77: ooOoO0o . I11i + OoooooooOO
   if 100 - 100: ooOoO0o . oO0o % I1ii11iIi11i . IiII * IiII - o0oOOo0O0Ooo
   if 49 - 49: iIii1I11I1II1 % Ii1I / OoooooooOO - II111iiii . Ii1I
   if 65 - 65: OoooooooOO + I1Ii111 % ooOoO0o + II111iiii . i1IIi + OoooooooOO
 if ( i1iii1ii11 ) : return ( iii1Ii1i1i1I )
 if 26 - 26: I1IiiI / II111iiii % I1ii11iIi11i * o0oOOo0O0Ooo . IiII / OoO0O00
 if 10 - 10: i11iIiiIii / i1IIi + O0 - i11iIiiIii % I11i - i1IIi
 if 38 - 38: O0 - I1IiiI + Oo0Ooo + ooOoO0o
 if 56 - 56: I1Ii111 + oO0o / Ii1I + I1Ii111
 if 21 - 21: OOooOOo / OoOoOO00 + OoOoOO00 + OoOoOO00 - i1IIi + Ii1I
 if 43 - 43: O0 % II111iiii
 if 60 - 60: iII111i / ooOoO0o - Ii1I - OoooooooOO
 if 79 - 79: oO0o / iII111i . iIii1I11I1II1 * i11iIiiIii * i1IIi . iIii1I11I1II1
 if 31 - 31: OoooooooOO / ooOoO0o / OoooooooOO + ooOoO0o . O0 - IiII
 if 53 - 53: Oo0Ooo % iII111i % iII111i
 iii1Ii1i1i1I = [ ]
 for IIiO0Ooo in registered_rloc_set :
  if ( IIiO0Ooo . rloc . is_private_address ( ) ) : iii1Ii1i1i1I . append ( IIiO0Ooo )
  if 71 - 71: iII111i
 iii1Ii1i1i1I += OOoOoO
 return ( iii1Ii1i1i1I )
 if 99 - 99: O0 - OoOoOO00 * I1Ii111 - Oo0Ooo
 if 62 - 62: i1IIi + ooOoO0o + Oo0Ooo - i11iIiiIii
 if 19 - 19: I1IiiI / OOooOOo
 if 6 - 6: I1ii11iIi11i + IiII * oO0o * OoOoOO00
 if 67 - 67: I1Ii111 + OoooooooOO + OoOoOO00 % iIii1I11I1II1 . I1IiiI
 if 68 - 68: ooOoO0o
 if 68 - 68: I11i % IiII
 if 1 - 1: I1IiiI + OOooOOo - OOooOOo * O0 + o0oOOo0O0Ooo * OOooOOo
 if 48 - 48: ooOoO0o - iII111i + I1ii11iIi11i * I1Ii111 % ooOoO0o * OoO0O00
 if 28 - 28: i1IIi / iII111i + OOooOOo
def lisp_store_pubsub_state ( reply_eid , itr_rloc , mr_sport , nonce , ttl , xtr_id ) :
 OO0oOOoOoOo = lisp_pubsub ( itr_rloc , mr_sport , nonce , ttl , xtr_id )
 OO0oOOoOoOo . add ( reply_eid )
 return
 if 36 - 36: II111iiii % II111iiii + i11iIiiIii / oO0o
 if 26 - 26: OoOoOO00 / i11iIiiIii - OOooOOo % oO0o % I1IiiI
 if 23 - 23: i11iIiiIii / iII111i + IiII / i11iIiiIii
 if 97 - 97: o0oOOo0O0Ooo + o0oOOo0O0Ooo / I1ii11iIi11i * OoooooooOO
 if 61 - 61: I1IiiI - I11i
 if 5 - 5: i11iIiiIii % i1IIi / IiII * i11iIiiIii . i1IIi * iII111i
 if 71 - 71: i11iIiiIii / iIii1I11I1II1 % i1IIi + oO0o - i1IIi + II111iiii
 if 40 - 40: OOooOOo + ooOoO0o
 if 96 - 96: i11iIiiIii + IiII / iIii1I11I1II1
 if 49 - 49: OoOoOO00 - I1ii11iIi11i . I11i % II111iiii % iII111i
 if 6 - 6: OoooooooOO
 if 49 - 49: iII111i
 if 12 - 12: Oo0Ooo / II111iiii * OoOoOO00 * i1IIi - i1IIi / iII111i
 if 43 - 43: I1IiiI / IiII
 if 38 - 38: I1ii11iIi11i + i11iIiiIii * I1IiiI % oO0o % OoooooooOO
def lisp_convert_reply_to_notify ( packet ) :
 if 4 - 4: OoO0O00 . I1IiiI - O0 % iII111i . OOooOOo
 if 69 - 69: OoooooooOO
 if 19 - 19: O0 + iIii1I11I1II1 / OoOoOO00 / oO0o + II111iiii - OOooOOo
 if 70 - 70: i1IIi * o0oOOo0O0Ooo + I1Ii111 . ooOoO0o - O0 + i11iIiiIii
 oooOooOoO = struct . unpack ( "I" , packet [ 0 : 4 ] ) [ 0 ]
 oooOooOoO = socket . ntohl ( oooOooOoO ) & 0xff
 iI1III = packet [ 4 : 12 ]
 packet = packet [ 12 : : ]
 if 65 - 65: o0oOOo0O0Ooo % i11iIiiIii / II111iiii
 if 85 - 85: I1Ii111 / II111iiii / OOooOOo
 if 87 - 87: OoOoOO00 - oO0o - IiII / iII111i - OOooOOo / Oo0Ooo
 if 99 - 99: OoO0O00 * I11i
 oo0I1I1iiI1i = ( LISP_MAP_NOTIFY << 28 ) | oooOooOoO
 I1I = struct . pack ( "I" , socket . htonl ( oo0I1I1iiI1i ) )
 i111iii1I1 = struct . pack ( "I" , 0 )
 if 33 - 33: I1Ii111 % IiII * OOooOOo - I1Ii111
 if 100 - 100: ooOoO0o . i11iIiiIii * Oo0Ooo - i11iIiiIii
 if 72 - 72: oO0o + I11i . OoooooooOO
 if 84 - 84: oO0o * oO0o - i1IIi + ooOoO0o
 packet = I1I + iI1III + i111iii1I1 + packet
 return ( packet )
 if 83 - 83: i1IIi
 if 85 - 85: i11iIiiIii / OoO0O00 / oO0o
 if 12 - 12: iII111i % OOooOOo % i1IIi
 if 17 - 17: IiII
 if 63 - 63: ooOoO0o . i11iIiiIii / iIii1I11I1II1
 if 8 - 8: i11iIiiIii . IiII * iIii1I11I1II1 * I1IiiI * Ii1I * i11iIiiIii
 if 24 - 24: I1IiiI * I11i - o0oOOo0O0Ooo / iII111i + IiII - I1ii11iIi11i
 if 53 - 53: I11i / I1IiiI - iIii1I11I1II1 - o0oOOo0O0Ooo * OoOoOO00
def lisp_notify_subscribers ( lisp_sockets , eid_record , eid , site ) :
 oOoo0OooOOo00 = eid . print_prefix ( )
 if ( lisp_pubsub_cache . has_key ( oOoo0OooOOo00 ) == False ) : return
 if 86 - 86: iIii1I11I1II1 - I1Ii111
 for OO0oOOoOoOo in lisp_pubsub_cache [ oOoo0OooOOo00 ] . values ( ) :
  oOooOo000O = OO0oOOoOoOo . itr
  o00o = OO0oOOoOoOo . port
  OoO0OOOOO0OO = red ( oOooOo000O . print_address_no_iid ( ) , False )
  iI11I1iI = bold ( "subscriber" , False )
  oO = "0x" + lisp_hex_string ( OO0oOOoOoOo . xtr_id )
  iI1III = "0x" + lisp_hex_string ( OO0oOOoOoOo . nonce )
  if 39 - 39: iII111i + o0oOOo0O0Ooo % I11i / iII111i * I11i
  lprint ( "    Notify {} {}:{} xtr-id {} for {}, nonce {}" . format ( iI11I1iI , OoO0OOOOO0OO , o00o , oO , green ( oOoo0OooOOo00 , False ) , iI1III ) )
  if 52 - 52: II111iiii
  if 41 - 41: I1IiiI / OoO0O00
  lisp_build_map_notify ( lisp_sockets , eid_record , [ oOoo0OooOOo00 ] , 1 , oOooOo000O ,
 o00o , OO0oOOoOoOo . nonce , 0 , 0 , 0 , site , False )
  OO0oOOoOoOo . map_notify_count += 1
  if 86 - 86: Ii1I + Ii1I - Oo0Ooo * I1IiiI
 return
 if 52 - 52: I11i - OoO0O00 - I1IiiI % OoOoOO00 % OoOoOO00 + Oo0Ooo
 if 88 - 88: iIii1I11I1II1 * OoO0O00 / IiII
 if 74 - 74: I1ii11iIi11i / i11iIiiIii - II111iiii . Oo0Ooo / ooOoO0o
 if 55 - 55: OoO0O00 % IiII
 if 93 - 93: OoO0O00 . I1ii11iIi11i / OOooOOo % OoooooooOO + i1IIi + I1Ii111
 if 94 - 94: II111iiii + i11iIiiIii % Ii1I / ooOoO0o * OoOoOO00
 if 68 - 68: O0 / Oo0Ooo / iIii1I11I1II1
def lisp_process_pubsub ( lisp_sockets , packet , reply_eid , itr_rloc , port , nonce ,
 ttl , xtr_id ) :
 if 63 - 63: I1Ii111 + iII111i
 if 6 - 6: I1ii11iIi11i + Ii1I
 if 36 - 36: iII111i + iII111i * OoO0O00 * I1ii11iIi11i
 if 97 - 97: ooOoO0o + OOooOOo
 lisp_store_pubsub_state ( reply_eid , itr_rloc , port , nonce , ttl , xtr_id )
 if 70 - 70: o0oOOo0O0Ooo + Ii1I - i11iIiiIii + I11i * o0oOOo0O0Ooo . Ii1I
 o00oo00oo = green ( reply_eid . print_prefix ( ) , False )
 oOooOo000O = red ( itr_rloc . print_address_no_iid ( ) , False )
 iIiIiiI = bold ( "Map-Notify" , False )
 xtr_id = "0x" + lisp_hex_string ( xtr_id )
 lprint ( "{} pubsub request for {} to ack ITR {} xtr-id: {}" . format ( iIiIiiI ,
 o00oo00oo , oOooOo000O , xtr_id ) )
 if 58 - 58: I1ii11iIi11i / Ii1I * ooOoO0o - IiII
 if 67 - 67: ooOoO0o - ooOoO0o * o0oOOo0O0Ooo
 if 65 - 65: O0
 if 37 - 37: I1ii11iIi11i - Oo0Ooo . i11iIiiIii / i11iIiiIii + oO0o
 packet = lisp_convert_reply_to_notify ( packet )
 lisp_send_map_notify ( lisp_sockets , packet , itr_rloc , port )
 return
 if 19 - 19: i1IIi / i1IIi - OoooooooOO - OOooOOo . i1IIi
 if 57 - 57: OOooOOo / I1ii11iIi11i * oO0o
 if 53 - 53: o0oOOo0O0Ooo * Ii1I
 if 42 - 42: I11i + iII111i / iIii1I11I1II1
 if 1 - 1: O0 - II111iiii
 if 75 - 75: II111iiii / OoO0O00 % II111iiii
 if 3 - 3: Ii1I - Ii1I % I1ii11iIi11i
 if 44 - 44: OOooOOo - o0oOOo0O0Ooo
def lisp_ms_process_map_request ( lisp_sockets , packet , map_request , mr_source ,
 mr_sport , ecm_source ) :
 if 69 - 69: IiII + I1ii11iIi11i / o0oOOo0O0Ooo / OOooOOo
 if 31 - 31: oO0o + I1ii11iIi11i * i1IIi % I1IiiI % I1IiiI + iIii1I11I1II1
 if 62 - 62: OoooooooOO
 if 38 - 38: iII111i % iII111i * ooOoO0o / OoO0O00 + ooOoO0o
 if 52 - 52: ooOoO0o . iIii1I11I1II1 / iIii1I11I1II1 % oO0o - oO0o * II111iiii
 if 57 - 57: I1Ii111
 o00oo00oo = map_request . target_eid
 ii1I1 = map_request . target_group
 oOoo0OooOOo00 = lisp_print_eid_tuple ( o00oo00oo , ii1I1 )
 O0OoO0OOo0o0 = map_request . itr_rlocs [ 0 ]
 oO = map_request . xtr_id
 iI1III = map_request . nonce
 oo0oOOo0 = LISP_NO_ACTION
 OO0oOOoOoOo = map_request . subscribe_bit
 if 23 - 23: I1ii11iIi11i + II111iiii
 if 99 - 99: o0oOOo0O0Ooo . I1IiiI + o0oOOo0O0Ooo * o0oOOo0O0Ooo / O0
 if 27 - 27: OOooOOo - I1Ii111
 if 33 - 33: OOooOOo - Ii1I - iII111i + I1ii11iIi11i - i11iIiiIii
 if 89 - 89: iIii1I11I1II1 * I11i + OOooOOo
 iiIiIIi1I = True
 Ooo0 = ( lisp_get_eid_hash ( o00oo00oo ) != None )
 if ( Ooo0 ) :
  iIiI1iI = map_request . map_request_signature
  if ( iIiI1iI == None ) :
   iiIiIIi1I = False
   lprint ( ( "EID-crypto-hash signature verification {}, " + "no signature found" ) . format ( bold ( "failed" , False ) ) )
   if 52 - 52: O0 + O0 + I1IiiI
  else :
   I1III1iI1II = map_request . signature_eid
   oO0oOOoo0Oooo , iI1I , iiIiIIi1I = lisp_lookup_public_key ( I1III1iI1II )
   if ( iiIiIIi1I ) :
    iiIiIIi1I = map_request . verify_map_request_sig ( iI1I )
   else :
    lprint ( "Public-key lookup failed for sig-eid {}, hash-eid {}" . format ( I1III1iI1II . print_address ( ) , oO0oOOoo0Oooo . print_address ( ) ) )
    if 43 - 43: IiII / OOooOOo % II111iiii . o0oOOo0O0Ooo / i11iIiiIii
    if 5 - 5: oO0o % iII111i . Oo0Ooo . O0 . OoOoOO00 / iII111i
   O0OOOooo = bold ( "passed" , False ) if iiIiIIi1I else bold ( "failed" , False )
   lprint ( "EID-crypto-hash signature verification {}" . format ( O0OOOooo ) )
   if 62 - 62: iII111i * I1Ii111 / o0oOOo0O0Ooo
   if 20 - 20: oO0o * OoOoOO00
   if 90 - 90: i11iIiiIii . I1ii11iIi11i . IiII . OoO0O00 . I1ii11iIi11i
 if ( OO0oOOoOoOo and iiIiIIi1I == False ) :
  OO0oOOoOoOo = False
  lprint ( "Suppress creating pubsub state due to signature failure" )
  if 29 - 29: OoOoOO00 / OoO0O00 / OoooooooOO * O0 / iIii1I11I1II1
  if 29 - 29: OoO0O00 / IiII + i1IIi / OoO0O00 . Oo0Ooo
  if 52 - 52: OoOoOO00 . iIii1I11I1II1 / OoOoOO00
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
  if 78 - 78: oO0o
 ii1iii = O0OoO0OOo0o0 if ( O0OoO0OOo0o0 . afi == ecm_source . afi ) else ecm_source
 if 71 - 71: OoOoOO00 / i11iIiiIii * iII111i
 ooOOOo0o0oo = lisp_site_eid_lookup ( o00oo00oo , ii1I1 , False )
 if 82 - 82: oO0o % OOooOOo - iII111i
 if ( ooOOOo0o0oo == None or ooOOOo0o0oo . is_star_g ( ) ) :
  OOOO0OOoO = bold ( "Site not found" , False )
  lprint ( "{} for requested EID {}" . format ( OOOO0OOoO ,
 green ( oOoo0OooOOo00 , False ) ) )
  if 45 - 45: oO0o
  if 50 - 50: Ii1I * Ii1I / O0 . Oo0Ooo + iII111i
  if 9 - 9: OoooooooOO % O0 % I1ii11iIi11i
  if 100 - 100: i11iIiiIii - iII111i - I11i
  lisp_send_negative_map_reply ( lisp_sockets , o00oo00oo , ii1I1 , iI1III , O0OoO0OOo0o0 ,
 mr_sport , 15 , oO , OO0oOOoOoOo )
  if 5 - 5: oO0o % IiII * iII111i
  return ( [ o00oo00oo , ii1I1 , LISP_DDT_ACTION_SITE_NOT_FOUND ] )
  if 98 - 98: iII111i / OOooOOo + IiII
  if 100 - 100: II111iiii . i11iIiiIii / oO0o - OOooOOo + OoOoOO00 % I1ii11iIi11i
 I11 = ooOOOo0o0oo . print_eid_tuple ( )
 o00O00oOO00 = ooOOOo0o0oo . site . site_name
 if 3 - 3: i1IIi * I1ii11iIi11i * II111iiii . I1ii11iIi11i
 if 82 - 82: OoOoOO00
 if 5 - 5: OOooOOo . OOooOOo
 if 53 - 53: OOooOOo * OoOoOO00 % iII111i
 if 86 - 86: OOooOOo . OOooOOo + IiII - I1ii11iIi11i . OoO0O00
 if ( Ooo0 == False and ooOOOo0o0oo . require_signature ) :
  iIiI1iI = map_request . map_request_signature
  I1III1iI1II = map_request . signature_eid
  if ( iIiI1iI == None or I1III1iI1II . is_null ( ) ) :
   lprint ( "Signature required for site {}" . format ( o00O00oOO00 ) )
   iiIiIIi1I = False
  else :
   I1III1iI1II = map_request . signature_eid
   oO0oOOoo0Oooo , iI1I , iiIiIIi1I = lisp_lookup_public_key ( I1III1iI1II )
   if ( iiIiIIi1I ) :
    iiIiIIi1I = map_request . verify_map_request_sig ( iI1I )
   else :
    lprint ( "Public-key lookup failed for sig-eid {}, hash-eid {}" . format ( I1III1iI1II . print_address ( ) , oO0oOOoo0Oooo . print_address ( ) ) )
    if 66 - 66: I1IiiI * OoOoOO00 . I1IiiI / Oo0Ooo - Ii1I
    if 69 - 69: iIii1I11I1II1 % iII111i + ooOoO0o * i1IIi + iII111i * I1Ii111
   O0OOOooo = bold ( "passed" , False ) if iiIiIIi1I else bold ( "failed" , False )
   lprint ( "Required signature verification {}" . format ( O0OOOooo ) )
   if 67 - 67: Ii1I % Oo0Ooo - Oo0Ooo . I11i + IiII
   if 73 - 73: Oo0Ooo + iIii1I11I1II1 . iIii1I11I1II1
   if 73 - 73: ooOoO0o + OoOoOO00
   if 61 - 61: I1Ii111 * I1Ii111 % OOooOOo
   if 31 - 31: oO0o + Ii1I - iIii1I11I1II1 / i11iIiiIii
   if 9 - 9: IiII % OoO0O00
 if ( iiIiIIi1I and ooOOOo0o0oo . registered == False ) :
  lprint ( "Site '{}' with EID-prefix {} is not registered for EID {}" . format ( o00O00oOO00 , green ( I11 , False ) , green ( oOoo0OooOOo00 , False ) ) )
  if 58 - 58: iII111i
  if 12 - 12: OoO0O00
  if 59 - 59: OOooOOo + i1IIi
  if 8 - 8: i1IIi + Oo0Ooo / Ii1I . OoOoOO00 % i1IIi
  if 33 - 33: OoooooooOO + iIii1I11I1II1
  if 68 - 68: II111iiii * iIii1I11I1II1 - OoO0O00 - I1ii11iIi11i * II111iiii
  if ( ooOOOo0o0oo . accept_more_specifics == False ) :
   o00oo00oo = ooOOOo0o0oo . eid
   ii1I1 = ooOOOo0o0oo . group
   if 37 - 37: OoooooooOO - I1ii11iIi11i . O0
   if 65 - 65: I1Ii111 + I1ii11iIi11i % I11i / iII111i
   if 38 - 38: I1IiiI - OOooOOo * OoOoOO00 + O0 * I1IiiI
   if 8 - 8: I1IiiI
   if 31 - 31: o0oOOo0O0Ooo + OOooOOo
  oooOooOO = 1
  if ( ooOOOo0o0oo . force_ttl != None ) :
   oooOooOO = ooOOOo0o0oo . force_ttl | 0x80000000
   if 7 - 7: IiII + iIii1I11I1II1
   if 97 - 97: oO0o
   if 52 - 52: I1ii11iIi11i / OoOoOO00 * OoO0O00 + II111iiii * OoooooooOO
   if 11 - 11: Ii1I * iII111i * I1IiiI - Oo0Ooo
   if 76 - 76: oO0o * II111iiii
  lisp_send_negative_map_reply ( lisp_sockets , o00oo00oo , ii1I1 , iI1III , O0OoO0OOo0o0 ,
 mr_sport , oooOooOO , oO , OO0oOOoOoOo )
  if 81 - 81: I11i
  return ( [ o00oo00oo , ii1I1 , LISP_DDT_ACTION_MS_NOT_REG ] )
  if 2 - 2: OoOoOO00
  if 75 - 75: I1IiiI - OoooooooOO * I1Ii111
  if 1 - 1: o0oOOo0O0Ooo % oO0o * I1Ii111 - i1IIi - iII111i . oO0o
  if 25 - 25: i1IIi * o0oOOo0O0Ooo / oO0o
  if 11 - 11: IiII + II111iiii
 i1I = False
 Oo0ii111I = ""
 iiIIi1iIIi = False
 if ( ooOOOo0o0oo . force_nat_proxy_reply ) :
  Oo0ii111I = ", nat-forced"
  i1I = True
  iiIIi1iIIi = True
 elif ( ooOOOo0o0oo . force_proxy_reply ) :
  Oo0ii111I = ", forced"
  iiIIi1iIIi = True
 elif ( ooOOOo0o0oo . proxy_reply_requested ) :
  Oo0ii111I = ", requested"
  iiIIi1iIIi = True
 elif ( map_request . pitr_bit and ooOOOo0o0oo . pitr_proxy_reply_drop ) :
  Oo0ii111I = ", drop-to-pitr"
  oo0oOOo0 = LISP_DROP_ACTION
 elif ( ooOOOo0o0oo . proxy_reply_action != "" ) :
  oo0oOOo0 = ooOOOo0o0oo . proxy_reply_action
  Oo0ii111I = ", forced, action {}" . format ( oo0oOOo0 )
  oo0oOOo0 = LISP_DROP_ACTION if ( oo0oOOo0 == "drop" ) else LISP_NATIVE_FORWARD_ACTION
  if 39 - 39: iII111i * iII111i * OOooOOo / O0 % Ii1I . I1Ii111
  if 53 - 53: I1ii11iIi11i . iIii1I11I1II1 % iIii1I11I1II1 / Ii1I / OoooooooOO . I1Ii111
  if 17 - 17: Oo0Ooo + i11iIiiIii + OoO0O00 - OOooOOo
  if 9 - 9: II111iiii * OOooOOo / Oo0Ooo + iIii1I11I1II1 % I1IiiI
  if 95 - 95: I1Ii111 . IiII % OoO0O00 - OOooOOo - I11i
  if 55 - 55: OoooooooOO % I1ii11iIi11i % iII111i / IiII
  if 65 - 65: II111iiii
 Ooooo = False
 OOOoo0Oo00 = None
 if ( iiIIi1iIIi and lisp_policies . has_key ( ooOOOo0o0oo . policy ) ) :
  i111 = lisp_policies [ ooOOOo0o0oo . policy ]
  if ( i111 . match_policy_map_request ( map_request , mr_source ) ) : OOOoo0Oo00 = i111
  if 83 - 83: OoOoOO00
  if ( OOOoo0Oo00 ) :
   oo0OooO = bold ( "matched" , False )
   lprint ( "Map-Request {} policy '{}', set-action '{}'" . format ( oo0OooO ,
 i111 . policy_name , i111 . set_action ) )
  else :
   oo0OooO = bold ( "no match" , False )
   lprint ( "Map-Request {} for policy '{}', implied drop" . format ( oo0OooO ,
 i111 . policy_name ) )
   Ooooo = True
   if 90 - 90: oO0o
   if 51 - 51: oO0o / o0oOOo0O0Ooo
   if 97 - 97: II111iiii + o0oOOo0O0Ooo . OoOoOO00
 if ( Oo0ii111I != "" ) :
  lprint ( "Proxy-replying for EID {}, found site '{}' EID-prefix {}{}" . format ( green ( oOoo0OooOOo00 , False ) , o00O00oOO00 , green ( I11 , False ) ,
  # i1IIi - IiII + oO0o / OoO0O00 . OOooOOo * I1ii11iIi11i
 Oo0ii111I ) )
  if 100 - 100: iIii1I11I1II1 / OOooOOo . O0 * I1IiiI . iIii1I11I1II1 . OoO0O00
  iii1Ii1i1i1I = ooOOOo0o0oo . registered_rlocs
  oooOooOO = 1440
  if ( i1I ) :
   if ( ooOOOo0o0oo . site_id != 0 ) :
    Oooo0oo000O0 = map_request . source_eid
    iii1Ii1i1i1I = lisp_get_private_rloc_set ( ooOOOo0o0oo , Oooo0oo000O0 , ii1I1 )
    if 48 - 48: i1IIi
   if ( iii1Ii1i1i1I == ooOOOo0o0oo . registered_rlocs ) :
    oo0oO00 = ( ooOOOo0o0oo . group . is_null ( ) == False )
    IIii1Ii1Iii = lisp_get_partial_rloc_set ( iii1Ii1i1i1I , ii1iii , oo0oO00 )
    if ( IIii1Ii1Iii != iii1Ii1i1i1I ) :
     oooOooOO = 15
     iii1Ii1i1i1I = IIii1Ii1Iii
     if 48 - 48: Ii1I
     if 62 - 62: oO0o - I1ii11iIi11i - oO0o - OoO0O00 * Oo0Ooo
     if 47 - 47: o0oOOo0O0Ooo
     if 88 - 88: iIii1I11I1II1 + OOooOOo . II111iiii / i11iIiiIii % OOooOOo % IiII
     if 38 - 38: OOooOOo
     if 82 - 82: OoOoOO00 % II111iiii * ooOoO0o + OoooooooOO + I1IiiI
     if 89 - 89: ooOoO0o % i1IIi - OoooooooOO
     if 100 - 100: Ii1I % I1ii11iIi11i % I1IiiI
  if ( ooOOOo0o0oo . force_ttl != None ) :
   oooOooOO = ooOOOo0o0oo . force_ttl | 0x80000000
   if 19 - 19: I1ii11iIi11i . o0oOOo0O0Ooo % Oo0Ooo / OoooooooOO
   if 68 - 68: iII111i
   if 55 - 55: IiII . i11iIiiIii % OoooooooOO
   if 88 - 88: Ii1I * o0oOOo0O0Ooo / oO0o
   if 58 - 58: O0
   if 43 - 43: O0 / i1IIi / I11i % I1IiiI
  if ( OOOoo0Oo00 ) :
   if ( OOOoo0Oo00 . set_record_ttl ) :
    oooOooOO = OOOoo0Oo00 . set_record_ttl
    lprint ( "Policy set-record-ttl to {}" . format ( oooOooOO ) )
    if 82 - 82: i11iIiiIii * i11iIiiIii + I1Ii111 - I1ii11iIi11i * oO0o - Ii1I
   if ( OOOoo0Oo00 . set_action == "drop" ) :
    lprint ( "Policy set-action drop, send negative Map-Reply" )
    oo0oOOo0 = LISP_POLICY_DENIED_ACTION
    iii1Ii1i1i1I = [ ]
   else :
    oOOoo0O00 = OOOoo0Oo00 . set_policy_map_reply ( )
    if ( oOOoo0O00 ) : iii1Ii1i1i1I = [ oOOoo0O00 ]
    if 40 - 40: o0oOOo0O0Ooo + OoO0O00 % i1IIi % iII111i * I1Ii111
    if 36 - 36: I1ii11iIi11i % II111iiii % I1Ii111 / I1ii11iIi11i
    if 34 - 34: OoooooooOO * i11iIiiIii
  if ( Ooooo ) :
   lprint ( "Implied drop action, send negative Map-Reply" )
   oo0oOOo0 = LISP_POLICY_DENIED_ACTION
   iii1Ii1i1i1I = [ ]
   if 33 - 33: II111iiii
   if 59 - 59: iIii1I11I1II1 % I11i
  OOoo00oo0 = ooOOOo0o0oo . echo_nonce_capable
  if 93 - 93: I1ii11iIi11i
  if 50 - 50: ooOoO0o % OoO0O00 % OoO0O00
  if 36 - 36: I1IiiI * O0 . IiII / I1Ii111
  if 15 - 15: I11i + iII111i
  if ( iiIiIIi1I ) :
   oo000oOOooo0O = ooOOOo0o0oo . eid
   OO0000oo0oo = ooOOOo0o0oo . group
  else :
   oo000oOOooo0O = o00oo00oo
   OO0000oo0oo = ii1I1
   oo0oOOo0 = LISP_AUTH_FAILURE_ACTION
   iii1Ii1i1i1I = [ ]
   if 75 - 75: Ii1I + iII111i + I1IiiI . i1IIi * iIii1I11I1II1 * i11iIiiIii
   if 54 - 54: O0 * Ii1I + Ii1I
   if 59 - 59: i11iIiiIii % iII111i
   if 54 - 54: I11i . ooOoO0o / OOooOOo % I1Ii111
   if 13 - 13: I11i / O0 . o0oOOo0O0Ooo . ooOoO0o
   if 7 - 7: OoO0O00 + OoooooooOO % II111iiii % oO0o
  packet = lisp_build_map_reply ( oo000oOOooo0O , OO0000oo0oo , iii1Ii1i1i1I ,
 iI1III , oo0oOOo0 , oooOooOO , False , None , OOoo00oo0 , False )
  if 48 - 48: OOooOOo . II111iiii * OOooOOo - I11i / iIii1I11I1II1 / i11iIiiIii
  if ( OO0oOOoOoOo ) :
   lisp_process_pubsub ( lisp_sockets , packet , oo000oOOooo0O , O0OoO0OOo0o0 ,
 mr_sport , iI1III , oooOooOO , oO )
  else :
   lisp_send_map_reply ( lisp_sockets , packet , O0OoO0OOo0o0 , mr_sport )
   if 37 - 37: II111iiii % O0 + iIii1I11I1II1 - I1IiiI . I11i + I1ii11iIi11i
   if 14 - 14: ooOoO0o % iIii1I11I1II1 % ooOoO0o / IiII + OOooOOo
  return ( [ ooOOOo0o0oo . eid , ooOOOo0o0oo . group , LISP_DDT_ACTION_MS_ACK ] )
  if 14 - 14: Oo0Ooo
  if 79 - 79: I1ii11iIi11i % I1Ii111 % I11i - iII111i * OoOoOO00
  if 48 - 48: O0 + OoOoOO00 - O0
  if 79 - 79: ooOoO0o . OoOoOO00 / OoooooooOO - II111iiii
  if 48 - 48: Oo0Ooo
 OoIiIii = len ( ooOOOo0o0oo . registered_rlocs )
 if ( OoIiIii == 0 ) :
  lprint ( "Requested EID {} found site '{}' with EID-prefix {} with " + "no registered RLOCs" . format ( green ( oOoo0OooOOo00 , False ) , o00O00oOO00 ,
  # I11i / o0oOOo0O0Ooo + oO0o % Ii1I
 green ( I11 , False ) ) )
  return ( [ ooOOOo0o0oo . eid , ooOOOo0o0oo . group , LISP_DDT_ACTION_MS_ACK ] )
  if 83 - 83: I1ii11iIi11i . OOooOOo
  if 50 - 50: Ii1I - i11iIiiIii % Ii1I - OoOoOO00 + I1IiiI / OoooooooOO
  if 57 - 57: I1IiiI - I11i - I1Ii111 . oO0o % Ii1I
  if 59 - 59: I1IiiI % OoO0O00 . o0oOOo0O0Ooo
  if 85 - 85: ooOoO0o . ooOoO0o % Oo0Ooo . OOooOOo + OOooOOo / I1IiiI
 oooo0o = map_request . target_eid if map_request . source_eid . is_null ( ) else map_request . source_eid
 if 76 - 76: OOooOOo % OOooOOo + o0oOOo0O0Ooo - I1ii11iIi11i * oO0o * IiII
 o0o0oooO00O0 = map_request . target_eid . hash_address ( oooo0o )
 o0o0oooO00O0 %= OoIiIii
 I11i1i1i1iii = ooOOOo0o0oo . registered_rlocs [ o0o0oooO00O0 ]
 if 41 - 41: OoOoOO00 + IiII % I1Ii111 / OOooOOo . I1IiiI
 if ( I11i1i1i1iii . rloc . is_null ( ) ) :
  lprint ( ( "Suppress forwarding Map-Request for EID {} at site '{}' " + "EID-prefix {}, no RLOC address" ) . format ( green ( oOoo0OooOOo00 , False ) ,
  # o0oOOo0O0Ooo + II111iiii / ooOoO0o
 o00O00oOO00 , green ( I11 , False ) ) )
 else :
  lprint ( ( "Forwarding Map-Request for EID {} to ETR {} at site '{}' " + "EID-prefix {}" ) . format ( green ( oOoo0OooOOo00 , False ) ,
  # II111iiii
 red ( I11i1i1i1iii . rloc . print_address ( ) , False ) , o00O00oOO00 ,
 green ( I11 , False ) ) )
  if 83 - 83: II111iiii . OoOoOO00 - i11iIiiIii . OoOoOO00 . i1IIi % OoooooooOO
  if 47 - 47: II111iiii
  if 30 - 30: i1IIi . Oo0Ooo / o0oOOo0O0Ooo + IiII * OOooOOo
  if 26 - 26: Ii1I % O0 - i1IIi % iII111i * OoO0O00
  lisp_send_ecm ( lisp_sockets , packet , map_request . source_eid , mr_sport ,
 map_request . target_eid , I11i1i1i1iii . rloc , to_etr = True )
  if 60 - 60: I1ii11iIi11i * iII111i / OoOoOO00 . o0oOOo0O0Ooo / iIii1I11I1II1
 return ( [ ooOOOo0o0oo . eid , ooOOOo0o0oo . group , LISP_DDT_ACTION_MS_ACK ] )
 if 94 - 94: OoO0O00 . ooOoO0o
 if 25 - 25: I1Ii111 % OOooOOo
 if 82 - 82: Ii1I
 if 17 - 17: iII111i . i1IIi . i1IIi
 if 76 - 76: OoooooooOO % IiII
 if 81 - 81: iII111i . OOooOOo * i1IIi
 if 14 - 14: oO0o
def lisp_ddt_process_map_request ( lisp_sockets , map_request , ecm_source , port ) :
 if 16 - 16: iII111i
 if 26 - 26: iII111i . oO0o * i11iIiiIii . iIii1I11I1II1
 if 74 - 74: Ii1I / iIii1I11I1II1 + OOooOOo . II111iiii
 if 65 - 65: OOooOOo * I11i * Oo0Ooo
 o00oo00oo = map_request . target_eid
 ii1I1 = map_request . target_group
 oOoo0OooOOo00 = lisp_print_eid_tuple ( o00oo00oo , ii1I1 )
 iI1III = map_request . nonce
 oo0oOOo0 = LISP_DDT_ACTION_NULL
 if 21 - 21: Ii1I . iIii1I11I1II1
 if 84 - 84: OOooOOo
 if 67 - 67: I1IiiI % OoO0O00 % o0oOOo0O0Ooo % IiII
 if 33 - 33: ooOoO0o % I1IiiI
 if 98 - 98: oO0o . o0oOOo0O0Ooo + II111iiii
 O0oooOO0O = None
 if ( lisp_i_am_ms ) :
  ooOOOo0o0oo = lisp_site_eid_lookup ( o00oo00oo , ii1I1 , False )
  if ( ooOOOo0o0oo == None ) : return
  if 70 - 70: oO0o % OoooooooOO * I1IiiI - OoOoOO00 * OoOoOO00 . OOooOOo
  if ( ooOOOo0o0oo . registered ) :
   oo0oOOo0 = LISP_DDT_ACTION_MS_ACK
   oooOooOO = 1440
  else :
   o00oo00oo , ii1I1 , oo0oOOo0 = lisp_ms_compute_neg_prefix ( o00oo00oo , ii1I1 )
   oo0oOOo0 = LISP_DDT_ACTION_MS_NOT_REG
   oooOooOO = 1
   if 9 - 9: iII111i * Oo0Ooo % iII111i % Oo0Ooo * II111iiii
 else :
  O0oooOO0O = lisp_ddt_cache_lookup ( o00oo00oo , ii1I1 , False )
  if ( O0oooOO0O == None ) :
   oo0oOOo0 = LISP_DDT_ACTION_NOT_AUTH
   oooOooOO = 0
   lprint ( "DDT delegation entry not found for EID {}" . format ( green ( oOoo0OooOOo00 , False ) ) )
   if 71 - 71: II111iiii + I1ii11iIi11i * II111iiii
  elif ( O0oooOO0O . is_auth_prefix ( ) ) :
   if 59 - 59: OoO0O00
   if 81 - 81: i11iIiiIii
   if 57 - 57: Oo0Ooo * iIii1I11I1II1 - OoOoOO00 % iII111i % I1ii11iIi11i + Ii1I
   if 82 - 82: IiII * Oo0Ooo - iIii1I11I1II1 - i11iIiiIii
   oo0oOOo0 = LISP_DDT_ACTION_DELEGATION_HOLE
   oooOooOO = 15
   oO0 = O0oooOO0O . print_eid_tuple ( )
   lprint ( ( "DDT delegation entry not found but auth-prefix {} " + "found for EID {}" ) . format ( oO0 ,
   # OoO0O00 / OoO0O00 . I1ii11iIi11i
 green ( oOoo0OooOOo00 , False ) ) )
   if 100 - 100: iIii1I11I1II1 % II111iiii - I1ii11iIi11i . iIii1I11I1II1 + IiII % iIii1I11I1II1
   if ( ii1I1 . is_null ( ) ) :
    o00oo00oo = lisp_ddt_compute_neg_prefix ( o00oo00oo , O0oooOO0O ,
 lisp_ddt_cache )
   else :
    ii1I1 = lisp_ddt_compute_neg_prefix ( ii1I1 , O0oooOO0O ,
 lisp_ddt_cache )
    o00oo00oo = lisp_ddt_compute_neg_prefix ( o00oo00oo , O0oooOO0O ,
 O0oooOO0O . source_cache )
    if 48 - 48: Ii1I % i1IIi
   O0oooOO0O = None
  else :
   oO0 = O0oooOO0O . print_eid_tuple ( )
   lprint ( "DDT delegation entry {} found for EID {}" . format ( oO0 , green ( oOoo0OooOOo00 , False ) ) )
   if 38 - 38: OOooOOo / I1ii11iIi11i % oO0o / o0oOOo0O0Ooo
   oooOooOO = 1440
   if 54 - 54: OoOoOO00 * OoooooooOO - OoO0O00 * OoOoOO00 % I1ii11iIi11i * I11i
   if 34 - 34: I11i - oO0o + I11i * OoooooooOO * I11i
   if 73 - 73: OOooOOo * iII111i * OoO0O00
   if 11 - 11: I1Ii111 * II111iiii
   if 3 - 3: Oo0Ooo * OOooOOo
   if 13 - 13: I1Ii111 + i11iIiiIii / OOooOOo
 i1II1IiiIi = lisp_build_map_referral ( o00oo00oo , ii1I1 , O0oooOO0O , oo0oOOo0 , oooOooOO , iI1III )
 iI1III = map_request . nonce >> 32
 if ( map_request . nonce != 0 and iI1III != 0xdfdf0e1d ) : port = LISP_CTRL_PORT
 lisp_send_map_referral ( lisp_sockets , i1II1IiiIi , ecm_source , port )
 return
 if 98 - 98: I1IiiI * Oo0Ooo
 if 9 - 9: O0 / i11iIiiIii . iIii1I11I1II1 . IiII
 if 14 - 14: OoOoOO00 . OOooOOo - Oo0Ooo + I1Ii111 % ooOoO0o
 if 95 - 95: OoO0O00 * II111iiii + i1IIi
 if 22 - 22: Ii1I / ooOoO0o % I11i + OoO0O00 . ooOoO0o
 if 61 - 61: O0 - iIii1I11I1II1 * Oo0Ooo . Ii1I + O0
 if 20 - 20: ooOoO0o / ooOoO0o - Ii1I - ooOoO0o
 if 93 - 93: O0 * OoOoOO00 * iIii1I11I1II1
 if 3 - 3: I1ii11iIi11i - O0
 if 46 - 46: iII111i
 if 99 - 99: oO0o
 if 85 - 85: I1Ii111 * iIii1I11I1II1 . OoOoOO00
 if 20 - 20: I11i * O0 - OoooooooOO * OOooOOo % oO0o * iII111i
def lisp_find_negative_mask_len ( eid , entry_prefix , neg_prefix ) :
 O0oooo = eid . hash_address ( entry_prefix )
 o0oO0ooOOoOo = eid . addr_length ( ) * 8
 iI1iiII1iii111 = 0
 if 24 - 24: I1IiiI
 if 63 - 63: I11i - iIii1I11I1II1 * Ii1I + OoooooooOO . i11iIiiIii
 if 94 - 94: OoO0O00 . oO0o . OoOoOO00 * i11iIiiIii
 if 96 - 96: i1IIi . OoO0O00 . OoO0O00 - o0oOOo0O0Ooo - Ii1I
 for iI1iiII1iii111 in range ( o0oO0ooOOoOo ) :
  I1IIiI = 1 << ( o0oO0ooOOoOo - iI1iiII1iii111 - 1 )
  if ( O0oooo & I1IIiI ) : break
  if 30 - 30: I1Ii111 + oO0o + iIii1I11I1II1 % OoO0O00 / I1IiiI
  if 55 - 55: Ii1I
 if ( iI1iiII1iii111 > neg_prefix . mask_len ) : neg_prefix . mask_len = iI1iiII1iii111
 return
 if 14 - 14: i1IIi * I1ii11iIi11i
 if 77 - 77: ooOoO0o . II111iiii
 if 41 - 41: IiII
 if 27 - 27: IiII / IiII
 if 91 - 91: Ii1I
 if 93 - 93: OoO0O00 * OoO0O00 * I1ii11iIi11i * OoO0O00 * o0oOOo0O0Ooo
 if 84 - 84: I1Ii111 * OoO0O00 - ooOoO0o - Oo0Ooo . OoO0O00 % oO0o
 if 98 - 98: OoO0O00 . i1IIi
 if 58 - 58: i1IIi * O0 + I1ii11iIi11i . IiII
 if 11 - 11: OOooOOo + iIii1I11I1II1 - ooOoO0o * OoO0O00 * i11iIiiIii
def lisp_neg_prefix_walk ( entry , parms ) :
 o00oo00oo , iIIiIII , O0oo00000o00 = parms
 if 78 - 78: Oo0Ooo
 if ( iIIiIII == None ) :
  if ( entry . eid . instance_id != o00oo00oo . instance_id ) :
   return ( [ True , parms ] )
   if 90 - 90: OoooooooOO * i11iIiiIii / OoOoOO00 % I1ii11iIi11i - iIii1I11I1II1 % i1IIi
  if ( entry . eid . afi != o00oo00oo . afi ) : return ( [ True , parms ] )
 else :
  if ( entry . eid . is_more_specific ( iIIiIII ) == False ) :
   return ( [ True , parms ] )
   if 71 - 71: Oo0Ooo % i11iIiiIii
   if 54 - 54: IiII . iII111i * OOooOOo / ooOoO0o . i11iIiiIii
   if 91 - 91: ooOoO0o % iII111i
   if 41 - 41: o0oOOo0O0Ooo . I1Ii111 + IiII / oO0o
   if 86 - 86: iII111i % OoOoOO00 . i11iIiiIii . I1Ii111 + II111iiii . i1IIi
   if 88 - 88: O0
 lisp_find_negative_mask_len ( o00oo00oo , entry . eid , O0oo00000o00 )
 return ( [ True , parms ] )
 if 28 - 28: OOooOOo % IiII * Oo0Ooo / OoO0O00
 if 67 - 67: Oo0Ooo * I11i - IiII + I1Ii111
 if 90 - 90: iII111i % II111iiii % o0oOOo0O0Ooo + o0oOOo0O0Ooo + II111iiii
 if 54 - 54: OoooooooOO . IiII - oO0o
 if 26 - 26: o0oOOo0O0Ooo - i1IIi / I1ii11iIi11i / OoooooooOO . i1IIi
 if 22 - 22: o0oOOo0O0Ooo * I1Ii111 * I1ii11iIi11i . OoOoOO00 . i1IIi % ooOoO0o
 if 67 - 67: I11i
 if 95 - 95: OoO0O00 % I1Ii111
def lisp_ddt_compute_neg_prefix ( eid , ddt_entry , cache ) :
 if 49 - 49: II111iiii % OoOoOO00 % OOooOOo
 if 40 - 40: I1ii11iIi11i + i1IIi
 if 9 - 9: OOooOOo
 if 74 - 74: OoOoOO00 - OOooOOo % OoOoOO00
 if ( eid . is_binary ( ) == False ) : return ( eid )
 if 82 - 82: I11i % IiII + Oo0Ooo + iIii1I11I1II1 - I11i - I1IiiI
 O0oo00000o00 = lisp_address ( eid . afi , "" , 0 , 0 )
 O0oo00000o00 . copy_address ( eid )
 O0oo00000o00 . mask_len = 0
 if 65 - 65: IiII / O0 * II111iiii + oO0o
 OO0OoooO0 = ddt_entry . print_eid_tuple ( )
 iIIiIII = ddt_entry . eid
 if 56 - 56: oO0o + o0oOOo0O0Ooo - i1IIi % Ii1I - II111iiii
 if 7 - 7: OoO0O00 . i1IIi * OoooooooOO . II111iiii * O0
 if 9 - 9: iII111i * iII111i / iIii1I11I1II1 * IiII . II111iiii
 if 3 - 3: I1IiiI - I1IiiI - iIii1I11I1II1
 if 29 - 29: Oo0Ooo
 eid , iIIiIII , O0oo00000o00 = cache . walk_cache ( lisp_neg_prefix_walk ,
 ( eid , iIIiIII , O0oo00000o00 ) )
 if 35 - 35: OoOoOO00 + II111iiii
 if 46 - 46: O0 / I1ii11iIi11i + OOooOOo - I1Ii111 + I1IiiI - ooOoO0o
 if 96 - 96: IiII + i1IIi - I11i * I11i - OoO0O00 % II111iiii
 if 47 - 47: I1Ii111 . i11iIiiIii + oO0o . I1ii11iIi11i
 O0oo00000o00 . mask_address ( O0oo00000o00 . mask_len )
 if 12 - 12: iIii1I11I1II1 % I1Ii111 * OoOoOO00 / OoooooooOO % OoooooooOO
 lprint ( ( "Least specific prefix computed from ddt-cache for EID {} " + "using auth-prefix {} is {}" ) . format ( green ( eid . print_address ( ) , False ) ,
 # o0oOOo0O0Ooo % o0oOOo0O0Ooo . iIii1I11I1II1 + OoOoOO00 * OoO0O00
 OO0OoooO0 , O0oo00000o00 . print_prefix ( ) ) )
 return ( O0oo00000o00 )
 if 57 - 57: i11iIiiIii * i11iIiiIii % I1Ii111 - iII111i * O0 - Ii1I
 if 63 - 63: IiII % OoooooooOO * OoOoOO00 * iIii1I11I1II1 . iII111i % oO0o
 if 58 - 58: I11i * iII111i + I11i % OoO0O00
 if 19 - 19: Oo0Ooo
 if 43 - 43: oO0o % ooOoO0o
 if 36 - 36: I11i / I1IiiI + O0 % II111iiii
 if 24 - 24: I1Ii111 / o0oOOo0O0Ooo - OOooOOo / IiII
 if 7 - 7: OoooooooOO - i11iIiiIii * i11iIiiIii / oO0o * i1IIi % OoooooooOO
def lisp_ms_compute_neg_prefix ( eid , group ) :
 O0oo00000o00 = lisp_address ( eid . afi , "" , 0 , 0 )
 O0oo00000o00 . copy_address ( eid )
 O0oo00000o00 . mask_len = 0
 II1iii1iiIIiI = lisp_address ( group . afi , "" , 0 , 0 )
 II1iii1iiIIiI . copy_address ( group )
 II1iii1iiIIiI . mask_len = 0
 iIIiIII = None
 if 24 - 24: I1Ii111 % iIii1I11I1II1
 if 87 - 87: OoOoOO00 - II111iiii + Oo0Ooo
 if 44 - 44: i1IIi + I1ii11iIi11i / iIii1I11I1II1
 if 47 - 47: I1Ii111
 if 41 - 41: IiII
 if ( group . is_null ( ) ) :
  O0oooOO0O = lisp_ddt_cache . lookup_cache ( eid , False )
  if ( O0oooOO0O == None ) :
   O0oo00000o00 . mask_len = O0oo00000o00 . host_mask_len ( )
   II1iii1iiIIiI . mask_len = II1iii1iiIIiI . host_mask_len ( )
   return ( [ O0oo00000o00 , II1iii1iiIIiI , LISP_DDT_ACTION_NOT_AUTH ] )
   if 25 - 25: I11i % iIii1I11I1II1
  iiiii1IIII1 = lisp_sites_by_eid
  if ( O0oooOO0O . is_auth_prefix ( ) ) : iIIiIII = O0oooOO0O . eid
 else :
  O0oooOO0O = lisp_ddt_cache . lookup_cache ( group , False )
  if ( O0oooOO0O == None ) :
   O0oo00000o00 . mask_len = O0oo00000o00 . host_mask_len ( )
   II1iii1iiIIiI . mask_len = II1iii1iiIIiI . host_mask_len ( )
   return ( [ O0oo00000o00 , II1iii1iiIIiI , LISP_DDT_ACTION_NOT_AUTH ] )
   if 54 - 54: o0oOOo0O0Ooo * iII111i * i1IIi + IiII
  if ( O0oooOO0O . is_auth_prefix ( ) ) : iIIiIII = O0oooOO0O . group
  if 57 - 57: oO0o - OoO0O00 . oO0o . OoO0O00 . I1ii11iIi11i
  group , iIIiIII , II1iii1iiIIiI = lisp_sites_by_eid . walk_cache ( lisp_neg_prefix_walk , ( group , iIIiIII , II1iii1iiIIiI ) )
  if 57 - 57: OOooOOo / II111iiii . Ii1I / I1Ii111 . OoooooooOO
  if 18 - 18: IiII % I1IiiI % i11iIiiIii . II111iiii / Oo0Ooo
  II1iii1iiIIiI . mask_address ( II1iii1iiIIiI . mask_len )
  if 88 - 88: i1IIi / Ii1I . iII111i
  lprint ( ( "Least specific prefix computed from site-cache for " + "group EID {} using auth-prefix {} is {}" ) . format ( group . print_address ( ) , iIIiIII . print_prefix ( ) if ( iIIiIII != None ) else "'not found'" ,
  # iIii1I11I1II1 . ooOoO0o % I11i
  # OoooooooOO + ooOoO0o * o0oOOo0O0Ooo + I1IiiI
  # oO0o . I1Ii111 * I1Ii111
 II1iii1iiIIiI . print_prefix ( ) ) )
  if 32 - 32: I1Ii111 . Ii1I / i1IIi
  iiiii1IIII1 = O0oooOO0O . source_cache
  if 2 - 2: OOooOOo * ooOoO0o / I11i + OoO0O00
  if 96 - 96: II111iiii * OoO0O00 + I1ii11iIi11i + OoOoOO00 / II111iiii . iII111i
  if 64 - 64: iII111i % Oo0Ooo
  if 79 - 79: IiII + iII111i / II111iiii . i1IIi + iIii1I11I1II1
  if 32 - 32: Ii1I * iII111i
 oo0oOOo0 = LISP_DDT_ACTION_DELEGATION_HOLE if ( iIIiIII != None ) else LISP_DDT_ACTION_NOT_AUTH
 if 52 - 52: I11i
 if 100 - 100: Oo0Ooo % Oo0Ooo % I1ii11iIi11i
 if 33 - 33: I1Ii111 . I1Ii111 * i1IIi
 if 22 - 22: I1ii11iIi11i . II111iiii + iIii1I11I1II1 / OoooooooOO . ooOoO0o
 if 13 - 13: II111iiii
 if 36 - 36: iII111i - oO0o / Oo0Ooo / O0 . OoO0O00 . i1IIi
 eid , iIIiIII , O0oo00000o00 = iiiii1IIII1 . walk_cache ( lisp_neg_prefix_walk ,
 ( eid , iIIiIII , O0oo00000o00 ) )
 if 19 - 19: O0 . OoooooooOO % iIii1I11I1II1 - Ii1I . Ii1I + I1IiiI
 if 98 - 98: oO0o . Oo0Ooo
 if 9 - 9: I1Ii111 % IiII - i11iIiiIii - OOooOOo % iII111i % OoooooooOO
 if 6 - 6: i1IIi - II111iiii * OoOoOO00 + oO0o
 O0oo00000o00 . mask_address ( O0oo00000o00 . mask_len )
 if 6 - 6: I1IiiI - ooOoO0o + I1IiiI + OoO0O00 - i11iIiiIii % ooOoO0o
 lprint ( ( "Least specific prefix computed from site-cache for EID {} " + "using auth-prefix {} is {}" ) . format ( green ( eid . print_address ( ) , False ) ,
 # OoO0O00 / OOooOOo . I11i + o0oOOo0O0Ooo
 # Ii1I / I1ii11iIi11i + Ii1I
 iIIiIII . print_prefix ( ) if ( iIIiIII != None ) else "'not found'" , O0oo00000o00 . print_prefix ( ) ) )
 if 38 - 38: i1IIi * iIii1I11I1II1 * iII111i + OoOoOO00
 if 64 - 64: OoO0O00 % o0oOOo0O0Ooo
 return ( [ O0oo00000o00 , II1iii1iiIIiI , oo0oOOo0 ] )
 if 72 - 72: O0 + OoOoOO00 % OOooOOo / oO0o / IiII
 if 98 - 98: Oo0Ooo . II111iiii * I11i
 if 39 - 39: IiII * o0oOOo0O0Ooo + Ii1I - I11i
 if 70 - 70: oO0o * ooOoO0o / ooOoO0o - Ii1I * Ii1I % OOooOOo
 if 91 - 91: OoO0O00 - OoO0O00 % O0
 if 67 - 67: ooOoO0o * i1IIi
 if 66 - 66: o0oOOo0O0Ooo - I1ii11iIi11i . OoOoOO00 / iII111i - Ii1I - i1IIi
 if 97 - 97: oO0o % iII111i - OOooOOo . OoooooooOO
def lisp_ms_send_map_referral ( lisp_sockets , map_request , ecm_source , port ,
 action , eid_prefix , group_prefix ) :
 if 94 - 94: Oo0Ooo
 o00oo00oo = map_request . target_eid
 ii1I1 = map_request . target_group
 iI1III = map_request . nonce
 if 10 - 10: i11iIiiIii / I1ii11iIi11i . i1IIi + i1IIi * iII111i
 if ( action == LISP_DDT_ACTION_MS_ACK ) : oooOooOO = 1440
 if 64 - 64: II111iiii % I1ii11iIi11i . OoOoOO00 . iIii1I11I1II1 / I1ii11iIi11i
 if 43 - 43: OoooooooOO * I1IiiI
 if 2 - 2: OOooOOo / oO0o + I1ii11iIi11i + i11iIiiIii % iIii1I11I1II1 . I1ii11iIi11i
 if 100 - 100: Oo0Ooo * ooOoO0o + Ii1I / iII111i * o0oOOo0O0Ooo
 OOoO000o00000 = lisp_map_referral ( )
 OOoO000o00000 . record_count = 1
 OOoO000o00000 . nonce = iI1III
 i1II1IiiIi = OOoO000o00000 . encode ( )
 OOoO000o00000 . print_map_referral ( )
 if 26 - 26: I1Ii111 * OoOoOO00
 iiI1I1IIi = False
 if 38 - 38: II111iiii
 if 50 - 50: OoOoOO00 . IiII - OOooOOo
 if 46 - 46: iIii1I11I1II1
 if 97 - 97: O0 * OOooOOo - o0oOOo0O0Ooo % o0oOOo0O0Ooo * II111iiii % I11i
 if 65 - 65: iIii1I11I1II1 / OOooOOo
 if 2 - 2: I11i - OOooOOo / o0oOOo0O0Ooo
 if ( action == LISP_DDT_ACTION_SITE_NOT_FOUND ) :
  eid_prefix , group_prefix , action = lisp_ms_compute_neg_prefix ( o00oo00oo ,
 ii1I1 )
  oooOooOO = 15
  if 14 - 14: I11i + Oo0Ooo + i11iIiiIii - i1IIi . O0
 if ( action == LISP_DDT_ACTION_MS_NOT_REG ) : oooOooOO = 1
 if ( action == LISP_DDT_ACTION_MS_ACK ) : oooOooOO = 1440
 if ( action == LISP_DDT_ACTION_DELEGATION_HOLE ) : oooOooOO = 15
 if ( action == LISP_DDT_ACTION_NOT_AUTH ) : oooOooOO = 0
 if 47 - 47: o0oOOo0O0Ooo / i1IIi * IiII
 iiIi11I1I1 = False
 OoIiIii = 0
 O0oooOO0O = lisp_ddt_cache_lookup ( o00oo00oo , ii1I1 , False )
 if ( O0oooOO0O != None ) :
  OoIiIii = len ( O0oooOO0O . delegation_set )
  iiIi11I1I1 = O0oooOO0O . is_ms_peer_entry ( )
  O0oooOO0O . map_referrals_sent += 1
  if 96 - 96: I1IiiI
  if 34 - 34: Ii1I * i1IIi + OoooooooOO . oO0o
  if 30 - 30: I1Ii111 % IiII / II111iiii
  if 68 - 68: oO0o / O0 / OOooOOo
  if 3 - 3: o0oOOo0O0Ooo / o0oOOo0O0Ooo
 if ( action == LISP_DDT_ACTION_NOT_AUTH ) : iiI1I1IIi = True
 if ( action in ( LISP_DDT_ACTION_MS_REFERRAL , LISP_DDT_ACTION_MS_ACK ) ) :
  iiI1I1IIi = ( iiIi11I1I1 == False )
  if 17 - 17: OoO0O00 * i1IIi
  if 50 - 50: OoOoOO00 + I11i
  if 56 - 56: OOooOOo * OOooOOo + I1IiiI % I1IiiI - I11i
  if 1 - 1: OoooooooOO . ooOoO0o - i1IIi
  if 73 - 73: iIii1I11I1II1 - I1Ii111 % Oo0Ooo . O0
 iI1iii1IIIIi = lisp_eid_record ( )
 iI1iii1IIIIi . rloc_count = OoIiIii
 iI1iii1IIIIi . authoritative = True
 iI1iii1IIIIi . action = action
 iI1iii1IIIIi . ddt_incomplete = iiI1I1IIi
 iI1iii1IIIIi . eid = eid_prefix
 iI1iii1IIIIi . group = group_prefix
 iI1iii1IIIIi . record_ttl = oooOooOO
 if 16 - 16: OoO0O00 / Oo0Ooo / IiII . Oo0Ooo - OoooooooOO
 i1II1IiiIi += iI1iii1IIIIi . encode ( )
 iI1iii1IIIIi . print_record ( "  " , True )
 if 5 - 5: OoOoOO00 . I11i
 if 28 - 28: I11i % OOooOOo + Oo0Ooo / OoO0O00 % o0oOOo0O0Ooo + OoO0O00
 if 20 - 20: ooOoO0o . iII111i % OOooOOo + i11iIiiIii
 if 64 - 64: i1IIi . o0oOOo0O0Ooo * I1Ii111 - O0
 if ( OoIiIii != 0 ) :
  for O0O0Oo0o in O0oooOO0O . delegation_set :
   oooO0oo00oOOoo0O = lisp_rloc_record ( )
   oooO0oo00oOOoo0O . rloc = O0O0Oo0o . delegate_address
   oooO0oo00oOOoo0O . priority = O0O0Oo0o . priority
   oooO0oo00oOOoo0O . weight = O0O0Oo0o . weight
   oooO0oo00oOOoo0O . mpriority = 255
   oooO0oo00oOOoo0O . mweight = 0
   oooO0oo00oOOoo0O . reach_bit = True
   i1II1IiiIi += oooO0oo00oOOoo0O . encode ( )
   oooO0oo00oOOoo0O . print_record ( "    " )
   if 76 - 76: I1IiiI % Ii1I + OoO0O00 + I1ii11iIi11i * II111iiii + Oo0Ooo
   if 3 - 3: Ii1I - I1IiiI + O0
   if 90 - 90: Ii1I + OoooooooOO . i11iIiiIii / Oo0Ooo % OoOoOO00 / IiII
   if 45 - 45: OoooooooOO / oO0o . I1ii11iIi11i + OOooOOo
   if 54 - 54: Ii1I - o0oOOo0O0Ooo + OoOoOO00 / OoooooooOO
   if 61 - 61: I11i / IiII % OoooooooOO - i11iIiiIii * i1IIi % o0oOOo0O0Ooo
   if 67 - 67: o0oOOo0O0Ooo - Ii1I
 if ( map_request . nonce != 0 ) : port = LISP_CTRL_PORT
 lisp_send_map_referral ( lisp_sockets , i1II1IiiIi , ecm_source , port )
 return
 if 29 - 29: OoOoOO00 . I1ii11iIi11i
 if 24 - 24: OOooOOo + i1IIi . I11i . OoOoOO00 + OoooooooOO
 if 98 - 98: ooOoO0o + i1IIi / I1IiiI
 if 1 - 1: IiII . OoooooooOO + II111iiii
 if 6 - 6: O0 * Oo0Ooo
 if 20 - 20: OoooooooOO * i1IIi * IiII / OoooooooOO - Oo0Ooo / i11iIiiIii
 if 28 - 28: iIii1I11I1II1 % OOooOOo * I1IiiI
 if 28 - 28: O0 . OoOoOO00
def lisp_send_negative_map_reply ( sockets , eid , group , nonce , dest , port , ttl ,
 xtr_id , pubsub ) :
 if 27 - 27: I1ii11iIi11i / II111iiii + O0 % I1ii11iIi11i
 lprint ( "Build negative Map-Reply EID-prefix {}, nonce 0x{} to ITR {}" . format ( lisp_print_eid_tuple ( eid , group ) , lisp_hex_string ( nonce ) ,
 # oO0o / i1IIi / Oo0Ooo . iIii1I11I1II1 . ooOoO0o
 red ( dest . print_address ( ) , False ) ) )
 if 41 - 41: OoooooooOO - Oo0Ooo / I1ii11iIi11i / OoO0O00 - II111iiii
 oo0oOOo0 = LISP_NATIVE_FORWARD_ACTION if group . is_null ( ) else LISP_DROP_ACTION
 if 73 - 73: oO0o - o0oOOo0O0Ooo
 if 50 - 50: iIii1I11I1II1 - i11iIiiIii / iII111i + ooOoO0o / OOooOOo
 if 80 - 80: IiII / OoooooooOO
 if 69 - 69: OoOoOO00 + IiII
 if 18 - 18: O0 / I11i
 if ( lisp_get_eid_hash ( eid ) != None ) :
  oo0oOOo0 = LISP_SEND_MAP_REQUEST_ACTION
  if 10 - 10: I1Ii111 * i1IIi
  if 48 - 48: Oo0Ooo % i1IIi / iII111i . O0
 i1II1IiiIi = lisp_build_map_reply ( eid , group , [ ] , nonce , oo0oOOo0 , ttl , False ,
 None , False , False )
 if 27 - 27: I11i + iIii1I11I1II1 - i11iIiiIii
 if 81 - 81: I11i + oO0o * iIii1I11I1II1 * IiII
 if 7 - 7: I11i - I1IiiI . iII111i + O0 / iIii1I11I1II1 - I1Ii111
 if 32 - 32: ooOoO0o
 if ( pubsub ) :
  lisp_process_pubsub ( sockets , i1II1IiiIi , eid , dest , port , nonce , ttl ,
 xtr_id )
 else :
  lisp_send_map_reply ( sockets , i1II1IiiIi , dest , port )
  if 9 - 9: I1Ii111
 return
 if 77 - 77: OoooooooOO * I1Ii111
 if 63 - 63: IiII * oO0o * iIii1I11I1II1
 if 18 - 18: II111iiii * o0oOOo0O0Ooo % i11iIiiIii . OoOoOO00
 if 40 - 40: oO0o - o0oOOo0O0Ooo * II111iiii
 if 4 - 4: O0
 if 9 - 9: Oo0Ooo . i1IIi - i1IIi + I1Ii111 * ooOoO0o . I1ii11iIi11i
 if 17 - 17: I11i * I1ii11iIi11i % I1IiiI + OoO0O00 + IiII
def lisp_retransmit_ddt_map_request ( mr ) :
 OooOOOOOO = mr . mr_source . print_address ( )
 oO0oOoo = mr . print_eid_tuple ( )
 iI1III = mr . nonce
 if 68 - 68: i11iIiiIii
 if 29 - 29: ooOoO0o - iII111i + IiII % Ii1I - oO0o - ooOoO0o
 if 43 - 43: oO0o
 if 22 - 22: I1Ii111 + i11iIiiIii
 if 49 - 49: O0 % II111iiii . OOooOOo + iII111i + iIii1I11I1II1 / i11iIiiIii
 if ( mr . last_request_sent_to ) :
  OoO0Oo = mr . last_request_sent_to . print_address ( )
  iii = lisp_referral_cache_lookup ( mr . last_cached_prefix [ 0 ] ,
 mr . last_cached_prefix [ 1 ] , True )
  if ( iii and iii . referral_set . has_key ( OoO0Oo ) ) :
   iii . referral_set [ OoO0Oo ] . no_responses += 1
   if 78 - 78: I1IiiI * I11i % OOooOOo + Ii1I + OoOoOO00
   if 23 - 23: iII111i / Oo0Ooo % OoooooooOO * OoooooooOO . iII111i / I1ii11iIi11i
   if 30 - 30: oO0o - OoOoOO00 . I1IiiI
   if 17 - 17: OoOoOO00
   if 76 - 76: I1ii11iIi11i - ooOoO0o % OoooooooOO / Oo0Ooo % IiII / ooOoO0o
   if 57 - 57: O0
   if 23 - 23: OoO0O00 / II111iiii . I1ii11iIi11i . O0
 if ( mr . retry_count == LISP_MAX_MAP_NOTIFY_RETRIES ) :
  lprint ( "DDT Map-Request retry limit reached for EID {}, nonce 0x{}" . format ( green ( oO0oOoo , False ) , lisp_hex_string ( iI1III ) ) )
  if 13 - 13: I1ii11iIi11i
  mr . dequeue_map_request ( )
  return
  if 32 - 32: OOooOOo / I11i + I1Ii111 / Oo0Ooo * OoooooooOO / II111iiii
  if 8 - 8: OoO0O00
 mr . retry_count += 1
 if 17 - 17: iIii1I11I1II1 - Oo0Ooo
 IiIIi1I1I11Ii = green ( OooOOOOOO , False )
 oOo0OOOOOO = green ( oO0oOoo , False )
 lprint ( "Retransmit DDT {} from {}ITR {} EIDs: {} -> {}, nonce 0x{}" . format ( bold ( "Map-Request" , False ) , "P" if mr . from_pitr else "" ,
 # OoO0O00 / O0
 red ( mr . itr . print_address ( ) , False ) , IiIIi1I1I11Ii , oOo0OOOOOO ,
 lisp_hex_string ( iI1III ) ) )
 if 60 - 60: iIii1I11I1II1 / Oo0Ooo / oO0o + iII111i
 if 66 - 66: iIii1I11I1II1 . O0 * IiII . ooOoO0o + i1IIi
 if 83 - 83: o0oOOo0O0Ooo / II111iiii + I1IiiI - iII111i + OoO0O00
 if 67 - 67: I1Ii111 - OoOoOO00 . i11iIiiIii - I1Ii111 . i11iIiiIii
 lisp_send_ddt_map_request ( mr , False )
 if 25 - 25: I11i % I1Ii111 + Ii1I
 if 46 - 46: ooOoO0o + Oo0Ooo + oO0o / II111iiii . iIii1I11I1II1 * I1IiiI
 if 87 - 87: I11i + iIii1I11I1II1
 if 91 - 91: oO0o
 mr . retransmit_timer = threading . Timer ( LISP_DDT_MAP_REQUEST_INTERVAL ,
 lisp_retransmit_ddt_map_request , [ mr ] )
 mr . retransmit_timer . start ( )
 return
 if 58 - 58: i11iIiiIii / Ii1I - OoooooooOO
 if 25 - 25: i1IIi * ooOoO0o % OOooOOo / I1IiiI
 if 75 - 75: i11iIiiIii
 if 38 - 38: iIii1I11I1II1
 if 80 - 80: OoO0O00
 if 72 - 72: I11i * II111iiii
 if 82 - 82: I1Ii111 . OoO0O00 * II111iiii
 if 99 - 99: iIii1I11I1II1 / iII111i % i1IIi - II111iiii / OoO0O00
def lisp_get_referral_node ( referral , source_eid , dest_eid ) :
 if 33 - 33: OoooooooOO / i1IIi . Ii1I
 if 96 - 96: OoOoOO00 / Oo0Ooo . II111iiii / ooOoO0o
 if 56 - 56: IiII - ooOoO0o % oO0o / Oo0Ooo * oO0o % O0
 if 71 - 71: iII111i / II111iiii - II111iiii / I1IiiI
 Iii11 = [ ]
 for oo00OO in referral . referral_set . values ( ) :
  if ( oo00OO . updown == False ) : continue
  if ( len ( Iii11 ) == 0 or Iii11 [ 0 ] . priority == oo00OO . priority ) :
   Iii11 . append ( oo00OO )
  elif ( Iii11 [ 0 ] . priority > oo00OO . priority ) :
   Iii11 = [ ]
   Iii11 . append ( oo00OO )
   if 49 - 49: iIii1I11I1II1 % Oo0Ooo % I11i * Ii1I - OoO0O00
   if 15 - 15: i11iIiiIii + o0oOOo0O0Ooo . Ii1I . I1IiiI
   if 8 - 8: iII111i % II111iiii + IiII
 iii1Ii = len ( Iii11 )
 if ( iii1Ii == 0 ) : return ( None )
 if 69 - 69: IiII
 o0o0oooO00O0 = dest_eid . hash_address ( source_eid )
 o0o0oooO00O0 = o0o0oooO00O0 % iii1Ii
 return ( Iii11 [ o0o0oooO00O0 ] )
 if 36 - 36: I1IiiI / oO0o
 if 72 - 72: i1IIi - I1ii11iIi11i . OOooOOo + I1Ii111 - ooOoO0o
 if 69 - 69: o0oOOo0O0Ooo * I1IiiI - I11i
 if 11 - 11: OOooOOo * O0
 if 43 - 43: I1IiiI - i1IIi . i1IIi * II111iiii
 if 64 - 64: I1IiiI * iIii1I11I1II1 % I1Ii111
 if 22 - 22: OoooooooOO + I1Ii111 . o0oOOo0O0Ooo * Oo0Ooo
def lisp_send_ddt_map_request ( mr , send_to_root ) :
 o0O = mr . lisp_sockets
 iI1III = mr . nonce
 oOooOo000O = mr . itr
 I1I11IIII1I1 = mr . mr_source
 oOoo0OooOOo00 = mr . print_eid_tuple ( )
 if 74 - 74: OoO0O00
 if 23 - 23: O0 + Oo0Ooo % IiII
 if 99 - 99: I1ii11iIi11i + O0
 if 26 - 26: iIii1I11I1II1 * II111iiii
 if 59 - 59: OoOoOO00 . iIii1I11I1II1 / I1ii11iIi11i - OoO0O00 - OoOoOO00
 if ( mr . send_count == 8 ) :
  lprint ( "Giving up on map-request-queue entry {}, nonce 0x{}" . format ( green ( oOoo0OooOOo00 , False ) , lisp_hex_string ( iI1III ) ) )
  if 69 - 69: o0oOOo0O0Ooo
  mr . dequeue_map_request ( )
  return
  if 67 - 67: OoO0O00 + iIii1I11I1II1
  if 20 - 20: OoOoOO00 + Oo0Ooo - OoOoOO00
  if 40 - 40: oO0o . O0 / IiII % I11i * i1IIi
  if 75 - 75: Ii1I . o0oOOo0O0Ooo / I11i
  if 31 - 31: I11i + OOooOOo / I1IiiI / iIii1I11I1II1 + o0oOOo0O0Ooo
  if 76 - 76: i1IIi
 if ( send_to_root ) :
  o000oOOooO00 = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  O0Oi1iIIiI1i = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  mr . tried_root = True
  lprint ( "Jumping up to root for EID {}" . format ( green ( oOoo0OooOOo00 , False ) ) )
 else :
  o000oOOooO00 = mr . eid
  O0Oi1iIIiI1i = mr . group
  if 18 - 18: i1IIi
  if 42 - 42: II111iiii - i1IIi . oO0o % OOooOOo % ooOoO0o - i11iIiiIii
  if 23 - 23: OOooOOo + iIii1I11I1II1 - i1IIi
  if 72 - 72: OOooOOo . I1IiiI * O0 + i11iIiiIii - iII111i
  if 79 - 79: o0oOOo0O0Ooo + I1ii11iIi11i
 i1ii1iIiI1 = lisp_referral_cache_lookup ( o000oOOooO00 , O0Oi1iIIiI1i , False )
 if ( i1ii1iIiI1 == None ) :
  lprint ( "No referral cache entry found" )
  lisp_send_negative_map_reply ( o0O , o000oOOooO00 , O0Oi1iIIiI1i ,
 iI1III , oOooOo000O , mr . sport , 15 , None , False )
  return
  if 60 - 60: IiII - I1Ii111 * iIii1I11I1II1 . I1ii11iIi11i
  if 45 - 45: i1IIi - OoO0O00 % Oo0Ooo
 i1111I1I = i1ii1iIiI1 . print_eid_tuple ( )
 lprint ( "Found referral cache entry {}, referral-type: {}" . format ( i1111I1I ,
 i1ii1iIiI1 . print_referral_type ( ) ) )
 if 66 - 66: iII111i - ooOoO0o * I1ii11iIi11i - Ii1I / OoooooooOO
 oo00OO = lisp_get_referral_node ( i1ii1iIiI1 , I1I11IIII1I1 , mr . eid )
 if ( oo00OO == None ) :
  lprint ( "No reachable referral-nodes found" )
  mr . dequeue_map_request ( )
  lisp_send_negative_map_reply ( o0O , i1ii1iIiI1 . eid ,
 i1ii1iIiI1 . group , iI1III , oOooOo000O , mr . sport , 1 , None , False )
  return
  if 86 - 86: I1IiiI % iII111i + Oo0Ooo + i1IIi % o0oOOo0O0Ooo
  if 85 - 85: Ii1I + I1Ii111 * I11i
 lprint ( "Send DDT Map-Request to {} {} for EID {}, nonce 0x{}" . format ( oo00OO . referral_address . print_address ( ) ,
 # Oo0Ooo . OoO0O00 + OoooooooOO + I1Ii111
 i1ii1iIiI1 . print_referral_type ( ) , green ( oOoo0OooOOo00 , False ) ,
 lisp_hex_string ( iI1III ) ) )
 if 57 - 57: Ii1I % Ii1I * Oo0Ooo % i11iIiiIii
 if 12 - 12: oO0o . Oo0Ooo . I1IiiI - i11iIiiIii / o0oOOo0O0Ooo
 if 54 - 54: i11iIiiIii + I1Ii111 . I1Ii111 * I1ii11iIi11i % I1Ii111 - OoooooooOO
 if 76 - 76: IiII + i1IIi + i11iIiiIii . oO0o
 I1IIiII1 = ( i1ii1iIiI1 . referral_type == LISP_DDT_ACTION_MS_REFERRAL or
 i1ii1iIiI1 . referral_type == LISP_DDT_ACTION_MS_ACK )
 lisp_send_ecm ( o0O , mr . packet , I1I11IIII1I1 , mr . sport , mr . eid ,
 oo00OO . referral_address , to_ms = I1IIiII1 , ddt = True )
 if 35 - 35: iII111i / iII111i * OoOoOO00 - i11iIiiIii
 if 27 - 27: i1IIi / I11i + I1Ii111 . II111iiii * OoO0O00
 if 55 - 55: i1IIi % Ii1I - o0oOOo0O0Ooo - o0oOOo0O0Ooo
 if 6 - 6: i1IIi
 mr . last_request_sent_to = oo00OO . referral_address
 mr . last_sent = lisp_get_timestamp ( )
 mr . send_count += 1
 oo00OO . map_requests_sent += 1
 return
 if 10 - 10: OoO0O00 % iIii1I11I1II1 * OoOoOO00 / i11iIiiIii - I1IiiI . O0
 if 2 - 2: II111iiii
 if 13 - 13: Ii1I % i11iIiiIii
 if 3 - 3: ooOoO0o % OoOoOO00 * I1Ii111 - OoO0O00 / i1IIi % I1IiiI
 if 50 - 50: I1ii11iIi11i + iII111i
 if 64 - 64: oO0o
 if 11 - 11: o0oOOo0O0Ooo
 if 95 - 95: i1IIi . ooOoO0o . Oo0Ooo
def lisp_mr_process_map_request ( lisp_sockets , packet , map_request , ecm_source ,
 sport , mr_source ) :
 if 13 - 13: OOooOOo - Oo0Ooo % O0 . I1Ii111
 o00oo00oo = map_request . target_eid
 ii1I1 = map_request . target_group
 oO0oOoo = map_request . print_eid_tuple ( )
 OooOOOOOO = mr_source . print_address ( )
 iI1III = map_request . nonce
 if 66 - 66: I1IiiI + I11i
 IiIIi1I1I11Ii = green ( OooOOOOOO , False )
 oOo0OOOOOO = green ( oO0oOoo , False )
 lprint ( "Received Map-Request from {}ITR {} EIDs: {} -> {}, nonce 0x{}" . format ( "P" if map_request . pitr_bit else "" ,
 # I1ii11iIi11i . OoooooooOO . oO0o - I11i
 red ( ecm_source . print_address ( ) , False ) , IiIIi1I1I11Ii , oOo0OOOOOO ,
 lisp_hex_string ( iI1III ) ) )
 if 59 - 59: Ii1I / o0oOOo0O0Ooo / OoO0O00 + IiII + i11iIiiIii
 if 64 - 64: o0oOOo0O0Ooo * IiII * IiII * iII111i % i11iIiiIii
 if 22 - 22: I1ii11iIi11i * II111iiii - OOooOOo % i11iIiiIii
 if 10 - 10: OOooOOo / I1ii11iIi11i
 IIiIII1IIi = lisp_ddt_map_request ( lisp_sockets , packet , o00oo00oo , ii1I1 , iI1III )
 IIiIII1IIi . packet = packet
 IIiIII1IIi . itr = ecm_source
 IIiIII1IIi . mr_source = mr_source
 IIiIII1IIi . sport = sport
 IIiIII1IIi . from_pitr = map_request . pitr_bit
 IIiIII1IIi . queue_map_request ( )
 if 8 - 8: iII111i / iIii1I11I1II1
 lisp_send_ddt_map_request ( IIiIII1IIi , False )
 return
 if 82 - 82: OoO0O00 . iII111i + I1ii11iIi11i + ooOoO0o
 if 79 - 79: oO0o - IiII % OoooooooOO . ooOoO0o * I1IiiI
 if 44 - 44: o0oOOo0O0Ooo
 if 76 - 76: i11iIiiIii % OoO0O00
 if 38 - 38: I1ii11iIi11i + II111iiii - I1ii11iIi11i
 if 67 - 67: Ii1I / OoOoOO00
 if 19 - 19: OoO0O00 - OOooOOo * O0
def lisp_process_map_request ( lisp_sockets , packet , ecm_source , ecm_port ,
 mr_source , mr_port , ddt_request , ttl ) :
 if 75 - 75: Ii1I + Oo0Ooo
 iIiiII11 = packet
 O00O0 = lisp_map_request ( )
 packet = O00O0 . decode ( packet , mr_source , mr_port )
 if ( packet == None ) :
  lprint ( "Could not decode Map-Request packet" )
  return
  if 33 - 33: I1Ii111 - i11iIiiIii - o0oOOo0O0Ooo . Ii1I * iIii1I11I1II1
  if 12 - 12: i1IIi + IiII / OoOoOO00 . OoO0O00 / ooOoO0o
 O00O0 . print_map_request ( )
 if 65 - 65: OoO0O00
 if 87 - 87: oO0o . I11i / IiII * OoO0O00 / OoooooooOO % OoOoOO00
 if 51 - 51: oO0o / IiII % Oo0Ooo
 if 69 - 69: I1ii11iIi11i % oO0o / iIii1I11I1II1 * OoOoOO00 % I1IiiI + IiII
 if ( O00O0 . rloc_probe ) :
  lisp_process_rloc_probe_request ( lisp_sockets , O00O0 ,
 mr_source , mr_port , ttl )
  return
  if 34 - 34: ooOoO0o - OoooooooOO . o0oOOo0O0Ooo
  if 83 - 83: II111iiii . OOooOOo
  if 88 - 88: O0
  if 12 - 12: Ii1I % OOooOOo % Oo0Ooo * I1Ii111
  if 96 - 96: iII111i + ooOoO0o
 if ( O00O0 . smr_bit ) :
  lisp_process_smr ( O00O0 )
  if 100 - 100: OOooOOo . ooOoO0o + Ii1I + Ii1I
  if 70 - 70: ooOoO0o . iIii1I11I1II1 / oO0o
  if 18 - 18: Ii1I / OoooooooOO % i1IIi * o0oOOo0O0Ooo
  if 70 - 70: IiII % i1IIi / IiII - o0oOOo0O0Ooo . Oo0Ooo / O0
  if 54 - 54: o0oOOo0O0Ooo
 if ( O00O0 . smr_invoked_bit ) :
  lisp_process_smr_invoked_request ( O00O0 )
  if 53 - 53: II111iiii / IiII . i1IIi + I1Ii111 / OoO0O00 - OoooooooOO
  if 67 - 67: ooOoO0o . Ii1I - Oo0Ooo * iII111i . I11i - OOooOOo
  if 10 - 10: I11i
  if 37 - 37: o0oOOo0O0Ooo / I1IiiI * oO0o / II111iiii
  if 39 - 39: IiII - i1IIi - IiII - OoooooooOO - I1ii11iIi11i
 if ( lisp_i_am_etr ) :
  lisp_etr_process_map_request ( lisp_sockets , O00O0 , mr_source ,
 mr_port , ttl )
  if 66 - 66: IiII + i1IIi
  if 21 - 21: IiII / i11iIiiIii / OoOoOO00
  if 75 - 75: Ii1I . i1IIi / I1IiiI * iII111i . IiII / OoOoOO00
  if 58 - 58: ooOoO0o + OOooOOo / ooOoO0o / i11iIiiIii
  if 95 - 95: ooOoO0o
 if ( lisp_i_am_ms ) :
  packet = iIiiII11
  o00oo00oo , ii1I1 , iI11IIii1Ii = lisp_ms_process_map_request ( lisp_sockets ,
 iIiiII11 , O00O0 , mr_source , mr_port , ecm_source )
  if ( ddt_request ) :
   lisp_ms_send_map_referral ( lisp_sockets , O00O0 , ecm_source ,
 ecm_port , iI11IIii1Ii , o00oo00oo , ii1I1 )
   if 62 - 62: OoooooooOO * Oo0Ooo * iIii1I11I1II1 % I1IiiI . i11iIiiIii + I11i
  return
  if 78 - 78: Ii1I % Oo0Ooo / OoO0O00 . iIii1I11I1II1 . II111iiii
  if 67 - 67: oO0o % I1Ii111
  if 72 - 72: I1IiiI . i11iIiiIii . OoOoOO00 + I1IiiI - I1Ii111 + iII111i
  if 15 - 15: I1IiiI
  if 88 - 88: IiII / I1ii11iIi11i % I11i + i11iIiiIii * O0 . I1Ii111
 if ( lisp_i_am_mr and not ddt_request ) :
  lisp_mr_process_map_request ( lisp_sockets , iIiiII11 , O00O0 ,
 ecm_source , mr_port , mr_source )
  if 69 - 69: Oo0Ooo - OOooOOo / I1IiiI . i11iIiiIii * OoO0O00
  if 45 - 45: I1Ii111 + OOooOOo
  if 78 - 78: OoOoOO00 . Oo0Ooo % I11i
  if 7 - 7: I1ii11iIi11i % Ii1I . OoooooooOO - iII111i
  if 18 - 18: O0 * OoooooooOO % IiII - iIii1I11I1II1 % IiII * o0oOOo0O0Ooo
 if ( lisp_i_am_ddt or ddt_request ) :
  packet = iIiiII11
  lisp_ddt_process_map_request ( lisp_sockets , O00O0 , ecm_source ,
 ecm_port )
  if 13 - 13: OoO0O00 + i11iIiiIii + O0 / ooOoO0o % iIii1I11I1II1
 return
 if 75 - 75: oO0o / i1IIi / Ii1I * Oo0Ooo
 if 75 - 75: Oo0Ooo / OoooooooOO
 if 98 - 98: II111iiii - I1Ii111 . ooOoO0o * iII111i
 if 49 - 49: I1ii11iIi11i / OoooooooOO - I11i
 if 76 - 76: i1IIi . OoO0O00 . O0 / OOooOOo - iII111i
 if 60 - 60: I1IiiI
 if 3 - 3: II111iiii % IiII % I1IiiI - I1IiiI . I1Ii111 - OoOoOO00
 if 18 - 18: O0
def lisp_store_mr_stats ( source , nonce ) :
 IIiIII1IIi = lisp_get_map_resolver ( source , None )
 if ( IIiIII1IIi == None ) : return
 if 26 - 26: i1IIi - iIii1I11I1II1
 if 8 - 8: I1Ii111
 if 86 - 86: i1IIi
 if 26 - 26: o0oOOo0O0Ooo % I1Ii111 / Oo0Ooo
 IIiIII1IIi . neg_map_replies_received += 1
 IIiIII1IIi . last_reply = lisp_get_timestamp ( )
 if 68 - 68: II111iiii / Oo0Ooo / Oo0Ooo
 if 1 - 1: Oo0Ooo
 if 73 - 73: Ii1I * iIii1I11I1II1 / o0oOOo0O0Ooo - o0oOOo0O0Ooo / i1IIi
 if 64 - 64: Ii1I * I1ii11iIi11i % II111iiii
 if ( ( IIiIII1IIi . neg_map_replies_received % 100 ) == 0 ) : IIiIII1IIi . total_rtt = 0
 if 31 - 31: iIii1I11I1II1 % Oo0Ooo . I1IiiI % ooOoO0o
 if 38 - 38: I1ii11iIi11i + I1Ii111 * I11i / OoO0O00 + o0oOOo0O0Ooo
 if 46 - 46: iII111i
 if 56 - 56: Oo0Ooo / II111iiii
 if ( IIiIII1IIi . last_nonce == nonce ) :
  IIiIII1IIi . total_rtt += ( time . time ( ) - IIiIII1IIi . last_used )
  IIiIII1IIi . last_nonce = 0
  if 61 - 61: Ii1I - i1IIi / ooOoO0o - Oo0Ooo / IiII % Oo0Ooo
 if ( ( IIiIII1IIi . neg_map_replies_received % 10 ) == 0 ) : IIiIII1IIi . last_nonce = 0
 return
 if 53 - 53: OoooooooOO + iII111i % II111iiii * IiII
 if 10 - 10: OoOoOO00 % I11i
 if 46 - 46: i1IIi % IiII
 if 45 - 45: I1ii11iIi11i / I1ii11iIi11i - OoO0O00
 if 54 - 54: Ii1I + I1IiiI * OoOoOO00 + oO0o
 if 10 - 10: Ii1I - I1IiiI / IiII / iII111i - I1Ii111 - o0oOOo0O0Ooo
 if 75 - 75: OOooOOo . ooOoO0o
def lisp_process_map_reply ( lisp_sockets , packet , source , ttl ) :
 global lisp_map_cache
 if 32 - 32: i1IIi / I11i + iIii1I11I1II1 . OOooOOo
 OOO00o00o000 = lisp_map_reply ( )
 packet = OOO00o00o000 . decode ( packet )
 if ( packet == None ) :
  lprint ( "Could not decode Map-Reply packet" )
  return
  if 67 - 67: iII111i - OoO0O00 % I1ii11iIi11i * Oo0Ooo
 OOO00o00o000 . print_map_reply ( )
 if 51 - 51: I1IiiI + O0
 if 4 - 4: ooOoO0o / OoO0O00 * iIii1I11I1II1 * iIii1I11I1II1
 if 33 - 33: iII111i . iIii1I11I1II1 - Ii1I
 if 85 - 85: OoOoOO00
 OOOo0OOO = None
 for Ii11 in range ( OOO00o00o000 . record_count ) :
  iI1iii1IIIIi = lisp_eid_record ( )
  packet = iI1iii1IIIIi . decode ( packet )
  if ( packet == None ) :
   lprint ( "Could not decode EID-record in Map-Reply packet" )
   return
   if 64 - 64: I1IiiI % ooOoO0o
  iI1iii1IIIIi . print_record ( "  " , False )
  if 78 - 78: I11i / Ii1I . IiII / o0oOOo0O0Ooo / OoO0O00 + OoOoOO00
  if 50 - 50: Ii1I
  if 84 - 84: iII111i % II111iiii
  if 31 - 31: I11i
  if 28 - 28: i11iIiiIii + IiII / I11i . Ii1I / OoO0O00
  if ( iI1iii1IIIIi . rloc_count == 0 ) :
   lisp_store_mr_stats ( source , OOO00o00o000 . nonce )
   if 100 - 100: o0oOOo0O0Ooo - I11i . o0oOOo0O0Ooo
   if 90 - 90: OoOoOO00 / II111iiii / I11i * I11i - iIii1I11I1II1
  o0OoOO00O0O0 = ( iI1iii1IIIIi . group . is_null ( ) == False )
  if 84 - 84: ooOoO0o * OOooOOo / I1Ii111 * I1IiiI * ooOoO0o
  if 75 - 75: oO0o
  if 60 - 60: OoOoOO00 % I1IiiI . i11iIiiIii % OoOoOO00 - I1Ii111
  if 71 - 71: OoooooooOO * Oo0Ooo
  if 80 - 80: iIii1I11I1II1
  if ( lisp_decent_push_configured ) :
   oo0oOOo0 = iI1iii1IIIIi . action
   if ( o0OoOO00O0O0 and oo0oOOo0 == LISP_DROP_ACTION ) :
    if ( iI1iii1IIIIi . eid . is_local ( ) ) : continue
    if 91 - 91: OoOoOO00 + OoOoOO00 + ooOoO0o
    if 44 - 44: I1ii11iIi11i * OOooOOo % OoO0O00 . I1IiiI % Ii1I + II111iiii
    if 100 - 100: oO0o - II111iiii . o0oOOo0O0Ooo
    if 63 - 63: OoOoOO00 % IiII . iII111i
    if 44 - 44: I1IiiI
    if 25 - 25: oO0o
    if 100 - 100: I1IiiI / IiII + OoO0O00 . iII111i
  if ( iI1iii1IIIIi . eid . is_null ( ) ) : continue
  if 39 - 39: OoooooooOO * OOooOOo - OoO0O00
  if 3 - 3: I11i . i11iIiiIii % Oo0Ooo % II111iiii . I11i
  if 88 - 88: iIii1I11I1II1 . OOooOOo % iII111i
  if 72 - 72: ooOoO0o + i11iIiiIii / i1IIi
  if 64 - 64: OOooOOo - OOooOOo
  if ( o0OoOO00O0O0 ) :
   Iii1 = lisp_map_cache_lookup ( iI1iii1IIIIi . eid , iI1iii1IIIIi . group )
  else :
   Iii1 = lisp_map_cache . lookup_cache ( iI1iii1IIIIi . eid , True )
   if 75 - 75: OOooOOo + IiII + ooOoO0o / I1IiiI . iIii1I11I1II1 / Oo0Ooo
  O0OooOOooo0 = ( Iii1 == None )
  if 67 - 67: ooOoO0o . I1Ii111 . Oo0Ooo . Ii1I + iIii1I11I1II1 / OoooooooOO
  if 93 - 93: ooOoO0o * OoO0O00 - I1Ii111 / I1ii11iIi11i
  if 60 - 60: OoO0O00 / oO0o . I1IiiI + OoOoOO00 + I1ii11iIi11i % Ii1I
  if 70 - 70: i1IIi * II111iiii * I1IiiI
  iii1Ii1i1i1I = [ ]
  for Ii1i1Ii in range ( iI1iii1IIIIi . rloc_count ) :
   oooO0oo00oOOoo0O = lisp_rloc_record ( )
   oooO0oo00oOOoo0O . keys = OOO00o00o000 . keys
   packet = oooO0oo00oOOoo0O . decode ( packet , OOO00o00o000 . nonce )
   if ( packet == None ) :
    lprint ( "Could not decode RLOC-record in Map-Reply packet" )
    return
    if 7 - 7: OoooooooOO + II111iiii / Oo0Ooo % O0 % OOooOOo . I1Ii111
   oooO0oo00oOOoo0O . print_record ( "    " )
   if 78 - 78: iIii1I11I1II1 % OOooOOo
   I1I1ii1 = None
   if ( Iii1 ) : I1I1ii1 = Iii1 . get_rloc ( oooO0oo00oOOoo0O . rloc )
   if ( I1I1ii1 ) :
    oOOoo0O00 = I1I1ii1
   else :
    oOOoo0O00 = lisp_rloc ( )
    if 17 - 17: I1ii11iIi11i . Ii1I / IiII - i1IIi - Ii1I
    if 95 - 95: IiII % I11i % iIii1I11I1II1 . OoO0O00
    if 11 - 11: i11iIiiIii - IiII . o0oOOo0O0Ooo / IiII - I1IiiI
    if 66 - 66: iIii1I11I1II1 . i1IIi . i11iIiiIii % I1ii11iIi11i * OOooOOo % IiII
    if 34 - 34: I1IiiI % I11i - iII111i - i11iIiiIii - iIii1I11I1II1 / i1IIi
    if 7 - 7: I1IiiI + iIii1I11I1II1 . oO0o
    if 17 - 17: OoO0O00 / OoO0O00 + o0oOOo0O0Ooo / OOooOOo . I1ii11iIi11i % IiII
   o00o = oOOoo0O00 . store_rloc_from_record ( oooO0oo00oOOoo0O , OOO00o00o000 . nonce ,
 source )
   oOOoo0O00 . echo_nonce_capable = OOO00o00o000 . echo_nonce_capable
   if 40 - 40: OoOoOO00
   if ( oOOoo0O00 . echo_nonce_capable ) :
    I1iiIiiii1111 = oOOoo0O00 . rloc . print_address_no_iid ( )
    if ( lisp_get_echo_nonce ( None , I1iiIiiii1111 ) == None ) :
     lisp_echo_nonce ( I1iiIiiii1111 )
     if 81 - 81: Ii1I % I1Ii111 / I1ii11iIi11i % iII111i
     if 39 - 39: i1IIi . iII111i . Oo0Ooo % Oo0Ooo * IiII % Ii1I
     if 40 - 40: o0oOOo0O0Ooo * i11iIiiIii . ooOoO0o
     if 63 - 63: I1Ii111 / Ii1I - iIii1I11I1II1 / i11iIiiIii / IiII + I11i
     if 57 - 57: iIii1I11I1II1 % iIii1I11I1II1
     if 23 - 23: II111iiii . ooOoO0o % I1Ii111
     if 39 - 39: OoooooooOO
   if ( Iii1 and Iii1 . gleaned ) :
    oOOoo0O00 = Iii1 . rloc_set [ 0 ]
    o00o = oOOoo0O00 . translated_port
    if 10 - 10: Oo0Ooo * iII111i
    if 78 - 78: Oo0Ooo / i11iIiiIii - I1IiiI
    if 51 - 51: ooOoO0o / Oo0Ooo - I1Ii111 - iII111i
    if 68 - 68: I1ii11iIi11i - iIii1I11I1II1 * OoooooooOO
    if 44 - 44: OoooooooOO + I1Ii111 + OoO0O00
    if 15 - 15: iIii1I11I1II1 % i1IIi + iII111i
    if 48 - 48: o0oOOo0O0Ooo / oO0o
    if 61 - 61: I1IiiI + iII111i * Ii1I % I1Ii111 . Ii1I
    if 83 - 83: i11iIiiIii * OoOoOO00 * i11iIiiIii % II111iiii . i11iIiiIii * I11i
   if ( OOO00o00o000 . rloc_probe and oooO0oo00oOOoo0O . probe_bit ) :
    if ( oOOoo0O00 . rloc . afi == source . afi ) :
     lisp_process_rloc_probe_reply ( oOOoo0O00 . rloc , source , o00o ,
 OOO00o00o000 . nonce , OOO00o00o000 . hop_count , ttl )
     if 67 - 67: i1IIi / i1IIi + IiII . oO0o
     if 70 - 70: i1IIi . I11i * o0oOOo0O0Ooo . iII111i
     if 75 - 75: oO0o * OoO0O00 * I11i + oO0o + O0 . I1Ii111
     if 8 - 8: I1ii11iIi11i / i1IIi - I1ii11iIi11i + Ii1I + OoO0O00 - I11i
     if 79 - 79: OoooooooOO - I1Ii111 * I1IiiI . I1Ii111 - iIii1I11I1II1
     if 27 - 27: OoOoOO00 % OoOoOO00 % II111iiii
   iii1Ii1i1i1I . append ( oOOoo0O00 )
   if 45 - 45: iIii1I11I1II1 . o0oOOo0O0Ooo % I1IiiI
   if 10 - 10: I1IiiI / i1IIi * o0oOOo0O0Ooo + Oo0Ooo - OoOoOO00 % iII111i
   if 88 - 88: Ii1I % Ii1I
   if 29 - 29: OOooOOo % I1ii11iIi11i
   if ( lisp_data_plane_security and oOOoo0O00 . rloc_recent_rekey ( ) ) :
    OOOo0OOO = oOOoo0O00
    if 57 - 57: I1ii11iIi11i - OoOoOO00 + IiII
    if 58 - 58: OOooOOo % I1IiiI / oO0o . ooOoO0o . OoO0O00 / IiII
    if 72 - 72: ooOoO0o + ooOoO0o + o0oOOo0O0Ooo - o0oOOo0O0Ooo % Ii1I
    if 52 - 52: I11i % i1IIi . I1ii11iIi11i
    if 62 - 62: ooOoO0o - I1ii11iIi11i
    if 71 - 71: I11i
    if 34 - 34: oO0o / O0 * oO0o
    if 47 - 47: iIii1I11I1II1 - o0oOOo0O0Ooo % Ii1I
    if 38 - 38: ooOoO0o / IiII * I1ii11iIi11i % I1ii11iIi11i % oO0o
    if 82 - 82: I1ii11iIi11i . i11iIiiIii - I11i . iII111i / OOooOOo
    if 60 - 60: I1IiiI / I1IiiI / II111iiii
  if ( OOO00o00o000 . rloc_probe == False and lisp_nat_traversal ) :
   IIii1Ii1Iii = [ ]
   O0I1iIii1IIii = [ ]
   for oOOoo0O00 in iii1Ii1i1i1I :
    if 18 - 18: II111iiii * OOooOOo * OoO0O00 * iIii1I11I1II1 % o0oOOo0O0Ooo / IiII
    if 95 - 95: I1ii11iIi11i + I1IiiI . OoooooooOO
    if 22 - 22: I1Ii111 / I1Ii111 / OOooOOo + OoOoOO00 % I1Ii111 / Ii1I
    if 14 - 14: o0oOOo0O0Ooo % i11iIiiIii + i11iIiiIii - I1ii11iIi11i % I1ii11iIi11i
    if 26 - 26: oO0o + OoooooooOO % o0oOOo0O0Ooo
    if ( oOOoo0O00 . rloc . is_private_address ( ) ) :
     oOOoo0O00 . priority = 1
     oOOoo0O00 . state = LISP_RLOC_UNREACH_STATE
     IIii1Ii1Iii . append ( oOOoo0O00 )
     O0I1iIii1IIii . append ( oOOoo0O00 . rloc . print_address_no_iid ( ) )
     continue
     if 96 - 96: ooOoO0o * OoOoOO00 - II111iiii
     if 40 - 40: oO0o * OOooOOo + Ii1I + I11i * Ii1I + OoooooooOO
     if 77 - 77: OOooOOo + ooOoO0o / O0
     if 16 - 16: ooOoO0o + Oo0Ooo * Oo0Ooo . I11i - IiII
     if 49 - 49: ooOoO0o . Ii1I
     if 75 - 75: OOooOOo / II111iiii - Oo0Ooo + I1Ii111
    if ( oOOoo0O00 . priority == 254 and lisp_i_am_rtr == False ) :
     IIii1Ii1Iii . append ( oOOoo0O00 )
     O0I1iIii1IIii . append ( oOOoo0O00 . rloc . print_address_no_iid ( ) )
     if 42 - 42: OoooooooOO * II111iiii + Ii1I % OoO0O00 / I1Ii111
    if ( oOOoo0O00 . priority != 254 and lisp_i_am_rtr ) :
     IIii1Ii1Iii . append ( oOOoo0O00 )
     O0I1iIii1IIii . append ( oOOoo0O00 . rloc . print_address_no_iid ( ) )
     if 11 - 11: ooOoO0o / Oo0Ooo + i1IIi / IiII
     if 4 - 4: iII111i - Oo0Ooo
     if 100 - 100: OOooOOo . i1IIi
   if ( O0I1iIii1IIii != [ ] ) :
    iii1Ii1i1i1I = IIii1Ii1Iii
    lprint ( "NAT-traversal optimized RLOC-set: {}" . format ( O0I1iIii1IIii ) )
    if 15 - 15: O0 % Oo0Ooo % o0oOOo0O0Ooo . ooOoO0o * iII111i % O0
    if 31 - 31: i1IIi . Ii1I - OoooooooOO * I11i * ooOoO0o % oO0o
    if 61 - 61: I1Ii111 . Ii1I * I1ii11iIi11i
    if 59 - 59: OoOoOO00 + Oo0Ooo . I1ii11iIi11i - Ii1I
    if 48 - 48: I1Ii111 % Ii1I + I1IiiI * OoooooooOO % OoOoOO00 % i11iIiiIii
    if 13 - 13: iII111i % i1IIi
    if 13 - 13: iII111i / OoooooooOO + Ii1I / iII111i
  IIii1Ii1Iii = [ ]
  for oOOoo0O00 in iii1Ii1i1i1I :
   if ( oOOoo0O00 . json != None ) : continue
   IIii1Ii1Iii . append ( oOOoo0O00 )
   if 29 - 29: OOooOOo + ooOoO0o % o0oOOo0O0Ooo
  if ( IIii1Ii1Iii != [ ] ) :
   I1I11Iiii111 = len ( iii1Ii1i1i1I ) - len ( IIii1Ii1Iii )
   lprint ( "Pruning {} no-address RLOC-records for map-cache" . format ( I1I11Iiii111 ) )
   if 18 - 18: I11i + OoO0O00 + OoO0O00 . ooOoO0o
   iii1Ii1i1i1I = IIii1Ii1Iii
   if 37 - 37: i1IIi . IiII + I1IiiI % OoOoOO00
   if 3 - 3: i11iIiiIii + Ii1I % IiII - I1Ii111 / Oo0Ooo % iIii1I11I1II1
   if 86 - 86: Oo0Ooo + Oo0Ooo * oO0o * I1IiiI
   if 95 - 95: IiII - OoO0O00 + OOooOOo
   if 33 - 33: o0oOOo0O0Ooo . i11iIiiIii . ooOoO0o
   if 100 - 100: i11iIiiIii % I1Ii111 - OoO0O00 + I1Ii111 / i11iIiiIii + OOooOOo
   if 55 - 55: i11iIiiIii / I1Ii111 . OOooOOo - OoO0O00
   if 60 - 60: OoOoOO00 / i1IIi . Ii1I - OoO0O00 - OoooooooOO
  if ( OOO00o00o000 . rloc_probe and Iii1 != None ) : iii1Ii1i1i1I = Iii1 . rloc_set
  if 39 - 39: I1IiiI + i1IIi * OoO0O00 % I11i
  if 41 - 41: I1ii11iIi11i * IiII
  if 16 - 16: I1Ii111 % iIii1I11I1II1 / I1IiiI * OoOoOO00 / IiII / OoOoOO00
  if 29 - 29: OoooooooOO / oO0o
  if 1 - 1: OoOoOO00 . i11iIiiIii % I1Ii111 + OoooooooOO - Oo0Ooo . I1ii11iIi11i
  IiI1ii = O0OooOOooo0
  if ( Iii1 and iii1Ii1i1i1I != Iii1 . rloc_set ) :
   Iii1 . delete_rlocs_from_rloc_probe_list ( )
   IiI1ii = True
   if 56 - 56: ooOoO0o / OoO0O00 / i1IIi
   if 45 - 45: OoOoOO00 + I11i / I1IiiI % OOooOOo
   if 37 - 37: iIii1I11I1II1
   if 64 - 64: II111iiii * oO0o % I1Ii111 + i1IIi
   if 57 - 57: OoOoOO00 + OoOoOO00
  Iii1i1I1 = Iii1 . uptime if ( Iii1 ) else None
  if ( Iii1 == None or Iii1 . gleaned == False ) :
   Iii1 = lisp_mapping ( iI1iii1IIIIi . eid , iI1iii1IIIIi . group , iii1Ii1i1i1I )
   Iii1 . mapping_source = source
   Iii1 . map_cache_ttl = iI1iii1IIIIi . store_ttl ( )
   Iii1 . action = iI1iii1IIIIi . action
   Iii1 . add_cache ( IiI1ii )
   if 76 - 76: Oo0Ooo + OOooOOo - i1IIi * iII111i % i11iIiiIii
   if 78 - 78: i11iIiiIii / I11i / Oo0Ooo + II111iiii - I1ii11iIi11i / I1ii11iIi11i
  IiI1i = "Add"
  if ( Iii1i1I1 ) :
   Iii1 . uptime = Iii1i1I1
   IiI1i = "Replace"
   if 14 - 14: IiII / ooOoO0o . i1IIi + Oo0Ooo
   if 80 - 80: I1Ii111 + I1Ii111 / o0oOOo0O0Ooo - ooOoO0o - OoooooooOO . I11i
  lprint ( "{} {} map-cache with {} RLOCs" . format ( IiI1i ,
 green ( Iii1 . print_eid_tuple ( ) , False ) , len ( iii1Ii1i1i1I ) ) )
  if 60 - 60: I1ii11iIi11i - I1IiiI % OOooOOo + Ii1I - ooOoO0o % OoOoOO00
  if 94 - 94: OoOoOO00 - i1IIi
  if 65 - 65: OoO0O00 / i11iIiiIii + I1ii11iIi11i + OoOoOO00
  if 82 - 82: Ii1I * OOooOOo % ooOoO0o / OoO0O00 - Oo0Ooo . I1Ii111
  if 90 - 90: I11i * i11iIiiIii % i1IIi + I1Ii111 / OoO0O00
  if ( lisp_ipc_dp_socket and OOOo0OOO != None ) :
   lisp_write_ipc_keys ( OOOo0OOO )
   if 15 - 15: Oo0Ooo + oO0o . I11i % OoO0O00
   if 13 - 13: I1ii11iIi11i / ooOoO0o * I1Ii111
   if 45 - 45: I1ii11iIi11i - I11i
   if 60 - 60: OOooOOo - OOooOOo * OoOoOO00 / Ii1I % iII111i % Oo0Ooo
   if 75 - 75: iIii1I11I1II1 - IiII - I1Ii111
   if 4 - 4: i11iIiiIii % OoooooooOO . i11iIiiIii
   if 61 - 61: iIii1I11I1II1 . Oo0Ooo . i1IIi
  if ( O0OooOOooo0 ) :
   iI11iI11i11ii = bold ( "RLOC-probe" , False )
   for oOOoo0O00 in Iii1 . best_rloc_set :
    I1iiIiiii1111 = red ( oOOoo0O00 . rloc . print_address_no_iid ( ) , False )
    lprint ( "Trigger {} to {}" . format ( iI11iI11i11ii , I1iiIiiii1111 ) )
    lisp_send_map_request ( lisp_sockets , 0 , Iii1 . eid , Iii1 . group , oOOoo0O00 )
    if 48 - 48: IiII . I1ii11iIi11i % iII111i
    if 53 - 53: I1ii11iIi11i . o0oOOo0O0Ooo % OoO0O00 * I1Ii111
    if 52 - 52: OoO0O00
 return
 if 20 - 20: OoO0O00 + OoOoOO00 * Oo0Ooo
 if 94 - 94: i1IIi + Ii1I * iII111i / I1IiiI
 if 75 - 75: OoOoOO00 * Oo0Ooo - i11iIiiIii . I1IiiI
 if 83 - 83: I11i - i11iIiiIii - I1IiiI - OoO0O00 / i1IIi
 if 49 - 49: OoOoOO00 + iIii1I11I1II1
 if 53 - 53: I1Ii111
 if 2 - 2: Ii1I + I11i
 if 94 - 94: OoO0O00 / i11iIiiIii
def lisp_compute_auth ( packet , map_register , password ) :
 if ( map_register . alg_id == LISP_NONE_ALG_ID ) : return ( packet )
 if 68 - 68: iIii1I11I1II1 % Oo0Ooo + Oo0Ooo
 packet = map_register . zero_auth ( packet )
 o0o0oooO00O0 = lisp_hash_me ( packet , map_register . alg_id , password , False )
 if 44 - 44: I11i / OoO0O00
 if 66 - 66: i11iIiiIii
 if 83 - 83: I1Ii111 / iIii1I11I1II1 - oO0o
 if 3 - 3: OOooOOo - Oo0Ooo * I1IiiI - OoO0O00 / OOooOOo + IiII
 map_register . auth_data = o0o0oooO00O0
 packet = map_register . encode_auth ( packet )
 return ( packet )
 if 83 - 83: i1IIi * i1IIi - II111iiii / OoooooooOO . Ii1I + I1Ii111
 if 10 - 10: I11i
 if 24 - 24: Ii1I
 if 30 - 30: II111iiii / Ii1I - I11i - OoO0O00
 if 25 - 25: I11i % i1IIi / I11i * i11iIiiIii
 if 71 - 71: IiII % I11i - OoooooooOO + I1IiiI / Oo0Ooo % I11i
 if 6 - 6: i1IIi * i11iIiiIii + ooOoO0o - IiII
def lisp_hash_me ( packet , alg_id , password , do_hex ) :
 if ( alg_id == LISP_NONE_ALG_ID ) : return ( True )
 if 97 - 97: iIii1I11I1II1 * i1IIi * II111iiii - OOooOOo - Oo0Ooo - iIii1I11I1II1
 if ( alg_id == LISP_SHA_1_96_ALG_ID ) :
  i1IiiI = hashlib . sha1
  if 43 - 43: OoO0O00
 if ( alg_id == LISP_SHA_256_128_ALG_ID ) :
  i1IiiI = hashlib . sha256
  if 51 - 51: OoooooooOO % IiII % Oo0Ooo
  if 50 - 50: I1IiiI - i11iIiiIii / I1ii11iIi11i . Ii1I - iIii1I11I1II1
 if ( do_hex ) :
  o0o0oooO00O0 = hmac . new ( password , packet , i1IiiI ) . hexdigest ( )
 else :
  o0o0oooO00O0 = hmac . new ( password , packet , i1IiiI ) . digest ( )
  if 91 - 91: I1IiiI . I1Ii111 + II111iiii . Oo0Ooo
 return ( o0o0oooO00O0 )
 if 95 - 95: iII111i
 if 77 - 77: I1IiiI * II111iiii * iIii1I11I1II1
 if 19 - 19: OOooOOo * o0oOOo0O0Ooo
 if 64 - 64: I11i % ooOoO0o / OOooOOo / iII111i
 if 80 - 80: i1IIi
 if 74 - 74: I1ii11iIi11i . OoO0O00 + i11iIiiIii
 if 19 - 19: i1IIi / I1IiiI + IiII . iII111i
 if 68 - 68: iII111i
def lisp_verify_auth ( packet , alg_id , auth_data , password ) :
 if ( alg_id == LISP_NONE_ALG_ID ) : return ( True )
 if 29 - 29: II111iiii / II111iiii % OoO0O00 % Oo0Ooo . II111iiii
 o0o0oooO00O0 = lisp_hash_me ( packet , alg_id , password , True )
 ii1 = ( o0o0oooO00O0 == auth_data )
 if 44 - 44: O0
 if 54 - 54: Oo0Ooo * i11iIiiIii . II111iiii % ooOoO0o . iIii1I11I1II1 + OoOoOO00
 if 1 - 1: oO0o - II111iiii - IiII
 if 93 - 93: OoOoOO00 + OoooooooOO . OOooOOo / oO0o / OoOoOO00
 if ( ii1 == False ) :
  lprint ( "Hashed value: {} does not match packet value: {}" . format ( o0o0oooO00O0 , auth_data ) )
  if 94 - 94: OoO0O00 / i1IIi . OoO0O00 . I1Ii111 + OoO0O00
  if 30 - 30: o0oOOo0O0Ooo + iIii1I11I1II1 - II111iiii - ooOoO0o + OoOoOO00 - II111iiii
 return ( ii1 )
 if 69 - 69: oO0o / O0 / I1IiiI + OoooooooOO * I11i * IiII
 if 41 - 41: ooOoO0o % i11iIiiIii
 if 69 - 69: IiII - oO0o
 if 21 - 21: Oo0Ooo / I1Ii111
 if 72 - 72: OoOoOO00 . i11iIiiIii
 if 25 - 25: i1IIi
 if 69 - 69: OOooOOo / Ii1I
def lisp_retransmit_map_notify ( map_notify ) :
 oooooO0oO0o = map_notify . etr
 o00o = map_notify . etr_port
 if 67 - 67: i11iIiiIii . II111iiii + OoooooooOO % o0oOOo0O0Ooo + IiII * i1IIi
 if 53 - 53: oO0o * OoooooooOO + II111iiii . IiII * I1ii11iIi11i
 if 55 - 55: OoOoOO00
 if 27 - 27: I1IiiI
 if 81 - 81: Oo0Ooo
 if ( map_notify . retry_count == LISP_MAX_MAP_NOTIFY_RETRIES ) :
  lprint ( "Map-Notify with nonce 0x{} retry limit reached for ETR {}" . format ( map_notify . nonce_key , red ( oooooO0oO0o . print_address ( ) , False ) ) )
  if 43 - 43: i1IIi * O0 + ooOoO0o + OoO0O00
  if 99 - 99: IiII . OoOoOO00
  o0OoOo0o0OOoO0 = map_notify . nonce_key
  if ( lisp_map_notify_queue . has_key ( o0OoOo0o0OOoO0 ) ) :
   map_notify . retransmit_timer . cancel ( )
   lprint ( "Dequeue Map-Notify from retransmit queue, key is: {}" . format ( o0OoOo0o0OOoO0 ) )
   if 64 - 64: I1Ii111
   try :
    lisp_map_notify_queue . pop ( o0OoOo0o0OOoO0 )
   except :
    lprint ( "Key not found in Map-Notify queue" )
    if 96 - 96: Ii1I
    if 100 - 100: ooOoO0o
  return
  if 43 - 43: Ii1I * ooOoO0o + O0 . II111iiii
  if 8 - 8: IiII * OOooOOo + I11i + O0 * oO0o - oO0o
 o0O = map_notify . lisp_sockets
 map_notify . retry_count += 1
 if 19 - 19: OoO0O00 - ooOoO0o + I1ii11iIi11i / I1ii11iIi11i % I1Ii111 % iIii1I11I1II1
 lprint ( "Retransmit {} with nonce 0x{} to xTR {}, retry {}" . format ( bold ( "Map-Notify" , False ) , map_notify . nonce_key ,
 # ooOoO0o
 red ( oooooO0oO0o . print_address ( ) , False ) , map_notify . retry_count ) )
 if 48 - 48: ooOoO0o - O0
 lisp_send_map_notify ( o0O , map_notify . packet , oooooO0oO0o , o00o )
 if ( map_notify . site ) : map_notify . site . map_notifies_sent += 1
 if 29 - 29: oO0o . oO0o
 if 96 - 96: O0
 if 85 - 85: Oo0Ooo + i11iIiiIii . OOooOOo / II111iiii / iII111i
 if 90 - 90: o0oOOo0O0Ooo - OoooooooOO - i1IIi
 map_notify . retransmit_timer = threading . Timer ( LISP_MAP_NOTIFY_INTERVAL ,
 lisp_retransmit_map_notify , [ map_notify ] )
 map_notify . retransmit_timer . start ( )
 return
 if 47 - 47: I1Ii111 * Ii1I . iIii1I11I1II1 / OoOoOO00
 if 68 - 68: i11iIiiIii / OOooOOo / I1ii11iIi11i % IiII * IiII + II111iiii
 if 65 - 65: I1IiiI + OoOoOO00 - OoOoOO00 . oO0o
 if 84 - 84: Ii1I * i1IIi
 if 42 - 42: OoOoOO00 - ooOoO0o + oO0o - II111iiii
 if 92 - 92: Oo0Ooo - I11i . ooOoO0o % oO0o
 if 6 - 6: iIii1I11I1II1 + oO0o
def lisp_send_merged_map_notify ( lisp_sockets , parent , map_register ,
 eid_record ) :
 if 8 - 8: I1ii11iIi11i + o0oOOo0O0Ooo
 if 29 - 29: Ii1I . OOooOOo
 if 59 - 59: O0 . OoO0O00
 if 10 - 10: I1Ii111 / OoooooooOO / OoO0O00 * ooOoO0o
 eid_record . rloc_count = len ( parent . registered_rlocs )
 oo00oO0ooo = eid_record . encode ( )
 eid_record . print_record ( "Merged Map-Notify " , False )
 if 6 - 6: iIii1I11I1II1 . O0 . oO0o + I1ii11iIi11i
 if 32 - 32: I1IiiI / OOooOOo . i11iIiiIii - IiII . iII111i . Ii1I
 if 34 - 34: i1IIi % iII111i + Oo0Ooo * OoOoOO00 + OoO0O00
 if 37 - 37: I1Ii111 / OoooooooOO
 for I1IiIiIi in parent . registered_rlocs :
  oooO0oo00oOOoo0O = lisp_rloc_record ( )
  oooO0oo00oOOoo0O . store_rloc_entry ( I1IiIiIi )
  oo00oO0ooo += oooO0oo00oOOoo0O . encode ( )
  oooO0oo00oOOoo0O . print_record ( "  " )
  del ( oooO0oo00oOOoo0O )
  if 59 - 59: OoO0O00 + O0 + i11iIiiIii / OoOoOO00 + iIii1I11I1II1 / OoOoOO00
  if 69 - 69: OoOoOO00 * Ii1I % ooOoO0o . OoOoOO00 / oO0o * I1Ii111
  if 93 - 93: OoO0O00 % IiII % ooOoO0o . I1IiiI
  if 96 - 96: II111iiii
  if 73 - 73: II111iiii
 for I1IiIiIi in parent . registered_rlocs :
  oooooO0oO0o = I1IiIiIi . rloc
  ooOo00 = lisp_map_notify ( lisp_sockets )
  ooOo00 . record_count = 1
  o0OOOoO0O = map_register . key_id
  ooOo00 . key_id = o0OOOoO0O
  ooOo00 . alg_id = map_register . alg_id
  ooOo00 . auth_len = map_register . auth_len
  ooOo00 . nonce = map_register . nonce
  ooOo00 . nonce_key = lisp_hex_string ( ooOo00 . nonce )
  ooOo00 . etr . copy_address ( oooooO0oO0o )
  ooOo00 . etr_port = map_register . sport
  ooOo00 . site = parent . site
  i1II1IiiIi = ooOo00 . encode ( oo00oO0ooo , parent . site . auth_key [ o0OOOoO0O ] )
  ooOo00 . print_notify ( )
  if 45 - 45: iII111i + O0 % i11iIiiIii * I1ii11iIi11i + I1Ii111 / OOooOOo
  if 55 - 55: OoooooooOO % iIii1I11I1II1 . ooOoO0o
  if 10 - 10: O0 * iIii1I11I1II1 . OOooOOo
  if 4 - 4: iIii1I11I1II1
  o0OoOo0o0OOoO0 = ooOo00 . nonce_key
  if ( lisp_map_notify_queue . has_key ( o0OoOo0o0OOoO0 ) ) :
   i1Ioo = lisp_map_notify_queue [ o0OoOo0o0OOoO0 ]
   i1Ioo . retransmit_timer . cancel ( )
   del ( i1Ioo )
   if 32 - 32: iII111i + i11iIiiIii / OOooOOo - IiII
  lisp_map_notify_queue [ o0OoOo0o0OOoO0 ] = ooOo00
  if 93 - 93: iIii1I11I1II1 / O0 + OoO0O00 * iIii1I11I1II1 % iIii1I11I1II1 / IiII
  if 21 - 21: ooOoO0o / iII111i % II111iiii * I1IiiI * II111iiii
  if 40 - 40: Ii1I / i1IIi . iII111i
  if 65 - 65: iIii1I11I1II1 * O0 . II111iiii * o0oOOo0O0Ooo . I1ii11iIi11i * I1IiiI
  lprint ( "Send merged Map-Notify to ETR {}" . format ( red ( oooooO0oO0o . print_address ( ) , False ) ) )
  if 63 - 63: II111iiii . Oo0Ooo % iIii1I11I1II1
  lisp_send ( lisp_sockets , oooooO0oO0o , LISP_CTRL_PORT , i1II1IiiIi )
  if 85 - 85: I1IiiI + i1IIi % I1Ii111
  parent . site . map_notifies_sent += 1
  if 76 - 76: i11iIiiIii % i11iIiiIii
  if 33 - 33: OOooOOo . ooOoO0o / iIii1I11I1II1 * OOooOOo / oO0o
  if 75 - 75: Ii1I - OoOoOO00 . OOooOOo - o0oOOo0O0Ooo - I1ii11iIi11i
  if 69 - 69: O0 % I1ii11iIi11i
  ooOo00 . retransmit_timer = threading . Timer ( LISP_MAP_NOTIFY_INTERVAL ,
 lisp_retransmit_map_notify , [ ooOo00 ] )
  ooOo00 . retransmit_timer . start ( )
  if 77 - 77: iIii1I11I1II1 . OOooOOo
 return
 if 64 - 64: OoOoOO00 - i1IIi * i1IIi / iII111i * OoOoOO00 * OoO0O00
 if 61 - 61: OOooOOo
 if 51 - 51: Oo0Ooo * OOooOOo / iII111i
 if 49 - 49: ooOoO0o . i1IIi % I1Ii111 . I1IiiI . I1ii11iIi11i + OoO0O00
 if 65 - 65: I1ii11iIi11i + Ii1I / i11iIiiIii * I1Ii111 + OoooooooOO
 if 7 - 7: Oo0Ooo % o0oOOo0O0Ooo
 if 40 - 40: oO0o * IiII
def lisp_build_map_notify ( lisp_sockets , eid_records , eid_list , record_count ,
 source , port , nonce , key_id , alg_id , auth_len , site , map_register_ack ) :
 if 29 - 29: O0 - II111iiii + iII111i
 o0OoOo0o0OOoO0 = lisp_hex_string ( nonce ) + source . print_address ( )
 if 73 - 73: I1Ii111 - I11i + IiII - o0oOOo0O0Ooo - I11i - OOooOOo
 if 40 - 40: iIii1I11I1II1 . iII111i * I1ii11iIi11i + IiII - iIii1I11I1II1
 if 83 - 83: i1IIi
 if 9 - 9: iIii1I11I1II1 + i11iIiiIii
 if 70 - 70: I1IiiI - OoO0O00 % OOooOOo + ooOoO0o % II111iiii
 if 19 - 19: I11i + i1IIi / i1IIi - II111iiii + I1Ii111
 lisp_remove_eid_from_map_notify_queue ( eid_list )
 if ( lisp_map_notify_queue . has_key ( o0OoOo0o0OOoO0 ) ) :
  ooOo00 = lisp_map_notify_queue [ o0OoOo0o0OOoO0 ]
  IiIIi1I1I11Ii = red ( source . print_address_no_iid ( ) , False )
  lprint ( "Map-Notify with nonce 0x{} pending for xTR {}" . format ( lisp_hex_string ( ooOo00 . nonce ) , IiIIi1I1I11Ii ) )
  if 11 - 11: i11iIiiIii % i11iIiiIii / IiII - Oo0Ooo / O0 - I11i
  return
  if 29 - 29: OOooOOo * iIii1I11I1II1 * ooOoO0o
  if 80 - 80: oO0o * I1Ii111
 ooOo00 = lisp_map_notify ( lisp_sockets )
 ooOo00 . record_count = record_count
 key_id = key_id
 ooOo00 . key_id = key_id
 ooOo00 . alg_id = alg_id
 ooOo00 . auth_len = auth_len
 ooOo00 . nonce = nonce
 ooOo00 . nonce_key = lisp_hex_string ( nonce )
 ooOo00 . etr . copy_address ( source )
 ooOo00 . etr_port = port
 ooOo00 . site = site
 ooOo00 . eid_list = eid_list
 if 87 - 87: iII111i + OoOoOO00 % ooOoO0o - oO0o
 if 40 - 40: i1IIi / OoOoOO00 - I11i / ooOoO0o . Ii1I
 if 8 - 8: I1IiiI . IiII . OOooOOo . O0
 if 3 - 3: Ii1I + i11iIiiIii
 if ( map_register_ack == False ) :
  o0OoOo0o0OOoO0 = ooOo00 . nonce_key
  lisp_map_notify_queue [ o0OoOo0o0OOoO0 ] = ooOo00
  if 87 - 87: ooOoO0o - iII111i % I11i
  if 88 - 88: I11i . OoooooooOO
 if ( map_register_ack ) :
  lprint ( "Send Map-Notify to ack Map-Register" )
 else :
  lprint ( "Send Map-Notify for RLOC-set change" )
  if 86 - 86: Ii1I - I1IiiI - iII111i % Ii1I . I1ii11iIi11i % i1IIi
  if 84 - 84: OoOoOO00
  if 99 - 99: OoO0O00 - OoOoOO00 - i1IIi / OoO0O00 * I1ii11iIi11i * iIii1I11I1II1
  if 65 - 65: iII111i - O0 / i1IIi . I1Ii111
  if 85 - 85: o0oOOo0O0Ooo % Ii1I
 i1II1IiiIi = ooOo00 . encode ( eid_records , site . auth_key [ key_id ] )
 ooOo00 . print_notify ( )
 if 81 - 81: oO0o / OoO0O00 * i1IIi % iIii1I11I1II1
 if ( map_register_ack == False ) :
  iI1iii1IIIIi = lisp_eid_record ( )
  iI1iii1IIIIi . decode ( eid_records )
  iI1iii1IIIIi . print_record ( "  " , False )
  if 23 - 23: II111iiii . II111iiii
  if 17 - 17: i11iIiiIii / IiII * I1IiiI . Oo0Ooo / o0oOOo0O0Ooo - iIii1I11I1II1
  if 21 - 21: OOooOOo % Ii1I
  if 3 - 3: OOooOOo / ooOoO0o / I1Ii111 . I11i
  if 54 - 54: I1ii11iIi11i - I1IiiI . OoOoOO00
 lisp_send_map_notify ( lisp_sockets , i1II1IiiIi , ooOo00 . etr , port )
 site . map_notifies_sent += 1
 if 36 - 36: OoO0O00 * I1IiiI / iII111i
 if ( map_register_ack ) : return
 if 95 - 95: Ii1I . Oo0Ooo
 if 42 - 42: IiII . i1IIi % O0 * ooOoO0o - OOooOOo % ooOoO0o
 if 99 - 99: i1IIi + OoOoOO00 - iII111i % II111iiii
 if 6 - 6: ooOoO0o - I1Ii111 . OoOoOO00
 if 64 - 64: iII111i + I1ii11iIi11i
 if 88 - 88: I1Ii111 / i11iIiiIii - O0 . II111iiii / II111iiii * II111iiii
 ooOo00 . retransmit_timer = threading . Timer ( LISP_MAP_NOTIFY_INTERVAL ,
 lisp_retransmit_map_notify , [ ooOo00 ] )
 ooOo00 . retransmit_timer . start ( )
 return
 if 56 - 56: Oo0Ooo / I1IiiI % I1Ii111 % I1ii11iIi11i * I1IiiI - IiII
 if 39 - 39: oO0o + iII111i . I1Ii111 * i11iIiiIii % o0oOOo0O0Ooo + OOooOOo
 if 61 - 61: ooOoO0o / I1Ii111 / I1ii11iIi11i - Ii1I % o0oOOo0O0Ooo * iII111i
 if 94 - 94: I1IiiI / I11i
 if 100 - 100: Ii1I % OoO0O00 % OoooooooOO / II111iiii * I1Ii111
 if 64 - 64: I1Ii111 * OOooOOo * Ii1I + I1ii11iIi11i / iIii1I11I1II1 / Oo0Ooo
 if 50 - 50: OOooOOo % i11iIiiIii
 if 99 - 99: IiII
def lisp_send_map_notify_ack ( lisp_sockets , eid_records , map_notify , ms ) :
 map_notify . map_notify_ack = True
 if 87 - 87: IiII
 if 35 - 35: oO0o . O0 . Ii1I / ooOoO0o
 if 36 - 36: i11iIiiIii . II111iiii . I11i . II111iiii
 if 36 - 36: Ii1I + ooOoO0o / Oo0Ooo % Oo0Ooo
 i1II1IiiIi = map_notify . encode ( eid_records , ms . password )
 map_notify . print_notify ( )
 if 2 - 2: oO0o - Oo0Ooo * OoO0O00 . ooOoO0o . OOooOOo - oO0o
 if 74 - 74: o0oOOo0O0Ooo
 if 18 - 18: Oo0Ooo % OOooOOo / OOooOOo . I1IiiI + i1IIi . I1IiiI
 if 3 - 3: O0 * O0 + II111iiii + OoOoOO00 * I11i % Oo0Ooo
 oooooO0oO0o = ms . map_server
 lprint ( "Send Map-Notify-Ack to {}" . format (
 red ( oooooO0oO0o . print_address ( ) , False ) ) )
 lisp_send ( lisp_sockets , oooooO0oO0o , LISP_CTRL_PORT , i1II1IiiIi )
 return
 if 19 - 19: oO0o % IiII % OoooooooOO % I1ii11iIi11i / OoO0O00
 if 6 - 6: O0 * I1Ii111 - II111iiii
 if 60 - 60: oO0o % oO0o
 if 76 - 76: I1Ii111 / o0oOOo0O0Ooo
 if 19 - 19: O0 . i1IIi % iIii1I11I1II1 + OOooOOo * OoOoOO00 / I11i
 if 82 - 82: I1ii11iIi11i
 if 75 - 75: I11i - II111iiii
 if 84 - 84: I1ii11iIi11i * IiII / I1IiiI - Ii1I + IiII - i1IIi
def lisp_send_multicast_map_notify ( lisp_sockets , site_eid , eid_list , xtr ) :
 if 98 - 98: II111iiii - iII111i % i11iIiiIii + ooOoO0o
 ooOo00 = lisp_map_notify ( lisp_sockets )
 ooOo00 . record_count = 1
 ooOo00 . nonce = lisp_get_control_nonce ( )
 ooOo00 . nonce_key = lisp_hex_string ( ooOo00 . nonce )
 ooOo00 . etr . copy_address ( xtr )
 ooOo00 . etr_port = LISP_CTRL_PORT
 ooOo00 . eid_list = eid_list
 o0OoOo0o0OOoO0 = ooOo00 . nonce_key
 if 76 - 76: OOooOOo - iII111i + IiII
 if 48 - 48: I1IiiI - II111iiii
 if 15 - 15: O0
 if 54 - 54: iIii1I11I1II1
 if 54 - 54: iII111i + OOooOOo + OoO0O00
 if 6 - 6: oO0o - OoooooooOO * iIii1I11I1II1 * I1ii11iIi11i
 lisp_remove_eid_from_map_notify_queue ( ooOo00 . eid_list )
 if ( lisp_map_notify_queue . has_key ( o0OoOo0o0OOoO0 ) ) :
  ooOo00 = lisp_map_notify_queue [ o0OoOo0o0OOoO0 ]
  lprint ( "Map-Notify with nonce 0x{} pending for ITR {}" . format ( ooOo00 . nonce , red ( xtr . print_address_no_iid ( ) , False ) ) )
  if 65 - 65: IiII + OoOoOO00
  return
  if 93 - 93: Ii1I
  if 43 - 43: iIii1I11I1II1 / iII111i - Ii1I + I11i % iII111i - OoO0O00
  if 5 - 5: OoO0O00 / ooOoO0o
  if 92 - 92: Oo0Ooo / iII111i + O0 * ooOoO0o * OOooOOo % Oo0Ooo
  if 97 - 97: oO0o / Ii1I
 lisp_map_notify_queue [ o0OoOo0o0OOoO0 ] = ooOo00
 if 70 - 70: iII111i / Oo0Ooo . OoOoOO00 - II111iiii * II111iiii % I1IiiI
 if 34 - 34: I1Ii111 + OOooOOo * iII111i / ooOoO0o % i11iIiiIii
 if 91 - 91: IiII * Ii1I * OOooOOo
 if 17 - 17: o0oOOo0O0Ooo + Ii1I % I1ii11iIi11i + IiII % I1Ii111 + I1ii11iIi11i
 O0OOOo00O0oO = site_eid . rtrs_in_rloc_set ( )
 if ( O0OOOo00O0oO ) :
  if ( site_eid . is_rtr_in_rloc_set ( xtr ) ) : O0OOOo00O0oO = False
  if 69 - 69: oO0o - Ii1I
  if 97 - 97: OOooOOo / ooOoO0o . Oo0Ooo - Oo0Ooo . OoOoOO00
  if 88 - 88: iIii1I11I1II1 - OoO0O00 + II111iiii
  if 100 - 100: I1Ii111 + I1IiiI + OOooOOo * iII111i
  if 35 - 35: Oo0Ooo . O0
 iI1iii1IIIIi = lisp_eid_record ( )
 iI1iii1IIIIi . record_ttl = 1440
 iI1iii1IIIIi . eid . copy_address ( site_eid . eid )
 iI1iii1IIIIi . group . copy_address ( site_eid . group )
 iI1iii1IIIIi . rloc_count = 0
 for IIiO0Ooo in site_eid . registered_rlocs :
  if ( O0OOOo00O0oO ^ IIiO0Ooo . is_rtr ( ) ) : continue
  iI1iii1IIIIi . rloc_count += 1
  if 43 - 43: oO0o . O0 . OOooOOo
 i1II1IiiIi = iI1iii1IIIIi . encode ( )
 if 3 - 3: i1IIi
 if 85 - 85: i11iIiiIii % i1IIi
 if 78 - 78: ooOoO0o / I1ii11iIi11i
 if 72 - 72: II111iiii / O0 - I1ii11iIi11i + oO0o + iIii1I11I1II1
 ooOo00 . print_notify ( )
 iI1iii1IIIIi . print_record ( "  " , False )
 if 65 - 65: OoO0O00 * II111iiii
 if 25 - 25: I1ii11iIi11i - I1Ii111 * I1Ii111 / O0 - iIii1I11I1II1 . iII111i
 if 83 - 83: ooOoO0o * oO0o * OoO0O00 + OoO0O00
 if 58 - 58: I1ii11iIi11i
 for IIiO0Ooo in site_eid . registered_rlocs :
  if ( O0OOOo00O0oO ^ IIiO0Ooo . is_rtr ( ) ) : continue
  oooO0oo00oOOoo0O = lisp_rloc_record ( )
  oooO0oo00oOOoo0O . store_rloc_entry ( IIiO0Ooo )
  i1II1IiiIi += oooO0oo00oOOoo0O . encode ( )
  oooO0oo00oOOoo0O . print_record ( "    " )
  if 93 - 93: i1IIi - IiII + IiII % OoooooooOO / o0oOOo0O0Ooo
  if 39 - 39: I1IiiI + Ii1I - O0
  if 25 - 25: IiII % iIii1I11I1II1 + ooOoO0o % iII111i - OoO0O00
  if 36 - 36: OoooooooOO / oO0o + IiII . I1IiiI - o0oOOo0O0Ooo % OOooOOo
  if 15 - 15: Ii1I % IiII + IiII % iII111i - O0 * OoooooooOO
 i1II1IiiIi = ooOo00 . encode ( i1II1IiiIi , "" )
 if ( i1II1IiiIi == None ) : return
 if 53 - 53: OoOoOO00 . Ii1I / Oo0Ooo
 if 62 - 62: i11iIiiIii
 if 38 - 38: I1ii11iIi11i % ooOoO0o * OoooooooOO + iIii1I11I1II1 % i1IIi / OOooOOo
 if 6 - 6: i11iIiiIii
 lisp_send_map_notify ( lisp_sockets , i1II1IiiIi , xtr , LISP_CTRL_PORT )
 if 8 - 8: iIii1I11I1II1 + I1ii11iIi11i . i1IIi % OoOoOO00 % OoooooooOO * Oo0Ooo
 if 53 - 53: oO0o
 if 23 - 23: I1ii11iIi11i . I1Ii111 + OOooOOo
 if 4 - 4: I1IiiI
 ooOo00 . retransmit_timer = threading . Timer ( LISP_MAP_NOTIFY_INTERVAL ,
 lisp_retransmit_map_notify , [ ooOo00 ] )
 ooOo00 . retransmit_timer . start ( )
 return
 if 31 - 31: ooOoO0o * i1IIi . O0
 if 5 - 5: OOooOOo . I1ii11iIi11i + ooOoO0o . ooOoO0o + iII111i
 if 100 - 100: I1Ii111
 if 71 - 71: ooOoO0o * i1IIi / OoOoOO00 * i11iIiiIii - iII111i
 if 88 - 88: IiII
 if 29 - 29: iII111i . ooOoO0o
 if 62 - 62: IiII
def lisp_queue_multicast_map_notify ( lisp_sockets , rle_list ) :
 O0OoO = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
 if 27 - 27: OoO0O00 + OOooOOo / ooOoO0o * I1IiiI / I11i
 for I111iiiIii1I in rle_list :
  O00 = lisp_site_eid_lookup ( I111iiiIii1I [ 0 ] , I111iiiIii1I [ 1 ] , True )
  if ( O00 == None ) : continue
  if 4 - 4: I1IiiI * I1IiiI . O0 / I1Ii111 . oO0o
  if 92 - 92: OoO0O00 % OoooooooOO % Ii1I + I11i % I1Ii111 / Ii1I
  if 100 - 100: iII111i + o0oOOo0O0Ooo / Oo0Ooo * I1IiiI
  if 35 - 35: I1IiiI / Ii1I * IiII + OOooOOo - iIii1I11I1II1 + I11i
  if 50 - 50: I11i * Ii1I . iIii1I11I1II1 . iII111i - O0 . ooOoO0o
  if 3 - 3: OoOoOO00
  if 79 - 79: i11iIiiIii * OoooooooOO
  Iiiii11ii1ii = O00 . registered_rlocs
  if ( len ( Iiiii11ii1ii ) == 0 ) :
   IIO0 = { }
   for I11IiI1ii in O00 . individual_registrations . values ( ) :
    for IIiO0Ooo in I11IiI1ii . registered_rlocs :
     if ( IIiO0Ooo . is_rtr ( ) == False ) : continue
     IIO0 [ IIiO0Ooo . rloc . print_address ( ) ] = IIiO0Ooo
     if 7 - 7: iIii1I11I1II1 - I1Ii111 . ooOoO0o . O0 - OOooOOo
     if 5 - 5: i1IIi * OoOoOO00 + i1IIi % I11i
   Iiiii11ii1ii = IIO0 . values ( )
   if 79 - 79: OOooOOo % iIii1I11I1II1 / OoOoOO00
   if 9 - 9: Ii1I
   if 44 - 44: iII111i
   if 46 - 46: I11i . i11iIiiIii * OoOoOO00 + o0oOOo0O0Ooo / ooOoO0o
   if 37 - 37: OoO0O00 - Ii1I + OoO0O00
   if 49 - 49: OoooooooOO - I1ii11iIi11i % I1ii11iIi11i / i1IIi . ooOoO0o
  oOoOOo = [ ]
  Ii111i1iI111 = False
  if ( O00 . eid . address == 0 and O00 . eid . mask_len == 0 ) :
   O00Oo0o00 = [ ]
   iiI = [ ] if len ( Iiiii11ii1ii ) == 0 else Iiiii11ii1ii [ 0 ] . rle . rle_nodes
   if 4 - 4: i11iIiiIii % OoO0O00 . oO0o
   for OOoo0Oo00 in iiI :
    oOoOOo . append ( OOoo0Oo00 . address )
    O00Oo0o00 . append ( OOoo0Oo00 . address . print_address_no_iid ( ) )
    if 72 - 72: i1IIi + I1Ii111 . oO0o * oO0o * I1IiiI
   lprint ( "Notify existing RLE-nodes {}" . format ( O00Oo0o00 ) )
  else :
   if 40 - 40: OoO0O00 % ooOoO0o + iII111i + IiII + I11i * Oo0Ooo
   if 99 - 99: Oo0Ooo
   if 99 - 99: I1Ii111 + oO0o % OoooooooOO
   if 88 - 88: ooOoO0o % Oo0Ooo * II111iiii
   if 62 - 62: iII111i * I1Ii111 % OoOoOO00 * O0
   for IIiO0Ooo in Iiiii11ii1ii :
    if ( IIiO0Ooo . is_rtr ( ) ) : oOoOOo . append ( IIiO0Ooo . rloc )
    if 85 - 85: II111iiii - O0 . i11iIiiIii . o0oOOo0O0Ooo + ooOoO0o - ooOoO0o
    if 25 - 25: I1ii11iIi11i % Ii1I * O0 / I1IiiI % OOooOOo
    if 42 - 42: IiII - IiII - I1ii11iIi11i + i1IIi * Oo0Ooo
    if 80 - 80: oO0o + O0
    if 84 - 84: i1IIi - II111iiii
   Ii111i1iI111 = ( len ( oOoOOo ) != 0 )
   if ( Ii111i1iI111 == False ) :
    ooOOOo0o0oo = lisp_site_eid_lookup ( I111iiiIii1I [ 0 ] , O0OoO , False )
    if ( ooOOOo0o0oo == None ) : continue
    if 2 - 2: i11iIiiIii - OoO0O00 * Oo0Ooo
    for IIiO0Ooo in ooOOOo0o0oo . registered_rlocs :
     if ( IIiO0Ooo . rloc . is_null ( ) ) : continue
     oOoOOo . append ( IIiO0Ooo . rloc )
     if 100 - 100: I1Ii111
     if 5 - 5: IiII % oO0o . I1IiiI * II111iiii + o0oOOo0O0Ooo / Ii1I
     if 55 - 55: Oo0Ooo / o0oOOo0O0Ooo
     if 51 - 51: I1IiiI + i11iIiiIii / ooOoO0o % I1IiiI + Oo0Ooo
     if 6 - 6: OoOoOO00 . O0
     if 44 - 44: ooOoO0o % I11i + ooOoO0o . oO0o
   if ( len ( oOoOOo ) == 0 ) :
    lprint ( "No ITRs or RTRs found for {}, Map-Notify suppressed" . format ( green ( O00 . print_eid_tuple ( ) , False ) ) )
    if 70 - 70: O0 - I11i . iIii1I11I1II1 % I11i . OoOoOO00 % oO0o
    continue
    if 5 - 5: O0 * OoO0O00
    if 61 - 61: Ii1I / I11i + Ii1I . IiII - OoO0O00 - o0oOOo0O0Ooo
    if 84 - 84: OoooooooOO - Oo0Ooo
    if 86 - 86: O0 + OoO0O00 + O0 . I1IiiI
    if 82 - 82: OoOoOO00
    if 61 - 61: oO0o . o0oOOo0O0Ooo
  for I1IiIiIi in oOoOOo :
   lprint ( "Build Map-Notify to {}TR {} for {}" . format ( "R" if Ii111i1iI111 else "x" , red ( I1IiIiIi . print_address_no_iid ( ) , False ) ,
   # IiII - II111iiii + II111iiii / I1IiiI * OOooOOo
 green ( O00 . print_eid_tuple ( ) , False ) ) )
   if 9 - 9: I1IiiI % ooOoO0o
   oOooOooo000oO = [ O00 . print_eid_tuple ( ) ]
   lisp_send_multicast_map_notify ( lisp_sockets , O00 , oOooOooo000oO , I1IiIiIi )
   time . sleep ( .001 )
   if 56 - 56: i1IIi + Ii1I * iIii1I11I1II1
   if 1 - 1: iII111i
 return
 if 25 - 25: oO0o - i1IIi
 if 67 - 67: I1IiiI % I11i - OoooooooOO
 if 2 - 2: Ii1I
 if 25 - 25: I1Ii111 * I1IiiI + OoOoOO00 . i11iIiiIii . I1IiiI . I11i
 if 61 - 61: o0oOOo0O0Ooo / ooOoO0o + o0oOOo0O0Ooo + Ii1I * iIii1I11I1II1 * OoooooooOO
 if 86 - 86: oO0o . o0oOOo0O0Ooo * OoOoOO00 / oO0o
 if 47 - 47: OOooOOo
 if 40 - 40: I1ii11iIi11i
def lisp_find_sig_in_rloc_set ( packet , rloc_count ) :
 for Ii11 in range ( rloc_count ) :
  oooO0oo00oOOoo0O = lisp_rloc_record ( )
  packet = oooO0oo00oOOoo0O . decode ( packet , None )
  O00OO0oOo = oooO0oo00oOOoo0O . json
  if ( O00OO0oOo == None ) : continue
  if 43 - 43: i11iIiiIii + IiII % o0oOOo0O0Ooo * O0 * OoOoOO00 * i11iIiiIii
  try :
   O00OO0oOo = json . loads ( O00OO0oOo . json_string )
  except :
   lprint ( "Found corrupted JSON signature" )
   continue
   if 73 - 73: OoooooooOO
   if 68 - 68: i11iIiiIii - O0 - OoO0O00
  if ( O00OO0oOo . has_key ( "signature" ) == False ) : continue
  return ( oooO0oo00oOOoo0O )
  if 14 - 14: oO0o . ooOoO0o % i1IIi + i11iIiiIii
 return ( None )
 if 7 - 7: i11iIiiIii - o0oOOo0O0Ooo
 if 86 - 86: I1Ii111 / I1ii11iIi11i * iII111i . IiII * OoooooooOO - OoO0O00
 if 80 - 80: OoOoOO00 * iIii1I11I1II1 % O0 . O0
 if 100 - 100: OoO0O00 + II111iiii % oO0o / OoOoOO00 * OOooOOo
 if 23 - 23: OoOoOO00
 if 56 - 56: o0oOOo0O0Ooo / oO0o * I1Ii111 + iIii1I11I1II1 / IiII + o0oOOo0O0Ooo
 if 50 - 50: I1IiiI * ooOoO0o
 if 49 - 49: oO0o . I11i + OoooooooOO / iII111i * Oo0Ooo % iIii1I11I1II1
 if 49 - 49: II111iiii * iIii1I11I1II1 / OoooooooOO * i1IIi
 if 81 - 81: OoOoOO00 * i11iIiiIii + I1IiiI
 if 2 - 2: I11i - IiII + I1IiiI % OoO0O00 + iIii1I11I1II1 + oO0o
 if 49 - 49: I1IiiI * I1Ii111 . I1IiiI - II111iiii
 if 57 - 57: oO0o + O0 - OoOoOO00
 if 14 - 14: II111iiii + i11iIiiIii + Ii1I / o0oOOo0O0Ooo . OoO0O00
 if 93 - 93: o0oOOo0O0Ooo + i1IIi
 if 24 - 24: i1IIi
 if 54 - 54: iIii1I11I1II1 - IiII + o0oOOo0O0Ooo + I1ii11iIi11i + IiII
 if 99 - 99: Oo0Ooo
 if 38 - 38: I1ii11iIi11i - I1IiiI
def lisp_get_eid_hash ( eid ) :
 I1IIIIiIii = None
 for oO0OO in lisp_eid_hashes :
  if 29 - 29: IiII - I1ii11iIi11i . Oo0Ooo + IiII - I1IiiI
  if 95 - 95: O0 / o0oOOo0O0Ooo + OoO0O00 / IiII - IiII % OOooOOo
  if 16 - 16: I1IiiI * iIii1I11I1II1 % o0oOOo0O0Ooo - IiII - OOooOOo
  if 83 - 83: Ii1I
  o0OOoOO = oO0OO . instance_id
  if ( o0OOoOO == - 1 ) : oO0OO . instance_id = eid . instance_id
  if 20 - 20: ooOoO0o
  I1iII1 = eid . is_more_specific ( oO0OO )
  oO0OO . instance_id = o0OOoOO
  if ( I1iII1 ) :
   I1IIIIiIii = 128 - oO0OO . mask_len
   break
   if 41 - 41: iII111i * OOooOOo . oO0o / ooOoO0o + OoooooooOO + ooOoO0o
   if 100 - 100: I1IiiI / I1IiiI - I1IiiI % OOooOOo * O0 * I1IiiI
 if ( I1IIIIiIii == None ) : return ( None )
 if 20 - 20: iII111i + ooOoO0o . i11iIiiIii
 oOoO0Oo0 = eid . address
 Oo00O0OO0Oo0 = ""
 for Ii11 in range ( 0 , I1IIIIiIii / 16 ) :
  o0o0O00 = oOoO0Oo0 & 0xffff
  o0o0O00 = hex ( o0o0O00 ) [ 2 : - 1 ]
  Oo00O0OO0Oo0 = o0o0O00 . zfill ( 4 ) + ":" + Oo00O0OO0Oo0
  oOoO0Oo0 >>= 16
  if 19 - 19: I1IiiI . I1IiiI
 if ( I1IIIIiIii % 16 != 0 ) :
  o0o0O00 = oOoO0Oo0 & 0xff
  o0o0O00 = hex ( o0o0O00 ) [ 2 : - 1 ]
  Oo00O0OO0Oo0 = o0o0O00 . zfill ( 2 ) + ":" + Oo00O0OO0Oo0
  if 97 - 97: iII111i % i1IIi . O0 % II111iiii * I1Ii111 / i1IIi
 return ( Oo00O0OO0Oo0 [ 0 : - 1 ] )
 if 97 - 97: ooOoO0o
 if 46 - 46: II111iiii - i1IIi
 if 72 - 72: I11i
 if 35 - 35: I1Ii111 + oO0o + II111iiii
 if 71 - 71: OoOoOO00 * OoOoOO00
 if 27 - 27: II111iiii + OoooooooOO - I11i * o0oOOo0O0Ooo
 if 67 - 67: i11iIiiIii - OoOoOO00
 if 90 - 90: i11iIiiIii . I1ii11iIi11i - OoooooooOO / o0oOOo0O0Ooo
 if 58 - 58: II111iiii + iIii1I11I1II1
 if 51 - 51: ooOoO0o - Ii1I + ooOoO0o
 if 87 - 87: O0 - I1IiiI
def lisp_lookup_public_key ( eid ) :
 o0OOoOO = eid . instance_id
 if 37 - 37: Oo0Ooo - o0oOOo0O0Ooo * II111iiii / ooOoO0o
 if 90 - 90: iIii1I11I1II1 . II111iiii % I1Ii111
 if 28 - 28: i11iIiiIii + OoO0O00 % O0 - I1ii11iIi11i % oO0o
 if 30 - 30: I11i + OOooOOo
 if 27 - 27: OoOoOO00 . ooOoO0o
 ooooOOoO = lisp_get_eid_hash ( eid )
 if ( ooooOOoO == None ) : return ( [ None , None , False ] )
 if 8 - 8: ooOoO0o % o0oOOo0O0Ooo
 ooooOOoO = "hash-" + ooooOOoO
 oO0oOOoo0Oooo = lisp_address ( LISP_AFI_NAME , ooooOOoO , len ( ooooOOoO ) , o0OOoOO )
 ii1I1 = lisp_address ( LISP_AFI_NONE , "" , 0 , o0OOoOO )
 if 22 - 22: O0 * IiII . OoO0O00
 if 63 - 63: oO0o % Oo0Ooo * OoO0O00 / II111iiii / Ii1I - ooOoO0o
 if 14 - 14: ooOoO0o . o0oOOo0O0Ooo + II111iiii
 if 50 - 50: Ii1I - i1IIi * oO0o
 ooOOOo0o0oo = lisp_site_eid_lookup ( oO0oOOoo0Oooo , ii1I1 , True )
 if ( ooOOOo0o0oo == None ) : return ( [ oO0oOOoo0Oooo , None , False ] )
 if 52 - 52: I11i / oO0o - oO0o
 if 84 - 84: iIii1I11I1II1 - o0oOOo0O0Ooo
 if 37 - 37: iII111i * o0oOOo0O0Ooo
 if 23 - 23: ooOoO0o + OoooooooOO * iII111i . I11i
 iI1I = None
 for oOOoo0O00 in ooOOOo0o0oo . registered_rlocs :
  iiIIi1I1111Ii = oOOoo0O00 . json
  if ( iiIIi1I1111Ii == None ) : continue
  try :
   iiIIi1I1111Ii = json . loads ( iiIIi1I1111Ii . json_string )
  except :
   lprint ( "Registered RLOC JSON format is invalid for {}" . format ( ooooOOoO ) )
   if 23 - 23: oO0o . Ii1I - OOooOOo . iII111i - Oo0Ooo / O0
   return ( [ oO0oOOoo0Oooo , None , False ] )
   if 84 - 84: Oo0Ooo * iIii1I11I1II1 - iII111i % OoooooooOO % o0oOOo0O0Ooo
  if ( iiIIi1I1111Ii . has_key ( "public-key" ) == False ) : continue
  iI1I = iiIIi1I1111Ii [ "public-key" ]
  break
  if 31 - 31: IiII - OOooOOo % IiII % O0
 return ( [ oO0oOOoo0Oooo , iI1I , True ] )
 if 1 - 1: iIii1I11I1II1
 if 33 - 33: IiII - OoooooooOO % i11iIiiIii - I1Ii111
 if 89 - 89: I1ii11iIi11i + I1ii11iIi11i / I1Ii111 - I11i % OoOoOO00 * OOooOOo
 if 80 - 80: I1Ii111 / OoOoOO00 % O0 / OoooooooOO * II111iiii
 if 80 - 80: OOooOOo . OoO0O00 + O0 / IiII
 if 30 - 30: Ii1I / I11i . II111iiii + ooOoO0o
 if 58 - 58: Oo0Ooo % OOooOOo - i11iIiiIii - I1Ii111 - Ii1I % OoO0O00
 if 67 - 67: I1Ii111 + OoO0O00 - oO0o / OOooOOo . OoooooooOO * O0
def lisp_verify_cga_sig ( eid , rloc_record ) :
 if 91 - 91: O0 * OoOoOO00 - OoOoOO00 * II111iiii - iII111i
 if 38 - 38: oO0o * I11i % OOooOOo
 if 80 - 80: O0 % II111iiii / O0 . Oo0Ooo * OoOoOO00 + OOooOOo
 if 47 - 47: Ii1I - Oo0Ooo * OoOoOO00
 if 20 - 20: oO0o
 iIiI1iI = json . loads ( rloc_record . json . json_string )
 if 48 - 48: I1IiiI % OoO0O00
 if ( lisp_get_eid_hash ( eid ) ) :
  I1III1iI1II = eid
 elif ( iIiI1iI . has_key ( "signature-eid" ) ) :
  i1ii11I1i1I = iIiI1iI [ "signature-eid" ]
  I1III1iI1II = lisp_address ( LISP_AFI_IPV6 , i1ii11I1i1I , 0 , 0 )
 else :
  lprint ( "  No signature-eid found in RLOC-record" )
  return ( False )
  if 87 - 87: ooOoO0o * iII111i + i1IIi * i11iIiiIii * IiII / II111iiii
  if 55 - 55: OoOoOO00
  if 53 - 53: iIii1I11I1II1 % I1Ii111 / Oo0Ooo % Oo0Ooo
  if 6 - 6: iII111i
  if 44 - 44: oO0o
 oO0oOOoo0Oooo , iI1I , IiiiI1I = lisp_lookup_public_key ( I1III1iI1II )
 if ( oO0oOOoo0Oooo == None ) :
  oOoo0OooOOo00 = green ( I1III1iI1II . print_address ( ) , False )
  lprint ( "  Could not parse hash in EID {}" . format ( oOoo0OooOOo00 ) )
  return ( False )
  if 69 - 69: i1IIi + ooOoO0o - OoO0O00
  if 4 - 4: i11iIiiIii + oO0o + IiII % IiII . i11iIiiIii - OOooOOo
 IIIIIiiIII = "found" if IiiiI1I else bold ( "not found" , False )
 oOoo0OooOOo00 = green ( oO0oOOoo0Oooo . print_address ( ) , False )
 lprint ( "  Lookup for crypto-hashed EID {} {}" . format ( oOoo0OooOOo00 , IIIIIiiIII ) )
 if ( IiiiI1I == False ) : return ( False )
 if 40 - 40: OoO0O00 * o0oOOo0O0Ooo / i1IIi * I1Ii111 * I1ii11iIi11i
 if ( iI1I == None ) :
  lprint ( "  RLOC-record with public-key not found" )
  return ( False )
  if 45 - 45: iII111i / Oo0Ooo - ooOoO0o . iII111i * OoOoOO00 / OoooooooOO
  if 66 - 66: I1IiiI
 IiI1ii1iI111I = iI1I [ 0 : 8 ] + "..." + iI1I [ - 8 : : ]
 lprint ( "  RLOC-record with public-key '{}' found" . format ( IiI1ii1iI111I ) )
 if 45 - 45: I1ii11iIi11i / OoooooooOO % iII111i
 if 22 - 22: I1Ii111
 if 41 - 41: O0 * i1IIi
 if 89 - 89: iIii1I11I1II1 . I11i % I1ii11iIi11i + II111iiii . OoO0O00
 if 5 - 5: I1ii11iIi11i / I1IiiI . iII111i
 iI1IIi1Ii1i = iIiI1iI [ "signature" ]
 if 79 - 79: oO0o . OoO0O00 * oO0o % iII111i
 try :
  iIiI1iI = binascii . a2b_base64 ( iI1IIi1Ii1i )
 except :
  lprint ( "  Incorrect padding in signature string" )
  return ( False )
  if 53 - 53: I1IiiI % IiII . I11i + OoOoOO00 . OoooooooOO + oO0o
  if 17 - 17: IiII
 I1o0o = len ( iIiI1iI )
 if ( I1o0o & 1 ) :
  lprint ( "  Signature length is odd, length {}" . format ( I1o0o ) )
  return ( False )
  if 63 - 63: I1ii11iIi11i % I11i % OoooooooOO
  if 100 - 100: O0
  if 9 - 9: Ii1I
  if 87 - 87: I1IiiI
  if 56 - 56: OOooOOo % oO0o - OoOoOO00
 IIIIII = I1III1iI1II . print_address ( )
 if 27 - 27: I1ii11iIi11i - IiII * OoooooooOO * I1ii11iIi11i + i11iIiiIii . IiII
 if 81 - 81: oO0o / iIii1I11I1II1
 if 15 - 15: Ii1I + I1IiiI . OOooOOo / OoooooooOO + I11i - I11i
 if 27 - 27: Ii1I / o0oOOo0O0Ooo . iIii1I11I1II1 . I1IiiI - OoO0O00
 iI1I = binascii . a2b_base64 ( iI1I )
 try :
  o0OoOo0o0OOoO0 = ecdsa . VerifyingKey . from_pem ( iI1I )
 except :
  i1iI1II1i1Ii1 = bold ( "Bad public-key" , False )
  lprint ( "  {}, not in PEM format" . format ( i1iI1II1i1Ii1 ) )
  return ( False )
  if 61 - 61: IiII + iII111i
  if 15 - 15: II111iiii / iIii1I11I1II1 / I1ii11iIi11i % OoOoOO00 % OoO0O00 - I1Ii111
  if 17 - 17: OoooooooOO
  if 23 - 23: OoO0O00
  if 26 - 26: I11i % IiII . OoooooooOO % i11iIiiIii * IiII
  if 55 - 55: I11i / I11i - IiII - I11i
  if 3 - 3: oO0o % o0oOOo0O0Ooo + OoOoOO00
  if 22 - 22: O0
  if 36 - 36: OOooOOo
  if 42 - 42: OOooOOo * ooOoO0o * i11iIiiIii + OoooooooOO . iIii1I11I1II1
  if 95 - 95: i1IIi * O0 / II111iiii * OoOoOO00 * I1IiiI
 try :
  o0O0OoOOo0o = o0OoOo0o0OOoO0 . verify ( iIiI1iI , IIIIII , hashfunc = hashlib . sha256 )
 except :
  lprint ( "  Signature library failed for signature data '{}'" . format ( IIIIII ) )
  if 38 - 38: OOooOOo - OoOoOO00 / OoO0O00 / o0oOOo0O0Ooo - i11iIiiIii
  lprint ( "  Signature used '{}'" . format ( iI1IIi1Ii1i ) )
  return ( False )
  if 4 - 4: I1IiiI * o0oOOo0O0Ooo - I11i - OoooooooOO . OoooooooOO
 return ( o0O0OoOOo0o )
 if 79 - 79: oO0o - iII111i
 if 34 - 34: OoooooooOO + Ii1I - iII111i + OoooooooOO / I1IiiI
 if 39 - 39: o0oOOo0O0Ooo . i1IIi * OoO0O00 / II111iiii / I1ii11iIi11i * OOooOOo
 if 39 - 39: O0 . OOooOOo
 if 95 - 95: I11i
 if 58 - 58: I1ii11iIi11i / i11iIiiIii + iII111i + I11i / oO0o
 if 8 - 8: I1ii11iIi11i
 if 100 - 100: OoooooooOO / I11i - Ii1I
 if 11 - 11: OoO0O00
 if 20 - 20: Oo0Ooo
def lisp_remove_eid_from_map_notify_queue ( eid_list ) :
 if 34 - 34: I1Ii111 % i11iIiiIii / oO0o - i1IIi . o0oOOo0O0Ooo / oO0o
 if 68 - 68: I1Ii111 % Ii1I * Oo0Ooo - O0 . IiII
 if 1 - 1: I1ii11iIi11i
 if 18 - 18: i11iIiiIii % OoO0O00 % OOooOOo . OOooOOo * Ii1I / II111iiii
 if 81 - 81: iII111i % IiII / I11i
 i11i11i = [ ]
 for oOoo0 in eid_list :
  for O0O0ooo in lisp_map_notify_queue :
   ooOo00 = lisp_map_notify_queue [ O0O0ooo ]
   if ( oOoo0 not in ooOo00 . eid_list ) : continue
   if 76 - 76: iII111i
   i11i11i . append ( O0O0ooo )
   oO00oo0 = ooOo00 . retransmit_timer
   if ( oO00oo0 ) : oO00oo0 . cancel ( )
   if 36 - 36: i11iIiiIii / OOooOOo . O0 . OoO0O00 - Ii1I
   lprint ( "Remove from Map-Notify queue nonce 0x{} for EID {}" . format ( ooOo00 . nonce_key , green ( oOoo0 , False ) ) )
   if 31 - 31: OoOoOO00 * o0oOOo0O0Ooo / O0 . iII111i / i11iIiiIii
   if 22 - 22: I1IiiI . OoooooooOO * I1ii11iIi11i + i11iIiiIii - O0 + i11iIiiIii
   if 98 - 98: OOooOOo + I1IiiI / IiII / OoooooooOO / OOooOOo
   if 8 - 8: OoooooooOO * OOooOOo * iII111i - iII111i
   if 32 - 32: I1Ii111
   if 28 - 28: I11i . i11iIiiIii % iIii1I11I1II1 + OoOoOO00
   if 4 - 4: OOooOOo + I1ii11iIi11i - iII111i + OOooOOo / IiII
 for O0O0ooo in i11i11i : lisp_map_notify_queue . pop ( O0O0ooo )
 return
 if 23 - 23: iIii1I11I1II1 + OoooooooOO + ooOoO0o . iII111i . Oo0Ooo - iIii1I11I1II1
 if 25 - 25: O0 + I1IiiI % OOooOOo / Oo0Ooo . IiII / I1Ii111
 if 84 - 84: ooOoO0o . O0 + I1IiiI * OoO0O00 - I1IiiI
 if 24 - 24: Ii1I
 if 23 - 23: Oo0Ooo * i1IIi / I1IiiI . I11i - I1ii11iIi11i . iIii1I11I1II1
 if 15 - 15: O0 + o0oOOo0O0Ooo / oO0o
 if 27 - 27: Ii1I * II111iiii / oO0o
 if 99 - 99: I11i + ooOoO0o % I11i + O0 - Ii1I - I1Ii111
def lisp_decrypt_map_register ( packet ) :
 if 3 - 3: Oo0Ooo . I1IiiI
 if 61 - 61: OoO0O00 - I1ii11iIi11i . Ii1I * i11iIiiIii
 if 97 - 97: ooOoO0o
 if 58 - 58: iII111i
 if 47 - 47: II111iiii % Oo0Ooo . iIii1I11I1II1 . oO0o
 I1I = socket . ntohl ( struct . unpack ( "I" , packet [ 0 : 4 ] ) [ 0 ] )
 O00OO0O0O0ooo = ( I1I >> 13 ) & 0x1
 if ( O00OO0O0O0ooo == 0 ) : return ( packet )
 if 85 - 85: O0 * i1IIi . I1IiiI % Oo0Ooo / II111iiii / Ii1I
 Oo000OooOO = ( I1I >> 14 ) & 0x7
 if 96 - 96: oO0o . ooOoO0o * Oo0Ooo % ooOoO0o + I1Ii111 + iIii1I11I1II1
 if 45 - 45: II111iiii
 if 42 - 42: ooOoO0o
 if 62 - 62: II111iiii * o0oOOo0O0Ooo . OoO0O00 / II111iiii
 try :
  IIiiIiI = lisp_ms_encryption_keys [ Oo000OooOO ]
  IIiiIiI = IIiiIiI . zfill ( 32 )
  O0o = "0" * 8
 except :
  lprint ( "Cannot decrypt Map-Register with key-id {}" . format ( Oo000OooOO ) )
  return ( None )
  if 34 - 34: OOooOOo / I11i / OoooooooOO + i11iIiiIii / II111iiii - O0
  if 37 - 37: i1IIi . oO0o * o0oOOo0O0Ooo + I1ii11iIi11i - OoO0O00
 oOo0OOOOOO = bold ( "Decrypt" , False )
 lprint ( "{} Map-Register with key-id {}" . format ( oOo0OOOOOO , Oo000OooOO ) )
 if 62 - 62: I11i * oO0o
 Oooo = chacha . ChaCha ( IIiiIiI , O0o ) . decrypt ( packet [ 4 : : ] )
 return ( packet [ 0 : 4 ] + Oooo )
 if 91 - 91: I1Ii111
 if 77 - 77: I1ii11iIi11i . ooOoO0o - iIii1I11I1II1 + Ii1I % II111iiii * II111iiii
 if 41 - 41: II111iiii + Oo0Ooo - IiII / I1Ii111 - OOooOOo . oO0o
 if 100 - 100: ooOoO0o / I1ii11iIi11i * OoOoOO00 . I1ii11iIi11i . o0oOOo0O0Ooo * iIii1I11I1II1
 if 15 - 15: iII111i + o0oOOo0O0Ooo / IiII
 if 33 - 33: OoooooooOO . IiII * o0oOOo0O0Ooo
 if 41 - 41: Ii1I . iII111i . o0oOOo0O0Ooo % OoooooooOO % IiII
def lisp_process_map_register ( lisp_sockets , packet , source , sport ) :
 global lisp_registered_count
 if 81 - 81: IiII * i11iIiiIii + i1IIi + OOooOOo . i1IIi
 if 6 - 6: i11iIiiIii - oO0o % OoO0O00 + iIii1I11I1II1
 if 69 - 69: IiII
 if 13 - 13: i11iIiiIii
 if 49 - 49: OoOoOO00
 if 61 - 61: I1Ii111 / I1Ii111 / iII111i / ooOoO0o - I1IiiI . o0oOOo0O0Ooo
 packet = lisp_decrypt_map_register ( packet )
 if ( packet == None ) : return
 if 80 - 80: I1IiiI - OOooOOo . oO0o
 oOOOoO0 = lisp_map_register ( )
 iIiiII11 , packet = oOOOoO0 . decode ( packet )
 if ( packet == None ) :
  lprint ( "Could not decode Map-Register packet" )
  return
  if 23 - 23: ooOoO0o / OoOoOO00 * OOooOOo . O0 - OOooOOo
 oOOOoO0 . sport = sport
 if 5 - 5: OOooOOo % I1Ii111 * II111iiii
 oOOOoO0 . print_map_register ( )
 if 69 - 69: OoO0O00 . o0oOOo0O0Ooo
 if 86 - 86: I1ii11iIi11i
 if 51 - 51: O0 % OoO0O00 - I1Ii111
 if 82 - 82: OoOoOO00 - OOooOOo . i1IIi / I11i
 Iiii = True
 if ( oOOOoO0 . auth_len == LISP_SHA1_160_AUTH_DATA_LEN ) :
  Iiii = True
  if 8 - 8: O0 / OOooOOo + iII111i % iIii1I11I1II1 % iIii1I11I1II1 . ooOoO0o
 if ( oOOOoO0 . alg_id == LISP_SHA_256_128_ALG_ID ) :
  Iiii = False
  if 47 - 47: OoO0O00 / o0oOOo0O0Ooo / Ii1I * I1IiiI % ooOoO0o / I1Ii111
  if 80 - 80: I1Ii111 / O0 * O0
  if 40 - 40: OoO0O00 - oO0o / o0oOOo0O0Ooo . oO0o
  if 89 - 89: i11iIiiIii - II111iiii
  if 67 - 67: IiII % I1Ii111 + i11iIiiIii
 o00OO00o00 = [ ]
 if 19 - 19: O0 / OOooOOo / I1Ii111 . o0oOOo0O0Ooo
 if 22 - 22: O0 * OOooOOo - OoooooooOO - Ii1I * I1ii11iIi11i
 if 21 - 21: I1IiiI . i11iIiiIii - o0oOOo0O0Ooo * II111iiii % iIii1I11I1II1
 if 9 - 9: I1ii11iIi11i + I11i
 I1ii1I = None
 o0OOO0O = packet
 IiiiIIIi = [ ]
 oooOooOoO = oOOOoO0 . record_count
 for Ii11 in range ( oooOooOoO ) :
  iI1iii1IIIIi = lisp_eid_record ( )
  oooO0oo00oOOoo0O = lisp_rloc_record ( )
  packet = iI1iii1IIIIi . decode ( packet )
  if ( packet == None ) :
   lprint ( "Could not decode EID-record in Map-Register packet" )
   return
   if 32 - 32: o0oOOo0O0Ooo + OoooooooOO + I1ii11iIi11i + OoooooooOO . OOooOOo * o0oOOo0O0Ooo
  iI1iii1IIIIi . print_record ( "  " , False )
  if 8 - 8: I1ii11iIi11i . o0oOOo0O0Ooo + OoooooooOO
  if 52 - 52: i1IIi - oO0o
  if 33 - 33: Ii1I / I1ii11iIi11i . ooOoO0o . OoooooooOO
  if 45 - 45: OoO0O00 . I1ii11iIi11i + Ii1I / I11i - ooOoO0o / OoooooooOO
  ooOOOo0o0oo = lisp_site_eid_lookup ( iI1iii1IIIIi . eid , iI1iii1IIIIi . group ,
 False )
  if 44 - 44: OoO0O00 % O0 * IiII + iII111i
  o0OOoOOoo0oo0 = ooOOOo0o0oo . print_eid_tuple ( ) if ooOOOo0o0oo else None
  if 1 - 1: ooOoO0o . IiII
  if 4 - 4: iIii1I11I1II1 % I1IiiI - OoooooooOO / iII111i
  if 55 - 55: O0 + iII111i * OoOoOO00 . i11iIiiIii * Ii1I + oO0o
  if 66 - 66: i1IIi . I1ii11iIi11i
  if 86 - 86: Oo0Ooo
  if 48 - 48: OoO0O00
  if 55 - 55: OoO0O00 * i1IIi * I11i / iII111i
  if ( ooOOOo0o0oo and ooOOOo0o0oo . accept_more_specifics == False ) :
   if ( ooOOOo0o0oo . eid_record_matches ( iI1iii1IIIIi ) == False ) :
    iiiIIIII1iIi = ooOOOo0o0oo . parent_for_more_specifics
    if ( iiiIIIII1iIi ) : ooOOOo0o0oo = iiiIIIII1iIi
    if 8 - 8: o0oOOo0O0Ooo * OoO0O00 % IiII / OoooooooOO * ooOoO0o - i11iIiiIii
    if 14 - 14: Oo0Ooo . iII111i
    if 50 - 50: iIii1I11I1II1
    if 48 - 48: Ii1I - o0oOOo0O0Ooo - Oo0Ooo . iIii1I11I1II1
    if 1 - 1: i1IIi % OoooooooOO
    if 30 - 30: ooOoO0o % I11i
    if 4 - 4: oO0o / OoO0O00
    if 90 - 90: I11i . IiII / OoO0O00 . IiII
  OoO0OOoooooOO = ( ooOOOo0o0oo and ooOOOo0o0oo . accept_more_specifics )
  if ( OoO0OOoooooOO ) :
   i1iIIiii = lisp_site_eid ( ooOOOo0o0oo . site )
   i1iIIiii . dynamic = True
   i1iIIiii . eid . copy_address ( iI1iii1IIIIi . eid )
   i1iIIiii . group . copy_address ( iI1iii1IIIIi . group )
   i1iIIiii . parent_for_more_specifics = ooOOOo0o0oo
   i1iIIiii . add_cache ( )
   i1iIIiii . inherit_from_ams_parent ( )
   ooOOOo0o0oo . more_specific_registrations . append ( i1iIIiii )
   ooOOOo0o0oo = i1iIIiii
  else :
   ooOOOo0o0oo = lisp_site_eid_lookup ( iI1iii1IIIIi . eid , iI1iii1IIIIi . group ,
 True )
   if 2 - 2: I11i + I1IiiI . IiII . OoOoOO00 * oO0o - ooOoO0o
   if 29 - 29: OoO0O00
  oOoo0OooOOo00 = iI1iii1IIIIi . print_eid_tuple ( )
  if 78 - 78: iII111i * ooOoO0o + O0 % ooOoO0o + OoO0O00
  if ( ooOOOo0o0oo == None ) :
   OOOO0OOoO = bold ( "Site not found" , False )
   lprint ( "  {} for EID {}{}" . format ( OOOO0OOoO , green ( oOoo0OooOOo00 , False ) ,
 ", matched non-ams {}" . format ( green ( o0OOoOOoo0oo0 , False ) if o0OOoOOoo0oo0 else "" ) ) )
   if 41 - 41: II111iiii . oO0o + O0 % i1IIi . Ii1I
   if 90 - 90: ooOoO0o * I1IiiI / II111iiii % Oo0Ooo % OoooooooOO
   if 78 - 78: OoooooooOO . IiII
   if 55 - 55: I11i / I1ii11iIi11i * O0 + IiII % I11i
   if 69 - 69: o0oOOo0O0Ooo % iIii1I11I1II1 . OoooooooOO - ooOoO0o
   packet = oooO0oo00oOOoo0O . end_of_rlocs ( packet , iI1iii1IIIIi . rloc_count )
   if ( packet == None ) :
    lprint ( "  Could not decode RLOC-record in Map-Register packet" )
    return
    if 94 - 94: iIii1I11I1II1 / Oo0Ooo % IiII * IiII
   continue
   if 62 - 62: I11i . IiII - OOooOOo - I1Ii111 / OoooooooOO . Ii1I
   if 28 - 28: iII111i / I1ii11iIi11i - OoOoOO00 * Oo0Ooo + Ii1I * OoOoOO00
  I1ii1I = ooOOOo0o0oo . site
  if 94 - 94: oO0o
  if ( OoO0OOoooooOO ) :
   ooo0OO = ooOOOo0o0oo . parent_for_more_specifics . print_eid_tuple ( )
   lprint ( "  Found ams {} for site '{}' for registering prefix {}" . format ( green ( ooo0OO , False ) , I1ii1I . site_name , green ( oOoo0OooOOo00 , False ) ) )
   if 95 - 95: ooOoO0o * O0 + OOooOOo
  else :
   ooo0OO = green ( ooOOOo0o0oo . print_eid_tuple ( ) , False )
   lprint ( "  Found {} for site '{}' for registering prefix {}" . format ( ooo0OO , I1ii1I . site_name , green ( oOoo0OooOOo00 , False ) ) )
   if 11 - 11: i1IIi / OoOoOO00 + OoOoOO00 + I1ii11iIi11i + OOooOOo
   if 21 - 21: ooOoO0o
   if 28 - 28: OoOoOO00 + OoOoOO00 - OoOoOO00 / ooOoO0o
   if 81 - 81: oO0o
   if 34 - 34: o0oOOo0O0Ooo * OOooOOo - i1IIi * o0oOOo0O0Ooo * Oo0Ooo
   if 59 - 59: iIii1I11I1II1 / Oo0Ooo % II111iiii
  if ( I1ii1I . shutdown ) :
   lprint ( ( "  Rejecting registration for site '{}', configured in " +
 "admin-shutdown state" ) . format ( I1ii1I . site_name ) )
   packet = oooO0oo00oOOoo0O . end_of_rlocs ( packet , iI1iii1IIIIi . rloc_count )
   continue
   if 55 - 55: ooOoO0o - IiII + o0oOOo0O0Ooo
   if 48 - 48: O0 - iIii1I11I1II1 * OOooOOo
   if 33 - 33: I11i
   if 63 - 63: Ii1I % II111iiii / OoOoOO00 + Oo0Ooo
   if 28 - 28: OoO0O00 + I1IiiI . oO0o + II111iiii - O0
   if 32 - 32: oO0o
   if 62 - 62: i11iIiiIii + OoooooooOO + IiII - OoO0O00 / oO0o * iIii1I11I1II1
   if 91 - 91: o0oOOo0O0Ooo - i11iIiiIii + Oo0Ooo % iIii1I11I1II1
  o0OOOoO0O = oOOOoO0 . key_id
  if ( I1ii1I . auth_key . has_key ( o0OOOoO0O ) == False ) : o0OOOoO0O = 0
  O0O0 = I1ii1I . auth_key [ o0OOOoO0O ]
  if 40 - 40: I1Ii111 * OoOoOO00 * Ii1I % iII111i % ooOoO0o . Ii1I
  i111II = lisp_verify_auth ( iIiiII11 , oOOOoO0 . alg_id ,
 oOOOoO0 . auth_data , O0O0 )
  iiIi1i1i = "dynamic " if ooOOOo0o0oo . dynamic else ""
  if 69 - 69: i11iIiiIii + Oo0Ooo / II111iiii % OoOoOO00
  O0O0oooo = bold ( "passed" if i111II else "failed" , False )
  o0OOOoO0O = "key-id {}" . format ( o0OOOoO0O ) if o0OOOoO0O == oOOOoO0 . key_id else "bad key-id {}" . format ( oOOOoO0 . key_id )
  if 4 - 4: II111iiii + ooOoO0o
  lprint ( "  Authentication {} for {}EID-prefix {}, {}" . format ( O0O0oooo , iiIi1i1i , green ( oOoo0OooOOo00 , False ) , o0OOOoO0O ) )
  if 25 - 25: I1IiiI - iIii1I11I1II1
  if 11 - 11: I1Ii111 / iII111i - I11i
  if 87 - 87: I1Ii111 * i11iIiiIii . OOooOOo . OoooooooOO
  if 2 - 2: i11iIiiIii + oO0o
  if 40 - 40: i11iIiiIii + oO0o * IiII
  if 19 - 19: iII111i / II111iiii . I1Ii111 * I1IiiI - OOooOOo
  oO0OoO0 = True
  O0o0O0oooo0O = ( lisp_get_eid_hash ( iI1iii1IIIIi . eid ) != None )
  if ( O0o0O0oooo0O or ooOOOo0o0oo . require_signature ) :
   o000000oOooO = "Required " if ooOOOo0o0oo . require_signature else ""
   oOoo0OooOOo00 = green ( oOoo0OooOOo00 , False )
   oOOoo0O00 = lisp_find_sig_in_rloc_set ( packet , iI1iii1IIIIi . rloc_count )
   if ( oOOoo0O00 == None ) :
    oO0OoO0 = False
    lprint ( ( "  {}EID-crypto-hash signature verification {} " + "for EID-prefix {}, no signature found" ) . format ( o000000oOooO ,
    # OOooOOo
 bold ( "failed" , False ) , oOoo0OooOOo00 ) )
   else :
    oO0OoO0 = lisp_verify_cga_sig ( iI1iii1IIIIi . eid , oOOoo0O00 )
    O0O0oooo = bold ( "passed" if oO0OoO0 else "failed" , False )
    lprint ( ( "  {}EID-crypto-hash signature verification {} " + "for EID-prefix {}" ) . format ( o000000oOooO , O0O0oooo , oOoo0OooOOo00 ) )
    if 88 - 88: OoooooooOO / iII111i + i1IIi
    if 64 - 64: IiII % I11i / iIii1I11I1II1
    if 66 - 66: Ii1I
    if 55 - 55: OOooOOo + I1IiiI + IiII . Ii1I * oO0o
  if ( i111II == False or oO0OoO0 == False ) :
   packet = oooO0oo00oOOoo0O . end_of_rlocs ( packet , iI1iii1IIIIi . rloc_count )
   if ( packet == None ) :
    lprint ( "  Could not decode RLOC-record in Map-Register packet" )
    return
    if 71 - 71: IiII - iII111i % I1IiiI * iII111i
   continue
   if 27 - 27: ooOoO0o - OoO0O00
   if 83 - 83: iII111i * OoOoOO00 - O0 * Ii1I
   if 79 - 79: I11i / iII111i % Ii1I / OoOoOO00 % O0 / IiII
   if 32 - 32: IiII * II111iiii . Ii1I
   if 68 - 68: I11i / O0
   if 6 - 6: oO0o - oO0o . I1IiiI % I1ii11iIi11i
  if ( oOOOoO0 . merge_register_requested ) :
   iiiIIIII1iIi = ooOOOo0o0oo
   iiiIIIII1iIi . inconsistent_registration = False
   if 22 - 22: Ii1I / I1IiiI / II111iiii
   if 31 - 31: II111iiii - Ii1I * OOooOOo - i11iIiiIii / OoooooooOO - I1Ii111
   if 76 - 76: Oo0Ooo
   if 93 - 93: i1IIi - I1IiiI * i11iIiiIii / Ii1I . Ii1I - i1IIi
   if 19 - 19: iIii1I11I1II1 * OOooOOo * Oo0Ooo % I1IiiI
   if ( ooOOOo0o0oo . group . is_null ( ) ) :
    if ( iiiIIIII1iIi . site_id != oOOOoO0 . site_id ) :
     iiiIIIII1iIi . site_id = oOOOoO0 . site_id
     iiiIIIII1iIi . registered = False
     iiiIIIII1iIi . individual_registrations = { }
     iiiIIIII1iIi . registered_rlocs = [ ]
     lisp_registered_count -= 1
     if 93 - 93: IiII % OoOoOO00 / I1IiiI + o0oOOo0O0Ooo * ooOoO0o / i1IIi
     if 25 - 25: O0 / Oo0Ooo - o0oOOo0O0Ooo * Oo0Ooo
     if 45 - 45: Ii1I * IiII - OOooOOo
   o0OoOo0o0OOoO0 = source . address + oOOOoO0 . xtr_id
   if ( ooOOOo0o0oo . individual_registrations . has_key ( o0OoOo0o0OOoO0 ) ) :
    ooOOOo0o0oo = ooOOOo0o0oo . individual_registrations [ o0OoOo0o0OOoO0 ]
   else :
    ooOOOo0o0oo = lisp_site_eid ( I1ii1I )
    ooOOOo0o0oo . eid . copy_address ( iiiIIIII1iIi . eid )
    ooOOOo0o0oo . group . copy_address ( iiiIIIII1iIi . group )
    iiiIIIII1iIi . individual_registrations [ o0OoOo0o0OOoO0 ] = ooOOOo0o0oo
    if 57 - 57: iII111i % OoO0O00 / OoooooooOO
  else :
   ooOOOo0o0oo . inconsistent_registration = ooOOOo0o0oo . merge_register_requested
   if 69 - 69: oO0o
   if 44 - 44: IiII - II111iiii % Ii1I
   if 64 - 64: Ii1I % OoO0O00 + OOooOOo % OoOoOO00 + IiII
  ooOOOo0o0oo . map_registers_received += 1
  if 92 - 92: iII111i * Oo0Ooo - OoOoOO00
  if 33 - 33: i11iIiiIii - OoOoOO00 . OOooOOo * II111iiii . Ii1I
  if 59 - 59: OoOoOO00
  if 29 - 29: iII111i - II111iiii * OoooooooOO * OoooooooOO
  if 15 - 15: IiII / OOooOOo / iIii1I11I1II1 / OoOoOO00
  i1iI1II1i1Ii1 = ( ooOOOo0o0oo . is_rloc_in_rloc_set ( source ) == False )
  if ( iI1iii1IIIIi . record_ttl == 0 and i1iI1II1i1Ii1 ) :
   lprint ( "  Ignore deregistration request from {}" . format ( red ( source . print_address_no_iid ( ) , False ) ) )
   if 91 - 91: i11iIiiIii % O0 . Oo0Ooo / I1Ii111
   continue
   if 62 - 62: Oo0Ooo . II111iiii % OoO0O00 . Ii1I * OOooOOo + II111iiii
   if 7 - 7: OOooOOo
   if 22 - 22: Oo0Ooo + ooOoO0o
   if 71 - 71: OOooOOo . Ii1I * i11iIiiIii . I11i
   if 9 - 9: O0 / I1ii11iIi11i . iII111i . O0 + IiII % I11i
   if 27 - 27: i11iIiiIii - I1ii11iIi11i / O0 - i1IIi + I1IiiI * iII111i
  iI1iIIIIiiii = ooOOOo0o0oo . registered_rlocs
  ooOOOo0o0oo . registered_rlocs = [ ]
  if 17 - 17: II111iiii - I1Ii111 - i11iIiiIii - iIii1I11I1II1
  if 10 - 10: I1IiiI
  if 40 - 40: OoO0O00 * oO0o / OoOoOO00
  if 37 - 37: iII111i * oO0o / I1IiiI * I1ii11iIi11i
  oOo0000 = packet
  for Ii1i1Ii in range ( iI1iii1IIIIi . rloc_count ) :
   oooO0oo00oOOoo0O = lisp_rloc_record ( )
   packet = oooO0oo00oOOoo0O . decode ( packet , None )
   if ( packet == None ) :
    lprint ( "  Could not decode RLOC-record in Map-Register packet" )
    return
    if 59 - 59: I1Ii111 % o0oOOo0O0Ooo - I1IiiI * i1IIi
   oooO0oo00oOOoo0O . print_record ( "    " )
   if 5 - 5: I1IiiI
   if 22 - 22: II111iiii / iII111i
   if 18 - 18: i11iIiiIii * ooOoO0o . I1IiiI + i1IIi + I11i
   if 62 - 62: O0 % o0oOOo0O0Ooo + iIii1I11I1II1 + iIii1I11I1II1 * ooOoO0o
   if ( len ( I1ii1I . allowed_rlocs ) > 0 ) :
    I1iiIiiii1111 = oooO0oo00oOOoo0O . rloc . print_address ( )
    if ( I1ii1I . allowed_rlocs . has_key ( I1iiIiiii1111 ) == False ) :
     lprint ( ( "  Reject registration, RLOC {} not " + "configured in allowed RLOC-set" ) . format ( red ( I1iiIiiii1111 , False ) ) )
     if 21 - 21: o0oOOo0O0Ooo % O0
     if 81 - 81: i1IIi + i1IIi
     ooOOOo0o0oo . registered = False
     packet = oooO0oo00oOOoo0O . end_of_rlocs ( packet ,
 iI1iii1IIIIi . rloc_count - Ii1i1Ii - 1 )
     break
     if 3 - 3: I1Ii111 . I1ii11iIi11i * iII111i * i11iIiiIii * IiII
     if 52 - 52: iIii1I11I1II1 % o0oOOo0O0Ooo % I1IiiI
     if 71 - 71: I1IiiI + iII111i
     if 47 - 47: iIii1I11I1II1 . OoO0O00 . iIii1I11I1II1
     if 57 - 57: IiII * ooOoO0o * ooOoO0o * iIii1I11I1II1 * I1Ii111 + OoOoOO00
     if 83 - 83: OoOoOO00 . Oo0Ooo . OoO0O00
   oOOoo0O00 = lisp_rloc ( )
   oOOoo0O00 . store_rloc_from_record ( oooO0oo00oOOoo0O , None , source )
   if 65 - 65: iII111i * iIii1I11I1II1
   if 48 - 48: iII111i * OoO0O00
   if 57 - 57: ooOoO0o + I1IiiI
   if 32 - 32: I1ii11iIi11i + OOooOOo - I11i
   if 82 - 82: Oo0Ooo % Oo0Ooo
   if 91 - 91: I11i
   if ( source . is_exact_match ( oOOoo0O00 . rloc ) ) :
    oOOoo0O00 . map_notify_requested = oOOOoO0 . map_notify_requested
    if 98 - 98: I11i - II111iiii . IiII % Oo0Ooo
    if 65 - 65: OoO0O00
    if 65 - 65: oO0o
    if 77 - 77: I11i * i1IIi - OOooOOo / OoOoOO00
    if 50 - 50: O0 - oO0o . oO0o
   ooOOOo0o0oo . registered_rlocs . append ( oOOoo0O00 )
   if 98 - 98: IiII % Ii1I / Ii1I
   if 10 - 10: Ii1I
  O0oo0Oo0Oo00o = ( ooOOOo0o0oo . do_rloc_sets_match ( iI1iIIIIiiii ) == False )
  if 94 - 94: O0 + II111iiii - iII111i / i1IIi
  if 25 - 25: ooOoO0o . OoO0O00 - oO0o
  if 76 - 76: iIii1I11I1II1 / II111iiii * OoOoOO00 % iII111i . II111iiii + i11iIiiIii
  if 41 - 41: oO0o . o0oOOo0O0Ooo . I11i
  if 53 - 53: I11i
  if 64 - 64: OoO0O00 + I11i / I1IiiI . II111iiii
  if ( oOOOoO0 . map_register_refresh and O0oo0Oo0Oo00o and
 ooOOOo0o0oo . registered ) :
   lprint ( "  Reject registration, refreshes cannot change RLOC-set" )
   ooOOOo0o0oo . registered_rlocs = iI1iIIIIiiii
   continue
   if 79 - 79: I1Ii111 + IiII / OoooooooOO
   if 53 - 53: Ii1I
   if 85 - 85: OoO0O00 + II111iiii / OoO0O00 . II111iiii * OoOoOO00 * I1IiiI
   if 19 - 19: iII111i / Ii1I + iIii1I11I1II1 * O0 - Oo0Ooo
   if 47 - 47: iIii1I11I1II1 % I1ii11iIi11i
   if 33 - 33: oO0o . oO0o / IiII + II111iiii
  if ( ooOOOo0o0oo . registered == False ) :
   ooOOOo0o0oo . first_registered = lisp_get_timestamp ( )
   lisp_registered_count += 1
   if 34 - 34: OoO0O00 . OoOoOO00 / i1IIi / OOooOOo
  ooOOOo0o0oo . last_registered = lisp_get_timestamp ( )
  ooOOOo0o0oo . registered = ( iI1iii1IIIIi . record_ttl != 0 )
  ooOOOo0o0oo . last_registerer = source
  if 12 - 12: o0oOOo0O0Ooo . Oo0Ooo / II111iiii
  if 18 - 18: I1Ii111 % II111iiii + Ii1I * Oo0Ooo - OoooooooOO . Oo0Ooo
  if 25 - 25: OoO0O00
  if 83 - 83: II111iiii . iIii1I11I1II1
  ooOOOo0o0oo . auth_sha1_or_sha2 = Iiii
  ooOOOo0o0oo . proxy_reply_requested = oOOOoO0 . proxy_reply_requested
  ooOOOo0o0oo . lisp_sec_present = oOOOoO0 . lisp_sec_present
  ooOOOo0o0oo . map_notify_requested = oOOOoO0 . map_notify_requested
  ooOOOo0o0oo . mobile_node_requested = oOOOoO0 . mobile_node
  ooOOOo0o0oo . merge_register_requested = oOOOoO0 . merge_register_requested
  if 77 - 77: O0 . OoOoOO00 % oO0o / OOooOOo
  ooOOOo0o0oo . use_register_ttl_requested = oOOOoO0 . use_ttl_for_timeout
  if ( ooOOOo0o0oo . use_register_ttl_requested ) :
   ooOOOo0o0oo . register_ttl = iI1iii1IIIIi . store_ttl ( )
  else :
   ooOOOo0o0oo . register_ttl = LISP_SITE_TIMEOUT_CHECK_INTERVAL * 3
   if 8 - 8: iII111i - i1IIi
  ooOOOo0o0oo . xtr_id_present = oOOOoO0 . xtr_id_present
  if ( ooOOOo0o0oo . xtr_id_present ) :
   ooOOOo0o0oo . xtr_id = oOOOoO0 . xtr_id
   ooOOOo0o0oo . site_id = oOOOoO0 . site_id
   if 81 - 81: ooOoO0o / OOooOOo % OoOoOO00 . iIii1I11I1II1
   if 45 - 45: I1IiiI . ooOoO0o - OoooooooOO
   if 84 - 84: I1ii11iIi11i
   if 69 - 69: I1Ii111 + II111iiii
   if 92 - 92: OoooooooOO
  if ( oOOOoO0 . merge_register_requested ) :
   if ( iiiIIIII1iIi . merge_in_site_eid ( ooOOOo0o0oo ) ) :
    o00OO00o00 . append ( [ iI1iii1IIIIi . eid , iI1iii1IIIIi . group ] )
    if 80 - 80: I1ii11iIi11i % I1ii11iIi11i . OoO0O00 . oO0o % I1IiiI % I11i
   if ( oOOOoO0 . map_notify_requested ) :
    lisp_send_merged_map_notify ( lisp_sockets , iiiIIIII1iIi , oOOOoO0 ,
 iI1iii1IIIIi )
    if 4 - 4: OoO0O00 / iII111i / I1ii11iIi11i - o0oOOo0O0Ooo * I1Ii111
    if 24 - 24: OoooooooOO / ooOoO0o + Oo0Ooo - OOooOOo - o0oOOo0O0Ooo . I1ii11iIi11i
    if 2 - 2: I1IiiI . o0oOOo0O0Ooo / Oo0Ooo - OoOoOO00 - OoooooooOO
  if ( O0oo0Oo0Oo00o == False ) : continue
  if ( len ( o00OO00o00 ) != 0 ) : continue
  if 73 - 73: I1Ii111 . i11iIiiIii * ooOoO0o . IiII - I11i + I1Ii111
  IiiiIIIi . append ( ooOOOo0o0oo . print_eid_tuple ( ) )
  if 21 - 21: I1Ii111 + iIii1I11I1II1 + I1IiiI / O0 * I1ii11iIi11i
  if 57 - 57: OOooOOo * I11i . oO0o
  if 17 - 17: iII111i - OOooOOo * I1IiiI + i1IIi % I1ii11iIi11i
  if 71 - 71: Ii1I - o0oOOo0O0Ooo - oO0o
  if 27 - 27: O0 - iIii1I11I1II1
  if 78 - 78: Oo0Ooo / o0oOOo0O0Ooo
  if 35 - 35: o0oOOo0O0Ooo . OoO0O00 / o0oOOo0O0Ooo / IiII - I1ii11iIi11i . Oo0Ooo
  iI1iii1IIIIi = iI1iii1IIIIi . encode ( )
  iI1iii1IIIIi += oOo0000
  oOooOooo000oO = [ ooOOOo0o0oo . print_eid_tuple ( ) ]
  lprint ( "    Changed RLOC-set, Map-Notifying old RLOC-set" )
  if 97 - 97: i11iIiiIii + I1ii11iIi11i - I11i . oO0o
  for oOOoo0O00 in iI1iIIIIiiii :
   if ( oOOoo0O00 . map_notify_requested == False ) : continue
   if ( oOOoo0O00 . rloc . is_exact_match ( source ) ) : continue
   lisp_build_map_notify ( lisp_sockets , iI1iii1IIIIi , oOooOooo000oO , 1 , oOOoo0O00 . rloc ,
 LISP_CTRL_PORT , oOOOoO0 . nonce , oOOOoO0 . key_id ,
 oOOOoO0 . alg_id , oOOOoO0 . auth_len , I1ii1I , False )
   if 76 - 76: IiII * II111iiii * I1ii11iIi11i + OoooooooOO - OoOoOO00 . Ii1I
   if 51 - 51: II111iiii % I1Ii111 * O0 . ooOoO0o * OoOoOO00
   if 17 - 17: I1IiiI % I11i
   if 28 - 28: I1ii11iIi11i * OoooooooOO
   if 19 - 19: Oo0Ooo - iII111i % OoOoOO00 * i11iIiiIii / oO0o . i11iIiiIii
  lisp_notify_subscribers ( lisp_sockets , iI1iii1IIIIi , ooOOOo0o0oo . eid , I1ii1I )
  if 46 - 46: I1ii11iIi11i
  if 50 - 50: OOooOOo * OoO0O00 * OOooOOo % I1IiiI - I1Ii111 * Ii1I
  if 88 - 88: OOooOOo . iII111i / I11i
  if 1 - 1: iIii1I11I1II1 - Oo0Ooo % OoooooooOO
  if 71 - 71: OOooOOo - Ii1I
 if ( len ( o00OO00o00 ) != 0 ) :
  lisp_queue_multicast_map_notify ( lisp_sockets , o00OO00o00 )
  if 68 - 68: ooOoO0o
  if 35 - 35: IiII . iIii1I11I1II1 + Ii1I % O0
  if 94 - 94: OoOoOO00 + II111iiii . II111iiii + ooOoO0o + ooOoO0o
  if 95 - 95: iIii1I11I1II1 / i11iIiiIii - IiII - OOooOOo
  if 4 - 4: II111iiii + oO0o + o0oOOo0O0Ooo % IiII % iIii1I11I1II1
  if 68 - 68: i11iIiiIii
 if ( oOOOoO0 . merge_register_requested ) : return
 if 79 - 79: OoOoOO00 * Ii1I / I1ii11iIi11i + OOooOOo
 if 19 - 19: I1IiiI + I11i + I1IiiI + OoO0O00
 if 33 - 33: i11iIiiIii - Ii1I * II111iiii
 if 97 - 97: OoO0O00 / o0oOOo0O0Ooo * iIii1I11I1II1
 if 5 - 5: I1IiiI
 if ( oOOOoO0 . map_notify_requested and I1ii1I != None ) :
  lisp_build_map_notify ( lisp_sockets , o0OOO0O , IiiiIIIi ,
 oOOOoO0 . record_count , source , sport , oOOOoO0 . nonce ,
 oOOOoO0 . key_id , oOOOoO0 . alg_id , oOOOoO0 . auth_len ,
 I1ii1I , True )
  if 27 - 27: i1IIi + oO0o / I1ii11iIi11i + oO0o
 return
 if 98 - 98: II111iiii + iIii1I11I1II1
 if 70 - 70: I11i / OoooooooOO / i11iIiiIii
 if 61 - 61: O0 . Oo0Ooo . iIii1I11I1II1
 if 54 - 54: OOooOOo * I1ii11iIi11i + OoooooooOO
 if 58 - 58: i1IIi - OoooooooOO * OOooOOo . ooOoO0o + O0 + o0oOOo0O0Ooo
 if 87 - 87: OOooOOo + I1Ii111 + O0 / oO0o / i11iIiiIii
 if 60 - 60: O0 . II111iiii
 if 69 - 69: II111iiii / ooOoO0o - OoOoOO00 / OOooOOo
 if 52 - 52: OoO0O00 % I11i + o0oOOo0O0Ooo % OoOoOO00
 if 46 - 46: o0oOOo0O0Ooo % O0
def lisp_process_multicast_map_notify ( packet , source ) :
 ooOo00 = lisp_map_notify ( "" )
 packet = ooOo00 . decode ( packet )
 if ( packet == None ) :
  lprint ( "Could not decode Map-Notify packet" )
  return
  if 30 - 30: oO0o
  if 64 - 64: O0
 ooOo00 . print_notify ( )
 if ( ooOo00 . record_count == 0 ) : return
 if 70 - 70: oO0o % I1IiiI . iIii1I11I1II1 - Oo0Ooo + OoOoOO00 % O0
 O00OO0OO = ooOo00 . eid_records
 if 38 - 38: OoooooooOO . i1IIi - i1IIi + iIii1I11I1II1 * OOooOOo - I1IiiI
 for Ii11 in range ( ooOo00 . record_count ) :
  iI1iii1IIIIi = lisp_eid_record ( )
  O00OO0OO = iI1iii1IIIIi . decode ( O00OO0OO )
  if ( packet == None ) : return
  iI1iii1IIIIi . print_record ( "  " , False )
  if 92 - 92: I11i
  if 77 - 77: I11i / iII111i / O0 % II111iiii % OoOoOO00 / I1Ii111
  if 77 - 77: OoOoOO00 % I1IiiI % II111iiii * iII111i . OoOoOO00 / O0
  if 21 - 21: ooOoO0o - I11i . i11iIiiIii
  Iii1 = lisp_map_cache_lookup ( iI1iii1IIIIi . eid , iI1iii1IIIIi . group )
  if ( Iii1 == None ) :
   Iii1 = lisp_mapping ( iI1iii1IIIIi . eid , iI1iii1IIIIi . group , [ ] )
   Iii1 . add_cache ( )
   if 39 - 39: Oo0Ooo * II111iiii % OOooOOo / oO0o . ooOoO0o
   if 75 - 75: I11i / O0 + OoooooooOO + OOooOOo % iII111i + I1IiiI
  Iii1 . mapping_source = None if source == "lisp-etr" else source
  Iii1 . map_cache_ttl = iI1iii1IIIIi . store_ttl ( )
  if 10 - 10: II111iiii * I11i - IiII * iIii1I11I1II1 . OoooooooOO
  if 39 - 39: I11i . I1IiiI % Oo0Ooo + oO0o
  if 76 - 76: I1IiiI * OoooooooOO - i11iIiiIii / I11i / Oo0Ooo
  if 82 - 82: IiII % ooOoO0o
  if 100 - 100: Oo0Ooo . oO0o - iII111i + OoooooooOO
  if ( len ( Iii1 . rloc_set ) != 0 and iI1iii1IIIIi . rloc_count == 0 ) :
   Iii1 . rloc_set = [ ]
   Iii1 . build_best_rloc_set ( )
   lisp_write_ipc_map_cache ( True , Iii1 )
   lprint ( "Update {} map-cache entry with no RLOC-set" . format ( green ( Iii1 . print_eid_tuple ( ) , False ) ) )
   if 27 - 27: Oo0Ooo . I1Ii111 - i1IIi * I1IiiI
   continue
   if 96 - 96: I1ii11iIi11i - Ii1I . I1ii11iIi11i
   if 89 - 89: II111iiii % I1ii11iIi11i % IiII . I11i
  I11iI1iIi1i = Iii1 . rtrs_in_rloc_set ( )
  if 26 - 26: iIii1I11I1II1 + i11iIiiIii % iII111i + I1IiiI + oO0o - ooOoO0o
  if 4 - 4: Oo0Ooo - IiII - I11i
  if 72 - 72: OoooooooOO
  if 19 - 19: Oo0Ooo . OOooOOo
  if 58 - 58: IiII % iII111i + i1IIi % I1IiiI % OOooOOo . iII111i
  for Ii1i1Ii in range ( iI1iii1IIIIi . rloc_count ) :
   oooO0oo00oOOoo0O = lisp_rloc_record ( )
   O00OO0OO = oooO0oo00oOOoo0O . decode ( O00OO0OO , None )
   oooO0oo00oOOoo0O . print_record ( "    " )
   if ( iI1iii1IIIIi . group . is_null ( ) ) : continue
   if ( oooO0oo00oOOoo0O . rle == None ) : continue
   if 85 - 85: i11iIiiIii . o0oOOo0O0Ooo * iII111i . I1ii11iIi11i / I1Ii111 % Ii1I
   if 27 - 27: II111iiii . iIii1I11I1II1 / I1ii11iIi11i / i1IIi / iIii1I11I1II1
   if 70 - 70: i11iIiiIii . OoO0O00 / OoooooooOO * OoooooooOO - OOooOOo
   if 34 - 34: I1ii11iIi11i * i1IIi % OoooooooOO / I1IiiI
   if 39 - 39: OoO0O00 + IiII - II111iiii % I11i
   oO000O0oooOo = Iii1 . rloc_set [ 0 ] . stats if len ( Iii1 . rloc_set ) != 0 else None
   if 47 - 47: IiII + O0 / OoooooooOO + iIii1I11I1II1
   if 97 - 97: OoooooooOO * I11i . I1Ii111
   if 20 - 20: I1IiiI . I1ii11iIi11i
   if 55 - 55: OoOoOO00 + I11i - OOooOOo
   oOOoo0O00 = lisp_rloc ( )
   oOOoo0O00 . store_rloc_from_record ( oooO0oo00oOOoo0O , None , Iii1 . mapping_source )
   if ( oO000O0oooOo != None ) : oOOoo0O00 . stats = copy . deepcopy ( oO000O0oooOo )
   if 20 - 20: OoO0O00 . OoooooooOO - I1Ii111 * IiII
   if ( I11iI1iIi1i and oOOoo0O00 . is_rtr ( ) == False ) : continue
   if 20 - 20: o0oOOo0O0Ooo . OoooooooOO * I1IiiI . Oo0Ooo * OoOoOO00
   Iii1 . rloc_set = [ oOOoo0O00 ]
   Iii1 . build_best_rloc_set ( )
   lisp_write_ipc_map_cache ( True , Iii1 )
   if 3 - 3: I1Ii111 % i11iIiiIii % O0 % II111iiii
   lprint ( "Update {} map-cache entry with RLE {}" . format ( green ( Iii1 . print_eid_tuple ( ) , False ) , oOOoo0O00 . rle . print_rle ( False ) ) )
   if 8 - 8: OoooooooOO * ooOoO0o
   if 26 - 26: i11iIiiIii + oO0o - i1IIi
   if 71 - 71: I1IiiI % I1Ii111 / oO0o % oO0o / iIii1I11I1II1 + I1Ii111
 return
 if 86 - 86: IiII % i1IIi * o0oOOo0O0Ooo - I1Ii111
 if 37 - 37: iII111i % I1IiiI - I1ii11iIi11i % I11i
 if 35 - 35: O0 - OoooooooOO % iII111i
 if 48 - 48: OOooOOo % i11iIiiIii
 if 49 - 49: O0 * iII111i + II111iiii - OOooOOo
 if 29 - 29: OoooooooOO % II111iiii - Oo0Ooo / IiII - i11iIiiIii
 if 64 - 64: iII111i . I1Ii111 + I1Ii111
 if 1 - 1: OOooOOo % Oo0Ooo
def lisp_process_map_notify ( lisp_sockets , orig_packet , source ) :
 ooOo00 = lisp_map_notify ( "" )
 i1II1IiiIi = ooOo00 . decode ( orig_packet )
 if ( i1II1IiiIi == None ) :
  lprint ( "Could not decode Map-Notify packet" )
  return
  if 81 - 81: oO0o / I11i % Ii1I . I11i + OoooooooOO
  if 31 - 31: OoO0O00
 ooOo00 . print_notify ( )
 if 41 - 41: i11iIiiIii - I1ii11iIi11i - II111iiii
 if 5 - 5: OoOoOO00 + i1IIi
 if 43 - 43: iII111i * I1IiiI
 if 20 - 20: I1IiiI . I11i * OoO0O00 . ooOoO0o . II111iiii
 if 6 - 6: Ii1I * OoOoOO00 % IiII + I11i
 IiIIi1I1I11Ii = source . print_address ( )
 if ( ooOo00 . alg_id != 0 or ooOo00 . auth_len != 0 ) :
  I1iII1 = None
  for o0OoOo0o0OOoO0 in lisp_map_servers_list :
   if ( o0OoOo0o0OOoO0 . find ( IiIIi1I1I11Ii ) == - 1 ) : continue
   I1iII1 = lisp_map_servers_list [ o0OoOo0o0OOoO0 ]
   if 20 - 20: oO0o
  if ( I1iII1 == None ) :
   lprint ( ( "  Could not find Map-Server {} to authenticate " + "Map-Notify" ) . format ( IiIIi1I1I11Ii ) )
   if 34 - 34: i1IIi + oO0o * Oo0Ooo * I1Ii111 % OoooooooOO % ooOoO0o
   return
   if 17 - 17: I1ii11iIi11i + o0oOOo0O0Ooo / OoO0O00 . Oo0Ooo - o0oOOo0O0Ooo / oO0o
   if 87 - 87: ooOoO0o
  I1iII1 . map_notifies_received += 1
  if 74 - 74: i11iIiiIii . i11iIiiIii . iIii1I11I1II1
  i111II = lisp_verify_auth ( i1II1IiiIi , ooOo00 . alg_id ,
 ooOo00 . auth_data , I1iII1 . password )
  if 100 - 100: i11iIiiIii - oO0o + iIii1I11I1II1 * OoOoOO00 % OOooOOo % i11iIiiIii
  lprint ( "  Authentication {} for Map-Notify" . format ( "succeeded" if i111II else "failed" ) )
  if 26 - 26: O0
  if ( i111II == False ) : return
 else :
  I1iII1 = lisp_ms ( IiIIi1I1I11Ii , None , "" , 0 , "" , False , False , False , False , 0 , 0 , 0 ,
 None )
  if 97 - 97: OOooOOo + I11i % I1Ii111 % i11iIiiIii / I1ii11iIi11i
  if 21 - 21: O0 + iIii1I11I1II1 / i11iIiiIii . OOooOOo * i1IIi
  if 3 - 3: i1IIi % o0oOOo0O0Ooo + OoOoOO00
  if 32 - 32: OoO0O00 . Oo0Ooo * iIii1I11I1II1
  if 12 - 12: O0 + I1ii11iIi11i + I11i . I1Ii111
  if 48 - 48: Ii1I . iIii1I11I1II1 - iIii1I11I1II1 * I11i . OoooooooOO
 O00OO0OO = ooOo00 . eid_records
 if ( ooOo00 . record_count == 0 ) :
  lisp_send_map_notify_ack ( lisp_sockets , O00OO0OO , ooOo00 , I1iII1 )
  return
  if 73 - 73: Ii1I / II111iiii - iIii1I11I1II1 . ooOoO0o * II111iiii . OOooOOo
  if 50 - 50: iIii1I11I1II1 + OoOoOO00 % O0 + OoO0O00 . i11iIiiIii / oO0o
  if 31 - 31: I1IiiI % o0oOOo0O0Ooo . i11iIiiIii % OOooOOo - iIii1I11I1II1
  if 77 - 77: i11iIiiIii / OOooOOo
  if 93 - 93: I1ii11iIi11i - iII111i % O0 - Ii1I
  if 84 - 84: I1ii11iIi11i . iIii1I11I1II1 % IiII * I11i + ooOoO0o
  if 59 - 59: oO0o * OoO0O00 - I11i * I1IiiI
  if 60 - 60: iII111i - OoooooooOO / iII111i % OoO0O00 . OoOoOO00 - o0oOOo0O0Ooo
 iI1iii1IIIIi = lisp_eid_record ( )
 i1II1IiiIi = iI1iii1IIIIi . decode ( O00OO0OO )
 if ( i1II1IiiIi == None ) : return
 if 71 - 71: iII111i * o0oOOo0O0Ooo * i11iIiiIii * O0
 iI1iii1IIIIi . print_record ( "  " , False )
 if 77 - 77: OOooOOo % iII111i + I11i / OoOoOO00
 for Ii1i1Ii in range ( iI1iii1IIIIi . rloc_count ) :
  oooO0oo00oOOoo0O = lisp_rloc_record ( )
  i1II1IiiIi = oooO0oo00oOOoo0O . decode ( i1II1IiiIi , None )
  if ( i1II1IiiIi == None ) :
   lprint ( "  Could not decode RLOC-record in Map-Notify packet" )
   return
   if 50 - 50: OoOoOO00 - i11iIiiIii - OOooOOo . iIii1I11I1II1
  oooO0oo00oOOoo0O . print_record ( "    " )
  if 97 - 97: oO0o % OOooOOo . OoooooooOO * Ii1I
  if 100 - 100: I1ii11iIi11i / Ii1I % Oo0Ooo
  if 83 - 83: O0 . I1Ii111 % I1ii11iIi11i
  if 97 - 97: Oo0Ooo % OoO0O00 * I1ii11iIi11i * ooOoO0o * OoO0O00
  if 12 - 12: ooOoO0o
 if ( iI1iii1IIIIi . group . is_null ( ) == False ) :
  if 56 - 56: i1IIi
  if 3 - 3: OOooOOo - Oo0Ooo * Ii1I + i11iIiiIii
  if 53 - 53: i1IIi % I1ii11iIi11i
  if 65 - 65: I11i + OoOoOO00 - i11iIiiIii
  if 72 - 72: i11iIiiIii - iII111i . i11iIiiIii
  lprint ( "Send {} Map-Notify IPC message to ITR process" . format ( green ( iI1iii1IIIIi . print_eid_tuple ( ) , False ) ) )
  if 61 - 61: oO0o . i11iIiiIii / Ii1I % iII111i
  if 36 - 36: OoO0O00 + Ii1I / I11i - iII111i % OoO0O00 / Oo0Ooo
  IIi1IIII = lisp_control_packet_ipc ( orig_packet , IiIIi1I1I11Ii , "lisp-itr" , 0 )
  lisp_ipc ( IIi1IIII , lisp_sockets [ 2 ] , "lisp-core-pkt" )
  if 38 - 38: Ii1I - ooOoO0o - O0 + oO0o . iIii1I11I1II1
  if 90 - 90: i1IIi * OoOoOO00
  if 27 - 27: iIii1I11I1II1
  if 95 - 95: iII111i / ooOoO0o % Ii1I
  if 44 - 44: OOooOOo . OOooOOo
 lisp_send_map_notify_ack ( lisp_sockets , O00OO0OO , ooOo00 , I1iII1 )
 return
 if 5 - 5: oO0o + OoooooooOO
 if 88 - 88: oO0o + OOooOOo
 if 14 - 14: I11i / i1IIi
 if 56 - 56: OoooooooOO
 if 59 - 59: I1ii11iIi11i + OoO0O00
 if 37 - 37: IiII * I1IiiI % O0
 if 32 - 32: ooOoO0o % II111iiii
 if 60 - 60: i11iIiiIii
def lisp_process_map_notify_ack ( packet , source ) :
 ooOo00 = lisp_map_notify ( "" )
 packet = ooOo00 . decode ( packet )
 if ( packet == None ) :
  lprint ( "Could not decode Map-Notify-Ack packet" )
  return
  if 11 - 11: o0oOOo0O0Ooo
  if 77 - 77: o0oOOo0O0Ooo / iIii1I11I1II1 * iIii1I11I1II1 / o0oOOo0O0Ooo * iII111i
 ooOo00 . print_notify ( )
 if 26 - 26: Ii1I
 if 1 - 1: OoOoOO00 . o0oOOo0O0Ooo + Oo0Ooo % Oo0Ooo * I1ii11iIi11i
 if 50 - 50: IiII / i1IIi . I1ii11iIi11i
 if 75 - 75: I11i * oO0o + OoooooooOO . iII111i + OoO0O00
 if 44 - 44: II111iiii
 if ( ooOo00 . record_count < 1 ) :
  lprint ( "No EID-prefix found, cannot authenticate Map-Notify-Ack" )
  return
  if 65 - 65: I11i . iII111i . I1IiiI - Oo0Ooo % iIii1I11I1II1 / O0
  if 54 - 54: iII111i - I1Ii111
 iI1iii1IIIIi = lisp_eid_record ( )
 if 88 - 88: iII111i * OoO0O00 % OoooooooOO / oO0o
 if ( iI1iii1IIIIi . decode ( ooOo00 . eid_records ) == None ) :
  lprint ( "Could not decode EID-record, cannot authenticate " +
 "Map-Notify-Ack" )
  return
  if 7 - 7: i1IIi
 iI1iii1IIIIi . print_record ( "  " , False )
 if 30 - 30: oO0o . i1IIi / I11i
 oOoo0OooOOo00 = iI1iii1IIIIi . print_eid_tuple ( )
 if 23 - 23: i1IIi + oO0o % iII111i - OoO0O00 - i1IIi
 if 74 - 74: Ii1I + I11i . OoooooooOO - I1ii11iIi11i
 if 2 - 2: oO0o - o0oOOo0O0Ooo
 if 80 - 80: i1IIi
 if ( ooOo00 . alg_id != LISP_NONE_ALG_ID and ooOo00 . auth_len != 0 ) :
  ooOOOo0o0oo = lisp_sites_by_eid . lookup_cache ( iI1iii1IIIIi . eid , True )
  if ( ooOOOo0o0oo == None ) :
   OOOO0OOoO = bold ( "Site not found" , False )
   lprint ( ( "{} for EID {}, cannot authenticate Map-Notify-Ack" ) . format ( OOOO0OOoO , green ( oOoo0OooOOo00 , False ) ) )
   if 40 - 40: O0 . ooOoO0o * iII111i . I11i + I1Ii111 % OoO0O00
   return
   if 9 - 9: IiII * oO0o - o0oOOo0O0Ooo
  I1ii1I = ooOOOo0o0oo . site
  if 17 - 17: iII111i % Oo0Ooo
  if 14 - 14: I1IiiI - I1Ii111 % I1IiiI - II111iiii
  if 34 - 34: I1ii11iIi11i * IiII / II111iiii / ooOoO0o * oO0o
  if 3 - 3: II111iiii
  I1ii1I . map_notify_acks_received += 1
  if 61 - 61: oO0o . I1IiiI + i1IIi
  o0OOOoO0O = ooOo00 . key_id
  if ( I1ii1I . auth_key . has_key ( o0OOOoO0O ) == False ) : o0OOOoO0O = 0
  O0O0 = I1ii1I . auth_key [ o0OOOoO0O ]
  if 69 - 69: O0 / i1IIi - OoOoOO00 + ooOoO0o - oO0o
  i111II = lisp_verify_auth ( packet , ooOo00 . alg_id ,
 ooOo00 . auth_data , O0O0 )
  if 80 - 80: o0oOOo0O0Ooo % O0 * I11i . i1IIi - ooOoO0o
  o0OOOoO0O = "key-id {}" . format ( o0OOOoO0O ) if o0OOOoO0O == ooOo00 . key_id else "bad key-id {}" . format ( ooOo00 . key_id )
  if 93 - 93: OoooooooOO / o0oOOo0O0Ooo
  if 61 - 61: II111iiii / i1IIi . I1ii11iIi11i % iIii1I11I1II1
  lprint ( "  Authentication {} for Map-Notify-Ack, {}" . format ( "succeeded" if i111II else "failed" , o0OOOoO0O ) )
  if 66 - 66: iIii1I11I1II1 % OoOoOO00 + i1IIi * i11iIiiIii * OoooooooOO
  if ( i111II == False ) : return
  if 36 - 36: iII111i - OoO0O00 + I1IiiI + Ii1I . OoooooooOO
  if 75 - 75: oO0o * Oo0Ooo * O0
  if 22 - 22: ooOoO0o / OoooooooOO . II111iiii / Ii1I * OoO0O00 . i1IIi
  if 62 - 62: oO0o % Ii1I - Ii1I
  if 16 - 16: OoO0O00 - O0 - OOooOOo - I11i % OoOoOO00
 if ( ooOo00 . retransmit_timer ) : ooOo00 . retransmit_timer . cancel ( )
 if 7 - 7: I1Ii111 / OoOoOO00 . II111iiii
 I11i1i1i1iii = source . print_address ( )
 o0OoOo0o0OOoO0 = ooOo00 . nonce_key
 if 9 - 9: I11i . I11i . OoooooooOO
 if ( lisp_map_notify_queue . has_key ( o0OoOo0o0OOoO0 ) ) :
  ooOo00 = lisp_map_notify_queue . pop ( o0OoOo0o0OOoO0 )
  if ( ooOo00 . retransmit_timer ) : ooOo00 . retransmit_timer . cancel ( )
  lprint ( "Dequeue Map-Notify from retransmit queue, key is: {}" . format ( o0OoOo0o0OOoO0 ) )
  if 42 - 42: iII111i / oO0o / iII111i * OoO0O00
 else :
  lprint ( "Map-Notify with nonce 0x{} queue entry not found for {}" . format ( ooOo00 . nonce_key , red ( I11i1i1i1iii , False ) ) )
  if 25 - 25: OoOoOO00 - II111iiii + II111iiii . Ii1I * II111iiii
  if 12 - 12: IiII / Ii1I
 return
 if 54 - 54: Oo0Ooo + Ii1I % OoooooooOO * OOooOOo / OoOoOO00
 if 39 - 39: I1IiiI % i11iIiiIii % Ii1I
 if 59 - 59: ooOoO0o % OoO0O00 / I1IiiI - II111iiii + OoooooooOO * i11iIiiIii
 if 58 - 58: IiII / Oo0Ooo + o0oOOo0O0Ooo
 if 71 - 71: Ii1I - IiII
 if 2 - 2: OoOoOO00 % IiII % OoO0O00 . i1IIi / I1Ii111 - iIii1I11I1II1
 if 88 - 88: Oo0Ooo * i1IIi % OOooOOo
 if 65 - 65: iII111i . oO0o
def lisp_map_referral_loop ( mr , eid , group , action , s ) :
 if ( action not in ( LISP_DDT_ACTION_NODE_REFERRAL ,
 LISP_DDT_ACTION_MS_REFERRAL ) ) : return ( False )
 if 67 - 67: I1IiiI / iII111i / O0 % ooOoO0o - IiII / Ii1I
 if ( mr . last_cached_prefix [ 0 ] == None ) : return ( False )
 if 31 - 31: I11i - oO0o * ooOoO0o
 if 64 - 64: I11i
 if 41 - 41: I1Ii111 * OoooooooOO / OoOoOO00 + OoO0O00 . OoOoOO00 + I1Ii111
 if 9 - 9: IiII . I11i . I1Ii111 / i1IIi * OoOoOO00 - O0
 iIII11iiIiIiI = False
 if ( group . is_null ( ) == False ) :
  iIII11iiIiIiI = mr . last_cached_prefix [ 1 ] . is_more_specific ( group )
  if 3 - 3: O0 / iIii1I11I1II1 % IiII + I11i
 if ( iIII11iiIiIiI == False ) :
  iIII11iiIiIiI = mr . last_cached_prefix [ 0 ] . is_more_specific ( eid )
  if 43 - 43: Oo0Ooo % I11i
  if 53 - 53: OoOoOO00 % OoooooooOO * o0oOOo0O0Ooo % OoooooooOO
 if ( iIII11iiIiIiI ) :
  I11 = lisp_print_eid_tuple ( eid , group )
  IiII1II1I = lisp_print_eid_tuple ( mr . last_cached_prefix [ 0 ] ,
 mr . last_cached_prefix [ 1 ] )
  if 40 - 40: o0oOOo0O0Ooo - OoOoOO00 - iIii1I11I1II1
  lprint ( ( "Map-Referral prefix {} from {} is not more-specific " + "than cached prefix {}" ) . format ( green ( I11 , False ) , s ,
  # OoooooooOO + ooOoO0o * I1ii11iIi11i
 IiII1II1I ) )
  if 6 - 6: OoooooooOO % i1IIi % II111iiii + ooOoO0o / IiII + Ii1I
 return ( iIII11iiIiIiI )
 if 97 - 97: ooOoO0o / I1Ii111 * I1ii11iIi11i
 if 83 - 83: Ii1I + ooOoO0o
 if 46 - 46: OoOoOO00
 if 66 - 66: iII111i - O0 . I1Ii111 * i1IIi / OoO0O00 / II111iiii
 if 35 - 35: ooOoO0o * OOooOOo / I11i % I11i / OoooooooOO . I1Ii111
 if 70 - 70: I1ii11iIi11i % I1ii11iIi11i / oO0o
 if 85 - 85: OoOoOO00 % I11i / Oo0Ooo + I11i - Oo0Ooo
def lisp_process_map_referral ( lisp_sockets , packet , source ) :
 if 20 - 20: IiII
 OOoO000o00000 = lisp_map_referral ( )
 packet = OOoO000o00000 . decode ( packet )
 if ( packet == None ) :
  lprint ( "Could not decode Map-Referral packet" )
  return
  if 81 - 81: Oo0Ooo / I1Ii111
 OOoO000o00000 . print_map_referral ( )
 if 20 - 20: o0oOOo0O0Ooo + ooOoO0o % i1IIi
 IiIIi1I1I11Ii = source . print_address ( )
 iI1III = OOoO000o00000 . nonce
 if 51 - 51: iII111i - ooOoO0o
 if 32 - 32: IiII - i11iIiiIii
 if 41 - 41: Ii1I % Ii1I * oO0o - I11i + iIii1I11I1II1 . ooOoO0o
 if 30 - 30: Ii1I * iII111i . II111iiii / i1IIi
 for Ii11 in range ( OOoO000o00000 . record_count ) :
  iI1iii1IIIIi = lisp_eid_record ( )
  packet = iI1iii1IIIIi . decode ( packet )
  if ( packet == None ) :
   lprint ( "Could not decode EID-record in Map-Referral packet" )
   return
   if 77 - 77: oO0o . IiII + I1ii11iIi11i . i1IIi
  iI1iii1IIIIi . print_record ( "  " , True )
  if 49 - 49: I1Ii111 . OoooooooOO / o0oOOo0O0Ooo - iII111i - iII111i - i11iIiiIii
  if 37 - 37: OOooOOo
  if 79 - 79: I1Ii111 - OoO0O00 + ooOoO0o + oO0o . i11iIiiIii + i1IIi
  if 32 - 32: IiII . ooOoO0o / OoO0O00 / iII111i . iIii1I11I1II1 % IiII
  o0OoOo0o0OOoO0 = str ( iI1III )
  if ( o0OoOo0o0OOoO0 not in lisp_ddt_map_requestQ ) :
   lprint ( ( "Map-Referral nonce 0x{} from {} not found in " + "Map-Request queue, EID-record ignored" ) . format ( lisp_hex_string ( iI1III ) , IiIIi1I1I11Ii ) )
   if 28 - 28: I1Ii111 + OoooooooOO + IiII . ooOoO0o . I1IiiI / oO0o
   if 66 - 66: Ii1I - I11i + Oo0Ooo . ooOoO0o
   continue
   if 89 - 89: IiII . II111iiii / OoO0O00 + I1ii11iIi11i * i11iIiiIii
  IIiIII1IIi = lisp_ddt_map_requestQ [ o0OoOo0o0OOoO0 ]
  if ( IIiIII1IIi == None ) :
   lprint ( ( "No Map-Request queue entry found for Map-Referral " +
 "nonce 0x{} from {}, EID-record ignored" ) . format ( lisp_hex_string ( iI1III ) , IiIIi1I1I11Ii ) )
   if 85 - 85: o0oOOo0O0Ooo - Oo0Ooo / I1Ii111
   continue
   if 100 - 100: OoO0O00 * iIii1I11I1II1 - IiII . i1IIi % i11iIiiIii % Oo0Ooo
   if 22 - 22: ooOoO0o - OOooOOo
   if 90 - 90: i11iIiiIii . i11iIiiIii - iIii1I11I1II1
   if 20 - 20: ooOoO0o - i11iIiiIii
   if 23 - 23: OoO0O00 + I1IiiI / I1ii11iIi11i * I1ii11iIi11i % ooOoO0o
   if 83 - 83: I1IiiI * i11iIiiIii - I1ii11iIi11i + I11i
  if ( lisp_map_referral_loop ( IIiIII1IIi , iI1iii1IIIIi . eid , iI1iii1IIIIi . group ,
 iI1iii1IIIIi . action , IiIIi1I1I11Ii ) ) :
   IIiIII1IIi . dequeue_map_request ( )
   continue
   if 33 - 33: OoO0O00 . OoooooooOO % iII111i / oO0o * Ii1I + ooOoO0o
   if 29 - 29: oO0o
  IIiIII1IIi . last_cached_prefix [ 0 ] = iI1iii1IIIIi . eid
  IIiIII1IIi . last_cached_prefix [ 1 ] = iI1iii1IIIIi . group
  if 21 - 21: i11iIiiIii . o0oOOo0O0Ooo
  if 78 - 78: Oo0Ooo
  if 77 - 77: oO0o % Oo0Ooo % O0
  if 51 - 51: IiII % IiII + OOooOOo . II111iiii / I1ii11iIi11i
  IiI1i = False
  i1ii1iIiI1 = lisp_referral_cache_lookup ( iI1iii1IIIIi . eid , iI1iii1IIIIi . group ,
 True )
  if ( i1ii1iIiI1 == None ) :
   IiI1i = True
   i1ii1iIiI1 = lisp_referral ( )
   i1ii1iIiI1 . eid = iI1iii1IIIIi . eid
   i1ii1iIiI1 . group = iI1iii1IIIIi . group
   if ( iI1iii1IIIIi . ddt_incomplete == False ) : i1ii1iIiI1 . add_cache ( )
  elif ( i1ii1iIiI1 . referral_source . not_set ( ) ) :
   lprint ( "Do not replace static referral entry {}" . format ( green ( i1ii1iIiI1 . print_eid_tuple ( ) , False ) ) )
   if 4 - 4: o0oOOo0O0Ooo % I1IiiI * o0oOOo0O0Ooo * OoOoOO00 - Ii1I
   IIiIII1IIi . dequeue_map_request ( )
   continue
   if 61 - 61: OoooooooOO - OoOoOO00 . O0 / ooOoO0o . Ii1I
   if 41 - 41: Oo0Ooo / OoOoOO00 % I1Ii111 - O0
  oo0oOOo0 = iI1iii1IIIIi . action
  i1ii1iIiI1 . referral_source = source
  i1ii1iIiI1 . referral_type = oo0oOOo0
  oooOooOO = iI1iii1IIIIi . store_ttl ( )
  i1ii1iIiI1 . referral_ttl = oooOooOO
  i1ii1iIiI1 . expires = lisp_set_timestamp ( oooOooOO )
  if 19 - 19: I1IiiI % I1Ii111 - O0 . iIii1I11I1II1 . I11i % O0
  if 88 - 88: ooOoO0o
  if 52 - 52: iIii1I11I1II1 % ooOoO0o * iIii1I11I1II1
  if 20 - 20: i11iIiiIii * I11i
  i11Ii = i1ii1iIiI1 . is_referral_negative ( )
  if ( i1ii1iIiI1 . referral_set . has_key ( IiIIi1I1I11Ii ) ) :
   oo00OO = i1ii1iIiI1 . referral_set [ IiIIi1I1I11Ii ]
   if 37 - 37: II111iiii
   if ( oo00OO . updown == False and i11Ii == False ) :
    oo00OO . updown = True
    lprint ( "Change up/down status for referral-node {} to up" . format ( IiIIi1I1I11Ii ) )
    if 94 - 94: OOooOOo % I1ii11iIi11i % O0 + iII111i
   elif ( oo00OO . updown == True and i11Ii == True ) :
    oo00OO . updown = False
    lprint ( ( "Change up/down status for referral-node {} " + "to down, received negative referral" ) . format ( IiIIi1I1I11Ii ) )
    if 62 - 62: iIii1I11I1II1 . OoOoOO00 / iIii1I11I1II1 + IiII
    if 31 - 31: Ii1I . OoO0O00 . Ii1I + OoO0O00 * iIii1I11I1II1 . iII111i
    if 42 - 42: O0 / oO0o % O0 . i1IIi % OOooOOo
    if 13 - 13: I1IiiI % ooOoO0o + OOooOOo
    if 91 - 91: oO0o - ooOoO0o
    if 20 - 20: i1IIi . IiII / o0oOOo0O0Ooo / I11i
    if 27 - 27: ooOoO0o . ooOoO0o - Ii1I % i11iIiiIii
    if 74 - 74: I1Ii111 - II111iiii % o0oOOo0O0Ooo
  IiIiiI = { }
  for o0OoOo0o0OOoO0 in i1ii1iIiI1 . referral_set : IiIiiI [ o0OoOo0o0OOoO0 ] = None
  if 19 - 19: ooOoO0o * iII111i
  if 38 - 38: ooOoO0o
  if 35 - 35: o0oOOo0O0Ooo * IiII * Oo0Ooo
  if 34 - 34: I11i - OoooooooOO % i1IIi + I1IiiI
  for Ii11 in range ( iI1iii1IIIIi . rloc_count ) :
   oooO0oo00oOOoo0O = lisp_rloc_record ( )
   packet = oooO0oo00oOOoo0O . decode ( packet , None )
   if ( packet == None ) :
    lprint ( "Could not decode RLOC-record in Map-Referral packet" )
    return
    if 14 - 14: I1IiiI . o0oOOo0O0Ooo / I1Ii111
   oooO0oo00oOOoo0O . print_record ( "    " )
   if 67 - 67: OoooooooOO . oO0o * OoOoOO00 - OoooooooOO
   if 32 - 32: oO0o
   if 72 - 72: I1IiiI
   if 34 - 34: ooOoO0o % II111iiii / ooOoO0o
   I1iiIiiii1111 = oooO0oo00oOOoo0O . rloc . print_address ( )
   if ( i1ii1iIiI1 . referral_set . has_key ( I1iiIiiii1111 ) == False ) :
    oo00OO = lisp_referral_node ( )
    oo00OO . referral_address . copy_address ( oooO0oo00oOOoo0O . rloc )
    i1ii1iIiI1 . referral_set [ I1iiIiiii1111 ] = oo00OO
    if ( IiIIi1I1I11Ii == I1iiIiiii1111 and i11Ii ) : oo00OO . updown = False
   else :
    oo00OO = i1ii1iIiI1 . referral_set [ I1iiIiiii1111 ]
    if ( IiIiiI . has_key ( I1iiIiiii1111 ) ) : IiIiiI . pop ( I1iiIiiii1111 )
    if 87 - 87: Oo0Ooo
   oo00OO . priority = oooO0oo00oOOoo0O . priority
   oo00OO . weight = oooO0oo00oOOoo0O . weight
   if 7 - 7: iIii1I11I1II1
   if 85 - 85: iIii1I11I1II1 . O0
   if 43 - 43: II111iiii / OoOoOO00 + OOooOOo % Oo0Ooo * OOooOOo
   if 62 - 62: ooOoO0o * OOooOOo . I11i + Oo0Ooo - I1Ii111
   if 48 - 48: I1Ii111 * Oo0Ooo % OoO0O00 % Ii1I
  for o0OoOo0o0OOoO0 in IiIiiI : i1ii1iIiI1 . referral_set . pop ( o0OoOo0o0OOoO0 )
  if 8 - 8: OoO0O00 . OoO0O00
  oOoo0OooOOo00 = i1ii1iIiI1 . print_eid_tuple ( )
  if 29 - 29: I11i + OoooooooOO % o0oOOo0O0Ooo - I1Ii111
  if ( IiI1i ) :
   if ( iI1iii1IIIIi . ddt_incomplete ) :
    lprint ( "Suppress add {} to referral-cache" . format ( green ( oOoo0OooOOo00 , False ) ) )
    if 45 - 45: II111iiii - OOooOOo / oO0o % O0 . iII111i . iII111i
   else :
    lprint ( "Add {}, referral-count {} to referral-cache" . format ( green ( oOoo0OooOOo00 , False ) , iI1iii1IIIIi . rloc_count ) )
    if 82 - 82: iIii1I11I1II1 % Oo0Ooo * i1IIi - I1Ii111 - I1ii11iIi11i / iII111i
    if 24 - 24: IiII
  else :
   lprint ( "Replace {}, referral-count: {} in referral-cache" . format ( green ( oOoo0OooOOo00 , False ) , iI1iii1IIIIi . rloc_count ) )
   if 95 - 95: IiII + OoOoOO00 * OOooOOo
   if 92 - 92: OoOoOO00 + ooOoO0o . iII111i
   if 59 - 59: iIii1I11I1II1 % I1Ii111 + I1ii11iIi11i . OoOoOO00 * Oo0Ooo / I1Ii111
   if 41 - 41: i1IIi / IiII
   if 73 - 73: o0oOOo0O0Ooo % ooOoO0o
   if 72 - 72: OoO0O00 * OoOoOO00 % I1IiiI - OOooOOo . Oo0Ooo
  if ( oo0oOOo0 == LISP_DDT_ACTION_DELEGATION_HOLE ) :
   lisp_send_negative_map_reply ( IIiIII1IIi . lisp_sockets , i1ii1iIiI1 . eid ,
 i1ii1iIiI1 . group , IIiIII1IIi . nonce , IIiIII1IIi . itr , IIiIII1IIi . sport , 15 , None , False )
   IIiIII1IIi . dequeue_map_request ( )
   if 70 - 70: ooOoO0o . o0oOOo0O0Ooo * II111iiii - O0
   if 74 - 74: oO0o % I1IiiI / oO0o / Oo0Ooo / ooOoO0o
  if ( oo0oOOo0 == LISP_DDT_ACTION_NOT_AUTH ) :
   if ( IIiIII1IIi . tried_root ) :
    lisp_send_negative_map_reply ( IIiIII1IIi . lisp_sockets , i1ii1iIiI1 . eid ,
 i1ii1iIiI1 . group , IIiIII1IIi . nonce , IIiIII1IIi . itr , IIiIII1IIi . sport , 0 , None , False )
    IIiIII1IIi . dequeue_map_request ( )
   else :
    lisp_send_ddt_map_request ( IIiIII1IIi , True )
    if 29 - 29: ooOoO0o + iIii1I11I1II1 + OoO0O00 - o0oOOo0O0Ooo
    if 74 - 74: II111iiii - II111iiii + ooOoO0o + Oo0Ooo % iIii1I11I1II1
    if 90 - 90: oO0o / o0oOOo0O0Ooo . o0oOOo0O0Ooo % OoOoOO00 / IiII
  if ( oo0oOOo0 == LISP_DDT_ACTION_MS_NOT_REG ) :
   if ( i1ii1iIiI1 . referral_set . has_key ( IiIIi1I1I11Ii ) ) :
    oo00OO = i1ii1iIiI1 . referral_set [ IiIIi1I1I11Ii ]
    oo00OO . updown = False
    if 13 - 13: oO0o + IiII
   if ( len ( i1ii1iIiI1 . referral_set ) == 0 ) :
    IIiIII1IIi . dequeue_map_request ( )
   else :
    lisp_send_ddt_map_request ( IIiIII1IIi , False )
    if 36 - 36: oO0o - OoOoOO00 . O0 % IiII
    if 65 - 65: Oo0Ooo - i11iIiiIii * OoOoOO00 . I1Ii111 . iIii1I11I1II1
    if 48 - 48: iIii1I11I1II1 - oO0o / OoO0O00 + O0 . Ii1I + I1Ii111
  if ( oo0oOOo0 in ( LISP_DDT_ACTION_NODE_REFERRAL ,
 LISP_DDT_ACTION_MS_REFERRAL ) ) :
   if ( IIiIII1IIi . eid . is_exact_match ( iI1iii1IIIIi . eid ) ) :
    if ( not IIiIII1IIi . tried_root ) :
     lisp_send_ddt_map_request ( IIiIII1IIi , True )
    else :
     lisp_send_negative_map_reply ( IIiIII1IIi . lisp_sockets ,
 i1ii1iIiI1 . eid , i1ii1iIiI1 . group , IIiIII1IIi . nonce , IIiIII1IIi . itr ,
 IIiIII1IIi . sport , 15 , None , False )
     IIiIII1IIi . dequeue_map_request ( )
     if 17 - 17: OoOoOO00 . Oo0Ooo - I1Ii111 / I1Ii111 + I11i % i1IIi
   else :
    lisp_send_ddt_map_request ( IIiIII1IIi , False )
    if 31 - 31: OoooooooOO . O0 / OoO0O00 . I1Ii111
    if 41 - 41: OoooooooOO + iII111i . OOooOOo
    if 73 - 73: oO0o + i1IIi + i11iIiiIii / I1ii11iIi11i
  if ( oo0oOOo0 == LISP_DDT_ACTION_MS_ACK ) : IIiIII1IIi . dequeue_map_request ( )
  if 100 - 100: I1IiiI % ooOoO0o % OoooooooOO / i11iIiiIii + i11iIiiIii % IiII
 return
 if 39 - 39: Ii1I % o0oOOo0O0Ooo + OOooOOo / iIii1I11I1II1
 if 40 - 40: iIii1I11I1II1 / iII111i % OOooOOo % i11iIiiIii
 if 57 - 57: II111iiii % OoO0O00 * i1IIi
 if 19 - 19: ooOoO0o . iIii1I11I1II1 + I1ii11iIi11i + I1ii11iIi11i / o0oOOo0O0Ooo . Oo0Ooo
 if 9 - 9: II111iiii % OoooooooOO
 if 4 - 4: i1IIi * i11iIiiIii % OoooooooOO + OoOoOO00 . oO0o
 if 95 - 95: I1ii11iIi11i * OoOoOO00 % o0oOOo0O0Ooo / O0 + ooOoO0o % OOooOOo
 if 48 - 48: i1IIi + IiII - iIii1I11I1II1 . i11iIiiIii % OOooOOo + I1ii11iIi11i
def lisp_process_ecm ( lisp_sockets , packet , source , ecm_port ) :
 IIi11 = lisp_ecm ( 0 )
 packet = IIi11 . decode ( packet )
 if ( packet == None ) :
  lprint ( "Could not decode ECM packet" )
  return
  if 95 - 95: ooOoO0o + OoOoOO00 . II111iiii + Ii1I
  if 81 - 81: OoooooooOO / OOooOOo / Oo0Ooo
 IIi11 . print_ecm ( )
 if 26 - 26: iII111i
 I1I = lisp_control_header ( )
 if ( I1I . decode ( packet ) == None ) :
  lprint ( "Could not decode control header" )
  return
  if 93 - 93: Oo0Ooo + I1IiiI % OoOoOO00 / OOooOOo / I1ii11iIi11i
  if 6 - 6: IiII
 o00o0o = I1I . type
 del ( I1I )
 if 15 - 15: Ii1I + Oo0Ooo - I1ii11iIi11i / i11iIiiIii
 if ( o00o0o != LISP_MAP_REQUEST ) :
  lprint ( "Received ECM without Map-Request inside" )
  return
  if 80 - 80: i11iIiiIii + oO0o
  if 42 - 42: i11iIiiIii . Ii1I / i1IIi % OoooooooOO + Oo0Ooo % II111iiii
  if 33 - 33: II111iiii + IiII % O0 * I1Ii111 - Oo0Ooo / i1IIi
  if 87 - 87: O0 + iII111i . iIii1I11I1II1 - I11i + OOooOOo
  if 18 - 18: I1ii11iIi11i . Ii1I * iII111i . I1IiiI . O0 - OoO0O00
 ooO0o00000O0o = IIi11 . udp_sport
 lisp_process_map_request ( lisp_sockets , packet , source , ecm_port ,
 IIi11 . source , ooO0o00000O0o , IIi11 . ddt , - 1 )
 return
 if 44 - 44: i1IIi - i11iIiiIii - i1IIi
 if 82 - 82: Oo0Ooo - oO0o
 if 36 - 36: Oo0Ooo / Oo0Ooo - o0oOOo0O0Ooo - i11iIiiIii
 if 59 - 59: i11iIiiIii / iIii1I11I1II1 / ooOoO0o
 if 2 - 2: iII111i + II111iiii
 if 88 - 88: i1IIi - iII111i / OOooOOo / i1IIi
 if 48 - 48: iII111i / OoooooooOO / iIii1I11I1II1
 if 41 - 41: II111iiii - II111iiii - OoO0O00 + oO0o * I11i
 if 77 - 77: IiII % iIii1I11I1II1 - OOooOOo / I1Ii111 / ooOoO0o . iII111i
 if 62 - 62: I1Ii111
def lisp_send_map_register ( lisp_sockets , packet , map_register , ms ) :
 if 42 - 42: o0oOOo0O0Ooo
 if 59 - 59: I1ii11iIi11i % O0 - i1IIi . Oo0Ooo
 if 18 - 18: II111iiii
 if 31 - 31: Oo0Ooo / Oo0Ooo / iIii1I11I1II1 / I11i % OoooooooOO
 if 90 - 90: I1IiiI
 if 35 - 35: O0
 if 10 - 10: Ii1I - I1Ii111 / Oo0Ooo + O0
 oooooO0oO0o = ms . map_server
 if ( lisp_decent_push_configured and oooooO0oO0o . is_multicast_address ( ) and
 ( ms . map_registers_multicast_sent == 1 or ms . map_registers_sent == 1 ) ) :
  oooooO0oO0o = copy . deepcopy ( oooooO0oO0o )
  oooooO0oO0o . address = 0x7f000001
  iIIi1I1ii = bold ( "Bootstrap" , False )
  O0oOo00Oo0oo0 = ms . map_server . print_address_no_iid ( )
  lprint ( "{} mapping system for peer-group {}" . format ( iIIi1I1ii , O0oOo00Oo0oo0 ) )
  if 67 - 67: Ii1I % i11iIiiIii . Oo0Ooo
  if 78 - 78: I1IiiI - iIii1I11I1II1
  if 20 - 20: i11iIiiIii % I1IiiI % OoOoOO00
  if 85 - 85: I11i + OoOoOO00 * O0 * O0
  if 92 - 92: i11iIiiIii
  if 16 - 16: I11i . ooOoO0o - Oo0Ooo / OoO0O00 . i1IIi
 packet = lisp_compute_auth ( packet , map_register , ms . password )
 if 59 - 59: ooOoO0o - ooOoO0o % I11i + OoO0O00
 if 88 - 88: Ii1I - ooOoO0o . Oo0Ooo
 if 83 - 83: I11i + Oo0Ooo . I1ii11iIi11i * I1ii11iIi11i
 if 80 - 80: i1IIi * I11i - OOooOOo / II111iiii * iIii1I11I1II1
 if 42 - 42: OoOoOO00 . I11i % II111iiii
 if ( ms . ekey != None ) :
  IIiiIiI = ms . ekey . zfill ( 32 )
  O0o = "0" * 8
  Oo0 = chacha . ChaCha ( IIiiIiI , O0o ) . encrypt ( packet [ 4 : : ] )
  packet = packet [ 0 : 4 ] + Oo0
  ooo0OO = bold ( "Encrypt" , False )
  lprint ( "{} Map-Register with key-id {}" . format ( ooo0OO , ms . ekey_id ) )
  if 19 - 19: OoooooooOO
  if 31 - 31: I11i . OoOoOO00 - O0 * iII111i % I1Ii111 - II111iiii
 iIIii1iIii1 = ""
 if ( lisp_decent_pull_xtr_configured ( ) ) :
  iIIii1iIii1 = ", decent-index {}" . format ( bold ( ms . dns_name , False ) )
  if 33 - 33: OoO0O00 / OOooOOo / i1IIi / ooOoO0o % ooOoO0o - ooOoO0o
  if 90 - 90: OoooooooOO * OoO0O00 + O0
 lprint ( "Send Map-Register to map-server {}{}{}" . format ( oooooO0oO0o . print_address ( ) , ", ms-name '{}'" . format ( ms . ms_name ) , iIIii1iIii1 ) )
 if 36 - 36: i1IIi * oO0o
 lisp_send ( lisp_sockets , oooooO0oO0o , LISP_CTRL_PORT , packet )
 return
 if 51 - 51: iIii1I11I1II1 / o0oOOo0O0Ooo % OOooOOo * Oo0Ooo . I1ii11iIi11i - oO0o
 if 91 - 91: OOooOOo % OoooooooOO
 if 52 - 52: OOooOOo + OoO0O00
 if 96 - 96: OOooOOo % O0 - Oo0Ooo % oO0o / I1IiiI . i1IIi
 if 42 - 42: i1IIi
 if 52 - 52: OoO0O00 % iII111i % O0
 if 11 - 11: i1IIi / i11iIiiIii + Ii1I % Oo0Ooo % O0
 if 50 - 50: oO0o . I1Ii111
def lisp_send_ipc_to_core ( lisp_socket , packet , dest , port ) :
 O0Oo00o0o = lisp_socket . getsockname ( )
 dest = dest . print_address_no_iid ( )
 if 38 - 38: iIii1I11I1II1 . Ii1I
 lprint ( "Send IPC {} bytes to {} {}, control-packet: {}" . format ( len ( packet ) , dest , port , lisp_format_packet ( packet ) ) )
 if 82 - 82: OOooOOo * Ii1I + I1ii11iIi11i . OoO0O00
 if 15 - 15: O0
 packet = lisp_control_packet_ipc ( packet , O0Oo00o0o , dest , port )
 lisp_ipc ( packet , lisp_socket , "lisp-core-pkt" )
 return
 if 44 - 44: Ii1I . Oo0Ooo . I1Ii111 + oO0o
 if 32 - 32: OOooOOo - II111iiii + IiII * iIii1I11I1II1 - Oo0Ooo
 if 25 - 25: ooOoO0o
 if 33 - 33: Oo0Ooo
 if 11 - 11: I11i
 if 55 - 55: i11iIiiIii * OoOoOO00 - OoOoOO00 * OoO0O00 / iII111i
 if 64 - 64: iIii1I11I1II1 . Ii1I * Oo0Ooo - OoO0O00
 if 74 - 74: I1IiiI / o0oOOo0O0Ooo
def lisp_send_map_reply ( lisp_sockets , packet , dest , port ) :
 lprint ( "Send Map-Reply to {}" . format ( dest . print_address_no_iid ( ) ) )
 lisp_send_ipc_to_core ( lisp_sockets [ 2 ] , packet , dest , port )
 return
 if 53 - 53: iIii1I11I1II1 * oO0o
 if 43 - 43: IiII * Oo0Ooo / OOooOOo % oO0o
 if 11 - 11: OoOoOO00 * Oo0Ooo / I11i * OOooOOo
 if 15 - 15: ooOoO0o - OOooOOo / OoooooooOO
 if 41 - 41: OoOoOO00 . iII111i . i1IIi + oO0o
 if 60 - 60: oO0o * I1Ii111
 if 81 - 81: oO0o - OOooOOo - oO0o
 if 54 - 54: oO0o % I11i
def lisp_send_map_referral ( lisp_sockets , packet , dest , port ) :
 lprint ( "Send Map-Referral to {}" . format ( dest . print_address ( ) ) )
 lisp_send_ipc_to_core ( lisp_sockets [ 2 ] , packet , dest , port )
 return
 if 71 - 71: oO0o / I1ii11iIi11i . Ii1I % II111iiii
 if 22 - 22: iIii1I11I1II1 - OoooooooOO
 if 8 - 8: ooOoO0o % i11iIiiIii
 if 41 - 41: I1Ii111 . ooOoO0o - i11iIiiIii + Ii1I . OOooOOo . OoOoOO00
 if 70 - 70: i1IIi % OoOoOO00 / iII111i + i11iIiiIii % ooOoO0o + IiII
 if 58 - 58: OOooOOo / i11iIiiIii . Oo0Ooo % iII111i
 if 92 - 92: OoOoOO00 / ooOoO0o % iII111i / iIii1I11I1II1
 if 73 - 73: O0 % i11iIiiIii
def lisp_send_map_notify ( lisp_sockets , packet , dest , port ) :
 lprint ( "Send Map-Notify to xTR {}" . format ( dest . print_address ( ) ) )
 lisp_send_ipc_to_core ( lisp_sockets [ 2 ] , packet , dest , port )
 return
 if 16 - 16: O0
 if 15 - 15: i1IIi % i11iIiiIii
 if 18 - 18: Ii1I . OoO0O00 . iII111i * oO0o + O0
 if 35 - 35: OoOoOO00 . oO0o / II111iiii
 if 97 - 97: Ii1I + I1Ii111 / II111iiii
 if 14 - 14: iII111i / IiII / oO0o
 if 55 - 55: OoO0O00 % O0
def lisp_send_ecm ( lisp_sockets , packet , inner_source , inner_sport , inner_dest ,
 outer_dest , to_etr = False , to_ms = False , ddt = False ) :
 if 92 - 92: OoooooooOO / O0
 if ( inner_source == None or inner_source . is_null ( ) ) :
  inner_source = inner_dest
  if 14 - 14: i11iIiiIii
  if 43 - 43: OOooOOo
  if 79 - 79: iII111i % Oo0Ooo . i1IIi % ooOoO0o
  if 93 - 93: OoOoOO00
  if 49 - 49: i1IIi * OOooOOo % I11i * Ii1I . I1Ii111 * iIii1I11I1II1
  if 72 - 72: ooOoO0o
 if ( lisp_nat_traversal ) :
  iiI1iIII1ii = lisp_get_any_translated_port ( )
  if ( iiI1iIII1ii != None ) : inner_sport = iiI1iIII1ii
  if 63 - 63: Oo0Ooo . OoO0O00 . OoooooooOO / i1IIi
 IIi11 = lisp_ecm ( inner_sport )
 if 53 - 53: OOooOOo * O0 . iII111i
 IIi11 . to_etr = to_etr if lisp_is_running ( "lisp-etr" ) else False
 IIi11 . to_ms = to_ms if lisp_is_running ( "lisp-ms" ) else False
 IIi11 . ddt = ddt
 Ii11I11111i11 = IIi11 . encode ( packet , inner_source , inner_dest )
 if ( Ii11I11111i11 == None ) :
  lprint ( "Could not encode ECM message" )
  return
  if 45 - 45: Oo0Ooo / OOooOOo / oO0o * I1IiiI % OoOoOO00 * OoooooooOO
 IIi11 . print_ecm ( )
 if 40 - 40: Oo0Ooo - i11iIiiIii / o0oOOo0O0Ooo . II111iiii
 packet = Ii11I11111i11 + packet
 if 63 - 63: O0
 I1iiIiiii1111 = outer_dest . print_address_no_iid ( )
 lprint ( "Send Encapsulated-Control-Message to {}" . format ( I1iiIiiii1111 ) )
 oooooO0oO0o = lisp_convert_4to6 ( I1iiIiiii1111 )
 lisp_send ( lisp_sockets , oooooO0oO0o , LISP_CTRL_PORT , packet )
 return
 if 64 - 64: i11iIiiIii / oO0o . oO0o - Oo0Ooo
 if 48 - 48: i1IIi + I1ii11iIi11i + I1Ii111 - iII111i
 if 3 - 3: i1IIi + OoooooooOO * ooOoO0o + I1Ii111 % OOooOOo / IiII
 if 70 - 70: oO0o + i1IIi % o0oOOo0O0Ooo - I11i
 if 74 - 74: i11iIiiIii
 if 93 - 93: I1Ii111 % OOooOOo * I1IiiI % iII111i / iIii1I11I1II1 + OoO0O00
 if 6 - 6: I11i
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
if 70 - 70: ooOoO0o + OoooooooOO % OoOoOO00 % oO0o / Ii1I . I11i
LISP_RLOC_UNKNOWN_STATE = 0
LISP_RLOC_UP_STATE = 1
LISP_RLOC_DOWN_STATE = 2
LISP_RLOC_UNREACH_STATE = 3
LISP_RLOC_NO_ECHOED_NONCE_STATE = 4
LISP_RLOC_ADMIN_DOWN_STATE = 5
if 63 - 63: I1ii11iIi11i - ooOoO0o . OOooOOo / O0 . iIii1I11I1II1 - Ii1I
LISP_AUTH_NONE = 0
LISP_AUTH_MD5 = 1
LISP_AUTH_SHA1 = 2
LISP_AUTH_SHA2 = 3
if 6 - 6: Ii1I
if 60 - 60: iII111i + I1IiiI
if 36 - 36: i1IIi . O0 . OoO0O00 % OOooOOo * I11i / Ii1I
if 16 - 16: Oo0Ooo
if 44 - 44: iIii1I11I1II1 - II111iiii . IiII . i1IIi
if 37 - 37: OoooooooOO + Oo0Ooo - Oo0Ooo + I1ii11iIi11i . I1Ii111 / I1IiiI
if 60 - 60: I1IiiI % Ii1I / I1Ii111 + Ii1I
LISP_IPV4_HOST_MASK_LEN = 32
LISP_IPV6_HOST_MASK_LEN = 128
LISP_MAC_HOST_MASK_LEN = 48
LISP_E164_HOST_MASK_LEN = 60
if 43 - 43: I1ii11iIi11i + I11i
if 83 - 83: II111iiii + o0oOOo0O0Ooo - I1Ii111
if 100 - 100: IiII - OoOoOO00 / I11i
if 33 - 33: I1Ii111 * OoOoOO00 . I1ii11iIi11i % I1Ii111
if 87 - 87: Oo0Ooo
if 65 - 65: ooOoO0o . I1IiiI
def byte_swap_64 ( address ) :
 o0o0O00 = ( ( address & 0x00000000000000ff ) << 56 ) | ( ( address & 0x000000000000ff00 ) << 40 ) | ( ( address & 0x0000000000ff0000 ) << 24 ) | ( ( address & 0x00000000ff000000 ) << 8 ) | ( ( address & 0x000000ff00000000 ) >> 8 ) | ( ( address & 0x0000ff0000000000 ) >> 24 ) | ( ( address & 0x00ff000000000000 ) >> 40 ) | ( ( address & 0xff00000000000000 ) >> 56 )
 if 51 - 51: IiII
 if 43 - 43: oO0o - I11i . i11iIiiIii
 if 78 - 78: i11iIiiIii + Oo0Ooo * Ii1I - o0oOOo0O0Ooo % i11iIiiIii
 if 30 - 30: I1IiiI % oO0o * OoooooooOO
 if 64 - 64: I1IiiI
 if 11 - 11: I1ii11iIi11i % iII111i / II111iiii % ooOoO0o % IiII
 if 14 - 14: ooOoO0o / IiII . o0oOOo0O0Ooo
 if 27 - 27: I1IiiI - OOooOOo . II111iiii * I1ii11iIi11i % ooOoO0o / I1IiiI
 return ( o0o0O00 )
 if 90 - 90: o0oOOo0O0Ooo / I1ii11iIi11i - oO0o - Ii1I - I1IiiI + I1Ii111
 if 93 - 93: I1IiiI - I11i . I1IiiI - iIii1I11I1II1
 if 1 - 1: O0 . Ii1I % Ii1I + II111iiii . oO0o
 if 24 - 24: o0oOOo0O0Ooo . I1Ii111 % O0
 if 67 - 67: I1IiiI * Ii1I
 if 64 - 64: OOooOOo
 if 90 - 90: iII111i . OoOoOO00 + i1IIi % ooOoO0o * I11i + OoooooooOO
 if 2 - 2: o0oOOo0O0Ooo . II111iiii
 if 9 - 9: I1Ii111 - II111iiii + OoOoOO00 . OoO0O00
 if 33 - 33: Oo0Ooo
 if 12 - 12: i11iIiiIii . Oo0Ooo / OoOoOO00 + iII111i . Ii1I + ooOoO0o
 if 66 - 66: IiII
 if 41 - 41: II111iiii + Oo0Ooo / iII111i . IiII / iII111i / I1IiiI
 if 78 - 78: o0oOOo0O0Ooo % OoOoOO00 . O0
 if 41 - 41: iIii1I11I1II1 . OOooOOo - Oo0Ooo % OOooOOo
class lisp_cache_entries ( ) :
 def __init__ ( self ) :
  self . entries = { }
  self . entries_sorted = [ ]
  if 90 - 90: i11iIiiIii + OoooooooOO - i11iIiiIii + OoooooooOO
  if 23 - 23: i11iIiiIii - IiII - I1ii11iIi11i + I1ii11iIi11i % I1IiiI
  if 79 - 79: II111iiii / OoooooooOO
class lisp_cache ( ) :
 def __init__ ( self ) :
  self . cache = { }
  self . cache_sorted = [ ]
  self . cache_count = 0
  if 35 - 35: i1IIi + IiII + II111iiii % OOooOOo
  if 25 - 25: I11i + i11iIiiIii + O0 - Ii1I
 def cache_size ( self ) :
  return ( self . cache_count )
  if 69 - 69: I11i . OoOoOO00 / OOooOOo / i1IIi . II111iiii
  if 17 - 17: I1Ii111
 def build_key ( self , prefix ) :
  if ( prefix . afi == LISP_AFI_ULTIMATE_ROOT ) :
   ii1I1I1iII = 0
  elif ( prefix . afi == LISP_AFI_IID_RANGE ) :
   ii1I1I1iII = prefix . mask_len
  else :
   ii1I1I1iII = prefix . mask_len + 48
   if 2 - 2: O0 % OoOoOO00 + oO0o
   if 24 - 24: iII111i + iII111i - OoooooooOO % OoooooooOO * O0
  o0OOoOO = lisp_hex_string ( prefix . instance_id ) . zfill ( 8 )
  oOo00Oo0o00oo = lisp_hex_string ( prefix . afi ) . zfill ( 4 )
  if 51 - 51: IiII
  if ( prefix . afi > 0 ) :
   if ( prefix . is_binary ( ) ) :
    o00OOo00 = prefix . addr_length ( ) * 2
    o0o0O00 = lisp_hex_string ( prefix . address ) . zfill ( o00OOo00 )
   else :
    o0o0O00 = prefix . address
    if 31 - 31: I11i - iIii1I11I1II1 * Ii1I + Ii1I
  elif ( prefix . afi == LISP_AFI_GEO_COORD ) :
   oOo00Oo0o00oo = "8003"
   o0o0O00 = prefix . address . print_geo ( )
  else :
   oOo00Oo0o00oo = ""
   o0o0O00 = ""
   if 10 - 10: OoOoOO00 - i11iIiiIii % iIii1I11I1II1 / ooOoO0o * i11iIiiIii - Ii1I
   if 64 - 64: II111iiii . i11iIiiIii . iII111i . OOooOOo
  o0OoOo0o0OOoO0 = o0OOoOO + oOo00Oo0o00oo + o0o0O00
  return ( [ ii1I1I1iII , o0OoOo0o0OOoO0 ] )
  if 95 - 95: O0 - OoOoOO00
  if 68 - 68: ooOoO0o . I1Ii111
 def add_cache ( self , prefix , entry ) :
  if ( prefix . is_binary ( ) ) : prefix . zero_host_bits ( )
  ii1I1I1iII , o0OoOo0o0OOoO0 = self . build_key ( prefix )
  if ( self . cache . has_key ( ii1I1I1iII ) == False ) :
   self . cache [ ii1I1I1iII ] = lisp_cache_entries ( )
   self . cache [ ii1I1I1iII ] . entries = { }
   self . cache [ ii1I1I1iII ] . entries_sorted = [ ]
   self . cache_sorted = sorted ( self . cache )
   if 84 - 84: OoooooooOO + oO0o % i1IIi + o0oOOo0O0Ooo * i1IIi
  if ( self . cache [ ii1I1I1iII ] . entries . has_key ( o0OoOo0o0OOoO0 ) == False ) :
   self . cache_count += 1
   if 51 - 51: oO0o . OoooooooOO + OOooOOo * I1ii11iIi11i - ooOoO0o
  self . cache [ ii1I1I1iII ] . entries [ o0OoOo0o0OOoO0 ] = entry
  self . cache [ ii1I1I1iII ] . entries_sorted = sorted ( self . cache [ ii1I1I1iII ] . entries )
  if 41 - 41: Oo0Ooo
  if 46 - 46: i11iIiiIii + iIii1I11I1II1 . i11iIiiIii . iII111i
 def lookup_cache ( self , prefix , exact ) :
  oO0ooOo00o , o0OoOo0o0OOoO0 = self . build_key ( prefix )
  if ( exact ) :
   if ( self . cache . has_key ( oO0ooOo00o ) == False ) : return ( None )
   if ( self . cache [ oO0ooOo00o ] . entries . has_key ( o0OoOo0o0OOoO0 ) == False ) : return ( None )
   return ( self . cache [ oO0ooOo00o ] . entries [ o0OoOo0o0OOoO0 ] )
   if 64 - 64: i1IIi
   if 26 - 26: OOooOOo - iII111i * I1ii11iIi11i / iII111i
  IIIIIiiIII = None
  for ii1I1I1iII in self . cache_sorted :
   if ( oO0ooOo00o < ii1I1I1iII ) : return ( IIIIIiiIII )
   for I11ii in self . cache [ ii1I1I1iII ] . entries_sorted :
    OOOOo0oO0o = self . cache [ ii1I1I1iII ] . entries
    if ( I11ii in OOOOo0oO0o ) :
     iIIiI11iI1Ii1 = OOOOo0oO0o [ I11ii ]
     if ( iIIiI11iI1Ii1 == None ) : continue
     if ( prefix . is_more_specific ( iIIiI11iI1Ii1 . eid ) ) : IIIIIiiIII = iIIiI11iI1Ii1
     if 13 - 13: iII111i
     if 42 - 42: I1Ii111 - I1IiiI % I1IiiI * I1IiiI
     if 70 - 70: O0 / I1IiiI / I1IiiI
  return ( IIIIIiiIII )
  if 71 - 71: OOooOOo - Oo0Ooo + IiII * oO0o
  if 90 - 90: OoOoOO00 * I1ii11iIi11i
 def delete_cache ( self , prefix ) :
  ii1I1I1iII , o0OoOo0o0OOoO0 = self . build_key ( prefix )
  if ( self . cache . has_key ( ii1I1I1iII ) == False ) : return
  if ( self . cache [ ii1I1I1iII ] . entries . has_key ( o0OoOo0o0OOoO0 ) == False ) : return
  self . cache [ ii1I1I1iII ] . entries . pop ( o0OoOo0o0OOoO0 )
  self . cache [ ii1I1I1iII ] . entries_sorted . remove ( o0OoOo0o0OOoO0 )
  self . cache_count -= 1
  if 16 - 16: i1IIi - OoO0O00
  if 61 - 61: o0oOOo0O0Ooo + OoOoOO00 - ooOoO0o + ooOoO0o % ooOoO0o % II111iiii
 def walk_cache ( self , function , parms ) :
  for ii1I1I1iII in self . cache_sorted :
   for o0OoOo0o0OOoO0 in self . cache [ ii1I1I1iII ] . entries_sorted :
    iIIiI11iI1Ii1 = self . cache [ ii1I1I1iII ] . entries [ o0OoOo0o0OOoO0 ]
    ii1O0ooooo0OoO0 , parms = function ( iIIiI11iI1Ii1 , parms )
    if ( ii1O0ooooo0OoO0 == False ) : return ( parms )
    if 60 - 60: i11iIiiIii % IiII % i1IIi
    if 24 - 24: OOooOOo - OoOoOO00 - i1IIi + O0 + I1IiiI . o0oOOo0O0Ooo
  return ( parms )
  if 97 - 97: I1Ii111 + Ii1I * ooOoO0o
  if 95 - 95: O0
 def print_cache ( self ) :
  lprint ( "Printing contents of {}: " . format ( self ) )
  if ( self . cache_size ( ) == 0 ) :
   lprint ( "  Cache is empty" )
   return
   if 61 - 61: Oo0Ooo % O0 . Ii1I - OOooOOo - o0oOOo0O0Ooo
  for ii1I1I1iII in self . cache_sorted :
   for o0OoOo0o0OOoO0 in self . cache [ ii1I1I1iII ] . entries_sorted :
    iIIiI11iI1Ii1 = self . cache [ ii1I1I1iII ] . entries [ o0OoOo0o0OOoO0 ]
    lprint ( "  Mask-length: {}, key: {}, entry: {}" . format ( ii1I1I1iII , o0OoOo0o0OOoO0 ,
 iIIiI11iI1Ii1 ) )
    if 71 - 71: iIii1I11I1II1
    if 10 - 10: OoooooooOO - iII111i . i1IIi % oO0o . OoooooooOO + OOooOOo
    if 59 - 59: I1IiiI * OoooooooOO % OOooOOo / I11i
    if 77 - 77: II111iiii - IiII % OOooOOo
    if 22 - 22: OoooooooOO / oO0o
    if 78 - 78: oO0o * I11i . i1IIi % i1IIi + i1IIi / OOooOOo
    if 66 - 66: OoooooooOO % o0oOOo0O0Ooo / I11i * I1Ii111
    if 12 - 12: I1Ii111
lisp_referral_cache = lisp_cache ( )
lisp_ddt_cache = lisp_cache ( )
lisp_sites_by_eid = lisp_cache ( )
lisp_map_cache = lisp_cache ( )
lisp_db_for_lookups = lisp_cache ( )
if 17 - 17: I1Ii111 % oO0o + O0
if 15 - 15: o0oOOo0O0Ooo - OoooooooOO % ooOoO0o % oO0o / i11iIiiIii / Oo0Ooo
if 59 - 59: iII111i + O0 - I1ii11iIi11i * I1ii11iIi11i + iIii1I11I1II1
if 41 - 41: iIii1I11I1II1 . O0 - ooOoO0o / OoOoOO00 % iIii1I11I1II1 + IiII
if 23 - 23: OoOoOO00 + ooOoO0o . i11iIiiIii
if 39 - 39: OoOoOO00 - I1ii11iIi11i / I1Ii111
if 48 - 48: IiII - oO0o + I11i % o0oOOo0O0Ooo
def lisp_map_cache_lookup ( source , dest ) :
 if 81 - 81: Oo0Ooo . I1Ii111 * iIii1I11I1II1
 o0OoOO00O0O0 = dest . is_multicast_address ( )
 if 60 - 60: OoooooooOO
 if 41 - 41: iIii1I11I1II1 + O0 % o0oOOo0O0Ooo - IiII . I11i * O0
 if 39 - 39: i11iIiiIii . Ii1I
 if 68 - 68: OOooOOo * ooOoO0o . I1IiiI - iII111i
 Iii1 = lisp_map_cache . lookup_cache ( dest , False )
 if ( Iii1 == None ) :
  oOoo0OooOOo00 = source . print_sg ( dest ) if o0OoOO00O0O0 else dest . print_address ( )
  oOoo0OooOOo00 = green ( oOoo0OooOOo00 , False )
  dprint ( "Lookup for EID {} not found in map-cache" . format ( oOoo0OooOOo00 ) )
  return ( None )
  if 81 - 81: I11i % Oo0Ooo / iII111i
  if 44 - 44: Oo0Ooo
  if 90 - 90: Oo0Ooo . ooOoO0o / IiII * I1Ii111 . ooOoO0o + II111iiii
  if 43 - 43: iIii1I11I1II1 % OOooOOo + OoOoOO00 + I1ii11iIi11i - Oo0Ooo / Ii1I
  if 94 - 94: Ii1I / Oo0Ooo % II111iiii % Oo0Ooo * oO0o
 if ( o0OoOO00O0O0 == False ) :
  oo0oO00 = green ( Iii1 . eid . print_prefix ( ) , False )
  dprint ( "Lookup for EID {} found map-cache entry {}" . format ( green ( dest . print_address ( ) , False ) , oo0oO00 ) )
  if 54 - 54: O0 / ooOoO0o * I1Ii111
  return ( Iii1 )
  if 5 - 5: Ii1I / OoOoOO00 - O0 * OoO0O00
  if 13 - 13: IiII + Oo0Ooo - I1Ii111
  if 10 - 10: OOooOOo % OoooooooOO / I1IiiI . II111iiii % iII111i
  if 47 - 47: o0oOOo0O0Ooo . i11iIiiIii * i1IIi % I11i - ooOoO0o * oO0o
  if 95 - 95: oO0o / Ii1I + OoO0O00
 Iii1 = Iii1 . lookup_source_cache ( source , False )
 if ( Iii1 == None ) :
  oOoo0OooOOo00 = source . print_sg ( dest )
  dprint ( "Lookup for EID {} not found in map-cache" . format ( oOoo0OooOOo00 ) )
  return ( None )
  if 57 - 57: iIii1I11I1II1 + I1Ii111 % oO0o - Ii1I . I1IiiI
  if 39 - 39: OoO0O00 + II111iiii
  if 98 - 98: O0 - I1Ii111 % oO0o - iII111i + Ii1I * i1IIi
  if 76 - 76: o0oOOo0O0Ooo
  if 55 - 55: OOooOOo + I1ii11iIi11i * Oo0Ooo
 oo0oO00 = green ( Iii1 . print_eid_tuple ( ) , False )
 dprint ( "Lookup for EID {} found map-cache entry {}" . format ( green ( source . print_sg ( dest ) , False ) , oo0oO00 ) )
 if 11 - 11: i1IIi - OoooooooOO * OoOoOO00 / oO0o - OoooooooOO - I1IiiI
 return ( Iii1 )
 if 22 - 22: i11iIiiIii . Ii1I . Oo0Ooo * Oo0Ooo - iII111i / I1ii11iIi11i
 if 49 - 49: iII111i + I11i . Oo0Ooo
 if 23 - 23: I1IiiI . Ii1I + ooOoO0o . OoooooooOO
 if 57 - 57: OOooOOo / OoOoOO00 / i11iIiiIii - I11i - I11i . Ii1I
 if 53 - 53: ooOoO0o . iII111i + Ii1I * I1Ii111
 if 49 - 49: II111iiii . I1ii11iIi11i * OoOoOO00 - OOooOOo
 if 48 - 48: OoO0O00 . iIii1I11I1II1 - OoooooooOO + I1Ii111 / i11iIiiIii . Oo0Ooo
def lisp_referral_cache_lookup ( eid , group , exact ) :
 if ( group and group . is_null ( ) ) :
  iii = lisp_referral_cache . lookup_cache ( eid , exact )
  return ( iii )
  if 61 - 61: II111iiii + OOooOOo . o0oOOo0O0Ooo . iIii1I11I1II1
  if 63 - 63: I11i + i11iIiiIii . o0oOOo0O0Ooo . i1IIi + OoOoOO00
  if 1 - 1: i11iIiiIii
  if 1 - 1: iIii1I11I1II1
  if 73 - 73: iII111i + IiII
 if ( eid == None or eid . is_null ( ) ) : return ( None )
 if 95 - 95: O0
 if 75 - 75: ooOoO0o
 if 8 - 8: O0 - OoooooooOO + I1ii11iIi11i / Oo0Ooo . oO0o + I1Ii111
 if 85 - 85: ooOoO0o
 if 29 - 29: iII111i . Ii1I
 if 43 - 43: I11i - I1ii11iIi11i + iIii1I11I1II1 / I1ii11iIi11i * oO0o / iIii1I11I1II1
 iii = lisp_referral_cache . lookup_cache ( group , exact )
 if ( iii == None ) : return ( None )
 if 45 - 45: IiII
 Ii1 = iii . lookup_source_cache ( eid , exact )
 if ( Ii1 ) : return ( Ii1 )
 if 79 - 79: i11iIiiIii / II111iiii . I1Ii111 % O0
 if ( exact ) : iii = None
 return ( iii )
 if 52 - 52: I1IiiI . oO0o % OOooOOo . oO0o * i11iIiiIii * IiII
 if 30 - 30: iIii1I11I1II1 - ooOoO0o / iIii1I11I1II1 / I1IiiI + OoOoOO00 - iIii1I11I1II1
 if 69 - 69: i11iIiiIii . O0
 if 21 - 21: i1IIi . OoO0O00 % I11i + II111iiii % o0oOOo0O0Ooo
 if 17 - 17: i11iIiiIii + oO0o * iII111i . II111iiii
 if 44 - 44: I1ii11iIi11i
 if 39 - 39: iII111i + Oo0Ooo / oO0o
def lisp_ddt_cache_lookup ( eid , group , exact ) :
 if ( group . is_null ( ) ) :
  IiiI11i11i = lisp_ddt_cache . lookup_cache ( eid , exact )
  return ( IiiI11i11i )
  if 95 - 95: I1Ii111 * oO0o / ooOoO0o . Ii1I . OoOoOO00
  if 99 - 99: I1IiiI * II111iiii
  if 84 - 84: II111iiii - I1IiiI
  if 41 - 41: iIii1I11I1II1 % I1Ii111 % OoOoOO00
  if 35 - 35: I11i + i1IIi
 if ( eid . is_null ( ) ) : return ( None )
 if 85 - 85: Ii1I * Ii1I . OoOoOO00 / Oo0Ooo
 if 97 - 97: oO0o % iIii1I11I1II1
 if 87 - 87: II111iiii % I1IiiI + oO0o - I11i / I11i
 if 16 - 16: I1IiiI
 if 39 - 39: ooOoO0o * II111iiii
 if 90 - 90: OoooooooOO * ooOoO0o
 IiiI11i11i = lisp_ddt_cache . lookup_cache ( group , exact )
 if ( IiiI11i11i == None ) : return ( None )
 if 14 - 14: I1IiiI % i1IIi
 i11I11111i1 = IiiI11i11i . lookup_source_cache ( eid , exact )
 if ( i11I11111i1 ) : return ( i11I11111i1 )
 if 15 - 15: Ii1I
 if ( exact ) : IiiI11i11i = None
 return ( IiiI11i11i )
 if 23 - 23: iIii1I11I1II1 - oO0o / O0 - I1Ii111 - OOooOOo
 if 49 - 49: I1Ii111
 if 88 - 88: O0
 if 75 - 75: iII111i - Oo0Ooo / OoooooooOO - O0
 if 36 - 36: OoO0O00 % Ii1I . Oo0Ooo
 if 90 - 90: i11iIiiIii - iII111i * oO0o
 if 79 - 79: IiII
def lisp_site_eid_lookup ( eid , group , exact ) :
 if 38 - 38: I1Ii111
 if ( group . is_null ( ) ) :
  ooOOOo0o0oo = lisp_sites_by_eid . lookup_cache ( eid , exact )
  return ( ooOOOo0o0oo )
  if 56 - 56: i11iIiiIii
  if 58 - 58: i11iIiiIii / OoOoOO00
  if 23 - 23: I1IiiI % iIii1I11I1II1 - oO0o - iII111i - o0oOOo0O0Ooo
  if 39 - 39: Oo0Ooo . OoO0O00
  if 74 - 74: I1IiiI . O0 . IiII + IiII - IiII
 if ( eid . is_null ( ) ) : return ( None )
 if 100 - 100: ooOoO0o / OoooooooOO
 if 73 - 73: i11iIiiIii - Oo0Ooo
 if 100 - 100: iIii1I11I1II1 + I1Ii111
 if 51 - 51: o0oOOo0O0Ooo * I11i
 if 42 - 42: OOooOOo % I11i
 if 84 - 84: Oo0Ooo * OoOoOO00 / Ii1I / IiII / o0oOOo0O0Ooo . I1ii11iIi11i
 ooOOOo0o0oo = lisp_sites_by_eid . lookup_cache ( group , exact )
 if ( ooOOOo0o0oo == None ) : return ( None )
 if 81 - 81: I1IiiI
 if 82 - 82: I1Ii111 - OoooooooOO - Ii1I
 if 34 - 34: OOooOOo . iIii1I11I1II1 / I1IiiI . Oo0Ooo - iIii1I11I1II1
 if 83 - 83: iII111i - I1ii11iIi11i + iII111i
 if 4 - 4: o0oOOo0O0Ooo % iIii1I11I1II1 + I11i
 if 60 - 60: I1ii11iIi11i / I1Ii111 % i11iIiiIii % oO0o % I1IiiI . Oo0Ooo
 if 20 - 20: IiII - OOooOOo + OoOoOO00
 if 83 - 83: OoooooooOO / I1IiiI + iII111i - iIii1I11I1II1 % ooOoO0o
 if 74 - 74: OoO0O00
 if 13 - 13: I1ii11iIi11i / OoO0O00
 if 90 - 90: iIii1I11I1II1 - OoO0O00 . i1IIi / o0oOOo0O0Ooo + O0
 if 94 - 94: IiII * i1IIi
 if 90 - 90: O0 % I1IiiI . o0oOOo0O0Ooo % ooOoO0o % I1IiiI
 if 16 - 16: OoO0O00 / OOooOOo / iIii1I11I1II1 / OoooooooOO . oO0o - I1Ii111
 if 43 - 43: OoOoOO00 % OOooOOo / I1IiiI + I1IiiI
 if 40 - 40: OOooOOo . I1Ii111 + I1Ii111
 if 4 - 4: iIii1I11I1II1 - iIii1I11I1II1 * I11i
 if 32 - 32: I1IiiI + II111iiii * iII111i + O0 / O0 * Oo0Ooo
 Oooo0oo000O0 = ooOOOo0o0oo . lookup_source_cache ( eid , exact )
 if ( Oooo0oo000O0 ) : return ( Oooo0oo000O0 )
 if 64 - 64: i11iIiiIii / iII111i + i11iIiiIii . I11i
 if ( exact ) :
  ooOOOo0o0oo = None
 else :
  iiiIIIII1iIi = ooOOOo0o0oo . parent_for_more_specifics
  if ( iiiIIIII1iIi and iiiIIIII1iIi . accept_more_specifics ) :
   if ( group . is_more_specific ( iiiIIIII1iIi . group ) ) : ooOOOo0o0oo = iiiIIIII1iIi
   if 66 - 66: i1IIi
   if 98 - 98: Oo0Ooo / iIii1I11I1II1
 return ( ooOOOo0o0oo )
 if 33 - 33: O0 - iII111i
 if 40 - 40: iII111i * I11i
 if 25 - 25: O0 * o0oOOo0O0Ooo % ooOoO0o % I1IiiI
 if 87 - 87: OoOoOO00
 if 30 - 30: IiII % OoOoOO00 + I1Ii111
 if 13 - 13: iII111i * Ii1I % o0oOOo0O0Ooo * i1IIi . IiII % i1IIi
 if 79 - 79: OoooooooOO % I11i / o0oOOo0O0Ooo + IiII + O0 + iII111i
 if 87 - 87: I11i
 if 39 - 39: I1ii11iIi11i * i11iIiiIii % I1Ii111
 if 72 - 72: OoO0O00 * Oo0Ooo - IiII
 if 74 - 74: Ii1I
 if 26 - 26: I11i . O0
 if 68 - 68: Ii1I
 if 26 - 26: o0oOOo0O0Ooo - I1ii11iIi11i / O0 % i11iIiiIii
 if 7 - 7: I1Ii111 . Oo0Ooo + IiII / iIii1I11I1II1
 if 22 - 22: iIii1I11I1II1 - O0 . iII111i - IiII - ooOoO0o
 if 54 - 54: OoO0O00 . iII111i . OoOoOO00 * OoO0O00 + o0oOOo0O0Ooo . ooOoO0o
 if 44 - 44: I11i * iIii1I11I1II1 . I1ii11iIi11i
 if 9 - 9: o0oOOo0O0Ooo
 if 23 - 23: ooOoO0o * OoO0O00 + O0 % I1Ii111
 if 21 - 21: Ii1I * OoOoOO00
 if 29 - 29: iIii1I11I1II1 / ooOoO0o
 if 75 - 75: OoooooooOO + I1IiiI % OoOoOO00 / O0 - IiII
 if 88 - 88: OoO0O00 % Ii1I
 if 12 - 12: OoooooooOO . O0
 if 33 - 33: OoooooooOO / I11i . II111iiii * i1IIi
class lisp_address ( ) :
 def __init__ ( self , afi , addr_str , mask_len , iid ) :
  self . afi = afi
  self . mask_len = mask_len
  self . instance_id = iid
  self . iid_list = [ ]
  self . address = 0
  if ( addr_str != "" ) : self . store_address ( addr_str )
  if 34 - 34: i11iIiiIii / OoOoOO00
  if 100 - 100: o0oOOo0O0Ooo - I1IiiI / I11i
 def copy_address ( self , addr ) :
  if ( addr == None ) : return
  self . afi = addr . afi
  self . address = addr . address
  self . mask_len = addr . mask_len
  self . instance_id = addr . instance_id
  self . iid_list = addr . iid_list
  if 43 - 43: o0oOOo0O0Ooo % iIii1I11I1II1
  if 85 - 85: oO0o + OoooooooOO - IiII % o0oOOo0O0Ooo * ooOoO0o * II111iiii
 def make_default_route ( self , addr ) :
  self . afi = addr . afi
  self . instance_id = addr . instance_id
  self . mask_len = 0
  self . address = 0
  if 4 - 4: Ii1I . i1IIi + Oo0Ooo % I11i . OoO0O00
  if 70 - 70: OOooOOo * OoOoOO00 / OoOoOO00 / OoOoOO00
 def make_default_multicast_route ( self , addr ) :
  self . afi = addr . afi
  self . instance_id = addr . instance_id
  if ( self . afi == LISP_AFI_IPV4 ) :
   self . address = 0xe0000000
   self . mask_len = 4
   if 23 - 23: I1IiiI
  if ( self . afi == LISP_AFI_IPV6 ) :
   self . address = 0xff << 120
   self . mask_len = 8
   if 24 - 24: I1Ii111 * i1IIi % O0 * Ii1I + iII111i
  if ( self . afi == LISP_AFI_MAC ) :
   self . address = 0xffffffffffff
   self . mask_len = 48
   if 14 - 14: oO0o * iII111i + Ii1I + Ii1I * IiII
   if 82 - 82: IiII * ooOoO0o / OOooOOo + OoOoOO00
   if 32 - 32: IiII
 def not_set ( self ) :
  return ( self . afi == LISP_AFI_NONE )
  if 90 - 90: I1ii11iIi11i / I11i * o0oOOo0O0Ooo % O0 * i11iIiiIii
  if 68 - 68: I11i . Ii1I + I11i / IiII . I11i / iIii1I11I1II1
 def is_private_address ( self ) :
  if ( self . is_ipv4 ( ) == False ) : return ( False )
  o0o0O00 = self . address
  if ( ( ( o0o0O00 & 0xff000000 ) >> 24 ) == 10 ) : return ( True )
  if ( ( ( o0o0O00 & 0xff000000 ) >> 24 ) == 172 ) :
   oo = ( o0o0O00 & 0x00ff0000 ) >> 16
   if ( oo >= 16 and oo <= 31 ) : return ( True )
   if 40 - 40: Oo0Ooo + iII111i
  if ( ( ( o0o0O00 & 0xffff0000 ) >> 16 ) == 0xc0a8 ) : return ( True )
  return ( False )
  if 51 - 51: o0oOOo0O0Ooo - I11i
  if 65 - 65: ooOoO0o - o0oOOo0O0Ooo + I11i
 def is_multicast_address ( self ) :
  if ( self . is_ipv4 ( ) ) : return ( self . is_ipv4_multicast ( ) )
  if ( self . is_ipv6 ( ) ) : return ( self . is_ipv6_multicast ( ) )
  if ( self . is_mac ( ) ) : return ( self . is_mac_multicast ( ) )
  return ( False )
  if 50 - 50: I11i + O0 + O0 * oO0o * II111iiii
  if 7 - 7: Oo0Ooo . I1Ii111 % oO0o % Oo0Ooo - IiII . ooOoO0o
 def host_mask_len ( self ) :
  if ( self . afi == LISP_AFI_IPV4 ) : return ( LISP_IPV4_HOST_MASK_LEN )
  if ( self . afi == LISP_AFI_IPV6 ) : return ( LISP_IPV6_HOST_MASK_LEN )
  if ( self . afi == LISP_AFI_MAC ) : return ( LISP_MAC_HOST_MASK_LEN )
  if ( self . afi == LISP_AFI_E164 ) : return ( LISP_E164_HOST_MASK_LEN )
  if ( self . afi == LISP_AFI_NAME ) : return ( len ( self . address ) * 8 )
  if ( self . afi == LISP_AFI_GEO_COORD ) :
   return ( len ( self . address . print_geo ( ) ) * 8 )
   if 73 - 73: iIii1I11I1II1 / o0oOOo0O0Ooo + o0oOOo0O0Ooo + ooOoO0o + ooOoO0o
  return ( 0 )
  if 58 - 58: i1IIi . I1Ii111
  if 94 - 94: ooOoO0o - IiII
 def is_iana_eid ( self ) :
  if ( self . is_ipv6 ( ) == False ) : return ( False )
  o0o0O00 = self . address >> 96
  return ( o0o0O00 == 0x20010005 )
  if 92 - 92: Ii1I . i11iIiiIii
  if 45 - 45: ooOoO0o * I1IiiI / iII111i
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
   if 29 - 29: i1IIi + Ii1I * OoO0O00
  return ( 0 )
  if 69 - 69: Ii1I - OOooOOo * I11i . I1IiiI + o0oOOo0O0Ooo / OoO0O00
  if 45 - 45: OOooOOo
 def afi_to_version ( self ) :
  if ( self . afi == LISP_AFI_IPV4 ) : return ( 4 )
  if ( self . afi == LISP_AFI_IPV6 ) : return ( 6 )
  return ( 0 )
  if 57 - 57: iIii1I11I1II1 + IiII - I1IiiI
  if 64 - 64: II111iiii . IiII / I1IiiI
 def packet_format ( self ) :
  if 20 - 20: OoooooooOO - I1ii11iIi11i * I1ii11iIi11i * I1ii11iIi11i
  if 87 - 87: OoooooooOO * ooOoO0o
  if 6 - 6: I1Ii111 / ooOoO0o / OoooooooOO . iIii1I11I1II1
  if 68 - 68: OoO0O00
  if 26 - 26: I11i % i1IIi / iIii1I11I1II1 % IiII . iII111i + I1ii11iIi11i
  if ( self . afi == LISP_AFI_IPV4 ) : return ( "I" )
  if ( self . afi == LISP_AFI_IPV6 ) : return ( "QQ" )
  if ( self . afi == LISP_AFI_MAC ) : return ( "HHH" )
  if ( self . afi == LISP_AFI_E164 ) : return ( "II" )
  if ( self . afi == LISP_AFI_LCAF ) : return ( "I" )
  return ( "" )
  if 49 - 49: O0 . IiII + I1Ii111 - I11i % II111iiii
  if 15 - 15: O0 - OoOoOO00 % II111iiii + O0 % O0 + OoOoOO00
 def pack_address ( self ) :
  oOo0ooO0O0oo = self . packet_format ( )
  i1II1IiiIi = ""
  if ( self . is_ipv4 ( ) ) :
   i1II1IiiIi = struct . pack ( oOo0ooO0O0oo , socket . htonl ( self . address ) )
  elif ( self . is_ipv6 ( ) ) :
   OooO0O0Ooo = byte_swap_64 ( self . address >> 64 )
   oO0O = byte_swap_64 ( self . address & 0xffffffffffffffff )
   i1II1IiiIi = struct . pack ( oOo0ooO0O0oo , OooO0O0Ooo , oO0O )
  elif ( self . is_mac ( ) ) :
   o0o0O00 = self . address
   OooO0O0Ooo = ( o0o0O00 >> 32 ) & 0xffff
   oO0O = ( o0o0O00 >> 16 ) & 0xffff
   i1Iii1I1iIi11 = o0o0O00 & 0xffff
   i1II1IiiIi = struct . pack ( oOo0ooO0O0oo , OooO0O0Ooo , oO0O , i1Iii1I1iIi11 )
  elif ( self . is_e164 ( ) ) :
   o0o0O00 = self . address
   OooO0O0Ooo = ( o0o0O00 >> 32 ) & 0xffffffff
   oO0O = ( o0o0O00 & 0xffffffff )
   i1II1IiiIi = struct . pack ( oOo0ooO0O0oo , OooO0O0Ooo , oO0O )
  elif ( self . is_dist_name ( ) ) :
   i1II1IiiIi += self . address + "\0"
   if 98 - 98: Oo0Ooo - OoOoOO00
  return ( i1II1IiiIi )
  if 28 - 28: I1IiiI * I1Ii111 % OoO0O00
  if 51 - 51: Ii1I
 def unpack_address ( self , packet ) :
  oOo0ooO0O0oo = self . packet_format ( )
  OO00OO = struct . calcsize ( oOo0ooO0O0oo )
  if ( len ( packet ) < OO00OO ) : return ( None )
  if 85 - 85: Ii1I + OOooOOo + ooOoO0o
  o0o0O00 = struct . unpack ( oOo0ooO0O0oo , packet [ : OO00OO ] )
  if 13 - 13: I1ii11iIi11i
  if ( self . is_ipv4 ( ) ) :
   self . address = socket . ntohl ( o0o0O00 [ 0 ] )
   if 97 - 97: oO0o - Oo0Ooo . i11iIiiIii % ooOoO0o * i11iIiiIii - OoooooooOO
  elif ( self . is_ipv6 ( ) ) :
   if 44 - 44: I11i % OoooooooOO / iII111i - i11iIiiIii * i1IIi * o0oOOo0O0Ooo
   if 51 - 51: Ii1I + IiII / I1ii11iIi11i + O0 % Ii1I
   if 55 - 55: iII111i % o0oOOo0O0Ooo - oO0o % OoooooooOO
   if 18 - 18: OoooooooOO - I1ii11iIi11i
   if 94 - 94: OOooOOo . Oo0Ooo + Ii1I * o0oOOo0O0Ooo
   if 79 - 79: OOooOOo + Oo0Ooo
   if 33 - 33: iIii1I11I1II1
   if 75 - 75: I1Ii111 / iIii1I11I1II1 . OoooooooOO
   if ( o0o0O00 [ 0 ] <= 0xffff and ( o0o0O00 [ 0 ] & 0xff ) == 0 ) :
    ooOoo = ( o0o0O00 [ 0 ] << 48 ) << 64
   else :
    ooOoo = byte_swap_64 ( o0o0O00 [ 0 ] ) << 64
    if 80 - 80: II111iiii . Oo0Ooo * oO0o % II111iiii / I1ii11iIi11i
   o0oO = byte_swap_64 ( o0o0O00 [ 1 ] )
   self . address = ooOoo | o0oO
   if 1 - 1: OOooOOo . OoOoOO00 - i11iIiiIii . o0oOOo0O0Ooo / o0oOOo0O0Ooo * Ii1I
  elif ( self . is_mac ( ) ) :
   IiIIIi11I = o0o0O00 [ 0 ]
   OO0O = o0o0O00 [ 1 ]
   O0OOoOO = o0o0O00 [ 2 ]
   self . address = ( IiIIIi11I << 32 ) + ( OO0O << 16 ) + O0OOoOO
   if 72 - 72: ooOoO0o . I11i + i11iIiiIii / oO0o % oO0o * i1IIi
  elif ( self . is_e164 ( ) ) :
   self . address = ( o0o0O00 [ 0 ] << 32 ) + o0o0O00 [ 1 ]
   if 55 - 55: Oo0Ooo % oO0o . i11iIiiIii
  elif ( self . is_dist_name ( ) ) :
   packet , self . address = lisp_decode_dist_name ( packet )
   self . mask_len = len ( self . address ) * 8
   OO00OO = 0
   if 95 - 95: OoO0O00 * OOooOOo
  packet = packet [ OO00OO : : ]
  return ( packet )
  if 93 - 93: I1Ii111 / I11i % Oo0Ooo . I11i . oO0o + OoooooooOO
  if 9 - 9: OoO0O00
 def is_ipv4 ( self ) :
  return ( True if ( self . afi == LISP_AFI_IPV4 ) else False )
  if 46 - 46: o0oOOo0O0Ooo % OoO0O00 + I11i % o0oOOo0O0Ooo + oO0o . Oo0Ooo
  if 58 - 58: I1Ii111 + I1ii11iIi11i
 def is_ipv4_link_local ( self ) :
  if ( self . is_ipv4 ( ) == False ) : return ( False )
  return ( ( ( self . address >> 16 ) & 0xffff ) == 0xa9fe )
  if 57 - 57: OOooOOo + II111iiii
  if 67 - 67: II111iiii
 def is_ipv4_loopback ( self ) :
  if ( self . is_ipv4 ( ) == False ) : return ( False )
  return ( self . address == 0x7f000001 )
  if 39 - 39: i1IIi
  if 16 - 16: OoOoOO00 % iIii1I11I1II1 + Ii1I - o0oOOo0O0Ooo . Oo0Ooo + i1IIi
 def is_ipv4_multicast ( self ) :
  if ( self . is_ipv4 ( ) == False ) : return ( False )
  return ( ( ( self . address >> 24 ) & 0xf0 ) == 0xe0 )
  if 59 - 59: i1IIi
  if 37 - 37: OoO0O00 / I1ii11iIi11i / OoOoOO00
 def is_ipv4_string ( self , addr_str ) :
  return ( addr_str . find ( "." ) != - 1 )
  if 15 - 15: I1IiiI % iIii1I11I1II1 . I1Ii111
  if 71 - 71: I11i - Ii1I + i11iIiiIii % I1ii11iIi11i - OoO0O00 - OOooOOo
 def is_ipv6 ( self ) :
  return ( True if ( self . afi == LISP_AFI_IPV6 ) else False )
  if 71 - 71: OOooOOo
  if 27 - 27: OOooOOo * O0 * i11iIiiIii / OoOoOO00 - i1IIi
 def is_ipv6_link_local ( self ) :
  if ( self . is_ipv6 ( ) == False ) : return ( False )
  return ( ( ( self . address >> 112 ) & 0xffff ) == 0xfe80 )
  if 73 - 73: iII111i / I1IiiI * ooOoO0o
  if 85 - 85: I11i + I11i + oO0o - OoOoOO00
 def is_ipv6_string_link_local ( self , addr_str ) :
  return ( addr_str . find ( "fe80::" ) != - 1 )
  if 15 - 15: OoO0O00
  if 88 - 88: Ii1I % i1IIi / I1Ii111
 def is_ipv6_loopback ( self ) :
  if ( self . is_ipv6 ( ) == False ) : return ( False )
  return ( self . address == 1 )
  if 2 - 2: Ii1I . IiII % OoOoOO00
  if 42 - 42: OoOoOO00 * OoO0O00 * IiII - IiII % Oo0Ooo . IiII
 def is_ipv6_multicast ( self ) :
  if ( self . is_ipv6 ( ) == False ) : return ( False )
  return ( ( ( self . address >> 120 ) & 0xff ) == 0xff )
  if 38 - 38: I1Ii111 . IiII - ooOoO0o . i11iIiiIii
  if 35 - 35: i11iIiiIii
 def is_ipv6_string ( self , addr_str ) :
  return ( addr_str . find ( ":" ) != - 1 )
  if 62 - 62: O0 - o0oOOo0O0Ooo + I1Ii111 * I1ii11iIi11i / OOooOOo
  if 87 - 87: Oo0Ooo / OoooooooOO + O0 / o0oOOo0O0Ooo % II111iiii - O0
 def is_mac ( self ) :
  return ( True if ( self . afi == LISP_AFI_MAC ) else False )
  if 63 - 63: OOooOOo - OoO0O00 * i1IIi - I1ii11iIi11i . I1IiiI
  if 59 - 59: i11iIiiIii . OOooOOo % Oo0Ooo + O0
 def is_mac_multicast ( self ) :
  if ( self . is_mac ( ) == False ) : return ( False )
  return ( ( self . address & 0x010000000000 ) != 0 )
  if 84 - 84: I1Ii111 / O0 - IiII . I11i / o0oOOo0O0Ooo
  if 12 - 12: i11iIiiIii / Ii1I + i1IIi
 def is_mac_broadcast ( self ) :
  if ( self . is_mac ( ) == False ) : return ( False )
  return ( self . address == 0xffffffffffff )
  if 54 - 54: I1IiiI
  if 55 - 55: I1ii11iIi11i % IiII % o0oOOo0O0Ooo + i1IIi * OoooooooOO % II111iiii
 def is_mac_string ( self , addr_str ) :
  return ( len ( addr_str ) == 15 and addr_str . find ( "-" ) != - 1 )
  if 37 - 37: Oo0Ooo
  if 33 - 33: OoooooooOO - O0 . O0 - o0oOOo0O0Ooo % o0oOOo0O0Ooo % OoO0O00
 def is_link_local_multicast ( self ) :
  if ( self . is_ipv4 ( ) ) :
   return ( ( 0xe0ffff00 & self . address ) == 0xe0000000 )
   if 27 - 27: ooOoO0o . i11iIiiIii / o0oOOo0O0Ooo * OoO0O00 * OoOoOO00 * oO0o
  if ( self . is_ipv6 ( ) ) :
   return ( ( self . address >> 112 ) & 0xffff == 0xff02 )
   if 19 - 19: O0 * II111iiii * OoOoOO00
  return ( False )
  if 53 - 53: Oo0Ooo
  if 16 - 16: Ii1I
 def is_null ( self ) :
  return ( True if ( self . afi == LISP_AFI_NONE ) else False )
  if 73 - 73: i11iIiiIii + I1IiiI - IiII - IiII + IiII . Ii1I
  if 78 - 78: OoO0O00 + oO0o
 def is_ultimate_root ( self ) :
  return ( True if self . afi == LISP_AFI_ULTIMATE_ROOT else False )
  if 86 - 86: ooOoO0o . ooOoO0o + oO0o
  if 84 - 84: OOooOOo - OoOoOO00 + i1IIi * I1ii11iIi11i % I1ii11iIi11i * I1Ii111
 def is_iid_range ( self ) :
  return ( True if self . afi == LISP_AFI_IID_RANGE else False )
  if 31 - 31: IiII + iII111i
  if 5 - 5: O0 * Ii1I
 def is_e164 ( self ) :
  return ( True if ( self . afi == LISP_AFI_E164 ) else False )
  if 78 - 78: iII111i * iIii1I11I1II1 . OoO0O00 . OoOoOO00 % I1Ii111
  if 77 - 77: OOooOOo / OoooooooOO
 def is_dist_name ( self ) :
  return ( True if ( self . afi == LISP_AFI_NAME ) else False )
  if 11 - 11: iIii1I11I1II1 - Ii1I - OoOoOO00 . oO0o / I1ii11iIi11i
  if 79 - 79: i11iIiiIii % o0oOOo0O0Ooo * II111iiii . i1IIi * Ii1I - i11iIiiIii
 def is_geo_prefix ( self ) :
  return ( True if ( self . afi == LISP_AFI_GEO_COORD ) else False )
  if 31 - 31: IiII / o0oOOo0O0Ooo
  if 27 - 27: Oo0Ooo
 def is_binary ( self ) :
  if ( self . is_dist_name ( ) ) : return ( False )
  if ( self . is_geo_prefix ( ) ) : return ( False )
  return ( True )
  if 32 - 32: Oo0Ooo * i11iIiiIii % I1IiiI - i11iIiiIii - I1Ii111 % I1ii11iIi11i
  if 35 - 35: o0oOOo0O0Ooo % iII111i / O0 * I1IiiI . o0oOOo0O0Ooo / OOooOOo
 def store_address ( self , addr_str ) :
  if ( self . afi == LISP_AFI_NONE ) : self . string_to_afi ( addr_str )
  if 81 - 81: I1ii11iIi11i - i11iIiiIii
  if 49 - 49: iII111i * I11i - II111iiii . o0oOOo0O0Ooo
  if 52 - 52: Ii1I + Ii1I - II111iiii . O0 + I1ii11iIi11i
  if 60 - 60: i11iIiiIii + IiII
  Ii11 = addr_str . find ( "[" )
  Ii1i1Ii = addr_str . find ( "]" )
  if ( Ii11 != - 1 and Ii1i1Ii != - 1 ) :
   self . instance_id = int ( addr_str [ Ii11 + 1 : Ii1i1Ii ] )
   addr_str = addr_str [ Ii1i1Ii + 1 : : ]
   if ( self . is_dist_name ( ) == False ) :
    addr_str = addr_str . replace ( " " , "" )
    if 41 - 41: I1Ii111 * o0oOOo0O0Ooo + Oo0Ooo
    if 86 - 86: Ii1I / oO0o
    if 40 - 40: OoO0O00 % oO0o + Oo0Ooo
    if 60 - 60: II111iiii / Ii1I
    if 14 - 14: iII111i - Oo0Ooo / o0oOOo0O0Ooo * oO0o / Oo0Ooo - I1IiiI
    if 89 - 89: i1IIi / I1Ii111 + Ii1I - i1IIi
  if ( self . is_ipv4 ( ) ) :
   o0oOOoOOoO00O0oO = addr_str . split ( "." )
   oOO = int ( o0oOOoOOoO00O0oO [ 0 ] ) << 24
   oOO += int ( o0oOOoOOoO00O0oO [ 1 ] ) << 16
   oOO += int ( o0oOOoOOoO00O0oO [ 2 ] ) << 8
   oOO += int ( o0oOOoOOoO00O0oO [ 3 ] )
   self . address = oOO
  elif ( self . is_ipv6 ( ) ) :
   if 81 - 81: Ii1I
   if 8 - 8: I1ii11iIi11i * I1IiiI * OOooOOo - I1Ii111 - iII111i
   if 67 - 67: oO0o
   if 76 - 76: I1IiiI % I1IiiI - IiII / OoOoOO00 / I1ii11iIi11i
   if 42 - 42: I1IiiI + I1ii11iIi11i + Oo0Ooo * i1IIi - II111iiii
   if 15 - 15: o0oOOo0O0Ooo
   if 60 - 60: I1ii11iIi11i / I1Ii111
   if 13 - 13: I1Ii111
   if 52 - 52: II111iiii / OoO0O00 . Ii1I
   if 68 - 68: iII111i
   if 67 - 67: I1IiiI * I1IiiI
   if 100 - 100: iII111i * iII111i . Oo0Ooo
   if 10 - 10: Oo0Ooo % ooOoO0o * Oo0Ooo
   if 48 - 48: ooOoO0o + II111iiii
   if 73 - 73: II111iiii
   if 63 - 63: i11iIiiIii . Oo0Ooo . OOooOOo - II111iiii
   if 35 - 35: II111iiii + IiII
   oO0Oo0oO00O = ( addr_str [ 2 : 4 ] == "::" )
   try :
    addr_str = socket . inet_pton ( socket . AF_INET6 , addr_str )
   except :
    addr_str = socket . inet_pton ( socket . AF_INET6 , "0::0" )
    if 54 - 54: IiII - Oo0Ooo
   addr_str = binascii . hexlify ( addr_str )
   if 55 - 55: I11i * OOooOOo * I1ii11iIi11i . i11iIiiIii
   if ( oO0Oo0oO00O ) :
    addr_str = addr_str [ 2 : 4 ] + addr_str [ 0 : 2 ] + addr_str [ 4 : : ]
    if 93 - 93: Oo0Ooo % i11iIiiIii / i11iIiiIii . II111iiii % I11i
   self . address = int ( addr_str , 16 )
   if 13 - 13: O0 . i1IIi - OoooooooOO . oO0o
  elif ( self . is_geo_prefix ( ) ) :
   oO0o0oO0O = lisp_geo ( None )
   oO0o0oO0O . name = "geo-prefix-{}" . format ( oO0o0oO0O )
   oO0o0oO0O . parse_geo_string ( addr_str )
   self . address = oO0o0oO0O
  elif ( self . is_mac ( ) ) :
   addr_str = addr_str . replace ( "-" , "" )
   oOO = int ( addr_str , 16 )
   self . address = oOO
  elif ( self . is_e164 ( ) ) :
   addr_str = addr_str [ 1 : : ]
   oOO = int ( addr_str , 16 )
   self . address = oOO << 4
  elif ( self . is_dist_name ( ) ) :
   self . address = addr_str . replace ( "'" , "" )
   if 38 - 38: ooOoO0o . i1IIi / iII111i + I1IiiI - II111iiii
  self . mask_len = self . host_mask_len ( )
  if 21 - 21: i11iIiiIii + II111iiii - i1IIi / OoooooooOO * OOooOOo % Oo0Ooo
  if 59 - 59: Ii1I
 def store_prefix ( self , prefix_str ) :
  if ( self . is_geo_string ( prefix_str ) ) :
   iI11I = prefix_str . find ( "]" )
   iI1iiII1iii111 = len ( prefix_str [ iI11I + 1 : : ] ) * 8
  elif ( prefix_str . find ( "/" ) != - 1 ) :
   prefix_str , iI1iiII1iii111 = prefix_str . split ( "/" )
  else :
   iIi1IiI = prefix_str . find ( "'" )
   if ( iIi1IiI == - 1 ) : return
   OoO00 = prefix_str . find ( "'" , iIi1IiI + 1 )
   if ( OoO00 == - 1 ) : return
   iI1iiII1iii111 = len ( prefix_str [ iIi1IiI + 1 : OoO00 ] ) * 8
   if 77 - 77: I1ii11iIi11i * Ii1I * O0 * I1IiiI % OoO0O00 - iIii1I11I1II1
   if 6 - 6: i11iIiiIii . I11i - OoooooooOO
  self . string_to_afi ( prefix_str )
  self . store_address ( prefix_str )
  self . mask_len = int ( iI1iiII1iii111 )
  if 26 - 26: I1IiiI
  if 26 - 26: IiII . Ii1I / IiII - OoO0O00 % OoO0O00
 def zero_host_bits ( self ) :
  OoOo0Ooo0Oooo = ( 2 ** self . mask_len ) - 1
  iiIiII1IiiI1 = self . addr_length ( ) * 8 - self . mask_len
  OoOo0Ooo0Oooo <<= iiIiII1IiiI1
  self . address &= OoOo0Ooo0Oooo
  if 33 - 33: OoOoOO00 - I1IiiI + iII111i . iII111i
  if 68 - 68: OoO0O00 / OoO0O00 - I1IiiI + OoOoOO00
 def is_geo_string ( self , addr_str ) :
  iI11I = addr_str . find ( "]" )
  if ( iI11I != - 1 ) : addr_str = addr_str [ iI11I + 1 : : ]
  if 22 - 22: iIii1I11I1II1 . i1IIi . OOooOOo % Oo0Ooo - i1IIi
  oO0o0oO0O = addr_str . split ( "/" )
  if ( len ( oO0o0oO0O ) == 2 ) :
   if ( oO0o0oO0O [ 1 ] . isdigit ( ) == False ) : return ( False )
   if 78 - 78: I1IiiI / i1IIi % II111iiii % I1IiiI % Ii1I
  oO0o0oO0O = oO0o0oO0O [ 0 ]
  oO0o0oO0O = oO0o0oO0O . split ( "-" )
  IiIIi1IIii = len ( oO0o0oO0O )
  if ( IiIIi1IIii < 8 or IiIIi1IIii > 9 ) : return ( False )
  if 86 - 86: I1Ii111 % ooOoO0o + OoOoOO00 + II111iiii % I1Ii111 + i11iIiiIii
  for OO00o0O0Oo in range ( 0 , IiIIi1IIii ) :
   if ( OO00o0O0Oo == 3 ) :
    if ( oO0o0oO0O [ OO00o0O0Oo ] in [ "N" , "S" ] ) : continue
    return ( False )
    if 90 - 90: i11iIiiIii
   if ( OO00o0O0Oo == 7 ) :
    if ( oO0o0oO0O [ OO00o0O0Oo ] in [ "W" , "E" ] ) : continue
    return ( False )
    if 92 - 92: i1IIi
   if ( oO0o0oO0O [ OO00o0O0Oo ] . isdigit ( ) == False ) : return ( False )
   if 3 - 3: iIii1I11I1II1 . I1ii11iIi11i
  return ( True )
  if 97 - 97: O0
  if 82 - 82: OoooooooOO / I1Ii111 - ooOoO0o . I1Ii111
 def string_to_afi ( self , addr_str ) :
  if ( addr_str . count ( "'" ) == 2 ) :
   self . afi = LISP_AFI_NAME
   return
   if 41 - 41: I11i . I11i
  if ( addr_str . find ( ":" ) != - 1 ) : self . afi = LISP_AFI_IPV6
  elif ( addr_str . find ( "." ) != - 1 ) : self . afi = LISP_AFI_IPV4
  elif ( addr_str . find ( "+" ) != - 1 ) : self . afi = LISP_AFI_E164
  elif ( self . is_geo_string ( addr_str ) ) : self . afi = LISP_AFI_GEO_COORD
  elif ( addr_str . find ( "-" ) != - 1 ) : self . afi = LISP_AFI_MAC
  else : self . afi = LISP_AFI_NONE
  if 12 - 12: OoOoOO00 / I1IiiI
  if 4 - 4: Oo0Ooo * o0oOOo0O0Ooo
 def print_address ( self ) :
  o0o0O00 = self . print_address_no_iid ( )
  o0OOoOO = "[" + str ( self . instance_id )
  for Ii11 in self . iid_list : o0OOoOO += "," + str ( Ii11 )
  o0OOoOO += "]"
  o0o0O00 = "{}{}" . format ( o0OOoOO , o0o0O00 )
  return ( o0o0O00 )
  if 45 - 45: Ii1I % OOooOOo * Ii1I - iIii1I11I1II1
  if 18 - 18: I1Ii111 / Oo0Ooo % Ii1I + OoO0O00
 def print_address_no_iid ( self ) :
  if ( self . is_ipv4 ( ) ) :
   o0o0O00 = self . address
   o0Ooo0OoOo = o0o0O00 >> 24
   oOO0O = ( o0o0O00 >> 16 ) & 0xff
   II1o0OoO = ( o0o0O00 >> 8 ) & 0xff
   oo0o0O00O = o0o0O00 & 0xff
   return ( "{}.{}.{}.{}" . format ( o0Ooo0OoOo , oOO0O , II1o0OoO , oo0o0O00O ) )
  elif ( self . is_ipv6 ( ) ) :
   I1iiIiiii1111 = lisp_hex_string ( self . address ) . zfill ( 32 )
   I1iiIiiii1111 = binascii . unhexlify ( I1iiIiiii1111 )
   I1iiIiiii1111 = socket . inet_ntop ( socket . AF_INET6 , I1iiIiiii1111 )
   return ( "{}" . format ( I1iiIiiii1111 ) )
  elif ( self . is_geo_prefix ( ) ) :
   return ( "{}" . format ( self . address . print_geo ( ) ) )
  elif ( self . is_mac ( ) ) :
   I1iiIiiii1111 = lisp_hex_string ( self . address ) . zfill ( 12 )
   I1iiIiiii1111 = "{}-{}-{}" . format ( I1iiIiiii1111 [ 0 : 4 ] , I1iiIiiii1111 [ 4 : 8 ] ,
 I1iiIiiii1111 [ 8 : 12 ] )
   return ( "{}" . format ( I1iiIiiii1111 ) )
  elif ( self . is_e164 ( ) ) :
   I1iiIiiii1111 = lisp_hex_string ( self . address ) . zfill ( 15 )
   return ( "+{}" . format ( I1iiIiiii1111 ) )
  elif ( self . is_dist_name ( ) ) :
   return ( "'{}'" . format ( self . address ) )
  elif ( self . is_null ( ) ) :
   return ( "no-address" )
   if 61 - 61: iIii1I11I1II1 - I1ii11iIi11i
  return ( "unknown-afi:{}" . format ( self . afi ) )
  if 65 - 65: II111iiii - I1Ii111 * Oo0Ooo + ooOoO0o / OOooOOo . i11iIiiIii
  if 15 - 15: I1IiiI
 def print_prefix ( self ) :
  if ( self . is_ultimate_root ( ) ) : return ( "[*]" )
  if ( self . is_iid_range ( ) ) :
   if ( self . mask_len == 32 ) : return ( "[{}]" . format ( self . instance_id ) )
   IIi1Iii1 = self . instance_id + ( 2 ** ( 32 - self . mask_len ) - 1 )
   return ( "[{}-{}]" . format ( self . instance_id , IIi1Iii1 ) )
   if 4 - 4: oO0o % OoO0O00 + IiII + o0oOOo0O0Ooo
  o0o0O00 = self . print_address ( )
  if ( self . is_dist_name ( ) ) : return ( o0o0O00 )
  if ( self . is_geo_prefix ( ) ) : return ( o0o0O00 )
  if 82 - 82: O0 / I1Ii111 + OOooOOo . IiII + Ii1I
  iI11I = o0o0O00 . find ( "no-address" )
  if ( iI11I == - 1 ) :
   o0o0O00 = "{}/{}" . format ( o0o0O00 , str ( self . mask_len ) )
  else :
   o0o0O00 = o0o0O00 [ 0 : iI11I ]
   if 31 - 31: i1IIi * OoO0O00 - Ii1I + I11i
  return ( o0o0O00 )
  if 8 - 8: O0 + i1IIi . O0
  if 67 - 67: I1IiiI
 def print_prefix_no_iid ( self ) :
  o0o0O00 = self . print_address_no_iid ( )
  if ( self . is_dist_name ( ) ) : return ( o0o0O00 )
  if ( self . is_geo_prefix ( ) ) : return ( o0o0O00 )
  return ( "{}/{}" . format ( o0o0O00 , str ( self . mask_len ) ) )
  if 42 - 42: ooOoO0o - o0oOOo0O0Ooo % oO0o - ooOoO0o
  if 87 - 87: OoooooooOO / O0
 def print_prefix_url ( self ) :
  if ( self . is_ultimate_root ( ) ) : return ( "0--0" )
  o0o0O00 = self . print_address ( )
  iI11I = o0o0O00 . find ( "]" )
  if ( iI11I != - 1 ) : o0o0O00 = o0o0O00 [ iI11I + 1 : : ]
  if ( self . is_geo_prefix ( ) ) :
   o0o0O00 = o0o0O00 . replace ( "/" , "-" )
   return ( "{}-{}" . format ( self . instance_id , o0o0O00 ) )
   if 57 - 57: iIii1I11I1II1 / IiII + OoO0O00 * oO0o + Ii1I
  return ( "{}-{}-{}" . format ( self . instance_id , o0o0O00 , self . mask_len ) )
  if 76 - 76: i11iIiiIii . OOooOOo / I11i * oO0o % iIii1I11I1II1 . ooOoO0o
  if 75 - 75: O0 + I1IiiI
 def print_sg ( self , g ) :
  IiIIi1I1I11Ii = self . print_prefix ( )
  OOooOOoOoo = IiIIi1I1I11Ii . find ( "]" ) + 1
  g = g . print_prefix ( )
  o00OOO0 = g . find ( "]" ) + 1
  o0 = "[{}]({}, {})" . format ( self . instance_id , IiIIi1I1I11Ii [ OOooOOoOoo : : ] , g [ o00OOO0 : : ] )
  return ( o0 )
  if 2 - 2: o0oOOo0O0Ooo / O0
  if 29 - 29: OOooOOo . OOooOOo * iII111i % OoO0O00
 def hash_address ( self , addr ) :
  OooO0O0Ooo = self . address
  oO0O = addr . address
  if 66 - 66: Ii1I / OoO0O00 * i11iIiiIii * oO0o . iIii1I11I1II1
  if ( self . is_geo_prefix ( ) ) : OooO0O0Ooo = self . address . print_geo ( )
  if ( addr . is_geo_prefix ( ) ) : oO0O = addr . address . print_geo ( )
  if 16 - 16: Oo0Ooo % IiII * o0oOOo0O0Ooo % OoOoOO00 - OoooooooOO
  if ( type ( OooO0O0Ooo ) == str ) :
   OooO0O0Ooo = int ( binascii . hexlify ( OooO0O0Ooo [ 0 : 1 ] ) )
   if 61 - 61: i11iIiiIii - i1IIi + iIii1I11I1II1 * I1IiiI % OoOoOO00 . oO0o
  if ( type ( oO0O ) == str ) :
   oO0O = int ( binascii . hexlify ( oO0O [ 0 : 1 ] ) )
   if 24 - 24: iII111i . i1IIi * I1ii11iIi11i
  return ( OooO0O0Ooo ^ oO0O )
  if 1 - 1: oO0o / OoOoOO00 + I1IiiI
  if 47 - 47: O0 / OOooOOo . i1IIi / OoooooooOO . IiII
  if 34 - 34: OoO0O00 * II111iiii + I1Ii111
  if 20 - 20: iIii1I11I1II1 . OoO0O00 . II111iiii / Ii1I - iIii1I11I1II1 / OOooOOo
  if 20 - 20: i11iIiiIii * oO0o * ooOoO0o
  if 65 - 65: I1ii11iIi11i / Oo0Ooo / I1IiiI + IiII
 def is_more_specific ( self , prefix ) :
  if ( prefix . afi == LISP_AFI_ULTIMATE_ROOT ) : return ( True )
  if 71 - 71: OoO0O00 . I1Ii111 + OoooooooOO
  iI1iiII1iii111 = prefix . mask_len
  if ( prefix . afi == LISP_AFI_IID_RANGE ) :
   Ii1ii = 2 ** ( 32 - iI1iiII1iii111 )
   iI11IOOO0OO0oo0 = prefix . instance_id
   IIi1Iii1 = iI11IOOO0OO0oo0 + Ii1ii
   return ( self . instance_id in range ( iI11IOOO0OO0oo0 , IIi1Iii1 ) )
   if 50 - 50: i11iIiiIii + O0 + OOooOOo / oO0o % i11iIiiIii / I1IiiI
   if 98 - 98: I1Ii111 . i11iIiiIii * iIii1I11I1II1 + oO0o
  if ( self . instance_id != prefix . instance_id ) : return ( False )
  if ( self . afi != prefix . afi ) :
   if ( prefix . afi != LISP_AFI_NONE ) : return ( False )
   if 96 - 96: II111iiii - OOooOOo * I1Ii111 . oO0o
   if 21 - 21: OoooooooOO * I11i * IiII / II111iiii * II111iiii / Oo0Ooo
   if 42 - 42: oO0o % OOooOOo + oO0o + I1Ii111
   if 39 - 39: i11iIiiIii % OOooOOo % iIii1I11I1II1 / oO0o
   if 57 - 57: I1Ii111 % iII111i % oO0o . IiII + iIii1I11I1II1
  if ( self . is_binary ( ) == False ) :
   if ( prefix . afi == LISP_AFI_NONE ) : return ( True )
   if ( type ( self . address ) != type ( prefix . address ) ) : return ( False )
   o0o0O00 = self . address
   oooOo0O0000O = prefix . address
   if ( self . is_geo_prefix ( ) ) :
    o0o0O00 = self . address . print_geo ( )
    oooOo0O0000O = prefix . address . print_geo ( )
    if 59 - 59: Oo0Ooo % iII111i
   if ( len ( o0o0O00 ) < len ( oooOo0O0000O ) ) : return ( False )
   return ( o0o0O00 . find ( oooOo0O0000O ) == 0 )
   if 52 - 52: o0oOOo0O0Ooo . I1ii11iIi11i
   if 72 - 72: Ii1I
   if 76 - 76: O0 + oO0o * OoooooooOO - I11i
   if 96 - 96: I1Ii111 - Ii1I - i11iIiiIii
   if 57 - 57: IiII % i1IIi
  if ( self . mask_len < iI1iiII1iii111 ) : return ( False )
  if 74 - 74: iII111i % I11i * i11iIiiIii . i11iIiiIii + iIii1I11I1II1 * i1IIi
  iiIiII1IiiI1 = ( prefix . addr_length ( ) * 8 ) - iI1iiII1iii111
  OoOo0Ooo0Oooo = ( 2 ** iI1iiII1iii111 - 1 ) << iiIiII1IiiI1
  return ( ( self . address & OoOo0Ooo0Oooo ) == prefix . address )
  if 53 - 53: I1ii11iIi11i + IiII / OOooOOo . OoooooooOO - ooOoO0o
  if 47 - 47: i11iIiiIii
 def mask_address ( self , mask_len ) :
  iiIiII1IiiI1 = ( self . addr_length ( ) * 8 ) - mask_len
  OoOo0Ooo0Oooo = ( 2 ** mask_len - 1 ) << iiIiII1IiiI1
  self . address &= OoOo0Ooo0Oooo
  if 21 - 21: i1IIi - oO0o - Oo0Ooo
  if 11 - 11: i1IIi
 def is_exact_match ( self , prefix ) :
  if ( self . instance_id != prefix . instance_id ) : return ( False )
  O00o0Oo = self . print_prefix ( )
  o00ooOoo0000o = prefix . print_prefix ( ) if prefix else ""
  return ( O00o0Oo == o00ooOoo0000o )
  if 31 - 31: Oo0Ooo % OoooooooOO + OoooooooOO * o0oOOo0O0Ooo . I1IiiI
  if 68 - 68: iII111i - iIii1I11I1II1 - OoO0O00 - iII111i . O0 - i11iIiiIii
 def is_local ( self ) :
  if ( self . is_ipv4 ( ) ) :
   iiiii1i11IIii = lisp_myrlocs [ 0 ]
   if ( iiiii1i11IIii == None ) : return ( False )
   iiiii1i11IIii = iiiii1i11IIii . print_address_no_iid ( )
   return ( self . print_address_no_iid ( ) == iiiii1i11IIii )
   if 63 - 63: Ii1I * ooOoO0o / II111iiii . IiII / iII111i + I1ii11iIi11i
  if ( self . is_ipv6 ( ) ) :
   iiiii1i11IIii = lisp_myrlocs [ 1 ]
   if ( iiiii1i11IIii == None ) : return ( False )
   iiiii1i11IIii = iiiii1i11IIii . print_address_no_iid ( )
   return ( self . print_address_no_iid ( ) == iiiii1i11IIii )
   if 58 - 58: iIii1I11I1II1 * ooOoO0o - Ii1I - Ii1I . Oo0Ooo . i1IIi
  return ( False )
  if 69 - 69: iII111i / o0oOOo0O0Ooo - I1IiiI
  if 87 - 87: OoO0O00 - o0oOOo0O0Ooo . i11iIiiIii / I1IiiI * II111iiii % i11iIiiIii
 def store_iid_range ( self , iid , mask_len ) :
  if ( self . afi == LISP_AFI_NONE ) :
   if ( iid is 0 and mask_len is 0 ) : self . afi = LISP_AFI_ULTIMATE_ROOT
   else : self . afi = LISP_AFI_IID_RANGE
   if 48 - 48: IiII / II111iiii + iIii1I11I1II1 % Ii1I * I1IiiI / iII111i
  self . instance_id = iid
  self . mask_len = mask_len
  if 24 - 24: Ii1I . Ii1I + II111iiii
  if 44 - 44: OoOoOO00 / OoooooooOO % O0 * Ii1I * IiII
 def lcaf_length ( self , lcaf_type ) :
  o00OOo00 = self . addr_length ( ) + 2
  if ( lcaf_type == LISP_LCAF_AFI_LIST_TYPE ) : o00OOo00 += 4
  if ( lcaf_type == LISP_LCAF_INSTANCE_ID_TYPE ) : o00OOo00 += 4
  if ( lcaf_type == LISP_LCAF_ASN_TYPE ) : o00OOo00 += 4
  if ( lcaf_type == LISP_LCAF_APP_DATA_TYPE ) : o00OOo00 += 8
  if ( lcaf_type == LISP_LCAF_GEO_COORD_TYPE ) : o00OOo00 += 12
  if ( lcaf_type == LISP_LCAF_OPAQUE_TYPE ) : o00OOo00 += 0
  if ( lcaf_type == LISP_LCAF_NAT_TYPE ) : o00OOo00 += 4
  if ( lcaf_type == LISP_LCAF_NONCE_LOC_TYPE ) : o00OOo00 += 4
  if ( lcaf_type == LISP_LCAF_MCAST_INFO_TYPE ) : o00OOo00 = o00OOo00 * 2 + 8
  if ( lcaf_type == LISP_LCAF_ELP_TYPE ) : o00OOo00 += 0
  if ( lcaf_type == LISP_LCAF_SECURITY_TYPE ) : o00OOo00 += 6
  if ( lcaf_type == LISP_LCAF_SOURCE_DEST_TYPE ) : o00OOo00 += 4
  if ( lcaf_type == LISP_LCAF_RLE_TYPE ) : o00OOo00 += 4
  return ( o00OOo00 )
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
  if 39 - 39: Ii1I . II111iiii / I1IiiI
  if 44 - 44: Ii1I / Ii1I / OoO0O00 % ooOoO0o / I11i . I1ii11iIi11i
 def lcaf_encode_iid ( self ) :
  OOo000OOoOO = LISP_LCAF_INSTANCE_ID_TYPE
  iII = socket . htons ( self . lcaf_length ( OOo000OOoOO ) )
  o0OOoOO = self . instance_id
  oOo00Oo0o00oo = self . afi
  ii1I1I1iII = 0
  if ( oOo00Oo0o00oo < 0 ) :
   if ( self . afi == LISP_AFI_GEO_COORD ) :
    oOo00Oo0o00oo = LISP_AFI_LCAF
    ii1I1I1iII = 0
   else :
    oOo00Oo0o00oo = 0
    ii1I1I1iII = self . mask_len
    if 41 - 41: I1ii11iIi11i * ooOoO0o * I11i + O0 * O0 - O0
    if 81 - 81: I1Ii111 % OoO0O00 / O0
    if 55 - 55: i1IIi - I1Ii111 + I11i
  Ooo0OO000o0 = struct . pack ( "BBBBH" , 0 , 0 , OOo000OOoOO , ii1I1I1iII , iII )
  Ooo0OO000o0 += struct . pack ( "IH" , socket . htonl ( o0OOoOO ) , socket . htons ( oOo00Oo0o00oo ) )
  if ( oOo00Oo0o00oo == 0 ) : return ( Ooo0OO000o0 )
  if 39 - 39: OOooOOo / Oo0Ooo / I1IiiI + I1Ii111 % iII111i * iIii1I11I1II1
  if ( self . afi == LISP_AFI_GEO_COORD ) :
   Ooo0OO000o0 = Ooo0OO000o0 [ 0 : - 2 ]
   Ooo0OO000o0 += self . address . encode_geo ( )
   return ( Ooo0OO000o0 )
   if 94 - 94: o0oOOo0O0Ooo
   if 66 - 66: Ii1I - Oo0Ooo / oO0o + iII111i % IiII
  Ooo0OO000o0 += self . pack_address ( )
  return ( Ooo0OO000o0 )
  if 19 - 19: I1IiiI + I1IiiI + I1Ii111 % i1IIi * I1IiiI
  if 83 - 83: II111iiii - o0oOOo0O0Ooo . OoO0O00 . OOooOOo % o0oOOo0O0Ooo
 def lcaf_decode_iid ( self , packet ) :
  oOo0ooO0O0oo = "BBBBH"
  OO00OO = struct . calcsize ( oOo0ooO0O0oo )
  if ( len ( packet ) < OO00OO ) : return ( None )
  if 96 - 96: i1IIi % OoooooooOO * OOooOOo - Oo0Ooo + iIii1I11I1II1
  I1I111 , iI11Ii , OOo000OOoOO , O0IiIiiI1I , o00OOo00 = struct . unpack ( oOo0ooO0O0oo ,
 packet [ : OO00OO ] )
  packet = packet [ OO00OO : : ]
  if 56 - 56: OOooOOo * i11iIiiIii - i11iIiiIii * I1IiiI + iII111i . OoOoOO00
  if ( OOo000OOoOO != LISP_LCAF_INSTANCE_ID_TYPE ) : return ( None )
  if 49 - 49: I1ii11iIi11i % oO0o - I1Ii111 . I1ii11iIi11i % II111iiii
  oOo0ooO0O0oo = "IH"
  OO00OO = struct . calcsize ( oOo0ooO0O0oo )
  if ( len ( packet ) < OO00OO ) : return ( None )
  if 20 - 20: I1ii11iIi11i . iIii1I11I1II1 - Ii1I % OoO0O00
  o0OOoOO , oOo00Oo0o00oo = struct . unpack ( oOo0ooO0O0oo , packet [ : OO00OO ] )
  packet = packet [ OO00OO : : ]
  if 27 - 27: iIii1I11I1II1 / I1Ii111 - I11i . OoO0O00 + ooOoO0o
  o00OOo00 = socket . ntohs ( o00OOo00 )
  self . instance_id = socket . ntohl ( o0OOoOO )
  oOo00Oo0o00oo = socket . ntohs ( oOo00Oo0o00oo )
  self . afi = oOo00Oo0o00oo
  if ( O0IiIiiI1I != 0 and oOo00Oo0o00oo == 0 ) : self . mask_len = O0IiIiiI1I
  if ( oOo00Oo0o00oo == 0 ) :
   self . afi = LISP_AFI_IID_RANGE if O0IiIiiI1I else LISP_AFI_ULTIMATE_ROOT
   if 89 - 89: I1IiiI % I11i - OOooOOo
   if 71 - 71: OOooOOo % Oo0Ooo - o0oOOo0O0Ooo / I1Ii111 - O0 - oO0o
   if 10 - 10: I1IiiI
   if 17 - 17: i11iIiiIii % o0oOOo0O0Ooo . ooOoO0o
   if 34 - 34: OoooooooOO / iII111i / O0
  if ( oOo00Oo0o00oo == 0 ) : return ( packet )
  if 75 - 75: I11i % OOooOOo - OoO0O00 * I11i * IiII
  if 11 - 11: I1ii11iIi11i . O0 - iII111i * IiII . i1IIi . iII111i
  if 82 - 82: i1IIi * I11i * Ii1I - IiII . i11iIiiIii
  if 40 - 40: OOooOOo - OoooooooOO
  if ( self . is_dist_name ( ) ) :
   packet , self . address = lisp_decode_dist_name ( packet )
   self . mask_len = len ( self . address ) * 8
   return ( packet )
   if 36 - 36: i1IIi % OoOoOO00 - i1IIi
   if 5 - 5: I1IiiI . I1IiiI % II111iiii - I1Ii111
   if 97 - 97: I11i . ooOoO0o
   if 87 - 87: oO0o / iIii1I11I1II1 - I11i + OoooooooOO
   if 79 - 79: I1ii11iIi11i * IiII . I1ii11iIi11i
  if ( oOo00Oo0o00oo == LISP_AFI_LCAF ) :
   oOo0ooO0O0oo = "BBBBH"
   OO00OO = struct . calcsize ( oOo0ooO0O0oo )
   if ( len ( packet ) < OO00OO ) : return ( None )
   if 65 - 65: iII111i - Ii1I - II111iiii * O0 + I1ii11iIi11i . iIii1I11I1II1
   oO0OO0o0oo0o , oOo0ooo00OoO , OOo000OOoOO , ooooOo00O , ii1iII1i1iiIi = struct . unpack ( oOo0ooO0O0oo , packet [ : OO00OO ] )
   if 76 - 76: OoO0O00 * ooOoO0o
   if 32 - 32: O0 . oO0o * o0oOOo0O0Ooo . Ii1I + IiII
   if ( OOo000OOoOO != LISP_LCAF_GEO_COORD_TYPE ) : return ( None )
   if 98 - 98: iII111i . II111iiii % O0
   ii1iII1i1iiIi = socket . ntohs ( ii1iII1i1iiIi )
   packet = packet [ OO00OO : : ]
   if ( ii1iII1i1iiIi > len ( packet ) ) : return ( None )
   if 43 - 43: OOooOOo % I1Ii111 . IiII % OoO0O00 + I1Ii111 % OoooooooOO
   oO0o0oO0O = lisp_geo ( "" )
   self . afi = LISP_AFI_GEO_COORD
   self . address = oO0o0oO0O
   packet = oO0o0oO0O . decode_geo ( packet , ii1iII1i1iiIi , ooooOo00O )
   self . mask_len = self . host_mask_len ( )
   return ( packet )
   if 17 - 17: OoooooooOO - i1IIi * I11i
   if 33 - 33: i1IIi . Oo0Ooo + I11i
  iII = self . addr_length ( )
  if ( len ( packet ) < iII ) : return ( None )
  if 97 - 97: OOooOOo / IiII / ooOoO0o / OoooooooOO
  packet = self . unpack_address ( packet )
  return ( packet )
  if 78 - 78: I1Ii111 + I1Ii111
  if 43 - 43: I1Ii111 * o0oOOo0O0Ooo + i1IIi
  if 19 - 19: Ii1I
  if 51 - 51: oO0o
  if 57 - 57: i11iIiiIii - Oo0Ooo + I1Ii111 * OoO0O00
  if 35 - 35: o0oOOo0O0Ooo % II111iiii + O0
  if 70 - 70: I1ii11iIi11i . II111iiii
  if 54 - 54: OOooOOo
  if 67 - 67: I1IiiI . o0oOOo0O0Ooo / i1IIi * I1ii11iIi11i . Oo0Ooo + II111iiii
  if 63 - 63: OoOoOO00 - OoOoOO00
  if 31 - 31: I1ii11iIi11i % O0 - i11iIiiIii * o0oOOo0O0Ooo . ooOoO0o * ooOoO0o
  if 18 - 18: OoO0O00 - OoO0O00 . o0oOOo0O0Ooo
  if 80 - 80: I11i + I1Ii111 / I1IiiI * OOooOOo % iII111i
  if 48 - 48: iIii1I11I1II1 + i1IIi . I1IiiI % OoO0O00 - iIii1I11I1II1 / i1IIi
  if 14 - 14: IiII . I11i
  if 13 - 13: OoOoOO00 - I11i . OOooOOo % OoO0O00
  if 79 - 79: iII111i / Ii1I % i11iIiiIii . I1IiiI % OoO0O00 / i11iIiiIii
  if 100 - 100: OOooOOo + Oo0Ooo . iIii1I11I1II1 . ooOoO0o * Oo0Ooo
  if 16 - 16: Oo0Ooo % OoOoOO00 + I1Ii111 % I1Ii111
  if 12 - 12: I1Ii111 . Ii1I / iIii1I11I1II1 + i1IIi
  if 9 - 9: iIii1I11I1II1
 def lcaf_encode_sg ( self , group ) :
  OOo000OOoOO = LISP_LCAF_MCAST_INFO_TYPE
  o0OOoOO = socket . htonl ( self . instance_id )
  iII = socket . htons ( self . lcaf_length ( OOo000OOoOO ) )
  Ooo0OO000o0 = struct . pack ( "BBBBHIHBB" , 0 , 0 , OOo000OOoOO , 0 , iII , o0OOoOO ,
 0 , self . mask_len , group . mask_len )
  if 75 - 75: I11i . II111iiii * I1IiiI * IiII
  Ooo0OO000o0 += struct . pack ( "H" , socket . htons ( self . afi ) )
  Ooo0OO000o0 += self . pack_address ( )
  Ooo0OO000o0 += struct . pack ( "H" , socket . htons ( group . afi ) )
  Ooo0OO000o0 += group . pack_address ( )
  return ( Ooo0OO000o0 )
  if 36 - 36: OOooOOo / I1ii11iIi11i / oO0o / ooOoO0o / I11i
  if 7 - 7: OoO0O00 - I11i - o0oOOo0O0Ooo / o0oOOo0O0Ooo + i11iIiiIii
 def lcaf_decode_sg ( self , packet ) :
  oOo0ooO0O0oo = "BBBBHIHBB"
  OO00OO = struct . calcsize ( oOo0ooO0O0oo )
  if ( len ( packet ) < OO00OO ) : return ( [ None , None ] )
  if 28 - 28: OoOoOO00 % ooOoO0o . I1IiiI + II111iiii
  I1I111 , iI11Ii , OOo000OOoOO , O0ooO , o00OOo00 , o0OOoOO , iIIo0OOO , oOOooO0OO , OOOoo0O0 = struct . unpack ( oOo0ooO0O0oo , packet [ : OO00OO ] )
  if 25 - 25: o0oOOo0O0Ooo
  packet = packet [ OO00OO : : ]
  if 29 - 29: I1Ii111
  if ( OOo000OOoOO != LISP_LCAF_MCAST_INFO_TYPE ) : return ( [ None , None ] )
  if 58 - 58: i1IIi / I1ii11iIi11i
  self . instance_id = socket . ntohl ( o0OOoOO )
  o00OOo00 = socket . ntohs ( o00OOo00 ) - 8
  if 5 - 5: iIii1I11I1II1 % ooOoO0o . OOooOOo . ooOoO0o
  if 65 - 65: Oo0Ooo . I1IiiI / I11i * OOooOOo
  if 17 - 17: Ii1I . IiII
  if 46 - 46: O0 . OoooooooOO . ooOoO0o
  if 44 - 44: IiII / II111iiii - OoooooooOO
  oOo0ooO0O0oo = "H"
  OO00OO = struct . calcsize ( oOo0ooO0O0oo )
  if ( len ( packet ) < OO00OO ) : return ( [ None , None ] )
  if ( o00OOo00 < OO00OO ) : return ( [ None , None ] )
  if 47 - 47: OoO0O00 - ooOoO0o
  oOo00Oo0o00oo = struct . unpack ( oOo0ooO0O0oo , packet [ : OO00OO ] ) [ 0 ]
  packet = packet [ OO00OO : : ]
  o00OOo00 -= OO00OO
  self . afi = socket . ntohs ( oOo00Oo0o00oo )
  self . mask_len = oOOooO0OO
  iII = self . addr_length ( )
  if ( o00OOo00 < iII ) : return ( [ None , None ] )
  if 22 - 22: ooOoO0o % ooOoO0o . OOooOOo - II111iiii + OoO0O00
  packet = self . unpack_address ( packet )
  if ( packet == None ) : return ( [ None , None ] )
  if 44 - 44: I11i / o0oOOo0O0Ooo - OoO0O00 . Ii1I % oO0o - o0oOOo0O0Ooo
  o00OOo00 -= iII
  if 14 - 14: OOooOOo * IiII
  if 15 - 15: o0oOOo0O0Ooo + OoooooooOO - OOooOOo - o0oOOo0O0Ooo . iIii1I11I1II1 / Ii1I
  if 33 - 33: OoO0O00
  if 91 - 91: I11i % I11i % iII111i
  if 19 - 19: I11i / I11i + I1IiiI * OoO0O00 - iII111i . Oo0Ooo
  oOo0ooO0O0oo = "H"
  OO00OO = struct . calcsize ( oOo0ooO0O0oo )
  if ( len ( packet ) < OO00OO ) : return ( [ None , None ] )
  if ( o00OOo00 < OO00OO ) : return ( [ None , None ] )
  if 76 - 76: iII111i % OOooOOo / OoooooooOO . I1IiiI % OoO0O00 % i1IIi
  oOo00Oo0o00oo = struct . unpack ( oOo0ooO0O0oo , packet [ : OO00OO ] ) [ 0 ]
  packet = packet [ OO00OO : : ]
  o00OOo00 -= OO00OO
  ii1I1 = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  ii1I1 . afi = socket . ntohs ( oOo00Oo0o00oo )
  ii1I1 . mask_len = OOOoo0O0
  ii1I1 . instance_id = self . instance_id
  iII = self . addr_length ( )
  if ( o00OOo00 < iII ) : return ( [ None , None ] )
  if 95 - 95: Oo0Ooo - O0 / I1ii11iIi11i . I1IiiI / o0oOOo0O0Ooo % OoOoOO00
  packet = ii1I1 . unpack_address ( packet )
  if ( packet == None ) : return ( [ None , None ] )
  if 38 - 38: OoOoOO00 % OoooooooOO . oO0o - OoooooooOO + I11i
  return ( [ packet , ii1I1 ] )
  if 18 - 18: OoooooooOO + ooOoO0o * OoOoOO00 - OoO0O00
  if 42 - 42: oO0o % OoOoOO00 - oO0o + I11i / i11iIiiIii
 def lcaf_decode_eid ( self , packet ) :
  oOo0ooO0O0oo = "BBB"
  OO00OO = struct . calcsize ( oOo0ooO0O0oo )
  if ( len ( packet ) < OO00OO ) : return ( [ None , None ] )
  if 74 - 74: OoO0O00 - II111iiii - ooOoO0o % i1IIi
  if 42 - 42: i11iIiiIii / O0
  if 8 - 8: I1Ii111
  if 51 - 51: i11iIiiIii
  if 1 - 1: iIii1I11I1II1 . i1IIi . i11iIiiIii % I1ii11iIi11i
  O0ooO , oOo0ooo00OoO , OOo000OOoOO = struct . unpack ( oOo0ooO0O0oo ,
 packet [ : OO00OO ] )
  if 58 - 58: i11iIiiIii * i11iIiiIii - OoO0O00
  if ( OOo000OOoOO == LISP_LCAF_INSTANCE_ID_TYPE ) :
   return ( [ self . lcaf_decode_iid ( packet ) , None ] )
  elif ( OOo000OOoOO == LISP_LCAF_MCAST_INFO_TYPE ) :
   packet , ii1I1 = self . lcaf_decode_sg ( packet )
   return ( [ packet , ii1I1 ] )
  elif ( OOo000OOoOO == LISP_LCAF_GEO_COORD_TYPE ) :
   oOo0ooO0O0oo = "BBBBH"
   OO00OO = struct . calcsize ( oOo0ooO0O0oo )
   if ( len ( packet ) < OO00OO ) : return ( None )
   if 8 - 8: i11iIiiIii * OoOoOO00 . o0oOOo0O0Ooo
   oO0OO0o0oo0o , oOo0ooo00OoO , OOo000OOoOO , ooooOo00O , ii1iII1i1iiIi = struct . unpack ( oOo0ooO0O0oo , packet [ : OO00OO ] )
   if 27 - 27: I1ii11iIi11i + Ii1I % I1Ii111
   if 20 - 20: Oo0Ooo
   if ( OOo000OOoOO != LISP_LCAF_GEO_COORD_TYPE ) : return ( None )
   if 33 - 33: oO0o - OoOoOO00 - i11iIiiIii + I1Ii111 + iIii1I11I1II1
   ii1iII1i1iiIi = socket . ntohs ( ii1iII1i1iiIi )
   packet = packet [ OO00OO : : ]
   if ( ii1iII1i1iiIi > len ( packet ) ) : return ( None )
   if 2 - 2: OoooooooOO + IiII / iII111i . iIii1I11I1II1 * OoOoOO00
   oO0o0oO0O = lisp_geo ( "" )
   self . instance_id = 0
   self . afi = LISP_AFI_GEO_COORD
   self . address = oO0o0oO0O
   packet = oO0o0oO0O . decode_geo ( packet , ii1iII1i1iiIi , ooooOo00O )
   self . mask_len = self . host_mask_len ( )
   if 84 - 84: OOooOOo
  return ( [ packet , None ] )
  if 68 - 68: I1Ii111
  if 92 - 92: oO0o * Ii1I / OoO0O00 % II111iiii
  if 54 - 54: oO0o + I11i - OoO0O00
  if 86 - 86: OoooooooOO
  if 51 - 51: i11iIiiIii
  if 91 - 91: OOooOOo
class lisp_elp_node ( ) :
 def __init__ ( self ) :
  self . address = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . probe = False
  self . strict = False
  self . eid = False
  self . we_are_last = False
  if 22 - 22: OoooooooOO + OoOoOO00 - Ii1I . iII111i / OoooooooOO / I1IiiI
  if 73 - 73: i1IIi - Ii1I + oO0o * iIii1I11I1II1
 def copy_elp_node ( self ) :
  ii1iIiIIiIIii = lisp_elp_node ( )
  ii1iIiIIiIIii . copy_address ( self . address )
  ii1iIiIIiIIii . probe = self . probe
  ii1iIiIIiIIii . strict = self . strict
  ii1iIiIIiIIii . eid = self . eid
  ii1iIiIIiIIii . we_are_last = self . we_are_last
  return ( ii1iIiIIiIIii )
  if 100 - 100: i11iIiiIii / iIii1I11I1II1 + Oo0Ooo + OoO0O00 - iII111i
  if 8 - 8: i11iIiiIii . O0 + o0oOOo0O0Ooo * oO0o + II111iiii
  if 61 - 61: ooOoO0o / ooOoO0o
class lisp_elp ( ) :
 def __init__ ( self , name ) :
  self . elp_name = name
  self . elp_nodes = [ ]
  self . use_elp_node = None
  self . we_are_last = False
  if 51 - 51: iIii1I11I1II1 / oO0o * I1Ii111 + i1IIi
  if 96 - 96: Oo0Ooo + oO0o - Oo0Ooo - OoOoOO00 % OOooOOo . iIii1I11I1II1
 def copy_elp ( self ) :
  iI1ii1I1i = lisp_elp ( self . elp_name )
  iI1ii1I1i . use_elp_node = self . use_elp_node
  iI1ii1I1i . we_are_last = self . we_are_last
  for ii1iIiIIiIIii in self . elp_nodes :
   iI1ii1I1i . elp_nodes . append ( ii1iIiIIiIIii . copy_elp_node ( ) )
   if 93 - 93: iIii1I11I1II1 % OoooooooOO
  return ( iI1ii1I1i )
  if 6 - 6: II111iiii / oO0o - OOooOOo . O0 - o0oOOo0O0Ooo
  if 72 - 72: iIii1I11I1II1 / OoooooooOO * ooOoO0o / ooOoO0o % O0 + IiII
 def print_elp ( self , want_marker ) :
  II1iIiiI = ""
  for ii1iIiIIiIIii in self . elp_nodes :
   O0Oo = ""
   if ( want_marker ) :
    if ( ii1iIiIIiIIii == self . use_elp_node ) :
     O0Oo = "*"
    elif ( ii1iIiIIiIIii . we_are_last ) :
     O0Oo = "x"
     if 5 - 5: I1IiiI + iII111i % OoOoOO00
     if 19 - 19: i11iIiiIii . Oo0Ooo . OoOoOO00 - I1IiiI
   II1iIiiI += "{}{}({}{}{}), " . format ( O0Oo ,
 ii1iIiIIiIIii . address . print_address_no_iid ( ) ,
 "r" if ii1iIiIIiIIii . eid else "R" , "P" if ii1iIiIIiIIii . probe else "p" ,
 "S" if ii1iIiIIiIIii . strict else "s" )
   if 85 - 85: I11i - OoO0O00 % iIii1I11I1II1 . iII111i + ooOoO0o . Oo0Ooo
  return ( II1iIiiI [ 0 : - 2 ] if II1iIiiI != "" else "" )
  if 87 - 87: iII111i
  if 86 - 86: IiII - I11i
 def select_elp_node ( self ) :
  ooOoOo0 , oO0oOOOOOOoOO , O0OoO0o = lisp_myrlocs
  iI11I = None
  if 26 - 26: I1ii11iIi11i / Oo0Ooo
  for ii1iIiIIiIIii in self . elp_nodes :
   if ( ooOoOo0 and ii1iIiIIiIIii . address . is_exact_match ( ooOoOo0 ) ) :
    iI11I = self . elp_nodes . index ( ii1iIiIIiIIii )
    break
    if 28 - 28: OoO0O00 / I1ii11iIi11i % OOooOOo % I1IiiI + Ii1I
   if ( oO0oOOOOOOoOO and ii1iIiIIiIIii . address . is_exact_match ( oO0oOOOOOOoOO ) ) :
    iI11I = self . elp_nodes . index ( ii1iIiIIiIIii )
    break
    if 6 - 6: o0oOOo0O0Ooo % OOooOOo
    if 71 - 71: oO0o + II111iiii * O0 / i11iIiiIii * o0oOOo0O0Ooo
    if 85 - 85: o0oOOo0O0Ooo - I1Ii111
    if 90 - 90: OoO0O00 * I1Ii111 * iII111i * Ii1I + OoOoOO00 / iII111i
    if 63 - 63: o0oOOo0O0Ooo * I1Ii111
    if 9 - 9: ooOoO0o . O0 + II111iiii . OoooooooOO
    if 97 - 97: O0 / OoOoOO00 / ooOoO0o
  if ( iI11I == None ) :
   self . use_elp_node = self . elp_nodes [ 0 ]
   ii1iIiIIiIIii . we_are_last = False
   return
   if 11 - 11: II111iiii . i11iIiiIii - Ii1I . IiII
   if 10 - 10: OOooOOo * OoooooooOO
   if 12 - 12: II111iiii - O0 . i1IIi % oO0o % OoooooooOO
   if 36 - 36: IiII * OoOoOO00 - iIii1I11I1II1 + II111iiii
   if 65 - 65: I1IiiI * I11i . I1Ii111 % I1ii11iIi11i + O0
   if 91 - 91: OoooooooOO % I1Ii111 * OoO0O00 - OoOoOO00
  if ( self . elp_nodes [ - 1 ] == self . elp_nodes [ iI11I ] ) :
   self . use_elp_node = None
   ii1iIiIIiIIii . we_are_last = True
   return
   if 5 - 5: iIii1I11I1II1 * I11i - oO0o % oO0o % o0oOOo0O0Ooo . i1IIi
   if 95 - 95: Oo0Ooo * I1ii11iIi11i + iII111i - o0oOOo0O0Ooo - Oo0Ooo . OoO0O00
   if 62 - 62: I11i
   if 58 - 58: I11i . OoOoOO00 + iII111i . iII111i
   if 43 - 43: I1Ii111 + I1Ii111 % Oo0Ooo % OoO0O00 - ooOoO0o
  self . use_elp_node = self . elp_nodes [ iI11I + 1 ]
  return
  if 61 - 61: OoOoOO00 + Ii1I % i11iIiiIii - I1IiiI * OoO0O00 % iIii1I11I1II1
  if 66 - 66: iII111i + i1IIi
  if 24 - 24: O0 / OoooooooOO - OoOoOO00
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
  if 51 - 51: OoO0O00 + o0oOOo0O0Ooo - II111iiii * I11i + Ii1I
  if 16 - 16: I1Ii111 * i1IIi . I1IiiI . OOooOOo % Ii1I - o0oOOo0O0Ooo
 def copy_geo ( self ) :
  oO0o0oO0O = lisp_geo ( self . geo_name )
  oO0o0oO0O . latitude = self . latitude
  oO0o0oO0O . lat_mins = self . lat_mins
  oO0o0oO0O . lat_secs = self . lat_secs
  oO0o0oO0O . longitude = self . longitude
  oO0o0oO0O . long_mins = self . long_mins
  oO0o0oO0O . long_secs = self . long_secs
  oO0o0oO0O . altitude = self . altitude
  oO0o0oO0O . radius = self . radius
  return ( oO0o0oO0O )
  if 89 - 89: Ii1I * I1ii11iIi11i * I1IiiI % iII111i % Ii1I + O0
  if 53 - 53: i11iIiiIii % I1ii11iIi11i
 def no_geo_altitude ( self ) :
  return ( self . altitude == - 1 )
  if 59 - 59: OOooOOo
  if 61 - 61: OoooooooOO + O0 - i1IIi % oO0o / I1ii11iIi11i
 def parse_geo_string ( self , geo_str ) :
  iI11I = geo_str . find ( "]" )
  if ( iI11I != - 1 ) : geo_str = geo_str [ iI11I + 1 : : ]
  if 50 - 50: oO0o + II111iiii * OoOoOO00 % OoO0O00 . II111iiii % o0oOOo0O0Ooo
  if 32 - 32: i1IIi / Ii1I + i11iIiiIii % oO0o
  if 11 - 11: Ii1I - ooOoO0o % i11iIiiIii / OoooooooOO - O0 - IiII
  if 25 - 25: IiII + O0 + oO0o % iIii1I11I1II1 - II111iiii . I1IiiI
  if 62 - 62: IiII . O0 + oO0o - ooOoO0o * iIii1I11I1II1
  if ( geo_str . find ( "/" ) != - 1 ) :
   geo_str , iIii1I1I = geo_str . split ( "/" )
   self . radius = int ( iIii1I1I )
   if 48 - 48: OoOoOO00 * I11i
   if 92 - 92: I1IiiI * I1IiiI
  geo_str = geo_str . split ( "-" )
  if ( len ( geo_str ) < 8 ) : return ( False )
  if 9 - 9: IiII * I1IiiI * OoO0O00 - I1IiiI * I1IiiI - OoO0O00
  IiIiIi = geo_str [ 0 : 4 ]
  ii11III = geo_str [ 4 : 8 ]
  if 47 - 47: oO0o - oO0o * OoOoOO00 % iII111i - i1IIi
  if 7 - 7: I1Ii111 . I1Ii111 / I1ii11iIi11i / I1IiiI % I1IiiI
  if 3 - 3: II111iiii
  if 97 - 97: o0oOOo0O0Ooo . IiII . I1ii11iIi11i * II111iiii - I11i
  if ( len ( geo_str ) > 8 ) : self . altitude = int ( geo_str [ 8 ] )
  if 37 - 37: I1Ii111 / i11iIiiIii . I1ii11iIi11i - OoO0O00 * ooOoO0o
  if 91 - 91: ooOoO0o % II111iiii
  if 48 - 48: oO0o
  if 10 - 10: Oo0Ooo - O0 * i1IIi + I11i - OoooooooOO
  self . latitude = int ( IiIiIi [ 0 ] )
  self . lat_mins = int ( IiIiIi [ 1 ] )
  self . lat_secs = int ( IiIiIi [ 2 ] )
  if ( IiIiIi [ 3 ] == "N" ) : self . latitude = - self . latitude
  if 25 - 25: I1IiiI + iIii1I11I1II1 * Oo0Ooo - iIii1I11I1II1 % IiII * oO0o
  if 71 - 71: iIii1I11I1II1 % I1Ii111 % IiII / IiII + iIii1I11I1II1 % i1IIi
  if 93 - 93: Oo0Ooo / I1ii11iIi11i + Oo0Ooo + OOooOOo
  if 58 - 58: oO0o
  self . longitude = int ( ii11III [ 0 ] )
  self . long_mins = int ( ii11III [ 1 ] )
  self . long_secs = int ( ii11III [ 2 ] )
  if ( ii11III [ 3 ] == "E" ) : self . longitude = - self . longitude
  return ( True )
  if 9 - 9: I1Ii111 - i1IIi . ooOoO0o
  if 33 - 33: I11i
 def print_geo ( self ) :
  iIi111 = "N" if self . latitude < 0 else "S"
  OO0000Oo0O = "E" if self . longitude < 0 else "W"
  if 10 - 10: o0oOOo0O0Ooo - OoooooooOO - iIii1I11I1II1 - o0oOOo0O0Ooo / iII111i
  oo00OoO00o = "{}-{}-{}-{}-{}-{}-{}-{}" . format ( abs ( self . latitude ) ,
 self . lat_mins , self . lat_secs , iIi111 , abs ( self . longitude ) ,
 self . long_mins , self . long_secs , OO0000Oo0O )
  if 10 - 10: OoOoOO00 . i1IIi
  if ( self . no_geo_altitude ( ) == False ) :
   oo00OoO00o += "-" + str ( self . altitude )
   if 44 - 44: OOooOOo - OOooOOo * IiII - iIii1I11I1II1
   if 72 - 72: iIii1I11I1II1 . OoooooooOO
   if 44 - 44: I11i * I11i + OoooooooOO
   if 26 - 26: I1Ii111 * Ii1I
   if 95 - 95: oO0o + OoOoOO00 / OoO0O00 % I1IiiI
  if ( self . radius != 0 ) : oo00OoO00o += "/{}" . format ( self . radius )
  return ( oo00OoO00o )
  if 28 - 28: I1IiiI
  if 59 - 59: OOooOOo . I1IiiI / i1IIi / II111iiii . II111iiii
 def geo_url ( self ) :
  oo0O00OOO0 = os . getenv ( "LISP_GEO_ZOOM_LEVEL" )
  oo0O00OOO0 = "10" if ( oo0O00OOO0 == "" or oo0O00OOO0 . isdigit ( ) == False ) else oo0O00OOO0
  iiiI1II1 , iii1 = self . dms_to_decimal ( )
  ii1iIIiii = ( "http://maps.googleapis.com/maps/api/staticmap?center={},{}" + "&markers=color:blue%7Clabel:lisp%7C{},{}" + "&zoom={}&size=1024x1024&sensor=false" ) . format ( iiiI1II1 , iii1 , iiiI1II1 , iii1 ,
  # ooOoO0o % I1IiiI / iIii1I11I1II1 + O0
  # o0oOOo0O0Ooo * OoOoOO00 . i11iIiiIii - IiII - i11iIiiIii / iII111i
 oo0O00OOO0 )
  return ( ii1iIIiii )
  if 36 - 36: I11i . Ii1I - I1IiiI / II111iiii
  if 57 - 57: OoOoOO00 % Ii1I
 def print_geo_url ( self ) :
  oO0o0oO0O = self . print_geo ( )
  if ( self . radius == 0 ) :
   ii1iIIiii = self . geo_url ( )
   OO0o0o0oo = "<a href='{}'>{}</a>" . format ( ii1iIIiii , oO0o0oO0O )
  else :
   ii1iIIiii = oO0o0oO0O . replace ( "/" , "-" )
   OO0o0o0oo = "<a href='/lisp/geo-map/{}'>{}</a>" . format ( ii1iIIiii , oO0o0oO0O )
   if 14 - 14: OoooooooOO - i11iIiiIii . OoooooooOO % I1ii11iIi11i + iII111i % iII111i
  return ( OO0o0o0oo )
  if 58 - 58: I1Ii111 % Ii1I / I11i % i1IIi / OoO0O00
  if 4 - 4: i11iIiiIii / i11iIiiIii
 def dms_to_decimal ( self ) :
  oooO0 , oO0OO0 , IiI1i1II = self . latitude , self . lat_mins , self . lat_secs
  I11iii1i1 = float ( abs ( oooO0 ) )
  I11iii1i1 += float ( oO0OO0 * 60 + IiI1i1II ) / 3600
  if ( oooO0 > 0 ) : I11iii1i1 = - I11iii1i1
  o00oo = I11iii1i1
  if 35 - 35: i11iIiiIii - I1IiiI . o0oOOo0O0Ooo - i1IIi - Ii1I
  oooO0 , oO0OO0 , IiI1i1II = self . longitude , self . long_mins , self . long_secs
  I11iii1i1 = float ( abs ( oooO0 ) )
  I11iii1i1 += float ( oO0OO0 * 60 + IiI1i1II ) / 3600
  if ( oooO0 > 0 ) : I11iii1i1 = - I11iii1i1
  O0OOOoo0Oo000 = I11iii1i1
  return ( ( o00oo , O0OOOoo0Oo000 ) )
  if 90 - 90: I1ii11iIi11i * iII111i * I1ii11iIi11i . IiII + OoOoOO00
  if 5 - 5: O0 - I11i - Oo0Ooo . iII111i / oO0o * iIii1I11I1II1
 def get_distance ( self , geo_point ) :
  o00ooOOo00O0Oo = self . dms_to_decimal ( )
  i1i = geo_point . dms_to_decimal ( )
  OOOo0oo0oOo = vincenty ( o00ooOOo00O0Oo , i1i )
  return ( OOOo0oo0oOo . km )
  if 21 - 21: I1IiiI + i1IIi . i1IIi
  if 46 - 46: I11i * OOooOOo
 def point_in_circle ( self , geo_point ) :
  oo0iiiIi = self . get_distance ( geo_point )
  return ( oo0iiiIi <= self . radius )
  if 92 - 92: OOooOOo / OOooOOo - I1ii11iIi11i . OOooOOo - IiII
  if 7 - 7: II111iiii . I1ii11iIi11i / I1Ii111
 def encode_geo ( self ) :
  iIi11 = socket . htons ( LISP_AFI_LCAF )
  IiIIi1IIii = socket . htons ( 20 + 2 )
  oOo0ooo00OoO = 0
  if 5 - 5: Oo0Ooo / o0oOOo0O0Ooo % i11iIiiIii - ooOoO0o
  iiiI1II1 = abs ( self . latitude )
  o0iIII1i11i = ( ( self . lat_mins * 60 ) + self . lat_secs ) * 1000
  if ( self . latitude < 0 ) : oOo0ooo00OoO |= 0x40
  if 48 - 48: Ii1I / Ii1I / i1IIi * I1IiiI . iII111i + I1ii11iIi11i
  iii1 = abs ( self . longitude )
  ooiIIi11I1 = ( ( self . long_mins * 60 ) + self . long_secs ) * 1000
  if ( self . longitude < 0 ) : oOo0ooo00OoO |= 0x20
  if 3 - 3: OoOoOO00 / Oo0Ooo - Oo0Ooo
  OO0 = 0
  if ( self . no_geo_altitude ( ) == False ) :
   OO0 = socket . htonl ( self . altitude )
   oOo0ooo00OoO |= 0x10
   if 44 - 44: IiII / II111iiii * o0oOOo0O0Ooo + Ii1I % OoO0O00
  iIii1I1I = socket . htons ( self . radius )
  if ( iIii1I1I != 0 ) : oOo0ooo00OoO |= 0x06
  if 55 - 55: oO0o . I11i % ooOoO0o * OOooOOo % OoooooooOO
  iiI1i1i1i = struct . pack ( "HBBBBH" , iIi11 , 0 , 0 , LISP_LCAF_GEO_COORD_TYPE ,
 0 , IiIIi1IIii )
  iiI1i1i1i += struct . pack ( "BBHBBHBBHIHHH" , oOo0ooo00OoO , 0 , 0 , iiiI1II1 , o0iIII1i11i >> 16 ,
 socket . htons ( o0iIII1i11i & 0x0ffff ) , iii1 , ooiIIi11I1 >> 16 ,
 socket . htons ( ooiIIi11I1 & 0xffff ) , OO0 , iIii1I1I , 0 , 0 )
  if 34 - 34: oO0o . oO0o % I11i . OoOoOO00
  return ( iiI1i1i1i )
  if 10 - 10: i11iIiiIii . IiII * I1IiiI
  if 27 - 27: Ii1I % II111iiii . OOooOOo
 def decode_geo ( self , packet , lcaf_len , radius_hi ) :
  oOo0ooO0O0oo = "BBHBBHBBHIHHH"
  OO00OO = struct . calcsize ( oOo0ooO0O0oo )
  if ( lcaf_len < OO00OO ) : return ( None )
  if 14 - 14: IiII - O0 / II111iiii + I1IiiI + I1ii11iIi11i * ooOoO0o
  oOo0ooo00OoO , IIo0Oo0OooOoOo , oOo0O000000 , iiiI1II1 , o0O00O , o0iIII1i11i , iii1 , I11I , ooiIIi11I1 , OO0 , iIii1I1I , oOOooOoOOOo0O , oOo00Oo0o00oo = struct . unpack ( oOo0ooO0O0oo ,
  # iIii1I11I1II1 . iIii1I11I1II1 . Ii1I . i1IIi + I1Ii111
 packet [ : OO00OO ] )
  if 65 - 65: i11iIiiIii * oO0o + OoO0O00
  if 86 - 86: iII111i - Ii1I / OoO0O00
  if 19 - 19: iIii1I11I1II1 / iII111i + OOooOOo . ooOoO0o
  if 85 - 85: i1IIi
  oOo00Oo0o00oo = socket . ntohs ( oOo00Oo0o00oo )
  if ( oOo00Oo0o00oo == LISP_AFI_LCAF ) : return ( None )
  if 78 - 78: oO0o
  if ( oOo0ooo00OoO & 0x40 ) : iiiI1II1 = - iiiI1II1
  self . latitude = iiiI1II1
  i1i11I1iII11 = ( ( o0O00O << 16 ) | socket . ntohs ( o0iIII1i11i ) ) / 1000
  self . lat_mins = i1i11I1iII11 / 60
  self . lat_secs = i1i11I1iII11 % 60
  if 38 - 38: I1IiiI % II111iiii
  if ( oOo0ooo00OoO & 0x20 ) : iii1 = - iii1
  self . longitude = iii1
  o00OOo = ( ( I11I << 16 ) | socket . ntohs ( ooiIIi11I1 ) ) / 1000
  self . long_mins = o00OOo / 60
  self . long_secs = o00OOo % 60
  if 11 - 11: I1Ii111 - Oo0Ooo / iIii1I11I1II1 - OoooooooOO
  self . altitude = socket . ntohl ( OO0 ) if ( oOo0ooo00OoO & 0x10 ) else - 1
  iIii1I1I = socket . ntohs ( iIii1I1I )
  self . radius = iIii1I1I if ( oOo0ooo00OoO & 0x02 ) else iIii1I1I * 1000
  if 71 - 71: Oo0Ooo + Ii1I - OoooooooOO + I11i - iIii1I11I1II1 / O0
  self . geo_name = None
  packet = packet [ OO00OO : : ]
  if 76 - 76: i11iIiiIii % o0oOOo0O0Ooo . O0 * I11i
  if ( oOo00Oo0o00oo != 0 ) :
   self . rloc . afi = oOo00Oo0o00oo
   packet = self . rloc . unpack_address ( packet )
   self . rloc . mask_len = self . rloc . host_mask_len ( )
   if 90 - 90: II111iiii + OOooOOo % I1Ii111 * iIii1I11I1II1 % iIii1I11I1II1
  return ( packet )
  if 55 - 55: II111iiii % O0 * O0 - II111iiii * I1IiiI % Oo0Ooo
  if 48 - 48: I1ii11iIi11i + OoooooooOO % i1IIi
  if 46 - 46: OoOoOO00
  if 75 - 75: I1IiiI
  if 37 - 37: iIii1I11I1II1 % OoO0O00 * ooOoO0o + I11i % ooOoO0o / i11iIiiIii
  if 14 - 14: i1IIi / ooOoO0o
class lisp_rle_node ( ) :
 def __init__ ( self ) :
  self . address = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . level = 0
  self . translated_port = 0
  self . rloc_name = None
  if 10 - 10: ooOoO0o / OoooooooOO - ooOoO0o % O0 + oO0o - oO0o
  if 16 - 16: O0
 def copy_rle_node ( self ) :
  OOoo0Oo00 = lisp_rle_node ( )
  OOoo0Oo00 . address . copy_address ( self . address )
  OOoo0Oo00 . level = self . level
  OOoo0Oo00 . translated_port = self . translated_port
  OOoo0Oo00 . rloc_name = self . rloc_name
  return ( OOoo0Oo00 )
  if 14 - 14: Ii1I . Ii1I . OOooOOo - O0 / OoO0O00 % II111iiii
  if 5 - 5: iIii1I11I1II1 % OoOoOO00 % OOooOOo % O0 * oO0o . iIii1I11I1II1
 def store_translated_rloc ( self , rloc , port ) :
  self . address . copy_address ( rloc )
  self . translated_port = port
  if 96 - 96: i11iIiiIii + oO0o / I1ii11iIi11i . IiII % o0oOOo0O0Ooo
  if 41 - 41: o0oOOo0O0Ooo . i1IIi - OOooOOo
 def get_encap_keys ( self ) :
  o00o = "4341" if self . translated_port == 0 else str ( self . translated_port )
  if 19 - 19: o0oOOo0O0Ooo % I1Ii111 % I11i
  I1iiIiiii1111 = self . address . print_address_no_iid ( ) + ":" + o00o
  if 1 - 1: I1IiiI / o0oOOo0O0Ooo - I1Ii111
  try :
   o00OO0o0 = lisp_crypto_keys_by_rloc_encap [ I1iiIiiii1111 ]
   if ( o00OO0o0 [ 1 ] ) : return ( o00OO0o0 [ 1 ] . encrypt_key , o00OO0o0 [ 1 ] . icv_key )
   return ( None , None )
  except :
   return ( None , None )
   if 50 - 50: I11i - OoOoOO00 + I1IiiI % Oo0Ooo / OoooooooOO - I1ii11iIi11i
   if 26 - 26: IiII . Ii1I
   if 35 - 35: I1ii11iIi11i + OOooOOo
   if 88 - 88: O0
class lisp_rle ( ) :
 def __init__ ( self , name ) :
  self . rle_name = name
  self . rle_nodes = [ ]
  self . rle_forwarding_list = [ ]
  if 4 - 4: OoOoOO00 % iIii1I11I1II1 % OoooooooOO . oO0o
  if 27 - 27: II111iiii - OoOoOO00
 def copy_rle ( self ) :
  iiiI1i1111II = lisp_rle ( self . rle_name )
  for OOoo0Oo00 in self . rle_nodes :
   iiiI1i1111II . rle_nodes . append ( OOoo0Oo00 . copy_rle_node ( ) )
   if 81 - 81: o0oOOo0O0Ooo - Oo0Ooo % IiII - ooOoO0o / O0
  iiiI1i1111II . build_forwarding_list ( )
  return ( iiiI1i1111II )
  if 27 - 27: Oo0Ooo
  if 15 - 15: iIii1I11I1II1 . OoOoOO00 % Ii1I / i1IIi . o0oOOo0O0Ooo
 def print_rle ( self , html ) :
  O0O00OOOO = ""
  for OOoo0Oo00 in self . rle_nodes :
   o00o = OOoo0Oo00 . translated_port
   Ii1iIiI1I = blue ( OOoo0Oo00 . rloc_name , html ) if OOoo0Oo00 . rloc_name != None else ""
   if 15 - 15: iIii1I11I1II1 - OoooooooOO / ooOoO0o
   I1iiIiiii1111 = OOoo0Oo00 . address . print_address_no_iid ( )
   if ( OOoo0Oo00 . address . is_local ( ) ) : I1iiIiiii1111 = red ( I1iiIiiii1111 , html )
   O0O00OOOO += "{}{}(L{}){}, " . format ( I1iiIiiii1111 , "" if o00o == 0 else "-" + str ( o00o ) , OOoo0Oo00 . level ,
   # OoO0O00 % i1IIi * ooOoO0o * i11iIiiIii + IiII
 "" if OOoo0Oo00 . rloc_name == None else Ii1iIiI1I )
   if 62 - 62: Oo0Ooo + O0
  return ( O0O00OOOO [ 0 : - 2 ] if O0O00OOOO != "" else "" )
  if 48 - 48: I1ii11iIi11i * O0 % oO0o - o0oOOo0O0Ooo * I1Ii111 . I1ii11iIi11i
  if 9 - 9: I1Ii111 / OoO0O00 / I1IiiI - I1IiiI - i11iIiiIii . o0oOOo0O0Ooo
 def build_forwarding_list ( self ) :
  iI1iiiIii = - 1
  for OOoo0Oo00 in self . rle_nodes :
   if ( iI1iiiIii == - 1 ) :
    if ( OOoo0Oo00 . address . is_local ( ) ) : iI1iiiIii = OOoo0Oo00 . level
   else :
    if ( OOoo0Oo00 . level > iI1iiiIii ) : break
    if 35 - 35: iIii1I11I1II1 / I1IiiI * oO0o % OoOoOO00 . I1Ii111
    if 76 - 76: IiII % i1IIi / iIii1I11I1II1 - II111iiii * IiII + ooOoO0o
  iI1iiiIii = 0 if iI1iiiIii == - 1 else OOoo0Oo00 . level
  if 9 - 9: oO0o / OOooOOo + II111iiii . i1IIi % I1IiiI / I1IiiI
  self . rle_forwarding_list = [ ]
  for OOoo0Oo00 in self . rle_nodes :
   if ( OOoo0Oo00 . level == iI1iiiIii or ( iI1iiiIii == 0 and
 OOoo0Oo00 . level == 128 ) ) :
    if ( lisp_i_am_rtr == False and OOoo0Oo00 . address . is_local ( ) ) :
     I1iiIiiii1111 = OOoo0Oo00 . address . print_address_no_iid ( )
     lprint ( "Exclude local RLE RLOC {}" . format ( I1iiIiiii1111 ) )
     continue
     if 1 - 1: iIii1I11I1II1
    self . rle_forwarding_list . append ( OOoo0Oo00 )
    if 8 - 8: o0oOOo0O0Ooo % II111iiii * O0 . ooOoO0o
    if 96 - 96: I1ii11iIi11i / I11i - I1ii11iIi11i . I1Ii111 . i11iIiiIii . I11i
    if 93 - 93: OoO0O00 % I1ii11iIi11i * Ii1I . OoO0O00 % OOooOOo - OoooooooOO
    if 17 - 17: O0 + OOooOOo * ooOoO0o - i1IIi + OOooOOo
    if 30 - 30: OOooOOo / I1ii11iIi11i - iIii1I11I1II1 % i1IIi
class lisp_json ( ) :
 def __init__ ( self , name , string ) :
  self . json_name = name
  self . json_string = string
  if 34 - 34: I1IiiI . II111iiii
  if 100 - 100: OoO0O00 / O0 / OoOoOO00
 def add ( self ) :
  self . delete ( )
  lisp_json_list [ self . json_name ] = self
  if 33 - 33: i1IIi / o0oOOo0O0Ooo . OoooooooOO
  if 8 - 8: I1IiiI * OOooOOo * IiII / I1IiiI + i1IIi
 def delete ( self ) :
  if ( lisp_json_list . has_key ( self . json_name ) ) :
   del ( lisp_json_list [ self . json_name ] )
   lisp_json_list [ self . json_name ] = None
   if 11 - 11: I11i * Ii1I * I1IiiI - I1IiiI % OoooooooOO
   if 83 - 83: i11iIiiIii % iII111i * O0 % OoooooooOO
   if 99 - 99: I1ii11iIi11i % I1ii11iIi11i * iII111i % oO0o
 def print_json ( self , html ) :
  OOOooO = self . json_string
  i1iI1II1i1Ii1 = "***"
  if ( html ) : i1iI1II1i1Ii1 = red ( i1iI1II1i1Ii1 , html )
  IiI11iii1ii1 = i1iI1II1i1Ii1 + self . json_string + i1iI1II1i1Ii1
  if ( self . valid_json ( ) ) : return ( OOOooO )
  return ( IiI11iii1ii1 )
  if 10 - 10: i1IIi * OoOoOO00 + I1Ii111 . IiII % i11iIiiIii
  if 98 - 98: I1IiiI - oO0o / i11iIiiIii % I1ii11iIi11i * oO0o * OoO0O00
 def valid_json ( self ) :
  try :
   json . loads ( self . json_string )
  except :
   return ( False )
   if 74 - 74: I1Ii111 . I1ii11iIi11i - Ii1I * i11iIiiIii
  return ( True )
  if 36 - 36: II111iiii * Ii1I
  if 53 - 53: Ii1I / iIii1I11I1II1 + o0oOOo0O0Ooo . Ii1I
  if 79 - 79: Ii1I % O0 * OOooOOo
  if 41 - 41: I1ii11iIi11i . OoooooooOO * I1ii11iIi11i - oO0o
  if 40 - 40: I1IiiI % OoO0O00 + i11iIiiIii / oO0o
  if 98 - 98: oO0o + iIii1I11I1II1 . ooOoO0o / I1ii11iIi11i
class lisp_stats ( ) :
 def __init__ ( self ) :
  self . packet_count = 0
  self . byte_count = 0
  self . last_rate_check = 0
  self . last_packet_count = 0
  self . last_byte_count = 0
  self . last_increment = None
  if 77 - 77: OoOoOO00 / Oo0Ooo * OoOoOO00 % I1IiiI . II111iiii % OoO0O00
  if 38 - 38: iII111i - OoO0O00 / i1IIi + ooOoO0o . ooOoO0o . iII111i
 def increment ( self , octets ) :
  self . packet_count += 1
  self . byte_count += octets
  self . last_increment = lisp_get_timestamp ( )
  if 37 - 37: iIii1I11I1II1 * OoOoOO00 . OoOoOO00 + OoooooooOO + OoO0O00
  if 25 - 25: I1IiiI / IiII . OOooOOo . I1ii11iIi11i % i1IIi
 def recent_packet_sec ( self ) :
  if ( self . last_increment == None ) : return ( False )
  i11IiIIi11I = time . time ( ) - self . last_increment
  return ( i11IiIIi11I <= 1 )
  if 12 - 12: O0 % O0
  if 9 - 9: O0 . I1IiiI + I1ii11iIi11i / OOooOOo * I1ii11iIi11i
 def recent_packet_min ( self ) :
  if ( self . last_increment == None ) : return ( False )
  i11IiIIi11I = time . time ( ) - self . last_increment
  return ( i11IiIIi11I <= 60 )
  if 10 - 10: IiII % o0oOOo0O0Ooo / O0 / II111iiii
  if 81 - 81: Ii1I / o0oOOo0O0Ooo % OoOoOO00 . I1ii11iIi11i
 def stat_colors ( self , c1 , c2 , html ) :
  if ( self . recent_packet_sec ( ) ) :
   return ( green_last_sec ( c1 ) , green_last_sec ( c2 ) )
   if 47 - 47: II111iiii + OOooOOo / II111iiii . OOooOOo
  if ( self . recent_packet_min ( ) ) :
   return ( green_last_min ( c1 ) , green_last_min ( c2 ) )
   if 68 - 68: OoooooooOO
  return ( c1 , c2 )
  if 63 - 63: I1IiiI
  if 80 - 80: oO0o + iIii1I11I1II1
 def normalize ( self , count ) :
  count = str ( count )
  oOo0000OOo = len ( count )
  if ( oOo0000OOo > 12 ) :
   count = count [ 0 : - 10 ] + "." + count [ - 10 : - 7 ] + "T"
   return ( count )
   if 88 - 88: iII111i / I11i / I1ii11iIi11i + IiII * OoooooooOO . IiII
  if ( oOo0000OOo > 9 ) :
   count = count [ 0 : - 9 ] + "." + count [ - 9 : - 7 ] + "B"
   return ( count )
   if 3 - 3: ooOoO0o - Oo0Ooo
  if ( oOo0000OOo > 6 ) :
   count = count [ 0 : - 6 ] + "." + count [ - 6 ] + "M"
   return ( count )
   if 86 - 86: I1ii11iIi11i * I1Ii111 / o0oOOo0O0Ooo . OoO0O00
  return ( count )
  if 14 - 14: I11i * IiII / iIii1I11I1II1
  if 88 - 88: OoOoOO00 % II111iiii . I1IiiI / oO0o * IiII / i11iIiiIii
 def get_stats ( self , summary , html ) :
  o0o0o0o0 = self . last_rate_check
  iIOOOoOo0oO = self . last_packet_count
  I111 = self . last_byte_count
  self . last_rate_check = lisp_get_timestamp ( )
  self . last_packet_count = self . packet_count
  self . last_byte_count = self . byte_count
  if 78 - 78: iIii1I11I1II1 % iIii1I11I1II1 . iIii1I11I1II1 / Ii1I . O0 + i1IIi
  O0O00o0oo0 = self . last_rate_check - o0o0o0o0
  if ( O0O00o0oo0 == 0 ) :
   IiIIi11Ii1iII = 0
   o0ooO0ooO0000 = 0
  else :
   IiIIi11Ii1iII = int ( ( self . packet_count - iIOOOoOo0oO ) / O0O00o0oo0 )
   o0ooO0ooO0000 = ( self . byte_count - I111 ) / O0O00o0oo0
   o0ooO0ooO0000 = ( o0ooO0ooO0000 * 8 ) / 1000000
   o0ooO0ooO0000 = round ( o0ooO0ooO0000 , 2 )
   if 92 - 92: iII111i * OoooooooOO % I1IiiI / OOooOOo
   if 46 - 46: OoOoOO00
   if 52 - 52: o0oOOo0O0Ooo - OoO0O00 % i1IIi / Ii1I % IiII
   if 100 - 100: oO0o . i11iIiiIii - ooOoO0o
   if 49 - 49: Oo0Ooo % ooOoO0o % o0oOOo0O0Ooo + ooOoO0o * I1Ii111 % I1IiiI
  ooo0O = self . normalize ( self . packet_count )
  i1I11iI11I = self . normalize ( self . byte_count )
  if 77 - 77: I1Ii111 / iIii1I11I1II1 * I1Ii111 % oO0o + o0oOOo0O0Ooo . IiII
  if 80 - 80: OOooOOo . I1IiiI % iIii1I11I1II1
  if 45 - 45: OoooooooOO * O0
  if 86 - 86: O0 * oO0o + Oo0Ooo / II111iiii + i1IIi
  if 12 - 12: I1IiiI + OOooOOo / Ii1I % i11iIiiIii - I1Ii111 % I11i
  if ( summary ) :
   i1Ii111Ii111 = "<br>" if html else ""
   ooo0O , i1I11iI11I = self . stat_colors ( ooo0O , i1I11iI11I , html )
   i1I11 = "packet-count: {}{}byte-count: {}" . format ( ooo0O , i1Ii111Ii111 , i1I11iI11I )
   oO000O0oooOo = "packet-rate: {} pps\nbit-rate: {} Mbps" . format ( IiIIi11Ii1iII , o0ooO0ooO0000 )
   if 71 - 71: iII111i . OoooooooOO - i1IIi % I1Ii111 * OoooooooOO
   if ( html != "" ) : oO000O0oooOo = lisp_span ( i1I11 , oO000O0oooOo )
  else :
   ii1i1I1i1II = str ( IiIIi11Ii1iII )
   O0O0O0Oo = str ( o0ooO0ooO0000 )
   if ( html ) :
    ooo0O = lisp_print_cour ( ooo0O )
    ii1i1I1i1II = lisp_print_cour ( ii1i1I1i1II )
    i1I11iI11I = lisp_print_cour ( i1I11iI11I )
    O0O0O0Oo = lisp_print_cour ( O0O0O0Oo )
    if 18 - 18: OoOoOO00 * I1ii11iIi11i . i1IIi * iII111i
   i1Ii111Ii111 = "<br>" if html else ", "
   if 67 - 67: IiII + i11iIiiIii . II111iiii / OoOoOO00 + OoooooooOO + i11iIiiIii
   oO000O0oooOo = ( "packet-count: {}{}packet-rate: {} pps{}byte-count: " + "{}{}bit-rate: {} mbps" ) . format ( ooo0O , i1Ii111Ii111 , ii1i1I1i1II , i1Ii111Ii111 , i1I11iI11I , i1Ii111Ii111 ,
   # Oo0Ooo . O0
 O0O0O0Oo )
   if 58 - 58: i11iIiiIii + oO0o
  return ( oO000O0oooOo )
  if 70 - 70: iII111i % II111iiii % O0 / O0 - II111iiii . OoooooooOO
  if 78 - 78: OoOoOO00 + i11iIiiIii
  if 11 - 11: OoOoOO00 . I1IiiI + i11iIiiIii * OoooooooOO
  if 74 - 74: OoooooooOO * iII111i % OOooOOo . OoooooooOO * I11i % I1Ii111
  if 67 - 67: I11i * i1IIi
  if 7 - 7: i1IIi * OoOoOO00 . Ii1I
  if 80 - 80: OoOoOO00 + o0oOOo0O0Ooo - II111iiii
  if 3 - 3: ooOoO0o * I1Ii111
lisp_decap_stats = {
 "good-packets" : lisp_stats ( ) , "ICV-error" : lisp_stats ( ) ,
 "checksum-error" : lisp_stats ( ) , "lisp-header-error" : lisp_stats ( ) ,
 "no-decrypt-key" : lisp_stats ( ) , "bad-inner-version" : lisp_stats ( ) ,
 "outer-header-error" : lisp_stats ( )
 }
if 34 - 34: Ii1I / Oo0Ooo . II111iiii - ooOoO0o - I1ii11iIi11i % OoOoOO00
if 43 - 43: Ii1I * oO0o
if 57 - 57: OoooooooOO + I1IiiI % I1ii11iIi11i % ooOoO0o * I1Ii111
if 9 - 9: i11iIiiIii
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
  if 85 - 85: IiII / o0oOOo0O0Ooo * ooOoO0o
  if ( recurse == False ) : return
  if 74 - 74: O0 - o0oOOo0O0Ooo
  if 68 - 68: I1Ii111
  if 19 - 19: o0oOOo0O0Ooo
  if 63 - 63: OoooooooOO % ooOoO0o
  if 26 - 26: OOooOOo + Oo0Ooo
  if 97 - 97: I1Ii111 * I1Ii111 + iII111i % Ii1I / iII111i
  oOo0OO00oo0 = lisp_get_default_route_next_hops ( )
  if ( oOo0OO00oo0 == [ ] or len ( oOo0OO00oo0 ) == 1 ) : return
  if 13 - 13: o0oOOo0O0Ooo - OoOoOO00 . O0
  self . rloc_next_hop = oOo0OO00oo0 [ 0 ]
  i1oo0OO0Oo = self
  for o00ooO0Ooo in oOo0OO00oo0 [ 1 : : ] :
   o00o000oOoo0o = lisp_rloc ( False )
   o00o000oOoo0o = copy . deepcopy ( self )
   o00o000oOoo0o . rloc_next_hop = o00ooO0Ooo
   i1oo0OO0Oo . next_rloc = o00o000oOoo0o
   i1oo0OO0Oo = o00o000oOoo0o
   if 71 - 71: oO0o % OoO0O00 / Ii1I % II111iiii * OoOoOO00
   if 19 - 19: o0oOOo0O0Ooo * IiII . Oo0Ooo * OOooOOo
   if 6 - 6: I1ii11iIi11i / O0
 def up_state ( self ) :
  return ( self . state == LISP_RLOC_UP_STATE )
  if 16 - 16: II111iiii . Oo0Ooo * I1Ii111 + o0oOOo0O0Ooo - i11iIiiIii
  if 98 - 98: II111iiii - i1IIi - ooOoO0o
 def unreach_state ( self ) :
  return ( self . state == LISP_RLOC_UNREACH_STATE )
  if 36 - 36: IiII + o0oOOo0O0Ooo
  if 81 - 81: OOooOOo / I11i % oO0o + ooOoO0o
 def no_echoed_nonce_state ( self ) :
  return ( self . state == LISP_RLOC_NO_ECHOED_NONCE_STATE )
  if 10 - 10: oO0o / i11iIiiIii
  if 73 - 73: OoO0O00 - i1IIi
 def down_state ( self ) :
  return ( self . state in [ LISP_RLOC_DOWN_STATE , LISP_RLOC_ADMIN_DOWN_STATE ] )
  if 52 - 52: I1ii11iIi11i
  if 4 - 4: Ii1I - iII111i + i1IIi - I1Ii111 / iII111i . Oo0Ooo
  if 18 - 18: oO0o % iIii1I11I1II1 + ooOoO0o
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
  if 34 - 34: I1IiiI - OoooooooOO . IiII - OOooOOo % IiII
  if 19 - 19: IiII + I1ii11iIi11i % Oo0Ooo
 def print_rloc ( self , indent ) :
  OOOO0O00o = lisp_print_elapsed ( self . uptime )
  lprint ( "{}rloc {}, uptime {}, {}, parms {}/{}/{}/{}" . format ( indent ,
 red ( self . rloc . print_address ( ) , False ) , OOOO0O00o , self . print_state ( ) ,
 self . priority , self . weight , self . mpriority , self . mweight ) )
  if 32 - 32: OOooOOo
  if 46 - 46: II111iiii . OoO0O00
 def print_rloc_name ( self , cour = False ) :
  if ( self . rloc_name == None ) : return ( "" )
  I1IiiIoo0o00O = self . rloc_name
  if ( cour ) : I1IiiIoo0o00O = lisp_print_cour ( I1IiiIoo0o00O )
  return ( 'rloc-name: {}' . format ( blue ( I1IiiIoo0o00O , cour ) ) )
  if 97 - 97: oO0o
  if 45 - 45: i11iIiiIii / IiII + OoO0O00
 def store_rloc_from_record ( self , rloc_record , nonce , source ) :
  o00o = LISP_DATA_PORT
  self . rloc . copy_address ( rloc_record . rloc )
  self . rloc_name = rloc_record . rloc_name
  if 55 - 55: Ii1I / II111iiii - oO0o
  if 58 - 58: i1IIi . OoooooooOO % iIii1I11I1II1 * o0oOOo0O0Ooo + O0 / oO0o
  if 77 - 77: I11i . I1ii11iIi11i
  if 92 - 92: i11iIiiIii + I11i % I1IiiI / ooOoO0o
  oOOoo0O00 = self . rloc
  if ( oOOoo0O00 . is_null ( ) == False ) :
   iiiII1 = lisp_get_nat_info ( oOOoo0O00 , self . rloc_name )
   if ( iiiII1 ) :
    o00o = iiiII1 . port
    oo0OOOo = lisp_nat_state_info [ self . rloc_name ] [ 0 ]
    I1iiIiiii1111 = oOOoo0O00 . print_address_no_iid ( )
    oooOOoo0 = red ( I1iiIiiii1111 , False )
    oOoo00o0 = "" if self . rloc_name == None else blue ( self . rloc_name , False )
    if 11 - 11: OoO0O00 / IiII + IiII
    if 4 - 4: Oo0Ooo / O0 * OoO0O00 * Oo0Ooo - Ii1I
    if 43 - 43: o0oOOo0O0Ooo
    if 61 - 61: o0oOOo0O0Ooo * IiII / I1ii11iIi11i
    if 67 - 67: iII111i * OoO0O00 + oO0o - iIii1I11I1II1 / Ii1I - o0oOOo0O0Ooo
    if 45 - 45: OoooooooOO % OoOoOO00 / o0oOOo0O0Ooo + I1IiiI
    if ( iiiII1 . timed_out ( ) ) :
     lprint ( ( "    Matched stored NAT state timed out for " + "RLOC {}:{}, {}" ) . format ( oooOOoo0 , o00o , oOoo00o0 ) )
     if 32 - 32: OOooOOo + i11iIiiIii
     if 4 - 4: I11i % o0oOOo0O0Ooo - o0oOOo0O0Ooo / OoO0O00 + Ii1I
     iiiII1 = None if ( iiiII1 == oo0OOOo ) else oo0OOOo
     if ( iiiII1 and iiiII1 . timed_out ( ) ) :
      o00o = iiiII1 . port
      oooOOoo0 = red ( iiiII1 . address , False )
      lprint ( ( "    Youngest stored NAT state timed out " + " for RLOC {}:{}, {}" ) . format ( oooOOoo0 , o00o ,
      # IiII * I1IiiI % O0 * OoO0O00 % OoooooooOO
 oOoo00o0 ) )
      iiiII1 = None
      if 46 - 46: I1IiiI * Oo0Ooo * IiII + o0oOOo0O0Ooo - iII111i - iIii1I11I1II1
      if 99 - 99: I1ii11iIi11i . i1IIi / I11i . Ii1I
      if 94 - 94: ooOoO0o . I1IiiI + IiII % I1IiiI / o0oOOo0O0Ooo % o0oOOo0O0Ooo
      if 21 - 21: O0 / OOooOOo - II111iiii + I1ii11iIi11i / OoooooooOO
      if 81 - 81: i11iIiiIii / Oo0Ooo * i1IIi + OoO0O00 + O0 % I1ii11iIi11i
      if 3 - 3: i11iIiiIii * IiII . Oo0Ooo % OoOoOO00 * I11i . iII111i
      if 80 - 80: I11i - IiII
    if ( iiiII1 ) :
     if ( iiiII1 . address != I1iiIiiii1111 ) :
      lprint ( "RLOC conflict, RLOC-record {}, NAT state {}" . format ( oooOOoo0 , red ( iiiII1 . address , False ) ) )
      if 40 - 40: OOooOOo * I1IiiI % I11i . I1Ii111 % O0 . O0
      self . rloc . store_address ( iiiII1 . address )
      if 14 - 14: ooOoO0o . OoOoOO00 + ooOoO0o * OoOoOO00 . OoOoOO00 * Oo0Ooo
     oooOOoo0 = red ( iiiII1 . address , False )
     o00o = iiiII1 . port
     lprint ( "    Use NAT translated RLOC {}:{} for {}" . format ( oooOOoo0 , o00o , oOoo00o0 ) )
     if 40 - 40: OoooooooOO
     self . store_translated_rloc ( oOOoo0O00 , o00o )
     if 14 - 14: o0oOOo0O0Ooo / OOooOOo . OoOoOO00 % iIii1I11I1II1 % OoOoOO00
     if 92 - 92: o0oOOo0O0Ooo + II111iiii
     if 56 - 56: OoOoOO00 - OoOoOO00 / Ii1I
     if 92 - 92: iIii1I11I1II1
  self . geo = rloc_record . geo
  self . elp = rloc_record . elp
  self . json = rloc_record . json
  if 21 - 21: I1IiiI
  if 69 - 69: OoooooooOO + iII111i
  if 29 - 29: ooOoO0o * I1IiiI / Oo0Ooo / I1ii11iIi11i
  if 74 - 74: I1ii11iIi11i - ooOoO0o / OoOoOO00 - OoooooooOO * oO0o
  self . rle = rloc_record . rle
  if ( self . rle ) :
   for OOoo0Oo00 in self . rle . rle_nodes :
    I1IiiIoo0o00O = OOoo0Oo00 . rloc_name
    iiiII1 = lisp_get_nat_info ( OOoo0Oo00 . address , I1IiiIoo0o00O )
    if ( iiiII1 == None ) : continue
    if 45 - 45: o0oOOo0O0Ooo . I1Ii111 % Ii1I
    o00o = iiiII1 . port
    IiIi1I1i1iII = I1IiiIoo0o00O
    if ( IiIi1I1i1iII ) : IiIi1I1i1iII = blue ( I1IiiIoo0o00O , False )
    if 42 - 42: Oo0Ooo + i11iIiiIii - OOooOOo . I1ii11iIi11i % I1Ii111 . I1ii11iIi11i
    lprint ( ( "      Store translated encap-port {} for RLE-" + "node {}, rloc-name '{}'" ) . format ( o00o ,
    # OoooooooOO . I1ii11iIi11i * i11iIiiIii / Ii1I
 OOoo0Oo00 . address . print_address_no_iid ( ) , IiIi1I1i1iII ) )
    OOoo0Oo00 . translated_port = o00o
    if 39 - 39: O0 % Ii1I
    if 63 - 63: OOooOOo / I1ii11iIi11i
    if 11 - 11: O0 % iIii1I11I1II1
  self . priority = rloc_record . priority
  self . mpriority = rloc_record . mpriority
  self . weight = rloc_record . weight
  self . mweight = rloc_record . mweight
  if ( rloc_record . reach_bit and rloc_record . local_bit and
 rloc_record . probe_bit == False ) : self . state = LISP_RLOC_UP_STATE
  if 64 - 64: OoOoOO00 - oO0o
  if 8 - 8: i11iIiiIii - iIii1I11I1II1 / I1Ii111 . i11iIiiIii % o0oOOo0O0Ooo / oO0o
  if 36 - 36: IiII
  if 53 - 53: OoooooooOO / I1IiiI % I11i + Oo0Ooo
  i1iIi1Ii1I11I = source . is_exact_match ( rloc_record . rloc ) if source != None else None
  if 58 - 58: ooOoO0o
  if ( rloc_record . keys != None and i1iIi1Ii1I11I ) :
   o0OoOo0o0OOoO0 = rloc_record . keys [ 1 ]
   if ( o0OoOo0o0OOoO0 != None ) :
    I1iiIiiii1111 = rloc_record . rloc . print_address_no_iid ( ) + ":" + str ( o00o )
    if 84 - 84: OoOoOO00 - I11i
    o0OoOo0o0OOoO0 . add_key_by_rloc ( I1iiIiiii1111 , True )
    lprint ( "    Store encap-keys for nonce 0x{}, RLOC {}" . format ( lisp_hex_string ( nonce ) , red ( I1iiIiiii1111 , False ) ) )
    if 34 - 34: Ii1I % I1Ii111 % I1ii11iIi11i - IiII
    if 89 - 89: IiII
    if 64 - 64: OoOoOO00
  return ( o00o )
  if 3 - 3: i11iIiiIii / I1Ii111
  if 40 - 40: OoooooooOO / o0oOOo0O0Ooo + OoOoOO00
 def store_translated_rloc ( self , rloc , port ) :
  self . rloc . copy_address ( rloc )
  self . translated_rloc . copy_address ( rloc )
  self . translated_port = port
  if 73 - 73: OOooOOo / Oo0Ooo
  if 80 - 80: OoO0O00 + I1IiiI % i1IIi / I11i % i1IIi * i11iIiiIii
 def is_rloc_translated ( self ) :
  return ( self . translated_rloc . is_null ( ) == False )
  if 27 - 27: OoOoOO00 / I1Ii111 * O0 / I1IiiI - IiII / o0oOOo0O0Ooo
  if 70 - 70: I1ii11iIi11i
 def rloc_exists ( self ) :
  if ( self . rloc . is_null ( ) == False ) : return ( True )
  if ( self . rle_name or self . geo_name or self . elp_name or self . json_name ) :
   return ( False )
   if 11 - 11: I1Ii111
  return ( True )
  if 70 - 70: Ii1I
  if 22 - 22: Ii1I
 def is_rtr ( self ) :
  return ( ( self . priority == 254 and self . mpriority == 255 and self . weight == 0 and self . mweight == 0 ) )
  if 59 - 59: I1ii11iIi11i
  if 90 - 90: OOooOOo / iII111i
  if 70 - 70: o0oOOo0O0Ooo
 def print_state_change ( self , new_state ) :
  I1Ii1iI1 = self . print_state ( )
  OO0o0o0oo = "{} -> {}" . format ( I1Ii1iI1 , new_state )
  if ( new_state == "up" and self . unreach_state ( ) ) :
   OO0o0o0oo = bold ( OO0o0o0oo , False )
   if 44 - 44: Oo0Ooo + Ii1I + ooOoO0o / I1ii11iIi11i
  return ( OO0o0o0oo )
  if 50 - 50: i1IIi . iIii1I11I1II1 % OoO0O00
  if 45 - 45: OoooooooOO . O0 * oO0o + IiII
 def print_rloc_probe_rtt ( self ) :
  if ( self . rloc_probe_rtt == - 1 ) : return ( "none" )
  return ( self . rloc_probe_rtt )
  if 18 - 18: II111iiii . O0 - I11i / I11i
  if 71 - 71: OoOoOO00 + iIii1I11I1II1 - II111iiii / i1IIi
 def print_recent_rloc_probe_rtts ( self ) :
  I111II = str ( self . recent_rloc_probe_rtts )
  I111II = I111II . replace ( "-1" , "?" )
  return ( I111II )
  if 22 - 22: I1Ii111 - OOooOOo * i1IIi
  if 88 - 88: ooOoO0o + iIii1I11I1II1 + OoO0O00 * I1Ii111 + oO0o
 def compute_rloc_probe_rtt ( self ) :
  i1oo0OO0Oo = self . rloc_probe_rtt
  self . rloc_probe_rtt = - 1
  if ( self . last_rloc_probe_reply == None ) : return
  if ( self . last_rloc_probe == None ) : return
  self . rloc_probe_rtt = self . last_rloc_probe_reply - self . last_rloc_probe
  self . rloc_probe_rtt = round ( self . rloc_probe_rtt , 3 )
  I1IIIIII1 = self . recent_rloc_probe_rtts
  self . recent_rloc_probe_rtts = [ i1oo0OO0Oo ] + I1IIIIII1 [ 0 : - 1 ]
  if 76 - 76: I1Ii111 * OOooOOo * IiII % IiII / o0oOOo0O0Ooo * I11i
  if 41 - 41: i11iIiiIii . I1IiiI / O0
 def print_rloc_probe_hops ( self ) :
  return ( self . rloc_probe_hops )
  if 93 - 93: Oo0Ooo % OoOoOO00 . II111iiii
  if 60 - 60: OoO0O00 - IiII % O0 * I1ii11iIi11i
 def print_recent_rloc_probe_hops ( self ) :
  oOO000OOOOOooo = str ( self . recent_rloc_probe_hops )
  return ( oOO000OOOOOooo )
  if 64 - 64: OoO0O00 % OoOoOO00 % I1IiiI - Ii1I / IiII * Ii1I
  if 74 - 74: IiII - O0 % OOooOOo % OoooooooOO - I11i
 def store_rloc_probe_hops ( self , to_hops , from_ttl ) :
  if ( to_hops == 0 ) :
   to_hops = "?"
  elif ( to_hops < LISP_RLOC_PROBE_TTL / 2 ) :
   to_hops = "!"
  else :
   to_hops = str ( LISP_RLOC_PROBE_TTL - to_hops )
   if 4 - 4: i1IIi + OoOoOO00 + iIii1I11I1II1 - i1IIi * i11iIiiIii
  if ( from_ttl < LISP_RLOC_PROBE_TTL / 2 ) :
   OO0oOo00 = "!"
  else :
   OO0oOo00 = str ( LISP_RLOC_PROBE_TTL - from_ttl )
   if 88 - 88: O0 % OOooOOo . iII111i
   if 40 - 40: O0 . Ii1I % IiII % I1ii11iIi11i - OoOoOO00
  i1oo0OO0Oo = self . rloc_probe_hops
  self . rloc_probe_hops = to_hops + "/" + OO0oOo00
  I1IIIIII1 = self . recent_rloc_probe_hops
  self . recent_rloc_probe_hops = [ i1oo0OO0Oo ] + I1IIIIII1 [ 0 : - 1 ]
  if 94 - 94: I1IiiI . I1Ii111
  if 37 - 37: i1IIi - O0
 def process_rloc_probe_reply ( self , nonce , eid , group , hop_count , ttl ) :
  oOOoo0O00 = self
  while ( True ) :
   if ( oOOoo0O00 . last_rloc_probe_nonce == nonce ) : break
   oOOoo0O00 = oOOoo0O00 . next_rloc
   if ( oOOoo0O00 == None ) :
    lprint ( "    No matching nonce state found for nonce 0x{}" . format ( lisp_hex_string ( nonce ) ) )
    if 36 - 36: I1Ii111 . OoooooooOO - i1IIi % iII111i - II111iiii * i11iIiiIii
    return
    if 90 - 90: OoOoOO00 % iII111i - Oo0Ooo
    if 13 - 13: o0oOOo0O0Ooo / O0 . I1Ii111 * I1Ii111
    if 76 - 76: Ii1I - iII111i
  oOOoo0O00 . last_rloc_probe_reply = lisp_get_timestamp ( )
  oOOoo0O00 . compute_rloc_probe_rtt ( )
  OOo0OOo = oOOoo0O00 . print_state_change ( "up" )
  if ( oOOoo0O00 . state != LISP_RLOC_UP_STATE ) :
   lisp_update_rtr_updown ( oOOoo0O00 . rloc , True )
   oOOoo0O00 . state = LISP_RLOC_UP_STATE
   oOOoo0O00 . last_state_change = lisp_get_timestamp ( )
   Iii1 = lisp_map_cache . lookup_cache ( eid , True )
   if ( Iii1 ) : lisp_write_ipc_map_cache ( True , Iii1 )
   if 31 - 31: I11i . ooOoO0o
   if 69 - 69: I1ii11iIi11i
  oOOoo0O00 . store_rloc_probe_hops ( hop_count , ttl )
  if 6 - 6: iIii1I11I1II1 * I1ii11iIi11i / I11i % I1Ii111 / Oo0Ooo
  iI11iI11i11ii = bold ( "RLOC-probe reply" , False )
  I1iiIiiii1111 = oOOoo0O00 . rloc . print_address_no_iid ( )
  OOOOo000o = bold ( str ( oOOoo0O00 . print_rloc_probe_rtt ( ) ) , False )
  i111 = ":{}" . format ( self . translated_port ) if self . translated_port != 0 else ""
  if 42 - 42: iII111i / i11iIiiIii + II111iiii % IiII / ooOoO0o
  o00ooO0Ooo = ""
  if ( oOOoo0O00 . rloc_next_hop != None ) :
   oOo0OOOOOO , o0O0 = oOOoo0O00 . rloc_next_hop
   o00ooO0Ooo = ", nh {}({})" . format ( o0O0 , oOo0OOOOOO )
   if 57 - 57: ooOoO0o * oO0o + o0oOOo0O0Ooo
   if 97 - 97: OoooooooOO * I1IiiI . Ii1I * I1IiiI
  ooo0OO = green ( lisp_print_eid_tuple ( eid , group ) , False )
  lprint ( ( "    Received {} from {}{} for {}, {}, rtt {}{}, " + "to-ttl/from-ttl {}" ) . format ( iI11iI11i11ii , red ( I1iiIiiii1111 , False ) , i111 , ooo0OO ,
  # OoO0O00 * OoO0O00
 OOo0OOo , OOOOo000o , o00ooO0Ooo , str ( hop_count ) + "/" + str ( ttl ) ) )
  if 66 - 66: i1IIi . IiII / OoOoOO00 / i11iIiiIii
  if ( oOOoo0O00 . rloc_next_hop == None ) : return
  if 53 - 53: OoOoOO00 % OoooooooOO + Ii1I
  if 85 - 85: ooOoO0o % i11iIiiIii * oO0o / ooOoO0o / I1Ii111 . i11iIiiIii
  if 23 - 23: i1IIi + I1Ii111 / Oo0Ooo * O0 . O0
  if 67 - 67: OoO0O00 - II111iiii + Ii1I
  oOOoo0O00 = None
  iIiiII = None
  while ( True ) :
   oOOoo0O00 = self if oOOoo0O00 == None else oOOoo0O00 . next_rloc
   if ( oOOoo0O00 == None ) : break
   if ( oOOoo0O00 . up_state ( ) == False ) : continue
   if ( oOOoo0O00 . rloc_probe_rtt == - 1 ) : continue
   if 88 - 88: i1IIi . I1IiiI - I11i % OoooooooOO / OoOoOO00 + OoOoOO00
   if ( iIiiII == None ) : iIiiII = oOOoo0O00
   if ( oOOoo0O00 . rloc_probe_rtt < iIiiII . rloc_probe_rtt ) : iIiiII = oOOoo0O00
   if 32 - 32: o0oOOo0O0Ooo * O0
   if 65 - 65: Oo0Ooo + i1IIi + OoooooooOO % o0oOOo0O0Ooo
  if ( iIiiII != None ) :
   oOo0OOOOOO , o0O0 = iIiiII . rloc_next_hop
   o00ooO0Ooo = bold ( "nh {}({})" . format ( o0O0 , oOo0OOOOOO ) , False )
   lprint ( "    Install host-route via best {}" . format ( o00ooO0Ooo ) )
   lisp_install_host_route ( I1iiIiiii1111 , None , False )
   lisp_install_host_route ( I1iiIiiii1111 , o0O0 , True )
   if 4 - 4: I1IiiI
   if 74 - 74: oO0o / i11iIiiIii + Oo0Ooo
   if 99 - 99: I1Ii111 . II111iiii * IiII . II111iiii + OoOoOO00
 def add_to_rloc_probe_list ( self , eid , group ) :
  I1iiIiiii1111 = self . rloc . print_address_no_iid ( )
  o00o = self . translated_port
  if ( o00o != 0 ) : I1iiIiiii1111 += ":" + str ( o00o )
  if 36 - 36: OoO0O00 * iII111i % ooOoO0o % OoOoOO00 * I1IiiI % i1IIi
  if ( lisp_rloc_probe_list . has_key ( I1iiIiiii1111 ) == False ) :
   lisp_rloc_probe_list [ I1iiIiiii1111 ] = [ ]
   if 25 - 25: iII111i + I1IiiI / OoO0O00 - I1IiiI / OoooooooOO - ooOoO0o
   if 22 - 22: iII111i
  if ( group . is_null ( ) ) : group . instance_id = 0
  for O00oo00o000o , ooo0OO , O0oOo00Oo0oo0 in lisp_rloc_probe_list [ I1iiIiiii1111 ] :
   if ( ooo0OO . is_exact_match ( eid ) and O0oOo00Oo0oo0 . is_exact_match ( group ) ) :
    if ( O00oo00o000o == self ) :
     if ( lisp_rloc_probe_list [ I1iiIiiii1111 ] == [ ] ) :
      lisp_rloc_probe_list . pop ( I1iiIiiii1111 )
      if 30 - 30: OoO0O00 + I11i + Oo0Ooo
     return
     if 77 - 77: II111iiii
    lisp_rloc_probe_list [ I1iiIiiii1111 ] . remove ( [ O00oo00o000o , ooo0OO , O0oOo00Oo0oo0 ] )
    break
    if 92 - 92: I1Ii111 / I1IiiI / I1ii11iIi11i + I11i + Ii1I
    if 51 - 51: OOooOOo
  lisp_rloc_probe_list [ I1iiIiiii1111 ] . append ( [ self , eid , group ] )
  if 85 - 85: II111iiii
  if 60 - 60: Ii1I * OOooOOo - o0oOOo0O0Ooo - Ii1I / Oo0Ooo . OOooOOo
  if 43 - 43: II111iiii * o0oOOo0O0Ooo % o0oOOo0O0Ooo + iIii1I11I1II1 + OoOoOO00
  if 54 - 54: II111iiii + OOooOOo * Oo0Ooo * I1Ii111 - o0oOOo0O0Ooo % Ii1I
  if 69 - 69: I11i + OoOoOO00 - i11iIiiIii * O0 % O0
  oOOoo0O00 = lisp_rloc_probe_list [ I1iiIiiii1111 ] [ 0 ] [ 0 ]
  if ( oOOoo0O00 . state == LISP_RLOC_UNREACH_STATE ) :
   self . state = LISP_RLOC_UNREACH_STATE
   self . last_state_change = lisp_get_timestamp ( )
   if 81 - 81: I11i - o0oOOo0O0Ooo % Ii1I / I1Ii111 * II111iiii
   if 40 - 40: OoO0O00 . i11iIiiIii
   if 36 - 36: o0oOOo0O0Ooo * iII111i / I1ii11iIi11i % i1IIi % I1ii11iIi11i + i11iIiiIii
 def delete_from_rloc_probe_list ( self , eid , group ) :
  I1iiIiiii1111 = self . rloc . print_address_no_iid ( )
  o00o = self . translated_port
  if ( o00o != 0 ) : I1iiIiiii1111 += ":" + str ( o00o )
  if ( lisp_rloc_probe_list . has_key ( I1iiIiiii1111 ) == False ) : return
  if 24 - 24: I1Ii111 / ooOoO0o - i11iIiiIii
  Iii111II1I11I = [ ]
  for iIIiI11iI1Ii1 in lisp_rloc_probe_list [ I1iiIiiii1111 ] :
   if ( iIIiI11iI1Ii1 [ 0 ] != self ) : continue
   if ( iIIiI11iI1Ii1 [ 1 ] . is_exact_match ( eid ) == False ) : continue
   if ( iIIiI11iI1Ii1 [ 2 ] . is_exact_match ( group ) == False ) : continue
   Iii111II1I11I = iIIiI11iI1Ii1
   break
   if 18 - 18: OOooOOo / O0 . OoO0O00 - II111iiii * OOooOOo
  if ( Iii111II1I11I == [ ] ) : return
  if 13 - 13: OoO0O00 % i1IIi . i11iIiiIii / iII111i
  try :
   lisp_rloc_probe_list [ I1iiIiiii1111 ] . remove ( Iii111II1I11I )
   if ( lisp_rloc_probe_list [ I1iiIiiii1111 ] == [ ] ) :
    lisp_rloc_probe_list . pop ( I1iiIiiii1111 )
    if 28 - 28: i1IIi - iII111i + o0oOOo0O0Ooo / Oo0Ooo * oO0o
  except :
   return
   if 8 - 8: ooOoO0o + OOooOOo * ooOoO0o / i1IIi . I1ii11iIi11i
   if 4 - 4: Ii1I - Oo0Ooo . i1IIi + iIii1I11I1II1
   if 28 - 28: O0 / ooOoO0o / IiII - I11i + IiII + OoO0O00
 def print_rloc_probe_state ( self , trailing_linefeed ) :
  Oo0O = ""
  oOOoo0O00 = self
  while ( True ) :
   OOoOo0O = oOOoo0O00 . last_rloc_probe
   if ( OOoOo0O == None ) : OOoOo0O = 0
   iII111 = oOOoo0O00 . last_rloc_probe_reply
   if ( iII111 == None ) : iII111 = 0
   OOOOo000o = oOOoo0O00 . print_rloc_probe_rtt ( )
   IiIIi1I1I11Ii = space ( 4 )
   if 64 - 64: OoO0O00 . I1IiiI + I1Ii111
   if ( oOOoo0O00 . rloc_next_hop == None ) :
    Oo0O += "RLOC-Probing:\n"
   else :
    oOo0OOOOOO , o0O0 = oOOoo0O00 . rloc_next_hop
    Oo0O += "RLOC-Probing for nh {}({}):\n" . format ( o0O0 , oOo0OOOOOO )
    if 42 - 42: oO0o + iIii1I11I1II1 / Ii1I - oO0o % oO0o . I1Ii111
    if 88 - 88: Oo0Ooo / Ii1I . OOooOOo * Oo0Ooo
   Oo0O += ( "{}RLOC-probe request sent: {}\n{}RLOC-probe reply " + "received: {}, rtt {}" ) . format ( IiIIi1I1I11Ii , lisp_print_elapsed ( OOoOo0O ) ,
   # Oo0Ooo
 IiIIi1I1I11Ii , lisp_print_elapsed ( iII111 ) , OOOOo000o )
   if 44 - 44: ooOoO0o * iII111i * IiII % o0oOOo0O0Ooo
   if ( trailing_linefeed ) : Oo0O += "\n"
   if 45 - 45: OoOoOO00 % o0oOOo0O0Ooo + IiII / i11iIiiIii
   oOOoo0O00 = oOOoo0O00 . next_rloc
   if ( oOOoo0O00 == None ) : break
   Oo0O += "\n"
   if 29 - 29: iIii1I11I1II1 . OoO0O00 / I1IiiI
  return ( Oo0O )
  if 38 - 38: Oo0Ooo / Oo0Ooo % ooOoO0o
  if 56 - 56: oO0o / iII111i % i1IIi * II111iiii . Ii1I
 def get_encap_keys ( self ) :
  o00o = "4341" if self . translated_port == 0 else str ( self . translated_port )
  if 10 - 10: ooOoO0o - I1ii11iIi11i
  I1iiIiiii1111 = self . rloc . print_address_no_iid ( ) + ":" + o00o
  if 82 - 82: o0oOOo0O0Ooo / I11i - I11i / O0 * I1IiiI / OoO0O00
  try :
   o00OO0o0 = lisp_crypto_keys_by_rloc_encap [ I1iiIiiii1111 ]
   if ( o00OO0o0 [ 1 ] ) : return ( o00OO0o0 [ 1 ] . encrypt_key , o00OO0o0 [ 1 ] . icv_key )
   return ( None , None )
  except :
   return ( None , None )
   if 71 - 71: I11i % I11i - i11iIiiIii + iIii1I11I1II1 / iII111i
   if 63 - 63: O0 * i11iIiiIii / IiII / IiII
   if 72 - 72: i11iIiiIii * OoOoOO00 % oO0o / I1Ii111
 def rloc_recent_rekey ( self ) :
  o00o = "4341" if self . translated_port == 0 else str ( self . translated_port )
  if 9 - 9: iIii1I11I1II1 . IiII
  I1iiIiiii1111 = self . rloc . print_address_no_iid ( ) + ":" + o00o
  if 42 - 42: i1IIi / Ii1I * I1ii11iIi11i
  try :
   o0OoOo0o0OOoO0 = lisp_crypto_keys_by_rloc_encap [ I1iiIiiii1111 ] [ 1 ]
   if ( o0OoOo0o0OOoO0 == None ) : return ( False )
   if ( o0OoOo0o0OOoO0 . last_rekey == None ) : return ( True )
   return ( time . time ( ) - o0OoOo0o0OOoO0 . last_rekey < 1 )
  except :
   return ( False )
   if 9 - 9: I11i % i1IIi / i1IIi / OoO0O00
   if 46 - 46: I1Ii111 * II111iiii + II111iiii * O0 % II111iiii
   if 37 - 37: OOooOOo . iIii1I11I1II1 / O0 . ooOoO0o + OOooOOo - OoooooooOO
   if 96 - 96: I1Ii111 / oO0o . I1ii11iIi11i % I1IiiI * OOooOOo
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
  if 99 - 99: i11iIiiIii - I1Ii111
  if 4 - 4: o0oOOo0O0Ooo - i11iIiiIii . iIii1I11I1II1 . OOooOOo % IiII
 def print_mapping ( self , eid_indent , rloc_indent ) :
  OOOO0O00o = lisp_print_elapsed ( self . uptime )
  ii1I1 = "" if self . group . is_null ( ) else ", group {}" . format ( self . group . print_prefix ( ) )
  if 68 - 68: I11i / iII111i - IiII . iIii1I11I1II1 / o0oOOo0O0Ooo
  lprint ( "{}eid {}{}, uptime {}, {} rlocs:" . format ( eid_indent ,
 green ( self . eid . print_prefix ( ) , False ) , ii1I1 , OOOO0O00o ,
 len ( self . rloc_set ) ) )
  for oOOoo0O00 in self . rloc_set : oOOoo0O00 . print_rloc ( rloc_indent )
  if 54 - 54: II111iiii * I1IiiI
  if 49 - 49: I1ii11iIi11i
 def print_eid_tuple ( self ) :
  return ( lisp_print_eid_tuple ( self . eid , self . group ) )
  if 31 - 31: o0oOOo0O0Ooo - OoOoOO00 + I1ii11iIi11i . oO0o - O0
  if 61 - 61: I1ii11iIi11i * II111iiii . i1IIi
 def print_ttl ( self ) :
  oooOooOO = self . map_cache_ttl
  if ( oooOooOO == None ) : return ( "forever" )
  if 60 - 60: OoooooooOO % ooOoO0o * i11iIiiIii * OoooooooOO % IiII
  if ( oooOooOO >= 3600 ) :
   if ( ( oooOooOO % 3600 ) == 0 ) :
    oooOooOO = str ( oooOooOO / 3600 ) + " hours"
   else :
    oooOooOO = str ( oooOooOO * 60 ) + " mins"
    if 15 - 15: oO0o
  elif ( oooOooOO >= 60 ) :
   if ( ( oooOooOO % 60 ) == 0 ) :
    oooOooOO = str ( oooOooOO / 60 ) + " mins"
   else :
    oooOooOO = str ( oooOooOO ) + " secs"
    if 40 - 40: I1Ii111
  else :
   oooOooOO = str ( oooOooOO ) + " secs"
   if 77 - 77: II111iiii - o0oOOo0O0Ooo . Ii1I
  return ( oooOooOO )
  if 47 - 47: o0oOOo0O0Ooo % OOooOOo + I1Ii111
  if 64 - 64: ooOoO0o / IiII . I1IiiI
 def has_ttl_elapsed ( self ) :
  if ( self . map_cache_ttl == None ) : return ( False )
  i11IiIIi11I = time . time ( ) - self . last_refresh_time
  return ( i11IiIIi11I >= self . map_cache_ttl )
  if 77 - 77: o0oOOo0O0Ooo % I1Ii111 . OOooOOo
  if 90 - 90: I11i
 def is_active ( self ) :
  if ( self . stats . last_increment == None ) : return ( False )
  i11IiIIi11I = time . time ( ) - self . stats . last_increment
  return ( i11IiIIi11I <= 60 )
  if 53 - 53: I1ii11iIi11i + i11iIiiIii / iIii1I11I1II1 + OoooooooOO + IiII * I1IiiI
  if 16 - 16: i11iIiiIii - oO0o . i11iIiiIii + OoO0O00 + i11iIiiIii
 def match_eid_tuple ( self , db ) :
  if ( self . eid . is_exact_match ( db . eid ) == False ) : return ( False )
  if ( self . group . is_exact_match ( db . group ) == False ) : return ( False )
  return ( True )
  if 85 - 85: I1ii11iIi11i - ooOoO0o + I1Ii111 + I1Ii111
  if 13 - 13: II111iiii
 def sort_rloc_set ( self ) :
  self . rloc_set . sort ( key = operator . attrgetter ( 'rloc.address' ) )
  if 22 - 22: o0oOOo0O0Ooo
  if 45 - 45: I1Ii111 + OoooooooOO + o0oOOo0O0Ooo * II111iiii
 def delete_rlocs_from_rloc_probe_list ( self ) :
  for oOOoo0O00 in self . best_rloc_set :
   oOOoo0O00 . delete_from_rloc_probe_list ( self . eid , self . group )
   if 12 - 12: I1ii11iIi11i / O0
   if 18 - 18: OoOoOO00 . i11iIiiIii + i1IIi / OoooooooOO - IiII % OoO0O00
   if 47 - 47: iII111i % IiII + I1Ii111 * o0oOOo0O0Ooo * OoooooooOO
 def build_best_rloc_set ( self ) :
  OOoOo = self . best_rloc_set
  self . best_rloc_set = [ ]
  if ( self . rloc_set == None ) : return
  if 81 - 81: I11i * oO0o
  if 51 - 51: I1IiiI
  if 35 - 35: OOooOOo % oO0o
  if 73 - 73: II111iiii / i11iIiiIii
  o0O0OOOOO = 256
  for oOOoo0O00 in self . rloc_set :
   if ( oOOoo0O00 . up_state ( ) ) : o0O0OOOOO = min ( oOOoo0O00 . priority , o0O0OOOOO )
   if 86 - 86: Oo0Ooo - OOooOOo * I11i
   if 60 - 60: ooOoO0o - Ii1I - OoO0O00 % OoooooooOO
   if 22 - 22: oO0o * i1IIi
   if 54 - 54: I1IiiI * I1IiiI % IiII - i11iIiiIii * o0oOOo0O0Ooo
   if 38 - 38: OoOoOO00 / OOooOOo % OoooooooOO * I1ii11iIi11i
   if 7 - 7: I11i * O0 + Oo0Ooo / O0 * oO0o + i11iIiiIii
   if 74 - 74: OoOoOO00
   if 91 - 91: i11iIiiIii / Ii1I % OOooOOo % O0 - I11i . I11i
   if 78 - 78: i1IIi + I11i % OoooooooOO + i1IIi + iII111i % Ii1I
   if 87 - 87: ooOoO0o . iIii1I11I1II1
  for oOOoo0O00 in self . rloc_set :
   if ( oOOoo0O00 . priority <= o0O0OOOOO ) :
    if ( oOOoo0O00 . unreach_state ( ) and oOOoo0O00 . last_rloc_probe == None ) :
     oOOoo0O00 . last_rloc_probe = lisp_get_timestamp ( )
     if 99 - 99: Ii1I + OoooooooOO * IiII * i11iIiiIii - iIii1I11I1II1
    self . best_rloc_set . append ( oOOoo0O00 )
    if 58 - 58: IiII % i1IIi . i11iIiiIii
    if 5 - 5: OoOoOO00
    if 75 - 75: OOooOOo
    if 60 - 60: ooOoO0o - II111iiii - iIii1I11I1II1
    if 23 - 23: I1ii11iIi11i
    if 68 - 68: OoO0O00 . oO0o / IiII - II111iiii % Oo0Ooo
    if 24 - 24: II111iiii / I1ii11iIi11i + oO0o / Ii1I + IiII % oO0o
    if 86 - 86: I1IiiI
  for oOOoo0O00 in OOoOo :
   if ( oOOoo0O00 . priority < o0O0OOOOO ) : continue
   oOOoo0O00 . delete_from_rloc_probe_list ( self . eid , self . group )
   if 83 - 83: I11i % Ii1I + IiII % I11i / i1IIi . oO0o
  for oOOoo0O00 in self . best_rloc_set :
   if ( oOOoo0O00 . rloc . is_null ( ) ) : continue
   oOOoo0O00 . add_to_rloc_probe_list ( self . eid , self . group )
   if 56 - 56: I1Ii111 - OOooOOo % o0oOOo0O0Ooo
   if 30 - 30: I1Ii111 % i1IIi
   if 98 - 98: oO0o . i11iIiiIii / Ii1I - Ii1I
 def select_rloc ( self , lisp_packet , ipc_socket ) :
  i1II1IiiIi = lisp_packet . packet
  iiIIIiIiI11 = lisp_packet . inner_version
  o00OOo00 = len ( self . best_rloc_set )
  if ( o00OOo00 is 0 ) :
   self . stats . increment ( len ( i1II1IiiIi ) )
   return ( [ None , None , None , self . action , None , None ] )
   if 24 - 24: i1IIi
   if 93 - 93: OoOoOO00 - Oo0Ooo + iIii1I11I1II1 % iIii1I11I1II1 / I1ii11iIi11i - I1Ii111
  IIiI1ii1i = 4 if lisp_load_split_pings else 0
  o0o0oooO00O0 = lisp_packet . hash_ports ( )
  if ( iiIIIiIiI11 == 4 ) :
   for Ii11 in range ( 8 + IIiI1ii1i ) :
    o0o0oooO00O0 = o0o0oooO00O0 ^ struct . unpack ( "B" , i1II1IiiIi [ Ii11 + 12 ] ) [ 0 ]
    if 49 - 49: I1IiiI / iIii1I11I1II1
  elif ( iiIIIiIiI11 == 6 ) :
   for Ii11 in range ( 0 , 32 + IIiI1ii1i , 4 ) :
    o0o0oooO00O0 = o0o0oooO00O0 ^ struct . unpack ( "I" , i1II1IiiIi [ Ii11 + 8 : Ii11 + 12 ] ) [ 0 ]
    if 31 - 31: i1IIi % I11i * o0oOOo0O0Ooo % i1IIi / IiII
   o0o0oooO00O0 = ( o0o0oooO00O0 >> 16 ) + ( o0o0oooO00O0 & 0xffff )
   o0o0oooO00O0 = ( o0o0oooO00O0 >> 8 ) + ( o0o0oooO00O0 & 0xff )
  else :
   for Ii11 in range ( 0 , 12 + IIiI1ii1i , 4 ) :
    o0o0oooO00O0 = o0o0oooO00O0 ^ struct . unpack ( "I" , i1II1IiiIi [ Ii11 : Ii11 + 4 ] ) [ 0 ]
    if 20 - 20: iIii1I11I1II1 . O0
    if 61 - 61: OoOoOO00 * OOooOOo
    if 3 - 3: I1IiiI + Oo0Ooo / I1Ii111
  if ( lisp_data_plane_logging ) :
   IiiI = [ ]
   for O00oo00o000o in self . best_rloc_set :
    if ( O00oo00o000o . rloc . is_null ( ) ) : continue
    IiiI . append ( [ O00oo00o000o . rloc . print_address_no_iid ( ) , O00oo00o000o . print_state ( ) ] )
    if 28 - 28: I1IiiI . O0 % o0oOOo0O0Ooo / I11i
   dprint ( "Packet hash {}, index {}, best-rloc-list: {}" . format ( hex ( o0o0oooO00O0 ) , o0o0oooO00O0 % o00OOo00 , red ( str ( IiiI ) , False ) ) )
   if 48 - 48: II111iiii % I1ii11iIi11i - II111iiii
   if 29 - 29: I1Ii111 - I1Ii111 - I11i * iIii1I11I1II1 % OoO0O00 % IiII
   if 73 - 73: i1IIi . OoooooooOO / OoOoOO00 % Ii1I / Ii1I / Ii1I
   if 40 - 40: I1Ii111 - iIii1I11I1II1
   if 88 - 88: OOooOOo * O0 * OoOoOO00
   if 26 - 26: Ii1I
  oOOoo0O00 = self . best_rloc_set [ o0o0oooO00O0 % o00OOo00 ]
  if 65 - 65: iII111i / iIii1I11I1II1 + I11i - iIii1I11I1II1 - Ii1I . I1Ii111
  if 77 - 77: OoOoOO00 / I1IiiI + IiII
  if 66 - 66: i11iIiiIii * OoooooooOO + iII111i / Ii1I
  if 42 - 42: Ii1I / iIii1I11I1II1 / Oo0Ooo . O0 . oO0o * I1IiiI
  if 21 - 21: OoooooooOO
  O00o = lisp_get_echo_nonce ( oOOoo0O00 . rloc , None )
  if ( O00o ) :
   O00o . change_state ( oOOoo0O00 )
   if ( oOOoo0O00 . no_echoed_nonce_state ( ) ) :
    O00o . request_nonce_sent = None
    if 76 - 76: i1IIi * i11iIiiIii / OOooOOo + I1Ii111
    if 50 - 50: oO0o % OoOoOO00 + I1IiiI
    if 15 - 15: II111iiii - iII111i / I1ii11iIi11i
    if 81 - 81: Ii1I - i1IIi % oO0o * Oo0Ooo * OoOoOO00
    if 79 - 79: oO0o + I1IiiI % iII111i + II111iiii % OoO0O00 % iII111i
    if 46 - 46: o0oOOo0O0Ooo
  if ( oOOoo0O00 . up_state ( ) == False ) :
   OOO = o0o0oooO00O0 % o00OOo00
   iI11I = ( OOO + 1 ) % o00OOo00
   while ( iI11I != OOO ) :
    oOOoo0O00 = self . best_rloc_set [ iI11I ]
    if ( oOOoo0O00 . up_state ( ) ) : break
    iI11I = ( iI11I + 1 ) % o00OOo00
    if 9 - 9: OoO0O00 - OoooooooOO + iIii1I11I1II1
   if ( iI11I == OOO ) :
    self . build_best_rloc_set ( )
    return ( [ None , None , None , None , None , None ] )
    if 71 - 71: I1Ii111 - I1ii11iIi11i * II111iiii % OoOoOO00
    if 74 - 74: II111iiii
    if 23 - 23: I11i * Oo0Ooo
    if 79 - 79: OoO0O00 . OoooooooOO + iII111i
    if 25 - 25: Ii1I * i11iIiiIii / OoOoOO00
    if 54 - 54: i1IIi / I11i % O0 - Ii1I - Oo0Ooo - OoO0O00
  oOOoo0O00 . stats . increment ( len ( i1II1IiiIi ) )
  if 63 - 63: o0oOOo0O0Ooo
  if 46 - 46: Oo0Ooo . ooOoO0o + OoOoOO00 - I11i / i11iIiiIii . iII111i
  if 80 - 80: II111iiii + OoO0O00 % ooOoO0o + i11iIiiIii
  if 30 - 30: Ii1I / I1ii11iIi11i % IiII - Oo0Ooo
  if ( oOOoo0O00 . rle_name and oOOoo0O00 . rle == None ) :
   if ( lisp_rle_list . has_key ( oOOoo0O00 . rle_name ) ) :
    oOOoo0O00 . rle = lisp_rle_list [ oOOoo0O00 . rle_name ]
    if 100 - 100: IiII . I1Ii111 * oO0o % OoO0O00 . iIii1I11I1II1 * Oo0Ooo
    if 100 - 100: IiII - OoOoOO00 % iII111i
  if ( oOOoo0O00 . rle ) : return ( [ None , None , None , None , oOOoo0O00 . rle , None ] )
  if 24 - 24: Oo0Ooo / OoO0O00 + i11iIiiIii
  if 81 - 81: i11iIiiIii . iIii1I11I1II1 - OoooooooOO
  if 52 - 52: O0 - I1Ii111 + oO0o % ooOoO0o . oO0o
  if 60 - 60: oO0o + o0oOOo0O0Ooo - OOooOOo % o0oOOo0O0Ooo . I11i + OoO0O00
  if ( oOOoo0O00 . elp and oOOoo0O00 . elp . use_elp_node ) :
   return ( [ oOOoo0O00 . elp . use_elp_node . address , None , None , None , None ,
 None ] )
   if 27 - 27: i11iIiiIii - I1ii11iIi11i * I1Ii111 . I1IiiI / OoO0O00 * ooOoO0o
   if 42 - 42: OOooOOo
   if 36 - 36: OoooooooOO + ooOoO0o + iII111i
   if 30 - 30: i1IIi % Ii1I
   if 18 - 18: o0oOOo0O0Ooo % I1ii11iIi11i . Ii1I . O0 * II111iiii + I1ii11iIi11i
  II1I1 = None if ( oOOoo0O00 . rloc . is_null ( ) ) else oOOoo0O00 . rloc
  o00o = oOOoo0O00 . translated_port
  oo0oOOo0 = self . action if ( II1I1 == None ) else None
  if 96 - 96: IiII % iII111i . OoOoOO00 / oO0o . OoO0O00
  if 85 - 85: iIii1I11I1II1 / OoOoOO00 * I1ii11iIi11i
  if 26 - 26: iII111i - OoO0O00 . o0oOOo0O0Ooo
  if 50 - 50: I1Ii111 . O0 . OoOoOO00 + I1Ii111 + OoooooooOO . i11iIiiIii
  if 65 - 65: I1IiiI % iIii1I11I1II1
  iI1III = None
  if ( O00o and O00o . request_nonce_timeout ( ) == False ) :
   iI1III = O00o . get_request_or_echo_nonce ( ipc_socket , II1I1 )
   if 52 - 52: I1IiiI
   if 19 - 19: I1IiiI
   if 17 - 17: I11i + OoooooooOO
   if 63 - 63: IiII
   if 3 - 3: oO0o * II111iiii . O0
  return ( [ II1I1 , o00o , iI1III , oo0oOOo0 , None , oOOoo0O00 ] )
  if 19 - 19: I1IiiI / I1IiiI / Oo0Ooo + oO0o + i1IIi
  if 31 - 31: iII111i / OoooooooOO - I1Ii111 . iII111i
 def do_rloc_sets_match ( self , rloc_address_set ) :
  if ( len ( self . rloc_set ) != len ( rloc_address_set ) ) : return ( False )
  if 38 - 38: ooOoO0o . OoooooooOO - II111iiii * i11iIiiIii / i1IIi . OoooooooOO
  if 51 - 51: oO0o - I1ii11iIi11i + I1ii11iIi11i
  if 100 - 100: I11i - I1ii11iIi11i . i1IIi
  if 85 - 85: II111iiii
  if 58 - 58: i1IIi - OoO0O00 + ooOoO0o
  for IIiO0Ooo in self . rloc_set :
   for oOOoo0O00 in rloc_address_set :
    if ( oOOoo0O00 . is_exact_match ( IIiO0Ooo . rloc ) == False ) : continue
    oOOoo0O00 = None
    break
    if 6 - 6: IiII % I1IiiI + OoooooooOO * oO0o . iII111i + oO0o
   if ( oOOoo0O00 == rloc_address_set [ - 1 ] ) : return ( False )
   if 4 - 4: I11i % I1IiiI
  return ( True )
  if 72 - 72: I1IiiI % II111iiii % iII111i / OoOoOO00
  if 96 - 96: OoOoOO00 % Ii1I
 def get_rloc ( self , rloc ) :
  for IIiO0Ooo in self . rloc_set :
   O00oo00o000o = IIiO0Ooo . rloc
   if ( rloc . is_exact_match ( O00oo00o000o ) ) : return ( IIiO0Ooo )
   if 50 - 50: IiII - II111iiii
  return ( None )
  if 10 - 10: OoooooooOO % Ii1I * OOooOOo + IiII * oO0o
  if 13 - 13: II111iiii
 def get_rloc_by_interface ( self , interface ) :
  for IIiO0Ooo in self . rloc_set :
   if ( IIiO0Ooo . interface == interface ) : return ( IIiO0Ooo )
   if 14 - 14: i11iIiiIii . IiII
  return ( None )
  if 70 - 70: Oo0Ooo * OOooOOo + I1Ii111 % OoOoOO00 / O0
  if 23 - 23: O0 * oO0o / I1IiiI + i1IIi * O0 % oO0o
 def add_db ( self ) :
  if ( self . group . is_null ( ) ) :
   lisp_db_for_lookups . add_cache ( self . eid , self )
  else :
   I11i111 = lisp_db_for_lookups . lookup_cache ( self . group , True )
   if ( I11i111 == None ) :
    I11i111 = lisp_mapping ( self . group , self . group , [ ] )
    lisp_db_for_lookups . add_cache ( self . group , I11i111 )
    if 11 - 11: I1Ii111 . OoooooooOO * iIii1I11I1II1 / I1ii11iIi11i - ooOoO0o . iII111i
   I11i111 . add_source_entry ( self )
   if 71 - 71: i11iIiiIii + I11i / i11iIiiIii % Oo0Ooo / iIii1I11I1II1 * OoO0O00
   if 49 - 49: iII111i + OoOoOO00
   if 33 - 33: ooOoO0o
 def add_cache ( self , do_ipc = True ) :
  if ( self . group . is_null ( ) ) :
   lisp_map_cache . add_cache ( self . eid , self )
   if ( lisp_program_hardware ) : lisp_program_vxlan_hardware ( self )
  else :
   Iii1 = lisp_map_cache . lookup_cache ( self . group , True )
   if ( Iii1 == None ) :
    Iii1 = lisp_mapping ( self . group , self . group , [ ] )
    Iii1 . eid . copy_address ( self . group )
    Iii1 . group . copy_address ( self . group )
    lisp_map_cache . add_cache ( self . group , Iii1 )
    if 19 - 19: I1Ii111 % IiII
   if ( self . eid . is_null ( ) ) : self . eid . make_default_route ( Iii1 . group )
   Iii1 . add_source_entry ( self )
   if 94 - 94: I1Ii111 * I1ii11iIi11i * I1ii11iIi11i - o0oOOo0O0Ooo . i11iIiiIii
  if ( do_ipc ) : lisp_write_ipc_map_cache ( True , self )
  if 16 - 16: i1IIi
  if 88 - 88: OOooOOo
 def delete_cache ( self ) :
  self . delete_rlocs_from_rloc_probe_list ( )
  lisp_write_ipc_map_cache ( False , self )
  if 79 - 79: oO0o
  if ( self . group . is_null ( ) ) :
   lisp_map_cache . delete_cache ( self . eid )
   if ( lisp_program_hardware ) :
    OOoOOoo = self . eid . print_prefix_no_iid ( )
    os . system ( "ip route delete {}" . format ( OOoOOoo ) )
    if 13 - 13: oO0o % ooOoO0o % I1IiiI - o0oOOo0O0Ooo
  else :
   Iii1 = lisp_map_cache . lookup_cache ( self . group , True )
   if ( Iii1 == None ) : return
   if 50 - 50: I1Ii111 . I1Ii111 . OoO0O00 + I11i * o0oOOo0O0Ooo
   i111i111I111 = Iii1 . lookup_source_cache ( self . eid , True )
   if ( i111i111I111 == None ) : return
   if 16 - 16: i11iIiiIii
   Iii1 . source_cache . delete_cache ( self . eid )
   if ( Iii1 . source_cache . cache_size ( ) == 0 ) :
    lisp_map_cache . delete_cache ( self . group )
    if 83 - 83: Oo0Ooo / Oo0Ooo . I11i + oO0o % Ii1I
    if 22 - 22: ooOoO0o
    if 83 - 83: OOooOOo - i11iIiiIii - i1IIi / oO0o
    if 33 - 33: OoO0O00 + OOooOOo
 def add_source_entry ( self , source_mc ) :
  if ( self . source_cache == None ) : self . source_cache = lisp_cache ( )
  self . source_cache . add_cache ( source_mc . eid , source_mc )
  if 36 - 36: o0oOOo0O0Ooo . o0oOOo0O0Ooo / oO0o * ooOoO0o * Ii1I * IiII
  if 39 - 39: i1IIi
 def lookup_source_cache ( self , source , exact ) :
  if ( self . source_cache == None ) : return ( None )
  return ( self . source_cache . lookup_cache ( source , exact ) )
  if 79 - 79: ooOoO0o - II111iiii - oO0o
  if 55 - 55: iII111i % iIii1I11I1II1 + Ii1I + oO0o . i11iIiiIii - OOooOOo
 def dynamic_eid_configured ( self ) :
  return ( self . dynamic_eids != None )
  if 14 - 14: oO0o - i11iIiiIii / OoOoOO00 % o0oOOo0O0Ooo / IiII * I1IiiI
  if 2 - 2: i1IIi / I1Ii111 + I1IiiI + I1ii11iIi11i - o0oOOo0O0Ooo + iIii1I11I1II1
 def star_secondary_iid ( self , prefix ) :
  if ( self . secondary_iid == None ) : return ( prefix )
  o0OOoOO = "," + str ( self . secondary_iid )
  return ( prefix . replace ( o0OOoOO , o0OOoOO + "*" ) )
  if 78 - 78: I1ii11iIi11i % i1IIi . I1Ii111 + Oo0Ooo . o0oOOo0O0Ooo % II111iiii
  if 65 - 65: Ii1I . OoOoOO00 + O0 / iIii1I11I1II1 % Ii1I % I1Ii111
 def increment_decap_stats ( self , packet ) :
  o00o = packet . udp_dport
  if ( o00o == LISP_DATA_PORT ) :
   oOOoo0O00 = self . get_rloc ( packet . outer_dest )
  else :
   if 31 - 31: o0oOOo0O0Ooo - Oo0Ooo
   if 15 - 15: O0 + OOooOOo
   if 8 - 8: i11iIiiIii . IiII . I1ii11iIi11i + i1IIi % I1Ii111
   if 64 - 64: I1IiiI . Oo0Ooo * OoO0O00
   for oOOoo0O00 in self . rloc_set :
    if ( oOOoo0O00 . translated_port != 0 ) : break
    if 87 - 87: i1IIi / OoooooooOO
    if 68 - 68: I1Ii111 / iIii1I11I1II1
  if ( oOOoo0O00 != None ) : oOOoo0O00 . stats . increment ( len ( packet . packet ) )
  self . stats . increment ( len ( packet . packet ) )
  if 8 - 8: ooOoO0o * IiII * OOooOOo / I1IiiI
  if 40 - 40: i11iIiiIii + OoooooooOO
 def rtrs_in_rloc_set ( self ) :
  for oOOoo0O00 in self . rloc_set :
   if ( oOOoo0O00 . is_rtr ( ) ) : return ( True )
   if 2 - 2: o0oOOo0O0Ooo * OoO0O00
  return ( False )
  if 88 - 88: Oo0Ooo + oO0o + iII111i
  if 51 - 51: i1IIi + i11iIiiIii * I11i / iII111i + OoooooooOO
  if 89 - 89: i11iIiiIii - I1Ii111 - O0 % iIii1I11I1II1 / IiII - O0
class lisp_dynamic_eid ( ) :
 def __init__ ( self ) :
  self . dynamic_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . uptime = lisp_get_timestamp ( )
  self . interface = None
  self . last_packet = None
  self . timeout = LISP_DEFAULT_DYN_EID_TIMEOUT
  if 63 - 63: OOooOOo
  if 23 - 23: Oo0Ooo / i1IIi - OOooOOo / Oo0Ooo
 def get_timeout ( self , interface ) :
  try :
   IIiiiiII = lisp_myinterfaces [ interface ]
   self . timeout = IIiiiiII . dynamic_eid_timeout
  except :
   self . timeout = LISP_DEFAULT_DYN_EID_TIMEOUT
   if 86 - 86: OOooOOo * OoOoOO00 % i1IIi * IiII . I1ii11iIi11i
   if 72 - 72: i1IIi - I1Ii111 . O0 * OoO0O00
   if 62 - 62: Oo0Ooo . iII111i
   if 15 - 15: i11iIiiIii * I11i + oO0o
class lisp_group_mapping ( ) :
 def __init__ ( self , group_name , ms_name , group_prefix , sources , rle_addr ) :
  self . group_name = group_name
  self . group_prefix = group_prefix
  self . use_ms_name = ms_name
  self . sources = sources
  self . rle_address = rle_addr
  if 67 - 67: IiII . OoO0O00
  if 59 - 59: oO0o * o0oOOo0O0Ooo
 def add_group ( self ) :
  lisp_group_mapping_list [ self . group_name ] = self
  if 76 - 76: I1IiiI
  if 94 - 94: OoooooooOO * I1ii11iIi11i
  if 28 - 28: II111iiii / II111iiii / II111iiii
lisp_site_flags = {
 "P" : "ETR is {}Requesting Map-Server to Proxy Map-Reply" ,
 "S" : "ETR is {}LISP-SEC capable" ,
 "I" : "xTR-ID and site-ID are {}included in Map-Register" ,
 "T" : "Use Map-Register TTL field to timeout registration is {}set" ,
 "R" : "Merging registrations are {}requested" ,
 "M" : "ETR is {}a LISP Mobile-Node" ,
 "N" : "ETR is {}requesting Map-Notify messages from Map-Server"
 }
if 70 - 70: OoO0O00 + O0 * OoO0O00
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
  if 25 - 25: OoooooooOO . Oo0Ooo + OOooOOo + Oo0Ooo * O0 % i1IIi
  if 71 - 71: II111iiii / Ii1I + i1IIi - OoOoOO00 + Ii1I
  if 31 - 31: OoooooooOO * Ii1I - iII111i . oO0o % Ii1I
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
  if 97 - 97: Ii1I
  if 51 - 51: II111iiii . oO0o % iII111i
 def print_eid_tuple ( self ) :
  return ( lisp_print_eid_tuple ( self . eid , self . group ) )
  if 47 - 47: II111iiii - iII111i * I1IiiI . IiII
  if 41 - 41: OoOoOO00 / O0 + I1Ii111 . I1ii11iIi11i
 def print_flags ( self , html ) :
  if ( html == False ) :
   Oo0O = "{}-{}-{}-{}-{}-{}-{}" . format ( "P" if self . proxy_reply_requested else "p" ,
   # iIii1I11I1II1 * I1Ii111 % o0oOOo0O0Ooo
 "S" if self . lisp_sec_present else "s" ,
 "I" if self . xtr_id_present else "i" ,
 "T" if self . use_register_ttl_requested else "t" ,
 "R" if self . merge_register_requested else "r" ,
 "M" if self . mobile_node_requested else "m" ,
 "N" if self . map_notify_requested else "n" )
  else :
   oo00000ooOooO = self . print_flags ( False )
   oo00000ooOooO = oo00000ooOooO . split ( "-" )
   Oo0O = ""
   for iiI1I1 in oo00000ooOooO :
    O0OOo0ooOoo = lisp_site_flags [ iiI1I1 . upper ( ) ]
    O0OOo0ooOoo = O0OOo0ooOoo . format ( "" if iiI1I1 . isupper ( ) else "not " )
    Oo0O += lisp_span ( iiI1I1 , O0OOo0ooOoo )
    if ( iiI1I1 . lower ( ) != "n" ) : Oo0O += "-"
    if 49 - 49: OoOoOO00 % iIii1I11I1II1 + I1Ii111
    if 38 - 38: i11iIiiIii
  return ( Oo0O )
  if 75 - 75: iIii1I11I1II1 / OoO0O00 * OOooOOo % O0
  if 82 - 82: Oo0Ooo / i1IIi . i1IIi / oO0o
 def copy_state_to_parent ( self , child ) :
  self . xtr_id = child . xtr_id
  self . site_id = child . site_id
  self . first_registered = child . first_registered
  self . last_registered = child . last_registered
  self . last_registerer = child . last_registerer
  self . register_ttl = child . register_ttl
  if ( self . registered == False ) :
   self . first_registered = lisp_get_timestamp ( )
   if 7 - 7: Oo0Ooo . iII111i % I1ii11iIi11i / iII111i
  self . auth_sha1_or_sha2 = child . auth_sha1_or_sha2
  self . registered = child . registered
  self . proxy_reply_requested = child . proxy_reply_requested
  self . lisp_sec_present = child . lisp_sec_present
  self . xtr_id_present = child . xtr_id_present
  self . use_register_ttl_requested = child . use_register_ttl_requested
  self . merge_register_requested = child . merge_register_requested
  self . mobile_node_requested = child . mobile_node_requested
  self . map_notify_requested = child . map_notify_requested
  if 93 - 93: iII111i
  if 5 - 5: iII111i . I11i % I11i * Ii1I - I1ii11iIi11i . i11iIiiIii
 def build_sort_key ( self ) :
  iI1II = lisp_cache ( )
  ii1I1I1iII , o0OoOo0o0OOoO0 = iI1II . build_key ( self . eid )
  O00i1IIi1 = ""
  if ( self . group . is_null ( ) == False ) :
   OOOoo0O0 , O00i1IIi1 = iI1II . build_key ( self . group )
   O00i1IIi1 = "-" + O00i1IIi1 [ 0 : 12 ] + "-" + str ( OOOoo0O0 ) + "-" + O00i1IIi1 [ 12 : : ]
   if 61 - 61: IiII / oO0o . I1Ii111 - IiII * IiII - iII111i
  o0OoOo0o0OOoO0 = o0OoOo0o0OOoO0 [ 0 : 12 ] + "-" + str ( ii1I1I1iII ) + "-" + o0OoOo0o0OOoO0 [ 12 : : ] + O00i1IIi1
  del ( iI1II )
  return ( o0OoOo0o0OOoO0 )
  if 49 - 49: Ii1I
  if 91 - 91: Ii1I / ooOoO0o % iII111i
 def merge_in_site_eid ( self , child ) :
  oo0O = False
  if ( self . group . is_null ( ) ) :
   self . merge_rlocs_in_site_eid ( )
  else :
   oo0O = self . merge_rles_in_site_eid ( )
   if 64 - 64: OoooooooOO / II111iiii + II111iiii . I1Ii111 . OoOoOO00
   if 75 - 75: Oo0Ooo + I11i
   if 87 - 87: I1IiiI
   if 36 - 36: OoO0O00 . ooOoO0o . O0 / OoO0O00
   if 50 - 50: Ii1I . OoOoOO00 * o0oOOo0O0Ooo
   if 68 - 68: IiII * oO0o / OoOoOO00 / I1Ii111
  if ( child != None ) :
   self . copy_state_to_parent ( child )
   self . map_registers_received += 1
   if 72 - 72: I1ii11iIi11i
  return ( oo0O )
  if 74 - 74: I1Ii111 * iIii1I11I1II1 / oO0o - IiII - I1IiiI
  if 84 - 84: iIii1I11I1II1 % Oo0Ooo / I1ii11iIi11i + o0oOOo0O0Ooo * II111iiii
 def copy_rloc_records ( self ) :
  oooO0oO0OO000OOo = [ ]
  for IIiO0Ooo in self . registered_rlocs :
   oooO0oO0OO000OOo . append ( copy . deepcopy ( IIiO0Ooo ) )
   if 64 - 64: I1ii11iIi11i - iIii1I11I1II1 + I1Ii111 . oO0o . iIii1I11I1II1
  return ( oooO0oO0OO000OOo )
  if 79 - 79: OoOoOO00 . ooOoO0o
  if 22 - 22: oO0o + Ii1I - ooOoO0o + OoOoOO00 % OOooOOo - Oo0Ooo
 def merge_rlocs_in_site_eid ( self ) :
  self . registered_rlocs = [ ]
  for ooOOOo0o0oo in self . individual_registrations . values ( ) :
   if ( self . site_id != ooOOOo0o0oo . site_id ) : continue
   if ( ooOOOo0o0oo . registered == False ) : continue
   self . registered_rlocs += ooOOOo0o0oo . copy_rloc_records ( )
   if 59 - 59: OoOoOO00 * iII111i - OOooOOo
   if 49 - 49: I1ii11iIi11i / oO0o . oO0o * iII111i % iII111i . I1IiiI
   if 96 - 96: II111iiii / OoooooooOO + iIii1I11I1II1 . Ii1I + OoooooooOO
   if 62 - 62: OoOoOO00 + OoOoOO00 % OOooOOo * iII111i
   if 24 - 24: Oo0Ooo % i1IIi
   if 50 - 50: OoO0O00
  oooO0oO0OO000OOo = [ ]
  for IIiO0Ooo in self . registered_rlocs :
   if ( IIiO0Ooo . rloc . is_null ( ) or len ( oooO0oO0OO000OOo ) == 0 ) :
    oooO0oO0OO000OOo . append ( IIiO0Ooo )
    continue
    if 52 - 52: o0oOOo0O0Ooo + O0
   for iIIiI11 in oooO0oO0OO000OOo :
    if ( iIIiI11 . rloc . is_null ( ) ) : continue
    if ( IIiO0Ooo . rloc . is_exact_match ( iIIiI11 . rloc ) ) : break
    if 59 - 59: OoOoOO00 % O0 * I1Ii111 - i1IIi
   if ( iIIiI11 == oooO0oO0OO000OOo [ - 1 ] ) : oooO0oO0OO000OOo . append ( IIiO0Ooo )
   if 68 - 68: OOooOOo % IiII / Oo0Ooo + OoOoOO00
  self . registered_rlocs = oooO0oO0OO000OOo
  if 11 - 11: OoO0O00
  if 70 - 70: o0oOOo0O0Ooo * O0 * II111iiii
  if 38 - 38: OoO0O00 - I1IiiI * OoooooooOO / I11i . O0
  if 77 - 77: OOooOOo + oO0o * iIii1I11I1II1 / oO0o / OOooOOo . i11iIiiIii
  if ( len ( self . registered_rlocs ) == 0 ) : self . registered = False
  return
  if 92 - 92: Oo0Ooo . o0oOOo0O0Ooo % OoooooooOO * i11iIiiIii * OoO0O00 * o0oOOo0O0Ooo
  if 48 - 48: iII111i * I1ii11iIi11i * oO0o % O0 . OoO0O00
 def merge_rles_in_site_eid ( self ) :
  if 11 - 11: OOooOOo / o0oOOo0O0Ooo
  if 98 - 98: oO0o + I11i . oO0o
  if 10 - 10: iII111i + i1IIi . I11i % ooOoO0o / ooOoO0o
  if 86 - 86: Oo0Ooo
  i11 = { }
  for IIiO0Ooo in self . registered_rlocs :
   if ( IIiO0Ooo . rle == None ) : continue
   for OOoo0Oo00 in IIiO0Ooo . rle . rle_nodes :
    o0o0O00 = OOoo0Oo00 . address . print_address_no_iid ( )
    i11 [ o0o0O00 ] = OOoo0Oo00 . address
    if 37 - 37: iII111i * II111iiii - IiII - O0 - i11iIiiIii / OOooOOo
   break
   if 76 - 76: OOooOOo
   if 31 - 31: OOooOOo + i1IIi / Ii1I / OoOoOO00 % OoO0O00 + Oo0Ooo
   if 84 - 84: i1IIi / i1IIi * oO0o * i11iIiiIii
   if 92 - 92: iII111i - Ii1I . iIii1I11I1II1 . iII111i + ooOoO0o % OoOoOO00
   if 38 - 38: OOooOOo . I11i - oO0o
  self . merge_rlocs_in_site_eid ( )
  if 85 - 85: O0 * I1IiiI . Oo0Ooo - IiII
  if 84 - 84: I1Ii111 . iIii1I11I1II1 . O0 * I1ii11iIi11i
  if 59 - 59: i1IIi . o0oOOo0O0Ooo . Oo0Ooo * I1Ii111 + OoooooooOO
  if 11 - 11: I11i * ooOoO0o % iIii1I11I1II1 - O0
  if 68 - 68: ooOoO0o * OoooooooOO - OoooooooOO
  if 59 - 59: Ii1I / I11i / I1Ii111 + IiII * I1ii11iIi11i
  if 18 - 18: O0
  if 60 - 60: II111iiii % O0 - I1Ii111 / iII111i / I1IiiI
  oooOiI = [ ]
  for IIiO0Ooo in self . registered_rlocs :
   if ( self . registered_rlocs . index ( IIiO0Ooo ) == 0 ) :
    oooOiI . append ( IIiO0Ooo )
    continue
    if 52 - 52: oO0o
   if ( IIiO0Ooo . rle == None ) : oooOiI . append ( IIiO0Ooo )
   if 56 - 56: ooOoO0o
  self . registered_rlocs = oooOiI
  if 94 - 94: OoOoOO00
  if 12 - 12: I11i * OoooooooOO + ooOoO0o
  if 16 - 16: IiII
  if 100 - 100: OoO0O00 % Oo0Ooo - OoooooooOO
  if 48 - 48: IiII / I11i * OoooooooOO
  if 1 - 1: I1ii11iIi11i + I11i
  if 54 - 54: IiII * O0 * I1Ii111 + i1IIi - I11i . I11i
  iiiI1i1111II = lisp_rle ( "" )
  iI1iiiiiiiiI = { }
  I1IiiIoo0o00O = None
  for ooOOOo0o0oo in self . individual_registrations . values ( ) :
   if ( ooOOOo0o0oo . registered == False ) : continue
   o0o0O0o0000 = ooOOOo0o0oo . registered_rlocs [ 0 ] . rle
   if ( o0o0O0o0000 == None ) : continue
   if 81 - 81: O0 . IiII
   I1IiiIoo0o00O = ooOOOo0o0oo . registered_rlocs [ 0 ] . rloc_name
   for oooOOO0 in o0o0O0o0000 . rle_nodes :
    o0o0O00 = oooOOO0 . address . print_address_no_iid ( )
    if ( iI1iiiiiiiiI . has_key ( o0o0O00 ) ) : break
    if 53 - 53: I1Ii111 . i11iIiiIii * i1IIi . Oo0Ooo + I11i * i11iIiiIii
    OOoo0Oo00 = lisp_rle_node ( )
    OOoo0Oo00 . address . copy_address ( oooOOO0 . address )
    OOoo0Oo00 . level = oooOOO0 . level
    OOoo0Oo00 . rloc_name = I1IiiIoo0o00O
    iiiI1i1111II . rle_nodes . append ( OOoo0Oo00 )
    iI1iiiiiiiiI [ o0o0O00 ] = oooOOO0 . address
    if 75 - 75: OoOoOO00 % OoooooooOO + OoOoOO00
    if 46 - 46: IiII
    if 53 - 53: iII111i + oO0o % O0
    if 92 - 92: O0 / iIii1I11I1II1
    if 72 - 72: o0oOOo0O0Ooo / iII111i - I1ii11iIi11i . II111iiii
    if 95 - 95: II111iiii / I11i / ooOoO0o - I1Ii111 % i11iIiiIii
  if ( len ( iiiI1i1111II . rle_nodes ) == 0 ) : iiiI1i1111II = None
  if ( len ( self . registered_rlocs ) != 0 ) :
   self . registered_rlocs [ 0 ] . rle = iiiI1i1111II
   if ( I1IiiIoo0o00O ) : self . registered_rlocs [ 0 ] . rloc_name = None
   if 53 - 53: iII111i
   if 45 - 45: OOooOOo * I1IiiI / oO0o . Ii1I - OoO0O00 % OOooOOo
   if 40 - 40: I11i
   if 69 - 69: OoOoOO00 + OoOoOO00 + o0oOOo0O0Ooo / iIii1I11I1II1 * OoO0O00
   if 44 - 44: II111iiii / o0oOOo0O0Ooo
  if ( i11 . keys ( ) == iI1iiiiiiiiI . keys ( ) ) : return ( False )
  if 81 - 81: I1Ii111 . Ii1I * ooOoO0o . IiII - OoOoOO00
  lprint ( "{} {} from {} to {}" . format ( green ( self . print_eid_tuple ( ) , False ) , bold ( "RLE change" , False ) ,
  # I1ii11iIi11i / O0 * O0 - IiII * OOooOOo
 i11 . keys ( ) , iI1iiiiiiiiI . keys ( ) ) )
  if 68 - 68: II111iiii
  return ( True )
  if 12 - 12: oO0o + I1IiiI * Oo0Ooo - iII111i
  if 88 - 88: OOooOOo . OoO0O00
 def add_cache ( self ) :
  if ( self . group . is_null ( ) ) :
   lisp_sites_by_eid . add_cache ( self . eid , self )
  else :
   I11IiI1ii = lisp_sites_by_eid . lookup_cache ( self . group , True )
   if ( I11IiI1ii == None ) :
    I11IiI1ii = lisp_site_eid ( self . site )
    I11IiI1ii . eid . copy_address ( self . group )
    I11IiI1ii . group . copy_address ( self . group )
    lisp_sites_by_eid . add_cache ( self . group , I11IiI1ii )
    if 86 - 86: OoOoOO00 . o0oOOo0O0Ooo / ooOoO0o * I1IiiI . OoO0O00 / I1Ii111
    if 47 - 47: I11i . iII111i * OoOoOO00 % OoooooooOO
    if 59 - 59: OoooooooOO + I1ii11iIi11i - I11i / I1IiiI * oO0o
    if 90 - 90: I1Ii111 + i1IIi * I1Ii111 / I11i * Oo0Ooo
    if 27 - 27: OoooooooOO
    I11IiI1ii . parent_for_more_specifics = self . parent_for_more_specifics
    if 42 - 42: OoO0O00 + OoOoOO00
   if ( self . eid . is_null ( ) ) : self . eid . make_default_route ( I11IiI1ii . group )
   I11IiI1ii . add_source_entry ( self )
   if 52 - 52: iII111i * OoOoOO00
   if 80 - 80: I1Ii111 / IiII * o0oOOo0O0Ooo - OoOoOO00 / iIii1I11I1II1
   if 38 - 38: II111iiii / I11i + IiII % OoooooooOO
 def delete_cache ( self ) :
  if ( self . group . is_null ( ) ) :
   lisp_sites_by_eid . delete_cache ( self . eid )
  else :
   I11IiI1ii = lisp_sites_by_eid . lookup_cache ( self . group , True )
   if ( I11IiI1ii == None ) : return
   if 27 - 27: OoOoOO00 * OoO0O00 * OOooOOo % I1IiiI * o0oOOo0O0Ooo + I1ii11iIi11i
   ooOOOo0o0oo = I11IiI1ii . lookup_source_cache ( self . eid , True )
   if ( ooOOOo0o0oo == None ) : return
   if 73 - 73: i1IIi
   if ( I11IiI1ii . source_cache == None ) : return
   if 52 - 52: IiII / i11iIiiIii * O0
   I11IiI1ii . source_cache . delete_cache ( self . eid )
   if ( I11IiI1ii . source_cache . cache_size ( ) == 0 ) :
    lisp_sites_by_eid . delete_cache ( self . group )
    if 67 - 67: OOooOOo / I11i - I1Ii111 % i11iIiiIii
    if 3 - 3: oO0o + iII111i + OOooOOo
    if 54 - 54: i11iIiiIii + OoO0O00 - IiII - iII111i / I11i
    if 85 - 85: OOooOOo * OOooOOo * I1Ii111 - ooOoO0o . O0 % iII111i
 def add_source_entry ( self , source_se ) :
  if ( self . source_cache == None ) : self . source_cache = lisp_cache ( )
  self . source_cache . add_cache ( source_se . eid , source_se )
  if 5 - 5: i1IIi * iII111i . o0oOOo0O0Ooo - I1ii11iIi11i
  if 84 - 84: i1IIi
 def lookup_source_cache ( self , source , exact ) :
  if ( self . source_cache == None ) : return ( None )
  return ( self . source_cache . lookup_cache ( source , exact ) )
  if 17 - 17: IiII + iII111i * OoO0O00 / iII111i
  if 67 - 67: i1IIi * IiII . OoOoOO00 % iIii1I11I1II1 - iIii1I11I1II1 * I1ii11iIi11i
 def is_star_g ( self ) :
  if ( self . group . is_null ( ) ) : return ( False )
  return ( self . eid . is_exact_match ( self . group ) )
  if 96 - 96: iII111i / i11iIiiIii / oO0o + Oo0Ooo
  if 65 - 65: OoOoOO00
 def eid_record_matches ( self , eid_record ) :
  if ( self . eid . is_exact_match ( eid_record . eid ) == False ) : return ( False )
  if ( eid_record . group . is_null ( ) ) : return ( True )
  return ( eid_record . group . is_exact_match ( self . group ) )
  if 87 - 87: I11i % i1IIi + i11iIiiIii * II111iiii
  if 58 - 58: OoO0O00 * I1IiiI - II111iiii / Ii1I - I1IiiI % OoooooooOO
 def inherit_from_ams_parent ( self ) :
  iiiIIIII1iIi = self . parent_for_more_specifics
  if ( iiiIIIII1iIi == None ) : return
  self . force_proxy_reply = iiiIIIII1iIi . force_proxy_reply
  self . force_nat_proxy_reply = iiiIIIII1iIi . force_nat_proxy_reply
  self . force_ttl = iiiIIIII1iIi . force_ttl
  self . pitr_proxy_reply_drop = iiiIIIII1iIi . pitr_proxy_reply_drop
  self . proxy_reply_action = iiiIIIII1iIi . proxy_reply_action
  self . echo_nonce_capable = iiiIIIII1iIi . echo_nonce_capable
  self . policy = iiiIIIII1iIi . policy
  self . require_signature = iiiIIIII1iIi . require_signature
  if 33 - 33: IiII / i1IIi + I1Ii111
  if 5 - 5: O0 / iII111i % II111iiii . Oo0Ooo - I11i
 def rtrs_in_rloc_set ( self ) :
  for IIiO0Ooo in self . registered_rlocs :
   if ( IIiO0Ooo . is_rtr ( ) ) : return ( True )
   if 84 - 84: oO0o * iII111i % i11iIiiIii - O0 . iIii1I11I1II1 - OoOoOO00
  return ( False )
  if 73 - 73: OoOoOO00
  if 66 - 66: Oo0Ooo
 def is_rtr_in_rloc_set ( self , rtr_rloc ) :
  for IIiO0Ooo in self . registered_rlocs :
   if ( IIiO0Ooo . rloc . is_exact_match ( rtr_rloc ) == False ) : continue
   if ( IIiO0Ooo . is_rtr ( ) ) : return ( True )
   if 42 - 42: i11iIiiIii / II111iiii . OOooOOo
  return ( False )
  if 65 - 65: OoOoOO00 % II111iiii + Oo0Ooo
  if 24 - 24: OoO0O00 % OoooooooOO
 def is_rloc_in_rloc_set ( self , rloc ) :
  for IIiO0Ooo in self . registered_rlocs :
   if ( IIiO0Ooo . rle ) :
    for iiiI1i1111II in IIiO0Ooo . rle . rle_nodes :
     if ( iiiI1i1111II . address . is_exact_match ( rloc ) ) : return ( True )
     if 16 - 16: OoOoOO00 % Oo0Ooo * OoOoOO00 . Ii1I
     if 91 - 91: I1Ii111 - OoooooooOO . i1IIi . I1ii11iIi11i
   if ( IIiO0Ooo . rloc . is_exact_match ( rloc ) ) : return ( True )
   if 37 - 37: IiII - oO0o
  return ( False )
  if 92 - 92: I1IiiI
  if 51 - 51: OoO0O00 + Oo0Ooo - OOooOOo + I1ii11iIi11i
 def do_rloc_sets_match ( self , prev_rloc_set ) :
  if ( len ( self . registered_rlocs ) != len ( prev_rloc_set ) ) : return ( False )
  if 32 - 32: I1ii11iIi11i % OoOoOO00 + Oo0Ooo
  for IIiO0Ooo in prev_rloc_set :
   I1I1ii1 = IIiO0Ooo . rloc
   if ( self . is_rloc_in_rloc_set ( I1I1ii1 ) == False ) : return ( False )
   if 92 - 92: II111iiii . O0 . iIii1I11I1II1 % IiII - i11iIiiIii
  return ( True )
  if 9 - 9: OoO0O00
  if 60 - 60: O0 / OoOoOO00 % i11iIiiIii % II111iiii / OoooooooOO
  if 52 - 52: ooOoO0o
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
   if 100 - 100: Oo0Ooo - o0oOOo0O0Ooo + iIii1I11I1II1 / ooOoO0o % iIii1I11I1II1
  self . last_used = 0
  self . last_reply = 0
  self . last_nonce = 0
  self . map_requests_sent = 0
  self . neg_map_replies_received = 0
  self . total_rtt = 0
  if 4 - 4: OoOoOO00 / Oo0Ooo - OoO0O00 . OoOoOO00 / I1Ii111
  if 60 - 60: OOooOOo * I1Ii111
 def resolve_dns_name ( self ) :
  if ( self . dns_name == None ) : return
  if ( self . last_dns_resolve and
 time . time ( ) - self . last_dns_resolve < 30 ) : return
  if 17 - 17: iII111i * I11i / iIii1I11I1II1 - II111iiii
  try :
   iI1 = socket . gethostbyname_ex ( self . dns_name )
   self . last_dns_resolve = lisp_get_timestamp ( )
   ooOoooOo00Ooo = iI1 [ 2 ]
  except :
   return
   if 95 - 95: I11i . IiII
   if 5 - 5: OoooooooOO + I1IiiI % OOooOOo + ooOoO0o . o0oOOo0O0Ooo * i11iIiiIii
   if 43 - 43: I1IiiI - oO0o + OOooOOo * OoooooooOO
   if 92 - 92: i11iIiiIii / II111iiii * OoO0O00
   if 51 - 51: I1ii11iIi11i
   if 95 - 95: I1IiiI / iII111i + i1IIi
  if ( len ( ooOoooOo00Ooo ) <= self . a_record_index ) :
   self . delete_mr ( )
   return
   if 31 - 31: OoOoOO00
   if 37 - 37: iIii1I11I1II1 % IiII / i11iIiiIii - oO0o
  o0o0O00 = ooOoooOo00Ooo [ self . a_record_index ]
  if ( o0o0O00 != self . map_resolver . print_address_no_iid ( ) ) :
   self . delete_mr ( )
   self . map_resolver . store_address ( o0o0O00 )
   self . insert_mr ( )
   if 43 - 43: II111iiii - OoooooooOO
   if 11 - 11: I1IiiI
   if 76 - 76: iII111i - II111iiii % Oo0Ooo . I1Ii111
   if 64 - 64: OoO0O00 - OoO0O00
   if 93 - 93: Oo0Ooo . O0
   if 75 - 75: iII111i * II111iiii - I1IiiI
  if ( lisp_is_decent_dns_suffix ( self . dns_name ) == False ) : return
  if ( self . a_record_index != 0 ) : return
  if 30 - 30: i1IIi / ooOoO0o . ooOoO0o
  for o0o0O00 in ooOoooOo00Ooo [ 1 : : ] :
   oOO0oo = lisp_address ( LISP_AFI_NONE , o0o0O00 , 0 , 0 )
   IIiIII1IIi = lisp_get_map_resolver ( oOO0oo , None )
   if ( IIiIII1IIi != None and IIiIII1IIi . a_record_index == ooOoooOo00Ooo . index ( o0o0O00 ) ) :
    continue
    if 22 - 22: I11i % iIii1I11I1II1 - i11iIiiIii * OoOoOO00 - I1Ii111
   IIiIII1IIi = lisp_mr ( o0o0O00 , None , None )
   IIiIII1IIi . a_record_index = ooOoooOo00Ooo . index ( o0o0O00 )
   IIiIII1IIi . dns_name = self . dns_name
   IIiIII1IIi . last_dns_resolve = lisp_get_timestamp ( )
   if 97 - 97: i11iIiiIii . OoOoOO00 + oO0o * O0 % OoO0O00 - Ii1I
   if 46 - 46: I1Ii111
   if 87 - 87: o0oOOo0O0Ooo - iII111i * OoO0O00 * o0oOOo0O0Ooo . o0oOOo0O0Ooo / OOooOOo
   if 50 - 50: i11iIiiIii - II111iiii * OoooooooOO + II111iiii - ooOoO0o
   if 52 - 52: i1IIi + i1IIi * i1IIi / OoOoOO00
  O0iIIiii1ii1III = [ ]
  for IIiIII1IIi in lisp_map_resolvers_list . values ( ) :
   if ( self . dns_name != IIiIII1IIi . dns_name ) : continue
   oOO0oo = IIiIII1IIi . map_resolver . print_address_no_iid ( )
   if ( oOO0oo in ooOoooOo00Ooo ) : continue
   O0iIIiii1ii1III . append ( IIiIII1IIi )
   if 91 - 91: OoOoOO00 * I1IiiI - Oo0Ooo
  for IIiIII1IIi in O0iIIiii1ii1III : IIiIII1IIi . delete_mr ( )
  if 36 - 36: O0 - IiII % iII111i
  if 93 - 93: OoooooooOO . iIii1I11I1II1 % OoO0O00 / I11i + oO0o % OOooOOo
 def insert_mr ( self ) :
  o0OoOo0o0OOoO0 = self . mr_name + self . map_resolver . print_address ( )
  lisp_map_resolvers_list [ o0OoOo0o0OOoO0 ] = self
  if 9 - 9: IiII . Oo0Ooo - iIii1I11I1II1 / I1Ii111
  if 66 - 66: ooOoO0o * I1Ii111 - II111iiii
 def delete_mr ( self ) :
  o0OoOo0o0OOoO0 = self . mr_name + self . map_resolver . print_address ( )
  if ( lisp_map_resolvers_list . has_key ( o0OoOo0o0OOoO0 ) == False ) : return
  lisp_map_resolvers_list . pop ( o0OoOo0o0OOoO0 )
  if 38 - 38: O0 % I1ii11iIi11i + O0
  if 37 - 37: Oo0Ooo / I1IiiI
  if 23 - 23: II111iiii / iII111i
class lisp_ddt_root ( ) :
 def __init__ ( self ) :
  self . root_address = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . public_key = ""
  self . priority = 0
  self . weight = 0
  if 55 - 55: i11iIiiIii - Ii1I % OoooooooOO * OoooooooOO
  if 92 - 92: iIii1I11I1II1
  if 47 - 47: Oo0Ooo + Oo0Ooo * ooOoO0o - OoOoOO00 + II111iiii
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
  if 10 - 10: II111iiii / ooOoO0o . Ii1I / I1Ii111 / oO0o
  if 8 - 8: OOooOOo / ooOoO0o * I11i + OOooOOo * i1IIi
 def print_referral ( self , eid_indent , referral_indent ) :
  iIiI1I1Ii = lisp_print_elapsed ( self . uptime )
  I1i1iiI1iI = lisp_print_future ( self . expires )
  lprint ( "{}Referral EID {}, uptime/expires {}/{}, {} referrals:" . format ( eid_indent , green ( self . eid . print_prefix ( ) , False ) , iIiI1I1Ii ,
  # IiII / o0oOOo0O0Ooo - IiII . I11i - I1Ii111 * o0oOOo0O0Ooo
 I1i1iiI1iI , len ( self . referral_set ) ) )
  if 75 - 75: OoO0O00 / II111iiii - I1Ii111
  for oo00OO in self . referral_set . values ( ) :
   oo00OO . print_ref_node ( referral_indent )
   if 95 - 95: OOooOOo / OoOoOO00 + I1ii11iIi11i
   if 86 - 86: O0 / Ii1I . OoooooooOO . O0
   if 87 - 87: Ii1I + o0oOOo0O0Ooo + OoooooooOO . Ii1I
 def print_referral_type ( self ) :
  if ( self . eid . afi == LISP_AFI_ULTIMATE_ROOT ) : return ( "root" )
  if ( self . referral_type == LISP_DDT_ACTION_NULL ) :
   return ( "null-referral" )
   if 73 - 73: o0oOOo0O0Ooo + OoooooooOO - I1Ii111 . iIii1I11I1II1
  if ( self . referral_type == LISP_DDT_ACTION_SITE_NOT_FOUND ) :
   return ( "no-site-action" )
   if 25 - 25: OoooooooOO % I1ii11iIi11i % Oo0Ooo % i11iIiiIii
  if ( self . referral_type > LISP_DDT_ACTION_MAX ) :
   return ( "invalid-action" )
   if 8 - 8: O0 - O0 % Ii1I
  return ( lisp_map_referral_action_string [ self . referral_type ] )
  if 22 - 22: OoOoOO00
  if 85 - 85: II111iiii - II111iiii
 def print_eid_tuple ( self ) :
  return ( lisp_print_eid_tuple ( self . eid , self . group ) )
  if 95 - 95: II111iiii + II111iiii + iII111i
  if 38 - 38: OoO0O00 * Ii1I * O0 / I1IiiI
 def print_ttl ( self ) :
  oooOooOO = self . referral_ttl
  if ( oooOooOO < 60 ) : return ( str ( oooOooOO ) + " secs" )
  if 99 - 99: Oo0Ooo + ooOoO0o - I1ii11iIi11i + I1Ii111 + Ii1I * I1IiiI
  if ( ( oooOooOO % 60 ) == 0 ) :
   oooOooOO = str ( oooOooOO / 60 ) + " mins"
  else :
   oooOooOO = str ( oooOooOO ) + " secs"
   if 68 - 68: OoO0O00
  return ( oooOooOO )
  if 79 - 79: Ii1I . IiII + OoOoOO00
  if 10 - 10: OoooooooOO * iII111i * ooOoO0o . Ii1I % I1Ii111 / I1ii11iIi11i
 def is_referral_negative ( self ) :
  return ( self . referral_type in ( LISP_DDT_ACTION_MS_NOT_REG , LISP_DDT_ACTION_DELEGATION_HOLE ,
  # Oo0Ooo / IiII % OOooOOo . II111iiii % i11iIiiIii
 LISP_DDT_ACTION_NOT_AUTH ) )
  if 52 - 52: iII111i - OOooOOo . OoooooooOO / IiII % Ii1I
  if 40 - 40: oO0o
 def add_cache ( self ) :
  if ( self . group . is_null ( ) ) :
   lisp_referral_cache . add_cache ( self . eid , self )
  else :
   iii = lisp_referral_cache . lookup_cache ( self . group , True )
   if ( iii == None ) :
    iii = lisp_referral ( )
    iii . eid . copy_address ( self . group )
    iii . group . copy_address ( self . group )
    lisp_referral_cache . add_cache ( self . group , iii )
    if 4 - 4: o0oOOo0O0Ooo + I1IiiI - O0 - iIii1I11I1II1
   if ( self . eid . is_null ( ) ) : self . eid . make_default_route ( iii . group )
   iii . add_source_entry ( self )
   if 56 - 56: OOooOOo * o0oOOo0O0Ooo - O0
   if 45 - 45: OOooOOo - OoO0O00
   if 49 - 49: OoOoOO00 / o0oOOo0O0Ooo % OoO0O00
 def delete_cache ( self ) :
  if ( self . group . is_null ( ) ) :
   lisp_referral_cache . delete_cache ( self . eid )
  else :
   iii = lisp_referral_cache . lookup_cache ( self . group , True )
   if ( iii == None ) : return
   if 50 - 50: iIii1I11I1II1 - OoooooooOO + I1ii11iIi11i / Oo0Ooo * OOooOOo
   Ii1 = iii . lookup_source_cache ( self . eid , True )
   if ( Ii1 == None ) : return
   if 37 - 37: O0 % I1Ii111 * OOooOOo / OOooOOo
   iii . source_cache . delete_cache ( self . eid )
   if ( iii . source_cache . cache_size ( ) == 0 ) :
    lisp_referral_cache . delete_cache ( self . group )
    if 95 - 95: I1ii11iIi11i % o0oOOo0O0Ooo . oO0o
    if 9 - 9: OoOoOO00 % OoOoOO00 * ooOoO0o / I1IiiI - OOooOOo
    if 62 - 62: Oo0Ooo + OOooOOo - Oo0Ooo
    if 32 - 32: OoooooooOO
 def add_source_entry ( self , source_ref ) :
  if ( self . source_cache == None ) : self . source_cache = lisp_cache ( )
  self . source_cache . add_cache ( source_ref . eid , source_ref )
  if 99 - 99: II111iiii % Oo0Ooo / OOooOOo / I1ii11iIi11i % O0 + i1IIi
  if 90 - 90: OoOoOO00 % OoO0O00 . I1IiiI * oO0o
 def lookup_source_cache ( self , source , exact ) :
  if ( self . source_cache == None ) : return ( None )
  return ( self . source_cache . lookup_cache ( source , exact ) )
  if 17 - 17: O0 - i1IIi
  if 77 - 77: OOooOOo - i1IIi / II111iiii . I1Ii111 + O0
  if 1 - 1: OoooooooOO % iIii1I11I1II1 * I1ii11iIi11i
class lisp_referral_node ( ) :
 def __init__ ( self ) :
  self . referral_address = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . priority = 0
  self . weight = 0
  self . updown = True
  self . map_requests_sent = 0
  self . no_responses = 0
  self . uptime = lisp_get_timestamp ( )
  if 17 - 17: Ii1I * i1IIi % OoO0O00
  if 12 - 12: I1ii11iIi11i
 def print_ref_node ( self , indent ) :
  OOOO0O00o = lisp_print_elapsed ( self . uptime )
  lprint ( "{}referral {}, uptime {}, {}, priority/weight: {}/{}" . format ( indent , red ( self . referral_address . print_address ( ) , False ) , OOOO0O00o ,
  # I11i / iII111i . i11iIiiIii % Oo0Ooo + I1ii11iIi11i / i11iIiiIii
 "up" if self . updown else "down" , self . priority , self . weight ) )
  if 94 - 94: i1IIi * i1IIi / Ii1I
  if 38 - 38: O0 % I11i - I11i / iIii1I11I1II1 - II111iiii
  if 13 - 13: II111iiii * OoO0O00 - iIii1I11I1II1
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
   if 30 - 30: O0 - O0 - I1Ii111
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
   if 88 - 88: o0oOOo0O0Ooo % I1Ii111
   if 4 - 4: i11iIiiIii + o0oOOo0O0Ooo % I11i - I1ii11iIi11i * I1ii11iIi11i
   if 87 - 87: I1Ii111 % i11iIiiIii + O0
 def resolve_dns_name ( self ) :
  if ( self . dns_name == None ) : return
  if ( self . last_dns_resolve and
 time . time ( ) - self . last_dns_resolve < 30 ) : return
  if 67 - 67: OoooooooOO / i1IIi / ooOoO0o . i1IIi - i11iIiiIii . i1IIi
  try :
   iI1 = socket . gethostbyname_ex ( self . dns_name )
   self . last_dns_resolve = lisp_get_timestamp ( )
   ooOoooOo00Ooo = iI1 [ 2 ]
  except :
   return
   if 41 - 41: i11iIiiIii / ooOoO0o - Ii1I + I11i
   if 15 - 15: I1ii11iIi11i
   if 22 - 22: iIii1I11I1II1 - i1IIi - i11iIiiIii / I1IiiI + o0oOOo0O0Ooo
   if 56 - 56: I1IiiI . ooOoO0o
   if 35 - 35: iIii1I11I1II1 % Oo0Ooo + o0oOOo0O0Ooo * o0oOOo0O0Ooo % ooOoO0o
   if 10 - 10: I1ii11iIi11i / II111iiii % II111iiii - OoooooooOO * o0oOOo0O0Ooo / ooOoO0o
  if ( len ( ooOoooOo00Ooo ) <= self . a_record_index ) :
   self . delete_ms ( )
   return
   if 26 - 26: OoO0O00 . O0 * iII111i % OoOoOO00 % iIii1I11I1II1
   if 37 - 37: iII111i - ooOoO0o * Ii1I + II111iiii * i11iIiiIii
  o0o0O00 = ooOoooOo00Ooo [ self . a_record_index ]
  if ( o0o0O00 != self . map_server . print_address_no_iid ( ) ) :
   self . delete_ms ( )
   self . map_server . store_address ( o0o0O00 )
   self . insert_ms ( )
   if 8 - 8: OoooooooOO % I11i - iII111i * OOooOOo . O0
   if 40 - 40: I1Ii111 . oO0o + OoO0O00 % Oo0Ooo / II111iiii
   if 19 - 19: i11iIiiIii
   if 20 - 20: i11iIiiIii . II111iiii - I1ii11iIi11i / ooOoO0o % i11iIiiIii
   if 35 - 35: Oo0Ooo - I1ii11iIi11i . Oo0Ooo
   if 13 - 13: II111iiii / OoOoOO00 * iII111i % O0 % I1ii11iIi11i * i11iIiiIii
  if ( lisp_is_decent_dns_suffix ( self . dns_name ) == False ) : return
  if ( self . a_record_index != 0 ) : return
  if 92 - 92: i11iIiiIii + OoO0O00
  for o0o0O00 in ooOoooOo00Ooo [ 1 : : ] :
   oOO0oo = lisp_address ( LISP_AFI_NONE , o0o0O00 , 0 , 0 )
   I1iII1 = lisp_get_map_server ( oOO0oo )
   if ( I1iII1 != None and I1iII1 . a_record_index == ooOoooOo00Ooo . index ( o0o0O00 ) ) :
    continue
    if 94 - 94: I1ii11iIi11i + OoO0O00 . II111iiii + oO0o . II111iiii
   I1iII1 = copy . deepcopy ( self )
   I1iII1 . map_server . store_address ( o0o0O00 )
   I1iII1 . a_record_index = ooOoooOo00Ooo . index ( o0o0O00 )
   I1iII1 . last_dns_resolve = lisp_get_timestamp ( )
   I1iII1 . insert_ms ( )
   if 96 - 96: i11iIiiIii
   if 66 - 66: ooOoO0o * iII111i - iII111i - O0 . o0oOOo0O0Ooo
   if 23 - 23: iIii1I11I1II1 / I11i % OoOoOO00 . OoO0O00
   if 90 - 90: iIii1I11I1II1 - OOooOOo . Ii1I % OoO0O00
   if 89 - 89: i11iIiiIii
  O0iIIiii1ii1III = [ ]
  for I1iII1 in lisp_map_servers_list . values ( ) :
   if ( self . dns_name != I1iII1 . dns_name ) : continue
   oOO0oo = I1iII1 . map_server . print_address_no_iid ( )
   if ( oOO0oo in ooOoooOo00Ooo ) : continue
   O0iIIiii1ii1III . append ( I1iII1 )
   if 86 - 86: Oo0Ooo % iIii1I11I1II1 . II111iiii / I11i % OoO0O00 % OoO0O00
  for I1iII1 in O0iIIiii1ii1III : I1iII1 . delete_ms ( )
  if 40 - 40: o0oOOo0O0Ooo . iIii1I11I1II1 * Oo0Ooo * i1IIi
  if 94 - 94: oO0o - II111iiii + OoOoOO00
 def insert_ms ( self ) :
  o0OoOo0o0OOoO0 = self . ms_name + self . map_server . print_address ( )
  lisp_map_servers_list [ o0OoOo0o0OOoO0 ] = self
  if 90 - 90: Oo0Ooo + Oo0Ooo + I1Ii111
  if 81 - 81: i1IIi % iIii1I11I1II1 % Ii1I * ooOoO0o % i1IIi * I1IiiI
 def delete_ms ( self ) :
  o0OoOo0o0OOoO0 = self . ms_name + self . map_server . print_address ( )
  if ( lisp_map_servers_list . has_key ( o0OoOo0o0OOoO0 ) == False ) : return
  lisp_map_servers_list . pop ( o0OoOo0o0OOoO0 )
  if 15 - 15: ooOoO0o
  if 26 - 26: IiII % ooOoO0o / OOooOOo
  if 14 - 14: i11iIiiIii . I1ii11iIi11i
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
  if 20 - 20: O0 . iIii1I11I1II1 * I1ii11iIi11i - O0 + I1ii11iIi11i / I1IiiI
  if 67 - 67: OoO0O00 / OoOoOO00 / i11iIiiIii % OoOoOO00
 def add_interface ( self ) :
  lisp_myinterfaces [ self . device ] = self
  if 54 - 54: o0oOOo0O0Ooo . i11iIiiIii + I1IiiI * ooOoO0o - ooOoO0o
  if 28 - 28: I1Ii111 . i11iIiiIii * oO0o % ooOoO0o / iII111i . OOooOOo
 def get_instance_id ( self ) :
  return ( self . instance_id )
  if 57 - 57: OoooooooOO . iIii1I11I1II1 % iII111i % Oo0Ooo
  if 92 - 92: I1Ii111 - Ii1I + I1Ii111
 def get_socket ( self ) :
  return ( self . raw_socket )
  if 8 - 8: Oo0Ooo . iII111i / i11iIiiIii + iIii1I11I1II1 - OoOoOO00
  if 1 - 1: i11iIiiIii
 def get_bridge_socket ( self ) :
  return ( self . bridge_socket )
  if 25 - 25: OoooooooOO / II111iiii . OOooOOo * OoOoOO00 - OoooooooOO
  if 8 - 8: iII111i . iIii1I11I1II1 * O0
 def does_dynamic_eid_match ( self , eid ) :
  if ( self . dynamic_eid . is_null ( ) ) : return ( False )
  return ( eid . is_more_specific ( self . dynamic_eid ) )
  if 87 - 87: OoO0O00 * OoooooooOO + OoOoOO00 . OoooooooOO + o0oOOo0O0Ooo + Ii1I
  if 26 - 26: i1IIi
 def set_socket ( self , device ) :
  IiIIi1I1I11Ii = socket . socket ( socket . AF_INET , socket . SOCK_RAW , socket . IPPROTO_RAW )
  IiIIi1I1I11Ii . setsockopt ( socket . SOL_IP , socket . IP_HDRINCL , 1 )
  try :
   IiIIi1I1I11Ii . setsockopt ( socket . SOL_SOCKET , socket . SO_BINDTODEVICE , device )
  except :
   IiIIi1I1I11Ii . close ( )
   IiIIi1I1I11Ii = None
   if 33 - 33: OoOoOO00 + OOooOOo . i1IIi . IiII
  self . raw_socket = IiIIi1I1I11Ii
  if 78 - 78: OoooooooOO * I11i / OOooOOo + oO0o . I1Ii111 * iII111i
  if 98 - 98: i1IIi
 def set_bridge_socket ( self , device ) :
  IiIIi1I1I11Ii = socket . socket ( socket . PF_PACKET , socket . SOCK_RAW )
  try :
   IiIIi1I1I11Ii = IiIIi1I1I11Ii . bind ( ( device , 0 ) )
   self . bridge_socket = IiIIi1I1I11Ii
  except :
   return
   if 28 - 28: Oo0Ooo . I1Ii111 . iIii1I11I1II1 + I1IiiI . II111iiii * I1ii11iIi11i
   if 26 - 26: i1IIi / i11iIiiIii * II111iiii
   if 11 - 11: Oo0Ooo % i1IIi
   if 70 - 70: II111iiii * Oo0Ooo * OOooOOo - I1IiiI + iIii1I11I1II1 + ooOoO0o
class lisp_datetime ( ) :
 def __init__ ( self , datetime_str ) :
  self . datetime_name = datetime_str
  self . datetime = None
  self . parse_datetime ( )
  if 27 - 27: I1ii11iIi11i - I1Ii111 * O0 % ooOoO0o / I1IiiI
  if 53 - 53: i11iIiiIii * i11iIiiIii % O0 % IiII
 def valid_datetime ( self ) :
  Oo0oOOo000 = self . datetime_name
  if ( Oo0oOOo000 . find ( ":" ) == - 1 ) : return ( False )
  if ( Oo0oOOo000 . find ( "-" ) == - 1 ) : return ( False )
  OoOOOo , i1I1 , IiIi111I , time = Oo0oOOo000 [ 0 : 4 ] , Oo0oOOo000 [ 5 : 7 ] , Oo0oOOo000 [ 8 : 10 ] , Oo0oOOo000 [ 11 : : ]
  if 52 - 52: Oo0Ooo * iII111i - O0 . OoOoOO00 - I1IiiI
  if ( ( OoOOOo + i1I1 + IiIi111I ) . isdigit ( ) == False ) : return ( False )
  if ( i1I1 < "01" and i1I1 > "12" ) : return ( False )
  if ( IiIi111I < "01" and IiIi111I > "31" ) : return ( False )
  if 47 - 47: II111iiii
  i1i11i1 , ooOo0 , I11IIiIIi = time . split ( ":" )
  if 63 - 63: OoOoOO00 - o0oOOo0O0Ooo % II111iiii - Ii1I
  if ( ( i1i11i1 + ooOo0 + I11IIiIIi ) . isdigit ( ) == False ) : return ( False )
  if ( i1i11i1 < "00" and i1i11i1 > "23" ) : return ( False )
  if ( ooOo0 < "00" and ooOo0 > "59" ) : return ( False )
  if ( I11IIiIIi < "00" and I11IIiIIi > "59" ) : return ( False )
  return ( True )
  if 81 - 81: iII111i % OOooOOo * oO0o
  if 84 - 84: iII111i - OoooooooOO + I1ii11iIi11i - I1IiiI
 def parse_datetime ( self ) :
  OOo0 = self . datetime_name
  OOo0 = OOo0 . replace ( "-" , "" )
  OOo0 = OOo0 . replace ( ":" , "" )
  self . datetime = int ( OOo0 )
  if 29 - 29: OoOoOO00 * I11i . O0 + oO0o - iIii1I11I1II1 - I11i
  if 40 - 40: OoooooooOO + O0
 def now ( self ) :
  OOOO0O00o = datetime . datetime . now ( ) . strftime ( "%Y-%m-%d-%H:%M:%S" )
  OOOO0O00o = lisp_datetime ( OOOO0O00o )
  return ( OOOO0O00o )
  if 55 - 55: i11iIiiIii * Ii1I % OOooOOo + ooOoO0o - I1ii11iIi11i . Oo0Ooo
  if 48 - 48: o0oOOo0O0Ooo
 def print_datetime ( self ) :
  return ( self . datetime_name )
  if 55 - 55: OOooOOo - OoooooooOO * iIii1I11I1II1 + iII111i % II111iiii
  if 33 - 33: I1Ii111 * oO0o * OoooooooOO + OOooOOo - I1IiiI + I1Ii111
 def future ( self ) :
  return ( self . datetime > self . now ( ) . datetime )
  if 92 - 92: ooOoO0o * I11i % iIii1I11I1II1 + Ii1I - OoOoOO00
  if 31 - 31: OoooooooOO
 def past ( self ) :
  return ( self . future ( ) == False )
  if 87 - 87: OoooooooOO - Ii1I . I11i / I1Ii111 . i1IIi
  if 86 - 86: i1IIi . oO0o % OOooOOo
 def now_in_range ( self , upper ) :
  return ( self . past ( ) and upper . future ( ) )
  if 99 - 99: oO0o / I1Ii111 * oO0o * I11i
  if 38 - 38: o0oOOo0O0Ooo + OoOoOO00
 def this_year ( self ) :
  I1IIIIi1i = str ( self . now ( ) . datetime ) [ 0 : 4 ]
  OOOO0O00o = str ( self . datetime ) [ 0 : 4 ]
  return ( OOOO0O00o == I1IIIIi1i )
  if 17 - 17: OoO0O00
  if 79 - 79: Ii1I - II111iiii
 def this_month ( self ) :
  I1IIIIi1i = str ( self . now ( ) . datetime ) [ 0 : 6 ]
  OOOO0O00o = str ( self . datetime ) [ 0 : 6 ]
  return ( OOOO0O00o == I1IIIIi1i )
  if 57 - 57: II111iiii / OoooooooOO
  if 4 - 4: I11i * OoOoOO00
 def today ( self ) :
  I1IIIIi1i = str ( self . now ( ) . datetime ) [ 0 : 8 ]
  OOOO0O00o = str ( self . datetime ) [ 0 : 8 ]
  return ( OOOO0O00o == I1IIIIi1i )
  if 18 - 18: iIii1I11I1II1 % OOooOOo - I1ii11iIi11i * i1IIi + Oo0Ooo
  if 87 - 87: oO0o . I11i
  if 15 - 15: oO0o
  if 45 - 45: Oo0Ooo * IiII * OoO0O00 + iIii1I11I1II1
  if 89 - 89: IiII . IiII . oO0o % iII111i
  if 27 - 27: OoOoOO00 + O0 % i1IIi - Oo0Ooo
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
  if 96 - 96: O0 % o0oOOo0O0Ooo + OOooOOo % I1IiiI
  if 51 - 51: i1IIi . o0oOOo0O0Ooo % I1IiiI - OoooooooOO / OoOoOO00 - I11i
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
  if 45 - 45: O0 * II111iiii / i11iIiiIii
  if 38 - 38: OoooooooOO % i11iIiiIii - O0 / O0
 def match_policy_map_request ( self , mr , srloc ) :
  for oo0oO00 in self . match_clauses :
   i111 = oo0oO00 . source_eid
   oOO0oOo0OOoOO = mr . source_eid
   if ( i111 and oOO0oOo0OOoOO and oOO0oOo0OOoOO . is_more_specific ( i111 ) == False ) : continue
   if 59 - 59: OoO0O00 % iII111i + oO0o * II111iiii . OOooOOo
   i111 = oo0oO00 . dest_eid
   oOO0oOo0OOoOO = mr . target_eid
   if ( i111 and oOO0oOo0OOoOO and oOO0oOo0OOoOO . is_more_specific ( i111 ) == False ) : continue
   if 26 - 26: OOooOOo % OoooooooOO . Ii1I / iIii1I11I1II1 * I1IiiI
   i111 = oo0oO00 . source_rloc
   oOO0oOo0OOoOO = srloc
   if ( i111 and oOO0oOo0OOoOO and oOO0oOo0OOoOO . is_more_specific ( i111 ) == False ) : continue
   I1i = oo0oO00 . datetime_lower
   O0O0OooOo0000O = oo0oO00 . datetime_upper
   if ( I1i and O0O0OooOo0000O and I1i . now_in_range ( O0O0OooOo0000O ) == False ) : continue
   return ( True )
   if 20 - 20: OoO0O00
  return ( False )
  if 63 - 63: iIii1I11I1II1 * iIii1I11I1II1 % IiII % II111iiii
  if 80 - 80: iII111i
 def set_policy_map_reply ( self ) :
  oOo0o00OOOO = ( self . set_rloc_address == None and
 self . set_rloc_record_name == None and self . set_geo_name == None and
 self . set_elp_name == None and self . set_rle_name == None )
  if ( oOo0o00OOOO ) : return ( None )
  if 7 - 7: I1Ii111 + O0 % i11iIiiIii + o0oOOo0O0Ooo . OoooooooOO
  oOOoo0O00 = lisp_rloc ( )
  if ( self . set_rloc_address ) :
   oOOoo0O00 . rloc . copy_address ( self . set_rloc_address )
   o0o0O00 = oOOoo0O00 . rloc . print_address_no_iid ( )
   lprint ( "Policy set-rloc-address to {}" . format ( o0o0O00 ) )
   if 74 - 74: OOooOOo
  if ( self . set_rloc_record_name ) :
   oOOoo0O00 . rloc_name = self . set_rloc_record_name
   II1 = blue ( oOOoo0O00 . rloc_name , False )
   lprint ( "Policy set-rloc-record-name to {}" . format ( II1 ) )
   if 10 - 10: OoOoOO00 / i11iIiiIii
  if ( self . set_geo_name ) :
   oOOoo0O00 . geo_name = self . set_geo_name
   II1 = oOOoo0O00 . geo_name
   I1iiI11I = "" if lisp_geo_list . has_key ( II1 ) else "(not configured)"
   if 36 - 36: II111iiii . O0 % O0 * iII111i * iIii1I11I1II1
   lprint ( "Policy set-geo-name '{}' {}" . format ( II1 , I1iiI11I ) )
   if 42 - 42: iII111i . OOooOOo + oO0o / OoOoOO00
  if ( self . set_elp_name ) :
   oOOoo0O00 . elp_name = self . set_elp_name
   II1 = oOOoo0O00 . elp_name
   I1iiI11I = "" if lisp_elp_list . has_key ( II1 ) else "(not configured)"
   if 54 - 54: ooOoO0o % o0oOOo0O0Ooo + i11iIiiIii / ooOoO0o * II111iiii * Ii1I
   lprint ( "Policy set-elp-name '{}' {}" . format ( II1 , I1iiI11I ) )
   if 52 - 52: ooOoO0o + IiII * OoOoOO00 - OoO0O00 - OoooooooOO - oO0o
  if ( self . set_rle_name ) :
   oOOoo0O00 . rle_name = self . set_rle_name
   II1 = oOOoo0O00 . rle_name
   I1iiI11I = "" if lisp_rle_list . has_key ( II1 ) else "(not configured)"
   if 60 - 60: iII111i / oO0o
   lprint ( "Policy set-rle-name '{}' {}" . format ( II1 , I1iiI11I ) )
   if 98 - 98: OoOoOO00 / OOooOOo
  if ( self . set_json_name ) :
   oOOoo0O00 . json_name = self . set_json_name
   II1 = oOOoo0O00 . json_name
   I1iiI11I = "" if lisp_json_list . has_key ( II1 ) else "(not configured)"
   if 31 - 31: II111iiii % I11i - I11i
   lprint ( "Policy set-json-name '{}' {}" . format ( II1 , I1iiI11I ) )
   if 17 - 17: iII111i . IiII + OOooOOo % I1Ii111 % i11iIiiIii
  return ( oOOoo0O00 )
  if 100 - 100: i11iIiiIii - O0 . OoO0O00 / O0 - Ii1I - IiII
  if 72 - 72: Ii1I % O0 + II111iiii . i11iIiiIii
 def save_policy ( self ) :
  lisp_policies [ self . policy_name ] = self
  if 66 - 66: II111iiii % I1IiiI
  if 88 - 88: iIii1I11I1II1 * iIii1I11I1II1 + I1Ii111 * OOooOOo . I1IiiI
  if 96 - 96: I1ii11iIi11i
class lisp_pubsub ( ) :
 def __init__ ( self , itr , port , nonce , ttl , xtr_id ) :
  self . itr = itr
  self . port = port
  self . nonce = nonce
  self . uptime = lisp_get_timestamp ( )
  self . ttl = ttl
  self . xtr_id = xtr_id
  self . map_notify_count = 0
  if 37 - 37: OoO0O00 % o0oOOo0O0Ooo * O0 * O0 + iII111i
  if 18 - 18: i11iIiiIii . o0oOOo0O0Ooo - OOooOOo % oO0o * Ii1I / I1IiiI
 def add ( self , eid_prefix ) :
  oooOooOO = self . ttl
  o00oo00oo = eid_prefix . print_prefix ( )
  if ( lisp_pubsub_cache . has_key ( o00oo00oo ) == False ) :
   lisp_pubsub_cache [ o00oo00oo ] = { }
   if 46 - 46: o0oOOo0O0Ooo . ooOoO0o / Ii1I
  OO0oOOoOoOo = lisp_pubsub_cache [ o00oo00oo ]
  if 97 - 97: Ii1I . Oo0Ooo - O0 - I1Ii111 . i1IIi
  I1I11i1Iiii11 = "Add"
  if ( OO0oOOoOoOo . has_key ( self . xtr_id ) ) :
   I1I11i1Iiii11 = "Replace"
   del ( OO0oOOoOoOo [ self . xtr_id ] )
   if 20 - 20: IiII - i1IIi - I1Ii111
  OO0oOOoOoOo [ self . xtr_id ] = self
  if 32 - 32: O0 + II111iiii / OoOoOO00 - OoO0O00 * IiII
  o00oo00oo = green ( o00oo00oo , False )
  oOooOo000O = red ( self . itr . print_address_no_iid ( ) , False )
  oO = "0x" + lisp_hex_string ( self . xtr_id )
  lprint ( "{} pubsub state {} for {}, xtr-id: {}, ttl {}" . format ( I1I11i1Iiii11 , o00oo00oo ,
 oOooOo000O , oO , oooOooOO ) )
  if 14 - 14: iII111i % o0oOOo0O0Ooo * iIii1I11I1II1 * ooOoO0o
  if 15 - 15: i11iIiiIii % Ii1I + I1IiiI % I1ii11iIi11i * Oo0Ooo
 def delete ( self , eid_prefix ) :
  o00oo00oo = eid_prefix . print_prefix ( )
  oOooOo000O = red ( self . itr . print_address_no_iid ( ) , False )
  oO = "0x" + lisp_hex_string ( self . xtr_id )
  if ( lisp_pubsub_cache . has_key ( o00oo00oo ) ) :
   OO0oOOoOoOo = lisp_pubsub_cache [ o00oo00oo ]
   if ( OO0oOOoOoOo . has_key ( self . xtr_id ) ) :
    OO0oOOoOoOo . pop ( self . xtr_id )
    lprint ( "Remove pubsub state {} for {}, xtr-id: {}" . format ( o00oo00oo ,
 oOooOo000O , oO ) )
    if 32 - 32: OoOoOO00 % II111iiii % OOooOOo + I1Ii111
    if 41 - 41: I11i + Oo0Ooo . Oo0Ooo / iII111i . OoOoOO00
    if 1 - 1: ooOoO0o + iII111i % i11iIiiIii / OoOoOO00
    if 98 - 98: IiII
    if 75 - 75: OoooooooOO % IiII + Ii1I - i1IIi / OoooooooOO
    if 57 - 57: iII111i
    if 18 - 18: II111iiii % i11iIiiIii + I11i - OOooOOo
    if 100 - 100: o0oOOo0O0Ooo / Ii1I - iIii1I11I1II1 / oO0o
    if 68 - 68: I11i / II111iiii * oO0o . II111iiii * OOooOOo
    if 78 - 78: I11i * OoO0O00 / II111iiii
    if 86 - 86: I1Ii111 % II111iiii
    if 90 - 90: OoO0O00 / I11i - Oo0Ooo
    if 76 - 76: O0 + OoO0O00 / ooOoO0o . II111iiii * iIii1I11I1II1 . I1Ii111
    if 43 - 43: Oo0Ooo + o0oOOo0O0Ooo % o0oOOo0O0Ooo % I1ii11iIi11i / iIii1I11I1II1 . I1ii11iIi11i
    if 59 - 59: IiII . OoO0O00 - OoooooooOO . O0
    if 33 - 33: Ii1I
    if 95 - 95: OoooooooOO + OoO0O00 * ooOoO0o
    if 40 - 40: I1IiiI / OOooOOo * Ii1I
    if 98 - 98: I1IiiI
    if 4 - 4: I1IiiI % O0 / Oo0Ooo / O0
    if 90 - 90: ooOoO0o - O0 . IiII - O0 . iIii1I11I1II1
    if 42 - 42: I1ii11iIi11i
class lisp_trace ( ) :
 def __init__ ( self ) :
  self . nonce = lisp_get_control_nonce ( )
  self . packet_json = [ ]
  self . local_rloc = None
  self . local_port = None
  self . lisp_socket = None
  if 51 - 51: iII111i % i11iIiiIii . OoO0O00 . IiII - OoOoOO00 * i1IIi
  if 14 - 14: I1ii11iIi11i . OoO0O00
 def print_trace ( self ) :
  I1i1 = self . packet_json
  lprint ( "LISP-Trace JSON: '{}'" . format ( I1i1 ) )
  if 25 - 25: Oo0Ooo . I1ii11iIi11i * OOooOOo
  if 25 - 25: IiII % I1IiiI / O0 % OOooOOo - OoooooooOO
 def encode ( self ) :
  oo0I1I1iiI1i = socket . htonl ( 0x90000000 )
  i1II1IiiIi = struct . pack ( "II" , oo0I1I1iiI1i , 0 )
  i1II1IiiIi += struct . pack ( "Q" , self . nonce )
  i1II1IiiIi += json . dumps ( self . packet_json )
  return ( i1II1IiiIi )
  if 29 - 29: O0 + iII111i
  if 4 - 4: I11i * I11i - Ii1I * oO0o . I1ii11iIi11i % o0oOOo0O0Ooo
 def decode ( self , packet ) :
  oOo0ooO0O0oo = "I"
  OO00OO = struct . calcsize ( oOo0ooO0O0oo )
  if ( len ( packet ) < OO00OO ) : return ( False )
  oo0I1I1iiI1i = struct . unpack ( oOo0ooO0O0oo , packet [ : OO00OO ] ) [ 0 ]
  packet = packet [ OO00OO : : ]
  oo0I1I1iiI1i = socket . ntohl ( oo0I1I1iiI1i )
  if ( ( oo0I1I1iiI1i & 0xff000000 ) != 0x90000000 ) : return ( False )
  if 33 - 33: Ii1I * i11iIiiIii / O0 . Oo0Ooo + i1IIi . OoOoOO00
  if ( len ( packet ) < OO00OO ) : return ( False )
  o0o0O00 = struct . unpack ( oOo0ooO0O0oo , packet [ : OO00OO ] ) [ 0 ]
  packet = packet [ OO00OO : : ]
  if 76 - 76: OoooooooOO - O0
  o0o0O00 = socket . ntohl ( o0o0O00 )
  IIi1IIiii1i = o0o0O00 >> 24
  Ii1IiiI1I = ( o0o0O00 >> 16 ) & 0xff
  OO0OOO0O0 = ( o0o0O00 >> 8 ) & 0xff
  ooOoOo0 = o0o0O00 & 0xff
  self . local_rloc = "{}.{}.{}.{}" . format ( IIi1IIiii1i , Ii1IiiI1I , OO0OOO0O0 , ooOoOo0 )
  self . local_port = str ( oo0I1I1iiI1i & 0xffff )
  if 75 - 75: oO0o * I1ii11iIi11i . iIii1I11I1II1 / ooOoO0o + ooOoO0o + I11i
  oOo0ooO0O0oo = "Q"
  OO00OO = struct . calcsize ( oOo0ooO0O0oo )
  if ( len ( packet ) < OO00OO ) : return ( False )
  self . nonce = struct . unpack ( oOo0ooO0O0oo , packet [ : OO00OO ] ) [ 0 ]
  packet = packet [ OO00OO : : ]
  if ( len ( packet ) == 0 ) : return ( True )
  if 20 - 20: OOooOOo - i1IIi / i11iIiiIii
  try :
   self . packet_json = json . loads ( packet )
  except :
   return ( False )
   if 60 - 60: I11i * I11i + Oo0Ooo . IiII / iII111i % OoooooooOO
  return ( True )
  if 35 - 35: O0 . Oo0Ooo / Oo0Ooo / Ii1I / i1IIi * I11i
  if 93 - 93: O0 + IiII
 def myeid ( self , eid ) :
  return ( lisp_is_myeid ( eid ) )
  if 91 - 91: iIii1I11I1II1
  if 66 - 66: i1IIi . ooOoO0o
 def return_to_sender ( self , lisp_socket , rts_rloc , packet ) :
  oOOoo0O00 , o00o = self . rtr_cache_nat_trace_find ( rts_rloc )
  if ( oOOoo0O00 == None ) :
   oOOoo0O00 , o00o = rts_rloc . split ( ":" )
   o00o = int ( o00o )
   lprint ( "Send LISP-Trace to address {}:{}" . format ( oOOoo0O00 , o00o ) )
  else :
   lprint ( "Send LISP-Trace to translated address {}:{}" . format ( oOOoo0O00 ,
 o00o ) )
   if 84 - 84: O0 % ooOoO0o / I1Ii111
   if 75 - 75: I11i - iII111i . O0
  if ( lisp_socket == None ) :
   IiIIi1I1I11Ii = socket . socket ( socket . AF_INET , socket . SOCK_DGRAM )
   IiIIi1I1I11Ii . bind ( ( "0.0.0.0" , LISP_TRACE_PORT ) )
   IiIIi1I1I11Ii . sendto ( packet , ( oOOoo0O00 , o00o ) )
   IiIIi1I1I11Ii . close ( )
  else :
   lisp_socket . sendto ( packet , ( oOOoo0O00 , o00o ) )
   if 52 - 52: I1ii11iIi11i
   if 22 - 22: I1ii11iIi11i - i1IIi / OOooOOo . o0oOOo0O0Ooo . oO0o
   if 9 - 9: ooOoO0o - I1Ii111 + IiII . iII111i
 def packet_length ( self ) :
  I1iIIIiI = 8 ; O00OOo = 4 + 4 + 8
  return ( I1iIIIiI + O00OOo + len ( json . dumps ( self . packet_json ) ) )
  if 21 - 21: iII111i * I1Ii111
  if 43 - 43: I1Ii111 / I1ii11iIi11i - o0oOOo0O0Ooo + OoOoOO00 * iII111i - OoO0O00
 def rtr_cache_nat_trace ( self , translated_rloc , translated_port ) :
  o0OoOo0o0OOoO0 = self . local_rloc + ":" + self . local_port
  oOO = ( translated_rloc , translated_port )
  lisp_rtr_nat_trace_cache [ o0OoOo0o0OOoO0 ] = oOO
  lprint ( "Cache NAT Trace addresses {} -> {}" . format ( o0OoOo0o0OOoO0 , oOO ) )
  if 4 - 4: O0 + OoO0O00 / II111iiii
  if 93 - 93: o0oOOo0O0Ooo * I11i * II111iiii / OOooOOo
 def rtr_cache_nat_trace_find ( self , local_rloc_and_port ) :
  o0OoOo0o0OOoO0 = local_rloc_and_port
  try : oOO = lisp_rtr_nat_trace_cache [ o0OoOo0o0OOoO0 ]
  except : oOO = ( None , None )
  return ( oOO )
  if 95 - 95: OoOoOO00 % I1ii11iIi11i * I1Ii111 % II111iiii
  if 15 - 15: IiII . I1ii11iIi11i / I1IiiI . I1ii11iIi11i + Ii1I
  if 82 - 82: OOooOOo / I1IiiI % Oo0Ooo - OoO0O00 - o0oOOo0O0Ooo
  if 95 - 95: iII111i % o0oOOo0O0Ooo
  if 26 - 26: i1IIi / iII111i + iII111i
  if 66 - 66: i1IIi + I1IiiI
  if 45 - 45: I1Ii111 . iII111i + OoO0O00 - O0
  if 71 - 71: Oo0Ooo + OOooOOo
  if 94 - 94: OOooOOo
  if 81 - 81: i11iIiiIii + iIii1I11I1II1 . i11iIiiIii / OOooOOo / iII111i
  if 34 - 34: i11iIiiIii - o0oOOo0O0Ooo * OoooooooOO * I1ii11iIi11i * Oo0Ooo % I1ii11iIi11i
def lisp_get_map_server ( address ) :
 for I1iII1 in lisp_map_servers_list . values ( ) :
  if ( I1iII1 . map_server . is_exact_match ( address ) ) : return ( I1iII1 )
  if 31 - 31: I11i . o0oOOo0O0Ooo
 return ( None )
 if 82 - 82: I11i - Oo0Ooo
 if 77 - 77: I1IiiI + OoO0O00 % iIii1I11I1II1 - OOooOOo
 if 80 - 80: oO0o % I1ii11iIi11i * I1Ii111 + i1IIi
 if 79 - 79: oO0o + IiII
 if 4 - 4: iII111i + OoooooooOO / I1Ii111
 if 57 - 57: I1IiiI . iIii1I11I1II1 % iII111i * iII111i / I1Ii111
 if 30 - 30: O0 / I11i % OoOoOO00 * I1Ii111 / O0 % ooOoO0o
def lisp_get_any_map_server ( ) :
 for I1iII1 in lisp_map_servers_list . values ( ) : return ( I1iII1 )
 return ( None )
 if 36 - 36: iIii1I11I1II1 . iII111i * I1IiiI . I1IiiI - IiII
 if 39 - 39: O0 / ooOoO0o + I11i - OoOoOO00 * o0oOOo0O0Ooo - OoO0O00
 if 97 - 97: i11iIiiIii / O0 % OoO0O00
 if 88 - 88: i1IIi . I1IiiI
 if 8 - 8: I1ii11iIi11i . OoO0O00 % o0oOOo0O0Ooo / O0
 if 51 - 51: oO0o + Ii1I * Ii1I * I1ii11iIi11i % I11i - I1ii11iIi11i
 if 15 - 15: i1IIi / OoO0O00 - Oo0Ooo
 if 74 - 74: o0oOOo0O0Ooo % Ii1I - II111iiii / ooOoO0o
 if 84 - 84: I1IiiI + OOooOOo
 if 80 - 80: OOooOOo / OoOoOO00
def lisp_get_map_resolver ( address , eid ) :
 if ( address != None ) :
  o0o0O00 = address . print_address ( )
  IIiIII1IIi = None
  for o0OoOo0o0OOoO0 in lisp_map_resolvers_list :
   if ( o0OoOo0o0OOoO0 . find ( o0o0O00 ) == - 1 ) : continue
   IIiIII1IIi = lisp_map_resolvers_list [ o0OoOo0o0OOoO0 ]
   if 93 - 93: OOooOOo
  return ( IIiIII1IIi )
  if 82 - 82: iIii1I11I1II1 + OoO0O00 / iIii1I11I1II1 . iIii1I11I1II1
  if 36 - 36: iII111i % I1ii11iIi11i + OoOoOO00 - i11iIiiIii % II111iiii % I11i
  if 92 - 92: O0 * OoooooooOO + I1ii11iIi11i / IiII
  if 97 - 97: o0oOOo0O0Ooo . Ii1I + I1Ii111
  if 72 - 72: i11iIiiIii . iII111i . Ii1I * I1ii11iIi11i
  if 49 - 49: OoOoOO00 - O0 % I11i - ooOoO0o * OOooOOo
  if 58 - 58: OoooooooOO - OOooOOo * oO0o / Ii1I . IiII
 if ( eid == "" ) :
  I1IIiiI1Ii = ""
 elif ( eid == None ) :
  I1IIiiI1Ii = "all"
 else :
  I11i111 = lisp_db_for_lookups . lookup_cache ( eid , False )
  I1IIiiI1Ii = "all" if I11i111 == None else I11i111 . use_mr_name
  if 98 - 98: i11iIiiIii . I1Ii111
  if 19 - 19: o0oOOo0O0Ooo / oO0o / iIii1I11I1II1 % Oo0Ooo * OoOoOO00 % IiII
 o00oO0ooO000 = None
 for IIiIII1IIi in lisp_map_resolvers_list . values ( ) :
  if ( I1IIiiI1Ii == "" ) : return ( IIiIII1IIi )
  if ( IIiIII1IIi . mr_name != I1IIiiI1Ii ) : continue
  if ( o00oO0ooO000 == None or IIiIII1IIi . last_used < o00oO0ooO000 . last_used ) : o00oO0ooO000 = IIiIII1IIi
  if 29 - 29: iII111i * IiII % II111iiii - i11iIiiIii / ooOoO0o . I11i
 return ( o00oO0ooO000 )
 if 23 - 23: OoOoOO00 / ooOoO0o * IiII * OOooOOo / OOooOOo
 if 7 - 7: I1Ii111
 if 47 - 47: oO0o - IiII - Ii1I % OoO0O00 % I1IiiI % i1IIi
 if 69 - 69: I1IiiI - OoooooooOO * OoooooooOO
 if 49 - 49: IiII
 if 80 - 80: i11iIiiIii - OoooooooOO + II111iiii / i1IIi - oO0o
 if 100 - 100: Ii1I
 if 73 - 73: IiII - O0
def lisp_get_decent_map_resolver ( eid ) :
 iI11I = lisp_get_decent_index ( eid )
 oo0Oo0OOOO = str ( iI11I ) + "." + lisp_decent_dns_suffix
 if 18 - 18: i11iIiiIii % o0oOOo0O0Ooo % iII111i - OOooOOo / iIii1I11I1II1 % i11iIiiIii
 lprint ( "Use LISP-Decent map-resolver {} for EID {}" . format ( bold ( oo0Oo0OOOO , False ) , eid . print_prefix ( ) ) )
 if 39 - 39: o0oOOo0O0Ooo
 if 32 - 32: iIii1I11I1II1 . II111iiii / IiII % O0 / iII111i
 o00oO0ooO000 = None
 for IIiIII1IIi in lisp_map_resolvers_list . values ( ) :
  if ( oo0Oo0OOOO != IIiIII1IIi . dns_name ) : continue
  if ( o00oO0ooO000 == None or IIiIII1IIi . last_used < o00oO0ooO000 . last_used ) : o00oO0ooO000 = IIiIII1IIi
  if 97 - 97: iIii1I11I1II1
 return ( o00oO0ooO000 )
 if 18 - 18: OOooOOo
 if 87 - 87: O0 - i1IIi . I11i / Ii1I % iIii1I11I1II1
 if 57 - 57: I11i . IiII / iIii1I11I1II1 - ooOoO0o
 if 50 - 50: O0 / II111iiii
 if 94 - 94: O0 + O0 % I1ii11iIi11i % i1IIi
 if 15 - 15: I1IiiI
 if 48 - 48: Ii1I * IiII % O0 - II111iiii
def lisp_ipv4_input ( packet ) :
 if 66 - 66: iIii1I11I1II1 / OOooOOo
 if 65 - 65: IiII . oO0o + O0 - i11iIiiIii + iIii1I11I1II1
 if 82 - 82: iIii1I11I1II1 * iII111i + iIii1I11I1II1 / OoO0O00 + O0
 if 67 - 67: I1Ii111
 oOOoo0 = struct . unpack ( "H" , packet [ 10 : 12 ] ) [ 0 ]
 if ( oOOoo0 == 0 ) :
  dprint ( "Packet arrived with checksum of 0!" )
 else :
  packet = lisp_ip_checksum ( packet )
  oOOoo0 = struct . unpack ( "H" , packet [ 10 : 12 ] ) [ 0 ]
  if ( oOOoo0 != 0 ) :
   dprint ( "IPv4 header checksum failed for inner header" )
   packet = lisp_format_packet ( packet [ 0 : 20 ] )
   dprint ( "Packet header: {}" . format ( packet ) )
   return ( None )
   if 94 - 94: I1Ii111 % iIii1I11I1II1 - II111iiii . ooOoO0o + i11iIiiIii - i11iIiiIii
   if 55 - 55: OoooooooOO % iIii1I11I1II1 % I1ii11iIi11i % i1IIi
   if 46 - 46: I11i - ooOoO0o . I1IiiI
   if 36 - 36: I11i + OoO0O00 * O0 * OoOoOO00 * iII111i
   if 90 - 90: i11iIiiIii / i1IIi
   if 35 - 35: Ii1I . I11i / oO0o / OoOoOO00
   if 5 - 5: I1ii11iIi11i . o0oOOo0O0Ooo * iII111i * I1ii11iIi11i % I1Ii111
 oooOooOO = struct . unpack ( "B" , packet [ 8 : 9 ] ) [ 0 ]
 if ( oooOooOO == 0 ) :
  dprint ( "IPv4 packet arrived with ttl 0, packet discarded" )
  return ( None )
 elif ( oooOooOO == 1 ) :
  dprint ( "IPv4 packet {}, packet discarded" . format ( bold ( "ttl expiry" , False ) ) )
  if 83 - 83: iIii1I11I1II1 * o0oOOo0O0Ooo % i11iIiiIii + OoO0O00 . O0
  return ( None )
  if 87 - 87: II111iiii - iIii1I11I1II1 % I11i % I1IiiI . o0oOOo0O0Ooo
  if 52 - 52: i11iIiiIii . oO0o / OoooooooOO - OoO0O00
 oooOooOO -= 1
 packet = packet [ 0 : 8 ] + struct . pack ( "B" , oooOooOO ) + packet [ 9 : : ]
 packet = packet [ 0 : 10 ] + struct . pack ( "H" , 0 ) + packet [ 12 : : ]
 packet = lisp_ip_checksum ( packet )
 return ( packet )
 if 7 - 7: I1IiiI * I1IiiI % OOooOOo % iIii1I11I1II1 * OoO0O00 . o0oOOo0O0Ooo
 if 32 - 32: ooOoO0o / i1IIi
 if 55 - 55: oO0o . OoOoOO00 + OoooooooOO - ooOoO0o . OoooooooOO
 if 77 - 77: I1IiiI
 if 16 - 16: I1IiiI + ooOoO0o - O0 / o0oOOo0O0Ooo
 if 36 - 36: Oo0Ooo - OoOoOO00 - II111iiii
 if 25 - 25: i11iIiiIii + II111iiii * OOooOOo % OOooOOo
def lisp_ipv6_input ( packet ) :
 oooooO0oO0o = packet . inner_dest
 packet = packet . packet
 if 87 - 87: I11i % Ii1I % Oo0Ooo . II111iiii / oO0o
 if 19 - 19: O0 . OOooOOo + I1Ii111 * I1ii11iIi11i
 if 91 - 91: o0oOOo0O0Ooo / oO0o . o0oOOo0O0Ooo + IiII + ooOoO0o . I1Ii111
 if 90 - 90: i1IIi + oO0o * oO0o / ooOoO0o . IiII
 if 98 - 98: I11i % OoO0O00 . iII111i - o0oOOo0O0Ooo
 oooOooOO = struct . unpack ( "B" , packet [ 7 : 8 ] ) [ 0 ]
 if ( oooOooOO == 0 ) :
  dprint ( "IPv6 packet arrived with hop-limit 0, packet discarded" )
  return ( None )
 elif ( oooOooOO == 1 ) :
  dprint ( "IPv6 packet {}, packet discarded" . format ( bold ( "ttl expiry" , False ) ) )
  if 92 - 92: I11i
  return ( None )
  if 34 - 34: I1IiiI % iIii1I11I1II1 . I1ii11iIi11i * Oo0Ooo * iIii1I11I1II1 / O0
  if 98 - 98: iII111i % IiII + OoO0O00
  if 23 - 23: OOooOOo
  if 83 - 83: I1ii11iIi11i / O0 * II111iiii + IiII + Oo0Ooo
  if 99 - 99: II111iiii + O0
 if ( oooooO0oO0o . is_ipv6_link_local ( ) ) :
  dprint ( "Do not encapsulate IPv6 link-local packets" )
  return ( None )
  if 94 - 94: ooOoO0o * ooOoO0o + o0oOOo0O0Ooo . iII111i % iIii1I11I1II1 + Ii1I
  if 88 - 88: Oo0Ooo . iII111i
 oooOooOO -= 1
 packet = packet [ 0 : 7 ] + struct . pack ( "B" , oooOooOO ) + packet [ 8 : : ]
 return ( packet )
 if 89 - 89: OOooOOo + I1Ii111 % i11iIiiIii + Oo0Ooo / Oo0Ooo + OoO0O00
 if 9 - 9: OoOoOO00 % i1IIi + IiII
 if 19 - 19: I1Ii111 - II111iiii / I1Ii111 + I1IiiI - OoooooooOO + o0oOOo0O0Ooo
 if 100 - 100: OoO0O00 / OoOoOO00 / OOooOOo / OoO0O00
 if 95 - 95: ooOoO0o
 if 95 - 95: Ii1I + i1IIi . I1IiiI % I1Ii111 / Ii1I * O0
 if 68 - 68: I1Ii111 - IiII - oO0o - Oo0Ooo - o0oOOo0O0Ooo
 if 32 - 32: OoOoOO00 % i11iIiiIii
def lisp_mac_input ( packet ) :
 return ( packet )
 if 53 - 53: I1Ii111 * Ii1I / IiII . i1IIi * II111iiii / o0oOOo0O0Ooo
 if 44 - 44: I1Ii111 + ooOoO0o
 if 15 - 15: I11i + OoO0O00 + OoOoOO00
 if 100 - 100: I1Ii111
 if 78 - 78: OoOoOO00
 if 16 - 16: I1Ii111 % OoO0O00 - OoO0O00 % OoOoOO00 * OoO0O00
 if 36 - 36: OoOoOO00 * II111iiii . OoooooooOO * I11i . I11i
 if 13 - 13: I1ii11iIi11i * II111iiii
 if 93 - 93: OOooOOo / O0 - o0oOOo0O0Ooo + OoO0O00 * I1IiiI
def lisp_rate_limit_map_request ( source , dest ) :
 if ( lisp_last_map_request_sent == None ) : return ( False )
 I1IIIIi1i = lisp_get_timestamp ( )
 i11IiIIi11I = I1IIIIi1i - lisp_last_map_request_sent
 o0OOOoOo = ( i11IiIIi11I < LISP_MAP_REQUEST_RATE_LIMIT )
 if 64 - 64: ooOoO0o
 if ( o0OOOoOo ) :
  if ( source != None ) : source = source . print_address ( )
  dest = dest . print_address ( )
  dprint ( "Rate-limiting Map-Request for {} -> {}" . format ( source , dest ) )
  if 23 - 23: Oo0Ooo . OoO0O00
 return ( o0OOOoOo )
 if 49 - 49: oO0o % i11iIiiIii * Ii1I
 if 9 - 9: Oo0Ooo - OoO0O00 + ooOoO0o / o0oOOo0O0Ooo
 if 61 - 61: O0 - i11iIiiIii * o0oOOo0O0Ooo
 if 92 - 92: Oo0Ooo + OOooOOo - i11iIiiIii
 if 26 - 26: O0 % Oo0Ooo + ooOoO0o - Ii1I . Oo0Ooo
 if 33 - 33: I1Ii111 / iII111i . I1Ii111 % II111iiii
 if 52 - 52: I1ii11iIi11i
def lisp_send_map_request ( lisp_sockets , lisp_ephem_port , seid , deid , rloc ) :
 global lisp_last_map_request_sent
 if 1 - 1: II111iiii + I1ii11iIi11i * OoOoOO00 % ooOoO0o - iII111i % OoooooooOO
 if 77 - 77: iII111i + o0oOOo0O0Ooo
 if 60 - 60: I1ii11iIi11i
 if 23 - 23: iII111i % I1IiiI % I1Ii111 * oO0o * I1IiiI
 if 74 - 74: O0 / I11i . Oo0Ooo / I11i % OoO0O00 % o0oOOo0O0Ooo
 if 83 - 83: OoO0O00 - i11iIiiIii + iIii1I11I1II1
 oOOo = i11I = None
 if ( rloc ) :
  oOOo = rloc . rloc
  i11I = rloc . translated_port if lisp_i_am_rtr else LISP_DATA_PORT
  if 36 - 36: I1ii11iIi11i / OoO0O00 - oO0o % O0
  if 12 - 12: i1IIi * ooOoO0o / oO0o + I1IiiI / OoooooooOO
  if 86 - 86: Oo0Ooo / OoO0O00
  if 78 - 78: I1IiiI * I1IiiI
  if 13 - 13: oO0o
 iI11 , ooO , O0OoO0o = lisp_myrlocs
 if ( iI11 == None ) :
  lprint ( "Suppress sending Map-Request, IPv4 RLOC not found" )
  return
  if 80 - 80: IiII % OOooOOo
 if ( ooO == None and oOOo != None and oOOo . is_ipv6 ( ) ) :
  lprint ( "Suppress sending Map-Request, IPv6 RLOC not found" )
  return
  if 6 - 6: O0 - Ii1I . OOooOOo
  if 39 - 39: I1IiiI + I1Ii111 / I1ii11iIi11i * i1IIi
 O00O0 = lisp_map_request ( )
 O00O0 . record_count = 1
 O00O0 . nonce = lisp_get_control_nonce ( )
 O00O0 . rloc_probe = ( oOOo != None )
 if 37 - 37: O0 + iIii1I11I1II1 % IiII * oO0o
 if 43 - 43: OOooOOo . O0
 if 76 - 76: OOooOOo * OoooooooOO / IiII . OoO0O00 + II111iiii
 if 23 - 23: OoO0O00 - OoooooooOO * I11i . iIii1I11I1II1 / o0oOOo0O0Ooo + oO0o
 if 74 - 74: II111iiii / I1IiiI * O0 * OoO0O00 . I11i
 if 74 - 74: O0 . i1IIi / I1ii11iIi11i + o0oOOo0O0Ooo
 if 24 - 24: ooOoO0o % I1Ii111 + OoO0O00 * o0oOOo0O0Ooo % O0 - i11iIiiIii
 if ( rloc ) : rloc . last_rloc_probe_nonce = O00O0 . nonce
 if 49 - 49: o0oOOo0O0Ooo / OoOoOO00 + iII111i
 I111iiiIii1I = deid . is_multicast_address ( )
 if ( I111iiiIii1I ) :
  O00O0 . target_eid = seid
  O00O0 . target_group = deid
 else :
  O00O0 . target_eid = deid
  if 85 - 85: I1IiiI - o0oOOo0O0Ooo
  if 86 - 86: II111iiii + Ii1I * Ii1I
  if 26 - 26: o0oOOo0O0Ooo + oO0o * i11iIiiIii / II111iiii
  if 86 - 86: Ii1I
  if 69 - 69: oO0o % o0oOOo0O0Ooo / o0oOOo0O0Ooo
  if 1 - 1: Ii1I
  if 43 - 43: o0oOOo0O0Ooo
  if 78 - 78: I1Ii111 % i1IIi * I11i
  if 59 - 59: OoOoOO00 % OoO0O00 % i11iIiiIii . II111iiii % I1ii11iIi11i + i1IIi
 if ( O00O0 . rloc_probe == False ) :
  I11i111 = lisp_get_signature_eid ( )
  if ( I11i111 ) :
   O00O0 . signature_eid . copy_address ( I11i111 . eid )
   O00O0 . privkey_filename = "./lisp-sig.pem"
   if 99 - 99: I11i + IiII * I1Ii111 - OOooOOo - i1IIi
   if 77 - 77: I11i . IiII / OoO0O00 / I1Ii111
   if 8 - 8: o0oOOo0O0Ooo + iII111i / OoO0O00 * ooOoO0o - oO0o . iII111i
   if 32 - 32: OoooooooOO . I1Ii111 - I1ii11iIi11i
   if 29 - 29: OoO0O00
   if 33 - 33: I1ii11iIi11i - O0
 if ( seid == None or I111iiiIii1I ) :
  O00O0 . source_eid . afi = LISP_AFI_NONE
 else :
  O00O0 . source_eid = seid
  if 72 - 72: Oo0Ooo * iII111i - I11i
  if 81 - 81: I1Ii111
  if 85 - 85: O0 % OoOoOO00 . I1ii11iIi11i
  if 46 - 46: OOooOOo * iIii1I11I1II1
  if 33 - 33: OoO0O00 * II111iiii / i1IIi
  if 93 - 93: I1Ii111 % I11i
  if 64 - 64: I1IiiI % OoOoOO00 / Oo0Ooo
  if 40 - 40: Ii1I + iIii1I11I1II1 / oO0o . II111iiii % O0 - IiII
  if 49 - 49: IiII - OOooOOo * OOooOOo . O0
  if 60 - 60: OoOoOO00 % iIii1I11I1II1 + IiII % o0oOOo0O0Ooo
  if 64 - 64: OoOoOO00 * I1ii11iIi11i . OoooooooOO . i1IIi
  if 61 - 61: OoO0O00
 if ( oOOo != None and lisp_nat_traversal and lisp_i_am_rtr == False ) :
  if ( oOOo . is_private_address ( ) == False ) :
   iI11 = lisp_get_any_translated_rloc ( )
   if 100 - 100: OoOoOO00
  if ( iI11 == None ) :
   lprint ( "Suppress sending Map-Request, translated RLOC not found" )
   return
   if 97 - 97: OoooooooOO
   if 91 - 91: o0oOOo0O0Ooo / O0 % OoO0O00
   if 35 - 35: iII111i % OoO0O00 * O0
   if 37 - 37: OOooOOo
   if 100 - 100: Oo0Ooo * I1IiiI . ooOoO0o
   if 53 - 53: OOooOOo + o0oOOo0O0Ooo * Ii1I + O0
   if 75 - 75: OoooooooOO
   if 24 - 24: I1Ii111 % i11iIiiIii % oO0o . OOooOOo % IiII
 if ( oOOo == None or oOOo . is_ipv4 ( ) ) :
  if ( lisp_nat_traversal and oOOo == None ) :
   IIIiIIi11Ii1 = lisp_get_any_translated_rloc ( )
   if ( IIIiIIi11Ii1 != None ) : iI11 = IIIiIIi11Ii1
   if 30 - 30: Ii1I / I1Ii111 - OoOoOO00 / OOooOOo * I1IiiI + Ii1I
  O00O0 . itr_rlocs . append ( iI11 )
  if 41 - 41: ooOoO0o . i1IIi * iIii1I11I1II1 - I1IiiI
 if ( oOOo == None or oOOo . is_ipv6 ( ) ) :
  if ( ooO == None or ooO . is_ipv6_link_local ( ) ) :
   ooO = None
  else :
   O00O0 . itr_rloc_count = 1 if ( oOOo == None ) else 0
   O00O0 . itr_rlocs . append ( ooO )
   if 9 - 9: I11i % i1IIi / ooOoO0o % iII111i - oO0o - II111iiii
   if 29 - 29: ooOoO0o . II111iiii . i1IIi % oO0o
   if 11 - 11: OoOoOO00 . OoO0O00 % I11i * iII111i % I1Ii111 . O0
   if 17 - 17: OOooOOo / i11iIiiIii - i11iIiiIii . II111iiii . ooOoO0o
   if 38 - 38: OOooOOo . OoooooooOO . II111iiii + OoO0O00 / oO0o . OoooooooOO
   if 100 - 100: OoO0O00
   if 36 - 36: oO0o + Ii1I - O0
   if 19 - 19: O0 + I1Ii111 . I1Ii111 * IiII * ooOoO0o + i1IIi
   if 51 - 51: ooOoO0o % OoOoOO00 % i1IIi / O0
 if ( oOOo != None and O00O0 . itr_rlocs != [ ] ) :
  O0OoO0OOo0o0 = O00O0 . itr_rlocs [ 0 ]
 else :
  if ( deid . is_ipv4 ( ) ) :
   O0OoO0OOo0o0 = iI11
  elif ( deid . is_ipv6 ( ) ) :
   O0OoO0OOo0o0 = ooO
  else :
   O0OoO0OOo0o0 = iI11
   if 11 - 11: OOooOOo . I1ii11iIi11i * OOooOOo * OoO0O00
   if 11 - 11: I11i
   if 85 - 85: OoOoOO00 - Ii1I / Oo0Ooo % I1ii11iIi11i
   if 12 - 12: i1IIi + o0oOOo0O0Ooo / oO0o . O0
   if 37 - 37: IiII
   if 99 - 99: i11iIiiIii % i11iIiiIii . I11i * I1ii11iIi11i . OoO0O00 / I1IiiI
 i1II1IiiIi = O00O0 . encode ( oOOo , i11I )
 O00O0 . print_map_request ( )
 if 44 - 44: iII111i - OoO0O00 / i11iIiiIii
 if 55 - 55: O0 * OoO0O00 * i1IIi
 if 9 - 9: IiII
 if 64 - 64: ooOoO0o + OoooooooOO
 if 99 - 99: iIii1I11I1II1 * II111iiii * i11iIiiIii
 if 10 - 10: OOooOOo
 if ( oOOo != None ) :
  if ( rloc . is_rloc_translated ( ) ) :
   iiiII1 = lisp_get_nat_info ( oOOo , rloc . rloc_name )
   if 75 - 75: I11i * ooOoO0o * Oo0Ooo . i1IIi . ooOoO0o . ooOoO0o
   if 24 - 24: iIii1I11I1II1
   if 72 - 72: i11iIiiIii + o0oOOo0O0Ooo % ooOoO0o * I1ii11iIi11i . i1IIi
   if 59 - 59: OoooooooOO - OoooooooOO - o0oOOo0O0Ooo + i1IIi % I1Ii111
   if ( iiiII1 == None ) :
    O00oo00o000o = rloc . rloc . print_address_no_iid ( )
    O0oOo00Oo0oo0 = "gleaned-{}" . format ( O00oo00o000o )
    i111 = rloc . translated_port
    iiiII1 = lisp_nat_info ( O00oo00o000o , O0oOo00Oo0oo0 , i111 )
    if 74 - 74: IiII * iIii1I11I1II1 - I1IiiI
   lisp_encapsulate_rloc_probe ( lisp_sockets , oOOo , iiiII1 ,
 i1II1IiiIi )
   return
   if 62 - 62: o0oOOo0O0Ooo
   if 54 - 54: iIii1I11I1II1 / OoooooooOO + o0oOOo0O0Ooo . i1IIi - OoooooooOO
  I1iiIiiii1111 = oOOo . print_address_no_iid ( )
  oooooO0oO0o = lisp_convert_4to6 ( I1iiIiiii1111 )
  lisp_send ( lisp_sockets , oooooO0oO0o , LISP_CTRL_PORT , i1II1IiiIi )
  return
  if 70 - 70: Ii1I / OoOoOO00 * Oo0Ooo
  if 32 - 32: I1Ii111 . OoOoOO00 % OoooooooOO + I1Ii111 * OoO0O00
  if 84 - 84: OoOoOO00
  if 80 - 80: oO0o
  if 59 - 59: iIii1I11I1II1 / IiII % I1ii11iIi11i + OoO0O00 - I11i % OOooOOo
  if 92 - 92: iII111i
 OOoOO = None if lisp_i_am_rtr else seid
 if ( lisp_decent_pull_xtr_configured ( ) ) :
  IIiIII1IIi = lisp_get_decent_map_resolver ( deid )
 else :
  IIiIII1IIi = lisp_get_map_resolver ( None , OOoOO )
  if 47 - 47: Oo0Ooo . I1ii11iIi11i * I1IiiI
 if ( IIiIII1IIi == None ) :
  lprint ( "Cannot find Map-Resolver for source-EID {}" . format ( green ( seid . print_address ( ) , False ) ) )
  if 46 - 46: I1Ii111 / I11i
  return
  if 13 - 13: I1ii11iIi11i + II111iiii * IiII * OoooooooOO + O0 * O0
 IIiIII1IIi . last_used = lisp_get_timestamp ( )
 IIiIII1IIi . map_requests_sent += 1
 if ( IIiIII1IIi . last_nonce == 0 ) : IIiIII1IIi . last_nonce = O00O0 . nonce
 if 15 - 15: Oo0Ooo % I11i * O0
 if 61 - 61: I1ii11iIi11i - ooOoO0o / OoOoOO00 % OOooOOo * i1IIi . IiII
 if 27 - 27: I1ii11iIi11i % iII111i . Oo0Ooo * iIii1I11I1II1
 if 40 - 40: I11i
 if ( seid == None ) : seid = O0OoO0OOo0o0
 lisp_send_ecm ( lisp_sockets , i1II1IiiIi , seid , lisp_ephem_port , deid ,
 IIiIII1IIi . map_resolver )
 if 58 - 58: o0oOOo0O0Ooo / OOooOOo . oO0o % ooOoO0o
 if 33 - 33: I1IiiI * I1ii11iIi11i . OoO0O00 - I1Ii111 . OoO0O00
 if 79 - 79: ooOoO0o
 if 90 - 90: OOooOOo
 lisp_last_map_request_sent = lisp_get_timestamp ( )
 if 4 - 4: OoOoOO00 - I1Ii111 . i1IIi - IiII . ooOoO0o + II111iiii
 if 56 - 56: I1ii11iIi11i / i1IIi + I11i % Oo0Ooo
 if 86 - 86: O0 * II111iiii
 if 75 - 75: iIii1I11I1II1 - Oo0Ooo - OoOoOO00 % I1ii11iIi11i . II111iiii
 IIiIII1IIi . resolve_dns_name ( )
 return
 if 11 - 11: I1ii11iIi11i - I1ii11iIi11i . ooOoO0o * Oo0Ooo + I1Ii111
 if 59 - 59: iII111i - OOooOOo - OoO0O00 . I1IiiI % o0oOOo0O0Ooo + iII111i
 if 10 - 10: iIii1I11I1II1 - Ii1I
 if 84 - 84: iII111i
 if 21 - 21: i11iIiiIii
 if 30 - 30: OoO0O00 + OoooooooOO
 if 98 - 98: I1ii11iIi11i % I1IiiI
 if 9 - 9: o0oOOo0O0Ooo / I1Ii111 % i1IIi - OOooOOo % I1IiiI / I1ii11iIi11i
def lisp_send_info_request ( lisp_sockets , dest , port , device_name ) :
 if 66 - 66: IiII
 if 56 - 56: oO0o + OoooooooOO
 if 75 - 75: O0 % Ii1I
 if 47 - 47: OoooooooOO - OoooooooOO + OoO0O00 / iIii1I11I1II1
 i1iii11iiiI1I = lisp_info ( )
 i1iii11iiiI1I . nonce = lisp_get_control_nonce ( )
 if ( device_name ) : i1iii11iiiI1I . hostname += "-" + device_name
 if 7 - 7: OoooooooOO - oO0o . Ii1I % OoO0O00 % I1Ii111
 I1iiIiiii1111 = dest . print_address_no_iid ( )
 if 95 - 95: O0
 if 45 - 45: I1Ii111 / I1IiiI . I1ii11iIi11i . I1ii11iIi11i
 if 7 - 7: I1IiiI + iII111i . O0 - OOooOOo
 if 84 - 84: i11iIiiIii * iIii1I11I1II1 % I11i % iII111i + OoooooooOO . o0oOOo0O0Ooo
 if 78 - 78: o0oOOo0O0Ooo . iII111i + O0 / I1ii11iIi11i + I1ii11iIi11i + II111iiii
 if 96 - 96: iIii1I11I1II1 * II111iiii . iIii1I11I1II1
 if 13 - 13: Ii1I - OoOoOO00 . Ii1I
 if 7 - 7: Ii1I - I11i / I1ii11iIi11i + iII111i
 if 47 - 47: I11i * IiII / oO0o - OoooooooOO . OoooooooOO / I11i
 if 73 - 73: Ii1I . IiII % IiII
 if 56 - 56: I1Ii111 + iII111i + iII111i
 if 99 - 99: o0oOOo0O0Ooo % I1ii11iIi11i / Oo0Ooo . O0 + OoO0O00 * OoOoOO00
 if 48 - 48: iIii1I11I1II1 + O0 * I11i * i11iIiiIii . Ii1I / i1IIi
 if 48 - 48: i1IIi % iIii1I11I1II1 + I1IiiI - OoOoOO00 % I11i . I1Ii111
 if 66 - 66: I1Ii111 * i11iIiiIii + I1IiiI % II111iiii
 if 47 - 47: II111iiii % o0oOOo0O0Ooo
 IIi1 = False
 if ( device_name ) :
  ii1i1I = lisp_get_host_route_next_hop ( I1iiIiiii1111 )
  if 72 - 72: i1IIi * II111iiii
  if 71 - 71: O0 / I1Ii111 * iII111i - oO0o
  if 47 - 47: O0 % oO0o + ooOoO0o
  if 65 - 65: iII111i
  if 3 - 3: iIii1I11I1II1
  if 25 - 25: OOooOOo * OoO0O00 + o0oOOo0O0Ooo % Ii1I - o0oOOo0O0Ooo - iII111i
  if 17 - 17: O0 . ooOoO0o % I1IiiI . iII111i / oO0o . IiII
  if 95 - 95: ooOoO0o . I11i / i11iIiiIii - IiII
  if 87 - 87: I1Ii111 - iII111i * I11i
  if ( port == LISP_CTRL_PORT and ii1i1I != None ) :
   while ( True ) :
    time . sleep ( .01 )
    ii1i1I = lisp_get_host_route_next_hop ( I1iiIiiii1111 )
    if ( ii1i1I == None ) : break
    if 74 - 74: Ii1I - OoOoOO00 + i11iIiiIii - II111iiii - i11iIiiIii . ooOoO0o
    if 83 - 83: I1Ii111 % ooOoO0o + OoooooooOO
    if 50 - 50: i11iIiiIii % I1IiiI * iII111i / Ii1I
  I1III = lisp_get_default_route_next_hops ( )
  for O0OoO0o , o00ooO0Ooo in I1III :
   if ( O0OoO0o != device_name ) : continue
   if 26 - 26: i11iIiiIii % i1IIi / OoO0O00
   if 92 - 92: II111iiii / IiII + Oo0Ooo * OoOoOO00 / I1IiiI
   if 74 - 74: II111iiii . IiII - o0oOOo0O0Ooo . O0 % I11i . Ii1I
   if 11 - 11: I1Ii111 . OoooooooOO
   if 49 - 49: OOooOOo % I11i - OOooOOo + Ii1I . I1ii11iIi11i + ooOoO0o
   if 15 - 15: i11iIiiIii
   if ( ii1i1I != o00ooO0Ooo ) :
    if ( ii1i1I != None ) :
     lisp_install_host_route ( I1iiIiiii1111 , ii1i1I , False )
     if 85 - 85: I1Ii111 + iII111i - oO0o
    lisp_install_host_route ( I1iiIiiii1111 , o00ooO0Ooo , True )
    IIi1 = True
    if 59 - 59: IiII . oO0o / i11iIiiIii . I1Ii111
   break
   if 64 - 64: OoOoOO00
   if 20 - 20: OoOoOO00 / O0 * OOooOOo % I11i + OoO0O00 + o0oOOo0O0Ooo
   if 51 - 51: Ii1I - OoOoOO00 / i11iIiiIii + O0
   if 71 - 71: ooOoO0o
   if 35 - 35: OoOoOO00
   if 55 - 55: iII111i - o0oOOo0O0Ooo + IiII * II111iiii
 i1II1IiiIi = i1iii11iiiI1I . encode ( )
 i1iii11iiiI1I . print_info ( )
 if 6 - 6: I1Ii111 / i1IIi / IiII . o0oOOo0O0Ooo
 if 69 - 69: ooOoO0o - OoOoOO00 . I1IiiI . I11i + OoOoOO00 / i11iIiiIii
 if 20 - 20: OoO0O00 . OoooooooOO - ooOoO0o . I11i / Oo0Ooo
 if 89 - 89: iIii1I11I1II1 . ooOoO0o
 OOoo0O00 = "(for control)" if port == LISP_CTRL_PORT else "(for data)"
 OOoo0O00 = bold ( OOoo0O00 , False )
 i111 = bold ( "{}" . format ( port ) , False )
 oOO0oo = red ( I1iiIiiii1111 , False )
 iI11I1I = "RTR " if port == LISP_DATA_PORT else "MS "
 lprint ( "Send Info-Request to {}{}, port {} {}" . format ( iI11I1I , oOO0oo , i111 , OOoo0O00 ) )
 if 22 - 22: oO0o + O0 + I11i . OoO0O00 - II111iiii
 if 20 - 20: Ii1I * I1Ii111 . I1IiiI % OoOoOO00 / OoO0O00 % II111iiii
 if 43 - 43: IiII + II111iiii + oO0o / I1ii11iIi11i % i1IIi - OoO0O00
 if 59 - 59: Oo0Ooo + O0 + iII111i
 if 71 - 71: IiII - OoO0O00
 if 90 - 90: Oo0Ooo
 if ( port == LISP_CTRL_PORT ) :
  lisp_send ( lisp_sockets , dest , LISP_CTRL_PORT , i1II1IiiIi )
 else :
  I1I = lisp_data_header ( )
  I1I . instance_id ( 0xffffff )
  I1I = I1I . encode ( )
  if ( I1I ) :
   i1II1IiiIi = I1I + i1II1IiiIi
   if 83 - 83: iIii1I11I1II1 % ooOoO0o % OOooOOo * i1IIi - o0oOOo0O0Ooo * i1IIi
   if 60 - 60: Ii1I . I1ii11iIi11i - I11i + i11iIiiIii / iII111i
   if 9 - 9: I1Ii111 . oO0o . OoO0O00 / IiII - oO0o / oO0o
   if 50 - 50: II111iiii + OoOoOO00
   if 17 - 17: ooOoO0o + I1ii11iIi11i
   if 34 - 34: Ii1I / II111iiii + OoOoOO00 . II111iiii + OoooooooOO * o0oOOo0O0Ooo
   if 48 - 48: O0
   if 99 - 99: II111iiii * oO0o / I1ii11iIi11i - i1IIi
   if 84 - 84: i11iIiiIii . OoooooooOO
   lisp_send ( lisp_sockets , dest , LISP_DATA_PORT , i1II1IiiIi )
   if 69 - 69: I1Ii111 * II111iiii % I1Ii111 * i11iIiiIii . ooOoO0o / Oo0Ooo
   if 5 - 5: Ii1I
   if 19 - 19: oO0o
   if 61 - 61: OoOoOO00 + iIii1I11I1II1 / I1ii11iIi11i - i1IIi
   if 11 - 11: oO0o * o0oOOo0O0Ooo . I1IiiI
   if 12 - 12: I1IiiI % OoO0O00 / I1Ii111 / O0 % o0oOOo0O0Ooo
   if 1 - 1: OoOoOO00 / I11i
 if ( IIi1 ) :
  lisp_install_host_route ( I1iiIiiii1111 , None , False )
  if ( ii1i1I != None ) : lisp_install_host_route ( I1iiIiiii1111 , ii1i1I , True )
  if 43 - 43: o0oOOo0O0Ooo - i1IIi / Ii1I . OoOoOO00 + i11iIiiIii
 return
 if 69 - 69: i11iIiiIii - iIii1I11I1II1
 if 40 - 40: I1IiiI / oO0o + ooOoO0o
 if 100 - 100: OoOoOO00 % iII111i * ooOoO0o . O0
 if 37 - 37: I1ii11iIi11i
 if 24 - 24: O0 . I1Ii111 * i11iIiiIii
 if 84 - 84: ooOoO0o / I1ii11iIi11i - o0oOOo0O0Ooo . OoooooooOO * iIii1I11I1II1
 if 16 - 16: I11i % O0
def lisp_process_info_request ( lisp_sockets , packet , addr_str , sport , rtr_list ) :
 if 56 - 56: Ii1I * OoOoOO00 . i1IIi
 if 15 - 15: I1Ii111
 if 64 - 64: OOooOOo * Oo0Ooo
 if 96 - 96: Oo0Ooo / I1ii11iIi11i * iIii1I11I1II1 / iII111i
 i1iii11iiiI1I = lisp_info ( )
 packet = i1iii11iiiI1I . decode ( packet )
 if ( packet == None ) : return
 i1iii11iiiI1I . print_info ( )
 if 18 - 18: I1Ii111
 if 29 - 29: i1IIi - I1IiiI / i1IIi
 if 64 - 64: IiII
 if 69 - 69: OOooOOo . I1IiiI
 if 11 - 11: I1Ii111 * I1IiiI - I1Ii111 / iII111i
 i1iii11iiiI1I . info_reply = True
 i1iii11iiiI1I . global_etr_rloc . store_address ( addr_str )
 i1iii11iiiI1I . etr_port = sport
 if 22 - 22: iII111i % I11i % O0 - I11i
 if 71 - 71: I1Ii111 / II111iiii - OoooooooOO % i1IIi + OoOoOO00 % OoooooooOO
 if 52 - 52: Ii1I . OoOoOO00 / o0oOOo0O0Ooo / iII111i
 if 83 - 83: OoO0O00 - Oo0Ooo + I1Ii111 . I1IiiI
 if 78 - 78: I11i / ooOoO0o . OoOoOO00 * i1IIi
 if ( i1iii11iiiI1I . hostname != None ) :
  i1iii11iiiI1I . private_etr_rloc . afi = LISP_AFI_NAME
  i1iii11iiiI1I . private_etr_rloc . store_address ( i1iii11iiiI1I . hostname )
  if 15 - 15: i1IIi . II111iiii * OoOoOO00 / Oo0Ooo
  if 99 - 99: iII111i - o0oOOo0O0Ooo / O0
 if ( rtr_list != None ) : i1iii11iiiI1I . rtr_list = rtr_list
 packet = i1iii11iiiI1I . encode ( )
 i1iii11iiiI1I . print_info ( )
 if 97 - 97: iIii1I11I1II1 * I1Ii111
 if 39 - 39: I1Ii111 . II111iiii
 if 94 - 94: OoO0O00 - OoO0O00 + iIii1I11I1II1 + O0 * oO0o
 if 9 - 9: Ii1I * Oo0Ooo / oO0o / Ii1I
 if 34 - 34: I1IiiI
 lprint ( "Send Info-Reply to {}" . format ( red ( addr_str , False ) ) )
 oooooO0oO0o = lisp_convert_4to6 ( addr_str )
 lisp_send ( lisp_sockets , oooooO0oO0o , sport , packet )
 if 56 - 56: Ii1I
 if 71 - 71: O0 / i1IIi
 if 20 - 20: OOooOOo . iIii1I11I1II1 - I1Ii111 . i1IIi
 if 82 - 82: oO0o * i11iIiiIii % o0oOOo0O0Ooo % IiII - I11i - OoO0O00
 if 24 - 24: oO0o . II111iiii + OoO0O00 * I1ii11iIi11i / oO0o
 o0OO0O0 = lisp_info_source ( i1iii11iiiI1I . hostname , addr_str , sport )
 o0OO0O0 . cache_address_for_info_source ( )
 return
 if 9 - 9: oO0o
 if 53 - 53: IiII / iII111i / I1Ii111 / Oo0Ooo
 if 13 - 13: iII111i - OoooooooOO % iIii1I11I1II1 % O0 % i1IIi
 if 94 - 94: Oo0Ooo
 if 33 - 33: oO0o / ooOoO0o
 if 92 - 92: O0 . Oo0Ooo - Ii1I * I1IiiI * Oo0Ooo * iII111i
 if 78 - 78: Ii1I * iIii1I11I1II1 - Ii1I - I1ii11iIi11i * I1ii11iIi11i
 if 44 - 44: o0oOOo0O0Ooo
def lisp_get_signature_eid ( ) :
 for I11i111 in lisp_db_list :
  if ( I11i111 . signature_eid ) : return ( I11i111 )
  if 1 - 1: OoooooooOO / i11iIiiIii . o0oOOo0O0Ooo
 return ( None )
 if 78 - 78: OOooOOo * O0 * II111iiii % OoOoOO00
 if 12 - 12: Oo0Ooo . o0oOOo0O0Ooo - i1IIi - oO0o % IiII . I11i
 if 17 - 17: i1IIi % OoO0O00 + i11iIiiIii % I1Ii111 * ooOoO0o . I1ii11iIi11i
 if 64 - 64: O0 - iII111i
 if 82 - 82: O0
 if 37 - 37: I1Ii111
 if 98 - 98: iII111i - OoOoOO00 / I1Ii111 . OOooOOo - OOooOOo - ooOoO0o
 if 84 - 84: OOooOOo * ooOoO0o / O0
def lisp_get_any_translated_port ( ) :
 for I11i111 in lisp_db_list :
  for IIiO0Ooo in I11i111 . rloc_set :
   if ( IIiO0Ooo . translated_rloc . is_null ( ) ) : continue
   return ( IIiO0Ooo . translated_port )
   if 96 - 96: I11i . I11i % II111iiii
   if 14 - 14: iII111i / OoooooooOO
 return ( None )
 if 8 - 8: OOooOOo + I1IiiI - Oo0Ooo + i1IIi . Ii1I . I1Ii111
 if 38 - 38: I1IiiI / II111iiii * OoOoOO00 / I1Ii111
 if 80 - 80: I1ii11iIi11i / ooOoO0o * ooOoO0o . Oo0Ooo
 if 44 - 44: Ii1I * i1IIi % OoOoOO00 . OoOoOO00
 if 16 - 16: Oo0Ooo / i1IIi / iIii1I11I1II1 / iIii1I11I1II1 % o0oOOo0O0Ooo / I1ii11iIi11i
 if 11 - 11: I1IiiI
 if 45 - 45: OOooOOo / i1IIi * IiII * I1Ii111
 if 34 - 34: ooOoO0o / iIii1I11I1II1 . iII111i
 if 91 - 91: OoO0O00
def lisp_get_any_translated_rloc ( ) :
 for I11i111 in lisp_db_list :
  for IIiO0Ooo in I11i111 . rloc_set :
   if ( IIiO0Ooo . translated_rloc . is_null ( ) ) : continue
   return ( IIiO0Ooo . translated_rloc )
   if 8 - 8: oO0o
   if 96 - 96: IiII
 return ( None )
 if 37 - 37: Ii1I % i11iIiiIii + iIii1I11I1II1 % Oo0Ooo - iIii1I11I1II1
 if 26 - 26: o0oOOo0O0Ooo . i1IIi
 if 62 - 62: IiII * I1ii11iIi11i % iIii1I11I1II1 / II111iiii - OoO0O00
 if 52 - 52: iII111i . I11i - I11i + oO0o + iIii1I11I1II1
 if 83 - 83: I11i * iIii1I11I1II1 + OoOoOO00
 if 81 - 81: ooOoO0o * OOooOOo / OoO0O00 + I1ii11iIi11i % I1Ii111
 if 37 - 37: i11iIiiIii - OoooooooOO - OoOoOO00 * oO0o / Ii1I
def lisp_get_all_translated_rlocs ( ) :
 OooOo = [ ]
 for I11i111 in lisp_db_list :
  for IIiO0Ooo in I11i111 . rloc_set :
   if ( IIiO0Ooo . is_rloc_translated ( ) == False ) : continue
   o0o0O00 = IIiO0Ooo . translated_rloc . print_address_no_iid ( )
   OooOo . append ( o0o0O00 )
   if 82 - 82: i11iIiiIii * OoOoOO00 . i1IIi + IiII * ooOoO0o
   if 75 - 75: iIii1I11I1II1 / IiII / II111iiii . I11i
 return ( OooOo )
 if 23 - 23: OOooOOo . ooOoO0o - iII111i % Ii1I . I1ii11iIi11i + IiII
 if 81 - 81: I11i
 if 5 - 5: OoooooooOO
 if 5 - 5: iII111i + oO0o % O0 . OoooooooOO + i1IIi
 if 55 - 55: I1ii11iIi11i
 if 34 - 34: OoO0O00 * iIii1I11I1II1 . iIii1I11I1II1
 if 39 - 39: o0oOOo0O0Ooo
 if 29 - 29: Oo0Ooo . Oo0Ooo * OoO0O00 % Ii1I - ooOoO0o
def lisp_update_default_routes ( map_resolver , iid , rtr_list ) :
 OOOoOO = ( os . getenv ( "LISP_RTR_BEHIND_NAT" ) != None )
 if 67 - 67: I1IiiI % O0 + I1IiiI * I1Ii111 * OoOoOO00 * II111iiii
 oOoO0 = { }
 for oOOoo0O00 in rtr_list :
  if ( oOOoo0O00 == None ) : continue
  o0o0O00 = rtr_list [ oOOoo0O00 ]
  if ( OOOoOO and o0o0O00 . is_private_address ( ) ) : continue
  oOoO0 [ oOOoo0O00 ] = o0o0O00
  if 76 - 76: i11iIiiIii . I1IiiI - I1Ii111
 rtr_list = oOoO0
 if 6 - 6: I1IiiI / i1IIi + IiII / iIii1I11I1II1
 iIi1i = [ ]
 for oOo00Oo0o00oo in [ LISP_AFI_IPV4 , LISP_AFI_IPV6 , LISP_AFI_MAC ] :
  if ( oOo00Oo0o00oo == LISP_AFI_MAC and lisp_l2_overlay == False ) : break
  if 5 - 5: OoOoOO00 . iIii1I11I1II1 + iII111i
  if 63 - 63: i1IIi
  if 24 - 24: i11iIiiIii % iII111i . oO0o
  if 44 - 44: II111iiii - OoO0O00 + i11iIiiIii
  if 34 - 34: I1ii11iIi11i % ooOoO0o / II111iiii * O0 % OOooOOo
  OOoOOoo = lisp_address ( oOo00Oo0o00oo , "" , 0 , iid )
  OOoOOoo . make_default_route ( OOoOOoo )
  Iii1 = lisp_map_cache . lookup_cache ( OOoOOoo , True )
  if ( Iii1 ) :
   if ( Iii1 . checkpoint_entry ) :
    lprint ( "Updating checkpoint entry for {}" . format ( green ( Iii1 . print_eid_tuple ( ) , False ) ) )
    if 9 - 9: I1ii11iIi11i / I1ii11iIi11i - OOooOOo . iIii1I11I1II1
   elif ( Iii1 . do_rloc_sets_match ( rtr_list . values ( ) ) ) :
    continue
    if 33 - 33: I1IiiI + oO0o % I1IiiI / iII111i - ooOoO0o - i11iIiiIii
   Iii1 . delete_cache ( )
   if 39 - 39: i11iIiiIii / oO0o
   if 71 - 71: I1Ii111 * iIii1I11I1II1 - I1Ii111
  iIi1i . append ( [ OOoOOoo , "" ] )
  if 87 - 87: I1IiiI / Ii1I
  if 54 - 54: OoooooooOO / Ii1I
  if 26 - 26: o0oOOo0O0Ooo + OoO0O00
  if 59 - 59: Ii1I * IiII
  ii1I1 = lisp_address ( oOo00Oo0o00oo , "" , 0 , iid )
  ii1I1 . make_default_multicast_route ( ii1I1 )
  o0OiiI1iiI11 = lisp_map_cache . lookup_cache ( ii1I1 , True )
  if ( o0OiiI1iiI11 ) : o0OiiI1iiI11 = o0OiiI1iiI11 . source_cache . lookup_cache ( OOoOOoo , True )
  if ( o0OiiI1iiI11 ) : o0OiiI1iiI11 . delete_cache ( )
  if 3 - 3: I11i
  iIi1i . append ( [ OOoOOoo , ii1I1 ] )
  if 55 - 55: OoO0O00 . i11iIiiIii . o0oOOo0O0Ooo % iIii1I11I1II1 . I1ii11iIi11i * I11i
 if ( len ( iIi1i ) == 0 ) : return
 if 7 - 7: OoOoOO00 * iII111i - i11iIiiIii
 if 79 - 79: OOooOOo
 if 2 - 2: I11i % I1Ii111 - OoO0O00 % OoO0O00 % OOooOOo - OoO0O00
 if 3 - 3: iIii1I11I1II1 + iIii1I11I1II1 + OoO0O00
 iii1Ii1i1i1I = [ ]
 for iI11I1I in rtr_list :
  oo00OOo000o0 = rtr_list [ iI11I1I ]
  IIiO0Ooo = lisp_rloc ( )
  IIiO0Ooo . rloc . copy_address ( oo00OOo000o0 )
  IIiO0Ooo . priority = 254
  IIiO0Ooo . mpriority = 255
  IIiO0Ooo . rloc_name = "RTR"
  iii1Ii1i1i1I . append ( IIiO0Ooo )
  if 82 - 82: OoOoOO00 - OoOoOO00 + iIii1I11I1II1 + o0oOOo0O0Ooo + IiII - o0oOOo0O0Ooo
  if 65 - 65: I1Ii111 + OOooOOo
 for OOoOOoo in iIi1i :
  Iii1 = lisp_mapping ( OOoOOoo [ 0 ] , OOoOOoo [ 1 ] , iii1Ii1i1i1I )
  Iii1 . mapping_source = map_resolver
  Iii1 . map_cache_ttl = LISP_MR_TTL * 60
  Iii1 . add_cache ( )
  lprint ( "Add {} to map-cache with RTR RLOC-set: {}" . format ( green ( Iii1 . print_eid_tuple ( ) , False ) , rtr_list . keys ( ) ) )
  if 97 - 97: oO0o % OoOoOO00 * oO0o % II111iiii + iIii1I11I1II1
  iii1Ii1i1i1I = copy . deepcopy ( iii1Ii1i1i1I )
  if 11 - 11: ooOoO0o . o0oOOo0O0Ooo
 return
 if 94 - 94: ooOoO0o . oO0o * OoooooooOO % oO0o
 if 77 - 77: ooOoO0o % I1IiiI
 if 26 - 26: o0oOOo0O0Ooo
 if 72 - 72: I1IiiI
 if 90 - 90: ooOoO0o
 if 67 - 67: iIii1I11I1II1 + i1IIi * I1IiiI * OoooooooOO
 if 23 - 23: IiII
 if 32 - 32: OoOoOO00 - iII111i % oO0o / I1ii11iIi11i - o0oOOo0O0Ooo
 if 52 - 52: Ii1I / OoooooooOO % i11iIiiIii + iII111i
 if 59 - 59: Ii1I / o0oOOo0O0Ooo / oO0o + iII111i * I1ii11iIi11i - o0oOOo0O0Ooo
def lisp_process_info_reply ( source , packet , store ) :
 if 70 - 70: O0 / I1ii11iIi11i + ooOoO0o . OoO0O00 - OoO0O00 / i11iIiiIii
 if 1 - 1: iIii1I11I1II1 % I1ii11iIi11i
 if 49 - 49: iII111i + o0oOOo0O0Ooo % I1ii11iIi11i . O0 % OoooooooOO . o0oOOo0O0Ooo
 if 3 - 3: i11iIiiIii - i1IIi * o0oOOo0O0Ooo / OoOoOO00 % Oo0Ooo
 i1iii11iiiI1I = lisp_info ( )
 packet = i1iii11iiiI1I . decode ( packet )
 if ( packet == None ) : return ( [ None , None , False ] )
 if 65 - 65: OoooooooOO + iII111i - i11iIiiIii - IiII + oO0o
 i1iii11iiiI1I . print_info ( )
 if 67 - 67: i1IIi * I1Ii111 * O0
 if 16 - 16: OoO0O00 + iII111i + i1IIi + I1ii11iIi11i - I1IiiI
 if 88 - 88: oO0o % iII111i + I1ii11iIi11i - II111iiii . I11i
 if 18 - 18: I1ii11iIi11i - i1IIi - IiII * II111iiii % I1Ii111 . II111iiii
 OOOOoOO = False
 for iI11I1I in i1iii11iiiI1I . rtr_list :
  I1iiIiiii1111 = iI11I1I . print_address_no_iid ( )
  if ( lisp_rtr_list . has_key ( I1iiIiiii1111 ) ) :
   if ( lisp_register_all_rtrs == False ) : continue
   if ( lisp_rtr_list [ I1iiIiiii1111 ] != None ) : continue
   if 75 - 75: i11iIiiIii
  OOOOoOO = True
  lisp_rtr_list [ I1iiIiiii1111 ] = iI11I1I
  if 58 - 58: iII111i
  if 48 - 48: OoO0O00 * OOooOOo / iII111i
  if 90 - 90: I1IiiI * i11iIiiIii . OOooOOo / o0oOOo0O0Ooo
  if 82 - 82: Oo0Ooo
  if 50 - 50: I1Ii111 * OOooOOo * OoOoOO00 / OoooooooOO % iII111i
 if ( lisp_i_am_itr and OOOOoOO ) :
  if ( lisp_iid_to_interface == { } ) :
   lisp_update_default_routes ( source , lisp_default_iid , lisp_rtr_list )
  else :
   for o0OOoOO in lisp_iid_to_interface . keys ( ) :
    lisp_update_default_routes ( source , int ( o0OOoOO ) , lisp_rtr_list )
    if 80 - 80: I1Ii111
    if 35 - 35: Ii1I . O0 % i11iIiiIii * oO0o - OoooooooOO
    if 87 - 87: iII111i * ooOoO0o - OOooOOo . O0
    if 20 - 20: OoOoOO00 - IiII
    if 9 - 9: O0 . I11i % I1ii11iIi11i * oO0o - I1Ii111 - i1IIi
    if 66 - 66: II111iiii / Oo0Ooo
    if 93 - 93: iII111i + I11i * OoooooooOO . OoO0O00
 if ( store == False ) :
  return ( [ i1iii11iiiI1I . global_etr_rloc , i1iii11iiiI1I . etr_port , OOOOoOO ] )
  if 40 - 40: ooOoO0o * I1Ii111 + iII111i
  if 52 - 52: iII111i % I11i
  if 95 - 95: IiII + Ii1I / OoO0O00 - iII111i / I1IiiI
  if 27 - 27: Oo0Ooo + i1IIi + i11iIiiIii . OoO0O00 . OoO0O00
  if 56 - 56: I1Ii111 / OoO0O00 + o0oOOo0O0Ooo . OoooooooOO * Oo0Ooo
  if 14 - 14: OoO0O00
 for I11i111 in lisp_db_list :
  for IIiO0Ooo in I11i111 . rloc_set :
   oOOoo0O00 = IIiO0Ooo . rloc
   I111IIiIII = IIiO0Ooo . interface
   if ( I111IIiIII == None ) :
    if ( oOOoo0O00 . is_null ( ) ) : continue
    if ( oOOoo0O00 . is_local ( ) == False ) : continue
    if ( i1iii11iiiI1I . private_etr_rloc . is_null ( ) == False and
 oOOoo0O00 . is_exact_match ( i1iii11iiiI1I . private_etr_rloc ) == False ) :
     continue
     if 21 - 21: II111iiii + i11iIiiIii + I11i % I1IiiI
   elif ( i1iii11iiiI1I . private_etr_rloc . is_dist_name ( ) ) :
    I1IiiIoo0o00O = i1iii11iiiI1I . private_etr_rloc . address
    if ( I1IiiIoo0o00O != IIiO0Ooo . rloc_name ) : continue
    if 65 - 65: IiII + I1ii11iIi11i / iII111i / I1IiiI + Ii1I
    if 88 - 88: IiII % iIii1I11I1II1
   oOoo0OooOOo00 = green ( I11i111 . eid . print_prefix ( ) , False )
   oooOOoo0 = red ( oOOoo0O00 . print_address_no_iid ( ) , False )
   if 3 - 3: ooOoO0o / I1Ii111 % iIii1I11I1II1 % I11i * oO0o / iIii1I11I1II1
   ooOoO0OoOo = i1iii11iiiI1I . global_etr_rloc . is_exact_match ( oOOoo0O00 )
   if ( IIiO0Ooo . translated_port == 0 and ooOoO0OoOo ) :
    lprint ( "No NAT for {} ({}), EID-prefix {}" . format ( oooOOoo0 ,
 I111IIiIII , oOoo0OooOOo00 ) )
    continue
    if 45 - 45: oO0o % I1ii11iIi11i * I1Ii111
    if 21 - 21: O0 + i11iIiiIii
    if 72 - 72: OoOoOO00 * OoooooooOO % O0 / I1ii11iIi11i % Ii1I - I11i
    if 65 - 65: iIii1I11I1II1 + II111iiii * OoO0O00 * i11iIiiIii / IiII
    if 15 - 15: OoOoOO00 % O0 - OOooOOo - oO0o . iII111i . OoO0O00
   ooO0oO0o0O0o = i1iii11iiiI1I . global_etr_rloc
   I1iIIi = IIiO0Ooo . translated_rloc
   if ( I1iIIi . is_exact_match ( ooO0oO0o0O0o ) and
 i1iii11iiiI1I . etr_port == IIiO0Ooo . translated_port ) : continue
   if 80 - 80: i1IIi / I1Ii111 / I11i . O0 * OoooooooOO + IiII
   lprint ( "Store translation {}:{} for {} ({}), EID-prefix {}" . format ( red ( i1iii11iiiI1I . global_etr_rloc . print_address_no_iid ( ) , False ) ,
   # oO0o % II111iiii . IiII + Oo0Ooo * OoO0O00 * II111iiii
 i1iii11iiiI1I . etr_port , oooOOoo0 , I111IIiIII , oOoo0OooOOo00 ) )
   if 48 - 48: I1Ii111 % iII111i
   IIiO0Ooo . store_translated_rloc ( i1iii11iiiI1I . global_etr_rloc ,
 i1iii11iiiI1I . etr_port )
   if 76 - 76: OoOoOO00
   if 63 - 63: OoOoOO00 % i11iIiiIii - Ii1I
 return ( [ i1iii11iiiI1I . global_etr_rloc , i1iii11iiiI1I . etr_port , OOOOoOO ] )
 if 56 - 56: OoooooooOO % OoOoOO00
 if 11 - 11: OoOoOO00 * OoOoOO00 % I11i
 if 21 - 21: ooOoO0o . i11iIiiIii / IiII . i1IIi + OoooooooOO
 if 18 - 18: ooOoO0o - I11i - I1Ii111
 if 81 - 81: IiII - Ii1I % i1IIi
 if 48 - 48: Ii1I + I11i % iIii1I11I1II1 + ooOoO0o + ooOoO0o + OoO0O00
 if 7 - 7: O0 + II111iiii
 if 44 - 44: OOooOOo + i11iIiiIii - I1Ii111 + ooOoO0o
def lisp_test_mr ( lisp_sockets , port ) :
 return
 lprint ( "Test Map-Resolvers" )
 if 92 - 92: O0 . iIii1I11I1II1 % iIii1I11I1II1 % OoO0O00 - i11iIiiIii - iII111i
 o00oo00oo = lisp_address ( LISP_AFI_IPV4 , "" , 0 , 0 )
 oOo = lisp_address ( LISP_AFI_IPV6 , "" , 0 , 0 )
 if 26 - 26: iII111i . OoOoOO00 . O0 + OoO0O00
 if 85 - 85: I1IiiI
 if 35 - 35: i11iIiiIii . I11i . OoOoOO00 - i11iIiiIii / oO0o / IiII
 if 84 - 84: I11i . oO0o + ooOoO0o
 o00oo00oo . store_address ( "10.0.0.1" )
 lisp_send_map_request ( lisp_sockets , port , None , o00oo00oo , None )
 o00oo00oo . store_address ( "192.168.0.1" )
 lisp_send_map_request ( lisp_sockets , port , None , o00oo00oo , None )
 if 75 - 75: I1Ii111
 if 97 - 97: ooOoO0o % Oo0Ooo . o0oOOo0O0Ooo
 if 22 - 22: O0 % I11i + OoO0O00 - iII111i + I1IiiI . O0
 if 73 - 73: ooOoO0o + O0 - I11i . I1IiiI + OOooOOo
 oOo . store_address ( "0100::1" )
 lisp_send_map_request ( lisp_sockets , port , None , oOo , None )
 oOo . store_address ( "8000::1" )
 lisp_send_map_request ( lisp_sockets , port , None , oOo , None )
 if 36 - 36: I11i % OoO0O00 * OoOoOO00 - I1Ii111
 if 16 - 16: ooOoO0o % OOooOOo . OoO0O00 % II111iiii . iIii1I11I1II1
 if 21 - 21: oO0o + II111iiii / OoOoOO00 * I11i
 if 90 - 90: OoOoOO00 % OoOoOO00 + I11i
 OoI1II = threading . Timer ( LISP_TEST_MR_INTERVAL , lisp_test_mr ,
 [ lisp_sockets , port ] )
 OoI1II . start ( )
 return
 if 78 - 78: IiII - I1IiiI . ooOoO0o . OoO0O00 + oO0o
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
 if 65 - 65: OOooOOo . I1Ii111 * IiII + OoO0O00 - iIii1I11I1II1
 if 23 - 23: I11i % IiII
def lisp_update_local_rloc ( rloc ) :
 if ( rloc . interface == None ) : return
 if 79 - 79: I1IiiI . i11iIiiIii % I1Ii111 - I11i + Oo0Ooo * II111iiii
 o0o0O00 = lisp_get_interface_address ( rloc . interface )
 if ( o0o0O00 == None ) : return
 if 62 - 62: I1Ii111 * iII111i % OOooOOo / o0oOOo0O0Ooo
 oooOOoooOoOoo = rloc . rloc . print_address_no_iid ( )
 iIiIII11 = o0o0O00 . print_address_no_iid ( )
 if 90 - 90: i11iIiiIii
 if ( oooOOoooOoOoo == iIiIII11 ) : return
 if 6 - 6: I11i . I11i % I11i / iIii1I11I1II1 - i11iIiiIii / i1IIi
 lprint ( "Local interface address changed on {} from {} to {}" . format ( rloc . interface , oooOOoooOoOoo , iIiIII11 ) )
 if 9 - 9: OoooooooOO
 if 71 - 71: Ii1I
 rloc . rloc . copy_address ( o0o0O00 )
 lisp_myrlocs [ 0 ] = o0o0O00
 return
 if 59 - 59: i1IIi * ooOoO0o . iIii1I11I1II1
 if 87 - 87: ooOoO0o % I1ii11iIi11i . I1IiiI
 if 42 - 42: iII111i % i11iIiiIii % o0oOOo0O0Ooo . O0 % iII111i
 if 72 - 72: Oo0Ooo . Oo0Ooo . IiII . Oo0Ooo
 if 80 - 80: I1Ii111 + IiII + O0 - I1Ii111 . iIii1I11I1II1
 if 53 - 53: OoO0O00 / i11iIiiIii * I1Ii111
 if 62 - 62: oO0o / Oo0Ooo / IiII + I11i * ooOoO0o
 if 84 - 84: ooOoO0o + OoOoOO00 * I1ii11iIi11i % OoooooooOO . O0
def lisp_update_encap_port ( mc ) :
 for oOOoo0O00 in mc . rloc_set :
  iiiII1 = lisp_get_nat_info ( oOOoo0O00 . rloc , oOOoo0O00 . rloc_name )
  if ( iiiII1 == None ) : continue
  if ( oOOoo0O00 . translated_port == iiiII1 . port ) : continue
  if 27 - 27: OoO0O00 * OoooooooOO - II111iiii / o0oOOo0O0Ooo
  lprint ( ( "Encap-port changed from {} to {} for RLOC {}, " + "EID-prefix {}" ) . format ( oOOoo0O00 . translated_port , iiiII1 . port ,
  # I11i * Ii1I % OoO0O00 * I1Ii111 % IiII
 red ( oOOoo0O00 . rloc . print_address_no_iid ( ) , False ) ,
 green ( mc . print_eid_tuple ( ) , False ) ) )
  if 35 - 35: iII111i + iIii1I11I1II1 + II111iiii % IiII * Ii1I
  oOOoo0O00 . store_translated_rloc ( oOOoo0O00 . rloc , iiiII1 . port )
  if 63 - 63: I1Ii111
 return
 if 55 - 55: I11i + OoO0O00 - i1IIi - I11i % IiII
 if 64 - 64: Oo0Ooo
 if 33 - 33: I1Ii111
 if 1 - 1: IiII - iIii1I11I1II1 % OoooooooOO
 if 1 - 1: o0oOOo0O0Ooo - i11iIiiIii + I11i
 if 47 - 47: O0 + IiII + ooOoO0o + OOooOOo / OoOoOO00
 if 31 - 31: oO0o * iII111i % OoOoOO00
 if 80 - 80: ooOoO0o % I1ii11iIi11i % I11i . I1Ii111
 if 3 - 3: ooOoO0o - Oo0Ooo
 if 2 - 2: iII111i . iII111i
 if 77 - 77: OOooOOo
 if 74 - 74: O0
def lisp_timeout_map_cache_entry ( mc , delete_list ) :
 if ( mc . map_cache_ttl == None ) :
  lisp_update_encap_port ( mc )
  return ( [ True , delete_list ] )
  if 86 - 86: OoOoOO00
  if 4 - 4: OoooooooOO * OoO0O00
  if 93 - 93: OoO0O00 - I1Ii111 - OoO0O00
  if 1 - 1: o0oOOo0O0Ooo . oO0o * i11iIiiIii * IiII - OoO0O00 - OoooooooOO
  if 29 - 29: iIii1I11I1II1 + OoO0O00 * II111iiii * Ii1I * iII111i . O0
 if ( mc . action == LISP_NO_ACTION ) :
  I1IIIIi1i = lisp_get_timestamp ( )
  if ( mc . last_refresh_time + mc . map_cache_ttl > I1IIIIi1i ) :
   lisp_update_encap_port ( mc )
   return ( [ True , delete_list ] )
   if 6 - 6: I1IiiI - OoOoOO00
   if 63 - 63: OOooOOo - oO0o * I1IiiI
   if 60 - 60: II111iiii - Oo0Ooo
   if 43 - 43: I1IiiI - IiII - OOooOOo
   if 19 - 19: I1Ii111 / I1Ii111 - i1IIi
   if 99 - 99: O0
 i11IiIIi11I = lisp_print_elapsed ( mc . last_refresh_time )
 I11 = mc . print_eid_tuple ( )
 lprint ( "Map-cache entry for EID-prefix {} has {}, had uptime of {}" . format ( green ( I11 , False ) , bold ( "timed out" , False ) , i11IiIIi11I ) )
 if 37 - 37: iIii1I11I1II1 / I1Ii111 + OoO0O00
 if 85 - 85: ooOoO0o / I1IiiI
 if 7 - 7: Oo0Ooo - iIii1I11I1II1 / I1ii11iIi11i * I1IiiI + Ii1I
 if 99 - 99: i11iIiiIii - I1ii11iIi11i
 if 64 - 64: IiII . OoOoOO00 . Oo0Ooo . I1Ii111 / I11i / Ii1I
 delete_list . append ( mc )
 return ( [ True , delete_list ] )
 if 95 - 95: iIii1I11I1II1 . Ii1I % oO0o - I11i % IiII
 if 42 - 42: OoOoOO00 + oO0o * i1IIi + i11iIiiIii
 if 25 - 25: Ii1I - Ii1I - I1ii11iIi11i / i1IIi . OoOoOO00 % Oo0Ooo
 if 76 - 76: I1Ii111 / OoOoOO00
 if 61 - 61: Oo0Ooo . i1IIi
 if 78 - 78: i11iIiiIii
 if 20 - 20: Ii1I
 if 100 - 100: OoooooooOO . I1Ii111
def lisp_timeout_map_cache_walk ( mc , parms ) :
 O0iIIiii1ii1III = parms [ 0 ]
 IioooOo = parms [ 1 ]
 if 14 - 14: oO0o
 if 98 - 98: I1IiiI
 if 8 - 8: OOooOOo
 if 39 - 39: OoOoOO00 % ooOoO0o * IiII - I1IiiI
 if ( mc . group . is_null ( ) ) :
  ii1O0ooooo0OoO0 , O0iIIiii1ii1III = lisp_timeout_map_cache_entry ( mc , O0iIIiii1ii1III )
  if ( O0iIIiii1ii1III == [ ] or mc != O0iIIiii1ii1III [ - 1 ] ) :
   IioooOo = lisp_write_checkpoint_entry ( IioooOo , mc )
   if 53 - 53: I11i % OoO0O00 * IiII % IiII % IiII
  return ( [ ii1O0ooooo0OoO0 , parms ] )
  if 81 - 81: I1ii11iIi11i
  if 59 - 59: I11i + i11iIiiIii
 if ( mc . source_cache == None ) : return ( [ True , parms ] )
 if 48 - 48: Oo0Ooo
 if 9 - 9: IiII - ooOoO0o * Ii1I / I1IiiI . i1IIi % O0
 if 96 - 96: OoooooooOO
 if 83 - 83: i1IIi * OoO0O00
 if 30 - 30: OOooOOo % IiII
 parms = mc . source_cache . walk_cache ( lisp_timeout_map_cache_entry , parms )
 return ( [ True , parms ] )
 if 88 - 88: i1IIi - OoOoOO00
 if 66 - 66: OoooooooOO - OoooooooOO * I11i / II111iiii + oO0o / Ii1I
 if 7 - 7: Ii1I / iIii1I11I1II1
 if 36 - 36: iIii1I11I1II1 % i11iIiiIii
 if 35 - 35: Oo0Ooo + I1IiiI - O0 - I1Ii111
 if 64 - 64: i1IIi * OoOoOO00 / II111iiii * oO0o
 if 35 - 35: i1IIi - Ii1I - Ii1I . O0 % iII111i * iII111i
def lisp_timeout_map_cache ( lisp_map_cache ) :
 III11I1 = [ [ ] , [ ] ]
 III11I1 = lisp_map_cache . walk_cache ( lisp_timeout_map_cache_walk , III11I1 )
 if 15 - 15: OoooooooOO . Ii1I * I1Ii111 . ooOoO0o % OoO0O00 * Oo0Ooo
 if 10 - 10: iII111i + i11iIiiIii . OOooOOo % iII111i - i1IIi
 if 10 - 10: iIii1I11I1II1 * i11iIiiIii - O0
 if 45 - 45: oO0o % OOooOOo - IiII + o0oOOo0O0Ooo + i11iIiiIii
 if 79 - 79: IiII % I1Ii111 . I1IiiI + O0 * oO0o * ooOoO0o
 O0iIIiii1ii1III = III11I1 [ 0 ]
 for Iii1 in O0iIIiii1ii1III : Iii1 . delete_cache ( )
 if 38 - 38: IiII
 if 78 - 78: Oo0Ooo * I1ii11iIi11i % OOooOOo / Oo0Ooo + I1ii11iIi11i * IiII
 if 2 - 2: Oo0Ooo - OoOoOO00
 if 22 - 22: OoO0O00 - oO0o - O0
 IioooOo = III11I1 [ 1 ]
 lisp_checkpoint ( IioooOo )
 return
 if 49 - 49: iIii1I11I1II1 + I1Ii111 / i11iIiiIii
 if 62 - 62: ooOoO0o . I1IiiI * i11iIiiIii
 if 2 - 2: i11iIiiIii
 if 86 - 86: I1Ii111 + o0oOOo0O0Ooo
 if 17 - 17: iIii1I11I1II1
 if 32 - 32: IiII - OoOoOO00
 if 88 - 88: OOooOOo - II111iiii + i1IIi * Oo0Ooo
 if 48 - 48: I1Ii111 + IiII % iII111i * iII111i + I1Ii111
 if 83 - 83: OoO0O00 . I11i * I1ii11iIi11i - II111iiii
 if 41 - 41: OoooooooOO . OoOoOO00 * iIii1I11I1II1
 if 18 - 18: IiII / I1Ii111 % i1IIi * i11iIiiIii
 if 16 - 16: Oo0Ooo
 if 24 - 24: o0oOOo0O0Ooo . OoOoOO00
 if 50 - 50: I1ii11iIi11i / iIii1I11I1II1 - Oo0Ooo - i11iIiiIii % o0oOOo0O0Ooo - ooOoO0o
 if 92 - 92: OoooooooOO - I1ii11iIi11i . I11i / O0 % iII111i
 if 96 - 96: I1IiiI . oO0o % O0
def lisp_store_nat_info ( hostname , rloc , port ) :
 I1iiIiiii1111 = rloc . print_address_no_iid ( )
 Iii11i = "{} NAT state for {}, RLOC {}, port {}" . format ( "{}" ,
 blue ( hostname , False ) , red ( I1iiIiiii1111 , False ) , port )
 if 55 - 55: i1IIi + IiII % OoooooooOO . OoOoOO00 * ooOoO0o
 ooO0OoOo0OOO = lisp_nat_info ( I1iiIiiii1111 , hostname , port )
 if 74 - 74: i1IIi * i11iIiiIii - o0oOOo0O0Ooo
 if ( lisp_nat_state_info . has_key ( hostname ) == False ) :
  lisp_nat_state_info [ hostname ] = [ ooO0OoOo0OOO ]
  lprint ( Iii11i . format ( "Store initial" ) )
  return ( True )
  if 62 - 62: iIii1I11I1II1 / oO0o - OoO0O00 * I1Ii111
  if 1 - 1: I1ii11iIi11i . OoOoOO00 % o0oOOo0O0Ooo * i11iIiiIii - OOooOOo % oO0o
  if 35 - 35: I1ii11iIi11i / II111iiii * OoO0O00 - i11iIiiIii / iII111i / o0oOOo0O0Ooo
  if 39 - 39: II111iiii * iII111i
  if 7 - 7: OOooOOo + OoOoOO00 . II111iiii * OoO0O00 . I1IiiI * o0oOOo0O0Ooo
  if 62 - 62: I1ii11iIi11i / iIii1I11I1II1 + oO0o . II111iiii
 iiiII1 = lisp_nat_state_info [ hostname ] [ 0 ]
 if ( iiiII1 . address == I1iiIiiii1111 and iiiII1 . port == port ) :
  iiiII1 . uptime = lisp_get_timestamp ( )
  lprint ( Iii11i . format ( "Refresh existing" ) )
  return ( False )
  if 65 - 65: Oo0Ooo % i1IIi * o0oOOo0O0Ooo * IiII
  if 24 - 24: i11iIiiIii / iIii1I11I1II1 / iII111i
  if 31 - 31: OOooOOo . iIii1I11I1II1 - oO0o
  if 36 - 36: O0
  if 30 - 30: i11iIiiIii * Oo0Ooo . IiII
  if 65 - 65: oO0o * IiII * OOooOOo / OoooooooOO % I11i / I1Ii111
  if 21 - 21: i1IIi * iII111i + OoO0O00
 I1iII = None
 for iiiII1 in lisp_nat_state_info [ hostname ] :
  if ( iiiII1 . address == I1iiIiiii1111 and iiiII1 . port == port ) :
   I1iII = iiiII1
   break
   if 81 - 81: OOooOOo - OoooooooOO * iII111i / OOooOOo
   if 98 - 98: I11i . OOooOOo - OoO0O00 % O0 * O0
   if 91 - 91: I1IiiI % ooOoO0o * iII111i % OoOoOO00 . OoOoOO00 + OoOoOO00
 if ( I1iII == None ) :
  lprint ( Iii11i . format ( "Store new" ) )
 else :
  lisp_nat_state_info [ hostname ] . remove ( I1iII )
  lprint ( Iii11i . format ( "Use previous" ) )
  if 95 - 95: o0oOOo0O0Ooo % i1IIi
  if 14 - 14: iIii1I11I1II1 + iIii1I11I1II1
 OOOi11IIIIiIii = lisp_nat_state_info [ hostname ]
 lisp_nat_state_info [ hostname ] = [ ooO0OoOo0OOO ] + OOOi11IIIIiIii
 return ( True )
 if 13 - 13: OOooOOo / O0
 if 19 - 19: iIii1I11I1II1 + IiII * I11i * II111iiii + o0oOOo0O0Ooo + i11iIiiIii
 if 69 - 69: iIii1I11I1II1 . II111iiii
 if 36 - 36: I1IiiI * i1IIi + OoOoOO00
 if 63 - 63: OoOoOO00 - iII111i
 if 83 - 83: i1IIi / iII111i % ooOoO0o % i11iIiiIii + I1ii11iIi11i
 if 82 - 82: iIii1I11I1II1 / OOooOOo
 if 7 - 7: OoooooooOO
def lisp_get_nat_info ( rloc , hostname ) :
 if ( lisp_nat_state_info . has_key ( hostname ) == False ) : return ( None )
 if 71 - 71: OOooOOo * Oo0Ooo . Oo0Ooo % iIii1I11I1II1
 I1iiIiiii1111 = rloc . print_address_no_iid ( )
 for iiiII1 in lisp_nat_state_info [ hostname ] :
  if ( iiiII1 . address == I1iiIiiii1111 ) : return ( iiiII1 )
  if 56 - 56: IiII * iIii1I11I1II1 - iIii1I11I1II1 . O0
 return ( None )
 if 56 - 56: I1Ii111 / iIii1I11I1II1 % IiII * iIii1I11I1II1 . I1ii11iIi11i . OOooOOo
 if 1 - 1: Ii1I . Ii1I % II111iiii + I11i + OoOoOO00
 if 52 - 52: OoooooooOO - OoO0O00
 if 24 - 24: iII111i / Oo0Ooo - I1ii11iIi11i + o0oOOo0O0Ooo
 if 44 - 44: OoOoOO00 + I1IiiI . I1ii11iIi11i / i1IIi + II111iiii . Oo0Ooo
 if 39 - 39: o0oOOo0O0Ooo
 if 64 - 64: oO0o - i11iIiiIii
 if 62 - 62: OoooooooOO - OoooooooOO / OoO0O00 - II111iiii . iIii1I11I1II1
 if 2 - 2: O0 + o0oOOo0O0Ooo % OOooOOo . ooOoO0o % i1IIi
 if 21 - 21: OoOoOO00 / OoooooooOO + I1Ii111 - IiII
 if 62 - 62: Oo0Ooo % iII111i + OoooooooOO - I1ii11iIi11i % iII111i % iIii1I11I1II1
 if 54 - 54: IiII + OoOoOO00 / II111iiii % i11iIiiIii . I1Ii111
 if 69 - 69: i1IIi + ooOoO0o + Ii1I
 if 88 - 88: OoOoOO00 + iII111i % O0 + OOooOOo / OoooooooOO / OOooOOo
 if 95 - 95: ooOoO0o . Oo0Ooo % IiII + iII111i
 if 16 - 16: I11i * OoO0O00 % o0oOOo0O0Ooo - O0 % II111iiii - I1IiiI
 if 72 - 72: OoooooooOO * OoOoOO00 . OOooOOo + Ii1I . OOooOOo / II111iiii
 if 8 - 8: i1IIi
 if 1 - 1: OoOoOO00 . OoO0O00 . OoO0O00 * O0
 if 97 - 97: OoooooooOO % ooOoO0o . I1Ii111 / iII111i
def lisp_build_info_requests ( lisp_sockets , dest , port ) :
 if ( lisp_nat_traversal == False ) : return
 if 59 - 59: II111iiii + O0 . I1ii11iIi11i . Oo0Ooo * OoO0O00
 if 35 - 35: oO0o / I1Ii111 * OOooOOo + OoooooooOO . IiII
 if 1 - 1: I1IiiI + I1Ii111 / OOooOOo . Ii1I . oO0o / I1ii11iIi11i
 if 54 - 54: OOooOOo
 if 86 - 86: oO0o * Oo0Ooo / OOooOOo
 if 18 - 18: II111iiii - I1Ii111
 Ii1iII11 = [ ]
 OOoo0000 = [ ]
 if ( dest == None ) :
  for IIiIII1IIi in lisp_map_resolvers_list . values ( ) :
   OOoo0000 . append ( IIiIII1IIi . map_resolver )
   if 20 - 20: OoOoOO00 * iIii1I11I1II1 % O0 - i1IIi
  Ii1iII11 = OOoo0000
  if ( Ii1iII11 == [ ] ) :
   for I1iII1 in lisp_map_servers_list . values ( ) :
    Ii1iII11 . append ( I1iII1 . map_server )
    if 51 - 51: I1ii11iIi11i * Ii1I - oO0o / O0 * OoooooooOO
    if 12 - 12: i1IIi / iIii1I11I1II1 / O0 * OoO0O00
  if ( Ii1iII11 == [ ] ) : return
 else :
  Ii1iII11 . append ( dest )
  if 15 - 15: i11iIiiIii / IiII + Ii1I % OOooOOo % I1ii11iIi11i * oO0o
  if 24 - 24: OOooOOo / OOooOOo + I11i / iII111i . oO0o - iII111i
  if 59 - 59: I1ii11iIi11i % II111iiii - i11iIiiIii - I1Ii111
  if 34 - 34: II111iiii + iII111i / IiII
  if 47 - 47: OoO0O00
 OooOo = { }
 for I11i111 in lisp_db_list :
  for IIiO0Ooo in I11i111 . rloc_set :
   lisp_update_local_rloc ( IIiO0Ooo )
   if ( IIiO0Ooo . rloc . is_null ( ) ) : continue
   if ( IIiO0Ooo . interface == None ) : continue
   if 40 - 40: o0oOOo0O0Ooo / iII111i . o0oOOo0O0Ooo
   o0o0O00 = IIiO0Ooo . rloc . print_address_no_iid ( )
   if ( o0o0O00 in OooOo ) : continue
   OooOo [ o0o0O00 ] = IIiO0Ooo . interface
   if 63 - 63: o0oOOo0O0Ooo * iIii1I11I1II1 * II111iiii . OoO0O00 - oO0o / OoOoOO00
   if 78 - 78: i11iIiiIii / OoO0O00 / i1IIi . i11iIiiIii
 if ( OooOo == { } ) :
  lprint ( 'Suppress Info-Request, no "interface = <device>" RLOC ' + "found in any database-mappings" )
  if 100 - 100: II111iiii . IiII . I11i
  return
  if 60 - 60: OoOoOO00 % OOooOOo * i1IIi
  if 3 - 3: OoooooooOO
  if 75 - 75: OoooooooOO * I1Ii111 * o0oOOo0O0Ooo + I1ii11iIi11i . iIii1I11I1II1 / O0
  if 23 - 23: oO0o - O0 * IiII + i11iIiiIii * Ii1I
  if 8 - 8: ooOoO0o / II111iiii . I1ii11iIi11i * ooOoO0o % oO0o
  if 36 - 36: I1ii11iIi11i % OOooOOo - ooOoO0o - I11i + I1IiiI
 for o0o0O00 in OooOo :
  I111IIiIII = OooOo [ o0o0O00 ]
  oOO0oo = red ( o0o0O00 , False )
  lprint ( "Build Info-Request for private address {} ({})" . format ( oOO0oo ,
 I111IIiIII ) )
  O0OoO0o = I111IIiIII if len ( OooOo ) > 1 else None
  for dest in Ii1iII11 :
   lisp_send_info_request ( lisp_sockets , dest , port , O0OoO0o )
   if 37 - 37: I1ii11iIi11i * IiII
   if 65 - 65: OOooOOo / O0 . I1ii11iIi11i % i1IIi % Oo0Ooo
   if 36 - 36: i11iIiiIii - OOooOOo + iII111i + iII111i * I11i * oO0o
   if 14 - 14: O0 - iII111i * I1Ii111 - I1IiiI + IiII
   if 46 - 46: OoooooooOO * OoO0O00 . I1Ii111
   if 95 - 95: ooOoO0o . I1ii11iIi11i . ooOoO0o / I1IiiI * OoOoOO00 . O0
 if ( OOoo0000 != [ ] ) :
  for IIiIII1IIi in lisp_map_resolvers_list . values ( ) :
   IIiIII1IIi . resolve_dns_name ( )
   if 78 - 78: oO0o
   if 33 - 33: oO0o + i1IIi
 return
 if 32 - 32: iIii1I11I1II1
 if 71 - 71: Ii1I * I1IiiI
 if 62 - 62: II111iiii / I1IiiI . I1ii11iIi11i
 if 49 - 49: IiII / OoOoOO00 / O0 * i11iIiiIii
 if 47 - 47: i11iIiiIii + iII111i + i11iIiiIii
 if 66 - 66: o0oOOo0O0Ooo . I1IiiI + OoooooooOO . iII111i / OoooooooOO - IiII
 if 47 - 47: o0oOOo0O0Ooo / II111iiii * i11iIiiIii * OoO0O00 . iIii1I11I1II1
 if 34 - 34: I11i / o0oOOo0O0Ooo * OOooOOo * OOooOOo
def lisp_valid_address_format ( kw , value ) :
 if ( kw != "address" ) : return ( True )
 if 89 - 89: I1ii11iIi11i . OoooooooOO
 if 61 - 61: i1IIi + i11iIiiIii
 if 59 - 59: i11iIiiIii * OOooOOo + i1IIi * iIii1I11I1II1 + I11i
 if 97 - 97: OoO0O00 - I11i . OoooooooOO
 if 58 - 58: I1ii11iIi11i / II111iiii / i11iIiiIii
 if ( value [ 0 ] == "'" and value [ - 1 ] == "'" ) : return ( True )
 if 27 - 27: iIii1I11I1II1 - O0 + OoOoOO00
 if 28 - 28: oO0o . IiII * iII111i % Oo0Ooo - OoO0O00 / I11i
 if 67 - 67: i11iIiiIii + i11iIiiIii / ooOoO0o - o0oOOo0O0Ooo
 if 94 - 94: O0 + OoO0O00 / I1IiiI * II111iiii * i11iIiiIii
 if ( value . find ( "." ) != - 1 ) :
  o0o0O00 = value . split ( "." )
  if ( len ( o0o0O00 ) != 4 ) : return ( False )
  if 55 - 55: OoooooooOO * O0 + i1IIi % I1IiiI
  for Iii1i1Ii in o0o0O00 :
   if ( Iii1i1Ii . isdigit ( ) == False ) : return ( False )
   if ( int ( Iii1i1Ii ) > 255 ) : return ( False )
   if 79 - 79: I1IiiI * O0 . Ii1I
  return ( True )
  if 24 - 24: ooOoO0o * OoOoOO00 * iIii1I11I1II1 * iII111i + I1IiiI - II111iiii
  if 31 - 31: oO0o / I1ii11iIi11i
  if 96 - 96: i1IIi + i1IIi * I1Ii111 . II111iiii % OoooooooOO
  if 58 - 58: IiII
  if 64 - 64: iIii1I11I1II1 / OoOoOO00
 if ( value . find ( "-" ) != - 1 ) :
  o0o0O00 = value . split ( "-" )
  for Ii11 in [ "N" , "S" , "W" , "E" ] :
   if ( Ii11 in o0o0O00 ) :
    if ( len ( o0o0O00 ) < 8 ) : return ( False )
    return ( True )
    if 14 - 14: Ii1I / OoooooooOO . i1IIi % IiII % i11iIiiIii
    if 23 - 23: iIii1I11I1II1 - o0oOOo0O0Ooo - Ii1I % OOooOOo
    if 100 - 100: oO0o . OoO0O00 . i11iIiiIii % II111iiii * IiII
    if 81 - 81: OOooOOo - OOooOOo + OoOoOO00
    if 19 - 19: o0oOOo0O0Ooo
    if 20 - 20: I1Ii111 + iIii1I11I1II1 % I1IiiI + ooOoO0o
    if 86 - 86: o0oOOo0O0Ooo * i11iIiiIii - I11i
 if ( value . find ( "-" ) != - 1 ) :
  o0o0O00 = value . split ( "-" )
  if ( len ( o0o0O00 ) != 3 ) : return ( False )
  if 71 - 71: OoO0O00 - I11i
  for o00O in o0o0O00 :
   try : int ( o00O , 16 )
   except : return ( False )
   if 44 - 44: O0 - IiII . OoOoOO00 . I11i / Ii1I % oO0o
  return ( True )
  if 50 - 50: i11iIiiIii
  if 93 - 93: i1IIi / Ii1I * II111iiii - Oo0Ooo . OoOoOO00 - OOooOOo
  if 25 - 25: I11i / ooOoO0o % ooOoO0o - OOooOOo
  if 59 - 59: I1IiiI + o0oOOo0O0Ooo . iIii1I11I1II1 - O0 - i11iIiiIii
  if 4 - 4: I1IiiI
 if ( value . find ( ":" ) != - 1 ) :
  o0o0O00 = value . split ( ":" )
  if ( len ( o0o0O00 ) < 2 ) : return ( False )
  if 36 - 36: Ii1I
  oooO0OO = False
  I1I11Iiii111 = 0
  for o00O in o0o0O00 :
   I1I11Iiii111 += 1
   if ( o00O == "" ) :
    if ( oooO0OO ) :
     if ( len ( o0o0O00 ) == I1I11Iiii111 ) : break
     if ( I1I11Iiii111 > 2 ) : return ( False )
     if 27 - 27: i11iIiiIii * iII111i
    oooO0OO = True
    continue
    if 48 - 48: Oo0Ooo . i1IIi
   try : int ( o00O , 16 )
   except : return ( False )
   if 49 - 49: OOooOOo / OoO0O00 % I1Ii111
  return ( True )
  if 80 - 80: iII111i
  if 17 - 17: oO0o % o0oOOo0O0Ooo . o0oOOo0O0Ooo + ooOoO0o + I1Ii111 - OoO0O00
  if 37 - 37: i1IIi * OOooOOo / OoooooooOO + II111iiii
  if 73 - 73: I1Ii111 - II111iiii / Ii1I + Ii1I
  if 41 - 41: II111iiii / II111iiii / iII111i * I1IiiI * I1Ii111 * oO0o
 if ( value [ 0 ] == "+" ) :
  o0o0O00 = value [ 1 : : ]
  for II1I1i1II in o0o0O00 :
   if ( II1I1i1II . isdigit ( ) == False ) : return ( False )
   if 3 - 3: OOooOOo / OoOoOO00 % iIii1I11I1II1
  return ( True )
  if 47 - 47: ooOoO0o . i11iIiiIii / OoO0O00
 return ( False )
 if 48 - 48: O0
 if 89 - 89: i11iIiiIii % OoO0O00 . OoOoOO00 + Oo0Ooo + OoOoOO00
 if 53 - 53: Ii1I / OoOoOO00 % iII111i * OoooooooOO + Oo0Ooo
 if 70 - 70: OoO0O00 % OoO0O00 * OoooooooOO
 if 96 - 96: ooOoO0o * Ii1I + I11i + II111iiii * I1IiiI / iII111i
 if 40 - 40: OoooooooOO - I11i % OOooOOo - I1IiiI . I1IiiI + Ii1I
 if 97 - 97: OOooOOo . OoooooooOO . OOooOOo . i11iIiiIii
 if 71 - 71: oO0o + I1ii11iIi11i * I1ii11iIi11i
 if 79 - 79: oO0o
 if 47 - 47: OoooooooOO - i1IIi * OOooOOo
 if 11 - 11: I11i / OOooOOo . o0oOOo0O0Ooo - O0 * OoooooooOO % iII111i
 if 7 - 7: OoOoOO00 . IiII + OoooooooOO - I1Ii111 / oO0o
def lisp_process_api ( process , lisp_socket , data_structure ) :
 IiI1I1 , III11I1 = data_structure . split ( "%" )
 if 48 - 48: i11iIiiIii * o0oOOo0O0Ooo
 lprint ( "Process API request '{}', parameters: '{}'" . format ( IiI1I1 ,
 III11I1 ) )
 if 8 - 8: iII111i
 i11iII1IiI = [ ]
 if ( IiI1I1 == "map-cache" ) :
  if ( III11I1 == "" ) :
   i11iII1IiI = lisp_map_cache . walk_cache ( lisp_process_api_map_cache , i11iII1IiI )
  else :
   i11iII1IiI = lisp_process_api_map_cache_entry ( json . loads ( III11I1 ) )
   if 10 - 10: OoOoOO00 % I11i
   if 49 - 49: oO0o % ooOoO0o + II111iiii
 if ( IiI1I1 == "site-cache" ) :
  if ( III11I1 == "" ) :
   i11iII1IiI = lisp_sites_by_eid . walk_cache ( lisp_process_api_site_cache ,
 i11iII1IiI )
  else :
   i11iII1IiI = lisp_process_api_site_cache_entry ( json . loads ( III11I1 ) )
   if 21 - 21: i1IIi + OoO0O00 . I1IiiI - Oo0Ooo
   if 99 - 99: OoOoOO00
 if ( IiI1I1 == "map-server" ) :
  III11I1 = { } if ( III11I1 == "" ) else json . loads ( III11I1 )
  i11iII1IiI = lisp_process_api_ms_or_mr ( True , III11I1 )
  if 46 - 46: I1ii11iIi11i / II111iiii / OoooooooOO / Ii1I
 if ( IiI1I1 == "map-resolver" ) :
  III11I1 = { } if ( III11I1 == "" ) else json . loads ( III11I1 )
  i11iII1IiI = lisp_process_api_ms_or_mr ( False , III11I1 )
  if 37 - 37: I1ii11iIi11i - Ii1I / oO0o . I1IiiI % I1Ii111
 if ( IiI1I1 == "database-mapping" ) :
  i11iII1IiI = lisp_process_api_database_mapping ( )
  if 8 - 8: oO0o
  if 46 - 46: I1Ii111 + IiII + II111iiii . o0oOOo0O0Ooo + i11iIiiIii
  if 97 - 97: o0oOOo0O0Ooo % OoOoOO00 * O0 / iIii1I11I1II1 * OoO0O00 / i11iIiiIii
  if 1 - 1: OoooooooOO . Ii1I
  if 68 - 68: Ii1I
 i11iII1IiI = json . dumps ( i11iII1IiI )
 IIi1IIII = lisp_api_ipc ( process , i11iII1IiI )
 lisp_ipc ( IIi1IIII , lisp_socket , "lisp-core" )
 return
 if 98 - 98: iII111i
 if 33 - 33: OoO0O00 - ooOoO0o % O0 % iIii1I11I1II1 * iII111i - iII111i
 if 27 - 27: i11iIiiIii + I1ii11iIi11i + i1IIi
 if 67 - 67: o0oOOo0O0Ooo
 if 58 - 58: IiII % o0oOOo0O0Ooo + i1IIi
 if 33 - 33: II111iiii
 if 61 - 61: I1Ii111
def lisp_process_api_map_cache ( mc , data ) :
 if 56 - 56: I1ii11iIi11i - OoooooooOO
 if 52 - 52: Oo0Ooo - I11i - IiII - OoOoOO00
 if 21 - 21: oO0o % o0oOOo0O0Ooo + I1Ii111 . OOooOOo / OOooOOo
 if 41 - 41: Oo0Ooo . ooOoO0o * oO0o
 if ( mc . group . is_null ( ) ) : return ( lisp_gather_map_cache_data ( mc , data ) )
 if 31 - 31: Oo0Ooo * IiII / IiII
 if ( mc . source_cache == None ) : return ( [ True , data ] )
 if 3 - 3: I1Ii111
 if 65 - 65: iIii1I11I1II1 % Oo0Ooo % I11i / OoooooooOO
 if 82 - 82: o0oOOo0O0Ooo
 if 33 - 33: OoOoOO00 / i11iIiiIii - I1IiiI - OoooooooOO + i1IIi * I1Ii111
 if 92 - 92: iII111i + OoO0O00
 data = mc . source_cache . walk_cache ( lisp_gather_map_cache_data , data )
 return ( [ True , data ] )
 if 70 - 70: iIii1I11I1II1
 if 100 - 100: OOooOOo . oO0o % ooOoO0o * ooOoO0o . I1Ii111 - oO0o
 if 33 - 33: Oo0Ooo . i1IIi - OoooooooOO
 if 14 - 14: I1Ii111 + Oo0Ooo
 if 35 - 35: i11iIiiIii * Ii1I
 if 100 - 100: O0 . iII111i / iIii1I11I1II1
 if 47 - 47: ooOoO0o + OoOoOO00
def lisp_gather_map_cache_data ( mc , data ) :
 iIIiI11iI1Ii1 = { }
 iIIiI11iI1Ii1 [ "instance-id" ] = str ( mc . eid . instance_id )
 iIIiI11iI1Ii1 [ "eid-prefix" ] = mc . eid . print_prefix_no_iid ( )
 if ( mc . group . is_null ( ) == False ) :
  iIIiI11iI1Ii1 [ "group-prefix" ] = mc . group . print_prefix_no_iid ( )
  if 67 - 67: IiII - I1ii11iIi11i * i1IIi - ooOoO0o
 iIIiI11iI1Ii1 [ "uptime" ] = lisp_print_elapsed ( mc . uptime )
 iIIiI11iI1Ii1 [ "expires" ] = lisp_print_elapsed ( mc . uptime )
 iIIiI11iI1Ii1 [ "action" ] = lisp_map_reply_action_string [ mc . action ]
 iIIiI11iI1Ii1 [ "ttl" ] = "--" if mc . map_cache_ttl == None else str ( mc . map_cache_ttl / 60 )
 if 91 - 91: I11i
 if 54 - 54: I1ii11iIi11i / i1IIi
 if 14 - 14: iIii1I11I1II1 * I11i . I11i * ooOoO0o * iII111i
 if 60 - 60: iIii1I11I1II1 + i1IIi + oO0o - iIii1I11I1II1 . i11iIiiIii * OoooooooOO
 if 23 - 23: iII111i - IiII % i11iIiiIii
 iii1Ii1i1i1I = [ ]
 for oOOoo0O00 in mc . rloc_set :
  O00oo00o000o = { }
  if ( oOOoo0O00 . rloc_exists ( ) ) :
   O00oo00o000o [ "address" ] = oOOoo0O00 . rloc . print_address_no_iid ( )
   if 81 - 81: OoooooooOO % OoOoOO00 / IiII / OoooooooOO + i1IIi - O0
   if 60 - 60: OOooOOo - I1Ii111 * Oo0Ooo
  if ( oOOoo0O00 . translated_port != 0 ) :
   O00oo00o000o [ "encap-port" ] = str ( oOOoo0O00 . translated_port )
   if 9 - 9: OoooooooOO * OOooOOo % OoO0O00 - ooOoO0o + Ii1I
  O00oo00o000o [ "state" ] = oOOoo0O00 . print_state ( )
  if ( oOOoo0O00 . geo ) : O00oo00o000o [ "geo" ] = oOOoo0O00 . geo . print_geo ( )
  if ( oOOoo0O00 . elp ) : O00oo00o000o [ "elp" ] = oOOoo0O00 . elp . print_elp ( False )
  if ( oOOoo0O00 . rle ) : O00oo00o000o [ "rle" ] = oOOoo0O00 . rle . print_rle ( False )
  if ( oOOoo0O00 . json ) : O00oo00o000o [ "json" ] = oOOoo0O00 . json . print_json ( False )
  if ( oOOoo0O00 . rloc_name ) : O00oo00o000o [ "rloc-name" ] = oOOoo0O00 . rloc_name
  oO000O0oooOo = oOOoo0O00 . stats . get_stats ( False , False )
  if ( oO000O0oooOo ) : O00oo00o000o [ "stats" ] = oO000O0oooOo
  O00oo00o000o [ "uptime" ] = lisp_print_elapsed ( oOOoo0O00 . uptime )
  O00oo00o000o [ "upriority" ] = str ( oOOoo0O00 . priority )
  O00oo00o000o [ "uweight" ] = str ( oOOoo0O00 . weight )
  O00oo00o000o [ "mpriority" ] = str ( oOOoo0O00 . mpriority )
  O00oo00o000o [ "mweight" ] = str ( oOOoo0O00 . mweight )
  Ii1i = oOOoo0O00 . last_rloc_probe_reply
  if ( Ii1i ) :
   O00oo00o000o [ "last-rloc-probe-reply" ] = lisp_print_elapsed ( Ii1i )
   O00oo00o000o [ "rloc-probe-rtt" ] = str ( oOOoo0O00 . rloc_probe_rtt )
   if 82 - 82: I1ii11iIi11i * iIii1I11I1II1 * Oo0Ooo / i1IIi / i11iIiiIii
  O00oo00o000o [ "rloc-hop-count" ] = oOOoo0O00 . rloc_probe_hops
  O00oo00o000o [ "recent-rloc-hop-counts" ] = oOOoo0O00 . recent_rloc_probe_hops
  if 9 - 9: I1ii11iIi11i / i1IIi + OoooooooOO * OOooOOo . Oo0Ooo
  oOOO = [ ]
  for OOOOo000o in oOOoo0O00 . recent_rloc_probe_rtts : oOOO . append ( str ( OOOOo000o ) )
  O00oo00o000o [ "recent-rloc-probe-rtts" ] = oOOO
  if 54 - 54: I1IiiI + IiII
  iii1Ii1i1i1I . append ( O00oo00o000o )
  if 7 - 7: Ii1I % I1Ii111 + I1ii11iIi11i * IiII . OoO0O00 / I11i
 iIIiI11iI1Ii1 [ "rloc-set" ] = iii1Ii1i1i1I
 if 39 - 39: Oo0Ooo + OOooOOo . I1IiiI + OoO0O00 . OoooooooOO
 data . append ( iIIiI11iI1Ii1 )
 return ( [ True , data ] )
 if 31 - 31: OoO0O00
 if 55 - 55: OoOoOO00 + I1Ii111 * o0oOOo0O0Ooo - I1ii11iIi11i + OoOoOO00
 if 6 - 6: II111iiii % iIii1I11I1II1 * I1Ii111
 if 2 - 2: IiII - I1Ii111 . iIii1I11I1II1 - Ii1I * I11i
 if 58 - 58: i1IIi % iIii1I11I1II1 % i11iIiiIii - o0oOOo0O0Ooo + ooOoO0o
 if 23 - 23: Oo0Ooo % Oo0Ooo / IiII
 if 63 - 63: I11i % Oo0Ooo * I1Ii111 - Oo0Ooo % i11iIiiIii . II111iiii
def lisp_process_api_map_cache_entry ( parms ) :
 o0OOoOO = parms [ "instance-id" ]
 o0OOoOO = 0 if ( o0OOoOO == "" ) else int ( o0OOoOO )
 if 44 - 44: I11i . I1Ii111 . I1ii11iIi11i . oO0o
 if 1 - 1: I11i % II111iiii / OoO0O00 + OoO0O00
 if 46 - 46: Oo0Ooo * Ii1I / IiII % O0 * iII111i
 if 74 - 74: OoooooooOO + Ii1I
 o00oo00oo = lisp_address ( LISP_AFI_NONE , "" , 0 , o0OOoOO )
 o00oo00oo . store_prefix ( parms [ "eid-prefix" ] )
 oooooO0oO0o = o00oo00oo
 O0Oo00o0o = o00oo00oo
 if 100 - 100: I1IiiI
 if 59 - 59: I1IiiI - OoOoOO00 * ooOoO0o / O0
 if 54 - 54: Oo0Ooo % iIii1I11I1II1 * Oo0Ooo
 if 80 - 80: I1ii11iIi11i - I1ii11iIi11i
 if 26 - 26: I1ii11iIi11i - I1IiiI * I1Ii111 % iIii1I11I1II1
 ii1I1 = lisp_address ( LISP_AFI_NONE , "" , 0 , o0OOoOO )
 if ( parms . has_key ( "group-prefix" ) ) :
  ii1I1 . store_prefix ( parms [ "group-prefix" ] )
  oooooO0oO0o = ii1I1
  if 77 - 77: o0oOOo0O0Ooo + I1Ii111 . OOooOOo . i1IIi . I1IiiI
  if 100 - 100: ooOoO0o . i11iIiiIii + Ii1I - OOooOOo - i11iIiiIii - OoooooooOO
 i11iII1IiI = [ ]
 Iii1 = lisp_map_cache_lookup ( O0Oo00o0o , oooooO0oO0o )
 if ( Iii1 ) : ii1O0ooooo0OoO0 , i11iII1IiI = lisp_process_api_map_cache ( Iii1 , i11iII1IiI )
 return ( i11iII1IiI )
 if 42 - 42: OoOoOO00 . I1IiiI / OoOoOO00 / I1ii11iIi11i . OoO0O00
 if 67 - 67: Ii1I - O0 . OoooooooOO . I1Ii111 . o0oOOo0O0Ooo
 if 73 - 73: I11i - oO0o . I1Ii111 + oO0o
 if 48 - 48: IiII . IiII * o0oOOo0O0Ooo * II111iiii % ooOoO0o
 if 40 - 40: I1ii11iIi11i
 if 76 - 76: Oo0Ooo - I11i
 if 82 - 82: OoO0O00 % oO0o . I11i / O0 - I1Ii111
def lisp_process_api_site_cache ( se , data ) :
 if 39 - 39: I1IiiI
 if 8 - 8: IiII * i1IIi * i1IIi * O0
 if 69 - 69: Oo0Ooo
 if 48 - 48: iII111i
 if ( se . group . is_null ( ) ) : return ( lisp_gather_site_cache_data ( se , data ) )
 if 11 - 11: i11iIiiIii * OoOoOO00 . OoO0O00
 if ( se . source_cache == None ) : return ( [ True , data ] )
 if 47 - 47: Oo0Ooo % I1Ii111 + ooOoO0o
 if 89 - 89: iII111i
 if 29 - 29: I1ii11iIi11i . ooOoO0o * II111iiii / iII111i . OoooooooOO - OoOoOO00
 if 99 - 99: IiII % O0 - I1Ii111 * OoO0O00
 if 77 - 77: OoooooooOO - I11i / I1IiiI % OoOoOO00 - OOooOOo
 data = se . source_cache . walk_cache ( lisp_gather_site_cache_data , data )
 return ( [ True , data ] )
 if 37 - 37: ooOoO0o
 if 22 - 22: I1ii11iIi11i + II111iiii / OoooooooOO % o0oOOo0O0Ooo * OoOoOO00 . Oo0Ooo
 if 26 - 26: OoO0O00 % oO0o * Ii1I % OoooooooOO - oO0o
 if 46 - 46: I1IiiI + OoO0O00 - O0 * O0
 if 75 - 75: OOooOOo + iIii1I11I1II1 * OOooOOo
 if 82 - 82: iII111i - I1Ii111 - OoOoOO00
 if 96 - 96: Oo0Ooo . Oo0Ooo % o0oOOo0O0Ooo - I1IiiI * iIii1I11I1II1
def lisp_process_api_ms_or_mr ( ms_or_mr , data ) :
 oOoO0Oo0 = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
 oo0Oo0OOOO = data [ "dns-name" ] if data . has_key ( "dns-name" ) else None
 if ( data . has_key ( "address" ) ) :
  oOoO0Oo0 . store_address ( data [ "address" ] )
  if 29 - 29: i1IIi / Ii1I / oO0o * iII111i
  if 44 - 44: O0
 oOO = { }
 if ( ms_or_mr ) :
  for I1iII1 in lisp_map_servers_list . values ( ) :
   if ( oo0Oo0OOOO ) :
    if ( oo0Oo0OOOO != I1iII1 . dns_name ) : continue
   else :
    if ( oOoO0Oo0 . is_exact_match ( I1iII1 . map_server ) == False ) : continue
    if 95 - 95: OOooOOo + OOooOOo - OoOoOO00
    if 83 - 83: II111iiii * ooOoO0o - O0 - i11iIiiIii
   oOO [ "dns-name" ] = I1iII1 . dns_name
   oOO [ "address" ] = I1iII1 . map_server . print_address_no_iid ( )
   oOO [ "ms-name" ] = "" if I1iII1 . ms_name == None else I1iII1 . ms_name
   return ( [ oOO ] )
   if 62 - 62: I1IiiI + II111iiii * iIii1I11I1II1 % iII111i + IiII / ooOoO0o
 else :
  for IIiIII1IIi in lisp_map_resolvers_list . values ( ) :
   if ( oo0Oo0OOOO ) :
    if ( oo0Oo0OOOO != IIiIII1IIi . dns_name ) : continue
   else :
    if ( oOoO0Oo0 . is_exact_match ( IIiIII1IIi . map_resolver ) == False ) : continue
    if 14 - 14: iIii1I11I1II1 * I1ii11iIi11i + OOooOOo + O0
    if 79 - 79: II111iiii - iII111i
   oOO [ "dns-name" ] = IIiIII1IIi . dns_name
   oOO [ "address" ] = IIiIII1IIi . map_resolver . print_address_no_iid ( )
   oOO [ "mr-name" ] = "" if IIiIII1IIi . mr_name == None else IIiIII1IIi . mr_name
   return ( [ oOO ] )
   if 89 - 89: O0 - OoO0O00
   if 8 - 8: I1ii11iIi11i / oO0o - OoooooooOO + ooOoO0o + o0oOOo0O0Ooo % i11iIiiIii
 return ( [ ] )
 if 32 - 32: O0 + IiII
 if 93 - 93: OoOoOO00 - I11i / iII111i - iIii1I11I1II1 + I11i % oO0o
 if 24 - 24: Ii1I / iIii1I11I1II1 + o0oOOo0O0Ooo
 if 17 - 17: OOooOOo
 if 75 - 75: Ii1I / i1IIi % I1ii11iIi11i . Ii1I
 if 46 - 46: II111iiii * OoO0O00
 if 77 - 77: ooOoO0o * I11i
 if 85 - 85: OoO0O00 * I1Ii111 - OoooooooOO / iIii1I11I1II1 - i1IIi + Ii1I
def lisp_process_api_database_mapping ( ) :
 i11iII1IiI = [ ]
 if 76 - 76: iII111i * OoooooooOO
 for I11i111 in lisp_db_list :
  iIIiI11iI1Ii1 = { }
  iIIiI11iI1Ii1 [ "eid-prefix" ] = I11i111 . eid . print_prefix ( )
  if ( I11i111 . group . is_null ( ) == False ) :
   iIIiI11iI1Ii1 [ "group-prefix" ] = I11i111 . group . print_prefix ( )
   if 49 - 49: II111iiii - OOooOOo + II111iiii + OoOoOO00
   if 51 - 51: i11iIiiIii
  Ii11iiI = [ ]
  for O00oo00o000o in I11i111 . rloc_set :
   oOOoo0O00 = { }
   if ( O00oo00o000o . rloc . is_null ( ) == False ) :
    oOOoo0O00 [ "rloc" ] = O00oo00o000o . rloc . print_address_no_iid ( )
    if 39 - 39: o0oOOo0O0Ooo % I1Ii111 % i1IIi - II111iiii + i11iIiiIii
   if ( O00oo00o000o . rloc_name != None ) : oOOoo0O00 [ "rloc-name" ] = O00oo00o000o . rloc_name
   if ( O00oo00o000o . interface != None ) : oOOoo0O00 [ "interface" ] = O00oo00o000o . interface
   OO0O0oOO = O00oo00o000o . translated_rloc
   if ( OO0O0oOO . is_null ( ) == False ) :
    oOOoo0O00 [ "translated-rloc" ] = OO0O0oOO . print_address_no_iid ( )
    if 22 - 22: Oo0Ooo / OOooOOo - iIii1I11I1II1 / ooOoO0o
   if ( oOOoo0O00 != { } ) : Ii11iiI . append ( oOOoo0O00 )
   if 7 - 7: ooOoO0o . OoooooooOO . iII111i * II111iiii . II111iiii / OOooOOo
   if 46 - 46: Ii1I - Oo0Ooo / i1IIi % IiII - I1ii11iIi11i + OOooOOo
   if 42 - 42: i1IIi - IiII % OOooOOo % iIii1I11I1II1
   if 71 - 71: OoO0O00
   if 72 - 72: II111iiii + o0oOOo0O0Ooo / i1IIi * Oo0Ooo / i1IIi
  iIIiI11iI1Ii1 [ "rlocs" ] = Ii11iiI
  if 52 - 52: I1Ii111 % OoO0O00 . I1Ii111 * I1ii11iIi11i * OoOoOO00 + i1IIi
  if 54 - 54: Ii1I / I1IiiI
  if 7 - 7: iIii1I11I1II1 . O0 + OOooOOo . Ii1I * Oo0Ooo
  if 25 - 25: I1Ii111 . Oo0Ooo % II111iiii . IiII - O0
  i11iII1IiI . append ( iIIiI11iI1Ii1 )
  if 18 - 18: oO0o * OOooOOo
 return ( i11iII1IiI )
 if 19 - 19: iIii1I11I1II1 / I1ii11iIi11i - I1ii11iIi11i / iIii1I11I1II1
 if 42 - 42: iIii1I11I1II1 / OOooOOo - O0 * OoooooooOO / i1IIi
 if 33 - 33: OOooOOo . o0oOOo0O0Ooo % OoO0O00 - I1Ii111 . OoooooooOO
 if 96 - 96: II111iiii % I11i / Ii1I - i11iIiiIii
 if 63 - 63: I1IiiI
 if 15 - 15: iIii1I11I1II1 - I1ii11iIi11i % OoO0O00 * II111iiii / I11i + I11i
 if 23 - 23: I1IiiI
def lisp_gather_site_cache_data ( se , data ) :
 iIIiI11iI1Ii1 = { }
 iIIiI11iI1Ii1 [ "site-name" ] = se . site . site_name
 iIIiI11iI1Ii1 [ "instance-id" ] = str ( se . eid . instance_id )
 iIIiI11iI1Ii1 [ "eid-prefix" ] = se . eid . print_prefix_no_iid ( )
 if ( se . group . is_null ( ) == False ) :
  iIIiI11iI1Ii1 [ "group-prefix" ] = se . group . print_prefix_no_iid ( )
  if 51 - 51: i11iIiiIii / ooOoO0o - OoooooooOO + OoOoOO00 + oO0o
 iIIiI11iI1Ii1 [ "registered" ] = "yes" if se . registered else "no"
 iIIiI11iI1Ii1 [ "first-registered" ] = lisp_print_elapsed ( se . first_registered )
 iIIiI11iI1Ii1 [ "last-registered" ] = lisp_print_elapsed ( se . last_registered )
 if 57 - 57: iIii1I11I1II1
 o0o0O00 = se . last_registerer
 o0o0O00 = "none" if o0o0O00 . is_null ( ) else o0o0O00 . print_address ( )
 iIIiI11iI1Ii1 [ "last-registerer" ] = o0o0O00
 iIIiI11iI1Ii1 [ "ams" ] = "yes" if ( se . accept_more_specifics ) else "no"
 iIIiI11iI1Ii1 [ "dynamic" ] = "yes" if ( se . dynamic ) else "no"
 iIIiI11iI1Ii1 [ "site-id" ] = str ( se . site_id )
 if ( se . xtr_id_present ) :
  iIIiI11iI1Ii1 [ "xtr-id" ] = "0x" + lisp_hex_string ( se . xtr_id )
  if 19 - 19: Ii1I / o0oOOo0O0Ooo + O0 / iIii1I11I1II1 + II111iiii
  if 3 - 3: oO0o % OoO0O00 % OOooOOo
  if 64 - 64: o0oOOo0O0Ooo . II111iiii * IiII % Oo0Ooo + I11i - OoooooooOO
  if 58 - 58: ooOoO0o
  if 15 - 15: O0 * OOooOOo * I11i + Ii1I * OoooooooOO + OOooOOo
 iii1Ii1i1i1I = [ ]
 for oOOoo0O00 in se . registered_rlocs :
  O00oo00o000o = { }
  O00oo00o000o [ "address" ] = oOOoo0O00 . rloc . print_address_no_iid ( ) if oOOoo0O00 . rloc_exists ( ) else "none"
  if 77 - 77: O0
  if 98 - 98: iII111i - iII111i % i1IIi - I1Ii111 . I1IiiI % o0oOOo0O0Ooo
  if ( oOOoo0O00 . geo ) : O00oo00o000o [ "geo" ] = oOOoo0O00 . geo . print_geo ( )
  if ( oOOoo0O00 . elp ) : O00oo00o000o [ "elp" ] = oOOoo0O00 . elp . print_elp ( False )
  if ( oOOoo0O00 . rle ) : O00oo00o000o [ "rle" ] = oOOoo0O00 . rle . print_rle ( False )
  if ( oOOoo0O00 . json ) : O00oo00o000o [ "json" ] = oOOoo0O00 . json . print_json ( False )
  if ( oOOoo0O00 . rloc_name ) : O00oo00o000o [ "rloc-name" ] = oOOoo0O00 . rloc_name
  O00oo00o000o [ "uptime" ] = lisp_print_elapsed ( oOOoo0O00 . uptime )
  O00oo00o000o [ "upriority" ] = str ( oOOoo0O00 . priority )
  O00oo00o000o [ "uweight" ] = str ( oOOoo0O00 . weight )
  O00oo00o000o [ "mpriority" ] = str ( oOOoo0O00 . mpriority )
  O00oo00o000o [ "mweight" ] = str ( oOOoo0O00 . mweight )
  if 38 - 38: IiII % OoOoOO00 . OOooOOo . I1ii11iIi11i
  iii1Ii1i1i1I . append ( O00oo00o000o )
  if 34 - 34: iII111i . i11iIiiIii + OoO0O00 + o0oOOo0O0Ooo / ooOoO0o - i11iIiiIii
 iIIiI11iI1Ii1 [ "registered-rlocs" ] = iii1Ii1i1i1I
 if 63 - 63: ooOoO0o % OoO0O00 % ooOoO0o
 data . append ( iIIiI11iI1Ii1 )
 return ( [ True , data ] )
 if 28 - 28: IiII * I1Ii111 * o0oOOo0O0Ooo + ooOoO0o - IiII / IiII
 if 73 - 73: iIii1I11I1II1 . I1ii11iIi11i + OOooOOo
 if 51 - 51: I11i % Oo0Ooo * OOooOOo % OoooooooOO - OoOoOO00 % Ii1I
 if 60 - 60: OoOoOO00 - IiII + OoO0O00
 if 77 - 77: iIii1I11I1II1
 if 92 - 92: IiII
 if 68 - 68: OOooOOo . IiII / iIii1I11I1II1 % i11iIiiIii
def lisp_process_api_site_cache_entry ( parms ) :
 o0OOoOO = parms [ "instance-id" ]
 o0OOoOO = 0 if ( o0OOoOO == "" ) else int ( o0OOoOO )
 if 74 - 74: iII111i + i11iIiiIii
 if 95 - 95: Ii1I
 if 49 - 49: I1ii11iIi11i . i1IIi + OoO0O00 % O0 + OoO0O00
 if 21 - 21: ooOoO0o * oO0o / OoooooooOO % ooOoO0o / O0
 o00oo00oo = lisp_address ( LISP_AFI_NONE , "" , 0 , o0OOoOO )
 o00oo00oo . store_prefix ( parms [ "eid-prefix" ] )
 if 24 - 24: OoO0O00 - i11iIiiIii / i11iIiiIii * I1Ii111
 if 20 - 20: IiII % iIii1I11I1II1 . iII111i + iIii1I11I1II1 + O0
 if 96 - 96: I1ii11iIi11i - IiII % OoooooooOO . iII111i
 if 30 - 30: Oo0Ooo . OoooooooOO / Oo0Ooo / oO0o
 if 44 - 44: I1ii11iIi11i % o0oOOo0O0Ooo / iIii1I11I1II1 - o0oOOo0O0Ooo / I11i * I1Ii111
 ii1I1 = lisp_address ( LISP_AFI_NONE , "" , 0 , o0OOoOO )
 if ( parms . has_key ( "group-prefix" ) ) :
  ii1I1 . store_prefix ( parms [ "group-prefix" ] )
  if 49 - 49: iII111i / iII111i - OoOoOO00
  if 89 - 89: ooOoO0o
 i11iII1IiI = [ ]
 I11IiI1ii = lisp_site_eid_lookup ( o00oo00oo , ii1I1 , False )
 if ( I11IiI1ii ) : lisp_gather_site_cache_data ( I11IiI1ii , i11iII1IiI )
 return ( i11iII1IiI )
 if 16 - 16: oO0o + oO0o + i1IIi + iIii1I11I1II1
 if 93 - 93: I1IiiI - i11iIiiIii * I1Ii111 - O0 + iII111i
 if 11 - 11: iII111i
 if 100 - 100: OoooooooOO / ooOoO0o . OoO0O00
 if 89 - 89: I11i % II111iiii
 if 35 - 35: oO0o
 if 65 - 65: II111iiii
def lisp_get_interface_instance_id ( device , source_eid ) :
 I111IIiIII = None
 if ( lisp_myinterfaces . has_key ( device ) ) :
  I111IIiIII = lisp_myinterfaces [ device ]
  if 87 - 87: oO0o / OoO0O00 - oO0o
  if 69 - 69: i11iIiiIii
  if 29 - 29: IiII . ooOoO0o / iII111i - OOooOOo / OOooOOo % Oo0Ooo
  if 42 - 42: OoO0O00 . I1Ii111 . I1IiiI + Oo0Ooo * O0
  if 35 - 35: Oo0Ooo / iII111i - O0 - OOooOOo * Oo0Ooo . i11iIiiIii
  if 43 - 43: OoOoOO00 % oO0o % OoO0O00 / Ii1I . I11i
 if ( I111IIiIII == None or I111IIiIII . instance_id == None ) :
  return ( lisp_default_iid )
  if 86 - 86: I1Ii111 * i1IIi + IiII - OoOoOO00
  if 14 - 14: I1ii11iIi11i / i11iIiiIii * I11i % o0oOOo0O0Ooo + IiII / I1ii11iIi11i
  if 82 - 82: OOooOOo . oO0o
  if 12 - 12: i11iIiiIii + II111iiii
  if 49 - 49: OoooooooOO
  if 48 - 48: i1IIi . IiII - O0 + OoooooooOO
  if 6 - 6: I1Ii111 * OOooOOo + o0oOOo0O0Ooo . I1ii11iIi11i * I1Ii111
  if 6 - 6: oO0o / II111iiii
  if 23 - 23: IiII - OoooooooOO / oO0o
 o0OOoOO = I111IIiIII . get_instance_id ( )
 if ( source_eid == None ) : return ( o0OOoOO )
 if 69 - 69: O0 - OoooooooOO
 III = source_eid . instance_id
 IiiI = None
 for I111IIiIII in lisp_multi_tenant_interfaces :
  if ( I111IIiIII . device != device ) : continue
  OOoOOoo = I111IIiIII . multi_tenant_eid
  source_eid . instance_id = OOoOOoo . instance_id
  if ( source_eid . is_more_specific ( OOoOOoo ) == False ) : continue
  if ( IiiI == None or IiiI . multi_tenant_eid . mask_len < OOoOOoo . mask_len ) :
   IiiI = I111IIiIII
   if 21 - 21: oO0o / iIii1I11I1II1 / OoO0O00 + IiII - iII111i
   if 68 - 68: II111iiii - IiII * i11iIiiIii
 source_eid . instance_id = III
 if 64 - 64: i11iIiiIii . I1Ii111 % i11iIiiIii % I11i
 if ( IiiI == None ) : return ( o0OOoOO )
 return ( IiiI . get_instance_id ( ) )
 if 56 - 56: o0oOOo0O0Ooo + ooOoO0o + OoooooooOO
 if 64 - 64: OOooOOo / OoOoOO00
 if 30 - 30: OOooOOo % I1Ii111 - i11iIiiIii
 if 20 - 20: i1IIi * I11i / OoO0O00 / i1IIi / I1Ii111 * O0
 if 95 - 95: Ii1I + Ii1I % IiII - IiII / OOooOOo
 if 46 - 46: IiII + iII111i + II111iiii . iII111i - i11iIiiIii % OoO0O00
 if 24 - 24: oO0o + IiII . o0oOOo0O0Ooo . OoooooooOO . i11iIiiIii / I1ii11iIi11i
 if 49 - 49: IiII
 if 1 - 1: oO0o / I11i
def lisp_allow_dynamic_eid ( device , eid ) :
 if ( lisp_myinterfaces . has_key ( device ) == False ) : return ( None )
 if 99 - 99: OoO0O00 % IiII + I1Ii111 - oO0o
 I111IIiIII = lisp_myinterfaces [ device ]
 I1Ii1i1ii = device if I111IIiIII . dynamic_eid_device == None else I111IIiIII . dynamic_eid_device
 if 60 - 60: OoooooooOO / i1IIi / i1IIi / Ii1I . IiII
 if 24 - 24: O0
 if ( I111IIiIII . does_dynamic_eid_match ( eid ) ) : return ( I1Ii1i1ii )
 return ( None )
 if 6 - 6: I1IiiI . i11iIiiIii . OoooooooOO . I1IiiI . o0oOOo0O0Ooo
 if 65 - 65: i11iIiiIii
 if 46 - 46: i11iIiiIii
 if 70 - 70: i1IIi + o0oOOo0O0Ooo
 if 44 - 44: iII111i . II111iiii % o0oOOo0O0Ooo
 if 29 - 29: i11iIiiIii * i1IIi
 if 36 - 36: OoO0O00 * I11i . ooOoO0o
def lisp_start_rloc_probe_timer ( interval , lisp_sockets ) :
 global lisp_rloc_probe_timer
 if 50 - 50: oO0o * OoOoOO00 / OoO0O00 / ooOoO0o + II111iiii
 if ( lisp_rloc_probe_timer != None ) : lisp_rloc_probe_timer . cancel ( )
 if 55 - 55: II111iiii - IiII
 iIi1i1iiIII = lisp_process_rloc_probe_timer
 oO00oo0 = threading . Timer ( interval , iIi1i1iiIII , [ lisp_sockets ] )
 lisp_rloc_probe_timer = oO00oo0
 oO00oo0 . start ( )
 return
 if 17 - 17: Ii1I / OoOoOO00 % I1ii11iIi11i - IiII
 if 76 - 76: Ii1I / o0oOOo0O0Ooo % IiII % Oo0Ooo
 if 68 - 68: o0oOOo0O0Ooo / O0 + i11iIiiIii % II111iiii
 if 10 - 10: iII111i - Oo0Ooo
 if 10 - 10: IiII + I1Ii111 / OoooooooOO % I1Ii111 * i11iIiiIii - oO0o
 if 73 - 73: IiII - II111iiii - OOooOOo % II111iiii + iIii1I11I1II1
 if 81 - 81: i11iIiiIii - O0 + I1IiiI
def lisp_show_rloc_probe_list ( ) :
 lprint ( bold ( "----- RLOC-probe-list -----" , False ) )
 for o0OoOo0o0OOoO0 in lisp_rloc_probe_list :
  I1i1IiIIiIIi1 = lisp_rloc_probe_list [ o0OoOo0o0OOoO0 ]
  lprint ( "RLOC {}:" . format ( o0OoOo0o0OOoO0 ) )
  for O00oo00o000o , ooo0OO , O0oOo00Oo0oo0 in I1i1IiIIiIIi1 :
   lprint ( "  [{}, {}, {}, {}]" . format ( hex ( id ( O00oo00o000o ) ) , ooo0OO . print_prefix ( ) ,
 O0oOo00Oo0oo0 . print_prefix ( ) , O00oo00o000o . translated_port ) )
   if 23 - 23: ooOoO0o * II111iiii . II111iiii % I1Ii111
   if 69 - 69: I1ii11iIi11i * IiII / II111iiii
 lprint ( bold ( "---------------------------" , False ) )
 return
 if 10 - 10: O0 / I11i
 if 29 - 29: i11iIiiIii % I11i
 if 49 - 49: I11i
 if 69 - 69: o0oOOo0O0Ooo . O0 * I11i
 if 92 - 92: OoO0O00 . O0 / Ii1I % Oo0Ooo . Ii1I
 if 40 - 40: o0oOOo0O0Ooo - Ii1I . iII111i - O0
 if 53 - 53: Oo0Ooo - I1IiiI * O0 . II111iiii
 if 72 - 72: ooOoO0o - Ii1I . Ii1I . I11i / OoooooooOO + Ii1I
 if 32 - 32: O0
def lisp_mark_rlocs_for_other_eids ( eid_list ) :
 if 42 - 42: i1IIi * I1ii11iIi11i * OoOoOO00
 if 43 - 43: I1ii11iIi11i % I1ii11iIi11i % i1IIi
 if 56 - 56: I1IiiI - OoO0O00 - iII111i . o0oOOo0O0Ooo . I1Ii111
 if 70 - 70: iIii1I11I1II1 - I11i
 oOOoo0O00 , ooo0OO , O0oOo00Oo0oo0 = eid_list [ 0 ]
 iI1i = [ lisp_print_eid_tuple ( ooo0OO , O0oOo00Oo0oo0 ) ]
 if 45 - 45: OoO0O00 % iII111i / iIii1I11I1II1 % I1IiiI + OOooOOo
 for oOOoo0O00 , ooo0OO , O0oOo00Oo0oo0 in eid_list [ 1 : : ] :
  oOOoo0O00 . state = LISP_RLOC_UNREACH_STATE
  oOOoo0O00 . last_state_change = lisp_get_timestamp ( )
  iI1i . append ( lisp_print_eid_tuple ( ooo0OO , O0oOo00Oo0oo0 ) )
  if 62 - 62: OOooOOo . OOooOOo . oO0o
  if 18 - 18: iII111i . I1IiiI . ooOoO0o * oO0o / OoooooooOO
 o0oOO0o0 = bold ( "unreachable" , False )
 oooOOoo0 = red ( oOOoo0O00 . rloc . print_address_no_iid ( ) , False )
 if 27 - 27: Oo0Ooo
 for o00oo00oo in iI1i :
  ooo0OO = green ( o00oo00oo , False )
  lprint ( "RLOC {} went {} for EID {}" . format ( oooOOoo0 , o0oOO0o0 , ooo0OO ) )
  if 15 - 15: Ii1I / OOooOOo % i1IIi . I1Ii111 / O0 + I1Ii111
  if 39 - 39: I1ii11iIi11i * I1IiiI * II111iiii . Oo0Ooo % I1IiiI
  if 100 - 100: iIii1I11I1II1 - OoooooooOO * OoooooooOO - iII111i / ooOoO0o
  if 98 - 98: OoO0O00 + oO0o - II111iiii
  if 84 - 84: Oo0Ooo . OoOoOO00 - iII111i
  if 5 - 5: OoooooooOO . O0 / OOooOOo + I11i - Ii1I
 for oOOoo0O00 , ooo0OO , O0oOo00Oo0oo0 in eid_list :
  Iii1 = lisp_map_cache . lookup_cache ( ooo0OO , True )
  if ( Iii1 ) : lisp_write_ipc_map_cache ( True , Iii1 )
  if 77 - 77: iIii1I11I1II1 * Oo0Ooo . IiII / oO0o + O0
 return
 if 76 - 76: iII111i + o0oOOo0O0Ooo - OoooooooOO * oO0o % OoooooooOO - O0
 if 18 - 18: Ii1I
 if 82 - 82: OoOoOO00 + OoO0O00 - IiII / ooOoO0o
 if 70 - 70: OoO0O00
 if 43 - 43: ooOoO0o + OOooOOo + II111iiii - I1IiiI
 if 58 - 58: I11i
 if 94 - 94: Oo0Ooo
 if 39 - 39: I11i - oO0o % iII111i - ooOoO0o - OoOoOO00
 if 8 - 8: i1IIi % i1IIi % OoooooooOO % i1IIi . iIii1I11I1II1
 if 70 - 70: O0 + II111iiii % IiII / I1Ii111 - IiII
def lisp_process_rloc_probe_timer ( lisp_sockets ) :
 lisp_set_exception ( )
 if 58 - 58: II111iiii * oO0o - i1IIi . I11i
 lisp_start_rloc_probe_timer ( LISP_RLOC_PROBE_INTERVAL , lisp_sockets )
 if ( lisp_rloc_probing == False ) : return
 if 23 - 23: OoO0O00 - I1IiiI * i11iIiiIii
 if 62 - 62: OoO0O00 . i11iIiiIii / i1IIi
 if 3 - 3: OoO0O00 + O0 % Oo0Ooo * Oo0Ooo % i11iIiiIii
 if 29 - 29: ooOoO0o / iII111i / OOooOOo - iIii1I11I1II1
 if ( lisp_print_rloc_probe_list ) : lisp_show_rloc_probe_list ( )
 if 31 - 31: i1IIi * Ii1I
 if 94 - 94: oO0o / Ii1I % iIii1I11I1II1 + i1IIi / O0 - iII111i
 if 77 - 77: o0oOOo0O0Ooo - IiII . i1IIi
 if 70 - 70: i1IIi . I1Ii111 . iII111i - OoOoOO00 + II111iiii + OOooOOo
 OOOIiiiIiIiIIi1I = lisp_get_default_route_next_hops ( )
 if 89 - 89: ooOoO0o * II111iiii * oO0o - iII111i
 lprint ( "---------- Start RLOC Probing for {} entries ----------" . format ( len ( lisp_rloc_probe_list ) ) )
 if 22 - 22: I1Ii111 * oO0o - OoO0O00
 if 12 - 12: IiII . OoooooooOO - iIii1I11I1II1 % iII111i
 if 56 - 56: Oo0Ooo / I1IiiI + iIii1I11I1II1 + I1IiiI % iIii1I11I1II1
 if 64 - 64: O0
 if 55 - 55: OoO0O00 * oO0o . Ii1I + OoOoOO00 % I11i + IiII
 I1I11Iiii111 = 0
 iI11iI11i11ii = bold ( "RLOC-probe" , False )
 for OooO0OO in lisp_rloc_probe_list . values ( ) :
  if 14 - 14: OoO0O00 + I1IiiI . o0oOOo0O0Ooo - OoO0O00 + Ii1I - Ii1I
  if 98 - 98: oO0o * O0 + I11i
  if 75 - 75: i1IIi . I11i . O0 / I1ii11iIi11i / Oo0Ooo . i1IIi
  if 36 - 36: Oo0Ooo . Oo0Ooo - OOooOOo / IiII / OoooooooOO / I1IiiI
  if 7 - 7: ooOoO0o * o0oOOo0O0Ooo + ooOoO0o / Oo0Ooo % o0oOOo0O0Ooo . ooOoO0o
  iIi1I11IIi = None
  for O0Oo0o0o0 , o00oo00oo , ii1I1 in OooO0OO :
   I1iiIiiii1111 = O0Oo0o0o0 . rloc . print_address_no_iid ( )
   if 69 - 69: I1Ii111 . Ii1I * I1ii11iIi11i % I11i - o0oOOo0O0Ooo
   if 30 - 30: ooOoO0o / Oo0Ooo * iII111i % OoooooooOO / I1ii11iIi11i
   if 64 - 64: OoooooooOO
   if 41 - 41: Ii1I . I11i / oO0o * OoooooooOO
   if 98 - 98: I1ii11iIi11i - O0 + i11iIiiIii
   if 71 - 71: O0 - OoooooooOO
   if ( O0Oo0o0o0 . down_state ( ) ) : continue
   if 82 - 82: i11iIiiIii * II111iiii % IiII
   if 80 - 80: Ii1I . i11iIiiIii % oO0o * o0oOOo0O0Ooo
   if 56 - 56: I1Ii111 % iII111i / II111iiii - Oo0Ooo - Oo0Ooo - iIii1I11I1II1
   if 67 - 67: iII111i
   if 80 - 80: Ii1I . iII111i * I1IiiI * Ii1I
   if 82 - 82: OoO0O00 % OoOoOO00 * i11iIiiIii . OoO0O00 . I1ii11iIi11i + Ii1I
   if 60 - 60: i1IIi / iII111i
   if 10 - 10: I1Ii111 / OoOoOO00 * Ii1I % o0oOOo0O0Ooo . OoOoOO00 / I1ii11iIi11i
   if 2 - 2: iIii1I11I1II1
   if 85 - 85: O0 - ooOoO0o
   if 35 - 35: o0oOOo0O0Ooo - I1IiiI
   if ( iIi1I11IIi ) :
    O0Oo0o0o0 . last_rloc_probe_nonce = iIi1I11IIi . last_rloc_probe_nonce
    if 47 - 47: i11iIiiIii * iII111i . OoOoOO00 * I1Ii111 % i11iIiiIii + Ii1I
    if ( iIi1I11IIi . translated_port == O0Oo0o0o0 . translated_port and iIi1I11IIi . rloc_name == O0Oo0o0o0 . rloc_name ) :
     if 65 - 65: Ii1I % i11iIiiIii
     ooo0OO = green ( lisp_print_eid_tuple ( o00oo00oo , ii1I1 ) , False )
     lprint ( "Suppress probe to duplicate RLOC {} for {}" . format ( red ( I1iiIiiii1111 , False ) , ooo0OO ) )
     if 98 - 98: iII111i * o0oOOo0O0Ooo % Oo0Ooo
     continue
     if 7 - 7: oO0o * OoooooooOO % o0oOOo0O0Ooo . I1Ii111 + O0
     if 14 - 14: I11i * II111iiii % o0oOOo0O0Ooo / iII111i . OoooooooOO % iII111i
     if 88 - 88: iII111i
   o00ooO0Ooo = None
   oOOoo0O00 = None
   while ( True ) :
    oOOoo0O00 = O0Oo0o0o0 if oOOoo0O00 == None else oOOoo0O00 . next_rloc
    if ( oOOoo0O00 == None ) : break
    if 94 - 94: OoooooooOO
    if 32 - 32: I1ii11iIi11i
    if 8 - 8: I11i * i11iIiiIii - ooOoO0o
    if 47 - 47: ooOoO0o . I1IiiI / i11iIiiIii * iII111i * I1IiiI
    if 8 - 8: oO0o % oO0o . iII111i / i1IIi % IiII
    if ( oOOoo0O00 . rloc_next_hop != None ) :
     if ( oOOoo0O00 . rloc_next_hop not in OOOIiiiIiIiIIi1I ) :
      if ( oOOoo0O00 . up_state ( ) ) :
       oOo0OOOOOO , o0O0 = oOOoo0O00 . rloc_next_hop
       oOOoo0O00 . state = LISP_RLOC_UNREACH_STATE
       oOOoo0O00 . last_state_change = lisp_get_timestamp ( )
       lisp_update_rtr_updown ( oOOoo0O00 . rloc , False )
       if 71 - 71: OoOoOO00 + oO0o % O0 + Oo0Ooo
      o0oOO0o0 = bold ( "unreachable" , False )
      lprint ( "Next-hop {}({}) for RLOC {} is {}" . format ( o0O0 , oOo0OOOOOO ,
 red ( I1iiIiiii1111 , False ) , o0oOO0o0 ) )
      continue
      if 62 - 62: i1IIi . Ii1I * i1IIi * O0 . I1IiiI % o0oOOo0O0Ooo
      if 16 - 16: I11i . Ii1I - ooOoO0o . OOooOOo % O0 / oO0o
      if 42 - 42: II111iiii . iII111i
      if 67 - 67: i1IIi - i11iIiiIii / ooOoO0o * oO0o
      if 64 - 64: oO0o / IiII
      if 86 - 86: I11i
    i1oo0OO0Oo = oOOoo0O00 . last_rloc_probe
    iIIi1 = 0 if i1oo0OO0Oo == None else time . time ( ) - i1oo0OO0Oo
    if ( oOOoo0O00 . unreach_state ( ) and iIIi1 < LISP_RLOC_PROBE_INTERVAL ) :
     lprint ( "Waiting for probe-reply from RLOC {}" . format ( red ( I1iiIiiii1111 , False ) ) )
     if 80 - 80: I1IiiI + iII111i * OoooooooOO . IiII . I1ii11iIi11i
     continue
     if 20 - 20: Ii1I % O0 . o0oOOo0O0Ooo + i11iIiiIii % iII111i / o0oOOo0O0Ooo
     if 34 - 34: iIii1I11I1II1
     if 26 - 26: iII111i / IiII * iII111i
     if 91 - 91: Oo0Ooo
     if 98 - 98: iIii1I11I1II1 . OoO0O00
     if 1 - 1: OOooOOo % Oo0Ooo
    O00o = lisp_get_echo_nonce ( None , I1iiIiiii1111 )
    if ( O00o and O00o . request_nonce_timeout ( ) ) :
     oOOoo0O00 . state = LISP_RLOC_NO_ECHOED_NONCE_STATE
     oOOoo0O00 . last_state_change = lisp_get_timestamp ( )
     o0oOO0o0 = bold ( "unreachable" , False )
     lprint ( "RLOC {} went {}, nonce-echo failed" . format ( red ( I1iiIiiii1111 , False ) , o0oOO0o0 ) )
     if 86 - 86: i11iIiiIii
     lisp_update_rtr_updown ( oOOoo0O00 . rloc , False )
     continue
     if 57 - 57: iII111i - OoooooooOO - ooOoO0o % II111iiii
     if 62 - 62: i11iIiiIii . Oo0Ooo / Oo0Ooo . IiII . OoooooooOO
     if 86 - 86: I1ii11iIi11i * OoOoOO00 + iII111i
     if 79 - 79: I11i - II111iiii
     if 27 - 27: I1IiiI + o0oOOo0O0Ooo * oO0o % I1IiiI
     if 66 - 66: OoO0O00 + IiII . o0oOOo0O0Ooo . IiII
    if ( O00o and O00o . recently_echoed ( ) ) :
     lprint ( ( "Suppress RLOC-probe to {}, nonce-echo " + "received" ) . format ( red ( I1iiIiiii1111 , False ) ) )
     if 88 - 88: oO0o + oO0o % OoO0O00 . OoooooooOO - OoooooooOO . Oo0Ooo
     continue
     if 44 - 44: I1IiiI * IiII . OoooooooOO
     if 62 - 62: I11i - Ii1I / i11iIiiIii * I1IiiI + ooOoO0o + o0oOOo0O0Ooo
     if 10 - 10: i1IIi + o0oOOo0O0Ooo
     if 47 - 47: OOooOOo * IiII % I1Ii111 . OoOoOO00 - OoooooooOO / OoooooooOO
     if 79 - 79: I11i % i11iIiiIii % I1IiiI . OoooooooOO * oO0o . Ii1I
     if 14 - 14: iIii1I11I1II1 / I11i - o0oOOo0O0Ooo / IiII / o0oOOo0O0Ooo . OoO0O00
    if ( oOOoo0O00 . last_rloc_probe != None ) :
     i1oo0OO0Oo = oOOoo0O00 . last_rloc_probe_reply
     if ( i1oo0OO0Oo == None ) : i1oo0OO0Oo = 0
     iIIi1 = time . time ( ) - i1oo0OO0Oo
     if ( oOOoo0O00 . up_state ( ) and iIIi1 >= LISP_RLOC_PROBE_REPLY_WAIT ) :
      if 2 - 2: I11i
      oOOoo0O00 . state = LISP_RLOC_UNREACH_STATE
      oOOoo0O00 . last_state_change = lisp_get_timestamp ( )
      lisp_update_rtr_updown ( oOOoo0O00 . rloc , False )
      o0oOO0o0 = bold ( "unreachable" , False )
      lprint ( "RLOC {} went {}, probe it" . format ( red ( I1iiIiiii1111 , False ) , o0oOO0o0 ) )
      if 12 - 12: i1IIi . I1Ii111
      if 99 - 99: Oo0Ooo / i11iIiiIii
      lisp_mark_rlocs_for_other_eids ( OooO0OO )
      if 81 - 81: Ii1I . i1IIi % iII111i . OoO0O00 % IiII
      if 42 - 42: iII111i / Oo0Ooo
      if 14 - 14: O0 . Oo0Ooo
    oOOoo0O00 . last_rloc_probe = lisp_get_timestamp ( )
    if 8 - 8: i11iIiiIii
    oO0oo0o = "" if oOOoo0O00 . unreach_state ( ) == False else " unreachable"
    if 36 - 36: O0 + OOooOOo * i1IIi - OoooooooOO * iII111i
    if 8 - 8: OoooooooOO * i11iIiiIii * iII111i * O0 - OoOoOO00
    if 3 - 3: OoooooooOO % oO0o + OoOoOO00 % I1IiiI
    if 50 - 50: OoO0O00 - Oo0Ooo
    if 13 - 13: OoOoOO00
    if 72 - 72: II111iiii * iII111i . II111iiii + iII111i * IiII
    if 90 - 90: oO0o * I1Ii111 / O0
    IIiii1IiiIiii = ""
    o0O0 = None
    if ( oOOoo0O00 . rloc_next_hop != None ) :
     oOo0OOOOOO , o0O0 = oOOoo0O00 . rloc_next_hop
     lisp_install_host_route ( I1iiIiiii1111 , o0O0 , True )
     IIiii1IiiIiii = ", send on nh {}({})" . format ( o0O0 , oOo0OOOOOO )
     if 81 - 81: I11i
     if 31 - 31: OoooooooOO - OoO0O00 . iIii1I11I1II1 % I1IiiI
     if 98 - 98: I1IiiI + Ii1I
     if 7 - 7: o0oOOo0O0Ooo . OoooooooOO
     if 32 - 32: I1ii11iIi11i
    OOOOo000o = oOOoo0O00 . print_rloc_probe_rtt ( )
    I1iIIii111i11i11 = I1iiIiiii1111
    if ( oOOoo0O00 . translated_port != 0 ) :
     I1iIIii111i11i11 += ":{}" . format ( oOOoo0O00 . translated_port )
     if 10 - 10: I1IiiI % I1Ii111 . IiII - OOooOOo
    I1iIIii111i11i11 = red ( I1iIIii111i11i11 , False )
    if ( oOOoo0O00 . rloc_name != None ) :
     I1iIIii111i11i11 += " (" + blue ( oOOoo0O00 . rloc_name , False ) + ")"
     if 93 - 93: iIii1I11I1II1
    lprint ( "Send {}{} {}, last rtt: {}{}" . format ( iI11iI11i11ii , oO0oo0o ,
 I1iIIii111i11i11 , OOOOo000o , IIiii1IiiIiii ) )
    if 33 - 33: OOooOOo . i1IIi
    if 63 - 63: II111iiii . oO0o * IiII
    if 73 - 73: iII111i . i1IIi + oO0o + OOooOOo + ooOoO0o - iIii1I11I1II1
    if 47 - 47: I11i
    if 88 - 88: OoO0O00 - OoooooooOO
    if 93 - 93: Oo0Ooo * I1IiiI
    if 60 - 60: I1Ii111 + OOooOOo % iII111i
    if 40 - 40: I11i + oO0o . O0 % oO0o
    if ( oOOoo0O00 . rloc_next_hop != None ) :
     o00ooO0Ooo = lisp_get_host_route_next_hop ( I1iiIiiii1111 )
     if ( o00ooO0Ooo ) : lisp_install_host_route ( I1iiIiiii1111 , o00ooO0Ooo , False )
     if 12 - 12: iIii1I11I1II1
     if 9 - 9: OoOoOO00 * II111iiii / o0oOOo0O0Ooo * iII111i - II111iiii / i11iIiiIii
     if 14 - 14: i11iIiiIii + I1Ii111 . OoOoOO00 - oO0o * OoO0O00
     if 23 - 23: iIii1I11I1II1
     if 32 - 32: iII111i * iIii1I11I1II1 + I1Ii111 + IiII + O0 * OoO0O00
     if 100 - 100: II111iiii
    if ( oOOoo0O00 . rloc . is_null ( ) ) :
     oOOoo0O00 . rloc . copy_address ( O0Oo0o0o0 . rloc )
     if 34 - 34: I11i % OOooOOo - iII111i % II111iiii
     if 14 - 14: I11i * o0oOOo0O0Ooo % II111iiii
     if 36 - 36: ooOoO0o - iIii1I11I1II1 / IiII + OoOoOO00
     if 42 - 42: ooOoO0o + I1IiiI * iII111i / OoOoOO00 . i1IIi - OoooooooOO
     if 8 - 8: iIii1I11I1II1 - Oo0Ooo + iII111i
    Oooo0oo000O0 = None if ( ii1I1 . is_null ( ) ) else o00oo00oo
    iII1I1iiII11I = o00oo00oo if ( ii1I1 . is_null ( ) ) else ii1I1
    lisp_send_map_request ( lisp_sockets , 0 , Oooo0oo000O0 , iII1I1iiII11I , oOOoo0O00 )
    iIi1I11IIi = O0Oo0o0o0
    if 44 - 44: iII111i / Oo0Ooo / IiII / i11iIiiIii - i11iIiiIii
    if 14 - 14: i1IIi
    if 19 - 19: I1IiiI * OoO0O00 * O0 - i11iIiiIii - ooOoO0o - I11i
    if 47 - 47: iIii1I11I1II1
    if ( o0O0 ) : lisp_install_host_route ( I1iiIiiii1111 , o0O0 , False )
    if 64 - 64: OoooooooOO . Ii1I
    if 38 - 38: Oo0Ooo
    if 64 - 64: ooOoO0o % i11iIiiIii
    if 10 - 10: Ii1I % oO0o + oO0o * OoOoOO00 % iII111i / o0oOOo0O0Ooo
    if 17 - 17: iII111i / I1IiiI . II111iiii - OoO0O00 + iII111i
   if ( o00ooO0Ooo ) : lisp_install_host_route ( I1iiIiiii1111 , o00ooO0Ooo , True )
   if 22 - 22: Oo0Ooo - I1ii11iIi11i + I11i . oO0o
   if 85 - 85: iIii1I11I1II1 / Ii1I
   if 43 - 43: I1IiiI % I1Ii111 - oO0o . II111iiii / iIii1I11I1II1
   if 97 - 97: I1Ii111 + I1ii11iIi11i
   I1I11Iiii111 += 1
   if ( ( I1I11Iiii111 % 10 ) == 0 ) : time . sleep ( 0.020 )
   if 21 - 21: O0 + o0oOOo0O0Ooo * OoooooooOO % IiII % I1ii11iIi11i
   if 80 - 80: I11i
   if 28 - 28: OoOoOO00 * OoooooooOO * i11iIiiIii
 lprint ( "---------- End RLOC Probing ----------" )
 return
 if 88 - 88: ooOoO0o + ooOoO0o / I1Ii111
 if 69 - 69: O0 * o0oOOo0O0Ooo + i1IIi * ooOoO0o . o0oOOo0O0Ooo
 if 46 - 46: Oo0Ooo / Oo0Ooo * IiII
 if 65 - 65: iIii1I11I1II1 * o0oOOo0O0Ooo - iII111i % II111iiii - I1ii11iIi11i
 if 65 - 65: I11i
 if 92 - 92: iII111i . IiII + i1IIi % i1IIi
 if 11 - 11: I1ii11iIi11i + iIii1I11I1II1 - I1Ii111 * iIii1I11I1II1 * IiII + oO0o
 if 6 - 6: I1Ii111 * OOooOOo + i1IIi - Ii1I / oO0o
def lisp_update_rtr_updown ( rtr , updown ) :
 global lisp_ipc_socket
 if 81 - 81: I1Ii111 % oO0o * i1IIi * OoooooooOO / Oo0Ooo
 if 70 - 70: I1IiiI
 if 35 - 35: i11iIiiIii
 if 59 - 59: ooOoO0o . iII111i - II111iiii
 if ( lisp_i_am_itr == False ) : return
 if 30 - 30: o0oOOo0O0Ooo % iII111i - i11iIiiIii
 if 25 - 25: i11iIiiIii + OoOoOO00 + oO0o / Ii1I * Oo0Ooo + Oo0Ooo
 if 26 - 26: I1IiiI % I1ii11iIi11i + o0oOOo0O0Ooo / I1ii11iIi11i - I1IiiI
 if 55 - 55: OoooooooOO
 if 2 - 2: Oo0Ooo + I11i / OOooOOo + OOooOOo
 if ( lisp_register_all_rtrs ) : return
 if 62 - 62: OOooOOo . iIii1I11I1II1 + I1IiiI / OOooOOo
 oo0OOoOOOO = rtr . print_address_no_iid ( )
 if 38 - 38: O0 * iIii1I11I1II1 - oO0o
 if 38 - 38: iIii1I11I1II1 / I1Ii111 + ooOoO0o . II111iiii - iIii1I11I1II1
 if 13 - 13: Ii1I
 if 34 - 34: I1IiiI / iIii1I11I1II1
 if 35 - 35: oO0o / oO0o
 if ( lisp_rtr_list . has_key ( oo0OOoOOOO ) == False ) : return
 if 86 - 86: o0oOOo0O0Ooo . Oo0Ooo - Ii1I / i11iIiiIii
 updown = "up" if updown else "down"
 lprint ( "Send ETR IPC message, RTR {} has done {}" . format (
 red ( oo0OOoOOOO , False ) , bold ( updown , False ) ) )
 if 63 - 63: oO0o - O0 + I1ii11iIi11i + Ii1I / i1IIi
 if 77 - 77: O0
 if 49 - 49: o0oOOo0O0Ooo / i11iIiiIii
 if 36 - 36: II111iiii
 IIi1IIII = "rtr%{}%{}" . format ( oo0OOoOOOO , updown )
 IIi1IIII = lisp_command_ipc ( IIi1IIII , "lisp-itr" )
 lisp_ipc ( IIi1IIII , lisp_ipc_socket , "lisp-etr" )
 return
 if 78 - 78: OoO0O00 + iIii1I11I1II1 * i1IIi
 if 7 - 7: i11iIiiIii
 if 49 - 49: I1IiiI - oO0o % OOooOOo / O0 / II111iiii
 if 41 - 41: IiII % II111iiii
 if 99 - 99: IiII - O0
 if 59 - 59: iII111i % O0 + OOooOOo * ooOoO0o
 if 27 - 27: I1Ii111 % i11iIiiIii * I1IiiI
def lisp_process_rloc_probe_reply ( rloc , source , port , nonce , hop_count , ttl ) :
 iI11iI11i11ii = bold ( "RLOC-probe reply" , False )
 IIII = rloc . print_address_no_iid ( )
 Ii1II1 = source . print_address_no_iid ( )
 OO = lisp_rloc_probe_list
 if 34 - 34: II111iiii . I11i . iII111i / I1Ii111
 if 67 - 67: i1IIi . oO0o
 if 17 - 17: iII111i * I1IiiI % I1Ii111 + OoOoOO00 * ooOoO0o - O0
 if 36 - 36: O0 / I11i % OoOoOO00 % OoOoOO00 * iII111i
 if 99 - 99: o0oOOo0O0Ooo - iIii1I11I1II1 * OoO0O00 - oO0o * oO0o % IiII
 if 44 - 44: I11i / I1ii11iIi11i
 o0o0O00 = IIII
 if ( OO . has_key ( o0o0O00 ) == False ) :
  o0o0O00 += ":" + str ( port )
  if ( OO . has_key ( o0o0O00 ) == False ) :
   o0o0O00 = Ii1II1
   if ( OO . has_key ( o0o0O00 ) == False ) :
    o0o0O00 += ":" + str ( port )
    lprint ( "    Received unsolicited {} from {}/{}, port {}" . format ( iI11iI11i11ii , red ( IIII , False ) , red ( Ii1II1 ,
    # OoooooooOO % i1IIi . iIii1I11I1II1 / I1IiiI
 False ) , port ) )
    return
    if 97 - 97: iII111i
    if 26 - 26: i1IIi - I1Ii111 - ooOoO0o
    if 73 - 73: o0oOOo0O0Ooo . OoooooooOO
    if 96 - 96: i1IIi - OOooOOo / I11i % OoOoOO00 - i11iIiiIii % II111iiii
    if 47 - 47: I1Ii111 * iII111i
    if 90 - 90: i1IIi * Ii1I . OoO0O00 % I11i * ooOoO0o . OOooOOo
    if 76 - 76: iIii1I11I1II1 . i11iIiiIii * II111iiii - iII111i
    if 51 - 51: I1IiiI
 for rloc , o00oo00oo , ii1I1 in lisp_rloc_probe_list [ o0o0O00 ] :
  if ( lisp_i_am_rtr and rloc . translated_port != 0 and
 rloc . translated_port != port ) : continue
  if 52 - 52: I1Ii111
  rloc . process_rloc_probe_reply ( nonce , o00oo00oo , ii1I1 , hop_count , ttl )
  if 82 - 82: iII111i + II111iiii
 return
 if 29 - 29: O0 % Ii1I * ooOoO0o % O0
 if 83 - 83: oO0o
 if 95 - 95: Oo0Ooo * O0 % i1IIi / iII111i + oO0o
 if 85 - 85: iIii1I11I1II1 / I11i
 if 65 - 65: I11i / i1IIi * OoOoOO00 * Ii1I * OoO0O00
 if 74 - 74: I1ii11iIi11i . I1ii11iIi11i % IiII + OOooOOo . OoO0O00 * I11i
 if 20 - 20: OOooOOo % i1IIi * Ii1I / i11iIiiIii
 if 89 - 89: ooOoO0o
def lisp_db_list_length ( ) :
 I1I11Iiii111 = 0
 for I11i111 in lisp_db_list :
  I1I11Iiii111 += len ( I11i111 . dynamic_eids ) if I11i111 . dynamic_eid_configured ( ) else 1
  I1I11Iiii111 += len ( I11i111 . eid . iid_list )
  if 83 - 83: I11i . I11i * OOooOOo - OOooOOo
 return ( I1I11Iiii111 )
 if 46 - 46: iIii1I11I1II1 . I1Ii111 % I1IiiI
 if 22 - 22: i1IIi * I11i + II111iiii + II111iiii
 if 20 - 20: I11i
 if 37 - 37: I1Ii111
 if 19 - 19: I1ii11iIi11i / OOooOOo . I1IiiI / ooOoO0o + OoO0O00 + i11iIiiIii
 if 80 - 80: OoO0O00 . O0 / Ii1I % I1Ii111 / iII111i * I1IiiI
 if 41 - 41: O0 / OoooooooOO - i1IIi
 if 6 - 6: i1IIi - I1ii11iIi11i % I1Ii111 - II111iiii / ooOoO0o / i11iIiiIii
def lisp_is_myeid ( eid ) :
 for I11i111 in lisp_db_list :
  if ( eid . is_more_specific ( I11i111 . eid ) ) : return ( True )
  if 32 - 32: oO0o / IiII - I11i . ooOoO0o
 return ( False )
 if 69 - 69: i11iIiiIii * i11iIiiIii
 if 100 - 100: I1ii11iIi11i * I1ii11iIi11i + i1IIi
 if 96 - 96: I1Ii111 / I1IiiI + ooOoO0o
 if 16 - 16: I1ii11iIi11i % o0oOOo0O0Ooo % OOooOOo % OoOoOO00 + ooOoO0o % I1ii11iIi11i
 if 85 - 85: oO0o * OoooooooOO * iIii1I11I1II1 + iII111i
 if 67 - 67: Ii1I / i11iIiiIii % OoOoOO00 % O0 / OoOoOO00
 if 54 - 54: I11i . OoOoOO00 / II111iiii . i1IIi + OOooOOo % II111iiii
 if 82 - 82: i11iIiiIii . OoooooooOO % OoOoOO00 * O0 - I1Ii111
 if 78 - 78: OoOoOO00 % Ii1I % OOooOOo % Oo0Ooo % I11i . Ii1I
def lisp_format_macs ( sa , da ) :
 sa = sa [ 0 : 4 ] + "-" + sa [ 4 : 8 ] + "-" + sa [ 8 : 12 ]
 da = da [ 0 : 4 ] + "-" + da [ 4 : 8 ] + "-" + da [ 8 : 12 ]
 return ( "{} -> {}" . format ( sa , da ) )
 if 73 - 73: OoooooooOO / i1IIi . iIii1I11I1II1
 if 89 - 89: I1Ii111
 if 29 - 29: I11i * ooOoO0o - OoooooooOO
 if 92 - 92: O0 % i1IIi / OOooOOo - oO0o
 if 83 - 83: o0oOOo0O0Ooo . OoO0O00 % iIii1I11I1II1 % OoOoOO00 - i11iIiiIii
 if 71 - 71: I1ii11iIi11i - II111iiii / O0 % i1IIi + oO0o
 if 73 - 73: OoooooooOO
def lisp_get_echo_nonce ( rloc , rloc_str ) :
 if ( lisp_nonce_echoing == False ) : return ( None )
 if 25 - 25: i1IIi . II111iiii . I1Ii111
 if ( rloc ) : rloc_str = rloc . print_address_no_iid ( )
 O00o = None
 if ( lisp_nonce_echo_list . has_key ( rloc_str ) ) :
  O00o = lisp_nonce_echo_list [ rloc_str ]
  if 81 - 81: II111iiii + OoOoOO00 * II111iiii / iIii1I11I1II1 - Oo0Ooo % oO0o
 return ( O00o )
 if 66 - 66: ooOoO0o % O0 + iIii1I11I1II1 * I1Ii111 - I1Ii111
 if 61 - 61: I1ii11iIi11i
 if 12 - 12: OoO0O00
 if 97 - 97: OOooOOo . Oo0Ooo . oO0o * i1IIi
 if 7 - 7: Oo0Ooo
 if 38 - 38: Oo0Ooo - I1ii11iIi11i
 if 19 - 19: Ii1I * OoO0O00 / OoO0O00 . II111iiii % iIii1I11I1II1
 if 61 - 61: I1ii11iIi11i * oO0o % iII111i + IiII + i11iIiiIii * I11i
def lisp_decode_dist_name ( packet ) :
 I1I11Iiii111 = 0
 i1IiiiIi1i1 = ""
 if 73 - 73: OoO0O00 / iII111i
 while ( packet [ 0 : 1 ] != "\0" ) :
  if ( I1I11Iiii111 == 255 ) : return ( [ None , None ] )
  i1IiiiIi1i1 += packet [ 0 : 1 ]
  packet = packet [ 1 : : ]
  I1I11Iiii111 += 1
  if 40 - 40: I11i + IiII * Oo0Ooo . OoooooooOO * I1IiiI
  if 91 - 91: ooOoO0o / oO0o * OOooOOo . II111iiii - I11i - I11i
 packet = packet [ 1 : : ]
 return ( packet , i1IiiiIi1i1 )
 if 5 - 5: O0 + OoooooooOO + i11iIiiIii * Oo0Ooo * OoOoOO00 . oO0o
 if 6 - 6: OoO0O00 % Oo0Ooo % I1IiiI % o0oOOo0O0Ooo % O0 % Oo0Ooo
 if 94 - 94: I11i . i1IIi / II111iiii + OOooOOo
 if 64 - 64: I1IiiI % ooOoO0o
 if 72 - 72: O0 * II111iiii % OoO0O00 - I1IiiI * OOooOOo
 if 80 - 80: OOooOOo * I11i / OOooOOo - oO0o
 if 18 - 18: i1IIi - OOooOOo - o0oOOo0O0Ooo - iIii1I11I1II1
 if 72 - 72: OoooooooOO % I1IiiI . OoO0O00
def lisp_write_flow_log ( flow_log ) :
 Ii = open ( "./logs/lisp-flow.log" , "a" )
 if 28 - 28: II111iiii / iIii1I11I1II1 / iII111i - o0oOOo0O0Ooo . I1IiiI / O0
 I1I11Iiii111 = 0
 for o00oOo0OoO0oO in flow_log :
  i1II1IiiIi = o00oOo0OoO0oO [ 3 ]
  i1iIiII1iI1II = i1II1IiiIi . print_flow ( o00oOo0OoO0oO [ 0 ] , o00oOo0OoO0oO [ 1 ] , o00oOo0OoO0oO [ 2 ] )
  Ii . write ( i1iIiII1iI1II )
  I1I11Iiii111 += 1
  if 17 - 17: OoO0O00
 Ii . close ( )
 del ( flow_log )
 if 8 - 8: I11i . O0 / ooOoO0o
 I1I11Iiii111 = bold ( str ( I1I11Iiii111 ) , False )
 lprint ( "Wrote {} flow entries to ./logs/lisp-flow.log" . format ( I1I11Iiii111 ) )
 return
 if 1 - 1: IiII / OoO0O00 * oO0o - I1Ii111 . OoOoOO00
 if 85 - 85: i11iIiiIii + OoOoOO00
 if 4 - 4: OOooOOo . OoO0O00 * II111iiii + OoO0O00 % Oo0Ooo
 if 60 - 60: OOooOOo . Ii1I
 if 13 - 13: i1IIi . iII111i / OoOoOO00 . I1Ii111
 if 65 - 65: oO0o % I1Ii111 % OoO0O00 . iIii1I11I1II1
 if 38 - 38: IiII / I11i / IiII * iII111i
def lisp_policy_command ( kv_pair ) :
 i111 = lisp_policy ( "" )
 iiii1I11i = None
 if 65 - 65: OoOoOO00
 Iiii1Iiii1Ii1I1 = [ ]
 for Ii11 in range ( len ( kv_pair [ "datetime-range" ] ) ) :
  Iiii1Iiii1Ii1I1 . append ( lisp_policy_match ( ) )
  if 91 - 91: I11i % I1ii11iIi11i . I11i + IiII
  if 52 - 52: o0oOOo0O0Ooo
 for IIiI1iiIi in kv_pair . keys ( ) :
  oOO = kv_pair [ IIiI1iiIi ]
  if 75 - 75: IiII - OoOoOO00 / i1IIi + I1ii11iIi11i
  if 70 - 70: I1Ii111 - I1Ii111 / i1IIi * I1Ii111
  if 20 - 20: oO0o / i1IIi
  if 100 - 100: i11iIiiIii / o0oOOo0O0Ooo - I1IiiI / o0oOOo0O0Ooo / I1IiiI . II111iiii
  if ( IIiI1iiIi == "instance-id" ) :
   for Ii11 in range ( len ( Iiii1Iiii1Ii1I1 ) ) :
    O0o0 = oOO [ Ii11 ]
    if ( O0o0 == "" ) : continue
    I11111II = Iiii1Iiii1Ii1I1 [ Ii11 ]
    if ( I11111II . source_eid == None ) :
     I11111II . source_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
     if 40 - 40: I1IiiI + Ii1I . O0 . i1IIi - ooOoO0o . ooOoO0o
    if ( I11111II . dest_eid == None ) :
     I11111II . dest_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
     if 80 - 80: i11iIiiIii % I1Ii111 % I1IiiI / I1IiiI + oO0o + iII111i
    I11111II . source_eid . instance_id = int ( O0o0 )
    I11111II . dest_eid . instance_id = int ( O0o0 )
    if 18 - 18: OoO0O00 * ooOoO0o
    if 32 - 32: oO0o . OoooooooOO - o0oOOo0O0Ooo + II111iiii
  if ( IIiI1iiIi == "source-eid" ) :
   for Ii11 in range ( len ( Iiii1Iiii1Ii1I1 ) ) :
    O0o0 = oOO [ Ii11 ]
    if ( O0o0 == "" ) : continue
    I11111II = Iiii1Iiii1Ii1I1 [ Ii11 ]
    if ( I11111II . source_eid == None ) :
     I11111II . source_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
     if 4 - 4: OOooOOo * I1IiiI - I11i - I11i
    o0OOoOO = I11111II . source_eid . instance_id
    I11111II . source_eid . store_prefix ( O0o0 )
    I11111II . source_eid . instance_id = o0OOoOO
    if 67 - 67: I1IiiI
    if 32 - 32: oO0o * i11iIiiIii - I11i % Oo0Ooo * I1ii11iIi11i
  if ( IIiI1iiIi == "destination-eid" ) :
   for Ii11 in range ( len ( Iiii1Iiii1Ii1I1 ) ) :
    O0o0 = oOO [ Ii11 ]
    if ( O0o0 == "" ) : continue
    I11111II = Iiii1Iiii1Ii1I1 [ Ii11 ]
    if ( I11111II . dest_eid == None ) :
     I11111II . dest_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
     if 79 - 79: II111iiii / Oo0Ooo / I1ii11iIi11i
    o0OOoOO = I11111II . dest_eid . instance_id
    I11111II . dest_eid . store_prefix ( O0o0 )
    I11111II . dest_eid . instance_id = o0OOoOO
    if 30 - 30: I11i . o0oOOo0O0Ooo / II111iiii
    if 59 - 59: i11iIiiIii
  if ( IIiI1iiIi == "source-rloc" ) :
   for Ii11 in range ( len ( Iiii1Iiii1Ii1I1 ) ) :
    O0o0 = oOO [ Ii11 ]
    if ( O0o0 == "" ) : continue
    I11111II = Iiii1Iiii1Ii1I1 [ Ii11 ]
    I11111II . source_rloc = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
    I11111II . source_rloc . store_prefix ( O0o0 )
    if 5 - 5: i11iIiiIii + o0oOOo0O0Ooo . OoO0O00 % OoOoOO00 + I11i
    if 59 - 59: I1ii11iIi11i
  if ( IIiI1iiIi == "destination-rloc" ) :
   for Ii11 in range ( len ( Iiii1Iiii1Ii1I1 ) ) :
    O0o0 = oOO [ Ii11 ]
    if ( O0o0 == "" ) : continue
    I11111II = Iiii1Iiii1Ii1I1 [ Ii11 ]
    I11111II . dest_rloc = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
    I11111II . dest_rloc . store_prefix ( O0o0 )
    if 47 - 47: I1IiiI + Oo0Ooo
    if 78 - 78: i1IIi / I1ii11iIi11i % ooOoO0o * OoO0O00
  if ( IIiI1iiIi == "rloc-record-name" ) :
   for Ii11 in range ( len ( Iiii1Iiii1Ii1I1 ) ) :
    O0o0 = oOO [ Ii11 ]
    if ( O0o0 == "" ) : continue
    I11111II = Iiii1Iiii1Ii1I1 [ Ii11 ]
    I11111II . rloc_record_name = O0o0
    if 10 - 10: i1IIi % ooOoO0o / iII111i
    if 98 - 98: IiII / o0oOOo0O0Ooo - i1IIi - OOooOOo
  if ( IIiI1iiIi == "geo-name" ) :
   for Ii11 in range ( len ( Iiii1Iiii1Ii1I1 ) ) :
    O0o0 = oOO [ Ii11 ]
    if ( O0o0 == "" ) : continue
    I11111II = Iiii1Iiii1Ii1I1 [ Ii11 ]
    I11111II . geo_name = O0o0
    if 65 - 65: Ii1I + OoOoOO00 * Oo0Ooo . O0 . IiII
    if 33 - 33: i11iIiiIii . i1IIi . I1Ii111 - OoOoOO00 + OOooOOo
  if ( IIiI1iiIi == "elp-name" ) :
   for Ii11 in range ( len ( Iiii1Iiii1Ii1I1 ) ) :
    O0o0 = oOO [ Ii11 ]
    if ( O0o0 == "" ) : continue
    I11111II = Iiii1Iiii1Ii1I1 [ Ii11 ]
    I11111II . elp_name = O0o0
    if 34 - 34: I1ii11iIi11i . i1IIi * O0 / OoooooooOO
    if 22 - 22: OOooOOo % o0oOOo0O0Ooo - i11iIiiIii
  if ( IIiI1iiIi == "rle-name" ) :
   for Ii11 in range ( len ( Iiii1Iiii1Ii1I1 ) ) :
    O0o0 = oOO [ Ii11 ]
    if ( O0o0 == "" ) : continue
    I11111II = Iiii1Iiii1Ii1I1 [ Ii11 ]
    I11111II . rle_name = O0o0
    if 58 - 58: IiII . Ii1I + II111iiii
    if 31 - 31: i11iIiiIii + i11iIiiIii + I11i * Oo0Ooo . I11i
  if ( IIiI1iiIi == "json-name" ) :
   for Ii11 in range ( len ( Iiii1Iiii1Ii1I1 ) ) :
    O0o0 = oOO [ Ii11 ]
    if ( O0o0 == "" ) : continue
    I11111II = Iiii1Iiii1Ii1I1 [ Ii11 ]
    I11111II . json_name = O0o0
    if 28 - 28: OOooOOo * iIii1I11I1II1 * OoOoOO00
    if 75 - 75: Oo0Ooo % IiII + II111iiii + oO0o
  if ( IIiI1iiIi == "datetime-range" ) :
   for Ii11 in range ( len ( Iiii1Iiii1Ii1I1 ) ) :
    O0o0 = oOO [ Ii11 ]
    I11111II = Iiii1Iiii1Ii1I1 [ Ii11 ]
    if ( O0o0 == "" ) : continue
    I1i = lisp_datetime ( O0o0 [ 0 : 19 ] )
    O0O0OooOo0000O = lisp_datetime ( O0o0 [ 19 : : ] )
    if ( I1i . valid_datetime ( ) and O0O0OooOo0000O . valid_datetime ( ) ) :
     I11111II . datetime_lower = I1i
     I11111II . datetime_upper = O0O0OooOo0000O
     if 35 - 35: I1ii11iIi11i - oO0o - O0 / iII111i % IiII
     if 10 - 10: OOooOOo + oO0o - I1Ii111 . I1IiiI
     if 11 - 11: I1ii11iIi11i . I1Ii111 / o0oOOo0O0Ooo + IiII
     if 73 - 73: OoO0O00 . i11iIiiIii * OoO0O00 * i1IIi + I11i
     if 27 - 27: i11iIiiIii / OoOoOO00 % O0 / II111iiii . I11i - ooOoO0o
     if 54 - 54: oO0o * II111iiii
     if 79 - 79: o0oOOo0O0Ooo . ooOoO0o . Oo0Ooo * OoooooooOO
  if ( IIiI1iiIi == "set-action" ) :
   i111 . set_action = oOO
   if 98 - 98: ooOoO0o
  if ( IIiI1iiIi == "set-record-ttl" ) :
   i111 . set_record_ttl = int ( oOO )
   if 73 - 73: I1Ii111
  if ( IIiI1iiIi == "set-instance-id" ) :
   if ( i111 . set_source_eid == None ) :
    i111 . set_source_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
    if 97 - 97: OoO0O00 * Ii1I + Oo0Ooo
   if ( i111 . set_dest_eid == None ) :
    i111 . set_dest_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
    if 83 - 83: II111iiii - Oo0Ooo % II111iiii * o0oOOo0O0Ooo
   iiii1I11i = int ( oOO )
   i111 . set_source_eid . instance_id = iiii1I11i
   i111 . set_dest_eid . instance_id = iiii1I11i
   if 51 - 51: iII111i * iIii1I11I1II1 % Ii1I * Ii1I + i11iIiiIii . OoooooooOO
  if ( IIiI1iiIi == "set-source-eid" ) :
   if ( i111 . set_source_eid == None ) :
    i111 . set_source_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
    if 54 - 54: i11iIiiIii . iIii1I11I1II1 * iIii1I11I1II1 + Ii1I % I11i - OoO0O00
   i111 . set_source_eid . store_prefix ( oOO )
   if ( iiii1I11i != None ) : i111 . set_source_eid . instance_id = iiii1I11i
   if 16 - 16: IiII % iIii1I11I1II1 * i11iIiiIii + O0
  if ( IIiI1iiIi == "set-destination-eid" ) :
   if ( i111 . set_dest_eid == None ) :
    i111 . set_dest_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
    if 76 - 76: iII111i * OOooOOo
   i111 . set_dest_eid . store_prefix ( oOO )
   if ( iiii1I11i != None ) : i111 . set_dest_eid . instance_id = iiii1I11i
   if 7 - 7: ooOoO0o + o0oOOo0O0Ooo + o0oOOo0O0Ooo
  if ( IIiI1iiIi == "set-rloc-address" ) :
   i111 . set_rloc_address = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
   i111 . set_rloc_address . store_address ( oOO )
   if 73 - 73: IiII % I11i % i11iIiiIii + ooOoO0o
  if ( IIiI1iiIi == "set-rloc-record-name" ) :
   i111 . set_rloc_record_name = oOO
   if 83 - 83: Ii1I * I1Ii111 * i11iIiiIii / iIii1I11I1II1 % I1ii11iIi11i
  if ( IIiI1iiIi == "set-elp-name" ) :
   i111 . set_elp_name = oOO
   if 40 - 40: iII111i
  if ( IIiI1iiIi == "set-geo-name" ) :
   i111 . set_geo_name = oOO
   if 21 - 21: I1Ii111 / iII111i + Oo0Ooo / I1ii11iIi11i / I1Ii111
  if ( IIiI1iiIi == "set-rle-name" ) :
   i111 . set_rle_name = oOO
   if 33 - 33: OoooooooOO
  if ( IIiI1iiIi == "set-json-name" ) :
   i111 . set_json_name = oOO
   if 59 - 59: i11iIiiIii - OoooooooOO . ooOoO0o / i11iIiiIii % iIii1I11I1II1 * I1ii11iIi11i
  if ( IIiI1iiIi == "policy-name" ) :
   i111 . policy_name = oOO
   if 45 - 45: I1ii11iIi11i * I1ii11iIi11i
   if 31 - 31: OoO0O00 - OOooOOo . iII111i * I1Ii111 * iII111i + I1ii11iIi11i
   if 5 - 5: Oo0Ooo . I1Ii111
   if 77 - 77: i11iIiiIii / I1Ii111 / I1ii11iIi11i % oO0o
   if 83 - 83: Ii1I % iIii1I11I1II1 / I1ii11iIi11i + I11i
   if 23 - 23: iIii1I11I1II1 - I1IiiI
 i111 . match_clauses = Iiii1Iiii1Ii1I1
 i111 . save_policy ( )
 return
 if 51 - 51: OoooooooOO / IiII / I1ii11iIi11i . Oo0Ooo - o0oOOo0O0Ooo * OoooooooOO
 if 40 - 40: OoO0O00 / IiII . O0 / I1IiiI + OoO0O00 . o0oOOo0O0Ooo
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
if 25 - 25: ooOoO0o * I1Ii111 * oO0o
if 64 - 64: Ii1I / I1ii11iIi11i
if 30 - 30: OoooooooOO + O0 / I1ii11iIi11i * o0oOOo0O0Ooo
if 11 - 11: O0 + OoO0O00 - Oo0Ooo - Oo0Ooo . i11iIiiIii
if 15 - 15: Ii1I % i11iIiiIii / OoOoOO00
if 85 - 85: ooOoO0o . i1IIi / iII111i % iIii1I11I1II1 / II111iiii / I1Ii111
if 60 - 60: iIii1I11I1II1 - iIii1I11I1II1 . I11i
def lisp_send_to_arista ( command , interface ) :
 interface = "" if ( interface == None ) else "interface " + interface
 if 55 - 55: OoO0O00
 O0o0OoOO = command
 if ( interface != "" ) : O0o0OoOO = interface + ": " + O0o0OoOO
 lprint ( "Send CLI command '{}' to hardware" . format ( O0o0OoOO ) )
 if 68 - 68: Ii1I
 commands = '''
        enable
        configure
        {}
        {}
    ''' . format ( interface , command )
 if 47 - 47: iII111i * I1Ii111 % o0oOOo0O0Ooo / OoOoOO00 / OoO0O00 % OoO0O00
 os . system ( "FastCli -c '{}'" . format ( commands ) )
 return
 if 43 - 43: Oo0Ooo
 if 34 - 34: OoO0O00 . i1IIi + IiII * IiII
 if 76 - 76: OOooOOo
 if 54 - 54: O0 * II111iiii * OOooOOo
 if 44 - 44: I1IiiI
 if 66 - 66: o0oOOo0O0Ooo
 if 40 - 40: OOooOOo * Ii1I
def lisp_arista_is_alive ( prefix ) :
 o00OoOO0O0 = "enable\nsh plat trident l3 software routes {}\n" . format ( prefix )
 Oo0O = commands . getoutput ( "FastCli -c '{}'" . format ( o00OoOO0O0 ) )
 if 38 - 38: ooOoO0o
 if 5 - 5: OoooooooOO + iII111i - I11i
 if 95 - 95: OOooOOo / i11iIiiIii - Ii1I + I1ii11iIi11i
 if 7 - 7: I1ii11iIi11i
 Oo0O = Oo0O . split ( "\n" ) [ 1 ]
 iiiOOO0O = Oo0O . split ( " " )
 iiiOOO0O = iiiOOO0O [ - 1 ] . replace ( "\r" , "" )
 if 21 - 21: Ii1I % Oo0Ooo . iII111i . O0 + iIii1I11I1II1
 if 42 - 42: oO0o . OOooOOo * OoO0O00
 if 88 - 88: I1ii11iIi11i
 if 21 - 21: i1IIi . I1IiiI / OoooooooOO % oO0o
 return ( iiiOOO0O == "Y" )
 if 31 - 31: O0
 if 37 - 37: Oo0Ooo . OoOoOO00 % I1ii11iIi11i * O0
 if 20 - 20: ooOoO0o + I1IiiI - IiII % ooOoO0o - IiII . oO0o
 if 39 - 39: O0 / oO0o % oO0o * iIii1I11I1II1
 if 7 - 7: iII111i % o0oOOo0O0Ooo / II111iiii % IiII / iIii1I11I1II1
 if 17 - 17: I11i * I11i - O0 / IiII + OoOoOO00
 if 65 - 65: I1Ii111 * i1IIi
 if 10 - 10: OOooOOo % IiII
 if 20 - 20: I11i / OoooooooOO % OoOoOO00 . oO0o * I1IiiI % IiII
 if 84 - 84: I1ii11iIi11i % I11i / OOooOOo % O0
 if 63 - 63: Ii1I / I1ii11iIi11i / Oo0Ooo
 if 74 - 74: i1IIi
 if 38 - 38: II111iiii * i1IIi
 if 43 - 43: O0 - OOooOOo / I1IiiI * II111iiii . OoooooooOO / OoOoOO00
 if 77 - 77: OoOoOO00
 if 10 - 10: IiII / i11iIiiIii
 if 19 - 19: OoO0O00
 if 100 - 100: I1ii11iIi11i - I1ii11iIi11i
 if 38 - 38: I1Ii111
 if 23 - 23: Ii1I . I1ii11iIi11i + I1Ii111 + i1IIi * o0oOOo0O0Ooo - i11iIiiIii
 if 92 - 92: I1Ii111 - I1IiiI + Ii1I / iII111i % OOooOOo
 if 32 - 32: i1IIi . iII111i - Ii1I % iII111i % II111iiii - oO0o
 if 36 - 36: OoooooooOO * OoooooooOO . ooOoO0o . O0
 if 5 - 5: I11i % I1IiiI - OoO0O00 . Oo0Ooo
 if 79 - 79: iII111i + IiII % I11i . Oo0Ooo / IiII * iII111i
 if 40 - 40: iII111i - I1IiiI + OoOoOO00
 if 2 - 2: I11i - II111iiii / I1Ii111
 if 27 - 27: OoO0O00 - I1ii11iIi11i * i11iIiiIii + Oo0Ooo
 if 29 - 29: I1ii11iIi11i / IiII . I1Ii111 + Ii1I + OoO0O00
 if 76 - 76: ooOoO0o . I11i * OoO0O00
 if 53 - 53: II111iiii / OoOoOO00 / IiII * oO0o
 if 52 - 52: O0 % iII111i * iIii1I11I1II1 / I11i / I1IiiI * ooOoO0o
 if 93 - 93: iIii1I11I1II1 . II111iiii * OOooOOo - iIii1I11I1II1 . oO0o % Oo0Ooo
 if 92 - 92: OoO0O00
 if 42 - 42: I1ii11iIi11i - iIii1I11I1II1 % ooOoO0o
 if 7 - 7: Oo0Ooo / ooOoO0o + o0oOOo0O0Ooo
 if 38 - 38: o0oOOo0O0Ooo . O0 - OoO0O00 % I11i
 if 80 - 80: o0oOOo0O0Ooo
 if 100 - 100: iIii1I11I1II1 . OoOoOO00 . OoooooooOO / I1ii11iIi11i - I1IiiI * I11i
 if 5 - 5: i1IIi * o0oOOo0O0Ooo - I1Ii111 + I1IiiI - II111iiii
 if 15 - 15: I1Ii111
 if 38 - 38: O0
 if 50 - 50: i11iIiiIii * OoO0O00 + iII111i / O0 * oO0o % ooOoO0o
 if 6 - 6: OoO0O00 . o0oOOo0O0Ooo / Ii1I + Ii1I
def lisp_program_vxlan_hardware ( mc ) :
 if 59 - 59: II111iiii - o0oOOo0O0Ooo * OoooooooOO
 if 83 - 83: oO0o . iIii1I11I1II1 . iII111i % Oo0Ooo
 if 48 - 48: oO0o % OoO0O00 - OoooooooOO . IiII
 if 11 - 11: I1Ii111 % o0oOOo0O0Ooo - o0oOOo0O0Ooo % OoooooooOO . o0oOOo0O0Ooo - I1ii11iIi11i
 if 33 - 33: OoO0O00 + II111iiii . Oo0Ooo * I1Ii111
 if 63 - 63: OoooooooOO + OoOoOO00 - OoooooooOO
 if ( os . path . exists ( "/persist/local/lispers.net" ) == False ) : return
 if 54 - 54: OoO0O00 + I1IiiI % O0 + OoO0O00
 if 37 - 37: II111iiii / I1ii11iIi11i * I1IiiI - OoooooooOO
 if 55 - 55: IiII / ooOoO0o * I1IiiI / I1Ii111 - Oo0Ooo % o0oOOo0O0Ooo
 if 82 - 82: OoO0O00 - iIii1I11I1II1 . Oo0Ooo / IiII . OoO0O00
 if ( len ( mc . best_rloc_set ) == 0 ) : return
 if 47 - 47: OOooOOo + IiII
 if 11 - 11: Oo0Ooo + I1IiiI % i11iIiiIii % Oo0Ooo + ooOoO0o + i1IIi
 if 100 - 100: II111iiii - OOooOOo + iII111i - i11iIiiIii . O0 / iII111i
 if 64 - 64: Ii1I
 oO0OO = mc . eid . print_prefix_no_iid ( )
 oOOoo0O00 = mc . best_rloc_set [ 0 ] . rloc . print_address_no_iid ( )
 if 4 - 4: OoOoOO00
 if 78 - 78: i1IIi - iII111i + O0 - I1IiiI % o0oOOo0O0Ooo
 if 48 - 48: iII111i / II111iiii * I1Ii111 + I11i / ooOoO0o . OoOoOO00
 if 45 - 45: OOooOOo / Ii1I % O0
 IIIiIi1iI1i1 = commands . getoutput ( "ip route get {} | egrep vlan4094" . format ( oO0OO ) )
 if 40 - 40: I1Ii111
 if ( IIIiIi1iI1i1 != "" ) :
  lprint ( "Route {} already in hardware: '{}'" . format ( green ( oO0OO , False ) , IIIiIi1iI1i1 ) )
  if 88 - 88: i11iIiiIii * O0 . i11iIiiIii . o0oOOo0O0Ooo . OoooooooOO
  return
  if 94 - 94: ooOoO0o / oO0o . iII111i % IiII - I11i
  if 61 - 61: OoooooooOO % OoO0O00 . OoO0O00 - I11i
  if 35 - 35: oO0o . Ii1I
  if 71 - 71: iIii1I11I1II1 / I1ii11iIi11i + OoooooooOO . ooOoO0o
  if 63 - 63: i11iIiiIii % I1Ii111 % IiII * i1IIi + I1Ii111 + I1Ii111
  if 51 - 51: iII111i / Ii1I . iII111i + O0 / IiII + OoooooooOO
  if 29 - 29: I1IiiI - OOooOOo
 OOoOO0O0OoOo = commands . getoutput ( "ifconfig | egrep 'vxlan|vlan4094'" )
 if ( OOoOO0O0OoOo . find ( "vxlan" ) == - 1 ) :
  lprint ( "No VXLAN interface found, cannot program hardware" )
  return
  if 85 - 85: O0 * OOooOOo % I1Ii111
 if ( OOoOO0O0OoOo . find ( "vlan4094" ) == - 1 ) :
  lprint ( "No vlan4094 interface found, cannot program hardware" )
  return
  if 33 - 33: O0
 IiiIIIiIIIii1II = commands . getoutput ( "ip addr | egrep vlan4094 | egrep inet" )
 if ( IiiIIIiIIIii1II == "" ) :
  lprint ( "No IP address found on vlan4094, cannot program hardware" )
  return
  if 33 - 33: OoO0O00
 IiiIIIiIIIii1II = IiiIIIiIIIii1II . split ( "inet " ) [ 1 ]
 IiiIIIiIIIii1II = IiiIIIiIIIii1II . split ( "/" ) [ 0 ]
 if 10 - 10: oO0o
 if 75 - 75: II111iiii % OOooOOo / iIii1I11I1II1 / OoO0O00 + oO0o
 if 16 - 16: oO0o + I1Ii111 - II111iiii - o0oOOo0O0Ooo / i11iIiiIii
 if 59 - 59: OOooOOo - o0oOOo0O0Ooo
 if 82 - 82: IiII % ooOoO0o - OoO0O00 % ooOoO0o
 if 51 - 51: ooOoO0o % iII111i . o0oOOo0O0Ooo . o0oOOo0O0Ooo
 if 20 - 20: i1IIi - ooOoO0o % OoooooooOO * I1ii11iIi11i + II111iiii % i1IIi
 IiIiII1iI = [ ]
 I11I1I1 = commands . getoutput ( "arp -i vlan4094" ) . split ( "\n" )
 for oooOo in I11I1I1 :
  if ( oooOo . find ( "vlan4094" ) == - 1 ) : continue
  if ( oooOo . find ( "(incomplete)" ) == - 1 ) : continue
  o00ooO0Ooo = oooOo . split ( " " ) [ 0 ]
  IiIiII1iI . append ( o00ooO0Ooo )
  if 91 - 91: OoOoOO00 . OoooooooOO . ooOoO0o + Oo0Ooo * OoOoOO00 * I1ii11iIi11i
  if 7 - 7: i1IIi . I1ii11iIi11i / iII111i . ooOoO0o / I11i - i1IIi
 o00ooO0Ooo = None
 iiiii1i11IIii = IiiIIIiIIIii1II
 IiiIIIiIIIii1II = IiiIIIiIIIii1II . split ( "." )
 for Ii11 in range ( 1 , 255 ) :
  IiiIIIiIIIii1II [ 3 ] = str ( Ii11 )
  o0o0O00 = "." . join ( IiiIIIiIIIii1II )
  if ( o0o0O00 in IiIiII1iI ) : continue
  if ( o0o0O00 == iiiii1i11IIii ) : continue
  o00ooO0Ooo = o0o0O00
  break
  if 36 - 36: Ii1I / OoooooooOO - I1IiiI
 if ( o00ooO0Ooo == None ) :
  lprint ( "Address allocation failed for vlan4094, cannot program " + "hardware" )
  if 71 - 71: I1ii11iIi11i - O0
  return
  if 83 - 83: Oo0Ooo + I11i
  if 23 - 23: o0oOOo0O0Ooo + i11iIiiIii . I1IiiI + iIii1I11I1II1
  if 18 - 18: o0oOOo0O0Ooo . O0 + I1Ii111
  if 66 - 66: OoooooooOO
  if 90 - 90: IiII - OoOoOO00
  if 98 - 98: Oo0Ooo / oO0o . Ii1I
  if 56 - 56: ooOoO0o % OoO0O00 * i11iIiiIii % IiII % I1IiiI - oO0o
 i1i1II1i = oOOoo0O00 . split ( "." )
 ooOO0o00 = lisp_hex_string ( i1i1II1i [ 1 ] ) . zfill ( 2 )
 iIII11III = lisp_hex_string ( i1i1II1i [ 2 ] ) . zfill ( 2 )
 iiIi1IIiIi11I = lisp_hex_string ( i1i1II1i [ 3 ] ) . zfill ( 2 )
 II11iI1iiI = "00:00:00:{}:{}:{}" . format ( ooOO0o00 , iIII11III , iiIi1IIiIi11I )
 I11O0o0 = "0000.00{}.{}{}" . format ( ooOO0o00 , iIII11III , iiIi1IIiIi11I )
 IiOOo00O = "arp -i vlan4094 -s {} {}" . format ( o00ooO0Ooo , II11iI1iiI )
 os . system ( IiOOo00O )
 if 20 - 20: Oo0Ooo % IiII - I1Ii111 - I1IiiI - I11i * oO0o
 if 43 - 43: iII111i . I1Ii111 . OOooOOo
 if 89 - 89: OoOoOO00 % O0
 if 7 - 7: O0 % oO0o
 oo0O0Oo0 = ( "mac address-table static {} vlan 4094 " + "interface vxlan 1 vtep {}" ) . format ( I11O0o0 , oOOoo0O00 )
 if 96 - 96: OoO0O00
 lisp_send_to_arista ( oo0O0Oo0 , None )
 if 69 - 69: IiII
 if 46 - 46: I1Ii111 + OoO0O00 * OOooOOo / Ii1I
 if 92 - 92: OoOoOO00
 if 24 - 24: oO0o % I1Ii111 % o0oOOo0O0Ooo . I1ii11iIi11i
 if 32 - 32: I11i
 Ooii1 = "ip route add {} via {}" . format ( oO0OO , o00ooO0Ooo )
 os . system ( Ooii1 )
 if 36 - 36: ooOoO0o * II111iiii * OoO0O00
 lprint ( "Hardware programmed with commands:" )
 Ooii1 = Ooii1 . replace ( oO0OO , green ( oO0OO , False ) )
 lprint ( "  " + Ooii1 )
 lprint ( "  " + IiOOo00O )
 oo0O0Oo0 = oo0O0Oo0 . replace ( oOOoo0O00 , red ( oOOoo0O00 , False ) )
 lprint ( "  " + oo0O0Oo0 )
 return
 if 50 - 50: i11iIiiIii / OOooOOo + I1ii11iIi11i
 if 24 - 24: II111iiii
 if 15 - 15: o0oOOo0O0Ooo . I11i
 if 100 - 100: I1IiiI
 if 58 - 58: iII111i % IiII
 if 90 - 90: ooOoO0o + II111iiii + I1IiiI / OoooooooOO . o0oOOo0O0Ooo
 if 3 - 3: i11iIiiIii . I1ii11iIi11i
def lisp_clear_hardware_walk ( mc , parms ) :
 OOoOOoo = mc . eid . print_prefix_no_iid ( )
 os . system ( "ip route delete {}" . format ( OOoOOoo ) )
 return ( [ True , None ] )
 if 65 - 65: II111iiii * iII111i - OoO0O00 + oO0o % OoO0O00
 if 83 - 83: OoooooooOO % I1ii11iIi11i . IiII + OOooOOo . iII111i - ooOoO0o
 if 100 - 100: o0oOOo0O0Ooo
 if 95 - 95: iII111i * oO0o * i1IIi
 if 100 - 100: iII111i . o0oOOo0O0Ooo - I1Ii111 % oO0o
 if 11 - 11: o0oOOo0O0Ooo . OoooooooOO - i1IIi
 if 71 - 71: I1IiiI . OOooOOo . I1ii11iIi11i
 if 90 - 90: i11iIiiIii + I1Ii111 % II111iiii
def lisp_clear_map_cache ( ) :
 global lisp_map_cache , lisp_rloc_probe_list
 global lisp_crypto_keys_by_rloc_encap , lisp_crypto_keys_by_rloc_decap
 global lisp_rtr_list
 if 67 - 67: OoOoOO00 / iII111i * OoO0O00 % i11iIiiIii
 o0O0o0o = bold ( "User cleared" , False )
 I1I11Iiii111 = lisp_map_cache . cache_count
 lprint ( "{} map-cache with {} entries" . format ( o0O0o0o , I1I11Iiii111 ) )
 if 74 - 74: Oo0Ooo / oO0o + IiII * IiII % iII111i / iIii1I11I1II1
 if ( lisp_program_hardware ) :
  lisp_map_cache . walk_cache ( lisp_clear_hardware_walk , None )
  if 15 - 15: Ii1I
 lisp_map_cache = lisp_cache ( )
 if 50 - 50: II111iiii * O0 / I1IiiI
 if 11 - 11: I1IiiI
 if 92 - 92: iIii1I11I1II1 - I11i - OOooOOo / Ii1I . o0oOOo0O0Ooo . OoO0O00
 if 33 - 33: oO0o / I11i % ooOoO0o * I11i / oO0o - OoOoOO00
 if 89 - 89: iIii1I11I1II1 . II111iiii + IiII
 lisp_rloc_probe_list = { }
 if 8 - 8: I1ii11iIi11i / II111iiii / II111iiii
 if 62 - 62: I11i - iII111i . Ii1I
 if 20 - 20: I1ii11iIi11i
 if 99 - 99: o0oOOo0O0Ooo + I1ii11iIi11i * IiII
 lisp_crypto_keys_by_rloc_encap = { }
 lisp_crypto_keys_by_rloc_decap = { }
 if 67 - 67: I1IiiI
 if 93 - 93: ooOoO0o . Ii1I + IiII / Oo0Ooo % I11i
 if 40 - 40: Oo0Ooo % OoOoOO00 . IiII / I1IiiI % OoooooooOO
 if 33 - 33: OOooOOo - OoooooooOO . iII111i
 if 2 - 2: I11i + i1IIi
 lisp_rtr_list = { }
 if 52 - 52: I11i - OoO0O00 % I1Ii111 . OOooOOo
 if 90 - 90: O0 - Oo0Ooo / i1IIi * iIii1I11I1II1 % o0oOOo0O0Ooo / oO0o
 if 73 - 73: iII111i % iIii1I11I1II1 + o0oOOo0O0Ooo % Ii1I . II111iiii + IiII
 if 55 - 55: OoOoOO00 * II111iiii / iII111i + OOooOOo / OoooooooOO
 lisp_process_data_plane_restart ( True )
 return
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
def lisp_encapsulate_rloc_probe ( lisp_sockets , rloc , nat_info , packet ) :
 if ( len ( lisp_sockets ) != 4 ) : return
 if 91 - 91: I11i
 I1Ii11 = lisp_myrlocs [ 0 ]
 if 15 - 15: i1IIi / O0 . i11iIiiIii
 if 51 - 51: IiII
 if 53 - 53: O0
 if 19 - 19: o0oOOo0O0Ooo / iII111i % OoOoOO00
 if 65 - 65: o0oOOo0O0Ooo
 o00OOo00 = len ( packet ) + 28
 i1I1i1i = struct . pack ( "BBHIBBHII" , 0x45 , 0 , socket . htons ( o00OOo00 ) , 0 , 64 ,
 17 , 0 , socket . htonl ( I1Ii11 . address ) , socket . htonl ( rloc . address ) )
 i1I1i1i = lisp_ip_checksum ( i1I1i1i )
 if 89 - 89: iIii1I11I1II1 + OoooooooOO + i1IIi + OoooooooOO % IiII * OoO0O00
 I1iIIIiI = struct . pack ( "HHHH" , 0 , socket . htons ( LISP_CTRL_PORT ) ,
 socket . htons ( o00OOo00 - 20 ) , 0 )
 if 53 - 53: OOooOOo . IiII % I11i - OoO0O00 - Oo0Ooo
 if 58 - 58: I1Ii111 / OoooooooOO . I11i % I1Ii111
 if 8 - 8: Oo0Ooo % ooOoO0o / i11iIiiIii
 if 54 - 54: IiII
 packet = lisp_packet ( i1I1i1i + I1iIIIiI + packet )
 if 85 - 85: OOooOOo - i1IIi
 if 10 - 10: I1ii11iIi11i
 if 3 - 3: ooOoO0o * O0 / o0oOOo0O0Ooo
 if 22 - 22: OoOoOO00 + OOooOOo . iII111i % iIii1I11I1II1 - I11i
 packet . inner_dest . copy_address ( rloc )
 packet . inner_dest . instance_id = 0xffffff
 packet . inner_source . copy_address ( I1Ii11 )
 packet . inner_ttl = 64
 packet . outer_dest . copy_address ( rloc )
 packet . outer_source . copy_address ( I1Ii11 )
 packet . outer_version = packet . outer_dest . afi_to_version ( )
 packet . outer_ttl = 64
 packet . encap_port = nat_info . port if nat_info else LISP_DATA_PORT
 if 23 - 23: OoOoOO00 * I1Ii111
 oooOOoo0 = red ( rloc . print_address_no_iid ( ) , False )
 if ( nat_info ) :
  O0oO0Oooo = " {}" . format ( blue ( nat_info . hostname , False ) )
  iI11iI11i11ii = bold ( "RLOC-probe request" , False )
 else :
  O0oO0Oooo = ""
  iI11iI11i11ii = bold ( "RLOC-probe reply" , False )
  if 18 - 18: o0oOOo0O0Ooo % i11iIiiIii . Ii1I . O0
  if 85 - 85: I1ii11iIi11i * iIii1I11I1II1 + o0oOOo0O0Ooo * OoO0O00
 lprint ( ( "Data encapsulate {} to {}{} port {} for " + "NAT-traversal" ) . format ( iI11iI11i11ii , oooOOoo0 , O0oO0Oooo , packet . encap_port ) )
 if 25 - 25: o0oOOo0O0Ooo / Ii1I / Oo0Ooo . ooOoO0o - ooOoO0o * O0
 if 14 - 14: O0 - Ii1I + iIii1I11I1II1 + II111iiii . ooOoO0o + Ii1I
 if 25 - 25: OoO0O00 * oO0o
 if 29 - 29: OOooOOo - I1Ii111 - i11iIiiIii % i1IIi
 if 2 - 2: i11iIiiIii % iIii1I11I1II1 * OOooOOo
 if ( packet . encode ( None ) == None ) : return
 packet . print_packet ( "Send" , True )
 if 45 - 45: oO0o + i1IIi + iII111i + o0oOOo0O0Ooo * OOooOOo + ooOoO0o
 OOo00oOoo = lisp_sockets [ 3 ]
 packet . send_packet ( OOo00oOoo , packet . outer_dest )
 del ( packet )
 return
 if 73 - 73: Oo0Ooo + II111iiii - IiII
 if 60 - 60: i1IIi . i11iIiiIii / i1IIi . I11i % OOooOOo
 if 47 - 47: oO0o + IiII * I1Ii111 % o0oOOo0O0Ooo - O0 % IiII
 if 66 - 66: II111iiii * I1IiiI . Oo0Ooo * OoooooooOO % OoOoOO00 . II111iiii
 if 4 - 4: iII111i + I1Ii111 % OoOoOO00 / Ii1I
 if 94 - 94: OoO0O00
 if 35 - 35: I1ii11iIi11i % OoO0O00 + II111iiii % II111iiii / IiII - iII111i
 if 9 - 9: I1ii11iIi11i * o0oOOo0O0Ooo . oO0o
def lisp_get_default_route_next_hops ( ) :
 if 48 - 48: IiII . I1Ii111 + OoooooooOO - I1Ii111 . Ii1I . I1Ii111
 if 24 - 24: ooOoO0o * iIii1I11I1II1
 if 1 - 1: I1ii11iIi11i . O0
 if 3 - 3: iIii1I11I1II1 * ooOoO0o - OoOoOO00 * I1ii11iIi11i % OoOoOO00 - OoooooooOO
 if ( lisp_is_macos ( ) ) :
  o00OoOO0O0 = "route -n get default"
  i1i11i1i = commands . getoutput ( o00OoOO0O0 ) . split ( "\n" )
  ooOiiIiI1I = I111IIiIII = None
  for Ii in i1i11i1i :
   if ( Ii . find ( "gateway: " ) != - 1 ) : ooOiiIiI1I = Ii . split ( ": " ) [ 1 ]
   if ( Ii . find ( "interface: " ) != - 1 ) : I111IIiIII = Ii . split ( ": " ) [ 1 ]
   if 52 - 52: OOooOOo / oO0o - I1ii11iIi11i * OoooooooOO * OoO0O00
  return ( [ [ I111IIiIII , ooOiiIiI1I ] ] )
  if 71 - 71: iII111i % i11iIiiIii * OoooooooOO * iII111i
  if 92 - 92: I11i % iIii1I11I1II1 * iII111i - OoooooooOO - I11i
  if 34 - 34: I1Ii111 / i1IIi / O0 / OoooooooOO
  if 55 - 55: I1Ii111 . I1IiiI * iIii1I11I1II1 / Ii1I . I1IiiI
  if 63 - 63: ooOoO0o . Ii1I - I1Ii111 - oO0o * I1Ii111 + ooOoO0o
 o00OoOO0O0 = "ip route | egrep 'default via'"
 I1III = commands . getoutput ( o00OoOO0O0 ) . split ( "\n" )
 if 85 - 85: II111iiii + I1ii11iIi11i
 oOo0OO00oo0 = [ ]
 for IIIiIi1iI1i1 in I1III :
  if ( IIIiIi1iI1i1 . find ( " metric " ) != - 1 ) : continue
  O00oo00o000o = IIIiIi1iI1i1 . split ( " " )
  try :
   iiI1iiIi111i = O00oo00o000o . index ( "via" ) + 1
   if ( iiI1iiIi111i >= len ( O00oo00o000o ) ) : continue
   o0OOo0o0oO = O00oo00o000o . index ( "dev" ) + 1
   if ( o0OOo0o0oO >= len ( O00oo00o000o ) ) : continue
  except :
   continue
   if 6 - 6: OOooOOo
   if 21 - 21: I1Ii111 - Ii1I - i1IIi % oO0o
  oOo0OO00oo0 . append ( [ O00oo00o000o [ o0OOo0o0oO ] , O00oo00o000o [ iiI1iiIi111i ] ] )
  if 55 - 55: OOooOOo + oO0o - II111iiii
 return ( oOo0OO00oo0 )
 if 5 - 5: iII111i * OoooooooOO . OoO0O00 % ooOoO0o + Ii1I
 if 59 - 59: OoOoOO00
 if 96 - 96: I1IiiI
 if 3 - 3: OoooooooOO
 if 3 - 3: IiII / O0 * i11iIiiIii . iII111i - iIii1I11I1II1
 if 56 - 56: ooOoO0o
 if 82 - 82: ooOoO0o . IiII . I1Ii111 - iIii1I11I1II1 + II111iiii . OoOoOO00
def lisp_get_host_route_next_hop ( rloc ) :
 o00OoOO0O0 = "ip route | egrep '{} via'" . format ( rloc )
 IIIiIi1iI1i1 = commands . getoutput ( o00OoOO0O0 ) . split ( " " )
 if 59 - 59: Oo0Ooo
 try : iI11I = IIIiIi1iI1i1 . index ( "via" ) + 1
 except : return ( None )
 if 98 - 98: I1Ii111 * II111iiii / Oo0Ooo . Oo0Ooo % I1Ii111
 if ( iI11I >= len ( IIIiIi1iI1i1 ) ) : return ( None )
 return ( IIIiIi1iI1i1 [ iI11I ] )
 if 52 - 52: OoOoOO00
 if 59 - 59: ooOoO0o / OoooooooOO
 if 71 - 71: OOooOOo + I11i * O0 / o0oOOo0O0Ooo + I1IiiI + Ii1I
 if 41 - 41: ooOoO0o * I1Ii111
 if 40 - 40: OoOoOO00
 if 60 - 60: IiII . i11iIiiIii * II111iiii . Ii1I
 if 10 - 10: O0
def lisp_install_host_route ( dest , nh , install ) :
 install = "add" if install else "delete"
 IIiii1IiiIiii = "none" if nh == None else nh
 if 65 - 65: I11i % i11iIiiIii + i11iIiiIii % II111iiii
 lprint ( "{} host-route {}, nh {}" . format ( install . title ( ) , dest , IIiii1IiiIiii ) )
 if 95 - 95: I1Ii111 - I11i . II111iiii . i1IIi / II111iiii + Oo0Ooo
 if ( nh == None ) :
  I1I11i1Iiii11 = "ip route {} {}/32" . format ( install , dest )
 else :
  I1I11i1Iiii11 = "ip route {} {}/32 via {}" . format ( install , dest , nh )
  if 96 - 96: iIii1I11I1II1 * iII111i / OOooOOo * iIii1I11I1II1 - O0
 os . system ( I1I11i1Iiii11 )
 return
 if 28 - 28: I11i / I1IiiI - I1Ii111 + I1ii11iIi11i % iIii1I11I1II1
 if 35 - 35: iIii1I11I1II1 % Oo0Ooo % iII111i / iIii1I11I1II1 - I1ii11iIi11i . Oo0Ooo
 if 81 - 81: II111iiii + oO0o
 if 67 - 67: ooOoO0o + I11i - I1ii11iIi11i - OoooooooOO
 if 37 - 37: I11i % I1IiiI
 if 32 - 32: OOooOOo + OoooooooOO . IiII . Oo0Ooo * iII111i
 if 86 - 86: I1ii11iIi11i . iII111i + Ii1I - IiII / i11iIiiIii + OoOoOO00
 if 50 - 50: o0oOOo0O0Ooo - IiII + OoOoOO00 - II111iiii
def lisp_checkpoint ( checkpoint_list ) :
 if ( lisp_checkpoint_map_cache == False ) : return
 if 24 - 24: I1Ii111 - IiII % I1IiiI - OoooooooOO % Ii1I
 Ii = open ( lisp_checkpoint_filename , "w" )
 for iIIiI11iI1Ii1 in checkpoint_list :
  Ii . write ( iIIiI11iI1Ii1 + "\n" )
  if 56 - 56: I1ii11iIi11i
 Ii . close ( )
 lprint ( "{} {} entries to file '{}'" . format ( bold ( "Checkpoint" , False ) ,
 len ( checkpoint_list ) , lisp_checkpoint_filename ) )
 return
 if 40 - 40: OoooooooOO
 if 100 - 100: IiII - I11i
 if 79 - 79: iII111i % O0
 if 73 - 73: Oo0Ooo
 if 13 - 13: OOooOOo - ooOoO0o
 if 8 - 8: I1Ii111 % oO0o
 if 19 - 19: O0 + OoO0O00 - i1IIi % OoOoOO00 / Oo0Ooo + OoooooooOO
 if 93 - 93: i11iIiiIii % OOooOOo . I11i * ooOoO0o
def lisp_load_checkpoint ( ) :
 if ( lisp_checkpoint_map_cache == False ) : return
 if ( os . path . exists ( lisp_checkpoint_filename ) == False ) : return
 if 90 - 90: OoO0O00
 Ii = open ( lisp_checkpoint_filename , "r" )
 if 54 - 54: OOooOOo + Oo0Ooo * o0oOOo0O0Ooo - iIii1I11I1II1 * ooOoO0o
 I1I11Iiii111 = 0
 for iIIiI11iI1Ii1 in Ii :
  I1I11Iiii111 += 1
  ooo0OO = iIIiI11iI1Ii1 . split ( " rloc " )
  Ii11iiI = [ ] if ( ooo0OO [ 1 ] in [ "native-forward\n" , "\n" ] ) else ooo0OO [ 1 ] . split ( ", " )
  if 76 - 76: i11iIiiIii * I1IiiI - IiII . o0oOOo0O0Ooo % iII111i . i11iIiiIii
  if 69 - 69: O0 + o0oOOo0O0Ooo / ooOoO0o
  iii1Ii1i1i1I = [ ]
  for oOOoo0O00 in Ii11iiI :
   IIiO0Ooo = lisp_rloc ( False )
   O00oo00o000o = oOOoo0O00 . split ( " " )
   IIiO0Ooo . rloc . store_address ( O00oo00o000o [ 0 ] )
   IIiO0Ooo . priority = int ( O00oo00o000o [ 1 ] )
   IIiO0Ooo . weight = int ( O00oo00o000o [ 2 ] )
   iii1Ii1i1i1I . append ( IIiO0Ooo )
   if 7 - 7: Ii1I . Ii1I . iIii1I11I1II1 / ooOoO0o
   if 70 - 70: O0
  Iii1 = lisp_mapping ( "" , "" , iii1Ii1i1i1I )
  if ( Iii1 != None ) :
   Iii1 . eid . store_prefix ( ooo0OO [ 0 ] )
   Iii1 . checkpoint_entry = True
   Iii1 . map_cache_ttl = LISP_NMR_TTL * 60
   if ( iii1Ii1i1i1I == [ ] ) : Iii1 . action = LISP_NATIVE_FORWARD_ACTION
   Iii1 . add_cache ( )
   continue
   if 42 - 42: I1Ii111 + OoooooooOO + I11i
   if 48 - 48: Oo0Ooo . IiII / ooOoO0o + I11i
  I1I11Iiii111 -= 1
  if 40 - 40: I1IiiI + I1ii11iIi11i * I1IiiI % Ii1I
  if 27 - 27: O0 / Oo0Ooo . oO0o
 Ii . close ( )
 lprint ( "{} {} map-cache entries from file '{}'" . format (
 bold ( "Loaded" , False ) , I1I11Iiii111 , lisp_checkpoint_filename ) )
 return
 if 34 - 34: I1Ii111 % Ii1I / Oo0Ooo % ooOoO0o / i11iIiiIii * I1IiiI
 if 36 - 36: i11iIiiIii * i1IIi % iII111i . Oo0Ooo
 if 54 - 54: o0oOOo0O0Ooo % i1IIi % I1ii11iIi11i . o0oOOo0O0Ooo / OoOoOO00
 if 55 - 55: O0 / OoooooooOO % Ii1I * O0 + iIii1I11I1II1 . iIii1I11I1II1
 if 55 - 55: Ii1I . OoooooooOO % Ii1I . IiII
 if 67 - 67: oO0o
 if 12 - 12: I1IiiI + OoooooooOO
 if 25 - 25: iIii1I11I1II1 - I1IiiI . i11iIiiIii + ooOoO0o
 if 19 - 19: OoooooooOO / IiII
 if 40 - 40: OoOoOO00 / OoooooooOO * iIii1I11I1II1 / i1IIi . OoooooooOO
 if 88 - 88: I1IiiI % I1IiiI / II111iiii - IiII
 if 72 - 72: OoO0O00 - I1ii11iIi11i . Oo0Ooo / OoO0O00
 if 86 - 86: i11iIiiIii - oO0o . i11iIiiIii
 if 51 - 51: OoO0O00 - OoO0O00 * IiII
def lisp_write_checkpoint_entry ( checkpoint_list , mc ) :
 if ( lisp_checkpoint_map_cache == False ) : return
 if 24 - 24: OoooooooOO . II111iiii
 iIIiI11iI1Ii1 = "{} rloc " . format ( mc . eid . print_prefix ( ) )
 if 97 - 97: II111iiii . O0
 for IIiO0Ooo in mc . rloc_set :
  if ( IIiO0Ooo . rloc . is_null ( ) ) : continue
  iIIiI11iI1Ii1 += "{} {} {}, " . format ( IIiO0Ooo . rloc . print_address_no_iid ( ) ,
 IIiO0Ooo . priority , IIiO0Ooo . weight )
  if 18 - 18: iII111i
  if 35 - 35: ooOoO0o / O0 / iIii1I11I1II1 - iIii1I11I1II1 + I11i
 if ( mc . rloc_set != [ ] ) :
  iIIiI11iI1Ii1 = iIIiI11iI1Ii1 [ 0 : - 2 ]
 elif ( mc . action == LISP_NATIVE_FORWARD_ACTION ) :
  iIIiI11iI1Ii1 += "native-forward"
  if 8 - 8: I1Ii111 . oO0o % Oo0Ooo * OoooooooOO
  if 25 - 25: OoO0O00
 checkpoint_list . append ( iIIiI11iI1Ii1 )
 return
 if 54 - 54: O0
 if 20 - 20: ooOoO0o + Oo0Ooo - Oo0Ooo
 if 2 - 2: i1IIi - IiII . I1ii11iIi11i / i1IIi
 if 92 - 92: ooOoO0o - iII111i
 if 69 - 69: iII111i
 if 48 - 48: O0 + o0oOOo0O0Ooo . oO0o - IiII * OoooooooOO . OoO0O00
 if 63 - 63: oO0o * OoO0O00 * oO0o
def lisp_check_dp_socket ( ) :
 i11i11 = lisp_ipc_dp_socket_name
 if ( os . path . exists ( i11i11 ) == False ) :
  oO0Ii1Ii = bold ( "does not exist" , False )
  lprint ( "Socket '{}' {}" . format ( i11i11 , oO0Ii1Ii ) )
  return ( False )
  if 20 - 20: I1Ii111 . II111iiii % II111iiii
 return ( True )
 if 79 - 79: II111iiii . I11i + o0oOOo0O0Ooo % I1ii11iIi11i + I1ii11iIi11i
 if 4 - 4: I1ii11iIi11i % OoooooooOO
 if 43 - 43: IiII - I1Ii111 % ooOoO0o
 if 49 - 49: OoOoOO00
 if 43 - 43: I1Ii111 - Oo0Ooo % i1IIi . II111iiii
 if 80 - 80: IiII . iII111i + I1Ii111 + iII111i % Oo0Ooo
 if 98 - 98: i11iIiiIii . II111iiii + OoOoOO00
def lisp_write_to_dp_socket ( entry ) :
 try :
  IiiiI1IO000Oooo = json . dumps ( entry )
  i11iiI = bold ( "Write IPC" , False )
  lprint ( "{} record to named socket: '{}'" . format ( i11iiI , IiiiI1IO000Oooo ) )
  lisp_ipc_dp_socket . sendto ( IiiiI1IO000Oooo , lisp_ipc_dp_socket_name )
 except :
  lprint ( "Failed to write IPC record to named socket: '{}'" . format ( IiiiI1IO000Oooo ) )
  if 5 - 5: i11iIiiIii - oO0o + o0oOOo0O0Ooo % ooOoO0o
 return
 if 63 - 63: oO0o
 if 7 - 7: IiII / i11iIiiIii - OOooOOo
 if 9 - 9: II111iiii + i11iIiiIii % I1Ii111 - Oo0Ooo * OOooOOo
 if 55 - 55: I1Ii111 + ooOoO0o
 if 58 - 58: iII111i . I1ii11iIi11i - Oo0Ooo % o0oOOo0O0Ooo + I1Ii111
 if 58 - 58: oO0o . ooOoO0o . I1IiiI . Oo0Ooo * iIii1I11I1II1 - iII111i
 if 96 - 96: OOooOOo % o0oOOo0O0Ooo / iIii1I11I1II1
 if 60 - 60: i1IIi / iIii1I11I1II1 + I11i % iII111i
 if 64 - 64: I11i . i11iIiiIii / iIii1I11I1II1 . I11i
def lisp_write_ipc_keys ( rloc ) :
 I1iiIiiii1111 = rloc . rloc . print_address_no_iid ( )
 o00o = rloc . translated_port
 if ( o00o != 0 ) : I1iiIiiii1111 += ":" + str ( o00o )
 if ( lisp_rloc_probe_list . has_key ( I1iiIiiii1111 ) == False ) : return
 if 73 - 73: OoO0O00 % iIii1I11I1II1 + IiII * I1Ii111 % II111iiii
 for O00oo00o000o , ooo0OO , O0oOo00Oo0oo0 in lisp_rloc_probe_list [ I1iiIiiii1111 ] :
  Iii1 = lisp_map_cache . lookup_cache ( ooo0OO , True )
  if ( Iii1 == None ) : continue
  lisp_write_ipc_map_cache ( True , Iii1 )
  if 20 - 20: I11i % I1ii11iIi11i . OoO0O00 % OoOoOO00
 return
 if 84 - 84: OoooooooOO / i11iIiiIii . IiII / I1IiiI
 if 62 - 62: iII111i - I1IiiI + OoooooooOO
 if 59 - 59: iIii1I11I1II1 + i11iIiiIii * oO0o . Oo0Ooo . I1Ii111
 if 49 - 49: II111iiii
 if 99 - 99: Oo0Ooo . OOooOOo
 if 85 - 85: OoOoOO00 . IiII + oO0o - II111iiii
 if 70 - 70: O0 % I1Ii111
def lisp_write_ipc_map_cache ( add_or_delete , mc , dont_send = False ) :
 if ( lisp_i_am_etr ) : return
 if ( lisp_ipc_dp_socket == None ) : return
 if ( lisp_check_dp_socket ( ) == False ) : return
 if 13 - 13: I1ii11iIi11i % OoO0O00 / Ii1I * IiII
 if 82 - 82: ooOoO0o % Oo0Ooo
 if 26 - 26: OoO0O00 + i11iIiiIii % I11i . I1ii11iIi11i
 if 76 - 76: i1IIi + ooOoO0o - Oo0Ooo + OoOoOO00 / I1ii11iIi11i . OOooOOo
 Oo = "add" if add_or_delete else "delete"
 iIIiI11iI1Ii1 = { "type" : "map-cache" , "opcode" : Oo }
 if 50 - 50: IiII - Ii1I % iIii1I11I1II1
 o0OoOO00O0O0 = ( mc . group . is_null ( ) == False )
 if ( o0OoOO00O0O0 ) :
  iIIiI11iI1Ii1 [ "eid-prefix" ] = mc . group . print_prefix_no_iid ( )
  iIIiI11iI1Ii1 [ "rles" ] = [ ]
 else :
  iIIiI11iI1Ii1 [ "eid-prefix" ] = mc . eid . print_prefix_no_iid ( )
  iIIiI11iI1Ii1 [ "rlocs" ] = [ ]
  if 60 - 60: o0oOOo0O0Ooo - Oo0Ooo
 iIIiI11iI1Ii1 [ "instance-id" ] = str ( mc . eid . instance_id )
 if 92 - 92: OoOoOO00 + IiII . OoO0O00 % iII111i / II111iiii / I11i
 if ( o0OoOO00O0O0 ) :
  if ( len ( mc . rloc_set ) >= 1 and mc . rloc_set [ 0 ] . rle ) :
   for OOoo0Oo00 in mc . rloc_set [ 0 ] . rle . rle_forwarding_list :
    o0o0O00 = OOoo0Oo00 . address . print_address_no_iid ( )
    o00o = str ( 4341 ) if OOoo0Oo00 . translated_port == 0 else str ( OOoo0Oo00 . translated_port )
    if 62 - 62: I1ii11iIi11i
    O00oo00o000o = { "rle" : o0o0O00 , "port" : o00o }
    IIiiIiI , O0o00 = OOoo0Oo00 . get_encap_keys ( )
    O00oo00o000o = lisp_build_json_keys ( O00oo00o000o , IIiiIiI , O0o00 , "encrypt-key" )
    iIIiI11iI1Ii1 [ "rles" ] . append ( O00oo00o000o )
    if 90 - 90: I1IiiI . oO0o
    if 17 - 17: OoooooooOO / oO0o * I11i
 else :
  for oOOoo0O00 in mc . rloc_set :
   if ( oOOoo0O00 . rloc . is_ipv4 ( ) == False and oOOoo0O00 . rloc . is_ipv6 ( ) == False ) :
    continue
    if 63 - 63: Oo0Ooo
   if ( oOOoo0O00 . up_state ( ) == False ) : continue
   if 4 - 4: ooOoO0o
   o00o = str ( 4341 ) if oOOoo0O00 . translated_port == 0 else str ( oOOoo0O00 . translated_port )
   if 46 - 46: IiII * I11i - OoO0O00 - Ii1I
   O00oo00o000o = { "rloc" : oOOoo0O00 . rloc . print_address_no_iid ( ) , "priority" :
 str ( oOOoo0O00 . priority ) , "weight" : str ( oOOoo0O00 . weight ) , "port" :
 o00o }
   IIiiIiI , O0o00 = oOOoo0O00 . get_encap_keys ( )
   O00oo00o000o = lisp_build_json_keys ( O00oo00o000o , IIiiIiI , O0o00 , "encrypt-key" )
   iIIiI11iI1Ii1 [ "rlocs" ] . append ( O00oo00o000o )
   if 93 - 93: iIii1I11I1II1 / o0oOOo0O0Ooo - I11i - OOooOOo % ooOoO0o
   if 16 - 16: ooOoO0o * o0oOOo0O0Ooo - IiII + I1ii11iIi11i / o0oOOo0O0Ooo - O0
   if 71 - 71: i1IIi
 if ( dont_send == False ) : lisp_write_to_dp_socket ( iIIiI11iI1Ii1 )
 return ( iIIiI11iI1Ii1 )
 if 79 - 79: iII111i * O0 / Ii1I / O0 % i1IIi
 if 52 - 52: OoooooooOO % oO0o - I11i % OoOoOO00 . II111iiii
 if 62 - 62: Ii1I . I1ii11iIi11i . iII111i + I11i * o0oOOo0O0Ooo
 if 56 - 56: oO0o * iIii1I11I1II1 . II111iiii - II111iiii + II111iiii - i11iIiiIii
 if 79 - 79: iII111i
 if 29 - 29: Ii1I * I1Ii111 / OoO0O00 - O0 - i11iIiiIii * I1IiiI
 if 2 - 2: OoOoOO00 . I1ii11iIi11i * I1ii11iIi11i
def lisp_write_ipc_decap_key ( rloc_addr , keys ) :
 if ( lisp_i_am_itr ) : return
 if ( lisp_ipc_dp_socket == None ) : return
 if ( lisp_check_dp_socket ( ) == False ) : return
 if 42 - 42: OoO0O00 . OoO0O00 + II111iiii - IiII - OOooOOo * Oo0Ooo
 if 47 - 47: oO0o - OoooooooOO + iII111i
 if 69 - 69: I1ii11iIi11i - I1IiiI % oO0o + OOooOOo - I1Ii111
 if 5 - 5: ooOoO0o . OoO0O00
 if ( keys == None or len ( keys ) == 0 or keys [ 1 ] == None ) : return
 if 40 - 40: iII111i
 IIiiIiI = keys [ 1 ] . encrypt_key
 O0o00 = keys [ 1 ] . icv_key
 if 87 - 87: IiII / II111iiii
 if 44 - 44: OoO0O00 . I1Ii111 - OoooooooOO * OoOoOO00 . OoO0O00
 if 84 - 84: OOooOOo . OOooOOo . oO0o % iII111i * Oo0Ooo - iIii1I11I1II1
 if 4 - 4: iII111i
 IiiIi11I = rloc_addr . split ( ":" )
 if ( len ( IiiIi11I ) == 1 ) :
  iIIiI11iI1Ii1 = { "type" : "decap-keys" , "rloc" : IiiIi11I [ 0 ] }
 else :
  iIIiI11iI1Ii1 = { "type" : "decap-keys" , "rloc" : IiiIi11I [ 0 ] , "port" : IiiIi11I [ 1 ] }
  if 80 - 80: OoO0O00 % I1IiiI * I11i
 iIIiI11iI1Ii1 = lisp_build_json_keys ( iIIiI11iI1Ii1 , IIiiIiI , O0o00 , "decrypt-key" )
 if 78 - 78: OoooooooOO . I1Ii111 + Ii1I - II111iiii - IiII / iIii1I11I1II1
 lisp_write_to_dp_socket ( iIIiI11iI1Ii1 )
 return
 if 92 - 92: Ii1I
 if 34 - 34: OOooOOo * OoooooooOO / I1ii11iIi11i
 if 41 - 41: i1IIi
 if 75 - 75: o0oOOo0O0Ooo . I1Ii111 - I1Ii111 % Ii1I * OoooooooOO
 if 99 - 99: OOooOOo + o0oOOo0O0Ooo - OOooOOo . i1IIi
 if 86 - 86: Ii1I % oO0o - i11iIiiIii - O0 + IiII + iII111i
 if 100 - 100: OoO0O00 . Oo0Ooo
 if 29 - 29: OoO0O00
def lisp_build_json_keys ( entry , ekey , ikey , key_type ) :
 if ( ekey == None ) : return ( entry )
 if 34 - 34: O0 - o0oOOo0O0Ooo % OOooOOo . OoO0O00 % IiII
 entry [ "keys" ] = [ ]
 o0OoOo0o0OOoO0 = { "key-id" : "1" , key_type : ekey , "icv-key" : ikey }
 entry [ "keys" ] . append ( o0OoOo0o0OOoO0 )
 return ( entry )
 if 63 - 63: O0 % iIii1I11I1II1 . o0oOOo0O0Ooo . I1IiiI * Ii1I % i1IIi
 if 47 - 47: II111iiii * I1ii11iIi11i
 if 70 - 70: I1ii11iIi11i - o0oOOo0O0Ooo
 if 71 - 71: I1ii11iIi11i * i1IIi
 if 67 - 67: I1ii11iIi11i % OoOoOO00 . iII111i / Ii1I . I1IiiI
 if 48 - 48: IiII + II111iiii . I1IiiI % o0oOOo0O0Ooo
 if 57 - 57: OOooOOo . I11i % OoOoOO00
def lisp_write_ipc_database_mappings ( ephem_port ) :
 if ( lisp_i_am_etr == False ) : return
 if ( lisp_ipc_dp_socket == None ) : return
 if ( lisp_check_dp_socket ( ) == False ) : return
 if 68 - 68: iIii1I11I1II1 % I1ii11iIi11i % II111iiii / O0 + iII111i
 if 78 - 78: iII111i - OOooOOo / I1Ii111
 if 38 - 38: I11i % i1IIi + o0oOOo0O0Ooo + I1ii11iIi11i + I1IiiI
 if 1 - 1: II111iiii * o0oOOo0O0Ooo . O0 - Ii1I / oO0o
 iIIiI11iI1Ii1 = { "type" : "database-mappings" , "database-mappings" : [ ] }
 if 17 - 17: OoooooooOO % OoooooooOO + Oo0Ooo + I1Ii111
 if 56 - 56: I11i % OoOoOO00 - OoO0O00
 if 31 - 31: iII111i % i11iIiiIii - Ii1I / OOooOOo - I1Ii111
 if 60 - 60: o0oOOo0O0Ooo + Oo0Ooo . O0
 for I11i111 in lisp_db_list :
  if ( I11i111 . eid . is_ipv4 ( ) == False and I11i111 . eid . is_ipv6 ( ) == False ) : continue
  OoooO = { "instance-id" : str ( I11i111 . eid . instance_id ) ,
 "eid-prefix" : I11i111 . eid . print_prefix_no_iid ( ) }
  iIIiI11iI1Ii1 [ "database-mappings" ] . append ( OoooO )
  if 31 - 31: iIii1I11I1II1 % iII111i * Ii1I % Ii1I . I11i / Ii1I
 lisp_write_to_dp_socket ( iIIiI11iI1Ii1 )
 if 25 - 25: I1ii11iIi11i / o0oOOo0O0Ooo - I1ii11iIi11i
 if 43 - 43: ooOoO0o + o0oOOo0O0Ooo / OOooOOo * I1Ii111
 if 100 - 100: IiII / i11iIiiIii . I1Ii111 / OoO0O00 - I1Ii111
 if 42 - 42: Ii1I
 if 42 - 42: I11i / Ii1I / Oo0Ooo - I1IiiI - I11i - i11iIiiIii
 iIIiI11iI1Ii1 = { "type" : "etr-nat-port" , "port" : ephem_port }
 lisp_write_to_dp_socket ( iIIiI11iI1Ii1 )
 return
 if 45 - 45: ooOoO0o - IiII / OoO0O00 / IiII
 if 63 - 63: ooOoO0o . i11iIiiIii + iII111i . OoO0O00 / ooOoO0o % iII111i
 if 23 - 23: iIii1I11I1II1 - ooOoO0o / I11i * I11i
 if 62 - 62: OOooOOo - I1IiiI * oO0o + O0 / ooOoO0o * iIii1I11I1II1
 if 25 - 25: I1Ii111 % Oo0Ooo + OoO0O00 % OOooOOo
 if 85 - 85: I1IiiI . i11iIiiIii - ooOoO0o * I11i * OoOoOO00 * I11i
 if 29 - 29: I1Ii111 * I1Ii111 . iII111i + o0oOOo0O0Ooo
def lisp_write_ipc_interfaces ( ) :
 if ( lisp_i_am_etr ) : return
 if ( lisp_ipc_dp_socket == None ) : return
 if ( lisp_check_dp_socket ( ) == False ) : return
 if 57 - 57: I1Ii111 - IiII
 if 89 - 89: oO0o + iII111i
 if 52 - 52: OOooOOo % O0 * I1ii11iIi11i . I1ii11iIi11i / IiII
 if 7 - 7: II111iiii
 iIIiI11iI1Ii1 = { "type" : "interfaces" , "interfaces" : [ ] }
 if 7 - 7: iIii1I11I1II1 . O0 + Ii1I % I1IiiI * O0 + OoO0O00
 for I111IIiIII in lisp_myinterfaces . values ( ) :
  if ( I111IIiIII . instance_id == None ) : continue
  OoooO = { "interface" : I111IIiIII . device ,
 "instance-id" : str ( I111IIiIII . instance_id ) }
  iIIiI11iI1Ii1 [ "interfaces" ] . append ( OoooO )
  if 3 - 3: Oo0Ooo * OoooooooOO * oO0o % OoOoOO00 * OoOoOO00 . ooOoO0o
  if 16 - 16: ooOoO0o / o0oOOo0O0Ooo - O0 * I1IiiI
 lisp_write_to_dp_socket ( iIIiI11iI1Ii1 )
 return
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
 if 38 - 38: II111iiii % OoooooooOO / OoooooooOO . Ii1I . Ii1I
 if 13 - 13: oO0o - i1IIi / i1IIi + OoooooooOO
def lisp_parse_auth_key ( value ) :
 OooO0OO = value . split ( "[" )
 OoOo0 = { }
 if ( len ( OooO0OO ) == 1 ) :
  OoOo0 [ 0 ] = value
  return ( OoOo0 )
  if 60 - 60: I1IiiI % Ii1I - iII111i + I1IiiI * ooOoO0o * Oo0Ooo
  if 68 - 68: ooOoO0o + OoOoOO00 + iIii1I11I1II1
 for O0o0 in OooO0OO :
  if ( O0o0 == "" ) : continue
  iI11I = O0o0 . find ( "]" )
  o0OOOoO0O = O0o0 [ 0 : iI11I ]
  try : o0OOOoO0O = int ( o0OOOoO0O )
  except : return
  if 21 - 21: iII111i + II111iiii - I1ii11iIi11i / OOooOOo + iII111i
  OoOo0 [ o0OOOoO0O ] = O0o0 [ iI11I + 1 : : ]
  if 60 - 60: iII111i . OoO0O00 / oO0o - OoO0O00 + ooOoO0o * I1Ii111
 return ( OoOo0 )
 if 8 - 8: oO0o - O0 % I1IiiI . I1ii11iIi11i / I11i / I1Ii111
 if 18 - 18: Oo0Ooo % I1ii11iIi11i
 if 90 - 90: iII111i . O0
 if 6 - 6: I1IiiI + o0oOOo0O0Ooo . OoooooooOO * oO0o + OoooooooOO
 if 77 - 77: II111iiii / I1Ii111 * i11iIiiIii + OoooooooOO
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
 if 20 - 20: IiII
def lisp_reassemble ( packet ) :
 o0o0oO0OOO = socket . ntohs ( struct . unpack ( "H" , packet [ 6 : 8 ] ) [ 0 ] )
 if 81 - 81: I1Ii111 . i1IIi / o0oOOo0O0Ooo
 if 30 - 30: i11iIiiIii . I1IiiI
 if 5 - 5: Ii1I / O0 + iIii1I11I1II1
 if 22 - 22: ooOoO0o . ooOoO0o * OOooOOo % OoOoOO00
 if ( o0o0oO0OOO == 0 or o0o0oO0OOO == 0x4000 ) : return ( packet )
 if 51 - 51: OoOoOO00 . oO0o - OoOoOO00
 if 79 - 79: iII111i
 if 71 - 71: i1IIi / OoO0O00 / OOooOOo + I1Ii111
 if 80 - 80: Oo0Ooo . iIii1I11I1II1 . OoooooooOO % iII111i . oO0o
 O0o00ooo = socket . ntohs ( struct . unpack ( "H" , packet [ 4 : 6 ] ) [ 0 ] )
 iiiiiI111IIiI = socket . ntohs ( struct . unpack ( "H" , packet [ 2 : 4 ] ) [ 0 ] )
 if 60 - 60: iIii1I11I1II1 % I1ii11iIi11i
 OoooOo = ( o0o0oO0OOO & 0x2000 == 0 and ( o0o0oO0OOO & 0x1fff ) != 0 )
 iIIiI11iI1Ii1 = [ ( o0o0oO0OOO & 0x1fff ) * 8 , iiiiiI111IIiI - 20 , packet , OoooOo ]
 if 75 - 75: Oo0Ooo - I1Ii111 * IiII
 if 2 - 2: I1Ii111 - O0 % OoooooooOO + I1Ii111
 if 1 - 1: I1Ii111 % OoooooooOO + OoooooooOO - I1IiiI % I1IiiI
 if 51 - 51: iIii1I11I1II1 / I1IiiI
 if 27 - 27: O0 . o0oOOo0O0Ooo / ooOoO0o / OoooooooOO % Ii1I
 if 27 - 27: ooOoO0o / IiII + OoO0O00 + Ii1I % I1Ii111
 if 86 - 86: O0 % i11iIiiIii - Ii1I * oO0o % OOooOOo * i1IIi
 if 87 - 87: II111iiii
 if ( o0o0oO0OOO == 0x2000 ) :
  iiI1iIII1ii , i1iiIIiII1 = struct . unpack ( "HH" , packet [ 20 : 24 ] )
  iiI1iIII1ii = socket . ntohs ( iiI1iIII1ii )
  i1iiIIiII1 = socket . ntohs ( i1iiIIiII1 )
  if ( i1iiIIiII1 not in [ 4341 , 8472 , 4789 ] and iiI1iIII1ii != 4341 ) :
   lisp_reassembly_queue [ O0o00ooo ] = [ ]
   iIIiI11iI1Ii1 [ 2 ] = None
   if 53 - 53: OoOoOO00 * i11iIiiIii / I1Ii111
   if 100 - 100: ooOoO0o + I1IiiI * oO0o + ooOoO0o
   if 24 - 24: i11iIiiIii + ooOoO0o
   if 80 - 80: IiII % I11i % oO0o
   if 97 - 97: i1IIi * i11iIiiIii / Ii1I - I1IiiI % IiII
   if 70 - 70: iIii1I11I1II1
 if ( lisp_reassembly_queue . has_key ( O0o00ooo ) == False ) :
  lisp_reassembly_queue [ O0o00ooo ] = [ ]
  if 2 - 2: IiII - i1IIi * IiII % O0 / Ii1I
  if 64 - 64: iII111i - Oo0Ooo
  if 73 - 73: iIii1I11I1II1 * I1Ii111 * OoO0O00
  if 68 - 68: ooOoO0o * Ii1I / I1ii11iIi11i * OoooooooOO + OoooooooOO . OoooooooOO
  if 50 - 50: I1IiiI % o0oOOo0O0Ooo
 iiiI1 = lisp_reassembly_queue [ O0o00ooo ]
 if 83 - 83: iII111i % o0oOOo0O0Ooo * OoOoOO00
 if 49 - 49: II111iiii / OoO0O00
 if 69 - 69: Ii1I * II111iiii
 if 24 - 24: I1Ii111 * I1ii11iIi11i . OOooOOo . I1IiiI - I1ii11iIi11i
 if 56 - 56: I1IiiI * Oo0Ooo + OoO0O00 - oO0o * I1Ii111
 if ( len ( iiiI1 ) == 1 and iiiI1 [ 0 ] [ 2 ] == None ) :
  dprint ( "Drop non-LISP encapsulated fragment 0x{}" . format ( lisp_hex_string ( O0o00ooo ) . zfill ( 4 ) ) )
  if 68 - 68: ooOoO0o * i11iIiiIii * OOooOOo % iII111i
  return ( None )
  if 10 - 10: Ii1I / Oo0Ooo - i1IIi
  if 11 - 11: I11i * iII111i
  if 28 - 28: II111iiii + IiII / Oo0Ooo * I1IiiI - OOooOOo
  if 2 - 2: oO0o + I11i / I1Ii111 . I11i
  if 59 - 59: Ii1I
 iiiI1 . append ( iIIiI11iI1Ii1 )
 iiiI1 = sorted ( iiiI1 )
 if 47 - 47: iII111i % iII111i
 if 81 - 81: oO0o / I1ii11iIi11i . OoooooooOO % II111iiii / oO0o
 if 23 - 23: IiII + oO0o + o0oOOo0O0Ooo . I1ii11iIi11i / i11iIiiIii + iIii1I11I1II1
 if 74 - 74: I11i % OOooOOo
 o0o0O00 = lisp_address ( LISP_AFI_IPV4 , "" , 32 , 0 )
 o0o0O00 . address = socket . ntohl ( struct . unpack ( "I" , packet [ 12 : 16 ] ) [ 0 ] )
 ooOoo0 = o0o0O00 . print_address_no_iid ( )
 o0o0O00 . address = socket . ntohl ( struct . unpack ( "I" , packet [ 16 : 20 ] ) [ 0 ] )
 o0OOoOo0o = o0o0O00 . print_address_no_iid ( )
 o0o0O00 = red ( "{} -> {}" . format ( ooOoo0 , o0OOoOo0o ) , False )
 if 31 - 31: I1Ii111 * i11iIiiIii * IiII - OoooooooOO
 dprint ( "{}{} fragment, RLOCs: {}, packet 0x{}, frag-offset: 0x{}" . format ( bold ( "Received" , False ) , " non-LISP encapsulated" if iIIiI11iI1Ii1 [ 2 ] == None else "" , o0o0O00 , lisp_hex_string ( O0o00ooo ) . zfill ( 4 ) ,
 # iIii1I11I1II1 % i11iIiiIii / Ii1I % iIii1I11I1II1 / iII111i
 # ooOoO0o - II111iiii
 lisp_hex_string ( o0o0oO0OOO ) . zfill ( 4 ) ) )
 if 33 - 33: Ii1I
 if 38 - 38: OoO0O00
 if 84 - 84: I11i - iIii1I11I1II1
 if 61 - 61: I1Ii111 % I11i * i1IIi . O0 . iIii1I11I1II1
 if 42 - 42: Oo0Ooo * I1ii11iIi11i
 if ( iiiI1 [ 0 ] [ 0 ] != 0 or iiiI1 [ - 1 ] [ 3 ] == False ) : return ( None )
 o00oO0O0O0 = iiiI1 [ 0 ]
 for IiI1IiI1iiI1 in iiiI1 [ 1 : : ] :
  o0o0oO0OOO = IiI1IiI1iiI1 [ 0 ]
  IiI1IIiIiI1I , OOoo0o00O = o00oO0O0O0 [ 0 ] , o00oO0O0O0 [ 1 ]
  if ( IiI1IIiIiI1I + OOoo0o00O != o0o0oO0OOO ) : return ( None )
  o00oO0O0O0 = IiI1IiI1iiI1
  if 9 - 9: OoooooooOO - Oo0Ooo - O0 * o0oOOo0O0Ooo + i11iIiiIii % I1IiiI
 lisp_reassembly_queue . pop ( O0o00ooo )
 if 87 - 87: II111iiii . iIii1I11I1II1 . OoOoOO00
 if 23 - 23: Oo0Ooo / II111iiii % OOooOOo % iII111i - Oo0Ooo / OoO0O00
 if 7 - 7: Ii1I / I11i / II111iiii % I11i * I11i + iIii1I11I1II1
 if 6 - 6: iIii1I11I1II1 * oO0o - iIii1I11I1II1 . O0 . O0
 if 96 - 96: I1Ii111 * II111iiii % i11iIiiIii - oO0o
 packet = iiiI1 [ 0 ] [ 2 ]
 for IiI1IiI1iiI1 in iiiI1 [ 1 : : ] : packet += IiI1IiI1iiI1 [ 2 ] [ 20 : : ]
 if 32 - 32: i11iIiiIii * o0oOOo0O0Ooo . OoooooooOO / O0
 dprint ( "{} fragments arrived for packet 0x{}, length {}" . format ( bold ( "All" , False ) , lisp_hex_string ( O0o00ooo ) . zfill ( 4 ) , len ( packet ) ) )
 if 14 - 14: i11iIiiIii . I1Ii111 % I1ii11iIi11i . I1ii11iIi11i % IiII
 if 93 - 93: iIii1I11I1II1 / IiII
 if 91 - 91: i11iIiiIii % ooOoO0o - iII111i * I1Ii111 . i11iIiiIii
 if 1 - 1: IiII + iIii1I11I1II1 * I1ii11iIi11i - IiII - i1IIi
 if 75 - 75: II111iiii * o0oOOo0O0Ooo / I1ii11iIi11i
 o00OOo00 = socket . htons ( len ( packet ) )
 I1I = packet [ 0 : 2 ] + struct . pack ( "H" , o00OOo00 ) + packet [ 4 : 6 ] + struct . pack ( "H" , 0 ) + packet [ 8 : 10 ] + struct . pack ( "H" , 0 ) + packet [ 12 : 20 ]
 if 46 - 46: OOooOOo
 if 67 - 67: OoO0O00 . I11i % OOooOOo + Oo0Ooo
 I1I = lisp_ip_checksum ( I1I )
 return ( I1I + packet [ 20 : : ] )
 if 40 - 40: OoO0O00 / I11i % iIii1I11I1II1 - ooOoO0o
 if 51 - 51: Oo0Ooo % iIii1I11I1II1 % oO0o + o0oOOo0O0Ooo
 if 32 - 32: I1Ii111 * I1IiiI + Ii1I
 if 30 - 30: OoooooooOO / I1IiiI . iIii1I11I1II1 / ooOoO0o
 if 20 - 20: OoooooooOO * OOooOOo
 if 77 - 77: Ii1I - OoooooooOO . OoOoOO00
 if 93 - 93: OoooooooOO / I1Ii111
 if 91 - 91: I1Ii111
def lisp_get_crypto_decap_lookup_key ( addr , port ) :
 I1iiIiiii1111 = addr . print_address_no_iid ( ) + ":" + str ( port )
 if ( lisp_crypto_keys_by_rloc_decap . has_key ( I1iiIiiii1111 ) ) : return ( I1iiIiiii1111 )
 if 18 - 18: ooOoO0o * I11i
 I1iiIiiii1111 = addr . print_address_no_iid ( )
 if ( lisp_crypto_keys_by_rloc_decap . has_key ( I1iiIiiii1111 ) ) : return ( I1iiIiiii1111 )
 if 53 - 53: I11i . i11iIiiIii - iIii1I11I1II1 / I1Ii111
 if 86 - 86: i1IIi % OoO0O00 - OoooooooOO
 if 63 - 63: o0oOOo0O0Ooo . iIii1I11I1II1 % IiII * i11iIiiIii
 if 70 - 70: iIii1I11I1II1
 if 12 - 12: OoOoOO00 / o0oOOo0O0Ooo - I1ii11iIi11i + oO0o + O0
 for IIiiii11iiiI in lisp_crypto_keys_by_rloc_decap :
  oOO0oo = IIiiii11iiiI . split ( ":" )
  if ( len ( oOO0oo ) == 1 ) : continue
  oOO0oo = oOO0oo [ 0 ] if len ( oOO0oo ) == 2 else ":" . join ( oOO0oo [ 0 : - 1 ] )
  if ( oOO0oo == I1iiIiiii1111 ) :
   o00OO0o0 = lisp_crypto_keys_by_rloc_decap [ IIiiii11iiiI ]
   lisp_crypto_keys_by_rloc_decap [ I1iiIiiii1111 ] = o00OO0o0
   return ( I1iiIiiii1111 )
   if 81 - 81: OoOoOO00
   if 81 - 81: O0
 return ( None )
 if 57 - 57: oO0o - o0oOOo0O0Ooo % i11iIiiIii / OoOoOO00 . iIii1I11I1II1
 if 68 - 68: iII111i
 if 59 - 59: O0 - i11iIiiIii + OoooooooOO - iII111i - Oo0Ooo . OoooooooOO
 if 60 - 60: O0 * iIii1I11I1II1 - Ii1I * II111iiii . ooOoO0o
 if 61 - 61: I1IiiI . iII111i
 if 19 - 19: iIii1I11I1II1 * Oo0Ooo - I1IiiI - I1IiiI + O0 - I1Ii111
 if 56 - 56: I1Ii111 - i1IIi + I11i . i1IIi / II111iiii * oO0o
 if 70 - 70: ooOoO0o - II111iiii . I11i
 if 70 - 70: OOooOOo / iII111i - I11i + OoOoOO00 % Ii1I * IiII
 if 26 - 26: O0 / oO0o
 if 96 - 96: ooOoO0o * iII111i . IiII
def lisp_build_crypto_decap_lookup_key ( addr , port ) :
 addr = addr . print_address_no_iid ( )
 oO00OO00 = addr + ":" + str ( port )
 if 35 - 35: oO0o
 if ( lisp_i_am_rtr ) :
  if ( lisp_rloc_probe_list . has_key ( addr ) ) : return ( addr )
  if 8 - 8: IiII / o0oOOo0O0Ooo
  if 75 - 75: I1IiiI + oO0o
  if 50 - 50: iIii1I11I1II1 / I1IiiI / O0 . I1IiiI
  if 35 - 35: I1Ii111
  if 80 - 80: I1Ii111 * I11i + O0 - OOooOOo . ooOoO0o - i11iIiiIii
  if 49 - 49: iIii1I11I1II1 + iIii1I11I1II1 - I1ii11iIi11i % o0oOOo0O0Ooo - i11iIiiIii
  for iiiII1 in lisp_nat_state_info . values ( ) :
   for i1I in iiiII1 :
    if ( addr == i1I . address ) : return ( oO00OO00 )
    if 52 - 52: I1Ii111 . o0oOOo0O0Ooo / iIii1I11I1II1 - I11i
    if 23 - 23: i11iIiiIii / OoooooooOO + I1ii11iIi11i + O0 + I1ii11iIi11i / i11iIiiIii
  return ( addr )
  if 14 - 14: OoOoOO00 . II111iiii / iII111i / oO0o - oO0o
 return ( oO00OO00 )
 if 12 - 12: O0
 if 77 - 77: oO0o % o0oOOo0O0Ooo % iII111i
 if 28 - 28: OoOoOO00 . O0 - II111iiii - I1IiiI / OOooOOo % O0
 if 49 - 49: ooOoO0o % Ii1I
 if 86 - 86: o0oOOo0O0Ooo - I1IiiI . II111iiii . I1Ii111
 if 22 - 22: IiII
 if 63 - 63: I1IiiI . OOooOOo . O0
def lisp_set_ttl ( lisp_socket , ttl ) :
 try :
  lisp_socket . setsockopt ( socket . SOL_IP , socket . IP_TTL , ttl )
 except :
  lprint ( "socket.setsockopt(IP_TTL) not supported" )
  pass
  if 32 - 32: Ii1I / OOooOOo * i1IIi / i1IIi + I1IiiI % o0oOOo0O0Ooo
 return
 if 61 - 61: o0oOOo0O0Ooo
 if 39 - 39: I1ii11iIi11i / o0oOOo0O0Ooo / Oo0Ooo * II111iiii - OoO0O00
 if 66 - 66: OoO0O00 / oO0o / I1ii11iIi11i - oO0o
 if 9 - 9: ooOoO0o * iIii1I11I1II1 * OoooooooOO
 if 13 - 13: iII111i . i11iIiiIii * o0oOOo0O0Ooo . iII111i
 if 96 - 96: Ii1I
 if 90 - 90: II111iiii
def lisp_is_rloc_probe_request ( lisp_type ) :
 lisp_type = struct . unpack ( "B" , lisp_type ) [ 0 ]
 return ( lisp_type == 0x12 )
 if 93 - 93: i11iIiiIii / Ii1I * Oo0Ooo . iII111i % iII111i / IiII
 if 15 - 15: OoOoOO00 % I1Ii111 - iIii1I11I1II1
 if 52 - 52: i11iIiiIii * ooOoO0o
 if 15 - 15: OoooooooOO . oO0o . i11iIiiIii / o0oOOo0O0Ooo
 if 91 - 91: ooOoO0o
 if 47 - 47: II111iiii + I11i + ooOoO0o % Oo0Ooo / iII111i
 if 9 - 9: O0 + IiII
def lisp_is_rloc_probe_reply ( lisp_type ) :
 lisp_type = struct . unpack ( "B" , lisp_type ) [ 0 ]
 return ( lisp_type == 0x28 )
 if 69 - 69: I1IiiI
 if 11 - 11: I11i % I1Ii111 + O0 . Ii1I . I1ii11iIi11i % I1Ii111
 if 28 - 28: IiII . o0oOOo0O0Ooo + iII111i - OoOoOO00 / OOooOOo
 if 86 - 86: ooOoO0o * OoOoOO00 + oO0o / II111iiii % OOooOOo
 if 89 - 89: O0 * Ii1I / OoO0O00 / OoOoOO00 % iII111i * iIii1I11I1II1
 if 72 - 72: iIii1I11I1II1 / iIii1I11I1II1 * I11i
 if 19 - 19: I1ii11iIi11i
 if 42 - 42: OoOoOO00 / IiII
 if 65 - 65: ooOoO0o - ooOoO0o * OoO0O00
 if 99 - 99: I11i % ooOoO0o . I1Ii111
 if 34 - 34: ooOoO0o + oO0o + II111iiii . I1Ii111 . i1IIi
 if 14 - 14: OoO0O00 . ooOoO0o - i1IIi * I1IiiI
 if 24 - 24: iIii1I11I1II1 / I1Ii111
 if 16 - 16: OoOoOO00 * I1Ii111 - I1IiiI / I1Ii111
 if 64 - 64: I1ii11iIi11i . i1IIi % II111iiii % Oo0Ooo + oO0o - I1IiiI
 if 24 - 24: IiII . II111iiii . II111iiii . OoOoOO00 . i11iIiiIii
 if 11 - 11: Ii1I
 if 82 - 82: I11i - i1IIi . Oo0Ooo * I1Ii111
 if 44 - 44: iII111i
def lisp_is_rloc_probe ( packet , rr ) :
 I1iIIIiI = ( struct . unpack ( "B" , packet [ 9 ] ) [ 0 ] == 17 )
 if ( I1iIIIiI == False ) : return ( [ packet , None , None , None ] )
 if 56 - 56: II111iiii / Oo0Ooo % IiII * II111iiii - iIii1I11I1II1 + ooOoO0o
 if ( rr == 0 ) :
  iI11iI11i11ii = lisp_is_rloc_probe_request ( packet [ 28 ] )
  if ( iI11iI11i11ii == False ) : return ( [ packet , None , None , None ] )
 elif ( rr == 1 ) :
  iI11iI11i11ii = lisp_is_rloc_probe_reply ( packet [ 28 ] )
  if ( iI11iI11i11ii == False ) : return ( [ packet , None , None , None ] )
 elif ( rr == - 1 ) :
  iI11iI11i11ii = lisp_is_rloc_probe_request ( packet [ 28 ] )
  if ( iI11iI11i11ii == False ) :
   iI11iI11i11ii = lisp_is_rloc_probe_reply ( packet [ 28 ] )
   if ( iI11iI11i11ii == False ) : return ( [ packet , None , None , None ] )
   if 33 - 33: o0oOOo0O0Ooo . I11i / I1IiiI
   if 29 - 29: o0oOOo0O0Ooo - ooOoO0o
   if 59 - 59: I11i / IiII * OoO0O00 / IiII . I1Ii111
   if 82 - 82: OOooOOo . iIii1I11I1II1 + I1Ii111
   if 14 - 14: IiII . i11iIiiIii
   if 17 - 17: ooOoO0o % ooOoO0o * oO0o
 O0Oo00o0o = lisp_address ( LISP_AFI_IPV4 , "" , 32 , 0 )
 O0Oo00o0o . address = socket . ntohl ( struct . unpack ( "I" , packet [ 12 : 16 ] ) [ 0 ] )
 if 8 - 8: ooOoO0o + OoO0O00 . II111iiii / iIii1I11I1II1 - OOooOOo
 if 87 - 87: iIii1I11I1II1 . IiII % I1IiiI . OoO0O00 - I1Ii111
 if 53 - 53: I1Ii111 % i11iIiiIii
 if 99 - 99: I1IiiI - i1IIi * i11iIiiIii + OoO0O00
 if ( O0Oo00o0o . is_local ( ) ) : return ( [ None , None , None , None ] )
 if 80 - 80: o0oOOo0O0Ooo . I11i % iIii1I11I1II1 + OoOoOO00
 if 87 - 87: I1Ii111 + II111iiii / I1ii11iIi11i + OoOoOO00
 if 71 - 71: I1IiiI + iIii1I11I1II1 + O0 * iII111i % IiII
 if 42 - 42: OOooOOo - I1ii11iIi11i
 O0Oo00o0o = O0Oo00o0o . print_address_no_iid ( )
 o00o = socket . ntohs ( struct . unpack ( "H" , packet [ 20 : 22 ] ) [ 0 ] )
 oooOooOO = struct . unpack ( "B" , packet [ 8 ] ) [ 0 ] - 1
 packet = packet [ 28 : : ]
 if 93 - 93: I1Ii111 + OOooOOo % ooOoO0o / I1Ii111 % OOooOOo . IiII
 O00oo00o000o = bold ( "Receive(pcap)" , False )
 Ii = bold ( "from " + O0Oo00o0o , False )
 i111 = lisp_format_packet ( packet )
 lprint ( "{} {} bytes {} {}, packet: {}" . format ( O00oo00o000o , len ( packet ) , Ii , o00o , i111 ) )
 if 37 - 37: iII111i * oO0o / oO0o / Ii1I % I11i
 return ( [ packet , O0Oo00o0o , o00o , oooOooOO ] )
 if 12 - 12: i11iIiiIii
 if 62 - 62: oO0o + OOooOOo + oO0o + I1IiiI
 if 10 - 10: IiII - Oo0Ooo % ooOoO0o
 if 38 - 38: oO0o * o0oOOo0O0Ooo . I11i % II111iiii / I11i % Ii1I
 if 19 - 19: II111iiii / i11iIiiIii * II111iiii + OoOoOO00 - OoOoOO00
 if 7 - 7: OoOoOO00 - OoO0O00 % OoOoOO00 . I1ii11iIi11i % Oo0Ooo * iII111i
 if 90 - 90: IiII - OOooOOo + iIii1I11I1II1
 if 88 - 88: ooOoO0o . o0oOOo0O0Ooo . OOooOOo - I11i
 if 76 - 76: IiII % I1IiiI . iII111i
 if 5 - 5: ooOoO0o . oO0o - OoOoOO00 - OoooooooOO
 if 2 - 2: OOooOOo
def lisp_ipc_write_xtr_parameters ( cp , dp ) :
 if ( lisp_ipc_dp_socket == None ) : return
 if 37 - 37: IiII - iIii1I11I1II1 * i11iIiiIii . ooOoO0o
 IIi1IIII = { "type" : "xtr-parameters" , "control-plane-logging" : cp ,
 "data-plane-logging" : dp , "rtr" : lisp_i_am_rtr }
 if 78 - 78: OOooOOo - I1ii11iIi11i + iII111i % OoOoOO00
 lisp_write_to_dp_socket ( IIi1IIII )
 return
 if 28 - 28: I11i + i1IIi / i11iIiiIii * OOooOOo * II111iiii
 if 78 - 78: OoO0O00 - i1IIi % I1Ii111
 if 87 - 87: I11i
 if 37 - 37: iII111i . I1Ii111 - iII111i - I11i - iIii1I11I1II1 - II111iiii
 if 80 - 80: I1Ii111 % O0 - IiII / II111iiii + i1IIi
 if 4 - 4: OOooOOo + II111iiii
 if 1 - 1: OoooooooOO * I1Ii111 - I11i / IiII
 if 43 - 43: i11iIiiIii * I1IiiI
def lisp_external_data_plane ( ) :
 o00OoOO0O0 = 'egrep "ipc-data-plane = yes" ./lisp.config'
 if ( commands . getoutput ( o00OoOO0O0 ) != "" ) : return ( True )
 if 48 - 48: Oo0Ooo - OOooOOo / iII111i % I1ii11iIi11i . OoOoOO00
 if ( os . getenv ( "LISP_RUN_LISP_XTR" ) != None ) : return ( True )
 return ( False )
 if 6 - 6: i11iIiiIii
 if 51 - 51: o0oOOo0O0Ooo - OoooooooOO - I11i % i11iIiiIii / I1IiiI + IiII
 if 91 - 91: O0
 if 13 - 13: o0oOOo0O0Ooo
 if 15 - 15: iIii1I11I1II1 * Oo0Ooo . iIii1I11I1II1 . Ii1I % iII111i - i11iIiiIii
 if 77 - 77: ooOoO0o - o0oOOo0O0Ooo * OoOoOO00 % oO0o
 if 4 - 4: i11iIiiIii + OoOoOO00
 if 45 - 45: ooOoO0o / OoooooooOO . Oo0Ooo
 if 35 - 35: i11iIiiIii / o0oOOo0O0Ooo / oO0o / I11i . O0
 if 53 - 53: i1IIi
 if 51 - 51: OoOoOO00 / iIii1I11I1II1 . oO0o - I1ii11iIi11i - OOooOOo
 if 90 - 90: i1IIi / oO0o * I1Ii111 + II111iiii % I11i
 if 41 - 41: o0oOOo0O0Ooo - II111iiii . ooOoO0o . iII111i - ooOoO0o / iII111i
 if 59 - 59: O0 / II111iiii * II111iiii - ooOoO0o
def lisp_process_data_plane_restart ( do_clear = False ) :
 os . system ( "touch ./lisp.config" )
 if 63 - 63: I1ii11iIi11i * IiII % OoO0O00 . OoOoOO00 - II111iiii % IiII
 i1III1iiiII1II = { "type" : "entire-map-cache" , "entries" : [ ] }
 if 54 - 54: OoOoOO00 - OoOoOO00 % I1ii11iIi11i . i1IIi
 if ( do_clear == False ) :
  OOOOo0oO0o = i1III1iiiII1II [ "entries" ]
  lisp_map_cache . walk_cache ( lisp_ipc_walk_map_cache , OOOOo0oO0o )
  if 17 - 17: iIii1I11I1II1 / ooOoO0o - IiII . OoooooooOO + iII111i / I1IiiI
  if 13 - 13: I1ii11iIi11i * IiII . ooOoO0o / I1ii11iIi11i + o0oOOo0O0Ooo
 lisp_write_to_dp_socket ( i1III1iiiII1II )
 return
 if 5 - 5: OoOoOO00 - OoOoOO00
 if 14 - 14: OoOoOO00 . I1Ii111
 if 84 - 84: OoOoOO00 * OoOoOO00 % o0oOOo0O0Ooo * II111iiii
 if 28 - 28: ooOoO0o % OoOoOO00 + ooOoO0o
 if 68 - 68: II111iiii
 if 71 - 71: I1Ii111 % Ii1I - I11i / I11i - Ii1I
 if 54 - 54: Oo0Ooo . OoO0O00 * iII111i . i1IIi - o0oOOo0O0Ooo
 if 33 - 33: Ii1I - oO0o . iII111i * I1ii11iIi11i
 if 78 - 78: oO0o % ooOoO0o
 if 37 - 37: iIii1I11I1II1 + Oo0Ooo + OoO0O00 . I11i % iIii1I11I1II1 + I1Ii111
 if 48 - 48: II111iiii . OOooOOo . ooOoO0o - iII111i
 if 90 - 90: OOooOOo
 if 43 - 43: IiII + ooOoO0o
 if 4 - 4: i1IIi
def lisp_process_data_plane_stats ( msg , lisp_sockets , lisp_port ) :
 if ( msg . has_key ( "entries" ) == False ) :
  lprint ( "No 'entries' in stats IPC message" )
  return
  if 89 - 89: Oo0Ooo / iIii1I11I1II1 . OoOoOO00
 if ( type ( msg [ "entries" ] ) != list ) :
  lprint ( "'entries' in stats IPC message must be an array" )
  return
  if 6 - 6: Ii1I / iII111i
  if 69 - 69: iIii1I11I1II1 % I1Ii111 % OOooOOo + O0 - OoOoOO00 % oO0o
 for msg in msg [ "entries" ] :
  if ( msg . has_key ( "eid-prefix" ) == False ) :
   lprint ( "No 'eid-prefix' in stats IPC message" )
   continue
   if 70 - 70: oO0o - I1IiiI + Ii1I
  oOoo0OooOOo00 = msg [ "eid-prefix" ]
  if 54 - 54: OoOoOO00 / ooOoO0o - I1IiiI
  if ( msg . has_key ( "instance-id" ) == False ) :
   lprint ( "No 'instance-id' in stats IPC message" )
   continue
   if 37 - 37: o0oOOo0O0Ooo
  o0OOoOO = int ( msg [ "instance-id" ] )
  if 57 - 57: iII111i / i1IIi / i1IIi + IiII
  if 75 - 75: IiII / O0
  if 72 - 72: I11i
  if 35 - 35: I11i % OoooooooOO / i1IIi * i1IIi / I1IiiI
  o00oo00oo = lisp_address ( LISP_AFI_NONE , "" , 0 , o0OOoOO )
  o00oo00oo . store_prefix ( oOoo0OooOOo00 )
  Iii1 = lisp_map_cache_lookup ( None , o00oo00oo )
  if ( Iii1 == None ) :
   lprint ( "Map-cache entry for {} not found for stats update" . format ( oOoo0OooOOo00 ) )
   if 42 - 42: I11i - i1IIi - oO0o / I11i + Ii1I + ooOoO0o
   continue
   if 23 - 23: OoOoOO00 . oO0o - iII111i
   if 27 - 27: Oo0Ooo * OOooOOo - OoOoOO00
  if ( msg . has_key ( "rlocs" ) == False ) :
   lprint ( "No 'rlocs' in stats IPC message for {}" . format ( oOoo0OooOOo00 ) )
   if 1 - 1: II111iiii * i11iIiiIii . OoooooooOO
   continue
   if 37 - 37: OoooooooOO + O0 . I11i % OoOoOO00
  if ( type ( msg [ "rlocs" ] ) != list ) :
   lprint ( "'rlocs' in stats IPC message must be an array" )
   continue
   if 57 - 57: I1Ii111 . OOooOOo + I1Ii111 . iIii1I11I1II1 / oO0o / O0
  oo0oOo0oOoO0o = msg [ "rlocs" ]
  if 43 - 43: OoOoOO00 % i11iIiiIii / I11i
  if 5 - 5: I1Ii111 - OOooOOo
  if 83 - 83: oO0o
  if 100 - 100: I1Ii111 + o0oOOo0O0Ooo * oO0o / oO0o . oO0o + iII111i
  for OoO00oo in oo0oOo0oOoO0o :
   if ( OoO00oo . has_key ( "rloc" ) == False ) : continue
   if 38 - 38: I11i - i11iIiiIii
   oooOOoo0 = OoO00oo [ "rloc" ]
   if ( oooOOoo0 == "no-address" ) : continue
   if 38 - 38: I1IiiI * i1IIi / OoO0O00 + iIii1I11I1II1 / I1Ii111 % II111iiii
   oOOoo0O00 = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
   oOOoo0O00 . store_address ( oooOOoo0 )
   if 62 - 62: OoOoOO00 * i1IIi + iII111i
   IIiO0Ooo = Iii1 . get_rloc ( oOOoo0O00 )
   if ( IIiO0Ooo == None ) : continue
   if 43 - 43: OOooOOo % i11iIiiIii / I1ii11iIi11i + i1IIi / ooOoO0o
   if 74 - 74: Ii1I + iIii1I11I1II1
   if 23 - 23: OoO0O00 * i1IIi * oO0o % I1ii11iIi11i
   if 92 - 92: iII111i / I1IiiI / i11iIiiIii
   OOo0000 = 0 if OoO00oo . has_key ( "packet-count" ) == False else OoO00oo [ "packet-count" ]
   if 74 - 74: I1Ii111 * I1Ii111
   i1I11iI11I = 0 if OoO00oo . has_key ( "byte-count" ) == False else OoO00oo [ "byte-count" ]
   if 2 - 2: O0 % oO0o % IiII
   OOOO0O00o = 0 if OoO00oo . has_key ( "seconds-last-packet" ) == False else OoO00oo [ "seconds-last-packet" ]
   if 10 - 10: iIii1I11I1II1
   if 54 - 54: Ii1I * I11i - oO0o . OoOoOO00 - II111iiii
   IIiO0Ooo . stats . packet_count += OOo0000
   IIiO0Ooo . stats . byte_count += i1I11iI11I
   IIiO0Ooo . stats . last_increment = lisp_get_timestamp ( ) - OOOO0O00o
   if 37 - 37: Oo0Ooo * o0oOOo0O0Ooo % I11i * iII111i
   lprint ( "Update stats {}/{}/{}s for {} RLOC {}" . format ( OOo0000 , i1I11iI11I ,
 OOOO0O00o , oOoo0OooOOo00 , oooOOoo0 ) )
   if 59 - 59: o0oOOo0O0Ooo % OoooooooOO - I1IiiI % Ii1I / oO0o * OoO0O00
   if 24 - 24: I1Ii111
   if 84 - 84: I1ii11iIi11i - I1IiiI
   if 93 - 93: IiII . OoooooooOO % iII111i * oO0o + I1IiiI * iIii1I11I1II1
   if 72 - 72: II111iiii
  if ( Iii1 . group . is_null ( ) and Iii1 . has_ttl_elapsed ( ) ) :
   oOoo0OooOOo00 = green ( Iii1 . print_eid_tuple ( ) , False )
   lprint ( "Refresh map-cache entry {}" . format ( oOoo0OooOOo00 ) )
   lisp_send_map_request ( lisp_sockets , lisp_port , None , Iii1 . eid , None )
   if 10 - 10: II111iiii
   if 14 - 14: oO0o . I11i . i1IIi + I1ii11iIi11i
 return
 if 53 - 53: Ii1I
 if 35 - 35: oO0o * i1IIi / IiII / iII111i
 if 19 - 19: I1IiiI + iIii1I11I1II1 * O0 - OOooOOo
 if 32 - 32: O0 - II111iiii - i1IIi + O0 + OOooOOo
 if 44 - 44: I11i * oO0o % OoooooooOO % OoO0O00 / o0oOOo0O0Ooo
 if 37 - 37: OoO0O00 + OoOoOO00 - I1IiiI
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
 if 91 - 91: ooOoO0o
 if 96 - 96: I1IiiI . OOooOOo
def lisp_process_data_plane_decap_stats ( msg , lisp_ipc_socket ) :
 if 94 - 94: OoooooooOO + II111iiii % ooOoO0o - II111iiii / O0
 if 34 - 34: IiII % oO0o
 if 54 - 54: I1IiiI
 if 80 - 80: OoOoOO00 . I1IiiI / I1ii11iIi11i . iII111i
 if 31 - 31: I11i * o0oOOo0O0Ooo
 if ( lisp_i_am_itr ) :
  lprint ( "Send decap-stats IPC message to lisp-etr process" )
  IIi1IIII = "stats%{}" . format ( json . dumps ( msg ) )
  IIi1IIII = lisp_command_ipc ( IIi1IIII , "lisp-itr" )
  lisp_ipc ( IIi1IIII , lisp_ipc_socket , "lisp-etr" )
  return
  if 17 - 17: Ii1I * iIii1I11I1II1
  if 9 - 9: o0oOOo0O0Ooo - IiII
  if 78 - 78: i11iIiiIii . o0oOOo0O0Ooo
  if 72 - 72: Oo0Ooo % II111iiii + O0 * OoOoOO00 - OOooOOo + I1Ii111
  if 23 - 23: I1IiiI - O0 - iII111i . II111iiii / oO0o
  if 1 - 1: I11i . OOooOOo / oO0o % I11i * Oo0Ooo + Oo0Ooo
  if 23 - 23: Ii1I % i1IIi - I1Ii111
  if 95 - 95: OoOoOO00 - ooOoO0o . i1IIi . OoooooooOO
 IIi1IIII = bold ( "IPC" , False )
 lprint ( "Process decap-stats {} message: '{}'" . format ( IIi1IIII , msg ) )
 if 38 - 38: I1IiiI + I1ii11iIi11i - Oo0Ooo . i11iIiiIii - i1IIi
 if ( lisp_i_am_etr ) : msg = json . loads ( msg )
 if 11 - 11: IiII / I1IiiI . I1IiiI
 oo0Ooo00OO0Oo = [ "good-packets" , "ICV-error" , "checksum-error" ,
 "lisp-header-error" , "no-decrypt-key" , "bad-inner-version" ,
 "outer-header-error" ]
 if 23 - 23: iIii1I11I1II1
 for O0000o000o in oo0Ooo00OO0Oo :
  OOo0000 = 0 if msg . has_key ( O0000o000o ) == False else msg [ O0000o000o ] [ "packet-count" ]
  if 21 - 21: o0oOOo0O0Ooo * o0oOOo0O0Ooo - OoOoOO00 % OoOoOO00
  lisp_decap_stats [ O0000o000o ] . packet_count += OOo0000
  if 8 - 8: I1ii11iIi11i
  i1I11iI11I = 0 if msg . has_key ( O0000o000o ) == False else msg [ O0000o000o ] [ "byte-count" ]
  if 5 - 5: OOooOOo * i11iIiiIii % oO0o * ooOoO0o
  lisp_decap_stats [ O0000o000o ] . byte_count += i1I11iI11I
  if 37 - 37: oO0o . IiII + I1ii11iIi11i
  OOOO0O00o = 0 if msg . has_key ( O0000o000o ) == False else msg [ O0000o000o ] [ "seconds-last-packet" ]
  if 57 - 57: ooOoO0o * o0oOOo0O0Ooo . i11iIiiIii . I1Ii111 . i1IIi
  lisp_decap_stats [ O0000o000o ] . last_increment = lisp_get_timestamp ( ) - OOOO0O00o
  if 95 - 95: I1Ii111 % o0oOOo0O0Ooo . I1Ii111
 return
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
 if 80 - 80: O0
 if 16 - 16: OOooOOo - iII111i
 if 5 - 5: o0oOOo0O0Ooo % ooOoO0o % O0 % I1ii11iIi11i + Oo0Ooo
 if 82 - 82: oO0o / iIii1I11I1II1 % ooOoO0o . Ii1I / i1IIi - I1Ii111
 if 15 - 15: I11i - OOooOOo . II111iiii . iIii1I11I1II1
 if 93 - 93: I11i + o0oOOo0O0Ooo / OOooOOo + Ii1I % Oo0Ooo % I1ii11iIi11i
def lisp_process_punt ( punt_socket , lisp_send_sockets , lisp_ephem_port ) :
 o0oo , O0Oo00o0o = punt_socket . recvfrom ( 4000 )
 if 64 - 64: OoOoOO00 / OoO0O00 + oO0o
 Iii11i = json . loads ( o0oo )
 if ( type ( Iii11i ) != dict ) :
  lprint ( "Invalid punt message from {}, not in JSON format" . format ( O0Oo00o0o ) )
  if 16 - 16: I1ii11iIi11i . I1ii11iIi11i
  return
  if 38 - 38: O0 / OoO0O00
 oOo0OOO0Oo00o = bold ( "Punt" , False )
 lprint ( "{} message from '{}': '{}'" . format ( oOo0OOO0Oo00o , O0Oo00o0o , Iii11i ) )
 if 11 - 11: i11iIiiIii / OoO0O00 * OoO0O00 . I1Ii111 - OOooOOo
 if ( Iii11i . has_key ( "type" ) == False ) :
  lprint ( "Punt IPC message has no 'type' key" )
  return
  if 12 - 12: OOooOOo . OoOoOO00 % ooOoO0o
  if 100 - 100: OoOoOO00 . iII111i
  if 50 - 50: iIii1I11I1II1 * OOooOOo . I1IiiI . OoOoOO00 - O0 + Oo0Ooo
  if 89 - 89: IiII - iII111i + IiII
  if 39 - 39: oO0o % I11i . oO0o * I11i
 if ( Iii11i [ "type" ] == "statistics" ) :
  lisp_process_data_plane_stats ( Iii11i , lisp_send_sockets , lisp_ephem_port )
  return
  if 36 - 36: i1IIi / I1ii11iIi11i * iIii1I11I1II1
 if ( Iii11i [ "type" ] == "decap-statistics" ) :
  lisp_process_data_plane_decap_stats ( Iii11i , punt_socket )
  return
  if 44 - 44: Ii1I / I1Ii111
  if 81 - 81: OoooooooOO * I1IiiI * II111iiii . Oo0Ooo
  if 28 - 28: iII111i * I1IiiI + Oo0Ooo % I1ii11iIi11i / OoooooooOO * ooOoO0o
  if 45 - 45: OoO0O00 + iIii1I11I1II1 + ooOoO0o - OoO0O00
  if 22 - 22: I1IiiI
 if ( Iii11i [ "type" ] == "restart" ) :
  lisp_process_data_plane_restart ( )
  return
  if 28 - 28: OoO0O00 / ooOoO0o % OoOoOO00 - Ii1I * i11iIiiIii + I1ii11iIi11i
  if 90 - 90: ooOoO0o * o0oOOo0O0Ooo + Ii1I / I11i % II111iiii
  if 59 - 59: I11i + iII111i + I11i
  if 84 - 84: I1IiiI * Ii1I . I1IiiI % OOooOOo * Ii1I % OoO0O00
  if 72 - 72: OoOoOO00 + o0oOOo0O0Ooo - i1IIi - OoO0O00 % OoOoOO00
 if ( Iii11i [ "type" ] != "discovery" ) :
  lprint ( "Punt IPC message has wrong format" )
  return
  if 42 - 42: oO0o / i1IIi . IiII
 if ( Iii11i . has_key ( "interface" ) == False ) :
  lprint ( "Invalid punt message from {}, required keys missing" . format ( O0Oo00o0o ) )
  if 12 - 12: i11iIiiIii . ooOoO0o
  return
  if 80 - 80: O0 / iIii1I11I1II1 % iII111i * ooOoO0o / i11iIiiIii . OoOoOO00
  if 88 - 88: OoooooooOO . I1IiiI
  if 6 - 6: I1Ii111 - i11iIiiIii - oO0o
  if 7 - 7: i1IIi
  if 6 - 6: OoooooooOO - Oo0Ooo - I1ii11iIi11i
 O0OoO0o = Iii11i [ "interface" ]
 if ( O0OoO0o == "" ) :
  o0OOoOO = int ( Iii11i [ "instance-id" ] )
  if ( o0OOoOO == - 1 ) : return
 else :
  o0OOoOO = lisp_get_interface_instance_id ( O0OoO0o , None )
  if 34 - 34: iII111i + i11iIiiIii . IiII
  if 54 - 54: Oo0Ooo + I11i - iII111i * ooOoO0o % i11iIiiIii . IiII
  if 29 - 29: II111iiii % i11iIiiIii % O0
  if 38 - 38: o0oOOo0O0Ooo * IiII
  if 51 - 51: OoooooooOO . Ii1I % OoooooooOO - I1IiiI + I1Ii111 % oO0o
 Oooo0oo000O0 = None
 if ( Iii11i . has_key ( "source-eid" ) ) :
  I1IiIiIiiiI = Iii11i [ "source-eid" ]
  Oooo0oo000O0 = lisp_address ( LISP_AFI_NONE , I1IiIiIiiiI , 0 , o0OOoOO )
  if ( Oooo0oo000O0 . is_null ( ) ) :
   lprint ( "Invalid source-EID format '{}'" . format ( I1IiIiIiiiI ) )
   return
   if 28 - 28: i11iIiiIii - I1IiiI * OoO0O00
   if 19 - 19: OoooooooOO
 iII1I1iiII11I = None
 if ( Iii11i . has_key ( "dest-eid" ) ) :
  iIIoO0o000 = Iii11i [ "dest-eid" ]
  iII1I1iiII11I = lisp_address ( LISP_AFI_NONE , iIIoO0o000 , 0 , o0OOoOO )
  if ( iII1I1iiII11I . is_null ( ) ) :
   lprint ( "Invalid dest-EID format '{}'" . format ( iIIoO0o000 ) )
   return
   if 57 - 57: o0oOOo0O0Ooo % o0oOOo0O0Ooo % iII111i * OoOoOO00
   if 50 - 50: I1Ii111 + I1Ii111 + I11i - OoOoOO00
   if 65 - 65: oO0o / I11i + iII111i - I1ii11iIi11i
   if 80 - 80: II111iiii . i11iIiiIii
   if 66 - 66: ooOoO0o * iII111i * OOooOOo % OoO0O00 / I1ii11iIi11i
   if 33 - 33: iIii1I11I1II1
   if 52 - 52: iIii1I11I1II1 + O0
   if 84 - 84: OOooOOo / iII111i . I1IiiI / O0 % OOooOOo . iII111i
 if ( Oooo0oo000O0 ) :
  ooo0OO = green ( Oooo0oo000O0 . print_address ( ) , False )
  I11i111 = lisp_db_for_lookups . lookup_cache ( Oooo0oo000O0 , False )
  if ( I11i111 != None ) :
   if 32 - 32: OoO0O00 + OoO0O00 % o0oOOo0O0Ooo / O0
   if 29 - 29: iII111i % I1Ii111
   if 95 - 95: OOooOOo - ooOoO0o % i1IIi / O0 % I11i . IiII
   if 63 - 63: ooOoO0o
   if 22 - 22: OOooOOo . i11iIiiIii + II111iiii - Oo0Ooo % i1IIi / o0oOOo0O0Ooo
   if ( I11i111 . dynamic_eid_configured ( ) ) :
    I111IIiIII = lisp_allow_dynamic_eid ( O0OoO0o , Oooo0oo000O0 )
    if ( I111IIiIII != None and lisp_i_am_itr ) :
     lisp_itr_discover_eid ( I11i111 , Oooo0oo000O0 , O0OoO0o , I111IIiIII )
    else :
     lprint ( ( "Disallow dynamic source-EID {} " + "on interface {}" ) . format ( ooo0OO , O0OoO0o ) )
     if 90 - 90: IiII
     if 38 - 38: i1IIi / ooOoO0o / I11i * I1ii11iIi11i / II111iiii . iIii1I11I1II1
     if 52 - 52: I1ii11iIi11i % ooOoO0o * Ii1I * IiII + IiII / i11iIiiIii
  else :
   lprint ( "Punt from non-EID source {}" . format ( ooo0OO ) )
   if 51 - 51: iIii1I11I1II1 * o0oOOo0O0Ooo % o0oOOo0O0Ooo . Ii1I / OoooooooOO
   if 23 - 23: oO0o * I1IiiI - oO0o - ooOoO0o . IiII / i11iIiiIii
   if 53 - 53: Ii1I * Ii1I . OoOoOO00 . OOooOOo / I1ii11iIi11i % O0
   if 98 - 98: OOooOOo
   if 11 - 11: OOooOOo * iIii1I11I1II1 % IiII - I1IiiI . I11i
   if 29 - 29: OOooOOo % I11i - OOooOOo - OOooOOo * I11i . oO0o
 if ( iII1I1iiII11I ) :
  Iii1 = lisp_map_cache_lookup ( Oooo0oo000O0 , iII1I1iiII11I )
  if ( Iii1 == None or Iii1 . action == LISP_SEND_MAP_REQUEST_ACTION ) :
   if 75 - 75: II111iiii . O0 . I1Ii111 * O0 / OoooooooOO
   if 60 - 60: OOooOOo - Oo0Ooo * OOooOOo / OoO0O00
   if 55 - 55: I1ii11iIi11i * II111iiii * iIii1I11I1II1
   if 38 - 38: iIii1I11I1II1 % I1ii11iIi11i . Ii1I + I1IiiI % i11iIiiIii - i11iIiiIii
   if 62 - 62: I1Ii111 + I1IiiI
   if ( lisp_rate_limit_map_request ( Oooo0oo000O0 , iII1I1iiII11I ) ) : return
   lisp_send_map_request ( lisp_send_sockets , lisp_ephem_port ,
 Oooo0oo000O0 , iII1I1iiII11I , None )
  else :
   ooo0OO = green ( iII1I1iiII11I . print_address ( ) , False )
   lprint ( "Map-cache entry for {} already exists" . format ( ooo0OO ) )
   if 9 - 9: iIii1I11I1II1 / iIii1I11I1II1
   if 24 - 24: OOooOOo . I1IiiI % i11iIiiIii
 return
 if 43 - 43: OoooooooOO . o0oOOo0O0Ooo - I1ii11iIi11i + OoO0O00 . I1Ii111 . iII111i
 if 1 - 1: iII111i / OoO0O00 / OoOoOO00 * Oo0Ooo * OoooooooOO
 if 59 - 59: iII111i
 if 14 - 14: oO0o . IiII + iIii1I11I1II1 - i1IIi
 if 46 - 46: i11iIiiIii * II111iiii / i11iIiiIii % i11iIiiIii * II111iiii + i11iIiiIii
 if 87 - 87: Oo0Ooo + OoO0O00 / II111iiii * OoooooooOO
 if 95 - 95: I1Ii111 * o0oOOo0O0Ooo + OoO0O00 % OoOoOO00 - ooOoO0o / OoOoOO00
def lisp_ipc_map_cache_entry ( mc , jdata ) :
 iIIiI11iI1Ii1 = lisp_write_ipc_map_cache ( True , mc , dont_send = True )
 jdata . append ( iIIiI11iI1Ii1 )
 return ( [ True , jdata ] )
 if 45 - 45: OoooooooOO / oO0o / o0oOOo0O0Ooo + Ii1I + O0 . iII111i
 if 34 - 34: iIii1I11I1II1 . o0oOOo0O0Ooo + ooOoO0o
 if 96 - 96: O0 / ooOoO0o
 if 82 - 82: OoO0O00 * OOooOOo * I11i * I1Ii111 % iIii1I11I1II1
 if 50 - 50: Ii1I * Ii1I % I11i / iIii1I11I1II1 / ooOoO0o / iII111i
 if 91 - 91: Ii1I - O0 . I11i - OoooooooOO * IiII . II111iiii
 if 38 - 38: I1IiiI + OoO0O00
 if 11 - 11: iIii1I11I1II1 + i1IIi * IiII - Oo0Ooo
def lisp_ipc_walk_map_cache ( mc , jdata ) :
 if 66 - 66: I1Ii111 . Ii1I / I1ii11iIi11i / iIii1I11I1II1 + O0 / i1IIi
 if 72 - 72: ooOoO0o . II111iiii
 if 32 - 32: I1Ii111 - oO0o + OoooooooOO . OoOoOO00 + i11iIiiIii / i1IIi
 if 26 - 26: I1IiiI + OoooooooOO % OoOoOO00 . IiII - II111iiii . OoOoOO00
 if ( mc . group . is_null ( ) ) : return ( lisp_ipc_map_cache_entry ( mc , jdata ) )
 if 37 - 37: OoO0O00 % O0 + OoOoOO00 * I11i . Ii1I * OoO0O00
 if ( mc . source_cache == None ) : return ( [ True , jdata ] )
 if 18 - 18: o0oOOo0O0Ooo / OOooOOo
 if 28 - 28: O0 / Ii1I - oO0o % I1ii11iIi11i % O0 . OoO0O00
 if 100 - 100: O0
 if 19 - 19: Ii1I * iIii1I11I1II1 * Oo0Ooo - i11iIiiIii * i11iIiiIii - OOooOOo
 if 88 - 88: O0 . iIii1I11I1II1 . I1ii11iIi11i
 jdata = mc . source_cache . walk_cache ( lisp_ipc_map_cache_entry , jdata )
 return ( [ True , jdata ] )
 if 80 - 80: oO0o / i1IIi * iIii1I11I1II1
 if 38 - 38: Ii1I
 if 20 - 20: iIii1I11I1II1 + Oo0Ooo - Ii1I / i11iIiiIii . OoO0O00
 if 66 - 66: OoooooooOO - Ii1I / iII111i . I1IiiI + I1ii11iIi11i - I1Ii111
 if 36 - 36: I1Ii111 - OoO0O00 . I1ii11iIi11i * I1ii11iIi11i
 if 9 - 9: OOooOOo - oO0o - iIii1I11I1II1 * i11iIiiIii / I11i
 if 2 - 2: i1IIi % iII111i * ooOoO0o / OoOoOO00 + Oo0Ooo
def lisp_itr_discover_eid ( db , eid , input_interface , routed_interface ,
 lisp_ipc_listen_socket ) :
 oOoo0OooOOo00 = eid . print_address ( )
 if ( db . dynamic_eids . has_key ( oOoo0OooOOo00 ) ) :
  db . dynamic_eids [ oOoo0OooOOo00 ] . last_packet = lisp_get_timestamp ( )
  return
  if 59 - 59: i11iIiiIii / I1IiiI * iII111i
  if 16 - 16: i11iIiiIii * II111iiii - ooOoO0o
  if 80 - 80: iIii1I11I1II1 + iIii1I11I1II1 + I1Ii111 - IiII * iII111i - Ii1I
  if 89 - 89: O0 * ooOoO0o
  if 36 - 36: I1ii11iIi11i * II111iiii * iII111i + I1IiiI + OoO0O00 + oO0o
 OoiiI11111II = lisp_dynamic_eid ( )
 OoiiI11111II . dynamic_eid . copy_address ( eid )
 OoiiI11111II . interface = routed_interface
 OoiiI11111II . last_packet = lisp_get_timestamp ( )
 OoiiI11111II . get_timeout ( routed_interface )
 db . dynamic_eids [ oOoo0OooOOo00 ] = OoiiI11111II
 if 28 - 28: Ii1I - i11iIiiIii . oO0o / II111iiii
 O0o000oo00o00 = ""
 if ( input_interface != routed_interface ) :
  O0o000oo00o00 = ", routed-interface " + routed_interface
  if 22 - 22: II111iiii . OoOoOO00 * Ii1I * Ii1I / i11iIiiIii * O0
  if 67 - 67: oO0o / I11i . Oo0Ooo
 IIi1iI = green ( oOoo0OooOOo00 , False ) + bold ( " discovered" , False )
 lprint ( "Dynamic-EID {} on interface {}{}, timeout {}" . format ( IIi1iI , input_interface , O0o000oo00o00 , OoiiI11111II . timeout ) )
 if 45 - 45: I1Ii111 / iIii1I11I1II1 . I1IiiI
 if 60 - 60: OoooooooOO + i11iIiiIii - o0oOOo0O0Ooo . OoooooooOO + oO0o / ooOoO0o
 if 93 - 93: I1ii11iIi11i - ooOoO0o - Oo0Ooo + o0oOOo0O0Ooo . ooOoO0o
 if 98 - 98: II111iiii
 if 56 - 56: i1IIi % IiII / I1Ii111
 IIi1IIII = "learn%{}%{}" . format ( oOoo0OooOOo00 , routed_interface )
 IIi1IIII = lisp_command_ipc ( IIi1IIII , "lisp-itr" )
 lisp_ipc ( IIi1IIII , lisp_ipc_listen_socket , "lisp-etr" )
 return
 if 1 - 1: I1IiiI / OoOoOO00 - oO0o + OoooooooOO
 if 51 - 51: ooOoO0o + Ii1I * o0oOOo0O0Ooo * I1IiiI / oO0o + OoO0O00
 if 92 - 92: oO0o * o0oOOo0O0Ooo % ooOoO0o + OoOoOO00 * OoooooooOO * Oo0Ooo
 if 86 - 86: iII111i / OoooooooOO * I1Ii111 % I1IiiI + Ii1I
 if 16 - 16: OoO0O00
 if 41 - 41: i1IIi
 if 72 - 72: OoooooooOO / i11iIiiIii - O0 . OoOoOO00
 if 41 - 41: IiII + oO0o * iIii1I11I1II1 % oO0o + IiII
 if 64 - 64: I1ii11iIi11i % OoO0O00 + oO0o
 if 47 - 47: I1ii11iIi11i + Ii1I % I1Ii111 % OoO0O00 . IiII % i1IIi
 if 14 - 14: O0 / I1IiiI . I1ii11iIi11i
 if 47 - 47: I1Ii111 * ooOoO0o / iII111i . O0
 if 61 - 61: II111iiii . OoO0O00 * OoO0O00 % II111iiii % OOooOOo * OoOoOO00
def lisp_retry_decap_keys ( addr_str , packet , iv , packet_icv ) :
 if ( lisp_search_decap_keys == False ) : return
 if 82 - 82: Ii1I
 if 83 - 83: I1IiiI
 if 22 - 22: IiII / Ii1I + I1Ii111 % iIii1I11I1II1
 if 75 - 75: OoOoOO00 % OoOoOO00 % o0oOOo0O0Ooo % I1ii11iIi11i + IiII
 if ( addr_str . find ( ":" ) != - 1 ) : return
 if 45 - 45: I11i - iIii1I11I1II1
 iiiIIIII1iIi = lisp_crypto_keys_by_rloc_decap [ addr_str ]
 if 20 - 20: OoOoOO00
 for o0OoOo0o0OOoO0 in lisp_crypto_keys_by_rloc_decap :
  if 84 - 84: OoOoOO00
  if 59 - 59: Ii1I / I1Ii111 + i11iIiiIii
  if 20 - 20: O0 / I1Ii111 - OOooOOo % iIii1I11I1II1
  if 89 - 89: O0 * OoOoOO00 . ooOoO0o
  if ( o0OoOo0o0OOoO0 . find ( addr_str ) == - 1 ) : continue
  if 11 - 11: iIii1I11I1II1 * OoO0O00 . I1IiiI * OoOoOO00 / II111iiii
  if 72 - 72: I11i
  if 7 - 7: i1IIi - o0oOOo0O0Ooo - I1IiiI
  if 62 - 62: OoOoOO00 * oO0o - I1IiiI / Ii1I
  if ( o0OoOo0o0OOoO0 == addr_str ) : continue
  if 48 - 48: o0oOOo0O0Ooo % o0oOOo0O0Ooo - OoOoOO00
  if 13 - 13: OoO0O00 - Ii1I . ooOoO0o / O0 * OoOoOO00
  if 57 - 57: O0 + OoooooooOO % o0oOOo0O0Ooo / I1Ii111 / OOooOOo - OoOoOO00
  if 48 - 48: o0oOOo0O0Ooo - II111iiii + OoOoOO00
  iIIiI11iI1Ii1 = lisp_crypto_keys_by_rloc_decap [ o0OoOo0o0OOoO0 ]
  if ( iIIiI11iI1Ii1 == iiiIIIII1iIi ) : continue
  if 54 - 54: II111iiii - OoO0O00 - o0oOOo0O0Ooo - O0 % I1Ii111
  if 9 - 9: i1IIi % iII111i / Ii1I
  if 83 - 83: oO0o
  if 1 - 1: oO0o * iIii1I11I1II1 % iIii1I11I1II1 % iIii1I11I1II1 / oO0o + IiII
  iI1oO0O00O0oo0 = iIIiI11iI1Ii1 [ 1 ]
  if ( packet_icv != iI1oO0O00O0oo0 . do_icv ( packet , iv ) ) :
   lprint ( "Test ICV with key {} failed" . format ( red ( o0OoOo0o0OOoO0 , False ) ) )
   continue
   if 33 - 33: iII111i + I11i * ooOoO0o / O0
   if 72 - 72: O0 * iIii1I11I1II1 * i1IIi
  lprint ( "Changing decap crypto key to {}" . format ( red ( o0OoOo0o0OOoO0 , False ) ) )
  lisp_crypto_keys_by_rloc_decap [ addr_str ] = iIIiI11iI1Ii1
  if 53 - 53: I11i * ooOoO0o - Oo0Ooo + o0oOOo0O0Ooo
 return
 if 52 - 52: Ii1I % OoOoOO00 / oO0o / OOooOOo
 if 22 - 22: iIii1I11I1II1 * Oo0Ooo % i1IIi % i11iIiiIii + oO0o
 if 94 - 94: OoO0O00 * I1IiiI / O0 + I1Ii111 / i11iIiiIii
 if 34 - 34: Oo0Ooo . i1IIi
 if 97 - 97: I11i
 if 89 - 89: iII111i % OoOoOO00 . Oo0Ooo
 if 20 - 20: oO0o % OoOoOO00
 if 93 - 93: I1ii11iIi11i - Ii1I % i1IIi / i1IIi
def lisp_decent_pull_xtr_configured ( ) :
 return ( lisp_decent_modulus != 0 and lisp_decent_dns_suffix != None )
 if 82 - 82: OOooOOo
 if 27 - 27: I1Ii111 / IiII - i1IIi * Ii1I
 if 90 - 90: ooOoO0o
 if 100 - 100: iII111i * i1IIi . iII111i / O0 / OoO0O00 - oO0o
 if 65 - 65: OoOoOO00 + ooOoO0o * OoO0O00 % OoooooooOO + OoooooooOO * OoooooooOO
 if 49 - 49: o0oOOo0O0Ooo + i1IIi / iII111i
 if 43 - 43: i1IIi . OoO0O00 + I1ii11iIi11i
 if 88 - 88: OoooooooOO / I11i % II111iiii % OOooOOo - I11i
def lisp_is_decent_dns_suffix ( dns_name ) :
 if ( lisp_decent_dns_suffix == None ) : return ( False )
 II1 = dns_name . split ( "." )
 II1 = "." . join ( II1 [ 1 : : ] )
 return ( II1 == lisp_decent_dns_suffix )
 if 55 - 55: Oo0Ooo - OOooOOo - O0
 if 40 - 40: OoOoOO00 - OOooOOo
 if 3 - 3: IiII % I11i * I1Ii111 + iIii1I11I1II1 . oO0o
 if 35 - 35: II111iiii
 if 15 - 15: I11i * iIii1I11I1II1 + OOooOOo % IiII . o0oOOo0O0Ooo % Oo0Ooo
 if 96 - 96: O0
 if 15 - 15: i1IIi . iIii1I11I1II1
def lisp_get_decent_index ( eid ) :
 oOoo0OooOOo00 = eid . print_prefix ( )
 Ii1iIiii11I1 = hashlib . sha256 ( oOoo0OooOOo00 ) . hexdigest ( )
 iI11I = int ( Ii1iIiii11I1 , 16 ) % lisp_decent_modulus
 return ( iI11I )
 if 78 - 78: Oo0Ooo . II111iiii - OoO0O00 - I1Ii111 + Oo0Ooo
 if 71 - 71: O0 + OOooOOo % OoooooooOO
 if 51 - 51: I1ii11iIi11i * o0oOOo0O0Ooo * I11i
 if 27 - 27: OoOoOO00 % OoO0O00 * oO0o . II111iiii - i11iIiiIii
 if 56 - 56: OOooOOo . IiII - OOooOOo / i11iIiiIii * I1ii11iIi11i
 if 66 - 66: oO0o + ooOoO0o
 if 1 - 1: ooOoO0o
def lisp_get_decent_dns_name ( eid ) :
 iI11I = lisp_get_decent_index ( eid )
 return ( str ( iI11I ) + "." + lisp_decent_dns_suffix )
 if 61 - 61: o0oOOo0O0Ooo / OoooooooOO . I1ii11iIi11i + Oo0Ooo
 if 75 - 75: Ii1I
 if 79 - 79: i1IIi . I1ii11iIi11i * o0oOOo0O0Ooo / I11i . I11i / ooOoO0o
 if 99 - 99: oO0o + I11i % i1IIi . iII111i
 if 58 - 58: Oo0Ooo % i11iIiiIii . Oo0Ooo / Oo0Ooo - I1IiiI . Ii1I
 if 65 - 65: OoO0O00
 if 16 - 16: IiII % I1IiiI % iIii1I11I1II1 . I1IiiI . I1ii11iIi11i - IiII
 if 6 - 6: I1Ii111 + OoO0O00 + O0 * OoOoOO00 . iIii1I11I1II1 . I1Ii111
def lisp_get_decent_dns_name_from_str ( iid , eid_str ) :
 o00oo00oo = lisp_address ( LISP_AFI_NONE , eid_str , 0 , iid )
 iI11I = lisp_get_decent_index ( o00oo00oo )
 return ( str ( iI11I ) + "." + lisp_decent_dns_suffix )
 if 93 - 93: ooOoO0o % iIii1I11I1II1 + I1ii11iIi11i
 if 74 - 74: OoOoOO00 + I1ii11iIi11i
 if 82 - 82: II111iiii
 if 55 - 55: I11i . iIii1I11I1II1 / Ii1I - OoO0O00 * I1ii11iIi11i % iIii1I11I1II1
 if 48 - 48: ooOoO0o + Oo0Ooo / Oo0Ooo
 if 15 - 15: iIii1I11I1II1 . I1Ii111 * OoooooooOO * O0 % OOooOOo
 if 53 - 53: Ii1I
 if 63 - 63: I11i % OoOoOO00
 if 46 - 46: iIii1I11I1II1 . II111iiii / OoooooooOO - ooOoO0o * iII111i
 if 52 - 52: I11i + iII111i
def lisp_trace_append ( packet , reason = None , ed = "encap" , lisp_socket = None ,
 rloc_entry = None ) :
 if 9 - 9: OoOoOO00 % II111iiii . I11i * Oo0Ooo
 I11iiIi1i1 = 28 if packet . inner_version == 4 else 48
 OoOo = packet . packet [ I11iiIi1i1 : : ]
 O00OOo = lisp_trace ( )
 if ( O00OOo . decode ( OoOo ) == False ) :
  lprint ( "Could not decode JSON portion of a LISP-Trace packet" )
  return ( False )
  if 92 - 92: oO0o . II111iiii
  if 4 - 4: IiII . i1IIi - i1IIi - O0 - OOooOOo * I1Ii111
 OoOoOOOOoO = "?" if packet . outer_dest . is_null ( ) else packet . outer_dest . print_address_no_iid ( )
 if 64 - 64: OoOoOO00
 if 31 - 31: i11iIiiIii / Ii1I * iII111i * OoooooooOO + OoO0O00
 if 91 - 91: ooOoO0o * o0oOOo0O0Ooo - o0oOOo0O0Ooo * Oo0Ooo
 if 70 - 70: Oo0Ooo . I1IiiI / OoO0O00
 if 65 - 65: o0oOOo0O0Ooo * O0 / IiII + II111iiii + I1ii11iIi11i
 if 94 - 94: I11i / I1ii11iIi11i / I11i + iII111i % oO0o + I1ii11iIi11i
 if ( OoOoOOOOoO != "?" and packet . encap_port != LISP_DATA_PORT ) :
  if ( ed == "encap" ) : OoOoOOOOoO += ":{}" . format ( packet . encap_port )
  if 65 - 65: Oo0Ooo
  if 66 - 66: iII111i . I1ii11iIi11i - Oo0Ooo
  if 84 - 84: IiII + Oo0Ooo / OoooooooOO
  if 20 - 20: IiII . ooOoO0o . I1ii11iIi11i * I1IiiI
  if 84 - 84: IiII / OOooOOo + I1IiiI . IiII % i11iIiiIii % I1IiiI
 iIIiI11iI1Ii1 = { }
 iIIiI11iI1Ii1 [ "node" ] = "ITR" if lisp_i_am_itr else "ETR" if lisp_i_am_etr else "RTR" if lisp_i_am_rtr else "?"
 if 33 - 33: OoOoOO00 - OoO0O00 / OoooooooOO
 oOo0O = packet . outer_source
 if ( oOo0O . is_null ( ) ) : oOo0O = lisp_myrlocs [ 0 ]
 iIIiI11iI1Ii1 [ "srloc" ] = oOo0O . print_address_no_iid ( )
 if 98 - 98: OoO0O00 * iIii1I11I1II1 % I1Ii111
 if 100 - 100: oO0o / OoO0O00
 if 74 - 74: O0 % OOooOOo * OoOoOO00 / oO0o - Oo0Ooo
 if 79 - 79: Ii1I + IiII
 if 21 - 21: o0oOOo0O0Ooo * iII111i * o0oOOo0O0Ooo * o0oOOo0O0Ooo . Oo0Ooo
 if ( iIIiI11iI1Ii1 [ "node" ] == "ITR" and packet . inner_sport != LISP_TRACE_PORT ) :
  iIIiI11iI1Ii1 [ "srloc" ] += ":{}" . format ( packet . inner_sport )
  if 98 - 98: I1ii11iIi11i
  if 58 - 58: IiII / i11iIiiIii % I11i
 iIIiI11iI1Ii1 [ "hn" ] = lisp_hostname
 o0OoOo0o0OOoO0 = ed + "-ts"
 iIIiI11iI1Ii1 [ o0OoOo0o0OOoO0 ] = lisp_get_timestamp ( )
 if 74 - 74: OoooooooOO - I1ii11iIi11i + OOooOOo % IiII . o0oOOo0O0Ooo
 if 21 - 21: Ii1I
 if 72 - 72: I1Ii111 . OoooooooOO / I1Ii111 - Ii1I / I1ii11iIi11i * I1ii11iIi11i
 if 72 - 72: IiII . Ii1I + OoooooooOO * OoOoOO00 + Oo0Ooo . iII111i
 if 92 - 92: O0 * Ii1I - I1ii11iIi11i - IiII . OoO0O00 + I1IiiI
 if 59 - 59: i1IIi * OOooOOo % Oo0Ooo
 if ( OoOoOOOOoO == "?" and iIIiI11iI1Ii1 [ "node" ] == "ETR" ) :
  I11i111 = lisp_db_for_lookups . lookup_cache ( packet . inner_dest , False )
  if ( I11i111 != None and len ( I11i111 . rloc_set ) >= 1 ) :
   OoOoOOOOoO = I11i111 . rloc_set [ 0 ] . rloc . print_address_no_iid ( )
   if 44 - 44: iIii1I11I1II1 . OOooOOo
   if 57 - 57: II111iiii + I1Ii111
 iIIiI11iI1Ii1 [ "drloc" ] = OoOoOOOOoO
 if 42 - 42: OoOoOO00 % O0
 if 70 - 70: iIii1I11I1II1 * Oo0Ooo - I1IiiI / OoO0O00 + OoOoOO00
 if 94 - 94: OoooooooOO + O0 * iIii1I11I1II1 * II111iiii
 if 90 - 90: I11i + O0 / I1IiiI . oO0o / O0
 if ( OoOoOOOOoO == "?" and reason != None ) :
  iIIiI11iI1Ii1 [ "drloc" ] += " ({})" . format ( reason )
  if 46 - 46: O0 . O0 - oO0o . II111iiii * I1IiiI * Ii1I
  if 10 - 10: i1IIi + i1IIi . i1IIi - I1IiiI - I1IiiI
  if 26 - 26: Ii1I * I11i / I11i
  if 79 - 79: ooOoO0o / oO0o - oO0o / OoooooooOO
  if 91 - 91: iIii1I11I1II1 - O0 * o0oOOo0O0Ooo * o0oOOo0O0Ooo . II111iiii
 if ( rloc_entry != None ) :
  iIIiI11iI1Ii1 [ "rtts" ] = rloc_entry . recent_rloc_probe_rtts
  iIIiI11iI1Ii1 [ "hops" ] = rloc_entry . recent_rloc_probe_hops
  if 69 - 69: II111iiii - Oo0Ooo + i1IIi . II111iiii + o0oOOo0O0Ooo
  if 20 - 20: OoooooooOO - OoO0O00 * ooOoO0o * OoOoOO00 / OOooOOo
  if 64 - 64: O0 + iII111i / I11i * OoOoOO00 + o0oOOo0O0Ooo + I1Ii111
  if 16 - 16: I11i
  if 9 - 9: Ii1I / IiII * I11i - i11iIiiIii * I1ii11iIi11i / iII111i
  if 61 - 61: O0 % iII111i
 Oooo0oo000O0 = packet . inner_source . print_address ( )
 iII1I1iiII11I = packet . inner_dest . print_address ( )
 if ( O00OOo . packet_json == [ ] ) :
  IiiiI1IO000Oooo = { }
  IiiiI1IO000Oooo [ "seid" ] = Oooo0oo000O0
  IiiiI1IO000Oooo [ "deid" ] = iII1I1iiII11I
  IiiiI1IO000Oooo [ "paths" ] = [ ]
  O00OOo . packet_json . append ( IiiiI1IO000Oooo )
  if 41 - 41: I1Ii111 * OoooooooOO
  if 76 - 76: OoooooooOO * II111iiii . II111iiii / o0oOOo0O0Ooo - iII111i
  if 49 - 49: O0 . I1ii11iIi11i . OoOoOO00 . I1Ii111 % O0 . iIii1I11I1II1
  if 19 - 19: iIii1I11I1II1
  if 97 - 97: Ii1I . I11i / ooOoO0o + Oo0Ooo
  if 100 - 100: iII111i / I1Ii111 % OoOoOO00 . O0 / OoOoOO00
 for IiiiI1IO000Oooo in O00OOo . packet_json :
  if ( IiiiI1IO000Oooo [ "deid" ] != iII1I1iiII11I ) : continue
  IiiiI1IO000Oooo [ "paths" ] . append ( iIIiI11iI1Ii1 )
  break
  if 81 - 81: OoO0O00 % i11iIiiIii / OoO0O00 + ooOoO0o
  if 100 - 100: O0 . Oo0Ooo % Oo0Ooo % O0 / i11iIiiIii
  if 56 - 56: IiII - OOooOOo - OoOoOO00 - I11i
  if 57 - 57: i1IIi
  if 41 - 41: I11i / Ii1I
  if 1 - 1: II111iiii / iII111i
  if 83 - 83: OoO0O00 / iII111i
  if 59 - 59: I1Ii111 % OOooOOo . I1IiiI + I1ii11iIi11i % oO0o
 oOoOOOO = False
 if ( len ( O00OOo . packet_json ) == 1 and iIIiI11iI1Ii1 [ "node" ] == "ETR" and
 O00OOo . myeid ( packet . inner_dest ) ) :
  IiiiI1IO000Oooo = { }
  IiiiI1IO000Oooo [ "seid" ] = iII1I1iiII11I
  IiiiI1IO000Oooo [ "deid" ] = Oooo0oo000O0
  IiiiI1IO000Oooo [ "paths" ] = [ ]
  O00OOo . packet_json . append ( IiiiI1IO000Oooo )
  oOoOOOO = True
  if 27 - 27: OoOoOO00 . I11i - Ii1I
  if 82 - 82: I1IiiI + OoOoOO00 . II111iiii / OoOoOO00 % OoOoOO00 . I1ii11iIi11i
  if 19 - 19: iIii1I11I1II1 . iIii1I11I1II1 + OOooOOo - I1ii11iIi11i
  if 59 - 59: i11iIiiIii / oO0o * IiII . o0oOOo0O0Ooo % Ii1I
  if 95 - 95: OoooooooOO - I1IiiI * I1ii11iIi11i
  if 52 - 52: oO0o % iII111i - I1IiiI - o0oOOo0O0Ooo
 O00OOo . print_trace ( )
 OoOo = O00OOo . encode ( )
 if 66 - 66: o0oOOo0O0Ooo - Oo0Ooo - OoooooooOO * o0oOOo0O0Ooo + I1Ii111
 if 82 - 82: I11i * i1IIi / Ii1I + O0
 if 85 - 85: O0 + oO0o / I1Ii111
 if 65 - 65: o0oOOo0O0Ooo . Oo0Ooo . i1IIi / IiII . I11i . O0
 if 69 - 69: Oo0Ooo - i11iIiiIii
 if 87 - 87: Oo0Ooo % OOooOOo - Ii1I
 if 34 - 34: iII111i / Ii1I / I1IiiI * i11iIiiIii
 if 41 - 41: Ii1I / Oo0Ooo . OoO0O00 . iIii1I11I1II1 % IiII . I11i
 OoOo00 = O00OOo . packet_json [ 0 ] [ "paths" ] [ 0 ] [ "srloc" ]
 if ( OoOoOOOOoO == "?" ) :
  lprint ( "LISP-Trace return to sender RLOC {}" . format ( OoOo00 ) )
  O00OOo . return_to_sender ( lisp_socket , OoOo00 , OoOo )
  return ( False )
  if 36 - 36: oO0o . I1ii11iIi11i % Oo0Ooo * oO0o + I1IiiI
  if 15 - 15: ooOoO0o - Ii1I * OoOoOO00
  if 80 - 80: i1IIi % OOooOOo - ooOoO0o % iII111i . I1Ii111 + I1ii11iIi11i
  if 9 - 9: OoooooooOO . iII111i . iIii1I11I1II1 . I11i % ooOoO0o % I1IiiI
  if 78 - 78: OoO0O00 - ooOoO0o * I1IiiI * iII111i . i1IIi - OOooOOo
  if 47 - 47: oO0o + ooOoO0o . OoooooooOO / ooOoO0o + i1IIi / I1Ii111
 IiI = O00OOo . packet_length ( )
 if 92 - 92: I1IiiI
 if 56 - 56: I1Ii111 . Oo0Ooo
 if 29 - 29: I1IiiI * Ii1I . OoooooooOO
 if 18 - 18: I11i % iIii1I11I1II1 * OOooOOo
 if 58 - 58: i11iIiiIii / OoOoOO00
 if 18 - 18: ooOoO0o + O0 - OOooOOo + iIii1I11I1II1 . OOooOOo * iIii1I11I1II1
 OO0O0O0OO = packet . packet [ 0 : I11iiIi1i1 ]
 i111 = struct . pack ( "HH" , socket . htons ( IiI ) , 0 )
 OO0O0O0OO = OO0O0O0OO [ 0 : I11iiIi1i1 - 4 ] + i111
 if ( packet . inner_version == 6 and iIIiI11iI1Ii1 [ "node" ] == "ETR" and
 len ( O00OOo . packet_json ) == 2 ) :
  I1iIIIiI = OO0O0O0OO [ I11iiIi1i1 - 8 : : ] + OoOo
  I1iIIIiI = lisp_udp_checksum ( Oooo0oo000O0 , iII1I1iiII11I , I1iIIIiI )
  OO0O0O0OO = OO0O0O0OO [ 0 : I11iiIi1i1 - 8 ] + I1iIIIiI [ 0 : 8 ]
  if 64 - 64: OoOoOO00 + oO0o / OoooooooOO . i11iIiiIii / II111iiii
  if 55 - 55: ooOoO0o . i11iIiiIii . o0oOOo0O0Ooo
  if 52 - 52: IiII . oO0o + i11iIiiIii % IiII
  if 45 - 45: i1IIi - I1IiiI / IiII - I1IiiI
  if 21 - 21: IiII
  if 43 - 43: IiII
 if ( oOoOOOO ) :
  if ( packet . inner_version == 4 ) :
   OO0O0O0OO = OO0O0O0OO [ 0 : 12 ] + OO0O0O0OO [ 16 : 20 ] + OO0O0O0OO [ 12 : 16 ] + OO0O0O0OO [ 22 : 24 ] + OO0O0O0OO [ 20 : 22 ] + OO0O0O0OO [ 24 : : ]
   if 9 - 9: OOooOOo * ooOoO0o + ooOoO0o . I1Ii111
  else :
   OO0O0O0OO = OO0O0O0OO [ 0 : 8 ] + OO0O0O0OO [ 24 : 40 ] + OO0O0O0OO [ 8 : 24 ] + OO0O0O0OO [ 42 : 44 ] + OO0O0O0OO [ 40 : 42 ] + OO0O0O0OO [ 44 : : ]
   if 8 - 8: IiII * iIii1I11I1II1
   if 7 - 7: I1Ii111 / OoooooooOO % O0 - I1ii11iIi11i
  oOo0OOOOOO = packet . inner_dest
  packet . inner_dest = packet . inner_source
  packet . inner_source = oOo0OOOOOO
  if 49 - 49: OoooooooOO . I1ii11iIi11i / OoooooooOO * oO0o
  if 81 - 81: I1ii11iIi11i . ooOoO0o + I1ii11iIi11i
  if 84 - 84: OoooooooOO
  if 95 - 95: o0oOOo0O0Ooo
  if 22 - 22: ooOoO0o / o0oOOo0O0Ooo - OoooooooOO / Oo0Ooo - I1Ii111 / OOooOOo
 I11iiIi1i1 = 2 if packet . inner_version == 4 else 4
 iIiI = 20 + IiI if packet . inner_version == 4 else IiI
 i1Ii111Ii111 = struct . pack ( "H" , socket . htons ( iIiI ) )
 OO0O0O0OO = OO0O0O0OO [ 0 : I11iiIi1i1 ] + i1Ii111Ii111 + OO0O0O0OO [ I11iiIi1i1 + 2 : : ]
 if 5 - 5: Oo0Ooo
 if 23 - 23: i11iIiiIii / I11i + i1IIi % I1Ii111
 if 100 - 100: Oo0Ooo
 if 13 - 13: I1IiiI + ooOoO0o * II111iiii
 if ( packet . inner_version == 4 ) :
  i1 = struct . pack ( "H" , 0 )
  OO0O0O0OO = OO0O0O0OO [ 0 : 10 ] + i1 + OO0O0O0OO [ 12 : : ]
  i1Ii111Ii111 = lisp_ip_checksum ( OO0O0O0OO [ 0 : 20 ] )
  OO0O0O0OO = i1Ii111Ii111 + OO0O0O0OO [ 20 : : ]
  if 32 - 32: iIii1I11I1II1 + O0 + i1IIi
  if 28 - 28: IiII + I11i
  if 1 - 1: OoooooooOO - i11iIiiIii . OoooooooOO - o0oOOo0O0Ooo - OOooOOo * I1Ii111
  if 56 - 56: Ii1I . OoO0O00
  if 43 - 43: iII111i * iII111i
 packet . packet = OO0O0O0OO + OoOo
 return ( True )
 if 31 - 31: O0 - iIii1I11I1II1 . I11i . oO0o
 if 96 - 96: OoooooooOO * iIii1I11I1II1 * Oo0Ooo
 if 76 - 76: OoO0O00 / i11iIiiIii % ooOoO0o % I11i * O0
 if 84 - 84: II111iiii - iII111i / IiII . O0 % i1IIi / I1ii11iIi11i
 if 2 - 2: OoooooooOO . OoO0O00 . II111iiii / Ii1I - OOooOOo % Oo0Ooo
 if 47 - 47: OOooOOo * oO0o
 if 41 - 41: OoooooooOO * I1IiiI
 if 3 - 3: IiII
 if 96 - 96: I11i - OOooOOo + I11i
def lisp_allow_gleaning ( eid , rloc ) :
 if ( lisp_glean_mappings == [ ] ) : return ( False )
 if 71 - 71: Oo0Ooo
 for iIIiI11iI1Ii1 in lisp_glean_mappings :
  if ( iIIiI11iI1Ii1 . has_key ( "instance-id" ) ) :
   o0OOoOO = eid . instance_id
   o0oO , ooOoo = iIIiI11iI1Ii1 [ "instance-id" ]
   if ( o0OOoOO < o0oO or o0OOoOO > ooOoo ) : continue
   if 48 - 48: o0oOOo0O0Ooo / II111iiii / OoOoOO00 * o0oOOo0O0Ooo + I1IiiI . OoOoOO00
  if ( iIIiI11iI1Ii1 . has_key ( "eid-prefix" ) ) :
   ooo0OO = copy . deepcopy ( iIIiI11iI1Ii1 [ "eid-prefix" ] )
   ooo0OO . instance_id = eid . instance_id
   if ( eid . is_more_specific ( ooo0OO ) == False ) : continue
   if 52 - 52: Ii1I / OoOoOO00 . OOooOOo * IiII . OoooooooOO
  if ( iIIiI11iI1Ii1 . has_key ( "rloc-prefix" ) ) :
   if ( rloc != None and rloc . is_more_specific ( iIIiI11iI1Ii1 [ "rloc-prefix" ] )
 == False ) : continue
   if 6 - 6: i1IIi . oO0o % IiII . Oo0Ooo % I11i
  return ( True )
  if 86 - 86: OoooooooOO + IiII % o0oOOo0O0Ooo . i1IIi . iII111i
 return ( False )
 if 25 - 25: iII111i * I1ii11iIi11i + I11i - I1ii11iIi11i
 if 75 - 75: IiII
 if 74 - 74: o0oOOo0O0Ooo - iIii1I11I1II1
 if 92 - 92: i11iIiiIii * iIii1I11I1II1 - I1Ii111 . i1IIi
 if 23 - 23: O0 - O0 . I1Ii111 . I1IiiI - I1IiiI * i1IIi
 if 8 - 8: I1IiiI . I1ii11iIi11i + oO0o % oO0o * oO0o
 if 70 - 70: II111iiii + IiII + O0 / Ii1I - i11iIiiIii
def lisp_glean_map_cache ( eid , rloc , encap_port ) :
 if 72 - 72: II111iiii - II111iiii
 if 44 - 44: o0oOOo0O0Ooo + OoooooooOO
 if 34 - 34: i11iIiiIii + iIii1I11I1II1 - i11iIiiIii * o0oOOo0O0Ooo - iII111i
 if 87 - 87: OOooOOo * OoO0O00
 if 61 - 61: iII111i - II111iiii . I1Ii111 % II111iiii / I11i
 if 86 - 86: II111iiii
 Iii1 = lisp_map_cache . lookup_cache ( eid , True )
 if ( Iii1 ) :
  Iii1 . last_refresh_time = lisp_get_timestamp ( )
  if 94 - 94: o0oOOo0O0Ooo % Ii1I * Ii1I % Oo0Ooo / I1ii11iIi11i
  IIiii1i1IiI = Iii1 . rloc_set [ 0 ]
  if ( IIiii1i1IiI . rloc . is_exact_match ( rloc ) and
 IIiii1i1IiI . translated_port == encap_port ) : return
  if 56 - 56: O0 % i11iIiiIii - O0
  ooo0OO = green ( eid . print_address ( ) , False )
  O00oo00o000o = red ( rloc . print_address_no_iid ( ) + ":" + str ( encap_port ) , False )
  lprint ( "Gleaned EID {} RLOC changed to {}" . format ( ooo0OO , O00oo00o000o ) )
  IIiii1i1IiI . delete_from_rloc_probe_list ( Iii1 . eid , Iii1 . group )
 else :
  Iii1 = lisp_mapping ( "" , "" , [ ] )
  Iii1 . eid . copy_address ( eid )
  Iii1 . mapping_source . copy_address ( rloc )
  Iii1 . map_cache_ttl = LISP_GLEAN_TTL
  Iii1 . gleaned = True
  ooo0OO = green ( eid . print_address ( ) , False )
  O00oo00o000o = red ( rloc . print_address_no_iid ( ) + ":" + str ( encap_port ) , False )
  lprint ( "Add gleaned EID {} to map-cache with RLOC {}" . format ( ooo0OO , O00oo00o000o ) )
  Iii1 . add_cache ( )
  if 24 - 24: o0oOOo0O0Ooo % iII111i
  if 47 - 47: OoooooooOO
  if 65 - 65: I1ii11iIi11i . o0oOOo0O0Ooo * I1Ii111
  if 52 - 52: IiII - ooOoO0o / I11i + OoO0O00 * II111iiii
  if 16 - 16: ooOoO0o - I1ii11iIi11i % oO0o + OoooooooOO - ooOoO0o . OoOoOO00
  if 67 - 67: O0 - o0oOOo0O0Ooo - OOooOOo
 IIiO0Ooo = lisp_rloc ( )
 IIiO0Ooo . store_translated_rloc ( rloc , encap_port )
 IIiO0Ooo . add_to_rloc_probe_list ( Iii1 . eid , Iii1 . group )
 IIiO0Ooo . priority = 253
 IIiO0Ooo . mpriority = 255
 iii1Ii1i1i1I = [ IIiO0Ooo ]
 Iii1 . rloc_set = iii1Ii1i1i1I
 Iii1 . build_best_rloc_set ( )
 if 17 - 17: i1IIi - ooOoO0o + O0 + I1IiiI / I11i / OoO0O00
 if 94 - 94: i1IIi - oO0o - O0 . I1Ii111
 if 86 - 86: i11iIiiIii . i11iIiiIii - iII111i . oO0o % i11iIiiIii
# dd678faae9ac167bc83abf78e5cb2f3f0688d3a3
