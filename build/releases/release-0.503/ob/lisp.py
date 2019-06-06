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
  self . gleaned_dest = False
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
    if ( self . gleaned_dest ) :
     self . udp_sport = LISP_DATA_PORT
    else :
     self . hash_packet ( )
     if 25 - 25: iIii1I11I1II1 % II111iiii / I11i / I1ii11iIi11i
   else :
    self . udp_sport = lisp_crypto_ephem_port
    if 22 - 22: oO0o * iII111i
  else :
   self . udp_sport = LISP_DATA_PORT
   if 4 - 4: OoOoOO00 - oO0o + I1IiiI
  self . udp_dport = self . encap_port
  self . udp_length = len ( self . packet ) + 16
  if 36 - 36: IiII
  if 19 - 19: OoOoOO00 . o0oOOo0O0Ooo . OoooooooOO
  if 13 - 13: OOooOOo . Oo0Ooo / II111iiii
  if 43 - 43: iIii1I11I1II1 % OoO0O00
  if ( self . outer_version == 4 ) :
   oOO0ooi1iiIIiII1 = socket . htons ( self . udp_sport )
   o0O00OooooO = socket . htons ( self . udp_dport )
  else :
   oOO0ooi1iiIIiII1 = self . udp_sport
   o0O00OooooO = self . udp_dport
   if 77 - 77: I1IiiI % ooOoO0o
   if 74 - 74: OoOoOO00 / i1IIi % OoooooooOO
  o0O00OooooO = socket . htons ( self . udp_dport ) if self . outer_version == 4 else self . udp_dport
  if 52 - 52: IiII % ooOoO0o
  if 25 - 25: I11i / I11i % OoooooooOO - I1ii11iIi11i * oO0o
  I1iIIIiI = struct . pack ( "HHHH" , oOO0ooi1iiIIiII1 , o0O00OooooO , socket . htons ( self . udp_length ) ,
 self . udp_checksum )
  if 23 - 23: i11iIiiIii
  if 100 - 100: oO0o + O0 . I1IiiI + i1IIi - OoOoOO00 + o0oOOo0O0Ooo
  if 65 - 65: II111iiii / Oo0Ooo
  if 42 - 42: i11iIiiIii . O0
  o0oo0Oo = self . lisp_header . encode ( )
  if 10 - 10: I1ii11iIi11i
  if 87 - 87: Oo0Ooo % Ii1I
  if 53 - 53: i1IIi - IiII + iIii1I11I1II1
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
  self . packet = O000o0 + I1iIIIiI + o0oo0Oo + self . packet
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
  o0oo0Oo = self . lisp_header . encode ( )
  if 79 - 79: IiII + IiII + Ii1I
  iiiII1i1I = key . do_icv ( o0oo0Oo + O0o + Oo0 , O0o )
  if 97 - 97: O0 . I1Ii111 / II111iiii . O0 + OoooooooOO
  oo0OooO = 4 if ( key . do_poly ) else 8
  if 4 - 4: IiII + iIii1I11I1II1 * iII111i + Oo0Ooo * o0oOOo0O0Ooo % II111iiii
  OO0o0o0oo = bold ( "Encrypt" , False )
  iIiII1 = bold ( key . cipher_suite_string , False )
  addr_str = "RLOC: " + red ( addr_str , False )
  i111iii1I1 = "poly" if key . do_poly else "sha256"
  i111iii1I1 = bold ( i111iii1I1 , False )
  ii = "ICV({}): 0x{}...{}" . format ( i111iii1I1 , iiiII1i1I [ 0 : oo0OooO ] , iiiII1i1I [ - oo0OooO : : ] )
  dprint ( "{} for key-id: {}, {}, {}, {}-time: {} usec" . format ( OO0o0o0oo , key . key_id , addr_str , ii , iIiII1 , OOOO0O00o ) )
  if 47 - 47: i11iIiiIii / Oo0Ooo - Oo0Ooo * OoO0O00
  if 48 - 48: IiII
  iiiII1i1I = int ( iiiII1i1I , 16 )
  if ( key . do_poly ) :
   OOooO = byte_swap_64 ( ( iiiII1i1I >> 64 ) & LISP_8_64_MASK )
   II1i1i1I1iII = byte_swap_64 ( iiiII1i1I & LISP_8_64_MASK )
   iiiII1i1I = struct . pack ( "QQ" , OOooO , II1i1i1I1iII )
  else :
   OOooO = byte_swap_64 ( ( iiiII1i1I >> 96 ) & LISP_8_64_MASK )
   II1i1i1I1iII = byte_swap_64 ( ( iiiII1i1I >> 32 ) & LISP_8_64_MASK )
   I1I = socket . htonl ( iiiII1i1I & 0xffffffff )
   iiiII1i1I = struct . pack ( "QQI" , OOooO , II1i1i1I1iII , I1I )
   if 70 - 70: Ii1I . O0 - OOooOOo
   if 62 - 62: I1Ii111 * I11i
  return ( [ O0o + Oo0 + iiiII1i1I , True ] )
  if 74 - 74: OoOoOO00 . iIii1I11I1II1
  if 87 - 87: ooOoO0o
 def decrypt ( self , packet , header_length , key , addr_str ) :
  if 41 - 41: OoOoOO00 . iIii1I11I1II1 % ooOoO0o + O0
  if 22 - 22: o0oOOo0O0Ooo + Oo0Ooo . ooOoO0o + I1ii11iIi11i * iII111i . i11iIiiIii
  if 90 - 90: OOooOOo * OoOoOO00 - Oo0Ooo + o0oOOo0O0Ooo
  if 53 - 53: OoooooooOO . OoooooooOO + o0oOOo0O0Ooo - iII111i + OOooOOo
  if 44 - 44: I1Ii111 - IiII
  if 100 - 100: oO0o . OoO0O00 - Ii1I + O0 * OoO0O00
  if ( key . do_poly ) :
   OOooO , II1i1i1I1iII = struct . unpack ( "QQ" , packet [ - 16 : : ] )
   oOoOO = byte_swap_64 ( OOooO ) << 64
   oOoOO |= byte_swap_64 ( II1i1i1I1iII )
   oOoOO = lisp_hex_string ( oOoOO ) . zfill ( 32 )
   packet = packet [ 0 : - 16 ]
   oo0OooO = 4
   i11 = bold ( "poly" , False )
  else :
   OOooO , II1i1i1I1iII , I1I = struct . unpack ( "QQI" , packet [ - 20 : : ] )
   oOoOO = byte_swap_64 ( OOooO ) << 96
   oOoOO |= byte_swap_64 ( II1i1i1I1iII ) << 32
   oOoOO |= socket . htonl ( I1I )
   oOoOO = lisp_hex_string ( oOoOO ) . zfill ( 40 )
   packet = packet [ 0 : - 20 ]
   oo0OooO = 8
   i11 = bold ( "sha" , False )
   if 42 - 42: I11i % Oo0Ooo . II111iiii / II111iiii * iII111i
  o0oo0Oo = self . lisp_header . encode ( )
  if 80 - 80: I1Ii111 / i11iIiiIii + OoooooooOO
  if 38 - 38: I1ii11iIi11i % ooOoO0o + i1IIi * OoooooooOO * oO0o
  if 83 - 83: iIii1I11I1II1 - ooOoO0o - I1Ii111 / OoO0O00 - O0
  if 81 - 81: Ii1I - oO0o * I1ii11iIi11i / I1Ii111
  if ( key . cipher_suite == LISP_CS_25519_CHACHA ) :
   iIIi11i = 8
   iIiII1 = bold ( "chacha" , False )
  elif ( key . cipher_suite == LISP_CS_25519_GCM ) :
   iIIi11i = 12
   iIiII1 = bold ( "aes-gcm" , False )
  else :
   iIIi11i = 16
   iIiII1 = bold ( "aes-cbc" , False )
   if 39 - 39: OoOoOO00 . Oo0Ooo - IiII / o0oOOo0O0Ooo / i1IIi
  O0o = packet [ 0 : iIIi11i ]
  if 79 - 79: OOooOOo % I1Ii111 / oO0o - iIii1I11I1II1 - OoOoOO00
  if 60 - 60: II111iiii
  if 90 - 90: OoOoOO00
  if 37 - 37: OoOoOO00 + O0 . O0 * Oo0Ooo % I1Ii111 / iII111i
  iIIi = key . do_icv ( o0oo0Oo + packet , O0o )
  if 98 - 98: oO0o + OoooooooOO - I1Ii111 % i11iIiiIii / o0oOOo0O0Ooo . OoooooooOO
  ooo0 = "0x{}...{}" . format ( oOoOO [ 0 : oo0OooO ] , oOoOO [ - oo0OooO : : ] )
  o0OOo0O = "0x{}...{}" . format ( iIIi [ 0 : oo0OooO ] , iIIi [ - oo0OooO : : ] )
  if 52 - 52: OoooooooOO / IiII % II111iiii
  if ( iIIi != oOoOO ) :
   self . packet_error = "ICV-error"
   Ii11I1I11II = iIiII1 + "/" + i11
   IIiiiI = bold ( "ICV failed ({})" . format ( Ii11I1I11II ) , False )
   ii = "packet-ICV {} != computed-ICV {}" . format ( ooo0 , o0OOo0O )
   dprint ( ( "{} from RLOC {}, receive-port: {}, key-id: {}, " + "packet dropped, {}" ) . format ( IIiiiI , red ( addr_str , False ) ,
   # iII111i / ooOoO0o - i11iIiiIii + OoooooooOO
 self . udp_sport , key . key_id , ii ) )
   dprint ( "{}" . format ( key . print_keys ( ) ) )
   if 33 - 33: O0 + Oo0Ooo - iIii1I11I1II1 % i11iIiiIii / I1IiiI
   if 47 - 47: I1ii11iIi11i * oO0o + iIii1I11I1II1 - oO0o / IiII
   if 86 - 86: IiII
   if 43 - 43: I1IiiI / iII111i / ooOoO0o + iIii1I11I1II1 + OoooooooOO
   if 33 - 33: II111iiii - IiII - ooOoO0o
   if 92 - 92: OoO0O00 * IiII
   lisp_retry_decap_keys ( addr_str , o0oo0Oo + packet , O0o , oOoOO )
   return ( [ None , False ] )
   if 92 - 92: oO0o
   if 7 - 7: iII111i
   if 73 - 73: OoO0O00 % I1ii11iIi11i
   if 32 - 32: OOooOOo + iII111i + iIii1I11I1II1 * Oo0Ooo
   if 62 - 62: i11iIiiIii
  packet = packet [ iIIi11i : : ]
  if 2 - 2: I1IiiI
  if 69 - 69: OoooooooOO / Oo0Ooo * I1Ii111
  if 99 - 99: II111iiii * iIii1I11I1II1 % O0 * oO0o / II111iiii % OoooooooOO
  if 14 - 14: IiII . IiII % ooOoO0o
  OOOO0O00o = lisp_get_timestamp ( )
  if ( key . cipher_suite == LISP_CS_25519_CHACHA ) :
   iII = chacha . ChaCha ( key . encrypt_key , O0o ) . decrypt
  elif ( key . cipher_suite == LISP_CS_25519_GCM ) :
   oOOO0OO = binascii . unhexlify ( key . encrypt_key )
   try :
    iII = AES . new ( oOOO0OO , AES . MODE_GCM , O0o ) . decrypt
   except :
    self . packet_error = "no-decrypt-key"
    lprint ( "You need AES-GCM, do a 'pip install pycryptodome'" )
    return ( [ None , False ] )
    if 67 - 67: I11i / II111iiii / O0 / IiII - I11i - i1IIi
  else :
   if ( ( len ( packet ) % 16 ) != 0 ) :
    dprint ( "Ciphertext not multiple of 16 bytes, packet dropped" )
    return ( [ None , False ] )
    if 8 - 8: i11iIiiIii . iII111i / iIii1I11I1II1 / I1ii11iIi11i / IiII - Ii1I
   oOOO0OO = binascii . unhexlify ( key . encrypt_key )
   iII = AES . new ( oOOO0OO , AES . MODE_CBC , O0o ) . decrypt
   if 32 - 32: o0oOOo0O0Ooo . i1IIi * Oo0Ooo
   if 98 - 98: Ii1I - II111iiii / I1IiiI . oO0o * IiII . I11i
  IiIIIIi = iII ( packet )
  OOOO0O00o = int ( str ( time . time ( ) - OOOO0O00o ) . split ( "." ) [ 1 ] [ 0 : 6 ] )
  if 51 - 51: II111iiii . oO0o . OoO0O00 % II111iiii
  if 41 - 41: OoOoOO00 - OOooOOo + ooOoO0o - i1IIi
  if 6 - 6: II111iiii
  if 7 - 7: i1IIi
  OO0o0o0oo = bold ( "Decrypt" , False )
  addr_str = "RLOC: " + red ( addr_str , False )
  i111iii1I1 = "poly" if key . do_poly else "sha256"
  i111iii1I1 = bold ( i111iii1I1 , False )
  ii = "ICV({}): {}" . format ( i111iii1I1 , ooo0 )
  dprint ( "{} for key-id: {}, {}, {} (good), {}-time: {} usec" . format ( OO0o0o0oo , key . key_id , addr_str , ii , iIiII1 , OOOO0O00o ) )
  if 63 - 63: iIii1I11I1II1 + IiII % i1IIi / I1IiiI % II111iiii
  if 60 - 60: o0oOOo0O0Ooo . OoOoOO00 % I1Ii111 / I1IiiI / O0
  if 19 - 19: i11iIiiIii . I1IiiI + II111iiii / OOooOOo . I1ii11iIi11i * ooOoO0o
  if 59 - 59: iIii1I11I1II1 / I1ii11iIi11i % ooOoO0o
  if 84 - 84: iIii1I11I1II1 / I1IiiI . OoOoOO00 % I11i
  if 99 - 99: Oo0Ooo + i11iIiiIii
  if 36 - 36: Ii1I * I1Ii111 * iIii1I11I1II1 - I11i % i11iIiiIii
  self . packet = self . packet [ 0 : header_length ]
  return ( [ IiIIIIi , True ] )
  if 98 - 98: iIii1I11I1II1 - i1IIi + ooOoO0o % I11i + ooOoO0o / oO0o
  if 97 - 97: IiII % ooOoO0o + II111iiii - IiII % OoO0O00 + ooOoO0o
 def fragment_outer ( self , outer_hdr , inner_packet ) :
  iIIII11i = 1000
  if 97 - 97: OoOoOO00 % ooOoO0o . oO0o
  if 67 - 67: Ii1I / i11iIiiIii
  if 5 - 5: O0 - I1IiiI
  if 44 - 44: II111iiii . II111iiii + OOooOOo * Ii1I
  if 16 - 16: II111iiii
  oooOO0OO0 = [ ]
  I11iiIi1i1 = 0
  o00OOo00 = len ( inner_packet )
  while ( I11iiIi1i1 < o00OOo00 ) :
   IiI1IiI1iiI1 = inner_packet [ I11iiIi1i1 : : ]
   if ( len ( IiI1IiI1iiI1 ) > iIIII11i ) : IiI1IiI1iiI1 = IiI1IiI1iiI1 [ 0 : iIIII11i ]
   oooOO0OO0 . append ( IiI1IiI1iiI1 )
   I11iiIi1i1 += len ( IiI1IiI1iiI1 )
   if 10 - 10: I1IiiI / I1ii11iIi11i
   if 68 - 68: OOooOOo - OoooooooOO
   if 14 - 14: O0 / oO0o - Oo0Ooo - IiII
   if 44 - 44: OoO0O00
   if 32 - 32: OoOoOO00 % OoO0O00 + i11iIiiIii + ooOoO0o - Ii1I + oO0o
   if 31 - 31: iIii1I11I1II1 - o0oOOo0O0Ooo
  oOOo00Ooo0O = [ ]
  I11iiIi1i1 = 0
  for IiI1IiI1iiI1 in oooOO0OO0 :
   if 34 - 34: II111iiii
   if 49 - 49: I11i . OOooOOo
   if 74 - 74: i1IIi
   if 15 - 15: i1IIi + IiII % I1IiiI / i11iIiiIii * OoOoOO00
   oO = I11iiIi1i1 if ( IiI1IiI1iiI1 == oooOO0OO0 [ - 1 ] ) else 0x2000 + I11iiIi1i1
   oO = socket . htons ( oO )
   outer_hdr = outer_hdr [ 0 : 6 ] + struct . pack ( "H" , oO ) + outer_hdr [ 8 : : ]
   if 13 - 13: i1IIi
   if 48 - 48: O0 + OoO0O00 . iII111i * o0oOOo0O0Ooo * iII111i
   if 69 - 69: OoO0O00 - OoooooooOO - OOooOOo % I11i / OoOoOO00 - II111iiii
   if 67 - 67: OOooOOo + OOooOOo + OoO0O00 . i11iIiiIii + I1ii11iIi11i + i11iIiiIii
   IIi11I1i1I1I = socket . htons ( len ( IiI1IiI1iiI1 ) + 20 )
   outer_hdr = outer_hdr [ 0 : 2 ] + struct . pack ( "H" , IIi11I1i1I1I ) + outer_hdr [ 4 : : ]
   outer_hdr = lisp_ip_checksum ( outer_hdr )
   oOOo00Ooo0O . append ( outer_hdr + IiI1IiI1iiI1 )
   I11iiIi1i1 += len ( IiI1IiI1iiI1 ) / 8
   if 35 - 35: O0 + Oo0Ooo - I1IiiI % Ii1I % II111iiii
  return ( oOOo00Ooo0O )
  if 77 - 77: I1Ii111 + oO0o
  if 38 - 38: I1ii11iIi11i - Ii1I * o0oOOo0O0Ooo
 def fragment ( self ) :
  i1II1IiiIi = self . fix_outer_header ( self . packet )
  if 13 - 13: I1IiiI * oO0o
  if 41 - 41: IiII
  if 16 - 16: iIii1I11I1II1
  if 94 - 94: ooOoO0o % I11i % i1IIi
  if 90 - 90: Ii1I * OoO0O00
  if 7 - 7: iII111i . Ii1I . iII111i - I1Ii111
  o00OOo00 = len ( i1II1IiiIi )
  if ( o00OOo00 <= 1500 ) : return ( [ i1II1IiiIi ] , "Fragment-None" )
  if 33 - 33: ooOoO0o + OoooooooOO - OoO0O00 / i1IIi / OoooooooOO
  i1II1IiiIi = self . packet
  if 82 - 82: I1ii11iIi11i / OOooOOo - iII111i / Oo0Ooo * OoO0O00
  if 55 - 55: OoooooooOO
  if 73 - 73: OoOoOO00 - I1ii11iIi11i % Oo0Ooo + I1ii11iIi11i - O0 . OoO0O00
  if 38 - 38: O0
  if 79 - 79: i1IIi . oO0o
  if ( self . inner_version != 4 ) :
   i1i1i11iI11II = random . randint ( 0 , 0xffff )
   II1 = i1II1IiiIi [ 0 : 4 ] + struct . pack ( "H" , i1i1i11iI11II ) + i1II1IiiIi [ 6 : 20 ]
   iiI1iI = i1II1IiiIi [ 20 : : ]
   oOOo00Ooo0O = self . fragment_outer ( II1 , iiI1iI )
   return ( oOOo00Ooo0O , "Fragment-Outer" )
   if 74 - 74: IiII - O0 / I1Ii111 * Ii1I % ooOoO0o . I1Ii111
   if 60 - 60: I1ii11iIi11i . II111iiii * i11iIiiIii . o0oOOo0O0Ooo
   if 66 - 66: iII111i / i11iIiiIii * O0
   if 78 - 78: IiII - I11i % O0 - OOooOOo % OoO0O00
   if 43 - 43: OoO0O00
  OoOooO = 56 if ( self . outer_version == 6 ) else 36
  II1 = i1II1IiiIi [ 0 : OoOooO ]
  I1I1i11iiiiI = i1II1IiiIi [ OoOooO : OoOooO + 20 ]
  iiI1iI = i1II1IiiIi [ OoOooO + 20 : : ]
  if 66 - 66: oO0o / OoOoOO00
  if 13 - 13: II111iiii
  if 55 - 55: Oo0Ooo % i1IIi * I11i
  if 95 - 95: OOooOOo / II111iiii - o0oOOo0O0Ooo % I1Ii111 . I11i
  oo0o = struct . unpack ( "H" , I1I1i11iiiiI [ 6 : 8 ] ) [ 0 ]
  oo0o = socket . ntohs ( oo0o )
  if ( oo0o & 0x4000 ) :
   o0o00O = bold ( "DF-bit set" , False )
   dprint ( "{} in inner header, packet discarded" . format ( o0o00O ) )
   return ( [ ] , "Fragment-None-DF-bit" )
   if 46 - 46: OoOoOO00
   if 4 - 4: iII111i + O0
  I11iiIi1i1 = 0
  o00OOo00 = len ( iiI1iI )
  oOOo00Ooo0O = [ ]
  while ( I11iiIi1i1 < o00OOo00 ) :
   oOOo00Ooo0O . append ( iiI1iI [ I11iiIi1i1 : I11iiIi1i1 + 1400 ] )
   I11iiIi1i1 += 1400
   if 28 - 28: IiII + i11iIiiIii + OoooooooOO / OoO0O00
   if 6 - 6: I1IiiI - i11iIiiIii
   if 61 - 61: I1Ii111 * I1ii11iIi11i % I1IiiI % OoO0O00 % I11i + I11i
   if 6 - 6: Oo0Ooo
   if 73 - 73: I1Ii111 * I1ii11iIi11i + o0oOOo0O0Ooo - Oo0Ooo . I11i
  oooOO0OO0 = oOOo00Ooo0O
  oOOo00Ooo0O = [ ]
  o0oOOO = True if oo0o & 0x2000 else False
  oo0o = ( oo0o & 0x1fff ) * 8
  for IiI1IiI1iiI1 in oooOO0OO0 :
   if 62 - 62: Ii1I - oO0o % iIii1I11I1II1
   if 57 - 57: OoooooooOO / OoOoOO00
   if 44 - 44: OoOoOO00 * i1IIi * O0
   if 94 - 94: I1IiiI - O0
   I1iIi = oo0o / 8
   if ( o0oOOO ) :
    I1iIi |= 0x2000
   elif ( IiI1IiI1iiI1 != oooOO0OO0 [ - 1 ] ) :
    I1iIi |= 0x2000
    if 62 - 62: iIii1I11I1II1
   I1iIi = socket . htons ( I1iIi )
   I1I1i11iiiiI = I1I1i11iiiiI [ 0 : 6 ] + struct . pack ( "H" , I1iIi ) + I1I1i11iiiiI [ 8 : : ]
   if 4 - 4: I1ii11iIi11i * I11i . I11i . II111iiii / OOooOOo
   if 86 - 86: oO0o % O0 + OoO0O00
   if 52 - 52: Oo0Ooo / iII111i
   if 42 - 42: iIii1I11I1II1 * Ii1I / OoO0O00 + OOooOOo
   if 48 - 48: OoooooooOO - I1Ii111 . i11iIiiIii * iII111i - Ii1I - o0oOOo0O0Ooo
   if 59 - 59: iII111i / I11i . Oo0Ooo
   o00OOo00 = len ( IiI1IiI1iiI1 )
   oo0o += o00OOo00
   IIi11I1i1I1I = socket . htons ( o00OOo00 + 20 )
   I1I1i11iiiiI = I1I1i11iiiiI [ 0 : 2 ] + struct . pack ( "H" , IIi11I1i1I1I ) + I1I1i11iiiiI [ 4 : 10 ] + struct . pack ( "H" , 0 ) + I1I1i11iiiiI [ 12 : : ]
   if 100 - 100: O0
   I1I1i11iiiiI = lisp_ip_checksum ( I1I1i11iiiiI )
   oOOO00Oo = I1I1i11iiiiI + IiI1IiI1iiI1
   if 48 - 48: II111iiii + II111iiii * i1IIi / Ii1I
   if 37 - 37: iIii1I11I1II1 % I11i / IiII
   if 37 - 37: I1Ii111 - oO0o - OoO0O00
   if 42 - 42: iIii1I11I1II1 % Ii1I - I1ii11iIi11i + iIii1I11I1II1
   if 27 - 27: O0 / OoO0O00
   o00OOo00 = len ( oOOO00Oo )
   if ( self . outer_version == 4 ) :
    IIi11I1i1I1I = o00OOo00 + OoOooO
    o00OOo00 += 16
    II1 = II1 [ 0 : 2 ] + struct . pack ( "H" , IIi11I1i1I1I ) + II1 [ 4 : : ]
    if 99 - 99: Ii1I - IiII * iIii1I11I1II1 . II111iiii
    II1 = lisp_ip_checksum ( II1 )
    oOOO00Oo = II1 + oOOO00Oo
    oOOO00Oo = self . fix_outer_header ( oOOO00Oo )
    if 56 - 56: iIii1I11I1II1 % OoO0O00 . ooOoO0o % IiII . I1Ii111 * Oo0Ooo
    if 41 - 41: iIii1I11I1II1 % IiII * oO0o - ooOoO0o
    if 5 - 5: OoO0O00 + OoO0O00 + II111iiii * iIii1I11I1II1 + OoooooooOO
    if 77 - 77: O0 * I1ii11iIi11i * oO0o + OoO0O00 + I1ii11iIi11i - I1Ii111
    if 10 - 10: I1ii11iIi11i + IiII
   Ooooo00 = OoOooO - 12
   IIi11I1i1I1I = socket . htons ( o00OOo00 )
   oOOO00Oo = oOOO00Oo [ 0 : Ooooo00 ] + struct . pack ( "H" , IIi11I1i1I1I ) + oOOO00Oo [ Ooooo00 + 2 : : ]
   if 99 - 99: I1ii11iIi11i - oO0o
   oOOo00Ooo0O . append ( oOOO00Oo )
   if 10 - 10: II111iiii . OoO0O00
  return ( oOOo00Ooo0O , "Fragment-Inner" )
  if 89 - 89: ooOoO0o * Ii1I
  if 93 - 93: i1IIi . Ii1I * I1Ii111 . ooOoO0o
 def fix_outer_header ( self , packet ) :
  if 54 - 54: iII111i . i1IIi . I1ii11iIi11i * o0oOOo0O0Ooo % iII111i
  if 30 - 30: I11i
  if 85 - 85: II111iiii + ooOoO0o * I11i
  if 12 - 12: Ii1I . I1IiiI % o0oOOo0O0Ooo
  if 28 - 28: Ii1I - I1IiiI % OoO0O00 * I1Ii111
  if 80 - 80: OOooOOo * IiII
  if 4 - 4: iIii1I11I1II1 . I1Ii111 + II111iiii % OoooooooOO
  if 82 - 82: OoooooooOO / ooOoO0o * I11i * O0 . I1ii11iIi11i
  if ( self . outer_version == 4 or self . inner_version == 4 ) :
   if ( lisp_is_macos ( ) ) :
    packet = packet [ 0 : 2 ] + packet [ 3 ] + packet [ 2 ] + packet [ 4 : 6 ] + packet [ 7 ] + packet [ 6 ] + packet [ 8 : : ]
    if 21 - 21: II111iiii + Oo0Ooo
   else :
    packet = packet [ 0 : 2 ] + packet [ 3 ] + packet [ 2 ] + packet [ 4 : : ]
    if 59 - 59: OOooOOo + I1IiiI / II111iiii / OoOoOO00
    if 80 - 80: OoOoOO00 + iIii1I11I1II1 . IiII
  return ( packet )
  if 76 - 76: I1IiiI * OOooOOo
  if 12 - 12: iIii1I11I1II1 / I11i % Ii1I
 def send_packet ( self , lisp_raw_socket , dest ) :
  if ( lisp_flow_logging and dest != self . inner_dest ) : self . log_flow ( True )
  if 49 - 49: OoO0O00 + II111iiii / IiII - O0 % Ii1I
  dest = dest . print_address_no_iid ( )
  oOOo00Ooo0O , iII1i1 = self . fragment ( )
  if 34 - 34: OoO0O00 / OoooooooOO - oO0o / oO0o * I1IiiI
  for oOOO00Oo in oOOo00Ooo0O :
   if ( len ( oOOo00Ooo0O ) != 1 ) :
    self . packet = oOOO00Oo
    self . print_packet ( iII1i1 , True )
    if 61 - 61: I11i
    if 81 - 81: I11i
   try : lisp_raw_socket . sendto ( oOOO00Oo , ( dest , 0 ) )
   except socket . error , ooo0OO :
    lprint ( "socket.sendto() failed: {}" . format ( ooo0OO ) )
    if 92 - 92: OOooOOo - Oo0Ooo - OoooooooOO / IiII - i1IIi
    if 81 - 81: i1IIi / I1Ii111 % i11iIiiIii . iIii1I11I1II1 * OoOoOO00 + OoooooooOO
    if 31 - 31: i1IIi % II111iiii
    if 13 - 13: iIii1I11I1II1 - II111iiii % O0 . Ii1I % OoO0O00
 def send_l2_packet ( self , l2_socket , mac_header ) :
  if ( l2_socket == None ) :
   lprint ( "No layer-2 socket, drop IPv6 packet" )
   return
   if 2 - 2: OoooooooOO - Ii1I % oO0o / I1IiiI / o0oOOo0O0Ooo
  if ( mac_header == None ) :
   lprint ( "Could not build MAC header, drop IPv6 packet" )
   return
   if 3 - 3: II111iiii / OOooOOo
   if 48 - 48: ooOoO0o . I1ii11iIi11i
  i1II1IiiIi = mac_header + self . packet
  if 49 - 49: i1IIi - OoOoOO00 . Oo0Ooo + iIii1I11I1II1 - ooOoO0o / Oo0Ooo
  if 24 - 24: oO0o - iII111i / ooOoO0o
  if 10 - 10: OoOoOO00 * i1IIi
  if 15 - 15: I11i + i1IIi - II111iiii % I1IiiI
  if 34 - 34: I1IiiI
  if 57 - 57: OOooOOo . Ii1I % o0oOOo0O0Ooo
  if 32 - 32: I11i / IiII - O0 * iIii1I11I1II1
  if 70 - 70: OoooooooOO % OoooooooOO % OoO0O00
  if 98 - 98: OoO0O00
  if 18 - 18: I11i + Oo0Ooo - OoO0O00 / I1Ii111 / OOooOOo
  if 53 - 53: OOooOOo + o0oOOo0O0Ooo . oO0o / I11i
  l2_socket . write ( i1II1IiiIi )
  return
  if 52 - 52: I1Ii111 + I1Ii111
  if 73 - 73: o0oOOo0O0Ooo . i11iIiiIii % OoooooooOO + ooOoO0o . OoooooooOO / OOooOOo
 def bridge_l2_packet ( self , eid , db ) :
  try : oOiiI1i11I = db . dynamic_eids [ eid . print_address_no_iid ( ) ]
  except : return
  try : I111IIiIII = lisp_myinterfaces [ oOiiI1i11I . interface ]
  except : return
  try :
   socket = I111IIiIII . get_bridge_socket ( )
   if ( socket == None ) : return
  except : return
  if 31 - 31: II111iiii + OOooOOo - OoooooooOO . I11i
  try : socket . send ( self . packet )
  except socket . error , ooo0OO :
   lprint ( "bridge_l2_packet(): socket.send() failed: {}" . format ( ooo0OO ) )
   if 28 - 28: Ii1I . I1ii11iIi11i
   if 77 - 77: I1ii11iIi11i % II111iiii
   if 81 - 81: OoOoOO00 % Ii1I / O0 * iIii1I11I1II1 % IiII . I1IiiI
 def is_lisp_packet ( self , packet ) :
  I1iIIIiI = ( struct . unpack ( "B" , packet [ 9 ] ) [ 0 ] == LISP_UDP_PROTOCOL )
  if ( I1iIIIiI == False ) : return ( False )
  if 90 - 90: o0oOOo0O0Ooo
  IIiII = struct . unpack ( "H" , packet [ 22 : 24 ] ) [ 0 ]
  if ( socket . ntohs ( IIiII ) == LISP_DATA_PORT ) : return ( True )
  IIiII = struct . unpack ( "H" , packet [ 20 : 22 ] ) [ 0 ]
  if ( socket . ntohs ( IIiII ) == LISP_DATA_PORT ) : return ( True )
  return ( False )
  if 39 - 39: o0oOOo0O0Ooo / IiII - iII111i
  if 96 - 96: I11i * I1ii11iIi11i * Ii1I + I1ii11iIi11i % I1IiiI + i11iIiiIii
 def decode ( self , is_lisp_packet , lisp_ipc_socket , stats ) :
  self . packet_error = ""
  i1II1IiiIi = self . packet
  i1iI11Ii1i = len ( i1II1IiiIi )
  Ii = i1Iii = True
  if 48 - 48: OOooOOo
  if 26 - 26: iII111i * I1Ii111 * oO0o * OoOoOO00
  if 48 - 48: iII111i % i11iIiiIii . OoooooooOO * IiII % OoO0O00 . iII111i
  if 6 - 6: O0 . ooOoO0o - oO0o / i11iIiiIii
  O00O0 = 0
  o0OOoOO = self . lisp_header . get_instance_id ( )
  if ( is_lisp_packet ) :
   O00o0O = struct . unpack ( "B" , i1II1IiiIi [ 0 : 1 ] ) [ 0 ]
   self . outer_version = O00o0O >> 4
   if ( self . outer_version == 4 ) :
    if 73 - 73: OoO0O00
    if 28 - 28: OoooooooOO - I11i
    if 84 - 84: II111iiii
    if 36 - 36: OOooOOo - OoOoOO00 - iIii1I11I1II1
    if 10 - 10: I1ii11iIi11i / Ii1I * i1IIi % O0 + I11i
    I1i1ii1ii = struct . unpack ( "H" , i1II1IiiIi [ 10 : 12 ] ) [ 0 ]
    i1II1IiiIi = lisp_ip_checksum ( i1II1IiiIi )
    oOOoo0 = struct . unpack ( "H" , i1II1IiiIi [ 10 : 12 ] ) [ 0 ]
    if ( oOOoo0 != 0 ) :
     if ( I1i1ii1ii != 0 or lisp_is_macos ( ) == False ) :
      self . packet_error = "checksum-error"
      if ( stats ) :
       stats [ self . packet_error ] . increment ( i1iI11Ii1i )
       if 32 - 32: IiII / OoooooooOO
       if 30 - 30: OoOoOO00 / I1IiiI - OoO0O00 - iII111i - i11iIiiIii
      lprint ( "IPv4 header checksum failed for outer header" )
      if ( lisp_flow_logging ) : self . log_flow ( False )
      return ( None )
      if 84 - 84: i1IIi - I1IiiI % iII111i
      if 80 - 80: o0oOOo0O0Ooo % iII111i
      if 80 - 80: Ii1I
    iioOO = LISP_AFI_IPV4
    I11iiIi1i1 = 12
    self . outer_tos = struct . unpack ( "B" , i1II1IiiIi [ 1 : 2 ] ) [ 0 ]
    self . outer_ttl = struct . unpack ( "B" , i1II1IiiIi [ 8 : 9 ] ) [ 0 ]
    O00O0 = 20
   elif ( self . outer_version == 6 ) :
    iioOO = LISP_AFI_IPV6
    I11iiIi1i1 = 8
    I1OO = struct . unpack ( "H" , i1II1IiiIi [ 0 : 2 ] ) [ 0 ]
    self . outer_tos = ( socket . ntohs ( I1OO ) >> 4 ) & 0xff
    self . outer_ttl = struct . unpack ( "B" , i1II1IiiIi [ 7 : 8 ] ) [ 0 ]
    O00O0 = 40
   else :
    self . packet_error = "outer-header-error"
    if ( stats ) : stats [ self . packet_error ] . increment ( i1iI11Ii1i )
    lprint ( "Cannot decode outer header" )
    return ( None )
    if 34 - 34: I1Ii111 . OoOoOO00 / i11iIiiIii / iII111i
    if 46 - 46: Oo0Ooo + II111iiii * I1IiiI + OOooOOo
   self . outer_source . afi = iioOO
   self . outer_dest . afi = iioOO
   I11II11IiI11 = self . outer_source . addr_length ( )
   if 97 - 97: ooOoO0o / iIii1I11I1II1 % ooOoO0o / I1IiiI * iII111i % OoOoOO00
   self . outer_source . unpack_address ( i1II1IiiIi [ I11iiIi1i1 : I11iiIi1i1 + I11II11IiI11 ] )
   I11iiIi1i1 += I11II11IiI11
   self . outer_dest . unpack_address ( i1II1IiiIi [ I11iiIi1i1 : I11iiIi1i1 + I11II11IiI11 ] )
   i1II1IiiIi = i1II1IiiIi [ O00O0 : : ]
   self . outer_source . mask_len = self . outer_source . host_mask_len ( )
   self . outer_dest . mask_len = self . outer_dest . host_mask_len ( )
   if 17 - 17: iIii1I11I1II1
   if 89 - 89: i1IIi . i1IIi
   if 10 - 10: iII111i % Oo0Ooo
   if 48 - 48: OOooOOo + I1Ii111 % OOooOOo
   Ooo0o0000OO = struct . unpack ( "H" , i1II1IiiIi [ 0 : 2 ] ) [ 0 ]
   self . udp_sport = socket . ntohs ( Ooo0o0000OO )
   Ooo0o0000OO = struct . unpack ( "H" , i1II1IiiIi [ 2 : 4 ] ) [ 0 ]
   self . udp_dport = socket . ntohs ( Ooo0o0000OO )
   Ooo0o0000OO = struct . unpack ( "H" , i1II1IiiIi [ 4 : 6 ] ) [ 0 ]
   self . udp_length = socket . ntohs ( Ooo0o0000OO )
   Ooo0o0000OO = struct . unpack ( "H" , i1II1IiiIi [ 6 : 8 ] ) [ 0 ]
   self . udp_checksum = socket . ntohs ( Ooo0o0000OO )
   i1II1IiiIi = i1II1IiiIi [ 8 : : ]
   if 8 - 8: I1ii11iIi11i % oO0o / Ii1I
   if 37 - 37: oO0o % I1Ii111 % oO0o
   if 14 - 14: OoO0O00 / I1IiiI
   if 66 - 66: Oo0Ooo / i11iIiiIii % ooOoO0o
   Ii = ( self . udp_dport == LISP_DATA_PORT or
 self . udp_sport == LISP_DATA_PORT )
   i1Iii = ( self . udp_dport in ( LISP_L2_DATA_PORT , LISP_VXLAN_DATA_PORT ) )
   if 43 - 43: OOooOOo
   if 84 - 84: OOooOOo . IiII . iII111i
   if 2 - 2: Oo0Ooo - OoOoOO00
   if 49 - 49: Ii1I + II111iiii / oO0o - OoOoOO00 % OoOoOO00 + I1IiiI
   if ( self . lisp_header . decode ( i1II1IiiIi ) == False ) :
    self . packet_error = "lisp-header-error"
    if ( stats ) : stats [ self . packet_error ] . increment ( i1iI11Ii1i )
    if 54 - 54: ooOoO0o % Oo0Ooo - OOooOOo
    if ( lisp_flow_logging ) : self . log_flow ( False )
    lprint ( "Cannot decode LISP header" )
    return ( None )
    if 16 - 16: I1ii11iIi11i * iII111i / I11i
   i1II1IiiIi = i1II1IiiIi [ 8 : : ]
   o0OOoOO = self . lisp_header . get_instance_id ( )
   O00O0 += 16
   if 46 - 46: II111iiii
  if ( o0OOoOO == 0xffffff ) : o0OOoOO = 0
  if 13 - 13: IiII + II111iiii % I1IiiI
  if 30 - 30: OoooooooOO - i11iIiiIii + oO0o / Oo0Ooo - i11iIiiIii
  if 74 - 74: O0 . I11i
  if 64 - 64: ooOoO0o / i1IIi % iII111i
  OOoOo0O0 = False
  I1o0 = self . lisp_header . k_bits
  if ( I1o0 ) :
   I1iiIiiii1111 = lisp_get_crypto_decap_lookup_key ( self . outer_source ,
 self . udp_sport )
   if ( I1iiIiiii1111 == None ) :
    self . packet_error = "no-decrypt-key"
    if ( stats ) : stats [ self . packet_error ] . increment ( i1iI11Ii1i )
    if 26 - 26: iII111i * iIii1I11I1II1 + II111iiii / I1IiiI
    self . print_packet ( "Receive" , is_lisp_packet )
    O0OO = bold ( "No key available" , False )
    dprint ( "{} for key-id {} to decrypt packet" . format ( O0OO , I1o0 ) )
    if ( lisp_flow_logging ) : self . log_flow ( False )
    return ( None )
    if 77 - 77: Ii1I % OOooOOo / oO0o
    if 91 - 91: OoO0O00 / OoO0O00 . II111iiii . ooOoO0o - I1IiiI
   iii11 = lisp_crypto_keys_by_rloc_decap [ I1iiIiiii1111 ] [ I1o0 ]
   if ( iii11 == None ) :
    self . packet_error = "no-decrypt-key"
    if ( stats ) : stats [ self . packet_error ] . increment ( i1iI11Ii1i )
    if 59 - 59: Oo0Ooo / i11iIiiIii * I1IiiI + OoO0O00
    self . print_packet ( "Receive" , is_lisp_packet )
    O0OO = bold ( "No key available" , False )
    dprint ( "{} to decrypt packet from RLOC {}" . format ( O0OO ,
 red ( I1iiIiiii1111 , False ) ) )
    if ( lisp_flow_logging ) : self . log_flow ( False )
    return ( None )
    if 47 - 47: OOooOOo / II111iiii % IiII . oO0o * I1ii11iIi11i
    if 35 - 35: Oo0Ooo * II111iiii
    if 32 - 32: oO0o . Oo0Ooo / ooOoO0o + ooOoO0o . I1ii11iIi11i
    if 50 - 50: iIii1I11I1II1 * oO0o
    if 85 - 85: i1IIi
   iii11 . use_count += 1
   i1II1IiiIi , OOoOo0O0 = self . decrypt ( i1II1IiiIi , O00O0 , iii11 ,
 I1iiIiiii1111 )
   if ( OOoOo0O0 == False ) :
    if ( stats ) : stats [ self . packet_error ] . increment ( i1iI11Ii1i )
    if ( lisp_flow_logging ) : self . log_flow ( False )
    return ( None )
    if 100 - 100: OoooooooOO / I11i % OoO0O00 + Ii1I
    if 42 - 42: Oo0Ooo / IiII . Ii1I * I1IiiI
    if 54 - 54: OoOoOO00 * iII111i + OoO0O00
    if 93 - 93: o0oOOo0O0Ooo / I1IiiI
    if 47 - 47: Oo0Ooo * OOooOOo
    if 98 - 98: oO0o - oO0o . ooOoO0o
  O00o0O = struct . unpack ( "B" , i1II1IiiIi [ 0 : 1 ] ) [ 0 ]
  self . inner_version = O00o0O >> 4
  if ( Ii and self . inner_version == 4 and O00o0O >= 0x45 ) :
   OooOOoO00OO00 = socket . ntohs ( struct . unpack ( "H" , i1II1IiiIi [ 2 : 4 ] ) [ 0 ] )
   self . inner_tos = struct . unpack ( "B" , i1II1IiiIi [ 1 : 2 ] ) [ 0 ]
   self . inner_ttl = struct . unpack ( "B" , i1II1IiiIi [ 8 : 9 ] ) [ 0 ]
   self . inner_protocol = struct . unpack ( "B" , i1II1IiiIi [ 9 : 10 ] ) [ 0 ]
   self . inner_source . afi = LISP_AFI_IPV4
   self . inner_dest . afi = LISP_AFI_IPV4
   self . inner_source . unpack_address ( i1II1IiiIi [ 12 : 16 ] )
   self . inner_dest . unpack_address ( i1II1IiiIi [ 16 : 20 ] )
   oo0o = socket . ntohs ( struct . unpack ( "H" , i1II1IiiIi [ 6 : 8 ] ) [ 0 ] )
   self . inner_is_fragment = ( oo0o & 0x2000 or oo0o != 0 )
   if ( self . inner_protocol == LISP_UDP_PROTOCOL ) :
    self . inner_sport = struct . unpack ( "H" , i1II1IiiIi [ 20 : 22 ] ) [ 0 ]
    self . inner_sport = socket . ntohs ( self . inner_sport )
    self . inner_dport = struct . unpack ( "H" , i1II1IiiIi [ 22 : 24 ] ) [ 0 ]
    self . inner_dport = socket . ntohs ( self . inner_dport )
    if 17 - 17: OoooooooOO * I1Ii111 * I1IiiI
  elif ( Ii and self . inner_version == 6 and O00o0O >= 0x60 ) :
   OooOOoO00OO00 = socket . ntohs ( struct . unpack ( "H" , i1II1IiiIi [ 4 : 6 ] ) [ 0 ] ) + 40
   I1OO = struct . unpack ( "H" , i1II1IiiIi [ 0 : 2 ] ) [ 0 ]
   self . inner_tos = ( socket . ntohs ( I1OO ) >> 4 ) & 0xff
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
    if 30 - 30: OoOoOO00 / oO0o / Ii1I * o0oOOo0O0Ooo * oO0o . I1IiiI
  elif ( i1Iii ) :
   OooOOoO00OO00 = len ( i1II1IiiIi )
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
   if ( stats ) : stats [ self . packet_error ] . increment ( i1iI11Ii1i )
   if 93 - 93: OoOoOO00
   lprint ( "Cannot decode encapsulation, header version {}" . format ( hex ( O00o0O ) ) )
   if 97 - 97: i11iIiiIii
   i1II1IiiIi = lisp_format_packet ( i1II1IiiIi [ 0 : 20 ] )
   lprint ( "Packet header: {}" . format ( i1II1IiiIi ) )
   if ( lisp_flow_logging and is_lisp_packet ) : self . log_flow ( False )
   return ( None )
   if 68 - 68: IiII * OoO0O00 . I11i / Ii1I . o0oOOo0O0Ooo - i11iIiiIii
  self . inner_source . mask_len = self . inner_source . host_mask_len ( )
  self . inner_dest . mask_len = self . inner_dest . host_mask_len ( )
  self . inner_source . instance_id = o0OOoOO
  self . inner_dest . instance_id = o0OOoOO
  if 49 - 49: Oo0Ooo / Ii1I % I11i + oO0o - OoO0O00
  if 13 - 13: II111iiii
  if 83 - 83: OoooooooOO . I1IiiI + Ii1I * O0 / oO0o
  if 8 - 8: i1IIi + II111iiii / Ii1I + I1ii11iIi11i % Ii1I - iIii1I11I1II1
  if 29 - 29: Oo0Ooo + II111iiii
  if ( lisp_nonce_echoing and is_lisp_packet ) :
   oOOo00ooO = lisp_get_echo_nonce ( self . outer_source , None )
   if ( oOOo00ooO == None ) :
    ooOo = self . outer_source . print_address_no_iid ( )
    oOOo00ooO = lisp_echo_nonce ( ooOo )
    if 73 - 73: OoO0O00 * OoooooooOO - OoooooooOO + I1IiiI * Oo0Ooo
   oOo0 = self . lisp_header . get_nonce ( )
   if ( self . lisp_header . is_e_bit_set ( ) ) :
    oOOo00ooO . receive_request ( lisp_ipc_socket , oOo0 )
   elif ( oOOo00ooO . request_nonce_sent ) :
    oOOo00ooO . receive_echo ( lisp_ipc_socket , oOo0 )
    if 2 - 2: I1IiiI + II111iiii / Ii1I % Oo0Ooo - I1Ii111 + I1Ii111
    if 84 - 84: o0oOOo0O0Ooo % i1IIi / Oo0Ooo - I1IiiI . I1ii11iIi11i . o0oOOo0O0Ooo
    if 75 - 75: O0 * i1IIi - I11i / OOooOOo % OOooOOo / OoOoOO00
    if 5 - 5: O0 - iII111i / I1Ii111 . o0oOOo0O0Ooo
    if 7 - 7: I1ii11iIi11i - OoOoOO00
    if 54 - 54: oO0o / iIii1I11I1II1 / OoooooooOO . i1IIi - OoOoOO00
    if 57 - 57: iIii1I11I1II1 * Ii1I * iII111i / oO0o
  if ( OOoOo0O0 ) : self . packet += i1II1IiiIi [ : OooOOoO00OO00 ]
  if 46 - 46: Ii1I
  if 61 - 61: o0oOOo0O0Ooo / ooOoO0o - II111iiii
  if 87 - 87: I1ii11iIi11i / I1IiiI
  if 45 - 45: OoOoOO00 * ooOoO0o / OoooooooOO + OoO0O00 . I1Ii111 / OoO0O00
  if ( lisp_flow_logging and is_lisp_packet ) : self . log_flow ( False )
  return ( self )
  if 64 - 64: Ii1I / i1IIi % I1IiiI - o0oOOo0O0Ooo
  if 11 - 11: I1ii11iIi11i - OoooooooOO
 def swap_mac ( self , mac ) :
  return ( mac [ 1 ] + mac [ 0 ] + mac [ 3 ] + mac [ 2 ] + mac [ 5 ] + mac [ 4 ] )
  if 16 - 16: IiII % OoooooooOO - ooOoO0o * Ii1I - Ii1I
  if 27 - 27: IiII + iIii1I11I1II1 / Oo0Ooo + OoO0O00 % Oo0Ooo + OoO0O00
 def strip_outer_headers ( self ) :
  I11iiIi1i1 = 16
  I11iiIi1i1 += 20 if ( self . outer_version == 4 ) else 40
  self . packet = self . packet [ I11iiIi1i1 : : ]
  return ( self )
  if 77 - 77: Oo0Ooo * ooOoO0o % Ii1I
  if 2 - 2: I11i / Oo0Ooo / Ii1I / I1ii11iIi11i / OoooooooOO
 def hash_ports ( self ) :
  i1II1IiiIi = self . packet
  O00o0O = self . inner_version
  IiiiI1I1iI11 = 0
  if ( O00o0O == 4 ) :
   iIiIiI1ii = struct . unpack ( "B" , i1II1IiiIi [ 9 ] ) [ 0 ]
   if ( self . inner_is_fragment ) : return ( iIiIiI1ii )
   if ( iIiIiI1ii in [ 6 , 17 ] ) :
    IiiiI1I1iI11 = iIiIiI1ii
    IiiiI1I1iI11 += struct . unpack ( "I" , i1II1IiiIi [ 20 : 24 ] ) [ 0 ]
    IiiiI1I1iI11 = ( IiiiI1I1iI11 >> 16 ) ^ ( IiiiI1I1iI11 & 0xffff )
    if 75 - 75: OoO0O00 % OoooooooOO
    if 16 - 16: O0 / i1IIi
  if ( O00o0O == 6 ) :
   iIiIiI1ii = struct . unpack ( "B" , i1II1IiiIi [ 6 ] ) [ 0 ]
   if ( iIiIiI1ii in [ 6 , 17 ] ) :
    IiiiI1I1iI11 = iIiIiI1ii
    IiiiI1I1iI11 += struct . unpack ( "I" , i1II1IiiIi [ 40 : 44 ] ) [ 0 ]
    IiiiI1I1iI11 = ( IiiiI1I1iI11 >> 16 ) ^ ( IiiiI1I1iI11 & 0xffff )
    if 58 - 58: o0oOOo0O0Ooo / i11iIiiIii / O0 % I11i % I1IiiI
    if 86 - 86: IiII + OoOoOO00 / I1IiiI + I11i % I11i / i11iIiiIii
  return ( IiiiI1I1iI11 )
  if 12 - 12: OoOoOO00 + o0oOOo0O0Ooo . I1Ii111
  if 52 - 52: OoO0O00
 def hash_packet ( self ) :
  IiiiI1I1iI11 = self . inner_source . address ^ self . inner_dest . address
  IiiiI1I1iI11 += self . hash_ports ( )
  if ( self . inner_version == 4 ) :
   IiiiI1I1iI11 = ( IiiiI1I1iI11 >> 16 ) ^ ( IiiiI1I1iI11 & 0xffff )
  elif ( self . inner_version == 6 ) :
   IiiiI1I1iI11 = ( IiiiI1I1iI11 >> 64 ) ^ ( IiiiI1I1iI11 & 0xffffffffffffffff )
   IiiiI1I1iI11 = ( IiiiI1I1iI11 >> 32 ) ^ ( IiiiI1I1iI11 & 0xffffffff )
   IiiiI1I1iI11 = ( IiiiI1I1iI11 >> 16 ) ^ ( IiiiI1I1iI11 & 0xffff )
   if 4 - 4: Ii1I % I1ii11iIi11i + I11i - I1ii11iIi11i
  self . udp_sport = 0xf000 | ( IiiiI1I1iI11 & 0xfff )
  if 98 - 98: Ii1I - O0 * oO0o * Ii1I * Ii1I
  if 44 - 44: IiII + I11i
 def print_packet ( self , s_or_r , is_lisp_packet ) :
  if ( is_lisp_packet == False ) :
   oOO00OoOo = "{} -> {}" . format ( self . inner_source . print_address ( ) ,
 self . inner_dest . print_address ( ) )
   dprint ( ( "{} {}, tos/ttl: {}/{}, length: {}, packet: {} ..." ) . format ( bold ( s_or_r , False ) ,
   # i1IIi . II111iiii + OOooOOo / OoOoOO00 / OOooOOo
 green ( oOO00OoOo , False ) , self . inner_tos ,
 self . inner_ttl , len ( self . packet ) ,
 lisp_format_packet ( self . packet [ 0 : 60 ] ) ) )
   return
   if 77 - 77: IiII + OoooooooOO * i1IIi % OoooooooOO
   if 3 - 3: Ii1I * ooOoO0o - I1IiiI / i1IIi
  if ( s_or_r . find ( "Receive" ) != - 1 ) :
   ii1iIi1 = "decap"
   ii1iIi1 += "-vxlan" if self . udp_dport == LISP_VXLAN_DATA_PORT else ""
  else :
   ii1iIi1 = s_or_r
   if ( ii1iIi1 in [ "Send" , "Replicate" ] or ii1iIi1 . find ( "Fragment" ) != - 1 ) :
    ii1iIi1 = "encap"
    if 44 - 44: OoO0O00 + I11i % OoO0O00 + i1IIi + iII111i + O0
    if 18 - 18: iIii1I11I1II1 % iIii1I11I1II1 % oO0o + I1IiiI % ooOoO0o / Ii1I
  iIi = "{} -> {}" . format ( self . outer_source . print_address_no_iid ( ) ,
 self . outer_dest . print_address_no_iid ( ) )
  if 81 - 81: Oo0Ooo * iII111i * OoO0O00
  if 85 - 85: O0 * oO0o
  if 39 - 39: II111iiii * I1IiiI - iIii1I11I1II1
  if 25 - 25: OoooooooOO . Ii1I % iII111i . IiII
  if 67 - 67: OoooooooOO + I1Ii111 / ooOoO0o
  if ( self . lisp_header . get_instance_id ( ) == 0xffffff ) :
   oooOo = ( "{} LISP packet, outer RLOCs: {}, outer tos/ttl: " + "{}/{}, outer UDP: {} -> {}, " )
   if 75 - 75: IiII / OoooooooOO . I1IiiI + I1Ii111 - II111iiii
   oooOo += bold ( "control-packet" , False ) + ": {} ..."
   if 33 - 33: IiII / IiII . i11iIiiIii * I1ii11iIi11i + o0oOOo0O0Ooo
   dprint ( oooOo . format ( bold ( s_or_r , False ) , red ( iIi , False ) ,
 self . outer_tos , self . outer_ttl , self . udp_sport ,
 self . udp_dport , lisp_format_packet ( self . packet [ 0 : 56 ] ) ) )
   return
  else :
   oooOo = ( "{} LISP packet, outer RLOCs: {}, outer tos/ttl: " + "{}/{}, outer UDP: {} -> {}, inner EIDs: {}, " + "inner tos/ttl: {}/{}, length: {}, {}, packet: {} ..." )
   if 16 - 16: IiII
   if 10 - 10: OoOoOO00 . IiII * iIii1I11I1II1 - oO0o - OoOoOO00 / I1Ii111
   if 13 - 13: oO0o + OoOoOO00 % IiII % OoooooooOO
   if 22 - 22: I1Ii111
  if ( self . lisp_header . k_bits ) :
   if ( ii1iIi1 == "encap" ) : ii1iIi1 = "encrypt/encap"
   if ( ii1iIi1 == "decap" ) : ii1iIi1 = "decap/decrypt"
   if 23 - 23: O0
   if 41 - 41: i1IIi . OOooOOo / ooOoO0o / o0oOOo0O0Ooo % IiII - Ii1I
  oOO00OoOo = "{} -> {}" . format ( self . inner_source . print_address ( ) ,
 self . inner_dest . print_address ( ) )
  if 14 - 14: I1ii11iIi11i - i11iIiiIii * I1Ii111
  dprint ( oooOo . format ( bold ( s_or_r , False ) , red ( iIi , False ) ,
 self . outer_tos , self . outer_ttl , self . udp_sport , self . udp_dport ,
 green ( oOO00OoOo , False ) , self . inner_tos , self . inner_ttl ,
 len ( self . packet ) , self . lisp_header . print_header ( ii1iIi1 ) ,
 lisp_format_packet ( self . packet [ 0 : 56 ] ) ) )
  if 39 - 39: OoooooooOO
  if 19 - 19: i11iIiiIii
 def print_eid_tuple ( self ) :
  return ( lisp_print_eid_tuple ( self . inner_source , self . inner_dest ) )
  if 80 - 80: I1IiiI
  if 58 - 58: oO0o + I1ii11iIi11i % OoOoOO00
 def get_raw_socket ( self ) :
  o0OOoOO = str ( self . lisp_header . get_instance_id ( ) )
  if ( o0OOoOO == "0" ) : return ( None )
  if ( lisp_iid_to_interface . has_key ( o0OOoOO ) == False ) : return ( None )
  if 22 - 22: iIii1I11I1II1 - Ii1I / I1IiiI * IiII
  I111IIiIII = lisp_iid_to_interface [ o0OOoOO ]
  IiIIi1I1I11Ii = I111IIiIII . get_socket ( )
  if ( IiIIi1I1I11Ii == None ) :
   OO0o0o0oo = bold ( "SO_BINDTODEVICE" , False )
   III1IIi = ( os . getenv ( "LISP_ENFORCE_BINDTODEVICE" ) != None )
   lprint ( "{} required for multi-tenancy support, {} packet" . format ( OO0o0o0oo , "drop" if III1IIi else "forward" ) )
   if 37 - 37: iIii1I11I1II1 * OoOoOO00 / I1ii11iIi11i . II111iiii
   if ( III1IIi ) : return ( None )
   if 88 - 88: ooOoO0o + O0
   if 87 - 87: I1Ii111 + OoooooooOO * i1IIi * i11iIiiIii
  o0OOoOO = bold ( o0OOoOO , False )
  oOo0OOOOOO = bold ( I111IIiIII . device , False )
  dprint ( "Send packet on instance-id {} interface {}" . format ( o0OOoOO , oOo0OOOOOO ) )
  return ( IiIIi1I1I11Ii )
  if 74 - 74: OoooooooOO - o0oOOo0O0Ooo * iII111i
  if 37 - 37: o0oOOo0O0Ooo * Oo0Ooo
 def log_flow ( self , encap ) :
  global lisp_flow_log
  if 11 - 11: oO0o
  Oo0O0o00o00 = os . path . exists ( "./log-flows" )
  if ( len ( lisp_flow_log ) == LISP_FLOW_LOG_SIZE or Oo0O0o00o00 ) :
   o0o = [ lisp_flow_log ]
   lisp_flow_log = [ ]
   threading . Thread ( target = lisp_write_flow_log , args = o0o ) . start ( )
   if ( Oo0O0o00o00 ) : os . system ( "rm ./log-flows" )
   return
   if 26 - 26: I1Ii111 / ooOoO0o - OoO0O00 . iIii1I11I1II1
   if 83 - 83: ooOoO0o % Ii1I / Oo0Ooo - iII111i / O0
  OOOO0O00o = datetime . datetime . now ( )
  lisp_flow_log . append ( [ OOOO0O00o , encap , self . packet , self ] )
  if 97 - 97: iIii1I11I1II1 * I11i
  if 95 - 95: OoO0O00
 def print_flow ( self , ts , encap , packet ) :
  ts = ts . strftime ( "%m/%d/%y %H:%M:%S.%f" ) [ : - 3 ]
  OoiIIii1Ii1 = "{}: {}" . format ( ts , "encap" if encap else "decap" )
  if 92 - 92: ooOoO0o / IiII + iIii1I11I1II1
  I111ii1III1I = red ( self . outer_source . print_address_no_iid ( ) , False )
  OO0o0oo = red ( self . outer_dest . print_address_no_iid ( ) , False )
  o0oo0oOOOo00 = green ( self . inner_source . print_address ( ) , False )
  OO0OOO = green ( self . inner_dest . print_address ( ) , False )
  if 80 - 80: iIii1I11I1II1 - Oo0Ooo % I1Ii111 % Oo0Ooo + I1IiiI % Ii1I
  if ( self . lisp_header . get_instance_id ( ) == 0xffffff ) :
   OoiIIii1Ii1 += " {}:{} -> {}:{}, LISP control message type {}\n"
   OoiIIii1Ii1 = OoiIIii1Ii1 . format ( I111ii1III1I , self . udp_sport , OO0o0oo , self . udp_dport ,
 self . inner_version )
   return ( OoiIIii1Ii1 )
   if 86 - 86: I1Ii111 - oO0o % OOooOOo % i11iIiiIii
   if 57 - 57: I1Ii111
  if ( self . outer_dest . is_null ( ) == False ) :
   OoiIIii1Ii1 += " {}:{} -> {}:{}, len/tos/ttl {}/{}/{}"
   OoiIIii1Ii1 = OoiIIii1Ii1 . format ( I111ii1III1I , self . udp_sport , OO0o0oo , self . udp_dport ,
 len ( packet ) , self . outer_tos , self . outer_ttl )
   if 10 - 10: I11i % II111iiii * I1IiiI % i1IIi * i11iIiiIii + OoOoOO00
   if 100 - 100: i1IIi % Ii1I
   if 55 - 55: I1IiiI + iII111i
   if 85 - 85: oO0o + iII111i % iII111i / I11i . I1IiiI - OoOoOO00
   if 19 - 19: I11i / iII111i + IiII
  if ( self . lisp_header . k_bits != 0 ) :
   OoO00OO0ooO0O = "\n"
   if ( self . packet_error != "" ) :
    OoO00OO0ooO0O = " ({})" . format ( self . packet_error ) + OoO00OO0ooO0O
    if 27 - 27: Oo0Ooo - iIii1I11I1II1 * iII111i * II111iiii * I1ii11iIi11i
   OoiIIii1Ii1 += ", encrypted" + OoO00OO0ooO0O
   return ( OoiIIii1Ii1 )
   if 9 - 9: i11iIiiIii + OOooOOo - OoOoOO00 / ooOoO0o % i1IIi / oO0o
   if 22 - 22: i1IIi
   if 3 - 3: OoO0O00 * I1ii11iIi11i - iII111i + I1ii11iIi11i
   if 63 - 63: I11i * ooOoO0o % II111iiii % I1Ii111 + I1IiiI * Oo0Ooo
   if 96 - 96: IiII
  if ( self . outer_dest . is_null ( ) == False ) :
   packet = packet [ 36 : : ] if self . outer_version == 4 else packet [ 56 : : ]
   if 99 - 99: iIii1I11I1II1 - ooOoO0o
   if 79 - 79: I1IiiI + oO0o % I11i % oO0o
  iIiIiI1ii = packet [ 9 ] if self . inner_version == 4 else packet [ 6 ]
  iIiIiI1ii = struct . unpack ( "B" , iIiIiI1ii ) [ 0 ]
  if 56 - 56: I1ii11iIi11i + oO0o . OoO0O00 + OoooooooOO * I1ii11iIi11i - O0
  OoiIIii1Ii1 += " {} -> {}, len/tos/ttl/prot {}/{}/{}/{}"
  OoiIIii1Ii1 = OoiIIii1Ii1 . format ( o0oo0oOOOo00 , OO0OOO , len ( packet ) , self . inner_tos ,
 self . inner_ttl , iIiIiI1ii )
  if 35 - 35: OOooOOo . I11i . I1Ii111 - I11i % I11i + I1Ii111
  if 99 - 99: o0oOOo0O0Ooo + OOooOOo
  if 34 - 34: I1Ii111 * o0oOOo0O0Ooo . I1IiiI % i11iIiiIii
  if 61 - 61: iIii1I11I1II1 + oO0o * I11i - i1IIi % oO0o
  if ( iIiIiI1ii in [ 6 , 17 ] ) :
   oOOo = packet [ 20 : 24 ] if self . inner_version == 4 else packet [ 40 : 44 ]
   if ( len ( oOOo ) == 4 ) :
    oOOo = socket . ntohl ( struct . unpack ( "I" , oOOo ) [ 0 ] )
    OoiIIii1Ii1 += ", ports {} -> {}" . format ( oOOo >> 16 , oOOo & 0xffff )
    if 9 - 9: I1Ii111 - OoO0O00 + iIii1I11I1II1 % O0 + I11i + IiII
  elif ( iIiIiI1ii == 1 ) :
   ii1II1 = packet [ 26 : 28 ] if self . inner_version == 4 else packet [ 46 : 48 ]
   if ( len ( ii1II1 ) == 2 ) :
    ii1II1 = socket . ntohs ( struct . unpack ( "H" , ii1II1 ) [ 0 ] )
    OoiIIii1Ii1 += ", icmp-seq {}" . format ( ii1II1 )
    if 53 - 53: oO0o
    if 99 - 99: Oo0Ooo
  if ( self . packet_error != "" ) :
   OoiIIii1Ii1 += " ({})" . format ( self . packet_error )
   if 17 - 17: i11iIiiIii - i11iIiiIii + I1ii11iIi11i * ooOoO0o * oO0o / OoooooooOO
  OoiIIii1Ii1 += "\n"
  return ( OoiIIii1Ii1 )
  if 22 - 22: I1Ii111 * I1ii11iIi11i - IiII
  if 71 - 71: iIii1I11I1II1 / i11iIiiIii % o0oOOo0O0Ooo . I1Ii111 * I1IiiI % II111iiii
 def is_trace ( self ) :
  oOOo = [ self . inner_sport , self . inner_dport ]
  return ( self . inner_protocol == LISP_UDP_PROTOCOL and
 LISP_TRACE_PORT in oOOo )
  if 35 - 35: I1Ii111 - OoOoOO00
  if 61 - 61: I1Ii111 * o0oOOo0O0Ooo * OoO0O00 + I1ii11iIi11i . Oo0Ooo + i1IIi
  if 82 - 82: Oo0Ooo + I1Ii111
  if 93 - 93: I11i * O0 * OOooOOo - o0oOOo0O0Ooo / I1ii11iIi11i
  if 54 - 54: i1IIi - OoO0O00 / OoooooooOO
  if 95 - 95: O0 + iIii1I11I1II1 . I1ii11iIi11i
  if 61 - 61: Ii1I * Ii1I
  if 70 - 70: I1Ii111 . I1ii11iIi11i / o0oOOo0O0Ooo * oO0o
  if 74 - 74: I1IiiI . ooOoO0o / iII111i . IiII
  if 74 - 74: Oo0Ooo / I1Ii111 % I1Ii111 . IiII
  if 72 - 72: i1IIi
  if 21 - 21: I1Ii111 . OOooOOo / i11iIiiIii * i1IIi
  if 82 - 82: ooOoO0o * Oo0Ooo % i11iIiiIii * i1IIi . OOooOOo
  if 89 - 89: IiII - i1IIi - IiII
  if 74 - 74: OoO0O00 % OoO0O00
  if 28 - 28: OoOoOO00 % oO0o - OOooOOo + OOooOOo + oO0o / iIii1I11I1II1
LISP_N_BIT = 0x80000000
LISP_L_BIT = 0x40000000
LISP_E_BIT = 0x20000000
LISP_V_BIT = 0x10000000
LISP_I_BIT = 0x08000000
LISP_P_BIT = 0x04000000
LISP_K_BITS = 0x03000000
if 91 - 91: I1IiiI / II111iiii * OOooOOo
class lisp_data_header ( ) :
 def __init__ ( self ) :
  self . first_long = 0
  self . second_long = 0
  self . k_bits = 0
  if 94 - 94: II111iiii - iIii1I11I1II1 - iIii1I11I1II1
  if 83 - 83: I1ii11iIi11i * iIii1I11I1II1 + OoOoOO00 * i1IIi . OoooooooOO % Ii1I
 def print_header ( self , e_or_d ) :
  oOoOo00oo = lisp_hex_string ( self . first_long & 0xffffff )
  II11IiIIiiiii = lisp_hex_string ( self . second_long ) . zfill ( 8 )
  if 66 - 66: O0 * o0oOOo0O0Ooo / I1ii11iIi11i
  oooOo = ( "{} LISP-header -> flags: {}{}{}{}{}{}{}{}, nonce: {}, " + "iid/lsb: {}" )
  if 15 - 15: OOooOOo . o0oOOo0O0Ooo + OoooooooOO - Oo0Ooo * iIii1I11I1II1 . i1IIi
  return ( oooOo . format ( bold ( e_or_d , False ) ,
 "N" if ( self . first_long & LISP_N_BIT ) else "n" ,
 "L" if ( self . first_long & LISP_L_BIT ) else "l" ,
 "E" if ( self . first_long & LISP_E_BIT ) else "e" ,
 "V" if ( self . first_long & LISP_V_BIT ) else "v" ,
 "I" if ( self . first_long & LISP_I_BIT ) else "i" ,
 "P" if ( self . first_long & LISP_P_BIT ) else "p" ,
 "K" if ( self . k_bits in [ 2 , 3 ] ) else "k" ,
 "K" if ( self . k_bits in [ 1 , 3 ] ) else "k" ,
 oOoOo00oo , II11IiIIiiiii ) )
  if 39 - 39: Ii1I % i1IIi . I1ii11iIi11i - O0
  if 65 - 65: oO0o * oO0o / I11i + oO0o % ooOoO0o + OoOoOO00
 def encode ( self ) :
  oOoOo000 = "II"
  oOoOo00oo = socket . htonl ( self . first_long )
  II11IiIIiiiii = socket . htonl ( self . second_long )
  if 37 - 37: iII111i
  iIiI1I1II1 = struct . pack ( oOoOo000 , oOoOo00oo , II11IiIIiiiii )
  return ( iIiI1I1II1 )
  if 45 - 45: I1IiiI + I11i + i1IIi
  if 22 - 22: IiII / OOooOOo
 def decode ( self , packet ) :
  oOoOo000 = "II"
  O0OOoooO = struct . calcsize ( oOoOo000 )
  if ( len ( packet ) < O0OOoooO ) : return ( False )
  if 31 - 31: oO0o % i1IIi . OoooooooOO - o0oOOo0O0Ooo + OoooooooOO
  oOoOo00oo , II11IiIIiiiii = struct . unpack ( oOoOo000 , packet [ : O0OOoooO ] )
  if 45 - 45: OOooOOo + I11i / OoooooooOO - Ii1I + OoooooooOO
  if 42 - 42: iIii1I11I1II1 * I1IiiI * I1Ii111
  self . first_long = socket . ntohl ( oOoOo00oo )
  self . second_long = socket . ntohl ( II11IiIIiiiii )
  self . k_bits = ( self . first_long & LISP_K_BITS ) >> 24
  return ( True )
  if 62 - 62: OOooOOo * O0 % IiII . IiII . I1IiiI
  if 91 - 91: i1IIi . iII111i
 def key_id ( self , key_id ) :
  self . first_long &= ~ ( 0x3 << 24 )
  self . first_long |= ( ( key_id & 0x3 ) << 24 )
  self . k_bits = key_id
  if 37 - 37: iII111i - I11i + iIii1I11I1II1 / I1Ii111 - OoO0O00 . o0oOOo0O0Ooo
  if 62 - 62: I1ii11iIi11i
 def nonce ( self , nonce ) :
  self . first_long |= LISP_N_BIT
  self . first_long |= nonce
  if 47 - 47: I1Ii111 % OOooOOo * OoO0O00 . iIii1I11I1II1 % Oo0Ooo + OoooooooOO
  if 2 - 2: I1Ii111 % OoooooooOO - ooOoO0o * I1ii11iIi11i * IiII
 def map_version ( self , version ) :
  self . first_long |= LISP_V_BIT
  self . first_long |= version
  if 99 - 99: iIii1I11I1II1 . Oo0Ooo / ooOoO0o . OOooOOo % I1IiiI * I11i
  if 95 - 95: oO0o
 def instance_id ( self , iid ) :
  if ( iid == 0 ) : return
  self . first_long |= LISP_I_BIT
  self . second_long &= 0xff
  self . second_long |= ( iid << 8 )
  if 80 - 80: IiII
  if 42 - 42: OoooooooOO * II111iiii
 def get_instance_id ( self ) :
  return ( ( self . second_long >> 8 ) & 0xffffff )
  if 53 - 53: I1Ii111 + i1IIi . OoO0O00 / i11iIiiIii + Ii1I % OoOoOO00
  if 9 - 9: ooOoO0o . I11i - Oo0Ooo . I1Ii111
 def locator_status_bits ( self , lsbs ) :
  self . first_long |= LISP_L_BIT
  self . second_long &= 0xffffff00
  self . second_long |= ( lsbs & 0xff )
  if 39 - 39: OOooOOo
  if 70 - 70: IiII % OoO0O00 % I1IiiI
 def is_request_nonce ( self , nonce ) :
  return ( nonce & 0x80000000 )
  if 95 - 95: OoOoOO00 - I1Ii111 / O0 * I1IiiI - o0oOOo0O0Ooo
  if 12 - 12: iIii1I11I1II1 % Oo0Ooo . iII111i . IiII % i11iIiiIii
 def request_nonce ( self , nonce ) :
  self . first_long |= LISP_E_BIT
  self . first_long |= LISP_N_BIT
  self . first_long |= ( nonce & 0xffffff )
  if 2 - 2: oO0o * oO0o . OoOoOO00 * Ii1I * iIii1I11I1II1
  if 13 - 13: I11i / O0 . i11iIiiIii * i1IIi % i11iIiiIii
 def is_e_bit_set ( self ) :
  return ( self . first_long & LISP_E_BIT )
  if 8 - 8: OoOoOO00 - OoooooooOO
  if 99 - 99: II111iiii / IiII % OoooooooOO . i11iIiiIii
 def get_nonce ( self ) :
  return ( self . first_long & 0xffffff )
  if 18 - 18: o0oOOo0O0Ooo . ooOoO0o
  if 70 - 70: OoooooooOO . ooOoO0o / oO0o . oO0o - o0oOOo0O0Ooo
  if 29 - 29: I11i % OOooOOo - ooOoO0o
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
  if 26 - 26: O0 . I11i + iII111i - Ii1I . I11i
  if 2 - 2: I1ii11iIi11i . Oo0Ooo * OOooOOo % II111iiii . iII111i
 def send_ipc ( self , ipc_socket , ipc ) :
  II1i1iI = "lisp-itr" if lisp_i_am_itr else "lisp-etr"
  iI111I1 = "lisp-etr" if lisp_i_am_itr else "lisp-itr"
  ipc = lisp_command_ipc ( ipc , II1i1iI )
  lisp_ipc ( ipc , ipc_socket , iI111I1 )
  if 46 - 46: Ii1I
  if 42 - 42: iIii1I11I1II1
 def send_request_ipc ( self , ipc_socket , nonce ) :
  nonce = lisp_hex_string ( nonce )
  IIi1IiIii = "nonce%R%{}%{}" . format ( self . rloc_str , nonce )
  self . send_ipc ( ipc_socket , IIi1IiIii )
  if 40 - 40: I1IiiI
  if 3 - 3: ooOoO0o / i1IIi - OoOoOO00
 def send_echo_ipc ( self , ipc_socket , nonce ) :
  nonce = lisp_hex_string ( nonce )
  IIi1IiIii = "nonce%E%{}%{}" . format ( self . rloc_str , nonce )
  self . send_ipc ( ipc_socket , IIi1IiIii )
  if 73 - 73: OoooooooOO * O0 * ooOoO0o
  if 7 - 7: II111iiii + i1IIi
 def receive_request ( self , ipc_socket , nonce ) :
  OoooO0 = self . request_nonce_rcvd
  self . request_nonce_rcvd = nonce
  self . last_request_nonce_rcvd = lisp_get_timestamp ( )
  if ( lisp_i_am_rtr ) : return
  if ( OoooO0 != nonce ) : self . send_request_ipc ( ipc_socket , nonce )
  if 43 - 43: iIii1I11I1II1
  if 29 - 29: IiII % ooOoO0o + OoO0O00 . i1IIi + I1IiiI
 def receive_echo ( self , ipc_socket , nonce ) :
  if ( self . request_nonce_sent != nonce ) : return
  self . last_echo_nonce_rcvd = lisp_get_timestamp ( )
  if ( self . echo_nonce_rcvd == nonce ) : return
  if 24 - 24: I1Ii111 / Ii1I * I1ii11iIi11i - OoooooooOO / I1IiiI . oO0o
  self . echo_nonce_rcvd = nonce
  if ( lisp_i_am_rtr ) : return
  self . send_echo_ipc ( ipc_socket , nonce )
  if 98 - 98: i1IIi - iII111i
  if 49 - 49: o0oOOo0O0Ooo . Ii1I . oO0o
 def get_request_or_echo_nonce ( self , ipc_socket , remote_rloc ) :
  if 9 - 9: IiII - II111iiii * OoO0O00
  if 78 - 78: iIii1I11I1II1 / O0 * oO0o / iII111i / OoOoOO00
  if 15 - 15: ooOoO0o / oO0o
  if 54 - 54: ooOoO0o - iIii1I11I1II1 - I11i % Ii1I / II111iiii
  if 80 - 80: i11iIiiIii % iIii1I11I1II1 / i11iIiiIii
  if ( self . request_nonce_sent and self . echo_nonce_sent and remote_rloc ) :
   OO = lisp_myrlocs [ 0 ] if remote_rloc . is_ipv4 ( ) else lisp_myrlocs [ 1 ]
   if 91 - 91: oO0o
   if 56 - 56: iIii1I11I1II1 % II111iiii / OoOoOO00 % OoooooooOO
   if ( remote_rloc . address > OO . address ) :
    oOO0oo = "exit"
    self . request_nonce_sent = None
   else :
    oOO0oo = "stay in"
    self . echo_nonce_sent = None
    if 13 - 13: IiII . Oo0Ooo - I11i / oO0o - Oo0Ooo - I1IiiI
    if 84 - 84: II111iiii
   Oo0ooooO0o00 = bold ( "collision" , False )
   IIi11I1i1I1I = red ( OO . print_address_no_iid ( ) , False )
   iIIIIIi11Ii = red ( remote_rloc . print_address_no_iid ( ) , False )
   lprint ( "Echo nonce {}, {} -> {}, {} request-nonce mode" . format ( Oo0ooooO0o00 ,
 IIi11I1i1I1I , iIIIIIi11Ii , oOO0oo ) )
   if 92 - 92: oO0o / I1ii11iIi11i
   if 6 - 6: i11iIiiIii / i1IIi / IiII . I1IiiI - OOooOOo % i11iIiiIii
   if 77 - 77: OOooOOo % i11iIiiIii - I1ii11iIi11i
   if 21 - 21: I11i . Oo0Ooo - OoooooooOO * i1IIi
   if 54 - 54: II111iiii % o0oOOo0O0Ooo - i1IIi . I1IiiI - II111iiii / iIii1I11I1II1
  if ( self . echo_nonce_sent != None ) :
   oOo0 = self . echo_nonce_sent
   ooo0OO = bold ( "Echoing" , False )
   lprint ( "{} nonce 0x{} to {}" . format ( ooo0OO ,
 lisp_hex_string ( oOo0 ) , red ( self . rloc_str , False ) ) )
   self . last_echo_nonce_sent = lisp_get_timestamp ( )
   self . echo_nonce_sent = None
   return ( oOo0 )
   if 29 - 29: oO0o
   if 66 - 66: OoooooooOO + iII111i . IiII % i1IIi
   if 58 - 58: OOooOOo % iII111i * O0 + I1ii11iIi11i - IiII
   if 26 - 26: i1IIi / I1IiiI / I11i + I11i
   if 46 - 46: I1Ii111 % I1ii11iIi11i + Ii1I
   if 67 - 67: iIii1I11I1II1 . i11iIiiIii . i11iIiiIii . i11iIiiIii / I11i + ooOoO0o
   if 10 - 10: ooOoO0o - Oo0Ooo % II111iiii
  oOo0 = self . request_nonce_sent
  oo = self . last_request_nonce_sent
  if ( oOo0 and oo != None ) :
   if ( time . time ( ) - oo >= LISP_NONCE_ECHO_INTERVAL ) :
    self . request_nonce_sent = None
    lprint ( "Stop request-nonce mode for {}, nonce 0x{}" . format ( red ( self . rloc_str , False ) , lisp_hex_string ( oOo0 ) ) )
    if 15 - 15: ooOoO0o * iIii1I11I1II1 * oO0o
    return ( None )
    if 96 - 96: I1Ii111 * iIii1I11I1II1 / OoOoOO00 % OOooOOo * II111iiii
    if 3 - 3: OOooOOo . Oo0Ooo / i11iIiiIii + OoO0O00
    if 47 - 47: IiII . OOooOOo
    if 96 - 96: I11i % II111iiii / ooOoO0o % OOooOOo / ooOoO0o % i11iIiiIii
    if 57 - 57: I11i - I11i % II111iiii % Oo0Ooo . o0oOOo0O0Ooo % Oo0Ooo
    if 91 - 91: I1IiiI - OoO0O00 - Oo0Ooo - Ii1I * iIii1I11I1II1
    if 68 - 68: OoO0O00 % O0 * iIii1I11I1II1 / oO0o * o0oOOo0O0Ooo + OOooOOo
    if 89 - 89: ooOoO0o * I1IiiI . oO0o
    if 75 - 75: ooOoO0o - iII111i % iII111i + ooOoO0o * o0oOOo0O0Ooo - I1ii11iIi11i
  if ( oOo0 == None ) :
   oOo0 = lisp_get_data_nonce ( )
   if ( self . recently_requested ( ) ) : return ( oOo0 )
   if 26 - 26: I11i * Ii1I % I1IiiI + iII111i
   self . request_nonce_sent = oOo0
   lprint ( "Start request-nonce mode for {}, nonce 0x{}" . format ( red ( self . rloc_str , False ) , lisp_hex_string ( oOo0 ) ) )
   if 38 - 38: iII111i - Oo0Ooo / Ii1I + oO0o . iII111i + IiII
   self . last_new_request_nonce_sent = lisp_get_timestamp ( )
   if 19 - 19: Ii1I
   if 51 - 51: iIii1I11I1II1
   if 8 - 8: OoO0O00 / o0oOOo0O0Ooo % iII111i . i11iIiiIii . OoooooooOO . Ii1I
   if 8 - 8: OoO0O00 * Oo0Ooo
   if 41 - 41: Oo0Ooo / OoO0O00 / OoOoOO00 - i11iIiiIii - OoOoOO00
   if ( lisp_i_am_itr == False ) : return ( oOo0 | 0x80000000 )
   self . send_request_ipc ( ipc_socket , oOo0 )
  else :
   lprint ( "Continue request-nonce mode for {}, nonce 0x{}" . format ( red ( self . rloc_str , False ) , lisp_hex_string ( oOo0 ) ) )
   if 4 - 4: I11i . IiII
   if 39 - 39: OOooOOo . Oo0Ooo - OoOoOO00 * i11iIiiIii
   if 4 - 4: OoOoOO00 * O0 - I11i
   if 72 - 72: I11i + ooOoO0o / I1IiiI . IiII % OoO0O00 / i11iIiiIii
   if 13 - 13: I1Ii111 % o0oOOo0O0Ooo + OOooOOo + I1Ii111 + i11iIiiIii - I1ii11iIi11i
   if 70 - 70: II111iiii * II111iiii . I1IiiI
   if 11 - 11: iII111i
  self . last_request_nonce_sent = lisp_get_timestamp ( )
  return ( oOo0 | 0x80000000 )
  if 20 - 20: Ii1I . I1Ii111 % Ii1I
  if 5 - 5: OOooOOo + iII111i
 def request_nonce_timeout ( self ) :
  if ( self . request_nonce_sent == None ) : return ( False )
  if ( self . request_nonce_sent == self . echo_nonce_rcvd ) : return ( False )
  if 23 - 23: I1Ii111 % iIii1I11I1II1 . I11i
  i11IiIIi11I = time . time ( ) - self . last_request_nonce_sent
  OO0oO0O = self . last_echo_nonce_rcvd
  return ( i11IiIIi11I >= LISP_NONCE_ECHO_INTERVAL and OO0oO0O == None )
  if 11 - 11: I1ii11iIi11i / O0 + II111iiii
  if 95 - 95: I1Ii111 + IiII * iIii1I11I1II1
 def recently_requested ( self ) :
  OO0oO0O = self . last_request_nonce_sent
  if ( OO0oO0O == None ) : return ( False )
  if 17 - 17: OoO0O00 - Oo0Ooo * O0 / Ii1I
  i11IiIIi11I = time . time ( ) - OO0oO0O
  return ( i11IiIIi11I <= LISP_NONCE_ECHO_INTERVAL )
  if 19 - 19: i1IIi - iIii1I11I1II1 . I11i
  if 2 - 2: Ii1I
 def recently_echoed ( self ) :
  if ( self . request_nonce_sent == None ) : return ( True )
  if 12 - 12: i11iIiiIii - iIii1I11I1II1 * IiII * iII111i
  if 19 - 19: O0 + oO0o + o0oOOo0O0Ooo
  if 81 - 81: iIii1I11I1II1
  if 51 - 51: o0oOOo0O0Ooo . I1ii11iIi11i * Ii1I / Oo0Ooo * II111iiii / O0
  OO0oO0O = self . last_good_echo_nonce_rcvd
  if ( OO0oO0O == None ) : OO0oO0O = 0
  i11IiIIi11I = time . time ( ) - OO0oO0O
  if ( i11IiIIi11I <= LISP_NONCE_ECHO_INTERVAL ) : return ( True )
  if 44 - 44: i11iIiiIii % I1Ii111 % oO0o + I11i * oO0o . Ii1I
  if 89 - 89: OoooooooOO % II111iiii - OoO0O00 % i11iIiiIii
  if 7 - 7: IiII
  if 15 - 15: Oo0Ooo + iII111i + I1IiiI * o0oOOo0O0Ooo
  if 33 - 33: o0oOOo0O0Ooo * Oo0Ooo
  if 88 - 88: I1Ii111 % OOooOOo - OoOoOO00 - OoOoOO00 . I1IiiI
  OO0oO0O = self . last_new_request_nonce_sent
  if ( OO0oO0O == None ) : OO0oO0O = 0
  i11IiIIi11I = time . time ( ) - OO0oO0O
  return ( i11IiIIi11I <= LISP_NONCE_ECHO_INTERVAL )
  if 52 - 52: II111iiii / II111iiii / I1IiiI - I1Ii111
  if 91 - 91: I1IiiI + o0oOOo0O0Ooo % II111iiii + OoO0O00
 def change_state ( self , rloc ) :
  if ( rloc . up_state ( ) and self . recently_echoed ( ) == False ) :
   Oo0o0OOo0Oo0 = bold ( "down" , False )
   O00o = lisp_print_elapsed ( self . last_good_echo_nonce_rcvd )
   lprint ( "Take {} {}, last good echo: {}" . format ( red ( self . rloc_str , False ) , Oo0o0OOo0Oo0 , O00o ) )
   if 65 - 65: OoOoOO00 / I1ii11iIi11i / o0oOOo0O0Ooo
   rloc . state = LISP_RLOC_NO_ECHOED_NONCE_STATE
   rloc . last_state_change = lisp_get_timestamp ( )
   return
   if 15 - 15: ooOoO0o / ooOoO0o % OoooooooOO . I1Ii111
   if 93 - 93: I1ii11iIi11i * I1ii11iIi11i / OoooooooOO
  if ( rloc . no_echoed_nonce_state ( ) == False ) : return
  if 6 - 6: I1ii11iIi11i * Oo0Ooo + iIii1I11I1II1
  if ( self . recently_requested ( ) == False ) :
   ii1iIi111i1 = bold ( "up" , False )
   lprint ( "Bring {} {}, retry request-nonce mode" . format ( red ( self . rloc_str , False ) , ii1iIi111i1 ) )
   if 57 - 57: I1IiiI
   rloc . state = LISP_RLOC_UP_STATE
   rloc . last_state_change = lisp_get_timestamp ( )
   if 63 - 63: i1IIi + oO0o
   if 58 - 58: iII111i - OoooooooOO
   if 56 - 56: iII111i / iII111i
 def print_echo_nonce ( self ) :
  Ii11iIi1iIiii = lisp_print_elapsed ( self . last_request_nonce_sent )
  iIIIi = lisp_print_elapsed ( self . last_good_echo_nonce_rcvd )
  if 11 - 11: I11i
  IIIIi1 = lisp_print_elapsed ( self . last_echo_nonce_sent )
  IiII1II1 = lisp_print_elapsed ( self . last_request_nonce_rcvd )
  IiIIi1I1I11Ii = space ( 4 )
  if 61 - 61: Ii1I + I1IiiI / i1IIi + i1IIi / oO0o
  Oo0O = "Nonce-Echoing:\n"
  Oo0O += ( "{}Last request-nonce sent: {}\n{}Last echo-nonce " + "received: {}\n" ) . format ( IiIIi1I1I11Ii , Ii11iIi1iIiii , IiIIi1I1I11Ii , iIIIi )
  if 47 - 47: I1Ii111
  Oo0O += ( "{}Last request-nonce received: {}\n{}Last echo-nonce " + "sent: {}" ) . format ( IiIIi1I1I11Ii , IiII1II1 , IiIIi1I1I11Ii , IIIIi1 )
  if 25 - 25: iII111i + I1IiiI + OoOoOO00 + I1Ii111 % O0
  if 26 - 26: ooOoO0o + OoOoOO00
  return ( Oo0O )
  if 17 - 17: I1ii11iIi11i - iII111i % Oo0Ooo * O0 % O0 * OOooOOo
  if 6 - 6: I1Ii111
  if 46 - 46: II111iiii * I1Ii111
  if 23 - 23: i1IIi - O0
  if 6 - 6: ooOoO0o % OoooooooOO * I1Ii111 - IiII
  if 24 - 24: I11i / iIii1I11I1II1 . OoooooooOO % OoOoOO00 . Ii1I
  if 73 - 73: I1Ii111
  if 25 - 25: IiII
  if 77 - 77: o0oOOo0O0Ooo . iIii1I11I1II1 . OoooooooOO . iIii1I11I1II1
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
    if 87 - 87: II111iiii - OoooooooOO / i1IIi . Ii1I - Oo0Ooo . i11iIiiIii
   self . local_private_key = random . randint ( 0 , 2 ** 128 - 1 )
   iii11 = lisp_hex_string ( self . local_private_key ) . zfill ( 32 )
   self . curve25519 = curve25519 . Private ( iii11 )
  else :
   self . local_private_key = random . randint ( 0 , 0x1fff )
   if 47 - 47: Oo0Ooo % OoO0O00 - ooOoO0o - Oo0Ooo * oO0o
  self . local_public_key = self . compute_public_key ( )
  self . remote_public_key = None
  self . shared_key = None
  self . encrypt_key = None
  self . icv_key = None
  self . icv = poly1305 if do_poly else hashlib . sha256
  self . iv = None
  self . get_iv ( )
  self . do_poly = do_poly
  if 72 - 72: o0oOOo0O0Ooo % o0oOOo0O0Ooo + iII111i + I1ii11iIi11i / Oo0Ooo
  if 30 - 30: Oo0Ooo + I1IiiI + i11iIiiIii / OoO0O00
 def copy_keypair ( self , key ) :
  self . local_private_key = key . local_private_key
  self . local_public_key = key . local_public_key
  self . curve25519 = key . curve25519
  if 64 - 64: IiII
  if 80 - 80: I1IiiI - i11iIiiIii / OoO0O00 / OoOoOO00 + OoOoOO00
 def get_iv ( self ) :
  if ( self . iv == None ) :
   self . iv = random . randint ( 0 , LISP_16_128_MASK )
  else :
   self . iv += 1
   if 89 - 89: O0 + IiII * I1Ii111
  O0o = self . iv
  if ( self . cipher_suite == LISP_CS_25519_CHACHA ) :
   O0o = struct . pack ( "Q" , O0o & LISP_8_64_MASK )
  elif ( self . cipher_suite == LISP_CS_25519_GCM ) :
   iIIIIII = struct . pack ( "I" , ( O0o >> 64 ) & LISP_4_32_MASK )
   IIIi1i1i1iii = struct . pack ( "Q" , O0o & LISP_8_64_MASK )
   O0o = iIIIIII + IIIi1i1i1iii
  else :
   O0o = struct . pack ( "QQ" , O0o >> 64 , O0o & LISP_8_64_MASK )
  return ( O0o )
  if 53 - 53: OoO0O00
  if 80 - 80: II111iiii - o0oOOo0O0Ooo . iIii1I11I1II1
 def key_length ( self , key ) :
  if ( type ( key ) != str ) : key = self . normalize_pub_key ( key )
  return ( len ( key ) / 2 )
  if 44 - 44: i11iIiiIii % I11i % I1ii11iIi11i
  if 7 - 7: Oo0Ooo * OoO0O00 - II111iiii % I1Ii111 . Oo0Ooo . Oo0Ooo
 def print_key ( self , key ) :
  oOOO0OO = self . normalize_pub_key ( key )
  return ( "0x{}...{}({})" . format ( oOOO0OO [ 0 : 4 ] , oOOO0OO [ - 4 : : ] , self . key_length ( oOOO0OO ) ) )
  if 5 - 5: OoooooooOO * I1ii11iIi11i
  if 42 - 42: o0oOOo0O0Ooo . I1Ii111 / O0 . II111iiii * OoOoOO00
 def normalize_pub_key ( self , key ) :
  if ( type ( key ) == str ) :
   if ( self . curve25519 ) : return ( binascii . hexlify ( key ) )
   return ( key )
   if 7 - 7: I1Ii111 * O0 + OoOoOO00
  key = lisp_hex_string ( key ) . zfill ( 256 )
  return ( key )
  if 90 - 90: IiII * II111iiii * IiII - iII111i
  if 34 - 34: OOooOOo - I1ii11iIi11i * iII111i % Ii1I
 def print_keys ( self , do_bold = True ) :
  IIi11I1i1I1I = bold ( "local-key: " , False ) if do_bold else "local-key: "
  if ( self . local_public_key == None ) :
   IIi11I1i1I1I += "none"
  else :
   IIi11I1i1I1I += self . print_key ( self . local_public_key )
   if 25 - 25: II111iiii + I1IiiI * ooOoO0o * I1ii11iIi11i . iII111i
  iIIIIIi11Ii = bold ( "remote-key: " , False ) if do_bold else "remote-key: "
  if ( self . remote_public_key == None ) :
   iIIIIIi11Ii += "none"
  else :
   iIIIIIi11Ii += self . print_key ( self . remote_public_key )
   if 26 - 26: iII111i - ooOoO0o / OoooooooOO + o0oOOo0O0Ooo . Oo0Ooo
  oooO0 = "ECDH" if ( self . curve25519 ) else "DH"
  iI1iIi1ii1I1 = self . cipher_suite
  return ( "{} cipher-suite: {}, {}, {}" . format ( oooO0 , iI1iIi1ii1I1 , IIi11I1i1I1I , iIIIIIi11Ii ) )
  if 59 - 59: II111iiii * OoooooooOO - OoooooooOO
  if 33 - 33: O0 . i11iIiiIii % o0oOOo0O0Ooo
 def compare_keys ( self , keys ) :
  if ( self . dh_g_value != keys . dh_g_value ) : return ( False )
  if ( self . dh_p_value != keys . dh_p_value ) : return ( False )
  if ( self . remote_public_key != keys . remote_public_key ) : return ( False )
  return ( True )
  if 50 - 50: ooOoO0o
  if 81 - 81: i11iIiiIii * iIii1I11I1II1 / Oo0Ooo * OOooOOo
 def compute_public_key ( self ) :
  if ( self . curve25519 ) : return ( self . curve25519 . get_public ( ) . public )
  if 83 - 83: i11iIiiIii - I1IiiI * i11iIiiIii
  iii11 = self . local_private_key
  O0ooO0oOO = self . dh_g_value
  OoOoO = self . dh_p_value
  return ( int ( ( O0ooO0oOO ** iii11 ) % OoOoO ) )
  if 70 - 70: oO0o
  if 69 - 69: IiII
 def compute_shared_key ( self , ed , print_shared = False ) :
  iii11 = self . local_private_key
  OOOo0O0o0oo = self . remote_public_key
  if 25 - 25: OoooooooOO
  IiIi1I1IiI1II1 = bold ( "Compute {} shared-key" . format ( ed ) , False )
  lprint ( "{}, key-material: {}" . format ( IiIi1I1IiI1II1 , self . print_keys ( ) ) )
  if 21 - 21: OoooooooOO . O0 / i11iIiiIii
  if ( self . curve25519 ) :
   oOOO = curve25519 . Public ( OOOo0O0o0oo )
   self . shared_key = self . curve25519 . get_shared_key ( oOOO )
  else :
   OoOoO = self . dh_p_value
   self . shared_key = ( OOOo0O0o0oo ** iii11 ) % OoOoO
   if 71 - 71: I1IiiI . ooOoO0o
   if 43 - 43: I1ii11iIi11i * OOooOOo
   if 1 - 1: OoO0O00 * ooOoO0o + IiII . oO0o / ooOoO0o
   if 91 - 91: Ii1I + I11i - Oo0Ooo % OoOoOO00 . iII111i
   if 51 - 51: OOooOOo / I11i
   if 51 - 51: ooOoO0o * oO0o - I1Ii111 + iII111i
   if 46 - 46: o0oOOo0O0Ooo - i11iIiiIii % OoO0O00 / Ii1I - OoOoOO00
  if ( print_shared ) :
   oOOO0OO = self . print_key ( self . shared_key )
   lprint ( "Computed shared-key: {}" . format ( oOOO0OO ) )
   if 88 - 88: oO0o * I1IiiI / OoO0O00 - OOooOOo / i1IIi . I1Ii111
   if 26 - 26: i11iIiiIii - ooOoO0o
   if 45 - 45: ooOoO0o + II111iiii % iII111i
   if 55 - 55: ooOoO0o - oO0o % I1IiiI
   if 61 - 61: ooOoO0o
  self . compute_encrypt_icv_keys ( )
  if 22 - 22: iIii1I11I1II1 / ooOoO0o / I1IiiI - o0oOOo0O0Ooo
  if 21 - 21: oO0o . i11iIiiIii * I11i . OOooOOo / OOooOOo
  if 42 - 42: OoooooooOO / I1Ii111 . o0oOOo0O0Ooo / O0 - IiII * IiII
  if 1 - 1: Ii1I % I1Ii111
  self . rekey_count += 1
  self . last_rekey = lisp_get_timestamp ( )
  if 97 - 97: OoOoOO00
  if 13 - 13: OoOoOO00 % OOooOOo . O0 / Oo0Ooo % Oo0Ooo
 def compute_encrypt_icv_keys ( self ) :
  I1I111iII1 = hashlib . sha256
  if ( self . curve25519 ) :
   IIII1iI1iiI = self . shared_key
  else :
   IIII1iI1iiI = lisp_hex_string ( self . shared_key )
   if 78 - 78: ooOoO0o . OOooOOo / OoOoOO00 * Oo0Ooo % oO0o
   if 20 - 20: OoOoOO00
   if 1 - 1: I1Ii111 * OoO0O00 - iII111i
   if 97 - 97: iII111i . I1ii11iIi11i - iIii1I11I1II1 . ooOoO0o + I1IiiI % oO0o
   if 4 - 4: I1IiiI / II111iiii % O0 * ooOoO0o / II111iiii . Oo0Ooo
  IIi11I1i1I1I = self . local_public_key
  if ( type ( IIi11I1i1I1I ) != long ) : IIi11I1i1I1I = int ( binascii . hexlify ( IIi11I1i1I1I ) , 16 )
  iIIIIIi11Ii = self . remote_public_key
  if ( type ( iIIIIIi11Ii ) != long ) : iIIIIIi11Ii = int ( binascii . hexlify ( iIIIIIi11Ii ) , 16 )
  iiIiii = "0001" + "lisp-crypto" + lisp_hex_string ( IIi11I1i1I1I ^ iIIIIIi11Ii ) + "0100"
  if 3 - 3: I11i / I1Ii111 * IiII - O0 + I1IiiI / IiII
  iii1II11II1 = hmac . new ( iiIiii , IIII1iI1iiI , I1I111iII1 ) . hexdigest ( )
  iii1II11II1 = int ( iii1II11II1 , 16 )
  if 30 - 30: IiII / i11iIiiIii % OoO0O00 * OOooOOo
  if 27 - 27: O0
  if 95 - 95: OoOoOO00 . Oo0Ooo + II111iiii - I1ii11iIi11i
  if 57 - 57: OoooooooOO . I1ii11iIi11i - oO0o * i1IIi . I11i
  II1iIi11iIii = ( iii1II11II1 >> 128 ) & LISP_16_128_MASK
  oOOO0oo0 = iii1II11II1 & LISP_16_128_MASK
  self . encrypt_key = lisp_hex_string ( II1iIi11iIii ) . zfill ( 32 )
  iI1IiiiiI = 32 if self . do_poly else 40
  self . icv_key = lisp_hex_string ( oOOO0oo0 ) . zfill ( iI1IiiiiI )
  if 12 - 12: i11iIiiIii . I11i * OOooOOo % i1IIi . ooOoO0o
  if 58 - 58: iII111i % iIii1I11I1II1 . iIii1I11I1II1 / I11i
 def do_icv ( self , packet , nonce ) :
  if ( self . icv_key == None ) : return ( "" )
  if ( self . do_poly ) :
   OOO0O = self . icv . poly1305aes
   II11 = self . icv . binascii . hexlify
   nonce = II11 ( nonce )
   oOoOo000Ooooo = OOO0O ( self . encrypt_key , self . icv_key , nonce , packet )
   oOoOo000Ooooo = II11 ( oOoOo000Ooooo )
  else :
   iii11 = binascii . unhexlify ( self . icv_key )
   oOoOo000Ooooo = hmac . new ( iii11 , packet , self . icv ) . hexdigest ( )
   oOoOo000Ooooo = oOoOo000Ooooo [ 0 : 40 ]
   if 18 - 18: Ii1I + OoOoOO00 . i1IIi / IiII / iII111i
  return ( oOoOo000Ooooo )
  if 97 - 97: OoO0O00 + iIii1I11I1II1
  if 79 - 79: ooOoO0o + oO0o - II111iiii . Oo0Ooo
 def add_key_by_nonce ( self , nonce ) :
  if ( lisp_crypto_keys_by_nonce . has_key ( nonce ) == False ) :
   lisp_crypto_keys_by_nonce [ nonce ] = [ None , None , None , None ]
   if 26 - 26: IiII
  lisp_crypto_keys_by_nonce [ nonce ] [ self . key_id ] = self
  if 52 - 52: O0 + ooOoO0o
  if 11 - 11: i1IIi / I1Ii111 * I1ii11iIi11i * I1Ii111 * ooOoO0o - i11iIiiIii
 def delete_key_by_nonce ( self , nonce ) :
  if ( lisp_crypto_keys_by_nonce . has_key ( nonce ) == False ) : return
  lisp_crypto_keys_by_nonce . pop ( nonce )
  if 96 - 96: I1ii11iIi11i % I1ii11iIi11i
  if 1 - 1: I1IiiI . Ii1I
 def add_key_by_rloc ( self , addr_str , encap ) :
  II11IIII1 = lisp_crypto_keys_by_rloc_encap if encap else lisp_crypto_keys_by_rloc_decap
  if 33 - 33: Ii1I + OoOoOO00 - I1ii11iIi11i + iIii1I11I1II1 % i1IIi * IiII
  if 21 - 21: O0 * ooOoO0o % OoO0O00
  if ( II11IIII1 . has_key ( addr_str ) == False ) :
   II11IIII1 [ addr_str ] = [ None , None , None , None ]
   if 14 - 14: O0 / I1Ii111 / ooOoO0o + IiII - IiII
  II11IIII1 [ addr_str ] [ self . key_id ] = self
  if 10 - 10: O0 - I1ii11iIi11i / I1Ii111 % OoOoOO00 / OoooooooOO / Ii1I
  if 73 - 73: ooOoO0o + IiII % o0oOOo0O0Ooo . I1ii11iIi11i / OOooOOo . I1Ii111
  if 76 - 76: I11i . I1ii11iIi11i * OoooooooOO % iII111i
  if 24 - 24: OoooooooOO
  if 83 - 83: O0 / OoO0O00
  if ( encap == False ) :
   lisp_write_ipc_decap_key ( addr_str , II11IIII1 [ addr_str ] )
   if 62 - 62: I11i
   if 73 - 73: Ii1I % OoO0O00 * OOooOOo
   if 84 - 84: Oo0Ooo
 def encode_lcaf ( self , rloc_addr ) :
  i1Ii = self . normalize_pub_key ( self . local_public_key )
  iI1i11 = self . key_length ( i1Ii )
  OO0OoO0OOoOo = ( 6 + iI1i11 + 2 )
  if ( rloc_addr != None ) : OO0OoO0OOoOo += rloc_addr . addr_length ( )
  if 84 - 84: oO0o / Ii1I * iII111i
  i1II1IiiIi = struct . pack ( "HBBBBHBB" , socket . htons ( LISP_AFI_LCAF ) , 0 , 0 ,
 LISP_LCAF_SECURITY_TYPE , 0 , socket . htons ( OO0OoO0OOoOo ) , 1 , 0 )
  if 20 - 20: OoOoOO00 % O0
  if 59 - 59: O0 . o0oOOo0O0Ooo % I1ii11iIi11i * oO0o + I11i
  if 82 - 82: OoooooooOO
  if 88 - 88: O0 / o0oOOo0O0Ooo * o0oOOo0O0Ooo . o0oOOo0O0Ooo . O0
  if 27 - 27: i11iIiiIii % iII111i + Ii1I . OOooOOo
  if 9 - 9: OoO0O00
  iI1iIi1ii1I1 = self . cipher_suite
  i1II1IiiIi += struct . pack ( "BBH" , iI1iIi1ii1I1 , 0 , socket . htons ( iI1i11 ) )
  if 43 - 43: Ii1I . OOooOOo + I1IiiI * i11iIiiIii
  if 2 - 2: OOooOOo
  if 3 - 3: I1IiiI . iII111i % O0 - ooOoO0o / O0
  if 79 - 79: Ii1I + oO0o % ooOoO0o % I1IiiI
  for Ii11 in range ( 0 , iI1i11 * 2 , 16 ) :
   iii11 = int ( i1Ii [ Ii11 : Ii11 + 16 ] , 16 )
   i1II1IiiIi += struct . pack ( "Q" , byte_swap_64 ( iii11 ) )
   if 68 - 68: II111iiii - OoooooooOO / iIii1I11I1II1 - o0oOOo0O0Ooo % II111iiii
   if 53 - 53: iII111i . oO0o / Oo0Ooo . OoO0O00 . i11iIiiIii
   if 60 - 60: II111iiii
   if 25 - 25: Oo0Ooo + o0oOOo0O0Ooo - OoO0O00
   if 57 - 57: II111iiii . i1IIi
  if ( rloc_addr ) :
   i1II1IiiIi += struct . pack ( "H" , socket . htons ( rloc_addr . afi ) )
   i1II1IiiIi += rloc_addr . pack_address ( )
   if 33 - 33: iII111i + Oo0Ooo % I11i . oO0o
  return ( i1II1IiiIi )
  if 6 - 6: IiII + I1ii11iIi11i
  if 62 - 62: oO0o . I1Ii111 - OoooooooOO * II111iiii . i11iIiiIii
 def decode_lcaf ( self , packet , lcaf_len ) :
  if 13 - 13: iIii1I11I1II1 * o0oOOo0O0Ooo - i11iIiiIii
  if 63 - 63: OoooooooOO * I1Ii111
  if 50 - 50: Oo0Ooo - o0oOOo0O0Ooo % II111iiii . O0 . oO0o % II111iiii
  if 18 - 18: I11i % OoooooooOO + OoO0O00 / I11i
  if ( lcaf_len == 0 ) :
   oOoOo000 = "HHBBH"
   O0OOoooO = struct . calcsize ( oOoOo000 )
   if ( len ( packet ) < O0OOoooO ) : return ( None )
   if 37 - 37: i1IIi - Ii1I / IiII . II111iiii % ooOoO0o
   iioOO , i11iIi1I1i1 , oOOi1I111II , i11iIi1I1i1 , lcaf_len = struct . unpack ( oOoOo000 , packet [ : O0OOoooO ] )
   if 51 - 51: I1IiiI * ooOoO0o
   if 47 - 47: OOooOOo . OOooOOo . IiII . I1Ii111 / i1IIi
   if ( oOOi1I111II != LISP_LCAF_SECURITY_TYPE ) :
    packet = packet [ lcaf_len + 6 : : ]
    return ( packet )
    if 77 - 77: II111iiii % I11i / Oo0Ooo
   lcaf_len = socket . ntohs ( lcaf_len )
   packet = packet [ O0OOoooO : : ]
   if 23 - 23: iIii1I11I1II1
   if 10 - 10: I11i - o0oOOo0O0Ooo % OoooooooOO - I1ii11iIi11i
   if 64 - 64: OoO0O00 / I1IiiI
   if 23 - 23: I11i * I1Ii111 * o0oOOo0O0Ooo - I1IiiI % OoOoOO00 + o0oOOo0O0Ooo
   if 41 - 41: IiII * OoooooooOO . ooOoO0o % i11iIiiIii
   if 11 - 11: iIii1I11I1II1 . I1Ii111 - Oo0Ooo / I11i + II111iiii
  oOOi1I111II = LISP_LCAF_SECURITY_TYPE
  oOoOo000 = "BBBBH"
  O0OOoooO = struct . calcsize ( oOoOo000 )
  if ( len ( packet ) < O0OOoooO ) : return ( None )
  if 29 - 29: I11i . i11iIiiIii + i1IIi - Ii1I + O0 . I1IiiI
  i1iIiII1 , i11iIi1I1i1 , iI1iIi1ii1I1 , i11iIi1I1i1 , iI1i11 = struct . unpack ( oOoOo000 ,
 packet [ : O0OOoooO ] )
  if 59 - 59: OoooooooOO + I1Ii111 % o0oOOo0O0Ooo - OoOoOO00 . I1IiiI
  if 42 - 42: I1Ii111
  if 70 - 70: o0oOOo0O0Ooo / I11i + oO0o % I1IiiI % Oo0Ooo + OoO0O00
  if 80 - 80: OOooOOo
  if 12 - 12: Ii1I
  if 2 - 2: OoooooooOO
  packet = packet [ O0OOoooO : : ]
  iI1i11 = socket . ntohs ( iI1i11 )
  if ( len ( packet ) < iI1i11 ) : return ( None )
  if 100 - 100: Oo0Ooo / O0 * i11iIiiIii * OoooooooOO
  if 46 - 46: O0 % OoooooooOO
  if 22 - 22: iII111i + OoooooooOO - OoOoOO00 - OoO0O00 * I1Ii111 - oO0o
  if 99 - 99: ooOoO0o / I1IiiI . Ii1I - Ii1I * I1IiiI
  I1IIiIIiiI1i = [ LISP_CS_25519_CBC , LISP_CS_25519_GCM , LISP_CS_25519_CHACHA ,
 LISP_CS_1024 ]
  if ( iI1iIi1ii1I1 not in I1IIiIIiiI1i ) :
   lprint ( "Cipher-suites {} supported, received {}" . format ( I1IIiIIiiI1i ,
 iI1iIi1ii1I1 ) )
   packet = packet [ iI1i11 : : ]
   return ( packet )
   if 83 - 83: I1ii11iIi11i * II111iiii . I1Ii111 - I11i
   if 46 - 46: OoO0O00 % I1ii11iIi11i
  self . cipher_suite = iI1iIi1ii1I1
  if 58 - 58: oO0o + IiII % iII111i - Ii1I - OOooOOo % Ii1I
  if 86 - 86: o0oOOo0O0Ooo
  if 15 - 15: oO0o - iIii1I11I1II1 - II111iiii - IiII % I1ii11iIi11i
  if 80 - 80: IiII * iII111i . i1IIi % Ii1I % I1ii11iIi11i + ooOoO0o
  if 6 - 6: I1ii11iIi11i . oO0o . OoO0O00 + IiII
  i1Ii = 0
  for Ii11 in range ( 0 , iI1i11 , 8 ) :
   iii11 = byte_swap_64 ( struct . unpack ( "Q" , packet [ Ii11 : Ii11 + 8 ] ) [ 0 ] )
   i1Ii <<= 64
   i1Ii |= iii11
   if 65 - 65: I1ii11iIi11i / ooOoO0o
  self . remote_public_key = i1Ii
  if 23 - 23: OOooOOo / OOooOOo * o0oOOo0O0Ooo * OOooOOo
  if 57 - 57: iII111i
  if 29 - 29: I1IiiI
  if 41 - 41: I1Ii111 * OoO0O00 - iII111i . Ii1I
  if 41 - 41: iIii1I11I1II1 - O0 - I1ii11iIi11i - oO0o + I1Ii111
  if ( self . curve25519 ) :
   iii11 = lisp_hex_string ( self . remote_public_key )
   iii11 = iii11 . zfill ( 64 )
   Ii1111iI1i1 = ""
   for Ii11 in range ( 0 , len ( iii11 ) , 2 ) :
    Ii1111iI1i1 += chr ( int ( iii11 [ Ii11 : Ii11 + 2 ] , 16 ) )
    if 78 - 78: I1ii11iIi11i . iII111i % II111iiii
   self . remote_public_key = Ii1111iI1i1
   if 90 - 90: OoooooooOO % i11iIiiIii % o0oOOo0O0Ooo % I1Ii111 - ooOoO0o + iIii1I11I1II1
   if 98 - 98: O0 / oO0o / iII111i
  packet = packet [ iI1i11 : : ]
  return ( packet )
  if 83 - 83: I1Ii111
  if 38 - 38: oO0o
  if 9 - 9: I11i . OoO0O00 . oO0o / OoooooooOO
  if 59 - 59: iIii1I11I1II1 + i1IIi % II111iiii
  if 2 - 2: II111iiii + I11i . OoO0O00
  if 14 - 14: OOooOOo * I1IiiI - I1ii11iIi11i
  if 10 - 10: iII111i % I1Ii111 * I1ii11iIi11i * O0 * i11iIiiIii % I1Ii111
  if 68 - 68: OoooooooOO * OoOoOO00
class lisp_thread ( ) :
 def __init__ ( self , name ) :
  self . thread_name = name
  self . thread_number = - 1
  self . number_of_pcap_threads = 0
  self . number_of_worker_threads = 0
  self . input_queue = Queue . Queue ( )
  self . input_stats = lisp_stats ( )
  self . lisp_packet = lisp_packet ( None )
  if 9 - 9: I1Ii111
  if 36 - 36: I1Ii111 / OoOoOO00 + OoOoOO00 * ooOoO0o / OOooOOo * O0
  if 17 - 17: OoO0O00 / ooOoO0o % I1IiiI
  if 47 - 47: Oo0Ooo * OoO0O00 / o0oOOo0O0Ooo * I1IiiI
  if 60 - 60: I1ii11iIi11i / IiII . i11iIiiIii / OoO0O00 % II111iiii
  if 6 - 6: iII111i % o0oOOo0O0Ooo + I1Ii111
  if 91 - 91: o0oOOo0O0Ooo + O0 * oO0o * IiII * I1ii11iIi11i
  if 83 - 83: OoooooooOO
  if 52 - 52: o0oOOo0O0Ooo / OoOoOO00 % oO0o % OoO0O00 / IiII % o0oOOo0O0Ooo
  if 88 - 88: OOooOOo / i11iIiiIii / Ii1I / i11iIiiIii * I1ii11iIi11i % I11i
  if 43 - 43: OoOoOO00 * OoO0O00 % i1IIi * Ii1I + iIii1I11I1II1
  if 80 - 80: o0oOOo0O0Ooo . iII111i . OoooooooOO
  if 63 - 63: ooOoO0o . OOooOOo
  if 66 - 66: I1IiiI
  if 99 - 99: OoO0O00 % O0 . I1Ii111 - I1ii11iIi11i . Oo0Ooo / OoOoOO00
  if 60 - 60: I1ii11iIi11i
  if 78 - 78: oO0o + II111iiii
  if 55 - 55: OoooooooOO
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
  if 90 - 90: I1IiiI
  if 4 - 4: OOooOOo % ooOoO0o - OOooOOo - o0oOOo0O0Ooo
 def decode ( self , packet ) :
  oOoOo000 = "BBBBQ"
  O0OOoooO = struct . calcsize ( oOoOo000 )
  if ( len ( packet ) < O0OOoooO ) : return ( False )
  if 30 - 30: IiII
  IIIiIII1 , OOo0OOo , OOIiI1IIIiI1I1i , self . record_count , self . nonce = struct . unpack ( oOoOo000 , packet [ : O0OOoooO ] )
  if 84 - 84: OoOoOO00 - I11i
  if 80 - 80: i11iIiiIii % OOooOOo - Oo0Ooo % OOooOOo
  self . type = IIIiIII1 >> 4
  if ( self . type == LISP_MAP_REQUEST ) :
   self . smr_bit = True if ( IIIiIII1 & 0x01 ) else False
   self . rloc_probe = True if ( IIIiIII1 & 0x02 ) else False
   self . smr_invoked_bit = True if ( OOo0OOo & 0x40 ) else False
   if 89 - 89: Ii1I * I11i + OoOoOO00 / i11iIiiIii
  if ( self . type == LISP_ECM ) :
   self . ddt_bit = True if ( IIIiIII1 & 0x04 ) else False
   self . to_etr = True if ( IIIiIII1 & 0x02 ) else False
   self . to_ms = True if ( IIIiIII1 & 0x01 ) else False
   if 68 - 68: OoooooooOO * I11i
  if ( self . type == LISP_NAT_INFO ) :
   self . info_reply = True if ( IIIiIII1 & 0x08 ) else False
   if 86 - 86: o0oOOo0O0Ooo / OoOoOO00
  return ( True )
  if 40 - 40: iII111i
  if 62 - 62: ooOoO0o / OOooOOo
 def is_info_request ( self ) :
  return ( ( self . type == LISP_NAT_INFO and self . is_info_reply ( ) == False ) )
  if 74 - 74: iII111i % I1Ii111 / I1Ii111 - iIii1I11I1II1 - II111iiii + OOooOOo
  if 92 - 92: I11i % I1Ii111
 def is_info_reply ( self ) :
  return ( True if self . info_reply else False )
  if 18 - 18: ooOoO0o + I1Ii111 / OOooOOo / oO0o + iIii1I11I1II1 % IiII
  if 94 - 94: I11i
 def is_rloc_probe ( self ) :
  return ( True if self . rloc_probe else False )
  if 37 - 37: oO0o
  if 52 - 52: I1ii11iIi11i * I1IiiI . OOooOOo + i1IIi % oO0o / iIii1I11I1II1
 def is_smr ( self ) :
  return ( True if self . smr_bit else False )
  if 68 - 68: I1Ii111 - OoOoOO00 . i11iIiiIii + o0oOOo0O0Ooo
  if 71 - 71: i11iIiiIii / i1IIi * I1IiiI / OoOoOO00
 def is_smr_invoked ( self ) :
  return ( True if self . smr_invoked_bit else False )
  if 33 - 33: I11i . Oo0Ooo
  if 89 - 89: iII111i + i1IIi - IiII + ooOoO0o . II111iiii
 def is_ddt ( self ) :
  return ( True if self . ddt_bit else False )
  if 85 - 85: iIii1I11I1II1 - Ii1I * Oo0Ooo . oO0o + I1Ii111
  if 13 - 13: O0 + iIii1I11I1II1 % II111iiii + iIii1I11I1II1
 def is_to_etr ( self ) :
  return ( True if self . to_etr else False )
  if 85 - 85: I1IiiI * iIii1I11I1II1 . iII111i / iII111i
  if 43 - 43: I1IiiI
 def is_to_ms ( self ) :
  return ( True if self . to_ms else False )
  if 78 - 78: OoO0O00 % II111iiii + OoOoOO00 / I1IiiI
  if 34 - 34: o0oOOo0O0Ooo % I1ii11iIi11i + Ii1I * I11i / oO0o
  if 18 - 18: ooOoO0o
  if 92 - 92: OoO0O00 % iIii1I11I1II1 / IiII * iII111i . i1IIi + oO0o
  if 24 - 24: IiII . iII111i * IiII % i11iIiiIii . i11iIiiIii + i1IIi
  if 64 - 64: iIii1I11I1II1 / IiII / Oo0Ooo - I1ii11iIi11i
  if 100 - 100: IiII + i1IIi * OoO0O00
  if 64 - 64: oO0o * i11iIiiIii . Oo0Ooo
  if 52 - 52: Oo0Ooo / ooOoO0o / iII111i - o0oOOo0O0Ooo / iII111i
  if 74 - 74: i1IIi . iIii1I11I1II1
  if 85 - 85: I1IiiI
  if 10 - 10: O0 . II111iiii / OoooooooOO
  if 72 - 72: OoooooooOO . o0oOOo0O0Ooo + O0
  if 46 - 46: OoOoOO00 * I11i / oO0o + Oo0Ooo + IiII
  if 95 - 95: o0oOOo0O0Ooo - Ii1I
  if 67 - 67: I1ii11iIi11i * Oo0Ooo % o0oOOo0O0Ooo
  if 19 - 19: OoOoOO00 . OOooOOo . OoooooooOO
  if 79 - 79: OOooOOo * ooOoO0o * I1IiiI * I1ii11iIi11i / I1ii11iIi11i
  if 62 - 62: ooOoO0o * Ii1I % I1ii11iIi11i - i1IIi - I1ii11iIi11i
  if 24 - 24: OOooOOo
  if 71 - 71: IiII - i1IIi
  if 56 - 56: OoOoOO00 + oO0o
  if 74 - 74: iII111i / I1Ii111 / II111iiii - iII111i / oO0o % I11i
  if 19 - 19: IiII % OoooooooOO + OoooooooOO
  if 7 - 7: i1IIi
  if 91 - 91: OoOoOO00 - OoOoOO00 . IiII
  if 33 - 33: I1Ii111 - iIii1I11I1II1 / Ii1I % O0
  if 80 - 80: IiII % OoooooooOO - IiII
  if 27 - 27: I1Ii111 - o0oOOo0O0Ooo * I1ii11iIi11i - I1IiiI
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
  if 65 - 65: II111iiii % i1IIi
  if 13 - 13: OoO0O00 * I1Ii111 + Oo0Ooo - IiII
 def print_map_register ( self ) :
  i11IIii = lisp_hex_string ( self . xtr_id )
  if 48 - 48: iII111i
  oooOo = ( "{} -> flags: {}{}{}{}{}{}{}{}{}, record-count: " +
 "{}, nonce: 0x{}, key/alg-id: {}/{}{}, auth-len: {}, xtr-id: " +
 "0x{}, site-id: {}" )
  if 26 - 26: I1ii11iIi11i . Ii1I % o0oOOo0O0Ooo
  lprint ( oooOo . format ( bold ( "Map-Register" , False ) , "P" if self . proxy_reply_requested else "p" ,
  # i11iIiiIii
 "S" if self . lisp_sec_present else "s" ,
 "I" if self . xtr_id_present else "i" ,
 "T" if self . use_ttl_for_timeout else "t" ,
 "R" if self . merge_register_requested else "r" ,
 "M" if self . mobile_node else "m" ,
 "N" if self . map_notify_requested else "n" ,
 "F" if self . map_register_refresh else "f" ,
 "E" if self . encrypt_bit else "e" ,
 self . record_count , lisp_hex_string ( self . nonce ) , self . key_id ,
 self . alg_id , " (sha1)" if ( self . key_id == LISP_SHA_1_96_ALG_ID ) else ( " (sha2)" if ( self . key_id == LISP_SHA_256_128_ALG_ID ) else "" ) , self . auth_len , i11IIii , self . site_id ) )
  if 92 - 92: iIii1I11I1II1 - Ii1I + OoooooooOO . o0oOOo0O0Ooo - o0oOOo0O0Ooo
  if 82 - 82: iIii1I11I1II1 + I11i . I11i * OoooooooOO + i11iIiiIii
  if 46 - 46: i1IIi + O0
  if 5 - 5: o0oOOo0O0Ooo + I1IiiI / OoooooooOO % i11iIiiIii % OoooooooOO - o0oOOo0O0Ooo
 def encode ( self ) :
  oOoOo00oo = ( LISP_MAP_REGISTER << 28 ) | self . record_count
  if ( self . proxy_reply_requested ) : oOoOo00oo |= 0x08000000
  if ( self . lisp_sec_present ) : oOoOo00oo |= 0x04000000
  if ( self . xtr_id_present ) : oOoOo00oo |= 0x02000000
  if ( self . map_register_refresh ) : oOoOo00oo |= 0x1000
  if ( self . use_ttl_for_timeout ) : oOoOo00oo |= 0x800
  if ( self . merge_register_requested ) : oOoOo00oo |= 0x400
  if ( self . mobile_node ) : oOoOo00oo |= 0x200
  if ( self . map_notify_requested ) : oOoOo00oo |= 0x100
  if ( self . encryption_key_id != None ) :
   oOoOo00oo |= 0x2000
   oOoOo00oo |= self . encryption_key_id << 14
   if 53 - 53: OoO0O00 + i11iIiiIii / iIii1I11I1II1
   if 1 - 1: IiII % i1IIi
   if 41 - 41: OoO0O00 * OoO0O00 / iII111i + I1ii11iIi11i . o0oOOo0O0Ooo
   if 84 - 84: i11iIiiIii + OoO0O00 * I1IiiI + I1ii11iIi11i / Ii1I
   if 80 - 80: I1ii11iIi11i
  if ( self . alg_id == LISP_NONE_ALG_ID ) :
   self . auth_len = 0
  else :
   if ( self . alg_id == LISP_SHA_1_96_ALG_ID ) :
    self . auth_len = LISP_SHA1_160_AUTH_DATA_LEN
    if 67 - 67: II111iiii
   if ( self . alg_id == LISP_SHA_256_128_ALG_ID ) :
    self . auth_len = LISP_SHA2_256_AUTH_DATA_LEN
    if 2 - 2: o0oOOo0O0Ooo - O0 * Ii1I % IiII
    if 64 - 64: i1IIi . ooOoO0o
    if 7 - 7: oO0o . iII111i - iII111i / I1Ii111 % Oo0Ooo
  i1II1IiiIi = struct . pack ( "I" , socket . htonl ( oOoOo00oo ) )
  i1II1IiiIi += struct . pack ( "QBBH" , self . nonce , self . key_id , self . alg_id ,
 socket . htons ( self . auth_len ) )
  if 61 - 61: oO0o - I1ii11iIi11i / iII111i % I1ii11iIi11i + OoO0O00 / Oo0Ooo
  i1II1IiiIi = self . zero_auth ( i1II1IiiIi )
  return ( i1II1IiiIi )
  if 10 - 10: i11iIiiIii / OoOoOO00
  if 27 - 27: I1IiiI / OoooooooOO
 def zero_auth ( self , packet ) :
  I11iiIi1i1 = struct . calcsize ( "I" ) + struct . calcsize ( "QHH" )
  OOO00Oo00o = ""
  IiII1Iiii = 0
  if ( self . alg_id == LISP_NONE_ALG_ID ) : return ( packet )
  if ( self . alg_id == LISP_SHA_1_96_ALG_ID ) :
   OOO00Oo00o = struct . pack ( "QQI" , 0 , 0 , 0 )
   IiII1Iiii = struct . calcsize ( "QQI" )
   if 16 - 16: iII111i . O0 - I1Ii111 * I1Ii111
  if ( self . alg_id == LISP_SHA_256_128_ALG_ID ) :
   OOO00Oo00o = struct . pack ( "QQQQ" , 0 , 0 , 0 , 0 )
   IiII1Iiii = struct . calcsize ( "QQQQ" )
   if 80 - 80: Ii1I % I1ii11iIi11i
  packet = packet [ 0 : I11iiIi1i1 ] + OOO00Oo00o + packet [ I11iiIi1i1 + IiII1Iiii : : ]
  return ( packet )
  if 60 - 60: OoO0O00 % iIii1I11I1II1 . ooOoO0o * o0oOOo0O0Ooo % ooOoO0o - I1Ii111
  if 51 - 51: ooOoO0o * IiII * iIii1I11I1II1 / OoOoOO00 % IiII
 def encode_auth ( self , packet ) :
  I11iiIi1i1 = struct . calcsize ( "I" ) + struct . calcsize ( "QHH" )
  IiII1Iiii = self . auth_len
  OOO00Oo00o = self . auth_data
  packet = packet [ 0 : I11iiIi1i1 ] + OOO00Oo00o + packet [ I11iiIi1i1 + IiII1Iiii : : ]
  return ( packet )
  if 36 - 36: I1ii11iIi11i * o0oOOo0O0Ooo + i11iIiiIii + OoooooooOO
  if 82 - 82: OoOoOO00 . OoOoOO00
 def decode ( self , packet ) :
  IIiIiIii11I1 = packet
  oOoOo000 = "I"
  O0OOoooO = struct . calcsize ( oOoOo000 )
  if ( len ( packet ) < O0OOoooO ) : return ( [ None , None ] )
  if 60 - 60: OoooooooOO * Oo0Ooo % I1Ii111
  oOoOo00oo = struct . unpack ( oOoOo000 , packet [ : O0OOoooO ] )
  oOoOo00oo = socket . ntohl ( oOoOo00oo [ 0 ] )
  packet = packet [ O0OOoooO : : ]
  if 68 - 68: O0 - Oo0Ooo . II111iiii % Ii1I % Oo0Ooo + i11iIiiIii
  oOoOo000 = "QBBH"
  O0OOoooO = struct . calcsize ( oOoOo000 )
  if ( len ( packet ) < O0OOoooO ) : return ( [ None , None ] )
  if 90 - 90: II111iiii / OOooOOo * I1IiiI - Oo0Ooo
  self . nonce , self . key_id , self . alg_id , self . auth_len = struct . unpack ( oOoOo000 , packet [ : O0OOoooO ] )
  if 11 - 11: IiII - oO0o - oO0o / I1Ii111 * II111iiii % oO0o
  if 39 - 39: oO0o / i11iIiiIii
  self . auth_len = socket . ntohs ( self . auth_len )
  self . proxy_reply_requested = True if ( oOoOo00oo & 0x08000000 ) else False
  if 46 - 46: i11iIiiIii . I1ii11iIi11i
  self . lisp_sec_present = True if ( oOoOo00oo & 0x04000000 ) else False
  self . xtr_id_present = True if ( oOoOo00oo & 0x02000000 ) else False
  self . use_ttl_for_timeout = True if ( oOoOo00oo & 0x800 ) else False
  self . map_register_refresh = True if ( oOoOo00oo & 0x1000 ) else False
  self . merge_register_requested = True if ( oOoOo00oo & 0x400 ) else False
  self . mobile_node = True if ( oOoOo00oo & 0x200 ) else False
  self . map_notify_requested = True if ( oOoOo00oo & 0x100 ) else False
  self . record_count = oOoOo00oo & 0xff
  if 11 - 11: ooOoO0o
  if 36 - 36: OoO0O00 % iIii1I11I1II1 - I1ii11iIi11i - i1IIi % o0oOOo0O0Ooo
  if 54 - 54: IiII - II111iiii . ooOoO0o + Ii1I
  if 45 - 45: oO0o + II111iiii . iII111i / I1ii11iIi11i
  self . encrypt_bit = True if oOoOo00oo & 0x2000 else False
  if ( self . encrypt_bit ) :
   self . encryption_key_id = ( oOoOo00oo >> 14 ) & 0x7
   if 76 - 76: Ii1I + iII111i - IiII * iIii1I11I1II1 % i1IIi
   if 72 - 72: ooOoO0o + II111iiii . O0 - iII111i / OoooooooOO . I1Ii111
   if 28 - 28: iIii1I11I1II1 . O0
   if 32 - 32: OoooooooOO
   if 29 - 29: I1ii11iIi11i
  if ( self . xtr_id_present ) :
   if ( self . decode_xtr_id ( IIiIiIii11I1 ) == False ) : return ( [ None , None ] )
   if 41 - 41: Ii1I
   if 49 - 49: Ii1I % II111iiii . Ii1I - o0oOOo0O0Ooo - I11i * IiII
  packet = packet [ O0OOoooO : : ]
  if 47 - 47: O0 . o0oOOo0O0Ooo / Ii1I * iII111i
  if 63 - 63: I1Ii111 - oO0o - iII111i - ooOoO0o / oO0o + OoO0O00
  if 94 - 94: IiII / I1IiiI . II111iiii
  if 32 - 32: oO0o . OOooOOo % OOooOOo . OoOoOO00
  if ( self . auth_len != 0 ) :
   if ( len ( packet ) < self . auth_len ) : return ( [ None , None ] )
   if 37 - 37: OOooOOo + O0 + OOooOOo . iII111i . o0oOOo0O0Ooo
   if ( self . alg_id not in ( LISP_NONE_ALG_ID , LISP_SHA_1_96_ALG_ID ,
 LISP_SHA_256_128_ALG_ID ) ) :
    lprint ( "Invalid authentication alg-id: {}" . format ( self . alg_id ) )
    return ( [ None , None ] )
    if 78 - 78: I1IiiI / I11i + o0oOOo0O0Ooo . Oo0Ooo / O0
    if 49 - 49: I1ii11iIi11i
   IiII1Iiii = self . auth_len
   if ( self . alg_id == LISP_SHA_1_96_ALG_ID ) :
    O0OOoooO = struct . calcsize ( "QQI" )
    if ( IiII1Iiii < O0OOoooO ) :
     lprint ( "Invalid sha1-96 authentication length" )
     return ( [ None , None ] )
     if 66 - 66: o0oOOo0O0Ooo . I1ii11iIi11i
    iI111I , i1 , iiII1I1I1ii = struct . unpack ( "QQI" , packet [ : IiII1Iiii ] )
    Iii1I1111iI = ""
   elif ( self . alg_id == LISP_SHA_256_128_ALG_ID ) :
    O0OOoooO = struct . calcsize ( "QQQQ" )
    if ( IiII1Iiii < O0OOoooO ) :
     lprint ( "Invalid sha2-256 authentication length" )
     return ( [ None , None ] )
     if 71 - 71: Oo0Ooo
    iI111I , i1 , iiII1I1I1ii , Iii1I1111iI = struct . unpack ( "QQQQ" ,
 packet [ : IiII1Iiii ] )
   else :
    lprint ( "Unsupported authentication alg-id value {}" . format ( self . alg_id ) )
    if 34 - 34: O0 / OOooOOo % OoooooooOO . OoooooooOO
    return ( [ None , None ] )
    if 30 - 30: OoO0O00 % OOooOOo * OoO0O00 + oO0o % iIii1I11I1II1 + OoooooooOO
   self . auth_data = lisp_concat_auth_data ( self . alg_id , iI111I , i1 ,
 iiII1I1I1ii , Iii1I1111iI )
   IIiIiIii11I1 = self . zero_auth ( IIiIiIii11I1 )
   packet = packet [ self . auth_len : : ]
   if 71 - 71: Oo0Ooo
  return ( [ IIiIiIii11I1 , packet ] )
  if 98 - 98: o0oOOo0O0Ooo * Oo0Ooo - Ii1I . ooOoO0o
  if 2 - 2: Oo0Ooo - ooOoO0o % iIii1I11I1II1
 def encode_xtr_id ( self , packet ) :
  o0O0o0O0O = self . xtr_id >> 64
  ii11iIi1IiI = self . xtr_id & 0xffffffffffffffff
  o0O0o0O0O = byte_swap_64 ( o0O0o0O0O )
  ii11iIi1IiI = byte_swap_64 ( ii11iIi1IiI )
  ooO0OOoOooO = byte_swap_64 ( self . site_id )
  packet += struct . pack ( "QQQ" , o0O0o0O0O , ii11iIi1IiI , ooO0OOoOooO )
  return ( packet )
  if 76 - 76: Oo0Ooo * ooOoO0o % OOooOOo . OoO0O00
  if 31 - 31: I1IiiI - OoooooooOO . IiII
 def decode_xtr_id ( self , packet ) :
  O0OOoooO = struct . calcsize ( "QQQ" )
  if ( len ( packet ) < O0OOoooO ) : return ( [ None , None ] )
  packet = packet [ len ( packet ) - O0OOoooO : : ]
  o0O0o0O0O , ii11iIi1IiI , ooO0OOoOooO = struct . unpack ( "QQQ" ,
 packet [ : O0OOoooO ] )
  o0O0o0O0O = byte_swap_64 ( o0O0o0O0O )
  ii11iIi1IiI = byte_swap_64 ( ii11iIi1IiI )
  self . xtr_id = ( o0O0o0O0O << 64 ) | ii11iIi1IiI
  self . site_id = byte_swap_64 ( ooO0OOoOooO )
  return ( True )
  if 12 - 12: I11i . Ii1I + I11i - OOooOOo * iII111i - O0
  if 44 - 44: i1IIi % oO0o / OoOoOO00 % IiII . I1ii11iIi11i
  if 38 - 38: OoOoOO00 . I11i
  if 66 - 66: iII111i
  if 61 - 61: i11iIiiIii / oO0o / i11iIiiIii
  if 61 - 61: I11i / iIii1I11I1II1 - i1IIi - IiII * i11iIiiIii
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
  if 95 - 95: iIii1I11I1II1 + OoOoOO00 . I1IiiI + OoOoOO00 * I11i + OOooOOo
  if 14 - 14: Ii1I - O0
 def print_notify ( self ) :
  OOO00Oo00o = binascii . hexlify ( self . auth_data )
  if ( self . alg_id == LISP_SHA_1_96_ALG_ID and len ( OOO00Oo00o ) != 40 ) :
   OOO00Oo00o = self . auth_data
  elif ( self . alg_id == LISP_SHA_256_128_ALG_ID and len ( OOO00Oo00o ) != 64 ) :
   OOO00Oo00o = self . auth_data
   if 68 - 68: II111iiii - I1ii11iIi11i - OoO0O00 * iIii1I11I1II1 / I1IiiI * I1ii11iIi11i
  oooOo = ( "{} -> record-count: {}, nonce: 0x{}, key/alg-id: " +
 "{}{}{}, auth-len: {}, auth-data: {}" )
  lprint ( oooOo . format ( bold ( "Map-Notify-Ack" , False ) if self . map_notify_ack else bold ( "Map-Notify" , False ) ,
  # IiII % II111iiii * I11i
 self . record_count , lisp_hex_string ( self . nonce ) , self . key_id ,
 self . alg_id , " (sha1)" if ( self . key_id == LISP_SHA_1_96_ALG_ID ) else ( " (sha2)" if ( self . key_id == LISP_SHA_256_128_ALG_ID ) else "" ) , self . auth_len , OOO00Oo00o ) )
  if 27 - 27: iII111i
  if 35 - 35: iII111i + I1IiiI
  if 78 - 78: iII111i
  if 15 - 15: iII111i + i11iIiiIii % O0 % I1Ii111 + OoO0O00 * ooOoO0o
 def zero_auth ( self , packet ) :
  if ( self . alg_id == LISP_NONE_ALG_ID ) : return ( packet )
  if ( self . alg_id == LISP_SHA_1_96_ALG_ID ) :
   OOO00Oo00o = struct . pack ( "QQI" , 0 , 0 , 0 )
   if 46 - 46: iII111i . OoOoOO00
  if ( self . alg_id == LISP_SHA_256_128_ALG_ID ) :
   OOO00Oo00o = struct . pack ( "QQQQ" , 0 , 0 , 0 , 0 )
   if 18 - 18: I1ii11iIi11i
  packet += OOO00Oo00o
  return ( packet )
  if 33 - 33: i11iIiiIii % o0oOOo0O0Ooo . iII111i * OOooOOo / I11i
  if 25 - 25: OoO0O00
 def encode ( self , eid_records , password ) :
  if ( self . map_notify_ack ) :
   oOoOo00oo = ( LISP_MAP_NOTIFY_ACK << 28 ) | self . record_count
  else :
   oOoOo00oo = ( LISP_MAP_NOTIFY << 28 ) | self . record_count
   if 39 - 39: Ii1I * OoOoOO00 + Oo0Ooo . OOooOOo - O0 * I1ii11iIi11i
  i1II1IiiIi = struct . pack ( "I" , socket . htonl ( oOoOo00oo ) )
  i1II1IiiIi += struct . pack ( "QBBH" , self . nonce , self . key_id , self . alg_id ,
 socket . htons ( self . auth_len ) )
  if 98 - 98: IiII * iII111i . OoooooooOO . O0
  if ( self . alg_id == LISP_NONE_ALG_ID ) :
   self . packet = i1II1IiiIi + eid_records
   return ( self . packet )
   if 89 - 89: iII111i / O0 % OoooooooOO - O0 . OoO0O00
   if 32 - 32: ooOoO0o
   if 26 - 26: O0 * Ii1I - I1IiiI - iII111i / iIii1I11I1II1
   if 57 - 57: I1ii11iIi11i - OoO0O00 * iIii1I11I1II1
   if 26 - 26: OoO0O00 % ooOoO0o % o0oOOo0O0Ooo % OoOoOO00 . iII111i % O0
  i1II1IiiIi = self . zero_auth ( i1II1IiiIi )
  i1II1IiiIi += eid_records
  if 91 - 91: II111iiii . Oo0Ooo . oO0o - OoooooooOO / OoOoOO00
  IiiiI1I1iI11 = lisp_hash_me ( i1II1IiiIi , self . alg_id , password , False )
  if 30 - 30: I11i % o0oOOo0O0Ooo + i1IIi * OoooooooOO * OoO0O00 - II111iiii
  I11iiIi1i1 = struct . calcsize ( "I" ) + struct . calcsize ( "QHH" )
  IiII1Iiii = self . auth_len
  self . auth_data = IiiiI1I1iI11
  i1II1IiiIi = i1II1IiiIi [ 0 : I11iiIi1i1 ] + IiiiI1I1iI11 + i1II1IiiIi [ I11iiIi1i1 + IiII1Iiii : : ]
  self . packet = i1II1IiiIi
  return ( i1II1IiiIi )
  if 55 - 55: OoO0O00
  if 20 - 20: ooOoO0o * I1Ii111 * o0oOOo0O0Ooo - ooOoO0o
 def decode ( self , packet ) :
  IIiIiIii11I1 = packet
  oOoOo000 = "I"
  O0OOoooO = struct . calcsize ( oOoOo000 )
  if ( len ( packet ) < O0OOoooO ) : return ( None )
  if 32 - 32: Ii1I * oO0o
  oOoOo00oo = struct . unpack ( oOoOo000 , packet [ : O0OOoooO ] )
  oOoOo00oo = socket . ntohl ( oOoOo00oo [ 0 ] )
  self . map_notify_ack = ( ( oOoOo00oo >> 28 ) == LISP_MAP_NOTIFY_ACK )
  self . record_count = oOoOo00oo & 0xff
  packet = packet [ O0OOoooO : : ]
  if 85 - 85: i11iIiiIii . OoO0O00 + OoO0O00
  oOoOo000 = "QBBH"
  O0OOoooO = struct . calcsize ( oOoOo000 )
  if ( len ( packet ) < O0OOoooO ) : return ( None )
  if 28 - 28: Oo0Ooo
  self . nonce , self . key_id , self . alg_id , self . auth_len = struct . unpack ( oOoOo000 , packet [ : O0OOoooO ] )
  if 62 - 62: Oo0Ooo + OoooooooOO / iII111i
  self . nonce_key = lisp_hex_string ( self . nonce )
  self . auth_len = socket . ntohs ( self . auth_len )
  packet = packet [ O0OOoooO : : ]
  self . eid_records = packet [ self . auth_len : : ]
  if 60 - 60: Ii1I / OoOoOO00 . I11i % OOooOOo
  if ( self . auth_len == 0 ) : return ( self . eid_records )
  if 61 - 61: O0 . Ii1I . O0 * i11iIiiIii * II111iiii / I1Ii111
  if 69 - 69: I11i
  if 17 - 17: I11i
  if 38 - 38: I1Ii111 % OOooOOo
  if ( len ( packet ) < self . auth_len ) : return ( None )
  if 9 - 9: O0 . iIii1I11I1II1
  IiII1Iiii = self . auth_len
  if ( self . alg_id == LISP_SHA_1_96_ALG_ID ) :
   iI111I , i1 , iiII1I1I1ii = struct . unpack ( "QQI" , packet [ : IiII1Iiii ] )
   Iii1I1111iI = ""
   if 44 - 44: I1ii11iIi11i % IiII
  if ( self . alg_id == LISP_SHA_256_128_ALG_ID ) :
   iI111I , i1 , iiII1I1I1ii , Iii1I1111iI = struct . unpack ( "QQQQ" ,
 packet [ : IiII1Iiii ] )
   if 6 - 6: OoO0O00
  self . auth_data = lisp_concat_auth_data ( self . alg_id , iI111I , i1 ,
 iiII1I1I1ii , Iii1I1111iI )
  if 82 - 82: iIii1I11I1II1 . I11i / IiII / OOooOOo * II111iiii % oO0o
  O0OOoooO = struct . calcsize ( "I" ) + struct . calcsize ( "QHH" )
  packet = self . zero_auth ( IIiIiIii11I1 [ : O0OOoooO ] )
  O0OOoooO += IiII1Iiii
  packet += IIiIiIii11I1 [ O0OOoooO : : ]
  return ( packet )
  if 62 - 62: II111iiii
  if 96 - 96: I11i % OoOoOO00 * I1ii11iIi11i
  if 94 - 94: Oo0Ooo - i1IIi . O0 % Oo0Ooo . ooOoO0o
  if 63 - 63: i11iIiiIii % I1ii11iIi11i % I1IiiI . IiII * o0oOOo0O0Ooo + OOooOOo
  if 77 - 77: o0oOOo0O0Ooo
  if 63 - 63: ooOoO0o * oO0o + ooOoO0o * Ii1I + Oo0Ooo / I1ii11iIi11i
  if 15 - 15: O0 . I1ii11iIi11i * I1ii11iIi11i
  if 65 - 65: I1Ii111 + O0 % o0oOOo0O0Ooo
  if 72 - 72: OOooOOo . OoOoOO00 / II111iiii
  if 69 - 69: OOooOOo * II111iiii - ooOoO0o - i1IIi + i11iIiiIii
  if 50 - 50: OoooooooOO * i1IIi / oO0o
  if 83 - 83: i1IIi
  if 38 - 38: OoooooooOO * iIii1I11I1II1
  if 54 - 54: OoooooooOO . I1Ii111
  if 71 - 71: Ii1I
  if 31 - 31: I11i . i11iIiiIii . OoO0O00 * Oo0Ooo % Ii1I . o0oOOo0O0Ooo
  if 92 - 92: OoooooooOO / O0 * i1IIi + iIii1I11I1II1
  if 93 - 93: ooOoO0o % I1Ii111
  if 46 - 46: I1ii11iIi11i * OoOoOO00 * IiII * I1ii11iIi11i . I1ii11iIi11i
  if 43 - 43: ooOoO0o . i1IIi
  if 68 - 68: IiII % Oo0Ooo . O0 - OoOoOO00 + I1ii11iIi11i . i11iIiiIii
  if 45 - 45: I1IiiI
  if 17 - 17: OoooooooOO - ooOoO0o + Ii1I . OoooooooOO % Oo0Ooo
  if 92 - 92: I1Ii111 - OOooOOo % OoO0O00 - o0oOOo0O0Ooo % i1IIi
  if 38 - 38: I1ii11iIi11i . I11i / OoOoOO00 % I11i
  if 10 - 10: O0 . I1IiiI * o0oOOo0O0Ooo / iII111i
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
  if 82 - 82: O0 / iII111i * OoO0O00 - I11i + Oo0Ooo
  if 47 - 47: I1ii11iIi11i * I1IiiI / I1ii11iIi11i + Ii1I * II111iiii
 def print_prefix ( self ) :
  if ( self . target_group . is_null ( ) ) :
   return ( green ( self . target_eid . print_prefix ( ) , False ) )
   if 78 - 78: I1Ii111 - i1IIi + OoOoOO00 + Oo0Ooo * I1ii11iIi11i * o0oOOo0O0Ooo
  return ( green ( self . target_eid . print_sg ( self . target_group ) , False ) )
  if 97 - 97: i1IIi
  if 29 - 29: I1IiiI
 def print_map_request ( self ) :
  i11IIii = ""
  if ( self . xtr_id != None and self . subscribe_bit ) :
   i11IIii = "subscribe, xtr-id: 0x{}, " . format ( lisp_hex_string ( self . xtr_id ) )
   if 37 - 37: I1ii11iIi11i * I1Ii111 * I1IiiI * O0
   if 35 - 35: I1IiiI - I1ii11iIi11i * iII111i + IiII / i1IIi
   if 46 - 46: Oo0Ooo . ooOoO0o % Oo0Ooo / II111iiii * ooOoO0o * OOooOOo
  oooOo = ( "{} -> flags: {}{}{}{}{}{}{}{}{}{}, itr-rloc-" +
 "count: {} (+1), record-count: {}, nonce: 0x{}, source-eid: " +
 "afi {}, {}{}, target-eid: afi {}, {}, {}ITR-RLOCs:" )
  if 59 - 59: I1Ii111 * iII111i
  lprint ( oooOo . format ( bold ( "Map-Request" , False ) , "A" if self . auth_bit else "a" ,
  # I1IiiI / I11i
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
 self . target_eid . afi , green ( self . print_prefix ( ) , False ) , i11IIii ) )
  if 6 - 6: Ii1I / ooOoO0o / i11iIiiIii % o0oOOo0O0Ooo
  o00OO0o0 = self . keys
  for o00ooOOo0ooO0 in self . itr_rlocs :
   lprint ( "  itr-rloc: afi {} {}{}" . format ( o00ooOOo0ooO0 . afi ,
 red ( o00ooOOo0ooO0 . print_address_no_iid ( ) , False ) ,
 "" if ( o00OO0o0 == None ) else ", " + o00OO0o0 [ 1 ] . print_keys ( ) ) )
   o00OO0o0 = None
   if 28 - 28: I1Ii111 + II111iiii % OOooOOo * i11iIiiIii % oO0o + OoooooooOO
   if 65 - 65: o0oOOo0O0Ooo . IiII % i1IIi % OoOoOO00 + I1ii11iIi11i
   if 41 - 41: OoOoOO00 / iIii1I11I1II1
 def sign_map_request ( self , privkey ) :
  O0O0o0OOOooo0 = self . signature_eid . print_address ( )
  iiI1i = self . source_eid . print_address ( )
  i1i11IIi11iiI = self . target_eid . print_address ( )
  ii1Ii111I11 = lisp_hex_string ( self . nonce ) + iiI1i + i1i11IIi11iiI
  self . map_request_signature = privkey . sign ( ii1Ii111I11 )
  IiiiI1I1i = binascii . b2a_base64 ( self . map_request_signature )
  IiiiI1I1i = { "source-eid" : iiI1i , "signature-eid" : O0O0o0OOOooo0 ,
 "signature" : IiiiI1I1i }
  return ( json . dumps ( IiiiI1I1i ) )
  if 53 - 53: Oo0Ooo . OOooOOo + iII111i * Ii1I
  if 23 - 23: o0oOOo0O0Ooo + ooOoO0o
 def verify_map_request_sig ( self , pubkey ) :
  i1i1iIi1IiI = green ( self . signature_eid . print_address ( ) , False )
  if ( pubkey == None ) :
   lprint ( "Public-key not found for signature-EID {}" . format ( i1i1iIi1IiI ) )
   return ( False )
   if 16 - 16: oO0o
   if 96 - 96: ooOoO0o / oO0o % O0 / OOooOOo * OoO0O00 * I11i
  iiI1i = self . source_eid . print_address ( )
  i1i11IIi11iiI = self . target_eid . print_address ( )
  ii1Ii111I11 = lisp_hex_string ( self . nonce ) + iiI1i + i1i11IIi11iiI
  pubkey = binascii . a2b_base64 ( pubkey )
  if 27 - 27: OoOoOO00 % Ii1I / i1IIi . i1IIi * OoooooooOO % ooOoO0o
  O0o0O00O0 = True
  try :
   iii11 = ecdsa . VerifyingKey . from_pem ( pubkey )
  except :
   lprint ( "Invalid public-key in mapping system for sig-eid {}" . format ( self . signature_eid . print_address_no_iid ( ) ) )
   if 67 - 67: OoooooooOO * OoO0O00 * iII111i + ooOoO0o - i1IIi
   O0o0O00O0 = False
   if 66 - 66: IiII / OoOoOO00 % O0 % o0oOOo0O0Ooo - OOooOOo / OoOoOO00
   if 11 - 11: I1IiiI + IiII
  if ( O0o0O00O0 ) :
   try :
    O0o0O00O0 = iii11 . verify ( self . map_request_signature , ii1Ii111I11 )
   except :
    O0o0O00O0 = False
    if 95 - 95: I1IiiI - OOooOOo . Oo0Ooo / O0 + Ii1I
    if 67 - 67: OoOoOO00 % Oo0Ooo
    if 7 - 7: i11iIiiIii % I1ii11iIi11i / I1Ii111 % Oo0Ooo - OoO0O00
  o0OOo0o0 = bold ( "passed" if O0o0O00O0 else "failed" , False )
  lprint ( "Signature verification {} for EID {}" . format ( o0OOo0o0 , i1i1iIi1IiI ) )
  return ( O0o0O00O0 )
  if 60 - 60: o0oOOo0O0Ooo / Oo0Ooo
  if 19 - 19: iIii1I11I1II1 . OoO0O00 / OoooooooOO
 def encode ( self , probe_dest , probe_port ) :
  oOoOo00oo = ( LISP_MAP_REQUEST << 28 ) | self . record_count
  oOoOo00oo = oOoOo00oo | ( self . itr_rloc_count << 8 )
  if ( self . auth_bit ) : oOoOo00oo |= 0x08000000
  if ( self . map_data_present ) : oOoOo00oo |= 0x04000000
  if ( self . rloc_probe ) : oOoOo00oo |= 0x02000000
  if ( self . smr_bit ) : oOoOo00oo |= 0x01000000
  if ( self . pitr_bit ) : oOoOo00oo |= 0x00800000
  if ( self . smr_invoked_bit ) : oOoOo00oo |= 0x00400000
  if ( self . mobile_node ) : oOoOo00oo |= 0x00200000
  if ( self . xtr_id_present ) : oOoOo00oo |= 0x00100000
  if ( self . local_xtr ) : oOoOo00oo |= 0x00004000
  if ( self . dont_reply_bit ) : oOoOo00oo |= 0x00002000
  if 2 - 2: O0 - O0 % I1Ii111 / I1ii11iIi11i
  i1II1IiiIi = struct . pack ( "I" , socket . htonl ( oOoOo00oo ) )
  i1II1IiiIi += struct . pack ( "Q" , self . nonce )
  if 76 - 76: OoO0O00 * oO0o - OoO0O00
  if 57 - 57: OoooooooOO / OoOoOO00 + oO0o . Ii1I
  if 14 - 14: i11iIiiIii % OOooOOo * o0oOOo0O0Ooo * OoOoOO00
  if 55 - 55: I1Ii111 * OOooOOo * I1Ii111
  if 70 - 70: O0 . Ii1I
  if 33 - 33: OOooOOo * Ii1I
  oooIII1II1I1iI = False
  oOOOO = self . privkey_filename
  if ( oOOOO != None and os . path . exists ( oOOOO ) ) :
   Oo0OO0o0oOO0 = open ( oOOOO , "r" ) ; iii11 = Oo0OO0o0oOO0 . read ( ) ; Oo0OO0o0oOO0 . close ( )
   try :
    iii11 = ecdsa . SigningKey . from_pem ( iii11 )
   except :
    return ( None )
    if 48 - 48: I11i
   O0OoOOo0o = self . sign_map_request ( iii11 )
   oooIII1II1I1iI = True
  elif ( self . map_request_signature != None ) :
   IiiiI1I1i = binascii . b2a_base64 ( self . map_request_signature )
   O0OoOOo0o = { "source-eid" : self . source_eid . print_address ( ) ,
 "signature-eid" : self . signature_eid . print_address ( ) ,
 "signature" : IiiiI1I1i }
   O0OoOOo0o = json . dumps ( O0OoOOo0o )
   oooIII1II1I1iI = True
   if 21 - 21: I11i - I1IiiI / OoooooooOO . i1IIi + II111iiii
  if ( oooIII1II1I1iI ) :
   oOOi1I111II = LISP_LCAF_JSON_TYPE
   O0OOOOO0O = socket . htons ( LISP_AFI_LCAF )
   ii111 = socket . htons ( len ( O0OoOOo0o ) + 2 )
   i1oO0o00oOo00oO = socket . htons ( len ( O0OoOOo0o ) )
   i1II1IiiIi += struct . pack ( "HBBBBHH" , O0OOOOO0O , 0 , 0 , oOOi1I111II , 0 ,
 ii111 , i1oO0o00oOo00oO )
   i1II1IiiIi += O0OoOOo0o
   i1II1IiiIi += struct . pack ( "H" , 0 )
  else :
   if ( self . source_eid . instance_id != 0 ) :
    i1II1IiiIi += struct . pack ( "H" , socket . htons ( LISP_AFI_LCAF ) )
    i1II1IiiIi += self . source_eid . lcaf_encode_iid ( )
   else :
    i1II1IiiIi += struct . pack ( "H" , socket . htons ( self . source_eid . afi ) )
    i1II1IiiIi += self . source_eid . pack_address ( )
    if 68 - 68: iIii1I11I1II1 - I1IiiI . oO0o + OoOoOO00
    if 94 - 94: o0oOOo0O0Ooo % o0oOOo0O0Ooo % II111iiii * iIii1I11I1II1 / IiII . I1ii11iIi11i
    if 13 - 13: OoOoOO00 . I1IiiI . o0oOOo0O0Ooo * oO0o / Ii1I
    if 38 - 38: IiII - i1IIi . i11iIiiIii
    if 28 - 28: I1Ii111 / oO0o . I1ii11iIi11i
    if 83 - 83: I11i
    if 36 - 36: iIii1I11I1II1
  if ( probe_dest ) :
   if ( probe_port == 0 ) : probe_port = LISP_DATA_PORT
   I1iiIiiii1111 = probe_dest . print_address_no_iid ( ) + ":" + str ( probe_port )
   if 74 - 74: IiII * I1ii11iIi11i - OoooooooOO
   if ( lisp_crypto_keys_by_rloc_encap . has_key ( I1iiIiiii1111 ) ) :
    self . keys = lisp_crypto_keys_by_rloc_encap [ I1iiIiiii1111 ]
    if 59 - 59: ooOoO0o * OoO0O00 - I1Ii111 % oO0o
    if 95 - 95: II111iiii + II111iiii
    if 33 - 33: i1IIi . Oo0Ooo - IiII
    if 30 - 30: OoooooooOO % OOooOOo
    if 14 - 14: OoOoOO00 / OoO0O00 / i11iIiiIii - OoOoOO00 / o0oOOo0O0Ooo - OOooOOo
    if 81 - 81: iII111i % Ii1I . ooOoO0o
    if 66 - 66: I1ii11iIi11i * Ii1I / OoooooooOO * O0 % OOooOOo
  for o00ooOOo0ooO0 in self . itr_rlocs :
   if ( lisp_data_plane_security and self . itr_rlocs . index ( o00ooOOo0ooO0 ) == 0 ) :
    if ( self . keys == None or self . keys [ 1 ] == None ) :
     o00OO0o0 = lisp_keys ( 1 )
     self . keys = [ None , o00OO0o0 , None , None ]
     if 49 - 49: II111iiii . I1IiiI * O0 * Ii1I / I1Ii111 * OoooooooOO
    o00OO0o0 = self . keys [ 1 ]
    o00OO0o0 . add_key_by_nonce ( self . nonce )
    i1II1IiiIi += o00OO0o0 . encode_lcaf ( o00ooOOo0ooO0 )
   else :
    i1II1IiiIi += struct . pack ( "H" , socket . htons ( o00ooOOo0ooO0 . afi ) )
    i1II1IiiIi += o00ooOOo0ooO0 . pack_address ( )
    if 82 - 82: Oo0Ooo / Ii1I / Ii1I % Ii1I
    if 20 - 20: ooOoO0o
    if 63 - 63: iIii1I11I1II1 . OoO0O00
  ooooOo00OO0o = 0 if self . target_eid . is_binary ( ) == False else self . target_eid . mask_len
  if 86 - 86: OoOoOO00
  if 61 - 61: IiII / II111iiii . O0 + OoooooooOO * i1IIi
  Oooo00oOO00 = 0
  if ( self . subscribe_bit ) :
   Oooo00oOO00 = 0x80
   self . xtr_id_present = True
   if ( self . xtr_id == None ) :
    self . xtr_id = random . randint ( 0 , ( 2 ** 128 ) - 1 )
    if 81 - 81: i11iIiiIii * OoooooooOO + Ii1I . IiII / O0
    if 82 - 82: II111iiii * OoOoOO00 * iIii1I11I1II1 % oO0o * OOooOOo
    if 33 - 33: Ii1I . oO0o
  oOoOo000 = "BB"
  i1II1IiiIi += struct . pack ( oOoOo000 , Oooo00oOO00 , ooooOo00OO0o )
  if 87 - 87: Oo0Ooo . o0oOOo0O0Ooo - OoooooooOO * oO0o % IiII + O0
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
   if 16 - 16: I1ii11iIi11i % Oo0Ooo % II111iiii % II111iiii
   if 51 - 51: OoOoOO00 * OoOoOO00 - O0 % iIii1I11I1II1 / O0
   if 5 - 5: i11iIiiIii * ooOoO0o % iII111i - I11i
   if 5 - 5: O0 * IiII * OOooOOo + I1Ii111 % Oo0Ooo - I1ii11iIi11i
   if 62 - 62: I1ii11iIi11i + I11i
  if ( self . subscribe_bit ) : i1II1IiiIi = self . encode_xtr_id ( i1II1IiiIi )
  return ( i1II1IiiIi )
  if 90 - 90: iIii1I11I1II1
  if 18 - 18: I11i * I1ii11iIi11i / i11iIiiIii / iIii1I11I1II1 * OoooooooOO . OOooOOo
 def lcaf_decode_json ( self , packet ) :
  oOoOo000 = "BBBBHH"
  O0OOoooO = struct . calcsize ( oOoOo000 )
  if ( len ( packet ) < O0OOoooO ) : return ( None )
  if 69 - 69: Oo0Ooo * ooOoO0o
  OOII1iI , Ooooo0OO , oOOi1I111II , o0o0OO0OO , ii111 , i1oO0o00oOo00oO = struct . unpack ( oOoOo000 , packet [ : O0OOoooO ] )
  if 21 - 21: I1IiiI - OoooooooOO / OoOoOO00 * OoooooooOO % OoooooooOO + OoO0O00
  if 89 - 89: iII111i . OOooOOo . I1ii11iIi11i
  if ( oOOi1I111II != LISP_LCAF_JSON_TYPE ) : return ( packet )
  if 93 - 93: II111iiii
  if 8 - 8: Ii1I * OoooooooOO / Ii1I / OoO0O00 % OoOoOO00 + I11i
  if 16 - 16: I11i % ooOoO0o - i11iIiiIii
  if 38 - 38: o0oOOo0O0Ooo / I1ii11iIi11i - O0
  ii111 = socket . ntohs ( ii111 )
  i1oO0o00oOo00oO = socket . ntohs ( i1oO0o00oOo00oO )
  packet = packet [ O0OOoooO : : ]
  if ( len ( packet ) < ii111 ) : return ( None )
  if ( ii111 != i1oO0o00oOo00oO + 2 ) : return ( None )
  if 21 - 21: OOooOOo
  if 77 - 77: II111iiii
  if 54 - 54: OoooooooOO % O0 % O0 * Ii1I % II111iiii + OOooOOo
  if 89 - 89: IiII - o0oOOo0O0Ooo - II111iiii * Ii1I . iIii1I11I1II1
  try :
   O0OoOOo0o = json . loads ( packet [ 0 : i1oO0o00oOo00oO ] )
  except :
   return ( None )
   if 33 - 33: I1IiiI . iIii1I11I1II1 / i11iIiiIii * Ii1I
  packet = packet [ i1oO0o00oOo00oO : : ]
  if 18 - 18: OoOoOO00 * OoOoOO00 - o0oOOo0O0Ooo % ooOoO0o % II111iiii - IiII
  if 75 - 75: OoO0O00 . II111iiii . oO0o / OoO0O00 % iIii1I11I1II1
  if 8 - 8: O0 / II111iiii
  if 62 - 62: iIii1I11I1II1 % I1Ii111 % I1ii11iIi11i * IiII
  oOoOo000 = "H"
  O0OOoooO = struct . calcsize ( oOoOo000 )
  iioOO = struct . unpack ( oOoOo000 , packet [ : O0OOoooO ] ) [ 0 ]
  packet = packet [ O0OOoooO : : ]
  if ( iioOO != 0 ) : return ( packet )
  if 87 - 87: IiII
  if 45 - 45: oO0o + II111iiii * O0 % OOooOOo . iIii1I11I1II1
  if 55 - 55: IiII
  if 43 - 43: OOooOOo
  if ( O0OoOOo0o . has_key ( "source-eid" ) == False ) : return ( packet )
  i1OO0o = O0OoOOo0o [ "source-eid" ]
  iioOO = LISP_AFI_IPV4 if i1OO0o . count ( "." ) == 3 else LISP_AFI_IPV6 if i1OO0o . count ( ":" ) == 7 else None
  if 64 - 64: i1IIi / o0oOOo0O0Ooo
  if ( iioOO == None ) :
   lprint ( "Bad JSON 'source-eid' value: {}" . format ( i1OO0o ) )
   return ( None )
   if 24 - 24: I1ii11iIi11i * OoO0O00 . OoooooooOO % Ii1I % O0
   if 46 - 46: iII111i + I1Ii111 % OoooooooOO * I1ii11iIi11i
  self . source_eid . afi = iioOO
  self . source_eid . store_address ( i1OO0o )
  if 89 - 89: IiII - IiII % iII111i / I11i + oO0o - IiII
  if ( O0OoOOo0o . has_key ( "signature-eid" ) == False ) : return ( packet )
  i1OO0o = O0OoOOo0o [ "signature-eid" ]
  if ( i1OO0o . count ( ":" ) != 7 ) :
   lprint ( "Bad JSON 'signature-eid' value: {}" . format ( i1OO0o ) )
   return ( None )
   if 97 - 97: Ii1I % OoOoOO00 / I1ii11iIi11i / iIii1I11I1II1 * OoooooooOO * OOooOOo
   if 80 - 80: oO0o / O0
  self . signature_eid . afi = LISP_AFI_IPV6
  self . signature_eid . store_address ( i1OO0o )
  if 55 - 55: I1IiiI * I11i / O0 % OoOoOO00
  if ( O0OoOOo0o . has_key ( "signature" ) == False ) : return ( packet )
  IiiiI1I1i = binascii . a2b_base64 ( O0OoOOo0o [ "signature" ] )
  self . map_request_signature = IiiiI1I1i
  return ( packet )
  if 71 - 71: i11iIiiIii * OoOoOO00 * OOooOOo + oO0o + Oo0Ooo
  if 59 - 59: IiII
 def decode ( self , packet , source , port ) :
  oOoOo000 = "I"
  O0OOoooO = struct . calcsize ( oOoOo000 )
  if ( len ( packet ) < O0OOoooO ) : return ( None )
  if 54 - 54: OOooOOo
  oOoOo00oo = struct . unpack ( oOoOo000 , packet [ : O0OOoooO ] )
  oOoOo00oo = oOoOo00oo [ 0 ]
  packet = packet [ O0OOoooO : : ]
  if 27 - 27: OoOoOO00 - OoO0O00 + o0oOOo0O0Ooo + ooOoO0o . OoO0O00
  oOoOo000 = "Q"
  O0OOoooO = struct . calcsize ( oOoOo000 )
  if ( len ( packet ) < O0OOoooO ) : return ( None )
  if 86 - 86: II111iiii - OoooooooOO - ooOoO0o % iII111i
  oOo0 = struct . unpack ( oOoOo000 , packet [ : O0OOoooO ] )
  packet = packet [ O0OOoooO : : ]
  if 16 - 16: ooOoO0o + Oo0Ooo + OoooooooOO
  oOoOo00oo = socket . ntohl ( oOoOo00oo )
  self . auth_bit = True if ( oOoOo00oo & 0x08000000 ) else False
  self . map_data_present = True if ( oOoOo00oo & 0x04000000 ) else False
  self . rloc_probe = True if ( oOoOo00oo & 0x02000000 ) else False
  self . smr_bit = True if ( oOoOo00oo & 0x01000000 ) else False
  self . pitr_bit = True if ( oOoOo00oo & 0x00800000 ) else False
  self . smr_invoked_bit = True if ( oOoOo00oo & 0x00400000 ) else False
  self . mobile_node = True if ( oOoOo00oo & 0x00200000 ) else False
  self . xtr_id_present = True if ( oOoOo00oo & 0x00100000 ) else False
  self . local_xtr = True if ( oOoOo00oo & 0x00004000 ) else False
  self . dont_reply_bit = True if ( oOoOo00oo & 0x00002000 ) else False
  self . itr_rloc_count = ( ( oOoOo00oo >> 8 ) & 0x1f ) + 1
  self . record_count = oOoOo00oo & 0xff
  self . nonce = oOo0 [ 0 ]
  if 87 - 87: I1IiiI . oO0o / IiII - OoooooooOO
  if 33 - 33: oO0o % OoO0O00 . iIii1I11I1II1 / IiII
  if 3 - 3: Ii1I + OoO0O00
  if 60 - 60: OoO0O00 . OoOoOO00 - I1ii11iIi11i - I1IiiI - II111iiii % Oo0Ooo
  if ( self . xtr_id_present ) :
   if ( self . decode_xtr_id ( packet ) == False ) : return ( None )
   if 62 - 62: O0 + iII111i - iII111i % iIii1I11I1II1
   if 47 - 47: I1Ii111 + I1IiiI
  O0OOoooO = struct . calcsize ( "H" )
  if ( len ( packet ) < O0OOoooO ) : return ( None )
  if 40 - 40: iIii1I11I1II1 % Ii1I + II111iiii - I1IiiI
  iioOO = struct . unpack ( "H" , packet [ : O0OOoooO ] )
  self . source_eid . afi = socket . ntohs ( iioOO [ 0 ] )
  packet = packet [ O0OOoooO : : ]
  if 80 - 80: oO0o
  if ( self . source_eid . afi == LISP_AFI_LCAF ) :
   Oo00o = packet
   packet = self . source_eid . lcaf_decode_iid ( packet )
   if ( packet == None ) :
    packet = self . lcaf_decode_json ( Oo00o )
    if ( packet == None ) : return ( None )
    if 14 - 14: II111iiii + O0 - iII111i
  elif ( self . source_eid . afi != LISP_AFI_NONE ) :
   packet = self . source_eid . unpack_address ( packet )
   if ( packet == None ) : return ( None )
   if 18 - 18: o0oOOo0O0Ooo / i11iIiiIii % I1ii11iIi11i * OoooooooOO
  self . source_eid . mask_len = self . source_eid . host_mask_len ( )
  if 67 - 67: OoOoOO00
  OOO0 = ( os . getenv ( "LISP_NO_CRYPTO" ) != None )
  self . itr_rlocs = [ ]
  while ( self . itr_rloc_count != 0 ) :
   O0OOoooO = struct . calcsize ( "H" )
   if ( len ( packet ) < O0OOoooO ) : return ( None )
   if 75 - 75: I1IiiI
   iioOO = struct . unpack ( "H" , packet [ : O0OOoooO ] ) [ 0 ]
   if 99 - 99: ooOoO0o . Ii1I
   o00ooOOo0ooO0 = lisp_address ( LISP_AFI_NONE , "" , 32 , 0 )
   o00ooOOo0ooO0 . afi = socket . ntohs ( iioOO )
   if 92 - 92: i1IIi
   if 68 - 68: OoO0O00 % IiII - oO0o - ooOoO0o . Oo0Ooo
   if 30 - 30: OoooooooOO % o0oOOo0O0Ooo + ooOoO0o * OoO0O00
   if 57 - 57: I11i + iIii1I11I1II1 . OoO0O00 + oO0o
   if 4 - 4: Ii1I
   if ( o00ooOOo0ooO0 . afi != LISP_AFI_LCAF ) :
    if ( len ( packet ) < o00ooOOo0ooO0 . addr_length ( ) ) : return ( None )
    packet = o00ooOOo0ooO0 . unpack_address ( packet [ O0OOoooO : : ] )
    if ( packet == None ) : return ( None )
    if 43 - 43: i1IIi . I1IiiI * iIii1I11I1II1 * i11iIiiIii - OOooOOo + ooOoO0o
    if ( OOO0 ) :
     self . itr_rlocs . append ( o00ooOOo0ooO0 )
     self . itr_rloc_count -= 1
     continue
     if 56 - 56: Oo0Ooo % i11iIiiIii / Ii1I . I1Ii111 . OoO0O00 - OoOoOO00
     if 32 - 32: I1Ii111 / oO0o / I1IiiI
    I1iiIiiii1111 = lisp_build_crypto_decap_lookup_key ( o00ooOOo0ooO0 , port )
    if 22 - 22: OoO0O00 - OoOoOO00 . Oo0Ooo + o0oOOo0O0Ooo
    if 69 - 69: oO0o - I1IiiI
    if 10 - 10: i1IIi / iII111i . II111iiii * i1IIi % OoooooooOO
    if 83 - 83: I11i . OOooOOo + I1Ii111 * I11i . I1Ii111 + oO0o
    if 64 - 64: Ii1I . o0oOOo0O0Ooo - i1IIi
    if ( lisp_nat_traversal and o00ooOOo0ooO0 . is_private_address ( ) and source ) : o00ooOOo0ooO0 = source
    if 35 - 35: I1ii11iIi11i % OoooooooOO
    oO0oO0oOoo = lisp_crypto_keys_by_rloc_decap
    if ( oO0oO0oOoo . has_key ( I1iiIiiii1111 ) ) : oO0oO0oOoo . pop ( I1iiIiiii1111 )
    if 34 - 34: IiII
    if 5 - 5: OoO0O00 . I1IiiI
    if 48 - 48: Oo0Ooo - OoO0O00 . I11i - iIii1I11I1II1 % Ii1I
    if 47 - 47: iII111i / OoooooooOO - II111iiii
    if 91 - 91: OoOoOO00 + o0oOOo0O0Ooo
    if 23 - 23: i1IIi
    lisp_write_ipc_decap_key ( I1iiIiiii1111 , None )
   else :
    IIiIiIii11I1 = packet
    IiI11IiIIi = lisp_keys ( 1 )
    packet = IiI11IiIIi . decode_lcaf ( IIiIiIii11I1 , 0 )
    if ( packet == None ) : return ( None )
    if 92 - 92: Ii1I
    if 48 - 48: iII111i . I1IiiI + O0
    if 19 - 19: I1IiiI / I1Ii111 - I11i
    if 49 - 49: iIii1I11I1II1 - iIii1I11I1II1 - OoOoOO00 + IiII / OoOoOO00
    I1IIiIIiiI1i = [ LISP_CS_25519_CBC , LISP_CS_25519_GCM ,
 LISP_CS_25519_CHACHA ]
    if ( IiI11IiIIi . cipher_suite in I1IIiIIiiI1i ) :
     if ( IiI11IiIIi . cipher_suite == LISP_CS_25519_CBC or
 IiI11IiIIi . cipher_suite == LISP_CS_25519_GCM ) :
      iii11 = lisp_keys ( 1 , do_poly = False , do_chacha = False )
      if 74 - 74: OoooooooOO + I1ii11iIi11i % O0
     if ( IiI11IiIIi . cipher_suite == LISP_CS_25519_CHACHA ) :
      iii11 = lisp_keys ( 1 , do_poly = True , do_chacha = True )
      if 32 - 32: I1ii11iIi11i + I1ii11iIi11i
    else :
     iii11 = lisp_keys ( 1 , do_poly = False , do_curve = False ,
 do_chacha = False )
     if 89 - 89: ooOoO0o + oO0o + Ii1I - OOooOOo
    packet = iii11 . decode_lcaf ( IIiIiIii11I1 , 0 )
    if ( packet == None ) : return ( None )
    if 12 - 12: OoOoOO00 - o0oOOo0O0Ooo - I1Ii111 / I11i
    if ( len ( packet ) < O0OOoooO ) : return ( None )
    iioOO = struct . unpack ( "H" , packet [ : O0OOoooO ] ) [ 0 ]
    o00ooOOo0ooO0 . afi = socket . ntohs ( iioOO )
    if ( len ( packet ) < o00ooOOo0ooO0 . addr_length ( ) ) : return ( None )
    if 17 - 17: OoO0O00 - I1Ii111 - II111iiii / I1Ii111 / Ii1I
    packet = o00ooOOo0ooO0 . unpack_address ( packet [ O0OOoooO : : ] )
    if ( packet == None ) : return ( None )
    if 30 - 30: OOooOOo * I1ii11iIi11i % I1ii11iIi11i + iII111i * IiII
    if ( OOO0 ) :
     self . itr_rlocs . append ( o00ooOOo0ooO0 )
     self . itr_rloc_count -= 1
     continue
     if 33 - 33: o0oOOo0O0Ooo + I11i * O0 * OoO0O00 . I1ii11iIi11i
     if 74 - 74: iII111i * iII111i * o0oOOo0O0Ooo / oO0o
    I1iiIiiii1111 = lisp_build_crypto_decap_lookup_key ( o00ooOOo0ooO0 , port )
    if 91 - 91: i11iIiiIii . I1ii11iIi11i / II111iiii
    O00oO0OOOo0 = None
    if ( lisp_nat_traversal and o00ooOOo0ooO0 . is_private_address ( ) and source ) : o00ooOOo0ooO0 = source
    if 64 - 64: Ii1I - iII111i
    if 12 - 12: i1IIi
    if ( lisp_crypto_keys_by_rloc_decap . has_key ( I1iiIiiii1111 ) ) :
     o00OO0o0 = lisp_crypto_keys_by_rloc_decap [ I1iiIiiii1111 ]
     O00oO0OOOo0 = o00OO0o0 [ 1 ] if o00OO0o0 and o00OO0o0 [ 1 ] else None
     if 99 - 99: II111iiii - I1ii11iIi11i * IiII
     if 3 - 3: IiII - I1ii11iIi11i * iII111i * I1ii11iIi11i + Oo0Ooo
    IIi1i1iI11I11 = True
    if ( O00oO0OOOo0 ) :
     if ( O00oO0OOOo0 . compare_keys ( iii11 ) ) :
      self . keys = [ None , O00oO0OOOo0 , None , None ]
      lprint ( "Maintain stored decap-keys for RLOC {}" . format ( red ( I1iiIiiii1111 , False ) ) )
      if 67 - 67: i11iIiiIii % I11i
     else :
      IIi1i1iI11I11 = False
      ii1I11iIi = bold ( "Remote decap-rekeying" , False )
      lprint ( "{} for RLOC {}" . format ( ii1I11iIi , red ( I1iiIiiii1111 ,
 False ) ) )
      iii11 . copy_keypair ( O00oO0OOOo0 )
      iii11 . uptime = O00oO0OOOo0 . uptime
      O00oO0OOOo0 = None
      if 13 - 13: O0 . iII111i - IiII % i11iIiiIii % I1IiiI
      if 88 - 88: i1IIi % O0
      if 35 - 35: OoOoOO00 % OoO0O00 + O0 * o0oOOo0O0Ooo % I1ii11iIi11i
    if ( O00oO0OOOo0 == None ) :
     self . keys = [ None , iii11 , None , None ]
     if ( lisp_i_am_etr == False and lisp_i_am_rtr == False ) :
      iii11 . local_public_key = None
      lprint ( "{} for {}" . format ( bold ( "Ignoring decap-keys" ,
 False ) , red ( I1iiIiiii1111 , False ) ) )
     elif ( iii11 . remote_public_key != None ) :
      if ( IIi1i1iI11I11 ) :
       lprint ( "{} for RLOC {}" . format ( bold ( "New decap-keying" , False ) ,
       # i1IIi / I11i - o0oOOo0O0Ooo - ooOoO0o
 red ( I1iiIiiii1111 , False ) ) )
       if 98 - 98: Oo0Ooo + OoOoOO00 * OOooOOo / iII111i * OoOoOO00 / OoooooooOO
      iii11 . compute_shared_key ( "decap" )
      iii11 . add_key_by_rloc ( I1iiIiiii1111 , False )
      if 35 - 35: II111iiii . OOooOOo + iIii1I11I1II1 . i1IIi - OoOoOO00 + IiII
      if 55 - 55: Oo0Ooo % I1Ii111 . II111iiii
      if 53 - 53: O0 / OoO0O00 % i11iIiiIii
      if 11 - 11: I1Ii111 + i1IIi - iII111i - OoO0O00 * ooOoO0o / ooOoO0o
   self . itr_rlocs . append ( o00ooOOo0ooO0 )
   self . itr_rloc_count -= 1
   if 4 - 4: iIii1I11I1II1 - i11iIiiIii * OoO0O00 . I1Ii111 + o0oOOo0O0Ooo
   if 11 - 11: OoOoOO00 % I1ii11iIi11i - Ii1I - I1Ii111
  O0OOoooO = struct . calcsize ( "BBH" )
  if ( len ( packet ) < O0OOoooO ) : return ( None )
  if 58 - 58: OoOoOO00 . Ii1I / IiII * oO0o
  Oooo00oOO00 , ooooOo00OO0o , iioOO = struct . unpack ( "BBH" , packet [ : O0OOoooO ] )
  self . subscribe_bit = ( Oooo00oOO00 & 0x80 )
  self . target_eid . afi = socket . ntohs ( iioOO )
  packet = packet [ O0OOoooO : : ]
  if 70 - 70: OoooooooOO
  self . target_eid . mask_len = ooooOo00OO0o
  if ( self . target_eid . afi == LISP_AFI_LCAF ) :
   packet , OOOoo = self . target_eid . lcaf_decode_eid ( packet )
   if ( packet == None ) : return ( None )
   if ( OOOoo ) : self . target_group = OOOoo
  else :
   packet = self . target_eid . unpack_address ( packet )
   if ( packet == None ) : return ( None )
   packet = packet [ O0OOoooO : : ]
   if 97 - 97: I11i
  return ( packet )
  if 84 - 84: IiII - OoOoOO00 . IiII + ooOoO0o . iII111i
  if 96 - 96: Ii1I % iII111i * Ii1I % I1IiiI . o0oOOo0O0Ooo / o0oOOo0O0Ooo
 def print_eid_tuple ( self ) :
  return ( lisp_print_eid_tuple ( self . target_eid , self . target_group ) )
  if 7 - 7: OoO0O00 - ooOoO0o % i1IIi
  if 24 - 24: OoO0O00 % O0 % I11i
 def encode_xtr_id ( self , packet ) :
  o0O0o0O0O = self . xtr_id >> 64
  ii11iIi1IiI = self . xtr_id & 0xffffffffffffffff
  o0O0o0O0O = byte_swap_64 ( o0O0o0O0O )
  ii11iIi1IiI = byte_swap_64 ( ii11iIi1IiI )
  packet += struct . pack ( "QQ" , o0O0o0O0O , ii11iIi1IiI )
  return ( packet )
  if 61 - 61: ooOoO0o . iII111i / ooOoO0o * OoooooooOO
  if 13 - 13: II111iiii
 def decode_xtr_id ( self , packet ) :
  O0OOoooO = struct . calcsize ( "QQ" )
  if ( len ( packet ) < O0OOoooO ) : return ( None )
  packet = packet [ len ( packet ) - O0OOoooO : : ]
  o0O0o0O0O , ii11iIi1IiI = struct . unpack ( "QQ" , packet [ : O0OOoooO ] )
  o0O0o0O0O = byte_swap_64 ( o0O0o0O0O )
  ii11iIi1IiI = byte_swap_64 ( ii11iIi1IiI )
  self . xtr_id = ( o0O0o0O0O << 64 ) | ii11iIi1IiI
  return ( True )
  if 17 - 17: II111iiii
  if 66 - 66: IiII * oO0o
  if 73 - 73: i11iIiiIii + O0 % O0
  if 70 - 70: II111iiii * OoooooooOO - Ii1I + oO0o * O0
  if 49 - 49: oO0o . Ii1I . OoOoOO00 - I1ii11iIi11i
  if 74 - 74: ooOoO0o % I1ii11iIi11i * i1IIi
  if 18 - 18: OoOoOO00
  if 30 - 30: II111iiii
  if 27 - 27: i1IIi - iIii1I11I1II1 + O0 % Oo0Ooo / OOooOOo + i1IIi
  if 48 - 48: Oo0Ooo
  if 70 - 70: OoooooooOO * i11iIiiIii
  if 60 - 60: IiII / iIii1I11I1II1 + OoooooooOO - I1ii11iIi11i * i11iIiiIii
  if 47 - 47: O0 . I1IiiI / ooOoO0o % i11iIiiIii
  if 47 - 47: Ii1I . OoOoOO00 . iIii1I11I1II1 . o0oOOo0O0Ooo
  if 39 - 39: o0oOOo0O0Ooo
  if 89 - 89: OoooooooOO + iII111i . I1Ii111 / Ii1I
  if 75 - 75: iIii1I11I1II1 * iII111i / OoOoOO00 * II111iiii . i1IIi
  if 6 - 6: Ii1I % Ii1I / OoooooooOO * oO0o . I1IiiI . i1IIi
  if 59 - 59: I11i . I11i * I1IiiI - Ii1I % OoOoOO00
  if 19 - 19: OoooooooOO / Oo0Ooo - I1Ii111 . OoOoOO00
  if 8 - 8: I11i % ooOoO0o . iIii1I11I1II1
  if 95 - 95: o0oOOo0O0Ooo + i11iIiiIii . I1ii11iIi11i . ooOoO0o . o0oOOo0O0Ooo
  if 93 - 93: iII111i
  if 55 - 55: II111iiii % o0oOOo0O0Ooo - OoO0O00
  if 48 - 48: ooOoO0o * iIii1I11I1II1 % OoOoOO00
  if 100 - 100: II111iiii - i11iIiiIii + OoO0O00 % ooOoO0o - iIii1I11I1II1 * i11iIiiIii
  if 30 - 30: OoO0O00 . OoO0O00 . Ii1I % Ii1I * i1IIi * oO0o
  if 74 - 74: OoooooooOO
  if 33 - 33: o0oOOo0O0Ooo - II111iiii
  if 95 - 95: OoooooooOO
  if 23 - 23: II111iiii + I11i / O0 . I11i . I1Ii111 + iIii1I11I1II1
  if 2 - 2: i1IIi . O0 / o0oOOo0O0Ooo . II111iiii / OoO0O00 % i1IIi
class lisp_map_reply ( ) :
 def __init__ ( self ) :
  self . rloc_probe = False
  self . echo_nonce_capable = False
  self . security = False
  self . record_count = 0
  self . hop_count = 0
  self . nonce = 0
  self . keys = None
  if 12 - 12: o0oOOo0O0Ooo
  if 58 - 58: iIii1I11I1II1 * Ii1I . ooOoO0o . Oo0Ooo * Ii1I
 def print_map_reply ( self ) :
  oooOo = "{} -> flags: {}{}{}, hop-count: {}, record-count: {}, " + "nonce: 0x{}"
  if 63 - 63: OoOoOO00 . I11i * o0oOOo0O0Ooo - I11i % I11i
  lprint ( oooOo . format ( bold ( "Map-Reply" , False ) , "R" if self . rloc_probe else "r" ,
  # o0oOOo0O0Ooo + I1IiiI % ooOoO0o * I1Ii111
 "E" if self . echo_nonce_capable else "e" ,
 "S" if self . security else "s" , self . hop_count , self . record_count ,
 lisp_hex_string ( self . nonce ) ) )
  if 87 - 87: II111iiii + O0 / iII111i * ooOoO0o
  if 52 - 52: iIii1I11I1II1 / iII111i . O0 * IiII . I1IiiI
 def encode ( self ) :
  oOoOo00oo = ( LISP_MAP_REPLY << 28 ) | self . record_count
  oOoOo00oo |= self . hop_count << 8
  if ( self . rloc_probe ) : oOoOo00oo |= 0x08000000
  if ( self . echo_nonce_capable ) : oOoOo00oo |= 0x04000000
  if ( self . security ) : oOoOo00oo |= 0x02000000
  if 67 - 67: II111iiii + Ii1I - I1IiiI * ooOoO0o
  i1II1IiiIi = struct . pack ( "I" , socket . htonl ( oOoOo00oo ) )
  i1II1IiiIi += struct . pack ( "Q" , self . nonce )
  return ( i1II1IiiIi )
  if 19 - 19: i11iIiiIii * Oo0Ooo
  if 33 - 33: i11iIiiIii + I1IiiI
 def decode ( self , packet ) :
  oOoOo000 = "I"
  O0OOoooO = struct . calcsize ( oOoOo000 )
  if ( len ( packet ) < O0OOoooO ) : return ( None )
  if 95 - 95: I1ii11iIi11i / IiII % iIii1I11I1II1 + O0
  oOoOo00oo = struct . unpack ( oOoOo000 , packet [ : O0OOoooO ] )
  oOoOo00oo = oOoOo00oo [ 0 ]
  packet = packet [ O0OOoooO : : ]
  if 6 - 6: IiII
  oOoOo000 = "Q"
  O0OOoooO = struct . calcsize ( oOoOo000 )
  if ( len ( packet ) < O0OOoooO ) : return ( None )
  if 73 - 73: o0oOOo0O0Ooo % o0oOOo0O0Ooo . OOooOOo * I1ii11iIi11i - Ii1I
  oOo0 = struct . unpack ( oOoOo000 , packet [ : O0OOoooO ] )
  packet = packet [ O0OOoooO : : ]
  if 97 - 97: IiII
  oOoOo00oo = socket . ntohl ( oOoOo00oo )
  self . rloc_probe = True if ( oOoOo00oo & 0x08000000 ) else False
  self . echo_nonce_capable = True if ( oOoOo00oo & 0x04000000 ) else False
  self . security = True if ( oOoOo00oo & 0x02000000 ) else False
  self . hop_count = ( oOoOo00oo >> 8 ) & 0xff
  self . record_count = oOoOo00oo & 0xff
  self . nonce = oOo0 [ 0 ]
  if 15 - 15: O0 - I1IiiI / i1IIi . I1Ii111
  if ( lisp_crypto_keys_by_nonce . has_key ( self . nonce ) ) :
   self . keys = lisp_crypto_keys_by_nonce [ self . nonce ]
   self . keys [ 1 ] . delete_key_by_nonce ( self . nonce )
   if 64 - 64: ooOoO0o / i1IIi
  return ( packet )
  if 100 - 100: II111iiii
  if 16 - 16: Ii1I
  if 96 - 96: o0oOOo0O0Ooo / I1Ii111 % Ii1I - ooOoO0o
  if 35 - 35: OOooOOo
  if 90 - 90: i11iIiiIii
  if 47 - 47: OoO0O00 . i11iIiiIii
  if 9 - 9: OoOoOO00 - I11i . OoooooooOO % ooOoO0o
  if 13 - 13: OoO0O00 * iIii1I11I1II1 + II111iiii - Oo0Ooo - OoOoOO00
  if 43 - 43: iII111i / I1Ii111 * I1IiiI % ooOoO0o % I1IiiI
  if 18 - 18: OoO0O00
  if 99 - 99: iII111i / oO0o . i11iIiiIii / I11i + i1IIi - I11i
  if 50 - 50: i1IIi
  if 56 - 56: OoO0O00 + I1Ii111 / Ii1I
  if 75 - 75: OoOoOO00
  if 96 - 96: o0oOOo0O0Ooo * I11i * Oo0Ooo
  if 36 - 36: OoooooooOO + ooOoO0o . oO0o * ooOoO0o + IiII
  if 45 - 45: oO0o / iII111i + I1ii11iIi11i - Oo0Ooo - ooOoO0o . iIii1I11I1II1
  if 52 - 52: I1IiiI + i1IIi . iII111i * I1IiiI
  if 31 - 31: Oo0Ooo % iIii1I11I1II1 . O0
  if 80 - 80: I11i / Oo0Ooo + I1ii11iIi11i
  if 18 - 18: II111iiii - iII111i / iIii1I11I1II1 % OoOoOO00 % I1ii11iIi11i / o0oOOo0O0Ooo
  if 47 - 47: OOooOOo
  if 24 - 24: Ii1I % o0oOOo0O0Ooo
  if 87 - 87: o0oOOo0O0Ooo % iII111i / ooOoO0o - IiII + i11iIiiIii
  if 85 - 85: OoooooooOO * IiII . OOooOOo / iII111i / OoooooooOO
  if 87 - 87: OoO0O00
  if 32 - 32: i11iIiiIii - OoOoOO00 * I11i . Oo0Ooo * ooOoO0o
  if 21 - 21: OOooOOo
  if 11 - 11: oO0o % i11iIiiIii * O0
  if 28 - 28: I1Ii111 / iIii1I11I1II1 + OOooOOo . I1ii11iIi11i % OOooOOo + OoO0O00
  if 79 - 79: oO0o
  if 39 - 39: I1Ii111 % oO0o % O0 % O0 - iII111i - oO0o
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
  if 83 - 83: i11iIiiIii + iIii1I11I1II1
  if 21 - 21: o0oOOo0O0Ooo / i11iIiiIii % I1Ii111
 def print_prefix ( self ) :
  if ( self . group . is_null ( ) ) :
   return ( green ( self . eid . print_prefix ( ) , False ) )
   if 56 - 56: o0oOOo0O0Ooo * iIii1I11I1II1 . Ii1I + OoOoOO00 % I1Ii111
  return ( green ( self . eid . print_sg ( self . group ) , False ) )
  if 11 - 11: OOooOOo
  if 12 - 12: OoooooooOO * OOooOOo * I1ii11iIi11i * ooOoO0o
 def print_ttl ( self ) :
  iiI = self . record_ttl
  if ( self . record_ttl & 0x80000000 ) :
   iiI = str ( self . record_ttl & 0x7fffffff ) + " secs"
  elif ( ( iiI % 60 ) == 0 ) :
   iiI = str ( iiI / 60 ) + " hours"
  else :
   iiI = str ( iiI ) + " mins"
   if 23 - 23: IiII + i11iIiiIii * Ii1I
  return ( iiI )
  if 55 - 55: Oo0Ooo % IiII + i11iIiiIii - OOooOOo - II111iiii
  if 80 - 80: IiII
 def store_ttl ( self ) :
  iiI = self . record_ttl * 60
  if ( self . record_ttl & 0x80000000 ) : iiI = self . record_ttl & 0x7fffffff
  return ( iiI )
  if 97 - 97: iII111i
  if 40 - 40: ooOoO0o
 def print_record ( self , indent , ddt ) :
  O0oOo00O = ""
  I11I = ""
  Oo0OOo0oO00O00 = bold ( "invalid-action" , False )
  if ( ddt ) :
   if ( self . action < len ( lisp_map_referral_action_string ) ) :
    Oo0OOo0oO00O00 = lisp_map_referral_action_string [ self . action ]
    Oo0OOo0oO00O00 = bold ( Oo0OOo0oO00O00 , False )
    O0oOo00O = ( ", " + bold ( "ddt-incomplete" , False ) ) if self . ddt_incomplete else ""
    if 16 - 16: OOooOOo % IiII - II111iiii - o0oOOo0O0Ooo * i11iIiiIii / I1Ii111
    I11I = ( ", sig-count: " + str ( self . signature_count ) ) if ( self . signature_count != 0 ) else ""
    if 74 - 74: iII111i % i1IIi / Oo0Ooo . O0
    if 48 - 48: I1ii11iIi11i % II111iiii + I11i
  else :
   if ( self . action < len ( lisp_map_reply_action_string ) ) :
    Oo0OOo0oO00O00 = lisp_map_reply_action_string [ self . action ]
    if ( self . action != LISP_NO_ACTION ) :
     Oo0OOo0oO00O00 = bold ( Oo0OOo0oO00O00 , False )
     if 25 - 25: IiII * o0oOOo0O0Ooo / I1IiiI . IiII % II111iiii
     if 50 - 50: OoOoOO00 * iII111i
     if 59 - 59: I1IiiI * I1IiiI / I11i
     if 92 - 92: o0oOOo0O0Ooo
  iioOO = LISP_AFI_LCAF if ( self . eid . afi < 0 ) else self . eid . afi
  oooOo = ( "{}EID-record -> record-ttl: {}, rloc-count: {}, action: " +
 "{}, {}{}{}, map-version: {}, afi: {}, [iid]eid/ml: {}" )
  if 8 - 8: iII111i + I1ii11iIi11i . Ii1I
  lprint ( oooOo . format ( indent , self . print_ttl ( ) , self . rloc_count ,
 Oo0OOo0oO00O00 , "auth" if ( self . authoritative is True ) else "non-auth" ,
 O0oOo00O , I11I , self . map_version , iioOO ,
 green ( self . print_prefix ( ) , False ) ) )
  if 50 - 50: Oo0Ooo
  if 16 - 16: Ii1I - OoOoOO00 % Oo0Ooo / Ii1I . I11i + ooOoO0o
 def encode ( self ) :
  ooOOoo0 = self . action << 13
  if ( self . authoritative ) : ooOOoo0 |= 0x1000
  if ( self . ddt_incomplete ) : ooOOoo0 |= 0x800
  if 47 - 47: Ii1I % ooOoO0o + Ii1I
  if 49 - 49: OoOoOO00 / i1IIi / OoooooooOO . iII111i + iII111i
  if 51 - 51: OoooooooOO + i11iIiiIii
  if 57 - 57: Oo0Ooo % o0oOOo0O0Ooo
  iioOO = self . eid . afi if ( self . eid . instance_id == 0 ) else LISP_AFI_LCAF
  if ( iioOO < 0 ) : iioOO = LISP_AFI_LCAF
  OOoo = ( self . group . is_null ( ) == False )
  if ( OOoo ) : iioOO = LISP_AFI_LCAF
  if 42 - 42: OOooOOo . Oo0Ooo
  i1i1IIiIiI11 = ( self . signature_count << 12 ) | self . map_version
  ooooOo00OO0o = 0 if self . eid . is_binary ( ) == False else self . eid . mask_len
  if 61 - 61: i11iIiiIii % I1Ii111 / o0oOOo0O0Ooo
  i1II1IiiIi = struct . pack ( "IBBHHH" , socket . htonl ( self . record_ttl ) ,
 self . rloc_count , ooooOo00OO0o , socket . htons ( ooOOoo0 ) ,
 socket . htons ( i1i1IIiIiI11 ) , socket . htons ( iioOO ) )
  if 40 - 40: OOooOOo / Ii1I % I1IiiI / o0oOOo0O0Ooo . iII111i
  if 78 - 78: I11i - I1IiiI * IiII
  if 43 - 43: OoooooooOO . OOooOOo
  if 33 - 33: o0oOOo0O0Ooo % OoOoOO00 * I1IiiI
  if ( OOoo ) :
   i1II1IiiIi += self . eid . lcaf_encode_sg ( self . group )
   return ( i1II1IiiIi )
   if 26 - 26: I11i . iII111i . o0oOOo0O0Ooo
   if 15 - 15: OoO0O00 / iII111i
   if 46 - 46: OoooooooOO . I1Ii111
   if 15 - 15: Ii1I
   if 84 - 84: OoOoOO00 - ooOoO0o - OoooooooOO . OoooooooOO % IiII
  if ( self . eid . afi == LISP_AFI_GEO_COORD and self . eid . instance_id == 0 ) :
   i1II1IiiIi = i1II1IiiIi [ 0 : - 2 ]
   i1II1IiiIi += self . eid . address . encode_geo ( )
   return ( i1II1IiiIi )
   if 38 - 38: OoO0O00 * I1ii11iIi11i
   if 4 - 4: OoO0O00 . I1ii11iIi11i
   if 21 - 21: i11iIiiIii / OoO0O00 / I1ii11iIi11i * O0 - II111iiii * OOooOOo
   if 27 - 27: o0oOOo0O0Ooo . OoOoOO00 * Ii1I * iII111i * O0
   if 93 - 93: IiII % I1Ii111 % II111iiii
  if ( iioOO == LISP_AFI_LCAF ) :
   i1II1IiiIi += self . eid . lcaf_encode_iid ( )
   return ( i1II1IiiIi )
   if 20 - 20: OoooooooOO * I1Ii111
   if 38 - 38: iII111i . OoooooooOO
   if 28 - 28: I1Ii111 * i1IIi . I1ii11iIi11i
   if 75 - 75: O0 / oO0o * ooOoO0o - OOooOOo / i1IIi
   if 61 - 61: I11i
  i1II1IiiIi += self . eid . pack_address ( )
  return ( i1II1IiiIi )
  if 100 - 100: O0 - iIii1I11I1II1 * Oo0Ooo
  if 35 - 35: ooOoO0o
 def decode ( self , packet ) :
  oOoOo000 = "IBBHHH"
  O0OOoooO = struct . calcsize ( oOoOo000 )
  if ( len ( packet ) < O0OOoooO ) : return ( None )
  if 57 - 57: OoO0O00 . Oo0Ooo + I1IiiI
  self . record_ttl , self . rloc_count , self . eid . mask_len , ooOOoo0 , self . map_version , self . eid . afi = struct . unpack ( oOoOo000 , packet [ : O0OOoooO ] )
  if 18 - 18: I1IiiI - I1ii11iIi11i * I11i / i11iIiiIii - o0oOOo0O0Ooo % o0oOOo0O0Ooo
  if 31 - 31: I11i
  if 100 - 100: i11iIiiIii * i11iIiiIii . iIii1I11I1II1 % iII111i * I1ii11iIi11i
  self . record_ttl = socket . ntohl ( self . record_ttl )
  ooOOoo0 = socket . ntohs ( ooOOoo0 )
  self . action = ( ooOOoo0 >> 13 ) & 0x7
  self . authoritative = True if ( ( ooOOoo0 >> 12 ) & 1 ) else False
  self . ddt_incomplete = True if ( ( ooOOoo0 >> 11 ) & 1 ) else False
  self . map_version = socket . ntohs ( self . map_version )
  self . signature_count = self . map_version >> 12
  self . map_version = self . map_version & 0xfff
  self . eid . afi = socket . ntohs ( self . eid . afi )
  self . eid . instance_id = 0
  packet = packet [ O0OOoooO : : ]
  if 17 - 17: Ii1I * IiII * i11iIiiIii / I1ii11iIi11i / i11iIiiIii
  if 23 - 23: OoooooooOO + i11iIiiIii / Oo0Ooo / iII111i . iII111i * I1IiiI
  if 98 - 98: IiII
  if 23 - 23: I11i / i1IIi * OoO0O00
  if ( self . eid . afi == LISP_AFI_LCAF ) :
   packet , O0oo0oo0 = self . eid . lcaf_decode_eid ( packet )
   if ( O0oo0oo0 ) : self . group = O0oo0oo0
   self . group . instance_id = self . eid . instance_id
   return ( packet )
   if 40 - 40: OoO0O00
   if 1 - 1: I11i + oO0o - iII111i . Ii1I
  packet = self . eid . unpack_address ( packet )
  return ( packet )
  if 76 - 76: IiII
  if 6 - 6: Oo0Ooo % oO0o * ooOoO0o - i1IIi . OoOoOO00
 def print_eid_tuple ( self ) :
  return ( lisp_print_eid_tuple ( self . eid , self . group ) )
  if 20 - 20: Oo0Ooo / I1Ii111 . Oo0Ooo
  if 60 - 60: I1ii11iIi11i - I1IiiI * O0 * Oo0Ooo . i1IIi . OoOoOO00
  if 24 - 24: IiII * I1IiiI / OOooOOo
  if 51 - 51: iIii1I11I1II1 / I11i * OoO0O00 * Ii1I + I1ii11iIi11i . OoooooooOO
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
LISP_UDP_PROTOCOL = 17
LISP_DEFAULT_ECM_TTL = 128
if 35 - 35: ooOoO0o + OoOoOO00 * OoooooooOO - II111iiii
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
  if 19 - 19: i1IIi / Ii1I / OoOoOO00 . I1IiiI / Ii1I % o0oOOo0O0Ooo
  if 39 - 39: ooOoO0o - OoooooooOO
 def print_ecm ( self ) :
  oooOo = ( "{} -> flags: {}{}{}{}, " + "inner IP: {} -> {}, inner UDP: {} -> {}" )
  if 88 - 88: i1IIi + iIii1I11I1II1 * i11iIiiIii - OoooooooOO % o0oOOo0O0Ooo
  lprint ( oooOo . format ( bold ( "ECM" , False ) , "S" if self . security else "s" ,
 "D" if self . ddt else "d" , "E" if self . to_etr else "e" ,
 "M" if self . to_ms else "m" ,
 green ( self . source . print_address ( ) , False ) ,
 green ( self . dest . print_address ( ) , False ) , self . udp_sport ,
 self . udp_dport ) )
  if 74 - 74: ooOoO0o - i11iIiiIii
 def encode ( self , packet , inner_source , inner_dest ) :
  self . udp_length = len ( packet ) + 8
  self . source = inner_source
  self . dest = inner_dest
  if ( inner_dest . is_ipv4 ( ) ) :
   self . afi = LISP_AFI_IPV4
   self . length = self . udp_length + 20
   if 34 - 34: IiII + I1Ii111 + Oo0Ooo / II111iiii
  if ( inner_dest . is_ipv6 ( ) ) :
   self . afi = LISP_AFI_IPV6
   self . length = self . udp_length
   if 33 - 33: Ii1I . i1IIi - II111iiii - OoO0O00
   if 31 - 31: I11i - OoOoOO00 / o0oOOo0O0Ooo * OoOoOO00 / Oo0Ooo + o0oOOo0O0Ooo
   if 46 - 46: IiII * OoO0O00 / OOooOOo + Oo0Ooo
   if 24 - 24: ooOoO0o % OOooOOo . O0 * Oo0Ooo
   if 52 - 52: O0 . I1Ii111 + iII111i / i11iIiiIii
   if 52 - 52: oO0o % Oo0Ooo * II111iiii
  oOoOo00oo = ( LISP_ECM << 28 )
  if ( self . security ) : oOoOo00oo |= 0x08000000
  if ( self . ddt ) : oOoOo00oo |= 0x04000000
  if ( self . to_etr ) : oOoOo00oo |= 0x02000000
  if ( self . to_ms ) : oOoOo00oo |= 0x01000000
  if 24 - 24: i11iIiiIii * i1IIi * i1IIi
  iiIIIiI1 = struct . pack ( "I" , socket . htonl ( oOoOo00oo ) )
  if 89 - 89: I1Ii111
  i1I1i1i = ""
  if ( self . afi == LISP_AFI_IPV4 ) :
   i1I1i1i = struct . pack ( "BBHHHBBH" , 0x45 , 0 , socket . htons ( self . length ) ,
 0 , 0 , self . ttl , self . protocol , socket . htons ( self . ip_checksum ) )
   i1I1i1i += self . source . pack_address ( )
   i1I1i1i += self . dest . pack_address ( )
   i1I1i1i = lisp_ip_checksum ( i1I1i1i )
   if 19 - 19: IiII + I1Ii111
  if ( self . afi == LISP_AFI_IPV6 ) :
   i1I1i1i = struct . pack ( "BBHHBB" , 0x60 , 0 , 0 , socket . htons ( self . length ) ,
 self . protocol , self . ttl )
   i1I1i1i += self . source . pack_address ( )
   i1I1i1i += self . dest . pack_address ( )
   if 65 - 65: Ii1I - oO0o + i1IIi + OOooOOo % iII111i
   if 5 - 5: OoO0O00 / iII111i / OOooOOo
  IiIIi1I1I11Ii = socket . htons ( self . udp_sport )
  oOo0OOOOOO = socket . htons ( self . udp_dport )
  IIi11I1i1I1I = socket . htons ( self . udp_length )
  Oo0ooooO0o00 = socket . htons ( self . udp_checksum )
  I1iIIIiI = struct . pack ( "HHHH" , IiIIi1I1I11Ii , oOo0OOOOOO , IIi11I1i1I1I , Oo0ooooO0o00 )
  return ( iiIIIiI1 + i1I1i1i + I1iIIIiI )
  if 70 - 70: OoOoOO00 - I11i + ooOoO0o / i11iIiiIii / I1IiiI % iIii1I11I1II1
  if 83 - 83: oO0o . Ii1I - o0oOOo0O0Ooo % I11i + i11iIiiIii
 def decode ( self , packet ) :
  if 40 - 40: O0 . Ii1I
  if 58 - 58: i11iIiiIii * iII111i / Ii1I - oO0o - I1ii11iIi11i % o0oOOo0O0Ooo
  if 16 - 16: OoooooooOO
  if 71 - 71: Ii1I % O0 / I1Ii111 % iII111i - II111iiii / OoO0O00
  oOoOo000 = "I"
  O0OOoooO = struct . calcsize ( oOoOo000 )
  if ( len ( packet ) < O0OOoooO ) : return ( None )
  if 30 - 30: I11i
  oOoOo00oo = struct . unpack ( oOoOo000 , packet [ : O0OOoooO ] )
  if 60 - 60: ooOoO0o - Ii1I . I1IiiI * oO0o * i11iIiiIii
  oOoOo00oo = socket . ntohl ( oOoOo00oo [ 0 ] )
  self . security = True if ( oOoOo00oo & 0x08000000 ) else False
  self . ddt = True if ( oOoOo00oo & 0x04000000 ) else False
  self . to_etr = True if ( oOoOo00oo & 0x02000000 ) else False
  self . to_ms = True if ( oOoOo00oo & 0x01000000 ) else False
  packet = packet [ O0OOoooO : : ]
  if 29 - 29: OoO0O00 - Oo0Ooo . oO0o / OoO0O00 % i11iIiiIii
  if 26 - 26: ooOoO0o . I1Ii111 / II111iiii % Ii1I
  if 82 - 82: OOooOOo % O0 % iIii1I11I1II1 % IiII + i11iIiiIii
  if 64 - 64: i1IIi / IiII . IiII - I1Ii111 % OOooOOo . II111iiii
  if ( len ( packet ) < 1 ) : return ( None )
  O00o0O = struct . unpack ( "B" , packet [ 0 : 1 ] ) [ 0 ]
  O00o0O = O00o0O >> 4
  if 78 - 78: I1Ii111 - O0 - I1Ii111 . iIii1I11I1II1 % I1ii11iIi11i . OoooooooOO
  if ( O00o0O == 4 ) :
   O0OOoooO = struct . calcsize ( "HHIBBH" )
   if ( len ( packet ) < O0OOoooO ) : return ( None )
   if 64 - 64: IiII
   II11iiii , IIi11I1i1I1I , II11iiii , O000o0Ooo , OoOoO , Oo0ooooO0o00 = struct . unpack ( "HHIBBH" , packet [ : O0OOoooO ] )
   self . length = socket . ntohs ( IIi11I1i1I1I )
   self . ttl = O000o0Ooo
   self . protocol = OoOoO
   self . ip_checksum = socket . ntohs ( Oo0ooooO0o00 )
   self . source . afi = self . dest . afi = LISP_AFI_IPV4
   if 51 - 51: I1ii11iIi11i + OoOoOO00 - O0 / o0oOOo0O0Ooo
   if 43 - 43: I1ii11iIi11i . IiII * OoOoOO00 / Oo0Ooo
   if 2 - 2: iIii1I11I1II1
   if 2 - 2: oO0o + ooOoO0o % OOooOOo + IiII
   OoOoO = struct . pack ( "H" , 0 )
   iIIIII1Iii1 = struct . calcsize ( "HHIBB" )
   IiIIIii11 = struct . calcsize ( "H" )
   packet = packet [ : iIIIII1Iii1 ] + OoOoO + packet [ iIIIII1Iii1 + IiIIIii11 : ]
   if 46 - 46: I1Ii111 / I1ii11iIi11i
   packet = packet [ O0OOoooO : : ]
   packet = self . source . unpack_address ( packet )
   if ( packet == None ) : return ( None )
   packet = self . dest . unpack_address ( packet )
   if ( packet == None ) : return ( None )
   if 41 - 41: i1IIi % Ii1I + I1Ii111 . Oo0Ooo / iIii1I11I1II1
   if 77 - 77: Oo0Ooo . OoO0O00 % O0 - OoO0O00 - Oo0Ooo
  if ( O00o0O == 6 ) :
   O0OOoooO = struct . calcsize ( "IHBB" )
   if ( len ( packet ) < O0OOoooO ) : return ( None )
   if 95 - 95: IiII * II111iiii % o0oOOo0O0Ooo * Oo0Ooo . I11i
   II11iiii , IIi11I1i1I1I , OoOoO , O000o0Ooo = struct . unpack ( "IHBB" , packet [ : O0OOoooO ] )
   self . length = socket . ntohs ( IIi11I1i1I1I )
   self . protocol = OoOoO
   self . ttl = O000o0Ooo
   self . source . afi = self . dest . afi = LISP_AFI_IPV6
   if 46 - 46: II111iiii - OoO0O00 % ooOoO0o
   packet = packet [ O0OOoooO : : ]
   packet = self . source . unpack_address ( packet )
   if ( packet == None ) : return ( None )
   packet = self . dest . unpack_address ( packet )
   if ( packet == None ) : return ( None )
   if 97 - 97: OoO0O00 . OoOoOO00
   if 78 - 78: I1ii11iIi11i + I1ii11iIi11i . OoOoOO00 - IiII * iIii1I11I1II1 * O0
  self . source . mask_len = self . source . host_mask_len ( )
  self . dest . mask_len = self . dest . host_mask_len ( )
  if 26 - 26: OoooooooOO + oO0o + OoO0O00 . O0
  O0OOoooO = struct . calcsize ( "HHHH" )
  if ( len ( packet ) < O0OOoooO ) : return ( None )
  if 46 - 46: OoooooooOO - Oo0Ooo * I1Ii111 * OOooOOo * I1Ii111 . oO0o
  IiIIi1I1I11Ii , oOo0OOOOOO , IIi11I1i1I1I , Oo0ooooO0o00 = struct . unpack ( "HHHH" , packet [ : O0OOoooO ] )
  self . udp_sport = socket . ntohs ( IiIIi1I1I11Ii )
  self . udp_dport = socket . ntohs ( oOo0OOOOOO )
  self . udp_length = socket . ntohs ( IIi11I1i1I1I )
  self . udp_checksum = socket . ntohs ( Oo0ooooO0o00 )
  packet = packet [ O0OOoooO : : ]
  return ( packet )
  if 96 - 96: Ii1I / IiII % o0oOOo0O0Ooo + I11i
  if 46 - 46: OoO0O00 * I1IiiI
  if 25 - 25: I1Ii111 . IiII % O0 % i1IIi
  if 53 - 53: O0 % ooOoO0o
  if 41 - 41: IiII
  if 29 - 29: ooOoO0o
  if 70 - 70: oO0o . O0 % I11i % IiII - I11i * I1ii11iIi11i
  if 22 - 22: i1IIi
  if 82 - 82: oO0o . iIii1I11I1II1 - I1ii11iIi11i
  if 55 - 55: Oo0Ooo % Ii1I . iIii1I11I1II1 * I1Ii111
  if 33 - 33: O0 - I1IiiI / I1ii11iIi11i / OoO0O00 + iII111i - oO0o
  if 27 - 27: I1Ii111 + ooOoO0o - I1Ii111 % i11iIiiIii * Oo0Ooo * o0oOOo0O0Ooo
  if 88 - 88: OOooOOo
  if 25 - 25: OoO0O00 + o0oOOo0O0Ooo . ooOoO0o - Ii1I . oO0o * Ii1I
  if 85 - 85: i1IIi
  if 94 - 94: OoooooooOO . O0 / OoooooooOO
  if 67 - 67: i11iIiiIii + OoOoOO00
  if 50 - 50: ooOoO0o . i1IIi + I1ii11iIi11i . OOooOOo
  if 97 - 97: I1IiiI
  if 63 - 63: O0 - OoOoOO00 / i11iIiiIii / OoooooooOO / ooOoO0o / II111iiii
  if 45 - 45: II111iiii . OoO0O00 + OoO0O00 * iIii1I11I1II1
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
  if 67 - 67: OoOoOO00 - ooOoO0o - iIii1I11I1II1
  if 31 - 31: II111iiii + o0oOOo0O0Ooo * i11iIiiIii . o0oOOo0O0Ooo
 def print_rloc_name ( self , cour = False ) :
  if ( self . rloc_name == None ) : return ( "" )
  OO000 = self . rloc_name
  if ( cour ) : OO000 = lisp_print_cour ( OO000 )
  return ( 'rloc-name: {}' . format ( blue ( OO000 , cour ) ) )
  if 28 - 28: oO0o . ooOoO0o / I11i + Oo0Ooo
  if 55 - 55: OoooooooOO % OoOoOO00 + i1IIi * OoO0O00 * OOooOOo
 def print_record ( self , indent ) :
  ooOo = self . print_rloc_name ( )
  if ( ooOo != "" ) : ooOo = ", " + ooOo
  iII1I1I11 = ""
  if ( self . geo ) :
   IiIII = ""
   if ( self . geo . geo_name ) : IiIII = "'{}' " . format ( self . geo . geo_name )
   iII1I1I11 = ", geo: {}{}" . format ( IiIII , self . geo . print_geo ( ) )
   if 32 - 32: i11iIiiIii - OoooooooOO + I11i . i1IIi
  iI11i1Ii = ""
  if ( self . elp ) :
   IiIII = ""
   if ( self . elp . elp_name ) : IiIII = "'{}' " . format ( self . elp . elp_name )
   iI11i1Ii = ", elp: {}{}" . format ( IiIII , self . elp . print_elp ( True ) )
   if 82 - 82: iII111i + I11i * OoO0O00 - I1ii11iIi11i % iII111i
  Oo0OooO00O = ""
  if ( self . rle ) :
   IiIII = ""
   if ( self . rle . rle_name ) : IiIII = "'{}' " . format ( self . rle . rle_name )
   Oo0OooO00O = ", rle: {}{}" . format ( IiIII , self . rle . print_rle ( False ) )
   if 63 - 63: OoOoOO00
  IiIiII = ""
  if ( self . json ) :
   IiIII = ""
   if ( self . json . json_name ) :
    IiIII = "'{}' " . format ( self . json . json_name )
    if 99 - 99: OoooooooOO - i1IIi % o0oOOo0O0Ooo / o0oOOo0O0Ooo + IiII
   IiIiII = ", json: {}" . format ( self . json . print_json ( False ) )
   if 96 - 96: OoooooooOO + OOooOOo - I1Ii111 / oO0o % oO0o
   if 34 - 34: IiII
  o0OOO0Oo = ""
  if ( self . rloc . is_null ( ) == False and self . keys and self . keys [ 1 ] ) :
   o0OOO0Oo = ", " + self . keys [ 1 ] . print_keys ( )
   if 81 - 81: I1Ii111 + Ii1I + i11iIiiIii * iIii1I11I1II1
   if 46 - 46: OoOoOO00
  oooOo = ( "{}RLOC-record -> flags: {}, {}/{}/{}/{}, afi: {}, rloc: "
 + "{}{}{}{}{}{}{}" )
  lprint ( oooOo . format ( indent , self . print_flags ( ) , self . priority ,
 self . weight , self . mpriority , self . mweight , self . rloc . afi ,
 red ( self . rloc . print_address_no_iid ( ) , False ) , ooOo , iII1I1I11 ,
 iI11i1Ii , Oo0OooO00O , IiIiII , o0OOO0Oo ) )
  if 15 - 15: oO0o + II111iiii / OOooOOo % iII111i
  if 67 - 67: i11iIiiIii + i11iIiiIii % OoOoOO00 + oO0o
 def print_flags ( self ) :
  return ( "{}{}{}" . format ( "L" if self . local_bit else "l" , "P" if self . probe_bit else "p" , "R" if self . reach_bit else "r" ) )
  if 87 - 87: ooOoO0o * Oo0Ooo / iII111i + I11i + Ii1I
  if 84 - 84: iIii1I11I1II1 * oO0o / Ii1I % OoO0O00
  if 91 - 91: o0oOOo0O0Ooo - OOooOOo - I11i
 def store_rloc_entry ( self , rloc_entry ) :
  OoOOo = rloc_entry . rloc if ( rloc_entry . translated_rloc . is_null ( ) ) else rloc_entry . translated_rloc
  if 98 - 98: OoOoOO00 / O0
  self . rloc . copy_address ( OoOOo )
  if 92 - 92: OoooooooOO
  if ( rloc_entry . rloc_name ) :
   self . rloc_name = rloc_entry . rloc_name
   if 23 - 23: i11iIiiIii / ooOoO0o + oO0o . Oo0Ooo
   if 94 - 94: i11iIiiIii . IiII - OoO0O00 + O0
  if ( rloc_entry . geo ) :
   self . geo = rloc_entry . geo
  else :
   IiIII = rloc_entry . geo_name
   if ( IiIII and lisp_geo_list . has_key ( IiIII ) ) :
    self . geo = lisp_geo_list [ IiIII ]
    if 89 - 89: iII111i * oO0o
    if 36 - 36: ooOoO0o / II111iiii - ooOoO0o * iII111i
  if ( rloc_entry . elp ) :
   self . elp = rloc_entry . elp
  else :
   IiIII = rloc_entry . elp_name
   if ( IiIII and lisp_elp_list . has_key ( IiIII ) ) :
    self . elp = lisp_elp_list [ IiIII ]
    if 43 - 43: iII111i * i1IIi . I1IiiI . OoOoOO00 / IiII - Oo0Ooo
    if 95 - 95: OoooooooOO % OOooOOo * OOooOOo
  if ( rloc_entry . rle ) :
   self . rle = rloc_entry . rle
  else :
   IiIII = rloc_entry . rle_name
   if ( IiIII and lisp_rle_list . has_key ( IiIII ) ) :
    self . rle = lisp_rle_list [ IiIII ]
    if 24 - 24: Ii1I * i11iIiiIii / O0 - I1ii11iIi11i
    if 93 - 93: ooOoO0o - OoooooooOO / IiII . I11i
  if ( rloc_entry . json ) :
   self . json = rloc_entry . json
  else :
   IiIII = rloc_entry . json_name
   if ( IiIII and lisp_json_list . has_key ( IiIII ) ) :
    self . json = lisp_json_list [ IiIII ]
    if 7 - 7: o0oOOo0O0Ooo % Ii1I - i11iIiiIii
    if 47 - 47: Oo0Ooo / OoOoOO00
  self . priority = rloc_entry . priority
  self . weight = rloc_entry . weight
  self . mpriority = rloc_entry . mpriority
  self . mweight = rloc_entry . mweight
  if 26 - 26: I11i . I1ii11iIi11i
  if 55 - 55: OoOoOO00 * I1Ii111 % OoO0O00 - OoO0O00
 def encode_lcaf ( self ) :
  O0OOOOO0O = socket . htons ( LISP_AFI_LCAF )
  IiIIII11i1ii = ""
  if ( self . geo ) :
   IiIIII11i1ii = self . geo . encode_geo ( )
   if 48 - 48: I1ii11iIi11i . i1IIi % OoO0O00 + ooOoO0o . I1ii11iIi11i
   if 72 - 72: OoO0O00
  O0oo0O00OOO0o = ""
  if ( self . elp ) :
   oo00O0o = ""
   for Oo00o0o00oOo in self . elp . elp_nodes :
    iioOO = socket . htons ( Oo00o0o00oOo . address . afi )
    Ooooo0OO = 0
    if ( Oo00o0o00oOo . eid ) : Ooooo0OO |= 0x4
    if ( Oo00o0o00oOo . probe ) : Ooooo0OO |= 0x2
    if ( Oo00o0o00oOo . strict ) : Ooooo0OO |= 0x1
    Ooooo0OO = socket . htons ( Ooooo0OO )
    oo00O0o += struct . pack ( "HH" , Ooooo0OO , iioOO )
    oo00O0o += Oo00o0o00oOo . address . pack_address ( )
    if 90 - 90: OoO0O00 + i1IIi
    if 43 - 43: O0 % oO0o * I1IiiI
   ooooo0 = socket . htons ( len ( oo00O0o ) )
   O0oo0O00OOO0o = struct . pack ( "HBBBBH" , O0OOOOO0O , 0 , 0 , LISP_LCAF_ELP_TYPE ,
 0 , ooooo0 )
   O0oo0O00OOO0o += oo00O0o
   if 7 - 7: Oo0Ooo + IiII
   if 15 - 15: iIii1I11I1II1 % OoOoOO00 + i1IIi . Ii1I - Oo0Ooo
  oOOoo0O00 = ""
  if ( self . rle ) :
   i111 = ""
   for IIi1i1111i in self . rle . rle_nodes :
    iioOO = socket . htons ( IIi1i1111i . address . afi )
    i111 += struct . pack ( "HBBH" , 0 , 0 , IIi1i1111i . level , iioOO )
    i111 += IIi1i1111i . address . pack_address ( )
    if ( IIi1i1111i . rloc_name ) :
     i111 += struct . pack ( "H" , socket . htons ( LISP_AFI_NAME ) )
     i111 += IIi1i1111i . rloc_name + "\0"
     if 55 - 55: I1Ii111 / i11iIiiIii / OoOoOO00
     if 25 - 25: Oo0Ooo / Oo0Ooo
     if 74 - 74: OOooOOo
   Iii = socket . htons ( len ( i111 ) )
   oOOoo0O00 = struct . pack ( "HBBBBH" , O0OOOOO0O , 0 , 0 , LISP_LCAF_RLE_TYPE ,
 0 , Iii )
   oOOoo0O00 += i111
   if 79 - 79: I1ii11iIi11i - O0 / IiII
   if 1 - 1: I1IiiI
  iii11Ii = ""
  if ( self . json ) :
   ii111 = socket . htons ( len ( self . json . json_string ) + 2 )
   i1oO0o00oOo00oO = socket . htons ( len ( self . json . json_string ) )
   iii11Ii = struct . pack ( "HBBBBHH" , O0OOOOO0O , 0 , 0 , LISP_LCAF_JSON_TYPE ,
 0 , ii111 , i1oO0o00oOo00oO )
   iii11Ii += self . json . json_string
   iii11Ii += struct . pack ( "H" , 0 )
   if 73 - 73: O0 * O0 / O0 . i1IIi
   if 49 - 49: I1Ii111 - Ii1I . O0
  iIiiiIiIIi = ""
  if ( self . rloc . is_null ( ) == False and self . keys and self . keys [ 1 ] ) :
   iIiiiIiIIi = self . keys [ 1 ] . encode_lcaf ( self . rloc )
   if 87 - 87: i1IIi - O0 % OoooooooOO * i11iIiiIii % i11iIiiIii
   if 19 - 19: ooOoO0o
  i11ii1i1i = ""
  if ( self . rloc_name ) :
   i11ii1i1i += struct . pack ( "H" , socket . htons ( LISP_AFI_NAME ) )
   i11ii1i1i += self . rloc_name + "\0"
   if 79 - 79: OoO0O00
   if 4 - 4: I11i / I1ii11iIi11i
  I1i1ii = len ( IiIIII11i1ii ) + len ( O0oo0O00OOO0o ) + len ( oOOoo0O00 ) + len ( iIiiiIiIIi ) + 2 + len ( iii11Ii ) + self . rloc . addr_length ( ) + len ( i11ii1i1i )
  if 14 - 14: ooOoO0o
  I1i1ii = socket . htons ( I1i1ii )
  IIi = struct . pack ( "HBBBBHH" , O0OOOOO0O , 0 , 0 , LISP_LCAF_AFI_LIST_TYPE ,
 0 , I1i1ii , socket . htons ( self . rloc . afi ) )
  IIi += self . rloc . pack_address ( )
  return ( IIi + i11ii1i1i + IiIIII11i1ii + O0oo0O00OOO0o + oOOoo0O00 + iIiiiIiIIi + iii11Ii )
  if 38 - 38: OOooOOo . i11iIiiIii - Ii1I . II111iiii
  if 31 - 31: i1IIi . OoooooooOO
 def encode ( self ) :
  Ooooo0OO = 0
  if ( self . local_bit ) : Ooooo0OO |= 0x0004
  if ( self . probe_bit ) : Ooooo0OO |= 0x0002
  if ( self . reach_bit ) : Ooooo0OO |= 0x0001
  if 19 - 19: Ii1I * I11i . II111iiii
  i1II1IiiIi = struct . pack ( "BBBBHH" , self . priority , self . weight ,
 self . mpriority , self . mweight , socket . htons ( Ooooo0OO ) ,
 socket . htons ( self . rloc . afi ) )
  if 84 - 84: iIii1I11I1II1 / o0oOOo0O0Ooo / II111iiii
  if ( self . geo or self . elp or self . rle or self . keys or self . rloc_name or self . json ) :
   if 81 - 81: i11iIiiIii + o0oOOo0O0Ooo / II111iiii + I11i
   i1II1IiiIi = i1II1IiiIi [ 0 : - 2 ] + self . encode_lcaf ( )
  else :
   i1II1IiiIi += self . rloc . pack_address ( )
   if 73 - 73: OoO0O00 + OOooOOo + IiII - i1IIi
  return ( i1II1IiiIi )
  if 67 - 67: OoooooooOO - i1IIi + Ii1I + I1IiiI
  if 18 - 18: Oo0Ooo * iII111i / II111iiii
 def decode_lcaf ( self , packet , nonce ) :
  oOoOo000 = "HBBBBH"
  O0OOoooO = struct . calcsize ( oOoOo000 )
  if ( len ( packet ) < O0OOoooO ) : return ( None )
  if 77 - 77: Ii1I . o0oOOo0O0Ooo * oO0o
  iioOO , OOII1iI , Ooooo0OO , oOOi1I111II , o0o0OO0OO , ii111 = struct . unpack ( oOoOo000 , packet [ : O0OOoooO ] )
  if 42 - 42: Ii1I / Oo0Ooo
  if 25 - 25: OoooooooOO % Ii1I * I1Ii111 * I11i + I1IiiI % I1ii11iIi11i
  ii111 = socket . ntohs ( ii111 )
  packet = packet [ O0OOoooO : : ]
  if ( ii111 > len ( packet ) ) : return ( None )
  if 70 - 70: Ii1I + I1ii11iIi11i * I11i * i1IIi . I1Ii111
  if 76 - 76: OoooooooOO * OoOoOO00 . OoooooooOO
  if 46 - 46: ooOoO0o * o0oOOo0O0Ooo % II111iiii / I1Ii111
  if 29 - 29: OoO0O00 - i11iIiiIii % Oo0Ooo % o0oOOo0O0Ooo
  if ( oOOi1I111II == LISP_LCAF_AFI_LIST_TYPE ) :
   while ( ii111 > 0 ) :
    oOoOo000 = "H"
    O0OOoooO = struct . calcsize ( oOoOo000 )
    if ( ii111 < O0OOoooO ) : return ( None )
    if 30 - 30: oO0o - Ii1I % Ii1I
    OooOOoO00OO00 = len ( packet )
    iioOO = struct . unpack ( oOoOo000 , packet [ : O0OOoooO ] ) [ 0 ]
    iioOO = socket . ntohs ( iioOO )
    if 8 - 8: IiII
    if ( iioOO == LISP_AFI_LCAF ) :
     packet = self . decode_lcaf ( packet , nonce )
     if ( packet == None ) : return ( None )
    else :
     packet = packet [ O0OOoooO : : ]
     self . rloc_name = None
     if ( iioOO == LISP_AFI_NAME ) :
      packet , OO000 = lisp_decode_dist_name ( packet )
      self . rloc_name = OO000
     else :
      self . rloc . afi = iioOO
      packet = self . rloc . unpack_address ( packet )
      if ( packet == None ) : return ( None )
      self . rloc . mask_len = self . rloc . host_mask_len ( )
      if 68 - 68: IiII . OoooooooOO - i11iIiiIii + i11iIiiIii
      if 81 - 81: OoOoOO00 + iII111i . i11iIiiIii
      if 10 - 10: OoOoOO00 + I11i - iIii1I11I1II1 - I11i
    ii111 -= OooOOoO00OO00 - len ( packet )
    if 58 - 58: ooOoO0o
    if 98 - 98: Ii1I / OoO0O00 % OoooooooOO
  elif ( oOOi1I111II == LISP_LCAF_GEO_COORD_TYPE ) :
   if 65 - 65: ooOoO0o % Oo0Ooo - I1IiiI % I1Ii111 + iIii1I11I1II1 / iIii1I11I1II1
   if 94 - 94: IiII - Oo0Ooo . o0oOOo0O0Ooo - ooOoO0o - oO0o . I11i
   if 39 - 39: oO0o + OoOoOO00
   if 68 - 68: i1IIi * oO0o / i11iIiiIii
   o0oO0O = lisp_geo ( "" )
   packet = o0oO0O . decode_geo ( packet , ii111 , o0o0OO0OO )
   if ( packet == None ) : return ( None )
   self . geo = o0oO0O
   if 28 - 28: O0 % II111iiii / OoOoOO00 / OOooOOo
  elif ( oOOi1I111II == LISP_LCAF_JSON_TYPE ) :
   if 84 - 84: OOooOOo / iIii1I11I1II1 - I1ii11iIi11i . Ii1I
   if 27 - 27: IiII * i1IIi + II111iiii . iIii1I11I1II1 - i11iIiiIii
   if 29 - 29: OOooOOo - i11iIiiIii % IiII / OoooooooOO
   if 92 - 92: I1ii11iIi11i
   oOoOo000 = "H"
   O0OOoooO = struct . calcsize ( oOoOo000 )
   if ( ii111 < O0OOoooO ) : return ( None )
   if 89 - 89: OoO0O00 * i11iIiiIii - IiII * i1IIi - ooOoO0o . Ii1I
   i1oO0o00oOo00oO = struct . unpack ( oOoOo000 , packet [ : O0OOoooO ] ) [ 0 ]
   i1oO0o00oOo00oO = socket . ntohs ( i1oO0o00oOo00oO )
   if ( ii111 < O0OOoooO + i1oO0o00oOo00oO ) : return ( None )
   if 26 - 26: I1IiiI * OoooooooOO / I1IiiI . O0 . ooOoO0o + O0
   packet = packet [ O0OOoooO : : ]
   self . json = lisp_json ( "" , packet [ 0 : i1oO0o00oOo00oO ] )
   packet = packet [ i1oO0o00oOo00oO : : ]
   if 84 - 84: I1Ii111 . O0 + O0 % O0 % i1IIi + iIii1I11I1II1
  elif ( oOOi1I111II == LISP_LCAF_ELP_TYPE ) :
   if 71 - 71: iII111i / iIii1I11I1II1 . OOooOOo * i11iIiiIii
   if 98 - 98: O0 % iIii1I11I1II1 . IiII - II111iiii
   if 14 - 14: Ii1I % ooOoO0o - OoOoOO00
   if 52 - 52: OoO0O00 / i1IIi - Ii1I
   IIi1iIi = lisp_elp ( None )
   IIi1iIi . elp_nodes = [ ]
   while ( ii111 > 0 ) :
    Ooooo0OO , iioOO = struct . unpack ( "HH" , packet [ : 4 ] )
    if 25 - 25: I1IiiI
    iioOO = socket . ntohs ( iioOO )
    if ( iioOO == LISP_AFI_LCAF ) : return ( None )
    if 88 - 88: i1IIi
    Oo00o0o00oOo = lisp_elp_node ( )
    IIi1iIi . elp_nodes . append ( Oo00o0o00oOo )
    if 93 - 93: I1ii11iIi11i . OoO0O00
    Ooooo0OO = socket . ntohs ( Ooooo0OO )
    Oo00o0o00oOo . eid = ( Ooooo0OO & 0x4 )
    Oo00o0o00oOo . probe = ( Ooooo0OO & 0x2 )
    Oo00o0o00oOo . strict = ( Ooooo0OO & 0x1 )
    Oo00o0o00oOo . address . afi = iioOO
    Oo00o0o00oOo . address . mask_len = Oo00o0o00oOo . address . host_mask_len ( )
    packet = Oo00o0o00oOo . address . unpack_address ( packet [ 4 : : ] )
    ii111 -= Oo00o0o00oOo . address . addr_length ( ) + 4
    if 67 - 67: II111iiii + OoooooooOO + I1IiiI
   IIi1iIi . select_elp_node ( )
   self . elp = IIi1iIi
   if 76 - 76: O0 / Oo0Ooo . OoOoOO00
  elif ( oOOi1I111II == LISP_LCAF_RLE_TYPE ) :
   if 81 - 81: o0oOOo0O0Ooo + II111iiii % I1Ii111 - oO0o + ooOoO0o - I1ii11iIi11i
   if 99 - 99: iIii1I11I1II1
   if 100 - 100: OoOoOO00 + I1Ii111 * Oo0Ooo / IiII - IiII
   if 19 - 19: OoooooooOO . Ii1I + Oo0Ooo + II111iiii
   iiiI1i1111II = lisp_rle ( None )
   iiiI1i1111II . rle_nodes = [ ]
   while ( ii111 > 0 ) :
    II11iiii , oo0Oo0o0O , oo0O , iioOO = struct . unpack ( "HBBH" , packet [ : 6 ] )
    if 81 - 81: oO0o . OoO0O00 % OOooOOo - iII111i * iIii1I11I1II1 . iIii1I11I1II1
    iioOO = socket . ntohs ( iioOO )
    if ( iioOO == LISP_AFI_LCAF ) : return ( None )
    if 48 - 48: iIii1I11I1II1 - Oo0Ooo
    IIi1i1111i = lisp_rle_node ( )
    iiiI1i1111II . rle_nodes . append ( IIi1i1111i )
    if 80 - 80: i1IIi
    IIi1i1111i . level = oo0O
    IIi1i1111i . address . afi = iioOO
    IIi1i1111i . address . mask_len = IIi1i1111i . address . host_mask_len ( )
    packet = IIi1i1111i . address . unpack_address ( packet [ 6 : : ] )
    if 56 - 56: II111iiii - o0oOOo0O0Ooo
    ii111 -= IIi1i1111i . address . addr_length ( ) + 6
    if ( ii111 >= 2 ) :
     iioOO = struct . unpack ( "H" , packet [ : 2 ] ) [ 0 ]
     if ( socket . ntohs ( iioOO ) == LISP_AFI_NAME ) :
      packet = packet [ 2 : : ]
      packet , IIi1i1111i . rloc_name = lisp_decode_dist_name ( packet )
      if 48 - 48: Oo0Ooo - I1ii11iIi11i - II111iiii . Ii1I . oO0o / iIii1I11I1II1
      if ( packet == None ) : return ( None )
      ii111 -= len ( IIi1i1111i . rloc_name ) + 1 + 2
      if 38 - 38: I1Ii111 % i11iIiiIii + Ii1I * ooOoO0o / I1Ii111
      if 93 - 93: oO0o
      if 60 - 60: I1Ii111 . oO0o / Oo0Ooo * ooOoO0o + OoOoOO00 - i1IIi
   self . rle = iiiI1i1111II
   self . rle . build_forwarding_list ( )
   if 13 - 13: i11iIiiIii * oO0o / I11i * I1IiiI
  elif ( oOOi1I111II == LISP_LCAF_SECURITY_TYPE ) :
   if 31 - 31: iIii1I11I1II1 * Ii1I % OOooOOo . II111iiii
   if 56 - 56: IiII / i11iIiiIii . o0oOOo0O0Ooo . oO0o - i11iIiiIii
   if 23 - 23: I1ii11iIi11i * i11iIiiIii % ooOoO0o
   if 47 - 47: iIii1I11I1II1 . OOooOOo / I11i % II111iiii
   if 92 - 92: I1ii11iIi11i % i11iIiiIii
   IIiIiIii11I1 = packet
   IiI11IiIIi = lisp_keys ( 1 )
   packet = IiI11IiIIi . decode_lcaf ( IIiIiIii11I1 , ii111 )
   if ( packet == None ) : return ( None )
   if 82 - 82: I1Ii111 * I1ii11iIi11i % Ii1I / o0oOOo0O0Ooo
   if 28 - 28: iII111i % OoO0O00 - OOooOOo - Oo0Ooo
   if 16 - 16: i11iIiiIii - i11iIiiIii . OoOoOO00 / i1IIi
   if 76 - 76: O0 * OoO0O00 / O0
   I1IIiIIiiI1i = [ LISP_CS_25519_CBC , LISP_CS_25519_CHACHA ]
   if ( IiI11IiIIi . cipher_suite in I1IIiIIiiI1i ) :
    if ( IiI11IiIIi . cipher_suite == LISP_CS_25519_CBC ) :
     iii11 = lisp_keys ( 1 , do_poly = False , do_chacha = False )
     if 23 - 23: I1ii11iIi11i . iIii1I11I1II1 - i11iIiiIii / II111iiii
    if ( IiI11IiIIi . cipher_suite == LISP_CS_25519_CHACHA ) :
     iii11 = lisp_keys ( 1 , do_poly = True , do_chacha = True )
     if 48 - 48: oO0o - II111iiii * I1IiiI
   else :
    iii11 = lisp_keys ( 1 , do_poly = False , do_chacha = False )
    if 78 - 78: I1IiiI * i11iIiiIii * II111iiii
   packet = iii11 . decode_lcaf ( IIiIiIii11I1 , ii111 )
   if ( packet == None ) : return ( None )
   if 19 - 19: OoooooooOO * i11iIiiIii / O0 . I1IiiI % I11i
   if ( len ( packet ) < 2 ) : return ( None )
   iioOO = struct . unpack ( "H" , packet [ : 2 ] ) [ 0 ]
   self . rloc . afi = socket . ntohs ( iioOO )
   if ( len ( packet ) < self . rloc . addr_length ( ) ) : return ( None )
   packet = self . rloc . unpack_address ( packet [ 2 : : ] )
   if ( packet == None ) : return ( None )
   self . rloc . mask_len = self . rloc . host_mask_len ( )
   if 35 - 35: iIii1I11I1II1 + I1IiiI - ooOoO0o / Oo0Ooo * I1ii11iIi11i * Oo0Ooo
   if 17 - 17: OoOoOO00
   if 24 - 24: iIii1I11I1II1 / OOooOOo % OoooooooOO / O0 / oO0o
   if 93 - 93: Oo0Ooo
   if 5 - 5: iII111i
   if 61 - 61: OOooOOo * OoO0O00 - O0
   if ( self . rloc . is_null ( ) ) : return ( packet )
   if 30 - 30: iIii1I11I1II1
   iI11Ii = self . rloc_name
   if ( iI11Ii ) : iI11Ii = blue ( self . rloc_name , False )
   if 18 - 18: OoOoOO00 - i11iIiiIii * i1IIi
   if 13 - 13: i1IIi . I1ii11iIi11i * o0oOOo0O0Ooo
   if 31 - 31: i11iIiiIii % OoO0O00 . i11iIiiIii % oO0o - i1IIi
   if 62 - 62: oO0o + oO0o . OoooooooOO
   if 59 - 59: iIii1I11I1II1 . Oo0Ooo * I11i
   if 29 - 29: Oo0Ooo - I1IiiI * I11i
   O00oO0OOOo0 = self . keys [ 1 ] if self . keys else None
   if ( O00oO0OOOo0 == None ) :
    if ( iii11 . remote_public_key == None ) :
     OO0o0o0oo = bold ( "No remote encap-public-key supplied" , False )
     lprint ( "    {} for {}" . format ( OO0o0o0oo , iI11Ii ) )
     iii11 = None
    else :
     OO0o0o0oo = bold ( "New encap-keying with new state" , False )
     lprint ( "    {} for {}" . format ( OO0o0o0oo , iI11Ii ) )
     iii11 . compute_shared_key ( "encap" )
     if 58 - 58: i1IIi * Ii1I / ooOoO0o % iIii1I11I1II1
     if 24 - 24: OoOoOO00 - o0oOOo0O0Ooo * I1IiiI . I11i / OoO0O00 * Ii1I
     if 12 - 12: OoooooooOO % oO0o
     if 92 - 92: ooOoO0o % OoO0O00 + O0 + OoOoOO00 / OoO0O00 * iIii1I11I1II1
     if 79 - 79: O0
     if 71 - 71: OoO0O00 - O0
     if 73 - 73: iIii1I11I1II1
     if 7 - 7: OoOoOO00
     if 55 - 55: oO0o . OoO0O00 + iIii1I11I1II1 + OoOoOO00 / I1ii11iIi11i - O0
     if 14 - 14: II111iiii - OoO0O00 - O0 * OoooooooOO / I1IiiI
   if ( O00oO0OOOo0 ) :
    if ( iii11 . remote_public_key == None ) :
     iii11 = None
     ii1I11iIi = bold ( "Remote encap-unkeying occurred" , False )
     lprint ( "    {} for {}" . format ( ii1I11iIi , iI11Ii ) )
    elif ( O00oO0OOOo0 . compare_keys ( iii11 ) ) :
     iii11 = O00oO0OOOo0
     lprint ( "    Maintain stored encap-keys for {}" . format ( iI11Ii ) )
     if 3 - 3: I11i
    else :
     if ( O00oO0OOOo0 . remote_public_key == None ) :
      OO0o0o0oo = "New encap-keying for existing state"
     else :
      OO0o0o0oo = "Remote encap-rekeying"
      if 46 - 46: I1ii11iIi11i * I1Ii111 - iIii1I11I1II1
     lprint ( "    {} for {}" . format ( bold ( OO0o0o0oo , False ) ,
 iI11Ii ) )
     O00oO0OOOo0 . remote_public_key = iii11 . remote_public_key
     O00oO0OOOo0 . compute_shared_key ( "encap" )
     iii11 = O00oO0OOOo0
     if 25 - 25: II111iiii / OOooOOo + Oo0Ooo - iIii1I11I1II1 - OoOoOO00
     if 97 - 97: OOooOOo . OOooOOo / I1ii11iIi11i + I1IiiI * i1IIi
   self . keys = [ None , iii11 , None , None ]
   if 53 - 53: O0
  else :
   if 28 - 28: iII111i % OoO0O00 . OoO0O00 / IiII * Oo0Ooo * iII111i
   if 49 - 49: I1IiiI / I1Ii111 * iII111i + I1IiiI % oO0o % ooOoO0o
   if 27 - 27: OoO0O00 / iII111i . I1ii11iIi11i
   if 71 - 71: OoO0O00 . i11iIiiIii . iIii1I11I1II1 + I1IiiI - o0oOOo0O0Ooo
   packet = packet [ ii111 : : ]
   if 34 - 34: iII111i
  return ( packet )
  if 6 - 6: OoO0O00 . OoOoOO00 + I1ii11iIi11i
  if 24 - 24: OoO0O00 . Ii1I
 def decode ( self , packet , nonce ) :
  oOoOo000 = "BBBBHH"
  O0OOoooO = struct . calcsize ( oOoOo000 )
  if ( len ( packet ) < O0OOoooO ) : return ( None )
  if 26 - 26: O0 * I1IiiI - OOooOOo * OoooooooOO * II111iiii % OoOoOO00
  self . priority , self . weight , self . mpriority , self . mweight , Ooooo0OO , iioOO = struct . unpack ( oOoOo000 , packet [ : O0OOoooO ] )
  if 56 - 56: OOooOOo * i11iIiiIii % ooOoO0o * OoOoOO00 % Oo0Ooo * IiII
  if 30 - 30: i1IIi + o0oOOo0O0Ooo - OoOoOO00 . OOooOOo
  Ooooo0OO = socket . ntohs ( Ooooo0OO )
  iioOO = socket . ntohs ( iioOO )
  self . local_bit = True if ( Ooooo0OO & 0x0004 ) else False
  self . probe_bit = True if ( Ooooo0OO & 0x0002 ) else False
  self . reach_bit = True if ( Ooooo0OO & 0x0001 ) else False
  if 95 - 95: i1IIi . I11i + O0 . I11i - I11i / Oo0Ooo
  if ( iioOO == LISP_AFI_LCAF ) :
   packet = packet [ O0OOoooO - 2 : : ]
   packet = self . decode_lcaf ( packet , nonce )
  else :
   self . rloc . afi = iioOO
   packet = packet [ O0OOoooO : : ]
   packet = self . rloc . unpack_address ( packet )
   if 41 - 41: OoooooooOO . OOooOOo - Ii1I * OoO0O00 % i11iIiiIii
  self . rloc . mask_len = self . rloc . host_mask_len ( )
  return ( packet )
  if 7 - 7: Ii1I
  if 16 - 16: IiII * o0oOOo0O0Ooo % II111iiii - II111iiii + ooOoO0o
 def end_of_rlocs ( self , packet , rloc_count ) :
  for Ii11 in range ( rloc_count ) :
   packet = self . decode ( packet , None )
   if ( packet == None ) : return ( None )
   if 55 - 55: OoO0O00 % OoOoOO00
  return ( packet )
  if 58 - 58: Ii1I
  if 17 - 17: OoO0O00 - oO0o % Oo0Ooo % oO0o * I1Ii111 / IiII
  if 88 - 88: ooOoO0o . II111iiii * O0 % IiII
  if 15 - 15: O0 % i1IIi - OOooOOo . IiII
  if 1 - 1: I1IiiI
  if 40 - 40: o0oOOo0O0Ooo % I11i % O0
  if 88 - 88: o0oOOo0O0Ooo - oO0o
  if 73 - 73: II111iiii
  if 7 - 7: O0 / OoO0O00
  if 90 - 90: iII111i % oO0o / iIii1I11I1II1
  if 52 - 52: I1IiiI / o0oOOo0O0Ooo
  if 20 - 20: I1Ii111 . I1IiiI - iIii1I11I1II1 / iII111i
  if 46 - 46: I1Ii111 . i11iIiiIii
  if 89 - 89: OoO0O00 - OOooOOo - i1IIi - OoO0O00 % iIii1I11I1II1
  if 52 - 52: o0oOOo0O0Ooo * O0 + I1ii11iIi11i
  if 83 - 83: I11i + OOooOOo - OoooooooOO
  if 7 - 7: IiII % ooOoO0o / OoooooooOO / o0oOOo0O0Ooo + OoO0O00 - OoO0O00
  if 15 - 15: i1IIi + OOooOOo / Ii1I
  if 51 - 51: OOooOOo + O0
  if 91 - 91: i11iIiiIii + o0oOOo0O0Ooo % OoO0O00 / oO0o - i1IIi
  if 82 - 82: Ii1I . OoooooooOO + OoooooooOO % OoO0O00 % I1ii11iIi11i
  if 65 - 65: Oo0Ooo . I11i
  if 7 - 7: Oo0Ooo * II111iiii
  if 11 - 11: OoOoOO00 % OoooooooOO
  if 92 - 92: OoOoOO00 - iII111i * Ii1I - i1IIi
  if 87 - 87: Ii1I * I1Ii111 + iIii1I11I1II1 * o0oOOo0O0Ooo * iIii1I11I1II1 . I11i
  if 66 - 66: Ii1I / OoO0O00 . O0 . I11i % OoooooooOO / OOooOOo
  if 49 - 49: I1IiiI * iII111i - OoO0O00 % Ii1I + Ii1I * I1Ii111
  if 94 - 94: OoOoOO00 - I11i + Ii1I + OoOoOO00 + II111iiii
  if 61 - 61: IiII + Ii1I / oO0o . OoooooooOO + iII111i
class lisp_map_referral ( ) :
 def __init__ ( self ) :
  self . record_count = 0
  self . nonce = 0
  if 29 - 29: OOooOOo
  if 69 - 69: oO0o % OoooooooOO * iII111i
 def print_map_referral ( self ) :
  lprint ( "{} -> record-count: {}, nonce: 0x{}" . format ( bold ( "Map-Referral" , False ) , self . record_count ,
  # i1IIi % i11iIiiIii - OOooOOo . OoOoOO00
 lisp_hex_string ( self . nonce ) ) )
  if 25 - 25: iIii1I11I1II1
  if 50 - 50: I1Ii111 . I11i / O0 . I11i
 def encode ( self ) :
  oOoOo00oo = ( LISP_MAP_REFERRAL << 28 ) | self . record_count
  i1II1IiiIi = struct . pack ( "I" , socket . htonl ( oOoOo00oo ) )
  i1II1IiiIi += struct . pack ( "Q" , self . nonce )
  return ( i1II1IiiIi )
  if 91 - 91: i11iIiiIii . I1ii11iIi11i + I11i
  if 67 - 67: I1ii11iIi11i * I1Ii111 * I1IiiI / I11i - IiII + oO0o
 def decode ( self , packet ) :
  oOoOo000 = "I"
  O0OOoooO = struct . calcsize ( oOoOo000 )
  if ( len ( packet ) < O0OOoooO ) : return ( None )
  if 11 - 11: O0 + i1IIi / o0oOOo0O0Ooo * OoO0O00
  oOoOo00oo = struct . unpack ( oOoOo000 , packet [ : O0OOoooO ] )
  oOoOo00oo = socket . ntohl ( oOoOo00oo [ 0 ] )
  self . record_count = oOoOo00oo & 0xff
  packet = packet [ O0OOoooO : : ]
  if 64 - 64: i1IIi % IiII . ooOoO0o . iIii1I11I1II1 + OoO0O00 - iIii1I11I1II1
  oOoOo000 = "Q"
  O0OOoooO = struct . calcsize ( oOoOo000 )
  if ( len ( packet ) < O0OOoooO ) : return ( None )
  if 52 - 52: II111iiii - IiII
  self . nonce = struct . unpack ( oOoOo000 , packet [ : O0OOoooO ] ) [ 0 ]
  packet = packet [ O0OOoooO : : ]
  return ( packet )
  if 91 - 91: iIii1I11I1II1 + iII111i . I11i % i11iIiiIii - i11iIiiIii + I1IiiI
  if 75 - 75: I1ii11iIi11i / I1IiiI - iIii1I11I1II1 / OoO0O00 * OOooOOo
  if 73 - 73: OoooooooOO % IiII / I1Ii111 * I11i + i1IIi % i11iIiiIii
  if 91 - 91: i11iIiiIii
  if 6 - 6: O0 - iIii1I11I1II1 + I1Ii111 . o0oOOo0O0Ooo * i11iIiiIii
  if 53 - 53: OOooOOo / I1IiiI / oO0o * OOooOOo / i1IIi - I1Ii111
  if 71 - 71: O0 + Oo0Ooo % oO0o - o0oOOo0O0Ooo
  if 82 - 82: iIii1I11I1II1
class lisp_ddt_entry ( ) :
 def __init__ ( self ) :
  self . eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . group = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . uptime = lisp_get_timestamp ( )
  self . delegation_set = [ ]
  self . source_cache = None
  self . map_referrals_sent = 0
  if 64 - 64: ooOoO0o + I1IiiI % OOooOOo + II111iiii
  if 46 - 46: I1IiiI
 def is_auth_prefix ( self ) :
  if ( len ( self . delegation_set ) != 0 ) : return ( False )
  if ( self . is_star_g ( ) ) : return ( False )
  return ( True )
  if 72 - 72: iII111i
  if 100 - 100: I1IiiI
 def is_ms_peer_entry ( self ) :
  if ( len ( self . delegation_set ) == 0 ) : return ( False )
  return ( self . delegation_set [ 0 ] . is_ms_peer ( ) )
  if 55 - 55: i1IIi % IiII
  if 44 - 44: oO0o - iIii1I11I1II1 / ooOoO0o - iIii1I11I1II1 % i1IIi + ooOoO0o
 def print_referral_type ( self ) :
  if ( len ( self . delegation_set ) == 0 ) : return ( "unknown" )
  o0i1II1iI = self . delegation_set [ 0 ]
  return ( o0i1II1iI . print_node_type ( ) )
  if 82 - 82: OoO0O00 * o0oOOo0O0Ooo
  if 67 - 67: OOooOOo . Ii1I * OoooooooOO
 def print_eid_tuple ( self ) :
  return ( lisp_print_eid_tuple ( self . eid , self . group ) )
  if 93 - 93: OoO0O00 . OoO0O00
  if 52 - 52: OOooOOo . oO0o / Oo0Ooo . OoooooooOO % I1ii11iIi11i
 def add_cache ( self ) :
  if ( self . group . is_null ( ) ) :
   lisp_ddt_cache . add_cache ( self . eid , self )
  else :
   O0ooO0OooO = lisp_ddt_cache . lookup_cache ( self . group , True )
   if ( O0ooO0OooO == None ) :
    O0ooO0OooO = lisp_ddt_entry ( )
    O0ooO0OooO . eid . copy_address ( self . group )
    O0ooO0OooO . group . copy_address ( self . group )
    lisp_ddt_cache . add_cache ( self . group , O0ooO0OooO )
    if 49 - 49: I1IiiI
   if ( self . eid . is_null ( ) ) : self . eid . make_default_route ( O0ooO0OooO . group )
   O0ooO0OooO . add_source_entry ( self )
   if 61 - 61: o0oOOo0O0Ooo / I1ii11iIi11i / ooOoO0o
   if 54 - 54: I1Ii111 * I1Ii111
   if 30 - 30: I1Ii111 . OoOoOO00 + I1ii11iIi11i - iIii1I11I1II1 * ooOoO0o
 def add_source_entry ( self , source_ddt ) :
  if ( self . source_cache == None ) : self . source_cache = lisp_cache ( )
  self . source_cache . add_cache ( source_ddt . eid , source_ddt )
  if 87 - 87: O0 + O0 - ooOoO0o . i11iIiiIii - Oo0Ooo * i11iIiiIii
  if 72 - 72: I11i / OoooooooOO
 def lookup_source_cache ( self , source , exact ) :
  if ( self . source_cache == None ) : return ( None )
  return ( self . source_cache . lookup_cache ( source , exact ) )
  if 95 - 95: I1IiiI * i11iIiiIii + i11iIiiIii / iIii1I11I1II1
  if 20 - 20: I11i
 def is_star_g ( self ) :
  if ( self . group . is_null ( ) ) : return ( False )
  return ( self . eid . is_exact_match ( self . group ) )
  if 15 - 15: o0oOOo0O0Ooo . i11iIiiIii * I1ii11iIi11i / ooOoO0o
  if 41 - 41: ooOoO0o + IiII . i1IIi + iIii1I11I1II1
  if 57 - 57: i11iIiiIii * oO0o * i11iIiiIii
class lisp_ddt_node ( ) :
 def __init__ ( self ) :
  self . delegate_address = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . public_key = ""
  self . map_server_peer = False
  self . map_server_child = False
  self . priority = 0
  self . weight = 0
  if 14 - 14: Oo0Ooo / I11i
  if 14 - 14: Oo0Ooo - Ii1I + ooOoO0o - I1IiiI % IiII
 def print_node_type ( self ) :
  if ( self . is_ddt_child ( ) ) : return ( "ddt-child" )
  if ( self . is_ms_child ( ) ) : return ( "map-server-child" )
  if ( self . is_ms_peer ( ) ) : return ( "map-server-peer" )
  if 70 - 70: I1IiiI % ooOoO0o * OoO0O00 + OoOoOO00 % i11iIiiIii
  if 39 - 39: Oo0Ooo % I1Ii111 / I1IiiI / Oo0Ooo . o0oOOo0O0Ooo + o0oOOo0O0Ooo
 def is_ddt_child ( self ) :
  if ( self . map_server_child ) : return ( False )
  if ( self . map_server_peer ) : return ( False )
  return ( True )
  if 83 - 83: OoooooooOO * II111iiii % OoooooooOO
  if 30 - 30: I1Ii111 / o0oOOo0O0Ooo + OoooooooOO + OoOoOO00 + OoO0O00
 def is_ms_child ( self ) :
  return ( self . map_server_child )
  if 40 - 40: OoooooooOO / IiII
  if 82 - 82: i11iIiiIii - oO0o - i1IIi
 def is_ms_peer ( self ) :
  return ( self . map_server_peer )
  if 78 - 78: oO0o % iII111i / i1IIi / ooOoO0o
  if 44 - 44: o0oOOo0O0Ooo + Ii1I + I1IiiI % O0
  if 100 - 100: OoooooooOO
  if 27 - 27: i11iIiiIii % II111iiii + I1Ii111
  if 76 - 76: OOooOOo - I1Ii111 + iIii1I11I1II1 + I1IiiI * oO0o
  if 93 - 93: i11iIiiIii * i11iIiiIii - I1IiiI + iIii1I11I1II1 * i11iIiiIii
  if 14 - 14: ooOoO0o . OoooooooOO . I1IiiI - IiII + iIii1I11I1II1
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
  if 47 - 47: OOooOOo % i1IIi
  if 23 - 23: Ii1I * Ii1I / I11i
 def print_ddt_map_request ( self ) :
  lprint ( "Queued Map-Request from {}ITR {}->{}, nonce 0x{}" . format ( "P" if self . from_pitr else "" ,
  # iIii1I11I1II1
 red ( self . itr . print_address ( ) , False ) ,
 green ( self . eid . print_address ( ) , False ) , self . nonce ) )
  if 66 - 66: IiII / OoooooooOO + II111iiii + I1ii11iIi11i
  if 85 - 85: OOooOOo / O0 . Oo0Ooo
 def queue_map_request ( self ) :
  self . retransmit_timer = threading . Timer ( LISP_DDT_MAP_REQUEST_INTERVAL ,
 lisp_retransmit_ddt_map_request , [ self ] )
  self . retransmit_timer . start ( )
  lisp_ddt_map_requestQ [ str ( self . nonce ) ] = self
  if 23 - 23: Oo0Ooo % II111iiii
  if 96 - 96: ooOoO0o % Ii1I
 def dequeue_map_request ( self ) :
  self . retransmit_timer . cancel ( )
  if ( lisp_ddt_map_requestQ . has_key ( str ( self . nonce ) ) ) :
   lisp_ddt_map_requestQ . pop ( str ( self . nonce ) )
   if 83 - 83: I1IiiI - OOooOOo . I1IiiI * Oo0Ooo
   if 76 - 76: i11iIiiIii + Ii1I
   if 14 - 14: OoO0O00 * OoooooooOO
 def print_eid_tuple ( self ) :
  return ( lisp_print_eid_tuple ( self . eid , self . group ) )
  if 45 - 45: iIii1I11I1II1 * I1IiiI . OoOoOO00
  if 97 - 97: I11i % II111iiii % Ii1I . II111iiii . iIii1I11I1II1
  if 98 - 98: i11iIiiIii + O0 - O0 - iII111i
  if 25 - 25: oO0o / O0 + I1Ii111 % i11iIiiIii / I1IiiI
  if 62 - 62: iII111i . I11i * i1IIi + iII111i
  if 95 - 95: Ii1I / o0oOOo0O0Ooo % ooOoO0o - I1IiiI / OOooOOo * OOooOOo
  if 6 - 6: OoO0O00 % IiII + iIii1I11I1II1
  if 18 - 18: II111iiii . Ii1I + OoOoOO00 + O0 - I11i
  if 30 - 30: II111iiii
  if 26 - 26: I11i - i1IIi - Oo0Ooo * O0 * OOooOOo . OoooooooOO
  if 99 - 99: oO0o . OoO0O00 / OOooOOo
  if 12 - 12: iIii1I11I1II1 + ooOoO0o * I1Ii111 % OoooooooOO / iIii1I11I1II1
  if 43 - 43: O0 . i1IIi - OoooooooOO - i1IIi - I1ii11iIi11i
  if 8 - 8: OoOoOO00 / Ii1I
  if 12 - 12: iIii1I11I1II1
  if 52 - 52: oO0o . I1ii11iIi11i + oO0o
  if 73 - 73: II111iiii / i11iIiiIii / ooOoO0o
  if 1 - 1: iII111i + OoOoOO00 / IiII - I1IiiI % I1IiiI
  if 6 - 6: OoOoOO00 - i1IIi + II111iiii % oO0o
  if 72 - 72: OOooOOo + OOooOOo
LISP_DDT_ACTION_SITE_NOT_FOUND = - 2
LISP_DDT_ACTION_NULL = - 1
LISP_DDT_ACTION_NODE_REFERRAL = 0
LISP_DDT_ACTION_MS_REFERRAL = 1
LISP_DDT_ACTION_MS_ACK = 2
LISP_DDT_ACTION_MS_NOT_REG = 3
LISP_DDT_ACTION_DELEGATION_HOLE = 4
LISP_DDT_ACTION_NOT_AUTH = 5
LISP_DDT_ACTION_MAX = LISP_DDT_ACTION_NOT_AUTH
if 30 - 30: I11i
lisp_map_referral_action_string = [
 "node-referral" , "ms-referral" , "ms-ack" , "ms-not-registered" ,
 "delegation-hole" , "not-authoritative" ]
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
if 20 - 20: IiII % I1IiiI + iIii1I11I1II1 % iII111i
if 100 - 100: o0oOOo0O0Ooo - Oo0Ooo % I1Ii111 . i11iIiiIii % OoooooooOO
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
  if 39 - 39: I1ii11iIi11i / i11iIiiIii * i1IIi * Oo0Ooo
  if 39 - 39: OoO0O00 * OoooooooOO / i1IIi + Oo0Ooo
 def print_info ( self ) :
  if ( self . info_reply ) :
   o0o000ooOooO = "Info-Reply"
   OoOOo = ( ", ms-port: {}, etr-port: {}, global-rloc: {}, " + "ms-rloc: {}, private-rloc: {}, RTR-list: " ) . format ( self . ms_port , self . etr_port ,
   # II111iiii % OoooooooOO
   # o0oOOo0O0Ooo % i1IIi / Oo0Ooo / I11i * Oo0Ooo
 red ( self . global_etr_rloc . print_address_no_iid ( ) , False ) ,
 red ( self . global_ms_rloc . print_address_no_iid ( ) , False ) ,
 red ( self . private_etr_rloc . print_address_no_iid ( ) , False ) )
   if ( len ( self . rtr_list ) == 0 ) : OoOOo += "empty, "
   for oOOoOO in self . rtr_list :
    OoOOo += red ( oOOoOO . print_address_no_iid ( ) , False ) + ", "
    if 63 - 63: I1IiiI
   OoOOo = OoOOo [ 0 : - 2 ]
  else :
   o0o000ooOooO = "Info-Request"
   i1II11 = "<none>" if self . hostname == None else self . hostname
   OoOOo = ", hostname: {}" . format ( blue ( i1II11 , False ) )
   if 64 - 64: ooOoO0o % IiII - iII111i * i1IIi * I1Ii111 + IiII
  lprint ( "{} -> nonce: 0x{}{}" . format ( bold ( o0o000ooOooO , False ) ,
 lisp_hex_string ( self . nonce ) , OoOOo ) )
  if 43 - 43: O0 / IiII
  if 41 - 41: OoOoOO00
 def encode ( self ) :
  oOoOo00oo = ( LISP_NAT_INFO << 28 )
  if ( self . info_reply ) : oOoOo00oo |= ( 1 << 27 )
  if 81 - 81: Ii1I . I1IiiI % o0oOOo0O0Ooo . OoOoOO00
  if 94 - 94: oO0o % Oo0Ooo + OoO0O00 * oO0o - i11iIiiIii / I11i
  if 46 - 46: IiII - OoO0O00 * iII111i . I1Ii111 - ooOoO0o . i1IIi
  if 53 - 53: I1Ii111 * I1IiiI + Oo0Ooo + I1IiiI + OOooOOo
  if 8 - 8: i11iIiiIii + OoOoOO00 . I1ii11iIi11i / OoooooooOO % II111iiii
  i1II1IiiIi = struct . pack ( "I" , socket . htonl ( oOoOo00oo ) )
  i1II1IiiIi += struct . pack ( "Q" , self . nonce )
  i1II1IiiIi += struct . pack ( "III" , 0 , 0 , 0 )
  if 21 - 21: oO0o - o0oOOo0O0Ooo + ooOoO0o . I1IiiI * oO0o * Ii1I
  if 41 - 41: i1IIi % i11iIiiIii + I11i % OoooooooOO / I1ii11iIi11i
  if 8 - 8: OoooooooOO - OoO0O00 / i11iIiiIii / O0 . IiII
  if 86 - 86: ooOoO0o * OoooooooOO + iII111i + o0oOOo0O0Ooo
  if ( self . info_reply == False ) :
   if ( self . hostname == None ) :
    i1II1IiiIi += struct . pack ( "H" , 0 )
   else :
    i1II1IiiIi += struct . pack ( "H" , socket . htons ( LISP_AFI_NAME ) )
    i1II1IiiIi += self . hostname + "\0"
    if 79 - 79: i1IIi % I1ii11iIi11i - OoO0O00 % I1ii11iIi11i
   return ( i1II1IiiIi )
   if 6 - 6: Oo0Ooo / iII111i . i11iIiiIii
   if 8 - 8: I1ii11iIi11i + O0 - oO0o % II111iiii . I1Ii111
   if 86 - 86: IiII
   if 71 - 71: Ii1I - i1IIi . I1IiiI
   if 15 - 15: i1IIi % II111iiii / II111iiii - I1ii11iIi11i - I11i % i1IIi
  iioOO = socket . htons ( LISP_AFI_LCAF )
  oOOi1I111II = LISP_LCAF_NAT_TYPE
  ii111 = socket . htons ( 16 )
  OoO = socket . htons ( self . ms_port )
  i1IiiIiIII11 = socket . htons ( self . etr_port )
  i1II1IiiIi += struct . pack ( "HHBBHHHH" , iioOO , 0 , oOOi1I111II , 0 , ii111 ,
 OoO , i1IiiIiIII11 , socket . htons ( self . global_etr_rloc . afi ) )
  i1II1IiiIi += self . global_etr_rloc . pack_address ( )
  i1II1IiiIi += struct . pack ( "HH" , 0 , socket . htons ( self . private_etr_rloc . afi ) )
  i1II1IiiIi += self . private_etr_rloc . pack_address ( )
  if ( len ( self . rtr_list ) == 0 ) : i1II1IiiIi += struct . pack ( "H" , 0 )
  if 39 - 39: I1IiiI + oO0o . I1Ii111 * iII111i - OoOoOO00 / Ii1I
  if 38 - 38: i1IIi / II111iiii
  if 51 - 51: iII111i - OoOoOO00 + II111iiii
  if 83 - 83: Ii1I
  for oOOoOO in self . rtr_list :
   i1II1IiiIi += struct . pack ( "H" , socket . htons ( oOOoOO . afi ) )
   i1II1IiiIi += oOOoOO . pack_address ( )
   if 25 - 25: OoOoOO00 + IiII . i11iIiiIii
  return ( i1II1IiiIi )
  if 87 - 87: I1IiiI + OoooooooOO + O0
  if 32 - 32: Ii1I / I1ii11iIi11i . Ii1I
 def decode ( self , packet ) :
  IIiIiIii11I1 = packet
  oOoOo000 = "I"
  O0OOoooO = struct . calcsize ( oOoOo000 )
  if ( len ( packet ) < O0OOoooO ) : return ( None )
  if 65 - 65: IiII
  oOoOo00oo = struct . unpack ( oOoOo000 , packet [ : O0OOoooO ] )
  oOoOo00oo = oOoOo00oo [ 0 ]
  packet = packet [ O0OOoooO : : ]
  if 74 - 74: Oo0Ooo + i1IIi - II111iiii / ooOoO0o / iII111i
  oOoOo000 = "Q"
  O0OOoooO = struct . calcsize ( oOoOo000 )
  if ( len ( packet ) < O0OOoooO ) : return ( None )
  if 66 - 66: ooOoO0o / IiII * iIii1I11I1II1
  oOo0 = struct . unpack ( oOoOo000 , packet [ : O0OOoooO ] )
  if 42 - 42: I1Ii111 - i11iIiiIii % II111iiii * ooOoO0o . O0 % I11i
  oOoOo00oo = socket . ntohl ( oOoOo00oo )
  self . nonce = oOo0 [ 0 ]
  self . info_reply = oOoOo00oo & 0x08000000
  self . hostname = None
  packet = packet [ O0OOoooO : : ]
  if 82 - 82: Oo0Ooo % O0 + I1ii11iIi11i % I1ii11iIi11i
  if 74 - 74: O0 * IiII . I11i - I1Ii111 + O0 + I11i
  if 48 - 48: oO0o . o0oOOo0O0Ooo - OOooOOo
  if 29 - 29: Oo0Ooo - Ii1I - Oo0Ooo
  if 89 - 89: Oo0Ooo . OoO0O00 . I1ii11iIi11i * oO0o . O0
  oOoOo000 = "HH"
  O0OOoooO = struct . calcsize ( oOoOo000 )
  if ( len ( packet ) < O0OOoooO ) : return ( None )
  if 72 - 72: i11iIiiIii % I11i / I1Ii111 + I1IiiI * iII111i
  if 69 - 69: I1Ii111 + O0 . IiII . o0oOOo0O0Ooo
  if 38 - 38: IiII / i1IIi
  if 60 - 60: OoOoOO00
  if 75 - 75: II111iiii / iIii1I11I1II1 / OoooooooOO
  I1o0 , IiII1Iiii = struct . unpack ( oOoOo000 , packet [ : O0OOoooO ] )
  if ( IiII1Iiii != 0 ) : return ( None )
  if 61 - 61: IiII . IiII
  packet = packet [ O0OOoooO : : ]
  oOoOo000 = "IBBH"
  O0OOoooO = struct . calcsize ( oOoOo000 )
  if ( len ( packet ) < O0OOoooO ) : return ( None )
  if 17 - 17: OoOoOO00 % Oo0Ooo / I1Ii111 . Ii1I % OoO0O00
  iiI , i11iIi1I1i1 , Iii11i1 , ii1Ii1 = struct . unpack ( oOoOo000 ,
 packet [ : O0OOoooO ] )
  if 35 - 35: Ii1I * OoooooooOO + I1ii11iIi11i . IiII / O0 % I1ii11iIi11i
  if ( ii1Ii1 != 0 ) : return ( None )
  packet = packet [ O0OOoooO : : ]
  if 31 - 31: O0 % ooOoO0o / I1IiiI * iII111i % iIii1I11I1II1 * OoOoOO00
  if 76 - 76: I1Ii111 - O0
  if 23 - 23: O0 * Ii1I * ooOoO0o % ooOoO0o
  if 7 - 7: II111iiii + I11i
  if ( self . info_reply == False ) :
   oOoOo000 = "H"
   O0OOoooO = struct . calcsize ( oOoOo000 )
   if ( len ( packet ) >= O0OOoooO ) :
    iioOO = struct . unpack ( oOoOo000 , packet [ : O0OOoooO ] ) [ 0 ]
    if ( socket . ntohs ( iioOO ) == LISP_AFI_NAME ) :
     packet = packet [ O0OOoooO : : ]
     packet , self . hostname = lisp_decode_dist_name ( packet )
     if 99 - 99: iIii1I11I1II1 * oO0o
     if 37 - 37: ooOoO0o * iII111i * I11i
   return ( IIiIiIii11I1 )
   if 11 - 11: I1IiiI
   if 48 - 48: O0 . I11i
   if 9 - 9: oO0o / Oo0Ooo
   if 85 - 85: i11iIiiIii / I1IiiI . OoO0O00 . I11i . oO0o * IiII
   if 41 - 41: Ii1I / OoO0O00 / OoO0O00 * I11i
  oOoOo000 = "HHBBHHH"
  O0OOoooO = struct . calcsize ( oOoOo000 )
  if ( len ( packet ) < O0OOoooO ) : return ( None )
  if 31 - 31: Ii1I / OoooooooOO % iIii1I11I1II1 - IiII * I1IiiI - O0
  iioOO , II11iiii , oOOi1I111II , i11iIi1I1i1 , ii111 , OoO , i1IiiIiIII11 = struct . unpack ( oOoOo000 , packet [ : O0OOoooO ] )
  if 31 - 31: oO0o
  if 74 - 74: OoO0O00
  if ( socket . ntohs ( iioOO ) != LISP_AFI_LCAF ) : return ( None )
  if 11 - 11: oO0o + O0 % Ii1I . I11i * o0oOOo0O0Ooo
  self . ms_port = socket . ntohs ( OoO )
  self . etr_port = socket . ntohs ( i1IiiIiIII11 )
  packet = packet [ O0OOoooO : : ]
  if 14 - 14: I11i . iIii1I11I1II1 + I1Ii111 % OoooooooOO
  if 9 - 9: oO0o + Ii1I / I1ii11iIi11i * iIii1I11I1II1 + o0oOOo0O0Ooo
  if 64 - 64: I11i % i11iIiiIii % I1ii11iIi11i
  if 14 - 14: I1Ii111 - OoOoOO00 - I1ii11iIi11i % I11i + OoooooooOO
  oOoOo000 = "H"
  O0OOoooO = struct . calcsize ( oOoOo000 )
  if ( len ( packet ) < O0OOoooO ) : return ( None )
  if 4 - 4: I1Ii111 - I1IiiI / iIii1I11I1II1 + I1ii11iIi11i % iIii1I11I1II1 * I1IiiI
  if 30 - 30: i11iIiiIii % OOooOOo
  if 52 - 52: I11i - oO0o . i11iIiiIii - II111iiii + Ii1I . iII111i
  if 27 - 27: I1IiiI + OoOoOO00 + iII111i
  iioOO = struct . unpack ( oOoOo000 , packet [ : O0OOoooO ] ) [ 0 ]
  packet = packet [ O0OOoooO : : ]
  if ( iioOO != 0 ) :
   self . global_etr_rloc . afi = socket . ntohs ( iioOO )
   packet = self . global_etr_rloc . unpack_address ( packet )
   if ( packet == None ) : return ( None )
   self . global_etr_rloc . mask_len = self . global_etr_rloc . host_mask_len ( )
   if 70 - 70: I11i + IiII . ooOoO0o - I1ii11iIi11i
   if 34 - 34: i1IIi % Oo0Ooo . oO0o
   if 36 - 36: I1ii11iIi11i / I1Ii111 - IiII + OOooOOo + I1Ii111
   if 62 - 62: Oo0Ooo . OoO0O00 * I1Ii111 . i11iIiiIii * O0
   if 10 - 10: Oo0Ooo / OoOoOO00 * OOooOOo - IiII + Ii1I
   if 62 - 62: I1IiiI . Ii1I
  if ( len ( packet ) < O0OOoooO ) : return ( IIiIiIii11I1 )
  if 74 - 74: Ii1I - I11i % ooOoO0o - I1IiiI - Ii1I - II111iiii
  iioOO = struct . unpack ( oOoOo000 , packet [ : O0OOoooO ] ) [ 0 ]
  packet = packet [ O0OOoooO : : ]
  if ( iioOO != 0 ) :
   self . global_ms_rloc . afi = socket . ntohs ( iioOO )
   packet = self . global_ms_rloc . unpack_address ( packet )
   if ( packet == None ) : return ( IIiIiIii11I1 )
   self . global_ms_rloc . mask_len = self . global_ms_rloc . host_mask_len ( )
   if 81 - 81: i1IIi * I1ii11iIi11i + IiII - OoO0O00 * i1IIi
   if 6 - 6: iIii1I11I1II1 % OoOoOO00 % II111iiii % o0oOOo0O0Ooo
   if 52 - 52: Ii1I - I1IiiI * iIii1I11I1II1 % Oo0Ooo * OOooOOo
   if 67 - 67: OoooooooOO * I11i * Ii1I * iIii1I11I1II1
   if 22 - 22: OoO0O00 / o0oOOo0O0Ooo
  if ( len ( packet ) < O0OOoooO ) : return ( IIiIiIii11I1 )
  if 35 - 35: I1Ii111 / I1Ii111 + o0oOOo0O0Ooo - oO0o
  iioOO = struct . unpack ( oOoOo000 , packet [ : O0OOoooO ] ) [ 0 ]
  packet = packet [ O0OOoooO : : ]
  if ( iioOO != 0 ) :
   self . private_etr_rloc . afi = socket . ntohs ( iioOO )
   packet = self . private_etr_rloc . unpack_address ( packet )
   if ( packet == None ) : return ( IIiIiIii11I1 )
   self . private_etr_rloc . mask_len = self . private_etr_rloc . host_mask_len ( )
   if 40 - 40: OoOoOO00 - II111iiii
   if 29 - 29: I1IiiI - O0
   if 36 - 36: I1IiiI * I1IiiI
   if 79 - 79: I1Ii111 - I11i
   if 49 - 49: II111iiii + O0 * ooOoO0o - Oo0Ooo
   if 89 - 89: I1IiiI + I11i . oO0o . II111iiii + oO0o / Oo0Ooo
  while ( len ( packet ) >= O0OOoooO ) :
   iioOO = struct . unpack ( oOoOo000 , packet [ : O0OOoooO ] ) [ 0 ]
   packet = packet [ O0OOoooO : : ]
   if ( iioOO == 0 ) : continue
   oOOoOO = lisp_address ( socket . ntohs ( iioOO ) , "" , 0 , 0 )
   packet = oOOoOO . unpack_address ( packet )
   if ( packet == None ) : return ( IIiIiIii11I1 )
   oOOoOO . mask_len = oOOoOO . host_mask_len ( )
   self . rtr_list . append ( oOOoOO )
   if 32 - 32: OoO0O00 % oO0o * I1ii11iIi11i + I11i / I1Ii111
  return ( IIiIiIii11I1 )
  if 5 - 5: o0oOOo0O0Ooo + iII111i / OoooooooOO + Ii1I . OoOoOO00 / oO0o
  if 18 - 18: II111iiii . o0oOOo0O0Ooo
  if 75 - 75: OoooooooOO - Oo0Ooo
class lisp_nat_info ( ) :
 def __init__ ( self , addr_str , hostname , port ) :
  self . address = addr_str
  self . hostname = hostname
  self . port = port
  self . uptime = lisp_get_timestamp ( )
  if 56 - 56: II111iiii - i11iIiiIii - oO0o . o0oOOo0O0Ooo
  if 4 - 4: i1IIi
 def timed_out ( self ) :
  i11IiIIi11I = time . time ( ) - self . uptime
  return ( i11IiIIi11I >= ( LISP_INFO_INTERVAL * 2 ) )
  if 91 - 91: IiII . OoO0O00 * Ii1I / o0oOOo0O0Ooo
  if 41 - 41: I1IiiI . OoO0O00 / i1IIi . Oo0Ooo . oO0o
  if 44 - 44: iII111i * I11i + i11iIiiIii + i1IIi / IiII * II111iiii
class lisp_info_source ( ) :
 def __init__ ( self , hostname , addr_str , port ) :
  self . address = lisp_address ( LISP_AFI_IPV4 , addr_str , 32 , 0 )
  self . port = port
  self . uptime = lisp_get_timestamp ( )
  self . nonce = None
  self . hostname = hostname
  self . no_timeout = False
  if 58 - 58: OOooOOo
  if 72 - 72: OoO0O00 + OOooOOo - Oo0Ooo % ooOoO0o . IiII
 def cache_address_for_info_source ( self ) :
  iii11 = self . address . print_address_no_iid ( ) + self . hostname
  lisp_info_sources_by_address [ iii11 ] = self
  if 95 - 95: iII111i % OOooOOo - IiII - OoOoOO00 % o0oOOo0O0Ooo * O0
  if 16 - 16: I1Ii111 / Oo0Ooo
 def cache_nonce_for_info_source ( self , nonce ) :
  self . nonce = nonce
  lisp_info_sources_by_nonce [ nonce ] = self
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
def lisp_concat_auth_data ( alg_id , auth1 , auth2 , auth3 , auth4 ) :
 if 97 - 97: Ii1I . Ii1I % iII111i
 if ( lisp_is_x86 ( ) ) :
  if ( auth1 != "" ) : auth1 = byte_swap_64 ( auth1 )
  if ( auth2 != "" ) : auth2 = byte_swap_64 ( auth2 )
  if ( auth3 != "" ) :
   if ( alg_id == LISP_SHA_1_96_ALG_ID ) : auth3 = socket . ntohl ( auth3 )
   else : auth3 = byte_swap_64 ( auth3 )
   if 49 - 49: Oo0Ooo % OOooOOo - OoooooooOO + IiII
  if ( auth4 != "" ) : auth4 = byte_swap_64 ( auth4 )
  if 54 - 54: iIii1I11I1II1 - OoooooooOO / I11i / oO0o % I1IiiI + OoOoOO00
  if 26 - 26: OoO0O00 * II111iiii % OOooOOo * iII111i + iII111i
 if ( alg_id == LISP_SHA_1_96_ALG_ID ) :
  auth1 = lisp_hex_string ( auth1 )
  auth1 = auth1 . zfill ( 16 )
  auth2 = lisp_hex_string ( auth2 )
  auth2 = auth2 . zfill ( 16 )
  auth3 = lisp_hex_string ( auth3 )
  auth3 = auth3 . zfill ( 8 )
  OOO00Oo00o = auth1 + auth2 + auth3
  if 25 - 25: I11i - I1ii11iIi11i
 if ( alg_id == LISP_SHA_256_128_ALG_ID ) :
  auth1 = lisp_hex_string ( auth1 )
  auth1 = auth1 . zfill ( 16 )
  auth2 = lisp_hex_string ( auth2 )
  auth2 = auth2 . zfill ( 16 )
  auth3 = lisp_hex_string ( auth3 )
  auth3 = auth3 . zfill ( 16 )
  auth4 = lisp_hex_string ( auth4 )
  auth4 = auth4 . zfill ( 16 )
  OOO00Oo00o = auth1 + auth2 + auth3 + auth4
  if 100 - 100: I1Ii111 / Ii1I + OoOoOO00 . OoooooooOO
 return ( OOO00Oo00o )
 if 83 - 83: O0
 if 35 - 35: i11iIiiIii - I11i . OoOoOO00 * II111iiii % i11iIiiIii
 if 55 - 55: o0oOOo0O0Ooo / O0 / OoooooooOO * Oo0Ooo % iII111i
 if 24 - 24: I1ii11iIi11i % OOooOOo + OoooooooOO + OoO0O00
 if 100 - 100: Oo0Ooo % OoO0O00 - OoOoOO00
 if 46 - 46: o0oOOo0O0Ooo
 if 28 - 28: i1IIi
 if 81 - 81: oO0o % OoooooooOO . I1Ii111 - OoOoOO00 / I1IiiI
 if 62 - 62: I1Ii111 * I11i / I11i
 if 42 - 42: ooOoO0o * ooOoO0o / Ii1I / OOooOOo * OOooOOo
def lisp_open_listen_socket ( local_addr , port ) :
 if ( port . isdigit ( ) ) :
  if ( local_addr . find ( "." ) != - 1 ) :
   OOO0oO0O00o0000 = socket . socket ( socket . AF_INET , socket . SOCK_DGRAM )
   if 80 - 80: o0oOOo0O0Ooo
  if ( local_addr . find ( ":" ) != - 1 ) :
   if ( lisp_is_raspbian ( ) ) : return ( None )
   OOO0oO0O00o0000 = socket . socket ( socket . AF_INET6 , socket . SOCK_DGRAM )
   if 77 - 77: iIii1I11I1II1 * OOooOOo % ooOoO0o
  OOO0oO0O00o0000 . bind ( ( local_addr , int ( port ) ) )
 else :
  IiIII = port
  if ( os . path . exists ( IiIII ) ) :
   os . system ( "rm " + IiIII )
   time . sleep ( 1 )
   if 80 - 80: II111iiii
  OOO0oO0O00o0000 = socket . socket ( socket . AF_UNIX , socket . SOCK_DGRAM )
  OOO0oO0O00o0000 . bind ( IiIII )
  if 66 - 66: Oo0Ooo . I1Ii111
 return ( OOO0oO0O00o0000 )
 if 59 - 59: iII111i - I1IiiI . I1IiiI - Ii1I * OoOoOO00
 if 27 - 27: Oo0Ooo + Oo0Ooo / II111iiii % I1Ii111
 if 11 - 11: Ii1I
 if 54 - 54: I1IiiI * I1Ii111 / ooOoO0o / iIii1I11I1II1 % iII111i / oO0o
 if 11 - 11: ooOoO0o + I1IiiI + Ii1I . II111iiii
 if 50 - 50: Oo0Ooo
 if 14 - 14: O0
def lisp_open_send_socket ( internal_name , afi ) :
 if ( internal_name == "" ) :
  if ( afi == LISP_AFI_IPV4 ) :
   OOO0oO0O00o0000 = socket . socket ( socket . AF_INET , socket . SOCK_DGRAM )
   if 67 - 67: II111iiii / O0
  if ( afi == LISP_AFI_IPV6 ) :
   if ( lisp_is_raspbian ( ) ) : return ( None )
   OOO0oO0O00o0000 = socket . socket ( socket . AF_INET6 , socket . SOCK_DGRAM )
   if 10 - 10: i1IIi / Oo0Ooo
 else :
  if ( os . path . exists ( internal_name ) ) : os . system ( "rm " + internal_name )
  OOO0oO0O00o0000 = socket . socket ( socket . AF_UNIX , socket . SOCK_DGRAM )
  OOO0oO0O00o0000 . bind ( internal_name )
  if 20 - 20: Oo0Ooo * I1Ii111 / I1ii11iIi11i . ooOoO0o
 return ( OOO0oO0O00o0000 )
 if 67 - 67: o0oOOo0O0Ooo . Oo0Ooo % I11i
 if 38 - 38: OOooOOo - OoO0O00 . ooOoO0o
 if 50 - 50: o0oOOo0O0Ooo
 if 85 - 85: II111iiii . iII111i - i1IIi
 if 23 - 23: iII111i . Ii1I - OoO0O00 / I1ii11iIi11i / O0
 if 4 - 4: i1IIi % Oo0Ooo % Ii1I * ooOoO0o - I11i
 if 76 - 76: iIii1I11I1II1 / ooOoO0o % I1ii11iIi11i % OOooOOo
def lisp_close_socket ( sock , internal_name ) :
 sock . close ( )
 if ( os . path . exists ( internal_name ) ) : os . system ( "rm " + internal_name )
 return
 if 13 - 13: IiII
 if 56 - 56: Oo0Ooo
 if 55 - 55: i11iIiiIii + iIii1I11I1II1 / i1IIi / I1ii11iIi11i
 if 64 - 64: IiII . OoO0O00 * i11iIiiIii
 if 18 - 18: Ii1I % o0oOOo0O0Ooo - Oo0Ooo
 if 28 - 28: IiII
 if 93 - 93: Oo0Ooo % i1IIi
 if 51 - 51: oO0o % O0
def lisp_is_running ( node ) :
 return ( True if ( os . path . exists ( node ) ) else False )
 if 41 - 41: I1IiiI * I1IiiI . I1Ii111
 if 38 - 38: I1IiiI % i11iIiiIii
 if 17 - 17: i11iIiiIii
 if 81 - 81: I1Ii111
 if 25 - 25: I1IiiI
 if 52 - 52: I1ii11iIi11i % i1IIi . IiII % OoOoOO00
 if 50 - 50: OOooOOo * I1IiiI / o0oOOo0O0Ooo
 if 91 - 91: iIii1I11I1II1 / OOooOOo * O0 . o0oOOo0O0Ooo + oO0o / I1ii11iIi11i
 if 33 - 33: II111iiii + Ii1I
def lisp_packet_ipc ( packet , source , sport ) :
 return ( ( "packet@" + str ( len ( packet ) ) + "@" + source + "@" + str ( sport ) + "@" + packet ) )
 if 46 - 46: IiII + O0 + i1IIi + ooOoO0o / iII111i
 if 94 - 94: oO0o + iII111i * OoOoOO00 - i1IIi / OoooooooOO
 if 59 - 59: I11i % Ii1I / OoOoOO00
 if 99 - 99: Ii1I + II111iiii / i11iIiiIii - IiII / iII111i + iII111i
 if 55 - 55: IiII + OoooooooOO * I1ii11iIi11i . IiII * I1ii11iIi11i + IiII
 if 81 - 81: iIii1I11I1II1 . ooOoO0o + OoOoOO00
 if 31 - 31: I11i / OoOoOO00 + o0oOOo0O0Ooo
 if 80 - 80: Oo0Ooo
 if 58 - 58: I1Ii111 + OOooOOo
def lisp_control_packet_ipc ( packet , source , dest , dport ) :
 return ( "control-packet@" + dest + "@" + str ( dport ) + "@" + packet )
 if 76 - 76: II111iiii - o0oOOo0O0Ooo % OoO0O00 + iII111i
 if 38 - 38: I1Ii111 - I11i * i1IIi + iIii1I11I1II1
 if 41 - 41: Ii1I . OoO0O00 + I1ii11iIi11i + OoOoOO00
 if 76 - 76: iII111i - iIii1I11I1II1
 if 23 - 23: I11i / OoO0O00 % OOooOOo
 if 9 - 9: ooOoO0o % I1ii11iIi11i . OoooooooOO + OoO0O00 % OOooOOo * OoooooooOO
 if 21 - 21: Ii1I % O0
def lisp_data_packet_ipc ( packet , source ) :
 return ( "data-packet@" + str ( len ( packet ) ) + "@" + source + "@@" + packet )
 if 15 - 15: II111iiii * Ii1I + IiII % iII111i
 if 96 - 96: II111iiii * I1Ii111 / Oo0Ooo
 if 35 - 35: I1IiiI
 if 54 - 54: I1ii11iIi11i % o0oOOo0O0Ooo . i1IIi
 if 72 - 72: Ii1I
 if 87 - 87: iII111i - I1IiiI
 if 54 - 54: iIii1I11I1II1 + oO0o * o0oOOo0O0Ooo % OoooooooOO . Oo0Ooo
 if 32 - 32: iII111i
 if 33 - 33: ooOoO0o + Oo0Ooo * OoOoOO00 % ooOoO0o * oO0o - OoO0O00
def lisp_command_ipc ( packet , source ) :
 return ( "command@" + str ( len ( packet ) ) + "@" + source + "@@" + packet )
 if 40 - 40: I11i . OoooooooOO * O0 / I1Ii111 + O0
 if 97 - 97: ooOoO0o - ooOoO0o * OOooOOo % OoOoOO00 - OoOoOO00 - I1Ii111
 if 52 - 52: O0 % iII111i
 if 81 - 81: OoooooooOO % OoOoOO00 % Oo0Ooo - I1IiiI
 if 43 - 43: o0oOOo0O0Ooo % o0oOOo0O0Ooo
 if 48 - 48: O0
 if 5 - 5: OOooOOo / i11iIiiIii . I11i % OOooOOo
 if 1 - 1: II111iiii + O0 * OoOoOO00 / IiII . O0
 if 87 - 87: IiII + I1IiiI
def lisp_api_ipc ( source , data ) :
 return ( "api@" + str ( len ( data ) ) + "@" + source + "@@" + data )
 if 74 - 74: OoO0O00 + OoO0O00 % iII111i / I11i / O0
 if 54 - 54: o0oOOo0O0Ooo / OoooooooOO * ooOoO0o . OoOoOO00 - I1Ii111
 if 69 - 69: oO0o - OoO0O00
 if 80 - 80: ooOoO0o + iIii1I11I1II1 . II111iiii + I1IiiI - oO0o % OoOoOO00
 if 10 - 10: iIii1I11I1II1
 if 44 - 44: OoOoOO00 * oO0o . I1ii11iIi11i + i11iIiiIii
 if 85 - 85: I11i
 if 36 - 36: ooOoO0o % OoO0O00
 if 1 - 1: OoooooooOO - OoOoOO00
def lisp_ipc ( packet , send_socket , node ) :
 if 35 - 35: I1Ii111
 if 35 - 35: Oo0Ooo - iIii1I11I1II1 / i1IIi + OoO0O00 - OoooooooOO / i11iIiiIii
 if 79 - 79: I1IiiI * ooOoO0o * ooOoO0o
 if 92 - 92: iII111i % I1ii11iIi11i
 if ( lisp_is_running ( node ) == False ) :
  lprint ( "Suppress sending IPC to {}" . format ( node ) )
  return
  if 16 - 16: oO0o
  if 52 - 52: OoooooooOO % ooOoO0o - I1Ii111 * I11i
 I1I1iii = 1500 if ( packet . find ( "control-packet" ) == - 1 ) else 9000
 if 63 - 63: IiII / OoooooooOO - ooOoO0o
 I11iiIi1i1 = 0
 o00OOo00 = len ( packet )
 iI1i11OO0o0OOoO = 0
 O0Ooo0OOo = .001
 while ( o00OOo00 > 0 ) :
  o00ooooOOo = min ( o00OOo00 , I1I1iii )
  O0000 = packet [ I11iiIi1i1 : o00ooooOOo + I11iiIi1i1 ]
  if 15 - 15: iIii1I11I1II1 * OoOoOO00
  try :
   send_socket . sendto ( O0000 , node )
   lprint ( "Send IPC {}-out-of-{} byte to {} succeeded" . format ( len ( O0000 ) , len ( packet ) , node ) )
   if 82 - 82: II111iiii * I1IiiI * I1ii11iIi11i
   iI1i11OO0o0OOoO = 0
   O0Ooo0OOo = .001
   if 79 - 79: o0oOOo0O0Ooo - oO0o . ooOoO0o / ooOoO0o - iII111i / OoooooooOO
  except socket . error , ooo0OO :
   if ( iI1i11OO0o0OOoO == 12 ) :
    lprint ( "Giving up on {}, consider it down" . format ( node ) )
    break
    if 58 - 58: ooOoO0o * I1IiiI - OoO0O00 + OOooOOo
    if 79 - 79: Oo0Ooo . i11iIiiIii * OoO0O00 / I11i * OoOoOO00
   lprint ( "Send IPC {}-out-of-{} byte to {} failed: {}" . format ( len ( O0000 ) , len ( packet ) , node , ooo0OO ) )
   if 78 - 78: I11i . I1ii11iIi11i . I1ii11iIi11i
   if 71 - 71: iII111i + IiII + I1IiiI - OoOoOO00
   iI1i11OO0o0OOoO += 1
   time . sleep ( O0Ooo0OOo )
   if 49 - 49: I1IiiI % O0 - OoooooooOO * OoO0O00 / iIii1I11I1II1 + I11i
   lprint ( "Retrying after {} ms ..." . format ( O0Ooo0OOo * 1000 ) )
   O0Ooo0OOo *= 2
   continue
   if 7 - 7: iII111i * I1ii11iIi11i / oO0o
   if 31 - 31: I1ii11iIi11i - II111iiii
  I11iiIi1i1 += o00ooooOOo
  o00OOo00 -= o00ooooOOo
  if 86 - 86: IiII % OOooOOo % OoOoOO00 / I1IiiI % OoooooooOO
 return
 if 83 - 83: i1IIi . OoOoOO00 . i1IIi / OOooOOo * O0
 if 99 - 99: OoooooooOO . OoOoOO00 / II111iiii
 if 64 - 64: iII111i / i1IIi . I1IiiI + O0
 if 5 - 5: O0 . i11iIiiIii
 if 71 - 71: o0oOOo0O0Ooo + iII111i + ooOoO0o
 if 27 - 27: OoooooooOO . iII111i * I1Ii111 % O0 + OoooooooOO - iII111i
 if 86 - 86: i1IIi
def lisp_format_packet ( packet ) :
 packet = binascii . hexlify ( packet )
 I11iiIi1i1 = 0
 IIi1i1iI11I11 = ""
 o00OOo00 = len ( packet ) * 2
 while ( I11iiIi1i1 < o00OOo00 ) :
  IIi1i1iI11I11 += packet [ I11iiIi1i1 : I11iiIi1i1 + 8 ] + " "
  I11iiIi1i1 += 8
  o00OOo00 -= 4
  if 81 - 81: OoOoOO00
 return ( IIi1i1iI11I11 )
 if 52 - 52: iII111i * IiII % I1IiiI * I11i
 if 73 - 73: I1Ii111 * ooOoO0o
 if 62 - 62: OOooOOo . I1IiiI * iIii1I11I1II1 + OoO0O00 * ooOoO0o / oO0o
 if 14 - 14: iII111i / OoO0O00
 if 75 - 75: IiII
 if 68 - 68: IiII - i1IIi % IiII . OoO0O00 . i11iIiiIii . OoooooooOO
 if 32 - 32: iII111i + OoO0O00 % IiII + I1IiiI
def lisp_send ( lisp_sockets , dest , port , packet ) :
 O0O0Ooo = lisp_sockets [ 0 ] if dest . is_ipv4 ( ) else lisp_sockets [ 1 ]
 if 29 - 29: iII111i % I1ii11iIi11i % o0oOOo0O0Ooo + O0 - I1ii11iIi11i
 if 4 - 4: OOooOOo * i1IIi + OoO0O00 - I11i - I11i
 if 9 - 9: OoO0O00 + ooOoO0o - OOooOOo - ooOoO0o + Ii1I
 if 54 - 54: OoOoOO00
 if 53 - 53: I1Ii111
 if 72 - 72: i11iIiiIii
 if 64 - 64: I1Ii111 % OoooooooOO / i1IIi / OoO0O00
 if 2 - 2: I11i % o0oOOo0O0Ooo . OoO0O00 . OoO0O00
 if 89 - 89: ooOoO0o - oO0o + II111iiii + OoO0O00 - IiII
 if 27 - 27: I1Ii111 - o0oOOo0O0Ooo + OoO0O00
 if 38 - 38: OoOoOO00 + OoO0O00 . i11iIiiIii + Ii1I % i1IIi % I1IiiI
 if 93 - 93: i11iIiiIii
 oOoO0Oo0 = dest . print_address_no_iid ( )
 if ( oOoO0Oo0 . find ( "::ffff:" ) != - 1 and oOoO0Oo0 . count ( "." ) == 3 ) :
  if ( lisp_i_am_rtr ) : O0O0Ooo = lisp_sockets [ 0 ]
  if ( O0O0Ooo == None ) :
   O0O0Ooo = lisp_sockets [ 0 ]
   oOoO0Oo0 = oOoO0Oo0 . split ( "::ffff:" ) [ - 1 ]
   if 63 - 63: iIii1I11I1II1 - iIii1I11I1II1 % o0oOOo0O0Ooo
   if 97 - 97: i1IIi % I11i % OoOoOO00
   if 25 - 25: OoOoOO00 . iIii1I11I1II1 - iII111i % II111iiii . OoOoOO00
 lprint ( "{} {} bytes {} {}, packet: {}" . format ( bold ( "Send" , False ) ,
 len ( packet ) , bold ( "to " + oOoO0Oo0 , False ) , port ,
 lisp_format_packet ( packet ) ) )
 if 16 - 16: OOooOOo . Oo0Ooo . I1IiiI % O0 . I1ii11iIi11i + i11iIiiIii
 if 100 - 100: I1ii11iIi11i - i1IIi - OoO0O00 * o0oOOo0O0Ooo + OoOoOO00
 if 31 - 31: i1IIi
 if 21 - 21: o0oOOo0O0Ooo / O0 % O0 . OoooooooOO / I1IiiI
 O0oOO0O = ( LISP_RLOC_PROBE_TTL == 255 )
 if ( O0oOO0O ) :
  oOOooO = struct . unpack ( "B" , packet [ 0 ] ) [ 0 ]
  O0oOO0O = ( oOOooO in [ 0x12 , 0x28 ] )
  if ( O0oOO0O ) : lisp_set_ttl ( O0O0Ooo , LISP_RLOC_PROBE_TTL )
  if 38 - 38: OoooooooOO
  if 78 - 78: OoooooooOO . iIii1I11I1II1 / II111iiii * Oo0Ooo
 try : O0O0Ooo . sendto ( packet , ( oOoO0Oo0 , port ) )
 except socket . error , ooo0OO :
  lprint ( "socket.sendto() failed: {}" . format ( ooo0OO ) )
  if 75 - 75: ooOoO0o * O0 / Oo0Ooo
  if 57 - 57: II111iiii
  if 93 - 93: IiII . i11iIiiIii * OoO0O00 . o0oOOo0O0Ooo . OoooooooOO . I1ii11iIi11i
  if 49 - 49: OoOoOO00 % I1ii11iIi11i - OoooooooOO + O0
  if 15 - 15: I1ii11iIi11i / IiII % I1IiiI
 if ( O0oOO0O ) : lisp_set_ttl ( O0O0Ooo , 64 )
 return
 if 16 - 16: Ii1I
 if 26 - 26: o0oOOo0O0Ooo / I11i + OoOoOO00 / OoOoOO00
 if 31 - 31: I1Ii111
 if 84 - 84: i11iIiiIii * OOooOOo . iII111i - Ii1I * i1IIi - I1ii11iIi11i
 if 1 - 1: II111iiii
 if 94 - 94: I1ii11iIi11i * iII111i % iII111i % I11i - iII111i
 if 38 - 38: IiII - OoO0O00 % Ii1I - II111iiii
 if 97 - 97: O0 . Ii1I
def lisp_receive_segments ( lisp_socket , packet , source , total_length ) :
 if 52 - 52: IiII
 if 86 - 86: I1Ii111 / O0 + OoooooooOO % oO0o
 if 45 - 45: I1IiiI . Oo0Ooo . I11i . Ii1I
 if 81 - 81: II111iiii + OoOoOO00 % i11iIiiIii / iII111i . I1Ii111 + II111iiii
 if 48 - 48: I1IiiI . I1ii11iIi11i * OoOoOO00 % i1IIi / I1Ii111 * II111iiii
 o00ooooOOo = total_length - len ( packet )
 if ( o00ooooOOo == 0 ) : return ( [ True , packet ] )
 if 62 - 62: o0oOOo0O0Ooo * I1Ii111 . iIii1I11I1II1 / i1IIi
 lprint ( "Received {}-out-of-{} byte segment from {}" . format ( len ( packet ) ,
 total_length , source ) )
 if 75 - 75: OoooooooOO / ooOoO0o - iII111i . OoooooooOO . OoOoOO00 % i1IIi
 if 7 - 7: OoOoOO00 . i1IIi * i11iIiiIii % i11iIiiIii
 if 54 - 54: OoO0O00 / I1IiiI . Oo0Ooo
 if 39 - 39: OoO0O00 . ooOoO0o
 if 41 - 41: Oo0Ooo * I1ii11iIi11i - II111iiii - II111iiii
 o00OOo00 = o00ooooOOo
 while ( o00OOo00 > 0 ) :
  try : O0000 = lisp_socket . recvfrom ( 9000 )
  except : return ( [ False , None ] )
  if 7 - 7: oO0o
  O0000 = O0000 [ 0 ]
  if 41 - 41: ooOoO0o
  if 93 - 93: Ii1I + I1Ii111 + Ii1I
  if 23 - 23: I1IiiI - i1IIi / ooOoO0o
  if 4 - 4: IiII . I1ii11iIi11i + iII111i % ooOoO0o
  if 28 - 28: I1Ii111
  if ( O0000 . find ( "packet@" ) == 0 ) :
   i1IIIiiIiII1I = O0000 . split ( "@" )
   lprint ( "Received new message ({}-out-of-{}) while receiving " + "fragments, old message discarded" , len ( O0000 ) ,
   # ooOoO0o / OOooOOo + I11i % I1Ii111 + Ii1I * I1IiiI
 i1IIIiiIiII1I [ 1 ] if len ( i1IIIiiIiII1I ) > 2 else "?" )
   return ( [ False , O0000 ] )
   if 70 - 70: oO0o / i1IIi * iIii1I11I1II1 + I11i
   if 48 - 48: ooOoO0o / I1ii11iIi11i / OoO0O00 / II111iiii * OoOoOO00
  o00OOo00 -= len ( O0000 )
  packet += O0000
  if 73 - 73: I11i / I1IiiI - IiII - i1IIi * IiII - OOooOOo
  lprint ( "Received {}-out-of-{} byte segment from {}" . format ( len ( O0000 ) , total_length , source ) )
  if 39 - 39: I11i . ooOoO0o * II111iiii
  if 21 - 21: Ii1I
 return ( [ True , packet ] )
 if 92 - 92: OoO0O00 * I1ii11iIi11i + iIii1I11I1II1
 if 88 - 88: iIii1I11I1II1 + iIii1I11I1II1 * i11iIiiIii . I1ii11iIi11i % oO0o
 if 94 - 94: I1IiiI / I1ii11iIi11i / OOooOOo
 if 45 - 45: II111iiii
 if 98 - 98: i11iIiiIii + I1ii11iIi11i * OOooOOo / OoOoOO00
 if 84 - 84: o0oOOo0O0Ooo
 if 40 - 40: OoooooooOO - oO0o / O0 * I1Ii111 . O0 + i11iIiiIii
 if 9 - 9: OOooOOo % O0 % O0 / I1ii11iIi11i . II111iiii / II111iiii
def lisp_bit_stuff ( payload ) :
 lprint ( "Bit-stuffing, found {} segments" . format ( len ( payload ) ) )
 i1II1IiiIi = ""
 for O0000 in payload : i1II1IiiIi += O0000 + "\x40"
 return ( i1II1IiiIi [ : - 1 ] )
 if 78 - 78: iIii1I11I1II1 - i1IIi . I11i . o0oOOo0O0Ooo
 if 66 - 66: OOooOOo * Oo0Ooo
 if 58 - 58: OOooOOo
 if 96 - 96: IiII % OoooooooOO + O0 * II111iiii / OOooOOo . I1Ii111
 if 47 - 47: OoO0O00 - Oo0Ooo * OoO0O00 / oO0o
 if 13 - 13: ooOoO0o
 if 55 - 55: i1IIi . I11i . II111iiii + O0 + ooOoO0o - i1IIi
 if 3 - 3: iIii1I11I1II1 / oO0o
 if 61 - 61: I1Ii111 / O0 - iII111i
 if 44 - 44: i1IIi
 if 23 - 23: I1ii11iIi11i . OoooooooOO / Ii1I + o0oOOo0O0Ooo
 if 89 - 89: OoOoOO00 + Oo0Ooo . OoOoOO00 - II111iiii
 if 85 - 85: OoooooooOO * OoooooooOO / Ii1I - II111iiii
 if 69 - 69: iII111i * I11i
 if 43 - 43: o0oOOo0O0Ooo - IiII * Ii1I . i11iIiiIii / II111iiii
 if 61 - 61: OoOoOO00 / I1IiiI . I1ii11iIi11i % OOooOOo
 if 70 - 70: OOooOOo * OoOoOO00 / oO0o + Oo0Ooo / O0
 if 16 - 16: Oo0Ooo / OoooooooOO / IiII + Oo0Ooo * i11iIiiIii
 if 15 - 15: o0oOOo0O0Ooo / i11iIiiIii
 if 63 - 63: I1ii11iIi11i - Ii1I + I11i
def lisp_receive ( lisp_socket , internal ) :
 while ( True ) :
  if 98 - 98: iII111i / IiII * I1IiiI / oO0o - iIii1I11I1II1
  if 72 - 72: O0 . OOooOOo
  if 99 - 99: i1IIi + iIii1I11I1II1 - ooOoO0o + OoO0O00 + Oo0Ooo . I1ii11iIi11i
  if 74 - 74: i1IIi
  try : O0o00O = lisp_socket . recvfrom ( 9000 )
  except : return ( [ "" , "" , "" , "" ] )
  if 17 - 17: iIii1I11I1II1 - OoOoOO00
  if 97 - 97: iIii1I11I1II1 / OOooOOo * i1IIi - OoO0O00 / ooOoO0o % Ii1I
  if 30 - 30: OoOoOO00 / oO0o . iII111i
  if 56 - 56: OoOoOO00
  if 83 - 83: OOooOOo
  if 17 - 17: IiII + I1IiiI - I11i . I1IiiI
  if ( internal == False ) :
   i1II1IiiIi = O0o00O [ 0 ]
   II1i1iI = lisp_convert_6to4 ( O0o00O [ 1 ] [ 0 ] )
   IIiII = O0o00O [ 1 ] [ 1 ]
   if 34 - 34: ooOoO0o . i11iIiiIii * I1IiiI . II111iiii - iIii1I11I1II1
   if ( IIiII == LISP_DATA_PORT ) :
    iiI1iii1Ii = lisp_data_plane_logging
    O0OoO0O00o = lisp_format_packet ( i1II1IiiIi [ 0 : 60 ] ) + " ..."
   else :
    iiI1iii1Ii = True
    O0OoO0O00o = lisp_format_packet ( i1II1IiiIi )
    if 96 - 96: oO0o
    if 88 - 88: OoO0O00 / OoO0O00 * I1ii11iIi11i + I1IiiI % i1IIi
   if ( iiI1iii1Ii ) :
    lprint ( "{} {} bytes {} {}, packet: {}" . format ( bold ( "Receive" ,
 False ) , len ( i1II1IiiIi ) , bold ( "from " + II1i1iI , False ) , IIiII ,
 O0OoO0O00o ) )
    if 86 - 86: II111iiii / I1Ii111
   return ( [ "packet" , II1i1iI , IIiII , i1II1IiiIi ] )
   if 39 - 39: OoOoOO00 / o0oOOo0O0Ooo . II111iiii
   if 74 - 74: I11i . OoO0O00 . I1Ii111 . iII111i
   if 17 - 17: iIii1I11I1II1
   if 10 - 10: i11iIiiIii / iII111i - oO0o
   if 98 - 98: Ii1I % iII111i . I11i
   if 38 - 38: iIii1I11I1II1 % I1ii11iIi11i % o0oOOo0O0Ooo . ooOoO0o - oO0o
  o000o0oO0oO0o = False
  IIII1iI1iiI = O0o00O [ 0 ]
  Oo00O0OoooO = False
  if 54 - 54: i1IIi
  while ( o000o0oO0oO0o == False ) :
   IIII1iI1iiI = IIII1iI1iiI . split ( "@" )
   if 26 - 26: o0oOOo0O0Ooo % i11iIiiIii % OoOoOO00 % OoO0O00 * iII111i % I1IiiI
   if ( len ( IIII1iI1iiI ) < 4 ) :
    lprint ( "Possible fragment (length {}), from old message, " + "discarding" , len ( IIII1iI1iiI [ 0 ] ) )
    if 91 - 91: i1IIi * ooOoO0o
    Oo00O0OoooO = True
    break
    if 33 - 33: I11i / OoooooooOO - Ii1I / OoO0O00 - OoO0O00
    if 60 - 60: OOooOOo . ooOoO0o % i1IIi % Ii1I % ooOoO0o + OoO0O00
   IiII111I1i = IIII1iI1iiI [ 0 ]
   try :
    O0o0o0OOo = int ( IIII1iI1iiI [ 1 ] )
   except :
    o0oOOOO = bold ( "Internal packet reassembly error" , False )
    lprint ( "{}: {}" . format ( o0oOOOO , O0o00O ) )
    Oo00O0OoooO = True
    break
    if 23 - 23: II111iiii * I11i * I11i % Ii1I - OoOoOO00
   II1i1iI = IIII1iI1iiI [ 2 ]
   IIiII = IIII1iI1iiI [ 3 ]
   if 89 - 89: iIii1I11I1II1 . I1IiiI * i11iIiiIii + iII111i % OOooOOo / I11i
   if 89 - 89: iIii1I11I1II1 * oO0o + IiII * o0oOOo0O0Ooo - iIii1I11I1II1
   if 78 - 78: I1ii11iIi11i / Oo0Ooo
   if 25 - 25: i11iIiiIii * i1IIi . oO0o - iII111i * I1Ii111
   if 66 - 66: OoOoOO00 / I1Ii111
   if 66 - 66: iIii1I11I1II1 / OoOoOO00 * iII111i - iIii1I11I1II1 % I1Ii111 - II111iiii
   if 24 - 24: ooOoO0o % Oo0Ooo . I11i * I1ii11iIi11i / I1Ii111
   if 21 - 21: oO0o / I1ii11iIi11i % iII111i . I11i
   if ( len ( IIII1iI1iiI ) > 5 ) :
    i1II1IiiIi = lisp_bit_stuff ( IIII1iI1iiI [ 4 : : ] )
   else :
    i1II1IiiIi = IIII1iI1iiI [ 4 ]
    if 58 - 58: I1IiiI - i1IIi - OOooOOo
    if 33 - 33: O0 % I1IiiI + ooOoO0o % OOooOOo
    if 49 - 49: ooOoO0o / O0 - OoOoOO00 % O0 * oO0o * OoooooooOO
    if 66 - 66: o0oOOo0O0Ooo . I1ii11iIi11i / OoooooooOO . I11i
    if 33 - 33: I1Ii111
    if 41 - 41: ooOoO0o + Ii1I / i1IIi % Ii1I
   o000o0oO0oO0o , i1II1IiiIi = lisp_receive_segments ( lisp_socket , i1II1IiiIi ,
 II1i1iI , O0o0o0OOo )
   if ( i1II1IiiIi == None ) : return ( [ "" , "" , "" , "" ] )
   if 97 - 97: Oo0Ooo % OoOoOO00 / OOooOOo / iIii1I11I1II1 / OoooooooOO - I1ii11iIi11i
   if 6 - 6: iIii1I11I1II1
   if 27 - 27: Ii1I / i11iIiiIii / i1IIi
   if 36 - 36: ooOoO0o % ooOoO0o . i11iIiiIii
   if 42 - 42: OoO0O00 . I1Ii111 / Ii1I
   if ( o000o0oO0oO0o == False ) :
    IIII1iI1iiI = i1II1IiiIi
    continue
    if 57 - 57: iIii1I11I1II1 % I1ii11iIi11i . OOooOOo / oO0o . OoOoOO00
    if 74 - 74: I1IiiI * OoO0O00 + OoooooooOO * ooOoO0o . oO0o
   if ( IIiII == "" ) : IIiII = "no-port"
   if ( IiII111I1i == "command" and lisp_i_am_core == False ) :
    iI11I = i1II1IiiIi . find ( " {" )
    OoO0oo = i1II1IiiIi if iI11I == - 1 else i1II1IiiIi [ : iI11I ]
    OoO0oo = ": '" + OoO0oo + "'"
   else :
    OoO0oo = ""
    if 26 - 26: I1IiiI % iIii1I11I1II1 / OoO0O00
    if 71 - 71: OoOoOO00 + iII111i - I1IiiI
   lprint ( "{} {} bytes {} {}, {}{}" . format ( bold ( "Receive" , False ) ,
 len ( i1II1IiiIi ) , bold ( "from " + II1i1iI , False ) , IIiII , IiII111I1i ,
 OoO0oo if ( IiII111I1i in [ "command" , "api" ] ) else ": ... " if ( IiII111I1i == "data-packet" ) else ": " + lisp_format_packet ( i1II1IiiIi ) ) )
   if 80 - 80: OoO0O00 . ooOoO0o
   if 58 - 58: iII111i / o0oOOo0O0Ooo . iII111i % OoO0O00
   if 38 - 38: iIii1I11I1II1 % IiII * OoooooooOO - OOooOOo
   if 15 - 15: I1IiiI + iIii1I11I1II1 . i11iIiiIii % oO0o
   if 92 - 92: I11i
  if ( Oo00O0OoooO ) : continue
  return ( [ IiII111I1i , II1i1iI , IIiII , i1II1IiiIi ] )
  if 96 - 96: O0 / i1IIi - i11iIiiIii / OoOoOO00 + OoooooooOO
  if 12 - 12: oO0o . OOooOOo
  if 76 - 76: oO0o - I11i * I1Ii111 . oO0o % iIii1I11I1II1
  if 86 - 86: OoooooooOO + I1Ii111
  if 5 - 5: I1ii11iIi11i
  if 89 - 89: OoO0O00 - OoOoOO00 / II111iiii . I1ii11iIi11i
  if 50 - 50: Ii1I * I1Ii111 * OoooooooOO . OoooooooOO
  if 67 - 67: i11iIiiIii % ooOoO0o . I1ii11iIi11i + II111iiii . OoO0O00
def lisp_parse_packet ( lisp_sockets , packet , source , udp_sport , ttl = - 1 ) :
 I1iI1 = False
 if 42 - 42: OoO0O00 . II111iiii % oO0o . ooOoO0o * OoooooooOO
 iIiI1I1II1 = lisp_control_header ( )
 if ( iIiI1I1II1 . decode ( packet ) == None ) :
  lprint ( "Could not decode control header" )
  return ( I1iI1 )
  if 47 - 47: II111iiii + I1Ii111 + II111iiii
  if 45 - 45: II111iiii % OoOoOO00 / O0 % iIii1I11I1II1 + oO0o
  if 51 - 51: o0oOOo0O0Ooo * o0oOOo0O0Ooo . Ii1I
  if 14 - 14: OoO0O00 . I11i % II111iiii % i11iIiiIii + OoooooooOO
  if 50 - 50: i11iIiiIii * I11i + i11iIiiIii - i1IIi
 OoO00O = source
 if ( source . find ( "lisp" ) == - 1 ) :
  IiIIi1I1I11Ii = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  IiIIi1I1I11Ii . string_to_afi ( source )
  IiIIi1I1I11Ii . store_address ( source )
  source = IiIIi1I1I11Ii
  if 15 - 15: iIii1I11I1II1 / Ii1I / I1ii11iIi11i / Oo0Ooo
  if 99 - 99: iII111i / O0 % ooOoO0o - II111iiii - i11iIiiIii
 if ( iIiI1I1II1 . type == LISP_MAP_REQUEST ) :
  lisp_process_map_request ( lisp_sockets , packet , None , 0 , source ,
 udp_sport , False , ttl )
  if 44 - 44: i11iIiiIii . I11i - IiII + OoooooooOO . oO0o + I11i
 elif ( iIiI1I1II1 . type == LISP_MAP_REPLY ) :
  lisp_process_map_reply ( lisp_sockets , packet , source , ttl )
  if 6 - 6: i1IIi . o0oOOo0O0Ooo + OoO0O00 + OOooOOo + oO0o
 elif ( iIiI1I1II1 . type == LISP_MAP_REGISTER ) :
  lisp_process_map_register ( lisp_sockets , packet , source , udp_sport )
  if 30 - 30: O0
 elif ( iIiI1I1II1 . type == LISP_MAP_NOTIFY ) :
  if ( OoO00O == "lisp-etr" ) :
   lisp_process_multicast_map_notify ( packet , source )
  else :
   if ( lisp_is_running ( "lisp-rtr" ) ) :
    lisp_process_multicast_map_notify ( packet , source )
    if 98 - 98: I1Ii111
   lisp_process_map_notify ( lisp_sockets , packet , source )
   if 58 - 58: OOooOOo
   if 6 - 6: I1ii11iIi11i
 elif ( iIiI1I1II1 . type == LISP_MAP_NOTIFY_ACK ) :
  lisp_process_map_notify_ack ( packet , source )
  if 37 - 37: i11iIiiIii . II111iiii + OOooOOo + i1IIi * OOooOOo
 elif ( iIiI1I1II1 . type == LISP_MAP_REFERRAL ) :
  lisp_process_map_referral ( lisp_sockets , packet , source )
  if 18 - 18: ooOoO0o
 elif ( iIiI1I1II1 . type == LISP_NAT_INFO and iIiI1I1II1 . is_info_reply ( ) ) :
  II11iiii , oo0Oo0o0O , I1iI1 = lisp_process_info_reply ( source , packet , True )
  if 18 - 18: I1Ii111 + OoOoOO00 % OOooOOo - IiII - i1IIi + I1ii11iIi11i
 elif ( iIiI1I1II1 . type == LISP_NAT_INFO and iIiI1I1II1 . is_info_reply ( ) == False ) :
  I1iiIiiii1111 = source . print_address_no_iid ( )
  lisp_process_info_request ( lisp_sockets , packet , I1iiIiiii1111 , udp_sport ,
 None )
  if 33 - 33: I11i * Ii1I / Oo0Ooo + oO0o % OOooOOo % OoooooooOO
 elif ( iIiI1I1II1 . type == LISP_ECM ) :
  lisp_process_ecm ( lisp_sockets , packet , source , udp_sport )
  if 29 - 29: Ii1I . II111iiii / I1Ii111
 else :
  lprint ( "Invalid LISP control packet type {}" . format ( iIiI1I1II1 . type ) )
  if 79 - 79: IiII . OoOoOO00 / oO0o % OoO0O00 / Ii1I + I11i
 return ( I1iI1 )
 if 78 - 78: o0oOOo0O0Ooo + I1Ii111 % i11iIiiIii % I1IiiI - Ii1I
 if 81 - 81: i11iIiiIii - II111iiii + I11i
 if 52 - 52: II111iiii
 if 62 - 62: iII111i / OoO0O00 + i11iIiiIii / Oo0Ooo
 if 26 - 26: I1ii11iIi11i - OoO0O00
 if 19 - 19: iIii1I11I1II1 / I1ii11iIi11i + O0
 if 12 - 12: I11i . OOooOOo + o0oOOo0O0Ooo . OoO0O00 + o0oOOo0O0Ooo
def lisp_process_rloc_probe_request ( lisp_sockets , map_request , source , port ,
 ttl ) :
 if 56 - 56: i1IIi / i1IIi . OoO0O00 % i1IIi - OoOoOO00 % OOooOOo
 OoOoO = bold ( "RLOC-probe" , False )
 if 66 - 66: i11iIiiIii * IiII % IiII . I1IiiI / ooOoO0o
 if ( lisp_i_am_etr ) :
  lprint ( "Received {} Map-Request, send RLOC-probe Map-Reply" . format ( OoOoO ) )
  lisp_etr_process_map_request ( lisp_sockets , map_request , source , port ,
 ttl )
  return
  if 50 - 50: IiII . iII111i / o0oOOo0O0Ooo % OoOoOO00 * IiII % I11i
  if 15 - 15: Ii1I
 if ( lisp_i_am_rtr ) :
  lprint ( "Received {} Map-Request, send RLOC-probe Map-Reply" . format ( OoOoO ) )
  lisp_rtr_process_map_request ( lisp_sockets , map_request , source , port ,
 ttl )
  return
  if 29 - 29: I11i / I1IiiI / OoooooooOO . OoOoOO00 / I11i . I1Ii111
  if 69 - 69: O0 * OoOoOO00 + o0oOOo0O0Ooo + I1IiiI % iII111i . OoooooooOO
 lprint ( "Ignoring received {} Map-Request, not an ETR or RTR" . format ( OoOoO ) )
 return
 if 45 - 45: I1Ii111 + oO0o - o0oOOo0O0Ooo - OoOoOO00 + I1IiiI / II111iiii
 if 46 - 46: II111iiii . iIii1I11I1II1
 if 62 - 62: I1ii11iIi11i % i1IIi % I1Ii111 * ooOoO0o % OOooOOo + I1IiiI
 if 100 - 100: II111iiii - o0oOOo0O0Ooo * OoooooooOO . ooOoO0o / II111iiii / oO0o
 if 43 - 43: iIii1I11I1II1 + ooOoO0o * iII111i + iIii1I11I1II1 . I1Ii111
def lisp_process_smr ( map_request ) :
 lprint ( "Received SMR-based Map-Request" )
 return
 if 87 - 87: I1Ii111
 if 47 - 47: II111iiii + I1IiiI . Oo0Ooo / iIii1I11I1II1
 if 14 - 14: i1IIi / OoO0O00 / iII111i % I1Ii111
 if 72 - 72: OoO0O00 . II111iiii - IiII + IiII + iIii1I11I1II1 % oO0o
 if 21 - 21: iII111i + OoOoOO00 - i11iIiiIii % O0 + OOooOOo
def lisp_process_smr_invoked_request ( map_request ) :
 lprint ( "Received SMR-invoked Map-Request" )
 return
 if 30 - 30: o0oOOo0O0Ooo - Oo0Ooo + iII111i / O0
 if 94 - 94: IiII
 if 69 - 69: I1Ii111 . I1Ii111
 if 53 - 53: i11iIiiIii + iII111i * Oo0Ooo - I1Ii111
 if 61 - 61: o0oOOo0O0Ooo / OOooOOo . II111iiii - I1IiiI * i11iIiiIii
 if 8 - 8: iII111i % o0oOOo0O0Ooo
 if 87 - 87: Ii1I % I11i / I1Ii111
def lisp_build_map_reply ( eid , group , rloc_set , nonce , action , ttl , rloc_probe ,
 keys , enc , auth , mr_ttl = - 1 ) :
 iIi111 = lisp_map_reply ( )
 iIi111 . rloc_probe = rloc_probe
 iIi111 . echo_nonce_capable = enc
 iIi111 . hop_count = 0 if ( mr_ttl == - 1 ) else mr_ttl
 iIi111 . record_count = 1
 iIi111 . nonce = nonce
 i1II1IiiIi = iIi111 . encode ( )
 iIi111 . print_map_reply ( )
 if 55 - 55: I1Ii111
 OoOO = lisp_eid_record ( )
 OoOO . rloc_count = len ( rloc_set )
 OoOO . authoritative = auth
 OoOO . record_ttl = ttl
 OoOO . action = action
 OoOO . eid = eid
 OoOO . group = group
 if 3 - 3: ooOoO0o . OoOoOO00
 i1II1IiiIi += OoOO . encode ( )
 OoOO . print_record ( "  " , False )
 if 57 - 57: O0 + OoO0O00 % i1IIi - oO0o / I1IiiI
 O0OOOoO00OO0o = lisp_get_all_addresses ( ) + lisp_get_all_translated_rlocs ( )
 if 34 - 34: I1ii11iIi11i + I1Ii111 / Ii1I
 for IiI1I1iii11 in rloc_set :
  iI11iII1IiiI = lisp_rloc_record ( )
  I1iiIiiii1111 = IiI1I1iii11 . rloc . print_address_no_iid ( )
  if ( I1iiIiiii1111 in O0OOOoO00OO0o ) :
   iI11iII1IiiI . local_bit = True
   iI11iII1IiiI . probe_bit = rloc_probe
   iI11iII1IiiI . keys = keys
   if ( IiI1I1iii11 . priority == 254 and lisp_i_am_rtr ) :
    iI11iII1IiiI . rloc_name = "RTR"
    if 98 - 98: Oo0Ooo * oO0o - Oo0Ooo * oO0o
    if 24 - 24: IiII % i11iIiiIii + ooOoO0o
  iI11iII1IiiI . store_rloc_entry ( IiI1I1iii11 )
  iI11iII1IiiI . reach_bit = True
  iI11iII1IiiI . print_record ( "    " )
  i1II1IiiIi += iI11iII1IiiI . encode ( )
  if 28 - 28: I11i * I11i + I11i / O0 - OOooOOo
 return ( i1II1IiiIi )
 if 29 - 29: OoOoOO00 + i11iIiiIii % OoO0O00 - OoooooooOO
 if 68 - 68: iII111i / OOooOOo
 if 28 - 28: II111iiii
 if 49 - 49: I1ii11iIi11i
 if 33 - 33: iIii1I11I1II1
 if 72 - 72: I1ii11iIi11i * i11iIiiIii
 if 12 - 12: O0 - iIii1I11I1II1 % Oo0Ooo / O0 - IiII
def lisp_build_map_referral ( eid , group , ddt_entry , action , ttl , nonce ) :
 O0oO0o = lisp_map_referral ( )
 O0oO0o . record_count = 1
 O0oO0o . nonce = nonce
 i1II1IiiIi = O0oO0o . encode ( )
 O0oO0o . print_map_referral ( )
 if 41 - 41: oO0o
 OoOO = lisp_eid_record ( )
 if 45 - 45: Ii1I
 iIII1I = 0
 if ( ddt_entry == None ) :
  OoOO . eid = eid
  OoOO . group = group
 else :
  iIII1I = len ( ddt_entry . delegation_set )
  OoOO . eid = ddt_entry . eid
  OoOO . group = ddt_entry . group
  ddt_entry . map_referrals_sent += 1
  if 90 - 90: I1ii11iIi11i + Oo0Ooo - Oo0Ooo
 OoOO . rloc_count = iIII1I
 OoOO . authoritative = True
 if 90 - 90: OOooOOo - Oo0Ooo
 if 57 - 57: I1IiiI + IiII + IiII * I1ii11iIi11i
 if 63 - 63: iIii1I11I1II1 % IiII * I1Ii111 . IiII * oO0o % o0oOOo0O0Ooo
 if 78 - 78: OOooOOo
 if 10 - 10: oO0o
 O0oOo00O = False
 if ( action == LISP_DDT_ACTION_NULL ) :
  if ( iIII1I == 0 ) :
   action = LISP_DDT_ACTION_NODE_REFERRAL
  else :
   o0i1II1iI = ddt_entry . delegation_set [ 0 ]
   if ( o0i1II1iI . is_ddt_child ( ) ) :
    action = LISP_DDT_ACTION_NODE_REFERRAL
    if 19 - 19: OoOoOO00 * I11i
   if ( o0i1II1iI . is_ms_child ( ) ) :
    action = LISP_DDT_ACTION_MS_REFERRAL
    if 32 - 32: i1IIi
    if 79 - 79: Oo0Ooo + II111iiii - o0oOOo0O0Ooo / Ii1I
    if 15 - 15: I11i / i1IIi % O0 % ooOoO0o / II111iiii * I11i
    if 18 - 18: i1IIi % oO0o
    if 80 - 80: II111iiii
    if 18 - 18: I1Ii111 % iII111i + OoOoOO00 . I1ii11iIi11i / I11i
    if 29 - 29: II111iiii - I1Ii111 . OoooooooOO / i11iIiiIii / I1ii11iIi11i
 if ( action == LISP_DDT_ACTION_NOT_AUTH ) : O0oOo00O = True
 if ( action in ( LISP_DDT_ACTION_MS_REFERRAL , LISP_DDT_ACTION_MS_ACK ) ) :
  O0oOo00O = ( lisp_i_am_ms and o0i1II1iI . is_ms_peer ( ) == False )
  if 60 - 60: i1IIi % ooOoO0o / II111iiii * Oo0Ooo - i1IIi . Ii1I
  if 63 - 63: OoO0O00 * OoooooooOO + iII111i / iIii1I11I1II1 . i11iIiiIii
 OoOO . action = action
 OoOO . ddt_incomplete = O0oOo00O
 OoOO . record_ttl = ttl
 if 17 - 17: OOooOOo
 i1II1IiiIi += OoOO . encode ( )
 OoOO . print_record ( "  " , True )
 if 21 - 21: i1IIi
 if ( iIII1I == 0 ) : return ( i1II1IiiIi )
 if 10 - 10: i11iIiiIii / ooOoO0o - o0oOOo0O0Ooo . o0oOOo0O0Ooo
 for o0i1II1iI in ddt_entry . delegation_set :
  iI11iII1IiiI = lisp_rloc_record ( )
  iI11iII1IiiI . rloc = o0i1II1iI . delegate_address
  iI11iII1IiiI . priority = o0i1II1iI . priority
  iI11iII1IiiI . weight = o0i1II1iI . weight
  iI11iII1IiiI . mpriority = 255
  iI11iII1IiiI . mweight = 0
  iI11iII1IiiI . reach_bit = True
  i1II1IiiIi += iI11iII1IiiI . encode ( )
  iI11iII1IiiI . print_record ( "    " )
  if 8 - 8: iII111i + iIii1I11I1II1 . I1ii11iIi11i
 return ( i1II1IiiIi )
 if 68 - 68: OoooooooOO . OoooooooOO % I1ii11iIi11i + i1IIi % OoooooooOO + Ii1I
 if 89 - 89: ooOoO0o + I11i * O0 % OoOoOO00
 if 2 - 2: I1Ii111 % iIii1I11I1II1 . Ii1I - II111iiii
 if 33 - 33: I11i . i11iIiiIii % i1IIi * II111iiii * i11iIiiIii + OoOoOO00
 if 26 - 26: I1IiiI % OoOoOO00 % I11i + Oo0Ooo
 if 86 - 86: iII111i / i1IIi % Oo0Ooo
 if 84 - 84: o0oOOo0O0Ooo * OOooOOo . I11i * Ii1I
def lisp_etr_process_map_request ( lisp_sockets , map_request , source , sport ,
 ttl ) :
 if 32 - 32: ooOoO0o % ooOoO0o * I1ii11iIi11i % Ii1I + Oo0Ooo . OoOoOO00
 if ( map_request . target_group . is_null ( ) ) :
  I111I = lisp_db_for_lookups . lookup_cache ( map_request . target_eid , False )
 else :
  I111I = lisp_db_for_lookups . lookup_cache ( map_request . target_group , False )
  if ( I111I ) : I111I = I111I . lookup_source_cache ( map_request . target_eid , False )
  if 61 - 61: Ii1I . OoOoOO00 / iIii1I11I1II1 . o0oOOo0O0Ooo % i11iIiiIii . OoOoOO00
 oOoo0OooOOo00 = map_request . print_prefix ( )
 if 92 - 92: OoO0O00 . i1IIi
 if ( I111I == None ) :
  lprint ( "Database-mapping entry not found for requested EID {}" . format ( green ( oOoo0OooOOo00 , False ) ) )
  if 22 - 22: Ii1I . I1IiiI
  return
  if 54 - 54: OOooOOo / I1ii11iIi11i % oO0o
  if 66 - 66: I11i + iII111i
 iiI11IIii1i1 = I111I . print_eid_tuple ( )
 if 90 - 90: ooOoO0o % o0oOOo0O0Ooo * Ii1I . o0oOOo0O0Ooo + o0oOOo0O0Ooo * OoOoOO00
 lprint ( "Found database-mapping EID-prefix {} for requested EID {}" . format ( green ( iiI11IIii1i1 , False ) , green ( oOoo0OooOOo00 , False ) ) )
 if 40 - 40: iIii1I11I1II1 - i11iIiiIii / i1IIi / II111iiii
 if 37 - 37: Ii1I + o0oOOo0O0Ooo
 if 74 - 74: Oo0Ooo / O0 + i1IIi . I1IiiI + OoO0O00 / Oo0Ooo
 if 13 - 13: o0oOOo0O0Ooo / Ii1I . II111iiii
 if 8 - 8: I11i - I11i % IiII
 Ii1 = map_request . itr_rlocs [ 0 ]
 if ( Ii1 . is_private_address ( ) and lisp_nat_traversal ) :
  Ii1 = source
  if 86 - 86: o0oOOo0O0Ooo . I11i . I1IiiI . oO0o + Oo0Ooo + II111iiii
  if 75 - 75: o0oOOo0O0Ooo / iII111i / iII111i % i1IIi
 oOo0 = map_request . nonce
 Ii11Ii11III = lisp_nonce_echoing
 o00OO0o0 = map_request . keys
 if 1 - 1: O0 * oO0o * OoOoOO00 . i1IIi . Ii1I - OoOoOO00
 I111I . map_replies_sent += 1
 if 27 - 27: O0
 i1II1IiiIi = lisp_build_map_reply ( I111I . eid , I111I . group , I111I . rloc_set , oOo0 ,
 LISP_NO_ACTION , 1440 , map_request . rloc_probe , o00OO0o0 , Ii11Ii11III , True , ttl )
 if 86 - 86: IiII + Ii1I / Oo0Ooo / O0 % iII111i - oO0o
 if 3 - 3: i11iIiiIii / I1ii11iIi11i % I1Ii111 + o0oOOo0O0Ooo + O0
 if 42 - 42: IiII / i11iIiiIii % o0oOOo0O0Ooo / II111iiii / IiII
 if 97 - 97: OOooOOo . OoOoOO00 / I11i - IiII - iIii1I11I1II1
 if 82 - 82: II111iiii + OoO0O00 % iIii1I11I1II1 / O0
 if 75 - 75: OOooOOo * OoO0O00 + OoooooooOO + i11iIiiIii . OoO0O00
 if 94 - 94: I11i * ooOoO0o . I1IiiI / Ii1I - I1IiiI % OoooooooOO
 if 32 - 32: OoO0O00
 if 22 - 22: II111iiii . I11i
 if 61 - 61: OOooOOo % O0 . I1ii11iIi11i . iIii1I11I1II1 * I11i
 if 29 - 29: ooOoO0o + i1IIi % IiII * Ii1I
 if 94 - 94: OOooOOo / IiII
 if 18 - 18: IiII - I11i / Ii1I % IiII * i1IIi
 if 22 - 22: OoOoOO00 - Oo0Ooo
 if 41 - 41: iIii1I11I1II1 * I1Ii111 / OoO0O00
 if 33 - 33: I11i + O0
 if ( map_request . rloc_probe and len ( lisp_sockets ) == 4 ) :
  oOOO = ( Ii1 . is_private_address ( ) == False )
  oOOoOO = Ii1 . print_address_no_iid ( )
  if ( ( oOOO and lisp_rtr_list . has_key ( oOOoOO ) ) or sport == 0 ) :
   lisp_encapsulate_rloc_probe ( lisp_sockets , Ii1 , None , i1II1IiiIi )
   return
   if 9 - 9: I11i . iII111i * ooOoO0o * ooOoO0o
   if 68 - 68: O0 - i11iIiiIii % iIii1I11I1II1 % ooOoO0o
   if 12 - 12: II111iiii + I11i
   if 9 - 9: I1ii11iIi11i
   if 51 - 51: I1ii11iIi11i
   if 37 - 37: I1IiiI % I1Ii111
 lisp_send_map_reply ( lisp_sockets , i1II1IiiIi , Ii1 , sport )
 return
 if 22 - 22: o0oOOo0O0Ooo % OOooOOo - I11i + ooOoO0o / OOooOOo
 if 98 - 98: I11i * O0 + IiII - oO0o
 if 35 - 35: OoooooooOO * Ii1I
 if 73 - 73: ooOoO0o . OoO0O00 % I1ii11iIi11i - oO0o
 if 67 - 67: o0oOOo0O0Ooo . I11i + i1IIi
 if 100 - 100: Oo0Ooo - I1IiiI . OOooOOo % iIii1I11I1II1 . I11i
 if 83 - 83: OoOoOO00 * iII111i
def lisp_rtr_process_map_request ( lisp_sockets , map_request , source , sport ,
 ttl ) :
 if 75 - 75: i11iIiiIii . o0oOOo0O0Ooo / oO0o . OoO0O00 % Ii1I % Ii1I
 if 94 - 94: iII111i . Ii1I
 if 71 - 71: o0oOOo0O0Ooo * II111iiii / OOooOOo . OoO0O00
 if 73 - 73: I1Ii111 * OoO0O00 / OoOoOO00 . II111iiii
 Ii1 = map_request . itr_rlocs [ 0 ]
 if ( Ii1 . is_private_address ( ) ) : Ii1 = source
 oOo0 = map_request . nonce
 if 87 - 87: OoO0O00 + Oo0Ooo + O0 % OoooooooOO - iIii1I11I1II1
 i1OO0o = map_request . target_eid
 O0oo0oo0 = map_request . target_group
 if 100 - 100: Oo0Ooo + IiII
 oooo0O = [ ]
 for o0O0 in [ lisp_myrlocs [ 0 ] , lisp_myrlocs [ 1 ] ] :
  if ( o0O0 == None ) : continue
  OoOOo = lisp_rloc ( )
  OoOOo . rloc . copy_address ( o0O0 )
  OoOOo . priority = 254
  oooo0O . append ( OoOOo )
  if 26 - 26: ooOoO0o * i1IIi
  if 2 - 2: ooOoO0o % Ii1I + Ii1I / i1IIi % o0oOOo0O0Ooo . iIii1I11I1II1
 Ii11Ii11III = lisp_nonce_echoing
 o00OO0o0 = map_request . keys
 if 15 - 15: Oo0Ooo % I11i . i1IIi
 i1II1IiiIi = lisp_build_map_reply ( i1OO0o , O0oo0oo0 , oooo0O , oOo0 , LISP_NO_ACTION ,
 1440 , True , o00OO0o0 , Ii11Ii11III , True , ttl )
 lisp_send_map_reply ( lisp_sockets , i1II1IiiIi , Ii1 , sport )
 return
 if 77 - 77: O0 * iII111i % Oo0Ooo * I1Ii111
 if 41 - 41: OoOoOO00 / ooOoO0o / o0oOOo0O0Ooo . OoO0O00 + Ii1I % i1IIi
 if 14 - 14: i1IIi * OoooooooOO % i1IIi % iII111i . I11i
 if 83 - 83: O0 % I1ii11iIi11i - i1IIi . i11iIiiIii * I11i
 if 2 - 2: Ii1I / OOooOOo
 if 64 - 64: i1IIi % Oo0Ooo / O0 % Oo0Ooo
 if 49 - 49: II111iiii * iIii1I11I1II1 / I11i - oO0o
 if 76 - 76: I1Ii111 . Oo0Ooo - ooOoO0o . II111iiii - iII111i
 if 36 - 36: iIii1I11I1II1 % Oo0Ooo
 if 67 - 67: oO0o / II111iiii . I11i / oO0o
def lisp_get_private_rloc_set ( target_site_eid , seid , group ) :
 oooo0O = target_site_eid . registered_rlocs
 if 46 - 46: oO0o * Oo0Ooo - I11i / iIii1I11I1II1
 ooOOO00Ooo0 = lisp_site_eid_lookup ( seid , group , False )
 if ( ooOOO00Ooo0 == None ) : return ( oooo0O )
 if 3 - 3: I1ii11iIi11i
 if 38 - 38: ooOoO0o % Ii1I % I11i % iIii1I11I1II1
 if 2 - 2: I11i * oO0o - Ii1I
 if 41 - 41: OoOoOO00 * IiII + iII111i
 OOOO = None
 oooOooO0 = [ ]
 for IiI1I1iii11 in oooo0O :
  if ( IiI1I1iii11 . is_rtr ( ) ) : continue
  if ( IiI1I1iii11 . rloc . is_private_address ( ) ) :
   II1iI = copy . deepcopy ( IiI1I1iii11 )
   oooOooO0 . append ( II1iI )
   continue
   if 62 - 62: i1IIi / I1IiiI - OoO0O00 % OOooOOo + O0 + O0
  OOOO = IiI1I1iii11
  break
  if 50 - 50: iIii1I11I1II1
 if ( OOOO == None ) : return ( oooo0O )
 OOOO = OOOO . rloc . print_address_no_iid ( )
 if 86 - 86: iIii1I11I1II1
 if 81 - 81: OOooOOo / I11i / OoooooooOO
 if 74 - 74: I11i + OoooooooOO % II111iiii % o0oOOo0O0Ooo
 if 27 - 27: OoO0O00 * Oo0Ooo
 Ooo00o0oo0O0 = None
 for IiI1I1iii11 in ooOOO00Ooo0 . registered_rlocs :
  if ( IiI1I1iii11 . is_rtr ( ) ) : continue
  if ( IiI1I1iii11 . rloc . is_private_address ( ) ) : continue
  Ooo00o0oo0O0 = IiI1I1iii11
  break
  if 89 - 89: OoOoOO00 / Oo0Ooo + O0 * ooOoO0o
 if ( Ooo00o0oo0O0 == None ) : return ( oooo0O )
 Ooo00o0oo0O0 = Ooo00o0oo0O0 . rloc . print_address_no_iid ( )
 if 80 - 80: i11iIiiIii - O0 / I1Ii111 + OOooOOo % Oo0Ooo
 if 95 - 95: II111iiii
 if 76 - 76: OoO0O00 % iII111i * OoOoOO00 / ooOoO0o / i1IIi
 if 45 - 45: Ii1I . I11i * I1Ii111 . i11iIiiIii
 ooO0OOoOooO = target_site_eid . site_id
 if ( ooO0OOoOooO == 0 ) :
  if ( Ooo00o0oo0O0 == OOOO ) :
   lprint ( "Return private RLOCs for sites behind {}" . format ( OOOO ) )
   if 34 - 34: O0 * o0oOOo0O0Ooo / IiII
   return ( oooOooO0 )
   if 75 - 75: I1Ii111 - i1IIi - OoO0O00
  return ( oooo0O )
  if 25 - 25: iII111i . o0oOOo0O0Ooo
  if 62 - 62: I11i + i1IIi . I1ii11iIi11i - I1ii11iIi11i
  if 68 - 68: ooOoO0o % OoooooooOO
  if 94 - 94: Oo0Ooo * o0oOOo0O0Ooo
  if 60 - 60: iII111i . OOooOOo
  if 39 - 39: O0 - i11iIiiIii - I1IiiI / Oo0Ooo - i11iIiiIii
  if 30 - 30: OoO0O00 / OoOoOO00 + I1ii11iIi11i % IiII - OoO0O00
 if ( ooO0OOoOooO == ooOOO00Ooo0 . site_id ) :
  lprint ( "Return private RLOCs for sites in site-id {}" . format ( ooO0OOoOooO ) )
  return ( oooOooO0 )
  if 19 - 19: I1IiiI
 return ( oooo0O )
 if 99 - 99: OOooOOo - OOooOOo
 if 98 - 98: o0oOOo0O0Ooo + O0 * oO0o - i11iIiiIii
 if 83 - 83: o0oOOo0O0Ooo
 if 23 - 23: o0oOOo0O0Ooo . I11i
 if 67 - 67: iII111i
 if 52 - 52: IiII . OoooooooOO
 if 34 - 34: o0oOOo0O0Ooo / IiII . OoooooooOO . Oo0Ooo / ooOoO0o + O0
 if 38 - 38: I11i
 if 66 - 66: II111iiii
def lisp_get_partial_rloc_set ( registered_rloc_set , mr_source , multicast ) :
 OO0O = [ ]
 oooo0O = [ ]
 if 88 - 88: OOooOOo - I1ii11iIi11i % iII111i
 if 58 - 58: OoO0O00 . O0 - i11iIiiIii . I1IiiI
 if 95 - 95: OoooooooOO / ooOoO0o * I11i - Ii1I
 if 94 - 94: I1Ii111 + OoO0O00 . OoooooooOO
 if 60 - 60: Ii1I . II111iiii
 if 36 - 36: IiII . iII111i * O0 . i1IIi * O0 * I1Ii111
 IiIIIi = False
 O0000O00O00OO = False
 for IiI1I1iii11 in registered_rloc_set :
  if ( IiI1I1iii11 . priority != 254 ) : continue
  O0000O00O00OO |= True
  if ( IiI1I1iii11 . rloc . is_exact_match ( mr_source ) == False ) : continue
  IiIIIi = True
  break
  if 10 - 10: I1ii11iIi11i
  if 5 - 5: IiII - iIii1I11I1II1 % oO0o % i1IIi
  if 68 - 68: OoooooooOO * Oo0Ooo / o0oOOo0O0Ooo * I11i + OoO0O00 . OoooooooOO
  if 12 - 12: oO0o - I1ii11iIi11i
  if 69 - 69: iII111i * IiII * oO0o % OoO0O00 - o0oOOo0O0Ooo
  if 97 - 97: O0 + i11iIiiIii . i1IIi
  if 43 - 43: II111iiii + OOooOOo . i11iIiiIii - II111iiii
 if ( O0000O00O00OO == False ) : return ( registered_rloc_set )
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
 oO0OO0oOo00 = ( os . getenv ( "LISP_RTR_BEHIND_NAT" ) != None )
 if 60 - 60: OoO0O00 % iIii1I11I1II1 - OoooooooOO + OoOoOO00
 if 50 - 50: O0 . I1Ii111 + i1IIi * iIii1I11I1II1 % iIii1I11I1II1
 if 18 - 18: iII111i . Oo0Ooo
 if 4 - 4: o0oOOo0O0Ooo % oO0o - OoOoOO00 * iIii1I11I1II1
 if 96 - 96: Ii1I
 for IiI1I1iii11 in registered_rloc_set :
  if ( oO0OO0oOo00 and IiI1I1iii11 . rloc . is_private_address ( ) ) : continue
  if ( multicast == False and IiI1I1iii11 . priority == 255 ) : continue
  if ( multicast and IiI1I1iii11 . mpriority == 255 ) : continue
  if ( IiI1I1iii11 . priority == 254 ) :
   OO0O . append ( IiI1I1iii11 )
  else :
   oooo0O . append ( IiI1I1iii11 )
   if 1 - 1: i1IIi % O0 / I11i
   if 52 - 52: I1IiiI + oO0o * II111iiii
   if 15 - 15: I11i
   if 72 - 72: O0
   if 15 - 15: II111iiii / I11i % II111iiii % Ii1I % i11iIiiIii / I1Ii111
   if 93 - 93: OOooOOo / OoooooooOO % iII111i
 if ( IiIIIi ) : return ( oooo0O )
 if 47 - 47: o0oOOo0O0Ooo - I1IiiI % O0 % I1Ii111 . O0 . OoOoOO00
 if 95 - 95: o0oOOo0O0Ooo * OOooOOo - iII111i * OoooooooOO - ooOoO0o / I1IiiI
 if 47 - 47: OoO0O00 % I1IiiI / OoOoOO00 - I1Ii111 / I1IiiI
 if 13 - 13: o0oOOo0O0Ooo % ooOoO0o
 if 15 - 15: iII111i * I1IiiI . iIii1I11I1II1 % I1IiiI / O0
 if 47 - 47: OoooooooOO - i11iIiiIii . I1IiiI / i1IIi
 if 74 - 74: OoooooooOO * ooOoO0o
 if 45 - 45: Oo0Ooo + iIii1I11I1II1 . o0oOOo0O0Ooo
 if 50 - 50: o0oOOo0O0Ooo % O0
 if 67 - 67: OoOoOO00
 oooo0O = [ ]
 for IiI1I1iii11 in registered_rloc_set :
  if ( IiI1I1iii11 . rloc . is_private_address ( ) ) : oooo0O . append ( IiI1I1iii11 )
  if 21 - 21: I11i % Oo0Ooo + Oo0Ooo / iIii1I11I1II1 % iIii1I11I1II1
 oooo0O += OO0O
 return ( oooo0O )
 if 66 - 66: iII111i
 if 72 - 72: ooOoO0o / oO0o / iII111i . I1Ii111 . I1ii11iIi11i + IiII
 if 39 - 39: I1IiiI % I1Ii111
 if 22 - 22: OoOoOO00 - OOooOOo % i1IIi + i1IIi
 if 28 - 28: oO0o + OoOoOO00 * Ii1I . I11i
 if 80 - 80: I1ii11iIi11i / OoOoOO00
 if 74 - 74: I1ii11iIi11i + O0 + o0oOOo0O0Ooo - iII111i
 if 48 - 48: ooOoO0o * iIii1I11I1II1 % Oo0Ooo
 if 60 - 60: OoOoOO00 / i1IIi * iIii1I11I1II1
 if 91 - 91: I1Ii111 . OoooooooOO / IiII / I1IiiI
def lisp_store_pubsub_state ( reply_eid , itr_rloc , mr_sport , nonce , ttl , xtr_id ) :
 Ooooo00oOO0Oo = lisp_pubsub ( itr_rloc , mr_sport , nonce , ttl , xtr_id )
 Ooooo00oOO0Oo . add ( reply_eid )
 return
 if 2 - 2: ooOoO0o + OoO0O00 % i11iIiiIii
 if 97 - 97: OoooooooOO % IiII * iIii1I11I1II1
 if 97 - 97: iIii1I11I1II1 - I1Ii111 - o0oOOo0O0Ooo * o0oOOo0O0Ooo * OoOoOO00
 if 80 - 80: II111iiii . I1ii11iIi11i % i11iIiiIii / Ii1I / oO0o
 if 100 - 100: Ii1I . OoO0O00 * ooOoO0o
 if 4 - 4: i1IIi + OoooooooOO
 if 26 - 26: I1IiiI / II111iiii % I1ii11iIi11i * o0oOOo0O0Ooo . IiII / OoO0O00
 if 10 - 10: i11iIiiIii / i1IIi + O0 - i11iIiiIii % I11i - i1IIi
 if 38 - 38: O0 - I1IiiI + Oo0Ooo + ooOoO0o
 if 56 - 56: I1Ii111 + oO0o / Ii1I + I1Ii111
 if 21 - 21: OOooOOo / OoOoOO00 + OoOoOO00 + OoOoOO00 - i1IIi + Ii1I
 if 43 - 43: O0 % II111iiii
 if 60 - 60: iII111i / ooOoO0o - Ii1I - OoooooooOO
 if 79 - 79: oO0o / iII111i . iIii1I11I1II1 * i11iIiiIii * i1IIi . iIii1I11I1II1
 if 31 - 31: OoooooooOO / ooOoO0o / OoooooooOO + ooOoO0o . O0 - IiII
def lisp_convert_reply_to_notify ( packet ) :
 if 53 - 53: Oo0Ooo % iII111i % iII111i
 if 71 - 71: iII111i
 if 99 - 99: O0 - OoOoOO00 * I1Ii111 - Oo0Ooo
 if 62 - 62: i1IIi + ooOoO0o + Oo0Ooo - i11iIiiIii
 ii1i = struct . unpack ( "I" , packet [ 0 : 4 ] ) [ 0 ]
 ii1i = socket . ntohl ( ii1i ) & 0xff
 oOo0 = packet [ 4 : 12 ]
 packet = packet [ 12 : : ]
 if 51 - 51: ooOoO0o - I1Ii111 * oO0o
 if 47 - 47: Oo0Ooo % OoO0O00 * Ii1I / OoOoOO00
 if 1 - 1: I1IiiI
 if 68 - 68: ooOoO0o
 oOoOo00oo = ( LISP_MAP_NOTIFY << 28 ) | ii1i
 iIiI1I1II1 = struct . pack ( "I" , socket . htonl ( oOoOo00oo ) )
 i111iii1I1 = struct . pack ( "I" , 0 )
 if 68 - 68: I11i % IiII
 if 1 - 1: I1IiiI + OOooOOo - OOooOOo * O0 + o0oOOo0O0Ooo * OOooOOo
 if 48 - 48: ooOoO0o - iII111i + I1ii11iIi11i * I1Ii111 % ooOoO0o * OoO0O00
 if 28 - 28: i1IIi / iII111i + OOooOOo
 packet = iIiI1I1II1 + oOo0 + i111iii1I1 + packet
 return ( packet )
 if 89 - 89: Oo0Ooo + II111iiii * OoO0O00 + Oo0Ooo % II111iiii
 if 59 - 59: O0 + Oo0Ooo
 if 63 - 63: OoO0O00 / I1IiiI / oO0o . Ii1I / i1IIi
 if 50 - 50: I11i . I11i % I1IiiI - i1IIi
 if 63 - 63: OoO0O00 . iII111i
 if 28 - 28: ooOoO0o . Oo0Ooo - OoooooooOO - I1Ii111 - OoooooooOO - oO0o
 if 25 - 25: I11i / I1Ii111 . i11iIiiIii % i1IIi
 if 21 - 21: O0 * IiII . iII111i / iII111i % i11iIiiIii / I11i
def lisp_notify_subscribers ( lisp_sockets , eid_record , eid , site ) :
 oOoo0OooOOo00 = eid . print_prefix ( )
 if ( lisp_pubsub_cache . has_key ( oOoo0OooOOo00 ) == False ) : return
 if 15 - 15: o0oOOo0O0Ooo / OoO0O00 - i1IIi
 for Ooooo00oOO0Oo in lisp_pubsub_cache [ oOoo0OooOOo00 ] . values ( ) :
  o00ooOOo0ooO0 = Ooooo00oOO0Oo . itr
  IIiII = Ooooo00oOO0Oo . port
  iI111 = red ( o00ooOOo0ooO0 . print_address_no_iid ( ) , False )
  iio0OOoO0 = bold ( "subscriber" , False )
  i11IIii = "0x" + lisp_hex_string ( Ooooo00oOO0Oo . xtr_id )
  oOo0 = "0x" + lisp_hex_string ( Ooooo00oOO0Oo . nonce )
  if 71 - 71: iII111i / O0 . OoOoOO00 / iII111i . iIii1I11I1II1
  lprint ( "    Notify {} {}:{} xtr-id {} for {}, nonce {}" . format ( iio0OOoO0 , iI111 , IIiII , i11IIii , green ( oOoo0OooOOo00 , False ) , oOo0 ) )
  if 88 - 88: ooOoO0o + II111iiii
  if 89 - 89: i1IIi - i1IIi / iII111i
  lisp_build_map_notify ( lisp_sockets , eid_record , [ oOoo0OooOOo00 ] , 1 , o00ooOOo0ooO0 ,
 IIiII , Ooooo00oOO0Oo . nonce , 0 , 0 , 0 , site , False )
  Ooooo00oOO0Oo . map_notify_count += 1
  if 43 - 43: I1IiiI / IiII
 return
 if 38 - 38: I1ii11iIi11i + i11iIiiIii * I1IiiI % oO0o % OoooooooOO
 if 4 - 4: OoO0O00 . I1IiiI - O0 % iII111i . OOooOOo
 if 69 - 69: OoooooooOO
 if 19 - 19: O0 + iIii1I11I1II1 / OoOoOO00 / oO0o + II111iiii - OOooOOo
 if 70 - 70: i1IIi * o0oOOo0O0Ooo + I1Ii111 . ooOoO0o - O0 + i11iIiiIii
 if 81 - 81: iIii1I11I1II1 - OoO0O00 . i11iIiiIii
 if 4 - 4: o0oOOo0O0Ooo / OoO0O00 - I11i
def lisp_process_pubsub ( lisp_sockets , packet , reply_eid , itr_rloc , port , nonce ,
 ttl , xtr_id ) :
 if 52 - 52: II111iiii . iII111i
 if 36 - 36: I1IiiI * II111iiii
 if 68 - 68: oO0o * o0oOOo0O0Ooo + OoooooooOO - I1ii11iIi11i * i1IIi % OOooOOo
 if 39 - 39: I1Ii111 / I11i + oO0o / I1Ii111 % IiII * I1ii11iIi11i
 lisp_store_pubsub_state ( reply_eid , itr_rloc , port , nonce , ttl , xtr_id )
 if 66 - 66: I1ii11iIi11i * ooOoO0o . i11iIiiIii * Oo0Ooo - I11i . I1IiiI
 i1OO0o = green ( reply_eid . print_prefix ( ) , False )
 o00ooOOo0ooO0 = red ( itr_rloc . print_address_no_iid ( ) , False )
 I1I1IIIIi11 = bold ( "Map-Notify" , False )
 xtr_id = "0x" + lisp_hex_string ( xtr_id )
 lprint ( "{} pubsub request for {} to ack ITR {} xtr-id: {}" . format ( I1I1IIIIi11 ,
 i1OO0o , o00ooOOo0ooO0 , xtr_id ) )
 if 17 - 17: Oo0Ooo * II111iiii
 if 1 - 1: oO0o + iIii1I11I1II1
 if 36 - 36: iII111i * i1IIi % iIii1I11I1II1 . oO0o * Oo0Ooo
 if 10 - 10: i11iIiiIii / O0 . iIii1I11I1II1 * ooOoO0o . I1Ii111 * iIii1I11I1II1
 packet = lisp_convert_reply_to_notify ( packet )
 lisp_send_map_notify ( lisp_sockets , packet , itr_rloc , port )
 return
 if 91 - 91: Ii1I * i11iIiiIii
 if 24 - 24: I1IiiI * I11i - o0oOOo0O0Ooo / iII111i + IiII - I1ii11iIi11i
 if 53 - 53: I11i / I1IiiI - iIii1I11I1II1 - o0oOOo0O0Ooo * OoOoOO00
 if 86 - 86: iIii1I11I1II1 - I1Ii111
 if 86 - 86: O0 * IiII + OoOoOO00 + OoO0O00
 if 53 - 53: I1IiiI % i11iIiiIii + o0oOOo0O0Ooo . I1ii11iIi11i
 if 73 - 73: iII111i - o0oOOo0O0Ooo / OOooOOo + iII111i + o0oOOo0O0Ooo % II111iiii
 if 74 - 74: I11i * iIii1I11I1II1 - OoO0O00 / i1IIi / OoO0O00 / IiII
def lisp_ms_process_map_request ( lisp_sockets , packet , map_request , mr_source ,
 mr_sport , ecm_source ) :
 if 60 - 60: oO0o % I1Ii111 % Oo0Ooo
 if 34 - 34: o0oOOo0O0Ooo * OOooOOo % Ii1I + I1IiiI
 if 77 - 77: OoOoOO00 + IiII + Oo0Ooo
 if 88 - 88: i1IIi
 if 45 - 45: iII111i % I1ii11iIi11i / i11iIiiIii - II111iiii . Oo0Ooo / ooOoO0o
 if 55 - 55: OoO0O00 % IiII
 i1OO0o = map_request . target_eid
 O0oo0oo0 = map_request . target_group
 oOoo0OooOOo00 = lisp_print_eid_tuple ( i1OO0o , O0oo0oo0 )
 Ii1 = map_request . itr_rlocs [ 0 ]
 i11IIii = map_request . xtr_id
 oOo0 = map_request . nonce
 ooOOoo0 = LISP_NO_ACTION
 Ooooo00oOO0Oo = map_request . subscribe_bit
 if 93 - 93: OoO0O00 . I1ii11iIi11i / OOooOOo % OoooooooOO + i1IIi + I1Ii111
 if 94 - 94: II111iiii + i11iIiiIii % Ii1I / ooOoO0o * OoOoOO00
 if 68 - 68: O0 / Oo0Ooo / iIii1I11I1II1
 if 63 - 63: I1Ii111 + iII111i
 if 6 - 6: I1ii11iIi11i + Ii1I
 I1111I = True
 OO0OOOO0Oo = ( lisp_get_eid_hash ( i1OO0o ) != None )
 if ( OO0OOOO0Oo ) :
  IiiiI1I1i = map_request . map_request_signature
  if ( IiiiI1I1i == None ) :
   I1111I = False
   lprint ( ( "EID-crypto-hash signature verification {}, " + "no signature found" ) . format ( bold ( "failed" , False ) ) )
   if 99 - 99: o0oOOo0O0Ooo . O0 % OoOoOO00 / I1IiiI + OoOoOO00
  else :
   O0O0o0OOOooo0 = map_request . signature_eid
   iIIiI11I1 , OO000OO , I1111I = lisp_lookup_public_key ( O0O0o0OOOooo0 )
   if ( I1111I ) :
    I1111I = map_request . verify_map_request_sig ( OO000OO )
   else :
    lprint ( "Public-key lookup failed for sig-eid {}, hash-eid {}" . format ( O0O0o0OOOooo0 . print_address ( ) , iIIiI11I1 . print_address ( ) ) )
    if 3 - 3: Oo0Ooo
    if 80 - 80: O0 - i1IIi + OoO0O00 . i11iIiiIii
   oooOoOoo0o = bold ( "passed" , False ) if I1111I else bold ( "failed" , False )
   lprint ( "EID-crypto-hash signature verification {}" . format ( oooOoOoo0o ) )
   if 57 - 57: OOooOOo / I1ii11iIi11i * oO0o
   if 53 - 53: o0oOOo0O0Ooo * Ii1I
   if 42 - 42: I11i + iII111i / iIii1I11I1II1
 if ( Ooooo00oOO0Oo and I1111I == False ) :
  Ooooo00oOO0Oo = False
  lprint ( "Suppress creating pubsub state due to signature failure" )
  if 1 - 1: O0 - II111iiii
  if 75 - 75: II111iiii / OoO0O00 % II111iiii
  if 3 - 3: Ii1I - Ii1I % I1ii11iIi11i
  if 44 - 44: OOooOOo - o0oOOo0O0Ooo
  if 69 - 69: IiII + I1ii11iIi11i / o0oOOo0O0Ooo / OOooOOo
  if 31 - 31: oO0o + I1ii11iIi11i * i1IIi % I1IiiI % I1IiiI + iIii1I11I1II1
  if 62 - 62: OoooooooOO
  if 38 - 38: iII111i % iII111i * ooOoO0o / OoO0O00 + ooOoO0o
  if 52 - 52: ooOoO0o . iIii1I11I1II1 / iIii1I11I1II1 % oO0o - oO0o * II111iiii
  if 57 - 57: I1Ii111
  if 23 - 23: I1ii11iIi11i + II111iiii
  if 99 - 99: o0oOOo0O0Ooo . I1IiiI + o0oOOo0O0Ooo * o0oOOo0O0Ooo / O0
  if 27 - 27: OOooOOo - I1Ii111
  if 33 - 33: OOooOOo - Ii1I - iII111i + I1ii11iIi11i - i11iIiiIii
 ooO0OooOoOoO = Ii1 if ( Ii1 . afi == ecm_source . afi ) else ecm_source
 if 37 - 37: ooOoO0o
 Iiii1IIIiIi = lisp_site_eid_lookup ( i1OO0o , O0oo0oo0 , False )
 if 33 - 33: ooOoO0o . I1Ii111 + I1IiiI . Oo0Ooo
 if ( Iiii1IIIiIi == None or Iiii1IIIiIi . is_star_g ( ) ) :
  iIiiiiiiI1II = bold ( "Site not found" , False )
  lprint ( "{} for requested EID {}" . format ( iIiiiiiiI1II ,
 green ( oOoo0OooOOo00 , False ) ) )
  if 72 - 72: OOooOOo * OOooOOo
  if 5 - 5: o0oOOo0O0Ooo / i11iIiiIii
  if 5 - 5: oO0o % iII111i . Oo0Ooo . O0 . OoOoOO00 / iII111i
  if 78 - 78: Ii1I - I1ii11iIi11i + iIii1I11I1II1 + OoooooooOO . OoO0O00 - ooOoO0o
  lisp_send_negative_map_reply ( lisp_sockets , i1OO0o , O0oo0oo0 , oOo0 , Ii1 ,
 mr_sport , 15 , i11IIii , Ooooo00oOO0Oo )
  if 81 - 81: o0oOOo0O0Ooo * OoooooooOO
  return ( [ i1OO0o , O0oo0oo0 , LISP_DDT_ACTION_SITE_NOT_FOUND ] )
  if 32 - 32: OoOoOO00 - I11i * i11iIiiIii . I1ii11iIi11i . IiII . iIii1I11I1II1
  if 41 - 41: iII111i / OoOoOO00 / OoO0O00 / ooOoO0o
 iiI11IIii1i1 = Iiii1IIIiIi . print_eid_tuple ( )
 iiIII1 = Iiii1IIIiIi . site . site_name
 if 18 - 18: OoO0O00 . Oo0Ooo
 if 52 - 52: OoOoOO00 . iIii1I11I1II1 / OoOoOO00
 if 14 - 14: i1IIi
 if 63 - 63: OoOoOO00 . i11iIiiIii / IiII
 if 36 - 36: OOooOOo * OoOoOO00 + i11iIiiIii + O0 + O0
 if ( OO0OOOO0Oo == False and Iiii1IIIiIi . require_signature ) :
  IiiiI1I1i = map_request . map_request_signature
  O0O0o0OOOooo0 = map_request . signature_eid
  if ( IiiiI1I1i == None or O0O0o0OOOooo0 . is_null ( ) ) :
   lprint ( "Signature required for site {}" . format ( iiIII1 ) )
   I1111I = False
  else :
   O0O0o0OOOooo0 = map_request . signature_eid
   iIIiI11I1 , OO000OO , I1111I = lisp_lookup_public_key ( O0O0o0OOOooo0 )
   if ( I1111I ) :
    I1111I = map_request . verify_map_request_sig ( OO000OO )
   else :
    lprint ( "Public-key lookup failed for sig-eid {}, hash-eid {}" . format ( O0O0o0OOOooo0 . print_address ( ) , iIIiI11I1 . print_address ( ) ) )
    if 18 - 18: Oo0Ooo . I1ii11iIi11i * ooOoO0o % Ii1I + I1ii11iIi11i
    if 23 - 23: oO0o / o0oOOo0O0Ooo + I11i % IiII * OoO0O00
   oooOoOoo0o = bold ( "passed" , False ) if I1111I else bold ( "failed" , False )
   lprint ( "Required signature verification {}" . format ( oooOoOoo0o ) )
   if 48 - 48: OoO0O00
   if 30 - 30: iIii1I11I1II1
   if 53 - 53: II111iiii
   if 40 - 40: Ii1I % oO0o
   if 69 - 69: iIii1I11I1II1 - O0 . I1Ii111 % I1IiiI / o0oOOo0O0Ooo
   if 78 - 78: oO0o
 if ( I1111I and Iiii1IIIiIi . registered == False ) :
  lprint ( "Site '{}' with EID-prefix {} is not registered for EID {}" . format ( iiIII1 , green ( iiI11IIii1i1 , False ) , green ( oOoo0OooOOo00 , False ) ) )
  if 20 - 20: i1IIi + i1IIi * i1IIi
  if 32 - 32: I1IiiI + IiII + iII111i . iIii1I11I1II1 * Ii1I
  if 27 - 27: oO0o + Ii1I . i11iIiiIii
  if 97 - 97: iII111i . I1IiiI
  if 71 - 71: OOooOOo - IiII % oO0o * I1ii11iIi11i
  if 48 - 48: o0oOOo0O0Ooo * iIii1I11I1II1 + Oo0Ooo
  if ( Iiii1IIIiIi . accept_more_specifics == False ) :
   i1OO0o = Iiii1IIIiIi . eid
   O0oo0oo0 = Iiii1IIIiIi . group
   if 45 - 45: oO0o
   if 50 - 50: Ii1I * Ii1I / O0 . Oo0Ooo + iII111i
   if 9 - 9: OoooooooOO % O0 % I1ii11iIi11i
   if 100 - 100: i11iIiiIii - iII111i - I11i
   if 5 - 5: oO0o % IiII * iII111i
  iiI = 1
  if ( Iiii1IIIiIi . force_ttl != None ) :
   iiI = Iiii1IIIiIi . force_ttl | 0x80000000
   if 98 - 98: iII111i / OOooOOo + IiII
   if 100 - 100: II111iiii . i11iIiiIii / oO0o - OOooOOo + OoOoOO00 % I1ii11iIi11i
   if 82 - 82: ooOoO0o % OOooOOo % Ii1I
   if 82 - 82: I1ii11iIi11i
   if 52 - 52: i11iIiiIii % I1Ii111 - iII111i / O0 - I1ii11iIi11i / iII111i
  lisp_send_negative_map_reply ( lisp_sockets , i1OO0o , O0oo0oo0 , oOo0 , Ii1 ,
 mr_sport , iiI , i11IIii , Ooooo00oOO0Oo )
  if 7 - 7: OoooooooOO . OOooOOo . OOooOOo
  return ( [ i1OO0o , O0oo0oo0 , LISP_DDT_ACTION_MS_NOT_REG ] )
  if 53 - 53: OOooOOo * OoOoOO00 % iII111i
  if 86 - 86: OOooOOo . OOooOOo + IiII - I1ii11iIi11i . OoO0O00
  if 66 - 66: I1IiiI * OoOoOO00 . I1IiiI / Oo0Ooo - Ii1I
  if 69 - 69: iIii1I11I1II1 % iII111i + ooOoO0o * i1IIi + iII111i * I1Ii111
  if 67 - 67: Ii1I % Oo0Ooo - Oo0Ooo . I11i + IiII
 oOooo0o = False
 III1111 = ""
 oOOO0ooo = False
 if ( Iiii1IIIiIi . force_nat_proxy_reply ) :
  III1111 = ", nat-forced"
  oOooo0o = True
  oOOO0ooo = True
 elif ( Iiii1IIIiIi . force_proxy_reply ) :
  III1111 = ", forced"
  oOOO0ooo = True
 elif ( Iiii1IIIiIi . proxy_reply_requested ) :
  III1111 = ", requested"
  oOOO0ooo = True
 elif ( map_request . pitr_bit and Iiii1IIIiIi . pitr_proxy_reply_drop ) :
  III1111 = ", drop-to-pitr"
  ooOOoo0 = LISP_DROP_ACTION
 elif ( Iiii1IIIiIi . proxy_reply_action != "" ) :
  ooOOoo0 = Iiii1IIIiIi . proxy_reply_action
  III1111 = ", forced, action {}" . format ( ooOOoo0 )
  ooOOoo0 = LISP_DROP_ACTION if ( ooOOoo0 == "drop" ) else LISP_NATIVE_FORWARD_ACTION
  if 9 - 9: IiII % OoO0O00
  if 58 - 58: iII111i
  if 12 - 12: OoO0O00
  if 59 - 59: OOooOOo + i1IIi
  if 8 - 8: i1IIi + Oo0Ooo / Ii1I . OoOoOO00 % i1IIi
  if 33 - 33: OoooooooOO + iIii1I11I1II1
  if 68 - 68: II111iiii * iIii1I11I1II1 - OoO0O00 - I1ii11iIi11i * II111iiii
 iiiIiIII = False
 Oo00O0Oo = None
 if ( oOOO0ooo and lisp_policies . has_key ( Iiii1IIIiIi . policy ) ) :
  OoOoO = lisp_policies [ Iiii1IIIiIi . policy ]
  if ( OoOoO . match_policy_map_request ( map_request , mr_source ) ) : Oo00O0Oo = OoOoO
  if 97 - 97: OoOoOO00 + O0 * O0 / I1IiiI . I1IiiI
  if ( Oo00O0Oo ) :
   oo0OooO = bold ( "matched" , False )
   lprint ( "Map-Request {} policy '{}', set-action '{}'" . format ( oo0OooO ,
 OoOoO . policy_name , OoOoO . set_action ) )
  else :
   oo0OooO = bold ( "no match" , False )
   lprint ( "Map-Request {} for policy '{}', implied drop" . format ( oo0OooO ,
 OoOoO . policy_name ) )
   iiiIiIII = True
   if 32 - 32: OOooOOo - I1IiiI . Oo0Ooo
   if 86 - 86: ooOoO0o
   if 16 - 16: I11i - I1ii11iIi11i / OoOoOO00 * Oo0Ooo
 if ( III1111 != "" ) :
  lprint ( "Proxy-replying for EID {}, found site '{}' EID-prefix {}{}" . format ( green ( oOoo0OooOOo00 , False ) , iiIII1 , green ( iiI11IIii1i1 , False ) ,
  # II111iiii * iIii1I11I1II1 / o0oOOo0O0Ooo
 III1111 ) )
  if 89 - 89: iII111i * I1IiiI - Ii1I + I1Ii111 / oO0o
  oooo0O = Iiii1IIIiIi . registered_rlocs
  iiI = 1440
  if ( oOooo0o ) :
   if ( Iiii1IIIiIi . site_id != 0 ) :
    I1i1III1i = map_request . source_eid
    oooo0O = lisp_get_private_rloc_set ( Iiii1IIIiIi , I1i1III1i , O0oo0oo0 )
    if 93 - 93: IiII
   if ( oooo0O == Iiii1IIIiIi . registered_rlocs ) :
    OOO0Ooo0OoO0 = ( Iiii1IIIiIi . group . is_null ( ) == False )
    oooOooO0 = lisp_get_partial_rloc_set ( oooo0O , ooO0OooOoOoO , OOO0Ooo0OoO0 )
    if ( oooOooO0 != oooo0O ) :
     iiI = 15
     oooo0O = oooOooO0
     if 22 - 22: oO0o - iIii1I11I1II1
     if 33 - 33: II111iiii * O0 + O0
     if 98 - 98: IiII * OoooooooOO . iII111i
     if 34 - 34: OoooooooOO + I1Ii111
     if 97 - 97: II111iiii + I11i + OOooOOo / i11iIiiIii - iII111i
     if 9 - 9: i1IIi - I1Ii111 + I1Ii111
     if 81 - 81: II111iiii % I11i % O0 . I1Ii111 % ooOoO0o - O0
     if 58 - 58: OoooooooOO . II111iiii . O0 % I1Ii111 / OoooooooOO
  if ( Iiii1IIIiIi . force_ttl != None ) :
   iiI = Iiii1IIIiIi . force_ttl | 0x80000000
   if 64 - 64: Oo0Ooo + oO0o . OoO0O00
   if 67 - 67: I11i
   if 91 - 91: OOooOOo / OoO0O00
   if 36 - 36: I1IiiI . iII111i * I1Ii111 . IiII % I1ii11iIi11i
   if 44 - 44: I11i % I1ii11iIi11i - OoooooooOO % iII111i
   if 60 - 60: IiII % oO0o
  if ( Oo00O0Oo ) :
   if ( Oo00O0Oo . set_record_ttl ) :
    iiI = Oo00O0Oo . set_record_ttl
    lprint ( "Policy set-record-ttl to {}" . format ( iiI ) )
    if 11 - 11: I1Ii111 - II111iiii
   if ( Oo00O0Oo . set_action == "drop" ) :
    lprint ( "Policy set-action drop, send negative Map-Reply" )
    ooOOoo0 = LISP_POLICY_DENIED_ACTION
    oooo0O = [ ]
   else :
    OoOOo = Oo00O0Oo . set_policy_map_reply ( )
    if ( OoOOo ) : oooo0O = [ OoOOo ]
    if 12 - 12: i11iIiiIii
    if 9 - 9: OOooOOo * I1ii11iIi11i + iIii1I11I1II1 / OoO0O00 * OoooooooOO
    if 91 - 91: i11iIiiIii % IiII + oO0o . I1IiiI - I1IiiI
  if ( iiiIiIII ) :
   lprint ( "Implied drop action, send negative Map-Reply" )
   ooOOoo0 = LISP_POLICY_DENIED_ACTION
   oooo0O = [ ]
   if 62 - 62: Oo0Ooo * II111iiii + o0oOOo0O0Ooo . OoOoOO00
   if 94 - 94: Oo0Ooo / I1IiiI * iIii1I11I1II1 - OoO0O00
  Ii11Ii11III = Iiii1IIIiIi . echo_nonce_capable
  if 96 - 96: ooOoO0o - OoooooooOO * iIii1I11I1II1 . IiII - O0
  if 7 - 7: iIii1I11I1II1 . OoO0O00
  if 88 - 88: i1IIi * II111iiii / i11iIiiIii % IiII . IiII
  if 93 - 93: OoOoOO00 * i1IIi . Ii1I
  if ( I1111I ) :
   i11i = Iiii1IIIiIi . eid
   i1Ii1I1IIII = Iiii1IIIiIi . group
  else :
   i11i = i1OO0o
   i1Ii1I1IIII = O0oo0oo0
   ooOOoo0 = LISP_AUTH_FAILURE_ACTION
   oooo0O = [ ]
   if 54 - 54: OoO0O00 * OoOoOO00 + o0oOOo0O0Ooo . IiII
   if 87 - 87: i11iIiiIii . OoooooooOO - II111iiii
   if 69 - 69: iII111i
   if 70 - 70: O0 + iII111i % I11i % I1Ii111 + OoOoOO00 / ooOoO0o
   if 35 - 35: IiII + OoO0O00
   if 82 - 82: i1IIi - ooOoO0o / I11i + I11i % I1IiiI - OoooooooOO
  packet = lisp_build_map_reply ( i11i , i1Ii1I1IIII , oooo0O ,
 oOo0 , ooOOoo0 , iiI , False , None , Ii11Ii11III , False )
  if 56 - 56: I1ii11iIi11i
  if ( Ooooo00oOO0Oo ) :
   lisp_process_pubsub ( lisp_sockets , packet , i11i , Ii1 ,
 mr_sport , oOo0 , iiI , i11IIii )
  else :
   lisp_send_map_reply ( lisp_sockets , packet , Ii1 , mr_sport )
   if 80 - 80: Oo0Ooo / OOooOOo / iII111i . o0oOOo0O0Ooo
   if 43 - 43: IiII
  return ( [ Iiii1IIIiIi . eid , Iiii1IIIiIi . group , LISP_DDT_ACTION_MS_ACK ] )
  if 74 - 74: OoooooooOO
  if 88 - 88: Ii1I * o0oOOo0O0Ooo / oO0o
  if 58 - 58: O0
  if 43 - 43: O0 / i1IIi / I11i % I1IiiI
  if 82 - 82: i11iIiiIii * i11iIiiIii + I1Ii111 - I1ii11iIi11i * oO0o - Ii1I
 iIII1I = len ( Iiii1IIIiIi . registered_rlocs )
 if ( iIII1I == 0 ) :
  lprint ( "Requested EID {} found site '{}' with EID-prefix {} with " + "no registered RLOCs" . format ( green ( oOoo0OooOOo00 , False ) , iiIII1 ,
  # OoOoOO00 % I11i - OoO0O00
 green ( iiI11IIii1i1 , False ) ) )
  return ( [ Iiii1IIIiIi . eid , Iiii1IIIiIi . group , LISP_DDT_ACTION_MS_ACK ] )
  if 77 - 77: iII111i * I1Ii111
  if 36 - 36: I1ii11iIi11i % II111iiii % I1Ii111 / I1ii11iIi11i
  if 34 - 34: OoooooooOO * i11iIiiIii
  if 33 - 33: II111iiii
  if 59 - 59: iIii1I11I1II1 % I11i
 oOO000OOO = map_request . target_eid if map_request . source_eid . is_null ( ) else map_request . source_eid
 if 61 - 61: i11iIiiIii + i1IIi . I1Ii111 * II111iiii . I11i + iII111i
 IiiiI1I1iI11 = map_request . target_eid . hash_address ( oOO000OOO )
 IiiiI1I1iI11 %= iIII1I
 oo000oOOooo0O = Iiii1IIIiIi . registered_rlocs [ IiiiI1I1iI11 ]
 if 63 - 63: Oo0Ooo % OOooOOo * IiII % iIii1I11I1II1 / iII111i
 if ( oo000oOOooo0O . rloc . is_null ( ) ) :
  lprint ( ( "Suppress forwarding Map-Request for EID {} at site '{}' " + "EID-prefix {}, no RLOC address" ) . format ( green ( oOoo0OooOOo00 , False ) ,
  # OoooooooOO
 iiIII1 , green ( iiI11IIii1i1 , False ) ) )
 else :
  lprint ( ( "Forwarding Map-Request for EID {} to ETR {} at site '{}' " + "EID-prefix {}" ) . format ( green ( oOoo0OooOOo00 , False ) ,
  # OoO0O00 * OoOoOO00 % O0 % iII111i / i1IIi
 red ( oo000oOOooo0O . rloc . print_address ( ) , False ) , iiIII1 ,
 green ( iiI11IIii1i1 , False ) ) )
  if 100 - 100: i11iIiiIii
  if 54 - 54: O0 * Ii1I + Ii1I
  if 59 - 59: i11iIiiIii % iII111i
  if 54 - 54: I11i . ooOoO0o / OOooOOo % I1Ii111
  lisp_send_ecm ( lisp_sockets , packet , map_request . source_eid , mr_sport ,
 map_request . target_eid , oo000oOOooo0O . rloc , to_etr = True )
  if 13 - 13: I11i / O0 . o0oOOo0O0Ooo . ooOoO0o
 return ( [ Iiii1IIIiIi . eid , Iiii1IIIiIi . group , LISP_DDT_ACTION_MS_ACK ] )
 if 7 - 7: OoO0O00 + OoooooooOO % II111iiii % oO0o
 if 48 - 48: OOooOOo . II111iiii * OOooOOo - I11i / iIii1I11I1II1 / i11iIiiIii
 if 37 - 37: II111iiii % O0 + iIii1I11I1II1 - I1IiiI . I11i + I1ii11iIi11i
 if 14 - 14: ooOoO0o % iIii1I11I1II1 % ooOoO0o / IiII + OOooOOo
 if 14 - 14: Oo0Ooo
 if 79 - 79: I1ii11iIi11i % I1Ii111 % I11i - iII111i * OoOoOO00
 if 48 - 48: O0 + OoOoOO00 - O0
def lisp_ddt_process_map_request ( lisp_sockets , map_request , ecm_source , port ) :
 if 79 - 79: ooOoO0o . OoOoOO00 / OoooooooOO - II111iiii
 if 48 - 48: Oo0Ooo
 if 59 - 59: OoO0O00 % o0oOOo0O0Ooo
 if 83 - 83: iII111i % iIii1I11I1II1 / OOooOOo - OoOoOO00
 i1OO0o = map_request . target_eid
 O0oo0oo0 = map_request . target_group
 oOoo0OooOOo00 = lisp_print_eid_tuple ( i1OO0o , O0oo0oo0 )
 oOo0 = map_request . nonce
 ooOOoo0 = LISP_DDT_ACTION_NULL
 if 98 - 98: I11i % oO0o . I1IiiI % OoOoOO00
 if 32 - 32: I1ii11iIi11i / Ii1I
 if 54 - 54: I11i - i11iIiiIii
 if 91 - 91: Ii1I - OoO0O00 - I1IiiI % OoO0O00 . o0oOOo0O0Ooo
 if 85 - 85: ooOoO0o . ooOoO0o % Oo0Ooo . OOooOOo + OOooOOo / I1IiiI
 oooo0o = None
 if ( lisp_i_am_ms ) :
  Iiii1IIIiIi = lisp_site_eid_lookup ( i1OO0o , O0oo0oo0 , False )
  if ( Iiii1IIIiIi == None ) : return
  if 76 - 76: OOooOOo % OOooOOo + o0oOOo0O0Ooo - I1ii11iIi11i * oO0o * IiII
  if ( Iiii1IIIiIi . registered ) :
   ooOOoo0 = LISP_DDT_ACTION_MS_ACK
   iiI = 1440
  else :
   i1OO0o , O0oo0oo0 , ooOOoo0 = lisp_ms_compute_neg_prefix ( i1OO0o , O0oo0oo0 )
   ooOOoo0 = LISP_DDT_ACTION_MS_NOT_REG
   iiI = 1
   if 14 - 14: I1Ii111 . OoOoOO00 % OOooOOo . i11iIiiIii * I1IiiI % Ii1I
 else :
  oooo0o = lisp_ddt_cache_lookup ( i1OO0o , O0oo0oo0 , False )
  if ( oooo0o == None ) :
   ooOOoo0 = LISP_DDT_ACTION_NOT_AUTH
   iiI = 0
   lprint ( "DDT delegation entry not found for EID {}" . format ( green ( oOoo0OooOOo00 , False ) ) )
   if 7 - 7: OoooooooOO
  elif ( oooo0o . is_auth_prefix ( ) ) :
   if 41 - 41: OoOoOO00 + IiII % I1Ii111 / OOooOOo . I1IiiI
   if 43 - 43: II111iiii - ooOoO0o / iIii1I11I1II1
   if 30 - 30: O0 * o0oOOo0O0Ooo / iIii1I11I1II1 + iIii1I11I1II1 . OoOoOO00
   if 78 - 78: OoOoOO00 . i11iIiiIii
   ooOOoo0 = LISP_DDT_ACTION_DELEGATION_HOLE
   iiI = 15
   iiiiIII11Ii = oooo0o . print_eid_tuple ( )
   lprint ( ( "DDT delegation entry not found but auth-prefix {} " + "found for EID {}" ) . format ( iiiiIII11Ii ,
   # Ii1I % O0 - i1IIi % iII111i * OoO0O00
 green ( oOoo0OooOOo00 , False ) ) )
   if 60 - 60: I1ii11iIi11i * iII111i / OoOoOO00 . o0oOOo0O0Ooo / iIii1I11I1II1
   if ( O0oo0oo0 . is_null ( ) ) :
    i1OO0o = lisp_ddt_compute_neg_prefix ( i1OO0o , oooo0o ,
 lisp_ddt_cache )
   else :
    O0oo0oo0 = lisp_ddt_compute_neg_prefix ( O0oo0oo0 , oooo0o ,
 lisp_ddt_cache )
    i1OO0o = lisp_ddt_compute_neg_prefix ( i1OO0o , oooo0o ,
 oooo0o . source_cache )
    if 94 - 94: OoO0O00 . ooOoO0o
   oooo0o = None
  else :
   iiiiIII11Ii = oooo0o . print_eid_tuple ( )
   lprint ( "DDT delegation entry {} found for EID {}" . format ( iiiiIII11Ii , green ( oOoo0OooOOo00 , False ) ) )
   if 25 - 25: I1Ii111 % OOooOOo
   iiI = 1440
   if 82 - 82: Ii1I
   if 17 - 17: iII111i . i1IIi . i1IIi
   if 76 - 76: OoooooooOO % IiII
   if 81 - 81: iII111i . OOooOOo * i1IIi
   if 14 - 14: oO0o
   if 16 - 16: iII111i
 i1II1IiiIi = lisp_build_map_referral ( i1OO0o , O0oo0oo0 , oooo0o , ooOOoo0 , iiI , oOo0 )
 oOo0 = map_request . nonce >> 32
 if ( map_request . nonce != 0 and oOo0 != 0xdfdf0e1d ) : port = LISP_CTRL_PORT
 lisp_send_map_referral ( lisp_sockets , i1II1IiiIi , ecm_source , port )
 return
 if 26 - 26: iII111i . oO0o * i11iIiiIii . iIii1I11I1II1
 if 74 - 74: Ii1I / iIii1I11I1II1 + OOooOOo . II111iiii
 if 65 - 65: OOooOOo * I11i * Oo0Ooo
 if 21 - 21: Ii1I . iIii1I11I1II1
 if 84 - 84: OOooOOo
 if 67 - 67: I1IiiI % OoO0O00 % o0oOOo0O0Ooo % IiII
 if 33 - 33: ooOoO0o % I1IiiI
 if 98 - 98: oO0o . o0oOOo0O0Ooo + II111iiii
 if 62 - 62: ooOoO0o - OoooooooOO / I1ii11iIi11i / iII111i - o0oOOo0O0Ooo
 if 70 - 70: oO0o % OoooooooOO * I1IiiI - OoOoOO00 * OoOoOO00 . OOooOOo
 if 9 - 9: iII111i * Oo0Ooo % iII111i % Oo0Ooo * II111iiii
 if 71 - 71: II111iiii + I1ii11iIi11i * II111iiii
 if 59 - 59: OoO0O00
def lisp_find_negative_mask_len ( eid , entry_prefix , neg_prefix ) :
 oOOOo0O0 = eid . hash_address ( entry_prefix )
 o00O00OOO = eid . addr_length ( ) * 8
 ooooOo00OO0o = 0
 if 14 - 14: iII111i
 if 3 - 3: Oo0Ooo
 if 81 - 81: OoO0O00 / OoO0O00 . I1ii11iIi11i
 if 100 - 100: iIii1I11I1II1 % II111iiii - I1ii11iIi11i . iIii1I11I1II1 + IiII % iIii1I11I1II1
 for ooooOo00OO0o in range ( o00O00OOO ) :
  i1iIIi11Ii = 1 << ( o00O00OOO - ooooOo00OO0o - 1 )
  if ( oOOOo0O0 & i1iIIi11Ii ) : break
  if 64 - 64: I1Ii111 - OoOoOO00 * OoooooooOO - I1Ii111
  if 43 - 43: I1Ii111 + I11i - Ii1I + I11i - Oo0Ooo
 if ( ooooOo00OO0o > neg_prefix . mask_len ) : neg_prefix . mask_len = ooooOo00OO0o
 return
 if 63 - 63: IiII % I11i / OoOoOO00 % OOooOOo * iII111i * OoO0O00
 if 11 - 11: I1Ii111 * II111iiii
 if 3 - 3: Oo0Ooo * OOooOOo
 if 13 - 13: I1Ii111 + i11iIiiIii / OOooOOo
 if 98 - 98: I1IiiI * Oo0Ooo
 if 9 - 9: O0 / i11iIiiIii . iIii1I11I1II1 . IiII
 if 14 - 14: OoOoOO00 . OOooOOo - Oo0Ooo + I1Ii111 % ooOoO0o
 if 95 - 95: OoO0O00 * II111iiii + i1IIi
 if 22 - 22: Ii1I / ooOoO0o % I11i + OoO0O00 . ooOoO0o
 if 61 - 61: O0 - iIii1I11I1II1 * Oo0Ooo . Ii1I + O0
def lisp_neg_prefix_walk ( entry , parms ) :
 i1OO0o , I1I1I , OO0o0OoooOOoO = parms
 if 4 - 4: O0 * iII111i - iII111i + iIii1I11I1II1 * iIii1I11I1II1
 if ( I1I1I == None ) :
  if ( entry . eid . instance_id != i1OO0o . instance_id ) :
   return ( [ True , parms ] )
   if 48 - 48: I1Ii111 * I11i
  if ( entry . eid . afi != i1OO0o . afi ) : return ( [ True , parms ] )
 else :
  if ( entry . eid . is_more_specific ( I1I1I ) == False ) :
   return ( [ True , parms ] )
   if 52 - 52: ooOoO0o
   if 16 - 16: ooOoO0o % iII111i - o0oOOo0O0Ooo % I11i + i11iIiiIii
   if 6 - 6: i11iIiiIii
   if 66 - 66: I1Ii111 * I1ii11iIi11i . Ii1I
   if 28 - 28: oO0o - I1IiiI
   if 42 - 42: i1IIi
 lisp_find_negative_mask_len ( i1OO0o , entry . eid , OO0o0OoooOOoO )
 return ( [ True , parms ] )
 if 8 - 8: Ii1I - oO0o
 if 73 - 73: Oo0Ooo . i11iIiiIii % i11iIiiIii / o0oOOo0O0Ooo * OoO0O00 . i11iIiiIii
 if 61 - 61: i11iIiiIii + I11i * i1IIi . OoO0O00 . OoO0O00 - oO0o
 if 52 - 52: OOooOOo / ooOoO0o + I1ii11iIi11i - I1IiiI . II111iiii
 if 83 - 83: Oo0Ooo * OOooOOo - iIii1I11I1II1
 if 18 - 18: o0oOOo0O0Ooo + Ii1I . iIii1I11I1II1
 if 31 - 31: I1ii11iIi11i / I1IiiI % ooOoO0o . OoO0O00 / IiII . II111iiii
 if 20 - 20: IiII * I1Ii111
def lisp_ddt_compute_neg_prefix ( eid , ddt_entry , cache ) :
 if 11 - 11: I11i * OoO0O00 * OoO0O00 * I1ii11iIi11i * IiII
 if 42 - 42: I1Ii111 * I1Ii111 * OoO0O00 - oO0o
 if 96 - 96: Oo0Ooo
 if 82 - 82: ooOoO0o - O0 / OoO0O00
 if ( eid . is_binary ( ) == False ) : return ( eid )
 if 24 - 24: IiII - OoOoOO00 / OoooooooOO . I1ii11iIi11i
 OO0o0OoooOOoO = lisp_address ( eid . afi , "" , 0 , 0 )
 OO0o0OoooOOoO . copy_address ( eid )
 OO0o0OoooOOoO . mask_len = 0
 if 88 - 88: I11i
 Ii111IiI = ddt_entry . print_eid_tuple ( )
 I1I1I = ddt_entry . eid
 if 30 - 30: Oo0Ooo - o0oOOo0O0Ooo . OoO0O00
 if 40 - 40: IiII * iIii1I11I1II1 * ooOoO0o . Ii1I
 if 96 - 96: OoooooooOO * ooOoO0o * iIii1I11I1II1 % IiII + ooOoO0o
 if 99 - 99: i1IIi
 if 3 - 3: o0oOOo0O0Ooo + Ii1I - i1IIi . OoooooooOO % Ii1I
 eid , I1I1I , OO0o0OoooOOoO = cache . walk_cache ( lisp_neg_prefix_walk ,
 ( eid , I1I1I , OO0o0OoooOOoO ) )
 if 39 - 39: o0oOOo0O0Ooo
 if 73 - 73: IiII
 if 92 - 92: OOooOOo / ooOoO0o . I1Ii111 . iII111i / ooOoO0o
 if 83 - 83: iIii1I11I1II1 - OoO0O00 - I1Ii111
 OO0o0OoooOOoO . mask_address ( OO0o0OoooOOoO . mask_len )
 if 27 - 27: IiII - iII111i * i11iIiiIii % i11iIiiIii + OoOoOO00 . I1Ii111
 lprint ( ( "Least specific prefix computed from ddt-cache for EID {} " + "using auth-prefix {} is {}" ) . format ( green ( eid . print_address ( ) , False ) ,
 # II111iiii
 Ii111IiI , OO0o0OoooOOoO . print_prefix ( ) ) )
 return ( OO0o0OoooOOoO )
 if 24 - 24: O0 . I1ii11iIi11i / OOooOOo % IiII * Oo0Ooo / OoO0O00
 if 67 - 67: Oo0Ooo * I11i - IiII + I1Ii111
 if 90 - 90: iII111i % II111iiii % o0oOOo0O0Ooo + o0oOOo0O0Ooo + II111iiii
 if 54 - 54: OoooooooOO . IiII - oO0o
 if 26 - 26: o0oOOo0O0Ooo - i1IIi / I1ii11iIi11i / OoooooooOO . i1IIi
 if 22 - 22: o0oOOo0O0Ooo * I1Ii111 * I1ii11iIi11i . OoOoOO00 . i1IIi % ooOoO0o
 if 67 - 67: I11i
 if 95 - 95: OoO0O00 % I1Ii111
def lisp_ms_compute_neg_prefix ( eid , group ) :
 OO0o0OoooOOoO = lisp_address ( eid . afi , "" , 0 , 0 )
 OO0o0OoooOOoO . copy_address ( eid )
 OO0o0OoooOOoO . mask_len = 0
 ii1I1IiIIii = lisp_address ( group . afi , "" , 0 , 0 )
 ii1I1IiIIii . copy_address ( group )
 ii1I1IiIIii . mask_len = 0
 I1I1I = None
 if 10 - 10: Oo0Ooo % OoOoOO00 - OOooOOo % iII111i + I1Ii111
 if 82 - 82: IiII + Oo0Ooo + iIii1I11I1II1 - I11i - I1IiiI
 if 65 - 65: IiII / O0 * II111iiii + oO0o
 if 52 - 52: o0oOOo0O0Ooo - OoOoOO00 * II111iiii / OoooooooOO
 if 44 - 44: OOooOOo - oO0o + o0oOOo0O0Ooo - i1IIi % o0oOOo0O0Ooo
 if ( group . is_null ( ) ) :
  oooo0o = lisp_ddt_cache . lookup_cache ( eid , False )
  if ( oooo0o == None ) :
   OO0o0OoooOOoO . mask_len = OO0o0OoooOOoO . host_mask_len ( )
   ii1I1IiIIii . mask_len = ii1I1IiIIii . host_mask_len ( )
   return ( [ OO0o0OoooOOoO , ii1I1IiIIii , LISP_DDT_ACTION_NOT_AUTH ] )
   if 79 - 79: iII111i . iIii1I11I1II1
  Iii1 = lisp_sites_by_eid
  if ( oooo0o . is_auth_prefix ( ) ) : I1I1I = oooo0o . eid
 else :
  oooo0o = lisp_ddt_cache . lookup_cache ( group , False )
  if ( oooo0o == None ) :
   OO0o0OoooOOoO . mask_len = OO0o0OoooOOoO . host_mask_len ( )
   ii1I1IiIIii . mask_len = ii1I1IiIIii . host_mask_len ( )
   return ( [ OO0o0OoooOOoO , ii1I1IiIIii , LISP_DDT_ACTION_NOT_AUTH ] )
   if 26 - 26: O0
  if ( oooo0o . is_auth_prefix ( ) ) : I1I1I = oooo0o . group
  if 70 - 70: i1IIi % IiII % iIii1I11I1II1 . II111iiii * Oo0Ooo . o0oOOo0O0Ooo
  group , I1I1I , ii1I1IiIIii = lisp_sites_by_eid . walk_cache ( lisp_neg_prefix_walk , ( group , I1I1I , ii1I1IiIIii ) )
  if 33 - 33: iIii1I11I1II1 / OoooooooOO / I1IiiI + II111iiii
  if 42 - 42: OoOoOO00 / i1IIi * O0
  ii1I1IiIIii . mask_address ( ii1I1IiIIii . mask_len )
  if 46 - 46: OOooOOo - I1Ii111 + I1IiiI - ooOoO0o
  lprint ( ( "Least specific prefix computed from site-cache for " + "group EID {} using auth-prefix {} is {}" ) . format ( group . print_address ( ) , I1I1I . print_prefix ( ) if ( I1I1I != None ) else "'not found'" ,
  # OoO0O00 * OOooOOo * iII111i / I1ii11iIi11i % I11i % OoO0O00
  # o0oOOo0O0Ooo + iIii1I11I1II1
  # i11iIiiIii + oO0o . iIii1I11I1II1 - I11i % IiII . I1Ii111
 ii1I1IiIIii . print_prefix ( ) ) )
  if 31 - 31: OoooooooOO % iII111i / OOooOOo
  Iii1 = oooo0o . source_cache
  if 54 - 54: o0oOOo0O0Ooo
  if 37 - 37: ooOoO0o
  if 46 - 46: iII111i - i11iIiiIii * iII111i
  if 1 - 1: iII111i * oO0o % Ii1I . oO0o
  if 86 - 86: iII111i * ooOoO0o / iIii1I11I1II1 + Ii1I . iII111i
 ooOOoo0 = LISP_DDT_ACTION_DELEGATION_HOLE if ( I1I1I != None ) else LISP_DDT_ACTION_NOT_AUTH
 if 64 - 64: IiII - Oo0Ooo % iII111i % I11i
 if 42 - 42: Oo0Ooo . OoO0O00
 if 22 - 22: ooOoO0o - o0oOOo0O0Ooo + I11i / I1IiiI + OOooOOo
 if 10 - 10: oO0o / I1IiiI
 if 95 - 95: II111iiii - IiII % IiII . o0oOOo0O0Ooo
 if 19 - 19: II111iiii . ooOoO0o . I11i - OoooooooOO / I1ii11iIi11i . I1Ii111
 eid , I1I1I , OO0o0OoooOOoO = Iii1 . walk_cache ( lisp_neg_prefix_walk ,
 ( eid , I1I1I , OO0o0OoooOOoO ) )
 if 57 - 57: II111iiii . I1Ii111 . i11iIiiIii / OoOoOO00 - O0
 if 56 - 56: OOooOOo / I1Ii111
 if 13 - 13: oO0o + Oo0Ooo + Oo0Ooo / OoO0O00 + i1IIi + I1IiiI
 if 56 - 56: OoOoOO00
 OO0o0OoooOOoO . mask_address ( OO0o0OoooOOoO . mask_len )
 if 10 - 10: iIii1I11I1II1 + i1IIi * Ii1I / iIii1I11I1II1 % OoOoOO00 / O0
 lprint ( ( "Least specific prefix computed from site-cache for EID {} " + "using auth-prefix {} is {}" ) . format ( green ( eid . print_address ( ) , False ) ,
 # O0
 # oO0o
 I1I1I . print_prefix ( ) if ( I1I1I != None ) else "'not found'" , OO0o0OoooOOoO . print_prefix ( ) ) )
 if 21 - 21: oO0o * I1ii11iIi11i
 if 44 - 44: o0oOOo0O0Ooo * IiII - o0oOOo0O0Ooo
 return ( [ OO0o0OoooOOoO , ii1I1IiIIii , ooOOoo0 ] )
 if 90 - 90: i1IIi + I1ii11iIi11i * oO0o % i11iIiiIii - OoO0O00
 if 12 - 12: OoO0O00 . I1ii11iIi11i - I1IiiI % OOooOOo
 if 9 - 9: Ii1I / O0
 if 95 - 95: iII111i / I11i
 if 86 - 86: O0 / II111iiii . Oo0Ooo / Oo0Ooo * II111iiii
 if 22 - 22: Ii1I
 if 81 - 81: iIii1I11I1II1 . ooOoO0o % I11i
 if 64 - 64: I1Ii111 . Oo0Ooo * o0oOOo0O0Ooo
def lisp_ms_send_map_referral ( lisp_sockets , map_request , ecm_source , port ,
 action , eid_prefix , group_prefix ) :
 if 32 - 32: oO0o . I1Ii111 * I1Ii111
 i1OO0o = map_request . target_eid
 O0oo0oo0 = map_request . target_group
 oOo0 = map_request . nonce
 if 32 - 32: I1Ii111 . Ii1I / i1IIi
 if ( action == LISP_DDT_ACTION_MS_ACK ) : iiI = 1440
 if 2 - 2: OOooOOo * ooOoO0o / I11i + OoO0O00
 if 96 - 96: II111iiii * OoO0O00 + I1ii11iIi11i + OoOoOO00 / II111iiii . iII111i
 if 64 - 64: iII111i % Oo0Ooo
 if 79 - 79: IiII + iII111i / II111iiii . i1IIi + iIii1I11I1II1
 O0oO0o = lisp_map_referral ( )
 O0oO0o . record_count = 1
 O0oO0o . nonce = oOo0
 i1II1IiiIi = O0oO0o . encode ( )
 O0oO0o . print_map_referral ( )
 if 32 - 32: Ii1I * iII111i
 O0oOo00O = False
 if 52 - 52: I11i
 if 100 - 100: Oo0Ooo % Oo0Ooo % I1ii11iIi11i
 if 33 - 33: I1Ii111 . I1Ii111 * i1IIi
 if 22 - 22: I1ii11iIi11i . II111iiii + iIii1I11I1II1 / OoooooooOO . ooOoO0o
 if 13 - 13: II111iiii
 if 36 - 36: iII111i - oO0o / Oo0Ooo / O0 . OoO0O00 . i1IIi
 if ( action == LISP_DDT_ACTION_SITE_NOT_FOUND ) :
  eid_prefix , group_prefix , action = lisp_ms_compute_neg_prefix ( i1OO0o ,
 O0oo0oo0 )
  iiI = 15
  if 19 - 19: O0 . OoooooooOO % iIii1I11I1II1 - Ii1I . Ii1I + I1IiiI
 if ( action == LISP_DDT_ACTION_MS_NOT_REG ) : iiI = 1
 if ( action == LISP_DDT_ACTION_MS_ACK ) : iiI = 1440
 if ( action == LISP_DDT_ACTION_DELEGATION_HOLE ) : iiI = 15
 if ( action == LISP_DDT_ACTION_NOT_AUTH ) : iiI = 0
 if 98 - 98: oO0o . Oo0Ooo
 I1I1Ii1111 = False
 iIII1I = 0
 oooo0o = lisp_ddt_cache_lookup ( i1OO0o , O0oo0oo0 , False )
 if ( oooo0o != None ) :
  iIII1I = len ( oooo0o . delegation_set )
  I1I1Ii1111 = oooo0o . is_ms_peer_entry ( )
  oooo0o . map_referrals_sent += 1
  if 20 - 20: o0oOOo0O0Ooo
  if 54 - 54: II111iiii * OoOoOO00
  if 46 - 46: ooOoO0o . I1IiiI - ooOoO0o + Oo0Ooo
  if 31 - 31: OOooOOo + ooOoO0o . i1IIi - OoO0O00
  if 16 - 16: I11i + I1IiiI - Ii1I / I1ii11iIi11i + Ii1I
 if ( action == LISP_DDT_ACTION_NOT_AUTH ) : O0oOo00O = True
 if ( action in ( LISP_DDT_ACTION_MS_REFERRAL , LISP_DDT_ACTION_MS_ACK ) ) :
  O0oOo00O = ( I1I1Ii1111 == False )
  if 38 - 38: i1IIi * iIii1I11I1II1 * iII111i + OoOoOO00
  if 64 - 64: OoO0O00 % o0oOOo0O0Ooo
  if 72 - 72: O0 + OoOoOO00 % OOooOOo / oO0o / IiII
  if 98 - 98: Oo0Ooo . II111iiii * I11i
  if 39 - 39: IiII * o0oOOo0O0Ooo + Ii1I - I11i
 OoOO = lisp_eid_record ( )
 OoOO . rloc_count = iIII1I
 OoOO . authoritative = True
 OoOO . action = action
 OoOO . ddt_incomplete = O0oOo00O
 OoOO . eid = eid_prefix
 OoOO . group = group_prefix
 OoOO . record_ttl = iiI
 if 70 - 70: oO0o * ooOoO0o / ooOoO0o - Ii1I * Ii1I % OOooOOo
 i1II1IiiIi += OoOO . encode ( )
 OoOO . print_record ( "  " , True )
 if 91 - 91: OoO0O00 - OoO0O00 % O0
 if 67 - 67: ooOoO0o * i1IIi
 if 66 - 66: o0oOOo0O0Ooo - I1ii11iIi11i . OoOoOO00 / iII111i - Ii1I - i1IIi
 if 97 - 97: oO0o % iII111i - OOooOOo . OoooooooOO
 if ( iIII1I != 0 ) :
  for o0i1II1iI in oooo0o . delegation_set :
   iI11iII1IiiI = lisp_rloc_record ( )
   iI11iII1IiiI . rloc = o0i1II1iI . delegate_address
   iI11iII1IiiI . priority = o0i1II1iI . priority
   iI11iII1IiiI . weight = o0i1II1iI . weight
   iI11iII1IiiI . mpriority = 255
   iI11iII1IiiI . mweight = 0
   iI11iII1IiiI . reach_bit = True
   i1II1IiiIi += iI11iII1IiiI . encode ( )
   iI11iII1IiiI . print_record ( "    " )
   if 94 - 94: Oo0Ooo
   if 10 - 10: i11iIiiIii / I1ii11iIi11i . i1IIi + i1IIi * iII111i
   if 64 - 64: II111iiii % I1ii11iIi11i . OoOoOO00 . iIii1I11I1II1 / I1ii11iIi11i
   if 43 - 43: OoooooooOO * I1IiiI
   if 2 - 2: OOooOOo / oO0o + I1ii11iIi11i + i11iIiiIii % iIii1I11I1II1 . I1ii11iIi11i
   if 100 - 100: Oo0Ooo * ooOoO0o + Ii1I / iII111i * o0oOOo0O0Ooo
   if 26 - 26: I1Ii111 * OoOoOO00
 if ( map_request . nonce != 0 ) : port = LISP_CTRL_PORT
 lisp_send_map_referral ( lisp_sockets , i1II1IiiIi , ecm_source , port )
 return
 if 38 - 38: II111iiii
 if 50 - 50: OoOoOO00 . IiII - OOooOOo
 if 46 - 46: iIii1I11I1II1
 if 97 - 97: O0 * OOooOOo - o0oOOo0O0Ooo % o0oOOo0O0Ooo * II111iiii % I11i
 if 65 - 65: iIii1I11I1II1 / OOooOOo
 if 2 - 2: I11i - OOooOOo / o0oOOo0O0Ooo
 if 14 - 14: I11i + Oo0Ooo + i11iIiiIii - i1IIi . O0
 if 47 - 47: o0oOOo0O0Ooo / i1IIi * IiII
def lisp_send_negative_map_reply ( sockets , eid , group , nonce , dest , port , ttl ,
 xtr_id , pubsub ) :
 if 50 - 50: I11i
 lprint ( "Build negative Map-Reply EID-prefix {}, nonce 0x{} to ITR {}" . format ( lisp_print_eid_tuple ( eid , group ) , lisp_hex_string ( nonce ) ,
 # OoO0O00
 red ( dest . print_address ( ) , False ) ) )
 if 12 - 12: OoOoOO00 * o0oOOo0O0Ooo % ooOoO0o % I1IiiI . I1IiiI
 ooOOoo0 = LISP_NATIVE_FORWARD_ACTION if group . is_null ( ) else LISP_DROP_ACTION
 if 51 - 51: OoO0O00 % i11iIiiIii / oO0o / OoOoOO00 / I1Ii111 % i1IIi
 if 86 - 86: Oo0Ooo % OoooooooOO
 if 61 - 61: OOooOOo . i11iIiiIii
 if 33 - 33: o0oOOo0O0Ooo - OoooooooOO
 if 30 - 30: i1IIi + II111iiii + OoOoOO00 + I1ii11iIi11i % ooOoO0o % OOooOOo
 if ( lisp_get_eid_hash ( eid ) != None ) :
  ooOOoo0 = LISP_SEND_MAP_REQUEST_ACTION
  if 40 - 40: I1IiiI % I1IiiI - i11iIiiIii % OoOoOO00
  if 17 - 17: ooOoO0o - i1IIi
 i1II1IiiIi = lisp_build_map_reply ( eid , group , [ ] , nonce , ooOOoo0 , ttl , False ,
 None , False , False )
 if 73 - 73: iIii1I11I1II1 - I1Ii111 % Oo0Ooo . O0
 if 16 - 16: OoO0O00 / Oo0Ooo / IiII . Oo0Ooo - OoooooooOO
 if 5 - 5: OoOoOO00 . I11i
 if 28 - 28: I11i % OOooOOo + Oo0Ooo / OoO0O00 % o0oOOo0O0Ooo + OoO0O00
 if ( pubsub ) :
  lisp_process_pubsub ( sockets , i1II1IiiIi , eid , dest , port , nonce , ttl ,
 xtr_id )
 else :
  lisp_send_map_reply ( sockets , i1II1IiiIi , dest , port )
  if 20 - 20: ooOoO0o . iII111i % OOooOOo + i11iIiiIii
 return
 if 64 - 64: i1IIi . o0oOOo0O0Ooo * I1Ii111 - O0
 if 76 - 76: I1IiiI % Ii1I + OoO0O00 + I1ii11iIi11i * II111iiii + Oo0Ooo
 if 3 - 3: Ii1I - I1IiiI + O0
 if 90 - 90: Ii1I + OoooooooOO . i11iIiiIii / Oo0Ooo % OoOoOO00 / IiII
 if 45 - 45: OoooooooOO / oO0o . I1ii11iIi11i + OOooOOo
 if 54 - 54: Ii1I - o0oOOo0O0Ooo + OoOoOO00 / OoooooooOO
 if 61 - 61: I11i / IiII % OoooooooOO - i11iIiiIii * i1IIi % o0oOOo0O0Ooo
def lisp_retransmit_ddt_map_request ( mr ) :
 oO0oooOOo = mr . mr_source . print_address ( )
 oooo0OOo0O = mr . print_eid_tuple ( )
 oOo0 = mr . nonce
 if 34 - 34: i1IIi / i11iIiiIii / OoooooooOO + OoO0O00 * II111iiii / O0
 if 27 - 27: Oo0Ooo . IiII / OoooooooOO * i1IIi * IiII / I1ii11iIi11i
 if 19 - 19: i11iIiiIii + II111iiii
 if 37 - 37: I1Ii111 . I1IiiI - II111iiii / O0 . OoOoOO00
 if 27 - 27: I1ii11iIi11i / II111iiii + O0 % I1ii11iIi11i
 if ( mr . last_request_sent_to ) :
  ooooOoo0O = mr . last_request_sent_to . print_address ( )
  OoOo = lisp_referral_cache_lookup ( mr . last_cached_prefix [ 0 ] ,
 mr . last_cached_prefix [ 1 ] , True )
  if ( OoOo and OoOo . referral_set . has_key ( ooooOoo0O ) ) :
   OoOo . referral_set [ ooooOoo0O ] . no_responses += 1
   if 60 - 60: II111iiii + I1IiiI % oO0o - o0oOOo0O0Ooo
   if 50 - 50: iIii1I11I1II1 - i11iIiiIii / iII111i + ooOoO0o / OOooOOo
   if 80 - 80: IiII / OoooooooOO
   if 69 - 69: OoOoOO00 + IiII
   if 18 - 18: O0 / I11i
   if 10 - 10: I1Ii111 * i1IIi
   if 48 - 48: Oo0Ooo % i1IIi / iII111i . O0
 if ( mr . retry_count == LISP_MAX_MAP_NOTIFY_RETRIES ) :
  lprint ( "DDT Map-Request retry limit reached for EID {}, nonce 0x{}" . format ( green ( oooo0OOo0O , False ) , lisp_hex_string ( oOo0 ) ) )
  if 27 - 27: I11i + iIii1I11I1II1 - i11iIiiIii
  mr . dequeue_map_request ( )
  return
  if 81 - 81: I11i + oO0o * iIii1I11I1II1 * IiII
  if 7 - 7: I11i - I1IiiI . iII111i + O0 / iIii1I11I1II1 - I1Ii111
 mr . retry_count += 1
 if 32 - 32: ooOoO0o
 IiIIi1I1I11Ii = green ( oO0oooOOo , False )
 oOo0OOOOOO = green ( oooo0OOo0O , False )
 lprint ( "Retransmit DDT {} from {}ITR {} EIDs: {} -> {}, nonce 0x{}" . format ( bold ( "Map-Request" , False ) , "P" if mr . from_pitr else "" ,
 # i11iIiiIii
 red ( mr . itr . print_address ( ) , False ) , IiIIi1I1I11Ii , oOo0OOOOOO ,
 lisp_hex_string ( oOo0 ) ) )
 if 91 - 91: ooOoO0o / I1Ii111 . OoO0O00 - IiII * ooOoO0o
 if 64 - 64: OoooooooOO
 if 56 - 56: I11i / iIii1I11I1II1 - OoOoOO00 . Oo0Ooo + oO0o - ooOoO0o
 if 51 - 51: O0 . O0
 lisp_send_ddt_map_request ( mr , False )
 if 9 - 9: Oo0Ooo . i1IIi - i1IIi + I1Ii111 * ooOoO0o . I1ii11iIi11i
 if 17 - 17: I11i * I1ii11iIi11i % I1IiiI + OoO0O00 + IiII
 if 90 - 90: OoooooooOO - I1IiiI / I1ii11iIi11i + oO0o - o0oOOo0O0Ooo
 if 84 - 84: OoOoOO00 + O0 % Oo0Ooo
 mr . retransmit_timer = threading . Timer ( LISP_DDT_MAP_REQUEST_INTERVAL ,
 lisp_retransmit_ddt_map_request , [ mr ] )
 mr . retransmit_timer . start ( )
 return
 if 22 - 22: iIii1I11I1II1 % i11iIiiIii
 if 29 - 29: ooOoO0o - iII111i + IiII % Ii1I - oO0o - ooOoO0o
 if 43 - 43: oO0o
 if 22 - 22: I1Ii111 + i11iIiiIii
 if 49 - 49: O0 % II111iiii . OOooOOo + iII111i + iIii1I11I1II1 / i11iIiiIii
 if 79 - 79: II111iiii + ooOoO0o - i1IIi - i1IIi + II111iiii . i1IIi
 if 78 - 78: I1IiiI * I11i % OOooOOo + Ii1I + OoOoOO00
 if 23 - 23: iII111i / Oo0Ooo % OoooooooOO * OoooooooOO . iII111i / I1ii11iIi11i
def lisp_get_referral_node ( referral , source_eid , dest_eid ) :
 if 30 - 30: oO0o - OoOoOO00 . I1IiiI
 if 17 - 17: OoOoOO00
 if 76 - 76: I1ii11iIi11i - ooOoO0o % OoooooooOO / Oo0Ooo % IiII / ooOoO0o
 if 57 - 57: O0
 IIiii = [ ]
 for ooO in referral . referral_set . values ( ) :
  if ( ooO . updown == False ) : continue
  if ( len ( IIiii ) == 0 or IIiii [ 0 ] . priority == ooO . priority ) :
   IIiii . append ( ooO )
  elif ( IIiii [ 0 ] . priority > ooO . priority ) :
   IIiii = [ ]
   IIiii . append ( ooO )
   if 32 - 32: OOooOOo / I11i + I1Ii111 / Oo0Ooo * OoooooooOO / II111iiii
   if 8 - 8: OoO0O00
   if 17 - 17: iIii1I11I1II1 - Oo0Ooo
 iiIIii = len ( IIiii )
 if ( iiIIii == 0 ) : return ( None )
 if 18 - 18: oO0o + OOooOOo % OOooOOo
 IiiiI1I1iI11 = dest_eid . hash_address ( source_eid )
 IiiiI1I1iI11 = IiiiI1I1iI11 % iiIIii
 return ( IIiii [ IiiiI1I1iI11 ] )
 if 5 - 5: ooOoO0o
 if 7 - 7: IiII
 if 39 - 39: iII111i / i1IIi % Oo0Ooo - o0oOOo0O0Ooo / OoO0O00 / iII111i
 if 43 - 43: oO0o % O0 * I1ii11iIi11i + i11iIiiIii
 if 16 - 16: i1IIi . I11i + OoO0O00 % Ii1I * IiII + I1IiiI
 if 96 - 96: II111iiii + O0 - II111iiii
 if 97 - 97: I1IiiI
def lisp_send_ddt_map_request ( mr , send_to_root ) :
 o0o0oO = mr . lisp_sockets
 oOo0 = mr . nonce
 o00ooOOo0ooO0 = mr . itr
 ooO0 = mr . mr_source
 oOoo0OooOOo00 = mr . print_eid_tuple ( )
 if 20 - 20: IiII - i1IIi
 if 68 - 68: OOooOOo / I11i / i11iIiiIii . i11iIiiIii + Ii1I . i11iIiiIii
 if 45 - 45: ooOoO0o / II111iiii % OoOoOO00 % I1Ii111 . I1Ii111
 if 43 - 43: I11i * II111iiii
 if 14 - 14: I1ii11iIi11i * OoooooooOO / OoO0O00 / OoOoOO00 / OoooooooOO
 if ( mr . send_count == 8 ) :
  lprint ( "Giving up on map-request-queue entry {}, nonce 0x{}" . format ( green ( oOoo0OooOOo00 , False ) , lisp_hex_string ( oOo0 ) ) )
  if 17 - 17: i1IIi
  mr . dequeue_map_request ( )
  return
  if 80 - 80: i1IIi - iIii1I11I1II1 + OoooooooOO + ooOoO0o / IiII - I1ii11iIi11i
  if 90 - 90: I1IiiI * ooOoO0o - I11i + O0 - I11i
  if 59 - 59: OOooOOo % II111iiii
  if 30 - 30: i1IIi / I1ii11iIi11i
  if 4 - 4: Oo0Ooo
  if 31 - 31: IiII
 if ( send_to_root ) :
  OOo00OO = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  Ii1I11I1IiI = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  mr . tried_root = True
  lprint ( "Jumping up to root for EID {}" . format ( green ( oOoo0OooOOo00 , False ) ) )
 else :
  OOo00OO = mr . eid
  Ii1I11I1IiI = mr . group
  if 35 - 35: iIii1I11I1II1
  if 51 - 51: Ii1I
  if 31 - 31: OoOoOO00
  if 72 - 72: II111iiii + i11iIiiIii * OoO0O00 / II111iiii / I11i
  if 59 - 59: OOooOOo
 IiiII1 = lisp_referral_cache_lookup ( OOo00OO , Ii1I11I1IiI , False )
 if ( IiiII1 == None ) :
  lprint ( "No referral cache entry found" )
  lisp_send_negative_map_reply ( o0o0oO , OOo00OO , Ii1I11I1IiI ,
 oOo0 , o00ooOOo0ooO0 , mr . sport , 15 , None , False )
  return
  if 72 - 72: iIii1I11I1II1 / Oo0Ooo - o0oOOo0O0Ooo % I1Ii111
  if 96 - 96: IiII + o0oOOo0O0Ooo - I11i + I1IiiI . iII111i
 oOOooo0 = IiiII1 . print_eid_tuple ( )
 lprint ( "Found referral cache entry {}, referral-type: {}" . format ( oOOooo0 ,
 IiiII1 . print_referral_type ( ) ) )
 if 24 - 24: I1IiiI - IiII
 ooO = lisp_get_referral_node ( IiiII1 , ooO0 , mr . eid )
 if ( ooO == None ) :
  lprint ( "No reachable referral-nodes found" )
  mr . dequeue_map_request ( )
  lisp_send_negative_map_reply ( o0o0oO , IiiII1 . eid ,
 IiiII1 . group , oOo0 , o00ooOOo0ooO0 , mr . sport , 1 , None , False )
  return
  if 32 - 32: I1Ii111 . I1ii11iIi11i / OoooooooOO + I1Ii111 . I1Ii111
  if 52 - 52: O0 - I1Ii111 . oO0o
 lprint ( "Send DDT Map-Request to {} {} for EID {}, nonce 0x{}" . format ( ooO . referral_address . print_address ( ) ,
 # iII111i - I1ii11iIi11i * Ii1I
 IiiII1 . print_referral_type ( ) , green ( oOoo0OooOOo00 , False ) ,
 lisp_hex_string ( oOo0 ) ) )
 if 88 - 88: o0oOOo0O0Ooo - iII111i - ooOoO0o - I11i
 if 9 - 9: I1IiiI / O0 + I11i
 if 39 - 39: OoooooooOO * I1ii11iIi11i + II111iiii . I1Ii111 / II111iiii . I1ii11iIi11i
 if 72 - 72: OoOoOO00
 iIIII1iI1 = ( IiiII1 . referral_type == LISP_DDT_ACTION_MS_REFERRAL or
 IiiII1 . referral_type == LISP_DDT_ACTION_MS_ACK )
 lisp_send_ecm ( o0o0oO , mr . packet , ooO0 , mr . sport , mr . eid ,
 ooO . referral_address , to_ms = iIIII1iI1 , ddt = True )
 if 23 - 23: iIii1I11I1II1 + OoO0O00 / I1IiiI
 if 48 - 48: OoOoOO00 + I11i + oO0o . I1IiiI
 if 7 - 7: iII111i * i1IIi % OoOoOO00 % Ii1I . I1IiiI
 if 53 - 53: OOooOOo / I11i + OOooOOo / I1IiiI / OoO0O00
 mr . last_request_sent_to = ooO . referral_address
 mr . last_sent = lisp_get_timestamp ( )
 mr . send_count += 1
 ooO . map_requests_sent += 1
 return
 if 12 - 12: i11iIiiIii % ooOoO0o / iII111i . IiII
 if 68 - 68: OOooOOo / iIii1I11I1II1 + I1IiiI . ooOoO0o * IiII
 if 72 - 72: I1Ii111
 if 51 - 51: OoOoOO00
 if 61 - 61: Oo0Ooo / i1IIi + I1Ii111 - OoooooooOO / O0
 if 25 - 25: I1ii11iIi11i * i11iIiiIii / i1IIi
 if 69 - 69: OOooOOo % ooOoO0o - i1IIi . Oo0Ooo
 if 35 - 35: iIii1I11I1II1 - I11i / iIii1I11I1II1 % ooOoO0o % I1IiiI
def lisp_mr_process_map_request ( lisp_sockets , packet , map_request , ecm_source ,
 sport , mr_source ) :
 if 46 - 46: oO0o
 i1OO0o = map_request . target_eid
 O0oo0oo0 = map_request . target_group
 oooo0OOo0O = map_request . print_eid_tuple ( )
 oO0oooOOo = mr_source . print_address ( )
 oOo0 = map_request . nonce
 if 5 - 5: i1IIi % o0oOOo0O0Ooo + OoOoOO00 - I11i . Ii1I
 IiIIi1I1I11Ii = green ( oO0oooOOo , False )
 oOo0OOOOOO = green ( oooo0OOo0O , False )
 lprint ( "Received Map-Request from {}ITR {} EIDs: {} -> {}, nonce 0x{}" . format ( "P" if map_request . pitr_bit else "" ,
 # IiII / II111iiii
 red ( ecm_source . print_address ( ) , False ) , IiIIi1I1I11Ii , oOo0OOOOOO ,
 lisp_hex_string ( oOo0 ) ) )
 if 55 - 55: Oo0Ooo
 if 80 - 80: o0oOOo0O0Ooo - I1Ii111 * O0 * iIii1I11I1II1
 if 59 - 59: I1ii11iIi11i + I11i / OoO0O00
 if 36 - 36: o0oOOo0O0Ooo + ooOoO0o * I11i
 oOO0O000OOo0 = lisp_ddt_map_request ( lisp_sockets , packet , i1OO0o , O0oo0oo0 , oOo0 )
 oOO0O000OOo0 . packet = packet
 oOO0O000OOo0 . itr = ecm_source
 oOO0O000OOo0 . mr_source = mr_source
 oOO0O000OOo0 . sport = sport
 oOO0O000OOo0 . from_pitr = map_request . pitr_bit
 oOO0O000OOo0 . queue_map_request ( )
 if 19 - 19: I11i % OoOoOO00 / OoO0O00 % I11i + o0oOOo0O0Ooo / iII111i
 lisp_send_ddt_map_request ( oOO0O000OOo0 , False )
 return
 if 35 - 35: ooOoO0o % I11i * I1ii11iIi11i
 if 10 - 10: OoO0O00 + OoooooooOO + I1Ii111
 if 57 - 57: Ii1I % Ii1I * Oo0Ooo % i11iIiiIii
 if 12 - 12: oO0o . Oo0Ooo . I1IiiI - i11iIiiIii / o0oOOo0O0Ooo
 if 54 - 54: i11iIiiIii + I1Ii111 . I1Ii111 * I1ii11iIi11i % I1Ii111 - OoooooooOO
 if 76 - 76: IiII + i1IIi + i11iIiiIii . oO0o
 if 23 - 23: ooOoO0o - OoO0O00 + oO0o . OOooOOo - I1IiiI
def lisp_process_map_request ( lisp_sockets , packet , ecm_source , ecm_port ,
 mr_source , mr_port , ddt_request , ttl ) :
 if 66 - 66: iII111i % iII111i
 IIiIiIii11I1 = packet
 oooO0o = lisp_map_request ( )
 packet = oooO0o . decode ( packet , mr_source , mr_port )
 if ( packet == None ) :
  lprint ( "Could not decode Map-Request packet" )
  return
  if 95 - 95: OoO0O00 / o0oOOo0O0Ooo - i1IIi % Ii1I - o0oOOo0O0Ooo - o0oOOo0O0Ooo
  if 6 - 6: i1IIi
 oooO0o . print_map_request ( )
 if 10 - 10: OoO0O00 % iIii1I11I1II1 * OoOoOO00 / i11iIiiIii - I1IiiI . O0
 if 2 - 2: II111iiii
 if 13 - 13: Ii1I % i11iIiiIii
 if 3 - 3: ooOoO0o % OoOoOO00 * I1Ii111 - OoO0O00 / i1IIi % I1IiiI
 if ( oooO0o . rloc_probe ) :
  lisp_process_rloc_probe_request ( lisp_sockets , oooO0o ,
 mr_source , mr_port , ttl )
  return
  if 50 - 50: I1ii11iIi11i + iII111i
  if 64 - 64: oO0o
  if 11 - 11: o0oOOo0O0Ooo
  if 95 - 95: i1IIi . ooOoO0o . Oo0Ooo
  if 13 - 13: OOooOOo - Oo0Ooo % O0 . I1Ii111
 if ( oooO0o . smr_bit ) :
  lisp_process_smr ( oooO0o )
  if 66 - 66: I1IiiI + I11i
  if 58 - 58: I1ii11iIi11i
  if 7 - 7: oO0o - I11i
  if 59 - 59: Ii1I / o0oOOo0O0Ooo / OoO0O00 + IiII + i11iIiiIii
  if 64 - 64: o0oOOo0O0Ooo * IiII * IiII * iII111i % i11iIiiIii
 if ( oooO0o . smr_invoked_bit ) :
  lisp_process_smr_invoked_request ( oooO0o )
  if 22 - 22: I1ii11iIi11i * II111iiii - OOooOOo % i11iIiiIii
  if 10 - 10: OOooOOo / I1ii11iIi11i
  if 21 - 21: OoO0O00 % Oo0Ooo . o0oOOo0O0Ooo + IiII
  if 48 - 48: O0 / i1IIi / iII111i
  if 11 - 11: O0 - OoO0O00 + OoOoOO00 * ooOoO0o - Ii1I
 if ( lisp_i_am_etr ) :
  lisp_etr_process_map_request ( lisp_sockets , oooO0o , mr_source ,
 mr_port , ttl )
  if 82 - 82: Ii1I - O0 * ooOoO0o . ooOoO0o
  if 32 - 32: o0oOOo0O0Ooo . OoooooooOO % OOooOOo
  if 2 - 2: OoOoOO00 + I1ii11iIi11i + oO0o
  if 27 - 27: OoooooooOO - Ii1I / OoooooooOO + OoO0O00
  if 58 - 58: OOooOOo * I11i . I1IiiI
 if ( lisp_i_am_ms ) :
  packet = IIiIiIii11I1
  i1OO0o , O0oo0oo0 , I11i11 = lisp_ms_process_map_request ( lisp_sockets ,
 IIiIiIii11I1 , oooO0o , mr_source , mr_port , ecm_source )
  if ( ddt_request ) :
   lisp_ms_send_map_referral ( lisp_sockets , oooO0o , ecm_source ,
 ecm_port , I11i11 , i1OO0o , O0oo0oo0 )
   if 54 - 54: I11i / I1Ii111 - i11iIiiIii - o0oOOo0O0Ooo . Ii1I * iIii1I11I1II1
  return
  if 12 - 12: i1IIi + IiII / OoOoOO00 . OoO0O00 / ooOoO0o
  if 65 - 65: OoO0O00
  if 87 - 87: oO0o . I11i / IiII * OoO0O00 / OoooooooOO % OoOoOO00
  if 51 - 51: oO0o / IiII % Oo0Ooo
  if 69 - 69: I1ii11iIi11i % oO0o / iIii1I11I1II1 * OoOoOO00 % I1IiiI + IiII
 if ( lisp_i_am_mr and not ddt_request ) :
  lisp_mr_process_map_request ( lisp_sockets , IIiIiIii11I1 , oooO0o ,
 ecm_source , mr_port , mr_source )
  if 34 - 34: ooOoO0o - OoooooooOO . o0oOOo0O0Ooo
  if 83 - 83: II111iiii . OOooOOo
  if 88 - 88: O0
  if 12 - 12: Ii1I % OOooOOo % Oo0Ooo * I1Ii111
  if 96 - 96: iII111i + ooOoO0o
 if ( lisp_i_am_ddt or ddt_request ) :
  packet = IIiIiIii11I1
  lisp_ddt_process_map_request ( lisp_sockets , oooO0o , ecm_source ,
 ecm_port )
  if 100 - 100: OOooOOo . ooOoO0o + Ii1I + Ii1I
 return
 if 70 - 70: ooOoO0o . iIii1I11I1II1 / oO0o
 if 18 - 18: Ii1I / OoooooooOO % i1IIi * o0oOOo0O0Ooo
 if 70 - 70: IiII % i1IIi / IiII - o0oOOo0O0Ooo . Oo0Ooo / O0
 if 54 - 54: o0oOOo0O0Ooo
 if 53 - 53: II111iiii / IiII . i1IIi + I1Ii111 / OoO0O00 - OoooooooOO
 if 67 - 67: ooOoO0o . Ii1I - Oo0Ooo * iII111i . I11i - OOooOOo
 if 10 - 10: I11i
 if 37 - 37: o0oOOo0O0Ooo / I1IiiI * oO0o / II111iiii
def lisp_store_mr_stats ( source , nonce ) :
 oOO0O000OOo0 = lisp_get_map_resolver ( source , None )
 if ( oOO0O000OOo0 == None ) : return
 if 39 - 39: IiII - i1IIi - IiII - OoooooooOO - I1ii11iIi11i
 if 66 - 66: IiII + i1IIi
 if 21 - 21: IiII / i11iIiiIii / OoOoOO00
 if 75 - 75: Ii1I . i1IIi / I1IiiI * iII111i . IiII / OoOoOO00
 oOO0O000OOo0 . neg_map_replies_received += 1
 oOO0O000OOo0 . last_reply = lisp_get_timestamp ( )
 if 58 - 58: ooOoO0o + OOooOOo / ooOoO0o / i11iIiiIii
 if 95 - 95: ooOoO0o
 if 10 - 10: OoO0O00 % ooOoO0o * o0oOOo0O0Ooo
 if 37 - 37: Ii1I . o0oOOo0O0Ooo
 if ( ( oOO0O000OOo0 . neg_map_replies_received % 100 ) == 0 ) : oOO0O000OOo0 . total_rtt = 0
 if 34 - 34: ooOoO0o * IiII . Ii1I + iIii1I11I1II1
 if 1 - 1: i11iIiiIii + I11i
 if 78 - 78: Ii1I % Oo0Ooo / OoO0O00 . iIii1I11I1II1 . II111iiii
 if 67 - 67: oO0o % I1Ii111
 if ( oOO0O000OOo0 . last_nonce == nonce ) :
  oOO0O000OOo0 . total_rtt += ( time . time ( ) - oOO0O000OOo0 . last_used )
  oOO0O000OOo0 . last_nonce = 0
  if 72 - 72: I1IiiI . i11iIiiIii . OoOoOO00 + I1IiiI - I1Ii111 + iII111i
 if ( ( oOO0O000OOo0 . neg_map_replies_received % 10 ) == 0 ) : oOO0O000OOo0 . last_nonce = 0
 return
 if 15 - 15: I1IiiI
 if 88 - 88: IiII / I1ii11iIi11i % I11i + i11iIiiIii * O0 . I1Ii111
 if 69 - 69: Oo0Ooo - OOooOOo / I1IiiI . i11iIiiIii * OoO0O00
 if 45 - 45: I1Ii111 + OOooOOo
 if 78 - 78: OoOoOO00 . Oo0Ooo % I11i
 if 7 - 7: I1ii11iIi11i % Ii1I . OoooooooOO - iII111i
 if 18 - 18: O0 * OoooooooOO % IiII - iIii1I11I1II1 % IiII * o0oOOo0O0Ooo
def lisp_process_map_reply ( lisp_sockets , packet , source , ttl ) :
 global lisp_map_cache
 if 13 - 13: OoO0O00 + i11iIiiIii + O0 / ooOoO0o % iIii1I11I1II1
 iIi111 = lisp_map_reply ( )
 packet = iIi111 . decode ( packet )
 if ( packet == None ) :
  lprint ( "Could not decode Map-Reply packet" )
  return
  if 75 - 75: oO0o / i1IIi / Ii1I * Oo0Ooo
 iIi111 . print_map_reply ( )
 if 75 - 75: Oo0Ooo / OoooooooOO
 if 98 - 98: II111iiii - I1Ii111 . ooOoO0o * iII111i
 if 49 - 49: I1ii11iIi11i / OoooooooOO - I11i
 if 76 - 76: i1IIi . OoO0O00 . O0 / OOooOOo - iII111i
 oo00o = None
 for Ii11 in range ( iIi111 . record_count ) :
  OoOO = lisp_eid_record ( )
  packet = OoOO . decode ( packet )
  if ( packet == None ) :
   lprint ( "Could not decode EID-record in Map-Reply packet" )
   return
   if 68 - 68: I1IiiI - I1IiiI . I1Ii111 - OoooooooOO + O0 . II111iiii
  OoOO . print_record ( "  " , False )
  if 26 - 26: iIii1I11I1II1 / iIii1I11I1II1 . IiII * i11iIiiIii
  if 21 - 21: OOooOOo + o0oOOo0O0Ooo
  if 28 - 28: OOooOOo + i1IIi + II111iiii / Oo0Ooo + iIii1I11I1II1 . Oo0Ooo
  if 73 - 73: Ii1I * iIii1I11I1II1 / o0oOOo0O0Ooo - o0oOOo0O0Ooo / i1IIi
  if 64 - 64: Ii1I * I1ii11iIi11i % II111iiii
  if ( OoOO . rloc_count == 0 ) :
   lisp_store_mr_stats ( source , iIi111 . nonce )
   if 31 - 31: iIii1I11I1II1 % Oo0Ooo . I1IiiI % ooOoO0o
   if 38 - 38: I1ii11iIi11i + I1Ii111 * I11i / OoO0O00 + o0oOOo0O0Ooo
  iIiiIiI1I1ii = ( OoOO . group . is_null ( ) == False )
  if 63 - 63: Oo0Ooo / IiII % o0oOOo0O0Ooo + I1IiiI - iII111i / iII111i
  if 88 - 88: O0 * II111iiii
  if 81 - 81: OoOoOO00 % I11i / i1IIi
  if 87 - 87: II111iiii + oO0o - I1ii11iIi11i
  if 42 - 42: Oo0Ooo - ooOoO0o % OoOoOO00 + OoOoOO00
  if ( lisp_decent_push_configured ) :
   ooOOoo0 = OoOO . action
   if ( iIiiIiI1I1ii and ooOOoo0 == LISP_DROP_ACTION ) :
    if ( OoOO . eid . is_local ( ) ) : continue
    if 61 - 61: I1Ii111
    if 67 - 67: I1IiiI / IiII / iII111i - I1Ii111 - o0oOOo0O0Ooo
    if 75 - 75: OOooOOo . ooOoO0o
    if 32 - 32: i1IIi / I11i + iIii1I11I1II1 . OOooOOo
    if 67 - 67: iII111i - OoO0O00 % I1ii11iIi11i * Oo0Ooo
    if 51 - 51: I1IiiI + O0
    if 4 - 4: ooOoO0o / OoO0O00 * iIii1I11I1II1 * iIii1I11I1II1
  if ( OoOO . eid . is_null ( ) ) : continue
  if 33 - 33: iII111i . iIii1I11I1II1 - Ii1I
  if 85 - 85: OoOoOO00
  if 57 - 57: Oo0Ooo - II111iiii - I1ii11iIi11i * oO0o
  if 41 - 41: I11i / ooOoO0o + IiII % OoooooooOO
  if 72 - 72: Ii1I
  if ( iIiiIiI1I1ii ) :
   IIII = lisp_map_cache_lookup ( OoOO . eid , OoOO . group )
  else :
   IIII = lisp_map_cache . lookup_cache ( OoOO . eid , True )
   if 50 - 50: Ii1I . II111iiii * I11i
  oo0o0 = ( IIII == None )
  if 37 - 37: i1IIi
  if 87 - 87: I11i
  if 32 - 32: ooOoO0o + I1ii11iIi11i + OoooooooOO - o0oOOo0O0Ooo % IiII
  if 75 - 75: i1IIi + II111iiii
  oooo0O = [ ]
  for O0o0o00O in range ( OoOO . rloc_count ) :
   iI11iII1IiiI = lisp_rloc_record ( )
   iI11iII1IiiI . keys = iIi111 . keys
   packet = iI11iII1IiiI . decode ( packet , iIi111 . nonce )
   if ( packet == None ) :
    lprint ( "Could not decode RLOC-record in Map-Reply packet" )
    return
    if 20 - 20: IiII - OoO0O00 * I1Ii111
   iI11iII1IiiI . print_record ( "    " )
   if 51 - 51: I11i * ooOoO0o * OOooOOo / I1Ii111 * I1IiiI * ooOoO0o
   oO00Ooo0o = None
   if ( IIII ) : oO00Ooo0o = IIII . get_rloc ( iI11iII1IiiI . rloc )
   if ( oO00Ooo0o ) :
    OoOOo = oO00Ooo0o
   else :
    OoOOo = lisp_rloc ( )
    if 64 - 64: I11i * ooOoO0o / OoooooooOO
    if 38 - 38: iIii1I11I1II1 . OoO0O00 * OoOoOO00 + OoOoOO00 + ooOoO0o
    if 44 - 44: I1ii11iIi11i * OOooOOo % OoO0O00 . I1IiiI % Ii1I + II111iiii
    if 100 - 100: oO0o - II111iiii . o0oOOo0O0Ooo
    if 63 - 63: OoOoOO00 % IiII . iII111i
    if 44 - 44: I1IiiI
    if 25 - 25: oO0o
   IIiII = OoOOo . store_rloc_from_record ( iI11iII1IiiI , iIi111 . nonce ,
 source )
   OoOOo . echo_nonce_capable = iIi111 . echo_nonce_capable
   if 100 - 100: I1IiiI / IiII + OoO0O00 . iII111i
   if ( OoOOo . echo_nonce_capable ) :
    I1iiIiiii1111 = OoOOo . rloc . print_address_no_iid ( )
    if ( lisp_get_echo_nonce ( None , I1iiIiiii1111 ) == None ) :
     lisp_echo_nonce ( I1iiIiiii1111 )
     if 39 - 39: OoooooooOO * OOooOOo - OoO0O00
     if 3 - 3: I11i . i11iIiiIii % Oo0Ooo % II111iiii . I11i
     if 88 - 88: iIii1I11I1II1 . OOooOOo % iII111i
     if 72 - 72: ooOoO0o + i11iIiiIii / i1IIi
     if 64 - 64: OOooOOo - OOooOOo
     if 42 - 42: i1IIi / ooOoO0o . I1Ii111 % OoOoOO00
     if 67 - 67: i1IIi * i11iIiiIii * I1IiiI
   if ( IIII and IIII . gleaned ) :
    OoOOo = IIII . rloc_set [ 0 ]
    IIiII = OoOOo . translated_port
    if 23 - 23: Oo0Ooo
    if 81 - 81: I1Ii111 % II111iiii - Oo0Ooo / I1IiiI + i11iIiiIii . I11i
    if 67 - 67: ooOoO0o . I1Ii111 . Oo0Ooo . Ii1I + iIii1I11I1II1 / OoooooooOO
    if 93 - 93: ooOoO0o * OoO0O00 - I1Ii111 / I1ii11iIi11i
    if 60 - 60: OoO0O00 / oO0o . I1IiiI + OoOoOO00 + I1ii11iIi11i % Ii1I
    if 70 - 70: i1IIi * II111iiii * I1IiiI
    if 7 - 7: OoooooooOO + II111iiii % o0oOOo0O0Ooo * O0 . OoO0O00 * OoooooooOO
    if 20 - 20: Oo0Ooo % OOooOOo
    if 8 - 8: OOooOOo
   if ( iIi111 . rloc_probe and iI11iII1IiiI . probe_bit ) :
    if ( OoOOo . rloc . afi == source . afi ) :
     lisp_process_rloc_probe_reply ( OoOOo . rloc , source , IIiII ,
 iIi111 . nonce , iIi111 . hop_count , ttl )
     if 92 - 92: iII111i / OOooOOo . IiII / I11i + o0oOOo0O0Ooo
     if 99 - 99: II111iiii
     if 70 - 70: O0 % I1ii11iIi11i
     if 28 - 28: IiII - i1IIi - I1Ii111 % Ii1I - IiII
     if 73 - 73: iIii1I11I1II1 . iIii1I11I1II1 + oO0o % i11iIiiIii . IiII
     if 33 - 33: IiII - OOooOOo / i11iIiiIii * iIii1I11I1II1
   oooo0O . append ( OoOOo )
   if 2 - 2: i11iIiiIii % ooOoO0o
   if 56 - 56: IiII % ooOoO0o + I1IiiI % I11i - OOooOOo
   if 82 - 82: OoooooooOO . i1IIi . OoO0O00 . OoO0O00
   if 31 - 31: iIii1I11I1II1
   if ( lisp_data_plane_security and OoOOo . rloc_recent_rekey ( ) ) :
    oo00o = OoOOo
    if 64 - 64: ooOoO0o
    if 30 - 30: OoO0O00 + o0oOOo0O0Ooo / iIii1I11I1II1
    if 69 - 69: IiII - OoooooooOO + iII111i + iII111i - Ii1I
    if 27 - 27: I1ii11iIi11i % Oo0Ooo * iIii1I11I1II1 * O0 / I11i * Oo0Ooo
    if 97 - 97: IiII % Oo0Ooo % OoOoOO00
    if 87 - 87: i11iIiiIii . oO0o * I1IiiI * I1Ii111
    if 57 - 57: iIii1I11I1II1 / i11iIiiIii / IiII + I1ii11iIi11i % I1IiiI
    if 80 - 80: iIii1I11I1II1
    if 23 - 23: II111iiii . ooOoO0o % I1Ii111
    if 39 - 39: OoooooooOO
    if 10 - 10: Oo0Ooo * iII111i
  if ( iIi111 . rloc_probe == False and lisp_nat_traversal ) :
   oooOooO0 = [ ]
   oOOoo = [ ]
   for OoOOo in oooo0O :
    if 51 - 51: ooOoO0o / Oo0Ooo - I1Ii111 - iII111i
    if 68 - 68: I1ii11iIi11i - iIii1I11I1II1 * OoooooooOO
    if 44 - 44: OoooooooOO + I1Ii111 + OoO0O00
    if 15 - 15: iIii1I11I1II1 % i1IIi + iII111i
    if 48 - 48: o0oOOo0O0Ooo / oO0o
    if ( OoOOo . rloc . is_private_address ( ) ) :
     OoOOo . priority = 1
     OoOOo . state = LISP_RLOC_UNREACH_STATE
     oooOooO0 . append ( OoOOo )
     oOOoo . append ( OoOOo . rloc . print_address_no_iid ( ) )
     continue
     if 61 - 61: I1IiiI + iII111i * Ii1I % I1Ii111 . Ii1I
     if 83 - 83: i11iIiiIii * OoOoOO00 * i11iIiiIii % II111iiii . i11iIiiIii * I11i
     if 67 - 67: i1IIi / i1IIi + IiII . oO0o
     if 70 - 70: i1IIi . I11i * o0oOOo0O0Ooo . iII111i
     if 75 - 75: oO0o * OoO0O00 * I11i + oO0o + O0 . I1Ii111
     if 8 - 8: I1ii11iIi11i / i1IIi - I1ii11iIi11i + Ii1I + OoO0O00 - I11i
    if ( OoOOo . priority == 254 and lisp_i_am_rtr == False ) :
     oooOooO0 . append ( OoOOo )
     oOOoo . append ( OoOOo . rloc . print_address_no_iid ( ) )
     if 79 - 79: OoooooooOO - I1Ii111 * I1IiiI . I1Ii111 - iIii1I11I1II1
    if ( OoOOo . priority != 254 and lisp_i_am_rtr ) :
     oooOooO0 . append ( OoOOo )
     oOOoo . append ( OoOOo . rloc . print_address_no_iid ( ) )
     if 27 - 27: OoOoOO00 % OoOoOO00 % II111iiii
     if 45 - 45: iIii1I11I1II1 . o0oOOo0O0Ooo % I1IiiI
     if 10 - 10: I1IiiI / i1IIi * o0oOOo0O0Ooo + Oo0Ooo - OoOoOO00 % iII111i
   if ( oOOoo != [ ] ) :
    oooo0O = oooOooO0
    lprint ( "NAT-traversal optimized RLOC-set: {}" . format ( oOOoo ) )
    if 88 - 88: Ii1I % Ii1I
    if 29 - 29: OOooOOo % I1ii11iIi11i
    if 57 - 57: I1ii11iIi11i - OoOoOO00 + IiII
    if 58 - 58: OOooOOo % I1IiiI / oO0o . ooOoO0o . OoO0O00 / IiII
    if 72 - 72: ooOoO0o + ooOoO0o + o0oOOo0O0Ooo - o0oOOo0O0Ooo % Ii1I
    if 52 - 52: I11i % i1IIi . I1ii11iIi11i
    if 62 - 62: ooOoO0o - I1ii11iIi11i
  oooOooO0 = [ ]
  for OoOOo in oooo0O :
   if ( OoOOo . json != None ) : continue
   oooOooO0 . append ( OoOOo )
   if 71 - 71: I11i
  if ( oooOooO0 != [ ] ) :
   I1I11Iiii111 = len ( oooo0O ) - len ( oooOooO0 )
   lprint ( "Pruning {} no-address RLOC-records for map-cache" . format ( I1I11Iiii111 ) )
   if 34 - 34: oO0o / O0 * oO0o
   oooo0O = oooOooO0
   if 47 - 47: iIii1I11I1II1 - o0oOOo0O0Ooo % Ii1I
   if 38 - 38: ooOoO0o / IiII * I1ii11iIi11i % I1ii11iIi11i % oO0o
   if 82 - 82: I1ii11iIi11i . i11iIiiIii - I11i . iII111i / OOooOOo
   if 60 - 60: I1IiiI / I1IiiI / II111iiii
   if 59 - 59: OOooOOo . oO0o + ooOoO0o % o0oOOo0O0Ooo . i11iIiiIii
   if 27 - 27: OoOoOO00 - OoooooooOO / IiII / II111iiii * OOooOOo * ooOoO0o
   if 43 - 43: II111iiii . IiII - I1IiiI * I1ii11iIi11i + OoooooooOO
   if 34 - 34: I1Ii111 / i1IIi
  if ( iIi111 . rloc_probe and IIII != None ) : oooo0O = IIII . rloc_set
  if 95 - 95: OoOoOO00 * OOooOOo
  if 68 - 68: I1Ii111 / iIii1I11I1II1 % Ii1I
  if 77 - 77: i11iIiiIii + i11iIiiIii - I1ii11iIi11i % I1ii11iIi11i
  if 26 - 26: oO0o + OoooooooOO % o0oOOo0O0Ooo
  if 96 - 96: ooOoO0o * OoOoOO00 - II111iiii
  III1I111I1i1I = oo0o0
  if ( IIII and oooo0O != IIII . rloc_set ) :
   IIII . delete_rlocs_from_rloc_probe_list ( )
   III1I111I1i1I = True
   if 43 - 43: ooOoO0o / OoooooooOO . Oo0Ooo % ooOoO0o
   if 92 - 92: Oo0Ooo . I11i - IiII
   if 49 - 49: ooOoO0o . Ii1I
   if 75 - 75: OOooOOo / II111iiii - Oo0Ooo + I1Ii111
   if 42 - 42: OoooooooOO * II111iiii + Ii1I % OoO0O00 / I1Ii111
  I1II = IIII . uptime if ( IIII ) else None
  if ( IIII == None or IIII . gleaned == False ) :
   IIII = lisp_mapping ( OoOO . eid , OoOO . group , oooo0O )
   IIII . mapping_source = source
   IIII . map_cache_ttl = OoOO . store_ttl ( )
   IIII . action = OoOO . action
   IIII . add_cache ( III1I111I1i1I )
   if 30 - 30: i11iIiiIii * I1IiiI
   if 63 - 63: ooOoO0o + i11iIiiIii / i1IIi - I1Ii111 . O0 % OOooOOo
  i1111ii1 = "Add"
  if ( I1II ) :
   IIII . uptime = I1II
   i1111ii1 = "Replace"
   if 11 - 11: Ii1I - IiII
   if 20 - 20: I11i % oO0o * Oo0Ooo - I1Ii111 . Ii1I * I1ii11iIi11i
  lprint ( "{} {} map-cache with {} RLOCs" . format ( i1111ii1 ,
 green ( IIII . print_eid_tuple ( ) , False ) , len ( oooo0O ) ) )
  if 59 - 59: OoOoOO00 + Oo0Ooo . I1ii11iIi11i - Ii1I
  if 48 - 48: I1Ii111 % Ii1I + I1IiiI * OoooooooOO % OoOoOO00 % i11iIiiIii
  if 13 - 13: iII111i % i1IIi
  if 13 - 13: iII111i / OoooooooOO + Ii1I / iII111i
  if 29 - 29: OOooOOo + ooOoO0o % o0oOOo0O0Ooo
  if ( lisp_ipc_dp_socket and oo00o != None ) :
   lisp_write_ipc_keys ( oo00o )
   if 18 - 18: I11i + OoO0O00 + OoO0O00 . ooOoO0o
   if 37 - 37: i1IIi . IiII + I1IiiI % OoOoOO00
   if 3 - 3: i11iIiiIii + Ii1I % IiII - I1Ii111 / Oo0Ooo % iIii1I11I1II1
   if 86 - 86: Oo0Ooo + Oo0Ooo * oO0o * I1IiiI
   if 95 - 95: IiII - OoO0O00 + OOooOOo
   if 33 - 33: o0oOOo0O0Ooo . i11iIiiIii . ooOoO0o
   if 100 - 100: i11iIiiIii % I1Ii111 - OoO0O00 + I1Ii111 / i11iIiiIii + OOooOOo
  if ( oo0o0 ) :
   Ooo0O = bold ( "RLOC-probe" , False )
   for OoOOo in IIII . best_rloc_set :
    I1iiIiiii1111 = red ( OoOOo . rloc . print_address_no_iid ( ) , False )
    lprint ( "Trigger {} to {}" . format ( Ooo0O , I1iiIiiii1111 ) )
    lisp_send_map_request ( lisp_sockets , 0 , IIII . eid , IIII . group , OoOOo )
    if 69 - 69: iII111i - OoOoOO00 / O0
    if 22 - 22: o0oOOo0O0Ooo % OoooooooOO + oO0o + Oo0Ooo
    if 34 - 34: iII111i / I11i + i1IIi + I1ii11iIi11i * OoooooooOO * IiII
 return
 if 70 - 70: iIii1I11I1II1 / I1IiiI * OoOoOO00 / IiII / II111iiii + I1IiiI
 if 33 - 33: oO0o
 if 1 - 1: OoOoOO00 . i11iIiiIii % I1Ii111 + OoooooooOO - Oo0Ooo . I1ii11iIi11i
 if 46 - 46: i11iIiiIii + I11i - iIii1I11I1II1 / OoO0O00 - ooOoO0o / i1IIi
 if 44 - 44: o0oOOo0O0Ooo + Oo0Ooo
 if 46 - 46: OOooOOo % I1IiiI
 if 66 - 66: iIii1I11I1II1 . o0oOOo0O0Ooo - ooOoO0o
 if 27 - 27: Oo0Ooo - i1IIi * OoooooooOO - OoOoOO00 + OoOoOO00
def lisp_compute_auth ( packet , map_register , password ) :
 if ( map_register . alg_id == LISP_NONE_ALG_ID ) : return ( packet )
 if 24 - 24: i1IIi . OoOoOO00 / I1Ii111 + O0
 packet = map_register . zero_auth ( packet )
 IiiiI1I1iI11 = lisp_hash_me ( packet , map_register . alg_id , password , False )
 if 86 - 86: Ii1I * OoOoOO00 % I1ii11iIi11i + OOooOOo
 if 85 - 85: iII111i % i11iIiiIii
 if 78 - 78: i11iIiiIii / I11i / Oo0Ooo + II111iiii - I1ii11iIi11i / I1ii11iIi11i
 if 28 - 28: iIii1I11I1II1 / IiII - iIii1I11I1II1 . i1IIi - O0 * ooOoO0o
 map_register . auth_data = IiiiI1I1iI11
 packet = map_register . encode_auth ( packet )
 return ( packet )
 if 41 - 41: Ii1I + IiII
 if 37 - 37: I1Ii111 / o0oOOo0O0Ooo - ooOoO0o - OoooooooOO . I1ii11iIi11i % I1Ii111
 if 53 - 53: I1IiiI % OOooOOo + Ii1I - Ii1I
 if 99 - 99: i1IIi * OoOoOO00 - i1IIi
 if 65 - 65: OoO0O00 / i11iIiiIii + I1ii11iIi11i + OoOoOO00
 if 82 - 82: Ii1I * OOooOOo % ooOoO0o / OoO0O00 - Oo0Ooo . I1Ii111
 if 90 - 90: I11i * i11iIiiIii % i1IIi + I1Ii111 / OoO0O00
def lisp_hash_me ( packet , alg_id , password , do_hex ) :
 if ( alg_id == LISP_NONE_ALG_ID ) : return ( True )
 if 15 - 15: Oo0Ooo + oO0o . I11i % OoO0O00
 if ( alg_id == LISP_SHA_1_96_ALG_ID ) :
  iI111iI1I1I111 = hashlib . sha1
  if 31 - 31: Ii1I % iII111i % Oo0Ooo
 if ( alg_id == LISP_SHA_256_128_ALG_ID ) :
  iI111iI1I1I111 = hashlib . sha256
  if 75 - 75: iIii1I11I1II1 - IiII - I1Ii111
  if 4 - 4: i11iIiiIii % OoooooooOO . i11iIiiIii
 if ( do_hex ) :
  IiiiI1I1iI11 = hmac . new ( password , packet , iI111iI1I1I111 ) . hexdigest ( )
 else :
  IiiiI1I1iI11 = hmac . new ( password , packet , iI111iI1I1I111 ) . digest ( )
  if 61 - 61: iIii1I11I1II1 . Oo0Ooo . i1IIi
 return ( IiiiI1I1iI11 )
 if 45 - 45: I1Ii111
 if 49 - 49: i1IIi * iII111i - iIii1I11I1II1 % I11i * O0 / OoOoOO00
 if 48 - 48: IiII
 if 69 - 69: o0oOOo0O0Ooo % i11iIiiIii - OOooOOo - o0oOOo0O0Ooo
 if 98 - 98: o0oOOo0O0Ooo * OoO0O00 . OoooooooOO
 if 40 - 40: I1Ii111 + Oo0Ooo + I1Ii111
 if 57 - 57: I1Ii111 / II111iiii % iII111i
 if 32 - 32: IiII - OOooOOo + i11iIiiIii + I1IiiI . iII111i
def lisp_verify_auth ( packet , alg_id , auth_data , password ) :
 if ( alg_id == LISP_NONE_ALG_ID ) : return ( True )
 if 75 - 75: o0oOOo0O0Ooo % o0oOOo0O0Ooo . I1IiiI / OoO0O00
 IiiiI1I1iI11 = lisp_hash_me ( packet , alg_id , password , True )
 iIIiI = ( IiiiI1I1iI11 == auth_data )
 if 16 - 16: II111iiii . Ii1I + I1Ii111 % i1IIi / i11iIiiIii + OOooOOo
 if 43 - 43: I1IiiI . Oo0Ooo + i1IIi + I11i / OoO0O00
 if 66 - 66: i11iIiiIii
 if 83 - 83: I1Ii111 / iIii1I11I1II1 - oO0o
 if ( iIIiI == False ) :
  lprint ( "Hashed value: {} does not match packet value: {}" . format ( IiiiI1I1iI11 , auth_data ) )
  if 3 - 3: OOooOOo - Oo0Ooo * I1IiiI - OoO0O00 / OOooOOo + IiII
  if 83 - 83: i1IIi * i1IIi - II111iiii / OoooooooOO . Ii1I + I1Ii111
 return ( iIIiI )
 if 10 - 10: I11i
 if 24 - 24: Ii1I
 if 30 - 30: II111iiii / Ii1I - I11i - OoO0O00
 if 25 - 25: I11i % i1IIi / I11i * i11iIiiIii
 if 71 - 71: IiII % I11i - OoooooooOO + I1IiiI / Oo0Ooo % I11i
 if 6 - 6: i1IIi * i11iIiiIii + ooOoO0o - IiII
 if 97 - 97: iIii1I11I1II1 * i1IIi * II111iiii - OOooOOo - Oo0Ooo - iIii1I11I1II1
def lisp_retransmit_map_notify ( map_notify ) :
 iI111I1 = map_notify . etr
 IIiII = map_notify . etr_port
 if 26 - 26: ooOoO0o + Oo0Ooo
 if 24 - 24: I1IiiI
 if 43 - 43: OoO0O00
 if 51 - 51: OoooooooOO % IiII % Oo0Ooo
 if 50 - 50: I1IiiI - i11iIiiIii / I1ii11iIi11i . Ii1I - iIii1I11I1II1
 if ( map_notify . retry_count == LISP_MAX_MAP_NOTIFY_RETRIES ) :
  lprint ( "Map-Notify with nonce 0x{} retry limit reached for ETR {}" . format ( map_notify . nonce_key , red ( iI111I1 . print_address ( ) , False ) ) )
  if 91 - 91: I1IiiI . I1Ii111 + II111iiii . Oo0Ooo
  if 95 - 95: iII111i
  iii11 = map_notify . nonce_key
  if ( lisp_map_notify_queue . has_key ( iii11 ) ) :
   map_notify . retransmit_timer . cancel ( )
   lprint ( "Dequeue Map-Notify from retransmit queue, key is: {}" . format ( iii11 ) )
   if 77 - 77: I1IiiI * II111iiii * iIii1I11I1II1
   try :
    lisp_map_notify_queue . pop ( iii11 )
   except :
    lprint ( "Key not found in Map-Notify queue" )
    if 19 - 19: OOooOOo * o0oOOo0O0Ooo
    if 64 - 64: I11i % ooOoO0o / OOooOOo / iII111i
  return
  if 80 - 80: i1IIi
  if 74 - 74: I1ii11iIi11i . OoO0O00 + i11iIiiIii
 o0o0oO = map_notify . lisp_sockets
 map_notify . retry_count += 1
 if 19 - 19: i1IIi / I1IiiI + IiII . iII111i
 lprint ( "Retransmit {} with nonce 0x{} to xTR {}, retry {}" . format ( bold ( "Map-Notify" , False ) , map_notify . nonce_key ,
 # iII111i . OOooOOo / II111iiii / II111iiii % Ii1I
 red ( iI111I1 . print_address ( ) , False ) , map_notify . retry_count ) )
 if 44 - 44: Oo0Ooo
 lisp_send_map_notify ( o0o0oO , map_notify . packet , iI111I1 , IIiII )
 if ( map_notify . site ) : map_notify . site . map_notifies_sent += 1
 if 29 - 29: O0 + OoooooooOO
 if 82 - 82: O0 . I1Ii111 - IiII
 if 37 - 37: i11iIiiIii
 if 67 - 67: ooOoO0o . Oo0Ooo
 map_notify . retransmit_timer = threading . Timer ( LISP_MAP_NOTIFY_INTERVAL ,
 lisp_retransmit_map_notify , [ map_notify ] )
 map_notify . retransmit_timer . start ( )
 return
 if 15 - 15: OoO0O00 . oO0o - o0oOOo0O0Ooo
 if 28 - 28: OOooOOo * OoOoOO00 + OoooooooOO . OOooOOo / oO0o / OoOoOO00
 if 94 - 94: OoO0O00 / i1IIi . OoO0O00 . I1Ii111 + OoO0O00
 if 30 - 30: o0oOOo0O0Ooo + iIii1I11I1II1 - II111iiii - ooOoO0o + OoOoOO00 - II111iiii
 if 69 - 69: oO0o / O0 / I1IiiI + OoooooooOO * I11i * IiII
 if 41 - 41: ooOoO0o % i11iIiiIii
 if 69 - 69: IiII - oO0o
def lisp_send_merged_map_notify ( lisp_sockets , parent , map_register ,
 eid_record ) :
 if 21 - 21: Oo0Ooo / I1Ii111
 if 72 - 72: OoOoOO00 . i11iIiiIii
 if 25 - 25: i1IIi
 if 69 - 69: OOooOOo / Ii1I
 eid_record . rloc_count = len ( parent . registered_rlocs )
 OoOIII = eid_record . encode ( )
 eid_record . print_record ( "Merged Map-Notify " , False )
 if 87 - 87: o0oOOo0O0Ooo / I1Ii111 % Oo0Ooo - iIii1I11I1II1 / IiII / IiII
 if 57 - 57: OoOoOO00 . O0 / iII111i / i11iIiiIii
 if 38 - 38: iII111i - Oo0Ooo / O0
 if 40 - 40: ooOoO0o + iIii1I11I1II1 / OoOoOO00 * iIii1I11I1II1 - ooOoO0o * iIii1I11I1II1
 for O0O in parent . registered_rlocs :
  iI11iII1IiiI = lisp_rloc_record ( )
  iI11iII1IiiI . store_rloc_entry ( O0O )
  OoOIII += iI11iII1IiiI . encode ( )
  iI11iII1IiiI . print_record ( "  " )
  del ( iI11iII1IiiI )
  if 65 - 65: I1IiiI % iIii1I11I1II1 * II111iiii . IiII . IiII * OoOoOO00
  if 66 - 66: IiII % I1ii11iIi11i . oO0o
  if 65 - 65: o0oOOo0O0Ooo * OoO0O00
  if 38 - 38: I1ii11iIi11i / I1ii11iIi11i % I1Ii111 % i11iIiiIii . OoOoOO00 * OoooooooOO
  if 53 - 53: II111iiii . i11iIiiIii / oO0o - i11iIiiIii * iII111i . I11i
 for O0O in parent . registered_rlocs :
  iI111I1 = O0O . rloc
  iiIi11I = lisp_map_notify ( lisp_sockets )
  iiIi11I . record_count = 1
  I1o0 = map_register . key_id
  iiIi11I . key_id = I1o0
  iiIi11I . alg_id = map_register . alg_id
  iiIi11I . auth_len = map_register . auth_len
  iiIi11I . nonce = map_register . nonce
  iiIi11I . nonce_key = lisp_hex_string ( iiIi11I . nonce )
  iiIi11I . etr . copy_address ( iI111I1 )
  iiIi11I . etr_port = map_register . sport
  iiIi11I . site = parent . site
  i1II1IiiIi = iiIi11I . encode ( OoOIII , parent . site . auth_key [ I1o0 ] )
  iiIi11I . print_notify ( )
  if 53 - 53: OoooooooOO - OoOoOO00 / IiII - I1Ii111
  if 16 - 16: iIii1I11I1II1 / OOooOOo + I1IiiI * II111iiii . OOooOOo
  if 68 - 68: IiII * IiII + oO0o / o0oOOo0O0Ooo
  if 41 - 41: OoOoOO00 - O0
  iii11 = iiIi11I . nonce_key
  if ( lisp_map_notify_queue . has_key ( iii11 ) ) :
   Ii11iIIIII1 = lisp_map_notify_queue [ iii11 ]
   Ii11iIIIII1 . retransmit_timer . cancel ( )
   del ( Ii11iIIIII1 )
   if 65 - 65: I1Ii111 / o0oOOo0O0Ooo - i11iIiiIii + I11i
  lisp_map_notify_queue [ iii11 ] = iiIi11I
  if 75 - 75: O0 - OoO0O00 / oO0o . i1IIi . I1ii11iIi11i + o0oOOo0O0Ooo
  if 29 - 29: Ii1I . OOooOOo
  if 59 - 59: O0 . OoO0O00
  if 10 - 10: I1Ii111 / OoooooooOO / OoO0O00 * ooOoO0o
  lprint ( "Send merged Map-Notify to ETR {}" . format ( red ( iI111I1 . print_address ( ) , False ) ) )
  if 81 - 81: i1IIi % I11i * iIii1I11I1II1
  lisp_send ( lisp_sockets , iI111I1 , LISP_CTRL_PORT , i1II1IiiIi )
  if 39 - 39: iIii1I11I1II1 / O0 . OoooooooOO - O0 . OoO0O00 . oO0o
  parent . site . map_notifies_sent += 1
  if 59 - 59: II111iiii * I1IiiI
  if 12 - 12: i11iIiiIii - IiII . iII111i . Ii1I
  if 34 - 34: i1IIi % iII111i + Oo0Ooo * OoOoOO00 + OoO0O00
  if 37 - 37: I1Ii111 / OoooooooOO
  iiIi11I . retransmit_timer = threading . Timer ( LISP_MAP_NOTIFY_INTERVAL ,
 lisp_retransmit_map_notify , [ iiIi11I ] )
  iiIi11I . retransmit_timer . start ( )
  if 19 - 19: Ii1I - O0 + I1IiiI + OoooooooOO + ooOoO0o - Oo0Ooo
 return
 if 45 - 45: I1IiiI . OoOoOO00 . OoOoOO00
 if 20 - 20: OoOoOO00
 if 69 - 69: OoOoOO00 * Ii1I % ooOoO0o . OoOoOO00 / oO0o * I1Ii111
 if 93 - 93: OoO0O00 % IiII % ooOoO0o . I1IiiI
 if 96 - 96: II111iiii
 if 73 - 73: II111iiii
 if 81 - 81: I1IiiI + OoO0O00
def lisp_build_map_notify ( lisp_sockets , eid_records , eid_list , record_count ,
 source , port , nonce , key_id , alg_id , auth_len , site , map_register_ack ) :
 if 22 - 22: OoO0O00 * OoOoOO00 * I11i * IiII . OoO0O00 . I1ii11iIi11i
 iii11 = lisp_hex_string ( nonce ) + source . print_address ( )
 if 32 - 32: o0oOOo0O0Ooo - iII111i + i11iIiiIii / ooOoO0o . OoOoOO00 . IiII
 if 9 - 9: iIii1I11I1II1
 if 66 - 66: iIii1I11I1II1
 if 13 - 13: O0 / ooOoO0o
 if 64 - 64: i11iIiiIii + I1IiiI / Oo0Ooo - iII111i
 if 26 - 26: I1ii11iIi11i
 lisp_remove_eid_from_map_notify_queue ( eid_list )
 if ( lisp_map_notify_queue . has_key ( iii11 ) ) :
  iiIi11I = lisp_map_notify_queue [ iii11 ]
  IiIIi1I1I11Ii = red ( source . print_address_no_iid ( ) , False )
  lprint ( "Map-Notify with nonce 0x{} pending for xTR {}" . format ( lisp_hex_string ( iiIi11I . nonce ) , IiIIi1I1I11Ii ) )
  if 67 - 67: I1Ii111 * iIii1I11I1II1 / O0 + OoO0O00 * iIii1I11I1II1 % II111iiii
  return
  if 13 - 13: Ii1I / ooOoO0o / iII111i % II111iiii * I1IiiI * II111iiii
  if 40 - 40: Ii1I / i1IIi . iII111i
 iiIi11I = lisp_map_notify ( lisp_sockets )
 iiIi11I . record_count = record_count
 key_id = key_id
 iiIi11I . key_id = key_id
 iiIi11I . alg_id = alg_id
 iiIi11I . auth_len = auth_len
 iiIi11I . nonce = nonce
 iiIi11I . nonce_key = lisp_hex_string ( nonce )
 iiIi11I . etr . copy_address ( source )
 iiIi11I . etr_port = port
 iiIi11I . site = site
 iiIi11I . eid_list = eid_list
 if 65 - 65: iIii1I11I1II1 * O0 . II111iiii * o0oOOo0O0Ooo . I1ii11iIi11i * I1IiiI
 if 63 - 63: II111iiii . Oo0Ooo % iIii1I11I1II1
 if 85 - 85: I1IiiI + i1IIi % I1Ii111
 if 76 - 76: i11iIiiIii % i11iIiiIii
 if ( map_register_ack == False ) :
  iii11 = iiIi11I . nonce_key
  lisp_map_notify_queue [ iii11 ] = iiIi11I
  if 33 - 33: OOooOOo . ooOoO0o / iIii1I11I1II1 * OOooOOo / oO0o
  if 75 - 75: Ii1I - OoOoOO00 . OOooOOo - o0oOOo0O0Ooo - I1ii11iIi11i
 if ( map_register_ack ) :
  lprint ( "Send Map-Notify to ack Map-Register" )
 else :
  lprint ( "Send Map-Notify for RLOC-set change" )
  if 69 - 69: O0 % I1ii11iIi11i
  if 77 - 77: iIii1I11I1II1 . OOooOOo
  if 64 - 64: OoOoOO00 - i1IIi * i1IIi / iII111i * OoOoOO00 * OoO0O00
  if 61 - 61: OOooOOo
  if 51 - 51: Oo0Ooo * OOooOOo / iII111i
 i1II1IiiIi = iiIi11I . encode ( eid_records , site . auth_key [ key_id ] )
 iiIi11I . print_notify ( )
 if 49 - 49: ooOoO0o . i1IIi % I1Ii111 . I1IiiI . I1ii11iIi11i + OoO0O00
 if ( map_register_ack == False ) :
  OoOO = lisp_eid_record ( )
  OoOO . decode ( eid_records )
  OoOO . print_record ( "  " , False )
  if 65 - 65: I1ii11iIi11i + Ii1I / i11iIiiIii * I1Ii111 + OoooooooOO
  if 7 - 7: Oo0Ooo % o0oOOo0O0Ooo
  if 40 - 40: oO0o * IiII
  if 29 - 29: O0 - II111iiii + iII111i
  if 73 - 73: I1Ii111 - I11i + IiII - o0oOOo0O0Ooo - I11i - OOooOOo
 lisp_send_map_notify ( lisp_sockets , i1II1IiiIi , iiIi11I . etr , port )
 site . map_notifies_sent += 1
 if 40 - 40: iIii1I11I1II1 . iII111i * I1ii11iIi11i + IiII - iIii1I11I1II1
 if ( map_register_ack ) : return
 if 83 - 83: i1IIi
 if 9 - 9: iIii1I11I1II1 + i11iIiiIii
 if 70 - 70: I1IiiI - OoO0O00 % OOooOOo + ooOoO0o % II111iiii
 if 19 - 19: I11i + i1IIi / i1IIi - II111iiii + I1Ii111
 if 11 - 11: i11iIiiIii % i11iIiiIii / IiII - Oo0Ooo / O0 - I11i
 if 29 - 29: OOooOOo * iIii1I11I1II1 * ooOoO0o
 iiIi11I . retransmit_timer = threading . Timer ( LISP_MAP_NOTIFY_INTERVAL ,
 lisp_retransmit_map_notify , [ iiIi11I ] )
 iiIi11I . retransmit_timer . start ( )
 return
 if 80 - 80: oO0o * I1Ii111
 if 87 - 87: iII111i + OoOoOO00 % ooOoO0o - oO0o
 if 40 - 40: i1IIi / OoOoOO00 - I11i / ooOoO0o . Ii1I
 if 8 - 8: I1IiiI . IiII . OOooOOo . O0
 if 3 - 3: Ii1I + i11iIiiIii
 if 87 - 87: ooOoO0o - iII111i % I11i
 if 88 - 88: I11i . OoooooooOO
 if 86 - 86: Ii1I - I1IiiI - iII111i % Ii1I . I1ii11iIi11i % i1IIi
def lisp_send_map_notify_ack ( lisp_sockets , eid_records , map_notify , ms ) :
 map_notify . map_notify_ack = True
 if 84 - 84: OoOoOO00
 if 99 - 99: OoO0O00 - OoOoOO00 - i1IIi / OoO0O00 * I1ii11iIi11i * iIii1I11I1II1
 if 65 - 65: iII111i - O0 / i1IIi . I1Ii111
 if 85 - 85: o0oOOo0O0Ooo % Ii1I
 i1II1IiiIi = map_notify . encode ( eid_records , ms . password )
 map_notify . print_notify ( )
 if 81 - 81: oO0o / OoO0O00 * i1IIi % iIii1I11I1II1
 if 23 - 23: II111iiii . II111iiii
 if 17 - 17: i11iIiiIii / IiII * I1IiiI . Oo0Ooo / o0oOOo0O0Ooo - iIii1I11I1II1
 if 21 - 21: OOooOOo % Ii1I
 iI111I1 = ms . map_server
 lprint ( "Send Map-Notify-Ack to {}" . format (
 red ( iI111I1 . print_address ( ) , False ) ) )
 lisp_send ( lisp_sockets , iI111I1 , LISP_CTRL_PORT , i1II1IiiIi )
 return
 if 3 - 3: OOooOOo / ooOoO0o / I1Ii111 . I11i
 if 54 - 54: I1ii11iIi11i - I1IiiI . OoOoOO00
 if 36 - 36: OoO0O00 * I1IiiI / iII111i
 if 95 - 95: Ii1I . Oo0Ooo
 if 42 - 42: IiII . i1IIi % O0 * ooOoO0o - OOooOOo % ooOoO0o
 if 99 - 99: i1IIi + OoOoOO00 - iII111i % II111iiii
 if 6 - 6: ooOoO0o - I1Ii111 . OoOoOO00
 if 64 - 64: iII111i + I1ii11iIi11i
def lisp_send_multicast_map_notify ( lisp_sockets , site_eid , eid_list , xtr ) :
 if 88 - 88: I1Ii111 / i11iIiiIii - O0 . II111iiii / II111iiii * II111iiii
 iiIi11I = lisp_map_notify ( lisp_sockets )
 iiIi11I . record_count = 1
 iiIi11I . nonce = lisp_get_control_nonce ( )
 iiIi11I . nonce_key = lisp_hex_string ( iiIi11I . nonce )
 iiIi11I . etr . copy_address ( xtr )
 iiIi11I . etr_port = LISP_CTRL_PORT
 iiIi11I . eid_list = eid_list
 iii11 = iiIi11I . nonce_key
 if 56 - 56: Oo0Ooo / I1IiiI % I1Ii111 % I1ii11iIi11i * I1IiiI - IiII
 if 39 - 39: oO0o + iII111i . I1Ii111 * i11iIiiIii % o0oOOo0O0Ooo + OOooOOo
 if 61 - 61: ooOoO0o / I1Ii111 / I1ii11iIi11i - Ii1I % o0oOOo0O0Ooo * iII111i
 if 94 - 94: I1IiiI / I11i
 if 100 - 100: Ii1I % OoO0O00 % OoooooooOO / II111iiii * I1Ii111
 if 64 - 64: I1Ii111 * OOooOOo * Ii1I + I1ii11iIi11i / iIii1I11I1II1 / Oo0Ooo
 lisp_remove_eid_from_map_notify_queue ( iiIi11I . eid_list )
 if ( lisp_map_notify_queue . has_key ( iii11 ) ) :
  iiIi11I = lisp_map_notify_queue [ iii11 ]
  lprint ( "Map-Notify with nonce 0x{} pending for ITR {}" . format ( iiIi11I . nonce , red ( xtr . print_address_no_iid ( ) , False ) ) )
  if 50 - 50: OOooOOo % i11iIiiIii
  return
  if 99 - 99: IiII
  if 87 - 87: IiII
  if 35 - 35: oO0o . O0 . Ii1I / ooOoO0o
  if 36 - 36: i11iIiiIii . II111iiii . I11i . II111iiii
  if 36 - 36: Ii1I + ooOoO0o / Oo0Ooo % Oo0Ooo
 lisp_map_notify_queue [ iii11 ] = iiIi11I
 if 2 - 2: oO0o - Oo0Ooo * OoO0O00 . ooOoO0o . OOooOOo - oO0o
 if 74 - 74: o0oOOo0O0Ooo
 if 18 - 18: Oo0Ooo % OOooOOo / OOooOOo . I1IiiI + i1IIi . I1IiiI
 if 3 - 3: O0 * O0 + II111iiii + OoOoOO00 * I11i % Oo0Ooo
 II111iiIIiI = site_eid . rtrs_in_rloc_set ( )
 if ( II111iiIIiI ) :
  if ( site_eid . is_rtr_in_rloc_set ( xtr ) ) : II111iiIIiI = False
  if 97 - 97: o0oOOo0O0Ooo
  if 93 - 93: II111iiii - Ii1I
  if 65 - 65: II111iiii % I1Ii111 / OoooooooOO - IiII
  if 7 - 7: Ii1I
  if 25 - 25: I1Ii111 . II111iiii % OoOoOO00
 OoOO = lisp_eid_record ( )
 OoOO . record_ttl = 1440
 OoOO . eid . copy_address ( site_eid . eid )
 OoOO . group . copy_address ( site_eid . group )
 OoOO . rloc_count = 0
 for IiI1I1iii11 in site_eid . registered_rlocs :
  if ( II111iiIIiI ^ IiI1I1iii11 . is_rtr ( ) ) : continue
  OoOO . rloc_count += 1
  if 72 - 72: I1ii11iIi11i . I1IiiI % I11i - iII111i / ooOoO0o
 i1II1IiiIi = OoOO . encode ( )
 if 91 - 91: IiII / I1IiiI - Ii1I + o0oOOo0O0Ooo
 if 90 - 90: I1ii11iIi11i * oO0o
 if 29 - 29: OoOoOO00 % ooOoO0o . OoOoOO00 % OOooOOo - OoOoOO00
 if 81 - 81: i1IIi + I1IiiI - iIii1I11I1II1 / O0 . iIii1I11I1II1 - iIii1I11I1II1
 iiIi11I . print_notify ( )
 OoOO . print_record ( "  " , False )
 if 54 - 54: iII111i + OOooOOo + OoO0O00
 if 6 - 6: oO0o - OoooooooOO * iIii1I11I1II1 * I1ii11iIi11i
 if 65 - 65: IiII + OoOoOO00
 if 93 - 93: Ii1I
 for IiI1I1iii11 in site_eid . registered_rlocs :
  if ( II111iiIIiI ^ IiI1I1iii11 . is_rtr ( ) ) : continue
  iI11iII1IiiI = lisp_rloc_record ( )
  iI11iII1IiiI . store_rloc_entry ( IiI1I1iii11 )
  i1II1IiiIi += iI11iII1IiiI . encode ( )
  iI11iII1IiiI . print_record ( "    " )
  if 43 - 43: iIii1I11I1II1 / iII111i - Ii1I + I11i % iII111i - OoO0O00
  if 5 - 5: OoO0O00 / ooOoO0o
  if 92 - 92: Oo0Ooo / iII111i + O0 * ooOoO0o * OOooOOo % Oo0Ooo
  if 97 - 97: oO0o / Ii1I
  if 70 - 70: iII111i / Oo0Ooo . OoOoOO00 - II111iiii * II111iiii % I1IiiI
 i1II1IiiIi = iiIi11I . encode ( i1II1IiiIi , "" )
 if ( i1II1IiiIi == None ) : return
 if 34 - 34: I1Ii111 + OOooOOo * iII111i / ooOoO0o % i11iIiiIii
 if 91 - 91: IiII * Ii1I * OOooOOo
 if 17 - 17: o0oOOo0O0Ooo + Ii1I % I1ii11iIi11i + IiII % I1Ii111 + I1ii11iIi11i
 if 100 - 100: I11i * OoO0O00 - i1IIi + iII111i * Ii1I - OoooooooOO
 lisp_send_map_notify ( lisp_sockets , i1II1IiiIi , xtr , LISP_CTRL_PORT )
 if 47 - 47: o0oOOo0O0Ooo / Ii1I - iII111i * OOooOOo / i11iIiiIii
 if 97 - 97: iIii1I11I1II1 + OoOoOO00 + OoOoOO00 * o0oOOo0O0Ooo
 if 14 - 14: II111iiii + I1ii11iIi11i * Oo0Ooo
 if 95 - 95: IiII + iII111i % I1IiiI
 iiIi11I . retransmit_timer = threading . Timer ( LISP_MAP_NOTIFY_INTERVAL ,
 lisp_retransmit_map_notify , [ iiIi11I ] )
 iiIi11I . retransmit_timer . start ( )
 return
 if 18 - 18: Oo0Ooo
 if 8 - 8: O0 + iIii1I11I1II1 - O0
 if 67 - 67: O0
 if 22 - 22: I11i / i1IIi . II111iiii % ooOoO0o / I11i - Ii1I
 if 28 - 28: O0 - Oo0Ooo
 if 58 - 58: iIii1I11I1II1 - OoooooooOO - iII111i
 if 43 - 43: ooOoO0o / o0oOOo0O0Ooo
def lisp_queue_multicast_map_notify ( lisp_sockets , rle_list ) :
 Oo0Oooo00O00 = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
 if 100 - 100: OoO0O00 + I1ii11iIi11i + I1ii11iIi11i . I1Ii111
 for OOoo in rle_list :
  OO00 = lisp_site_eid_lookup ( OOoo [ 0 ] , OOoo [ 1 ] , True )
  if ( OO00 == None ) : continue
  if 89 - 89: o0oOOo0O0Ooo . Oo0Ooo
  if 48 - 48: o0oOOo0O0Ooo / O0 % i1IIi
  if 82 - 82: OoOoOO00 * Ii1I . I1ii11iIi11i * OoO0O00 % Oo0Ooo
  if 95 - 95: OoO0O00 / oO0o
  if 15 - 15: I1IiiI - o0oOOo0O0Ooo % iIii1I11I1II1 % I11i * OoOoOO00 % IiII
  if 74 - 74: iII111i - O0 * o0oOOo0O0Ooo / OoooooooOO + II111iiii + Ii1I
  if 39 - 39: i11iIiiIii . IiII + I1ii11iIi11i % IiII
  o0oo = OO00 . registered_rlocs
  if ( len ( o0oo ) == 0 ) :
   IiiIiiI1i1I1iI = { }
   for ooOoOO0Oo in OO00 . individual_registrations . values ( ) :
    for IiI1I1iii11 in ooOoOO0Oo . registered_rlocs :
     if ( IiI1I1iii11 . is_rtr ( ) == False ) : continue
     IiiIiiI1i1I1iI [ IiI1I1iii11 . rloc . print_address ( ) ] = IiI1I1iii11
     if 12 - 12: Oo0Ooo / iII111i
     if 96 - 96: i1IIi
   o0oo = IiiIiiI1i1I1iI . values ( )
   if 6 - 6: OOooOOo
   if 7 - 7: I1ii11iIi11i + ooOoO0o . ooOoO0o + iII111i
   if 100 - 100: I1Ii111
   if 71 - 71: ooOoO0o * i1IIi / OoOoOO00 * i11iIiiIii - iII111i
   if 88 - 88: IiII
   if 29 - 29: iII111i . ooOoO0o
  o00o0OoOo0OO = [ ]
  I1iI111i11i1 = False
  if ( OO00 . eid . address == 0 and OO00 . eid . mask_len == 0 ) :
   ooi1I = [ ]
   OO0oO000o00 = [ ] if len ( o0oo ) == 0 else o0oo [ 0 ] . rle . rle_nodes
   if 100 - 100: iII111i + o0oOOo0O0Ooo / Oo0Ooo * I1IiiI
   for IIi1i1111i in OO0oO000o00 :
    o00o0OoOo0OO . append ( IIi1i1111i . address )
    ooi1I . append ( IIi1i1111i . address . print_address_no_iid ( ) )
    if 35 - 35: I1IiiI / Ii1I * IiII + OOooOOo - iIii1I11I1II1 + I11i
   lprint ( "Notify existing RLE-nodes {}" . format ( ooi1I ) )
  else :
   if 50 - 50: I11i * Ii1I . iIii1I11I1II1 . iII111i - O0 . ooOoO0o
   if 3 - 3: OoOoOO00
   if 79 - 79: i11iIiiIii * OoooooooOO
   if 50 - 50: I1IiiI * II111iiii . I1Ii111 / I1Ii111
   if 28 - 28: ooOoO0o
   for IiI1I1iii11 in o0oo :
    if ( IiI1I1iii11 . is_rtr ( ) ) : o00o0OoOo0OO . append ( IiI1I1iii11 . rloc )
    if 27 - 27: OoO0O00
    if 80 - 80: o0oOOo0O0Ooo
    if 70 - 70: iII111i . OOooOOo / ooOoO0o - OoO0O00 * oO0o / ooOoO0o
    if 5 - 5: O0
    if 73 - 73: iIii1I11I1II1 . i11iIiiIii * OOooOOo * O0
   I1iI111i11i1 = ( len ( o00o0OoOo0OO ) != 0 )
   if ( I1iI111i11i1 == False ) :
    Iiii1IIIiIi = lisp_site_eid_lookup ( OOoo [ 0 ] , Oo0Oooo00O00 , False )
    if ( Iiii1IIIiIi == None ) : continue
    if 66 - 66: o0oOOo0O0Ooo
    for IiI1I1iii11 in Iiii1IIIiIi . registered_rlocs :
     if ( IiI1I1iii11 . rloc . is_null ( ) ) : continue
     o00o0OoOo0OO . append ( IiI1I1iii11 . rloc )
     if 91 - 91: OoOoOO00 + OOooOOo
     if 23 - 23: Oo0Ooo % OOooOOo % iIii1I11I1II1 / O0 + i11iIiiIii
     if 80 - 80: iII111i . Ii1I + iIii1I11I1II1
     if 75 - 75: OoO0O00 . II111iiii + ooOoO0o - OoO0O00 + OoO0O00 - OoOoOO00
     if 80 - 80: OOooOOo + OoooooooOO - iII111i
     if 56 - 56: iIii1I11I1II1 - i1IIi
   if ( len ( o00o0OoOo0OO ) == 0 ) :
    lprint ( "No ITRs or RTRs found for {}, Map-Notify suppressed" . format ( green ( OO00 . print_eid_tuple ( ) , False ) ) )
    if 96 - 96: Oo0Ooo . OoooooooOO + OoOoOO00 + i1IIi
    continue
    if 43 - 43: II111iiii * IiII % iIii1I11I1II1 % i11iIiiIii % I1ii11iIi11i
    if 81 - 81: oO0o % I1ii11iIi11i % ooOoO0o * O0 - OOooOOo
    if 17 - 17: O0 % O0 / I1ii11iIi11i . Oo0Ooo . iII111i
    if 4 - 4: OoO0O00
    if 65 - 65: Oo0Ooo % O0 / I1Ii111 * IiII - oO0o
    if 32 - 32: Ii1I * OoO0O00 + ooOoO0o
  for O0O in o00o0OoOo0OO :
   lprint ( "Build Map-Notify to {}TR {} for {}" . format ( "R" if I1iI111i11i1 else "x" , red ( O0O . print_address_no_iid ( ) , False ) ,
   # I1IiiI % I1Ii111 * I11i
 green ( OO00 . print_eid_tuple ( ) , False ) ) )
   if 39 - 39: Oo0Ooo . Oo0Ooo * I1Ii111 + oO0o % IiII / Oo0Ooo
   OOoOO00000Oo = [ OO00 . print_eid_tuple ( ) ]
   lisp_send_multicast_map_notify ( lisp_sockets , OO00 , OOoOO00000Oo , O0O )
   time . sleep ( .001 )
   if 85 - 85: II111iiii - O0 . i11iIiiIii . o0oOOo0O0Ooo + ooOoO0o - ooOoO0o
   if 25 - 25: I1ii11iIi11i % Ii1I * O0 / I1IiiI % OOooOOo
 return
 if 42 - 42: IiII - IiII - I1ii11iIi11i + i1IIi * Oo0Ooo
 if 80 - 80: oO0o + O0
 if 84 - 84: i1IIi - II111iiii
 if 2 - 2: i11iIiiIii - OoO0O00 * Oo0Ooo
 if 100 - 100: I1Ii111
 if 5 - 5: IiII % oO0o . I1IiiI * II111iiii + o0oOOo0O0Ooo / Ii1I
 if 55 - 55: Oo0Ooo / o0oOOo0O0Ooo
 if 51 - 51: I1IiiI + i11iIiiIii / ooOoO0o % I1IiiI + Oo0Ooo
def lisp_find_sig_in_rloc_set ( packet , rloc_count ) :
 for Ii11 in range ( rloc_count ) :
  iI11iII1IiiI = lisp_rloc_record ( )
  packet = iI11iII1IiiI . decode ( packet , None )
  iIiI1I1i1I11I = iI11iII1IiiI . json
  if ( iIiI1I1i1I11I == None ) : continue
  if 9 - 9: I11i
  try :
   iIiI1I1i1I11I = json . loads ( iIiI1I1i1I11I . json_string )
  except :
   lprint ( "Found corrupted JSON signature" )
   continue
   if 83 - 83: i11iIiiIii
   if 72 - 72: oO0o + II111iiii . O0 * oO0o + iII111i
  if ( iIiI1I1i1I11I . has_key ( "signature" ) == False ) : continue
  return ( iI11iII1IiiI )
  if 22 - 22: I11i + Ii1I . IiII - OoO0O00 - o0oOOo0O0Ooo
 return ( None )
 if 84 - 84: OoooooooOO - Oo0Ooo
 if 86 - 86: O0 + OoO0O00 + O0 . I1IiiI
 if 82 - 82: OoOoOO00
 if 61 - 61: oO0o . o0oOOo0O0Ooo
 if 82 - 82: Oo0Ooo * OoooooooOO / ooOoO0o / I1IiiI
 if 70 - 70: I1IiiI
 if 74 - 74: ooOoO0o * II111iiii
 if 96 - 96: i11iIiiIii . I1IiiI - II111iiii . I11i
 if 79 - 79: OoO0O00 . OoOoOO00 - i1IIi + Ii1I * i11iIiiIii . OoooooooOO
 if 83 - 83: o0oOOo0O0Ooo / oO0o
 if 24 - 24: Ii1I + oO0o / OoooooooOO % i11iIiiIii
 if 1 - 1: iII111i / I1Ii111 * I1IiiI + OoOoOO00 . OoooooooOO
 if 5 - 5: I1IiiI
 if 74 - 74: i1IIi * Oo0Ooo - OoOoOO00 * o0oOOo0O0Ooo
 if 85 - 85: iIii1I11I1II1 * IiII / i11iIiiIii - ooOoO0o - o0oOOo0O0Ooo
 if 30 - 30: OoOoOO00 - OOooOOo . Oo0Ooo
 if 11 - 11: IiII - I1Ii111 - OoO0O00 * o0oOOo0O0Ooo
 if 99 - 99: O0 - OoO0O00
 if 95 - 95: Ii1I . IiII * o0oOOo0O0Ooo
def lisp_get_eid_hash ( eid ) :
 oOo0oo0OOoOo = None
 for iiI11Iiii in lisp_eid_hashes :
  if 22 - 22: o0oOOo0O0Ooo . IiII * I1Ii111 / ooOoO0o
  if 56 - 56: iII111i
  if 95 - 95: OoooooooOO - Ii1I + I1Ii111 - I11i + O0 . O0
  if 8 - 8: OoO0O00 % I11i + I1IiiI / IiII - OOooOOo + i1IIi
  o0OOoOO = iiI11Iiii . instance_id
  if ( o0OOoOO == - 1 ) : iiI11Iiii . instance_id = eid . instance_id
  if 3 - 3: iII111i - o0oOOo0O0Ooo / I1Ii111
  oooO0OOo0O0O0 = eid . is_more_specific ( iiI11Iiii )
  iiI11Iiii . instance_id = o0OOoOO
  if ( oooO0OOo0O0O0 ) :
   oOo0oo0OOoOo = 128 - iiI11Iiii . mask_len
   break
   if 10 - 10: I11i + OoooooooOO / iII111i * OOooOOo
   if 39 - 39: OoOoOO00
 if ( oOo0oo0OOoOo == None ) : return ( None )
 if 61 - 61: OoooooooOO / ooOoO0o . i1IIi . Oo0Ooo % OoOoOO00 * OoO0O00
 oOoO0Oo0 = eid . address
 i1O00oOO = ""
 for Ii11 in range ( 0 , oOo0oo0OOoOo / 16 ) :
  o0o0O00 = oOoO0Oo0 & 0xffff
  o0o0O00 = hex ( o0o0O00 ) [ 2 : - 1 ]
  i1O00oOO = o0o0O00 . zfill ( 4 ) + ":" + i1O00oOO
  oOoO0Oo0 >>= 16
  if 39 - 39: oO0o
 if ( oOo0oo0OOoOo % 16 != 0 ) :
  o0o0O00 = oOoO0Oo0 & 0xff
  o0o0O00 = hex ( o0o0O00 ) [ 2 : - 1 ]
  i1O00oOO = o0o0O00 . zfill ( 2 ) + ":" + i1O00oOO
  if 49 - 49: I1IiiI * I1Ii111 . I1IiiI - II111iiii
 return ( i1O00oOO [ 0 : - 1 ] )
 if 57 - 57: oO0o + O0 - OoOoOO00
 if 14 - 14: II111iiii + i11iIiiIii + Ii1I / o0oOOo0O0Ooo . OoO0O00
 if 93 - 93: o0oOOo0O0Ooo + i1IIi
 if 24 - 24: i1IIi
 if 54 - 54: iIii1I11I1II1 - IiII + o0oOOo0O0Ooo + I1ii11iIi11i + IiII
 if 99 - 99: Oo0Ooo
 if 38 - 38: I1ii11iIi11i - I1IiiI
 if 50 - 50: iII111i % OoO0O00 - oO0o + Oo0Ooo . O0 . iII111i
 if 42 - 42: iII111i + I1ii11iIi11i
 if 44 - 44: I1ii11iIi11i % IiII
 if 1 - 1: Oo0Ooo + IiII - I1Ii111 / I1Ii111
def lisp_lookup_public_key ( eid ) :
 o0OOoOO = eid . instance_id
 if 25 - 25: OoOoOO00
 if 52 - 52: OOooOOo + IiII
 if 73 - 73: OoooooooOO - I1Ii111 % iII111i / OOooOOo . o0oOOo0O0Ooo - IiII
 if 69 - 69: Ii1I . iIii1I11I1II1 / Oo0Ooo * Oo0Ooo % IiII
 if 5 - 5: OOooOOo - I1Ii111 + IiII
 ooOO0Oo000 = lisp_get_eid_hash ( eid )
 if ( ooOO0Oo000 == None ) : return ( [ None , None , False ] )
 if 26 - 26: I1IiiI - OOooOOo
 ooOO0Oo000 = "hash-" + ooOO0Oo000
 iIIiI11I1 = lisp_address ( LISP_AFI_NAME , ooOO0Oo000 , len ( ooOO0Oo000 ) , o0OOoOO )
 O0oo0oo0 = lisp_address ( LISP_AFI_NONE , "" , 0 , o0OOoOO )
 if 34 - 34: I1Ii111 % I1IiiI . OoOoOO00 / iII111i + ooOoO0o . i11iIiiIii
 if 51 - 51: OoooooooOO * I1Ii111 * I11i - I1ii11iIi11i + I1Ii111
 if 50 - 50: OoooooooOO * II111iiii
 if 7 - 7: ooOoO0o / I11i * iII111i
 Iiii1IIIiIi = lisp_site_eid_lookup ( iIIiI11I1 , O0oo0oo0 , True )
 if ( Iiii1IIIiIi == None ) : return ( [ iIIiI11I1 , None , False ] )
 if 17 - 17: O0 % I1Ii111
 if 28 - 28: i1IIi * ooOoO0o
 if 14 - 14: II111iiii + II111iiii - I11i / I11i . OoOoOO00 + OoO0O00
 if 92 - 92: II111iiii - II111iiii % IiII
 OO000OO = None
 for OoOOo in Iiii1IIIiIi . registered_rlocs :
  iIIiIIIIiIiI1Ii = OoOOo . json
  if ( iIIiIIIIiIiI1Ii == None ) : continue
  try :
   iIIiIIIIiIiI1Ii = json . loads ( iIIiIIIIiIiI1Ii . json_string )
  except :
   lprint ( "Registered RLOC JSON format is invalid for {}" . format ( ooOO0Oo000 ) )
   if 4 - 4: II111iiii - o0oOOo0O0Ooo / i1IIi - Oo0Ooo
   return ( [ iIIiI11I1 , None , False ] )
   if 26 - 26: o0oOOo0O0Ooo
  if ( iIIiIIIIiIiI1Ii . has_key ( "public-key" ) == False ) : continue
  OO000OO = iIIiIIIIiIiI1Ii [ "public-key" ]
  break
  if 43 - 43: OoOoOO00 * ooOoO0o % OoooooooOO * o0oOOo0O0Ooo
 return ( [ iIIiI11I1 , OO000OO , True ] )
 if 8 - 8: I1ii11iIi11i + Oo0Ooo - iII111i
 if 53 - 53: ooOoO0o / IiII
 if 36 - 36: iIii1I11I1II1
 if 78 - 78: II111iiii * I11i
 if 47 - 47: Ii1I
 if 42 - 42: I11i . oO0o - I1IiiI / OoO0O00
 if 75 - 75: I1IiiI / OoOoOO00 . I11i * iIii1I11I1II1
 if 53 - 53: iIii1I11I1II1
def lisp_verify_cga_sig ( eid , rloc_record ) :
 if 8 - 8: O0 - O0 - II111iiii
 if 77 - 77: i1IIi - ooOoO0o + O0 . OoO0O00 * I1Ii111 - I11i
 if 64 - 64: i1IIi + OoooooooOO + OOooOOo / ooOoO0o % I1IiiI . OoooooooOO
 if 96 - 96: II111iiii - OoOoOO00 + oO0o
 if 80 - 80: oO0o / OoOoOO00 - I11i / oO0o - iII111i - OoooooooOO
 IiiiI1I1i = json . loads ( rloc_record . json . json_string )
 if 57 - 57: o0oOOo0O0Ooo
 if ( lisp_get_eid_hash ( eid ) ) :
  O0O0o0OOOooo0 = eid
 elif ( IiiiI1I1i . has_key ( "signature-eid" ) ) :
  i1IiII11ii11 = IiiiI1I1i [ "signature-eid" ]
  O0O0o0OOOooo0 = lisp_address ( LISP_AFI_IPV6 , i1IiII11ii11 , 0 , 0 )
 else :
  lprint ( "  No signature-eid found in RLOC-record" )
  return ( False )
  if 2 - 2: iIii1I11I1II1 * I1ii11iIi11i - OoooooooOO
  if 93 - 93: iII111i % ooOoO0o * Oo0Ooo
  if 34 - 34: O0 * oO0o
  if 58 - 58: OOooOOo . iII111i - Oo0Ooo / iII111i . I11i
  if 86 - 86: iIii1I11I1II1 - iII111i % Ii1I
 iIIiI11I1 , OO000OO , III11 = lisp_lookup_public_key ( O0O0o0OOOooo0 )
 if ( iIIiI11I1 == None ) :
  oOoo0OooOOo00 = green ( O0O0o0OOOooo0 . print_address ( ) , False )
  lprint ( "  Could not parse hash in EID {}" . format ( oOoo0OooOOo00 ) )
  return ( False )
  if 68 - 68: O0 * iIii1I11I1II1 . I1IiiI . OOooOOo - IiII
  if 79 - 79: i11iIiiIii - I1Ii111
 OOoOO0 = "found" if III11 else bold ( "not found" , False )
 oOoo0OooOOo00 = green ( iIIiI11I1 . print_address ( ) , False )
 lprint ( "  Lookup for crypto-hashed EID {} {}" . format ( oOoo0OooOOo00 , OOoOO0 ) )
 if ( III11 == False ) : return ( False )
 if 69 - 69: OoOoOO00 * Ii1I % OoooooooOO % OOooOOo * OoOoOO00
 if ( OO000OO == None ) :
  lprint ( "  RLOC-record with public-key not found" )
  return ( False )
  if 20 - 20: IiII
  if 17 - 17: o0oOOo0O0Ooo % iIii1I11I1II1
 ooo0oOo = OO000OO [ 0 : 8 ] + "..." + OO000OO [ - 8 : : ]
 lprint ( "  RLOC-record with public-key '{}' found" . format ( ooo0oOo ) )
 if 79 - 79: I11i
 if 38 - 38: I1ii11iIi11i * ooOoO0o
 if 77 - 77: OOooOOo - i11iIiiIii - I1ii11iIi11i
 if 94 - 94: OoO0O00 % iII111i - I1Ii111 + OoO0O00 - I1IiiI
 if 65 - 65: OOooOOo
 o00 = IiiiI1I1i [ "signature" ]
 if 94 - 94: o0oOOo0O0Ooo
 try :
  IiiiI1I1i = binascii . a2b_base64 ( o00 )
 except :
  lprint ( "  Incorrect padding in signature string" )
  return ( False )
  if 46 - 46: I1ii11iIi11i + iII111i / OoO0O00 + oO0o * I11i % OOooOOo
  if 80 - 80: O0 % II111iiii / O0 . Oo0Ooo * OoOoOO00 + OOooOOo
 i11IIiiII = len ( IiiiI1I1i )
 if ( i11IIiiII & 1 ) :
  lprint ( "  Signature length is odd, length {}" . format ( i11IIiiII ) )
  return ( False )
  if 31 - 31: OoO0O00 + i11iIiiIii / I11i % O0 / Ii1I
  if 90 - 90: iIii1I11I1II1 % oO0o % IiII
  if 84 - 84: I1IiiI * IiII * iII111i / i1IIi . II111iiii * o0oOOo0O0Ooo
  if 1 - 1: oO0o - iIii1I11I1II1 % i1IIi
  if 94 - 94: Oo0Ooo + iIii1I11I1II1 . OoO0O00 * oO0o . i1IIi
 ii1Ii111I11 = O0O0o0OOOooo0 . print_address ( )
 if 85 - 85: O0 / OoOoOO00 . iII111i
 if 64 - 64: OoO0O00 + I1ii11iIi11i / OoO0O00 * I1Ii111 . Oo0Ooo
 if 5 - 5: iII111i - iIii1I11I1II1 * IiII
 if 52 - 52: OOooOOo
 OO000OO = binascii . a2b_base64 ( OO000OO )
 try :
  iii11 = ecdsa . VerifyingKey . from_pem ( OO000OO )
 except :
  IIIIIiiIII = bold ( "Bad public-key" , False )
  lprint ( "  {}, not in PEM format" . format ( IIIIIiiIII ) )
  return ( False )
  if 40 - 40: OoO0O00 * o0oOOo0O0Ooo / i1IIi * I1Ii111 * I1ii11iIi11i
  if 45 - 45: iII111i / Oo0Ooo - ooOoO0o . iII111i * OoOoOO00 / OoooooooOO
  if 66 - 66: I1IiiI
  if 45 - 45: II111iiii * I1Ii111 - II111iiii / I1IiiI % oO0o
  if 83 - 83: oO0o % OoO0O00 + I1ii11iIi11i / OoooooooOO % iII111i
  if 22 - 22: I1Ii111
  if 41 - 41: O0 * i1IIi
  if 89 - 89: iIii1I11I1II1 . I11i % I1ii11iIi11i + II111iiii . OoO0O00
  if 5 - 5: I1ii11iIi11i / I1IiiI . iII111i
  if 7 - 7: Ii1I
  if 62 - 62: I1ii11iIi11i + IiII . O0 - OoooooooOO * o0oOOo0O0Ooo % O0
 try :
  O0o0O00O0 = iii11 . verify ( IiiiI1I1i , ii1Ii111I11 , hashfunc = hashlib . sha256 )
 except :
  lprint ( "  Signature library failed for signature data '{}'" . format ( ii1Ii111I11 ) )
  if 63 - 63: OOooOOo + iII111i - IiII - I1IiiI % IiII . OoO0O00
  lprint ( "  Signature used '{}'" . format ( o00 ) )
  return ( False )
  if 73 - 73: OoOoOO00
 return ( O0o0O00O0 )
 if 47 - 47: oO0o
 if 17 - 17: IiII
 if 47 - 47: I11i . I1IiiI % ooOoO0o . i11iIiiIii
 if 63 - 63: I1ii11iIi11i % I11i % OoooooooOO
 if 100 - 100: O0
 if 9 - 9: Ii1I
 if 87 - 87: I1IiiI
 if 56 - 56: OOooOOo % oO0o - OoOoOO00
 if 27 - 27: I1ii11iIi11i - IiII * OoooooooOO * I1ii11iIi11i + i11iIiiIii . IiII
 if 81 - 81: oO0o / iIii1I11I1II1
def lisp_remove_eid_from_map_notify_queue ( eid_list ) :
 if 15 - 15: Ii1I + I1IiiI . OOooOOo / OoooooooOO + I11i - I11i
 if 27 - 27: Ii1I / o0oOOo0O0Ooo . iIii1I11I1II1 . I1IiiI - OoO0O00
 if 28 - 28: ooOoO0o
 if 88 - 88: oO0o
 if 77 - 77: ooOoO0o + I1Ii111 . OoOoOO00
 IiI11i1ii = [ ]
 for iI1III1iii in eid_list :
  for ii111i1 in lisp_map_notify_queue :
   iiIi11I = lisp_map_notify_queue [ ii111i1 ]
   if ( iI1III1iii not in iiIi11I . eid_list ) : continue
   if 79 - 79: i11iIiiIii * IiII
   IiI11i1ii . append ( ii111i1 )
   O0O0 = iiIi11I . retransmit_timer
   if ( O0O0 ) : O0O0 . cancel ( )
   if 58 - 58: i11iIiiIii % Ii1I + Oo0Ooo - OoOoOO00 - i11iIiiIii / O0
   lprint ( "Remove from Map-Notify queue nonce 0x{} for EID {}" . format ( iiIi11I . nonce_key , green ( iI1III1iii , False ) ) )
   if 36 - 36: OOooOOo
   if 42 - 42: OOooOOo * ooOoO0o * i11iIiiIii + OoooooooOO . iIii1I11I1II1
   if 95 - 95: i1IIi * O0 / II111iiii * OoOoOO00 * I1IiiI
   if 38 - 38: OOooOOo - OoOoOO00 / OoO0O00 / o0oOOo0O0Ooo - i11iIiiIii
   if 4 - 4: I1IiiI * o0oOOo0O0Ooo - I11i - OoooooooOO . OoooooooOO
   if 79 - 79: oO0o - iII111i
   if 34 - 34: OoooooooOO + Ii1I - iII111i + OoooooooOO / I1IiiI
 for ii111i1 in IiI11i1ii : lisp_map_notify_queue . pop ( ii111i1 )
 return
 if 39 - 39: o0oOOo0O0Ooo . i1IIi * OoO0O00 / II111iiii / I1ii11iIi11i * OOooOOo
 if 39 - 39: O0 . OOooOOo
 if 95 - 95: I11i
 if 58 - 58: I1ii11iIi11i / i11iIiiIii + iII111i + I11i / oO0o
 if 8 - 8: I1ii11iIi11i
 if 100 - 100: OoooooooOO / I11i - Ii1I
 if 11 - 11: OoO0O00
 if 20 - 20: Oo0Ooo
def lisp_decrypt_map_register ( packet ) :
 if 34 - 34: I1Ii111 % i11iIiiIii / oO0o - i1IIi . o0oOOo0O0Ooo / oO0o
 if 68 - 68: I1Ii111 % Ii1I * Oo0Ooo - O0 . IiII
 if 1 - 1: I1ii11iIi11i
 if 18 - 18: i11iIiiIii % OoO0O00 % OOooOOo . OOooOOo * Ii1I / II111iiii
 if 81 - 81: iII111i % IiII / I11i
 iIiI1I1II1 = socket . ntohl ( struct . unpack ( "I" , packet [ 0 : 4 ] ) [ 0 ] )
 i11i11i = ( iIiI1I1II1 >> 13 ) & 0x1
 if ( i11i11i == 0 ) : return ( packet )
 if 93 - 93: I1IiiI
 o00O = ( iIiI1I1II1 >> 14 ) & 0x7
 if 49 - 49: I11i + iIii1I11I1II1 / Ii1I . iII111i . OoOoOO00 * OoOoOO00
 if 60 - 60: i1IIi % ooOoO0o . OOooOOo + i11iIiiIii / O0
 if 69 - 69: O0
 if 53 - 53: I1IiiI % IiII % OoOoOO00
 try :
  Iiio0oO = lisp_ms_encryption_keys [ o00O ]
  Iiio0oO = Iiio0oO . zfill ( 32 )
  O0o = "0" * 8
 except :
  lprint ( "Cannot decrypt Map-Register with key-id {}" . format ( o00O ) )
  return ( None )
  if 87 - 87: I1ii11iIi11i + I1ii11iIi11i
  if 1 - 1: i11iIiiIii . iII111i * OoOoOO00
 oOo0OOOOOO = bold ( "Decrypt" , False )
 lprint ( "{} Map-Register with key-id {}" . format ( oOo0OOOOOO , o00O ) )
 if 66 - 66: i1IIi / IiII
 IiIIIIi = chacha . ChaCha ( Iiio0oO , O0o ) . decrypt ( packet [ 4 : : ] )
 return ( packet [ 0 : 4 ] + IiIIIIi )
 if 17 - 17: O0 - OOooOOo
 if 96 - 96: OOooOOo * I1ii11iIi11i
 if 85 - 85: O0 / II111iiii * O0 - iII111i % i11iIiiIii
 if 47 - 47: OoOoOO00
 if 4 - 4: OOooOOo + I1ii11iIi11i - iII111i + OOooOOo / IiII
 if 23 - 23: iIii1I11I1II1 + OoooooooOO + ooOoO0o . iII111i . Oo0Ooo - iIii1I11I1II1
 if 25 - 25: O0 + I1IiiI % OOooOOo / Oo0Ooo . IiII / I1Ii111
def lisp_process_map_register ( lisp_sockets , packet , source , sport ) :
 global lisp_registered_count
 if 84 - 84: ooOoO0o . O0 + I1IiiI * OoO0O00 - I1IiiI
 if 24 - 24: Ii1I
 if 23 - 23: Oo0Ooo * i1IIi / I1IiiI . I11i - I1ii11iIi11i . iIii1I11I1II1
 if 15 - 15: O0 + o0oOOo0O0Ooo / oO0o
 if 27 - 27: Ii1I * II111iiii / oO0o
 if 99 - 99: I11i + ooOoO0o % I11i + O0 - Ii1I - I1Ii111
 packet = lisp_decrypt_map_register ( packet )
 if ( packet == None ) : return
 if 3 - 3: Oo0Ooo . I1IiiI
 OOoO00o0o = lisp_map_register ( )
 IIiIiIii11I1 , packet = OOoO00o0o . decode ( packet )
 if ( packet == None ) :
  lprint ( "Could not decode Map-Register packet" )
  return
  if 99 - 99: iII111i . oO0o + II111iiii % O0
 OOoO00o0o . sport = sport
 if 40 - 40: iIii1I11I1II1
 OOoO00o0o . print_map_register ( )
 if 64 - 64: ooOoO0o * OOooOOo % o0oOOo0O0Ooo + I11i
 if 64 - 64: Ii1I - iIii1I11I1II1 . iII111i . ooOoO0o * O0
 if 3 - 3: I1IiiI % II111iiii
 if 38 - 38: Ii1I / I11i
 O00 = True
 if ( OOoO00o0o . auth_len == LISP_SHA1_160_AUTH_DATA_LEN ) :
  O00 = True
  if 94 - 94: II111iiii . Oo0Ooo - ooOoO0o
 if ( OOoO00o0o . alg_id == LISP_SHA_256_128_ALG_ID ) :
  O00 = False
  if 97 - 97: oO0o
  if 90 - 90: Oo0Ooo % ooOoO0o + I1Ii111 + OoO0O00 . II111iiii . OoO0O00
  if 10 - 10: I1ii11iIi11i - II111iiii * o0oOOo0O0Ooo . OoO0O00 / i11iIiiIii / iII111i
  if 42 - 42: O0 . OoooooooOO + Oo0Ooo
  if 34 - 34: OOooOOo / I11i / OoooooooOO + i11iIiiIii / II111iiii - O0
 Ii1oOOOOo00 = [ ]
 if 62 - 62: I1Ii111 . ooOoO0o % I1ii11iIi11i . ooOoO0o - iIii1I11I1II1 + iII111i
 if 79 - 79: II111iiii / I1Ii111 + II111iiii + Oo0Ooo - IiII / I1ii11iIi11i
 if 93 - 93: OOooOOo
 if 65 - 65: i1IIi * ooOoO0o * OoooooooOO - i11iIiiIii + IiII - o0oOOo0O0Ooo
 iI1iI1 = None
 iiOO0o0o00 = packet
 O000 = [ ]
 ii1i = OOoO00o0o . record_count
 for Ii11 in range ( ii1i ) :
  OoOO = lisp_eid_record ( )
  iI11iII1IiiI = lisp_rloc_record ( )
  packet = OoOO . decode ( packet )
  if ( packet == None ) :
   lprint ( "Could not decode EID-record in Map-Register packet" )
   return
   if 89 - 89: i11iIiiIii + i1IIi + OOooOOo . O0 / o0oOOo0O0Ooo - i11iIiiIii
  OoOO . print_record ( "  " , False )
  if 74 - 74: OoO0O00 + OOooOOo . IiII . iIii1I11I1II1
  if 2 - 2: OoOoOO00
  if 11 - 11: ooOoO0o - I1Ii111 / I1IiiI
  if 94 - 94: I1ii11iIi11i * ooOoO0o
  Iiii1IIIiIi = lisp_site_eid_lookup ( OoOO . eid , OoOO . group ,
 False )
  if 12 - 12: Ii1I - OoOoOO00
  o0O = Iiii1IIIiIi . print_eid_tuple ( ) if Iiii1IIIiIi else None
  if 75 - 75: oO0o + OoOoOO00 - OoooooooOO
  if 38 - 38: I11i / ooOoO0o / OoOoOO00 * OOooOOo . oO0o
  if 8 - 8: OoO0O00 . OOooOOo % I1Ii111 * OOooOOo / I1IiiI
  if 3 - 3: IiII - I1ii11iIi11i . o0oOOo0O0Ooo
  if 39 - 39: oO0o . I1Ii111 + oO0o % OoOoOO00 - i11iIiiIii
  if 69 - 69: I11i / OoO0O00
  if 73 - 73: i11iIiiIii / i1IIi
  if ( Iiii1IIIiIi and Iiii1IIIiIi . accept_more_specifics == False ) :
   if ( Iiii1IIIiIi . eid_record_matches ( OoOO ) == False ) :
    IiI1 = Iiii1IIIiIi . parent_for_more_specifics
    if ( IiI1 ) : Iiii1IIIiIi = IiI1
    if 72 - 72: iIii1I11I1II1 % iIii1I11I1II1 . OoOoOO00 * OoooooooOO * OoO0O00
    if 26 - 26: Ii1I * I1IiiI % ooOoO0o / I1Ii111
    if 80 - 80: I1Ii111 / O0 * O0
    if 40 - 40: OoO0O00 - oO0o / o0oOOo0O0Ooo . oO0o
    if 89 - 89: i11iIiiIii - II111iiii
    if 67 - 67: IiII % I1Ii111 + i11iIiiIii
    if 53 - 53: OOooOOo
    if 95 - 95: oO0o - OOooOOo % I1Ii111 / OoooooooOO % OoooooooOO - O0
  I1o0oO0Oo00Oo = ( Iiii1IIIiIi and Iiii1IIIiIi . accept_more_specifics )
  if ( I1o0oO0Oo00Oo ) :
   oOo0O0 = lisp_site_eid ( Iiii1IIIiIi . site )
   oOo0O0 . dynamic = True
   oOo0O0 . eid . copy_address ( OoOO . eid )
   oOo0O0 . group . copy_address ( OoOO . group )
   oOo0O0 . parent_for_more_specifics = Iiii1IIIiIi
   oOo0O0 . add_cache ( )
   oOo0O0 . inherit_from_ams_parent ( )
   Iiii1IIIiIi . more_specific_registrations . append ( oOo0O0 )
   Iiii1IIIiIi = oOo0O0
  else :
   Iiii1IIIiIi = lisp_site_eid_lookup ( OoOO . eid , OoOO . group ,
 True )
   if 28 - 28: O0
   if 29 - 29: I11i - OOooOOo / OoO0O00
  oOoo0OooOOo00 = OoOO . print_eid_tuple ( )
  if 81 - 81: I11i / oO0o
  if ( Iiii1IIIiIi == None ) :
   iIiiiiiiI1II = bold ( "Site not found" , False )
   lprint ( "  {} for EID {}{}" . format ( iIiiiiiiI1II , green ( oOoo0OooOOo00 , False ) ,
 ", matched non-ams {}" . format ( green ( o0O , False ) if o0O else "" ) ) )
   if 89 - 89: OoOoOO00
   if 70 - 70: Oo0Ooo - OOooOOo * OOooOOo / o0oOOo0O0Ooo
   if 4 - 4: OoOoOO00 / OoO0O00
   if 66 - 66: I1Ii111 / OoOoOO00
   if 53 - 53: OoOoOO00 . i11iIiiIii - OoooooooOO
   packet = iI11iII1IiiI . end_of_rlocs ( packet , OoOO . rloc_count )
   if ( packet == None ) :
    lprint ( "  Could not decode RLOC-record in Map-Register packet" )
    return
    if 92 - 92: O0 - i11iIiiIii + OoO0O00 - OoooooooOO - o0oOOo0O0Ooo
   continue
   if 25 - 25: oO0o / oO0o / Ii1I / O0
   if 56 - 56: ooOoO0o
  iI1iI1 = Iiii1IIIiIi . site
  if 19 - 19: O0 * I1IiiI + I1ii11iIi11i
  if ( I1o0oO0Oo00Oo ) :
   ooo0OO = Iiii1IIIiIi . parent_for_more_specifics . print_eid_tuple ( )
   lprint ( "  Found ams {} for site '{}' for registering prefix {}" . format ( green ( ooo0OO , False ) , iI1iI1 . site_name , green ( oOoo0OooOOo00 , False ) ) )
   if 25 - 25: I11i - ooOoO0o / OoO0O00 / iII111i - OoO0O00
  else :
   ooo0OO = green ( Iiii1IIIiIi . print_eid_tuple ( ) , False )
   lprint ( "  Found {} for site '{}' for registering prefix {}" . format ( ooo0OO , iI1iI1 . site_name , green ( oOoo0OooOOo00 , False ) ) )
   if 86 - 86: OoO0O00
   if 89 - 89: OoooooooOO % iII111i * I1ii11iIi11i + I1ii11iIi11i . Oo0Ooo
   if 4 - 4: I11i
   if 8 - 8: IiII
   if 1 - 1: ooOoO0o . IiII
   if 4 - 4: iIii1I11I1II1 % I1IiiI - OoooooooOO / iII111i
  if ( iI1iI1 . shutdown ) :
   lprint ( ( "  Rejecting registration for site '{}', configured in " +
 "admin-shutdown state" ) . format ( iI1iI1 . site_name ) )
   packet = iI11iII1IiiI . end_of_rlocs ( packet , OoOO . rloc_count )
   continue
   if 55 - 55: O0 + iII111i * OoOoOO00 . i11iIiiIii * Ii1I + oO0o
   if 66 - 66: i1IIi . I1ii11iIi11i
   if 86 - 86: Oo0Ooo
   if 48 - 48: OoO0O00
   if 55 - 55: OoO0O00 * i1IIi * I11i / iII111i
   if 42 - 42: IiII
   if 28 - 28: OoOoOO00 + OoOoOO00
   if 53 - 53: II111iiii % i1IIi + ooOoO0o . I1Ii111
  I1o0 = OOoO00o0o . key_id
  if ( iI1iI1 . auth_key . has_key ( I1o0 ) == False ) : I1o0 = 0
  Oo00oO0 = iI1iI1 . auth_key [ I1o0 ]
  if 4 - 4: II111iiii
  iIiiIII1IIiI = lisp_verify_auth ( IIiIiIii11I1 , OOoO00o0o . alg_id ,
 OOoO00o0o . auth_data , Oo00oO0 )
  i1ii = "dynamic " if Iiii1IIIiIi . dynamic else ""
  if 30 - 30: ooOoO0o % I11i
  o0OOo0o0 = bold ( "passed" if iIiiIII1IIiI else "failed" , False )
  I1o0 = "key-id {}" . format ( I1o0 ) if I1o0 == OOoO00o0o . key_id else "bad key-id {}" . format ( OOoO00o0o . key_id )
  if 4 - 4: oO0o / OoO0O00
  lprint ( "  Authentication {} for {}EID-prefix {}, {}" . format ( o0OOo0o0 , i1ii , green ( oOoo0OooOOo00 , False ) , I1o0 ) )
  if 90 - 90: I11i . IiII / OoO0O00 . IiII
  if 62 - 62: i11iIiiIii * I11i + oO0o - i1IIi
  if 9 - 9: I1IiiI
  if 17 - 17: II111iiii + i11iIiiIii + IiII
  if 41 - 41: OoOoOO00 + i1IIi - iIii1I11I1II1
  if 8 - 8: I1Ii111
  II = True
  IIII1iiI1111I = ( lisp_get_eid_hash ( OoOO . eid ) != None )
  if ( IIII1iiI1111I or Iiii1IIIiIi . require_signature ) :
   OOo0ooOO = "Required " if Iiii1IIIiIi . require_signature else ""
   oOoo0OooOOo00 = green ( oOoo0OooOOo00 , False )
   OoOOo = lisp_find_sig_in_rloc_set ( packet , OoOO . rloc_count )
   if ( OoOOo == None ) :
    II = False
    lprint ( ( "  {}EID-crypto-hash signature verification {} " + "for EID-prefix {}, no signature found" ) . format ( OOo0ooOO ,
    # O0 . Ii1I / iII111i * ooOoO0o * I1IiiI
 bold ( "failed" , False ) , oOoo0OooOOo00 ) )
   else :
    II = lisp_verify_cga_sig ( OoOO . eid , OoOOo )
    o0OOo0o0 = bold ( "passed" if II else "failed" , False )
    lprint ( ( "  {}EID-crypto-hash signature verification {} " + "for EID-prefix {}" ) . format ( OOo0ooOO , o0OOo0o0 , oOoo0OooOOo00 ) )
    if 34 - 34: Ii1I / OoooooooOO + OoooooooOO % OoooooooOO . IiII
    if 55 - 55: I11i / I1ii11iIi11i * O0 + IiII % I11i
    if 69 - 69: o0oOOo0O0Ooo % iIii1I11I1II1 . OoooooooOO - ooOoO0o
    if 94 - 94: iIii1I11I1II1 / Oo0Ooo % IiII * IiII
  if ( iIiiIII1IIiI == False or II == False ) :
   packet = iI11iII1IiiI . end_of_rlocs ( packet , OoOO . rloc_count )
   if ( packet == None ) :
    lprint ( "  Could not decode RLOC-record in Map-Register packet" )
    return
    if 62 - 62: I11i . IiII - OOooOOo - I1Ii111 / OoooooooOO . Ii1I
   continue
   if 28 - 28: iII111i / I1ii11iIi11i - OoOoOO00 * Oo0Ooo + Ii1I * OoOoOO00
   if 94 - 94: oO0o
   if 95 - 95: ooOoO0o * O0 + OOooOOo
   if 11 - 11: i1IIi / OoOoOO00 + OoOoOO00 + I1ii11iIi11i + OOooOOo
   if 21 - 21: ooOoO0o
   if 28 - 28: OoOoOO00 + OoOoOO00 - OoOoOO00 / ooOoO0o
  if ( OOoO00o0o . merge_register_requested ) :
   IiI1 = Iiii1IIIiIi
   IiI1 . inconsistent_registration = False
   if 81 - 81: oO0o
   if 34 - 34: o0oOOo0O0Ooo * OOooOOo - i1IIi * o0oOOo0O0Ooo * Oo0Ooo
   if 59 - 59: iIii1I11I1II1 / Oo0Ooo % II111iiii
   if 55 - 55: ooOoO0o - IiII + o0oOOo0O0Ooo
   if 48 - 48: O0 - iIii1I11I1II1 * OOooOOo
   if ( Iiii1IIIiIi . group . is_null ( ) ) :
    if ( IiI1 . site_id != OOoO00o0o . site_id ) :
     IiI1 . site_id = OOoO00o0o . site_id
     IiI1 . registered = False
     IiI1 . individual_registrations = { }
     IiI1 . registered_rlocs = [ ]
     lisp_registered_count -= 1
     if 33 - 33: I11i
     if 63 - 63: Ii1I % II111iiii / OoOoOO00 + Oo0Ooo
     if 28 - 28: OoO0O00 + I1IiiI . oO0o + II111iiii - O0
   iii11 = source . address + OOoO00o0o . xtr_id
   if ( Iiii1IIIiIi . individual_registrations . has_key ( iii11 ) ) :
    Iiii1IIIiIi = Iiii1IIIiIi . individual_registrations [ iii11 ]
   else :
    Iiii1IIIiIi = lisp_site_eid ( iI1iI1 )
    Iiii1IIIiIi . eid . copy_address ( IiI1 . eid )
    Iiii1IIIiIi . group . copy_address ( IiI1 . group )
    IiI1 . individual_registrations [ iii11 ] = Iiii1IIIiIi
    if 32 - 32: oO0o
  else :
   Iiii1IIIiIi . inconsistent_registration = Iiii1IIIiIi . merge_register_requested
   if 62 - 62: i11iIiiIii + OoooooooOO + IiII - OoO0O00 / oO0o * iIii1I11I1II1
   if 91 - 91: o0oOOo0O0Ooo - i11iIiiIii + Oo0Ooo % iIii1I11I1II1
   if 58 - 58: iII111i / ooOoO0o - I1Ii111 + I1Ii111 * ooOoO0o
  Iiii1IIIiIi . map_registers_received += 1
  if 48 - 48: iII111i % O0 % Ii1I * OoO0O00 . OoO0O00
  if 74 - 74: OoO0O00 * i1IIi + I1ii11iIi11i / o0oOOo0O0Ooo / i1IIi
  if 94 - 94: Ii1I
  if 13 - 13: OoO0O00 - II111iiii . iII111i + OoOoOO00 / i11iIiiIii
  if 32 - 32: ooOoO0o / II111iiii / I1ii11iIi11i
  IIIIIiiIII = ( Iiii1IIIiIi . is_rloc_in_rloc_set ( source ) == False )
  if ( OoOO . record_ttl == 0 and IIIIIiiIII ) :
   lprint ( "  Ignore deregistration request from {}" . format ( red ( source . print_address_no_iid ( ) , False ) ) )
   if 34 - 34: iIii1I11I1II1
   continue
   if 47 - 47: OOooOOo * iII111i
   if 71 - 71: IiII - OoooooooOO * i11iIiiIii . OoooooooOO % i1IIi . Oo0Ooo
   if 3 - 3: OoO0O00 + i11iIiiIii + oO0o * IiII
   if 19 - 19: iII111i / II111iiii . I1Ii111 * I1IiiI - OOooOOo
   if 70 - 70: OoO0O00
   if 42 - 42: OoooooooOO - I1Ii111 + I1ii11iIi11i * iII111i * iII111i / OoO0O00
  ooooo0000000oOoo = Iiii1IIIiIi . registered_rlocs
  Iiii1IIIiIi . registered_rlocs = [ ]
  if 54 - 54: OOooOOo
  if 88 - 88: OoooooooOO / iII111i + i1IIi
  if 64 - 64: IiII % I11i / iIii1I11I1II1
  if 66 - 66: Ii1I
  O0Ooo0 = packet
  for O0o0o00O in range ( OoOO . rloc_count ) :
   iI11iII1IiiI = lisp_rloc_record ( )
   packet = iI11iII1IiiI . decode ( packet , None )
   if ( packet == None ) :
    lprint ( "  Could not decode RLOC-record in Map-Register packet" )
    return
    if 95 - 95: I11i - oO0o - OOooOOo * ooOoO0o % I1IiiI
   iI11iII1IiiI . print_record ( "    " )
   if 82 - 82: oO0o / ooOoO0o
   if 43 - 43: IiII - oO0o % ooOoO0o + Ii1I . Ii1I
   if 100 - 100: Ii1I % iII111i
   if 25 - 25: OoOoOO00 % O0 / I1IiiI * IiII + IiII
   if ( len ( iI1iI1 . allowed_rlocs ) > 0 ) :
    I1iiIiiii1111 = iI11iII1IiiI . rloc . print_address ( )
    if ( iI1iI1 . allowed_rlocs . has_key ( I1iiIiiii1111 ) == False ) :
     lprint ( ( "  Reject registration, RLOC {} not " + "configured in allowed RLOC-set" ) . format ( red ( I1iiIiiii1111 , False ) ) )
     if 14 - 14: OOooOOo % I1IiiI
     if 27 - 27: O0 . OOooOOo - iIii1I11I1II1 - Ii1I - I1IiiI
     Iiii1IIIiIi . registered = False
     packet = iI11iII1IiiI . end_of_rlocs ( packet ,
 OoOO . rloc_count - O0o0o00O - 1 )
     break
     if 60 - 60: I1IiiI + Ii1I
     if 24 - 24: I1IiiI / ooOoO0o
     if 60 - 60: Ii1I * o0oOOo0O0Ooo
     if 69 - 69: I1ii11iIi11i . OoooooooOO
     if 92 - 92: Oo0Ooo . ooOoO0o * i1IIi - I1IiiI * OoooooooOO
     if 3 - 3: Ii1I
   OoOOo = lisp_rloc ( )
   OoOOo . store_rloc_from_record ( iI11iII1IiiI , None , source )
   if 64 - 64: OoooooooOO / IiII - IiII . Ii1I % Oo0Ooo
   if 35 - 35: iII111i * I1IiiI * Oo0Ooo + I1Ii111 + i1IIi - ooOoO0o
   if 23 - 23: II111iiii - O0
   if 58 - 58: o0oOOo0O0Ooo * OoO0O00 + OoO0O00
   if 93 - 93: IiII - I1ii11iIi11i % I11i + i1IIi % OoO0O00
   if 20 - 20: oO0o . Oo0Ooo + IiII - II111iiii % Ii1I
   if ( source . is_exact_match ( OoOOo . rloc ) ) :
    OoOOo . map_notify_requested = OOoO00o0o . map_notify_requested
    if 64 - 64: Ii1I % OoO0O00 + OOooOOo % OoOoOO00 + IiII
    if 92 - 92: iII111i * Oo0Ooo - OoOoOO00
    if 33 - 33: i11iIiiIii - OoOoOO00 . OOooOOo * II111iiii . Ii1I
    if 59 - 59: OoOoOO00
    if 29 - 29: iII111i - II111iiii * OoooooooOO * OoooooooOO
   Iiii1IIIiIi . registered_rlocs . append ( OoOOo )
   if 15 - 15: IiII / OOooOOo / iIii1I11I1II1 / OoOoOO00
   if 91 - 91: i11iIiiIii % O0 . Oo0Ooo / I1Ii111
  OOoO0 = ( Iiii1IIIiIi . do_rloc_sets_match ( ooooo0000000oOoo ) == False )
  if 78 - 78: II111iiii - i11iIiiIii . OOooOOo
  if 22 - 22: Oo0Ooo + ooOoO0o
  if 71 - 71: OOooOOo . Ii1I * i11iIiiIii . I11i
  if 9 - 9: O0 / I1ii11iIi11i . iII111i . O0 + IiII % I11i
  if 27 - 27: i11iIiiIii - I1ii11iIi11i / O0 - i1IIi + I1IiiI * iII111i
  if 26 - 26: Oo0Ooo . Ii1I
  if ( OOoO00o0o . map_register_refresh and OOoO0 and
 Iiii1IIIiIi . registered ) :
   lprint ( "  Reject registration, refreshes cannot change RLOC-set" )
   Iiii1IIIiIi . registered_rlocs = ooooo0000000oOoo
   continue
   if 7 - 7: OoOoOO00 - o0oOOo0O0Ooo + oO0o
   if 8 - 8: iIii1I11I1II1
   if 6 - 6: oO0o
   if 51 - 51: I1Ii111 - o0oOOo0O0Ooo
   if 5 - 5: O0
   if 7 - 7: OoOoOO00 + OoO0O00 * I1IiiI
  if ( Iiii1IIIiIi . registered == False ) :
   Iiii1IIIiIi . first_registered = lisp_get_timestamp ( )
   lisp_registered_count += 1
   if 63 - 63: I1ii11iIi11i + iII111i * i1IIi
  Iiii1IIIiIi . last_registered = lisp_get_timestamp ( )
  Iiii1IIIiIi . registered = ( OoOO . record_ttl != 0 )
  Iiii1IIIiIi . last_registerer = source
  if 63 - 63: I1ii11iIi11i / II111iiii % oO0o + ooOoO0o . Ii1I % I11i
  if 59 - 59: I1Ii111 % o0oOOo0O0Ooo - I1IiiI * i1IIi
  if 5 - 5: I1IiiI
  if 22 - 22: II111iiii / iII111i
  Iiii1IIIiIi . auth_sha1_or_sha2 = O00
  Iiii1IIIiIi . proxy_reply_requested = OOoO00o0o . proxy_reply_requested
  Iiii1IIIiIi . lisp_sec_present = OOoO00o0o . lisp_sec_present
  Iiii1IIIiIi . map_notify_requested = OOoO00o0o . map_notify_requested
  Iiii1IIIiIi . mobile_node_requested = OOoO00o0o . mobile_node
  Iiii1IIIiIi . merge_register_requested = OOoO00o0o . merge_register_requested
  if 18 - 18: i11iIiiIii * ooOoO0o . I1IiiI + i1IIi + I11i
  Iiii1IIIiIi . use_register_ttl_requested = OOoO00o0o . use_ttl_for_timeout
  if ( Iiii1IIIiIi . use_register_ttl_requested ) :
   Iiii1IIIiIi . register_ttl = OoOO . store_ttl ( )
  else :
   Iiii1IIIiIi . register_ttl = LISP_SITE_TIMEOUT_CHECK_INTERVAL * 3
   if 62 - 62: O0 % o0oOOo0O0Ooo + iIii1I11I1II1 + iIii1I11I1II1 * ooOoO0o
  Iiii1IIIiIi . xtr_id_present = OOoO00o0o . xtr_id_present
  if ( Iiii1IIIiIi . xtr_id_present ) :
   Iiii1IIIiIi . xtr_id = OOoO00o0o . xtr_id
   Iiii1IIIiIi . site_id = OOoO00o0o . site_id
   if 21 - 21: o0oOOo0O0Ooo % O0
   if 81 - 81: i1IIi + i1IIi
   if 3 - 3: I1Ii111 . I1ii11iIi11i * iII111i * i11iIiiIii * IiII
   if 52 - 52: iIii1I11I1II1 % o0oOOo0O0Ooo % I1IiiI
   if 71 - 71: I1IiiI + iII111i
  if ( OOoO00o0o . merge_register_requested ) :
   if ( IiI1 . merge_in_site_eid ( Iiii1IIIiIi ) ) :
    Ii1oOOOOo00 . append ( [ OoOO . eid , OoOO . group ] )
    if 47 - 47: iIii1I11I1II1 . OoO0O00 . iIii1I11I1II1
   if ( OOoO00o0o . map_notify_requested ) :
    lisp_send_merged_map_notify ( lisp_sockets , IiI1 , OOoO00o0o ,
 OoOO )
    if 57 - 57: IiII * ooOoO0o * ooOoO0o * iIii1I11I1II1 * I1Ii111 + OoOoOO00
    if 83 - 83: OoOoOO00 . Oo0Ooo . OoO0O00
    if 65 - 65: iII111i * iIii1I11I1II1
  if ( OOoO0 == False ) : continue
  if ( len ( Ii1oOOOOo00 ) != 0 ) : continue
  if 48 - 48: iII111i * OoO0O00
  O000 . append ( Iiii1IIIiIi . print_eid_tuple ( ) )
  if 57 - 57: ooOoO0o + I1IiiI
  if 32 - 32: I1ii11iIi11i + OOooOOo - I11i
  if 82 - 82: Oo0Ooo % Oo0Ooo
  if 91 - 91: I11i
  if 98 - 98: I11i - II111iiii . IiII % Oo0Ooo
  if 65 - 65: OoO0O00
  if 65 - 65: oO0o
  OoOO = OoOO . encode ( )
  OoOO += O0Ooo0
  OOoOO00000Oo = [ Iiii1IIIiIi . print_eid_tuple ( ) ]
  lprint ( "    Changed RLOC-set, Map-Notifying old RLOC-set" )
  if 77 - 77: I11i * i1IIi - OOooOOo / OoOoOO00
  for OoOOo in ooooo0000000oOoo :
   if ( OoOOo . map_notify_requested == False ) : continue
   if ( OoOOo . rloc . is_exact_match ( source ) ) : continue
   lisp_build_map_notify ( lisp_sockets , OoOO , OOoOO00000Oo , 1 , OoOOo . rloc ,
 LISP_CTRL_PORT , OOoO00o0o . nonce , OOoO00o0o . key_id ,
 OOoO00o0o . alg_id , OOoO00o0o . auth_len , iI1iI1 , False )
   if 50 - 50: O0 - oO0o . oO0o
   if 98 - 98: IiII % Ii1I / Ii1I
   if 10 - 10: Ii1I
   if 69 - 69: I1Ii111 * OoooooooOO . o0oOOo0O0Ooo % I1IiiI
   if 70 - 70: iII111i . i11iIiiIii * I1Ii111
  lisp_notify_subscribers ( lisp_sockets , OoOO , Iiii1IIIiIi . eid , iI1iI1 )
  if 54 - 54: o0oOOo0O0Ooo . i1IIi / iII111i
  if 21 - 21: O0 + ooOoO0o
  if 53 - 53: Ii1I - II111iiii * iIii1I11I1II1
  if 91 - 91: OoOoOO00 % iIii1I11I1II1
  if 81 - 81: i11iIiiIii / OoOoOO00 + iIii1I11I1II1
 if ( len ( Ii1oOOOOo00 ) != 0 ) :
  lisp_queue_multicast_map_notify ( lisp_sockets , Ii1oOOOOo00 )
  if 65 - 65: o0oOOo0O0Ooo
  if 73 - 73: I11i . I1ii11iIi11i - OoO0O00 + OoooooooOO
  if 71 - 71: I1IiiI
  if 27 - 27: OoO0O00 + i1IIi * OoooooooOO * iIii1I11I1II1 - Ii1I
  if 85 - 85: OoO0O00 + II111iiii / OoO0O00 . II111iiii * OoOoOO00 * I1IiiI
  if 19 - 19: iII111i / Ii1I + iIii1I11I1II1 * O0 - Oo0Ooo
 if ( OOoO00o0o . merge_register_requested ) : return
 if 47 - 47: iIii1I11I1II1 % I1ii11iIi11i
 if 33 - 33: oO0o . oO0o / IiII + II111iiii
 if 34 - 34: OoO0O00 . OoOoOO00 / i1IIi / OOooOOo
 if 12 - 12: o0oOOo0O0Ooo . Oo0Ooo / II111iiii
 if 18 - 18: I1Ii111 % II111iiii + Ii1I * Oo0Ooo - OoooooooOO . Oo0Ooo
 if ( OOoO00o0o . map_notify_requested and iI1iI1 != None ) :
  lisp_build_map_notify ( lisp_sockets , iiOO0o0o00 , O000 ,
 OOoO00o0o . record_count , source , sport , OOoO00o0o . nonce ,
 OOoO00o0o . key_id , OOoO00o0o . alg_id , OOoO00o0o . auth_len ,
 iI1iI1 , True )
  if 25 - 25: OoO0O00
 return
 if 83 - 83: II111iiii . iIii1I11I1II1
 if 77 - 77: O0 . OoOoOO00 % oO0o / OOooOOo
 if 8 - 8: iII111i - i1IIi
 if 81 - 81: ooOoO0o / OOooOOo % OoOoOO00 . iIii1I11I1II1
 if 45 - 45: I1IiiI . ooOoO0o - OoooooooOO
 if 84 - 84: I1ii11iIi11i
 if 69 - 69: I1Ii111 + II111iiii
 if 92 - 92: OoooooooOO
 if 80 - 80: I1ii11iIi11i % I1ii11iIi11i . OoO0O00 . oO0o % I1IiiI % I11i
 if 4 - 4: OoO0O00 / iII111i / I1ii11iIi11i - o0oOOo0O0Ooo * I1Ii111
def lisp_process_multicast_map_notify ( packet , source ) :
 iiIi11I = lisp_map_notify ( "" )
 packet = iiIi11I . decode ( packet )
 if ( packet == None ) :
  lprint ( "Could not decode Map-Notify packet" )
  return
  if 24 - 24: OoooooooOO / ooOoO0o + Oo0Ooo - OOooOOo - o0oOOo0O0Ooo . I1ii11iIi11i
  if 2 - 2: I1IiiI . o0oOOo0O0Ooo / Oo0Ooo - OoOoOO00 - OoooooooOO
 iiIi11I . print_notify ( )
 if ( iiIi11I . record_count == 0 ) : return
 if 73 - 73: I1Ii111 . i11iIiiIii * ooOoO0o . IiII - I11i + I1Ii111
 I1IiiI1 = iiIi11I . eid_records
 if 7 - 7: OoO0O00 - OOooOOo * I11i . oO0o
 for Ii11 in range ( iiIi11I . record_count ) :
  OoOO = lisp_eid_record ( )
  I1IiiI1 = OoOO . decode ( I1IiiI1 )
  if ( packet == None ) : return
  OoOO . print_record ( "  " , False )
  if 17 - 17: iII111i - OOooOOo * I1IiiI + i1IIi % I1ii11iIi11i
  if 71 - 71: Ii1I - o0oOOo0O0Ooo - oO0o
  if 27 - 27: O0 - iIii1I11I1II1
  if 78 - 78: Oo0Ooo / o0oOOo0O0Ooo
  IIII = lisp_map_cache_lookup ( OoOO . eid , OoOO . group )
  if ( IIII == None ) :
   IIII = lisp_mapping ( OoOO . eid , OoOO . group , [ ] )
   IIII . add_cache ( )
   if 35 - 35: o0oOOo0O0Ooo . OoO0O00 / o0oOOo0O0Ooo / IiII - I1ii11iIi11i . Oo0Ooo
   if 97 - 97: i11iIiiIii + I1ii11iIi11i - I11i . oO0o
  IIII . mapping_source = None if source == "lisp-etr" else source
  IIII . map_cache_ttl = OoOO . store_ttl ( )
  if 76 - 76: IiII * II111iiii * I1ii11iIi11i + OoooooooOO - OoOoOO00 . Ii1I
  if 51 - 51: II111iiii % I1Ii111 * O0 . ooOoO0o * OoOoOO00
  if 17 - 17: I1IiiI % I11i
  if 28 - 28: I1ii11iIi11i * OoooooooOO
  if 19 - 19: Oo0Ooo - iII111i % OoOoOO00 * i11iIiiIii / oO0o . i11iIiiIii
  if ( len ( IIII . rloc_set ) != 0 and OoOO . rloc_count == 0 ) :
   IIII . rloc_set = [ ]
   IIII . build_best_rloc_set ( )
   lisp_write_ipc_map_cache ( True , IIII )
   lprint ( "Update {} map-cache entry with no RLOC-set" . format ( green ( IIII . print_eid_tuple ( ) , False ) ) )
   if 46 - 46: I1ii11iIi11i
   continue
   if 50 - 50: OOooOOo * OoO0O00 * OOooOOo % I1IiiI - I1Ii111 * Ii1I
   if 88 - 88: OOooOOo . iII111i / I11i
  ii1Ii1iI1 = IIII . rtrs_in_rloc_set ( )
  if 79 - 79: ooOoO0o . I1ii11iIi11i + IiII . iIii1I11I1II1 + OOooOOo
  if 79 - 79: I1Ii111
  if 81 - 81: OoooooooOO + OoOoOO00 / II111iiii
  if 39 - 39: I1Ii111 * I1IiiI - o0oOOo0O0Ooo . oO0o . OOooOOo * i11iIiiIii
  if 70 - 70: OoOoOO00 / OOooOOo - o0oOOo0O0Ooo
  for O0o0o00O in range ( OoOO . rloc_count ) :
   iI11iII1IiiI = lisp_rloc_record ( )
   I1IiiI1 = iI11iII1IiiI . decode ( I1IiiI1 , None )
   iI11iII1IiiI . print_record ( "    " )
   if ( OoOO . group . is_null ( ) ) : continue
   if ( iI11iII1IiiI . rle == None ) : continue
   if 82 - 82: OOooOOo . i11iIiiIii . I1ii11iIi11i % OoOoOO00 * Ii1I / OoO0O00
   if 56 - 56: o0oOOo0O0Ooo / I1IiiI + I11i + I1IiiI
   if 34 - 34: Oo0Ooo / i11iIiiIii - ooOoO0o
   if 77 - 77: OoOoOO00 * OoooooooOO
   if 41 - 41: iIii1I11I1II1 - O0 . II111iiii + I1IiiI - II111iiii / oO0o
   I1iIii1Ii = IIII . rloc_set [ 0 ] . stats if len ( IIII . rloc_set ) != 0 else None
   if 75 - 75: i11iIiiIii / oO0o
   if 34 - 34: O0
   if 11 - 11: o0oOOo0O0Ooo . IiII + OOooOOo
   if 35 - 35: I1ii11iIi11i . OOooOOo * I1Ii111 / OoooooooOO
   OoOOo = lisp_rloc ( )
   OoOOo . store_rloc_from_record ( iI11iII1IiiI , None , IIII . mapping_source )
   if ( I1iIii1Ii != None ) : OoOOo . stats = copy . deepcopy ( I1iIii1Ii )
   if 8 - 8: ooOoO0o + O0 + IiII - Oo0Ooo % OOooOOo
   if ( ii1Ii1iI1 and OoOOo . is_rtr ( ) == False ) : continue
   if 47 - 47: O0 / oO0o / I1ii11iIi11i . OoooooooOO / II111iiii . OOooOOo
   IIII . rloc_set = [ OoOOo ]
   IIII . build_best_rloc_set ( )
   lisp_write_ipc_map_cache ( True , IIII )
   if 58 - 58: oO0o / ooOoO0o
   lprint ( "Update {} map-cache entry with RLE {}" . format ( green ( IIII . print_eid_tuple ( ) , False ) , OoOOo . rle . print_rle ( False ) ) )
   if 31 - 31: o0oOOo0O0Ooo % I11i - OoO0O00
   if 40 - 40: o0oOOo0O0Ooo % OoOoOO00 + I11i / O0 - II111iiii
   if 9 - 9: OoooooooOO - OOooOOo . I11i * oO0o
 return
 if 3 - 3: iIii1I11I1II1 - OoO0O00
 if 38 - 38: O0 + ooOoO0o * I1Ii111 - oO0o * o0oOOo0O0Ooo
 if 97 - 97: Oo0Ooo - O0 * OoooooooOO
 if 52 - 52: i1IIi + IiII
 if 11 - 11: I1IiiI % iIii1I11I1II1 * Ii1I % ooOoO0o
 if 33 - 33: iII111i / O0 % II111iiii % OoOoOO00 / I1Ii111
 if 77 - 77: OoOoOO00 % I1IiiI % II111iiii * iII111i . OoOoOO00 / O0
 if 21 - 21: ooOoO0o - I11i . i11iIiiIii
def lisp_process_map_notify ( lisp_sockets , orig_packet , source ) :
 iiIi11I = lisp_map_notify ( "" )
 i1II1IiiIi = iiIi11I . decode ( orig_packet )
 if ( i1II1IiiIi == None ) :
  lprint ( "Could not decode Map-Notify packet" )
  return
  if 39 - 39: Oo0Ooo * II111iiii % OOooOOo / oO0o . ooOoO0o
  if 75 - 75: I11i / O0 + OoooooooOO + OOooOOo % iII111i + I1IiiI
 iiIi11I . print_notify ( )
 if 10 - 10: II111iiii * I11i - IiII * iIii1I11I1II1 . OoooooooOO
 if 39 - 39: I11i . I1IiiI % Oo0Ooo + oO0o
 if 76 - 76: I1IiiI * OoooooooOO - i11iIiiIii / I11i / Oo0Ooo
 if 82 - 82: IiII % ooOoO0o
 if 100 - 100: Oo0Ooo . oO0o - iII111i + OoooooooOO
 IiIIi1I1I11Ii = source . print_address ( )
 if ( iiIi11I . alg_id != 0 or iiIi11I . auth_len != 0 ) :
  oooO0OOo0O0O0 = None
  for iii11 in lisp_map_servers_list :
   if ( iii11 . find ( IiIIi1I1I11Ii ) == - 1 ) : continue
   oooO0OOo0O0O0 = lisp_map_servers_list [ iii11 ]
   if 27 - 27: Oo0Ooo . I1Ii111 - i1IIi * I1IiiI
  if ( oooO0OOo0O0O0 == None ) :
   lprint ( ( "  Could not find Map-Server {} to authenticate " + "Map-Notify" ) . format ( IiIIi1I1I11Ii ) )
   if 96 - 96: I1ii11iIi11i - Ii1I . I1ii11iIi11i
   return
   if 89 - 89: II111iiii % I1ii11iIi11i % IiII . I11i
   if 49 - 49: iII111i % i11iIiiIii * I11i - oO0o . OOooOOo . i11iIiiIii
  oooO0OOo0O0O0 . map_notifies_received += 1
  if 26 - 26: iIii1I11I1II1 + i11iIiiIii % iII111i + I1IiiI + oO0o - ooOoO0o
  iIiiIII1IIiI = lisp_verify_auth ( i1II1IiiIi , iiIi11I . alg_id ,
 iiIi11I . auth_data , oooO0OOo0O0O0 . password )
  if 4 - 4: Oo0Ooo - IiII - I11i
  lprint ( "  Authentication {} for Map-Notify" . format ( "succeeded" if iIiiIII1IIiI else "failed" ) )
  if 72 - 72: OoooooooOO
  if ( iIiiIII1IIiI == False ) : return
 else :
  oooO0OOo0O0O0 = lisp_ms ( IiIIi1I1I11Ii , None , "" , 0 , "" , False , False , False , False , 0 , 0 , 0 ,
 None )
  if 19 - 19: Oo0Ooo . OOooOOo
  if 58 - 58: IiII % iII111i + i1IIi % I1IiiI % OOooOOo . iII111i
  if 85 - 85: i11iIiiIii . o0oOOo0O0Ooo * iII111i . I1ii11iIi11i / I1Ii111 % Ii1I
  if 27 - 27: II111iiii . iIii1I11I1II1 / I1ii11iIi11i / i1IIi / iIii1I11I1II1
  if 70 - 70: i11iIiiIii . OoO0O00 / OoooooooOO * OoooooooOO - OOooOOo
  if 34 - 34: I1ii11iIi11i * i1IIi % OoooooooOO / I1IiiI
 I1IiiI1 = iiIi11I . eid_records
 if ( iiIi11I . record_count == 0 ) :
  lisp_send_map_notify_ack ( lisp_sockets , I1IiiI1 , iiIi11I , oooO0OOo0O0O0 )
  return
  if 39 - 39: OoO0O00 + IiII - II111iiii % I11i
  if 80 - 80: o0oOOo0O0Ooo * ooOoO0o
  if 87 - 87: I1Ii111 + O0 / I1ii11iIi11i / OoOoOO00 . Oo0Ooo - IiII
  if 24 - 24: OoOoOO00
  if 19 - 19: ooOoO0o
  if 43 - 43: O0 . I1Ii111 % OoooooooOO / I1IiiI . o0oOOo0O0Ooo - OoOoOO00
  if 46 - 46: I11i - OoooooooOO % o0oOOo0O0Ooo
  if 7 - 7: OoooooooOO - I1Ii111 * IiII
 OoOO = lisp_eid_record ( )
 i1II1IiiIi = OoOO . decode ( I1IiiI1 )
 if ( i1II1IiiIi == None ) : return
 if 20 - 20: o0oOOo0O0Ooo . OoooooooOO * I1IiiI . Oo0Ooo * OoOoOO00
 OoOO . print_record ( "  " , False )
 if 3 - 3: I1Ii111 % i11iIiiIii % O0 % II111iiii
 for O0o0o00O in range ( OoOO . rloc_count ) :
  iI11iII1IiiI = lisp_rloc_record ( )
  i1II1IiiIi = iI11iII1IiiI . decode ( i1II1IiiIi , None )
  if ( i1II1IiiIi == None ) :
   lprint ( "  Could not decode RLOC-record in Map-Notify packet" )
   return
   if 8 - 8: OoooooooOO * ooOoO0o
  iI11iII1IiiI . print_record ( "    " )
  if 26 - 26: i11iIiiIii + oO0o - i1IIi
  if 71 - 71: I1IiiI % I1Ii111 / oO0o % oO0o / iIii1I11I1II1 + I1Ii111
  if 86 - 86: IiII % i1IIi * o0oOOo0O0Ooo - I1Ii111
  if 37 - 37: iII111i % I1IiiI - I1ii11iIi11i % I11i
  if 35 - 35: O0 - OoooooooOO % iII111i
 if ( OoOO . group . is_null ( ) == False ) :
  if 48 - 48: OOooOOo % i11iIiiIii
  if 49 - 49: O0 * iII111i + II111iiii - OOooOOo
  if 29 - 29: OoooooooOO % II111iiii - Oo0Ooo / IiII - i11iIiiIii
  if 64 - 64: iII111i . I1Ii111 + I1Ii111
  if 1 - 1: OOooOOo % Oo0Ooo
  lprint ( "Send {} Map-Notify IPC message to ITR process" . format ( green ( OoOO . print_eid_tuple ( ) , False ) ) )
  if 81 - 81: oO0o / I11i % Ii1I . I11i + OoooooooOO
  if 31 - 31: OoO0O00
  IIi1IiIii = lisp_control_packet_ipc ( orig_packet , IiIIi1I1I11Ii , "lisp-itr" , 0 )
  lisp_ipc ( IIi1IiIii , lisp_sockets [ 2 ] , "lisp-core-pkt" )
  if 41 - 41: i11iIiiIii - I1ii11iIi11i - II111iiii
  if 5 - 5: OoOoOO00 + i1IIi
  if 43 - 43: iII111i * I1IiiI
  if 20 - 20: I1IiiI . I11i * OoO0O00 . ooOoO0o . II111iiii
  if 6 - 6: Ii1I * OoOoOO00 % IiII + I11i
 lisp_send_map_notify_ack ( lisp_sockets , I1IiiI1 , iiIi11I , oooO0OOo0O0O0 )
 return
 if 20 - 20: oO0o
 if 34 - 34: i1IIi + oO0o * Oo0Ooo * I1Ii111 % OoooooooOO % ooOoO0o
 if 17 - 17: I1ii11iIi11i + o0oOOo0O0Ooo / OoO0O00 . Oo0Ooo - o0oOOo0O0Ooo / oO0o
 if 87 - 87: ooOoO0o
 if 74 - 74: i11iIiiIii . i11iIiiIii . iIii1I11I1II1
 if 100 - 100: i11iIiiIii - oO0o + iIii1I11I1II1 * OoOoOO00 % OOooOOo % i11iIiiIii
 if 26 - 26: O0
 if 97 - 97: OOooOOo + I11i % I1Ii111 % i11iIiiIii / I1ii11iIi11i
def lisp_process_map_notify_ack ( packet , source ) :
 iiIi11I = lisp_map_notify ( "" )
 packet = iiIi11I . decode ( packet )
 if ( packet == None ) :
  lprint ( "Could not decode Map-Notify-Ack packet" )
  return
  if 21 - 21: O0 + iIii1I11I1II1 / i11iIiiIii . OOooOOo * i1IIi
  if 3 - 3: i1IIi % o0oOOo0O0Ooo + OoOoOO00
 iiIi11I . print_notify ( )
 if 32 - 32: OoO0O00 . Oo0Ooo * iIii1I11I1II1
 if 12 - 12: O0 + I1ii11iIi11i + I11i . I1Ii111
 if 48 - 48: Ii1I . iIii1I11I1II1 - iIii1I11I1II1 * I11i . OoooooooOO
 if 73 - 73: Ii1I / II111iiii - iIii1I11I1II1 . ooOoO0o * II111iiii . OOooOOo
 if 50 - 50: iIii1I11I1II1 + OoOoOO00 % O0 + OoO0O00 . i11iIiiIii / oO0o
 if ( iiIi11I . record_count < 1 ) :
  lprint ( "No EID-prefix found, cannot authenticate Map-Notify-Ack" )
  return
  if 31 - 31: I1IiiI % o0oOOo0O0Ooo . i11iIiiIii % OOooOOo - iIii1I11I1II1
  if 77 - 77: i11iIiiIii / OOooOOo
 OoOO = lisp_eid_record ( )
 if 93 - 93: I1ii11iIi11i - iII111i % O0 - Ii1I
 if ( OoOO . decode ( iiIi11I . eid_records ) == None ) :
  lprint ( "Could not decode EID-record, cannot authenticate " +
 "Map-Notify-Ack" )
  return
  if 84 - 84: I1ii11iIi11i . iIii1I11I1II1 % IiII * I11i + ooOoO0o
 OoOO . print_record ( "  " , False )
 if 59 - 59: oO0o * OoO0O00 - I11i * I1IiiI
 oOoo0OooOOo00 = OoOO . print_eid_tuple ( )
 if 60 - 60: iII111i - OoooooooOO / iII111i % OoO0O00 . OoOoOO00 - o0oOOo0O0Ooo
 if 71 - 71: iII111i * o0oOOo0O0Ooo * i11iIiiIii * O0
 if 77 - 77: OOooOOo % iII111i + I11i / OoOoOO00
 if 50 - 50: OoOoOO00 - i11iIiiIii - OOooOOo . iIii1I11I1II1
 if ( iiIi11I . alg_id != LISP_NONE_ALG_ID and iiIi11I . auth_len != 0 ) :
  Iiii1IIIiIi = lisp_sites_by_eid . lookup_cache ( OoOO . eid , True )
  if ( Iiii1IIIiIi == None ) :
   iIiiiiiiI1II = bold ( "Site not found" , False )
   lprint ( ( "{} for EID {}, cannot authenticate Map-Notify-Ack" ) . format ( iIiiiiiiI1II , green ( oOoo0OooOOo00 , False ) ) )
   if 97 - 97: oO0o % OOooOOo . OoooooooOO * Ii1I
   return
   if 100 - 100: I1ii11iIi11i / Ii1I % Oo0Ooo
  iI1iI1 = Iiii1IIIiIi . site
  if 83 - 83: O0 . I1Ii111 % I1ii11iIi11i
  if 97 - 97: Oo0Ooo % OoO0O00 * I1ii11iIi11i * ooOoO0o * OoO0O00
  if 12 - 12: ooOoO0o
  if 56 - 56: i1IIi
  iI1iI1 . map_notify_acks_received += 1
  if 3 - 3: OOooOOo - Oo0Ooo * Ii1I + i11iIiiIii
  I1o0 = iiIi11I . key_id
  if ( iI1iI1 . auth_key . has_key ( I1o0 ) == False ) : I1o0 = 0
  Oo00oO0 = iI1iI1 . auth_key [ I1o0 ]
  if 53 - 53: i1IIi % I1ii11iIi11i
  iIiiIII1IIiI = lisp_verify_auth ( packet , iiIi11I . alg_id ,
 iiIi11I . auth_data , Oo00oO0 )
  if 65 - 65: I11i + OoOoOO00 - i11iIiiIii
  I1o0 = "key-id {}" . format ( I1o0 ) if I1o0 == iiIi11I . key_id else "bad key-id {}" . format ( iiIi11I . key_id )
  if 72 - 72: i11iIiiIii - iII111i . i11iIiiIii
  if 61 - 61: oO0o . i11iIiiIii / Ii1I % iII111i
  lprint ( "  Authentication {} for Map-Notify-Ack, {}" . format ( "succeeded" if iIiiIII1IIiI else "failed" , I1o0 ) )
  if 36 - 36: OoO0O00 + Ii1I / I11i - iII111i % OoO0O00 / Oo0Ooo
  if ( iIiiIII1IIiI == False ) : return
  if 38 - 38: Ii1I - ooOoO0o - O0 + oO0o . iIii1I11I1II1
  if 90 - 90: i1IIi * OoOoOO00
  if 27 - 27: iIii1I11I1II1
  if 95 - 95: iII111i / ooOoO0o % Ii1I
  if 44 - 44: OOooOOo . OOooOOo
 if ( iiIi11I . retransmit_timer ) : iiIi11I . retransmit_timer . cancel ( )
 if 5 - 5: oO0o + OoooooooOO
 oo000oOOooo0O = source . print_address ( )
 iii11 = iiIi11I . nonce_key
 if 88 - 88: oO0o + OOooOOo
 if ( lisp_map_notify_queue . has_key ( iii11 ) ) :
  iiIi11I = lisp_map_notify_queue . pop ( iii11 )
  if ( iiIi11I . retransmit_timer ) : iiIi11I . retransmit_timer . cancel ( )
  lprint ( "Dequeue Map-Notify from retransmit queue, key is: {}" . format ( iii11 ) )
  if 14 - 14: I11i / i1IIi
 else :
  lprint ( "Map-Notify with nonce 0x{} queue entry not found for {}" . format ( iiIi11I . nonce_key , red ( oo000oOOooo0O , False ) ) )
  if 56 - 56: OoooooooOO
  if 59 - 59: I1ii11iIi11i + OoO0O00
 return
 if 37 - 37: IiII * I1IiiI % O0
 if 32 - 32: ooOoO0o % II111iiii
 if 60 - 60: i11iIiiIii
 if 11 - 11: o0oOOo0O0Ooo
 if 77 - 77: o0oOOo0O0Ooo / iIii1I11I1II1 * iIii1I11I1II1 / o0oOOo0O0Ooo * iII111i
 if 26 - 26: Ii1I
 if 1 - 1: OoOoOO00 . o0oOOo0O0Ooo + Oo0Ooo % Oo0Ooo * I1ii11iIi11i
 if 50 - 50: IiII / i1IIi . I1ii11iIi11i
def lisp_map_referral_loop ( mr , eid , group , action , s ) :
 if ( action not in ( LISP_DDT_ACTION_NODE_REFERRAL ,
 LISP_DDT_ACTION_MS_REFERRAL ) ) : return ( False )
 if 75 - 75: I11i * oO0o + OoooooooOO . iII111i + OoO0O00
 if ( mr . last_cached_prefix [ 0 ] == None ) : return ( False )
 if 44 - 44: II111iiii
 if 65 - 65: I11i . iII111i . I1IiiI - Oo0Ooo % iIii1I11I1II1 / O0
 if 54 - 54: iII111i - I1Ii111
 if 88 - 88: iII111i * OoO0O00 % OoooooooOO / oO0o
 Oo00O0OoooO = False
 if ( group . is_null ( ) == False ) :
  Oo00O0OoooO = mr . last_cached_prefix [ 1 ] . is_more_specific ( group )
  if 7 - 7: i1IIi
 if ( Oo00O0OoooO == False ) :
  Oo00O0OoooO = mr . last_cached_prefix [ 0 ] . is_more_specific ( eid )
  if 30 - 30: oO0o . i1IIi / I11i
  if 23 - 23: i1IIi + oO0o % iII111i - OoO0O00 - i1IIi
 if ( Oo00O0OoooO ) :
  iiI11IIii1i1 = lisp_print_eid_tuple ( eid , group )
  O0o0OoO = lisp_print_eid_tuple ( mr . last_cached_prefix [ 0 ] ,
 mr . last_cached_prefix [ 1 ] )
  if 2 - 2: oO0o - o0oOOo0O0Ooo
  lprint ( ( "Map-Referral prefix {} from {} is not more-specific " + "than cached prefix {}" ) . format ( green ( iiI11IIii1i1 , False ) , s ,
  # i1IIi . ooOoO0o + O0 . ooOoO0o * iIii1I11I1II1
 O0o0OoO ) )
  if 82 - 82: iII111i % OoO0O00 * O0
 return ( Oo00O0OoooO )
 if 38 - 38: o0oOOo0O0Ooo * o0oOOo0O0Ooo - I1IiiI . iII111i % iIii1I11I1II1 + I1ii11iIi11i
 if 56 - 56: I1Ii111 % oO0o
 if 31 - 31: OOooOOo + IiII
 if 56 - 56: OoooooooOO * II111iiii
 if 99 - 99: i11iIiiIii - II111iiii . Oo0Ooo - oO0o . I1IiiI + i1IIi
 if 69 - 69: O0 / i1IIi - OoOoOO00 + ooOoO0o - oO0o
 if 80 - 80: o0oOOo0O0Ooo % O0 * I11i . i1IIi - ooOoO0o
def lisp_process_map_referral ( lisp_sockets , packet , source ) :
 if 93 - 93: OoooooooOO / o0oOOo0O0Ooo
 O0oO0o = lisp_map_referral ( )
 packet = O0oO0o . decode ( packet )
 if ( packet == None ) :
  lprint ( "Could not decode Map-Referral packet" )
  return
  if 61 - 61: II111iiii / i1IIi . I1ii11iIi11i % iIii1I11I1II1
 O0oO0o . print_map_referral ( )
 if 66 - 66: iIii1I11I1II1 % OoOoOO00 + i1IIi * i11iIiiIii * OoooooooOO
 IiIIi1I1I11Ii = source . print_address ( )
 oOo0 = O0oO0o . nonce
 if 36 - 36: iII111i - OoO0O00 + I1IiiI + Ii1I . OoooooooOO
 if 75 - 75: oO0o * Oo0Ooo * O0
 if 22 - 22: ooOoO0o / OoooooooOO . II111iiii / Ii1I * OoO0O00 . i1IIi
 if 62 - 62: oO0o % Ii1I - Ii1I
 for Ii11 in range ( O0oO0o . record_count ) :
  OoOO = lisp_eid_record ( )
  packet = OoOO . decode ( packet )
  if ( packet == None ) :
   lprint ( "Could not decode EID-record in Map-Referral packet" )
   return
   if 16 - 16: OoO0O00 - O0 - OOooOOo - I11i % OoOoOO00
  OoOO . print_record ( "  " , True )
  if 7 - 7: I1Ii111 / OoOoOO00 . II111iiii
  if 9 - 9: I11i . I11i . OoooooooOO
  if 42 - 42: iII111i / oO0o / iII111i * OoO0O00
  if 25 - 25: OoOoOO00 - II111iiii + II111iiii . Ii1I * II111iiii
  iii11 = str ( oOo0 )
  if ( iii11 not in lisp_ddt_map_requestQ ) :
   lprint ( ( "Map-Referral nonce 0x{} from {} not found in " + "Map-Request queue, EID-record ignored" ) . format ( lisp_hex_string ( oOo0 ) , IiIIi1I1I11Ii ) )
   if 12 - 12: IiII / Ii1I
   if 54 - 54: Oo0Ooo + Ii1I % OoooooooOO * OOooOOo / OoOoOO00
   continue
   if 39 - 39: I1IiiI % i11iIiiIii % Ii1I
  oOO0O000OOo0 = lisp_ddt_map_requestQ [ iii11 ]
  if ( oOO0O000OOo0 == None ) :
   lprint ( ( "No Map-Request queue entry found for Map-Referral " +
 "nonce 0x{} from {}, EID-record ignored" ) . format ( lisp_hex_string ( oOo0 ) , IiIIi1I1I11Ii ) )
   if 59 - 59: ooOoO0o % OoO0O00 / I1IiiI - II111iiii + OoooooooOO * i11iIiiIii
   continue
   if 58 - 58: IiII / Oo0Ooo + o0oOOo0O0Ooo
   if 71 - 71: Ii1I - IiII
   if 2 - 2: OoOoOO00 % IiII % OoO0O00 . i1IIi / I1Ii111 - iIii1I11I1II1
   if 88 - 88: Oo0Ooo * i1IIi % OOooOOo
   if 65 - 65: iII111i . oO0o
   if 67 - 67: I1IiiI / iII111i / O0 % ooOoO0o - IiII / Ii1I
  if ( lisp_map_referral_loop ( oOO0O000OOo0 , OoOO . eid , OoOO . group ,
 OoOO . action , IiIIi1I1I11Ii ) ) :
   oOO0O000OOo0 . dequeue_map_request ( )
   continue
   if 31 - 31: I11i - oO0o * ooOoO0o
   if 64 - 64: I11i
  oOO0O000OOo0 . last_cached_prefix [ 0 ] = OoOO . eid
  oOO0O000OOo0 . last_cached_prefix [ 1 ] = OoOO . group
  if 41 - 41: I1Ii111 * OoooooooOO / OoOoOO00 + OoO0O00 . OoOoOO00 + I1Ii111
  if 9 - 9: IiII . I11i . I1Ii111 / i1IIi * OoOoOO00 - O0
  if 3 - 3: O0 / iIii1I11I1II1 % IiII + I11i
  if 43 - 43: Oo0Ooo % I11i
  i1111ii1 = False
  IiiII1 = lisp_referral_cache_lookup ( OoOO . eid , OoOO . group ,
 True )
  if ( IiiII1 == None ) :
   i1111ii1 = True
   IiiII1 = lisp_referral ( )
   IiiII1 . eid = OoOO . eid
   IiiII1 . group = OoOO . group
   if ( OoOO . ddt_incomplete == False ) : IiiII1 . add_cache ( )
  elif ( IiiII1 . referral_source . not_set ( ) ) :
   lprint ( "Do not replace static referral entry {}" . format ( green ( IiiII1 . print_eid_tuple ( ) , False ) ) )
   if 53 - 53: OoOoOO00 % OoooooooOO * o0oOOo0O0Ooo % OoooooooOO
   oOO0O000OOo0 . dequeue_map_request ( )
   continue
   if 47 - 47: iIii1I11I1II1 - OOooOOo + I1ii11iIi11i * ooOoO0o + Oo0Ooo + OoO0O00
   if 64 - 64: OoOoOO00 - OoOoOO00 . OoooooooOO + ooOoO0o
  ooOOoo0 = OoOO . action
  IiiII1 . referral_source = source
  IiiII1 . referral_type = ooOOoo0
  iiI = OoOO . store_ttl ( )
  IiiII1 . referral_ttl = iiI
  IiiII1 . expires = lisp_set_timestamp ( iiI )
  if 100 - 100: ooOoO0o . OoooooooOO % i1IIi % OoO0O00
  if 26 - 26: OoOoOO00 * IiII
  if 76 - 76: I1IiiI + IiII * I1ii11iIi11i * I1IiiI % Ii1I + ooOoO0o
  if 46 - 46: OoOoOO00
  O0oo00ooo = IiiII1 . is_referral_negative ( )
  if ( IiiII1 . referral_set . has_key ( IiIIi1I1I11Ii ) ) :
   ooO = IiiII1 . referral_set [ IiIIi1I1I11Ii ]
   if 41 - 41: ooOoO0o + IiII
   if ( ooO . updown == False and O0oo00ooo == False ) :
    ooO . updown = True
    lprint ( "Change up/down status for referral-node {} to up" . format ( IiIIi1I1I11Ii ) )
    if 97 - 97: I11i % I11i
   elif ( ooO . updown == True and O0oo00ooo == True ) :
    ooO . updown = False
    lprint ( ( "Change up/down status for referral-node {} " + "to down, received negative referral" ) . format ( IiIIi1I1I11Ii ) )
    if 18 - 18: OoooooooOO . OOooOOo * Ii1I + II111iiii - I1ii11iIi11i
    if 61 - 61: Ii1I % i1IIi + OoOoOO00 % o0oOOo0O0Ooo + Oo0Ooo % OoooooooOO
    if 5 - 5: i1IIi % Oo0Ooo / OoooooooOO * OoOoOO00 + OOooOOo - ooOoO0o
    if 24 - 24: oO0o / ooOoO0o % I1IiiI / I1ii11iIi11i
    if 88 - 88: OoO0O00
    if 96 - 96: IiII % I1ii11iIi11i % Oo0Ooo - i11iIiiIii % iIii1I11I1II1
    if 100 - 100: IiII - Ii1I
    if 9 - 9: II111iiii / Ii1I / O0 - OoOoOO00 - IiII
  II1i = { }
  for iii11 in IiiII1 . referral_set : II1i [ iii11 ] = None
  if 94 - 94: I1ii11iIi11i . o0oOOo0O0Ooo
  if 59 - 59: iII111i - Oo0Ooo . OOooOOo . ooOoO0o % oO0o
  if 95 - 95: OoO0O00 + O0 * oO0o
  if 39 - 39: i1IIi
  for Ii11 in range ( OoOO . rloc_count ) :
   iI11iII1IiiI = lisp_rloc_record ( )
   packet = iI11iII1IiiI . decode ( packet , None )
   if ( packet == None ) :
    lprint ( "Could not decode RLOC-record in Map-Referral packet" )
    return
    if 32 - 32: IiII . ooOoO0o / OoO0O00 / iII111i . iIii1I11I1II1 % IiII
   iI11iII1IiiI . print_record ( "    " )
   if 28 - 28: I1Ii111 + OoooooooOO + IiII . ooOoO0o . I1IiiI / oO0o
   if 66 - 66: Ii1I - I11i + Oo0Ooo . ooOoO0o
   if 89 - 89: IiII . II111iiii / OoO0O00 + I1ii11iIi11i * i11iIiiIii
   if 85 - 85: o0oOOo0O0Ooo - Oo0Ooo / I1Ii111
   I1iiIiiii1111 = iI11iII1IiiI . rloc . print_address ( )
   if ( IiiII1 . referral_set . has_key ( I1iiIiiii1111 ) == False ) :
    ooO = lisp_referral_node ( )
    ooO . referral_address . copy_address ( iI11iII1IiiI . rloc )
    IiiII1 . referral_set [ I1iiIiiii1111 ] = ooO
    if ( IiIIi1I1I11Ii == I1iiIiiii1111 and O0oo00ooo ) : ooO . updown = False
   else :
    ooO = IiiII1 . referral_set [ I1iiIiiii1111 ]
    if ( II1i . has_key ( I1iiIiiii1111 ) ) : II1i . pop ( I1iiIiiii1111 )
    if 100 - 100: OoO0O00 * iIii1I11I1II1 - IiII . i1IIi % i11iIiiIii % Oo0Ooo
   ooO . priority = iI11iII1IiiI . priority
   ooO . weight = iI11iII1IiiI . weight
   if 22 - 22: ooOoO0o - OOooOOo
   if 90 - 90: i11iIiiIii . i11iIiiIii - iIii1I11I1II1
   if 20 - 20: ooOoO0o - i11iIiiIii
   if 23 - 23: OoO0O00 + I1IiiI / I1ii11iIi11i * I1ii11iIi11i % ooOoO0o
   if 83 - 83: I1IiiI * i11iIiiIii - I1ii11iIi11i + I11i
  for iii11 in II1i : IiiII1 . referral_set . pop ( iii11 )
  if 33 - 33: OoO0O00 . OoooooooOO % iII111i / oO0o * Ii1I + ooOoO0o
  oOoo0OooOOo00 = IiiII1 . print_eid_tuple ( )
  if 29 - 29: oO0o
  if ( i1111ii1 ) :
   if ( OoOO . ddt_incomplete ) :
    lprint ( "Suppress add {} to referral-cache" . format ( green ( oOoo0OooOOo00 , False ) ) )
    if 21 - 21: i11iIiiIii . o0oOOo0O0Ooo
   else :
    lprint ( "Add {}, referral-count {} to referral-cache" . format ( green ( oOoo0OooOOo00 , False ) , OoOO . rloc_count ) )
    if 78 - 78: Oo0Ooo
    if 77 - 77: oO0o % Oo0Ooo % O0
  else :
   lprint ( "Replace {}, referral-count: {} in referral-cache" . format ( green ( oOoo0OooOOo00 , False ) , OoOO . rloc_count ) )
   if 51 - 51: IiII % IiII + OOooOOo . II111iiii / I1ii11iIi11i
   if 4 - 4: o0oOOo0O0Ooo % I1IiiI * o0oOOo0O0Ooo * OoOoOO00 - Ii1I
   if 61 - 61: OoooooooOO - OoOoOO00 . O0 / ooOoO0o . Ii1I
   if 41 - 41: Oo0Ooo / OoOoOO00 % I1Ii111 - O0
   if 19 - 19: I1IiiI % I1Ii111 - O0 . iIii1I11I1II1 . I11i % O0
   if 88 - 88: ooOoO0o
  if ( ooOOoo0 == LISP_DDT_ACTION_DELEGATION_HOLE ) :
   lisp_send_negative_map_reply ( oOO0O000OOo0 . lisp_sockets , IiiII1 . eid ,
 IiiII1 . group , oOO0O000OOo0 . nonce , oOO0O000OOo0 . itr , oOO0O000OOo0 . sport , 15 , None , False )
   oOO0O000OOo0 . dequeue_map_request ( )
   if 52 - 52: iIii1I11I1II1 % ooOoO0o * iIii1I11I1II1
   if 20 - 20: i11iIiiIii * I11i
  if ( ooOOoo0 == LISP_DDT_ACTION_NOT_AUTH ) :
   if ( oOO0O000OOo0 . tried_root ) :
    lisp_send_negative_map_reply ( oOO0O000OOo0 . lisp_sockets , IiiII1 . eid ,
 IiiII1 . group , oOO0O000OOo0 . nonce , oOO0O000OOo0 . itr , oOO0O000OOo0 . sport , 0 , None , False )
    oOO0O000OOo0 . dequeue_map_request ( )
   else :
    lisp_send_ddt_map_request ( oOO0O000OOo0 , True )
    if 29 - 29: IiII / OOooOOo
    if 39 - 39: O0 + II111iiii
    if 94 - 94: OOooOOo % I1ii11iIi11i % O0 + iII111i
  if ( ooOOoo0 == LISP_DDT_ACTION_MS_NOT_REG ) :
   if ( IiiII1 . referral_set . has_key ( IiIIi1I1I11Ii ) ) :
    ooO = IiiII1 . referral_set [ IiIIi1I1I11Ii ]
    ooO . updown = False
    if 62 - 62: iIii1I11I1II1 . OoOoOO00 / iIii1I11I1II1 + IiII
   if ( len ( IiiII1 . referral_set ) == 0 ) :
    oOO0O000OOo0 . dequeue_map_request ( )
   else :
    lisp_send_ddt_map_request ( oOO0O000OOo0 , False )
    if 31 - 31: Ii1I . OoO0O00 . Ii1I + OoO0O00 * iIii1I11I1II1 . iII111i
    if 42 - 42: O0 / oO0o % O0 . i1IIi % OOooOOo
    if 13 - 13: I1IiiI % ooOoO0o + OOooOOo
  if ( ooOOoo0 in ( LISP_DDT_ACTION_NODE_REFERRAL ,
 LISP_DDT_ACTION_MS_REFERRAL ) ) :
   if ( oOO0O000OOo0 . eid . is_exact_match ( OoOO . eid ) ) :
    if ( not oOO0O000OOo0 . tried_root ) :
     lisp_send_ddt_map_request ( oOO0O000OOo0 , True )
    else :
     lisp_send_negative_map_reply ( oOO0O000OOo0 . lisp_sockets ,
 IiiII1 . eid , IiiII1 . group , oOO0O000OOo0 . nonce , oOO0O000OOo0 . itr ,
 oOO0O000OOo0 . sport , 15 , None , False )
     oOO0O000OOo0 . dequeue_map_request ( )
     if 91 - 91: oO0o - ooOoO0o
   else :
    lisp_send_ddt_map_request ( oOO0O000OOo0 , False )
    if 20 - 20: i1IIi . IiII / o0oOOo0O0Ooo / I11i
    if 27 - 27: ooOoO0o . ooOoO0o - Ii1I % i11iIiiIii
    if 74 - 74: I1Ii111 - II111iiii % o0oOOo0O0Ooo
  if ( ooOOoo0 == LISP_DDT_ACTION_MS_ACK ) : oOO0O000OOo0 . dequeue_map_request ( )
  if 7 - 7: I1IiiI + OoooooooOO + o0oOOo0O0Ooo . OoooooooOO
 return
 if 29 - 29: iII111i * O0 + I1IiiI * IiII + iII111i - IiII
 if 38 - 38: I1ii11iIi11i - Ii1I % OoooooooOO
 if 43 - 43: iIii1I11I1II1 / OoOoOO00
 if 13 - 13: o0oOOo0O0Ooo / I1Ii111
 if 67 - 67: OoooooooOO . oO0o * OoOoOO00 - OoooooooOO
 if 32 - 32: oO0o
 if 72 - 72: I1IiiI
 if 34 - 34: ooOoO0o % II111iiii / ooOoO0o
def lisp_process_ecm ( lisp_sockets , packet , source , ecm_port ) :
 iiIIIiI1 = lisp_ecm ( 0 )
 packet = iiIIIiI1 . decode ( packet )
 if ( packet == None ) :
  lprint ( "Could not decode ECM packet" )
  return
  if 87 - 87: Oo0Ooo
  if 7 - 7: iIii1I11I1II1
 iiIIIiI1 . print_ecm ( )
 if 85 - 85: iIii1I11I1II1 . O0
 iIiI1I1II1 = lisp_control_header ( )
 if ( iIiI1I1II1 . decode ( packet ) == None ) :
  lprint ( "Could not decode control header" )
  return
  if 43 - 43: II111iiii / OoOoOO00 + OOooOOo % Oo0Ooo * OOooOOo
  if 62 - 62: ooOoO0o * OOooOOo . I11i + Oo0Ooo - I1Ii111
 I11I1I1iiiIIi = iIiI1I1II1 . type
 del ( iIiI1I1II1 )
 if 63 - 63: I11i % I1ii11iIi11i / o0oOOo0O0Ooo
 if ( I11I1I1iiiIIi != LISP_MAP_REQUEST ) :
  lprint ( "Received ECM without Map-Request inside" )
  return
  if 95 - 95: oO0o * I1IiiI / OOooOOo
  if 79 - 79: O0 . iII111i . iII111i % ooOoO0o
  if 74 - 74: ooOoO0o
  if 37 - 37: oO0o / i1IIi * iII111i - i1IIi
  if 12 - 12: OoO0O00 * IiII + OoOoOO00 * I1Ii111 % OoOoOO00 + OoOoOO00
 II11iI1iI1I = iiIIIiI1 . udp_sport
 lisp_process_map_request ( lisp_sockets , packet , source , ecm_port ,
 iiIIIiI1 . source , II11iI1iI1I , iiIIIiI1 . ddt , - 1 )
 return
 if 33 - 33: OoO0O00 * I1IiiI / i1IIi
 if 88 - 88: Ii1I / ooOoO0o - I11i % OoO0O00 * iII111i
 if 47 - 47: i11iIiiIii + Oo0Ooo % oO0o % O0
 if 98 - 98: oO0o - O0 / iII111i % oO0o % I1IiiI / i1IIi
 if 61 - 61: ooOoO0o + II111iiii
 if 54 - 54: OoOoOO00 * o0oOOo0O0Ooo . OoO0O00
 if 53 - 53: oO0o % OoO0O00 / OoO0O00 / I11i * Oo0Ooo
 if 13 - 13: i1IIi % iIii1I11I1II1 - iII111i - I1IiiI - IiII + iIii1I11I1II1
 if 22 - 22: IiII - OOooOOo + I1ii11iIi11i
 if 64 - 64: OoOoOO00
def lisp_send_map_register ( lisp_sockets , packet , map_register , ms ) :
 if 79 - 79: IiII
 if 65 - 65: Oo0Ooo - i11iIiiIii * OoOoOO00 . I1Ii111 . iIii1I11I1II1
 if 48 - 48: iIii1I11I1II1 - oO0o / OoO0O00 + O0 . Ii1I + I1Ii111
 if 17 - 17: OoOoOO00 . Oo0Ooo - I1Ii111 / I1Ii111 + I11i % i1IIi
 if 31 - 31: OoooooooOO . O0 / OoO0O00 . I1Ii111
 if 41 - 41: OoooooooOO + iII111i . OOooOOo
 if 73 - 73: oO0o + i1IIi + i11iIiiIii / I1ii11iIi11i
 iI111I1 = ms . map_server
 if ( lisp_decent_push_configured and iI111I1 . is_multicast_address ( ) and
 ( ms . map_registers_multicast_sent == 1 or ms . map_registers_sent == 1 ) ) :
  iI111I1 = copy . deepcopy ( iI111I1 )
  iI111I1 . address = 0x7f000001
  iIIi1I1ii = bold ( "Bootstrap" , False )
  O0ooO0oOO = ms . map_server . print_address_no_iid ( )
  lprint ( "{} mapping system for peer-group {}" . format ( iIIi1I1ii , O0ooO0oOO ) )
  if 100 - 100: I1IiiI % ooOoO0o % OoooooooOO / i11iIiiIii + i11iIiiIii % IiII
  if 39 - 39: Ii1I % o0oOOo0O0Ooo + OOooOOo / iIii1I11I1II1
  if 40 - 40: iIii1I11I1II1 / iII111i % OOooOOo % i11iIiiIii
  if 57 - 57: II111iiii % OoO0O00 * i1IIi
  if 19 - 19: ooOoO0o . iIii1I11I1II1 + I1ii11iIi11i + I1ii11iIi11i / o0oOOo0O0Ooo . Oo0Ooo
  if 9 - 9: II111iiii % OoooooooOO
 packet = lisp_compute_auth ( packet , map_register , ms . password )
 if 4 - 4: i1IIi * i11iIiiIii % OoooooooOO + OoOoOO00 . oO0o
 if 95 - 95: I1ii11iIi11i * OoOoOO00 % o0oOOo0O0Ooo / O0 + ooOoO0o % OOooOOo
 if 48 - 48: i1IIi + IiII - iIii1I11I1II1 . i11iIiiIii % OOooOOo + I1ii11iIi11i
 if 95 - 95: ooOoO0o + OoOoOO00 . II111iiii + Ii1I
 if 81 - 81: OoooooooOO / OOooOOo / Oo0Ooo
 if ( ms . ekey != None ) :
  Iiio0oO = ms . ekey . zfill ( 32 )
  O0o = "0" * 8
  Oo0 = chacha . ChaCha ( Iiio0oO , O0o ) . encrypt ( packet [ 4 : : ] )
  packet = packet [ 0 : 4 ] + Oo0
  ooo0OO = bold ( "Encrypt" , False )
  lprint ( "{} Map-Register with key-id {}" . format ( ooo0OO , ms . ekey_id ) )
  if 26 - 26: iII111i
  if 93 - 93: Oo0Ooo + I1IiiI % OoOoOO00 / OOooOOo / I1ii11iIi11i
 i1iI11i1iiII = ""
 if ( lisp_decent_pull_xtr_configured ( ) ) :
  i1iI11i1iiII = ", decent-index {}" . format ( bold ( ms . dns_name , False ) )
  if 76 - 76: II111iiii + i11iIiiIii - OoooooooOO % OoOoOO00
  if 4 - 4: I1Ii111 + i11iIiiIii . Ii1I / iII111i
 lprint ( "Send Map-Register to map-server {}{}{}" . format ( iI111I1 . print_address ( ) , ", ms-name '{}'" . format ( ms . ms_name ) , i1iI11i1iiII ) )
 if 24 - 24: Ii1I / II111iiii + I1IiiI
 lisp_send ( lisp_sockets , iI111I1 , LISP_CTRL_PORT , packet )
 return
 if 100 - 100: Ii1I / IiII * O0
 if 60 - 60: Oo0Ooo / IiII / OoOoOO00 % iIii1I11I1II1 . o0oOOo0O0Ooo % iIii1I11I1II1
 if 35 - 35: OoooooooOO % O0 * I1Ii111 - iIii1I11I1II1 % iII111i
 if 15 - 15: O0 - Ii1I + OoOoOO00
 if 93 - 93: OoO0O00
 if 68 - 68: OOooOOo
 if 87 - 87: IiII * IiII - OoO0O00 / I1ii11iIi11i + OOooOOo / i11iIiiIii
 if 21 - 21: o0oOOo0O0Ooo / oO0o + oO0o + Oo0Ooo / o0oOOo0O0Ooo
def lisp_send_ipc_to_core ( lisp_socket , packet , dest , port ) :
 II1i1iI = lisp_socket . getsockname ( )
 dest = dest . print_address_no_iid ( )
 if 39 - 39: i11iIiiIii - OoO0O00 - i11iIiiIii / OoooooooOO
 lprint ( "Send IPC {} bytes to {} {}, control-packet: {}" . format ( len ( packet ) , dest , port , lisp_format_packet ( packet ) ) )
 if 15 - 15: i1IIi . iII111i + IiII / I1ii11iIi11i - i1IIi / iII111i
 if 27 - 27: OoOoOO00 / OoooooooOO + i1IIi % iIii1I11I1II1 / OoO0O00
 packet = lisp_control_packet_ipc ( packet , II1i1iI , dest , port )
 lisp_ipc ( packet , lisp_socket , "lisp-core-pkt" )
 return
 if 73 - 73: I1ii11iIi11i / OoOoOO00 / IiII + oO0o
 if 73 - 73: I11i * o0oOOo0O0Ooo * I1IiiI . OoooooooOO % I1Ii111
 if 9 - 9: oO0o % I1Ii111 . O0 + I1ii11iIi11i - Ii1I - I1ii11iIi11i
 if 57 - 57: i11iIiiIii
 if 21 - 21: iIii1I11I1II1 / I1IiiI / iII111i
 if 19 - 19: Oo0Ooo / iIii1I11I1II1 / I11i
 if 71 - 71: iIii1I11I1II1 * I1IiiI
 if 35 - 35: O0
def lisp_send_map_reply ( lisp_sockets , packet , dest , port ) :
 lprint ( "Send Map-Reply to {}" . format ( dest . print_address_no_iid ( ) ) )
 lisp_send_ipc_to_core ( lisp_sockets [ 2 ] , packet , dest , port )
 return
 if 10 - 10: Ii1I - I1Ii111 / Oo0Ooo + O0
 if 67 - 67: Ii1I % i11iIiiIii . Oo0Ooo
 if 78 - 78: I1IiiI - iIii1I11I1II1
 if 20 - 20: i11iIiiIii % I1IiiI % OoOoOO00
 if 85 - 85: I11i + OoOoOO00 * O0 * O0
 if 92 - 92: i11iIiiIii
 if 16 - 16: I11i . ooOoO0o - Oo0Ooo / OoO0O00 . i1IIi
 if 59 - 59: ooOoO0o - ooOoO0o % I11i + OoO0O00
def lisp_send_map_referral ( lisp_sockets , packet , dest , port ) :
 lprint ( "Send Map-Referral to {}" . format ( dest . print_address ( ) ) )
 lisp_send_ipc_to_core ( lisp_sockets [ 2 ] , packet , dest , port )
 return
 if 88 - 88: Ii1I - ooOoO0o . Oo0Ooo
 if 83 - 83: I11i + Oo0Ooo . I1ii11iIi11i * I1ii11iIi11i
 if 80 - 80: i1IIi * I11i - OOooOOo / II111iiii * iIii1I11I1II1
 if 42 - 42: OoOoOO00 . I11i % II111iiii
 if 19 - 19: OoooooooOO
 if 31 - 31: I11i . OoOoOO00 - O0 * iII111i % I1Ii111 - II111iiii
 if 21 - 21: OOooOOo . Oo0Ooo - i1IIi
 if 56 - 56: I11i
def lisp_send_map_notify ( lisp_sockets , packet , dest , port ) :
 lprint ( "Send Map-Notify to xTR {}" . format ( dest . print_address ( ) ) )
 lisp_send_ipc_to_core ( lisp_sockets [ 2 ] , packet , dest , port )
 return
 if 24 - 24: I1IiiI . I1IiiI % ooOoO0o
 if 32 - 32: OOooOOo / i1IIi / OOooOOo
 if 97 - 97: ooOoO0o * Oo0Ooo * OoooooooOO * I1IiiI
 if 45 - 45: Oo0Ooo
 if 27 - 27: oO0o / IiII - iIii1I11I1II1 / o0oOOo0O0Ooo % OOooOOo * iIii1I11I1II1
 if 40 - 40: oO0o - II111iiii * OOooOOo % OoooooooOO
 if 52 - 52: OOooOOo + OoO0O00
def lisp_send_ecm ( lisp_sockets , packet , inner_source , inner_sport , inner_dest ,
 outer_dest , to_etr = False , to_ms = False , ddt = False ) :
 if 96 - 96: OOooOOo % O0 - Oo0Ooo % oO0o / I1IiiI . i1IIi
 if ( inner_source == None or inner_source . is_null ( ) ) :
  inner_source = inner_dest
  if 42 - 42: i1IIi
  if 52 - 52: OoO0O00 % iII111i % O0
  if 11 - 11: i1IIi / i11iIiiIii + Ii1I % Oo0Ooo % O0
  if 50 - 50: oO0o . I1Ii111
  if 38 - 38: iIii1I11I1II1 . Ii1I
  if 82 - 82: OOooOOo * Ii1I + I1ii11iIi11i . OoO0O00
 if ( lisp_nat_traversal ) :
  oOO0ooi1iiIIiII1 = lisp_get_any_translated_port ( )
  if ( oOO0ooi1iiIIiII1 != None ) : inner_sport = oOO0ooi1iiIIiII1
  if 15 - 15: O0
 iiIIIiI1 = lisp_ecm ( inner_sport )
 if 44 - 44: Ii1I . Oo0Ooo . I1Ii111 + oO0o
 iiIIIiI1 . to_etr = to_etr if lisp_is_running ( "lisp-etr" ) else False
 iiIIIiI1 . to_ms = to_ms if lisp_is_running ( "lisp-ms" ) else False
 iiIIIiI1 . ddt = ddt
 I1Ii11Ii = iiIIIiI1 . encode ( packet , inner_source , inner_dest )
 if ( I1Ii11Ii == None ) :
  lprint ( "Could not encode ECM message" )
  return
  if 37 - 37: ooOoO0o . I1IiiI
 iiIIIiI1 . print_ecm ( )
 if 1 - 1: iIii1I11I1II1 . o0oOOo0O0Ooo % I11i
 packet = I1Ii11Ii + packet
 if 94 - 94: oO0o
 I1iiIiiii1111 = outer_dest . print_address_no_iid ( )
 lprint ( "Send Encapsulated-Control-Message to {}" . format ( I1iiIiiii1111 ) )
 iI111I1 = lisp_convert_4to6 ( I1iiIiiii1111 )
 lisp_send ( lisp_sockets , iI111I1 , LISP_CTRL_PORT , packet )
 return
 if 47 - 47: II111iiii + iII111i + I1ii11iIi11i - iIii1I11I1II1 . Ii1I * oO0o
 if 40 - 40: i1IIi % I1IiiI / o0oOOo0O0Ooo
 if 53 - 53: iIii1I11I1II1 * oO0o
 if 43 - 43: IiII * Oo0Ooo / OOooOOo % oO0o
 if 11 - 11: OoOoOO00 * Oo0Ooo / I11i * OOooOOo
 if 15 - 15: ooOoO0o - OOooOOo / OoooooooOO
 if 41 - 41: OoOoOO00 . iII111i . i1IIi + oO0o
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
if 60 - 60: oO0o * I1Ii111
LISP_RLOC_UNKNOWN_STATE = 0
LISP_RLOC_UP_STATE = 1
LISP_RLOC_DOWN_STATE = 2
LISP_RLOC_UNREACH_STATE = 3
LISP_RLOC_NO_ECHOED_NONCE_STATE = 4
LISP_RLOC_ADMIN_DOWN_STATE = 5
if 81 - 81: oO0o - OOooOOo - oO0o
LISP_AUTH_NONE = 0
LISP_AUTH_MD5 = 1
LISP_AUTH_SHA1 = 2
LISP_AUTH_SHA2 = 3
if 54 - 54: oO0o % I11i
if 71 - 71: oO0o / I1ii11iIi11i . Ii1I % II111iiii
if 22 - 22: iIii1I11I1II1 - OoooooooOO
if 8 - 8: ooOoO0o % i11iIiiIii
if 41 - 41: I1Ii111 . ooOoO0o - i11iIiiIii + Ii1I . OOooOOo . OoOoOO00
if 70 - 70: i1IIi % OoOoOO00 / iII111i + i11iIiiIii % ooOoO0o + IiII
if 58 - 58: OOooOOo / i11iIiiIii . Oo0Ooo % iII111i
LISP_IPV4_HOST_MASK_LEN = 32
LISP_IPV6_HOST_MASK_LEN = 128
LISP_MAC_HOST_MASK_LEN = 48
LISP_E164_HOST_MASK_LEN = 60
if 92 - 92: OoOoOO00 / ooOoO0o % iII111i / iIii1I11I1II1
if 73 - 73: O0 % i11iIiiIii
if 16 - 16: O0
if 15 - 15: i1IIi % i11iIiiIii
if 18 - 18: Ii1I . OoO0O00 . iII111i * oO0o + O0
if 35 - 35: OoOoOO00 . oO0o / II111iiii
def byte_swap_64 ( address ) :
 o0o0O00 = ( ( address & 0x00000000000000ff ) << 56 ) | ( ( address & 0x000000000000ff00 ) << 40 ) | ( ( address & 0x0000000000ff0000 ) << 24 ) | ( ( address & 0x00000000ff000000 ) << 8 ) | ( ( address & 0x000000ff00000000 ) >> 8 ) | ( ( address & 0x0000ff0000000000 ) >> 24 ) | ( ( address & 0x00ff000000000000 ) >> 40 ) | ( ( address & 0xff00000000000000 ) >> 56 )
 if 97 - 97: Ii1I + I1Ii111 / II111iiii
 if 14 - 14: iII111i / IiII / oO0o
 if 55 - 55: OoO0O00 % O0
 if 92 - 92: OoooooooOO / O0
 if 14 - 14: i11iIiiIii
 if 43 - 43: OOooOOo
 if 79 - 79: iII111i % Oo0Ooo . i1IIi % ooOoO0o
 if 93 - 93: OoOoOO00
 return ( o0o0O00 )
 if 49 - 49: i1IIi * OOooOOo % I11i * Ii1I . I1Ii111 * iIii1I11I1II1
 if 72 - 72: ooOoO0o
 if 63 - 63: Oo0Ooo . OoO0O00 . OoooooooOO / i1IIi
 if 53 - 53: OOooOOo * O0 . iII111i
 if 3 - 3: OoooooooOO * I1Ii111 * IiII - OOooOOo * I1Ii111
 if 78 - 78: iII111i
 if 80 - 80: i1IIi * I1IiiI + OOooOOo
 if 91 - 91: I1IiiI % OoOoOO00 * Oo0Ooo / I1ii11iIi11i
 if 57 - 57: i11iIiiIii / o0oOOo0O0Ooo . II111iiii
 if 63 - 63: O0
 if 64 - 64: i11iIiiIii / oO0o . oO0o - Oo0Ooo
 if 48 - 48: i1IIi + I1ii11iIi11i + I1Ii111 - iII111i
 if 3 - 3: i1IIi + OoooooooOO * ooOoO0o + I1Ii111 % OOooOOo / IiII
 if 70 - 70: oO0o + i1IIi % o0oOOo0O0Ooo - I11i
 if 74 - 74: i11iIiiIii
class lisp_cache_entries ( ) :
 def __init__ ( self ) :
  self . entries = { }
  self . entries_sorted = [ ]
  if 93 - 93: I1Ii111 % OOooOOo * I1IiiI % iII111i / iIii1I11I1II1 + OoO0O00
  if 6 - 6: I11i
  if 70 - 70: ooOoO0o + OoooooooOO % OoOoOO00 % oO0o / Ii1I . I11i
class lisp_cache ( ) :
 def __init__ ( self ) :
  self . cache = { }
  self . cache_sorted = [ ]
  self . cache_count = 0
  if 63 - 63: I1ii11iIi11i - ooOoO0o . OOooOOo / O0 . iIii1I11I1II1 - Ii1I
  if 6 - 6: Ii1I
 def cache_size ( self ) :
  return ( self . cache_count )
  if 60 - 60: iII111i + I1IiiI
  if 36 - 36: i1IIi . O0 . OoO0O00 % OOooOOo * I11i / Ii1I
 def build_key ( self , prefix ) :
  if ( prefix . afi == LISP_AFI_ULTIMATE_ROOT ) :
   Iii11i1 = 0
  elif ( prefix . afi == LISP_AFI_IID_RANGE ) :
   Iii11i1 = prefix . mask_len
  else :
   Iii11i1 = prefix . mask_len + 48
   if 16 - 16: Oo0Ooo
   if 44 - 44: iIii1I11I1II1 - II111iiii . IiII . i1IIi
  o0OOoOO = lisp_hex_string ( prefix . instance_id ) . zfill ( 8 )
  iioOO = lisp_hex_string ( prefix . afi ) . zfill ( 4 )
  if 37 - 37: OoooooooOO + Oo0Ooo - Oo0Ooo + I1ii11iIi11i . I1Ii111 / I1IiiI
  if ( prefix . afi > 0 ) :
   if ( prefix . is_binary ( ) ) :
    o00OOo00 = prefix . addr_length ( ) * 2
    o0o0O00 = lisp_hex_string ( prefix . address ) . zfill ( o00OOo00 )
   else :
    o0o0O00 = prefix . address
    if 60 - 60: I1IiiI % Ii1I / I1Ii111 + Ii1I
  elif ( prefix . afi == LISP_AFI_GEO_COORD ) :
   iioOO = "8003"
   o0o0O00 = prefix . address . print_geo ( )
  else :
   iioOO = ""
   o0o0O00 = ""
   if 43 - 43: I1ii11iIi11i + I11i
   if 83 - 83: II111iiii + o0oOOo0O0Ooo - I1Ii111
  iii11 = o0OOoOO + iioOO + o0o0O00
  return ( [ Iii11i1 , iii11 ] )
  if 100 - 100: IiII - OoOoOO00 / I11i
  if 33 - 33: I1Ii111 * OoOoOO00 . I1ii11iIi11i % I1Ii111
 def add_cache ( self , prefix , entry ) :
  if ( prefix . is_binary ( ) ) : prefix . zero_host_bits ( )
  Iii11i1 , iii11 = self . build_key ( prefix )
  if ( self . cache . has_key ( Iii11i1 ) == False ) :
   self . cache [ Iii11i1 ] = lisp_cache_entries ( )
   self . cache [ Iii11i1 ] . entries = { }
   self . cache [ Iii11i1 ] . entries_sorted = [ ]
   self . cache_sorted = sorted ( self . cache )
   if 87 - 87: Oo0Ooo
  if ( self . cache [ Iii11i1 ] . entries . has_key ( iii11 ) == False ) :
   self . cache_count += 1
   if 65 - 65: ooOoO0o . I1IiiI
  self . cache [ Iii11i1 ] . entries [ iii11 ] = entry
  self . cache [ Iii11i1 ] . entries_sorted = sorted ( self . cache [ Iii11i1 ] . entries )
  if 51 - 51: IiII
  if 43 - 43: oO0o - I11i . i11iIiiIii
 def lookup_cache ( self , prefix , exact ) :
  Oo0OO0 , iii11 = self . build_key ( prefix )
  if ( exact ) :
   if ( self . cache . has_key ( Oo0OO0 ) == False ) : return ( None )
   if ( self . cache [ Oo0OO0 ] . entries . has_key ( iii11 ) == False ) : return ( None )
   return ( self . cache [ Oo0OO0 ] . entries [ iii11 ] )
   if 83 - 83: II111iiii . Ii1I + IiII / oO0o
   if 17 - 17: I1IiiI . Ii1I . I1ii11iIi11i % OoooooooOO
  OOoOO0 = None
  for Iii11i1 in self . cache_sorted :
   if ( Oo0OO0 < Iii11i1 ) : return ( OOoOO0 )
   for O000o in self . cache [ Iii11i1 ] . entries_sorted :
    ii1Ii1Iii11i1 = self . cache [ Iii11i1 ] . entries
    if ( O000o in ii1Ii1Iii11i1 ) :
     iIIiI11iI1Ii1 = ii1Ii1Iii11i1 [ O000o ]
     if ( iIIiI11iI1Ii1 == None ) : continue
     if ( prefix . is_more_specific ( iIIiI11iI1Ii1 . eid ) ) : OOoOO0 = iIIiI11iI1Ii1
     if 57 - 57: I1IiiI * IiII
     if 99 - 99: OOooOOo - I1ii11iIi11i
     if 63 - 63: Ii1I - I1IiiI + I1Ii111 * oO0o
  return ( OOoOO0 )
  if 61 - 61: I11i . I1IiiI - iIii1I11I1II1
  if 1 - 1: O0 . Ii1I % Ii1I + II111iiii . oO0o
 def delete_cache ( self , prefix ) :
  Iii11i1 , iii11 = self . build_key ( prefix )
  if ( self . cache . has_key ( Iii11i1 ) == False ) : return
  if ( self . cache [ Iii11i1 ] . entries . has_key ( iii11 ) == False ) : return
  self . cache [ Iii11i1 ] . entries . pop ( iii11 )
  self . cache [ Iii11i1 ] . entries_sorted . remove ( iii11 )
  self . cache_count -= 1
  if 24 - 24: o0oOOo0O0Ooo . I1Ii111 % O0
  if 67 - 67: I1IiiI * Ii1I
 def walk_cache ( self , function , parms ) :
  for Iii11i1 in self . cache_sorted :
   for iii11 in self . cache [ Iii11i1 ] . entries_sorted :
    iIIiI11iI1Ii1 = self . cache [ Iii11i1 ] . entries [ iii11 ]
    o00o0OO0o , parms = function ( iIIiI11iI1Ii1 , parms )
    if ( o00o0OO0o == False ) : return ( parms )
    if 92 - 92: I11i + i11iIiiIii / i11iIiiIii / II111iiii - o0oOOo0O0Ooo . o0oOOo0O0Ooo
    if 93 - 93: i11iIiiIii / OoO0O00 + I1IiiI
  return ( parms )
  if 4 - 4: ooOoO0o . i11iIiiIii . i1IIi
  if 37 - 37: i11iIiiIii + OoO0O00 * Ii1I
 def print_cache ( self ) :
  lprint ( "Printing contents of {}: " . format ( self ) )
  if ( self . cache_size ( ) == 0 ) :
   lprint ( "  Cache is empty" )
   return
   if 100 - 100: IiII . I1Ii111 + II111iiii + i1IIi
  for Iii11i1 in self . cache_sorted :
   for iii11 in self . cache [ Iii11i1 ] . entries_sorted :
    iIIiI11iI1Ii1 = self . cache [ Iii11i1 ] . entries [ iii11 ]
    lprint ( "  Mask-length: {}, key: {}, entry: {}" . format ( Iii11i1 , iii11 ,
 iIIiI11iI1Ii1 ) )
    if 37 - 37: iII111i
    if 27 - 27: iII111i / Ii1I / iII111i + OoooooooOO - O0 + OoO0O00
    if 62 - 62: iIii1I11I1II1
    if 60 - 60: Oo0Ooo % IiII % OoO0O00 - i11iIiiIii
    if 53 - 53: i11iIiiIii + OoooooooOO
    if 23 - 23: i11iIiiIii - IiII - I1ii11iIi11i + I1ii11iIi11i % I1IiiI
    if 79 - 79: II111iiii / OoooooooOO
    if 35 - 35: i1IIi + IiII + II111iiii % OOooOOo
lisp_referral_cache = lisp_cache ( )
lisp_ddt_cache = lisp_cache ( )
lisp_sites_by_eid = lisp_cache ( )
lisp_map_cache = lisp_cache ( )
lisp_db_for_lookups = lisp_cache ( )
if 25 - 25: I11i + i11iIiiIii + O0 - Ii1I
if 69 - 69: I11i . OoOoOO00 / OOooOOo / i1IIi . II111iiii
if 17 - 17: I1Ii111
if 2 - 2: O0 % OoOoOO00 + oO0o
if 24 - 24: iII111i + iII111i - OoooooooOO % OoooooooOO * O0
if 51 - 51: IiII
if 31 - 31: I11i - iIii1I11I1II1 * Ii1I + Ii1I
def lisp_map_cache_lookup ( source , dest ) :
 if 10 - 10: OoOoOO00 - i11iIiiIii % iIii1I11I1II1 / ooOoO0o * i11iIiiIii - Ii1I
 iIiiIiI1I1ii = dest . is_multicast_address ( )
 if 64 - 64: II111iiii . i11iIiiIii . iII111i . OOooOOo
 if 95 - 95: O0 - OoOoOO00
 if 68 - 68: ooOoO0o . I1Ii111
 if 84 - 84: OoooooooOO + oO0o % i1IIi + o0oOOo0O0Ooo * i1IIi
 IIII = lisp_map_cache . lookup_cache ( dest , False )
 if ( IIII == None ) :
  oOoo0OooOOo00 = source . print_sg ( dest ) if iIiiIiI1I1ii else dest . print_address ( )
  oOoo0OooOOo00 = green ( oOoo0OooOOo00 , False )
  dprint ( "Lookup for EID {} not found in map-cache" . format ( oOoo0OooOOo00 ) )
  return ( None )
  if 51 - 51: oO0o . OoooooooOO + OOooOOo * I1ii11iIi11i - ooOoO0o
  if 41 - 41: Oo0Ooo
  if 46 - 46: i11iIiiIii + iIii1I11I1II1 . i11iIiiIii . iII111i
  if 66 - 66: oO0o % i1IIi % OoooooooOO
  if 58 - 58: OOooOOo
 if ( iIiiIiI1I1ii == False ) :
  OOO0Ooo0OoO0 = green ( IIII . eid . print_prefix ( ) , False )
  dprint ( "Lookup for EID {} found map-cache entry {}" . format ( green ( dest . print_address ( ) , False ) , OOO0Ooo0OoO0 ) )
  if 89 - 89: iIii1I11I1II1 - i1IIi
  return ( IIII )
  if 26 - 26: OOooOOo - iII111i * I1ii11iIi11i / iII111i
  if 9 - 9: I1Ii111 / II111iiii * I1Ii111 / I11i - OoO0O00
  if 36 - 36: IiII . OoOoOO00 . Ii1I
  if 31 - 31: iIii1I11I1II1
  if 84 - 84: I1ii11iIi11i - iII111i * I1IiiI
 IIII = IIII . lookup_source_cache ( source , False )
 if ( IIII == None ) :
  oOoo0OooOOo00 = source . print_sg ( dest )
  dprint ( "Lookup for EID {} not found in map-cache" . format ( oOoo0OooOOo00 ) )
  return ( None )
  if 88 - 88: OOooOOo / Oo0Ooo
  if 31 - 31: II111iiii
  if 32 - 32: o0oOOo0O0Ooo % o0oOOo0O0Ooo
  if 67 - 67: IiII + oO0o * IiII
  if 26 - 26: I1ii11iIi11i + i1IIi . i1IIi - oO0o + I1IiiI * o0oOOo0O0Ooo
 OOO0Ooo0OoO0 = green ( IIII . print_eid_tuple ( ) , False )
 dprint ( "Lookup for EID {} found map-cache entry {}" . format ( green ( source . print_sg ( dest ) , False ) , OOO0Ooo0OoO0 ) )
 if 62 - 62: ooOoO0o + ooOoO0o % I11i
 return ( IIII )
 if 100 - 100: II111iiii . OoooooooOO
 if 32 - 32: I11i % OOooOOo * O0 / iIii1I11I1II1 / i1IIi
 if 87 - 87: OoO0O00 . I1ii11iIi11i * I1IiiI
 if 83 - 83: OOooOOo
 if 86 - 86: I1Ii111 / oO0o
 if 67 - 67: OoOoOO00 + Oo0Ooo / i11iIiiIii . I1IiiI
 if 53 - 53: Oo0Ooo + IiII * ooOoO0o % OoooooooOO * oO0o . iII111i
def lisp_referral_cache_lookup ( eid , group , exact ) :
 if ( group and group . is_null ( ) ) :
  OoOo = lisp_referral_cache . lookup_cache ( eid , exact )
  return ( OoOo )
  if 78 - 78: O0 . Ii1I - I1ii11iIi11i
  if 69 - 69: O0 % O0 . oO0o * OoooooooOO
  if 13 - 13: i1IIi % oO0o . OoooooooOO + I1ii11iIi11i - OOooOOo
  if 99 - 99: OoooooooOO % OOooOOo / I11i
  if 77 - 77: II111iiii - IiII % OOooOOo
 if ( eid == None or eid . is_null ( ) ) : return ( None )
 if 22 - 22: OoooooooOO / oO0o
 if 78 - 78: oO0o * I11i . i1IIi % i1IIi + i1IIi / OOooOOo
 if 66 - 66: OoooooooOO % o0oOOo0O0Ooo / I11i * I1Ii111
 if 12 - 12: I1Ii111
 if 17 - 17: I1Ii111 % oO0o + O0
 if 15 - 15: o0oOOo0O0Ooo - OoooooooOO % ooOoO0o % oO0o / i11iIiiIii / Oo0Ooo
 OoOo = lisp_referral_cache . lookup_cache ( group , exact )
 if ( OoOo == None ) : return ( None )
 if 59 - 59: iII111i + O0 - I1ii11iIi11i * I1ii11iIi11i + iIii1I11I1II1
 Iio00OO = OoOo . lookup_source_cache ( eid , exact )
 if ( Iio00OO ) : return ( Iio00OO )
 if 12 - 12: Oo0Ooo / OoOoOO00 + ooOoO0o . Oo0Ooo . o0oOOo0O0Ooo + OoOoOO00
 if ( exact ) : OoOo = None
 return ( OoOo )
 if 32 - 32: OoOoOO00 * o0oOOo0O0Ooo - OoOoOO00 * oO0o
 if 80 - 80: iII111i - O0 + IiII + iIii1I11I1II1 * I1ii11iIi11i
 if 8 - 8: OoO0O00
 if 99 - 99: iII111i . I1ii11iIi11i . o0oOOo0O0Ooo
 if 4 - 4: I11i * Oo0Ooo . i11iIiiIii / Ii1I . I1ii11iIi11i % I1Ii111
 if 68 - 68: ooOoO0o
 if 58 - 58: iII111i * I1IiiI
def lisp_ddt_cache_lookup ( eid , group , exact ) :
 if ( group . is_null ( ) ) :
  O0ooO0OooO = lisp_ddt_cache . lookup_cache ( eid , exact )
  return ( O0ooO0OooO )
  if 82 - 82: Oo0Ooo / OoO0O00 % Oo0Ooo . ooOoO0o * O0
  if 39 - 39: I1Ii111 * IiII
  if 16 - 16: ooOoO0o + OoO0O00 / I11i * OoO0O00 . Oo0Ooo % OoOoOO00
  if 65 - 65: Oo0Ooo / I1Ii111 % II111iiii % Ii1I
  if 70 - 70: II111iiii % Oo0Ooo * oO0o
 if ( eid . is_null ( ) ) : return ( None )
 if 54 - 54: O0 / ooOoO0o * I1Ii111
 if 5 - 5: Ii1I / OoOoOO00 - O0 * OoO0O00
 if 13 - 13: IiII + Oo0Ooo - I1Ii111
 if 10 - 10: OOooOOo % OoooooooOO / I1IiiI . II111iiii % iII111i
 if 47 - 47: o0oOOo0O0Ooo . i11iIiiIii * i1IIi % I11i - ooOoO0o * oO0o
 if 95 - 95: oO0o / Ii1I + OoO0O00
 O0ooO0OooO = lisp_ddt_cache . lookup_cache ( group , exact )
 if ( O0ooO0OooO == None ) : return ( None )
 if 57 - 57: iIii1I11I1II1 + I1Ii111 % oO0o - Ii1I . I1IiiI
 iIi11Ii = O0ooO0OooO . lookup_source_cache ( eid , exact )
 if ( iIi11Ii ) : return ( iIi11Ii )
 if 70 - 70: oO0o - iII111i + Ii1I * Ii1I / o0oOOo0O0Ooo . o0oOOo0O0Ooo
 if ( exact ) : O0ooO0OooO = None
 return ( O0ooO0OooO )
 if 41 - 41: I1Ii111 % Oo0Ooo - iIii1I11I1II1
 if 96 - 96: I1Ii111 / II111iiii . oO0o + oO0o
 if 62 - 62: I1IiiI
 if 22 - 22: i11iIiiIii . Ii1I . Oo0Ooo * Oo0Ooo - iII111i / I1ii11iIi11i
 if 49 - 49: iII111i + I11i . Oo0Ooo
 if 23 - 23: I1IiiI . Ii1I + ooOoO0o . OoooooooOO
 if 57 - 57: OOooOOo / OoOoOO00 / i11iIiiIii - I11i - I11i . Ii1I
def lisp_site_eid_lookup ( eid , group , exact ) :
 if 53 - 53: ooOoO0o . iII111i + Ii1I * I1Ii111
 if ( group . is_null ( ) ) :
  Iiii1IIIiIi = lisp_sites_by_eid . lookup_cache ( eid , exact )
  return ( Iiii1IIIiIi )
  if 49 - 49: II111iiii . I1ii11iIi11i * OoOoOO00 - OOooOOo
  if 48 - 48: OoO0O00 . iIii1I11I1II1 - OoooooooOO + I1Ii111 / i11iIiiIii . Oo0Ooo
  if 61 - 61: II111iiii + OOooOOo . o0oOOo0O0Ooo . iIii1I11I1II1
  if 63 - 63: I11i + i11iIiiIii . o0oOOo0O0Ooo . i1IIi + OoOoOO00
  if 1 - 1: i11iIiiIii
 if ( eid . is_null ( ) ) : return ( None )
 if 1 - 1: iIii1I11I1II1
 if 73 - 73: iII111i + IiII
 if 95 - 95: O0
 if 75 - 75: ooOoO0o
 if 8 - 8: O0 - OoooooooOO + I1ii11iIi11i / Oo0Ooo . oO0o + I1Ii111
 if 85 - 85: ooOoO0o
 Iiii1IIIiIi = lisp_sites_by_eid . lookup_cache ( group , exact )
 if ( Iiii1IIIiIi == None ) : return ( None )
 if 29 - 29: iII111i . Ii1I
 if 43 - 43: I11i - I1ii11iIi11i + iIii1I11I1II1 / I1ii11iIi11i * oO0o / iIii1I11I1II1
 if 45 - 45: IiII
 if 49 - 49: I1IiiI . Ii1I * I1IiiI - OoooooooOO . I11i / I1Ii111
 if 9 - 9: iIii1I11I1II1 * Ii1I / O0 - OOooOOo
 if 95 - 95: i11iIiiIii * II111iiii * OOooOOo * iIii1I11I1II1
 if 22 - 22: iIii1I11I1II1 / I1IiiI + OoOoOO00 - OOooOOo . i11iIiiIii / i11iIiiIii
 if 10 - 10: iIii1I11I1II1 % i1IIi
 if 78 - 78: I11i + II111iiii % o0oOOo0O0Ooo
 if 17 - 17: i11iIiiIii + oO0o * iII111i . II111iiii
 if 44 - 44: I1ii11iIi11i
 if 39 - 39: iII111i + Oo0Ooo / oO0o
 if 95 - 95: I1Ii111 * oO0o / ooOoO0o . Ii1I . OoOoOO00
 if 99 - 99: I1IiiI * II111iiii
 if 84 - 84: II111iiii - I1IiiI
 if 41 - 41: iIii1I11I1II1 % I1Ii111 % OoOoOO00
 if 35 - 35: I11i + i1IIi
 if 85 - 85: Ii1I * Ii1I . OoOoOO00 / Oo0Ooo
 I1i1III1i = Iiii1IIIiIi . lookup_source_cache ( eid , exact )
 if ( I1i1III1i ) : return ( I1i1III1i )
 if 97 - 97: oO0o % iIii1I11I1II1
 if ( exact ) :
  Iiii1IIIiIi = None
 else :
  IiI1 = Iiii1IIIiIi . parent_for_more_specifics
  if ( IiI1 and IiI1 . accept_more_specifics ) :
   if ( group . is_more_specific ( IiI1 . group ) ) : Iiii1IIIiIi = IiI1
   if 87 - 87: II111iiii % I1IiiI + oO0o - I11i / I11i
   if 16 - 16: I1IiiI
 return ( Iiii1IIIiIi )
 if 39 - 39: ooOoO0o * II111iiii
 if 90 - 90: OoooooooOO * ooOoO0o
 if 14 - 14: I1IiiI % i1IIi
 if 35 - 35: ooOoO0o % o0oOOo0O0Ooo % ooOoO0o
 if 77 - 77: OOooOOo % I1Ii111 / i11iIiiIii . i1IIi % OOooOOo
 if 55 - 55: i1IIi
 if 64 - 64: oO0o . OOooOOo * i11iIiiIii + I1Ii111
 if 88 - 88: O0
 if 75 - 75: iII111i - Oo0Ooo / OoooooooOO - O0
 if 36 - 36: OoO0O00 % Ii1I . Oo0Ooo
 if 90 - 90: i11iIiiIii - iII111i * oO0o
 if 79 - 79: IiII
 if 38 - 38: I1Ii111
 if 56 - 56: i11iIiiIii
 if 58 - 58: i11iIiiIii / OoOoOO00
 if 23 - 23: I1IiiI % iIii1I11I1II1 - oO0o - iII111i - o0oOOo0O0Ooo
 if 39 - 39: Oo0Ooo . OoO0O00
 if 74 - 74: I1IiiI . O0 . IiII + IiII - IiII
 if 100 - 100: ooOoO0o / OoooooooOO
 if 73 - 73: i11iIiiIii - Oo0Ooo
 if 100 - 100: iIii1I11I1II1 + I1Ii111
 if 51 - 51: o0oOOo0O0Ooo * I11i
 if 42 - 42: OOooOOo % I11i
 if 84 - 84: Oo0Ooo * OoOoOO00 / Ii1I / IiII / o0oOOo0O0Ooo . I1ii11iIi11i
 if 81 - 81: I1IiiI
 if 82 - 82: I1Ii111 - OoooooooOO - Ii1I
class lisp_address ( ) :
 def __init__ ( self , afi , addr_str , mask_len , iid ) :
  self . afi = afi
  self . mask_len = mask_len
  self . instance_id = iid
  self . iid_list = [ ]
  self . address = 0
  if ( addr_str != "" ) : self . store_address ( addr_str )
  if 34 - 34: OOooOOo . iIii1I11I1II1 / I1IiiI . Oo0Ooo - iIii1I11I1II1
  if 83 - 83: iII111i - I1ii11iIi11i + iII111i
 def copy_address ( self , addr ) :
  if ( addr == None ) : return
  self . afi = addr . afi
  self . address = addr . address
  self . mask_len = addr . mask_len
  self . instance_id = addr . instance_id
  self . iid_list = addr . iid_list
  if 4 - 4: o0oOOo0O0Ooo % iIii1I11I1II1 + I11i
  if 60 - 60: I1ii11iIi11i / I1Ii111 % i11iIiiIii % oO0o % I1IiiI . Oo0Ooo
 def make_default_route ( self , addr ) :
  self . afi = addr . afi
  self . instance_id = addr . instance_id
  self . mask_len = 0
  self . address = 0
  if 20 - 20: IiII - OOooOOo + OoOoOO00
  if 83 - 83: OoooooooOO / I1IiiI + iII111i - iIii1I11I1II1 % ooOoO0o
 def make_default_multicast_route ( self , addr ) :
  self . afi = addr . afi
  self . instance_id = addr . instance_id
  if ( self . afi == LISP_AFI_IPV4 ) :
   self . address = 0xe0000000
   self . mask_len = 4
   if 74 - 74: OoO0O00
  if ( self . afi == LISP_AFI_IPV6 ) :
   self . address = 0xff << 120
   self . mask_len = 8
   if 13 - 13: I1ii11iIi11i / OoO0O00
  if ( self . afi == LISP_AFI_MAC ) :
   self . address = 0xffffffffffff
   self . mask_len = 48
   if 90 - 90: iIii1I11I1II1 - OoO0O00 . i1IIi / o0oOOo0O0Ooo + O0
   if 94 - 94: IiII * i1IIi
   if 90 - 90: O0 % I1IiiI . o0oOOo0O0Ooo % ooOoO0o % I1IiiI
 def not_set ( self ) :
  return ( self . afi == LISP_AFI_NONE )
  if 16 - 16: OoO0O00 / OOooOOo / iIii1I11I1II1 / OoooooooOO . oO0o - I1Ii111
  if 43 - 43: OoOoOO00 % OOooOOo / I1IiiI + I1IiiI
 def is_private_address ( self ) :
  if ( self . is_ipv4 ( ) == False ) : return ( False )
  o0o0O00 = self . address
  if ( ( ( o0o0O00 & 0xff000000 ) >> 24 ) == 10 ) : return ( True )
  if ( ( ( o0o0O00 & 0xff000000 ) >> 24 ) == 172 ) :
   i1I = ( o0o0O00 & 0x00ff0000 ) >> 16
   if ( i1I >= 16 and i1I <= 31 ) : return ( True )
   if 95 - 95: Oo0Ooo . iIii1I11I1II1 - iIii1I11I1II1 * I1IiiI % Oo0Ooo * I1IiiI
  if ( ( ( o0o0O00 & 0xffff0000 ) >> 16 ) == 0xc0a8 ) : return ( True )
  return ( False )
  if 87 - 87: iII111i + i1IIi
  if 10 - 10: Oo0Ooo . o0oOOo0O0Ooo - i11iIiiIii / iII111i + i11iIiiIii . I11i
 def is_multicast_address ( self ) :
  if ( self . is_ipv4 ( ) ) : return ( self . is_ipv4_multicast ( ) )
  if ( self . is_ipv6 ( ) ) : return ( self . is_ipv6_multicast ( ) )
  if ( self . is_mac ( ) ) : return ( self . is_mac_multicast ( ) )
  return ( False )
  if 66 - 66: i1IIi
  if 98 - 98: Oo0Ooo / iIii1I11I1II1
 def host_mask_len ( self ) :
  if ( self . afi == LISP_AFI_IPV4 ) : return ( LISP_IPV4_HOST_MASK_LEN )
  if ( self . afi == LISP_AFI_IPV6 ) : return ( LISP_IPV6_HOST_MASK_LEN )
  if ( self . afi == LISP_AFI_MAC ) : return ( LISP_MAC_HOST_MASK_LEN )
  if ( self . afi == LISP_AFI_E164 ) : return ( LISP_E164_HOST_MASK_LEN )
  if ( self . afi == LISP_AFI_NAME ) : return ( len ( self . address ) * 8 )
  if ( self . afi == LISP_AFI_GEO_COORD ) :
   return ( len ( self . address . print_geo ( ) ) * 8 )
   if 33 - 33: O0 - iII111i
  return ( 0 )
  if 40 - 40: iII111i * I11i
  if 25 - 25: O0 * o0oOOo0O0Ooo % ooOoO0o % I1IiiI
 def is_iana_eid ( self ) :
  if ( self . is_ipv6 ( ) == False ) : return ( False )
  o0o0O00 = self . address >> 96
  return ( o0o0O00 == 0x20010005 )
  if 87 - 87: OoOoOO00
  if 30 - 30: IiII % OoOoOO00 + I1Ii111
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
   if 13 - 13: iII111i * Ii1I % o0oOOo0O0Ooo * i1IIi . IiII % i1IIi
  return ( 0 )
  if 79 - 79: OoooooooOO % I11i / o0oOOo0O0Ooo + IiII + O0 + iII111i
  if 87 - 87: I11i
 def afi_to_version ( self ) :
  if ( self . afi == LISP_AFI_IPV4 ) : return ( 4 )
  if ( self . afi == LISP_AFI_IPV6 ) : return ( 6 )
  return ( 0 )
  if 39 - 39: I1ii11iIi11i * i11iIiiIii % I1Ii111
  if 72 - 72: OoO0O00 * Oo0Ooo - IiII
 def packet_format ( self ) :
  if 74 - 74: Ii1I
  if 26 - 26: I11i . O0
  if 68 - 68: Ii1I
  if 26 - 26: o0oOOo0O0Ooo - I1ii11iIi11i / O0 % i11iIiiIii
  if 7 - 7: I1Ii111 . Oo0Ooo + IiII / iIii1I11I1II1
  if ( self . afi == LISP_AFI_IPV4 ) : return ( "I" )
  if ( self . afi == LISP_AFI_IPV6 ) : return ( "QQ" )
  if ( self . afi == LISP_AFI_MAC ) : return ( "HHH" )
  if ( self . afi == LISP_AFI_E164 ) : return ( "II" )
  if ( self . afi == LISP_AFI_LCAF ) : return ( "I" )
  return ( "" )
  if 22 - 22: iIii1I11I1II1 - O0 . iII111i - IiII - ooOoO0o
  if 54 - 54: OoO0O00 . iII111i . OoOoOO00 * OoO0O00 + o0oOOo0O0Ooo . ooOoO0o
 def pack_address ( self ) :
  oOoOo000 = self . packet_format ( )
  i1II1IiiIi = ""
  if ( self . is_ipv4 ( ) ) :
   i1II1IiiIi = struct . pack ( oOoOo000 , socket . htonl ( self . address ) )
  elif ( self . is_ipv6 ( ) ) :
   OooO0O0Ooo = byte_swap_64 ( self . address >> 64 )
   oO0O = byte_swap_64 ( self . address & 0xffffffffffffffff )
   i1II1IiiIi = struct . pack ( oOoOo000 , OooO0O0Ooo , oO0O )
  elif ( self . is_mac ( ) ) :
   o0o0O00 = self . address
   OooO0O0Ooo = ( o0o0O00 >> 32 ) & 0xffff
   oO0O = ( o0o0O00 >> 16 ) & 0xffff
   i1iiIiiIiI11 = o0o0O00 & 0xffff
   i1II1IiiIi = struct . pack ( oOoOo000 , OooO0O0Ooo , oO0O , i1iiIiiIiI11 )
  elif ( self . is_e164 ( ) ) :
   o0o0O00 = self . address
   OooO0O0Ooo = ( o0o0O00 >> 32 ) & 0xffffffff
   oO0O = ( o0o0O00 & 0xffffffff )
   i1II1IiiIi = struct . pack ( oOoOo000 , OooO0O0Ooo , oO0O )
  elif ( self . is_dist_name ( ) ) :
   i1II1IiiIi += self . address + "\0"
   if 41 - 41: O0 % i1IIi * i1IIi
  return ( i1II1IiiIi )
  if 85 - 85: II111iiii + i1IIi / ooOoO0o . OOooOOo % OoO0O00
  if 19 - 19: i1IIi + OOooOOo + IiII . I1IiiI * Ii1I
 def unpack_address ( self , packet ) :
  oOoOo000 = self . packet_format ( )
  O0OOoooO = struct . calcsize ( oOoOo000 )
  if ( len ( packet ) < O0OOoooO ) : return ( None )
  if 43 - 43: i1IIi . OoooooooOO . I1IiiI . OoooooooOO - OoooooooOO
  o0o0O00 = struct . unpack ( oOoOo000 , packet [ : O0OOoooO ] )
  if 10 - 10: II111iiii * I1IiiI / II111iiii / OoOoOO00 . ooOoO0o
  if ( self . is_ipv4 ( ) ) :
   self . address = socket . ntohl ( o0o0O00 [ 0 ] )
   if 42 - 42: I1IiiI - I11i / I1IiiI + I11i
  elif ( self . is_ipv6 ( ) ) :
   if 54 - 54: iII111i
   if 86 - 86: I1ii11iIi11i - Ii1I / IiII
   if 91 - 91: ooOoO0o * i11iIiiIii / O0 % Ii1I
   if 35 - 35: Oo0Ooo % O0
   if 71 - 71: oO0o % OOooOOo * i1IIi
   if 50 - 50: OoOoOO00 + i1IIi
   if 9 - 9: iII111i / I1Ii111 * Ii1I
   if 25 - 25: OoO0O00 . iII111i % I11i . oO0o * iII111i + Oo0Ooo
   if ( o0o0O00 [ 0 ] <= 0xffff and ( o0o0O00 [ 0 ] & 0xff ) == 0 ) :
    O00O00o0O0O = ( o0o0O00 [ 0 ] << 48 ) << 64
   else :
    O00O00o0O0O = byte_swap_64 ( o0o0O00 [ 0 ] ) << 64
    if 32 - 32: IiII
   OO000Oo = byte_swap_64 ( o0o0O00 [ 1 ] )
   self . address = O00O00o0O0O | OO000Oo
   if 68 - 68: I11i . Ii1I + I11i / IiII . I11i / iIii1I11I1II1
  elif ( self . is_mac ( ) ) :
   ooiI1IiII = o0o0O00 [ 0 ]
   OO0OO0O = o0o0O00 [ 1 ]
   oOo0o0Ooo0 = o0o0O00 [ 2 ]
   self . address = ( ooiI1IiII << 32 ) + ( OO0OO0O << 16 ) + oOo0o0Ooo0
   if 6 - 6: I1Ii111 % oO0o % I1ii11iIi11i
  elif ( self . is_e164 ( ) ) :
   self . address = ( o0o0O00 [ 0 ] << 32 ) + o0o0O00 [ 1 ]
   if 36 - 36: IiII
  elif ( self . is_dist_name ( ) ) :
   packet , self . address = lisp_decode_dist_name ( packet )
   self . mask_len = len ( self . address ) * 8
   O0OOoooO = 0
   if 97 - 97: i1IIi % OoOoOO00 . Oo0Ooo - OoO0O00 - ooOoO0o
  packet = packet [ O0OOoooO : : ]
  return ( packet )
  if 99 - 99: i11iIiiIii / I1Ii111 / I1IiiI * oO0o
  if 100 - 100: II111iiii * Ii1I . OoO0O00 . iII111i + i1IIi * I1IiiI
 def is_ipv4 ( self ) :
  return ( True if ( self . afi == LISP_AFI_IPV4 ) else False )
  if 84 - 84: OoO0O00 + i1IIi
  if 99 - 99: OOooOOo + o0oOOo0O0Ooo * I1Ii111 % OoooooooOO % I11i
 def is_ipv4_link_local ( self ) :
  if ( self . is_ipv4 ( ) == False ) : return ( False )
  return ( ( ( self . address >> 16 ) & 0xffff ) == 0xa9fe )
  if 48 - 48: o0oOOo0O0Ooo / OoO0O00
  if 45 - 45: OOooOOo
 def is_ipv4_loopback ( self ) :
  if ( self . is_ipv4 ( ) == False ) : return ( False )
  return ( self . address == 0x7f000001 )
  if 57 - 57: iIii1I11I1II1 + IiII - I1IiiI
  if 64 - 64: II111iiii . IiII / I1IiiI
 def is_ipv4_multicast ( self ) :
  if ( self . is_ipv4 ( ) == False ) : return ( False )
  return ( ( ( self . address >> 24 ) & 0xf0 ) == 0xe0 )
  if 20 - 20: OoooooooOO - I1ii11iIi11i * I1ii11iIi11i * I1ii11iIi11i
  if 87 - 87: OoooooooOO * ooOoO0o
 def is_ipv4_string ( self , addr_str ) :
  return ( addr_str . find ( "." ) != - 1 )
  if 6 - 6: I1Ii111 / ooOoO0o / OoooooooOO . iIii1I11I1II1
  if 68 - 68: OoO0O00
 def is_ipv6 ( self ) :
  return ( True if ( self . afi == LISP_AFI_IPV6 ) else False )
  if 26 - 26: I11i % i1IIi / iIii1I11I1II1 % IiII . iII111i + I1ii11iIi11i
  if 49 - 49: O0 . IiII + I1Ii111 - I11i % II111iiii
 def is_ipv6_link_local ( self ) :
  if ( self . is_ipv6 ( ) == False ) : return ( False )
  return ( ( ( self . address >> 112 ) & 0xffff ) == 0xfe80 )
  if 15 - 15: O0 - OoOoOO00 % II111iiii + O0 % O0 + OoOoOO00
  if 34 - 34: I1Ii111
 def is_ipv6_string_link_local ( self , addr_str ) :
  return ( addr_str . find ( "fe80::" ) != - 1 )
  if 69 - 69: iIii1I11I1II1 . OOooOOo % I11i
  if 28 - 28: I1Ii111 . ooOoO0o % I1IiiI
 def is_ipv6_loopback ( self ) :
  if ( self . is_ipv6 ( ) == False ) : return ( False )
  return ( self . address == 1 )
  if 62 - 62: II111iiii + ooOoO0o + I1IiiI
  if 70 - 70: o0oOOo0O0Ooo + Ii1I . OoO0O00 * Ii1I + OOooOOo + ooOoO0o
 def is_ipv6_multicast ( self ) :
  if ( self . is_ipv6 ( ) == False ) : return ( False )
  return ( ( ( self . address >> 120 ) & 0xff ) == 0xff )
  if 13 - 13: I1ii11iIi11i
  if 97 - 97: oO0o - Oo0Ooo . i11iIiiIii % ooOoO0o * i11iIiiIii - OoooooooOO
 def is_ipv6_string ( self , addr_str ) :
  return ( addr_str . find ( ":" ) != - 1 )
  if 44 - 44: I11i % OoooooooOO / iII111i - i11iIiiIii * i1IIi * o0oOOo0O0Ooo
  if 51 - 51: Ii1I + IiII / I1ii11iIi11i + O0 % Ii1I
 def is_mac ( self ) :
  return ( True if ( self . afi == LISP_AFI_MAC ) else False )
  if 55 - 55: iII111i % o0oOOo0O0Ooo - oO0o % OoooooooOO
  if 18 - 18: OoooooooOO - I1ii11iIi11i
 def is_mac_multicast ( self ) :
  if ( self . is_mac ( ) == False ) : return ( False )
  return ( ( self . address & 0x010000000000 ) != 0 )
  if 94 - 94: OOooOOo . Oo0Ooo + Ii1I * o0oOOo0O0Ooo
  if 79 - 79: OOooOOo + Oo0Ooo
 def is_mac_broadcast ( self ) :
  if ( self . is_mac ( ) == False ) : return ( False )
  return ( self . address == 0xffffffffffff )
  if 33 - 33: iIii1I11I1II1
  if 75 - 75: I1Ii111 / iIii1I11I1II1 . OoooooooOO
 def is_mac_string ( self , addr_str ) :
  return ( len ( addr_str ) == 15 and addr_str . find ( "-" ) != - 1 )
  if 98 - 98: iIii1I11I1II1 / I1IiiI + i1IIi
  if 80 - 80: II111iiii . Oo0Ooo * oO0o % II111iiii / I1ii11iIi11i
 def is_link_local_multicast ( self ) :
  if ( self . is_ipv4 ( ) ) :
   return ( ( 0xe0ffff00 & self . address ) == 0xe0000000 )
   if 66 - 66: iII111i / OoO0O00 / i11iIiiIii
  if ( self . is_ipv6 ( ) ) :
   return ( ( self . address >> 112 ) & 0xffff == 0xff02 )
   if 99 - 99: OOooOOo
  return ( False )
  if 51 - 51: i11iIiiIii . o0oOOo0O0Ooo / iII111i
  if 53 - 53: oO0o / i1IIi - Oo0Ooo - i1IIi + IiII
 def is_null ( self ) :
  return ( True if ( self . afi == LISP_AFI_NONE ) else False )
  if 79 - 79: oO0o % o0oOOo0O0Ooo / o0oOOo0O0Ooo % iII111i
  if 56 - 56: Oo0Ooo % I1ii11iIi11i
 def is_ultimate_root ( self ) :
  return ( True if self . afi == LISP_AFI_ULTIMATE_ROOT else False )
  if 53 - 53: OoO0O00 . I11i - ooOoO0o
  if 11 - 11: I11i + i11iIiiIii / oO0o % oO0o * o0oOOo0O0Ooo / OoOoOO00
 def is_iid_range ( self ) :
  return ( True if self . afi == LISP_AFI_IID_RANGE else False )
  if 74 - 74: oO0o . I1Ii111 . II111iiii
  if 92 - 92: I1Ii111 % OoooooooOO * I1Ii111
 def is_e164 ( self ) :
  return ( True if ( self . afi == LISP_AFI_E164 ) else False )
  if 78 - 78: Oo0Ooo . I11i . oO0o + O0 / O0
  if 41 - 41: iII111i * OoO0O00 - OoO0O00
 def is_dist_name ( self ) :
  return ( True if ( self . afi == LISP_AFI_NAME ) else False )
  if 72 - 72: o0oOOo0O0Ooo + oO0o . I1ii11iIi11i + OoO0O00 / I1Ii111
  if 58 - 58: Oo0Ooo / II111iiii % OoooooooOO % II111iiii
 def is_geo_prefix ( self ) :
  return ( True if ( self . afi == LISP_AFI_GEO_COORD ) else False )
  if 39 - 39: i1IIi
  if 16 - 16: OoOoOO00 % iIii1I11I1II1 + Ii1I - o0oOOo0O0Ooo . Oo0Ooo + i1IIi
 def is_binary ( self ) :
  if ( self . is_dist_name ( ) ) : return ( False )
  if ( self . is_geo_prefix ( ) ) : return ( False )
  return ( True )
  if 59 - 59: i1IIi
  if 37 - 37: OoO0O00 / I1ii11iIi11i / OoOoOO00
 def store_address ( self , addr_str ) :
  if ( self . afi == LISP_AFI_NONE ) : self . string_to_afi ( addr_str )
  if 15 - 15: I1IiiI % iIii1I11I1II1 . I1Ii111
  if 71 - 71: I11i - Ii1I + i11iIiiIii % I1ii11iIi11i - OoO0O00 - OOooOOo
  if 71 - 71: OOooOOo
  if 27 - 27: OOooOOo * O0 * i11iIiiIii / OoOoOO00 - i1IIi
  Ii11 = addr_str . find ( "[" )
  O0o0o00O = addr_str . find ( "]" )
  if ( Ii11 != - 1 and O0o0o00O != - 1 ) :
   self . instance_id = int ( addr_str [ Ii11 + 1 : O0o0o00O ] )
   addr_str = addr_str [ O0o0o00O + 1 : : ]
   if ( self . is_dist_name ( ) == False ) :
    addr_str = addr_str . replace ( " " , "" )
    if 73 - 73: iII111i / I1IiiI * ooOoO0o
    if 85 - 85: I11i + I11i + oO0o - OoOoOO00
    if 15 - 15: OoO0O00
    if 88 - 88: Ii1I % i1IIi / I1Ii111
    if 2 - 2: Ii1I . IiII % OoOoOO00
    if 42 - 42: OoOoOO00 * OoO0O00 * IiII - IiII % Oo0Ooo . IiII
  if ( self . is_ipv4 ( ) ) :
   I1O0o = addr_str . split ( "." )
   oOO = int ( I1O0o [ 0 ] ) << 24
   oOO += int ( I1O0o [ 1 ] ) << 16
   oOO += int ( I1O0o [ 2 ] ) << 8
   oOO += int ( I1O0o [ 3 ] )
   self . address = oOO
  elif ( self . is_ipv6 ( ) ) :
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
   if 53 - 53: Oo0Ooo
   if 16 - 16: Ii1I
   if 73 - 73: i11iIiiIii + I1IiiI - IiII - IiII + IiII . Ii1I
   if 78 - 78: OoO0O00 + oO0o
   o0I11I1II1i = ( addr_str [ 2 : 4 ] == "::" )
   try :
    addr_str = socket . inet_pton ( socket . AF_INET6 , addr_str )
   except :
    addr_str = socket . inet_pton ( socket . AF_INET6 , "0::0" )
    if 81 - 81: I1ii11iIi11i * I1IiiI * OoOoOO00 / IiII
   addr_str = binascii . hexlify ( addr_str )
   if 85 - 85: OoooooooOO
   if ( o0I11I1II1i ) :
    addr_str = addr_str [ 2 : 4 ] + addr_str [ 0 : 2 ] + addr_str [ 4 : : ]
    if 87 - 87: Ii1I
   self . address = int ( addr_str , 16 )
   if 78 - 78: iII111i * iIii1I11I1II1 . OoO0O00 . OoOoOO00 % I1Ii111
  elif ( self . is_geo_prefix ( ) ) :
   o0oO0O = lisp_geo ( None )
   o0oO0O . name = "geo-prefix-{}" . format ( o0oO0O )
   o0oO0O . parse_geo_string ( addr_str )
   self . address = o0oO0O
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
   if 77 - 77: OOooOOo / OoooooooOO
  self . mask_len = self . host_mask_len ( )
  if 11 - 11: iIii1I11I1II1 - Ii1I - OoOoOO00 . oO0o / I1ii11iIi11i
  if 79 - 79: i11iIiiIii % o0oOOo0O0Ooo * II111iiii . i1IIi * Ii1I - i11iIiiIii
 def store_prefix ( self , prefix_str ) :
  if ( self . is_geo_string ( prefix_str ) ) :
   iI11I = prefix_str . find ( "]" )
   ooooOo00OO0o = len ( prefix_str [ iI11I + 1 : : ] ) * 8
  elif ( prefix_str . find ( "/" ) != - 1 ) :
   prefix_str , ooooOo00OO0o = prefix_str . split ( "/" )
  else :
   iIi1IiI = prefix_str . find ( "'" )
   if ( iIi1IiI == - 1 ) : return
   OoO00 = prefix_str . find ( "'" , iIi1IiI + 1 )
   if ( OoO00 == - 1 ) : return
   ooooOo00OO0o = len ( prefix_str [ iIi1IiI + 1 : OoO00 ] ) * 8
   if 31 - 31: IiII / o0oOOo0O0Ooo
   if 27 - 27: Oo0Ooo
  self . string_to_afi ( prefix_str )
  self . store_address ( prefix_str )
  self . mask_len = int ( ooooOo00OO0o )
  if 32 - 32: Oo0Ooo * i11iIiiIii % I1IiiI - i11iIiiIii - I1Ii111 % I1ii11iIi11i
  if 35 - 35: o0oOOo0O0Ooo % iII111i / O0 * I1IiiI . o0oOOo0O0Ooo / OOooOOo
 def zero_host_bits ( self ) :
  oOoOO00O = ( 2 ** self . mask_len ) - 1
  oOO0O = self . addr_length ( ) * 8 - self . mask_len
  oOoOO00O <<= oOO0O
  self . address &= oOoOO00O
  if 76 - 76: iIii1I11I1II1 % OoO0O00 / I1ii11iIi11i . I1ii11iIi11i
  if 26 - 26: IiII . Oo0Ooo + iII111i
 def is_geo_string ( self , addr_str ) :
  iI11I = addr_str . find ( "]" )
  if ( iI11I != - 1 ) : addr_str = addr_str [ iI11I + 1 : : ]
  if 92 - 92: Oo0Ooo - I1IiiI * I1IiiI
  o0oO0O = addr_str . split ( "/" )
  if ( len ( o0oO0O ) == 2 ) :
   if ( o0oO0O [ 1 ] . isdigit ( ) == False ) : return ( False )
   if 78 - 78: OoOoOO00 + OoO0O00 % oO0o + Oo0Ooo
  o0oO0O = o0oO0O [ 0 ]
  o0oO0O = o0oO0O . split ( "-" )
  oo0oOoO0OoOOOo0O = len ( o0oO0O )
  if ( oo0oOoO0OoOOOo0O < 8 or oo0oOoO0OoOOOo0O > 9 ) : return ( False )
  if 24 - 24: I1Ii111 + OOooOOo
  for ooo0oO000 in range ( 0 , oo0oOoO0OoOOOo0O ) :
   if ( ooo0oO000 == 3 ) :
    if ( o0oO0O [ ooo0oO000 ] in [ "N" , "S" ] ) : continue
    return ( False )
    if 17 - 17: II111iiii + iII111i + OoO0O00 % I11i
   if ( ooo0oO000 == 7 ) :
    if ( o0oO0O [ ooo0oO000 ] in [ "W" , "E" ] ) : continue
    return ( False )
    if 23 - 23: iIii1I11I1II1 % O0 % IiII % I1ii11iIi11i
   if ( o0oO0O [ ooo0oO000 ] . isdigit ( ) == False ) : return ( False )
   if 89 - 89: OOooOOo - I1Ii111 - iII111i
  return ( True )
  if 67 - 67: oO0o
  if 76 - 76: I1IiiI % I1IiiI - IiII / OoOoOO00 / I1ii11iIi11i
 def string_to_afi ( self , addr_str ) :
  if ( addr_str . count ( "'" ) == 2 ) :
   self . afi = LISP_AFI_NAME
   return
   if 42 - 42: I1IiiI + I1ii11iIi11i + Oo0Ooo * i1IIi - II111iiii
  if ( addr_str . find ( ":" ) != - 1 ) : self . afi = LISP_AFI_IPV6
  elif ( addr_str . find ( "." ) != - 1 ) : self . afi = LISP_AFI_IPV4
  elif ( addr_str . find ( "+" ) != - 1 ) : self . afi = LISP_AFI_E164
  elif ( self . is_geo_string ( addr_str ) ) : self . afi = LISP_AFI_GEO_COORD
  elif ( addr_str . find ( "-" ) != - 1 ) : self . afi = LISP_AFI_MAC
  else : self . afi = LISP_AFI_NONE
  if 15 - 15: o0oOOo0O0Ooo
  if 60 - 60: I1ii11iIi11i / I1Ii111
 def print_address ( self ) :
  o0o0O00 = self . print_address_no_iid ( )
  o0OOoOO = "[" + str ( self . instance_id )
  for Ii11 in self . iid_list : o0OOoOO += "," + str ( Ii11 )
  o0OOoOO += "]"
  o0o0O00 = "{}{}" . format ( o0OOoOO , o0o0O00 )
  return ( o0o0O00 )
  if 13 - 13: I1Ii111
  if 52 - 52: II111iiii / OoO0O00 . Ii1I
 def print_address_no_iid ( self ) :
  if ( self . is_ipv4 ( ) ) :
   o0o0O00 = self . address
   o0o0oo0O00o = o0o0O00 >> 24
   oO0 = ( o0o0O00 >> 16 ) & 0xff
   IIIiI1i1iiIIi = ( o0o0O00 >> 8 ) & 0xff
   iIIiIi = o0o0O00 & 0xff
   return ( "{}.{}.{}.{}" . format ( o0o0oo0O00o , oO0 , IIIiI1i1iiIIi , iIIiIi ) )
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
   if 36 - 36: OOooOOo * I1IiiI
  return ( "unknown-afi:{}" . format ( self . afi ) )
  if 78 - 78: Oo0Ooo * IiII . Oo0Ooo / I11i
  if 85 - 85: i1IIi - IiII - o0oOOo0O0Ooo + o0oOOo0O0Ooo
 def print_prefix ( self ) :
  if ( self . is_ultimate_root ( ) ) : return ( "[*]" )
  if ( self . is_iid_range ( ) ) :
   if ( self . mask_len == 32 ) : return ( "[{}]" . format ( self . instance_id ) )
   OOoOo000Ooooo = self . instance_id + ( 2 ** ( 32 - self . mask_len ) - 1 )
   return ( "[{}-{}]" . format ( self . instance_id , OOoOo000Ooooo ) )
   if 68 - 68: iIii1I11I1II1 % oO0o
  o0o0O00 = self . print_address ( )
  if ( self . is_dist_name ( ) ) : return ( o0o0O00 )
  if ( self . is_geo_prefix ( ) ) : return ( o0o0O00 )
  if 5 - 5: o0oOOo0O0Ooo
  iI11I = o0o0O00 . find ( "no-address" )
  if ( iI11I == - 1 ) :
   o0o0O00 = "{}/{}" . format ( o0o0O00 , str ( self . mask_len ) )
  else :
   o0o0O00 = o0o0O00 [ 0 : iI11I ]
   if 24 - 24: OoooooooOO
  return ( o0o0O00 )
  if 64 - 64: iIii1I11I1II1 % OoooooooOO * i1IIi
  if 50 - 50: I1IiiI - i1IIi / Oo0Ooo * I1ii11iIi11i . II111iiii
 def print_prefix_no_iid ( self ) :
  o0o0O00 = self . print_address_no_iid ( )
  if ( self . is_dist_name ( ) ) : return ( o0o0O00 )
  if ( self . is_geo_prefix ( ) ) : return ( o0o0O00 )
  return ( "{}/{}" . format ( o0o0O00 , str ( self . mask_len ) ) )
  if 24 - 24: OoooooooOO * Ii1I
  if 66 - 66: O0 - Ii1I % IiII
 def print_prefix_url ( self ) :
  if ( self . is_ultimate_root ( ) ) : return ( "0--0" )
  o0o0O00 = self . print_address ( )
  iI11I = o0o0O00 . find ( "]" )
  if ( iI11I != - 1 ) : o0o0O00 = o0o0O00 [ iI11I + 1 : : ]
  if ( self . is_geo_prefix ( ) ) :
   o0o0O00 = o0o0O00 . replace ( "/" , "-" )
   return ( "{}-{}" . format ( self . instance_id , o0o0O00 ) )
   if 97 - 97: Ii1I * O0 * I1IiiI % oO0o
  return ( "{}-{}-{}" . format ( self . instance_id , o0o0O00 , self . mask_len ) )
  if 44 - 44: O0
  if 38 - 38: i11iIiiIii
 def print_sg ( self , g ) :
  IiIIi1I1I11Ii = self . print_prefix ( )
  Ooo = IiIIi1I1I11Ii . find ( "]" ) + 1
  g = g . print_prefix ( )
  ii1i1I11II = g . find ( "]" ) + 1
  o0 = "[{}]({}, {})" . format ( self . instance_id , IiIIi1I1I11Ii [ Ooo : : ] , g [ ii1i1I11II : : ] )
  return ( o0 )
  if 72 - 72: OoooooooOO * II111iiii + OoO0O00 % iIii1I11I1II1 . I1ii11iIi11i % OoooooooOO
  if 19 - 19: OoOoOO00 + I1Ii111
 def hash_address ( self , addr ) :
  OooO0O0Ooo = self . address
  oO0O = addr . address
  if 19 - 19: I1ii11iIi11i / I1Ii111 + OoooooooOO - O0
  if ( self . is_geo_prefix ( ) ) : OooO0O0Ooo = self . address . print_geo ( )
  if ( addr . is_geo_prefix ( ) ) : oO0O = addr . address . print_geo ( )
  if 49 - 49: I1ii11iIi11i / OoOoOO00 - I1IiiI + iII111i . OOooOOo % oO0o
  if ( type ( OooO0O0Ooo ) == str ) :
   OooO0O0Ooo = int ( binascii . hexlify ( OooO0O0Ooo [ 0 : 1 ] ) )
   if 34 - 34: OoO0O00 - I1IiiI + OoOoOO00
  if ( type ( oO0O ) == str ) :
   oO0O = int ( binascii . hexlify ( oO0O [ 0 : 1 ] ) )
   if 22 - 22: iIii1I11I1II1 . i1IIi . OOooOOo % Oo0Ooo - i1IIi
  return ( OooO0O0Ooo ^ oO0O )
  if 78 - 78: I1IiiI / i1IIi % II111iiii % I1IiiI % Ii1I
  if 29 - 29: i1IIi % o0oOOo0O0Ooo + OOooOOo / Oo0Ooo
  if 38 - 38: IiII . I1Ii111
  if 69 - 69: ooOoO0o + OoOoOO00 + II111iiii % I1Ii111 + Ii1I . ooOoO0o
  if 73 - 73: I11i % I11i . ooOoO0o + OoOoOO00
  if 33 - 33: i11iIiiIii . i11iIiiIii * i11iIiiIii / iIii1I11I1II1 / I1ii11iIi11i . ooOoO0o
 def is_more_specific ( self , prefix ) :
  if ( prefix . afi == LISP_AFI_ULTIMATE_ROOT ) : return ( True )
  if 11 - 11: iII111i
  ooooOo00OO0o = prefix . mask_len
  if ( prefix . afi == LISP_AFI_IID_RANGE ) :
   oO0oOoo00o = 2 ** ( 32 - ooooOo00OO0o )
   iIii1II = prefix . instance_id
   OOoOo000Ooooo = iIii1II + oO0oOoo00o
   return ( self . instance_id in range ( iIii1II , OOoOo000Ooooo ) )
   if 45 - 45: Ii1I % OOooOOo * Ii1I - iIii1I11I1II1
   if 18 - 18: I1Ii111 / Oo0Ooo % Ii1I + OoO0O00
  if ( self . instance_id != prefix . instance_id ) : return ( False )
  if ( self . afi != prefix . afi ) :
   if ( prefix . afi != LISP_AFI_NONE ) : return ( False )
   if 69 - 69: iII111i % I1ii11iIi11i
   if 19 - 19: IiII
   if 35 - 35: OoOoOO00
   if 18 - 18: II111iiii . OoOoOO00 + I1ii11iIi11i * oO0o + OoooooooOO
   if 39 - 39: I1IiiI * ooOoO0o / i11iIiiIii - oO0o - oO0o + O0
  if ( self . is_binary ( ) == False ) :
   if ( prefix . afi == LISP_AFI_NONE ) : return ( True )
   if ( type ( self . address ) != type ( prefix . address ) ) : return ( False )
   o0o0O00 = self . address
   oO00OOoOoO = prefix . address
   if ( self . is_geo_prefix ( ) ) :
    o0o0O00 = self . address . print_geo ( )
    oO00OOoOoO = prefix . address . print_geo ( )
    if 65 - 65: II111iiii - I1Ii111 * Oo0Ooo + ooOoO0o / OOooOOo . i11iIiiIii
   if ( len ( o0o0O00 ) < len ( oO00OOoOoO ) ) : return ( False )
   return ( o0o0O00 . find ( oO00OOoOoO ) == 0 )
   if 15 - 15: I1IiiI
   if 50 - 50: Oo0Ooo - I1Ii111 / I1IiiI + IiII / o0oOOo0O0Ooo . iII111i
   if 61 - 61: OoO0O00 + o0oOOo0O0Ooo * iII111i
   if 84 - 84: Oo0Ooo . I1Ii111
   if 6 - 6: IiII + I1IiiI % iII111i - oO0o / OoO0O00
  if ( self . mask_len < ooooOo00OO0o ) : return ( False )
  if 37 - 37: O0 % OoO0O00 + i11iIiiIii . O0 / OOooOOo
  oOO0O = ( prefix . addr_length ( ) * 8 ) - ooooOo00OO0o
  oOoOO00O = ( 2 ** ooooOo00OO0o - 1 ) << oOO0O
  return ( ( self . address & oOoOO00O ) == prefix . address )
  if 15 - 15: I1ii11iIi11i + oO0o
  if 99 - 99: oO0o - ooOoO0o - II111iiii * OoooooooOO / O0
 def mask_address ( self , mask_len ) :
  oOO0O = ( self . addr_length ( ) * 8 ) - mask_len
  oOoOO00O = ( 2 ** mask_len - 1 ) << oOO0O
  self . address &= oOoOO00O
  if 57 - 57: iIii1I11I1II1 / IiII + OoO0O00 * oO0o + Ii1I
  if 76 - 76: i11iIiiIii . OOooOOo / I11i * oO0o % iIii1I11I1II1 . ooOoO0o
 def is_exact_match ( self , prefix ) :
  if ( self . instance_id != prefix . instance_id ) : return ( False )
  ooOO00 = self . print_prefix ( )
  iIIii = prefix . print_prefix ( ) if prefix else ""
  return ( ooOO00 == iIIii )
  if 81 - 81: OOooOOo . OOooOOo
  if 70 - 70: I1IiiI / I11i - II111iiii . o0oOOo0O0Ooo / O0
 def is_local ( self ) :
  if ( self . is_ipv4 ( ) ) :
   I11 = lisp_myrlocs [ 0 ]
   if ( I11 == None ) : return ( False )
   I11 = I11 . print_address_no_iid ( )
   return ( self . print_address_no_iid ( ) == I11 )
   if 70 - 70: OoO0O00 % Ii1I - Ii1I / OoO0O00 * IiII
  if ( self . is_ipv6 ( ) ) :
   I11 = lisp_myrlocs [ 1 ]
   if ( I11 == None ) : return ( False )
   I11 = I11 . print_address_no_iid ( )
   return ( self . print_address_no_iid ( ) == I11 )
   if 2 - 2: oO0o
  return ( False )
  if 11 - 11: Ii1I
  if 77 - 77: IiII * o0oOOo0O0Ooo % oO0o
 def store_iid_range ( self , iid , mask_len ) :
  if ( self . afi == LISP_AFI_NONE ) :
   if ( iid is 0 and mask_len is 0 ) : self . afi = LISP_AFI_ULTIMATE_ROOT
   else : self . afi = LISP_AFI_IID_RANGE
   if 49 - 49: oO0o
  self . instance_id = iid
  self . mask_len = mask_len
  if 85 - 85: OoO0O00 . IiII / iII111i . I1IiiI
  if 8 - 8: i1IIi - iIii1I11I1II1 + iII111i
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
  if 90 - 90: i11iIiiIii - Oo0Ooo
  if 31 - 31: OoOoOO00 + OoOoOO00 + OoooooooOO % O0
  if 14 - 14: i1IIi / OoooooooOO . I1IiiI * I1Ii111 + OoO0O00
  if 45 - 45: OoooooooOO * I1Ii111
  if 7 - 7: O0
  if 42 - 42: o0oOOo0O0Ooo / Ii1I
  if 31 - 31: OOooOOo
  if 20 - 20: i11iIiiIii * oO0o * ooOoO0o
  if 65 - 65: I1ii11iIi11i / Oo0Ooo / I1IiiI + IiII
  if 71 - 71: OoO0O00 . I1Ii111 + OoooooooOO
  if 9 - 9: OoooooooOO / iIii1I11I1II1 % I1IiiI . I1IiiI / I11i - iII111i
  if 60 - 60: I11i - OoO0O00 - OoOoOO00 * ooOoO0o - i1IIi
  if 18 - 18: ooOoO0o + i11iIiiIii + O0 + OOooOOo / Ii1I
  if 65 - 65: I1IiiI . ooOoO0o
  if 51 - 51: I1Ii111
  if 89 - 89: Oo0Ooo
  if 15 - 15: OOooOOo * II111iiii - OOooOOo * iIii1I11I1II1
 def lcaf_encode_iid ( self ) :
  oOOi1I111II = LISP_LCAF_INSTANCE_ID_TYPE
  I11II11IiI11 = socket . htons ( self . lcaf_length ( oOOi1I111II ) )
  o0OOoOO = self . instance_id
  iioOO = self . afi
  Iii11i1 = 0
  if ( iioOO < 0 ) :
   if ( self . afi == LISP_AFI_GEO_COORD ) :
    iioOO = LISP_AFI_LCAF
    Iii11i1 = 0
   else :
    iioOO = 0
    Iii11i1 = self . mask_len
    if 95 - 95: I1Ii111 / OoooooooOO * I11i * OoooooooOO
    if 88 - 88: I1IiiI / Oo0Ooo / oO0o + oO0o % OOooOOo + Oo0Ooo
    if 63 - 63: o0oOOo0O0Ooo + i11iIiiIii % OOooOOo % iIii1I11I1II1 / I1ii11iIi11i - iII111i
  O0oOO0oOo0o = struct . pack ( "BBBBH" , 0 , 0 , oOOi1I111II , Iii11i1 , I11II11IiI11 )
  O0oOO0oOo0o += struct . pack ( "IH" , socket . htonl ( o0OOoOO ) , socket . htons ( iioOO ) )
  if ( iioOO == 0 ) : return ( O0oOO0oOo0o )
  if 10 - 10: I11i . ooOoO0o + I11i * Ii1I
  if ( self . afi == LISP_AFI_GEO_COORD ) :
   O0oOO0oOo0o = O0oOO0oOo0o [ 0 : - 2 ]
   O0oOO0oOo0o += self . address . encode_geo ( )
   return ( O0oOO0oOo0o )
   if 55 - 55: OOooOOo / iII111i + OoooooooOO - OoooooooOO
   if 51 - 51: O0 % Ii1I % Oo0Ooo - O0
  O0oOO0oOo0o += self . pack_address ( )
  return ( O0oOO0oOo0o )
  if 94 - 94: OoooooooOO - ooOoO0o % I1ii11iIi11i + I1Ii111
  if 51 - 51: I1ii11iIi11i . iII111i / i1IIi * ooOoO0o % I11i
 def lcaf_decode_iid ( self , packet ) :
  oOoOo000 = "BBBBH"
  O0OOoooO = struct . calcsize ( oOoOo000 )
  if ( len ( packet ) < O0OOoooO ) : return ( None )
  if 82 - 82: O0 % OoOoOO00 . iII111i . i1IIi . iII111i - Oo0Ooo
  II11iiii , oo0Oo0o0O , oOOi1I111II , oo0Oo0OoooOO , o00OOo00 = struct . unpack ( oOoOo000 ,
 packet [ : O0OOoooO ] )
  packet = packet [ O0OOoooO : : ]
  if 23 - 23: Oo0Ooo - iIii1I11I1II1 . Ii1I / oO0o
  if ( oOOi1I111II != LISP_LCAF_INSTANCE_ID_TYPE ) : return ( None )
  if 50 - 50: i1IIi * OoOoOO00 % I1ii11iIi11i . ooOoO0o + I1Ii111
  oOoOo000 = "IH"
  O0OOoooO = struct . calcsize ( oOoOo000 )
  if ( len ( packet ) < O0OOoooO ) : return ( None )
  if 83 - 83: I1ii11iIi11i . II111iiii
  o0OOoOO , iioOO = struct . unpack ( oOoOo000 , packet [ : O0OOoooO ] )
  packet = packet [ O0OOoooO : : ]
  if 14 - 14: Ii1I % I1IiiI * OOooOOo / Oo0Ooo % OoOoOO00
  o00OOo00 = socket . ntohs ( o00OOo00 )
  self . instance_id = socket . ntohl ( o0OOoOO )
  iioOO = socket . ntohs ( iioOO )
  self . afi = iioOO
  if ( oo0Oo0OoooOO != 0 and iioOO == 0 ) : self . mask_len = oo0Oo0OoooOO
  if ( iioOO == 0 ) :
   self . afi = LISP_AFI_IID_RANGE if oo0Oo0OoooOO else LISP_AFI_ULTIMATE_ROOT
   if 20 - 20: i11iIiiIii . I1IiiI - iII111i % iII111i - iIii1I11I1II1 - o0oOOo0O0Ooo
   if 44 - 44: iII111i
   if 52 - 52: i11iIiiIii
   if 1 - 1: i1IIi * iIii1I11I1II1
   if 29 - 29: I11i
  if ( iioOO == 0 ) : return ( packet )
  if 12 - 12: oO0o % i1IIi - oO0o / ooOoO0o * II111iiii % ooOoO0o
  if 6 - 6: IiII / OoO0O00
  if 83 - 83: IiII - iIii1I11I1II1 * ooOoO0o - oO0o
  if 77 - 77: Ii1I
  if ( self . is_dist_name ( ) ) :
   packet , self . address = lisp_decode_dist_name ( packet )
   self . mask_len = len ( self . address ) * 8
   return ( packet )
   if 9 - 9: OOooOOo / OoooooooOO + iII111i
   if 52 - 52: IiII / OOooOOo * iIii1I11I1II1 + o0oOOo0O0Ooo
   if 20 - 20: I1Ii111
   if 33 - 33: i11iIiiIii / I1Ii111 + IiII / II111iiii + I11i
   if 13 - 13: i1IIi % iII111i + OoOoOO00 / Ii1I . Ii1I + II111iiii
  if ( iioOO == LISP_AFI_LCAF ) :
   oOoOo000 = "BBBBH"
   O0OOoooO = struct . calcsize ( oOoOo000 )
   if ( len ( packet ) < O0OOoooO ) : return ( None )
   if 44 - 44: OoOoOO00 / OoooooooOO % O0 * Ii1I * IiII
   OOII1iI , Ooooo0OO , oOOi1I111II , o0o0OO0OO , ii111 = struct . unpack ( oOoOo000 , packet [ : O0OOoooO ] )
   if 84 - 84: o0oOOo0O0Ooo * IiII * OOooOOo * iII111i
   if 56 - 56: iII111i * II111iiii . OoooooooOO . I11i
   if ( oOOi1I111II != LISP_LCAF_GEO_COORD_TYPE ) : return ( None )
   if 25 - 25: ooOoO0o % o0oOOo0O0Ooo - i11iIiiIii
   ii111 = socket . ntohs ( ii111 )
   packet = packet [ O0OOoooO : : ]
   if ( ii111 > len ( packet ) ) : return ( None )
   if 79 - 79: iII111i - I1IiiI % O0 / Oo0Ooo + OoOoOO00 . Oo0Ooo
   o0oO0O = lisp_geo ( "" )
   self . afi = LISP_AFI_GEO_COORD
   self . address = o0oO0O
   packet = o0oO0O . decode_geo ( packet , ii111 , o0o0OO0OO )
   self . mask_len = self . host_mask_len ( )
   return ( packet )
   if 59 - 59: I1ii11iIi11i * OoOoOO00 / Ii1I
   if 80 - 80: IiII - ooOoO0o / OoOoOO00 / I11i * O0 + oO0o
  I11II11IiI11 = self . addr_length ( )
  if ( len ( packet ) < I11II11IiI11 ) : return ( None )
  if 77 - 77: ooOoO0o + I1ii11iIi11i * o0oOOo0O0Ooo / i1IIi * I11i
  packet = self . unpack_address ( packet )
  return ( packet )
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
  if 41 - 41: I1ii11iIi11i * ooOoO0o * I11i + O0 * O0 - O0
  if 81 - 81: I1Ii111 % OoO0O00 / O0
  if 55 - 55: i1IIi - I1Ii111 + I11i
  if 93 - 93: I1IiiI % IiII . OoOoOO00 + iII111i
  if 81 - 81: ooOoO0o / I1Ii111 + OOooOOo / Oo0Ooo / OoOoOO00
  if 34 - 34: ooOoO0o * iIii1I11I1II1 % i11iIiiIii * OOooOOo - OOooOOo
  if 63 - 63: Oo0Ooo / oO0o + iII111i % OoooooooOO * I11i
  if 34 - 34: I1IiiI + I1Ii111 % ooOoO0o
  if 24 - 24: Ii1I % II111iiii - i11iIiiIii
  if 52 - 52: OoO0O00
  if 76 - 76: ooOoO0o - iII111i % ooOoO0o / oO0o . OOooOOo
 def lcaf_encode_sg ( self , group ) :
  oOOi1I111II = LISP_LCAF_MCAST_INFO_TYPE
  o0OOoOO = socket . htonl ( self . instance_id )
  I11II11IiI11 = socket . htons ( self . lcaf_length ( oOOi1I111II ) )
  O0oOO0oOo0o = struct . pack ( "BBBBHIHBB" , 0 , 0 , oOOi1I111II , 0 , I11II11IiI11 , o0OOoOO ,
 0 , self . mask_len , group . mask_len )
  if 50 - 50: IiII . i11iIiiIii % I11i
  O0oOO0oOo0o += struct . pack ( "H" , socket . htons ( self . afi ) )
  O0oOO0oOo0o += self . pack_address ( )
  O0oOO0oOo0o += struct . pack ( "H" , socket . htons ( group . afi ) )
  O0oOO0oOo0o += group . pack_address ( )
  return ( O0oOO0oOo0o )
  if 22 - 22: i1IIi - II111iiii - OoOoOO00 . iII111i
  if 43 - 43: I1Ii111 * OOooOOo - IiII . i11iIiiIii
 def lcaf_decode_sg ( self , packet ) :
  oOoOo000 = "BBBBHIHBB"
  O0OOoooO = struct . calcsize ( oOoOo000 )
  if ( len ( packet ) < O0OOoooO ) : return ( [ None , None ] )
  if 34 - 34: iII111i . OoOoOO00
  II11iiii , oo0Oo0o0O , oOOi1I111II , i11iIi1I1i1 , o00OOo00 , o0OOoOO , IIIIi11IiiI , Ii11Ii1i , Ii1II11I1iI11 = struct . unpack ( oOoOo000 , packet [ : O0OOoooO ] )
  if 71 - 71: OOooOOo % Oo0Ooo - o0oOOo0O0Ooo / I1Ii111 - O0 - oO0o
  packet = packet [ O0OOoooO : : ]
  if 10 - 10: I1IiiI
  if ( oOOi1I111II != LISP_LCAF_MCAST_INFO_TYPE ) : return ( [ None , None ] )
  if 17 - 17: i11iIiiIii % o0oOOo0O0Ooo . ooOoO0o
  self . instance_id = socket . ntohl ( o0OOoOO )
  o00OOo00 = socket . ntohs ( o00OOo00 ) - 8
  if 34 - 34: OoooooooOO / iII111i / O0
  if 75 - 75: I11i % OOooOOo - OoO0O00 * I11i * IiII
  if 11 - 11: I1ii11iIi11i . O0 - iII111i * IiII . i1IIi . iII111i
  if 82 - 82: i1IIi * I11i * Ii1I - IiII . i11iIiiIii
  if 40 - 40: OOooOOo - OoooooooOO
  oOoOo000 = "H"
  O0OOoooO = struct . calcsize ( oOoOo000 )
  if ( len ( packet ) < O0OOoooO ) : return ( [ None , None ] )
  if ( o00OOo00 < O0OOoooO ) : return ( [ None , None ] )
  if 36 - 36: i1IIi % OoOoOO00 - i1IIi
  iioOO = struct . unpack ( oOoOo000 , packet [ : O0OOoooO ] ) [ 0 ]
  packet = packet [ O0OOoooO : : ]
  o00OOo00 -= O0OOoooO
  self . afi = socket . ntohs ( iioOO )
  self . mask_len = Ii11Ii1i
  I11II11IiI11 = self . addr_length ( )
  if ( o00OOo00 < I11II11IiI11 ) : return ( [ None , None ] )
  if 5 - 5: I1IiiI . I1IiiI % II111iiii - I1Ii111
  packet = self . unpack_address ( packet )
  if ( packet == None ) : return ( [ None , None ] )
  if 97 - 97: I11i . ooOoO0o
  o00OOo00 -= I11II11IiI11
  if 87 - 87: oO0o / iIii1I11I1II1 - I11i + OoooooooOO
  if 79 - 79: I1ii11iIi11i * IiII . I1ii11iIi11i
  if 65 - 65: iII111i - Ii1I - II111iiii * O0 + I1ii11iIi11i . iIii1I11I1II1
  if 76 - 76: OoO0O00 * ooOoO0o
  if 32 - 32: O0 . oO0o * o0oOOo0O0Ooo . Ii1I + IiII
  oOoOo000 = "H"
  O0OOoooO = struct . calcsize ( oOoOo000 )
  if ( len ( packet ) < O0OOoooO ) : return ( [ None , None ] )
  if ( o00OOo00 < O0OOoooO ) : return ( [ None , None ] )
  if 98 - 98: iII111i . II111iiii % O0
  iioOO = struct . unpack ( oOoOo000 , packet [ : O0OOoooO ] ) [ 0 ]
  packet = packet [ O0OOoooO : : ]
  o00OOo00 -= O0OOoooO
  O0oo0oo0 = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  O0oo0oo0 . afi = socket . ntohs ( iioOO )
  O0oo0oo0 . mask_len = Ii1II11I1iI11
  O0oo0oo0 . instance_id = self . instance_id
  I11II11IiI11 = self . addr_length ( )
  if ( o00OOo00 < I11II11IiI11 ) : return ( [ None , None ] )
  if 43 - 43: OOooOOo % I1Ii111 . IiII % OoO0O00 + I1Ii111 % OoooooooOO
  packet = O0oo0oo0 . unpack_address ( packet )
  if ( packet == None ) : return ( [ None , None ] )
  if 17 - 17: OoooooooOO - i1IIi * I11i
  return ( [ packet , O0oo0oo0 ] )
  if 33 - 33: i1IIi . Oo0Ooo + I11i
  if 97 - 97: OOooOOo / IiII / ooOoO0o / OoooooooOO
 def lcaf_decode_eid ( self , packet ) :
  oOoOo000 = "BBB"
  O0OOoooO = struct . calcsize ( oOoOo000 )
  if ( len ( packet ) < O0OOoooO ) : return ( [ None , None ] )
  if 78 - 78: I1Ii111 + I1Ii111
  if 43 - 43: I1Ii111 * o0oOOo0O0Ooo + i1IIi
  if 19 - 19: Ii1I
  if 51 - 51: oO0o
  if 57 - 57: i11iIiiIii - Oo0Ooo + I1Ii111 * OoO0O00
  i11iIi1I1i1 , Ooooo0OO , oOOi1I111II = struct . unpack ( oOoOo000 ,
 packet [ : O0OOoooO ] )
  if 35 - 35: o0oOOo0O0Ooo % II111iiii + O0
  if ( oOOi1I111II == LISP_LCAF_INSTANCE_ID_TYPE ) :
   return ( [ self . lcaf_decode_iid ( packet ) , None ] )
  elif ( oOOi1I111II == LISP_LCAF_MCAST_INFO_TYPE ) :
   packet , O0oo0oo0 = self . lcaf_decode_sg ( packet )
   return ( [ packet , O0oo0oo0 ] )
  elif ( oOOi1I111II == LISP_LCAF_GEO_COORD_TYPE ) :
   oOoOo000 = "BBBBH"
   O0OOoooO = struct . calcsize ( oOoOo000 )
   if ( len ( packet ) < O0OOoooO ) : return ( None )
   if 70 - 70: I1ii11iIi11i . II111iiii
   OOII1iI , Ooooo0OO , oOOi1I111II , o0o0OO0OO , ii111 = struct . unpack ( oOoOo000 , packet [ : O0OOoooO ] )
   if 54 - 54: OOooOOo
   if 67 - 67: I1IiiI . o0oOOo0O0Ooo / i1IIi * I1ii11iIi11i . Oo0Ooo + II111iiii
   if ( oOOi1I111II != LISP_LCAF_GEO_COORD_TYPE ) : return ( None )
   if 63 - 63: OoOoOO00 - OoOoOO00
   ii111 = socket . ntohs ( ii111 )
   packet = packet [ O0OOoooO : : ]
   if ( ii111 > len ( packet ) ) : return ( None )
   if 31 - 31: I1ii11iIi11i % O0 - i11iIiiIii * o0oOOo0O0Ooo . ooOoO0o * ooOoO0o
   o0oO0O = lisp_geo ( "" )
   self . instance_id = 0
   self . afi = LISP_AFI_GEO_COORD
   self . address = o0oO0O
   packet = o0oO0O . decode_geo ( packet , ii111 , o0o0OO0OO )
   self . mask_len = self . host_mask_len ( )
   if 18 - 18: OoO0O00 - OoO0O00 . o0oOOo0O0Ooo
  return ( [ packet , None ] )
  if 80 - 80: I11i + I1Ii111 / I1IiiI * OOooOOo % iII111i
  if 48 - 48: iIii1I11I1II1 + i1IIi . I1IiiI % OoO0O00 - iIii1I11I1II1 / i1IIi
  if 14 - 14: IiII . I11i
  if 13 - 13: OoOoOO00 - I11i . OOooOOo % OoO0O00
  if 79 - 79: iII111i / Ii1I % i11iIiiIii . I1IiiI % OoO0O00 / i11iIiiIii
  if 100 - 100: OOooOOo + Oo0Ooo . iIii1I11I1II1 . ooOoO0o * Oo0Ooo
class lisp_elp_node ( ) :
 def __init__ ( self ) :
  self . address = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . probe = False
  self . strict = False
  self . eid = False
  self . we_are_last = False
  if 16 - 16: Oo0Ooo % OoOoOO00 + I1Ii111 % I1Ii111
  if 12 - 12: I1Ii111 . Ii1I / iIii1I11I1II1 + i1IIi
 def copy_elp_node ( self ) :
  Oo00o0o00oOo = lisp_elp_node ( )
  Oo00o0o00oOo . copy_address ( self . address )
  Oo00o0o00oOo . probe = self . probe
  Oo00o0o00oOo . strict = self . strict
  Oo00o0o00oOo . eid = self . eid
  Oo00o0o00oOo . we_are_last = self . we_are_last
  return ( Oo00o0o00oOo )
  if 9 - 9: iIii1I11I1II1
  if 75 - 75: I11i . II111iiii * I1IiiI * IiII
  if 36 - 36: OOooOOo / I1ii11iIi11i / oO0o / ooOoO0o / I11i
class lisp_elp ( ) :
 def __init__ ( self , name ) :
  self . elp_name = name
  self . elp_nodes = [ ]
  self . use_elp_node = None
  self . we_are_last = False
  if 7 - 7: OoO0O00 - I11i - o0oOOo0O0Ooo / o0oOOo0O0Ooo + i11iIiiIii
  if 28 - 28: OoOoOO00 % ooOoO0o . I1IiiI + II111iiii
 def copy_elp ( self ) :
  IIi1iIi = lisp_elp ( self . elp_name )
  IIi1iIi . use_elp_node = self . use_elp_node
  IIi1iIi . we_are_last = self . we_are_last
  for Oo00o0o00oOo in self . elp_nodes :
   IIi1iIi . elp_nodes . append ( Oo00o0o00oOo . copy_elp_node ( ) )
   if 34 - 34: iIii1I11I1II1
  return ( IIi1iIi )
  if 65 - 65: II111iiii - iII111i / o0oOOo0O0Ooo
  if 35 - 35: i11iIiiIii - Oo0Ooo . I1ii11iIi11i % OoOoOO00
 def print_elp ( self , want_marker ) :
  iI11i1Ii = ""
  for Oo00o0o00oOo in self . elp_nodes :
   i1II1II = ""
   if ( want_marker ) :
    if ( Oo00o0o00oOo == self . use_elp_node ) :
     i1II1II = "*"
    elif ( Oo00o0o00oOo . we_are_last ) :
     i1II1II = "x"
     if 57 - 57: II111iiii / Oo0Ooo % i1IIi * iIii1I11I1II1
     if 53 - 53: I1Ii111 . I1ii11iIi11i
   iI11i1Ii += "{}{}({}{}{}), " . format ( i1II1II ,
 Oo00o0o00oOo . address . print_address_no_iid ( ) ,
 "r" if Oo00o0o00oOo . eid else "R" , "P" if Oo00o0o00oOo . probe else "p" ,
 "S" if Oo00o0o00oOo . strict else "s" )
   if 18 - 18: I1ii11iIi11i / i11iIiiIii
  return ( iI11i1Ii [ 0 : - 2 ] if iI11i1Ii != "" else "" )
  if 52 - 52: i11iIiiIii . O0 * ooOoO0o - o0oOOo0O0Ooo - O0
  if 39 - 39: iII111i / I11i
 def select_elp_node ( self ) :
  oo00 , iiiIIi1IiiIiII1 , O0OoO0o = lisp_myrlocs
  iI11I = None
  if 22 - 22: ooOoO0o % ooOoO0o . OOooOOo - II111iiii + OoO0O00
  for Oo00o0o00oOo in self . elp_nodes :
   if ( oo00 and Oo00o0o00oOo . address . is_exact_match ( oo00 ) ) :
    iI11I = self . elp_nodes . index ( Oo00o0o00oOo )
    break
    if 44 - 44: I11i / o0oOOo0O0Ooo - OoO0O00 . Ii1I % oO0o - o0oOOo0O0Ooo
   if ( iiiIIi1IiiIiII1 and Oo00o0o00oOo . address . is_exact_match ( iiiIIi1IiiIiII1 ) ) :
    iI11I = self . elp_nodes . index ( Oo00o0o00oOo )
    break
    if 14 - 14: OOooOOo * IiII
    if 15 - 15: o0oOOo0O0Ooo + OoooooooOO - OOooOOo - o0oOOo0O0Ooo . iIii1I11I1II1 / Ii1I
    if 33 - 33: OoO0O00
    if 91 - 91: I11i % I11i % iII111i
    if 19 - 19: I11i / I11i + I1IiiI * OoO0O00 - iII111i . Oo0Ooo
    if 76 - 76: iII111i % OOooOOo / OoooooooOO . I1IiiI % OoO0O00 % i1IIi
    if 95 - 95: Oo0Ooo - O0 / I1ii11iIi11i . I1IiiI / o0oOOo0O0Ooo % OoOoOO00
  if ( iI11I == None ) :
   self . use_elp_node = self . elp_nodes [ 0 ]
   Oo00o0o00oOo . we_are_last = False
   return
   if 38 - 38: OoOoOO00 % OoooooooOO . oO0o - OoooooooOO + I11i
   if 18 - 18: OoooooooOO + ooOoO0o * OoOoOO00 - OoO0O00
   if 42 - 42: oO0o % OoOoOO00 - oO0o + I11i / i11iIiiIii
   if 74 - 74: OoO0O00 - II111iiii - ooOoO0o % i1IIi
   if 42 - 42: i11iIiiIii / O0
   if 8 - 8: I1Ii111
  if ( self . elp_nodes [ - 1 ] == self . elp_nodes [ iI11I ] ) :
   self . use_elp_node = None
   Oo00o0o00oOo . we_are_last = True
   return
   if 51 - 51: i11iIiiIii
   if 1 - 1: iIii1I11I1II1 . i1IIi . i11iIiiIii % I1ii11iIi11i
   if 58 - 58: i11iIiiIii * i11iIiiIii - OoO0O00
   if 8 - 8: i11iIiiIii * OoOoOO00 . o0oOOo0O0Ooo
   if 27 - 27: I1ii11iIi11i + Ii1I % I1Ii111
  self . use_elp_node = self . elp_nodes [ iI11I + 1 ]
  return
  if 20 - 20: Oo0Ooo
  if 33 - 33: oO0o - OoOoOO00 - i11iIiiIii + I1Ii111 + iIii1I11I1II1
  if 2 - 2: OoooooooOO + IiII / iII111i . iIii1I11I1II1 * OoOoOO00
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
  if 84 - 84: OOooOOo
  if 68 - 68: I1Ii111
 def copy_geo ( self ) :
  o0oO0O = lisp_geo ( self . geo_name )
  o0oO0O . latitude = self . latitude
  o0oO0O . lat_mins = self . lat_mins
  o0oO0O . lat_secs = self . lat_secs
  o0oO0O . longitude = self . longitude
  o0oO0O . long_mins = self . long_mins
  o0oO0O . long_secs = self . long_secs
  o0oO0O . altitude = self . altitude
  o0oO0O . radius = self . radius
  return ( o0oO0O )
  if 92 - 92: oO0o * Ii1I / OoO0O00 % II111iiii
  if 54 - 54: oO0o + I11i - OoO0O00
 def no_geo_altitude ( self ) :
  return ( self . altitude == - 1 )
  if 86 - 86: OoooooooOO
  if 51 - 51: i11iIiiIii
 def parse_geo_string ( self , geo_str ) :
  iI11I = geo_str . find ( "]" )
  if ( iI11I != - 1 ) : geo_str = geo_str [ iI11I + 1 : : ]
  if 91 - 91: OOooOOo
  if 22 - 22: OoooooooOO + OoOoOO00 - Ii1I . iII111i / OoooooooOO / I1IiiI
  if 73 - 73: i1IIi - Ii1I + oO0o * iIii1I11I1II1
  if 100 - 100: i11iIiiIii / iIii1I11I1II1 + Oo0Ooo + OoO0O00 - iII111i
  if 8 - 8: i11iIiiIii . O0 + o0oOOo0O0Ooo * oO0o + II111iiii
  if ( geo_str . find ( "/" ) != - 1 ) :
   geo_str , o00Oo0O = geo_str . split ( "/" )
   self . radius = int ( o00Oo0O )
   if 39 - 39: ooOoO0o / I1IiiI * o0oOOo0O0Ooo + o0oOOo0O0Ooo - Ii1I + OoOoOO00
   if 10 - 10: I1Ii111 . I11i / OoooooooOO . I11i . II111iiii
  geo_str = geo_str . split ( "-" )
  if ( len ( geo_str ) < 8 ) : return ( False )
  if 26 - 26: i11iIiiIii - oO0o % o0oOOo0O0Ooo . I11i
  o0oI1Ii111i1I = geo_str [ 0 : 4 ]
  iII11I = geo_str [ 4 : 8 ]
  if 19 - 19: i11iIiiIii . Oo0Ooo . OoOoOO00 - I1IiiI
  if 85 - 85: I11i - OoO0O00 % iIii1I11I1II1 . iII111i + ooOoO0o . Oo0Ooo
  if 87 - 87: iII111i
  if 86 - 86: IiII - I11i
  if ( len ( geo_str ) > 8 ) : self . altitude = int ( geo_str [ 8 ] )
  if 99 - 99: i1IIi + I1ii11iIi11i
  if 24 - 24: ooOoO0o / OoooooooOO % I1ii11iIi11i * ooOoO0o
  if 14 - 14: I1ii11iIi11i + OoO0O00 - I1IiiI - Oo0Ooo
  if 44 - 44: II111iiii / I1ii11iIi11i
  self . latitude = int ( o0oI1Ii111i1I [ 0 ] )
  self . lat_mins = int ( o0oI1Ii111i1I [ 1 ] )
  self . lat_secs = int ( o0oI1Ii111i1I [ 2 ] )
  if ( o0oI1Ii111i1I [ 3 ] == "N" ) : self . latitude = - self . latitude
  if 39 - 39: OoooooooOO % OoO0O00
  if 83 - 83: OOooOOo % I1IiiI + O0 % OoooooooOO
  if 84 - 84: I11i - Oo0Ooo % ooOoO0o - II111iiii
  if 29 - 29: IiII
  self . longitude = int ( iII11I [ 0 ] )
  self . long_mins = int ( iII11I [ 1 ] )
  self . long_secs = int ( iII11I [ 2 ] )
  if ( iII11I [ 3 ] == "E" ) : self . longitude = - self . longitude
  return ( True )
  if 4 - 4: II111iiii * o0oOOo0O0Ooo - IiII * iII111i
  if 91 - 91: I1Ii111 * iII111i * OoO0O00
 def print_geo ( self ) :
  o0Oo0O0 = "N" if self . latitude < 0 else "S"
  I1Iii1Ii = "E" if self . longitude < 0 else "W"
  if 7 - 7: ooOoO0o + iIii1I11I1II1
  iII1I1I11 = "{}-{}-{}-{}-{}-{}-{}-{}" . format ( abs ( self . latitude ) ,
 self . lat_mins , self . lat_secs , o0Oo0O0 , abs ( self . longitude ) ,
 self . long_mins , self . long_secs , I1Iii1Ii )
  if 63 - 63: II111iiii
  if ( self . no_geo_altitude ( ) == False ) :
   iII1I1I11 += "-" + str ( self . altitude )
   if 53 - 53: O0
   if 76 - 76: i1IIi . OOooOOo * iIii1I11I1II1 / I1ii11iIi11i % i11iIiiIii / O0
   if 83 - 83: oO0o % OoooooooOO
   if 36 - 36: IiII * OoOoOO00 - iIii1I11I1II1 + II111iiii
   if 65 - 65: I1IiiI * I11i . I1Ii111 % I1ii11iIi11i + O0
  if ( self . radius != 0 ) : iII1I1I11 += "/{}" . format ( self . radius )
  return ( iII1I1I11 )
  if 91 - 91: OoooooooOO % I1Ii111 * OoO0O00 - OoOoOO00
  if 5 - 5: iIii1I11I1II1 * I11i - oO0o % oO0o % o0oOOo0O0Ooo . i1IIi
 def geo_url ( self ) :
  OOOOO0OOoOOO = os . getenv ( "LISP_GEO_ZOOM_LEVEL" )
  OOOOO0OOoOOO = "10" if ( OOOOO0OOoOOO == "" or OOOOO0OOoOOO . isdigit ( ) == False ) else OOOOO0OOoOOO
  IIi1IIi1 , oO0000OOO0O = self . dms_to_decimal ( )
  o00Oo0o = ( "http://maps.googleapis.com/maps/api/staticmap?center={},{}" + "&markers=color:blue%7Clabel:lisp%7C{},{}" + "&zoom={}&size=1024x1024&sensor=false" ) . format ( IIi1IIi1 , oO0000OOO0O , IIi1IIi1 , oO0000OOO0O ,
  # iIii1I11I1II1 + i1IIi - iII111i + i1IIi / OoOoOO00
  # OOooOOo . OoooooooOO
 OOOOO0OOoOOO )
  return ( o00Oo0o )
  if 50 - 50: OoO0O00 % oO0o + I1Ii111 - II111iiii
  if 41 - 41: OoooooooOO % ooOoO0o * iIii1I11I1II1 * i11iIiiIii / I1IiiI
 def print_geo_url ( self ) :
  o0oO0O = self . print_geo ( )
  if ( self . radius == 0 ) :
   o00Oo0o = self . geo_url ( )
   OO0o0o0oo = "<a href='{}'>{}</a>" . format ( o00Oo0o , o0oO0O )
  else :
   o00Oo0o = o0oO0O . replace ( "/" , "-" )
   OO0o0o0oo = "<a href='/lisp/geo-map/{}'>{}</a>" . format ( o00Oo0o , o0oO0O )
   if 80 - 80: Ii1I - IiII - ooOoO0o * I1Ii111 % I1ii11iIi11i
  return ( OO0o0o0oo )
  if 82 - 82: iII111i % Ii1I + O0
  if 53 - 53: i11iIiiIii % I1ii11iIi11i
 def dms_to_decimal ( self ) :
  oO0OoOo0oo , O0OO0o0 , i1iIiIi = self . latitude , self . lat_mins , self . lat_secs
  i1iIi1I111i = float ( abs ( oO0OoOo0oo ) )
  i1iIi1I111i += float ( O0OO0o0 * 60 + i1iIiIi ) / 3600
  if ( oO0OoOo0oo > 0 ) : i1iIi1I111i = - i1iIi1I111i
  IIioO0Oo0OOoooO = i1iIi1I111i
  if 62 - 62: IiII . O0 + oO0o - ooOoO0o * iIii1I11I1II1
  oO0OoOo0oo , O0OO0o0 , i1iIiIi = self . longitude , self . long_mins , self . long_secs
  i1iIi1I111i = float ( abs ( oO0OoOo0oo ) )
  i1iIi1I111i += float ( O0OO0o0 * 60 + i1iIiIi ) / 3600
  if ( oO0OoOo0oo > 0 ) : i1iIi1I111i = - i1iIi1I111i
  iIii1I1I = i1iIi1I111i
  return ( ( IIioO0Oo0OOoooO , iIii1I1I ) )
  if 48 - 48: OoOoOO00 * I11i
  if 92 - 92: I1IiiI * I1IiiI
 def get_distance ( self , geo_point ) :
  I11III1iIIIi1 = self . dms_to_decimal ( )
  iiIiIi = geo_point . dms_to_decimal ( )
  i1i1iIII1II = vincenty ( I11III1iIIIi1 , iiIiIi )
  return ( i1i1iIII1II . km )
  if 85 - 85: OoOoOO00 % iII111i - O0 / Ii1I
  if 15 - 15: I1Ii111 / I1ii11iIi11i / I1IiiI % i11iIiiIii + II111iiii . ooOoO0o
 def point_in_circle ( self , geo_point ) :
  oo00OOo0 = self . get_distance ( geo_point )
  return ( oo00OOo0 <= self . radius )
  if 37 - 37: I1Ii111 / i11iIiiIii . I1ii11iIi11i - OoO0O00 * ooOoO0o
  if 91 - 91: ooOoO0o % II111iiii
 def encode_geo ( self ) :
  O0OOOOO0O = socket . htons ( LISP_AFI_LCAF )
  oo0oOoO0OoOOOo0O = socket . htons ( 20 + 2 )
  Ooooo0OO = 0
  if 48 - 48: oO0o
  IIi1IIi1 = abs ( self . latitude )
  II1iIiI1i = ( ( self . lat_mins * 60 ) + self . lat_secs ) * 1000
  if ( self . latitude < 0 ) : Ooooo0OO |= 0x40
  if 25 - 25: I1IiiI + iIii1I11I1II1 * Oo0Ooo - iIii1I11I1II1 % IiII * oO0o
  oO0000OOO0O = abs ( self . longitude )
  Oo00o0O00o = ( ( self . long_mins * 60 ) + self . long_secs ) * 1000
  if ( self . longitude < 0 ) : Ooooo0OO |= 0x20
  if 22 - 22: OoooooooOO - OoO0O00 + OoOoOO00 - OOooOOo + i11iIiiIii - oO0o
  i1ii1ii1I = 0
  if ( self . no_geo_altitude ( ) == False ) :
   i1ii1ii1I = socket . htonl ( self . altitude )
   Ooooo0OO |= 0x10
   if 9 - 9: OoooooooOO + IiII % I11i
  o00Oo0O = socket . htons ( self . radius )
  if ( o00Oo0O != 0 ) : Ooooo0OO |= 0x06
  if 72 - 72: oO0o % I11i % OOooOOo * iIii1I11I1II1 - OOooOOo % O0
  OOoOooO0 = struct . pack ( "HBBBBH" , O0OOOOO0O , 0 , 0 , LISP_LCAF_GEO_COORD_TYPE ,
 0 , oo0oOoO0OoOOOo0O )
  OOoOooO0 += struct . pack ( "BBHBBHBBHIHHH" , Ooooo0OO , 0 , 0 , IIi1IIi1 , II1iIiI1i >> 16 ,
 socket . htons ( II1iIiI1i & 0x0ffff ) , oO0000OOO0O , Oo00o0O00o >> 16 ,
 socket . htons ( Oo00o0O00o & 0xffff ) , i1ii1ii1I , o00Oo0O , 0 , 0 )
  if 10 - 10: OoOoOO00 . i1IIi
  return ( OOoOooO0 )
  if 44 - 44: OOooOOo - OOooOOo * IiII - iIii1I11I1II1
  if 72 - 72: iIii1I11I1II1 . OoooooooOO
 def decode_geo ( self , packet , lcaf_len , radius_hi ) :
  oOoOo000 = "BBHBBHBBHIHHH"
  O0OOoooO = struct . calcsize ( oOoOo000 )
  if ( lcaf_len < O0OOoooO ) : return ( None )
  if 44 - 44: I11i * I11i + OoooooooOO
  Ooooo0OO , i111IIIiI1Iii , i1i1iIiii , IIi1IIi1 , ii1i1I11 , II1iIiI1i , oO0000OOO0O , O0ooOoo , Oo00o0O00o , i1ii1ii1I , o00Oo0O , II1iIii , iioOO = struct . unpack ( oOoOo000 ,
  # OoO0O00 % iIii1I11I1II1
 packet [ : O0OOoooO ] )
  if 62 - 62: OoooooooOO * o0oOOo0O0Ooo
  if 59 - 59: iIii1I11I1II1
  if 18 - 18: ooOoO0o % I1IiiI / iIii1I11I1II1 + O0
  if 99 - 99: i11iIiiIii - o0oOOo0O0Ooo + o0oOOo0O0Ooo . OoooooooOO * iII111i . Oo0Ooo
  iioOO = socket . ntohs ( iioOO )
  if ( iioOO == LISP_AFI_LCAF ) : return ( None )
  if 63 - 63: I11i
  if ( Ooooo0OO & 0x40 ) : IIi1IIi1 = - IIi1IIi1
  self . latitude = IIi1IIi1
  OOoO = ( ( ii1i1I11 << 16 ) | socket . ntohs ( II1iIiI1i ) ) / 1000
  self . lat_mins = OOoO / 60
  self . lat_secs = OOoO % 60
  if 22 - 22: Ii1I + iII111i . OoooooooOO - i11iIiiIii . OOooOOo
  if ( Ooooo0OO & 0x20 ) : oO0000OOO0O = - oO0000OOO0O
  self . longitude = oO0000OOO0O
  i111I111 = ( ( O0ooOoo << 16 ) | socket . ntohs ( Oo00o0O00o ) ) / 1000
  self . long_mins = i111I111 / 60
  self . long_secs = i111I111 % 60
  if 25 - 25: I11i % i1IIi / i11iIiiIii + OoooooooOO / i11iIiiIii
  self . altitude = socket . ntohl ( i1ii1ii1I ) if ( Ooooo0OO & 0x10 ) else - 1
  o00Oo0O = socket . ntohs ( o00Oo0O )
  self . radius = o00Oo0O if ( Ooooo0OO & 0x02 ) else o00Oo0O * 1000
  if 1 - 1: i11iIiiIii + Ii1I / iIii1I11I1II1 . I1IiiI
  self . geo_name = None
  packet = packet [ O0OOoooO : : ]
  if 90 - 90: Oo0Ooo . IiII - I1ii11iIi11i - iII111i
  if ( iioOO != 0 ) :
   self . rloc . afi = iioOO
   packet = self . rloc . unpack_address ( packet )
   self . rloc . mask_len = self . rloc . host_mask_len ( )
   if 17 - 17: iIii1I11I1II1 - Ii1I + IiII . Oo0Ooo + i11iIiiIii
  return ( packet )
  if 97 - 97: ooOoO0o % II111iiii / Ii1I . iIii1I11I1II1
  if 100 - 100: II111iiii / I11i * iIii1I11I1II1 / OOooOOo + i11iIiiIii - iIii1I11I1II1
  if 32 - 32: o0oOOo0O0Ooo - Ii1I / ooOoO0o % I1Ii111
  if 69 - 69: oO0o - I1IiiI . OOooOOo * OoooooooOO
  if 83 - 83: IiII % I1Ii111 % IiII - O0 % I1ii11iIi11i
  if 44 - 44: i11iIiiIii + oO0o * oO0o . i11iIiiIii % i1IIi + iII111i
class lisp_rle_node ( ) :
 def __init__ ( self ) :
  self . address = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . level = 0
  self . translated_port = 0
  self . rloc_name = None
  if 91 - 91: I1Ii111 . II111iiii / Ii1I * O0
  if 33 - 33: oO0o * i1IIi + ooOoO0o * OOooOOo - O0 - iIii1I11I1II1
 def copy_rle_node ( self ) :
  IIi1i1111i = lisp_rle_node ( )
  IIi1i1111i . address . copy_address ( self . address )
  IIi1i1111i . level = self . level
  IIi1i1111i . translated_port = self . translated_port
  IIi1i1111i . rloc_name = self . rloc_name
  return ( IIi1i1111i )
  if 35 - 35: I1Ii111
  if 12 - 12: Ii1I % I1IiiI - I11i / iIii1I11I1II1 . I1IiiI % I1ii11iIi11i
 def store_translated_rloc ( self , rloc , port ) :
  self . address . copy_address ( rloc )
  self . translated_port = port
  if 12 - 12: Oo0Ooo + I1IiiI
  if 12 - 12: OoOoOO00 / II111iiii
 def get_encap_keys ( self ) :
  IIiII = "4341" if self . translated_port == 0 else str ( self . translated_port )
  if 100 - 100: I1ii11iIi11i % iIii1I11I1II1 . IiII . OoooooooOO / II111iiii
  I1iiIiiii1111 = self . address . print_address_no_iid ( ) + ":" + IIiII
  if 28 - 28: I1IiiI
  try :
   o00OO0o0 = lisp_crypto_keys_by_rloc_encap [ I1iiIiiii1111 ]
   if ( o00OO0o0 [ 1 ] ) : return ( o00OO0o0 [ 1 ] . encrypt_key , o00OO0o0 [ 1 ] . icv_key )
   return ( None , None )
  except :
   return ( None , None )
   if 27 - 27: I1IiiI % oO0o - iIii1I11I1II1 - o0oOOo0O0Ooo - IiII - O0
   if 46 - 46: II111iiii
   if 24 - 24: i11iIiiIii * i1IIi - I11i + o0oOOo0O0Ooo
   if 60 - 60: ooOoO0o
class lisp_rle ( ) :
 def __init__ ( self , name ) :
  self . rle_name = name
  self . rle_nodes = [ ]
  self . rle_forwarding_list = [ ]
  if 62 - 62: i11iIiiIii
  if 88 - 88: i11iIiiIii
 def copy_rle ( self ) :
  iiiI1i1111II = lisp_rle ( self . rle_name )
  for IIi1i1111i in self . rle_nodes :
   iiiI1i1111II . rle_nodes . append ( IIi1i1111i . copy_rle_node ( ) )
   if 59 - 59: oO0o - OoooooooOO % ooOoO0o
  iiiI1i1111II . build_forwarding_list ( )
  return ( iiiI1i1111II )
  if 90 - 90: OoOoOO00
  if 96 - 96: II111iiii % Ii1I
 def print_rle ( self , html ) :
  Oo0OooO00O = ""
  for IIi1i1111i in self . rle_nodes :
   IIiII = IIi1i1111i . translated_port
   oOIIIiiIiI = blue ( IIi1i1111i . rloc_name , html ) if IIi1i1111i . rloc_name != None else ""
   if 45 - 45: iII111i . oO0o * iII111i
   I1iiIiiii1111 = IIi1i1111i . address . print_address_no_iid ( )
   if ( IIi1i1111i . address . is_local ( ) ) : I1iiIiiii1111 = red ( I1iiIiiii1111 , html )
   Oo0OooO00O += "{}{}(L{}){}, " . format ( I1iiIiiii1111 , "" if IIiII == 0 else "-" + str ( IIiII ) , IIi1i1111i . level ,
   # Oo0Ooo
 "" if IIi1i1111i . rloc_name == None else oOIIIiiIiI )
   if 22 - 22: Oo0Ooo - o0oOOo0O0Ooo + I1ii11iIi11i
  return ( Oo0OooO00O [ 0 : - 2 ] if Oo0OooO00O != "" else "" )
  if 9 - 9: OoO0O00 * I1IiiI % IiII
  if 97 - 97: o0oOOo0O0Ooo + Ii1I
 def build_forwarding_list ( self ) :
  oo0O = - 1
  for IIi1i1111i in self . rle_nodes :
   if ( oo0O == - 1 ) :
    if ( IIi1i1111i . address . is_local ( ) ) : oo0O = IIi1i1111i . level
   else :
    if ( IIi1i1111i . level > oo0O ) : break
    if 77 - 77: I11i - oO0o . Ii1I
    if 75 - 75: I11i * OoooooooOO % OoOoOO00 . i1IIi - Ii1I + iIii1I11I1II1
  oo0O = 0 if oo0O == - 1 else IIi1i1111i . level
  if 74 - 74: ooOoO0o
  self . rle_forwarding_list = [ ]
  for IIi1i1111i in self . rle_nodes :
   if ( IIi1i1111i . level == oo0O or ( oo0O == 0 and
 IIi1i1111i . level == 128 ) ) :
    if ( lisp_i_am_rtr == False and IIi1i1111i . address . is_local ( ) ) :
     I1iiIiiii1111 = IIi1i1111i . address . print_address_no_iid ( )
     lprint ( "Exclude local RLE RLOC {}" . format ( I1iiIiiii1111 ) )
     continue
     if 18 - 18: iIii1I11I1II1 - I11i - oO0o
    self . rle_forwarding_list . append ( IIi1i1111i )
    if 12 - 12: O0 + O0 + ooOoO0o . I1IiiI * II111iiii
    if 47 - 47: i11iIiiIii % OOooOOo / ooOoO0o . IiII - I1IiiI
    if 10 - 10: Oo0Ooo / ooOoO0o / I1ii11iIi11i
    if 98 - 98: O0 - I1Ii111 - i11iIiiIii
    if 85 - 85: II111iiii - I1ii11iIi11i % I1IiiI . I1IiiI - OoooooooOO - I11i
class lisp_json ( ) :
 def __init__ ( self , name , string ) :
  self . json_name = name
  self . json_string = string
  if 38 - 38: i1IIi + oO0o * ooOoO0o % Ii1I % ooOoO0o
  if 80 - 80: OoO0O00 + OoOoOO00 % iII111i % OoooooooOO - ooOoO0o
 def add ( self ) :
  self . delete ( )
  lisp_json_list [ self . json_name ] = self
  if 25 - 25: OoOoOO00 % i11iIiiIii - I1IiiI * iIii1I11I1II1 - Oo0Ooo . O0
  if 48 - 48: I1IiiI + oO0o % i11iIiiIii % iIii1I11I1II1
 def delete ( self ) :
  if ( lisp_json_list . has_key ( self . json_name ) ) :
   del ( lisp_json_list [ self . json_name ] )
   lisp_json_list [ self . json_name ] = None
   if 14 - 14: iIii1I11I1II1
   if 78 - 78: I1Ii111 / Oo0Ooo - I1Ii111
   if 1 - 1: OoO0O00 - I1IiiI * o0oOOo0O0Ooo
 def print_json ( self , html ) :
  oOoOooO0o00 = self . json_string
  IIIIIiiIII = "***"
  if ( html ) : IIIIIiiIII = red ( IIIIIiiIII , html )
  o0oO = IIIIIiiIII + self . json_string + IIIIIiiIII
  if ( self . valid_json ( ) ) : return ( oOoOooO0o00 )
  return ( o0oO )
  if 6 - 6: IiII
  if 69 - 69: iII111i
 def valid_json ( self ) :
  try :
   json . loads ( self . json_string )
  except :
   return ( False )
   if 87 - 87: i11iIiiIii % o0oOOo0O0Ooo + Ii1I
  return ( True )
  if 72 - 72: Ii1I / II111iiii + o0oOOo0O0Ooo
  if 33 - 33: I1Ii111 * OoOoOO00 - OoooooooOO
  if 11 - 11: I1Ii111 - Oo0Ooo / iIii1I11I1II1 - OoooooooOO
  if 71 - 71: Oo0Ooo + Ii1I - OoooooooOO + I11i - iIii1I11I1II1 / O0
  if 76 - 76: i11iIiiIii % o0oOOo0O0Ooo . O0 * I11i
  if 90 - 90: II111iiii + OOooOOo % I1Ii111 * iIii1I11I1II1 % iIii1I11I1II1
class lisp_stats ( ) :
 def __init__ ( self ) :
  self . packet_count = 0
  self . byte_count = 0
  self . last_rate_check = 0
  self . last_packet_count = 0
  self . last_byte_count = 0
  self . last_increment = None
  if 55 - 55: II111iiii % O0 * O0 - II111iiii * I1IiiI % Oo0Ooo
  if 48 - 48: I1ii11iIi11i + OoooooooOO % i1IIi
 def increment ( self , octets ) :
  self . packet_count += 1
  self . byte_count += octets
  self . last_increment = lisp_get_timestamp ( )
  if 46 - 46: OoOoOO00
  if 75 - 75: I1IiiI
 def recent_packet_sec ( self ) :
  if ( self . last_increment == None ) : return ( False )
  i11IiIIi11I = time . time ( ) - self . last_increment
  return ( i11IiIIi11I <= 1 )
  if 37 - 37: iIii1I11I1II1 % OoO0O00 * ooOoO0o + I11i % ooOoO0o / i11iIiiIii
  if 14 - 14: i1IIi / ooOoO0o
 def recent_packet_min ( self ) :
  if ( self . last_increment == None ) : return ( False )
  i11IiIIi11I = time . time ( ) - self . last_increment
  return ( i11IiIIi11I <= 60 )
  if 10 - 10: ooOoO0o / OoooooooOO - ooOoO0o % O0 + oO0o - oO0o
  if 16 - 16: O0
 def stat_colors ( self , c1 , c2 , html ) :
  if ( self . recent_packet_sec ( ) ) :
   return ( green_last_sec ( c1 ) , green_last_sec ( c2 ) )
   if 14 - 14: Ii1I . Ii1I . OOooOOo - O0 / OoO0O00 % II111iiii
  if ( self . recent_packet_min ( ) ) :
   return ( green_last_min ( c1 ) , green_last_min ( c2 ) )
   if 5 - 5: iIii1I11I1II1 % OoOoOO00 % OOooOOo % O0 * oO0o . iIii1I11I1II1
  return ( c1 , c2 )
  if 96 - 96: i11iIiiIii + oO0o / I1ii11iIi11i . IiII % o0oOOo0O0Ooo
  if 41 - 41: o0oOOo0O0Ooo . i1IIi - OOooOOo
 def normalize ( self , count ) :
  count = str ( count )
  iI111iIiiI = len ( count )
  if ( iI111iIiiI > 12 ) :
   count = count [ 0 : - 10 ] + "." + count [ - 10 : - 7 ] + "T"
   return ( count )
   if 55 - 55: ooOoO0o + I11i - OoOoOO00 + I1IiiI % Oo0Ooo / I1ii11iIi11i
  if ( iI111iIiiI > 9 ) :
   count = count [ 0 : - 9 ] + "." + count [ - 9 : - 7 ] + "B"
   return ( count )
   if 17 - 17: i1IIi / IiII . I1IiiI % i1IIi
  if ( iI111iIiiI > 6 ) :
   count = count [ 0 : - 6 ] + "." + count [ - 6 ] + "M"
   return ( count )
   if 46 - 46: IiII % O0 . o0oOOo0O0Ooo . OOooOOo
  return ( count )
  if 47 - 47: OoooooooOO . oO0o . II111iiii / II111iiii - OoOoOO00
  if 81 - 81: o0oOOo0O0Ooo - Oo0Ooo % IiII - ooOoO0o / O0
 def get_stats ( self , summary , html ) :
  ii1ii1 = self . last_rate_check
  iiiII1Ii1iI = self . last_packet_count
  iIiIIiii111I1 = self . last_byte_count
  self . last_rate_check = lisp_get_timestamp ( )
  self . last_packet_count = self . packet_count
  self . last_byte_count = self . byte_count
  if 22 - 22: OoOoOO00 * IiII . i1IIi - Oo0Ooo + OoOoOO00 . ooOoO0o
  OoOO0Oo0Oo0 = self . last_rate_check - ii1ii1
  if ( OoOO0Oo0Oo0 == 0 ) :
   IIIiI = 0
   iIIi1I1 = 0
  else :
   IIIiI = int ( ( self . packet_count - iiiII1Ii1iI ) / OoOO0Oo0Oo0 )
   iIIi1I1 = ( self . byte_count - iIiIIiii111I1 ) / OoOO0Oo0Oo0
   iIIi1I1 = ( iIIi1I1 * 8 ) / 1000000
   iIIi1I1 = round ( iIIi1I1 , 2 )
   if 64 - 64: OoOoOO00
   if 94 - 94: OOooOOo * OoooooooOO * o0oOOo0O0Ooo / I1Ii111 . II111iiii
   if 37 - 37: O0 * II111iiii * I1IiiI - O0 - I11i / i1IIi
   if 27 - 27: i11iIiiIii + iIii1I11I1II1
   if 15 - 15: oO0o
  Oooo000oOO0oO = self . normalize ( self . packet_count )
  Ii1OO0Oo00OO0o = self . normalize ( self . byte_count )
  if 17 - 17: O0 + OOooOOo * ooOoO0o - i1IIi + OOooOOo
  if 30 - 30: OOooOOo / I1ii11iIi11i - iIii1I11I1II1 % i1IIi
  if 34 - 34: I1IiiI . II111iiii
  if 100 - 100: OoO0O00 / O0 / OoOoOO00
  if 33 - 33: i1IIi / o0oOOo0O0Ooo . OoooooooOO
  if ( summary ) :
   Ii11i1Iiii11 = "<br>" if html else ""
   Oooo000oOO0oO , Ii1OO0Oo00OO0o = self . stat_colors ( Oooo000oOO0oO , Ii1OO0Oo00OO0o , html )
   OOo0oo0O0o0 = "packet-count: {}{}byte-count: {}" . format ( Oooo000oOO0oO , Ii11i1Iiii11 , Ii1OO0Oo00OO0o )
   I1iIii1Ii = "packet-rate: {} pps\nbit-rate: {} Mbps" . format ( IIIiI , iIIi1I1 )
   if 82 - 82: OoooooooOO . o0oOOo0O0Ooo * I1ii11iIi11i % I1ii11iIi11i * Ii1I
   if ( html != "" ) : I1iIii1Ii = lisp_span ( OOo0oo0O0o0 , I1iIii1Ii )
  else :
   O0OOOooO = str ( IIIiI )
   IiI11iii1ii1 = str ( iIIi1I1 )
   if ( html ) :
    Oooo000oOO0oO = lisp_print_cour ( Oooo000oOO0oO )
    O0OOOooO = lisp_print_cour ( O0OOOooO )
    Ii1OO0Oo00OO0o = lisp_print_cour ( Ii1OO0Oo00OO0o )
    IiI11iii1ii1 = lisp_print_cour ( IiI11iii1ii1 )
    if 10 - 10: i1IIi * OoOoOO00 + I1Ii111 . IiII % i11iIiiIii
   Ii11i1Iiii11 = "<br>" if html else ", "
   if 98 - 98: I1IiiI - oO0o / i11iIiiIii % I1ii11iIi11i * oO0o * OoO0O00
   I1iIii1Ii = ( "packet-count: {}{}packet-rate: {} pps{}byte-count: " + "{}{}bit-rate: {} mbps" ) . format ( Oooo000oOO0oO , Ii11i1Iiii11 , O0OOOooO , Ii11i1Iiii11 , Ii1OO0Oo00OO0o , Ii11i1Iiii11 ,
   # O0 - o0oOOo0O0Ooo * I1Ii111 - i11iIiiIii % Oo0Ooo
 IiI11iii1ii1 )
   if 27 - 27: Ii1I / oO0o - Ii1I / iIii1I11I1II1 + o0oOOo0O0Ooo . Ii1I
  return ( I1iIii1Ii )
  if 79 - 79: Ii1I % O0 * OOooOOo
  if 41 - 41: I1ii11iIi11i . OoooooooOO * I1ii11iIi11i - oO0o
  if 40 - 40: I1IiiI % OoO0O00 + i11iIiiIii / oO0o
  if 98 - 98: oO0o + iIii1I11I1II1 . ooOoO0o / I1ii11iIi11i
  if 77 - 77: OoOoOO00 / Oo0Ooo * OoOoOO00 % I1IiiI . II111iiii % OoO0O00
  if 38 - 38: iII111i - OoO0O00 / i1IIi + ooOoO0o . ooOoO0o . iII111i
  if 37 - 37: iIii1I11I1II1 * OoOoOO00 . OoOoOO00 + OoooooooOO + OoO0O00
  if 25 - 25: I1IiiI / IiII . OOooOOo . I1ii11iIi11i % i1IIi
lisp_decap_stats = {
 "good-packets" : lisp_stats ( ) , "ICV-error" : lisp_stats ( ) ,
 "checksum-error" : lisp_stats ( ) , "lisp-header-error" : lisp_stats ( ) ,
 "no-decrypt-key" : lisp_stats ( ) , "bad-inner-version" : lisp_stats ( ) ,
 "outer-header-error" : lisp_stats ( )
 }
if 12 - 12: O0 % O0
if 9 - 9: O0 . I1IiiI + I1ii11iIi11i / OOooOOo * I1ii11iIi11i
if 10 - 10: IiII % o0oOOo0O0Ooo / O0 / II111iiii
if 81 - 81: Ii1I / o0oOOo0O0Ooo % OoOoOO00 . I1ii11iIi11i
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
  if 47 - 47: II111iiii + OOooOOo / II111iiii . OOooOOo
  if ( recurse == False ) : return
  if 68 - 68: OoooooooOO
  if 63 - 63: I1IiiI
  if 80 - 80: oO0o + iIii1I11I1II1
  if 87 - 87: I1ii11iIi11i % Ii1I . Ii1I
  if 71 - 71: OoO0O00 - IiII . i1IIi * I1IiiI % I11i
  if 36 - 36: IiII * OoooooooOO . i11iIiiIii * i1IIi
  O0O0Oo = lisp_get_default_route_next_hops ( )
  if ( O0O0Oo == [ ] or len ( O0O0Oo ) == 1 ) : return
  if 94 - 94: o0oOOo0O0Ooo
  self . rloc_next_hop = O0O0Oo [ 0 ]
  oo = self
  for i11i1i in O0O0Oo [ 1 : : ] :
   OOoooO0Oo0o = lisp_rloc ( False )
   OOoooO0Oo0o = copy . deepcopy ( self )
   OOoooO0Oo0o . rloc_next_hop = i11i1i
   oo . next_rloc = OOoooO0Oo0o
   oo = OOoooO0Oo0o
   if 76 - 76: o0oOOo0O0Ooo
   if 80 - 80: OOooOOo
   if 15 - 15: OOooOOo . OoOoOO00 / oO0o . I1ii11iIi11i % OoO0O00 - oO0o
 def up_state ( self ) :
  return ( self . state == LISP_RLOC_UP_STATE )
  if 21 - 21: ooOoO0o . o0oOOo0O0Ooo . oO0o . i1IIi
  if 96 - 96: Ii1I % I11i * OoooooooOO . I1IiiI . iIii1I11I1II1
 def unreach_state ( self ) :
  return ( self . state == LISP_RLOC_UNREACH_STATE )
  if 8 - 8: O0 + o0oOOo0O0Ooo / O0 - I1ii11iIi11i % I1ii11iIi11i
  if 55 - 55: OoooooooOO * OoooooooOO % I1Ii111 / Ii1I / ooOoO0o
 def no_echoed_nonce_state ( self ) :
  return ( self . state == LISP_RLOC_NO_ECHOED_NONCE_STATE )
  if 12 - 12: i11iIiiIii + Ii1I % iIii1I11I1II1 + I1Ii111
  if 12 - 12: Ii1I + I1Ii111 / O0 * II111iiii
 def down_state ( self ) :
  return ( self . state in [ LISP_RLOC_DOWN_STATE , LISP_RLOC_ADMIN_DOWN_STATE ] )
  if 67 - 67: iIii1I11I1II1 / I11i + ooOoO0o * I1Ii111 * oO0o
  if 100 - 100: OoooooooOO % I1IiiI / OoOoOO00 % OoOoOO00 . o0oOOo0O0Ooo
  if 81 - 81: Ii1I - II111iiii + I11i / Ii1I
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
  if 89 - 89: i11iIiiIii + I1ii11iIi11i - ooOoO0o . ooOoO0o + Oo0Ooo % Ii1I
  if 96 - 96: I1Ii111 - I11i * I1Ii111
 def print_rloc ( self , indent ) :
  OOOO0O00o = lisp_print_elapsed ( self . uptime )
  lprint ( "{}rloc {}, uptime {}, {}, parms {}/{}/{}/{}" . format ( indent ,
 red ( self . rloc . print_address ( ) , False ) , OOOO0O00o , self . print_state ( ) ,
 self . priority , self . weight , self . mpriority , self . mweight ) )
  if 32 - 32: I1IiiI / i1IIi / I1ii11iIi11i % i1IIi . ooOoO0o % I1ii11iIi11i
  if 97 - 97: OoO0O00 . OOooOOo % Ii1I + OoooooooOO * I1Ii111
 def print_rloc_name ( self , cour = False ) :
  if ( self . rloc_name == None ) : return ( "" )
  OO000 = self . rloc_name
  if ( cour ) : OO000 = lisp_print_cour ( OO000 )
  return ( 'rloc-name: {}' . format ( blue ( OO000 , cour ) ) )
  if 89 - 89: I11i
  if 91 - 91: OoooooooOO - IiII - Ii1I
 def store_rloc_from_record ( self , rloc_record , nonce , source ) :
  IIiII = LISP_DATA_PORT
  self . rloc . copy_address ( rloc_record . rloc )
  self . rloc_name = rloc_record . rloc_name
  if 36 - 36: OOooOOo
  if 76 - 76: OoO0O00 . i1IIi
  if 98 - 98: O0
  if 86 - 86: O0 * oO0o + Oo0Ooo / II111iiii + i1IIi
  OoOOo = self . rloc
  if ( OoOOo . is_null ( ) == False ) :
   Iii111I = lisp_get_nat_info ( OoOOo , self . rloc_name )
   if ( Iii111I ) :
    IIiII = Iii111I . port
    I1II11Ii111Ii = lisp_nat_state_info [ self . rloc_name ] [ 0 ]
    I1iiIiiii1111 = OoOOo . print_address_no_iid ( )
    ooOo = red ( I1iiIiiii1111 , False )
    Oooo0O0000o0O = "" if self . rloc_name == None else blue ( self . rloc_name , False )
    if 20 - 20: I1Ii111 / OoooooooOO * i1IIi + i1IIi % I11i
    if 11 - 11: Ii1I - Ii1I . o0oOOo0O0Ooo - I1Ii111 * Ii1I - o0oOOo0O0Ooo
    if 71 - 71: OoOoOO00 * OoooooooOO . IiII - OoOoOO00
    if 4 - 4: i1IIi * OOooOOo % Oo0Ooo * IiII
    if 10 - 10: OoooooooOO
    if 28 - 28: OoO0O00 + i11iIiiIii / i1IIi
    if ( Iii111I . timed_out ( ) ) :
     lprint ( ( "    Matched stored NAT state timed out for " + "RLOC {}:{}, {}" ) . format ( ooOo , IIiII , Oooo0O0000o0O ) )
     if 7 - 7: I1ii11iIi11i . Oo0Ooo / i11iIiiIii
     if 65 - 65: I11i * iII111i * II111iiii / o0oOOo0O0Ooo . O0
     Iii111I = None if ( Iii111I == I1II11Ii111Ii ) else I1II11Ii111Ii
     if ( Iii111I and Iii111I . timed_out ( ) ) :
      IIiII = Iii111I . port
      ooOo = red ( Iii111I . address , False )
      lprint ( ( "    Youngest stored NAT state timed out " + " for RLOC {}:{}, {}" ) . format ( ooOo , IIiII ,
      # II111iiii
 Oooo0O0000o0O ) )
      Iii111I = None
      if 17 - 17: I1IiiI / i11iIiiIii + o0oOOo0O0Ooo . OoOoOO00 . I1IiiI
      if 31 - 31: OoooooooOO . I1Ii111 % OoooooooOO * iII111i % OOooOOo . iII111i
      if 17 - 17: I1Ii111 % i1IIi % I11i * O0 / Oo0Ooo
      if 96 - 96: OoOoOO00 . Ii1I
      if 80 - 80: OoOoOO00 + o0oOOo0O0Ooo - II111iiii
      if 3 - 3: ooOoO0o * I1Ii111
      if 34 - 34: Ii1I / Oo0Ooo . II111iiii - ooOoO0o - I1ii11iIi11i % OoOoOO00
    if ( Iii111I ) :
     if ( Iii111I . address != I1iiIiiii1111 ) :
      lprint ( "RLOC conflict, RLOC-record {}, NAT state {}" . format ( ooOo , red ( Iii111I . address , False ) ) )
      if 43 - 43: Ii1I * oO0o
      self . rloc . store_address ( Iii111I . address )
      if 57 - 57: OoooooooOO + I1IiiI % I1ii11iIi11i % ooOoO0o * I1Ii111
     ooOo = red ( Iii111I . address , False )
     IIiII = Iii111I . port
     lprint ( "    Use NAT translated RLOC {}:{} for {}" . format ( ooOo , IIiII , Oooo0O0000o0O ) )
     if 9 - 9: i11iIiiIii
     self . store_translated_rloc ( OoOOo , IIiII )
     if 85 - 85: IiII / o0oOOo0O0Ooo * ooOoO0o
     if 74 - 74: O0 - o0oOOo0O0Ooo
     if 68 - 68: I1Ii111
     if 19 - 19: o0oOOo0O0Ooo
  self . geo = rloc_record . geo
  self . elp = rloc_record . elp
  self . json = rloc_record . json
  if 63 - 63: OoooooooOO % ooOoO0o
  if 26 - 26: OOooOOo + Oo0Ooo
  if 97 - 97: I1Ii111 * I1Ii111 + iII111i % Ii1I / iII111i
  if 73 - 73: OoOoOO00 % I1Ii111 . I1ii11iIi11i
  self . rle = rloc_record . rle
  if ( self . rle ) :
   for IIi1i1111i in self . rle . rle_nodes :
    OO000 = IIi1i1111i . rloc_name
    Iii111I = lisp_get_nat_info ( IIi1i1111i . address , OO000 )
    if ( Iii111I == None ) : continue
    if 45 - 45: iIii1I11I1II1 % Ii1I . OoOoOO00 . o0oOOo0O0Ooo - OoooooooOO
    IIiII = Iii111I . port
    iI11Ii = OO000
    if ( iI11Ii ) : iI11Ii = blue ( OO000 , False )
    if 46 - 46: I1ii11iIi11i
    lprint ( ( "      Store translated encap-port {} for RLE-" + "node {}, rloc-name '{}'" ) . format ( IIiII ,
    # IiII % iII111i
 IIi1i1111i . address . print_address_no_iid ( ) , iI11Ii ) )
    IIi1i1111i . translated_port = IIiII
    if 21 - 21: OoOoOO00
    if 86 - 86: O0 . O0 - I1Ii111
    if 95 - 95: Ii1I / Ii1I * OoO0O00 . OoooooooOO . OoooooooOO * I11i
  self . priority = rloc_record . priority
  self . mpriority = rloc_record . mpriority
  self . weight = rloc_record . weight
  self . mweight = rloc_record . mweight
  if ( rloc_record . reach_bit and rloc_record . local_bit and
 rloc_record . probe_bit == False ) : self . state = LISP_RLOC_UP_STATE
  if 76 - 76: OoooooooOO - Ii1I + IiII % OoOoOO00 / OoooooooOO
  if 55 - 55: i11iIiiIii - IiII * OOooOOo + II111iiii . I1ii11iIi11i / O0
  if 16 - 16: II111iiii . Oo0Ooo * I1Ii111 + o0oOOo0O0Ooo - i11iIiiIii
  if 98 - 98: II111iiii - i1IIi - ooOoO0o
  i1I1Ii = source . is_exact_match ( rloc_record . rloc ) if source != None else None
  if 66 - 66: OoOoOO00 % ooOoO0o - II111iiii . oO0o / i11iIiiIii
  if ( rloc_record . keys != None and i1I1Ii ) :
   iii11 = rloc_record . keys [ 1 ]
   if ( iii11 != None ) :
    I1iiIiiii1111 = rloc_record . rloc . print_address_no_iid ( ) + ":" + str ( IIiII )
    if 73 - 73: OoO0O00 - i1IIi
    iii11 . add_key_by_rloc ( I1iiIiiii1111 , True )
    lprint ( "    Store encap-keys for nonce 0x{}, RLOC {}" . format ( lisp_hex_string ( nonce ) , red ( I1iiIiiii1111 , False ) ) )
    if 52 - 52: I1ii11iIi11i
    if 4 - 4: Ii1I - iII111i + i1IIi - I1Ii111 / iII111i . Oo0Ooo
    if 18 - 18: oO0o % iIii1I11I1II1 + ooOoO0o
  return ( IIiII )
  if 34 - 34: I1IiiI - OoooooooOO . IiII - OOooOOo % IiII
  if 19 - 19: IiII + I1ii11iIi11i % Oo0Ooo
 def store_translated_rloc ( self , rloc , port ) :
  self . rloc . copy_address ( rloc )
  self . translated_rloc . copy_address ( rloc )
  self . translated_port = port
  if 32 - 32: OOooOOo
  if 46 - 46: II111iiii . OoO0O00
 def is_rloc_translated ( self ) :
  return ( self . translated_rloc . is_null ( ) == False )
  if 97 - 97: oO0o
  if 45 - 45: i11iIiiIii / IiII + OoO0O00
 def rloc_exists ( self ) :
  if ( self . rloc . is_null ( ) == False ) : return ( True )
  if ( self . rle_name or self . geo_name or self . elp_name or self . json_name ) :
   return ( False )
   if 55 - 55: Ii1I / II111iiii - oO0o
  return ( True )
  if 58 - 58: i1IIi . OoooooooOO % iIii1I11I1II1 * o0oOOo0O0Ooo + O0 / oO0o
  if 77 - 77: I11i . I1ii11iIi11i
 def is_rtr ( self ) :
  return ( ( self . priority == 254 and self . mpriority == 255 and self . weight == 0 and self . mweight == 0 ) )
  if 92 - 92: i11iIiiIii + I11i % I1IiiI / ooOoO0o
  if 28 - 28: i1IIi . I1IiiI
  if 41 - 41: I1ii11iIi11i . I1Ii111 * OoOoOO00 . I1Ii111 / o0oOOo0O0Ooo
 def print_state_change ( self , new_state ) :
  iIiI = self . print_state ( )
  OO0o0o0oo = "{} -> {}" . format ( iIiI , new_state )
  if ( new_state == "up" and self . unreach_state ( ) ) :
   OO0o0o0oo = bold ( OO0o0o0oo , False )
   if 40 - 40: i11iIiiIii
  return ( OO0o0o0oo )
  if 95 - 95: OOooOOo / Oo0Ooo . OoO0O00 / IiII + i11iIiiIii * OOooOOo
  if 27 - 27: O0 * OoO0O00 * I1ii11iIi11i
 def print_rloc_probe_rtt ( self ) :
  if ( self . rloc_probe_rtt == - 1 ) : return ( "none" )
  return ( self . rloc_probe_rtt )
  if 40 - 40: O0 + oO0o - ooOoO0o + I1IiiI - IiII
  if 60 - 60: I1Ii111 * OoO0O00 * oO0o + oO0o
 def print_recent_rloc_probe_rtts ( self ) :
  i1III1ii = str ( self . recent_rloc_probe_rtts )
  i1III1ii = i1III1ii . replace ( "-1" , "?" )
  return ( i1III1ii )
  if 48 - 48: I1IiiI - II111iiii / OoOoOO00
  if 69 - 69: i11iIiiIii
 def compute_rloc_probe_rtt ( self ) :
  oo = self . rloc_probe_rtt
  self . rloc_probe_rtt = - 1
  if ( self . last_rloc_probe_reply == None ) : return
  if ( self . last_rloc_probe == None ) : return
  self . rloc_probe_rtt = self . last_rloc_probe_reply - self . last_rloc_probe
  self . rloc_probe_rtt = round ( self . rloc_probe_rtt , 3 )
  OOOoOOO000 = self . recent_rloc_probe_rtts
  self . recent_rloc_probe_rtts = [ oo ] + OOOoOOO000 [ 0 : - 1 ]
  if 86 - 86: ooOoO0o / iII111i . OoooooooOO + I1Ii111 + I1Ii111
  if 35 - 35: Oo0Ooo + oO0o * o0oOOo0O0Ooo - iIii1I11I1II1 % I1ii11iIi11i * i11iIiiIii
 def print_rloc_probe_hops ( self ) :
  return ( self . rloc_probe_hops )
  if 56 - 56: iIii1I11I1II1 / I11i
  if 78 - 78: i11iIiiIii * OoO0O00 * Ii1I / i1IIi * OOooOOo + o0oOOo0O0Ooo
 def print_recent_rloc_probe_hops ( self ) :
  oooOOOooOo0 = str ( self . recent_rloc_probe_hops )
  return ( oooOOOooOo0 )
  if 97 - 97: I1Ii111 . Oo0Ooo
  if 44 - 44: OoO0O00 + OOooOOo
 def store_rloc_probe_hops ( self , to_hops , from_ttl ) :
  if ( to_hops == 0 ) :
   to_hops = "?"
  elif ( to_hops < LISP_RLOC_PROBE_TTL / 2 ) :
   to_hops = "!"
  else :
   to_hops = str ( LISP_RLOC_PROBE_TTL - to_hops )
   if 9 - 9: iII111i . i11iIiiIii * IiII . I11i
  if ( from_ttl < LISP_RLOC_PROBE_TTL / 2 ) :
   Ii111iI = "!"
  else :
   Ii111iI = str ( LISP_RLOC_PROBE_TTL - from_ttl )
   if 71 - 71: ooOoO0o + OOooOOo * I1IiiI % I11i . I1Ii111 % OoooooooOO
   if 7 - 7: iIii1I11I1II1
  oo = self . rloc_probe_hops
  self . rloc_probe_hops = to_hops + "/" + Ii111iI
  OOOoOOO000 = self . recent_rloc_probe_hops
  self . recent_rloc_probe_hops = [ oo ] + OOOoOOO000 [ 0 : - 1 ]
  if 88 - 88: ooOoO0o
  if 37 - 37: ooOoO0o * OoOoOO00 . ooOoO0o
 def process_rloc_probe_reply ( self , nonce , eid , group , hop_count , ttl ) :
  OoOOo = self
  while ( True ) :
   if ( OoOOo . last_rloc_probe_nonce == nonce ) : break
   OoOOo = OoOOo . next_rloc
   if ( OoOOo == None ) :
    lprint ( "    No matching nonce state found for nonce 0x{}" . format ( lisp_hex_string ( nonce ) ) )
    if 47 - 47: iIii1I11I1II1 + iIii1I11I1II1 / Ii1I
    return
    if 19 - 19: OOooOOo . OoOoOO00 % iIii1I11I1II1 % OoOoOO00
    if 92 - 92: o0oOOo0O0Ooo + II111iiii
    if 56 - 56: OoOoOO00 - OoOoOO00 / Ii1I
  OoOOo . last_rloc_probe_reply = lisp_get_timestamp ( )
  OoOOo . compute_rloc_probe_rtt ( )
  oooIIi1i = OoOOo . print_state_change ( "up" )
  if ( OoOOo . state != LISP_RLOC_UP_STATE ) :
   lisp_update_rtr_updown ( OoOOo . rloc , True )
   OoOOo . state = LISP_RLOC_UP_STATE
   OoOOo . last_state_change = lisp_get_timestamp ( )
   IIII = lisp_map_cache . lookup_cache ( eid , True )
   if ( IIII ) : lisp_write_ipc_map_cache ( True , IIII )
   if 64 - 64: i1IIi * II111iiii + I1ii11iIi11i + OOooOOo % I1ii11iIi11i - OoooooooOO
   if 96 - 96: IiII + oO0o / Oo0Ooo + OoooooooOO
  OoOOo . store_rloc_probe_hops ( hop_count , ttl )
  if 53 - 53: Ii1I * IiII + Oo0Ooo + i11iIiiIii - iIii1I11I1II1
  Ooo0O = bold ( "RLOC-probe reply" , False )
  I1iiIiiii1111 = OoOOo . rloc . print_address_no_iid ( )
  Oo0OOoo0 = bold ( str ( OoOOo . print_rloc_probe_rtt ( ) ) , False )
  OoOoO = ":{}" . format ( self . translated_port ) if self . translated_port != 0 else ""
  if 58 - 58: Ii1I . Oo0Ooo
  i11i1i = ""
  if ( OoOOo . rloc_next_hop != None ) :
   oOo0OOOOOO , I1o0Ooo = OoOOo . rloc_next_hop
   i11i1i = ", nh {}({})" . format ( I1o0Ooo , oOo0OOOOOO )
   if 78 - 78: iIii1I11I1II1
   if 64 - 64: OoOoOO00 - oO0o
  ooo0OO = green ( lisp_print_eid_tuple ( eid , group ) , False )
  lprint ( ( "    Received {} from {}{} for {}, {}, rtt {}{}, " + "to-ttl/from-ttl {}" ) . format ( Ooo0O , red ( I1iiIiiii1111 , False ) , OoOoO , ooo0OO ,
  # iII111i
 oooIIi1i , Oo0OOoo0 , i11i1i , str ( hop_count ) + "/" + str ( ttl ) ) )
  if 64 - 64: II111iiii
  if ( OoOOo . rloc_next_hop == None ) : return
  if 14 - 14: I1Ii111
  if 81 - 81: II111iiii
  if 55 - 55: O0 + o0oOOo0O0Ooo * I1IiiI - OoooooooOO
  if 68 - 68: I11i + Oo0Ooo
  OoOOo = None
  i1iIi1Ii1I11I = None
  while ( True ) :
   OoOOo = self if OoOOo == None else OoOOo . next_rloc
   if ( OoOOo == None ) : break
   if ( OoOOo . up_state ( ) == False ) : continue
   if ( OoOOo . rloc_probe_rtt == - 1 ) : continue
   if 58 - 58: ooOoO0o
   if ( i1iIi1Ii1I11I == None ) : i1iIi1Ii1I11I = OoOOo
   if ( OoOOo . rloc_probe_rtt < i1iIi1Ii1I11I . rloc_probe_rtt ) : i1iIi1Ii1I11I = OoOOo
   if 84 - 84: OoOoOO00 - I11i
   if 34 - 34: Ii1I % I1Ii111 % I1ii11iIi11i - IiII
  if ( i1iIi1Ii1I11I != None ) :
   oOo0OOOOOO , I1o0Ooo = i1iIi1Ii1I11I . rloc_next_hop
   i11i1i = bold ( "nh {}({})" . format ( I1o0Ooo , oOo0OOOOOO ) , False )
   lprint ( "    Install host-route via best {}" . format ( i11i1i ) )
   lisp_install_host_route ( I1iiIiiii1111 , None , False )
   lisp_install_host_route ( I1iiIiiii1111 , I1o0Ooo , True )
   if 89 - 89: IiII
   if 64 - 64: OoOoOO00
   if 3 - 3: i11iIiiIii / I1Ii111
 def add_to_rloc_probe_list ( self , eid , group ) :
  I1iiIiiii1111 = self . rloc . print_address_no_iid ( )
  IIiII = self . translated_port
  if ( IIiII != 0 ) : I1iiIiiii1111 += ":" + str ( IIiII )
  if 40 - 40: OoooooooOO / o0oOOo0O0Ooo + OoOoOO00
  if ( lisp_rloc_probe_list . has_key ( I1iiIiiii1111 ) == False ) :
   lisp_rloc_probe_list [ I1iiIiiii1111 ] = [ ]
   if 73 - 73: OOooOOo / Oo0Ooo
   if 80 - 80: OoO0O00 + I1IiiI % i1IIi / I11i % i1IIi * i11iIiiIii
  if ( group . is_null ( ) ) : group . instance_id = 0
  for iIIIIIi11Ii , ooo0OO , O0ooO0oOO in lisp_rloc_probe_list [ I1iiIiiii1111 ] :
   if ( ooo0OO . is_exact_match ( eid ) and O0ooO0oOO . is_exact_match ( group ) ) :
    if ( iIIIIIi11Ii == self ) :
     if ( lisp_rloc_probe_list [ I1iiIiiii1111 ] == [ ] ) :
      lisp_rloc_probe_list . pop ( I1iiIiiii1111 )
      if 27 - 27: OoOoOO00 / I1Ii111 * O0 / I1IiiI - IiII / o0oOOo0O0Ooo
     return
     if 70 - 70: I1ii11iIi11i
    lisp_rloc_probe_list [ I1iiIiiii1111 ] . remove ( [ iIIIIIi11Ii , ooo0OO , O0ooO0oOO ] )
    break
    if 11 - 11: I1Ii111
    if 70 - 70: Ii1I
  lisp_rloc_probe_list [ I1iiIiiii1111 ] . append ( [ self , eid , group ] )
  if 22 - 22: Ii1I
  if 59 - 59: I1ii11iIi11i
  if 90 - 90: OOooOOo / iII111i
  if 70 - 70: o0oOOo0O0Ooo
  if 49 - 49: OOooOOo - I1IiiI + OoooooooOO % iII111i + o0oOOo0O0Ooo + OoOoOO00
  OoOOo = lisp_rloc_probe_list [ I1iiIiiii1111 ] [ 0 ] [ 0 ]
  if ( OoOOo . state == LISP_RLOC_UNREACH_STATE ) :
   self . state = LISP_RLOC_UNREACH_STATE
   self . last_state_change = lisp_get_timestamp ( )
   if 37 - 37: II111iiii % I1ii11iIi11i * OoOoOO00
   if 35 - 35: i1IIi
   if 81 - 81: OoO0O00
 def delete_from_rloc_probe_list ( self , eid , group ) :
  I1iiIiiii1111 = self . rloc . print_address_no_iid ( )
  IIiII = self . translated_port
  if ( IIiII != 0 ) : I1iiIiiii1111 += ":" + str ( IIiII )
  if ( lisp_rloc_probe_list . has_key ( I1iiIiiii1111 ) == False ) : return
  if 45 - 45: OoooooooOO . O0 * oO0o + IiII
  IiIi11IIIIiii = [ ]
  for iIIiI11iI1Ii1 in lisp_rloc_probe_list [ I1iiIiiii1111 ] :
   if ( iIIiI11iI1Ii1 [ 0 ] != self ) : continue
   if ( iIIiI11iI1Ii1 [ 1 ] . is_exact_match ( eid ) == False ) : continue
   if ( iIIiI11iI1Ii1 [ 2 ] . is_exact_match ( group ) == False ) : continue
   IiIi11IIIIiii = iIIiI11iI1Ii1
   break
   if 25 - 25: Oo0Ooo * ooOoO0o % I1Ii111
  if ( IiIi11IIIIiii == [ ] ) : return
  if 34 - 34: OoOoOO00 / I1Ii111 - ooOoO0o
  try :
   lisp_rloc_probe_list [ I1iiIiiii1111 ] . remove ( IiIi11IIIIiii )
   if ( lisp_rloc_probe_list [ I1iiIiiii1111 ] == [ ] ) :
    lisp_rloc_probe_list . pop ( I1iiIiiii1111 )
    if 66 - 66: I11i * OoO0O00
  except :
   return
   if 98 - 98: IiII . Oo0Ooo + I1Ii111
   if 63 - 63: oO0o * I1IiiI * oO0o
   if 56 - 56: oO0o - Ii1I % I1Ii111
 def print_rloc_probe_state ( self , trailing_linefeed ) :
  Oo0O = ""
  OoOOo = self
  while ( True ) :
   O000o00O0OOoo = OoOOo . last_rloc_probe
   if ( O000o00O0OOoo == None ) : O000o00O0OOoo = 0
   i1IiIiII = OoOOo . last_rloc_probe_reply
   if ( i1IiIiII == None ) : i1IiIiII = 0
   Oo0OOoo0 = OoOOo . print_rloc_probe_rtt ( )
   IiIIi1I1I11Ii = space ( 4 )
   if 57 - 57: IiII % O0 * I1ii11iIi11i
   if ( OoOOo . rloc_next_hop == None ) :
    Oo0O += "RLOC-Probing:\n"
   else :
    oOo0OOOOOO , I1o0Ooo = OoOOo . rloc_next_hop
    Oo0O += "RLOC-Probing for nh {}({}):\n" . format ( I1o0Ooo , oOo0OOOOOO )
    if 61 - 61: O0
    if 51 - 51: I1Ii111 - I11i % o0oOOo0O0Ooo * Oo0Ooo - oO0o + II111iiii
   Oo0O += ( "{}RLOC-probe request sent: {}\n{}RLOC-probe reply " + "received: {}, rtt {}" ) . format ( IiIIi1I1I11Ii , lisp_print_elapsed ( O000o00O0OOoo ) ,
   # i11iIiiIii
 IiIIi1I1I11Ii , lisp_print_elapsed ( i1IiIiII ) , Oo0OOoo0 )
   if 64 - 64: OoO0O00 % OoOoOO00 % I1IiiI - Ii1I / IiII * Ii1I
   if ( trailing_linefeed ) : Oo0O += "\n"
   if 74 - 74: IiII - O0 % OOooOOo % OoooooooOO - I11i
   OoOOo = OoOOo . next_rloc
   if ( OoOOo == None ) : break
   Oo0O += "\n"
   if 4 - 4: i1IIi + OoOoOO00 + iIii1I11I1II1 - i1IIi * i11iIiiIii
  return ( Oo0O )
  if 99 - 99: I1ii11iIi11i - O0 % II111iiii + ooOoO0o % OoO0O00 * Ii1I
  if 8 - 8: OOooOOo
 def get_encap_keys ( self ) :
  IIiII = "4341" if self . translated_port == 0 else str ( self . translated_port )
  if 85 - 85: O0 % OOooOOo . Ii1I
  I1iiIiiii1111 = self . rloc . print_address_no_iid ( ) + ":" + IIiII
  if 74 - 74: I1ii11iIi11i - I1Ii111 + i11iIiiIii / I1Ii111 / OoooooooOO + o0oOOo0O0Ooo
  try :
   o00OO0o0 = lisp_crypto_keys_by_rloc_encap [ I1iiIiiii1111 ]
   if ( o00OO0o0 [ 1 ] ) : return ( o00OO0o0 [ 1 ] . encrypt_key , o00OO0o0 [ 1 ] . icv_key )
   return ( None , None )
  except :
   return ( None , None )
   if 23 - 23: Oo0Ooo
   if 91 - 91: I1Ii111
   if 59 - 59: i1IIi % OOooOOo
 def rloc_recent_rekey ( self ) :
  IIiII = "4341" if self . translated_port == 0 else str ( self . translated_port )
  if 81 - 81: i11iIiiIii / OoO0O00 * OoOoOO00 % iII111i - iIii1I11I1II1 + I1ii11iIi11i
  I1iiIiiii1111 = self . rloc . print_address_no_iid ( ) + ":" + IIiII
  if 20 - 20: O0 . I1Ii111 * Ii1I * II111iiii
  try :
   iii11 = lisp_crypto_keys_by_rloc_encap [ I1iiIiiii1111 ] [ 1 ]
   if ( iii11 == None ) : return ( False )
   if ( iii11 . last_rekey == None ) : return ( True )
   return ( time . time ( ) - iii11 . last_rekey < 1 )
  except :
   return ( False )
   if 66 - 66: Ii1I % OoO0O00 % II111iiii - OOooOOo * o0oOOo0O0Ooo
   if 33 - 33: OoooooooOO / I11i
   if 98 - 98: I1ii11iIi11i . Ii1I . iIii1I11I1II1 * I1ii11iIi11i / Ii1I
   if 74 - 74: Oo0Ooo * I1Ii111
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
  if 72 - 72: OoOoOO00 + O0 - IiII * ooOoO0o
  if 20 - 20: II111iiii % OoOoOO00 * i11iIiiIii
 def print_mapping ( self , eid_indent , rloc_indent ) :
  OOOO0O00o = lisp_print_elapsed ( self . uptime )
  O0oo0oo0 = "" if self . group . is_null ( ) else ", group {}" . format ( self . group . print_prefix ( ) )
  if 68 - 68: IiII / ooOoO0o
  lprint ( "{}eid {}{}, uptime {}, {} rlocs:" . format ( eid_indent ,
 green ( self . eid . print_prefix ( ) , False ) , O0oo0oo0 , OOOO0O00o ,
 len ( self . rloc_set ) ) )
  for OoOOo in self . rloc_set : OoOOo . print_rloc ( rloc_indent )
  if 100 - 100: ooOoO0o / I1IiiI
  if 69 - 69: ooOoO0o + OoO0O00 * o0oOOo0O0Ooo - ooOoO0o
 def print_eid_tuple ( self ) :
  return ( lisp_print_eid_tuple ( self . eid , self . group ) )
  if 66 - 66: OoooooooOO / iII111i / I1IiiI % ooOoO0o / OoO0O00 + OOooOOo
  if 64 - 64: i1IIi
 def print_ttl ( self ) :
  iiI = self . map_cache_ttl
  if ( iiI == None ) : return ( "forever" )
  if 26 - 26: OoOoOO00 / o0oOOo0O0Ooo . OOooOOo + I1IiiI + Ii1I . iII111i
  if ( iiI >= 3600 ) :
   if ( ( iiI % 3600 ) == 0 ) :
    iiI = str ( iiI / 3600 ) + " hours"
   else :
    iiI = str ( iiI * 60 ) + " mins"
    if 89 - 89: I1Ii111 * I1IiiI . i1IIi - iIii1I11I1II1 * I1Ii111
  elif ( iiI >= 60 ) :
   if ( ( iiI % 60 ) == 0 ) :
    iiI = str ( iiI / 60 ) + " mins"
   else :
    iiI = str ( iiI ) + " secs"
    if 5 - 5: OoOoOO00 % i1IIi
  else :
   iiI = str ( iiI ) + " secs"
   if 31 - 31: Oo0Ooo * O0 . OOooOOo . o0oOOo0O0Ooo + OoO0O00 + II111iiii
  return ( iiI )
  if 76 - 76: Oo0Ooo + I1IiiI - O0
  if 58 - 58: IiII * i1IIi . I1IiiI - iII111i
 def has_ttl_elapsed ( self ) :
  if ( self . map_cache_ttl == None ) : return ( False )
  i11IiIIi11I = time . time ( ) - self . last_refresh_time
  return ( i11IiIIi11I >= self . map_cache_ttl )
  if 73 - 73: Oo0Ooo . OoOoOO00
  if 50 - 50: IiII / o0oOOo0O0Ooo
 def is_active ( self ) :
  if ( self . stats . last_increment == None ) : return ( False )
  i11IiIIi11I = time . time ( ) - self . stats . last_increment
  return ( i11IiIIi11I <= 60 )
  if 9 - 9: Oo0Ooo - OoO0O00 + iII111i / OoooooooOO
  if 52 - 52: O0
 def match_eid_tuple ( self , db ) :
  if ( self . eid . is_exact_match ( db . eid ) == False ) : return ( False )
  if ( self . group . is_exact_match ( db . group ) == False ) : return ( False )
  return ( True )
  if 34 - 34: OoooooooOO + OoOoOO00 - Oo0Ooo . OOooOOo * iIii1I11I1II1
  if 93 - 93: i11iIiiIii / Oo0Ooo * OoOoOO00 / ooOoO0o + OoO0O00 * OOooOOo
 def sort_rloc_set ( self ) :
  self . rloc_set . sort ( key = operator . attrgetter ( 'rloc.address' ) )
  if 81 - 81: IiII * iII111i + i1IIi + I1Ii111 / OoO0O00
  if 83 - 83: oO0o / OoO0O00
 def delete_rlocs_from_rloc_probe_list ( self ) :
  for OoOOo in self . best_rloc_set :
   OoOOo . delete_from_rloc_probe_list ( self . eid , self . group )
   if 34 - 34: OoooooooOO - i1IIi * O0
   if 83 - 83: I1IiiI + OoO0O00
   if 41 - 41: Ii1I + II111iiii . OOooOOo * I1Ii111 / II111iiii
 def build_best_rloc_set ( self ) :
  iI11Ii11 = self . best_rloc_set
  self . best_rloc_set = [ ]
  if ( self . rloc_set == None ) : return
  if 11 - 11: I1Ii111 - ooOoO0o
  if 76 - 76: oO0o - i1IIi - O0 % Oo0Ooo
  if 66 - 66: IiII % iII111i / o0oOOo0O0Ooo
  if 44 - 44: iIii1I11I1II1 + o0oOOo0O0Ooo + OoO0O00 * II111iiii
  OOO00O000O0OO = 256
  for OoOOo in self . rloc_set :
   if ( OoOOo . up_state ( ) ) : OOO00O000O0OO = min ( OoOOo . priority , OOO00O000O0OO )
   if 96 - 96: Ii1I
   if 8 - 8: iII111i
   if 77 - 77: OOooOOo % I1IiiI - iII111i % I1Ii111
   if 29 - 29: iIii1I11I1II1 / i11iIiiIii + Oo0Ooo
   if 99 - 99: I1IiiI - iII111i * Ii1I - OoOoOO00 / i11iIiiIii - i1IIi
   if 46 - 46: I1ii11iIi11i * ooOoO0o
   if 4 - 4: I1Ii111 * II111iiii
   if 4 - 4: ooOoO0o * Oo0Ooo - I1ii11iIi11i % ooOoO0o % OoOoOO00
   if 18 - 18: OOooOOo / O0 . OoO0O00 - II111iiii * OOooOOo
   if 13 - 13: OoO0O00 % i1IIi . i11iIiiIii / iII111i
  for OoOOo in self . rloc_set :
   if ( OoOOo . priority <= OOO00O000O0OO ) :
    if ( OoOOo . unreach_state ( ) and OoOOo . last_rloc_probe == None ) :
     OoOOo . last_rloc_probe = lisp_get_timestamp ( )
     if 28 - 28: i1IIi - iII111i + o0oOOo0O0Ooo / Oo0Ooo * oO0o
    self . best_rloc_set . append ( OoOOo )
    if 8 - 8: ooOoO0o + OOooOOo * ooOoO0o / i1IIi . I1ii11iIi11i
    if 4 - 4: Ii1I - Oo0Ooo . i1IIi + iIii1I11I1II1
    if 28 - 28: O0 / ooOoO0o / IiII - I11i + IiII + OoO0O00
    if 84 - 84: Oo0Ooo + OoOoOO00 / iII111i . I1ii11iIi11i
    if 26 - 26: Oo0Ooo
    if 61 - 61: Ii1I * oO0o * i11iIiiIii + OoO0O00
    if 43 - 43: OoO0O00 * OoO0O00 * oO0o
    if 24 - 24: oO0o
  for OoOOo in iI11Ii11 :
   if ( OoOOo . priority < OOO00O000O0OO ) : continue
   OoOOo . delete_from_rloc_probe_list ( self . eid , self . group )
   if 77 - 77: i11iIiiIii - I1Ii111 - I1ii11iIi11i * Oo0Ooo / i11iIiiIii
  for OoOOo in self . best_rloc_set :
   if ( OoOOo . rloc . is_null ( ) ) : continue
   OoOOo . add_to_rloc_probe_list ( self . eid , self . group )
   if 79 - 79: Oo0Ooo % Oo0Ooo . oO0o + ooOoO0o * iII111i * I11i
   if 87 - 87: o0oOOo0O0Ooo + OoOoOO00 % o0oOOo0O0Ooo + I1IiiI
   if 89 - 89: II111iiii
 def select_rloc ( self , lisp_packet , ipc_socket ) :
  i1II1IiiIi = lisp_packet . packet
  iiIiiI1I1I = lisp_packet . inner_version
  o00OOo00 = len ( self . best_rloc_set )
  if ( o00OOo00 is 0 ) :
   self . stats . increment ( len ( i1II1IiiIi ) )
   return ( [ None , None , None , self . action , None , None ] )
   if 76 - 76: Ii1I - iII111i
   if 89 - 89: II111iiii . Ii1I
  i1I11iII1 = 4 if lisp_load_split_pings else 0
  IiiiI1I1iI11 = lisp_packet . hash_ports ( )
  if ( iiIiiI1I1I == 4 ) :
   for Ii11 in range ( 8 + i1I11iII1 ) :
    IiiiI1I1iI11 = IiiiI1I1iI11 ^ struct . unpack ( "B" , i1II1IiiIi [ Ii11 + 12 ] ) [ 0 ]
    if 22 - 22: O0 * I1IiiI / I11i + I11i % I11i
  elif ( iiIiiI1I1I == 6 ) :
   for Ii11 in range ( 0 , 32 + i1I11iII1 , 4 ) :
    IiiiI1I1iI11 = IiiiI1I1iI11 ^ struct . unpack ( "I" , i1II1IiiIi [ Ii11 + 8 : Ii11 + 12 ] ) [ 0 ]
    if 63 - 63: i11iIiiIii + iIii1I11I1II1 / oO0o % IiII - O0
   IiiiI1I1iI11 = ( IiiiI1I1iI11 >> 16 ) + ( IiiiI1I1iI11 & 0xffff )
   IiiiI1I1iI11 = ( IiiiI1I1iI11 >> 8 ) + ( IiiiI1I1iI11 & 0xff )
  else :
   for Ii11 in range ( 0 , 12 + i1I11iII1 , 4 ) :
    IiiiI1I1iI11 = IiiiI1I1iI11 ^ struct . unpack ( "I" , i1II1IiiIi [ Ii11 : Ii11 + 4 ] ) [ 0 ]
    if 21 - 21: II111iiii
    if 89 - 89: OOooOOo % i11iIiiIii * OoOoOO00 % oO0o / O0 * i1IIi
    if 16 - 16: IiII
  if ( lisp_data_plane_logging ) :
   ii11I = [ ]
   for iIIIIIi11Ii in self . best_rloc_set :
    if ( iIIIIIi11Ii . rloc . is_null ( ) ) : continue
    ii11I . append ( [ iIIIIIi11Ii . rloc . print_address_no_iid ( ) , iIIIIIi11Ii . print_state ( ) ] )
    if 9 - 9: I11i % i1IIi / i1IIi / OoO0O00
   dprint ( "Packet hash {}, index {}, best-rloc-list: {}" . format ( hex ( IiiiI1I1iI11 ) , IiiiI1I1iI11 % o00OOo00 , red ( str ( ii11I ) , False ) ) )
   if 46 - 46: I1Ii111 * II111iiii + II111iiii * O0 % II111iiii
   if 37 - 37: OOooOOo . iIii1I11I1II1 / O0 . ooOoO0o + OOooOOo - OoooooooOO
   if 96 - 96: I1Ii111 / oO0o . I1ii11iIi11i % I1IiiI * OOooOOo
   if 99 - 99: i11iIiiIii - I1Ii111
   if 4 - 4: o0oOOo0O0Ooo - i11iIiiIii . iIii1I11I1II1 . OOooOOo % IiII
   if 68 - 68: I11i / iII111i - IiII . iIii1I11I1II1 / o0oOOo0O0Ooo
  OoOOo = self . best_rloc_set [ IiiiI1I1iI11 % o00OOo00 ]
  if 54 - 54: II111iiii * I1IiiI
  if 49 - 49: I1ii11iIi11i
  if 31 - 31: o0oOOo0O0Ooo - OoOoOO00 + I1ii11iIi11i . oO0o - O0
  if 61 - 61: I1ii11iIi11i * II111iiii . i1IIi
  if 60 - 60: OoooooooOO % ooOoO0o * i11iIiiIii * OoooooooOO % IiII
  oOOo00ooO = lisp_get_echo_nonce ( OoOOo . rloc , None )
  if ( oOOo00ooO ) :
   oOOo00ooO . change_state ( OoOOo )
   if ( OoOOo . no_echoed_nonce_state ( ) ) :
    oOOo00ooO . request_nonce_sent = None
    if 15 - 15: oO0o
    if 40 - 40: I1Ii111
    if 77 - 77: II111iiii - o0oOOo0O0Ooo . Ii1I
    if 47 - 47: o0oOOo0O0Ooo % OOooOOo + I1Ii111
    if 64 - 64: ooOoO0o / IiII . I1IiiI
    if 77 - 77: o0oOOo0O0Ooo % I1Ii111 . OOooOOo
  if ( OoOOo . up_state ( ) == False ) :
   oO0OOooOoO = IiiiI1I1iI11 % o00OOo00
   iI11I = ( oO0OOooOoO + 1 ) % o00OOo00
   while ( iI11I != oO0OOooOoO ) :
    OoOOo = self . best_rloc_set [ iI11I ]
    if ( OoOOo . up_state ( ) ) : break
    iI11I = ( iI11I + 1 ) % o00OOo00
    if 17 - 17: I1IiiI * Ii1I . i11iIiiIii - oO0o . i11iIiiIii + Oo0Ooo
   if ( iI11I == oO0OOooOoO ) :
    self . build_best_rloc_set ( )
    return ( [ None , None , None , None , None , None ] )
    if 42 - 42: iII111i
    if 51 - 51: I1IiiI - OoOoOO00 * I1Ii111 * iIii1I11I1II1
    if 5 - 5: i11iIiiIii / o0oOOo0O0Ooo
    if 45 - 45: I1Ii111 + OoooooooOO + o0oOOo0O0Ooo * II111iiii
    if 12 - 12: I1ii11iIi11i / O0
    if 18 - 18: OoOoOO00 . i11iIiiIii + i1IIi / OoooooooOO - IiII % OoO0O00
  OoOOo . stats . increment ( len ( i1II1IiiIi ) )
  if 47 - 47: iII111i % IiII + I1Ii111 * o0oOOo0O0Ooo * OoooooooOO
  if 100 - 100: Oo0Ooo / I1IiiI / iII111i / I1Ii111 / oO0o % o0oOOo0O0Ooo
  if 16 - 16: I1IiiI + I11i
  if 66 - 66: OoooooooOO % II111iiii / I1Ii111 . i11iIiiIii
  if ( OoOOo . rle_name and OoOOo . rle == None ) :
   if ( lisp_rle_list . has_key ( OoOOo . rle_name ) ) :
    OoOOo . rle = lisp_rle_list [ OoOOo . rle_name ]
    if 67 - 67: Ii1I + Oo0Ooo - I1IiiI - IiII + oO0o + Oo0Ooo
    if 84 - 84: I1ii11iIi11i % oO0o - OOooOOo * Ii1I
  if ( OoOOo . rle ) : return ( [ None , None , None , None , OoOOo . rle , None ] )
  if 78 - 78: i1IIi / ooOoO0o / oO0o
  if 21 - 21: IiII % Ii1I + OOooOOo + IiII
  if 90 - 90: o0oOOo0O0Ooo
  if 38 - 38: OoOoOO00 / OOooOOo % OoooooooOO * I1ii11iIi11i
  if ( OoOOo . elp and OoOOo . elp . use_elp_node ) :
   return ( [ OoOOo . elp . use_elp_node . address , None , None , None , None ,
 None ] )
   if 7 - 7: I11i * O0 + Oo0Ooo / O0 * oO0o + i11iIiiIii
   if 74 - 74: OoOoOO00
   if 91 - 91: i11iIiiIii / Ii1I % OOooOOo % O0 - I11i . I11i
   if 78 - 78: i1IIi + I11i % OoooooooOO + i1IIi + iII111i % Ii1I
   if 87 - 87: ooOoO0o . iIii1I11I1II1
  O00o00 = None if ( OoOOo . rloc . is_null ( ) ) else OoOOo . rloc
  IIiII = OoOOo . translated_port
  ooOOoo0 = self . action if ( O00o00 == None ) else None
  if 65 - 65: iIii1I11I1II1
  if 58 - 58: IiII % i1IIi . i11iIiiIii
  if 5 - 5: OoOoOO00
  if 75 - 75: OOooOOo
  if 60 - 60: ooOoO0o - II111iiii - iIii1I11I1II1
  oOo0 = None
  if ( oOOo00ooO and oOOo00ooO . request_nonce_timeout ( ) == False ) :
   oOo0 = oOOo00ooO . get_request_or_echo_nonce ( ipc_socket , O00o00 )
   if 23 - 23: I1ii11iIi11i
   if 68 - 68: OoO0O00 . oO0o / IiII - II111iiii % Oo0Ooo
   if 24 - 24: II111iiii / I1ii11iIi11i + oO0o / Ii1I + IiII % oO0o
   if 86 - 86: I1IiiI
   if 83 - 83: I11i % Ii1I + IiII % I11i / i1IIi . oO0o
  return ( [ O00o00 , IIiII , oOo0 , ooOOoo0 , None , OoOOo ] )
  if 56 - 56: I1Ii111 - OOooOOo % o0oOOo0O0Ooo
  if 30 - 30: I1Ii111 % i1IIi
 def do_rloc_sets_match ( self , rloc_address_set ) :
  if ( len ( self . rloc_set ) != len ( rloc_address_set ) ) : return ( False )
  if 98 - 98: oO0o . i11iIiiIii / Ii1I - Ii1I
  if 23 - 23: iIii1I11I1II1
  if 30 - 30: I1ii11iIi11i + OoO0O00 - O0
  if 42 - 42: I11i - I1Ii111
  if 24 - 24: i1IIi
  for IiI1I1iii11 in self . rloc_set :
   for OoOOo in rloc_address_set :
    if ( OoOOo . is_exact_match ( IiI1I1iii11 . rloc ) == False ) : continue
    OoOOo = None
    break
    if 93 - 93: OoOoOO00 - Oo0Ooo + iIii1I11I1II1 % iIii1I11I1II1 / I1ii11iIi11i - I1Ii111
   if ( OoOOo == rloc_address_set [ - 1 ] ) : return ( False )
   if 9 - 9: I1ii11iIi11i - o0oOOo0O0Ooo / i11iIiiIii * iII111i / OoOoOO00 . I1IiiI
  return ( True )
  if 23 - 23: I1IiiI . iII111i % i1IIi
  if 92 - 92: o0oOOo0O0Ooo % i1IIi / OoooooooOO * OoooooooOO / iIii1I11I1II1
 def get_rloc ( self , rloc ) :
  for IiI1I1iii11 in self . rloc_set :
   iIIIIIi11Ii = IiI1I1iii11 . rloc
   if ( rloc . is_exact_match ( iIIIIIi11Ii ) ) : return ( IiI1I1iii11 )
   if 7 - 7: IiII / OOooOOo + Oo0Ooo . I1IiiI
  return ( None )
  if 33 - 33: I1Ii111 + OoooooooOO
  if 73 - 73: O0 . Oo0Ooo
 def get_rloc_by_interface ( self , interface ) :
  for IiI1I1iii11 in self . rloc_set :
   if ( IiI1I1iii11 . interface == interface ) : return ( IiI1I1iii11 )
   if 28 - 28: I1IiiI . O0 % o0oOOo0O0Ooo / I11i
  return ( None )
  if 48 - 48: II111iiii % I1ii11iIi11i - II111iiii
  if 29 - 29: I1Ii111 - I1Ii111 - I11i * iIii1I11I1II1 % OoO0O00 % IiII
 def add_db ( self ) :
  if ( self . group . is_null ( ) ) :
   lisp_db_for_lookups . add_cache ( self . eid , self )
  else :
   I111I = lisp_db_for_lookups . lookup_cache ( self . group , True )
   if ( I111I == None ) :
    I111I = lisp_mapping ( self . group , self . group , [ ] )
    lisp_db_for_lookups . add_cache ( self . group , I111I )
    if 73 - 73: i1IIi . OoooooooOO / OoOoOO00 % Ii1I / Ii1I / Ii1I
   I111I . add_source_entry ( self )
   if 40 - 40: I1Ii111 - iIii1I11I1II1
   if 88 - 88: OOooOOo * O0 * OoOoOO00
   if 26 - 26: Ii1I
 def add_cache ( self , do_ipc = True ) :
  if ( self . group . is_null ( ) ) :
   lisp_map_cache . add_cache ( self . eid , self )
   if ( lisp_program_hardware ) : lisp_program_vxlan_hardware ( self )
  else :
   IIII = lisp_map_cache . lookup_cache ( self . group , True )
   if ( IIII == None ) :
    IIII = lisp_mapping ( self . group , self . group , [ ] )
    IIII . eid . copy_address ( self . group )
    IIII . group . copy_address ( self . group )
    lisp_map_cache . add_cache ( self . group , IIII )
    if 65 - 65: iII111i / iIii1I11I1II1 + I11i - iIii1I11I1II1 - Ii1I . I1Ii111
   if ( self . eid . is_null ( ) ) : self . eid . make_default_route ( IIII . group )
   IIII . add_source_entry ( self )
   if 77 - 77: OoOoOO00 / I1IiiI + IiII
  if ( do_ipc ) : lisp_write_ipc_map_cache ( True , self )
  if 66 - 66: i11iIiiIii * OoooooooOO + iII111i / Ii1I
  if 42 - 42: Ii1I / iIii1I11I1II1 / Oo0Ooo . O0 . oO0o * I1IiiI
 def delete_cache ( self ) :
  self . delete_rlocs_from_rloc_probe_list ( )
  lisp_write_ipc_map_cache ( False , self )
  if 21 - 21: OoooooooOO
  if ( self . group . is_null ( ) ) :
   lisp_map_cache . delete_cache ( self . eid )
   if ( lisp_program_hardware ) :
    OoooO00OO0OO = self . eid . print_prefix_no_iid ( )
    os . system ( "ip route delete {}" . format ( OoooO00OO0OO ) )
    if 50 - 50: OoO0O00 . o0oOOo0O0Ooo
  else :
   IIII = lisp_map_cache . lookup_cache ( self . group , True )
   if ( IIII == None ) : return
   if 30 - 30: I1ii11iIi11i % iII111i
   O0o0O0OO00O = IIII . lookup_source_cache ( self . eid , True )
   if ( O0o0O0OO00O == None ) : return
   if 63 - 63: Oo0Ooo + I11i % I11i / iII111i + OoOoOO00
   IIII . source_cache . delete_cache ( self . eid )
   if ( IIII . source_cache . cache_size ( ) == 0 ) :
    lisp_map_cache . delete_cache ( self . group )
    if 9 - 9: oO0o - OoO0O00 . O0 + OoO0O00
    if 59 - 59: OoooooooOO + I11i . oO0o
    if 65 - 65: I1ii11iIi11i * II111iiii % I11i + II111iiii . i1IIi / ooOoO0o
    if 74 - 74: OoOoOO00 % OoO0O00 . OoOoOO00
 def add_source_entry ( self , source_mc ) :
  if ( self . source_cache == None ) : self . source_cache = lisp_cache ( )
  self . source_cache . add_cache ( source_mc . eid , source_mc )
  if 16 - 16: OoO0O00 / Ii1I * i11iIiiIii / o0oOOo0O0Ooo + I1Ii111
  if 21 - 21: I11i % I1ii11iIi11i
 def lookup_source_cache ( self , source , exact ) :
  if ( self . source_cache == None ) : return ( None )
  return ( self . source_cache . lookup_cache ( source , exact ) )
  if 8 - 8: OOooOOo % OoO0O00 + O0 - o0oOOo0O0Ooo
  if 46 - 46: Oo0Ooo . ooOoO0o + OoOoOO00 - I11i / i11iIiiIii . iII111i
 def dynamic_eid_configured ( self ) :
  return ( self . dynamic_eids != None )
  if 80 - 80: II111iiii + OoO0O00 % ooOoO0o + i11iIiiIii
  if 30 - 30: Ii1I / I1ii11iIi11i % IiII - Oo0Ooo
 def star_secondary_iid ( self , prefix ) :
  if ( self . secondary_iid == None ) : return ( prefix )
  o0OOoOO = "," + str ( self . secondary_iid )
  return ( prefix . replace ( o0OOoOO , o0OOoOO + "*" ) )
  if 100 - 100: IiII . I1Ii111 * oO0o % OoO0O00 . iIii1I11I1II1 * Oo0Ooo
  if 100 - 100: IiII - OoOoOO00 % iII111i
 def increment_decap_stats ( self , packet ) :
  IIiII = packet . udp_dport
  if ( IIiII == LISP_DATA_PORT ) :
   OoOOo = self . get_rloc ( packet . outer_dest )
  else :
   if 24 - 24: Oo0Ooo / OoO0O00 + i11iIiiIii
   if 81 - 81: i11iIiiIii . iIii1I11I1II1 - OoooooooOO
   if 52 - 52: O0 - I1Ii111 + oO0o % ooOoO0o . oO0o
   if 60 - 60: oO0o + o0oOOo0O0Ooo - OOooOOo % o0oOOo0O0Ooo . I11i + OoO0O00
   for OoOOo in self . rloc_set :
    if ( OoOOo . translated_port != 0 ) : break
    if 27 - 27: i11iIiiIii - I1ii11iIi11i * I1Ii111 . I1IiiI / OoO0O00 * ooOoO0o
    if 42 - 42: OOooOOo
  if ( OoOOo != None ) : OoOOo . stats . increment ( len ( packet . packet ) )
  self . stats . increment ( len ( packet . packet ) )
  if 36 - 36: OoooooooOO + ooOoO0o + iII111i
  if 30 - 30: i1IIi % Ii1I
 def rtrs_in_rloc_set ( self ) :
  for OoOOo in self . rloc_set :
   if ( OoOOo . is_rtr ( ) ) : return ( True )
   if 18 - 18: o0oOOo0O0Ooo % I1ii11iIi11i . Ii1I . O0 * II111iiii + I1ii11iIi11i
  return ( False )
  if 45 - 45: OoO0O00 / I1ii11iIi11i * ooOoO0o * OOooOOo % i11iIiiIii * iII111i
  if 33 - 33: oO0o . iII111i + Oo0Ooo
  if 33 - 33: ooOoO0o
class lisp_dynamic_eid ( ) :
 def __init__ ( self ) :
  self . dynamic_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . uptime = lisp_get_timestamp ( )
  self . interface = None
  self . last_packet = None
  self . timeout = LISP_DEFAULT_DYN_EID_TIMEOUT
  if 46 - 46: OoOoOO00 / iII111i - OoO0O00 . o0oOOo0O0Ooo
  if 50 - 50: I1Ii111 . O0 . OoOoOO00 + I1Ii111 + OoooooooOO . i11iIiiIii
 def get_timeout ( self , interface ) :
  try :
   oooOoOoooo = lisp_myinterfaces [ interface ]
   self . timeout = oooOoOoooo . dynamic_eid_timeout
  except :
   self . timeout = LISP_DEFAULT_DYN_EID_TIMEOUT
   if 26 - 26: OoooooooOO % iIii1I11I1II1 - IiII
   if 3 - 3: oO0o * II111iiii . O0
   if 19 - 19: I1IiiI / I1IiiI / Oo0Ooo + oO0o + i1IIi
   if 31 - 31: iII111i / OoooooooOO - I1Ii111 . iII111i
class lisp_group_mapping ( ) :
 def __init__ ( self , group_name , ms_name , group_prefix , sources , rle_addr ) :
  self . group_name = group_name
  self . group_prefix = group_prefix
  self . use_ms_name = ms_name
  self . sources = sources
  self . rle_address = rle_addr
  if 38 - 38: ooOoO0o . OoooooooOO - II111iiii * i11iIiiIii / i1IIi . OoooooooOO
  if 51 - 51: oO0o - I1ii11iIi11i + I1ii11iIi11i
 def add_group ( self ) :
  lisp_group_mapping_list [ self . group_name ] = self
  if 100 - 100: I11i - I1ii11iIi11i . i1IIi
  if 85 - 85: II111iiii
  if 58 - 58: i1IIi - OoO0O00 + ooOoO0o
lisp_site_flags = {
 "P" : "ETR is {}Requesting Map-Server to Proxy Map-Reply" ,
 "S" : "ETR is {}LISP-SEC capable" ,
 "I" : "xTR-ID and site-ID are {}included in Map-Register" ,
 "T" : "Use Map-Register TTL field to timeout registration is {}set" ,
 "R" : "Merging registrations are {}requested" ,
 "M" : "ETR is {}a LISP Mobile-Node" ,
 "N" : "ETR is {}requesting Map-Notify messages from Map-Server"
 }
if 6 - 6: IiII % I1IiiI + OoooooooOO * oO0o . iII111i + oO0o
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
  if 4 - 4: I11i % I1IiiI
  if 72 - 72: I1IiiI % II111iiii % iII111i / OoOoOO00
  if 96 - 96: OoOoOO00 % Ii1I
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
  if 50 - 50: IiII - II111iiii
  if 10 - 10: OoooooooOO % Ii1I * OOooOOo + IiII * oO0o
 def print_eid_tuple ( self ) :
  return ( lisp_print_eid_tuple ( self . eid , self . group ) )
  if 13 - 13: II111iiii
  if 14 - 14: i11iIiiIii . IiII
 def print_flags ( self , html ) :
  if ( html == False ) :
   Oo0O = "{}-{}-{}-{}-{}-{}-{}" . format ( "P" if self . proxy_reply_requested else "p" ,
   # ooOoO0o % Oo0Ooo + OOooOOo % II111iiii * OoOoOO00
 "S" if self . lisp_sec_present else "s" ,
 "I" if self . xtr_id_present else "i" ,
 "T" if self . use_register_ttl_requested else "t" ,
 "R" if self . merge_register_requested else "r" ,
 "M" if self . mobile_node_requested else "m" ,
 "N" if self . map_notify_requested else "n" )
  else :
   OOo0OOo = self . print_flags ( False )
   OOo0OOo = OOo0OOo . split ( "-" )
   Oo0O = ""
   for i1iiIIi1i1iI in OOo0OOo :
    I1ooOO = lisp_site_flags [ i1iiIIi1i1iI . upper ( ) ]
    I1ooOO = I1ooOO . format ( "" if i1iiIIi1i1iI . isupper ( ) else "not " )
    Oo0O += lisp_span ( i1iiIIi1i1iI , I1ooOO )
    if ( i1iiIIi1i1iI . lower ( ) != "n" ) : Oo0O += "-"
    if 16 - 16: I11i % OoOoOO00 * I1IiiI . I11i % I1IiiI . Oo0Ooo
    if 99 - 99: OoO0O00
  return ( Oo0O )
  if 49 - 49: iII111i + OoOoOO00
  if 33 - 33: ooOoO0o
 def copy_state_to_parent ( self , child ) :
  self . xtr_id = child . xtr_id
  self . site_id = child . site_id
  self . first_registered = child . first_registered
  self . last_registered = child . last_registered
  self . last_registerer = child . last_registerer
  self . register_ttl = child . register_ttl
  if ( self . registered == False ) :
   self . first_registered = lisp_get_timestamp ( )
   if 19 - 19: I1Ii111 % IiII
  self . auth_sha1_or_sha2 = child . auth_sha1_or_sha2
  self . registered = child . registered
  self . proxy_reply_requested = child . proxy_reply_requested
  self . lisp_sec_present = child . lisp_sec_present
  self . xtr_id_present = child . xtr_id_present
  self . use_register_ttl_requested = child . use_register_ttl_requested
  self . merge_register_requested = child . merge_register_requested
  self . mobile_node_requested = child . mobile_node_requested
  self . map_notify_requested = child . map_notify_requested
  if 94 - 94: I1Ii111 * I1ii11iIi11i * I1ii11iIi11i - o0oOOo0O0Ooo . i11iIiiIii
  if 16 - 16: i1IIi
 def build_sort_key ( self ) :
  o0oOO0OOoO = lisp_cache ( )
  Iii11i1 , iii11 = o0oOO0OOoO . build_key ( self . eid )
  ooO0O = ""
  if ( self . group . is_null ( ) == False ) :
   Ii1II11I1iI11 , ooO0O = o0oOO0OOoO . build_key ( self . group )
   ooO0O = "-" + ooO0O [ 0 : 12 ] + "-" + str ( Ii1II11I1iI11 ) + "-" + ooO0O [ 12 : : ]
   if 68 - 68: I1IiiI - OoOoOO00 - iIii1I11I1II1 % i11iIiiIii * OoOoOO00 * OoO0O00
  iii11 = iii11 [ 0 : 12 ] + "-" + str ( Iii11i1 ) + "-" + iii11 [ 12 : : ] + ooO0O
  del ( o0oOO0OOoO )
  return ( iii11 )
  if 97 - 97: OoO0O00 - IiII + ooOoO0o % iIii1I11I1II1 % iII111i
  if 100 - 100: IiII - Ii1I * iIii1I11I1II1 . iII111i . i1IIi % Oo0Ooo
 def merge_in_site_eid ( self , child ) :
  i11I1i = False
  if ( self . group . is_null ( ) ) :
   self . merge_rlocs_in_site_eid ( )
  else :
   i11I1i = self . merge_rles_in_site_eid ( )
   if 8 - 8: oO0o % OOooOOo - i11iIiiIii - i1IIi / I1IiiI - OoooooooOO
   if 46 - 46: Oo0Ooo % i11iIiiIii * o0oOOo0O0Ooo
   if 33 - 33: oO0o * ooOoO0o * Ii1I * IiII
   if 39 - 39: i1IIi
   if 79 - 79: ooOoO0o - II111iiii - oO0o
   if 55 - 55: iII111i % iIii1I11I1II1 + Ii1I + oO0o . i11iIiiIii - OOooOOo
  if ( child != None ) :
   self . copy_state_to_parent ( child )
   self . map_registers_received += 1
   if 14 - 14: oO0o - i11iIiiIii / OoOoOO00 % o0oOOo0O0Ooo / IiII * I1IiiI
  return ( i11I1i )
  if 2 - 2: i1IIi / I1Ii111 + I1IiiI + I1ii11iIi11i - o0oOOo0O0Ooo + iIii1I11I1II1
  if 78 - 78: I1ii11iIi11i % i1IIi . I1Ii111 + Oo0Ooo . o0oOOo0O0Ooo % II111iiii
 def copy_rloc_records ( self ) :
  O0ii1i = [ ]
  for IiI1I1iii11 in self . registered_rlocs :
   O0ii1i . append ( copy . deepcopy ( IiI1I1iii11 ) )
   if 75 - 75: I1IiiI * oO0o / Oo0Ooo - II111iiii . OoO0O00
  return ( O0ii1i )
  if 8 - 8: iII111i . i11iIiiIii . IiII . I1ii11iIi11i + I11i
  if 24 - 24: I1IiiI - I1IiiI . Oo0Ooo * IiII + I1IiiI / i1IIi
 def merge_rlocs_in_site_eid ( self ) :
  self . registered_rlocs = [ ]
  for Iiii1IIIiIi in self . individual_registrations . values ( ) :
   if ( self . site_id != Iiii1IIIiIi . site_id ) : continue
   if ( Iiii1IIIiIi . registered == False ) : continue
   self . registered_rlocs += Iiii1IIIiIi . copy_rloc_records ( )
   if 18 - 18: II111iiii / iIii1I11I1II1 * I1ii11iIi11i . ooOoO0o * ooOoO0o
   if 89 - 89: I1IiiI - Oo0Ooo
   if 28 - 28: OoooooooOO . i1IIi . I1Ii111
   if 53 - 53: OoO0O00 * Oo0Ooo + Oo0Ooo
   if 62 - 62: OOooOOo - i1IIi + i11iIiiIii * I11i / OoO0O00
   if 84 - 84: IiII * OOooOOo
  O0ii1i = [ ]
  for IiI1I1iii11 in self . registered_rlocs :
   if ( IiI1I1iii11 . rloc . is_null ( ) or len ( O0ii1i ) == 0 ) :
    O0ii1i . append ( IiI1I1iii11 )
    continue
    if 1 - 1: iII111i * I1IiiI . o0oOOo0O0Ooo . IiII
   for I1i in O0ii1i :
    if ( I1i . rloc . is_null ( ) ) : continue
    if ( IiI1I1iii11 . rloc . is_exact_match ( I1i . rloc ) ) : break
    if 63 - 63: o0oOOo0O0Ooo + i1IIi
   if ( I1i == O0ii1i [ - 1 ] ) : O0ii1i . append ( IiI1I1iii11 )
   if 31 - 31: OoooooooOO + o0oOOo0O0Ooo % OoooooooOO - II111iiii . OoooooooOO
  self . registered_rlocs = O0ii1i
  if 42 - 42: I11i * OOooOOo * OoOoOO00 % I1Ii111
  if 25 - 25: IiII
  if 60 - 60: oO0o - iIii1I11I1II1 / I1Ii111 * OoO0O00 . oO0o
  if 29 - 29: Oo0Ooo
  if ( len ( self . registered_rlocs ) == 0 ) : self . registered = False
  return
  if 82 - 82: OoO0O00
  if 93 - 93: Oo0Ooo
 def merge_rles_in_site_eid ( self ) :
  if 71 - 71: OoooooooOO - IiII . I1ii11iIi11i + OoooooooOO
  if 97 - 97: Ii1I - I1IiiI . OoooooooOO * IiII
  if 17 - 17: OoO0O00 / II111iiii / II111iiii / II111iiii
  if 70 - 70: OoO0O00 + O0 * OoO0O00
  Iii11I1i = { }
  for IiI1I1iii11 in self . registered_rlocs :
   if ( IiI1I1iii11 . rle == None ) : continue
   for IIi1i1111i in IiI1I1iii11 . rle . rle_nodes :
    o0o0O00 = IIi1i1111i . address . print_address_no_iid ( )
    Iii11I1i [ o0o0O00 ] = IIi1i1111i . address
    if 22 - 22: i1IIi % Oo0Ooo / oO0o % OoOoOO00 / OoOoOO00
   break
   if 79 - 79: IiII % OoooooooOO
   if 51 - 51: iII111i . oO0o % ooOoO0o % Ii1I . o0oOOo0O0Ooo
   if 43 - 43: II111iiii
   if 72 - 72: OoOoOO00 * oO0o - ooOoO0o / iII111i
   if 8 - 8: OoO0O00 * I1ii11iIi11i
  self . merge_rlocs_in_site_eid ( )
  if 18 - 18: O0 + I1Ii111 . I1ii11iIi11i
  if 48 - 48: Ii1I . o0oOOo0O0Ooo * O0 / OoooooooOO + I1Ii111 + Oo0Ooo
  if 92 - 92: Ii1I - o0oOOo0O0Ooo % I1IiiI + I1Ii111
  if 3 - 3: iIii1I11I1II1 + i11iIiiIii
  if 49 - 49: OoOoOO00 % iIii1I11I1II1 + I1Ii111
  if 38 - 38: i11iIiiIii
  if 75 - 75: iIii1I11I1II1 / OoO0O00 * OOooOOo % O0
  if 82 - 82: Oo0Ooo / i1IIi . i1IIi / oO0o
  IIOO00 = [ ]
  for IiI1I1iii11 in self . registered_rlocs :
   if ( self . registered_rlocs . index ( IiI1I1iii11 ) == 0 ) :
    IIOO00 . append ( IiI1I1iii11 )
    continue
    if 14 - 14: iII111i . iII111i . I11i % I11i * oO0o
   if ( IiI1I1iii11 . rle == None ) : IIOO00 . append ( IiI1I1iii11 )
   if 77 - 77: I1ii11iIi11i
  self . registered_rlocs = IIOO00
  if 5 - 5: II111iiii . I1ii11iIi11i
  if 96 - 96: o0oOOo0O0Ooo + OoooooooOO - iII111i * O0
  if 12 - 12: OoO0O00 % i11iIiiIii - iII111i
  if 61 - 61: IiII / oO0o . I1Ii111 - IiII * IiII - iII111i
  if 49 - 49: Ii1I
  if 91 - 91: Ii1I / ooOoO0o % iII111i
  if 75 - 75: i1IIi
  iiiI1i1111II = lisp_rle ( "" )
  II1iiI = { }
  OO000 = None
  for Iiii1IIIiIi in self . individual_registrations . values ( ) :
   if ( Iiii1IIIiIi . registered == False ) : continue
   ii1I1 = Iiii1IIIiIi . registered_rlocs [ 0 ] . rle
   if ( ii1I1 == None ) : continue
   if 27 - 27: I11i + iIii1I11I1II1 * I1IiiI
   OO000 = Iiii1IIIiIi . registered_rlocs [ 0 ] . rloc_name
   for IIIiIII in ii1I1 . rle_nodes :
    o0o0O00 = IIIiIII . address . print_address_no_iid ( )
    if ( II1iiI . has_key ( o0o0O00 ) ) : break
    if 3 - 3: OoOoOO00 * OOooOOo - IiII - II111iiii * oO0o
    IIi1i1111i = lisp_rle_node ( )
    IIi1i1111i . address . copy_address ( IIIiIII . address )
    IIi1i1111i . level = IIIiIII . level
    IIi1i1111i . rloc_name = OO000
    iiiI1i1111II . rle_nodes . append ( IIi1i1111i )
    II1iiI [ o0o0O00 ] = IIIiIII . address
    if 23 - 23: I11i * I1ii11iIi11i . I11i
    if 70 - 70: i1IIi * I1ii11iIi11i . oO0o - I1IiiI * Ii1I * iII111i
    if 11 - 11: Oo0Ooo + I1ii11iIi11i
    if 92 - 92: iII111i / II111iiii + i1IIi / I1ii11iIi11i
    if 67 - 67: iII111i / IiII + I1IiiI + IiII % OoOoOO00 % I1ii11iIi11i
    if 7 - 7: I1ii11iIi11i % OoOoOO00 - O0 . I1Ii111
  if ( len ( iiiI1i1111II . rle_nodes ) == 0 ) : iiiI1i1111II = None
  if ( len ( self . registered_rlocs ) != 0 ) :
   self . registered_rlocs [ 0 ] . rle = iiiI1i1111II
   if ( OO000 ) : self . registered_rlocs [ 0 ] . rloc_name = None
   if 9 - 9: Ii1I . OoooooooOO / ooOoO0o + i1IIi
   if 90 - 90: oO0o - OoOoOO00 % ooOoO0o
   if 83 - 83: OOooOOo - I1ii11iIi11i + OoO0O00
   if 99 - 99: iII111i - OoOoOO00 % ooOoO0o
   if 27 - 27: oO0o . oO0o * iII111i % iIii1I11I1II1
  if ( Iii11I1i . keys ( ) == II1iiI . keys ( ) ) : return ( False )
  if 81 - 81: iII111i * II111iiii
  lprint ( "{} {} from {} to {}" . format ( green ( self . print_eid_tuple ( ) , False ) , bold ( "RLE change" , False ) ,
  # OoooooooOO + i11iIiiIii
 Iii11I1i . keys ( ) , II1iiI . keys ( ) ) )
  if 11 - 11: OoooooooOO % oO0o - OoO0O00
  return ( True )
  if 49 - 49: ooOoO0o + iII111i % OoooooooOO / Oo0Ooo % i1IIi
  if 50 - 50: OoO0O00
 def add_cache ( self ) :
  if ( self . group . is_null ( ) ) :
   lisp_sites_by_eid . add_cache ( self . eid , self )
  else :
   ooOoOO0Oo = lisp_sites_by_eid . lookup_cache ( self . group , True )
   if ( ooOoOO0Oo == None ) :
    ooOoOO0Oo = lisp_site_eid ( self . site )
    ooOoOO0Oo . eid . copy_address ( self . group )
    ooOoOO0Oo . group . copy_address ( self . group )
    lisp_sites_by_eid . add_cache ( self . group , ooOoOO0Oo )
    if 52 - 52: o0oOOo0O0Ooo + O0
    if 13 - 13: OoO0O00
    if 56 - 56: OoOoOO00 . ooOoO0o * oO0o - I11i
    if 47 - 47: oO0o . i1IIi * I1ii11iIi11i % OOooOOo % IiII / Oo0Ooo
    if 39 - 39: i11iIiiIii . OOooOOo + Oo0Ooo
    ooOoOO0Oo . parent_for_more_specifics = self . parent_for_more_specifics
    if 92 - 92: O0 * Oo0Ooo / o0oOOo0O0Ooo % OoO0O00
   if ( self . eid . is_null ( ) ) : self . eid . make_default_route ( ooOoOO0Oo . group )
   ooOoOO0Oo . add_source_entry ( self )
   if 87 - 87: OoooooooOO / I11i . O0
   if 77 - 77: OOooOOo + oO0o * iIii1I11I1II1 / oO0o / OOooOOo . i11iIiiIii
   if 92 - 92: Oo0Ooo . o0oOOo0O0Ooo % OoooooooOO * i11iIiiIii * OoO0O00 * o0oOOo0O0Ooo
 def delete_cache ( self ) :
  if ( self . group . is_null ( ) ) :
   lisp_sites_by_eid . delete_cache ( self . eid )
  else :
   ooOoOO0Oo = lisp_sites_by_eid . lookup_cache ( self . group , True )
   if ( ooOoOO0Oo == None ) : return
   if 48 - 48: iII111i * I1ii11iIi11i * oO0o % O0 . OoO0O00
   Iiii1IIIiIi = ooOoOO0Oo . lookup_source_cache ( self . eid , True )
   if ( Iiii1IIIiIi == None ) : return
   if 11 - 11: OOooOOo / o0oOOo0O0Ooo
   if ( ooOoOO0Oo . source_cache == None ) : return
   if 98 - 98: oO0o + I11i . oO0o
   ooOoOO0Oo . source_cache . delete_cache ( self . eid )
   if ( ooOoOO0Oo . source_cache . cache_size ( ) == 0 ) :
    lisp_sites_by_eid . delete_cache ( self . group )
    if 10 - 10: iII111i + i1IIi . I11i % ooOoO0o / ooOoO0o
    if 86 - 86: Oo0Ooo
    if 7 - 7: iIii1I11I1II1
    if 86 - 86: IiII + iII111i * II111iiii - IiII - o0oOOo0O0Ooo
 def add_source_entry ( self , source_se ) :
  if ( self . source_cache == None ) : self . source_cache = lisp_cache ( )
  self . source_cache . add_cache ( source_se . eid , source_se )
  if 8 - 8: OOooOOo . Ii1I
  if 15 - 15: ooOoO0o / OOooOOo + i1IIi / Ii1I / OOooOOo
 def lookup_source_cache ( self , source , exact ) :
  if ( self . source_cache == None ) : return ( None )
  return ( self . source_cache . lookup_cache ( source , exact ) )
  if 47 - 47: Oo0Ooo + oO0o % OoooooooOO
  if 23 - 23: I1Ii111 / i11iIiiIii - ooOoO0o * iII111i - Ii1I . iIii1I11I1II1
 def is_star_g ( self ) :
  if ( self . group . is_null ( ) ) : return ( False )
  return ( self . eid . is_exact_match ( self . group ) )
  if 11 - 11: I11i % OoOoOO00 * Oo0Ooo
  if 48 - 48: OOooOOo
 def eid_record_matches ( self , eid_record ) :
  if ( self . eid . is_exact_match ( eid_record . eid ) == False ) : return ( False )
  if ( eid_record . group . is_null ( ) ) : return ( True )
  return ( eid_record . group . is_exact_match ( self . group ) )
  if 66 - 66: iII111i - I1Ii111 - i11iIiiIii . o0oOOo0O0Ooo + Oo0Ooo
  if 90 - 90: O0 - i11iIiiIii * ooOoO0o . I1ii11iIi11i . Ii1I - OoooooooOO
 def inherit_from_ams_parent ( self ) :
  IiI1 = self . parent_for_more_specifics
  if ( IiI1 == None ) : return
  self . force_proxy_reply = IiI1 . force_proxy_reply
  self . force_nat_proxy_reply = IiI1 . force_nat_proxy_reply
  self . force_ttl = IiI1 . force_ttl
  self . pitr_proxy_reply_drop = IiI1 . pitr_proxy_reply_drop
  self . proxy_reply_action = IiI1 . proxy_reply_action
  self . echo_nonce_capable = IiI1 . echo_nonce_capable
  self . policy = IiI1 . policy
  self . require_signature = IiI1 . require_signature
  if 23 - 23: o0oOOo0O0Ooo
  if 88 - 88: I1Ii111 + iIii1I11I1II1 / o0oOOo0O0Ooo
 def rtrs_in_rloc_set ( self ) :
  for IiI1I1iii11 in self . registered_rlocs :
   if ( IiI1I1iii11 . is_rtr ( ) ) : return ( True )
   if 93 - 93: ooOoO0o % iIii1I11I1II1 - OOooOOo . IiII + ooOoO0o
  return ( False )
  if 63 - 63: I1ii11iIi11i / OOooOOo
  if 28 - 28: I11i / I1Ii111 + IiII * OoooooooOO - iIii1I11I1II1
 def is_rtr_in_rloc_set ( self , rtr_rloc ) :
  for IiI1I1iii11 in self . registered_rlocs :
   if ( IiI1I1iii11 . rloc . is_exact_match ( rtr_rloc ) == False ) : continue
   if ( IiI1I1iii11 . is_rtr ( ) ) : return ( True )
   if 6 - 6: I11i % o0oOOo0O0Ooo / OoooooooOO . I1Ii111
  return ( False )
  if 17 - 17: I1ii11iIi11i + OoooooooOO / iIii1I11I1II1 . II111iiii + Oo0Ooo
  if 7 - 7: O0 - I1ii11iIi11i - iIii1I11I1II1
 def is_rloc_in_rloc_set ( self , rloc ) :
  for IiI1I1iii11 in self . registered_rlocs :
   if ( IiI1I1iii11 . rle ) :
    for iiiI1i1111II in IiI1I1iii11 . rle . rle_nodes :
     if ( iiiI1i1111II . address . is_exact_match ( rloc ) ) : return ( True )
     if 96 - 96: OoOoOO00 . I1IiiI . I11i * OoooooooOO + OoooooooOO * O0
     if 90 - 90: I11i + I1ii11iIi11i + OoooooooOO + OoOoOO00 + IiII / iII111i
   if ( IiI1I1iii11 . rloc . is_exact_match ( rloc ) ) : return ( True )
   if 75 - 75: i11iIiiIii
  return ( False )
  if 27 - 27: I11i - IiII - I1Ii111
  if 90 - 90: OoO0O00 . oO0o * O0 / I11i % O0 + I1Ii111
 def do_rloc_sets_match ( self , prev_rloc_set ) :
  if ( len ( self . registered_rlocs ) != len ( prev_rloc_set ) ) : return ( False )
  if 48 - 48: iIii1I11I1II1 . i11iIiiIii / OoooooooOO . i1IIi . o0oOOo0O0Ooo
  for IiI1I1iii11 in prev_rloc_set :
   oO00Ooo0o = IiI1I1iii11 . rloc
   if ( self . is_rloc_in_rloc_set ( oO00Ooo0o ) == False ) : return ( False )
   if 84 - 84: Ii1I
  return ( True )
  if 92 - 92: I11i
  if 64 - 64: iII111i / iII111i * iII111i % O0 / IiII . I1ii11iIi11i
  if 23 - 23: i1IIi / I1ii11iIi11i + o0oOOo0O0Ooo
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
   if 82 - 82: O0 * ooOoO0o * iIii1I11I1II1 . i1IIi
  self . last_used = 0
  self . last_reply = 0
  self . last_nonce = 0
  self . map_requests_sent = 0
  self . neg_map_replies_received = 0
  self . total_rtt = 0
  if 47 - 47: I11i * I11i . OoOoOO00
  if 68 - 68: OoooooooOO + OoOoOO00 + i11iIiiIii
 def resolve_dns_name ( self ) :
  if ( self . dns_name == None ) : return
  if ( self . last_dns_resolve and
 time . time ( ) - self . last_dns_resolve < 30 ) : return
  if 89 - 89: Oo0Ooo + Ii1I * O0 - I1Ii111
  try :
   iI1 = socket . gethostbyname_ex ( self . dns_name )
   self . last_dns_resolve = lisp_get_timestamp ( )
   iiOOO0o = iI1 [ 2 ]
  except :
   return
   if 59 - 59: OOooOOo * i1IIi
   if 26 - 26: OOooOOo % ooOoO0o
   if 80 - 80: o0oOOo0O0Ooo . iII111i . ooOoO0o + OOooOOo * I1IiiI / O0
   if 61 - 61: I11i % OOooOOo + i11iIiiIii + I11i
   if 69 - 69: OoOoOO00 + OoOoOO00 + o0oOOo0O0Ooo / iIii1I11I1II1 * OoO0O00
   if 44 - 44: II111iiii / o0oOOo0O0Ooo
  if ( len ( iiOOO0o ) <= self . a_record_index ) :
   self . delete_mr ( )
   return
   if 81 - 81: I1Ii111 . Ii1I * ooOoO0o . IiII - OoOoOO00
   if 79 - 79: ooOoO0o - O0
  o0o0O00 = iiOOO0o [ self . a_record_index ]
  if ( o0o0O00 != self . map_resolver . print_address_no_iid ( ) ) :
   self . delete_mr ( )
   self . map_resolver . store_address ( o0o0O00 )
   self . insert_mr ( )
   if 56 - 56: ooOoO0o
   if 89 - 89: O0 % iIii1I11I1II1 / OoOoOO00 - I1Ii111 - I1IiiI
   if 60 - 60: IiII % i11iIiiIii / OOooOOo
   if 43 - 43: i11iIiiIii * II111iiii + ooOoO0o - OoooooooOO * II111iiii / OoO0O00
   if 92 - 92: O0 - ooOoO0o % iII111i
   if 83 - 83: I1ii11iIi11i / OoOoOO00 % OoooooooOO
  if ( lisp_is_decent_dns_suffix ( self . dns_name ) == False ) : return
  if ( self . a_record_index != 0 ) : return
  if 54 - 54: I11i / I1IiiI * IiII - iII111i
  for o0o0O00 in iiOOO0o [ 1 : : ] :
   oOO0oo = lisp_address ( LISP_AFI_NONE , o0o0O00 , 0 , 0 )
   oOO0O000OOo0 = lisp_get_map_resolver ( oOO0oo , None )
   if ( oOO0O000OOo0 != None and oOO0O000OOo0 . a_record_index == iiOOO0o . index ( o0o0O00 ) ) :
    continue
    if 37 - 37: i1IIi * I1Ii111 / I11i * II111iiii + OoooooooOO . OoO0O00
   oOO0O000OOo0 = lisp_mr ( o0o0O00 , None , None )
   oOO0O000OOo0 . a_record_index = iiOOO0o . index ( o0o0O00 )
   oOO0O000OOo0 . dns_name = self . dns_name
   oOO0O000OOo0 . last_dns_resolve = lisp_get_timestamp ( )
   if 22 - 22: OoOoOO00 + OoooooooOO - I1Ii111
   if 82 - 82: Ii1I % I1Ii111 / ooOoO0o
   if 86 - 86: II111iiii - iIii1I11I1II1 + oO0o + I1IiiI
   if 29 - 29: Ii1I % OoooooooOO * II111iiii
   if 88 - 88: I1Ii111 + I11i + I1Ii111 % OoO0O00 / I1ii11iIi11i - I11i
  iIi11ii1 = [ ]
  for oOO0O000OOo0 in lisp_map_resolvers_list . values ( ) :
   if ( self . dns_name != oOO0O000OOo0 . dns_name ) : continue
   oOO0oo = oOO0O000OOo0 . map_resolver . print_address_no_iid ( )
   if ( oOO0oo in iiOOO0o ) : continue
   iIi11ii1 . append ( oOO0O000OOo0 )
   if 55 - 55: I1ii11iIi11i - I11i
  for oOO0O000OOo0 in iIi11ii1 : oOO0O000OOo0 . delete_mr ( )
  if 73 - 73: i11iIiiIii . OoO0O00 + OoO0O00 - OOooOOo % OOooOOo - OoO0O00
  if 5 - 5: I1ii11iIi11i + i1IIi * I11i % iII111i
 def insert_mr ( self ) :
  iii11 = self . mr_name + self . map_resolver . print_address ( )
  lisp_map_resolvers_list [ iii11 ] = self
  if 96 - 96: ooOoO0o % I1ii11iIi11i % i11iIiiIii * I11i * iII111i . i11iIiiIii
  if 65 - 65: i11iIiiIii / o0oOOo0O0Ooo % I1ii11iIi11i - O0 % OoooooooOO / o0oOOo0O0Ooo
 def delete_mr ( self ) :
  iii11 = self . mr_name + self . map_resolver . print_address ( )
  if ( lisp_map_resolvers_list . has_key ( iii11 ) == False ) : return
  lisp_map_resolvers_list . pop ( iii11 )
  if 36 - 36: iII111i * OoO0O00 / OOooOOo * IiII * iIii1I11I1II1 / IiII
  if 79 - 79: iIii1I11I1II1 - iIii1I11I1II1 * I1ii11iIi11i
  if 96 - 96: iII111i / i11iIiiIii / oO0o + Oo0Ooo
class lisp_ddt_root ( ) :
 def __init__ ( self ) :
  self . root_address = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . public_key = ""
  self . priority = 0
  self . weight = 0
  if 65 - 65: OoOoOO00
  if 87 - 87: I11i % i1IIi + i11iIiiIii * II111iiii
  if 58 - 58: OoO0O00 * I1IiiI - II111iiii / Ii1I - I1IiiI % OoooooooOO
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
  if 33 - 33: IiII / i1IIi + I1Ii111
  if 5 - 5: O0 / iII111i % II111iiii . Oo0Ooo - I11i
 def print_referral ( self , eid_indent , referral_indent ) :
  OO00OoooOoO0 = lisp_print_elapsed ( self . uptime )
  iiIIIiiii = lisp_print_future ( self . expires )
  lprint ( "{}Referral EID {}, uptime/expires {}/{}, {} referrals:" . format ( eid_indent , green ( self . eid . print_prefix ( ) , False ) , OO00OoooOoO0 ,
  # OoOoOO00 - OoOoOO00 % II111iiii + i1IIi + I1IiiI
 iiIIIiiii , len ( self . referral_set ) ) )
  if 75 - 75: OoooooooOO . I11i - OoOoOO00
  for ooO in self . referral_set . values ( ) :
   ooO . print_ref_node ( referral_indent )
   if 93 - 93: OoOoOO00 . I1Ii111 % I1ii11iIi11i
   if 58 - 58: OoooooooOO . i1IIi . Oo0Ooo - o0oOOo0O0Ooo / oO0o * I1Ii111
   if 6 - 6: oO0o - OoO0O00
 def print_referral_type ( self ) :
  if ( self . eid . afi == LISP_AFI_ULTIMATE_ROOT ) : return ( "root" )
  if ( self . referral_type == LISP_DDT_ACTION_NULL ) :
   return ( "null-referral" )
   if 44 - 44: Oo0Ooo + I1ii11iIi11i % Oo0Ooo / I11i
  if ( self . referral_type == LISP_DDT_ACTION_SITE_NOT_FOUND ) :
   return ( "no-site-action" )
   if 57 - 57: Oo0Ooo + Ii1I * OoooooooOO
  if ( self . referral_type > LISP_DDT_ACTION_MAX ) :
   return ( "invalid-action" )
   if 30 - 30: O0
  return ( lisp_map_referral_action_string [ self . referral_type ] )
  if 70 - 70: oO0o
  if 89 - 89: O0
 def print_eid_tuple ( self ) :
  return ( lisp_print_eid_tuple ( self . eid , self . group ) )
  if 3 - 3: iII111i - O0 / I11i
  if 46 - 46: I1IiiI . OoooooooOO / iIii1I11I1II1 - ooOoO0o * OOooOOo
 def print_ttl ( self ) :
  iiI = self . referral_ttl
  if ( iiI < 60 ) : return ( str ( iiI ) + " secs" )
  if 55 - 55: o0oOOo0O0Ooo + iIii1I11I1II1 / I11i
  if ( ( iiI % 60 ) == 0 ) :
   iiI = str ( iiI / 60 ) + " mins"
  else :
   iiI = str ( iiI ) + " secs"
   if 97 - 97: i11iIiiIii
  return ( iiI )
  if 71 - 71: oO0o + Oo0Ooo
  if 7 - 7: OoOoOO00 / I1ii11iIi11i * i1IIi
 def is_referral_negative ( self ) :
  return ( self . referral_type in ( LISP_DDT_ACTION_MS_NOT_REG , LISP_DDT_ACTION_DELEGATION_HOLE ,
  # I1Ii111 % o0oOOo0O0Ooo . iII111i * I11i / iIii1I11I1II1 - II111iiii
 LISP_DDT_ACTION_NOT_AUTH ) )
  if 97 - 97: II111iiii * o0oOOo0O0Ooo
  if 13 - 13: o0oOOo0O0Ooo . II111iiii
 def add_cache ( self ) :
  if ( self . group . is_null ( ) ) :
   lisp_referral_cache . add_cache ( self . eid , self )
  else :
   OoOo = lisp_referral_cache . lookup_cache ( self . group , True )
   if ( OoOo == None ) :
    OoOo = lisp_referral ( )
    OoOo . eid . copy_address ( self . group )
    OoOo . group . copy_address ( self . group )
    lisp_referral_cache . add_cache ( self . group , OoOo )
    if 76 - 76: II111iiii + I1Ii111 . OoooooooOO / IiII % i11iIiiIii
   if ( self . eid . is_null ( ) ) : self . eid . make_default_route ( OoOo . group )
   OoOo . add_source_entry ( self )
   if 87 - 87: Ii1I / OoOoOO00 / OOooOOo
   if 11 - 11: o0oOOo0O0Ooo * OoO0O00 . o0oOOo0O0Ooo - I1IiiI / IiII - OOooOOo
   if 19 - 19: i1IIi + IiII . OoO0O00 / O0 - I1Ii111 - Oo0Ooo
 def delete_cache ( self ) :
  if ( self . group . is_null ( ) ) :
   lisp_referral_cache . delete_cache ( self . eid )
  else :
   OoOo = lisp_referral_cache . lookup_cache ( self . group , True )
   if ( OoOo == None ) : return
   if 24 - 24: iII111i + i1IIi
   Iio00OO = OoOo . lookup_source_cache ( self . eid , True )
   if ( Iio00OO == None ) : return
   if 31 - 31: OoOoOO00
   OoOo . source_cache . delete_cache ( self . eid )
   if ( OoOo . source_cache . cache_size ( ) == 0 ) :
    lisp_referral_cache . delete_cache ( self . group )
    if 37 - 37: iIii1I11I1II1 % IiII / i11iIiiIii - oO0o
    if 43 - 43: II111iiii - OoooooooOO
    if 11 - 11: I1IiiI
    if 76 - 76: iII111i - II111iiii % Oo0Ooo . I1Ii111
 def add_source_entry ( self , source_ref ) :
  if ( self . source_cache == None ) : self . source_cache = lisp_cache ( )
  self . source_cache . add_cache ( source_ref . eid , source_ref )
  if 64 - 64: OoO0O00 - OoO0O00
  if 93 - 93: Oo0Ooo . O0
 def lookup_source_cache ( self , source , exact ) :
  if ( self . source_cache == None ) : return ( None )
  return ( self . source_cache . lookup_cache ( source , exact ) )
  if 75 - 75: iII111i * II111iiii - I1IiiI
  if 30 - 30: i1IIi / ooOoO0o . ooOoO0o
  if 22 - 22: I11i % iIii1I11I1II1 - i11iIiiIii * OoOoOO00 - I1Ii111
class lisp_referral_node ( ) :
 def __init__ ( self ) :
  self . referral_address = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . priority = 0
  self . weight = 0
  self . updown = True
  self . map_requests_sent = 0
  self . no_responses = 0
  self . uptime = lisp_get_timestamp ( )
  if 97 - 97: i11iIiiIii . OoOoOO00 + oO0o * O0 % OoO0O00 - Ii1I
  if 46 - 46: I1Ii111
 def print_ref_node ( self , indent ) :
  OOOO0O00o = lisp_print_elapsed ( self . uptime )
  lprint ( "{}referral {}, uptime {}, {}, priority/weight: {}/{}" . format ( indent , red ( self . referral_address . print_address ( ) , False ) , OOOO0O00o ,
  # o0oOOo0O0Ooo * I1Ii111 - I1Ii111 % i11iIiiIii + i1IIi - o0oOOo0O0Ooo
 "up" if self . updown else "down" , self . priority , self . weight ) )
  if 67 - 67: oO0o % iII111i . II111iiii
  if 36 - 36: II111iiii - ooOoO0o
  if 52 - 52: i1IIi + i1IIi * i1IIi / OoOoOO00
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
   if 98 - 98: iII111i . i1IIi + o0oOOo0O0Ooo * OoooooooOO - i11iIiiIii
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
   if 21 - 21: i11iIiiIii . oO0o * o0oOOo0O0Ooo + Oo0Ooo * OoOoOO00 * o0oOOo0O0Ooo
   if 33 - 33: I1IiiI + O0 - I11i
   if 90 - 90: I1Ii111 * OoooooooOO . iIii1I11I1II1 % OoO0O00 / I11i + iII111i
 def resolve_dns_name ( self ) :
  if ( self . dns_name == None ) : return
  if ( self . last_dns_resolve and
 time . time ( ) - self . last_dns_resolve < 30 ) : return
  if 63 - 63: o0oOOo0O0Ooo . IiII . Oo0Ooo - iIii1I11I1II1 / I1Ii111
  try :
   iI1 = socket . gethostbyname_ex ( self . dns_name )
   self . last_dns_resolve = lisp_get_timestamp ( )
   iiOOO0o = iI1 [ 2 ]
  except :
   return
   if 66 - 66: ooOoO0o * I1Ii111 - II111iiii
   if 38 - 38: O0 % I1ii11iIi11i + O0
   if 37 - 37: Oo0Ooo / I1IiiI
   if 23 - 23: II111iiii / iII111i
   if 55 - 55: i11iIiiIii - Ii1I % OoooooooOO * OoooooooOO
   if 92 - 92: iIii1I11I1II1
  if ( len ( iiOOO0o ) <= self . a_record_index ) :
   self . delete_ms ( )
   return
   if 47 - 47: Oo0Ooo + Oo0Ooo * ooOoO0o - OoOoOO00 + II111iiii
   if 10 - 10: II111iiii / ooOoO0o . Ii1I / I1Ii111 / oO0o
  o0o0O00 = iiOOO0o [ self . a_record_index ]
  if ( o0o0O00 != self . map_server . print_address_no_iid ( ) ) :
   self . delete_ms ( )
   self . map_server . store_address ( o0o0O00 )
   self . insert_ms ( )
   if 8 - 8: OOooOOo / ooOoO0o * I11i + OOooOOo * i1IIi
   if 48 - 48: o0oOOo0O0Ooo - I1ii11iIi11i / iII111i
   if 63 - 63: O0 - IiII . OOooOOo % IiII . I1IiiI / oO0o
   if 79 - 79: OoOoOO00
   if 88 - 88: oO0o * o0oOOo0O0Ooo
   if 5 - 5: I11i - I1Ii111 * I11i - II111iiii + OOooOOo + II111iiii
  if ( lisp_is_decent_dns_suffix ( self . dns_name ) == False ) : return
  if ( self . a_record_index != 0 ) : return
  if 91 - 91: i1IIi + Oo0Ooo - I1ii11iIi11i + I1ii11iIi11i * O0 / O0
  for o0o0O00 in iiOOO0o [ 1 : : ] :
   oOO0oo = lisp_address ( LISP_AFI_NONE , o0o0O00 , 0 , 0 )
   oooO0OOo0O0O0 = lisp_get_map_server ( oOO0oo )
   if ( oooO0OOo0O0O0 != None and oooO0OOo0O0O0 . a_record_index == iiOOO0o . index ( o0o0O00 ) ) :
    continue
    if 78 - 78: OoooooooOO
   oooO0OOo0O0O0 = copy . deepcopy ( self )
   oooO0OOo0O0O0 . map_server . store_address ( o0o0O00 )
   oooO0OOo0O0O0 . a_record_index = iiOOO0o . index ( o0o0O00 )
   oooO0OOo0O0O0 . last_dns_resolve = lisp_get_timestamp ( )
   oooO0OOo0O0O0 . insert_ms ( )
   if 8 - 8: Oo0Ooo - Oo0Ooo % O0 - Ii1I / o0oOOo0O0Ooo % Oo0Ooo
   if 51 - 51: iIii1I11I1II1 / iIii1I11I1II1 * I1ii11iIi11i / I11i
   if 18 - 18: Ii1I - i11iIiiIii + OoO0O00 . O0 - iII111i
   if 9 - 9: OoooooooOO / iII111i + o0oOOo0O0Ooo / II111iiii / I1Ii111
   if 44 - 44: I1IiiI / iII111i / Oo0Ooo
  iIi11ii1 = [ ]
  for oooO0OOo0O0O0 in lisp_map_servers_list . values ( ) :
   if ( self . dns_name != oooO0OOo0O0O0 . dns_name ) : continue
   oOO0oo = oooO0OOo0O0O0 . map_server . print_address_no_iid ( )
   if ( oOO0oo in iiOOO0o ) : continue
   iIi11ii1 . append ( oooO0OOo0O0O0 )
   if 66 - 66: I1Ii111 + OoooooooOO % I1IiiI . iII111i * Oo0Ooo + o0oOOo0O0Ooo
  for oooO0OOo0O0O0 in iIi11ii1 : oooO0OOo0O0O0 . delete_ms ( )
  if 96 - 96: OoO0O00 - ooOoO0o * Ii1I
  if 34 - 34: OoO0O00 . Oo0Ooo % Ii1I . IiII + OoOoOO00
 def insert_ms ( self ) :
  iii11 = self . ms_name + self . map_server . print_address ( )
  lisp_map_servers_list [ iii11 ] = self
  if 10 - 10: OoooooooOO * iII111i * ooOoO0o . Ii1I % I1Ii111 / I1ii11iIi11i
  if 71 - 71: Ii1I + IiII
 def delete_ms ( self ) :
  iii11 = self . ms_name + self . map_server . print_address ( )
  if ( lisp_map_servers_list . has_key ( iii11 ) == False ) : return
  lisp_map_servers_list . pop ( iii11 )
  if 10 - 10: II111iiii % o0oOOo0O0Ooo . o0oOOo0O0Ooo % iII111i
  if 2 - 2: OoooooooOO / IiII % Oo0Ooo % iIii1I11I1II1
  if 62 - 62: oO0o
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
  if 47 - 47: I1IiiI - O0 - I1ii11iIi11i . OoOoOO00
  if 98 - 98: o0oOOo0O0Ooo - OoO0O00 . I1ii11iIi11i / OOooOOo
 def add_interface ( self ) :
  lisp_myinterfaces [ self . device ] = self
  if 43 - 43: I1IiiI + OOooOOo + o0oOOo0O0Ooo
  if 44 - 44: o0oOOo0O0Ooo % OoO0O00 . OoooooooOO
 def get_instance_id ( self ) :
  return ( self . instance_id )
  if 21 - 21: Oo0Ooo * Oo0Ooo - iII111i - O0
  if 87 - 87: OOooOOo / I1Ii111 - Ii1I + O0 - oO0o - O0
 def get_socket ( self ) :
  return ( self . raw_socket )
  if 68 - 68: iII111i + II111iiii + I1ii11iIi11i * OOooOOo / oO0o
  if 41 - 41: OOooOOo + Oo0Ooo % I1IiiI
 def get_bridge_socket ( self ) :
  return ( self . bridge_socket )
  if 3 - 3: ooOoO0o * Ii1I
  if 29 - 29: OoooooooOO + OOooOOo
 def does_dynamic_eid_match ( self , eid ) :
  if ( self . dynamic_eid . is_null ( ) ) : return ( False )
  return ( eid . is_more_specific ( self . dynamic_eid ) )
  if 68 - 68: O0 + IiII / iII111i - OoOoOO00
  if 5 - 5: I1IiiI * OoooooooOO - II111iiii
 def set_socket ( self , device ) :
  IiIIi1I1I11Ii = socket . socket ( socket . AF_INET , socket . SOCK_RAW , socket . IPPROTO_RAW )
  IiIIi1I1I11Ii . setsockopt ( socket . SOL_IP , socket . IP_HDRINCL , 1 )
  try :
   IiIIi1I1I11Ii . setsockopt ( socket . SOL_SOCKET , socket . SO_BINDTODEVICE , device )
  except :
   IiIIi1I1I11Ii . close ( )
   IiIIi1I1I11Ii = None
   if 64 - 64: i1IIi
  self . raw_socket = IiIIi1I1I11Ii
  if 77 - 77: OOooOOo - i1IIi / II111iiii . I1Ii111 + O0
  if 1 - 1: OoooooooOO % iIii1I11I1II1 * I1ii11iIi11i
 def set_bridge_socket ( self , device ) :
  IiIIi1I1I11Ii = socket . socket ( socket . PF_PACKET , socket . SOCK_RAW )
  try :
   IiIIi1I1I11Ii = IiIIi1I1I11Ii . bind ( ( device , 0 ) )
   self . bridge_socket = IiIIi1I1I11Ii
  except :
   return
   if 17 - 17: Ii1I * i1IIi % OoO0O00
   if 12 - 12: I1ii11iIi11i
   if 86 - 86: iIii1I11I1II1 % iII111i
   if 80 - 80: Oo0Ooo
class lisp_datetime ( ) :
 def __init__ ( self , datetime_str ) :
  self . datetime_name = datetime_str
  self . datetime = None
  self . parse_datetime ( )
  if 37 - 37: i11iIiiIii - I1Ii111
  if 50 - 50: I1IiiI / Ii1I / Ii1I + O0 % I11i - i1IIi
 def valid_datetime ( self ) :
  OooIIIii = self . datetime_name
  if ( OooIIIii . find ( ":" ) == - 1 ) : return ( False )
  if ( OooIIIii . find ( "-" ) == - 1 ) : return ( False )
  IIiO0O0 , Ii1II11 , OO00Ooo00ooo , time = OooIIIii [ 0 : 4 ] , OooIIIii [ 5 : 7 ] , OooIIIii [ 8 : 10 ] , OooIIIii [ 11 : : ]
  if 25 - 25: ooOoO0o
  if ( ( IIiO0O0 + Ii1II11 + OO00Ooo00ooo ) . isdigit ( ) == False ) : return ( False )
  if ( Ii1II11 < "01" and Ii1II11 > "12" ) : return ( False )
  if ( OO00Ooo00ooo < "01" and OO00Ooo00ooo > "31" ) : return ( False )
  if 63 - 63: i11iIiiIii . i1IIi
  IiI1I , OoOIiIiiiIi , Ooo0 = time . split ( ":" )
  if 35 - 35: iIii1I11I1II1 % Oo0Ooo + o0oOOo0O0Ooo * o0oOOo0O0Ooo % ooOoO0o
  if ( ( IiI1I + OoOIiIiiiIi + Ooo0 ) . isdigit ( ) == False ) : return ( False )
  if ( IiI1I < "00" and IiI1I > "23" ) : return ( False )
  if ( OoOIiIiiiIi < "00" and OoOIiIiiiIi > "59" ) : return ( False )
  if ( Ooo0 < "00" and Ooo0 > "59" ) : return ( False )
  return ( True )
  if 10 - 10: I1ii11iIi11i / II111iiii % II111iiii - OoooooooOO * o0oOOo0O0Ooo / ooOoO0o
  if 26 - 26: OoO0O00 . O0 * iII111i % OoOoOO00 % iIii1I11I1II1
 def parse_datetime ( self ) :
  I111I11i = self . datetime_name
  I111I11i = I111I11i . replace ( "-" , "" )
  I111I11i = I111I11i . replace ( ":" , "" )
  self . datetime = int ( I111I11i )
  if 3 - 3: OOooOOo
  if 82 - 82: oO0o
 def now ( self ) :
  OOOO0O00o = datetime . datetime . now ( ) . strftime ( "%Y-%m-%d-%H:%M:%S" )
  OOOO0O00o = lisp_datetime ( OOOO0O00o )
  return ( OOOO0O00o )
  if 71 - 71: iIii1I11I1II1 * O0 % I11i + I1Ii111 . oO0o + I11i
  if 41 - 41: II111iiii + OoooooooOO
 def print_datetime ( self ) :
  return ( self . datetime_name )
  if 2 - 2: OoooooooOO
  if 79 - 79: i11iIiiIii
 def future ( self ) :
  return ( self . datetime > self . now ( ) . datetime )
  if 60 - 60: I1ii11iIi11i / I11i
  if 100 - 100: I1IiiI
 def past ( self ) :
  return ( self . future ( ) == False )
  if 44 - 44: iIii1I11I1II1 + Oo0Ooo - I1Ii111 . OoooooooOO
  if 28 - 28: Ii1I + OOooOOo % IiII . i11iIiiIii - I1IiiI * Oo0Ooo
 def now_in_range ( self , upper ) :
  return ( self . past ( ) and upper . future ( ) )
  if 2 - 2: I11i * I1ii11iIi11i + O0
  if 44 - 44: iIii1I11I1II1 / II111iiii - ooOoO0o
 def this_year ( self ) :
  i111I1I1i = str ( self . now ( ) . datetime ) [ 0 : 4 ]
  OOOO0O00o = str ( self . datetime ) [ 0 : 4 ]
  return ( OOOO0O00o == i111I1I1i )
  if 6 - 6: I1ii11iIi11i / iIii1I11I1II1 / I11i % iIii1I11I1II1
  if 49 - 49: OOooOOo * iIii1I11I1II1 - iIii1I11I1II1
 def this_month ( self ) :
  i111I1I1i = str ( self . now ( ) . datetime ) [ 0 : 6 ]
  OOOO0O00o = str ( self . datetime ) [ 0 : 6 ]
  return ( OOOO0O00o == i111I1I1i )
  if 70 - 70: OoO0O00 % i11iIiiIii * IiII . I11i * Oo0Ooo
  if 17 - 17: i1IIi
 def today ( self ) :
  i111I1I1i = str ( self . now ( ) . datetime ) [ 0 : 8 ]
  OOOO0O00o = str ( self . datetime ) [ 0 : 8 ]
  return ( OOOO0O00o == i111I1I1i )
  if 29 - 29: OOooOOo % OoO0O00 + oO0o + o0oOOo0O0Ooo . iII111i
  if 14 - 14: i1IIi + OoOoOO00 * oO0o - II111iiii + IiII + OoOoOO00
  if 42 - 42: Oo0Ooo + iII111i * ooOoO0o
  if 72 - 72: iIii1I11I1II1 % I1Ii111
  if 77 - 77: I1Ii111 * I1IiiI / iIii1I11I1II1 . II111iiii * Oo0Ooo
  if 71 - 71: ooOoO0o / iIii1I11I1II1 % O0 / I1ii11iIi11i . I1Ii111 / i11iIiiIii
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
  if 6 - 6: oO0o . OoO0O00 - II111iiii . I1IiiI - o0oOOo0O0Ooo - i1IIi
  if 42 - 42: Ii1I + i11iIiiIii
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
  if 46 - 46: O0 % OoOoOO00 - I1Ii111 . I1IiiI
  if 66 - 66: II111iiii * iIii1I11I1II1 * ooOoO0o * I11i . II111iiii - ooOoO0o
 def match_policy_map_request ( self , mr , srloc ) :
  for OOO0Ooo0OoO0 in self . match_clauses :
   OoOoO = OOO0Ooo0OoO0 . source_eid
   O000o0Ooo = mr . source_eid
   if ( OoOoO and O000o0Ooo and O000o0Ooo . is_more_specific ( OoOoO ) == False ) : continue
   if 15 - 15: I1ii11iIi11i - i11iIiiIii - Ii1I / Ii1I . iII111i
   OoOoO = OOO0Ooo0OoO0 . dest_eid
   O000o0Ooo = mr . target_eid
   if ( OoOoO and O000o0Ooo and O000o0Ooo . is_more_specific ( OoOoO ) == False ) : continue
   if 36 - 36: oO0o + Oo0Ooo * I1Ii111 % OOooOOo . Oo0Ooo . I1IiiI
   OoOoO = OOO0Ooo0OoO0 . source_rloc
   O000o0Ooo = srloc
   if ( OoOoO and O000o0Ooo and O000o0Ooo . is_more_specific ( OoOoO ) == False ) : continue
   IIi11I1i1I1I = OOO0Ooo0OoO0 . datetime_lower
   oOii = OOO0Ooo0OoO0 . datetime_upper
   if ( IIi11I1i1I1I and oOii and IIi11I1i1I1I . now_in_range ( oOii ) == False ) : continue
   return ( True )
   if 5 - 5: i1IIi % OoooooooOO
  return ( False )
  if 8 - 8: OOooOOo * oO0o
  if 47 - 47: O0
 def set_policy_map_reply ( self ) :
  i1ii111IIiiI = ( self . set_rloc_address == None and
 self . set_rloc_record_name == None and self . set_geo_name == None and
 self . set_elp_name == None and self . set_rle_name == None )
  if ( i1ii111IIiiI ) : return ( None )
  if 48 - 48: o0oOOo0O0Ooo + Ii1I
  OoOOo = lisp_rloc ( )
  if ( self . set_rloc_address ) :
   OoOOo . rloc . copy_address ( self . set_rloc_address )
   o0o0O00 = OoOOo . rloc . print_address_no_iid ( )
   lprint ( "Policy set-rloc-address to {}" . format ( o0o0O00 ) )
   if 26 - 26: i1IIi
  if ( self . set_rloc_record_name ) :
   OoOOo . rloc_name = self . set_rloc_record_name
   IiIII = blue ( OoOOo . rloc_name , False )
   lprint ( "Policy set-rloc-record-name to {}" . format ( IiIII ) )
   if 33 - 33: OoOoOO00 + OOooOOo . i1IIi . IiII
  if ( self . set_geo_name ) :
   OoOOo . geo_name = self . set_geo_name
   IiIII = OoOOo . geo_name
   Ooo0O0oO0000 = "" if lisp_geo_list . has_key ( IiIII ) else "(not configured)"
   if 8 - 8: IiII / i11iIiiIii
   lprint ( "Policy set-geo-name '{}' {}" . format ( IiIII , Ooo0O0oO0000 ) )
   if 39 - 39: I1Ii111
  if ( self . set_elp_name ) :
   OoOOo . elp_name = self . set_elp_name
   IiIII = OoOOo . elp_name
   Ooo0O0oO0000 = "" if lisp_elp_list . has_key ( IiIII ) else "(not configured)"
   if 42 - 42: iIii1I11I1II1
   lprint ( "Policy set-elp-name '{}' {}" . format ( IiIII , Ooo0O0oO0000 ) )
   if 35 - 35: I1ii11iIi11i / OoOoOO00 / i1IIi / i11iIiiIii * iIii1I11I1II1 / i1IIi
  if ( self . set_rle_name ) :
   OoOOo . rle_name = self . set_rle_name
   IiIII = OoOOo . rle_name
   Ooo0O0oO0000 = "" if lisp_rle_list . has_key ( IiIII ) else "(not configured)"
   if 69 - 69: OOooOOo / I1Ii111 * II111iiii
   lprint ( "Policy set-rle-name '{}' {}" . format ( IiIII , Ooo0O0oO0000 ) )
   if 88 - 88: OOooOOo - I1IiiI + Oo0Ooo
  if ( self . set_json_name ) :
   OoOOo . json_name = self . set_json_name
   IiIII = OoOOo . json_name
   Ooo0O0oO0000 = "" if lisp_json_list . has_key ( IiIII ) else "(not configured)"
   if 15 - 15: I11i / I1ii11iIi11i - I1Ii111 * O0 % ooOoO0o / I1IiiI
   lprint ( "Policy set-json-name '{}' {}" . format ( IiIII , Ooo0O0oO0000 ) )
   if 53 - 53: i11iIiiIii * i11iIiiIii % O0 % IiII
  return ( OoOOo )
  if 57 - 57: I1IiiI % i1IIi * OoO0O00 + I1Ii111 . I11i % I11i
  if 69 - 69: I1ii11iIi11i / OoOoOO00 + iIii1I11I1II1
 def save_policy ( self ) :
  lisp_policies [ self . policy_name ] = self
  if 8 - 8: OoooooooOO
  if 72 - 72: OoooooooOO % I1ii11iIi11i - OoO0O00 . OoooooooOO
  if 83 - 83: o0oOOo0O0Ooo * Ii1I - Oo0Ooo * iII111i - i11iIiiIii
class lisp_pubsub ( ) :
 def __init__ ( self , itr , port , nonce , ttl , xtr_id ) :
  self . itr = itr
  self . port = port
  self . nonce = nonce
  self . uptime = lisp_get_timestamp ( )
  self . ttl = ttl
  self . xtr_id = xtr_id
  self . map_notify_count = 0
  if 6 - 6: I1IiiI + i11iIiiIii + O0 / i1IIi
  if 50 - 50: iII111i . II111iiii % I1Ii111 % I1IiiI / o0oOOo0O0Ooo . I1IiiI
 def add ( self , eid_prefix ) :
  iiI = self . ttl
  i1OO0o = eid_prefix . print_prefix ( )
  if ( lisp_pubsub_cache . has_key ( i1OO0o ) == False ) :
   lisp_pubsub_cache [ i1OO0o ] = { }
   if 76 - 76: OOooOOo % iII111i
  Ooooo00oOO0Oo = lisp_pubsub_cache [ i1OO0o ]
  if 80 - 80: iIii1I11I1II1 + o0oOOo0O0Ooo + iIii1I11I1II1
  OO0OOo00O = "Add"
  if ( Ooooo00oOO0Oo . has_key ( self . xtr_id ) ) :
   OO0OOo00O = "Replace"
   del ( Ooooo00oOO0Oo [ self . xtr_id ] )
   if 68 - 68: OOooOOo * iII111i - o0oOOo0O0Ooo - Oo0Ooo % OoooooooOO
  Ooooo00oOO0Oo [ self . xtr_id ] = self
  if 60 - 60: o0oOOo0O0Ooo / OoooooooOO % II111iiii - ooOoO0o
  i1OO0o = green ( i1OO0o , False )
  o00ooOOo0ooO0 = red ( self . itr . print_address_no_iid ( ) , False )
  i11IIii = "0x" + lisp_hex_string ( self . xtr_id )
  lprint ( "{} pubsub state {} for {}, xtr-id: {}, ttl {}" . format ( OO0OOo00O , i1OO0o ,
 o00ooOOo0ooO0 , i11IIii , iiI ) )
  if 29 - 29: OoOoOO00 * I11i . O0 + oO0o - iIii1I11I1II1 - I11i
  if 40 - 40: OoooooooOO + O0
 def delete ( self , eid_prefix ) :
  i1OO0o = eid_prefix . print_prefix ( )
  o00ooOOo0ooO0 = red ( self . itr . print_address_no_iid ( ) , False )
  i11IIii = "0x" + lisp_hex_string ( self . xtr_id )
  if ( lisp_pubsub_cache . has_key ( i1OO0o ) ) :
   Ooooo00oOO0Oo = lisp_pubsub_cache [ i1OO0o ]
   if ( Ooooo00oOO0Oo . has_key ( self . xtr_id ) ) :
    Ooooo00oOO0Oo . pop ( self . xtr_id )
    lprint ( "Remove pubsub state {} for {}, xtr-id: {}" . format ( i1OO0o ,
 o00ooOOo0ooO0 , i11IIii ) )
    if 55 - 55: i11iIiiIii * Ii1I % OOooOOo + ooOoO0o - I1ii11iIi11i . Oo0Ooo
    if 48 - 48: o0oOOo0O0Ooo
    if 55 - 55: OOooOOo - OoooooooOO * iIii1I11I1II1 + iII111i % II111iiii
    if 33 - 33: I1Ii111 * oO0o * OoooooooOO + OOooOOo - I1IiiI + I1Ii111
    if 92 - 92: ooOoO0o * I11i % iIii1I11I1II1 + Ii1I - OoOoOO00
    if 31 - 31: OoooooooOO
    if 87 - 87: OoooooooOO - Ii1I . I11i / I1Ii111 . i1IIi
    if 86 - 86: i1IIi . oO0o % OOooOOo
    if 99 - 99: oO0o / I1Ii111 * oO0o * I11i
    if 38 - 38: o0oOOo0O0Ooo + OoOoOO00
    if 24 - 24: Ii1I - OOooOOo - o0oOOo0O0Ooo - I1Ii111 / OoooooooOO
    if 17 - 17: OoO0O00
    if 79 - 79: Ii1I - II111iiii
    if 57 - 57: II111iiii / OoooooooOO
    if 4 - 4: I11i * OoOoOO00
    if 18 - 18: iIii1I11I1II1 % OOooOOo - I1ii11iIi11i * i1IIi + Oo0Ooo
    if 87 - 87: oO0o . I11i
    if 15 - 15: oO0o
    if 45 - 45: Oo0Ooo * IiII * OoO0O00 + iIii1I11I1II1
    if 89 - 89: IiII . IiII . oO0o % iII111i
    if 27 - 27: OoOoOO00 + O0 % i1IIi - Oo0Ooo
    if 96 - 96: O0 % o0oOOo0O0Ooo + OOooOOo % I1IiiI
class lisp_trace ( ) :
 def __init__ ( self ) :
  self . nonce = lisp_get_control_nonce ( )
  self . packet_json = [ ]
  self . local_rloc = None
  self . local_port = None
  self . lisp_socket = None
  if 51 - 51: i1IIi . o0oOOo0O0Ooo % I1IiiI - OoooooooOO / OoOoOO00 - I11i
  if 45 - 45: O0 * II111iiii / i11iIiiIii
 def print_trace ( self ) :
  IiIiiiiI11I = self . packet_json
  lprint ( "LISP-Trace JSON: '{}'" . format ( IiIiiiiI11I ) )
  if 34 - 34: oO0o * II111iiii . II111iiii - OOooOOo % O0 - OoooooooOO
  if 33 - 33: iIii1I11I1II1 * iII111i / OoooooooOO - oO0o * Ii1I
 def encode ( self ) :
  oOoOo00oo = socket . htonl ( 0x90000000 )
  i1II1IiiIi = struct . pack ( "II" , oOoOo00oo , 0 )
  i1II1IiiIi += struct . pack ( "Q" , self . nonce )
  i1II1IiiIi += json . dumps ( self . packet_json )
  return ( i1II1IiiIi )
  if 95 - 95: OoooooooOO % I1ii11iIi11i . I1Ii111 . IiII
  if 98 - 98: OoooooooOO - OoO0O00 . oO0o - iIii1I11I1II1 * iIii1I11I1II1 % Ii1I
 def decode ( self , packet ) :
  oOoOo000 = "I"
  O0OOoooO = struct . calcsize ( oOoOo000 )
  if ( len ( packet ) < O0OOoooO ) : return ( False )
  oOoOo00oo = struct . unpack ( oOoOo000 , packet [ : O0OOoooO ] ) [ 0 ]
  packet = packet [ O0OOoooO : : ]
  oOoOo00oo = socket . ntohl ( oOoOo00oo )
  if ( ( oOoOo00oo & 0xff000000 ) != 0x90000000 ) : return ( False )
  if 87 - 87: O0 % iII111i
  if ( len ( packet ) < O0OOoooO ) : return ( False )
  o0o0O00 = struct . unpack ( oOoOo000 , packet [ : O0OOoooO ] ) [ 0 ]
  packet = packet [ O0OOoooO : : ]
  if 57 - 57: Ii1I
  o0o0O00 = socket . ntohl ( o0o0O00 )
  ii11IIIIi1 = o0o0O00 >> 24
  IiIiiIi1i1 = ( o0o0O00 >> 16 ) & 0xff
  iIiiI = ( o0o0O00 >> 8 ) & 0xff
  oo00 = o0o0O00 & 0xff
  self . local_rloc = "{}.{}.{}.{}" . format ( ii11IIIIi1 , IiIiiIi1i1 , iIiiI , oo00 )
  self . local_port = str ( oOoOo00oo & 0xffff )
  if 57 - 57: i1IIi / I11i + OoO0O00 * OOooOOo + OoooooooOO
  oOoOo000 = "Q"
  O0OOoooO = struct . calcsize ( oOoOo000 )
  if ( len ( packet ) < O0OOoooO ) : return ( False )
  self . nonce = struct . unpack ( oOoOo000 , packet [ : O0OOoooO ] ) [ 0 ]
  packet = packet [ O0OOoooO : : ]
  if ( len ( packet ) == 0 ) : return ( True )
  if 30 - 30: I1Ii111 . IiII . iIii1I11I1II1 % o0oOOo0O0Ooo + iIii1I11I1II1
  try :
   self . packet_json = json . loads ( packet )
  except :
   return ( False )
   if 83 - 83: I1IiiI % OoOoOO00 - o0oOOo0O0Ooo
  return ( True )
  if 85 - 85: OoO0O00 * I1IiiI - I1Ii111 . ooOoO0o * II111iiii
  if 76 - 76: OoO0O00 * IiII * oO0o * OoOoOO00
 def myeid ( self , eid ) :
  return ( lisp_is_myeid ( eid ) )
  if 67 - 67: OoooooooOO - I1ii11iIi11i - II111iiii
  if 26 - 26: ooOoO0o - i1IIi / OOooOOo + OoOoOO00 / iII111i
 def return_to_sender ( self , lisp_socket , rts_rloc , packet ) :
  OoOOo , IIiII = self . rtr_cache_nat_trace_find ( rts_rloc )
  if ( OoOOo == None ) :
   OoOOo , IIiII = rts_rloc . split ( ":" )
   IIiII = int ( IIiII )
   lprint ( "Send LISP-Trace to address {}:{}" . format ( OoOOo , IIiII ) )
  else :
   lprint ( "Send LISP-Trace to translated address {}:{}" . format ( OoOOo ,
 IIiII ) )
   if 27 - 27: I11i % Ii1I / iII111i . OoOoOO00
   if 88 - 88: iII111i - i11iIiiIii * I1Ii111 * i11iIiiIii - O0
  if ( lisp_socket == None ) :
   IiIIi1I1I11Ii = socket . socket ( socket . AF_INET , socket . SOCK_DGRAM )
   IiIIi1I1I11Ii . bind ( ( "0.0.0.0" , LISP_TRACE_PORT ) )
   IiIIi1I1I11Ii . sendto ( packet , ( OoOOo , IIiII ) )
   IiIIi1I1I11Ii . close ( )
  else :
   lisp_socket . sendto ( packet , ( OoOOo , IIiII ) )
   if 8 - 8: oO0o + O0
   if 52 - 52: I11i * OOooOOo - OoOoOO00 % iIii1I11I1II1 . II111iiii
   if 1 - 1: OOooOOo / I1IiiI / Ii1I * iII111i
 def packet_length ( self ) :
  I1iIIIiI = 8 ; i11I1iII = 4 + 4 + 8
  return ( I1iIIIiI + i11I1iII + len ( json . dumps ( self . packet_json ) ) )
  if 69 - 69: IiII + I1Ii111 - I1IiiI . iII111i . OoooooooOO
  if 88 - 88: i11iIiiIii
 def rtr_cache_nat_trace ( self , translated_rloc , translated_port ) :
  iii11 = self . local_rloc + ":" + self . local_port
  oOO = ( translated_rloc , translated_port )
  lisp_rtr_nat_trace_cache [ iii11 ] = oOO
  lprint ( "Cache NAT Trace addresses {} -> {}" . format ( iii11 , oOO ) )
  if 54 - 54: OOooOOo % oO0o * Ii1I / I1IiiI
  if 46 - 46: o0oOOo0O0Ooo . ooOoO0o / Ii1I
 def rtr_cache_nat_trace_find ( self , local_rloc_and_port ) :
  iii11 = local_rloc_and_port
  try : oOO = lisp_rtr_nat_trace_cache [ iii11 ]
  except : oOO = ( None , None )
  return ( oOO )
  if 97 - 97: Ii1I . Oo0Ooo - O0 - I1Ii111 . i1IIi
  if 47 - 47: IiII * ooOoO0o - i1IIi % OoOoOO00 * i11iIiiIii . OoooooooOO
  if 84 - 84: OoOoOO00 / IiII - i1IIi - I1IiiI * OOooOOo
  if 35 - 35: II111iiii
  if 28 - 28: I1Ii111 + IiII + I1ii11iIi11i . Ii1I
  if 82 - 82: ooOoO0o - ooOoO0o . Ii1I . i11iIiiIii % Ii1I + OOooOOo
  if 33 - 33: Oo0Ooo - OOooOOo / OoOoOO00 % II111iiii % OOooOOo + I1Ii111
  if 41 - 41: I11i + Oo0Ooo . Oo0Ooo / iII111i . OoOoOO00
  if 1 - 1: ooOoO0o + iII111i % i11iIiiIii / OoOoOO00
  if 98 - 98: IiII
  if 75 - 75: OoooooooOO % IiII + Ii1I - i1IIi / OoooooooOO
def lisp_get_map_server ( address ) :
 for oooO0OOo0O0O0 in lisp_map_servers_list . values ( ) :
  if ( oooO0OOo0O0O0 . map_server . is_exact_match ( address ) ) : return ( oooO0OOo0O0O0 )
  if 57 - 57: iII111i
 return ( None )
 if 18 - 18: II111iiii % i11iIiiIii + I11i - OOooOOo
 if 100 - 100: o0oOOo0O0Ooo / Ii1I - iIii1I11I1II1 / oO0o
 if 68 - 68: I11i / II111iiii * oO0o . II111iiii * OOooOOo
 if 78 - 78: I11i * OoO0O00 / II111iiii
 if 86 - 86: I1Ii111 % II111iiii
 if 90 - 90: OoO0O00 / I11i - Oo0Ooo
 if 76 - 76: O0 + OoO0O00 / ooOoO0o . II111iiii * iIii1I11I1II1 . I1Ii111
def lisp_get_any_map_server ( ) :
 for oooO0OOo0O0O0 in lisp_map_servers_list . values ( ) : return ( oooO0OOo0O0O0 )
 return ( None )
 if 43 - 43: Oo0Ooo + o0oOOo0O0Ooo % o0oOOo0O0Ooo % I1ii11iIi11i / iIii1I11I1II1 . I1ii11iIi11i
 if 59 - 59: IiII . OoO0O00 - OoooooooOO . O0
 if 33 - 33: Ii1I
 if 95 - 95: OoooooooOO + OoO0O00 * ooOoO0o
 if 40 - 40: I1IiiI / OOooOOo * Ii1I
 if 98 - 98: I1IiiI
 if 4 - 4: I1IiiI % O0 / Oo0Ooo / O0
 if 90 - 90: ooOoO0o - O0 . IiII - O0 . iIii1I11I1II1
 if 42 - 42: I1ii11iIi11i
 if 51 - 51: iII111i % i11iIiiIii . OoO0O00 . IiII - OoOoOO00 * i1IIi
def lisp_get_map_resolver ( address , eid ) :
 if ( address != None ) :
  o0o0O00 = address . print_address ( )
  oOO0O000OOo0 = None
  for iii11 in lisp_map_resolvers_list :
   if ( iii11 . find ( o0o0O00 ) == - 1 ) : continue
   oOO0O000OOo0 = lisp_map_resolvers_list [ iii11 ]
   if 14 - 14: I1ii11iIi11i . OoO0O00
  return ( oOO0O000OOo0 )
  if 26 - 26: iII111i / ooOoO0o / Oo0Ooo / Oo0Ooo . I1ii11iIi11i * OOooOOo
  if 25 - 25: IiII % I1IiiI / O0 % OOooOOo - OoooooooOO
  if 29 - 29: O0 + iII111i
  if 4 - 4: I11i * I11i - Ii1I * oO0o . I1ii11iIi11i % o0oOOo0O0Ooo
  if 33 - 33: Ii1I * i11iIiiIii / O0 . Oo0Ooo + i1IIi . OoOoOO00
  if 76 - 76: OoooooooOO - O0
  if 17 - 17: Oo0Ooo % I1Ii111 . oO0o - O0
 if ( eid == "" ) :
  iiiIIi1Iii = ""
 elif ( eid == None ) :
  iiiIIi1Iii = "all"
 else :
  I111I = lisp_db_for_lookups . lookup_cache ( eid , False )
  iiiIIi1Iii = "all" if I111I == None else I111I . use_mr_name
  if 39 - 39: iII111i - I1ii11iIi11i % ooOoO0o - OoOoOO00 + OoOoOO00
  if 97 - 97: I11i * I1Ii111 * oO0o
 IiI1IOOO0 = None
 for oOO0O000OOo0 in lisp_map_resolvers_list . values ( ) :
  if ( iiiIIi1Iii == "" ) : return ( oOO0O000OOo0 )
  if ( oOO0O000OOo0 . mr_name != iiiIIi1Iii ) : continue
  if ( IiI1IOOO0 == None or oOO0O000OOo0 . last_used < IiI1IOOO0 . last_used ) : IiI1IOOO0 = oOO0O000OOo0
  if 20 - 20: I1ii11iIi11i . IiII
 return ( IiI1IOOO0 )
 if 98 - 98: I11i + Oo0Ooo . IiII / iII111i % OoooooooOO
 if 35 - 35: O0 . Oo0Ooo / Oo0Ooo / Ii1I / i1IIi * I11i
 if 93 - 93: O0 + IiII
 if 91 - 91: iIii1I11I1II1
 if 66 - 66: i1IIi . ooOoO0o
 if 84 - 84: O0 % ooOoO0o / I1Ii111
 if 75 - 75: I11i - iII111i . O0
 if 52 - 52: I1ii11iIi11i
def lisp_get_decent_map_resolver ( eid ) :
 iI11I = lisp_get_decent_index ( eid )
 IIiiiIiI = str ( iI11I ) + "." + lisp_decent_dns_suffix
 if 65 - 65: oO0o
 lprint ( "Use LISP-Decent map-resolver {} for EID {}" . format ( bold ( IIiiiIiI , False ) , eid . print_prefix ( ) ) )
 if 57 - 57: I1Ii111 + IiII . o0oOOo0O0Ooo % OoO0O00 - I11i * oO0o
 if 55 - 55: I1IiiI / ooOoO0o
 IiI1IOOO0 = None
 for oOO0O000OOo0 in lisp_map_resolvers_list . values ( ) :
  if ( IIiiiIiI != oOO0O000OOo0 . dns_name ) : continue
  if ( IiI1IOOO0 == None or oOO0O000OOo0 . last_used < IiI1IOOO0 . last_used ) : IiI1IOOO0 = oOO0O000OOo0
  if 81 - 81: ooOoO0o + I1Ii111 / I1ii11iIi11i - o0oOOo0O0Ooo + OoOoOO00 * OOooOOo
 return ( IiI1IOOO0 )
 if 83 - 83: OoO0O00 . O0 + II111iiii
 if 42 - 42: OOooOOo * I1Ii111
 if 53 - 53: II111iiii % OOooOOo / I1ii11iIi11i * OoOoOO00 % I1ii11iIi11i * iII111i
 if 91 - 91: iII111i . OoooooooOO
 if 90 - 90: i11iIiiIii - I1IiiI
 if 39 - 39: iII111i % OoooooooOO % Ii1I % I1IiiI
 if 63 - 63: OoO0O00 - I1Ii111 - II111iiii
def lisp_ipv4_input ( packet ) :
 if 79 - 79: II111iiii - II111iiii + OoOoOO00 / iII111i % OoooooooOO - OoO0O00
 if 22 - 22: o0oOOo0O0Ooo + I1Ii111 . Oo0Ooo
 if 84 - 84: O0 + I1IiiI % Oo0Ooo + OOooOOo
 if 94 - 94: OOooOOo
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
   if 81 - 81: i11iIiiIii + iIii1I11I1II1 . i11iIiiIii / OOooOOo / iII111i
   if 34 - 34: i11iIiiIii - o0oOOo0O0Ooo * OoooooooOO * I1ii11iIi11i * Oo0Ooo % I1ii11iIi11i
   if 31 - 31: I11i . o0oOOo0O0Ooo
   if 82 - 82: I11i - Oo0Ooo
   if 77 - 77: I1IiiI + OoO0O00 % iIii1I11I1II1 - OOooOOo
   if 80 - 80: oO0o % I1ii11iIi11i * I1Ii111 + i1IIi
   if 79 - 79: oO0o + IiII
 iiI = struct . unpack ( "B" , packet [ 8 : 9 ] ) [ 0 ]
 if ( iiI == 0 ) :
  dprint ( "IPv4 packet arrived with ttl 0, packet discarded" )
  return ( None )
 elif ( iiI == 1 ) :
  dprint ( "IPv4 packet {}, packet discarded" . format ( bold ( "ttl expiry" , False ) ) )
  if 4 - 4: iII111i + OoooooooOO / I1Ii111
  return ( None )
  if 57 - 57: I1IiiI . iIii1I11I1II1 % iII111i * iII111i / I1Ii111
  if 30 - 30: O0 / I11i % OoOoOO00 * I1Ii111 / O0 % ooOoO0o
 iiI -= 1
 packet = packet [ 0 : 8 ] + struct . pack ( "B" , iiI ) + packet [ 9 : : ]
 packet = packet [ 0 : 10 ] + struct . pack ( "H" , 0 ) + packet [ 12 : : ]
 packet = lisp_ip_checksum ( packet )
 return ( packet )
 if 36 - 36: iIii1I11I1II1 . iII111i * I1IiiI . I1IiiI - IiII
 if 39 - 39: O0 / ooOoO0o + I11i - OoOoOO00 * o0oOOo0O0Ooo - OoO0O00
 if 97 - 97: i11iIiiIii / O0 % OoO0O00
 if 88 - 88: i1IIi . I1IiiI
 if 8 - 8: I1ii11iIi11i . OoO0O00 % o0oOOo0O0Ooo / O0
 if 51 - 51: oO0o + Ii1I * Ii1I * I1ii11iIi11i % I11i - I1ii11iIi11i
 if 15 - 15: i1IIi / OoO0O00 - Oo0Ooo
def lisp_ipv6_input ( packet ) :
 iI111I1 = packet . inner_dest
 packet = packet . packet
 if 74 - 74: o0oOOo0O0Ooo % Ii1I - II111iiii / ooOoO0o
 if 84 - 84: I1IiiI + OOooOOo
 if 80 - 80: OOooOOo / OoOoOO00
 if 93 - 93: OOooOOo
 if 82 - 82: iIii1I11I1II1 + OoO0O00 / iIii1I11I1II1 . iIii1I11I1II1
 iiI = struct . unpack ( "B" , packet [ 7 : 8 ] ) [ 0 ]
 if ( iiI == 0 ) :
  dprint ( "IPv6 packet arrived with hop-limit 0, packet discarded" )
  return ( None )
 elif ( iiI == 1 ) :
  dprint ( "IPv6 packet {}, packet discarded" . format ( bold ( "ttl expiry" , False ) ) )
  if 36 - 36: iII111i % I1ii11iIi11i + OoOoOO00 - i11iIiiIii % II111iiii % I11i
  return ( None )
  if 92 - 92: O0 * OoooooooOO + I1ii11iIi11i / IiII
  if 97 - 97: o0oOOo0O0Ooo . Ii1I + I1Ii111
  if 72 - 72: i11iIiiIii . iII111i . Ii1I * I1ii11iIi11i
  if 49 - 49: OoOoOO00 - O0 % I11i - ooOoO0o * OOooOOo
  if 58 - 58: OoooooooOO - OOooOOo * oO0o / Ii1I . IiII
 if ( iI111I1 . is_ipv6_link_local ( ) ) :
  dprint ( "Do not encapsulate IPv6 link-local packets" )
  return ( None )
  if 50 - 50: IiII . OOooOOo + I1ii11iIi11i - OoooooooOO
  if 2 - 2: o0oOOo0O0Ooo % ooOoO0o / O0 / i11iIiiIii
 iiI -= 1
 packet = packet [ 0 : 7 ] + struct . pack ( "B" , iiI ) + packet [ 8 : : ]
 return ( packet )
 if 91 - 91: II111iiii * o0oOOo0O0Ooo
 if 20 - 20: iIii1I11I1II1 % Oo0Ooo * OoOoOO00 % IiII
 if 93 - 93: I11i * iIii1I11I1II1 * oO0o
 if 74 - 74: I1IiiI
 if 39 - 39: iII111i * IiII / iII111i * IiII % I1ii11iIi11i
 if 27 - 27: iIii1I11I1II1 . ooOoO0o
 if 74 - 74: i1IIi % OoOoOO00
 if 98 - 98: IiII * OOooOOo / O0 - I1Ii111 . I1Ii111 + OOooOOo
def lisp_mac_input ( packet ) :
 return ( packet )
 if 61 - 61: iII111i * Ii1I % Ii1I + I1IiiI
 if 23 - 23: oO0o + I1Ii111 / OoooooooOO / O0 + IiII
 if 80 - 80: i11iIiiIii - OoooooooOO + II111iiii / i1IIi - oO0o
 if 100 - 100: Ii1I
 if 73 - 73: IiII - O0
 if 54 - 54: OOooOOo
 if 28 - 28: i1IIi - Oo0Ooo * OoO0O00 + OoooooooOO - Ii1I * i11iIiiIii
 if 71 - 71: iII111i - OOooOOo / iIii1I11I1II1 % i11iIiiIii
 if 39 - 39: o0oOOo0O0Ooo
def lisp_rate_limit_map_request ( source , dest ) :
 if ( lisp_last_map_request_sent == None ) : return ( False )
 i111I1I1i = lisp_get_timestamp ( )
 i11IiIIi11I = i111I1I1i - lisp_last_map_request_sent
 Iii1ii11iiii1 = ( i11IiIIi11I < LISP_MAP_REQUEST_RATE_LIMIT )
 if 87 - 87: O0 - i1IIi . I11i / Ii1I % iIii1I11I1II1
 if ( Iii1ii11iiii1 ) :
  if ( source != None ) : source = source . print_address ( )
  dest = dest . print_address ( )
  dprint ( "Rate-limiting Map-Request for {} -> {}" . format ( source , dest ) )
  if 57 - 57: I11i . IiII / iIii1I11I1II1 - ooOoO0o
 return ( Iii1ii11iiii1 )
 if 50 - 50: O0 / II111iiii
 if 94 - 94: O0 + O0 % I1ii11iIi11i % i1IIi
 if 15 - 15: I1IiiI
 if 48 - 48: Ii1I * IiII % O0 - II111iiii
 if 66 - 66: iIii1I11I1II1 / OOooOOo
 if 65 - 65: IiII . oO0o + O0 - i11iIiiIii + iIii1I11I1II1
 if 82 - 82: iIii1I11I1II1 * iII111i + iIii1I11I1II1 / OoO0O00 + O0
def lisp_send_map_request ( lisp_sockets , lisp_ephem_port , seid , deid , rloc ) :
 global lisp_last_map_request_sent
 if 67 - 67: I1Ii111
 if 94 - 94: I1Ii111 % iIii1I11I1II1 - II111iiii . ooOoO0o + i11iIiiIii - i11iIiiIii
 if 55 - 55: OoooooooOO % iIii1I11I1II1 % I1ii11iIi11i % i1IIi
 if 46 - 46: I11i - ooOoO0o . I1IiiI
 if 36 - 36: I11i + OoO0O00 * O0 * OoOoOO00 * iII111i
 if 90 - 90: i11iIiiIii / i1IIi
 I1ioOo0oO0O0 = O0000o0O = None
 if ( rloc ) :
  I1ioOo0oO0O0 = rloc . rloc
  O0000o0O = rloc . translated_port if lisp_i_am_rtr else LISP_DATA_PORT
  if 35 - 35: i11iIiiIii
  if 41 - 41: IiII
  if 79 - 79: OOooOOo / Ii1I . iIii1I11I1II1 % I1IiiI
  if 55 - 55: i11iIiiIii - I1IiiI . oO0o - OoooooooOO
  if 44 - 44: I1Ii111
 oo000ooOOo , iiI1iIIIIii1i , O0OoO0o = lisp_myrlocs
 if ( oo000ooOOo == None ) :
  lprint ( "Suppress sending Map-Request, IPv4 RLOC not found" )
  return
  if 77 - 77: I1IiiI
 if ( iiI1iIIIIii1i == None and I1ioOo0oO0O0 != None and I1ioOo0oO0O0 . is_ipv6 ( ) ) :
  lprint ( "Suppress sending Map-Request, IPv6 RLOC not found" )
  return
  if 16 - 16: I1IiiI + ooOoO0o - O0 / o0oOOo0O0Ooo
  if 36 - 36: Oo0Ooo - OoOoOO00 - II111iiii
 oooO0o = lisp_map_request ( )
 oooO0o . record_count = 1
 oooO0o . nonce = lisp_get_control_nonce ( )
 oooO0o . rloc_probe = ( I1ioOo0oO0O0 != None )
 if 25 - 25: i11iIiiIii + II111iiii * OOooOOo % OOooOOo
 if 87 - 87: I11i % Ii1I % Oo0Ooo . II111iiii / oO0o
 if 19 - 19: O0 . OOooOOo + I1Ii111 * I1ii11iIi11i
 if 91 - 91: o0oOOo0O0Ooo / oO0o . o0oOOo0O0Ooo + IiII + ooOoO0o . I1Ii111
 if 90 - 90: i1IIi + oO0o * oO0o / ooOoO0o . IiII
 if 98 - 98: I11i % OoO0O00 . iII111i - o0oOOo0O0Ooo
 if 92 - 92: I11i
 if ( rloc ) : rloc . last_rloc_probe_nonce = oooO0o . nonce
 if 34 - 34: I1IiiI % iIii1I11I1II1 . I1ii11iIi11i * Oo0Ooo * iIii1I11I1II1 / O0
 OOoo = deid . is_multicast_address ( )
 if ( OOoo ) :
  oooO0o . target_eid = seid
  oooO0o . target_group = deid
 else :
  oooO0o . target_eid = deid
  if 98 - 98: iII111i % IiII + OoO0O00
  if 23 - 23: OOooOOo
  if 83 - 83: I1ii11iIi11i / O0 * II111iiii + IiII + Oo0Ooo
  if 99 - 99: II111iiii + O0
  if 94 - 94: ooOoO0o * ooOoO0o + o0oOOo0O0Ooo . iII111i % iIii1I11I1II1 + Ii1I
  if 88 - 88: Oo0Ooo . iII111i
  if 89 - 89: OOooOOo + I1Ii111 % i11iIiiIii + Oo0Ooo / Oo0Ooo + OoO0O00
  if 9 - 9: OoOoOO00 % i1IIi + IiII
  if 19 - 19: I1Ii111 - II111iiii / I1Ii111 + I1IiiI - OoooooooOO + o0oOOo0O0Ooo
 if ( oooO0o . rloc_probe == False ) :
  I111I = lisp_get_signature_eid ( )
  if ( I111I ) :
   oooO0o . signature_eid . copy_address ( I111I . eid )
   oooO0o . privkey_filename = "./lisp-sig.pem"
   if 100 - 100: OoO0O00 / OoOoOO00 / OOooOOo / OoO0O00
   if 95 - 95: ooOoO0o
   if 95 - 95: Ii1I + i1IIi . I1IiiI % I1Ii111 / Ii1I * O0
   if 68 - 68: I1Ii111 - IiII - oO0o - Oo0Ooo - o0oOOo0O0Ooo
   if 32 - 32: OoOoOO00 % i11iIiiIii
   if 53 - 53: I1Ii111 * Ii1I / IiII . i1IIi * II111iiii / o0oOOo0O0Ooo
 if ( seid == None or OOoo ) :
  oooO0o . source_eid . afi = LISP_AFI_NONE
 else :
  oooO0o . source_eid = seid
  if 44 - 44: I1Ii111 + ooOoO0o
  if 15 - 15: I11i + OoO0O00 + OoOoOO00
  if 100 - 100: I1Ii111
  if 78 - 78: OoOoOO00
  if 16 - 16: I1Ii111 % OoO0O00 - OoO0O00 % OoOoOO00 * OoO0O00
  if 36 - 36: OoOoOO00 * II111iiii . OoooooooOO * I11i . I11i
  if 13 - 13: I1ii11iIi11i * II111iiii
  if 93 - 93: OOooOOo / O0 - o0oOOo0O0Ooo + OoO0O00 * I1IiiI
  if 53 - 53: I1ii11iIi11i
  if 91 - 91: o0oOOo0O0Ooo - I1ii11iIi11i . i1IIi
  if 64 - 64: ooOoO0o
  if 23 - 23: Oo0Ooo . OoO0O00
 if ( I1ioOo0oO0O0 != None and lisp_nat_traversal and lisp_i_am_rtr == False ) :
  if ( I1ioOo0oO0O0 . is_private_address ( ) == False ) :
   oo000ooOOo = lisp_get_any_translated_rloc ( )
   if 49 - 49: oO0o % i11iIiiIii * Ii1I
  if ( oo000ooOOo == None ) :
   lprint ( "Suppress sending Map-Request, translated RLOC not found" )
   return
   if 9 - 9: Oo0Ooo - OoO0O00 + ooOoO0o / o0oOOo0O0Ooo
   if 61 - 61: O0 - i11iIiiIii * o0oOOo0O0Ooo
   if 92 - 92: Oo0Ooo + OOooOOo - i11iIiiIii
   if 26 - 26: O0 % Oo0Ooo + ooOoO0o - Ii1I . Oo0Ooo
   if 33 - 33: I1Ii111 / iII111i . I1Ii111 % II111iiii
   if 52 - 52: I1ii11iIi11i
   if 1 - 1: II111iiii + I1ii11iIi11i * OoOoOO00 % ooOoO0o - iII111i % OoooooooOO
   if 77 - 77: iII111i + o0oOOo0O0Ooo
 if ( I1ioOo0oO0O0 == None or I1ioOo0oO0O0 . is_ipv4 ( ) ) :
  if ( lisp_nat_traversal and I1ioOo0oO0O0 == None ) :
   oo0000O0 = lisp_get_any_translated_rloc ( )
   if ( oo0000O0 != None ) : oo000ooOOo = oo0000O0
   if 91 - 91: I1IiiI - I1Ii111 % O0 / I11i . Oo0Ooo / Ii1I
  oooO0o . itr_rlocs . append ( oo000ooOOo )
  if 71 - 71: o0oOOo0O0Ooo + Oo0Ooo % OoO0O00 - i11iIiiIii + iIii1I11I1II1
 if ( I1ioOo0oO0O0 == None or I1ioOo0oO0O0 . is_ipv6 ( ) ) :
  if ( iiI1iIIIIii1i == None or iiI1iIIIIii1i . is_ipv6_link_local ( ) ) :
   iiI1iIIIIii1i = None
  else :
   oooO0o . itr_rloc_count = 1 if ( I1ioOo0oO0O0 == None ) else 0
   oooO0o . itr_rlocs . append ( iiI1iIIIIii1i )
   if 52 - 52: OoooooooOO
   if 44 - 44: O0 / OoooooooOO + ooOoO0o * I1ii11iIi11i
   if 36 - 36: I1ii11iIi11i / OoO0O00 - oO0o % O0
   if 12 - 12: i1IIi * ooOoO0o / oO0o + I1IiiI / OoooooooOO
   if 86 - 86: Oo0Ooo / OoO0O00
   if 78 - 78: I1IiiI * I1IiiI
   if 13 - 13: oO0o
   if 43 - 43: oO0o / Ii1I % OOooOOo
   if 45 - 45: II111iiii
 if ( I1ioOo0oO0O0 != None and oooO0o . itr_rlocs != [ ] ) :
  Ii1 = oooO0o . itr_rlocs [ 0 ]
 else :
  if ( deid . is_ipv4 ( ) ) :
   Ii1 = oo000ooOOo
  elif ( deid . is_ipv6 ( ) ) :
   Ii1 = iiI1iIIIIii1i
  else :
   Ii1 = oo000ooOOo
   if 41 - 41: Ii1I / OOooOOo * Oo0Ooo . O0 - i11iIiiIii
   if 77 - 77: o0oOOo0O0Ooo + I1IiiI + I1Ii111 / I1ii11iIi11i * i1IIi
   if 37 - 37: O0 + iIii1I11I1II1 % IiII * oO0o
   if 43 - 43: OOooOOo . O0
   if 76 - 76: OOooOOo * OoooooooOO / IiII . OoO0O00 + II111iiii
   if 23 - 23: OoO0O00 - OoooooooOO * I11i . iIii1I11I1II1 / o0oOOo0O0Ooo + oO0o
 i1II1IiiIi = oooO0o . encode ( I1ioOo0oO0O0 , O0000o0O )
 oooO0o . print_map_request ( )
 if 74 - 74: II111iiii / I1IiiI * O0 * OoO0O00 . I11i
 if 74 - 74: O0 . i1IIi / I1ii11iIi11i + o0oOOo0O0Ooo
 if 24 - 24: ooOoO0o % I1Ii111 + OoO0O00 * o0oOOo0O0Ooo % O0 - i11iIiiIii
 if 49 - 49: o0oOOo0O0Ooo / OoOoOO00 + iII111i
 if 85 - 85: I1IiiI - o0oOOo0O0Ooo
 if 86 - 86: II111iiii + Ii1I * Ii1I
 if ( I1ioOo0oO0O0 != None ) :
  if ( rloc . is_rloc_translated ( ) ) :
   Iii111I = lisp_get_nat_info ( I1ioOo0oO0O0 , rloc . rloc_name )
   if 26 - 26: o0oOOo0O0Ooo + oO0o * i11iIiiIii / II111iiii
   if 86 - 86: Ii1I
   if 69 - 69: oO0o % o0oOOo0O0Ooo / o0oOOo0O0Ooo
   if 1 - 1: Ii1I
   if ( Iii111I == None ) :
    iIIIIIi11Ii = rloc . rloc . print_address_no_iid ( )
    O0ooO0oOO = "gleaned-{}" . format ( iIIIIIi11Ii )
    OoOoO = rloc . translated_port
    Iii111I = lisp_nat_info ( iIIIIIi11Ii , O0ooO0oOO , OoOoO )
    if 43 - 43: o0oOOo0O0Ooo
   lisp_encapsulate_rloc_probe ( lisp_sockets , I1ioOo0oO0O0 , Iii111I ,
 i1II1IiiIi )
   return
   if 78 - 78: I1Ii111 % i1IIi * I11i
   if 59 - 59: OoOoOO00 % OoO0O00 % i11iIiiIii . II111iiii % I1ii11iIi11i + i1IIi
  I1iiIiiii1111 = I1ioOo0oO0O0 . print_address_no_iid ( )
  iI111I1 = lisp_convert_4to6 ( I1iiIiiii1111 )
  lisp_send ( lisp_sockets , iI111I1 , LISP_CTRL_PORT , i1II1IiiIi )
  return
  if 99 - 99: I11i + IiII * I1Ii111 - OOooOOo - i1IIi
  if 77 - 77: I11i . IiII / OoO0O00 / I1Ii111
  if 8 - 8: o0oOOo0O0Ooo + iII111i / OoO0O00 * ooOoO0o - oO0o . iII111i
  if 32 - 32: OoooooooOO . I1Ii111 - I1ii11iIi11i
  if 29 - 29: OoO0O00
  if 33 - 33: I1ii11iIi11i - O0
 oOO000o00O0o = None if lisp_i_am_rtr else seid
 if ( lisp_decent_pull_xtr_configured ( ) ) :
  oOO0O000OOo0 = lisp_get_decent_map_resolver ( deid )
 else :
  oOO0O000OOo0 = lisp_get_map_resolver ( None , oOO000o00O0o )
  if 11 - 11: OoOoOO00 - I1Ii111 / OOooOOo
 if ( oOO0O000OOo0 == None ) :
  lprint ( "Cannot find Map-Resolver for source-EID {}" . format ( green ( seid . print_address ( ) , False ) ) )
  if 12 - 12: IiII + OoO0O00
  return
  if 18 - 18: I1Ii111 / OoooooooOO
 oOO0O000OOo0 . last_used = lisp_get_timestamp ( )
 oOO0O000OOo0 . map_requests_sent += 1
 if ( oOO0O000OOo0 . last_nonce == 0 ) : oOO0O000OOo0 . last_nonce = oooO0o . nonce
 if 77 - 77: oO0o % I11i + i1IIi + Oo0Ooo + I1Ii111 + OoO0O00
 if 78 - 78: O0 . oO0o
 if 72 - 72: O0 - IiII
 if 49 - 49: IiII - OOooOOo * OOooOOo . O0
 if ( seid == None ) : seid = Ii1
 lisp_send_ecm ( lisp_sockets , i1II1IiiIi , seid , lisp_ephem_port , deid ,
 oOO0O000OOo0 . map_resolver )
 if 60 - 60: OoOoOO00 % iIii1I11I1II1 + IiII % o0oOOo0O0Ooo
 if 64 - 64: OoOoOO00 * I1ii11iIi11i . OoooooooOO . i1IIi
 if 61 - 61: OoO0O00
 if 100 - 100: OoOoOO00
 lisp_last_map_request_sent = lisp_get_timestamp ( )
 if 97 - 97: OoooooooOO
 if 91 - 91: o0oOOo0O0Ooo / O0 % OoO0O00
 if 35 - 35: iII111i % OoO0O00 * O0
 if 37 - 37: OOooOOo
 oOO0O000OOo0 . resolve_dns_name ( )
 return
 if 100 - 100: Oo0Ooo * I1IiiI . ooOoO0o
 if 53 - 53: OOooOOo + o0oOOo0O0Ooo * Ii1I + O0
 if 75 - 75: OoooooooOO
 if 24 - 24: I1Ii111 % i11iIiiIii % oO0o . OOooOOo % IiII
 if 23 - 23: o0oOOo0O0Ooo * II111iiii - Oo0Ooo - I1IiiI
 if 86 - 86: I1IiiI - II111iiii * II111iiii * oO0o % OoooooooOO * OoOoOO00
 if 93 - 93: I1IiiI + OoO0O00 % O0 - ooOoO0o * i1IIi
 if 60 - 60: I1IiiI
def lisp_send_info_request ( lisp_sockets , dest , port , device_name ) :
 if 9 - 9: I11i % i1IIi / ooOoO0o % iII111i - oO0o - II111iiii
 if 29 - 29: ooOoO0o . II111iiii . i1IIi % oO0o
 if 11 - 11: OoOoOO00 . OoO0O00 % I11i * iII111i % I1Ii111 . O0
 if 17 - 17: OOooOOo / i11iIiiIii - i11iIiiIii . II111iiii . ooOoO0o
 IIiiiIiIII = lisp_info ( )
 IIiiiIiIII . nonce = lisp_get_control_nonce ( )
 if ( device_name ) : IIiiiIiIII . hostname += "-" + device_name
 if 36 - 36: oO0o + Ii1I - O0
 I1iiIiiii1111 = dest . print_address_no_iid ( )
 if 19 - 19: O0 + I1Ii111 . I1Ii111 * IiII * ooOoO0o + i1IIi
 if 51 - 51: ooOoO0o % OoOoOO00 % i1IIi / O0
 if 11 - 11: OOooOOo . I1ii11iIi11i * OOooOOo * OoO0O00
 if 11 - 11: I11i
 if 85 - 85: OoOoOO00 - Ii1I / Oo0Ooo % I1ii11iIi11i
 if 12 - 12: i1IIi + o0oOOo0O0Ooo / oO0o . O0
 if 37 - 37: IiII
 if 99 - 99: i11iIiiIii % i11iIiiIii . I11i * I1ii11iIi11i . OoO0O00 / I1IiiI
 if 44 - 44: iII111i - OoO0O00 / i11iIiiIii
 if 55 - 55: O0 * OoO0O00 * i1IIi
 if 9 - 9: IiII
 if 64 - 64: ooOoO0o + OoooooooOO
 if 99 - 99: iIii1I11I1II1 * II111iiii * i11iIiiIii
 if 10 - 10: OOooOOo
 if 75 - 75: I11i * ooOoO0o * Oo0Ooo . i1IIi . ooOoO0o . ooOoO0o
 if 24 - 24: iIii1I11I1II1
 Oo0O00o = False
 if ( device_name ) :
  o0OoOoOO0 = lisp_get_host_route_next_hop ( I1iiIiiii1111 )
  if 25 - 25: OoO0O00 % IiII * iIii1I11I1II1 - oO0o / o0oOOo0O0Ooo . o0oOOo0O0Ooo
  if 73 - 73: OoOoOO00 . OoooooooOO
  if 14 - 14: i1IIi - OOooOOo / I1IiiI + Ii1I
  if 89 - 89: I1IiiI + i11iIiiIii % I1Ii111
  if 69 - 69: OoooooooOO + I1Ii111 * OoO0O00
  if 84 - 84: OoOoOO00
  if 80 - 80: oO0o
  if 59 - 59: iIii1I11I1II1 / IiII % I1ii11iIi11i + OoO0O00 - I11i % OOooOOo
  if 92 - 92: iII111i
  if ( port == LISP_CTRL_PORT and o0OoOoOO0 != None ) :
   while ( True ) :
    time . sleep ( .01 )
    o0OoOoOO0 = lisp_get_host_route_next_hop ( I1iiIiiii1111 )
    if ( o0OoOoOO0 == None ) : break
    if 96 - 96: OoOoOO00 / OoOoOO00 / OoOoOO00 + OoooooooOO + Oo0Ooo
    if 91 - 91: OoOoOO00 + II111iiii / I11i * iIii1I11I1II1
    if 92 - 92: I1Ii111 - IiII / IiII
  iiiiI1I11iI1 = lisp_get_default_route_next_hops ( )
  for O0OoO0o , i11i1i in iiiiI1I11iI1 :
   if ( O0OoO0o != device_name ) : continue
   if 51 - 51: ooOoO0o / OoOoOO00 % OOooOOo * i11iIiiIii
   if 21 - 21: I1ii11iIi11i / I1ii11iIi11i % iII111i . Oo0Ooo * Oo0Ooo . i11iIiiIii
   if 73 - 73: i1IIi - i11iIiiIii - Ii1I % oO0o
   if 99 - 99: ooOoO0o % I1IiiI
   if 11 - 11: OoO0O00 - I1Ii111 . Ii1I + OoooooooOO
   if 98 - 98: OOooOOo . ooOoO0o . OoOoOO00 - I1Ii111 . i1IIi - iIii1I11I1II1
   if ( o0OoOoOO0 != i11i1i ) :
    if ( o0OoOoOO0 != None ) :
     lisp_install_host_route ( I1iiIiiii1111 , o0OoOoOO0 , False )
     if 89 - 89: II111iiii * I1ii11iIi11i - I1IiiI
    lisp_install_host_route ( I1iiIiiii1111 , i11i1i , True )
    Oo0O00o = True
    if 58 - 58: Ii1I / Oo0Ooo % IiII
   break
   if 33 - 33: II111iiii . OOooOOo % iIii1I11I1II1 - Oo0Ooo - OoOoOO00 % i11iIiiIii
   if 60 - 60: iII111i . o0oOOo0O0Ooo
   if 56 - 56: I1ii11iIi11i
   if 89 - 89: Oo0Ooo + I1ii11iIi11i * o0oOOo0O0Ooo * oO0o % O0 % OoO0O00
   if 70 - 70: o0oOOo0O0Ooo + O0 % I1IiiI
   if 56 - 56: Ii1I
 i1II1IiiIi = IIiiiIiIII . encode ( )
 IIiiiIiIII . print_info ( )
 if 84 - 84: iII111i
 if 21 - 21: i11iIiiIii
 if 30 - 30: OoO0O00 + OoooooooOO
 if 98 - 98: I1ii11iIi11i % I1IiiI
 II11o0ooOOo0OoO = "(for control)" if port == LISP_CTRL_PORT else "(for data)"
 II11o0ooOOo0OoO = bold ( II11o0ooOOo0OoO , False )
 OoOoO = bold ( "{}" . format ( port ) , False )
 oOO0oo = red ( I1iiIiiii1111 , False )
 oOOoOO = "RTR " if port == LISP_DATA_PORT else "MS "
 lprint ( "Send Info-Request to {}{}, port {} {}" . format ( oOOoOO , oOO0oo , OoOoO , II11o0ooOOo0OoO ) )
 if 63 - 63: I11i
 if 32 - 32: Ii1I . I1ii11iIi11i + OoooooooOO - OoooooooOO + i1IIi
 if 42 - 42: i1IIi
 if 33 - 33: iIii1I11I1II1 * i11iIiiIii
 if 7 - 7: oO0o
 if 89 - 89: i11iIiiIii / o0oOOo0O0Ooo / I1ii11iIi11i % iII111i . OoooooooOO - iIii1I11I1II1
 if ( port == LISP_CTRL_PORT ) :
  lisp_send ( lisp_sockets , dest , LISP_CTRL_PORT , i1II1IiiIi )
 else :
  iIiI1I1II1 = lisp_data_header ( )
  iIiI1I1II1 . instance_id ( 0xffffff )
  iIiI1I1II1 = iIiI1I1II1 . encode ( )
  if ( iIiI1I1II1 ) :
   i1II1IiiIi = iIiI1I1II1 + i1II1IiiIi
   if 63 - 63: Ii1I % I1Ii111 + O0 * OoO0O00 . oO0o
   if 34 - 34: I1IiiI . I1ii11iIi11i . O0 - OoOoOO00 - i11iIiiIii / iII111i
   if 63 - 63: OOooOOo
   if 84 - 84: i11iIiiIii * iIii1I11I1II1 % I11i % iII111i + OoooooooOO . o0oOOo0O0Ooo
   if 78 - 78: o0oOOo0O0Ooo . iII111i + O0 / I1ii11iIi11i + I1ii11iIi11i + II111iiii
   if 96 - 96: iIii1I11I1II1 * II111iiii . iIii1I11I1II1
   if 13 - 13: Ii1I - OoOoOO00 . Ii1I
   if 7 - 7: Ii1I - I11i / I1ii11iIi11i + iII111i
   if 47 - 47: I11i * IiII / oO0o - OoooooooOO . OoooooooOO / I11i
   lisp_send ( lisp_sockets , dest , LISP_DATA_PORT , i1II1IiiIi )
   if 73 - 73: Ii1I . IiII % IiII
   if 56 - 56: I1Ii111 + iII111i + iII111i
   if 99 - 99: o0oOOo0O0Ooo % I1ii11iIi11i / Oo0Ooo . O0 + OoO0O00 * OoOoOO00
   if 48 - 48: iIii1I11I1II1 + O0 * I11i * i11iIiiIii . Ii1I / i1IIi
   if 48 - 48: i1IIi % iIii1I11I1II1 + I1IiiI - OoOoOO00 % I11i . I1Ii111
   if 66 - 66: I1Ii111 * i11iIiiIii + I1IiiI % II111iiii
   if 47 - 47: II111iiii % o0oOOo0O0Ooo
 if ( Oo0O00o ) :
  lisp_install_host_route ( I1iiIiiii1111 , None , False )
  if ( o0OoOoOO0 != None ) : lisp_install_host_route ( I1iiIiiii1111 , o0OoOoOO0 , True )
  if 26 - 26: I1ii11iIi11i / I11i / Oo0Ooo / i1IIi + O0 * ooOoO0o
 return
 if 53 - 53: IiII / II111iiii / oO0o % O0 / I1Ii111
 if 91 - 91: oO0o * OoOoOO00 + O0 % Oo0Ooo
 if 62 - 62: iIii1I11I1II1 - i11iIiiIii % iIii1I11I1II1 . ooOoO0o / OOooOOo * OoOoOO00
 if 45 - 45: OOooOOo - OOooOOo % iII111i - IiII . O0
 if 6 - 6: iIii1I11I1II1 * II111iiii / O0 % IiII - I1Ii111
 if 64 - 64: ooOoO0o
 if 28 - 28: i11iIiiIii - IiII * I1ii11iIi11i + IiII * iII111i
def lisp_process_info_request ( lisp_sockets , packet , addr_str , sport , rtr_list ) :
 if 75 - 75: o0oOOo0O0Ooo * OoOoOO00 % I1ii11iIi11i + OOooOOo . II111iiii
 if 12 - 12: ooOoO0o
 if 83 - 83: I1Ii111 % ooOoO0o + OoooooooOO
 if 50 - 50: i11iIiiIii % I1IiiI * iII111i / Ii1I
 IIiiiIiIII = lisp_info ( )
 packet = IIiiiIiIII . decode ( packet )
 if ( packet == None ) : return
 IIiiiIiIII . print_info ( )
 if 12 - 12: iII111i / OoO0O00 - II111iiii + Oo0Ooo
 if 78 - 78: i1IIi
 if 25 - 25: Ii1I * II111iiii / OoOoOO00
 if 86 - 86: i1IIi + I1IiiI + I1Ii111 % II111iiii . IiII - iIii1I11I1II1
 if 54 - 54: i11iIiiIii . Ii1I % I1IiiI . I1Ii111 . OoooooooOO
 IIiiiIiIII . info_reply = True
 IIiiiIiIII . global_etr_rloc . store_address ( addr_str )
 IIiiiIiIII . etr_port = sport
 if 49 - 49: OOooOOo % I11i - OOooOOo + Ii1I . I1ii11iIi11i + ooOoO0o
 if 15 - 15: i11iIiiIii
 if 85 - 85: I1Ii111 + iII111i - oO0o
 if 59 - 59: IiII . oO0o / i11iIiiIii . I1Ii111
 if 64 - 64: OoOoOO00
 if ( IIiiiIiIII . hostname != None ) :
  IIiiiIiIII . private_etr_rloc . afi = LISP_AFI_NAME
  IIiiiIiIII . private_etr_rloc . store_address ( IIiiiIiIII . hostname )
  if 20 - 20: OoOoOO00 / O0 * OOooOOo % I11i + OoO0O00 + o0oOOo0O0Ooo
  if 51 - 51: Ii1I - OoOoOO00 / i11iIiiIii + O0
 if ( rtr_list != None ) : IIiiiIiIII . rtr_list = rtr_list
 packet = IIiiiIiIII . encode ( )
 IIiiiIiIII . print_info ( )
 if 71 - 71: ooOoO0o
 if 35 - 35: OoOoOO00
 if 55 - 55: iII111i - o0oOOo0O0Ooo + IiII * II111iiii
 if 6 - 6: I1Ii111 / i1IIi / IiII . o0oOOo0O0Ooo
 if 69 - 69: ooOoO0o - OoOoOO00 . I1IiiI . I11i + OoOoOO00 / i11iIiiIii
 lprint ( "Send Info-Reply to {}" . format ( red ( addr_str , False ) ) )
 iI111I1 = lisp_convert_4to6 ( addr_str )
 lisp_send ( lisp_sockets , iI111I1 , sport , packet )
 if 20 - 20: OoO0O00 . OoooooooOO - ooOoO0o . I11i / Oo0Ooo
 if 89 - 89: iIii1I11I1II1 . ooOoO0o
 if 82 - 82: OoOoOO00 - II111iiii . OoO0O00 * ooOoO0o
 if 78 - 78: OoOoOO00 % oO0o
 if 39 - 39: iIii1I11I1II1
 Ooo000o = lisp_info_source ( IIiiiIiIII . hostname , addr_str , sport )
 Ooo000o . cache_address_for_info_source ( )
 return
 if 95 - 95: OoooooooOO + OOooOOo + II111iiii + IiII + OoO0O00
 if 86 - 86: II111iiii / iII111i - I1ii11iIi11i
 if 65 - 65: I1ii11iIi11i + OoOoOO00
 if 43 - 43: O0 + I11i % II111iiii
 if 56 - 56: IiII + Oo0Ooo . IiII % iIii1I11I1II1 % ooOoO0o % ooOoO0o
 if 70 - 70: ooOoO0o / i1IIi - I11i - i11iIiiIii
 if 79 - 79: OoO0O00 - OoooooooOO % iII111i . O0
 if 93 - 93: I1Ii111
def lisp_get_signature_eid ( ) :
 for I111I in lisp_db_list :
  if ( I111I . signature_eid ) : return ( I111I )
  if 3 - 3: OoO0O00 / IiII - oO0o / oO0o
 return ( None )
 if 50 - 50: II111iiii + OoOoOO00
 if 17 - 17: ooOoO0o + I1ii11iIi11i
 if 34 - 34: Ii1I / II111iiii + OoOoOO00 . II111iiii + OoooooooOO * o0oOOo0O0Ooo
 if 48 - 48: O0
 if 99 - 99: II111iiii * oO0o / I1ii11iIi11i - i1IIi
 if 84 - 84: i11iIiiIii . OoooooooOO
 if 69 - 69: I1Ii111 * II111iiii % I1Ii111 * i11iIiiIii . ooOoO0o / Oo0Ooo
 if 5 - 5: Ii1I
def lisp_get_any_translated_port ( ) :
 for I111I in lisp_db_list :
  for IiI1I1iii11 in I111I . rloc_set :
   if ( IiI1I1iii11 . translated_rloc . is_null ( ) ) : continue
   return ( IiI1I1iii11 . translated_port )
   if 19 - 19: oO0o
   if 61 - 61: OoOoOO00 + iIii1I11I1II1 / I1ii11iIi11i - i1IIi
 return ( None )
 if 11 - 11: oO0o * o0oOOo0O0Ooo . I1IiiI
 if 12 - 12: I1IiiI % OoO0O00 / I1Ii111 / O0 % o0oOOo0O0Ooo
 if 1 - 1: OoOoOO00 / I11i
 if 43 - 43: o0oOOo0O0Ooo - i1IIi / Ii1I . OoOoOO00 + i11iIiiIii
 if 69 - 69: i11iIiiIii - iIii1I11I1II1
 if 40 - 40: I1IiiI / oO0o + ooOoO0o
 if 100 - 100: OoOoOO00 % iII111i * ooOoO0o . O0
 if 37 - 37: I1ii11iIi11i
 if 24 - 24: O0 . I1Ii111 * i11iIiiIii
def lisp_get_any_translated_rloc ( ) :
 for I111I in lisp_db_list :
  for IiI1I1iii11 in I111I . rloc_set :
   if ( IiI1I1iii11 . translated_rloc . is_null ( ) ) : continue
   return ( IiI1I1iii11 . translated_rloc )
   if 84 - 84: ooOoO0o / I1ii11iIi11i - o0oOOo0O0Ooo . OoooooooOO * iIii1I11I1II1
   if 16 - 16: I11i % O0
 return ( None )
 if 56 - 56: Ii1I * OoOoOO00 . i1IIi
 if 15 - 15: I1Ii111
 if 64 - 64: OOooOOo * Oo0Ooo
 if 96 - 96: Oo0Ooo / I1ii11iIi11i * iIii1I11I1II1 / iII111i
 if 18 - 18: I1Ii111
 if 29 - 29: i1IIi - I1IiiI / i1IIi
 if 64 - 64: IiII
def lisp_get_all_translated_rlocs ( ) :
 oOo = [ ]
 for I111I in lisp_db_list :
  for IiI1I1iii11 in I111I . rloc_set :
   if ( IiI1I1iii11 . is_rloc_translated ( ) == False ) : continue
   o0o0O00 = IiI1I1iii11 . translated_rloc . print_address_no_iid ( )
   oOo . append ( o0o0O00 )
   if 11 - 11: I1Ii111 * I1IiiI - I1Ii111 / iII111i
   if 22 - 22: iII111i % I11i % O0 - I11i
 return ( oOo )
 if 71 - 71: I1Ii111 / II111iiii - OoooooooOO % i1IIi + OoOoOO00 % OoooooooOO
 if 52 - 52: Ii1I . OoOoOO00 / o0oOOo0O0Ooo / iII111i
 if 83 - 83: OoO0O00 - Oo0Ooo + I1Ii111 . I1IiiI
 if 78 - 78: I11i / ooOoO0o . OoOoOO00 * i1IIi
 if 15 - 15: i1IIi . II111iiii * OoOoOO00 / Oo0Ooo
 if 99 - 99: iII111i - o0oOOo0O0Ooo / O0
 if 97 - 97: iIii1I11I1II1 * I1Ii111
 if 39 - 39: I1Ii111 . II111iiii
def lisp_update_default_routes ( map_resolver , iid , rtr_list ) :
 oO0OO0oOo00 = ( os . getenv ( "LISP_RTR_BEHIND_NAT" ) != None )
 if 94 - 94: OoO0O00 - OoO0O00 + iIii1I11I1II1 + O0 * oO0o
 I1iIiI1IiIIi = { }
 for OoOOo in rtr_list :
  if ( OoOOo == None ) : continue
  o0o0O00 = rtr_list [ OoOOo ]
  if ( oO0OO0oOo00 and o0o0O00 . is_private_address ( ) ) : continue
  I1iIiI1IiIIi [ OoOOo ] = o0o0O00
  if 78 - 78: II111iiii / i1IIi . OOooOOo / OOooOOo . OOooOOo
 rtr_list = I1iIiI1IiIIi
 if 14 - 14: I1Ii111
 I1I1i1II1I1Ii = [ ]
 for iioOO in [ LISP_AFI_IPV4 , LISP_AFI_IPV6 , LISP_AFI_MAC ] :
  if ( iioOO == LISP_AFI_MAC and lisp_l2_overlay == False ) : break
  if 76 - 76: oO0o
  if 42 - 42: OoO0O00 * i1IIi
  if 60 - 60: I1IiiI * I1Ii111 + oO0o - Ii1I
  if 58 - 58: i11iIiiIii . o0oOOo0O0Ooo - i1IIi - I1IiiI * i1IIi % I1Ii111
  if 37 - 37: I11i
  OoooO00OO0OO = lisp_address ( iioOO , "" , 0 , iid )
  OoooO00OO0OO . make_default_route ( OoooO00OO0OO )
  IIII = lisp_map_cache . lookup_cache ( OoooO00OO0OO , True )
  if ( IIII ) :
   if ( IIII . checkpoint_entry ) :
    lprint ( "Updating checkpoint entry for {}" . format ( green ( IIII . print_eid_tuple ( ) , False ) ) )
    if 61 - 61: OoooooooOO % iIii1I11I1II1 % O0 % I1Ii111 / Oo0Ooo . I1IiiI
   elif ( IIII . do_rloc_sets_match ( rtr_list . values ( ) ) ) :
    continue
    if 20 - 20: ooOoO0o - I1Ii111
   IIII . delete_cache ( )
   if 97 - 97: O0
   if 56 - 56: Ii1I * I1IiiI * ooOoO0o
  I1I1i1II1I1Ii . append ( [ OoooO00OO0OO , "" ] )
  if 39 - 39: iII111i % Ii1I * iIii1I11I1II1 - Ii1I - I1Ii111
  if 60 - 60: i11iIiiIii + i11iIiiIii - OoooooooOO + OoooooooOO
  if 5 - 5: o0oOOo0O0Ooo
  if 78 - 78: OOooOOo * O0 * II111iiii % OoOoOO00
  O0oo0oo0 = lisp_address ( iioOO , "" , 0 , iid )
  O0oo0oo0 . make_default_multicast_route ( O0oo0oo0 )
  IIOo0Oo00o0 = lisp_map_cache . lookup_cache ( O0oo0oo0 , True )
  if ( IIOo0Oo00o0 ) : IIOo0Oo00o0 = IIOo0Oo00o0 . source_cache . lookup_cache ( OoooO00OO0OO , True )
  if ( IIOo0Oo00o0 ) : IIOo0Oo00o0 . delete_cache ( )
  if 82 - 82: OoO0O00 + Ii1I
  I1I1i1II1I1Ii . append ( [ OoooO00OO0OO , O0oo0oo0 ] )
  if 3 - 3: iIii1I11I1II1 * I1ii11iIi11i * i1IIi - O0 - iII111i * O0
 if ( len ( I1I1i1II1I1Ii ) == 0 ) : return
 if 10 - 10: I1Ii111 . IiII * I1ii11iIi11i
 if 81 - 81: i11iIiiIii + I1Ii111
 if 65 - 65: OOooOOo - iII111i * I1Ii111 + i1IIi % ooOoO0o
 if 6 - 6: O0 + Ii1I % II111iiii % i1IIi . iII111i / OoooooooOO
 oooo0O = [ ]
 for oOOoOO in rtr_list :
  I1IIIIi = rtr_list [ oOOoOO ]
  IiI1I1iii11 = lisp_rloc ( )
  IiI1I1iii11 . rloc . copy_address ( I1IIIIi )
  IiI1I1iii11 . priority = 254
  IiI1I1iii11 . mpriority = 255
  IiI1I1iii11 . rloc_name = "RTR"
  oooo0O . append ( IiI1I1iii11 )
  if 23 - 23: Ii1I
  if 92 - 92: II111iiii - IiII / II111iiii
 for OoooO00OO0OO in I1I1i1II1I1Ii :
  IIII = lisp_mapping ( OoooO00OO0OO [ 0 ] , OoooO00OO0OO [ 1 ] , oooo0O )
  IIII . mapping_source = map_resolver
  IIII . map_cache_ttl = LISP_MR_TTL * 60
  IIII . add_cache ( )
  lprint ( "Add {} to map-cache with RTR RLOC-set: {}" . format ( green ( IIII . print_eid_tuple ( ) , False ) , rtr_list . keys ( ) ) )
  if 23 - 23: Ii1I * II111iiii - I1ii11iIi11i
  oooo0O = copy . deepcopy ( oooo0O )
  if 86 - 86: ooOoO0o . OoO0O00 + I1Ii111 - I11i % i11iIiiIii / OoOoOO00
 return
 if 47 - 47: IiII
 if 32 - 32: i1IIi / iIii1I11I1II1 / iII111i
 if 11 - 11: I1ii11iIi11i - iIii1I11I1II1
 if 15 - 15: o0oOOo0O0Ooo + OoooooooOO
 if 68 - 68: ooOoO0o / I1Ii111 * OoO0O00 + ooOoO0o / iIii1I11I1II1 . iII111i
 if 91 - 91: OoO0O00
 if 8 - 8: oO0o
 if 96 - 96: IiII
 if 37 - 37: Ii1I % i11iIiiIii + iIii1I11I1II1 % Oo0Ooo - iIii1I11I1II1
 if 26 - 26: o0oOOo0O0Ooo . i1IIi
def lisp_process_info_reply ( source , packet , store ) :
 if 62 - 62: IiII * I1ii11iIi11i % iIii1I11I1II1 / II111iiii - OoO0O00
 if 52 - 52: iII111i . I11i - I11i + oO0o + iIii1I11I1II1
 if 83 - 83: I11i * iIii1I11I1II1 + OoOoOO00
 if 81 - 81: ooOoO0o * OOooOOo / OoO0O00 + I1ii11iIi11i % I1Ii111
 IIiiiIiIII = lisp_info ( )
 packet = IIiiiIiIII . decode ( packet )
 if ( packet == None ) : return ( [ None , None , False ] )
 if 37 - 37: i11iIiiIii - OoooooooOO - OoOoOO00 * oO0o / Ii1I
 IIiiiIiIII . print_info ( )
 if 100 - 100: II111iiii / Oo0Ooo / iII111i / OOooOOo
 if 100 - 100: iIii1I11I1II1
 if 50 - 50: I1Ii111 / ooOoO0o * I11i
 if 53 - 53: II111iiii . IiII
 ii1iII111i = False
 for oOOoOO in IIiiiIiIII . rtr_list :
  I1iiIiiii1111 = oOOoOO . print_address_no_iid ( )
  if ( lisp_rtr_list . has_key ( I1iiIiiii1111 ) ) :
   if ( lisp_register_all_rtrs == False ) : continue
   if ( lisp_rtr_list [ I1iiIiiii1111 ] != None ) : continue
   if 80 - 80: IiII - i11iIiiIii % I11i
  ii1iII111i = True
  lisp_rtr_list [ I1iiIiiii1111 ] = oOOoOO
  if 5 - 5: OoooooooOO
  if 5 - 5: iII111i + oO0o % O0 . OoooooooOO + i1IIi
  if 55 - 55: I1ii11iIi11i
  if 34 - 34: OoO0O00 * iIii1I11I1II1 . iIii1I11I1II1
  if 39 - 39: o0oOOo0O0Ooo
 if ( lisp_i_am_itr and ii1iII111i ) :
  if ( lisp_iid_to_interface == { } ) :
   lisp_update_default_routes ( source , lisp_default_iid , lisp_rtr_list )
  else :
   for o0OOoOO in lisp_iid_to_interface . keys ( ) :
    lisp_update_default_routes ( source , int ( o0OOoOO ) , lisp_rtr_list )
    if 29 - 29: Oo0Ooo . Oo0Ooo * OoO0O00 % Ii1I - ooOoO0o
    if 67 - 67: I1IiiI % O0 + I1IiiI * I1Ii111 * OoOoOO00 * II111iiii
    if 79 - 79: I1IiiI
    if 37 - 37: I1Ii111 + Ii1I
    if 50 - 50: i11iIiiIii
    if 57 - 57: O0 * i1IIi - I1IiiI
    if 48 - 48: IiII / iIii1I11I1II1
 if ( store == False ) :
  return ( [ IIiiiIiIII . global_etr_rloc , IIiiiIiIII . etr_port , ii1iII111i ] )
  if 20 - 20: oO0o / OoooooooOO
  if 95 - 95: Oo0Ooo . i11iIiiIii
  if 50 - 50: iII111i . i11iIiiIii - i1IIi
  if 24 - 24: i11iIiiIii % iII111i . oO0o
  if 44 - 44: II111iiii - OoO0O00 + i11iIiiIii
  if 34 - 34: I1ii11iIi11i % ooOoO0o / II111iiii * O0 % OOooOOo
 for I111I in lisp_db_list :
  for IiI1I1iii11 in I111I . rloc_set :
   OoOOo = IiI1I1iii11 . rloc
   I111IIiIII = IiI1I1iii11 . interface
   if ( I111IIiIII == None ) :
    if ( OoOOo . is_null ( ) ) : continue
    if ( OoOOo . is_local ( ) == False ) : continue
    if ( IIiiiIiIII . private_etr_rloc . is_null ( ) == False and
 OoOOo . is_exact_match ( IIiiiIiIII . private_etr_rloc ) == False ) :
     continue
     if 9 - 9: I1ii11iIi11i / I1ii11iIi11i - OOooOOo . iIii1I11I1II1
   elif ( IIiiiIiIII . private_etr_rloc . is_dist_name ( ) ) :
    OO000 = IIiiiIiIII . private_etr_rloc . address
    if ( OO000 != IiI1I1iii11 . rloc_name ) : continue
    if 33 - 33: I1IiiI + oO0o % I1IiiI / iII111i - ooOoO0o - i11iIiiIii
    if 39 - 39: i11iIiiIii / oO0o
   oOoo0OooOOo00 = green ( I111I . eid . print_prefix ( ) , False )
   ooOo = red ( OoOOo . print_address_no_iid ( ) , False )
   if 71 - 71: I1Ii111 * iIii1I11I1II1 - I1Ii111
   oo0Oi1ii = IIiiiIiIII . global_etr_rloc . is_exact_match ( OoOOo )
   if ( IiI1I1iii11 . translated_port == 0 and oo0Oi1ii ) :
    lprint ( "No NAT for {} ({}), EID-prefix {}" . format ( ooOo ,
 I111IIiIII , oOoo0OooOOo00 ) )
    continue
    if 38 - 38: I1ii11iIi11i + I1Ii111 / IiII % oO0o
    if 42 - 42: ooOoO0o
    if 62 - 62: OOooOOo + OoOoOO00 . iII111i
    if 26 - 26: OOooOOo
    if 89 - 89: i11iIiiIii . o0oOOo0O0Ooo % iIii1I11I1II1 * O0 + OOooOOo . o0oOOo0O0Ooo
   iI1iI1II1i1i = IIiiiIiIII . global_etr_rloc
   o00O00O0OO0O = IiI1I1iii11 . translated_rloc
   if ( o00O00O0OO0O . is_exact_match ( iI1iI1II1i1i ) and
 IIiiiIiIII . etr_port == IiI1I1iii11 . translated_port ) : continue
   if 3 - 3: iIii1I11I1II1 + iIii1I11I1II1 + OoO0O00
   lprint ( "Store translation {}:{} for {} ({}), EID-prefix {}" . format ( red ( IIiiiIiIII . global_etr_rloc . print_address_no_iid ( ) , False ) ,
   # iII111i . Ii1I . o0oOOo0O0Ooo * oO0o
 IIiiiIiIII . etr_port , ooOo , I111IIiIII , oOoo0OooOOo00 ) )
   if 18 - 18: iII111i % I1Ii111 / I1Ii111 % OoOoOO00 - OoOoOO00 + I1IiiI
   IiI1I1iii11 . store_translated_rloc ( IIiiiIiIII . global_etr_rloc ,
 IIiiiIiIII . etr_port )
   if 13 - 13: oO0o - o0oOOo0O0Ooo * oO0o
   if 27 - 27: OOooOOo * iII111i * I11i
 return ( [ IIiiiIiIII . global_etr_rloc , IIiiiIiIII . etr_port , ii1iII111i ] )
 if 65 - 65: iII111i + OoO0O00 - iIii1I11I1II1 / OoooooooOO . ooOoO0o . o0oOOo0O0Ooo
 if 94 - 94: ooOoO0o . oO0o * OoooooooOO % oO0o
 if 77 - 77: ooOoO0o % I1IiiI
 if 26 - 26: o0oOOo0O0Ooo
 if 72 - 72: I1IiiI
 if 90 - 90: ooOoO0o
 if 67 - 67: iIii1I11I1II1 + i1IIi * I1IiiI * OoooooooOO
 if 23 - 23: IiII
def lisp_test_mr ( lisp_sockets , port ) :
 return
 lprint ( "Test Map-Resolvers" )
 if 32 - 32: OoOoOO00 - iII111i % oO0o / I1ii11iIi11i - o0oOOo0O0Ooo
 i1OO0o = lisp_address ( LISP_AFI_IPV4 , "" , 0 , 0 )
 O00oiI1i1iIII11 = lisp_address ( LISP_AFI_IPV6 , "" , 0 , 0 )
 if 67 - 67: OOooOOo - II111iiii * OoO0O00 . I1ii11iIi11i
 if 9 - 9: OoO0O00 - OoO0O00 / i11iIiiIii . iII111i / I1ii11iIi11i . OoOoOO00
 if 89 - 89: I11i * iIii1I11I1II1 - I1ii11iIi11i
 if 82 - 82: iIii1I11I1II1
 i1OO0o . store_address ( "10.0.0.1" )
 lisp_send_map_request ( lisp_sockets , port , None , i1OO0o , None )
 i1OO0o . store_address ( "192.168.0.1" )
 lisp_send_map_request ( lisp_sockets , port , None , i1OO0o , None )
 if 18 - 18: Ii1I . i11iIiiIii - i1IIi * OoooooooOO
 if 52 - 52: Oo0Ooo + I11i - OoooooooOO + iII111i - oO0o
 if 2 - 2: oO0o * OoO0O00 - IiII
 if 24 - 24: O0 * OOooOOo . OoO0O00 + iII111i + i1IIi + oO0o
 O00oiI1i1iIII11 . store_address ( "0100::1" )
 lisp_send_map_request ( lisp_sockets , port , None , O00oiI1i1iIII11 , None )
 O00oiI1i1iIII11 . store_address ( "8000::1" )
 lisp_send_map_request ( lisp_sockets , port , None , O00oiI1i1iIII11 , None )
 if 57 - 57: OOooOOo * OOooOOo
 if 63 - 63: o0oOOo0O0Ooo * iIii1I11I1II1 - II111iiii
 if 72 - 72: o0oOOo0O0Ooo * I1ii11iIi11i
 if 57 - 57: IiII * OOooOOo
 ii1IIIIIiII1 = threading . Timer ( LISP_TEST_MR_INTERVAL , lisp_test_mr ,
 [ lisp_sockets , port ] )
 ii1IIIIIiII1 . start ( )
 return
 if 10 - 10: I1ii11iIi11i
 if 6 - 6: OoO0O00 + OoO0O00 * OOooOOo / IiII % ooOoO0o - I1IiiI
 if 17 - 17: II111iiii
 if 66 - 66: O0 % OoOoOO00 + IiII % I1Ii111
 if 94 - 94: OoOoOO00 / OoooooooOO % Ii1I * i11iIiiIii
 if 95 - 95: iIii1I11I1II1 % OOooOOo % O0
 if 93 - 93: I1ii11iIi11i
 if 61 - 61: o0oOOo0O0Ooo * ooOoO0o
 if 82 - 82: O0 * O0 % I1IiiI / o0oOOo0O0Ooo
 if 46 - 46: IiII . O0 . I11i % I1ii11iIi11i * oO0o - oO0o
 if 92 - 92: I1IiiI - I1IiiI
 if 28 - 28: oO0o * iII111i + IiII
 if 73 - 73: OoooooooOO
def lisp_update_local_rloc ( rloc ) :
 if ( rloc . interface == None ) : return
 if 45 - 45: IiII + I1IiiI * I1Ii111
 o0o0O00 = lisp_get_interface_address ( rloc . interface )
 if ( o0o0O00 == None ) : return
 if 82 - 82: OOooOOo / I11i % Ii1I * OoOoOO00
 oOOo0oo0OOO = rloc . rloc . print_address_no_iid ( )
 IIi1i1iI11I11 = o0o0O00 . print_address_no_iid ( )
 if 23 - 23: i11iIiiIii
 if ( oOOo0oo0OOO == IIi1i1iI11I11 ) : return
 if 14 - 14: I1ii11iIi11i + I1IiiI % I1Ii111
 lprint ( "Local interface address changed on {} from {} to {}" . format ( rloc . interface , oOOo0oo0OOO , IIi1i1iI11I11 ) )
 if 48 - 48: o0oOOo0O0Ooo . OoooooooOO * Oo0Ooo
 if 14 - 14: OoO0O00
 rloc . rloc . copy_address ( o0o0O00 )
 lisp_myrlocs [ 0 ] = o0o0O00
 return
 if 21 - 21: II111iiii + i11iIiiIii + I11i % I1IiiI
 if 65 - 65: IiII + I1ii11iIi11i / iII111i / I1IiiI + Ii1I
 if 88 - 88: IiII % iIii1I11I1II1
 if 3 - 3: ooOoO0o / I1Ii111 % iIii1I11I1II1 % I11i * oO0o / iIii1I11I1II1
 if 75 - 75: i11iIiiIii . iII111i
 if 68 - 68: OOooOOo . I1ii11iIi11i % I1ii11iIi11i . i11iIiiIii
 if 45 - 45: oO0o % I1ii11iIi11i * I1Ii111
 if 21 - 21: O0 + i11iIiiIii
def lisp_update_encap_port ( mc ) :
 for OoOOo in mc . rloc_set :
  Iii111I = lisp_get_nat_info ( OoOOo . rloc , OoOOo . rloc_name )
  if ( Iii111I == None ) : continue
  if ( OoOOo . translated_port == Iii111I . port ) : continue
  if 72 - 72: OoOoOO00 * OoooooooOO % O0 / I1ii11iIi11i % Ii1I - I11i
  lprint ( ( "Encap-port changed from {} to {} for RLOC {}, " + "EID-prefix {}" ) . format ( OoOOo . translated_port , Iii111I . port ,
  # OoOoOO00 % ooOoO0o . I1Ii111 / OoO0O00
 red ( OoOOo . rloc . print_address_no_iid ( ) , False ) ,
 green ( mc . print_eid_tuple ( ) , False ) ) )
  if 21 - 21: IiII
  OoOOo . store_translated_rloc ( OoOOo . rloc , Iii111I . port )
  if 15 - 15: OoOoOO00 % O0 - OOooOOo - oO0o . iII111i . OoO0O00
 return
 if 52 - 52: II111iiii * o0oOOo0O0Ooo
 if 95 - 95: I1Ii111 - OoooooooOO
 if 99 - 99: OoooooooOO % IiII . I11i + OoooooooOO
 if 57 - 57: Ii1I / I1IiiI * i1IIi
 if 21 - 21: I11i . O0 * OoooooooOO + ooOoO0o * oO0o % i11iIiiIii
 if 30 - 30: ooOoO0o * I1Ii111 + OoO0O00
 if 30 - 30: Ii1I / iII111i * Ii1I
 if 11 - 11: OoOoOO00 - OoOoOO00 % oO0o
 if 3 - 3: I1IiiI - OoooooooOO % iIii1I11I1II1 + I1Ii111 + OoOoOO00
 if 71 - 71: i1IIi % O0 % ooOoO0o
 if 24 - 24: O0
 if 88 - 88: OoooooooOO / Oo0Ooo / oO0o
def lisp_timeout_map_cache_entry ( mc , delete_list ) :
 if ( mc . map_cache_ttl == None ) :
  lisp_update_encap_port ( mc )
  return ( [ True , delete_list ] )
  if 99 - 99: I1Ii111 % OoOoOO00 % IiII - Ii1I
  if 79 - 79: ooOoO0o + Oo0Ooo
  if 80 - 80: OoOoOO00 % OoO0O00 . OoO0O00 * OoO0O00 * O0
  if 18 - 18: II111iiii . o0oOOo0O0Ooo + OoO0O00
  if 69 - 69: OoO0O00 . ooOoO0o * ooOoO0o * iIii1I11I1II1
 if ( mc . action == LISP_NO_ACTION ) :
  i111I1I1i = lisp_get_timestamp ( )
  if ( mc . last_refresh_time + mc . map_cache_ttl > i111I1I1i ) :
   lisp_update_encap_port ( mc )
   return ( [ True , delete_list ] )
   if 8 - 8: iII111i . oO0o . OOooOOo + iII111i . Ii1I
   if 46 - 46: OoO0O00
   if 21 - 21: iIii1I11I1II1 - iII111i
   if 15 - 15: O0 + iII111i + i11iIiiIii
   if 31 - 31: iIii1I11I1II1 * iIii1I11I1II1 . I11i
   if 52 - 52: i11iIiiIii / oO0o / IiII
 i11IiIIi11I = lisp_print_elapsed ( mc . last_refresh_time )
 iiI11IIii1i1 = mc . print_eid_tuple ( )
 lprint ( "Map-cache entry for EID-prefix {} has {}, had uptime of {}" . format ( green ( iiI11IIii1i1 , False ) , bold ( "timed out" , False ) , i11IiIIi11I ) )
 if 84 - 84: I11i . oO0o + ooOoO0o
 if 75 - 75: I1Ii111
 if 97 - 97: ooOoO0o % Oo0Ooo . o0oOOo0O0Ooo
 if 22 - 22: O0 % I11i + OoO0O00 - iII111i + I1IiiI . O0
 if 73 - 73: ooOoO0o + O0 - I11i . I1IiiI + OOooOOo
 delete_list . append ( mc )
 return ( [ True , delete_list ] )
 if 36 - 36: I11i % OoO0O00 * OoOoOO00 - I1Ii111
 if 16 - 16: ooOoO0o % OOooOOo . OoO0O00 % II111iiii . iIii1I11I1II1
 if 21 - 21: oO0o + II111iiii / OoOoOO00 * I11i
 if 90 - 90: OoOoOO00 % OoOoOO00 + I11i
 if 70 - 70: I1IiiI . ooOoO0o / I11i / OoO0O00
 if 40 - 40: oO0o % iIii1I11I1II1 * iIii1I11I1II1 / Oo0Ooo * OoO0O00
 if 61 - 61: OOooOOo
 if 80 - 80: I1ii11iIi11i
def lisp_timeout_map_cache_walk ( mc , parms ) :
 iIi11ii1 = parms [ 0 ]
 iI111IOoo = parms [ 1 ]
 if 33 - 33: oO0o % ooOoO0o / I11i
 if 2 - 2: I1ii11iIi11i
 if 90 - 90: II111iiii * I1Ii111 . ooOoO0o - I1ii11iIi11i % I11i * o0oOOo0O0Ooo
 if 85 - 85: iIii1I11I1II1
 if ( mc . group . is_null ( ) ) :
  o00o0OO0o , iIi11ii1 = lisp_timeout_map_cache_entry ( mc , iIi11ii1 )
  if ( iIi11ii1 == [ ] or mc != iIi11ii1 [ - 1 ] ) :
   iI111IOoo = lisp_write_checkpoint_entry ( iI111IOoo , mc )
   if 76 - 76: i11iIiiIii % I1IiiI / I11i
  return ( [ o00o0OO0o , parms ] )
  if 42 - 42: o0oOOo0O0Ooo . I1IiiI + I11i . OoOoOO00 - O0 / Ii1I
  if 66 - 66: IiII + OoOoOO00 + I1IiiI + i1IIi + OoooooooOO % I1IiiI
 if ( mc . source_cache == None ) : return ( [ True , parms ] )
 if 80 - 80: iII111i / O0 % OoooooooOO / Oo0Ooo
 if 75 - 75: ooOoO0o
 if 72 - 72: oO0o . OoooooooOO % ooOoO0o % OoO0O00 * oO0o * OoO0O00
 if 14 - 14: I11i / I11i
 if 90 - 90: O0 * OOooOOo / oO0o . Oo0Ooo * I11i
 parms = mc . source_cache . walk_cache ( lisp_timeout_map_cache_entry , parms )
 return ( [ True , parms ] )
 if 93 - 93: oO0o / ooOoO0o - I1Ii111
 if 70 - 70: OOooOOo / Ii1I - ooOoO0o + OoooooooOO / OoO0O00 - i11iIiiIii
 if 26 - 26: O0 + Oo0Ooo
 if 30 - 30: IiII
 if 6 - 6: O0
 if 92 - 92: I11i
 if 76 - 76: I11i / iIii1I11I1II1 - i11iIiiIii / O0 / O0
def lisp_timeout_map_cache ( lisp_map_cache ) :
 III11I1 = [ [ ] , [ ] ]
 III11I1 = lisp_map_cache . walk_cache ( lisp_timeout_map_cache_walk , III11I1 )
 if 19 - 19: Ii1I . I1IiiI - i1IIi * ooOoO0o . iIii1I11I1II1
 if 87 - 87: ooOoO0o % I1ii11iIi11i . I1IiiI
 if 42 - 42: iII111i % i11iIiiIii % o0oOOo0O0Ooo . O0 % iII111i
 if 72 - 72: Oo0Ooo . Oo0Ooo . IiII . Oo0Ooo
 if 80 - 80: I1Ii111 + IiII + O0 - I1Ii111 . iIii1I11I1II1
 iIi11ii1 = III11I1 [ 0 ]
 for IIII in iIi11ii1 : IIII . delete_cache ( )
 if 53 - 53: OoO0O00 / i11iIiiIii * I1Ii111
 if 62 - 62: oO0o / Oo0Ooo / IiII + I11i * ooOoO0o
 if 84 - 84: ooOoO0o + OoOoOO00 * I1ii11iIi11i % OoooooooOO . O0
 if 27 - 27: OoO0O00 * OoooooooOO - II111iiii / o0oOOo0O0Ooo
 iI111IOoo = III11I1 [ 1 ]
 lisp_checkpoint ( iI111IOoo )
 return
 if 76 - 76: I11i % I1Ii111 % iII111i + IiII * iII111i + OoOoOO00
 if 83 - 83: OOooOOo . ooOoO0o / IiII
 if 80 - 80: I1Ii111 . I11i - I11i + I1ii11iIi11i
 if 42 - 42: I11i / IiII % O0 - Oo0Ooo
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
 if 86 - 86: OoOoOO00
 if 4 - 4: OoooooooOO * OoO0O00
def lisp_store_nat_info ( hostname , rloc , port ) :
 I1iiIiiii1111 = rloc . print_address_no_iid ( )
 oOO0Oo0oO = "{} NAT state for {}, RLOC {}, port {}" . format ( "{}" ,
 blue ( hostname , False ) , red ( I1iiIiiii1111 , False ) , port )
 if 99 - 99: i11iIiiIii * IiII - OoO0O00 - OoooooooOO
 Ii1I1i = lisp_nat_info ( I1iiIiiii1111 , hostname , port )
 if 99 - 99: iII111i . O0 . oO0o / OoOoOO00 + oO0o
 if ( lisp_nat_state_info . has_key ( hostname ) == False ) :
  lisp_nat_state_info [ hostname ] = [ Ii1I1i ]
  lprint ( oOO0Oo0oO . format ( "Store initial" ) )
  return ( True )
  if 34 - 34: ooOoO0o - I1IiiI - II111iiii - oO0o
  if 29 - 29: OoO0O00 + I1IiiI - I1ii11iIi11i
  if 86 - 86: Oo0Ooo / I1Ii111 / I1Ii111 - ooOoO0o / O0
  if 7 - 7: II111iiii + Oo0Ooo . I1Ii111
  if 44 - 44: i1IIi / I1IiiI * I11i . Oo0Ooo - iIii1I11I1II1 / IiII
  if 56 - 56: Ii1I + i1IIi * oO0o
 Iii111I = lisp_nat_state_info [ hostname ] [ 0 ]
 if ( Iii111I . address == I1iiIiiii1111 and Iii111I . port == port ) :
  Iii111I . uptime = lisp_get_timestamp ( )
  lprint ( oOO0Oo0oO . format ( "Refresh existing" ) )
  return ( False )
  if 4 - 4: IiII - IiII . OoOoOO00 . iIii1I11I1II1
  if 36 - 36: i1IIi * I11i
  if 80 - 80: iIii1I11I1II1 % Ii1I . I1ii11iIi11i % iII111i - IiII % OoO0O00
  if 58 - 58: IiII + Oo0Ooo - i1IIi
  if 3 - 3: o0oOOo0O0Ooo * Ii1I
  if 53 - 53: I1ii11iIi11i / i1IIi . OoOoOO00 % Ii1I + I1IiiI
  if 25 - 25: oO0o + OoooooooOO / i1IIi + O0 % OoooooooOO . OoooooooOO
 Ooo0o = None
 for Iii111I in lisp_nat_state_info [ hostname ] :
  if ( Iii111I . address == I1iiIiiii1111 and Iii111I . port == port ) :
   Ooo0o = Iii111I
   break
   if 85 - 85: iIii1I11I1II1
   if 72 - 72: II111iiii
   if 26 - 26: Oo0Ooo
 if ( Ooo0o == None ) :
  lprint ( oOO0Oo0oO . format ( "Store new" ) )
 else :
  lisp_nat_state_info [ hostname ] . remove ( Ooo0o )
  lprint ( oOO0Oo0oO . format ( "Use previous" ) )
  if 14 - 14: O0
  if 63 - 63: I1IiiI . iIii1I11I1II1 . Oo0Ooo % OOooOOo - iII111i + ooOoO0o
 OO000o00000oOOoO = lisp_nat_state_info [ hostname ]
 lisp_nat_state_info [ hostname ] = [ Ii1I1i ] + OO000o00000oOOoO
 return ( True )
 if 74 - 74: OoOoOO00
 if 8 - 8: IiII . IiII - ooOoO0o
 if 97 - 97: O0 % I1IiiI
 if 69 - 69: ooOoO0o . OoooooooOO
 if 17 - 17: ooOoO0o / OoO0O00 / I1IiiI / OOooOOo % IiII
 if 88 - 88: i1IIi - OoOoOO00
 if 66 - 66: OoooooooOO - OoooooooOO * I11i / II111iiii + oO0o / Ii1I
 if 7 - 7: Ii1I / iIii1I11I1II1
def lisp_get_nat_info ( rloc , hostname ) :
 if ( lisp_nat_state_info . has_key ( hostname ) == False ) : return ( None )
 if 36 - 36: iIii1I11I1II1 % i11iIiiIii
 I1iiIiiii1111 = rloc . print_address_no_iid ( )
 for Iii111I in lisp_nat_state_info [ hostname ] :
  if ( Iii111I . address == I1iiIiiii1111 ) : return ( Iii111I )
  if 35 - 35: Oo0Ooo + I1IiiI - O0 - I1Ii111
 return ( None )
 if 64 - 64: i1IIi * OoOoOO00 / II111iiii * oO0o
 if 35 - 35: i1IIi - Ii1I - Ii1I . O0 % iII111i * iII111i
 if 15 - 15: OoooooooOO . Ii1I * I1Ii111 . ooOoO0o % OoO0O00 * Oo0Ooo
 if 10 - 10: iII111i + i11iIiiIii . OOooOOo % iII111i - i1IIi
 if 10 - 10: iIii1I11I1II1 * i11iIiiIii - O0
 if 45 - 45: oO0o % OOooOOo - IiII + o0oOOo0O0Ooo + i11iIiiIii
 if 79 - 79: IiII % I1Ii111 . I1IiiI + O0 * oO0o * ooOoO0o
 if 38 - 38: IiII
 if 78 - 78: Oo0Ooo * I1ii11iIi11i % OOooOOo / Oo0Ooo + I1ii11iIi11i * IiII
 if 2 - 2: Oo0Ooo - OoOoOO00
 if 22 - 22: OoO0O00 - oO0o - O0
 if 49 - 49: iIii1I11I1II1 + I1Ii111 / i11iIiiIii
 if 62 - 62: ooOoO0o . I1IiiI * i11iIiiIii
 if 2 - 2: i11iIiiIii
 if 86 - 86: I1Ii111 + o0oOOo0O0Ooo
 if 17 - 17: iIii1I11I1II1
 if 32 - 32: IiII - OoOoOO00
 if 88 - 88: OOooOOo - II111iiii + i1IIi * Oo0Ooo
 if 48 - 48: I1Ii111 + IiII % iII111i * iII111i + I1Ii111
 if 83 - 83: OoO0O00 . I11i * I1ii11iIi11i - II111iiii
def lisp_build_info_requests ( lisp_sockets , dest , port ) :
 if ( lisp_nat_traversal == False ) : return
 if 41 - 41: OoooooooOO . OoOoOO00 * iIii1I11I1II1
 if 18 - 18: IiII / I1Ii111 % i1IIi * i11iIiiIii
 if 16 - 16: Oo0Ooo
 if 24 - 24: o0oOOo0O0Ooo . OoOoOO00
 if 50 - 50: I1ii11iIi11i / iIii1I11I1II1 - Oo0Ooo - i11iIiiIii % o0oOOo0O0Ooo - ooOoO0o
 if 92 - 92: OoooooooOO - I1ii11iIi11i . I11i / O0 % iII111i
 oO0o0Oo = [ ]
 IiI1Ii11ii1 = [ ]
 if ( dest == None ) :
  for oOO0O000OOo0 in lisp_map_resolvers_list . values ( ) :
   IiI1Ii11ii1 . append ( oOO0O000OOo0 . map_resolver )
   if 48 - 48: i1IIi * iIii1I11I1II1 * IiII - i1IIi - i11iIiiIii + I11i
  oO0o0Oo = IiI1Ii11ii1
  if ( oO0o0Oo == [ ] ) :
   for oooO0OOo0O0O0 in lisp_map_servers_list . values ( ) :
    oO0o0Oo . append ( oooO0OOo0O0O0 . map_server )
    if 63 - 63: I11i + ooOoO0o + oO0o / i11iIiiIii
    if 51 - 51: i1IIi - o0oOOo0O0Ooo . I1Ii111 - OoO0O00
  if ( oO0o0Oo == [ ] ) : return
 else :
  oO0o0Oo . append ( dest )
  if 92 - 92: I1Ii111
  if 4 - 4: OoOoOO00 % o0oOOo0O0Ooo * i11iIiiIii - OOooOOo
  if 68 - 68: iII111i + I1ii11iIi11i / II111iiii * I1ii11iIi11i
  if 45 - 45: II111iiii . iII111i
  if 55 - 55: ooOoO0o / iII111i / O0
 oOo = { }
 for I111I in lisp_db_list :
  for IiI1I1iii11 in I111I . rloc_set :
   lisp_update_local_rloc ( IiI1I1iii11 )
   if ( IiI1I1iii11 . rloc . is_null ( ) ) : continue
   if ( IiI1I1iii11 . interface == None ) : continue
   if 98 - 98: O0 % iII111i + II111iiii
   o0o0O00 = IiI1I1iii11 . rloc . print_address_no_iid ( )
   if ( o0o0O00 in oOo ) : continue
   oOo [ o0o0O00 ] = IiI1I1iii11 . interface
   if 13 - 13: I1IiiI * oO0o - o0oOOo0O0Ooo
   if 23 - 23: iIii1I11I1II1 + oO0o . oO0o / o0oOOo0O0Ooo
 if ( oOo == { } ) :
  lprint ( 'Suppress Info-Request, no "interface = <device>" RLOC ' + "found in any database-mappings" )
  if 77 - 77: i1IIi * o0oOOo0O0Ooo * IiII
  return
  if 24 - 24: i11iIiiIii / iIii1I11I1II1 / iII111i
  if 31 - 31: OOooOOo . iIii1I11I1II1 - oO0o
  if 36 - 36: O0
  if 30 - 30: i11iIiiIii * Oo0Ooo . IiII
  if 65 - 65: oO0o * IiII * OOooOOo / OoooooooOO % I11i / I1Ii111
  if 21 - 21: i1IIi * iII111i + OoO0O00
 for o0o0O00 in oOo :
  I111IIiIII = oOo [ o0o0O00 ]
  oOO0oo = red ( o0o0O00 , False )
  lprint ( "Build Info-Request for private address {} ({})" . format ( oOO0oo ,
 I111IIiIII ) )
  O0OoO0o = I111IIiIII if len ( oOo ) > 1 else None
  for dest in oO0o0Oo :
   lisp_send_info_request ( lisp_sockets , dest , port , O0OoO0o )
   if 27 - 27: I11i / oO0o . iII111i + o0oOOo0O0Ooo - OOooOOo
   if 85 - 85: OoooooooOO
   if 83 - 83: iII111i * I11i . OOooOOo - OoO0O00 % IiII
   if 8 - 8: I1Ii111
   if 86 - 86: ooOoO0o + iII111i * O0 % OoO0O00 + OoOoOO00
   if 49 - 49: OOooOOo / i1IIi - II111iiii . iIii1I11I1II1 + I11i . OOooOOo
 if ( IiI1Ii11ii1 != [ ] ) :
  for oOO0O000OOo0 in lisp_map_resolvers_list . values ( ) :
   oOO0O000OOo0 . resolve_dns_name ( )
   if 9 - 9: iIii1I11I1II1 + Ii1I + I11i
   if 96 - 96: OoO0O00 + i11iIiiIii + OoO0O00
 return
 if 7 - 7: i1IIi . I1IiiI
 if 68 - 68: OoooooooOO
 if 91 - 91: IiII . ooOoO0o * I11i
 if 39 - 39: o0oOOo0O0Ooo + i11iIiiIii
 if 69 - 69: iIii1I11I1II1 . II111iiii
 if 36 - 36: I1IiiI * i1IIi + OoOoOO00
 if 63 - 63: OoOoOO00 - iII111i
 if 83 - 83: i1IIi / iII111i % ooOoO0o % i11iIiiIii + I1ii11iIi11i
def lisp_valid_address_format ( kw , value ) :
 if ( kw != "address" ) : return ( True )
 if 82 - 82: iIii1I11I1II1 / OOooOOo
 if 7 - 7: OoooooooOO
 if 71 - 71: OOooOOo * Oo0Ooo . Oo0Ooo % iIii1I11I1II1
 if 56 - 56: IiII * iIii1I11I1II1 - iIii1I11I1II1 . O0
 if 56 - 56: I1Ii111 / iIii1I11I1II1 % IiII * iIii1I11I1II1 . I1ii11iIi11i . OOooOOo
 if ( value [ 0 ] == "'" and value [ - 1 ] == "'" ) : return ( True )
 if 1 - 1: Ii1I . Ii1I % II111iiii + I11i + OoOoOO00
 if 52 - 52: OoooooooOO - OoO0O00
 if 24 - 24: iII111i / Oo0Ooo - I1ii11iIi11i + o0oOOo0O0Ooo
 if 44 - 44: OoOoOO00 + I1IiiI . I1ii11iIi11i / i1IIi + II111iiii . Oo0Ooo
 if ( value . find ( "." ) != - 1 ) :
  o0o0O00 = value . split ( "." )
  if ( len ( o0o0O00 ) != 4 ) : return ( False )
  if 39 - 39: o0oOOo0O0Ooo
  for oOoO0Ooo in o0o0O00 :
   if ( oOoO0Ooo . isdigit ( ) == False ) : return ( False )
   if ( int ( oOoO0Ooo ) > 255 ) : return ( False )
   if 20 - 20: i11iIiiIii + iIii1I11I1II1 / iII111i . I1IiiI
  return ( True )
  if 8 - 8: O0 - iII111i - i1IIi * oO0o / II111iiii
  if 48 - 48: I1ii11iIi11i . IiII * oO0o
  if 92 - 92: OoOoOO00 + oO0o % Ii1I / Ii1I - iII111i
  if 11 - 11: Oo0Ooo % II111iiii * Ii1I + II111iiii
  if 9 - 9: I1Ii111
 if ( value . find ( "-" ) != - 1 ) :
  o0o0O00 = value . split ( "-" )
  for Ii11 in [ "N" , "S" , "W" , "E" ] :
   if ( Ii11 in o0o0O00 ) :
    if ( len ( o0o0O00 ) < 8 ) : return ( False )
    return ( True )
    if 69 - 69: i1IIi + ooOoO0o + Ii1I
    if 88 - 88: OoOoOO00 + iII111i % O0 + OOooOOo / OoooooooOO / OOooOOo
    if 95 - 95: ooOoO0o . Oo0Ooo % IiII + iII111i
    if 16 - 16: I11i * OoO0O00 % o0oOOo0O0Ooo - O0 % II111iiii - I1IiiI
    if 72 - 72: OoooooooOO * OoOoOO00 . OOooOOo + Ii1I . OOooOOo / II111iiii
    if 8 - 8: i1IIi
    if 1 - 1: OoOoOO00 . OoO0O00 . OoO0O00 * O0
 if ( value . find ( "-" ) != - 1 ) :
  o0o0O00 = value . split ( "-" )
  if ( len ( o0o0O00 ) != 3 ) : return ( False )
  if 97 - 97: OoooooooOO % ooOoO0o . I1Ii111 / iII111i
  for OooooO0 in o0o0O00 :
   try : int ( OooooO0 , 16 )
   except : return ( False )
   if 36 - 36: iII111i + oO0o / I1Ii111
  return ( True )
  if 94 - 94: iIii1I11I1II1 - IiII . i11iIiiIii
  if 88 - 88: I1IiiI / i11iIiiIii * OOooOOo
  if 3 - 3: oO0o / o0oOOo0O0Ooo - OOooOOo . OoOoOO00 * I1Ii111
  if 61 - 61: OOooOOo + OoooooooOO
  if 17 - 17: I1Ii111 / OOooOOo . i11iIiiIii - I11i
 if ( value . find ( ":" ) != - 1 ) :
  o0o0O00 = value . split ( ":" )
  if ( len ( o0o0O00 ) < 2 ) : return ( False )
  if 7 - 7: I1Ii111 + ooOoO0o % o0oOOo0O0Ooo
  Oo00 = False
  I1I11Iiii111 = 0
  for OooooO0 in o0o0O00 :
   I1I11Iiii111 += 1
   if ( OooooO0 == "" ) :
    if ( Oo00 ) :
     if ( len ( o0o0O00 ) == I1I11Iiii111 ) : break
     if ( I1I11Iiii111 > 2 ) : return ( False )
     if 73 - 73: oO0o / OoOoOO00 * iIii1I11I1II1 % O0 - i1IIi
    Oo00 = True
    continue
    if 51 - 51: I1ii11iIi11i * Ii1I - oO0o / O0 * OoooooooOO
   try : int ( OooooO0 , 16 )
   except : return ( False )
   if 12 - 12: i1IIi / iIii1I11I1II1 / O0 * OoO0O00
  return ( True )
  if 15 - 15: i11iIiiIii / IiII + Ii1I % OOooOOo % I1ii11iIi11i * oO0o
  if 24 - 24: OOooOOo / OOooOOo + I11i / iII111i . oO0o - iII111i
  if 59 - 59: I1ii11iIi11i % II111iiii - i11iIiiIii - I1Ii111
  if 34 - 34: II111iiii + iII111i / IiII
  if 47 - 47: OoO0O00
 if ( value [ 0 ] == "+" ) :
  o0o0O00 = value [ 1 : : ]
  for iIi1I in o0o0O00 :
   if ( iIi1I . isdigit ( ) == False ) : return ( False )
   if 63 - 63: o0oOOo0O0Ooo * iIii1I11I1II1 * II111iiii . OoO0O00 - oO0o / OoOoOO00
  return ( True )
  if 78 - 78: i11iIiiIii / OoO0O00 / i1IIi . i11iIiiIii
 return ( False )
 if 100 - 100: II111iiii . IiII . I11i
 if 60 - 60: OoOoOO00 % OOooOOo * i1IIi
 if 3 - 3: OoooooooOO
 if 75 - 75: OoooooooOO * I1Ii111 * o0oOOo0O0Ooo + I1ii11iIi11i . iIii1I11I1II1 / O0
 if 23 - 23: oO0o - O0 * IiII + i11iIiiIii * Ii1I
 if 8 - 8: ooOoO0o / II111iiii . I1ii11iIi11i * ooOoO0o % oO0o
 if 36 - 36: I1ii11iIi11i % OOooOOo - ooOoO0o - I11i + I1IiiI
 if 37 - 37: I1ii11iIi11i * IiII
 if 65 - 65: OOooOOo / O0 . I1ii11iIi11i % i1IIi % Oo0Ooo
 if 36 - 36: i11iIiiIii - OOooOOo + iII111i + iII111i * I11i * oO0o
 if 14 - 14: O0 - iII111i * I1Ii111 - I1IiiI + IiII
 if 46 - 46: OoooooooOO * OoO0O00 . I1Ii111
def lisp_process_api ( process , lisp_socket , data_structure ) :
 O0oo0OoOo0oOooOO , III11I1 = data_structure . split ( "%" )
 if 22 - 22: iIii1I11I1II1 . I11i
 lprint ( "Process API request '{}', parameters: '{}'" . format ( O0oo0OoOo0oOooOO ,
 III11I1 ) )
 if 21 - 21: I1IiiI % Oo0Ooo - II111iiii / I1IiiI . OoOoOO00 - o0oOOo0O0Ooo
 IIII1iI1iiI = [ ]
 if ( O0oo0OoOo0oOooOO == "map-cache" ) :
  if ( III11I1 == "" ) :
   IIII1iI1iiI = lisp_map_cache . walk_cache ( lisp_process_api_map_cache , IIII1iI1iiI )
  else :
   IIII1iI1iiI = lisp_process_api_map_cache_entry ( json . loads ( III11I1 ) )
   if 23 - 23: OoOoOO00 / O0 * OoOoOO00 . I1IiiI + Oo0Ooo . iII111i
   if 1 - 1: i11iIiiIii * OoO0O00 - OoooooooOO + OoooooooOO
 if ( O0oo0OoOo0oOooOO == "site-cache" ) :
  if ( III11I1 == "" ) :
   IIII1iI1iiI = lisp_sites_by_eid . walk_cache ( lisp_process_api_site_cache ,
 IIII1iI1iiI )
  else :
   IIII1iI1iiI = lisp_process_api_site_cache_entry ( json . loads ( III11I1 ) )
   if 31 - 31: OoooooooOO - OoOoOO00 * II111iiii % ooOoO0o - ooOoO0o / i11iIiiIii
   if 8 - 8: I1IiiI . i1IIi - I11i
 if ( O0oo0OoOo0oOooOO == "map-server" ) :
  III11I1 = { } if ( III11I1 == "" ) else json . loads ( III11I1 )
  IIII1iI1iiI = lisp_process_api_ms_or_mr ( True , III11I1 )
  if 85 - 85: OOooOOo * IiII % O0 / I1ii11iIi11i
 if ( O0oo0OoOo0oOooOO == "map-resolver" ) :
  III11I1 = { } if ( III11I1 == "" ) else json . loads ( III11I1 )
  IIII1iI1iiI = lisp_process_api_ms_or_mr ( False , III11I1 )
  if 17 - 17: Oo0Ooo / i11iIiiIii / I11i - I1Ii111
 if ( O0oo0OoOo0oOooOO == "database-mapping" ) :
  IIII1iI1iiI = lisp_process_api_database_mapping ( )
  if 3 - 3: I1Ii111 - Oo0Ooo / iIii1I11I1II1
  if 71 - 71: o0oOOo0O0Ooo + i11iIiiIii + OoooooooOO % OoOoOO00 - I1ii11iIi11i / OoooooooOO
  if 26 - 26: II111iiii
  if 41 - 41: Oo0Ooo . OoOoOO00 . iII111i / i11iIiiIii
  if 65 - 65: iII111i * o0oOOo0O0Ooo * OoooooooOO + I11i + oO0o % OoO0O00
 IIII1iI1iiI = json . dumps ( IIII1iI1iiI )
 IIi1IiIii = lisp_api_ipc ( process , IIII1iI1iiI )
 lisp_ipc ( IIi1IiIii , lisp_socket , "lisp-core" )
 return
 if 1 - 1: I1ii11iIi11i . ooOoO0o
 if 54 - 54: OoOoOO00 % I1IiiI . ooOoO0o + IiII / i11iIiiIii / o0oOOo0O0Ooo
 if 51 - 51: OoOoOO00 / Ii1I . I1IiiI / Ii1I . II111iiii - iIii1I11I1II1
 if 78 - 78: I11i
 if 42 - 42: Ii1I
 if 50 - 50: iIii1I11I1II1 / Ii1I . ooOoO0o / ooOoO0o * OoOoOO00 * iII111i
 if 15 - 15: o0oOOo0O0Ooo % II111iiii + I1IiiI
def lisp_process_api_map_cache ( mc , data ) :
 if 21 - 21: I1ii11iIi11i - ooOoO0o
 if 81 - 81: iII111i / i11iIiiIii / I1Ii111
 if 70 - 70: I1ii11iIi11i / i11iIiiIii
 if 90 - 90: II111iiii / OoOoOO00 . Ii1I . OoooooooOO
 if ( mc . group . is_null ( ) ) : return ( lisp_gather_map_cache_data ( mc , data ) )
 if 76 - 76: OoooooooOO
 if ( mc . source_cache == None ) : return ( [ True , data ] )
 if 78 - 78: IiII % i11iIiiIii
 if 23 - 23: iIii1I11I1II1 - o0oOOo0O0Ooo - Ii1I % OOooOOo
 if 100 - 100: oO0o . OoO0O00 . i11iIiiIii % II111iiii * IiII
 if 81 - 81: OOooOOo - OOooOOo + OoOoOO00
 if 19 - 19: o0oOOo0O0Ooo
 data = mc . source_cache . walk_cache ( lisp_gather_map_cache_data , data )
 return ( [ True , data ] )
 if 20 - 20: I1Ii111 + iIii1I11I1II1 % I1IiiI + ooOoO0o
 if 86 - 86: o0oOOo0O0Ooo * i11iIiiIii - I11i
 if 71 - 71: OoO0O00 - I11i
 if 96 - 96: I1Ii111 / Ii1I
 if 65 - 65: I1ii11iIi11i * O0 . IiII
 if 11 - 11: I11i / Ii1I % oO0o
 if 50 - 50: i11iIiiIii
def lisp_gather_map_cache_data ( mc , data ) :
 iIIiI11iI1Ii1 = { }
 iIIiI11iI1Ii1 [ "instance-id" ] = str ( mc . eid . instance_id )
 iIIiI11iI1Ii1 [ "eid-prefix" ] = mc . eid . print_prefix_no_iid ( )
 if ( mc . group . is_null ( ) == False ) :
  iIIiI11iI1Ii1 [ "group-prefix" ] = mc . group . print_prefix_no_iid ( )
  if 93 - 93: i1IIi / Ii1I * II111iiii - Oo0Ooo . OoOoOO00 - OOooOOo
 iIIiI11iI1Ii1 [ "uptime" ] = lisp_print_elapsed ( mc . uptime )
 iIIiI11iI1Ii1 [ "expires" ] = lisp_print_elapsed ( mc . uptime )
 iIIiI11iI1Ii1 [ "action" ] = lisp_map_reply_action_string [ mc . action ]
 iIIiI11iI1Ii1 [ "ttl" ] = "--" if mc . map_cache_ttl == None else str ( mc . map_cache_ttl / 60 )
 if 25 - 25: I11i / ooOoO0o % ooOoO0o - OOooOOo
 if 59 - 59: I1IiiI + o0oOOo0O0Ooo . iIii1I11I1II1 - O0 - i11iIiiIii
 if 4 - 4: I1IiiI
 if 36 - 36: Ii1I
 if 76 - 76: i11iIiiIii + i1IIi
 oooo0O = [ ]
 for OoOOo in mc . rloc_set :
  iIIIIIi11Ii = { }
  if ( OoOOo . rloc_exists ( ) ) :
   iIIIIIi11Ii [ "address" ] = OoOOo . rloc . print_address_no_iid ( )
   if 56 - 56: OoOoOO00 + II111iiii / i11iIiiIii * OoOoOO00 * OoooooooOO
   if 15 - 15: OoOoOO00 / OoooooooOO + OOooOOo
  if ( OoOOo . translated_port != 0 ) :
   iIIIIIi11Ii [ "encap-port" ] = str ( OoOOo . translated_port )
   if 76 - 76: Ii1I * iII111i . OoooooooOO
  iIIIIIi11Ii [ "state" ] = OoOOo . print_state ( )
  if ( OoOOo . geo ) : iIIIIIi11Ii [ "geo" ] = OoOOo . geo . print_geo ( )
  if ( OoOOo . elp ) : iIIIIIi11Ii [ "elp" ] = OoOOo . elp . print_elp ( False )
  if ( OoOOo . rle ) : iIIIIIi11Ii [ "rle" ] = OoOOo . rle . print_rle ( False )
  if ( OoOOo . json ) : iIIIIIi11Ii [ "json" ] = OoOOo . json . print_json ( False )
  if ( OoOOo . rloc_name ) : iIIIIIi11Ii [ "rloc-name" ] = OoOOo . rloc_name
  I1iIii1Ii = OoOOo . stats . get_stats ( False , False )
  if ( I1iIii1Ii ) : iIIIIIi11Ii [ "stats" ] = I1iIii1Ii
  iIIIIIi11Ii [ "uptime" ] = lisp_print_elapsed ( OoOOo . uptime )
  iIIIIIi11Ii [ "upriority" ] = str ( OoOOo . priority )
  iIIIIIi11Ii [ "uweight" ] = str ( OoOOo . weight )
  iIIIIIi11Ii [ "mpriority" ] = str ( OoOOo . mpriority )
  iIIIIIi11Ii [ "mweight" ] = str ( OoOOo . mweight )
  OoOOOO0O0 = OoOOo . last_rloc_probe_reply
  if ( OoOOOO0O0 ) :
   iIIIIIi11Ii [ "last-rloc-probe-reply" ] = lisp_print_elapsed ( OoOOOO0O0 )
   iIIIIIi11Ii [ "rloc-probe-rtt" ] = str ( OoOOo . rloc_probe_rtt )
   if 44 - 44: I1Ii111 - II111iiii / OOooOOo
  iIIIIIi11Ii [ "rloc-hop-count" ] = OoOOo . rloc_probe_hops
  iIIIIIi11Ii [ "recent-rloc-hop-counts" ] = OoOOo . recent_rloc_probe_hops
  if 50 - 50: I11i / I1ii11iIi11i
  OoO0 = [ ]
  for Oo0OOoo0 in OoOOo . recent_rloc_probe_rtts : OoO0 . append ( str ( Oo0OOoo0 ) )
  iIIIIIi11Ii [ "recent-rloc-probe-rtts" ] = OoO0
  if 78 - 78: I1IiiI * i1IIi / II111iiii
  oooo0O . append ( iIIIIIi11Ii )
  if 91 - 91: I1IiiI * I1Ii111 * i11iIiiIii - oO0o - IiII + I1ii11iIi11i
 iIIiI11iI1Ii1 [ "rloc-set" ] = oooo0O
 if 99 - 99: OoO0O00 % o0oOOo0O0Ooo
 data . append ( iIIiI11iI1Ii1 )
 return ( [ True , data ] )
 if 3 - 3: OOooOOo / OoOoOO00 % iIii1I11I1II1
 if 47 - 47: ooOoO0o . i11iIiiIii / OoO0O00
 if 48 - 48: O0
 if 89 - 89: i11iIiiIii % OoO0O00 . OoOoOO00 + Oo0Ooo + OoOoOO00
 if 53 - 53: Ii1I / OoOoOO00 % iII111i * OoooooooOO + Oo0Ooo
 if 70 - 70: OoO0O00 % OoO0O00 * OoooooooOO
 if 96 - 96: ooOoO0o * Ii1I + I11i + II111iiii * I1IiiI / iII111i
def lisp_process_api_map_cache_entry ( parms ) :
 o0OOoOO = parms [ "instance-id" ]
 o0OOoOO = 0 if ( o0OOoOO == "" ) else int ( o0OOoOO )
 if 40 - 40: OoooooooOO - I11i % OOooOOo - I1IiiI . I1IiiI + Ii1I
 if 97 - 97: OOooOOo . OoooooooOO . OOooOOo . i11iIiiIii
 if 71 - 71: oO0o + I1ii11iIi11i * I1ii11iIi11i
 if 79 - 79: oO0o
 i1OO0o = lisp_address ( LISP_AFI_NONE , "" , 0 , o0OOoOO )
 i1OO0o . store_prefix ( parms [ "eid-prefix" ] )
 iI111I1 = i1OO0o
 II1i1iI = i1OO0o
 if 47 - 47: OoooooooOO - i1IIi * OOooOOo
 if 11 - 11: I11i / OOooOOo . o0oOOo0O0Ooo - O0 * OoooooooOO % iII111i
 if 7 - 7: OoOoOO00 . IiII + OoooooooOO - I1Ii111 / oO0o
 if 32 - 32: iIii1I11I1II1 + I11i + OOooOOo - OoooooooOO + i11iIiiIii * o0oOOo0O0Ooo
 if 8 - 8: iII111i
 O0oo0oo0 = lisp_address ( LISP_AFI_NONE , "" , 0 , o0OOoOO )
 if ( parms . has_key ( "group-prefix" ) ) :
  O0oo0oo0 . store_prefix ( parms [ "group-prefix" ] )
  iI111I1 = O0oo0oo0
  if 10 - 10: OoOoOO00 % I11i
  if 49 - 49: oO0o % ooOoO0o + II111iiii
 IIII1iI1iiI = [ ]
 IIII = lisp_map_cache_lookup ( II1i1iI , iI111I1 )
 if ( IIII ) : o00o0OO0o , IIII1iI1iiI = lisp_process_api_map_cache ( IIII , IIII1iI1iiI )
 return ( IIII1iI1iiI )
 if 21 - 21: i1IIi + OoO0O00 . I1IiiI - Oo0Ooo
 if 99 - 99: OoOoOO00
 if 46 - 46: I1ii11iIi11i / II111iiii / OoooooooOO / Ii1I
 if 37 - 37: I1ii11iIi11i - Ii1I / oO0o . I1IiiI % I1Ii111
 if 8 - 8: oO0o
 if 46 - 46: I1Ii111 + IiII + II111iiii . o0oOOo0O0Ooo + i11iIiiIii
 if 97 - 97: o0oOOo0O0Ooo % OoOoOO00 * O0 / iIii1I11I1II1 * OoO0O00 / i11iIiiIii
def lisp_process_api_site_cache ( se , data ) :
 if 1 - 1: OoooooooOO . Ii1I
 if 68 - 68: Ii1I
 if 98 - 98: iII111i
 if 33 - 33: OoO0O00 - ooOoO0o % O0 % iIii1I11I1II1 * iII111i - iII111i
 if ( se . group . is_null ( ) ) : return ( lisp_gather_site_cache_data ( se , data ) )
 if 27 - 27: i11iIiiIii + I1ii11iIi11i + i1IIi
 if ( se . source_cache == None ) : return ( [ True , data ] )
 if 67 - 67: o0oOOo0O0Ooo
 if 58 - 58: IiII % o0oOOo0O0Ooo + i1IIi
 if 33 - 33: II111iiii
 if 61 - 61: I1Ii111
 if 56 - 56: I1ii11iIi11i - OoooooooOO
 data = se . source_cache . walk_cache ( lisp_gather_site_cache_data , data )
 return ( [ True , data ] )
 if 52 - 52: Oo0Ooo - I11i - IiII - OoOoOO00
 if 21 - 21: oO0o % o0oOOo0O0Ooo + I1Ii111 . OOooOOo / OOooOOo
 if 41 - 41: Oo0Ooo . ooOoO0o * oO0o
 if 31 - 31: Oo0Ooo * IiII / IiII
 if 3 - 3: I1Ii111
 if 65 - 65: iIii1I11I1II1 % Oo0Ooo % I11i / OoooooooOO
 if 82 - 82: o0oOOo0O0Ooo
def lisp_process_api_ms_or_mr ( ms_or_mr , data ) :
 oOoO0Oo0 = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
 IIiiiIiI = data [ "dns-name" ] if data . has_key ( "dns-name" ) else None
 if ( data . has_key ( "address" ) ) :
  oOoO0Oo0 . store_address ( data [ "address" ] )
  if 33 - 33: OoOoOO00 / i11iIiiIii - I1IiiI - OoooooooOO + i1IIi * I1Ii111
  if 92 - 92: iII111i + OoO0O00
 oOO = { }
 if ( ms_or_mr ) :
  for oooO0OOo0O0O0 in lisp_map_servers_list . values ( ) :
   if ( IIiiiIiI ) :
    if ( IIiiiIiI != oooO0OOo0O0O0 . dns_name ) : continue
   else :
    if ( oOoO0Oo0 . is_exact_match ( oooO0OOo0O0O0 . map_server ) == False ) : continue
    if 70 - 70: iIii1I11I1II1
    if 100 - 100: OOooOOo . oO0o % ooOoO0o * ooOoO0o . I1Ii111 - oO0o
   oOO [ "dns-name" ] = oooO0OOo0O0O0 . dns_name
   oOO [ "address" ] = oooO0OOo0O0O0 . map_server . print_address_no_iid ( )
   oOO [ "ms-name" ] = "" if oooO0OOo0O0O0 . ms_name == None else oooO0OOo0O0O0 . ms_name
   return ( [ oOO ] )
   if 33 - 33: Oo0Ooo . i1IIi - OoooooooOO
 else :
  for oOO0O000OOo0 in lisp_map_resolvers_list . values ( ) :
   if ( IIiiiIiI ) :
    if ( IIiiiIiI != oOO0O000OOo0 . dns_name ) : continue
   else :
    if ( oOoO0Oo0 . is_exact_match ( oOO0O000OOo0 . map_resolver ) == False ) : continue
    if 14 - 14: I1Ii111 + Oo0Ooo
    if 35 - 35: i11iIiiIii * Ii1I
   oOO [ "dns-name" ] = oOO0O000OOo0 . dns_name
   oOO [ "address" ] = oOO0O000OOo0 . map_resolver . print_address_no_iid ( )
   oOO [ "mr-name" ] = "" if oOO0O000OOo0 . mr_name == None else oOO0O000OOo0 . mr_name
   return ( [ oOO ] )
   if 100 - 100: O0 . iII111i / iIii1I11I1II1
   if 47 - 47: ooOoO0o + OoOoOO00
 return ( [ ] )
 if 67 - 67: IiII - I1ii11iIi11i * i1IIi - ooOoO0o
 if 91 - 91: I11i
 if 54 - 54: I1ii11iIi11i / i1IIi
 if 14 - 14: iIii1I11I1II1 * I11i . I11i * ooOoO0o * iII111i
 if 60 - 60: iIii1I11I1II1 + i1IIi + oO0o - iIii1I11I1II1 . i11iIiiIii * OoooooooOO
 if 23 - 23: iII111i - IiII % i11iIiiIii
 if 81 - 81: OoooooooOO % OoOoOO00 / IiII / OoooooooOO + i1IIi - O0
 if 60 - 60: OOooOOo - I1Ii111 * Oo0Ooo
def lisp_process_api_database_mapping ( ) :
 IIII1iI1iiI = [ ]
 if 9 - 9: OoooooooOO * OOooOOo % OoO0O00 - ooOoO0o + Ii1I
 for I111I in lisp_db_list :
  iIIiI11iI1Ii1 = { }
  iIIiI11iI1Ii1 [ "eid-prefix" ] = I111I . eid . print_prefix ( )
  if ( I111I . group . is_null ( ) == False ) :
   iIIiI11iI1Ii1 [ "group-prefix" ] = I111I . group . print_prefix ( )
   if 39 - 39: iIii1I11I1II1 / i1IIi % I11i % I1ii11iIi11i * IiII
   if 11 - 11: II111iiii + i1IIi
  Ii11iiI = [ ]
  for iIIIIIi11Ii in I111I . rloc_set :
   OoOOo = { }
   if ( iIIIIIi11Ii . rloc . is_null ( ) == False ) :
    OoOOo [ "rloc" ] = iIIIIIi11Ii . rloc . print_address_no_iid ( )
    if 1 - 1: OOooOOo
   if ( iIIIIIi11Ii . rloc_name != None ) : OoOOo [ "rloc-name" ] = iIIIIIi11Ii . rloc_name
   if ( iIIIIIi11Ii . interface != None ) : OoOOo [ "interface" ] = iIIIIIi11Ii . interface
   Ii1iiI = iIIIIIi11Ii . translated_rloc
   if ( Ii1iiI . is_null ( ) == False ) :
    OoOOo [ "translated-rloc" ] = Ii1iiI . print_address_no_iid ( )
    if 37 - 37: OoooooooOO . o0oOOo0O0Ooo - o0oOOo0O0Ooo - Oo0Ooo / I1IiiI
   if ( OoOOo != { } ) : Ii11iiI . append ( OoOOo )
   if 87 - 87: IiII
   if 68 - 68: I1Ii111 + I1ii11iIi11i * IiII . OoO0O00 / I11i
   if 39 - 39: Oo0Ooo + OOooOOo . I1IiiI + OoO0O00 . OoooooooOO
   if 31 - 31: OoO0O00
   if 55 - 55: OoOoOO00 + I1Ii111 * o0oOOo0O0Ooo - I1ii11iIi11i + OoOoOO00
  iIIiI11iI1Ii1 [ "rlocs" ] = Ii11iiI
  if 6 - 6: II111iiii % iIii1I11I1II1 * I1Ii111
  if 2 - 2: IiII - I1Ii111 . iIii1I11I1II1 - Ii1I * I11i
  if 58 - 58: i1IIi % iIii1I11I1II1 % i11iIiiIii - o0oOOo0O0Ooo + ooOoO0o
  if 23 - 23: Oo0Ooo % Oo0Ooo / IiII
  IIII1iI1iiI . append ( iIIiI11iI1Ii1 )
  if 63 - 63: I11i % Oo0Ooo * I1Ii111 - Oo0Ooo % i11iIiiIii . II111iiii
 return ( IIII1iI1iiI )
 if 44 - 44: I11i . I1Ii111 . I1ii11iIi11i . oO0o
 if 1 - 1: I11i % II111iiii / OoO0O00 + OoO0O00
 if 46 - 46: Oo0Ooo * Ii1I / IiII % O0 * iII111i
 if 74 - 74: OoooooooOO + Ii1I
 if 100 - 100: I1IiiI
 if 59 - 59: I1IiiI - OoOoOO00 * ooOoO0o / O0
 if 54 - 54: Oo0Ooo % iIii1I11I1II1 * Oo0Ooo
def lisp_gather_site_cache_data ( se , data ) :
 iIIiI11iI1Ii1 = { }
 iIIiI11iI1Ii1 [ "site-name" ] = se . site . site_name
 iIIiI11iI1Ii1 [ "instance-id" ] = str ( se . eid . instance_id )
 iIIiI11iI1Ii1 [ "eid-prefix" ] = se . eid . print_prefix_no_iid ( )
 if ( se . group . is_null ( ) == False ) :
  iIIiI11iI1Ii1 [ "group-prefix" ] = se . group . print_prefix_no_iid ( )
  if 80 - 80: I1ii11iIi11i - I1ii11iIi11i
 iIIiI11iI1Ii1 [ "registered" ] = "yes" if se . registered else "no"
 iIIiI11iI1Ii1 [ "first-registered" ] = lisp_print_elapsed ( se . first_registered )
 iIIiI11iI1Ii1 [ "last-registered" ] = lisp_print_elapsed ( se . last_registered )
 if 26 - 26: I1ii11iIi11i - I1IiiI * I1Ii111 % iIii1I11I1II1
 o0o0O00 = se . last_registerer
 o0o0O00 = "none" if o0o0O00 . is_null ( ) else o0o0O00 . print_address ( )
 iIIiI11iI1Ii1 [ "last-registerer" ] = o0o0O00
 iIIiI11iI1Ii1 [ "ams" ] = "yes" if ( se . accept_more_specifics ) else "no"
 iIIiI11iI1Ii1 [ "dynamic" ] = "yes" if ( se . dynamic ) else "no"
 iIIiI11iI1Ii1 [ "site-id" ] = str ( se . site_id )
 if ( se . xtr_id_present ) :
  iIIiI11iI1Ii1 [ "xtr-id" ] = "0x" + lisp_hex_string ( se . xtr_id )
  if 77 - 77: o0oOOo0O0Ooo + I1Ii111 . OOooOOo . i1IIi . I1IiiI
  if 100 - 100: ooOoO0o . i11iIiiIii + Ii1I - OOooOOo - i11iIiiIii - OoooooooOO
  if 42 - 42: OoOoOO00 . I1IiiI / OoOoOO00 / I1ii11iIi11i . OoO0O00
  if 67 - 67: Ii1I - O0 . OoooooooOO . I1Ii111 . o0oOOo0O0Ooo
  if 73 - 73: I11i - oO0o . I1Ii111 + oO0o
 oooo0O = [ ]
 for OoOOo in se . registered_rlocs :
  iIIIIIi11Ii = { }
  iIIIIIi11Ii [ "address" ] = OoOOo . rloc . print_address_no_iid ( ) if OoOOo . rloc_exists ( ) else "none"
  if 48 - 48: IiII . IiII * o0oOOo0O0Ooo * II111iiii % ooOoO0o
  if 40 - 40: I1ii11iIi11i
  if ( OoOOo . geo ) : iIIIIIi11Ii [ "geo" ] = OoOOo . geo . print_geo ( )
  if ( OoOOo . elp ) : iIIIIIi11Ii [ "elp" ] = OoOOo . elp . print_elp ( False )
  if ( OoOOo . rle ) : iIIIIIi11Ii [ "rle" ] = OoOOo . rle . print_rle ( False )
  if ( OoOOo . json ) : iIIIIIi11Ii [ "json" ] = OoOOo . json . print_json ( False )
  if ( OoOOo . rloc_name ) : iIIIIIi11Ii [ "rloc-name" ] = OoOOo . rloc_name
  iIIIIIi11Ii [ "uptime" ] = lisp_print_elapsed ( OoOOo . uptime )
  iIIIIIi11Ii [ "upriority" ] = str ( OoOOo . priority )
  iIIIIIi11Ii [ "uweight" ] = str ( OoOOo . weight )
  iIIIIIi11Ii [ "mpriority" ] = str ( OoOOo . mpriority )
  iIIIIIi11Ii [ "mweight" ] = str ( OoOOo . mweight )
  if 76 - 76: Oo0Ooo - I11i
  oooo0O . append ( iIIIIIi11Ii )
  if 82 - 82: OoO0O00 % oO0o . I11i / O0 - I1Ii111
 iIIiI11iI1Ii1 [ "registered-rlocs" ] = oooo0O
 if 39 - 39: I1IiiI
 data . append ( iIIiI11iI1Ii1 )
 return ( [ True , data ] )
 if 8 - 8: IiII * i1IIi * i1IIi * O0
 if 69 - 69: Oo0Ooo
 if 48 - 48: iII111i
 if 11 - 11: i11iIiiIii * OoOoOO00 . OoO0O00
 if 47 - 47: Oo0Ooo % I1Ii111 + ooOoO0o
 if 89 - 89: iII111i
 if 29 - 29: I1ii11iIi11i . ooOoO0o * II111iiii / iII111i . OoooooooOO - OoOoOO00
def lisp_process_api_site_cache_entry ( parms ) :
 o0OOoOO = parms [ "instance-id" ]
 o0OOoOO = 0 if ( o0OOoOO == "" ) else int ( o0OOoOO )
 if 99 - 99: IiII % O0 - I1Ii111 * OoO0O00
 if 77 - 77: OoooooooOO - I11i / I1IiiI % OoOoOO00 - OOooOOo
 if 37 - 37: ooOoO0o
 if 22 - 22: I1ii11iIi11i + II111iiii / OoooooooOO % o0oOOo0O0Ooo * OoOoOO00 . Oo0Ooo
 i1OO0o = lisp_address ( LISP_AFI_NONE , "" , 0 , o0OOoOO )
 i1OO0o . store_prefix ( parms [ "eid-prefix" ] )
 if 26 - 26: OoO0O00 % oO0o * Ii1I % OoooooooOO - oO0o
 if 46 - 46: I1IiiI + OoO0O00 - O0 * O0
 if 75 - 75: OOooOOo + iIii1I11I1II1 * OOooOOo
 if 82 - 82: iII111i - I1Ii111 - OoOoOO00
 if 96 - 96: Oo0Ooo . Oo0Ooo % o0oOOo0O0Ooo - I1IiiI * iIii1I11I1II1
 O0oo0oo0 = lisp_address ( LISP_AFI_NONE , "" , 0 , o0OOoOO )
 if ( parms . has_key ( "group-prefix" ) ) :
  O0oo0oo0 . store_prefix ( parms [ "group-prefix" ] )
  if 29 - 29: i1IIi / Ii1I / oO0o * iII111i
  if 44 - 44: O0
 IIII1iI1iiI = [ ]
 ooOoOO0Oo = lisp_site_eid_lookup ( i1OO0o , O0oo0oo0 , False )
 if ( ooOoOO0Oo ) : lisp_gather_site_cache_data ( ooOoOO0Oo , IIII1iI1iiI )
 return ( IIII1iI1iiI )
 if 95 - 95: OOooOOo + OOooOOo - OoOoOO00
 if 83 - 83: II111iiii * ooOoO0o - O0 - i11iIiiIii
 if 62 - 62: I1IiiI + II111iiii * iIii1I11I1II1 % iII111i + IiII / ooOoO0o
 if 14 - 14: iIii1I11I1II1 * I1ii11iIi11i + OOooOOo + O0
 if 79 - 79: II111iiii - iII111i
 if 89 - 89: O0 - OoO0O00
 if 8 - 8: I1ii11iIi11i / oO0o - OoooooooOO + ooOoO0o + o0oOOo0O0Ooo % i11iIiiIii
def lisp_get_interface_instance_id ( device , source_eid ) :
 I111IIiIII = None
 if ( lisp_myinterfaces . has_key ( device ) ) :
  I111IIiIII = lisp_myinterfaces [ device ]
  if 32 - 32: O0 + IiII
  if 93 - 93: OoOoOO00 - I11i / iII111i - iIii1I11I1II1 + I11i % oO0o
  if 24 - 24: Ii1I / iIii1I11I1II1 + o0oOOo0O0Ooo
  if 17 - 17: OOooOOo
  if 75 - 75: Ii1I / i1IIi % I1ii11iIi11i . Ii1I
  if 46 - 46: II111iiii * OoO0O00
 if ( I111IIiIII == None or I111IIiIII . instance_id == None ) :
  return ( lisp_default_iid )
  if 77 - 77: ooOoO0o * I11i
  if 85 - 85: OoO0O00 * I1Ii111 - OoooooooOO / iIii1I11I1II1 - i1IIi + Ii1I
  if 76 - 76: iII111i * OoooooooOO
  if 49 - 49: II111iiii - OOooOOo + II111iiii + OoOoOO00
  if 51 - 51: i11iIiiIii
  if 39 - 39: o0oOOo0O0Ooo % I1Ii111 % i1IIi - II111iiii + i11iIiiIii
  if 62 - 62: I1ii11iIi11i - I1IiiI * i11iIiiIii % oO0o
  if 63 - 63: II111iiii - Oo0Ooo
  if 55 - 55: iIii1I11I1II1 / O0 * O0 * i11iIiiIii * OoooooooOO
 o0OOoOO = I111IIiIII . get_instance_id ( )
 if ( source_eid == None ) : return ( o0OOoOO )
 if 94 - 94: II111iiii . II111iiii / OoOoOO00 % oO0o * i1IIi % Oo0Ooo
 o0OO0OOO = source_eid . instance_id
 ii11I = None
 for I111IIiIII in lisp_multi_tenant_interfaces :
  if ( I111IIiIII . device != device ) : continue
  OoooO00OO0OO = I111IIiIII . multi_tenant_eid
  source_eid . instance_id = OoooO00OO0OO . instance_id
  if ( source_eid . is_more_specific ( OoooO00OO0OO ) == False ) : continue
  if ( ii11I == None or ii11I . multi_tenant_eid . mask_len < OoooO00OO0OO . mask_len ) :
   ii11I = I111IIiIII
   if 21 - 21: Ii1I * iIii1I11I1II1 % O0 % I11i + Ii1I
   if 40 - 40: o0oOOo0O0Ooo / IiII
 source_eid . instance_id = o0OO0OOO
 if 25 - 25: i1IIi + o0oOOo0O0Ooo
 if ( ii11I == None ) : return ( o0OOoOO )
 return ( ii11I . get_instance_id ( ) )
 if 90 - 90: OoooooooOO * ooOoO0o + IiII * OoOoOO00 - OoOoOO00
 if 24 - 24: OoooooooOO / I1IiiI % iII111i . i11iIiiIii
 if 14 - 14: O0 . IiII - Ii1I
 if 39 - 39: O0 % I1Ii111
 if 82 - 82: II111iiii . IiII - O0
 if 18 - 18: oO0o * OOooOOo
 if 19 - 19: iIii1I11I1II1 / I1ii11iIi11i - I1ii11iIi11i / iIii1I11I1II1
 if 42 - 42: iIii1I11I1II1 / OOooOOo - O0 * OoooooooOO / i1IIi
 if 33 - 33: OOooOOo . o0oOOo0O0Ooo % OoO0O00 - I1Ii111 . OoooooooOO
def lisp_allow_dynamic_eid ( device , eid ) :
 if ( lisp_myinterfaces . has_key ( device ) == False ) : return ( None )
 if 96 - 96: II111iiii % I11i / Ii1I - i11iIiiIii
 I111IIiIII = lisp_myinterfaces [ device ]
 oo0Oo = device if I111IIiIII . dynamic_eid_device == None else I111IIiIII . dynamic_eid_device
 if 70 - 70: OoO0O00 * II111iiii / I11i + I11i
 if 23 - 23: I1IiiI
 if ( I111IIiIII . does_dynamic_eid_match ( eid ) ) : return ( oo0Oo )
 return ( None )
 if 51 - 51: i11iIiiIii / ooOoO0o - OoooooooOO + OoOoOO00 + oO0o
 if 57 - 57: iIii1I11I1II1
 if 19 - 19: Ii1I / o0oOOo0O0Ooo + O0 / iIii1I11I1II1 + II111iiii
 if 3 - 3: oO0o % OoO0O00 % OOooOOo
 if 64 - 64: o0oOOo0O0Ooo . II111iiii * IiII % Oo0Ooo + I11i - OoooooooOO
 if 58 - 58: ooOoO0o
 if 15 - 15: O0 * OOooOOo * I11i + Ii1I * OoooooooOO + OOooOOo
def lisp_start_rloc_probe_timer ( interval , lisp_sockets ) :
 global lisp_rloc_probe_timer
 if 77 - 77: O0
 if ( lisp_rloc_probe_timer != None ) : lisp_rloc_probe_timer . cancel ( )
 if 98 - 98: iII111i - iII111i % i1IIi - I1Ii111 . I1IiiI % o0oOOo0O0Ooo
 I1iIi1II1i = lisp_process_rloc_probe_timer
 O0O0 = threading . Timer ( interval , I1iIi1II1i , [ lisp_sockets ] )
 lisp_rloc_probe_timer = O0O0
 O0O0 . start ( )
 return
 if 82 - 82: OoO0O00 . I1IiiI + o0oOOo0O0Ooo
 if 52 - 52: oO0o . OOooOOo + iII111i * ooOoO0o + IiII / I1Ii111
 if 88 - 88: OoO0O00 * I1ii11iIi11i - I1IiiI * IiII * Oo0Ooo % OoooooooOO
 if 15 - 15: OOooOOo - I1Ii111 - OOooOOo
 if 73 - 73: iII111i + o0oOOo0O0Ooo % iII111i . Ii1I + OoO0O00 - I1ii11iIi11i
 if 47 - 47: OoO0O00 * O0 % iIii1I11I1II1
 if 92 - 92: IiII
def lisp_show_rloc_probe_list ( ) :
 lprint ( bold ( "----- RLOC-probe-list -----" , False ) )
 for iii11 in lisp_rloc_probe_list :
  OOo = lisp_rloc_probe_list [ iii11 ]
  lprint ( "RLOC {}:" . format ( iii11 ) )
  for iIIIIIi11Ii , ooo0OO , O0ooO0oOO in OOo :
   lprint ( "  [{}, {}, {}, {}]" . format ( hex ( id ( iIIIIIi11Ii ) ) , ooo0OO . print_prefix ( ) ,
 O0ooO0oOO . print_prefix ( ) , iIIIIIi11Ii . translated_port ) )
   if 90 - 90: i11iIiiIii . OoooooooOO % iII111i + I1Ii111 . O0
   if 77 - 77: i11iIiiIii % OoOoOO00 - i1IIi
 lprint ( bold ( "---------------------------" , False ) )
 return
 if 73 - 73: O0 + i1IIi + iII111i
 if 100 - 100: oO0o / OoooooooOO % ooOoO0o / i1IIi . oO0o - OoO0O00
 if 32 - 32: IiII
 if 2 - 2: iII111i / IiII % iIii1I11I1II1 . iII111i + iIii1I11I1II1 + O0
 if 96 - 96: I1ii11iIi11i - IiII % OoooooooOO . iII111i
 if 30 - 30: Oo0Ooo . OoooooooOO / Oo0Ooo / oO0o
 if 44 - 44: I1ii11iIi11i % o0oOOo0O0Ooo / iIii1I11I1II1 - o0oOOo0O0Ooo / I11i * I1Ii111
 if 49 - 49: iII111i / iII111i - OoOoOO00
 if 89 - 89: ooOoO0o
def lisp_mark_rlocs_for_other_eids ( eid_list ) :
 if 16 - 16: oO0o + oO0o + i1IIi + iIii1I11I1II1
 if 93 - 93: I1IiiI - i11iIiiIii * I1Ii111 - O0 + iII111i
 if 11 - 11: iII111i
 if 100 - 100: OoooooooOO / ooOoO0o . OoO0O00
 OoOOo , ooo0OO , O0ooO0oOO = eid_list [ 0 ]
 o0oOoOOoo0O = [ lisp_print_eid_tuple ( ooo0OO , O0ooO0oOO ) ]
 if 21 - 21: OoO0O00 - OOooOOo - i11iIiiIii . II111iiii
 for OoOOo , ooo0OO , O0ooO0oOO in eid_list [ 1 : : ] :
  OoOOo . state = LISP_RLOC_UNREACH_STATE
  OoOOo . last_state_change = lisp_get_timestamp ( )
  o0oOoOOoo0O . append ( lisp_print_eid_tuple ( ooo0OO , O0ooO0oOO ) )
  if 98 - 98: IiII
  if 17 - 17: iII111i - OOooOOo / OOooOOo % OoO0O00 + i11iIiiIii % OoO0O00
 II1IiI = bold ( "unreachable" , False )
 ooOo = red ( OoOOo . rloc . print_address_no_iid ( ) , False )
 if 92 - 92: I1ii11iIi11i + iII111i
 for i1OO0o in o0oOoOOoo0O :
  ooo0OO = green ( i1OO0o , False )
  lprint ( "RLOC {} went {} for EID {}" . format ( ooOo , II1IiI , ooo0OO ) )
  if 55 - 55: ooOoO0o
  if 68 - 68: Oo0Ooo
  if 3 - 3: Ii1I % Ii1I + oO0o
  if 19 - 19: Ii1I . IiII % o0oOOo0O0Ooo
  if 92 - 92: i1IIi + IiII - iIii1I11I1II1 + i1IIi * ooOoO0o - i11iIiiIii
  if 68 - 68: o0oOOo0O0Ooo + IiII / iII111i - i11iIiiIii / OOooOOo
 for OoOOo , ooo0OO , O0ooO0oOO in eid_list :
  IIII = lisp_map_cache . lookup_cache ( ooo0OO , True )
  if ( IIII ) : lisp_write_ipc_map_cache ( True , IIII )
  if 62 - 62: I1IiiI
 return
 if 42 - 42: II111iiii
 if 49 - 49: OoooooooOO
 if 48 - 48: i1IIi . IiII - O0 + OoooooooOO
 if 6 - 6: I1Ii111 * OOooOOo + o0oOOo0O0Ooo . I1ii11iIi11i * I1Ii111
 if 6 - 6: oO0o / II111iiii
 if 23 - 23: IiII - OoooooooOO / oO0o
 if 69 - 69: O0 - OoooooooOO
 if 31 - 31: o0oOOo0O0Ooo . i1IIi - i1IIi % i1IIi - iIii1I11I1II1
 if 50 - 50: IiII - OOooOOo % OoOoOO00
 if 66 - 66: IiII * i11iIiiIii
def lisp_process_rloc_probe_timer ( lisp_sockets ) :
 lisp_set_exception ( )
 if 64 - 64: i11iIiiIii . I1Ii111 % i11iIiiIii % I11i
 lisp_start_rloc_probe_timer ( LISP_RLOC_PROBE_INTERVAL , lisp_sockets )
 if ( lisp_rloc_probing == False ) : return
 if 56 - 56: o0oOOo0O0Ooo + ooOoO0o + OoooooooOO
 if 64 - 64: OOooOOo / OoOoOO00
 if 30 - 30: OOooOOo % I1Ii111 - i11iIiiIii
 if 20 - 20: i1IIi * I11i / OoO0O00 / i1IIi / I1Ii111 * O0
 if ( lisp_print_rloc_probe_list ) : lisp_show_rloc_probe_list ( )
 if 95 - 95: Ii1I + Ii1I % IiII - IiII / OOooOOo
 if 46 - 46: IiII + iII111i + II111iiii . iII111i - i11iIiiIii % OoO0O00
 if 24 - 24: oO0o + IiII . o0oOOo0O0Ooo . OoooooooOO . i11iIiiIii / I1ii11iIi11i
 if 49 - 49: IiII
 iI11 = lisp_get_default_route_next_hops ( )
 if 58 - 58: OoO0O00 + I1ii11iIi11i * oO0o * I11i / oO0o
 lprint ( "---------- Start RLOC Probing for {} entries ----------" . format ( len ( lisp_rloc_probe_list ) ) )
 if 68 - 68: iII111i . IiII . OoooooooOO . I1ii11iIi11i
 if 79 - 79: OoooooooOO / i1IIi
 if 30 - 30: Ii1I . IiII
 if 24 - 24: O0
 if 6 - 6: I1IiiI . i11iIiiIii . OoooooooOO . I1IiiI . o0oOOo0O0Ooo
 I1I11Iiii111 = 0
 Ooo0O = bold ( "RLOC-probe" , False )
 for oOiiIiIIIi11 in lisp_rloc_probe_list . values ( ) :
  if 27 - 27: i1IIi / i11iIiiIii * Oo0Ooo / OoO0O00
  if 95 - 95: I11i . OoOoOO00 * Ii1I
  if 94 - 94: OoOoOO00 / OoO0O00 / ooOoO0o + II111iiii
  if 55 - 55: II111iiii - IiII
  if 24 - 24: oO0o % Ii1I / i1IIi
  oOOOI11I = None
  for O0Oo00O00O0O , i1OO0o , O0oo0oo0 in oOiiIiIIIi11 :
   I1iiIiiii1111 = O0Oo00O00O0O . rloc . print_address_no_iid ( )
   if 19 - 19: O0 + i11iIiiIii % O0 / II111iiii
   if 56 - 56: O0 + Oo0Ooo * II111iiii * iII111i * iII111i / I1Ii111
   if 52 - 52: oO0o
   if 73 - 73: IiII - II111iiii - OOooOOo % II111iiii + iIii1I11I1II1
   ooOoOO00 , Ooo0O = lisp_allow_gleaning ( i1OO0o , O0Oo00O00O0O )
   if ( ooOoOO00 and Ooo0O == False ) :
    ooo0OO = green ( i1OO0o . print_address ( ) , False )
    I1iiIiiii1111 += ":{}" . format ( O0Oo00O00O0O . translated_port )
    lprint ( "Suppress probe to RLOC {} for gleaned EID {}" . format ( red ( I1iiIiiii1111 , False ) , ooo0OO ) )
    if 87 - 87: OOooOOo
    continue
    if 44 - 44: Oo0Ooo + iIii1I11I1II1
    if 67 - 67: iII111i . OOooOOo / ooOoO0o * iIii1I11I1II1
    if 29 - 29: I1Ii111 / OoOoOO00 % I1ii11iIi11i * IiII / II111iiii
    if 10 - 10: O0 / I11i
    if 29 - 29: i11iIiiIii % I11i
    if 49 - 49: I11i
    if 69 - 69: o0oOOo0O0Ooo . O0 * I11i
   if ( O0Oo00O00O0O . down_state ( ) ) : continue
   if 92 - 92: OoO0O00 . O0 / Ii1I % Oo0Ooo . Ii1I
   if 40 - 40: o0oOOo0O0Ooo - Ii1I . iII111i - O0
   if 53 - 53: Oo0Ooo - I1IiiI * O0 . II111iiii
   if 72 - 72: ooOoO0o - Ii1I . Ii1I . I11i / OoooooooOO + Ii1I
   if 32 - 32: O0
   if 42 - 42: i1IIi * I1ii11iIi11i * OoOoOO00
   if 43 - 43: I1ii11iIi11i % I1ii11iIi11i % i1IIi
   if 56 - 56: I1IiiI - OoO0O00 - iII111i . o0oOOo0O0Ooo . I1Ii111
   if 70 - 70: iIii1I11I1II1 - I11i
   if 2 - 2: oO0o / II111iiii * OoO0O00
   if 71 - 71: i1IIi + I11i * OoO0O00 . OOooOOo + oO0o
   if ( oOOOI11I ) :
    O0Oo00O00O0O . last_rloc_probe_nonce = oOOOI11I . last_rloc_probe_nonce
    if 40 - 40: OOooOOo
    if ( oOOOI11I . translated_port == O0Oo00O00O0O . translated_port and oOOOI11I . rloc_name == O0Oo00O00O0O . rloc_name ) :
     if 14 - 14: OoooooooOO - OoooooooOO % i11iIiiIii % ooOoO0o / ooOoO0o
     ooo0OO = green ( lisp_print_eid_tuple ( i1OO0o , O0oo0oo0 ) , False )
     lprint ( "Suppress probe to duplicate RLOC {} for {}" . format ( red ( I1iiIiiii1111 , False ) , ooo0OO ) )
     if 33 - 33: iII111i / i1IIi . II111iiii % I1ii11iIi11i
     continue
     if 74 - 74: iII111i / OOooOOo / O0 / iIii1I11I1II1 + IiII
     if 26 - 26: OOooOOo % i1IIi . I1Ii111 / O0 + I1Ii111
     if 39 - 39: I1ii11iIi11i * I1IiiI * II111iiii . Oo0Ooo % I1IiiI
   i11i1i = None
   OoOOo = None
   while ( True ) :
    OoOOo = O0Oo00O00O0O if OoOOo == None else OoOOo . next_rloc
    if ( OoOOo == None ) : break
    if 100 - 100: iIii1I11I1II1 - OoooooooOO * OoooooooOO - iII111i / ooOoO0o
    if 98 - 98: OoO0O00 + oO0o - II111iiii
    if 84 - 84: Oo0Ooo . OoOoOO00 - iII111i
    if 5 - 5: OoooooooOO . O0 / OOooOOo + I11i - Ii1I
    if 77 - 77: iIii1I11I1II1 * Oo0Ooo . IiII / oO0o + O0
    if ( OoOOo . rloc_next_hop != None ) :
     if ( OoOOo . rloc_next_hop not in iI11 ) :
      if ( OoOOo . up_state ( ) ) :
       oOo0OOOOOO , I1o0Ooo = OoOOo . rloc_next_hop
       OoOOo . state = LISP_RLOC_UNREACH_STATE
       OoOOo . last_state_change = lisp_get_timestamp ( )
       lisp_update_rtr_updown ( OoOOo . rloc , False )
       if 76 - 76: iII111i + o0oOOo0O0Ooo - OoooooooOO * oO0o % OoooooooOO - O0
      II1IiI = bold ( "unreachable" , False )
      lprint ( "Next-hop {}({}) for RLOC {} is {}" . format ( I1o0Ooo , oOo0OOOOOO ,
 red ( I1iiIiiii1111 , False ) , II1IiI ) )
      continue
      if 18 - 18: Ii1I
      if 82 - 82: OoOoOO00 + OoO0O00 - IiII / ooOoO0o
      if 70 - 70: OoO0O00
      if 43 - 43: ooOoO0o + OOooOOo + II111iiii - I1IiiI
      if 58 - 58: I11i
      if 94 - 94: Oo0Ooo
    oo = OoOOo . last_rloc_probe
    I11II1I1I = 0 if oo == None else time . time ( ) - oo
    if ( OoOOo . unreach_state ( ) and I11II1I1I < LISP_RLOC_PROBE_INTERVAL ) :
     lprint ( "Waiting for probe-reply from RLOC {}" . format ( red ( I1iiIiiii1111 , False ) ) )
     if 8 - 8: i1IIi % i1IIi % OoooooooOO % i1IIi . iIii1I11I1II1
     continue
     if 70 - 70: O0 + II111iiii % IiII / I1Ii111 - IiII
     if 58 - 58: II111iiii * oO0o - i1IIi . I11i
     if 23 - 23: OoO0O00 - I1IiiI * i11iIiiIii
     if 62 - 62: OoO0O00 . i11iIiiIii / i1IIi
     if 3 - 3: OoO0O00 + O0 % Oo0Ooo * Oo0Ooo % i11iIiiIii
     if 29 - 29: ooOoO0o / iII111i / OOooOOo - iIii1I11I1II1
    oOOo00ooO = lisp_get_echo_nonce ( None , I1iiIiiii1111 )
    if ( oOOo00ooO and oOOo00ooO . request_nonce_timeout ( ) ) :
     OoOOo . state = LISP_RLOC_NO_ECHOED_NONCE_STATE
     OoOOo . last_state_change = lisp_get_timestamp ( )
     II1IiI = bold ( "unreachable" , False )
     lprint ( "RLOC {} went {}, nonce-echo failed" . format ( red ( I1iiIiiii1111 , False ) , II1IiI ) )
     if 31 - 31: i1IIi * Ii1I
     lisp_update_rtr_updown ( OoOOo . rloc , False )
     continue
     if 94 - 94: oO0o / Ii1I % iIii1I11I1II1 + i1IIi / O0 - iII111i
     if 77 - 77: o0oOOo0O0Ooo - IiII . i1IIi
     if 70 - 70: i1IIi . I1Ii111 . iII111i - OoOoOO00 + II111iiii + OOooOOo
     if 52 - 52: OOooOOo . OoOoOO00 - ooOoO0o % i1IIi
     if 15 - 15: oO0o
     if 6 - 6: oO0o . iIii1I11I1II1 - I1ii11iIi11i % IiII
    if ( oOOo00ooO and oOOo00ooO . recently_echoed ( ) ) :
     lprint ( ( "Suppress RLOC-probe to {}, nonce-echo " + "received" ) . format ( red ( I1iiIiiii1111 , False ) ) )
     if 58 - 58: iII111i * oO0o / iII111i - Oo0Ooo / I1Ii111 * oO0o
     continue
     if 63 - 63: oO0o . IiII . o0oOOo0O0Ooo
     if 16 - 16: iII111i . I11i - Oo0Ooo / I1IiiI + OoOoOO00
     if 14 - 14: iIii1I11I1II1 / i11iIiiIii - o0oOOo0O0Ooo . iII111i * OoO0O00
     if 5 - 5: Ii1I + OoOoOO00 % I11i + IiII
     if 55 - 55: OoooooooOO + oO0o . o0oOOo0O0Ooo % iIii1I11I1II1 - I1Ii111
     if 40 - 40: I1IiiI . o0oOOo0O0Ooo - Oo0Ooo
    if ( OoOOo . last_rloc_probe != None ) :
     oo = OoOOo . last_rloc_probe_reply
     if ( oo == None ) : oo = 0
     I11II1I1I = time . time ( ) - oo
     if ( OoOOo . up_state ( ) and I11II1I1I >= LISP_RLOC_PROBE_REPLY_WAIT ) :
      if 44 - 44: Ii1I % OoO0O00 * oO0o * OoO0O00
      OoOOo . state = LISP_RLOC_UNREACH_STATE
      OoOOo . last_state_change = lisp_get_timestamp ( )
      lisp_update_rtr_updown ( OoOOo . rloc , False )
      II1IiI = bold ( "unreachable" , False )
      lprint ( "RLOC {} went {}, probe it" . format ( red ( I1iiIiiii1111 , False ) , II1IiI ) )
      if 7 - 7: I1Ii111 % i1IIi . I11i . O0 / i1IIi
      if 56 - 56: Oo0Ooo
      lisp_mark_rlocs_for_other_eids ( oOiiIiIIIi11 )
      if 21 - 21: i11iIiiIii * o0oOOo0O0Ooo + Oo0Ooo
      if 20 - 20: IiII / OoooooooOO / O0 / I1Ii111 * ooOoO0o
      if 45 - 45: ooOoO0o / Oo0Ooo % o0oOOo0O0Ooo . ooOoO0o
    OoOOo . last_rloc_probe = lisp_get_timestamp ( )
    if 19 - 19: o0oOOo0O0Ooo % I11i . I1ii11iIi11i
    OOo00O0Oo = "" if OoOOo . unreach_state ( ) == False else " unreachable"
    if 72 - 72: i11iIiiIii * I11i
    if 69 - 69: I1Ii111 . Ii1I * I1ii11iIi11i % I11i - o0oOOo0O0Ooo
    if 30 - 30: ooOoO0o / Oo0Ooo * iII111i % OoooooooOO / I1ii11iIi11i
    if 64 - 64: OoooooooOO
    if 41 - 41: Ii1I . I11i / oO0o * OoooooooOO
    if 98 - 98: I1ii11iIi11i - O0 + i11iIiiIii
    if 71 - 71: O0 - OoooooooOO
    oo0o00Oo00o0 = ""
    I1o0Ooo = None
    if ( OoOOo . rloc_next_hop != None ) :
     oOo0OOOOOO , I1o0Ooo = OoOOo . rloc_next_hop
     lisp_install_host_route ( I1iiIiiii1111 , I1o0Ooo , True )
     oo0o00Oo00o0 = ", send on nh {}({})" . format ( I1o0Ooo , oOo0OOOOOO )
     if 62 - 62: IiII - I1Ii111 % iII111i / oO0o
     if 27 - 27: o0oOOo0O0Ooo + iIii1I11I1II1 + OoooooooOO - iII111i
     if 80 - 80: Ii1I . iII111i * I1IiiI * Ii1I
     if 82 - 82: OoO0O00 % OoOoOO00 * i11iIiiIii . OoO0O00 . I1ii11iIi11i + Ii1I
     if 60 - 60: i1IIi / iII111i
    Oo0OOoo0 = OoOOo . print_rloc_probe_rtt ( )
    I11IOOo = I1iiIiiii1111
    if ( OoOOo . translated_port != 0 ) :
     I11IOOo += ":{}" . format ( OoOOo . translated_port )
     if 50 - 50: OoooooooOO . iII111i . I1ii11iIi11i / O0
    I11IOOo = red ( I11IOOo , False )
    if ( OoOOo . rloc_name != None ) :
     I11IOOo += " (" + blue ( OoOOo . rloc_name , False ) + ")"
     if 97 - 97: o0oOOo0O0Ooo / I1IiiI - OoOoOO00
    lprint ( "Send {}{} {}, last rtt: {}{}" . format ( Ooo0O , OOo00O0Oo ,
 I11IOOo , Oo0OOoo0 , oo0o00Oo00o0 ) )
    if 98 - 98: OoooooooOO . ooOoO0o % iII111i + I1IiiI * Ii1I . oO0o
    if 21 - 21: i11iIiiIii % OoO0O00 * iII111i * o0oOOo0O0Ooo % Oo0Ooo
    if 7 - 7: oO0o * OoooooooOO % o0oOOo0O0Ooo . I1Ii111 + O0
    if 14 - 14: I11i * II111iiii % o0oOOo0O0Ooo / iII111i . OoooooooOO % iII111i
    if 88 - 88: iII111i
    if 94 - 94: OoooooooOO
    if 32 - 32: I1ii11iIi11i
    if 8 - 8: I11i * i11iIiiIii - ooOoO0o
    if ( OoOOo . rloc_next_hop != None ) :
     i11i1i = lisp_get_host_route_next_hop ( I1iiIiiii1111 )
     if ( i11i1i ) : lisp_install_host_route ( I1iiIiiii1111 , i11i1i , False )
     if 47 - 47: ooOoO0o . I1IiiI / i11iIiiIii * iII111i * I1IiiI
     if 8 - 8: oO0o % oO0o . iII111i / i1IIi % IiII
     if 71 - 71: OoOoOO00 + oO0o % O0 + Oo0Ooo
     if 62 - 62: i1IIi . Ii1I * i1IIi * O0 . I1IiiI % o0oOOo0O0Ooo
     if 16 - 16: I11i . Ii1I - ooOoO0o . OOooOOo % O0 / oO0o
     if 42 - 42: II111iiii . iII111i
    if ( OoOOo . rloc . is_null ( ) ) :
     OoOOo . rloc . copy_address ( O0Oo00O00O0O . rloc )
     if 67 - 67: i1IIi - i11iIiiIii / ooOoO0o * oO0o
     if 64 - 64: oO0o / IiII
     if 86 - 86: I11i
     if 36 - 36: o0oOOo0O0Ooo / OoO0O00
     if 6 - 6: I11i % I1IiiI + iII111i * OoooooooOO . O0
    I1i1III1i = None if ( O0oo0oo0 . is_null ( ) ) else i1OO0o
    O000iI1ii1I = i1OO0o if ( O0oo0oo0 . is_null ( ) ) else O0oo0oo0
    lisp_send_map_request ( lisp_sockets , 0 , I1i1III1i , O000iI1ii1I , OoOOo )
    oOOOI11I = O0Oo00O00O0O
    if 34 - 34: iIii1I11I1II1
    if 26 - 26: iII111i / IiII * iII111i
    if 91 - 91: Oo0Ooo
    if 98 - 98: iIii1I11I1II1 . OoO0O00
    if ( I1o0Ooo ) : lisp_install_host_route ( I1iiIiiii1111 , I1o0Ooo , False )
    if 1 - 1: OOooOOo % Oo0Ooo
    if 86 - 86: i11iIiiIii
    if 57 - 57: iII111i - OoooooooOO - ooOoO0o % II111iiii
    if 62 - 62: i11iIiiIii . Oo0Ooo / Oo0Ooo . IiII . OoooooooOO
    if 86 - 86: I1ii11iIi11i * OoOoOO00 + iII111i
   if ( i11i1i ) : lisp_install_host_route ( I1iiIiiii1111 , i11i1i , True )
   if 79 - 79: I11i - II111iiii
   if 27 - 27: I1IiiI + o0oOOo0O0Ooo * oO0o % I1IiiI
   if 66 - 66: OoO0O00 + IiII . o0oOOo0O0Ooo . IiII
   if 88 - 88: oO0o + oO0o % OoO0O00 . OoooooooOO - OoooooooOO . Oo0Ooo
   I1I11Iiii111 += 1
   if ( ( I1I11Iiii111 % 10 ) == 0 ) : time . sleep ( 0.020 )
   if 44 - 44: I1IiiI * IiII . OoooooooOO
   if 62 - 62: I11i - Ii1I / i11iIiiIii * I1IiiI + ooOoO0o + o0oOOo0O0Ooo
   if 10 - 10: i1IIi + o0oOOo0O0Ooo
 lprint ( "---------- End RLOC Probing ----------" )
 return
 if 47 - 47: OOooOOo * IiII % I1Ii111 . OoOoOO00 - OoooooooOO / OoooooooOO
 if 79 - 79: I11i % i11iIiiIii % I1IiiI . OoooooooOO * oO0o . Ii1I
 if 14 - 14: iIii1I11I1II1 / I11i - o0oOOo0O0Ooo / IiII / o0oOOo0O0Ooo . OoO0O00
 if 2 - 2: I11i
 if 12 - 12: i1IIi . I1Ii111
 if 99 - 99: Oo0Ooo / i11iIiiIii
 if 81 - 81: Ii1I . i1IIi % iII111i . OoO0O00 % IiII
 if 42 - 42: iII111i / Oo0Ooo
def lisp_update_rtr_updown ( rtr , updown ) :
 global lisp_ipc_socket
 if 14 - 14: O0 . Oo0Ooo
 if 8 - 8: i11iIiiIii
 if 80 - 80: I1ii11iIi11i + Ii1I
 if 16 - 16: i11iIiiIii * Oo0Ooo
 if ( lisp_i_am_itr == False ) : return
 if 76 - 76: iII111i . oO0o - i1IIi
 if 94 - 94: O0 % iII111i
 if 90 - 90: IiII
 if 1 - 1: I1ii11iIi11i % OoOoOO00 . I1ii11iIi11i . OoooooooOO % oO0o + Ii1I
 if 46 - 46: I1IiiI + OoO0O00 - Oo0Ooo
 if ( lisp_register_all_rtrs ) : return
 if 13 - 13: OoOoOO00
 Ooo0Oo0000O0O = rtr . print_address_no_iid ( )
 if 19 - 19: iIii1I11I1II1 . I1Ii111 - i11iIiiIii - OoooooooOO . Oo0Ooo % II111iiii
 if 28 - 28: OoooooooOO / iII111i / iIii1I11I1II1
 if 72 - 72: I1ii11iIi11i - OoooooooOO
 if 5 - 5: iIii1I11I1II1 % ooOoO0o / II111iiii
 if 44 - 44: O0 % OoooooooOO
 if ( lisp_rtr_list . has_key ( Ooo0Oo0000O0O ) == False ) : return
 if 6 - 6: I1IiiI / I1ii11iIi11i . I1ii11iIi11i + iIii1I11I1II1
 updown = "up" if updown else "down"
 lprint ( "Send ETR IPC message, RTR {} has done {}" . format (
 red ( Ooo0Oo0000O0O , False ) , bold ( updown , False ) ) )
 if 78 - 78: OOooOOo . I1Ii111
 if 60 - 60: i1IIi
 if 69 - 69: O0 * iII111i % I11i . O0 * Ii1I - I1IiiI
 if 9 - 9: IiII - I1Ii111 % iIii1I11I1II1 . i1IIi / OOooOOo . i1IIi
 IIi1IiIii = "rtr%{}%{}" . format ( Ooo0Oo0000O0O , updown )
 IIi1IiIii = lisp_command_ipc ( IIi1IiIii , "lisp-itr" )
 lisp_ipc ( IIi1IiIii , lisp_ipc_socket , "lisp-etr" )
 return
 if 63 - 63: II111iiii . oO0o * IiII
 if 73 - 73: iII111i . i1IIi + oO0o + OOooOOo + ooOoO0o - iIii1I11I1II1
 if 47 - 47: I11i
 if 88 - 88: OoO0O00 - OoooooooOO
 if 93 - 93: Oo0Ooo * I1IiiI
 if 60 - 60: I1Ii111 + OOooOOo % iII111i
 if 40 - 40: I11i + oO0o . O0 % oO0o
def lisp_process_rloc_probe_reply ( rloc , source , port , nonce , hop_count , ttl ) :
 Ooo0O = bold ( "RLOC-probe reply" , False )
 ii1 = rloc . print_address_no_iid ( )
 oo0OO = source . print_address_no_iid ( )
 ooo0O = lisp_rloc_probe_list
 if 1 - 1: I1Ii111
 if 57 - 57: oO0o * i1IIi + iIii1I11I1II1
 if 13 - 13: I1Ii111 * iII111i
 if 46 - 46: Oo0Ooo
 if 92 - 92: I1Ii111 * OoO0O00 . ooOoO0o
 if 6 - 6: o0oOOo0O0Ooo + OOooOOo
 o0o0O00 = ii1
 if ( ooo0O . has_key ( o0o0O00 ) == False ) :
  o0o0O00 += ":" + str ( port )
  if ( ooo0O . has_key ( o0o0O00 ) == False ) :
   o0o0O00 = oo0OO
   if ( ooo0O . has_key ( o0o0O00 ) == False ) :
    o0o0O00 += ":" + str ( port )
    lprint ( "    Received unsolicited {} from {}/{}, port {}" . format ( Ooo0O , red ( ii1 , False ) , red ( oo0OO ,
    # OOooOOo - iII111i % iIii1I11I1II1 / I1Ii111 + I11i
 False ) , port ) )
    return
    if 75 - 75: Oo0Ooo / I1ii11iIi11i - II111iiii * iIii1I11I1II1
    if 42 - 42: OoO0O00 + OoO0O00 * I1Ii111 * OoooooooOO + O0 * OoOoOO00
    if 54 - 54: O0 / Oo0Ooo
    if 54 - 54: OoO0O00
    if 38 - 38: II111iiii + o0oOOo0O0Ooo * I11i + I1Ii111 - II111iiii . OOooOOo
    if 38 - 38: I1ii11iIi11i % OOooOOo + iII111i / Oo0Ooo / IiII / oO0o
    if 2 - 2: iIii1I11I1II1
    if 9 - 9: I1Ii111 / IiII
 for rloc , i1OO0o , O0oo0oo0 in lisp_rloc_probe_list [ o0o0O00 ] :
  if ( lisp_i_am_rtr and rloc . translated_port != 0 and
 rloc . translated_port != port ) : continue
  if 33 - 33: o0oOOo0O0Ooo + oO0o . o0oOOo0O0Ooo . I11i * OoooooooOO + iIii1I11I1II1
  rloc . process_rloc_probe_reply ( nonce , i1OO0o , O0oo0oo0 , hop_count , ttl )
  if 64 - 64: OoooooooOO . Ii1I
 return
 if 38 - 38: Oo0Ooo
 if 64 - 64: ooOoO0o % i11iIiiIii
 if 10 - 10: Ii1I % oO0o + oO0o * OoOoOO00 % iII111i / o0oOOo0O0Ooo
 if 17 - 17: iII111i / I1IiiI . II111iiii - OoO0O00 + iII111i
 if 22 - 22: Oo0Ooo - I1ii11iIi11i + I11i . oO0o
 if 85 - 85: iIii1I11I1II1 / Ii1I
 if 43 - 43: I1IiiI % I1Ii111 - oO0o . II111iiii / iIii1I11I1II1
 if 97 - 97: I1Ii111 + I1ii11iIi11i
def lisp_db_list_length ( ) :
 I1I11Iiii111 = 0
 for I111I in lisp_db_list :
  I1I11Iiii111 += len ( I111I . dynamic_eids ) if I111I . dynamic_eid_configured ( ) else 1
  I1I11Iiii111 += len ( I111I . eid . iid_list )
  if 21 - 21: O0 + o0oOOo0O0Ooo * OoooooooOO % IiII % I1ii11iIi11i
 return ( I1I11Iiii111 )
 if 80 - 80: I11i
 if 28 - 28: OoOoOO00 * OoooooooOO * i11iIiiIii
 if 88 - 88: ooOoO0o + ooOoO0o / I1Ii111
 if 69 - 69: O0 * o0oOOo0O0Ooo + i1IIi * ooOoO0o . o0oOOo0O0Ooo
 if 46 - 46: Oo0Ooo / Oo0Ooo * IiII
 if 65 - 65: iIii1I11I1II1 * o0oOOo0O0Ooo - iII111i % II111iiii - I1ii11iIi11i
 if 65 - 65: I11i
 if 92 - 92: iII111i . IiII + i1IIi % i1IIi
def lisp_is_myeid ( eid ) :
 for I111I in lisp_db_list :
  if ( eid . is_more_specific ( I111I . eid ) ) : return ( True )
  if 11 - 11: I1ii11iIi11i + iIii1I11I1II1 - I1Ii111 * iIii1I11I1II1 * IiII + oO0o
 return ( False )
 if 6 - 6: I1Ii111 * OOooOOo + i1IIi - Ii1I / oO0o
 if 81 - 81: I1Ii111 % oO0o * i1IIi * OoooooooOO / Oo0Ooo
 if 70 - 70: I1IiiI
 if 35 - 35: i11iIiiIii
 if 59 - 59: ooOoO0o . iII111i - II111iiii
 if 30 - 30: o0oOOo0O0Ooo % iII111i - i11iIiiIii
 if 25 - 25: i11iIiiIii + OoOoOO00 + oO0o / Ii1I * Oo0Ooo + Oo0Ooo
 if 26 - 26: I1IiiI % I1ii11iIi11i + o0oOOo0O0Ooo / I1ii11iIi11i - I1IiiI
 if 55 - 55: OoooooooOO
def lisp_format_macs ( sa , da ) :
 sa = sa [ 0 : 4 ] + "-" + sa [ 4 : 8 ] + "-" + sa [ 8 : 12 ]
 da = da [ 0 : 4 ] + "-" + da [ 4 : 8 ] + "-" + da [ 8 : 12 ]
 return ( "{} -> {}" . format ( sa , da ) )
 if 2 - 2: Oo0Ooo + I11i / OOooOOo + OOooOOo
 if 62 - 62: OOooOOo . iIii1I11I1II1 + I1IiiI / OOooOOo
 if 90 - 90: OOooOOo
 if 29 - 29: OoOoOO00 - I1IiiI / oO0o + Oo0Ooo + I1Ii111 + O0
 if 65 - 65: oO0o
 if 38 - 38: iIii1I11I1II1 / I1Ii111 + ooOoO0o . II111iiii - iIii1I11I1II1
 if 13 - 13: Ii1I
def lisp_get_echo_nonce ( rloc , rloc_str ) :
 if ( lisp_nonce_echoing == False ) : return ( None )
 if 34 - 34: I1IiiI / iIii1I11I1II1
 if ( rloc ) : rloc_str = rloc . print_address_no_iid ( )
 oOOo00ooO = None
 if ( lisp_nonce_echo_list . has_key ( rloc_str ) ) :
  oOOo00ooO = lisp_nonce_echo_list [ rloc_str ]
  if 35 - 35: oO0o / oO0o
 return ( oOOo00ooO )
 if 86 - 86: o0oOOo0O0Ooo . Oo0Ooo - Ii1I / i11iIiiIii
 if 63 - 63: oO0o - O0 + I1ii11iIi11i + Ii1I / i1IIi
 if 77 - 77: O0
 if 49 - 49: o0oOOo0O0Ooo / i11iIiiIii
 if 36 - 36: II111iiii
 if 78 - 78: OoO0O00 + iIii1I11I1II1 * i1IIi
 if 7 - 7: i11iIiiIii
 if 49 - 49: I1IiiI - oO0o % OOooOOo / O0 / II111iiii
def lisp_decode_dist_name ( packet ) :
 I1I11Iiii111 = 0
 i1i1iI1iII = ""
 if 72 - 72: O0 + OOooOOo * II111iiii * iII111i + IiII * i11iIiiIii
 while ( packet [ 0 : 1 ] != "\0" ) :
  if ( I1I11Iiii111 == 255 ) : return ( [ None , None ] )
  i1i1iI1iII += packet [ 0 : 1 ]
  packet = packet [ 1 : : ]
  I1I11Iiii111 += 1
  if 35 - 35: i1IIi - OoOoOO00
  if 57 - 57: iII111i / iIii1I11I1II1 + I1ii11iIi11i * I1ii11iIi11i
 packet = packet [ 1 : : ]
 return ( packet , i1i1iI1iII )
 if 98 - 98: O0 % I1IiiI + O0 - iIii1I11I1II1 / I11i
 if 22 - 22: OOooOOo * i11iIiiIii / oO0o / IiII / I1Ii111
 if 84 - 84: Oo0Ooo / I1Ii111 * I1ii11iIi11i + O0 * Oo0Ooo
 if 74 - 74: I11i . I11i
 if 74 - 74: OoOoOO00 * ooOoO0o * I1Ii111
 if 56 - 56: iIii1I11I1II1 * OoO0O00 - oO0o * Ii1I
 if 62 - 62: i1IIi + I11i / OOooOOo - OoooooooOO % i1IIi . I1IiiI
 if 13 - 13: O0 * iII111i
def lisp_write_flow_log ( flow_log ) :
 Oo0OO0o0oOO0 = open ( "./logs/lisp-flow.log" , "a" )
 if 26 - 26: i1IIi - I1Ii111 - ooOoO0o
 I1I11Iiii111 = 0
 for OoiIIii1Ii1 in flow_log :
  i1II1IiiIi = OoiIIii1Ii1 [ 3 ]
  oOIIii111II1iiI = i1II1IiiIi . print_flow ( OoiIIii1Ii1 [ 0 ] , OoiIIii1Ii1 [ 1 ] , OoiIIii1Ii1 [ 2 ] )
  Oo0OO0o0oOO0 . write ( oOIIii111II1iiI )
  I1I11Iiii111 += 1
  if 19 - 19: iII111i * ooOoO0o * i1IIi * Ii1I . OoO0O00 % iII111i
 Oo0OO0o0oOO0 . close ( )
 del ( flow_log )
 if 74 - 74: ooOoO0o
 I1I11Iiii111 = bold ( str ( I1I11Iiii111 ) , False )
 lprint ( "Wrote {} flow entries to ./logs/lisp-flow.log" . format ( I1I11Iiii111 ) )
 return
 if 70 - 70: iIii1I11I1II1 - I1Ii111 . oO0o . iII111i / o0oOOo0O0Ooo
 if 8 - 8: O0 - I1Ii111
 if 82 - 82: iII111i + II111iiii
 if 29 - 29: O0 % Ii1I * ooOoO0o % O0
 if 83 - 83: oO0o
 if 95 - 95: Oo0Ooo * O0 % i1IIi / iII111i + oO0o
 if 85 - 85: iIii1I11I1II1 / I11i
def lisp_policy_command ( kv_pair ) :
 OoOoO = lisp_policy ( "" )
 O00oo0O00oO0OO0o0 = None
 if 91 - 91: OoooooooOO % I11i - OOooOOo
 o0o0o = [ ]
 for Ii11 in range ( len ( kv_pair [ "datetime-range" ] ) ) :
  o0o0o . append ( lisp_policy_match ( ) )
  if 96 - 96: i11iIiiIii - I1Ii111 % oO0o % OOooOOo % OoOoOO00
  if 37 - 37: iIii1I11I1II1
 for OoO0o in kv_pair . keys ( ) :
  oOO = kv_pair [ OoO0o ]
  if 39 - 39: II111iiii + OoooooooOO / I11i . i11iIiiIii + I1Ii111
  if 19 - 19: I1ii11iIi11i / OOooOOo . I1IiiI / ooOoO0o + OoO0O00 + i11iIiiIii
  if 80 - 80: OoO0O00 . O0 / Ii1I % I1Ii111 / iII111i * I1IiiI
  if 41 - 41: O0 / OoooooooOO - i1IIi
  if ( OoO0o == "instance-id" ) :
   for Ii11 in range ( len ( o0o0o ) ) :
    Ii1II1ii = oOO [ Ii11 ]
    if ( Ii1II1ii == "" ) : continue
    IioO0o000o0 = o0o0o [ Ii11 ]
    if ( IioO0o000o0 . source_eid == None ) :
     IioO0o000o0 . source_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
     if 2 - 2: ooOoO0o
    if ( IioO0o000o0 . dest_eid == None ) :
     IioO0o000o0 . dest_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
     if 44 - 44: OoOoOO00 - i1IIi - OoO0O00 * I1Ii111 / I1IiiI + ooOoO0o
    IioO0o000o0 . source_eid . instance_id = int ( Ii1II1ii )
    IioO0o000o0 . dest_eid . instance_id = int ( Ii1II1ii )
    if 16 - 16: I1ii11iIi11i % o0oOOo0O0Ooo % OOooOOo % OoOoOO00 + ooOoO0o % I1ii11iIi11i
    if 85 - 85: oO0o * OoooooooOO * iIii1I11I1II1 + iII111i
  if ( OoO0o == "source-eid" ) :
   for Ii11 in range ( len ( o0o0o ) ) :
    Ii1II1ii = oOO [ Ii11 ]
    if ( Ii1II1ii == "" ) : continue
    IioO0o000o0 = o0o0o [ Ii11 ]
    if ( IioO0o000o0 . source_eid == None ) :
     IioO0o000o0 . source_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
     if 67 - 67: Ii1I / i11iIiiIii % OoOoOO00 % O0 / OoOoOO00
    o0OOoOO = IioO0o000o0 . source_eid . instance_id
    IioO0o000o0 . source_eid . store_prefix ( Ii1II1ii )
    IioO0o000o0 . source_eid . instance_id = o0OOoOO
    if 54 - 54: I11i . OoOoOO00 / II111iiii . i1IIi + OOooOOo % II111iiii
    if 82 - 82: i11iIiiIii . OoooooooOO % OoOoOO00 * O0 - I1Ii111
  if ( OoO0o == "destination-eid" ) :
   for Ii11 in range ( len ( o0o0o ) ) :
    Ii1II1ii = oOO [ Ii11 ]
    if ( Ii1II1ii == "" ) : continue
    IioO0o000o0 = o0o0o [ Ii11 ]
    if ( IioO0o000o0 . dest_eid == None ) :
     IioO0o000o0 . dest_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
     if 78 - 78: OoOoOO00 % Ii1I % OOooOOo % Oo0Ooo % I11i . Ii1I
    o0OOoOO = IioO0o000o0 . dest_eid . instance_id
    IioO0o000o0 . dest_eid . store_prefix ( Ii1II1ii )
    IioO0o000o0 . dest_eid . instance_id = o0OOoOO
    if 73 - 73: OoooooooOO / i1IIi . iIii1I11I1II1
    if 89 - 89: I1Ii111
  if ( OoO0o == "source-rloc" ) :
   for Ii11 in range ( len ( o0o0o ) ) :
    Ii1II1ii = oOO [ Ii11 ]
    if ( Ii1II1ii == "" ) : continue
    IioO0o000o0 = o0o0o [ Ii11 ]
    IioO0o000o0 . source_rloc = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
    IioO0o000o0 . source_rloc . store_prefix ( Ii1II1ii )
    if 29 - 29: I11i * ooOoO0o - OoooooooOO
    if 92 - 92: O0 % i1IIi / OOooOOo - oO0o
  if ( OoO0o == "destination-rloc" ) :
   for Ii11 in range ( len ( o0o0o ) ) :
    Ii1II1ii = oOO [ Ii11 ]
    if ( Ii1II1ii == "" ) : continue
    IioO0o000o0 = o0o0o [ Ii11 ]
    IioO0o000o0 . dest_rloc = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
    IioO0o000o0 . dest_rloc . store_prefix ( Ii1II1ii )
    if 83 - 83: o0oOOo0O0Ooo . OoO0O00 % iIii1I11I1II1 % OoOoOO00 - i11iIiiIii
    if 71 - 71: I1ii11iIi11i - II111iiii / O0 % i1IIi + oO0o
  if ( OoO0o == "rloc-record-name" ) :
   for Ii11 in range ( len ( o0o0o ) ) :
    Ii1II1ii = oOO [ Ii11 ]
    if ( Ii1II1ii == "" ) : continue
    IioO0o000o0 = o0o0o [ Ii11 ]
    IioO0o000o0 . rloc_record_name = Ii1II1ii
    if 73 - 73: OoooooooOO
    if 25 - 25: i1IIi . II111iiii . I1Ii111
  if ( OoO0o == "geo-name" ) :
   for Ii11 in range ( len ( o0o0o ) ) :
    Ii1II1ii = oOO [ Ii11 ]
    if ( Ii1II1ii == "" ) : continue
    IioO0o000o0 = o0o0o [ Ii11 ]
    IioO0o000o0 . geo_name = Ii1II1ii
    if 81 - 81: II111iiii + OoOoOO00 * II111iiii / iIii1I11I1II1 - Oo0Ooo % oO0o
    if 66 - 66: ooOoO0o % O0 + iIii1I11I1II1 * I1Ii111 - I1Ii111
  if ( OoO0o == "elp-name" ) :
   for Ii11 in range ( len ( o0o0o ) ) :
    Ii1II1ii = oOO [ Ii11 ]
    if ( Ii1II1ii == "" ) : continue
    IioO0o000o0 = o0o0o [ Ii11 ]
    IioO0o000o0 . elp_name = Ii1II1ii
    if 61 - 61: I1ii11iIi11i
    if 12 - 12: OoO0O00
  if ( OoO0o == "rle-name" ) :
   for Ii11 in range ( len ( o0o0o ) ) :
    Ii1II1ii = oOO [ Ii11 ]
    if ( Ii1II1ii == "" ) : continue
    IioO0o000o0 = o0o0o [ Ii11 ]
    IioO0o000o0 . rle_name = Ii1II1ii
    if 97 - 97: OOooOOo . Oo0Ooo . oO0o * i1IIi
    if 7 - 7: Oo0Ooo
  if ( OoO0o == "json-name" ) :
   for Ii11 in range ( len ( o0o0o ) ) :
    Ii1II1ii = oOO [ Ii11 ]
    if ( Ii1II1ii == "" ) : continue
    IioO0o000o0 = o0o0o [ Ii11 ]
    IioO0o000o0 . json_name = Ii1II1ii
    if 38 - 38: Oo0Ooo - I1ii11iIi11i
    if 19 - 19: Ii1I * OoO0O00 / OoO0O00 . II111iiii % iIii1I11I1II1
  if ( OoO0o == "datetime-range" ) :
   for Ii11 in range ( len ( o0o0o ) ) :
    Ii1II1ii = oOO [ Ii11 ]
    IioO0o000o0 = o0o0o [ Ii11 ]
    if ( Ii1II1ii == "" ) : continue
    IIi11I1i1I1I = lisp_datetime ( Ii1II1ii [ 0 : 19 ] )
    oOii = lisp_datetime ( Ii1II1ii [ 19 : : ] )
    if ( IIi11I1i1I1I . valid_datetime ( ) and oOii . valid_datetime ( ) ) :
     IioO0o000o0 . datetime_lower = IIi11I1i1I1I
     IioO0o000o0 . datetime_upper = oOii
     if 61 - 61: I1ii11iIi11i * oO0o % iII111i + IiII + i11iIiiIii * I11i
     if 3 - 3: Ii1I
     if 71 - 71: iIii1I11I1II1 . OOooOOo / I11i / i1IIi
     if 69 - 69: i1IIi / iII111i + Ii1I + I11i + IiII
     if 86 - 86: Oo0Ooo
     if 97 - 97: I1IiiI
     if 91 - 91: ooOoO0o / oO0o * OOooOOo . II111iiii - I11i - I11i
  if ( OoO0o == "set-action" ) :
   OoOoO . set_action = oOO
   if 5 - 5: O0 + OoooooooOO + i11iIiiIii * Oo0Ooo * OoOoOO00 . oO0o
  if ( OoO0o == "set-record-ttl" ) :
   OoOoO . set_record_ttl = int ( oOO )
   if 6 - 6: OoO0O00 % Oo0Ooo % I1IiiI % o0oOOo0O0Ooo % O0 % Oo0Ooo
  if ( OoO0o == "set-instance-id" ) :
   if ( OoOoO . set_source_eid == None ) :
    OoOoO . set_source_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
    if 94 - 94: I11i . i1IIi / II111iiii + OOooOOo
   if ( OoOoO . set_dest_eid == None ) :
    OoOoO . set_dest_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
    if 64 - 64: I1IiiI % ooOoO0o
   O00oo0O00oO0OO0o0 = int ( oOO )
   OoOoO . set_source_eid . instance_id = O00oo0O00oO0OO0o0
   OoOoO . set_dest_eid . instance_id = O00oo0O00oO0OO0o0
   if 72 - 72: O0 * II111iiii % OoO0O00 - I1IiiI * OOooOOo
  if ( OoO0o == "set-source-eid" ) :
   if ( OoOoO . set_source_eid == None ) :
    OoOoO . set_source_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
    if 80 - 80: OOooOOo * I11i / OOooOOo - oO0o
   OoOoO . set_source_eid . store_prefix ( oOO )
   if ( O00oo0O00oO0OO0o0 != None ) : OoOoO . set_source_eid . instance_id = O00oo0O00oO0OO0o0
   if 18 - 18: i1IIi - OOooOOo - o0oOOo0O0Ooo - iIii1I11I1II1
  if ( OoO0o == "set-destination-eid" ) :
   if ( OoOoO . set_dest_eid == None ) :
    OoOoO . set_dest_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
    if 72 - 72: OoooooooOO % I1IiiI . OoO0O00
   OoOoO . set_dest_eid . store_prefix ( oOO )
   if ( O00oo0O00oO0OO0o0 != None ) : OoOoO . set_dest_eid . instance_id = O00oo0O00oO0OO0o0
   if 28 - 28: II111iiii / iIii1I11I1II1 / iII111i - o0oOOo0O0Ooo . I1IiiI / O0
  if ( OoO0o == "set-rloc-address" ) :
   OoOoO . set_rloc_address = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
   OoOoO . set_rloc_address . store_address ( oOO )
   if 16 - 16: ooOoO0o * oO0o . OoooooooOO
  if ( OoO0o == "set-rloc-record-name" ) :
   OoOoO . set_rloc_record_name = oOO
   if 44 - 44: iIii1I11I1II1 * OOooOOo + OoO0O00 - OoooooooOO
  if ( OoO0o == "set-elp-name" ) :
   OoOoO . set_elp_name = oOO
   if 13 - 13: Oo0Ooo . I11i . II111iiii
  if ( OoO0o == "set-geo-name" ) :
   OoOoO . set_geo_name = oOO
   if 6 - 6: OOooOOo . IiII / OoO0O00 * oO0o - I1Ii111 . OoOoOO00
  if ( OoO0o == "set-rle-name" ) :
   OoOoO . set_rle_name = oOO
   if 85 - 85: i11iIiiIii + OoOoOO00
  if ( OoO0o == "set-json-name" ) :
   OoOoO . set_json_name = oOO
   if 4 - 4: OOooOOo . OoO0O00 * II111iiii + OoO0O00 % Oo0Ooo
  if ( OoO0o == "policy-name" ) :
   OoOoO . policy_name = oOO
   if 60 - 60: OOooOOo . Ii1I
   if 13 - 13: i1IIi . iII111i / OoOoOO00 . I1Ii111
   if 65 - 65: oO0o % I1Ii111 % OoO0O00 . iIii1I11I1II1
   if 38 - 38: IiII / I11i / IiII * iII111i
   if 30 - 30: oO0o
   if 30 - 30: IiII / OoO0O00
 OoOoO . match_clauses = o0o0o
 OoOoO . save_policy ( )
 return
 if 89 - 89: oO0o . OoOoOO00 . IiII / iIii1I11I1II1 . iIii1I11I1II1 / OoOoOO00
 if 86 - 86: OoooooooOO - iIii1I11I1II1 . OoO0O00 * Ii1I / I1Ii111 + I1Ii111
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
if 52 - 52: iIii1I11I1II1 % OoO0O00 - IiII % i11iIiiIii - o0oOOo0O0Ooo
if 25 - 25: Oo0Ooo - OOooOOo . i1IIi * OoOoOO00 / I11i / o0oOOo0O0Ooo
if 54 - 54: OoOoOO00 / i1IIi + OOooOOo - I1ii11iIi11i - I1IiiI * I1Ii111
if 91 - 91: OoooooooOO * OoooooooOO
if 27 - 27: ooOoO0o / I1IiiI * I1ii11iIi11i . o0oOOo0O0Ooo
if 30 - 30: o0oOOo0O0Ooo / i11iIiiIii
if 33 - 33: OOooOOo % OoooooooOO
def lisp_send_to_arista ( command , interface ) :
 interface = "" if ( interface == None ) else "interface " + interface
 if 98 - 98: Ii1I
 I11111II = command
 if ( interface != "" ) : I11111II = interface + ": " + I11111II
 lprint ( "Send CLI command '{}' to hardware" . format ( I11111II ) )
 if 40 - 40: I1IiiI + Ii1I . O0 . i1IIi - ooOoO0o . ooOoO0o
 commands = '''
        enable
        configure
        {}
        {}
    ''' . format ( interface , command )
 if 80 - 80: i11iIiiIii % I1Ii111 % I1IiiI / I1IiiI + oO0o + iII111i
 os . system ( "FastCli -c '{}'" . format ( commands ) )
 return
 if 18 - 18: OoO0O00 * ooOoO0o
 if 32 - 32: oO0o . OoooooooOO - o0oOOo0O0Ooo + II111iiii
 if 4 - 4: OOooOOo * I1IiiI - I11i - I11i
 if 67 - 67: I1IiiI
 if 32 - 32: oO0o * i11iIiiIii - I11i % Oo0Ooo * I1ii11iIi11i
 if 79 - 79: II111iiii / Oo0Ooo / I1ii11iIi11i
 if 30 - 30: I11i . o0oOOo0O0Ooo / II111iiii
def lisp_arista_is_alive ( prefix ) :
 o00OoOO0O0 = "enable\nsh plat trident l3 software routes {}\n" . format ( prefix )
 Oo0O = commands . getoutput ( "FastCli -c '{}'" . format ( o00OoOO0O0 ) )
 if 59 - 59: i11iIiiIii
 if 5 - 5: i11iIiiIii + o0oOOo0O0Ooo . OoO0O00 % OoOoOO00 + I11i
 if 59 - 59: I1ii11iIi11i
 if 47 - 47: I1IiiI + Oo0Ooo
 Oo0O = Oo0O . split ( "\n" ) [ 1 ]
 Oo0O0 = Oo0O . split ( " " )
 Oo0O0 = Oo0O0 [ - 1 ] . replace ( "\r" , "" )
 if 98 - 98: OoO0O00 . i1IIi % OoooooooOO
 if 99 - 99: I1ii11iIi11i * IiII / o0oOOo0O0Ooo - i1IIi - OOooOOo
 if 65 - 65: Ii1I + OoOoOO00 * Oo0Ooo . O0 . IiII
 if 33 - 33: i11iIiiIii . i1IIi . I1Ii111 - OoOoOO00 + OOooOOo
 return ( Oo0O0 == "Y" )
 if 34 - 34: I1ii11iIi11i . i1IIi * O0 / OoooooooOO
 if 22 - 22: OOooOOo % o0oOOo0O0Ooo - i11iIiiIii
 if 58 - 58: IiII . Ii1I + II111iiii
 if 31 - 31: i11iIiiIii + i11iIiiIii + I11i * Oo0Ooo . I11i
 if 28 - 28: OOooOOo * iIii1I11I1II1 * OoOoOO00
 if 75 - 75: Oo0Ooo % IiII + II111iiii + oO0o
 if 35 - 35: I1ii11iIi11i - oO0o - O0 / iII111i % IiII
 if 10 - 10: OOooOOo + oO0o - I1Ii111 . I1IiiI
 if 11 - 11: I1ii11iIi11i . I1Ii111 / o0oOOo0O0Ooo + IiII
 if 73 - 73: OoO0O00 . i11iIiiIii * OoO0O00 * i1IIi + I11i
 if 27 - 27: i11iIiiIii / OoOoOO00 % O0 / II111iiii . I11i - ooOoO0o
 if 54 - 54: oO0o * II111iiii
 if 79 - 79: o0oOOo0O0Ooo . ooOoO0o . Oo0Ooo * OoooooooOO
 if 98 - 98: ooOoO0o
 if 73 - 73: I1Ii111
 if 97 - 97: OoO0O00 * Ii1I + Oo0Ooo
 if 83 - 83: II111iiii - Oo0Ooo % II111iiii * o0oOOo0O0Ooo
 if 51 - 51: iII111i * iIii1I11I1II1 % Ii1I * Ii1I + i11iIiiIii . OoooooooOO
 if 54 - 54: i11iIiiIii . iIii1I11I1II1 * iIii1I11I1II1 + Ii1I % I11i - OoO0O00
 if 16 - 16: IiII % iIii1I11I1II1 * i11iIiiIii + O0
 if 76 - 76: iII111i * OOooOOo
 if 7 - 7: ooOoO0o + o0oOOo0O0Ooo + o0oOOo0O0Ooo
 if 73 - 73: IiII % I11i % i11iIiiIii + ooOoO0o
 if 83 - 83: Ii1I * I1Ii111 * i11iIiiIii / iIii1I11I1II1 % I1ii11iIi11i
 if 40 - 40: iII111i
 if 21 - 21: I1Ii111 / iII111i + Oo0Ooo / I1ii11iIi11i / I1Ii111
 if 33 - 33: OoooooooOO
 if 59 - 59: i11iIiiIii - OoooooooOO . ooOoO0o / i11iIiiIii % iIii1I11I1II1 * I1ii11iIi11i
 if 45 - 45: I1ii11iIi11i * I1ii11iIi11i
 if 31 - 31: OoO0O00 - OOooOOo . iII111i * I1Ii111 * iII111i + I1ii11iIi11i
 if 5 - 5: Oo0Ooo . I1Ii111
 if 77 - 77: i11iIiiIii / I1Ii111 / I1ii11iIi11i % oO0o
 if 83 - 83: Ii1I % iIii1I11I1II1 / I1ii11iIi11i + I11i
 if 23 - 23: iIii1I11I1II1 - I1IiiI
 if 51 - 51: OoooooooOO / IiII / I1ii11iIi11i . Oo0Ooo - o0oOOo0O0Ooo * OoooooooOO
 if 40 - 40: OoO0O00 / IiII . O0 / I1IiiI + OoO0O00 . o0oOOo0O0Ooo
 if 25 - 25: ooOoO0o * I1Ii111 * oO0o
 if 64 - 64: Ii1I / I1ii11iIi11i
 if 30 - 30: OoooooooOO + O0 / I1ii11iIi11i * o0oOOo0O0Ooo
 if 11 - 11: O0 + OoO0O00 - Oo0Ooo - Oo0Ooo . i11iIiiIii
 if 15 - 15: Ii1I % i11iIiiIii / OoOoOO00
 if 85 - 85: ooOoO0o . i1IIi / iII111i % iIii1I11I1II1 / II111iiii / I1Ii111
 if 60 - 60: iIii1I11I1II1 - iIii1I11I1II1 . I11i
 if 55 - 55: OoO0O00
def lisp_program_vxlan_hardware ( mc ) :
 if 87 - 87: Ii1I - iII111i / O0 - o0oOOo0O0Ooo - iIii1I11I1II1 % Ii1I
 if 47 - 47: iII111i * I1Ii111 % o0oOOo0O0Ooo / OoOoOO00 / OoO0O00 % OoO0O00
 if 43 - 43: Oo0Ooo
 if 34 - 34: OoO0O00 . i1IIi + IiII * IiII
 if 76 - 76: OOooOOo
 if 54 - 54: O0 * II111iiii * OOooOOo
 if ( os . path . exists ( "/persist/local/lispers.net" ) == False ) : return
 if 44 - 44: I1IiiI
 if 66 - 66: o0oOOo0O0Ooo
 if 40 - 40: OOooOOo * Ii1I
 if 38 - 38: ooOoO0o
 if ( len ( mc . best_rloc_set ) == 0 ) : return
 if 5 - 5: OoooooooOO + iII111i - I11i
 if 95 - 95: OOooOOo / i11iIiiIii - Ii1I + I1ii11iIi11i
 if 7 - 7: I1ii11iIi11i
 if 37 - 37: O0 . II111iiii
 iiI11Iiii = mc . eid . print_prefix_no_iid ( )
 OoOOo = mc . best_rloc_set [ 0 ] . rloc . print_address_no_iid ( )
 if 70 - 70: o0oOOo0O0Ooo / iII111i + i1IIi + I11i % iIii1I11I1II1 % Oo0Ooo
 if 1 - 1: O0 + OoO0O00 . i11iIiiIii + I1Ii111 - OoO0O00 - IiII
 if 1 - 1: I1ii11iIi11i / i1IIi . I1IiiI / Ii1I
 if 19 - 19: iIii1I11I1II1 / Oo0Ooo . O0 - Oo0Ooo
 oOoo0O0OO00O0 = commands . getoutput ( "ip route get {} | egrep vlan4094" . format ( iiI11Iiii ) )
 if 6 - 6: Oo0Ooo - II111iiii - iII111i . ooOoO0o - iIii1I11I1II1 - O0
 if ( oOoo0O0OO00O0 != "" ) :
  lprint ( "Route {} already in hardware: '{}'" . format ( green ( iiI11Iiii , False ) , oOoo0O0OO00O0 ) )
  if 69 - 69: I1IiiI % Ii1I - OoooooooOO / iIii1I11I1II1 * OoooooooOO
  return
  if 70 - 70: o0oOOo0O0Ooo % OoooooooOO % I1IiiI . OoOoOO00 * I1IiiI - ooOoO0o
  if 92 - 92: I1IiiI . I11i
  if 66 - 66: I1Ii111 / I11i / OoooooooOO % OoOoOO00 . oO0o * iII111i
  if 34 - 34: I1ii11iIi11i * I1ii11iIi11i % I11i / OOooOOo % oO0o . OoOoOO00
  if 25 - 25: I1ii11iIi11i / I11i + i1IIi . I1IiiI + ooOoO0o
  if 29 - 29: IiII + I1ii11iIi11i
  if 8 - 8: IiII % I1IiiI
 iiI1iii1ii = commands . getoutput ( "ifconfig | egrep 'vxlan|vlan4094'" )
 if ( iiI1iii1ii . find ( "vxlan" ) == - 1 ) :
  lprint ( "No VXLAN interface found, cannot program hardware" )
  return
  if 4 - 4: OoooooooOO * I1ii11iIi11i - I1ii11iIi11i
 if ( iiI1iii1ii . find ( "vlan4094" ) == - 1 ) :
  lprint ( "No vlan4094 interface found, cannot program hardware" )
  return
  if 38 - 38: I1Ii111
 I1Io0oOOo00O0OOo = commands . getoutput ( "ip addr | egrep vlan4094 | egrep inet" )
 if ( I1Io0oOOo00O0OOo == "" ) :
  lprint ( "No IP address found on vlan4094, cannot program hardware" )
  return
  if 79 - 79: OOooOOo * IiII / i1IIi . iII111i - Ii1I
 I1Io0oOOo00O0OOo = I1Io0oOOo00O0OOo . split ( "inet " ) [ 1 ]
 I1Io0oOOo00O0OOo = I1Io0oOOo00O0OOo . split ( "/" ) [ 0 ]
 if 76 - 76: oO0o % oO0o / o0oOOo0O0Ooo + OoooooooOO * O0
 if 17 - 17: ooOoO0o
 if 8 - 8: o0oOOo0O0Ooo
 if 82 - 82: I1IiiI - OoO0O00 . Ii1I + I1IiiI * iII111i
 if 72 - 72: I11i . Oo0Ooo / IiII * Oo0Ooo % I1ii11iIi11i + iII111i
 if 49 - 49: i11iIiiIii + OoOoOO00
 if 61 - 61: II111iiii / II111iiii * o0oOOo0O0Ooo - IiII + I1ii11iIi11i
 ii1iIi = [ ]
 oO0O0Oo000OOO = commands . getoutput ( "arp -i vlan4094" ) . split ( "\n" )
 for oooOo in oO0O0Oo000OOO :
  if ( oooOo . find ( "vlan4094" ) == - 1 ) : continue
  if ( oooOo . find ( "(incomplete)" ) == - 1 ) : continue
  i11i1i = oooOo . split ( " " ) [ 0 ]
  ii1iIi . append ( i11i1i )
  if 23 - 23: OoOoOO00 / IiII
  if 90 - 90: I1Ii111 - O0 % iII111i * i1IIi
 i11i1i = None
 I11 = I1Io0oOOo00O0OOo
 I1Io0oOOo00O0OOo = I1Io0oOOo00O0OOo . split ( "." )
 for Ii11 in range ( 1 , 255 ) :
  I1Io0oOOo00O0OOo [ 3 ] = str ( Ii11 )
  o0o0O00 = "." . join ( I1Io0oOOo00O0OOo )
  if ( o0o0O00 in ii1iIi ) : continue
  if ( o0o0O00 == I11 ) : continue
  i11i1i = o0o0O00
  break
  if 14 - 14: ooOoO0o % I1IiiI
 if ( i11i1i == None ) :
  lprint ( "Address allocation failed for vlan4094, cannot program " + "hardware" )
  if 96 - 96: O0 * I1Ii111 . o0oOOo0O0Ooo / iIii1I11I1II1 - I11i . oO0o
  return
  if 37 - 37: OoO0O00 . I1IiiI + I1ii11iIi11i - iIii1I11I1II1 % O0 * OoOoOO00
  if 28 - 28: ooOoO0o + Oo0Ooo - I1ii11iIi11i
  if 16 - 16: O0 - OoO0O00 % Ii1I % O0
  if 51 - 51: iIii1I11I1II1 * i11iIiiIii . I1IiiI + o0oOOo0O0Ooo / iII111i - I1IiiI
  if 73 - 73: OOooOOo
  if 100 - 100: o0oOOo0O0Ooo - OoOoOO00
  if 91 - 91: II111iiii / i11iIiiIii . Oo0Ooo * iIii1I11I1II1
 i1iIIi11i1I1 = OoOOo . split ( "." )
 IIio0OOOo0Oo0O = lisp_hex_string ( i1iIIi11i1I1 [ 1 ] ) . zfill ( 2 )
 Ii1oO0OOOo = lisp_hex_string ( i1iIIi11i1I1 [ 2 ] ) . zfill ( 2 )
 I11O0OooOOO = lisp_hex_string ( i1iIIi11i1I1 [ 3 ] ) . zfill ( 2 )
 II11iI1iiI = "00:00:00:{}:{}:{}" . format ( IIio0OOOo0Oo0O , Ii1oO0OOOo , I11O0OooOOO )
 IIii1I = "0000.00{}.{}{}" . format ( IIio0OOOo0Oo0O , Ii1oO0OOOo , I11O0OooOOO )
 OOoOOoO = "arp -i vlan4094 -s {} {}" . format ( i11i1i , II11iI1iiI )
 os . system ( OOoOOoO )
 if 57 - 57: Ii1I + I1IiiI / O0
 if 44 - 44: i1IIi - ooOoO0o / I1ii11iIi11i
 if 60 - 60: o0oOOo0O0Ooo . i1IIi * IiII
 if 100 - 100: I1IiiI / I1Ii111 - Oo0Ooo % iII111i - I1ii11iIi11i % OoO0O00
 iIi1Ii11i1I = ( "mac address-table static {} vlan 4094 " + "interface vxlan 1 vtep {}" ) . format ( IIii1I , OoOOo )
 if 37 - 37: iII111i / OoOoOO00 . Oo0Ooo + i1IIi * ooOoO0o
 lisp_send_to_arista ( iIi1Ii11i1I , None )
 if 89 - 89: OoOoOO00 / I1ii11iIi11i - i11iIiiIii % i11iIiiIii
 if 31 - 31: iII111i
 if 64 - 64: Ii1I
 if 4 - 4: OoOoOO00
 if 78 - 78: i1IIi - iII111i + O0 - I1IiiI % o0oOOo0O0Ooo
 I11iI1i1 = "ip route add {} via {}" . format ( iiI11Iiii , i11i1i )
 os . system ( I11iI1i1 )
 if 48 - 48: i1IIi + iII111i - Ii1I
 lprint ( "Hardware programmed with commands:" )
 I11iI1i1 = I11iI1i1 . replace ( iiI11Iiii , green ( iiI11Iiii , False ) )
 lprint ( "  " + I11iI1i1 )
 lprint ( "  " + OOoOOoO )
 iIi1Ii11i1I = iIi1Ii11i1I . replace ( OoOOo , red ( OoOOo , False ) )
 lprint ( "  " + iIi1Ii11i1I )
 return
 if 9 - 9: o0oOOo0O0Ooo
 if 92 - 92: i11iIiiIii + OoooooooOO + O0 % oO0o
 if 90 - 90: Oo0Ooo * i11iIiiIii
 if 95 - 95: I1Ii111 % i11iIiiIii . i11iIiiIii . i11iIiiIii . OoooooooOO - I1Ii111
 if 69 - 69: iIii1I11I1II1 * oO0o
 if 80 - 80: IiII - oO0o % Ii1I - iIii1I11I1II1 . OoO0O00
 if 64 - 64: I1IiiI % i11iIiiIii / oO0o
def lisp_clear_hardware_walk ( mc , parms ) :
 OoooO00OO0OO = mc . eid . print_prefix_no_iid ( )
 os . system ( "ip route delete {}" . format ( OoooO00OO0OO ) )
 return ( [ True , None ] )
 if 78 - 78: II111iiii - Oo0Ooo . iIii1I11I1II1 - ooOoO0o . oO0o
 if 84 - 84: iII111i . ooOoO0o * I1IiiI * Oo0Ooo / I1Ii111
 if 93 - 93: i1IIi * i11iIiiIii % OoOoOO00 % iII111i
 if 31 - 31: OoO0O00
 if 89 - 89: II111iiii
 if 33 - 33: OOooOOo / oO0o % OoOoOO00 * O0
 if 65 - 65: OoO0O00 % OoOoOO00 % I1ii11iIi11i / OoooooooOO
 if 85 - 85: O0 * OOooOOo % I1Ii111
def lisp_clear_map_cache ( ) :
 global lisp_map_cache , lisp_rloc_probe_list
 global lisp_crypto_keys_by_rloc_encap , lisp_crypto_keys_by_rloc_decap
 global lisp_rtr_list
 if 33 - 33: O0
 IiiIIIiIIIii1II = bold ( "User cleared" , False )
 I1I11Iiii111 = lisp_map_cache . cache_count
 lprint ( "{} map-cache with {} entries" . format ( IiiIIIiIIIii1II , I1I11Iiii111 ) )
 if 33 - 33: OoO0O00
 if ( lisp_program_hardware ) :
  lisp_map_cache . walk_cache ( lisp_clear_hardware_walk , None )
  if 10 - 10: oO0o
 lisp_map_cache = lisp_cache ( )
 if 75 - 75: II111iiii % OOooOOo / iIii1I11I1II1 / OoO0O00 + oO0o
 if 16 - 16: oO0o + I1Ii111 - II111iiii - o0oOOo0O0Ooo / i11iIiiIii
 if 59 - 59: OOooOOo - o0oOOo0O0Ooo
 if 82 - 82: IiII % ooOoO0o - OoO0O00 % ooOoO0o
 if 51 - 51: ooOoO0o % iII111i . o0oOOo0O0Ooo . o0oOOo0O0Ooo
 lisp_rloc_probe_list = { }
 if 20 - 20: i1IIi - ooOoO0o % OoooooooOO * I1ii11iIi11i + II111iiii % i1IIi
 if 30 - 30: i11iIiiIii - I1IiiI + o0oOOo0O0Ooo + IiII
 if 16 - 16: I1ii11iIi11i / Ii1I + I1ii11iIi11i * I1Ii111
 if 49 - 49: ooOoO0o * OoOoOO00 . OoooooooOO . ooOoO0o + Oo0Ooo * IiII
 lisp_crypto_keys_by_rloc_encap = { }
 lisp_crypto_keys_by_rloc_decap = { }
 if 47 - 47: iII111i . i1IIi . I1ii11iIi11i / OoooooooOO
 if 84 - 84: o0oOOo0O0Ooo * I11i
 if 22 - 22: i1IIi + OOooOOo % OoooooooOO
 if 34 - 34: oO0o / O0 - II111iiii % Oo0Ooo + I11i
 if 23 - 23: o0oOOo0O0Ooo + i11iIiiIii . I1IiiI + iIii1I11I1II1
 lisp_rtr_list = { }
 if 18 - 18: o0oOOo0O0Ooo . O0 + I1Ii111
 if 66 - 66: OoooooooOO
 if 90 - 90: IiII - OoOoOO00
 if 98 - 98: Oo0Ooo / oO0o . Ii1I
 lisp_process_data_plane_restart ( True )
 return
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
def lisp_encapsulate_rloc_probe ( lisp_sockets , rloc , nat_info , packet ) :
 if ( len ( lisp_sockets ) != 4 ) : return
 if 66 - 66: OOooOOo / O0 + i1IIi . O0 % I1ii11iIi11i - OoooooooOO
 i11i1Ii11i = lisp_myrlocs [ 0 ]
 if 43 - 43: IiII . o0oOOo0O0Ooo + I1Ii111 + OoO0O00 * II111iiii
 if 67 - 67: i11iIiiIii * i1IIi + OOooOOo - I11i - I1Ii111
 if 9 - 9: I1IiiI - I11i . ooOoO0o % i11iIiiIii
 if 27 - 27: iIii1I11I1II1 . OoooooooOO
 if 92 - 92: ooOoO0o + IiII * II111iiii
 o00OOo00 = len ( packet ) + 28
 i1I1i1i = struct . pack ( "BBHIBBHII" , 0x45 , 0 , socket . htons ( o00OOo00 ) , 0 , 64 ,
 17 , 0 , socket . htonl ( i11i1Ii11i . address ) , socket . htonl ( rloc . address ) )
 i1I1i1i = lisp_ip_checksum ( i1I1i1i )
 if 41 - 41: I1IiiI + OoOoOO00 . OOooOOo
 I1iIIIiI = struct . pack ( "HHHH" , 0 , socket . htons ( LISP_CTRL_PORT ) ,
 socket . htons ( o00OOo00 - 20 ) , 0 )
 if 57 - 57: II111iiii . iIii1I11I1II1
 if 32 - 32: o0oOOo0O0Ooo
 if 75 - 75: I1IiiI . II111iiii - iII111i % IiII * OoO0O00 % ooOoO0o
 if 38 - 38: I1IiiI / OoooooooOO
 packet = lisp_packet ( i1I1i1i + I1iIIIiI + packet )
 if 16 - 16: i1IIi . i11iIiiIii . oO0o - I11i
 if 96 - 96: iII111i - OoOoOO00
 if 43 - 43: OoO0O00 - I1Ii111 % OoooooooOO % I1ii11iIi11i . OoOoOO00
 if 87 - 87: OOooOOo
 packet . inner_dest . copy_address ( rloc )
 packet . inner_dest . instance_id = 0xffffff
 packet . inner_source . copy_address ( i11i1Ii11i )
 packet . inner_ttl = 64
 packet . outer_dest . copy_address ( rloc )
 packet . outer_source . copy_address ( i11i1Ii11i )
 packet . outer_version = packet . outer_dest . afi_to_version ( )
 packet . outer_ttl = 64
 packet . encap_port = nat_info . port if nat_info else LISP_DATA_PORT
 if 60 - 60: ooOoO0o * o0oOOo0O0Ooo . OoO0O00 * iII111i * oO0o * i1IIi
 ooOo = red ( rloc . print_address_no_iid ( ) , False )
 if ( nat_info ) :
  i1II11 = " {}" . format ( blue ( nat_info . hostname , False ) )
  Ooo0O = bold ( "RLOC-probe request" , False )
 else :
  i1II11 = ""
  Ooo0O = bold ( "RLOC-probe reply" , False )
  if 100 - 100: iII111i . o0oOOo0O0Ooo - I1Ii111 % oO0o
  if 11 - 11: o0oOOo0O0Ooo . OoooooooOO - i1IIi
 lprint ( ( "Data encapsulate {} to {}{} port {} for " + "NAT-traversal" ) . format ( Ooo0O , ooOo , i1II11 , packet . encap_port ) )
 if 71 - 71: I1IiiI . OOooOOo . I1ii11iIi11i
 if 90 - 90: i11iIiiIii + I1Ii111 % II111iiii
 if 67 - 67: OoOoOO00 / iII111i * OoO0O00 % i11iIiiIii
 if 76 - 76: OoO0O00
 if 92 - 92: iIii1I11I1II1 * O0 % I11i
 if ( packet . encode ( None ) == None ) : return
 packet . print_packet ( "Send" , True )
 if 92 - 92: OoOoOO00 + oO0o
 O0o0ooo0OO = lisp_sockets [ 3 ]
 packet . send_packet ( O0o0ooo0OO , packet . outer_dest )
 del ( packet )
 return
 if 99 - 99: O0 / I1IiiI
 if 11 - 11: I1IiiI
 if 92 - 92: iIii1I11I1II1 - I11i - OOooOOo / Ii1I . o0oOOo0O0Ooo . OoO0O00
 if 33 - 33: oO0o / I11i % ooOoO0o * I11i / oO0o - OoOoOO00
 if 89 - 89: iIii1I11I1II1 . II111iiii + IiII
 if 8 - 8: I1ii11iIi11i / II111iiii / II111iiii
 if 62 - 62: I11i - iII111i . Ii1I
 if 20 - 20: I1ii11iIi11i
def lisp_get_default_route_next_hops ( ) :
 if 99 - 99: o0oOOo0O0Ooo + I1ii11iIi11i * IiII
 if 67 - 67: I1IiiI
 if 93 - 93: ooOoO0o . Ii1I + IiII / Oo0Ooo % I11i
 if 40 - 40: Oo0Ooo % OoOoOO00 . IiII / I1IiiI % OoooooooOO
 if ( lisp_is_macos ( ) ) :
  o00OoOO0O0 = "route -n get default"
  i1ii1iiI = commands . getoutput ( o00OoOO0O0 ) . split ( "\n" )
  oOO00Oo0 = I111IIiIII = None
  for Oo0OO0o0oOO0 in i1ii1iiI :
   if ( Oo0OO0o0oOO0 . find ( "gateway: " ) != - 1 ) : oOO00Oo0 = Oo0OO0o0oOO0 . split ( ": " ) [ 1 ]
   if ( Oo0OO0o0oOO0 . find ( "interface: " ) != - 1 ) : I111IIiIII = Oo0OO0o0oOO0 . split ( ": " ) [ 1 ]
   if 69 - 69: I1ii11iIi11i * I1IiiI . IiII + I11i / II111iiii . o0oOOo0O0Ooo
  return ( [ [ I111IIiIII , oOO00Oo0 ] ] )
  if 65 - 65: Ii1I * OoOoOO00 % OOooOOo . iIii1I11I1II1 - Ii1I
  if 39 - 39: o0oOOo0O0Ooo * iII111i
  if 95 - 95: II111iiii / iII111i + i1IIi
  if 70 - 70: IiII . I1Ii111
  if 29 - 29: Oo0Ooo . i11iIiiIii + OoOoOO00 - Oo0Ooo
 o00OoOO0O0 = "ip route | egrep 'default via'"
 iiiiI1I11iI1 = commands . getoutput ( o00OoOO0O0 ) . split ( "\n" )
 if 13 - 13: ooOoO0o
 O0O0Oo = [ ]
 for oOoo0O0OO00O0 in iiiiI1I11iI1 :
  if ( oOoo0O0OO00O0 . find ( " metric " ) != - 1 ) : continue
  iIIIIIi11Ii = oOoo0O0OO00O0 . split ( " " )
  try :
   O0oO = iIIIIIi11Ii . index ( "via" ) + 1
   if ( O0oO >= len ( iIIIIIi11Ii ) ) : continue
   iIIiii1iII1iII11i1 = iIIIIIi11Ii . index ( "dev" ) + 1
   if ( iIIiii1iII1iII11i1 >= len ( iIIIIIi11Ii ) ) : continue
  except :
   continue
   if 23 - 23: OOooOOo % Oo0Ooo . iII111i
   if 53 - 53: OoO0O00 - OoooooooOO
  O0O0Oo . append ( [ iIIIIIi11Ii [ iIIiii1iII1iII11i1 ] , iIIIIIi11Ii [ O0oO ] ] )
  if 81 - 81: i1IIi / I1ii11iIi11i - OoOoOO00 + I1Ii111
 return ( O0O0Oo )
 if 21 - 21: OoooooooOO
 if 63 - 63: I1IiiI / o0oOOo0O0Ooo - I1Ii111
 if 49 - 49: iII111i . OoOoOO00
 if 91 - 91: OOooOOo / Ii1I / IiII * OOooOOo
 if 68 - 68: I11i
 if 91 - 91: I11i
 if 24 - 24: ooOoO0o . i1IIi - O0 + I11i
def lisp_get_host_route_next_hop ( rloc ) :
 o00OoOO0O0 = "ip route | egrep '{} via'" . format ( rloc )
 oOoo0O0OO00O0 = commands . getoutput ( o00OoOO0O0 ) . split ( " " )
 if 71 - 71: OoOoOO00
 try : iI11I = oOoo0O0OO00O0 . index ( "via" ) + 1
 except : return ( None )
 if 29 - 29: O0 . i11iIiiIii
 if ( iI11I >= len ( oOoo0O0OO00O0 ) ) : return ( None )
 return ( oOoo0O0OO00O0 [ iI11I ] )
 if 51 - 51: IiII
 if 53 - 53: O0
 if 19 - 19: o0oOOo0O0Ooo / iII111i % OoOoOO00
 if 65 - 65: o0oOOo0O0Ooo
 if 89 - 89: iIii1I11I1II1 + OoooooooOO + i1IIi + OoooooooOO % IiII * OoO0O00
 if 53 - 53: OOooOOo . IiII % I11i - OoO0O00 - Oo0Ooo
 if 58 - 58: I1Ii111 / OoooooooOO . I11i % I1Ii111
def lisp_install_host_route ( dest , nh , install ) :
 install = "add" if install else "delete"
 oo0o00Oo00o0 = "none" if nh == None else nh
 if 8 - 8: Oo0Ooo % ooOoO0o / i11iIiiIii
 lprint ( "{} host-route {}, nh {}" . format ( install . title ( ) , dest , oo0o00Oo00o0 ) )
 if 54 - 54: IiII
 if ( nh == None ) :
  OO0OOo00O = "ip route {} {}/32" . format ( install , dest )
 else :
  OO0OOo00O = "ip route {} {}/32 via {}" . format ( install , dest , nh )
  if 85 - 85: OOooOOo - i1IIi
 os . system ( OO0OOo00O )
 return
 if 10 - 10: I1ii11iIi11i
 if 3 - 3: ooOoO0o * O0 / o0oOOo0O0Ooo
 if 22 - 22: OoOoOO00 + OOooOOo . iII111i % iIii1I11I1II1 - I11i
 if 23 - 23: OoOoOO00 * I1Ii111
 if 18 - 18: o0oOOo0O0Ooo % i11iIiiIii . Ii1I . O0
 if 85 - 85: I1ii11iIi11i * iIii1I11I1II1 + o0oOOo0O0Ooo * OoO0O00
 if 25 - 25: o0oOOo0O0Ooo / Ii1I / Oo0Ooo . ooOoO0o - ooOoO0o * O0
 if 14 - 14: O0 - Ii1I + iIii1I11I1II1 + II111iiii . ooOoO0o + Ii1I
def lisp_checkpoint ( checkpoint_list ) :
 if ( lisp_checkpoint_map_cache == False ) : return
 if 25 - 25: OoO0O00 * oO0o
 Oo0OO0o0oOO0 = open ( lisp_checkpoint_filename , "w" )
 for iIIiI11iI1Ii1 in checkpoint_list :
  Oo0OO0o0oOO0 . write ( iIIiI11iI1Ii1 + "\n" )
  if 29 - 29: OOooOOo - I1Ii111 - i11iIiiIii % i1IIi
 Oo0OO0o0oOO0 . close ( )
 lprint ( "{} {} entries to file '{}'" . format ( bold ( "Checkpoint" , False ) ,
 len ( checkpoint_list ) , lisp_checkpoint_filename ) )
 return
 if 2 - 2: i11iIiiIii % iIii1I11I1II1 * OOooOOo
 if 45 - 45: oO0o + i1IIi + iII111i + o0oOOo0O0Ooo * OOooOOo + ooOoO0o
 if 83 - 83: OoO0O00 - ooOoO0o / OoooooooOO % iIii1I11I1II1 - II111iiii
 if 73 - 73: Oo0Ooo + II111iiii - IiII
 if 60 - 60: i1IIi . i11iIiiIii / i1IIi . I11i % OOooOOo
 if 47 - 47: oO0o + IiII * I1Ii111 % o0oOOo0O0Ooo - O0 % IiII
 if 66 - 66: II111iiii * I1IiiI . Oo0Ooo * OoooooooOO % OoOoOO00 . II111iiii
 if 4 - 4: iII111i + I1Ii111 % OoOoOO00 / Ii1I
def lisp_load_checkpoint ( ) :
 if ( lisp_checkpoint_map_cache == False ) : return
 if ( os . path . exists ( lisp_checkpoint_filename ) == False ) : return
 if 94 - 94: OoO0O00
 Oo0OO0o0oOO0 = open ( lisp_checkpoint_filename , "r" )
 if 35 - 35: I1ii11iIi11i % OoO0O00 + II111iiii % II111iiii / IiII - iII111i
 I1I11Iiii111 = 0
 for iIIiI11iI1Ii1 in Oo0OO0o0oOO0 :
  I1I11Iiii111 += 1
  ooo0OO = iIIiI11iI1Ii1 . split ( " rloc " )
  Ii11iiI = [ ] if ( ooo0OO [ 1 ] in [ "native-forward\n" , "\n" ] ) else ooo0OO [ 1 ] . split ( ", " )
  if 9 - 9: I1ii11iIi11i * o0oOOo0O0Ooo . oO0o
  if 48 - 48: IiII . I1Ii111 + OoooooooOO - I1Ii111 . Ii1I . I1Ii111
  oooo0O = [ ]
  for OoOOo in Ii11iiI :
   IiI1I1iii11 = lisp_rloc ( False )
   iIIIIIi11Ii = OoOOo . split ( " " )
   IiI1I1iii11 . rloc . store_address ( iIIIIIi11Ii [ 0 ] )
   IiI1I1iii11 . priority = int ( iIIIIIi11Ii [ 1 ] )
   IiI1I1iii11 . weight = int ( iIIIIIi11Ii [ 2 ] )
   oooo0O . append ( IiI1I1iii11 )
   if 24 - 24: ooOoO0o * iIii1I11I1II1
   if 1 - 1: I1ii11iIi11i . O0
  IIII = lisp_mapping ( "" , "" , oooo0O )
  if ( IIII != None ) :
   IIII . eid . store_prefix ( ooo0OO [ 0 ] )
   IIII . checkpoint_entry = True
   IIII . map_cache_ttl = LISP_NMR_TTL * 60
   if ( oooo0O == [ ] ) : IIII . action = LISP_NATIVE_FORWARD_ACTION
   IIII . add_cache ( )
   continue
   if 3 - 3: iIii1I11I1II1 * ooOoO0o - OoOoOO00 * I1ii11iIi11i % OoOoOO00 - OoooooooOO
   if 42 - 42: I1Ii111 - i1IIi
  I1I11Iiii111 -= 1
  if 91 - 91: iII111i . OOooOOo / iIii1I11I1II1 . Oo0Ooo . II111iiii . OoOoOO00
  if 31 - 31: OoO0O00 . I1ii11iIi11i % I11i - II111iiii
 Oo0OO0o0oOO0 . close ( )
 lprint ( "{} {} map-cache entries from file '{}'" . format (
 bold ( "Loaded" , False ) , I1I11Iiii111 , lisp_checkpoint_filename ) )
 return
 if 70 - 70: ooOoO0o - IiII - OoO0O00 / I11i
 if 59 - 59: IiII % ooOoO0o . iII111i / Ii1I * Ii1I
 if 73 - 73: I1ii11iIi11i . oO0o % I11i . I1ii11iIi11i / I1Ii111 / II111iiii
 if 23 - 23: OoooooooOO . o0oOOo0O0Ooo
 if 76 - 76: I1Ii111
 if 91 - 91: iIii1I11I1II1 / Ii1I . I1IiiI
 if 63 - 63: ooOoO0o . Ii1I - I1Ii111 - oO0o * I1Ii111 + ooOoO0o
 if 85 - 85: II111iiii + I1ii11iIi11i
 if 33 - 33: iII111i
 if 14 - 14: O0 * Oo0Ooo / i1IIi
 if 95 - 95: O0 % i1IIi % ooOoO0o % oO0o - I1IiiI
 if 78 - 78: II111iiii % OOooOOo
 if 6 - 6: OOooOOo
 if 21 - 21: I1Ii111 - Ii1I - i1IIi % oO0o
def lisp_write_checkpoint_entry ( checkpoint_list , mc ) :
 if ( lisp_checkpoint_map_cache == False ) : return
 if 55 - 55: OOooOOo + oO0o - II111iiii
 iIIiI11iI1Ii1 = "{} rloc " . format ( mc . eid . print_prefix ( ) )
 if 5 - 5: iII111i * OoooooooOO . OoO0O00 % ooOoO0o + Ii1I
 for IiI1I1iii11 in mc . rloc_set :
  if ( IiI1I1iii11 . rloc . is_null ( ) ) : continue
  iIIiI11iI1Ii1 += "{} {} {}, " . format ( IiI1I1iii11 . rloc . print_address_no_iid ( ) ,
 IiI1I1iii11 . priority , IiI1I1iii11 . weight )
  if 59 - 59: OoOoOO00
  if 96 - 96: I1IiiI
 if ( mc . rloc_set != [ ] ) :
  iIIiI11iI1Ii1 = iIIiI11iI1Ii1 [ 0 : - 2 ]
 elif ( mc . action == LISP_NATIVE_FORWARD_ACTION ) :
  iIIiI11iI1Ii1 += "native-forward"
  if 3 - 3: OoooooooOO
  if 3 - 3: IiII / O0 * i11iIiiIii . iII111i - iIii1I11I1II1
 checkpoint_list . append ( iIIiI11iI1Ii1 )
 return
 if 56 - 56: ooOoO0o
 if 82 - 82: ooOoO0o . IiII . I1Ii111 - iIii1I11I1II1 + II111iiii . OoOoOO00
 if 59 - 59: Oo0Ooo
 if 98 - 98: I1Ii111 * II111iiii / Oo0Ooo . Oo0Ooo % I1Ii111
 if 52 - 52: OoOoOO00
 if 59 - 59: ooOoO0o / OoooooooOO
 if 71 - 71: OOooOOo + I11i * O0 / o0oOOo0O0Ooo + I1IiiI + Ii1I
def lisp_check_dp_socket ( ) :
 i11IiIIIi11i = lisp_ipc_dp_socket_name
 if ( os . path . exists ( i11IiIIIi11i ) == False ) :
  iiiiII11Ii1 = bold ( "does not exist" , False )
  lprint ( "Socket '{}' {}" . format ( i11IiIIIi11i , iiiiII11Ii1 ) )
  return ( False )
  if 2 - 2: I1Ii111 * oO0o
 return ( True )
 if 93 - 93: I11i
 if 2 - 2: i1IIi / I1IiiI
 if 29 - 29: Ii1I * iIii1I11I1II1 * i1IIi
 if 83 - 83: oO0o % O0 . I11i / I11i / I1IiiI - OoOoOO00
 if 91 - 91: iIii1I11I1II1 - IiII + iIii1I11I1II1 % Oo0Ooo % I1IiiI
 if 84 - 84: iIii1I11I1II1 . Oo0Ooo - OoooooooOO % Oo0Ooo
 if 27 - 27: I1ii11iIi11i - ooOoO0o + I11i - I1ii11iIi11i
def lisp_write_to_dp_socket ( entry ) :
 try :
  oo00Oo = json . dumps ( entry )
  oooo00O000 = bold ( "Write IPC" , False )
  lprint ( "{} record to named socket: '{}'" . format ( oooo00O000 , oo00Oo ) )
  lisp_ipc_dp_socket . sendto ( oo00Oo , lisp_ipc_dp_socket_name )
 except :
  lprint ( "Failed to write IPC record to named socket: '{}'" . format ( oo00Oo ) )
  if 14 - 14: iII111i + Ii1I - IiII / OoO0O00
 return
 if 4 - 4: o0oOOo0O0Ooo + o0oOOo0O0Ooo - Oo0Ooo
 if 87 - 87: II111iiii + iII111i / I1Ii111 - I11i
 if 90 - 90: Ii1I + Ii1I . O0 - I1ii11iIi11i
 if 40 - 40: OoooooooOO
 if 100 - 100: IiII - I11i
 if 79 - 79: iII111i % O0
 if 73 - 73: Oo0Ooo
 if 13 - 13: OOooOOo - ooOoO0o
 if 8 - 8: I1Ii111 % oO0o
def lisp_write_ipc_keys ( rloc ) :
 I1iiIiiii1111 = rloc . rloc . print_address_no_iid ( )
 IIiII = rloc . translated_port
 if ( IIiII != 0 ) : I1iiIiiii1111 += ":" + str ( IIiII )
 if ( lisp_rloc_probe_list . has_key ( I1iiIiiii1111 ) == False ) : return
 if 19 - 19: O0 + OoO0O00 - i1IIi % OoOoOO00 / Oo0Ooo + OoooooooOO
 for iIIIIIi11Ii , ooo0OO , O0ooO0oOO in lisp_rloc_probe_list [ I1iiIiiii1111 ] :
  IIII = lisp_map_cache . lookup_cache ( ooo0OO , True )
  if ( IIII == None ) : continue
  lisp_write_ipc_map_cache ( True , IIII )
  if 93 - 93: i11iIiiIii % OOooOOo . I11i * ooOoO0o
 return
 if 90 - 90: OoO0O00
 if 54 - 54: OOooOOo + Oo0Ooo * o0oOOo0O0Ooo - iIii1I11I1II1 * ooOoO0o
 if 76 - 76: i11iIiiIii * I1IiiI - IiII . o0oOOo0O0Ooo % iII111i . i11iIiiIii
 if 69 - 69: O0 + o0oOOo0O0Ooo / ooOoO0o
 if 7 - 7: Ii1I . Ii1I . iIii1I11I1II1 / ooOoO0o
 if 70 - 70: O0
 if 42 - 42: I1Ii111 + OoooooooOO + I11i
def lisp_write_ipc_map_cache ( add_or_delete , mc , dont_send = False ) :
 if ( lisp_i_am_etr ) : return
 if ( lisp_ipc_dp_socket == None ) : return
 if ( lisp_check_dp_socket ( ) == False ) : return
 if 48 - 48: Oo0Ooo . IiII / ooOoO0o + I11i
 if 40 - 40: I1IiiI + I1ii11iIi11i * I1IiiI % Ii1I
 if 27 - 27: O0 / Oo0Ooo . oO0o
 if 34 - 34: I1Ii111 % Ii1I / Oo0Ooo % ooOoO0o / i11iIiiIii * I1IiiI
 Oo = "add" if add_or_delete else "delete"
 iIIiI11iI1Ii1 = { "type" : "map-cache" , "opcode" : Oo }
 if 36 - 36: i11iIiiIii * i1IIi % iII111i . Oo0Ooo
 iIiiIiI1I1ii = ( mc . group . is_null ( ) == False )
 if ( iIiiIiI1I1ii ) :
  iIIiI11iI1Ii1 [ "eid-prefix" ] = mc . group . print_prefix_no_iid ( )
  iIIiI11iI1Ii1 [ "rles" ] = [ ]
 else :
  iIIiI11iI1Ii1 [ "eid-prefix" ] = mc . eid . print_prefix_no_iid ( )
  iIIiI11iI1Ii1 [ "rlocs" ] = [ ]
  if 54 - 54: o0oOOo0O0Ooo % i1IIi % I1ii11iIi11i . o0oOOo0O0Ooo / OoOoOO00
 iIIiI11iI1Ii1 [ "instance-id" ] = str ( mc . eid . instance_id )
 if 55 - 55: O0 / OoooooooOO % Ii1I * O0 + iIii1I11I1II1 . iIii1I11I1II1
 if ( iIiiIiI1I1ii ) :
  if ( len ( mc . rloc_set ) >= 1 and mc . rloc_set [ 0 ] . rle ) :
   for IIi1i1111i in mc . rloc_set [ 0 ] . rle . rle_forwarding_list :
    o0o0O00 = IIi1i1111i . address . print_address_no_iid ( )
    IIiII = str ( 4341 ) if IIi1i1111i . translated_port == 0 else str ( IIi1i1111i . translated_port )
    if 55 - 55: Ii1I . OoooooooOO % Ii1I . IiII
    iIIIIIi11Ii = { "rle" : o0o0O00 , "port" : IIiII }
    Iiio0oO , oooOoooOO = IIi1i1111i . get_encap_keys ( )
    iIIIIIi11Ii = lisp_build_json_keys ( iIIIIIi11Ii , Iiio0oO , oooOoooOO , "encrypt-key" )
    iIIiI11iI1Ii1 [ "rles" ] . append ( iIIIIIi11Ii )
    if 12 - 12: I1IiiI
    if 50 - 50: ooOoO0o
 else :
  for OoOOo in mc . rloc_set :
   if ( OoOOo . rloc . is_ipv4 ( ) == False and OoOOo . rloc . is_ipv6 ( ) == False ) :
    continue
    if 19 - 19: OoooooooOO / IiII
   if ( OoOOo . up_state ( ) == False ) : continue
   if 40 - 40: OoOoOO00 / OoooooooOO * iIii1I11I1II1 / i1IIi . OoooooooOO
   IIiII = str ( 4341 ) if OoOOo . translated_port == 0 else str ( OoOOo . translated_port )
   if 88 - 88: I1IiiI % I1IiiI / II111iiii - IiII
   iIIIIIi11Ii = { "rloc" : OoOOo . rloc . print_address_no_iid ( ) , "priority" :
 str ( OoOOo . priority ) , "weight" : str ( OoOOo . weight ) , "port" :
 IIiII }
   Iiio0oO , oooOoooOO = OoOOo . get_encap_keys ( )
   iIIIIIi11Ii = lisp_build_json_keys ( iIIIIIi11Ii , Iiio0oO , oooOoooOO , "encrypt-key" )
   iIIiI11iI1Ii1 [ "rlocs" ] . append ( iIIIIIi11Ii )
   if 72 - 72: OoO0O00 - I1ii11iIi11i . Oo0Ooo / OoO0O00
   if 86 - 86: i11iIiiIii - oO0o . i11iIiiIii
   if 51 - 51: OoO0O00 - OoO0O00 * IiII
 if ( dont_send == False ) : lisp_write_to_dp_socket ( iIIiI11iI1Ii1 )
 return ( iIIiI11iI1Ii1 )
 if 24 - 24: OoooooooOO . II111iiii
 if 97 - 97: II111iiii . O0
 if 18 - 18: iII111i
 if 35 - 35: ooOoO0o / O0 / iIii1I11I1II1 - iIii1I11I1II1 + I11i
 if 8 - 8: I1Ii111 . oO0o % Oo0Ooo * OoooooooOO
 if 25 - 25: OoO0O00
 if 54 - 54: O0
def lisp_write_ipc_decap_key ( rloc_addr , keys ) :
 if ( lisp_i_am_itr ) : return
 if ( lisp_ipc_dp_socket == None ) : return
 if ( lisp_check_dp_socket ( ) == False ) : return
 if 20 - 20: ooOoO0o + Oo0Ooo - Oo0Ooo
 if 2 - 2: i1IIi - IiII . I1ii11iIi11i / i1IIi
 if 92 - 92: ooOoO0o - iII111i
 if 69 - 69: iII111i
 if ( keys == None or len ( keys ) == 0 or keys [ 1 ] == None ) : return
 if 48 - 48: O0 + o0oOOo0O0Ooo . oO0o - IiII * OoooooooOO . OoO0O00
 Iiio0oO = keys [ 1 ] . encrypt_key
 oooOoooOO = keys [ 1 ] . icv_key
 if 63 - 63: oO0o * OoO0O00 * oO0o
 if 31 - 31: Oo0Ooo
 if 90 - 90: I11i . IiII * iIii1I11I1II1 . I11i + i1IIi
 if 67 - 67: I1Ii111 . I1ii11iIi11i
 ii11ii1 = rloc_addr . split ( ":" )
 if ( len ( ii11ii1 ) == 1 ) :
  iIIiI11iI1Ii1 = { "type" : "decap-keys" , "rloc" : ii11ii1 [ 0 ] }
 else :
  iIIiI11iI1Ii1 = { "type" : "decap-keys" , "rloc" : ii11ii1 [ 0 ] , "port" : ii11ii1 [ 1 ] }
  if 81 - 81: II111iiii
 iIIiI11iI1Ii1 = lisp_build_json_keys ( iIIiI11iI1Ii1 , Iiio0oO , oooOoooOO , "decrypt-key" )
 if 34 - 34: o0oOOo0O0Ooo % I1ii11iIi11i + i11iIiiIii - Ii1I / I1ii11iIi11i
 lisp_write_to_dp_socket ( iIIiI11iI1Ii1 )
 return
 if 17 - 17: I1ii11iIi11i + Ii1I * I1Ii111
 if 98 - 98: OoOoOO00 . I1ii11iIi11i + oO0o
 if 95 - 95: O0 + II111iiii / Ii1I % IiII . OoOoOO00
 if 85 - 85: Ii1I * Oo0Ooo * ooOoO0o
 if 48 - 48: i11iIiiIii
 if 45 - 45: i1IIi + I1ii11iIi11i
 if 49 - 49: i11iIiiIii . I1ii11iIi11i
 if 91 - 91: ooOoO0o - OOooOOo - OOooOOo * o0oOOo0O0Ooo
def lisp_build_json_keys ( entry , ekey , ikey , key_type ) :
 if ( ekey == None ) : return ( entry )
 if 33 - 33: II111iiii
 entry [ "keys" ] = [ ]
 iii11 = { "key-id" : "1" , key_type : ekey , "icv-key" : ikey }
 entry [ "keys" ] . append ( iii11 )
 return ( entry )
 if 39 - 39: ooOoO0o + I11i
 if 24 - 24: o0oOOo0O0Ooo
 if 5 - 5: i11iIiiIii - oO0o + o0oOOo0O0Ooo % ooOoO0o
 if 63 - 63: oO0o
 if 7 - 7: IiII / i11iIiiIii - OOooOOo
 if 9 - 9: II111iiii + i11iIiiIii % I1Ii111 - Oo0Ooo * OOooOOo
 if 55 - 55: I1Ii111 + ooOoO0o
def lisp_write_ipc_database_mappings ( ephem_port ) :
 if ( lisp_i_am_etr == False ) : return
 if ( lisp_ipc_dp_socket == None ) : return
 if ( lisp_check_dp_socket ( ) == False ) : return
 if 58 - 58: iII111i . I1ii11iIi11i - Oo0Ooo % o0oOOo0O0Ooo + I1Ii111
 if 58 - 58: oO0o . ooOoO0o . I1IiiI . Oo0Ooo * iIii1I11I1II1 - iII111i
 if 96 - 96: OOooOOo % o0oOOo0O0Ooo / iIii1I11I1II1
 if 60 - 60: i1IIi / iIii1I11I1II1 + I11i % iII111i
 iIIiI11iI1Ii1 = { "type" : "database-mappings" , "database-mappings" : [ ] }
 if 64 - 64: I11i . i11iIiiIii / iIii1I11I1II1 . I11i
 if 73 - 73: OoO0O00 % iIii1I11I1II1 + IiII * I1Ii111 % II111iiii
 if 20 - 20: I11i % I1ii11iIi11i . OoO0O00 % OoOoOO00
 if 84 - 84: OoooooooOO / i11iIiiIii . IiII / I1IiiI
 for I111I in lisp_db_list :
  if ( I111I . eid . is_ipv4 ( ) == False and I111I . eid . is_ipv6 ( ) == False ) : continue
  o0OooO0O = { "instance-id" : str ( I111I . eid . instance_id ) ,
 "eid-prefix" : I111I . eid . print_prefix_no_iid ( ) }
  iIIiI11iI1Ii1 [ "database-mappings" ] . append ( o0OooO0O )
  if 15 - 15: O0 . iIii1I11I1II1 - I1Ii111 + O0 + ooOoO0o / I1IiiI
 lisp_write_to_dp_socket ( iIIiI11iI1Ii1 )
 if 8 - 8: iII111i % O0 - OoOoOO00
 if 49 - 49: oO0o - OOooOOo / Ii1I / I1Ii111 . o0oOOo0O0Ooo . iII111i
 if 58 - 58: IiII + Ii1I
 if 89 - 89: Ii1I / Oo0Ooo * o0oOOo0O0Ooo / OoO0O00 + I11i
 if 4 - 4: I11i
 iIIiI11iI1Ii1 = { "type" : "etr-nat-port" , "port" : ephem_port }
 lisp_write_to_dp_socket ( iIIiI11iI1Ii1 )
 return
 if 59 - 59: OoOoOO00 * I1ii11iIi11i / I1IiiI * II111iiii + OoOoOO00
 if 6 - 6: OoOoOO00 % oO0o + I11i * Ii1I
 if 13 - 13: I1ii11iIi11i / Oo0Ooo - I1Ii111 * OoOoOO00
 if 47 - 47: IiII
 if 76 - 76: iII111i / II111iiii / I11i
 if 62 - 62: I1ii11iIi11i
 if 100 - 100: iII111i / ooOoO0o / IiII % II111iiii
def lisp_write_ipc_interfaces ( ) :
 if ( lisp_i_am_etr ) : return
 if ( lisp_ipc_dp_socket == None ) : return
 if ( lisp_check_dp_socket ( ) == False ) : return
 if 6 - 6: OoooooooOO - I1IiiI + OoooooooOO
 if 89 - 89: oO0o % Oo0Ooo . O0 . ooOoO0o
 if 46 - 46: IiII * I11i - OoO0O00 - Ii1I
 if 93 - 93: iIii1I11I1II1 / o0oOOo0O0Ooo - I11i - OOooOOo % ooOoO0o
 iIIiI11iI1Ii1 = { "type" : "interfaces" , "interfaces" : [ ] }
 if 16 - 16: ooOoO0o * o0oOOo0O0Ooo - IiII + I1ii11iIi11i / o0oOOo0O0Ooo - O0
 for I111IIiIII in lisp_myinterfaces . values ( ) :
  if ( I111IIiIII . instance_id == None ) : continue
  o0OooO0O = { "interface" : I111IIiIII . device ,
 "instance-id" : str ( I111IIiIII . instance_id ) }
  iIIiI11iI1Ii1 [ "interfaces" ] . append ( o0OooO0O )
  if 71 - 71: i1IIi
  if 79 - 79: iII111i * O0 / Ii1I / O0 % i1IIi
 lisp_write_to_dp_socket ( iIIiI11iI1Ii1 )
 return
 if 52 - 52: OoooooooOO % oO0o - I11i % OoOoOO00 . II111iiii
 if 62 - 62: Ii1I . I1ii11iIi11i . iII111i + I11i * o0oOOo0O0Ooo
 if 56 - 56: oO0o * iIii1I11I1II1 . II111iiii - II111iiii + II111iiii - i11iIiiIii
 if 79 - 79: iII111i
 if 29 - 29: Ii1I * I1Ii111 / OoO0O00 - O0 - i11iIiiIii * I1IiiI
 if 2 - 2: OoOoOO00 . I1ii11iIi11i * I1ii11iIi11i
 if 42 - 42: OoO0O00 . OoO0O00 + II111iiii - IiII - OOooOOo * Oo0Ooo
 if 47 - 47: oO0o - OoooooooOO + iII111i
 if 69 - 69: I1ii11iIi11i - I1IiiI % oO0o + OOooOOo - I1Ii111
 if 5 - 5: ooOoO0o . OoO0O00
 if 40 - 40: iII111i
 if 87 - 87: IiII / II111iiii
 if 44 - 44: OoO0O00 . I1Ii111 - OoooooooOO * OoOoOO00 . OoO0O00
 if 84 - 84: OOooOOo . OOooOOo . oO0o % iII111i * Oo0Ooo - iIii1I11I1II1
def lisp_parse_auth_key ( value ) :
 oOiiIiIIIi11 = value . split ( "[" )
 ii1iiiiiIiIi = { }
 if ( len ( oOiiIiIIIi11 ) == 1 ) :
  ii1iiiiiIiIi [ 0 ] = value
  return ( ii1iiiiiIiIi )
  if 83 - 83: Ii1I - Ii1I + IiII + I11i / I1Ii111 % iIii1I11I1II1
  if 17 - 17: I1ii11iIi11i * OOooOOo % II111iiii
 for Ii1II1ii in oOiiIiIIIi11 :
  if ( Ii1II1ii == "" ) : continue
  iI11I = Ii1II1ii . find ( "]" )
  I1o0 = Ii1II1ii [ 0 : iI11I ]
  try : I1o0 = int ( I1o0 )
  except : return
  if 30 - 30: I1Ii111 . Ii1I . Oo0Ooo / OOooOOo * OoooooooOO / I1ii11iIi11i
  ii1iiiiiIiIi [ I1o0 ] = Ii1II1ii [ iI11I + 1 : : ]
  if 41 - 41: i1IIi
 return ( ii1iiiiiIiIi )
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
 if 78 - 78: iII111i - OOooOOo / I1Ii111
 if 38 - 38: I11i % i1IIi + o0oOOo0O0Ooo + I1ii11iIi11i + I1IiiI
def lisp_reassemble ( packet ) :
 oO = socket . ntohs ( struct . unpack ( "H" , packet [ 6 : 8 ] ) [ 0 ] )
 if 1 - 1: II111iiii * o0oOOo0O0Ooo . O0 - Ii1I / oO0o
 if 17 - 17: OoooooooOO % OoooooooOO + Oo0Ooo + I1Ii111
 if 56 - 56: I11i % OoOoOO00 - OoO0O00
 if 31 - 31: iII111i % i11iIiiIii - Ii1I / OOooOOo - I1Ii111
 if ( oO == 0 or oO == 0x4000 ) : return ( packet )
 if 60 - 60: o0oOOo0O0Ooo + Oo0Ooo . O0
 if 51 - 51: i11iIiiIii / iIii1I11I1II1 . I1IiiI - Ii1I * I1Ii111 . iII111i
 if 72 - 72: Ii1I . I11i / i1IIi % i1IIi + I1ii11iIi11i
 if 56 - 56: OoO0O00 - OoOoOO00 - II111iiii * o0oOOo0O0Ooo
 i1i1i11iI11II = socket . ntohs ( struct . unpack ( "H" , packet [ 4 : 6 ] ) [ 0 ] )
 O00o0ooo0OO0 = socket . ntohs ( struct . unpack ( "H" , packet [ 2 : 4 ] ) [ 0 ] )
 if 42 - 42: Ii1I
 I1i1I = ( oO & 0x2000 == 0 and ( oO & 0x1fff ) != 0 )
 iIIiI11iI1Ii1 = [ ( oO & 0x1fff ) * 8 , O00o0ooo0OO0 - 20 , packet , I1i1I ]
 if 39 - 39: oO0o / i11iIiiIii % oO0o + oO0o
 if 96 - 96: i1IIi * OoO0O00
 if 89 - 89: O0 * OoOoOO00 * i11iIiiIii . iII111i
 if 28 - 28: ooOoO0o % i1IIi % I1ii11iIi11i
 if 58 - 58: I1IiiI
 if 100 - 100: I11i % ooOoO0o - OOooOOo - I1IiiI * oO0o + I1IiiI
 if 7 - 7: iIii1I11I1II1 * o0oOOo0O0Ooo / I1Ii111 % Oo0Ooo + OoO0O00 % OOooOOo
 if 85 - 85: I1IiiI . i11iIiiIii - ooOoO0o * I11i * OoOoOO00 * I11i
 if ( oO == 0x2000 ) :
  oOO0ooi1iiIIiII1 , o0O00OooooO = struct . unpack ( "HH" , packet [ 20 : 24 ] )
  oOO0ooi1iiIIiII1 = socket . ntohs ( oOO0ooi1iiIIiII1 )
  o0O00OooooO = socket . ntohs ( o0O00OooooO )
  if ( o0O00OooooO not in [ 4341 , 8472 , 4789 ] and oOO0ooi1iiIIiII1 != 4341 ) :
   lisp_reassembly_queue [ i1i1i11iI11II ] = [ ]
   iIIiI11iI1Ii1 [ 2 ] = None
   if 29 - 29: I1Ii111 * I1Ii111 . iII111i + o0oOOo0O0Ooo
   if 57 - 57: I1Ii111 - IiII
   if 89 - 89: oO0o + iII111i
   if 52 - 52: OOooOOo % O0 * I1ii11iIi11i . I1ii11iIi11i / IiII
   if 7 - 7: II111iiii
   if 7 - 7: iIii1I11I1II1 . O0 + Ii1I % I1IiiI * O0 + OoO0O00
 if ( lisp_reassembly_queue . has_key ( i1i1i11iI11II ) == False ) :
  lisp_reassembly_queue [ i1i1i11iI11II ] = [ ]
  if 3 - 3: Oo0Ooo * OoooooooOO * oO0o % OoOoOO00 * OoOoOO00 . ooOoO0o
  if 16 - 16: ooOoO0o / o0oOOo0O0Ooo - O0 * I1IiiI
  if 13 - 13: iII111i . iII111i % O0 % o0oOOo0O0Ooo
  if 99 - 99: OoO0O00 - OoOoOO00 + OoO0O00
  if 67 - 67: I1Ii111
 II1I1iIi11i1 = lisp_reassembly_queue [ i1i1i11iI11II ]
 if 14 - 14: Ii1I * I1Ii111 + I1ii11iIi11i % OoO0O00 * Ii1I + iII111i
 if 6 - 6: iII111i / iII111i . i11iIiiIii
 if 12 - 12: I11i - OoO0O00
 if 68 - 68: IiII - OoOoOO00
 if 22 - 22: i1IIi . IiII
 if ( len ( II1I1iIi11i1 ) == 1 and II1I1iIi11i1 [ 0 ] [ 2 ] == None ) :
  dprint ( "Drop non-LISP encapsulated fragment 0x{}" . format ( lisp_hex_string ( i1i1i11iI11II ) . zfill ( 4 ) ) )
  if 8 - 8: IiII % o0oOOo0O0Ooo . i11iIiiIii
  return ( None )
  if 69 - 69: I1Ii111 / Ii1I - ooOoO0o
  if 38 - 38: II111iiii % OoooooooOO / OoooooooOO . Ii1I . Ii1I
  if 13 - 13: oO0o - i1IIi / i1IIi + OoooooooOO
  if 57 - 57: OoooooooOO / O0 + I1ii11iIi11i % I11i * oO0o / Ii1I
  if 49 - 49: I1IiiI * ooOoO0o * OOooOOo + OoO0O00 + ooOoO0o
 II1I1iIi11i1 . append ( iIIiI11iI1Ii1 )
 II1I1iIi11i1 = sorted ( II1I1iIi11i1 )
 if 42 - 42: i1IIi . OoO0O00 % iII111i
 if 57 - 57: I1ii11iIi11i / I1IiiI
 if 69 - 69: iII111i - iII111i . OoO0O00 / oO0o - OoO0O00 + I1Ii111
 if 98 - 98: iII111i . oO0o - O0 % I1IiiI . I1ii11iIi11i / i1IIi
 o0o0O00 = lisp_address ( LISP_AFI_IPV4 , "" , 32 , 0 )
 o0o0O00 . address = socket . ntohl ( struct . unpack ( "I" , packet [ 12 : 16 ] ) [ 0 ] )
 Oo0OOo0oo = o0o0O00 . print_address_no_iid ( )
 o0o0O00 . address = socket . ntohl ( struct . unpack ( "I" , packet [ 16 : 20 ] ) [ 0 ] )
 ooO0o = o0o0O00 . print_address_no_iid ( )
 o0o0O00 = red ( "{} -> {}" . format ( Oo0OOo0oo , ooO0o ) , False )
 if 42 - 42: Ii1I / i1IIi - IiII / I1Ii111
 dprint ( "{}{} fragment, RLOCs: {}, packet 0x{}, frag-offset: 0x{}" . format ( bold ( "Received" , False ) , " non-LISP encapsulated" if iIIiI11iI1Ii1 [ 2 ] == None else "" , o0o0O00 , lisp_hex_string ( i1i1i11iI11II ) . zfill ( 4 ) ,
 # OoooooooOO . I1Ii111 . o0oOOo0O0Ooo
 # I1IiiI
 lisp_hex_string ( oO ) . zfill ( 4 ) ) )
 if 39 - 39: O0 % o0oOOo0O0Ooo / Oo0Ooo + II111iiii + i11iIiiIii
 if 30 - 30: IiII * Ii1I - O0 - OoOoOO00
 if 1 - 1: OoO0O00 * II111iiii * I11i % ooOoO0o * OoO0O00
 if 92 - 92: O0 . I1IiiI / iIii1I11I1II1
 if 1 - 1: Oo0Ooo + OoO0O00 . oO0o
 if ( II1I1iIi11i1 [ 0 ] [ 0 ] != 0 or II1I1iIi11i1 [ - 1 ] [ 3 ] == False ) : return ( None )
 IIIIi = II1I1iIi11i1 [ 0 ]
 for IiI1IiI1iiI1 in II1I1iIi11i1 [ 1 : : ] :
  oO = IiI1IiI1iiI1 [ 0 ]
  i1Iiiiii , Ii1Iiii1 = IIIIi [ 0 ] , IIIIi [ 1 ]
  if ( i1Iiiiii + Ii1Iiii1 != oO ) : return ( None )
  IIIIi = IiI1IiI1iiI1
  if 81 - 81: I1Ii111 . i1IIi / o0oOOo0O0Ooo
 lisp_reassembly_queue . pop ( i1i1i11iI11II )
 if 30 - 30: i11iIiiIii . I1IiiI
 if 5 - 5: Ii1I / O0 + iIii1I11I1II1
 if 22 - 22: ooOoO0o . ooOoO0o * OOooOOo % OoOoOO00
 if 51 - 51: OoOoOO00 . oO0o - OoOoOO00
 if 79 - 79: iII111i
 packet = II1I1iIi11i1 [ 0 ] [ 2 ]
 for IiI1IiI1iiI1 in II1I1iIi11i1 [ 1 : : ] : packet += IiI1IiI1iiI1 [ 2 ] [ 20 : : ]
 if 71 - 71: i1IIi / OoO0O00 / OOooOOo + I1Ii111
 dprint ( "{} fragments arrived for packet 0x{}, length {}" . format ( bold ( "All" , False ) , lisp_hex_string ( i1i1i11iI11II ) . zfill ( 4 ) , len ( packet ) ) )
 if 80 - 80: Oo0Ooo . iIii1I11I1II1 . OoooooooOO % iII111i . oO0o
 if 10 - 10: i11iIiiIii * OoooooooOO . i11iIiiIii
 if 35 - 35: OOooOOo * OOooOOo + o0oOOo0O0Ooo / i1IIi - I11i
 if 12 - 12: I1ii11iIi11i - i11iIiiIii + I1IiiI . Oo0Ooo
 if 26 - 26: oO0o + I1Ii111 + IiII * o0oOOo0O0Ooo . oO0o
 o00OOo00 = socket . htons ( len ( packet ) )
 iIiI1I1II1 = packet [ 0 : 2 ] + struct . pack ( "H" , o00OOo00 ) + packet [ 4 : 6 ] + struct . pack ( "H" , 0 ) + packet [ 8 : 10 ] + struct . pack ( "H" , 0 ) + packet [ 12 : 20 ]
 if 95 - 95: OoOoOO00 . I1Ii111 / Ii1I . I1Ii111 % OoO0O00
 if 16 - 16: Ii1I / I1IiiI / I1IiiI - OoooooooOO
 iIiI1I1II1 = lisp_ip_checksum ( iIiI1I1II1 )
 return ( iIiI1I1II1 + packet [ 20 : : ] )
 if 13 - 13: OOooOOo / OoooooooOO
 if 7 - 7: II111iiii - ooOoO0o
 if 72 - 72: Ii1I
 if 27 - 27: ooOoO0o / IiII + OoO0O00 + Ii1I % I1Ii111
 if 86 - 86: O0 % i11iIiiIii - Ii1I * oO0o % OOooOOo * i1IIi
 if 87 - 87: II111iiii
 if 53 - 53: OoOoOO00 * i11iIiiIii / I1Ii111
 if 100 - 100: ooOoO0o + I1IiiI * oO0o + ooOoO0o
def lisp_get_crypto_decap_lookup_key ( addr , port ) :
 I1iiIiiii1111 = addr . print_address_no_iid ( ) + ":" + str ( port )
 if ( lisp_crypto_keys_by_rloc_decap . has_key ( I1iiIiiii1111 ) ) : return ( I1iiIiiii1111 )
 if 24 - 24: i11iIiiIii + ooOoO0o
 I1iiIiiii1111 = addr . print_address_no_iid ( )
 if ( lisp_crypto_keys_by_rloc_decap . has_key ( I1iiIiiii1111 ) ) : return ( I1iiIiiii1111 )
 if 80 - 80: IiII % I11i % oO0o
 if 97 - 97: i1IIi * i11iIiiIii / Ii1I - I1IiiI % IiII
 if 70 - 70: iIii1I11I1II1
 if 2 - 2: IiII - i1IIi * IiII % O0 / Ii1I
 if 64 - 64: iII111i - Oo0Ooo
 for oo00O0000o00 in lisp_crypto_keys_by_rloc_decap :
  oOO0oo = oo00O0000o00 . split ( ":" )
  if ( len ( oOO0oo ) == 1 ) : continue
  oOO0oo = oOO0oo [ 0 ] if len ( oOO0oo ) == 2 else ":" . join ( oOO0oo [ 0 : - 1 ] )
  if ( oOO0oo == I1iiIiiii1111 ) :
   o00OO0o0 = lisp_crypto_keys_by_rloc_decap [ oo00O0000o00 ]
   lisp_crypto_keys_by_rloc_decap [ I1iiIiiii1111 ] = o00OO0o0
   return ( I1iiIiiii1111 )
   if 56 - 56: O0 / OoooooooOO / OoOoOO00
   if 19 - 19: o0oOOo0O0Ooo / i11iIiiIii . i1IIi / Oo0Ooo / I1Ii111
 return ( None )
 if 83 - 83: iII111i % o0oOOo0O0Ooo * OoOoOO00
 if 49 - 49: II111iiii / OoO0O00
 if 69 - 69: Ii1I * II111iiii
 if 24 - 24: I1Ii111 * I1ii11iIi11i . OOooOOo . I1IiiI - I1ii11iIi11i
 if 56 - 56: I1IiiI * Oo0Ooo + OoO0O00 - oO0o * I1Ii111
 if 68 - 68: ooOoO0o * i11iIiiIii * OOooOOo % iII111i
 if 10 - 10: Ii1I / Oo0Ooo - i1IIi
 if 11 - 11: I11i * iII111i
 if 28 - 28: II111iiii + IiII / Oo0Ooo * I1IiiI - OOooOOo
 if 2 - 2: oO0o + I11i / I1Ii111 . I11i
 if 59 - 59: Ii1I
def lisp_build_crypto_decap_lookup_key ( addr , port ) :
 addr = addr . print_address_no_iid ( )
 i1111iIiI1 = addr + ":" + str ( port )
 if 17 - 17: oO0o / i1IIi
 if ( lisp_i_am_rtr ) :
  if ( lisp_rloc_probe_list . has_key ( addr ) ) : return ( addr )
  if 94 - 94: Oo0Ooo * O0 - o0oOOo0O0Ooo
  if 31 - 31: i11iIiiIii + I11i . I11i / I11i
  if 67 - 67: Oo0Ooo + Oo0Ooo . i11iIiiIii / IiII
  if 53 - 53: I1ii11iIi11i
  if 85 - 85: iIii1I11I1II1 - II111iiii + Ii1I
  if 3 - 3: ooOoO0o - I1Ii111
  for Iii111I in lisp_nat_state_info . values ( ) :
   for oOooo0o in Iii111I :
    if ( addr == oOooo0o . address ) : return ( i1111iIiI1 )
    if 97 - 97: OOooOOo
    if 87 - 87: iII111i
  return ( addr )
  if 73 - 73: II111iiii
 return ( i1111iIiI1 )
 if 2 - 2: i1IIi % iII111i . oO0o / II111iiii * I1IiiI
 if 17 - 17: O0 + iII111i + oO0o / iIii1I11I1II1 % oO0o
 if 81 - 81: iII111i * i11iIiiIii % O0 / iIii1I11I1II1 . OoO0O00
 if 24 - 24: I1ii11iIi11i + OoOoOO00 % ooOoO0o % I1IiiI * I1Ii111 - o0oOOo0O0Ooo
 if 95 - 95: Oo0Ooo * IiII - I1IiiI
 if 37 - 37: Oo0Ooo - oO0o / I1ii11iIi11i . o0oOOo0O0Ooo * Ii1I
 if 95 - 95: i11iIiiIii - ooOoO0o / I11i / I1Ii111
def lisp_set_ttl ( lisp_socket , ttl ) :
 try :
  lisp_socket . setsockopt ( socket . SOL_IP , socket . IP_TTL , ttl )
 except :
  lprint ( "socket.setsockopt(IP_TTL) not supported" )
  pass
  if 59 - 59: iII111i
 return
 if 59 - 59: Oo0Ooo - IiII
 if 6 - 6: OOooOOo - I1IiiI . IiII
 if 40 - 40: II111iiii
 if 13 - 13: OoOoOO00
 if 23 - 23: Oo0Ooo / II111iiii % OOooOOo % iII111i - Oo0Ooo / OoO0O00
 if 7 - 7: Ii1I / I11i / II111iiii % I11i * I11i + iIii1I11I1II1
 if 6 - 6: iIii1I11I1II1 * oO0o - iIii1I11I1II1 . O0 . O0
def lisp_is_rloc_probe_request ( lisp_type ) :
 lisp_type = struct . unpack ( "B" , lisp_type ) [ 0 ]
 return ( lisp_type == 0x12 )
 if 96 - 96: I1Ii111 * II111iiii % i11iIiiIii - oO0o
 if 32 - 32: i11iIiiIii * o0oOOo0O0Ooo . OoooooooOO / O0
 if 14 - 14: i11iIiiIii . I1Ii111 % I1ii11iIi11i . I1ii11iIi11i % IiII
 if 93 - 93: iIii1I11I1II1 / IiII
 if 91 - 91: i11iIiiIii % ooOoO0o - iII111i * I1Ii111 . i11iIiiIii
 if 1 - 1: IiII + iIii1I11I1II1 * I1ii11iIi11i - IiII - i1IIi
 if 75 - 75: II111iiii * o0oOOo0O0Ooo / I1ii11iIi11i
def lisp_is_rloc_probe_reply ( lisp_type ) :
 lisp_type = struct . unpack ( "B" , lisp_type ) [ 0 ]
 return ( lisp_type == 0x28 )
 if 46 - 46: OOooOOo
 if 67 - 67: OoO0O00 . I11i % OOooOOo + Oo0Ooo
 if 40 - 40: OoO0O00 / I11i % iIii1I11I1II1 - ooOoO0o
 if 51 - 51: Oo0Ooo % iIii1I11I1II1 % oO0o + o0oOOo0O0Ooo
 if 32 - 32: I1Ii111 * I1IiiI + Ii1I
 if 30 - 30: OoooooooOO / I1IiiI . iIii1I11I1II1 / ooOoO0o
 if 20 - 20: OoooooooOO * OOooOOo
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
def lisp_is_rloc_probe ( packet , rr ) :
 I1iIIIiI = ( struct . unpack ( "B" , packet [ 9 ] ) [ 0 ] == 17 )
 if ( I1iIIIiI == False ) : return ( [ packet , None , None , None ] )
 if 81 - 81: I1ii11iIi11i * OoO0O00 . o0oOOo0O0Ooo . OoooooooOO
 if ( rr == 0 ) :
  Ooo0O = lisp_is_rloc_probe_request ( packet [ 28 ] )
  if ( Ooo0O == False ) : return ( [ packet , None , None , None ] )
 elif ( rr == 1 ) :
  Ooo0O = lisp_is_rloc_probe_reply ( packet [ 28 ] )
  if ( Ooo0O == False ) : return ( [ packet , None , None , None ] )
 elif ( rr == - 1 ) :
  Ooo0O = lisp_is_rloc_probe_request ( packet [ 28 ] )
  if ( Ooo0O == False ) :
   Ooo0O = lisp_is_rloc_probe_reply ( packet [ 28 ] )
   if ( Ooo0O == False ) : return ( [ packet , None , None , None ] )
   if 64 - 64: Oo0Ooo . I1ii11iIi11i / ooOoO0o % oO0o . iIii1I11I1II1
   if 84 - 84: II111iiii . oO0o * O0 / iII111i + OoooooooOO
   if 99 - 99: I1ii11iIi11i . oO0o + Oo0Ooo + I1ii11iIi11i / I1Ii111 . I1ii11iIi11i
   if 95 - 95: OoOoOO00 * iIii1I11I1II1 / OoooooooOO % i1IIi
   if 91 - 91: OOooOOo - OoOoOO00
   if 58 - 58: II111iiii . OOooOOo % II111iiii * oO0o % OoO0O00 % I11i
 II1i1iI = lisp_address ( LISP_AFI_IPV4 , "" , 32 , 0 )
 II1i1iI . address = socket . ntohl ( struct . unpack ( "I" , packet [ 12 : 16 ] ) [ 0 ] )
 if 71 - 71: Ii1I * II111iiii * I1IiiI
 if 22 - 22: oO0o
 if 96 - 96: ooOoO0o * iII111i . IiII
 if 77 - 77: OOooOOo - I11i % o0oOOo0O0Ooo
 if ( II1i1iI . is_local ( ) ) : return ( [ None , None , None , None ] )
 if 46 - 46: I1IiiI % oO0o . OoooooooOO . IiII / I11i - i1IIi
 if 43 - 43: OoOoOO00 - o0oOOo0O0Ooo
 if 22 - 22: i1IIi
 if 33 - 33: O0
 II1i1iI = II1i1iI . print_address_no_iid ( )
 IIiII = socket . ntohs ( struct . unpack ( "H" , packet [ 20 : 22 ] ) [ 0 ] )
 iiI = struct . unpack ( "B" , packet [ 8 ] ) [ 0 ] - 1
 packet = packet [ 28 : : ]
 if 34 - 34: I1Ii111 . IiII % iII111i
 iIIIIIi11Ii = bold ( "Receive(pcap)" , False )
 Oo0OO0o0oOO0 = bold ( "from " + II1i1iI , False )
 OoOoO = lisp_format_packet ( packet )
 lprint ( "{} {} bytes {} {}, packet: {}" . format ( iIIIIIi11Ii , len ( packet ) , Oo0OO0o0oOO0 , IIiII , OoOoO ) )
 if 94 - 94: OOooOOo % i11iIiiIii . OOooOOo
 return ( [ packet , II1i1iI , IIiII , iiI ] )
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
 if 67 - 67: OoOoOO00
def lisp_ipc_write_xtr_parameters ( cp , dp ) :
 if ( lisp_ipc_dp_socket == None ) : return
 if 22 - 22: Ii1I * I1ii11iIi11i * o0oOOo0O0Ooo - I1IiiI . i11iIiiIii
 IIi1IiIii = { "type" : "xtr-parameters" , "control-plane-logging" : cp ,
 "data-plane-logging" : dp , "rtr" : lisp_i_am_rtr }
 if 30 - 30: O0 / oO0o * i11iIiiIii + iIii1I11I1II1 + O0 % I1IiiI
 lisp_write_to_dp_socket ( IIi1IiIii )
 return
 if 95 - 95: ooOoO0o % OOooOOo
 if 17 - 17: i1IIi + Ii1I
 if 35 - 35: iIii1I11I1II1 - Oo0Ooo - OoooooooOO % I1ii11iIi11i
 if 27 - 27: Oo0Ooo * II111iiii - OOooOOo + o0oOOo0O0Ooo
 if 26 - 26: oO0o / I1ii11iIi11i - oO0o
 if 9 - 9: ooOoO0o * iIii1I11I1II1 * OoooooooOO
 if 13 - 13: iII111i . i11iIiiIii * o0oOOo0O0Ooo . iII111i
 if 96 - 96: Ii1I
def lisp_external_data_plane ( ) :
 o00OoOO0O0 = 'egrep "ipc-data-plane = yes" ./lisp.config'
 if ( commands . getoutput ( o00OoOO0O0 ) != "" ) : return ( True )
 if 90 - 90: II111iiii
 if ( os . getenv ( "LISP_RUN_LISP_XTR" ) != None ) : return ( True )
 return ( False )
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
 if 19 - 19: I1ii11iIi11i
def lisp_process_data_plane_restart ( do_clear = False ) :
 os . system ( "touch ./lisp.config" )
 if 42 - 42: OoOoOO00 / IiII
 o000O0O0 = { "type" : "entire-map-cache" , "entries" : [ ] }
 if 74 - 74: ooOoO0o
 if ( do_clear == False ) :
  ii1Ii1Iii11i1 = o000O0O0 [ "entries" ]
  lisp_map_cache . walk_cache ( lisp_ipc_walk_map_cache , ii1Ii1Iii11i1 )
  if 93 - 93: Oo0Ooo % ooOoO0o
  if 38 - 38: II111iiii . I1Ii111 . iIii1I11I1II1 / o0oOOo0O0Ooo
 lisp_write_to_dp_socket ( o000O0O0 )
 return
 if 6 - 6: ooOoO0o - i1IIi * I1IiiI
 if 24 - 24: iIii1I11I1II1 / I1Ii111
 if 16 - 16: OoOoOO00 * I1Ii111 - I1IiiI / I1Ii111
 if 64 - 64: I1ii11iIi11i . i1IIi % II111iiii % Oo0Ooo + oO0o - I1IiiI
 if 24 - 24: IiII . II111iiii . II111iiii . OoOoOO00 . i11iIiiIii
 if 11 - 11: Ii1I
 if 82 - 82: I11i - i1IIi . Oo0Ooo * I1Ii111
 if 44 - 44: iII111i
 if 56 - 56: II111iiii / Oo0Ooo % IiII * II111iiii - iIii1I11I1II1 + ooOoO0o
 if 33 - 33: o0oOOo0O0Ooo . I11i / I1IiiI
 if 29 - 29: o0oOOo0O0Ooo - ooOoO0o
 if 59 - 59: I11i / IiII * OoO0O00 / IiII . I1Ii111
 if 82 - 82: OOooOOo . iIii1I11I1II1 + I1Ii111
 if 14 - 14: IiII . i11iIiiIii
def lisp_process_data_plane_stats ( msg , lisp_sockets , lisp_port ) :
 if ( msg . has_key ( "entries" ) == False ) :
  lprint ( "No 'entries' in stats IPC message" )
  return
  if 17 - 17: ooOoO0o % ooOoO0o * oO0o
 if ( type ( msg [ "entries" ] ) != list ) :
  lprint ( "'entries' in stats IPC message must be an array" )
  return
  if 8 - 8: ooOoO0o + OoO0O00 . II111iiii / iIii1I11I1II1 - OOooOOo
  if 87 - 87: iIii1I11I1II1 . IiII % I1IiiI . OoO0O00 - I1Ii111
 for msg in msg [ "entries" ] :
  if ( msg . has_key ( "eid-prefix" ) == False ) :
   lprint ( "No 'eid-prefix' in stats IPC message" )
   continue
   if 53 - 53: I1Ii111 % i11iIiiIii
  oOoo0OooOOo00 = msg [ "eid-prefix" ]
  if 99 - 99: I1IiiI - i1IIi * i11iIiiIii + OoO0O00
  if ( msg . has_key ( "instance-id" ) == False ) :
   lprint ( "No 'instance-id' in stats IPC message" )
   continue
   if 80 - 80: o0oOOo0O0Ooo . I11i % iIii1I11I1II1 + OoOoOO00
  o0OOoOO = int ( msg [ "instance-id" ] )
  if 87 - 87: I1Ii111 + II111iiii / I1ii11iIi11i + OoOoOO00
  if 71 - 71: I1IiiI + iIii1I11I1II1 + O0 * iII111i % IiII
  if 42 - 42: OOooOOo - I1ii11iIi11i
  if 93 - 93: I1Ii111 + OOooOOo % ooOoO0o / I1Ii111 % OOooOOo . IiII
  i1OO0o = lisp_address ( LISP_AFI_NONE , "" , 0 , o0OOoOO )
  i1OO0o . store_prefix ( oOoo0OooOOo00 )
  IIII = lisp_map_cache_lookup ( None , i1OO0o )
  if ( IIII == None ) :
   lprint ( "Map-cache entry for {} not found for stats update" . format ( oOoo0OooOOo00 ) )
   if 37 - 37: iII111i * oO0o / oO0o / Ii1I % I11i
   continue
   if 12 - 12: i11iIiiIii
   if 62 - 62: oO0o + OOooOOo + oO0o + I1IiiI
  if ( msg . has_key ( "rlocs" ) == False ) :
   lprint ( "No 'rlocs' in stats IPC message for {}" . format ( oOoo0OooOOo00 ) )
   if 10 - 10: IiII - Oo0Ooo % ooOoO0o
   continue
   if 38 - 38: oO0o * o0oOOo0O0Ooo . I11i % II111iiii / I11i % Ii1I
  if ( type ( msg [ "rlocs" ] ) != list ) :
   lprint ( "'rlocs' in stats IPC message must be an array" )
   continue
   if 19 - 19: II111iiii / i11iIiiIii * II111iiii + OoOoOO00 - OoOoOO00
  II1IiI1I = msg [ "rlocs" ]
  if 88 - 88: IiII * I1ii11iIi11i + IiII
  if 37 - 37: IiII . OoooooooOO - i11iIiiIii * I1ii11iIi11i - OOooOOo
  if 74 - 74: Ii1I + i11iIiiIii * iII111i / o0oOOo0O0Ooo . i11iIiiIii
  if 99 - 99: OOooOOo - OoooooooOO + OoooooooOO . OOooOOo
  for I11iii11I in II1IiI1I :
   if ( I11iii11I . has_key ( "rloc" ) == False ) : continue
   if 67 - 67: I1ii11iIi11i + iII111i % II111iiii + I1IiiI % I11i
   ooOo = I11iii11I [ "rloc" ]
   if ( ooOo == "no-address" ) : continue
   if 19 - 19: i11iIiiIii * ooOoO0o
   OoOOo = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
   OoOOo . store_address ( ooOo )
   if 70 - 70: OoO0O00 % I1ii11iIi11i
   IiI1I1iii11 = IIII . get_rloc ( OoOOo )
   if ( IiI1I1iii11 == None ) : continue
   if 43 - 43: I1Ii111 / iIii1I11I1II1 * Oo0Ooo % O0 * iII111i
   if 63 - 63: iII111i - I11i - iIii1I11I1II1 - Ii1I / iII111i % I1Ii111
   if 59 - 59: OoooooooOO
   if 89 - 89: i1IIi / OoooooooOO . I1IiiI
   oOo0o00Oo0 = 0 if I11iii11I . has_key ( "packet-count" ) == False else I11iii11I [ "packet-count" ]
   if 4 - 4: Ii1I + I1ii11iIi11i
   Ii1OO0Oo00OO0o = 0 if I11iii11I . has_key ( "byte-count" ) == False else I11iii11I [ "byte-count" ]
   if 40 - 40: OOooOOo % iII111i
   OOOO0O00o = 0 if I11iii11I . has_key ( "seconds-last-packet" ) == False else I11iii11I [ "seconds-last-packet" ]
   if 5 - 5: O0 + i11iIiiIii . IiII - OOooOOo
   if 51 - 51: OOooOOo . I1IiiI % OoO0O00 . I1IiiI
   IiI1I1iii11 . stats . packet_count += oOo0o00Oo0
   IiI1I1iii11 . stats . byte_count += Ii1OO0Oo00OO0o
   IiI1I1iii11 . stats . last_increment = lisp_get_timestamp ( ) - OOOO0O00o
   if 88 - 88: O0 . iIii1I11I1II1 . iIii1I11I1II1 - ooOoO0o * iIii1I11I1II1 . Oo0Ooo
   lprint ( "Update stats {}/{}/{}s for {} RLOC {}" . format ( oOo0o00Oo0 , Ii1OO0Oo00OO0o ,
 OOOO0O00o , oOoo0OooOOo00 , ooOo ) )
   if 8 - 8: iII111i
   if 78 - 78: i11iIiiIii % oO0o % ooOoO0o - I1Ii111
   if 53 - 53: oO0o + i1IIi . i11iIiiIii + OoO0O00 + Oo0Ooo
   if 27 - 27: OoooooooOO . I1IiiI + OoooooooOO % II111iiii . II111iiii - oO0o
   if 8 - 8: o0oOOo0O0Ooo . i1IIi . Ii1I - OoOoOO00 / iIii1I11I1II1
  if ( IIII . group . is_null ( ) and IIII . has_ttl_elapsed ( ) ) :
   oOoo0OooOOo00 = green ( IIII . print_eid_tuple ( ) , False )
   lprint ( "Refresh map-cache entry {}" . format ( oOoo0OooOOo00 ) )
   lisp_send_map_request ( lisp_sockets , lisp_port , None , IIII . eid , None )
   if 11 - 11: oO0o - OOooOOo - I11i * I1IiiI
   if 25 - 25: OoOoOO00 - OOooOOo * I11i / iII111i + o0oOOo0O0Ooo - O0
 return
 if 29 - 29: ooOoO0o
 if 60 - 60: ooOoO0o / I1ii11iIi11i * i1IIi - IiII . II111iiii
 if 65 - 65: oO0o * IiII
 if 97 - 97: IiII % OoO0O00 . OoOoOO00 - Ii1I
 if 28 - 28: O0 . I11i . I1IiiI - Ii1I - iII111i - iIii1I11I1II1
 if 14 - 14: OOooOOo + ooOoO0o
 if 56 - 56: o0oOOo0O0Ooo - OoOoOO00 - Ii1I
 if 50 - 50: I1ii11iIi11i
 if 24 - 24: ooOoO0o
 if 19 - 19: oO0o
 if 97 - 97: IiII
 if 36 - 36: II111iiii
 if 83 - 83: I11i . ooOoO0o
 if 57 - 57: IiII
 if 34 - 34: I1ii11iIi11i + i11iIiiIii - I1ii11iIi11i / OoOoOO00 + i1IIi . i11iIiiIii
 if 48 - 48: I1ii11iIi11i % OoOoOO00 * OoOoOO00 % o0oOOo0O0Ooo * II111iiii / OoOoOO00
 if 73 - 73: OoOoOO00 + OOooOOo * II111iiii . OOooOOo % I1Ii111 % oO0o
 if 79 - 79: I1ii11iIi11i % I11i
 if 78 - 78: i11iIiiIii % I1Ii111 + iIii1I11I1II1 + iII111i
 if 66 - 66: I1IiiI - o0oOOo0O0Ooo
 if 67 - 67: oO0o . iII111i * Ii1I - OOooOOo / oO0o
 if 98 - 98: OoOoOO00 * OoO0O00 . Oo0Ooo
 if 6 - 6: I11i % iIii1I11I1II1 + I1Ii111
def lisp_process_data_plane_decap_stats ( msg , lisp_ipc_socket ) :
 if 48 - 48: II111iiii . OOooOOo . ooOoO0o - iII111i
 if 90 - 90: OOooOOo
 if 43 - 43: IiII + ooOoO0o
 if 4 - 4: i1IIi
 if 89 - 89: Oo0Ooo / iIii1I11I1II1 . OoOoOO00
 if ( lisp_i_am_itr ) :
  lprint ( "Send decap-stats IPC message to lisp-etr process" )
  IIi1IiIii = "stats%{}" . format ( json . dumps ( msg ) )
  IIi1IiIii = lisp_command_ipc ( IIi1IiIii , "lisp-itr" )
  lisp_ipc ( IIi1IiIii , lisp_ipc_socket , "lisp-etr" )
  return
  if 6 - 6: Ii1I / iII111i
  if 69 - 69: iIii1I11I1II1 % I1Ii111 % OOooOOo + O0 - OoOoOO00 % oO0o
  if 70 - 70: oO0o - I1IiiI + Ii1I
  if 54 - 54: OoOoOO00 / ooOoO0o - I1IiiI
  if 37 - 37: o0oOOo0O0Ooo
  if 57 - 57: iII111i / i1IIi / i1IIi + IiII
  if 75 - 75: IiII / O0
  if 72 - 72: I11i
 IIi1IiIii = bold ( "IPC" , False )
 lprint ( "Process decap-stats {} message: '{}'" . format ( IIi1IiIii , msg ) )
 if 35 - 35: I11i % OoooooooOO / i1IIi * i1IIi / I1IiiI
 if ( lisp_i_am_etr ) : msg = json . loads ( msg )
 if 42 - 42: I11i - i1IIi - oO0o / I11i + Ii1I + ooOoO0o
 iIIOO0OO = [ "good-packets" , "ICV-error" , "checksum-error" ,
 "lisp-header-error" , "no-decrypt-key" , "bad-inner-version" ,
 "outer-header-error" ]
 if 67 - 67: OoO0O00 . II111iiii * O0
 for iIIiii in iIIOO0OO :
  oOo0o00Oo0 = 0 if msg . has_key ( iIIiii ) == False else msg [ iIIiii ] [ "packet-count" ]
  if 77 - 77: I1ii11iIi11i + OoooooooOO * OoO0O00 * iIii1I11I1II1 % I1Ii111
  lisp_decap_stats [ iIIiii ] . packet_count += oOo0o00Oo0
  if 22 - 22: i1IIi
  Ii1OO0Oo00OO0o = 0 if msg . has_key ( iIIiii ) == False else msg [ iIIiii ] [ "byte-count" ]
  if 61 - 61: IiII
  lisp_decap_stats [ iIIiii ] . byte_count += Ii1OO0Oo00OO0o
  if 3 - 3: ooOoO0o . Oo0Ooo . ooOoO0o / OoO0O00 / o0oOOo0O0Ooo . I1Ii111
  OOOO0O00o = 0 if msg . has_key ( iIIiii ) == False else msg [ iIIiii ] [ "seconds-last-packet" ]
  if 20 - 20: iII111i + II111iiii + i11iIiiIii
  lisp_decap_stats [ iIIiii ] . last_increment = lisp_get_timestamp ( ) - OOOO0O00o
  if 75 - 75: OoooooooOO
 return
 if 63 - 63: iII111i % oO0o . ooOoO0o * I1Ii111 + o0oOOo0O0Ooo * II111iiii
 if 61 - 61: oO0o
 if 45 - 45: I11i * OoOoOO00 % Oo0Ooo / iII111i
 if 78 - 78: II111iiii
 if 38 - 38: I11i - i11iIiiIii
 if 38 - 38: I1IiiI * i1IIi / OoO0O00 + iIii1I11I1II1 / I1Ii111 % II111iiii
 if 62 - 62: OoOoOO00 * i1IIi + iII111i
 if 43 - 43: OOooOOo % i11iIiiIii / I1ii11iIi11i + i1IIi / ooOoO0o
 if 74 - 74: Ii1I + iIii1I11I1II1
 if 23 - 23: OoO0O00 * i1IIi * oO0o % I1ii11iIi11i
 if 92 - 92: iII111i / I1IiiI / i11iIiiIii
 if 75 - 75: Oo0Ooo + IiII / I11i % I11i % IiII / I1Ii111
 if 95 - 95: OoOoOO00
 if 78 - 78: I11i
 if 62 - 62: iIii1I11I1II1 . o0oOOo0O0Ooo . ooOoO0o % oO0o % O0 % oO0o
 if 51 - 51: Oo0Ooo / IiII - Oo0Ooo
 if 71 - 71: I11i * I1ii11iIi11i * OOooOOo * o0oOOo0O0Ooo
def lisp_process_punt ( punt_socket , lisp_send_sockets , lisp_ephem_port ) :
 ooo00OOoo00 , II1i1iI = punt_socket . recvfrom ( 4000 )
 if 21 - 21: I1IiiI - iII111i * IiII . I11i
 oOO0Oo0oO = json . loads ( ooo00OOoo00 )
 if ( type ( oOO0Oo0oO ) != dict ) :
  lprint ( "Invalid punt message from {}, not in JSON format" . format ( II1i1iI ) )
  if 18 - 18: OoOoOO00 % IiII - iIii1I11I1II1 / iIii1I11I1II1 % O0 / O0
  return
  if 28 - 28: OOooOOo
 I1IIi1II1Ii = bold ( "Punt" , False )
 lprint ( "{} message from '{}': '{}'" . format ( I1IIi1II1Ii , II1i1iI , oOO0Oo0oO ) )
 if 21 - 21: iII111i * OoooooooOO
 if ( oOO0Oo0oO . has_key ( "type" ) == False ) :
  lprint ( "Punt IPC message has no 'type' key" )
  return
  if 67 - 67: IiII / oO0o . O0
  if 70 - 70: I1ii11iIi11i % O0
  if 57 - 57: i1IIi + OoOoOO00
  if 8 - 8: Ii1I + I11i * oO0o % I11i
  if 17 - 17: o0oOOo0O0Ooo + Oo0Ooo
 if ( oOO0Oo0oO [ "type" ] == "statistics" ) :
  lisp_process_data_plane_stats ( oOO0Oo0oO , lisp_send_sockets , lisp_ephem_port )
  return
  if 38 - 38: oO0o + I1IiiI + OOooOOo
 if ( oOO0Oo0oO [ "type" ] == "decap-statistics" ) :
  lisp_process_data_plane_decap_stats ( oOO0Oo0oO , punt_socket )
  return
  if 82 - 82: iIii1I11I1II1 . OOooOOo
  if 7 - 7: i11iIiiIii . I11i
  if 56 - 56: iIii1I11I1II1 - II111iiii * i1IIi / Ii1I
  if 65 - 65: OOooOOo / I1IiiI . OoooooooOO + I1IiiI + OoooooooOO + i11iIiiIii
  if 20 - 20: I1IiiI + iII111i + O0 * O0
 if ( oOO0Oo0oO [ "type" ] == "restart" ) :
  lisp_process_data_plane_restart ( )
  return
  if 18 - 18: I11i - I11i . OoOoOO00 . ooOoO0o
  if 31 - 31: ooOoO0o
  if 87 - 87: OoooooooOO + OOooOOo - I1ii11iIi11i / I1IiiI + ooOoO0o - Oo0Ooo
  if 19 - 19: ooOoO0o + I1ii11iIi11i - ooOoO0o
  if 17 - 17: I11i * i1IIi + iIii1I11I1II1 % I1IiiI
 if ( oOO0Oo0oO [ "type" ] != "discovery" ) :
  lprint ( "Punt IPC message has wrong format" )
  return
  if 44 - 44: IiII + I1IiiI . Ii1I % Oo0Ooo
 if ( oOO0Oo0oO . has_key ( "interface" ) == False ) :
  lprint ( "Invalid punt message from {}, required keys missing" . format ( II1i1iI ) )
  if 97 - 97: O0
  return
  if 95 - 95: OoO0O00 % iII111i / I1IiiI * OoooooooOO
  if 31 - 31: iIii1I11I1II1
  if 62 - 62: o0oOOo0O0Ooo - iII111i / II111iiii . o0oOOo0O0Ooo
  if 20 - 20: iIii1I11I1II1 % OOooOOo
  if 91 - 91: ooOoO0o
 O0OoO0o = oOO0Oo0oO [ "interface" ]
 if ( O0OoO0o == "" ) :
  o0OOoOO = int ( oOO0Oo0oO [ "instance-id" ] )
  if ( o0OOoOO == - 1 ) : return
 else :
  o0OOoOO = lisp_get_interface_instance_id ( O0OoO0o , None )
  if 96 - 96: I1IiiI . OOooOOo
  if 94 - 94: OoooooooOO + II111iiii % ooOoO0o - II111iiii / O0
  if 34 - 34: IiII % oO0o
  if 54 - 54: I1IiiI
  if 80 - 80: OoOoOO00 . I1IiiI / I1ii11iIi11i . iII111i
 I1i1III1i = None
 if ( oOO0Oo0oO . has_key ( "source-eid" ) ) :
  iiI1i = oOO0Oo0oO [ "source-eid" ]
  I1i1III1i = lisp_address ( LISP_AFI_NONE , iiI1i , 0 , o0OOoOO )
  if ( I1i1III1i . is_null ( ) ) :
   lprint ( "Invalid source-EID format '{}'" . format ( iiI1i ) )
   return
   if 31 - 31: I11i * o0oOOo0O0Ooo
   if 17 - 17: Ii1I * iIii1I11I1II1
 O000iI1ii1I = None
 if ( oOO0Oo0oO . has_key ( "dest-eid" ) ) :
  iI11iiiI1 = oOO0Oo0oO [ "dest-eid" ]
  O000iI1ii1I = lisp_address ( LISP_AFI_NONE , iI11iiiI1 , 0 , o0OOoOO )
  if ( O000iI1ii1I . is_null ( ) ) :
   lprint ( "Invalid dest-EID format '{}'" . format ( iI11iiiI1 ) )
   return
   if 99 - 99: Oo0Ooo + ooOoO0o / o0oOOo0O0Ooo . OoO0O00 + OOooOOo
   if 95 - 95: I1ii11iIi11i % I1IiiI
   if 64 - 64: O0
   if 83 - 83: oO0o / i11iIiiIii
   if 85 - 85: I11i
   if 23 - 23: oO0o % I11i * Oo0Ooo + Oo0Ooo
   if 23 - 23: Ii1I % i1IIi - I1Ii111
   if 95 - 95: OoOoOO00 - ooOoO0o . i1IIi . OoooooooOO
 if ( I1i1III1i ) :
  ooo0OO = green ( I1i1III1i . print_address ( ) , False )
  I111I = lisp_db_for_lookups . lookup_cache ( I1i1III1i , False )
  if ( I111I != None ) :
   if 38 - 38: I1IiiI + I1ii11iIi11i - Oo0Ooo . i11iIiiIii - i1IIi
   if 11 - 11: IiII / I1IiiI . I1IiiI
   if 87 - 87: OoooooooOO * OoO0O00 * iIii1I11I1II1
   if 16 - 16: o0oOOo0O0Ooo * I11i + OoooooooOO + O0 / iIii1I11I1II1
   if 60 - 60: Ii1I % IiII * OoooooooOO * ooOoO0o * Ii1I
   if ( I111I . dynamic_eid_configured ( ) ) :
    I111IIiIII = lisp_allow_dynamic_eid ( O0OoO0o , I1i1III1i )
    if ( I111IIiIII != None and lisp_i_am_itr ) :
     lisp_itr_discover_eid ( I111I , I1i1III1i , O0OoO0o , I111IIiIII )
    else :
     lprint ( ( "Disallow dynamic source-EID {} " + "on interface {}" ) . format ( ooo0OO , O0OoO0o ) )
     if 8 - 8: I1Ii111 - o0oOOo0O0Ooo
     if 52 - 52: OoOoOO00 % O0 + I1ii11iIi11i . i11iIiiIii
     if 59 - 59: Ii1I - I1Ii111 . ooOoO0o - OoOoOO00 + oO0o . OoO0O00
  else :
   lprint ( "Punt from non-EID source {}" . format ( ooo0OO ) )
   if 88 - 88: OOooOOo - ooOoO0o * o0oOOo0O0Ooo . OoooooooOO
   if 3 - 3: I1Ii111
   if 24 - 24: Ii1I + i11iIiiIii * I1Ii111 - OoOoOO00 / Ii1I - OoOoOO00
   if 69 - 69: I11i - I1IiiI . oO0o - OoooooooOO
   if 33 - 33: o0oOOo0O0Ooo - o0oOOo0O0Ooo
   if 55 - 55: OoooooooOO / IiII + i1IIi
 if ( O000iI1ii1I ) :
  IIII = lisp_map_cache_lookup ( I1i1III1i , O000iI1ii1I )
  if ( IIII == None or IIII . action == LISP_SEND_MAP_REQUEST_ACTION ) :
   if 54 - 54: ooOoO0o * Ii1I / Ii1I
   if 15 - 15: oO0o * I1Ii111
   if 11 - 11: Ii1I + o0oOOo0O0Ooo * OoooooooOO % iIii1I11I1II1
   if 87 - 87: OoO0O00 + o0oOOo0O0Ooo
   if 46 - 46: oO0o + OoOoOO00
   if ( lisp_rate_limit_map_request ( I1i1III1i , O000iI1ii1I ) ) : return
   lisp_send_map_request ( lisp_send_sockets , lisp_ephem_port ,
 I1i1III1i , O000iI1ii1I , None )
  else :
   ooo0OO = green ( O000iI1ii1I . print_address ( ) , False )
   lprint ( "Map-cache entry for {} already exists" . format ( ooo0OO ) )
   if 17 - 17: Ii1I . Oo0Ooo - oO0o % OOooOOo
   if 59 - 59: O0
 return
 if 75 - 75: o0oOOo0O0Ooo / OoooooooOO . I1ii11iIi11i * oO0o * I11i / OoooooooOO
 if 17 - 17: Ii1I % I1ii11iIi11i + I11i
 if 80 - 80: i1IIi . OoooooooOO % OoooooooOO . oO0o / OOooOOo
 if 85 - 85: OOooOOo
 if 80 - 80: ooOoO0o % O0 % I1ii11iIi11i + Oo0Ooo
 if 82 - 82: oO0o / iIii1I11I1II1 % ooOoO0o . Ii1I / i1IIi - I1Ii111
 if 15 - 15: I11i - OOooOOo . II111iiii . iIii1I11I1II1
def lisp_ipc_map_cache_entry ( mc , jdata ) :
 iIIiI11iI1Ii1 = lisp_write_ipc_map_cache ( True , mc , dont_send = True )
 jdata . append ( iIIiI11iI1Ii1 )
 return ( [ True , jdata ] )
 if 93 - 93: I11i + o0oOOo0O0Ooo / OOooOOo + Ii1I % Oo0Ooo % I1ii11iIi11i
 if 72 - 72: IiII / II111iiii
 if 25 - 25: i1IIi + OoOoOO00 + oO0o + OoooooooOO
 if 21 - 21: I1ii11iIi11i
 if 60 - 60: i1IIi / OoO0O00 . Ii1I
 if 16 - 16: i11iIiiIii + OoOoOO00 % Oo0Ooo + I1ii11iIi11i * Ii1I / I1Ii111
 if 26 - 26: iII111i
 if 31 - 31: iII111i
def lisp_ipc_walk_map_cache ( mc , jdata ) :
 if 45 - 45: OoO0O00
 if 55 - 55: iIii1I11I1II1 % iIii1I11I1II1 + I11i - ooOoO0o + I1IiiI * O0
 if 47 - 47: ooOoO0o + iIii1I11I1II1 * OOooOOo . I1IiiI . o0oOOo0O0Ooo
 if 49 - 49: Oo0Ooo . OoOoOO00 * OOooOOo
 if ( mc . group . is_null ( ) ) : return ( lisp_ipc_map_cache_entry ( mc , jdata ) )
 if 86 - 86: IiII * OOooOOo + Ii1I
 if ( mc . source_cache == None ) : return ( [ True , jdata ] )
 if 62 - 62: I11i
 if 86 - 86: Oo0Ooo % II111iiii + I1Ii111 / I1ii11iIi11i
 if 15 - 15: I1IiiI / I1Ii111 % iII111i
 if 57 - 57: I1Ii111 . iIii1I11I1II1 / Oo0Ooo / IiII / iII111i * OoOoOO00
 if 35 - 35: i1IIi + I1Ii111 - ooOoO0o . I1ii11iIi11i + Oo0Ooo
 jdata = mc . source_cache . walk_cache ( lisp_ipc_map_cache_entry , jdata )
 return ( [ True , jdata ] )
 if 43 - 43: oO0o . OoO0O00 * i1IIi
 if 1 - 1: ooOoO0o / i1IIi
 if 42 - 42: I1ii11iIi11i * ooOoO0o + OoOoOO00 % I1ii11iIi11i . IiII
 if 75 - 75: OoO0O00 * i1IIi - OOooOOo % II111iiii % OoO0O00 - OoOoOO00
 if 75 - 75: I11i * IiII * ooOoO0o
 if 31 - 31: Ii1I
 if 72 - 72: OOooOOo * Ii1I % OoO0O00
def lisp_itr_discover_eid ( db , eid , input_interface , routed_interface ,
 lisp_ipc_listen_socket ) :
 oOoo0OooOOo00 = eid . print_address ( )
 if ( db . dynamic_eids . has_key ( oOoo0OooOOo00 ) ) :
  db . dynamic_eids [ oOoo0OooOOo00 ] . last_packet = lisp_get_timestamp ( )
  return
  if 72 - 72: OoOoOO00 + o0oOOo0O0Ooo - i1IIi - OoO0O00 % OoOoOO00
  if 42 - 42: oO0o / i1IIi . IiII
  if 12 - 12: i11iIiiIii . ooOoO0o
  if 80 - 80: O0 / iIii1I11I1II1 % iII111i * ooOoO0o / i11iIiiIii . OoOoOO00
  if 88 - 88: OoooooooOO . I1IiiI
 oOiiI1i11I = lisp_dynamic_eid ( )
 oOiiI1i11I . dynamic_eid . copy_address ( eid )
 oOiiI1i11I . interface = routed_interface
 oOiiI1i11I . last_packet = lisp_get_timestamp ( )
 oOiiI1i11I . get_timeout ( routed_interface )
 db . dynamic_eids [ oOoo0OooOOo00 ] = oOiiI1i11I
 if 6 - 6: I1Ii111 - i11iIiiIii - oO0o
 iiII = ""
 if ( input_interface != routed_interface ) :
  iiII = ", routed-interface " + routed_interface
  if 18 - 18: I1ii11iIi11i + I1IiiI / iII111i + iIii1I11I1II1
  if 1 - 1: I1Ii111 - Oo0Ooo + I11i - iII111i * ooOoO0o % i11iIiiIii
 II1i1 = green ( oOoo0OooOOo00 , False ) + bold ( " discovered" , False )
 lprint ( "Dynamic-EID {} on interface {}{}, timeout {}" . format ( II1i1 , input_interface , iiII , oOiiI1i11I . timeout ) )
 if 5 - 5: Oo0Ooo
 if 29 - 29: IiII - IiII - OoooooooOO . Ii1I % OoooooooOO - OoOoOO00
 if 33 - 33: oO0o * OoO0O00 / i11iIiiIii - I1IiiI * OoO0O00
 if 19 - 19: OoooooooOO
 if 34 - 34: OoOoOO00 . oO0o
 IIi1IiIii = "learn%{}%{}" . format ( oOoo0OooOOo00 , routed_interface )
 IIi1IiIii = lisp_command_ipc ( IIi1IiIii , "lisp-itr" )
 lisp_ipc ( IIi1IiIii , lisp_ipc_listen_socket , "lisp-etr" )
 return
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
def lisp_retry_decap_keys ( addr_str , packet , iv , packet_icv ) :
 if ( lisp_search_decap_keys == False ) : return
 if 22 - 22: OOooOOo . i11iIiiIii + II111iiii - Oo0Ooo % i1IIi / o0oOOo0O0Ooo
 if 90 - 90: IiII
 if 38 - 38: i1IIi / ooOoO0o / I11i * I1ii11iIi11i / II111iiii . iIii1I11I1II1
 if 52 - 52: I1ii11iIi11i % ooOoO0o * Ii1I * IiII + IiII / i11iIiiIii
 if ( addr_str . find ( ":" ) != - 1 ) : return
 if 51 - 51: iIii1I11I1II1 * o0oOOo0O0Ooo % o0oOOo0O0Ooo . Ii1I / OoooooooOO
 IiI1 = lisp_crypto_keys_by_rloc_decap [ addr_str ]
 if 23 - 23: oO0o * I1IiiI - oO0o - ooOoO0o . IiII / i11iIiiIii
 for iii11 in lisp_crypto_keys_by_rloc_decap :
  if 53 - 53: Ii1I * Ii1I . OoOoOO00 . OOooOOo / I1ii11iIi11i % O0
  if 98 - 98: OOooOOo
  if 11 - 11: OOooOOo * iIii1I11I1II1 % IiII - I1IiiI . I11i
  if 29 - 29: OOooOOo % I11i - OOooOOo - OOooOOo * I11i . oO0o
  if ( iii11 . find ( addr_str ) == - 1 ) : continue
  if 75 - 75: II111iiii . O0 . I1Ii111 * O0 / OoooooooOO
  if 60 - 60: OOooOOo - Oo0Ooo * OOooOOo / OoO0O00
  if 55 - 55: I1ii11iIi11i * II111iiii * iIii1I11I1II1
  if 38 - 38: iIii1I11I1II1 % I1ii11iIi11i . Ii1I + I1IiiI % i11iIiiIii - i11iIiiIii
  if ( iii11 == addr_str ) : continue
  if 62 - 62: I1Ii111 + I1IiiI
  if 9 - 9: iIii1I11I1II1 / iIii1I11I1II1
  if 24 - 24: OOooOOo . I1IiiI % i11iIiiIii
  if 43 - 43: OoooooooOO . o0oOOo0O0Ooo - I1ii11iIi11i + OoO0O00 . I1Ii111 . iII111i
  iIIiI11iI1Ii1 = lisp_crypto_keys_by_rloc_decap [ iii11 ]
  if ( iIIiI11iI1Ii1 == IiI1 ) : continue
  if 1 - 1: iII111i / OoO0O00 / OoOoOO00 * Oo0Ooo * OoooooooOO
  if 59 - 59: iII111i
  if 14 - 14: oO0o . IiII + iIii1I11I1II1 - i1IIi
  if 46 - 46: i11iIiiIii * II111iiii / i11iIiiIii % i11iIiiIii * II111iiii + i11iIiiIii
  OOoO0o = iIIiI11iI1Ii1 [ 1 ]
  if ( packet_icv != OOoO0o . do_icv ( packet , iv ) ) :
   lprint ( "Test ICV with key {} failed" . format ( red ( iii11 , False ) ) )
   continue
   if 20 - 20: iII111i * I1IiiI * iII111i - o0oOOo0O0Ooo + i1IIi + ooOoO0o
   if 49 - 49: II111iiii * I1IiiI / oO0o
  lprint ( "Changing decap crypto key to {}" . format ( red ( iii11 , False ) ) )
  lisp_crypto_keys_by_rloc_decap [ addr_str ] = iIIiI11iI1Ii1
  if 50 - 50: Ii1I + O0 . I1IiiI * Oo0Ooo
 return
 if 15 - 15: Oo0Ooo
 if 53 - 53: OoooooooOO * O0 / iII111i * ooOoO0o % I1Ii111 + OOooOOo
 if 95 - 95: I1Ii111 % OoOoOO00 . IiII * iII111i % Ii1I
 if 18 - 18: iIii1I11I1II1 / ooOoO0o / I1Ii111 % oO0o * Ii1I
 if 14 - 14: oO0o
 if 72 - 72: iIii1I11I1II1 / II111iiii * II111iiii + I1IiiI + iIii1I11I1II1 + oO0o
 if 46 - 46: I1Ii111
 if 23 - 23: Oo0Ooo * IiII - I1Ii111 . OoooooooOO
def lisp_decent_pull_xtr_configured ( ) :
 return ( lisp_decent_modulus != 0 and lisp_decent_dns_suffix != None )
 if 78 - 78: OoOoOO00 - iIii1I11I1II1
 if 20 - 20: i1IIi
 if 72 - 72: ooOoO0o . II111iiii
 if 32 - 32: I1Ii111 - oO0o + OoooooooOO . OoOoOO00 + i11iIiiIii / i1IIi
 if 26 - 26: I1IiiI + OoooooooOO % OoOoOO00 . IiII - II111iiii . OoOoOO00
 if 37 - 37: OoO0O00 % O0 + OoOoOO00 * I11i . Ii1I * OoO0O00
 if 18 - 18: o0oOOo0O0Ooo / OOooOOo
 if 28 - 28: O0 / Ii1I - oO0o % I1ii11iIi11i % O0 . OoO0O00
def lisp_is_decent_dns_suffix ( dns_name ) :
 if ( lisp_decent_dns_suffix == None ) : return ( False )
 IiIII = dns_name . split ( "." )
 IiIII = "." . join ( IiIII [ 1 : : ] )
 return ( IiIII == lisp_decent_dns_suffix )
 if 100 - 100: O0
 if 19 - 19: Ii1I * iIii1I11I1II1 * Oo0Ooo - i11iIiiIii * i11iIiiIii - OOooOOo
 if 88 - 88: O0 . iIii1I11I1II1 . I1ii11iIi11i
 if 80 - 80: oO0o / i1IIi * iIii1I11I1II1
 if 38 - 38: Ii1I
 if 20 - 20: iIii1I11I1II1 + Oo0Ooo - Ii1I / i11iIiiIii . OoO0O00
 if 66 - 66: OoooooooOO - Ii1I / iII111i . I1IiiI + I1ii11iIi11i - I1Ii111
def lisp_get_decent_index ( eid ) :
 oOoo0OooOOo00 = eid . print_prefix ( )
 I1iI1IIi1 = hashlib . sha256 ( oOoo0OooOOo00 ) . hexdigest ( )
 iI11I = int ( I1iI1IIi1 , 16 ) % lisp_decent_modulus
 return ( iI11I )
 if 58 - 58: oO0o - iIii1I11I1II1 * i11iIiiIii / i11iIiiIii % I11i
 if 69 - 69: iII111i * i1IIi
 if 100 - 100: Oo0Ooo + Oo0Ooo - II111iiii
 if 4 - 4: iII111i / OoO0O00 . i11iIiiIii * II111iiii - Ii1I * IiII
 if 45 - 45: OoO0O00
 if 15 - 15: iII111i * o0oOOo0O0Ooo * Ii1I % IiII
 if 31 - 31: ooOoO0o . IiII + I1ii11iIi11i * II111iiii * iII111i + Oo0Ooo
def lisp_get_decent_dns_name ( eid ) :
 iI11I = lisp_get_decent_index ( eid )
 return ( str ( iI11I ) + "." + lisp_decent_dns_suffix )
 if 35 - 35: oO0o + I1ii11iIi11i / o0oOOo0O0Ooo
 if 78 - 78: i11iIiiIii
 if 21 - 21: iII111i / ooOoO0o - i11iIiiIii % iII111i
 if 94 - 94: OoooooooOO / iII111i * ooOoO0o / i1IIi * i11iIiiIii * II111iiii
 if 98 - 98: Ii1I * Ii1I / IiII
 if 1 - 1: OOooOOo
 if 47 - 47: i11iIiiIii - I11i
 if 38 - 38: Oo0Ooo % OoooooooOO + iII111i
def lisp_get_decent_dns_name_from_str ( iid , eid_str ) :
 i1OO0o = lisp_address ( LISP_AFI_NONE , eid_str , 0 , iid )
 iI11I = lisp_get_decent_index ( i1OO0o )
 return ( str ( iI11I ) + "." + lisp_decent_dns_suffix )
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
def lisp_trace_append ( packet , reason = None , ed = "encap" , lisp_socket = None ,
 rloc_entry = None ) :
 if 20 - 20: Ii1I * iII111i / ooOoO0o
 I11iiIi1i1 = 28 if packet . inner_version == 4 else 48
 IIi1iiIIii1Ii = packet . packet [ I11iiIi1i1 : : ]
 i11I1iII = lisp_trace ( )
 if ( i11I1iII . decode ( IIi1iiIIii1Ii ) == False ) :
  lprint ( "Could not decode JSON portion of a LISP-Trace packet" )
  return ( False )
  if 16 - 16: O0 . OoOoOO00 . iII111i + Oo0Ooo
  if 89 - 89: I11i - OoO0O00 . IiII - OoO0O00 - I1ii11iIi11i % I1IiiI
 I1II111 = "?" if packet . outer_dest . is_null ( ) else packet . outer_dest . print_address_no_iid ( )
 if 94 - 94: OoO0O00
 if 78 - 78: iIii1I11I1II1 / I1IiiI + iIii1I11I1II1 . I1ii11iIi11i / I1ii11iIi11i + IiII
 if 92 - 92: i11iIiiIii * iII111i
 if 9 - 9: O0 * IiII / Ii1I + OoO0O00
 if 75 - 75: OOooOOo * OoOoOO00
 if 82 - 82: Ii1I
 if ( I1II111 != "?" and packet . encap_port != LISP_DATA_PORT ) :
  if ( ed == "encap" ) : I1II111 += ":{}" . format ( packet . encap_port )
  if 83 - 83: I1IiiI
  if 22 - 22: IiII / Ii1I + I1Ii111 % iIii1I11I1II1
  if 75 - 75: OoOoOO00 % OoOoOO00 % o0oOOo0O0Ooo % I1ii11iIi11i + IiII
  if 45 - 45: I11i - iIii1I11I1II1
  if 20 - 20: OoOoOO00
 iIIiI11iI1Ii1 = { }
 iIIiI11iI1Ii1 [ "node" ] = "ITR" if lisp_i_am_itr else "ETR" if lisp_i_am_etr else "RTR" if lisp_i_am_rtr else "?"
 if 84 - 84: OoOoOO00
 o0O0iiiI111i1 = packet . outer_source
 if ( o0O0iiiI111i1 . is_null ( ) ) : o0O0iiiI111i1 = lisp_myrlocs [ 0 ]
 iIIiI11iI1Ii1 [ "srloc" ] = o0O0iiiI111i1 . print_address_no_iid ( )
 if 42 - 42: O0 . ooOoO0o + OOooOOo . iIii1I11I1II1 * OoO0O00 . iII111i
 if 35 - 35: II111iiii + I11i
 if 15 - 15: Oo0Ooo . i1IIi - o0oOOo0O0Ooo - oO0o / o0oOOo0O0Ooo
 if 97 - 97: oO0o - I1IiiI / Ii1I
 if 48 - 48: o0oOOo0O0Ooo % o0oOOo0O0Ooo - OoOoOO00
 if ( iIIiI11iI1Ii1 [ "node" ] == "ITR" and packet . inner_sport != LISP_TRACE_PORT ) :
  iIIiI11iI1Ii1 [ "srloc" ] += ":{}" . format ( packet . inner_sport )
  if 13 - 13: OoO0O00 - Ii1I . ooOoO0o / O0 * OoOoOO00
  if 57 - 57: O0 + OoooooooOO % o0oOOo0O0Ooo / I1Ii111 / OOooOOo - OoOoOO00
 iIIiI11iI1Ii1 [ "hn" ] = lisp_hostname
 iii11 = ed + "-ts"
 iIIiI11iI1Ii1 [ iii11 ] = lisp_get_timestamp ( )
 if 48 - 48: o0oOOo0O0Ooo - II111iiii + OoOoOO00
 if 54 - 54: II111iiii - OoO0O00 - o0oOOo0O0Ooo - O0 % I1Ii111
 if 9 - 9: i1IIi % iII111i / Ii1I
 if 83 - 83: oO0o
 if 1 - 1: oO0o * iIii1I11I1II1 % iIii1I11I1II1 % iIii1I11I1II1 / oO0o + IiII
 if 29 - 29: OoooooooOO
 if ( I1II111 == "?" and iIIiI11iI1Ii1 [ "node" ] == "ETR" ) :
  I111I = lisp_db_for_lookups . lookup_cache ( packet . inner_dest , False )
  if ( I111I != None and len ( I111I . rloc_set ) >= 1 ) :
   I1II111 = I111I . rloc_set [ 0 ] . rloc . print_address_no_iid ( )
   if 55 - 55: O0 - o0oOOo0O0Ooo % I1ii11iIi11i * I11i * oO0o
   if 83 - 83: iIii1I11I1II1
 iIIiI11iI1Ii1 [ "drloc" ] = I1II111
 if 92 - 92: OoO0O00 - iII111i
 if 97 - 97: ooOoO0o / I11i . IiII + I1Ii111 . iIii1I11I1II1
 if 24 - 24: ooOoO0o - oO0o % OoOoOO00 * Oo0Ooo
 if 54 - 54: Ii1I - OoooooooOO % I1IiiI + oO0o
 if ( I1II111 == "?" and reason != None ) :
  iIIiI11iI1Ii1 [ "drloc" ] += " ({})" . format ( reason )
  if 70 - 70: I1Ii111 % iIii1I11I1II1
  if 74 - 74: i1IIi % i11iIiiIii + oO0o
  if 94 - 94: OoO0O00 * I1IiiI / O0 + I1Ii111 / i11iIiiIii
  if 34 - 34: Oo0Ooo . i1IIi
  if 97 - 97: I11i
 if ( rloc_entry != None ) :
  iIIiI11iI1Ii1 [ "rtts" ] = rloc_entry . recent_rloc_probe_rtts
  iIIiI11iI1Ii1 [ "hops" ] = rloc_entry . recent_rloc_probe_hops
  if 89 - 89: iII111i % OoOoOO00 . Oo0Ooo
  if 20 - 20: oO0o % OoOoOO00
  if 93 - 93: I1ii11iIi11i - Ii1I % i1IIi / i1IIi
  if 82 - 82: OOooOOo
  if 27 - 27: I1Ii111 / IiII - i1IIi * Ii1I
  if 90 - 90: ooOoO0o
 I1i1III1i = packet . inner_source . print_address ( )
 O000iI1ii1I = packet . inner_dest . print_address ( )
 if ( i11I1iII . packet_json == [ ] ) :
  oo00Oo = { }
  oo00Oo [ "seid" ] = I1i1III1i
  oo00Oo [ "deid" ] = O000iI1ii1I
  oo00Oo [ "paths" ] = [ ]
  i11I1iII . packet_json . append ( oo00Oo )
  if 100 - 100: iII111i * i1IIi . iII111i / O0 / OoO0O00 - oO0o
  if 65 - 65: OoOoOO00 + ooOoO0o * OoO0O00 % OoooooooOO + OoooooooOO * OoooooooOO
  if 49 - 49: o0oOOo0O0Ooo + i1IIi / iII111i
  if 43 - 43: i1IIi . OoO0O00 + I1ii11iIi11i
  if 88 - 88: OoooooooOO / I11i % II111iiii % OOooOOo - I11i
  if 55 - 55: Oo0Ooo - OOooOOo - O0
 for oo00Oo in i11I1iII . packet_json :
  if ( oo00Oo [ "deid" ] != O000iI1ii1I ) : continue
  oo00Oo [ "paths" ] . append ( iIIiI11iI1Ii1 )
  break
  if 40 - 40: OoOoOO00 - OOooOOo
  if 3 - 3: IiII % I11i * I1Ii111 + iIii1I11I1II1 . oO0o
  if 35 - 35: II111iiii
  if 15 - 15: I11i * iIii1I11I1II1 + OOooOOo % IiII . o0oOOo0O0Ooo % Oo0Ooo
  if 96 - 96: O0
  if 15 - 15: i1IIi . iIii1I11I1II1
  if 3 - 3: II111iiii * i11iIiiIii * i1IIi - i1IIi
  if 11 - 11: I1IiiI % Ii1I * i11iIiiIii % OOooOOo + II111iiii
 o0O0OO = False
 if ( len ( i11I1iII . packet_json ) == 1 and iIIiI11iI1Ii1 [ "node" ] == "ETR" and
 i11I1iII . myeid ( packet . inner_dest ) ) :
  oo00Oo = { }
  oo00Oo [ "seid" ] = O000iI1ii1I
  oo00Oo [ "deid" ] = I1i1III1i
  oo00Oo [ "paths" ] = [ ]
  i11I1iII . packet_json . append ( oo00Oo )
  o0O0OO = True
  if 9 - 9: OoooooooOO - Oo0Ooo - I1ii11iIi11i * o0oOOo0O0Ooo * I11i
  if 27 - 27: OoOoOO00 % OoO0O00 * oO0o . II111iiii - i11iIiiIii
  if 56 - 56: OOooOOo . IiII - OOooOOo / i11iIiiIii * I1ii11iIi11i
  if 66 - 66: oO0o + ooOoO0o
  if 1 - 1: ooOoO0o
  if 61 - 61: o0oOOo0O0Ooo / OoooooooOO . I1ii11iIi11i + Oo0Ooo
 i11I1iII . print_trace ( )
 IIi1iiIIii1Ii = i11I1iII . encode ( )
 if 75 - 75: Ii1I
 if 79 - 79: i1IIi . I1ii11iIi11i * o0oOOo0O0Ooo / I11i . I11i / ooOoO0o
 if 99 - 99: oO0o + I11i % i1IIi . iII111i
 if 58 - 58: Oo0Ooo % i11iIiiIii . Oo0Ooo / Oo0Ooo - I1IiiI . Ii1I
 if 65 - 65: OoO0O00
 if 16 - 16: IiII % I1IiiI % iIii1I11I1II1 . I1IiiI . I1ii11iIi11i - IiII
 if 6 - 6: I1Ii111 + OoO0O00 + O0 * OoOoOO00 . iIii1I11I1II1 . I1Ii111
 if 93 - 93: ooOoO0o % iIii1I11I1II1 + I1ii11iIi11i
 oOO0ooO = i11I1iII . packet_json [ 0 ] [ "paths" ] [ 0 ] [ "srloc" ]
 if ( I1II111 == "?" ) :
  lprint ( "LISP-Trace return to sender RLOC {}" . format ( oOO0ooO ) )
  i11I1iII . return_to_sender ( lisp_socket , oOO0ooO , IIi1iiIIii1Ii )
  return ( False )
  if 91 - 91: I11i
  if 24 - 24: o0oOOo0O0Ooo
  if 78 - 78: OOooOOo + iIii1I11I1II1 - OoO0O00 + ooOoO0o + Oo0Ooo / Oo0Ooo
  if 15 - 15: iIii1I11I1II1 . I1Ii111 * OoooooooOO * O0 % OOooOOo
  if 53 - 53: Ii1I
  if 63 - 63: I11i % OoOoOO00
 IiI = i11I1iII . packet_length ( )
 if 46 - 46: iIii1I11I1II1 . II111iiii / OoooooooOO - ooOoO0o * iII111i
 if 52 - 52: I11i + iII111i
 if 9 - 9: OoOoOO00 % II111iiii . I11i * Oo0Ooo
 if 53 - 53: II111iiii / i1IIi + OoooooooOO * O0
 if 62 - 62: IiII . O0
 if 87 - 87: I1ii11iIi11i / oO0o / IiII . OOooOOo
 O0oOoOOOOo = packet . packet [ 0 : I11iiIi1i1 ]
 OoOoO = struct . pack ( "HH" , socket . htons ( IiI ) , 0 )
 O0oOoOOOOo = O0oOoOOOOo [ 0 : I11iiIi1i1 - 4 ] + OoOoO
 if ( packet . inner_version == 6 and iIIiI11iI1Ii1 [ "node" ] == "ETR" and
 len ( i11I1iII . packet_json ) == 2 ) :
  I1iIIIiI = O0oOoOOOOo [ I11iiIi1i1 - 8 : : ] + IIi1iiIIii1Ii
  I1iIIIiI = lisp_udp_checksum ( I1i1III1i , O000iI1ii1I , I1iIIIiI )
  O0oOoOOOOo = O0oOoOOOOo [ 0 : I11iiIi1i1 - 8 ] + I1iIIIiI [ 0 : 8 ]
  if 66 - 66: OoOoOO00 . Ii1I / i11iIiiIii / ooOoO0o
  if 76 - 76: OoO0O00 % OoO0O00 / I1ii11iIi11i * ooOoO0o * o0oOOo0O0Ooo - I1Ii111
  if 53 - 53: OoO0O00 % Oo0Ooo . i1IIi
  if 34 - 34: Ii1I - o0oOOo0O0Ooo * i1IIi
  if 7 - 7: OoO0O00 * I1ii11iIi11i / I1Ii111
  if 98 - 98: II111iiii % I1ii11iIi11i
 if ( o0O0OO ) :
  if ( packet . inner_version == 4 ) :
   O0oOoOOOOo = O0oOoOOOOo [ 0 : 12 ] + O0oOoOOOOo [ 16 : 20 ] + O0oOoOOOOo [ 12 : 16 ] + O0oOoOOOOo [ 22 : 24 ] + O0oOoOOOOo [ 20 : 22 ] + O0oOoOOOOo [ 24 : : ]
   if 48 - 48: iII111i % oO0o + oO0o - Oo0Ooo . OOooOOo
  else :
   O0oOoOOOOo = O0oOoOOOOo [ 0 : 8 ] + O0oOoOOOOo [ 24 : 40 ] + O0oOoOOOOo [ 8 : 24 ] + O0oOoOOOOo [ 42 : 44 ] + O0oOoOOOOo [ 40 : 42 ] + O0oOoOOOOo [ 44 : : ]
   if 38 - 38: iII111i
   if 66 - 66: iII111i + Oo0Ooo + i1IIi * Oo0Ooo
  oOo0OOOOOO = packet . inner_dest
  packet . inner_dest = packet . inner_source
  packet . inner_source = oOo0OOOOOO
  if 18 - 18: O0 - IiII
  if 5 - 5: I1ii11iIi11i * iII111i + II111iiii * Oo0Ooo * O0 - I1IiiI
  if 71 - 71: i11iIiiIii % I1IiiI + I1ii11iIi11i + II111iiii + OoooooooOO + oO0o
  if 12 - 12: I1IiiI + I1Ii111
  if 66 - 66: I1Ii111 + OOooOOo + I1Ii111 . OoooooooOO * oO0o / OoO0O00
 I11iiIi1i1 = 2 if packet . inner_version == 4 else 4
 Oo0OoOOOO0 = 20 + IiI if packet . inner_version == 4 else IiI
 Ii11i1Iiii11 = struct . pack ( "H" , socket . htons ( Oo0OoOOOO0 ) )
 O0oOoOOOOo = O0oOoOOOOo [ 0 : I11iiIi1i1 ] + Ii11i1Iiii11 + O0oOoOOOOo [ I11iiIi1i1 + 2 : : ]
 if 24 - 24: IiII % Ii1I / ooOoO0o
 if 52 - 52: iII111i % iIii1I11I1II1 - Oo0Ooo - iIii1I11I1II1 * I1ii11iIi11i - OoO0O00
 if 26 - 26: i11iIiiIii % I11i % o0oOOo0O0Ooo % OoOoOO00 / iII111i - OOooOOo
 if 17 - 17: i1IIi - Ii1I . ooOoO0o % I1Ii111 . OoooooooOO / oO0o
 if ( packet . inner_version == 4 ) :
  Oo0ooooO0o00 = struct . pack ( "H" , 0 )
  O0oOoOOOOo = O0oOoOOOOo [ 0 : 10 ] + Oo0ooooO0o00 + O0oOoOOOOo [ 12 : : ]
  Ii11i1Iiii11 = lisp_ip_checksum ( O0oOoOOOOo [ 0 : 20 ] )
  O0oOoOOOOo = Ii11i1Iiii11 + O0oOoOOOOo [ 20 : : ]
  if 91 - 91: ooOoO0o % I1ii11iIi11i
  if 60 - 60: O0 * Oo0Ooo * IiII % OoOoOO00 . OoOoOO00
  if 4 - 4: I1Ii111 % I1Ii111 * O0
  if 54 - 54: I1ii11iIi11i - IiII . OoO0O00 + I1ii11iIi11i / I1IiiI
  if 91 - 91: OOooOOo % Oo0Ooo
 packet . packet = O0oOoOOOOo + IIi1iiIIii1Ii
 return ( True )
 if 44 - 44: iIii1I11I1II1 . OOooOOo
 if 57 - 57: II111iiii + I1Ii111
 if 42 - 42: OoOoOO00 % O0
 if 70 - 70: iIii1I11I1II1 * Oo0Ooo - I1IiiI / OoO0O00 + OoOoOO00
 if 94 - 94: OoooooooOO + O0 * iIii1I11I1II1 * II111iiii
 if 90 - 90: I11i + O0 / I1IiiI . oO0o / O0
 if 46 - 46: O0 . O0 - oO0o . II111iiii * I1IiiI * Ii1I
 if 10 - 10: i1IIi + i1IIi . i1IIi - I1IiiI - I1IiiI
 if 26 - 26: Ii1I * I11i / I11i
 if 79 - 79: ooOoO0o / oO0o - oO0o / OoooooooOO
def lisp_allow_gleaning ( eid , rloc ) :
 if ( lisp_glean_mappings == [ ] ) : return ( False , False )
 if 91 - 91: iIii1I11I1II1 - O0 * o0oOOo0O0Ooo * o0oOOo0O0Ooo . II111iiii
 for iIIiI11iI1Ii1 in lisp_glean_mappings :
  if ( iIIiI11iI1Ii1 . has_key ( "instance-id" ) ) :
   o0OOoOO = eid . instance_id
   OO000Oo , O00O00o0O0O = iIIiI11iI1Ii1 [ "instance-id" ]
   if ( o0OOoOO < OO000Oo or o0OOoOO > O00O00o0O0O ) : continue
   if 69 - 69: II111iiii - Oo0Ooo + i1IIi . II111iiii + o0oOOo0O0Ooo
  if ( iIIiI11iI1Ii1 . has_key ( "eid-prefix" ) ) :
   ooo0OO = copy . deepcopy ( iIIiI11iI1Ii1 [ "eid-prefix" ] )
   ooo0OO . instance_id = eid . instance_id
   if ( eid . is_more_specific ( ooo0OO ) == False ) : continue
   if 20 - 20: OoooooooOO - OoO0O00 * ooOoO0o * OoOoOO00 / OOooOOo
  if ( iIIiI11iI1Ii1 . has_key ( "rloc-prefix" ) ) :
   if ( rloc != None and rloc . is_more_specific ( iIIiI11iI1Ii1 [ "rloc-prefix" ] )
 == False ) : continue
   if 64 - 64: O0 + iII111i / I11i * OoOoOO00 + o0oOOo0O0Ooo + I1Ii111
  return ( True , iIIiI11iI1Ii1 [ "rloc-probe" ] )
  if 16 - 16: I11i
 return ( False , False )
 if 9 - 9: Ii1I / IiII * I11i - i11iIiiIii * I1ii11iIi11i / iII111i
 if 61 - 61: O0 % iII111i
 if 41 - 41: I1Ii111 * OoooooooOO
 if 76 - 76: OoooooooOO * II111iiii . II111iiii / o0oOOo0O0Ooo - iII111i
 if 49 - 49: O0 . I1ii11iIi11i . OoOoOO00 . I1Ii111 % O0 . iIii1I11I1II1
 if 19 - 19: iIii1I11I1II1
 if 97 - 97: Ii1I . I11i / ooOoO0o + Oo0Ooo
def lisp_glean_map_cache ( eid , rloc , encap_port ) :
 if 100 - 100: iII111i / I1Ii111 % OoOoOO00 . O0 / OoOoOO00
 if 81 - 81: OoO0O00 % i11iIiiIii / OoO0O00 + ooOoO0o
 if 100 - 100: O0 . Oo0Ooo % Oo0Ooo % O0 / i11iIiiIii
 if 56 - 56: IiII - OOooOOo - OoOoOO00 - I11i
 if 57 - 57: i1IIi
 if 41 - 41: I11i / Ii1I
 IIII = lisp_map_cache . lookup_cache ( eid , True )
 if ( IIII ) :
  IIII . last_refresh_time = lisp_get_timestamp ( )
  if 1 - 1: II111iiii / iII111i
  oO0OOoOOo0OO0oOOo = IIII . rloc_set [ 0 ]
  if ( oO0OOoOOo0OO0oOOo . rloc . is_exact_match ( rloc ) and
 oO0OOoOOo0OO0oOOo . translated_port == encap_port ) : return
  if 35 - 35: I1ii11iIi11i + OoOoOO00 / OoOoOO00 . oO0o
  ooo0OO = green ( eid . print_address ( ) , False )
  iIIIIIi11Ii = red ( rloc . print_address_no_iid ( ) + ":" + str ( encap_port ) , False )
  lprint ( "Gleaned EID {} RLOC changed to {}" . format ( ooo0OO , iIIIIIi11Ii ) )
  oO0OOoOOo0OO0oOOo . delete_from_rloc_probe_list ( IIII . eid , IIII . group )
 else :
  IIII = lisp_mapping ( "" , "" , [ ] )
  IIII . eid . copy_address ( eid )
  IIII . mapping_source . copy_address ( rloc )
  IIII . map_cache_ttl = LISP_GLEAN_TTL
  IIII . gleaned = True
  ooo0OO = green ( eid . print_address ( ) , False )
  iIIIIIi11Ii = red ( rloc . print_address_no_iid ( ) + ":" + str ( encap_port ) , False )
  lprint ( "Add gleaned EID {} to map-cache with RLOC {}" . format ( ooo0OO , iIIIIIi11Ii ) )
  IIII . add_cache ( )
  if 71 - 71: IiII % I1IiiI + OoOoOO00 . II111iiii / I11i
  if 46 - 46: OoOoOO00
  if 56 - 56: iIii1I11I1II1 - iIii1I11I1II1
  if 46 - 46: o0oOOo0O0Ooo
  if 67 - 67: OOooOOo - i11iIiiIii / oO0o * i11iIiiIii
  if 88 - 88: Ii1I - OoO0O00 * OoooooooOO - I1IiiI * I1ii11iIi11i
 IiI1I1iii11 = lisp_rloc ( )
 IiI1I1iii11 . store_translated_rloc ( rloc , encap_port )
 IiI1I1iii11 . add_to_rloc_probe_list ( IIII . eid , IIII . group )
 IiI1I1iii11 . priority = 253
 IiI1I1iii11 . mpriority = 255
 oooo0O = [ IiI1I1iii11 ]
 IIII . rloc_set = oooo0O
 IIII . build_best_rloc_set ( )
 if 52 - 52: oO0o % iII111i - I1IiiI - o0oOOo0O0Ooo
 if 66 - 66: o0oOOo0O0Ooo - Oo0Ooo - OoooooooOO * o0oOOo0O0Ooo + I1Ii111
 if 82 - 82: I11i * i1IIi / Ii1I + O0
# dd678faae9ac167bc83abf78e5cb2f3f0688d3a3
