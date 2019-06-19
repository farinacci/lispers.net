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
def lisp_on_aws ( ) :
 OO0 = commands . getoutput ( "sudo dmidecode -s bios-version" )
 return ( OO0 . lower ( ) . find ( "amazon" ) != - 1 )
 if 44 - 44: iII111i - I1Ii111 / O0 * Oo0Ooo + II111iiii / OoOoOO00
 if 88 - 88: o0oOOo0O0Ooo - OoO0O00 + I1ii11iIi11i . I1Ii111 % I1Ii111
 if 57 - 57: II111iiii
 if 54 - 54: Oo0Ooo + oO0o + i11iIiiIii
 if 28 - 28: oO0o
 if 70 - 70: IiII
 if 34 - 34: I1Ii111 % IiII
def lisp_on_gcp ( ) :
 OO0 = commands . getoutput ( "sudo dmidecode -s bios-version" )
 return ( OO0 . lower ( ) . find ( "google" ) != - 1 )
 if 3 - 3: II111iiii / OOooOOo + IiII . ooOoO0o . OoO0O00
 if 83 - 83: oO0o + OoooooooOO
 if 22 - 22: Ii1I % iII111i * OoooooooOO - o0oOOo0O0Ooo / iIii1I11I1II1
 if 86 - 86: OoooooooOO . iII111i % OoOoOO00 / I11i * iII111i / o0oOOo0O0Ooo
 if 64 - 64: i11iIiiIii
 if 38 - 38: IiII / I1IiiI - IiII . I11i
 if 69 - 69: OoooooooOO + I1ii11iIi11i
 if 97 - 97: OOooOOo - OoO0O00 / Ii1I . i11iIiiIii % oO0o * oO0o
def lisp_process_logfile ( ) :
 ii1IIIIiI11 = "./logs/lisp-{}.log" . format ( lisp_log_id )
 if ( os . path . exists ( ii1IIIIiI11 ) ) : return
 if 40 - 40: o0oOOo0O0Ooo
 sys . stdout . close ( )
 sys . stdout = open ( ii1IIIIiI11 , "a" )
 if 67 - 67: oO0o + II111iiii - O0 . oO0o * II111iiii * I11i
 lisp_print_banner ( bold ( "logfile rotation" , False ) )
 return
 if 90 - 90: Ii1I . IiII
 if 81 - 81: OOooOOo - I11i % ooOoO0o - OoO0O00 / Oo0Ooo
 if 4 - 4: OoooooooOO - i1IIi % Ii1I - OOooOOo * o0oOOo0O0Ooo
 if 85 - 85: OoooooooOO * iIii1I11I1II1 . iII111i / OoooooooOO % I1IiiI % O0
 if 36 - 36: Ii1I / II111iiii / IiII / IiII + I1ii11iIi11i
 if 95 - 95: IiII
 if 51 - 51: II111iiii + IiII . i1IIi . I1ii11iIi11i + OoOoOO00 * I1IiiI
 if 72 - 72: oO0o + oO0o / II111iiii . OoooooooOO % Ii1I
def lisp_i_am ( name ) :
 global lisp_log_id , lisp_i_am_itr , lisp_i_am_etr , lisp_i_am_rtr
 global lisp_i_am_mr , lisp_i_am_ms , lisp_i_am_ddt , lisp_i_am_core
 global lisp_hostname
 if 49 - 49: oO0o . OoO0O00 - Oo0Ooo * OoooooooOO . Oo0Ooo
 lisp_log_id = name
 if ( name == "itr" ) : lisp_i_am_itr = True
 if ( name == "etr" ) : lisp_i_am_etr = True
 if ( name == "rtr" ) : lisp_i_am_rtr = True
 if ( name == "mr" ) : lisp_i_am_mr = True
 if ( name == "ms" ) : lisp_i_am_ms = True
 if ( name == "ddt" ) : lisp_i_am_ddt = True
 if ( name == "core" ) : lisp_i_am_core = True
 if 2 - 2: OoooooooOO % OOooOOo
 if 63 - 63: I1IiiI % iIii1I11I1II1
 if 39 - 39: iII111i / II111iiii / I1ii11iIi11i % I1IiiI
 if 89 - 89: I1Ii111 + OoooooooOO + I1Ii111 * i1IIi + iIii1I11I1II1 % I11i
 if 59 - 59: OOooOOo + i11iIiiIii
 lisp_hostname = socket . gethostname ( )
 oo0OOo0O = lisp_hostname . find ( "." )
 if ( oo0OOo0O != - 1 ) : lisp_hostname = lisp_hostname [ 0 : oo0OOo0O ]
 return
 if 39 - 39: OoooooooOO + oO0o % OOooOOo / OOooOOo
 if 27 - 27: iII111i . I11i . iIii1I11I1II1 . iIii1I11I1II1
 if 20 - 20: o0oOOo0O0Ooo / i1IIi
 if 71 - 71: OoOoOO00 . i1IIi
 if 94 - 94: OOooOOo . I1Ii111
 if 84 - 84: O0 . I11i - II111iiii . ooOoO0o / II111iiii
 if 47 - 47: OoooooooOO
def lprint ( * args ) :
 if ( lisp_debug_logging == False ) : return
 if 4 - 4: I1IiiI % I11i
 lisp_process_logfile ( )
 OOOO0O00o = datetime . datetime . now ( ) . strftime ( "%m/%d/%y %H:%M:%S.%f" )
 OOOO0O00o = OOOO0O00o [ : - 3 ]
 print "{}: {}:" . format ( OOOO0O00o , lisp_log_id ) ,
 for I1 in args : print I1 ,
 print ""
 try : sys . stdout . flush ( )
 except : pass
 return
 if 67 - 67: OoO0O00 + oO0o
 if 88 - 88: iII111i
 if 19 - 19: II111iiii * IiII + Ii1I
 if 65 - 65: OOooOOo . I1Ii111 . OoO0O00 . iII111i - OOooOOo
 if 19 - 19: i11iIiiIii + iII111i % ooOoO0o
 if 14 - 14: OoO0O00 . II111iiii . I11i / Ii1I % I1ii11iIi11i - ooOoO0o
 if 67 - 67: I11i - OOooOOo . i1IIi
 if 35 - 35: iII111i + ooOoO0o - oO0o . iII111i . IiII
def dprint ( * args ) :
 if ( lisp_data_plane_logging ) : lprint ( * args )
 return
 if 87 - 87: OoOoOO00
 if 25 - 25: i1IIi . OoO0O00 - OoOoOO00 / OoO0O00 % OoO0O00 * iIii1I11I1II1
 if 50 - 50: OoO0O00 . i11iIiiIii - oO0o . oO0o
 if 31 - 31: OOooOOo / Oo0Ooo * i1IIi . OoOoOO00
 if 57 - 57: OOooOOo + iIii1I11I1II1 % i1IIi % I1IiiI
 if 83 - 83: o0oOOo0O0Ooo / i11iIiiIii % iIii1I11I1II1 . I11i % oO0o . OoooooooOO
 if 94 - 94: Ii1I + iIii1I11I1II1 % OoO0O00
 if 93 - 93: Ii1I - OOooOOo + iIii1I11I1II1 * o0oOOo0O0Ooo + I1Ii111 . iII111i
def debug ( * args ) :
 lisp_process_logfile ( )
 if 49 - 49: OoooooooOO * I11i - Oo0Ooo . oO0o
 OOOO0O00o = datetime . datetime . now ( ) . strftime ( "%m/%d/%y %H:%M:%S.%f" )
 OOOO0O00o = OOOO0O00o [ : - 3 ]
 if 89 - 89: ooOoO0o + Ii1I * ooOoO0o / ooOoO0o
 print red ( ">>>" , False ) ,
 print "{}:" . format ( OOOO0O00o ) ,
 for I1 in args : print I1 ,
 print red ( "<<<\n" , False )
 try : sys . stdout . flush ( )
 except : pass
 return
 if 46 - 46: OoO0O00
 if 71 - 71: I11i / I11i * oO0o * oO0o / II111iiii
 if 35 - 35: OOooOOo * o0oOOo0O0Ooo * I1IiiI % Oo0Ooo . OoOoOO00
 if 58 - 58: I11i + II111iiii * iII111i * i11iIiiIii - iIii1I11I1II1
 if 68 - 68: OoooooooOO % II111iiii
 if 26 - 26: II111iiii % i11iIiiIii % iIii1I11I1II1 % I11i * I11i * I1ii11iIi11i
 if 24 - 24: II111iiii % I1Ii111 - ooOoO0o + I1IiiI * I1ii11iIi11i
def lisp_print_banner ( string ) :
 global lisp_version , lisp_hostname
 if 2 - 2: Ii1I - IiII
 if ( lisp_version == "" ) :
  lisp_version = commands . getoutput ( "cat lisp-version.txt" )
  if 83 - 83: oO0o % o0oOOo0O0Ooo % Ii1I - II111iiii * OOooOOo / OoooooooOO
 IIIiIi = bold ( lisp_hostname , False )
 lprint ( "lispers.net LISP {} {}, version {}, hostname {}" . format ( string ,
 datetime . datetime . now ( ) , lisp_version , IIIiIi ) )
 return
 if 34 - 34: OoooooooOO . O0 / oO0o * OoOoOO00 - I1ii11iIi11i
 if 36 - 36: i1IIi / O0 / OoO0O00 - O0 - i1IIi
 if 22 - 22: i1IIi + Ii1I
 if 54 - 54: ooOoO0o % OOooOOo . I1Ii111 + oO0o - OOooOOo * I1IiiI
 if 92 - 92: o0oOOo0O0Ooo + I1Ii111 / Oo0Ooo % OoO0O00 % IiII . OoooooooOO
 if 52 - 52: ooOoO0o / i11iIiiIii - OOooOOo . IiII % iIii1I11I1II1 + o0oOOo0O0Ooo
 if 71 - 71: oO0o % I11i * OoOoOO00 . O0 / Ii1I . I1ii11iIi11i
def green ( string , html ) :
 if ( html ) : return ( '<font color="green"><b>{}</b></font>' . format ( string ) )
 return ( bold ( "\033[92m" + string + "\033[0m" , html ) )
 if 58 - 58: Oo0Ooo / oO0o
 if 44 - 44: OOooOOo
 if 54 - 54: Ii1I - I11i - I1Ii111 . iIii1I11I1II1
 if 79 - 79: Ii1I . OoO0O00
 if 40 - 40: o0oOOo0O0Ooo + Oo0Ooo . o0oOOo0O0Ooo % ooOoO0o
 if 15 - 15: Ii1I * Oo0Ooo % I1ii11iIi11i * iIii1I11I1II1 - i11iIiiIii
 if 60 - 60: I1IiiI * I1Ii111 % OoO0O00 + oO0o
def green_last_sec ( string ) :
 return ( green ( string , True ) )
 if 52 - 52: i1IIi
 if 84 - 84: Ii1I / IiII
 if 86 - 86: OoOoOO00 * II111iiii - O0 . OoOoOO00 % iIii1I11I1II1 / OOooOOo
 if 11 - 11: I1IiiI * oO0o + I1ii11iIi11i / I1ii11iIi11i
 if 37 - 37: i11iIiiIii + i1IIi
 if 23 - 23: iII111i + I11i . OoOoOO00 * I1IiiI + I1ii11iIi11i
 if 18 - 18: IiII * o0oOOo0O0Ooo . IiII / O0
def green_last_min ( string ) :
 return ( '<font color="#58D68D"><b>{}</b></font>' . format ( string ) )
 if 8 - 8: o0oOOo0O0Ooo
 if 4 - 4: I1ii11iIi11i + I1ii11iIi11i * ooOoO0o - OoOoOO00
 if 78 - 78: Ii1I / II111iiii % OoOoOO00
 if 52 - 52: OOooOOo - iII111i * oO0o
 if 17 - 17: OoooooooOO + OOooOOo * I11i * OoOoOO00
 if 36 - 36: O0 + Oo0Ooo
 if 5 - 5: Oo0Ooo * OoOoOO00
def red ( string , html ) :
 if ( html ) : return ( '<font color="red"><b>{}</b></font>' . format ( string ) )
 return ( bold ( "\033[91m" + string + "\033[0m" , html ) )
 if 46 - 46: ooOoO0o
 if 33 - 33: iII111i - II111iiii * OoooooooOO - Oo0Ooo - OOooOOo
 if 84 - 84: I1Ii111 + Oo0Ooo - OoOoOO00 * OoOoOO00
 if 61 - 61: OoooooooOO . oO0o . OoooooooOO / Oo0Ooo
 if 72 - 72: i1IIi
 if 82 - 82: OoOoOO00 + OoooooooOO / i11iIiiIii * I1ii11iIi11i . OoooooooOO
 if 63 - 63: I1ii11iIi11i
def blue ( string , html ) :
 if ( html ) : return ( '<font color="blue"><b>{}</b></font>' . format ( string ) )
 return ( bold ( "\033[94m" + string + "\033[0m" , html ) )
 if 6 - 6: ooOoO0o / I1ii11iIi11i
 if 57 - 57: I11i
 if 67 - 67: OoO0O00 . ooOoO0o
 if 87 - 87: oO0o % Ii1I
 if 83 - 83: II111iiii - I11i
 if 35 - 35: i1IIi - iIii1I11I1II1 + i1IIi
 if 86 - 86: iIii1I11I1II1 + OoOoOO00 . i11iIiiIii - Ii1I
def bold ( string , html ) :
 if ( html ) : return ( "<b>{}</b>" . format ( string ) )
 return ( "\033[1m" + string + "\033[0m" )
 if 51 - 51: OoOoOO00
 if 14 - 14: IiII % oO0o % Oo0Ooo - i11iIiiIii
 if 53 - 53: Ii1I % Oo0Ooo
 if 59 - 59: OOooOOo % iIii1I11I1II1 . i1IIi + II111iiii * IiII
 if 41 - 41: Ii1I % I1ii11iIi11i
 if 12 - 12: OOooOOo
 if 69 - 69: OoooooooOO + OOooOOo
def convert_font ( string ) :
 IIi11I1 = [ [ "[91m" , red ] , [ "[92m" , green ] , [ "[94m" , blue ] , [ "[1m" , bold ] ]
 iiiI111I = "[0m"
 if 75 - 75: OoooooooOO % OoO0O00 / I1IiiI
 for Oo0ooo0Ooo in IIi11I1 :
  i1II1I = Oo0ooo0Ooo [ 0 ]
  OOoO0ooOO = Oo0ooo0Ooo [ 1 ]
  ii = len ( i1II1I )
  oo0OOo0O = string . find ( i1II1I )
  if ( oo0OOo0O != - 1 ) : break
  if 1 - 1: ooOoO0o
  if 78 - 78: I1ii11iIi11i + I11i - O0
 while ( oo0OOo0O != - 1 ) :
  i1I1iIi1IiI = string [ oo0OOo0O : : ] . find ( iiiI111I )
  i1111 = string [ oo0OOo0O + ii : oo0OOo0O + i1I1iIi1IiI ]
  string = string [ : oo0OOo0O ] + OOoO0ooOO ( i1111 , True ) + string [ oo0OOo0O + i1I1iIi1IiI + ii : : ]
  if 82 - 82: ooOoO0o % Ii1I - ooOoO0o % OoOoOO00
  oo0OOo0O = string . find ( i1II1I )
  if 47 - 47: iIii1I11I1II1 . oO0o . OOooOOo * i1IIi
  if 32 - 32: i11iIiiIii - i1IIi % OOooOOo . O0 % OoOoOO00 * Oo0Ooo
  if 90 - 90: OOooOOo * I1Ii111
  if 50 - 50: IiII % i1IIi
  if 21 - 21: OoooooooOO - iIii1I11I1II1
 if ( string . find ( "[1m" ) != - 1 ) : string = convert_font ( string )
 return ( string )
 if 93 - 93: oO0o - o0oOOo0O0Ooo % OoOoOO00 . OoOoOO00 - ooOoO0o
 if 90 - 90: ooOoO0o + II111iiii * I1ii11iIi11i / Ii1I . o0oOOo0O0Ooo + o0oOOo0O0Ooo
 if 40 - 40: ooOoO0o / OoOoOO00 % i11iIiiIii % I1ii11iIi11i / I1IiiI
 if 62 - 62: i1IIi - OoOoOO00
 if 62 - 62: i1IIi + Oo0Ooo % IiII
 if 28 - 28: I1ii11iIi11i . i1IIi
 if 10 - 10: OoO0O00 / Oo0Ooo
def lisp_space ( num ) :
 I1i = ""
 for II11iIII1i1I in range ( num ) : I1i += "&#160;"
 return ( I1i )
 if 63 - 63: Oo0Ooo + I1Ii111 - II111iiii
 if 2 - 2: IiII
 if 97 - 97: oO0o - OoooooooOO
 if 79 - 79: OoOoOO00 % IiII % Oo0Ooo
 if 29 - 29: OoooooooOO . I1IiiI % I1ii11iIi11i - iII111i
 if 8 - 8: i1IIi
 if 32 - 32: oO0o / II111iiii
def lisp_button ( string , url ) :
 II1Iii = '<button style="background-color:transparent;border-radius:10px; ' + 'type="button">'
 if 73 - 73: I11i * OoooooooOO . O0 . IiII
 if 55 - 55: Oo0Ooo
 if ( url == None ) :
  ooO0o = II1Iii + string + "</button>"
 else :
  ii1iI1iI1 = '<a href="{}">' . format ( url )
  o00oOOO = lisp_space ( 2 )
  ooO0o = o00oOOO + ii1iI1iI1 + II1Iii + string + "</button></a>" + o00oOOO
  if 57 - 57: I1IiiI - o0oOOo0O0Ooo + OoO0O00 % Oo0Ooo
 return ( ooO0o )
 if 26 - 26: iII111i . iII111i
 if 35 - 35: I1Ii111 . OoOoOO00 * i11iIiiIii
 if 44 - 44: i11iIiiIii / Oo0Ooo
 if 42 - 42: OoooooooOO + Oo0Ooo % II111iiii + OoO0O00
 if 24 - 24: iII111i * II111iiii % iII111i % IiII + OoooooooOO
 if 29 - 29: II111iiii - OoooooooOO - i11iIiiIii . o0oOOo0O0Ooo
 if 19 - 19: II111iiii
def lisp_print_cour ( string ) :
 I1i = '<font face="Courier New">{}</font>' . format ( string )
 return ( I1i )
 if 72 - 72: OoooooooOO / I1IiiI + Ii1I / OoOoOO00 * Ii1I
 if 34 - 34: O0 * O0 % OoooooooOO + iII111i * iIii1I11I1II1 % Ii1I
 if 25 - 25: I11i + OoOoOO00 . o0oOOo0O0Ooo % OoOoOO00 * OOooOOo
 if 32 - 32: i11iIiiIii - I1Ii111
 if 53 - 53: OoooooooOO - IiII
 if 87 - 87: oO0o . I1IiiI
 if 17 - 17: Ii1I . i11iIiiIii
def lisp_print_sans ( string ) :
 I1i = '<font face="Sans-Serif">{}</font>' . format ( string )
 return ( I1i )
 if 5 - 5: I1ii11iIi11i + O0 + O0 . I1Ii111 - ooOoO0o
 if 63 - 63: oO0o
 if 71 - 71: i1IIi . Ii1I * iII111i % OoooooooOO + OOooOOo
 if 36 - 36: IiII
 if 49 - 49: OOooOOo / OoooooooOO / I1IiiI
 if 74 - 74: I1Ii111 % I1ii11iIi11i
 if 7 - 7: II111iiii
def lisp_span ( string , hover_string ) :
 I1i = '<span title="{}">{}</span>' . format ( hover_string , string )
 return ( I1i )
 if 27 - 27: oO0o . OoooooooOO + i11iIiiIii
 if 86 - 86: I11i / o0oOOo0O0Ooo - o0oOOo0O0Ooo + I1ii11iIi11i + oO0o
 if 33 - 33: o0oOOo0O0Ooo . iII111i . IiII . i1IIi
 if 49 - 49: I1ii11iIi11i
 if 84 - 84: I11i - Oo0Ooo / O0 - I1Ii111
 if 21 - 21: O0 * O0 % I1ii11iIi11i
 if 94 - 94: I11i + II111iiii % i11iIiiIii
def lisp_eid_help_hover ( output ) :
 i1i1IiIiIi1Ii = '''Unicast EID format:
  For longest match lookups: 
    <address> or [<iid>]<address>
  For exact match lookups: 
    <prefix> or [<iid>]<prefix>
Multicast EID format:
  For longest match lookups:
    <address>-><group> or
    [<iid>]<address>->[<iid>]<group>'''
 if 64 - 64: OOooOOo + OoooooooOO * OoooooooOO
 if 41 - 41: ooOoO0o . Oo0Ooo + I1IiiI
 o0O0OO = lisp_span ( output , i1i1IiIiIi1Ii )
 return ( o0O0OO )
 if 22 - 22: II111iiii * OoO0O00 * I11i + I1ii11iIi11i * o0oOOo0O0Ooo
 if 100 - 100: i1IIi / IiII
 if 3 - 3: II111iiii % I1ii11iIi11i - OoooooooOO * Oo0Ooo . iIii1I11I1II1
 if 37 - 37: iII111i / Oo0Ooo . I11i * I11i
 if 80 - 80: OOooOOo % I1ii11iIi11i
 if 91 - 91: I11i / O0 - Ii1I . I1IiiI
 if 82 - 82: IiII * OOooOOo / oO0o
def lisp_geo_help_hover ( output ) :
 i1i1IiIiIi1Ii = '''EID format:
    <address> or [<iid>]<address>
    '<name>' or [<iid>]'<name>'
Geo-Point format:
    d-m-s-<N|S>-d-m-s-<W|E> or 
    [<iid>]d-m-s-<N|S>-d-m-s-<W|E>
Geo-Prefix format:
    d-m-s-<N|S>-d-m-s-<W|E>/<km> or
    [<iid>]d-m-s-<N|S>-d-m-s-<W|E>/<km>'''
 if 2 - 2: I1IiiI + o0oOOo0O0Ooo . o0oOOo0O0Ooo . O0 / I11i
 if 40 - 40: o0oOOo0O0Ooo - II111iiii / Oo0Ooo
 o0O0OO = lisp_span ( output , i1i1IiIiIi1Ii )
 return ( o0O0OO )
 if 14 - 14: I1ii11iIi11i
 if 5 - 5: o0oOOo0O0Ooo . iIii1I11I1II1 % iIii1I11I1II1
 if 56 - 56: OoooooooOO - I11i - i1IIi
 if 8 - 8: I1Ii111 / OOooOOo . I1IiiI + I1ii11iIi11i / i11iIiiIii
 if 31 - 31: ooOoO0o - iIii1I11I1II1 + iII111i . Oo0Ooo / IiII % iIii1I11I1II1
 if 6 - 6: IiII * i11iIiiIii % iIii1I11I1II1 % i11iIiiIii + o0oOOo0O0Ooo / i1IIi
 if 53 - 53: I11i + iIii1I11I1II1
def space ( num ) :
 I1i = ""
 for II11iIII1i1I in range ( num ) : I1i += "&#160;"
 return ( I1i )
 if 70 - 70: I1ii11iIi11i
 if 67 - 67: OoooooooOO
 if 29 - 29: O0 - i11iIiiIii - II111iiii + OOooOOo * IiII
 if 2 - 2: i1IIi - ooOoO0o + I1IiiI . o0oOOo0O0Ooo * o0oOOo0O0Ooo / OoOoOO00
 if 93 - 93: i1IIi
 if 53 - 53: OoooooooOO + Oo0Ooo + oO0o
 if 24 - 24: iII111i - IiII - iII111i * I1ii11iIi11i . OoooooooOO / IiII
 if 66 - 66: Oo0Ooo
def lisp_get_ephemeral_port ( ) :
 return ( random . randrange ( 32768 , 65535 ) )
 if 97 - 97: i1IIi - OoooooooOO / I1Ii111 * I1IiiI
 if 55 - 55: o0oOOo0O0Ooo . iII111i
 if 87 - 87: o0oOOo0O0Ooo % iIii1I11I1II1
 if 100 - 100: I1Ii111 . I1IiiI * I1Ii111 - I1IiiI . I11i * Ii1I
 if 89 - 89: OoO0O00 + IiII * I1Ii111
 if 28 - 28: OoooooooOO . oO0o % I1ii11iIi11i / i1IIi / OOooOOo
 if 36 - 36: o0oOOo0O0Ooo + I11i - IiII + iIii1I11I1II1 + OoooooooOO
def lisp_get_data_nonce ( ) :
 return ( random . randint ( 0 , 0xffffff ) )
 if 4 - 4: II111iiii . I11i + Ii1I * I1Ii111 . ooOoO0o
 if 87 - 87: OoOoOO00 / OoO0O00 / i11iIiiIii
 if 74 - 74: oO0o / I1ii11iIi11i % o0oOOo0O0Ooo
 if 88 - 88: OoOoOO00 - i11iIiiIii % o0oOOo0O0Ooo * I11i + I1ii11iIi11i
 if 52 - 52: II111iiii . I1IiiI + OoOoOO00 % OoO0O00
 if 62 - 62: o0oOOo0O0Ooo
 if 15 - 15: I11i + Ii1I . OOooOOo * OoO0O00 . OoOoOO00
def lisp_get_control_nonce ( ) :
 return ( random . randint ( 0 , ( 2 ** 64 ) - 1 ) )
 if 18 - 18: i1IIi % II111iiii + I1Ii111 % Ii1I
 if 72 - 72: iIii1I11I1II1
 if 45 - 45: Oo0Ooo - o0oOOo0O0Ooo % I1Ii111
 if 38 - 38: I1Ii111 % OOooOOo - OoooooooOO
 if 87 - 87: OoO0O00 % I1IiiI
 if 77 - 77: iIii1I11I1II1 - i1IIi . oO0o
 if 26 - 26: o0oOOo0O0Ooo * IiII . i1IIi
 if 59 - 59: O0 + i1IIi - o0oOOo0O0Ooo
 if 62 - 62: i11iIiiIii % OOooOOo . IiII . OOooOOo
def lisp_hex_string ( integer_value ) :
 ooOo0O0O0oOO0 = hex ( integer_value ) [ 2 : : ]
 if ( ooOo0O0O0oOO0 [ - 1 ] == "L" ) : ooOo0O0O0oOO0 = ooOo0O0O0oOO0 [ 0 : - 1 ]
 return ( ooOo0O0O0oOO0 )
 if 10 - 10: Oo0Ooo + O0
 if 43 - 43: iIii1I11I1II1 / II111iiii % o0oOOo0O0Ooo - OOooOOo
 if 62 - 62: I11i
 if 63 - 63: OOooOOo + ooOoO0o * oO0o / o0oOOo0O0Ooo / Oo0Ooo * iIii1I11I1II1
 if 57 - 57: OoOoOO00 - oO0o / ooOoO0o % i11iIiiIii
 if 3 - 3: iII111i . ooOoO0o % I1IiiI + I1ii11iIi11i
 if 64 - 64: i1IIi
def lisp_get_timestamp ( ) :
 return ( time . time ( ) )
 if 29 - 29: o0oOOo0O0Ooo / i11iIiiIii / I1IiiI % oO0o % i11iIiiIii
 if 18 - 18: OOooOOo + I1Ii111
 if 80 - 80: oO0o + o0oOOo0O0Ooo * Ii1I + OoO0O00
 if 75 - 75: I11i / o0oOOo0O0Ooo / OOooOOo / IiII % ooOoO0o + II111iiii
 if 4 - 4: iII111i - Oo0Ooo - IiII - I11i % i11iIiiIii / OoO0O00
 if 50 - 50: ooOoO0o + i1IIi
 if 31 - 31: Ii1I
def lisp_set_timestamp ( seconds ) :
 return ( time . time ( ) + seconds )
 if 78 - 78: i11iIiiIii + o0oOOo0O0Ooo + I1Ii111 / o0oOOo0O0Ooo % iIii1I11I1II1 % IiII
 if 83 - 83: iIii1I11I1II1 % OoOoOO00 % o0oOOo0O0Ooo % I1Ii111 . I1ii11iIi11i % O0
 if 47 - 47: o0oOOo0O0Ooo
 if 66 - 66: I1IiiI - IiII
 if 33 - 33: I1IiiI / OoO0O00
 if 12 - 12: II111iiii
 if 2 - 2: i1IIi - I1IiiI + I11i . II111iiii
def lisp_print_elapsed ( ts ) :
 if ( ts == 0 or ts == None ) : return ( "never" )
 iIIiI1iiI = time . time ( ) - ts
 iIIiI1iiI = round ( iIIiI1iiI , 0 )
 return ( str ( datetime . timedelta ( seconds = iIIiI1iiI ) ) )
 if 18 - 18: iII111i - oO0o % iII111i / I11i
 if 68 - 68: Ii1I * iIii1I11I1II1 + I1Ii111 % OoOoOO00
 if 46 - 46: OoOoOO00 % i1IIi / oO0o * Oo0Ooo * OOooOOo
 if 67 - 67: OoOoOO00 * OoOoOO00 . OoOoOO00 + Ii1I / oO0o
 if 13 - 13: iII111i
 if 80 - 80: Ii1I - o0oOOo0O0Ooo
 if 41 - 41: o0oOOo0O0Ooo - Oo0Ooo * I1IiiI
def lisp_print_future ( ts ) :
 if ( ts == 0 ) : return ( "never" )
 OO0OoOo0OOO = ts - time . time ( )
 if ( OO0OoOo0OOO < 0 ) : return ( "expired" )
 OO0OoOo0OOO = round ( OO0OoOo0OOO , 0 )
 return ( str ( datetime . timedelta ( seconds = OO0OoOo0OOO ) ) )
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
def lisp_print_eid_tuple ( eid , group ) :
 oO00oo000O = eid . print_prefix ( )
 if ( group . is_null ( ) ) : return ( oO00oo000O )
 if 7 - 7: O0 / iII111i * oO0o
 i1iii1ii = group . print_prefix ( )
 II1 = group . instance_id
 if 27 - 27: Ii1I + I1IiiI * iIii1I11I1II1 . OoooooooOO * OoOoOO00
 if ( eid . is_null ( ) or eid . is_exact_match ( group ) ) :
  oo0OOo0O = i1iii1ii . find ( "]" ) + 1
  return ( "[{}](*, {})" . format ( II1 , i1iii1ii [ oo0OOo0O : : ] ) )
  if 100 - 100: OoO0O00 / i1IIi - I1IiiI % Ii1I - iIii1I11I1II1
  if 17 - 17: I11i / o0oOOo0O0Ooo % Oo0Ooo
 o0o = eid . print_sg ( group )
 return ( o0o )
 if 93 - 93: ooOoO0o % i11iIiiIii % I1Ii111
 if 64 - 64: I1Ii111 + I1IiiI * O0 / Oo0Ooo - I11i % I11i
 if 59 - 59: OOooOOo + OoooooooOO
 if 55 - 55: i11iIiiIii % iIii1I11I1II1 . i1IIi + OoooooooOO / i11iIiiIii
 if 10 - 10: iII111i - oO0o * iIii1I11I1II1 % iIii1I11I1II1 * IiII - I1ii11iIi11i
 if 97 - 97: II111iiii % I1Ii111 + I1Ii111 - OoO0O00 / Ii1I * I1IiiI
 if 17 - 17: Ii1I
 if 39 - 39: ooOoO0o . II111iiii
def lisp_convert_6to4 ( addr_str ) :
 if ( addr_str . find ( "::ffff:" ) == - 1 ) : return ( addr_str )
 iIiIi1iI11iiI = addr_str . split ( ":" )
 return ( iIiIi1iI11iiI [ - 1 ] )
 if 26 - 26: iIii1I11I1II1 * I1Ii111 - OOooOOo
 if 27 - 27: I1ii11iIi11i * I1Ii111 - OoO0O00 + Ii1I * Ii1I
 if 55 - 55: ooOoO0o
 if 82 - 82: I1Ii111 - OOooOOo + OoO0O00
 if 64 - 64: o0oOOo0O0Ooo . O0 * Ii1I + OoooooooOO - Oo0Ooo . OoooooooOO
 if 70 - 70: Oo0Ooo - oO0o . iIii1I11I1II1 % I11i / OoOoOO00 - O0
 if 55 - 55: iII111i - OoO0O00
 if 100 - 100: O0
 if 79 - 79: iIii1I11I1II1
 if 81 - 81: OOooOOo + iIii1I11I1II1 * I1Ii111 - iIii1I11I1II1 . OOooOOo
 if 48 - 48: I11i . OoooooooOO . I1IiiI . OoOoOO00 % I1ii11iIi11i / iII111i
def lisp_convert_4to6 ( addr_str ) :
 iIiIi1iI11iiI = lisp_address ( LISP_AFI_IPV6 , "" , 128 , 0 )
 if ( iIiIi1iI11iiI . is_ipv4_string ( addr_str ) ) : addr_str = "::ffff:" + addr_str
 iIiIi1iI11iiI . store_address ( addr_str )
 return ( iIiIi1iI11iiI )
 if 11 - 11: i1IIi % OoO0O00 % iII111i
 if 99 - 99: ooOoO0o / iIii1I11I1II1 - Ii1I * I1ii11iIi11i % I1IiiI
 if 13 - 13: OoO0O00
 if 70 - 70: I1Ii111 + O0 . oO0o * Ii1I
 if 2 - 2: OoooooooOO . OOooOOo . IiII
 if 42 - 42: OOooOOo % oO0o / OoO0O00 - oO0o * i11iIiiIii
 if 19 - 19: oO0o * I1IiiI % i11iIiiIii
 if 24 - 24: o0oOOo0O0Ooo
 if 10 - 10: o0oOOo0O0Ooo % Ii1I / OOooOOo
def lisp_gethostbyname ( string ) :
 i11Ii1iIiII = string . split ( "." )
 O0oOo00Ooo0o0 = string . split ( ":" )
 i1IiII1i1I = string . split ( "-" )
 if 39 - 39: I11i
 if ( len ( i11Ii1iIiII ) > 1 ) :
  if ( i11Ii1iIiII [ 0 ] . isdigit ( ) ) : return ( string )
  if 64 - 64: iIii1I11I1II1 / O0 % IiII . OoooooooOO + IiII + oO0o
 if ( len ( O0oOo00Ooo0o0 ) > 1 ) :
  try :
   int ( O0oOo00Ooo0o0 [ 0 ] , 16 )
   return ( string )
  except :
   pass
   if 79 - 79: OoooooooOO - IiII * IiII . OoOoOO00
   if 100 - 100: II111iiii * I11i % I1IiiI / I1ii11iIi11i
   if 90 - 90: I1ii11iIi11i . ooOoO0o . OoOoOO00 . Ii1I
   if 4 - 4: Ii1I + OoOoOO00 % I1ii11iIi11i / i11iIiiIii
   if 74 - 74: II111iiii . O0 - I1IiiI + IiII % i11iIiiIii % OoOoOO00
   if 78 - 78: Ii1I + OoOoOO00 + IiII - IiII . i11iIiiIii / OoO0O00
   if 27 - 27: Ii1I - O0 % I11i * I1Ii111 . IiII % iIii1I11I1II1
 if ( len ( i1IiII1i1I ) == 3 ) :
  for II11iIII1i1I in range ( 3 ) :
   try : int ( i1IiII1i1I [ II11iIII1i1I ] , 16 )
   except : break
   if 37 - 37: OoooooooOO + O0 - i1IIi % ooOoO0o
   if 24 - 24: OoOoOO00
   if 94 - 94: i1IIi * i1IIi % II111iiii + OOooOOo
 try :
  iIiIi1iI11iiI = socket . gethostbyname ( string )
  return ( iIiIi1iI11iiI )
 except :
  if ( lisp_is_alpine ( ) == False ) : return ( "" )
  if 28 - 28: I1IiiI
  if 49 - 49: I11i . o0oOOo0O0Ooo % oO0o / Ii1I
  if 95 - 95: O0 * OoOoOO00 * IiII . ooOoO0o / iIii1I11I1II1
  if 28 - 28: IiII + oO0o - ooOoO0o / iIii1I11I1II1 - I1IiiI
  if 45 - 45: O0 / i1IIi * oO0o * OoO0O00
 try :
  iIiIi1iI11iiI = socket . getaddrinfo ( string , 0 ) [ 0 ]
  if ( iIiIi1iI11iiI [ 3 ] != string ) : return ( "" )
  iIiIi1iI11iiI = iIiIi1iI11iiI [ 4 ] [ 0 ]
 except :
  iIiIi1iI11iiI = ""
  if 35 - 35: I1ii11iIi11i / iII111i % I1IiiI + iIii1I11I1II1
 return ( iIiIi1iI11iiI )
 if 79 - 79: OoOoOO00 / ooOoO0o
 if 77 - 77: Oo0Ooo
 if 46 - 46: I1Ii111
 if 72 - 72: iII111i * OOooOOo
 if 67 - 67: i1IIi
 if 5 - 5: II111iiii . OoooooooOO
 if 57 - 57: I1IiiI
 if 35 - 35: OoooooooOO - I1Ii111 / OoO0O00
def lisp_ip_checksum ( data ) :
 if ( len ( data ) < 20 ) :
  lprint ( "IPv4 packet too short, length {}" . format ( len ( data ) ) )
  return ( data )
  if 50 - 50: OoOoOO00
  if 33 - 33: I11i
 oOo00OoO0O = binascii . hexlify ( data )
 if 69 - 69: iIii1I11I1II1 * I1IiiI - iII111i + O0 + O0
 if 65 - 65: I1Ii111 / i11iIiiIii / OoO0O00 - OOooOOo
 if 9 - 9: I1IiiI / I1Ii111 - Oo0Ooo * iIii1I11I1II1
 if 86 - 86: II111iiii + ooOoO0o + IiII
 I11i11I = 0
 for II11iIII1i1I in range ( 0 , 40 , 4 ) :
  I11i11I += int ( oOo00OoO0O [ II11iIII1i1I : II11iIII1i1I + 4 ] , 16 )
  if 90 - 90: I1ii11iIi11i
  if 9 - 9: IiII + ooOoO0o
  if 7 - 7: O0 % I1Ii111 + I1ii11iIi11i + Ii1I % OoooooooOO . Oo0Ooo
  if 56 - 56: iII111i
  if 84 - 84: OoOoOO00 - i11iIiiIii
 I11i11I = ( I11i11I >> 16 ) + ( I11i11I & 0xffff )
 I11i11I += I11i11I >> 16
 I11i11I = socket . htons ( ~ I11i11I & 0xffff )
 if 1 - 1: iII111i * OoOoOO00
 if 66 - 66: OoOoOO00 + i1IIi % II111iiii . O0 * I1ii11iIi11i % I1ii11iIi11i
 if 87 - 87: OOooOOo + o0oOOo0O0Ooo . iII111i - OoooooooOO
 if 6 - 6: iIii1I11I1II1 * OoooooooOO
 I11i11I = struct . pack ( "H" , I11i11I )
 oOo00OoO0O = data [ 0 : 10 ] + I11i11I + data [ 12 : : ]
 return ( oOo00OoO0O )
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
 if 50 - 50: OoO0O00
 if 66 - 66: iIii1I11I1II1
 if 41 - 41: I1Ii111 . O0 * I1IiiI * I1ii11iIi11i
 if 100 - 100: iII111i
 if 73 - 73: I1ii11iIi11i % II111iiii
 if 79 - 79: OoOoOO00 + OoO0O00 - II111iiii + Ii1I
 if 11 - 11: oO0o + iIii1I11I1II1
 if 10 - 10: O0
 if 68 - 68: OOooOOo + oO0o . O0 . Ii1I % i1IIi % OOooOOo
 if 50 - 50: IiII + o0oOOo0O0Ooo
 if 96 - 96: OoO0O00
 if 92 - 92: Oo0Ooo / i11iIiiIii + I1ii11iIi11i
 if 87 - 87: OoOoOO00 % iIii1I11I1II1
 if 72 - 72: OOooOOo . OOooOOo - I1ii11iIi11i
 if 48 - 48: Oo0Ooo - ooOoO0o + Oo0Ooo - I1IiiI * i11iIiiIii . iII111i
 if 35 - 35: IiII . O0 + Oo0Ooo + OOooOOo + i1IIi
def lisp_udp_checksum ( source , dest , data ) :
 if 65 - 65: O0 * I1IiiI / I1IiiI . OoOoOO00
 if 87 - 87: II111iiii * I1ii11iIi11i % Oo0Ooo * Oo0Ooo
 if 58 - 58: OOooOOo . o0oOOo0O0Ooo + I1IiiI % Oo0Ooo - OoO0O00
 if 50 - 50: iII111i % II111iiii - ooOoO0o . i1IIi + O0 % iII111i
 o00oOOO = lisp_address ( LISP_AFI_IPV6 , source , LISP_IPV6_HOST_MASK_LEN , 0 )
 i1 = lisp_address ( LISP_AFI_IPV6 , dest , LISP_IPV6_HOST_MASK_LEN , 0 )
 iIi1IIiIII1 = socket . htonl ( len ( data ) )
 i1Ii11I1II = socket . htonl ( LISP_UDP_PROTOCOL )
 oOOOoo0o = o00oOOO . pack_address ( )
 oOOOoo0o += i1 . pack_address ( )
 oOOOoo0o += struct . pack ( "II" , iIi1IIiIII1 , i1Ii11I1II )
 if 44 - 44: O0 % i1IIi
 if 42 - 42: II111iiii - OoO0O00 - OoooooooOO . iII111i / OoOoOO00
 if 56 - 56: i11iIiiIii - iIii1I11I1II1 . II111iiii
 if 81 - 81: IiII / OoOoOO00 * IiII . O0
 OOOOo00oo00O = binascii . hexlify ( oOOOoo0o + data )
 Oo0oo0oOO0oOo = len ( OOOOo00oo00O ) % 4
 for II11iIII1i1I in range ( 0 , Oo0oo0oOO0oOo ) : OOOOo00oo00O += "0"
 if 18 - 18: II111iiii + OoOoOO00 - I1Ii111 + OoO0O00 / ooOoO0o % IiII
 if 94 - 94: iII111i % ooOoO0o . oO0o
 if 85 - 85: OOooOOo * i1IIi % I1IiiI - ooOoO0o
 if 37 - 37: IiII . Oo0Ooo * Oo0Ooo * II111iiii * O0
 I11i11I = 0
 for II11iIII1i1I in range ( 0 , len ( OOOOo00oo00O ) , 4 ) :
  I11i11I += int ( OOOOo00oo00O [ II11iIII1i1I : II11iIII1i1I + 4 ] , 16 )
  if 83 - 83: IiII / I1Ii111
  if 64 - 64: OoO0O00 % IiII . I1Ii111 % OoO0O00 + I11i * IiII
  if 83 - 83: o0oOOo0O0Ooo % oO0o + I11i % i11iIiiIii + O0
  if 65 - 65: iIii1I11I1II1 % oO0o + O0 / OoooooooOO
  if 52 - 52: Ii1I % OOooOOo * I1IiiI % I11i + OOooOOo / iII111i
 I11i11I = ( I11i11I >> 16 ) + ( I11i11I & 0xffff )
 I11i11I += I11i11I >> 16
 I11i11I = socket . htons ( ~ I11i11I & 0xffff )
 if 80 - 80: OoooooooOO + IiII
 if 95 - 95: I1Ii111 / oO0o * I1Ii111 - OoooooooOO * OoooooooOO % OoO0O00
 if 43 - 43: Oo0Ooo . I1Ii111
 if 12 - 12: I1Ii111 + OOooOOo + I11i . IiII / Ii1I
 I11i11I = struct . pack ( "H" , I11i11I )
 OOOOo00oo00O = data [ 0 : 6 ] + I11i11I + data [ 8 : : ]
 return ( OOOOo00oo00O )
 if 29 - 29: IiII . ooOoO0o - II111iiii
 if 68 - 68: iIii1I11I1II1 + II111iiii / oO0o
 if 91 - 91: OoOoOO00 % iIii1I11I1II1 . I1IiiI
 if 70 - 70: I11i % II111iiii % O0 . i1IIi / I1Ii111
 if 100 - 100: I1ii11iIi11i * i11iIiiIii % oO0o / Oo0Ooo / ooOoO0o + I1ii11iIi11i
 if 59 - 59: I1Ii111 - IiII
 if 14 - 14: iIii1I11I1II1 - iIii1I11I1II1
def lisp_get_interface_address ( device ) :
 if 5 - 5: IiII
 if 84 - 84: II111iiii * oO0o * II111iiii % IiII / I1IiiI
 if 100 - 100: IiII . Ii1I - iIii1I11I1II1 . i11iIiiIii / II111iiii
 if 71 - 71: I1Ii111 * Oo0Ooo . I11i
 if ( device not in netifaces . interfaces ( ) ) : return ( None )
 if 49 - 49: IiII * O0 . IiII
 if 19 - 19: II111iiii - IiII
 if 59 - 59: o0oOOo0O0Ooo * OoO0O00 - Ii1I . OOooOOo
 if 89 - 89: OOooOOo
 o00oo0OO0 = netifaces . ifaddresses ( device )
 if ( o00oo0OO0 . has_key ( netifaces . AF_INET ) == False ) : return ( None )
 if 60 - 60: ooOoO0o
 if 66 - 66: I11i / ooOoO0o % i1IIi - oO0o . O0 / O0
 if 96 - 96: OoooooooOO + IiII * O0
 if 86 - 86: Ii1I
 IiII1i1iI = lisp_address ( LISP_AFI_IPV4 , "" , 32 , 0 )
 if 84 - 84: IiII + I1ii11iIi11i + Ii1I + iII111i
 for iIiIi1iI11iiI in o00oo0OO0 [ netifaces . AF_INET ] :
  ooOOo0o = iIiIi1iI11iiI [ "addr" ]
  IiII1i1iI . store_address ( ooOOo0o )
  return ( IiII1i1iI )
  if 50 - 50: II111iiii - I1Ii111 + iIii1I11I1II1 + iIii1I11I1II1
 return ( None )
 if 91 - 91: II111iiii - O0 . iIii1I11I1II1 . O0 + I1ii11iIi11i - II111iiii
 if 26 - 26: o0oOOo0O0Ooo
 if 12 - 12: OoooooooOO / O0 + II111iiii * I1ii11iIi11i
 if 46 - 46: II111iiii - IiII * OoooooooOO / oO0o % IiII
 if 11 - 11: iIii1I11I1II1 . OoOoOO00 / IiII % ooOoO0o
 if 61 - 61: ooOoO0o - OOooOOo + OOooOOo
 if 40 - 40: i11iIiiIii . iIii1I11I1II1
 if 2 - 2: i1IIi * oO0o - oO0o + OoooooooOO % OoOoOO00 / OoOoOO00
 if 3 - 3: OoooooooOO
 if 71 - 71: IiII + i1IIi - iII111i - i11iIiiIii . I11i - ooOoO0o
 if 85 - 85: I1ii11iIi11i - OoOoOO00 / I1ii11iIi11i + OOooOOo - iII111i
 if 49 - 49: OoO0O00 - O0 / OoO0O00 * OoOoOO00 + I1Ii111
def lisp_get_input_interface ( packet ) :
 Ii = lisp_format_packet ( packet [ 0 : 12 ] ) . replace ( " " , "" )
 ii1I = Ii [ 0 : 12 ]
 Ooo000000 = Ii [ 12 : : ]
 if 80 - 80: II111iiii - OOooOOo % OoooooooOO . iIii1I11I1II1 - ooOoO0o + I1IiiI
 try : i1i1iiIIiiiII = lisp_mymacs . has_key ( Ooo000000 )
 except : i1i1iiIIiiiII = False
 if 5 - 5: OoooooooOO / o0oOOo0O0Ooo % I11i % OoO0O00 * iII111i + iIii1I11I1II1
 if ( lisp_mymacs . has_key ( ii1I ) ) : return ( lisp_mymacs [ ii1I ] , Ooo000000 , ii1I , i1i1iiIIiiiII )
 if ( i1i1iiIIiiiII ) : return ( lisp_mymacs [ Ooo000000 ] , Ooo000000 , ii1I , i1i1iiIIiiiII )
 return ( [ "?" ] , Ooo000000 , ii1I , i1i1iiIIiiiII )
 if 11 - 11: I1Ii111 % i11iIiiIii % oO0o . IiII
 if 92 - 92: II111iiii
 if 45 - 45: O0 % I1IiiI - iII111i . OoO0O00
 if 42 - 42: iII111i / o0oOOo0O0Ooo + Oo0Ooo . Oo0Ooo % OOooOOo
 if 16 - 16: i1IIi + OoO0O00 % OoOoOO00 + Ii1I * Oo0Ooo
 if 3 - 3: i11iIiiIii
 if 81 - 81: I1IiiI . OoooooooOO * Ii1I . oO0o - O0 * oO0o
 if 72 - 72: II111iiii - OOooOOo + I1IiiI - I11i
def lisp_get_local_interfaces ( ) :
 for oO00O in netifaces . interfaces ( ) :
  II111IiiiI1 = lisp_interface ( oO00O )
  II111IiiiI1 . add_interface ( )
  if 75 - 75: ooOoO0o
 return
 if 29 - 29: I1ii11iIi11i
 if 53 - 53: i11iIiiIii . I1ii11iIi11i % Ii1I / ooOoO0o % iIii1I11I1II1
 if 6 - 6: Oo0Ooo - OOooOOo . iIii1I11I1II1
 if 30 - 30: ooOoO0o + ooOoO0o % IiII - o0oOOo0O0Ooo - I1ii11iIi11i
 if 36 - 36: I11i % OOooOOo
 if 72 - 72: I1IiiI / iII111i - O0 + I11i
 if 83 - 83: O0
def lisp_get_loopback_address ( ) :
 for iIiIi1iI11iiI in netifaces . ifaddresses ( "lo" ) [ netifaces . AF_INET ] :
  if ( iIiIi1iI11iiI [ "peer" ] == "127.0.0.1" ) : continue
  return ( iIiIi1iI11iiI [ "peer" ] )
  if 89 - 89: Oo0Ooo + I1ii11iIi11i - o0oOOo0O0Ooo
 return ( None )
 if 40 - 40: OoO0O00 + OoO0O00
 if 94 - 94: iII111i * iIii1I11I1II1 . I11i
 if 13 - 13: iIii1I11I1II1 * OoOoOO00 / I1Ii111 % ooOoO0o + oO0o
 if 41 - 41: I1ii11iIi11i
 if 5 - 5: Oo0Ooo
 if 100 - 100: Ii1I + iIii1I11I1II1
 if 59 - 59: IiII
 if 89 - 89: OoOoOO00 % iIii1I11I1II1
def lisp_is_mac_string ( mac_str ) :
 i1IiII1i1I = mac_str . split ( "/" )
 if ( len ( i1IiII1i1I ) == 2 ) : mac_str = i1IiII1i1I [ 0 ]
 return ( len ( mac_str ) == 14 and mac_str . count ( "-" ) == 2 )
 if 35 - 35: I1ii11iIi11i + I1Ii111 - OoOoOO00 % oO0o % o0oOOo0O0Ooo % OoOoOO00
 if 45 - 45: I1IiiI * OOooOOo % OoO0O00
 if 24 - 24: ooOoO0o - I11i * oO0o
 if 87 - 87: Ii1I - I1ii11iIi11i % I1ii11iIi11i . oO0o / I1ii11iIi11i
 if 6 - 6: OoOoOO00 / iIii1I11I1II1 * OoooooooOO * i11iIiiIii
 if 79 - 79: IiII % OoO0O00
 if 81 - 81: i11iIiiIii + i11iIiiIii * OoO0O00 + IiII
 if 32 - 32: O0 . OoooooooOO
def lisp_get_local_macs ( ) :
 for oO00O in netifaces . interfaces ( ) :
  if 15 - 15: I1IiiI . OoO0O00
  if 17 - 17: i11iIiiIii / Oo0Ooo . OoO0O00 / I1IiiI
  if 38 - 38: i1IIi . I1ii11iIi11i % Ii1I + iIii1I11I1II1 + O0
  if 47 - 47: OoO0O00 + IiII / II111iiii
  if 97 - 97: I1ii11iIi11i / I1IiiI % O0 + i1IIi - ooOoO0o
  i1 = oO00O . replace ( ":" , "" )
  i1 = oO00O . replace ( "-" , "" )
  if ( i1 . isalnum ( ) == False ) : continue
  if 38 - 38: o0oOOo0O0Ooo % I1Ii111 + i11iIiiIii + iII111i + ooOoO0o / i11iIiiIii
  if 94 - 94: iII111i - Oo0Ooo + oO0o
  if 59 - 59: I11i . I1IiiI - iIii1I11I1II1 + iIii1I11I1II1
  if 56 - 56: oO0o + ooOoO0o
  if 32 - 32: II111iiii + OoOoOO00 % ooOoO0o / OoOoOO00 + I1ii11iIi11i
  try :
   IiI11I111 = netifaces . ifaddresses ( oO00O )
  except :
   continue
   if 54 - 54: O0 - iII111i . OOooOOo % iII111i + iII111i
  if ( IiI11I111 . has_key ( netifaces . AF_LINK ) == False ) : continue
  i1IiII1i1I = IiI11I111 [ netifaces . AF_LINK ] [ 0 ] [ "addr" ]
  i1IiII1i1I = i1IiII1i1I . replace ( ":" , "" )
  if 36 - 36: OOooOOo % i11iIiiIii
  if 47 - 47: i1IIi + II111iiii . Oo0Ooo * oO0o . I11i / i1IIi
  if 50 - 50: I1Ii111 / i1IIi % OoooooooOO
  if 83 - 83: I1ii11iIi11i * I1ii11iIi11i + OOooOOo
  if 57 - 57: O0 - O0 . I1ii11iIi11i / o0oOOo0O0Ooo / Ii1I
  if ( len ( i1IiII1i1I ) < 12 ) : continue
  if 20 - 20: OOooOOo * II111iiii - OoOoOO00 - oO0o * I1Ii111
  if ( lisp_mymacs . has_key ( i1IiII1i1I ) == False ) : lisp_mymacs [ i1IiII1i1I ] = [ ]
  lisp_mymacs [ i1IiII1i1I ] . append ( oO00O )
  if 6 - 6: ooOoO0o + OOooOOo / Oo0Ooo + IiII % II111iiii / OoO0O00
  if 45 - 45: OoooooooOO
 lprint ( "Local MACs are: {}" . format ( lisp_mymacs ) )
 return
 if 9 - 9: I11i . OoO0O00 * i1IIi . OoooooooOO
 if 32 - 32: OoOoOO00 . I1ii11iIi11i % I1IiiI - II111iiii
 if 11 - 11: O0 + I1IiiI
 if 80 - 80: oO0o % oO0o % O0 - i11iIiiIii . iII111i / O0
 if 13 - 13: I1IiiI + O0 - I1ii11iIi11i % Oo0Ooo / Ii1I . i1IIi
 if 60 - 60: Oo0Ooo . IiII % I1IiiI - I1Ii111
 if 79 - 79: OoooooooOO / I1ii11iIi11i . O0
 if 79 - 79: oO0o - II111iiii
def lisp_get_local_rloc ( ) :
 Ii1iiI1 = commands . getoutput ( "netstat -rn | egrep 'default|0.0.0.0'" )
 if ( Ii1iiI1 == "" ) : return ( lisp_address ( LISP_AFI_IPV4 , "" , 32 , 0 ) )
 if 76 - 76: Ii1I * iIii1I11I1II1
 if 31 - 31: i11iIiiIii + OOooOOo - O0
 if 51 - 51: OoO0O00 * i1IIi / Ii1I * OOooOOo + ooOoO0o % I1ii11iIi11i
 if 34 - 34: oO0o * OoooooooOO + Ii1I + i11iIiiIii
 Ii1iiI1 = Ii1iiI1 . split ( "\n" ) [ 0 ]
 oO00O = Ii1iiI1 . split ( ) [ - 1 ]
 if 22 - 22: i1IIi
 iIiIi1iI11iiI = ""
 I11io0Oo = lisp_is_macos ( )
 if ( I11io0Oo ) :
  Ii1iiI1 = commands . getoutput ( "ifconfig {} | egrep 'inet '" . format ( oO00O ) )
  if ( Ii1iiI1 == "" ) : return ( lisp_address ( LISP_AFI_IPV4 , "" , 32 , 0 ) )
 else :
  iiI1i = 'ip addr show | egrep "inet " | egrep "{}"' . format ( oO00O )
  Ii1iiI1 = commands . getoutput ( iiI1i )
  if ( Ii1iiI1 == "" ) :
   iiI1i = 'ip addr show | egrep "inet " | egrep "global lo"'
   Ii1iiI1 = commands . getoutput ( iiI1i )
   if 3 - 3: IiII / I11i
  if ( Ii1iiI1 == "" ) : return ( lisp_address ( LISP_AFI_IPV4 , "" , 32 , 0 ) )
  if 34 - 34: i11iIiiIii / I1Ii111 * OOooOOo . Oo0Ooo
  if 79 - 79: I1Ii111
  if 31 - 31: OOooOOo % I1Ii111
  if 98 - 98: IiII * iIii1I11I1II1 . Ii1I * Oo0Ooo / I1ii11iIi11i + ooOoO0o
  if 25 - 25: oO0o
  if 19 - 19: I1IiiI % Ii1I . IiII * ooOoO0o
 iIiIi1iI11iiI = ""
 Ii1iiI1 = Ii1iiI1 . split ( "\n" )
 if 89 - 89: OoOoOO00 . OOooOOo
 for IIIIIiI11Ii in Ii1iiI1 :
  ii1iI1iI1 = IIIIIiI11Ii . split ( ) [ 1 ]
  if ( I11io0Oo == False ) : ii1iI1iI1 = ii1iI1iI1 . split ( "/" ) [ 0 ]
  Iiii1Ii1I = lisp_address ( LISP_AFI_IPV4 , ii1iI1iI1 , 32 , 0 )
  return ( Iiii1Ii1I )
  if 94 - 94: iIii1I11I1II1 - OoO0O00 . Oo0Ooo
 return ( lisp_address ( LISP_AFI_IPV4 , iIiIi1iI11iiI , 32 , 0 ) )
 if 59 - 59: OoO0O00 - OoO0O00 + iII111i
 if 32 - 32: i1IIi / Oo0Ooo - O0
 if 85 - 85: Ii1I - O0 * i11iIiiIii . i1IIi
 if 20 - 20: iII111i / OOooOOo
 if 28 - 28: ooOoO0o * I11i % i11iIiiIii * iII111i / Ii1I
 if 41 - 41: OOooOOo - o0oOOo0O0Ooo + Ii1I
 if 15 - 15: I11i / o0oOOo0O0Ooo + Ii1I
 if 76 - 76: Ii1I + OoooooooOO / OOooOOo % OoO0O00 / I1ii11iIi11i
 if 38 - 38: I1Ii111 . iII111i . I1IiiI * OoO0O00
 if 69 - 69: o0oOOo0O0Ooo % i11iIiiIii / Ii1I
 if 93 - 93: ooOoO0o
def lisp_get_local_addresses ( ) :
 global lisp_myrlocs
 if 34 - 34: oO0o - ooOoO0o * Oo0Ooo / o0oOOo0O0Ooo
 if 19 - 19: I1ii11iIi11i
 if 46 - 46: iIii1I11I1II1 . i11iIiiIii - OoOoOO00 % O0 / II111iiii * i1IIi
 if 66 - 66: O0
 if 52 - 52: OoO0O00 * OoooooooOO
 if 12 - 12: O0 + IiII * i1IIi . OoO0O00
 if 71 - 71: I1Ii111 - o0oOOo0O0Ooo - OOooOOo
 if 28 - 28: iIii1I11I1II1
 if 7 - 7: o0oOOo0O0Ooo % IiII * OoOoOO00
 if 58 - 58: IiII / I11i + II111iiii % iII111i - OoooooooOO
 II1iII1i1i = None
 oo0OOo0O = 1
 o00oO0O0oo0o = os . getenv ( "LISP_ADDR_SELECT" )
 if ( o00oO0O0oo0o != None and o00oO0O0oo0o != "" ) :
  o00oO0O0oo0o = o00oO0O0oo0o . split ( ":" )
  if ( len ( o00oO0O0oo0o ) == 2 ) :
   II1iII1i1i = o00oO0O0oo0o [ 0 ]
   oo0OOo0O = o00oO0O0oo0o [ 1 ]
  else :
   if ( o00oO0O0oo0o [ 0 ] . isdigit ( ) ) :
    oo0OOo0O = o00oO0O0oo0o [ 0 ]
   else :
    II1iII1i1i = o00oO0O0oo0o [ 0 ]
    if 46 - 46: OoOoOO00 - O0
    if 70 - 70: I11i + Oo0Ooo * iIii1I11I1II1 . I1IiiI * I11i
  oo0OOo0O = 1 if ( oo0OOo0O == "" ) else int ( oo0OOo0O )
  if 49 - 49: o0oOOo0O0Ooo
  if 25 - 25: iII111i . OoooooooOO * iIii1I11I1II1 . o0oOOo0O0Ooo / O0 + Ii1I
 ooo0o0 = [ None , None , None ]
 O00Oooo00 = lisp_address ( LISP_AFI_IPV4 , "" , 32 , 0 )
 ooO0 = lisp_address ( LISP_AFI_IPV6 , "" , 128 , 0 )
 ii111iiIii = None
 if 57 - 57: o0oOOo0O0Ooo / I1Ii111
 for oO00O in netifaces . interfaces ( ) :
  if ( II1iII1i1i != None and II1iII1i1i != oO00O ) : continue
  o00oo0OO0 = netifaces . ifaddresses ( oO00O )
  if ( o00oo0OO0 == { } ) : continue
  if 13 - 13: OoooooooOO + OoO0O00
  if 32 - 32: O0 + oO0o % Oo0Ooo
  if 7 - 7: I1ii11iIi11i / ooOoO0o
  if 11 - 11: IiII * ooOoO0o / ooOoO0o - OOooOOo
  ii111iiIii = lisp_get_interface_instance_id ( oO00O , None )
  if 68 - 68: I1IiiI % IiII - IiII / I1IiiI + I1ii11iIi11i - Oo0Ooo
  if 65 - 65: ooOoO0o - i1IIi
  if 62 - 62: I11i / oO0o % Oo0Ooo . OoooooooOO / i11iIiiIii / I1Ii111
  if 60 - 60: I1IiiI % oO0o / o0oOOo0O0Ooo % oO0o * i11iIiiIii / iII111i
  if ( o00oo0OO0 . has_key ( netifaces . AF_INET ) ) :
   i11Ii1iIiII = o00oo0OO0 [ netifaces . AF_INET ]
   i1Ii11II = 0
   for iIiIi1iI11iiI in i11Ii1iIiII :
    O00Oooo00 . store_address ( iIiIi1iI11iiI [ "addr" ] )
    if ( O00Oooo00 . is_ipv4_loopback ( ) ) : continue
    if ( O00Oooo00 . is_ipv4_link_local ( ) ) : continue
    if ( O00Oooo00 . address == 0 ) : continue
    i1Ii11II += 1
    O00Oooo00 . instance_id = ii111iiIii
    if ( II1iII1i1i == None and
 lisp_db_for_lookups . lookup_cache ( O00Oooo00 , False ) ) : continue
    ooo0o0 [ 0 ] = O00Oooo00
    if ( i1Ii11II == oo0OOo0O ) : break
    if 33 - 33: IiII . OoooooooOO . oO0o
    if 15 - 15: I1ii11iIi11i . iII111i
  if ( o00oo0OO0 . has_key ( netifaces . AF_INET6 ) ) :
   O0oOo00Ooo0o0 = o00oo0OO0 [ netifaces . AF_INET6 ]
   i1Ii11II = 0
   for iIiIi1iI11iiI in O0oOo00Ooo0o0 :
    ooOOo0o = iIiIi1iI11iiI [ "addr" ]
    ooO0 . store_address ( ooOOo0o )
    if ( ooO0 . is_ipv6_string_link_local ( ooOOo0o ) ) : continue
    if ( ooO0 . is_ipv6_loopback ( ) ) : continue
    i1Ii11II += 1
    ooO0 . instance_id = ii111iiIii
    if ( II1iII1i1i == None and
 lisp_db_for_lookups . lookup_cache ( ooO0 , False ) ) : continue
    ooo0o0 [ 1 ] = ooO0
    if ( i1Ii11II == oo0OOo0O ) : break
    if 94 - 94: I11i . I1IiiI
    if 73 - 73: i1IIi / II111iiii
    if 45 - 45: Ii1I / ooOoO0o . OoooooooOO + OoO0O00
    if 51 - 51: iII111i % i11iIiiIii % IiII + I1Ii111 % I1ii11iIi11i
    if 16 - 16: OoOoOO00 / Oo0Ooo + O0 - OoOoOO00 . OoooooooOO
    if 19 - 19: o0oOOo0O0Ooo
  if ( ooo0o0 [ 0 ] == None ) : continue
  if 73 - 73: I1Ii111 * Oo0Ooo * OoOoOO00
  ooo0o0 [ 2 ] = oO00O
  break
  if 65 - 65: i11iIiiIii + Oo0Ooo * OoooooooOO - OoO0O00
  if 26 - 26: o0oOOo0O0Ooo % OOooOOo + OOooOOo % I11i * i11iIiiIii / iII111i
 OOoO0oO00o = ooo0o0 [ 0 ] . print_address_no_iid ( ) if ooo0o0 [ 0 ] else "none"
 OOO0OoO0oo0OO = ooo0o0 [ 1 ] . print_address_no_iid ( ) if ooo0o0 [ 1 ] else "none"
 oO00O = ooo0o0 [ 2 ] if ooo0o0 [ 2 ] else "none"
 if 31 - 31: I11i * oO0o . Ii1I
 II1iII1i1i = " (user selected)" if II1iII1i1i != None else ""
 if 35 - 35: I11i
 OOoO0oO00o = red ( OOoO0oO00o , False )
 OOO0OoO0oo0OO = red ( OOO0OoO0oo0OO , False )
 oO00O = bold ( oO00O , False )
 lprint ( "Local addresses are IPv4: {}, IPv6: {} from device {}{}, iid {}" . format ( OOoO0oO00o , OOO0OoO0oo0OO , oO00O , II1iII1i1i , ii111iiIii ) )
 if 94 - 94: ooOoO0o / i11iIiiIii % O0
 if 70 - 70: I11i - Oo0Ooo / OoooooooOO % OoooooooOO
 lisp_myrlocs = ooo0o0
 return ( ( ooo0o0 [ 0 ] != None ) )
 if 95 - 95: OoooooooOO % OoooooooOO . Ii1I
 if 26 - 26: oO0o + IiII - II111iiii . II111iiii + I1ii11iIi11i + OoOoOO00
 if 68 - 68: O0
 if 76 - 76: I1ii11iIi11i
 if 99 - 99: o0oOOo0O0Ooo
 if 1 - 1: Ii1I * OoOoOO00 * OoO0O00 + Oo0Ooo
 if 90 - 90: I1Ii111 % Oo0Ooo - Oo0Ooo . iIii1I11I1II1 / OOooOOo + I11i
 if 89 - 89: oO0o
 if 87 - 87: iII111i % Oo0Ooo
def lisp_get_all_addresses ( ) :
 OOo000o = [ ]
 for II111IiiiI1 in netifaces . interfaces ( ) :
  try : iiIIIIiI111 = netifaces . ifaddresses ( II111IiiiI1 )
  except : continue
  if 86 - 86: II111iiii % iIii1I11I1II1 / I1ii11iIi11i - o0oOOo0O0Ooo * Ii1I . I1IiiI
  if ( iiIIIIiI111 . has_key ( netifaces . AF_INET ) ) :
   for iIiIi1iI11iiI in iiIIIIiI111 [ netifaces . AF_INET ] :
    ii1iI1iI1 = iIiIi1iI11iiI [ "addr" ]
    if ( ii1iI1iI1 . find ( "127.0.0.1" ) != - 1 ) : continue
    OOo000o . append ( ii1iI1iI1 )
    if 68 - 68: OoooooooOO * iIii1I11I1II1 + i1IIi - i1IIi
    if 76 - 76: OoO0O00 . OoooooooOO % I1Ii111 * Ii1I
  if ( iiIIIIiI111 . has_key ( netifaces . AF_INET6 ) ) :
   for iIiIi1iI11iiI in iiIIIIiI111 [ netifaces . AF_INET6 ] :
    ii1iI1iI1 = iIiIi1iI11iiI [ "addr" ]
    if ( ii1iI1iI1 == "::1" ) : continue
    if ( ii1iI1iI1 [ 0 : 5 ] == "fe80:" ) : continue
    OOo000o . append ( ii1iI1iI1 )
    if 23 - 23: IiII + iIii1I11I1II1
    if 14 - 14: O0 % IiII % Ii1I * oO0o
    if 65 - 65: I11i % oO0o + I1ii11iIi11i
 return ( OOo000o )
 if 86 - 86: iIii1I11I1II1 / O0 . I1Ii111 % iIii1I11I1II1 % Oo0Ooo
 if 86 - 86: i11iIiiIii - o0oOOo0O0Ooo . ooOoO0o * Oo0Ooo / Ii1I % o0oOOo0O0Ooo
 if 61 - 61: o0oOOo0O0Ooo + OoOoOO00
 if 15 - 15: OoOoOO00 * oO0o + OOooOOo . I11i % I1IiiI - ooOoO0o
 if 13 - 13: OoOoOO00 % OoOoOO00 % Oo0Ooo % I1IiiI * i1IIi % I11i
 if 82 - 82: IiII . OoOoOO00 / ooOoO0o + iII111i - ooOoO0o
 if 55 - 55: ooOoO0o % Oo0Ooo % o0oOOo0O0Ooo
 if 29 - 29: IiII / iIii1I11I1II1 + I1ii11iIi11i % iII111i % I11i
def lisp_get_all_multicast_rles ( ) :
 i1i = [ ]
 Ii1iiI1 = commands . getoutput ( 'egrep "rle-address =" ./lisp.config' )
 if ( Ii1iiI1 == "" ) : return ( i1i )
 if 15 - 15: I11i % i11iIiiIii
 O0o0O00o0o = Ii1iiI1 . split ( "\n" )
 for IIIIIiI11Ii in O0o0O00o0o :
  if ( IIIIIiI11Ii [ 0 ] == "#" ) : continue
  II1IIiiI1 = IIIIIiI11Ii . split ( "rle-address = " ) [ 1 ]
  O00O00 = int ( II1IIiiI1 . split ( "." ) [ 0 ] )
  if ( O00O00 >= 224 and O00O00 < 240 ) : i1i . append ( II1IIiiI1 )
  if 66 - 66: Oo0Ooo - iIii1I11I1II1
 return ( i1i )
 if 9 - 9: o0oOOo0O0Ooo % I1ii11iIi11i . I1ii11iIi11i
 if 28 - 28: OoooooooOO % oO0o + I1ii11iIi11i + O0 . I1Ii111
 if 80 - 80: i11iIiiIii % I1ii11iIi11i
 if 54 - 54: o0oOOo0O0Ooo + I11i - iIii1I11I1II1 % ooOoO0o % IiII
 if 19 - 19: I1ii11iIi11i / iIii1I11I1II1 % i1IIi . OoooooooOO
 if 57 - 57: ooOoO0o . Oo0Ooo - OoO0O00 - i11iIiiIii * I1Ii111 / o0oOOo0O0Ooo
 if 79 - 79: I1ii11iIi11i + o0oOOo0O0Ooo % Oo0Ooo * o0oOOo0O0Ooo
 if 21 - 21: iII111i
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
  if 24 - 24: iII111i / ooOoO0o
  if 61 - 61: iIii1I11I1II1 + oO0o
 def encode ( self , nonce ) :
  if 8 - 8: I1Ii111 + OoO0O00
  if 9 - 9: OOooOOo + o0oOOo0O0Ooo
  if 8 - 8: OOooOOo * Oo0Ooo / iII111i - OoO0O00 - OoooooooOO
  if 100 - 100: oO0o . iIii1I11I1II1 . iIii1I11I1II1
  if 55 - 55: oO0o
  if ( self . outer_source . is_null ( ) ) : return ( None )
  if 37 - 37: IiII / i11iIiiIii / Oo0Ooo
  if 97 - 97: I1Ii111 . I11i / I1IiiI
  if 83 - 83: I11i - I1ii11iIi11i * oO0o
  if 90 - 90: Oo0Ooo * I1IiiI
  if 75 - 75: I1ii11iIi11i - OoOoOO00 * i11iIiiIii . OoooooooOO - Oo0Ooo . I11i
  if 6 - 6: I11i * oO0o / OoooooooOO % Ii1I * o0oOOo0O0Ooo
  if ( nonce == None ) :
   self . lisp_header . nonce ( lisp_get_data_nonce ( ) )
  elif ( self . lisp_header . is_request_nonce ( nonce ) ) :
   self . lisp_header . request_nonce ( nonce )
  else :
   self . lisp_header . nonce ( nonce )
   if 28 - 28: IiII * I1IiiI % IiII
  self . lisp_header . instance_id ( self . inner_dest . instance_id )
  if 95 - 95: O0 / I11i . I1Ii111
  if 17 - 17: I11i
  if 56 - 56: ooOoO0o * o0oOOo0O0Ooo + I11i
  if 48 - 48: IiII * OoO0O00 % I1Ii111 - I11i
  if 72 - 72: i1IIi % ooOoO0o % IiII % oO0o - oO0o
  if 97 - 97: o0oOOo0O0Ooo * O0 / o0oOOo0O0Ooo * OoO0O00 * Oo0Ooo
  self . lisp_header . key_id ( 0 )
  iiI1iiii1Iii = ( self . lisp_header . get_instance_id ( ) == 0xffffff )
  if ( lisp_data_plane_security and iiI1iiii1Iii == False ) :
   ooOOo0o = self . outer_dest . print_address_no_iid ( ) + ":" + str ( self . encap_port )
   if 94 - 94: i11iIiiIii % oO0o + Oo0Ooo + oO0o
   if ( lisp_crypto_keys_by_rloc_encap . has_key ( ooOOo0o ) ) :
    i1iIi = lisp_crypto_keys_by_rloc_encap [ ooOOo0o ]
    if ( i1iIi [ 1 ] ) :
     i1iIi [ 1 ] . use_count += 1
     oOo , ooOo0o = self . encrypt ( i1iIi [ 1 ] , ooOOo0o )
     if ( ooOo0o ) : self . packet = oOo
     if 44 - 44: Oo0Ooo . Oo0Ooo + OoooooooOO * i11iIiiIii / I11i + I1Ii111
     if 17 - 17: OOooOOo + II111iiii
     if 43 - 43: I11i % Ii1I / o0oOOo0O0Ooo * I1Ii111
     if 85 - 85: iIii1I11I1II1 . OoooooooOO . o0oOOo0O0Ooo
     if 77 - 77: I1IiiI % ooOoO0o
     if 74 - 74: OoOoOO00 / i1IIi % OoooooooOO
     if 52 - 52: IiII % ooOoO0o
     if 25 - 25: I11i / I11i % OoooooooOO - I1ii11iIi11i * oO0o
  self . udp_checksum = 0
  if ( self . encap_port == LISP_DATA_PORT ) :
   if ( lisp_crypto_ephem_port == None ) :
    if ( self . gleaned_dest ) :
     self . udp_sport = LISP_DATA_PORT
    else :
     self . hash_packet ( )
     if 23 - 23: i11iIiiIii
   else :
    self . udp_sport = lisp_crypto_ephem_port
    if 100 - 100: oO0o + O0 . I1IiiI + i1IIi - OoOoOO00 + o0oOOo0O0Ooo
  else :
   self . udp_sport = LISP_DATA_PORT
   if 65 - 65: II111iiii / Oo0Ooo
  self . udp_dport = self . encap_port
  self . udp_length = len ( self . packet ) + 16
  if 42 - 42: i11iIiiIii . O0
  if 75 - 75: I1Ii111 + iIii1I11I1II1
  if 19 - 19: I1IiiI + i11iIiiIii . IiII - I11i / Ii1I + o0oOOo0O0Ooo
  if 38 - 38: Oo0Ooo / iIii1I11I1II1 * iIii1I11I1II1 % I1ii11iIi11i
  if ( self . outer_version == 4 ) :
   O00o = socket . htons ( self . udp_sport )
   o0o0ooOo00 = socket . htons ( self . udp_dport )
  else :
   O00o = self . udp_sport
   o0o0ooOo00 = self . udp_dport
   if 91 - 91: OoO0O00 * I1Ii111 % OoO0O00 . o0oOOo0O0Ooo * I1ii11iIi11i . OOooOOo
   if 13 - 13: I1ii11iIi11i
  o0o0ooOo00 = socket . htons ( self . udp_dport ) if self . outer_version == 4 else self . udp_dport
  if 80 - 80: Oo0Ooo % IiII % OoooooooOO * Oo0Ooo % Ii1I
  if 41 - 41: OoooooooOO / i1IIi
  OOOOo00oo00O = struct . pack ( "HHHH" , O00o , o0o0ooOo00 , socket . htons ( self . udp_length ) ,
 self . udp_checksum )
  if 70 - 70: OoOoOO00 % o0oOOo0O0Ooo % i1IIi / I1ii11iIi11i % i11iIiiIii / i1IIi
  if 4 - 4: IiII
  if 93 - 93: oO0o % i1IIi
  if 83 - 83: I1IiiI . Oo0Ooo - I11i . o0oOOo0O0Ooo
  ooo00o0o0 = self . lisp_header . encode ( )
  if 54 - 54: Ii1I % I11i . OOooOOo + oO0o * iII111i - i1IIi
  if 27 - 27: Ii1I % i1IIi . Oo0Ooo % I1Ii111
  if 10 - 10: IiII / OoooooooOO
  if 50 - 50: i11iIiiIii - OoooooooOO . oO0o + O0 . i1IIi
  if 91 - 91: o0oOOo0O0Ooo . iII111i % Oo0Ooo - iII111i . oO0o % i11iIiiIii
  if ( self . outer_version == 4 ) :
   iIi = socket . htons ( self . udp_length + 20 )
   O0O = socket . htons ( 0x4000 )
   oOOoooo = struct . pack ( "BBHHHBBH" , 0x45 , self . outer_tos , iIi , 0xdfdf ,
 O0O , self . outer_ttl , 17 , 0 )
   oOOoooo += self . outer_source . pack_address ( )
   oOOoooo += self . outer_dest . pack_address ( )
   oOOoooo = lisp_ip_checksum ( oOOoooo )
  elif ( self . outer_version == 6 ) :
   oOOoooo = ""
   if 70 - 70: iII111i . II111iiii . iII111i - iIii1I11I1II1
   if 92 - 92: OoO0O00
   if 15 - 15: IiII / IiII + iIii1I11I1II1 % OoooooooOO
   if 12 - 12: ooOoO0o
   if 36 - 36: I1Ii111 . IiII * OoooooooOO - o0oOOo0O0Ooo
   if 60 - 60: OOooOOo . iII111i / iIii1I11I1II1 + OOooOOo * I1Ii111
   if 82 - 82: i11iIiiIii . iIii1I11I1II1 * I1IiiI - I11i + Ii1I
  else :
   return ( None )
   if 48 - 48: I1ii11iIi11i
   if 96 - 96: ooOoO0o . OoooooooOO
  self . packet = oOOoooo + OOOOo00oo00O + ooo00o0o0 + self . packet
  return ( self )
  if 39 - 39: OOooOOo + OoO0O00
  if 80 - 80: OOooOOo % OoO0O00 / OoOoOO00
 def cipher_pad ( self , packet ) :
  OOOOO000oo0 = len ( packet )
  if ( ( OOOOO000oo0 % 16 ) != 0 ) :
   I1iI111ii111i = ( ( OOOOO000oo0 / 16 ) + 1 ) * 16
   packet = packet . ljust ( I1iI111ii111i )
   if 83 - 83: iIii1I11I1II1
  return ( packet )
  if 97 - 97: i11iIiiIii + Oo0Ooo * OOooOOo % iII111i . IiII
  if 4 - 4: O0 . iII111i - iIii1I11I1II1
 def encrypt ( self , key , addr_str ) :
  if ( key == None or key . shared_key == None ) :
   return ( [ self . packet , False ] )
   if 19 - 19: OOooOOo % OoO0O00 / Ii1I + II111iiii % OoooooooOO
   if 89 - 89: Ii1I
   if 51 - 51: iII111i
   if 68 - 68: iII111i - o0oOOo0O0Ooo * OoO0O00 % ooOoO0o . ooOoO0o - iIii1I11I1II1
   if 22 - 22: OoooooooOO / I1ii11iIi11i % iII111i * OoOoOO00
  oOo = self . cipher_pad ( self . packet )
  Ii1IiiiI1ii = key . get_iv ( )
  if 55 - 55: I1ii11iIi11i
  OOOO0O00o = lisp_get_timestamp ( )
  oOoo0OO0 = None
  if ( key . cipher_suite == LISP_CS_25519_CHACHA ) :
   iiIiIi1111iI1 = chacha . ChaCha ( key . encrypt_key , Ii1IiiiI1ii ) . encrypt
  elif ( key . cipher_suite == LISP_CS_25519_GCM ) :
   III = binascii . unhexlify ( key . encrypt_key )
   try :
    OoO0o = AES . new ( III , AES . MODE_GCM , Ii1IiiiI1ii )
    iiIiIi1111iI1 = OoO0o . encrypt
    oOoo0OO0 = OoO0o . digest
   except :
    lprint ( "You need AES-GCM, do a 'pip install pycryptodome'" )
    return ( [ self . packet , False ] )
    if 72 - 72: OOooOOo % OoooooooOO % o0oOOo0O0Ooo * OOooOOo % I1IiiI * Ii1I
  else :
   III = binascii . unhexlify ( key . encrypt_key )
   iiIiIi1111iI1 = AES . new ( III , AES . MODE_CBC , Ii1IiiiI1ii ) . encrypt
   if 34 - 34: OoO0O00 * Ii1I * Oo0Ooo
   if 21 - 21: OoooooooOO . OoOoOO00 - iIii1I11I1II1 % IiII
  Oooo0ooOoo0 = iiIiIi1111iI1 ( oOo )
  if 26 - 26: IiII / iIii1I11I1II1 - iIii1I11I1II1
  if ( Oooo0ooOoo0 == None ) : return ( [ self . packet , False ] )
  OOOO0O00o = int ( str ( time . time ( ) - OOOO0O00o ) . split ( "." ) [ 1 ] [ 0 : 6 ] )
  if 57 - 57: IiII
  if 41 - 41: iIii1I11I1II1 * iII111i + Oo0Ooo * o0oOOo0O0Ooo % IiII / OOooOOo
  if 63 - 63: i1IIi % i11iIiiIii % II111iiii * OoooooooOO
  if 40 - 40: Oo0Ooo
  if 47 - 47: OoOoOO00
  if 65 - 65: O0 + I1Ii111 % Ii1I * I1IiiI / ooOoO0o / OoOoOO00
  if ( oOoo0OO0 != None ) : Oooo0ooOoo0 += oOoo0OO0 ( )
  if 71 - 71: i11iIiiIii / OoOoOO00 . oO0o
  if 33 - 33: oO0o
  if 39 - 39: OoO0O00 + O0 + ooOoO0o * II111iiii % O0 - O0
  if 41 - 41: IiII % o0oOOo0O0Ooo
  if 67 - 67: O0 % I1Ii111
  self . lisp_header . key_id ( key . key_id )
  ooo00o0o0 = self . lisp_header . encode ( )
  if 35 - 35: I1IiiI . OoOoOO00 + OoooooooOO % Oo0Ooo % OOooOOo
  iIi1Ii1111i = key . do_icv ( ooo00o0o0 + Ii1IiiiI1ii + Oooo0ooOoo0 , Ii1IiiiI1ii )
  if 16 - 16: IiII . ooOoO0o . OoO0O00
  o0oO0oo = 4 if ( key . do_poly ) else 8
  if 98 - 98: OoooooooOO - I1IiiI + ooOoO0o
  O0I11IIIII = bold ( "Encrypt" , False )
  OoO = bold ( key . cipher_suite_string , False )
  addr_str = "RLOC: " + red ( addr_str , False )
  II11IiI1 = "poly" if key . do_poly else "sha256"
  II11IiI1 = bold ( II11IiI1 , False )
  OoOOOO00oOO = "ICV({}): 0x{}...{}" . format ( II11IiI1 , iIi1Ii1111i [ 0 : o0oO0oo ] , iIi1Ii1111i [ - o0oO0oo : : ] )
  dprint ( "{} for key-id: {}, {}, {}, {}-time: {} usec" . format ( O0I11IIIII , key . key_id , addr_str , OoOOOO00oOO , OoO , OOOO0O00o ) )
  if 4 - 4: i1IIi + OoOoOO00
  if 39 - 39: iIii1I11I1II1 + ooOoO0o
  iIi1Ii1111i = int ( iIi1Ii1111i , 16 )
  if ( key . do_poly ) :
   o00oOoo0o00 = byte_swap_64 ( ( iIi1Ii1111i >> 64 ) & LISP_8_64_MASK )
   iIiiI11II11i = byte_swap_64 ( iIi1Ii1111i & LISP_8_64_MASK )
   iIi1Ii1111i = struct . pack ( "QQ" , o00oOoo0o00 , iIiiI11II11i )
  else :
   o00oOoo0o00 = byte_swap_64 ( ( iIi1Ii1111i >> 96 ) & LISP_8_64_MASK )
   iIiiI11II11i = byte_swap_64 ( ( iIi1Ii1111i >> 32 ) & LISP_8_64_MASK )
   o00OoO0o0 = socket . htonl ( iIi1Ii1111i & 0xffffffff )
   iIi1Ii1111i = struct . pack ( "QQI" , o00oOoo0o00 , iIiiI11II11i , o00OoO0o0 )
   if 52 - 52: iII111i . oO0o - Ii1I
   if 85 - 85: I1ii11iIi11i / i1IIi * OoO0O00 . oO0o
  return ( [ Ii1IiiiI1ii + Oooo0ooOoo0 + iIi1Ii1111i , True ] )
  if 60 - 60: I11i
  if 93 - 93: Oo0Ooo
 def decrypt ( self , packet , header_length , key , addr_str ) :
  if 75 - 75: OoOoOO00
  if 64 - 64: IiII / o0oOOo0O0Ooo / i1IIi
  if 79 - 79: OOooOOo % I1Ii111 / oO0o - iIii1I11I1II1 - OoOoOO00
  if 60 - 60: II111iiii
  if 90 - 90: OoOoOO00
  if 37 - 37: OoOoOO00 + O0 . O0 * Oo0Ooo % I1Ii111 / iII111i
  if ( key . do_poly ) :
   o00oOoo0o00 , iIiiI11II11i = struct . unpack ( "QQ" , packet [ - 16 : : ] )
   iIIi = byte_swap_64 ( o00oOoo0o00 ) << 64
   iIIi |= byte_swap_64 ( iIiiI11II11i )
   iIIi = lisp_hex_string ( iIIi ) . zfill ( 32 )
   packet = packet [ 0 : - 16 ]
   o0oO0oo = 4
   OOOo00o = bold ( "poly" , False )
  else :
   o00oOoo0o00 , iIiiI11II11i , o00OoO0o0 = struct . unpack ( "QQI" , packet [ - 20 : : ] )
   iIIi = byte_swap_64 ( o00oOoo0o00 ) << 96
   iIIi |= byte_swap_64 ( iIiiI11II11i ) << 32
   iIIi |= socket . htonl ( o00OoO0o0 )
   iIIi = lisp_hex_string ( iIIi ) . zfill ( 40 )
   packet = packet [ 0 : - 20 ]
   o0oO0oo = 8
   OOOo00o = bold ( "sha" , False )
   if 3 - 3: o0oOOo0O0Ooo
  ooo00o0o0 = self . lisp_header . encode ( )
  if 16 - 16: i1IIi . i1IIi / I1Ii111 % OoOoOO00 / I1IiiI * I1ii11iIi11i
  if 30 - 30: o0oOOo0O0Ooo + OoooooooOO + OOooOOo / II111iiii * Oo0Ooo
  if 59 - 59: Ii1I / OoOoOO00 * OoO0O00 * iII111i % oO0o
  if 61 - 61: Oo0Ooo - O0 - OoooooooOO
  if ( key . cipher_suite == LISP_CS_25519_CHACHA ) :
   Ii1I1Iiii = 8
   OoO = bold ( "chacha" , False )
  elif ( key . cipher_suite == LISP_CS_25519_GCM ) :
   Ii1I1Iiii = 12
   OoO = bold ( "aes-gcm" , False )
  else :
   Ii1I1Iiii = 16
   OoO = bold ( "aes-cbc" , False )
   if 80 - 80: OOooOOo . Ii1I + iIii1I11I1II1
  Ii1IiiiI1ii = packet [ 0 : Ii1I1Iiii ]
  if 32 - 32: I1IiiI
  if 47 - 47: I1ii11iIi11i * oO0o + iIii1I11I1II1 - oO0o / IiII
  if 86 - 86: IiII
  if 43 - 43: I1IiiI / iII111i / ooOoO0o + iIii1I11I1II1 + OoooooooOO
  iiI111i1 = key . do_icv ( ooo00o0o0 + packet , Ii1IiiiI1ii )
  if 41 - 41: i11iIiiIii * O0 - iII111i . II111iiii % OoO0O00 % I1ii11iIi11i
  I1I11i = "0x{}...{}" . format ( iIIi [ 0 : o0oO0oo ] , iIIi [ - o0oO0oo : : ] )
  Iii1Iii = "0x{}...{}" . format ( iiI111i1 [ 0 : o0oO0oo ] , iiI111i1 [ - o0oO0oo : : ] )
  if 91 - 91: ooOoO0o * IiII * II111iiii
  if ( iiI111i1 != iIIi ) :
   self . packet_error = "ICV-error"
   oooO0oooOo000 = OoO + "/" + OOOo00o
   ooOOO0o = bold ( "ICV failed ({})" . format ( oooO0oooOo000 ) , False )
   OoOOOO00oOO = "packet-ICV {} != computed-ICV {}" . format ( I1I11i , Iii1Iii )
   dprint ( ( "{} from RLOC {}, receive-port: {}, key-id: {}, " + "packet dropped, {}" ) . format ( ooOOO0o , red ( addr_str , False ) ,
   # II111iiii / O0 / IiII - I11i - i1IIi
 self . udp_sport , key . key_id , OoOOOO00oOO ) )
   dprint ( "{}" . format ( key . print_keys ( ) ) )
   if 8 - 8: i11iIiiIii . iII111i / iIii1I11I1II1 / I1ii11iIi11i / IiII - Ii1I
   if 32 - 32: o0oOOo0O0Ooo . i1IIi * Oo0Ooo
   if 98 - 98: Ii1I - II111iiii / I1IiiI . oO0o * IiII . I11i
   if 25 - 25: i11iIiiIii / OoOoOO00 - I1Ii111 / OoO0O00 . o0oOOo0O0Ooo . o0oOOo0O0Ooo
   if 6 - 6: oO0o . I11i
   if 43 - 43: I1ii11iIi11i + o0oOOo0O0Ooo
   lisp_retry_decap_keys ( addr_str , ooo00o0o0 + packet , Ii1IiiiI1ii , iIIi )
   return ( [ None , False ] )
   if 50 - 50: oO0o % i1IIi * O0
   if 4 - 4: iIii1I11I1II1 . i1IIi
   if 63 - 63: iIii1I11I1II1 + IiII % i1IIi / I1IiiI % II111iiii
   if 60 - 60: o0oOOo0O0Ooo . OoOoOO00 % I1Ii111 / I1IiiI / O0
   if 19 - 19: i11iIiiIii . I1IiiI + II111iiii / OOooOOo . I1ii11iIi11i * ooOoO0o
  packet = packet [ Ii1I1Iiii : : ]
  if 59 - 59: iIii1I11I1II1 / I1ii11iIi11i % ooOoO0o
  if 84 - 84: iIii1I11I1II1 / I1IiiI . OoOoOO00 % I11i
  if 99 - 99: Oo0Ooo + i11iIiiIii
  if 36 - 36: Ii1I * I1Ii111 * iIii1I11I1II1 - I11i % i11iIiiIii
  OOOO0O00o = lisp_get_timestamp ( )
  if ( key . cipher_suite == LISP_CS_25519_CHACHA ) :
   OoOo00O0o = chacha . ChaCha ( key . encrypt_key , Ii1IiiiI1ii ) . decrypt
  elif ( key . cipher_suite == LISP_CS_25519_GCM ) :
   III = binascii . unhexlify ( key . encrypt_key )
   try :
    OoOo00O0o = AES . new ( III , AES . MODE_GCM , Ii1IiiiI1ii ) . decrypt
   except :
    self . packet_error = "no-decrypt-key"
    lprint ( "You need AES-GCM, do a 'pip install pycryptodome'" )
    return ( [ None , False ] )
    if 96 - 96: IiII * IiII % ooOoO0o + o0oOOo0O0Ooo
  else :
   if ( ( len ( packet ) % 16 ) != 0 ) :
    dprint ( "Ciphertext not multiple of 16 bytes, packet dropped" )
    return ( [ None , False ] )
    if 27 - 27: Oo0Ooo * ooOoO0o + i11iIiiIii / I1IiiI - oO0o
   III = binascii . unhexlify ( key . encrypt_key )
   OoOo00O0o = AES . new ( III , AES . MODE_CBC , Ii1IiiiI1ii ) . decrypt
   if 44 - 44: Ii1I * ooOoO0o / OoOoOO00
   if 69 - 69: ooOoO0o . OOooOOo - I1IiiI
  IiIi = OoOo00O0o ( packet )
  OOOO0O00o = int ( str ( time . time ( ) - OOOO0O00o ) . split ( "." ) [ 1 ] [ 0 : 6 ] )
  if 44 - 44: II111iiii . II111iiii + OOooOOo * Ii1I
  if 16 - 16: II111iiii
  if 100 - 100: O0 - i1IIi
  if 48 - 48: oO0o % ooOoO0o + O0
  O0I11IIIII = bold ( "Decrypt" , False )
  addr_str = "RLOC: " + red ( addr_str , False )
  II11IiI1 = "poly" if key . do_poly else "sha256"
  II11IiI1 = bold ( II11IiI1 , False )
  OoOOOO00oOO = "ICV({}): {}" . format ( II11IiI1 , I1I11i )
  dprint ( "{} for key-id: {}, {}, {} (good), {}-time: {} usec" . format ( O0I11IIIII , key . key_id , addr_str , OoOOOO00oOO , OoO , OOOO0O00o ) )
  if 27 - 27: I1ii11iIi11i / OOooOOo
  if 33 - 33: OoooooooOO % I1ii11iIi11i . O0 / I1ii11iIi11i
  if 63 - 63: IiII + iIii1I11I1II1 + I1IiiI + I1Ii111
  if 72 - 72: OoO0O00 + i11iIiiIii + I1ii11iIi11i
  if 96 - 96: oO0o % i1IIi / o0oOOo0O0Ooo
  if 13 - 13: II111iiii - Oo0Ooo % i11iIiiIii + iII111i
  if 88 - 88: O0 . oO0o % I1IiiI
  self . packet = self . packet [ 0 : header_length ]
  return ( [ IiIi , True ] )
  if 10 - 10: I1IiiI + O0
  if 75 - 75: O0 % iIii1I11I1II1 / OoOoOO00 % OOooOOo / IiII
 def fragment_outer ( self , outer_hdr , inner_packet ) :
  iiI1iiIiiiI1I = 1000
  if 6 - 6: OoO0O00
  if 99 - 99: o0oOOo0O0Ooo * OOooOOo % oO0o * oO0o + OoooooooOO
  if 82 - 82: I11i / OoOoOO00 - OOooOOo / ooOoO0o
  if 50 - 50: OOooOOo + OoO0O00 . i11iIiiIii + I1ii11iIi11i + i11iIiiIii
  if 31 - 31: oO0o * I1Ii111 . OoOoOO00 * I11i
  I1II1I = [ ]
  ii = 0
  OOOOO000oo0 = len ( inner_packet )
  while ( ii < OOOOO000oo0 ) :
   O0O = inner_packet [ ii : : ]
   if ( len ( O0O ) > iiI1iiIiiiI1I ) : O0O = O0O [ 0 : iiI1iiIiiiI1I ]
   I1II1I . append ( O0O )
   ii += len ( O0O )
   if 7 - 7: I11i + I11i + II111iiii % Ii1I
   if 31 - 31: oO0o * OoOoOO00 + OOooOOo
   if 58 - 58: o0oOOo0O0Ooo % I1IiiI . I1IiiI * OoO0O00 - IiII . OoooooooOO
   if 10 - 10: I1Ii111
   if 48 - 48: iII111i * i1IIi % OoooooooOO * Ii1I * OoO0O00
   if 7 - 7: iII111i . Ii1I . iII111i - I1Ii111
  I1IiiIi11 = [ ]
  ii = 0
  for O0O in I1II1I :
   if 20 - 20: OOooOOo - iII111i / Oo0Ooo * OoO0O00
   if 55 - 55: OoooooooOO
   if 73 - 73: OoOoOO00 - I1ii11iIi11i % Oo0Ooo + I1ii11iIi11i - O0 . OoO0O00
   if 38 - 38: O0
   ooO = ii if ( O0O == I1II1I [ - 1 ] ) else 0x2000 + ii
   ooO = socket . htons ( ooO )
   outer_hdr = outer_hdr [ 0 : 6 ] + struct . pack ( "H" , ooO ) + outer_hdr [ 8 : : ]
   if 34 - 34: I1Ii111 * II111iiii
   if 71 - 71: IiII
   if 97 - 97: I1ii11iIi11i
   if 86 - 86: Oo0Ooo - OOooOOo . OoOoOO00 . II111iiii * I1IiiI . II111iiii
   II1Ooo0000o00OO = socket . htons ( len ( O0O ) + 20 )
   outer_hdr = outer_hdr [ 0 : 2 ] + struct . pack ( "H" , II1Ooo0000o00OO ) + outer_hdr [ 4 : : ]
   outer_hdr = lisp_ip_checksum ( outer_hdr )
   I1IiiIi11 . append ( outer_hdr + O0O )
   ii += len ( O0O ) / 8
   if 9 - 9: II111iiii * i11iIiiIii . OOooOOo - OoO0O00
  return ( I1IiiIi11 )
  if 31 - 31: i11iIiiIii * Ii1I . o0oOOo0O0Ooo % OOooOOo * I1ii11iIi11i % O0
  if 77 - 77: OoO0O00 + OoO0O00 . ooOoO0o * OoooooooOO + OoO0O00
 def fragment ( self ) :
  oOo = self . fix_outer_header ( self . packet )
  if 6 - 6: i1IIi - I11i
  if 89 - 89: ooOoO0o - I11i . O0 % OoooooooOO . i11iIiiIii
  if 35 - 35: II111iiii / OoOoOO00 - O0 . II111iiii
  if 55 - 55: Oo0Ooo % i1IIi * I11i
  if 95 - 95: OOooOOo / II111iiii - o0oOOo0O0Ooo % I1Ii111 . I11i
  if 63 - 63: iIii1I11I1II1 / ooOoO0o
  OOOOO000oo0 = len ( oOo )
  if ( OOOOO000oo0 <= 1500 ) : return ( [ oOo ] , "Fragment-None" )
  if 24 - 24: Oo0Ooo / iIii1I11I1II1 % OOooOOo * OoOoOO00 - iIii1I11I1II1
  oOo = self . packet
  if 50 - 50: II111iiii
  if 39 - 39: II111iiii . OoOoOO00 - Oo0Ooo * i1IIi . OoooooooOO
  if 44 - 44: I1IiiI
  if 55 - 55: oO0o . I1Ii111 * I1Ii111
  if 82 - 82: I1IiiI % OoO0O00 % I11i + I11i
  if ( self . inner_version != 4 ) :
   i1111I = random . randint ( 0 , 0xffff )
   OoO00oo0 = oOo [ 0 : 4 ] + struct . pack ( "H" , i1111I ) + oOo [ 6 : 20 ]
   oOOO = oOo [ 20 : : ]
   I1IiiIi11 = self . fragment_outer ( OoO00oo0 , oOOO )
   return ( I1IiiIi11 , "Fragment-Outer" )
   if 62 - 62: Ii1I - oO0o % iIii1I11I1II1
   if 57 - 57: OoooooooOO / OoOoOO00
   if 44 - 44: OoOoOO00 * i1IIi * O0
   if 94 - 94: I1IiiI - O0
   if 18 - 18: IiII / oO0o . oO0o . iIii1I11I1II1 . i11iIiiIii
  Oo0o0oo0 = 56 if ( self . outer_version == 6 ) else 36
  OoO00oo0 = oOo [ 0 : Oo0o0oo0 ]
  oOOoOOooO0 = oOo [ Oo0o0oo0 : Oo0o0oo0 + 20 ]
  oOOO = oOo [ Oo0o0oo0 + 20 : : ]
  if 42 - 42: iIii1I11I1II1 * Ii1I / OoO0O00 + OOooOOo
  if 48 - 48: OoooooooOO - I1Ii111 . i11iIiiIii * iII111i - Ii1I - o0oOOo0O0Ooo
  if 59 - 59: iII111i / I11i . Oo0Ooo
  if 100 - 100: O0
  oOOO00Oo = struct . unpack ( "H" , oOOoOOooO0 [ 6 : 8 ] ) [ 0 ]
  oOOO00Oo = socket . ntohs ( oOOO00Oo )
  Ii1iii1 = os . getenv ( "LISP_IGNORE_DF_BIT" ) != None
  if ( oOOO00Oo & 0x4000 ) :
   if ( Ii1iii1 ) :
    oOOO00Oo &= ~ 0x4000
   else :
    iii11III1I = bold ( "DF-bit set" , False )
    dprint ( "{} in inner header, packet discarded" . format ( iii11III1I ) )
    return ( [ ] , "Fragment-None-DF-bit" )
    if 61 - 61: I1ii11iIi11i + iIii1I11I1II1 % o0oOOo0O0Ooo
    if 78 - 78: iIii1I11I1II1 - II111iiii / I1IiiI
    if 9 - 9: I1ii11iIi11i * Ii1I - IiII
  ii = 0
  OOOOO000oo0 = len ( oOOO )
  I1IiiIi11 = [ ]
  while ( ii < OOOOO000oo0 ) :
   I1IiiIi11 . append ( oOOO [ ii : ii + 1400 ] )
   ii += 1400
   if 88 - 88: iIii1I11I1II1
   if 27 - 27: I11i * i11iIiiIii . OOooOOo + ooOoO0o
   if 14 - 14: I1Ii111 * OoO0O00 + I11i - IiII . I1ii11iIi11i * oO0o
   if 100 - 100: I11i
   if 36 - 36: OoO0O00 + II111iiii * OoOoOO00
  I1II1I = I1IiiIi11
  I1IiiIi11 = [ ]
  i11i1IIIIII = True if oOOO00Oo & 0x2000 else False
  oOOO00Oo = ( oOOO00Oo & 0x1fff ) * 8
  for O0O in I1II1I :
   if 59 - 59: II111iiii . I1ii11iIi11i + I1ii11iIi11i * OoO0O00 * I1IiiI / OoooooooOO
   if 15 - 15: ooOoO0o % o0oOOo0O0Ooo / oO0o - II111iiii . iIii1I11I1II1
   if 28 - 28: II111iiii * ooOoO0o * Ii1I
   if 93 - 93: i1IIi . Ii1I * I1Ii111 . ooOoO0o
   O0iI1I1ii11IIi1 = oOOO00Oo / 8
   if ( i11i1IIIIII ) :
    O0iI1I1ii11IIi1 |= 0x2000
   elif ( O0O != I1II1I [ - 1 ] ) :
    O0iI1I1ii11IIi1 |= 0x2000
    if 100 - 100: Oo0Ooo . Ii1I . I1IiiI % II111iiii - oO0o
   O0iI1I1ii11IIi1 = socket . htons ( O0iI1I1ii11IIi1 )
   oOOoOOooO0 = oOOoOOooO0 [ 0 : 6 ] + struct . pack ( "H" , O0iI1I1ii11IIi1 ) + oOOoOOooO0 [ 8 : : ]
   if 52 - 52: I1IiiI % OoO0O00 * Ii1I * iII111i / OOooOOo
   if 88 - 88: oO0o
   if 1 - 1: Oo0Ooo
   if 95 - 95: OoooooooOO / I11i % OoooooooOO / ooOoO0o * IiII
   if 75 - 75: O0
   if 56 - 56: OoO0O00 / II111iiii
   OOOOO000oo0 = len ( O0O )
   oOOO00Oo += OOOOO000oo0
   II1Ooo0000o00OO = socket . htons ( OOOOO000oo0 + 20 )
   oOOoOOooO0 = oOOoOOooO0 [ 0 : 2 ] + struct . pack ( "H" , II1Ooo0000o00OO ) + oOOoOOooO0 [ 4 : 10 ] + struct . pack ( "H" , 0 ) + oOOoOOooO0 [ 12 : : ]
   if 39 - 39: OoOoOO00 - OoooooooOO - i1IIi / II111iiii
   oOOoOOooO0 = lisp_ip_checksum ( oOOoOOooO0 )
   IIIii1 = oOOoOOooO0 + O0O
   if 76 - 76: I1IiiI * OOooOOo
   if 12 - 12: iIii1I11I1II1 / I11i % Ii1I
   if 49 - 49: OoO0O00 + II111iiii / IiII - O0 % Ii1I
   if 27 - 27: OoO0O00 + Oo0Ooo
   if 92 - 92: I1IiiI % iII111i
   OOOOO000oo0 = len ( IIIii1 )
   if ( self . outer_version == 4 ) :
    II1Ooo0000o00OO = OOOOO000oo0 + Oo0o0oo0
    OOOOO000oo0 += 16
    OoO00oo0 = OoO00oo0 [ 0 : 2 ] + struct . pack ( "H" , II1Ooo0000o00OO ) + OoO00oo0 [ 4 : : ]
    if 31 - 31: OoooooooOO - oO0o / I1Ii111
    OoO00oo0 = lisp_ip_checksum ( OoO00oo0 )
    IIIii1 = OoO00oo0 + IIIii1
    IIIii1 = self . fix_outer_header ( IIIii1 )
    if 62 - 62: i11iIiiIii - I11i
    if 81 - 81: I11i
    if 92 - 92: OOooOOo - Oo0Ooo - OoooooooOO / IiII - i1IIi
    if 81 - 81: i1IIi / I1Ii111 % i11iIiiIii . iIii1I11I1II1 * OoOoOO00 + OoooooooOO
    if 31 - 31: i1IIi % II111iiii
   Ii1iii11I = Oo0o0oo0 - 12
   II1Ooo0000o00OO = socket . htons ( OOOOO000oo0 )
   IIIii1 = IIIii1 [ 0 : Ii1iii11I ] + struct . pack ( "H" , II1Ooo0000o00OO ) + IIIii1 [ Ii1iii11I + 2 : : ]
   if 2 - 2: OoooooooOO - Ii1I % oO0o / I1IiiI / o0oOOo0O0Ooo
   I1IiiIi11 . append ( IIIii1 )
   if 3 - 3: II111iiii / OOooOOo
  return ( I1IiiIi11 , "Fragment-Inner" )
  if 48 - 48: ooOoO0o . I1ii11iIi11i
  if 49 - 49: i1IIi - OoOoOO00 . Oo0Ooo + iIii1I11I1II1 - ooOoO0o / Oo0Ooo
 def fix_outer_header ( self , packet ) :
  if 24 - 24: oO0o - iII111i / ooOoO0o
  if 10 - 10: OoOoOO00 * i1IIi
  if 15 - 15: I11i + i1IIi - II111iiii % I1IiiI
  if 34 - 34: I1IiiI
  if 57 - 57: OOooOOo . Ii1I % o0oOOo0O0Ooo
  if 32 - 32: I11i / IiII - O0 * iIii1I11I1II1
  if 70 - 70: OoooooooOO % OoooooooOO % OoO0O00
  if 98 - 98: OoO0O00
  if ( self . outer_version == 4 or self . inner_version == 4 ) :
   if ( lisp_is_macos ( ) ) :
    packet = packet [ 0 : 2 ] + packet [ 3 ] + packet [ 2 ] + packet [ 4 : 6 ] + packet [ 7 ] + packet [ 6 ] + packet [ 8 : : ]
    if 18 - 18: I11i + Oo0Ooo - OoO0O00 / I1Ii111 / OOooOOo
   else :
    packet = packet [ 0 : 2 ] + packet [ 3 ] + packet [ 2 ] + packet [ 4 : : ]
    if 53 - 53: OOooOOo + o0oOOo0O0Ooo . oO0o / I11i
    if 52 - 52: I1Ii111 + I1Ii111
  return ( packet )
  if 73 - 73: o0oOOo0O0Ooo . i11iIiiIii % OoooooooOO + ooOoO0o . OoooooooOO / OOooOOo
  if 54 - 54: OoOoOO00 . OoooooooOO
 def send_packet ( self , lisp_raw_socket , dest ) :
  if ( lisp_flow_logging and dest != self . inner_dest ) : self . log_flow ( True )
  if 36 - 36: oO0o / II111iiii * IiII % I1ii11iIi11i
  dest = dest . print_address_no_iid ( )
  I1IiiIi11 , IiIIii = self . fragment ( )
  if 74 - 74: iIii1I11I1II1 / Ii1I
  for IIIii1 in I1IiiIi11 :
   if ( len ( I1IiiIi11 ) != 1 ) :
    self . packet = IIIii1
    self . print_packet ( IiIIii , True )
    if 59 - 59: Ii1I / II111iiii - IiII % OoOoOO00 % OoooooooOO
    if 79 - 79: iII111i . OoooooooOO . I1IiiI * O0 * OoO0O00 - OOooOOo
   try : lisp_raw_socket . sendto ( IIIii1 , ( dest , 0 ) )
   except socket . error , Oo0ooo0Ooo :
    lprint ( "socket.sendto() failed: {}" . format ( Oo0ooo0Ooo ) )
    if 33 - 33: I1ii11iIi11i . Oo0Ooo + I1IiiI + o0oOOo0O0Ooo
    if 54 - 54: ooOoO0o * iII111i * iII111i % OoOoOO00 - OOooOOo % I1ii11iIi11i
    if 44 - 44: Oo0Ooo . OOooOOo + I11i
    if 22 - 22: I1Ii111 * OoooooooOO + i11iIiiIii % OoO0O00
 def send_l2_packet ( self , l2_socket , mac_header ) :
  if ( l2_socket == None ) :
   lprint ( "No layer-2 socket, drop IPv6 packet" )
   return
   if 53 - 53: I1IiiI
  if ( mac_header == None ) :
   lprint ( "Could not build MAC header, drop IPv6 packet" )
   return
   if 10 - 10: I1Ii111 / i11iIiiIii - II111iiii
   if 48 - 48: OOooOOo
  oOo = mac_header + self . packet
  if 26 - 26: iII111i * I1Ii111 * oO0o * OoOoOO00
  if 48 - 48: iII111i % i11iIiiIii . OoooooooOO * IiII % OoO0O00 . iII111i
  if 6 - 6: O0 . ooOoO0o - oO0o / i11iIiiIii
  if 84 - 84: I11i / I1ii11iIi11i * o0oOOo0O0Ooo * OoO0O00 * OOooOOo * O0
  if 83 - 83: O0 % II111iiii + o0oOOo0O0Ooo / OoooooooOO
  if 75 - 75: II111iiii . I1IiiI + OOooOOo - OoOoOO00 - O0 . I11i
  if 19 - 19: Ii1I * i1IIi % O0 + I11i
  if 25 - 25: I1Ii111 - Ii1I / O0 . OoooooooOO % I1IiiI . i1IIi
  if 19 - 19: II111iiii / II111iiii % I1ii11iIi11i + oO0o + oO0o + iII111i
  if 4 - 4: o0oOOo0O0Ooo + I11i / iII111i + i1IIi % o0oOOo0O0Ooo % iII111i
  if 80 - 80: Ii1I
  l2_socket . write ( oOo )
  return
  if 26 - 26: iIii1I11I1II1 . OoooooooOO - iIii1I11I1II1
  if 59 - 59: I1ii11iIi11i + I11i . oO0o
 def bridge_l2_packet ( self , eid , db ) :
  try : oOOo0oO = db . dynamic_eids [ eid . print_address_no_iid ( ) ]
  except : return
  try : II111IiiiI1 = lisp_myinterfaces [ oOOo0oO . interface ]
  except : return
  try :
   socket = II111IiiiI1 . get_bridge_socket ( )
   if ( socket == None ) : return
  except : return
  if 19 - 19: iII111i
  try : socket . send ( self . packet )
  except socket . error , Oo0ooo0Ooo :
   lprint ( "bridge_l2_packet(): socket.send() failed: {}" . format ( Oo0ooo0Ooo ) )
   if 46 - 46: Oo0Ooo + II111iiii * I1IiiI + OOooOOo
   if 31 - 31: Ii1I * o0oOOo0O0Ooo * Ii1I + OoO0O00 * o0oOOo0O0Ooo . I1Ii111
   if 89 - 89: OoooooooOO * Ii1I * I1IiiI . ooOoO0o * Ii1I / iII111i
 def is_lisp_packet ( self , packet ) :
  OOOOo00oo00O = ( struct . unpack ( "B" , packet [ 9 ] ) [ 0 ] == LISP_UDP_PROTOCOL )
  if ( OOOOo00oo00O == False ) : return ( False )
  if 46 - 46: i11iIiiIii
  Iiiii = struct . unpack ( "H" , packet [ 22 : 24 ] ) [ 0 ]
  if ( socket . ntohs ( Iiiii ) == LISP_DATA_PORT ) : return ( True )
  Iiiii = struct . unpack ( "H" , packet [ 20 : 22 ] ) [ 0 ]
  if ( socket . ntohs ( Iiiii ) == LISP_DATA_PORT ) : return ( True )
  return ( False )
  if 25 - 25: Oo0Ooo * I1IiiI + OOooOOo + I1Ii111 % OOooOOo
  if 84 - 84: O0 % Ii1I . Ii1I . iII111i * I11i
 def decode ( self , is_lisp_packet , lisp_ipc_socket , stats ) :
  self . packet_error = ""
  oOo = self . packet
  iI = len ( oOo )
  OO0O = I11IiiiII = True
  if 66 - 66: Oo0Ooo / i11iIiiIii % ooOoO0o
  if 43 - 43: OOooOOo
  if 84 - 84: OOooOOo . IiII . iII111i
  if 2 - 2: Oo0Ooo - OoOoOO00
  I1iiII = 0
  II1 = 0
  if ( is_lisp_packet ) :
   II1 = self . lisp_header . get_instance_id ( )
   oOOOO0 = struct . unpack ( "B" , oOo [ 0 : 1 ] ) [ 0 ]
   self . outer_version = oOOOO0 >> 4
   if ( self . outer_version == 4 ) :
    if 99 - 99: OOooOOo + I1IiiI . I1ii11iIi11i * OoooooooOO
    if 82 - 82: i11iIiiIii + iIii1I11I1II1 / Oo0Ooo + OOooOOo * II111iiii
    if 34 - 34: o0oOOo0O0Ooo % OoooooooOO
    if 36 - 36: I1IiiI
    if 64 - 64: i11iIiiIii + i1IIi % O0 . I11i
    o00o0 = struct . unpack ( "H" , oOo [ 10 : 12 ] ) [ 0 ]
    oOo = lisp_ip_checksum ( oOo )
    I11i11I = struct . unpack ( "H" , oOo [ 10 : 12 ] ) [ 0 ]
    if ( I11i11I != 0 ) :
     if ( o00o0 != 0 or lisp_is_macos ( ) == False ) :
      self . packet_error = "checksum-error"
      if ( stats ) :
       stats [ self . packet_error ] . increment ( iI )
       if 84 - 84: OoOoOO00 - Oo0Ooo . ooOoO0o . IiII - Oo0Ooo
       if 99 - 99: I1Ii111
      lprint ( "IPv4 header checksum failed for outer header" )
      if ( lisp_flow_logging ) : self . log_flow ( False )
      return ( None )
      if 75 - 75: ooOoO0o . OOooOOo / IiII
      if 84 - 84: OoooooooOO . I1IiiI / o0oOOo0O0Ooo
      if 86 - 86: Oo0Ooo % OoOoOO00
    o0o0O00oOo = LISP_AFI_IPV4
    ii = 12
    self . outer_tos = struct . unpack ( "B" , oOo [ 1 : 2 ] ) [ 0 ]
    self . outer_ttl = struct . unpack ( "B" , oOo [ 8 : 9 ] ) [ 0 ]
    I1iiII = 20
   elif ( self . outer_version == 6 ) :
    o0o0O00oOo = LISP_AFI_IPV6
    ii = 8
    iI1ii = struct . unpack ( "H" , oOo [ 0 : 2 ] ) [ 0 ]
    self . outer_tos = ( socket . ntohs ( iI1ii ) >> 4 ) & 0xff
    self . outer_ttl = struct . unpack ( "B" , oOo [ 7 : 8 ] ) [ 0 ]
    I1iiII = 40
   else :
    self . packet_error = "outer-header-error"
    if ( stats ) : stats [ self . packet_error ] . increment ( iI )
    lprint ( "Cannot decode outer header" )
    return ( None )
    if 2 - 2: II111iiii . I11i
    if 83 - 83: I1IiiI - I1Ii111 + I1IiiI . I1IiiI
   self . outer_source . afi = o0o0O00oOo
   self . outer_dest . afi = o0o0O00oOo
   ii11ii11II = self . outer_source . addr_length ( )
   if 35 - 35: Oo0Ooo * II111iiii
   self . outer_source . unpack_address ( oOo [ ii : ii + ii11ii11II ] )
   ii += ii11ii11II
   self . outer_dest . unpack_address ( oOo [ ii : ii + ii11ii11II ] )
   oOo = oOo [ I1iiII : : ]
   self . outer_source . mask_len = self . outer_source . host_mask_len ( )
   self . outer_dest . mask_len = self . outer_dest . host_mask_len ( )
   if 32 - 32: oO0o . Oo0Ooo / ooOoO0o + ooOoO0o . I1ii11iIi11i
   if 50 - 50: iIii1I11I1II1 * oO0o
   if 85 - 85: i1IIi
   if 100 - 100: OoooooooOO / I11i % OoO0O00 + Ii1I
   IIi11 = struct . unpack ( "H" , oOo [ 0 : 2 ] ) [ 0 ]
   self . udp_sport = socket . ntohs ( IIi11 )
   IIi11 = struct . unpack ( "H" , oOo [ 2 : 4 ] ) [ 0 ]
   self . udp_dport = socket . ntohs ( IIi11 )
   IIi11 = struct . unpack ( "H" , oOo [ 4 : 6 ] ) [ 0 ]
   self . udp_length = socket . ntohs ( IIi11 )
   IIi11 = struct . unpack ( "H" , oOo [ 6 : 8 ] ) [ 0 ]
   self . udp_checksum = socket . ntohs ( IIi11 )
   oOo = oOo [ 8 : : ]
   if 77 - 77: Oo0Ooo - IiII
   if 50 - 50: OoO0O00 % OoooooooOO * II111iiii
   if 54 - 54: OoooooooOO + Oo0Ooo * OOooOOo
   if 98 - 98: oO0o - oO0o . ooOoO0o
   OO0O = ( self . udp_dport == LISP_DATA_PORT or
 self . udp_sport == LISP_DATA_PORT )
   I11IiiiII = ( self . udp_dport in ( LISP_L2_DATA_PORT , LISP_VXLAN_DATA_PORT ) )
   if 60 - 60: I1IiiI * I1ii11iIi11i / O0 + I11i + IiII
   if 66 - 66: IiII * Oo0Ooo . OoooooooOO * I1Ii111
   if 93 - 93: IiII / i1IIi
   if 47 - 47: ooOoO0o - Ii1I
   if ( self . lisp_header . decode ( oOo ) == False ) :
    self . packet_error = "lisp-header-error"
    if ( stats ) : stats [ self . packet_error ] . increment ( iI )
    if 98 - 98: oO0o . I1Ii111 / OoOoOO00 . ooOoO0o
    if ( lisp_flow_logging ) : self . log_flow ( False )
    lprint ( "Cannot decode LISP header" )
    return ( None )
    if 1 - 1: OOooOOo
   oOo = oOo [ 8 : : ]
   II1 = self . lisp_header . get_instance_id ( )
   I1iiII += 16
   if 87 - 87: O0 * II111iiii + iIii1I11I1II1 % oO0o % i11iIiiIii - OoOoOO00
  if ( II1 == 0xffffff ) : II1 = 0
  if 73 - 73: iII111i + Ii1I
  if 37 - 37: oO0o - iIii1I11I1II1 + II111iiii . Ii1I % iIii1I11I1II1
  if 17 - 17: I1Ii111 + i1IIi % O0
  if 65 - 65: IiII
  iiI11 = False
  OoooOOo0oOO = self . lisp_header . k_bits
  if ( OoooOOo0oOO ) :
   ooOOo0o = lisp_get_crypto_decap_lookup_key ( self . outer_source ,
 self . udp_sport )
   if ( ooOOo0o == None ) :
    self . packet_error = "no-decrypt-key"
    if ( stats ) : stats [ self . packet_error ] . increment ( iI )
    if 44 - 44: OOooOOo % iIii1I11I1II1
    self . print_packet ( "Receive" , is_lisp_packet )
    iiiiIi111 = bold ( "No key available" , False )
    dprint ( "{} for key-id {} to decrypt packet" . format ( iiiiIi111 , OoooOOo0oOO ) )
    if ( lisp_flow_logging ) : self . log_flow ( False )
    return ( None )
    if 41 - 41: I1IiiI / IiII . Oo0Ooo / IiII
    if 49 - 49: OoooooooOO - IiII
   Iiii11 = lisp_crypto_keys_by_rloc_decap [ ooOOo0o ] [ OoooOOo0oOO ]
   if ( Iiii11 == None ) :
    self . packet_error = "no-decrypt-key"
    if ( stats ) : stats [ self . packet_error ] . increment ( iI )
    if 65 - 65: I1Ii111 + iII111i * iII111i
    self . print_packet ( "Receive" , is_lisp_packet )
    iiiiIi111 = bold ( "No key available" , False )
    dprint ( "{} to decrypt packet from RLOC {}" . format ( iiiiIi111 ,
 red ( ooOOo0o , False ) ) )
    if ( lisp_flow_logging ) : self . log_flow ( False )
    return ( None )
    if 79 - 79: i1IIi / Oo0Ooo - I1IiiI . O0
    if 56 - 56: IiII % O0 * i1IIi - II111iiii
    if 74 - 74: i1IIi - OoOoOO00 % oO0o . O0 - OoooooooOO
    if 84 - 84: I1Ii111
    if 53 - 53: i1IIi
   Iiii11 . use_count += 1
   oOo , iiI11 = self . decrypt ( oOo , I1iiII , Iiii11 ,
 ooOOo0o )
   if ( iiI11 == False ) :
    if ( stats ) : stats [ self . packet_error ] . increment ( iI )
    if ( lisp_flow_logging ) : self . log_flow ( False )
    return ( None )
    if 59 - 59: o0oOOo0O0Ooo + I1IiiI % OoooooooOO - iIii1I11I1II1
    if 9 - 9: i1IIi - OoOoOO00
    if 57 - 57: iIii1I11I1II1 * Ii1I * iII111i / oO0o
    if 46 - 46: Ii1I
    if 61 - 61: o0oOOo0O0Ooo / ooOoO0o - II111iiii
    if 87 - 87: I1ii11iIi11i / I1IiiI
  oOOOO0 = struct . unpack ( "B" , oOo [ 0 : 1 ] ) [ 0 ]
  self . inner_version = oOOOO0 >> 4
  if ( OO0O and self . inner_version == 4 and oOOOO0 >= 0x45 ) :
   IIi1IiiIi1III = socket . ntohs ( struct . unpack ( "H" , oOo [ 2 : 4 ] ) [ 0 ] )
   self . inner_tos = struct . unpack ( "B" , oOo [ 1 : 2 ] ) [ 0 ]
   self . inner_ttl = struct . unpack ( "B" , oOo [ 8 : 9 ] ) [ 0 ]
   self . inner_protocol = struct . unpack ( "B" , oOo [ 9 : 10 ] ) [ 0 ]
   self . inner_source . afi = LISP_AFI_IPV4
   self . inner_dest . afi = LISP_AFI_IPV4
   self . inner_source . unpack_address ( oOo [ 12 : 16 ] )
   self . inner_dest . unpack_address ( oOo [ 16 : 20 ] )
   oOOO00Oo = socket . ntohs ( struct . unpack ( "H" , oOo [ 6 : 8 ] ) [ 0 ] )
   self . inner_is_fragment = ( oOOO00Oo & 0x2000 or oOOO00Oo != 0 )
   if ( self . inner_protocol == LISP_UDP_PROTOCOL ) :
    self . inner_sport = struct . unpack ( "H" , oOo [ 20 : 22 ] ) [ 0 ]
    self . inner_sport = socket . ntohs ( self . inner_sport )
    self . inner_dport = struct . unpack ( "H" , oOo [ 22 : 24 ] ) [ 0 ]
    self . inner_dport = socket . ntohs ( self . inner_dport )
    if 19 - 19: i1IIi % I1IiiI - iIii1I11I1II1 - oO0o / I1ii11iIi11i
  elif ( OO0O and self . inner_version == 6 and oOOOO0 >= 0x60 ) :
   IIi1IiiIi1III = socket . ntohs ( struct . unpack ( "H" , oOo [ 4 : 6 ] ) [ 0 ] ) + 40
   iI1ii = struct . unpack ( "H" , oOo [ 0 : 2 ] ) [ 0 ]
   self . inner_tos = ( socket . ntohs ( iI1ii ) >> 4 ) & 0xff
   self . inner_ttl = struct . unpack ( "B" , oOo [ 7 : 8 ] ) [ 0 ]
   self . inner_protocol = struct . unpack ( "B" , oOo [ 6 : 7 ] ) [ 0 ]
   self . inner_source . afi = LISP_AFI_IPV6
   self . inner_dest . afi = LISP_AFI_IPV6
   self . inner_source . unpack_address ( oOo [ 8 : 24 ] )
   self . inner_dest . unpack_address ( oOo [ 24 : 40 ] )
   if ( self . inner_protocol == LISP_UDP_PROTOCOL ) :
    self . inner_sport = struct . unpack ( "H" , oOo [ 40 : 42 ] ) [ 0 ]
    self . inner_sport = socket . ntohs ( self . inner_sport )
    self . inner_dport = struct . unpack ( "H" , oOo [ 42 : 44 ] ) [ 0 ]
    self . inner_dport = socket . ntohs ( self . inner_dport )
    if 16 - 16: Ii1I
  elif ( I11IiiiII ) :
   IIi1IiiIi1III = len ( oOo )
   self . inner_tos = 0
   self . inner_ttl = 0
   self . inner_protocol = 0
   self . inner_source . afi = LISP_AFI_MAC
   self . inner_dest . afi = LISP_AFI_MAC
   self . inner_dest . unpack_address ( self . swap_mac ( oOo [ 0 : 6 ] ) )
   self . inner_source . unpack_address ( self . swap_mac ( oOo [ 6 : 12 ] ) )
  elif ( self . lisp_header . get_instance_id ( ) == 0xffffff ) :
   if ( lisp_flow_logging ) : self . log_flow ( False )
   return ( self )
  else :
   self . packet_error = "bad-inner-version"
   if ( stats ) : stats [ self . packet_error ] . increment ( iI )
   if 79 - 79: OoooooooOO - ooOoO0o * Ii1I - II111iiii % OoOoOO00 * IiII
   lprint ( "Cannot decode encapsulation, header version {}" . format ( hex ( oOOOO0 ) ) )
   if 31 - 31: I1IiiI
   oOo = lisp_format_packet ( oOo [ 0 : 20 ] )
   lprint ( "Packet header: {}" . format ( oOo ) )
   if ( lisp_flow_logging and is_lisp_packet ) : self . log_flow ( False )
   return ( None )
   if 36 - 36: OoO0O00 + OoO0O00 + OoO0O00 % Oo0Ooo * iII111i
  self . inner_source . mask_len = self . inner_source . host_mask_len ( )
  self . inner_dest . mask_len = self . inner_dest . host_mask_len ( )
  self . inner_source . instance_id = II1
  self . inner_dest . instance_id = II1
  if 98 - 98: I11i . I11i / Oo0Ooo / Ii1I / I1IiiI
  if 56 - 56: o0oOOo0O0Ooo / IiII
  if 11 - 11: OoOoOO00 / I11i
  if 47 - 47: OOooOOo . I1Ii111 % II111iiii + Oo0Ooo - oO0o . II111iiii
  if 37 - 37: iIii1I11I1II1 . I1IiiI % OoO0O00 % OoooooooOO . OoooooooOO / O0
  if ( lisp_nonce_echoing and is_lisp_packet ) :
   IiIii1i11i1 = lisp_get_echo_nonce ( self . outer_source , None )
   if ( IiIii1i11i1 == None ) :
    ooOOo00o0ooO = self . outer_source . print_address_no_iid ( )
    IiIii1i11i1 = lisp_echo_nonce ( ooOOo00o0ooO )
    if 40 - 40: o0oOOo0O0Ooo . o0oOOo0O0Ooo * i11iIiiIii
   i11III1I = self . lisp_header . get_nonce ( )
   if ( self . lisp_header . is_e_bit_set ( ) ) :
    IiIii1i11i1 . receive_request ( lisp_ipc_socket , i11III1I )
   elif ( IiIii1i11i1 . request_nonce_sent ) :
    IiIii1i11i1 . receive_echo ( lisp_ipc_socket , i11III1I )
    if 98 - 98: Ii1I - O0 * oO0o * Ii1I * Ii1I
    if 44 - 44: IiII + I11i
    if 66 - 66: oO0o
    if 34 - 34: iII111i % i11iIiiIii + i11iIiiIii - iII111i
    if 2 - 2: II111iiii + i1IIi
    if 68 - 68: OOooOOo + Ii1I
    if 58 - 58: IiII * Ii1I . i1IIi
  if ( iiI11 ) : self . packet += oOo [ : IIi1IiiIi1III ]
  if 19 - 19: oO0o
  if 85 - 85: ooOoO0o - I1IiiI / i1IIi / OoO0O00 / II111iiii
  if 94 - 94: iIii1I11I1II1 + IiII
  if 44 - 44: OoO0O00 + I11i % OoO0O00 + i1IIi + iII111i + O0
  if ( lisp_flow_logging and is_lisp_packet ) : self . log_flow ( False )
  return ( self )
  if 18 - 18: iIii1I11I1II1 % iIii1I11I1II1 % oO0o + I1IiiI % ooOoO0o / Ii1I
  if 36 - 36: OoOoOO00 . i11iIiiIii
 def swap_mac ( self , mac ) :
  return ( mac [ 1 ] + mac [ 0 ] + mac [ 3 ] + mac [ 2 ] + mac [ 5 ] + mac [ 4 ] )
  if 81 - 81: Oo0Ooo * iII111i * OoO0O00
  if 85 - 85: O0 * oO0o
 def strip_outer_headers ( self ) :
  ii = 16
  ii += 20 if ( self . outer_version == 4 ) else 40
  self . packet = self . packet [ ii : : ]
  return ( self )
  if 39 - 39: II111iiii * I1IiiI - iIii1I11I1II1
  if 25 - 25: OoooooooOO . Ii1I % iII111i . IiII
 def hash_ports ( self ) :
  oOo = self . packet
  oOOOO0 = self . inner_version
  ooo000 = 0
  if ( oOOOO0 == 4 ) :
   oooOoO0oo0o0 = struct . unpack ( "B" , oOo [ 9 ] ) [ 0 ]
   if ( self . inner_is_fragment ) : return ( oooOoO0oo0o0 )
   if ( oooOoO0oo0o0 in [ 6 , 17 ] ) :
    ooo000 = oooOoO0oo0o0
    ooo000 += struct . unpack ( "I" , oOo [ 20 : 24 ] ) [ 0 ]
    ooo000 = ( ooo000 >> 16 ) ^ ( ooo000 & 0xffff )
    if 4 - 4: i11iIiiIii * I1ii11iIi11i + OoooooooOO - IiII . ooOoO0o . iIii1I11I1II1
    if 48 - 48: o0oOOo0O0Ooo * oO0o . I1IiiI - I1Ii111 + OOooOOo . Oo0Ooo
  if ( oOOOO0 == 6 ) :
   oooOoO0oo0o0 = struct . unpack ( "B" , oOo [ 6 ] ) [ 0 ]
   if ( oooOoO0oo0o0 in [ 6 , 17 ] ) :
    ooo000 = oooOoO0oo0o0
    ooo000 += struct . unpack ( "I" , oOo [ 40 : 44 ] ) [ 0 ]
    ooo000 = ( ooo000 >> 16 ) ^ ( ooo000 & 0xffff )
    if 62 - 62: I11i + OoooooooOO * iIii1I11I1II1 / i1IIi * O0
    if 10 - 10: iIii1I11I1II1 * OoooooooOO / OOooOOo
  return ( ooo000 )
  if 33 - 33: o0oOOo0O0Ooo % IiII - iIii1I11I1II1 % OOooOOo + I1Ii111 - i11iIiiIii
  if 91 - 91: OoooooooOO . iIii1I11I1II1 / i11iIiiIii
 def hash_packet ( self ) :
  ooo000 = self . inner_source . address ^ self . inner_dest . address
  ooo000 += self . hash_ports ( )
  if ( self . inner_version == 4 ) :
   ooo000 = ( ooo000 >> 16 ) ^ ( ooo000 & 0xffff )
  elif ( self . inner_version == 6 ) :
   ooo000 = ( ooo000 >> 64 ) ^ ( ooo000 & 0xffffffffffffffff )
   ooo000 = ( ooo000 >> 32 ) ^ ( ooo000 & 0xffffffff )
   ooo000 = ( ooo000 >> 16 ) ^ ( ooo000 & 0xffff )
   if 80 - 80: I1IiiI
  self . udp_sport = 0xf000 | ( ooo000 & 0xfff )
  if 58 - 58: oO0o + I1ii11iIi11i % OoOoOO00
  if 22 - 22: iIii1I11I1II1 - Ii1I / I1IiiI * IiII
 def print_packet ( self , s_or_r , is_lisp_packet ) :
  if ( is_lisp_packet == False ) :
   III1IIi = "{} -> {}" . format ( self . inner_source . print_address ( ) ,
 self . inner_dest . print_address ( ) )
   dprint ( ( "{} {}, tos/ttl: {}/{}, length: {}, packet: {} ..." ) . format ( bold ( s_or_r , False ) ,
   # ooOoO0o - i1IIi . OoOoOO00
 green ( III1IIi , False ) , self . inner_tos ,
 self . inner_ttl , len ( self . packet ) ,
 lisp_format_packet ( self . packet [ 0 : 60 ] ) ) )
   return
   if 12 - 12: IiII / OoO0O00 / O0 * IiII
   if 51 - 51: ooOoO0o * iII111i / i1IIi
  if ( s_or_r . find ( "Receive" ) != - 1 ) :
   IIi1I1 = "decap"
   IIi1I1 += "-vxlan" if self . udp_dport == LISP_VXLAN_DATA_PORT else ""
  else :
   IIi1I1 = s_or_r
   if ( IIi1I1 in [ "Send" , "Replicate" ] or IIi1I1 . find ( "Fragment" ) != - 1 ) :
    IIi1I1 = "encap"
    if 37 - 37: o0oOOo0O0Ooo * Oo0Ooo
    if 11 - 11: oO0o
  Oo0O0o00o00 = "{} -> {}" . format ( self . outer_source . print_address_no_iid ( ) ,
 self . outer_dest . print_address_no_iid ( ) )
  if 90 - 90: I1Ii111 . II111iiii . I1ii11iIi11i
  if 32 - 32: ooOoO0o - OoO0O00 . iII111i . iII111i % i1IIi * Ii1I
  if 65 - 65: iII111i / ooOoO0o . II111iiii
  if 90 - 90: I11i
  if 95 - 95: OoO0O00
  if ( self . lisp_header . get_instance_id ( ) == 0xffffff ) :
   IIIIIiI11Ii = ( "{} LISP packet, outer RLOCs: {}, outer tos/ttl: " + "{}/{}, outer UDP: {} -> {}, " )
   if 68 - 68: iIii1I11I1II1 . iIii1I11I1II1 / OoOoOO00 - II111iiii - iIii1I11I1II1
   IIIIIiI11Ii += bold ( "control-packet" , False ) + ": {} ..."
   if 75 - 75: ooOoO0o . I1IiiI * II111iiii
   dprint ( IIIIIiI11Ii . format ( bold ( s_or_r , False ) , red ( Oo0O0o00o00 , False ) ,
 self . outer_tos , self . outer_ttl , self . udp_sport ,
 self . udp_dport , lisp_format_packet ( self . packet [ 0 : 56 ] ) ) )
   return
  else :
   IIIIIiI11Ii = ( "{} LISP packet, outer RLOCs: {}, outer tos/ttl: " + "{}/{}, outer UDP: {} -> {}, inner EIDs: {}, " + "inner tos/ttl: {}/{}, length: {}, {}, packet: {} ..." )
   if 99 - 99: iIii1I11I1II1 * I1ii11iIi11i + IiII
   if 70 - 70: i1IIi % ooOoO0o . I1ii11iIi11i - IiII + OOooOOo
   if 84 - 84: oO0o + II111iiii * II111iiii % o0oOOo0O0Ooo / iII111i + ooOoO0o
   if 9 - 9: iII111i
  if ( self . lisp_header . k_bits ) :
   if ( IIi1I1 == "encap" ) : IIi1I1 = "encrypt/encap"
   if ( IIi1I1 == "decap" ) : IIi1I1 = "decap/decrypt"
   if 25 - 25: OOooOOo - Ii1I . I11i
   if 57 - 57: o0oOOo0O0Ooo + Oo0Ooo * I1ii11iIi11i - ooOoO0o % iIii1I11I1II1 - Ii1I
  III1IIi = "{} -> {}" . format ( self . inner_source . print_address ( ) ,
 self . inner_dest . print_address ( ) )
  if 37 - 37: OoO0O00 * I11i + Ii1I + I1ii11iIi11i * o0oOOo0O0Ooo
  dprint ( IIIIIiI11Ii . format ( bold ( s_or_r , False ) , red ( Oo0O0o00o00 , False ) ,
 self . outer_tos , self . outer_ttl , self . udp_sport , self . udp_dport ,
 green ( III1IIi , False ) , self . inner_tos , self . inner_ttl ,
 len ( self . packet ) , self . lisp_header . print_header ( IIi1I1 ) ,
 lisp_format_packet ( self . packet [ 0 : 56 ] ) ) )
  if 95 - 95: Ii1I - i11iIiiIii % i11iIiiIii - O0 * I1Ii111
  if 81 - 81: II111iiii * I1IiiI % i1IIi * i11iIiiIii + OoOoOO00
 def print_eid_tuple ( self ) :
  return ( lisp_print_eid_tuple ( self . inner_source , self . inner_dest ) )
  if 100 - 100: i1IIi % Ii1I
  if 55 - 55: I1IiiI + iII111i
 def get_raw_socket ( self ) :
  II1 = str ( self . lisp_header . get_instance_id ( ) )
  if ( II1 == "0" ) : return ( None )
  if ( lisp_iid_to_interface . has_key ( II1 ) == False ) : return ( None )
  if 85 - 85: oO0o + iII111i % iII111i / I11i . I1IiiI - OoOoOO00
  II111IiiiI1 = lisp_iid_to_interface [ II1 ]
  o00oOOO = II111IiiiI1 . get_socket ( )
  if ( o00oOOO == None ) :
   O0I11IIIII = bold ( "SO_BINDTODEVICE" , False )
   i1I11 = ( os . getenv ( "LISP_ENFORCE_BINDTODEVICE" ) != None )
   lprint ( "{} required for multi-tenancy support, {} packet" . format ( O0I11IIIII , "drop" if i1I11 else "forward" ) )
   if 76 - 76: iIii1I11I1II1 / I1Ii111 - I1ii11iIi11i % o0oOOo0O0Ooo % OOooOOo + OoooooooOO
   if ( i1I11 ) : return ( None )
   if 10 - 10: OoO0O00 * I11i / Oo0Ooo - I1Ii111
   if 11 - 11: IiII % I1ii11iIi11i / ooOoO0o . i11iIiiIii + OOooOOo - II111iiii
  II1 = bold ( II1 , False )
  i1 = bold ( II111IiiiI1 . device , False )
  dprint ( "Send packet on instance-id {} interface {}" . format ( II1 , i1 ) )
  return ( o00oOOO )
  if 50 - 50: i1IIi * oO0o / i11iIiiIii / i11iIiiIii / oO0o
  if 84 - 84: I1ii11iIi11i - iII111i + I1ii11iIi11i
 def log_flow ( self , encap ) :
  global lisp_flow_log
  if 63 - 63: I11i * ooOoO0o % II111iiii % I1Ii111 + I1IiiI * Oo0Ooo
  o0oOo00OOo0O = os . path . exists ( "./log-flows" )
  if ( len ( lisp_flow_log ) == LISP_FLOW_LOG_SIZE or o0oOo00OOo0O ) :
   OO0OOoOOO = [ lisp_flow_log ]
   lisp_flow_log = [ ]
   threading . Thread ( target = lisp_write_flow_log , args = OO0OOoOOO ) . start ( )
   if ( o0oOo00OOo0O ) : os . system ( "rm ./log-flows" )
   return
   if 96 - 96: I1ii11iIi11i - O0
   if 35 - 35: OOooOOo . I11i . I1Ii111 - I11i % I11i + I1Ii111
  OOOO0O00o = datetime . datetime . now ( )
  lisp_flow_log . append ( [ OOOO0O00o , encap , self . packet , self ] )
  if 99 - 99: o0oOOo0O0Ooo + OOooOOo
  if 34 - 34: I1Ii111 * o0oOOo0O0Ooo . I1IiiI % i11iIiiIii
 def print_flow ( self , ts , encap , packet ) :
  ts = ts . strftime ( "%m/%d/%y %H:%M:%S.%f" ) [ : - 3 ]
  Oo0OO0 = "{}: {}" . format ( ts , "encap" if encap else "decap" )
  if 74 - 74: Ii1I - OoooooooOO
  Iii1I1I = red ( self . outer_source . print_address_no_iid ( ) , False )
  IIi = red ( self . outer_dest . print_address_no_iid ( ) , False )
  IIiIi1II1IiI = green ( self . inner_source . print_address ( ) , False )
  oo0OoO = green ( self . inner_dest . print_address ( ) , False )
  if 3 - 3: IiII - OoooooooOO * OoooooooOO - I1IiiI / I1Ii111 * I1ii11iIi11i
  if ( self . lisp_header . get_instance_id ( ) == 0xffffff ) :
   Oo0OO0 += " {}:{} -> {}:{}, LISP control message type {}\n"
   Oo0OO0 = Oo0OO0 . format ( Iii1I1I , self . udp_sport , IIi , self . udp_dport ,
 self . inner_version )
   return ( Oo0OO0 )
   if 58 - 58: IiII % iIii1I11I1II1 / i11iIiiIii % o0oOOo0O0Ooo . I1Ii111 * iII111i
   if 32 - 32: OoooooooOO + o0oOOo0O0Ooo
  if ( self . outer_dest . is_null ( ) == False ) :
   Oo0OO0 += " {}:{} -> {}:{}, len/tos/ttl {}/{}/{}"
   Oo0OO0 = Oo0OO0 . format ( Iii1I1I , self . udp_sport , IIi , self . udp_dport ,
 len ( packet ) , self . outer_tos , self . outer_ttl )
   if 91 - 91: ooOoO0o - I1Ii111 * I1Ii111
   if 55 - 55: iIii1I11I1II1 + I1IiiI - Oo0Ooo
   if 24 - 24: OoO0O00 / I1Ii111 + iII111i * I11i * iII111i
   if 10 - 10: I1IiiI - I1ii11iIi11i - Oo0Ooo - o0oOOo0O0Ooo
   if 21 - 21: OoooooooOO + I1Ii111
  if ( self . lisp_header . k_bits != 0 ) :
   iiIi1111Ii1 = "\n"
   if ( self . packet_error != "" ) :
    iiIi1111Ii1 = " ({})" . format ( self . packet_error ) + iiIi1111Ii1
    if 31 - 31: o0oOOo0O0Ooo * I11i - i11iIiiIii - I1IiiI
   Oo0OO0 += ", encrypted" + iiIi1111Ii1
   return ( Oo0OO0 )
   if 19 - 19: iII111i . I11i * OoooooooOO - OOooOOo + O0 * I1Ii111
   if 90 - 90: i1IIi . oO0o / I1Ii111 . OOooOOo / I1Ii111
   if 1 - 1: iII111i % ooOoO0o
   if 99 - 99: iII111i + iIii1I11I1II1 . OOooOOo / OoO0O00 * I1ii11iIi11i
   if 87 - 87: IiII / II111iiii % OoO0O00 % OoO0O00
  if ( self . outer_dest . is_null ( ) == False ) :
   packet = packet [ 36 : : ] if self . outer_version == 4 else packet [ 56 : : ]
   if 28 - 28: OoOoOO00 % oO0o - OOooOOo + OOooOOo + oO0o / iIii1I11I1II1
   if 91 - 91: I1IiiI / II111iiii * OOooOOo
  oooOoO0oo0o0 = packet [ 9 ] if self . inner_version == 4 else packet [ 6 ]
  oooOoO0oo0o0 = struct . unpack ( "B" , oooOoO0oo0o0 ) [ 0 ]
  if 94 - 94: II111iiii - iIii1I11I1II1 - iIii1I11I1II1
  Oo0OO0 += " {} -> {}, len/tos/ttl/prot {}/{}/{}/{}"
  Oo0OO0 = Oo0OO0 . format ( IIiIi1II1IiI , oo0OoO , len ( packet ) , self . inner_tos ,
 self . inner_ttl , oooOoO0oo0o0 )
  if 83 - 83: I1ii11iIi11i * iIii1I11I1II1 + OoOoOO00 * i1IIi . OoooooooOO % Ii1I
  if 81 - 81: OoO0O00 - iIii1I11I1II1
  if 60 - 60: I1Ii111
  if 77 - 77: I1IiiI / I1ii11iIi11i
  if ( oooOoO0oo0o0 in [ 6 , 17 ] ) :
   o0OoOOoooooOO = packet [ 20 : 24 ] if self . inner_version == 4 else packet [ 40 : 44 ]
   if ( len ( o0OoOOoooooOO ) == 4 ) :
    o0OoOOoooooOO = socket . ntohl ( struct . unpack ( "I" , o0OoOOoooooOO ) [ 0 ] )
    Oo0OO0 += ", ports {} -> {}" . format ( o0OoOOoooooOO >> 16 , o0OoOOoooooOO & 0xffff )
    if 88 - 88: i1IIi
  elif ( oooOoO0oo0o0 == 1 ) :
   O0o = packet [ 26 : 28 ] if self . inner_version == 4 else packet [ 46 : 48 ]
   if ( len ( O0o ) == 2 ) :
    O0o = socket . ntohs ( struct . unpack ( "H" , O0o ) [ 0 ] )
    Oo0OO0 += ", icmp-seq {}" . format ( O0o )
    if 69 - 69: oO0o - I1Ii111 / Oo0Ooo
    if 15 - 15: i1IIi
  if ( self . packet_error != "" ) :
   Oo0OO0 += " ({})" . format ( self . packet_error )
   if 39 - 39: Ii1I % i1IIi . I1ii11iIi11i - O0
  Oo0OO0 += "\n"
  return ( Oo0OO0 )
  if 65 - 65: oO0o * oO0o / I11i + oO0o % ooOoO0o + OoOoOO00
  if 92 - 92: o0oOOo0O0Ooo
 def is_trace ( self ) :
  o0OoOOoooooOO = [ self . inner_sport , self . inner_dport ]
  return ( self . inner_protocol == LISP_UDP_PROTOCOL and
 LISP_TRACE_PORT in o0OoOOoooooOO )
  if 37 - 37: oO0o
  if 18 - 18: IiII * i11iIiiIii + iIii1I11I1II1 % I11i + i1IIi - OoO0O00
  if 85 - 85: OoO0O00 * I11i + OoO0O00
  if 39 - 39: Oo0Ooo / i1IIi % i1IIi
  if 20 - 20: OOooOOo * oO0o
  if 91 - 91: OoO0O00 % i1IIi - iIii1I11I1II1 . OOooOOo
  if 31 - 31: oO0o % i1IIi . OoooooooOO - o0oOOo0O0Ooo + OoooooooOO
  if 45 - 45: OOooOOo + I11i / OoooooooOO - Ii1I + OoooooooOO
  if 42 - 42: iIii1I11I1II1 * I1IiiI * I1Ii111
  if 62 - 62: OOooOOo * O0 % IiII . IiII . I1IiiI
  if 91 - 91: i1IIi . iII111i
  if 37 - 37: iII111i - I11i + iIii1I11I1II1 / I1Ii111 - OoO0O00 . o0oOOo0O0Ooo
  if 62 - 62: I1ii11iIi11i
  if 47 - 47: I1Ii111 % OOooOOo * OoO0O00 . iIii1I11I1II1 % Oo0Ooo + OoooooooOO
  if 2 - 2: I1Ii111 % OoooooooOO - ooOoO0o * I1ii11iIi11i * IiII
  if 99 - 99: iIii1I11I1II1 . Oo0Ooo / ooOoO0o . OOooOOo % I1IiiI * I11i
LISP_N_BIT = 0x80000000
LISP_L_BIT = 0x40000000
LISP_E_BIT = 0x20000000
LISP_V_BIT = 0x10000000
LISP_I_BIT = 0x08000000
LISP_P_BIT = 0x04000000
LISP_K_BITS = 0x03000000
if 95 - 95: oO0o
class lisp_data_header ( ) :
 def __init__ ( self ) :
  self . first_long = 0
  self . second_long = 0
  self . k_bits = 0
  if 80 - 80: IiII
  if 42 - 42: OoooooooOO * II111iiii
 def print_header ( self , e_or_d ) :
  O0oooOO = lisp_hex_string ( self . first_long & 0xffffff )
  IIiIi1I1iI1 = lisp_hex_string ( self . second_long ) . zfill ( 8 )
  if 39 - 39: OOooOOo
  IIIIIiI11Ii = ( "{} LISP-header -> flags: {}{}{}{}{}{}{}{}, nonce: {}, " + "iid/lsb: {}" )
  if 70 - 70: IiII % OoO0O00 % I1IiiI
  return ( IIIIIiI11Ii . format ( bold ( e_or_d , False ) ,
 "N" if ( self . first_long & LISP_N_BIT ) else "n" ,
 "L" if ( self . first_long & LISP_L_BIT ) else "l" ,
 "E" if ( self . first_long & LISP_E_BIT ) else "e" ,
 "V" if ( self . first_long & LISP_V_BIT ) else "v" ,
 "I" if ( self . first_long & LISP_I_BIT ) else "i" ,
 "P" if ( self . first_long & LISP_P_BIT ) else "p" ,
 "K" if ( self . k_bits in [ 2 , 3 ] ) else "k" ,
 "K" if ( self . k_bits in [ 1 , 3 ] ) else "k" ,
 O0oooOO , IIiIi1I1iI1 ) )
  if 95 - 95: OoOoOO00 - I1Ii111 / O0 * I1IiiI - o0oOOo0O0Ooo
  if 12 - 12: iIii1I11I1II1 % Oo0Ooo . iII111i . IiII % i11iIiiIii
 def encode ( self ) :
  IIiI1I11ii1i = "II"
  O0oooOO = socket . htonl ( self . first_long )
  IIiIi1I1iI1 = socket . htonl ( self . second_long )
  if 75 - 75: O0
  oooooOOo0Oo = struct . pack ( IIiI1I11ii1i , O0oooOO , IIiIi1I1iI1 )
  return ( oooooOOo0Oo )
  if 29 - 29: O0 * i11iIiiIii / OoooooooOO / o0oOOo0O0Ooo . ooOoO0o
  if 70 - 70: OoooooooOO . ooOoO0o / oO0o . oO0o - o0oOOo0O0Ooo
 def decode ( self , packet ) :
  IIiI1I11ii1i = "II"
  i1II1i1iiI1 = struct . calcsize ( IIiI1I11ii1i )
  if ( len ( packet ) < i1II1i1iiI1 ) : return ( False )
  if 62 - 62: Ii1I . i11iIiiIii % O0 % I1Ii111 - Oo0Ooo
  O0oooOO , IIiIi1I1iI1 = struct . unpack ( IIiI1I11ii1i , packet [ : i1II1i1iiI1 ] )
  if 69 - 69: II111iiii . OoOoOO00 * OoOoOO00 % Ii1I + I1IiiI
  if 100 - 100: i11iIiiIii - Oo0Ooo
  self . first_long = socket . ntohl ( O0oooOO )
  self . second_long = socket . ntohl ( IIiIi1I1iI1 )
  self . k_bits = ( self . first_long & LISP_K_BITS ) >> 24
  return ( True )
  if 47 - 47: iII111i * OoOoOO00 * IiII
  if 46 - 46: Ii1I
 def key_id ( self , key_id ) :
  self . first_long &= ~ ( 0x3 << 24 )
  self . first_long |= ( ( key_id & 0x3 ) << 24 )
  self . k_bits = key_id
  if 42 - 42: iIii1I11I1II1
  if 32 - 32: Oo0Ooo - Ii1I . OoooooooOO - OoooooooOO - Oo0Ooo . iIii1I11I1II1
 def nonce ( self , nonce ) :
  self . first_long |= LISP_N_BIT
  self . first_long |= nonce
  if 34 - 34: Oo0Ooo
  if 31 - 31: i1IIi - I11i + I1Ii111 + ooOoO0o . ooOoO0o . O0
 def map_version ( self , version ) :
  self . first_long |= LISP_V_BIT
  self . first_long |= version
  if 33 - 33: i1IIi / iII111i * OoO0O00
  if 2 - 2: oO0o . OOooOOo
 def instance_id ( self , iid ) :
  if ( iid == 0 ) : return
  self . first_long |= LISP_I_BIT
  self . second_long &= 0xff
  self . second_long |= ( iid << 8 )
  if 43 - 43: iIii1I11I1II1
  if 29 - 29: IiII % ooOoO0o + OoO0O00 . i1IIi + I1IiiI
 def get_instance_id ( self ) :
  return ( ( self . second_long >> 8 ) & 0xffffff )
  if 24 - 24: I1Ii111 / Ii1I * I1ii11iIi11i - OoooooooOO / I1IiiI . oO0o
  if 98 - 98: i1IIi - iII111i
 def locator_status_bits ( self , lsbs ) :
  self . first_long |= LISP_L_BIT
  self . second_long &= 0xffffff00
  self . second_long |= ( lsbs & 0xff )
  if 49 - 49: o0oOOo0O0Ooo . Ii1I . oO0o
  if 9 - 9: IiII - II111iiii * OoO0O00
 def is_request_nonce ( self , nonce ) :
  return ( nonce & 0x80000000 )
  if 78 - 78: iIii1I11I1II1 / O0 * oO0o / iII111i / OoOoOO00
  if 15 - 15: ooOoO0o / oO0o
 def request_nonce ( self , nonce ) :
  self . first_long |= LISP_E_BIT
  self . first_long |= LISP_N_BIT
  self . first_long |= ( nonce & 0xffffff )
  if 54 - 54: ooOoO0o - iIii1I11I1II1 - I11i % Ii1I / II111iiii
  if 80 - 80: i11iIiiIii % iIii1I11I1II1 / i11iIiiIii
 def is_e_bit_set ( self ) :
  return ( self . first_long & LISP_E_BIT )
  if 66 - 66: OoOoOO00 . iIii1I11I1II1 * I1ii11iIi11i - Ii1I - iIii1I11I1II1
  if 28 - 28: OoOoOO00 % OoooooooOO
 def get_nonce ( self ) :
  return ( self . first_long & 0xffffff )
  if 13 - 13: IiII . Oo0Ooo - I11i / oO0o - Oo0Ooo - I1IiiI
  if 84 - 84: II111iiii
  if 57 - 57: O0 * iIii1I11I1II1 % O0 . OoooooooOO
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
  if 53 - 53: Ii1I / I1IiiI * Ii1I + o0oOOo0O0Ooo + oO0o - Oo0Ooo
  if 16 - 16: OoO0O00 % I1Ii111 . i1IIi / I1ii11iIi11i - O0
 def send_ipc ( self , ipc_socket , ipc ) :
  oo = "lisp-itr" if lisp_i_am_itr else "lisp-etr"
  iIi11i1I11Ii = "lisp-etr" if lisp_i_am_itr else "lisp-itr"
  ipc = lisp_command_ipc ( ipc , oo )
  lisp_ipc ( ipc , ipc_socket , iIi11i1I11Ii )
  if 59 - 59: i11iIiiIii - I11i
  if 59 - 59: OoooooooOO * o0oOOo0O0Ooo / I1Ii111
 def send_request_ipc ( self , ipc_socket , nonce ) :
  nonce = lisp_hex_string ( nonce )
  oOooOOoo = "nonce%R%{}%{}" . format ( self . rloc_str , nonce )
  self . send_ipc ( ipc_socket , oOooOOoo )
  if 12 - 12: oO0o . OOooOOo
  if 52 - 52: i11iIiiIii / I11i % IiII
 def send_echo_ipc ( self , ipc_socket , nonce ) :
  nonce = lisp_hex_string ( nonce )
  oOooOOoo = "nonce%E%{}%{}" . format ( self . rloc_str , nonce )
  self . send_ipc ( ipc_socket , oOooOOoo )
  if 21 - 21: iII111i % IiII % Oo0Ooo % O0
  if 63 - 63: II111iiii * I1IiiI - OoooooooOO / I1IiiI
 def receive_request ( self , ipc_socket , nonce ) :
  III11II111 = self . request_nonce_rcvd
  self . request_nonce_rcvd = nonce
  self . last_request_nonce_rcvd = lisp_get_timestamp ( )
  if ( lisp_i_am_rtr ) : return
  if ( III11II111 != nonce ) : self . send_request_ipc ( ipc_socket , nonce )
  if 8 - 8: i11iIiiIii
  if 4 - 4: i11iIiiIii
 def receive_echo ( self , ipc_socket , nonce ) :
  if ( self . request_nonce_sent != nonce ) : return
  self . last_echo_nonce_rcvd = lisp_get_timestamp ( )
  if ( self . echo_nonce_rcvd == nonce ) : return
  if 28 - 28: OoO0O00
  self . echo_nonce_rcvd = nonce
  if ( lisp_i_am_rtr ) : return
  self . send_echo_ipc ( ipc_socket , nonce )
  if 73 - 73: Oo0Ooo . ooOoO0o - Oo0Ooo % OOooOOo / i11iIiiIii / iIii1I11I1II1
  if 15 - 15: ooOoO0o * iIii1I11I1II1 * oO0o
 def get_request_or_echo_nonce ( self , ipc_socket , remote_rloc ) :
  if 96 - 96: I1Ii111 * iIii1I11I1II1 / OoOoOO00 % OOooOOo * II111iiii
  if 3 - 3: OOooOOo . Oo0Ooo / i11iIiiIii + OoO0O00
  if 47 - 47: IiII . OOooOOo
  if 96 - 96: I11i % II111iiii / ooOoO0o % OOooOOo / ooOoO0o % i11iIiiIii
  if 57 - 57: I11i - I11i % II111iiii % Oo0Ooo . o0oOOo0O0Ooo % Oo0Ooo
  if ( self . request_nonce_sent and self . echo_nonce_sent and remote_rloc ) :
   OoOOOO00 = lisp_myrlocs [ 0 ] if remote_rloc . is_ipv4 ( ) else lisp_myrlocs [ 1 ]
   if 15 - 15: OOooOOo * ooOoO0o + II111iiii . I1Ii111 . oO0o
   if 46 - 46: IiII % I1Ii111 + iIii1I11I1II1 * I1IiiI
   if ( remote_rloc . address > OoOOOO00 . address ) :
    ii1iI1iI1 = "exit"
    self . request_nonce_sent = None
   else :
    ii1iI1iI1 = "stay in"
    self . echo_nonce_sent = None
    if 64 - 64: I1ii11iIi11i * Ii1I * Oo0Ooo % IiII % ooOoO0o
    if 55 - 55: II111iiii - I1Ii111 - OOooOOo % Ii1I
   iI1I1iII1iII = bold ( "collision" , False )
   II1Ooo0000o00OO = red ( OoOOOO00 . print_address_no_iid ( ) , False )
   Oo0O = red ( remote_rloc . print_address_no_iid ( ) , False )
   lprint ( "Echo nonce {}, {} -> {}, {} request-nonce mode" . format ( iI1I1iII1iII ,
 II1Ooo0000o00OO , Oo0O , ii1iI1iI1 ) )
   if 11 - 11: O0
   if 96 - 96: iII111i + o0oOOo0O0Ooo
   if 10 - 10: i11iIiiIii . OoooooooOO . O0 % ooOoO0o / OoO0O00
   if 36 - 36: I1IiiI % i1IIi + OoO0O00
   if 59 - 59: i11iIiiIii - i11iIiiIii + I1IiiI
  if ( self . echo_nonce_sent != None ) :
   i11III1I = self . echo_nonce_sent
   Oo0ooo0Ooo = bold ( "Echoing" , False )
   lprint ( "{} nonce 0x{} to {}" . format ( Oo0ooo0Ooo ,
 lisp_hex_string ( i11III1I ) , red ( self . rloc_str , False ) ) )
   self . last_echo_nonce_sent = lisp_get_timestamp ( )
   self . echo_nonce_sent = None
   return ( i11III1I )
   if 4 - 4: Oo0Ooo * O0 - oO0o % ooOoO0o + OoOoOO00
   if 3 - 3: OoOoOO00
   if 91 - 91: O0 - I11i % I1Ii111
   if 46 - 46: ooOoO0o / I1IiiI . IiII % OoO0O00 / i11iIiiIii
   if 13 - 13: I1Ii111 % o0oOOo0O0Ooo + OOooOOo + I1Ii111 + i11iIiiIii - I1ii11iIi11i
   if 70 - 70: II111iiii * II111iiii . I1IiiI
   if 11 - 11: iII111i
  i11III1I = self . request_nonce_sent
  i1OooO00oO00o = self . last_request_nonce_sent
  if ( i11III1I and i1OooO00oO00o != None ) :
   if ( time . time ( ) - i1OooO00oO00o >= LISP_NONCE_ECHO_INTERVAL ) :
    self . request_nonce_sent = None
    lprint ( "Stop request-nonce mode for {}, nonce 0x{}" . format ( red ( self . rloc_str , False ) , lisp_hex_string ( i11III1I ) ) )
    if 14 - 14: I1ii11iIi11i * Oo0Ooo + i11iIiiIii % OOooOOo - oO0o
    return ( None )
    if 11 - 11: I1ii11iIi11i / O0 + II111iiii
    if 95 - 95: I1Ii111 + IiII * iIii1I11I1II1
    if 17 - 17: OoO0O00 - Oo0Ooo * O0 / Ii1I
    if 19 - 19: i1IIi - iIii1I11I1II1 . I11i
    if 2 - 2: Ii1I
    if 12 - 12: i11iIiiIii - iIii1I11I1II1 * IiII * iII111i
    if 19 - 19: O0 + oO0o + o0oOOo0O0Ooo
    if 81 - 81: iIii1I11I1II1
    if 51 - 51: o0oOOo0O0Ooo . I1ii11iIi11i * Ii1I / Oo0Ooo * II111iiii / O0
  if ( i11III1I == None ) :
   i11III1I = lisp_get_data_nonce ( )
   if ( self . recently_requested ( ) ) : return ( i11III1I )
   if 44 - 44: i11iIiiIii % I1Ii111 % oO0o + I11i * oO0o . Ii1I
   self . request_nonce_sent = i11III1I
   lprint ( "Start request-nonce mode for {}, nonce 0x{}" . format ( red ( self . rloc_str , False ) , lisp_hex_string ( i11III1I ) ) )
   if 89 - 89: OoooooooOO % II111iiii - OoO0O00 % i11iIiiIii
   self . last_new_request_nonce_sent = lisp_get_timestamp ( )
   if 7 - 7: IiII
   if 15 - 15: Oo0Ooo + iII111i + I1IiiI * o0oOOo0O0Ooo
   if 33 - 33: o0oOOo0O0Ooo * Oo0Ooo
   if 88 - 88: I1Ii111 % OOooOOo - OoOoOO00 - OoOoOO00 . I1IiiI
   if 52 - 52: II111iiii / II111iiii / I1IiiI - I1Ii111
   if ( lisp_i_am_itr == False ) : return ( i11III1I | 0x80000000 )
   self . send_request_ipc ( ipc_socket , i11III1I )
  else :
   lprint ( "Continue request-nonce mode for {}, nonce 0x{}" . format ( red ( self . rloc_str , False ) , lisp_hex_string ( i11III1I ) ) )
   if 91 - 91: I1IiiI + o0oOOo0O0Ooo % II111iiii + OoO0O00
   if 66 - 66: iIii1I11I1II1 * II111iiii % Oo0Ooo % I1IiiI - Ii1I
   if 59 - 59: IiII % oO0o
   if 21 - 21: OoooooooOO % OoOoOO00 - OoOoOO00 / I1ii11iIi11i / o0oOOo0O0Ooo
   if 15 - 15: ooOoO0o / ooOoO0o % OoooooooOO . I1Ii111
   if 93 - 93: I1ii11iIi11i * I1ii11iIi11i / OoooooooOO
   if 6 - 6: I1ii11iIi11i * Oo0Ooo + iIii1I11I1II1
  self . last_request_nonce_sent = lisp_get_timestamp ( )
  return ( i11III1I | 0x80000000 )
  if 19 - 19: O0 % II111iiii * o0oOOo0O0Ooo
  if 27 - 27: OOooOOo * IiII / i11iIiiIii - oO0o + II111iiii
 def request_nonce_timeout ( self ) :
  if ( self . request_nonce_sent == None ) : return ( False )
  if ( self . request_nonce_sent == self . echo_nonce_rcvd ) : return ( False )
  if 43 - 43: I1ii11iIi11i - II111iiii
  iIIiI1iiI = time . time ( ) - self . last_request_nonce_sent
  OOo = self . last_echo_nonce_rcvd
  return ( iIIiI1iiI >= LISP_NONCE_ECHO_INTERVAL and OOo == None )
  if 22 - 22: i1IIi % ooOoO0o - I11i . II111iiii * OoOoOO00
  if 10 - 10: OoOoOO00 / OoooooooOO . iIii1I11I1II1 / I1IiiI / I1ii11iIi11i - Oo0Ooo
 def recently_requested ( self ) :
  OOo = self . last_request_nonce_sent
  if ( OOo == None ) : return ( False )
  if 22 - 22: O0
  iIIiI1iiI = time . time ( ) - OOo
  return ( iIIiI1iiI <= LISP_NONCE_ECHO_INTERVAL )
  if 72 - 72: Oo0Ooo % Oo0Ooo - o0oOOo0O0Ooo
  if 28 - 28: Ii1I + I1IiiI - oO0o + oO0o * I11i + oO0o
 def recently_echoed ( self ) :
  if ( self . request_nonce_sent == None ) : return ( True )
  if 70 - 70: i1IIi % OoO0O00 / i1IIi
  if 30 - 30: OoOoOO00 - i11iIiiIii
  if 94 - 94: OoOoOO00 % iII111i
  if 39 - 39: OoOoOO00 + I1Ii111 % O0
  OOo = self . last_good_echo_nonce_rcvd
  if ( OOo == None ) : OOo = 0
  iIIiI1iiI = time . time ( ) - OOo
  if ( iIIiI1iiI <= LISP_NONCE_ECHO_INTERVAL ) : return ( True )
  if 26 - 26: ooOoO0o + OoOoOO00
  if 17 - 17: I1ii11iIi11i - iII111i % Oo0Ooo * O0 % O0 * OOooOOo
  if 6 - 6: I1Ii111
  if 46 - 46: II111iiii * I1Ii111
  if 23 - 23: i1IIi - O0
  if 6 - 6: ooOoO0o % OoooooooOO * I1Ii111 - IiII
  OOo = self . last_new_request_nonce_sent
  if ( OOo == None ) : OOo = 0
  iIIiI1iiI = time . time ( ) - OOo
  return ( iIIiI1iiI <= LISP_NONCE_ECHO_INTERVAL )
  if 24 - 24: I11i / iIii1I11I1II1 . OoooooooOO % OoOoOO00 . Ii1I
  if 73 - 73: I1Ii111
 def change_state ( self , rloc ) :
  if ( rloc . up_state ( ) and self . recently_echoed ( ) == False ) :
   i1IiIiiiii11 = bold ( "down" , False )
   oooo = lisp_print_elapsed ( self . last_good_echo_nonce_rcvd )
   lprint ( "Take {} {}, last good echo: {}" . format ( red ( self . rloc_str , False ) , i1IiIiiiii11 , oooo ) )
   if 65 - 65: Oo0Ooo . OoOoOO00 . OOooOOo % o0oOOo0O0Ooo + OoO0O00
   rloc . state = LISP_RLOC_NO_ECHOED_NONCE_STATE
   rloc . last_state_change = lisp_get_timestamp ( )
   return
   if 53 - 53: Oo0Ooo * I11i - Ii1I % OoO0O00 - OoOoOO00 - iII111i
   if 21 - 21: II111iiii + OoO0O00 - Oo0Ooo + I1IiiI
  if ( rloc . no_echoed_nonce_state ( ) == False ) : return
  if 20 - 20: OoO0O00
  if ( self . recently_requested ( ) == False ) :
   o00OooooOOOO = bold ( "up" , False )
   lprint ( "Bring {} {}, retry request-nonce mode" . format ( red ( self . rloc_str , False ) , o00OooooOOOO ) )
   if 89 - 89: O0 + IiII * I1Ii111
   rloc . state = LISP_RLOC_UP_STATE
   rloc . last_state_change = lisp_get_timestamp ( )
   if 30 - 30: OoOoOO00
   if 39 - 39: I1ii11iIi11i + o0oOOo0O0Ooo + I1Ii111 + IiII
   if 48 - 48: I1Ii111 / ooOoO0o . iIii1I11I1II1
 def print_echo_nonce ( self ) :
  ooo0OOoo = lisp_print_elapsed ( self . last_request_nonce_sent )
  oO0o00O = lisp_print_elapsed ( self . last_good_echo_nonce_rcvd )
  if 7 - 7: Oo0Ooo * OoO0O00 - II111iiii % I1Ii111 . Oo0Ooo . Oo0Ooo
  iiII1iIi1ii1i = lisp_print_elapsed ( self . last_echo_nonce_sent )
  i11IiI1 = lisp_print_elapsed ( self . last_request_nonce_rcvd )
  o00oOOO = space ( 4 )
  if 62 - 62: ooOoO0o * I1ii11iIi11i / iII111i * OOooOOo / OOooOOo - iII111i
  I1i = "Nonce-Echoing:\n"
  I1i += ( "{}Last request-nonce sent: {}\n{}Last echo-nonce " + "received: {}\n" ) . format ( o00oOOO , ooo0OOoo , o00oOOO , oO0o00O )
  if 59 - 59: Ii1I % iII111i / II111iiii + I1IiiI * ooOoO0o
  I1i += ( "{}Last request-nonce received: {}\n{}Last echo-nonce " + "sent: {}" ) . format ( o00oOOO , i11IiI1 , o00oOOO , iiII1iIi1ii1i )
  if 100 - 100: I1ii11iIi11i
  if 81 - 81: I1ii11iIi11i % iII111i
  return ( I1i )
  if 22 - 22: OoooooooOO + o0oOOo0O0Ooo . I11i + I1IiiI + OoooooooOO . OoOoOO00
  if 93 - 93: I1IiiI
  if 89 - 89: OoooooooOO % i11iIiiIii + I1Ii111
  if 12 - 12: OoOoOO00 * ooOoO0o
  if 59 - 59: II111iiii * OoooooooOO - OoooooooOO
  if 33 - 33: O0 . i11iIiiIii % o0oOOo0O0Ooo
  if 50 - 50: ooOoO0o
  if 81 - 81: i11iIiiIii * iIii1I11I1II1 / Oo0Ooo * OOooOOo
  if 83 - 83: i11iIiiIii - I1IiiI * i11iIiiIii
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
    if 59 - 59: iII111i - OoooooooOO / ooOoO0o + I1ii11iIi11i . o0oOOo0O0Ooo - iII111i
   self . local_private_key = random . randint ( 0 , 2 ** 128 - 1 )
   Iiii11 = lisp_hex_string ( self . local_private_key ) . zfill ( 32 )
   self . curve25519 = curve25519 . Private ( Iiii11 )
  else :
   self . local_private_key = random . randint ( 0 , 0x1fff )
   if 29 - 29: oO0o
  self . local_public_key = self . compute_public_key ( )
  self . remote_public_key = None
  self . shared_key = None
  self . encrypt_key = None
  self . icv_key = None
  self . icv = poly1305 if do_poly else hashlib . sha256
  self . iv = None
  self . get_iv ( )
  self . do_poly = do_poly
  if 26 - 26: O0 % OOooOOo - IiII . OOooOOo
  if 70 - 70: o0oOOo0O0Ooo + I11i / iII111i + ooOoO0o / I1IiiI
 def copy_keypair ( self , key ) :
  self . local_private_key = key . local_private_key
  self . local_public_key = key . local_public_key
  self . curve25519 = key . curve25519
  if 33 - 33: OoooooooOO . O0
  if 59 - 59: iIii1I11I1II1
 def get_iv ( self ) :
  if ( self . iv == None ) :
   self . iv = random . randint ( 0 , LISP_16_128_MASK )
  else :
   self . iv += 1
   if 45 - 45: O0
  Ii1IiiiI1ii = self . iv
  if ( self . cipher_suite == LISP_CS_25519_CHACHA ) :
   Ii1IiiiI1ii = struct . pack ( "Q" , Ii1IiiiI1ii & LISP_8_64_MASK )
  elif ( self . cipher_suite == LISP_CS_25519_GCM ) :
   O0OoO0OO = struct . pack ( "I" , ( Ii1IiiiI1ii >> 64 ) & LISP_4_32_MASK )
   oooooo0 = struct . pack ( "Q" , Ii1IiiiI1ii & LISP_8_64_MASK )
   Ii1IiiiI1ii = O0OoO0OO + oooooo0
  else :
   Ii1IiiiI1ii = struct . pack ( "QQ" , Ii1IiiiI1ii >> 64 , Ii1IiiiI1ii & LISP_8_64_MASK )
  return ( Ii1IiiiI1ii )
  if 26 - 26: OOooOOo + Oo0Ooo
  if 71 - 71: I1IiiI . ooOoO0o
 def key_length ( self , key ) :
  if ( type ( key ) != str ) : key = self . normalize_pub_key ( key )
  return ( len ( key ) / 2 )
  if 43 - 43: I1ii11iIi11i * OOooOOo
  if 1 - 1: OoO0O00 * ooOoO0o + IiII . oO0o / ooOoO0o
 def print_key ( self , key ) :
  III = self . normalize_pub_key ( key )
  return ( "0x{}...{}({})" . format ( III [ 0 : 4 ] , III [ - 4 : : ] , self . key_length ( III ) ) )
  if 91 - 91: Ii1I + I11i - Oo0Ooo % OoOoOO00 . iII111i
  if 51 - 51: OOooOOo / I11i
 def normalize_pub_key ( self , key ) :
  if ( type ( key ) == str ) :
   if ( self . curve25519 ) : return ( binascii . hexlify ( key ) )
   return ( key )
   if 51 - 51: ooOoO0o * oO0o - I1Ii111 + iII111i
  key = lisp_hex_string ( key ) . zfill ( 256 )
  return ( key )
  if 46 - 46: o0oOOo0O0Ooo - i11iIiiIii % OoO0O00 / Ii1I - OoOoOO00
  if 88 - 88: oO0o * I1IiiI / OoO0O00 - OOooOOo / i1IIi . I1Ii111
 def print_keys ( self , do_bold = True ) :
  II1Ooo0000o00OO = bold ( "local-key: " , False ) if do_bold else "local-key: "
  if ( self . local_public_key == None ) :
   II1Ooo0000o00OO += "none"
  else :
   II1Ooo0000o00OO += self . print_key ( self . local_public_key )
   if 26 - 26: i11iIiiIii - ooOoO0o
  Oo0O = bold ( "remote-key: " , False ) if do_bold else "remote-key: "
  if ( self . remote_public_key == None ) :
   Oo0O += "none"
  else :
   Oo0O += self . print_key ( self . remote_public_key )
   if 45 - 45: ooOoO0o + II111iiii % iII111i
  o00OoOo0 = "ECDH" if ( self . curve25519 ) else "DH"
  Iii1I = self . cipher_suite
  return ( "{} cipher-suite: {}, {}, {}" . format ( o00OoOo0 , Iii1I , II1Ooo0000o00OO , Oo0O ) )
  if 33 - 33: OOooOOo / oO0o . i11iIiiIii * iIii1I11I1II1
  if 75 - 75: OOooOOo - OoO0O00
 def compare_keys ( self , keys ) :
  if ( self . dh_g_value != keys . dh_g_value ) : return ( False )
  if ( self . dh_p_value != keys . dh_p_value ) : return ( False )
  if ( self . remote_public_key != keys . remote_public_key ) : return ( False )
  return ( True )
  if 91 - 91: O0 . I1Ii111
  if 31 - 31: O0 - IiII * i11iIiiIii * i1IIi
 def compute_public_key ( self ) :
  if ( self . curve25519 ) : return ( self . curve25519 . get_public ( ) . public )
  if 78 - 78: ooOoO0o * OoOoOO00 . Ii1I . OoOoOO00 % iIii1I11I1II1
  Iiii11 = self . local_private_key
  o0 = self . dh_g_value
  i111 = self . dh_p_value
  return ( int ( ( o0 ** Iiii11 ) % i111 ) )
  if 63 - 63: ooOoO0o % I1IiiI . OOooOOo - ooOoO0o / Oo0Ooo % I1IiiI
  if 39 - 39: o0oOOo0O0Ooo . i1IIi % oO0o / I11i % O0
 def compute_shared_key ( self , ed , print_shared = False ) :
  Iiii11 = self . local_private_key
  o0O0OOooO = self . remote_public_key
  if 1 - 1: I1Ii111 * OoO0O00 - iII111i
  O0OoO0 = bold ( "Compute {} shared-key" . format ( ed ) , False )
  lprint ( "{}, key-material: {}" . format ( O0OoO0 , self . print_keys ( ) ) )
  if 73 - 73: i11iIiiIii - I1IiiI * I1IiiI
  if ( self . curve25519 ) :
   ooo0ooOoOOoO = curve25519 . Public ( o0O0OOooO )
   self . shared_key = self . curve25519 . get_shared_key ( ooo0ooOoOOoO )
  else :
   i111 = self . dh_p_value
   self . shared_key = ( o0O0OOooO ** Iiii11 ) % i111
   if 8 - 8: i11iIiiIii / ooOoO0o
   if 33 - 33: I1Ii111 * IiII - O0 + I1IiiI / IiII
   if 19 - 19: i1IIi % II111iiii
   if 85 - 85: IiII - o0oOOo0O0Ooo % OOooOOo - II111iiii
   if 56 - 56: Ii1I * i11iIiiIii
   if 92 - 92: II111iiii - O0 . I1Ii111
   if 59 - 59: OoOoOO00
  if ( print_shared ) :
   III = self . print_key ( self . shared_key )
   lprint ( "Computed shared-key: {}" . format ( III ) )
   if 47 - 47: II111iiii - I1ii11iIi11i - Ii1I
   if 9 - 9: I1ii11iIi11i - IiII
   if 64 - 64: i1IIi
   if 71 - 71: IiII * o0oOOo0O0Ooo
   if 99 - 99: o0oOOo0O0Ooo
  self . compute_encrypt_icv_keys ( )
  if 28 - 28: OoooooooOO % O0 - OOooOOo / o0oOOo0O0Ooo / I1IiiI
  if 41 - 41: II111iiii * IiII / OoO0O00 . oO0o
  if 50 - 50: OoooooooOO + iIii1I11I1II1 / oO0o / OOooOOo . i11iIiiIii . ooOoO0o
  if 75 - 75: iIii1I11I1II1 % ooOoO0o / OOooOOo - iII111i % i11iIiiIii
  self . rekey_count += 1
  self . last_rekey = lisp_get_timestamp ( )
  if 11 - 11: I11i . Ii1I
  if 87 - 87: OOooOOo + OOooOOo
 def compute_encrypt_icv_keys ( self ) :
  iiI11II1I = hashlib . sha256
  if ( self . curve25519 ) :
   i11 = self . shared_key
  else :
   i11 = lisp_hex_string ( self . shared_key )
   if 75 - 75: iIii1I11I1II1 / II111iiii / Ii1I / OoOoOO00
   if 77 - 77: OoOoOO00
   if 31 - 31: IiII / iII111i
   if 97 - 97: OoO0O00 + iIii1I11I1II1
   if 79 - 79: ooOoO0o + oO0o - II111iiii . Oo0Ooo
  II1Ooo0000o00OO = self . local_public_key
  if ( type ( II1Ooo0000o00OO ) != long ) : II1Ooo0000o00OO = int ( binascii . hexlify ( II1Ooo0000o00OO ) , 16 )
  Oo0O = self . remote_public_key
  if ( type ( Oo0O ) != long ) : Oo0O = int ( binascii . hexlify ( Oo0O ) , 16 )
  iIiIi1i1ii11 = "0001" + "lisp-crypto" + lisp_hex_string ( II1Ooo0000o00OO ^ Oo0O ) + "0100"
  if 86 - 86: I1Ii111 * ooOoO0o - ooOoO0o . I1IiiI
  Ooooo0o0 = hmac . new ( iIiIi1i1ii11 , i11 , iiI11II1I ) . hexdigest ( )
  Ooooo0o0 = int ( Ooooo0o0 , 16 )
  if 59 - 59: ooOoO0o % Oo0Ooo - oO0o + IiII
  if 33 - 33: Ii1I + OoOoOO00 - I1ii11iIi11i + iIii1I11I1II1 % i1IIi * IiII
  if 21 - 21: O0 * ooOoO0o % OoO0O00
  if 14 - 14: O0 / I1Ii111 / ooOoO0o + IiII - IiII
  IiiI11iIi = ( Ooooo0o0 >> 128 ) & LISP_16_128_MASK
  I1I111iIiI = Ooooo0o0 & LISP_16_128_MASK
  self . encrypt_key = lisp_hex_string ( IiiI11iIi ) . zfill ( 32 )
  I1Ii11I1i1iii = 32 if self . do_poly else 40
  self . icv_key = lisp_hex_string ( I1I111iIiI ) . zfill ( I1Ii11I1i1iii )
  if 83 - 83: O0 / OoO0O00
  if 62 - 62: I11i
 def do_icv ( self , packet , nonce ) :
  if ( self . icv_key == None ) : return ( "" )
  if ( self . do_poly ) :
   o00O00oOooo = self . icv . poly1305aes
   oooii111I1I1I = self . icv . binascii . hexlify
   nonce = oooii111I1I1I ( nonce )
   iIIiIi1IiI1 = o00O00oOooo ( self . encrypt_key , self . icv_key , nonce , packet )
   iIIiIi1IiI1 = oooii111I1I1I ( iIIiIi1IiI1 )
  else :
   Iiii11 = binascii . unhexlify ( self . icv_key )
   iIIiIi1IiI1 = hmac . new ( Iiii11 , packet , self . icv ) . hexdigest ( )
   iIIiIi1IiI1 = iIIiIi1IiI1 [ 0 : 40 ]
   if 80 - 80: II111iiii / OoOoOO00 % I1ii11iIi11i . iIii1I11I1II1 % I11i . o0oOOo0O0Ooo
  return ( iIIiIi1IiI1 )
  if 86 - 86: oO0o + iII111i % OoooooooOO . IiII
  if 80 - 80: IiII . o0oOOo0O0Ooo
 def add_key_by_nonce ( self , nonce ) :
  if ( lisp_crypto_keys_by_nonce . has_key ( nonce ) == False ) :
   lisp_crypto_keys_by_nonce [ nonce ] = [ None , None , None , None ]
   if 8 - 8: o0oOOo0O0Ooo . II111iiii . iII111i - i11iIiiIii
  lisp_crypto_keys_by_nonce [ nonce ] [ self . key_id ] = self
  if 50 - 50: Ii1I . O0 % OoO0O00 . oO0o + Ii1I . OoOoOO00
  if 69 - 69: i11iIiiIii + i11iIiiIii . i11iIiiIii - i11iIiiIii % Ii1I / iII111i
 def delete_key_by_nonce ( self , nonce ) :
  if ( lisp_crypto_keys_by_nonce . has_key ( nonce ) == False ) : return
  lisp_crypto_keys_by_nonce . pop ( nonce )
  if 59 - 59: OoooooooOO
  if 96 - 96: Ii1I
 def add_key_by_rloc ( self , addr_str , encap ) :
  o0O00o00Ooo = lisp_crypto_keys_by_rloc_encap if encap else lisp_crypto_keys_by_rloc_decap
  if 16 - 16: OOooOOo . II111iiii - Ii1I - OoooooooOO
  if 83 - 83: i11iIiiIii - Oo0Ooo
  if ( o0O00o00Ooo . has_key ( addr_str ) == False ) :
   o0O00o00Ooo [ addr_str ] = [ None , None , None , None ]
   if 5 - 5: I1ii11iIi11i . II111iiii . i1IIi
  o0O00o00Ooo [ addr_str ] [ self . key_id ] = self
  if 35 - 35: o0oOOo0O0Ooo + OoO0O00 - I1ii11iIi11i
  if 24 - 24: II111iiii
  if 23 - 23: Oo0Ooo - iII111i
  if 79 - 79: I11i . O0 - i1IIi
  if 42 - 42: oO0o - i11iIiiIii % oO0o - I1Ii111 * O0 / II111iiii
  if ( encap == False ) :
   lisp_write_ipc_decap_key ( addr_str , o0O00o00Ooo [ addr_str ] )
   if 5 - 5: Oo0Ooo
   if 84 - 84: I1ii11iIi11i
   if 53 - 53: oO0o
 def encode_lcaf ( self , rloc_addr ) :
  I1I1 = self . normalize_pub_key ( self . local_public_key )
  oOoooo0OooO = self . key_length ( I1I1 )
  OooO0O = ( 6 + oOoooo0OooO + 2 )
  if ( rloc_addr != None ) : OooO0O += rloc_addr . addr_length ( )
  if 73 - 73: I1IiiI / O0 % iII111i * II111iiii
  oOo = struct . pack ( "HBBBBHBB" , socket . htons ( LISP_AFI_LCAF ) , 0 , 0 ,
 LISP_LCAF_SECURITY_TYPE , 0 , socket . htons ( OooO0O ) , 1 , 0 )
  if 99 - 99: Ii1I + IiII % i11iIiiIii
  if 41 - 41: I1IiiI % OOooOOo
  if 30 - 30: i11iIiiIii * Oo0Ooo . II111iiii + I1ii11iIi11i / o0oOOo0O0Ooo % I1Ii111
  if 78 - 78: I1ii11iIi11i + OoooooooOO - I1IiiI * OoOoOO00 * iII111i
  if 7 - 7: OOooOOo . IiII . I1Ii111 / Ii1I / Oo0Ooo
  if 83 - 83: I11i / Oo0Ooo
  Iii1I = self . cipher_suite
  oOo += struct . pack ( "BBH" , Iii1I , 0 , socket . htons ( oOoooo0OooO ) )
  if 23 - 23: iIii1I11I1II1
  if 10 - 10: I11i - o0oOOo0O0Ooo % OoooooooOO - I1ii11iIi11i
  if 64 - 64: OoO0O00 / I1IiiI
  if 23 - 23: I11i * I1Ii111 * o0oOOo0O0Ooo - I1IiiI % OoOoOO00 + o0oOOo0O0Ooo
  for II11iIII1i1I in range ( 0 , oOoooo0OooO * 2 , 16 ) :
   Iiii11 = int ( I1I1 [ II11iIII1i1I : II11iIII1i1I + 16 ] , 16 )
   oOo += struct . pack ( "Q" , byte_swap_64 ( Iiii11 ) )
   if 41 - 41: IiII * OoooooooOO . ooOoO0o % i11iIiiIii
   if 11 - 11: iIii1I11I1II1 . I1Ii111 - Oo0Ooo / I11i + II111iiii
   if 29 - 29: I11i . i11iIiiIii + i1IIi - Ii1I + O0 . I1IiiI
   if 8 - 8: o0oOOo0O0Ooo
   if 78 - 78: i1IIi - Oo0Ooo
  if ( rloc_addr ) :
   oOo += struct . pack ( "H" , socket . htons ( rloc_addr . afi ) )
   oOo += rloc_addr . pack_address ( )
   if 48 - 48: Ii1I - OoooooooOO + I1Ii111 % o0oOOo0O0Ooo - OoOoOO00 . I1IiiI
  return ( oOo )
  if 42 - 42: I1Ii111
  if 70 - 70: o0oOOo0O0Ooo / I11i + oO0o % I1IiiI % Oo0Ooo + OoO0O00
 def decode_lcaf ( self , packet , lcaf_len ) :
  if 80 - 80: OOooOOo
  if 12 - 12: Ii1I
  if 2 - 2: OoooooooOO
  if 100 - 100: Oo0Ooo / O0 * i11iIiiIii * OoooooooOO
  if ( lcaf_len == 0 ) :
   IIiI1I11ii1i = "HHBBH"
   i1II1i1iiI1 = struct . calcsize ( IIiI1I11ii1i )
   if ( len ( packet ) < i1II1i1iiI1 ) : return ( None )
   if 46 - 46: O0 % OoooooooOO
   o0o0O00oOo , I1IiII , o0O00o0o , I1IiII , lcaf_len = struct . unpack ( IIiI1I11ii1i , packet [ : i1II1i1iiI1 ] )
   if 31 - 31: ooOoO0o % I1IiiI % IiII / I1Ii111
   if 74 - 74: i1IIi + oO0o - iIii1I11I1II1 . Oo0Ooo
   if ( o0O00o0o != LISP_LCAF_SECURITY_TYPE ) :
    packet = packet [ lcaf_len + 6 : : ]
    return ( packet )
    if 70 - 70: iII111i
   lcaf_len = socket . ntohs ( lcaf_len )
   packet = packet [ i1II1i1iiI1 : : ]
   if 51 - 51: O0 - I1ii11iIi11i / I11i * II111iiii + OoO0O00 % I1ii11iIi11i
   if 58 - 58: oO0o + IiII % iII111i - Ii1I - OOooOOo % Ii1I
   if 86 - 86: o0oOOo0O0Ooo
   if 15 - 15: oO0o - iIii1I11I1II1 - II111iiii - IiII % I1ii11iIi11i
   if 80 - 80: IiII * iII111i . i1IIi % Ii1I % I1ii11iIi11i + ooOoO0o
   if 6 - 6: I1ii11iIi11i . oO0o . OoO0O00 + IiII
  o0O00o0o = LISP_LCAF_SECURITY_TYPE
  IIiI1I11ii1i = "BBBBH"
  i1II1i1iiI1 = struct . calcsize ( IIiI1I11ii1i )
  if ( len ( packet ) < i1II1i1iiI1 ) : return ( None )
  if 65 - 65: I1ii11iIi11i / ooOoO0o
  II1I1 , I1IiII , Iii1I , I1IiII , oOoooo0OooO = struct . unpack ( IIiI1I11ii1i ,
 packet [ : i1II1i1iiI1 ] )
  if 53 - 53: i11iIiiIii - II111iiii % I1IiiI . OoO0O00
  if 67 - 67: I1ii11iIi11i * i11iIiiIii + Ii1I % Ii1I + iIii1I11I1II1 - OOooOOo
  if 10 - 10: I1IiiI - I1Ii111 - I1ii11iIi11i / iII111i
  if 10 - 10: Ii1I * I1IiiI % I1Ii111 + iII111i . Ii1I
  if 40 - 40: I1ii11iIi11i
  if 78 - 78: IiII / iII111i * Ii1I . OOooOOo . oO0o - I1Ii111
  packet = packet [ i1II1i1iiI1 : : ]
  oOoooo0OooO = socket . ntohs ( oOoooo0OooO )
  if ( len ( packet ) < oOoooo0OooO ) : return ( None )
  if 39 - 39: ooOoO0o . i1IIi + OoooooooOO . iII111i - i11iIiiIii % I1Ii111
  if 38 - 38: oO0o
  if 9 - 9: I11i . OoO0O00 . oO0o / OoooooooOO
  if 59 - 59: iIii1I11I1II1 + i1IIi % II111iiii
  iii1IiI = [ LISP_CS_25519_CBC , LISP_CS_25519_GCM , LISP_CS_25519_CHACHA ,
 LISP_CS_1024 ]
  if ( Iii1I not in iii1IiI ) :
   lprint ( "Cipher-suites {} supported, received {}" . format ( iii1IiI ,
 Iii1I ) )
   packet = packet [ oOoooo0OooO : : ]
   return ( packet )
   if 87 - 87: I1IiiI - O0 - I11i * I1Ii111 % I1Ii111
   if 99 - 99: O0 * i11iIiiIii % OOooOOo * II111iiii
  self . cipher_suite = Iii1I
  if 98 - 98: O0 + iIii1I11I1II1
  if 94 - 94: i1IIi * OoO0O00 * OoOoOO00
  if 93 - 93: ooOoO0o / OOooOOo * O0
  if 17 - 17: OoO0O00 / ooOoO0o % I1IiiI
  if 47 - 47: Oo0Ooo * OoO0O00 / o0oOOo0O0Ooo * I1IiiI
  I1I1 = 0
  for II11iIII1i1I in range ( 0 , oOoooo0OooO , 8 ) :
   Iiii11 = byte_swap_64 ( struct . unpack ( "Q" , packet [ II11iIII1i1I : II11iIII1i1I + 8 ] ) [ 0 ] )
   I1I1 <<= 64
   I1I1 |= Iiii11
   if 60 - 60: I1ii11iIi11i / IiII . i11iIiiIii / OoO0O00 % II111iiii
  self . remote_public_key = I1I1
  if 6 - 6: iII111i % o0oOOo0O0Ooo + I1Ii111
  if 91 - 91: o0oOOo0O0Ooo + O0 * oO0o * IiII * I1ii11iIi11i
  if 83 - 83: OoooooooOO
  if 52 - 52: o0oOOo0O0Ooo / OoOoOO00 % oO0o % OoO0O00 / IiII % o0oOOo0O0Ooo
  if 88 - 88: OOooOOo / i11iIiiIii / Ii1I / i11iIiiIii * I1ii11iIi11i % I11i
  if ( self . curve25519 ) :
   Iiii11 = lisp_hex_string ( self . remote_public_key )
   Iiii11 = Iiii11 . zfill ( 64 )
   II1I1iI1i1IiI = ""
   for II11iIII1i1I in range ( 0 , len ( Iiii11 ) , 2 ) :
    II1I1iI1i1IiI += chr ( int ( Iiii11 [ II11iIII1i1I : II11iIII1i1I + 2 ] , 16 ) )
    if 9 - 9: oO0o / OoooooooOO / OOooOOo * i11iIiiIii - ooOoO0o + I1Ii111
   self . remote_public_key = II1I1iI1i1IiI
   if 69 - 69: O0 . I1Ii111 - O0
   if 58 - 58: OoOoOO00 + I1ii11iIi11i
  packet = packet [ oOoooo0OooO : : ]
  return ( packet )
  if 4 - 4: II111iiii % oO0o + o0oOOo0O0Ooo / i11iIiiIii
  if 16 - 16: I1IiiI . oO0o . OOooOOo % ooOoO0o - OOooOOo - o0oOOo0O0Ooo
  if 30 - 30: IiII
  if 34 - 34: oO0o - II111iiii - o0oOOo0O0Ooo + iII111i + I1Ii111
  if 70 - 70: OoooooooOO + OoO0O00 * Oo0Ooo
  if 20 - 20: i11iIiiIii - II111iiii - ooOoO0o % oO0o . ooOoO0o
  if 50 - 50: iIii1I11I1II1 + I1Ii111 - I11i - OoooooooOO
  if 84 - 84: OoOoOO00 - I11i
class lisp_thread ( ) :
 def __init__ ( self , name ) :
  self . thread_name = name
  self . thread_number = - 1
  self . number_of_pcap_threads = 0
  self . number_of_worker_threads = 0
  self . input_queue = Queue . Queue ( )
  self . input_stats = lisp_stats ( )
  self . lisp_packet = lisp_packet ( None )
  if 80 - 80: i11iIiiIii % OOooOOo - Oo0Ooo % OOooOOo
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
  if 85 - 85: I1IiiI * iIii1I11I1II1 . iII111i / iII111i
  if 43 - 43: I1IiiI
 def decode ( self , packet ) :
  IIiI1I11ii1i = "BBBBQ"
  i1II1i1iiI1 = struct . calcsize ( IIiI1I11ii1i )
  if ( len ( packet ) < i1II1i1iiI1 ) : return ( False )
  if 78 - 78: OoO0O00 % II111iiii + OoOoOO00 / I1IiiI
  IIII11i1Ii , I11Iii11i1Ii , oo00000ooOooO , self . record_count , self . nonce = struct . unpack ( IIiI1I11ii1i , packet [ : i1II1i1iiI1 ] )
  if 56 - 56: I1IiiI . IiII
  if 53 - 53: ooOoO0o - OoOoOO00 + IiII
  self . type = IIII11i1Ii >> 4
  if ( self . type == LISP_MAP_REQUEST ) :
   self . smr_bit = True if ( IIII11i1Ii & 0x01 ) else False
   self . rloc_probe = True if ( IIII11i1Ii & 0x02 ) else False
   self . smr_invoked_bit = True if ( I11Iii11i1Ii & 0x40 ) else False
   if 100 - 100: oO0o + OoO0O00
  if ( self . type == LISP_ECM ) :
   self . ddt_bit = True if ( IIII11i1Ii & 0x04 ) else False
   self . to_etr = True if ( IIII11i1Ii & 0x02 ) else False
   self . to_ms = True if ( IIII11i1Ii & 0x01 ) else False
   if 95 - 95: i11iIiiIii . o0oOOo0O0Ooo + OoooooooOO % Oo0Ooo
  if ( self . type == LISP_NAT_INFO ) :
   self . info_reply = True if ( IIII11i1Ii & 0x08 ) else False
   if 21 - 21: iII111i - o0oOOo0O0Ooo / I11i % O0 / iIii1I11I1II1 / iII111i
  return ( True )
  if 1 - 1: Oo0Ooo . i11iIiiIii
  if 9 - 9: OoooooooOO / I11i
 def is_info_request ( self ) :
  return ( ( self . type == LISP_NAT_INFO and self . is_info_reply ( ) == False ) )
  if 47 - 47: OoooooooOO
  if 48 - 48: OoOoOO00 . IiII % I1IiiI + I11i
 def is_info_reply ( self ) :
  return ( True if self . info_reply else False )
  if 37 - 37: Oo0Ooo + I1Ii111 * oO0o / o0oOOo0O0Ooo
  if 78 - 78: IiII + I11i - o0oOOo0O0Ooo + OoO0O00 / iIii1I11I1II1
 def is_rloc_probe ( self ) :
  return ( True if self . rloc_probe else False )
  if 47 - 47: OOooOOo
  if 20 - 20: I1Ii111 % ooOoO0o - I1Ii111 * OoooooooOO / I1ii11iIi11i
 def is_smr ( self ) :
  return ( True if self . smr_bit else False )
  if 57 - 57: IiII % I11i * OOooOOo % I1ii11iIi11i
  if 65 - 65: i1IIi - OoooooooOO
 def is_smr_invoked ( self ) :
  return ( True if self . smr_invoked_bit else False )
  if 66 - 66: I1ii11iIi11i / i1IIi * I1IiiI - OoOoOO00 + oO0o
  if 74 - 74: iII111i / I1Ii111 / II111iiii - iII111i / oO0o % I11i
 def is_ddt ( self ) :
  return ( True if self . ddt_bit else False )
  if 19 - 19: IiII % OoooooooOO + OoooooooOO
  if 7 - 7: i1IIi
 def is_to_etr ( self ) :
  return ( True if self . to_etr else False )
  if 91 - 91: OoOoOO00 - OoOoOO00 . IiII
  if 33 - 33: I1Ii111 - iIii1I11I1II1 / Ii1I % O0
 def is_to_ms ( self ) :
  return ( True if self . to_ms else False )
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
  if 58 - 58: Ii1I * iIii1I11I1II1 + ooOoO0o . ooOoO0o
  if 74 - 74: ooOoO0o - o0oOOo0O0Ooo * IiII % ooOoO0o
 def print_map_register ( self ) :
  Oo0O0 = lisp_hex_string ( self . xtr_id )
  if 36 - 36: I1ii11iIi11i * o0oOOo0O0Ooo + i11iIiiIii + OoooooooOO
  IIIIIiI11Ii = ( "{} -> flags: {}{}{}{}{}{}{}{}{}, record-count: " +
 "{}, nonce: 0x{}, key/alg-id: {}/{}{}, auth-len: {}, xtr-id: " +
 "0x{}, site-id: {}" )
  if 82 - 82: OoOoOO00 . OoOoOO00
  lprint ( IIIIIiI11Ii . format ( bold ( "Map-Register" , False ) , "P" if self . proxy_reply_requested else "p" ,
  # iII111i
 "S" if self . lisp_sec_present else "s" ,
 "I" if self . xtr_id_present else "i" ,
 "T" if self . use_ttl_for_timeout else "t" ,
 "R" if self . merge_register_requested else "r" ,
 "M" if self . mobile_node else "m" ,
 "N" if self . map_notify_requested else "n" ,
 "F" if self . map_register_refresh else "f" ,
 "E" if self . encrypt_bit else "e" ,
 self . record_count , lisp_hex_string ( self . nonce ) , self . key_id ,
 self . alg_id , " (sha1)" if ( self . key_id == LISP_SHA_1_96_ALG_ID ) else ( " (sha2)" if ( self . key_id == LISP_SHA_256_128_ALG_ID ) else "" ) , self . auth_len , Oo0O0 , self . site_id ) )
  if 85 - 85: I1ii11iIi11i . oO0o . O0
  if 16 - 16: I1ii11iIi11i % I1ii11iIi11i % I1Ii111 + I11i . I1Ii111 + OOooOOo
  if 85 - 85: i11iIiiIii . I11i + Ii1I / Ii1I
  if 43 - 43: IiII . OoooooooOO - II111iiii
 def encode ( self ) :
  O0oooOO = ( LISP_MAP_REGISTER << 28 ) | self . record_count
  if ( self . proxy_reply_requested ) : O0oooOO |= 0x08000000
  if ( self . lisp_sec_present ) : O0oooOO |= 0x04000000
  if ( self . xtr_id_present ) : O0oooOO |= 0x02000000
  if ( self . map_register_refresh ) : O0oooOO |= 0x1000
  if ( self . use_ttl_for_timeout ) : O0oooOO |= 0x800
  if ( self . merge_register_requested ) : O0oooOO |= 0x400
  if ( self . mobile_node ) : O0oooOO |= 0x200
  if ( self . map_notify_requested ) : O0oooOO |= 0x100
  if ( self . encryption_key_id != None ) :
   O0oooOO |= 0x2000
   O0oooOO |= self . encryption_key_id << 14
   if 90 - 90: I1IiiI - iIii1I11I1II1 + I1ii11iIi11i * OOooOOo * oO0o
   if 19 - 19: I1Ii111 * II111iiii % Oo0Ooo - i1IIi
   if 27 - 27: OoOoOO00 . O0 / I1ii11iIi11i . iIii1I11I1II1
   if 15 - 15: Ii1I + OoO0O00 % iIii1I11I1II1 - I1ii11iIi11i - i1IIi % o0oOOo0O0Ooo
   if 54 - 54: IiII - II111iiii . ooOoO0o + Ii1I
  if ( self . alg_id == LISP_NONE_ALG_ID ) :
   self . auth_len = 0
  else :
   if ( self . alg_id == LISP_SHA_1_96_ALG_ID ) :
    self . auth_len = LISP_SHA1_160_AUTH_DATA_LEN
    if 45 - 45: oO0o + II111iiii . iII111i / I1ii11iIi11i
   if ( self . alg_id == LISP_SHA_256_128_ALG_ID ) :
    self . auth_len = LISP_SHA2_256_AUTH_DATA_LEN
    if 76 - 76: Ii1I + iII111i - IiII * iIii1I11I1II1 % i1IIi
    if 72 - 72: ooOoO0o + II111iiii . O0 - iII111i / OoooooooOO . I1Ii111
    if 28 - 28: iIii1I11I1II1 . O0
  oOo = struct . pack ( "I" , socket . htonl ( O0oooOO ) )
  oOo += struct . pack ( "QBBH" , self . nonce , self . key_id , self . alg_id ,
 socket . htons ( self . auth_len ) )
  if 32 - 32: OoooooooOO
  oOo = self . zero_auth ( oOo )
  return ( oOo )
  if 29 - 29: I1ii11iIi11i
  if 41 - 41: Ii1I
 def zero_auth ( self , packet ) :
  ii = struct . calcsize ( "I" ) + struct . calcsize ( "QHH" )
  I1iiI1II11 = ""
  ooooO000 = 0
  if ( self . alg_id == LISP_NONE_ALG_ID ) : return ( packet )
  if ( self . alg_id == LISP_SHA_1_96_ALG_ID ) :
   I1iiI1II11 = struct . pack ( "QQI" , 0 , 0 , 0 )
   ooooO000 = struct . calcsize ( "QQI" )
   if 63 - 63: I1Ii111 - oO0o - iII111i - ooOoO0o / oO0o + OoO0O00
  if ( self . alg_id == LISP_SHA_256_128_ALG_ID ) :
   I1iiI1II11 = struct . pack ( "QQQQ" , 0 , 0 , 0 , 0 )
   ooooO000 = struct . calcsize ( "QQQQ" )
   if 94 - 94: IiII / I1IiiI . II111iiii
  packet = packet [ 0 : ii ] + I1iiI1II11 + packet [ ii + ooooO000 : : ]
  return ( packet )
  if 32 - 32: oO0o . OOooOOo % OOooOOo . OoOoOO00
  if 37 - 37: OOooOOo + O0 + OOooOOo . iII111i . o0oOOo0O0Ooo
 def encode_auth ( self , packet ) :
  ii = struct . calcsize ( "I" ) + struct . calcsize ( "QHH" )
  ooooO000 = self . auth_len
  I1iiI1II11 = self . auth_data
  packet = packet [ 0 : ii ] + I1iiI1II11 + packet [ ii + ooooO000 : : ]
  return ( packet )
  if 78 - 78: I1IiiI / I11i + o0oOOo0O0Ooo . Oo0Ooo / O0
  if 49 - 49: I1ii11iIi11i
 def decode ( self , packet ) :
  oOO = packet
  IIiI1I11ii1i = "I"
  i1II1i1iiI1 = struct . calcsize ( IIiI1I11ii1i )
  if ( len ( packet ) < i1II1i1iiI1 ) : return ( [ None , None ] )
  if 18 - 18: Oo0Ooo + IiII
  O0oooOO = struct . unpack ( IIiI1I11ii1i , packet [ : i1II1i1iiI1 ] )
  O0oooOO = socket . ntohl ( O0oooOO [ 0 ] )
  packet = packet [ i1II1i1iiI1 : : ]
  if 79 - 79: OoO0O00 - O0 + II111iiii % Ii1I . I1IiiI
  IIiI1I11ii1i = "QBBH"
  i1II1i1iiI1 = struct . calcsize ( IIiI1I11ii1i )
  if ( len ( packet ) < i1II1i1iiI1 ) : return ( [ None , None ] )
  if 43 - 43: I1IiiI % I1ii11iIi11i * Ii1I
  self . nonce , self . key_id , self . alg_id , self . auth_len = struct . unpack ( IIiI1I11ii1i , packet [ : i1II1i1iiI1 ] )
  if 31 - 31: Ii1I / iII111i
  if 3 - 3: IiII
  self . auth_len = socket . ntohs ( self . auth_len )
  self . proxy_reply_requested = True if ( O0oooOO & 0x08000000 ) else False
  if 37 - 37: Ii1I * OoooooooOO * I11i + Oo0Ooo . I1IiiI
  self . lisp_sec_present = True if ( O0oooOO & 0x04000000 ) else False
  self . xtr_id_present = True if ( O0oooOO & 0x02000000 ) else False
  self . use_ttl_for_timeout = True if ( O0oooOO & 0x800 ) else False
  self . map_register_refresh = True if ( O0oooOO & 0x1000 ) else False
  self . merge_register_requested = True if ( O0oooOO & 0x400 ) else False
  self . mobile_node = True if ( O0oooOO & 0x200 ) else False
  self . map_notify_requested = True if ( O0oooOO & 0x100 ) else False
  self . record_count = O0oooOO & 0xff
  if 61 - 61: OOooOOo . OOooOOo
  if 17 - 17: II111iiii / ooOoO0o
  if 80 - 80: OOooOOo * OoO0O00 + Ii1I
  if 62 - 62: OoooooooOO . O0 % Oo0Ooo
  self . encrypt_bit = True if O0oooOO & 0x2000 else False
  if ( self . encrypt_bit ) :
   self . encryption_key_id = ( O0oooOO >> 14 ) & 0x7
   if 98 - 98: o0oOOo0O0Ooo * Oo0Ooo - Ii1I . ooOoO0o
   if 2 - 2: Oo0Ooo - ooOoO0o % iIii1I11I1II1
   if 88 - 88: I1Ii111 - OoO0O00
   if 79 - 79: iII111i
   if 45 - 45: II111iiii + iII111i . I11i . O0 * i1IIi - Ii1I
  if ( self . xtr_id_present ) :
   if ( self . decode_xtr_id ( oOO ) == False ) : return ( [ None , None ] )
   if 48 - 48: I1ii11iIi11i + Oo0Ooo
   if 76 - 76: I1ii11iIi11i
  packet = packet [ i1II1i1iiI1 : : ]
  if 98 - 98: II111iiii + I1IiiI - I1ii11iIi11i . Ii1I
  if 51 - 51: Ii1I + i11iIiiIii * OoO0O00 % Oo0Ooo / I1IiiI - iIii1I11I1II1
  if 20 - 20: I1Ii111 . I11i . Ii1I + I11i - OOooOOo * oO0o
  if 82 - 82: OoO0O00
  if ( self . auth_len != 0 ) :
   if ( len ( packet ) < self . auth_len ) : return ( [ None , None ] )
   if 78 - 78: II111iiii / I11i - i11iIiiIii + I1ii11iIi11i * Oo0Ooo
   if ( self . alg_id not in ( LISP_NONE_ALG_ID , LISP_SHA_1_96_ALG_ID ,
 LISP_SHA_256_128_ALG_ID ) ) :
    lprint ( "Invalid authentication alg-id: {}" . format ( self . alg_id ) )
    return ( [ None , None ] )
    if 17 - 17: OoOoOO00
    if 72 - 72: iII111i . Oo0Ooo - i11iIiiIii / I1IiiI
   ooooO000 = self . auth_len
   if ( self . alg_id == LISP_SHA_1_96_ALG_ID ) :
    i1II1i1iiI1 = struct . calcsize ( "QQI" )
    if ( ooooO000 < i1II1i1iiI1 ) :
     lprint ( "Invalid sha1-96 authentication length" )
     return ( [ None , None ] )
     if 64 - 64: oO0o
    oOoOo00o00 , O0OOo00O , i1iI1iIIiIi1I = struct . unpack ( "QQI" , packet [ : ooooO000 ] )
    I11iIiIII11 = ""
   elif ( self . alg_id == LISP_SHA_256_128_ALG_ID ) :
    i1II1i1iiI1 = struct . calcsize ( "QQQQ" )
    if ( ooooO000 < i1II1i1iiI1 ) :
     lprint ( "Invalid sha2-256 authentication length" )
     return ( [ None , None ] )
     if 81 - 81: I1ii11iIi11i + OoooooooOO - OOooOOo * O0
    oOoOo00o00 , O0OOo00O , i1iI1iIIiIi1I , I11iIiIII11 = struct . unpack ( "QQQQ" ,
 packet [ : ooooO000 ] )
   else :
    lprint ( "Unsupported authentication alg-id value {}" . format ( self . alg_id ) )
    if 100 - 100: iIii1I11I1II1 - OoOoOO00
    return ( [ None , None ] )
    if 28 - 28: Oo0Ooo . O0 . I11i
   self . auth_data = lisp_concat_auth_data ( self . alg_id , oOoOo00o00 , O0OOo00O ,
 i1iI1iIIiIi1I , I11iIiIII11 )
   oOO = self . zero_auth ( oOO )
   packet = packet [ self . auth_len : : ]
   if 60 - 60: II111iiii + I1Ii111 / oO0o % OoooooooOO - i1IIi
  return ( [ oOO , packet ] )
  if 57 - 57: ooOoO0o
  if 99 - 99: Oo0Ooo + I1Ii111 % ooOoO0o - o0oOOo0O0Ooo
 def encode_xtr_id ( self , packet ) :
  o0oo0oo0 = self . xtr_id >> 64
  IIi1II = self . xtr_id & 0xffffffffffffffff
  o0oo0oo0 = byte_swap_64 ( o0oo0oo0 )
  IIi1II = byte_swap_64 ( IIi1II )
  OOOoooO0o0o = byte_swap_64 ( self . site_id )
  packet += struct . pack ( "QQQ" , o0oo0oo0 , IIi1II , OOOoooO0o0o )
  return ( packet )
  if 56 - 56: oO0o - o0oOOo0O0Ooo . OoOoOO00 . Ii1I + oO0o * OoooooooOO
  if 31 - 31: iII111i - i11iIiiIii % Ii1I / iII111i . OoooooooOO + Oo0Ooo
 def decode_xtr_id ( self , packet ) :
  i1II1i1iiI1 = struct . calcsize ( "QQQ" )
  if ( len ( packet ) < i1II1i1iiI1 ) : return ( [ None , None ] )
  packet = packet [ len ( packet ) - i1II1i1iiI1 : : ]
  o0oo0oo0 , IIi1II , OOOoooO0o0o = struct . unpack ( "QQQ" ,
 packet [ : i1II1i1iiI1 ] )
  o0oo0oo0 = byte_swap_64 ( o0oo0oo0 )
  IIi1II = byte_swap_64 ( IIi1II )
  self . xtr_id = ( o0oo0oo0 << 64 ) | IIi1II
  self . site_id = byte_swap_64 ( OOOoooO0o0o )
  return ( True )
  if 82 - 82: I1ii11iIi11i * O0 + OOooOOo . ooOoO0o + OoO0O00 % O0
  if 2 - 2: II111iiii * O0 . ooOoO0o * i1IIi
  if 29 - 29: iIii1I11I1II1 - I1Ii111 - Ii1I - o0oOOo0O0Ooo + i11iIiiIii
  if 78 - 78: o0oOOo0O0Ooo + iIii1I11I1II1 / I1ii11iIi11i - OoooooooOO - oO0o
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
  if 28 - 28: Oo0Ooo
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
  if 62 - 62: Oo0Ooo + OoooooooOO / iII111i
  if 60 - 60: Ii1I / OoOoOO00 . I11i % OOooOOo
 def print_notify ( self ) :
  I1iiI1II11 = binascii . hexlify ( self . auth_data )
  if ( self . alg_id == LISP_SHA_1_96_ALG_ID and len ( I1iiI1II11 ) != 40 ) :
   I1iiI1II11 = self . auth_data
  elif ( self . alg_id == LISP_SHA_256_128_ALG_ID and len ( I1iiI1II11 ) != 64 ) :
   I1iiI1II11 = self . auth_data
   if 61 - 61: O0 . Ii1I . O0 * i11iIiiIii * II111iiii / I1Ii111
  IIIIIiI11Ii = ( "{} -> record-count: {}, nonce: 0x{}, key/alg-id: " +
 "{}{}{}, auth-len: {}, auth-data: {}" )
  lprint ( IIIIIiI11Ii . format ( bold ( "Map-Notify-Ack" , False ) if self . map_notify_ack else bold ( "Map-Notify" , False ) ,
  # I11i . i11iIiiIii / Oo0Ooo % iII111i / I1Ii111
 self . record_count , lisp_hex_string ( self . nonce ) , self . key_id ,
 self . alg_id , " (sha1)" if ( self . key_id == LISP_SHA_1_96_ALG_ID ) else ( " (sha2)" if ( self . key_id == LISP_SHA_256_128_ALG_ID ) else "" ) , self . auth_len , I1iiI1II11 ) )
  if 70 - 70: OoooooooOO
  if 1 - 1: iIii1I11I1II1
  if 44 - 44: I1ii11iIi11i % IiII
  if 6 - 6: OoO0O00
 def zero_auth ( self , packet ) :
  if ( self . alg_id == LISP_NONE_ALG_ID ) : return ( packet )
  if ( self . alg_id == LISP_SHA_1_96_ALG_ID ) :
   I1iiI1II11 = struct . pack ( "QQI" , 0 , 0 , 0 )
   if 82 - 82: iIii1I11I1II1 . I11i / IiII / OOooOOo * II111iiii % oO0o
  if ( self . alg_id == LISP_SHA_256_128_ALG_ID ) :
   I1iiI1II11 = struct . pack ( "QQQQ" , 0 , 0 , 0 , 0 )
   if 62 - 62: II111iiii
  packet += I1iiI1II11
  return ( packet )
  if 96 - 96: I11i % OoOoOO00 * I1ii11iIi11i
  if 94 - 94: Oo0Ooo - i1IIi . O0 % Oo0Ooo . ooOoO0o
 def encode ( self , eid_records , password ) :
  if ( self . map_notify_ack ) :
   O0oooOO = ( LISP_MAP_NOTIFY_ACK << 28 ) | self . record_count
  else :
   O0oooOO = ( LISP_MAP_NOTIFY << 28 ) | self . record_count
   if 63 - 63: i11iIiiIii % I1ii11iIi11i % I1IiiI . IiII * o0oOOo0O0Ooo + OOooOOo
  oOo = struct . pack ( "I" , socket . htonl ( O0oooOO ) )
  oOo += struct . pack ( "QBBH" , self . nonce , self . key_id , self . alg_id ,
 socket . htons ( self . auth_len ) )
  if 77 - 77: o0oOOo0O0Ooo
  if ( self . alg_id == LISP_NONE_ALG_ID ) :
   self . packet = oOo + eid_records
   return ( self . packet )
   if 63 - 63: ooOoO0o * oO0o + ooOoO0o * Ii1I + Oo0Ooo / I1ii11iIi11i
   if 15 - 15: O0 . I1ii11iIi11i * I1ii11iIi11i
   if 65 - 65: I1Ii111 + O0 % o0oOOo0O0Ooo
   if 72 - 72: OOooOOo . OoOoOO00 / II111iiii
   if 69 - 69: OOooOOo * II111iiii - ooOoO0o - i1IIi + i11iIiiIii
  oOo = self . zero_auth ( oOo )
  oOo += eid_records
  if 50 - 50: OoooooooOO * i1IIi / oO0o
  ooo000 = lisp_hash_me ( oOo , self . alg_id , password , False )
  if 83 - 83: i1IIi
  ii = struct . calcsize ( "I" ) + struct . calcsize ( "QHH" )
  ooooO000 = self . auth_len
  self . auth_data = ooo000
  oOo = oOo [ 0 : ii ] + ooo000 + oOo [ ii + ooooO000 : : ]
  self . packet = oOo
  return ( oOo )
  if 38 - 38: OoooooooOO * iIii1I11I1II1
  if 54 - 54: OoooooooOO . I1Ii111
 def decode ( self , packet ) :
  oOO = packet
  IIiI1I11ii1i = "I"
  i1II1i1iiI1 = struct . calcsize ( IIiI1I11ii1i )
  if ( len ( packet ) < i1II1i1iiI1 ) : return ( None )
  if 71 - 71: Ii1I
  O0oooOO = struct . unpack ( IIiI1I11ii1i , packet [ : i1II1i1iiI1 ] )
  O0oooOO = socket . ntohl ( O0oooOO [ 0 ] )
  self . map_notify_ack = ( ( O0oooOO >> 28 ) == LISP_MAP_NOTIFY_ACK )
  self . record_count = O0oooOO & 0xff
  packet = packet [ i1II1i1iiI1 : : ]
  if 31 - 31: I11i . i11iIiiIii . OoO0O00 * Oo0Ooo % Ii1I . o0oOOo0O0Ooo
  IIiI1I11ii1i = "QBBH"
  i1II1i1iiI1 = struct . calcsize ( IIiI1I11ii1i )
  if ( len ( packet ) < i1II1i1iiI1 ) : return ( None )
  if 92 - 92: OoooooooOO / O0 * i1IIi + iIii1I11I1II1
  self . nonce , self . key_id , self . alg_id , self . auth_len = struct . unpack ( IIiI1I11ii1i , packet [ : i1II1i1iiI1 ] )
  if 93 - 93: ooOoO0o % I1Ii111
  self . nonce_key = lisp_hex_string ( self . nonce )
  self . auth_len = socket . ntohs ( self . auth_len )
  packet = packet [ i1II1i1iiI1 : : ]
  self . eid_records = packet [ self . auth_len : : ]
  if 46 - 46: I1ii11iIi11i * OoOoOO00 * IiII * I1ii11iIi11i . I1ii11iIi11i
  if ( self . auth_len == 0 ) : return ( self . eid_records )
  if 43 - 43: ooOoO0o . i1IIi
  if 68 - 68: IiII % Oo0Ooo . O0 - OoOoOO00 + I1ii11iIi11i . i11iIiiIii
  if 45 - 45: I1IiiI
  if 17 - 17: OoooooooOO - ooOoO0o + Ii1I . OoooooooOO % Oo0Ooo
  if ( len ( packet ) < self . auth_len ) : return ( None )
  if 92 - 92: I1Ii111 - OOooOOo % OoO0O00 - o0oOOo0O0Ooo % i1IIi
  ooooO000 = self . auth_len
  if ( self . alg_id == LISP_SHA_1_96_ALG_ID ) :
   oOoOo00o00 , O0OOo00O , i1iI1iIIiIi1I = struct . unpack ( "QQI" , packet [ : ooooO000 ] )
   I11iIiIII11 = ""
   if 38 - 38: I1ii11iIi11i . I11i / OoOoOO00 % I11i
  if ( self . alg_id == LISP_SHA_256_128_ALG_ID ) :
   oOoOo00o00 , O0OOo00O , i1iI1iIIiIi1I , I11iIiIII11 = struct . unpack ( "QQQQ" ,
 packet [ : ooooO000 ] )
   if 10 - 10: O0 . I1IiiI * o0oOOo0O0Ooo / iII111i
  self . auth_data = lisp_concat_auth_data ( self . alg_id , oOoOo00o00 , O0OOo00O ,
 i1iI1iIIiIi1I , I11iIiIII11 )
  if 61 - 61: Oo0Ooo - I1Ii111
  i1II1i1iiI1 = struct . calcsize ( "I" ) + struct . calcsize ( "QHH" )
  packet = self . zero_auth ( oOO [ : i1II1i1iiI1 ] )
  i1II1i1iiI1 += ooooO000
  packet += oOO [ i1II1i1iiI1 : : ]
  return ( packet )
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
  if 37 - 37: IiII % Ii1I % i1IIi
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
  if 23 - 23: ooOoO0o - O0 + i11iIiiIii
  if 98 - 98: OoooooooOO
 def print_prefix ( self ) :
  if ( self . target_group . is_null ( ) ) :
   return ( green ( self . target_eid . print_prefix ( ) , False ) )
   if 61 - 61: o0oOOo0O0Ooo . IiII . O0 + OoooooooOO + O0
  return ( green ( self . target_eid . print_sg ( self . target_group ) , False ) )
  if 65 - 65: i1IIi * OOooOOo * OoooooooOO - IiII . iII111i - OoO0O00
  if 71 - 71: Ii1I * OoOoOO00
 def print_map_request ( self ) :
  Oo0O0 = ""
  if ( self . xtr_id != None and self . subscribe_bit ) :
   Oo0O0 = "subscribe, xtr-id: 0x{}, " . format ( lisp_hex_string ( self . xtr_id ) )
   if 33 - 33: i1IIi . i1IIi * OoooooooOO % I1Ii111 * o0oOOo0O0Ooo
   if 64 - 64: ooOoO0o / ooOoO0o + I1ii11iIi11i * OOooOOo % OOooOOo
   if 87 - 87: OoO0O00 * Oo0Ooo
  IIIIIiI11Ii = ( "{} -> flags: {}{}{}{}{}{}{}{}{}{}, itr-rloc-" +
 "count: {} (+1), record-count: {}, nonce: 0x{}, source-eid: " +
 "afi {}, {}{}, target-eid: afi {}, {}, {}ITR-RLOCs:" )
  if 83 - 83: i1IIi * I1Ii111 - IiII / Ii1I
  lprint ( IIIIIiI11Ii . format ( bold ( "Map-Request" , False ) , "A" if self . auth_bit else "a" ,
  # O0 % o0oOOo0O0Ooo - II111iiii
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
 self . target_eid . afi , green ( self . print_prefix ( ) , False ) , Oo0O0 ) )
  if 69 - 69: i1IIi . I1IiiI + IiII
  i1iIi = self . keys
  for OooOoOOo0 in self . itr_rlocs :
   lprint ( "  itr-rloc: afi {} {}{}" . format ( OooOoOOo0 . afi ,
 red ( OooOoOOo0 . print_address_no_iid ( ) , False ) ,
 "" if ( i1iIi == None ) else ", " + i1iIi [ 1 ] . print_keys ( ) ) )
   i1iIi = None
   if 67 - 67: OoOoOO00 % Oo0Ooo
   if 7 - 7: i11iIiiIii % I1ii11iIi11i / I1Ii111 % Oo0Ooo - OoO0O00
   if 73 - 73: I1ii11iIi11i
 def sign_map_request ( self , privkey ) :
  oo0o0Oo = self . signature_eid . print_address ( )
  IiIiii = self . source_eid . print_address ( )
  iIooo0O0O0OO = self . target_eid . print_address ( )
  oOooOOoO = lisp_hex_string ( self . nonce ) + IiIiii + iIooo0O0O0OO
  self . map_request_signature = privkey . sign ( oOooOOoO )
  o0o000OOO = binascii . b2a_base64 ( self . map_request_signature )
  o0o000OOO = { "source-eid" : IiIiii , "signature-eid" : oo0o0Oo ,
 "signature" : o0o000OOO }
  return ( json . dumps ( o0o000OOO ) )
  if 36 - 36: I1Ii111 * I1Ii111 % I1IiiI % O0 . I1IiiI % OoooooooOO
  if 96 - 96: oO0o % iIii1I11I1II1 / iIii1I11I1II1 . iII111i . Ii1I
 def verify_map_request_sig ( self , pubkey ) :
  iII1I1iIIIiII = green ( self . signature_eid . print_address ( ) , False )
  if ( pubkey == None ) :
   lprint ( "Public-key not found for signature-EID {}" . format ( iII1I1iIIIiII ) )
   return ( False )
   if 41 - 41: I1Ii111 - O0 * Oo0Ooo % I1IiiI
   if 70 - 70: IiII
  IiIiii = self . source_eid . print_address ( )
  iIooo0O0O0OO = self . target_eid . print_address ( )
  oOooOOoO = lisp_hex_string ( self . nonce ) + IiIiii + iIooo0O0O0OO
  pubkey = binascii . a2b_base64 ( pubkey )
  if 4 - 4: OOooOOo + i11iIiiIii + I11i
  O0OoOOo0o = True
  try :
   Iiii11 = ecdsa . VerifyingKey . from_pem ( pubkey )
  except :
   lprint ( "Invalid public-key in mapping system for sig-eid {}" . format ( self . signature_eid . print_address_no_iid ( ) ) )
   if 21 - 21: I11i - I1IiiI / OoooooooOO . i1IIi + II111iiii
   O0OoOOo0o = False
   if 99 - 99: I1Ii111 - I1ii11iIi11i - I1IiiI - I1Ii111 + OoO0O00 + II111iiii
   if 34 - 34: I1Ii111 * I11i
  if ( O0OoOOo0o ) :
   try :
    O0OoOOo0o = Iiii11 . verify ( self . map_request_signature , oOooOOoO )
   except :
    O0OoOOo0o = False
    if 31 - 31: IiII . oO0o
    if 40 - 40: Ii1I - I11i / II111iiii * i1IIi + IiII * II111iiii
    if 53 - 53: I1ii11iIi11i - i11iIiiIii . OoO0O00 / OoOoOO00 - I1Ii111
  O0O0oooo = bold ( "passed" if O0OoOOo0o else "failed" , False )
  lprint ( "Signature verification {} for EID {}" . format ( O0O0oooo , iII1I1iIIIiII ) )
  return ( O0OoOOo0o )
  if 90 - 90: OOooOOo . OoOoOO00 . I1IiiI . IiII
  if 52 - 52: Ii1I - Oo0Ooo
 def encode ( self , probe_dest , probe_port ) :
  O0oooOO = ( LISP_MAP_REQUEST << 28 ) | self . record_count
  O0oooOO = O0oooOO | ( self . itr_rloc_count << 8 )
  if ( self . auth_bit ) : O0oooOO |= 0x08000000
  if ( self . map_data_present ) : O0oooOO |= 0x04000000
  if ( self . rloc_probe ) : O0oooOO |= 0x02000000
  if ( self . smr_bit ) : O0oooOO |= 0x01000000
  if ( self . pitr_bit ) : O0oooOO |= 0x00800000
  if ( self . smr_invoked_bit ) : O0oooOO |= 0x00400000
  if ( self . mobile_node ) : O0oooOO |= 0x00200000
  if ( self . xtr_id_present ) : O0oooOO |= 0x00100000
  if ( self . local_xtr ) : O0oooOO |= 0x00004000
  if ( self . dont_reply_bit ) : O0oooOO |= 0x00002000
  if 48 - 48: iIii1I11I1II1 * i11iIiiIii / OoO0O00 / I1IiiI
  oOo = struct . pack ( "I" , socket . htonl ( O0oooOO ) )
  oOo += struct . pack ( "Q" , self . nonce )
  if 93 - 93: oO0o
  if 57 - 57: I11i . iIii1I11I1II1 + I11i . IiII + IiII
  if 53 - 53: I1ii11iIi11i / iII111i - I1ii11iIi11i * OoO0O00
  if 81 - 81: I1Ii111 - Oo0Ooo / II111iiii / Oo0Ooo / i1IIi . o0oOOo0O0Ooo
  if 38 - 38: OoooooooOO / OoooooooOO % iIii1I11I1II1 % OoooooooOO * OoooooooOO + OoO0O00
  if 66 - 66: i1IIi
  I11I11i1 = False
  O0Oo00o0oO = self . privkey_filename
  if ( O0Oo00o0oO != None and os . path . exists ( O0Oo00o0oO ) ) :
   Iiooo000o0OoOo = open ( O0Oo00o0oO , "r" ) ; Iiii11 = Iiooo000o0OoOo . read ( ) ; Iiooo000o0OoOo . close ( )
   try :
    Iiii11 = ecdsa . SigningKey . from_pem ( Iiii11 )
   except :
    return ( None )
    if 76 - 76: Ii1I % iIii1I11I1II1 / oO0o * iIii1I11I1II1 / iIii1I11I1II1
   I1ii = self . sign_map_request ( Iiii11 )
   I11I11i1 = True
  elif ( self . map_request_signature != None ) :
   o0o000OOO = binascii . b2a_base64 ( self . map_request_signature )
   I1ii = { "source-eid" : self . source_eid . print_address ( ) ,
 "signature-eid" : self . signature_eid . print_address ( ) ,
 "signature" : o0o000OOO }
   I1ii = json . dumps ( I1ii )
   I11I11i1 = True
   if 26 - 26: OOooOOo . OoO0O00 % OoOoOO00
  if ( I11I11i1 ) :
   o0O00o0o = LISP_LCAF_JSON_TYPE
   ooOO0o0ooOo0 = socket . htons ( LISP_AFI_LCAF )
   i11iii11 = socket . htons ( len ( I1ii ) + 2 )
   I11111i = socket . htons ( len ( I1ii ) )
   oOo += struct . pack ( "HBBBBHH" , ooOO0o0ooOo0 , 0 , 0 , o0O00o0o , 0 ,
 i11iii11 , I11111i )
   oOo += I1ii
   oOo += struct . pack ( "H" , 0 )
  else :
   if ( self . source_eid . instance_id != 0 ) :
    oOo += struct . pack ( "H" , socket . htons ( LISP_AFI_LCAF ) )
    oOo += self . source_eid . lcaf_encode_iid ( )
   else :
    oOo += struct . pack ( "H" , socket . htons ( self . source_eid . afi ) )
    oOo += self . source_eid . pack_address ( )
    if 46 - 46: OoooooooOO
    if 80 - 80: O0 * iII111i
    if 73 - 73: IiII / Ii1I + I1Ii111 . OOooOOo - II111iiii / iIii1I11I1II1
    if 79 - 79: I1Ii111 * Oo0Ooo . o0oOOo0O0Ooo - I1Ii111
    if 16 - 16: I1IiiI - O0 * I1ii11iIi11i . I1ii11iIi11i % OOooOOo
    if 39 - 39: II111iiii / I11i - OoOoOO00 * OoOoOO00 - Ii1I
    if 8 - 8: O0 . i11iIiiIii
  if ( probe_dest ) :
   if ( probe_port == 0 ) : probe_port = LISP_DATA_PORT
   ooOOo0o = probe_dest . print_address_no_iid ( ) + ":" + str ( probe_port )
   if 54 - 54: OOooOOo . I1ii11iIi11i * I11i % I1Ii111 . O0 * IiII
   if ( lisp_crypto_keys_by_rloc_encap . has_key ( ooOOo0o ) ) :
    self . keys = lisp_crypto_keys_by_rloc_encap [ ooOOo0o ]
    if 87 - 87: Ii1I % I1ii11iIi11i * Oo0Ooo
    if 59 - 59: Oo0Ooo / I11i - iIii1I11I1II1 * iIii1I11I1II1
    if 18 - 18: I11i * I1ii11iIi11i / i11iIiiIii / iIii1I11I1II1 * OoooooooOO . OOooOOo
    if 69 - 69: Oo0Ooo * ooOoO0o
    if 91 - 91: o0oOOo0O0Ooo . ooOoO0o / OoO0O00 / i11iIiiIii * o0oOOo0O0Ooo
    if 52 - 52: I1IiiI - i11iIiiIii / IiII . oO0o
    if 38 - 38: oO0o + OoooooooOO * OoOoOO00 % oO0o
  for OooOoOOo0 in self . itr_rlocs :
   if ( lisp_data_plane_security and self . itr_rlocs . index ( OooOoOOo0 ) == 0 ) :
    if ( self . keys == None or self . keys [ 1 ] == None ) :
     i1iIi = lisp_keys ( 1 )
     self . keys = [ None , i1iIi , None , None ]
     if 91 - 91: i1IIi - I1ii11iIi11i * I1IiiI
    i1iIi = self . keys [ 1 ]
    i1iIi . add_key_by_nonce ( self . nonce )
    oOo += i1iIi . encode_lcaf ( OooOoOOo0 )
   else :
    oOo += struct . pack ( "H" , socket . htons ( OooOoOOo0 . afi ) )
    oOo += OooOoOOo0 . pack_address ( )
    if 24 - 24: OoOoOO00 * Ii1I
    if 17 - 17: OoO0O00 . I1IiiI * O0
    if 81 - 81: OOooOOo
  Ooo = 0 if self . target_eid . is_binary ( ) == False else self . target_eid . mask_len
  if 93 - 93: i1IIi % I1IiiI . I11i % OoO0O00 + I11i + OoooooooOO
  if 41 - 41: OOooOOo % i11iIiiIii * I1IiiI + o0oOOo0O0Ooo / oO0o
  ooO0i11i1i1i = 0
  if ( self . subscribe_bit ) :
   ooO0i11i1i1i = 0x80
   self . xtr_id_present = True
   if ( self . xtr_id == None ) :
    self . xtr_id = random . randint ( 0 , ( 2 ** 128 ) - 1 )
    if 83 - 83: II111iiii + IiII - o0oOOo0O0Ooo % o0oOOo0O0Ooo * o0oOOo0O0Ooo
    if 100 - 100: Ii1I . iIii1I11I1II1
    if 33 - 33: I1IiiI . iIii1I11I1II1 / i11iIiiIii * Ii1I
  IIiI1I11ii1i = "BB"
  oOo += struct . pack ( IIiI1I11ii1i , ooO0i11i1i1i , Ooo )
  if 18 - 18: OoOoOO00 * OoOoOO00 - o0oOOo0O0Ooo % ooOoO0o % II111iiii - IiII
  if ( self . target_group . is_null ( ) == False ) :
   oOo += struct . pack ( "H" , socket . htons ( LISP_AFI_LCAF ) )
   oOo += self . target_eid . lcaf_encode_sg ( self . target_group )
  elif ( self . target_eid . instance_id != 0 or
 self . target_eid . is_geo_prefix ( ) ) :
   oOo += struct . pack ( "H" , socket . htons ( LISP_AFI_LCAF ) )
   oOo += self . target_eid . lcaf_encode_iid ( )
  else :
   oOo += struct . pack ( "H" , socket . htons ( self . target_eid . afi ) )
   oOo += self . target_eid . pack_address ( )
   if 75 - 75: OoO0O00 . II111iiii . oO0o / OoO0O00 % iIii1I11I1II1
   if 8 - 8: O0 / II111iiii
   if 62 - 62: iIii1I11I1II1 % I1Ii111 % I1ii11iIi11i * IiII
   if 87 - 87: IiII
   if 45 - 45: oO0o + II111iiii * O0 % OOooOOo . iIii1I11I1II1
  if ( self . subscribe_bit ) : oOo = self . encode_xtr_id ( oOo )
  return ( oOo )
  if 55 - 55: IiII
  if 43 - 43: OOooOOo
 def lcaf_decode_json ( self , packet ) :
  IIiI1I11ii1i = "BBBBHH"
  i1II1i1iiI1 = struct . calcsize ( IIiI1I11ii1i )
  if ( len ( packet ) < i1II1i1iiI1 ) : return ( None )
  if 17 - 17: i11iIiiIii
  OoO0oOoo , I11I , o0O00o0o , ii11iIII111 , i11iii11 , I11111i = struct . unpack ( IIiI1I11ii1i , packet [ : i1II1i1iiI1 ] )
  if 86 - 86: IiII - IiII
  if 51 - 51: IiII % iII111i / I11i + oO0o - ooOoO0o * I1Ii111
  if ( o0O00o0o != LISP_LCAF_JSON_TYPE ) : return ( packet )
  if 76 - 76: OoOoOO00 / I1ii11iIi11i / iIii1I11I1II1 * OoooooooOO * OOooOOo
  if 80 - 80: oO0o / O0
  if 55 - 55: I1IiiI * I11i / O0 % OoOoOO00
  if 71 - 71: i11iIiiIii * OoOoOO00 * OOooOOo + oO0o + Oo0Ooo
  i11iii11 = socket . ntohs ( i11iii11 )
  I11111i = socket . ntohs ( I11111i )
  packet = packet [ i1II1i1iiI1 : : ]
  if ( len ( packet ) < i11iii11 ) : return ( None )
  if ( i11iii11 != I11111i + 2 ) : return ( None )
  if 59 - 59: IiII
  if 54 - 54: OOooOOo
  if 27 - 27: OoOoOO00 - OoO0O00 + o0oOOo0O0Ooo + ooOoO0o . OoO0O00
  if 86 - 86: II111iiii - OoooooooOO - ooOoO0o % iII111i
  try :
   I1ii = json . loads ( packet [ 0 : I11111i ] )
  except :
   return ( None )
   if 16 - 16: ooOoO0o + Oo0Ooo + OoooooooOO
  packet = packet [ I11111i : : ]
  if 87 - 87: I1IiiI . oO0o / IiII - OoooooooOO
  if 33 - 33: oO0o % OoO0O00 . iIii1I11I1II1 / IiII
  if 3 - 3: Ii1I + OoO0O00
  if 60 - 60: OoO0O00 . OoOoOO00 - I1ii11iIi11i - I1IiiI - II111iiii % Oo0Ooo
  IIiI1I11ii1i = "H"
  i1II1i1iiI1 = struct . calcsize ( IIiI1I11ii1i )
  o0o0O00oOo = struct . unpack ( IIiI1I11ii1i , packet [ : i1II1i1iiI1 ] ) [ 0 ]
  packet = packet [ i1II1i1iiI1 : : ]
  if ( o0o0O00oOo != 0 ) : return ( packet )
  if 62 - 62: O0 + iII111i - iII111i % iIii1I11I1II1
  if 47 - 47: I1Ii111 + I1IiiI
  if 40 - 40: iIii1I11I1II1 % Ii1I + II111iiii - I1IiiI
  if 80 - 80: oO0o
  if ( I1ii . has_key ( "source-eid" ) == False ) : return ( packet )
  Oo00o = I1ii [ "source-eid" ]
  o0o0O00oOo = LISP_AFI_IPV4 if Oo00o . count ( "." ) == 3 else LISP_AFI_IPV6 if Oo00o . count ( ":" ) == 7 else None
  if 14 - 14: II111iiii + O0 - iII111i
  if ( o0o0O00oOo == None ) :
   lprint ( "Bad JSON 'source-eid' value: {}" . format ( Oo00o ) )
   return ( None )
   if 18 - 18: o0oOOo0O0Ooo / i11iIiiIii % I1ii11iIi11i * OoooooooOO
   if 67 - 67: OoOoOO00
  self . source_eid . afi = o0o0O00oOo
  self . source_eid . store_address ( Oo00o )
  if 67 - 67: I1ii11iIi11i / iII111i + iIii1I11I1II1 % I1IiiI
  if ( I1ii . has_key ( "signature-eid" ) == False ) : return ( packet )
  Oo00o = I1ii [ "signature-eid" ]
  if ( Oo00o . count ( ":" ) != 7 ) :
   lprint ( "Bad JSON 'signature-eid' value: {}" . format ( Oo00o ) )
   return ( None )
   if 99 - 99: ooOoO0o . Ii1I
   if 92 - 92: i1IIi
  self . signature_eid . afi = LISP_AFI_IPV6
  self . signature_eid . store_address ( Oo00o )
  if 68 - 68: OoO0O00 % IiII - oO0o - ooOoO0o . Oo0Ooo
  if ( I1ii . has_key ( "signature" ) == False ) : return ( packet )
  o0o000OOO = binascii . a2b_base64 ( I1ii [ "signature" ] )
  self . map_request_signature = o0o000OOO
  return ( packet )
  if 30 - 30: OoooooooOO % o0oOOo0O0Ooo + ooOoO0o * OoO0O00
  if 57 - 57: I11i + iIii1I11I1II1 . OoO0O00 + oO0o
 def decode ( self , packet , source , port ) :
  IIiI1I11ii1i = "I"
  i1II1i1iiI1 = struct . calcsize ( IIiI1I11ii1i )
  if ( len ( packet ) < i1II1i1iiI1 ) : return ( None )
  if 4 - 4: Ii1I
  O0oooOO = struct . unpack ( IIiI1I11ii1i , packet [ : i1II1i1iiI1 ] )
  O0oooOO = O0oooOO [ 0 ]
  packet = packet [ i1II1i1iiI1 : : ]
  if 43 - 43: i1IIi . I1IiiI * iIii1I11I1II1 * i11iIiiIii - OOooOOo + ooOoO0o
  IIiI1I11ii1i = "Q"
  i1II1i1iiI1 = struct . calcsize ( IIiI1I11ii1i )
  if ( len ( packet ) < i1II1i1iiI1 ) : return ( None )
  if 56 - 56: Oo0Ooo % i11iIiiIii / Ii1I . I1Ii111 . OoO0O00 - OoOoOO00
  i11III1I = struct . unpack ( IIiI1I11ii1i , packet [ : i1II1i1iiI1 ] )
  packet = packet [ i1II1i1iiI1 : : ]
  if 32 - 32: I1Ii111 / oO0o / I1IiiI
  O0oooOO = socket . ntohl ( O0oooOO )
  self . auth_bit = True if ( O0oooOO & 0x08000000 ) else False
  self . map_data_present = True if ( O0oooOO & 0x04000000 ) else False
  self . rloc_probe = True if ( O0oooOO & 0x02000000 ) else False
  self . smr_bit = True if ( O0oooOO & 0x01000000 ) else False
  self . pitr_bit = True if ( O0oooOO & 0x00800000 ) else False
  self . smr_invoked_bit = True if ( O0oooOO & 0x00400000 ) else False
  self . mobile_node = True if ( O0oooOO & 0x00200000 ) else False
  self . xtr_id_present = True if ( O0oooOO & 0x00100000 ) else False
  self . local_xtr = True if ( O0oooOO & 0x00004000 ) else False
  self . dont_reply_bit = True if ( O0oooOO & 0x00002000 ) else False
  self . itr_rloc_count = ( ( O0oooOO >> 8 ) & 0x1f ) + 1
  self . record_count = O0oooOO & 0xff
  self . nonce = i11III1I [ 0 ]
  if 22 - 22: OoO0O00 - OoOoOO00 . Oo0Ooo + o0oOOo0O0Ooo
  if 69 - 69: oO0o - I1IiiI
  if 10 - 10: i1IIi / iII111i . II111iiii * i1IIi % OoooooooOO
  if 83 - 83: I11i . OOooOOo + I1Ii111 * I11i . I1Ii111 + oO0o
  if ( self . xtr_id_present ) :
   if ( self . decode_xtr_id ( packet ) == False ) : return ( None )
   if 64 - 64: Ii1I . o0oOOo0O0Ooo - i1IIi
   if 35 - 35: I1ii11iIi11i % OoooooooOO
  i1II1i1iiI1 = struct . calcsize ( "H" )
  if ( len ( packet ) < i1II1i1iiI1 ) : return ( None )
  if 59 - 59: I1IiiI % I11i
  o0o0O00oOo = struct . unpack ( "H" , packet [ : i1II1i1iiI1 ] )
  self . source_eid . afi = socket . ntohs ( o0o0O00oOo [ 0 ] )
  packet = packet [ i1II1i1iiI1 : : ]
  if 32 - 32: I1IiiI * O0 + O0
  if ( self . source_eid . afi == LISP_AFI_LCAF ) :
   iiiiIiI1IIiI = packet
   packet = self . source_eid . lcaf_decode_iid ( packet )
   if ( packet == None ) :
    packet = self . lcaf_decode_json ( iiiiIiI1IIiI )
    if ( packet == None ) : return ( None )
    if 53 - 53: iIii1I11I1II1 % OoOoOO00 % I1IiiI + I1ii11iIi11i % OoooooooOO
  elif ( self . source_eid . afi != LISP_AFI_NONE ) :
   packet = self . source_eid . unpack_address ( packet )
   if ( packet == None ) : return ( None )
   if 29 - 29: I1IiiI / o0oOOo0O0Ooo + iIii1I11I1II1 / O0 / OOooOOo % i1IIi
  self . source_eid . mask_len = self . source_eid . host_mask_len ( )
  if 65 - 65: OoO0O00 * OoOoOO00 . OoooooooOO - O0 * OoOoOO00 % OoOoOO00
  IiiiIii = ( os . getenv ( "LISP_NO_CRYPTO" ) != None )
  self . itr_rlocs = [ ]
  while ( self . itr_rloc_count != 0 ) :
   i1II1i1iiI1 = struct . calcsize ( "H" )
   if ( len ( packet ) < i1II1i1iiI1 ) : return ( None )
   if 67 - 67: OoOoOO00 % o0oOOo0O0Ooo % I1ii11iIi11i . OoO0O00 . II111iiii + IiII
   o0o0O00oOo = struct . unpack ( "H" , packet [ : i1II1i1iiI1 ] ) [ 0 ]
   if 50 - 50: Oo0Ooo + iII111i . O0 - i1IIi / Oo0Ooo
   OooOoOOo0 = lisp_address ( LISP_AFI_NONE , "" , 32 , 0 )
   OooOoOOo0 . afi = socket . ntohs ( o0o0O00oOo )
   if 59 - 59: oO0o * ooOoO0o + oO0o + I1ii11iIi11i
   if 80 - 80: o0oOOo0O0Ooo . OoOoOO00 - o0oOOo0O0Ooo - I1Ii111 / I11i
   if 17 - 17: OoO0O00 - I1Ii111 - II111iiii / I1Ii111 / Ii1I
   if 30 - 30: OOooOOo * I1ii11iIi11i % I1ii11iIi11i + iII111i * IiII
   if 33 - 33: o0oOOo0O0Ooo + I11i * O0 * OoO0O00 . I1ii11iIi11i
   if ( OooOoOOo0 . afi != LISP_AFI_LCAF ) :
    if ( len ( packet ) < OooOoOOo0 . addr_length ( ) ) : return ( None )
    packet = OooOoOOo0 . unpack_address ( packet [ i1II1i1iiI1 : : ] )
    if ( packet == None ) : return ( None )
    if 74 - 74: iII111i * iII111i * o0oOOo0O0Ooo / oO0o
    if ( IiiiIii ) :
     self . itr_rlocs . append ( OooOoOOo0 )
     self . itr_rloc_count -= 1
     continue
     if 91 - 91: i11iIiiIii . I1ii11iIi11i / II111iiii
     if 97 - 97: Ii1I % i1IIi % IiII + Oo0Ooo - O0 - I11i
    ooOOo0o = lisp_build_crypto_decap_lookup_key ( OooOoOOo0 , port )
    if 64 - 64: Ii1I - iII111i
    if 12 - 12: i1IIi
    if 99 - 99: II111iiii - I1ii11iIi11i * IiII
    if 3 - 3: IiII - I1ii11iIi11i * iII111i * I1ii11iIi11i + Oo0Ooo
    if 15 - 15: I1ii11iIi11i * Ii1I / iII111i . o0oOOo0O0Ooo / Ii1I % OoOoOO00
    if ( lisp_nat_traversal and OooOoOOo0 . is_private_address ( ) and source ) : OooOoOOo0 = source
    if 75 - 75: OoooooooOO % i11iIiiIii % iIii1I11I1II1 % I1ii11iIi11i / i11iIiiIii
    O0oOoo0ooO00 = lisp_crypto_keys_by_rloc_decap
    if ( O0oOoo0ooO00 . has_key ( ooOOo0o ) ) : O0oOoo0ooO00 . pop ( ooOOo0o )
    if 86 - 86: I1IiiI . II111iiii * i1IIi % I1IiiI . OOooOOo
    if 79 - 79: OoO0O00 + O0 * OOooOOo
    if 51 - 51: i1IIi - oO0o / oO0o % o0oOOo0O0Ooo
    if 98 - 98: OoO0O00 * ooOoO0o + i1IIi + IiII - i1IIi % OoOoOO00
    if 19 - 19: iIii1I11I1II1 * Oo0Ooo / OOooOOo
    if 5 - 5: o0oOOo0O0Ooo
    lisp_write_ipc_decap_key ( ooOOo0o , None )
   else :
    oOO = packet
    i1II1Ii = lisp_keys ( 1 )
    packet = i1II1Ii . decode_lcaf ( oOO , 0 )
    if ( packet == None ) : return ( None )
    if 92 - 92: Oo0Ooo - II111iiii
    if 7 - 7: i11iIiiIii + ooOoO0o . I1Ii111 + i1IIi - o0oOOo0O0Ooo
    if 82 - 82: II111iiii + ooOoO0o * OOooOOo . iIii1I11I1II1 - i11iIiiIii * iIii1I11I1II1
    if 42 - 42: o0oOOo0O0Ooo * oO0o . OOooOOo
    iii1IiI = [ LISP_CS_25519_CBC , LISP_CS_25519_GCM ,
 LISP_CS_25519_CHACHA ]
    if ( i1II1Ii . cipher_suite in iii1IiI ) :
     if ( i1II1Ii . cipher_suite == LISP_CS_25519_CBC or
 i1II1Ii . cipher_suite == LISP_CS_25519_GCM ) :
      Iiii11 = lisp_keys ( 1 , do_poly = False , do_chacha = False )
      if 46 - 46: I1ii11iIi11i - I1Ii111 % I1ii11iIi11i - i11iIiiIii
     if ( i1II1Ii . cipher_suite == LISP_CS_25519_CHACHA ) :
      Iiii11 = lisp_keys ( 1 , do_poly = True , do_chacha = True )
      if 50 - 50: I1Ii111 % IiII
    else :
     Iiii11 = lisp_keys ( 1 , do_poly = False , do_curve = False ,
 do_chacha = False )
     if 63 - 63: OoooooooOO . Ii1I - oO0o / II111iiii + I1IiiI
    packet = Iiii11 . decode_lcaf ( oOO , 0 )
    if ( packet == None ) : return ( None )
    if 97 - 97: I11i
    if ( len ( packet ) < i1II1i1iiI1 ) : return ( None )
    o0o0O00oOo = struct . unpack ( "H" , packet [ : i1II1i1iiI1 ] ) [ 0 ]
    OooOoOOo0 . afi = socket . ntohs ( o0o0O00oOo )
    if ( len ( packet ) < OooOoOOo0 . addr_length ( ) ) : return ( None )
    if 84 - 84: IiII - OoOoOO00 . IiII + ooOoO0o . iII111i
    packet = OooOoOOo0 . unpack_address ( packet [ i1II1i1iiI1 : : ] )
    if ( packet == None ) : return ( None )
    if 96 - 96: Ii1I % iII111i * Ii1I % I1IiiI . o0oOOo0O0Ooo / o0oOOo0O0Ooo
    if ( IiiiIii ) :
     self . itr_rlocs . append ( OooOoOOo0 )
     self . itr_rloc_count -= 1
     continue
     if 7 - 7: OoO0O00 - ooOoO0o % i1IIi
     if 24 - 24: OoO0O00 % O0 % I11i
    ooOOo0o = lisp_build_crypto_decap_lookup_key ( OooOoOOo0 , port )
    if 61 - 61: ooOoO0o . iII111i / ooOoO0o * OoooooooOO
    iiiiI = None
    if ( lisp_nat_traversal and OooOoOOo0 . is_private_address ( ) and source ) : OooOoOOo0 = source
    if 18 - 18: oO0o * Oo0Ooo % i11iIiiIii + O0 % OOooOOo . OOooOOo
    if 84 - 84: OoooooooOO - Oo0Ooo
    if ( lisp_crypto_keys_by_rloc_decap . has_key ( ooOOo0o ) ) :
     i1iIi = lisp_crypto_keys_by_rloc_decap [ ooOOo0o ]
     iiiiI = i1iIi [ 1 ] if i1iIi and i1iIi [ 1 ] else None
     if 79 - 79: O0 - oO0o + oO0o . Ii1I . OoOoOO00 - I1ii11iIi11i
     if 74 - 74: ooOoO0o % I1ii11iIi11i * i1IIi
    iiiii1I = True
    if ( iiiiI ) :
     if ( iiiiI . compare_keys ( Iiii11 ) ) :
      self . keys = [ None , iiiiI , None , None ]
      lprint ( "Maintain stored decap-keys for RLOC {}" . format ( red ( ooOOo0o , False ) ) )
      if 22 - 22: iII111i . OoooooooOO . Oo0Ooo
     else :
      iiiii1I = False
      IIiI = bold ( "Remote decap-rekeying" , False )
      lprint ( "{} for RLOC {}" . format ( IIiI , red ( ooOOo0o ,
 False ) ) )
      Iiii11 . copy_keypair ( iiiiI )
      Iiii11 . uptime = iiiiI . uptime
      iiiiI = None
      if 70 - 70: OoooooooOO * i11iIiiIii
      if 60 - 60: IiII / iIii1I11I1II1 + OoooooooOO - I1ii11iIi11i * i11iIiiIii
      if 47 - 47: O0 . I1IiiI / ooOoO0o % i11iIiiIii
    if ( iiiiI == None ) :
     self . keys = [ None , Iiii11 , None , None ]
     if ( lisp_i_am_etr == False and lisp_i_am_rtr == False ) :
      Iiii11 . local_public_key = None
      lprint ( "{} for {}" . format ( bold ( "Ignoring decap-keys" ,
 False ) , red ( ooOOo0o , False ) ) )
     elif ( Iiii11 . remote_public_key != None ) :
      if ( iiiii1I ) :
       lprint ( "{} for RLOC {}" . format ( bold ( "New decap-keying" , False ) ,
       # O0 - i11iIiiIii % OoOoOO00
 red ( ooOOo0o , False ) ) )
       if 17 - 17: o0oOOo0O0Ooo
      Iiii11 . compute_shared_key ( "decap" )
      Iiii11 . add_key_by_rloc ( ooOOo0o , False )
      if 39 - 39: o0oOOo0O0Ooo
      if 89 - 89: OoooooooOO + iII111i . I1Ii111 / Ii1I
      if 75 - 75: iIii1I11I1II1 * iII111i / OoOoOO00 * II111iiii . i1IIi
      if 6 - 6: Ii1I % Ii1I / OoooooooOO * oO0o . I1IiiI . i1IIi
   self . itr_rlocs . append ( OooOoOOo0 )
   self . itr_rloc_count -= 1
   if 59 - 59: I11i . I11i * I1IiiI - Ii1I % OoOoOO00
   if 19 - 19: OoooooooOO / Oo0Ooo - I1Ii111 . OoOoOO00
  i1II1i1iiI1 = struct . calcsize ( "BBH" )
  if ( len ( packet ) < i1II1i1iiI1 ) : return ( None )
  if 8 - 8: I11i % ooOoO0o . iIii1I11I1II1
  ooO0i11i1i1i , Ooo , o0o0O00oOo = struct . unpack ( "BBH" , packet [ : i1II1i1iiI1 ] )
  self . subscribe_bit = ( ooO0i11i1i1i & 0x80 )
  self . target_eid . afi = socket . ntohs ( o0o0O00oOo )
  packet = packet [ i1II1i1iiI1 : : ]
  if 95 - 95: o0oOOo0O0Ooo + i11iIiiIii . I1ii11iIi11i . ooOoO0o . o0oOOo0O0Ooo
  self . target_eid . mask_len = Ooo
  if ( self . target_eid . afi == LISP_AFI_LCAF ) :
   packet , oOO0oOOOOO0 = self . target_eid . lcaf_decode_eid ( packet )
   if ( packet == None ) : return ( None )
   if ( oOO0oOOOOO0 ) : self . target_group = oOO0oOOOOO0
  else :
   packet = self . target_eid . unpack_address ( packet )
   if ( packet == None ) : return ( None )
   packet = packet [ i1II1i1iiI1 : : ]
   if 99 - 99: OoOoOO00 . I1Ii111 * II111iiii - i11iIiiIii + I11i
  return ( packet )
  if 44 - 44: ooOoO0o * i11iIiiIii . iII111i / iIii1I11I1II1
  if 44 - 44: OoO0O00
 def print_eid_tuple ( self ) :
  return ( lisp_print_eid_tuple ( self . target_eid , self . target_group ) )
  if 74 - 74: Ii1I * i1IIi * I11i - OoooooooOO . I1IiiI
  if 24 - 24: II111iiii - i11iIiiIii * i1IIi . ooOoO0o
 def encode_xtr_id ( self , packet ) :
  o0oo0oo0 = self . xtr_id >> 64
  IIi1II = self . xtr_id & 0xffffffffffffffff
  o0oo0oo0 = byte_swap_64 ( o0oo0oo0 )
  IIi1II = byte_swap_64 ( IIi1II )
  packet += struct . pack ( "QQ" , o0oo0oo0 , IIi1II )
  return ( packet )
  if 42 - 42: I11i / i11iIiiIii
  if 7 - 7: I11i
 def decode_xtr_id ( self , packet ) :
  i1II1i1iiI1 = struct . calcsize ( "QQ" )
  if ( len ( packet ) < i1II1i1iiI1 ) : return ( None )
  packet = packet [ len ( packet ) - i1II1i1iiI1 : : ]
  o0oo0oo0 , IIi1II = struct . unpack ( "QQ" , packet [ : i1II1i1iiI1 ] )
  o0oo0oo0 = byte_swap_64 ( o0oo0oo0 )
  IIi1II = byte_swap_64 ( IIi1II )
  self . xtr_id = ( o0oo0oo0 << 64 ) | IIi1II
  return ( True )
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
class lisp_map_reply ( ) :
 def __init__ ( self ) :
  self . rloc_probe = False
  self . echo_nonce_capable = False
  self . security = False
  self . record_count = 0
  self . hop_count = 0
  self . nonce = 0
  self . keys = None
  if 45 - 45: oO0o / iII111i + I1ii11iIi11i - Oo0Ooo - ooOoO0o . iIii1I11I1II1
  if 52 - 52: I1IiiI + i1IIi . iII111i * I1IiiI
 def print_map_reply ( self ) :
  IIIIIiI11Ii = "{} -> flags: {}{}{}, hop-count: {}, record-count: {}, " + "nonce: 0x{}"
  if 31 - 31: Oo0Ooo % iIii1I11I1II1 . O0
  lprint ( IIIIIiI11Ii . format ( bold ( "Map-Reply" , False ) , "R" if self . rloc_probe else "r" ,
  # II111iiii + Oo0Ooo % I1ii11iIi11i + ooOoO0o / OOooOOo
 "E" if self . echo_nonce_capable else "e" ,
 "S" if self . security else "s" , self . hop_count , self . record_count ,
 lisp_hex_string ( self . nonce ) ) )
  if 28 - 28: Ii1I % iIii1I11I1II1
  if 72 - 72: I1ii11iIi11i / OoOoOO00 - i11iIiiIii
 def encode ( self ) :
  O0oooOO = ( LISP_MAP_REPLY << 28 ) | self . record_count
  O0oooOO |= self . hop_count << 8
  if ( self . rloc_probe ) : O0oooOO |= 0x08000000
  if ( self . echo_nonce_capable ) : O0oooOO |= 0x04000000
  if ( self . security ) : O0oooOO |= 0x02000000
  if 67 - 67: OOooOOo / Ii1I
  oOo = struct . pack ( "I" , socket . htonl ( O0oooOO ) )
  oOo += struct . pack ( "Q" , self . nonce )
  return ( oOo )
  if 51 - 51: I11i % II111iiii - o0oOOo0O0Ooo % OoO0O00 * i11iIiiIii * iII111i
  if 82 - 82: OoooooooOO / I1IiiI * II111iiii - OoooooooOO % iIii1I11I1II1 * OoO0O00
 def decode ( self , packet ) :
  IIiI1I11ii1i = "I"
  i1II1i1iiI1 = struct . calcsize ( IIiI1I11ii1i )
  if ( len ( packet ) < i1II1i1iiI1 ) : return ( None )
  if 32 - 32: i11iIiiIii - OoOoOO00 * I11i . Oo0Ooo * ooOoO0o
  O0oooOO = struct . unpack ( IIiI1I11ii1i , packet [ : i1II1i1iiI1 ] )
  O0oooOO = O0oooOO [ 0 ]
  packet = packet [ i1II1i1iiI1 : : ]
  if 21 - 21: OOooOOo
  IIiI1I11ii1i = "Q"
  i1II1i1iiI1 = struct . calcsize ( IIiI1I11ii1i )
  if ( len ( packet ) < i1II1i1iiI1 ) : return ( None )
  if 11 - 11: oO0o % i11iIiiIii * O0
  i11III1I = struct . unpack ( IIiI1I11ii1i , packet [ : i1II1i1iiI1 ] )
  packet = packet [ i1II1i1iiI1 : : ]
  if 28 - 28: I1Ii111 / iIii1I11I1II1 + OOooOOo . I1ii11iIi11i % OOooOOo + OoO0O00
  O0oooOO = socket . ntohl ( O0oooOO )
  self . rloc_probe = True if ( O0oooOO & 0x08000000 ) else False
  self . echo_nonce_capable = True if ( O0oooOO & 0x04000000 ) else False
  self . security = True if ( O0oooOO & 0x02000000 ) else False
  self . hop_count = ( O0oooOO >> 8 ) & 0xff
  self . record_count = O0oooOO & 0xff
  self . nonce = i11III1I [ 0 ]
  if 79 - 79: oO0o
  if ( lisp_crypto_keys_by_nonce . has_key ( self . nonce ) ) :
   self . keys = lisp_crypto_keys_by_nonce [ self . nonce ]
   self . keys [ 1 ] . delete_key_by_nonce ( self . nonce )
   if 39 - 39: I1Ii111 % oO0o % O0 % O0 - iII111i - oO0o
  return ( packet )
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
  if 79 - 79: I1IiiI / o0oOOo0O0Ooo . Ii1I * I1ii11iIi11i + I11i
  if 96 - 96: OoO0O00 * II111iiii
 def print_prefix ( self ) :
  if ( self . group . is_null ( ) ) :
   return ( green ( self . eid . print_prefix ( ) , False ) )
   if 1 - 1: I1IiiI - OoOoOO00
  return ( green ( self . eid . print_sg ( self . group ) , False ) )
  if 74 - 74: OoOoOO00 * II111iiii + O0 + I11i
  if 3 - 3: iIii1I11I1II1 - i1IIi / iII111i + i1IIi + O0
 def print_ttl ( self ) :
  Ii1 = self . record_ttl
  if ( self . record_ttl & 0x80000000 ) :
   Ii1 = str ( self . record_ttl & 0x7fffffff ) + " secs"
  elif ( ( Ii1 % 60 ) == 0 ) :
   Ii1 = str ( Ii1 / 60 ) + " hours"
  else :
   Ii1 = str ( Ii1 ) + " mins"
   if 84 - 84: OoOoOO00 - ooOoO0o - OoooooooOO . OoooooooOO % IiII
  return ( Ii1 )
  if 38 - 38: OoO0O00 * I1ii11iIi11i
  if 4 - 4: OoO0O00 . I1ii11iIi11i
 def store_ttl ( self ) :
  Ii1 = self . record_ttl * 60
  if ( self . record_ttl & 0x80000000 ) : Ii1 = self . record_ttl & 0x7fffffff
  return ( Ii1 )
  if 21 - 21: i11iIiiIii / OoO0O00 / I1ii11iIi11i * O0 - II111iiii * OOooOOo
  if 27 - 27: o0oOOo0O0Ooo . OoOoOO00 * Ii1I * iII111i * O0
 def print_record ( self , indent , ddt ) :
  o000ooo0o0O = ""
  iiiI11iiI11 = ""
  iII1i1iIi11I = bold ( "invalid-action" , False )
  if ( ddt ) :
   if ( self . action < len ( lisp_map_referral_action_string ) ) :
    iII1i1iIi11I = lisp_map_referral_action_string [ self . action ]
    iII1i1iIi11I = bold ( iII1i1iIi11I , False )
    o000ooo0o0O = ( ", " + bold ( "ddt-incomplete" , False ) ) if self . ddt_incomplete else ""
    if 55 - 55: IiII
    iiiI11iiI11 = ( ", sig-count: " + str ( self . signature_count ) ) if ( self . signature_count != 0 ) else ""
    if 12 - 12: i11iIiiIii + I1ii11iIi11i * OoO0O00
    if 13 - 13: Oo0Ooo + OoooooooOO / IiII
  else :
   if ( self . action < len ( lisp_map_reply_action_string ) ) :
    iII1i1iIi11I = lisp_map_reply_action_string [ self . action ]
    if ( self . action != LISP_NO_ACTION ) :
     iII1i1iIi11I = bold ( iII1i1iIi11I , False )
     if 56 - 56: I1ii11iIi11i * II111iiii
     if 75 - 75: I11i . o0oOOo0O0Ooo - i11iIiiIii / I11i
     if 100 - 100: i11iIiiIii * i11iIiiIii . iIii1I11I1II1 % iII111i * I1ii11iIi11i
     if 17 - 17: Ii1I * IiII * i11iIiiIii / I1ii11iIi11i / i11iIiiIii
  o0o0O00oOo = LISP_AFI_LCAF if ( self . eid . afi < 0 ) else self . eid . afi
  IIIIIiI11Ii = ( "{}EID-record -> record-ttl: {}, rloc-count: {}, action: " +
 "{}, {}{}{}, map-version: {}, afi: {}, [iid]eid/ml: {}" )
  if 23 - 23: OoooooooOO + i11iIiiIii / Oo0Ooo / iII111i . iII111i * I1IiiI
  lprint ( IIIIIiI11Ii . format ( indent , self . print_ttl ( ) , self . rloc_count ,
 iII1i1iIi11I , "auth" if ( self . authoritative is True ) else "non-auth" ,
 o000ooo0o0O , iiiI11iiI11 , self . map_version , o0o0O00oOo ,
 green ( self . print_prefix ( ) , False ) ) )
  if 98 - 98: IiII
  if 23 - 23: I11i / i1IIi * OoO0O00
 def encode ( self ) :
  O0oo0oo0 = self . action << 13
  if ( self . authoritative ) : O0oo0oo0 |= 0x1000
  if ( self . ddt_incomplete ) : O0oo0oo0 |= 0x800
  if 40 - 40: OoO0O00
  if 1 - 1: I11i + oO0o - iII111i . Ii1I
  if 76 - 76: IiII
  if 6 - 6: Oo0Ooo % oO0o * ooOoO0o - i1IIi . OoOoOO00
  o0o0O00oOo = self . eid . afi if ( self . eid . instance_id == 0 ) else LISP_AFI_LCAF
  if ( o0o0O00oOo < 0 ) : o0o0O00oOo = LISP_AFI_LCAF
  iIi1I = ( self . group . is_null ( ) == False )
  if ( iIi1I ) : o0o0O00oOo = LISP_AFI_LCAF
  if 60 - 60: I1ii11iIi11i - I1IiiI * O0 * Oo0Ooo . i1IIi . OoOoOO00
  i1ii1I1ii111I = ( self . signature_count << 12 ) | self . map_version
  Ooo = 0 if self . eid . is_binary ( ) == False else self . eid . mask_len
  if 45 - 45: I1ii11iIi11i . I11i . II111iiii - II111iiii * OoooooooOO
  oOo = struct . pack ( "IBBHHH" , socket . htonl ( self . record_ttl ) ,
 self . rloc_count , Ooo , socket . htons ( O0oo0oo0 ) ,
 socket . htons ( i1ii1I1ii111I ) , socket . htons ( o0o0O00oOo ) )
  if 71 - 71: OOooOOo
  if 87 - 87: II111iiii / iIii1I11I1II1 % I1ii11iIi11i
  if 11 - 11: o0oOOo0O0Ooo * OoO0O00
  if 92 - 92: OoOoOO00 . Oo0Ooo * I11i
  if ( iIi1I ) :
   oOo += self . eid . lcaf_encode_sg ( self . group )
   return ( oOo )
   if 86 - 86: O0
   if 55 - 55: Ii1I / I1Ii111 / I1ii11iIi11i % ooOoO0o % I1IiiI
   if 55 - 55: oO0o + OoooooooOO % i1IIi
   if 24 - 24: I1ii11iIi11i - Oo0Ooo
   if 36 - 36: I1IiiI . OOooOOo % II111iiii * IiII
  if ( self . eid . afi == LISP_AFI_GEO_COORD and self . eid . instance_id == 0 ) :
   oOo = oOo [ 0 : - 2 ]
   oOo += self . eid . address . encode_geo ( )
   return ( oOo )
   if 34 - 34: I11i % iII111i - ooOoO0o - I1IiiI
   if 44 - 44: Ii1I . o0oOOo0O0Ooo . iIii1I11I1II1 + OoooooooOO - I1IiiI
   if 22 - 22: I11i * I1ii11iIi11i . OoooooooOO / Oo0Ooo / Ii1I
   if 54 - 54: I1Ii111 % Ii1I + ooOoO0o
   if 45 - 45: Ii1I / oO0o * I1Ii111 . Ii1I
  if ( o0o0O00oOo == LISP_AFI_LCAF ) :
   oOo += self . eid . lcaf_encode_iid ( )
   return ( oOo )
   if 25 - 25: I1ii11iIi11i / I1ii11iIi11i
   if 79 - 79: Oo0Ooo - OoO0O00 % Oo0Ooo . II111iiii
   if 84 - 84: ooOoO0o * OoooooooOO + O0
   if 84 - 84: i1IIi . I11i . i1IIi . Oo0Ooo
   if 21 - 21: II111iiii . O0 + Oo0Ooo - i11iIiiIii
  oOo += self . eid . pack_address ( )
  return ( oOo )
  if 5 - 5: iIii1I11I1II1 * i11iIiiIii + OoO0O00 + I11i * O0 % ooOoO0o
  if 88 - 88: o0oOOo0O0Ooo / i11iIiiIii * I1ii11iIi11i
 def decode ( self , packet ) :
  IIiI1I11ii1i = "IBBHHH"
  i1II1i1iiI1 = struct . calcsize ( IIiI1I11ii1i )
  if ( len ( packet ) < i1II1i1iiI1 ) : return ( None )
  if 23 - 23: O0 / iII111i
  self . record_ttl , self . rloc_count , self . eid . mask_len , O0oo0oo0 , self . map_version , self . eid . afi = struct . unpack ( IIiI1I11ii1i , packet [ : i1II1i1iiI1 ] )
  if 66 - 66: i1IIi % OoooooooOO * i11iIiiIii + oO0o * O0 / OoO0O00
  if 14 - 14: I1IiiI . IiII
  if 29 - 29: OoooooooOO / IiII + OoOoOO00 - I1Ii111 + IiII . i1IIi
  self . record_ttl = socket . ntohl ( self . record_ttl )
  O0oo0oo0 = socket . ntohs ( O0oo0oo0 )
  self . action = ( O0oo0oo0 >> 13 ) & 0x7
  self . authoritative = True if ( ( O0oo0oo0 >> 12 ) & 1 ) else False
  self . ddt_incomplete = True if ( ( O0oo0oo0 >> 11 ) & 1 ) else False
  self . map_version = socket . ntohs ( self . map_version )
  self . signature_count = self . map_version >> 12
  self . map_version = self . map_version & 0xfff
  self . eid . afi = socket . ntohs ( self . eid . afi )
  self . eid . instance_id = 0
  packet = packet [ i1II1i1iiI1 : : ]
  if 26 - 26: i11iIiiIii - II111iiii
  if 43 - 43: I1IiiI
  if 35 - 35: ooOoO0o + OoOoOO00 * OoooooooOO - II111iiii
  if 19 - 19: i1IIi / Ii1I / OoOoOO00 . I1IiiI / Ii1I % o0oOOo0O0Ooo
  if ( self . eid . afi == LISP_AFI_LCAF ) :
   packet , i1i11Ii1 = self . eid . lcaf_decode_eid ( packet )
   if ( i1i11Ii1 ) : self . group = i1i11Ii1
   self . group . instance_id = self . eid . instance_id
   return ( packet )
   if 14 - 14: OOooOOo . o0oOOo0O0Ooo / II111iiii % OOooOOo
   if 98 - 98: I1IiiI
  packet = self . eid . unpack_address ( packet )
  return ( packet )
  if 51 - 51: OoOoOO00 * OoooooooOO * Oo0Ooo
  if 28 - 28: i11iIiiIii - Ii1I
 def print_eid_tuple ( self ) :
  return ( lisp_print_eid_tuple ( self . eid , self . group ) )
  if 59 - 59: II111iiii - OoO0O00
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
  if 64 - 64: i1IIi / IiII . IiII - I1Ii111 % OOooOOo . II111iiii
  if 78 - 78: I1Ii111 - O0 - I1Ii111 . iIii1I11I1II1 % I1ii11iIi11i . OoooooooOO
  if 64 - 64: IiII
  if 21 - 21: o0oOOo0O0Ooo - ooOoO0o * OoooooooOO . OoooooooOO
  if 17 - 17: OOooOOo - iII111i % I1IiiI * OOooOOo * iIii1I11I1II1 . o0oOOo0O0Ooo
  if 58 - 58: oO0o - II111iiii + O0
  if 54 - 54: iIii1I11I1II1 - IiII - IiII
LISP_UDP_PROTOCOL = 17
LISP_DEFAULT_ECM_TTL = 128
if 18 - 18: i11iIiiIii + iIii1I11I1II1 . i11iIiiIii
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
  if 63 - 63: iII111i - OoO0O00 * OOooOOo
  if 89 - 89: iII111i / Oo0Ooo
 def print_ecm ( self ) :
  IIIIIiI11Ii = ( "{} -> flags: {}{}{}{}, " + "inner IP: {} -> {}, inner UDP: {} -> {}" )
  if 66 - 66: o0oOOo0O0Ooo + OoOoOO00 % OoooooooOO . I11i
  lprint ( IIIIIiI11Ii . format ( bold ( "ECM" , False ) , "S" if self . security else "s" ,
 "D" if self . ddt else "d" , "E" if self . to_etr else "e" ,
 "M" if self . to_ms else "m" ,
 green ( self . source . print_address ( ) , False ) ,
 green ( self . dest . print_address ( ) , False ) , self . udp_sport ,
 self . udp_dport ) )
  if 30 - 30: II111iiii - Oo0Ooo - i11iIiiIii + O0
 def encode ( self , packet , inner_source , inner_dest ) :
  self . udp_length = len ( packet ) + 8
  self . source = inner_source
  self . dest = inner_dest
  if ( inner_dest . is_ipv4 ( ) ) :
   self . afi = LISP_AFI_IPV4
   self . length = self . udp_length + 20
   if 93 - 93: i1IIi + I1Ii111 / OoO0O00 - I11i % Oo0Ooo / Ii1I
  if ( inner_dest . is_ipv6 ( ) ) :
   self . afi = LISP_AFI_IPV6
   self . length = self . udp_length
   if 1 - 1: Oo0Ooo / Ii1I . i11iIiiIii % OOooOOo + o0oOOo0O0Ooo + O0
   if 54 - 54: I1Ii111 + ooOoO0o % IiII
   if 83 - 83: o0oOOo0O0Ooo * iIii1I11I1II1
   if 36 - 36: OoOoOO00 + II111iiii - OoO0O00 % ooOoO0o * i1IIi
   if 4 - 4: Ii1I + OoO0O00 * I1ii11iIi11i
   if 13 - 13: OoOoOO00 - IiII * iIii1I11I1II1 * O0
  O0oooOO = ( LISP_ECM << 28 )
  if ( self . security ) : O0oooOO |= 0x08000000
  if ( self . ddt ) : O0oooOO |= 0x04000000
  if ( self . to_etr ) : O0oooOO |= 0x02000000
  if ( self . to_ms ) : O0oooOO |= 0x01000000
  if 26 - 26: OoooooooOO + oO0o + OoO0O00 . O0
  Ii1I111Ii = struct . pack ( "I" , socket . htonl ( O0oooOO ) )
  if 92 - 92: o0oOOo0O0Ooo * Ii1I / IiII % Oo0Ooo
  oOo00OoO0O = ""
  if ( self . afi == LISP_AFI_IPV4 ) :
   oOo00OoO0O = struct . pack ( "BBHHHBBH" , 0x45 , 0 , socket . htons ( self . length ) ,
 0 , 0 , self . ttl , self . protocol , socket . htons ( self . ip_checksum ) )
   oOo00OoO0O += self . source . pack_address ( )
   oOo00OoO0O += self . dest . pack_address ( )
   oOo00OoO0O = lisp_ip_checksum ( oOo00OoO0O )
   if 52 - 52: OoooooooOO + OoO0O00 * i1IIi / i11iIiiIii - I1Ii111
  if ( self . afi == LISP_AFI_IPV6 ) :
   oOo00OoO0O = struct . pack ( "BBHHBB" , 0x60 , 0 , 0 , socket . htons ( self . length ) ,
 self . protocol , self . ttl )
   oOo00OoO0O += self . source . pack_address ( )
   oOo00OoO0O += self . dest . pack_address ( )
   if 81 - 81: O0 % o0oOOo0O0Ooo / Ii1I / ooOoO0o . i11iIiiIii + IiII
   if 29 - 29: ooOoO0o
  o00oOOO = socket . htons ( self . udp_sport )
  i1 = socket . htons ( self . udp_dport )
  II1Ooo0000o00OO = socket . htons ( self . udp_length )
  iI1I1iII1iII = socket . htons ( self . udp_checksum )
  OOOOo00oo00O = struct . pack ( "HHHH" , o00oOOO , i1 , II1Ooo0000o00OO , iI1I1iII1iII )
  return ( Ii1I111Ii + oOo00OoO0O + OOOOo00oo00O )
  if 70 - 70: oO0o . O0 % I11i % IiII - I11i * I1ii11iIi11i
  if 22 - 22: i1IIi
 def decode ( self , packet ) :
  if 82 - 82: oO0o . iIii1I11I1II1 - I1ii11iIi11i
  if 55 - 55: Oo0Ooo % Ii1I . iIii1I11I1II1 * I1Ii111
  if 33 - 33: O0 - I1IiiI / I1ii11iIi11i / OoO0O00 + iII111i - oO0o
  if 27 - 27: I1Ii111 + ooOoO0o - I1Ii111 % i11iIiiIii * Oo0Ooo * o0oOOo0O0Ooo
  IIiI1I11ii1i = "I"
  i1II1i1iiI1 = struct . calcsize ( IIiI1I11ii1i )
  if ( len ( packet ) < i1II1i1iiI1 ) : return ( None )
  if 88 - 88: OOooOOo
  O0oooOO = struct . unpack ( IIiI1I11ii1i , packet [ : i1II1i1iiI1 ] )
  if 25 - 25: OoO0O00 + o0oOOo0O0Ooo . ooOoO0o - Ii1I . oO0o * Ii1I
  O0oooOO = socket . ntohl ( O0oooOO [ 0 ] )
  self . security = True if ( O0oooOO & 0x08000000 ) else False
  self . ddt = True if ( O0oooOO & 0x04000000 ) else False
  self . to_etr = True if ( O0oooOO & 0x02000000 ) else False
  self . to_ms = True if ( O0oooOO & 0x01000000 ) else False
  packet = packet [ i1II1i1iiI1 : : ]
  if 85 - 85: i1IIi
  if 94 - 94: OoooooooOO . O0 / OoooooooOO
  if 67 - 67: i11iIiiIii + OoOoOO00
  if 50 - 50: ooOoO0o . i1IIi + I1ii11iIi11i . OOooOOo
  if ( len ( packet ) < 1 ) : return ( None )
  oOOOO0 = struct . unpack ( "B" , packet [ 0 : 1 ] ) [ 0 ]
  oOOOO0 = oOOOO0 >> 4
  if 97 - 97: I1IiiI
  if ( oOOOO0 == 4 ) :
   i1II1i1iiI1 = struct . calcsize ( "HHIBBH" )
   if ( len ( packet ) < i1II1i1iiI1 ) : return ( None )
   if 63 - 63: O0 - OoOoOO00 / i11iIiiIii / OoooooooOO / ooOoO0o / II111iiii
   IiiIii1111Ii1I1 , II1Ooo0000o00OO , IiiIii1111Ii1I1 , O00o00oOOo , i111 , iI1I1iII1iII = struct . unpack ( "HHIBBH" , packet [ : i1II1i1iiI1 ] )
   self . length = socket . ntohs ( II1Ooo0000o00OO )
   self . ttl = O00o00oOOo
   self . protocol = i111
   self . ip_checksum = socket . ntohs ( iI1I1iII1iII )
   self . source . afi = self . dest . afi = LISP_AFI_IPV4
   if 39 - 39: iII111i . Oo0Ooo - I1IiiI . I11i % I1IiiI % iII111i
   if 27 - 27: OOooOOo - OOooOOo / i11iIiiIii * OoOoOO00 + O0
   if 2 - 2: i11iIiiIii % I1IiiI
   if 90 - 90: II111iiii
   i111 = struct . pack ( "H" , 0 )
   I1Ii1iiI1 = struct . calcsize ( "HHIBB" )
   OO = struct . calcsize ( "H" )
   packet = packet [ : I1Ii1iiI1 ] + i111 + packet [ I1Ii1iiI1 + OO : ]
   if 92 - 92: I1Ii111 + OOooOOo - OoO0O00 . o0oOOo0O0Ooo
   packet = packet [ i1II1i1iiI1 : : ]
   packet = self . source . unpack_address ( packet )
   if ( packet == None ) : return ( None )
   packet = self . dest . unpack_address ( packet )
   if ( packet == None ) : return ( None )
   if 16 - 16: I1IiiI - ooOoO0o
   if 39 - 39: i1IIi % i1IIi / iIii1I11I1II1 % OoooooooOO . ooOoO0o
  if ( oOOOO0 == 6 ) :
   i1II1i1iiI1 = struct . calcsize ( "IHBB" )
   if ( len ( packet ) < i1II1i1iiI1 ) : return ( None )
   if 30 - 30: o0oOOo0O0Ooo - Ii1I . i11iIiiIii + oO0o % ooOoO0o + I1ii11iIi11i
   IiiIii1111Ii1I1 , II1Ooo0000o00OO , i111 , O00o00oOOo = struct . unpack ( "IHBB" , packet [ : i1II1i1iiI1 ] )
   self . length = socket . ntohs ( II1Ooo0000o00OO )
   self . protocol = i111
   self . ttl = O00o00oOOo
   self . source . afi = self . dest . afi = LISP_AFI_IPV6
   if 5 - 5: OOooOOo . iII111i . oO0o % IiII * O0
   packet = packet [ i1II1i1iiI1 : : ]
   packet = self . source . unpack_address ( packet )
   if ( packet == None ) : return ( None )
   packet = self . dest . unpack_address ( packet )
   if ( packet == None ) : return ( None )
   if 20 - 20: Oo0Ooo . I1IiiI . I1IiiI / OoooooooOO . OoooooooOO + iIii1I11I1II1
   if 60 - 60: OoOoOO00 / ooOoO0o % iIii1I11I1II1
  self . source . mask_len = self . source . host_mask_len ( )
  self . dest . mask_len = self . dest . host_mask_len ( )
  if 32 - 32: i11iIiiIii + II111iiii + II111iiii % I11i
  i1II1i1iiI1 = struct . calcsize ( "HHHH" )
  if ( len ( packet ) < i1II1i1iiI1 ) : return ( None )
  if 96 - 96: o0oOOo0O0Ooo
  o00oOOO , i1 , II1Ooo0000o00OO , iI1I1iII1iII = struct . unpack ( "HHHH" , packet [ : i1II1i1iiI1 ] )
  self . udp_sport = socket . ntohs ( o00oOOO )
  self . udp_dport = socket . ntohs ( i1 )
  self . udp_length = socket . ntohs ( II1Ooo0000o00OO )
  self . udp_checksum = socket . ntohs ( iI1I1iII1iII )
  packet = packet [ i1II1i1iiI1 : : ]
  return ( packet )
  if 90 - 90: IiII * Ii1I . I11i / I1ii11iIi11i % I11i
  if 58 - 58: iII111i % iIii1I11I1II1 * OoO0O00
  if 25 - 25: I1Ii111 - ooOoO0o + Oo0Ooo . I1IiiI % iIii1I11I1II1
  if 49 - 49: i1IIi + OoO0O00 + iII111i / Oo0Ooo
  if 5 - 5: i11iIiiIii + I11i . IiII
  if 9 - 9: i11iIiiIii / iIii1I11I1II1 - I1ii11iIi11i * I1ii11iIi11i
  if 99 - 99: I11i
  if 64 - 64: iIii1I11I1II1
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
  if 34 - 34: O0 * OoO0O00 - oO0o - IiII * Ii1I . II111iiii
  if 28 - 28: O0 % iII111i - i1IIi
 def print_rloc_name ( self , cour = False ) :
  if ( self . rloc_name == None ) : return ( "" )
  i1OOO = self . rloc_name
  if ( cour ) : i1OOO = lisp_print_cour ( i1OOO )
  return ( 'rloc-name: {}' . format ( blue ( i1OOO , cour ) ) )
  if 100 - 100: i11iIiiIii % ooOoO0o . ooOoO0o - I1ii11iIi11i % Oo0Ooo - iII111i
  if 12 - 12: OoOoOO00 + I11i . OoO0O00 * i11iIiiIii * I11i * I1Ii111
 def print_record ( self , indent ) :
  ooOOo00o0ooO = self . print_rloc_name ( )
  if ( ooOOo00o0ooO != "" ) : ooOOo00o0ooO = ", " + ooOOo00o0ooO
  Ii1i11iIi1iII = ""
  if ( self . geo ) :
   i1i1Ii = ""
   if ( self . geo . geo_name ) : i1i1Ii = "'{}' " . format ( self . geo . geo_name )
   Ii1i11iIi1iII = ", geo: {}{}" . format ( i1i1Ii , self . geo . print_geo ( ) )
   if 64 - 64: II111iiii + i11iIiiIii
  iiiII1i11iII = ""
  if ( self . elp ) :
   i1i1Ii = ""
   if ( self . elp . elp_name ) : i1i1Ii = "'{}' " . format ( self . elp . elp_name )
   iiiII1i11iII = ", elp: {}{}" . format ( i1i1Ii , self . elp . print_elp ( True ) )
   if 13 - 13: Ii1I - Oo0Ooo
  oOOoo0O00 = ""
  if ( self . rle ) :
   i1i1Ii = ""
   if ( self . rle . rle_name ) : i1i1Ii = "'{}' " . format ( self . rle . rle_name )
   oOOoo0O00 = ", rle: {}{}" . format ( i1i1Ii , self . rle . print_rle ( False ) )
   if 30 - 30: i1IIi
  Oo00Oo0o000 = ""
  if ( self . json ) :
   i1i1Ii = ""
   if ( self . json . json_name ) :
    i1i1Ii = "'{}' " . format ( self . json . json_name )
    if 93 - 93: OoOoOO00 - OoooooooOO
   Oo00Oo0o000 = ", json: {}" . format ( self . json . print_json ( False ) )
   if 92 - 92: OoOoOO00 . i1IIi
   if 24 - 24: Oo0Ooo + I11i
  I1iii = ""
  if ( self . rloc . is_null ( ) == False and self . keys and self . keys [ 1 ] ) :
   I1iii = ", " + self . keys [ 1 ] . print_keys ( )
   if 79 - 79: I1ii11iIi11i - O0 / IiII
   if 1 - 1: I1IiiI
  IIIIIiI11Ii = ( "{}RLOC-record -> flags: {}, {}/{}/{}/{}, afi: {}, rloc: "
 + "{}{}{}{}{}{}{}" )
  lprint ( IIIIIiI11Ii . format ( indent , self . print_flags ( ) , self . priority ,
 self . weight , self . mpriority , self . mweight , self . rloc . afi ,
 red ( self . rloc . print_address_no_iid ( ) , False ) , ooOOo00o0ooO , Ii1i11iIi1iII ,
 iiiII1i11iII , oOOoo0O00 , Oo00Oo0o000 , I1iii ) )
  if 25 - 25: O0 + OOooOOo / iII111i
  if 51 - 51: I11i
 def print_flags ( self ) :
  return ( "{}{}{}" . format ( "L" if self . local_bit else "l" , "P" if self . probe_bit else "p" , "R" if self . reach_bit else "r" ) )
  if 54 - 54: i1IIi . O0 . i1IIi . OoO0O00 + I1Ii111 - i11iIiiIii
  if 80 - 80: OoOoOO00
  if 5 - 5: I1IiiI - I1IiiI / O0 + OOooOOo - i11iIiiIii
 def store_rloc_entry ( self , rloc_entry ) :
  Oo0o0o0oo = rloc_entry . rloc if ( rloc_entry . translated_rloc . is_null ( ) ) else rloc_entry . translated_rloc
  if 19 - 19: ooOoO0o
  self . rloc . copy_address ( Oo0o0o0oo )
  if 44 - 44: I1Ii111 - i11iIiiIii * I1IiiI
  if ( rloc_entry . rloc_name ) :
   self . rloc_name = rloc_entry . rloc_name
   if 84 - 84: O0 % Ii1I
   if 3 - 3: I1IiiI . I11i / I1ii11iIi11i
  if ( rloc_entry . geo ) :
   self . geo = rloc_entry . geo
  else :
   i1i1Ii = rloc_entry . geo_name
   if ( i1i1Ii and lisp_geo_list . has_key ( i1i1Ii ) ) :
    self . geo = lisp_geo_list [ i1i1Ii ]
    if 2 - 2: IiII + I11i / iIii1I11I1II1 . i11iIiiIii . i1IIi * ooOoO0o
    if 14 - 14: Oo0Ooo . O0 - oO0o - i11iIiiIii
  if ( rloc_entry . elp ) :
   self . elp = rloc_entry . elp
  else :
   i1i1Ii = rloc_entry . elp_name
   if ( i1i1Ii and lisp_elp_list . has_key ( i1i1Ii ) ) :
    self . elp = lisp_elp_list [ i1i1Ii ]
    if 8 - 8: I1IiiI / iIii1I11I1II1 / OoooooooOO / Oo0Ooo / ooOoO0o
    if 80 - 80: I11i
  if ( rloc_entry . rle ) :
   self . rle = rloc_entry . rle
  else :
   i1i1Ii = rloc_entry . rle_name
   if ( i1i1Ii and lisp_rle_list . has_key ( i1i1Ii ) ) :
    self . rle = lisp_rle_list [ i1i1Ii ]
    if 26 - 26: II111iiii + I1IiiI . II111iiii - oO0o % OoO0O00
    if 1 - 1: OoO0O00 - II111iiii
  if ( rloc_entry . json ) :
   self . json = rloc_entry . json
  else :
   i1i1Ii = rloc_entry . json_name
   if ( i1i1Ii and lisp_json_list . has_key ( i1i1Ii ) ) :
    self . json = lisp_json_list [ i1i1Ii ]
    if 75 - 75: Oo0Ooo - OoOoOO00 + oO0o % i1IIi * OOooOOo
    if 56 - 56: OoOoOO00 / OoO0O00 / I1IiiI % OoooooooOO
  self . priority = rloc_entry . priority
  self . weight = rloc_entry . weight
  self . mpriority = rloc_entry . mpriority
  self . mweight = rloc_entry . mweight
  if 39 - 39: I1IiiI + II111iiii * Oo0Ooo % Ii1I . o0oOOo0O0Ooo * oO0o
  if 42 - 42: Ii1I / Oo0Ooo
 def encode_lcaf ( self ) :
  ooOO0o0ooOo0 = socket . htons ( LISP_AFI_LCAF )
  Ii1111I11I = ""
  if ( self . geo ) :
   Ii1111I11I = self . geo . encode_geo ( )
   if 57 - 57: OoO0O00 % IiII % IiII - OoooooooOO % i1IIi
   if 92 - 92: I1Ii111 + iIii1I11I1II1 . OoooooooOO + oO0o + I1Ii111
  Ooo0oOOO = ""
  if ( self . elp ) :
   oOOoOOO000o = ""
   for IIi1IiIii1 in self . elp . elp_nodes :
    o0o0O00oOo = socket . htons ( IIi1IiIii1 . address . afi )
    I11I = 0
    if ( IIi1IiIii1 . eid ) : I11I |= 0x4
    if ( IIi1IiIii1 . probe ) : I11I |= 0x2
    if ( IIi1IiIii1 . strict ) : I11I |= 0x1
    I11I = socket . htons ( I11I )
    oOOoOOO000o += struct . pack ( "HH" , I11I , o0o0O00oOo )
    oOOoOOO000o += IIi1IiIii1 . address . pack_address ( )
    if 48 - 48: OoooooooOO + i11iIiiIii % O0
    if 54 - 54: I1ii11iIi11i + I1ii11iIi11i % iIii1I11I1II1
   O00 = socket . htons ( len ( oOOoOOO000o ) )
   Ooo0oOOO = struct . pack ( "HBBBBH" , ooOO0o0ooOo0 , 0 , 0 , LISP_LCAF_ELP_TYPE ,
 0 , O00 )
   Ooo0oOOO += oOOoOOO000o
   if 40 - 40: Ii1I % OoO0O00
   if 19 - 19: I11i * oO0o * I11i + I1IiiI
  Iii1 = ""
  if ( self . rle ) :
   OoOOOO0oO0Oo = ""
   for I1I1iiI in self . rle . rle_nodes :
    o0o0O00oOo = socket . htons ( I1I1iiI . address . afi )
    OoOOOO0oO0Oo += struct . pack ( "HBBH" , 0 , 0 , I1I1iiI . level , o0o0O00oOo )
    OoOOOO0oO0Oo += I1I1iiI . address . pack_address ( )
    if ( I1I1iiI . rloc_name ) :
     OoOOOO0oO0Oo += struct . pack ( "H" , socket . htons ( LISP_AFI_NAME ) )
     OoOOOO0oO0Oo += I1I1iiI . rloc_name + "\0"
     if 4 - 4: I1IiiI . i11iIiiIii % I11i + II111iiii - Ii1I - O0
     if 23 - 23: OoOoOO00 / OOooOOo
     if 84 - 84: OOooOOo / iIii1I11I1II1 - I1ii11iIi11i . Ii1I
   I1IiiiIiiiIII = socket . htons ( len ( OoOOOO0oO0Oo ) )
   Iii1 = struct . pack ( "HBBBBH" , ooOO0o0ooOo0 , 0 , 0 , LISP_LCAF_RLE_TYPE ,
 0 , I1IiiiIiiiIII )
   Iii1 += OoOOOO0oO0Oo
   if 78 - 78: I1IiiI
   if 90 - 90: I1Ii111
  I11IIi11Iii1 = ""
  if ( self . json ) :
   i11iii11 = socket . htons ( len ( self . json . json_string ) + 2 )
   I11111i = socket . htons ( len ( self . json . json_string ) )
   I11IIi11Iii1 = struct . pack ( "HBBBBHH" , ooOO0o0ooOo0 , 0 , 0 , LISP_LCAF_JSON_TYPE ,
 0 , i11iii11 , I11111i )
   I11IIi11Iii1 += self . json . json_string
   I11IIi11Iii1 += struct . pack ( "H" , 0 )
   if 77 - 77: I1Ii111 * I1IiiI
   if 27 - 27: O0
  iIo0o0Oo0o0oOo = ""
  if ( self . rloc . is_null ( ) == False and self . keys and self . keys [ 1 ] ) :
   iIo0o0Oo0o0oOo = self . keys [ 1 ] . encode_lcaf ( self . rloc )
   if 14 - 14: I1IiiI - i11iIiiIii * I1Ii111 . i11iIiiIii % ooOoO0o
   if 53 - 53: O0 . o0oOOo0O0Ooo . II111iiii * OoOoOO00 . OOooOOo
  OOOOoOOo0o0OO = ""
  if ( self . rloc_name ) :
   OOOOoOOo0o0OO += struct . pack ( "H" , socket . htons ( LISP_AFI_NAME ) )
   OOOOoOOo0o0OO += self . rloc_name + "\0"
   if 12 - 12: I1ii11iIi11i . i1IIi / I1IiiI . O0 * I1Ii111 / i1IIi
   if 6 - 6: OOooOOo + OoO0O00 + I1IiiI / OoooooooOO
  IiiiII1 = len ( Ii1111I11I ) + len ( Ooo0oOOO ) + len ( Iii1 ) + len ( iIo0o0Oo0o0oOo ) + 2 + len ( I11IIi11Iii1 ) + self . rloc . addr_length ( ) + len ( OOOOoOOo0o0OO )
  if 94 - 94: I11i - o0oOOo0O0Ooo / I1Ii111
  IiiiII1 = socket . htons ( IiiiII1 )
  I1I1ii11 = struct . pack ( "HBBBBHH" , ooOO0o0ooOo0 , 0 , 0 , LISP_LCAF_AFI_LIST_TYPE ,
 0 , IiiiII1 , socket . htons ( self . rloc . afi ) )
  I1I1ii11 += self . rloc . pack_address ( )
  return ( I1I1ii11 + OOOOoOOo0o0OO + Ii1111I11I + Ooo0oOOO + Iii1 + iIo0o0Oo0o0oOo + I11IIi11Iii1 )
  if 35 - 35: I1Ii111 * Oo0Ooo / o0oOOo0O0Ooo
  if 89 - 89: oO0o / OoooooooOO . Ii1I + Oo0Ooo + IiII / OoOoOO00
 def encode ( self ) :
  I11I = 0
  if ( self . local_bit ) : I11I |= 0x0004
  if ( self . probe_bit ) : I11I |= 0x0002
  if ( self . reach_bit ) : I11I |= 0x0001
  if 67 - 67: IiII
  oOo = struct . pack ( "BBBBHH" , self . priority , self . weight ,
 self . mpriority , self . mweight , socket . htons ( I11I ) ,
 socket . htons ( self . rloc . afi ) )
  if 66 - 66: i11iIiiIii * iII111i
  if ( self . geo or self . elp or self . rle or self . keys or self . rloc_name or self . json ) :
   if 51 - 51: OoooooooOO + I11i . iII111i + i11iIiiIii * iII111i - OoO0O00
   oOo = oOo [ 0 : - 2 ] + self . encode_lcaf ( )
  else :
   oOo += self . rloc . pack_address ( )
   if 60 - 60: iII111i * iIii1I11I1II1 . OoOoOO00 . o0oOOo0O0Ooo / iIii1I11I1II1
  return ( oOo )
  if 36 - 36: i1IIi . OoooooooOO - II111iiii - OoOoOO00 - IiII
  if 53 - 53: I1ii11iIi11i - II111iiii . i11iIiiIii
 def decode_lcaf ( self , packet , nonce ) :
  IIiI1I11ii1i = "HBBBBH"
  i1II1i1iiI1 = struct . calcsize ( IIiI1I11ii1i )
  if ( len ( packet ) < i1II1i1iiI1 ) : return ( None )
  if 76 - 76: iIii1I11I1II1 - Oo0Ooo
  o0o0O00oOo , OoO0oOoo , I11I , o0O00o0o , ii11iIII111 , i11iii11 = struct . unpack ( IIiI1I11ii1i , packet [ : i1II1i1iiI1 ] )
  if 79 - 79: I1IiiI * IiII . OoooooooOO % I1Ii111 * I1Ii111
  if 17 - 17: I1Ii111 - I1Ii111 . oO0o / I1Ii111
  i11iii11 = socket . ntohs ( i11iii11 )
  packet = packet [ i1II1i1iiI1 : : ]
  if ( i11iii11 > len ( packet ) ) : return ( None )
  if 36 - 36: I1ii11iIi11i * i1IIi + iIii1I11I1II1
  if 55 - 55: I1IiiI . I1Ii111 - I1IiiI % oO0o / iIii1I11I1II1 * Ii1I
  if 77 - 77: OOooOOo
  if 29 - 29: II111iiii % iIii1I11I1II1 * O0 . o0oOOo0O0Ooo
  if ( o0O00o0o == LISP_LCAF_AFI_LIST_TYPE ) :
   while ( i11iii11 > 0 ) :
    IIiI1I11ii1i = "H"
    i1II1i1iiI1 = struct . calcsize ( IIiI1I11ii1i )
    if ( i11iii11 < i1II1i1iiI1 ) : return ( None )
    if 56 - 56: i1IIi . ooOoO0o + I11i - i11iIiiIii
    IIi1IiiIi1III = len ( packet )
    o0o0O00oOo = struct . unpack ( IIiI1I11ii1i , packet [ : i1II1i1iiI1 ] ) [ 0 ]
    o0o0O00oOo = socket . ntohs ( o0o0O00oOo )
    if 100 - 100: iIii1I11I1II1 - i1IIi . OOooOOo
    if ( o0o0O00oOo == LISP_AFI_LCAF ) :
     packet = self . decode_lcaf ( packet , nonce )
     if ( packet == None ) : return ( None )
    else :
     packet = packet [ i1II1i1iiI1 : : ]
     self . rloc_name = None
     if ( o0o0O00oOo == LISP_AFI_NAME ) :
      packet , i1OOO = lisp_decode_dist_name ( packet )
      self . rloc_name = i1OOO
     else :
      self . rloc . afi = o0o0O00oOo
      packet = self . rloc . unpack_address ( packet )
      if ( packet == None ) : return ( None )
      self . rloc . mask_len = self . rloc . host_mask_len ( )
      if 73 - 73: I1Ii111 / I11i / i11iIiiIii - I1ii11iIi11i % ooOoO0o
      if 92 - 92: I1IiiI - o0oOOo0O0Ooo % I1ii11iIi11i / iII111i % oO0o
      if 43 - 43: Oo0Ooo % oO0o . i11iIiiIii - O0
    i11iii11 -= IIi1IiiIi1III - len ( packet )
    if 5 - 5: i1IIi + Ii1I
    if 38 - 38: I1IiiI . O0 + OOooOOo / I1ii11iIi11i . iIii1I11I1II1 - i1IIi
  elif ( o0O00o0o == LISP_LCAF_GEO_COORD_TYPE ) :
   if 3 - 3: Oo0Ooo + oO0o
   if 65 - 65: I1IiiI / OoOoOO00 % I1IiiI * i11iIiiIii * OoooooooOO / I11i
   if 91 - 91: i11iIiiIii / i11iIiiIii
   if 9 - 9: I11i / I1Ii111 + iIii1I11I1II1 + I1IiiI - II111iiii
   O0OOoo = lisp_geo ( "" )
   packet = O0OOoo . decode_geo ( packet , i11iii11 , ii11iIII111 )
   if ( packet == None ) : return ( None )
   self . geo = O0OOoo
   if 46 - 46: i1IIi % iIii1I11I1II1
  elif ( o0O00o0o == LISP_LCAF_JSON_TYPE ) :
   if 80 - 80: OoooooooOO / O0 / I1Ii111 - Oo0Ooo . i11iIiiIii
   if 3 - 3: Oo0Ooo - OOooOOo * OoO0O00 - II111iiii . OoooooooOO
   if 14 - 14: I1IiiI
   if 41 - 41: I1Ii111 % i1IIi + OoO0O00 / oO0o
   IIiI1I11ii1i = "H"
   i1II1i1iiI1 = struct . calcsize ( IIiI1I11ii1i )
   if ( i11iii11 < i1II1i1iiI1 ) : return ( None )
   if 48 - 48: i1IIi . Oo0Ooo . i1IIi . I1ii11iIi11i * I1IiiI - Ii1I
   I11111i = struct . unpack ( IIiI1I11ii1i , packet [ : i1II1i1iiI1 ] ) [ 0 ]
   I11111i = socket . ntohs ( I11111i )
   if ( i11iii11 < i1II1i1iiI1 + I11111i ) : return ( None )
   if 83 - 83: OoooooooOO
   packet = packet [ i1II1i1iiI1 : : ]
   self . json = lisp_json ( "" , packet [ 0 : I11111i ] )
   packet = packet [ I11111i : : ]
   if 42 - 42: I1ii11iIi11i . i1IIi - OoOoOO00 - oO0o + i11iIiiIii
  elif ( o0O00o0o == LISP_LCAF_ELP_TYPE ) :
   if 65 - 65: I1IiiI - O0
   if 15 - 15: I11i + OoOoOO00 / Oo0Ooo - I1IiiI * I1ii11iIi11i % oO0o
   if 90 - 90: Ii1I / I11i
   if 98 - 98: i1IIi
   O0Oooo0 = lisp_elp ( None )
   O0Oooo0 . elp_nodes = [ ]
   while ( i11iii11 > 0 ) :
    I11I , o0o0O00oOo = struct . unpack ( "HH" , packet [ : 4 ] )
    if 84 - 84: iIii1I11I1II1 % Ii1I / OoooooooOO
    o0o0O00oOo = socket . ntohs ( o0o0O00oOo )
    if ( o0o0O00oOo == LISP_AFI_LCAF ) : return ( None )
    if 62 - 62: OOooOOo * OoO0O00 * OoO0O00 + OoooooooOO . IiII + OoO0O00
    IIi1IiIii1 = lisp_elp_node ( )
    O0Oooo0 . elp_nodes . append ( IIi1IiIii1 )
    if 13 - 13: O0 . I1IiiI % OoO0O00 - I11i . O0
    I11I = socket . ntohs ( I11I )
    IIi1IiIii1 . eid = ( I11I & 0x4 )
    IIi1IiIii1 . probe = ( I11I & 0x2 )
    IIi1IiIii1 . strict = ( I11I & 0x1 )
    IIi1IiIii1 . address . afi = o0o0O00oOo
    IIi1IiIii1 . address . mask_len = IIi1IiIii1 . address . host_mask_len ( )
    packet = IIi1IiIii1 . address . unpack_address ( packet [ 4 : : ] )
    i11iii11 -= IIi1IiIii1 . address . addr_length ( ) + 4
    if 14 - 14: iIii1I11I1II1
   O0Oooo0 . select_elp_node ( )
   self . elp = O0Oooo0
   if 48 - 48: i11iIiiIii * OoOoOO00 - I1IiiI + iIii1I11I1II1
  elif ( o0O00o0o == LISP_LCAF_RLE_TYPE ) :
   if 20 - 20: I1ii11iIi11i - iIii1I11I1II1 . iII111i
   if 52 - 52: OoO0O00 - I1Ii111
   if 9 - 9: I1IiiI . i11iIiiIii
   if 3 - 3: I1IiiI + I1ii11iIi11i * I1Ii111 - i1IIi . OOooOOo
   II1IIiiI1 = lisp_rle ( None )
   II1IIiiI1 . rle_nodes = [ ]
   while ( i11iii11 > 0 ) :
    IiiIii1111Ii1I1 , iIIIIi , IiIi1II1Ii , o0o0O00oOo = struct . unpack ( "HBBH" , packet [ : 6 ] )
    if 53 - 53: O0
    o0o0O00oOo = socket . ntohs ( o0o0O00oOo )
    if ( o0o0O00oOo == LISP_AFI_LCAF ) : return ( None )
    if 28 - 28: iII111i % OoO0O00 . OoO0O00 / IiII * Oo0Ooo * iII111i
    I1I1iiI = lisp_rle_node ( )
    II1IIiiI1 . rle_nodes . append ( I1I1iiI )
    if 49 - 49: I1IiiI / I1Ii111 * iII111i + I1IiiI % oO0o % ooOoO0o
    I1I1iiI . level = IiIi1II1Ii
    I1I1iiI . address . afi = o0o0O00oOo
    I1I1iiI . address . mask_len = I1I1iiI . address . host_mask_len ( )
    packet = I1I1iiI . address . unpack_address ( packet [ 6 : : ] )
    if 27 - 27: OoO0O00 / iII111i . I1ii11iIi11i
    i11iii11 -= I1I1iiI . address . addr_length ( ) + 6
    if ( i11iii11 >= 2 ) :
     o0o0O00oOo = struct . unpack ( "H" , packet [ : 2 ] ) [ 0 ]
     if ( socket . ntohs ( o0o0O00oOo ) == LISP_AFI_NAME ) :
      packet = packet [ 2 : : ]
      packet , I1I1iiI . rloc_name = lisp_decode_dist_name ( packet )
      if 71 - 71: OoO0O00 . i11iIiiIii . iIii1I11I1II1 + I1IiiI - o0oOOo0O0Ooo
      if ( packet == None ) : return ( None )
      i11iii11 -= len ( I1I1iiI . rloc_name ) + 1 + 2
      if 34 - 34: iII111i
      if 6 - 6: OoO0O00 . OoOoOO00 + I1ii11iIi11i
      if 24 - 24: OoO0O00 . Ii1I
   self . rle = II1IIiiI1
   self . rle . build_forwarding_list ( )
   if 26 - 26: O0 * I1IiiI - OOooOOo * OoooooooOO * II111iiii % OoOoOO00
  elif ( o0O00o0o == LISP_LCAF_SECURITY_TYPE ) :
   if 56 - 56: OOooOOo * i11iIiiIii % ooOoO0o * OoOoOO00 % Oo0Ooo * IiII
   if 30 - 30: i1IIi + o0oOOo0O0Ooo - OoOoOO00 . OOooOOo
   if 95 - 95: i1IIi . I11i + O0 . I11i - I11i / Oo0Ooo
   if 41 - 41: OoooooooOO . OOooOOo - Ii1I * OoO0O00 % i11iIiiIii
   if 7 - 7: Ii1I
   oOO = packet
   i1II1Ii = lisp_keys ( 1 )
   packet = i1II1Ii . decode_lcaf ( oOO , i11iii11 )
   if ( packet == None ) : return ( None )
   if 16 - 16: IiII * o0oOOo0O0Ooo % II111iiii - II111iiii + ooOoO0o
   if 55 - 55: OoO0O00 % OoOoOO00
   if 58 - 58: Ii1I
   if 17 - 17: OoO0O00 - oO0o % Oo0Ooo % oO0o * I1Ii111 / IiII
   iii1IiI = [ LISP_CS_25519_CBC , LISP_CS_25519_CHACHA ]
   if ( i1II1Ii . cipher_suite in iii1IiI ) :
    if ( i1II1Ii . cipher_suite == LISP_CS_25519_CBC ) :
     Iiii11 = lisp_keys ( 1 , do_poly = False , do_chacha = False )
     if 88 - 88: ooOoO0o . II111iiii * O0 % IiII
    if ( i1II1Ii . cipher_suite == LISP_CS_25519_CHACHA ) :
     Iiii11 = lisp_keys ( 1 , do_poly = True , do_chacha = True )
     if 15 - 15: O0 % i1IIi - OOooOOo . IiII
   else :
    Iiii11 = lisp_keys ( 1 , do_poly = False , do_chacha = False )
    if 1 - 1: I1IiiI
   packet = Iiii11 . decode_lcaf ( oOO , i11iii11 )
   if ( packet == None ) : return ( None )
   if 40 - 40: o0oOOo0O0Ooo % I11i % O0
   if ( len ( packet ) < 2 ) : return ( None )
   o0o0O00oOo = struct . unpack ( "H" , packet [ : 2 ] ) [ 0 ]
   self . rloc . afi = socket . ntohs ( o0o0O00oOo )
   if ( len ( packet ) < self . rloc . addr_length ( ) ) : return ( None )
   packet = self . rloc . unpack_address ( packet [ 2 : : ] )
   if ( packet == None ) : return ( None )
   self . rloc . mask_len = self . rloc . host_mask_len ( )
   if 88 - 88: o0oOOo0O0Ooo - oO0o
   if 73 - 73: II111iiii
   if 7 - 7: O0 / OoO0O00
   if 90 - 90: iII111i % oO0o / iIii1I11I1II1
   if 52 - 52: I1IiiI / o0oOOo0O0Ooo
   if 20 - 20: I1Ii111 . I1IiiI - iIii1I11I1II1 / iII111i
   if ( self . rloc . is_null ( ) ) : return ( packet )
   if 46 - 46: I1Ii111 . i11iIiiIii
   OOO0Oo0Oo = self . rloc_name
   if ( OOO0Oo0Oo ) : OOO0Oo0Oo = blue ( self . rloc_name , False )
   if 52 - 52: o0oOOo0O0Ooo * O0 + I1ii11iIi11i
   if 83 - 83: I11i + OOooOOo - OoooooooOO
   if 7 - 7: IiII % ooOoO0o / OoooooooOO / o0oOOo0O0Ooo + OoO0O00 - OoO0O00
   if 15 - 15: i1IIi + OOooOOo / Ii1I
   if 51 - 51: OOooOOo + O0
   if 91 - 91: i11iIiiIii + o0oOOo0O0Ooo % OoO0O00 / oO0o - i1IIi
   iiiiI = self . keys [ 1 ] if self . keys else None
   if ( iiiiI == None ) :
    if ( Iiii11 . remote_public_key == None ) :
     O0I11IIIII = bold ( "No remote encap-public-key supplied" , False )
     lprint ( "    {} for {}" . format ( O0I11IIIII , OOO0Oo0Oo ) )
     Iiii11 = None
    else :
     O0I11IIIII = bold ( "New encap-keying with new state" , False )
     lprint ( "    {} for {}" . format ( O0I11IIIII , OOO0Oo0Oo ) )
     Iiii11 . compute_shared_key ( "encap" )
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
   if ( iiiiI ) :
    if ( Iiii11 . remote_public_key == None ) :
     Iiii11 = None
     IIiI = bold ( "Remote encap-unkeying occurred" , False )
     lprint ( "    {} for {}" . format ( IIiI , OOO0Oo0Oo ) )
    elif ( iiiiI . compare_keys ( Iiii11 ) ) :
     Iiii11 = iiiiI
     lprint ( "    Maintain stored encap-keys for {}" . format ( OOO0Oo0Oo ) )
     if 29 - 29: OOooOOo
    else :
     if ( iiiiI . remote_public_key == None ) :
      O0I11IIIII = "New encap-keying for existing state"
     else :
      O0I11IIIII = "Remote encap-rekeying"
      if 69 - 69: oO0o % OoooooooOO * iII111i
     lprint ( "    {} for {}" . format ( bold ( O0I11IIIII , False ) ,
 OOO0Oo0Oo ) )
     iiiiI . remote_public_key = Iiii11 . remote_public_key
     iiiiI . compute_shared_key ( "encap" )
     Iiii11 = iiiiI
     if 58 - 58: oO0o / i11iIiiIii . OoOoOO00 % O0 / iIii1I11I1II1
     if 50 - 50: I1Ii111 . I11i / O0 . I11i
   self . keys = [ None , Iiii11 , None , None ]
   if 91 - 91: i11iIiiIii . I1ii11iIi11i + I11i
  else :
   if 67 - 67: I1ii11iIi11i * I1Ii111 * I1IiiI / I11i - IiII + oO0o
   if 11 - 11: O0 + i1IIi / o0oOOo0O0Ooo * OoO0O00
   if 64 - 64: i1IIi % IiII . ooOoO0o . iIii1I11I1II1 + OoO0O00 - iIii1I11I1II1
   if 52 - 52: II111iiii - IiII
   packet = packet [ i11iii11 : : ]
   if 91 - 91: iIii1I11I1II1 + iII111i . I11i % i11iIiiIii - i11iIiiIii + I1IiiI
  return ( packet )
  if 75 - 75: I1ii11iIi11i / I1IiiI - iIii1I11I1II1 / OoO0O00 * OOooOOo
  if 73 - 73: OoooooooOO % IiII / I1Ii111 * I11i + i1IIi % i11iIiiIii
 def decode ( self , packet , nonce ) :
  IIiI1I11ii1i = "BBBBHH"
  i1II1i1iiI1 = struct . calcsize ( IIiI1I11ii1i )
  if ( len ( packet ) < i1II1i1iiI1 ) : return ( None )
  if 91 - 91: i11iIiiIii
  self . priority , self . weight , self . mpriority , self . mweight , I11I , o0o0O00oOo = struct . unpack ( IIiI1I11ii1i , packet [ : i1II1i1iiI1 ] )
  if 6 - 6: O0 - iIii1I11I1II1 + I1Ii111 . o0oOOo0O0Ooo * i11iIiiIii
  if 53 - 53: OOooOOo / I1IiiI / oO0o * OOooOOo / i1IIi - I1Ii111
  I11I = socket . ntohs ( I11I )
  o0o0O00oOo = socket . ntohs ( o0o0O00oOo )
  self . local_bit = True if ( I11I & 0x0004 ) else False
  self . probe_bit = True if ( I11I & 0x0002 ) else False
  self . reach_bit = True if ( I11I & 0x0001 ) else False
  if 71 - 71: O0 + Oo0Ooo % oO0o - o0oOOo0O0Ooo
  if ( o0o0O00oOo == LISP_AFI_LCAF ) :
   packet = packet [ i1II1i1iiI1 - 2 : : ]
   packet = self . decode_lcaf ( packet , nonce )
  else :
   self . rloc . afi = o0o0O00oOo
   packet = packet [ i1II1i1iiI1 : : ]
   packet = self . rloc . unpack_address ( packet )
   if 82 - 82: iIii1I11I1II1
  self . rloc . mask_len = self . rloc . host_mask_len ( )
  return ( packet )
  if 64 - 64: ooOoO0o + I1IiiI % OOooOOo + II111iiii
  if 46 - 46: I1IiiI
 def end_of_rlocs ( self , packet , rloc_count ) :
  for II11iIII1i1I in range ( rloc_count ) :
   packet = self . decode ( packet , None )
   if ( packet == None ) : return ( None )
   if 72 - 72: iII111i
  return ( packet )
  if 100 - 100: I1IiiI
  if 55 - 55: i1IIi % IiII
  if 44 - 44: oO0o - iIii1I11I1II1 / ooOoO0o - iIii1I11I1II1 % i1IIi + ooOoO0o
  if 74 - 74: I11i . OoOoOO00 + OoOoOO00
  if 87 - 87: IiII + o0oOOo0O0Ooo . i1IIi % I1Ii111
  if 44 - 44: Oo0Ooo - OOooOOo . Ii1I * OoooooooOO
  if 93 - 93: OoO0O00 . OoO0O00
  if 52 - 52: OOooOOo . oO0o / Oo0Ooo . OoooooooOO % I1ii11iIi11i
  if 65 - 65: ooOoO0o % II111iiii . iII111i - iIii1I11I1II1 - I1IiiI
  if 63 - 63: I1IiiI . OoOoOO00 - II111iiii
  if 55 - 55: ooOoO0o - o0oOOo0O0Ooo
  if 32 - 32: I1Ii111 * Ii1I / I1Ii111 . OoOoOO00 + I1ii11iIi11i - ooOoO0o
  if 14 - 14: IiII * O0 + O0 - ooOoO0o . i11iIiiIii - IiII
  if 37 - 37: I11i
  if 19 - 19: OoooooooOO % I1Ii111
  if 57 - 57: OoOoOO00 + i1IIi . iIii1I11I1II1 . iIii1I11I1II1 / iIii1I11I1II1 % oO0o
  if 7 - 7: i11iIiiIii * I1ii11iIi11i / OoO0O00 * oO0o
  if 35 - 35: IiII . i1IIi + I1ii11iIi11i . IiII + ooOoO0o . oO0o
  if 2 - 2: II111iiii
  if 18 - 18: iIii1I11I1II1 % I1ii11iIi11i % Oo0Ooo
  if 47 - 47: ooOoO0o - I1IiiI % OOooOOo * Ii1I % I1IiiI
  if 95 - 95: OoO0O00 + OoOoOO00 % Oo0Ooo . Ii1I * I1IiiI + I1Ii111
  if 22 - 22: Oo0Ooo . OoO0O00
  if 55 - 55: Oo0Ooo % OoooooooOO * II111iiii % OoooooooOO
  if 30 - 30: I1Ii111 / o0oOOo0O0Ooo + OoooooooOO + OoOoOO00 + OoO0O00
  if 40 - 40: OoooooooOO / IiII
  if 82 - 82: i11iIiiIii - oO0o - i1IIi
  if 78 - 78: oO0o % iII111i / i1IIi / ooOoO0o
  if 44 - 44: o0oOOo0O0Ooo + Ii1I + I1IiiI % O0
  if 100 - 100: OoooooooOO
class lisp_map_referral ( ) :
 def __init__ ( self ) :
  self . record_count = 0
  self . nonce = 0
  if 27 - 27: i11iIiiIii % II111iiii + I1Ii111
  if 76 - 76: OOooOOo - I1Ii111 + iIii1I11I1II1 + I1IiiI * oO0o
 def print_map_referral ( self ) :
  lprint ( "{} -> record-count: {}, nonce: 0x{}" . format ( bold ( "Map-Referral" , False ) , self . record_count ,
  # ooOoO0o % I1ii11iIi11i . OoO0O00 . ooOoO0o + i11iIiiIii . iIii1I11I1II1
 lisp_hex_string ( self . nonce ) ) )
  if 70 - 70: ooOoO0o
  if 3 - 3: I1IiiI - I1IiiI
 def encode ( self ) :
  O0oooOO = ( LISP_MAP_REFERRAL << 28 ) | self . record_count
  oOo = struct . pack ( "I" , socket . htonl ( O0oooOO ) )
  oOo += struct . pack ( "Q" , self . nonce )
  return ( oOo )
  if 89 - 89: OoOoOO00
  if 27 - 27: i1IIi % OoOoOO00 / Ii1I * Ii1I / I11i
 def decode ( self , packet ) :
  IIiI1I11ii1i = "I"
  i1II1i1iiI1 = struct . calcsize ( IIiI1I11ii1i )
  if ( len ( packet ) < i1II1i1iiI1 ) : return ( None )
  if 11 - 11: OOooOOo
  O0oooOO = struct . unpack ( IIiI1I11ii1i , packet [ : i1II1i1iiI1 ] )
  O0oooOO = socket . ntohl ( O0oooOO [ 0 ] )
  self . record_count = O0oooOO & 0xff
  packet = packet [ i1II1i1iiI1 : : ]
  if 58 - 58: OoO0O00 * OoooooooOO
  IIiI1I11ii1i = "Q"
  i1II1i1iiI1 = struct . calcsize ( IIiI1I11ii1i )
  if ( len ( packet ) < i1II1i1iiI1 ) : return ( None )
  if 47 - 47: iII111i - Oo0Ooo
  self . nonce = struct . unpack ( IIiI1I11ii1i , packet [ : i1II1i1iiI1 ] ) [ 0 ]
  packet = packet [ i1II1i1iiI1 : : ]
  return ( packet )
  if 19 - 19: O0 . i1IIi + I11i / II111iiii + ooOoO0o
  if 26 - 26: Ii1I * oO0o % I1IiiI - OOooOOo . I1Ii111
  if 35 - 35: i1IIi % i11iIiiIii + Ii1I
  if 14 - 14: OoO0O00 * OoooooooOO
  if 45 - 45: iIii1I11I1II1 * I1IiiI . OoOoOO00
  if 97 - 97: I11i % II111iiii % Ii1I . II111iiii . iIii1I11I1II1
  if 98 - 98: i11iIiiIii + O0 - O0 - iII111i
  if 25 - 25: oO0o / O0 + I1Ii111 % i11iIiiIii / I1IiiI
class lisp_ddt_entry ( ) :
 def __init__ ( self ) :
  self . eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . group = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . uptime = lisp_get_timestamp ( )
  self . delegation_set = [ ]
  self . source_cache = None
  self . map_referrals_sent = 0
  if 62 - 62: iII111i . I11i * i1IIi + iII111i
  if 95 - 95: Ii1I / o0oOOo0O0Ooo % ooOoO0o - I1IiiI / OOooOOo * OOooOOo
 def is_auth_prefix ( self ) :
  if ( len ( self . delegation_set ) != 0 ) : return ( False )
  if ( self . is_star_g ( ) ) : return ( False )
  return ( True )
  if 6 - 6: OoO0O00 % IiII + iIii1I11I1II1
  if 18 - 18: II111iiii . Ii1I + OoOoOO00 + O0 - I11i
 def is_ms_peer_entry ( self ) :
  if ( len ( self . delegation_set ) == 0 ) : return ( False )
  return ( self . delegation_set [ 0 ] . is_ms_peer ( ) )
  if 30 - 30: II111iiii
  if 26 - 26: I11i - i1IIi - Oo0Ooo * O0 * OOooOOo . OoooooooOO
 def print_referral_type ( self ) :
  if ( len ( self . delegation_set ) == 0 ) : return ( "unknown" )
  oOoI1I = self . delegation_set [ 0 ]
  return ( oOoI1I . print_node_type ( ) )
  if 13 - 13: iII111i * i1IIi * iIii1I11I1II1 . OOooOOo + O0 . o0oOOo0O0Ooo
  if 23 - 23: I1ii11iIi11i . I1ii11iIi11i / I1IiiI . i1IIi
 def print_eid_tuple ( self ) :
  return ( lisp_print_eid_tuple ( self . eid , self . group ) )
  if 47 - 47: i11iIiiIii . o0oOOo0O0Ooo . i11iIiiIii + I1IiiI - I1ii11iIi11i
  if 62 - 62: OoooooooOO + I1IiiI / ooOoO0o . Ii1I . Oo0Ooo
 def add_cache ( self ) :
  if ( self . group . is_null ( ) ) :
   lisp_ddt_cache . add_cache ( self . eid , self )
  else :
   oO00oOo = lisp_ddt_cache . lookup_cache ( self . group , True )
   if ( oO00oOo == None ) :
    oO00oOo = lisp_ddt_entry ( )
    oO00oOo . eid . copy_address ( self . group )
    oO00oOo . group . copy_address ( self . group )
    lisp_ddt_cache . add_cache ( self . group , oO00oOo )
    if 60 - 60: Oo0Ooo + Ii1I / oO0o / I11i
   if ( self . eid . is_null ( ) ) : self . eid . make_default_route ( oO00oOo . group )
   oO00oOo . add_source_entry ( self )
   if 21 - 21: OOooOOo % O0 / I11i
   if 15 - 15: O0 - i1IIi . iIii1I11I1II1 - i11iIiiIii / Ii1I
   if 11 - 11: iIii1I11I1II1 + I1IiiI
 def add_source_entry ( self , source_ddt ) :
  if ( self . source_cache == None ) : self . source_cache = lisp_cache ( )
  self . source_cache . add_cache ( source_ddt . eid , source_ddt )
  if 15 - 15: o0oOOo0O0Ooo
  if 55 - 55: i11iIiiIii / OoooooooOO - I11i
 def lookup_source_cache ( self , source , exact ) :
  if ( self . source_cache == None ) : return ( None )
  return ( self . source_cache . lookup_cache ( source , exact ) )
  if 89 - 89: I11i - i1IIi - i1IIi * OOooOOo - O0
  if 94 - 94: Oo0Ooo / I11i . I1ii11iIi11i
 def is_star_g ( self ) :
  if ( self . group . is_null ( ) ) : return ( False )
  return ( self . eid . is_exact_match ( self . group ) )
  if 31 - 31: i11iIiiIii + iIii1I11I1II1 . II111iiii
  if 72 - 72: I1Ii111 * OoO0O00 + Oo0Ooo / Ii1I % OOooOOo
  if 84 - 84: OoOoOO00 / o0oOOo0O0Ooo
class lisp_ddt_node ( ) :
 def __init__ ( self ) :
  self . delegate_address = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . public_key = ""
  self . map_server_peer = False
  self . map_server_child = False
  self . priority = 0
  self . weight = 0
  if 9 - 9: Ii1I
  if 76 - 76: I1IiiI % Oo0Ooo / iIii1I11I1II1 - Oo0Ooo
 def print_node_type ( self ) :
  if ( self . is_ddt_child ( ) ) : return ( "ddt-child" )
  if ( self . is_ms_child ( ) ) : return ( "map-server-child" )
  if ( self . is_ms_peer ( ) ) : return ( "map-server-peer" )
  if 34 - 34: OoOoOO00 - i1IIi + OOooOOo + Ii1I . o0oOOo0O0Ooo
  if 42 - 42: OoO0O00
 def is_ddt_child ( self ) :
  if ( self . map_server_child ) : return ( False )
  if ( self . map_server_peer ) : return ( False )
  return ( True )
  if 59 - 59: OoO0O00 . I1Ii111 % OoO0O00
  if 22 - 22: Oo0Ooo
 def is_ms_child ( self ) :
  return ( self . map_server_child )
  if 21 - 21: o0oOOo0O0Ooo
  if 86 - 86: ooOoO0o / iIii1I11I1II1 . OOooOOo
 def is_ms_peer ( self ) :
  return ( self . map_server_peer )
  if 93 - 93: Oo0Ooo / II111iiii . Oo0Ooo + i1IIi + i1IIi
  if 30 - 30: OoOoOO00 . OOooOOo % OOooOOo / II111iiii + i1IIi
  if 61 - 61: i1IIi % II111iiii * II111iiii . o0oOOo0O0Ooo / I1ii11iIi11i - I1Ii111
  if 93 - 93: Ii1I - i1IIi
  if 3 - 3: oO0o + OoO0O00 - iII111i / Ii1I
  if 58 - 58: Ii1I * I11i
  if 95 - 95: oO0o
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
  if 49 - 49: I1IiiI
  if 23 - 23: I1Ii111
 def print_ddt_map_request ( self ) :
  lprint ( "Queued Map-Request from {}ITR {}->{}, nonce 0x{}" . format ( "P" if self . from_pitr else "" ,
  # I11i
 red ( self . itr . print_address ( ) , False ) ,
 green ( self . eid . print_address ( ) , False ) , self . nonce ) )
  if 69 - 69: OoOoOO00 . OoooooooOO . o0oOOo0O0Ooo + i11iIiiIii
  if 54 - 54: ooOoO0o - O0 + iII111i
 def queue_map_request ( self ) :
  self . retransmit_timer = threading . Timer ( LISP_DDT_MAP_REQUEST_INTERVAL ,
 lisp_retransmit_ddt_map_request , [ self ] )
  self . retransmit_timer . start ( )
  lisp_ddt_map_requestQ [ str ( self . nonce ) ] = self
  if 34 - 34: Ii1I - OOooOOo % iII111i
  if 48 - 48: oO0o - O0
 def dequeue_map_request ( self ) :
  self . retransmit_timer . cancel ( )
  if ( lisp_ddt_map_requestQ . has_key ( str ( self . nonce ) ) ) :
   lisp_ddt_map_requestQ . pop ( str ( self . nonce ) )
   if 17 - 17: iIii1I11I1II1 . IiII / ooOoO0o % I11i + o0oOOo0O0Ooo - iIii1I11I1II1
   if 95 - 95: OoOoOO00 + OOooOOo - I11i * i1IIi + i1IIi * O0
   if 60 - 60: Oo0Ooo + I11i % iIii1I11I1II1 % oO0o - I1Ii111 / o0oOOo0O0Ooo
 def print_eid_tuple ( self ) :
  return ( lisp_print_eid_tuple ( self . eid , self . group ) )
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
LISP_DDT_ACTION_SITE_NOT_FOUND = - 2
LISP_DDT_ACTION_NULL = - 1
LISP_DDT_ACTION_NODE_REFERRAL = 0
LISP_DDT_ACTION_MS_REFERRAL = 1
LISP_DDT_ACTION_MS_ACK = 2
LISP_DDT_ACTION_MS_NOT_REG = 3
LISP_DDT_ACTION_DELEGATION_HOLE = 4
LISP_DDT_ACTION_NOT_AUTH = 5
LISP_DDT_ACTION_MAX = LISP_DDT_ACTION_NOT_AUTH
if 39 - 39: I1ii11iIi11i / i11iIiiIii * i1IIi * Oo0Ooo
lisp_map_referral_action_string = [
 "node-referral" , "ms-referral" , "ms-ack" , "ms-not-registered" ,
 "delegation-hole" , "not-authoritative" ]
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
if 71 - 71: Ii1I - i1IIi . I1IiiI
if 15 - 15: i1IIi % II111iiii / II111iiii - I1ii11iIi11i - I11i % i1IIi
if 54 - 54: i1IIi . OoO0O00 + iII111i + OoO0O00 * i1IIi
if 13 - 13: Oo0Ooo / OoO0O00 + OOooOOo
if 90 - 90: OoO0O00 * i11iIiiIii / oO0o
if 91 - 91: iII111i - OoOoOO00 / Oo0Ooo % II111iiii / II111iiii / o0oOOo0O0Ooo
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
  if 17 - 17: OoOoOO00 % Oo0Ooo / I1Ii111 . Ii1I % OoO0O00
  if 32 - 32: I1IiiI + ooOoO0o / O0 * i11iIiiIii % Oo0Ooo + II111iiii
 def print_info ( self ) :
  if ( self . info_reply ) :
   o0O00 = "Info-Reply"
   Oo0o0o0oo = ( ", ms-port: {}, etr-port: {}, global-rloc: {}, " + "ms-rloc: {}, private-rloc: {}, RTR-list: " ) . format ( self . ms_port , self . etr_port ,
   # OoooooooOO + I1ii11iIi11i . IiII / O0 % I1ii11iIi11i
   # Ii1I * O0
 red ( self . global_etr_rloc . print_address_no_iid ( ) , False ) ,
 red ( self . global_ms_rloc . print_address_no_iid ( ) , False ) ,
 red ( self . private_etr_rloc . print_address_no_iid ( ) , False ) )
   if ( len ( self . rtr_list ) == 0 ) : Oo0o0o0oo += "empty, "
   for Ii111iI1iI1ii in self . rtr_list :
    Oo0o0o0oo += red ( Ii111iI1iI1ii . print_address_no_iid ( ) , False ) + ", "
    if 54 - 54: IiII . I11i % ooOoO0o * II111iiii . II111iiii + I11i
   Oo0o0o0oo = Oo0o0o0oo [ 0 : - 2 ]
  else :
   o0O00 = "Info-Request"
   ooOOO00000oo = "<none>" if self . hostname == None else self . hostname
   Oo0o0o0oo = ", hostname: {}" . format ( blue ( ooOOO00000oo , False ) )
   if 32 - 32: O0 / I11i . O0
  lprint ( "{} -> nonce: 0x{}{}" . format ( bold ( o0O00 , False ) ,
 lisp_hex_string ( self . nonce ) , Oo0o0o0oo ) )
  if 25 - 25: Oo0Ooo - iII111i
  if 96 - 96: O0 . I1IiiI
 def encode ( self ) :
  O0oooOO = ( LISP_NAT_INFO << 28 )
  if ( self . info_reply ) : O0oooOO |= ( 1 << 27 )
  if 2 - 2: I11i . oO0o * IiII
  if 41 - 41: Ii1I / OoO0O00 / OoO0O00 * I11i
  if 31 - 31: Ii1I / OoooooooOO % iIii1I11I1II1 - IiII * I1IiiI - O0
  if 31 - 31: oO0o
  if 74 - 74: OoO0O00
  oOo = struct . pack ( "I" , socket . htonl ( O0oooOO ) )
  oOo += struct . pack ( "Q" , self . nonce )
  oOo += struct . pack ( "III" , 0 , 0 , 0 )
  if 11 - 11: oO0o + O0 % Ii1I . I11i * o0oOOo0O0Ooo
  if 14 - 14: I11i . iIii1I11I1II1 + I1Ii111 % OoooooooOO
  if 9 - 9: oO0o + Ii1I / I1ii11iIi11i * iIii1I11I1II1 + o0oOOo0O0Ooo
  if 64 - 64: I11i % i11iIiiIii % I1ii11iIi11i
  if ( self . info_reply == False ) :
   if ( self . hostname == None ) :
    oOo += struct . pack ( "H" , 0 )
   else :
    oOo += struct . pack ( "H" , socket . htons ( LISP_AFI_NAME ) )
    oOo += self . hostname + "\0"
    if 14 - 14: I1Ii111 - OoOoOO00 - I1ii11iIi11i % I11i + OoooooooOO
   return ( oOo )
   if 4 - 4: I1Ii111 - I1IiiI / iIii1I11I1II1 + I1ii11iIi11i % iIii1I11I1II1 * I1IiiI
   if 30 - 30: i11iIiiIii % OOooOOo
   if 52 - 52: I11i - oO0o . i11iIiiIii - II111iiii + Ii1I . iII111i
   if 27 - 27: I1IiiI + OoOoOO00 + iII111i
   if 70 - 70: I11i + IiII . ooOoO0o - I1ii11iIi11i
  o0o0O00oOo = socket . htons ( LISP_AFI_LCAF )
  o0O00o0o = LISP_LCAF_NAT_TYPE
  i11iii11 = socket . htons ( 16 )
  iiiIII1iII = socket . htons ( self . ms_port )
  oO00O0oO0Oo0 = socket . htons ( self . etr_port )
  oOo += struct . pack ( "HHBBHHHH" , o0o0O00oOo , 0 , o0O00o0o , 0 , i11iii11 ,
 iiiIII1iII , oO00O0oO0Oo0 , socket . htons ( self . global_etr_rloc . afi ) )
  oOo += self . global_etr_rloc . pack_address ( )
  oOo += struct . pack ( "HH" , 0 , socket . htons ( self . private_etr_rloc . afi ) )
  oOo += self . private_etr_rloc . pack_address ( )
  if ( len ( self . rtr_list ) == 0 ) : oOo += struct . pack ( "H" , 0 )
  if 85 - 85: O0
  if 10 - 10: Oo0Ooo / OoOoOO00 * OOooOOo - IiII + Ii1I
  if 62 - 62: I1IiiI . Ii1I
  if 74 - 74: Ii1I - I11i % ooOoO0o - I1IiiI - Ii1I - II111iiii
  for Ii111iI1iI1ii in self . rtr_list :
   oOo += struct . pack ( "H" , socket . htons ( Ii111iI1iI1ii . afi ) )
   oOo += Ii111iI1iI1ii . pack_address ( )
   if 81 - 81: i1IIi * I1ii11iIi11i + IiII - OoO0O00 * i1IIi
  return ( oOo )
  if 6 - 6: iIii1I11I1II1 % OoOoOO00 % II111iiii % o0oOOo0O0Ooo
  if 52 - 52: Ii1I - I1IiiI * iIii1I11I1II1 % Oo0Ooo * OOooOOo
 def decode ( self , packet ) :
  oOO = packet
  IIiI1I11ii1i = "I"
  i1II1i1iiI1 = struct . calcsize ( IIiI1I11ii1i )
  if ( len ( packet ) < i1II1i1iiI1 ) : return ( None )
  if 67 - 67: OoooooooOO * I11i * Ii1I * iIii1I11I1II1
  O0oooOO = struct . unpack ( IIiI1I11ii1i , packet [ : i1II1i1iiI1 ] )
  O0oooOO = O0oooOO [ 0 ]
  packet = packet [ i1II1i1iiI1 : : ]
  if 22 - 22: OoO0O00 / o0oOOo0O0Ooo
  IIiI1I11ii1i = "Q"
  i1II1i1iiI1 = struct . calcsize ( IIiI1I11ii1i )
  if ( len ( packet ) < i1II1i1iiI1 ) : return ( None )
  if 35 - 35: I1Ii111 / I1Ii111 + o0oOOo0O0Ooo - oO0o
  i11III1I = struct . unpack ( IIiI1I11ii1i , packet [ : i1II1i1iiI1 ] )
  if 40 - 40: OoOoOO00 - II111iiii
  O0oooOO = socket . ntohl ( O0oooOO )
  self . nonce = i11III1I [ 0 ]
  self . info_reply = O0oooOO & 0x08000000
  self . hostname = None
  packet = packet [ i1II1i1iiI1 : : ]
  if 29 - 29: I1IiiI - O0
  if 36 - 36: I1IiiI * I1IiiI
  if 79 - 79: I1Ii111 - I11i
  if 49 - 49: II111iiii + O0 * ooOoO0o - Oo0Ooo
  if 89 - 89: I1IiiI + I11i . oO0o . II111iiii + oO0o / Oo0Ooo
  IIiI1I11ii1i = "HH"
  i1II1i1iiI1 = struct . calcsize ( IIiI1I11ii1i )
  if ( len ( packet ) < i1II1i1iiI1 ) : return ( None )
  if 32 - 32: OoO0O00 % oO0o * I1ii11iIi11i + I11i / I1Ii111
  if 5 - 5: o0oOOo0O0Ooo + iII111i / OoooooooOO + Ii1I . OoOoOO00 / oO0o
  if 18 - 18: II111iiii . o0oOOo0O0Ooo
  if 75 - 75: OoooooooOO - Oo0Ooo
  if 56 - 56: II111iiii - i11iIiiIii - oO0o . o0oOOo0O0Ooo
  OoooOOo0oOO , ooooO000 = struct . unpack ( IIiI1I11ii1i , packet [ : i1II1i1iiI1 ] )
  if ( ooooO000 != 0 ) : return ( None )
  if 4 - 4: i1IIi
  packet = packet [ i1II1i1iiI1 : : ]
  IIiI1I11ii1i = "IBBH"
  i1II1i1iiI1 = struct . calcsize ( IIiI1I11ii1i )
  if ( len ( packet ) < i1II1i1iiI1 ) : return ( None )
  if 91 - 91: IiII . OoO0O00 * Ii1I / o0oOOo0O0Ooo
  Ii1 , I1IiII , IIiiiII , I1I1Iiii11iIi = struct . unpack ( IIiI1I11ii1i ,
 packet [ : i1II1i1iiI1 ] )
  if 70 - 70: I1IiiI % oO0o + iII111i % i11iIiiIii + ooOoO0o
  if ( I1I1Iiii11iIi != 0 ) : return ( None )
  packet = packet [ i1II1i1iiI1 : : ]
  if 88 - 88: I11i * oO0o * I1ii11iIi11i - OOooOOo * IiII + o0oOOo0O0Ooo
  if 9 - 9: OoooooooOO
  if 26 - 26: OoOoOO00 + II111iiii - OoO0O00 + iII111i - iII111i % O0
  if 79 - 79: iIii1I11I1II1 - OoOoOO00 - O0 + I1ii11iIi11i
  if ( self . info_reply == False ) :
   IIiI1I11ii1i = "H"
   i1II1i1iiI1 = struct . calcsize ( IIiI1I11ii1i )
   if ( len ( packet ) >= i1II1i1iiI1 ) :
    o0o0O00oOo = struct . unpack ( IIiI1I11ii1i , packet [ : i1II1i1iiI1 ] ) [ 0 ]
    if ( socket . ntohs ( o0o0O00oOo ) == LISP_AFI_NAME ) :
     packet = packet [ i1II1i1iiI1 : : ]
     packet , self . hostname = lisp_decode_dist_name ( packet )
     if 69 - 69: oO0o % OoooooooOO
     if 21 - 21: I1Ii111
   return ( oOO )
   if 62 - 62: Ii1I % o0oOOo0O0Ooo
   if 65 - 65: OoO0O00 + Oo0Ooo + IiII / OoOoOO00
   if 37 - 37: oO0o - I11i
   if 64 - 64: OoO0O00 * OoOoOO00
   if 50 - 50: I1ii11iIi11i + I11i * iII111i
  IIiI1I11ii1i = "HHBBHHH"
  i1II1i1iiI1 = struct . calcsize ( IIiI1I11ii1i )
  if ( len ( packet ) < i1II1i1iiI1 ) : return ( None )
  if 27 - 27: OoOoOO00 * OOooOOo * iIii1I11I1II1 / i1IIi
  o0o0O00oOo , IiiIii1111Ii1I1 , o0O00o0o , I1IiII , i11iii11 , iiiIII1iII , oO00O0oO0Oo0 = struct . unpack ( IIiI1I11ii1i , packet [ : i1II1i1iiI1 ] )
  if 60 - 60: OOooOOo * I1Ii111 . oO0o
  if 47 - 47: oO0o % OOooOOo / OOooOOo % OoOoOO00 % I1Ii111 / OoOoOO00
  if ( socket . ntohs ( o0o0O00oOo ) != LISP_AFI_LCAF ) : return ( None )
  if 51 - 51: I1IiiI . I11i - OoOoOO00
  self . ms_port = socket . ntohs ( iiiIII1iII )
  self . etr_port = socket . ntohs ( oO00O0oO0Oo0 )
  packet = packet [ i1II1i1iiI1 : : ]
  if 10 - 10: Oo0Ooo * OOooOOo / IiII . o0oOOo0O0Ooo
  if 97 - 97: Ii1I . Ii1I % iII111i
  if 49 - 49: Oo0Ooo % OOooOOo - OoooooooOO + IiII
  if 54 - 54: iIii1I11I1II1 - OoooooooOO / I11i / oO0o % I1IiiI + OoOoOO00
  IIiI1I11ii1i = "H"
  i1II1i1iiI1 = struct . calcsize ( IIiI1I11ii1i )
  if ( len ( packet ) < i1II1i1iiI1 ) : return ( None )
  if 26 - 26: OoO0O00 * II111iiii % OOooOOo * iII111i + iII111i
  if 25 - 25: I11i - I1ii11iIi11i
  if 100 - 100: I1Ii111 / Ii1I + OoOoOO00 . OoooooooOO
  if 83 - 83: O0
  o0o0O00oOo = struct . unpack ( IIiI1I11ii1i , packet [ : i1II1i1iiI1 ] ) [ 0 ]
  packet = packet [ i1II1i1iiI1 : : ]
  if ( o0o0O00oOo != 0 ) :
   self . global_etr_rloc . afi = socket . ntohs ( o0o0O00oOo )
   packet = self . global_etr_rloc . unpack_address ( packet )
   if ( packet == None ) : return ( None )
   self . global_etr_rloc . mask_len = self . global_etr_rloc . host_mask_len ( )
   if 35 - 35: i11iIiiIii - I11i . OoOoOO00 * II111iiii % i11iIiiIii
   if 55 - 55: o0oOOo0O0Ooo / O0 / OoooooooOO * Oo0Ooo % iII111i
   if 24 - 24: I1ii11iIi11i % OOooOOo + OoooooooOO + OoO0O00
   if 100 - 100: Oo0Ooo % OoO0O00 - OoOoOO00
   if 46 - 46: o0oOOo0O0Ooo
   if 28 - 28: i1IIi
  if ( len ( packet ) < i1II1i1iiI1 ) : return ( oOO )
  if 81 - 81: oO0o % OoooooooOO . I1Ii111 - OoOoOO00 / I1IiiI
  o0o0O00oOo = struct . unpack ( IIiI1I11ii1i , packet [ : i1II1i1iiI1 ] ) [ 0 ]
  packet = packet [ i1II1i1iiI1 : : ]
  if ( o0o0O00oOo != 0 ) :
   self . global_ms_rloc . afi = socket . ntohs ( o0o0O00oOo )
   packet = self . global_ms_rloc . unpack_address ( packet )
   if ( packet == None ) : return ( oOO )
   self . global_ms_rloc . mask_len = self . global_ms_rloc . host_mask_len ( )
   if 62 - 62: I1Ii111 * I11i / I11i
   if 42 - 42: ooOoO0o * ooOoO0o / Ii1I / OOooOOo * OOooOOo
   if 92 - 92: Oo0Ooo / iII111i - OoooooooOO - o0oOOo0O0Ooo % ooOoO0o
   if 35 - 35: i1IIi % iII111i % I11i * iIii1I11I1II1 % Ii1I - Oo0Ooo
   if 94 - 94: iII111i
  if ( len ( packet ) < i1II1i1iiI1 ) : return ( oOO )
  if 68 - 68: OoooooooOO % OOooOOo / OoooooooOO / I1Ii111 + Ii1I - o0oOOo0O0Ooo
  o0o0O00oOo = struct . unpack ( IIiI1I11ii1i , packet [ : i1II1i1iiI1 ] ) [ 0 ]
  packet = packet [ i1II1i1iiI1 : : ]
  if ( o0o0O00oOo != 0 ) :
   self . private_etr_rloc . afi = socket . ntohs ( o0o0O00oOo )
   packet = self . private_etr_rloc . unpack_address ( packet )
   if ( packet == None ) : return ( oOO )
   self . private_etr_rloc . mask_len = self . private_etr_rloc . host_mask_len ( )
   if 81 - 81: I1IiiI
   if 62 - 62: Ii1I * OoOoOO00
   if 27 - 27: Oo0Ooo + Oo0Ooo / II111iiii % I1Ii111
   if 11 - 11: Ii1I
   if 54 - 54: I1IiiI * I1Ii111 / ooOoO0o / iIii1I11I1II1 % iII111i / oO0o
   if 11 - 11: ooOoO0o + I1IiiI + Ii1I . II111iiii
  while ( len ( packet ) >= i1II1i1iiI1 ) :
   o0o0O00oOo = struct . unpack ( IIiI1I11ii1i , packet [ : i1II1i1iiI1 ] ) [ 0 ]
   packet = packet [ i1II1i1iiI1 : : ]
   if ( o0o0O00oOo == 0 ) : continue
   Ii111iI1iI1ii = lisp_address ( socket . ntohs ( o0o0O00oOo ) , "" , 0 , 0 )
   packet = Ii111iI1iI1ii . unpack_address ( packet )
   if ( packet == None ) : return ( oOO )
   Ii111iI1iI1ii . mask_len = Ii111iI1iI1ii . host_mask_len ( )
   self . rtr_list . append ( Ii111iI1iI1ii )
   if 50 - 50: Oo0Ooo
  return ( oOO )
  if 14 - 14: O0
  if 67 - 67: II111iiii / O0
  if 10 - 10: i1IIi / Oo0Ooo
class lisp_nat_info ( ) :
 def __init__ ( self , addr_str , hostname , port ) :
  self . address = addr_str
  self . hostname = hostname
  self . port = port
  self . uptime = lisp_get_timestamp ( )
  if 20 - 20: Oo0Ooo * I1Ii111 / I1ii11iIi11i . ooOoO0o
  if 67 - 67: o0oOOo0O0Ooo . Oo0Ooo % I11i
 def timed_out ( self ) :
  iIIiI1iiI = time . time ( ) - self . uptime
  return ( iIIiI1iiI >= ( LISP_INFO_INTERVAL * 2 ) )
  if 38 - 38: OOooOOo - OoO0O00 . ooOoO0o
  if 50 - 50: o0oOOo0O0Ooo
  if 85 - 85: II111iiii . iII111i - i1IIi
class lisp_info_source ( ) :
 def __init__ ( self , hostname , addr_str , port ) :
  self . address = lisp_address ( LISP_AFI_IPV4 , addr_str , 32 , 0 )
  self . port = port
  self . uptime = lisp_get_timestamp ( )
  self . nonce = None
  self . hostname = hostname
  self . no_timeout = False
  if 23 - 23: iII111i . Ii1I - OoO0O00 / I1ii11iIi11i / O0
  if 4 - 4: i1IIi % Oo0Ooo % Ii1I * ooOoO0o - I11i
 def cache_address_for_info_source ( self ) :
  Iiii11 = self . address . print_address_no_iid ( ) + self . hostname
  lisp_info_sources_by_address [ Iiii11 ] = self
  if 76 - 76: iIii1I11I1II1 / ooOoO0o % I1ii11iIi11i % OOooOOo
  if 13 - 13: IiII
 def cache_nonce_for_info_source ( self , nonce ) :
  self . nonce = nonce
  lisp_info_sources_by_nonce [ nonce ] = self
  if 56 - 56: Oo0Ooo
  if 55 - 55: i11iIiiIii + iIii1I11I1II1 / i1IIi / I1ii11iIi11i
  if 64 - 64: IiII . OoO0O00 * i11iIiiIii
  if 18 - 18: Ii1I % o0oOOo0O0Ooo - Oo0Ooo
  if 28 - 28: IiII
  if 93 - 93: Oo0Ooo % i1IIi
  if 51 - 51: oO0o % O0
  if 41 - 41: I1IiiI * I1IiiI . I1Ii111
  if 38 - 38: I1IiiI % i11iIiiIii
  if 17 - 17: i11iIiiIii
  if 81 - 81: I1Ii111
def lisp_concat_auth_data ( alg_id , auth1 , auth2 , auth3 , auth4 ) :
 if 25 - 25: I1IiiI
 if ( lisp_is_x86 ( ) ) :
  if ( auth1 != "" ) : auth1 = byte_swap_64 ( auth1 )
  if ( auth2 != "" ) : auth2 = byte_swap_64 ( auth2 )
  if ( auth3 != "" ) :
   if ( alg_id == LISP_SHA_1_96_ALG_ID ) : auth3 = socket . ntohl ( auth3 )
   else : auth3 = byte_swap_64 ( auth3 )
   if 52 - 52: I1ii11iIi11i % i1IIi . IiII % OoOoOO00
  if ( auth4 != "" ) : auth4 = byte_swap_64 ( auth4 )
  if 50 - 50: OOooOOo * I1IiiI / o0oOOo0O0Ooo
  if 91 - 91: iIii1I11I1II1 / OOooOOo * O0 . o0oOOo0O0Ooo + oO0o / I1ii11iIi11i
 if ( alg_id == LISP_SHA_1_96_ALG_ID ) :
  auth1 = lisp_hex_string ( auth1 )
  auth1 = auth1 . zfill ( 16 )
  auth2 = lisp_hex_string ( auth2 )
  auth2 = auth2 . zfill ( 16 )
  auth3 = lisp_hex_string ( auth3 )
  auth3 = auth3 . zfill ( 8 )
  I1iiI1II11 = auth1 + auth2 + auth3
  if 33 - 33: II111iiii + Ii1I
 if ( alg_id == LISP_SHA_256_128_ALG_ID ) :
  auth1 = lisp_hex_string ( auth1 )
  auth1 = auth1 . zfill ( 16 )
  auth2 = lisp_hex_string ( auth2 )
  auth2 = auth2 . zfill ( 16 )
  auth3 = lisp_hex_string ( auth3 )
  auth3 = auth3 . zfill ( 16 )
  auth4 = lisp_hex_string ( auth4 )
  auth4 = auth4 . zfill ( 16 )
  I1iiI1II11 = auth1 + auth2 + auth3 + auth4
  if 46 - 46: IiII + O0 + i1IIi + ooOoO0o / iII111i
 return ( I1iiI1II11 )
 if 94 - 94: oO0o + iII111i * OoOoOO00 - i1IIi / OoooooooOO
 if 59 - 59: I11i % Ii1I / OoOoOO00
 if 99 - 99: Ii1I + II111iiii / i11iIiiIii - IiII / iII111i + iII111i
 if 55 - 55: IiII + OoooooooOO * I1ii11iIi11i . IiII * I1ii11iIi11i + IiII
 if 81 - 81: iIii1I11I1II1 . ooOoO0o + OoOoOO00
 if 31 - 31: I11i / OoOoOO00 + o0oOOo0O0Ooo
 if 80 - 80: Oo0Ooo
 if 58 - 58: I1Ii111 + OOooOOo
 if 76 - 76: II111iiii - o0oOOo0O0Ooo % OoO0O00 + iII111i
 if 38 - 38: I1Ii111 - I11i * i1IIi + iIii1I11I1II1
def lisp_open_listen_socket ( local_addr , port ) :
 if ( port . isdigit ( ) ) :
  if ( local_addr . find ( "." ) != - 1 ) :
   I1iII1iI1 = socket . socket ( socket . AF_INET , socket . SOCK_DGRAM )
   if 15 - 15: OoooooooOO + I11i
  if ( local_addr . find ( ":" ) != - 1 ) :
   if ( lisp_is_raspbian ( ) ) : return ( None )
   I1iII1iI1 = socket . socket ( socket . AF_INET6 , socket . SOCK_DGRAM )
   if 76 - 76: O0 % Ii1I * ooOoO0o
  I1iII1iI1 . bind ( ( local_addr , int ( port ) ) )
 else :
  i1i1Ii = port
  if ( os . path . exists ( i1i1Ii ) ) :
   os . system ( "rm " + i1i1Ii )
   time . sleep ( 1 )
   if 13 - 13: OoooooooOO + OoO0O00 % OOooOOo * OoooooooOO
  I1iII1iI1 = socket . socket ( socket . AF_UNIX , socket . SOCK_DGRAM )
  I1iII1iI1 . bind ( i1i1Ii )
  if 21 - 21: Ii1I % O0
 return ( I1iII1iI1 )
 if 15 - 15: II111iiii * Ii1I + IiII % iII111i
 if 96 - 96: II111iiii * I1Ii111 / Oo0Ooo
 if 35 - 35: I1IiiI
 if 54 - 54: I1ii11iIi11i % o0oOOo0O0Ooo . i1IIi
 if 72 - 72: Ii1I
 if 87 - 87: iII111i - I1IiiI
 if 54 - 54: iIii1I11I1II1 + oO0o * o0oOOo0O0Ooo % OoooooooOO . Oo0Ooo
def lisp_open_send_socket ( internal_name , afi ) :
 if ( internal_name == "" ) :
  if ( afi == LISP_AFI_IPV4 ) :
   I1iII1iI1 = socket . socket ( socket . AF_INET , socket . SOCK_DGRAM )
   if 32 - 32: iII111i
  if ( afi == LISP_AFI_IPV6 ) :
   if ( lisp_is_raspbian ( ) ) : return ( None )
   I1iII1iI1 = socket . socket ( socket . AF_INET6 , socket . SOCK_DGRAM )
   if 33 - 33: ooOoO0o + Oo0Ooo * OoOoOO00 % ooOoO0o * oO0o - OoO0O00
 else :
  if ( os . path . exists ( internal_name ) ) : os . system ( "rm " + internal_name )
  I1iII1iI1 = socket . socket ( socket . AF_UNIX , socket . SOCK_DGRAM )
  I1iII1iI1 . bind ( internal_name )
  if 40 - 40: I11i . OoooooooOO * O0 / I1Ii111 + O0
 return ( I1iII1iI1 )
 if 97 - 97: ooOoO0o - ooOoO0o * OOooOOo % OoOoOO00 - OoOoOO00 - I1Ii111
 if 52 - 52: O0 % iII111i
 if 81 - 81: OoooooooOO % OoOoOO00 % Oo0Ooo - I1IiiI
 if 43 - 43: o0oOOo0O0Ooo % o0oOOo0O0Ooo
 if 48 - 48: O0
 if 5 - 5: OOooOOo / i11iIiiIii . I11i % OOooOOo
 if 1 - 1: II111iiii + O0 * OoOoOO00 / IiII . O0
def lisp_close_socket ( sock , internal_name ) :
 sock . close ( )
 if ( os . path . exists ( internal_name ) ) : os . system ( "rm " + internal_name )
 return
 if 87 - 87: IiII + I1IiiI
 if 74 - 74: OoO0O00 + OoO0O00 % iII111i / I11i / O0
 if 54 - 54: o0oOOo0O0Ooo / OoooooooOO * ooOoO0o . OoOoOO00 - I1Ii111
 if 69 - 69: oO0o - OoO0O00
 if 80 - 80: ooOoO0o + iIii1I11I1II1 . II111iiii + I1IiiI - oO0o % OoOoOO00
 if 10 - 10: iIii1I11I1II1
 if 44 - 44: OoOoOO00 * oO0o . I1ii11iIi11i + i11iIiiIii
 if 85 - 85: I11i
def lisp_is_running ( node ) :
 return ( True if ( os . path . exists ( node ) ) else False )
 if 36 - 36: ooOoO0o % OoO0O00
 if 1 - 1: OoooooooOO - OoOoOO00
 if 35 - 35: I1Ii111
 if 35 - 35: Oo0Ooo - iIii1I11I1II1 / i1IIi + OoO0O00 - OoooooooOO / i11iIiiIii
 if 79 - 79: I1IiiI * ooOoO0o * ooOoO0o
 if 92 - 92: iII111i % I1ii11iIi11i
 if 16 - 16: oO0o
 if 52 - 52: OoooooooOO % ooOoO0o - I1Ii111 * I11i
 if 24 - 24: Ii1I + IiII + OoooooooOO / oO0o / I1IiiI + IiII
def lisp_packet_ipc ( packet , source , sport ) :
 return ( ( "packet@" + str ( len ( packet ) ) + "@" + source + "@" + str ( sport ) + "@" + packet ) )
 if 52 - 52: ooOoO0o
 if 38 - 38: OoO0O00 + I1IiiI % IiII
 if 87 - 87: oO0o * Ii1I - I1Ii111 / oO0o
 if 65 - 65: OoOoOO00
 if 87 - 87: I11i - i11iIiiIii - OOooOOo . OoOoOO00 + IiII . OoO0O00
 if 70 - 70: iIii1I11I1II1 % OoooooooOO / OoO0O00 . O0 - I11i % II111iiii
 if 84 - 84: OOooOOo * i1IIi . iIii1I11I1II1 * iII111i + I1Ii111 + II111iiii
 if 97 - 97: Ii1I - IiII
 if 64 - 64: oO0o . ooOoO0o / ooOoO0o - II111iiii
def lisp_control_packet_ipc ( packet , source , dest , dport ) :
 return ( "control-packet@" + dest + "@" + str ( dport ) + "@" + packet )
 if 81 - 81: I1ii11iIi11i
 if 64 - 64: oO0o * OoO0O00 / OOooOOo + Ii1I % Oo0Ooo . IiII
 if 2 - 2: I1Ii111 + I11i
 if 47 - 47: i11iIiiIii + iIii1I11I1II1 % I1ii11iIi11i - oO0o % OoO0O00
 if 85 - 85: oO0o * OoOoOO00 / OoOoOO00
 if 85 - 85: OOooOOo / I1Ii111 . i1IIi / OoOoOO00 + iIii1I11I1II1
 if 71 - 71: OoO0O00
def lisp_data_packet_ipc ( packet , source ) :
 return ( "data-packet@" + str ( len ( packet ) ) + "@" + source + "@@" + packet )
 if 96 - 96: I1ii11iIi11i / I1IiiI - I1ii11iIi11i / II111iiii - IiII
 if 74 - 74: Ii1I * OoooooooOO % OOooOOo + OoooooooOO + iII111i
 if 83 - 83: i1IIi
 if 2 - 2: i1IIi / OOooOOo * O0
 if 99 - 99: OoooooooOO . OoOoOO00 / II111iiii
 if 64 - 64: iII111i / i1IIi . I1IiiI + O0
 if 5 - 5: O0 . i11iIiiIii
 if 71 - 71: o0oOOo0O0Ooo + iII111i + ooOoO0o
 if 27 - 27: OoooooooOO . iII111i * I1Ii111 % O0 + OoooooooOO - iII111i
def lisp_command_ipc ( packet , source ) :
 return ( "command@" + str ( len ( packet ) ) + "@" + source + "@@" + packet )
 if 86 - 86: i1IIi
 if 81 - 81: OoOoOO00
 if 52 - 52: iII111i * IiII % I1IiiI * I11i
 if 73 - 73: I1Ii111 * ooOoO0o
 if 62 - 62: OOooOOo . I1IiiI * iIii1I11I1II1 + OoO0O00 * ooOoO0o / oO0o
 if 14 - 14: iII111i / OoO0O00
 if 75 - 75: IiII
 if 68 - 68: IiII - i1IIi % IiII . OoO0O00 . i11iIiiIii . OoooooooOO
 if 32 - 32: iII111i + OoO0O00 % IiII + I1IiiI
def lisp_api_ipc ( source , data ) :
 return ( "api@" + str ( len ( data ) ) + "@" + source + "@@" + data )
 if 69 - 69: I1Ii111 + I11i - iIii1I11I1II1 - II111iiii . Ii1I
 if 74 - 74: I1ii11iIi11i % o0oOOo0O0Ooo + O0 - i11iIiiIii - IiII % OOooOOo
 if 39 - 39: OoO0O00 - o0oOOo0O0Ooo
 if 71 - 71: iII111i . OoO0O00 + ooOoO0o - OOooOOo - Oo0Ooo
 if 100 - 100: OoooooooOO - o0oOOo0O0Ooo + I1Ii111 . OoooooooOO % i11iIiiIii
 if 64 - 64: I1Ii111 % OoooooooOO / i1IIi / OoO0O00
 if 2 - 2: I11i % o0oOOo0O0Ooo . OoO0O00 . OoO0O00
 if 89 - 89: ooOoO0o - oO0o + II111iiii + OoO0O00 - IiII
 if 27 - 27: I1Ii111 - o0oOOo0O0Ooo + OoO0O00
def lisp_ipc ( packet , send_socket , node ) :
 if 38 - 38: OoOoOO00 + OoO0O00 . i11iIiiIii + Ii1I % i1IIi % I1IiiI
 if 93 - 93: i11iIiiIii
 if 63 - 63: iIii1I11I1II1 - iIii1I11I1II1 % o0oOOo0O0Ooo
 if 97 - 97: i1IIi % I11i % OoOoOO00
 if ( lisp_is_running ( node ) == False ) :
  lprint ( "Suppress sending IPC to {}" . format ( node ) )
  return
  if 25 - 25: OoOoOO00 . iIii1I11I1II1 - iII111i % II111iiii . OoOoOO00
  if 16 - 16: OOooOOo . Oo0Ooo . I1IiiI % O0 . I1ii11iIi11i + i11iIiiIii
 OOOo0OOOO = 1500 if ( packet . find ( "control-packet" ) == - 1 ) else 9000
 if 31 - 31: i1IIi
 ii = 0
 OOOOO000oo0 = len ( packet )
 II1ii = 0
 ii1 = .001
 while ( OOOOO000oo0 > 0 ) :
  ooOO0O0OOOOoo = min ( OOOOO000oo0 , OOOo0OOOO )
  oo0 = packet [ ii : ooOO0O0OOOOoo + ii ]
  if 64 - 64: OoooooooOO
  try :
   send_socket . sendto ( oo0 , node )
   lprint ( "Send IPC {}-out-of-{} byte to {} succeeded" . format ( len ( oo0 ) , len ( packet ) , node ) )
   if 25 - 25: IiII
   II1ii = 0
   ii1 = .001
   if 29 - 29: OoOoOO00 % ooOoO0o * OoooooooOO
  except socket . error , Oo0ooo0Ooo :
   if ( II1ii == 12 ) :
    lprint ( "Giving up on {}, consider it down" . format ( node ) )
    break
    if 8 - 8: i11iIiiIii - I1Ii111 / IiII
    if 17 - 17: i11iIiiIii * OoO0O00 . o0oOOo0O0Ooo . OoooooooOO . OoOoOO00 - I1ii11iIi11i
   lprint ( "Send IPC {}-out-of-{} byte to {} failed: {}" . format ( len ( oo0 ) , len ( packet ) , node , Oo0ooo0Ooo ) )
   if 78 - 78: I1ii11iIi11i - OoooooooOO + O0
   if 15 - 15: I1ii11iIi11i / IiII % I1IiiI
   II1ii += 1
   time . sleep ( ii1 )
   if 16 - 16: Ii1I
   lprint ( "Retrying after {} ms ..." . format ( ii1 * 1000 ) )
   ii1 *= 2
   continue
   if 26 - 26: o0oOOo0O0Ooo / I11i + OoOoOO00 / OoOoOO00
   if 31 - 31: I1Ii111
  ii += ooOO0O0OOOOoo
  OOOOO000oo0 -= ooOO0O0OOOOoo
  if 84 - 84: i11iIiiIii * OOooOOo . iII111i - Ii1I * i1IIi - I1ii11iIi11i
 return
 if 1 - 1: II111iiii
 if 94 - 94: I1ii11iIi11i * iII111i % iII111i % I11i - iII111i
 if 38 - 38: IiII - OoO0O00 % Ii1I - II111iiii
 if 97 - 97: O0 . Ii1I
 if 52 - 52: IiII
 if 86 - 86: I1Ii111 / O0 + OoooooooOO % oO0o
 if 45 - 45: I1IiiI . Oo0Ooo . I11i . Ii1I
def lisp_format_packet ( packet ) :
 packet = binascii . hexlify ( packet )
 ii = 0
 iiiii1I = ""
 OOOOO000oo0 = len ( packet ) * 2
 while ( ii < OOOOO000oo0 ) :
  iiiii1I += packet [ ii : ii + 8 ] + " "
  ii += 8
  OOOOO000oo0 -= 4
  if 81 - 81: II111iiii + OoOoOO00 % i11iIiiIii / iII111i . I1Ii111 + II111iiii
 return ( iiiii1I )
 if 48 - 48: I1IiiI . I1ii11iIi11i * OoOoOO00 % i1IIi / I1Ii111 * II111iiii
 if 62 - 62: o0oOOo0O0Ooo * I1Ii111 . iIii1I11I1II1 / i1IIi
 if 75 - 75: OoooooooOO / ooOoO0o - iII111i . OoooooooOO . OoOoOO00 % i1IIi
 if 7 - 7: OoOoOO00 . i1IIi * i11iIiiIii % i11iIiiIii
 if 54 - 54: OoO0O00 / I1IiiI . Oo0Ooo
 if 39 - 39: OoO0O00 . ooOoO0o
 if 41 - 41: Oo0Ooo * I1ii11iIi11i - II111iiii - II111iiii
def lisp_send ( lisp_sockets , dest , port , packet ) :
 iIi11II1I = lisp_sockets [ 0 ] if dest . is_ipv4 ( ) else lisp_sockets [ 1 ]
 if 95 - 95: OoOoOO00 / I1IiiI - i1IIi / i11iIiiIii * o0oOOo0O0Ooo
 if 12 - 12: I1ii11iIi11i + iII111i % II111iiii * I1Ii111 . II111iiii / I1Ii111
 if 82 - 82: OoO0O00 - i1IIi / OOooOOo
 if 31 - 31: I11i + I1Ii111 + ooOoO0o / OoOoOO00
 if 68 - 68: Oo0Ooo % IiII * I1IiiI % I1ii11iIi11i % OoooooooOO
 if 63 - 63: Oo0Ooo / I11i . iII111i + ooOoO0o / I1ii11iIi11i / I1IiiI
 if 43 - 43: OoOoOO00 / I1Ii111 % I11i / I1IiiI - IiII - ooOoO0o
 if 25 - 25: OOooOOo * OoOoOO00 + I11i . ooOoO0o
 if 96 - 96: iIii1I11I1II1 / Ii1I
 if 92 - 92: OoO0O00 * I1ii11iIi11i + iIii1I11I1II1
 if 88 - 88: iIii1I11I1II1 + iIii1I11I1II1 * i11iIiiIii . I1ii11iIi11i % oO0o
 if 94 - 94: I1IiiI / I1ii11iIi11i / OOooOOo
 Iiii1Ii1I = dest . print_address_no_iid ( )
 if ( Iiii1Ii1I . find ( "::ffff:" ) != - 1 and Iiii1Ii1I . count ( "." ) == 3 ) :
  if ( lisp_i_am_rtr ) : iIi11II1I = lisp_sockets [ 0 ]
  if ( iIi11II1I == None ) :
   iIi11II1I = lisp_sockets [ 0 ]
   Iiii1Ii1I = Iiii1Ii1I . split ( "::ffff:" ) [ - 1 ]
   if 45 - 45: II111iiii
   if 98 - 98: i11iIiiIii + I1ii11iIi11i * OOooOOo / OoOoOO00
   if 84 - 84: o0oOOo0O0Ooo
 lprint ( "{} {} bytes {} {}, packet: {}" . format ( bold ( "Send" , False ) ,
 len ( packet ) , bold ( "to " + Iiii1Ii1I , False ) , port ,
 lisp_format_packet ( packet ) ) )
 if 40 - 40: OoooooooOO - oO0o / O0 * I1Ii111 . O0 + i11iIiiIii
 if 9 - 9: OOooOOo % O0 % O0 / I1ii11iIi11i . II111iiii / II111iiii
 if 78 - 78: iIii1I11I1II1 - i1IIi . I11i . o0oOOo0O0Ooo
 if 66 - 66: OOooOOo * Oo0Ooo
 o0000Oo0oo = ( LISP_RLOC_PROBE_TTL == 255 )
 if ( o0000Oo0oo ) :
  i1IIII1IiI = struct . unpack ( "B" , packet [ 0 ] ) [ 0 ]
  o0000Oo0oo = ( i1IIII1IiI in [ 0x12 , 0x28 ] )
  if ( o0000Oo0oo ) : lisp_set_ttl ( iIi11II1I , LISP_RLOC_PROBE_TTL )
  if 61 - 61: O0
  if 100 - 100: i11iIiiIii * O0 / Oo0Ooo % II111iiii
 try : iIi11II1I . sendto ( packet , ( Iiii1Ii1I , port ) )
 except socket . error , Oo0ooo0Ooo :
  lprint ( "socket.sendto() failed: {}" . format ( Oo0ooo0Ooo ) )
  if 49 - 49: oO0o
  if 98 - 98: OoooooooOO . II111iiii
  if 12 - 12: OoO0O00 - I1Ii111 / O0 - iII111i
  if 44 - 44: i1IIi
  if 23 - 23: I1ii11iIi11i . OoooooooOO / Ii1I + o0oOOo0O0Ooo
 if ( o0000Oo0oo ) : lisp_set_ttl ( iIi11II1I , 64 )
 return
 if 89 - 89: OoOoOO00 + Oo0Ooo . OoOoOO00 - II111iiii
 if 85 - 85: OoooooooOO * OoooooooOO / Ii1I - II111iiii
 if 69 - 69: iII111i * I11i
 if 43 - 43: o0oOOo0O0Ooo - IiII * Ii1I . i11iIiiIii / II111iiii
 if 61 - 61: OoOoOO00 / I1IiiI . I1ii11iIi11i % OOooOOo
 if 70 - 70: OOooOOo * OoOoOO00 / oO0o + Oo0Ooo / O0
 if 16 - 16: Oo0Ooo / OoooooooOO / IiII + Oo0Ooo * i11iIiiIii
 if 15 - 15: o0oOOo0O0Ooo / i11iIiiIii
def lisp_receive_segments ( lisp_socket , packet , source , total_length ) :
 if 63 - 63: I1ii11iIi11i - Ii1I + I11i
 if 98 - 98: iII111i / IiII * I1IiiI / oO0o - iIii1I11I1II1
 if 72 - 72: O0 . OOooOOo
 if 99 - 99: i1IIi + iIii1I11I1II1 - ooOoO0o + OoO0O00 + Oo0Ooo . I1ii11iIi11i
 if 74 - 74: i1IIi
 ooOO0O0OOOOoo = total_length - len ( packet )
 if ( ooOO0O0OOOOoo == 0 ) : return ( [ True , packet ] )
 if 80 - 80: ooOoO0o + I1Ii111 . I1ii11iIi11i % OoooooooOO
 lprint ( "Received {}-out-of-{} byte segment from {}" . format ( len ( packet ) ,
 total_length , source ) )
 if 26 - 26: OoOoOO00 . iII111i * iIii1I11I1II1 / IiII
 if 69 - 69: OoooooooOO / I11i + Ii1I * II111iiii
 if 35 - 35: i11iIiiIii + oO0o
 if 85 - 85: OoOoOO00 . O0 % OoooooooOO % oO0o
 if 43 - 43: I1IiiI - I11i . I1IiiI / i11iIiiIii % IiII * i11iIiiIii
 OOOOO000oo0 = ooOO0O0OOOOoo
 while ( OOOOO000oo0 > 0 ) :
  try : oo0 = lisp_socket . recvfrom ( 9000 )
  except : return ( [ False , None ] )
  if 12 - 12: II111iiii - iIii1I11I1II1
  oo0 = oo0 [ 0 ]
  if 43 - 43: i11iIiiIii % OoO0O00
  if 100 - 100: i1IIi
  if 4 - 4: i11iIiiIii - OOooOOo * IiII % OoooooooOO - OoOoOO00
  if 81 - 81: Ii1I * ooOoO0o . oO0o . IiII
  if 71 - 71: IiII + OoO0O00
  if ( oo0 . find ( "packet@" ) == 0 ) :
   Iii1iii1II = oo0 . split ( "@" )
   lprint ( "Received new message ({}-out-of-{}) while receiving " + "fragments, old message discarded" , len ( oo0 ) ,
   # i11iIiiIii + o0oOOo0O0Ooo
 Iii1iii1II [ 1 ] if len ( Iii1iii1II ) > 2 else "?" )
   return ( [ False , oo0 ] )
   if 30 - 30: O0 - O0 % iIii1I11I1II1 + iII111i * OoooooooOO
   if 1 - 1: O0
  OOOOO000oo0 -= len ( oo0 )
  packet += oo0
  if 36 - 36: oO0o . iII111i
  lprint ( "Received {}-out-of-{} byte segment from {}" . format ( len ( oo0 ) , total_length , source ) )
  if 62 - 62: I11i + iIii1I11I1II1 % I11i * OOooOOo + iIii1I11I1II1 % Ii1I
  if 56 - 56: o0oOOo0O0Ooo
 return ( [ True , packet ] )
 if 55 - 55: oO0o - I1Ii111 / ooOoO0o % I1IiiI * OoooooooOO * I1IiiI
 if 88 - 88: Ii1I + O0
 if 92 - 92: I1IiiI % iII111i % I11i + OoooooooOO - i11iIiiIii
 if 9 - 9: i11iIiiIii - II111iiii / ooOoO0o
 if 81 - 81: i11iIiiIii % OoOoOO00 % OoO0O00 * Ii1I
 if 85 - 85: OoooooooOO * ooOoO0o
 if 23 - 23: OOooOOo / I11i / OoooooooOO - Ii1I / OoO0O00 - OoO0O00
 if 60 - 60: OOooOOo . ooOoO0o % i1IIi % Ii1I % ooOoO0o + OoO0O00
def lisp_bit_stuff ( payload ) :
 lprint ( "Bit-stuffing, found {} segments" . format ( len ( payload ) ) )
 oOo = ""
 for oo0 in payload : oOo += oo0 + "\x40"
 return ( oOo [ : - 1 ] )
 if 26 - 26: O0 % o0oOOo0O0Ooo + iII111i * I1ii11iIi11i * I1Ii111
 if 4 - 4: OOooOOo * OoooooooOO * i1IIi % I1ii11iIi11i % Oo0Ooo
 if 1 - 1: OoO0O00 / iIii1I11I1II1 % I1ii11iIi11i - o0oOOo0O0Ooo
 if 62 - 62: I1Ii111 % II111iiii
 if 91 - 91: I11i % Ii1I - IiII + iIii1I11I1II1 * iIii1I11I1II1
 if 91 - 91: i11iIiiIii + Ii1I
 if 85 - 85: I11i % IiII
 if 68 - 68: Oo0Ooo . I1Ii111 - o0oOOo0O0Ooo * iIii1I11I1II1 - II111iiii % i1IIi
 if 58 - 58: I11i / i11iIiiIii * i11iIiiIii
 if 24 - 24: ooOoO0o - I1Ii111 * II111iiii - II111iiii
 if 47 - 47: IiII - iIii1I11I1II1 / OoOoOO00 * iII111i - iIii1I11I1II1 % oO0o
 if 93 - 93: Ii1I / iII111i
 if 100 - 100: Oo0Ooo
 if 94 - 94: I1ii11iIi11i / i1IIi * I1IiiI - I11i - I1ii11iIi11i
 if 6 - 6: I1ii11iIi11i % o0oOOo0O0Ooo + o0oOOo0O0Ooo / OOooOOo / I1IiiI
 if 67 - 67: OoOoOO00 . iII111i / OOooOOo * ooOoO0o + i1IIi
 if 100 - 100: OOooOOo . ooOoO0o + I1Ii111 . oO0o
 if 20 - 20: i11iIiiIii - i1IIi - iIii1I11I1II1 - OoooooooOO
 if 72 - 72: I1Ii111 . OoO0O00
 if 59 - 59: I1IiiI * I11i % i1IIi
def lisp_receive ( lisp_socket , internal ) :
 while ( True ) :
  if 77 - 77: OOooOOo * OoooooooOO + I1IiiI + I1IiiI % oO0o . OoooooooOO
  if 60 - 60: iIii1I11I1II1
  if 13 - 13: II111iiii + Ii1I
  if 33 - 33: i1IIi
  try : i1i1iIIiIi = lisp_socket . recvfrom ( 9000 )
  except : return ( [ "" , "" , "" , "" ] )
  if 94 - 94: Ii1I - iIii1I11I1II1 % I1ii11iIi11i . OOooOOo / O0
  if 64 - 64: Ii1I % I1IiiI * OoO0O00
  if 41 - 41: iIii1I11I1II1 / oO0o * oO0o - II111iiii + OOooOOo + i1IIi
  if 1 - 1: iII111i + I1IiiI
  if 34 - 34: OoO0O00
  if 71 - 71: OoOoOO00 + iII111i - I1IiiI
  if ( internal == False ) :
   oOo = i1i1iIIiIi [ 0 ]
   oo = lisp_convert_6to4 ( i1i1iIIiIi [ 1 ] [ 0 ] )
   Iiiii = i1i1iIIiIi [ 1 ] [ 1 ]
   if 80 - 80: OoO0O00 . ooOoO0o
   if ( Iiiii == LISP_DATA_PORT ) :
    O0oO0 = lisp_data_plane_logging
    oO0o00 = lisp_format_packet ( oOo [ 0 : 60 ] ) + " ..."
   else :
    O0oO0 = True
    oO0o00 = lisp_format_packet ( oOo )
    if 57 - 57: iIii1I11I1II1 % I1ii11iIi11i
    if 38 - 38: iIii1I11I1II1 . i11iIiiIii % oO0o
   if ( O0oO0 ) :
    lprint ( "{} {} bytes {} {}, packet: {}" . format ( bold ( "Receive" ,
 False ) , len ( oOo ) , bold ( "from " + oo , False ) , Iiiii ,
 oO0o00 ) )
    if 92 - 92: I11i
   return ( [ "packet" , oo , Iiiii , oOo ] )
   if 96 - 96: O0 / i1IIi - i11iIiiIii / OoOoOO00 + OoooooooOO
   if 12 - 12: oO0o . OOooOOo
   if 76 - 76: oO0o - I11i * I1Ii111 . oO0o % iIii1I11I1II1
   if 86 - 86: OoooooooOO + I1Ii111
   if 5 - 5: I1ii11iIi11i
   if 89 - 89: OoO0O00 - OoOoOO00 / II111iiii . I1ii11iIi11i
  I111iiiI11ii = False
  i11 = i1i1iIIiIi [ 0 ]
  oooOOOo0 = False
  if 28 - 28: OoO0O00 * i11iIiiIii % OoO0O00
  while ( I111iiiI11ii == False ) :
   i11 = i11 . split ( "@" )
   if 84 - 84: oO0o . I1Ii111
   if ( len ( i11 ) < 4 ) :
    lprint ( "Possible fragment (length {}), from old message, " + "discarding" , len ( i11 [ 0 ] ) )
    if 100 - 100: OoOoOO00 + OoOoOO00
    oooOOOo0 = True
    break
    if 26 - 26: II111iiii * iII111i + OOooOOo
    if 28 - 28: Ii1I + O0
   iII1IiI1i = i11 [ 0 ]
   try :
    o000oO = int ( i11 [ 1 ] )
   except :
    iI1iI1I = bold ( "Internal packet reassembly error" , False )
    lprint ( "{}: {}" . format ( iI1iI1I , i1i1iIIiIi ) )
    oooOOOo0 = True
    break
    if 2 - 2: ooOoO0o % OoO0O00
   oo = i11 [ 2 ]
   Iiiii = i11 [ 3 ]
   if 31 - 31: iII111i * iIii1I11I1II1 - I1ii11iIi11i
   if 20 - 20: OoooooooOO
   if 77 - 77: Oo0Ooo - ooOoO0o
   if 68 - 68: Ii1I * O0
   if 61 - 61: II111iiii - OoO0O00 . iIii1I11I1II1 * o0oOOo0O0Ooo . OoO0O00 % IiII
   if 11 - 11: oO0o + I11i
   if 6 - 6: i1IIi . o0oOOo0O0Ooo + OoO0O00 + OOooOOo + oO0o
   if 30 - 30: O0
   if ( len ( i11 ) > 5 ) :
    oOo = lisp_bit_stuff ( i11 [ 4 : : ] )
   else :
    oOo = i11 [ 4 ]
    if 98 - 98: I1Ii111
    if 58 - 58: OOooOOo
    if 6 - 6: I1ii11iIi11i
    if 37 - 37: i11iIiiIii . II111iiii + OOooOOo + i1IIi * OOooOOo
    if 18 - 18: ooOoO0o
    if 18 - 18: I1Ii111 + OoOoOO00 % OOooOOo - IiII - i1IIi + I1ii11iIi11i
   I111iiiI11ii , oOo = lisp_receive_segments ( lisp_socket , oOo ,
 oo , o000oO )
   if ( oOo == None ) : return ( [ "" , "" , "" , "" ] )
   if 33 - 33: I11i * Ii1I / Oo0Ooo + oO0o % OOooOOo % OoooooooOO
   if 29 - 29: Ii1I . II111iiii / I1Ii111
   if 79 - 79: IiII . OoOoOO00 / oO0o % OoO0O00 / Ii1I + I11i
   if 78 - 78: o0oOOo0O0Ooo + I1Ii111 % i11iIiiIii % I1IiiI - Ii1I
   if 81 - 81: i11iIiiIii - II111iiii + I11i
   if ( I111iiiI11ii == False ) :
    i11 = oOo
    continue
    if 52 - 52: II111iiii
    if 62 - 62: iII111i / OoO0O00 + i11iIiiIii / Oo0Ooo
   if ( Iiiii == "" ) : Iiiii = "no-port"
   if ( iII1IiI1i == "command" and lisp_i_am_core == False ) :
    oo0OOo0O = oOo . find ( " {" )
    iIIiIiiI = oOo if oo0OOo0O == - 1 else oOo [ : oo0OOo0O ]
    iIIiIiiI = ": '" + iIIiIiiI + "'"
   else :
    iIIiIiiI = ""
    if 60 - 60: iIii1I11I1II1
    if 70 - 70: I11i
   lprint ( "{} {} bytes {} {}, {}{}" . format ( bold ( "Receive" , False ) ,
 len ( oOo ) , bold ( "from " + oo , False ) , Iiiii , iII1IiI1i ,
 iIIiIiiI if ( iII1IiI1i in [ "command" , "api" ] ) else ": ... " if ( iII1IiI1i == "data-packet" ) else ": " + lisp_format_packet ( oOo ) ) )
   if 38 - 38: o0oOOo0O0Ooo . OoO0O00 + I1ii11iIi11i - I1IiiI * i1IIi
   if 17 - 17: OoO0O00 % o0oOOo0O0Ooo
   if 21 - 21: OOooOOo + OOooOOo - i11iIiiIii * IiII % iIii1I11I1II1
   if 86 - 86: ooOoO0o + OoOoOO00
   if 94 - 94: IiII
  if ( oooOOOo0 ) : continue
  return ( [ iII1IiI1i , oo , Iiiii , oOo ] )
  if 30 - 30: o0oOOo0O0Ooo % OoOoOO00 * IiII % iIii1I11I1II1 % O0
  if 76 - 76: II111iiii * I11i
  if 29 - 29: OoooooooOO . i1IIi
  if 46 - 46: I11i
  if 92 - 92: IiII * OoO0O00 . OoOoOO00 + iII111i - I1IiiI
  if 15 - 15: OoO0O00 / OoO0O00 * o0oOOo0O0Ooo * I1ii11iIi11i - o0oOOo0O0Ooo
  if 47 - 47: I1IiiI / OoOoOO00 / II111iiii
  if 7 - 7: oO0o . ooOoO0o
def lisp_parse_packet ( lisp_sockets , packet , source , udp_sport , ttl = - 1 ) :
 Oo0000O0o0 = False
 if 99 - 99: IiII / i11iIiiIii - II111iiii . ooOoO0o
 oooooOOo0Oo = lisp_control_header ( )
 if ( oooooOOo0Oo . decode ( packet ) == None ) :
  lprint ( "Could not decode control header" )
  return ( Oo0000O0o0 )
  if 29 - 29: OoO0O00 - Ii1I
  if 35 - 35: IiII
  if 99 - 99: iIii1I11I1II1 % I1Ii111 . IiII
  if 7 - 7: OOooOOo + II111iiii + I1IiiI . Oo0Ooo / iIii1I11I1II1 . oO0o
  if 30 - 30: OoO0O00 / OOooOOo
 O0oOOoO0O0 = source
 if ( source . find ( "lisp" ) == - 1 ) :
  o00oOOO = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  o00oOOO . string_to_afi ( source )
  o00oOOO . store_address ( source )
  source = o00oOOO
  if 80 - 80: oO0o
  if 21 - 21: iII111i + OoOoOO00 - i11iIiiIii % O0 + OOooOOo
 if ( oooooOOo0Oo . type == LISP_MAP_REQUEST ) :
  lisp_process_map_request ( lisp_sockets , packet , None , 0 , source ,
 udp_sport , False , ttl )
  if 30 - 30: o0oOOo0O0Ooo - Oo0Ooo + iII111i / O0
 elif ( oooooOOo0Oo . type == LISP_MAP_REPLY ) :
  lisp_process_map_reply ( lisp_sockets , packet , source , ttl )
  if 94 - 94: IiII
 elif ( oooooOOo0Oo . type == LISP_MAP_REGISTER ) :
  lisp_process_map_register ( lisp_sockets , packet , source , udp_sport )
  if 69 - 69: I1Ii111 . I1Ii111
 elif ( oooooOOo0Oo . type == LISP_MAP_NOTIFY ) :
  if ( O0oOOoO0O0 == "lisp-etr" ) :
   lisp_process_multicast_map_notify ( packet , source )
  else :
   if ( lisp_is_running ( "lisp-rtr" ) ) :
    lisp_process_multicast_map_notify ( packet , source )
    if 53 - 53: i11iIiiIii + iII111i * Oo0Ooo - I1Ii111
   lisp_process_map_notify ( lisp_sockets , packet , source )
   if 61 - 61: o0oOOo0O0Ooo / OOooOOo . II111iiii - I1IiiI * i11iIiiIii
   if 8 - 8: iII111i % o0oOOo0O0Ooo
 elif ( oooooOOo0Oo . type == LISP_MAP_NOTIFY_ACK ) :
  lisp_process_map_notify_ack ( packet , source )
  if 87 - 87: Ii1I % I11i / I1Ii111
 elif ( oooooOOo0Oo . type == LISP_MAP_REFERRAL ) :
  lisp_process_map_referral ( lisp_sockets , packet , source )
  if 21 - 21: OoO0O00 + Ii1I / I1Ii111
 elif ( oooooOOo0Oo . type == LISP_NAT_INFO and oooooOOo0Oo . is_info_reply ( ) ) :
  IiiIii1111Ii1I1 , iIIIIi , Oo0000O0o0 = lisp_process_info_reply ( source , packet , True )
  if 75 - 75: I1Ii111 . Ii1I % iIii1I11I1II1 / OoOoOO00
 elif ( oooooOOo0Oo . type == LISP_NAT_INFO and oooooOOo0Oo . is_info_reply ( ) == False ) :
  ooOOo0o = source . print_address_no_iid ( )
  lisp_process_info_request ( lisp_sockets , packet , ooOOo0o , udp_sport ,
 None )
  if 38 - 38: i1IIi
 elif ( oooooOOo0Oo . type == LISP_ECM ) :
  lisp_process_ecm ( lisp_sockets , packet , source , udp_sport )
  if 1 - 1: I1ii11iIi11i + OoO0O00 % I11i . OOooOOo + i1IIi / oO0o
 else :
  lprint ( "Invalid LISP control packet type {}" . format ( oooooOOo0Oo . type ) )
  if 35 - 35: ooOoO0o % OoOoOO00 % OoO0O00 + OOooOOo / IiII * OoOoOO00
 return ( Oo0000O0o0 )
 if 65 - 65: I1IiiI . Oo0Ooo + i1IIi - Ii1I * i1IIi
 if 64 - 64: I1IiiI / OoO0O00 * I1IiiI * II111iiii . Ii1I
 if 98 - 98: I1Ii111 + o0oOOo0O0Ooo
 if 73 - 73: I1ii11iIi11i / I1Ii111 + i11iIiiIii + OoO0O00 . ooOoO0o
 if 54 - 54: I1ii11iIi11i + IiII - oO0o + Oo0Ooo / IiII % Oo0Ooo
 if 2 - 2: OOooOOo / I11i * I11i + I11i / O0 - OOooOOo
 if 29 - 29: OoOoOO00 + i11iIiiIii % OoO0O00 - OoooooooOO
def lisp_process_rloc_probe_request ( lisp_sockets , map_request , source , port ,
 ttl ) :
 if 68 - 68: iII111i / OOooOOo
 i111 = bold ( "RLOC-probe" , False )
 if 28 - 28: II111iiii
 if ( lisp_i_am_etr ) :
  lprint ( "Received {} Map-Request, send RLOC-probe Map-Reply" . format ( i111 ) )
  lisp_etr_process_map_request ( lisp_sockets , map_request , source , port ,
 ttl )
  return
  if 49 - 49: I1ii11iIi11i
  if 33 - 33: iIii1I11I1II1
 if ( lisp_i_am_rtr ) :
  lprint ( "Received {} Map-Request, send RLOC-probe Map-Reply" . format ( i111 ) )
  lisp_rtr_process_map_request ( lisp_sockets , map_request , source , port ,
 ttl )
  return
  if 72 - 72: I1ii11iIi11i * i11iIiiIii
  if 12 - 12: O0 - iIii1I11I1II1 % Oo0Ooo / O0 - IiII
 lprint ( "Ignoring received {} Map-Request, not an ETR or RTR" . format ( i111 ) )
 return
 if 55 - 55: OOooOOo . Oo0Ooo * OoOoOO00 / OoooooooOO * i11iIiiIii + oO0o
 if 45 - 45: Ii1I
 if 8 - 8: oO0o + OOooOOo
 if 37 - 37: IiII - OoOoOO00 + oO0o - Oo0Ooo + IiII
 if 33 - 33: Oo0Ooo % oO0o - I1IiiI + Oo0Ooo
def lisp_process_smr ( map_request ) :
 lprint ( "Received SMR-based Map-Request" )
 return
 if 90 - 90: I1ii11iIi11i * I1Ii111 - iIii1I11I1II1 % IiII * I1Ii111 . I1Ii111
 if 90 - 90: o0oOOo0O0Ooo - O0 % O0 - oO0o . OoooooooOO
 if 30 - 30: I11i + O0 / Ii1I / OoOoOO00 - oO0o + II111iiii
 if 21 - 21: iIii1I11I1II1 % OoooooooOO * OOooOOo % i1IIi
 if 73 - 73: OoooooooOO
def lisp_process_smr_invoked_request ( map_request ) :
 lprint ( "Received SMR-invoked Map-Request" )
 return
 if 100 - 100: I11i / i1IIi / i1IIi % Ii1I - II111iiii . OoooooooOO
 if 72 - 72: Oo0Ooo * OoooooooOO % I1IiiI + I11i - II111iiii
 if 82 - 82: iIii1I11I1II1 / i1IIi * I1IiiI . i11iIiiIii
 if 56 - 56: Ii1I * I1IiiI / ooOoO0o * II111iiii
 if 51 - 51: i1IIi . oO0o % OOooOOo
 if 90 - 90: OoooooooOO + iII111i / iIii1I11I1II1
 if 12 - 12: OoooooooOO
def lisp_build_map_reply ( eid , group , rloc_set , nonce , action , ttl , rloc_probe ,
 keys , enc , auth , mr_ttl = - 1 ) :
 Iiii = lisp_map_reply ( )
 Iiii . rloc_probe = rloc_probe
 Iiii . echo_nonce_capable = enc
 Iiii . hop_count = 0 if ( mr_ttl == - 1 ) else mr_ttl
 Iiii . record_count = 1
 Iiii . nonce = nonce
 oOo = Iiii . encode ( )
 Iiii . print_map_reply ( )
 if 60 - 60: oO0o . ooOoO0o
 IiII1iiI = lisp_eid_record ( )
 IiII1iiI . rloc_count = len ( rloc_set )
 IiII1iiI . authoritative = auth
 IiII1iiI . record_ttl = ttl
 IiII1iiI . action = action
 IiII1iiI . eid = eid
 IiII1iiI . group = group
 if 68 - 68: OoooooooOO . OoooooooOO % I1ii11iIi11i + i1IIi % OoooooooOO + Ii1I
 oOo += IiII1iiI . encode ( )
 IiII1iiI . print_record ( "  " , False )
 if 89 - 89: ooOoO0o + I11i * O0 % OoOoOO00
 I1iiI1ii1i = lisp_get_all_addresses ( ) + lisp_get_all_translated_rlocs ( )
 if 73 - 73: IiII . ooOoO0o / Oo0Ooo / OoOoOO00 . II111iiii
 for O0OO0O in rloc_set :
  o00o = lisp_rloc_record ( )
  ooOOo0o = O0OO0O . rloc . print_address_no_iid ( )
  if ( ooOOo0o in I1iiI1ii1i ) :
   o00o . local_bit = True
   o00o . probe_bit = rloc_probe
   o00o . keys = keys
   if ( O0OO0O . priority == 254 and lisp_i_am_rtr ) :
    o00o . rloc_name = "RTR"
    if 40 - 40: ooOoO0o - O0 - IiII - Ii1I % IiII / Ii1I
    if 98 - 98: Ii1I * Oo0Ooo - O0 % OoOoOO00 + I1ii11iIi11i . II111iiii
  o00o . store_rloc_entry ( O0OO0O )
  o00o . reach_bit = True
  o00o . print_record ( "    " )
  oOo += o00o . encode ( )
  if 92 - 92: Oo0Ooo * IiII - Ii1I . OoOoOO00 / iIii1I11I1II1 . OOooOOo
 return ( oOo )
 if 53 - 53: i11iIiiIii
 if 50 - 50: i11iIiiIii / i1IIi + i1IIi / Ii1I . o0oOOo0O0Ooo + OoOoOO00
 if 29 - 29: I1ii11iIi11i % OOooOOo - I1IiiI / iII111i % OoOoOO00
 if 15 - 15: o0oOOo0O0Ooo / OOooOOo % I1IiiI - I1IiiI / i1IIi * Ii1I
 if 90 - 90: ooOoO0o % o0oOOo0O0Ooo * Ii1I . o0oOOo0O0Ooo + o0oOOo0O0Ooo * OoOoOO00
 if 40 - 40: iIii1I11I1II1 - i11iIiiIii / i1IIi / II111iiii
 if 37 - 37: Ii1I + o0oOOo0O0Ooo
def lisp_build_map_referral ( eid , group , ddt_entry , action , ttl , nonce ) :
 OOOoo = lisp_map_referral ( )
 OOOoo . record_count = 1
 OOOoo . nonce = nonce
 oOo = OOOoo . encode ( )
 OOOoo . print_map_referral ( )
 if 23 - 23: OoooooooOO + Oo0Ooo + iIii1I11I1II1
 IiII1iiI = lisp_eid_record ( )
 if 36 - 36: iIii1I11I1II1 - Ii1I
 iI1111i = 0
 if ( ddt_entry == None ) :
  IiII1iiI . eid = eid
  IiII1iiI . group = group
 else :
  iI1111i = len ( ddt_entry . delegation_set )
  IiII1iiI . eid = ddt_entry . eid
  IiII1iiI . group = ddt_entry . group
  ddt_entry . map_referrals_sent += 1
  if 54 - 54: I1IiiI
 IiII1iiI . rloc_count = iI1111i
 IiII1iiI . authoritative = True
 if 92 - 92: O0 * OoooooooOO - i11iIiiIii % I1IiiI / Oo0Ooo - Oo0Ooo
 if 26 - 26: i1IIi - II111iiii - Ii1I * i1IIi * OoOoOO00
 if 99 - 99: IiII / oO0o % ooOoO0o / Oo0Ooo * OoO0O00
 if 43 - 43: ooOoO0o
 if 86 - 86: ooOoO0o
 o000ooo0o0O = False
 if ( action == LISP_DDT_ACTION_NULL ) :
  if ( iI1111i == 0 ) :
   action = LISP_DDT_ACTION_NODE_REFERRAL
  else :
   oOoI1I = ddt_entry . delegation_set [ 0 ]
   if ( oOoI1I . is_ddt_child ( ) ) :
    action = LISP_DDT_ACTION_NODE_REFERRAL
    if 65 - 65: OoOoOO00
   if ( oOoI1I . is_ms_child ( ) ) :
    action = LISP_DDT_ACTION_MS_REFERRAL
    if 15 - 15: Ii1I - OoOoOO00
    if 27 - 27: O0
    if 86 - 86: IiII + Ii1I / Oo0Ooo / O0 % iII111i - oO0o
    if 3 - 3: i11iIiiIii / I1ii11iIi11i % I1Ii111 + o0oOOo0O0Ooo + O0
    if 42 - 42: IiII / i11iIiiIii % o0oOOo0O0Ooo / II111iiii / IiII
    if 97 - 97: OOooOOo . OoOoOO00 / I11i - IiII - iIii1I11I1II1
    if 82 - 82: II111iiii + OoO0O00 % iIii1I11I1II1 / O0
 if ( action == LISP_DDT_ACTION_NOT_AUTH ) : o000ooo0o0O = True
 if ( action in ( LISP_DDT_ACTION_MS_REFERRAL , LISP_DDT_ACTION_MS_ACK ) ) :
  o000ooo0o0O = ( lisp_i_am_ms and oOoI1I . is_ms_peer ( ) == False )
  if 75 - 75: OOooOOo * OoO0O00 + OoooooooOO + i11iIiiIii . OoO0O00
  if 94 - 94: I11i * ooOoO0o . I1IiiI / Ii1I - I1IiiI % OoooooooOO
 IiII1iiI . action = action
 IiII1iiI . ddt_incomplete = o000ooo0o0O
 IiII1iiI . record_ttl = ttl
 if 32 - 32: OoO0O00
 oOo += IiII1iiI . encode ( )
 IiII1iiI . print_record ( "  " , True )
 if 22 - 22: II111iiii . I11i
 if ( iI1111i == 0 ) : return ( oOo )
 if 61 - 61: OOooOOo % O0 . I1ii11iIi11i . iIii1I11I1II1 * I11i
 for oOoI1I in ddt_entry . delegation_set :
  o00o = lisp_rloc_record ( )
  o00o . rloc = oOoI1I . delegate_address
  o00o . priority = oOoI1I . priority
  o00o . weight = oOoI1I . weight
  o00o . mpriority = 255
  o00o . mweight = 0
  o00o . reach_bit = True
  oOo += o00o . encode ( )
  o00o . print_record ( "    " )
  if 29 - 29: ooOoO0o + i1IIi % IiII * Ii1I
 return ( oOo )
 if 94 - 94: OOooOOo / IiII
 if 18 - 18: IiII - I11i / Ii1I % IiII * i1IIi
 if 22 - 22: OoOoOO00 - Oo0Ooo
 if 41 - 41: iIii1I11I1II1 * I1Ii111 / OoO0O00
 if 33 - 33: I11i + O0
 if 9 - 9: I11i . iII111i * ooOoO0o * ooOoO0o
 if 68 - 68: O0 - i11iIiiIii % iIii1I11I1II1 % ooOoO0o
def lisp_etr_process_map_request ( lisp_sockets , map_request , source , sport ,
 ttl ) :
 if 12 - 12: II111iiii + I11i
 if ( map_request . target_group . is_null ( ) ) :
  iIiIIi1i = lisp_db_for_lookups . lookup_cache ( map_request . target_eid , False )
 else :
  iIiIIi1i = lisp_db_for_lookups . lookup_cache ( map_request . target_group , False )
  if ( iIiIIi1i ) : iIiIIi1i = iIiIIi1i . lookup_source_cache ( map_request . target_eid , False )
  if 92 - 92: Ii1I % o0oOOo0O0Ooo
 oO00oo000O = map_request . print_prefix ( )
 if 55 - 55: I11i + ooOoO0o / ooOoO0o % I1ii11iIi11i
 if ( iIiIIi1i == None ) :
  lprint ( "Database-mapping entry not found for requested EID {}" . format ( green ( oO00oo000O , False ) ) )
  if 84 - 84: O0 + IiII - I1IiiI - I1Ii111 / OoooooooOO
  return
  if 76 - 76: i11iIiiIii - Ii1I * I1ii11iIi11i + oO0o - OOooOOo
  if 42 - 42: o0oOOo0O0Ooo
 I11Ii11ii = iIiIIi1i . print_eid_tuple ( )
 if 72 - 72: ooOoO0o / iII111i + iII111i % i11iIiiIii . i1IIi
 lprint ( "Found database-mapping EID-prefix {} for requested EID {}" . format ( green ( I11Ii11ii , False ) , green ( oO00oo000O , False ) ) )
 if 53 - 53: oO0o
 if 76 - 76: Ii1I % I1Ii111 % i1IIi
 if 4 - 4: I11i % IiII - II111iiii - OoooooooOO / OOooOOo
 if 44 - 44: IiII - OoooooooOO * O0 + II111iiii + IiII
 if 82 - 82: OoO0O00 + OOooOOo + O0
 o0oi1iIiii1I1ii = map_request . itr_rlocs [ 0 ]
 if ( o0oi1iIiii1I1ii . is_private_address ( ) and lisp_nat_traversal ) :
  o0oi1iIiii1I1ii = source
  if 85 - 85: II111iiii * I1Ii111 / ooOoO0o
  if 23 - 23: I1Ii111
 i11III1I = map_request . nonce
 O0o00oo = lisp_nonce_echoing
 i1iIi = map_request . keys
 if 52 - 52: iIii1I11I1II1
 iIiIIi1i . map_replies_sent += 1
 if 47 - 47: iIii1I11I1II1 + i1IIi % I1ii11iIi11i % O0 * Ii1I
 oOo = lisp_build_map_reply ( iIiIIi1i . eid , iIiIIi1i . group , iIiIIi1i . rloc_set , i11III1I ,
 LISP_NO_ACTION , 1440 , map_request . rloc_probe , i1iIi , O0o00oo , True , ttl )
 if 85 - 85: I1Ii111 + I1Ii111 + OoOoOO00 / ooOoO0o / o0oOOo0O0Ooo . Oo0Ooo
 if 41 - 41: i1IIi % Ii1I . i1IIi * OoooooooOO % Ii1I
 if 21 - 21: iII111i
 if 72 - 72: I11i % o0oOOo0O0Ooo . iIii1I11I1II1 - I1Ii111 / i11iIiiIii
 if 75 - 75: OoooooooOO
 if 24 - 24: oO0o % iII111i - II111iiii / Ii1I + O0
 if 37 - 37: I1Ii111 - i1IIi / iIii1I11I1II1
 if 53 - 53: Ii1I - iIii1I11I1II1 % I1ii11iIi11i * i11iIiiIii + ooOoO0o
 if 63 - 63: Oo0Ooo * I1IiiI
 if 84 - 84: Oo0Ooo
 if 67 - 67: oO0o / II111iiii . I11i / oO0o
 if 46 - 46: oO0o * Oo0Ooo - I11i / iIii1I11I1II1
 if 100 - 100: i11iIiiIii % oO0o
 if 62 - 62: OOooOOo * i1IIi - OOooOOo / i11iIiiIii
 if 17 - 17: I1ii11iIi11i + ooOoO0o % Ii1I % OOooOOo
 if 73 - 73: i11iIiiIii
 if ( map_request . rloc_probe and len ( lisp_sockets ) == 4 ) :
  ooo0ooOoOOoO = ( o0oi1iIiii1I1ii . is_private_address ( ) == False )
  Ii111iI1iI1ii = o0oi1iIiii1I1ii . print_address_no_iid ( )
  if ( ( ooo0ooOoOOoO and lisp_rtr_list . has_key ( Ii111iI1iI1ii ) ) or sport == 0 ) :
   lisp_encapsulate_rloc_probe ( lisp_sockets , o0oi1iIiii1I1ii , None , oOo )
   return
   if 44 - 44: o0oOOo0O0Ooo % Ii1I - OoOoOO00 + OoOoOO00 * IiII + iII111i
   if 58 - 58: I1ii11iIi11i / oO0o + i11iIiiIii * o0oOOo0O0Ooo
   if 19 - 19: OoOoOO00
   if 17 - 17: Oo0Ooo
   if 76 - 76: II111iiii % I1ii11iIi11i
   if 99 - 99: oO0o - I1Ii111
 lisp_send_map_reply ( lisp_sockets , oOo , o0oi1iIiii1I1ii , sport )
 return
 if 29 - 29: I1IiiI - I11i
 if 42 - 42: Oo0Ooo - O0 . OoOoOO00
 if 4 - 4: IiII
 if 2 - 2: iII111i
 if 47 - 47: i1IIi % I11i
 if 17 - 17: OoOoOO00 - iII111i % I11i / o0oOOo0O0Ooo / II111iiii
 if 22 - 22: Oo0Ooo + I1ii11iIi11i % i11iIiiIii . OoO0O00 - I11i % I11i
def lisp_rtr_process_map_request ( lisp_sockets , map_request , source , sport ,
 ttl ) :
 if 21 - 21: I1IiiI . OoO0O00 * IiII % OoooooooOO - Oo0Ooo + Oo0Ooo
 if 94 - 94: ooOoO0o
 if 80 - 80: i11iIiiIii - O0 / I1Ii111 + OOooOOo % Oo0Ooo
 if 95 - 95: II111iiii
 o0oi1iIiii1I1ii = map_request . itr_rlocs [ 0 ]
 if ( o0oi1iIiii1I1ii . is_private_address ( ) ) : o0oi1iIiii1I1ii = source
 i11III1I = map_request . nonce
 if 76 - 76: OoO0O00 % iII111i * OoOoOO00 / ooOoO0o / i1IIi
 Oo00o = map_request . target_eid
 i1i11Ii1 = map_request . target_group
 if 45 - 45: Ii1I . I11i * I1Ii111 . i11iIiiIii
 iiiI11II1IiIi = [ ]
 for iIIII1iiIII in [ lisp_myrlocs [ 0 ] , lisp_myrlocs [ 1 ] ] :
  if ( iIIII1iiIII == None ) : continue
  Oo0o0o0oo = lisp_rloc ( )
  Oo0o0o0oo . rloc . copy_address ( iIIII1iiIII )
  Oo0o0o0oo . priority = 254
  iiiI11II1IiIi . append ( Oo0o0o0oo )
  if 68 - 68: ooOoO0o % OoooooooOO
  if 94 - 94: Oo0Ooo * o0oOOo0O0Ooo
 O0o00oo = lisp_nonce_echoing
 i1iIi = map_request . keys
 if 60 - 60: iII111i . OOooOOo
 oOo = lisp_build_map_reply ( Oo00o , i1i11Ii1 , iiiI11II1IiIi , i11III1I , LISP_NO_ACTION ,
 1440 , True , i1iIi , O0o00oo , True , ttl )
 lisp_send_map_reply ( lisp_sockets , oOo , o0oi1iIiii1I1ii , sport )
 return
 if 39 - 39: O0 - i11iIiiIii - I1IiiI / Oo0Ooo - i11iIiiIii
 if 30 - 30: OoO0O00 / OoOoOO00 + I1ii11iIi11i % IiII - OoO0O00
 if 19 - 19: I1IiiI
 if 99 - 99: OOooOOo - OOooOOo
 if 98 - 98: o0oOOo0O0Ooo + O0 * oO0o - i11iIiiIii
 if 83 - 83: o0oOOo0O0Ooo
 if 23 - 23: o0oOOo0O0Ooo . I11i
 if 67 - 67: iII111i
 if 52 - 52: IiII . OoooooooOO
 if 34 - 34: o0oOOo0O0Ooo / IiII . OoooooooOO . Oo0Ooo / ooOoO0o + O0
def lisp_get_private_rloc_set ( target_site_eid , seid , group ) :
 iiiI11II1IiIi = target_site_eid . registered_rlocs
 if 38 - 38: I11i
 oOOoO = lisp_site_eid_lookup ( seid , group , False )
 if ( oOOoO == None ) : return ( iiiI11II1IiIi )
 if 79 - 79: I1IiiI * OOooOOo - I11i
 if 60 - 60: o0oOOo0O0Ooo - OoO0O00 . O0 - i11iIiiIii . I1IiiI
 if 95 - 95: OoooooooOO / ooOoO0o * I11i - Ii1I
 if 94 - 94: I1Ii111 + OoO0O00 . OoooooooOO
 o0oI1 = None
 Oo = [ ]
 for O0OO0O in iiiI11II1IiIi :
  if ( O0OO0O . is_rtr ( ) ) : continue
  if ( O0OO0O . rloc . is_private_address ( ) ) :
   oo0OOOoOOOo0 = copy . deepcopy ( O0OO0O )
   Oo . append ( oo0OOOoOOOo0 )
   continue
   if 90 - 90: Ii1I * I11i % I1Ii111 - I1ii11iIi11i * I1Ii111 % OoO0O00
  o0oI1 = O0OO0O
  break
  if 50 - 50: iIii1I11I1II1
 if ( o0oI1 == None ) : return ( iiiI11II1IiIi )
 o0oI1 = o0oI1 . rloc . print_address_no_iid ( )
 if 56 - 56: oO0o
 if 55 - 55: iIii1I11I1II1 % oO0o % OOooOOo / I1Ii111 * OoooooooOO / Oo0Ooo
 if 88 - 88: I11i + OoO0O00 . iIii1I11I1II1 . II111iiii
 if 67 - 67: OOooOOo - ooOoO0o % iII111i % IiII
 OOO0OOoo = None
 for O0OO0O in oOOoO . registered_rlocs :
  if ( O0OO0O . is_rtr ( ) ) : continue
  if ( O0OO0O . rloc . is_private_address ( ) ) : continue
  OOO0OOoo = O0OO0O
  break
  if 5 - 5: o0oOOo0O0Ooo + OoO0O00
 if ( OOO0OOoo == None ) : return ( iiiI11II1IiIi )
 OOO0OOoo = OOO0OOoo . rloc . print_address_no_iid ( )
 if 28 - 28: OOooOOo
 if 56 - 56: II111iiii
 if 80 - 80: o0oOOo0O0Ooo . oO0o . I1Ii111
 if 26 - 26: i1IIi - I1IiiI + IiII / OoO0O00 . I1ii11iIi11i
 OOOoooO0o0o = target_site_eid . site_id
 if ( OOOoooO0o0o == 0 ) :
  if ( OOO0OOoo == o0oI1 ) :
   lprint ( "Return private RLOCs for sites behind {}" . format ( o0oI1 ) )
   if 82 - 82: I1Ii111 % iII111i . OoOoOO00 % OoO0O00 + I1ii11iIi11i
   return ( Oo )
   if 69 - 69: I1IiiI * OoOoOO00 - ooOoO0o . O0
  return ( iiiI11II1IiIi )
  if 15 - 15: oO0o . IiII + I1Ii111 - OoooooooOO
  if 85 - 85: II111iiii - Oo0Ooo + oO0o . i11iIiiIii + Oo0Ooo
  if 86 - 86: ooOoO0o . OoO0O00
  if 47 - 47: IiII % I1IiiI
  if 91 - 91: Ii1I
  if 69 - 69: iII111i
  if 96 - 96: Ii1I
 if ( OOOoooO0o0o == oOOoO . site_id ) :
  lprint ( "Return private RLOCs for sites in site-id {}" . format ( OOOoooO0o0o ) )
  return ( Oo )
  if 39 - 39: OoO0O00 - I1IiiI % II111iiii - IiII * I1ii11iIi11i
 return ( iiiI11II1IiIi )
 if 64 - 64: OOooOOo + Oo0Ooo . OoOoOO00 . OOooOOo + i11iIiiIii
 if 7 - 7: ooOoO0o * I11i / iIii1I11I1II1
 if 15 - 15: OoooooooOO / iII111i
 if 40 - 40: o0oOOo0O0Ooo
 if 75 - 75: oO0o - OoOoOO00 * ooOoO0o . O0
 if 78 - 78: Oo0Ooo
 if 74 - 74: O0 / I11i
 if 52 - 52: I1IiiI + oO0o * II111iiii
 if 15 - 15: I11i
def lisp_get_partial_rloc_set ( registered_rloc_set , mr_source , multicast ) :
 oo0i11i11ii11 = [ ]
 iiiI11II1IiIi = [ ]
 if 49 - 49: iII111i % OoooooooOO
 if 85 - 85: I1ii11iIi11i * OOooOOo - I1IiiI
 if 76 - 76: iIii1I11I1II1
 if 94 - 94: O0
 if 50 - 50: I1Ii111 * o0oOOo0O0Ooo - ooOoO0o - I1ii11iIi11i % I1IiiI . ooOoO0o
 if 35 - 35: Ii1I % i1IIi + I1IiiI
 o0Ooo = False
 Oo000oo0ooooO = False
 for O0OO0O in registered_rloc_set :
  if ( O0OO0O . priority != 254 ) : continue
  Oo000oo0ooooO |= True
  if ( O0OO0O . rloc . is_exact_match ( mr_source ) == False ) : continue
  o0Ooo = True
  break
  if 53 - 53: i11iIiiIii / i1IIi . i1IIi + I11i
  if 19 - 19: ooOoO0o . OoOoOO00 + Oo0Ooo + iIii1I11I1II1 . OoOoOO00 - I1IiiI
  if 70 - 70: OOooOOo . OoOoOO00 . OOooOOo / iII111i
  if 72 - 72: OoooooooOO + Ii1I + iIii1I11I1II1
  if 13 - 13: iII111i . I1Ii111 % ooOoO0o / i1IIi
  if 64 - 64: iII111i
  if 9 - 9: I1ii11iIi11i + Oo0Ooo * I11i / I1Ii111 / I1ii11iIi11i / oO0o
 if ( Oo000oo0ooooO == False ) : return ( registered_rloc_set )
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
 OOOO = ( os . getenv ( "LISP_RTR_BEHIND_NAT" ) != None )
 if 73 - 73: i11iIiiIii . OoO0O00 + ooOoO0o
 if 77 - 77: ooOoO0o . I11i + OoooooooOO
 if 100 - 100: ooOoO0o . oO0o % I1ii11iIi11i . IiII * IiII - o0oOOo0O0Ooo
 if 49 - 49: iIii1I11I1II1 % Ii1I / OoooooooOO - II111iiii . Ii1I
 if 65 - 65: OoooooooOO + I1Ii111 % ooOoO0o + II111iiii . i1IIi + OoooooooOO
 for O0OO0O in registered_rloc_set :
  if ( OOOO and O0OO0O . rloc . is_private_address ( ) ) : continue
  if ( multicast == False and O0OO0O . priority == 255 ) : continue
  if ( multicast and O0OO0O . mpriority == 255 ) : continue
  if ( O0OO0O . priority == 254 ) :
   oo0i11i11ii11 . append ( O0OO0O )
  else :
   iiiI11II1IiIi . append ( O0OO0O )
   if 26 - 26: I1IiiI / II111iiii % I1ii11iIi11i * o0oOOo0O0Ooo . IiII / OoO0O00
   if 10 - 10: i11iIiiIii / i1IIi + O0 - i11iIiiIii % I11i - i1IIi
   if 38 - 38: O0 - I1IiiI + Oo0Ooo + ooOoO0o
   if 56 - 56: I1Ii111 + oO0o / Ii1I + I1Ii111
   if 21 - 21: OOooOOo / OoOoOO00 + OoOoOO00 + OoOoOO00 - i1IIi + Ii1I
   if 43 - 43: O0 % II111iiii
 if ( o0Ooo ) : return ( iiiI11II1IiIi )
 if 60 - 60: iII111i / ooOoO0o - Ii1I - OoooooooOO
 if 79 - 79: oO0o / iII111i . iIii1I11I1II1 * i11iIiiIii * i1IIi . iIii1I11I1II1
 if 31 - 31: OoooooooOO / ooOoO0o / OoooooooOO + ooOoO0o . O0 - IiII
 if 53 - 53: Oo0Ooo % iII111i % iII111i
 if 71 - 71: iII111i
 if 99 - 99: O0 - OoOoOO00 * I1Ii111 - Oo0Ooo
 if 62 - 62: i1IIi + ooOoO0o + Oo0Ooo - i11iIiiIii
 if 19 - 19: I1IiiI / OOooOOo
 if 6 - 6: I1ii11iIi11i + IiII * oO0o * OoOoOO00
 if 67 - 67: I1Ii111 + OoooooooOO + OoOoOO00 % iIii1I11I1II1 . I1IiiI
 iiiI11II1IiIi = [ ]
 for O0OO0O in registered_rloc_set :
  if ( O0OO0O . rloc . is_private_address ( ) ) : iiiI11II1IiIi . append ( O0OO0O )
  if 68 - 68: ooOoO0o
 iiiI11II1IiIi += oo0i11i11ii11
 return ( iiiI11II1IiIi )
 if 68 - 68: I11i % IiII
 if 1 - 1: I1IiiI + OOooOOo - OOooOOo * O0 + o0oOOo0O0Ooo * OOooOOo
 if 48 - 48: ooOoO0o - iII111i + I1ii11iIi11i * I1Ii111 % ooOoO0o * OoO0O00
 if 28 - 28: i1IIi / iII111i + OOooOOo
 if 89 - 89: Oo0Ooo + II111iiii * OoO0O00 + Oo0Ooo % II111iiii
 if 59 - 59: O0 + Oo0Ooo
 if 63 - 63: OoO0O00 / I1IiiI / oO0o . Ii1I / i1IIi
 if 50 - 50: I11i . I11i % I1IiiI - i1IIi
 if 63 - 63: OoO0O00 . iII111i
 if 28 - 28: ooOoO0o . Oo0Ooo - OoooooooOO - I1Ii111 - OoooooooOO - oO0o
def lisp_store_pubsub_state ( reply_eid , itr_rloc , mr_sport , nonce , ttl , xtr_id ) :
 I1i11 = lisp_pubsub ( itr_rloc , mr_sport , nonce , ttl , xtr_id )
 I1i11 . add ( reply_eid )
 return
 if 3 - 3: ooOoO0o / IiII
 if 9 - 9: IiII
 if 22 - 22: iII111i % i11iIiiIii / iIii1I11I1II1 % i1IIi + o0oOOo0O0Ooo
 if 64 - 64: II111iiii / II111iiii + OoO0O00
 if 70 - 70: Oo0Ooo * i11iIiiIii + IiII / OoOoOO00 . I1ii11iIi11i % OoOoOO00
 if 12 - 12: I11i % II111iiii % O0 % O0
 if 18 - 18: iII111i . IiII . I1IiiI
 if 40 - 40: IiII / oO0o + OoooooooOO / iII111i / II111iiii + i1IIi
 if 33 - 33: I11i + I1ii11iIi11i + i11iIiiIii * I1IiiI % oO0o % OoooooooOO
 if 4 - 4: OoO0O00 . I1IiiI - O0 % iII111i . OOooOOo
 if 69 - 69: OoooooooOO
 if 19 - 19: O0 + iIii1I11I1II1 / OoOoOO00 / oO0o + II111iiii - OOooOOo
 if 70 - 70: i1IIi * o0oOOo0O0Ooo + I1Ii111 . ooOoO0o - O0 + i11iIiiIii
 if 81 - 81: iIii1I11I1II1 - OoO0O00 . i11iIiiIii
 if 4 - 4: o0oOOo0O0Ooo / OoO0O00 - I11i
def lisp_convert_reply_to_notify ( packet ) :
 if 52 - 52: II111iiii . iII111i
 if 36 - 36: I1IiiI * II111iiii
 if 68 - 68: oO0o * o0oOOo0O0Ooo + OoooooooOO - I1ii11iIi11i * i1IIi % OOooOOo
 if 39 - 39: I1Ii111 / I11i + oO0o / I1Ii111 % IiII * I1ii11iIi11i
 OOo00oOOo0OOO = struct . unpack ( "I" , packet [ 0 : 4 ] ) [ 0 ]
 OOo00oOOo0OOO = socket . ntohl ( OOo00oOOo0OOO ) & 0xff
 i11III1I = packet [ 4 : 12 ]
 packet = packet [ 12 : : ]
 if 6 - 6: iII111i . IiII - I1ii11iIi11i - Oo0Ooo - i1IIi
 if 96 - 96: i1IIi . Oo0Ooo * i11iIiiIii / OoO0O00 / oO0o
 if 12 - 12: iII111i % OOooOOo % i1IIi
 if 17 - 17: IiII
 O0oooOO = ( LISP_MAP_NOTIFY << 28 ) | OOo00oOOo0OOO
 oooooOOo0Oo = struct . pack ( "I" , socket . htonl ( O0oooOO ) )
 II11IiI1 = struct . pack ( "I" , 0 )
 if 63 - 63: ooOoO0o . i11iIiiIii / iIii1I11I1II1
 if 8 - 8: i11iIiiIii . IiII * iIii1I11I1II1 * I1IiiI * Ii1I * i11iIiiIii
 if 24 - 24: I1IiiI * I11i - o0oOOo0O0Ooo / iII111i + IiII - I1ii11iIi11i
 if 53 - 53: I11i / I1IiiI - iIii1I11I1II1 - o0oOOo0O0Ooo * OoOoOO00
 packet = oooooOOo0Oo + i11III1I + II11IiI1 + packet
 return ( packet )
 if 86 - 86: iIii1I11I1II1 - I1Ii111
 if 86 - 86: O0 * IiII + OoOoOO00 + OoO0O00
 if 53 - 53: I1IiiI % i11iIiiIii + o0oOOo0O0Ooo . I1ii11iIi11i
 if 73 - 73: iII111i - o0oOOo0O0Ooo / OOooOOo + iII111i + o0oOOo0O0Ooo % II111iiii
 if 74 - 74: I11i * iIii1I11I1II1 - OoO0O00 / i1IIi / OoO0O00 / IiII
 if 60 - 60: oO0o % I1Ii111 % Oo0Ooo
 if 34 - 34: o0oOOo0O0Ooo * OOooOOo % Ii1I + I1IiiI
 if 77 - 77: OoOoOO00 + IiII + Oo0Ooo
def lisp_notify_subscribers ( lisp_sockets , eid_record , eid , site ) :
 oO00oo000O = eid . print_prefix ( )
 if ( lisp_pubsub_cache . has_key ( oO00oo000O ) == False ) : return
 if 88 - 88: i1IIi
 for I1i11 in lisp_pubsub_cache [ oO00oo000O ] . values ( ) :
  OooOoOOo0 = I1i11 . itr
  Iiiii = I1i11 . port
  I1iIIiiiiI = red ( OooOoOOo0 . print_address_no_iid ( ) , False )
  O0O00 = bold ( "subscriber" , False )
  Oo0O0 = "0x" + lisp_hex_string ( I1i11 . xtr_id )
  i11III1I = "0x" + lisp_hex_string ( I1i11 . nonce )
  if 85 - 85: OoO0O00
  lprint ( "    Notify {} {}:{} xtr-id {} for {}, nonce {}" . format ( O0O00 , I1iIIiiiiI , Iiiii , Oo0O0 , green ( oO00oo000O , False ) , i11III1I ) )
  if 20 - 20: OOooOOo % OoooooooOO + i1IIi + I1Ii111
  if 94 - 94: II111iiii + i11iIiiIii % Ii1I / ooOoO0o * OoOoOO00
  lisp_build_map_notify ( lisp_sockets , eid_record , [ oO00oo000O ] , 1 , OooOoOOo0 ,
 Iiiii , I1i11 . nonce , 0 , 0 , 0 , site , False )
  I1i11 . map_notify_count += 1
  if 68 - 68: O0 / Oo0Ooo / iIii1I11I1II1
 return
 if 63 - 63: I1Ii111 + iII111i
 if 6 - 6: I1ii11iIi11i + Ii1I
 if 36 - 36: iII111i + iII111i * OoO0O00 * I1ii11iIi11i
 if 97 - 97: ooOoO0o + OOooOOo
 if 70 - 70: o0oOOo0O0Ooo + Ii1I - i11iIiiIii + I11i * o0oOOo0O0Ooo . Ii1I
 if 6 - 6: Oo0Ooo + I1IiiI
 if 48 - 48: oO0o . I1ii11iIi11i
def lisp_process_pubsub ( lisp_sockets , packet , reply_eid , itr_rloc , port , nonce ,
 ttl , xtr_id ) :
 if 59 - 59: IiII - Ii1I
 if 62 - 62: OOooOOo * o0oOOo0O0Ooo + IiII * o0oOOo0O0Ooo * i11iIiiIii - O0
 if 37 - 37: I1ii11iIi11i - Oo0Ooo . i11iIiiIii / i11iIiiIii + oO0o
 if 19 - 19: i1IIi / i1IIi - OoooooooOO - OOooOOo . i1IIi
 lisp_store_pubsub_state ( reply_eid , itr_rloc , port , nonce , ttl , xtr_id )
 if 57 - 57: OOooOOo / I1ii11iIi11i * oO0o
 Oo00o = green ( reply_eid . print_prefix ( ) , False )
 OooOoOOo0 = red ( itr_rloc . print_address_no_iid ( ) , False )
 oO0OOO0o0oooO = bold ( "Map-Notify" , False )
 xtr_id = "0x" + lisp_hex_string ( xtr_id )
 lprint ( "{} pubsub request for {} to ack ITR {} xtr-id: {}" . format ( oO0OOO0o0oooO ,
 Oo00o , OooOoOOo0 , xtr_id ) )
 if 10 - 10: OoO0O00 % II111iiii
 if 28 - 28: II111iiii + OoOoOO00 . Ii1I - Ii1I % I1ii11iIi11i
 if 44 - 44: OOooOOo - o0oOOo0O0Ooo
 if 69 - 69: IiII + I1ii11iIi11i / o0oOOo0O0Ooo / OOooOOo
 packet = lisp_convert_reply_to_notify ( packet )
 lisp_send_map_notify ( lisp_sockets , packet , itr_rloc , port )
 return
 if 31 - 31: oO0o + I1ii11iIi11i * i1IIi % I1IiiI % I1IiiI + iIii1I11I1II1
 if 62 - 62: OoooooooOO
 if 38 - 38: iII111i % iII111i * ooOoO0o / OoO0O00 + ooOoO0o
 if 52 - 52: ooOoO0o . iIii1I11I1II1 / iIii1I11I1II1 % oO0o - oO0o * II111iiii
 if 57 - 57: I1Ii111
 if 23 - 23: I1ii11iIi11i + II111iiii
 if 99 - 99: o0oOOo0O0Ooo . I1IiiI + o0oOOo0O0Ooo * o0oOOo0O0Ooo / O0
 if 27 - 27: OOooOOo - I1Ii111
def lisp_ms_process_map_request ( lisp_sockets , packet , map_request , mr_source ,
 mr_sport , ecm_source ) :
 if 33 - 33: OOooOOo - Ii1I - iII111i + I1ii11iIi11i - i11iIiiIii
 if 89 - 89: iIii1I11I1II1 * I11i + OOooOOo
 if 27 - 27: i1IIi - OoO0O00
 if 23 - 23: iIii1I11I1II1 + Oo0Ooo * IiII
 if 80 - 80: OoooooooOO . ooOoO0o
 if 52 - 52: O0 + O0 + I1IiiI
 Oo00o = map_request . target_eid
 i1i11Ii1 = map_request . target_group
 oO00oo000O = lisp_print_eid_tuple ( Oo00o , i1i11Ii1 )
 o0oi1iIiii1I1ii = map_request . itr_rlocs [ 0 ]
 Oo0O0 = map_request . xtr_id
 i11III1I = map_request . nonce
 O0oo0oo0 = LISP_NO_ACTION
 I1i11 = map_request . subscribe_bit
 if 64 - 64: ooOoO0o
 if 35 - 35: I1IiiI . iIii1I11I1II1 + IiII / i11iIiiIii - II111iiii . OoooooooOO
 if 19 - 19: IiII - OoOoOO00
 if 43 - 43: IiII / OOooOOo % II111iiii . o0oOOo0O0Ooo / i11iIiiIii
 if 5 - 5: oO0o % iII111i . Oo0Ooo . O0 . OoOoOO00 / iII111i
 O0OOOooo = True
 o0o0Ooo0OO00o = ( lisp_get_eid_hash ( Oo00o ) != None )
 if ( o0o0Ooo0OO00o ) :
  o0o000OOO = map_request . map_request_signature
  if ( o0o000OOO == None ) :
   O0OOOooo = False
   lprint ( ( "EID-crypto-hash signature verification {}, " + "no signature found" ) . format ( bold ( "failed" , False ) ) )
   if 5 - 5: I1ii11iIi11i
  else :
   oo0o0Oo = map_request . signature_eid
   IIIIIiI , oooo0 , O0OOOooo = lisp_lookup_public_key ( oo0o0Oo )
   if ( O0OOOooo ) :
    O0OOOooo = map_request . verify_map_request_sig ( oooo0 )
   else :
    lprint ( "Public-key lookup failed for sig-eid {}, hash-eid {}" . format ( oo0o0Oo . print_address ( ) , IIIIIiI . print_address ( ) ) )
    if 18 - 18: IiII + i1IIi / O0
    if 42 - 42: OoO0O00 - OoOoOO00 . I1IiiI
   iii = bold ( "passed" , False ) if O0OOOooo else bold ( "failed" , False )
   lprint ( "EID-crypto-hash signature verification {}" . format ( iii ) )
   if 63 - 63: OoOoOO00 . i11iIiiIii / IiII
   if 36 - 36: OOooOOo * OoOoOO00 + i11iIiiIii + O0 + O0
   if 18 - 18: Oo0Ooo . I1ii11iIi11i * ooOoO0o % Ii1I + I1ii11iIi11i
 if ( I1i11 and O0OOOooo == False ) :
  I1i11 = False
  lprint ( "Suppress creating pubsub state due to signature failure" )
  if 23 - 23: oO0o / o0oOOo0O0Ooo + I11i % IiII * OoO0O00
  if 48 - 48: OoO0O00
  if 30 - 30: iIii1I11I1II1
  if 53 - 53: II111iiii
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
 I1i1iiII1iI1i = o0oi1iIiii1I1ii if ( o0oi1iIiii1I1ii . afi == ecm_source . afi ) else ecm_source
 if 72 - 72: I1ii11iIi11i
 ooO00oO0O = lisp_site_eid_lookup ( Oo00o , i1i11Ii1 , False )
 if 93 - 93: ooOoO0o % i1IIi + OoOoOO00 * IiII - IiII * i11iIiiIii
 if ( ooO00oO0O == None or ooO00oO0O . is_star_g ( ) ) :
  iIo0OO0O000 = bold ( "Site not found" , False )
  lprint ( "{} for requested EID {}" . format ( iIo0OO0O000 ,
 green ( oO00oo000O , False ) ) )
  if 66 - 66: O0 % o0oOOo0O0Ooo - I11i * oO0o . I1Ii111
  if 23 - 23: O0 - I1ii11iIi11i / O0 % i11iIiiIii + iIii1I11I1II1 / OOooOOo
  if 67 - 67: iII111i + OOooOOo % iII111i + IiII
  if 79 - 79: OOooOOo
  lisp_send_negative_map_reply ( lisp_sockets , Oo00o , i1i11Ii1 , i11III1I , o0oi1iIiii1I1ii ,
 mr_sport , 15 , Oo0O0 , I1i11 )
  if 47 - 47: IiII - I1ii11iIi11i . OOooOOo + I1Ii111 % I1IiiI
  return ( [ Oo00o , i1i11Ii1 , LISP_DDT_ACTION_SITE_NOT_FOUND ] )
  if 3 - 3: I1IiiI / Oo0Ooo - Ii1I
  if 69 - 69: iIii1I11I1II1 % iII111i + ooOoO0o * i1IIi + iII111i * I1Ii111
 I11Ii11ii = ooO00oO0O . print_eid_tuple ( )
 O0OOoOO000 = ooO00oO0O . site . site_name
 if 42 - 42: iIii1I11I1II1 + iIii1I11I1II1 . I11i
 if 27 - 27: OoOoOO00 * Oo0Ooo - ooOoO0o
 if 93 - 93: OOooOOo * o0oOOo0O0Ooo / oO0o + Ii1I - OoooooooOO
 if 15 - 15: O0
 if 21 - 21: OoO0O00 * iIii1I11I1II1 - iIii1I11I1II1 % OoO0O00 . I1ii11iIi11i
 if ( o0o0Ooo0OO00o == False and ooO00oO0O . require_signature ) :
  o0o000OOO = map_request . map_request_signature
  oo0o0Oo = map_request . signature_eid
  if ( o0o000OOO == None or oo0o0Oo . is_null ( ) ) :
   lprint ( "Signature required for site {}" . format ( O0OOoOO000 ) )
   O0OOOooo = False
  else :
   oo0o0Oo = map_request . signature_eid
   IIIIIiI , oooo0 , O0OOOooo = lisp_lookup_public_key ( oo0o0Oo )
   if ( O0OOOooo ) :
    O0OOOooo = map_request . verify_map_request_sig ( oooo0 )
   else :
    lprint ( "Public-key lookup failed for sig-eid {}, hash-eid {}" . format ( oo0o0Oo . print_address ( ) , IIIIIiI . print_address ( ) ) )
    if 19 - 19: i1IIi % Ii1I . OoOoOO00
    if 22 - 22: iIii1I11I1II1 + Ii1I
   iii = bold ( "passed" , False ) if O0OOOooo else bold ( "failed" , False )
   lprint ( "Required signature verification {}" . format ( iii ) )
   if 73 - 73: I1IiiI / OoO0O00 / OoooooooOO
   if 14 - 14: ooOoO0o % o0oOOo0O0Ooo / I1ii11iIi11i . IiII + I1ii11iIi11i
   if 30 - 30: I1ii11iIi11i + iIii1I11I1II1 . I1ii11iIi11i
   if 9 - 9: I1IiiI - Ii1I * II111iiii - I11i
   if 85 - 85: oO0o % ooOoO0o / OOooOOo
   if 50 - 50: O0 * O0 / iIii1I11I1II1
 if ( O0OOOooo and ooO00oO0O . registered == False ) :
  lprint ( "Site '{}' with EID-prefix {} is not registered for EID {}" . format ( O0OOoOO000 , green ( I11Ii11ii , False ) , green ( oO00oo000O , False ) ) )
  if 31 - 31: I1IiiI / o0oOOo0O0Ooo
  if 70 - 70: I1IiiI
  if 36 - 36: ooOoO0o . oO0o . I11i - I1ii11iIi11i / OoOoOO00 * Oo0Ooo
  if 42 - 42: OoooooooOO / o0oOOo0O0Ooo . Ii1I * iII111i * I1IiiI - Oo0Ooo
  if 76 - 76: oO0o * II111iiii
  if 81 - 81: I11i
  if ( ooO00oO0O . accept_more_specifics == False ) :
   Oo00o = ooO00oO0O . eid
   i1i11Ii1 = ooO00oO0O . group
   if 2 - 2: OoOoOO00
   if 75 - 75: I1IiiI - OoooooooOO * I1Ii111
   if 1 - 1: o0oOOo0O0Ooo % oO0o * I1Ii111 - i1IIi - iII111i . oO0o
   if 25 - 25: i1IIi * o0oOOo0O0Ooo / oO0o
   if 11 - 11: IiII + II111iiii
  Ii1 = 1
  if ( ooO00oO0O . force_ttl != None ) :
   Ii1 = ooO00oO0O . force_ttl | 0x80000000
   if 37 - 37: O0
   if 98 - 98: IiII * OoooooooOO . iII111i
   if 34 - 34: OoooooooOO + I1Ii111
   if 97 - 97: II111iiii + I11i + OOooOOo / i11iIiiIii - iII111i
   if 9 - 9: i1IIi - I1Ii111 + I1Ii111
  lisp_send_negative_map_reply ( lisp_sockets , Oo00o , i1i11Ii1 , i11III1I , o0oi1iIiii1I1ii ,
 mr_sport , Ii1 , Oo0O0 , I1i11 )
  if 81 - 81: II111iiii % I11i % O0 . I1Ii111 % ooOoO0o - O0
  return ( [ Oo00o , i1i11Ii1 , LISP_DDT_ACTION_MS_NOT_REG ] )
  if 58 - 58: OoooooooOO . II111iiii . O0 % I1Ii111 / OoooooooOO
  if 64 - 64: Oo0Ooo + oO0o . OoO0O00
  if 67 - 67: I11i
  if 91 - 91: OOooOOo / OoO0O00
  if 36 - 36: I1IiiI . iII111i * I1Ii111 . IiII % I1ii11iIi11i
 I1II1i1Ii1 = False
 OoOooo = ""
 I1IIii1Ii111i = False
 if ( ooO00oO0O . force_nat_proxy_reply ) :
  OoOooo = ", nat-forced"
  I1II1i1Ii1 = True
  I1IIii1Ii111i = True
 elif ( ooO00oO0O . force_proxy_reply ) :
  OoOooo = ", forced"
  I1IIii1Ii111i = True
 elif ( ooO00oO0O . proxy_reply_requested ) :
  OoOooo = ", requested"
  I1IIii1Ii111i = True
 elif ( map_request . pitr_bit and ooO00oO0O . pitr_proxy_reply_drop ) :
  OoOooo = ", drop-to-pitr"
  O0oo0oo0 = LISP_DROP_ACTION
 elif ( ooO00oO0O . proxy_reply_action != "" ) :
  O0oo0oo0 = ooO00oO0O . proxy_reply_action
  OoOooo = ", forced, action {}" . format ( O0oo0oo0 )
  O0oo0oo0 = LISP_DROP_ACTION if ( O0oo0oo0 == "drop" ) else LISP_NATIVE_FORWARD_ACTION
  if 46 - 46: oO0o . I1IiiI - oO0o / ooOoO0o - Oo0Ooo + II111iiii
  if 8 - 8: I1Ii111 + i1IIi - IiII + I1IiiI
  if 61 - 61: OoO0O00
  if 96 - 96: ooOoO0o - OoooooooOO * iIii1I11I1II1 . IiII - O0
  if 7 - 7: iIii1I11I1II1 . OoO0O00
  if 88 - 88: i1IIi * II111iiii / i11iIiiIii % IiII . IiII
  if 93 - 93: OoOoOO00 * i1IIi . Ii1I
 i11i = False
 i1Ii1I1IIII = None
 if ( I1IIii1Ii111i and lisp_policies . has_key ( ooO00oO0O . policy ) ) :
  i111 = lisp_policies [ ooO00oO0O . policy ]
  if ( i111 . match_policy_map_request ( map_request , mr_source ) ) : i1Ii1I1IIII = i111
  if 54 - 54: OoO0O00 * OoOoOO00 + o0oOOo0O0Ooo . IiII
  if ( i1Ii1I1IIII ) :
   o0oO0oo = bold ( "matched" , False )
   lprint ( "Map-Request {} policy '{}', set-action '{}'" . format ( o0oO0oo ,
 i111 . policy_name , i111 . set_action ) )
  else :
   o0oO0oo = bold ( "no match" , False )
   lprint ( "Map-Request {} for policy '{}', implied drop" . format ( o0oO0oo ,
 i111 . policy_name ) )
   i11i = True
   if 87 - 87: i11iIiiIii . OoooooooOO - II111iiii
   if 69 - 69: iII111i
   if 70 - 70: O0 + iII111i % I11i % I1Ii111 + OoOoOO00 / ooOoO0o
 if ( OoOooo != "" ) :
  lprint ( "Proxy-replying for EID {}, found site '{}' EID-prefix {}{}" . format ( green ( oO00oo000O , False ) , O0OOoOO000 , green ( I11Ii11ii , False ) ,
  # I1IiiI / OoO0O00 * iII111i
 OoOooo ) )
  if 99 - 99: OoooooooOO / OoO0O00 * Ii1I % I11i
  iiiI11II1IiIi = ooO00oO0O . registered_rlocs
  Ii1 = 1440
  if ( I1II1i1Ii1 ) :
   if ( ooO00oO0O . site_id != 0 ) :
    oOoO = map_request . source_eid
    iiiI11II1IiIi = lisp_get_private_rloc_set ( ooO00oO0O , oOoO , i1i11Ii1 )
    if 80 - 80: Oo0Ooo / OOooOOo / iII111i . o0oOOo0O0Ooo
   if ( iiiI11II1IiIi == ooO00oO0O . registered_rlocs ) :
    i1ii1I11iIII = ( ooO00oO0O . group . is_null ( ) == False )
    Oo = lisp_get_partial_rloc_set ( iiiI11II1IiIi , I1i1iiII1iI1i , i1ii1I11iIII )
    if ( Oo != iiiI11II1IiIi ) :
     Ii1 = 15
     iiiI11II1IiIi = Oo
     if 8 - 8: OoO0O00
     if 58 - 58: OoooooooOO . i1IIi
     if 71 - 71: iII111i + ooOoO0o * OoOoOO00 . I1ii11iIi11i . I1Ii111
     if 91 - 91: oO0o - Oo0Ooo % OoOoOO00 % o0oOOo0O0Ooo
     if 71 - 71: i1IIi % iII111i * I1Ii111
     if 36 - 36: I1ii11iIi11i % II111iiii % I1Ii111 / I1ii11iIi11i
     if 34 - 34: OoooooooOO * i11iIiiIii
     if 33 - 33: II111iiii
  if ( ooO00oO0O . force_ttl != None ) :
   Ii1 = ooO00oO0O . force_ttl | 0x80000000
   if 59 - 59: iIii1I11I1II1 % I11i
   if 93 - 93: I1ii11iIi11i
   if 50 - 50: ooOoO0o % OoO0O00 % OoO0O00
   if 36 - 36: I1IiiI * O0 . IiII / I1Ii111
   if 15 - 15: I11i + iII111i
   if 79 - 79: i11iIiiIii * IiII % iII111i
  if ( i1Ii1I1IIII ) :
   if ( i1Ii1I1IIII . set_record_ttl ) :
    Ii1 = i1Ii1I1IIII . set_record_ttl
    lprint ( "Policy set-record-ttl to {}" . format ( Ii1 ) )
    if 18 - 18: iIii1I11I1II1 - O0 . o0oOOo0O0Ooo % oO0o
   if ( i1Ii1I1IIII . set_action == "drop" ) :
    lprint ( "Policy set-action drop, send negative Map-Reply" )
    O0oo0oo0 = LISP_POLICY_DENIED_ACTION
    iiiI11II1IiIi = [ ]
   else :
    Oo0o0o0oo = i1Ii1I1IIII . set_policy_map_reply ( )
    if ( Oo0o0o0oo ) : iiiI11II1IiIi = [ Oo0o0o0oo ]
    if 73 - 73: IiII + I11i % I1IiiI * iII111i . O0
    if 17 - 17: OoO0O00 * OoOoOO00 % O0 % iII111i / i1IIi
    if 100 - 100: i11iIiiIii
  if ( i11i ) :
   lprint ( "Implied drop action, send negative Map-Reply" )
   O0oo0oo0 = LISP_POLICY_DENIED_ACTION
   iiiI11II1IiIi = [ ]
   if 54 - 54: O0 * Ii1I + Ii1I
   if 59 - 59: i11iIiiIii % iII111i
  O0o00oo = ooO00oO0O . echo_nonce_capable
  if 54 - 54: I11i . ooOoO0o / OOooOOo % I1Ii111
  if 13 - 13: I11i / O0 . o0oOOo0O0Ooo . ooOoO0o
  if 7 - 7: OoO0O00 + OoooooooOO % II111iiii % oO0o
  if 48 - 48: OOooOOo . II111iiii * OOooOOo - I11i / iIii1I11I1II1 / i11iIiiIii
  if ( O0OOOooo ) :
   IiIiIiiII1I = ooO00oO0O . eid
   I11ii1I11ii = ooO00oO0O . group
  else :
   IiIiIiiII1I = Oo00o
   I11ii1I11ii = i1i11Ii1
   O0oo0oo0 = LISP_AUTH_FAILURE_ACTION
   iiiI11II1IiIi = [ ]
   if 38 - 38: iII111i % Ii1I - I1ii11iIi11i * I1Ii111 % iII111i
   if 50 - 50: Oo0Ooo + o0oOOo0O0Ooo . OoOoOO00
   if 8 - 8: O0 - i1IIi * oO0o + II111iiii . OoOoOO00
   if 4 - 4: I1IiiI - OoO0O00 % o0oOOo0O0Ooo
   if 83 - 83: iII111i % iIii1I11I1II1 / OOooOOo - OoOoOO00
   if 98 - 98: I11i % oO0o . I1IiiI % OoOoOO00
  packet = lisp_build_map_reply ( IiIiIiiII1I , I11ii1I11ii , iiiI11II1IiIi ,
 i11III1I , O0oo0oo0 , Ii1 , False , None , O0o00oo , False )
  if 32 - 32: I1ii11iIi11i / Ii1I
  if ( I1i11 ) :
   lisp_process_pubsub ( lisp_sockets , packet , IiIiIiiII1I , o0oi1iIiii1I1ii ,
 mr_sport , i11III1I , Ii1 , Oo0O0 )
  else :
   lisp_send_map_reply ( lisp_sockets , packet , o0oi1iIiii1I1ii , mr_sport )
   if 54 - 54: I11i - i11iIiiIii
   if 91 - 91: Ii1I - OoO0O00 - I1IiiI % OoO0O00 . o0oOOo0O0Ooo
  return ( [ ooO00oO0O . eid , ooO00oO0O . group , LISP_DDT_ACTION_MS_ACK ] )
  if 85 - 85: ooOoO0o . ooOoO0o % Oo0Ooo . OOooOOo + OOooOOo / I1IiiI
  if 69 - 69: i1IIi + II111iiii / Ii1I
  if 4 - 4: I11i * OoOoOO00 % o0oOOo0O0Ooo % ooOoO0o - I1ii11iIi11i
  if 88 - 88: iIii1I11I1II1 * iIii1I11I1II1 * I11i * OoOoOO00
  if 14 - 14: i11iIiiIii * I1IiiI % O0 % iIii1I11I1II1
 iI1111i = len ( ooO00oO0O . registered_rlocs )
 if ( iI1111i == 0 ) :
  lprint ( "Requested EID {} found site '{}' with EID-prefix {} with " + "no registered RLOCs" . format ( green ( oO00oo000O , False ) , O0OOoOO000 ,
  # OOooOOo + Oo0Ooo
 green ( I11Ii11ii , False ) ) )
  return ( [ ooO00oO0O . eid , ooO00oO0O . group , LISP_DDT_ACTION_MS_ACK ] )
  if 50 - 50: II111iiii * i11iIiiIii * I1IiiI % OoOoOO00 + o0oOOo0O0Ooo
  if 26 - 26: iIii1I11I1II1 * II111iiii
  if 83 - 83: II111iiii . OoOoOO00 - i11iIiiIii . OoOoOO00 . i1IIi % OoooooooOO
  if 47 - 47: II111iiii
  if 30 - 30: i1IIi . Oo0Ooo / o0oOOo0O0Ooo + IiII * OOooOOo
 I1Ii1i11II = map_request . target_eid if map_request . source_eid . is_null ( ) else map_request . source_eid
 if 75 - 75: II111iiii - OoooooooOO * II111iiii + iIii1I11I1II1 - OoooooooOO * O0
 ooo000 = map_request . target_eid . hash_address ( I1Ii1i11II )
 ooo000 %= iI1111i
 Ii11 = ooO00oO0O . registered_rlocs [ ooo000 ]
 if 69 - 69: Ii1I . Oo0Ooo . iII111i . i1IIi . i1IIi
 if ( Ii11 . rloc . is_null ( ) ) :
  lprint ( ( "Suppress forwarding Map-Request for EID {} at site '{}' " + "EID-prefix {}, no RLOC address" ) . format ( green ( oO00oo000O , False ) ,
  # I11i / IiII . OoOoOO00 % iII111i . ooOoO0o
 O0OOoOO000 , green ( I11Ii11ii , False ) ) )
 else :
  lprint ( ( "Forwarding Map-Request for EID {} to ETR {} at site '{}' " + "EID-prefix {}" ) . format ( green ( oO00oo000O , False ) ,
  # iIii1I11I1II1 / oO0o . iIii1I11I1II1 . II111iiii % oO0o
 red ( Ii11 . rloc . print_address ( ) , False ) , O0OOoOO000 ,
 green ( I11Ii11ii , False ) ) )
  if 12 - 12: oO0o * i11iIiiIii . I11i . i1IIi - Oo0Ooo % iIii1I11I1II1
  if 8 - 8: oO0o / I1Ii111 + I1Ii111 - Oo0Ooo % i1IIi
  if 27 - 27: Ii1I
  if 12 - 12: OOooOOo . oO0o % I1IiiI % OoO0O00 % I11i
  lisp_send_ecm ( lisp_sockets , packet , map_request . source_eid , mr_sport ,
 map_request . target_eid , Ii11 . rloc , to_etr = True )
  if 54 - 54: i1IIi / ooOoO0o % ooOoO0o / iIii1I11I1II1 + Oo0Ooo - o0oOOo0O0Ooo
 return ( [ ooO00oO0O . eid , ooO00oO0O . group , LISP_DDT_ACTION_MS_ACK ] )
 if 27 - 27: OOooOOo % OoooooooOO * OoooooooOO / I1ii11iIi11i
 if 60 - 60: OOooOOo - I11i * IiII - o0oOOo0O0Ooo / I1IiiI
 if 93 - 93: OoOoOO00 . O0 - OOooOOo
 if 90 - 90: Oo0Ooo % iII111i % Oo0Ooo * I11i / OoOoOO00
 if 49 - 49: I1ii11iIi11i * II111iiii
 if 59 - 59: OoO0O00
 if 81 - 81: i11iIiiIii
def lisp_ddt_process_map_request ( lisp_sockets , map_request , ecm_source , port ) :
 if 57 - 57: Oo0Ooo * iIii1I11I1II1 - OoOoOO00 % iII111i % I1ii11iIi11i + Ii1I
 if 82 - 82: IiII * Oo0Ooo - iIii1I11I1II1 - i11iIiiIii
 if 85 - 85: OoooooooOO
 if 37 - 37: OoooooooOO + O0 + I1ii11iIi11i + IiII * iII111i
 Oo00o = map_request . target_eid
 i1i11Ii1 = map_request . target_group
 oO00oo000O = lisp_print_eid_tuple ( Oo00o , i1i11Ii1 )
 i11III1I = map_request . nonce
 O0oo0oo0 = LISP_DDT_ACTION_NULL
 if 15 - 15: i11iIiiIii / Oo0Ooo - OOooOOo . IiII
 if 11 - 11: OOooOOo / i1IIi % Oo0Ooo
 if 65 - 65: OOooOOo % I1ii11iIi11i
 if 25 - 25: o0oOOo0O0Ooo - I1Ii111 * I1ii11iIi11i + OoooooooOO
 if 93 - 93: OoOoOO00 % I1ii11iIi11i * I11i
 I1II111i1 = None
 if ( lisp_i_am_ms ) :
  ooO00oO0O = lisp_site_eid_lookup ( Oo00o , i1i11Ii1 , False )
  if ( ooO00oO0O == None ) : return
  if 73 - 73: OOooOOo * iII111i * OoO0O00
  if ( ooO00oO0O . registered ) :
   O0oo0oo0 = LISP_DDT_ACTION_MS_ACK
   Ii1 = 1440
  else :
   Oo00o , i1i11Ii1 , O0oo0oo0 = lisp_ms_compute_neg_prefix ( Oo00o , i1i11Ii1 )
   O0oo0oo0 = LISP_DDT_ACTION_MS_NOT_REG
   Ii1 = 1
   if 11 - 11: I1Ii111 * II111iiii
 else :
  I1II111i1 = lisp_ddt_cache_lookup ( Oo00o , i1i11Ii1 , False )
  if ( I1II111i1 == None ) :
   O0oo0oo0 = LISP_DDT_ACTION_NOT_AUTH
   Ii1 = 0
   lprint ( "DDT delegation entry not found for EID {}" . format ( green ( oO00oo000O , False ) ) )
   if 3 - 3: Oo0Ooo * OOooOOo
  elif ( I1II111i1 . is_auth_prefix ( ) ) :
   if 13 - 13: I1Ii111 + i11iIiiIii / OOooOOo
   if 98 - 98: I1IiiI * Oo0Ooo
   if 9 - 9: O0 / i11iIiiIii . iIii1I11I1II1 . IiII
   if 14 - 14: OoOoOO00 . OOooOOo - Oo0Ooo + I1Ii111 % ooOoO0o
   O0oo0oo0 = LISP_DDT_ACTION_DELEGATION_HOLE
   Ii1 = 15
   oOOooo0o000O0 = I1II111i1 . print_eid_tuple ( )
   lprint ( ( "DDT delegation entry not found but auth-prefix {} " + "found for EID {}" ) . format ( oOOooo0o000O0 ,
   # OoO0O00
 green ( oO00oo000O , False ) ) )
   if 97 - 97: I1ii11iIi11i % ooOoO0o . i11iIiiIii . Oo0Ooo
   if ( i1i11Ii1 . is_null ( ) ) :
    Oo00o = lisp_ddt_compute_neg_prefix ( Oo00o , I1II111i1 ,
 lisp_ddt_cache )
   else :
    i1i11Ii1 = lisp_ddt_compute_neg_prefix ( i1i11Ii1 , I1II111i1 ,
 lisp_ddt_cache )
    Oo00o = lisp_ddt_compute_neg_prefix ( Oo00o , I1II111i1 ,
 I1II111i1 . source_cache )
    if 49 - 49: OoooooooOO . II111iiii - o0oOOo0O0Ooo * I1ii11iIi11i * Ii1I
   I1II111i1 = None
  else :
   oOOooo0o000O0 = I1II111i1 . print_eid_tuple ( )
   lprint ( "DDT delegation entry {} found for EID {}" . format ( oOOooo0o000O0 , green ( oO00oo000O , False ) ) )
   if 98 - 98: IiII + I1Ii111 . iIii1I11I1II1 + OoooooooOO . I1ii11iIi11i - O0
   Ii1 = 1440
   if 46 - 46: iII111i
   if 99 - 99: oO0o
   if 85 - 85: I1Ii111 * iIii1I11I1II1 . OoOoOO00
   if 20 - 20: I11i * O0 - OoooooooOO * OOooOOo % oO0o * iII111i
   if 70 - 70: I11i + O0 . i11iIiiIii . OOooOOo
   if 48 - 48: iIii1I11I1II1 * Ii1I - OoooooooOO / oO0o - OoO0O00 / i11iIiiIii
 oOo = lisp_build_map_referral ( Oo00o , i1i11Ii1 , I1II111i1 , O0oo0oo0 , Ii1 , i11III1I )
 i11III1I = map_request . nonce >> 32
 if ( map_request . nonce != 0 and i11III1I != 0xdfdf0e1d ) : port = LISP_CTRL_PORT
 lisp_send_map_referral ( lisp_sockets , oOo , ecm_source , port )
 return
 if 24 - 24: I1IiiI
 if 63 - 63: I11i - iIii1I11I1II1 * Ii1I + OoooooooOO . i11iIiiIii
 if 94 - 94: OoO0O00 . oO0o . OoOoOO00 * i11iIiiIii
 if 96 - 96: i1IIi . OoO0O00 . OoO0O00 - o0oOOo0O0Ooo - Ii1I
 if 33 - 33: ooOoO0o + I1ii11iIi11i - I1IiiI . iII111i / OoO0O00
 if 91 - 91: OOooOOo - OoooooooOO . OoO0O00
 if 34 - 34: Ii1I . I1IiiI . i1IIi * I1ii11iIi11i
 if 77 - 77: ooOoO0o . II111iiii
 if 41 - 41: IiII
 if 27 - 27: IiII / IiII
 if 91 - 91: Ii1I
 if 93 - 93: OoO0O00 * OoO0O00 * I1ii11iIi11i * OoO0O00 * o0oOOo0O0Ooo
 if 84 - 84: I1Ii111 * OoO0O00 - ooOoO0o - Oo0Ooo . OoO0O00 % oO0o
def lisp_find_negative_mask_len ( eid , entry_prefix , neg_prefix ) :
 oOoOoOooO0o0O0O = eid . hash_address ( entry_prefix )
 I1IiIiIIIiIII = eid . addr_length ( ) * 8
 Ooo = 0
 if 58 - 58: I1Ii111 * O0 . Ii1I * OOooOOo * OoooooooOO * ooOoO0o
 if 97 - 97: Oo0Ooo . ooOoO0o * OoooooooOO * i11iIiiIii / Ii1I
 if 46 - 46: Ii1I - i1IIi . OoooooooOO % Ii1I
 if 39 - 39: o0oOOo0O0Ooo
 for Ooo in range ( I1IiIiIIIiIII ) :
  o00oOo0o0o00 = 1 << ( I1IiIiIIIiIII - Ooo - 1 )
  if ( oOoOoOooO0o0O0O & o00oOo0o0o00 ) : break
  if 83 - 83: iIii1I11I1II1 - OoO0O00 - I1Ii111
  if 27 - 27: IiII - iII111i * i11iIiiIii % i11iIiiIii + OoOoOO00 . I1Ii111
 if ( Ooo > neg_prefix . mask_len ) : neg_prefix . mask_len = Ooo
 return
 if 10 - 10: IiII / i11iIiiIii
 if 6 - 6: I11i - OOooOOo
 if 100 - 100: Oo0Ooo / OOooOOo + iII111i - o0oOOo0O0Ooo + OoO0O00 % IiII
 if 91 - 91: Ii1I % I11i % Oo0Ooo / OoO0O00 - II111iiii - o0oOOo0O0Ooo
 if 50 - 50: OoooooooOO
 if 51 - 51: II111iiii - oO0o % OoooooooOO - II111iiii / O0 - OoooooooOO
 if 21 - 21: iII111i * o0oOOo0O0Ooo
 if 85 - 85: I1ii11iIi11i . OoOoOO00 . i1IIi % OOooOOo * I11i . I1Ii111
 if 26 - 26: I1Ii111 + Oo0Ooo + II111iiii % OoOoOO00 % OOooOOo
 if 40 - 40: I1ii11iIi11i + i1IIi
def lisp_neg_prefix_walk ( entry , parms ) :
 Oo00o , i1III11I11 , O0OOOo = parms
 if 51 - 51: oO0o + I1IiiI - I1Ii111 * Oo0Ooo . II111iiii
 if ( i1III11I11 == None ) :
  if ( entry . eid . instance_id != Oo00o . instance_id ) :
   return ( [ True , parms ] )
   if 63 - 63: I1ii11iIi11i - ooOoO0o - II111iiii + II111iiii
  if ( entry . eid . afi != Oo00o . afi ) : return ( [ True , parms ] )
 else :
  if ( entry . eid . is_more_specific ( i1III11I11 ) == False ) :
   return ( [ True , parms ] )
   if 17 - 17: I1ii11iIi11i % OoO0O00 % oO0o
   if 60 - 60: i1IIi % Ii1I - O0 / iII111i
   if 14 - 14: i1IIi * OoooooooOO . IiII
   if 26 - 26: O0
   if 70 - 70: i1IIi % IiII % iIii1I11I1II1 . II111iiii * Oo0Ooo . o0oOOo0O0Ooo
   if 33 - 33: iIii1I11I1II1 / OoooooooOO / I1IiiI + II111iiii
 lisp_find_negative_mask_len ( Oo00o , entry . eid , O0OOOo )
 return ( [ True , parms ] )
 if 42 - 42: OoOoOO00 / i1IIi * O0
 if 46 - 46: OOooOOo - I1Ii111 + I1IiiI - ooOoO0o
 if 96 - 96: IiII + i1IIi - I11i * I11i - OoO0O00 % II111iiii
 if 47 - 47: I1Ii111 . i11iIiiIii + oO0o . I1ii11iIi11i
 if 12 - 12: iIii1I11I1II1 % I1Ii111 * OoOoOO00 / OoooooooOO % OoooooooOO
 if 81 - 81: iIii1I11I1II1 - Oo0Ooo - ooOoO0o . OoO0O00 + I1ii11iIi11i
 if 84 - 84: iII111i . OOooOOo . iII111i * oO0o % Ii1I . oO0o
 if 86 - 86: iII111i * ooOoO0o / iIii1I11I1II1 + Ii1I . iII111i
def lisp_ddt_compute_neg_prefix ( eid , ddt_entry , cache ) :
 if 64 - 64: IiII - Oo0Ooo % iII111i % I11i
 if 42 - 42: Oo0Ooo . OoO0O00
 if 22 - 22: ooOoO0o - o0oOOo0O0Ooo + I11i / I1IiiI + OOooOOo
 if 10 - 10: oO0o / I1IiiI
 if ( eid . is_binary ( ) == False ) : return ( eid )
 if 95 - 95: II111iiii - IiII % IiII . o0oOOo0O0Ooo
 O0OOOo = lisp_address ( eid . afi , "" , 0 , 0 )
 O0OOOo . copy_address ( eid )
 O0OOOo . mask_len = 0
 if 19 - 19: II111iiii . ooOoO0o . I11i - OoooooooOO / I1ii11iIi11i . I1Ii111
 OoIiII = ddt_entry . print_eid_tuple ( )
 i1III11I11 = ddt_entry . eid
 if 10 - 10: I1IiiI / I1Ii111 % IiII . OoOoOO00
 if 65 - 65: II111iiii + OoO0O00 + OoO0O00
 if 48 - 48: I1ii11iIi11i / iIii1I11I1II1
 if 47 - 47: I1Ii111
 if 41 - 41: IiII
 eid , i1III11I11 , O0OOOo = cache . walk_cache ( lisp_neg_prefix_walk ,
 ( eid , i1III11I11 , O0OOOo ) )
 if 25 - 25: I11i % iIii1I11I1II1
 if 27 - 27: iIii1I11I1II1 . O0 . oO0o
 if 21 - 21: oO0o * I1ii11iIi11i
 if 44 - 44: o0oOOo0O0Ooo * IiII - o0oOOo0O0Ooo
 O0OOOo . mask_address ( O0OOOo . mask_len )
 if 90 - 90: i1IIi + I1ii11iIi11i * oO0o % i11iIiiIii - OoO0O00
 lprint ( ( "Least specific prefix computed from ddt-cache for EID {} " + "using auth-prefix {} is {}" ) . format ( green ( eid . print_address ( ) , False ) ,
 # oO0o
 OoIiII , O0OOOo . print_prefix ( ) ) )
 return ( O0OOOo )
 if 15 - 15: I1ii11iIi11i - I1IiiI % OOooOOo
 if 9 - 9: Ii1I / O0
 if 95 - 95: iII111i / I11i
 if 86 - 86: O0 / II111iiii . Oo0Ooo / Oo0Ooo * II111iiii
 if 22 - 22: Ii1I
 if 81 - 81: iIii1I11I1II1 . ooOoO0o % I11i
 if 64 - 64: I1Ii111 . Oo0Ooo * o0oOOo0O0Ooo
 if 32 - 32: oO0o . I1Ii111 * I1Ii111
def lisp_ms_compute_neg_prefix ( eid , group ) :
 O0OOOo = lisp_address ( eid . afi , "" , 0 , 0 )
 O0OOOo . copy_address ( eid )
 O0OOOo . mask_len = 0
 i1IiI1 = lisp_address ( group . afi , "" , 0 , 0 )
 i1IiI1 . copy_address ( group )
 i1IiI1 . mask_len = 0
 i1III11I11 = None
 if 67 - 67: I1IiiI * I11i
 if 43 - 43: IiII * Oo0Ooo / OoOoOO00 + I1IiiI - i11iIiiIii + II111iiii
 if 81 - 81: I11i / Oo0Ooo % Ii1I % OoO0O00
 if 87 - 87: O0 % II111iiii
 if 42 - 42: I1IiiI . i1IIi
 if ( group . is_null ( ) ) :
  I1II111i1 = lisp_ddt_cache . lookup_cache ( eid , False )
  if ( I1II111i1 == None ) :
   O0OOOo . mask_len = O0OOOo . host_mask_len ( )
   i1IiI1 . mask_len = i1IiI1 . host_mask_len ( )
   return ( [ O0OOOo , i1IiI1 , LISP_DDT_ACTION_NOT_AUTH ] )
   if 98 - 98: o0oOOo0O0Ooo % I11i . Oo0Ooo * Oo0Ooo % iII111i
  IIi11o0oO = lisp_sites_by_eid
  if ( I1II111i1 . is_auth_prefix ( ) ) : i1III11I11 = I1II111i1 . eid
 else :
  I1II111i1 = lisp_ddt_cache . lookup_cache ( group , False )
  if ( I1II111i1 == None ) :
   O0OOOo . mask_len = O0OOOo . host_mask_len ( )
   i1IiI1 . mask_len = i1IiI1 . host_mask_len ( )
   return ( [ O0OOOo , i1IiI1 , LISP_DDT_ACTION_NOT_AUTH ] )
   if 40 - 40: iIii1I11I1II1 / i11iIiiIii
  if ( I1II111i1 . is_auth_prefix ( ) ) : i1III11I11 = I1II111i1 . group
  if 16 - 16: O0 . Oo0Ooo / oO0o * OoooooooOO * i1IIi - Oo0Ooo
  group , i1III11I11 , i1IiI1 = lisp_sites_by_eid . walk_cache ( lisp_neg_prefix_walk , ( group , i1III11I11 , i1IiI1 ) )
  if 5 - 5: iIii1I11I1II1
  if 43 - 43: iII111i / i11iIiiIii
  i1IiI1 . mask_address ( i1IiI1 . mask_len )
  if 8 - 8: I1ii11iIi11i . i11iIiiIii . Oo0Ooo % I1IiiI % ooOoO0o
  lprint ( ( "Least specific prefix computed from site-cache for " + "group EID {} using auth-prefix {} is {}" ) . format ( group . print_address ( ) , i1III11I11 . print_prefix ( ) if ( i1III11I11 != None ) else "'not found'" ,
  # oO0o . Oo0Ooo
  # ooOoO0o
  # I1ii11iIi11i * I1ii11iIi11i * iII111i . OOooOOo % iII111i
 i1IiI1 . print_prefix ( ) ) )
  if 20 - 20: o0oOOo0O0Ooo
  IIi11o0oO = I1II111i1 . source_cache
  if 54 - 54: II111iiii * OoOoOO00
  if 46 - 46: ooOoO0o . I1IiiI - ooOoO0o + Oo0Ooo
  if 31 - 31: OOooOOo + ooOoO0o . i1IIi - OoO0O00
  if 16 - 16: I11i + I1IiiI - Ii1I / I1ii11iIi11i + Ii1I
  if 38 - 38: i1IIi * iIii1I11I1II1 * iII111i + OoOoOO00
 O0oo0oo0 = LISP_DDT_ACTION_DELEGATION_HOLE if ( i1III11I11 != None ) else LISP_DDT_ACTION_NOT_AUTH
 if 64 - 64: OoO0O00 % o0oOOo0O0Ooo
 if 72 - 72: O0 + OoOoOO00 % OOooOOo / oO0o / IiII
 if 98 - 98: Oo0Ooo . II111iiii * I11i
 if 39 - 39: IiII * o0oOOo0O0Ooo + Ii1I - I11i
 if 70 - 70: oO0o * ooOoO0o / ooOoO0o - Ii1I * Ii1I % OOooOOo
 if 91 - 91: OoO0O00 - OoO0O00 % O0
 eid , i1III11I11 , O0OOOo = IIi11o0oO . walk_cache ( lisp_neg_prefix_walk ,
 ( eid , i1III11I11 , O0OOOo ) )
 if 67 - 67: ooOoO0o * i1IIi
 if 66 - 66: o0oOOo0O0Ooo - I1ii11iIi11i . OoOoOO00 / iII111i - Ii1I - i1IIi
 if 97 - 97: oO0o % iII111i - OOooOOo . OoooooooOO
 if 94 - 94: Oo0Ooo
 O0OOOo . mask_address ( O0OOOo . mask_len )
 if 10 - 10: i11iIiiIii / I1ii11iIi11i . i1IIi + i1IIi * iII111i
 lprint ( ( "Least specific prefix computed from site-cache for EID {} " + "using auth-prefix {} is {}" ) . format ( green ( eid . print_address ( ) , False ) ,
 # OOooOOo % i11iIiiIii / O0 - OoOoOO00
 # I1ii11iIi11i . OoO0O00
 i1III11I11 . print_prefix ( ) if ( i1III11I11 != None ) else "'not found'" , O0OOOo . print_prefix ( ) ) )
 if 19 - 19: I1IiiI / iII111i . OOooOOo / oO0o + I1ii11iIi11i + OOooOOo
 if 1 - 1: iIii1I11I1II1
 return ( [ O0OOOo , i1IiI1 , O0oo0oo0 ] )
 if 59 - 59: ooOoO0o % I1IiiI + i1IIi * I1Ii111 % o0oOOo0O0Ooo * II111iiii
 if 22 - 22: OoOoOO00 * O0 + OoOoOO00 / iIii1I11I1II1 + oO0o + IiII
 if 69 - 69: iIii1I11I1II1 . I1Ii111 * iII111i
 if 6 - 6: I11i - IiII - I11i - II111iiii
 if 72 - 72: i1IIi / OOooOOo . Oo0Ooo . oO0o
 if 72 - 72: o0oOOo0O0Ooo % iIii1I11I1II1
 if 74 - 74: Oo0Ooo % OOooOOo + i11iIiiIii
 if 17 - 17: OoOoOO00 . I1IiiI
def lisp_ms_send_map_referral ( lisp_sockets , map_request , ecm_source , port ,
 action , eid_prefix , group_prefix ) :
 if 30 - 30: i1IIi * OoOoOO00 * I11i . O0
 Oo00o = map_request . target_eid
 i1i11Ii1 = map_request . target_group
 i11III1I = map_request . nonce
 if 45 - 45: iII111i
 if ( action == LISP_DDT_ACTION_MS_ACK ) : Ii1 = 1440
 if 99 - 99: o0oOOo0O0Ooo % ooOoO0o % i11iIiiIii
 if 32 - 32: IiII - Ii1I
 if 44 - 44: OoooooooOO . oO0o
 if 30 - 30: I1Ii111 % IiII / II111iiii
 OOOoo = lisp_map_referral ( )
 OOOoo . record_count = 1
 OOOoo . nonce = i11III1I
 oOo = OOOoo . encode ( )
 OOOoo . print_map_referral ( )
 if 68 - 68: oO0o / O0 / OOooOOo
 o000ooo0o0O = False
 if 3 - 3: o0oOOo0O0Ooo / o0oOOo0O0Ooo
 if 17 - 17: OoO0O00 * i1IIi
 if 50 - 50: OoOoOO00 + I11i
 if 56 - 56: OOooOOo * OOooOOo + I1IiiI % I1IiiI - I11i
 if 1 - 1: OoooooooOO . ooOoO0o - i1IIi
 if 73 - 73: iIii1I11I1II1 - I1Ii111 % Oo0Ooo . O0
 if ( action == LISP_DDT_ACTION_SITE_NOT_FOUND ) :
  eid_prefix , group_prefix , action = lisp_ms_compute_neg_prefix ( Oo00o ,
 i1i11Ii1 )
  Ii1 = 15
  if 16 - 16: OoO0O00 / Oo0Ooo / IiII . Oo0Ooo - OoooooooOO
 if ( action == LISP_DDT_ACTION_MS_NOT_REG ) : Ii1 = 1
 if ( action == LISP_DDT_ACTION_MS_ACK ) : Ii1 = 1440
 if ( action == LISP_DDT_ACTION_DELEGATION_HOLE ) : Ii1 = 15
 if ( action == LISP_DDT_ACTION_NOT_AUTH ) : Ii1 = 0
 if 5 - 5: OoOoOO00 . I11i
 I1I1iI1IIII = False
 iI1111i = 0
 I1II111i1 = lisp_ddt_cache_lookup ( Oo00o , i1i11Ii1 , False )
 if ( I1II111i1 != None ) :
  iI1111i = len ( I1II111i1 . delegation_set )
  I1I1iI1IIII = I1II111i1 . is_ms_peer_entry ( )
  I1II111i1 . map_referrals_sent += 1
  if 20 - 20: ooOoO0o . iII111i % OOooOOo + i11iIiiIii
  if 64 - 64: i1IIi . o0oOOo0O0Ooo * I1Ii111 - O0
  if 76 - 76: I1IiiI % Ii1I + OoO0O00 + I1ii11iIi11i * II111iiii + Oo0Ooo
  if 3 - 3: Ii1I - I1IiiI + O0
  if 90 - 90: Ii1I + OoooooooOO . i11iIiiIii / Oo0Ooo % OoOoOO00 / IiII
 if ( action == LISP_DDT_ACTION_NOT_AUTH ) : o000ooo0o0O = True
 if ( action in ( LISP_DDT_ACTION_MS_REFERRAL , LISP_DDT_ACTION_MS_ACK ) ) :
  o000ooo0o0O = ( I1I1iI1IIII == False )
  if 45 - 45: OoooooooOO / oO0o . I1ii11iIi11i + OOooOOo
  if 54 - 54: Ii1I - o0oOOo0O0Ooo + OoOoOO00 / OoooooooOO
  if 61 - 61: I11i / IiII % OoooooooOO - i11iIiiIii * i1IIi % o0oOOo0O0Ooo
  if 67 - 67: o0oOOo0O0Ooo - Ii1I
  if 29 - 29: OoOoOO00 . I1ii11iIi11i
 IiII1iiI = lisp_eid_record ( )
 IiII1iiI . rloc_count = iI1111i
 IiII1iiI . authoritative = True
 IiII1iiI . action = action
 IiII1iiI . ddt_incomplete = o000ooo0o0O
 IiII1iiI . eid = eid_prefix
 IiII1iiI . group = group_prefix
 IiII1iiI . record_ttl = Ii1
 if 24 - 24: OOooOOo + i1IIi . I11i . OoOoOO00 + OoooooooOO
 oOo += IiII1iiI . encode ( )
 IiII1iiI . print_record ( "  " , True )
 if 98 - 98: ooOoO0o + i1IIi / I1IiiI
 if 1 - 1: IiII . OoooooooOO + II111iiii
 if 6 - 6: O0 * Oo0Ooo
 if 20 - 20: OoooooooOO * i1IIi * IiII / OoooooooOO - Oo0Ooo / i11iIiiIii
 if ( iI1111i != 0 ) :
  for oOoI1I in I1II111i1 . delegation_set :
   o00o = lisp_rloc_record ( )
   o00o . rloc = oOoI1I . delegate_address
   o00o . priority = oOoI1I . priority
   o00o . weight = oOoI1I . weight
   o00o . mpriority = 255
   o00o . mweight = 0
   o00o . reach_bit = True
   oOo += o00o . encode ( )
   o00o . print_record ( "    " )
   if 28 - 28: iIii1I11I1II1 % OOooOOo * I1IiiI
   if 28 - 28: O0 . OoOoOO00
   if 27 - 27: I1ii11iIi11i / II111iiii + O0 % I1ii11iIi11i
   if 72 - 72: I1IiiI - i1IIi
   if 11 - 11: iIii1I11I1II1 . OoO0O00 * Ii1I
   if 65 - 65: Oo0Ooo / OoooooooOO
   if 60 - 60: II111iiii + I1IiiI % oO0o - o0oOOo0O0Ooo
 if ( map_request . nonce != 0 ) : port = LISP_CTRL_PORT
 lisp_send_map_referral ( lisp_sockets , oOo , ecm_source , port )
 return
 if 50 - 50: iIii1I11I1II1 - i11iIiiIii / iII111i + ooOoO0o / OOooOOo
 if 80 - 80: IiII / OoooooooOO
 if 69 - 69: OoOoOO00 + IiII
 if 18 - 18: O0 / I11i
 if 10 - 10: I1Ii111 * i1IIi
 if 48 - 48: Oo0Ooo % i1IIi / iII111i . O0
 if 27 - 27: I11i + iIii1I11I1II1 - i11iIiiIii
 if 81 - 81: I11i + oO0o * iIii1I11I1II1 * IiII
def lisp_send_negative_map_reply ( sockets , eid , group , nonce , dest , port , ttl ,
 xtr_id , pubsub ) :
 if 7 - 7: I11i - I1IiiI . iII111i + O0 / iIii1I11I1II1 - I1Ii111
 lprint ( "Build negative Map-Reply EID-prefix {}, nonce 0x{} to ITR {}" . format ( lisp_print_eid_tuple ( eid , group ) , lisp_hex_string ( nonce ) ,
 # ooOoO0o . O0
 red ( dest . print_address ( ) , False ) ) )
 if 5 - 5: OoooooooOO % OoooooooOO * oO0o * ooOoO0o + ooOoO0o * oO0o
 O0oo0oo0 = LISP_NATIVE_FORWARD_ACTION if group . is_null ( ) else LISP_DROP_ACTION
 if 12 - 12: IiII - II111iiii
 if 71 - 71: i11iIiiIii . Oo0Ooo + oO0o + oO0o
 if 97 - 97: i11iIiiIii / O0 . iII111i . iIii1I11I1II1
 if 40 - 40: OoOoOO00 / iII111i / O0 * ooOoO0o
 if 58 - 58: iII111i % I11i
 if ( lisp_get_eid_hash ( eid ) != None ) :
  O0oo0oo0 = LISP_SEND_MAP_REQUEST_ACTION
  if 71 - 71: I1IiiI + OoO0O00 + IiII * I11i
  if 61 - 61: I1IiiI / OoOoOO00
 oOo = lisp_build_map_reply ( eid , group , [ ] , nonce , O0oo0oo0 , ttl , False ,
 None , False , False )
 if 58 - 58: o0oOOo0O0Ooo - Oo0Ooo % OoOoOO00 + I11i
 if 10 - 10: II111iiii / iIii1I11I1II1 % i11iIiiIii
 if 29 - 29: ooOoO0o - iII111i + IiII % Ii1I - oO0o - ooOoO0o
 if 43 - 43: oO0o
 if ( pubsub ) :
  lisp_process_pubsub ( sockets , oOo , eid , dest , port , nonce , ttl ,
 xtr_id )
 else :
  lisp_send_map_reply ( sockets , oOo , dest , port )
  if 22 - 22: I1Ii111 + i11iIiiIii
 return
 if 49 - 49: O0 % II111iiii . OOooOOo + iII111i + iIii1I11I1II1 / i11iIiiIii
 if 79 - 79: II111iiii + ooOoO0o - i1IIi - i1IIi + II111iiii . i1IIi
 if 78 - 78: I1IiiI * I11i % OOooOOo + Ii1I + OoOoOO00
 if 23 - 23: iII111i / Oo0Ooo % OoooooooOO * OoooooooOO . iII111i / I1ii11iIi11i
 if 30 - 30: oO0o - OoOoOO00 . I1IiiI
 if 17 - 17: OoOoOO00
 if 76 - 76: I1ii11iIi11i - ooOoO0o % OoooooooOO / Oo0Ooo % IiII / ooOoO0o
def lisp_retransmit_ddt_map_request ( mr ) :
 ooooooOoo = mr . mr_source . print_address ( )
 I1i1I = mr . print_eid_tuple ( )
 i11III1I = mr . nonce
 if 71 - 71: IiII * Oo0Ooo
 if 25 - 25: II111iiii
 if 8 - 8: OoO0O00
 if 17 - 17: iIii1I11I1II1 - Oo0Ooo
 if 25 - 25: O0 + I1ii11iIi11i
 if ( mr . last_request_sent_to ) :
  ooOII1ii1ii1I1 = mr . last_request_sent_to . print_address ( )
  IiIIiIiI1II = lisp_referral_cache_lookup ( mr . last_cached_prefix [ 0 ] ,
 mr . last_cached_prefix [ 1 ] , True )
  if ( IiIIiIiI1II and IiIIiIiI1II . referral_set . has_key ( ooOII1ii1ii1I1 ) ) :
   IiIIiIiI1II . referral_set [ ooOII1ii1ii1I1 ] . no_responses += 1
   if 68 - 68: O0 * I1ii11iIi11i + OoooooooOO . I1Ii111
   if 4 - 4: I11i + I11i
   if 42 - 42: OoOoOO00 % I1IiiI * Oo0Ooo * II111iiii + O0 - II111iiii
   if 97 - 97: I1IiiI
   if 87 - 87: I11i + iIii1I11I1II1
   if 91 - 91: oO0o
   if 58 - 58: i11iIiiIii / Ii1I - OoooooooOO
 if ( mr . retry_count == LISP_MAX_MAP_NOTIFY_RETRIES ) :
  lprint ( "DDT Map-Request retry limit reached for EID {}, nonce 0x{}" . format ( green ( I1i1I , False ) , lisp_hex_string ( i11III1I ) ) )
  if 25 - 25: i1IIi * ooOoO0o % OOooOOo / I1IiiI
  mr . dequeue_map_request ( )
  return
  if 75 - 75: i11iIiiIii
  if 38 - 38: iIii1I11I1II1
 mr . retry_count += 1
 if 80 - 80: OoO0O00
 o00oOOO = green ( ooooooOoo , False )
 i1 = green ( I1i1I , False )
 lprint ( "Retransmit DDT {} from {}ITR {} EIDs: {} -> {}, nonce 0x{}" . format ( bold ( "Map-Request" , False ) , "P" if mr . from_pitr else "" ,
 # ooOoO0o / II111iiii % OoOoOO00 % I1Ii111 . I1Ii111
 red ( mr . itr . print_address ( ) , False ) , o00oOOO , i1 ,
 lisp_hex_string ( i11III1I ) ) )
 if 43 - 43: I11i * II111iiii
 if 14 - 14: I1ii11iIi11i * OoooooooOO / OoO0O00 / OoOoOO00 / OoooooooOO
 if 17 - 17: i1IIi
 if 80 - 80: i1IIi - iIii1I11I1II1 + OoooooooOO + ooOoO0o / IiII - I1ii11iIi11i
 lisp_send_ddt_map_request ( mr , False )
 if 90 - 90: I1IiiI * ooOoO0o - I11i + O0 - I11i
 if 59 - 59: OOooOOo % II111iiii
 if 30 - 30: i1IIi / I1ii11iIi11i
 if 4 - 4: Oo0Ooo
 mr . retransmit_timer = threading . Timer ( LISP_DDT_MAP_REQUEST_INTERVAL ,
 lisp_retransmit_ddt_map_request , [ mr ] )
 mr . retransmit_timer . start ( )
 return
 if 31 - 31: IiII
 if 86 - 86: Oo0Ooo + IiII / o0oOOo0O0Ooo % OoOoOO00
 if 49 - 49: iIii1I11I1II1 % Oo0Ooo % I11i * Ii1I - OoO0O00
 if 15 - 15: i11iIiiIii + o0oOOo0O0Ooo . Ii1I . I1IiiI
 if 8 - 8: iII111i % II111iiii + IiII
 if 5 - 5: i1IIi + II111iiii
 if 75 - 75: OOooOOo . IiII . I1IiiI + OoooooooOO
 if 35 - 35: I11i % i1IIi - I1ii11iIi11i . Oo0Ooo
def lisp_get_referral_node ( referral , source_eid , dest_eid ) :
 if 69 - 69: ooOoO0o * OoO0O00 % o0oOOo0O0Ooo * o0oOOo0O0Ooo
 if 35 - 35: I1IiiI . OOooOOo * OoO0O00 . I1ii11iIi11i - I1IiiI
 if 5 - 5: i1IIi * II111iiii
 if 64 - 64: I1IiiI * iIii1I11I1II1 % I1Ii111
 Iii11I = [ ]
 for IiOO00O00 in referral . referral_set . values ( ) :
  if ( IiOO00O00 . updown == False ) : continue
  if ( len ( Iii11I ) == 0 or Iii11I [ 0 ] . priority == IiOO00O00 . priority ) :
   Iii11I . append ( IiOO00O00 )
  elif ( Iii11I [ 0 ] . priority > IiOO00O00 . priority ) :
   Iii11I = [ ]
   Iii11I . append ( IiOO00O00 )
   if 58 - 58: I1ii11iIi11i - oO0o % I11i * O0
   if 43 - 43: OoOoOO00 + O0
   if 71 - 71: ooOoO0o * I1IiiI / I1ii11iIi11i
 i1ii = len ( Iii11I )
 if ( i1ii == 0 ) : return ( None )
 if 59 - 59: OoOoOO00 . iIii1I11I1II1 / I1ii11iIi11i - OoO0O00 - OoOoOO00
 ooo000 = dest_eid . hash_address ( source_eid )
 ooo000 = ooo000 % i1ii
 return ( Iii11I [ ooo000 ] )
 if 69 - 69: o0oOOo0O0Ooo
 if 67 - 67: OoO0O00 + iIii1I11I1II1
 if 20 - 20: OoOoOO00 + Oo0Ooo - OoOoOO00
 if 40 - 40: oO0o . O0 / IiII % I11i * i1IIi
 if 75 - 75: Ii1I . o0oOOo0O0Ooo / I11i
 if 31 - 31: I11i + OOooOOo / I1IiiI / iIii1I11I1II1 + o0oOOo0O0Ooo
 if 76 - 76: i1IIi
def lisp_send_ddt_map_request ( mr , send_to_root ) :
 o000oOOooO00 = mr . lisp_sockets
 i11III1I = mr . nonce
 OooOoOOo0 = mr . itr
 O0Oi1iIIiI1i = mr . mr_source
 oO00oo000O = mr . print_eid_tuple ( )
 if 18 - 18: i1IIi
 if 42 - 42: II111iiii - i1IIi . oO0o % OOooOOo % ooOoO0o - i11iIiiIii
 if 23 - 23: OOooOOo + iIii1I11I1II1 - i1IIi
 if 72 - 72: OOooOOo . I1IiiI * O0 + i11iIiiIii - iII111i
 if 79 - 79: o0oOOo0O0Ooo + I1ii11iIi11i
 if ( mr . send_count == 8 ) :
  lprint ( "Giving up on map-request-queue entry {}, nonce 0x{}" . format ( green ( oO00oo000O , False ) , lisp_hex_string ( i11III1I ) ) )
  if 46 - 46: I11i
  mr . dequeue_map_request ( )
  return
  if 78 - 78: IiII / II111iiii
  if 55 - 55: Oo0Ooo
  if 80 - 80: o0oOOo0O0Ooo - I1Ii111 * O0 * iIii1I11I1II1
  if 59 - 59: I1ii11iIi11i + I11i / OoO0O00
  if 36 - 36: o0oOOo0O0Ooo + ooOoO0o * I11i
  if 81 - 81: OOooOOo * I11i - I1ii11iIi11i
 if ( send_to_root ) :
  OOOo0o000oO0O = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  II1I = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  mr . tried_root = True
  lprint ( "Jumping up to root for EID {}" . format ( green ( oO00oo000O , False ) ) )
 else :
  OOOo0o000oO0O = mr . eid
  II1I = mr . group
  if 34 - 34: I1Ii111 * I1ii11iIi11i % Oo0Ooo . OoO0O00 + OoO0O00
  if 19 - 19: OOooOOo - Ii1I % Ii1I * Oo0Ooo % iIii1I11I1II1 . Ii1I
  if 9 - 9: Oo0Ooo . I1IiiI - i11iIiiIii / o0oOOo0O0Ooo
  if 54 - 54: i11iIiiIii + I1Ii111 . I1Ii111 * I1ii11iIi11i % I1Ii111 - OoooooooOO
  if 76 - 76: IiII + i1IIi + i11iIiiIii . oO0o
 I1IIiII1 = lisp_referral_cache_lookup ( OOOo0o000oO0O , II1I , False )
 if ( I1IIiII1 == None ) :
  lprint ( "No referral cache entry found" )
  lisp_send_negative_map_reply ( o000oOOooO00 , OOOo0o000oO0O , II1I ,
 i11III1I , OooOoOOo0 , mr . sport , 15 , None , False )
  return
  if 35 - 35: iII111i / iII111i * OoOoOO00 - i11iIiiIii
  if 27 - 27: i1IIi / I11i + I1Ii111 . II111iiii * OoO0O00
 OoO0OOOooo = I1IIiII1 . print_eid_tuple ( )
 lprint ( "Found referral cache entry {}, referral-type: {}" . format ( OoO0OOOooo ,
 I1IIiII1 . print_referral_type ( ) ) )
 if 10 - 10: OoO0O00 % iIii1I11I1II1 * OoOoOO00 / i11iIiiIii - I1IiiI . O0
 IiOO00O00 = lisp_get_referral_node ( I1IIiII1 , O0Oi1iIIiI1i , mr . eid )
 if ( IiOO00O00 == None ) :
  lprint ( "No reachable referral-nodes found" )
  mr . dequeue_map_request ( )
  lisp_send_negative_map_reply ( o000oOOooO00 , I1IIiII1 . eid ,
 I1IIiII1 . group , i11III1I , OooOoOOo0 , mr . sport , 1 , None , False )
  return
  if 2 - 2: II111iiii
  if 13 - 13: Ii1I % i11iIiiIii
 lprint ( "Send DDT Map-Request to {} {} for EID {}, nonce 0x{}" . format ( IiOO00O00 . referral_address . print_address ( ) ,
 # I1Ii111
 I1IIiII1 . print_referral_type ( ) , green ( oO00oo000O , False ) ,
 lisp_hex_string ( i11III1I ) ) )
 if 68 - 68: OoOoOO00 * I1Ii111 - OoO0O00 / i1IIi % OoOoOO00 / i1IIi
 if 41 - 41: oO0o % oO0o . iIii1I11I1II1 . o0oOOo0O0Ooo
 if 95 - 95: i1IIi . ooOoO0o . Oo0Ooo
 if 13 - 13: OOooOOo - Oo0Ooo % O0 . I1Ii111
 oo0OoOiI1I1i1i = ( I1IIiII1 . referral_type == LISP_DDT_ACTION_MS_REFERRAL or
 I1IIiII1 . referral_type == LISP_DDT_ACTION_MS_ACK )
 lisp_send_ecm ( o000oOOooO00 , mr . packet , O0Oi1iIIiI1i , mr . sport , mr . eid ,
 IiOO00O00 . referral_address , to_ms = oo0OoOiI1I1i1i , ddt = True )
 if 55 - 55: OoOoOO00 + i11iIiiIii * oO0o
 if 84 - 84: I1Ii111 - iII111i * Ii1I * i11iIiiIii % oO0o / ooOoO0o
 if 56 - 56: OOooOOo / i11iIiiIii - OoooooooOO . i1IIi
 if 70 - 70: oO0o / OoO0O00 % Oo0Ooo . Oo0Ooo
 mr . last_request_sent_to = IiOO00O00 . referral_address
 mr . last_sent = lisp_get_timestamp ( )
 mr . send_count += 1
 IiOO00O00 . map_requests_sent += 1
 return
 if 51 - 51: I1IiiI + O0 / i1IIi / iIii1I11I1II1 % o0oOOo0O0Ooo % O0
 if 44 - 44: OoOoOO00 * ooOoO0o - Ii1I
 if 82 - 82: Ii1I - O0 * ooOoO0o . ooOoO0o
 if 32 - 32: o0oOOo0O0Ooo . OoooooooOO % OOooOOo
 if 2 - 2: OoOoOO00 + I1ii11iIi11i + oO0o
 if 27 - 27: OoooooooOO - Ii1I / OoooooooOO + OoO0O00
 if 58 - 58: OOooOOo * I11i . I1IiiI
 if 46 - 46: I11i + II111iiii * iII111i % ooOoO0o - I1IiiI
def lisp_mr_process_map_request ( lisp_sockets , packet , map_request , ecm_source ,
 sport , mr_source ) :
 if 73 - 73: I1ii11iIi11i * iIii1I11I1II1 . I1Ii111 - Ii1I
 Oo00o = map_request . target_eid
 i1i11Ii1 = map_request . target_group
 I1i1I = map_request . print_eid_tuple ( )
 ooooooOoo = mr_source . print_address ( )
 i11III1I = map_request . nonce
 if 11 - 11: I11i
 o00oOOO = green ( ooooooOoo , False )
 i1 = green ( I1i1I , False )
 lprint ( "Received Map-Request from {}ITR {} EIDs: {} -> {}, nonce 0x{}" . format ( "P" if map_request . pitr_bit else "" ,
 # i1IIi / O0 * OoOoOO00
 red ( ecm_source . print_address ( ) , False ) , o00oOOO , i1 ,
 lisp_hex_string ( i11III1I ) ) )
 if 29 - 29: oO0o * OoO0O00 . IiII
 if 99 - 99: oO0o
 if 21 - 21: IiII * OoO0O00 / OoooooooOO % o0oOOo0O0Ooo + OoO0O00
 if 25 - 25: IiII % OOooOOo + Ii1I * I1ii11iIi11i
 Ii1IIi1III1i = lisp_ddt_map_request ( lisp_sockets , packet , Oo00o , i1i11Ii1 , i11III1I )
 Ii1IIi1III1i . packet = packet
 Ii1IIi1III1i . itr = ecm_source
 Ii1IIi1III1i . mr_source = mr_source
 Ii1IIi1III1i . sport = sport
 Ii1IIi1III1i . from_pitr = map_request . pitr_bit
 Ii1IIi1III1i . queue_map_request ( )
 if 20 - 20: i1IIi % II111iiii . IiII % iIii1I11I1II1
 lisp_send_ddt_map_request ( Ii1IIi1III1i , False )
 return
 if 9 - 9: o0oOOo0O0Ooo
 if 68 - 68: OOooOOo % Oo0Ooo * ooOoO0o * OoO0O00 / iII111i
 if 96 - 96: i11iIiiIii - I1IiiI % OoOoOO00 * Ii1I % OoO0O00 % O0
 if 100 - 100: oO0o . OoooooooOO
 if 58 - 58: I11i % OoooooooOO
 if 97 - 97: OOooOOo - IiII
 if 77 - 77: i1IIi / IiII - o0oOOo0O0Ooo . Oo0Ooo / o0oOOo0O0Ooo . OoooooooOO
def lisp_process_map_request ( lisp_sockets , packet , ecm_source , ecm_port ,
 mr_source , mr_port , ddt_request , ttl ) :
 if 54 - 54: i1IIi * i11iIiiIii / I1IiiI * i1IIi
 oOO = packet
 IIi11i1I = lisp_map_request ( )
 packet = IIi11i1I . decode ( packet , mr_source , mr_port )
 if ( packet == None ) :
  lprint ( "Could not decode Map-Request packet" )
  return
  if 76 - 76: iIii1I11I1II1 + o0oOOo0O0Ooo % OOooOOo % iIii1I11I1II1 . Oo0Ooo % o0oOOo0O0Ooo
  if 18 - 18: I1IiiI * oO0o / Oo0Ooo / OOooOOo
 IIi11i1I . print_map_request ( )
 if 53 - 53: i1IIi - IiII - OoooooooOO - OOooOOo - OoOoOO00 / IiII
 if 22 - 22: i1IIi + IiII
 if 30 - 30: OoOoOO00
 if 75 - 75: Ii1I . i1IIi / I1IiiI * iII111i . IiII / OoOoOO00
 if ( IIi11i1I . rloc_probe ) :
  lisp_process_rloc_probe_request ( lisp_sockets , IIi11i1I ,
 mr_source , mr_port , ttl )
  return
  if 58 - 58: ooOoO0o + OOooOOo / ooOoO0o / i11iIiiIii
  if 95 - 95: ooOoO0o
  if 10 - 10: OoO0O00 % ooOoO0o * o0oOOo0O0Ooo
  if 37 - 37: Ii1I . o0oOOo0O0Ooo
  if 34 - 34: ooOoO0o * IiII . Ii1I + iIii1I11I1II1
 if ( IIi11i1I . smr_bit ) :
  lisp_process_smr ( IIi11i1I )
  if 1 - 1: i11iIiiIii + I11i
  if 78 - 78: Ii1I % Oo0Ooo / OoO0O00 . iIii1I11I1II1 . II111iiii
  if 67 - 67: oO0o % I1Ii111
  if 72 - 72: I1IiiI . i11iIiiIii . OoOoOO00 + I1IiiI - I1Ii111 + iII111i
  if 15 - 15: I1IiiI
 if ( IIi11i1I . smr_invoked_bit ) :
  lisp_process_smr_invoked_request ( IIi11i1I )
  if 88 - 88: IiII / I1ii11iIi11i % I11i + i11iIiiIii * O0 . I1Ii111
  if 69 - 69: Oo0Ooo - OOooOOo / I1IiiI . i11iIiiIii * OoO0O00
  if 45 - 45: I1Ii111 + OOooOOo
  if 78 - 78: OoOoOO00 . Oo0Ooo % I11i
  if 7 - 7: I1ii11iIi11i % Ii1I . OoooooooOO - iII111i
 if ( lisp_i_am_etr ) :
  lisp_etr_process_map_request ( lisp_sockets , IIi11i1I , mr_source ,
 mr_port , ttl )
  if 18 - 18: O0 * OoooooooOO % IiII - iIii1I11I1II1 % IiII * o0oOOo0O0Ooo
  if 13 - 13: OoO0O00 + i11iIiiIii + O0 / ooOoO0o % iIii1I11I1II1
  if 75 - 75: oO0o / i1IIi / Ii1I * Oo0Ooo
  if 75 - 75: Oo0Ooo / OoooooooOO
  if 98 - 98: II111iiii - I1Ii111 . ooOoO0o * iII111i
 if ( lisp_i_am_ms ) :
  packet = oOO
  Oo00o , i1i11Ii1 , iIIi1 = lisp_ms_process_map_request ( lisp_sockets ,
 oOO , IIi11i1I , mr_source , mr_port , ecm_source )
  if ( ddt_request ) :
   lisp_ms_send_map_referral ( lisp_sockets , IIi11i1I , ecm_source ,
 ecm_port , iIIi1 , Oo00o , i1i11Ii1 )
   if 76 - 76: i1IIi . OoO0O00 . O0 / OOooOOo - iII111i
  return
  if 60 - 60: I1IiiI
  if 3 - 3: II111iiii % IiII % I1IiiI - I1IiiI . I1Ii111 - OoOoOO00
  if 18 - 18: O0
  if 26 - 26: i1IIi - iIii1I11I1II1
  if 8 - 8: I1Ii111
 if ( lisp_i_am_mr and not ddt_request ) :
  lisp_mr_process_map_request ( lisp_sockets , oOO , IIi11i1I ,
 ecm_source , mr_port , mr_source )
  if 86 - 86: i1IIi
  if 26 - 26: o0oOOo0O0Ooo % I1Ii111 / Oo0Ooo
  if 68 - 68: II111iiii / Oo0Ooo / Oo0Ooo
  if 1 - 1: Oo0Ooo
  if 73 - 73: Ii1I * iIii1I11I1II1 / o0oOOo0O0Ooo - o0oOOo0O0Ooo / i1IIi
 if ( lisp_i_am_ddt or ddt_request ) :
  packet = oOO
  lisp_ddt_process_map_request ( lisp_sockets , IIi11i1I , ecm_source ,
 ecm_port )
  if 64 - 64: Ii1I * I1ii11iIi11i % II111iiii
 return
 if 31 - 31: iIii1I11I1II1 % Oo0Ooo . I1IiiI % ooOoO0o
 if 38 - 38: I1ii11iIi11i + I1Ii111 * I11i / OoO0O00 + o0oOOo0O0Ooo
 if 46 - 46: iII111i
 if 56 - 56: Oo0Ooo / II111iiii
 if 61 - 61: Ii1I - i1IIi / ooOoO0o - Oo0Ooo / IiII % Oo0Ooo
 if 53 - 53: OoooooooOO + iII111i % II111iiii * IiII
 if 10 - 10: OoOoOO00 % I11i
 if 46 - 46: i1IIi % IiII
def lisp_store_mr_stats ( source , nonce ) :
 Ii1IIi1III1i = lisp_get_map_resolver ( source , None )
 if ( Ii1IIi1III1i == None ) : return
 if 45 - 45: I1ii11iIi11i / I1ii11iIi11i - OoO0O00
 if 54 - 54: Ii1I + I1IiiI * OoOoOO00 + oO0o
 if 10 - 10: Ii1I - I1IiiI / IiII / iII111i - I1Ii111 - o0oOOo0O0Ooo
 if 75 - 75: OOooOOo . ooOoO0o
 Ii1IIi1III1i . neg_map_replies_received += 1
 Ii1IIi1III1i . last_reply = lisp_get_timestamp ( )
 if 32 - 32: i1IIi / I11i + iIii1I11I1II1 . OOooOOo
 if 67 - 67: iII111i - OoO0O00 % I1ii11iIi11i * Oo0Ooo
 if 51 - 51: I1IiiI + O0
 if 4 - 4: ooOoO0o / OoO0O00 * iIii1I11I1II1 * iIii1I11I1II1
 if ( ( Ii1IIi1III1i . neg_map_replies_received % 100 ) == 0 ) : Ii1IIi1III1i . total_rtt = 0
 if 33 - 33: iII111i . iIii1I11I1II1 - Ii1I
 if 85 - 85: OoOoOO00
 if 57 - 57: Oo0Ooo - II111iiii - I1ii11iIi11i * oO0o
 if 41 - 41: I11i / ooOoO0o + IiII % OoooooooOO
 if ( Ii1IIi1III1i . last_nonce == nonce ) :
  Ii1IIi1III1i . total_rtt += ( time . time ( ) - Ii1IIi1III1i . last_used )
  Ii1IIi1III1i . last_nonce = 0
  if 72 - 72: Ii1I
 if ( ( Ii1IIi1III1i . neg_map_replies_received % 10 ) == 0 ) : Ii1IIi1III1i . last_nonce = 0
 return
 if 22 - 22: o0oOOo0O0Ooo / OoO0O00 + OoOoOO00 + Ii1I . II111iiii * I11i
 if 85 - 85: i11iIiiIii / I11i
 if 28 - 28: i11iIiiIii + IiII / I11i . Ii1I / OoO0O00
 if 100 - 100: o0oOOo0O0Ooo - I11i . o0oOOo0O0Ooo
 if 90 - 90: OoOoOO00 / II111iiii / I11i * I11i - iIii1I11I1II1
 if 87 - 87: IiII
 if 92 - 92: OoO0O00 / IiII - ooOoO0o
def lisp_process_map_reply ( lisp_sockets , packet , source , ttl ) :
 global lisp_map_cache
 if 45 - 45: iII111i - I11i * ooOoO0o * OOooOOo / I1Ii111 * iII111i
 Iiii = lisp_map_reply ( )
 packet = Iiii . decode ( packet )
 if ( packet == None ) :
  lprint ( "Could not decode Map-Reply packet" )
  return
  if 33 - 33: iIii1I11I1II1 % I1ii11iIi11i - OOooOOo % iIii1I11I1II1 + I11i / i11iIiiIii
 Iiii . print_map_reply ( )
 if 64 - 64: I11i * ooOoO0o / OoooooooOO
 if 38 - 38: iIii1I11I1II1 . OoO0O00 * OoOoOO00 + OoOoOO00 + ooOoO0o
 if 44 - 44: I1ii11iIi11i * OOooOOo % OoO0O00 . I1IiiI % Ii1I + II111iiii
 if 100 - 100: oO0o - II111iiii . o0oOOo0O0Ooo
 oOo00OoOoo = None
 for II11iIII1i1I in range ( Iiii . record_count ) :
  IiII1iiI = lisp_eid_record ( )
  packet = IiII1iiI . decode ( packet )
  if ( packet == None ) :
   lprint ( "Could not decode EID-record in Map-Reply packet" )
   return
   if 65 - 65: I1IiiI - OoO0O00 / iIii1I11I1II1 * iII111i + OoOoOO00 + IiII
  IiII1iiI . print_record ( "  " , False )
  if 16 - 16: OoO0O00 % OOooOOo . I11i . I11i
  if 4 - 4: O0 + I11i / OoOoOO00 * iIii1I11I1II1 . Ii1I
  if 68 - 68: Oo0Ooo % ooOoO0o + i11iIiiIii / oO0o / II111iiii
  if 63 - 63: OoO0O00 % i1IIi - OoooooooOO / ooOoO0o
  if 75 - 75: OOooOOo + IiII + ooOoO0o / I1IiiI . iIii1I11I1II1 / Oo0Ooo
  if ( IiII1iiI . rloc_count == 0 ) :
   lisp_store_mr_stats ( source , Iiii . nonce )
   if 81 - 81: I1Ii111 % II111iiii - Oo0Ooo / I1IiiI + i11iIiiIii . I11i
   if 67 - 67: ooOoO0o . I1Ii111 . Oo0Ooo . Ii1I + iIii1I11I1II1 / OoooooooOO
  O0OOo0OO0oOo = ( IiII1iiI . group . is_null ( ) == False )
  if 65 - 65: Oo0Ooo + Ii1I + I1ii11iIi11i
  if 76 - 76: IiII + IiII / I1IiiI / ooOoO0o . OoOoOO00
  if 20 - 20: IiII / i11iIiiIii - ooOoO0o . OoooooooOO + OoooooooOO
  if 27 - 27: OOooOOo + iIii1I11I1II1 . I1Ii111 % i1IIi % iII111i
  if 13 - 13: IiII / I11i + ooOoO0o - II111iiii . OOooOOo
  if ( lisp_decent_push_configured ) :
   O0oo0oo0 = IiII1iiI . action
   if ( O0OOo0OO0oOo and O0oo0oo0 == LISP_DROP_ACTION ) :
    if ( IiII1iiI . eid . is_local ( ) ) : continue
    if 17 - 17: I1ii11iIi11i . Ii1I / IiII - i1IIi - Ii1I
    if 95 - 95: IiII % I11i % iIii1I11I1II1 . OoO0O00
    if 11 - 11: i11iIiiIii - IiII . o0oOOo0O0Ooo / IiII - I1IiiI
    if 66 - 66: iIii1I11I1II1 . i1IIi . i11iIiiIii % I1ii11iIi11i * OOooOOo % IiII
    if 34 - 34: I1IiiI % I11i - iII111i - i11iIiiIii - iIii1I11I1II1 / i1IIi
    if 7 - 7: I1IiiI + iIii1I11I1II1 . oO0o
    if 17 - 17: OoO0O00 / OoO0O00 + o0oOOo0O0Ooo / OOooOOo . I1ii11iIi11i % IiII
  if ( IiII1iiI . eid . is_null ( ) ) : continue
  if 40 - 40: OoOoOO00
  if 81 - 81: Ii1I % I1Ii111 / I1ii11iIi11i % iII111i
  if 39 - 39: i1IIi . iII111i . Oo0Ooo % Oo0Ooo * IiII % Ii1I
  if 40 - 40: o0oOOo0O0Ooo * i11iIiiIii . ooOoO0o
  if 63 - 63: I1Ii111 / Ii1I - iIii1I11I1II1 / i11iIiiIii / IiII + I11i
  if ( O0OOo0OO0oOo ) :
   ooooOoo000O = lisp_map_cache_lookup ( IiII1iiI . eid , IiII1iiI . group )
  else :
   ooooOoo000O = lisp_map_cache . lookup_cache ( IiII1iiI . eid , True )
   if 10 - 10: i1IIi . IiII
  IIiIIiiIIi1 = ( ooooOoo000O == None )
  if 52 - 52: I1Ii111 - OOooOOo * OoOoOO00
  if 54 - 54: iIii1I11I1II1 * OoO0O00 / Oo0Ooo + OoooooooOO
  if 38 - 38: iIii1I11I1II1 + OOooOOo + OoO0O00 . iII111i / i1IIi + II111iiii
  if 54 - 54: Ii1I - I1IiiI + iII111i * iII111i
  iiiI11II1IiIi = [ ]
  for o0000o0O0ooo in range ( IiII1iiI . rloc_count ) :
   o00o = lisp_rloc_record ( )
   o00o . keys = Iiii . keys
   packet = o00o . decode ( packet , Iiii . nonce )
   if ( packet == None ) :
    lprint ( "Could not decode RLOC-record in Map-Reply packet" )
    return
    if 87 - 87: I11i
   o00o . print_record ( "    " )
   if 67 - 67: i1IIi / i1IIi + IiII . oO0o
   OoOO0 = None
   if ( ooooOoo000O ) : OoOO0 = ooooOoo000O . get_rloc ( o00o . rloc )
   if ( OoOO0 ) :
    Oo0o0o0oo = OoOO0
   else :
    Oo0o0o0oo = lisp_rloc ( )
    if 75 - 75: oO0o * OoO0O00 * I11i + oO0o + O0 . I1Ii111
    if 8 - 8: I1ii11iIi11i / i1IIi - I1ii11iIi11i + Ii1I + OoO0O00 - I11i
    if 79 - 79: OoooooooOO - I1Ii111 * I1IiiI . I1Ii111 - iIii1I11I1II1
    if 27 - 27: OoOoOO00 % OoOoOO00 % II111iiii
    if 45 - 45: iIii1I11I1II1 . o0oOOo0O0Ooo % I1IiiI
    if 10 - 10: I1IiiI / i1IIi * o0oOOo0O0Ooo + Oo0Ooo - OoOoOO00 % iII111i
    if 88 - 88: Ii1I % Ii1I
   Iiiii = Oo0o0o0oo . store_rloc_from_record ( o00o , Iiii . nonce ,
 source )
   Oo0o0o0oo . echo_nonce_capable = Iiii . echo_nonce_capable
   if 29 - 29: OOooOOo % I1ii11iIi11i
   if ( Oo0o0o0oo . echo_nonce_capable ) :
    ooOOo0o = Oo0o0o0oo . rloc . print_address_no_iid ( )
    if ( lisp_get_echo_nonce ( None , ooOOo0o ) == None ) :
     lisp_echo_nonce ( ooOOo0o )
     if 57 - 57: I1ii11iIi11i - OoOoOO00 + IiII
     if 58 - 58: OOooOOo % I1IiiI / oO0o . ooOoO0o . OoO0O00 / IiII
     if 72 - 72: ooOoO0o + ooOoO0o + o0oOOo0O0Ooo - o0oOOo0O0Ooo % Ii1I
     if 52 - 52: I11i % i1IIi . I1ii11iIi11i
     if 62 - 62: ooOoO0o - I1ii11iIi11i
     if 71 - 71: I11i
     if 34 - 34: oO0o / O0 * oO0o
   if ( ooooOoo000O and ooooOoo000O . gleaned ) :
    Oo0o0o0oo = ooooOoo000O . rloc_set [ 0 ]
    Iiiii = Oo0o0o0oo . translated_port
    if 47 - 47: iIii1I11I1II1 - o0oOOo0O0Ooo % Ii1I
    if 38 - 38: ooOoO0o / IiII * I1ii11iIi11i % I1ii11iIi11i % oO0o
    if 82 - 82: I1ii11iIi11i . i11iIiiIii - I11i . iII111i / OOooOOo
    if 60 - 60: I1IiiI / I1IiiI / II111iiii
    if 59 - 59: OOooOOo . oO0o + ooOoO0o % o0oOOo0O0Ooo . i11iIiiIii
    if 27 - 27: OoOoOO00 - OoooooooOO / IiII / II111iiii * OOooOOo * ooOoO0o
    if 43 - 43: II111iiii . IiII - I1IiiI * I1ii11iIi11i + OoooooooOO
    if 34 - 34: I1Ii111 / i1IIi
    if 95 - 95: OoOoOO00 * OOooOOo
   if ( Iiii . rloc_probe and o00o . probe_bit ) :
    if ( Oo0o0o0oo . rloc . afi == source . afi ) :
     lisp_process_rloc_probe_reply ( Oo0o0o0oo . rloc , source , Iiiii ,
 Iiii . nonce , Iiii . hop_count , ttl )
     if 68 - 68: I1Ii111 / iIii1I11I1II1 % Ii1I
     if 77 - 77: i11iIiiIii + i11iIiiIii - I1ii11iIi11i % I1ii11iIi11i
     if 26 - 26: oO0o + OoooooooOO % o0oOOo0O0Ooo
     if 96 - 96: ooOoO0o * OoOoOO00 - II111iiii
     if 40 - 40: oO0o * OOooOOo + Ii1I + I11i * Ii1I + OoooooooOO
     if 77 - 77: OOooOOo + ooOoO0o / O0
   iiiI11II1IiIi . append ( Oo0o0o0oo )
   if 16 - 16: ooOoO0o + Oo0Ooo * Oo0Ooo . I11i - IiII
   if 49 - 49: ooOoO0o . Ii1I
   if 75 - 75: OOooOOo / II111iiii - Oo0Ooo + I1Ii111
   if 42 - 42: OoooooooOO * II111iiii + Ii1I % OoO0O00 / I1Ii111
   if ( lisp_data_plane_security and Oo0o0o0oo . rloc_recent_rekey ( ) ) :
    oOo00OoOoo = Oo0o0o0oo
    if 11 - 11: ooOoO0o / Oo0Ooo + i1IIi / IiII
    if 4 - 4: iII111i - Oo0Ooo
    if 100 - 100: OOooOOo . i1IIi
    if 15 - 15: O0 % Oo0Ooo % o0oOOo0O0Ooo . ooOoO0o * iII111i % O0
    if 31 - 31: i1IIi . Ii1I - OoooooooOO * I11i * ooOoO0o % oO0o
    if 61 - 61: I1Ii111 . Ii1I * I1ii11iIi11i
    if 59 - 59: OoOoOO00 + Oo0Ooo . I1ii11iIi11i - Ii1I
    if 48 - 48: I1Ii111 % Ii1I + I1IiiI * OoooooooOO % OoOoOO00 % i11iIiiIii
    if 13 - 13: iII111i % i1IIi
    if 13 - 13: iII111i / OoooooooOO + Ii1I / iII111i
    if 29 - 29: OOooOOo + ooOoO0o % o0oOOo0O0Ooo
  if ( Iiii . rloc_probe == False and lisp_nat_traversal ) :
   Oo = [ ]
   I1IIiI = [ ]
   for Oo0o0o0oo in iiiI11II1IiIi :
    if 99 - 99: OoooooooOO - Oo0Ooo / IiII
    if 70 - 70: i11iIiiIii + ooOoO0o
    if 44 - 44: OOooOOo
    if 77 - 77: OoooooooOO * Ii1I * iIii1I11I1II1 + IiII
    if 53 - 53: IiII + I1Ii111 + oO0o
    if ( Oo0o0o0oo . rloc . is_private_address ( ) ) :
     Oo0o0o0oo . priority = 1
     Oo0o0o0oo . state = LISP_RLOC_UNREACH_STATE
     Oo . append ( Oo0o0o0oo )
     I1IIiI . append ( Oo0o0o0oo . rloc . print_address_no_iid ( ) )
     continue
     if 31 - 31: OOooOOo + OoOoOO00 * OOooOOo + OoOoOO00 / o0oOOo0O0Ooo . iIii1I11I1II1
     if 1 - 1: I1Ii111 * i11iIiiIii % I1Ii111 - OoO0O00 + I1Ii111 / Oo0Ooo
     if 3 - 3: OOooOOo - i11iIiiIii / I1Ii111 . OOooOOo - OoO0O00
     if 60 - 60: OoOoOO00 / i1IIi . Ii1I - OoO0O00 - OoooooooOO
     if 39 - 39: I1IiiI + i1IIi * OoO0O00 % I11i
     if 41 - 41: I1ii11iIi11i * IiII
    if ( Oo0o0o0oo . priority == 254 and lisp_i_am_rtr == False ) :
     Oo . append ( Oo0o0o0oo )
     I1IIiI . append ( Oo0o0o0oo . rloc . print_address_no_iid ( ) )
     if 16 - 16: I1Ii111 % iIii1I11I1II1 / I1IiiI * OoOoOO00 / IiII / OoOoOO00
    if ( Oo0o0o0oo . priority != 254 and lisp_i_am_rtr ) :
     Oo . append ( Oo0o0o0oo )
     I1IIiI . append ( Oo0o0o0oo . rloc . print_address_no_iid ( ) )
     if 29 - 29: OoooooooOO / oO0o
     if 1 - 1: OoOoOO00 . i11iIiiIii % I1Ii111 + OoooooooOO - Oo0Ooo . I1ii11iIi11i
     if 46 - 46: i11iIiiIii + I11i - iIii1I11I1II1 / OoO0O00 - ooOoO0o / i1IIi
   if ( I1IIiI != [ ] ) :
    iiiI11II1IiIi = Oo
    lprint ( "NAT-traversal optimized RLOC-set: {}" . format ( I1IIiI ) )
    if 44 - 44: o0oOOo0O0Ooo + Oo0Ooo
    if 46 - 46: OOooOOo % I1IiiI
    if 66 - 66: iIii1I11I1II1 . o0oOOo0O0Ooo - ooOoO0o
    if 27 - 27: Oo0Ooo - i1IIi * OoooooooOO - OoOoOO00 + OoOoOO00
    if 24 - 24: i1IIi . OoOoOO00 / I1Ii111 + O0
    if 86 - 86: Ii1I * OoOoOO00 % I1ii11iIi11i + OOooOOo
    if 85 - 85: iII111i % i11iIiiIii
  Oo = [ ]
  for Oo0o0o0oo in iiiI11II1IiIi :
   if ( Oo0o0o0oo . json != None ) : continue
   Oo . append ( Oo0o0o0oo )
   if 78 - 78: i11iIiiIii / I11i / Oo0Ooo + II111iiii - I1ii11iIi11i / I1ii11iIi11i
  if ( Oo != [ ] ) :
   i1Ii11II = len ( iiiI11II1IiIi ) - len ( Oo )
   lprint ( "Pruning {} no-address RLOC-records for map-cache" . format ( i1Ii11II ) )
   if 28 - 28: iIii1I11I1II1 / IiII - iIii1I11I1II1 . i1IIi - O0 * ooOoO0o
   iiiI11II1IiIi = Oo
   if 41 - 41: Ii1I + IiII
   if 37 - 37: I1Ii111 / o0oOOo0O0Ooo - ooOoO0o - OoooooooOO . I1ii11iIi11i % I1Ii111
   if 53 - 53: I1IiiI % OOooOOo + Ii1I - Ii1I
   if 99 - 99: i1IIi * OoOoOO00 - i1IIi
   if 65 - 65: OoO0O00 / i11iIiiIii + I1ii11iIi11i + OoOoOO00
   if 82 - 82: Ii1I * OOooOOo % ooOoO0o / OoO0O00 - Oo0Ooo . I1Ii111
   if 90 - 90: I11i * i11iIiiIii % i1IIi + I1Ii111 / OoO0O00
   if 15 - 15: Oo0Ooo + oO0o . I11i % OoO0O00
  if ( Iiii . rloc_probe and ooooOoo000O != None ) : iiiI11II1IiIi = ooooOoo000O . rloc_set
  if 13 - 13: I1ii11iIi11i / ooOoO0o * I1Ii111
  if 45 - 45: I1ii11iIi11i - I11i
  if 60 - 60: OOooOOo - OOooOOo * OoOoOO00 / Ii1I % iII111i % Oo0Ooo
  if 75 - 75: iIii1I11I1II1 - IiII - I1Ii111
  if 4 - 4: i11iIiiIii % OoooooooOO . i11iIiiIii
  ooiIi1 = IIiIIiiIIi1
  if ( ooooOoo000O and iiiI11II1IiIi != ooooOoo000O . rloc_set ) :
   ooooOoo000O . delete_rlocs_from_rloc_probe_list ( )
   ooiIi1 = True
   if 49 - 49: i1IIi * iII111i - iIii1I11I1II1 % I11i * O0 / OoOoOO00
   if 48 - 48: IiII
   if 69 - 69: o0oOOo0O0Ooo % i11iIiiIii - OOooOOo - o0oOOo0O0Ooo
   if 98 - 98: o0oOOo0O0Ooo * OoO0O00 . OoooooooOO
   if 40 - 40: I1Ii111 + Oo0Ooo + I1Ii111
  o00ooO0OOOooo0 = ooooOoo000O . uptime if ( ooooOoo000O ) else None
  if ( ooooOoo000O == None or ooooOoo000O . gleaned == False ) :
   ooooOoo000O = lisp_mapping ( IiII1iiI . eid , IiII1iiI . group , iiiI11II1IiIi )
   ooooOoo000O . mapping_source = source
   ooooOoo000O . map_cache_ttl = IiII1iiI . store_ttl ( )
   ooooOoo000O . action = IiII1iiI . action
   ooooOoo000O . add_cache ( ooiIi1 )
   if 75 - 75: o0oOOo0O0Ooo % o0oOOo0O0Ooo . I1IiiI / OoO0O00
   if 22 - 22: Oo0Ooo / iIii1I11I1II1 + o0oOOo0O0Ooo
  IiI1iiIi1I1i = "Add"
  if ( o00ooO0OOOooo0 ) :
   ooooOoo000O . uptime = o00ooO0OOOooo0
   ooooOoo000O . refresh_time = lisp_get_timestamp ( )
   IiI1iiIi1I1i = "Replace"
   if 35 - 35: OoO0O00 + II111iiii / I11i
   if 45 - 45: i11iIiiIii . I1IiiI % I1Ii111 / I1ii11iIi11i
  lprint ( "{} {} map-cache with {} RLOCs" . format ( IiI1iiIi1I1i ,
 green ( ooooOoo000O . print_eid_tuple ( ) , False ) , len ( iiiI11II1IiIi ) ) )
  if 14 - 14: IiII . OOooOOo - Oo0Ooo * oO0o
  if 31 - 31: I1IiiI + OOooOOo
  if 90 - 90: I1Ii111 * OOooOOo / i1IIi / iIii1I11I1II1 / OoooooooOO
  if 37 - 37: O0 * I11i . O0 / II111iiii % oO0o
  if 19 - 19: Ii1I - oO0o
  if ( lisp_ipc_dp_socket and oOo00OoOoo != None ) :
   lisp_write_ipc_keys ( oOo00OoOoo )
   if 72 - 72: oO0o / I11i % II111iiii
   if 22 - 22: i11iIiiIii % IiII % IiII % I11i - OoooooooOO + I1IiiI
   if 31 - 31: I11i + I1ii11iIi11i . i1IIi * i11iIiiIii + I1ii11iIi11i
   if 97 - 97: ooOoO0o * iIii1I11I1II1 * i1IIi * II111iiii - OOooOOo - o0oOOo0O0Ooo
   if 37 - 37: II111iiii
   if 27 - 27: Oo0Ooo * OoooooooOO / I1IiiI
   if 43 - 43: OoO0O00
  if ( IIiIIiiIIi1 ) :
   oo00OO0Oooo = bold ( "RLOC-probe" , False )
   for Oo0o0o0oo in ooooOoo000O . best_rloc_set :
    ooOOo0o = red ( Oo0o0o0oo . rloc . print_address_no_iid ( ) , False )
    lprint ( "Trigger {} to {}" . format ( oo00OO0Oooo , ooOOo0o ) )
    lisp_send_map_request ( lisp_sockets , 0 , ooooOoo000O . eid , ooooOoo000O . group , Oo0o0o0oo )
    if 6 - 6: Ii1I - I1Ii111 . O0 - I1IiiI
    if 50 - 50: II111iiii . I1Ii111 + iII111i . OoO0O00 % I1IiiI * iII111i
    if 27 - 27: OoooooooOO
 return
 if 27 - 27: o0oOOo0O0Ooo % I1ii11iIi11i - I11i % ooOoO0o / OOooOOo / iII111i
 if 80 - 80: i1IIi
 if 74 - 74: I1ii11iIi11i . OoO0O00 + i11iIiiIii
 if 19 - 19: i1IIi / I1IiiI + IiII . iII111i
 if 68 - 68: iII111i
 if 29 - 29: II111iiii / II111iiii % OoO0O00 % Oo0Ooo . II111iiii
 if 33 - 33: OoooooooOO . OoO0O00 % OoooooooOO
 if 9 - 9: IiII * O0 + OOooOOo . II111iiii
def lisp_compute_auth ( packet , map_register , password ) :
 if ( map_register . alg_id == LISP_NONE_ALG_ID ) : return ( packet )
 if 14 - 14: iIii1I11I1II1 + i11iIiiIii + o0oOOo0O0Ooo + o0oOOo0O0Ooo - IiII / I1Ii111
 packet = map_register . zero_auth ( packet )
 ooo000 = lisp_hash_me ( packet , map_register . alg_id , password , False )
 if 70 - 70: OoooooooOO + I1IiiI / OOooOOo
 if 19 - 19: I1Ii111 + i1IIi % OoooooooOO + i1IIi
 if 16 - 16: I1Ii111 + II111iiii + IiII
 if 34 - 34: iIii1I11I1II1 - II111iiii - ooOoO0o + oO0o
 map_register . auth_data = ooo000
 packet = map_register . encode_auth ( packet )
 return ( packet )
 if 46 - 46: ooOoO0o % II111iiii
 if 61 - 61: OoO0O00 . I1IiiI
 if 89 - 89: IiII
 if 73 - 73: II111iiii + ooOoO0o % OOooOOo . oO0o / oO0o * i1IIi
 if 19 - 19: I1Ii111 + I11i
 if 21 - 21: OoOoOO00
 if 2 - 2: i1IIi . OOooOOo
def lisp_hash_me ( packet , alg_id , password , do_hex ) :
 if ( alg_id == LISP_NONE_ALG_ID ) : return ( True )
 if 23 - 23: Ii1I - OOooOOo
 if ( alg_id == LISP_SHA_1_96_ALG_ID ) :
  oO = hashlib . sha1
  if 28 - 28: OoO0O00 . IiII - i1IIi * OOooOOo - I1Ii111
 if ( alg_id == LISP_SHA_256_128_ALG_ID ) :
  oO = hashlib . sha256
  if 65 - 65: iIii1I11I1II1 / IiII / IiII
  if 57 - 57: OoOoOO00 . O0 / iII111i / i11iIiiIii
 if ( do_hex ) :
  ooo000 = hmac . new ( password , packet , oO ) . hexdigest ( )
 else :
  ooo000 = hmac . new ( password , packet , oO ) . digest ( )
  if 38 - 38: iII111i - Oo0Ooo / O0
 return ( ooo000 )
 if 40 - 40: ooOoO0o + iIii1I11I1II1 / OoOoOO00 * iIii1I11I1II1 - ooOoO0o * iIii1I11I1II1
 if 79 - 79: ooOoO0o . oO0o + Ii1I * ooOoO0o + O0 . II111iiii
 if 8 - 8: IiII * OOooOOo + I11i + O0 * oO0o - oO0o
 if 19 - 19: OoO0O00 - ooOoO0o + I1ii11iIi11i / I1ii11iIi11i % I1Ii111 % iIii1I11I1II1
 if 5 - 5: OoooooooOO + ooOoO0o - II111iiii . i11iIiiIii / oO0o - ooOoO0o
 if 3 - 3: iII111i
 if 74 - 74: i11iIiiIii + OoooooooOO . OOooOOo
 if 29 - 29: IiII % OoO0O00
def lisp_verify_auth ( packet , alg_id , auth_data , password ) :
 if ( alg_id == LISP_NONE_ALG_ID ) : return ( True )
 if 53 - 53: OoooooooOO - OoOoOO00 / IiII - I1Ii111
 ooo000 = lisp_hash_me ( packet , alg_id , password , True )
 IiI1 = ( ooo000 == auth_data )
 if 97 - 97: II111iiii . OOooOOo
 if 68 - 68: IiII * IiII + oO0o / o0oOOo0O0Ooo
 if 41 - 41: OoOoOO00 - O0
 if 48 - 48: OoooooooOO % Ii1I * OoO0O00 / I1ii11iIi11i
 if ( IiI1 == False ) :
  lprint ( "Hashed value: {} does not match packet value: {}" . format ( ooo000 , auth_data ) )
  if 53 - 53: ooOoO0o + oO0o - II111iiii
  if 92 - 92: Oo0Ooo - I11i . ooOoO0o % oO0o
 return ( IiI1 )
 if 6 - 6: iIii1I11I1II1 + oO0o
 if 8 - 8: I1ii11iIi11i + o0oOOo0O0Ooo
 if 29 - 29: Ii1I . OOooOOo
 if 59 - 59: O0 . OoO0O00
 if 10 - 10: I1Ii111 / OoooooooOO / OoO0O00 * ooOoO0o
 if 81 - 81: i1IIi % I11i * iIii1I11I1II1
 if 39 - 39: iIii1I11I1II1 / O0 . OoooooooOO - O0 . OoO0O00 . oO0o
def lisp_retransmit_map_notify ( map_notify ) :
 iIi11i1I11Ii = map_notify . etr
 Iiiii = map_notify . etr_port
 if 59 - 59: II111iiii * I1IiiI
 if 12 - 12: i11iIiiIii - IiII . iII111i . Ii1I
 if 34 - 34: i1IIi % iII111i + Oo0Ooo * OoOoOO00 + OoO0O00
 if 37 - 37: I1Ii111 / OoooooooOO
 if 19 - 19: Ii1I - O0 + I1IiiI + OoooooooOO + ooOoO0o - Oo0Ooo
 if ( map_notify . retry_count == LISP_MAX_MAP_NOTIFY_RETRIES ) :
  lprint ( "Map-Notify with nonce 0x{} retry limit reached for ETR {}" . format ( map_notify . nonce_key , red ( iIi11i1I11Ii . print_address ( ) , False ) ) )
  if 45 - 45: I1IiiI . OoOoOO00 . OoOoOO00
  if 20 - 20: OoOoOO00
  Iiii11 = map_notify . nonce_key
  if ( lisp_map_notify_queue . has_key ( Iiii11 ) ) :
   map_notify . retransmit_timer . cancel ( )
   lprint ( "Dequeue Map-Notify from retransmit queue, key is: {}" . format ( Iiii11 ) )
   if 69 - 69: OoOoOO00 * Ii1I % ooOoO0o . OoOoOO00 / oO0o * I1Ii111
   try :
    lisp_map_notify_queue . pop ( Iiii11 )
   except :
    lprint ( "Key not found in Map-Notify queue" )
    if 93 - 93: OoO0O00 % IiII % ooOoO0o . I1IiiI
    if 96 - 96: II111iiii
  return
  if 73 - 73: II111iiii
  if 81 - 81: I1IiiI + OoO0O00
 o000oOOooO00 = map_notify . lisp_sockets
 map_notify . retry_count += 1
 if 22 - 22: OoO0O00 * OoOoOO00 * I11i * IiII . OoO0O00 . I1ii11iIi11i
 lprint ( "Retransmit {} with nonce 0x{} to xTR {}, retry {}" . format ( bold ( "Map-Notify" , False ) , map_notify . nonce_key ,
 # OOooOOo * o0oOOo0O0Ooo
 red ( iIi11i1I11Ii . print_address ( ) , False ) , map_notify . retry_count ) )
 if 48 - 48: i11iIiiIii / ooOoO0o . OoOoOO00 . O0 * i11iIiiIii
 lisp_send_map_notify ( o000oOOooO00 , map_notify . packet , iIi11i1I11Ii , Iiiii )
 if ( map_notify . site ) : map_notify . site . map_notifies_sent += 1
 if 11 - 11: iIii1I11I1II1 . i1IIi . O0 / ooOoO0o
 if 64 - 64: i11iIiiIii + I1IiiI / Oo0Ooo - iII111i
 if 26 - 26: I1ii11iIi11i
 if 67 - 67: I1Ii111 * iIii1I11I1II1 / O0 + OoO0O00 * iIii1I11I1II1 % II111iiii
 map_notify . retransmit_timer = threading . Timer ( LISP_MAP_NOTIFY_INTERVAL ,
 lisp_retransmit_map_notify , [ map_notify ] )
 map_notify . retransmit_timer . start ( )
 return
 if 13 - 13: Ii1I / ooOoO0o / iII111i % II111iiii * I1IiiI * II111iiii
 if 40 - 40: Ii1I / i1IIi . iII111i
 if 65 - 65: iIii1I11I1II1 * O0 . II111iiii * o0oOOo0O0Ooo . I1ii11iIi11i * I1IiiI
 if 63 - 63: II111iiii . Oo0Ooo % iIii1I11I1II1
 if 85 - 85: I1IiiI + i1IIi % I1Ii111
 if 76 - 76: i11iIiiIii % i11iIiiIii
 if 33 - 33: OOooOOo . ooOoO0o / iIii1I11I1II1 * OOooOOo / oO0o
def lisp_send_merged_map_notify ( lisp_sockets , parent , map_register ,
 eid_record ) :
 if 75 - 75: Ii1I - OoOoOO00 . OOooOOo - o0oOOo0O0Ooo - I1ii11iIi11i
 if 69 - 69: O0 % I1ii11iIi11i
 if 77 - 77: iIii1I11I1II1 . OOooOOo
 if 64 - 64: OoOoOO00 - i1IIi * i1IIi / iII111i * OoOoOO00 * OoO0O00
 eid_record . rloc_count = len ( parent . registered_rlocs )
 oOO0OoO0O = eid_record . encode ( )
 eid_record . print_record ( "Merged Map-Notify " , False )
 if 87 - 87: ooOoO0o
 if 80 - 80: I1Ii111 . iIii1I11I1II1
 if 33 - 33: OoO0O00 - I11i - Oo0Ooo
 if 57 - 57: I1Ii111 % i11iIiiIii
 for Iii in parent . registered_rlocs :
  o00o = lisp_rloc_record ( )
  o00o . store_rloc_entry ( Iii )
  oOO0OoO0O += o00o . encode ( )
  o00o . print_record ( "  " )
  del ( o00o )
  if 73 - 73: Oo0Ooo - IiII / oO0o
  if 90 - 90: oO0o + O0
  if 35 - 35: I11i % I1Ii111
  if 64 - 64: I11i + IiII - o0oOOo0O0Ooo - I11i - Oo0Ooo - Ii1I
  if 9 - 9: ooOoO0o
 for Iii in parent . registered_rlocs :
  iIi11i1I11Ii = Iii . rloc
  oO0o0ooo = lisp_map_notify ( lisp_sockets )
  oO0o0ooo . record_count = 1
  OoooOOo0oOO = map_register . key_id
  oO0o0ooo . key_id = OoooOOo0oOO
  oO0o0ooo . alg_id = map_register . alg_id
  oO0o0ooo . auth_len = map_register . auth_len
  oO0o0ooo . nonce = map_register . nonce
  oO0o0ooo . nonce_key = lisp_hex_string ( oO0o0ooo . nonce )
  oO0o0ooo . etr . copy_address ( iIi11i1I11Ii )
  oO0o0ooo . etr_port = map_register . sport
  oO0o0ooo . site = parent . site
  oOo = oO0o0ooo . encode ( oOO0OoO0O , parent . site . auth_key [ OoooOOo0oOO ] )
  oO0o0ooo . print_notify ( )
  if 33 - 33: i11iIiiIii . iII111i % o0oOOo0O0Ooo
  if 35 - 35: OoO0O00 + OOooOOo % II111iiii * Ii1I / OoOoOO00
  if 71 - 71: OOooOOo / i1IIi
  if 50 - 50: iIii1I11I1II1 * IiII
  Iiii11 = oO0o0ooo . nonce_key
  if ( lisp_map_notify_queue . has_key ( Iiii11 ) ) :
   ooO0oI1 = lisp_map_notify_queue [ Iiii11 ]
   ooO0oI1 . retransmit_timer . cancel ( )
   del ( ooO0oI1 )
   if 29 - 29: OOooOOo * iIii1I11I1II1 * ooOoO0o
  lisp_map_notify_queue [ Iiii11 ] = oO0o0ooo
  if 80 - 80: oO0o * I1Ii111
  if 87 - 87: iII111i + OoOoOO00 % ooOoO0o - oO0o
  if 40 - 40: i1IIi / OoOoOO00 - I11i / ooOoO0o . Ii1I
  if 8 - 8: I1IiiI . IiII . OOooOOo . O0
  lprint ( "Send merged Map-Notify to ETR {}" . format ( red ( iIi11i1I11Ii . print_address ( ) , False ) ) )
  if 3 - 3: Ii1I + i11iIiiIii
  lisp_send ( lisp_sockets , iIi11i1I11Ii , LISP_CTRL_PORT , oOo )
  if 87 - 87: ooOoO0o - iII111i % I11i
  parent . site . map_notifies_sent += 1
  if 88 - 88: I11i . OoooooooOO
  if 86 - 86: Ii1I - I1IiiI - iII111i % Ii1I . I1ii11iIi11i % i1IIi
  if 84 - 84: OoOoOO00
  if 99 - 99: OoO0O00 - OoOoOO00 - i1IIi / OoO0O00 * I1ii11iIi11i * iIii1I11I1II1
  oO0o0ooo . retransmit_timer = threading . Timer ( LISP_MAP_NOTIFY_INTERVAL ,
 lisp_retransmit_map_notify , [ oO0o0ooo ] )
  oO0o0ooo . retransmit_timer . start ( )
  if 65 - 65: iII111i - O0 / i1IIi . I1Ii111
 return
 if 85 - 85: o0oOOo0O0Ooo % Ii1I
 if 81 - 81: oO0o / OoO0O00 * i1IIi % iIii1I11I1II1
 if 23 - 23: II111iiii . II111iiii
 if 17 - 17: i11iIiiIii / IiII * I1IiiI . Oo0Ooo / o0oOOo0O0Ooo - iIii1I11I1II1
 if 21 - 21: OOooOOo % Ii1I
 if 3 - 3: OOooOOo / ooOoO0o / I1Ii111 . I11i
 if 54 - 54: I1ii11iIi11i - I1IiiI . OoOoOO00
def lisp_build_map_notify ( lisp_sockets , eid_records , eid_list , record_count ,
 source , port , nonce , key_id , alg_id , auth_len , site , map_register_ack ) :
 if 36 - 36: OoO0O00 * I1IiiI / iII111i
 Iiii11 = lisp_hex_string ( nonce ) + source . print_address ( )
 if 95 - 95: Ii1I . Oo0Ooo
 if 42 - 42: IiII . i1IIi % O0 * ooOoO0o - OOooOOo % ooOoO0o
 if 99 - 99: i1IIi + OoOoOO00 - iII111i % II111iiii
 if 6 - 6: ooOoO0o - I1Ii111 . OoOoOO00
 if 64 - 64: iII111i + I1ii11iIi11i
 if 88 - 88: I1Ii111 / i11iIiiIii - O0 . II111iiii / II111iiii * II111iiii
 lisp_remove_eid_from_map_notify_queue ( eid_list )
 if ( lisp_map_notify_queue . has_key ( Iiii11 ) ) :
  oO0o0ooo = lisp_map_notify_queue [ Iiii11 ]
  o00oOOO = red ( source . print_address_no_iid ( ) , False )
  lprint ( "Map-Notify with nonce 0x{} pending for xTR {}" . format ( lisp_hex_string ( oO0o0ooo . nonce ) , o00oOOO ) )
  if 56 - 56: Oo0Ooo / I1IiiI % I1Ii111 % I1ii11iIi11i * I1IiiI - IiII
  return
  if 39 - 39: oO0o + iII111i . I1Ii111 * i11iIiiIii % o0oOOo0O0Ooo + OOooOOo
  if 61 - 61: ooOoO0o / I1Ii111 / I1ii11iIi11i - Ii1I % o0oOOo0O0Ooo * iII111i
 oO0o0ooo = lisp_map_notify ( lisp_sockets )
 oO0o0ooo . record_count = record_count
 key_id = key_id
 oO0o0ooo . key_id = key_id
 oO0o0ooo . alg_id = alg_id
 oO0o0ooo . auth_len = auth_len
 oO0o0ooo . nonce = nonce
 oO0o0ooo . nonce_key = lisp_hex_string ( nonce )
 oO0o0ooo . etr . copy_address ( source )
 oO0o0ooo . etr_port = port
 oO0o0ooo . site = site
 oO0o0ooo . eid_list = eid_list
 if 94 - 94: I1IiiI / I11i
 if 100 - 100: Ii1I % OoO0O00 % OoooooooOO / II111iiii * I1Ii111
 if 64 - 64: I1Ii111 * OOooOOo * Ii1I + I1ii11iIi11i / iIii1I11I1II1 / Oo0Ooo
 if 50 - 50: OOooOOo % i11iIiiIii
 if ( map_register_ack == False ) :
  Iiii11 = oO0o0ooo . nonce_key
  lisp_map_notify_queue [ Iiii11 ] = oO0o0ooo
  if 99 - 99: IiII
  if 87 - 87: IiII
 if ( map_register_ack ) :
  lprint ( "Send Map-Notify to ack Map-Register" )
 else :
  lprint ( "Send Map-Notify for RLOC-set change" )
  if 35 - 35: oO0o . O0 . Ii1I / ooOoO0o
  if 36 - 36: i11iIiiIii . II111iiii . I11i . II111iiii
  if 36 - 36: Ii1I + ooOoO0o / Oo0Ooo % Oo0Ooo
  if 2 - 2: oO0o - Oo0Ooo * OoO0O00 . ooOoO0o . OOooOOo - oO0o
  if 74 - 74: o0oOOo0O0Ooo
 oOo = oO0o0ooo . encode ( eid_records , site . auth_key [ key_id ] )
 oO0o0ooo . print_notify ( )
 if 18 - 18: Oo0Ooo % OOooOOo / OOooOOo . I1IiiI + i1IIi . I1IiiI
 if ( map_register_ack == False ) :
  IiII1iiI = lisp_eid_record ( )
  IiII1iiI . decode ( eid_records )
  IiII1iiI . print_record ( "  " , False )
  if 3 - 3: O0 * O0 + II111iiii + OoOoOO00 * I11i % Oo0Ooo
  if 19 - 19: oO0o % IiII % OoooooooOO % I1ii11iIi11i / OoO0O00
  if 6 - 6: O0 * I1Ii111 - II111iiii
  if 60 - 60: oO0o % oO0o
  if 76 - 76: I1Ii111 / o0oOOo0O0Ooo
 lisp_send_map_notify ( lisp_sockets , oOo , oO0o0ooo . etr , port )
 site . map_notifies_sent += 1
 if 19 - 19: O0 . i1IIi % iIii1I11I1II1 + OOooOOo * OoOoOO00 / I11i
 if ( map_register_ack ) : return
 if 82 - 82: I1ii11iIi11i
 if 75 - 75: I11i - II111iiii
 if 84 - 84: I1ii11iIi11i * IiII / I1IiiI - Ii1I + IiII - i1IIi
 if 98 - 98: II111iiii - iII111i % i11iIiiIii + ooOoO0o
 if 76 - 76: OOooOOo - iII111i + IiII
 if 48 - 48: I1IiiI - II111iiii
 oO0o0ooo . retransmit_timer = threading . Timer ( LISP_MAP_NOTIFY_INTERVAL ,
 lisp_retransmit_map_notify , [ oO0o0ooo ] )
 oO0o0ooo . retransmit_timer . start ( )
 return
 if 15 - 15: O0
 if 54 - 54: iIii1I11I1II1
 if 54 - 54: iII111i + OOooOOo + OoO0O00
 if 6 - 6: oO0o - OoooooooOO * iIii1I11I1II1 * I1ii11iIi11i
 if 65 - 65: IiII + OoOoOO00
 if 93 - 93: Ii1I
 if 43 - 43: iIii1I11I1II1 / iII111i - Ii1I + I11i % iII111i - OoO0O00
 if 5 - 5: OoO0O00 / ooOoO0o
def lisp_send_map_notify_ack ( lisp_sockets , eid_records , map_notify , ms ) :
 map_notify . map_notify_ack = True
 if 92 - 92: Oo0Ooo / iII111i + O0 * ooOoO0o * OOooOOo % Oo0Ooo
 if 97 - 97: oO0o / Ii1I
 if 70 - 70: iII111i / Oo0Ooo . OoOoOO00 - II111iiii * II111iiii % I1IiiI
 if 34 - 34: I1Ii111 + OOooOOo * iII111i / ooOoO0o % i11iIiiIii
 oOo = map_notify . encode ( eid_records , ms . password )
 map_notify . print_notify ( )
 if 91 - 91: IiII * Ii1I * OOooOOo
 if 17 - 17: o0oOOo0O0Ooo + Ii1I % I1ii11iIi11i + IiII % I1Ii111 + I1ii11iIi11i
 if 100 - 100: I11i * OoO0O00 - i1IIi + iII111i * Ii1I - OoooooooOO
 if 47 - 47: o0oOOo0O0Ooo / Ii1I - iII111i * OOooOOo / i11iIiiIii
 iIi11i1I11Ii = ms . map_server
 lprint ( "Send Map-Notify-Ack to {}" . format (
 red ( iIi11i1I11Ii . print_address ( ) , False ) ) )
 lisp_send ( lisp_sockets , iIi11i1I11Ii , LISP_CTRL_PORT , oOo )
 return
 if 97 - 97: iIii1I11I1II1 + OoOoOO00 + OoOoOO00 * o0oOOo0O0Ooo
 if 14 - 14: II111iiii + I1ii11iIi11i * Oo0Ooo
 if 95 - 95: IiII + iII111i % I1IiiI
 if 18 - 18: Oo0Ooo
 if 8 - 8: O0 + iIii1I11I1II1 - O0
 if 67 - 67: O0
 if 22 - 22: I11i / i1IIi . II111iiii % ooOoO0o / I11i - Ii1I
 if 28 - 28: O0 - Oo0Ooo
def lisp_send_multicast_map_notify ( lisp_sockets , site_eid , eid_list , xtr ) :
 if 58 - 58: iIii1I11I1II1 - OoooooooOO - iII111i
 oO0o0ooo = lisp_map_notify ( lisp_sockets )
 oO0o0ooo . record_count = 1
 oO0o0ooo . nonce = lisp_get_control_nonce ( )
 oO0o0ooo . nonce_key = lisp_hex_string ( oO0o0ooo . nonce )
 oO0o0ooo . etr . copy_address ( xtr )
 oO0o0ooo . etr_port = LISP_CTRL_PORT
 oO0o0ooo . eid_list = eid_list
 Iiii11 = oO0o0ooo . nonce_key
 if 43 - 43: ooOoO0o / o0oOOo0O0Ooo
 if 56 - 56: II111iiii * I1ii11iIi11i * O0 . iII111i . I1ii11iIi11i % I1Ii111
 if 99 - 99: Oo0Ooo - OoO0O00 + OoooooooOO - I1Ii111 - I1ii11iIi11i % i1IIi
 if 49 - 49: IiII % OoooooooOO / Oo0Ooo - OoOoOO00 + o0oOOo0O0Ooo / Ii1I
 if 6 - 6: I11i % IiII
 if 48 - 48: Ii1I
 lisp_remove_eid_from_map_notify_queue ( oO0o0ooo . eid_list )
 if ( lisp_map_notify_queue . has_key ( Iiii11 ) ) :
  oO0o0ooo = lisp_map_notify_queue [ Iiii11 ]
  lprint ( "Map-Notify with nonce 0x{} pending for ITR {}" . format ( oO0o0ooo . nonce , red ( xtr . print_address_no_iid ( ) , False ) ) )
  if 100 - 100: OoO0O00 % I1Ii111 + OoooooooOO / OoO0O00
  return
  if 62 - 62: IiII
  if 66 - 66: o0oOOo0O0Ooo % OOooOOo
  if 15 - 15: Ii1I % IiII + IiII % iII111i - O0 * OoooooooOO
  if 53 - 53: OoOoOO00 . Ii1I / Oo0Ooo
  if 62 - 62: i11iIiiIii
 lisp_map_notify_queue [ Iiii11 ] = oO0o0ooo
 if 38 - 38: I1ii11iIi11i % ooOoO0o * OoooooooOO + iIii1I11I1II1 % i1IIi / OOooOOo
 if 6 - 6: i11iIiiIii
 if 8 - 8: iIii1I11I1II1 + I1ii11iIi11i . i1IIi % OoOoOO00 % OoooooooOO * Oo0Ooo
 if 53 - 53: oO0o
 iIIiiiiI11i = site_eid . rtrs_in_rloc_set ( )
 if ( iIIiiiiI11i ) :
  if ( site_eid . is_rtr_in_rloc_set ( xtr ) ) : iIIiiiiI11i = False
  if 22 - 22: i11iIiiIii
  if 70 - 70: OOooOOo
  if 47 - 47: ooOoO0o . ooOoO0o + ooOoO0o % i11iIiiIii
  if 95 - 95: ooOoO0o % i1IIi * iII111i / oO0o + i11iIiiIii
  if 85 - 85: IiII . OoooooooOO / iII111i . oO0o * IiII . I1Ii111
 IiII1iiI = lisp_eid_record ( )
 IiII1iiI . record_ttl = 1440
 IiII1iiI . eid . copy_address ( site_eid . eid )
 IiII1iiI . group . copy_address ( site_eid . group )
 IiII1iiI . rloc_count = 0
 for O0OO0O in site_eid . registered_rlocs :
  if ( iIIiiiiI11i ^ O0OO0O . is_rtr ( ) ) : continue
  IiII1iiI . rloc_count += 1
  if 68 - 68: OoO0O00 * i1IIi
 oOo = IiII1iiI . encode ( )
 if 39 - 39: OoO0O00 % OoO0O00
 if 18 - 18: ooOoO0o * I1IiiI / iII111i % iII111i
 if 9 - 9: i11iIiiIii % ooOoO0o % O0 + i1IIi / O0
 if 12 - 12: I1Ii111 - iII111i * iII111i + OoO0O00 . Ii1I % I11i
 oO0o0ooo . print_notify ( )
 IiII1iiI . print_record ( "  " , False )
 if 28 - 28: ooOoO0o % OoO0O00 - II111iiii * IiII - I1IiiI + I1IiiI
 if 84 - 84: IiII / Ii1I
 if 39 - 39: OOooOOo - iIii1I11I1II1 + OoOoOO00 % IiII * OoooooooOO % Ii1I
 if 11 - 11: I1ii11iIi11i
 for O0OO0O in site_eid . registered_rlocs :
  if ( iIIiiiiI11i ^ O0OO0O . is_rtr ( ) ) : continue
  o00o = lisp_rloc_record ( )
  o00o . store_rloc_entry ( O0OO0O )
  oOo += o00o . encode ( )
  o00o . print_record ( "    " )
  if 83 - 83: O0
  if 97 - 97: O0
  if 50 - 50: I1Ii111 / OoooooooOO . o0oOOo0O0Ooo + I1IiiI * i11iIiiIii
  if 28 - 28: I1Ii111 * II111iiii
  if 14 - 14: iIii1I11I1II1 / Ii1I + o0oOOo0O0Ooo . iII111i % iII111i . i1IIi
 oOo = oO0o0ooo . encode ( oOo , "" )
 if ( oOo == None ) : return
 if 67 - 67: IiII * II111iiii + ooOoO0o - i11iIiiIii
 if 15 - 15: I11i
 if 67 - 67: iIii1I11I1II1
 if 91 - 91: ooOoO0o
 lisp_send_map_notify ( lisp_sockets , oOo , xtr , LISP_CTRL_PORT )
 if 66 - 66: OOooOOo
 if 5 - 5: i1IIi * OoOoOO00 + i1IIi % I11i
 if 79 - 79: OOooOOo % iIii1I11I1II1 / OoOoOO00
 if 9 - 9: Ii1I
 oO0o0ooo . retransmit_timer = threading . Timer ( LISP_MAP_NOTIFY_INTERVAL ,
 lisp_retransmit_map_notify , [ oO0o0ooo ] )
 oO0o0ooo . retransmit_timer . start ( )
 return
 if 44 - 44: iII111i
 if 46 - 46: I11i . i11iIiiIii * OoOoOO00 + o0oOOo0O0Ooo / ooOoO0o
 if 37 - 37: OoO0O00 - Ii1I + OoO0O00
 if 49 - 49: OoooooooOO - I1ii11iIi11i % I1ii11iIi11i / i1IIi . ooOoO0o
 if 60 - 60: Oo0Ooo
 if 46 - 46: OoOoOO00 + i1IIi
 if 43 - 43: II111iiii * IiII % iIii1I11I1II1 % i11iIiiIii % I1ii11iIi11i
def lisp_queue_multicast_map_notify ( lisp_sockets , rle_list ) :
 OO0O00Oo0o = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
 if 76 - 76: i1IIi . i11iIiiIii . i11iIiiIii - iII111i + i11iIiiIii
 for iIi1I in rle_list :
  i11Iii11I = lisp_site_eid_lookup ( iIi1I [ 0 ] , iIi1I [ 1 ] , True )
  if ( i11Iii11I == None ) : continue
  if 89 - 89: Oo0Ooo / Ii1I * OoO0O00 + ooOoO0o
  if 41 - 41: IiII + I11i * ooOoO0o + Oo0Ooo . ooOoO0o
  if 38 - 38: iII111i * OoooooooOO - IiII
  if 36 - 36: I1Ii111 * II111iiii + I1ii11iIi11i - iII111i * iII111i
  if 91 - 91: O0 + I1Ii111 * II111iiii - O0 . i11iIiiIii . Oo0Ooo
  if 54 - 54: ooOoO0o * I11i / I1ii11iIi11i % ooOoO0o
  if 76 - 76: I11i . I1IiiI
  oO0O0OO0oO = i11Iii11I . registered_rlocs
  if ( len ( oO0O0OO0oO ) == 0 ) :
   oOo0oOo = { }
   for iIi1II1 in i11Iii11I . individual_registrations . values ( ) :
    for O0OO0O in iIi1II1 . registered_rlocs :
     if ( O0OO0O . is_rtr ( ) == False ) : continue
     oOo0oOo [ O0OO0O . rloc . print_address ( ) ] = O0OO0O
     if 1 - 1: I1Ii111 . IiII % oO0o . I1IiiI * II111iiii + i1IIi
     if 55 - 55: OoooooooOO - Oo0Ooo / o0oOOo0O0Ooo - OoO0O00 % I1IiiI
   oO0O0OO0oO = oOo0oOo . values ( )
   if 23 - 23: OOooOOo
   if 97 - 97: Oo0Ooo / OoooooooOO . OoooooooOO
   if 47 - 47: OoO0O00
   if 52 - 52: I1IiiI * iIii1I11I1II1 % oO0o * IiII % oO0o
   if 9 - 9: I11i
   if 83 - 83: i11iIiiIii
  OOoo0oO = [ ]
  O0O0 = False
  if ( i11Iii11I . eid . address == 0 and i11Iii11I . eid . mask_len == 0 ) :
   I1III1iI = [ ]
   iIIiIIiii1iI = [ ] if len ( oO0O0OO0oO ) == 0 else oO0O0OO0oO [ 0 ] . rle . rle_nodes
   if 61 - 61: oO0o . o0oOOo0O0Ooo
   for I1I1iiI in iIIiIIiii1iI :
    OOoo0oO . append ( I1I1iiI . address )
    I1III1iI . append ( I1I1iiI . address . print_address_no_iid ( ) )
    if 82 - 82: Oo0Ooo * OoooooooOO / ooOoO0o / I1IiiI
   lprint ( "Notify existing RLE-nodes {}" . format ( I1III1iI ) )
  else :
   if 70 - 70: I1IiiI
   if 74 - 74: ooOoO0o * II111iiii
   if 96 - 96: i11iIiiIii . I1IiiI - II111iiii . I11i
   if 79 - 79: OoO0O00 . OoOoOO00 - i1IIi + Ii1I * i11iIiiIii . OoooooooOO
   if 83 - 83: o0oOOo0O0Ooo / oO0o
   for O0OO0O in oO0O0OO0oO :
    if ( O0OO0O . is_rtr ( ) ) : OOoo0oO . append ( O0OO0O . rloc )
    if 24 - 24: Ii1I + oO0o / OoooooooOO % i11iIiiIii
    if 1 - 1: iII111i / I1Ii111 * I1IiiI + OoOoOO00 . OoooooooOO
    if 5 - 5: I1IiiI
    if 74 - 74: i1IIi * Oo0Ooo - OoOoOO00 * o0oOOo0O0Ooo
    if 85 - 85: iIii1I11I1II1 * IiII / i11iIiiIii - ooOoO0o - o0oOOo0O0Ooo
   O0O0 = ( len ( OOoo0oO ) != 0 )
   if ( O0O0 == False ) :
    ooO00oO0O = lisp_site_eid_lookup ( iIi1I [ 0 ] , OO0O00Oo0o , False )
    if ( ooO00oO0O == None ) : continue
    if 30 - 30: OoOoOO00 - OOooOOo . Oo0Ooo
    for O0OO0O in ooO00oO0O . registered_rlocs :
     if ( O0OO0O . rloc . is_null ( ) ) : continue
     OOoo0oO . append ( O0OO0O . rloc )
     if 11 - 11: IiII - I1Ii111 - OoO0O00 * o0oOOo0O0Ooo
     if 99 - 99: O0 - OoO0O00
     if 95 - 95: Ii1I . IiII * o0oOOo0O0Ooo
     if 91 - 91: I1Ii111
     if 49 - 49: I11i
     if 17 - 17: Oo0Ooo % o0oOOo0O0Ooo
   if ( len ( OOoo0oO ) == 0 ) :
    lprint ( "No ITRs or RTRs found for {}, Map-Notify suppressed" . format ( green ( i11Iii11I . print_eid_tuple ( ) , False ) ) )
    if 3 - 3: OoO0O00 . oO0o . oO0o . Ii1I
    continue
    if 100 - 100: i11iIiiIii / i1IIi . I1ii11iIi11i
    if 1 - 1: IiII * I1Ii111 / I1ii11iIi11i * i11iIiiIii
    if 82 - 82: o0oOOo0O0Ooo * OoO0O00 / o0oOOo0O0Ooo % OoOoOO00 * iIii1I11I1II1 % O0
    if 10 - 10: ooOoO0o
    if 69 - 69: I11i + I1IiiI / oO0o
    if 89 - 89: i1IIi % OoOoOO00 . I1ii11iIi11i
  for Iii in OOoo0oO :
   lprint ( "Build Map-Notify to {}TR {} for {}" . format ( "R" if O0O0 else "x" , red ( Iii . print_address_no_iid ( ) , False ) ,
   # o0oOOo0O0Ooo / oO0o * I1Ii111 + iIii1I11I1II1 / IiII + o0oOOo0O0Ooo
 green ( i11Iii11I . print_eid_tuple ( ) , False ) ) )
   if 50 - 50: I1IiiI * ooOoO0o
   IIIo000 = [ i11Iii11I . print_eid_tuple ( ) ]
   lisp_send_multicast_map_notify ( lisp_sockets , i11Iii11I , IIIo000 , Iii )
   time . sleep ( .001 )
   if 39 - 39: OoOoOO00
   if 61 - 61: OoooooooOO / ooOoO0o . i1IIi . Oo0Ooo % OoOoOO00 * OoO0O00
 return
 if 4 - 4: I1Ii111 . o0oOOo0O0Ooo
 if 72 - 72: Ii1I * OoO0O00 / OoO0O00
 if 39 - 39: oO0o
 if 49 - 49: I1IiiI * I1Ii111 . I1IiiI - II111iiii
 if 57 - 57: oO0o + O0 - OoOoOO00
 if 14 - 14: II111iiii + i11iIiiIii + Ii1I / o0oOOo0O0Ooo . OoO0O00
 if 93 - 93: o0oOOo0O0Ooo + i1IIi
 if 24 - 24: i1IIi
def lisp_find_sig_in_rloc_set ( packet , rloc_count ) :
 for II11iIII1i1I in range ( rloc_count ) :
  o00o = lisp_rloc_record ( )
  packet = o00o . decode ( packet , None )
  OoO0OOOO = o00o . json
  if ( OoO0OOOO == None ) : continue
  if 90 - 90: Oo0Ooo . II111iiii + I1ii11iIi11i - OoOoOO00 / I11i * iII111i
  try :
   OoO0OOOO = json . loads ( OoO0OOOO . json_string )
  except :
   lprint ( "Found corrupted JSON signature" )
   continue
   if 58 - 58: oO0o + Oo0Ooo . O0
   if 8 - 8: II111iiii + iII111i + OoO0O00 - Ii1I / I1ii11iIi11i
  if ( OoO0OOOO . has_key ( "signature" ) == False ) : continue
  return ( o00o )
  if 86 - 86: I1ii11iIi11i
 return ( None )
 if 43 - 43: IiII - I1Ii111 / I1Ii111
 if 25 - 25: OoOoOO00
 if 52 - 52: OOooOOo + IiII
 if 73 - 73: OoooooooOO - I1Ii111 % iII111i / OOooOOo . o0oOOo0O0Ooo - IiII
 if 69 - 69: Ii1I . iIii1I11I1II1 / Oo0Ooo * Oo0Ooo % IiII
 if 5 - 5: OOooOOo - I1Ii111 + IiII
 if 82 - 82: OOooOOo
 if 26 - 26: ooOoO0o + OoooooooOO + ooOoO0o * I1Ii111
 if 26 - 26: I1IiiI - OOooOOo
 if 34 - 34: I1Ii111 % I1IiiI . OoOoOO00 / iII111i + ooOoO0o . i11iIiiIii
 if 51 - 51: OoooooooOO * I1Ii111 * I11i - I1ii11iIi11i + I1Ii111
 if 50 - 50: OoooooooOO * II111iiii
 if 7 - 7: ooOoO0o / I11i * iII111i
 if 17 - 17: O0 % I1Ii111
 if 28 - 28: i1IIi * ooOoO0o
 if 14 - 14: II111iiii + II111iiii - I11i / I11i . OoOoOO00 + OoO0O00
 if 92 - 92: II111iiii - II111iiii % IiII
 if 48 - 48: oO0o / II111iiii + oO0o
 if 16 - 16: o0oOOo0O0Ooo % II111iiii - i11iIiiIii - IiII + O0 - i11iIiiIii
def lisp_get_eid_hash ( eid ) :
 OoOOo = None
 for iII in lisp_eid_hashes :
  if 51 - 51: Ii1I + IiII * o0oOOo0O0Ooo / I1IiiI . I1ii11iIi11i + I1ii11iIi11i
  if 37 - 37: II111iiii - ooOoO0o / Oo0Ooo * iIii1I11I1II1 . II111iiii % I1Ii111
  if 28 - 28: i11iIiiIii + OoO0O00 % O0 - I1ii11iIi11i % oO0o
  if 30 - 30: I11i + OOooOOo
  II1 = iII . instance_id
  if ( II1 == - 1 ) : iII . instance_id = eid . instance_id
  if 27 - 27: OoOoOO00 . ooOoO0o
  ooooOOoO = eid . is_more_specific ( iII )
  iII . instance_id = II1
  if ( ooooOOoO ) :
   OoOOo = 128 - iII . mask_len
   break
   if 8 - 8: ooOoO0o % o0oOOo0O0Ooo
   if 22 - 22: O0 * IiII . OoO0O00
 if ( OoOOo == None ) : return ( None )
 if 63 - 63: oO0o % Oo0Ooo * OoO0O00 / II111iiii / Ii1I - ooOoO0o
 Iiii1Ii1I = eid . address
 i1I = ""
 for II11iIII1i1I in range ( 0 , OoOOo / 16 ) :
  iIiIi1iI11iiI = Iiii1Ii1I & 0xffff
  iIiIi1iI11iiI = hex ( iIiIi1iI11iiI ) [ 2 : - 1 ]
  i1I = iIiIi1iI11iiI . zfill ( 4 ) + ":" + i1I
  Iiii1Ii1I >>= 16
  if 53 - 53: OoOoOO00 + oO0o
 if ( OoOOo % 16 != 0 ) :
  iIiIi1iI11iiI = Iiii1Ii1I & 0xff
  iIiIi1iI11iiI = hex ( iIiIi1iI11iiI ) [ 2 : - 1 ]
  i1I = iIiIi1iI11iiI . zfill ( 2 ) + ":" + i1I
  if 80 - 80: oO0o / OoOoOO00 - I11i / oO0o - iII111i - OoooooooOO
 return ( i1I [ 0 : - 1 ] )
 if 57 - 57: o0oOOo0O0Ooo
 if 37 - 37: iII111i * o0oOOo0O0Ooo
 if 23 - 23: ooOoO0o + OoooooooOO * iII111i . I11i
 if 2 - 2: iIii1I11I1II1 * I1ii11iIi11i - OoooooooOO
 if 93 - 93: iII111i % ooOoO0o * Oo0Ooo
 if 34 - 34: O0 * oO0o
 if 58 - 58: OOooOOo . iII111i - Oo0Ooo / iII111i . I11i
 if 86 - 86: iIii1I11I1II1 - iII111i % Ii1I
 if 18 - 18: oO0o / IiII - OOooOOo % Ii1I
 if 88 - 88: i11iIiiIii
 if 13 - 13: I1IiiI
def lisp_lookup_public_key ( eid ) :
 II1 = eid . instance_id
 if 52 - 52: Ii1I * oO0o / I1Ii111 . IiII
 if 84 - 84: OoooooooOO - oO0o - I1Ii111
 if 69 - 69: OoOoOO00 * Ii1I % OoooooooOO % OOooOOo * OoOoOO00
 if 20 - 20: IiII
 if 17 - 17: o0oOOo0O0Ooo % iIii1I11I1II1
 ooo0oOo = lisp_get_eid_hash ( eid )
 if ( ooo0oOo == None ) : return ( [ None , None , False ] )
 if 79 - 79: I11i
 ooo0oOo = "hash-" + ooo0oOo
 IIIIIiI = lisp_address ( LISP_AFI_NAME , ooo0oOo , len ( ooo0oOo ) , II1 )
 i1i11Ii1 = lisp_address ( LISP_AFI_NONE , "" , 0 , II1 )
 if 38 - 38: I1ii11iIi11i * ooOoO0o
 if 77 - 77: OOooOOo - i11iIiiIii - I1ii11iIi11i
 if 94 - 94: OoO0O00 % iII111i - I1Ii111 + OoO0O00 - I1IiiI
 if 65 - 65: OOooOOo
 ooO00oO0O = lisp_site_eid_lookup ( IIIIIiI , i1i11Ii1 , True )
 if ( ooO00oO0O == None ) : return ( [ IIIIIiI , None , False ] )
 if 90 - 90: O0
 if 91 - 91: O0 * OoOoOO00 - OoOoOO00 * II111iiii - iII111i
 if 38 - 38: oO0o * I11i % OOooOOo
 if 80 - 80: O0 % II111iiii / O0 . Oo0Ooo * OoOoOO00 + OOooOOo
 oooo0 = None
 for Oo0o0o0oo in ooO00oO0O . registered_rlocs :
  i11IIiiII = Oo0o0o0oo . json
  if ( i11IIiiII == None ) : continue
  try :
   i11IIiiII = json . loads ( i11IIiiII . json_string )
  except :
   lprint ( "Registered RLOC JSON format is invalid for {}" . format ( ooo0oOo ) )
   if 31 - 31: OoO0O00 + i11iIiiIii / I11i % O0 / Ii1I
   return ( [ IIIIIiI , None , False ] )
   if 90 - 90: iIii1I11I1II1 % oO0o % IiII
  if ( i11IIiiII . has_key ( "public-key" ) == False ) : continue
  oooo0 = i11IIiiII [ "public-key" ]
  break
  if 84 - 84: I1IiiI * IiII * iII111i / i1IIi . II111iiii * o0oOOo0O0Ooo
 return ( [ IIIIIiI , oooo0 , True ] )
 if 1 - 1: oO0o - iIii1I11I1II1 % i1IIi
 if 94 - 94: Oo0Ooo + iIii1I11I1II1 . OoO0O00 * oO0o . i1IIi
 if 85 - 85: O0 / OoOoOO00 . iII111i
 if 64 - 64: OoO0O00 + I1ii11iIi11i / OoO0O00 * I1Ii111 . Oo0Ooo
 if 5 - 5: iII111i - iIii1I11I1II1 * IiII
 if 52 - 52: OOooOOo
 if 50 - 50: OoOoOO00 % o0oOOo0O0Ooo - II111iiii - i1IIi
 if 35 - 35: Oo0Ooo - ooOoO0o % OoO0O00
def lisp_verify_cga_sig ( eid , rloc_record ) :
 if 26 - 26: i1IIi * I1Ii111 * OoO0O00 - IiII
 if 26 - 26: Oo0Ooo - ooOoO0o . iII111i * OoOoOO00 / OoooooooOO
 if 66 - 66: I1IiiI
 if 45 - 45: II111iiii * I1Ii111 - II111iiii / I1IiiI % oO0o
 if 83 - 83: oO0o % OoO0O00 + I1ii11iIi11i / OoooooooOO % iII111i
 o0o000OOO = json . loads ( rloc_record . json . json_string )
 if 22 - 22: I1Ii111
 if ( lisp_get_eid_hash ( eid ) ) :
  oo0o0Oo = eid
 elif ( o0o000OOO . has_key ( "signature-eid" ) ) :
  iii11ii11IIii = o0o000OOO [ "signature-eid" ]
  oo0o0Oo = lisp_address ( LISP_AFI_IPV6 , iii11ii11IIii , 0 , 0 )
 else :
  lprint ( "  No signature-eid found in RLOC-record" )
  return ( False )
  if 45 - 45: OoO0O00
  if 31 - 31: I1IiiI . O0 % Ii1I . oO0o
  if 91 - 91: O0 - oO0o * O0
  if 98 - 98: Ii1I
  if 54 - 54: oO0o
 IIIIIiI , oooo0 , oO0O00oo0O = lisp_lookup_public_key ( oo0o0Oo )
 if ( IIIIIiI == None ) :
  oO00oo000O = green ( oo0o0Oo . print_address ( ) , False )
  lprint ( "  Could not parse hash in EID {}" . format ( oO00oo000O ) )
  return ( False )
  if 73 - 73: OoOoOO00
  if 47 - 47: oO0o
 iIIi11Ii1iII = "found" if oO0O00oo0O else bold ( "not found" , False )
 oO00oo000O = green ( IIIIIiI . print_address ( ) , False )
 lprint ( "  Lookup for crypto-hashed EID {} {}" . format ( oO00oo000O , iIIi11Ii1iII ) )
 if ( oO0O00oo0O == False ) : return ( False )
 if 72 - 72: I11i % ooOoO0o / O0 . O0
 if ( oooo0 == None ) :
  lprint ( "  RLOC-record with public-key not found" )
  return ( False )
  if 7 - 7: O0 * I1ii11iIi11i + Ii1I + oO0o % oO0o
  if 47 - 47: oO0o * I1ii11iIi11i
 OoOOoo00ooOoo = oooo0 [ 0 : 8 ] + "..." + oooo0 [ - 8 : : ]
 lprint ( "  RLOC-record with public-key '{}' found" . format ( OoOOoo00ooOoo ) )
 if 92 - 92: O0 % I1IiiI / OOooOOo
 if 43 - 43: I11i - I11i
 if 27 - 27: Ii1I / o0oOOo0O0Ooo . iIii1I11I1II1 . I1IiiI - OoO0O00
 if 28 - 28: ooOoO0o
 if 88 - 88: oO0o
 o0o0Oo = o0o000OOO [ "signature" ]
 if 76 - 76: OoOoOO00 / iII111i * ooOoO0o . i1IIi
 try :
  o0o000OOO = binascii . a2b_base64 ( o0o0Oo )
 except :
  lprint ( "  Incorrect padding in signature string" )
  return ( False )
  if 28 - 28: I11i . I1ii11iIi11i
  if 80 - 80: OoO0O00 - OoooooooOO * i11iIiiIii
 iII1i11i1i1II = len ( o0o000OOO )
 if ( iII1i11i1i1II & 1 ) :
  lprint ( "  Signature length is odd, length {}" . format ( iII1i11i1i1II ) )
  return ( False )
  if 19 - 19: I11i - IiII - i11iIiiIii % Ii1I + oO0o
  if 37 - 37: i1IIi + O0 . iIii1I11I1II1 + OOooOOo
  if 42 - 42: OOooOOo * ooOoO0o * i11iIiiIii + OoooooooOO . iIii1I11I1II1
  if 95 - 95: i1IIi * O0 / II111iiii * OoOoOO00 * I1IiiI
  if 38 - 38: OOooOOo - OoOoOO00 / OoO0O00 / o0oOOo0O0Ooo - i11iIiiIii
 oOooOOoO = oo0o0Oo . print_address ( )
 if 4 - 4: I1IiiI * o0oOOo0O0Ooo - I11i - OoooooooOO . OoooooooOO
 if 79 - 79: oO0o - iII111i
 if 34 - 34: OoooooooOO + Ii1I - iII111i + OoooooooOO / I1IiiI
 if 39 - 39: o0oOOo0O0Ooo . i1IIi * OoO0O00 / II111iiii / I1ii11iIi11i * OOooOOo
 oooo0 = binascii . a2b_base64 ( oooo0 )
 try :
  Iiii11 = ecdsa . VerifyingKey . from_pem ( oooo0 )
 except :
  iiO0 = bold ( "Bad public-key" , False )
  lprint ( "  {}, not in PEM format" . format ( iiO0 ) )
  return ( False )
  if 58 - 58: I1ii11iIi11i / i11iIiiIii + iII111i + I11i / oO0o
  if 8 - 8: I1ii11iIi11i
  if 100 - 100: OoooooooOO / I11i - Ii1I
  if 11 - 11: OoO0O00
  if 20 - 20: Oo0Ooo
  if 34 - 34: I1Ii111 % i11iIiiIii / oO0o - i1IIi . o0oOOo0O0Ooo / oO0o
  if 68 - 68: I1Ii111 % Ii1I * Oo0Ooo - O0 . IiII
  if 1 - 1: I1ii11iIi11i
  if 18 - 18: i11iIiiIii % OoO0O00 % OOooOOo . OOooOOo * Ii1I / II111iiii
  if 81 - 81: iII111i % IiII / I11i
  if 50 - 50: IiII + i1IIi % I1Ii111
 try :
  O0OoOOo0o = Iiii11 . verify ( o0o000OOO , oOooOOoO , hashfunc = hashlib . sha256 )
 except :
  lprint ( "  Signature library failed for signature data '{}'" . format ( oOooOOoO ) )
  if 72 - 72: I1Ii111
  lprint ( "  Signature used '{}'" . format ( o0o0Oo ) )
  return ( False )
  if 6 - 6: II111iiii - i1IIi
 return ( O0OoOOo0o )
 if 78 - 78: OoOoOO00 - Oo0Ooo * II111iiii % iIii1I11I1II1 . i11iIiiIii % iII111i
 if 85 - 85: I1ii11iIi11i + OOooOOo % i1IIi
 if 13 - 13: OOooOOo + i11iIiiIii / OOooOOo . O0 . OoO0O00 - Ii1I
 if 31 - 31: OoOoOO00 * o0oOOo0O0Ooo / O0 . iII111i / i11iIiiIii
 if 22 - 22: I1IiiI . OoooooooOO * I1ii11iIi11i + i11iIiiIii - O0 + i11iIiiIii
 if 98 - 98: OOooOOo + I1IiiI / IiII / OoooooooOO / OOooOOo
 if 8 - 8: OoooooooOO * OOooOOo * iII111i - iII111i
 if 32 - 32: I1Ii111
 if 28 - 28: I11i . i11iIiiIii % iIii1I11I1II1 + OoOoOO00
 if 4 - 4: OOooOOo + I1ii11iIi11i - iII111i + OOooOOo / IiII
def lisp_remove_eid_from_map_notify_queue ( eid_list ) :
 if 23 - 23: iIii1I11I1II1 + OoooooooOO + ooOoO0o . iII111i . Oo0Ooo - iIii1I11I1II1
 if 25 - 25: O0 + I1IiiI % OOooOOo / Oo0Ooo . IiII / I1Ii111
 if 84 - 84: ooOoO0o . O0 + I1IiiI * OoO0O00 - I1IiiI
 if 24 - 24: Ii1I
 if 23 - 23: Oo0Ooo * i1IIi / I1IiiI . I11i - I1ii11iIi11i . iIii1I11I1II1
 iiiIIi = [ ]
 for IiiI11I111I in eid_list :
  for OOOo in lisp_map_notify_queue :
   oO0o0ooo = lisp_map_notify_queue [ OOOo ]
   if ( IiiI11I111I not in oO0o0ooo . eid_list ) : continue
   if 1 - 1: oO0o + oO0o - OoO0O00
   iiiIIi . append ( OOOo )
   I1i1i1Ii1II1 = oO0o0ooo . retransmit_timer
   if ( I1i1i1Ii1II1 ) : I1i1i1Ii1II1 . cancel ( )
   if 29 - 29: Oo0Ooo
   lprint ( "Remove from Map-Notify queue nonce 0x{} for EID {}" . format ( oO0o0ooo . nonce_key , green ( IiiI11I111I , False ) ) )
   if 16 - 16: oO0o
   if 52 - 52: I11i * I1IiiI % I11i - iII111i - Ii1I - OoooooooOO
   if 15 - 15: iII111i
   if 95 - 95: i11iIiiIii . Ii1I / II111iiii + II111iiii + Ii1I / I11i
   if 72 - 72: I1Ii111 . I1Ii111 * O0 + I1ii11iIi11i / Oo0Ooo
   if 96 - 96: oO0o . ooOoO0o * Oo0Ooo % ooOoO0o + I1Ii111 + iIii1I11I1II1
   if 45 - 45: II111iiii
 for OOOo in iiiIIi : lisp_map_notify_queue . pop ( OOOo )
 return
 if 42 - 42: ooOoO0o
 if 62 - 62: II111iiii * o0oOOo0O0Ooo . OoO0O00 / II111iiii
 if 5 - 5: OoO0O00 + O0 . OoooooooOO + I1IiiI + i1IIi * OOooOOo
 if 19 - 19: OoooooooOO + i11iIiiIii / II111iiii - Oo0Ooo . OOooOOo
 if 10 - 10: oO0o * Oo0Ooo
 if 55 - 55: OoO0O00 - i1IIi - I11i * oO0o
 if 91 - 91: I1Ii111
 if 77 - 77: I1ii11iIi11i . ooOoO0o - iIii1I11I1II1 + Ii1I % II111iiii * II111iiii
def lisp_decrypt_map_register ( packet ) :
 if 41 - 41: II111iiii + Oo0Ooo - IiII / I1Ii111 - OOooOOo . oO0o
 if 100 - 100: ooOoO0o / I1ii11iIi11i * OoOoOO00 . I1ii11iIi11i . o0oOOo0O0Ooo * iIii1I11I1II1
 if 15 - 15: iII111i + o0oOOo0O0Ooo / IiII
 if 33 - 33: OoooooooOO . IiII * o0oOOo0O0Ooo
 if 41 - 41: Ii1I . iII111i . o0oOOo0O0Ooo % OoooooooOO % IiII
 oooooOOo0Oo = socket . ntohl ( struct . unpack ( "I" , packet [ 0 : 4 ] ) [ 0 ] )
 O0OoOoo0ooOO = ( oooooOOo0Oo >> 13 ) & 0x1
 if ( O0OoOoo0ooOO == 0 ) : return ( packet )
 if 2 - 2: OoOoOO00 - iIii1I11I1II1 + O0 % iIii1I11I1II1 * i11iIiiIii
 iIIoo0o0O0ooO0O = ( oooooOOo0Oo >> 14 ) & 0x7
 if 56 - 56: OOooOOo . oO0o
 if 75 - 75: oO0o + OoOoOO00 - OoooooooOO
 if 38 - 38: I11i / ooOoO0o / OoOoOO00 * OOooOOo . oO0o
 if 8 - 8: OoO0O00 . OOooOOo % I1Ii111 * OOooOOo / I1IiiI
 try :
  i1iIII1i = lisp_ms_encryption_keys [ iIIoo0o0O0ooO0O ]
  i1iIII1i = i1iIII1i . zfill ( 32 )
  Ii1IiiiI1ii = "0" * 8
 except :
  lprint ( "Cannot decrypt Map-Register with key-id {}" . format ( iIIoo0o0O0ooO0O ) )
  return ( None )
  if 64 - 64: iII111i * I1ii11iIi11i - OoOoOO00
  if 1 - 1: i1IIi / OoO0O00 % i1IIi % i11iIiiIii / i1IIi
 i1 = bold ( "Decrypt" , False )
 lprint ( "{} Map-Register with key-id {}" . format ( i1 , iIIoo0o0O0ooO0O ) )
 if 8 - 8: O0 / OOooOOo + iII111i % iIii1I11I1II1 % iIii1I11I1II1 . ooOoO0o
 IiIi = chacha . ChaCha ( i1iIII1i , Ii1IiiiI1ii ) . decrypt ( packet [ 4 : : ] )
 return ( packet [ 0 : 4 ] + IiIi )
 if 47 - 47: OoO0O00 / o0oOOo0O0Ooo / Ii1I * I1IiiI % ooOoO0o / I1Ii111
 if 80 - 80: I1Ii111 / O0 * O0
 if 40 - 40: OoO0O00 - oO0o / o0oOOo0O0Ooo . oO0o
 if 89 - 89: i11iIiiIii - II111iiii
 if 67 - 67: IiII % I1Ii111 + i11iIiiIii
 if 53 - 53: OOooOOo
 if 95 - 95: oO0o - OOooOOo % I1Ii111 / OoooooooOO % OoooooooOO - O0
def lisp_process_map_register ( lisp_sockets , packet , source , sport ) :
 global lisp_registered_count
 if 21 - 21: I1Ii111 . i1IIi - iII111i % I1ii11iIi11i . OOooOOo
 if 52 - 52: Ii1I * I1ii11iIi11i
 if 21 - 21: I1IiiI . i11iIiiIii - o0oOOo0O0Ooo * II111iiii % iIii1I11I1II1
 if 9 - 9: I1ii11iIi11i + I11i
 if 20 - 20: iII111i + i1IIi / oO0o % OoooooooOO * OoOoOO00
 if 70 - 70: Oo0Ooo - OOooOOo * OOooOOo / o0oOOo0O0Ooo
 packet = lisp_decrypt_map_register ( packet )
 if ( packet == None ) : return
 if 4 - 4: OoOoOO00 / OoO0O00
 o0OOO = lisp_map_register ( )
 oOO , packet = o0OOO . decode ( packet )
 if ( packet == None ) :
  lprint ( "Could not decode Map-Register packet" )
  return
  if 16 - 16: i11iIiiIii - I1Ii111 . OOooOOo
 o0OOO . sport = sport
 if 54 - 54: I1IiiI
 o0OOO . print_map_register ( )
 if 4 - 4: o0oOOo0O0Ooo + o0oOOo0O0Ooo / oO0o / i1IIi
 if 65 - 65: i1IIi - Ii1I
 if 6 - 6: ooOoO0o . OoO0O00 / O0 * OoO0O00
 if 35 - 35: Ii1I / I11i - ooOoO0o / OoooooooOO
 II1iI111i11 = True
 if ( o0OOO . auth_len == LISP_SHA1_160_AUTH_DATA_LEN ) :
  II1iI111i11 = True
  if 39 - 39: I1ii11iIi11i . i11iIiiIii + I11i . O0
 if ( o0OOO . alg_id == LISP_SHA_256_128_ALG_ID ) :
  II1iI111i11 = False
  if 16 - 16: II111iiii . ooOoO0o . i11iIiiIii * Ii1I - o0oOOo0O0Ooo . I1IiiI
  if 33 - 33: o0oOOo0O0Ooo % ooOoO0o
  if 43 - 43: I1Ii111
  if 81 - 81: OoOoOO00
  if 97 - 97: OoO0O00
 OoooO0oOO = [ ]
 if 8 - 8: oO0o - OoO0O00 * I1Ii111
 if 25 - 25: iII111i % OoO0O00
 if 9 - 9: i1IIi / OoOoOO00 + o0oOOo0O0Ooo + OOooOOo - I1IiiI / i1IIi
 if 8 - 8: o0oOOo0O0Ooo * OoO0O00 % IiII / OoooooooOO * ooOoO0o - i11iIiiIii
 iIoo = None
 I1IIiIiii = packet
 oooOoooOO0Oo0 = [ ]
 OOo00oOOo0OOO = o0OOO . record_count
 for II11iIII1i1I in range ( OOo00oOOo0OOO ) :
  IiII1iiI = lisp_eid_record ( )
  o00o = lisp_rloc_record ( )
  packet = IiII1iiI . decode ( packet )
  if ( packet == None ) :
   lprint ( "Could not decode EID-record in Map-Register packet" )
   return
   if 32 - 32: OoO0O00 . oO0o * I1Ii111 - OoOoOO00 . o0oOOo0O0Ooo % oO0o
  IiII1iiI . print_record ( "  " , False )
  if 21 - 21: iIii1I11I1II1
  if 31 - 31: OoOoOO00
  if 37 - 37: i11iIiiIii + IiII
  if 41 - 41: OoOoOO00 + i1IIi - iIii1I11I1II1
  ooO00oO0O = lisp_site_eid_lookup ( IiII1iiI . eid , IiII1iiI . group ,
 False )
  if 8 - 8: I1Ii111
  II = ooO00oO0O . print_eid_tuple ( ) if ooO00oO0O else None
  if 6 - 6: OoOoOO00 * oO0o - II111iiii * OoO0O00 . I11i % I1Ii111
  if 83 - 83: OOooOOo * I1IiiI . ooOoO0o
  if 45 - 45: OoooooooOO % Oo0Ooo / oO0o
  if 71 - 71: O0
  if 22 - 22: iII111i * ooOoO0o * I1IiiI / II111iiii % Ii1I
  if 39 - 39: OoooooooOO % i11iIiiIii
  if 20 - 20: iII111i - I11i / I1ii11iIi11i * O0 + IiII % I11i
  if ( ooO00oO0O and ooO00oO0O . accept_more_specifics == False ) :
   if ( ooO00oO0O . eid_record_matches ( IiII1iiI ) == False ) :
    OOooOo00Ooo = ooO00oO0O . parent_for_more_specifics
    if ( OOooOo00Ooo ) : ooO00oO0O = OOooOo00Ooo
    if 81 - 81: IiII * oO0o * IiII
    if 16 - 16: IiII - OOooOOo - I1Ii111 / OoooooooOO . Ii1I
    if 28 - 28: iII111i / I1ii11iIi11i - OoOoOO00 * Oo0Ooo + Ii1I * OoOoOO00
    if 94 - 94: oO0o
    if 95 - 95: ooOoO0o * O0 + OOooOOo
    if 11 - 11: i1IIi / OoOoOO00 + OoOoOO00 + I1ii11iIi11i + OOooOOo
    if 21 - 21: ooOoO0o
    if 28 - 28: OoOoOO00 + OoOoOO00 - OoOoOO00 / ooOoO0o
  oO00OO00o = ( ooO00oO0O and ooO00oO0O . accept_more_specifics )
  if ( oO00OO00o ) :
   OOOoo0 = lisp_site_eid ( ooO00oO0O . site )
   OOOoo0 . dynamic = True
   OOOoo0 . eid . copy_address ( IiII1iiI . eid )
   OOOoo0 . group . copy_address ( IiII1iiI . group )
   OOOoo0 . parent_for_more_specifics = ooO00oO0O
   OOOoo0 . add_cache ( )
   OOOoo0 . inherit_from_ams_parent ( )
   ooO00oO0O . more_specific_registrations . append ( OOOoo0 )
   ooO00oO0O = OOOoo0
  else :
   ooO00oO0O = lisp_site_eid_lookup ( IiII1iiI . eid , IiII1iiI . group ,
 True )
   if 39 - 39: OoO0O00 - o0oOOo0O0Ooo
   if 100 - 100: o0oOOo0O0Ooo * OoO0O00 + I1ii11iIi11i
  oO00oo000O = IiII1iiI . print_eid_tuple ( )
  if 8 - 8: OOooOOo . i11iIiiIii / oO0o % OOooOOo - II111iiii % II111iiii
  if ( ooO00oO0O == None ) :
   iIo0OO0O000 = bold ( "Site not found" , False )
   lprint ( "  {} for EID {}{}" . format ( iIo0OO0O000 , green ( oO00oo000O , False ) ,
 ", matched non-ams {}" . format ( green ( II , False ) if II else "" ) ) )
   if 46 - 46: II111iiii + OoOoOO00 % OoO0O00
   if 7 - 7: oO0o + II111iiii - O0
   if 32 - 32: oO0o
   if 62 - 62: i11iIiiIii + OoooooooOO + IiII - OoO0O00 / oO0o * iIii1I11I1II1
   if 91 - 91: o0oOOo0O0Ooo - i11iIiiIii + Oo0Ooo % iIii1I11I1II1
   packet = o00o . end_of_rlocs ( packet , IiII1iiI . rloc_count )
   if ( packet == None ) :
    lprint ( "  Could not decode RLOC-record in Map-Register packet" )
    return
    if 58 - 58: iII111i / ooOoO0o - I1Ii111 + I1Ii111 * ooOoO0o
   continue
   if 48 - 48: iII111i % O0 % Ii1I * OoO0O00 . OoO0O00
   if 74 - 74: OoO0O00 * i1IIi + I1ii11iIi11i / o0oOOo0O0Ooo / i1IIi
  iIoo = ooO00oO0O . site
  if 94 - 94: Ii1I
  if ( oO00OO00o ) :
   Oo0ooo0Ooo = ooO00oO0O . parent_for_more_specifics . print_eid_tuple ( )
   lprint ( "  Found ams {} for site '{}' for registering prefix {}" . format ( green ( Oo0ooo0Ooo , False ) , iIoo . site_name , green ( oO00oo000O , False ) ) )
   if 13 - 13: OoO0O00 - II111iiii . iII111i + OoOoOO00 / i11iIiiIii
  else :
   Oo0ooo0Ooo = green ( ooO00oO0O . print_eid_tuple ( ) , False )
   lprint ( "  Found {} for site '{}' for registering prefix {}" . format ( Oo0ooo0Ooo , iIoo . site_name , green ( oO00oo000O , False ) ) )
   if 32 - 32: ooOoO0o / II111iiii / I1ii11iIi11i
   if 34 - 34: iIii1I11I1II1
   if 47 - 47: OOooOOo * iII111i
   if 71 - 71: IiII - OoooooooOO * i11iIiiIii . OoooooooOO % i1IIi . Oo0Ooo
   if 3 - 3: OoO0O00 + i11iIiiIii + oO0o * IiII
   if 19 - 19: iII111i / II111iiii . I1Ii111 * I1IiiI - OOooOOo
  if ( iIoo . shutdown ) :
   lprint ( ( "  Rejecting registration for site '{}', configured in " +
 "admin-shutdown state" ) . format ( iIoo . site_name ) )
   packet = o00o . end_of_rlocs ( packet , IiII1iiI . rloc_count )
   continue
   if 70 - 70: OoO0O00
   if 42 - 42: OoooooooOO - I1Ii111 + I1ii11iIi11i * iII111i * iII111i / OoO0O00
   if 85 - 85: O0 . II111iiii
   if 80 - 80: O0 * I11i * I1Ii111
   if 89 - 89: Ii1I * OoO0O00 . i1IIi . O0 - IiII - OoOoOO00
   if 25 - 25: iII111i + i1IIi
   if 64 - 64: IiII % I11i / iIii1I11I1II1
   if 66 - 66: Ii1I
  OoooOOo0oOO = o0OOO . key_id
  if ( iIoo . auth_key . has_key ( OoooOOo0oOO ) == False ) : OoooOOo0oOO = 0
  O0Ooo0 = iIoo . auth_key [ OoooOOo0oOO ]
  if 95 - 95: I11i - oO0o - OOooOOo * ooOoO0o % I1IiiI
  oO0O = lisp_verify_auth ( oOO , o0OOO . alg_id ,
 o0OOO . auth_data , O0Ooo0 )
  O0OO0o000o00 = "dynamic " if ooO00oO0O . dynamic else ""
  if 85 - 85: Ii1I % OoOoOO00
  O0O0oooo = bold ( "passed" if oO0O else "failed" , False )
  OoooOOo0oOO = "key-id {}" . format ( OoooOOo0oOO ) if OoooOOo0oOO == o0OOO . key_id else "bad key-id {}" . format ( o0OOO . key_id )
  if 28 - 28: IiII
  lprint ( "  Authentication {} for {}EID-prefix {}, {}" . format ( O0O0oooo , O0OO0o000o00 , green ( oO00oo000O , False ) , OoooOOo0oOO ) )
  if 32 - 32: IiII * II111iiii . Ii1I
  if 68 - 68: I11i / O0
  if 6 - 6: oO0o - oO0o . I1IiiI % I1ii11iIi11i
  if 22 - 22: Ii1I / I1IiiI / II111iiii
  if 31 - 31: II111iiii - Ii1I * OOooOOo - i11iIiiIii / OoooooooOO - I1Ii111
  if 76 - 76: Oo0Ooo
  Oo0Oooo0 = True
  OoO0 = ( lisp_get_eid_hash ( IiII1iiI . eid ) != None )
  if ( OoO0 or ooO00oO0O . require_signature ) :
   I1II1111iI = "Required " if ooO00oO0O . require_signature else ""
   oO00oo000O = green ( oO00oo000O , False )
   Oo0o0o0oo = lisp_find_sig_in_rloc_set ( packet , IiII1iiI . rloc_count )
   if ( Oo0o0o0oo == None ) :
    Oo0Oooo0 = False
    lprint ( ( "  {}EID-crypto-hash signature verification {} " + "for EID-prefix {}, no signature found" ) . format ( I1II1111iI ,
    # I1Ii111 + i1IIi - ooOoO0o
 bold ( "failed" , False ) , oO00oo000O ) )
   else :
    Oo0Oooo0 = lisp_verify_cga_sig ( IiII1iiI . eid , Oo0o0o0oo )
    O0O0oooo = bold ( "passed" if Oo0Oooo0 else "failed" , False )
    lprint ( ( "  {}EID-crypto-hash signature verification {} " + "for EID-prefix {}" ) . format ( I1II1111iI , O0O0oooo , oO00oo000O ) )
    if 23 - 23: II111iiii - O0
    if 58 - 58: o0oOOo0O0Ooo * OoO0O00 + OoO0O00
    if 93 - 93: IiII - I1ii11iIi11i % I11i + i1IIi % OoO0O00
    if 20 - 20: oO0o . Oo0Ooo + IiII - II111iiii % Ii1I
  if ( oO0O == False or Oo0Oooo0 == False ) :
   packet = o00o . end_of_rlocs ( packet , IiII1iiI . rloc_count )
   if ( packet == None ) :
    lprint ( "  Could not decode RLOC-record in Map-Register packet" )
    return
    if 64 - 64: Ii1I % OoO0O00 + OOooOOo % OoOoOO00 + IiII
   continue
   if 92 - 92: iII111i * Oo0Ooo - OoOoOO00
   if 33 - 33: i11iIiiIii - OoOoOO00 . OOooOOo * II111iiii . Ii1I
   if 59 - 59: OoOoOO00
   if 29 - 29: iII111i - II111iiii * OoooooooOO * OoooooooOO
   if 15 - 15: IiII / OOooOOo / iIii1I11I1II1 / OoOoOO00
   if 91 - 91: i11iIiiIii % O0 . Oo0Ooo / I1Ii111
  if ( o0OOO . merge_register_requested ) :
   OOooOo00Ooo = ooO00oO0O
   OOooOo00Ooo . inconsistent_registration = False
   if 62 - 62: Oo0Ooo . II111iiii % OoO0O00 . Ii1I * OOooOOo + II111iiii
   if 7 - 7: OOooOOo
   if 22 - 22: Oo0Ooo + ooOoO0o
   if 71 - 71: OOooOOo . Ii1I * i11iIiiIii . I11i
   if 9 - 9: O0 / I1ii11iIi11i . iII111i . O0 + IiII % I11i
   if ( ooO00oO0O . group . is_null ( ) ) :
    if ( OOooOo00Ooo . site_id != o0OOO . site_id ) :
     OOooOo00Ooo . site_id = o0OOO . site_id
     OOooOo00Ooo . registered = False
     OOooOo00Ooo . individual_registrations = { }
     OOooOo00Ooo . registered_rlocs = [ ]
     lisp_registered_count -= 1
     if 27 - 27: i11iIiiIii - I1ii11iIi11i / O0 - i1IIi + I1IiiI * iII111i
     if 26 - 26: Oo0Ooo . Ii1I
     if 7 - 7: OoOoOO00 - o0oOOo0O0Ooo + oO0o
   Iiii11 = source . address + o0OOO . xtr_id
   if ( ooO00oO0O . individual_registrations . has_key ( Iiii11 ) ) :
    ooO00oO0O = ooO00oO0O . individual_registrations [ Iiii11 ]
   else :
    ooO00oO0O = lisp_site_eid ( iIoo )
    ooO00oO0O . eid . copy_address ( OOooOo00Ooo . eid )
    ooO00oO0O . group . copy_address ( OOooOo00Ooo . group )
    OOooOo00Ooo . individual_registrations [ Iiii11 ] = ooO00oO0O
    if 8 - 8: iIii1I11I1II1
  else :
   ooO00oO0O . inconsistent_registration = ooO00oO0O . merge_register_requested
   if 6 - 6: oO0o
   if 51 - 51: I1Ii111 - o0oOOo0O0Ooo
   if 5 - 5: O0
  ooO00oO0O . map_registers_received += 1
  if 7 - 7: OoOoOO00 + OoO0O00 * I1IiiI
  if 63 - 63: I1ii11iIi11i + iII111i * i1IIi
  if 63 - 63: I1ii11iIi11i / II111iiii % oO0o + ooOoO0o . Ii1I % I11i
  if 59 - 59: I1Ii111 % o0oOOo0O0Ooo - I1IiiI * i1IIi
  if 5 - 5: I1IiiI
  iiO0 = ( ooO00oO0O . is_rloc_in_rloc_set ( source ) == False )
  if ( IiII1iiI . record_ttl == 0 and iiO0 ) :
   lprint ( "  Ignore deregistration request from {}" . format ( red ( source . print_address_no_iid ( ) , False ) ) )
   if 22 - 22: II111iiii / iII111i
   continue
   if 18 - 18: i11iIiiIii * ooOoO0o . I1IiiI + i1IIi + I11i
   if 62 - 62: O0 % o0oOOo0O0Ooo + iIii1I11I1II1 + iIii1I11I1II1 * ooOoO0o
   if 21 - 21: o0oOOo0O0Ooo % O0
   if 81 - 81: i1IIi + i1IIi
   if 3 - 3: I1Ii111 . I1ii11iIi11i * iII111i * i11iIiiIii * IiII
   if 52 - 52: iIii1I11I1II1 % o0oOOo0O0Ooo % I1IiiI
  oo0OOo = ooO00oO0O . registered_rlocs
  ooO00oO0O . registered_rlocs = [ ]
  if 14 - 14: OoO0O00
  if 11 - 11: ooOoO0o * IiII * I1Ii111 * ooOoO0o
  if 92 - 92: I1IiiI
  if 94 - 94: OoOoOO00 % OoOoOO00 . i11iIiiIii
  ii11iIi11 = packet
  for o0000o0O0ooo in range ( IiII1iiI . rloc_count ) :
   o00o = lisp_rloc_record ( )
   packet = o00o . decode ( packet , None )
   if ( packet == None ) :
    lprint ( "  Could not decode RLOC-record in Map-Register packet" )
    return
    if 43 - 43: OoOoOO00 / I1IiiI * OoO0O00 / Oo0Ooo
   o00o . print_record ( "    " )
   if 59 - 59: I11i % i1IIi % Oo0Ooo % Oo0Ooo
   if 91 - 91: I11i
   if 98 - 98: I11i - II111iiii . IiII % Oo0Ooo
   if 65 - 65: OoO0O00
   if ( len ( iIoo . allowed_rlocs ) > 0 ) :
    ooOOo0o = o00o . rloc . print_address ( )
    if ( iIoo . allowed_rlocs . has_key ( ooOOo0o ) == False ) :
     lprint ( ( "  Reject registration, RLOC {} not " + "configured in allowed RLOC-set" ) . format ( red ( ooOOo0o , False ) ) )
     if 65 - 65: oO0o
     if 77 - 77: I11i * i1IIi - OOooOOo / OoOoOO00
     ooO00oO0O . registered = False
     packet = o00o . end_of_rlocs ( packet ,
 IiII1iiI . rloc_count - o0000o0O0ooo - 1 )
     break
     if 50 - 50: O0 - oO0o . oO0o
     if 98 - 98: IiII % Ii1I / Ii1I
     if 10 - 10: Ii1I
     if 69 - 69: I1Ii111 * OoooooooOO . o0oOOo0O0Ooo % I1IiiI
     if 70 - 70: iII111i . i11iIiiIii * I1Ii111
     if 54 - 54: o0oOOo0O0Ooo . i1IIi / iII111i
   Oo0o0o0oo = lisp_rloc ( )
   Oo0o0o0oo . store_rloc_from_record ( o00o , None , source )
   if 21 - 21: O0 + ooOoO0o
   if 53 - 53: Ii1I - II111iiii * iIii1I11I1II1
   if 91 - 91: OoOoOO00 % iIii1I11I1II1
   if 81 - 81: i11iIiiIii / OoOoOO00 + iIii1I11I1II1
   if 65 - 65: o0oOOo0O0Ooo
   if 73 - 73: I11i . I1ii11iIi11i - OoO0O00 + OoooooooOO
   if ( source . is_exact_match ( Oo0o0o0oo . rloc ) ) :
    Oo0o0o0oo . map_notify_requested = o0OOO . map_notify_requested
    if 71 - 71: I1IiiI
    if 27 - 27: OoO0O00 + i1IIi * OoooooooOO * iIii1I11I1II1 - Ii1I
    if 85 - 85: OoO0O00 + II111iiii / OoO0O00 . II111iiii * OoOoOO00 * I1IiiI
    if 19 - 19: iII111i / Ii1I + iIii1I11I1II1 * O0 - Oo0Ooo
    if 47 - 47: iIii1I11I1II1 % I1ii11iIi11i
   ooO00oO0O . registered_rlocs . append ( Oo0o0o0oo )
   if 33 - 33: oO0o . oO0o / IiII + II111iiii
   if 34 - 34: OoO0O00 . OoOoOO00 / i1IIi / OOooOOo
  iIii111 = ( ooO00oO0O . do_rloc_sets_match ( oo0OOo ) == False )
  if 37 - 37: Ii1I * o0oOOo0O0Ooo
  if 39 - 39: OoooooooOO
  if 37 - 37: OoO0O00 . iII111i
  if 32 - 32: II111iiii
  if 11 - 11: i11iIiiIii - OOooOOo . i1IIi + OOooOOo - O0
  if 17 - 17: i1IIi % o0oOOo0O0Ooo % ooOoO0o / I11i
  if ( o0OOO . map_register_refresh and iIii111 and
 ooO00oO0O . registered ) :
   lprint ( "  Reject registration, refreshes cannot change RLOC-set" )
   ooO00oO0O . registered_rlocs = oo0OOo
   continue
   if 68 - 68: OoOoOO00
   if 14 - 14: iIii1I11I1II1 + oO0o / ooOoO0o
   if 20 - 20: I1ii11iIi11i . II111iiii % I1Ii111 + I1Ii111 / OoooooooOO . Ii1I
   if 98 - 98: OoooooooOO - i11iIiiIii - iII111i + Ii1I - I1IiiI
   if 75 - 75: OOooOOo
   if 25 - 25: iII111i / I1ii11iIi11i - ooOoO0o
  if ( ooO00oO0O . registered == False ) :
   ooO00oO0O . first_registered = lisp_get_timestamp ( )
   lisp_registered_count += 1
   if 53 - 53: IiII / OoooooooOO / ooOoO0o + Oo0Ooo - OOooOOo - iIii1I11I1II1
  ooO00oO0O . last_registered = lisp_get_timestamp ( )
  ooO00oO0O . registered = ( IiII1iiI . record_ttl != 0 )
  ooO00oO0O . last_registerer = source
  if 53 - 53: OOooOOo . I1IiiI . o0oOOo0O0Ooo / o0oOOo0O0Ooo
  if 40 - 40: OoooooooOO + iII111i % I1Ii111 . ooOoO0o
  if 2 - 2: ooOoO0o
  if 55 - 55: I11i + i1IIi * OoOoOO00 % Oo0Ooo * II111iiii . I1IiiI
  ooO00oO0O . auth_sha1_or_sha2 = II1iI111i11
  ooO00oO0O . proxy_reply_requested = o0OOO . proxy_reply_requested
  ooO00oO0O . lisp_sec_present = o0OOO . lisp_sec_present
  ooO00oO0O . map_notify_requested = o0OOO . map_notify_requested
  ooO00oO0O . mobile_node_requested = o0OOO . mobile_node
  ooO00oO0O . merge_register_requested = o0OOO . merge_register_requested
  if 98 - 98: I1ii11iIi11i
  ooO00oO0O . use_register_ttl_requested = o0OOO . use_ttl_for_timeout
  if ( ooO00oO0O . use_register_ttl_requested ) :
   ooO00oO0O . register_ttl = IiII1iiI . store_ttl ( )
  else :
   ooO00oO0O . register_ttl = LISP_SITE_TIMEOUT_CHECK_INTERVAL * 3
   if 57 - 57: OOooOOo * I11i . oO0o
  ooO00oO0O . xtr_id_present = o0OOO . xtr_id_present
  if ( ooO00oO0O . xtr_id_present ) :
   ooO00oO0O . xtr_id = o0OOO . xtr_id
   ooO00oO0O . site_id = o0OOO . site_id
   if 17 - 17: iII111i - OOooOOo * I1IiiI + i1IIi % I1ii11iIi11i
   if 71 - 71: Ii1I - o0oOOo0O0Ooo - oO0o
   if 27 - 27: O0 - iIii1I11I1II1
   if 78 - 78: Oo0Ooo / o0oOOo0O0Ooo
   if 35 - 35: o0oOOo0O0Ooo . OoO0O00 / o0oOOo0O0Ooo / IiII - I1ii11iIi11i . Oo0Ooo
  if ( o0OOO . merge_register_requested ) :
   if ( OOooOo00Ooo . merge_in_site_eid ( ooO00oO0O ) ) :
    OoooO0oOO . append ( [ IiII1iiI . eid , IiII1iiI . group ] )
    if 97 - 97: i11iIiiIii + I1ii11iIi11i - I11i . oO0o
   if ( o0OOO . map_notify_requested ) :
    lisp_send_merged_map_notify ( lisp_sockets , OOooOo00Ooo , o0OOO ,
 IiII1iiI )
    if 76 - 76: IiII * II111iiii * I1ii11iIi11i + OoooooooOO - OoOoOO00 . Ii1I
    if 51 - 51: II111iiii % I1Ii111 * O0 . ooOoO0o * OoOoOO00
    if 17 - 17: I1IiiI % I11i
  if ( iIii111 == False ) : continue
  if ( len ( OoooO0oOO ) != 0 ) : continue
  if 28 - 28: I1ii11iIi11i * OoooooooOO
  oooOoooOO0Oo0 . append ( ooO00oO0O . print_eid_tuple ( ) )
  if 19 - 19: Oo0Ooo - iII111i % OoOoOO00 * i11iIiiIii / oO0o . i11iIiiIii
  if 46 - 46: I1ii11iIi11i
  if 50 - 50: OOooOOo * OoO0O00 * OOooOOo % I1IiiI - I1Ii111 * Ii1I
  if 88 - 88: OOooOOo . iII111i / I11i
  if 1 - 1: iIii1I11I1II1 - Oo0Ooo % OoooooooOO
  if 71 - 71: OOooOOo - Ii1I
  if 68 - 68: ooOoO0o
  IiII1iiI = IiII1iiI . encode ( )
  IiII1iiI += ii11iIi11
  IIIo000 = [ ooO00oO0O . print_eid_tuple ( ) ]
  lprint ( "    Changed RLOC-set, Map-Notifying old RLOC-set" )
  if 35 - 35: IiII . iIii1I11I1II1 + Ii1I % O0
  for Oo0o0o0oo in oo0OOo :
   if ( Oo0o0o0oo . map_notify_requested == False ) : continue
   if ( Oo0o0o0oo . rloc . is_exact_match ( source ) ) : continue
   lisp_build_map_notify ( lisp_sockets , IiII1iiI , IIIo000 , 1 , Oo0o0o0oo . rloc ,
 LISP_CTRL_PORT , o0OOO . nonce , o0OOO . key_id ,
 o0OOO . alg_id , o0OOO . auth_len , iIoo , False )
   if 94 - 94: OoOoOO00 + II111iiii . II111iiii + ooOoO0o + ooOoO0o
   if 95 - 95: iIii1I11I1II1 / i11iIiiIii - IiII - OOooOOo
   if 4 - 4: II111iiii + oO0o + o0oOOo0O0Ooo % IiII % iIii1I11I1II1
   if 68 - 68: i11iIiiIii
   if 79 - 79: OoOoOO00 * Ii1I / I1ii11iIi11i + OOooOOo
  lisp_notify_subscribers ( lisp_sockets , IiII1iiI , ooO00oO0O . eid , iIoo )
  if 19 - 19: I1IiiI + I11i + I1IiiI + OoO0O00
  if 33 - 33: i11iIiiIii - Ii1I * II111iiii
  if 97 - 97: OoO0O00 / o0oOOo0O0Ooo * iIii1I11I1II1
  if 5 - 5: I1IiiI
  if 27 - 27: i1IIi + oO0o / I1ii11iIi11i + oO0o
 if ( len ( OoooO0oOO ) != 0 ) :
  lisp_queue_multicast_map_notify ( lisp_sockets , OoooO0oOO )
  if 98 - 98: II111iiii + iIii1I11I1II1
  if 70 - 70: I11i / OoooooooOO / i11iIiiIii
  if 61 - 61: O0 . Oo0Ooo . iIii1I11I1II1
  if 54 - 54: OOooOOo * I1ii11iIi11i + OoooooooOO
  if 58 - 58: i1IIi - OoooooooOO * OOooOOo . ooOoO0o + O0 + o0oOOo0O0Ooo
  if 87 - 87: OOooOOo + I1Ii111 + O0 / oO0o / i11iIiiIii
 if ( o0OOO . merge_register_requested ) : return
 if 60 - 60: O0 . II111iiii
 if 69 - 69: II111iiii / ooOoO0o - OoOoOO00 / OOooOOo
 if 52 - 52: OoO0O00 % I11i + o0oOOo0O0Ooo % OoOoOO00
 if 46 - 46: o0oOOo0O0Ooo % O0
 if 30 - 30: oO0o
 if ( o0OOO . map_notify_requested and iIoo != None ) :
  lisp_build_map_notify ( lisp_sockets , I1IIiIiii , oooOoooOO0Oo0 ,
 o0OOO . record_count , source , sport , o0OOO . nonce ,
 o0OOO . key_id , o0OOO . alg_id , o0OOO . auth_len ,
 iIoo , True )
  if 64 - 64: O0
 return
 if 70 - 70: oO0o % I1IiiI . iIii1I11I1II1 - Oo0Ooo + OoOoOO00 % O0
 if 91 - 91: I1Ii111 - oO0o * ooOoO0o - I1ii11iIi11i + IiII + O0
 if 18 - 18: OoOoOO00 / IiII / o0oOOo0O0Ooo . OOooOOo
 if 35 - 35: I11i . ooOoO0o % I11i / iII111i / O0 % I11i
 if 29 - 29: I1Ii111 + Ii1I
 if 100 - 100: Ii1I + I1Ii111 / iIii1I11I1II1 / i1IIi % OoOoOO00
 if 6 - 6: oO0o + ooOoO0o
 if 13 - 13: Oo0Ooo . IiII % iII111i + i1IIi / OOooOOo
 if 1 - 1: I11i * i1IIi * Oo0Ooo % O0
 if 41 - 41: OOooOOo % OoOoOO00
def lisp_process_multicast_map_notify ( packet , source ) :
 oO0o0ooo = lisp_map_notify ( "" )
 packet = oO0o0ooo . decode ( packet )
 if ( packet == None ) :
  lprint ( "Could not decode Map-Notify packet" )
  return
  if 82 - 82: I11i . IiII
  if 27 - 27: I1Ii111 % O0 * OoooooooOO . Oo0Ooo
 oO0o0ooo . print_notify ( )
 if ( oO0o0ooo . record_count == 0 ) : return
 if 51 - 51: I11i
 oOO000 = oO0o0ooo . eid_records
 if 34 - 34: OoooooooOO . I1IiiI . Oo0Ooo % iII111i
 for II11iIII1i1I in range ( oO0o0ooo . record_count ) :
  IiII1iiI = lisp_eid_record ( )
  oOO000 = IiII1iiI . decode ( oOO000 )
  if ( packet == None ) : return
  IiII1iiI . print_record ( "  " , False )
  if 24 - 24: ooOoO0o * oO0o * Oo0Ooo . oO0o - OoOoOO00
  if 85 - 85: II111iiii
  if 51 - 51: Oo0Ooo
  if 57 - 57: i1IIi * ooOoO0o + o0oOOo0O0Ooo + O0 - I1ii11iIi11i % IiII
  ooooOoo000O = lisp_map_cache_lookup ( IiII1iiI . eid , IiII1iiI . group )
  if ( ooooOoo000O == None ) :
   ooooOoo000O = lisp_mapping ( IiII1iiI . eid , IiII1iiI . group , [ ] )
   ooooOoo000O . add_cache ( )
   if 62 - 62: Ii1I / i11iIiiIii - I11i * ooOoO0o + iII111i
   if 85 - 85: oO0o . iIii1I11I1II1 % i11iIiiIii - i11iIiiIii % IiII / Oo0Ooo
  ooooOoo000O . mapping_source = None if source == "lisp-etr" else source
  ooooOoo000O . map_cache_ttl = IiII1iiI . store_ttl ( )
  if 11 - 11: OoO0O00 . I1IiiI * I1ii11iIi11i / ooOoO0o - i11iIiiIii
  if 40 - 40: I1ii11iIi11i + I11i * OoooooooOO % OoooooooOO
  if 19 - 19: Oo0Ooo . OOooOOo
  if 58 - 58: IiII % iII111i + i1IIi % I1IiiI % OOooOOo . iII111i
  if 85 - 85: i11iIiiIii . o0oOOo0O0Ooo * iII111i . I1ii11iIi11i / I1Ii111 % Ii1I
  if ( len ( ooooOoo000O . rloc_set ) != 0 and IiII1iiI . rloc_count == 0 ) :
   ooooOoo000O . rloc_set = [ ]
   ooooOoo000O . build_best_rloc_set ( )
   lisp_write_ipc_map_cache ( True , ooooOoo000O )
   lprint ( "Update {} map-cache entry with no RLOC-set" . format ( green ( ooooOoo000O . print_eid_tuple ( ) , False ) ) )
   if 27 - 27: II111iiii . iIii1I11I1II1 / I1ii11iIi11i / i1IIi / iIii1I11I1II1
   continue
   if 70 - 70: i11iIiiIii . OoO0O00 / OoooooooOO * OoooooooOO - OOooOOo
   if 34 - 34: I1ii11iIi11i * i1IIi % OoooooooOO / I1IiiI
  III11i1 = ooooOoo000O . rtrs_in_rloc_set ( )
  if 80 - 80: o0oOOo0O0Ooo * ooOoO0o
  if 87 - 87: I1Ii111 + O0 / I1ii11iIi11i / OoOoOO00 . Oo0Ooo - IiII
  if 24 - 24: OoOoOO00
  if 19 - 19: ooOoO0o
  if 43 - 43: O0 . I1Ii111 % OoooooooOO / I1IiiI . o0oOOo0O0Ooo - OoOoOO00
  for o0000o0O0ooo in range ( IiII1iiI . rloc_count ) :
   o00o = lisp_rloc_record ( )
   oOO000 = o00o . decode ( oOO000 , None )
   o00o . print_record ( "    " )
   if ( IiII1iiI . group . is_null ( ) ) : continue
   if ( o00o . rle == None ) : continue
   if 46 - 46: I11i - OoooooooOO % o0oOOo0O0Ooo
   if 7 - 7: OoooooooOO - I1Ii111 * IiII
   if 20 - 20: o0oOOo0O0Ooo . OoooooooOO * I1IiiI . Oo0Ooo * OoOoOO00
   if 3 - 3: I1Ii111 % i11iIiiIii % O0 % II111iiii
   if 8 - 8: OoooooooOO * ooOoO0o
   iiIIi11 = ooooOoo000O . rloc_set [ 0 ] . stats if len ( ooooOoo000O . rloc_set ) != 0 else None
   if 70 - 70: I1Ii111 / oO0o % OoooooooOO
   if 65 - 65: I1Ii111 . I1ii11iIi11i * iII111i
   if 89 - 89: o0oOOo0O0Ooo / I1Ii111 - oO0o + iII111i % I1IiiI - Ii1I
   if 58 - 58: OoOoOO00 + O0 - OoooooooOO % OoOoOO00 % i1IIi
   Oo0o0o0oo = lisp_rloc ( )
   Oo0o0o0oo . store_rloc_from_record ( o00o , None , ooooOoo000O . mapping_source )
   if ( iiIIi11 != None ) : Oo0o0o0oo . stats = copy . deepcopy ( iiIIi11 )
   if 75 - 75: OoOoOO00 . IiII - OoO0O00 . o0oOOo0O0Ooo % II111iiii
   if ( III11i1 and Oo0o0o0oo . is_rtr ( ) == False ) : continue
   if 69 - 69: Ii1I % OoooooooOO
   ooooOoo000O . rloc_set = [ Oo0o0o0oo ]
   ooooOoo000O . build_best_rloc_set ( )
   lisp_write_ipc_map_cache ( True , ooooOoo000O )
   if 62 - 62: Oo0Ooo / oO0o
   lprint ( "Update {} map-cache entry with RLE {}" . format ( green ( ooooOoo000O . print_eid_tuple ( ) , False ) , Oo0o0o0oo . rle . print_rle ( False ) ) )
   if 87 - 87: oO0o
   if 39 - 39: iII111i
   if 46 - 46: i11iIiiIii * iII111i / Oo0Ooo % OOooOOo % oO0o / Ii1I
 return
 if 75 - 75: Ii1I
 if 37 - 37: I1IiiI / OoO0O00 . OoO0O00 + i11iIiiIii - oO0o
 if 57 - 57: I1IiiI . OoO0O00
 if 49 - 49: II111iiii + iII111i
 if 85 - 85: I11i / i11iIiiIii
 if 33 - 33: iIii1I11I1II1 % O0 + II111iiii * OOooOOo . Ii1I * iII111i
 if 48 - 48: I11i * iIii1I11I1II1 / oO0o
 if 34 - 34: i1IIi + oO0o * Oo0Ooo * I1Ii111 % OoooooooOO % ooOoO0o
def lisp_process_map_notify ( lisp_sockets , orig_packet , source ) :
 oO0o0ooo = lisp_map_notify ( "" )
 oOo = oO0o0ooo . decode ( orig_packet )
 if ( oOo == None ) :
  lprint ( "Could not decode Map-Notify packet" )
  return
  if 17 - 17: I1ii11iIi11i + o0oOOo0O0Ooo / OoO0O00 . Oo0Ooo - o0oOOo0O0Ooo / oO0o
  if 87 - 87: ooOoO0o
 oO0o0ooo . print_notify ( )
 if 74 - 74: i11iIiiIii . i11iIiiIii . iIii1I11I1II1
 if 100 - 100: i11iIiiIii - oO0o + iIii1I11I1II1 * OoOoOO00 % OOooOOo % i11iIiiIii
 if 26 - 26: O0
 if 97 - 97: OOooOOo + I11i % I1Ii111 % i11iIiiIii / I1ii11iIi11i
 if 21 - 21: O0 + iIii1I11I1II1 / i11iIiiIii . OOooOOo * i1IIi
 o00oOOO = source . print_address ( )
 if ( oO0o0ooo . alg_id != 0 or oO0o0ooo . auth_len != 0 ) :
  ooooOOoO = None
  for Iiii11 in lisp_map_servers_list :
   if ( Iiii11 . find ( o00oOOO ) == - 1 ) : continue
   ooooOOoO = lisp_map_servers_list [ Iiii11 ]
   if 3 - 3: i1IIi % o0oOOo0O0Ooo + OoOoOO00
  if ( ooooOOoO == None ) :
   lprint ( ( "  Could not find Map-Server {} to authenticate " + "Map-Notify" ) . format ( o00oOOO ) )
   if 32 - 32: OoO0O00 . Oo0Ooo * iIii1I11I1II1
   return
   if 12 - 12: O0 + I1ii11iIi11i + I11i . I1Ii111
   if 48 - 48: Ii1I . iIii1I11I1II1 - iIii1I11I1II1 * I11i . OoooooooOO
  ooooOOoO . map_notifies_received += 1
  if 73 - 73: Ii1I / II111iiii - iIii1I11I1II1 . ooOoO0o * II111iiii . OOooOOo
  oO0O = lisp_verify_auth ( oOo , oO0o0ooo . alg_id ,
 oO0o0ooo . auth_data , ooooOOoO . password )
  if 50 - 50: iIii1I11I1II1 + OoOoOO00 % O0 + OoO0O00 . i11iIiiIii / oO0o
  lprint ( "  Authentication {} for Map-Notify" . format ( "succeeded" if oO0O else "failed" ) )
  if 31 - 31: I1IiiI % o0oOOo0O0Ooo . i11iIiiIii % OOooOOo - iIii1I11I1II1
  if ( oO0O == False ) : return
 else :
  ooooOOoO = lisp_ms ( o00oOOO , None , "" , 0 , "" , False , False , False , False , 0 , 0 , 0 ,
 None )
  if 77 - 77: i11iIiiIii / OOooOOo
  if 93 - 93: I1ii11iIi11i - iII111i % O0 - Ii1I
  if 84 - 84: I1ii11iIi11i . iIii1I11I1II1 % IiII * I11i + ooOoO0o
  if 59 - 59: oO0o * OoO0O00 - I11i * I1IiiI
  if 60 - 60: iII111i - OoooooooOO / iII111i % OoO0O00 . OoOoOO00 - o0oOOo0O0Ooo
  if 71 - 71: iII111i * o0oOOo0O0Ooo * i11iIiiIii * O0
 oOO000 = oO0o0ooo . eid_records
 if ( oO0o0ooo . record_count == 0 ) :
  lisp_send_map_notify_ack ( lisp_sockets , oOO000 , oO0o0ooo , ooooOOoO )
  return
  if 77 - 77: OOooOOo % iII111i + I11i / OoOoOO00
  if 50 - 50: OoOoOO00 - i11iIiiIii - OOooOOo . iIii1I11I1II1
  if 97 - 97: oO0o % OOooOOo . OoooooooOO * Ii1I
  if 100 - 100: I1ii11iIi11i / Ii1I % Oo0Ooo
  if 83 - 83: O0 . I1Ii111 % I1ii11iIi11i
  if 97 - 97: Oo0Ooo % OoO0O00 * I1ii11iIi11i * ooOoO0o * OoO0O00
  if 12 - 12: ooOoO0o
  if 56 - 56: i1IIi
 IiII1iiI = lisp_eid_record ( )
 oOo = IiII1iiI . decode ( oOO000 )
 if ( oOo == None ) : return
 if 3 - 3: OOooOOo - Oo0Ooo * Ii1I + i11iIiiIii
 IiII1iiI . print_record ( "  " , False )
 if 53 - 53: i1IIi % I1ii11iIi11i
 for o0000o0O0ooo in range ( IiII1iiI . rloc_count ) :
  o00o = lisp_rloc_record ( )
  oOo = o00o . decode ( oOo , None )
  if ( oOo == None ) :
   lprint ( "  Could not decode RLOC-record in Map-Notify packet" )
   return
   if 65 - 65: I11i + OoOoOO00 - i11iIiiIii
  o00o . print_record ( "    " )
  if 72 - 72: i11iIiiIii - iII111i . i11iIiiIii
  if 61 - 61: oO0o . i11iIiiIii / Ii1I % iII111i
  if 36 - 36: OoO0O00 + Ii1I / I11i - iII111i % OoO0O00 / Oo0Ooo
  if 38 - 38: Ii1I - ooOoO0o - O0 + oO0o . iIii1I11I1II1
  if 90 - 90: i1IIi * OoOoOO00
 if ( IiII1iiI . group . is_null ( ) == False ) :
  if 27 - 27: iIii1I11I1II1
  if 95 - 95: iII111i / ooOoO0o % Ii1I
  if 44 - 44: OOooOOo . OOooOOo
  if 5 - 5: oO0o + OoooooooOO
  if 88 - 88: oO0o + OOooOOo
  lprint ( "Send {} Map-Notify IPC message to ITR process" . format ( green ( IiII1iiI . print_eid_tuple ( ) , False ) ) )
  if 14 - 14: I11i / i1IIi
  if 56 - 56: OoooooooOO
  oOooOOoo = lisp_control_packet_ipc ( orig_packet , o00oOOO , "lisp-itr" , 0 )
  lisp_ipc ( oOooOOoo , lisp_sockets [ 2 ] , "lisp-core-pkt" )
  if 59 - 59: I1ii11iIi11i + OoO0O00
  if 37 - 37: IiII * I1IiiI % O0
  if 32 - 32: ooOoO0o % II111iiii
  if 60 - 60: i11iIiiIii
  if 11 - 11: o0oOOo0O0Ooo
 lisp_send_map_notify_ack ( lisp_sockets , oOO000 , oO0o0ooo , ooooOOoO )
 return
 if 77 - 77: o0oOOo0O0Ooo / iIii1I11I1II1 * iIii1I11I1II1 / o0oOOo0O0Ooo * iII111i
 if 26 - 26: Ii1I
 if 1 - 1: OoOoOO00 . o0oOOo0O0Ooo + Oo0Ooo % Oo0Ooo * I1ii11iIi11i
 if 50 - 50: IiII / i1IIi . I1ii11iIi11i
 if 75 - 75: I11i * oO0o + OoooooooOO . iII111i + OoO0O00
 if 44 - 44: II111iiii
 if 65 - 65: I11i . iII111i . I1IiiI - Oo0Ooo % iIii1I11I1II1 / O0
 if 54 - 54: iII111i - I1Ii111
def lisp_process_map_notify_ack ( packet , source ) :
 oO0o0ooo = lisp_map_notify ( "" )
 packet = oO0o0ooo . decode ( packet )
 if ( packet == None ) :
  lprint ( "Could not decode Map-Notify-Ack packet" )
  return
  if 88 - 88: iII111i * OoO0O00 % OoooooooOO / oO0o
  if 7 - 7: i1IIi
 oO0o0ooo . print_notify ( )
 if 30 - 30: oO0o . i1IIi / I11i
 if 23 - 23: i1IIi + oO0o % iII111i - OoO0O00 - i1IIi
 if 74 - 74: Ii1I + I11i . OoooooooOO - I1ii11iIi11i
 if 2 - 2: oO0o - o0oOOo0O0Ooo
 if 80 - 80: i1IIi
 if ( oO0o0ooo . record_count < 1 ) :
  lprint ( "No EID-prefix found, cannot authenticate Map-Notify-Ack" )
  return
  if 40 - 40: O0 . ooOoO0o * iII111i . I11i + I1Ii111 % OoO0O00
  if 9 - 9: IiII * oO0o - o0oOOo0O0Ooo
 IiII1iiI = lisp_eid_record ( )
 if 17 - 17: iII111i % Oo0Ooo
 if ( IiII1iiI . decode ( oO0o0ooo . eid_records ) == None ) :
  lprint ( "Could not decode EID-record, cannot authenticate " +
 "Map-Notify-Ack" )
  return
  if 14 - 14: I1IiiI - I1Ii111 % I1IiiI - II111iiii
 IiII1iiI . print_record ( "  " , False )
 if 34 - 34: I1ii11iIi11i * IiII / II111iiii / ooOoO0o * oO0o
 oO00oo000O = IiII1iiI . print_eid_tuple ( )
 if 3 - 3: II111iiii
 if 61 - 61: oO0o . I1IiiI + i1IIi
 if 69 - 69: O0 / i1IIi - OoOoOO00 + ooOoO0o - oO0o
 if 80 - 80: o0oOOo0O0Ooo % O0 * I11i . i1IIi - ooOoO0o
 if ( oO0o0ooo . alg_id != LISP_NONE_ALG_ID and oO0o0ooo . auth_len != 0 ) :
  ooO00oO0O = lisp_sites_by_eid . lookup_cache ( IiII1iiI . eid , True )
  if ( ooO00oO0O == None ) :
   iIo0OO0O000 = bold ( "Site not found" , False )
   lprint ( ( "{} for EID {}, cannot authenticate Map-Notify-Ack" ) . format ( iIo0OO0O000 , green ( oO00oo000O , False ) ) )
   if 93 - 93: OoooooooOO / o0oOOo0O0Ooo
   return
   if 61 - 61: II111iiii / i1IIi . I1ii11iIi11i % iIii1I11I1II1
  iIoo = ooO00oO0O . site
  if 66 - 66: iIii1I11I1II1 % OoOoOO00 + i1IIi * i11iIiiIii * OoooooooOO
  if 36 - 36: iII111i - OoO0O00 + I1IiiI + Ii1I . OoooooooOO
  if 75 - 75: oO0o * Oo0Ooo * O0
  if 22 - 22: ooOoO0o / OoooooooOO . II111iiii / Ii1I * OoO0O00 . i1IIi
  iIoo . map_notify_acks_received += 1
  if 62 - 62: oO0o % Ii1I - Ii1I
  OoooOOo0oOO = oO0o0ooo . key_id
  if ( iIoo . auth_key . has_key ( OoooOOo0oOO ) == False ) : OoooOOo0oOO = 0
  O0Ooo0 = iIoo . auth_key [ OoooOOo0oOO ]
  if 16 - 16: OoO0O00 - O0 - OOooOOo - I11i % OoOoOO00
  oO0O = lisp_verify_auth ( packet , oO0o0ooo . alg_id ,
 oO0o0ooo . auth_data , O0Ooo0 )
  if 7 - 7: I1Ii111 / OoOoOO00 . II111iiii
  OoooOOo0oOO = "key-id {}" . format ( OoooOOo0oOO ) if OoooOOo0oOO == oO0o0ooo . key_id else "bad key-id {}" . format ( oO0o0ooo . key_id )
  if 9 - 9: I11i . I11i . OoooooooOO
  if 42 - 42: iII111i / oO0o / iII111i * OoO0O00
  lprint ( "  Authentication {} for Map-Notify-Ack, {}" . format ( "succeeded" if oO0O else "failed" , OoooOOo0oOO ) )
  if 25 - 25: OoOoOO00 - II111iiii + II111iiii . Ii1I * II111iiii
  if ( oO0O == False ) : return
  if 12 - 12: IiII / Ii1I
  if 54 - 54: Oo0Ooo + Ii1I % OoooooooOO * OOooOOo / OoOoOO00
  if 39 - 39: I1IiiI % i11iIiiIii % Ii1I
  if 59 - 59: ooOoO0o % OoO0O00 / I1IiiI - II111iiii + OoooooooOO * i11iIiiIii
  if 58 - 58: IiII / Oo0Ooo + o0oOOo0O0Ooo
 if ( oO0o0ooo . retransmit_timer ) : oO0o0ooo . retransmit_timer . cancel ( )
 if 71 - 71: Ii1I - IiII
 Ii11 = source . print_address ( )
 Iiii11 = oO0o0ooo . nonce_key
 if 2 - 2: OoOoOO00 % IiII % OoO0O00 . i1IIi / I1Ii111 - iIii1I11I1II1
 if ( lisp_map_notify_queue . has_key ( Iiii11 ) ) :
  oO0o0ooo = lisp_map_notify_queue . pop ( Iiii11 )
  if ( oO0o0ooo . retransmit_timer ) : oO0o0ooo . retransmit_timer . cancel ( )
  lprint ( "Dequeue Map-Notify from retransmit queue, key is: {}" . format ( Iiii11 ) )
  if 88 - 88: Oo0Ooo * i1IIi % OOooOOo
 else :
  lprint ( "Map-Notify with nonce 0x{} queue entry not found for {}" . format ( oO0o0ooo . nonce_key , red ( Ii11 , False ) ) )
  if 65 - 65: iII111i . oO0o
  if 67 - 67: I1IiiI / iII111i / O0 % ooOoO0o - IiII / Ii1I
 return
 if 31 - 31: I11i - oO0o * ooOoO0o
 if 64 - 64: I11i
 if 41 - 41: I1Ii111 * OoooooooOO / OoOoOO00 + OoO0O00 . OoOoOO00 + I1Ii111
 if 9 - 9: IiII . I11i . I1Ii111 / i1IIi * OoOoOO00 - O0
 if 3 - 3: O0 / iIii1I11I1II1 % IiII + I11i
 if 43 - 43: Oo0Ooo % I11i
 if 53 - 53: OoOoOO00 % OoooooooOO * o0oOOo0O0Ooo % OoooooooOO
 if 47 - 47: iIii1I11I1II1 - OOooOOo + I1ii11iIi11i * ooOoO0o + Oo0Ooo + OoO0O00
def lisp_map_referral_loop ( mr , eid , group , action , s ) :
 if ( action not in ( LISP_DDT_ACTION_NODE_REFERRAL ,
 LISP_DDT_ACTION_MS_REFERRAL ) ) : return ( False )
 if 64 - 64: OoOoOO00 - OoOoOO00 . OoooooooOO + ooOoO0o
 if ( mr . last_cached_prefix [ 0 ] == None ) : return ( False )
 if 100 - 100: ooOoO0o . OoooooooOO % i1IIi % OoO0O00
 if 26 - 26: OoOoOO00 * IiII
 if 76 - 76: I1IiiI + IiII * I1ii11iIi11i * I1IiiI % Ii1I + ooOoO0o
 if 46 - 46: OoOoOO00
 oooOOOo0 = False
 if ( group . is_null ( ) == False ) :
  oooOOOo0 = mr . last_cached_prefix [ 1 ] . is_more_specific ( group )
  if 66 - 66: iII111i - O0 . I1Ii111 * i1IIi / OoO0O00 / II111iiii
 if ( oooOOOo0 == False ) :
  oooOOOo0 = mr . last_cached_prefix [ 0 ] . is_more_specific ( eid )
  if 35 - 35: ooOoO0o * OOooOOo / I11i % I11i / OoooooooOO . I1Ii111
  if 70 - 70: I1ii11iIi11i % I1ii11iIi11i / oO0o
 if ( oooOOOo0 ) :
  I11Ii11ii = lisp_print_eid_tuple ( eid , group )
  OOo0OOO0Ooo = lisp_print_eid_tuple ( mr . last_cached_prefix [ 0 ] ,
 mr . last_cached_prefix [ 1 ] )
  if 90 - 90: I1IiiI / I1Ii111 + Oo0Ooo / o0oOOo0O0Ooo + OOooOOo
  lprint ( ( "Map-Referral prefix {} from {} is not more-specific " + "than cached prefix {}" ) . format ( green ( I11Ii11ii , False ) , s ,
  # o0oOOo0O0Ooo / oO0o / ooOoO0o % I1IiiI / IiII - i11iIiiIii
 OOo0OOO0Ooo ) )
  if 41 - 41: Ii1I % Ii1I * oO0o - I11i + iIii1I11I1II1 . ooOoO0o
 return ( oooOOOo0 )
 if 30 - 30: Ii1I * iII111i . II111iiii / i1IIi
 if 77 - 77: oO0o . IiII + I1ii11iIi11i . i1IIi
 if 49 - 49: I1Ii111 . OoooooooOO / o0oOOo0O0Ooo - iII111i - iII111i - i11iIiiIii
 if 37 - 37: OOooOOo
 if 79 - 79: I1Ii111 - OoO0O00 + ooOoO0o + oO0o . i11iIiiIii + i1IIi
 if 32 - 32: IiII . ooOoO0o / OoO0O00 / iII111i . iIii1I11I1II1 % IiII
 if 28 - 28: I1Ii111 + OoooooooOO + IiII . ooOoO0o . I1IiiI / oO0o
def lisp_process_map_referral ( lisp_sockets , packet , source ) :
 if 66 - 66: Ii1I - I11i + Oo0Ooo . ooOoO0o
 OOOoo = lisp_map_referral ( )
 packet = OOOoo . decode ( packet )
 if ( packet == None ) :
  lprint ( "Could not decode Map-Referral packet" )
  return
  if 89 - 89: IiII . II111iiii / OoO0O00 + I1ii11iIi11i * i11iIiiIii
 OOOoo . print_map_referral ( )
 if 85 - 85: o0oOOo0O0Ooo - Oo0Ooo / I1Ii111
 o00oOOO = source . print_address ( )
 i11III1I = OOOoo . nonce
 if 100 - 100: OoO0O00 * iIii1I11I1II1 - IiII . i1IIi % i11iIiiIii % Oo0Ooo
 if 22 - 22: ooOoO0o - OOooOOo
 if 90 - 90: i11iIiiIii . i11iIiiIii - iIii1I11I1II1
 if 20 - 20: ooOoO0o - i11iIiiIii
 for II11iIII1i1I in range ( OOOoo . record_count ) :
  IiII1iiI = lisp_eid_record ( )
  packet = IiII1iiI . decode ( packet )
  if ( packet == None ) :
   lprint ( "Could not decode EID-record in Map-Referral packet" )
   return
   if 23 - 23: OoO0O00 + I1IiiI / I1ii11iIi11i * I1ii11iIi11i % ooOoO0o
  IiII1iiI . print_record ( "  " , True )
  if 83 - 83: I1IiiI * i11iIiiIii - I1ii11iIi11i + I11i
  if 33 - 33: OoO0O00 . OoooooooOO % iII111i / oO0o * Ii1I + ooOoO0o
  if 29 - 29: oO0o
  if 21 - 21: i11iIiiIii . o0oOOo0O0Ooo
  Iiii11 = str ( i11III1I )
  if ( Iiii11 not in lisp_ddt_map_requestQ ) :
   lprint ( ( "Map-Referral nonce 0x{} from {} not found in " + "Map-Request queue, EID-record ignored" ) . format ( lisp_hex_string ( i11III1I ) , o00oOOO ) )
   if 78 - 78: Oo0Ooo
   if 77 - 77: oO0o % Oo0Ooo % O0
   continue
   if 51 - 51: IiII % IiII + OOooOOo . II111iiii / I1ii11iIi11i
  Ii1IIi1III1i = lisp_ddt_map_requestQ [ Iiii11 ]
  if ( Ii1IIi1III1i == None ) :
   lprint ( ( "No Map-Request queue entry found for Map-Referral " +
 "nonce 0x{} from {}, EID-record ignored" ) . format ( lisp_hex_string ( i11III1I ) , o00oOOO ) )
   if 4 - 4: o0oOOo0O0Ooo % I1IiiI * o0oOOo0O0Ooo * OoOoOO00 - Ii1I
   continue
   if 61 - 61: OoooooooOO - OoOoOO00 . O0 / ooOoO0o . Ii1I
   if 41 - 41: Oo0Ooo / OoOoOO00 % I1Ii111 - O0
   if 19 - 19: I1IiiI % I1Ii111 - O0 . iIii1I11I1II1 . I11i % O0
   if 88 - 88: ooOoO0o
   if 52 - 52: iIii1I11I1II1 % ooOoO0o * iIii1I11I1II1
   if 20 - 20: i11iIiiIii * I11i
  if ( lisp_map_referral_loop ( Ii1IIi1III1i , IiII1iiI . eid , IiII1iiI . group ,
 IiII1iiI . action , o00oOOO ) ) :
   Ii1IIi1III1i . dequeue_map_request ( )
   continue
   if 29 - 29: IiII / OOooOOo
   if 39 - 39: O0 + II111iiii
  Ii1IIi1III1i . last_cached_prefix [ 0 ] = IiII1iiI . eid
  Ii1IIi1III1i . last_cached_prefix [ 1 ] = IiII1iiI . group
  if 94 - 94: OOooOOo % I1ii11iIi11i % O0 + iII111i
  if 62 - 62: iIii1I11I1II1 . OoOoOO00 / iIii1I11I1II1 + IiII
  if 31 - 31: Ii1I . OoO0O00 . Ii1I + OoO0O00 * iIii1I11I1II1 . iII111i
  if 42 - 42: O0 / oO0o % O0 . i1IIi % OOooOOo
  IiI1iiIi1I1i = False
  I1IIiII1 = lisp_referral_cache_lookup ( IiII1iiI . eid , IiII1iiI . group ,
 True )
  if ( I1IIiII1 == None ) :
   IiI1iiIi1I1i = True
   I1IIiII1 = lisp_referral ( )
   I1IIiII1 . eid = IiII1iiI . eid
   I1IIiII1 . group = IiII1iiI . group
   if ( IiII1iiI . ddt_incomplete == False ) : I1IIiII1 . add_cache ( )
  elif ( I1IIiII1 . referral_source . not_set ( ) ) :
   lprint ( "Do not replace static referral entry {}" . format ( green ( I1IIiII1 . print_eid_tuple ( ) , False ) ) )
   if 13 - 13: I1IiiI % ooOoO0o + OOooOOo
   Ii1IIi1III1i . dequeue_map_request ( )
   continue
   if 91 - 91: oO0o - ooOoO0o
   if 20 - 20: i1IIi . IiII / o0oOOo0O0Ooo / I11i
  O0oo0oo0 = IiII1iiI . action
  I1IIiII1 . referral_source = source
  I1IIiII1 . referral_type = O0oo0oo0
  Ii1 = IiII1iiI . store_ttl ( )
  I1IIiII1 . referral_ttl = Ii1
  I1IIiII1 . expires = lisp_set_timestamp ( Ii1 )
  if 27 - 27: ooOoO0o . ooOoO0o - Ii1I % i11iIiiIii
  if 74 - 74: I1Ii111 - II111iiii % o0oOOo0O0Ooo
  if 7 - 7: I1IiiI + OoooooooOO + o0oOOo0O0Ooo . OoooooooOO
  if 29 - 29: iII111i * O0 + I1IiiI * IiII + iII111i - IiII
  iI11iIii = I1IIiII1 . is_referral_negative ( )
  if ( I1IIiII1 . referral_set . has_key ( o00oOOO ) ) :
   IiOO00O00 = I1IIiII1 . referral_set [ o00oOOO ]
   if 14 - 14: I1IiiI . o0oOOo0O0Ooo / I1Ii111
   if ( IiOO00O00 . updown == False and iI11iIii == False ) :
    IiOO00O00 . updown = True
    lprint ( "Change up/down status for referral-node {} to up" . format ( o00oOOO ) )
    if 67 - 67: OoooooooOO . oO0o * OoOoOO00 - OoooooooOO
   elif ( IiOO00O00 . updown == True and iI11iIii == True ) :
    IiOO00O00 . updown = False
    lprint ( ( "Change up/down status for referral-node {} " + "to down, received negative referral" ) . format ( o00oOOO ) )
    if 32 - 32: oO0o
    if 72 - 72: I1IiiI
    if 34 - 34: ooOoO0o % II111iiii / ooOoO0o
    if 87 - 87: Oo0Ooo
    if 7 - 7: iIii1I11I1II1
    if 85 - 85: iIii1I11I1II1 . O0
    if 43 - 43: II111iiii / OoOoOO00 + OOooOOo % Oo0Ooo * OOooOOo
    if 62 - 62: ooOoO0o * OOooOOo . I11i + Oo0Ooo - I1Ii111
  I11I1I1iiiIIi = { }
  for Iiii11 in I1IIiII1 . referral_set : I11I1I1iiiIIi [ Iiii11 ] = None
  if 63 - 63: I11i % I1ii11iIi11i / o0oOOo0O0Ooo
  if 95 - 95: oO0o * I1IiiI / OOooOOo
  if 79 - 79: O0 . iII111i . iII111i % ooOoO0o
  if 74 - 74: ooOoO0o
  for II11iIII1i1I in range ( IiII1iiI . rloc_count ) :
   o00o = lisp_rloc_record ( )
   packet = o00o . decode ( packet , None )
   if ( packet == None ) :
    lprint ( "Could not decode RLOC-record in Map-Referral packet" )
    return
    if 37 - 37: oO0o / i1IIi * iII111i - i1IIi
   o00o . print_record ( "    " )
   if 12 - 12: OoO0O00 * IiII + OoOoOO00 * I1Ii111 % OoOoOO00 + OoOoOO00
   if 12 - 12: I1ii11iIi11i % Ii1I * OoOoOO00 . iIii1I11I1II1 * I1Ii111 - OoOoOO00
   if 33 - 33: OoO0O00 * I1IiiI / i1IIi
   if 88 - 88: Ii1I / ooOoO0o - I11i % OoO0O00 * iII111i
   ooOOo0o = o00o . rloc . print_address ( )
   if ( I1IIiII1 . referral_set . has_key ( ooOOo0o ) == False ) :
    IiOO00O00 = lisp_referral_node ( )
    IiOO00O00 . referral_address . copy_address ( o00o . rloc )
    I1IIiII1 . referral_set [ ooOOo0o ] = IiOO00O00
    if ( o00oOOO == ooOOo0o and iI11iIii ) : IiOO00O00 . updown = False
   else :
    IiOO00O00 = I1IIiII1 . referral_set [ ooOOo0o ]
    if ( I11I1I1iiiIIi . has_key ( ooOOo0o ) ) : I11I1I1iiiIIi . pop ( ooOOo0o )
    if 47 - 47: i11iIiiIii + Oo0Ooo % oO0o % O0
   IiOO00O00 . priority = o00o . priority
   IiOO00O00 . weight = o00o . weight
   if 98 - 98: oO0o - O0 / iII111i % oO0o % I1IiiI / i1IIi
   if 61 - 61: ooOoO0o + II111iiii
   if 54 - 54: OoOoOO00 * o0oOOo0O0Ooo . OoO0O00
   if 53 - 53: oO0o % OoO0O00 / OoO0O00 / I11i * Oo0Ooo
   if 13 - 13: i1IIi % iIii1I11I1II1 - iII111i - I1IiiI - IiII + iIii1I11I1II1
  for Iiii11 in I11I1I1iiiIIi : I1IIiII1 . referral_set . pop ( Iiii11 )
  if 22 - 22: IiII - OOooOOo + I1ii11iIi11i
  oO00oo000O = I1IIiII1 . print_eid_tuple ( )
  if 64 - 64: OoOoOO00
  if ( IiI1iiIi1I1i ) :
   if ( IiII1iiI . ddt_incomplete ) :
    lprint ( "Suppress add {} to referral-cache" . format ( green ( oO00oo000O , False ) ) )
    if 79 - 79: IiII
   else :
    lprint ( "Add {}, referral-count {} to referral-cache" . format ( green ( oO00oo000O , False ) , IiII1iiI . rloc_count ) )
    if 65 - 65: Oo0Ooo - i11iIiiIii * OoOoOO00 . I1Ii111 . iIii1I11I1II1
    if 48 - 48: iIii1I11I1II1 - oO0o / OoO0O00 + O0 . Ii1I + I1Ii111
  else :
   lprint ( "Replace {}, referral-count: {} in referral-cache" . format ( green ( oO00oo000O , False ) , IiII1iiI . rloc_count ) )
   if 17 - 17: OoOoOO00 . Oo0Ooo - I1Ii111 / I1Ii111 + I11i % i1IIi
   if 31 - 31: OoooooooOO . O0 / OoO0O00 . I1Ii111
   if 41 - 41: OoooooooOO + iII111i . OOooOOo
   if 73 - 73: oO0o + i1IIi + i11iIiiIii / I1ii11iIi11i
   if 100 - 100: I1IiiI % ooOoO0o % OoooooooOO / i11iIiiIii + i11iIiiIii % IiII
   if 39 - 39: Ii1I % o0oOOo0O0Ooo + OOooOOo / iIii1I11I1II1
  if ( O0oo0oo0 == LISP_DDT_ACTION_DELEGATION_HOLE ) :
   lisp_send_negative_map_reply ( Ii1IIi1III1i . lisp_sockets , I1IIiII1 . eid ,
 I1IIiII1 . group , Ii1IIi1III1i . nonce , Ii1IIi1III1i . itr , Ii1IIi1III1i . sport , 15 , None , False )
   Ii1IIi1III1i . dequeue_map_request ( )
   if 40 - 40: iIii1I11I1II1 / iII111i % OOooOOo % i11iIiiIii
   if 57 - 57: II111iiii % OoO0O00 * i1IIi
  if ( O0oo0oo0 == LISP_DDT_ACTION_NOT_AUTH ) :
   if ( Ii1IIi1III1i . tried_root ) :
    lisp_send_negative_map_reply ( Ii1IIi1III1i . lisp_sockets , I1IIiII1 . eid ,
 I1IIiII1 . group , Ii1IIi1III1i . nonce , Ii1IIi1III1i . itr , Ii1IIi1III1i . sport , 0 , None , False )
    Ii1IIi1III1i . dequeue_map_request ( )
   else :
    lisp_send_ddt_map_request ( Ii1IIi1III1i , True )
    if 19 - 19: ooOoO0o . iIii1I11I1II1 + I1ii11iIi11i + I1ii11iIi11i / o0oOOo0O0Ooo . Oo0Ooo
    if 9 - 9: II111iiii % OoooooooOO
    if 4 - 4: i1IIi * i11iIiiIii % OoooooooOO + OoOoOO00 . oO0o
  if ( O0oo0oo0 == LISP_DDT_ACTION_MS_NOT_REG ) :
   if ( I1IIiII1 . referral_set . has_key ( o00oOOO ) ) :
    IiOO00O00 = I1IIiII1 . referral_set [ o00oOOO ]
    IiOO00O00 . updown = False
    if 95 - 95: I1ii11iIi11i * OoOoOO00 % o0oOOo0O0Ooo / O0 + ooOoO0o % OOooOOo
   if ( len ( I1IIiII1 . referral_set ) == 0 ) :
    Ii1IIi1III1i . dequeue_map_request ( )
   else :
    lisp_send_ddt_map_request ( Ii1IIi1III1i , False )
    if 48 - 48: i1IIi + IiII - iIii1I11I1II1 . i11iIiiIii % OOooOOo + I1ii11iIi11i
    if 95 - 95: ooOoO0o + OoOoOO00 . II111iiii + Ii1I
    if 81 - 81: OoooooooOO / OOooOOo / Oo0Ooo
  if ( O0oo0oo0 in ( LISP_DDT_ACTION_NODE_REFERRAL ,
 LISP_DDT_ACTION_MS_REFERRAL ) ) :
   if ( Ii1IIi1III1i . eid . is_exact_match ( IiII1iiI . eid ) ) :
    if ( not Ii1IIi1III1i . tried_root ) :
     lisp_send_ddt_map_request ( Ii1IIi1III1i , True )
    else :
     lisp_send_negative_map_reply ( Ii1IIi1III1i . lisp_sockets ,
 I1IIiII1 . eid , I1IIiII1 . group , Ii1IIi1III1i . nonce , Ii1IIi1III1i . itr ,
 Ii1IIi1III1i . sport , 15 , None , False )
     Ii1IIi1III1i . dequeue_map_request ( )
     if 26 - 26: iII111i
   else :
    lisp_send_ddt_map_request ( Ii1IIi1III1i , False )
    if 93 - 93: Oo0Ooo + I1IiiI % OoOoOO00 / OOooOOo / I1ii11iIi11i
    if 6 - 6: IiII
    if 68 - 68: Oo0Ooo
  if ( O0oo0oo0 == LISP_DDT_ACTION_MS_ACK ) : Ii1IIi1III1i . dequeue_map_request ( )
  if 83 - 83: OOooOOo / iIii1I11I1II1 . OoO0O00 - oO0o % Oo0Ooo
 return
 if 30 - 30: Ii1I . OoOoOO00 / oO0o . OoO0O00
 if 93 - 93: i11iIiiIii
 if 33 - 33: i1IIi % OoooooooOO + Oo0Ooo % I1IiiI / ooOoO0o
 if 40 - 40: IiII % IiII
 if 9 - 9: I1IiiI * i1IIi + OOooOOo * OoOoOO00
 if 8 - 8: iII111i
 if 51 - 51: I1IiiI
 if 72 - 72: ooOoO0o / I1ii11iIi11i . Ii1I * iII111i . iIii1I11I1II1
def lisp_process_ecm ( lisp_sockets , packet , source , ecm_port ) :
 Ii1I111Ii = lisp_ecm ( 0 )
 packet = Ii1I111Ii . decode ( packet )
 if ( packet == None ) :
  lprint ( "Could not decode ECM packet" )
  return
  if 35 - 35: OoO0O00 . OoOoOO00 % O0 * OoO0O00
  if 68 - 68: OOooOOo
 Ii1I111Ii . print_ecm ( )
 if 87 - 87: IiII * IiII - OoO0O00 / I1ii11iIi11i + OOooOOo / i11iIiiIii
 oooooOOo0Oo = lisp_control_header ( )
 if ( oooooOOo0Oo . decode ( packet ) == None ) :
  lprint ( "Could not decode control header" )
  return
  if 21 - 21: o0oOOo0O0Ooo / oO0o + oO0o + Oo0Ooo / o0oOOo0O0Ooo
  if 39 - 39: i11iIiiIii - OoO0O00 - i11iIiiIii / OoooooooOO
 IiI1IIi = oooooOOo0Oo . type
 del ( oooooOOo0Oo )
 if 23 - 23: OOooOOo / OoOoOO00 / OoooooooOO + i1IIi % OoooooooOO
 if ( IiI1IIi != LISP_MAP_REQUEST ) :
  lprint ( "Received ECM without Map-Request inside" )
  return
  if 15 - 15: o0oOOo0O0Ooo % I1ii11iIi11i / II111iiii
  if 50 - 50: oO0o * Ii1I % I1Ii111
  if 74 - 74: iIii1I11I1II1 - OOooOOo / I1Ii111 / ooOoO0o . oO0o % iIii1I11I1II1
  if 91 - 91: o0oOOo0O0Ooo . o0oOOo0O0Ooo - Ii1I
  if 60 - 60: i11iIiiIii . Oo0Ooo / iIii1I11I1II1 / II111iiii
 IIiIi1i1iiIiii = Ii1I111Ii . udp_sport
 lisp_process_map_request ( lisp_sockets , packet , source , ecm_port ,
 Ii1I111Ii . source , IIiIi1i1iiIiii , Ii1I111Ii . ddt , - 1 )
 return
 if 62 - 62: OoooooooOO % OoO0O00 * O0 + OOooOOo
 if 34 - 34: O0 % Oo0Ooo . II111iiii % I1IiiI - iIii1I11I1II1
 if 20 - 20: i11iIiiIii % I1IiiI % OoOoOO00
 if 85 - 85: I11i + OoOoOO00 * O0 * O0
 if 92 - 92: i11iIiiIii
 if 16 - 16: I11i . ooOoO0o - Oo0Ooo / OoO0O00 . i1IIi
 if 59 - 59: ooOoO0o - ooOoO0o % I11i + OoO0O00
 if 88 - 88: Ii1I - ooOoO0o . Oo0Ooo
 if 83 - 83: I11i + Oo0Ooo . I1ii11iIi11i * I1ii11iIi11i
 if 80 - 80: i1IIi * I11i - OOooOOo / II111iiii * iIii1I11I1II1
def lisp_send_map_register ( lisp_sockets , packet , map_register , ms ) :
 if 42 - 42: OoOoOO00 . I11i % II111iiii
 if 19 - 19: OoooooooOO
 if 31 - 31: I11i . OoOoOO00 - O0 * iII111i % I1Ii111 - II111iiii
 if 21 - 21: OOooOOo . Oo0Ooo - i1IIi
 if 56 - 56: I11i
 if 24 - 24: I1IiiI . I1IiiI % ooOoO0o
 if 32 - 32: OOooOOo / i1IIi / OOooOOo
 iIi11i1I11Ii = ms . map_server
 if ( lisp_decent_push_configured and iIi11i1I11Ii . is_multicast_address ( ) and
 ( ms . map_registers_multicast_sent == 1 or ms . map_registers_sent == 1 ) ) :
  iIi11i1I11Ii = copy . deepcopy ( iIi11i1I11Ii )
  iIi11i1I11Ii . address = 0x7f000001
  II1Iii = bold ( "Bootstrap" , False )
  o0 = ms . map_server . print_address_no_iid ( )
  lprint ( "{} mapping system for peer-group {}" . format ( II1Iii , o0 ) )
  if 97 - 97: ooOoO0o * Oo0Ooo * OoooooooOO * I1IiiI
  if 45 - 45: Oo0Ooo
  if 27 - 27: oO0o / IiII - iIii1I11I1II1 / o0oOOo0O0Ooo % OOooOOo * iIii1I11I1II1
  if 40 - 40: oO0o - II111iiii * OOooOOo % OoooooooOO
  if 52 - 52: OOooOOo + OoO0O00
  if 96 - 96: OOooOOo % O0 - Oo0Ooo % oO0o / I1IiiI . i1IIi
 packet = lisp_compute_auth ( packet , map_register , ms . password )
 if 42 - 42: i1IIi
 if 52 - 52: OoO0O00 % iII111i % O0
 if 11 - 11: i1IIi / i11iIiiIii + Ii1I % Oo0Ooo % O0
 if 50 - 50: oO0o . I1Ii111
 if 38 - 38: iIii1I11I1II1 . Ii1I
 if ( ms . ekey != None ) :
  i1iIII1i = ms . ekey . zfill ( 32 )
  Ii1IiiiI1ii = "0" * 8
  Oooo0ooOoo0 = chacha . ChaCha ( i1iIII1i , Ii1IiiiI1ii ) . encrypt ( packet [ 4 : : ] )
  packet = packet [ 0 : 4 ] + Oooo0ooOoo0
  Oo0ooo0Ooo = bold ( "Encrypt" , False )
  lprint ( "{} Map-Register with key-id {}" . format ( Oo0ooo0Ooo , ms . ekey_id ) )
  if 82 - 82: OOooOOo * Ii1I + I1ii11iIi11i . OoO0O00
  if 15 - 15: O0
 I1i1Ii1I1 = ""
 if ( lisp_decent_pull_xtr_configured ( ) ) :
  I1i1Ii1I1 = ", decent-index {}" . format ( bold ( ms . dns_name , False ) )
  if 50 - 50: IiII * oO0o
  if 15 - 15: iIii1I11I1II1 / I1IiiI * i11iIiiIii
 lprint ( "Send Map-Register to map-server {}{}{}" . format ( iIi11i1I11Ii . print_address ( ) , ", ms-name '{}'" . format ( ms . ms_name ) , I1i1Ii1I1 ) )
 if 40 - 40: iIii1I11I1II1
 lisp_send ( lisp_sockets , iIi11i1I11Ii , LISP_CTRL_PORT , packet )
 return
 if 71 - 71: I1Ii111 % oO0o . iII111i + OoOoOO00
 if 29 - 29: oO0o % O0 - iIii1I11I1II1
 if 94 - 94: Oo0Ooo - I11i + I1IiiI / o0oOOo0O0Ooo / o0oOOo0O0Ooo
 if 19 - 19: oO0o . o0oOOo0O0Ooo + IiII * Oo0Ooo / OOooOOo % oO0o
 if 11 - 11: OoOoOO00 * Oo0Ooo / I11i * OOooOOo
 if 15 - 15: ooOoO0o - OOooOOo / OoooooooOO
 if 41 - 41: OoOoOO00 . iII111i . i1IIi + oO0o
 if 60 - 60: oO0o * I1Ii111
def lisp_send_ipc_to_core ( lisp_socket , packet , dest , port ) :
 oo = lisp_socket . getsockname ( )
 dest = dest . print_address_no_iid ( )
 if 81 - 81: oO0o - OOooOOo - oO0o
 lprint ( "Send IPC {} bytes to {} {}, control-packet: {}" . format ( len ( packet ) , dest , port , lisp_format_packet ( packet ) ) )
 if 54 - 54: oO0o % I11i
 if 71 - 71: oO0o / I1ii11iIi11i . Ii1I % II111iiii
 packet = lisp_control_packet_ipc ( packet , oo , dest , port )
 lisp_ipc ( packet , lisp_socket , "lisp-core-pkt" )
 return
 if 22 - 22: iIii1I11I1II1 - OoooooooOO
 if 8 - 8: ooOoO0o % i11iIiiIii
 if 41 - 41: I1Ii111 . ooOoO0o - i11iIiiIii + Ii1I . OOooOOo . OoOoOO00
 if 70 - 70: i1IIi % OoOoOO00 / iII111i + i11iIiiIii % ooOoO0o + IiII
 if 58 - 58: OOooOOo / i11iIiiIii . Oo0Ooo % iII111i
 if 92 - 92: OoOoOO00 / ooOoO0o % iII111i / iIii1I11I1II1
 if 73 - 73: O0 % i11iIiiIii
 if 16 - 16: O0
def lisp_send_map_reply ( lisp_sockets , packet , dest , port ) :
 lprint ( "Send Map-Reply to {}" . format ( dest . print_address_no_iid ( ) ) )
 lisp_send_ipc_to_core ( lisp_sockets [ 2 ] , packet , dest , port )
 return
 if 15 - 15: i1IIi % i11iIiiIii
 if 18 - 18: Ii1I . OoO0O00 . iII111i * oO0o + O0
 if 35 - 35: OoOoOO00 . oO0o / II111iiii
 if 97 - 97: Ii1I + I1Ii111 / II111iiii
 if 14 - 14: iII111i / IiII / oO0o
 if 55 - 55: OoO0O00 % O0
 if 92 - 92: OoooooooOO / O0
 if 14 - 14: i11iIiiIii
def lisp_send_map_referral ( lisp_sockets , packet , dest , port ) :
 lprint ( "Send Map-Referral to {}" . format ( dest . print_address ( ) ) )
 lisp_send_ipc_to_core ( lisp_sockets [ 2 ] , packet , dest , port )
 return
 if 43 - 43: OOooOOo
 if 79 - 79: iII111i % Oo0Ooo . i1IIi % ooOoO0o
 if 93 - 93: OoOoOO00
 if 49 - 49: i1IIi * OOooOOo % I11i * Ii1I . I1Ii111 * iIii1I11I1II1
 if 72 - 72: ooOoO0o
 if 63 - 63: Oo0Ooo . OoO0O00 . OoooooooOO / i1IIi
 if 53 - 53: OOooOOo * O0 . iII111i
 if 3 - 3: OoooooooOO * I1Ii111 * IiII - OOooOOo * I1Ii111
def lisp_send_map_notify ( lisp_sockets , packet , dest , port ) :
 lprint ( "Send Map-Notify to xTR {}" . format ( dest . print_address ( ) ) )
 lisp_send_ipc_to_core ( lisp_sockets [ 2 ] , packet , dest , port )
 return
 if 78 - 78: iII111i
 if 80 - 80: i1IIi * I1IiiI + OOooOOo
 if 91 - 91: I1IiiI % OoOoOO00 * Oo0Ooo / I1ii11iIi11i
 if 57 - 57: i11iIiiIii / o0oOOo0O0Ooo . II111iiii
 if 63 - 63: O0
 if 64 - 64: i11iIiiIii / oO0o . oO0o - Oo0Ooo
 if 48 - 48: i1IIi + I1ii11iIi11i + I1Ii111 - iII111i
def lisp_send_ecm ( lisp_sockets , packet , inner_source , inner_sport , inner_dest ,
 outer_dest , to_etr = False , to_ms = False , ddt = False ) :
 if 3 - 3: i1IIi + OoooooooOO * ooOoO0o + I1Ii111 % OOooOOo / IiII
 if ( inner_source == None or inner_source . is_null ( ) ) :
  inner_source = inner_dest
  if 70 - 70: oO0o + i1IIi % o0oOOo0O0Ooo - I11i
  if 74 - 74: i11iIiiIii
  if 93 - 93: I1Ii111 % OOooOOo * I1IiiI % iII111i / iIii1I11I1II1 + OoO0O00
  if 6 - 6: I11i
  if 70 - 70: ooOoO0o + OoooooooOO % OoOoOO00 % oO0o / Ii1I . I11i
  if 63 - 63: I1ii11iIi11i - ooOoO0o . OOooOOo / O0 . iIii1I11I1II1 - Ii1I
 if ( lisp_nat_traversal ) :
  O00o = lisp_get_any_translated_port ( )
  if ( O00o != None ) : inner_sport = O00o
  if 6 - 6: Ii1I
 Ii1I111Ii = lisp_ecm ( inner_sport )
 if 60 - 60: iII111i + I1IiiI
 Ii1I111Ii . to_etr = to_etr if lisp_is_running ( "lisp-etr" ) else False
 Ii1I111Ii . to_ms = to_ms if lisp_is_running ( "lisp-ms" ) else False
 Ii1I111Ii . ddt = ddt
 IiiI1Ii11i = Ii1I111Ii . encode ( packet , inner_source , inner_dest )
 if ( IiiI1Ii11i == None ) :
  lprint ( "Could not encode ECM message" )
  return
  if 11 - 11: o0oOOo0O0Ooo + iIii1I11I1II1 - OoooooooOO
 Ii1I111Ii . print_ecm ( )
 if 29 - 29: IiII
 packet = IiiI1Ii11i + packet
 if 22 - 22: I1IiiI * oO0o / Oo0Ooo
 ooOOo0o = outer_dest . print_address_no_iid ( )
 lprint ( "Send Encapsulated-Control-Message to {}" . format ( ooOOo0o ) )
 iIi11i1I11Ii = lisp_convert_4to6 ( ooOOo0o )
 lisp_send ( lisp_sockets , iIi11i1I11Ii , LISP_CTRL_PORT , packet )
 return
 if 40 - 40: I1ii11iIi11i . I1Ii111 / I1IiiI
 if 60 - 60: I1IiiI % Ii1I / I1Ii111 + Ii1I
 if 43 - 43: I1ii11iIi11i + I11i
 if 83 - 83: II111iiii + o0oOOo0O0Ooo - I1Ii111
 if 100 - 100: IiII - OoOoOO00 / I11i
 if 33 - 33: I1Ii111 * OoOoOO00 . I1ii11iIi11i % I1Ii111
 if 87 - 87: Oo0Ooo
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
if 65 - 65: ooOoO0o . I1IiiI
LISP_RLOC_UNKNOWN_STATE = 0
LISP_RLOC_UP_STATE = 1
LISP_RLOC_DOWN_STATE = 2
LISP_RLOC_UNREACH_STATE = 3
LISP_RLOC_NO_ECHOED_NONCE_STATE = 4
LISP_RLOC_ADMIN_DOWN_STATE = 5
if 51 - 51: IiII
LISP_AUTH_NONE = 0
LISP_AUTH_MD5 = 1
LISP_AUTH_SHA1 = 2
LISP_AUTH_SHA2 = 3
if 43 - 43: oO0o - I11i . i11iIiiIii
if 78 - 78: i11iIiiIii + Oo0Ooo * Ii1I - o0oOOo0O0Ooo % i11iIiiIii
if 30 - 30: I1IiiI % oO0o * OoooooooOO
if 64 - 64: I1IiiI
if 11 - 11: I1ii11iIi11i % iII111i / II111iiii % ooOoO0o % IiII
if 14 - 14: ooOoO0o / IiII . o0oOOo0O0Ooo
if 27 - 27: I1IiiI - OOooOOo . II111iiii * I1ii11iIi11i % ooOoO0o / I1IiiI
LISP_IPV4_HOST_MASK_LEN = 32
LISP_IPV6_HOST_MASK_LEN = 128
LISP_MAC_HOST_MASK_LEN = 48
LISP_E164_HOST_MASK_LEN = 60
if 90 - 90: o0oOOo0O0Ooo / I1ii11iIi11i - oO0o - Ii1I - I1IiiI + I1Ii111
if 93 - 93: I1IiiI - I11i . I1IiiI - iIii1I11I1II1
if 1 - 1: O0 . Ii1I % Ii1I + II111iiii . oO0o
if 24 - 24: o0oOOo0O0Ooo . I1Ii111 % O0
if 67 - 67: I1IiiI * Ii1I
if 64 - 64: OOooOOo
def byte_swap_64 ( address ) :
 iIiIi1iI11iiI = ( ( address & 0x00000000000000ff ) << 56 ) | ( ( address & 0x000000000000ff00 ) << 40 ) | ( ( address & 0x0000000000ff0000 ) << 24 ) | ( ( address & 0x00000000ff000000 ) << 8 ) | ( ( address & 0x000000ff00000000 ) >> 8 ) | ( ( address & 0x0000ff0000000000 ) >> 24 ) | ( ( address & 0x00ff000000000000 ) >> 40 ) | ( ( address & 0xff00000000000000 ) >> 56 )
 if 90 - 90: iII111i . OoOoOO00 + i1IIi % ooOoO0o * I11i + OoooooooOO
 if 2 - 2: o0oOOo0O0Ooo . II111iiii
 if 9 - 9: I1Ii111 - II111iiii + OoOoOO00 . OoO0O00
 if 33 - 33: Oo0Ooo
 if 12 - 12: i11iIiiIii . Oo0Ooo / OoOoOO00 + iII111i . Ii1I + ooOoO0o
 if 66 - 66: IiII
 if 41 - 41: II111iiii + Oo0Ooo / iII111i . IiII / iII111i / I1IiiI
 if 78 - 78: o0oOOo0O0Ooo % OoOoOO00 . O0
 return ( iIiIi1iI11iiI )
 if 41 - 41: iIii1I11I1II1 . OOooOOo - Oo0Ooo % OOooOOo
 if 90 - 90: i11iIiiIii + OoooooooOO - i11iIiiIii + OoooooooOO
 if 23 - 23: i11iIiiIii - IiII - I1ii11iIi11i + I1ii11iIi11i % I1IiiI
 if 79 - 79: II111iiii / OoooooooOO
 if 35 - 35: i1IIi + IiII + II111iiii % OOooOOo
 if 25 - 25: I11i + i11iIiiIii + O0 - Ii1I
 if 69 - 69: I11i . OoOoOO00 / OOooOOo / i1IIi . II111iiii
 if 17 - 17: I1Ii111
 if 2 - 2: O0 % OoOoOO00 + oO0o
 if 24 - 24: iII111i + iII111i - OoooooooOO % OoooooooOO * O0
 if 51 - 51: IiII
 if 31 - 31: I11i - iIii1I11I1II1 * Ii1I + Ii1I
 if 10 - 10: OoOoOO00 - i11iIiiIii % iIii1I11I1II1 / ooOoO0o * i11iIiiIii - Ii1I
 if 64 - 64: II111iiii . i11iIiiIii . iII111i . OOooOOo
 if 95 - 95: O0 - OoOoOO00
class lisp_cache_entries ( ) :
 def __init__ ( self ) :
  self . entries = { }
  self . entries_sorted = [ ]
  if 68 - 68: ooOoO0o . I1Ii111
  if 84 - 84: OoooooooOO + oO0o % i1IIi + o0oOOo0O0Ooo * i1IIi
  if 51 - 51: oO0o . OoooooooOO + OOooOOo * I1ii11iIi11i - ooOoO0o
class lisp_cache ( ) :
 def __init__ ( self ) :
  self . cache = { }
  self . cache_sorted = [ ]
  self . cache_count = 0
  if 41 - 41: Oo0Ooo
  if 46 - 46: i11iIiiIii + iIii1I11I1II1 . i11iIiiIii . iII111i
 def cache_size ( self ) :
  return ( self . cache_count )
  if 66 - 66: oO0o % i1IIi % OoooooooOO
  if 58 - 58: OOooOOo
 def build_key ( self , prefix ) :
  if ( prefix . afi == LISP_AFI_ULTIMATE_ROOT ) :
   IIiiiII = 0
  elif ( prefix . afi == LISP_AFI_IID_RANGE ) :
   IIiiiII = prefix . mask_len
  else :
   IIiiiII = prefix . mask_len + 48
   if 89 - 89: iIii1I11I1II1 - i1IIi
   if 26 - 26: OOooOOo - iII111i * I1ii11iIi11i / iII111i
  II1 = lisp_hex_string ( prefix . instance_id ) . zfill ( 8 )
  o0o0O00oOo = lisp_hex_string ( prefix . afi ) . zfill ( 4 )
  if 9 - 9: I1Ii111 / II111iiii * I1Ii111 / I11i - OoO0O00
  if ( prefix . afi > 0 ) :
   if ( prefix . is_binary ( ) ) :
    OOOOO000oo0 = prefix . addr_length ( ) * 2
    iIiIi1iI11iiI = lisp_hex_string ( prefix . address ) . zfill ( OOOOO000oo0 )
   else :
    iIiIi1iI11iiI = prefix . address
    if 36 - 36: IiII . OoOoOO00 . Ii1I
  elif ( prefix . afi == LISP_AFI_GEO_COORD ) :
   o0o0O00oOo = "8003"
   iIiIi1iI11iiI = prefix . address . print_geo ( )
  else :
   o0o0O00oOo = ""
   iIiIi1iI11iiI = ""
   if 31 - 31: iIii1I11I1II1
   if 84 - 84: I1ii11iIi11i - iII111i * I1IiiI
  Iiii11 = II1 + o0o0O00oOo + iIiIi1iI11iiI
  return ( [ IIiiiII , Iiii11 ] )
  if 88 - 88: OOooOOo / Oo0Ooo
  if 31 - 31: II111iiii
 def add_cache ( self , prefix , entry ) :
  if ( prefix . is_binary ( ) ) : prefix . zero_host_bits ( )
  IIiiiII , Iiii11 = self . build_key ( prefix )
  if ( self . cache . has_key ( IIiiiII ) == False ) :
   self . cache [ IIiiiII ] = lisp_cache_entries ( )
   self . cache [ IIiiiII ] . entries = { }
   self . cache [ IIiiiII ] . entries_sorted = [ ]
   self . cache_sorted = sorted ( self . cache )
   if 32 - 32: o0oOOo0O0Ooo % o0oOOo0O0Ooo
  if ( self . cache [ IIiiiII ] . entries . has_key ( Iiii11 ) == False ) :
   self . cache_count += 1
   if 67 - 67: IiII + oO0o * IiII
  self . cache [ IIiiiII ] . entries [ Iiii11 ] = entry
  self . cache [ IIiiiII ] . entries_sorted = sorted ( self . cache [ IIiiiII ] . entries )
  if 26 - 26: I1ii11iIi11i + i1IIi . i1IIi - oO0o + I1IiiI * o0oOOo0O0Ooo
  if 62 - 62: ooOoO0o + ooOoO0o % I11i
 def lookup_cache ( self , prefix , exact ) :
  oooI111iiiii1I , Iiii11 = self . build_key ( prefix )
  if ( exact ) :
   if ( self . cache . has_key ( oooI111iiiii1I ) == False ) : return ( None )
   if ( self . cache [ oooI111iiiii1I ] . entries . has_key ( Iiii11 ) == False ) : return ( None )
   return ( self . cache [ oooI111iiiii1I ] . entries [ Iiii11 ] )
   if 15 - 15: I1ii11iIi11i * iII111i + i11iIiiIii
   if 68 - 68: i1IIi / oO0o * I1ii11iIi11i - OoOoOO00 + Oo0Ooo / O0
  iIIi11Ii1iII = None
  for IIiiiII in self . cache_sorted :
   if ( oooI111iiiii1I < IIiiiII ) : return ( iIIi11Ii1iII )
   for i1II1111 in self . cache [ IIiiiII ] . entries_sorted :
    oO0 = self . cache [ IIiiiII ] . entries
    if ( i1II1111 in oO0 ) :
     iiIIIIiI111 = oO0 [ i1II1111 ]
     if ( iiIIIIiI111 == None ) : continue
     if ( prefix . is_more_specific ( iiIIIIiI111 . eid ) ) : iIIi11Ii1iII = iiIIIIiI111
     if 78 - 78: O0 . Ii1I - I1ii11iIi11i
     if 69 - 69: O0 % O0 . oO0o * OoooooooOO
     if 13 - 13: i1IIi % oO0o . OoooooooOO + I1ii11iIi11i - OOooOOo
  return ( iIIi11Ii1iII )
  if 99 - 99: OoooooooOO % OOooOOo / I11i
  if 77 - 77: II111iiii - IiII % OOooOOo
 def delete_cache ( self , prefix ) :
  IIiiiII , Iiii11 = self . build_key ( prefix )
  if ( self . cache . has_key ( IIiiiII ) == False ) : return
  if ( self . cache [ IIiiiII ] . entries . has_key ( Iiii11 ) == False ) : return
  self . cache [ IIiiiII ] . entries . pop ( Iiii11 )
  self . cache [ IIiiiII ] . entries_sorted . remove ( Iiii11 )
  self . cache_count -= 1
  if 22 - 22: OoooooooOO / oO0o
  if 78 - 78: oO0o * I11i . i1IIi % i1IIi + i1IIi / OOooOOo
 def walk_cache ( self , function , parms ) :
  for IIiiiII in self . cache_sorted :
   for Iiii11 in self . cache [ IIiiiII ] . entries_sorted :
    iiIIIIiI111 = self . cache [ IIiiiII ] . entries [ Iiii11 ]
    OooO000oo0o , parms = function ( iiIIIIiI111 , parms )
    if ( OooO000oo0o == False ) : return ( parms )
    if 50 - 50: OoO0O00 * O0 - IiII . o0oOOo0O0Ooo - iII111i
    if 18 - 18: II111iiii * OoooooooOO - Oo0Ooo . iII111i - Oo0Ooo
  return ( parms )
  if 82 - 82: I1Ii111 . OoOoOO00 - iIii1I11I1II1 - OoO0O00
  if 86 - 86: iIii1I11I1II1
 def print_cache ( self ) :
  lprint ( "Printing contents of {}: " . format ( self ) )
  if ( self . cache_size ( ) == 0 ) :
   lprint ( "  Cache is empty" )
   return
   if 54 - 54: II111iiii
  for IIiiiII in self . cache_sorted :
   for Iiii11 in self . cache [ IIiiiII ] . entries_sorted :
    iiIIIIiI111 = self . cache [ IIiiiII ] . entries [ Iiii11 ]
    lprint ( "  Mask-length: {}, key: {}, entry: {}" . format ( IIiiiII , Iiii11 ,
 iiIIIIiI111 ) )
    if 98 - 98: Oo0Ooo + IiII . Oo0Ooo / OoOoOO00 + O0
    if 99 - 99: Oo0Ooo
    if 42 - 42: I1IiiI + I1Ii111 - oO0o + o0oOOo0O0Ooo
    if 86 - 86: Ii1I - o0oOOo0O0Ooo % iII111i
    if 37 - 37: Oo0Ooo
    if 87 - 87: I1ii11iIi11i . OoooooooOO . ooOoO0o + iIii1I11I1II1 + O0 % I1ii11iIi11i
    if 53 - 53: IiII
    if 96 - 96: Oo0Ooo . i11iIiiIii / Ii1I . I1ii11iIi11i % I1Ii111
lisp_referral_cache = lisp_cache ( )
lisp_ddt_cache = lisp_cache ( )
lisp_sites_by_eid = lisp_cache ( )
lisp_map_cache = lisp_cache ( )
lisp_db_for_lookups = lisp_cache ( )
if 68 - 68: ooOoO0o
if 58 - 58: iII111i * I1IiiI
if 82 - 82: Oo0Ooo / OoO0O00 % Oo0Ooo . ooOoO0o * O0
if 39 - 39: I1Ii111 * IiII
if 16 - 16: ooOoO0o + OoO0O00 / I11i * OoO0O00 . Oo0Ooo % OoOoOO00
if 65 - 65: Oo0Ooo / I1Ii111 % II111iiii % Ii1I
if 70 - 70: II111iiii % Oo0Ooo * oO0o
def lisp_map_cache_lookup ( source , dest ) :
 if 54 - 54: O0 / ooOoO0o * I1Ii111
 O0OOo0OO0oOo = dest . is_multicast_address ( )
 if 5 - 5: Ii1I / OoOoOO00 - O0 * OoO0O00
 if 13 - 13: IiII + Oo0Ooo - I1Ii111
 if 10 - 10: OOooOOo % OoooooooOO / I1IiiI . II111iiii % iII111i
 if 47 - 47: o0oOOo0O0Ooo . i11iIiiIii * i1IIi % I11i - ooOoO0o * oO0o
 ooooOoo000O = lisp_map_cache . lookup_cache ( dest , False )
 if ( ooooOoo000O == None ) :
  oO00oo000O = source . print_sg ( dest ) if O0OOo0OO0oOo else dest . print_address ( )
  oO00oo000O = green ( oO00oo000O , False )
  dprint ( "Lookup for EID {} not found in map-cache" . format ( oO00oo000O ) )
  return ( None )
  if 95 - 95: oO0o / Ii1I + OoO0O00
  if 57 - 57: iIii1I11I1II1 + I1Ii111 % oO0o - Ii1I . I1IiiI
  if 39 - 39: OoO0O00 + II111iiii
  if 98 - 98: O0 - I1Ii111 % oO0o - iII111i + Ii1I * i1IIi
  if 76 - 76: o0oOOo0O0Ooo
 if ( O0OOo0OO0oOo == False ) :
  i1ii1I11iIII = green ( ooooOoo000O . eid . print_prefix ( ) , False )
  dprint ( "Lookup for EID {} found map-cache entry {}" . format ( green ( dest . print_address ( ) , False ) , i1ii1I11iIII ) )
  if 55 - 55: OOooOOo + I1ii11iIi11i * Oo0Ooo
  return ( ooooOoo000O )
  if 11 - 11: i1IIi - OoooooooOO * OoOoOO00 / oO0o - OoooooooOO - I1IiiI
  if 22 - 22: i11iIiiIii . Ii1I . Oo0Ooo * Oo0Ooo - iII111i / I1ii11iIi11i
  if 49 - 49: iII111i + I11i . Oo0Ooo
  if 23 - 23: I1IiiI . Ii1I + ooOoO0o . OoooooooOO
  if 57 - 57: OOooOOo / OoOoOO00 / i11iIiiIii - I11i - I11i . Ii1I
 ooooOoo000O = ooooOoo000O . lookup_source_cache ( source , False )
 if ( ooooOoo000O == None ) :
  oO00oo000O = source . print_sg ( dest )
  dprint ( "Lookup for EID {} not found in map-cache" . format ( oO00oo000O ) )
  return ( None )
  if 53 - 53: ooOoO0o . iII111i + Ii1I * I1Ii111
  if 49 - 49: II111iiii . I1ii11iIi11i * OoOoOO00 - OOooOOo
  if 48 - 48: OoO0O00 . iIii1I11I1II1 - OoooooooOO + I1Ii111 / i11iIiiIii . Oo0Ooo
  if 61 - 61: II111iiii + OOooOOo . o0oOOo0O0Ooo . iIii1I11I1II1
  if 63 - 63: I11i + i11iIiiIii . o0oOOo0O0Ooo . i1IIi + OoOoOO00
 i1ii1I11iIII = green ( ooooOoo000O . print_eid_tuple ( ) , False )
 dprint ( "Lookup for EID {} found map-cache entry {}" . format ( green ( source . print_sg ( dest ) , False ) , i1ii1I11iIII ) )
 if 1 - 1: i11iIiiIii
 return ( ooooOoo000O )
 if 1 - 1: iIii1I11I1II1
 if 73 - 73: iII111i + IiII
 if 95 - 95: O0
 if 75 - 75: ooOoO0o
 if 8 - 8: O0 - OoooooooOO + I1ii11iIi11i / Oo0Ooo . oO0o + I1Ii111
 if 85 - 85: ooOoO0o
 if 29 - 29: iII111i . Ii1I
def lisp_referral_cache_lookup ( eid , group , exact ) :
 if ( group and group . is_null ( ) ) :
  IiIIiIiI1II = lisp_referral_cache . lookup_cache ( eid , exact )
  return ( IiIIiIiI1II )
  if 43 - 43: I11i - I1ii11iIi11i + iIii1I11I1II1 / I1ii11iIi11i * oO0o / iIii1I11I1II1
  if 45 - 45: IiII
  if 49 - 49: I1IiiI . Ii1I * I1IiiI - OoooooooOO . I11i / I1Ii111
  if 9 - 9: iIii1I11I1II1 * Ii1I / O0 - OOooOOo
  if 95 - 95: i11iIiiIii * II111iiii * OOooOOo * iIii1I11I1II1
 if ( eid == None or eid . is_null ( ) ) : return ( None )
 if 22 - 22: iIii1I11I1II1 / I1IiiI + OoOoOO00 - OOooOOo . i11iIiiIii / i11iIiiIii
 if 10 - 10: iIii1I11I1II1 % i1IIi
 if 78 - 78: I11i + II111iiii % o0oOOo0O0Ooo
 if 17 - 17: i11iIiiIii + oO0o * iII111i . II111iiii
 if 44 - 44: I1ii11iIi11i
 if 39 - 39: iII111i + Oo0Ooo / oO0o
 IiIIiIiI1II = lisp_referral_cache . lookup_cache ( group , exact )
 if ( IiIIiIiI1II == None ) : return ( None )
 if 95 - 95: I1Ii111 * oO0o / ooOoO0o . Ii1I . OoOoOO00
 ooo0oOooOO0o0 = IiIIiIiI1II . lookup_source_cache ( eid , exact )
 if ( ooo0oOooOO0o0 ) : return ( ooo0oOooOO0o0 )
 if 91 - 91: II111iiii + I11i + i1IIi
 if ( exact ) : IiIIiIiI1II = None
 return ( IiIIiIiI1II )
 if 85 - 85: Ii1I * Ii1I . OoOoOO00 / Oo0Ooo
 if 97 - 97: oO0o % iIii1I11I1II1
 if 87 - 87: II111iiii % I1IiiI + oO0o - I11i / I11i
 if 16 - 16: I1IiiI
 if 39 - 39: ooOoO0o * II111iiii
 if 90 - 90: OoooooooOO * ooOoO0o
 if 14 - 14: I1IiiI % i1IIi
def lisp_ddt_cache_lookup ( eid , group , exact ) :
 if ( group . is_null ( ) ) :
  oO00oOo = lisp_ddt_cache . lookup_cache ( eid , exact )
  return ( oO00oOo )
  if 35 - 35: ooOoO0o % o0oOOo0O0Ooo % ooOoO0o
  if 77 - 77: OOooOOo % I1Ii111 / i11iIiiIii . i1IIi % OOooOOo
  if 55 - 55: i1IIi
  if 64 - 64: oO0o . OOooOOo * i11iIiiIii + I1Ii111
  if 88 - 88: O0
 if ( eid . is_null ( ) ) : return ( None )
 if 75 - 75: iII111i - Oo0Ooo / OoooooooOO - O0
 if 36 - 36: OoO0O00 % Ii1I . Oo0Ooo
 if 90 - 90: i11iIiiIii - iII111i * oO0o
 if 79 - 79: IiII
 if 38 - 38: I1Ii111
 if 56 - 56: i11iIiiIii
 oO00oOo = lisp_ddt_cache . lookup_cache ( group , exact )
 if ( oO00oOo == None ) : return ( None )
 if 58 - 58: i11iIiiIii / OoOoOO00
 IIIiIII1II = oO00oOo . lookup_source_cache ( eid , exact )
 if ( IIIiIII1II ) : return ( IIIiIII1II )
 if 20 - 20: Oo0Ooo
 if ( exact ) : oO00oOo = None
 return ( oO00oOo )
 if 45 - 45: iIii1I11I1II1 % O0 / I1IiiI . o0oOOo0O0Ooo * IiII
 if 87 - 87: II111iiii / OoooooooOO * II111iiii % i11iIiiIii - ooOoO0o + II111iiii
 if 39 - 39: I1Ii111
 if 51 - 51: o0oOOo0O0Ooo * I11i
 if 42 - 42: OOooOOo % I11i
 if 84 - 84: Oo0Ooo * OoOoOO00 / Ii1I / IiII / o0oOOo0O0Ooo . I1ii11iIi11i
 if 81 - 81: I1IiiI
def lisp_site_eid_lookup ( eid , group , exact ) :
 if 82 - 82: I1Ii111 - OoooooooOO - Ii1I
 if ( group . is_null ( ) ) :
  ooO00oO0O = lisp_sites_by_eid . lookup_cache ( eid , exact )
  return ( ooO00oO0O )
  if 34 - 34: OOooOOo . iIii1I11I1II1 / I1IiiI . Oo0Ooo - iIii1I11I1II1
  if 83 - 83: iII111i - I1ii11iIi11i + iII111i
  if 4 - 4: o0oOOo0O0Ooo % iIii1I11I1II1 + I11i
  if 60 - 60: I1ii11iIi11i / I1Ii111 % i11iIiiIii % oO0o % I1IiiI . Oo0Ooo
  if 20 - 20: IiII - OOooOOo + OoOoOO00
 if ( eid . is_null ( ) ) : return ( None )
 if 83 - 83: OoooooooOO / I1IiiI + iII111i - iIii1I11I1II1 % ooOoO0o
 if 74 - 74: OoO0O00
 if 13 - 13: I1ii11iIi11i / OoO0O00
 if 90 - 90: iIii1I11I1II1 - OoO0O00 . i1IIi / o0oOOo0O0Ooo + O0
 if 94 - 94: IiII * i1IIi
 if 90 - 90: O0 % I1IiiI . o0oOOo0O0Ooo % ooOoO0o % I1IiiI
 ooO00oO0O = lisp_sites_by_eid . lookup_cache ( group , exact )
 if ( ooO00oO0O == None ) : return ( None )
 if 16 - 16: OoO0O00 / OOooOOo / iIii1I11I1II1 / OoooooooOO . oO0o - I1Ii111
 if 43 - 43: OoOoOO00 % OOooOOo / I1IiiI + I1IiiI
 if 40 - 40: OOooOOo . I1Ii111 + I1Ii111
 if 4 - 4: iIii1I11I1II1 - iIii1I11I1II1 * I11i
 if 32 - 32: I1IiiI + II111iiii * iII111i + O0 / O0 * Oo0Ooo
 if 64 - 64: i11iIiiIii / iII111i + i11iIiiIii . I11i
 if 66 - 66: i1IIi
 if 98 - 98: Oo0Ooo / iIii1I11I1II1
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
 oOoO = ooO00oO0O . lookup_source_cache ( eid , exact )
 if ( oOoO ) : return ( oOoO )
 if 74 - 74: Ii1I
 if ( exact ) :
  ooO00oO0O = None
 else :
  OOooOo00Ooo = ooO00oO0O . parent_for_more_specifics
  if ( OOooOo00Ooo and OOooOo00Ooo . accept_more_specifics ) :
   if ( group . is_more_specific ( OOooOo00Ooo . group ) ) : ooO00oO0O = OOooOo00Ooo
   if 26 - 26: I11i . O0
   if 68 - 68: Ii1I
 return ( ooO00oO0O )
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
 if 34 - 34: i11iIiiIii / OoOoOO00
 if 100 - 100: o0oOOo0O0Ooo - I1IiiI / I11i
 if 43 - 43: o0oOOo0O0Ooo % iIii1I11I1II1
 if 85 - 85: oO0o + OoooooooOO - IiII % o0oOOo0O0Ooo * ooOoO0o * II111iiii
 if 4 - 4: Ii1I . i1IIi + Oo0Ooo % I11i . OoO0O00
 if 70 - 70: OOooOOo * OoOoOO00 / OoOoOO00 / OoOoOO00
 if 23 - 23: I1IiiI
 if 24 - 24: I1Ii111 * i1IIi % O0 * Ii1I + iII111i
 if 14 - 14: oO0o * iII111i + Ii1I + Ii1I * IiII
 if 82 - 82: IiII * ooOoO0o / OOooOOo + OoOoOO00
 if 32 - 32: IiII
 if 90 - 90: I1ii11iIi11i / I11i * o0oOOo0O0Ooo % O0 * i11iIiiIii
 if 68 - 68: I11i . Ii1I + I11i / IiII . I11i / iIii1I11I1II1
class lisp_address ( ) :
 def __init__ ( self , afi , addr_str , mask_len , iid ) :
  self . afi = afi
  self . mask_len = mask_len
  self . instance_id = iid
  self . iid_list = [ ]
  self . address = 0
  if ( addr_str != "" ) : self . store_address ( addr_str )
  if 96 - 96: O0
  if 2 - 2: OoO0O00 / iII111i + o0oOOo0O0Ooo
 def copy_address ( self , addr ) :
  if ( addr == None ) : return
  self . afi = addr . afi
  self . address = addr . address
  self . mask_len = addr . mask_len
  self . instance_id = addr . instance_id
  self . iid_list = addr . iid_list
  if 27 - 27: I11i - OoOoOO00 - ooOoO0o - I1IiiI
  if 51 - 51: I11i + I11i + O0 + O0 * I1Ii111
 def make_default_route ( self , addr ) :
  self . afi = addr . afi
  self . instance_id = addr . instance_id
  self . mask_len = 0
  self . address = 0
  if 61 - 61: IiII . O0
  if 38 - 38: Ii1I * I1ii11iIi11i - i11iIiiIii + ooOoO0o * I11i
 def make_default_multicast_route ( self , addr ) :
  self . afi = addr . afi
  self . instance_id = addr . instance_id
  if ( self . afi == LISP_AFI_IPV4 ) :
   self . address = 0xe0000000
   self . mask_len = 4
   if 74 - 74: OoOoOO00 . o0oOOo0O0Ooo
  if ( self . afi == LISP_AFI_IPV6 ) :
   self . address = 0xff << 120
   self . mask_len = 8
   if 40 - 40: ooOoO0o + I1ii11iIi11i * i11iIiiIii / i1IIi
  if ( self . afi == LISP_AFI_MAC ) :
   self . address = 0xffffffffffff
   self . mask_len = 48
   if 95 - 95: oO0o / IiII * II111iiii * Ii1I . OoO0O00 . OoO0O00
   if 85 - 85: I1IiiI / II111iiii * OoO0O00 + ooOoO0o / OoO0O00 % OOooOOo
   if 100 - 100: I1Ii111 % OoooooooOO % OoOoOO00 % I1IiiI
 def not_set ( self ) :
  return ( self . afi == LISP_AFI_NONE )
  if 32 - 32: OoO0O00 + OOooOOo . OoO0O00 - Oo0Ooo
  if 12 - 12: I1IiiI * OoO0O00 - II111iiii . i1IIi
 def is_private_address ( self ) :
  if ( self . is_ipv4 ( ) == False ) : return ( False )
  iIiIi1iI11iiI = self . address
  if ( ( ( iIiIi1iI11iiI & 0xff000000 ) >> 24 ) == 10 ) : return ( True )
  if ( ( ( iIiIi1iI11iiI & 0xff000000 ) >> 24 ) == 172 ) :
   oOOo = ( iIiIi1iI11iiI & 0x00ff0000 ) >> 16
   if ( oOOo >= 16 and oOOo <= 31 ) : return ( True )
   if 88 - 88: I1ii11iIi11i * IiII - I1Ii111 / OoooooooOO
  if ( ( ( iIiIi1iI11iiI & 0xffff0000 ) >> 16 ) == 0xc0a8 ) : return ( True )
  return ( False )
  if 99 - 99: o0oOOo0O0Ooo
  if 34 - 34: ooOoO0o / OoooooooOO . OOooOOo . OoO0O00 . IiII / Ii1I
 def is_multicast_address ( self ) :
  if ( self . is_ipv4 ( ) ) : return ( self . is_ipv4_multicast ( ) )
  if ( self . is_ipv6 ( ) ) : return ( self . is_ipv6_multicast ( ) )
  if ( self . is_mac ( ) ) : return ( self . is_mac_multicast ( ) )
  return ( False )
  if 73 - 73: iII111i / iIii1I11I1II1
  if 7 - 7: iII111i + OoOoOO00 - OoooooooOO % OoOoOO00 . oO0o * I1Ii111
 def host_mask_len ( self ) :
  if ( self . afi == LISP_AFI_IPV4 ) : return ( LISP_IPV4_HOST_MASK_LEN )
  if ( self . afi == LISP_AFI_IPV6 ) : return ( LISP_IPV6_HOST_MASK_LEN )
  if ( self . afi == LISP_AFI_MAC ) : return ( LISP_MAC_HOST_MASK_LEN )
  if ( self . afi == LISP_AFI_E164 ) : return ( LISP_E164_HOST_MASK_LEN )
  if ( self . afi == LISP_AFI_NAME ) : return ( len ( self . address ) * 8 )
  if ( self . afi == LISP_AFI_GEO_COORD ) :
   return ( len ( self . address . print_geo ( ) ) * 8 )
   if 82 - 82: iIii1I11I1II1 / oO0o * iII111i . OoOoOO00 + II111iiii
  return ( 0 )
  if 77 - 77: I1IiiI
  if 9 - 9: i11iIiiIii + OOooOOo * OoO0O00
 def is_iana_eid ( self ) :
  if ( self . is_ipv6 ( ) == False ) : return ( False )
  iIiIi1iI11iiI = self . address >> 96
  return ( iIiIi1iI11iiI == 0x20010005 )
  if 9 - 9: OOooOOo
  if 67 - 67: Oo0Ooo / I1Ii111 . ooOoO0o % oO0o / Oo0Ooo
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
   if 49 - 49: ooOoO0o + I1IiiI
  return ( 0 )
  if 70 - 70: o0oOOo0O0Ooo + Ii1I . OoO0O00 * Ii1I + OOooOOo + ooOoO0o
  if 13 - 13: I1ii11iIi11i
 def afi_to_version ( self ) :
  if ( self . afi == LISP_AFI_IPV4 ) : return ( 4 )
  if ( self . afi == LISP_AFI_IPV6 ) : return ( 6 )
  return ( 0 )
  if 97 - 97: oO0o - Oo0Ooo . i11iIiiIii % ooOoO0o * i11iIiiIii - OoooooooOO
  if 44 - 44: I11i % OoooooooOO / iII111i - i11iIiiIii * i1IIi * o0oOOo0O0Ooo
 def packet_format ( self ) :
  if 51 - 51: Ii1I + IiII / I1ii11iIi11i + O0 % Ii1I
  if 55 - 55: iII111i % o0oOOo0O0Ooo - oO0o % OoooooooOO
  if 18 - 18: OoooooooOO - I1ii11iIi11i
  if 94 - 94: OOooOOo . Oo0Ooo + Ii1I * o0oOOo0O0Ooo
  if 79 - 79: OOooOOo + Oo0Ooo
  if ( self . afi == LISP_AFI_IPV4 ) : return ( "I" )
  if ( self . afi == LISP_AFI_IPV6 ) : return ( "QQ" )
  if ( self . afi == LISP_AFI_MAC ) : return ( "HHH" )
  if ( self . afi == LISP_AFI_E164 ) : return ( "II" )
  if ( self . afi == LISP_AFI_LCAF ) : return ( "I" )
  return ( "" )
  if 33 - 33: iIii1I11I1II1
  if 75 - 75: I1Ii111 / iIii1I11I1II1 . OoooooooOO
 def pack_address ( self ) :
  IIiI1I11ii1i = self . packet_format ( )
  oOo = ""
  if ( self . is_ipv4 ( ) ) :
   oOo = struct . pack ( IIiI1I11ii1i , socket . htonl ( self . address ) )
  elif ( self . is_ipv6 ( ) ) :
   OOoO0oO00o = byte_swap_64 ( self . address >> 64 )
   OOO0OoO0oo0OO = byte_swap_64 ( self . address & 0xffffffffffffffff )
   oOo = struct . pack ( IIiI1I11ii1i , OOoO0oO00o , OOO0OoO0oo0OO )
  elif ( self . is_mac ( ) ) :
   iIiIi1iI11iiI = self . address
   OOoO0oO00o = ( iIiIi1iI11iiI >> 32 ) & 0xffff
   OOO0OoO0oo0OO = ( iIiIi1iI11iiI >> 16 ) & 0xffff
   ooOoo = iIiIi1iI11iiI & 0xffff
   oOo = struct . pack ( IIiI1I11ii1i , OOoO0oO00o , OOO0OoO0oo0OO , ooOoo )
  elif ( self . is_e164 ( ) ) :
   iIiIi1iI11iiI = self . address
   OOoO0oO00o = ( iIiIi1iI11iiI >> 32 ) & 0xffffffff
   OOO0OoO0oo0OO = ( iIiIi1iI11iiI & 0xffffffff )
   oOo = struct . pack ( IIiI1I11ii1i , OOoO0oO00o , OOO0OoO0oo0OO )
  elif ( self . is_dist_name ( ) ) :
   oOo += self . address + "\0"
   if 80 - 80: II111iiii . Oo0Ooo * oO0o % II111iiii / I1ii11iIi11i
  return ( oOo )
  if 66 - 66: iII111i / OoO0O00 / i11iIiiIii
  if 99 - 99: OOooOOo
 def unpack_address ( self , packet ) :
  IIiI1I11ii1i = self . packet_format ( )
  i1II1i1iiI1 = struct . calcsize ( IIiI1I11ii1i )
  if ( len ( packet ) < i1II1i1iiI1 ) : return ( None )
  if 51 - 51: i11iIiiIii . o0oOOo0O0Ooo / iII111i
  iIiIi1iI11iiI = struct . unpack ( IIiI1I11ii1i , packet [ : i1II1i1iiI1 ] )
  if 53 - 53: oO0o / i1IIi - Oo0Ooo - i1IIi + IiII
  if ( self . is_ipv4 ( ) ) :
   self . address = socket . ntohl ( iIiIi1iI11iiI [ 0 ] )
   if 79 - 79: oO0o % o0oOOo0O0Ooo / o0oOOo0O0Ooo % iII111i
  elif ( self . is_ipv6 ( ) ) :
   if 56 - 56: Oo0Ooo % I1ii11iIi11i
   if 53 - 53: OoO0O00 . I11i - ooOoO0o
   if 11 - 11: I11i + i11iIiiIii / oO0o % oO0o * o0oOOo0O0Ooo / OoOoOO00
   if 74 - 74: oO0o . I1Ii111 . II111iiii
   if 92 - 92: I1Ii111 % OoooooooOO * I1Ii111
   if 78 - 78: Oo0Ooo . I11i . oO0o + O0 / O0
   if 41 - 41: iII111i * OoO0O00 - OoO0O00
   if 72 - 72: o0oOOo0O0Ooo + oO0o . I1ii11iIi11i + OoO0O00 / I1Ii111
   if ( iIiIi1iI11iiI [ 0 ] <= 0xffff and ( iIiIi1iI11iiI [ 0 ] & 0xff ) == 0 ) :
    OO0o = ( iIiIi1iI11iiI [ 0 ] << 48 ) << 64
   else :
    OO0o = byte_swap_64 ( iIiIi1iI11iiI [ 0 ] ) << 64
    if 67 - 67: II111iiii
   ii11 = byte_swap_64 ( iIiIi1iI11iiI [ 1 ] )
   self . address = OO0o | ii11
   if 50 - 50: o0oOOo0O0Ooo . iIii1I11I1II1 % o0oOOo0O0Ooo
  elif ( self . is_mac ( ) ) :
   iIii = iIiIi1iI11iiI [ 0 ]
   iIiII = iIiIi1iI11iiI [ 1 ]
   iiii111I1I = iIiIi1iI11iiI [ 2 ]
   self . address = ( iIii << 32 ) + ( iIiII << 16 ) + iiii111I1I
   if 78 - 78: oO0o . o0oOOo0O0Ooo - OOooOOo + OoooooooOO % OOooOOo
  elif ( self . is_e164 ( ) ) :
   self . address = ( iIiIi1iI11iiI [ 0 ] << 32 ) + iIiIi1iI11iiI [ 1 ]
   if 27 - 27: OOooOOo * O0 * i11iIiiIii / OoOoOO00 - i1IIi
  elif ( self . is_dist_name ( ) ) :
   packet , self . address = lisp_decode_dist_name ( packet )
   self . mask_len = len ( self . address ) * 8
   i1II1i1iiI1 = 0
   if 73 - 73: iII111i / I1IiiI * ooOoO0o
  packet = packet [ i1II1i1iiI1 : : ]
  return ( packet )
  if 85 - 85: I11i + I11i + oO0o - OoOoOO00
  if 15 - 15: OoO0O00
 def is_ipv4 ( self ) :
  return ( True if ( self . afi == LISP_AFI_IPV4 ) else False )
  if 88 - 88: Ii1I % i1IIi / I1Ii111
  if 2 - 2: Ii1I . IiII % OoOoOO00
 def is_ipv4_link_local ( self ) :
  if ( self . is_ipv4 ( ) == False ) : return ( False )
  return ( ( ( self . address >> 16 ) & 0xffff ) == 0xa9fe )
  if 42 - 42: OoOoOO00 * OoO0O00 * IiII - IiII % Oo0Ooo . IiII
  if 38 - 38: I1Ii111 . IiII - ooOoO0o . i11iIiiIii
 def is_ipv4_loopback ( self ) :
  if ( self . is_ipv4 ( ) == False ) : return ( False )
  return ( self . address == 0x7f000001 )
  if 35 - 35: i11iIiiIii
  if 62 - 62: O0 - o0oOOo0O0Ooo + I1Ii111 * I1ii11iIi11i / OOooOOo
 def is_ipv4_multicast ( self ) :
  if ( self . is_ipv4 ( ) == False ) : return ( False )
  return ( ( ( self . address >> 24 ) & 0xf0 ) == 0xe0 )
  if 87 - 87: Oo0Ooo / OoooooooOO + O0 / o0oOOo0O0Ooo % II111iiii - O0
  if 63 - 63: OOooOOo - OoO0O00 * i1IIi - I1ii11iIi11i . I1IiiI
 def is_ipv4_string ( self , addr_str ) :
  return ( addr_str . find ( "." ) != - 1 )
  if 59 - 59: i11iIiiIii . OOooOOo % Oo0Ooo + O0
  if 84 - 84: I1Ii111 / O0 - IiII . I11i / o0oOOo0O0Ooo
 def is_ipv6 ( self ) :
  return ( True if ( self . afi == LISP_AFI_IPV6 ) else False )
  if 12 - 12: i11iIiiIii / Ii1I + i1IIi
  if 54 - 54: I1IiiI
 def is_ipv6_link_local ( self ) :
  if ( self . is_ipv6 ( ) == False ) : return ( False )
  return ( ( ( self . address >> 112 ) & 0xffff ) == 0xfe80 )
  if 55 - 55: I1ii11iIi11i % IiII % o0oOOo0O0Ooo + i1IIi * OoooooooOO % II111iiii
  if 37 - 37: Oo0Ooo
 def is_ipv6_string_link_local ( self , addr_str ) :
  return ( addr_str . find ( "fe80::" ) != - 1 )
  if 33 - 33: OoooooooOO - O0 . O0 - o0oOOo0O0Ooo % o0oOOo0O0Ooo % OoO0O00
  if 27 - 27: ooOoO0o . i11iIiiIii / o0oOOo0O0Ooo * OoO0O00 * OoOoOO00 * oO0o
 def is_ipv6_loopback ( self ) :
  if ( self . is_ipv6 ( ) == False ) : return ( False )
  return ( self . address == 1 )
  if 19 - 19: O0 * II111iiii * OoOoOO00
  if 53 - 53: Oo0Ooo
 def is_ipv6_multicast ( self ) :
  if ( self . is_ipv6 ( ) == False ) : return ( False )
  return ( ( ( self . address >> 120 ) & 0xff ) == 0xff )
  if 16 - 16: Ii1I
  if 73 - 73: i11iIiiIii + I1IiiI - IiII - IiII + IiII . Ii1I
 def is_ipv6_string ( self , addr_str ) :
  return ( addr_str . find ( ":" ) != - 1 )
  if 78 - 78: OoO0O00 + oO0o
  if 86 - 86: ooOoO0o . ooOoO0o + oO0o
 def is_mac ( self ) :
  return ( True if ( self . afi == LISP_AFI_MAC ) else False )
  if 84 - 84: OOooOOo - OoOoOO00 + i1IIi * I1ii11iIi11i % I1ii11iIi11i * I1Ii111
  if 31 - 31: IiII + iII111i
 def is_mac_multicast ( self ) :
  if ( self . is_mac ( ) == False ) : return ( False )
  return ( ( self . address & 0x010000000000 ) != 0 )
  if 5 - 5: O0 * Ii1I
  if 78 - 78: iII111i * iIii1I11I1II1 . OoO0O00 . OoOoOO00 % I1Ii111
 def is_mac_broadcast ( self ) :
  if ( self . is_mac ( ) == False ) : return ( False )
  return ( self . address == 0xffffffffffff )
  if 77 - 77: OOooOOo / OoooooooOO
  if 11 - 11: iIii1I11I1II1 - Ii1I - OoOoOO00 . oO0o / I1ii11iIi11i
 def is_mac_string ( self , addr_str ) :
  return ( len ( addr_str ) == 15 and addr_str . find ( "-" ) != - 1 )
  if 79 - 79: i11iIiiIii % o0oOOo0O0Ooo * II111iiii . i1IIi * Ii1I - i11iIiiIii
  if 31 - 31: IiII / o0oOOo0O0Ooo
 def is_link_local_multicast ( self ) :
  if ( self . is_ipv4 ( ) ) :
   return ( ( 0xe0ffff00 & self . address ) == 0xe0000000 )
   if 27 - 27: Oo0Ooo
  if ( self . is_ipv6 ( ) ) :
   return ( ( self . address >> 112 ) & 0xffff == 0xff02 )
   if 32 - 32: Oo0Ooo * i11iIiiIii % I1IiiI - i11iIiiIii - I1Ii111 % I1ii11iIi11i
  return ( False )
  if 35 - 35: o0oOOo0O0Ooo % iII111i / O0 * I1IiiI . o0oOOo0O0Ooo / OOooOOo
  if 81 - 81: I1ii11iIi11i - i11iIiiIii
 def is_null ( self ) :
  return ( True if ( self . afi == LISP_AFI_NONE ) else False )
  if 49 - 49: iII111i * I11i - II111iiii . o0oOOo0O0Ooo
  if 52 - 52: Ii1I + Ii1I - II111iiii . O0 + I1ii11iIi11i
 def is_ultimate_root ( self ) :
  return ( True if self . afi == LISP_AFI_ULTIMATE_ROOT else False )
  if 60 - 60: i11iIiiIii + IiII
  if 41 - 41: I1Ii111 * o0oOOo0O0Ooo + Oo0Ooo
 def is_iid_range ( self ) :
  return ( True if self . afi == LISP_AFI_IID_RANGE else False )
  if 86 - 86: Ii1I / oO0o
  if 40 - 40: OoO0O00 % oO0o + Oo0Ooo
 def is_e164 ( self ) :
  return ( True if ( self . afi == LISP_AFI_E164 ) else False )
  if 60 - 60: II111iiii / Ii1I
  if 14 - 14: iII111i - Oo0Ooo / o0oOOo0O0Ooo * oO0o / Oo0Ooo - I1IiiI
 def is_dist_name ( self ) :
  return ( True if ( self . afi == LISP_AFI_NAME ) else False )
  if 89 - 89: i1IIi / I1Ii111 + Ii1I - i1IIi
  if 66 - 66: OoooooooOO
 def is_geo_prefix ( self ) :
  return ( True if ( self . afi == LISP_AFI_GEO_COORD ) else False )
  if 68 - 68: iII111i + I1Ii111
  if 90 - 90: o0oOOo0O0Ooo
 def is_binary ( self ) :
  if ( self . is_dist_name ( ) ) : return ( False )
  if ( self . is_geo_prefix ( ) ) : return ( False )
  return ( True )
  if 48 - 48: iII111i + Ii1I
  if 45 - 45: oO0o / iIii1I11I1II1 % O0 % IiII % I1ii11iIi11i
 def store_address ( self , addr_str ) :
  if ( self . afi == LISP_AFI_NONE ) : self . string_to_afi ( addr_str )
  if 89 - 89: OOooOOo - I1Ii111 - iII111i
  if 67 - 67: oO0o
  if 76 - 76: I1IiiI % I1IiiI - IiII / OoOoOO00 / I1ii11iIi11i
  if 42 - 42: I1IiiI + I1ii11iIi11i + Oo0Ooo * i1IIi - II111iiii
  II11iIII1i1I = addr_str . find ( "[" )
  o0000o0O0ooo = addr_str . find ( "]" )
  if ( II11iIII1i1I != - 1 and o0000o0O0ooo != - 1 ) :
   self . instance_id = int ( addr_str [ II11iIII1i1I + 1 : o0000o0O0ooo ] )
   addr_str = addr_str [ o0000o0O0ooo + 1 : : ]
   if ( self . is_dist_name ( ) == False ) :
    addr_str = addr_str . replace ( " " , "" )
    if 15 - 15: o0oOOo0O0Ooo
    if 60 - 60: I1ii11iIi11i / I1Ii111
    if 13 - 13: I1Ii111
    if 52 - 52: II111iiii / OoO0O00 . Ii1I
    if 68 - 68: iII111i
    if 67 - 67: I1IiiI * I1IiiI
  if ( self . is_ipv4 ( ) ) :
   o0o0OoO0O00OO = addr_str . split ( "." )
   ooOo0O0O0oOO0 = int ( o0o0OoO0O00OO [ 0 ] ) << 24
   ooOo0O0O0oOO0 += int ( o0o0OoO0O00OO [ 1 ] ) << 16
   ooOo0O0O0oOO0 += int ( o0o0OoO0O00OO [ 2 ] ) << 8
   ooOo0O0O0oOO0 += int ( o0o0OoO0O00OO [ 3 ] )
   self . address = ooOo0O0O0oOO0
  elif ( self . is_ipv6 ( ) ) :
   if 19 - 19: II111iiii * O0 % II111iiii
   if 63 - 63: i11iIiiIii . Oo0Ooo . OOooOOo - II111iiii
   if 35 - 35: II111iiii + IiII
   if 66 - 66: o0oOOo0O0Ooo % IiII
   if 39 - 39: IiII
   if 18 - 18: iII111i % o0oOOo0O0Ooo - i1IIi
   if 53 - 53: o0oOOo0O0Ooo + IiII - ooOoO0o % i11iIiiIii - i11iIiiIii - I1Ii111
   if 79 - 79: II111iiii + i11iIiiIii . OOooOOo . I11i / iIii1I11I1II1
   if 62 - 62: O0
   if 52 - 52: OoooooooOO . oO0o
   if 38 - 38: ooOoO0o . i1IIi / iII111i + I1IiiI - II111iiii
   if 21 - 21: i11iIiiIii + II111iiii - i1IIi / OoooooooOO * OOooOOo % Oo0Ooo
   if 59 - 59: Ii1I
   if 77 - 77: I1ii11iIi11i * Ii1I * O0 * I1IiiI % OoO0O00 - iIii1I11I1II1
   if 6 - 6: i11iIiiIii . I11i - OoooooooOO
   if 26 - 26: I1IiiI
   if 26 - 26: IiII . Ii1I / IiII - OoO0O00 % OoO0O00
   OoOo0Ooo0Oooo = ( addr_str [ 2 : 4 ] == "::" )
   try :
    addr_str = socket . inet_pton ( socket . AF_INET6 , addr_str )
   except :
    addr_str = socket . inet_pton ( socket . AF_INET6 , "0::0" )
    if 37 - 37: OoooooooOO * I1IiiI - I1ii11iIi11i
   addr_str = binascii . hexlify ( addr_str )
   if 37 - 37: OoooooooOO - OoOoOO00 . I1IiiI * oO0o - Oo0Ooo + I1IiiI
   if ( OoOo0Ooo0Oooo ) :
    addr_str = addr_str [ 2 : 4 ] + addr_str [ 0 : 2 ] + addr_str [ 4 : : ]
    if 17 - 17: OOooOOo % I1IiiI - o0oOOo0O0Ooo + OoO0O00 + OoOoOO00 + i1IIi
   self . address = int ( addr_str , 16 )
   if 74 - 74: iIii1I11I1II1
  elif ( self . is_geo_prefix ( ) ) :
   O0OOoo = lisp_geo ( None )
   O0OOoo . name = "geo-prefix-{}" . format ( O0OOoo )
   O0OOoo . parse_geo_string ( addr_str )
   self . address = O0OOoo
  elif ( self . is_mac ( ) ) :
   addr_str = addr_str . replace ( "-" , "" )
   ooOo0O0O0oOO0 = int ( addr_str , 16 )
   self . address = ooOo0O0O0oOO0
  elif ( self . is_e164 ( ) ) :
   addr_str = addr_str [ 1 : : ]
   ooOo0O0O0oOO0 = int ( addr_str , 16 )
   self . address = ooOo0O0O0oOO0 << 4
  elif ( self . is_dist_name ( ) ) :
   self . address = addr_str . replace ( "'" , "" )
   if 8 - 8: OOooOOo % o0oOOo0O0Ooo
  self . mask_len = self . host_mask_len ( )
  if 36 - 36: Ii1I % OoooooooOO
  if 31 - 31: Ii1I / Ii1I / Ii1I / o0oOOo0O0Ooo / I11i
 def store_prefix ( self , prefix_str ) :
  if ( self . is_geo_string ( prefix_str ) ) :
   oo0OOo0O = prefix_str . find ( "]" )
   Ooo = len ( prefix_str [ oo0OOo0O + 1 : : ] ) * 8
  elif ( prefix_str . find ( "/" ) != - 1 ) :
   prefix_str , Ooo = prefix_str . split ( "/" )
  else :
   i1II1I = prefix_str . find ( "'" )
   if ( i1II1I == - 1 ) : return
   iiiI111I = prefix_str . find ( "'" , i1II1I + 1 )
   if ( iiiI111I == - 1 ) : return
   Ooo = len ( prefix_str [ i1II1I + 1 : iiiI111I ] ) * 8
   if 24 - 24: i1IIi - Oo0Ooo % Oo0Ooo
   if 29 - 29: IiII
  self . string_to_afi ( prefix_str )
  self . store_address ( prefix_str )
  self . mask_len = int ( Ooo )
  if 94 - 94: I1IiiI * Oo0Ooo * OOooOOo + Oo0Ooo / I1Ii111
  if 3 - 3: I11i * iII111i - OoooooooOO % OoOoOO00 % ooOoO0o
 def zero_host_bits ( self ) :
  if ( self . mask_len < 0 ) : return
  iii1iiiiiiI1 = ( 2 ** self . mask_len ) - 1
  iIiiI1i11Ii = self . addr_length ( ) * 8 - self . mask_len
  iii1iiiiiiI1 <<= iIiiI1i11Ii
  self . address &= iii1iiiiiiI1
  if 14 - 14: iIii1I11I1II1 % i1IIi / I1IiiI + I1IiiI . iII111i
  if 40 - 40: I1ii11iIi11i + Ii1I % OOooOOo * oO0o
 def is_geo_string ( self , addr_str ) :
  oo0OOo0O = addr_str . find ( "]" )
  if ( oo0OOo0O != - 1 ) : addr_str = addr_str [ oo0OOo0O + 1 : : ]
  if 77 - 77: OoooooooOO
  O0OOoo = addr_str . split ( "/" )
  if ( len ( O0OOoo ) == 2 ) :
   if ( O0OOoo [ 1 ] . isdigit ( ) == False ) : return ( False )
   if 54 - 54: I11i * Oo0Ooo
  O0OOoo = O0OOoo [ 0 ]
  O0OOoo = O0OOoo . split ( "-" )
  I1i11I = len ( O0OOoo )
  if ( I1i11I < 8 or I1i11I > 9 ) : return ( False )
  if 19 - 19: IiII
  for ii1iiII in range ( 0 , I1i11I ) :
   if ( ii1iiII == 3 ) :
    if ( O0OOoo [ ii1iiII ] in [ "N" , "S" ] ) : continue
    return ( False )
    if 99 - 99: oO0o + Oo0Ooo . IiII * I1IiiI
   if ( ii1iiII == 7 ) :
    if ( O0OOoo [ ii1iiII ] in [ "W" , "E" ] ) : continue
    return ( False )
    if 29 - 29: i11iIiiIii - oO0o - oO0o + I11i . OOooOOo . OoO0O00
   if ( O0OOoo [ ii1iiII ] . isdigit ( ) == False ) : return ( False )
   if 94 - 94: oO0o - o0oOOo0O0Ooo / I1ii11iIi11i . IiII - II111iiii - ooOoO0o
  return ( True )
  if 92 - 92: OoooooooOO + O0 * OOooOOo
  if 1 - 1: O0
 def string_to_afi ( self , addr_str ) :
  if ( addr_str . count ( "'" ) == 2 ) :
   self . afi = LISP_AFI_NAME
   return
   if 34 - 34: o0oOOo0O0Ooo * i1IIi + I1Ii111
  if ( addr_str . find ( ":" ) != - 1 ) : self . afi = LISP_AFI_IPV6
  elif ( addr_str . find ( "." ) != - 1 ) : self . afi = LISP_AFI_IPV4
  elif ( addr_str . find ( "+" ) != - 1 ) : self . afi = LISP_AFI_E164
  elif ( self . is_geo_string ( addr_str ) ) : self . afi = LISP_AFI_GEO_COORD
  elif ( addr_str . find ( "-" ) != - 1 ) : self . afi = LISP_AFI_MAC
  else : self . afi = LISP_AFI_NONE
  if 46 - 46: IiII / i11iIiiIii
  if 51 - 51: OoO0O00 - OoO0O00 + o0oOOo0O0Ooo * iII111i % II111iiii
 def print_address ( self ) :
  iIiIi1iI11iiI = self . print_address_no_iid ( )
  II1 = "[" + str ( self . instance_id )
  for II11iIII1i1I in self . iid_list : II1 += "," + str ( II11iIII1i1I )
  II1 += "]"
  iIiIi1iI11iiI = "{}{}" . format ( II1 , iIiIi1iI11iiI )
  return ( iIiIi1iI11iiI )
  if 7 - 7: O0 * OoO0O00 % IiII
  if 76 - 76: iII111i - i1IIi
 def print_address_no_iid ( self ) :
  if ( self . is_ipv4 ( ) ) :
   iIiIi1iI11iiI = self . address
   o00oOO = iIiIi1iI11iiI >> 24
   iiIi = ( iIiIi1iI11iiI >> 16 ) & 0xff
   iI11III1 = ( iIiIi1iI11iiI >> 8 ) & 0xff
   oooO0 = iIiIi1iI11iiI & 0xff
   return ( "{}.{}.{}.{}" . format ( o00oOO , iiIi , iI11III1 , oooO0 ) )
  elif ( self . is_ipv6 ( ) ) :
   ooOOo0o = lisp_hex_string ( self . address ) . zfill ( 32 )
   ooOOo0o = binascii . unhexlify ( ooOOo0o )
   ooOOo0o = socket . inet_ntop ( socket . AF_INET6 , ooOOo0o )
   return ( "{}" . format ( ooOOo0o ) )
  elif ( self . is_geo_prefix ( ) ) :
   return ( "{}" . format ( self . address . print_geo ( ) ) )
  elif ( self . is_mac ( ) ) :
   ooOOo0o = lisp_hex_string ( self . address ) . zfill ( 12 )
   ooOOo0o = "{}-{}-{}" . format ( ooOOo0o [ 0 : 4 ] , ooOOo0o [ 4 : 8 ] ,
 ooOOo0o [ 8 : 12 ] )
   return ( "{}" . format ( ooOOo0o ) )
  elif ( self . is_e164 ( ) ) :
   ooOOo0o = lisp_hex_string ( self . address ) . zfill ( 15 )
   return ( "+{}" . format ( ooOOo0o ) )
  elif ( self . is_dist_name ( ) ) :
   return ( "'{}'" . format ( self . address ) )
  elif ( self . is_null ( ) ) :
   return ( "no-address" )
   if 17 - 17: I1IiiI
  return ( "unknown-afi:{}" . format ( self . afi ) )
  if 87 - 87: OoO0O00 + Ii1I - IiII % i11iIiiIii . OOooOOo / IiII
  if 73 - 73: iIii1I11I1II1 - ooOoO0o . II111iiii % O0 + I1IiiI
 def print_prefix ( self ) :
  if ( self . is_ultimate_root ( ) ) : return ( "[*]" )
  if ( self . is_iid_range ( ) ) :
   if ( self . mask_len == 32 ) : return ( "[{}]" . format ( self . instance_id ) )
   OOooOOoOoo = self . instance_id + ( 2 ** ( 32 - self . mask_len ) - 1 )
   return ( "[{}-{}]" . format ( self . instance_id , OOooOOoOoo ) )
   if 81 - 81: OOooOOo . OOooOOo
  iIiIi1iI11iiI = self . print_address ( )
  if ( self . is_dist_name ( ) ) : return ( iIiIi1iI11iiI )
  if ( self . is_geo_prefix ( ) ) : return ( iIiIi1iI11iiI )
  if 70 - 70: I1IiiI / I11i - II111iiii . o0oOOo0O0Ooo / O0
  oo0OOo0O = iIiIi1iI11iiI . find ( "no-address" )
  if ( oo0OOo0O == - 1 ) :
   iIiIi1iI11iiI = "{}/{}" . format ( iIiIi1iI11iiI , str ( self . mask_len ) )
  else :
   iIiIi1iI11iiI = iIiIi1iI11iiI [ 0 : oo0OOo0O ]
   if 29 - 29: OOooOOo . OOooOOo * iII111i % OoO0O00
  return ( iIiIi1iI11iiI )
  if 66 - 66: Ii1I / OoO0O00 * i11iIiiIii * oO0o . iIii1I11I1II1
  if 16 - 16: Oo0Ooo % IiII * o0oOOo0O0Ooo % OoOoOO00 - OoooooooOO
 def print_prefix_no_iid ( self ) :
  iIiIi1iI11iiI = self . print_address_no_iid ( )
  if ( self . is_dist_name ( ) ) : return ( iIiIi1iI11iiI )
  if ( self . is_geo_prefix ( ) ) : return ( iIiIi1iI11iiI )
  return ( "{}/{}" . format ( iIiIi1iI11iiI , str ( self . mask_len ) ) )
  if 61 - 61: i11iIiiIii - i1IIi + iIii1I11I1II1 * I1IiiI % OoOoOO00 . oO0o
  if 24 - 24: iII111i . i1IIi * I1ii11iIi11i
 def print_prefix_url ( self ) :
  if ( self . is_ultimate_root ( ) ) : return ( "0--0" )
  iIiIi1iI11iiI = self . print_address ( )
  oo0OOo0O = iIiIi1iI11iiI . find ( "]" )
  if ( oo0OOo0O != - 1 ) : iIiIi1iI11iiI = iIiIi1iI11iiI [ oo0OOo0O + 1 : : ]
  if ( self . is_geo_prefix ( ) ) :
   iIiIi1iI11iiI = iIiIi1iI11iiI . replace ( "/" , "-" )
   return ( "{}-{}" . format ( self . instance_id , iIiIi1iI11iiI ) )
   if 1 - 1: oO0o / OoOoOO00 + I1IiiI
  return ( "{}-{}-{}" . format ( self . instance_id , iIiIi1iI11iiI , self . mask_len ) )
  if 47 - 47: O0 / OOooOOo . i1IIi / OoooooooOO . IiII
  if 34 - 34: OoO0O00 * II111iiii + I1Ii111
 def print_sg ( self , g ) :
  o00oOOO = self . print_prefix ( )
  IiiiI1 = o00oOOO . find ( "]" ) + 1
  g = g . print_prefix ( )
  iiI1i1I1I = g . find ( "]" ) + 1
  o0o = "[{}]({}, {})" . format ( self . instance_id , o00oOOO [ IiiiI1 : : ] , g [ iiI1i1I1I : : ] )
  return ( o0o )
  if 66 - 66: i1IIi - Oo0Ooo
  if 39 - 39: I11i * O0 + OoO0O00
 def hash_address ( self , addr ) :
  OOoO0oO00o = self . address
  OOO0OoO0oo0OO = addr . address
  if 42 - 42: O0 / I1IiiI * Ii1I / iIii1I11I1II1 . i1IIi / I1IiiI
  if ( self . is_geo_prefix ( ) ) : OOoO0oO00o = self . address . print_geo ( )
  if ( addr . is_geo_prefix ( ) ) : OOO0OoO0oo0OO = addr . address . print_geo ( )
  if 66 - 66: I1ii11iIi11i % I1ii11iIi11i % I1ii11iIi11i % ooOoO0o + OoOoOO00
  if ( type ( OOoO0oO00o ) == str ) :
   OOoO0oO00o = int ( binascii . hexlify ( OOoO0oO00o [ 0 : 1 ] ) )
   if 55 - 55: OoooooooOO / OoOoOO00 % Oo0Ooo * OoO0O00 . OoooooooOO . OOooOOo
  if ( type ( OOO0OoO0oo0OO ) == str ) :
   OOO0OoO0oo0OO = int ( binascii . hexlify ( OOO0OoO0oo0OO [ 0 : 1 ] ) )
   if 79 - 79: i11iIiiIii / ooOoO0o / i11iIiiIii - I1Ii111
  return ( OOoO0oO00o ^ OOO0OoO0oo0OO )
  if 89 - 89: Oo0Ooo
  if 15 - 15: OOooOOo * II111iiii - OOooOOo * iIii1I11I1II1
  if 95 - 95: I1Ii111 / OoooooooOO * I11i * OoooooooOO
  if 88 - 88: I1IiiI / Oo0Ooo / oO0o + oO0o % OOooOOo + Oo0Ooo
  if 63 - 63: o0oOOo0O0Ooo + i11iIiiIii % OOooOOo % iIii1I11I1II1 / I1ii11iIi11i - iII111i
  if 72 - 72: iII111i % oO0o . IiII + I1ii11iIi11i . IiII . II111iiii
 def is_more_specific ( self , prefix ) :
  if ( prefix . afi == LISP_AFI_ULTIMATE_ROOT ) : return ( True )
  if 10 - 10: I11i . ooOoO0o + I11i * Ii1I
  Ooo = prefix . mask_len
  if ( prefix . afi == LISP_AFI_IID_RANGE ) :
   O0O0O = 2 ** ( 32 - Ooo )
   iI1i11II = prefix . instance_id
   OOooOOoOoo = iI1i11II + O0O0O
   return ( self . instance_id in range ( iI1i11II , OOooOOoOoo ) )
   if 7 - 7: oO0o - I11i / OoOoOO00 * I1Ii111 - Ii1I - i11iIiiIii
   if 57 - 57: IiII % i1IIi
  if ( self . instance_id != prefix . instance_id ) : return ( False )
  if ( self . afi != prefix . afi ) :
   if ( prefix . afi != LISP_AFI_NONE ) : return ( False )
   if 74 - 74: iII111i % I11i * i11iIiiIii . i11iIiiIii + iIii1I11I1II1 * i1IIi
   if 53 - 53: I1ii11iIi11i + IiII / OOooOOo . OoooooooOO - ooOoO0o
   if 47 - 47: i11iIiiIii
   if 21 - 21: i1IIi - oO0o - Oo0Ooo
   if 11 - 11: i1IIi
  if ( self . is_binary ( ) == False ) :
   if ( prefix . afi == LISP_AFI_NONE ) : return ( True )
   if ( type ( self . address ) != type ( prefix . address ) ) : return ( False )
   iIiIi1iI11iiI = self . address
   O00o0Oo = prefix . address
   if ( self . is_geo_prefix ( ) ) :
    iIiIi1iI11iiI = self . address . print_geo ( )
    O00o0Oo = prefix . address . print_geo ( )
    if 56 - 56: I1Ii111 * i1IIi % i11iIiiIii
   if ( len ( iIiIi1iI11iiI ) < len ( O00o0Oo ) ) : return ( False )
   return ( iIiIi1iI11iiI . find ( O00o0Oo ) == 0 )
   if 56 - 56: Ii1I . iII111i
   if 76 - 76: I1IiiI / Ii1I % OoOoOO00 + IiII / i11iIiiIii . o0oOOo0O0Ooo
   if 31 - 31: oO0o * oO0o % o0oOOo0O0Ooo . O0 + iII111i
   if 52 - 52: i11iIiiIii
   if 1 - 1: i1IIi * iIii1I11I1II1
  if ( self . mask_len < Ooo ) : return ( False )
  if 29 - 29: I11i
  iIiiI1i11Ii = ( prefix . addr_length ( ) * 8 ) - Ooo
  iii1iiiiiiI1 = ( 2 ** Ooo - 1 ) << iIiiI1i11Ii
  return ( ( self . address & iii1iiiiiiI1 ) == prefix . address )
  if 12 - 12: oO0o % i1IIi - oO0o / ooOoO0o * II111iiii % ooOoO0o
  if 6 - 6: IiII / OoO0O00
 def mask_address ( self , mask_len ) :
  iIiiI1i11Ii = ( self . addr_length ( ) * 8 ) - mask_len
  iii1iiiiiiI1 = ( 2 ** mask_len - 1 ) << iIiiI1i11Ii
  self . address &= iii1iiiiiiI1
  if 83 - 83: IiII - iIii1I11I1II1 * ooOoO0o - oO0o
  if 77 - 77: Ii1I
 def is_exact_match ( self , prefix ) :
  if ( self . instance_id != prefix . instance_id ) : return ( False )
  i1Ii = self . print_prefix ( )
  Oo00OOoO = prefix . print_prefix ( ) if prefix else ""
  return ( i1Ii == Oo00OOoO )
  if 20 - 20: I1Ii111
  if 33 - 33: i11iIiiIii / I1Ii111 + IiII / II111iiii + I11i
 def is_local ( self ) :
  if ( self . is_ipv4 ( ) ) :
   IiI1iIi1I1i = lisp_myrlocs [ 0 ]
   if ( IiI1iIi1I1i == None ) : return ( False )
   IiI1iIi1I1i = IiI1iIi1I1i . print_address_no_iid ( )
   return ( self . print_address_no_iid ( ) == IiI1iIi1I1i )
   if 44 - 44: OoOoOO00 / OoooooooOO % O0 * Ii1I * IiII
  if ( self . is_ipv6 ( ) ) :
   IiI1iIi1I1i = lisp_myrlocs [ 1 ]
   if ( IiI1iIi1I1i == None ) : return ( False )
   IiI1iIi1I1i = IiI1iIi1I1i . print_address_no_iid ( )
   return ( self . print_address_no_iid ( ) == IiI1iIi1I1i )
   if 84 - 84: o0oOOo0O0Ooo * IiII * OOooOOo * iII111i
  return ( False )
  if 56 - 56: iII111i * II111iiii . OoooooooOO . I11i
  if 25 - 25: ooOoO0o % o0oOOo0O0Ooo - i11iIiiIii
 def store_iid_range ( self , iid , mask_len ) :
  if ( self . afi == LISP_AFI_NONE ) :
   if ( iid is 0 and mask_len is 0 ) : self . afi = LISP_AFI_ULTIMATE_ROOT
   else : self . afi = LISP_AFI_IID_RANGE
   if 79 - 79: iII111i - I1IiiI % O0 / Oo0Ooo + OoOoOO00 . Oo0Ooo
  self . instance_id = iid
  self . mask_len = mask_len
  if 59 - 59: I1ii11iIi11i * OoOoOO00 / Ii1I
  if 80 - 80: IiII - ooOoO0o / OoOoOO00 / I11i * O0 + oO0o
 def lcaf_length ( self , lcaf_type ) :
  OOOOO000oo0 = self . addr_length ( ) + 2
  if ( lcaf_type == LISP_LCAF_AFI_LIST_TYPE ) : OOOOO000oo0 += 4
  if ( lcaf_type == LISP_LCAF_INSTANCE_ID_TYPE ) : OOOOO000oo0 += 4
  if ( lcaf_type == LISP_LCAF_ASN_TYPE ) : OOOOO000oo0 += 4
  if ( lcaf_type == LISP_LCAF_APP_DATA_TYPE ) : OOOOO000oo0 += 8
  if ( lcaf_type == LISP_LCAF_GEO_COORD_TYPE ) : OOOOO000oo0 += 12
  if ( lcaf_type == LISP_LCAF_OPAQUE_TYPE ) : OOOOO000oo0 += 0
  if ( lcaf_type == LISP_LCAF_NAT_TYPE ) : OOOOO000oo0 += 4
  if ( lcaf_type == LISP_LCAF_NONCE_LOC_TYPE ) : OOOOO000oo0 += 4
  if ( lcaf_type == LISP_LCAF_MCAST_INFO_TYPE ) : OOOOO000oo0 = OOOOO000oo0 * 2 + 8
  if ( lcaf_type == LISP_LCAF_ELP_TYPE ) : OOOOO000oo0 += 0
  if ( lcaf_type == LISP_LCAF_SECURITY_TYPE ) : OOOOO000oo0 += 6
  if ( lcaf_type == LISP_LCAF_SOURCE_DEST_TYPE ) : OOOOO000oo0 += 4
  if ( lcaf_type == LISP_LCAF_RLE_TYPE ) : OOOOO000oo0 += 4
  return ( OOOOO000oo0 )
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
  if 41 - 41: I1ii11iIi11i * ooOoO0o * I11i + O0 * O0 - O0
  if 81 - 81: I1Ii111 % OoO0O00 / O0
  if 55 - 55: i1IIi - I1Ii111 + I11i
  if 93 - 93: I1IiiI % IiII . OoOoOO00 + iII111i
  if 81 - 81: ooOoO0o / I1Ii111 + OOooOOo / Oo0Ooo / OoOoOO00
  if 34 - 34: ooOoO0o * iIii1I11I1II1 % i11iIiiIii * OOooOOo - OOooOOo
 def lcaf_encode_iid ( self ) :
  o0O00o0o = LISP_LCAF_INSTANCE_ID_TYPE
  ii11ii11II = socket . htons ( self . lcaf_length ( o0O00o0o ) )
  II1 = self . instance_id
  o0o0O00oOo = self . afi
  IIiiiII = 0
  if ( o0o0O00oOo < 0 ) :
   if ( self . afi == LISP_AFI_GEO_COORD ) :
    o0o0O00oOo = LISP_AFI_LCAF
    IIiiiII = 0
   else :
    o0o0O00oOo = 0
    IIiiiII = self . mask_len
    if 63 - 63: Oo0Ooo / oO0o + iII111i % OoooooooOO * I11i
    if 34 - 34: I1IiiI + I1Ii111 % ooOoO0o
    if 24 - 24: Ii1I % II111iiii - i11iIiiIii
  o00O000 = struct . pack ( "BBBBH" , 0 , 0 , o0O00o0o , IIiiiII , ii11ii11II )
  o00O000 += struct . pack ( "IH" , socket . htonl ( II1 ) , socket . htons ( o0o0O00oOo ) )
  if ( o0o0O00oOo == 0 ) : return ( o00O000 )
  if 21 - 21: oO0o . OoOoOO00 - iIii1I11I1II1 + OOooOOo * I11i . i1IIi
  if ( self . afi == LISP_AFI_GEO_COORD ) :
   o00O000 = o00O000 [ 0 : - 2 ]
   o00O000 += self . address . encode_geo ( )
   return ( o00O000 )
   if 59 - 59: I1ii11iIi11i / i11iIiiIii / iII111i + OoO0O00
   if 56 - 56: OOooOOo * i11iIiiIii - i11iIiiIii * I1IiiI + iII111i . OoOoOO00
  o00O000 += self . pack_address ( )
  return ( o00O000 )
  if 49 - 49: I1ii11iIi11i % oO0o - I1Ii111 . I1ii11iIi11i % II111iiii
  if 20 - 20: I1ii11iIi11i . iIii1I11I1II1 - Ii1I % OoO0O00
 def lcaf_decode_iid ( self , packet ) :
  IIiI1I11ii1i = "BBBBH"
  i1II1i1iiI1 = struct . calcsize ( IIiI1I11ii1i )
  if ( len ( packet ) < i1II1i1iiI1 ) : return ( None )
  if 27 - 27: iIii1I11I1II1 / I1Ii111 - I11i . OoO0O00 + ooOoO0o
  IiiIii1111Ii1I1 , iIIIIi , o0O00o0o , ooO000000O , OOOOO000oo0 = struct . unpack ( IIiI1I11ii1i ,
 packet [ : i1II1i1iiI1 ] )
  packet = packet [ i1II1i1iiI1 : : ]
  if 36 - 36: oO0o - I1Ii111
  if ( o0O00o0o != LISP_LCAF_INSTANCE_ID_TYPE ) : return ( None )
  if 55 - 55: oO0o
  IIiI1I11ii1i = "IH"
  i1II1i1iiI1 = struct . calcsize ( IIiI1I11ii1i )
  if ( len ( packet ) < i1II1i1iiI1 ) : return ( None )
  if 10 - 10: I1IiiI
  II1 , o0o0O00oOo = struct . unpack ( IIiI1I11ii1i , packet [ : i1II1i1iiI1 ] )
  packet = packet [ i1II1i1iiI1 : : ]
  if 17 - 17: i11iIiiIii % o0oOOo0O0Ooo . ooOoO0o
  OOOOO000oo0 = socket . ntohs ( OOOOO000oo0 )
  self . instance_id = socket . ntohl ( II1 )
  o0o0O00oOo = socket . ntohs ( o0o0O00oOo )
  self . afi = o0o0O00oOo
  if ( ooO000000O != 0 and o0o0O00oOo == 0 ) : self . mask_len = ooO000000O
  if ( o0o0O00oOo == 0 ) :
   self . afi = LISP_AFI_IID_RANGE if ooO000000O else LISP_AFI_ULTIMATE_ROOT
   if 34 - 34: OoooooooOO / iII111i / O0
   if 75 - 75: I11i % OOooOOo - OoO0O00 * I11i * IiII
   if 11 - 11: I1ii11iIi11i . O0 - iII111i * IiII . i1IIi . iII111i
   if 82 - 82: i1IIi * I11i * Ii1I - IiII . i11iIiiIii
   if 40 - 40: OOooOOo - OoooooooOO
  if ( o0o0O00oOo == 0 ) : return ( packet )
  if 36 - 36: i1IIi % OoOoOO00 - i1IIi
  if 5 - 5: I1IiiI . I1IiiI % II111iiii - I1Ii111
  if 97 - 97: I11i . ooOoO0o
  if 87 - 87: oO0o / iIii1I11I1II1 - I11i + OoooooooOO
  if ( self . is_dist_name ( ) ) :
   packet , self . address = lisp_decode_dist_name ( packet )
   self . mask_len = len ( self . address ) * 8
   return ( packet )
   if 79 - 79: I1ii11iIi11i * IiII . I1ii11iIi11i
   if 65 - 65: iII111i - Ii1I - II111iiii * O0 + I1ii11iIi11i . iIii1I11I1II1
   if 76 - 76: OoO0O00 * ooOoO0o
   if 32 - 32: O0 . oO0o * o0oOOo0O0Ooo . Ii1I + IiII
   if 98 - 98: iII111i . II111iiii % O0
  if ( o0o0O00oOo == LISP_AFI_LCAF ) :
   IIiI1I11ii1i = "BBBBH"
   i1II1i1iiI1 = struct . calcsize ( IIiI1I11ii1i )
   if ( len ( packet ) < i1II1i1iiI1 ) : return ( None )
   if 43 - 43: OOooOOo % I1Ii111 . IiII % OoO0O00 + I1Ii111 % OoooooooOO
   OoO0oOoo , I11I , o0O00o0o , ii11iIII111 , i11iii11 = struct . unpack ( IIiI1I11ii1i , packet [ : i1II1i1iiI1 ] )
   if 17 - 17: OoooooooOO - i1IIi * I11i
   if 33 - 33: i1IIi . Oo0Ooo + I11i
   if ( o0O00o0o != LISP_LCAF_GEO_COORD_TYPE ) : return ( None )
   if 97 - 97: OOooOOo / IiII / ooOoO0o / OoooooooOO
   i11iii11 = socket . ntohs ( i11iii11 )
   packet = packet [ i1II1i1iiI1 : : ]
   if ( i11iii11 > len ( packet ) ) : return ( None )
   if 78 - 78: I1Ii111 + I1Ii111
   O0OOoo = lisp_geo ( "" )
   self . afi = LISP_AFI_GEO_COORD
   self . address = O0OOoo
   packet = O0OOoo . decode_geo ( packet , i11iii11 , ii11iIII111 )
   self . mask_len = self . host_mask_len ( )
   return ( packet )
   if 43 - 43: I1Ii111 * o0oOOo0O0Ooo + i1IIi
   if 19 - 19: Ii1I
  ii11ii11II = self . addr_length ( )
  if ( len ( packet ) < ii11ii11II ) : return ( None )
  if 51 - 51: oO0o
  packet = self . unpack_address ( packet )
  return ( packet )
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
  if 75 - 75: I11i . II111iiii * I1IiiI * IiII
  if 36 - 36: OOooOOo / I1ii11iIi11i / oO0o / ooOoO0o / I11i
  if 7 - 7: OoO0O00 - I11i - o0oOOo0O0Ooo / o0oOOo0O0Ooo + i11iIiiIii
  if 28 - 28: OoOoOO00 % ooOoO0o . I1IiiI + II111iiii
 def lcaf_encode_sg ( self , group ) :
  o0O00o0o = LISP_LCAF_MCAST_INFO_TYPE
  II1 = socket . htonl ( self . instance_id )
  ii11ii11II = socket . htons ( self . lcaf_length ( o0O00o0o ) )
  o00O000 = struct . pack ( "BBBBHIHBB" , 0 , 0 , o0O00o0o , 0 , ii11ii11II , II1 ,
 0 , self . mask_len , group . mask_len )
  if 34 - 34: iIii1I11I1II1
  o00O000 += struct . pack ( "H" , socket . htons ( self . afi ) )
  o00O000 += self . pack_address ( )
  o00O000 += struct . pack ( "H" , socket . htons ( group . afi ) )
  o00O000 += group . pack_address ( )
  return ( o00O000 )
  if 65 - 65: II111iiii - iII111i / o0oOOo0O0Ooo
  if 35 - 35: i11iIiiIii - Oo0Ooo . I1ii11iIi11i % OoOoOO00
 def lcaf_decode_sg ( self , packet ) :
  IIiI1I11ii1i = "BBBBHIHBB"
  i1II1i1iiI1 = struct . calcsize ( IIiI1I11ii1i )
  if ( len ( packet ) < i1II1i1iiI1 ) : return ( [ None , None ] )
  if 20 - 20: OoO0O00
  IiiIii1111Ii1I1 , iIIIIi , o0O00o0o , I1IiII , OOOOO000oo0 , II1 , o0OOOO , iI1iiIii1Ii , iiI1ii1i = struct . unpack ( IIiI1I11ii1i , packet [ : i1II1i1iiI1 ] )
  if 66 - 66: o0oOOo0O0Ooo - Oo0Ooo . I1IiiI / I11i * OoooooooOO % i1IIi
  packet = packet [ i1II1i1iiI1 : : ]
  if 1 - 1: OoOoOO00 * O0 + i11iIiiIii . ooOoO0o / OoO0O00
  if ( o0O00o0o != LISP_LCAF_MCAST_INFO_TYPE ) : return ( [ None , None ] )
  if 48 - 48: o0oOOo0O0Ooo * II111iiii
  self . instance_id = socket . ntohl ( II1 )
  OOOOO000oo0 = socket . ntohs ( OOOOO000oo0 ) - 8
  if 17 - 17: o0oOOo0O0Ooo / ooOoO0o + i1IIi
  if 78 - 78: iIii1I11I1II1 * o0oOOo0O0Ooo * Oo0Ooo - OoO0O00 / OoO0O00
  if 89 - 89: o0oOOo0O0Ooo % o0oOOo0O0Ooo
  if 8 - 8: Ii1I % oO0o - o0oOOo0O0Ooo
  if 14 - 14: OOooOOo * IiII
  IIiI1I11ii1i = "H"
  i1II1i1iiI1 = struct . calcsize ( IIiI1I11ii1i )
  if ( len ( packet ) < i1II1i1iiI1 ) : return ( [ None , None ] )
  if ( OOOOO000oo0 < i1II1i1iiI1 ) : return ( [ None , None ] )
  if 15 - 15: o0oOOo0O0Ooo + OoooooooOO - OOooOOo - o0oOOo0O0Ooo . iIii1I11I1II1 / Ii1I
  o0o0O00oOo = struct . unpack ( IIiI1I11ii1i , packet [ : i1II1i1iiI1 ] ) [ 0 ]
  packet = packet [ i1II1i1iiI1 : : ]
  OOOOO000oo0 -= i1II1i1iiI1
  self . afi = socket . ntohs ( o0o0O00oOo )
  self . mask_len = iI1iiIii1Ii
  ii11ii11II = self . addr_length ( )
  if ( OOOOO000oo0 < ii11ii11II ) : return ( [ None , None ] )
  if 33 - 33: OoO0O00
  packet = self . unpack_address ( packet )
  if ( packet == None ) : return ( [ None , None ] )
  if 91 - 91: I11i % I11i % iII111i
  OOOOO000oo0 -= ii11ii11II
  if 19 - 19: I11i / I11i + I1IiiI * OoO0O00 - iII111i . Oo0Ooo
  if 76 - 76: iII111i % OOooOOo / OoooooooOO . I1IiiI % OoO0O00 % i1IIi
  if 95 - 95: Oo0Ooo - O0 / I1ii11iIi11i . I1IiiI / o0oOOo0O0Ooo % OoOoOO00
  if 38 - 38: OoOoOO00 % OoooooooOO . oO0o - OoooooooOO + I11i
  if 18 - 18: OoooooooOO + ooOoO0o * OoOoOO00 - OoO0O00
  IIiI1I11ii1i = "H"
  i1II1i1iiI1 = struct . calcsize ( IIiI1I11ii1i )
  if ( len ( packet ) < i1II1i1iiI1 ) : return ( [ None , None ] )
  if ( OOOOO000oo0 < i1II1i1iiI1 ) : return ( [ None , None ] )
  if 42 - 42: oO0o % OoOoOO00 - oO0o + I11i / i11iIiiIii
  o0o0O00oOo = struct . unpack ( IIiI1I11ii1i , packet [ : i1II1i1iiI1 ] ) [ 0 ]
  packet = packet [ i1II1i1iiI1 : : ]
  OOOOO000oo0 -= i1II1i1iiI1
  i1i11Ii1 = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  i1i11Ii1 . afi = socket . ntohs ( o0o0O00oOo )
  i1i11Ii1 . mask_len = iiI1ii1i
  i1i11Ii1 . instance_id = self . instance_id
  ii11ii11II = self . addr_length ( )
  if ( OOOOO000oo0 < ii11ii11II ) : return ( [ None , None ] )
  if 74 - 74: OoO0O00 - II111iiii - ooOoO0o % i1IIi
  packet = i1i11Ii1 . unpack_address ( packet )
  if ( packet == None ) : return ( [ None , None ] )
  if 42 - 42: i11iIiiIii / O0
  return ( [ packet , i1i11Ii1 ] )
  if 8 - 8: I1Ii111
  if 51 - 51: i11iIiiIii
 def lcaf_decode_eid ( self , packet ) :
  IIiI1I11ii1i = "BBB"
  i1II1i1iiI1 = struct . calcsize ( IIiI1I11ii1i )
  if ( len ( packet ) < i1II1i1iiI1 ) : return ( [ None , None ] )
  if 1 - 1: iIii1I11I1II1 . i1IIi . i11iIiiIii % I1ii11iIi11i
  if 58 - 58: i11iIiiIii * i11iIiiIii - OoO0O00
  if 8 - 8: i11iIiiIii * OoOoOO00 . o0oOOo0O0Ooo
  if 27 - 27: I1ii11iIi11i + Ii1I % I1Ii111
  if 20 - 20: Oo0Ooo
  I1IiII , I11I , o0O00o0o = struct . unpack ( IIiI1I11ii1i ,
 packet [ : i1II1i1iiI1 ] )
  if 33 - 33: oO0o - OoOoOO00 - i11iIiiIii + I1Ii111 + iIii1I11I1II1
  if ( o0O00o0o == LISP_LCAF_INSTANCE_ID_TYPE ) :
   return ( [ self . lcaf_decode_iid ( packet ) , None ] )
  elif ( o0O00o0o == LISP_LCAF_MCAST_INFO_TYPE ) :
   packet , i1i11Ii1 = self . lcaf_decode_sg ( packet )
   return ( [ packet , i1i11Ii1 ] )
  elif ( o0O00o0o == LISP_LCAF_GEO_COORD_TYPE ) :
   IIiI1I11ii1i = "BBBBH"
   i1II1i1iiI1 = struct . calcsize ( IIiI1I11ii1i )
   if ( len ( packet ) < i1II1i1iiI1 ) : return ( None )
   if 2 - 2: OoooooooOO + IiII / iII111i . iIii1I11I1II1 * OoOoOO00
   OoO0oOoo , I11I , o0O00o0o , ii11iIII111 , i11iii11 = struct . unpack ( IIiI1I11ii1i , packet [ : i1II1i1iiI1 ] )
   if 84 - 84: OOooOOo
   if 68 - 68: I1Ii111
   if ( o0O00o0o != LISP_LCAF_GEO_COORD_TYPE ) : return ( None )
   if 92 - 92: oO0o * Ii1I / OoO0O00 % II111iiii
   i11iii11 = socket . ntohs ( i11iii11 )
   packet = packet [ i1II1i1iiI1 : : ]
   if ( i11iii11 > len ( packet ) ) : return ( None )
   if 54 - 54: oO0o + I11i - OoO0O00
   O0OOoo = lisp_geo ( "" )
   self . instance_id = 0
   self . afi = LISP_AFI_GEO_COORD
   self . address = O0OOoo
   packet = O0OOoo . decode_geo ( packet , i11iii11 , ii11iIII111 )
   self . mask_len = self . host_mask_len ( )
   if 86 - 86: OoooooooOO
  return ( [ packet , None ] )
  if 51 - 51: i11iIiiIii
  if 91 - 91: OOooOOo
  if 22 - 22: OoooooooOO + OoOoOO00 - Ii1I . iII111i / OoooooooOO / I1IiiI
  if 73 - 73: i1IIi - Ii1I + oO0o * iIii1I11I1II1
  if 100 - 100: i11iIiiIii / iIii1I11I1II1 + Oo0Ooo + OoO0O00 - iII111i
  if 8 - 8: i11iIiiIii . O0 + o0oOOo0O0Ooo * oO0o + II111iiii
class lisp_elp_node ( ) :
 def __init__ ( self ) :
  self . address = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . probe = False
  self . strict = False
  self . eid = False
  self . we_are_last = False
  if 61 - 61: ooOoO0o / ooOoO0o
  if 51 - 51: iIii1I11I1II1 / oO0o * I1Ii111 + i1IIi
 def copy_elp_node ( self ) :
  IIi1IiIii1 = lisp_elp_node ( )
  IIi1IiIii1 . copy_address ( self . address )
  IIi1IiIii1 . probe = self . probe
  IIi1IiIii1 . strict = self . strict
  IIi1IiIii1 . eid = self . eid
  IIi1IiIii1 . we_are_last = self . we_are_last
  return ( IIi1IiIii1 )
  if 96 - 96: Oo0Ooo + oO0o - Oo0Ooo - OoOoOO00 % OOooOOo . iIii1I11I1II1
  if 93 - 93: iIii1I11I1II1 % OoooooooOO
  if 6 - 6: II111iiii / oO0o - OOooOOo . O0 - o0oOOo0O0Ooo
class lisp_elp ( ) :
 def __init__ ( self , name ) :
  self . elp_name = name
  self . elp_nodes = [ ]
  self . use_elp_node = None
  self . we_are_last = False
  if 72 - 72: iIii1I11I1II1 / OoooooooOO * ooOoO0o / ooOoO0o % O0 + IiII
  if 96 - 96: iII111i / i11iIiiIii + Oo0Ooo . I1IiiI + iII111i % OoOoOO00
 def copy_elp ( self ) :
  O0Oooo0 = lisp_elp ( self . elp_name )
  O0Oooo0 . use_elp_node = self . use_elp_node
  O0Oooo0 . we_are_last = self . we_are_last
  for IIi1IiIii1 in self . elp_nodes :
   O0Oooo0 . elp_nodes . append ( IIi1IiIii1 . copy_elp_node ( ) )
   if 19 - 19: i11iIiiIii . Oo0Ooo . OoOoOO00 - I1IiiI
  return ( O0Oooo0 )
  if 85 - 85: I11i - OoO0O00 % iIii1I11I1II1 . iII111i + ooOoO0o . Oo0Ooo
  if 87 - 87: iII111i
 def print_elp ( self , want_marker ) :
  iiiII1i11iII = ""
  for IIi1IiIii1 in self . elp_nodes :
   o000oOoO = ""
   if ( want_marker ) :
    if ( IIi1IiIii1 == self . use_elp_node ) :
     o000oOoO = "*"
    elif ( IIi1IiIii1 . we_are_last ) :
     o000oOoO = "x"
     if 24 - 24: ooOoO0o / OoooooooOO % I1ii11iIi11i * ooOoO0o
     if 14 - 14: I1ii11iIi11i + OoO0O00 - I1IiiI - Oo0Ooo
   iiiII1i11iII += "{}{}({}{}{}), " . format ( o000oOoO ,
 IIi1IiIii1 . address . print_address_no_iid ( ) ,
 "r" if IIi1IiIii1 . eid else "R" , "P" if IIi1IiIii1 . probe else "p" ,
 "S" if IIi1IiIii1 . strict else "s" )
   if 44 - 44: II111iiii / I1ii11iIi11i
  return ( iiiII1i11iII [ 0 : - 2 ] if iiiII1i11iII != "" else "" )
  if 39 - 39: OoooooooOO % OoO0O00
  if 83 - 83: OOooOOo % I1IiiI + O0 % OoooooooOO
 def select_elp_node ( self ) :
  O00OO0ooo , o0oOO000 , oO00O = lisp_myrlocs
  oo0OOo0O = None
  if 91 - 91: I1Ii111 * iII111i * OoO0O00
  for IIi1IiIii1 in self . elp_nodes :
   if ( O00OO0ooo and IIi1IiIii1 . address . is_exact_match ( O00OO0ooo ) ) :
    oo0OOo0O = self . elp_nodes . index ( IIi1IiIii1 )
    break
    if 79 - 79: iII111i + oO0o
   if ( o0oOO000 and IIi1IiIii1 . address . is_exact_match ( o0oOO000 ) ) :
    oo0OOo0O = self . elp_nodes . index ( IIi1IiIii1 )
    break
    if 19 - 19: I1Ii111 - OOooOOo . ooOoO0o . O0 + II111iiii . OoooooooOO
    if 97 - 97: O0 / OoOoOO00 / ooOoO0o
    if 11 - 11: II111iiii . i11iIiiIii - Ii1I . IiII
    if 10 - 10: OOooOOo * OoooooooOO
    if 12 - 12: II111iiii - O0 . i1IIi % oO0o % OoooooooOO
    if 36 - 36: IiII * OoOoOO00 - iIii1I11I1II1 + II111iiii
    if 65 - 65: I1IiiI * I11i . I1Ii111 % I1ii11iIi11i + O0
  if ( oo0OOo0O == None ) :
   self . use_elp_node = self . elp_nodes [ 0 ]
   IIi1IiIii1 . we_are_last = False
   return
   if 91 - 91: OoooooooOO % I1Ii111 * OoO0O00 - OoOoOO00
   if 5 - 5: iIii1I11I1II1 * I11i - oO0o % oO0o % o0oOOo0O0Ooo . i1IIi
   if 95 - 95: Oo0Ooo * I1ii11iIi11i + iII111i - o0oOOo0O0Ooo - Oo0Ooo . OoO0O00
   if 62 - 62: I11i
   if 58 - 58: I11i . OoOoOO00 + iII111i . iII111i
   if 43 - 43: I1Ii111 + I1Ii111 % Oo0Ooo % OoO0O00 - ooOoO0o
  if ( self . elp_nodes [ - 1 ] == self . elp_nodes [ oo0OOo0O ] ) :
   self . use_elp_node = None
   IIi1IiIii1 . we_are_last = True
   return
   if 61 - 61: OoOoOO00 + Ii1I % i11iIiiIii - I1IiiI * OoO0O00 % iIii1I11I1II1
   if 66 - 66: iII111i + i1IIi
   if 24 - 24: O0 / OoooooooOO - OoOoOO00
   if 51 - 51: OoO0O00 + o0oOOo0O0Ooo - II111iiii * I11i + Ii1I
   if 16 - 16: I1Ii111 * i1IIi . I1IiiI . OOooOOo % Ii1I - o0oOOo0O0Ooo
  self . use_elp_node = self . elp_nodes [ oo0OOo0O + 1 ]
  return
  if 89 - 89: Ii1I * I1ii11iIi11i * I1IiiI % iII111i % Ii1I + O0
  if 53 - 53: i11iIiiIii % I1ii11iIi11i
  if 59 - 59: OOooOOo
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
  if 61 - 61: OoooooooOO + O0 - i1IIi % oO0o / I1ii11iIi11i
  if 50 - 50: oO0o + II111iiii * OoOoOO00 % OoO0O00 . II111iiii % o0oOOo0O0Ooo
 def copy_geo ( self ) :
  O0OOoo = lisp_geo ( self . geo_name )
  O0OOoo . latitude = self . latitude
  O0OOoo . lat_mins = self . lat_mins
  O0OOoo . lat_secs = self . lat_secs
  O0OOoo . longitude = self . longitude
  O0OOoo . long_mins = self . long_mins
  O0OOoo . long_secs = self . long_secs
  O0OOoo . altitude = self . altitude
  O0OOoo . radius = self . radius
  return ( O0OOoo )
  if 32 - 32: i1IIi / Ii1I + i11iIiiIii % oO0o
  if 11 - 11: Ii1I - ooOoO0o % i11iIiiIii / OoooooooOO - O0 - IiII
 def no_geo_altitude ( self ) :
  return ( self . altitude == - 1 )
  if 25 - 25: IiII + O0 + oO0o % iIii1I11I1II1 - II111iiii . I1IiiI
  if 62 - 62: IiII . O0 + oO0o - ooOoO0o * iIii1I11I1II1
 def parse_geo_string ( self , geo_str ) :
  oo0OOo0O = geo_str . find ( "]" )
  if ( oo0OOo0O != - 1 ) : geo_str = geo_str [ oo0OOo0O + 1 : : ]
  if 8 - 8: I1ii11iIi11i
  if 65 - 65: i11iIiiIii
  if 92 - 92: oO0o * II111iiii + I1Ii111
  if 49 - 49: II111iiii * I1IiiI * O0 / ooOoO0o * IiII
  if 94 - 94: OoO0O00 - I1IiiI * oO0o
  if ( geo_str . find ( "/" ) != - 1 ) :
   geo_str , i1IiiiIiii = geo_str . split ( "/" )
   self . radius = int ( i1IiiiIiii )
   if 81 - 81: ooOoO0o . Oo0Ooo . OoOoOO00 + OOooOOo % iII111i - oO0o
   if 68 - 68: iII111i - O0 / Ii1I
  geo_str = geo_str . split ( "-" )
  if ( len ( geo_str ) < 8 ) : return ( False )
  if 15 - 15: I1Ii111 / I1ii11iIi11i / I1IiiI % i11iIiiIii + II111iiii . ooOoO0o
  oo00OOo0 = geo_str [ 0 : 4 ]
  I1iiOO00o00oOoOo = geo_str [ 4 : 8 ]
  if 81 - 81: I1Ii111 + Oo0Ooo . I1ii11iIi11i / I11i
  if 16 - 16: Oo0Ooo * I1IiiI
  if 100 - 100: I1ii11iIi11i
  if 37 - 37: ooOoO0o . oO0o * ooOoO0o % iIii1I11I1II1 % Ii1I
  if ( len ( geo_str ) > 8 ) : self . altitude = int ( geo_str [ 8 ] )
  if 92 - 92: OoO0O00 * IiII
  if 76 - 76: i1IIi
  if 93 - 93: Oo0Ooo / I1ii11iIi11i + Oo0Ooo + OOooOOo
  if 58 - 58: oO0o
  self . latitude = int ( oo00OOo0 [ 0 ] )
  self . lat_mins = int ( oo00OOo0 [ 1 ] )
  self . lat_secs = int ( oo00OOo0 [ 2 ] )
  if ( oo00OOo0 [ 3 ] == "N" ) : self . latitude = - self . latitude
  if 9 - 9: I1Ii111 - i1IIi . ooOoO0o
  if 33 - 33: I11i
  if 37 - 37: Oo0Ooo
  if 36 - 36: IiII % I11i
  self . longitude = int ( I1iiOO00o00oOoOo [ 0 ] )
  self . long_mins = int ( I1iiOO00o00oOoOo [ 1 ] )
  self . long_secs = int ( I1iiOO00o00oOoOo [ 2 ] )
  if ( I1iiOO00o00oOoOo [ 3 ] == "E" ) : self . longitude = - self . longitude
  return ( True )
  if 72 - 72: oO0o % I11i % OOooOOo * iIii1I11I1II1 - OOooOOo % O0
  if 84 - 84: oO0o - o0oOOo0O0Ooo / II111iiii . o0oOOo0O0Ooo
 def print_geo ( self ) :
  ooOo = "N" if self . latitude < 0 else "S"
  I11II1i1i = "E" if self . longitude < 0 else "W"
  if 14 - 14: OoooooooOO
  Ii1i11iIi1iII = "{}-{}-{}-{}-{}-{}-{}-{}" . format ( abs ( self . latitude ) ,
 self . lat_mins , self . lat_secs , ooOo , abs ( self . longitude ) ,
 self . long_mins , self . long_secs , I11II1i1i )
  if 44 - 44: I11i * I11i + OoooooooOO
  if ( self . no_geo_altitude ( ) == False ) :
   Ii1i11iIi1iII += "-" + str ( self . altitude )
   if 26 - 26: I1Ii111 * Ii1I
   if 95 - 95: oO0o + OoOoOO00 / OoO0O00 % I1IiiI
   if 28 - 28: I1IiiI
   if 59 - 59: OOooOOo . I1IiiI / i1IIi / II111iiii . II111iiii
   if 54 - 54: iIii1I11I1II1 % ooOoO0o
  if ( self . radius != 0 ) : Ii1i11iIi1iII += "/{}" . format ( self . radius )
  return ( Ii1i11iIi1iII )
  if 37 - 37: OOooOOo % OoOoOO00 - II111iiii * o0oOOo0O0Ooo . I1IiiI . OoOoOO00
  if 92 - 92: I11i + OoO0O00 . OoooooooOO
 def geo_url ( self ) :
  iIiIi1iIIii = os . getenv ( "LISP_GEO_ZOOM_LEVEL" )
  iIiIi1iIIii = "10" if ( iIiIi1iIIii == "" or iIiIi1iIIii . isdigit ( ) == False ) else iIiIi1iIIii
  I1iiIii11Ii , IIo0 = self . dms_to_decimal ( )
  I1OOoO = ( "http://maps.googleapis.com/maps/api/staticmap?center={},{}" + "&markers=color:blue%7Clabel:lisp%7C{},{}" + "&zoom={}&size=1024x1024&sensor=false" ) . format ( I1iiIii11Ii , IIo0 , I1iiIii11Ii , IIo0 ,
  # OoOoOO00 % Ii1I
  # iII111i
 iIiIi1iIIii )
  return ( I1OOoO )
  if 59 - 59: i11iIiiIii . OOooOOo
  if 17 - 17: Ii1I - iII111i * I1ii11iIi11i
 def print_geo_url ( self ) :
  O0OOoo = self . print_geo ( )
  if ( self . radius == 0 ) :
   I1OOoO = self . geo_url ( )
   O0I11IIIII = "<a href='{}'>{}</a>" . format ( I1OOoO , O0OOoo )
  else :
   I1OOoO = O0OOoo . replace ( "/" , "-" )
   O0I11IIIII = "<a href='/lisp/geo-map/{}'>{}</a>" . format ( I1OOoO , O0OOoo )
   if 79 - 79: i1IIi * OOooOOo % II111iiii % OoO0O00 / i11iIiiIii
  return ( O0I11IIIII )
  if 18 - 18: i11iIiiIii . oO0o
  if 48 - 48: i1IIi
 def dms_to_decimal ( self ) :
  oO0oO0OO0 , IiI1i1II , I11iii1i1 = self . latitude , self . lat_mins , self . lat_secs
  o00oo = float ( abs ( oO0oO0OO0 ) )
  o00oo += float ( IiI1i1II * 60 + I11iii1i1 ) / 3600
  if ( oO0oO0OO0 > 0 ) : o00oo = - o00oo
  IiiiIIIi1 = o00oo
  if 70 - 70: OOooOOo * OOooOOo - O0 - I1Ii111 / OoooooooOO - iII111i
  oO0oO0OO0 , IiI1i1II , I11iii1i1 = self . longitude , self . long_mins , self . long_secs
  o00oo = float ( abs ( oO0oO0OO0 ) )
  o00oo += float ( IiI1i1II * 60 + I11iii1i1 ) / 3600
  if ( oO0oO0OO0 > 0 ) : o00oo = - o00oo
  O00O00oOO0Oo = o00oo
  return ( ( IiiiIIIi1 , O00O00oOO0Oo ) )
  if 99 - 99: oO0o . i11iIiiIii % i1IIi + iII111i
  if 91 - 91: I1Ii111 . II111iiii / Ii1I * O0
 def get_distance ( self , geo_point ) :
  IIIi11I1IiiIi = self . dms_to_decimal ( )
  o00OOo0oo0oO = geo_point . dms_to_decimal ( )
  iIiiii = vincenty ( IIIi11I1IiiIi , o00OOo0oo0oO )
  return ( iIiiii . km )
  if 46 - 46: I11i * OOooOOo
  if 57 - 57: iIii1I11I1II1
 def point_in_circle ( self , geo_point ) :
  Iiiii11iI = self . get_distance ( geo_point )
  return ( Iiiii11iI <= self . radius )
  if 61 - 61: I1ii11iIi11i . OOooOOo - O0 * OoOoOO00
  if 12 - 12: I1ii11iIi11i / I1Ii111
 def encode_geo ( self ) :
  ooOO0o0ooOo0 = socket . htons ( LISP_AFI_LCAF )
  I1i11I = socket . htons ( 20 + 2 )
  I11I = 0
  if 5 - 5: Oo0Ooo / o0oOOo0O0Ooo % i11iIiiIii - ooOoO0o
  I1iiIii11Ii = abs ( self . latitude )
  o0iIII1i11i = ( ( self . lat_mins * 60 ) + self . lat_secs ) * 1000
  if ( self . latitude < 0 ) : I11I |= 0x40
  if 48 - 48: Ii1I / Ii1I / i1IIi * I1IiiI . iII111i + I1ii11iIi11i
  IIo0 = abs ( self . longitude )
  ooiIIi11I1 = ( ( self . long_mins * 60 ) + self . long_secs ) * 1000
  if ( self . longitude < 0 ) : I11I |= 0x20
  if 3 - 3: OoOoOO00 / Oo0Ooo - Oo0Ooo
  OO0I11iI = 0
  if ( self . no_geo_altitude ( ) == False ) :
   OO0I11iI = socket . htonl ( self . altitude )
   I11I |= 0x10
   if 52 - 52: OoO0O00 % I11i - oO0o . I11i % IiII
  i1IiiiIiii = socket . htons ( self . radius )
  if ( i1IiiiIiii != 0 ) : I11I |= 0x06
  if 100 - 100: OoooooooOO % OoOoOO00 . i1IIi - Ii1I + iIii1I11I1II1
  ooOOoO0Oo0OoO = struct . pack ( "HBBBBH" , ooOO0o0ooOo0 , 0 , 0 , LISP_LCAF_GEO_COORD_TYPE ,
 0 , I1i11I )
  ooOOoO0Oo0OoO += struct . pack ( "BBHBBHBBHIHHH" , I11I , 0 , 0 , I1iiIii11Ii , o0iIII1i11i >> 16 ,
 socket . htons ( o0iIII1i11i & 0x0ffff ) , IIo0 , ooiIIi11I1 >> 16 ,
 socket . htons ( ooiIIi11I1 & 0xffff ) , OO0I11iI , i1IiiiIiii , 0 , 0 )
  if 10 - 10: ooOoO0o
  return ( ooOOoO0Oo0OoO )
  if 86 - 86: OoOoOO00 / Ii1I
  if 80 - 80: II111iiii
 def decode_geo ( self , packet , lcaf_len , radius_hi ) :
  IIiI1I11ii1i = "BBHBBHBBHIHHH"
  i1II1i1iiI1 = struct . calcsize ( IIiI1I11ii1i )
  if ( lcaf_len < i1II1i1iiI1 ) : return ( None )
  if 66 - 66: ooOoO0o
  I11I , OoOoO , I1IIiI1i , I1iiIii11Ii , Oo0OooOoO , o0iIII1i11i , IIo0 , I1Ii1I , ooiIIi11I1 , OO0I11iI , i1IiiiIiii , O0000OO0O0 , o0o0O00oOo = struct . unpack ( IIiI1I11ii1i ,
  # OoooooooOO - i1IIi * Ii1I * I1ii11iIi11i + I1Ii111 . I1IiiI
 packet [ : i1II1i1iiI1 ] )
  if 56 - 56: iIii1I11I1II1
  if 37 - 37: OoOoOO00
  if 56 - 56: OOooOOo / I11i - i11iIiiIii
  if 11 - 11: iIii1I11I1II1
  o0o0O00oOo = socket . ntohs ( o0o0O00oOo )
  if ( o0o0O00oOo == LISP_AFI_LCAF ) : return ( None )
  if 12 - 12: i1IIi + oO0o * I1Ii111 + OoOoOO00 . oO0o
  if ( I11I & 0x40 ) : I1iiIii11Ii = - I1iiIii11Ii
  self . latitude = I1iiIii11Ii
  II1i1I = ( ( Oo0OooOoO << 16 ) | socket . ntohs ( o0iIII1i11i ) ) / 1000
  self . lat_mins = II1i1I / 60
  self . lat_secs = II1i1I % 60
  if 19 - 19: iIii1I11I1II1 / iII111i + OOooOOo . ooOoO0o
  if ( I11I & 0x20 ) : IIo0 = - IIo0
  self . longitude = IIo0
  o0oO = ( ( I1Ii1I << 16 ) | socket . ntohs ( ooiIIi11I1 ) ) / 1000
  self . long_mins = o0oO / 60
  self . long_secs = o0oO % 60
  if 6 - 6: IiII
  self . altitude = socket . ntohl ( OO0I11iI ) if ( I11I & 0x10 ) else - 1
  i1IiiiIiii = socket . ntohs ( i1IiiiIiii )
  self . radius = i1IiiiIiii if ( I11I & 0x02 ) else i1IiiiIiii * 1000
  if 69 - 69: iII111i
  self . geo_name = None
  packet = packet [ i1II1i1iiI1 : : ]
  if 87 - 87: i11iIiiIii % o0oOOo0O0Ooo + Ii1I
  if ( o0o0O00oOo != 0 ) :
   self . rloc . afi = o0o0O00oOo
   packet = self . rloc . unpack_address ( packet )
   self . rloc . mask_len = self . rloc . host_mask_len ( )
   if 72 - 72: Ii1I / II111iiii + o0oOOo0O0Ooo
  return ( packet )
  if 33 - 33: I1Ii111 * OoOoOO00 - OoooooooOO
  if 11 - 11: I1Ii111 - Oo0Ooo / iIii1I11I1II1 - OoooooooOO
  if 71 - 71: Oo0Ooo + Ii1I - OoooooooOO + I11i - iIii1I11I1II1 / O0
  if 76 - 76: i11iIiiIii % o0oOOo0O0Ooo . O0 * I11i
  if 90 - 90: II111iiii + OOooOOo % I1Ii111 * iIii1I11I1II1 % iIii1I11I1II1
  if 55 - 55: II111iiii % O0 * O0 - II111iiii * I1IiiI % Oo0Ooo
class lisp_rle_node ( ) :
 def __init__ ( self ) :
  self . address = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . level = 0
  self . translated_port = 0
  self . rloc_name = None
  if 48 - 48: I1ii11iIi11i + OoooooooOO % i1IIi
  if 46 - 46: OoOoOO00
 def copy_rle_node ( self ) :
  I1I1iiI = lisp_rle_node ( )
  I1I1iiI . address . copy_address ( self . address )
  I1I1iiI . level = self . level
  I1I1iiI . translated_port = self . translated_port
  I1I1iiI . rloc_name = self . rloc_name
  return ( I1I1iiI )
  if 75 - 75: I1IiiI
  if 37 - 37: iIii1I11I1II1 % OoO0O00 * ooOoO0o + I11i % ooOoO0o / i11iIiiIii
 def store_translated_rloc ( self , rloc , port ) :
  self . address . copy_address ( rloc )
  self . translated_port = port
  if 14 - 14: i1IIi / ooOoO0o
  if 10 - 10: ooOoO0o / OoooooooOO - ooOoO0o % O0 + oO0o - oO0o
 def get_encap_keys ( self ) :
  Iiiii = "4341" if self . translated_port == 0 else str ( self . translated_port )
  if 16 - 16: O0
  ooOOo0o = self . address . print_address_no_iid ( ) + ":" + Iiiii
  if 14 - 14: Ii1I . Ii1I . OOooOOo - O0 / OoO0O00 % II111iiii
  try :
   i1iIi = lisp_crypto_keys_by_rloc_encap [ ooOOo0o ]
   if ( i1iIi [ 1 ] ) : return ( i1iIi [ 1 ] . encrypt_key , i1iIi [ 1 ] . icv_key )
   return ( None , None )
  except :
   return ( None , None )
   if 5 - 5: iIii1I11I1II1 % OoOoOO00 % OOooOOo % O0 * oO0o . iIii1I11I1II1
   if 96 - 96: i11iIiiIii + oO0o / I1ii11iIi11i . IiII % o0oOOo0O0Ooo
   if 41 - 41: o0oOOo0O0Ooo . i1IIi - OOooOOo
   if 19 - 19: o0oOOo0O0Ooo % I1Ii111 % I11i
class lisp_rle ( ) :
 def __init__ ( self , name ) :
  self . rle_name = name
  self . rle_nodes = [ ]
  self . rle_forwarding_list = [ ]
  if 1 - 1: I1IiiI / o0oOOo0O0Ooo - I1Ii111
  if 50 - 50: I11i - OoOoOO00 + I1IiiI % Oo0Ooo / OoooooooOO - I1ii11iIi11i
 def copy_rle ( self ) :
  II1IIiiI1 = lisp_rle ( self . rle_name )
  for I1I1iiI in self . rle_nodes :
   II1IIiiI1 . rle_nodes . append ( I1I1iiI . copy_rle_node ( ) )
   if 26 - 26: IiII . Ii1I
  II1IIiiI1 . build_forwarding_list ( )
  return ( II1IIiiI1 )
  if 35 - 35: I1ii11iIi11i + OOooOOo
  if 88 - 88: O0
 def print_rle ( self , html ) :
  oOOoo0O00 = ""
  for I1I1iiI in self . rle_nodes :
   Iiiii = I1I1iiI . translated_port
   II1iiiIiiI = blue ( I1I1iiI . rloc_name , html ) if I1I1iiI . rloc_name != None else ""
   if 29 - 29: Ii1I % o0oOOo0O0Ooo - Ii1I
   ooOOo0o = I1I1iiI . address . print_address_no_iid ( )
   if ( I1I1iiI . address . is_local ( ) ) : ooOOo0o = red ( ooOOo0o , html )
   oOOoo0O00 += "{}{}(L{}){}, " . format ( ooOOo0o , "" if Iiiii == 0 else "-" + str ( Iiiii ) , I1I1iiI . level ,
   # IiII - ooOoO0o / O0
 "" if I1I1iiI . rloc_name == None else II1iiiIiiI )
   if 27 - 27: Oo0Ooo
  return ( oOOoo0O00 [ 0 : - 2 ] if oOOoo0O00 != "" else "" )
  if 15 - 15: iIii1I11I1II1 . OoOoOO00 % Ii1I / i1IIi . o0oOOo0O0Ooo
  if 45 - 45: iIii1I11I1II1 - i1IIi % I1IiiI - I1Ii111 + oO0o
 def build_forwarding_list ( self ) :
  IiIi1II1Ii = - 1
  for I1I1iiI in self . rle_nodes :
   if ( IiIi1II1Ii == - 1 ) :
    if ( I1I1iiI . address . is_local ( ) ) : IiIi1II1Ii = I1I1iiI . level
   else :
    if ( I1I1iiI . level > IiIi1II1Ii ) : break
    if 15 - 15: iIii1I11I1II1 - OoooooooOO / ooOoO0o
    if 83 - 83: IiII + I1Ii111 / OoOoOO00 * IiII . oO0o
  IiIi1II1Ii = 0 if IiIi1II1Ii == - 1 else I1I1iiI . level
  if 22 - 22: O0 + ooOoO0o + I1Ii111
  self . rle_forwarding_list = [ ]
  for I1I1iiI in self . rle_nodes :
   if ( I1I1iiI . level == IiIi1II1Ii or ( IiIi1II1Ii == 0 and
 I1I1iiI . level == 128 ) ) :
    if ( lisp_i_am_rtr == False and I1I1iiI . address . is_local ( ) ) :
     ooOOo0o = I1I1iiI . address . print_address_no_iid ( )
     lprint ( "Exclude local RLE RLOC {}" . format ( ooOOo0o ) )
     continue
     if 57 - 57: OOooOOo . ooOoO0o - OoooooooOO - I1ii11iIi11i * O0
    self . rle_forwarding_list . append ( I1I1iiI )
    if 85 - 85: I1IiiI * OoO0O00
    if 63 - 63: I1IiiI - i11iIiiIii
    if 4 - 4: OOooOOo + iIii1I11I1II1 / I1IiiI * Ii1I
    if 64 - 64: OoOoOO00
    if 94 - 94: OOooOOo * OoooooooOO * o0oOOo0O0Ooo / I1Ii111 . II111iiii
class lisp_json ( ) :
 def __init__ ( self , name , string ) :
  self . json_name = name
  self . json_string = string
  if 37 - 37: O0 * II111iiii * I1IiiI - O0 - I11i / i1IIi
  if 27 - 27: i11iIiiIii + iIii1I11I1II1
 def add ( self ) :
  self . delete ( )
  lisp_json_list [ self . json_name ] = self
  if 15 - 15: oO0o
  if 69 - 69: II111iiii * O0 . ooOoO0o * IiII
 def delete ( self ) :
  if ( lisp_json_list . has_key ( self . json_name ) ) :
   del ( lisp_json_list [ self . json_name ] )
   lisp_json_list [ self . json_name ] = None
   if 25 - 25: I11i - I1ii11iIi11i . I1Ii111 . OoooooooOO
   if 4 - 4: IiII * OoO0O00 % I1ii11iIi11i * Ii1I . iII111i
   if 41 - 41: OoooooooOO % I11i . O0 + I1Ii111
 def print_json ( self , html ) :
  OOo0oOoOOO0oo = self . json_string
  iiO0 = "***"
  if ( html ) : iiO0 = red ( iiO0 , html )
  iIioOooO = iiO0 + self . json_string + iiO0
  if ( self . valid_json ( ) ) : return ( OOo0oOoOOO0oo )
  return ( iIioOooO )
  if 33 - 33: i1IIi / o0oOOo0O0Ooo . OoooooooOO
  if 8 - 8: I1IiiI * OOooOOo * IiII / I1IiiI + i1IIi
 def valid_json ( self ) :
  try :
   json . loads ( self . json_string )
  except :
   return ( False )
   if 11 - 11: I11i * Ii1I * I1IiiI - I1IiiI % OoooooooOO
  return ( True )
  if 83 - 83: i11iIiiIii % iII111i * O0 % OoooooooOO
  if 99 - 99: I1ii11iIi11i % I1ii11iIi11i * iII111i % oO0o
  if 56 - 56: Oo0Ooo + i11iIiiIii - oO0o . Ii1I + IiII
  if 19 - 19: I11i * OoooooooOO . i1IIi
  if 100 - 100: II111iiii
  if 95 - 95: iII111i
class lisp_stats ( ) :
 def __init__ ( self ) :
  self . packet_count = 0
  self . byte_count = 0
  self . last_rate_check = 0
  self . last_packet_count = 0
  self . last_byte_count = 0
  self . last_increment = None
  if 94 - 94: OoOoOO00 + OoooooooOO
  if 92 - 92: i11iIiiIii * IiII * I1IiiI - oO0o / iII111i
 def increment ( self , octets ) :
  self . packet_count += 1
  self . byte_count += octets
  self . last_increment = lisp_get_timestamp ( )
  if 1 - 1: ooOoO0o - OoO0O00 - o0oOOo0O0Ooo % I1Ii111 . I1ii11iIi11i - I1Ii111
  if 78 - 78: Oo0Ooo
 def recent_packet_sec ( self ) :
  if ( self . last_increment == None ) : return ( False )
  iIIiI1iiI = time . time ( ) - self . last_increment
  return ( iIIiI1iiI <= 1 )
  if 27 - 27: Ii1I / oO0o - Ii1I / iIii1I11I1II1 + o0oOOo0O0Ooo . Ii1I
  if 79 - 79: Ii1I % O0 * OOooOOo
 def recent_packet_min ( self ) :
  if ( self . last_increment == None ) : return ( False )
  iIIiI1iiI = time . time ( ) - self . last_increment
  return ( iIIiI1iiI <= 60 )
  if 41 - 41: I1ii11iIi11i . OoooooooOO * I1ii11iIi11i - oO0o
  if 40 - 40: I1IiiI % OoO0O00 + i11iIiiIii / oO0o
 def stat_colors ( self , c1 , c2 , html ) :
  if ( self . recent_packet_sec ( ) ) :
   return ( green_last_sec ( c1 ) , green_last_sec ( c2 ) )
   if 98 - 98: oO0o + iIii1I11I1II1 . ooOoO0o / I1ii11iIi11i
  if ( self . recent_packet_min ( ) ) :
   return ( green_last_min ( c1 ) , green_last_min ( c2 ) )
   if 77 - 77: OoOoOO00 / Oo0Ooo * OoOoOO00 % I1IiiI . II111iiii % OoO0O00
  return ( c1 , c2 )
  if 38 - 38: iII111i - OoO0O00 / i1IIi + ooOoO0o . ooOoO0o . iII111i
  if 37 - 37: iIii1I11I1II1 * OoOoOO00 . OoOoOO00 + OoooooooOO + OoO0O00
 def normalize ( self , count ) :
  count = str ( count )
  Iii1IIiii1iii1i = len ( count )
  if ( Iii1IIiii1iii1i > 12 ) :
   count = count [ 0 : - 10 ] + "." + count [ - 10 : - 7 ] + "T"
   return ( count )
   if 9 - 9: II111iiii / ooOoO0o - OOooOOo
  if ( Iii1IIiii1iii1i > 9 ) :
   count = count [ 0 : - 9 ] + "." + count [ - 9 : - 7 ] + "B"
   return ( count )
   if 57 - 57: I1ii11iIi11i
  if ( Iii1IIiii1iii1i > 6 ) :
   count = count [ 0 : - 6 ] + "." + count [ - 6 ] + "M"
   return ( count )
   if 82 - 82: o0oOOo0O0Ooo / O0 / iII111i / II111iiii - I11i % o0oOOo0O0Ooo
  return ( count )
  if 3 - 3: OoOoOO00 - Oo0Ooo - II111iiii
  if 20 - 20: II111iiii . OOooOOo % OoooooooOO . iIii1I11I1II1 - I1IiiI
 def get_stats ( self , summary , html ) :
  oOo0O0 = self . last_rate_check
  o000OOo00o0 = self . last_packet_count
  II11ii = self . last_byte_count
  self . last_rate_check = lisp_get_timestamp ( )
  self . last_packet_count = self . packet_count
  self . last_byte_count = self . byte_count
  if 90 - 90: i1IIi
  O0O0Oo = self . last_rate_check - oOo0O0
  if ( O0O0Oo == 0 ) :
   oOoO00o0 = 0
   I1IiiiI1Ii1i = 0
  else :
   oOoO00o0 = int ( ( self . packet_count - o000OOo00o0 ) / O0O0Oo )
   I1IiiiI1Ii1i = ( self . byte_count - II11ii ) / O0O0Oo
   I1IiiiI1Ii1i = ( I1IiiiI1Ii1i * 8 ) / 1000000
   I1IiiiI1Ii1i = round ( I1IiiiI1Ii1i , 2 )
   if 76 - 76: o0oOOo0O0Ooo
   if 80 - 80: OOooOOo
   if 15 - 15: OOooOOo . OoOoOO00 / oO0o . I1ii11iIi11i % OoO0O00 - oO0o
   if 21 - 21: ooOoO0o . o0oOOo0O0Ooo . oO0o . i1IIi
   if 96 - 96: Ii1I % I11i * OoooooooOO . I1IiiI . iIii1I11I1II1
  IiiIIi = self . normalize ( self . packet_count )
  OO00o0oo0 = self . normalize ( self . byte_count )
  if 31 - 31: iIii1I11I1II1 * OoO0O00 - I11i . OoO0O00 % iIii1I11I1II1
  if 92 - 92: oO0o
  if 45 - 45: I1Ii111 / O0 * OOooOOo / II111iiii % iIii1I11I1II1
  if 48 - 48: ooOoO0o * I1Ii111 * ooOoO0o - Ii1I % OoooooooOO
  if 18 - 18: OoOoOO00 % OoOoOO00 . o0oOOo0O0Ooo
  if ( summary ) :
   O0Ooo000 = "<br>" if html else ""
   IiiIIi , OO00o0oo0 = self . stat_colors ( IiiIIi , OO00o0oo0 , html )
   oOoO00O00OO0000 = "packet-count: {}{}byte-count: {}" . format ( IiiIIi , O0Ooo000 , OO00o0oo0 )
   iiIIi11 = "packet-rate: {} pps\nbit-rate: {} Mbps" . format ( oOoO00o0 , I1IiiiI1Ii1i )
   if 32 - 32: I1IiiI / i1IIi / I1ii11iIi11i % i1IIi . ooOoO0o % I1ii11iIi11i
   if ( html != "" ) : iiIIi11 = lisp_span ( oOoO00O00OO0000 , iiIIi11 )
  else :
   OOO00o00o = str ( oOoO00o0 )
   OOoO00O = str ( I1IiiiI1Ii1i )
   if ( html ) :
    IiiIIi = lisp_print_cour ( IiiIIi )
    OOO00o00o = lisp_print_cour ( OOO00o00o )
    OO00o0oo0 = lisp_print_cour ( OO00o0oo0 )
    OOoO00O = lisp_print_cour ( OOoO00O )
    if 16 - 16: I1IiiI % OoO0O00 . ooOoO0o / OoooooooOO
   O0Ooo000 = "<br>" if html else ", "
   if 8 - 8: I1Ii111 % OoO0O00 . I1IiiI - OoOoOO00 + i1IIi / iIii1I11I1II1
   iiIIi11 = ( "packet-count: {}{}packet-rate: {} pps{}byte-count: " + "{}{}bit-rate: {} mbps" ) . format ( IiiIIi , O0Ooo000 , OOO00o00o , O0Ooo000 , OO00o0oo0 , O0Ooo000 ,
   # I1IiiI + OOooOOo / Ii1I % i11iIiiIii - I1Ii111 % I11i
 OOoO00O )
   if 49 - 49: I11i * i1IIi - iII111i
  return ( iiIIi11 )
  if 98 - 98: iIii1I11I1II1 - I11i % i11iIiiIii * I1IiiI / OoOoOO00 * ooOoO0o
  if 78 - 78: i11iIiiIii % oO0o % Ii1I / I1Ii111 / I1Ii111
  if 20 - 20: iII111i / I11i / iIii1I11I1II1
  if 94 - 94: i11iIiiIii % I1ii11iIi11i % IiII - I1Ii111
  if 55 - 55: I11i - ooOoO0o - iIii1I11I1II1 + I1ii11iIi11i / IiII
  if 49 - 49: I1ii11iIi11i
  if 91 - 91: OOooOOo % iII111i
  if 40 - 40: i11iIiiIii . II111iiii / OoOoOO00 + OoooooooOO + i1IIi . O0
lisp_decap_stats = {
 "good-packets" : lisp_stats ( ) , "ICV-error" : lisp_stats ( ) ,
 "checksum-error" : lisp_stats ( ) , "lisp-header-error" : lisp_stats ( ) ,
 "no-decrypt-key" : lisp_stats ( ) , "bad-inner-version" : lisp_stats ( ) ,
 "outer-header-error" : lisp_stats ( )
 }
if 39 - 39: I1ii11iIi11i
if 26 - 26: oO0o . I1Ii111 % I11i
if 85 - 85: II111iiii / o0oOOo0O0Ooo . iIii1I11I1II1 . OoooooooOO / Ii1I
if 18 - 18: i11iIiiIii + o0oOOo0O0Ooo . i11iIiiIii
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
  if 50 - 50: IiII / OoooooooOO . I11i
  if ( recurse == False ) : return
  if 93 - 93: OOooOOo / OoooooooOO % iII111i % Ii1I / I1Ii111 % OOooOOo
  if 25 - 25: i1IIi % Oo0Ooo . i1IIi * OoOoOO00 . Ii1I % OoO0O00
  if 47 - 47: o0oOOo0O0Ooo - i11iIiiIii / OoooooooOO
  if 93 - 93: I1IiiI * II111iiii * O0 % o0oOOo0O0Ooo + oO0o / ooOoO0o
  if 79 - 79: OoO0O00 + ooOoO0o / oO0o % I1ii11iIi11i
  if 77 - 77: Ii1I / Ii1I / I1ii11iIi11i
  Oooo0Oo00O00 = lisp_get_default_route_next_hops ( )
  if ( Oooo0Oo00O00 == [ ] or len ( Oooo0Oo00O00 ) == 1 ) : return
  if 21 - 21: o0oOOo0O0Ooo . i11iIiiIii % OoooooooOO * O0
  self . rloc_next_hop = Oooo0Oo00O00 [ 0 ]
  i1OooO00oO00o = self
  for O0o0 in Oooo0Oo00O00 [ 1 : : ] :
   iII111 = lisp_rloc ( False )
   iII111 = copy . deepcopy ( self )
   iII111 . rloc_next_hop = O0o0
   i1OooO00oO00o . next_rloc = iII111
   i1OooO00oO00o = iII111
   if 95 - 95: I11i * II111iiii * Ii1I
   if 82 - 82: iII111i + i11iIiiIii + I1ii11iIi11i * Ii1I + I11i
   if 13 - 13: Ii1I
 def up_state ( self ) :
  return ( self . state == LISP_RLOC_UP_STATE )
  if 13 - 13: o0oOOo0O0Ooo - OoOoOO00 . O0
  if 57 - 57: IiII % iII111i
 def unreach_state ( self ) :
  return ( self . state == LISP_RLOC_UNREACH_STATE )
  if 21 - 21: OoOoOO00
  if 86 - 86: O0 . O0 - I1Ii111
 def no_echoed_nonce_state ( self ) :
  return ( self . state == LISP_RLOC_NO_ECHOED_NONCE_STATE )
  if 95 - 95: Ii1I / Ii1I * OoO0O00 . OoooooooOO . OoooooooOO * I11i
  if 76 - 76: OoooooooOO - Ii1I + IiII % OoOoOO00 / OoooooooOO
 def down_state ( self ) :
  return ( self . state in [ LISP_RLOC_DOWN_STATE , LISP_RLOC_ADMIN_DOWN_STATE ] )
  if 55 - 55: i11iIiiIii - IiII * OOooOOo + II111iiii . I1ii11iIi11i / O0
  if 16 - 16: II111iiii . Oo0Ooo * I1Ii111 + o0oOOo0O0Ooo - i11iIiiIii
  if 98 - 98: II111iiii - i1IIi - ooOoO0o
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
  if 36 - 36: IiII + o0oOOo0O0Ooo
  if 81 - 81: OOooOOo / I11i % oO0o + ooOoO0o
 def print_rloc ( self , indent ) :
  OOOO0O00o = lisp_print_elapsed ( self . uptime )
  lprint ( "{}rloc {}, uptime {}, {}, parms {}/{}/{}/{}" . format ( indent ,
 red ( self . rloc . print_address ( ) , False ) , OOOO0O00o , self . print_state ( ) ,
 self . priority , self . weight , self . mpriority , self . mweight ) )
  if 10 - 10: oO0o / i11iIiiIii
  if 73 - 73: OoO0O00 - i1IIi
 def print_rloc_name ( self , cour = False ) :
  if ( self . rloc_name == None ) : return ( "" )
  i1OOO = self . rloc_name
  if ( cour ) : i1OOO = lisp_print_cour ( i1OOO )
  return ( 'rloc-name: {}' . format ( blue ( i1OOO , cour ) ) )
  if 52 - 52: I1ii11iIi11i
  if 4 - 4: Ii1I - iII111i + i1IIi - I1Ii111 / iII111i . Oo0Ooo
 def store_rloc_from_record ( self , rloc_record , nonce , source ) :
  Iiiii = LISP_DATA_PORT
  self . rloc . copy_address ( rloc_record . rloc )
  self . rloc_name = rloc_record . rloc_name
  if 18 - 18: oO0o % iIii1I11I1II1 + ooOoO0o
  if 34 - 34: I1IiiI - OoooooooOO . IiII - OOooOOo % IiII
  if 19 - 19: IiII + I1ii11iIi11i % Oo0Ooo
  if 32 - 32: OOooOOo
  Oo0o0o0oo = self . rloc
  if ( Oo0o0o0oo . is_null ( ) == False ) :
   iiI = lisp_get_nat_info ( Oo0o0o0oo , self . rloc_name )
   if ( iiI ) :
    Iiiii = iiI . port
    oOOooO0OO = lisp_nat_state_info [ self . rloc_name ] [ 0 ]
    ooOOo0o = Oo0o0o0oo . print_address_no_iid ( )
    ooOOo00o0ooO = red ( ooOOo0o , False )
    iIiII1ii1i1 = "" if self . rloc_name == None else blue ( self . rloc_name , False )
    if 12 - 12: i1IIi - oO0o . Ii1I
    if 31 - 31: I11i
    if 60 - 60: Oo0Ooo - iII111i . II111iiii % ooOoO0o / OoooooooOO / iIii1I11I1II1
    if 23 - 23: I11i + iIii1I11I1II1
    if 60 - 60: O0 * I1IiiI + o0oOOo0O0Ooo * OoO0O00 + o0oOOo0O0Ooo / i11iIiiIii
    if 54 - 54: i11iIiiIii . iII111i * i1IIi
    if ( iiI . timed_out ( ) ) :
     lprint ( ( "    Matched stored NAT state timed out for " + "RLOC {}:{}, {}" ) . format ( ooOOo00o0ooO , Iiiii , iIiII1ii1i1 ) )
     if 68 - 68: Oo0Ooo
     if 20 - 20: IiII + i11iIiiIii * OOooOOo
     iiI = None if ( iiI == oOOooO0OO ) else oOOooO0OO
     if ( iiI and iiI . timed_out ( ) ) :
      Iiiii = iiI . port
      ooOOo00o0ooO = red ( iiI . address , False )
      lprint ( ( "    Youngest stored NAT state timed out " + " for RLOC {}:{}, {}" ) . format ( ooOOo00o0ooO , Iiiii ,
      # I1Ii111 + O0
 iIiII1ii1i1 ) )
      iiI = None
      if 89 - 89: Oo0Ooo - OoO0O00 % O0
      if 54 - 54: ooOoO0o + I1IiiI - I1ii11iIi11i * OOooOOo
      if 100 - 100: OoO0O00 * oO0o + I1IiiI - o0oOOo0O0Ooo . o0oOOo0O0Ooo % OoO0O00
      if 65 - 65: OoooooooOO / OoOoOO00 + I1IiiI - II111iiii / OoOoOO00
      if 69 - 69: i11iIiiIii
      if 77 - 77: I1ii11iIi11i % OoooooooOO - Oo0Ooo - Ii1I + I11i
      if 93 - 93: I1IiiI % O0 * OoO0O00 % OoOoOO00 . I1Ii111 * I1IiiI
    if ( iiI ) :
     if ( iiI . address != ooOOo0o ) :
      lprint ( "RLOC conflict, RLOC-record {}, NAT state {}" . format ( ooOOo00o0ooO , red ( iiI . address , False ) ) )
      if 95 - 95: IiII + o0oOOo0O0Ooo - o0oOOo0O0Ooo
      self . rloc . store_address ( iiI . address )
      if 83 - 83: ooOoO0o
     ooOOo00o0ooO = red ( iiI . address , False )
     Iiiii = iiI . port
     lprint ( "    Use NAT translated RLOC {}:{} for {}" . format ( ooOOo00o0ooO , Iiiii , iIiII1ii1i1 ) )
     if 59 - 59: I1ii11iIi11i
     self . store_translated_rloc ( Oo0o0o0oo , Iiiii )
     if 26 - 26: I11i . Ii1I
     if 94 - 94: ooOoO0o . I1IiiI + IiII % I1IiiI / o0oOOo0O0Ooo % o0oOOo0O0Ooo
     if 21 - 21: O0 / OOooOOo - II111iiii + I1ii11iIi11i / OoooooooOO
     if 81 - 81: i11iIiiIii / Oo0Ooo * i1IIi + OoO0O00 + O0 % I1ii11iIi11i
  self . geo = rloc_record . geo
  self . elp = rloc_record . elp
  self . json = rloc_record . json
  if 3 - 3: i11iIiiIii * IiII . Oo0Ooo % OoOoOO00 * I11i . iII111i
  if 80 - 80: I11i - IiII
  if 40 - 40: OOooOOo * I1IiiI % I11i . I1Ii111 % O0 . O0
  if 14 - 14: ooOoO0o . OoOoOO00 + ooOoO0o * OoOoOO00 . OoOoOO00 * Oo0Ooo
  self . rle = rloc_record . rle
  if ( self . rle ) :
   for I1I1iiI in self . rle . rle_nodes :
    i1OOO = I1I1iiI . rloc_name
    iiI = lisp_get_nat_info ( I1I1iiI . address , i1OOO )
    if ( iiI == None ) : continue
    if 40 - 40: OoooooooOO
    Iiiii = iiI . port
    OOO0Oo0Oo = i1OOO
    if ( OOO0Oo0Oo ) : OOO0Oo0Oo = blue ( i1OOO , False )
    if 14 - 14: o0oOOo0O0Ooo / OOooOOo . OoOoOO00 % iIii1I11I1II1 % OoOoOO00
    lprint ( ( "      Store translated encap-port {} for RLE-" + "node {}, rloc-name '{}'" ) . format ( Iiiii ,
    # Oo0Ooo / II111iiii - Oo0Ooo - OoOoOO00 - OoOoOO00 / Ii1I
 I1I1iiI . address . print_address_no_iid ( ) , OOO0Oo0Oo ) )
    I1I1iiI . translated_port = Iiiii
    if 92 - 92: iIii1I11I1II1
    if 21 - 21: I1IiiI
    if 69 - 69: OoooooooOO + iII111i
  self . priority = rloc_record . priority
  self . mpriority = rloc_record . mpriority
  self . weight = rloc_record . weight
  self . mweight = rloc_record . mweight
  if ( rloc_record . reach_bit and rloc_record . local_bit and
 rloc_record . probe_bit == False ) : self . state = LISP_RLOC_UP_STATE
  if 29 - 29: ooOoO0o * I1IiiI / Oo0Ooo / I1ii11iIi11i
  if 74 - 74: I1ii11iIi11i - ooOoO0o / OoOoOO00 - OoooooooOO * oO0o
  if 45 - 45: o0oOOo0O0Ooo . I1Ii111 % Ii1I
  if 42 - 42: Oo0Ooo + i11iIiiIii - OOooOOo . I1ii11iIi11i % I1Ii111 . I1ii11iIi11i
  o0Oo = source . is_exact_match ( rloc_record . rloc ) if source != None else None
  if 1 - 1: II111iiii + O0 % oO0o % II111iiii / OOooOOo
  if ( rloc_record . keys != None and o0Oo ) :
   Iiii11 = rloc_record . keys [ 1 ]
   if ( Iiii11 != None ) :
    ooOOo0o = rloc_record . rloc . print_address_no_iid ( ) + ":" + str ( Iiiii )
    if 59 - 59: I1IiiI
    Iiii11 . add_key_by_rloc ( ooOOo0o , True )
    lprint ( "    Store encap-keys for nonce 0x{}, RLOC {}" . format ( lisp_hex_string ( nonce ) , red ( ooOOo0o , False ) ) )
    if 78 - 78: iIii1I11I1II1
    if 64 - 64: OoOoOO00 - oO0o
    if 8 - 8: i11iIiiIii - iIii1I11I1II1 / I1Ii111 . i11iIiiIii % o0oOOo0O0Ooo / oO0o
  return ( Iiiii )
  if 36 - 36: IiII
  if 53 - 53: OoooooooOO / I1IiiI % I11i + Oo0Ooo
 def store_translated_rloc ( self , rloc , port ) :
  self . rloc . copy_address ( rloc )
  self . translated_rloc . copy_address ( rloc )
  self . translated_port = port
  if 15 - 15: O0
  if 75 - 75: iII111i / OoOoOO00
 def is_rloc_translated ( self ) :
  return ( self . translated_rloc . is_null ( ) == False )
  if 2 - 2: i1IIi + oO0o % iII111i % I1ii11iIi11i + ooOoO0o . iII111i
  if 26 - 26: I11i + o0oOOo0O0Ooo + Ii1I % I11i
 def rloc_exists ( self ) :
  if ( self . rloc . is_null ( ) == False ) : return ( True )
  if ( self . rle_name or self . geo_name or self . elp_name or self . json_name ) :
   return ( False )
   if 95 - 95: IiII - O0 * oO0o * O0
  return ( True )
  if 47 - 47: I1IiiI
  if 20 - 20: I1Ii111
 def is_rtr ( self ) :
  return ( ( self . priority == 254 and self . mpriority == 255 and self . weight == 0 and self . mweight == 0 ) )
  if 40 - 40: OoooooooOO / o0oOOo0O0Ooo + OoOoOO00
  if 73 - 73: OOooOOo / Oo0Ooo
  if 80 - 80: OoO0O00 + I1IiiI % i1IIi / I11i % i1IIi * i11iIiiIii
 def print_state_change ( self , new_state ) :
  II11i = self . print_state ( )
  O0I11IIIII = "{} -> {}" . format ( II11i , new_state )
  if ( new_state == "up" and self . unreach_state ( ) ) :
   O0I11IIIII = bold ( O0I11IIIII , False )
   if 6 - 6: II111iiii / o0oOOo0O0Ooo * O0 % I1ii11iIi11i
  return ( O0I11IIIII )
  if 11 - 11: I1Ii111
  if 70 - 70: Ii1I
 def print_rloc_probe_rtt ( self ) :
  if ( self . rloc_probe_rtt == - 1 ) : return ( "none" )
  return ( self . rloc_probe_rtt )
  if 22 - 22: Ii1I
  if 59 - 59: I1ii11iIi11i
 def print_recent_rloc_probe_rtts ( self ) :
  oO00o = str ( self . recent_rloc_probe_rtts )
  oO00o = oO00o . replace ( "-1" , "?" )
  return ( oO00o )
  if 53 - 53: o0oOOo0O0Ooo * Oo0Ooo % I1IiiI
  if 68 - 68: Oo0Ooo
 def compute_rloc_probe_rtt ( self ) :
  i1OooO00oO00o = self . rloc_probe_rtt
  self . rloc_probe_rtt = - 1
  if ( self . last_rloc_probe_reply == None ) : return
  if ( self . last_rloc_probe == None ) : return
  self . rloc_probe_rtt = self . last_rloc_probe_reply - self . last_rloc_probe
  self . rloc_probe_rtt = round ( self . rloc_probe_rtt , 3 )
  oOOO0o0O = self . recent_rloc_probe_rtts
  self . recent_rloc_probe_rtts = [ i1OooO00oO00o ] + oOOO0o0O [ 0 : - 1 ]
  if 50 - 50: i1IIi . iIii1I11I1II1 % OoO0O00
  if 45 - 45: OoooooooOO . O0 * oO0o + IiII
 def print_rloc_probe_hops ( self ) :
  return ( self . rloc_probe_hops )
  if 18 - 18: II111iiii . O0 - I11i / I11i
  if 71 - 71: OoOoOO00 + iIii1I11I1II1 - II111iiii / i1IIi
 def print_recent_rloc_probe_hops ( self ) :
  I111II = str ( self . recent_rloc_probe_hops )
  return ( I111II )
  if 22 - 22: I1Ii111 - OOooOOo * i1IIi
  if 88 - 88: ooOoO0o + iIii1I11I1II1 + OoO0O00 * I1Ii111 + oO0o
 def store_rloc_probe_hops ( self , to_hops , from_ttl ) :
  if ( to_hops == 0 ) :
   to_hops = "?"
  elif ( to_hops < LISP_RLOC_PROBE_TTL / 2 ) :
   to_hops = "!"
  else :
   to_hops = str ( LISP_RLOC_PROBE_TTL - to_hops )
   if 39 - 39: ooOoO0o - oO0o + OoOoOO00 - oO0o - Ii1I % I1Ii111
  if ( from_ttl < LISP_RLOC_PROBE_TTL / 2 ) :
   O000o00O0OOoo = "!"
  else :
   O000o00O0OOoo = str ( LISP_RLOC_PROBE_TTL - from_ttl )
   if 32 - 32: I1Ii111 . I1IiiI
   if 78 - 78: OoOoOO00 . I1ii11iIi11i / o0oOOo0O0Ooo
  i1OooO00oO00o = self . rloc_probe_hops
  self . rloc_probe_hops = to_hops + "/" + O000o00O0OOoo
  oOOO0o0O = self . recent_rloc_probe_hops
  self . recent_rloc_probe_hops = [ i1OooO00oO00o ] + oOOO0o0O [ 0 : - 1 ]
  if 57 - 57: IiII % O0 * I1ii11iIi11i
  if 61 - 61: O0
 def process_rloc_probe_reply ( self , nonce , eid , group , hop_count , ttl ) :
  Oo0o0o0oo = self
  while ( True ) :
   if ( Oo0o0o0oo . last_rloc_probe_nonce == nonce ) : break
   Oo0o0o0oo = Oo0o0o0oo . next_rloc
   if ( Oo0o0o0oo == None ) :
    lprint ( "    No matching nonce state found for nonce 0x{}" . format ( lisp_hex_string ( nonce ) ) )
    if 51 - 51: I1Ii111 - I11i % o0oOOo0O0Ooo * Oo0Ooo - oO0o + II111iiii
    return
    if 7 - 7: oO0o
    if 98 - 98: Ii1I + oO0o + i1IIi + IiII % IiII
    if 79 - 79: oO0o % I11i * I11i . OOooOOo % OoooooooOO
  Oo0o0o0oo . last_rloc_probe_reply = lisp_get_timestamp ( )
  Oo0o0o0oo . compute_rloc_probe_rtt ( )
  oOoOOOo0oo0 = Oo0o0o0oo . print_state_change ( "up" )
  if ( Oo0o0o0oo . state != LISP_RLOC_UP_STATE ) :
   lisp_update_rtr_updown ( Oo0o0o0oo . rloc , True )
   Oo0o0o0oo . state = LISP_RLOC_UP_STATE
   Oo0o0o0oo . last_state_change = lisp_get_timestamp ( )
   ooooOoo000O = lisp_map_cache . lookup_cache ( eid , True )
   if ( ooooOoo000O ) : lisp_write_ipc_map_cache ( True , ooooOoo000O )
   if 87 - 87: iII111i - OoO0O00 . Ii1I / ooOoO0o
   if 88 - 88: O0 % OOooOOo . iII111i
  Oo0o0o0oo . store_rloc_probe_hops ( hop_count , ttl )
  if 40 - 40: O0 . Ii1I % IiII % I1ii11iIi11i - OoOoOO00
  oo00OO0Oooo = bold ( "RLOC-probe reply" , False )
  ooOOo0o = Oo0o0o0oo . rloc . print_address_no_iid ( )
  oooOoo = bold ( str ( Oo0o0o0oo . print_rloc_probe_rtt ( ) ) , False )
  i111 = ":{}" . format ( self . translated_port ) if self . translated_port != 0 else ""
  if 36 - 36: I1Ii111 . OoooooooOO - i1IIi % iII111i - II111iiii * i11iIiiIii
  O0o0 = ""
  if ( Oo0o0o0oo . rloc_next_hop != None ) :
   i1 , oOO0OoOoOoo = Oo0o0o0oo . rloc_next_hop
   O0o0 = ", nh {}({})" . format ( oOO0OoOoOoo , i1 )
   if 88 - 88: Ii1I * OOooOOo / iII111i % iII111i % o0oOOo0O0Ooo + II111iiii
   if 89 - 89: I1IiiI - OoooooooOO / I11i . ooOoO0o
  Oo0ooo0Ooo = green ( lisp_print_eid_tuple ( eid , group ) , False )
  lprint ( ( "    Received {} from {}{} for {}, {}, rtt {}{}, " + "to-ttl/from-ttl {}" ) . format ( oo00OO0Oooo , red ( ooOOo0o , False ) , i111 , Oo0ooo0Ooo ,
  # I1ii11iIi11i . Ii1I . iIii1I11I1II1 * I1ii11iIi11i / Ii1I
 oOoOOOo0oo0 , oooOoo , O0o0 , str ( hop_count ) + "/" + str ( ttl ) ) )
  if 74 - 74: Oo0Ooo * I1Ii111
  if ( Oo0o0o0oo . rloc_next_hop == None ) : return
  if 72 - 72: OoOoOO00 + O0 - IiII * ooOoO0o
  if 20 - 20: II111iiii % OoOoOO00 * i11iIiiIii
  if 68 - 68: IiII / ooOoO0o
  if 100 - 100: ooOoO0o / I1IiiI
  Oo0o0o0oo = None
  O00OOO0 = None
  while ( True ) :
   Oo0o0o0oo = self if Oo0o0o0oo == None else Oo0o0o0oo . next_rloc
   if ( Oo0o0o0oo == None ) : break
   if ( Oo0o0o0oo . up_state ( ) == False ) : continue
   if ( Oo0o0o0oo . rloc_probe_rtt == - 1 ) : continue
   if 66 - 66: OoooooooOO / iII111i / I1IiiI % ooOoO0o / OoO0O00 + OOooOOo
   if ( O00OOO0 == None ) : O00OOO0 = Oo0o0o0oo
   if ( Oo0o0o0oo . rloc_probe_rtt < O00OOO0 . rloc_probe_rtt ) : O00OOO0 = Oo0o0o0oo
   if 64 - 64: i1IIi
   if 26 - 26: OoOoOO00 / o0oOOo0O0Ooo . OOooOOo + I1IiiI + Ii1I . iII111i
  if ( O00OOO0 != None ) :
   i1 , oOO0OoOoOoo = O00OOO0 . rloc_next_hop
   O0o0 = bold ( "nh {}({})" . format ( oOO0OoOoOoo , i1 ) , False )
   lprint ( "    Install host-route via best {}" . format ( O0o0 ) )
   lisp_install_host_route ( ooOOo0o , None , False )
   lisp_install_host_route ( ooOOo0o , oOO0OoOoOoo , True )
   if 89 - 89: I1Ii111 * I1IiiI . i1IIi - iIii1I11I1II1 * I1Ii111
   if 5 - 5: OoOoOO00 % i1IIi
   if 31 - 31: Oo0Ooo * O0 . OOooOOo . o0oOOo0O0Ooo + OoO0O00 + II111iiii
 def add_to_rloc_probe_list ( self , eid , group ) :
  ooOOo0o = self . rloc . print_address_no_iid ( )
  Iiiii = self . translated_port
  if ( Iiiii != 0 ) : ooOOo0o += ":" + str ( Iiiii )
  if 76 - 76: Oo0Ooo + I1IiiI - O0
  if ( lisp_rloc_probe_list . has_key ( ooOOo0o ) == False ) :
   lisp_rloc_probe_list [ ooOOo0o ] = [ ]
   if 58 - 58: IiII * i1IIi . I1IiiI - iII111i
   if 73 - 73: Oo0Ooo . OoOoOO00
  if ( group . is_null ( ) ) : group . instance_id = 0
  for Oo0O , Oo0ooo0Ooo , o0 in lisp_rloc_probe_list [ ooOOo0o ] :
   if ( Oo0ooo0Ooo . is_exact_match ( eid ) and o0 . is_exact_match ( group ) ) :
    if ( Oo0O == self ) :
     if ( lisp_rloc_probe_list [ ooOOo0o ] == [ ] ) :
      lisp_rloc_probe_list . pop ( ooOOo0o )
      if 50 - 50: IiII / o0oOOo0O0Ooo
     return
     if 9 - 9: Oo0Ooo - OoO0O00 + iII111i / OoooooooOO
    lisp_rloc_probe_list [ ooOOo0o ] . remove ( [ Oo0O , Oo0ooo0Ooo , o0 ] )
    break
    if 52 - 52: O0
    if 34 - 34: OoooooooOO + OoOoOO00 - Oo0Ooo . OOooOOo * iIii1I11I1II1
  lisp_rloc_probe_list [ ooOOo0o ] . append ( [ self , eid , group ] )
  if 93 - 93: i11iIiiIii / Oo0Ooo * OoOoOO00 / ooOoO0o + OoO0O00 * OOooOOo
  if 81 - 81: IiII * iII111i + i1IIi + I1Ii111 / OoO0O00
  if 83 - 83: oO0o / OoO0O00
  if 34 - 34: OoooooooOO - i1IIi * O0
  if 83 - 83: I1IiiI + OoO0O00
  Oo0o0o0oo = lisp_rloc_probe_list [ ooOOo0o ] [ 0 ] [ 0 ]
  if ( Oo0o0o0oo . state == LISP_RLOC_UNREACH_STATE ) :
   self . state = LISP_RLOC_UNREACH_STATE
   self . last_state_change = lisp_get_timestamp ( )
   if 41 - 41: Ii1I + II111iiii . OOooOOo * I1Ii111 / II111iiii
   if 32 - 32: Oo0Ooo - Ii1I % o0oOOo0O0Ooo
   if 15 - 15: iIii1I11I1II1 * I1ii11iIi11i / ooOoO0o * oO0o % OOooOOo
 def delete_from_rloc_probe_list ( self , eid , group ) :
  ooOOo0o = self . rloc . print_address_no_iid ( )
  Iiiii = self . translated_port
  if ( Iiiii != 0 ) : ooOOo0o += ":" + str ( Iiiii )
  if ( lisp_rloc_probe_list . has_key ( ooOOo0o ) == False ) : return
  if 62 - 62: Ii1I / Oo0Ooo . OoO0O00 - OOooOOo
  oOOOOoOO0Oo = [ ]
  for iiIIIIiI111 in lisp_rloc_probe_list [ ooOOo0o ] :
   if ( iiIIIIiI111 [ 0 ] != self ) : continue
   if ( iiIIIIiI111 [ 1 ] . is_exact_match ( eid ) == False ) : continue
   if ( iiIIIIiI111 [ 2 ] . is_exact_match ( group ) == False ) : continue
   oOOOOoOO0Oo = iiIIIIiI111
   break
   if 84 - 84: Oo0Ooo * I1Ii111 - o0oOOo0O0Ooo % Ii1I
  if ( oOOOOoOO0Oo == [ ] ) : return
  if 69 - 69: I11i + OoOoOO00 - i11iIiiIii * O0 % O0
  try :
   lisp_rloc_probe_list [ ooOOo0o ] . remove ( oOOOOoOO0Oo )
   if ( lisp_rloc_probe_list [ ooOOo0o ] == [ ] ) :
    lisp_rloc_probe_list . pop ( ooOOo0o )
    if 81 - 81: I11i - o0oOOo0O0Ooo % Ii1I / I1Ii111 * II111iiii
  except :
   return
   if 40 - 40: OoO0O00 . i11iIiiIii
   if 36 - 36: o0oOOo0O0Ooo * iII111i / I1ii11iIi11i % i1IIi % I1ii11iIi11i + i11iIiiIii
   if 24 - 24: I1Ii111 / ooOoO0o - i11iIiiIii
 def print_rloc_probe_state ( self , trailing_linefeed ) :
  I1i = ""
  Oo0o0o0oo = self
  while ( True ) :
   Iii111II1I11I = Oo0o0o0oo . last_rloc_probe
   if ( Iii111II1I11I == None ) : Iii111II1I11I = 0
   IIii = Oo0o0o0oo . last_rloc_probe_reply
   if ( IIii == None ) : IIii = 0
   oooOoo = Oo0o0o0oo . print_rloc_probe_rtt ( )
   o00oOOO = space ( 4 )
   if 56 - 56: II111iiii * iIii1I11I1II1 % I1ii11iIi11i
   if ( Oo0o0o0oo . rloc_next_hop == None ) :
    I1i += "RLOC-Probing:\n"
   else :
    i1 , oOO0OoOoOoo = Oo0o0o0oo . rloc_next_hop
    I1i += "RLOC-Probing for nh {}({}):\n" . format ( oOO0OoOoOoo , i1 )
    if 83 - 83: i1IIi . i11iIiiIii / iII111i
    if 28 - 28: i1IIi - iII111i + o0oOOo0O0Ooo / Oo0Ooo * oO0o
   I1i += ( "{}RLOC-probe request sent: {}\n{}RLOC-probe reply " + "received: {}, rtt {}" ) . format ( o00oOOO , lisp_print_elapsed ( Iii111II1I11I ) ,
   # I11i
 o00oOOO , lisp_print_elapsed ( IIii ) , oooOoo )
   if 42 - 42: OOooOOo * ooOoO0o / i1IIi . i11iIiiIii - oO0o - Ii1I
   if ( trailing_linefeed ) : I1i += "\n"
   if 5 - 5: i1IIi + II111iiii . ooOoO0o
   Oo0o0o0oo = Oo0o0o0oo . next_rloc
   if ( Oo0o0o0oo == None ) : break
   I1i += "\n"
   if 21 - 21: i1IIi
  return ( I1i )
  if 96 - 96: OoOoOO00 * OoOoOO00 % OoO0O00 * iII111i
  if 51 - 51: I1IiiI + i11iIiiIii + iII111i
 def get_encap_keys ( self ) :
  Iiiii = "4341" if self . translated_port == 0 else str ( self . translated_port )
  if 57 - 57: Oo0Ooo . oO0o
  ooOOo0o = self . rloc . print_address_no_iid ( ) + ":" + Iiiii
  if 52 - 52: IiII % OoO0O00 - OoO0O00 . I1IiiI + OoO0O00 * ooOoO0o
  try :
   i1iIi = lisp_crypto_keys_by_rloc_encap [ ooOOo0o ]
   if ( i1iIi [ 1 ] ) : return ( i1iIi [ 1 ] . encrypt_key , i1iIi [ 1 ] . icv_key )
   return ( None , None )
  except :
   return ( None , None )
   if 44 - 44: iIii1I11I1II1 / Ii1I - oO0o % i11iIiiIii
   if 65 - 65: I1ii11iIi11i * Oo0Ooo / Ii1I . OOooOOo * iIii1I11I1II1 + Oo0Ooo
   if 44 - 44: ooOoO0o * iII111i * IiII % o0oOOo0O0Ooo
 def rloc_recent_rekey ( self ) :
  Iiiii = "4341" if self . translated_port == 0 else str ( self . translated_port )
  if 45 - 45: OoOoOO00 % o0oOOo0O0Ooo + IiII / i11iIiiIii
  ooOOo0o = self . rloc . print_address_no_iid ( ) + ":" + Iiiii
  if 29 - 29: iIii1I11I1II1 . OoO0O00 / I1IiiI
  try :
   Iiii11 = lisp_crypto_keys_by_rloc_encap [ ooOOo0o ] [ 1 ]
   if ( Iiii11 == None ) : return ( False )
   if ( Iiii11 . last_rekey == None ) : return ( True )
   return ( time . time ( ) - Iiii11 . last_rekey < 1 )
  except :
   return ( False )
   if 38 - 38: Oo0Ooo / Oo0Ooo % ooOoO0o
   if 56 - 56: oO0o / iII111i % i1IIi * II111iiii . Ii1I
   if 10 - 10: ooOoO0o - I1ii11iIi11i
   if 82 - 82: o0oOOo0O0Ooo / I11i - I11i / O0 * I1IiiI / OoO0O00
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
  if 71 - 71: I11i % I11i - i11iIiiIii + iIii1I11I1II1 / iII111i
  if 63 - 63: O0 * i11iIiiIii / IiII / IiII
 def print_mapping ( self , eid_indent , rloc_indent ) :
  OOOO0O00o = lisp_print_elapsed ( self . uptime )
  i1i11Ii1 = "" if self . group . is_null ( ) else ", group {}" . format ( self . group . print_prefix ( ) )
  if 72 - 72: i11iIiiIii * OoOoOO00 % oO0o / I1Ii111
  lprint ( "{}eid {}{}, uptime {}, {} rlocs:" . format ( eid_indent ,
 green ( self . eid . print_prefix ( ) , False ) , i1i11Ii1 , OOOO0O00o ,
 len ( self . rloc_set ) ) )
  for Oo0o0o0oo in self . rloc_set : Oo0o0o0oo . print_rloc ( rloc_indent )
  if 9 - 9: iIii1I11I1II1 . IiII
  if 42 - 42: i1IIi / Ii1I * I1ii11iIi11i
 def print_eid_tuple ( self ) :
  return ( lisp_print_eid_tuple ( self . eid , self . group ) )
  if 9 - 9: I11i % i1IIi / i1IIi / OoO0O00
  if 46 - 46: I1Ii111 * II111iiii + II111iiii * O0 % II111iiii
 def print_ttl ( self ) :
  Ii1 = self . map_cache_ttl
  if ( Ii1 == None ) : return ( "forever" )
  if 37 - 37: OOooOOo . iIii1I11I1II1 / O0 . ooOoO0o + OOooOOo - OoooooooOO
  if ( Ii1 >= 3600 ) :
   if ( ( Ii1 % 3600 ) == 0 ) :
    Ii1 = str ( Ii1 / 3600 ) + " hours"
   else :
    Ii1 = str ( Ii1 * 60 ) + " mins"
    if 96 - 96: I1Ii111 / oO0o . I1ii11iIi11i % I1IiiI * OOooOOo
  elif ( Ii1 >= 60 ) :
   if ( ( Ii1 % 60 ) == 0 ) :
    Ii1 = str ( Ii1 / 60 ) + " mins"
   else :
    Ii1 = str ( Ii1 ) + " secs"
    if 99 - 99: i11iIiiIii - I1Ii111
  else :
   Ii1 = str ( Ii1 ) + " secs"
   if 4 - 4: o0oOOo0O0Ooo - i11iIiiIii . iIii1I11I1II1 . OOooOOo % IiII
  return ( Ii1 )
  if 68 - 68: I11i / iII111i - IiII . iIii1I11I1II1 / o0oOOo0O0Ooo
  if 54 - 54: II111iiii * I1IiiI
 def has_ttl_elapsed ( self ) :
  if ( self . map_cache_ttl == None ) : return ( False )
  iIIiI1iiI = time . time ( ) - self . last_refresh_time
  if ( iIIiI1iiI >= self . map_cache_ttl ) : return ( True )
  if 49 - 49: I1ii11iIi11i
  if 31 - 31: o0oOOo0O0Ooo - OoOoOO00 + I1ii11iIi11i . oO0o - O0
  if 61 - 61: I1ii11iIi11i * II111iiii . i1IIi
  if 60 - 60: OoooooooOO % ooOoO0o * i11iIiiIii * OoooooooOO % IiII
  if 15 - 15: oO0o
  i1IIiiI1II1II = self . map_cache_ttl - ( self . map_cache_ttl / 10 )
  if ( iIIiI1iiI >= i1IIiiI1II1II ) : return ( True )
  return ( False )
  if 69 - 69: OoO0O00 - ooOoO0o / IiII . Ii1I / Ii1I + o0oOOo0O0Ooo
  if 9 - 9: IiII % I11i . I1Ii111 - I1ii11iIi11i + i11iIiiIii / I1IiiI
 def is_active ( self ) :
  if ( self . stats . last_increment == None ) : return ( False )
  iIIiI1iiI = time . time ( ) - self . stats . last_increment
  return ( iIIiI1iiI <= 60 )
  if 12 - 12: iII111i . I1IiiI * OoooooooOO
  if 80 - 80: i11iIiiIii . OoO0O00 - Oo0Ooo . OoO0O00
 def match_eid_tuple ( self , db ) :
  if ( self . eid . is_exact_match ( db . eid ) == False ) : return ( False )
  if ( self . group . is_exact_match ( db . group ) == False ) : return ( False )
  return ( True )
  if 3 - 3: oO0o - I1IiiI - OoOoOO00 * I1Ii111 * i11iIiiIii . II111iiii
  if 22 - 22: o0oOOo0O0Ooo
 def sort_rloc_set ( self ) :
  self . rloc_set . sort ( key = operator . attrgetter ( 'rloc.address' ) )
  if 45 - 45: I1Ii111 + OoooooooOO + o0oOOo0O0Ooo * II111iiii
  if 12 - 12: I1ii11iIi11i / O0
 def delete_rlocs_from_rloc_probe_list ( self ) :
  for Oo0o0o0oo in self . best_rloc_set :
   Oo0o0o0oo . delete_from_rloc_probe_list ( self . eid , self . group )
   if 18 - 18: OoOoOO00 . i11iIiiIii + i1IIi / OoooooooOO - IiII % OoO0O00
   if 47 - 47: iII111i % IiII + I1Ii111 * o0oOOo0O0Ooo * OoooooooOO
   if 100 - 100: Oo0Ooo / I1IiiI / iII111i / I1Ii111 / oO0o % o0oOOo0O0Ooo
 def build_best_rloc_set ( self ) :
  ii1II1 = self . best_rloc_set
  self . best_rloc_set = [ ]
  if ( self . rloc_set == None ) : return
  if 20 - 20: i11iIiiIii / I1Ii111
  if 5 - 5: I1IiiI * o0oOOo0O0Ooo % o0oOOo0O0Ooo + I1IiiI
  if 35 - 35: oO0o + iII111i + I11i - I1ii11iIi11i - ooOoO0o - OOooOOo
  if 77 - 77: OoooooooOO + OoooooooOO / oO0o * o0oOOo0O0Ooo / I11i
  oOO00oOOOoO = 256
  for Oo0o0o0oo in self . rloc_set :
   if ( Oo0o0o0oo . up_state ( ) ) : oOO00oOOOoO = min ( Oo0o0o0oo . priority , oOO00oOOOoO )
   if 82 - 82: OoooooooOO * O0 - ooOoO0o * Oo0Ooo % O0
   if 19 - 19: O0 * oO0o + i11iIiiIii
   if 74 - 74: OoOoOO00
   if 91 - 91: i11iIiiIii / Ii1I % OOooOOo % O0 - I11i . I11i
   if 78 - 78: i1IIi + I11i % OoooooooOO + i1IIi + iII111i % Ii1I
   if 87 - 87: ooOoO0o . iIii1I11I1II1
   if 99 - 99: Ii1I + OoooooooOO * IiII * i11iIiiIii - iIii1I11I1II1
   if 58 - 58: IiII % i1IIi . i11iIiiIii
   if 5 - 5: OoOoOO00
   if 75 - 75: OOooOOo
  for Oo0o0o0oo in self . rloc_set :
   if ( Oo0o0o0oo . priority <= oOO00oOOOoO ) :
    if ( Oo0o0o0oo . unreach_state ( ) and Oo0o0o0oo . last_rloc_probe == None ) :
     Oo0o0o0oo . last_rloc_probe = lisp_get_timestamp ( )
     if 60 - 60: ooOoO0o - II111iiii - iIii1I11I1II1
    self . best_rloc_set . append ( Oo0o0o0oo )
    if 23 - 23: I1ii11iIi11i
    if 68 - 68: OoO0O00 . oO0o / IiII - II111iiii % Oo0Ooo
    if 24 - 24: II111iiii / I1ii11iIi11i + oO0o / Ii1I + IiII % oO0o
    if 86 - 86: I1IiiI
    if 83 - 83: I11i % Ii1I + IiII % I11i / i1IIi . oO0o
    if 56 - 56: I1Ii111 - OOooOOo % o0oOOo0O0Ooo
    if 30 - 30: I1Ii111 % i1IIi
    if 98 - 98: oO0o . i11iIiiIii / Ii1I - Ii1I
  for Oo0o0o0oo in ii1II1 :
   if ( Oo0o0o0oo . priority < oOO00oOOOoO ) : continue
   Oo0o0o0oo . delete_from_rloc_probe_list ( self . eid , self . group )
   if 23 - 23: iIii1I11I1II1
  for Oo0o0o0oo in self . best_rloc_set :
   if ( Oo0o0o0oo . rloc . is_null ( ) ) : continue
   Oo0o0o0oo . add_to_rloc_probe_list ( self . eid , self . group )
   if 30 - 30: I1ii11iIi11i + OoO0O00 - O0
   if 42 - 42: I11i - I1Ii111
   if 24 - 24: i1IIi
 def select_rloc ( self , lisp_packet , ipc_socket ) :
  oOo = lisp_packet . packet
  OOOO0oooO = lisp_packet . inner_version
  OOOOO000oo0 = len ( self . best_rloc_set )
  if ( OOOOO000oo0 is 0 ) :
   self . stats . increment ( len ( oOo ) )
   return ( [ None , None , None , self . action , None , None ] )
   if 56 - 56: I1Ii111 . I1ii11iIi11i - o0oOOo0O0Ooo / i11iIiiIii * iII111i / iIii1I11I1II1
   if 49 - 49: I1IiiI / iIii1I11I1II1
  Ii111Iii1ii = 4 if lisp_load_split_pings else 0
  ooo000 = lisp_packet . hash_ports ( )
  if ( OOOO0oooO == 4 ) :
   for II11iIII1i1I in range ( 8 + Ii111Iii1ii ) :
    ooo000 = ooo000 ^ struct . unpack ( "B" , oOo [ II11iIII1i1I + 12 ] ) [ 0 ]
    if 16 - 16: O0
  elif ( OOOO0oooO == 6 ) :
   for II11iIII1i1I in range ( 0 , 32 + Ii111Iii1ii , 4 ) :
    ooo000 = ooo000 ^ struct . unpack ( "I" , oOo [ II11iIII1i1I + 8 : II11iIII1i1I + 12 ] ) [ 0 ]
    if 61 - 61: OoOoOO00 * OOooOOo
   ooo000 = ( ooo000 >> 16 ) + ( ooo000 & 0xffff )
   ooo000 = ( ooo000 >> 8 ) + ( ooo000 & 0xff )
  else :
   for II11iIII1i1I in range ( 0 , 12 + Ii111Iii1ii , 4 ) :
    ooo000 = ooo000 ^ struct . unpack ( "I" , oOo [ II11iIII1i1I : II11iIII1i1I + 4 ] ) [ 0 ]
    if 3 - 3: I1IiiI + Oo0Ooo / I1Ii111
    if 17 - 17: i11iIiiIii / Oo0Ooo . o0oOOo0O0Ooo / I1IiiI . OOooOOo
    if 10 - 10: I11i - OoOoOO00
  if ( lisp_data_plane_logging ) :
   IIIii = [ ]
   for Oo0O in self . best_rloc_set :
    if ( Oo0O . rloc . is_null ( ) ) : continue
    IIIii . append ( [ Oo0O . rloc . print_address_no_iid ( ) , Oo0O . print_state ( ) ] )
    if 100 - 100: oO0o * IiII * iII111i % iIii1I11I1II1
   dprint ( "Packet hash {}, index {}, best-rloc-list: {}" . format ( hex ( ooo000 ) , ooo000 % OOOOO000oo0 , red ( str ( IIIii ) , False ) ) )
   if 76 - 76: I11i * O0 * i1IIi
   if 27 - 27: OoOoOO00 % OoooooooOO
   if 77 - 77: Ii1I % Oo0Ooo
   if 30 - 30: iIii1I11I1II1 * Oo0Ooo * OOooOOo * ooOoO0o
   if 6 - 6: iIii1I11I1II1 / oO0o % ooOoO0o
   if 19 - 19: iIii1I11I1II1 + I11i - iIii1I11I1II1 - Ii1I . Ii1I * OoO0O00
  Oo0o0o0oo = self . best_rloc_set [ ooo000 % OOOOO000oo0 ]
  if 32 - 32: I1IiiI + OOooOOo * oO0o
  if 100 - 100: OoO0O00
  if 20 - 20: Ii1I % OoO0O00
  if 85 - 85: i1IIi % iIii1I11I1II1
  if 10 - 10: O0 . oO0o * I1IiiI
  IiIii1i11i1 = lisp_get_echo_nonce ( Oo0o0o0oo . rloc , None )
  if ( IiIii1i11i1 ) :
   IiIii1i11i1 . change_state ( Oo0o0o0oo )
   if ( Oo0o0o0oo . no_echoed_nonce_state ( ) ) :
    IiIii1i11i1 . request_nonce_sent = None
    if 21 - 21: OoooooooOO
    if 76 - 76: i1IIi * i11iIiiIii / OOooOOo + I1Ii111
    if 50 - 50: oO0o % OoOoOO00 + I1IiiI
    if 15 - 15: II111iiii - iII111i / I1ii11iIi11i
    if 81 - 81: Ii1I - i1IIi % oO0o * Oo0Ooo * OoOoOO00
    if 79 - 79: oO0o + I1IiiI % iII111i + II111iiii % OoO0O00 % iII111i
  if ( Oo0o0o0oo . up_state ( ) == False ) :
   iIIiIIiI = ooo000 % OOOOO000oo0
   oo0OOo0O = ( iIIiIIiI + 1 ) % OOOOO000oo0
   while ( oo0OOo0O != iIIiIIiI ) :
    Oo0o0o0oo = self . best_rloc_set [ oo0OOo0O ]
    if ( Oo0o0o0oo . up_state ( ) ) : break
    oo0OOo0O = ( oo0OOo0O + 1 ) % OOOOO000oo0
    if 59 - 59: OoooooooOO + I11i . oO0o
   if ( oo0OOo0O == iIIiIIiI ) :
    self . build_best_rloc_set ( )
    return ( [ None , None , None , None , None , None ] )
    if 65 - 65: I1ii11iIi11i * II111iiii % I11i + II111iiii . i1IIi / ooOoO0o
    if 74 - 74: OoOoOO00 % OoO0O00 . OoOoOO00
    if 16 - 16: OoO0O00 / Ii1I * i11iIiiIii / o0oOOo0O0Ooo + I1Ii111
    if 21 - 21: I11i % I1ii11iIi11i
    if 8 - 8: OOooOOo % OoO0O00 + O0 - o0oOOo0O0Ooo
    if 46 - 46: Oo0Ooo . ooOoO0o + OoOoOO00 - I11i / i11iIiiIii . iII111i
  Oo0o0o0oo . stats . increment ( len ( oOo ) )
  if 80 - 80: II111iiii + OoO0O00 % ooOoO0o + i11iIiiIii
  if 30 - 30: Ii1I / I1ii11iIi11i % IiII - Oo0Ooo
  if 100 - 100: IiII . I1Ii111 * oO0o % OoO0O00 . iIii1I11I1II1 * Oo0Ooo
  if 100 - 100: IiII - OoOoOO00 % iII111i
  if ( Oo0o0o0oo . rle_name and Oo0o0o0oo . rle == None ) :
   if ( lisp_rle_list . has_key ( Oo0o0o0oo . rle_name ) ) :
    Oo0o0o0oo . rle = lisp_rle_list [ Oo0o0o0oo . rle_name ]
    if 24 - 24: Oo0Ooo / OoO0O00 + i11iIiiIii
    if 81 - 81: i11iIiiIii . iIii1I11I1II1 - OoooooooOO
  if ( Oo0o0o0oo . rle ) : return ( [ None , None , None , None , Oo0o0o0oo . rle , None ] )
  if 52 - 52: O0 - I1Ii111 + oO0o % ooOoO0o . oO0o
  if 60 - 60: oO0o + o0oOOo0O0Ooo - OOooOOo % o0oOOo0O0Ooo . I11i + OoO0O00
  if 27 - 27: i11iIiiIii - I1ii11iIi11i * I1Ii111 . I1IiiI / OoO0O00 * ooOoO0o
  if 42 - 42: OOooOOo
  if ( Oo0o0o0oo . elp and Oo0o0o0oo . elp . use_elp_node ) :
   return ( [ Oo0o0o0oo . elp . use_elp_node . address , None , None , None , None ,
 None ] )
   if 36 - 36: OoooooooOO + ooOoO0o + iII111i
   if 30 - 30: i1IIi % Ii1I
   if 18 - 18: o0oOOo0O0Ooo % I1ii11iIi11i . Ii1I . O0 * II111iiii + I1ii11iIi11i
   if 45 - 45: OoO0O00 / I1ii11iIi11i * ooOoO0o * OOooOOo % i11iIiiIii * iII111i
   if 33 - 33: oO0o . iII111i + Oo0Ooo
  iIIiII1iIII1i = None if ( Oo0o0o0oo . rloc . is_null ( ) ) else Oo0o0o0oo . rloc
  Iiiii = Oo0o0o0oo . translated_port
  O0oo0oo0 = self . action if ( iIIiII1iIII1i == None ) else None
  if 95 - 95: O0
  if 45 - 45: I1Ii111 + OoooooooOO . i11iIiiIii
  if 65 - 65: I1IiiI % iIii1I11I1II1
  if 52 - 52: I1IiiI
  if 19 - 19: I1IiiI
  i11III1I = None
  if ( IiIii1i11i1 and IiIii1i11i1 . request_nonce_timeout ( ) == False ) :
   i11III1I = IiIii1i11i1 . get_request_or_echo_nonce ( ipc_socket , iIIiII1iIII1i )
   if 17 - 17: I11i + OoooooooOO
   if 63 - 63: IiII
   if 3 - 3: oO0o * II111iiii . O0
   if 19 - 19: I1IiiI / I1IiiI / Oo0Ooo + oO0o + i1IIi
   if 31 - 31: iII111i / OoooooooOO - I1Ii111 . iII111i
  return ( [ iIIiII1iIII1i , Iiiii , i11III1I , O0oo0oo0 , None , Oo0o0o0oo ] )
  if 38 - 38: ooOoO0o . OoooooooOO - II111iiii * i11iIiiIii / i1IIi . OoooooooOO
  if 51 - 51: oO0o - I1ii11iIi11i + I1ii11iIi11i
 def do_rloc_sets_match ( self , rloc_address_set ) :
  if ( len ( self . rloc_set ) != len ( rloc_address_set ) ) : return ( False )
  if 100 - 100: I11i - I1ii11iIi11i . i1IIi
  if 85 - 85: II111iiii
  if 58 - 58: i1IIi - OoO0O00 + ooOoO0o
  if 6 - 6: IiII % I1IiiI + OoooooooOO * oO0o . iII111i + oO0o
  if 4 - 4: I11i % I1IiiI
  for O0OO0O in self . rloc_set :
   for Oo0o0o0oo in rloc_address_set :
    if ( Oo0o0o0oo . is_exact_match ( O0OO0O . rloc ) == False ) : continue
    Oo0o0o0oo = None
    break
    if 72 - 72: I1IiiI % II111iiii % iII111i / OoOoOO00
   if ( Oo0o0o0oo == rloc_address_set [ - 1 ] ) : return ( False )
   if 96 - 96: OoOoOO00 % Ii1I
  return ( True )
  if 50 - 50: IiII - II111iiii
  if 10 - 10: OoooooooOO % Ii1I * OOooOOo + IiII * oO0o
 def get_rloc ( self , rloc ) :
  for O0OO0O in self . rloc_set :
   Oo0O = O0OO0O . rloc
   if ( rloc . is_exact_match ( Oo0O ) ) : return ( O0OO0O )
   if 13 - 13: II111iiii
  return ( None )
  if 14 - 14: i11iIiiIii . IiII
  if 70 - 70: Oo0Ooo * OOooOOo + I1Ii111 % OoOoOO00 / O0
 def get_rloc_by_interface ( self , interface ) :
  for O0OO0O in self . rloc_set :
   if ( O0OO0O . interface == interface ) : return ( O0OO0O )
   if 23 - 23: O0 * oO0o / I1IiiI + i1IIi * O0 % oO0o
  return ( None )
  if 11 - 11: I1Ii111 . OoooooooOO * iIii1I11I1II1 / I1ii11iIi11i - ooOoO0o . iII111i
  if 71 - 71: i11iIiiIii + I11i / i11iIiiIii % Oo0Ooo / iIii1I11I1II1 * OoO0O00
 def add_db ( self ) :
  if ( self . group . is_null ( ) ) :
   lisp_db_for_lookups . add_cache ( self . eid , self )
  else :
   iIiIIi1i = lisp_db_for_lookups . lookup_cache ( self . group , True )
   if ( iIiIIi1i == None ) :
    iIiIIi1i = lisp_mapping ( self . group , self . group , [ ] )
    lisp_db_for_lookups . add_cache ( self . group , iIiIIi1i )
    if 49 - 49: iII111i + OoOoOO00
   iIiIIi1i . add_source_entry ( self )
   if 33 - 33: ooOoO0o
   if 19 - 19: I1Ii111 % IiII
   if 94 - 94: I1Ii111 * I1ii11iIi11i * I1ii11iIi11i - o0oOOo0O0Ooo . i11iIiiIii
 def add_cache ( self , do_ipc = True ) :
  if ( self . group . is_null ( ) ) :
   lisp_map_cache . add_cache ( self . eid , self )
   if ( lisp_program_hardware ) : lisp_program_vxlan_hardware ( self )
  else :
   ooooOoo000O = lisp_map_cache . lookup_cache ( self . group , True )
   if ( ooooOoo000O == None ) :
    ooooOoo000O = lisp_mapping ( self . group , self . group , [ ] )
    ooooOoo000O . eid . copy_address ( self . group )
    ooooOoo000O . group . copy_address ( self . group )
    lisp_map_cache . add_cache ( self . group , ooooOoo000O )
    if 16 - 16: i1IIi
   if ( self . eid . is_null ( ) ) : self . eid . make_default_route ( ooooOoo000O . group )
   ooooOoo000O . add_source_entry ( self )
   if 88 - 88: OOooOOo
  if ( do_ipc ) : lisp_write_ipc_map_cache ( True , self )
  if 79 - 79: oO0o
  if 52 - 52: oO0o + OoO0O00 / OoooooooOO - iIii1I11I1II1 / iII111i - oO0o
 def delete_cache ( self ) :
  self . delete_rlocs_from_rloc_probe_list ( )
  lisp_write_ipc_map_cache ( False , self )
  if 68 - 68: I1IiiI - OoOoOO00 - iIii1I11I1II1 % i11iIiiIii * OoOoOO00 * OoO0O00
  if ( self . group . is_null ( ) ) :
   lisp_map_cache . delete_cache ( self . eid )
   if ( lisp_program_hardware ) :
    OOO0000o = self . eid . print_prefix_no_iid ( )
    os . system ( "ip route delete {}" . format ( OOO0000o ) )
    if 85 - 85: oO0o * I1Ii111 * OoooooooOO % i11iIiiIii . Ii1I % i1IIi
  else :
   ooooOoo000O = lisp_map_cache . lookup_cache ( self . group , True )
   if ( ooooOoo000O == None ) : return
   if 40 - 40: Oo0Ooo
   II1ii11II1 = ooooOoo000O . lookup_source_cache ( self . eid , True )
   if ( II1ii11II1 == None ) : return
   if 52 - 52: OoooooooOO
   ooooOoo000O . source_cache . delete_cache ( self . eid )
   if ( ooooOoo000O . source_cache . cache_size ( ) == 0 ) :
    lisp_map_cache . delete_cache ( self . group )
    if 22 - 22: OoooooooOO / OoO0O00 + Oo0Ooo % ooOoO0o
    if 5 - 5: o0oOOo0O0Ooo / oO0o * ooOoO0o * I1Ii111
    if 78 - 78: O0 + Ii1I / o0oOOo0O0Ooo + I1ii11iIi11i * oO0o / o0oOOo0O0Ooo
    if 89 - 89: Oo0Ooo * Oo0Ooo . i11iIiiIii % I1ii11iIi11i - i11iIiiIii
 def add_source_entry ( self , source_mc ) :
  if ( self . source_cache == None ) : self . source_cache = lisp_cache ( )
  self . source_cache . add_cache ( source_mc . eid , source_mc )
  if 68 - 68: ooOoO0o
  if 53 - 53: i11iIiiIii / OoOoOO00 % o0oOOo0O0Ooo / IiII
 def lookup_source_cache ( self , source , exact ) :
  if ( self . source_cache == None ) : return ( None )
  return ( self . source_cache . lookup_cache ( source , exact ) )
  if 88 - 88: ooOoO0o . i1IIi
  if 21 - 21: OoO0O00 * I1ii11iIi11i + I1ii11iIi11i
 def dynamic_eid_configured ( self ) :
  return ( self . dynamic_eids != None )
  if 36 - 36: Ii1I . OOooOOo * iIii1I11I1II1 - i1IIi
  if 38 - 38: Oo0Ooo . o0oOOo0O0Ooo % oO0o / i11iIiiIii * OoO0O00 % OoOoOO00
 def star_secondary_iid ( self , prefix ) :
  if ( self . secondary_iid == None ) : return ( prefix )
  II1 = "," + str ( self . secondary_iid )
  return ( prefix . replace ( II1 , II1 + "*" ) )
  if 18 - 18: OOooOOo
  if 12 - 12: I1Ii111 % II111iiii / o0oOOo0O0Ooo - iIii1I11I1II1 + II111iiii
 def increment_decap_stats ( self , packet ) :
  Iiiii = packet . udp_dport
  if ( Iiiii == LISP_DATA_PORT ) :
   Oo0o0o0oo = self . get_rloc ( packet . outer_dest )
  else :
   if 41 - 41: OOooOOo
   if 8 - 8: i11iIiiIii . IiII . I1ii11iIi11i + i1IIi % I1Ii111
   if 64 - 64: I1IiiI . Oo0Ooo * OoO0O00
   if 87 - 87: i1IIi / OoooooooOO
   for Oo0o0o0oo in self . rloc_set :
    if ( Oo0o0o0oo . translated_port != 0 ) : break
    if 68 - 68: I1Ii111 / iIii1I11I1II1
    if 8 - 8: ooOoO0o * IiII * OOooOOo / I1IiiI
  if ( Oo0o0o0oo != None ) : Oo0o0o0oo . stats . increment ( len ( packet . packet ) )
  self . stats . increment ( len ( packet . packet ) )
  if 40 - 40: i11iIiiIii + OoooooooOO
  if 2 - 2: o0oOOo0O0Ooo * OoO0O00
 def rtrs_in_rloc_set ( self ) :
  for Oo0o0o0oo in self . rloc_set :
   if ( Oo0o0o0oo . is_rtr ( ) ) : return ( True )
   if 88 - 88: Oo0Ooo + oO0o + iII111i
  return ( False )
  if 51 - 51: i1IIi + i11iIiiIii * I11i / iII111i + OoooooooOO
  if 89 - 89: i11iIiiIii - I1Ii111 - O0 % iIii1I11I1II1 / IiII - O0
  if 63 - 63: OOooOOo
class lisp_dynamic_eid ( ) :
 def __init__ ( self ) :
  self . dynamic_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . uptime = lisp_get_timestamp ( )
  self . interface = None
  self . last_packet = None
  self . timeout = LISP_DEFAULT_DYN_EID_TIMEOUT
  if 23 - 23: Oo0Ooo / i1IIi - OOooOOo / Oo0Ooo
  if 16 - 16: o0oOOo0O0Ooo - iIii1I11I1II1 / OoooooooOO / I1ii11iIi11i + IiII
 def get_timeout ( self , interface ) :
  try :
   O0O0oo0O0O = lisp_myinterfaces [ interface ]
   self . timeout = O0O0oo0O0O . dynamic_eid_timeout
  except :
   self . timeout = LISP_DEFAULT_DYN_EID_TIMEOUT
   if 65 - 65: I1Ii111 . I1Ii111
   if 8 - 8: II111iiii - Oo0Ooo . iII111i
   if 15 - 15: i11iIiiIii * I11i + oO0o
   if 67 - 67: IiII . OoO0O00
class lisp_group_mapping ( ) :
 def __init__ ( self , group_name , ms_name , group_prefix , sources , rle_addr ) :
  self . group_name = group_name
  self . group_prefix = group_prefix
  self . use_ms_name = ms_name
  self . sources = sources
  self . rle_address = rle_addr
  if 59 - 59: oO0o * o0oOOo0O0Ooo
  if 76 - 76: I1IiiI
 def add_group ( self ) :
  lisp_group_mapping_list [ self . group_name ] = self
  if 94 - 94: OoooooooOO * I1ii11iIi11i
  if 28 - 28: II111iiii / II111iiii / II111iiii
  if 70 - 70: OoO0O00 + O0 * OoO0O00
lisp_site_flags = {
 "P" : "ETR is {}Requesting Map-Server to Proxy Map-Reply" ,
 "S" : "ETR is {}LISP-SEC capable" ,
 "I" : "xTR-ID and site-ID are {}included in Map-Register" ,
 "T" : "Use Map-Register TTL field to timeout registration is {}set" ,
 "R" : "Merging registrations are {}requested" ,
 "M" : "ETR is {}a LISP Mobile-Node" ,
 "N" : "ETR is {}requesting Map-Notify messages from Map-Server"
 }
if 25 - 25: OoooooooOO . Oo0Ooo + OOooOOo + Oo0Ooo * O0 % i1IIi
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
  if 71 - 71: II111iiii / Ii1I + i1IIi - OoOoOO00 + Ii1I
  if 31 - 31: OoooooooOO * Ii1I - iII111i . oO0o % Ii1I
  if 97 - 97: Ii1I
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
  if 51 - 51: II111iiii . oO0o % iII111i
  if 47 - 47: II111iiii - iII111i * I1IiiI . IiII
 def print_eid_tuple ( self ) :
  return ( lisp_print_eid_tuple ( self . eid , self . group ) )
  if 41 - 41: OoOoOO00 / O0 + I1Ii111 . I1ii11iIi11i
  if 48 - 48: Ii1I . o0oOOo0O0Ooo * O0 / OoooooooOO + I1Ii111 + Oo0Ooo
 def print_flags ( self , html ) :
  if ( html == False ) :
   I1i = "{}-{}-{}-{}-{}-{}-{}" . format ( "P" if self . proxy_reply_requested else "p" ,
   # oO0o - Ii1I % OoO0O00 - I1Ii111 / II111iiii . Oo0Ooo
 "S" if self . lisp_sec_present else "s" ,
 "I" if self . xtr_id_present else "i" ,
 "T" if self . use_register_ttl_requested else "t" ,
 "R" if self . merge_register_requested else "r" ,
 "M" if self . mobile_node_requested else "m" ,
 "N" if self . map_notify_requested else "n" )
  else :
   I11Iii11i1Ii = self . print_flags ( False )
   I11Iii11i1Ii = I11Iii11i1Ii . split ( "-" )
   I1i = ""
   for iI1IIi1 in I11Iii11i1Ii :
    i1o0O = lisp_site_flags [ iI1IIi1 . upper ( ) ]
    i1o0O = i1o0O . format ( "" if iI1IIi1 . isupper ( ) else "not " )
    I1i += lisp_span ( iI1IIi1 , i1o0O )
    if ( iI1IIi1 . lower ( ) != "n" ) : I1i += "-"
    if 77 - 77: iII111i . I1IiiI - iIii1I11I1II1 + II111iiii / i1IIi
    if 65 - 65: I1ii11iIi11i
  return ( I1i )
  if 2 - 2: iII111i % I1ii11iIi11i / iII111i
  if 93 - 93: iII111i
 def copy_state_to_parent ( self , child ) :
  self . xtr_id = child . xtr_id
  self . site_id = child . site_id
  self . first_registered = child . first_registered
  self . last_registered = child . last_registered
  self . last_registerer = child . last_registerer
  self . register_ttl = child . register_ttl
  if ( self . registered == False ) :
   self . first_registered = lisp_get_timestamp ( )
   if 5 - 5: iII111i . I11i % I11i * Ii1I - I1ii11iIi11i . i11iIiiIii
  self . auth_sha1_or_sha2 = child . auth_sha1_or_sha2
  self . registered = child . registered
  self . proxy_reply_requested = child . proxy_reply_requested
  self . lisp_sec_present = child . lisp_sec_present
  self . xtr_id_present = child . xtr_id_present
  self . use_register_ttl_requested = child . use_register_ttl_requested
  self . merge_register_requested = child . merge_register_requested
  self . mobile_node_requested = child . mobile_node_requested
  self . map_notify_requested = child . map_notify_requested
  if 32 - 32: II111iiii
  if 58 - 58: I1IiiI - o0oOOo0O0Ooo - I1Ii111 . O0 % OoO0O00 . I11i
 def build_sort_key ( self ) :
  I1O0oO = lisp_cache ( )
  IIiiiII , Iiii11 = I1O0oO . build_key ( self . eid )
  O0O00Oo00Oo0 = ""
  if ( self . group . is_null ( ) == False ) :
   iiI1ii1i , O0O00Oo00Oo0 = I1O0oO . build_key ( self . group )
   O0O00Oo00Oo0 = "-" + O0O00Oo00Oo0 [ 0 : 12 ] + "-" + str ( iiI1ii1i ) + "-" + O0O00Oo00Oo0 [ 12 : : ]
   if 70 - 70: I11i % i1IIi . I1Ii111 / oO0o + II111iiii % OoooooooOO
  Iiii11 = Iiii11 [ 0 : 12 ] + "-" + str ( IIiiiII ) + "-" + Iiii11 [ 12 : : ] + O0O00Oo00Oo0
  del ( I1O0oO )
  return ( Iiii11 )
  if 47 - 47: II111iiii . iIii1I11I1II1
  if 95 - 95: II111iiii % Oo0Ooo + I11i
 def merge_in_site_eid ( self , child ) :
  oOOoOIiIII = False
  if ( self . group . is_null ( ) ) :
   self . merge_rlocs_in_site_eid ( )
  else :
   oOOoOIiIII = self . merge_rles_in_site_eid ( )
   if 3 - 3: OoOoOO00 * OOooOOo - IiII - II111iiii * oO0o
   if 23 - 23: I11i * I1ii11iIi11i . I11i
   if 70 - 70: i1IIi * I1ii11iIi11i . oO0o - I1IiiI * Ii1I * iII111i
   if 11 - 11: Oo0Ooo + I1ii11iIi11i
   if 92 - 92: iII111i / II111iiii + i1IIi / I1ii11iIi11i
   if 67 - 67: iII111i / IiII + I1IiiI + IiII % OoOoOO00 % I1ii11iIi11i
  if ( child != None ) :
   self . copy_state_to_parent ( child )
   self . map_registers_received += 1
   if 7 - 7: I1ii11iIi11i % OoOoOO00 - O0 . I1Ii111
  return ( oOOoOIiIII )
  if 9 - 9: Ii1I . OoooooooOO / ooOoO0o + i1IIi
  if 90 - 90: oO0o - OoOoOO00 % ooOoO0o
 def copy_rloc_records ( self ) :
  o0OOO0OO = [ ]
  for O0OO0O in self . registered_rlocs :
   o0OOO0OO . append ( copy . deepcopy ( O0OO0O ) )
   if 85 - 85: ooOoO0o + I1ii11iIi11i / oO0o . oO0o * Ii1I
  return ( o0OOO0OO )
  if 84 - 84: iII111i
  if 32 - 32: II111iiii % OoO0O00 / i11iIiiIii . Oo0Ooo . OoooooooOO % oO0o
 def merge_rlocs_in_site_eid ( self ) :
  self . registered_rlocs = [ ]
  for ooO00oO0O in self . individual_registrations . values ( ) :
   if ( self . site_id != ooO00oO0O . site_id ) : continue
   if ( ooO00oO0O . registered == False ) : continue
   self . registered_rlocs += ooO00oO0O . copy_rloc_records ( )
   if 63 - 63: Ii1I + ooOoO0o + OOooOOo
   if 84 - 84: iII111i / Oo0Ooo
   if 21 - 21: OoO0O00 . I1IiiI - OoO0O00
   if 51 - 51: iIii1I11I1II1
   if 5 - 5: oO0o - OoOoOO00 . ooOoO0o
   if 97 - 97: I11i - ooOoO0o + oO0o . I1Ii111
  o0OOO0OO = [ ]
  for O0OO0O in self . registered_rlocs :
   if ( O0OO0O . rloc . is_null ( ) or len ( o0OOO0OO ) == 0 ) :
    o0OOO0OO . append ( O0OO0O )
    continue
    if 22 - 22: Ii1I - II111iiii % Oo0Ooo * OoOoOO00 + iIii1I11I1II1
   for iI1I1iiI1I in o0OOO0OO :
    if ( iI1I1iiI1I . rloc . is_null ( ) ) : continue
    if ( O0OO0O . rloc . is_exact_match ( iI1I1iiI1I . rloc ) ) : break
    if 41 - 41: OoooooooOO + iIii1I11I1II1 . O0 % I1Ii111 % OOooOOo + I1Ii111
   if ( iI1I1iiI1I == o0OOO0OO [ - 1 ] ) : o0OOO0OO . append ( O0OO0O )
   if 65 - 65: II111iiii . oO0o
  self . registered_rlocs = o0OOO0OO
  if 9 - 9: I1Ii111 . i11iIiiIii * I11i + o0oOOo0O0Ooo
  if 85 - 85: i11iIiiIii * iII111i
  if 43 - 43: Ii1I + iII111i * I1ii11iIi11i * Ii1I
  if 62 - 62: O0
  if ( len ( self . registered_rlocs ) == 0 ) : self . registered = False
  return
  if 44 - 44: i1IIi
  if 27 - 27: ooOoO0o - Oo0Ooo + i11iIiiIii - oO0o % O0
 def merge_rles_in_site_eid ( self ) :
  if 68 - 68: iIii1I11I1II1 % Ii1I / I11i
  if 17 - 17: IiII * Oo0Ooo . i11iIiiIii . IiII . Oo0Ooo % IiII
  if 93 - 93: II111iiii - IiII - O0 - i11iIiiIii / OOooOOo
  if 76 - 76: OOooOOo
  I1iii11 = { }
  for O0OO0O in self . registered_rlocs :
   if ( O0OO0O . rle == None ) : continue
   for I1I1iiI in O0OO0O . rle . rle_nodes :
    iIiIi1iI11iiI = I1I1iiI . address . print_address_no_iid ( )
    I1iii11 [ iIiIi1iI11iiI ] = I1I1iiI . address
    if 47 - 47: Oo0Ooo + oO0o % OoooooooOO
   break
   if 23 - 23: I1Ii111 / i11iIiiIii - ooOoO0o * iII111i - Ii1I . iIii1I11I1II1
   if 11 - 11: I11i % OoOoOO00 * Oo0Ooo
   if 48 - 48: OOooOOo
   if 66 - 66: iII111i - I1Ii111 - i11iIiiIii . o0oOOo0O0Ooo + Oo0Ooo
   if 90 - 90: O0 - i11iIiiIii * ooOoO0o . I1ii11iIi11i . Ii1I - OoooooooOO
  self . merge_rlocs_in_site_eid ( )
  if 23 - 23: o0oOOo0O0Ooo
  if 88 - 88: I1Ii111 + iIii1I11I1II1 / o0oOOo0O0Ooo
  if 93 - 93: ooOoO0o % iIii1I11I1II1 - OOooOOo . IiII + ooOoO0o
  if 63 - 63: I1ii11iIi11i / OOooOOo
  if 28 - 28: I11i / I1Ii111 + IiII * OoooooooOO - iIii1I11I1II1
  if 6 - 6: I11i % o0oOOo0O0Ooo / OoooooooOO . I1Ii111
  if 17 - 17: I1ii11iIi11i + OoooooooOO / iIii1I11I1II1 . II111iiii + Oo0Ooo
  if 7 - 7: O0 - I1ii11iIi11i - iIii1I11I1II1
  OOi1Ii1ii11I1II = [ ]
  for O0OO0O in self . registered_rlocs :
   if ( self . registered_rlocs . index ( O0OO0O ) == 0 ) :
    OOi1Ii1ii11I1II . append ( O0OO0O )
    continue
    if 38 - 38: OoOoOO00 + OoooooooOO
   if ( O0OO0O . rle == None ) : OOi1Ii1ii11I1II . append ( O0OO0O )
   if 89 - 89: OoooooooOO % II111iiii . I1ii11iIi11i + o0oOOo0O0Ooo % I1Ii111 * IiII
  self . registered_rlocs = OOi1Ii1ii11I1II
  if 89 - 89: OoO0O00
  if 92 - 92: O0 / I11i % O0 + I1Ii111
  if 48 - 48: iIii1I11I1II1 . i11iIiiIii / OoooooooOO . i1IIi . o0oOOo0O0Ooo
  if 84 - 84: Ii1I
  if 92 - 92: I11i
  if 64 - 64: iII111i / iII111i * iII111i % O0 / IiII . I1ii11iIi11i
  if 23 - 23: i1IIi / I1ii11iIi11i + o0oOOo0O0Ooo
  II1IIiiI1 = lisp_rle ( "" )
  Oo00oooOO00o0 = { }
  i1OOO = None
  for ooO00oO0O in self . individual_registrations . values ( ) :
   if ( ooO00oO0O . registered == False ) : continue
   IIiIIi1 = ooO00oO0O . registered_rlocs [ 0 ] . rle
   if ( IIiIIi1 == None ) : continue
   if 53 - 53: iII111i + oO0o % O0
   i1OOO = ooO00oO0O . registered_rlocs [ 0 ] . rloc_name
   for ooo0O in IIiIIi1 . rle_nodes :
    iIiIi1iI11iiI = ooo0O . address . print_address_no_iid ( )
    if ( Oo00oooOO00o0 . has_key ( iIiIi1iI11iiI ) ) : break
    if 27 - 27: iII111i - I1ii11iIi11i . I1Ii111 / OOooOOo
    I1I1iiI = lisp_rle_node ( )
    I1I1iiI . address . copy_address ( ooo0O . address )
    I1I1iiI . level = ooo0O . level
    I1I1iiI . rloc_name = i1OOO
    II1IIiiI1 . rle_nodes . append ( I1I1iiI )
    Oo00oooOO00o0 [ iIiIi1iI11iiI ] = ooo0O . address
    if 21 - 21: I11i / OOooOOo
    if 96 - 96: i11iIiiIii * OoooooooOO - OoO0O00 % IiII * OOooOOo
    if 28 - 28: oO0o . oO0o
    if 79 - 79: OOooOOo + i11iIiiIii + OOooOOo % I1IiiI % OoOoOO00
    if 50 - 50: o0oOOo0O0Ooo / iIii1I11I1II1 * OoO0O00
    if 44 - 44: II111iiii / o0oOOo0O0Ooo
  if ( len ( II1IIiiI1 . rle_nodes ) == 0 ) : II1IIiiI1 = None
  if ( len ( self . registered_rlocs ) != 0 ) :
   self . registered_rlocs [ 0 ] . rle = II1IIiiI1
   if ( i1OOO ) : self . registered_rlocs [ 0 ] . rloc_name = None
   if 81 - 81: I1Ii111 . Ii1I * ooOoO0o . IiII - OoOoOO00
   if 79 - 79: ooOoO0o - O0
   if 56 - 56: ooOoO0o
   if 89 - 89: O0 % iIii1I11I1II1 / OoOoOO00 - I1Ii111 - I1IiiI
   if 60 - 60: IiII % i11iIiiIii / OOooOOo
  if ( I1iii11 . keys ( ) == Oo00oooOO00o0 . keys ( ) ) : return ( False )
  if 43 - 43: i11iIiiIii * II111iiii + ooOoO0o - OoooooooOO * II111iiii / OoO0O00
  lprint ( "{} {} from {} to {}" . format ( green ( self . print_eid_tuple ( ) , False ) , bold ( "RLE change" , False ) ,
  # I1ii11iIi11i + I11i . iII111i * OoOoOO00 % I1ii11iIi11i / Ii1I
 I1iii11 . keys ( ) , Oo00oooOO00o0 . keys ( ) ) )
  if 48 - 48: I1ii11iIi11i - i1IIi
  return ( True )
  if 73 - 73: oO0o / iII111i * I1Ii111 + i1IIi * I1Ii111 / I1Ii111
  if 75 - 75: iIii1I11I1II1 / OoO0O00 / i1IIi
 def add_cache ( self ) :
  if ( self . group . is_null ( ) ) :
   lisp_sites_by_eid . add_cache ( self . eid , self )
  else :
   iIi1II1 = lisp_sites_by_eid . lookup_cache ( self . group , True )
   if ( iIi1II1 == None ) :
    iIi1II1 = lisp_site_eid ( self . site )
    iIi1II1 . eid . copy_address ( self . group )
    iIi1II1 . group . copy_address ( self . group )
    lisp_sites_by_eid . add_cache ( self . group , iIi1II1 )
    if 36 - 36: o0oOOo0O0Ooo + I1Ii111 / iII111i
    if 48 - 48: I1IiiI % ooOoO0o * o0oOOo0O0Ooo * II111iiii - OoOoOO00
    if 12 - 12: I1IiiI - Oo0Ooo / I11i
    if 79 - 79: II111iiii . I1Ii111 * I1Ii111 + I11i + I1Ii111 % I1IiiI
    if 42 - 42: I11i - i1IIi . Oo0Ooo - i1IIi
    iIi1II1 . parent_for_more_specifics = self . parent_for_more_specifics
    if 87 - 87: O0 . o0oOOo0O0Ooo % OOooOOo / I11i - I1Ii111 % i11iIiiIii
   if ( self . eid . is_null ( ) ) : self . eid . make_default_route ( iIi1II1 . group )
   iIi1II1 . add_source_entry ( self )
   if 3 - 3: oO0o + iII111i + OOooOOo
   if 54 - 54: i11iIiiIii + OoO0O00 - IiII - iII111i / I11i
   if 85 - 85: OOooOOo * OOooOOo * I1Ii111 - ooOoO0o . O0 % iII111i
 def delete_cache ( self ) :
  if ( self . group . is_null ( ) ) :
   lisp_sites_by_eid . delete_cache ( self . eid )
  else :
   iIi1II1 = lisp_sites_by_eid . lookup_cache ( self . group , True )
   if ( iIi1II1 == None ) : return
   if 5 - 5: i1IIi * iII111i . o0oOOo0O0Ooo - I1ii11iIi11i
   ooO00oO0O = iIi1II1 . lookup_source_cache ( self . eid , True )
   if ( ooO00oO0O == None ) : return
   if 84 - 84: i1IIi
   if ( iIi1II1 . source_cache == None ) : return
   if 17 - 17: IiII + iII111i * OoO0O00 / iII111i
   iIi1II1 . source_cache . delete_cache ( self . eid )
   if ( iIi1II1 . source_cache . cache_size ( ) == 0 ) :
    lisp_sites_by_eid . delete_cache ( self . group )
    if 67 - 67: i1IIi * IiII . OoOoOO00 % iIii1I11I1II1 - iIii1I11I1II1 * I1ii11iIi11i
    if 96 - 96: iII111i / i11iIiiIii / oO0o + Oo0Ooo
    if 65 - 65: OoOoOO00
    if 87 - 87: I11i % i1IIi + i11iIiiIii * II111iiii
 def add_source_entry ( self , source_se ) :
  if ( self . source_cache == None ) : self . source_cache = lisp_cache ( )
  self . source_cache . add_cache ( source_se . eid , source_se )
  if 58 - 58: OoO0O00 * I1IiiI - II111iiii / Ii1I - I1IiiI % OoooooooOO
  if 33 - 33: IiII / i1IIi + I1Ii111
 def lookup_source_cache ( self , source , exact ) :
  if ( self . source_cache == None ) : return ( None )
  return ( self . source_cache . lookup_cache ( source , exact ) )
  if 5 - 5: O0 / iII111i % II111iiii . Oo0Ooo - I11i
  if 84 - 84: oO0o * iII111i % i11iIiiIii - O0 . iIii1I11I1II1 - OoOoOO00
 def is_star_g ( self ) :
  if ( self . group . is_null ( ) ) : return ( False )
  return ( self . eid . is_exact_match ( self . group ) )
  if 73 - 73: OoOoOO00
  if 66 - 66: Oo0Ooo
 def eid_record_matches ( self , eid_record ) :
  if ( self . eid . is_exact_match ( eid_record . eid ) == False ) : return ( False )
  if ( eid_record . group . is_null ( ) ) : return ( True )
  return ( eid_record . group . is_exact_match ( self . group ) )
  if 42 - 42: i11iIiiIii / II111iiii . OOooOOo
  if 65 - 65: OoOoOO00 % II111iiii + Oo0Ooo
 def inherit_from_ams_parent ( self ) :
  OOooOo00Ooo = self . parent_for_more_specifics
  if ( OOooOo00Ooo == None ) : return
  self . force_proxy_reply = OOooOo00Ooo . force_proxy_reply
  self . force_nat_proxy_reply = OOooOo00Ooo . force_nat_proxy_reply
  self . force_ttl = OOooOo00Ooo . force_ttl
  self . pitr_proxy_reply_drop = OOooOo00Ooo . pitr_proxy_reply_drop
  self . proxy_reply_action = OOooOo00Ooo . proxy_reply_action
  self . echo_nonce_capable = OOooOo00Ooo . echo_nonce_capable
  self . policy = OOooOo00Ooo . policy
  self . require_signature = OOooOo00Ooo . require_signature
  if 24 - 24: OoO0O00 % OoooooooOO
  if 16 - 16: OoOoOO00 % Oo0Ooo * OoOoOO00 . Ii1I
 def rtrs_in_rloc_set ( self ) :
  for O0OO0O in self . registered_rlocs :
   if ( O0OO0O . is_rtr ( ) ) : return ( True )
   if 91 - 91: I1Ii111 - OoooooooOO . i1IIi . I1ii11iIi11i
  return ( False )
  if 37 - 37: IiII - oO0o
  if 92 - 92: I1IiiI
 def is_rtr_in_rloc_set ( self , rtr_rloc ) :
  for O0OO0O in self . registered_rlocs :
   if ( O0OO0O . rloc . is_exact_match ( rtr_rloc ) == False ) : continue
   if ( O0OO0O . is_rtr ( ) ) : return ( True )
   if 51 - 51: OoO0O00 + Oo0Ooo - OOooOOo + I1ii11iIi11i
  return ( False )
  if 32 - 32: I1ii11iIi11i % OoOoOO00 + Oo0Ooo
  if 92 - 92: II111iiii . O0 . iIii1I11I1II1 % IiII - i11iIiiIii
 def is_rloc_in_rloc_set ( self , rloc ) :
  for O0OO0O in self . registered_rlocs :
   if ( O0OO0O . rle ) :
    for II1IIiiI1 in O0OO0O . rle . rle_nodes :
     if ( II1IIiiI1 . address . is_exact_match ( rloc ) ) : return ( True )
     if 9 - 9: OoO0O00
     if 60 - 60: O0 / OoOoOO00 % i11iIiiIii % II111iiii / OoooooooOO
   if ( O0OO0O . rloc . is_exact_match ( rloc ) ) : return ( True )
   if 52 - 52: ooOoO0o
  return ( False )
  if 100 - 100: Oo0Ooo - o0oOOo0O0Ooo + iIii1I11I1II1 / ooOoO0o % iIii1I11I1II1
  if 4 - 4: OoOoOO00 / Oo0Ooo - OoO0O00 . OoOoOO00 / I1Ii111
 def do_rloc_sets_match ( self , prev_rloc_set ) :
  if ( len ( self . registered_rlocs ) != len ( prev_rloc_set ) ) : return ( False )
  if 60 - 60: OOooOOo * I1Ii111
  for O0OO0O in prev_rloc_set :
   OoOO0 = O0OO0O . rloc
   if ( self . is_rloc_in_rloc_set ( OoOO0 ) == False ) : return ( False )
   if 17 - 17: iII111i * I11i / iIii1I11I1II1 - II111iiii
  return ( True )
  if 97 - 97: II111iiii * o0oOOo0O0Ooo
  if 13 - 13: o0oOOo0O0Ooo . II111iiii
  if 76 - 76: II111iiii + I1Ii111 . OoooooooOO / IiII % i11iIiiIii
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
   if 87 - 87: Ii1I / OoOoOO00 / OOooOOo
  self . last_used = 0
  self . last_reply = 0
  self . last_nonce = 0
  self . map_requests_sent = 0
  self . neg_map_replies_received = 0
  self . total_rtt = 0
  if 11 - 11: o0oOOo0O0Ooo * OoO0O00 . o0oOOo0O0Ooo - I1IiiI / IiII - OOooOOo
  if 19 - 19: i1IIi + IiII . OoO0O00 / O0 - I1Ii111 - Oo0Ooo
 def resolve_dns_name ( self ) :
  if ( self . dns_name == None ) : return
  if ( self . last_dns_resolve and
 time . time ( ) - self . last_dns_resolve < 30 ) : return
  if 24 - 24: iII111i + i1IIi
  try :
   o00oo0OO0 = socket . gethostbyname_ex ( self . dns_name )
   self . last_dns_resolve = lisp_get_timestamp ( )
   iII1ii1 = o00oo0OO0 [ 2 ]
  except :
   return
   if 59 - 59: oO0o
   if 43 - 43: II111iiii - OoooooooOO
   if 11 - 11: I1IiiI
   if 76 - 76: iII111i - II111iiii % Oo0Ooo . I1Ii111
   if 64 - 64: OoO0O00 - OoO0O00
   if 93 - 93: Oo0Ooo . O0
  if ( len ( iII1ii1 ) <= self . a_record_index ) :
   self . delete_mr ( )
   return
   if 75 - 75: iII111i * II111iiii - I1IiiI
   if 30 - 30: i1IIi / ooOoO0o . ooOoO0o
  iIiIi1iI11iiI = iII1ii1 [ self . a_record_index ]
  if ( iIiIi1iI11iiI != self . map_resolver . print_address_no_iid ( ) ) :
   self . delete_mr ( )
   self . map_resolver . store_address ( iIiIi1iI11iiI )
   self . insert_mr ( )
   if 22 - 22: I11i % iIii1I11I1II1 - i11iIiiIii * OoOoOO00 - I1Ii111
   if 97 - 97: i11iIiiIii . OoOoOO00 + oO0o * O0 % OoO0O00 - Ii1I
   if 46 - 46: I1Ii111
   if 87 - 87: o0oOOo0O0Ooo - iII111i * OoO0O00 * o0oOOo0O0Ooo . o0oOOo0O0Ooo / OOooOOo
   if 50 - 50: i11iIiiIii - II111iiii * OoooooooOO + II111iiii - ooOoO0o
   if 52 - 52: i1IIi + i1IIi * i1IIi / OoOoOO00
  if ( lisp_is_decent_dns_suffix ( self . dns_name ) == False ) : return
  if ( self . a_record_index != 0 ) : return
  if 98 - 98: iII111i . i1IIi + o0oOOo0O0Ooo * OoooooooOO - i11iIiiIii
  for iIiIi1iI11iiI in iII1ii1 [ 1 : : ] :
   ii1iI1iI1 = lisp_address ( LISP_AFI_NONE , iIiIi1iI11iiI , 0 , 0 )
   Ii1IIi1III1i = lisp_get_map_resolver ( ii1iI1iI1 , None )
   if ( Ii1IIi1III1i != None and Ii1IIi1III1i . a_record_index == iII1ii1 . index ( iIiIi1iI11iiI ) ) :
    continue
    if 21 - 21: i11iIiiIii . oO0o * o0oOOo0O0Ooo + Oo0Ooo * OoOoOO00 * o0oOOo0O0Ooo
   Ii1IIi1III1i = lisp_mr ( iIiIi1iI11iiI , None , None )
   Ii1IIi1III1i . a_record_index = iII1ii1 . index ( iIiIi1iI11iiI )
   Ii1IIi1III1i . dns_name = self . dns_name
   Ii1IIi1III1i . last_dns_resolve = lisp_get_timestamp ( )
   if 33 - 33: I1IiiI + O0 - I11i
   if 90 - 90: I1Ii111 * OoooooooOO . iIii1I11I1II1 % OoO0O00 / I11i + iII111i
   if 63 - 63: o0oOOo0O0Ooo . IiII . Oo0Ooo - iIii1I11I1II1 / I1Ii111
   if 66 - 66: ooOoO0o * I1Ii111 - II111iiii
   if 38 - 38: O0 % I1ii11iIi11i + O0
  iIIii1III = [ ]
  for Ii1IIi1III1i in lisp_map_resolvers_list . values ( ) :
   if ( self . dns_name != Ii1IIi1III1i . dns_name ) : continue
   ii1iI1iI1 = Ii1IIi1III1i . map_resolver . print_address_no_iid ( )
   if ( ii1iI1iI1 in iII1ii1 ) : continue
   iIIii1III . append ( Ii1IIi1III1i )
   if 3 - 3: I1Ii111 % OoooooooOO / O0 * OoOoOO00 . Ii1I
  for Ii1IIi1III1i in iIIii1III : Ii1IIi1III1i . delete_mr ( )
  if 39 - 39: Oo0Ooo * ooOoO0o - OoOoOO00
  if 48 - 48: I11i . I1IiiI
 def insert_mr ( self ) :
  Iiii11 = self . mr_name + self . map_resolver . print_address ( )
  lisp_map_resolvers_list [ Iiii11 ] = self
  if 29 - 29: ooOoO0o
  if 18 - 18: I1Ii111 / O0 - II111iiii % IiII - ooOoO0o
 def delete_mr ( self ) :
  Iiii11 = self . mr_name + self . map_resolver . print_address ( )
  if ( lisp_map_resolvers_list . has_key ( Iiii11 ) == False ) : return
  lisp_map_resolvers_list . pop ( Iiii11 )
  if 48 - 48: OOooOOo * OoOoOO00 / oO0o + II111iiii - I1ii11iIi11i
  if 85 - 85: I1ii11iIi11i * OoooooooOO . OOooOOo * OOooOOo
  if 13 - 13: I1IiiI / Ii1I - OoOoOO00 . i1IIi * oO0o * o0oOOo0O0Ooo
class lisp_ddt_root ( ) :
 def __init__ ( self ) :
  self . root_address = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . public_key = ""
  self . priority = 0
  self . weight = 0
  if 5 - 5: I11i - I1Ii111 * I11i - II111iiii + OOooOOo + II111iiii
  if 91 - 91: i1IIi + Oo0Ooo - I1ii11iIi11i + I1ii11iIi11i * O0 / O0
  if 78 - 78: OoooooooOO
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
  if 8 - 8: Oo0Ooo - Oo0Ooo % O0 - Ii1I / o0oOOo0O0Ooo % Oo0Ooo
  if 51 - 51: iIii1I11I1II1 / iIii1I11I1II1 * I1ii11iIi11i / I11i
 def print_referral ( self , eid_indent , referral_indent ) :
  I1IiiIIi = lisp_print_elapsed ( self . uptime )
  oooO0oOoo0O = lisp_print_future ( self . expires )
  lprint ( "{}Referral EID {}, uptime/expires {}/{}, {} referrals:" . format ( eid_indent , green ( self . eid . print_prefix ( ) , False ) , I1IiiIIi ,
  # I1IiiI / iII111i / Oo0Ooo
 oooO0oOoo0O , len ( self . referral_set ) ) )
  if 66 - 66: I1Ii111 + OoooooooOO % I1IiiI . iII111i * Oo0Ooo + o0oOOo0O0Ooo
  for IiOO00O00 in self . referral_set . values ( ) :
   IiOO00O00 . print_ref_node ( referral_indent )
   if 96 - 96: OoO0O00 - ooOoO0o * Ii1I
   if 34 - 34: OoO0O00 . Oo0Ooo % Ii1I . IiII + OoOoOO00
   if 10 - 10: OoooooooOO * iII111i * ooOoO0o . Ii1I % I1Ii111 / I1ii11iIi11i
 def print_referral_type ( self ) :
  if ( self . eid . afi == LISP_AFI_ULTIMATE_ROOT ) : return ( "root" )
  if ( self . referral_type == LISP_DDT_ACTION_NULL ) :
   return ( "null-referral" )
   if 71 - 71: Ii1I + IiII
  if ( self . referral_type == LISP_DDT_ACTION_SITE_NOT_FOUND ) :
   return ( "no-site-action" )
   if 10 - 10: II111iiii % o0oOOo0O0Ooo . o0oOOo0O0Ooo % iII111i
  if ( self . referral_type > LISP_DDT_ACTION_MAX ) :
   return ( "invalid-action" )
   if 2 - 2: OoooooooOO / IiII % Oo0Ooo % iIii1I11I1II1
  return ( lisp_map_referral_action_string [ self . referral_type ] )
  if 62 - 62: oO0o
  if 47 - 47: I1IiiI - O0 - I1ii11iIi11i . OoOoOO00
 def print_eid_tuple ( self ) :
  return ( lisp_print_eid_tuple ( self . eid , self . group ) )
  if 98 - 98: o0oOOo0O0Ooo - OoO0O00 . I1ii11iIi11i / OOooOOo
  if 43 - 43: I1IiiI + OOooOOo + o0oOOo0O0Ooo
 def print_ttl ( self ) :
  Ii1 = self . referral_ttl
  if ( Ii1 < 60 ) : return ( str ( Ii1 ) + " secs" )
  if 44 - 44: o0oOOo0O0Ooo % OoO0O00 . OoooooooOO
  if ( ( Ii1 % 60 ) == 0 ) :
   Ii1 = str ( Ii1 / 60 ) + " mins"
  else :
   Ii1 = str ( Ii1 ) + " secs"
   if 21 - 21: Oo0Ooo * Oo0Ooo - iII111i - O0
  return ( Ii1 )
  if 87 - 87: OOooOOo / I1Ii111 - Ii1I + O0 - oO0o - O0
  if 68 - 68: iII111i + II111iiii + I1ii11iIi11i * OOooOOo / oO0o
 def is_referral_negative ( self ) :
  return ( self . referral_type in ( LISP_DDT_ACTION_MS_NOT_REG , LISP_DDT_ACTION_DELEGATION_HOLE ,
  # Oo0Ooo + OOooOOo - Oo0Ooo
 LISP_DDT_ACTION_NOT_AUTH ) )
  if 32 - 32: OoooooooOO
  if 99 - 99: II111iiii % Oo0Ooo / OOooOOo / I1ii11iIi11i % O0 + i1IIi
 def add_cache ( self ) :
  if ( self . group . is_null ( ) ) :
   lisp_referral_cache . add_cache ( self . eid , self )
  else :
   IiIIiIiI1II = lisp_referral_cache . lookup_cache ( self . group , True )
   if ( IiIIiIiI1II == None ) :
    IiIIiIiI1II = lisp_referral ( )
    IiIIiIiI1II . eid . copy_address ( self . group )
    IiIIiIiI1II . group . copy_address ( self . group )
    lisp_referral_cache . add_cache ( self . group , IiIIiIiI1II )
    if 90 - 90: OoOoOO00 % OoO0O00 . I1IiiI * oO0o
   if ( self . eid . is_null ( ) ) : self . eid . make_default_route ( IiIIiIiI1II . group )
   IiIIiIiI1II . add_source_entry ( self )
   if 17 - 17: O0 - i1IIi
   if 77 - 77: OOooOOo - i1IIi / II111iiii . I1Ii111 + O0
   if 1 - 1: OoooooooOO % iIii1I11I1II1 * I1ii11iIi11i
 def delete_cache ( self ) :
  if ( self . group . is_null ( ) ) :
   lisp_referral_cache . delete_cache ( self . eid )
  else :
   IiIIiIiI1II = lisp_referral_cache . lookup_cache ( self . group , True )
   if ( IiIIiIiI1II == None ) : return
   if 17 - 17: Ii1I * i1IIi % OoO0O00
   ooo0oOooOO0o0 = IiIIiIiI1II . lookup_source_cache ( self . eid , True )
   if ( ooo0oOooOO0o0 == None ) : return
   if 12 - 12: I1ii11iIi11i
   IiIIiIiI1II . source_cache . delete_cache ( self . eid )
   if ( IiIIiIiI1II . source_cache . cache_size ( ) == 0 ) :
    lisp_referral_cache . delete_cache ( self . group )
    if 86 - 86: iIii1I11I1II1 % iII111i
    if 80 - 80: Oo0Ooo
    if 37 - 37: i11iIiiIii - I1Ii111
    if 50 - 50: I1IiiI / Ii1I / Ii1I + O0 % I11i - i1IIi
 def add_source_entry ( self , source_ref ) :
  if ( self . source_cache == None ) : self . source_cache = lisp_cache ( )
  self . source_cache . add_cache ( source_ref . eid , source_ref )
  if 72 - 72: II111iiii . OoO0O00 . II111iiii * I1ii11iIi11i
  if 42 - 42: II111iiii
 def lookup_source_cache ( self , source , exact ) :
  if ( self . source_cache == None ) : return ( None )
  return ( self . source_cache . lookup_cache ( source , exact ) )
  if 45 - 45: I1ii11iIi11i . I1Ii111 . i1IIi * OOooOOo
  if 53 - 53: Ii1I . i11iIiiIii + o0oOOo0O0Ooo % I11i - I1ii11iIi11i * I1ii11iIi11i
  if 87 - 87: I1Ii111 % i11iIiiIii + O0
class lisp_referral_node ( ) :
 def __init__ ( self ) :
  self . referral_address = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . priority = 0
  self . weight = 0
  self . updown = True
  self . map_requests_sent = 0
  self . no_responses = 0
  self . uptime = lisp_get_timestamp ( )
  if 67 - 67: OoooooooOO / i1IIi / ooOoO0o . i1IIi - i11iIiiIii . i1IIi
  if 41 - 41: i11iIiiIii / ooOoO0o - Ii1I + I11i
 def print_ref_node ( self , indent ) :
  OOOO0O00o = lisp_print_elapsed ( self . uptime )
  lprint ( "{}referral {}, uptime {}, {}, priority/weight: {}/{}" . format ( indent , red ( self . referral_address . print_address ( ) , False ) , OOOO0O00o ,
  # i11iIiiIii
 "up" if self . updown else "down" , self . priority , self . weight ) )
  if 59 - 59: o0oOOo0O0Ooo % iIii1I11I1II1
  if 55 - 55: i11iIiiIii / OoOoOO00
  if 31 - 31: i1IIi - I1IiiI . I1IiiI * Ii1I
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
   if 80 - 80: OoOoOO00
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
   if 36 - 36: I11i - ooOoO0o - ooOoO0o . I1ii11iIi11i / II111iiii % OOooOOo
   if 26 - 26: OoooooooOO / ooOoO0o - iII111i / OoO0O00 . O0 * OOooOOo
   if 85 - 85: iIii1I11I1II1 + iII111i + iII111i - ooOoO0o * OoO0O00
 def resolve_dns_name ( self ) :
  if ( self . dns_name == None ) : return
  if ( self . last_dns_resolve and
 time . time ( ) - self . last_dns_resolve < 30 ) : return
  if 80 - 80: i11iIiiIii / OOooOOo . OoooooooOO % I11i - iII111i * iIii1I11I1II1
  try :
   o00oo0OO0 = socket . gethostbyname_ex ( self . dns_name )
   self . last_dns_resolve = lisp_get_timestamp ( )
   iII1ii1 = o00oo0OO0 [ 2 ]
  except :
   return
   if 70 - 70: Oo0Ooo
   if 75 - 75: I1Ii111
   if 40 - 40: OoO0O00 % Oo0Ooo / OoooooooOO / i11iIiiIii
   if 5 - 5: O0 % i11iIiiIii
   if 60 - 60: I1ii11iIi11i / I11i
   if 100 - 100: I1IiiI
  if ( len ( iII1ii1 ) <= self . a_record_index ) :
   self . delete_ms ( )
   return
   if 44 - 44: iIii1I11I1II1 + Oo0Ooo - I1Ii111 . OoooooooOO
   if 28 - 28: Ii1I + OOooOOo % IiII . i11iIiiIii - I1IiiI * Oo0Ooo
  iIiIi1iI11iiI = iII1ii1 [ self . a_record_index ]
  if ( iIiIi1iI11iiI != self . map_server . print_address_no_iid ( ) ) :
   self . delete_ms ( )
   self . map_server . store_address ( iIiIi1iI11iiI )
   self . insert_ms ( )
   if 2 - 2: I11i * I1ii11iIi11i + O0
   if 44 - 44: iIii1I11I1II1 / II111iiii - ooOoO0o
   if 10 - 10: OOooOOo
   if 78 - 78: OOooOOo * I1ii11iIi11i % i11iIiiIii % o0oOOo0O0Ooo . I1ii11iIi11i / OoooooooOO
   if 12 - 12: iIii1I11I1II1 % OoO0O00 + OOooOOo * iIii1I11I1II1 - iIii1I11I1II1
   if 70 - 70: OoO0O00 % i11iIiiIii * IiII . I11i * Oo0Ooo
  if ( lisp_is_decent_dns_suffix ( self . dns_name ) == False ) : return
  if ( self . a_record_index != 0 ) : return
  if 17 - 17: i1IIi
  for iIiIi1iI11iiI in iII1ii1 [ 1 : : ] :
   ii1iI1iI1 = lisp_address ( LISP_AFI_NONE , iIiIi1iI11iiI , 0 , 0 )
   ooooOOoO = lisp_get_map_server ( ii1iI1iI1 )
   if ( ooooOOoO != None and ooooOOoO . a_record_index == iII1ii1 . index ( iIiIi1iI11iiI ) ) :
    continue
    if 29 - 29: OOooOOo % OoO0O00 + oO0o + o0oOOo0O0Ooo . iII111i
   ooooOOoO = copy . deepcopy ( self )
   ooooOOoO . map_server . store_address ( iIiIi1iI11iiI )
   ooooOOoO . a_record_index = iII1ii1 . index ( iIiIi1iI11iiI )
   ooooOOoO . last_dns_resolve = lisp_get_timestamp ( )
   ooooOOoO . insert_ms ( )
   if 14 - 14: i1IIi + OoOoOO00 * oO0o - II111iiii + IiII + OoOoOO00
   if 42 - 42: Oo0Ooo + iII111i * ooOoO0o
   if 72 - 72: iIii1I11I1II1 % I1Ii111
   if 77 - 77: I1Ii111 * I1IiiI / iIii1I11I1II1 . II111iiii * Oo0Ooo
   if 71 - 71: ooOoO0o / iIii1I11I1II1 % O0 / I1ii11iIi11i . I1Ii111 / i11iIiiIii
  iIIii1III = [ ]
  for ooooOOoO in lisp_map_servers_list . values ( ) :
   if ( self . dns_name != ooooOOoO . dns_name ) : continue
   ii1iI1iI1 = ooooOOoO . map_server . print_address_no_iid ( )
   if ( ii1iI1iI1 in iII1ii1 ) : continue
   iIIii1III . append ( ooooOOoO )
   if 6 - 6: oO0o . OoO0O00 - II111iiii . I1IiiI - o0oOOo0O0Ooo - i1IIi
  for ooooOOoO in iIIii1III : ooooOOoO . delete_ms ( )
  if 42 - 42: Ii1I + i11iIiiIii
  if 46 - 46: O0 % OoOoOO00 - I1Ii111 . I1IiiI
 def insert_ms ( self ) :
  Iiii11 = self . ms_name + self . map_server . print_address ( )
  lisp_map_servers_list [ Iiii11 ] = self
  if 66 - 66: II111iiii * iIii1I11I1II1 * ooOoO0o * I11i . II111iiii - ooOoO0o
  if 15 - 15: I1ii11iIi11i - i11iIiiIii - Ii1I / Ii1I . iII111i
 def delete_ms ( self ) :
  Iiii11 = self . ms_name + self . map_server . print_address ( )
  if ( lisp_map_servers_list . has_key ( Iiii11 ) == False ) : return
  lisp_map_servers_list . pop ( Iiii11 )
  if 36 - 36: oO0o + Oo0Ooo * I1Ii111 % OOooOOo . Oo0Ooo . I1IiiI
  if 81 - 81: o0oOOo0O0Ooo . OoOoOO00 . i11iIiiIii
  if 13 - 13: i1IIi
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
  if 70 - 70: O0 / II111iiii
  if 98 - 98: OoOoOO00 - O0 . O0 + ooOoO0o * iIii1I11I1II1
 def add_interface ( self ) :
  lisp_myinterfaces [ self . device ] = self
  if 7 - 7: IiII * OoOoOO00 + iIii1I11I1II1 / OoOoOO00 + Oo0Ooo / o0oOOo0O0Ooo
  if 77 - 77: i1IIi . I1IiiI
 def get_instance_id ( self ) :
  return ( self . instance_id )
  if 59 - 59: O0 + OoooooooOO - i1IIi
  if 87 - 87: IiII * OoooooooOO / Oo0Ooo % iIii1I11I1II1 % oO0o
 def get_socket ( self ) :
  return ( self . raw_socket )
  if 97 - 97: ooOoO0o % i1IIi . IiII / Oo0Ooo . I1Ii111 . OoO0O00
  if 12 - 12: I1IiiI
 def get_bridge_socket ( self ) :
  return ( self . bridge_socket )
  if 99 - 99: II111iiii - OoOoOO00
  if 22 - 22: i11iIiiIii * II111iiii
 def does_dynamic_eid_match ( self , eid ) :
  if ( self . dynamic_eid . is_null ( ) ) : return ( False )
  return ( eid . is_more_specific ( self . dynamic_eid ) )
  if 11 - 11: Oo0Ooo % i1IIi
  if 70 - 70: II111iiii * Oo0Ooo * OOooOOo - I1IiiI + iIii1I11I1II1 + ooOoO0o
 def set_socket ( self , device ) :
  o00oOOO = socket . socket ( socket . AF_INET , socket . SOCK_RAW , socket . IPPROTO_RAW )
  o00oOOO . setsockopt ( socket . SOL_IP , socket . IP_HDRINCL , 1 )
  try :
   o00oOOO . setsockopt ( socket . SOL_SOCKET , socket . SO_BINDTODEVICE , device )
  except :
   o00oOOO . close ( )
   o00oOOO = None
   if 27 - 27: I1ii11iIi11i - I1Ii111 * O0 % ooOoO0o / I1IiiI
  self . raw_socket = o00oOOO
  if 53 - 53: i11iIiiIii * i11iIiiIii % O0 % IiII
  if 57 - 57: I1IiiI % i1IIi * OoO0O00 + I1Ii111 . I11i % I11i
 def set_bridge_socket ( self , device ) :
  o00oOOO = socket . socket ( socket . PF_PACKET , socket . SOCK_RAW )
  try :
   o00oOOO = o00oOOO . bind ( ( device , 0 ) )
   self . bridge_socket = o00oOOO
  except :
   return
   if 69 - 69: I1ii11iIi11i / OoOoOO00 + iIii1I11I1II1
   if 8 - 8: OoooooooOO
   if 72 - 72: OoooooooOO % I1ii11iIi11i - OoO0O00 . OoooooooOO
   if 83 - 83: o0oOOo0O0Ooo * Ii1I - Oo0Ooo * iII111i - i11iIiiIii
class lisp_datetime ( ) :
 def __init__ ( self , datetime_str ) :
  self . datetime_name = datetime_str
  self . datetime = None
  self . parse_datetime ( )
  if 6 - 6: I1IiiI + i11iIiiIii + O0 / i1IIi
  if 50 - 50: iII111i . II111iiii % I1Ii111 % I1IiiI / o0oOOo0O0Ooo . I1IiiI
 def valid_datetime ( self ) :
  oO00OOoOOoO = self . datetime_name
  if ( oO00OOoOOoO . find ( ":" ) == - 1 ) : return ( False )
  if ( oO00OOoOOoO . find ( "-" ) == - 1 ) : return ( False )
  O0OOo00 , I1II1II1IiI , o0oOo0o0 , time = oO00OOoOOoO [ 0 : 4 ] , oO00OOoOOoO [ 5 : 7 ] , oO00OOoOOoO [ 8 : 10 ] , oO00OOoOOoO [ 11 : : ]
  if 90 - 90: I11i . O0 + oO0o
  if ( ( O0OOo00 + I1II1II1IiI + o0oOo0o0 ) . isdigit ( ) == False ) : return ( False )
  if ( I1II1II1IiI < "01" and I1II1II1IiI > "12" ) : return ( False )
  if ( o0oOo0o0 < "01" and o0oOo0o0 > "31" ) : return ( False )
  if 63 - 63: I11i . I1IiiI + OoooooooOO + O0
  Oo00O0O0oOOO , I1I11iIi , Oo000 = time . split ( ":" )
  if 87 - 87: OoooooooOO + OOooOOo - I1IiiI + I1Ii111
  if ( ( Oo00O0O0oOOO + I1I11iIi + Oo000 ) . isdigit ( ) == False ) : return ( False )
  if ( Oo00O0O0oOOO < "00" and Oo00O0O0oOOO > "23" ) : return ( False )
  if ( I1I11iIi < "00" and I1I11iIi > "59" ) : return ( False )
  if ( Oo000 < "00" and Oo000 > "59" ) : return ( False )
  return ( True )
  if 92 - 92: ooOoO0o * I11i % iIii1I11I1II1 + Ii1I - OoOoOO00
  if 31 - 31: OoooooooOO
 def parse_datetime ( self ) :
  Ooo0o0o0o = self . datetime_name
  Ooo0o0o0o = Ooo0o0o0o . replace ( "-" , "" )
  Ooo0o0o0o = Ooo0o0o0o . replace ( ":" , "" )
  self . datetime = int ( Ooo0o0o0o )
  if 86 - 86: i1IIi . oO0o % OOooOOo
  if 99 - 99: oO0o / I1Ii111 * oO0o * I11i
 def now ( self ) :
  OOOO0O00o = datetime . datetime . now ( ) . strftime ( "%Y-%m-%d-%H:%M:%S" )
  OOOO0O00o = lisp_datetime ( OOOO0O00o )
  return ( OOOO0O00o )
  if 38 - 38: o0oOOo0O0Ooo + OoOoOO00
  if 24 - 24: Ii1I - OOooOOo - o0oOOo0O0Ooo - I1Ii111 / OoooooooOO
 def print_datetime ( self ) :
  return ( self . datetime_name )
  if 17 - 17: OoO0O00
  if 79 - 79: Ii1I - II111iiii
 def future ( self ) :
  return ( self . datetime > self . now ( ) . datetime )
  if 57 - 57: II111iiii / OoooooooOO
  if 4 - 4: I11i * OoOoOO00
 def past ( self ) :
  return ( self . future ( ) == False )
  if 18 - 18: iIii1I11I1II1 % OOooOOo - I1ii11iIi11i * i1IIi + Oo0Ooo
  if 87 - 87: oO0o . I11i
 def now_in_range ( self , upper ) :
  return ( self . past ( ) and upper . future ( ) )
  if 15 - 15: oO0o
  if 45 - 45: Oo0Ooo * IiII * OoO0O00 + iIii1I11I1II1
 def this_year ( self ) :
  O0oO0oOOO0oO = str ( self . now ( ) . datetime ) [ 0 : 4 ]
  OOOO0O00o = str ( self . datetime ) [ 0 : 4 ]
  return ( OOOO0O00o == O0oO0oOOO0oO )
  if 22 - 22: o0oOOo0O0Ooo * O0 % Oo0Ooo
  if 52 - 52: I1IiiI % I1Ii111 - i1IIi . o0oOOo0O0Ooo % I1ii11iIi11i
 def this_month ( self ) :
  O0oO0oOOO0oO = str ( self . now ( ) . datetime ) [ 0 : 6 ]
  OOOO0O00o = str ( self . datetime ) [ 0 : 6 ]
  return ( OOOO0O00o == O0oO0oOOO0oO )
  if 34 - 34: o0oOOo0O0Ooo / OoOoOO00
  if 74 - 74: IiII + i1IIi . II111iiii
 def today ( self ) :
  O0oO0oOOO0oO = str ( self . now ( ) . datetime ) [ 0 : 8 ]
  OOOO0O00o = str ( self . datetime ) [ 0 : 8 ]
  return ( OOOO0O00o == O0oO0oOOO0oO )
  if 1 - 1: Ii1I - o0oOOo0O0Ooo / i11iIiiIii
  if 24 - 24: O0
  if 59 - 59: OoO0O00 % iII111i + oO0o * II111iiii . OOooOOo
  if 26 - 26: OOooOOo % OoooooooOO . Ii1I / iIii1I11I1II1 * I1IiiI
  if 85 - 85: IiII / Ii1I - I1ii11iIi11i * OOooOOo
  if 19 - 19: I1ii11iIi11i
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
  if 12 - 12: ooOoO0o * I1ii11iIi11i * O0 / oO0o + iII111i - iIii1I11I1II1
  if 81 - 81: Ii1I
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
  if 87 - 87: O0 % iII111i
  if 57 - 57: Ii1I
 def match_policy_map_request ( self , mr , srloc ) :
  for i1ii1I11iIII in self . match_clauses :
   i111 = i1ii1I11iIII . source_eid
   O00o00oOOo = mr . source_eid
   if ( i111 and O00o00oOOo and O00o00oOOo . is_more_specific ( i111 ) == False ) : continue
   if 49 - 49: I11i
   i111 = i1ii1I11iIII . dest_eid
   O00o00oOOo = mr . target_eid
   if ( i111 and O00o00oOOo and O00o00oOOo . is_more_specific ( i111 ) == False ) : continue
   if 22 - 22: Oo0Ooo % OOooOOo + O0 - OoO0O00 % I11i * O0
   i111 = i1ii1I11iIII . source_rloc
   O00o00oOOo = srloc
   if ( i111 and O00o00oOOo and O00o00oOOo . is_more_specific ( i111 ) == False ) : continue
   II1Ooo0000o00OO = i1ii1I11iIII . datetime_lower
   iIiooooOooOO0 = i1ii1I11iIII . datetime_upper
   if ( II1Ooo0000o00OO and iIiooooOooOO0 and II1Ooo0000o00OO . now_in_range ( iIiooooOooOO0 ) == False ) : continue
   return ( True )
   if 20 - 20: I11i + IiII
  return ( False )
  if 44 - 44: OoooooooOO % I11i / O0
  if 94 - 94: IiII
 def set_policy_map_reply ( self ) :
  oOo0O0II111II = ( self . set_rloc_address == None and
 self . set_rloc_record_name == None and self . set_geo_name == None and
 self . set_elp_name == None and self . set_rle_name == None )
  if ( oOo0O0II111II ) : return ( None )
  if 33 - 33: I1Ii111
  Oo0o0o0oo = lisp_rloc ( )
  if ( self . set_rloc_address ) :
   Oo0o0o0oo . rloc . copy_address ( self . set_rloc_address )
   iIiIi1iI11iiI = Oo0o0o0oo . rloc . print_address_no_iid ( )
   lprint ( "Policy set-rloc-address to {}" . format ( iIiIi1iI11iiI ) )
   if 97 - 97: Ii1I / iII111i - ooOoO0o + IiII * OoOoOO00 - OOooOOo
  if ( self . set_rloc_record_name ) :
   Oo0o0o0oo . rloc_name = self . set_rloc_record_name
   i1i1Ii = blue ( Oo0o0o0oo . rloc_name , False )
   lprint ( "Policy set-rloc-record-name to {}" . format ( i1i1Ii ) )
   if 43 - 43: oO0o / II111iiii - iII111i / oO0o
  if ( self . set_geo_name ) :
   Oo0o0o0oo . geo_name = self . set_geo_name
   i1i1Ii = Oo0o0o0oo . geo_name
   oO0oII11i = "" if lisp_geo_list . has_key ( i1i1Ii ) else "(not configured)"
   if 76 - 76: iII111i
   lprint ( "Policy set-geo-name '{}' {}" . format ( i1i1Ii , oO0oII11i ) )
   if 48 - 48: OOooOOo % I1Ii111 % ooOoO0o . I1ii11iIi11i * O0 . O0
  if ( self . set_elp_name ) :
   Oo0o0o0oo . elp_name = self . set_elp_name
   i1i1Ii = Oo0o0o0oo . elp_name
   oO0oII11i = "" if lisp_elp_list . has_key ( i1i1Ii ) else "(not configured)"
   if 25 - 25: O0 - Ii1I - IiII
   lprint ( "Policy set-elp-name '{}' {}" . format ( i1i1Ii , oO0oII11i ) )
   if 72 - 72: Ii1I % O0 + II111iiii . i11iIiiIii
  if ( self . set_rle_name ) :
   Oo0o0o0oo . rle_name = self . set_rle_name
   i1i1Ii = Oo0o0o0oo . rle_name
   oO0oII11i = "" if lisp_rle_list . has_key ( i1i1Ii ) else "(not configured)"
   if 66 - 66: II111iiii % I1IiiI
   lprint ( "Policy set-rle-name '{}' {}" . format ( i1i1Ii , oO0oII11i ) )
   if 88 - 88: iIii1I11I1II1 * iIii1I11I1II1 + I1Ii111 * OOooOOo . I1IiiI
  if ( self . set_json_name ) :
   Oo0o0o0oo . json_name = self . set_json_name
   i1i1Ii = Oo0o0o0oo . json_name
   oO0oII11i = "" if lisp_json_list . has_key ( i1i1Ii ) else "(not configured)"
   if 96 - 96: I1ii11iIi11i
   lprint ( "Policy set-json-name '{}' {}" . format ( i1i1Ii , oO0oII11i ) )
   if 37 - 37: OoO0O00 % o0oOOo0O0Ooo * O0 * O0 + iII111i
  return ( Oo0o0o0oo )
  if 18 - 18: i11iIiiIii . o0oOOo0O0Ooo - OOooOOo % oO0o * Ii1I / I1IiiI
  if 46 - 46: o0oOOo0O0Ooo . ooOoO0o / Ii1I
 def save_policy ( self ) :
  lisp_policies [ self . policy_name ] = self
  if 97 - 97: Ii1I . Oo0Ooo - O0 - I1Ii111 . i1IIi
  if 47 - 47: IiII * ooOoO0o - i1IIi % OoOoOO00 * i11iIiiIii . OoooooooOO
  if 84 - 84: OoOoOO00 / IiII - i1IIi - I1IiiI * OOooOOo
class lisp_pubsub ( ) :
 def __init__ ( self , itr , port , nonce , ttl , xtr_id ) :
  self . itr = itr
  self . port = port
  self . nonce = nonce
  self . uptime = lisp_get_timestamp ( )
  self . ttl = ttl
  self . xtr_id = xtr_id
  self . map_notify_count = 0
  if 35 - 35: II111iiii
  if 28 - 28: I1Ii111 + IiII + I1ii11iIi11i . Ii1I
 def add ( self , eid_prefix ) :
  Ii1 = self . ttl
  Oo00o = eid_prefix . print_prefix ( )
  if ( lisp_pubsub_cache . has_key ( Oo00o ) == False ) :
   lisp_pubsub_cache [ Oo00o ] = { }
   if 82 - 82: ooOoO0o - ooOoO0o . Ii1I . i11iIiiIii % Ii1I + OOooOOo
  I1i11 = lisp_pubsub_cache [ Oo00o ]
  if 33 - 33: Oo0Ooo - OOooOOo / OoOoOO00 % II111iiii % OOooOOo + I1Ii111
  I1iIiI = "Add"
  if ( I1i11 . has_key ( self . xtr_id ) ) :
   I1iIiI = "Replace"
   del ( I1i11 [ self . xtr_id ] )
   if 4 - 4: i11iIiiIii + OoOoOO00 - Ii1I * i1IIi * i11iIiiIii
  I1i11 [ self . xtr_id ] = self
  if 46 - 46: IiII . iII111i % OoooooooOO % IiII + Ii1I - OoooooooOO
  Oo00o = green ( Oo00o , False )
  OooOoOOo0 = red ( self . itr . print_address_no_iid ( ) , False )
  Oo0O0 = "0x" + lisp_hex_string ( self . xtr_id )
  lprint ( "{} pubsub state {} for {}, xtr-id: {}, ttl {}" . format ( I1iIiI , Oo00o ,
 OooOoOOo0 , Oo0O0 , Ii1 ) )
  if 23 - 23: O0 - iII111i
  if 18 - 18: II111iiii % i11iIiiIii + I11i - OOooOOo
 def delete ( self , eid_prefix ) :
  Oo00o = eid_prefix . print_prefix ( )
  OooOoOOo0 = red ( self . itr . print_address_no_iid ( ) , False )
  Oo0O0 = "0x" + lisp_hex_string ( self . xtr_id )
  if ( lisp_pubsub_cache . has_key ( Oo00o ) ) :
   I1i11 = lisp_pubsub_cache [ Oo00o ]
   if ( I1i11 . has_key ( self . xtr_id ) ) :
    I1i11 . pop ( self . xtr_id )
    lprint ( "Remove pubsub state {} for {}, xtr-id: {}" . format ( Oo00o ,
 OooOoOOo0 , Oo0O0 ) )
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
    if 51 - 51: iII111i % i11iIiiIii . OoO0O00 . IiII - OoOoOO00 * i1IIi
    if 14 - 14: I1ii11iIi11i . OoO0O00
    if 26 - 26: iII111i / ooOoO0o / Oo0Ooo / Oo0Ooo . I1ii11iIi11i * OOooOOo
    if 25 - 25: IiII % I1IiiI / O0 % OOooOOo - OoooooooOO
    if 29 - 29: O0 + iII111i
    if 4 - 4: I11i * I11i - Ii1I * oO0o . I1ii11iIi11i % o0oOOo0O0Ooo
    if 33 - 33: Ii1I * i11iIiiIii / O0 . Oo0Ooo + i1IIi . OoOoOO00
class lisp_trace ( ) :
 def __init__ ( self ) :
  self . nonce = lisp_get_control_nonce ( )
  self . packet_json = [ ]
  self . local_rloc = None
  self . local_port = None
  self . lisp_socket = None
  if 76 - 76: OoooooooOO - O0
  if 17 - 17: Oo0Ooo % I1Ii111 . oO0o - O0
 def print_trace ( self ) :
  iiiIIi1Iii = self . packet_json
  lprint ( "LISP-Trace JSON: '{}'" . format ( iiiIIi1Iii ) )
  if 39 - 39: iII111i - I1ii11iIi11i % ooOoO0o - OoOoOO00 + OoOoOO00
  if 97 - 97: I11i * I1Ii111 * oO0o
 def encode ( self ) :
  O0oooOO = socket . htonl ( 0x90000000 )
  oOo = struct . pack ( "II" , O0oooOO , 0 )
  oOo += struct . pack ( "Q" , self . nonce )
  oOo += json . dumps ( self . packet_json )
  return ( oOo )
  if 3 - 3: iIii1I11I1II1 / ooOoO0o + ooOoO0o + I11i
  if 20 - 20: OOooOOo - i1IIi / i11iIiiIii
 def decode ( self , packet ) :
  IIiI1I11ii1i = "I"
  i1II1i1iiI1 = struct . calcsize ( IIiI1I11ii1i )
  if ( len ( packet ) < i1II1i1iiI1 ) : return ( False )
  O0oooOO = struct . unpack ( IIiI1I11ii1i , packet [ : i1II1i1iiI1 ] ) [ 0 ]
  packet = packet [ i1II1i1iiI1 : : ]
  O0oooOO = socket . ntohl ( O0oooOO )
  if ( ( O0oooOO & 0xff000000 ) != 0x90000000 ) : return ( False )
  if 60 - 60: I11i * I11i + Oo0Ooo . IiII / iII111i % OoooooooOO
  if ( len ( packet ) < i1II1i1iiI1 ) : return ( False )
  iIiIi1iI11iiI = struct . unpack ( IIiI1I11ii1i , packet [ : i1II1i1iiI1 ] ) [ 0 ]
  packet = packet [ i1II1i1iiI1 : : ]
  if 35 - 35: O0 . Oo0Ooo / Oo0Ooo / Ii1I / i1IIi * I11i
  iIiIi1iI11iiI = socket . ntohl ( iIiIi1iI11iiI )
  oo00oo = iIiIi1iI11iiI >> 24
  oo0ooo000OO0o = ( iIiIi1iI11iiI >> 16 ) & 0xff
  ooOo0OOo = ( iIiIi1iI11iiI >> 8 ) & 0xff
  O00OO0ooo = iIiIi1iI11iiI & 0xff
  self . local_rloc = "{}.{}.{}.{}" . format ( oo00oo , oo0ooo000OO0o , ooOo0OOo , O00OO0ooo )
  self . local_port = str ( O0oooOO & 0xffff )
  if 22 - 22: OOooOOo
  IIiI1I11ii1i = "Q"
  i1II1i1iiI1 = struct . calcsize ( IIiI1I11ii1i )
  if ( len ( packet ) < i1II1i1iiI1 ) : return ( False )
  self . nonce = struct . unpack ( IIiI1I11ii1i , packet [ : i1II1i1iiI1 ] ) [ 0 ]
  packet = packet [ i1II1i1iiI1 : : ]
  if ( len ( packet ) == 0 ) : return ( True )
  if 7 - 7: O0 - I1ii11iIi11i - OoO0O00 * I1Ii111
  try :
   self . packet_json = json . loads ( packet )
  except :
   return ( False )
   if 17 - 17: o0oOOo0O0Ooo % OoO0O00 - I11i * o0oOOo0O0Ooo - i1IIi / I1IiiI
  return ( True )
  if 100 - 100: OoO0O00 * i1IIi * o0oOOo0O0Ooo * Oo0Ooo - o0oOOo0O0Ooo
  if 100 - 100: iII111i - i11iIiiIii + OoO0O00
 def myeid ( self , eid ) :
  return ( lisp_is_myeid ( eid ) )
  if 50 - 50: II111iiii
  if 42 - 42: OOooOOo * I1Ii111
 def return_to_sender ( self , lisp_socket , rts_rloc , packet ) :
  Oo0o0o0oo , Iiiii = self . rtr_cache_nat_trace_find ( rts_rloc )
  if ( Oo0o0o0oo == None ) :
   Oo0o0o0oo , Iiiii = rts_rloc . split ( ":" )
   Iiiii = int ( Iiiii )
   lprint ( "Send LISP-Trace to address {}:{}" . format ( Oo0o0o0oo , Iiiii ) )
  else :
   lprint ( "Send LISP-Trace to translated address {}:{}" . format ( Oo0o0o0oo ,
 Iiiii ) )
   if 53 - 53: II111iiii % OOooOOo / I1ii11iIi11i * OoOoOO00 % I1ii11iIi11i * iII111i
   if 91 - 91: iII111i . OoooooooOO
  if ( lisp_socket == None ) :
   o00oOOO = socket . socket ( socket . AF_INET , socket . SOCK_DGRAM )
   o00oOOO . bind ( ( "0.0.0.0" , LISP_TRACE_PORT ) )
   o00oOOO . sendto ( packet , ( Oo0o0o0oo , Iiiii ) )
   o00oOOO . close ( )
  else :
   lisp_socket . sendto ( packet , ( Oo0o0o0oo , Iiiii ) )
   if 90 - 90: i11iIiiIii - I1IiiI
   if 39 - 39: iII111i % OoooooooOO % Ii1I % I1IiiI
   if 63 - 63: OoO0O00 - I1Ii111 - II111iiii
 def packet_length ( self ) :
  OOOOo00oo00O = 8 ; OoOooO00 = 4 + 4 + 8
  return ( OOOOo00oo00O + OoOooO00 + len ( json . dumps ( self . packet_json ) ) )
  if 66 - 66: i1IIi + I1IiiI
  if 45 - 45: I1Ii111 . iII111i + OoO0O00 - O0
 def rtr_cache_nat_trace ( self , translated_rloc , translated_port ) :
  Iiii11 = self . local_rloc + ":" + self . local_port
  ooOo0O0O0oOO0 = ( translated_rloc , translated_port )
  lisp_rtr_nat_trace_cache [ Iiii11 ] = ooOo0O0O0oOO0
  lprint ( "Cache NAT Trace addresses {} -> {}" . format ( Iiii11 , ooOo0O0O0oOO0 ) )
  if 71 - 71: Oo0Ooo + OOooOOo
  if 94 - 94: OOooOOo
 def rtr_cache_nat_trace_find ( self , local_rloc_and_port ) :
  Iiii11 = local_rloc_and_port
  try : ooOo0O0O0oOO0 = lisp_rtr_nat_trace_cache [ Iiii11 ]
  except : ooOo0O0O0oOO0 = ( None , None )
  return ( ooOo0O0O0oOO0 )
  if 81 - 81: i11iIiiIii + iIii1I11I1II1 . i11iIiiIii / OOooOOo / iII111i
  if 34 - 34: i11iIiiIii - o0oOOo0O0Ooo * OoooooooOO * I1ii11iIi11i * Oo0Ooo % I1ii11iIi11i
  if 31 - 31: I11i . o0oOOo0O0Ooo
  if 82 - 82: I11i - Oo0Ooo
  if 77 - 77: I1IiiI + OoO0O00 % iIii1I11I1II1 - OOooOOo
  if 80 - 80: oO0o % I1ii11iIi11i * I1Ii111 + i1IIi
  if 79 - 79: oO0o + IiII
  if 4 - 4: iII111i + OoooooooOO / I1Ii111
  if 57 - 57: I1IiiI . iIii1I11I1II1 % iII111i * iII111i / I1Ii111
  if 30 - 30: O0 / I11i % OoOoOO00 * I1Ii111 / O0 % ooOoO0o
  if 36 - 36: iIii1I11I1II1 . iII111i * I1IiiI . I1IiiI - IiII
def lisp_get_map_server ( address ) :
 for ooooOOoO in lisp_map_servers_list . values ( ) :
  if ( ooooOOoO . map_server . is_exact_match ( address ) ) : return ( ooooOOoO )
  if 39 - 39: O0 / ooOoO0o + I11i - OoOoOO00 * o0oOOo0O0Ooo - OoO0O00
 return ( None )
 if 97 - 97: i11iIiiIii / O0 % OoO0O00
 if 88 - 88: i1IIi . I1IiiI
 if 8 - 8: I1ii11iIi11i . OoO0O00 % o0oOOo0O0Ooo / O0
 if 51 - 51: oO0o + Ii1I * Ii1I * I1ii11iIi11i % I11i - I1ii11iIi11i
 if 15 - 15: i1IIi / OoO0O00 - Oo0Ooo
 if 74 - 74: o0oOOo0O0Ooo % Ii1I - II111iiii / ooOoO0o
 if 84 - 84: I1IiiI + OOooOOo
def lisp_get_any_map_server ( ) :
 for ooooOOoO in lisp_map_servers_list . values ( ) : return ( ooooOOoO )
 return ( None )
 if 80 - 80: OOooOOo / OoOoOO00
 if 93 - 93: OOooOOo
 if 82 - 82: iIii1I11I1II1 + OoO0O00 / iIii1I11I1II1 . iIii1I11I1II1
 if 36 - 36: iII111i % I1ii11iIi11i + OoOoOO00 - i11iIiiIii % II111iiii % I11i
 if 92 - 92: O0 * OoooooooOO + I1ii11iIi11i / IiII
 if 97 - 97: o0oOOo0O0Ooo . Ii1I + I1Ii111
 if 72 - 72: i11iIiiIii . iII111i . Ii1I * I1ii11iIi11i
 if 49 - 49: OoOoOO00 - O0 % I11i - ooOoO0o * OOooOOo
 if 58 - 58: OoooooooOO - OOooOOo * oO0o / Ii1I . IiII
 if 50 - 50: IiII . OOooOOo + I1ii11iIi11i - OoooooooOO
def lisp_get_map_resolver ( address , eid ) :
 if ( address != None ) :
  iIiIi1iI11iiI = address . print_address ( )
  Ii1IIi1III1i = None
  for Iiii11 in lisp_map_resolvers_list :
   if ( Iiii11 . find ( iIiIi1iI11iiI ) == - 1 ) : continue
   Ii1IIi1III1i = lisp_map_resolvers_list [ Iiii11 ]
   if 2 - 2: o0oOOo0O0Ooo % ooOoO0o / O0 / i11iIiiIii
  return ( Ii1IIi1III1i )
  if 91 - 91: II111iiii * o0oOOo0O0Ooo
  if 20 - 20: iIii1I11I1II1 % Oo0Ooo * OoOoOO00 % IiII
  if 93 - 93: I11i * iIii1I11I1II1 * oO0o
  if 74 - 74: I1IiiI
  if 39 - 39: iII111i * IiII / iII111i * IiII % I1ii11iIi11i
  if 27 - 27: iIii1I11I1II1 . ooOoO0o
  if 74 - 74: i1IIi % OoOoOO00
 if ( eid == "" ) :
  O0o0Ooo0O0OO = ""
 elif ( eid == None ) :
  O0o0Ooo0O0OO = "all"
 else :
  iIiIIi1i = lisp_db_for_lookups . lookup_cache ( eid , False )
  O0o0Ooo0O0OO = "all" if iIiIIi1i == None else iIiIIi1i . use_mr_name
  if 54 - 54: Ii1I % OoO0O00 % I1IiiI % OOooOOo / oO0o + I1IiiI
  if 94 - 94: OoOoOO00 . O0
 OOoOoooOoO = None
 for Ii1IIi1III1i in lisp_map_resolvers_list . values ( ) :
  if ( O0o0Ooo0O0OO == "" ) : return ( Ii1IIi1III1i )
  if ( Ii1IIi1III1i . mr_name != O0o0Ooo0O0OO ) : continue
  if ( OOoOoooOoO == None or Ii1IIi1III1i . last_used < OOoOoooOoO . last_used ) : OOoOoooOoO = Ii1IIi1III1i
  if 100 - 100: Ii1I
 return ( OOoOoooOoO )
 if 73 - 73: IiII - O0
 if 54 - 54: OOooOOo
 if 28 - 28: i1IIi - Oo0Ooo * OoO0O00 + OoooooooOO - Ii1I * i11iIiiIii
 if 71 - 71: iII111i - OOooOOo / iIii1I11I1II1 % i11iIiiIii
 if 39 - 39: o0oOOo0O0Ooo
 if 32 - 32: iIii1I11I1II1 . II111iiii / IiII % O0 / iII111i
 if 97 - 97: iIii1I11I1II1
 if 18 - 18: OOooOOo
def lisp_get_decent_map_resolver ( eid ) :
 oo0OOo0O = lisp_get_decent_index ( eid )
 Ooooo000 = str ( oo0OOo0O ) + "." + lisp_decent_dns_suffix
 if 13 - 13: iIii1I11I1II1 - I1IiiI % o0oOOo0O0Ooo * iIii1I11I1II1
 lprint ( "Use LISP-Decent map-resolver {} for EID {}" . format ( bold ( Ooooo000 , False ) , eid . print_prefix ( ) ) )
 if 99 - 99: OoooooooOO / II111iiii . I1Ii111
 if 62 - 62: OOooOOo . iII111i . I1ii11iIi11i
 OOoOoooOoO = None
 for Ii1IIi1III1i in lisp_map_resolvers_list . values ( ) :
  if ( Ooooo000 != Ii1IIi1III1i . dns_name ) : continue
  if ( OOoOoooOoO == None or Ii1IIi1III1i . last_used < OOoOoooOoO . last_used ) : OOoOoooOoO = Ii1IIi1III1i
  if 23 - 23: O0
 return ( OOoOoooOoO )
 if 33 - 33: ooOoO0o - iII111i % IiII
 if 67 - 67: II111iiii
 if 66 - 66: iIii1I11I1II1 / OOooOOo
 if 65 - 65: IiII . oO0o + O0 - i11iIiiIii + iIii1I11I1II1
 if 82 - 82: iIii1I11I1II1 * iII111i + iIii1I11I1II1 / OoO0O00 + O0
 if 67 - 67: I1Ii111
 if 94 - 94: I1Ii111 % iIii1I11I1II1 - II111iiii . ooOoO0o + i11iIiiIii - i11iIiiIii
def lisp_ipv4_input ( packet ) :
 if 55 - 55: OoooooooOO % iIii1I11I1II1 % I1ii11iIi11i % i1IIi
 if 46 - 46: I11i - ooOoO0o . I1IiiI
 if 36 - 36: I11i + OoO0O00 * O0 * OoOoOO00 * iII111i
 if 90 - 90: i11iIiiIii / i1IIi
 I11i11I = struct . unpack ( "H" , packet [ 10 : 12 ] ) [ 0 ]
 if ( I11i11I == 0 ) :
  dprint ( "Packet arrived with checksum of 0!" )
 else :
  packet = lisp_ip_checksum ( packet )
  I11i11I = struct . unpack ( "H" , packet [ 10 : 12 ] ) [ 0 ]
  if ( I11i11I != 0 ) :
   dprint ( "IPv4 header checksum failed for inner header" )
   packet = lisp_format_packet ( packet [ 0 : 20 ] )
   dprint ( "Packet header: {}" . format ( packet ) )
   return ( None )
   if 35 - 35: Ii1I . I11i / oO0o / OoOoOO00
   if 5 - 5: I1ii11iIi11i . o0oOOo0O0Ooo * iII111i * I1ii11iIi11i % I1Ii111
   if 83 - 83: iIii1I11I1II1 * o0oOOo0O0Ooo % i11iIiiIii + OoO0O00 . O0
   if 87 - 87: II111iiii - iIii1I11I1II1 % I11i % I1IiiI . o0oOOo0O0Ooo
   if 52 - 52: i11iIiiIii . oO0o / OoooooooOO - OoO0O00
   if 7 - 7: I1IiiI * I1IiiI % OOooOOo % iIii1I11I1II1 * OoO0O00 . o0oOOo0O0Ooo
   if 32 - 32: ooOoO0o / i1IIi
 Ii1 = struct . unpack ( "B" , packet [ 8 : 9 ] ) [ 0 ]
 if ( Ii1 == 0 ) :
  dprint ( "IPv4 packet arrived with ttl 0, packet discarded" )
  return ( None )
 elif ( Ii1 == 1 ) :
  dprint ( "IPv4 packet {}, packet discarded" . format ( bold ( "ttl expiry" , False ) ) )
  if 55 - 55: oO0o . OoOoOO00 + OoooooooOO - ooOoO0o . OoooooooOO
  return ( None )
  if 77 - 77: I1IiiI
  if 16 - 16: I1IiiI + ooOoO0o - O0 / o0oOOo0O0Ooo
 Ii1 -= 1
 packet = packet [ 0 : 8 ] + struct . pack ( "B" , Ii1 ) + packet [ 9 : : ]
 packet = packet [ 0 : 10 ] + struct . pack ( "H" , 0 ) + packet [ 12 : : ]
 packet = lisp_ip_checksum ( packet )
 return ( packet )
 if 36 - 36: Oo0Ooo - OoOoOO00 - II111iiii
 if 25 - 25: i11iIiiIii + II111iiii * OOooOOo % OOooOOo
 if 87 - 87: I11i % Ii1I % Oo0Ooo . II111iiii / oO0o
 if 19 - 19: O0 . OOooOOo + I1Ii111 * I1ii11iIi11i
 if 91 - 91: o0oOOo0O0Ooo / oO0o . o0oOOo0O0Ooo + IiII + ooOoO0o . I1Ii111
 if 90 - 90: i1IIi + oO0o * oO0o / ooOoO0o . IiII
 if 98 - 98: I11i % OoO0O00 . iII111i - o0oOOo0O0Ooo
def lisp_ipv6_input ( packet ) :
 iIi11i1I11Ii = packet . inner_dest
 packet = packet . packet
 if 92 - 92: I11i
 if 34 - 34: I1IiiI % iIii1I11I1II1 . I1ii11iIi11i * Oo0Ooo * iIii1I11I1II1 / O0
 if 98 - 98: iII111i % IiII + OoO0O00
 if 23 - 23: OOooOOo
 if 83 - 83: I1ii11iIi11i / O0 * II111iiii + IiII + Oo0Ooo
 Ii1 = struct . unpack ( "B" , packet [ 7 : 8 ] ) [ 0 ]
 if ( Ii1 == 0 ) :
  dprint ( "IPv6 packet arrived with hop-limit 0, packet discarded" )
  return ( None )
 elif ( Ii1 == 1 ) :
  dprint ( "IPv6 packet {}, packet discarded" . format ( bold ( "ttl expiry" , False ) ) )
  if 99 - 99: II111iiii + O0
  return ( None )
  if 94 - 94: ooOoO0o * ooOoO0o + o0oOOo0O0Ooo . iII111i % iIii1I11I1II1 + Ii1I
  if 88 - 88: Oo0Ooo . iII111i
  if 89 - 89: OOooOOo + I1Ii111 % i11iIiiIii + Oo0Ooo / Oo0Ooo + OoO0O00
  if 9 - 9: OoOoOO00 % i1IIi + IiII
  if 19 - 19: I1Ii111 - II111iiii / I1Ii111 + I1IiiI - OoooooooOO + o0oOOo0O0Ooo
 if ( iIi11i1I11Ii . is_ipv6_link_local ( ) ) :
  dprint ( "Do not encapsulate IPv6 link-local packets" )
  return ( None )
  if 100 - 100: OoO0O00 / OoOoOO00 / OOooOOo / OoO0O00
  if 95 - 95: ooOoO0o
 Ii1 -= 1
 packet = packet [ 0 : 7 ] + struct . pack ( "B" , Ii1 ) + packet [ 8 : : ]
 return ( packet )
 if 95 - 95: Ii1I + i1IIi . I1IiiI % I1Ii111 / Ii1I * O0
 if 68 - 68: I1Ii111 - IiII - oO0o - Oo0Ooo - o0oOOo0O0Ooo
 if 32 - 32: OoOoOO00 % i11iIiiIii
 if 53 - 53: I1Ii111 * Ii1I / IiII . i1IIi * II111iiii / o0oOOo0O0Ooo
 if 44 - 44: I1Ii111 + ooOoO0o
 if 15 - 15: I11i + OoO0O00 + OoOoOO00
 if 100 - 100: I1Ii111
 if 78 - 78: OoOoOO00
def lisp_mac_input ( packet ) :
 return ( packet )
 if 16 - 16: I1Ii111 % OoO0O00 - OoO0O00 % OoOoOO00 * OoO0O00
 if 36 - 36: OoOoOO00 * II111iiii . OoooooooOO * I11i . I11i
 if 13 - 13: I1ii11iIi11i * II111iiii
 if 93 - 93: OOooOOo / O0 - o0oOOo0O0Ooo + OoO0O00 * I1IiiI
 if 53 - 53: I1ii11iIi11i
 if 91 - 91: o0oOOo0O0Ooo - I1ii11iIi11i . i1IIi
 if 64 - 64: ooOoO0o
 if 23 - 23: Oo0Ooo . OoO0O00
 if 49 - 49: oO0o % i11iIiiIii * Ii1I
def lisp_rate_limit_map_request ( source , dest ) :
 if ( lisp_last_map_request_sent == None ) : return ( False )
 O0oO0oOOO0oO = lisp_get_timestamp ( )
 iIIiI1iiI = O0oO0oOOO0oO - lisp_last_map_request_sent
 IIIIi1II = ( iIIiI1iiI < LISP_MAP_REQUEST_RATE_LIMIT )
 if 42 - 42: iII111i . o0oOOo0O0Ooo . OoO0O00 * Oo0Ooo
 if ( IIIIi1II ) :
  if ( source != None ) : source = source . print_address ( )
  dest = dest . print_address ( )
  dprint ( "Rate-limiting Map-Request for {} -> {}" . format ( source , dest ) )
  if 39 - 39: i11iIiiIii - iII111i / O0 % Oo0Ooo
 return ( IIIIi1II )
 if 40 - 40: O0 * Oo0Ooo % o0oOOo0O0Ooo / OoooooooOO
 if 94 - 94: iII111i
 if 79 - 79: o0oOOo0O0Ooo / I1ii11iIi11i . iII111i . II111iiii + I1ii11iIi11i * I11i
 if 49 - 49: Ii1I * OoooooooOO * i1IIi % OoOoOO00
 if 83 - 83: iIii1I11I1II1 - i1IIi - Ii1I % iII111i
 if 69 - 69: I1Ii111 * oO0o * I1IiiI
 if 74 - 74: O0 / I11i . Oo0Ooo / I11i % OoO0O00 % o0oOOo0O0Ooo
def lisp_send_map_request ( lisp_sockets , lisp_ephem_port , seid , deid , rloc ) :
 global lisp_last_map_request_sent
 if 83 - 83: OoO0O00 - i11iIiiIii + iIii1I11I1II1
 if 52 - 52: OoooooooOO
 if 44 - 44: O0 / OoooooooOO + ooOoO0o * I1ii11iIi11i
 if 36 - 36: I1ii11iIi11i / OoO0O00 - oO0o % O0
 if 12 - 12: i1IIi * ooOoO0o / oO0o + I1IiiI / OoooooooOO
 if 86 - 86: Oo0Ooo / OoO0O00
 oooooOOOoO00 = ooOo00oOOoo00O = None
 if ( rloc ) :
  oooooOOOoO00 = rloc . rloc
  ooOo00oOOoo00O = rloc . translated_port if lisp_i_am_rtr else LISP_DATA_PORT
  if 55 - 55: i1IIi / ooOoO0o * I1ii11iIi11i
  if 23 - 23: OoOoOO00 - I11i . iIii1I11I1II1
  if 87 - 87: OoO0O00 - i11iIiiIii / O0 % OOooOOo % OOooOOo * i1IIi
  if 18 - 18: IiII
  if 50 - 50: i1IIi / o0oOOo0O0Ooo * OoO0O00
 o0iII11i , I1iiI , oO00O = lisp_myrlocs
 if ( o0iII11i == None ) :
  lprint ( "Suppress sending Map-Request, IPv4 RLOC not found" )
  return
  if 72 - 72: O0 - I1IiiI . Oo0Ooo / o0oOOo0O0Ooo - i1IIi
 if ( I1iiI == None and oooooOOOoO00 != None and oooooOOOoO00 . is_ipv6 ( ) ) :
  lprint ( "Suppress sending Map-Request, IPv6 RLOC not found" )
  return
  if 98 - 98: Oo0Ooo * ooOoO0o * I11i + oO0o - O0
  if 3 - 3: i1IIi + OoOoOO00 - OoOoOO00
 IIi11i1I = lisp_map_request ( )
 IIi11i1I . record_count = 1
 IIi11i1I . nonce = lisp_get_control_nonce ( )
 IIi11i1I . rloc_probe = ( oooooOOOoO00 != None )
 if 85 - 85: o0oOOo0O0Ooo / o0oOOo0O0Ooo + Oo0Ooo * II111iiii + Ii1I * Ii1I
 if 26 - 26: o0oOOo0O0Ooo + oO0o * i11iIiiIii / II111iiii
 if 86 - 86: Ii1I
 if 69 - 69: oO0o % o0oOOo0O0Ooo / o0oOOo0O0Ooo
 if 1 - 1: Ii1I
 if 43 - 43: o0oOOo0O0Ooo
 if 78 - 78: I1Ii111 % i1IIi * I11i
 if ( rloc ) : rloc . last_rloc_probe_nonce = IIi11i1I . nonce
 if 59 - 59: OoOoOO00 % OoO0O00 % i11iIiiIii . II111iiii % I1ii11iIi11i + i1IIi
 iIi1I = deid . is_multicast_address ( )
 if ( iIi1I ) :
  IIi11i1I . target_eid = seid
  IIi11i1I . target_group = deid
 else :
  IIi11i1I . target_eid = deid
  if 99 - 99: I11i + IiII * I1Ii111 - OOooOOo - i1IIi
  if 77 - 77: I11i . IiII / OoO0O00 / I1Ii111
  if 8 - 8: o0oOOo0O0Ooo + iII111i / OoO0O00 * ooOoO0o - oO0o . iII111i
  if 32 - 32: OoooooooOO . I1Ii111 - I1ii11iIi11i
  if 29 - 29: OoO0O00
  if 33 - 33: I1ii11iIi11i - O0
  if 72 - 72: Oo0Ooo * iII111i - I11i
  if 81 - 81: I1Ii111
  if 85 - 85: O0 % OoOoOO00 . I1ii11iIi11i
 if ( IIi11i1I . rloc_probe == False ) :
  iIiIIi1i = lisp_get_signature_eid ( )
  if ( iIiIIi1i ) :
   IIi11i1I . signature_eid . copy_address ( iIiIIi1i . eid )
   IIi11i1I . privkey_filename = "./lisp-sig.pem"
   if 46 - 46: OOooOOo * iIii1I11I1II1
   if 33 - 33: OoO0O00 * II111iiii / i1IIi
   if 93 - 93: I1Ii111 % I11i
   if 64 - 64: I1IiiI % OoOoOO00 / Oo0Ooo
   if 40 - 40: Ii1I + iIii1I11I1II1 / oO0o . II111iiii % O0 - IiII
   if 49 - 49: IiII - OOooOOo * OOooOOo . O0
 if ( seid == None or iIi1I ) :
  IIi11i1I . source_eid . afi = LISP_AFI_NONE
 else :
  IIi11i1I . source_eid = seid
  if 60 - 60: OoOoOO00 % iIii1I11I1II1 + IiII % o0oOOo0O0Ooo
  if 64 - 64: OoOoOO00 * I1ii11iIi11i . OoooooooOO . i1IIi
  if 61 - 61: OoO0O00
  if 100 - 100: OoOoOO00
  if 97 - 97: OoooooooOO
  if 91 - 91: o0oOOo0O0Ooo / O0 % OoO0O00
  if 35 - 35: iII111i % OoO0O00 * O0
  if 37 - 37: OOooOOo
  if 100 - 100: Oo0Ooo * I1IiiI . ooOoO0o
  if 53 - 53: OOooOOo + o0oOOo0O0Ooo * Ii1I + O0
  if 75 - 75: OoooooooOO
  if 24 - 24: I1Ii111 % i11iIiiIii % oO0o . OOooOOo % IiII
 if ( oooooOOOoO00 != None and lisp_nat_traversal and lisp_i_am_rtr == False ) :
  if ( oooooOOOoO00 . is_private_address ( ) == False ) :
   o0iII11i = lisp_get_any_translated_rloc ( )
   if 23 - 23: o0oOOo0O0Ooo * II111iiii - Oo0Ooo - I1IiiI
  if ( o0iII11i == None ) :
   lprint ( "Suppress sending Map-Request, translated RLOC not found" )
   return
   if 86 - 86: I1IiiI - II111iiii * II111iiii * oO0o % OoooooooOO * OoOoOO00
   if 93 - 93: I1IiiI + OoO0O00 % O0 - ooOoO0o * i1IIi
   if 60 - 60: I1IiiI
   if 9 - 9: I11i % i1IIi / ooOoO0o % iII111i - oO0o - II111iiii
   if 29 - 29: ooOoO0o . II111iiii . i1IIi % oO0o
   if 11 - 11: OoOoOO00 . OoO0O00 % I11i * iII111i % I1Ii111 . O0
   if 17 - 17: OOooOOo / i11iIiiIii - i11iIiiIii . II111iiii . ooOoO0o
   if 38 - 38: OOooOOo . OoooooooOO . II111iiii + OoO0O00 / oO0o . OoooooooOO
 if ( oooooOOOoO00 == None or oooooOOOoO00 . is_ipv4 ( ) ) :
  if ( lisp_nat_traversal and oooooOOOoO00 == None ) :
   oOOOOO0 = lisp_get_any_translated_rloc ( )
   if ( oOOOOO0 != None ) : o0iII11i = oOOOOO0
   if 6 - 6: OoO0O00 * O0
  IIi11i1I . itr_rlocs . append ( o0iII11i )
  if 6 - 6: I1Ii111 * IiII * ooOoO0o + o0oOOo0O0Ooo / I11i - ooOoO0o
 if ( oooooOOOoO00 == None or oooooOOOoO00 . is_ipv6 ( ) ) :
  if ( I1iiI == None or I1iiI . is_ipv6_link_local ( ) ) :
   I1iiI = None
  else :
   IIi11i1I . itr_rloc_count = 1 if ( oooooOOOoO00 == None ) else 0
   IIi11i1I . itr_rlocs . append ( I1iiI )
   if 78 - 78: i1IIi / iIii1I11I1II1 . oO0o
   if 8 - 8: I1ii11iIi11i * OOooOOo * iIii1I11I1II1 + I11i . iII111i
   if 55 - 55: I1IiiI + Ii1I % I1ii11iIi11i + iIii1I11I1II1
   if 64 - 64: i1IIi / O0 - oO0o
   if 7 - 7: IiII . IiII * Ii1I
   if 1 - 1: i11iIiiIii
   if 91 - 91: I1ii11iIi11i . OoO0O00 / OoO0O00 / I1ii11iIi11i + iII111i
   if 20 - 20: o0oOOo0O0Ooo . I1Ii111 + O0
   if 99 - 99: O0 / IiII . oO0o
 if ( oooooOOOoO00 != None and IIi11i1I . itr_rlocs != [ ] ) :
  o0oi1iIiii1I1ii = IIi11i1I . itr_rlocs [ 0 ]
 else :
  if ( deid . is_ipv4 ( ) ) :
   o0oi1iIiii1I1ii = o0iII11i
  elif ( deid . is_ipv6 ( ) ) :
   o0oi1iIiii1I1ii = I1iiI
  else :
   o0oi1iIiii1I1ii = o0iII11i
   if 18 - 18: OoooooooOO * OoO0O00 * I1Ii111
   if 12 - 12: i11iIiiIii / iIii1I11I1II1 . I11i % I1Ii111 * ooOoO0o % ooOoO0o
   if 13 - 13: i1IIi . ooOoO0o . ooOoO0o
   if 24 - 24: iIii1I11I1II1
   if 72 - 72: i11iIiiIii + o0oOOo0O0Ooo % ooOoO0o * I1ii11iIi11i . i1IIi
   if 59 - 59: OoooooooOO - OoooooooOO - o0oOOo0O0Ooo + i1IIi % I1Ii111
 oOo = IIi11i1I . encode ( oooooOOOoO00 , ooOo00oOOoo00O )
 IIi11i1I . print_map_request ( )
 if 74 - 74: IiII * iIii1I11I1II1 - I1IiiI
 if 62 - 62: o0oOOo0O0Ooo
 if 54 - 54: iIii1I11I1II1 / OoooooooOO + o0oOOo0O0Ooo . i1IIi - OoooooooOO
 if 70 - 70: Ii1I / OoOoOO00 * Oo0Ooo
 if 32 - 32: I1Ii111 . OoOoOO00 % OoooooooOO + I1Ii111 * OoO0O00
 if 84 - 84: OoOoOO00
 if ( oooooOOOoO00 != None ) :
  if ( rloc . is_rloc_translated ( ) ) :
   iiI = lisp_get_nat_info ( oooooOOOoO00 , rloc . rloc_name )
   if 80 - 80: oO0o
   if 59 - 59: iIii1I11I1II1 / IiII % I1ii11iIi11i + OoO0O00 - I11i % OOooOOo
   if 92 - 92: iII111i
   if 96 - 96: OoOoOO00 / OoOoOO00 / OoOoOO00 + OoooooooOO + Oo0Ooo
   if ( iiI == None ) :
    Oo0O = rloc . rloc . print_address_no_iid ( )
    o0 = "gleaned-{}" . format ( Oo0O )
    i111 = rloc . translated_port
    iiI = lisp_nat_info ( Oo0O , o0 , i111 )
    if 91 - 91: OoOoOO00 + II111iiii / I11i * iIii1I11I1II1
   lisp_encapsulate_rloc_probe ( lisp_sockets , oooooOOOoO00 , iiI ,
 oOo )
   return
   if 92 - 92: I1Ii111 - IiII / IiII
   if 42 - 42: IiII
  ooOOo0o = oooooOOOoO00 . print_address_no_iid ( )
  iIi11i1I11Ii = lisp_convert_4to6 ( ooOOo0o )
  lisp_send ( lisp_sockets , iIi11i1I11Ii , LISP_CTRL_PORT , oOo )
  return
  if 7 - 7: iIii1I11I1II1
  if 35 - 35: IiII + O0 % I1Ii111 - I1ii11iIi11i - i1IIi
  if 100 - 100: I1Ii111 + i11iIiiIii - IiII / I1ii11iIi11i / iII111i
  if 56 - 56: iII111i
  if 91 - 91: Oo0Ooo . I11i . I1ii11iIi11i
  if 60 - 60: i11iIiiIii - OOooOOo
 Oo00ooOOOo0O0 = None if lisp_i_am_rtr else seid
 if ( lisp_decent_pull_xtr_configured ( ) ) :
  Ii1IIi1III1i = lisp_get_decent_map_resolver ( deid )
 else :
  Ii1IIi1III1i = lisp_get_map_resolver ( None , Oo00ooOOOo0O0 )
  if 17 - 17: O0 * i11iIiiIii - I1ii11iIi11i * iIii1I11I1II1 + oO0o * i1IIi
 if ( Ii1IIi1III1i == None ) :
  lprint ( "Cannot find Map-Resolver for source-EID {}" . format ( green ( seid . print_address ( ) , False ) ) )
  if 15 - 15: ooOoO0o + I1ii11iIi11i / I1IiiI - Oo0Ooo - Ii1I / I11i
  return
  if 37 - 37: ooOoO0o / II111iiii . OOooOOo % iIii1I11I1II1 - Oo0Ooo - Ii1I
 Ii1IIi1III1i . last_used = lisp_get_timestamp ( )
 Ii1IIi1III1i . map_requests_sent += 1
 if ( Ii1IIi1III1i . last_nonce == 0 ) : Ii1IIi1III1i . last_nonce = IIi11i1I . nonce
 if 47 - 47: I1ii11iIi11i
 if 26 - 26: iII111i
 if 55 - 55: I1ii11iIi11i . ooOoO0o * Oo0Ooo + I1Ii111
 if 59 - 59: iII111i - OOooOOo - OoO0O00 . I1IiiI % o0oOOo0O0Ooo + iII111i
 if ( seid == None ) : seid = o0oi1iIiii1I1ii
 lisp_send_ecm ( lisp_sockets , oOo , seid , lisp_ephem_port , deid ,
 Ii1IIi1III1i . map_resolver )
 if 10 - 10: iIii1I11I1II1 - Ii1I
 if 84 - 84: iII111i
 if 21 - 21: i11iIiiIii
 if 30 - 30: OoO0O00 + OoooooooOO
 lisp_last_map_request_sent = lisp_get_timestamp ( )
 if 98 - 98: I1ii11iIi11i % I1IiiI
 if 9 - 9: o0oOOo0O0Ooo / I1Ii111 % i1IIi - OOooOOo % I1IiiI / I1ii11iIi11i
 if 66 - 66: IiII
 if 56 - 56: oO0o + OoooooooOO
 Ii1IIi1III1i . resolve_dns_name ( )
 return
 if 75 - 75: O0 % Ii1I
 if 47 - 47: OoooooooOO - OoooooooOO + OoO0O00 / iIii1I11I1II1
 if 23 - 23: iII111i / iIii1I11I1II1
 if 5 - 5: O0
 if 64 - 64: i1IIi * i1IIi . iII111i - O0 - oO0o % OoooooooOO
 if 14 - 14: Ii1I % OoO0O00 % I1Ii111 * O0
 if 8 - 8: I1IiiI - i11iIiiIii * I1IiiI
 if 6 - 6: O0 - OoOoOO00 - i11iIiiIii / iII111i
def lisp_send_info_request ( lisp_sockets , dest , port , device_name ) :
 if 63 - 63: OOooOOo
 if 84 - 84: i11iIiiIii * iIii1I11I1II1 % I11i % iII111i + OoooooooOO . o0oOOo0O0Ooo
 if 78 - 78: o0oOOo0O0Ooo . iII111i + O0 / I1ii11iIi11i + I1ii11iIi11i + II111iiii
 if 96 - 96: iIii1I11I1II1 * II111iiii . iIii1I11I1II1
 i1iI1iII = lisp_info ( )
 i1iI1iII . nonce = lisp_get_control_nonce ( )
 if ( device_name ) : i1iI1iII . hostname += "-" + device_name
 if 80 - 80: I1IiiI % I1ii11iIi11i
 ooOOo0o = dest . print_address_no_iid ( )
 if 82 - 82: ooOoO0o * I1IiiI % IiII
 if 62 - 62: OoooooooOO . OoooooooOO / I11i % OoOoOO00
 if 2 - 2: IiII % I1ii11iIi11i * OoO0O00 + Oo0Ooo * iII111i
 if 85 - 85: OOooOOo * I1IiiI - iIii1I11I1II1 - OoOoOO00 + ooOoO0o . OoO0O00
 if 46 - 46: OoO0O00 * I1Ii111 . O0
 if 86 - 86: i11iIiiIii . Ii1I / OoOoOO00 / I11i * i1IIi
 if 40 - 40: o0oOOo0O0Ooo
 if 33 - 33: i11iIiiIii + I1Ii111 % I1ii11iIi11i - I1Ii111 * OoO0O00
 if 1 - 1: II111iiii / I1IiiI + II111iiii % II111iiii - I1Ii111
 if 24 - 24: I11i / Oo0Ooo / i1IIi + IiII
 if 10 - 10: I11i - IiII / II111iiii / oO0o % O0 / I1Ii111
 if 91 - 91: oO0o * OoOoOO00 + O0 % Oo0Ooo
 if 62 - 62: iIii1I11I1II1 - i11iIiiIii % iIii1I11I1II1 . ooOoO0o / OOooOOo * OoOoOO00
 if 45 - 45: OOooOOo - OOooOOo % iII111i - IiII . O0
 if 6 - 6: iIii1I11I1II1 * II111iiii / O0 % IiII - I1Ii111
 if 64 - 64: ooOoO0o
 Ii11II111 = False
 if ( device_name ) :
  OO0OOOoOooo0 = lisp_get_host_route_next_hop ( ooOOo0o )
  if 83 - 83: I1Ii111 % ooOoO0o + OoooooooOO
  if 50 - 50: i11iIiiIii % I1IiiI * iII111i / Ii1I
  if 12 - 12: iII111i / OoO0O00 - II111iiii + Oo0Ooo
  if 78 - 78: i1IIi
  if 25 - 25: Ii1I * II111iiii / OoOoOO00
  if 86 - 86: i1IIi + I1IiiI + I1Ii111 % II111iiii . IiII - iIii1I11I1II1
  if 54 - 54: i11iIiiIii . Ii1I % I1IiiI . I1Ii111 . OoooooooOO
  if 49 - 49: OOooOOo % I11i - OOooOOo + Ii1I . I1ii11iIi11i + ooOoO0o
  if 15 - 15: i11iIiiIii
  if ( port == LISP_CTRL_PORT and OO0OOOoOooo0 != None ) :
   while ( True ) :
    time . sleep ( .01 )
    OO0OOOoOooo0 = lisp_get_host_route_next_hop ( ooOOo0o )
    if ( OO0OOOoOooo0 == None ) : break
    if 85 - 85: I1Ii111 + iII111i - oO0o
    if 59 - 59: IiII . oO0o / i11iIiiIii . I1Ii111
    if 64 - 64: OoOoOO00
  II1i1 = lisp_get_default_route_next_hops ( )
  for oO00O , O0o0 in II1i1 :
   if ( oO00O != device_name ) : continue
   if 70 - 70: OoOoOO00 % o0oOOo0O0Ooo + o0oOOo0O0Ooo
   if 53 - 53: i1IIi % Oo0Ooo + O0 . I11i
   if 8 - 8: O0 + o0oOOo0O0Ooo + oO0o - OoOoOO00 % iII111i - IiII
   if 27 - 27: o0oOOo0O0Ooo
   if 20 - 20: i1IIi / IiII . OOooOOo - I1ii11iIi11i * O0 * OoOoOO00
   if 11 - 11: I11i + i1IIi
   if ( OO0OOOoOooo0 != O0o0 ) :
    if ( OO0OOOoOooo0 != None ) :
     lisp_install_host_route ( ooOOo0o , OO0OOOoOooo0 , False )
     if 49 - 49: OoooooooOO
    lisp_install_host_route ( ooOOo0o , O0o0 , True )
    Ii11II111 = True
    if 75 - 75: OoO0O00
   break
   if 52 - 52: i11iIiiIii
   if 97 - 97: Oo0Ooo % IiII
   if 24 - 24: iIii1I11I1II1
   if 97 - 97: o0oOOo0O0Ooo - iIii1I11I1II1 + I1Ii111 / ooOoO0o + Ii1I
   if 22 - 22: oO0o + O0 + I11i . OoO0O00 - II111iiii
   if 20 - 20: Ii1I * I1Ii111 . I1IiiI % OoOoOO00 / OoO0O00 % II111iiii
 oOo = i1iI1iII . encode ( )
 i1iI1iII . print_info ( )
 if 43 - 43: IiII + II111iiii + oO0o / I1ii11iIi11i % i1IIi - OoO0O00
 if 59 - 59: Oo0Ooo + O0 + iII111i
 if 71 - 71: IiII - OoO0O00
 if 90 - 90: Oo0Ooo
 Oo0000Oo0Oo = "(for control)" if port == LISP_CTRL_PORT else "(for data)"
 Oo0000Oo0Oo = bold ( Oo0000Oo0Oo , False )
 i111 = bold ( "{}" . format ( port ) , False )
 ii1iI1iI1 = red ( ooOOo0o , False )
 Ii111iI1iI1ii = "RTR " if port == LISP_DATA_PORT else "MS "
 lprint ( "Send Info-Request to {}{}, port {} {}" . format ( Ii111iI1iI1ii , ii1iI1iI1 , i111 , Oo0000Oo0Oo ) )
 if 60 - 60: Ii1I . I1ii11iIi11i - I11i + i11iIiiIii / iII111i
 if 9 - 9: I1Ii111 . oO0o . OoO0O00 / IiII - oO0o / oO0o
 if 50 - 50: II111iiii + OoOoOO00
 if 17 - 17: ooOoO0o + I1ii11iIi11i
 if 34 - 34: Ii1I / II111iiii + OoOoOO00 . II111iiii + OoooooooOO * o0oOOo0O0Ooo
 if 48 - 48: O0
 if ( port == LISP_CTRL_PORT ) :
  lisp_send ( lisp_sockets , dest , LISP_CTRL_PORT , oOo )
 else :
  oooooOOo0Oo = lisp_data_header ( )
  oooooOOo0Oo . instance_id ( 0xffffff )
  oooooOOo0Oo = oooooOOo0Oo . encode ( )
  if ( oooooOOo0Oo ) :
   oOo = oooooOOo0Oo + oOo
   if 99 - 99: II111iiii * oO0o / I1ii11iIi11i - i1IIi
   if 84 - 84: i11iIiiIii . OoooooooOO
   if 69 - 69: I1Ii111 * II111iiii % I1Ii111 * i11iIiiIii . ooOoO0o / Oo0Ooo
   if 5 - 5: Ii1I
   if 19 - 19: oO0o
   if 61 - 61: OoOoOO00 + iIii1I11I1II1 / I1ii11iIi11i - i1IIi
   if 11 - 11: oO0o * o0oOOo0O0Ooo . I1IiiI
   if 12 - 12: I1IiiI % OoO0O00 / I1Ii111 / O0 % o0oOOo0O0Ooo
   if 1 - 1: OoOoOO00 / I11i
   lisp_send ( lisp_sockets , dest , LISP_DATA_PORT , oOo )
   if 43 - 43: o0oOOo0O0Ooo - i1IIi / Ii1I . OoOoOO00 + i11iIiiIii
   if 69 - 69: i11iIiiIii - iIii1I11I1II1
   if 40 - 40: I1IiiI / oO0o + ooOoO0o
   if 100 - 100: OoOoOO00 % iII111i * ooOoO0o . O0
   if 37 - 37: I1ii11iIi11i
   if 24 - 24: O0 . I1Ii111 * i11iIiiIii
   if 84 - 84: ooOoO0o / I1ii11iIi11i - o0oOOo0O0Ooo . OoooooooOO * iIii1I11I1II1
 if ( Ii11II111 ) :
  lisp_install_host_route ( ooOOo0o , None , False )
  if ( OO0OOOoOooo0 != None ) : lisp_install_host_route ( ooOOo0o , OO0OOOoOooo0 , True )
  if 16 - 16: I11i % O0
 return
 if 56 - 56: Ii1I * OoOoOO00 . i1IIi
 if 15 - 15: I1Ii111
 if 64 - 64: OOooOOo * Oo0Ooo
 if 96 - 96: Oo0Ooo / I1ii11iIi11i * iIii1I11I1II1 / iII111i
 if 18 - 18: I1Ii111
 if 29 - 29: i1IIi - I1IiiI / i1IIi
 if 64 - 64: IiII
def lisp_process_info_request ( lisp_sockets , packet , addr_str , sport , rtr_list ) :
 if 69 - 69: OOooOOo . I1IiiI
 if 11 - 11: I1Ii111 * I1IiiI - I1Ii111 / iII111i
 if 22 - 22: iII111i % I11i % O0 - I11i
 if 71 - 71: I1Ii111 / II111iiii - OoooooooOO % i1IIi + OoOoOO00 % OoooooooOO
 i1iI1iII = lisp_info ( )
 packet = i1iI1iII . decode ( packet )
 if ( packet == None ) : return
 i1iI1iII . print_info ( )
 if 52 - 52: Ii1I . OoOoOO00 / o0oOOo0O0Ooo / iII111i
 if 83 - 83: OoO0O00 - Oo0Ooo + I1Ii111 . I1IiiI
 if 78 - 78: I11i / ooOoO0o . OoOoOO00 * i1IIi
 if 15 - 15: i1IIi . II111iiii * OoOoOO00 / Oo0Ooo
 if 99 - 99: iII111i - o0oOOo0O0Ooo / O0
 i1iI1iII . info_reply = True
 i1iI1iII . global_etr_rloc . store_address ( addr_str )
 i1iI1iII . etr_port = sport
 if 97 - 97: iIii1I11I1II1 * I1Ii111
 if 39 - 39: I1Ii111 . II111iiii
 if 94 - 94: OoO0O00 - OoO0O00 + iIii1I11I1II1 + O0 * oO0o
 if 9 - 9: Ii1I * Oo0Ooo / oO0o / Ii1I
 if 34 - 34: I1IiiI
 if ( i1iI1iII . hostname != None ) :
  i1iI1iII . private_etr_rloc . afi = LISP_AFI_NAME
  i1iI1iII . private_etr_rloc . store_address ( i1iI1iII . hostname )
  if 56 - 56: Ii1I
  if 71 - 71: O0 / i1IIi
 if ( rtr_list != None ) : i1iI1iII . rtr_list = rtr_list
 packet = i1iI1iII . encode ( )
 i1iI1iII . print_info ( )
 if 20 - 20: OOooOOo . iIii1I11I1II1 - I1Ii111 . i1IIi
 if 82 - 82: oO0o * i11iIiiIii % o0oOOo0O0Ooo % IiII - I11i - OoO0O00
 if 24 - 24: oO0o . II111iiii + OoO0O00 * I1ii11iIi11i / oO0o
 if 86 - 86: I1Ii111 + I1ii11iIi11i
 if 63 - 63: ooOoO0o - i11iIiiIii . o0oOOo0O0Ooo - i1IIi - IiII
 lprint ( "Send Info-Reply to {}" . format ( red ( addr_str , False ) ) )
 iIi11i1I11Ii = lisp_convert_4to6 ( addr_str )
 lisp_send ( lisp_sockets , iIi11i1I11Ii , sport , packet )
 if 32 - 32: I1Ii111 / iIii1I11I1II1 + oO0o % I11i * OoooooooOO
 if 69 - 69: OOooOOo
 if 9 - 9: i11iIiiIii * Oo0Ooo
 if 33 - 33: oO0o / ooOoO0o
 if 92 - 92: O0 . Oo0Ooo - Ii1I * I1IiiI * Oo0Ooo * iII111i
 O0OoO00OOOoOo = lisp_info_source ( i1iI1iII . hostname , addr_str , sport )
 O0OoO00OOOoOo . cache_address_for_info_source ( )
 return
 if 46 - 46: i11iIiiIii . i11iIiiIii
 if 53 - 53: IiII - I1Ii111 - OOooOOo . OoOoOO00 / iIii1I11I1II1
 if 89 - 89: Oo0Ooo
 if 57 - 57: i1IIi - oO0o % IiII . I11i
 if 17 - 17: i1IIi % OoO0O00 + i11iIiiIii % I1Ii111 * ooOoO0o . I1ii11iIi11i
 if 64 - 64: O0 - iII111i
 if 82 - 82: O0
 if 37 - 37: I1Ii111
def lisp_get_signature_eid ( ) :
 for iIiIIi1i in lisp_db_list :
  if ( iIiIIi1i . signature_eid ) : return ( iIiIIi1i )
  if 98 - 98: iII111i - OoOoOO00 / I1Ii111 . OOooOOo - OOooOOo - ooOoO0o
 return ( None )
 if 84 - 84: OOooOOo * ooOoO0o / O0
 if 96 - 96: I11i . I11i % II111iiii
 if 14 - 14: iII111i / OoooooooOO
 if 8 - 8: OOooOOo + I1IiiI - Oo0Ooo + i1IIi . Ii1I . I1Ii111
 if 38 - 38: I1IiiI / II111iiii * OoOoOO00 / I1Ii111
 if 80 - 80: I1ii11iIi11i / ooOoO0o * ooOoO0o . Oo0Ooo
 if 44 - 44: Ii1I * i1IIi % OoOoOO00 . OoOoOO00
 if 16 - 16: Oo0Ooo / i1IIi / iIii1I11I1II1 / iIii1I11I1II1 % o0oOOo0O0Ooo / I1ii11iIi11i
def lisp_get_any_translated_port ( ) :
 for iIiIIi1i in lisp_db_list :
  for O0OO0O in iIiIIi1i . rloc_set :
   if ( O0OO0O . translated_rloc . is_null ( ) ) : continue
   return ( O0OO0O . translated_port )
   if 11 - 11: I1IiiI
   if 45 - 45: OOooOOo / i1IIi * IiII * I1Ii111
 return ( None )
 if 34 - 34: ooOoO0o / iIii1I11I1II1 . iII111i
 if 91 - 91: OoO0O00
 if 8 - 8: oO0o
 if 96 - 96: IiII
 if 37 - 37: Ii1I % i11iIiiIii + iIii1I11I1II1 % Oo0Ooo - iIii1I11I1II1
 if 26 - 26: o0oOOo0O0Ooo . i1IIi
 if 62 - 62: IiII * I1ii11iIi11i % iIii1I11I1II1 / II111iiii - OoO0O00
 if 52 - 52: iII111i . I11i - I11i + oO0o + iIii1I11I1II1
 if 83 - 83: I11i * iIii1I11I1II1 + OoOoOO00
def lisp_get_any_translated_rloc ( ) :
 for iIiIIi1i in lisp_db_list :
  for O0OO0O in iIiIIi1i . rloc_set :
   if ( O0OO0O . translated_rloc . is_null ( ) ) : continue
   return ( O0OO0O . translated_rloc )
   if 81 - 81: ooOoO0o * OOooOOo / OoO0O00 + I1ii11iIi11i % I1Ii111
   if 37 - 37: i11iIiiIii - OoooooooOO - OoOoOO00 * oO0o / Ii1I
 return ( None )
 if 100 - 100: II111iiii / Oo0Ooo / iII111i / OOooOOo
 if 100 - 100: iIii1I11I1II1
 if 50 - 50: I1Ii111 / ooOoO0o * I11i
 if 53 - 53: II111iiii . IiII
 if 5 - 5: i1IIi % IiII
 if 16 - 16: ooOoO0o - iII111i % Ii1I . OoOoOO00
 if 56 - 56: i11iIiiIii % i11iIiiIii % OoooooooOO . Ii1I . iII111i + I11i
def lisp_get_all_translated_rlocs ( ) :
 oOoII = [ ]
 for iIiIIi1i in lisp_db_list :
  for O0OO0O in iIiIIi1i . rloc_set :
   if ( O0OO0O . is_rloc_translated ( ) == False ) : continue
   iIiIi1iI11iiI = O0OO0O . translated_rloc . print_address_no_iid ( )
   oOoII . append ( iIiIi1iI11iiI )
   if 34 - 34: OoO0O00 * iIii1I11I1II1 . iIii1I11I1II1
   if 39 - 39: o0oOOo0O0Ooo
 return ( oOoII )
 if 29 - 29: Oo0Ooo . Oo0Ooo * OoO0O00 % Ii1I - ooOoO0o
 if 67 - 67: I1IiiI % O0 + I1IiiI * I1Ii111 * OoOoOO00 * II111iiii
 if 79 - 79: I1IiiI
 if 37 - 37: I1Ii111 + Ii1I
 if 50 - 50: i11iIiiIii
 if 57 - 57: O0 * i1IIi - I1IiiI
 if 48 - 48: IiII / iIii1I11I1II1
 if 20 - 20: oO0o / OoooooooOO
def lisp_update_default_routes ( map_resolver , iid , rtr_list ) :
 OOOO = ( os . getenv ( "LISP_RTR_BEHIND_NAT" ) != None )
 if 95 - 95: Oo0Ooo . i11iIiiIii
 i1IiI1i = { }
 for Oo0o0o0oo in rtr_list :
  if ( Oo0o0o0oo == None ) : continue
  iIiIi1iI11iiI = rtr_list [ Oo0o0o0oo ]
  if ( OOOO and iIiIi1iI11iiI . is_private_address ( ) ) : continue
  i1IiI1i [ Oo0o0o0oo ] = iIiIi1iI11iiI
  if 10 - 10: OoO0O00 - oO0o + Oo0Ooo / i11iIiiIii + Ii1I + I11i
 rtr_list = i1IiI1i
 if 59 - 59: ooOoO0o * II111iiii
 ooOoOOOoO = [ ]
 for o0o0O00oOo in [ LISP_AFI_IPV4 , LISP_AFI_IPV6 , LISP_AFI_MAC ] :
  if ( o0o0O00oOo == LISP_AFI_MAC and lisp_l2_overlay == False ) : break
  if 14 - 14: OoO0O00 * I1IiiI
  if 78 - 78: I1IiiI / iII111i - ooOoO0o - i11iIiiIii
  if 39 - 39: i11iIiiIii / oO0o
  if 71 - 71: I1Ii111 * iIii1I11I1II1 - I1Ii111
  if 87 - 87: I1IiiI / Ii1I
  OOO0000o = lisp_address ( o0o0O00oOo , "" , 0 , iid )
  OOO0000o . make_default_route ( OOO0000o )
  ooooOoo000O = lisp_map_cache . lookup_cache ( OOO0000o , True )
  if ( ooooOoo000O ) :
   if ( ooooOoo000O . checkpoint_entry ) :
    lprint ( "Updating checkpoint entry for {}" . format ( green ( ooooOoo000O . print_eid_tuple ( ) , False ) ) )
    if 54 - 54: OoooooooOO / Ii1I
   elif ( ooooOoo000O . do_rloc_sets_match ( rtr_list . values ( ) ) ) :
    continue
    if 26 - 26: o0oOOo0O0Ooo + OoO0O00
   ooooOoo000O . delete_cache ( )
   if 59 - 59: Ii1I * IiII
   if 64 - 64: ooOoO0o . Oo0Ooo - OoOoOO00
  ooOoOOOoO . append ( [ OOO0000o , "" ] )
  if 66 - 66: OoOoOO00
  if 83 - 83: OOooOOo . IiII
  if 98 - 98: i11iIiiIii
  if 74 - 74: iIii1I11I1II1 * O0 + OOooOOo . o0oOOo0O0Ooo
  i1i11Ii1 = lisp_address ( o0o0O00oOo , "" , 0 , iid )
  i1i11Ii1 . make_default_multicast_route ( i1i11Ii1 )
  iI1iI1II1i1i = lisp_map_cache . lookup_cache ( i1i11Ii1 , True )
  if ( iI1iI1II1i1i ) : iI1iI1II1i1i = iI1iI1II1i1i . source_cache . lookup_cache ( OOO0000o , True )
  if ( iI1iI1II1i1i ) : iI1iI1II1i1i . delete_cache ( )
  if 68 - 68: iII111i
  ooOoOOOoO . append ( [ OOO0000o , i1i11Ii1 ] )
  if 68 - 68: I1Ii111 - OoO0O00 % OoO0O00 % OOooOOo - OoO0O00
 if ( len ( ooOoOOOoO ) == 0 ) : return
 if 3 - 3: iIii1I11I1II1 + iIii1I11I1II1 + OoO0O00
 if 59 - 59: iII111i
 if 7 - 7: o0oOOo0O0Ooo * OoooooooOO - Ii1I * II111iiii % I1Ii111
 if 82 - 82: OoOoOO00 - OoOoOO00 + iIii1I11I1II1 + o0oOOo0O0Ooo + IiII - o0oOOo0O0Ooo
 iiiI11II1IiIi = [ ]
 for Ii111iI1iI1ii in rtr_list :
  o00000 = rtr_list [ Ii111iI1iI1ii ]
  O0OO0O = lisp_rloc ( )
  O0OO0O . rloc . copy_address ( o00000 )
  O0OO0O . priority = 254
  O0OO0O . mpriority = 255
  O0OO0O . rloc_name = "RTR"
  iiiI11II1IiIi . append ( O0OO0O )
  if 65 - 65: iII111i + OoO0O00 - iIii1I11I1II1 / OoooooooOO . ooOoO0o . o0oOOo0O0Ooo
  if 94 - 94: ooOoO0o . oO0o * OoooooooOO % oO0o
 for OOO0000o in ooOoOOOoO :
  ooooOoo000O = lisp_mapping ( OOO0000o [ 0 ] , OOO0000o [ 1 ] , iiiI11II1IiIi )
  ooooOoo000O . mapping_source = map_resolver
  ooooOoo000O . map_cache_ttl = LISP_MR_TTL * 60
  ooooOoo000O . add_cache ( )
  lprint ( "Add {} to map-cache with RTR RLOC-set: {}" . format ( green ( ooooOoo000O . print_eid_tuple ( ) , False ) , rtr_list . keys ( ) ) )
  if 77 - 77: ooOoO0o % I1IiiI
  iiiI11II1IiIi = copy . deepcopy ( iiiI11II1IiIi )
  if 26 - 26: o0oOOo0O0Ooo
 return
 if 72 - 72: I1IiiI
 if 90 - 90: ooOoO0o
 if 67 - 67: iIii1I11I1II1 + i1IIi * I1IiiI * OoooooooOO
 if 23 - 23: IiII
 if 32 - 32: OoOoOO00 - iII111i % oO0o / I1ii11iIi11i - o0oOOo0O0Ooo
 if 52 - 52: Ii1I / OoooooooOO % i11iIiiIii + iII111i
 if 59 - 59: Ii1I / o0oOOo0O0Ooo / oO0o + iII111i * I1ii11iIi11i - o0oOOo0O0Ooo
 if 70 - 70: O0 / I1ii11iIi11i + ooOoO0o . OoO0O00 - OoO0O00 / i11iIiiIii
 if 1 - 1: iIii1I11I1II1 % I1ii11iIi11i
 if 49 - 49: iII111i + o0oOOo0O0Ooo % I1ii11iIi11i . O0 % OoooooooOO . o0oOOo0O0Ooo
def lisp_process_info_reply ( source , packet , store ) :
 if 3 - 3: i11iIiiIii - i1IIi * o0oOOo0O0Ooo / OoOoOO00 % Oo0Ooo
 if 65 - 65: OoooooooOO + iII111i - i11iIiiIii - IiII + oO0o
 if 67 - 67: i1IIi * I1Ii111 * O0
 if 16 - 16: OoO0O00 + iII111i + i1IIi + I1ii11iIi11i - I1IiiI
 i1iI1iII = lisp_info ( )
 packet = i1iI1iII . decode ( packet )
 if ( packet == None ) : return ( [ None , None , False ] )
 if 88 - 88: oO0o % iII111i + I1ii11iIi11i - II111iiii . I11i
 i1iI1iII . print_info ( )
 if 18 - 18: I1ii11iIi11i - i1IIi - IiII * II111iiii % I1Ii111 . II111iiii
 if 80 - 80: oO0o + OoO0O00 + o0oOOo0O0Ooo . OoOoOO00
 if 75 - 75: i11iIiiIii
 if 58 - 58: iII111i
 iIi111I1iiii = False
 for Ii111iI1iI1ii in i1iI1iII . rtr_list :
  ooOOo0o = Ii111iI1iI1ii . print_address_no_iid ( )
  if ( lisp_rtr_list . has_key ( ooOOo0o ) ) :
   if ( lisp_register_all_rtrs == False ) : continue
   if ( lisp_rtr_list [ ooOOo0o ] != None ) : continue
   if 66 - 66: O0 % OoOoOO00 + IiII % I1Ii111
  iIi111I1iiii = True
  lisp_rtr_list [ ooOOo0o ] = Ii111iI1iI1ii
  if 94 - 94: OoOoOO00 / OoooooooOO % Ii1I * i11iIiiIii
  if 95 - 95: iIii1I11I1II1 % OOooOOo % O0
  if 93 - 93: I1ii11iIi11i
  if 61 - 61: o0oOOo0O0Ooo * ooOoO0o
  if 82 - 82: O0 * O0 % I1IiiI / o0oOOo0O0Ooo
 if ( lisp_i_am_itr and iIi111I1iiii ) :
  if ( lisp_iid_to_interface == { } ) :
   lisp_update_default_routes ( source , lisp_default_iid , lisp_rtr_list )
  else :
   for II1 in lisp_iid_to_interface . keys ( ) :
    lisp_update_default_routes ( source , int ( II1 ) , lisp_rtr_list )
    if 46 - 46: IiII . O0 . I11i % I1ii11iIi11i * oO0o - oO0o
    if 92 - 92: I1IiiI - I1IiiI
    if 28 - 28: oO0o * iII111i + IiII
    if 73 - 73: OoooooooOO
    if 45 - 45: IiII + I1IiiI * I1Ii111
    if 82 - 82: OOooOOo / I11i % Ii1I * OoOoOO00
    if 88 - 88: o0oOOo0O0Ooo % OoO0O00
 if ( store == False ) :
  return ( [ i1iI1iII . global_etr_rloc , i1iI1iII . etr_port , iIi111I1iiii ] )
  if 30 - 30: II111iiii / Oo0Ooo % Oo0Ooo + O0 / iIii1I11I1II1 . OoO0O00
  if 43 - 43: I1IiiI % OoOoOO00 * O0 + o0oOOo0O0Ooo
  if 97 - 97: iIii1I11I1II1 + O0
  if 41 - 41: OoOoOO00 - II111iiii
  if 46 - 46: OOooOOo
  if 73 - 73: iII111i - IiII + II111iiii
 for iIiIIi1i in lisp_db_list :
  for O0OO0O in iIiIIi1i . rloc_set :
   Oo0o0o0oo = O0OO0O . rloc
   II111IiiiI1 = O0OO0O . interface
   if ( II111IiiiI1 == None ) :
    if ( Oo0o0o0oo . is_null ( ) ) : continue
    if ( Oo0o0o0oo . is_local ( ) == False ) : continue
    if ( i1iI1iII . private_etr_rloc . is_null ( ) == False and
 Oo0o0o0oo . is_exact_match ( i1iI1iII . private_etr_rloc ) == False ) :
     continue
     if 58 - 58: Oo0Ooo % I1IiiI
   elif ( i1iI1iII . private_etr_rloc . is_dist_name ( ) ) :
    i1OOO = i1iI1iII . private_etr_rloc . address
    if ( i1OOO != O0OO0O . rloc_name ) : continue
    if 78 - 78: iII111i / iIii1I11I1II1 * IiII . ooOoO0o / I1Ii111 % I11i
    if 14 - 14: II111iiii % iIii1I11I1II1 - I1IiiI % i11iIiiIii . OOooOOo * I1ii11iIi11i
   oO00oo000O = green ( iIiIIi1i . eid . print_prefix ( ) , False )
   ooOOo00o0ooO = red ( Oo0o0o0oo . print_address_no_iid ( ) , False )
   if 12 - 12: I1ii11iIi11i % I1ii11iIi11i . OoO0O00 . OoOoOO00
   OO0ooOoo000O = i1iI1iII . global_etr_rloc . is_exact_match ( Oo0o0o0oo )
   if ( O0OO0O . translated_port == 0 and OO0ooOoo000O ) :
    lprint ( "No NAT for {} ({}), EID-prefix {}" . format ( ooOOo00o0ooO ,
 II111IiiiI1 , oO00oo000O ) )
    continue
    if 69 - 69: O0 / Ii1I
    if 58 - 58: I11i % Ii1I - iIii1I11I1II1 + ooOoO0o
    if 28 - 28: i1IIi + IiII . I1Ii111 . OoOoOO00 % O0 - I1ii11iIi11i
    if 68 - 68: oO0o
    if 3 - 3: o0oOOo0O0Ooo + iII111i / o0oOOo0O0Ooo / I1IiiI * OOooOOo
   oO0oo0O0oOOo0 = i1iI1iII . global_etr_rloc
   oo0o = O0OO0O . translated_rloc
   if ( oo0o . is_exact_match ( oO0oo0O0oOOo0 ) and
 i1iI1iII . etr_port == O0OO0O . translated_port ) : continue
   if 75 - 75: OoO0O00 . IiII / I11i * i11iIiiIii - OoO0O00 / IiII
   lprint ( "Store translation {}:{} for {} ({}), EID-prefix {}" . format ( red ( i1iI1iII . global_etr_rloc . print_address_no_iid ( ) , False ) ,
   # I1Ii111 + II111iiii + II111iiii + I1Ii111 % Ii1I % iIii1I11I1II1
 i1iI1iII . etr_port , ooOOo00o0ooO , II111IiiiI1 , oO00oo000O ) )
   if 48 - 48: Ii1I + oO0o + Ii1I . I1ii11iIi11i
   O0OO0O . store_translated_rloc ( i1iI1iII . global_etr_rloc ,
 i1iI1iII . etr_port )
   if 32 - 32: OoOoOO00 . Oo0Ooo . OoOoOO00 * OoOoOO00 % I11i
   if 21 - 21: ooOoO0o . i11iIiiIii / IiII . i1IIi + OoooooooOO
 return ( [ i1iI1iII . global_etr_rloc , i1iI1iII . etr_port , iIi111I1iiii ] )
 if 18 - 18: ooOoO0o - I11i - I1Ii111
 if 81 - 81: IiII - Ii1I % i1IIi
 if 48 - 48: Ii1I + I11i % iIii1I11I1II1 + ooOoO0o + ooOoO0o + OoO0O00
 if 7 - 7: O0 + II111iiii
 if 44 - 44: OOooOOo + i11iIiiIii - I1Ii111 + ooOoO0o
 if 92 - 92: O0 . iIii1I11I1II1 % iIii1I11I1II1 % OoO0O00 - i11iIiiIii - iII111i
 if 76 - 76: OoO0O00 . II111iiii / I1ii11iIi11i
 if 15 - 15: OoOoOO00 . O0 + iII111i + I1IiiI . ooOoO0o + iIii1I11I1II1
def lisp_test_mr ( lisp_sockets , port ) :
 return
 lprint ( "Test Map-Resolvers" )
 if 2 - 2: I11i
 Oo00o = lisp_address ( LISP_AFI_IPV4 , "" , 0 , 0 )
 oooO = lisp_address ( LISP_AFI_IPV6 , "" , 0 , 0 )
 if 86 - 86: iIii1I11I1II1 + Oo0Ooo % ooOoO0o - iIii1I11I1II1 % ooOoO0o * OoOoOO00
 if 80 - 80: Oo0Ooo . i1IIi - OOooOOo * OoOoOO00 . I1ii11iIi11i % OoO0O00
 if 43 - 43: I1IiiI . I11i . Oo0Ooo % I1ii11iIi11i * O0
 if 14 - 14: I1IiiI + Oo0Ooo - Ii1I - ooOoO0o % OoO0O00
 Oo00o . store_address ( "10.0.0.1" )
 lisp_send_map_request ( lisp_sockets , port , None , Oo00o , None )
 Oo00o . store_address ( "192.168.0.1" )
 lisp_send_map_request ( lisp_sockets , port , None , Oo00o , None )
 if 63 - 63: OoooooooOO * iII111i % ooOoO0o
 if 17 - 17: OoO0O00 % II111iiii . i1IIi . OOooOOo
 if 49 - 49: II111iiii / OoOoOO00 * IiII % OoO0O00
 if 77 - 77: OoOoOO00 + OOooOOo % o0oOOo0O0Ooo
 oooO . store_address ( "0100::1" )
 lisp_send_map_request ( lisp_sockets , port , None , oooO , None )
 oooO . store_address ( "8000::1" )
 lisp_send_map_request ( lisp_sockets , port , None , oooO , None )
 if 3 - 3: ooOoO0o / i1IIi
 if 71 - 71: Ii1I + oO0o % IiII
 if 15 - 15: ooOoO0o . Oo0Ooo
 if 42 - 42: OOooOOo . i11iIiiIii % O0 - OoO0O00
 I11I11iiii = threading . Timer ( LISP_TEST_MR_INTERVAL , lisp_test_mr ,
 [ lisp_sockets , port ] )
 I11I11iiii . start ( )
 return
 if 34 - 34: i1IIi - I11i * OoooooooOO . IiII - I1Ii111
 if 93 - 93: I1Ii111 . o0oOOo0O0Ooo
 if 96 - 96: ooOoO0o - o0oOOo0O0Ooo % O0 * Ii1I . OoOoOO00
 if 80 - 80: I1IiiI
 if 31 - 31: I1Ii111 + o0oOOo0O0Ooo . I1IiiI + I11i . oO0o
 if 50 - 50: Ii1I . OOooOOo
 if 84 - 84: OoOoOO00 * OoO0O00 + I1IiiI
 if 38 - 38: OoooooooOO % I1IiiI
 if 80 - 80: iII111i / O0 % OoooooooOO / Oo0Ooo
 if 75 - 75: ooOoO0o
 if 72 - 72: oO0o . OoooooooOO % ooOoO0o % OoO0O00 * oO0o * OoO0O00
 if 14 - 14: I11i / I11i
 if 90 - 90: O0 * OOooOOo / oO0o . Oo0Ooo * I11i
def lisp_update_local_rloc ( rloc ) :
 if ( rloc . interface == None ) : return
 if 93 - 93: oO0o / ooOoO0o - I1Ii111
 iIiIi1iI11iiI = lisp_get_interface_address ( rloc . interface )
 if ( iIiIi1iI11iiI == None ) : return
 if 70 - 70: OOooOOo / Ii1I - ooOoO0o + OoooooooOO / OoO0O00 - i11iIiiIii
 iiIii1i = rloc . rloc . print_address_no_iid ( )
 iiiii1I = iIiIi1iI11iiI . print_address_no_iid ( )
 if 4 - 4: I1Ii111
 if ( iiIii1i == iiiii1I ) : return
 if 15 - 15: I11i % I11i / iIii1I11I1II1 - i11iIiiIii / i1IIi
 lprint ( "Local interface address changed on {} from {} to {}" . format ( rloc . interface , iiIii1i , iiiii1I ) )
 if 9 - 9: OoooooooOO
 if 71 - 71: Ii1I
 rloc . rloc . copy_address ( iIiIi1iI11iiI )
 lisp_myrlocs [ 0 ] = iIiIi1iI11iiI
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
 for Oo0o0o0oo in mc . rloc_set :
  iiI = lisp_get_nat_info ( Oo0o0o0oo . rloc , Oo0o0o0oo . rloc_name )
  if ( iiI == None ) : continue
  if ( Oo0o0o0oo . translated_port == iiI . port ) : continue
  if 27 - 27: OoO0O00 * OoooooooOO - II111iiii / o0oOOo0O0Ooo
  lprint ( ( "Encap-port changed from {} to {} for RLOC {}, " + "EID-prefix {}" ) . format ( Oo0o0o0oo . translated_port , iiI . port ,
  # I11i * Ii1I % OoO0O00 * I1Ii111 % IiII
 red ( Oo0o0o0oo . rloc . print_address_no_iid ( ) , False ) ,
 green ( mc . print_eid_tuple ( ) , False ) ) )
  if 35 - 35: iII111i + iIii1I11I1II1 + II111iiii % IiII * Ii1I
  Oo0o0o0oo . store_translated_rloc ( Oo0o0o0oo . rloc , iiI . port )
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
 O0oO0oOOO0oO = lisp_get_timestamp ( )
 if 93 - 93: OoO0O00 - I1Ii111 - OoO0O00
 if 1 - 1: o0oOOo0O0Ooo . oO0o * i11iIiiIii * IiII - OoO0O00 - OoooooooOO
 if 29 - 29: iIii1I11I1II1 + OoO0O00 * II111iiii * Ii1I * iII111i . O0
 if 6 - 6: I1IiiI - OoOoOO00
 if 63 - 63: OOooOOo - oO0o * I1IiiI
 if 60 - 60: II111iiii - Oo0Ooo
 if ( mc . last_refresh_time + mc . map_cache_ttl > O0oO0oOOO0oO ) :
  if ( mc . action == LISP_NO_ACTION ) : lisp_update_encap_port ( mc )
  return ( [ True , delete_list ] )
  if 43 - 43: I1IiiI - IiII - OOooOOo
  if 19 - 19: I1Ii111 / I1Ii111 - i1IIi
  if 99 - 99: O0
  if 37 - 37: iIii1I11I1II1 / I1Ii111 + OoO0O00
  if 85 - 85: ooOoO0o / I1IiiI
 iIIiI1iiI = lisp_print_elapsed ( mc . last_refresh_time )
 I11Ii11ii = mc . print_eid_tuple ( )
 lprint ( "Map-cache entry for EID-prefix {} has {}, had uptime of {}" . format ( green ( I11Ii11ii , False ) , bold ( "timed out" , False ) , iIIiI1iiI ) )
 if 7 - 7: Oo0Ooo - iIii1I11I1II1 / I1ii11iIi11i * I1IiiI + Ii1I
 if 99 - 99: i11iIiiIii - I1ii11iIi11i
 if 64 - 64: IiII . OoOoOO00 . Oo0Ooo . I1Ii111 / I11i / Ii1I
 if 95 - 95: iIii1I11I1II1 . Ii1I % oO0o - I11i % IiII
 if 42 - 42: OoOoOO00 + oO0o * i1IIi + i11iIiiIii
 delete_list . append ( mc )
 return ( [ True , delete_list ] )
 if 25 - 25: Ii1I - Ii1I - I1ii11iIi11i / i1IIi . OoOoOO00 % Oo0Ooo
 if 76 - 76: I1Ii111 / OoOoOO00
 if 61 - 61: Oo0Ooo . i1IIi
 if 78 - 78: i11iIiiIii
 if 20 - 20: Ii1I
 if 100 - 100: OoooooooOO . I1Ii111
 if 32 - 32: iIii1I11I1II1 . iIii1I11I1II1 % II111iiii / Oo0Ooo . iIii1I11I1II1 . O0
 if 63 - 63: I1IiiI . iIii1I11I1II1 . Oo0Ooo % OOooOOo - iII111i + ooOoO0o
def lisp_timeout_map_cache_walk ( mc , parms ) :
 iIIii1III = parms [ 0 ]
 OO000 = parms [ 1 ]
 if 91 - 91: IiII % IiII % IiII
 if 81 - 81: I1ii11iIi11i
 if 59 - 59: I11i + i11iIiiIii
 if 48 - 48: Oo0Ooo
 if ( mc . group . is_null ( ) ) :
  OooO000oo0o , iIIii1III = lisp_timeout_map_cache_entry ( mc , iIIii1III )
  if ( iIIii1III == [ ] or mc != iIIii1III [ - 1 ] ) :
   OO000 = lisp_write_checkpoint_entry ( OO000 , mc )
   if 9 - 9: IiII - ooOoO0o * Ii1I / I1IiiI . i1IIi % O0
  return ( [ OooO000oo0o , parms ] )
  if 96 - 96: OoooooooOO
  if 83 - 83: i1IIi * OoO0O00
 if ( mc . source_cache == None ) : return ( [ True , parms ] )
 if 30 - 30: OOooOOo % IiII
 if 88 - 88: i1IIi - OoOoOO00
 if 66 - 66: OoooooooOO - OoooooooOO * I11i / II111iiii + oO0o / Ii1I
 if 7 - 7: Ii1I / iIii1I11I1II1
 if 36 - 36: iIii1I11I1II1 % i11iIiiIii
 parms = mc . source_cache . walk_cache ( lisp_timeout_map_cache_entry , parms )
 return ( [ True , parms ] )
 if 35 - 35: Oo0Ooo + I1IiiI - O0 - I1Ii111
 if 64 - 64: i1IIi * OoOoOO00 / II111iiii * oO0o
 if 35 - 35: i1IIi - Ii1I - Ii1I . O0 % iII111i * iII111i
 if 15 - 15: OoooooooOO . Ii1I * I1Ii111 . ooOoO0o % OoO0O00 * Oo0Ooo
 if 10 - 10: iII111i + i11iIiiIii . OOooOOo % iII111i - i1IIi
 if 10 - 10: iIii1I11I1II1 * i11iIiiIii - O0
 if 45 - 45: oO0o % OOooOOo - IiII + o0oOOo0O0Ooo + i11iIiiIii
def lisp_timeout_map_cache ( lisp_map_cache ) :
 IiI11I111 = [ [ ] , [ ] ]
 IiI11I111 = lisp_map_cache . walk_cache ( lisp_timeout_map_cache_walk , IiI11I111 )
 if 79 - 79: IiII % I1Ii111 . I1IiiI + O0 * oO0o * ooOoO0o
 if 38 - 38: IiII
 if 78 - 78: Oo0Ooo * I1ii11iIi11i % OOooOOo / Oo0Ooo + I1ii11iIi11i * IiII
 if 2 - 2: Oo0Ooo - OoOoOO00
 if 22 - 22: OoO0O00 - oO0o - O0
 iIIii1III = IiI11I111 [ 0 ]
 for ooooOoo000O in iIIii1III : ooooOoo000O . delete_cache ( )
 if 49 - 49: iIii1I11I1II1 + I1Ii111 / i11iIiiIii
 if 62 - 62: ooOoO0o . I1IiiI * i11iIiiIii
 if 2 - 2: i11iIiiIii
 if 86 - 86: I1Ii111 + o0oOOo0O0Ooo
 OO000 = IiI11I111 [ 1 ]
 lisp_checkpoint ( OO000 )
 return
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
 if 19 - 19: iIii1I11I1II1 + I1Ii111 / OoooooooOO % OOooOOo - i1IIi + I11i
 if 87 - 87: OoooooooOO
 if 97 - 97: ooOoO0o * IiII / iIii1I11I1II1
 if 65 - 65: i1IIi - i11iIiiIii + oO0o % I1IiiI - OoO0O00 % ooOoO0o
def lisp_store_nat_info ( hostname , rloc , port ) :
 ooOOo0o = rloc . print_address_no_iid ( )
 IIOoOO = "{} NAT state for {}, RLOC {}, port {}" . format ( "{}" ,
 blue ( hostname , False ) , red ( ooOOo0o , False ) , port )
 if 94 - 94: i11iIiiIii * i11iIiiIii * I1ii11iIi11i
 oOOo00OO0oO0o = lisp_nat_info ( ooOOo0o , hostname , port )
 if 57 - 57: i11iIiiIii / iII111i / o0oOOo0O0Ooo
 if ( lisp_nat_state_info . has_key ( hostname ) == False ) :
  lisp_nat_state_info [ hostname ] = [ oOOo00OO0oO0o ]
  lprint ( IIOoOO . format ( "Store initial" ) )
  return ( True )
  if 39 - 39: II111iiii * iII111i
  if 7 - 7: OOooOOo + OoOoOO00 . II111iiii * OoO0O00 . I1IiiI * o0oOOo0O0Ooo
  if 62 - 62: I1ii11iIi11i / iIii1I11I1II1 + oO0o . II111iiii
  if 65 - 65: Oo0Ooo % i1IIi * o0oOOo0O0Ooo * IiII
  if 24 - 24: i11iIiiIii / iIii1I11I1II1 / iII111i
  if 31 - 31: OOooOOo . iIii1I11I1II1 - oO0o
 iiI = lisp_nat_state_info [ hostname ] [ 0 ]
 if ( iiI . address == ooOOo0o and iiI . port == port ) :
  iiI . uptime = lisp_get_timestamp ( )
  lprint ( IIOoOO . format ( "Refresh existing" ) )
  return ( False )
  if 36 - 36: O0
  if 30 - 30: i11iIiiIii * Oo0Ooo . IiII
  if 65 - 65: oO0o * IiII * OOooOOo / OoooooooOO % I11i / I1Ii111
  if 21 - 21: i1IIi * iII111i + OoO0O00
  if 27 - 27: I11i / oO0o . iII111i + o0oOOo0O0Ooo - OOooOOo
  if 85 - 85: OoooooooOO
  if 83 - 83: iII111i * I11i . OOooOOo - OoO0O00 % IiII
 i11I1111iIII = None
 for iiI in lisp_nat_state_info [ hostname ] :
  if ( iiI . address == ooOOo0o and iiI . port == port ) :
   i11I1111iIII = iiI
   break
   if 49 - 49: OOooOOo / i1IIi - II111iiii . iIii1I11I1II1 + I11i . OOooOOo
   if 9 - 9: iIii1I11I1II1 + Ii1I + I11i
   if 96 - 96: OoO0O00 + i11iIiiIii + OoO0O00
 if ( i11I1111iIII == None ) :
  lprint ( IIOoOO . format ( "Store new" ) )
 else :
  lisp_nat_state_info [ hostname ] . remove ( i11I1111iIII )
  lprint ( IIOoOO . format ( "Use previous" ) )
  if 7 - 7: i1IIi . I1IiiI
  if 68 - 68: OoooooooOO
 o00 = lisp_nat_state_info [ hostname ]
 lisp_nat_state_info [ hostname ] = [ oOOo00OO0oO0o ] + o00
 return ( True )
 if 99 - 99: II111iiii + o0oOOo0O0Ooo + OOooOOo . O0 / iIii1I11I1II1
 if 28 - 28: ooOoO0o + OoO0O00 / i1IIi
 if 47 - 47: o0oOOo0O0Ooo / iII111i + iII111i % OoooooooOO
 if 23 - 23: I11i * OoO0O00 * I1ii11iIi11i . i1IIi % II111iiii
 if 15 - 15: O0 . I11i / IiII - iIii1I11I1II1 % Oo0Ooo
 if 76 - 76: I1ii11iIi11i . IiII - IiII
 if 51 - 51: i11iIiiIii
 if 11 - 11: I1ii11iIi11i
def lisp_get_nat_info ( rloc , hostname ) :
 if ( lisp_nat_state_info . has_key ( hostname ) == False ) : return ( None )
 if 96 - 96: iII111i * iIii1I11I1II1
 ooOOo0o = rloc . print_address_no_iid ( )
 for iiI in lisp_nat_state_info [ hostname ] :
  if ( iiI . address == ooOOo0o ) : return ( iiI )
  if 100 - 100: iIii1I11I1II1 . I1ii11iIi11i . i11iIiiIii % i11iIiiIii % I11i % Ii1I
 return ( None )
 if 39 - 39: I11i + OoOoOO00
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
 if 59 - 59: II111iiii + O0 . I1ii11iIi11i . Oo0Ooo * OoO0O00
def lisp_build_info_requests ( lisp_sockets , dest , port ) :
 if ( lisp_nat_traversal == False ) : return
 if 35 - 35: oO0o / I1Ii111 * OOooOOo + OoooooooOO . IiII
 if 1 - 1: I1IiiI + I1Ii111 / OOooOOo . Ii1I . oO0o / I1ii11iIi11i
 if 54 - 54: OOooOOo
 if 86 - 86: oO0o * Oo0Ooo / OOooOOo
 if 18 - 18: II111iiii - I1Ii111
 if 13 - 13: i11iIiiIii - O0 % OoOoOO00 + OOooOOo * ooOoO0o
 Ooo0000oO = [ ]
 ooOooO00OO = [ ]
 if ( dest == None ) :
  for Ii1IIi1III1i in lisp_map_resolvers_list . values ( ) :
   ooOooO00OO . append ( Ii1IIi1III1i . map_resolver )
   if 79 - 79: ooOoO0o - O0
  Ooo0000oO = ooOooO00OO
  if ( Ooo0000oO == [ ] ) :
   for ooooOOoO in lisp_map_servers_list . values ( ) :
    Ooo0000oO . append ( ooooOOoO . map_server )
    if 20 - 20: OOooOOo
    if 22 - 22: iIii1I11I1II1 / I1Ii111
  if ( Ooo0000oO == [ ] ) : return
 else :
  Ooo0000oO . append ( dest )
  if 6 - 6: iII111i . i11iIiiIii / Oo0Ooo
  if 86 - 86: I11i % I1Ii111 % oO0o - ooOoO0o / i1IIi
  if 68 - 68: i1IIi % O0 % iII111i
  if 55 - 55: I1ii11iIi11i % OOooOOo - o0oOOo0O0Ooo - II111iiii
  if 52 - 52: I1Ii111
 oOoII = { }
 for iIiIIi1i in lisp_db_list :
  for O0OO0O in iIiIIi1i . rloc_set :
   lisp_update_local_rloc ( O0OO0O )
   if ( O0OO0O . rloc . is_null ( ) ) : continue
   if ( O0OO0O . interface == None ) : continue
   if 34 - 34: II111iiii + iII111i / IiII
   iIiIi1iI11iiI = O0OO0O . rloc . print_address_no_iid ( )
   if ( iIiIi1iI11iiI in oOoII ) : continue
   oOoII [ iIiIi1iI11iiI ] = O0OO0O . interface
   if 47 - 47: OoO0O00
   if 40 - 40: o0oOOo0O0Ooo / iII111i . o0oOOo0O0Ooo
 if ( oOoII == { } ) :
  lprint ( 'Suppress Info-Request, no "interface = <device>" RLOC ' + "found in any database-mappings" )
  if 63 - 63: o0oOOo0O0Ooo * iIii1I11I1II1 * II111iiii . OoO0O00 - oO0o / OoOoOO00
  return
  if 78 - 78: i11iIiiIii / OoO0O00 / i1IIi . i11iIiiIii
  if 100 - 100: II111iiii . IiII . I11i
  if 60 - 60: OoOoOO00 % OOooOOo * i1IIi
  if 3 - 3: OoooooooOO
  if 75 - 75: OoooooooOO * I1Ii111 * o0oOOo0O0Ooo + I1ii11iIi11i . iIii1I11I1II1 / O0
  if 23 - 23: oO0o - O0 * IiII + i11iIiiIii * Ii1I
 for iIiIi1iI11iiI in oOoII :
  II111IiiiI1 = oOoII [ iIiIi1iI11iiI ]
  ii1iI1iI1 = red ( iIiIi1iI11iiI , False )
  lprint ( "Build Info-Request for private address {} ({})" . format ( ii1iI1iI1 ,
 II111IiiiI1 ) )
  oO00O = II111IiiiI1 if len ( oOoII ) > 1 else None
  for dest in Ooo0000oO :
   lisp_send_info_request ( lisp_sockets , dest , port , oO00O )
   if 8 - 8: ooOoO0o / II111iiii . I1ii11iIi11i * ooOoO0o % oO0o
   if 36 - 36: I1ii11iIi11i % OOooOOo - ooOoO0o - I11i + I1IiiI
   if 37 - 37: I1ii11iIi11i * IiII
   if 65 - 65: OOooOOo / O0 . I1ii11iIi11i % i1IIi % Oo0Ooo
   if 36 - 36: i11iIiiIii - OOooOOo + iII111i + iII111i * I11i * oO0o
   if 14 - 14: O0 - iII111i * I1Ii111 - I1IiiI + IiII
 if ( ooOooO00OO != [ ] ) :
  for Ii1IIi1III1i in lisp_map_resolvers_list . values ( ) :
   Ii1IIi1III1i . resolve_dns_name ( )
   if 46 - 46: OoooooooOO * OoO0O00 . I1Ii111
   if 95 - 95: ooOoO0o . I1ii11iIi11i . ooOoO0o / I1IiiI * OoOoOO00 . O0
 return
 if 78 - 78: oO0o
 if 33 - 33: oO0o + i1IIi
 if 32 - 32: iIii1I11I1II1
 if 71 - 71: Ii1I * I1IiiI
 if 62 - 62: II111iiii / I1IiiI . I1ii11iIi11i
 if 49 - 49: IiII / OoOoOO00 / O0 * i11iIiiIii
 if 47 - 47: i11iIiiIii + iII111i + i11iIiiIii
 if 66 - 66: o0oOOo0O0Ooo . I1IiiI + OoooooooOO . iII111i / OoooooooOO - IiII
def lisp_valid_address_format ( kw , value ) :
 if ( kw != "address" ) : return ( True )
 if 47 - 47: o0oOOo0O0Ooo / II111iiii * i11iIiiIii * OoO0O00 . iIii1I11I1II1
 if 34 - 34: I11i / o0oOOo0O0Ooo * OOooOOo * OOooOOo
 if 89 - 89: I1ii11iIi11i . OoooooooOO
 if 61 - 61: i1IIi + i11iIiiIii
 if 59 - 59: i11iIiiIii * OOooOOo + i1IIi * iIii1I11I1II1 + I11i
 if ( value [ 0 ] == "'" and value [ - 1 ] == "'" ) : return ( True )
 if 97 - 97: OoO0O00 - I11i . OoooooooOO
 if 58 - 58: I1ii11iIi11i / II111iiii / i11iIiiIii
 if 27 - 27: iIii1I11I1II1 - O0 + OoOoOO00
 if 28 - 28: oO0o . IiII * iII111i % Oo0Ooo - OoO0O00 / I11i
 if ( value . find ( "." ) != - 1 ) :
  iIiIi1iI11iiI = value . split ( "." )
  if ( len ( iIiIi1iI11iiI ) != 4 ) : return ( False )
  if 67 - 67: i11iIiiIii + i11iIiiIii / ooOoO0o - o0oOOo0O0Ooo
  for OooO0o0 in iIiIi1iI11iiI :
   if ( OooO0o0 . isdigit ( ) == False ) : return ( False )
   if ( int ( OooO0o0 ) > 255 ) : return ( False )
   if 29 - 29: o0oOOo0O0Ooo
  return ( True )
  if 51 - 51: OoOoOO00 / Ii1I . I1IiiI / Ii1I . II111iiii - iIii1I11I1II1
  if 78 - 78: I11i
  if 42 - 42: Ii1I
  if 50 - 50: iIii1I11I1II1 / Ii1I . ooOoO0o / ooOoO0o * OoOoOO00 * iII111i
  if 15 - 15: o0oOOo0O0Ooo % II111iiii + I1IiiI
 if ( value . find ( "-" ) != - 1 ) :
  iIiIi1iI11iiI = value . split ( "-" )
  for II11iIII1i1I in [ "N" , "S" , "W" , "E" ] :
   if ( II11iIII1i1I in iIiIi1iI11iiI ) :
    if ( len ( iIiIi1iI11iiI ) < 8 ) : return ( False )
    return ( True )
    if 21 - 21: I1ii11iIi11i - ooOoO0o
    if 81 - 81: iII111i / i11iIiiIii / I1Ii111
    if 70 - 70: I1ii11iIi11i / i11iIiiIii
    if 90 - 90: II111iiii / OoOoOO00 . Ii1I . OoooooooOO
    if 76 - 76: OoooooooOO
    if 78 - 78: IiII % i11iIiiIii
    if 23 - 23: iIii1I11I1II1 - o0oOOo0O0Ooo - Ii1I % OOooOOo
 if ( value . find ( "-" ) != - 1 ) :
  iIiIi1iI11iiI = value . split ( "-" )
  if ( len ( iIiIi1iI11iiI ) != 3 ) : return ( False )
  if 100 - 100: oO0o . OoO0O00 . i11iIiiIii % II111iiii * IiII
  for oOO0OooOo in iIiIi1iI11iiI :
   try : int ( oOO0OooOo , 16 )
   except : return ( False )
   if 64 - 64: I11i * OoO0O00 . I1IiiI
  return ( True )
  if 99 - 99: IiII + OOooOOo - I11i . i1IIi % OoO0O00 - I11i
  if 96 - 96: I1Ii111 / Ii1I
  if 65 - 65: I1ii11iIi11i * O0 . IiII
  if 11 - 11: I11i / Ii1I % oO0o
  if 50 - 50: i11iIiiIii
 if ( value . find ( ":" ) != - 1 ) :
  iIiIi1iI11iiI = value . split ( ":" )
  if ( len ( iIiIi1iI11iiI ) < 2 ) : return ( False )
  if 93 - 93: i1IIi / Ii1I * II111iiii - Oo0Ooo . OoOoOO00 - OOooOOo
  I111 = False
  i1Ii11II = 0
  for oOO0OooOo in iIiIi1iI11iiI :
   i1Ii11II += 1
   if ( oOO0OooOo == "" ) :
    if ( I111 ) :
     if ( len ( iIiIi1iI11iiI ) == i1Ii11II ) : break
     if ( i1Ii11II > 2 ) : return ( False )
     if 67 - 67: I1ii11iIi11i - OoO0O00 % O0 / I1ii11iIi11i - OOooOOo . O0
    I111 = True
    continue
    if 4 - 4: O0
   try : int ( oOO0OooOo , 16 )
   except : return ( False )
   if 35 - 35: Ii1I . II111iiii % OoOoOO00
  return ( True )
  if 3 - 3: OOooOOo - OoOoOO00
  if 49 - 49: IiII / i11iIiiIii
  if 84 - 84: iIii1I11I1II1 / i1IIi + OoOoOO00
  if 40 - 40: Ii1I % OoO0O00
  if 93 - 93: iII111i . I1Ii111 . oO0o % o0oOOo0O0Ooo . Oo0Ooo
 if ( value [ 0 ] == "+" ) :
  iIiIi1iI11iiI = value [ 1 : : ]
  for oO0OOO0oo0Ooo in iIiIi1iI11iiI :
   if ( oO0OOO0oo0Ooo . isdigit ( ) == False ) : return ( False )
   if 73 - 73: I1Ii111 - II111iiii / Ii1I + Ii1I
  return ( True )
  if 41 - 41: II111iiii / II111iiii / iII111i * I1IiiI * I1Ii111 * oO0o
 return ( False )
 if 2 - 2: OoOoOO00 - I1ii11iIi11i * I1IiiI * Ii1I
 if 41 - 41: OoOoOO00 . OOooOOo / OoOoOO00 % iIii1I11I1II1
 if 47 - 47: ooOoO0o . i11iIiiIii / OoO0O00
 if 48 - 48: O0
 if 89 - 89: i11iIiiIii % OoO0O00 . OoOoOO00 + Oo0Ooo + OoOoOO00
 if 53 - 53: Ii1I / OoOoOO00 % iII111i * OoooooooOO + Oo0Ooo
 if 70 - 70: OoO0O00 % OoO0O00 * OoooooooOO
 if 96 - 96: ooOoO0o * Ii1I + I11i + II111iiii * I1IiiI / iII111i
 if 40 - 40: OoooooooOO - I11i % OOooOOo - I1IiiI . I1IiiI + Ii1I
 if 97 - 97: OOooOOo . OoooooooOO . OOooOOo . i11iIiiIii
 if 71 - 71: oO0o + I1ii11iIi11i * I1ii11iIi11i
 if 79 - 79: oO0o
def lisp_process_api ( process , lisp_socket , data_structure ) :
 ii1i1i1i1 , IiI11I111 = data_structure . split ( "%" )
 if 4 - 4: o0oOOo0O0Ooo - O0 * OoooooooOO % O0 * Ii1I
 lprint ( "Process API request '{}', parameters: '{}'" . format ( ii1i1i1i1 ,
 IiI11I111 ) )
 if 3 - 3: IiII + OoooooooOO - i1IIi
 i11 = [ ]
 if ( ii1i1i1i1 == "map-cache" ) :
  if ( IiI11I111 == "" ) :
   i11 = lisp_map_cache . walk_cache ( lisp_process_api_map_cache , i11 )
  else :
   i11 = lisp_process_api_map_cache_entry ( json . loads ( IiI11I111 ) )
   if 94 - 94: ooOoO0o / iIii1I11I1II1 + I11i + I1ii11iIi11i
   if 67 - 67: IiII / o0oOOo0O0Ooo . O0
 if ( ii1i1i1i1 == "site-cache" ) :
  if ( IiI11I111 == "" ) :
   i11 = lisp_sites_by_eid . walk_cache ( lisp_process_api_site_cache ,
 i11 )
  else :
   i11 = lisp_process_api_site_cache_entry ( json . loads ( IiI11I111 ) )
   if 7 - 7: II111iiii . OoOoOO00 % OoOoOO00 % Ii1I + Oo0Ooo - ooOoO0o
   if 29 - 29: OoOoOO00 - i1IIi
 if ( ii1i1i1i1 == "map-server" ) :
  IiI11I111 = { } if ( IiI11I111 == "" ) else json . loads ( IiI11I111 )
  i11 = lisp_process_api_ms_or_mr ( True , IiI11I111 )
  if 5 - 5: I1IiiI - ooOoO0o + O0
 if ( ii1i1i1i1 == "map-resolver" ) :
  IiI11I111 = { } if ( IiI11I111 == "" ) else json . loads ( IiI11I111 )
  i11 = lisp_process_api_ms_or_mr ( False , IiI11I111 )
  if 47 - 47: i1IIi - II111iiii - II111iiii
 if ( ii1i1i1i1 == "database-mapping" ) :
  i11 = lisp_process_api_database_mapping ( )
  if 31 - 31: Ii1I
  if 37 - 37: I1ii11iIi11i - Ii1I / oO0o . I1IiiI % I1Ii111
  if 8 - 8: oO0o
  if 46 - 46: I1Ii111 + IiII + II111iiii . o0oOOo0O0Ooo + i11iIiiIii
  if 97 - 97: o0oOOo0O0Ooo % OoOoOO00 * O0 / iIii1I11I1II1 * OoO0O00 / i11iIiiIii
 i11 = json . dumps ( i11 )
 oOooOOoo = lisp_api_ipc ( process , i11 )
 lisp_ipc ( oOooOOoo , lisp_socket , "lisp-core" )
 return
 if 1 - 1: OoooooooOO . Ii1I
 if 68 - 68: Ii1I
 if 98 - 98: iII111i
 if 33 - 33: OoO0O00 - ooOoO0o % O0 % iIii1I11I1II1 * iII111i - iII111i
 if 27 - 27: i11iIiiIii + I1ii11iIi11i + i1IIi
 if 67 - 67: o0oOOo0O0Ooo
 if 58 - 58: IiII % o0oOOo0O0Ooo + i1IIi
def lisp_process_api_map_cache ( mc , data ) :
 if 33 - 33: II111iiii
 if 61 - 61: I1Ii111
 if 56 - 56: I1ii11iIi11i - OoooooooOO
 if 52 - 52: Oo0Ooo - I11i - IiII - OoOoOO00
 if ( mc . group . is_null ( ) ) : return ( lisp_gather_map_cache_data ( mc , data ) )
 if 21 - 21: oO0o % o0oOOo0O0Ooo + I1Ii111 . OOooOOo / OOooOOo
 if ( mc . source_cache == None ) : return ( [ True , data ] )
 if 41 - 41: Oo0Ooo . ooOoO0o * oO0o
 if 31 - 31: Oo0Ooo * IiII / IiII
 if 3 - 3: I1Ii111
 if 65 - 65: iIii1I11I1II1 % Oo0Ooo % I11i / OoooooooOO
 if 82 - 82: o0oOOo0O0Ooo
 data = mc . source_cache . walk_cache ( lisp_gather_map_cache_data , data )
 return ( [ True , data ] )
 if 33 - 33: OoOoOO00 / i11iIiiIii - I1IiiI - OoooooooOO + i1IIi * I1Ii111
 if 92 - 92: iII111i + OoO0O00
 if 70 - 70: iIii1I11I1II1
 if 100 - 100: OOooOOo . oO0o % ooOoO0o * ooOoO0o . I1Ii111 - oO0o
 if 33 - 33: Oo0Ooo . i1IIi - OoooooooOO
 if 14 - 14: I1Ii111 + Oo0Ooo
 if 35 - 35: i11iIiiIii * Ii1I
def lisp_gather_map_cache_data ( mc , data ) :
 iiIIIIiI111 = { }
 iiIIIIiI111 [ "instance-id" ] = str ( mc . eid . instance_id )
 iiIIIIiI111 [ "eid-prefix" ] = mc . eid . print_prefix_no_iid ( )
 if ( mc . group . is_null ( ) == False ) :
  iiIIIIiI111 [ "group-prefix" ] = mc . group . print_prefix_no_iid ( )
  if 100 - 100: O0 . iII111i / iIii1I11I1II1
 iiIIIIiI111 [ "uptime" ] = lisp_print_elapsed ( mc . uptime )
 iiIIIIiI111 [ "expires" ] = lisp_print_elapsed ( mc . uptime )
 iiIIIIiI111 [ "action" ] = lisp_map_reply_action_string [ mc . action ]
 iiIIIIiI111 [ "ttl" ] = "--" if mc . map_cache_ttl == None else str ( mc . map_cache_ttl / 60 )
 if 47 - 47: ooOoO0o + OoOoOO00
 if 67 - 67: IiII - I1ii11iIi11i * i1IIi - ooOoO0o
 if 91 - 91: I11i
 if 54 - 54: I1ii11iIi11i / i1IIi
 if 14 - 14: iIii1I11I1II1 * I11i . I11i * ooOoO0o * iII111i
 iiiI11II1IiIi = [ ]
 for Oo0o0o0oo in mc . rloc_set :
  Oo0O = { }
  if ( Oo0o0o0oo . rloc_exists ( ) ) :
   Oo0O [ "address" ] = Oo0o0o0oo . rloc . print_address_no_iid ( )
   if 60 - 60: iIii1I11I1II1 + i1IIi + oO0o - iIii1I11I1II1 . i11iIiiIii * OoooooooOO
   if 23 - 23: iII111i - IiII % i11iIiiIii
  if ( Oo0o0o0oo . translated_port != 0 ) :
   Oo0O [ "encap-port" ] = str ( Oo0o0o0oo . translated_port )
   if 81 - 81: OoooooooOO % OoOoOO00 / IiII / OoooooooOO + i1IIi - O0
  Oo0O [ "state" ] = Oo0o0o0oo . print_state ( )
  if ( Oo0o0o0oo . geo ) : Oo0O [ "geo" ] = Oo0o0o0oo . geo . print_geo ( )
  if ( Oo0o0o0oo . elp ) : Oo0O [ "elp" ] = Oo0o0o0oo . elp . print_elp ( False )
  if ( Oo0o0o0oo . rle ) : Oo0O [ "rle" ] = Oo0o0o0oo . rle . print_rle ( False )
  if ( Oo0o0o0oo . json ) : Oo0O [ "json" ] = Oo0o0o0oo . json . print_json ( False )
  if ( Oo0o0o0oo . rloc_name ) : Oo0O [ "rloc-name" ] = Oo0o0o0oo . rloc_name
  iiIIi11 = Oo0o0o0oo . stats . get_stats ( False , False )
  if ( iiIIi11 ) : Oo0O [ "stats" ] = iiIIi11
  Oo0O [ "uptime" ] = lisp_print_elapsed ( Oo0o0o0oo . uptime )
  Oo0O [ "upriority" ] = str ( Oo0o0o0oo . priority )
  Oo0O [ "uweight" ] = str ( Oo0o0o0oo . weight )
  Oo0O [ "mpriority" ] = str ( Oo0o0o0oo . mpriority )
  Oo0O [ "mweight" ] = str ( Oo0o0o0oo . mweight )
  o000Oo00o = Oo0o0o0oo . last_rloc_probe_reply
  if ( o000Oo00o ) :
   Oo0O [ "last-rloc-probe-reply" ] = lisp_print_elapsed ( o000Oo00o )
   Oo0O [ "rloc-probe-rtt" ] = str ( Oo0o0o0oo . rloc_probe_rtt )
   if 78 - 78: OoO0O00 - ooOoO0o + Oo0Ooo % i1IIi % iIii1I11I1II1
  Oo0O [ "rloc-hop-count" ] = Oo0o0o0oo . rloc_probe_hops
  Oo0O [ "recent-rloc-hop-counts" ] = Oo0o0o0oo . recent_rloc_probe_hops
  if 69 - 69: I11i % ooOoO0o
  OoOii = [ ]
  for oooOoo in Oo0o0o0oo . recent_rloc_probe_rtts : OoOii . append ( str ( oooOoo ) )
  Oo0O [ "recent-rloc-probe-rtts" ] = OoOii
  if 68 - 68: I1IiiI - i1IIi
  iiiI11II1IiIi . append ( Oo0O )
  if 98 - 98: OOooOOo . Oo0Ooo
 iiIIIIiI111 [ "rloc-set" ] = iiiI11II1IiIi
 if 83 - 83: OoooooooOO
 data . append ( iiIIIIiI111 )
 return ( [ True , data ] )
 if 53 - 53: o0oOOo0O0Ooo - Oo0Ooo / IiII + O0
 if 88 - 88: Oo0Ooo % I1Ii111 * O0 - i1IIi * OoO0O00
 if 74 - 74: Oo0Ooo % iIii1I11I1II1 + OOooOOo
 if 50 - 50: OoO0O00 . OoooooooOO
 if 31 - 31: OoO0O00
 if 55 - 55: OoOoOO00 + I1Ii111 * o0oOOo0O0Ooo - I1ii11iIi11i + OoOoOO00
 if 6 - 6: II111iiii % iIii1I11I1II1 * I1Ii111
def lisp_process_api_map_cache_entry ( parms ) :
 II1 = parms [ "instance-id" ]
 II1 = 0 if ( II1 == "" ) else int ( II1 )
 if 2 - 2: IiII - I1Ii111 . iIii1I11I1II1 - Ii1I * I11i
 if 58 - 58: i1IIi % iIii1I11I1II1 % i11iIiiIii - o0oOOo0O0Ooo + ooOoO0o
 if 23 - 23: Oo0Ooo % Oo0Ooo / IiII
 if 63 - 63: I11i % Oo0Ooo * I1Ii111 - Oo0Ooo % i11iIiiIii . II111iiii
 Oo00o = lisp_address ( LISP_AFI_NONE , "" , 0 , II1 )
 Oo00o . store_prefix ( parms [ "eid-prefix" ] )
 iIi11i1I11Ii = Oo00o
 oo = Oo00o
 if 44 - 44: I11i . I1Ii111 . I1ii11iIi11i . oO0o
 if 1 - 1: I11i % II111iiii / OoO0O00 + OoO0O00
 if 46 - 46: Oo0Ooo * Ii1I / IiII % O0 * iII111i
 if 74 - 74: OoooooooOO + Ii1I
 if 100 - 100: I1IiiI
 i1i11Ii1 = lisp_address ( LISP_AFI_NONE , "" , 0 , II1 )
 if ( parms . has_key ( "group-prefix" ) ) :
  i1i11Ii1 . store_prefix ( parms [ "group-prefix" ] )
  iIi11i1I11Ii = i1i11Ii1
  if 59 - 59: I1IiiI - OoOoOO00 * ooOoO0o / O0
  if 54 - 54: Oo0Ooo % iIii1I11I1II1 * Oo0Ooo
 i11 = [ ]
 ooooOoo000O = lisp_map_cache_lookup ( oo , iIi11i1I11Ii )
 if ( ooooOoo000O ) : OooO000oo0o , i11 = lisp_process_api_map_cache ( ooooOoo000O , i11 )
 return ( i11 )
 if 80 - 80: I1ii11iIi11i - I1ii11iIi11i
 if 26 - 26: I1ii11iIi11i - I1IiiI * I1Ii111 % iIii1I11I1II1
 if 77 - 77: o0oOOo0O0Ooo + I1Ii111 . OOooOOo . i1IIi . I1IiiI
 if 100 - 100: ooOoO0o . i11iIiiIii + Ii1I - OOooOOo - i11iIiiIii - OoooooooOO
 if 42 - 42: OoOoOO00 . I1IiiI / OoOoOO00 / I1ii11iIi11i . OoO0O00
 if 67 - 67: Ii1I - O0 . OoooooooOO . I1Ii111 . o0oOOo0O0Ooo
 if 73 - 73: I11i - oO0o . I1Ii111 + oO0o
def lisp_process_api_site_cache ( se , data ) :
 if 48 - 48: IiII . IiII * o0oOOo0O0Ooo * II111iiii % ooOoO0o
 if 40 - 40: I1ii11iIi11i
 if 76 - 76: Oo0Ooo - I11i
 if 82 - 82: OoO0O00 % oO0o . I11i / O0 - I1Ii111
 if ( se . group . is_null ( ) ) : return ( lisp_gather_site_cache_data ( se , data ) )
 if 39 - 39: I1IiiI
 if ( se . source_cache == None ) : return ( [ True , data ] )
 if 8 - 8: IiII * i1IIi * i1IIi * O0
 if 69 - 69: Oo0Ooo
 if 48 - 48: iII111i
 if 11 - 11: i11iIiiIii * OoOoOO00 . OoO0O00
 if 47 - 47: Oo0Ooo % I1Ii111 + ooOoO0o
 data = se . source_cache . walk_cache ( lisp_gather_site_cache_data , data )
 return ( [ True , data ] )
 if 89 - 89: iII111i
 if 29 - 29: I1ii11iIi11i . ooOoO0o * II111iiii / iII111i . OoooooooOO - OoOoOO00
 if 99 - 99: IiII % O0 - I1Ii111 * OoO0O00
 if 77 - 77: OoooooooOO - I11i / I1IiiI % OoOoOO00 - OOooOOo
 if 37 - 37: ooOoO0o
 if 22 - 22: I1ii11iIi11i + II111iiii / OoooooooOO % o0oOOo0O0Ooo * OoOoOO00 . Oo0Ooo
 if 26 - 26: OoO0O00 % oO0o * Ii1I % OoooooooOO - oO0o
def lisp_process_api_ms_or_mr ( ms_or_mr , data ) :
 Iiii1Ii1I = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
 Ooooo000 = data [ "dns-name" ] if data . has_key ( "dns-name" ) else None
 if ( data . has_key ( "address" ) ) :
  Iiii1Ii1I . store_address ( data [ "address" ] )
  if 46 - 46: I1IiiI + OoO0O00 - O0 * O0
  if 75 - 75: OOooOOo + iIii1I11I1II1 * OOooOOo
 ooOo0O0O0oOO0 = { }
 if ( ms_or_mr ) :
  for ooooOOoO in lisp_map_servers_list . values ( ) :
   if ( Ooooo000 ) :
    if ( Ooooo000 != ooooOOoO . dns_name ) : continue
   else :
    if ( Iiii1Ii1I . is_exact_match ( ooooOOoO . map_server ) == False ) : continue
    if 82 - 82: iII111i - I1Ii111 - OoOoOO00
    if 96 - 96: Oo0Ooo . Oo0Ooo % o0oOOo0O0Ooo - I1IiiI * iIii1I11I1II1
   ooOo0O0O0oOO0 [ "dns-name" ] = ooooOOoO . dns_name
   ooOo0O0O0oOO0 [ "address" ] = ooooOOoO . map_server . print_address_no_iid ( )
   ooOo0O0O0oOO0 [ "ms-name" ] = "" if ooooOOoO . ms_name == None else ooooOOoO . ms_name
   return ( [ ooOo0O0O0oOO0 ] )
   if 29 - 29: i1IIi / Ii1I / oO0o * iII111i
 else :
  for Ii1IIi1III1i in lisp_map_resolvers_list . values ( ) :
   if ( Ooooo000 ) :
    if ( Ooooo000 != Ii1IIi1III1i . dns_name ) : continue
   else :
    if ( Iiii1Ii1I . is_exact_match ( Ii1IIi1III1i . map_resolver ) == False ) : continue
    if 44 - 44: O0
    if 95 - 95: OOooOOo + OOooOOo - OoOoOO00
   ooOo0O0O0oOO0 [ "dns-name" ] = Ii1IIi1III1i . dns_name
   ooOo0O0O0oOO0 [ "address" ] = Ii1IIi1III1i . map_resolver . print_address_no_iid ( )
   ooOo0O0O0oOO0 [ "mr-name" ] = "" if Ii1IIi1III1i . mr_name == None else Ii1IIi1III1i . mr_name
   return ( [ ooOo0O0O0oOO0 ] )
   if 83 - 83: II111iiii * ooOoO0o - O0 - i11iIiiIii
   if 62 - 62: I1IiiI + II111iiii * iIii1I11I1II1 % iII111i + IiII / ooOoO0o
 return ( [ ] )
 if 14 - 14: iIii1I11I1II1 * I1ii11iIi11i + OOooOOo + O0
 if 79 - 79: II111iiii - iII111i
 if 89 - 89: O0 - OoO0O00
 if 8 - 8: I1ii11iIi11i / oO0o - OoooooooOO + ooOoO0o + o0oOOo0O0Ooo % i11iIiiIii
 if 32 - 32: O0 + IiII
 if 93 - 93: OoOoOO00 - I11i / iII111i - iIii1I11I1II1 + I11i % oO0o
 if 24 - 24: Ii1I / iIii1I11I1II1 + o0oOOo0O0Ooo
 if 17 - 17: OOooOOo
def lisp_process_api_database_mapping ( ) :
 i11 = [ ]
 if 75 - 75: Ii1I / i1IIi % I1ii11iIi11i . Ii1I
 for iIiIIi1i in lisp_db_list :
  iiIIIIiI111 = { }
  iiIIIIiI111 [ "eid-prefix" ] = iIiIIi1i . eid . print_prefix ( )
  if ( iIiIIi1i . group . is_null ( ) == False ) :
   iiIIIIiI111 [ "group-prefix" ] = iIiIIi1i . group . print_prefix ( )
   if 46 - 46: II111iiii * OoO0O00
   if 77 - 77: ooOoO0o * I11i
  ooo0o0 = [ ]
  for Oo0O in iIiIIi1i . rloc_set :
   Oo0o0o0oo = { }
   if ( Oo0O . rloc . is_null ( ) == False ) :
    Oo0o0o0oo [ "rloc" ] = Oo0O . rloc . print_address_no_iid ( )
    if 85 - 85: OoO0O00 * I1Ii111 - OoooooooOO / iIii1I11I1II1 - i1IIi + Ii1I
   if ( Oo0O . rloc_name != None ) : Oo0o0o0oo [ "rloc-name" ] = Oo0O . rloc_name
   if ( Oo0O . interface != None ) : Oo0o0o0oo [ "interface" ] = Oo0O . interface
   o0oOOOoO0OoO = Oo0O . translated_rloc
   if ( o0oOOOoO0OoO . is_null ( ) == False ) :
    Oo0o0o0oo [ "translated-rloc" ] = o0oOOOoO0OoO . print_address_no_iid ( )
    if 51 - 51: i11iIiiIii
   if ( Oo0o0o0oo != { } ) : ooo0o0 . append ( Oo0o0o0oo )
   if 39 - 39: o0oOOo0O0Ooo % I1Ii111 % i1IIi - II111iiii + i11iIiiIii
   if 62 - 62: I1ii11iIi11i - I1IiiI * i11iIiiIii % oO0o
   if 63 - 63: II111iiii - Oo0Ooo
   if 55 - 55: iIii1I11I1II1 / O0 * O0 * i11iIiiIii * OoooooooOO
   if 94 - 94: II111iiii . II111iiii / OoOoOO00 % oO0o * i1IIi % Oo0Ooo
  iiIIIIiI111 [ "rlocs" ] = ooo0o0
  if 78 - 78: IiII - I1IiiI
  if 59 - 59: oO0o + i1IIi - IiII % OOooOOo % iIii1I11I1II1
  if 71 - 71: OoO0O00
  if 72 - 72: II111iiii + o0oOOo0O0Ooo / i1IIi * Oo0Ooo / i1IIi
  i11 . append ( iiIIIIiI111 )
  if 52 - 52: I1Ii111 % OoO0O00 . I1Ii111 * I1ii11iIi11i * OoOoOO00 + i1IIi
 return ( i11 )
 if 54 - 54: Ii1I / I1IiiI
 if 7 - 7: iIii1I11I1II1 . O0 + OOooOOo . Ii1I * Oo0Ooo
 if 25 - 25: I1Ii111 . Oo0Ooo % II111iiii . IiII - O0
 if 18 - 18: oO0o * OOooOOo
 if 19 - 19: iIii1I11I1II1 / I1ii11iIi11i - I1ii11iIi11i / iIii1I11I1II1
 if 42 - 42: iIii1I11I1II1 / OOooOOo - O0 * OoooooooOO / i1IIi
 if 33 - 33: OOooOOo . o0oOOo0O0Ooo % OoO0O00 - I1Ii111 . OoooooooOO
def lisp_gather_site_cache_data ( se , data ) :
 iiIIIIiI111 = { }
 iiIIIIiI111 [ "site-name" ] = se . site . site_name
 iiIIIIiI111 [ "instance-id" ] = str ( se . eid . instance_id )
 iiIIIIiI111 [ "eid-prefix" ] = se . eid . print_prefix_no_iid ( )
 if ( se . group . is_null ( ) == False ) :
  iiIIIIiI111 [ "group-prefix" ] = se . group . print_prefix_no_iid ( )
  if 96 - 96: II111iiii % I11i / Ii1I - i11iIiiIii
 iiIIIIiI111 [ "registered" ] = "yes" if se . registered else "no"
 iiIIIIiI111 [ "first-registered" ] = lisp_print_elapsed ( se . first_registered )
 iiIIIIiI111 [ "last-registered" ] = lisp_print_elapsed ( se . last_registered )
 if 63 - 63: I1IiiI
 iIiIi1iI11iiI = se . last_registerer
 iIiIi1iI11iiI = "none" if iIiIi1iI11iiI . is_null ( ) else iIiIi1iI11iiI . print_address ( )
 iiIIIIiI111 [ "last-registerer" ] = iIiIi1iI11iiI
 iiIIIIiI111 [ "ams" ] = "yes" if ( se . accept_more_specifics ) else "no"
 iiIIIIiI111 [ "dynamic" ] = "yes" if ( se . dynamic ) else "no"
 iiIIIIiI111 [ "site-id" ] = str ( se . site_id )
 if ( se . xtr_id_present ) :
  iiIIIIiI111 [ "xtr-id" ] = "0x" + lisp_hex_string ( se . xtr_id )
  if 15 - 15: iIii1I11I1II1 - I1ii11iIi11i % OoO0O00 * II111iiii / I11i + I11i
  if 23 - 23: I1IiiI
  if 51 - 51: i11iIiiIii / ooOoO0o - OoooooooOO + OoOoOO00 + oO0o
  if 57 - 57: iIii1I11I1II1
  if 19 - 19: Ii1I / o0oOOo0O0Ooo + O0 / iIii1I11I1II1 + II111iiii
 iiiI11II1IiIi = [ ]
 for Oo0o0o0oo in se . registered_rlocs :
  Oo0O = { }
  Oo0O [ "address" ] = Oo0o0o0oo . rloc . print_address_no_iid ( ) if Oo0o0o0oo . rloc_exists ( ) else "none"
  if 3 - 3: oO0o % OoO0O00 % OOooOOo
  if 64 - 64: o0oOOo0O0Ooo . II111iiii * IiII % Oo0Ooo + I11i - OoooooooOO
  if ( Oo0o0o0oo . geo ) : Oo0O [ "geo" ] = Oo0o0o0oo . geo . print_geo ( )
  if ( Oo0o0o0oo . elp ) : Oo0O [ "elp" ] = Oo0o0o0oo . elp . print_elp ( False )
  if ( Oo0o0o0oo . rle ) : Oo0O [ "rle" ] = Oo0o0o0oo . rle . print_rle ( False )
  if ( Oo0o0o0oo . json ) : Oo0O [ "json" ] = Oo0o0o0oo . json . print_json ( False )
  if ( Oo0o0o0oo . rloc_name ) : Oo0O [ "rloc-name" ] = Oo0o0o0oo . rloc_name
  Oo0O [ "uptime" ] = lisp_print_elapsed ( Oo0o0o0oo . uptime )
  Oo0O [ "upriority" ] = str ( Oo0o0o0oo . priority )
  Oo0O [ "uweight" ] = str ( Oo0o0o0oo . weight )
  Oo0O [ "mpriority" ] = str ( Oo0o0o0oo . mpriority )
  Oo0O [ "mweight" ] = str ( Oo0o0o0oo . mweight )
  if 58 - 58: ooOoO0o
  iiiI11II1IiIi . append ( Oo0O )
  if 15 - 15: O0 * OOooOOo * I11i + Ii1I * OoooooooOO + OOooOOo
 iiIIIIiI111 [ "registered-rlocs" ] = iiiI11II1IiIi
 if 77 - 77: O0
 data . append ( iiIIIIiI111 )
 return ( [ True , data ] )
 if 98 - 98: iII111i - iII111i % i1IIi - I1Ii111 . I1IiiI % o0oOOo0O0Ooo
 if 38 - 38: IiII % OoOoOO00 . OOooOOo . I1ii11iIi11i
 if 34 - 34: iII111i . i11iIiiIii + OoO0O00 + o0oOOo0O0Ooo / ooOoO0o - i11iIiiIii
 if 63 - 63: ooOoO0o % OoO0O00 % ooOoO0o
 if 28 - 28: IiII * I1Ii111 * o0oOOo0O0Ooo + ooOoO0o - IiII / IiII
 if 73 - 73: iIii1I11I1II1 . I1ii11iIi11i + OOooOOo
 if 51 - 51: I11i % Oo0Ooo * OOooOOo % OoooooooOO - OoOoOO00 % Ii1I
def lisp_process_api_site_cache_entry ( parms ) :
 II1 = parms [ "instance-id" ]
 II1 = 0 if ( II1 == "" ) else int ( II1 )
 if 60 - 60: OoOoOO00 - IiII + OoO0O00
 if 77 - 77: iIii1I11I1II1
 if 92 - 92: IiII
 if 68 - 68: OOooOOo . IiII / iIii1I11I1II1 % i11iIiiIii
 Oo00o = lisp_address ( LISP_AFI_NONE , "" , 0 , II1 )
 Oo00o . store_prefix ( parms [ "eid-prefix" ] )
 if 74 - 74: iII111i + i11iIiiIii
 if 95 - 95: Ii1I
 if 49 - 49: I1ii11iIi11i . i1IIi + OoO0O00 % O0 + OoO0O00
 if 21 - 21: ooOoO0o * oO0o / OoooooooOO % ooOoO0o / O0
 if 24 - 24: OoO0O00 - i11iIiiIii / i11iIiiIii * I1Ii111
 i1i11Ii1 = lisp_address ( LISP_AFI_NONE , "" , 0 , II1 )
 if ( parms . has_key ( "group-prefix" ) ) :
  i1i11Ii1 . store_prefix ( parms [ "group-prefix" ] )
  if 20 - 20: IiII % iIii1I11I1II1 . iII111i + iIii1I11I1II1 + O0
  if 96 - 96: I1ii11iIi11i - IiII % OoooooooOO . iII111i
 i11 = [ ]
 iIi1II1 = lisp_site_eid_lookup ( Oo00o , i1i11Ii1 , False )
 if ( iIi1II1 ) : lisp_gather_site_cache_data ( iIi1II1 , i11 )
 return ( i11 )
 if 30 - 30: Oo0Ooo . OoooooooOO / Oo0Ooo / oO0o
 if 44 - 44: I1ii11iIi11i % o0oOOo0O0Ooo / iIii1I11I1II1 - o0oOOo0O0Ooo / I11i * I1Ii111
 if 49 - 49: iII111i / iII111i - OoOoOO00
 if 89 - 89: ooOoO0o
 if 16 - 16: oO0o + oO0o + i1IIi + iIii1I11I1II1
 if 93 - 93: I1IiiI - i11iIiiIii * I1Ii111 - O0 + iII111i
 if 11 - 11: iII111i
def lisp_get_interface_instance_id ( device , source_eid ) :
 II111IiiiI1 = None
 if ( lisp_myinterfaces . has_key ( device ) ) :
  II111IiiiI1 = lisp_myinterfaces [ device ]
  if 100 - 100: OoooooooOO / ooOoO0o . OoO0O00
  if 89 - 89: I11i % II111iiii
  if 35 - 35: oO0o
  if 65 - 65: II111iiii
  if 87 - 87: oO0o / OoO0O00 - oO0o
  if 69 - 69: i11iIiiIii
 if ( II111IiiiI1 == None or II111IiiiI1 . instance_id == None ) :
  return ( lisp_default_iid )
  if 29 - 29: IiII . ooOoO0o / iII111i - OOooOOo / OOooOOo % Oo0Ooo
  if 42 - 42: OoO0O00 . I1Ii111 . I1IiiI + Oo0Ooo * O0
  if 35 - 35: Oo0Ooo / iII111i - O0 - OOooOOo * Oo0Ooo . i11iIiiIii
  if 43 - 43: OoOoOO00 % oO0o % OoO0O00 / Ii1I . I11i
  if 86 - 86: I1Ii111 * i1IIi + IiII - OoOoOO00
  if 14 - 14: I1ii11iIi11i / i11iIiiIii * I11i % o0oOOo0O0Ooo + IiII / I1ii11iIi11i
  if 82 - 82: OOooOOo . oO0o
  if 12 - 12: i11iIiiIii + II111iiii
  if 49 - 49: OoooooooOO
 II1 = II111IiiiI1 . get_instance_id ( )
 if ( source_eid == None ) : return ( II1 )
 if 48 - 48: i1IIi . IiII - O0 + OoooooooOO
 I1IIiI1I1iiiI = source_eid . instance_id
 IIIii = None
 for II111IiiiI1 in lisp_multi_tenant_interfaces :
  if ( II111IiiiI1 . device != device ) : continue
  OOO0000o = II111IiiiI1 . multi_tenant_eid
  source_eid . instance_id = OOO0000o . instance_id
  if ( source_eid . is_more_specific ( OOO0000o ) == False ) : continue
  if ( IIIii == None or IIIii . multi_tenant_eid . mask_len < OOO0000o . mask_len ) :
   IIIii = II111IiiiI1
   if 27 - 27: OOooOOo + IiII
   if 21 - 21: OOooOOo - i1IIi
 source_eid . instance_id = I1IIiI1I1iiiI
 if 65 - 65: OoooooooOO
 if ( IIIii == None ) : return ( II1 )
 return ( IIIii . get_instance_id ( ) )
 if 31 - 31: o0oOOo0O0Ooo . i1IIi - i1IIi % i1IIi - iIii1I11I1II1
 if 50 - 50: IiII - OOooOOo % OoOoOO00
 if 66 - 66: IiII * i11iIiiIii
 if 64 - 64: i11iIiiIii . I1Ii111 % i11iIiiIii % I11i
 if 56 - 56: o0oOOo0O0Ooo + ooOoO0o + OoooooooOO
 if 64 - 64: OOooOOo / OoOoOO00
 if 30 - 30: OOooOOo % I1Ii111 - i11iIiiIii
 if 20 - 20: i1IIi * I11i / OoO0O00 / i1IIi / I1Ii111 * O0
 if 95 - 95: Ii1I + Ii1I % IiII - IiII / OOooOOo
def lisp_allow_dynamic_eid ( device , eid ) :
 if ( lisp_myinterfaces . has_key ( device ) == False ) : return ( None )
 if 46 - 46: IiII + iII111i + II111iiii . iII111i - i11iIiiIii % OoO0O00
 II111IiiiI1 = lisp_myinterfaces [ device ]
 IIi1iI = device if II111IiiiI1 . dynamic_eid_device == None else II111IiiiI1 . dynamic_eid_device
 if 3 - 3: i11iIiiIii / I1ii11iIi11i
 if 49 - 49: IiII
 if ( II111IiiiI1 . does_dynamic_eid_match ( eid ) ) : return ( IIi1iI )
 return ( None )
 if 1 - 1: oO0o / I11i
 if 99 - 99: OoO0O00 % IiII + I1Ii111 - oO0o
 if 28 - 28: OOooOOo - O0 - O0 % i11iIiiIii * OoooooooOO
 if 60 - 60: OoooooooOO / i1IIi / i1IIi / Ii1I . IiII
 if 24 - 24: O0
 if 6 - 6: I1IiiI . i11iIiiIii . OoooooooOO . I1IiiI . o0oOOo0O0Ooo
 if 65 - 65: i11iIiiIii
def lisp_start_rloc_probe_timer ( interval , lisp_sockets ) :
 global lisp_rloc_probe_timer
 if 46 - 46: i11iIiiIii
 if ( lisp_rloc_probe_timer != None ) : lisp_rloc_probe_timer . cancel ( )
 if 70 - 70: i1IIi + o0oOOo0O0Ooo
 i11Ii1ii = lisp_process_rloc_probe_timer
 I1i1i1Ii1II1 = threading . Timer ( interval , i11Ii1ii , [ lisp_sockets ] )
 lisp_rloc_probe_timer = I1i1i1Ii1II1
 I1i1i1Ii1II1 . start ( )
 return
 if 36 - 36: OoO0O00 * I11i . ooOoO0o
 if 50 - 50: oO0o * OoOoOO00 / OoO0O00 / ooOoO0o + II111iiii
 if 55 - 55: II111iiii - IiII
 if 24 - 24: oO0o % Ii1I / i1IIi
 if 84 - 84: i1IIi
 if 53 - 53: OoooooooOO - i1IIi - Ii1I
 if 73 - 73: I1ii11iIi11i - Ii1I * o0oOOo0O0Ooo
def lisp_show_rloc_probe_list ( ) :
 lprint ( bold ( "----- RLOC-probe-list -----" , False ) )
 for Iiii11 in lisp_rloc_probe_list :
  II11I1IiII = lisp_rloc_probe_list [ Iiii11 ]
  lprint ( "RLOC {}:" . format ( Iiii11 ) )
  for Oo0O , Oo0ooo0Ooo , o0 in II11I1IiII :
   lprint ( "  [{}, {}, {}, {}]" . format ( hex ( id ( Oo0O ) ) , Oo0ooo0Ooo . print_prefix ( ) ,
 o0 . print_prefix ( ) , Oo0O . translated_port ) )
   if 7 - 7: II111iiii . II111iiii . iII111i - O0 + I1Ii111
   if 36 - 36: I1Ii111 / OoooooooOO % I1Ii111 * i11iIiiIii - I11i - I11i
 lprint ( bold ( "---------------------------" , False ) )
 return
 if 55 - 55: II111iiii - OOooOOo % II111iiii + iII111i . o0oOOo0O0Ooo + i11iIiiIii
 if 43 - 43: I1IiiI
 if 39 - 39: IiII * OOooOOo . OoooooooOO + Oo0Ooo + iIii1I11I1II1
 if 67 - 67: iII111i . OOooOOo / ooOoO0o * iIii1I11I1II1
 if 29 - 29: I1Ii111 / OoOoOO00 % I1ii11iIi11i * IiII / II111iiii
 if 10 - 10: O0 / I11i
 if 29 - 29: i11iIiiIii % I11i
 if 49 - 49: I11i
 if 69 - 69: o0oOOo0O0Ooo . O0 * I11i
def lisp_mark_rlocs_for_other_eids ( eid_list ) :
 if 92 - 92: OoO0O00 . O0 / Ii1I % Oo0Ooo . Ii1I
 if 40 - 40: o0oOOo0O0Ooo - Ii1I . iII111i - O0
 if 53 - 53: Oo0Ooo - I1IiiI * O0 . II111iiii
 if 72 - 72: ooOoO0o - Ii1I . Ii1I . I11i / OoooooooOO + Ii1I
 Oo0o0o0oo , Oo0ooo0Ooo , o0 = eid_list [ 0 ]
 iII1II = [ lisp_print_eid_tuple ( Oo0ooo0Ooo , o0 ) ]
 if 43 - 43: I1ii11iIi11i % I1ii11iIi11i % i1IIi
 for Oo0o0o0oo , Oo0ooo0Ooo , o0 in eid_list [ 1 : : ] :
  Oo0o0o0oo . state = LISP_RLOC_UNREACH_STATE
  Oo0o0o0oo . last_state_change = lisp_get_timestamp ( )
  iII1II . append ( lisp_print_eid_tuple ( Oo0ooo0Ooo , o0 ) )
  if 56 - 56: I1IiiI - OoO0O00 - iII111i . o0oOOo0O0Ooo . I1Ii111
  if 70 - 70: iIii1I11I1II1 - I11i
 iI1i = bold ( "unreachable" , False )
 ooOOo00o0ooO = red ( Oo0o0o0oo . rloc . print_address_no_iid ( ) , False )
 if 45 - 45: OoO0O00 % iII111i / iIii1I11I1II1 % I1IiiI + OOooOOo
 for Oo00o in iII1II :
  Oo0ooo0Ooo = green ( Oo00o , False )
  lprint ( "RLOC {} went {} for EID {}" . format ( ooOOo00o0ooO , iI1i , Oo0ooo0Ooo ) )
  if 62 - 62: OOooOOo . OOooOOo . oO0o
  if 18 - 18: iII111i . I1IiiI . ooOoO0o * oO0o / OoooooooOO
  if 85 - 85: i1IIi
  if 79 - 79: I11i - I11i
  if 25 - 25: OOooOOo / O0 / iIii1I11I1II1 + II111iiii * Ii1I
  if 74 - 74: i1IIi . I1Ii111 / O0 + Oo0Ooo * OOooOOo
 for Oo0o0o0oo , Oo0ooo0Ooo , o0 in eid_list :
  ooooOoo000O = lisp_map_cache . lookup_cache ( Oo0ooo0Ooo , True )
  if ( ooooOoo000O ) : lisp_write_ipc_map_cache ( True , ooooOoo000O )
  if 90 - 90: I1IiiI * II111iiii . Oo0Ooo % I1IiiI
 return
 if 100 - 100: iIii1I11I1II1 - OoooooooOO * OoooooooOO - iII111i / ooOoO0o
 if 98 - 98: OoO0O00 + oO0o - II111iiii
 if 84 - 84: Oo0Ooo . OoOoOO00 - iII111i
 if 5 - 5: OoooooooOO . O0 / OOooOOo + I11i - Ii1I
 if 77 - 77: iIii1I11I1II1 * Oo0Ooo . IiII / oO0o + O0
 if 76 - 76: iII111i + o0oOOo0O0Ooo - OoooooooOO * oO0o % OoooooooOO - O0
 if 18 - 18: Ii1I
 if 82 - 82: OoOoOO00 + OoO0O00 - IiII / ooOoO0o
 if 70 - 70: OoO0O00
 if 43 - 43: ooOoO0o + OOooOOo + II111iiii - I1IiiI
def lisp_process_rloc_probe_timer ( lisp_sockets ) :
 lisp_set_exception ( )
 if 58 - 58: I11i
 lisp_start_rloc_probe_timer ( LISP_RLOC_PROBE_INTERVAL , lisp_sockets )
 if ( lisp_rloc_probing == False ) : return
 if 94 - 94: Oo0Ooo
 if 39 - 39: I11i - oO0o % iII111i - ooOoO0o - OoOoOO00
 if 8 - 8: i1IIi % i1IIi % OoooooooOO % i1IIi . iIii1I11I1II1
 if 70 - 70: O0 + II111iiii % IiII / I1Ii111 - IiII
 if ( lisp_print_rloc_probe_list ) : lisp_show_rloc_probe_list ( )
 if 58 - 58: II111iiii * oO0o - i1IIi . I11i
 if 23 - 23: OoO0O00 - I1IiiI * i11iIiiIii
 if 62 - 62: OoO0O00 . i11iIiiIii / i1IIi
 if 3 - 3: OoO0O00 + O0 % Oo0Ooo * Oo0Ooo % i11iIiiIii
 I1i1 = lisp_get_default_route_next_hops ( )
 if 51 - 51: I1IiiI . ooOoO0o / Ii1I / I1Ii111
 lprint ( "---------- Start RLOC Probing for {} entries ----------" . format ( len ( lisp_rloc_probe_list ) ) )
 if 84 - 84: I11i - Ii1I
 if 36 - 36: i1IIi
 if 21 - 21: iII111i . OoOoOO00 % o0oOOo0O0Ooo - i11iIiiIii
 if 86 - 86: I1Ii111 % i11iIiiIii
 if 22 - 22: I1Ii111
 i1Ii11II = 0
 oo00OO0Oooo = bold ( "RLOC-probe" , False )
 for OOOo0O in lisp_rloc_probe_list . values ( ) :
  if 51 - 51: OOooOOo
  if 60 - 60: ooOoO0o % iIii1I11I1II1 / iIii1I11I1II1
  if 61 - 61: oO0o
  if 12 - 12: iIii1I11I1II1 - I1ii11iIi11i % I1ii11iIi11i * I1Ii111
  if 98 - 98: oO0o / iII111i - Oo0Ooo / I1Ii111 * oO0o - OoO0O00
  I1oo0O0oOOoOo = None
  for oOoI1IiII11II11 , Oo00o , i1i11Ii1 in OOOo0O :
   ooOOo0o = oOoI1IiII11II11 . rloc . print_address_no_iid ( )
   if 55 - 55: OoooooooOO + oO0o . o0oOOo0O0Ooo % iIii1I11I1II1 - I1Ii111
   if 40 - 40: I1IiiI . o0oOOo0O0Ooo - Oo0Ooo
   if 44 - 44: Ii1I % OoO0O00 * oO0o * OoO0O00
   if 7 - 7: I1Ii111 % i1IIi . I11i . O0 / i1IIi
   ooO0oO , o0o0 = lisp_allow_gleaning ( Oo00o , oOoI1IiII11II11 )
   if ( ooO0oO and o0o0 == False ) :
    Oo0ooo0Ooo = green ( Oo00o . print_address ( ) , False )
    ooOOo0o += ":{}" . format ( oOoI1IiII11II11 . translated_port )
    lprint ( "Suppress probe to RLOC {} for gleaned EID {}" . format ( red ( ooOOo0o , False ) , Oo0ooo0Ooo ) )
    if 30 - 30: O0 / I1Ii111
    continue
    if 92 - 92: o0oOOo0O0Ooo + ooOoO0o / Oo0Ooo % o0oOOo0O0Ooo . OoooooooOO * Oo0Ooo
    if 68 - 68: I11i . OOooOOo - oO0o % Oo0Ooo
    if 27 - 27: I1ii11iIi11i % OoO0O00 % I11i / I1Ii111 / i11iIiiIii
    if 75 - 75: O0 % I1Ii111 * I11i % o0oOOo0O0Ooo - I11i
    if 51 - 51: II111iiii % ooOoO0o
    if 89 - 89: iII111i % OoooooooOO / I1ii11iIi11i
    if 64 - 64: OoooooooOO
   if ( oOoI1IiII11II11 . down_state ( ) ) : continue
   if 41 - 41: Ii1I . I11i / oO0o * OoooooooOO
   if 98 - 98: I1ii11iIi11i - O0 + i11iIiiIii
   if 71 - 71: O0 - OoooooooOO
   if 82 - 82: i11iIiiIii * II111iiii % IiII
   if 80 - 80: Ii1I . i11iIiiIii % oO0o * o0oOOo0O0Ooo
   if 56 - 56: I1Ii111 % iII111i / II111iiii - Oo0Ooo - Oo0Ooo - iIii1I11I1II1
   if 67 - 67: iII111i
   if 80 - 80: Ii1I . iII111i * I1IiiI * Ii1I
   if 82 - 82: OoO0O00 % OoOoOO00 * i11iIiiIii . OoO0O00 . I1ii11iIi11i + Ii1I
   if 60 - 60: i1IIi / iII111i
   if 10 - 10: I1Ii111 / OoOoOO00 * Ii1I % o0oOOo0O0Ooo . OoOoOO00 / I1ii11iIi11i
   if ( I1oo0O0oOOoOo ) :
    oOoI1IiII11II11 . last_rloc_probe_nonce = I1oo0O0oOOoOo . last_rloc_probe_nonce
    if 2 - 2: iIii1I11I1II1
    if ( I1oo0O0oOOoOo . translated_port == oOoI1IiII11II11 . translated_port and I1oo0O0oOOoOo . rloc_name == oOoI1IiII11II11 . rloc_name ) :
     if 85 - 85: O0 - ooOoO0o
     Oo0ooo0Ooo = green ( lisp_print_eid_tuple ( Oo00o , i1i11Ii1 ) , False )
     lprint ( "Suppress probe to duplicate RLOC {} for {}" . format ( red ( ooOOo0o , False ) , Oo0ooo0Ooo ) )
     if 35 - 35: o0oOOo0O0Ooo - I1IiiI
     continue
     if 47 - 47: i11iIiiIii * iII111i . OoOoOO00 * I1Ii111 % i11iIiiIii + Ii1I
     if 65 - 65: Ii1I % i11iIiiIii
     if 98 - 98: iII111i * o0oOOo0O0Ooo % Oo0Ooo
   O0o0 = None
   Oo0o0o0oo = None
   while ( True ) :
    Oo0o0o0oo = oOoI1IiII11II11 if Oo0o0o0oo == None else Oo0o0o0oo . next_rloc
    if ( Oo0o0o0oo == None ) : break
    if 7 - 7: oO0o * OoooooooOO % o0oOOo0O0Ooo . I1Ii111 + O0
    if 14 - 14: I11i * II111iiii % o0oOOo0O0Ooo / iII111i . OoooooooOO % iII111i
    if 88 - 88: iII111i
    if 94 - 94: OoooooooOO
    if 32 - 32: I1ii11iIi11i
    if ( Oo0o0o0oo . rloc_next_hop != None ) :
     if ( Oo0o0o0oo . rloc_next_hop not in I1i1 ) :
      if ( Oo0o0o0oo . up_state ( ) ) :
       i1 , oOO0OoOoOoo = Oo0o0o0oo . rloc_next_hop
       Oo0o0o0oo . state = LISP_RLOC_UNREACH_STATE
       Oo0o0o0oo . last_state_change = lisp_get_timestamp ( )
       lisp_update_rtr_updown ( Oo0o0o0oo . rloc , False )
       if 8 - 8: I11i * i11iIiiIii - ooOoO0o
      iI1i = bold ( "unreachable" , False )
      lprint ( "Next-hop {}({}) for RLOC {} is {}" . format ( oOO0OoOoOoo , i1 ,
 red ( ooOOo0o , False ) , iI1i ) )
      continue
      if 47 - 47: ooOoO0o . I1IiiI / i11iIiiIii * iII111i * I1IiiI
      if 8 - 8: oO0o % oO0o . iII111i / i1IIi % IiII
      if 71 - 71: OoOoOO00 + oO0o % O0 + Oo0Ooo
      if 62 - 62: i1IIi . Ii1I * i1IIi * O0 . I1IiiI % o0oOOo0O0Ooo
      if 16 - 16: I11i . Ii1I - ooOoO0o . OOooOOo % O0 / oO0o
      if 42 - 42: II111iiii . iII111i
    i1OooO00oO00o = Oo0o0o0oo . last_rloc_probe
    Oooo00OO = 0 if i1OooO00oO00o == None else time . time ( ) - i1OooO00oO00o
    if ( Oo0o0o0oo . unreach_state ( ) and Oooo00OO < LISP_RLOC_PROBE_INTERVAL ) :
     lprint ( "Waiting for probe-reply from RLOC {}" . format ( red ( ooOOo0o , False ) ) )
     if 25 - 25: IiII - IiII
     continue
     if 11 - 11: I1IiiI + o0oOOo0O0Ooo / O0 + Ii1I % I11i
     if 50 - 50: iII111i * OoooooooOO . O0
     if 87 - 87: ooOoO0o / Ii1I % O0 . OoO0O00
     if 55 - 55: i1IIi . o0oOOo0O0Ooo % OoooooooOO + II111iiii . OoOoOO00
     if 32 - 32: IiII * I1Ii111 * Oo0Ooo . i1IIi * OoooooooOO
     if 12 - 12: I1IiiI . OOooOOo % Oo0Ooo
    IiIii1i11i1 = lisp_get_echo_nonce ( None , ooOOo0o )
    if ( IiIii1i11i1 and IiIii1i11i1 . request_nonce_timeout ( ) ) :
     Oo0o0o0oo . state = LISP_RLOC_NO_ECHOED_NONCE_STATE
     Oo0o0o0oo . last_state_change = lisp_get_timestamp ( )
     iI1i = bold ( "unreachable" , False )
     lprint ( "RLOC {} went {}, nonce-echo failed" . format ( red ( ooOOo0o , False ) , iI1i ) )
     if 86 - 86: i11iIiiIii
     lisp_update_rtr_updown ( Oo0o0o0oo . rloc , False )
     continue
     if 57 - 57: iII111i - OoooooooOO - ooOoO0o % II111iiii
     if 62 - 62: i11iIiiIii . Oo0Ooo / Oo0Ooo . IiII . OoooooooOO
     if 86 - 86: I1ii11iIi11i * OoOoOO00 + iII111i
     if 79 - 79: I11i - II111iiii
     if 27 - 27: I1IiiI + o0oOOo0O0Ooo * oO0o % I1IiiI
     if 66 - 66: OoO0O00 + IiII . o0oOOo0O0Ooo . IiII
    if ( IiIii1i11i1 and IiIii1i11i1 . recently_echoed ( ) ) :
     lprint ( ( "Suppress RLOC-probe to {}, nonce-echo " + "received" ) . format ( red ( ooOOo0o , False ) ) )
     if 88 - 88: oO0o + oO0o % OoO0O00 . OoooooooOO - OoooooooOO . Oo0Ooo
     continue
     if 44 - 44: I1IiiI * IiII . OoooooooOO
     if 62 - 62: I11i - Ii1I / i11iIiiIii * I1IiiI + ooOoO0o + o0oOOo0O0Ooo
     if 10 - 10: i1IIi + o0oOOo0O0Ooo
     if 47 - 47: OOooOOo * IiII % I1Ii111 . OoOoOO00 - OoooooooOO / OoooooooOO
     if 79 - 79: I11i % i11iIiiIii % I1IiiI . OoooooooOO * oO0o . Ii1I
     if 14 - 14: iIii1I11I1II1 / I11i - o0oOOo0O0Ooo / IiII / o0oOOo0O0Ooo . OoO0O00
    if ( Oo0o0o0oo . last_rloc_probe != None ) :
     i1OooO00oO00o = Oo0o0o0oo . last_rloc_probe_reply
     if ( i1OooO00oO00o == None ) : i1OooO00oO00o = 0
     Oooo00OO = time . time ( ) - i1OooO00oO00o
     if ( Oo0o0o0oo . up_state ( ) and Oooo00OO >= LISP_RLOC_PROBE_REPLY_WAIT ) :
      if 2 - 2: I11i
      Oo0o0o0oo . state = LISP_RLOC_UNREACH_STATE
      Oo0o0o0oo . last_state_change = lisp_get_timestamp ( )
      lisp_update_rtr_updown ( Oo0o0o0oo . rloc , False )
      iI1i = bold ( "unreachable" , False )
      lprint ( "RLOC {} went {}, probe it" . format ( red ( ooOOo0o , False ) , iI1i ) )
      if 12 - 12: i1IIi . I1Ii111
      if 99 - 99: Oo0Ooo / i11iIiiIii
      lisp_mark_rlocs_for_other_eids ( OOOo0O )
      if 81 - 81: Ii1I . i1IIi % iII111i . OoO0O00 % IiII
      if 42 - 42: iII111i / Oo0Ooo
      if 14 - 14: O0 . Oo0Ooo
    Oo0o0o0oo . last_rloc_probe = lisp_get_timestamp ( )
    if 8 - 8: i11iIiiIii
    oO0oo0o = "" if Oo0o0o0oo . unreach_state ( ) == False else " unreachable"
    if 36 - 36: O0 + OOooOOo * i1IIi - OoooooooOO * iII111i
    if 8 - 8: OoooooooOO * i11iIiiIii * iII111i * O0 - OoOoOO00
    if 3 - 3: OoooooooOO % oO0o + OoOoOO00 % I1IiiI
    if 50 - 50: OoO0O00 - Oo0Ooo
    if 13 - 13: OoOoOO00
    if 72 - 72: II111iiii * iII111i . II111iiii + iII111i * IiII
    if 90 - 90: oO0o * I1Ii111 / O0
    IIiii1IiiIiii = ""
    oOO0OoOoOoo = None
    if ( Oo0o0o0oo . rloc_next_hop != None ) :
     i1 , oOO0OoOoOoo = Oo0o0o0oo . rloc_next_hop
     lisp_install_host_route ( ooOOo0o , oOO0OoOoOoo , True )
     IIiii1IiiIiii = ", send on nh {}({})" . format ( oOO0OoOoOoo , i1 )
     if 81 - 81: I11i
     if 31 - 31: OoooooooOO - OoO0O00 . iIii1I11I1II1 % I1IiiI
     if 98 - 98: I1IiiI + Ii1I
     if 7 - 7: o0oOOo0O0Ooo . OoooooooOO
     if 32 - 32: I1ii11iIi11i
    oooOoo = Oo0o0o0oo . print_rloc_probe_rtt ( )
    I1iIIii111i11i11 = ooOOo0o
    if ( Oo0o0o0oo . translated_port != 0 ) :
     I1iIIii111i11i11 += ":{}" . format ( Oo0o0o0oo . translated_port )
     if 10 - 10: I1IiiI % I1Ii111 . IiII - OOooOOo
    I1iIIii111i11i11 = red ( I1iIIii111i11i11 , False )
    if ( Oo0o0o0oo . rloc_name != None ) :
     I1iIIii111i11i11 += " (" + blue ( Oo0o0o0oo . rloc_name , False ) + ")"
     if 93 - 93: iIii1I11I1II1
    lprint ( "Send {}{} {}, last rtt: {}{}" . format ( oo00OO0Oooo , oO0oo0o ,
 I1iIIii111i11i11 , oooOoo , IIiii1IiiIiii ) )
    if 33 - 33: OOooOOo . i1IIi
    if 63 - 63: II111iiii . oO0o * IiII
    if 73 - 73: iII111i . i1IIi + oO0o + OOooOOo + ooOoO0o - iIii1I11I1II1
    if 47 - 47: I11i
    if 88 - 88: OoO0O00 - OoooooooOO
    if 93 - 93: Oo0Ooo * I1IiiI
    if 60 - 60: I1Ii111 + OOooOOo % iII111i
    if 40 - 40: I11i + oO0o . O0 % oO0o
    if ( Oo0o0o0oo . rloc_next_hop != None ) :
     O0o0 = lisp_get_host_route_next_hop ( ooOOo0o )
     if ( O0o0 ) : lisp_install_host_route ( ooOOo0o , O0o0 , False )
     if 12 - 12: iIii1I11I1II1
     if 9 - 9: OoOoOO00 * II111iiii / o0oOOo0O0Ooo * iII111i - II111iiii / i11iIiiIii
     if 14 - 14: i11iIiiIii + I1Ii111 . OoOoOO00 - oO0o * OoO0O00
     if 23 - 23: iIii1I11I1II1
     if 32 - 32: iII111i * iIii1I11I1II1 + I1Ii111 + IiII + O0 * OoO0O00
     if 100 - 100: II111iiii
    if ( Oo0o0o0oo . rloc . is_null ( ) ) :
     Oo0o0o0oo . rloc . copy_address ( oOoI1IiII11II11 . rloc )
     if 34 - 34: I11i % OOooOOo - iII111i % II111iiii
     if 14 - 14: I11i * o0oOOo0O0Ooo % II111iiii
     if 36 - 36: ooOoO0o - iIii1I11I1II1 / IiII + OoOoOO00
     if 42 - 42: ooOoO0o + I1IiiI * iII111i / OoOoOO00 . i1IIi - OoooooooOO
     if 8 - 8: iIii1I11I1II1 - Oo0Ooo + iII111i
    oOoO = None if ( i1i11Ii1 . is_null ( ) ) else Oo00o
    iII1I1iiII11I = Oo00o if ( i1i11Ii1 . is_null ( ) ) else i1i11Ii1
    lisp_send_map_request ( lisp_sockets , 0 , oOoO , iII1I1iiII11I , Oo0o0o0oo )
    I1oo0O0oOOoOo = oOoI1IiII11II11
    if 44 - 44: iII111i / Oo0Ooo / IiII / i11iIiiIii - i11iIiiIii
    if 14 - 14: i1IIi
    if 19 - 19: I1IiiI * OoO0O00 * O0 - i11iIiiIii - ooOoO0o - I11i
    if 47 - 47: iIii1I11I1II1
    if ( oOO0OoOoOoo ) : lisp_install_host_route ( ooOOo0o , oOO0OoOoOoo , False )
    if 64 - 64: OoooooooOO . Ii1I
    if 38 - 38: Oo0Ooo
    if 64 - 64: ooOoO0o % i11iIiiIii
    if 10 - 10: Ii1I % oO0o + oO0o * OoOoOO00 % iII111i / o0oOOo0O0Ooo
    if 17 - 17: iII111i / I1IiiI . II111iiii - OoO0O00 + iII111i
   if ( O0o0 ) : lisp_install_host_route ( ooOOo0o , O0o0 , True )
   if 22 - 22: Oo0Ooo - I1ii11iIi11i + I11i . oO0o
   if 85 - 85: iIii1I11I1II1 / Ii1I
   if 43 - 43: I1IiiI % I1Ii111 - oO0o . II111iiii / iIii1I11I1II1
   if 97 - 97: I1Ii111 + I1ii11iIi11i
   i1Ii11II += 1
   if ( ( i1Ii11II % 10 ) == 0 ) : time . sleep ( 0.020 )
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
 oOooOOoo = "rtr%{}%{}" . format ( oo0OOoOOOO , updown )
 oOooOOoo = lisp_command_ipc ( oOooOOoo , "lisp-itr" )
 lisp_ipc ( oOooOOoo , lisp_ipc_socket , "lisp-etr" )
 return
 if 78 - 78: OoO0O00 + iIii1I11I1II1 * i1IIi
 if 7 - 7: i11iIiiIii
 if 49 - 49: I1IiiI - oO0o % OOooOOo / O0 / II111iiii
 if 41 - 41: IiII % II111iiii
 if 99 - 99: IiII - O0
 if 59 - 59: iII111i % O0 + OOooOOo * ooOoO0o
 if 27 - 27: I1Ii111 % i11iIiiIii * I1IiiI
def lisp_process_rloc_probe_reply ( rloc , source , port , nonce , hop_count , ttl ) :
 oo00OO0Oooo = bold ( "RLOC-probe reply" , False )
 IIII = rloc . print_address_no_iid ( )
 Ii1II1 = source . print_address_no_iid ( )
 OOIii = lisp_rloc_probe_list
 if 72 - 72: I1Ii111 % OOooOOo
 if 32 - 32: i1IIi
 if 64 - 64: I1Ii111 * iII111i
 if 79 - 79: I1Ii111 + I1Ii111
 if 49 - 49: O0 * I11i + O0 / I11i
 if 72 - 72: iII111i + iII111i + I1Ii111 * o0oOOo0O0Ooo - IiII
 iIiIi1iI11iiI = IIII
 if ( OOIii . has_key ( iIiIi1iI11iiI ) == False ) :
  iIiIi1iI11iiI += ":" + str ( port )
  if ( OOIii . has_key ( iIiIi1iI11iiI ) == False ) :
   iIiIi1iI11iiI = Ii1II1
   if ( OOIii . has_key ( iIiIi1iI11iiI ) == False ) :
    iIiIi1iI11iiI += ":" + str ( port )
    lprint ( "    Received unsolicited {} from {}/{}, port {}" . format ( oo00OO0Oooo , red ( IIII , False ) , red ( Ii1II1 ,
    # o0oOOo0O0Ooo
 False ) , port ) )
    return
    if 42 - 42: Ii1I - IiII - i1IIi + I11i / OOooOOo - iII111i
    if 19 - 19: i1IIi
    if 32 - 32: I1IiiI
    if 97 - 97: iII111i
    if 26 - 26: i1IIi - I1Ii111 - ooOoO0o
    if 73 - 73: o0oOOo0O0Ooo . OoooooooOO
    if 96 - 96: i1IIi - OOooOOo / I11i % OoOoOO00 - i11iIiiIii % II111iiii
    if 47 - 47: I1Ii111 * iII111i
 for rloc , Oo00o , i1i11Ii1 in lisp_rloc_probe_list [ iIiIi1iI11iiI ] :
  if ( lisp_i_am_rtr and rloc . translated_port != 0 and
 rloc . translated_port != port ) : continue
  if 90 - 90: i1IIi * Ii1I . OoO0O00 % I11i * ooOoO0o . OOooOOo
  rloc . process_rloc_probe_reply ( nonce , Oo00o , i1i11Ii1 , hop_count , ttl )
  if 76 - 76: iIii1I11I1II1 . i11iIiiIii * II111iiii - iII111i
 return
 if 51 - 51: I1IiiI
 if 52 - 52: I1Ii111
 if 82 - 82: iII111i + II111iiii
 if 29 - 29: O0 % Ii1I * ooOoO0o % O0
 if 83 - 83: oO0o
 if 95 - 95: Oo0Ooo * O0 % i1IIi / iII111i + oO0o
 if 85 - 85: iIii1I11I1II1 / I11i
 if 65 - 65: I11i / i1IIi * OoOoOO00 * Ii1I * OoO0O00
def lisp_db_list_length ( ) :
 i1Ii11II = 0
 for iIiIIi1i in lisp_db_list :
  i1Ii11II += len ( iIiIIi1i . dynamic_eids ) if iIiIIi1i . dynamic_eid_configured ( ) else 1
  i1Ii11II += len ( iIiIIi1i . eid . iid_list )
  if 74 - 74: I1ii11iIi11i . I1ii11iIi11i % IiII + OOooOOo . OoO0O00 * I11i
 return ( i1Ii11II )
 if 20 - 20: OOooOOo % i1IIi * Ii1I / i11iIiiIii
 if 89 - 89: ooOoO0o
 if 83 - 83: I11i . I11i * OOooOOo - OOooOOo
 if 46 - 46: iIii1I11I1II1 . I1Ii111 % I1IiiI
 if 22 - 22: i1IIi * I11i + II111iiii + II111iiii
 if 20 - 20: I11i
 if 37 - 37: I1Ii111
 if 19 - 19: I1ii11iIi11i / OOooOOo . I1IiiI / ooOoO0o + OoO0O00 + i11iIiiIii
def lisp_is_myeid ( eid ) :
 for iIiIIi1i in lisp_db_list :
  if ( eid . is_more_specific ( iIiIIi1i . eid ) ) : return ( True )
  if 80 - 80: OoO0O00 . O0 / Ii1I % I1Ii111 / iII111i * I1IiiI
 return ( False )
 if 41 - 41: O0 / OoooooooOO - i1IIi
 if 6 - 6: i1IIi - I1ii11iIi11i % I1Ii111 - II111iiii / ooOoO0o / i11iIiiIii
 if 32 - 32: oO0o / IiII - I11i . ooOoO0o
 if 69 - 69: i11iIiiIii * i11iIiiIii
 if 100 - 100: I1ii11iIi11i * I1ii11iIi11i + i1IIi
 if 96 - 96: I1Ii111 / I1IiiI + ooOoO0o
 if 16 - 16: I1ii11iIi11i % o0oOOo0O0Ooo % OOooOOo % OoOoOO00 + ooOoO0o % I1ii11iIi11i
 if 85 - 85: oO0o * OoooooooOO * iIii1I11I1II1 + iII111i
 if 67 - 67: Ii1I / i11iIiiIii % OoOoOO00 % O0 / OoOoOO00
def lisp_format_macs ( sa , da ) :
 sa = sa [ 0 : 4 ] + "-" + sa [ 4 : 8 ] + "-" + sa [ 8 : 12 ]
 da = da [ 0 : 4 ] + "-" + da [ 4 : 8 ] + "-" + da [ 8 : 12 ]
 return ( "{} -> {}" . format ( sa , da ) )
 if 54 - 54: I11i . OoOoOO00 / II111iiii . i1IIi + OOooOOo % II111iiii
 if 82 - 82: i11iIiiIii . OoooooooOO % OoOoOO00 * O0 - I1Ii111
 if 78 - 78: OoOoOO00 % Ii1I % OOooOOo % Oo0Ooo % I11i . Ii1I
 if 73 - 73: OoooooooOO / i1IIi . iIii1I11I1II1
 if 89 - 89: I1Ii111
 if 29 - 29: I11i * ooOoO0o - OoooooooOO
 if 92 - 92: O0 % i1IIi / OOooOOo - oO0o
def lisp_get_echo_nonce ( rloc , rloc_str ) :
 if ( lisp_nonce_echoing == False ) : return ( None )
 if 83 - 83: o0oOOo0O0Ooo . OoO0O00 % iIii1I11I1II1 % OoOoOO00 - i11iIiiIii
 if ( rloc ) : rloc_str = rloc . print_address_no_iid ( )
 IiIii1i11i1 = None
 if ( lisp_nonce_echo_list . has_key ( rloc_str ) ) :
  IiIii1i11i1 = lisp_nonce_echo_list [ rloc_str ]
  if 71 - 71: I1ii11iIi11i - II111iiii / O0 % i1IIi + oO0o
 return ( IiIii1i11i1 )
 if 73 - 73: OoooooooOO
 if 25 - 25: i1IIi . II111iiii . I1Ii111
 if 81 - 81: II111iiii + OoOoOO00 * II111iiii / iIii1I11I1II1 - Oo0Ooo % oO0o
 if 66 - 66: ooOoO0o % O0 + iIii1I11I1II1 * I1Ii111 - I1Ii111
 if 61 - 61: I1ii11iIi11i
 if 12 - 12: OoO0O00
 if 97 - 97: OOooOOo . Oo0Ooo . oO0o * i1IIi
 if 7 - 7: Oo0Ooo
def lisp_decode_dist_name ( packet ) :
 i1Ii11II = 0
 iIIi111iI = ""
 if 1 - 1: II111iiii % oO0o . IiII
 while ( packet [ 0 : 1 ] != "\0" ) :
  if ( i1Ii11II == 255 ) : return ( [ None , None ] )
  iIIi111iI += packet [ 0 : 1 ]
  packet = packet [ 1 : : ]
  i1Ii11II += 1
  if 85 - 85: oO0o % iII111i + IiII + I1Ii111
  if 5 - 5: O0 . I11i % i11iIiiIii - i1IIi . OOooOOo
 packet = packet [ 1 : : ]
 return ( packet , iIIi111iI )
 if 25 - 25: OOooOOo / II111iiii % OoO0O00 / Oo0Ooo * Ii1I
 if 40 - 40: IiII * Oo0Ooo . OoooooooOO * I1Ii111 / I1Ii111
 if 17 - 17: oO0o * OOooOOo . II111iiii - I11i - i11iIiiIii % I1Ii111
 if 38 - 38: OoOoOO00
 if 20 - 20: ooOoO0o . i11iIiiIii + oO0o + ooOoO0o . OoO0O00 % iII111i
 if 38 - 38: I11i + I11i - Oo0Ooo . oO0o * OoooooooOO
 if 72 - 72: Oo0Ooo / II111iiii
 if 66 - 66: I11i / ooOoO0o / OOooOOo % ooOoO0o
def lisp_write_flow_log ( flow_log ) :
 Iiooo000o0OoOo = open ( "./logs/lisp-flow.log" , "a" )
 if 6 - 6: o0oOOo0O0Ooo / ooOoO0o + OOooOOo / I1ii11iIi11i % I1Ii111
 i1Ii11II = 0
 for Oo0OO0 in flow_log :
  oOo = Oo0OO0 [ 3 ]
  oO0OoOOoOO = oOo . print_flow ( Oo0OO0 [ 0 ] , Oo0OO0 [ 1 ] , Oo0OO0 [ 2 ] )
  Iiooo000o0OoOo . write ( oO0OoOOoOO )
  i1Ii11II += 1
  if 58 - 58: I11i . I11i + O0 / I1IiiI
 Iiooo000o0OoOo . close ( )
 del ( flow_log )
 if 45 - 45: OoooooooOO * II111iiii
 i1Ii11II = bold ( str ( i1Ii11II ) , False )
 lprint ( "Wrote {} flow entries to ./logs/lisp-flow.log" . format ( i1Ii11II ) )
 return
 if 28 - 28: I1ii11iIi11i
 if 85 - 85: o0oOOo0O0Ooo
 if 20 - 20: OoooooooOO . ooOoO0o + ooOoO0o
 if 7 - 7: OoO0O00 / IiII - OoO0O00 . OOooOOo
 if 56 - 56: iIii1I11I1II1 / O0 + Oo0Ooo
 if 5 - 5: O0 / i11iIiiIii * I1IiiI % IiII * OoO0O00
 if 67 - 67: I1Ii111 . iII111i + Oo0Ooo / i11iIiiIii
def lisp_policy_command ( kv_pair ) :
 i111 = lisp_policy ( "" )
 iiI1IIi1III = None
 if 27 - 27: OOooOOo
 oooo0oO0O = [ ]
 for II11iIII1i1I in range ( len ( kv_pair [ "datetime-range" ] ) ) :
  oooo0oO0O . append ( lisp_policy_match ( ) )
  if 65 - 65: iII111i - O0 * iIii1I11I1II1 + oO0o + i1IIi
  if 87 - 87: IiII % IiII
 for oOi1I1 in kv_pair . keys ( ) :
  ooOo0O0O0oOO0 = kv_pair [ oOi1I1 ]
  if 85 - 85: oO0o
  if 14 - 14: IiII / iIii1I11I1II1 . OoooooooOO
  if 14 - 14: IiII * OoooooooOO - iIii1I11I1II1
  if 11 - 11: I1IiiI + Oo0Ooo % I1Ii111 * Ii1I - iIii1I11I1II1 % I1ii11iIi11i
  if ( oOi1I1 == "instance-id" ) :
   for II11iIII1i1I in range ( len ( oooo0oO0O ) ) :
    IIiIi1IIiI1i = ooOo0O0O0oOO0 [ II11iIII1i1I ]
    if ( IIiIi1IIiI1i == "" ) : continue
    i1II = oooo0oO0O [ II11iIII1i1I ]
    if ( i1II . source_eid == None ) :
     i1II . source_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
     if 89 - 89: Oo0Ooo + i1IIi
    if ( i1II . dest_eid == None ) :
     i1II . dest_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
     if 60 - 60: I1ii11iIi11i - I1IiiI * I1Ii111 * I1Ii111 / OoooooooOO
    i1II . source_eid . instance_id = int ( IIiIi1IIiI1i )
    i1II . dest_eid . instance_id = int ( IIiIi1IIiI1i )
    if 17 - 17: i1IIi - ooOoO0o
    if 86 - 86: I1ii11iIi11i . o0oOOo0O0Ooo
  if ( oOi1I1 == "source-eid" ) :
   for II11iIII1i1I in range ( len ( oooo0oO0O ) ) :
    IIiIi1IIiI1i = ooOo0O0O0oOO0 [ II11iIII1i1I ]
    if ( IIiIi1IIiI1i == "" ) : continue
    i1II = oooo0oO0O [ II11iIII1i1I ]
    if ( i1II . source_eid == None ) :
     i1II . source_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
     if 30 - 30: o0oOOo0O0Ooo / i11iIiiIii
    II1 = i1II . source_eid . instance_id
    i1II . source_eid . store_prefix ( IIiIi1IIiI1i )
    i1II . source_eid . instance_id = II1
    if 33 - 33: OOooOOo % OoooooooOO
    if 98 - 98: Ii1I
  if ( oOi1I1 == "destination-eid" ) :
   for II11iIII1i1I in range ( len ( oooo0oO0O ) ) :
    IIiIi1IIiI1i = ooOo0O0O0oOO0 [ II11iIII1i1I ]
    if ( IIiIi1IIiI1i == "" ) : continue
    i1II = oooo0oO0O [ II11iIII1i1I ]
    if ( i1II . dest_eid == None ) :
     i1II . dest_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
     if 38 - 38: ooOoO0o - iII111i * OOooOOo % I1ii11iIi11i + Oo0Ooo
    II1 = i1II . dest_eid . instance_id
    i1II . dest_eid . store_prefix ( IIiIi1IIiI1i )
    i1II . dest_eid . instance_id = II1
    if 95 - 95: iIii1I11I1II1 / O0 % O0
    if 53 - 53: ooOoO0o . ooOoO0o
  if ( oOi1I1 == "source-rloc" ) :
   for II11iIII1i1I in range ( len ( oooo0oO0O ) ) :
    IIiIi1IIiI1i = ooOo0O0O0oOO0 [ II11iIII1i1I ]
    if ( IIiIi1IIiI1i == "" ) : continue
    i1II = oooo0oO0O [ II11iIII1i1I ]
    i1II . source_rloc = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
    i1II . source_rloc . store_prefix ( IIiIi1IIiI1i )
    if 80 - 80: i11iIiiIii % I1Ii111 % I1IiiI / I1IiiI + oO0o + iII111i
    if 18 - 18: OoO0O00 * ooOoO0o
  if ( oOi1I1 == "destination-rloc" ) :
   for II11iIII1i1I in range ( len ( oooo0oO0O ) ) :
    IIiIi1IIiI1i = ooOo0O0O0oOO0 [ II11iIII1i1I ]
    if ( IIiIi1IIiI1i == "" ) : continue
    i1II = oooo0oO0O [ II11iIII1i1I ]
    i1II . dest_rloc = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
    i1II . dest_rloc . store_prefix ( IIiIi1IIiI1i )
    if 32 - 32: oO0o . OoooooooOO - o0oOOo0O0Ooo + II111iiii
    if 4 - 4: OOooOOo * I1IiiI - I11i - I11i
  if ( oOi1I1 == "rloc-record-name" ) :
   for II11iIII1i1I in range ( len ( oooo0oO0O ) ) :
    IIiIi1IIiI1i = ooOo0O0O0oOO0 [ II11iIII1i1I ]
    if ( IIiIi1IIiI1i == "" ) : continue
    i1II = oooo0oO0O [ II11iIII1i1I ]
    i1II . rloc_record_name = IIiIi1IIiI1i
    if 67 - 67: I1IiiI
    if 32 - 32: oO0o * i11iIiiIii - I11i % Oo0Ooo * I1ii11iIi11i
  if ( oOi1I1 == "geo-name" ) :
   for II11iIII1i1I in range ( len ( oooo0oO0O ) ) :
    IIiIi1IIiI1i = ooOo0O0O0oOO0 [ II11iIII1i1I ]
    if ( IIiIi1IIiI1i == "" ) : continue
    i1II = oooo0oO0O [ II11iIII1i1I ]
    i1II . geo_name = IIiIi1IIiI1i
    if 79 - 79: II111iiii / Oo0Ooo / I1ii11iIi11i
    if 30 - 30: I11i . o0oOOo0O0Ooo / II111iiii
  if ( oOi1I1 == "elp-name" ) :
   for II11iIII1i1I in range ( len ( oooo0oO0O ) ) :
    IIiIi1IIiI1i = ooOo0O0O0oOO0 [ II11iIII1i1I ]
    if ( IIiIi1IIiI1i == "" ) : continue
    i1II = oooo0oO0O [ II11iIII1i1I ]
    i1II . elp_name = IIiIi1IIiI1i
    if 59 - 59: i11iIiiIii
    if 5 - 5: i11iIiiIii + o0oOOo0O0Ooo . OoO0O00 % OoOoOO00 + I11i
  if ( oOi1I1 == "rle-name" ) :
   for II11iIII1i1I in range ( len ( oooo0oO0O ) ) :
    IIiIi1IIiI1i = ooOo0O0O0oOO0 [ II11iIII1i1I ]
    if ( IIiIi1IIiI1i == "" ) : continue
    i1II = oooo0oO0O [ II11iIII1i1I ]
    i1II . rle_name = IIiIi1IIiI1i
    if 59 - 59: I1ii11iIi11i
    if 47 - 47: I1IiiI + Oo0Ooo
  if ( oOi1I1 == "json-name" ) :
   for II11iIII1i1I in range ( len ( oooo0oO0O ) ) :
    IIiIi1IIiI1i = ooOo0O0O0oOO0 [ II11iIII1i1I ]
    if ( IIiIi1IIiI1i == "" ) : continue
    i1II = oooo0oO0O [ II11iIII1i1I ]
    i1II . json_name = IIiIi1IIiI1i
    if 78 - 78: i1IIi / I1ii11iIi11i % ooOoO0o * OoO0O00
    if 10 - 10: i1IIi % ooOoO0o / iII111i
  if ( oOi1I1 == "datetime-range" ) :
   for II11iIII1i1I in range ( len ( oooo0oO0O ) ) :
    IIiIi1IIiI1i = ooOo0O0O0oOO0 [ II11iIII1i1I ]
    i1II = oooo0oO0O [ II11iIII1i1I ]
    if ( IIiIi1IIiI1i == "" ) : continue
    II1Ooo0000o00OO = lisp_datetime ( IIiIi1IIiI1i [ 0 : 19 ] )
    iIiooooOooOO0 = lisp_datetime ( IIiIi1IIiI1i [ 19 : : ] )
    if ( II1Ooo0000o00OO . valid_datetime ( ) and iIiooooOooOO0 . valid_datetime ( ) ) :
     i1II . datetime_lower = II1Ooo0000o00OO
     i1II . datetime_upper = iIiooooOooOO0
     if 98 - 98: IiII / o0oOOo0O0Ooo - i1IIi - OOooOOo
     if 65 - 65: Ii1I + OoOoOO00 * Oo0Ooo . O0 . IiII
     if 33 - 33: i11iIiiIii . i1IIi . I1Ii111 - OoOoOO00 + OOooOOo
     if 34 - 34: I1ii11iIi11i . i1IIi * O0 / OoooooooOO
     if 22 - 22: OOooOOo % o0oOOo0O0Ooo - i11iIiiIii
     if 58 - 58: IiII . Ii1I + II111iiii
     if 31 - 31: i11iIiiIii + i11iIiiIii + I11i * Oo0Ooo . I11i
  if ( oOi1I1 == "set-action" ) :
   i111 . set_action = ooOo0O0O0oOO0
   if 28 - 28: OOooOOo * iIii1I11I1II1 * OoOoOO00
  if ( oOi1I1 == "set-record-ttl" ) :
   i111 . set_record_ttl = int ( ooOo0O0O0oOO0 )
   if 75 - 75: Oo0Ooo % IiII + II111iiii + oO0o
  if ( oOi1I1 == "set-instance-id" ) :
   if ( i111 . set_source_eid == None ) :
    i111 . set_source_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
    if 35 - 35: I1ii11iIi11i - oO0o - O0 / iII111i % IiII
   if ( i111 . set_dest_eid == None ) :
    i111 . set_dest_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
    if 10 - 10: OOooOOo + oO0o - I1Ii111 . I1IiiI
   iiI1IIi1III = int ( ooOo0O0O0oOO0 )
   i111 . set_source_eid . instance_id = iiI1IIi1III
   i111 . set_dest_eid . instance_id = iiI1IIi1III
   if 11 - 11: I1ii11iIi11i . I1Ii111 / o0oOOo0O0Ooo + IiII
  if ( oOi1I1 == "set-source-eid" ) :
   if ( i111 . set_source_eid == None ) :
    i111 . set_source_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
    if 73 - 73: OoO0O00 . i11iIiiIii * OoO0O00 * i1IIi + I11i
   i111 . set_source_eid . store_prefix ( ooOo0O0O0oOO0 )
   if ( iiI1IIi1III != None ) : i111 . set_source_eid . instance_id = iiI1IIi1III
   if 27 - 27: i11iIiiIii / OoOoOO00 % O0 / II111iiii . I11i - ooOoO0o
  if ( oOi1I1 == "set-destination-eid" ) :
   if ( i111 . set_dest_eid == None ) :
    i111 . set_dest_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
    if 54 - 54: oO0o * II111iiii
   i111 . set_dest_eid . store_prefix ( ooOo0O0O0oOO0 )
   if ( iiI1IIi1III != None ) : i111 . set_dest_eid . instance_id = iiI1IIi1III
   if 79 - 79: o0oOOo0O0Ooo . ooOoO0o . Oo0Ooo * OoooooooOO
  if ( oOi1I1 == "set-rloc-address" ) :
   i111 . set_rloc_address = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
   i111 . set_rloc_address . store_address ( ooOo0O0O0oOO0 )
   if 98 - 98: ooOoO0o
  if ( oOi1I1 == "set-rloc-record-name" ) :
   i111 . set_rloc_record_name = ooOo0O0O0oOO0
   if 73 - 73: I1Ii111
  if ( oOi1I1 == "set-elp-name" ) :
   i111 . set_elp_name = ooOo0O0O0oOO0
   if 97 - 97: OoO0O00 * Ii1I + Oo0Ooo
  if ( oOi1I1 == "set-geo-name" ) :
   i111 . set_geo_name = ooOo0O0O0oOO0
   if 83 - 83: II111iiii - Oo0Ooo % II111iiii * o0oOOo0O0Ooo
  if ( oOi1I1 == "set-rle-name" ) :
   i111 . set_rle_name = ooOo0O0O0oOO0
   if 51 - 51: iII111i * iIii1I11I1II1 % Ii1I * Ii1I + i11iIiiIii . OoooooooOO
  if ( oOi1I1 == "set-json-name" ) :
   i111 . set_json_name = ooOo0O0O0oOO0
   if 54 - 54: i11iIiiIii . iIii1I11I1II1 * iIii1I11I1II1 + Ii1I % I11i - OoO0O00
  if ( oOi1I1 == "policy-name" ) :
   i111 . policy_name = ooOo0O0O0oOO0
   if 16 - 16: IiII % iIii1I11I1II1 * i11iIiiIii + O0
   if 76 - 76: iII111i * OOooOOo
   if 7 - 7: ooOoO0o + o0oOOo0O0Ooo + o0oOOo0O0Ooo
   if 73 - 73: IiII % I11i % i11iIiiIii + ooOoO0o
   if 83 - 83: Ii1I * I1Ii111 * i11iIiiIii / iIii1I11I1II1 % I1ii11iIi11i
   if 40 - 40: iII111i
 i111 . match_clauses = oooo0oO0O
 i111 . save_policy ( )
 return
 if 21 - 21: I1Ii111 / iII111i + Oo0Ooo / I1ii11iIi11i / I1Ii111
 if 33 - 33: OoooooooOO
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
if 59 - 59: i11iIiiIii - OoooooooOO . ooOoO0o / i11iIiiIii % iIii1I11I1II1 * I1ii11iIi11i
if 45 - 45: I1ii11iIi11i * I1ii11iIi11i
if 31 - 31: OoO0O00 - OOooOOo . iII111i * I1Ii111 * iII111i + I1ii11iIi11i
if 5 - 5: Oo0Ooo . I1Ii111
if 77 - 77: i11iIiiIii / I1Ii111 / I1ii11iIi11i % oO0o
if 83 - 83: Ii1I % iIii1I11I1II1 / I1ii11iIi11i + I11i
if 23 - 23: iIii1I11I1II1 - I1IiiI
def lisp_send_to_arista ( command , interface ) :
 interface = "" if ( interface == None ) else "interface " + interface
 if 51 - 51: OoooooooOO / IiII / I1ii11iIi11i . Oo0Ooo - o0oOOo0O0Ooo * OoooooooOO
 IIi1 = command
 if ( interface != "" ) : IIi1 = interface + ": " + IIi1
 lprint ( "Send CLI command '{}' to hardware" . format ( IIi1 ) )
 if 20 - 20: OoOoOO00
 commands = '''
        enable
        configure
        {}
        {}
    ''' . format ( interface , command )
 if 33 - 33: OoO0O00
 os . system ( "FastCli -c '{}'" . format ( commands ) )
 return
 if 55 - 55: ooOoO0o + ooOoO0o
 if 93 - 93: oO0o - I1IiiI / I1ii11iIi11i % o0oOOo0O0Ooo / OoooooooOO + II111iiii
 if 10 - 10: o0oOOo0O0Ooo - iII111i . O0 + OoO0O00 - Oo0Ooo - i11iIiiIii
 if 37 - 37: iIii1I11I1II1
 if 37 - 37: II111iiii % OoOoOO00 . IiII * ooOoO0o . I1IiiI
 if 25 - 25: OoooooooOO % i1IIi . I1Ii111 / OoOoOO00 - I1ii11iIi11i
 if 15 - 15: iIii1I11I1II1
def lisp_arista_is_alive ( prefix ) :
 iiI1i = "enable\nsh plat trident l3 software routes {}\n" . format ( prefix )
 I1i = commands . getoutput ( "FastCli -c '{}'" . format ( iiI1i ) )
 if 72 - 72: OoO0O00 . IiII * Ii1I - I1IiiI
 if 81 - 81: oO0o . OOooOOo - Ii1I . OoOoOO00
 if 100 - 100: Ii1I * i1IIi * i1IIi - iII111i + OoO0O00 + OoO0O00
 if 9 - 9: oO0o / OoO0O00 . I1IiiI
 I1i = I1i . split ( "\n" ) [ 1 ]
 I11iIII1i1i1 = I1i . split ( " " )
 I11iIII1i1i1 = I11iIII1i1i1 [ - 1 ] . replace ( "\r" , "" )
 if 44 - 44: I1IiiI
 if 66 - 66: o0oOOo0O0Ooo
 if 40 - 40: OOooOOo * Ii1I
 if 38 - 38: ooOoO0o
 return ( I11iIII1i1i1 == "Y" )
 if 5 - 5: OoooooooOO + iII111i - I11i
 if 95 - 95: OOooOOo / i11iIiiIii - Ii1I + I1ii11iIi11i
 if 7 - 7: I1ii11iIi11i
 if 37 - 37: O0 . II111iiii
 if 70 - 70: o0oOOo0O0Ooo / iII111i + i1IIi + I11i % iIii1I11I1II1 % Oo0Ooo
 if 1 - 1: O0 + OoO0O00 . i11iIiiIii + I1Ii111 - OoO0O00 - IiII
 if 1 - 1: I1ii11iIi11i / i1IIi . I1IiiI / Ii1I
 if 19 - 19: iIii1I11I1II1 / Oo0Ooo . O0 - Oo0Ooo
 if 74 - 74: I1ii11iIi11i * OoooooooOO . iII111i
 if 45 - 45: I1IiiI - IiII % ooOoO0o - IiII . Oo0Ooo - o0oOOo0O0Ooo
 if 27 - 27: iII111i
 if 64 - 64: iIii1I11I1II1 - OOooOOo . iII111i % o0oOOo0O0Ooo / II111iiii % OoooooooOO
 if 87 - 87: OoooooooOO
 if 70 - 70: o0oOOo0O0Ooo % OoooooooOO % I1IiiI . OoOoOO00 * I1IiiI - ooOoO0o
 if 92 - 92: I1IiiI . I11i
 if 66 - 66: I1Ii111 / I11i / OoooooooOO % OoOoOO00 . oO0o * iII111i
 if 34 - 34: I1ii11iIi11i * I1ii11iIi11i % I11i / OOooOOo % oO0o . OoOoOO00
 if 25 - 25: I1ii11iIi11i / I11i + i1IIi . I1IiiI + ooOoO0o
 if 29 - 29: IiII + I1ii11iIi11i
 if 8 - 8: IiII % I1IiiI
 if 10 - 10: OoooooooOO / OoOoOO00
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
def lisp_program_vxlan_hardware ( mc ) :
 if 80 - 80: o0oOOo0O0Ooo
 if 100 - 100: iIii1I11I1II1 . OoOoOO00 . OoooooooOO / I1ii11iIi11i - I1IiiI * I11i
 if 5 - 5: i1IIi * o0oOOo0O0Ooo - I1Ii111 + I1IiiI - II111iiii
 if 15 - 15: I1Ii111
 if 38 - 38: O0
 if 50 - 50: i11iIiiIii * OoO0O00 + iII111i / O0 * oO0o % ooOoO0o
 if ( os . path . exists ( "/persist/local/lispers.net" ) == False ) : return
 if 6 - 6: OoO0O00 . o0oOOo0O0Ooo / Ii1I + Ii1I
 if 59 - 59: II111iiii - o0oOOo0O0Ooo * OoooooooOO
 if 83 - 83: oO0o . iIii1I11I1II1 . iII111i % Oo0Ooo
 if 48 - 48: oO0o % OoO0O00 - OoooooooOO . IiII
 if ( len ( mc . best_rloc_set ) == 0 ) : return
 if 11 - 11: I1Ii111 % o0oOOo0O0Ooo - o0oOOo0O0Ooo % OoooooooOO . o0oOOo0O0Ooo - I1ii11iIi11i
 if 33 - 33: OoO0O00 + II111iiii . Oo0Ooo * I1Ii111
 if 63 - 63: OoooooooOO + OoOoOO00 - OoooooooOO
 if 54 - 54: OoO0O00 + I1IiiI % O0 + OoO0O00
 iII = mc . eid . print_prefix_no_iid ( )
 Oo0o0o0oo = mc . best_rloc_set [ 0 ] . rloc . print_address_no_iid ( )
 if 37 - 37: II111iiii / I1ii11iIi11i * I1IiiI - OoooooooOO
 if 55 - 55: IiII / ooOoO0o * I1IiiI / I1Ii111 - Oo0Ooo % o0oOOo0O0Ooo
 if 82 - 82: OoO0O00 - iIii1I11I1II1 . Oo0Ooo / IiII . OoO0O00
 if 47 - 47: OOooOOo + IiII
 II1i1iI = commands . getoutput ( "ip route get {} | egrep vlan4094" . format ( iII ) )
 if 36 - 36: i1IIi * IiII * I1ii11iIi11i
 if ( II1i1iI != "" ) :
  lprint ( "Route {} already in hardware: '{}'" . format ( green ( iII , False ) , II1i1iI ) )
  if 28 - 28: I1ii11iIi11i - i11iIiiIii % i11iIiiIii
  return
  if 31 - 31: iII111i
  if 64 - 64: Ii1I
  if 4 - 4: OoOoOO00
  if 78 - 78: i1IIi - iII111i + O0 - I1IiiI % o0oOOo0O0Ooo
  if 48 - 48: iII111i / II111iiii * I1Ii111 + I11i / ooOoO0o . OoOoOO00
  if 45 - 45: OOooOOo / Ii1I % O0
  if 7 - 7: oO0o * i11iIiiIii + OoooooooOO + I11i
 Ii1Ii1111iii = commands . getoutput ( "ifconfig | egrep 'vxlan|vlan4094'" )
 if ( Ii1Ii1111iii . find ( "vxlan" ) == - 1 ) :
  lprint ( "No VXLAN interface found, cannot program hardware" )
  return
  if 4 - 4: i11iIiiIii
 if ( Ii1Ii1111iii . find ( "vlan4094" ) == - 1 ) :
  lprint ( "No vlan4094 interface found, cannot program hardware" )
  return
  if 53 - 53: I1Ii111
 ooO00O00OO0oo = commands . getoutput ( "ip addr | egrep vlan4094 | egrep inet" )
 if ( ooO00O00OO0oo == "" ) :
  lprint ( "No IP address found on vlan4094, cannot program hardware" )
  return
  if 41 - 41: I11i + I1IiiI + oO0o . Ii1I
 ooO00O00OO0oo = ooO00O00OO0oo . split ( "inet " ) [ 1 ]
 ooO00O00OO0oo = ooO00O00OO0oo . split ( "/" ) [ 0 ]
 if 71 - 71: iIii1I11I1II1 / I1ii11iIi11i + OoooooooOO . ooOoO0o
 if 63 - 63: i11iIiiIii % I1Ii111 % IiII * i1IIi + I1Ii111 + I1Ii111
 if 51 - 51: iII111i / Ii1I . iII111i + O0 / IiII + OoooooooOO
 if 29 - 29: I1IiiI - OOooOOo
 if 83 - 83: OoOoOO00 * oO0o . OOooOOo - OoO0O00
 if 73 - 73: I1ii11iIi11i / iII111i / Oo0Ooo
 if 85 - 85: Ii1I
 Oooo0 = [ ]
 iiOOoOOOo = commands . getoutput ( "arp -i vlan4094" ) . split ( "\n" )
 for IIIIIiI11Ii in iiOOoOOOo :
  if ( IIIIIiI11Ii . find ( "vlan4094" ) == - 1 ) : continue
  if ( IIIIIiI11Ii . find ( "(incomplete)" ) == - 1 ) : continue
  O0o0 = IIIIIiI11Ii . split ( " " ) [ 0 ]
  Oooo0 . append ( O0o0 )
  if 12 - 12: oO0o - i11iIiiIii / O0 + oO0o . I11i % iII111i
  if 30 - 30: I1IiiI % iIii1I11I1II1
 O0o0 = None
 IiI1iIi1I1i = ooO00O00OO0oo
 ooO00O00OO0oo = ooO00O00OO0oo . split ( "." )
 for II11iIII1i1I in range ( 1 , 255 ) :
  ooO00O00OO0oo [ 3 ] = str ( II11iIII1i1I )
  iIiIi1iI11iiI = "." . join ( ooO00O00OO0oo )
  if ( iIiIi1iI11iiI in Oooo0 ) : continue
  if ( iIiIi1iI11iiI == IiI1iIi1I1i ) : continue
  O0o0 = iIiIi1iI11iiI
  break
  if 37 - 37: OoooooooOO - Oo0Ooo % oO0o
 if ( O0o0 == None ) :
  lprint ( "Address allocation failed for vlan4094, cannot program " + "hardware" )
  if 59 - 59: II111iiii - o0oOOo0O0Ooo / I1ii11iIi11i . oO0o / o0oOOo0O0Ooo - iII111i
  return
  if 65 - 65: I1ii11iIi11i * OOooOOo * ooOoO0o + oO0o - OOooOOo
  if 100 - 100: iII111i
  if 12 - 12: OoooooooOO - I1ii11iIi11i * iII111i / ooOoO0o
  if 99 - 99: I1ii11iIi11i + I11i
  if 29 - 29: I1ii11iIi11i / oO0o
  if 2 - 2: Oo0Ooo / IiII - OoooooooOO
  if 65 - 65: OoO0O00 - Ii1I
 OO000oOooO00 = Oo0o0o0oo . split ( "." )
 IIi1iii = lisp_hex_string ( OO000oOooO00 [ 1 ] ) . zfill ( 2 )
 oo0O0oOOo0O = lisp_hex_string ( OO000oOooO00 [ 2 ] ) . zfill ( 2 )
 iiIIi1iII1 = lisp_hex_string ( OO000oOooO00 [ 3 ] ) . zfill ( 2 )
 i1IiII1i1I = "00:00:00:{}:{}:{}" . format ( IIi1iii , oo0O0oOOo0O , iiIIi1iII1 )
 IIiiIi = "0000.00{}.{}{}" . format ( IIi1iii , oo0O0oOOo0O , iiIIi1iII1 )
 iiIIi1I = "arp -i vlan4094 -s {} {}" . format ( O0o0 , i1IiII1i1I )
 os . system ( iiIIi1I )
 if 3 - 3: i1IIi * OOooOOo
 if 86 - 86: OoOoOO00 * Oo0Ooo / iIii1I11I1II1
 if 63 - 63: IiII - ooOoO0o % OoO0O00 * i11iIiiIii % OOooOOo
 if 90 - 90: oO0o / Oo0Ooo + iII111i - O0
 O0o0oOo = ( "mac address-table static {} vlan 4094 " + "interface vxlan 1 vtep {}" ) . format ( IIiiIi , Oo0o0o0oo )
 if 52 - 52: iIii1I11I1II1 * OOooOOo % i1IIi
 lisp_send_to_arista ( O0o0oOo , None )
 if 1 - 1: o0oOOo0O0Ooo + Ii1I - o0oOOo0O0Ooo % I1ii11iIi11i
 if 61 - 61: OoooooooOO
 if 93 - 93: OoO0O00
 if 18 - 18: OoOoOO00 - OoOoOO00 . iII111i / Oo0Ooo % Ii1I / iIii1I11I1II1
 if 97 - 97: ooOoO0o * ooOoO0o / IiII / iII111i . i11iIiiIii
 IIIi11Ii11I = "ip route add {} via {}" . format ( iII , O0o0 )
 os . system ( IIIi11Ii11I )
 if 61 - 61: I1Ii111 - I1IiiI - I11i * OoO0O00 - O0 + iII111i
 lprint ( "Hardware programmed with commands:" )
 IIIi11Ii11I = IIIi11Ii11I . replace ( iII , green ( iII , False ) )
 lprint ( "  " + IIIi11Ii11I )
 lprint ( "  " + iiIIi1I )
 O0o0oOo = O0o0oOo . replace ( Oo0o0o0oo , red ( Oo0o0o0oo , False ) )
 lprint ( "  " + O0o0oOo )
 return
 if 9 - 9: IiII - OOooOOo / O0 + i1IIi . O0 % oO0o
 if 57 - 57: i1IIi . OOooOOo
 if 72 - 72: ooOoO0o / I1IiiI - ooOoO0o * OoO0O00 . OOooOOo
 if 1 - 1: o0oOOo0O0Ooo + I1Ii111 + OoO0O00 * OOooOOo / I1Ii111 % i11iIiiIii
 if 49 - 49: OOooOOo - oO0o
 if 73 - 73: o0oOOo0O0Ooo . I1IiiI - I11i . ooOoO0o % II111iiii . OoooooooOO
 if 8 - 8: OoooooooOO
def lisp_clear_hardware_walk ( mc , parms ) :
 OOO0000o = mc . eid . print_prefix_no_iid ( )
 os . system ( "ip route delete {}" . format ( OOO0000o ) )
 return ( [ True , None ] )
 if 92 - 92: ooOoO0o + IiII * II111iiii
 if 41 - 41: I1IiiI + OoOoOO00 . OOooOOo
 if 57 - 57: II111iiii . iIii1I11I1II1
 if 32 - 32: o0oOOo0O0Ooo
 if 75 - 75: I1IiiI . II111iiii - iII111i % IiII * OoO0O00 % ooOoO0o
 if 38 - 38: I1IiiI / OoooooooOO
 if 16 - 16: i1IIi . i11iIiiIii . oO0o - I11i
 if 96 - 96: iII111i - OoOoOO00
def lisp_clear_map_cache ( ) :
 global lisp_map_cache , lisp_rloc_probe_list
 global lisp_crypto_keys_by_rloc_encap , lisp_crypto_keys_by_rloc_decap
 global lisp_rtr_list
 if 43 - 43: OoO0O00 - I1Ii111 % OoooooooOO % I1ii11iIi11i . OoOoOO00
 oO000oO0O0 = bold ( "User cleared" , False )
 i1Ii11II = lisp_map_cache . cache_count
 lprint ( "{} map-cache with {} entries" . format ( oO000oO0O0 , i1Ii11II ) )
 if 83 - 83: i1IIi - OOooOOo * iII111i . o0oOOo0O0Ooo - I1Ii111 % oO0o
 if ( lisp_program_hardware ) :
  lisp_map_cache . walk_cache ( lisp_clear_hardware_walk , None )
  if 11 - 11: o0oOOo0O0Ooo . OoooooooOO - i1IIi
 lisp_map_cache = lisp_cache ( )
 if 71 - 71: I1IiiI . OOooOOo . I1ii11iIi11i
 if 90 - 90: i11iIiiIii + I1Ii111 % II111iiii
 if 67 - 67: OoOoOO00 / iII111i * OoO0O00 % i11iIiiIii
 if 76 - 76: OoO0O00
 if 92 - 92: iIii1I11I1II1 * O0 % I11i
 lisp_rloc_probe_list = { }
 if 92 - 92: OoOoOO00 + oO0o
 if 89 - 89: IiII % iII111i / iIii1I11I1II1 . Ii1I . Oo0Ooo + ooOoO0o
 if 28 - 28: I1IiiI . iIii1I11I1II1
 if 12 - 12: I1Ii111 * OOooOOo
 lisp_crypto_keys_by_rloc_encap = { }
 lisp_crypto_keys_by_rloc_decap = { }
 if 11 - 11: II111iiii % O0 % O0 % o0oOOo0O0Ooo
 if 45 - 45: OoooooooOO * oO0o
 if 74 - 74: ooOoO0o * I11i / oO0o - IiII + OoOoOO00
 if 16 - 16: Oo0Ooo
 if 29 - 29: Oo0Ooo . I1ii11iIi11i / II111iiii / oO0o / o0oOOo0O0Ooo + I11i
 lisp_rtr_list = { }
 if 4 - 4: OoooooooOO % I1ii11iIi11i . OoO0O00 * o0oOOo0O0Ooo + I1ii11iIi11i * IiII
 if 67 - 67: I1IiiI
 if 93 - 93: ooOoO0o . Ii1I + IiII / Oo0Ooo % I11i
 if 40 - 40: Oo0Ooo % OoOoOO00 . IiII / I1IiiI % OoooooooOO
 lisp_process_data_plane_restart ( True )
 return
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
def lisp_encapsulate_rloc_probe ( lisp_sockets , rloc , nat_info , packet ) :
 if ( len ( lisp_sockets ) != 4 ) : return
 if 5 - 5: o0oOOo0O0Ooo % oO0o / OoO0O00
 IiiIIII1 = lisp_myrlocs [ 0 ]
 if 21 - 21: OoooooooOO
 if 63 - 63: I1IiiI / o0oOOo0O0Ooo - I1Ii111
 if 49 - 49: iII111i . OoOoOO00
 if 91 - 91: OOooOOo / Ii1I / IiII * OOooOOo
 if 68 - 68: I11i
 OOOOO000oo0 = len ( packet ) + 28
 oOo00OoO0O = struct . pack ( "BBHIBBHII" , 0x45 , 0 , socket . htons ( OOOOO000oo0 ) , 0 , 64 ,
 17 , 0 , socket . htonl ( IiiIIII1 . address ) , socket . htonl ( rloc . address ) )
 oOo00OoO0O = lisp_ip_checksum ( oOo00OoO0O )
 if 91 - 91: I11i
 OOOOo00oo00O = struct . pack ( "HHHH" , 0 , socket . htons ( LISP_CTRL_PORT ) ,
 socket . htons ( OOOOO000oo0 - 20 ) , 0 )
 if 24 - 24: ooOoO0o . i1IIi - O0 + I11i
 if 71 - 71: OoOoOO00
 if 29 - 29: O0 . i11iIiiIii
 if 51 - 51: IiII
 packet = lisp_packet ( oOo00OoO0O + OOOOo00oo00O + packet )
 if 53 - 53: O0
 if 19 - 19: o0oOOo0O0Ooo / iII111i % OoOoOO00
 if 65 - 65: o0oOOo0O0Ooo
 if 89 - 89: iIii1I11I1II1 + OoooooooOO + i1IIi + OoooooooOO % IiII * OoO0O00
 packet . inner_dest . copy_address ( rloc )
 packet . inner_dest . instance_id = 0xffffff
 packet . inner_source . copy_address ( IiiIIII1 )
 packet . inner_ttl = 64
 packet . outer_dest . copy_address ( rloc )
 packet . outer_source . copy_address ( IiiIIII1 )
 packet . outer_version = packet . outer_dest . afi_to_version ( )
 packet . outer_ttl = 64
 packet . encap_port = nat_info . port if nat_info else LISP_DATA_PORT
 if 53 - 53: OOooOOo . IiII % I11i - OoO0O00 - Oo0Ooo
 ooOOo00o0ooO = red ( rloc . print_address_no_iid ( ) , False )
 if ( nat_info ) :
  ooOOO00000oo = " {}" . format ( blue ( nat_info . hostname , False ) )
  oo00OO0Oooo = bold ( "RLOC-probe request" , False )
 else :
  ooOOO00000oo = ""
  oo00OO0Oooo = bold ( "RLOC-probe reply" , False )
  if 58 - 58: I1Ii111 / OoooooooOO . I11i % I1Ii111
  if 8 - 8: Oo0Ooo % ooOoO0o / i11iIiiIii
 lprint ( ( "Data encapsulate {} to {}{} port {} for " + "NAT-traversal" ) . format ( oo00OO0Oooo , ooOOo00o0ooO , ooOOO00000oo , packet . encap_port ) )
 if 54 - 54: IiII
 if 85 - 85: OOooOOo - i1IIi
 if 10 - 10: I1ii11iIi11i
 if 3 - 3: ooOoO0o * O0 / o0oOOo0O0Ooo
 if 22 - 22: OoOoOO00 + OOooOOo . iII111i % iIii1I11I1II1 - I11i
 if ( packet . encode ( None ) == None ) : return
 packet . print_packet ( "Send" , True )
 if 23 - 23: OoOoOO00 * I1Ii111
 IIiii1i1I1I = lisp_sockets [ 3 ]
 packet . send_packet ( IIiii1i1I1I , packet . outer_dest )
 del ( packet )
 return
 if 41 - 41: ooOoO0o
 if 54 - 54: ooOoO0o / o0oOOo0O0Ooo / II111iiii
 if 77 - 77: Oo0Ooo
 if 53 - 53: ooOoO0o * iIii1I11I1II1 . oO0o * Oo0Ooo . Oo0Ooo % iIii1I11I1II1
 if 7 - 7: ooOoO0o + Ii1I
 if 25 - 25: OoO0O00 * oO0o
 if 29 - 29: OOooOOo - I1Ii111 - i11iIiiIii % i1IIi
 if 2 - 2: i11iIiiIii % iIii1I11I1II1 * OOooOOo
def lisp_get_default_route_next_hops ( ) :
 if 45 - 45: oO0o + i1IIi + iII111i + o0oOOo0O0Ooo * OOooOOo + ooOoO0o
 if 83 - 83: OoO0O00 - ooOoO0o / OoooooooOO % iIii1I11I1II1 - II111iiii
 if 73 - 73: Oo0Ooo + II111iiii - IiII
 if 60 - 60: i1IIi . i11iIiiIii / i1IIi . I11i % OOooOOo
 if ( lisp_is_macos ( ) ) :
  iiI1i = "route -n get default"
  II1111 = commands . getoutput ( iiI1i ) . split ( "\n" )
  Oo0O00ooo0O = II111IiiiI1 = None
  for Iiooo000o0OoOo in II1111 :
   if ( Iiooo000o0OoOo . find ( "gateway: " ) != - 1 ) : Oo0O00ooo0O = Iiooo000o0OoOo . split ( ": " ) [ 1 ]
   if ( Iiooo000o0OoOo . find ( "interface: " ) != - 1 ) : II111IiiiI1 = Iiooo000o0OoOo . split ( ": " ) [ 1 ]
   if 77 - 77: iIii1I11I1II1
  return ( [ [ II111IiiiI1 , Oo0O00ooo0O ] ] )
  if 46 - 46: oO0o . OoO0O00
  if 82 - 82: OoooooooOO * Ii1I + O0 * I1IiiI + ooOoO0o
  if 82 - 82: OoO0O00 + II111iiii % II111iiii / o0oOOo0O0Ooo
  if 89 - 89: OoOoOO00 . I1ii11iIi11i * o0oOOo0O0Ooo . OoOoOO00 - i11iIiiIii * IiII
  if 37 - 37: OoooooooOO - I1Ii111 . Ii1I . i1IIi * IiII / ooOoO0o
 iiI1i = "ip route | egrep 'default via'"
 II1i1 = commands . getoutput ( iiI1i ) . split ( "\n" )
 if 12 - 12: OoooooooOO
 Oooo0Oo00O00 = [ ]
 for II1i1iI in II1i1 :
  if ( II1i1iI . find ( " metric " ) != - 1 ) : continue
  Oo0O = II1i1iI . split ( " " )
  try :
   IiOO0 = Oo0O . index ( "via" ) + 1
   if ( IiOO0 >= len ( Oo0O ) ) : continue
   oOOOoOoO0o = Oo0O . index ( "dev" ) + 1
   if ( oOOOoOoO0o >= len ( Oo0O ) ) : continue
  except :
   continue
   if 91 - 91: iII111i . OOooOOo / iIii1I11I1II1 . Oo0Ooo . II111iiii . OoOoOO00
   if 31 - 31: OoO0O00 . I1ii11iIi11i % I11i - II111iiii
  Oooo0Oo00O00 . append ( [ Oo0O [ oOOOoOoO0o ] , Oo0O [ IiOO0 ] ] )
  if 70 - 70: ooOoO0o - IiII - OoO0O00 / I11i
 return ( Oooo0Oo00O00 )
 if 59 - 59: IiII % ooOoO0o . iII111i / Ii1I * Ii1I
 if 73 - 73: I1ii11iIi11i . oO0o % I11i . I1ii11iIi11i / I1Ii111 / II111iiii
 if 23 - 23: OoooooooOO . o0oOOo0O0Ooo
 if 76 - 76: I1Ii111
 if 91 - 91: iIii1I11I1II1 / Ii1I . I1IiiI
 if 63 - 63: ooOoO0o . Ii1I - I1Ii111 - oO0o * I1Ii111 + ooOoO0o
 if 85 - 85: II111iiii + I1ii11iIi11i
def lisp_get_host_route_next_hop ( rloc ) :
 iiI1i = "ip route | egrep '{} via'" . format ( rloc )
 II1i1iI = commands . getoutput ( iiI1i ) . split ( " " )
 if 33 - 33: iII111i
 try : oo0OOo0O = II1i1iI . index ( "via" ) + 1
 except : return ( None )
 if 14 - 14: O0 * Oo0Ooo / i1IIi
 if ( oo0OOo0O >= len ( II1i1iI ) ) : return ( None )
 return ( II1i1iI [ oo0OOo0O ] )
 if 95 - 95: O0 % i1IIi % ooOoO0o % oO0o - I1IiiI
 if 78 - 78: II111iiii % OOooOOo
 if 6 - 6: OOooOOo
 if 21 - 21: I1Ii111 - Ii1I - i1IIi % oO0o
 if 55 - 55: OOooOOo + oO0o - II111iiii
 if 5 - 5: iII111i * OoooooooOO . OoO0O00 % ooOoO0o + Ii1I
 if 59 - 59: OoOoOO00
def lisp_install_host_route ( dest , nh , install ) :
 install = "add" if install else "delete"
 IIiii1IiiIiii = "none" if nh == None else nh
 if 96 - 96: I1IiiI
 lprint ( "{} host-route {}, nh {}" . format ( install . title ( ) , dest , IIiii1IiiIiii ) )
 if 3 - 3: OoooooooOO
 if ( nh == None ) :
  I1iIiI = "ip route {} {}/32" . format ( install , dest )
 else :
  I1iIiI = "ip route {} {}/32 via {}" . format ( install , dest , nh )
  if 3 - 3: IiII / O0 * i11iIiiIii . iII111i - iIii1I11I1II1
 os . system ( I1iIiI )
 return
 if 56 - 56: ooOoO0o
 if 82 - 82: ooOoO0o . IiII . I1Ii111 - iIii1I11I1II1 + II111iiii . OoOoOO00
 if 59 - 59: Oo0Ooo
 if 98 - 98: I1Ii111 * II111iiii / Oo0Ooo . Oo0Ooo % I1Ii111
 if 52 - 52: OoOoOO00
 if 59 - 59: ooOoO0o / OoooooooOO
 if 71 - 71: OOooOOo + I11i * O0 / o0oOOo0O0Ooo + I1IiiI + Ii1I
 if 41 - 41: ooOoO0o * I1Ii111
def lisp_checkpoint ( checkpoint_list ) :
 if ( lisp_checkpoint_map_cache == False ) : return
 if 40 - 40: OoOoOO00
 Iiooo000o0OoOo = open ( lisp_checkpoint_filename , "w" )
 for iiIIIIiI111 in checkpoint_list :
  Iiooo000o0OoOo . write ( iiIIIIiI111 + "\n" )
  if 60 - 60: IiII . i11iIiiIii * II111iiii . Ii1I
 Iiooo000o0OoOo . close ( )
 lprint ( "{} {} entries to file '{}'" . format ( bold ( "Checkpoint" , False ) ,
 len ( checkpoint_list ) , lisp_checkpoint_filename ) )
 return
 if 10 - 10: O0
 if 65 - 65: I11i % i11iIiiIii + i11iIiiIii % II111iiii
 if 95 - 95: I1Ii111 - I11i . II111iiii . i1IIi / II111iiii + Oo0Ooo
 if 96 - 96: iIii1I11I1II1 * iII111i / OOooOOo * iIii1I11I1II1 - O0
 if 28 - 28: I11i / I1IiiI - I1Ii111 + I1ii11iIi11i % iIii1I11I1II1
 if 35 - 35: iIii1I11I1II1 % Oo0Ooo % iII111i / iIii1I11I1II1 - I1ii11iIi11i . Oo0Ooo
 if 81 - 81: II111iiii + oO0o
 if 67 - 67: ooOoO0o + I11i - I1ii11iIi11i - OoooooooOO
def lisp_load_checkpoint ( ) :
 if ( lisp_checkpoint_map_cache == False ) : return
 if ( os . path . exists ( lisp_checkpoint_filename ) == False ) : return
 if 37 - 37: I11i % I1IiiI
 Iiooo000o0OoOo = open ( lisp_checkpoint_filename , "r" )
 if 32 - 32: OOooOOo + OoooooooOO . IiII . Oo0Ooo * iII111i
 i1Ii11II = 0
 for iiIIIIiI111 in Iiooo000o0OoOo :
  i1Ii11II += 1
  Oo0ooo0Ooo = iiIIIIiI111 . split ( " rloc " )
  ooo0o0 = [ ] if ( Oo0ooo0Ooo [ 1 ] in [ "native-forward\n" , "\n" ] ) else Oo0ooo0Ooo [ 1 ] . split ( ", " )
  if 86 - 86: I1ii11iIi11i . iII111i + Ii1I - IiII / i11iIiiIii + OoOoOO00
  if 50 - 50: o0oOOo0O0Ooo - IiII + OoOoOO00 - II111iiii
  iiiI11II1IiIi = [ ]
  for Oo0o0o0oo in ooo0o0 :
   O0OO0O = lisp_rloc ( False )
   Oo0O = Oo0o0o0oo . split ( " " )
   O0OO0O . rloc . store_address ( Oo0O [ 0 ] )
   O0OO0O . priority = int ( Oo0O [ 1 ] )
   O0OO0O . weight = int ( Oo0O [ 2 ] )
   iiiI11II1IiIi . append ( O0OO0O )
   if 24 - 24: I1Ii111 - IiII % I1IiiI - OoooooooOO % Ii1I
   if 56 - 56: I1ii11iIi11i
  ooooOoo000O = lisp_mapping ( "" , "" , iiiI11II1IiIi )
  if ( ooooOoo000O != None ) :
   ooooOoo000O . eid . store_prefix ( Oo0ooo0Ooo [ 0 ] )
   ooooOoo000O . checkpoint_entry = True
   ooooOoo000O . map_cache_ttl = LISP_NMR_TTL * 60
   if ( iiiI11II1IiIi == [ ] ) : ooooOoo000O . action = LISP_NATIVE_FORWARD_ACTION
   ooooOoo000O . add_cache ( )
   continue
   if 40 - 40: OoooooooOO
   if 100 - 100: IiII - I11i
  i1Ii11II -= 1
  if 79 - 79: iII111i % O0
  if 73 - 73: Oo0Ooo
 Iiooo000o0OoOo . close ( )
 lprint ( "{} {} map-cache entries from file '{}'" . format (
 bold ( "Loaded" , False ) , i1Ii11II , lisp_checkpoint_filename ) )
 return
 if 13 - 13: OOooOOo - ooOoO0o
 if 8 - 8: I1Ii111 % oO0o
 if 19 - 19: O0 + OoO0O00 - i1IIi % OoOoOO00 / Oo0Ooo + OoooooooOO
 if 93 - 93: i11iIiiIii % OOooOOo . I11i * ooOoO0o
 if 90 - 90: OoO0O00
 if 54 - 54: OOooOOo + Oo0Ooo * o0oOOo0O0Ooo - iIii1I11I1II1 * ooOoO0o
 if 76 - 76: i11iIiiIii * I1IiiI - IiII . o0oOOo0O0Ooo % iII111i . i11iIiiIii
 if 69 - 69: O0 + o0oOOo0O0Ooo / ooOoO0o
 if 7 - 7: Ii1I . Ii1I . iIii1I11I1II1 / ooOoO0o
 if 70 - 70: O0
 if 42 - 42: I1Ii111 + OoooooooOO + I11i
 if 48 - 48: Oo0Ooo . IiII / ooOoO0o + I11i
 if 40 - 40: I1IiiI + I1ii11iIi11i * I1IiiI % Ii1I
 if 27 - 27: O0 / Oo0Ooo . oO0o
def lisp_write_checkpoint_entry ( checkpoint_list , mc ) :
 if ( lisp_checkpoint_map_cache == False ) : return
 if 34 - 34: I1Ii111 % Ii1I / Oo0Ooo % ooOoO0o / i11iIiiIii * I1IiiI
 iiIIIIiI111 = "{} rloc " . format ( mc . eid . print_prefix ( ) )
 if 36 - 36: i11iIiiIii * i1IIi % iII111i . Oo0Ooo
 for O0OO0O in mc . rloc_set :
  if ( O0OO0O . rloc . is_null ( ) ) : continue
  iiIIIIiI111 += "{} {} {}, " . format ( O0OO0O . rloc . print_address_no_iid ( ) ,
 O0OO0O . priority , O0OO0O . weight )
  if 54 - 54: o0oOOo0O0Ooo % i1IIi % I1ii11iIi11i . o0oOOo0O0Ooo / OoOoOO00
  if 55 - 55: O0 / OoooooooOO % Ii1I * O0 + iIii1I11I1II1 . iIii1I11I1II1
 if ( mc . rloc_set != [ ] ) :
  iiIIIIiI111 = iiIIIIiI111 [ 0 : - 2 ]
 elif ( mc . action == LISP_NATIVE_FORWARD_ACTION ) :
  iiIIIIiI111 += "native-forward"
  if 55 - 55: Ii1I . OoooooooOO % Ii1I . IiII
  if 67 - 67: oO0o
 checkpoint_list . append ( iiIIIIiI111 )
 return
 if 12 - 12: I1IiiI + OoooooooOO
 if 25 - 25: iIii1I11I1II1 - I1IiiI . i11iIiiIii + ooOoO0o
 if 19 - 19: OoooooooOO / IiII
 if 40 - 40: OoOoOO00 / OoooooooOO * iIii1I11I1II1 / i1IIi . OoooooooOO
 if 88 - 88: I1IiiI % I1IiiI / II111iiii - IiII
 if 72 - 72: OoO0O00 - I1ii11iIi11i . Oo0Ooo / OoO0O00
 if 86 - 86: i11iIiiIii - oO0o . i11iIiiIii
def lisp_check_dp_socket ( ) :
 oO0O0oooo = lisp_ipc_dp_socket_name
 if ( os . path . exists ( oO0O0oooo ) == False ) :
  IiiiiI1i1iiIiIi = bold ( "does not exist" , False )
  lprint ( "Socket '{}' {}" . format ( oO0O0oooo , IiiiiI1i1iiIiIi ) )
  return ( False )
  if 74 - 74: o0oOOo0O0Ooo
 return ( True )
 if 15 - 15: oO0o % Oo0Ooo * i1IIi / OoO0O00 . iIii1I11I1II1 - O0
 if 20 - 20: ooOoO0o + Oo0Ooo - Oo0Ooo
 if 2 - 2: i1IIi - IiII . I1ii11iIi11i / i1IIi
 if 92 - 92: ooOoO0o - iII111i
 if 69 - 69: iII111i
 if 48 - 48: O0 + o0oOOo0O0Ooo . oO0o - IiII * OoooooooOO . OoO0O00
 if 63 - 63: oO0o * OoO0O00 * oO0o
def lisp_write_to_dp_socket ( entry ) :
 try :
  i11i11 = json . dumps ( entry )
  oO0Ii1Ii = bold ( "Write IPC" , False )
  lprint ( "{} record to named socket: '{}'" . format ( oO0Ii1Ii , i11i11 ) )
  lisp_ipc_dp_socket . sendto ( i11i11 , lisp_ipc_dp_socket_name )
 except :
  lprint ( "Failed to write IPC record to named socket: '{}'" . format ( i11i11 ) )
  if 20 - 20: I1Ii111 . II111iiii % II111iiii
 return
 if 79 - 79: II111iiii . I11i + o0oOOo0O0Ooo % I1ii11iIi11i + I1ii11iIi11i
 if 4 - 4: I1ii11iIi11i % OoooooooOO
 if 43 - 43: IiII - I1Ii111 % ooOoO0o
 if 49 - 49: OoOoOO00
 if 43 - 43: I1Ii111 - Oo0Ooo % i1IIi . II111iiii
 if 80 - 80: IiII . iII111i + I1Ii111 + iII111i % Oo0Ooo
 if 98 - 98: i11iIiiIii . II111iiii + OoOoOO00
 if 25 - 25: I1IiiI + i11iIiiIii . I1Ii111 - I1ii11iIi11i
 if 67 - 67: OOooOOo - OOooOOo * I1IiiI - II111iiii . i1IIi + Oo0Ooo
def lisp_write_ipc_keys ( rloc ) :
 ooOOo0o = rloc . rloc . print_address_no_iid ( )
 Iiiii = rloc . translated_port
 if ( Iiiii != 0 ) : ooOOo0o += ":" + str ( Iiiii )
 if ( lisp_rloc_probe_list . has_key ( ooOOo0o ) == False ) : return
 if 97 - 97: O0 / i11iIiiIii - o0oOOo0O0Ooo - OoOoOO00 . oO0o
 for Oo0O , Oo0ooo0Ooo , o0 in lisp_rloc_probe_list [ ooOOo0o ] :
  ooooOoo000O = lisp_map_cache . lookup_cache ( Oo0ooo0Ooo , True )
  if ( ooooOoo000O == None ) : continue
  lisp_write_ipc_map_cache ( True , ooooOoo000O )
  if 77 - 77: oO0o * oO0o . OoOoOO00 . i1IIi
 return
 if 90 - 90: OOooOOo . Ii1I . II111iiii + Ii1I
 if 2 - 2: I1Ii111 * OOooOOo + II111iiii - OoOoOO00
 if 94 - 94: Ii1I - iII111i . I1ii11iIi11i - Oo0Ooo % o0oOOo0O0Ooo + I1Ii111
 if 58 - 58: oO0o . ooOoO0o . I1IiiI . Oo0Ooo * iIii1I11I1II1 - iII111i
 if 96 - 96: OOooOOo % o0oOOo0O0Ooo / iIii1I11I1II1
 if 60 - 60: i1IIi / iIii1I11I1II1 + I11i % iII111i
 if 64 - 64: I11i . i11iIiiIii / iIii1I11I1II1 . I11i
def lisp_write_ipc_map_cache ( add_or_delete , mc , dont_send = False ) :
 if ( lisp_i_am_etr ) : return
 if ( lisp_ipc_dp_socket == None ) : return
 if ( lisp_check_dp_socket ( ) == False ) : return
 if 73 - 73: OoO0O00 % iIii1I11I1II1 + IiII * I1Ii111 % II111iiii
 if 20 - 20: I11i % I1ii11iIi11i . OoO0O00 % OoOoOO00
 if 84 - 84: OoooooooOO / i11iIiiIii . IiII / I1IiiI
 if 62 - 62: iII111i - I1IiiI + OoooooooOO
 Oo0oo0oOO0oOo = "add" if add_or_delete else "delete"
 iiIIIIiI111 = { "type" : "map-cache" , "opcode" : Oo0oo0oOO0oOo }
 if 59 - 59: iIii1I11I1II1 + i11iIiiIii * oO0o . Oo0Ooo . I1Ii111
 O0OOo0OO0oOo = ( mc . group . is_null ( ) == False )
 if ( O0OOo0OO0oOo ) :
  iiIIIIiI111 [ "eid-prefix" ] = mc . group . print_prefix_no_iid ( )
  iiIIIIiI111 [ "rles" ] = [ ]
 else :
  iiIIIIiI111 [ "eid-prefix" ] = mc . eid . print_prefix_no_iid ( )
  iiIIIIiI111 [ "rlocs" ] = [ ]
  if 49 - 49: II111iiii
 iiIIIIiI111 [ "instance-id" ] = str ( mc . eid . instance_id )
 if 99 - 99: Oo0Ooo . OOooOOo
 if ( O0OOo0OO0oOo ) :
  if ( len ( mc . rloc_set ) >= 1 and mc . rloc_set [ 0 ] . rle ) :
   for I1I1iiI in mc . rloc_set [ 0 ] . rle . rle_forwarding_list :
    iIiIi1iI11iiI = I1I1iiI . address . print_address_no_iid ( )
    Iiiii = str ( 4341 ) if I1I1iiI . translated_port == 0 else str ( I1I1iiI . translated_port )
    if 85 - 85: OoOoOO00 . IiII + oO0o - II111iiii
    Oo0O = { "rle" : iIiIi1iI11iiI , "port" : Iiiii }
    i1iIII1i , oo0oO0OoO00 = I1I1iiI . get_encap_keys ( )
    Oo0O = lisp_build_json_keys ( Oo0O , i1iIII1i , oo0oO0OoO00 , "encrypt-key" )
    iiIIIIiI111 [ "rles" ] . append ( Oo0O )
    if 89 - 89: Ii1I / Oo0Ooo * o0oOOo0O0Ooo / OoO0O00 + I11i
    if 4 - 4: I11i
 else :
  for Oo0o0o0oo in mc . rloc_set :
   if ( Oo0o0o0oo . rloc . is_ipv4 ( ) == False and Oo0o0o0oo . rloc . is_ipv6 ( ) == False ) :
    continue
    if 59 - 59: OoOoOO00 * I1ii11iIi11i / I1IiiI * II111iiii + OoOoOO00
   if ( Oo0o0o0oo . up_state ( ) == False ) : continue
   if 6 - 6: OoOoOO00 % oO0o + I11i * Ii1I
   Iiiii = str ( 4341 ) if Oo0o0o0oo . translated_port == 0 else str ( Oo0o0o0oo . translated_port )
   if 13 - 13: I1ii11iIi11i / Oo0Ooo - I1Ii111 * OoOoOO00
   Oo0O = { "rloc" : Oo0o0o0oo . rloc . print_address_no_iid ( ) , "priority" :
 str ( Oo0o0o0oo . priority ) , "weight" : str ( Oo0o0o0oo . weight ) , "port" :
 Iiiii }
   i1iIII1i , oo0oO0OoO00 = Oo0o0o0oo . get_encap_keys ( )
   Oo0O = lisp_build_json_keys ( Oo0O , i1iIII1i , oo0oO0OoO00 , "encrypt-key" )
   iiIIIIiI111 [ "rlocs" ] . append ( Oo0O )
   if 47 - 47: IiII
   if 76 - 76: iII111i / II111iiii / I11i
   if 62 - 62: I1ii11iIi11i
 if ( dont_send == False ) : lisp_write_to_dp_socket ( iiIIIIiI111 )
 return ( iiIIIIiI111 )
 if 100 - 100: iII111i / ooOoO0o / IiII % II111iiii
 if 6 - 6: OoooooooOO - I1IiiI + OoooooooOO
 if 89 - 89: oO0o % Oo0Ooo . O0 . ooOoO0o
 if 46 - 46: IiII * I11i - OoO0O00 - Ii1I
 if 93 - 93: iIii1I11I1II1 / o0oOOo0O0Ooo - I11i - OOooOOo % ooOoO0o
 if 16 - 16: ooOoO0o * o0oOOo0O0Ooo - IiII + I1ii11iIi11i / o0oOOo0O0Ooo - O0
 if 71 - 71: i1IIi
def lisp_write_ipc_decap_key ( rloc_addr , keys ) :
 if ( lisp_i_am_itr ) : return
 if ( lisp_ipc_dp_socket == None ) : return
 if ( lisp_check_dp_socket ( ) == False ) : return
 if 79 - 79: iII111i * O0 / Ii1I / O0 % i1IIi
 if 52 - 52: OoooooooOO % oO0o - I11i % OoOoOO00 . II111iiii
 if 62 - 62: Ii1I . I1ii11iIi11i . iII111i + I11i * o0oOOo0O0Ooo
 if 56 - 56: oO0o * iIii1I11I1II1 . II111iiii - II111iiii + II111iiii - i11iIiiIii
 if ( keys == None or len ( keys ) == 0 or keys [ 1 ] == None ) : return
 if 79 - 79: iII111i
 i1iIII1i = keys [ 1 ] . encrypt_key
 oo0oO0OoO00 = keys [ 1 ] . icv_key
 if 29 - 29: Ii1I * I1Ii111 / OoO0O00 - O0 - i11iIiiIii * I1IiiI
 if 2 - 2: OoOoOO00 . I1ii11iIi11i * I1ii11iIi11i
 if 42 - 42: OoO0O00 . OoO0O00 + II111iiii - IiII - OOooOOo * Oo0Ooo
 if 47 - 47: oO0o - OoooooooOO + iII111i
 OO0oOOO00 = rloc_addr . split ( ":" )
 if ( len ( OO0oOOO00 ) == 1 ) :
  iiIIIIiI111 = { "type" : "decap-keys" , "rloc" : OO0oOOO00 [ 0 ] }
 else :
  iiIIIIiI111 = { "type" : "decap-keys" , "rloc" : OO0oOOO00 [ 0 ] , "port" : OO0oOOO00 [ 1 ] }
  if 5 - 5: ooOoO0o . OoO0O00
 iiIIIIiI111 = lisp_build_json_keys ( iiIIIIiI111 , i1iIII1i , oo0oO0OoO00 , "decrypt-key" )
 if 40 - 40: iII111i
 lisp_write_to_dp_socket ( iiIIIIiI111 )
 return
 if 87 - 87: IiII / II111iiii
 if 44 - 44: OoO0O00 . I1Ii111 - OoooooooOO * OoOoOO00 . OoO0O00
 if 84 - 84: OOooOOo . OOooOOo . oO0o % iII111i * Oo0Ooo - iIii1I11I1II1
 if 4 - 4: iII111i
 if 23 - 23: i1IIi . iIii1I11I1II1 / I1IiiI . OoOoOO00 . iII111i / IiII
 if 65 - 65: Ii1I + IiII + I11i / I1Ii111 % iIii1I11I1II1
 if 17 - 17: I1ii11iIi11i * OOooOOo % II111iiii
 if 30 - 30: I1Ii111 . Ii1I . Oo0Ooo / OOooOOo * OoooooooOO / I1ii11iIi11i
def lisp_build_json_keys ( entry , ekey , ikey , key_type ) :
 if ( ekey == None ) : return ( entry )
 if 41 - 41: i1IIi
 entry [ "keys" ] = [ ]
 Iiii11 = { "key-id" : "1" , key_type : ekey , "icv-key" : ikey }
 entry [ "keys" ] . append ( Iiii11 )
 return ( entry )
 if 75 - 75: o0oOOo0O0Ooo . I1Ii111 - I1Ii111 % Ii1I * OoooooooOO
 if 99 - 99: OOooOOo + o0oOOo0O0Ooo - OOooOOo . i1IIi
 if 86 - 86: Ii1I % oO0o - i11iIiiIii - O0 + IiII + iII111i
 if 100 - 100: OoO0O00 . Oo0Ooo
 if 29 - 29: OoO0O00
 if 34 - 34: O0 - o0oOOo0O0Ooo % OOooOOo . OoO0O00 % IiII
 if 63 - 63: O0 % iIii1I11I1II1 . o0oOOo0O0Ooo . I1IiiI * Ii1I % i1IIi
def lisp_write_ipc_database_mappings ( ephem_port ) :
 if ( lisp_i_am_etr == False ) : return
 if ( lisp_ipc_dp_socket == None ) : return
 if ( lisp_check_dp_socket ( ) == False ) : return
 if 47 - 47: II111iiii * I1ii11iIi11i
 if 70 - 70: I1ii11iIi11i - o0oOOo0O0Ooo
 if 71 - 71: I1ii11iIi11i * i1IIi
 if 67 - 67: I1ii11iIi11i % OoOoOO00 . iII111i / Ii1I . I1IiiI
 iiIIIIiI111 = { "type" : "database-mappings" , "database-mappings" : [ ] }
 if 48 - 48: IiII + II111iiii . I1IiiI % o0oOOo0O0Ooo
 if 57 - 57: OOooOOo . I11i % OoOoOO00
 if 68 - 68: iIii1I11I1II1 % I1ii11iIi11i % II111iiii / O0 + iII111i
 if 78 - 78: iII111i - OOooOOo / I1Ii111
 for iIiIIi1i in lisp_db_list :
  if ( iIiIIi1i . eid . is_ipv4 ( ) == False and iIiIIi1i . eid . is_ipv6 ( ) == False ) : continue
  I1IiIIIIii1 = { "instance-id" : str ( iIiIIi1i . eid . instance_id ) ,
 "eid-prefix" : iIiIIi1i . eid . print_prefix_no_iid ( ) }
  iiIIIIiI111 [ "database-mappings" ] . append ( I1IiIIIIii1 )
  if 99 - 99: o0oOOo0O0Ooo . oO0o
 lisp_write_to_dp_socket ( iiIIIIiI111 )
 if 9 - 9: oO0o % OoooooooOO
 if 62 - 62: OoO0O00 / OoOoOO00 / I1Ii111 + Oo0Ooo - Ii1I
 if 72 - 72: OoO0O00 + I11i / iII111i % OOooOOo
 if 5 - 5: oO0o % OOooOOo
 if 95 - 95: OoOoOO00 + OoooooooOO - O0 + o0oOOo0O0Ooo
 iiIIIIiI111 = { "type" : "etr-nat-port" , "port" : ephem_port }
 lisp_write_to_dp_socket ( iiIIIIiI111 )
 return
 if 88 - 88: i11iIiiIii . iIii1I11I1II1
 if 57 - 57: Ii1I * iIii1I11I1II1
 if 92 - 92: Ii1I % Ii1I . I11i / i1IIi % Oo0Ooo
 if 25 - 25: o0oOOo0O0Ooo - OoO0O00 - OoOoOO00 - ooOoO0o
 if 28 - 28: OOooOOo * ooOoO0o * OoooooooOO % IiII
 if 9 - 9: OoooooooOO
 if 92 - 92: I1Ii111 + O0 + OoO0O00 % IiII
def lisp_write_ipc_interfaces ( ) :
 if ( lisp_i_am_etr ) : return
 if ( lisp_ipc_dp_socket == None ) : return
 if ( lisp_check_dp_socket ( ) == False ) : return
 if 31 - 31: Ii1I / Oo0Ooo - I1IiiI - I11i - i11iIiiIii
 if 45 - 45: ooOoO0o - IiII / OoO0O00 / IiII
 if 63 - 63: ooOoO0o . i11iIiiIii + iII111i . OoO0O00 / ooOoO0o % iII111i
 if 23 - 23: iIii1I11I1II1 - ooOoO0o / I11i * I11i
 iiIIIIiI111 = { "type" : "interfaces" , "interfaces" : [ ] }
 if 62 - 62: OOooOOo - I1IiiI * oO0o + O0 / ooOoO0o * iIii1I11I1II1
 for II111IiiiI1 in lisp_myinterfaces . values ( ) :
  if ( II111IiiiI1 . instance_id == None ) : continue
  I1IiIIIIii1 = { "interface" : II111IiiiI1 . device ,
 "instance-id" : str ( II111IiiiI1 . instance_id ) }
  iiIIIIiI111 [ "interfaces" ] . append ( I1IiIIIIii1 )
  if 25 - 25: I1Ii111 % Oo0Ooo + OoO0O00 % OOooOOo
  if 85 - 85: I1IiiI . i11iIiiIii - ooOoO0o * I11i * OoOoOO00 * I11i
 lisp_write_to_dp_socket ( iiIIIIiI111 )
 return
 if 29 - 29: I1Ii111 * I1Ii111 . iII111i + o0oOOo0O0Ooo
 if 57 - 57: I1Ii111 - IiII
 if 89 - 89: oO0o + iII111i
 if 52 - 52: OOooOOo % O0 * I1ii11iIi11i . I1ii11iIi11i / IiII
 if 7 - 7: II111iiii
 if 7 - 7: iIii1I11I1II1 . O0 + Ii1I % I1IiiI * O0 + OoO0O00
 if 3 - 3: Oo0Ooo * OoooooooOO * oO0o % OoOoOO00 * OoOoOO00 . ooOoO0o
 if 16 - 16: ooOoO0o / o0oOOo0O0Ooo - O0 * I1IiiI
 if 13 - 13: iII111i . iII111i % O0 % o0oOOo0O0Ooo
 if 99 - 99: OoO0O00 - OoOoOO00 + OoO0O00
 if 67 - 67: I1Ii111
 if 31 - 31: OoO0O00 * Oo0Ooo % O0 * II111iiii + ooOoO0o * I1IiiI
 if 77 - 77: ooOoO0o
 if 98 - 98: I1Ii111 + I1ii11iIi11i % OoO0O00 * Ii1I + iII111i
def lisp_parse_auth_key ( value ) :
 OOOo0O = value . split ( "[" )
 i1i1 = { }
 if ( len ( OOOo0O ) == 1 ) :
  i1i1 [ 0 ] = value
  return ( i1i1 )
  if 2 - 2: i1IIi
  if 60 - 60: OOooOOo + I1ii11iIi11i / OoOoOO00 * i1IIi / O0
 for IIiIi1IIiI1i in OOOo0O :
  if ( IIiIi1IIiI1i == "" ) : continue
  oo0OOo0O = IIiIi1IIiI1i . find ( "]" )
  OoooOOo0oOO = IIiIi1IIiI1i [ 0 : oo0OOo0O ]
  try : OoooOOo0oOO = int ( OoooOOo0oOO )
  except : return
  if 24 - 24: Oo0Ooo . IiII % o0oOOo0O0Ooo . OOooOOo . I1IiiI + I1Ii111
  i1i1 [ OoooOOo0oOO ] = IIiIi1IIiI1i [ oo0OOo0O + 1 : : ]
  if 51 - 51: Oo0Ooo * I11i % i1IIi / iIii1I11I1II1 . OoooooooOO
 return ( i1i1 )
 if 5 - 5: iIii1I11I1II1 % oO0o - II111iiii - OoOoOO00 / i1IIi
 if 20 - 20: II111iiii * OoOoOO00 . Ii1I . I1ii11iIi11i
 if 91 - 91: oO0o / OoOoOO00 % I1Ii111 % I1Ii111 / ooOoO0o
 if 39 - 39: OoO0O00 + OoO0O00 * iIii1I11I1II1 + I11i / OoO0O00
 if 82 - 82: I1IiiI / I1IiiI - iII111i % I1ii11iIi11i
 if 84 - 84: iII111i
 if 24 - 24: oO0o - OoO0O00 + I1Ii111
 if 98 - 98: iII111i . oO0o - O0 % I1IiiI . I1ii11iIi11i / i1IIi
 if 72 - 72: I1IiiI / Oo0Ooo % IiII - O0 / O0 * O0
 if 83 - 83: O0 / I1Ii111 - OoooooooOO
 if 42 - 42: Ii1I / i1IIi - IiII / I1Ii111
 if 39 - 39: OoooooooOO
 if 4 - 4: iIii1I11I1II1 - Oo0Ooo / OOooOOo % OoooooooOO . Oo0Ooo - Oo0Ooo
 if 41 - 41: II111iiii . o0oOOo0O0Ooo
 if 92 - 92: Ii1I - O0 - i11iIiiIii + IiII % I1Ii111 + II111iiii
 if 71 - 71: ooOoO0o * I1Ii111 + i11iIiiIii + i1IIi . I1IiiI
def lisp_reassemble ( packet ) :
 ooO = socket . ntohs ( struct . unpack ( "H" , packet [ 6 : 8 ] ) [ 0 ] )
 if 15 - 15: OoO0O00
 if 37 - 37: OoO0O00 . OoooooooOO - OOooOOo
 if 34 - 34: o0oOOo0O0Ooo + iIii1I11I1II1 / o0oOOo0O0Ooo / ooOoO0o
 if 53 - 53: II111iiii / iIii1I11I1II1
 if ( ooO == 0 or ooO == 0x4000 ) : return ( packet )
 if 25 - 25: I1Ii111
 if 58 - 58: OoOoOO00 * i1IIi
 if 20 - 20: IiII
 if 81 - 81: I1Ii111 . i1IIi / o0oOOo0O0Ooo
 i1111I = socket . ntohs ( struct . unpack ( "H" , packet [ 4 : 6 ] ) [ 0 ] )
 iiii1Iiii = socket . ntohs ( struct . unpack ( "H" , packet [ 2 : 4 ] ) [ 0 ] )
 if 57 - 57: ooOoO0o
 O0OOOoOOOO0 = ( ooO & 0x2000 == 0 and ( ooO & 0x1fff ) != 0 )
 iiIIIIiI111 = [ ( ooO & 0x1fff ) * 8 , iiii1Iiii - 20 , packet , O0OOOoOOOO0 ]
 if 9 - 9: o0oOOo0O0Ooo % i1IIi / OoO0O00 / OOooOOo + I1Ii111
 if 80 - 80: Oo0Ooo . iIii1I11I1II1 . OoooooooOO % iII111i . oO0o
 if 10 - 10: i11iIiiIii * OoooooooOO . i11iIiiIii
 if 35 - 35: OOooOOo * OOooOOo + o0oOOo0O0Ooo / i1IIi - I11i
 if 12 - 12: I1ii11iIi11i - i11iIiiIii + I1IiiI . Oo0Ooo
 if 26 - 26: oO0o + I1Ii111 + IiII * o0oOOo0O0Ooo . oO0o
 if 95 - 95: OoOoOO00 . I1Ii111 / Ii1I . I1Ii111 % OoO0O00
 if 16 - 16: Ii1I / I1IiiI / I1IiiI - OoooooooOO
 if ( ooO == 0x2000 ) :
  O00o , o0o0ooOo00 = struct . unpack ( "HH" , packet [ 20 : 24 ] )
  O00o = socket . ntohs ( O00o )
  o0o0ooOo00 = socket . ntohs ( o0o0ooOo00 )
  if ( o0o0ooOo00 not in [ 4341 , 8472 , 4789 ] and O00o != 4341 ) :
   lisp_reassembly_queue [ i1111I ] = [ ]
   iiIIIIiI111 [ 2 ] = None
   if 13 - 13: OOooOOo / OoooooooOO
   if 7 - 7: II111iiii - ooOoO0o
   if 72 - 72: Ii1I
   if 27 - 27: ooOoO0o / IiII + OoO0O00 + Ii1I % I1Ii111
   if 86 - 86: O0 % i11iIiiIii - Ii1I * oO0o % OOooOOo * i1IIi
   if 87 - 87: II111iiii
 if ( lisp_reassembly_queue . has_key ( i1111I ) == False ) :
  lisp_reassembly_queue [ i1111I ] = [ ]
  if 53 - 53: OoOoOO00 * i11iIiiIii / I1Ii111
  if 100 - 100: ooOoO0o + I1IiiI * oO0o + ooOoO0o
  if 24 - 24: i11iIiiIii + ooOoO0o
  if 80 - 80: IiII % I11i % oO0o
  if 97 - 97: i1IIi * i11iIiiIii / Ii1I - I1IiiI % IiII
 oo0Oo00oo0OoO0O0 = lisp_reassembly_queue [ i1111I ]
 if 38 - 38: IiII . OoO0O00 * IiII % ooOoO0o * Ii1I / ooOoO0o
 if 56 - 56: O0 / OoooooooOO / OoOoOO00
 if 19 - 19: o0oOOo0O0Ooo / i11iIiiIii . i1IIi / Oo0Ooo / I1Ii111
 if 83 - 83: iII111i % o0oOOo0O0Ooo * OoOoOO00
 if 49 - 49: II111iiii / OoO0O00
 if ( len ( oo0Oo00oo0OoO0O0 ) == 1 and oo0Oo00oo0OoO0O0 [ 0 ] [ 2 ] == None ) :
  dprint ( "Drop non-LISP encapsulated fragment 0x{}" . format ( lisp_hex_string ( i1111I ) . zfill ( 4 ) ) )
  if 69 - 69: Ii1I * II111iiii
  return ( None )
  if 24 - 24: I1Ii111 * I1ii11iIi11i . OOooOOo . I1IiiI - I1ii11iIi11i
  if 56 - 56: I1IiiI * Oo0Ooo + OoO0O00 - oO0o * I1Ii111
  if 68 - 68: ooOoO0o * i11iIiiIii * OOooOOo % iII111i
  if 10 - 10: Ii1I / Oo0Ooo - i1IIi
  if 11 - 11: I11i * iII111i
 oo0Oo00oo0OoO0O0 . append ( iiIIIIiI111 )
 oo0Oo00oo0OoO0O0 = sorted ( oo0Oo00oo0OoO0O0 )
 if 28 - 28: II111iiii + IiII / Oo0Ooo * I1IiiI - OOooOOo
 if 2 - 2: oO0o + I11i / I1Ii111 . I11i
 if 59 - 59: Ii1I
 if 47 - 47: iII111i % iII111i
 iIiIi1iI11iiI = lisp_address ( LISP_AFI_IPV4 , "" , 32 , 0 )
 iIiIi1iI11iiI . address = socket . ntohl ( struct . unpack ( "I" , packet [ 12 : 16 ] ) [ 0 ] )
 OOoO0 = iIiIi1iI11iiI . print_address_no_iid ( )
 iIiIi1iI11iiI . address = socket . ntohl ( struct . unpack ( "I" , packet [ 16 : 20 ] ) [ 0 ] )
 iIi1IooOoOOoo0 = iIiIi1iI11iiI . print_address_no_iid ( )
 iIiIi1iI11iiI = red ( "{} -> {}" . format ( OOoO0 , iIi1IooOoOOoo0 ) , False )
 if 33 - 33: OOooOOo % OoO0O00 - O0 + I1IiiI + i11iIiiIii
 dprint ( "{}{} fragment, RLOCs: {}, packet 0x{}, frag-offset: 0x{}" . format ( bold ( "Received" , False ) , " non-LISP encapsulated" if iiIIIIiI111 [ 2 ] == None else "" , iIiIi1iI11iiI , lisp_hex_string ( i1111I ) . zfill ( 4 ) ,
 # iIii1I11I1II1 - iII111i - oO0o + Oo0Ooo . Ii1I / i11iIiiIii
 # ooOoO0o - I1Ii111
 lisp_hex_string ( ooO ) . zfill ( 4 ) ) )
 if 97 - 97: OOooOOo
 if 87 - 87: iII111i
 if 73 - 73: II111iiii
 if 2 - 2: i1IIi % iII111i . oO0o / II111iiii * I1IiiI
 if 17 - 17: O0 + iII111i + oO0o / iIii1I11I1II1 % oO0o
 if ( oo0Oo00oo0OoO0O0 [ 0 ] [ 0 ] != 0 or oo0Oo00oo0OoO0O0 [ - 1 ] [ 3 ] == False ) : return ( None )
 O00oooooOo0OO = oo0Oo00oo0OoO0O0 [ 0 ]
 for O0O in oo0Oo00oo0OoO0O0 [ 1 : : ] :
  ooO = O0O [ 0 ]
  o00oO0O0O0 , IiI1IIiIiI1I = O00oooooOo0OO [ 0 ] , O00oooooOo0OO [ 1 ]
  if ( o00oO0O0O0 + IiI1IIiIiI1I != ooO ) : return ( None )
  O00oooooOo0OO = O0O
  if 78 - 78: oO0o - II111iiii . II111iiii * I1Ii111 % O0 - iII111i
 lisp_reassembly_queue . pop ( i1111I )
 if 59 - 59: Oo0Ooo - IiII
 if 6 - 6: OOooOOo - I1IiiI . IiII
 if 40 - 40: II111iiii
 if 13 - 13: OoOoOO00
 if 23 - 23: Oo0Ooo / II111iiii % OOooOOo % iII111i - Oo0Ooo / OoO0O00
 packet = oo0Oo00oo0OoO0O0 [ 0 ] [ 2 ]
 for O0O in oo0Oo00oo0OoO0O0 [ 1 : : ] : packet += O0O [ 2 ] [ 20 : : ]
 if 7 - 7: Ii1I / I11i / II111iiii % I11i * I11i + iIii1I11I1II1
 dprint ( "{} fragments arrived for packet 0x{}, length {}" . format ( bold ( "All" , False ) , lisp_hex_string ( i1111I ) . zfill ( 4 ) , len ( packet ) ) )
 if 6 - 6: iIii1I11I1II1 * oO0o - iIii1I11I1II1 . O0 . O0
 if 96 - 96: I1Ii111 * II111iiii % i11iIiiIii - oO0o
 if 32 - 32: i11iIiiIii * o0oOOo0O0Ooo . OoooooooOO / O0
 if 14 - 14: i11iIiiIii . I1Ii111 % I1ii11iIi11i . I1ii11iIi11i % IiII
 if 93 - 93: iIii1I11I1II1 / IiII
 OOOOO000oo0 = socket . htons ( len ( packet ) )
 oooooOOo0Oo = packet [ 0 : 2 ] + struct . pack ( "H" , OOOOO000oo0 ) + packet [ 4 : 6 ] + struct . pack ( "H" , 0 ) + packet [ 8 : 10 ] + struct . pack ( "H" , 0 ) + packet [ 12 : 20 ]
 if 91 - 91: i11iIiiIii % ooOoO0o - iII111i * I1Ii111 . i11iIiiIii
 if 1 - 1: IiII + iIii1I11I1II1 * I1ii11iIi11i - IiII - i1IIi
 oooooOOo0Oo = lisp_ip_checksum ( oooooOOo0Oo )
 return ( oooooOOo0Oo + packet [ 20 : : ] )
 if 75 - 75: II111iiii * o0oOOo0O0Ooo / I1ii11iIi11i
 if 46 - 46: OOooOOo
 if 67 - 67: OoO0O00 . I11i % OOooOOo + Oo0Ooo
 if 40 - 40: OoO0O00 / I11i % iIii1I11I1II1 - ooOoO0o
 if 51 - 51: Oo0Ooo % iIii1I11I1II1 % oO0o + o0oOOo0O0Ooo
 if 32 - 32: I1Ii111 * I1IiiI + Ii1I
 if 30 - 30: OoooooooOO / I1IiiI . iIii1I11I1II1 / ooOoO0o
 if 20 - 20: OoooooooOO * OOooOOo
def lisp_get_crypto_decap_lookup_key ( addr , port ) :
 ooOOo0o = addr . print_address_no_iid ( ) + ":" + str ( port )
 if ( lisp_crypto_keys_by_rloc_decap . has_key ( ooOOo0o ) ) : return ( ooOOo0o )
 if 77 - 77: Ii1I - OoooooooOO . OoOoOO00
 ooOOo0o = addr . print_address_no_iid ( )
 if ( lisp_crypto_keys_by_rloc_decap . has_key ( ooOOo0o ) ) : return ( ooOOo0o )
 if 93 - 93: OoooooooOO / I1Ii111
 if 91 - 91: I1Ii111
 if 18 - 18: ooOoO0o * I11i
 if 53 - 53: I11i . i11iIiiIii - iIii1I11I1II1 / I1Ii111
 if 86 - 86: i1IIi % OoO0O00 - OoooooooOO
 for OO0Ii1iii1iIIII in lisp_crypto_keys_by_rloc_decap :
  ii1iI1iI1 = OO0Ii1iii1iIIII . split ( ":" )
  if ( len ( ii1iI1iI1 ) == 1 ) : continue
  ii1iI1iI1 = ii1iI1iI1 [ 0 ] if len ( ii1iI1iI1 ) == 2 else ":" . join ( ii1iI1iI1 [ 0 : - 1 ] )
  if ( ii1iI1iI1 == ooOOo0o ) :
   i1iIi = lisp_crypto_keys_by_rloc_decap [ OO0Ii1iii1iIIII ]
   lisp_crypto_keys_by_rloc_decap [ ooOOo0o ] = i1iIi
   return ( ooOOo0o )
   if 57 - 57: O0 - I1Ii111 . IiII
   if 56 - 56: OoooooooOO
 return ( None )
 if 12 - 12: ooOoO0o
 if 97 - 97: i1IIi . Oo0Ooo
 if 81 - 81: OoOoOO00
 if 81 - 81: O0
 if 57 - 57: oO0o - o0oOOo0O0Ooo % i11iIiiIii / OoOoOO00 . iIii1I11I1II1
 if 68 - 68: iII111i
 if 59 - 59: O0 - i11iIiiIii + OoooooooOO - iII111i - Oo0Ooo . OoooooooOO
 if 60 - 60: O0 * iIii1I11I1II1 - Ii1I * II111iiii . ooOoO0o
 if 61 - 61: I1IiiI . iII111i
 if 19 - 19: iIii1I11I1II1 * Oo0Ooo - I1IiiI - I1IiiI + O0 - I1Ii111
 if 56 - 56: I1Ii111 - i1IIi + I11i . i1IIi / II111iiii * oO0o
def lisp_build_crypto_decap_lookup_key ( addr , port ) :
 addr = addr . print_address_no_iid ( )
 o0oo000o = addr + ":" + str ( port )
 if 68 - 68: OoO0O00 % I11i % IiII + Ii1I
 if ( lisp_i_am_rtr ) :
  if ( lisp_rloc_probe_list . has_key ( addr ) ) : return ( addr )
  if 86 - 86: i1IIi / O0
  if 64 - 64: I1Ii111 + O0 * IiII % OoOoOO00 % OOooOOo - iII111i
  if 73 - 73: ooOoO0o + I1IiiI % oO0o . O0
  if 18 - 18: o0oOOo0O0Ooo * I11i
  if 24 - 24: oO0o / o0oOOo0O0Ooo + i1IIi
  if 15 - 15: i11iIiiIii / O0
  for iiI in lisp_nat_state_info . values ( ) :
   for I1II1i1Ii1 in iiI :
    if ( addr == I1II1i1Ii1 . address ) : return ( o0oo000o )
    if 34 - 34: I1Ii111 . IiII % iII111i
    if 94 - 94: OOooOOo % i11iIiiIii . OOooOOo
  return ( addr )
  if 55 - 55: OoOoOO00 . OoOoOO00 % o0oOOo0O0Ooo . I11i . I1ii11iIi11i - o0oOOo0O0Ooo
 return ( o0oo000o )
 if 1 - 1: i11iIiiIii - i1IIi * oO0o - iIii1I11I1II1
 if 75 - 75: i1IIi * i11iIiiIii
 if 40 - 40: I1ii11iIi11i + OoO0O00
 if 8 - 8: i11iIiiIii - iIii1I11I1II1
 if 73 - 73: OoOoOO00
 if 25 - 25: iII111i / oO0o
 if 61 - 61: OoooooooOO . Ii1I . I11i + oO0o
def lisp_set_ttl ( lisp_socket , ttl ) :
 try :
  lisp_socket . setsockopt ( socket . SOL_IP , socket . IP_TTL , ttl )
 except :
  lprint ( "socket.setsockopt(IP_TTL) not supported" )
  pass
  if 73 - 73: II111iiii % i11iIiiIii * I1ii11iIi11i + O0
 return
 if 61 - 61: I1IiiI / OOooOOo
 if 67 - 67: OoOoOO00
 if 22 - 22: Ii1I * I1ii11iIi11i * o0oOOo0O0Ooo - I1IiiI . i11iIiiIii
 if 30 - 30: O0 / oO0o * i11iIiiIii + iIii1I11I1II1 + O0 % I1IiiI
 if 95 - 95: ooOoO0o % OOooOOo
 if 17 - 17: i1IIi + Ii1I
 if 35 - 35: iIii1I11I1II1 - Oo0Ooo - OoooooooOO % I1ii11iIi11i
def lisp_is_rloc_probe_request ( lisp_type ) :
 lisp_type = struct . unpack ( "B" , lisp_type ) [ 0 ]
 return ( lisp_type == 0x12 )
 if 27 - 27: Oo0Ooo * II111iiii - OOooOOo + o0oOOo0O0Ooo
 if 26 - 26: oO0o / I1ii11iIi11i - oO0o
 if 9 - 9: ooOoO0o * iIii1I11I1II1 * OoooooooOO
 if 13 - 13: iII111i . i11iIiiIii * o0oOOo0O0Ooo . iII111i
 if 96 - 96: Ii1I
 if 90 - 90: II111iiii
 if 93 - 93: i11iIiiIii / Ii1I * Oo0Ooo . iII111i % iII111i / IiII
def lisp_is_rloc_probe_reply ( lisp_type ) :
 lisp_type = struct . unpack ( "B" , lisp_type ) [ 0 ]
 return ( lisp_type == 0x28 )
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
 if 42 - 42: OoOoOO00 / IiII
 if 65 - 65: ooOoO0o - ooOoO0o * OoO0O00
 if 99 - 99: I11i % ooOoO0o . I1Ii111
 if 34 - 34: ooOoO0o + oO0o + II111iiii . I1Ii111 . i1IIi
 if 14 - 14: OoO0O00 . ooOoO0o - i1IIi * I1IiiI
 if 24 - 24: iIii1I11I1II1 / I1Ii111
def lisp_is_rloc_probe ( packet , rr ) :
 OOOOo00oo00O = ( struct . unpack ( "B" , packet [ 9 ] ) [ 0 ] == 17 )
 if ( OOOOo00oo00O == False ) : return ( [ packet , None , None , None ] )
 if 16 - 16: OoOoOO00 * I1Ii111 - I1IiiI / I1Ii111
 O00o = struct . unpack ( "H" , packet [ 20 : 22 ] ) [ 0 ]
 o0o0ooOo00 = struct . unpack ( "H" , packet [ 22 : 24 ] ) [ 0 ]
 OOooOOOOoo0o0 = ( socket . htons ( LISP_CTRL_PORT ) in [ O00o , o0o0ooOo00 ] )
 if ( OOooOOOOoo0o0 == False ) : return ( [ packet , None , None , None ] )
 if 10 - 10: II111iiii . O0
 if ( rr == 0 ) :
  oo00OO0Oooo = lisp_is_rloc_probe_request ( packet [ 28 ] )
  if ( oo00OO0Oooo == False ) : return ( [ packet , None , None , None ] )
 elif ( rr == 1 ) :
  oo00OO0Oooo = lisp_is_rloc_probe_reply ( packet [ 28 ] )
  if ( oo00OO0Oooo == False ) : return ( [ packet , None , None , None ] )
 elif ( rr == - 1 ) :
  oo00OO0Oooo = lisp_is_rloc_probe_request ( packet [ 28 ] )
  if ( oo00OO0Oooo == False ) :
   oo00OO0Oooo = lisp_is_rloc_probe_reply ( packet [ 28 ] )
   if ( oo00OO0Oooo == False ) : return ( [ packet , None , None , None ] )
   if 46 - 46: iIii1I11I1II1
   if 8 - 8: I1ii11iIi11i % I11i - i1IIi . Oo0Ooo * I1Ii111
   if 44 - 44: iII111i
   if 56 - 56: II111iiii / Oo0Ooo % IiII * II111iiii - iIii1I11I1II1 + ooOoO0o
   if 33 - 33: o0oOOo0O0Ooo . I11i / I1IiiI
   if 29 - 29: o0oOOo0O0Ooo - ooOoO0o
 oo = lisp_address ( LISP_AFI_IPV4 , "" , 32 , 0 )
 oo . address = socket . ntohl ( struct . unpack ( "I" , packet [ 12 : 16 ] ) [ 0 ] )
 if 59 - 59: I11i / IiII * OoO0O00 / IiII . I1Ii111
 if 82 - 82: OOooOOo . iIii1I11I1II1 + I1Ii111
 if 14 - 14: IiII . i11iIiiIii
 if 17 - 17: ooOoO0o % ooOoO0o * oO0o
 if ( oo . is_local ( ) ) : return ( [ None , None , None , None ] )
 if 8 - 8: ooOoO0o + OoO0O00 . II111iiii / iIii1I11I1II1 - OOooOOo
 if 87 - 87: iIii1I11I1II1 . IiII % I1IiiI . OoO0O00 - I1Ii111
 if 53 - 53: I1Ii111 % i11iIiiIii
 if 99 - 99: I1IiiI - i1IIi * i11iIiiIii + OoO0O00
 oo = oo . print_address_no_iid ( )
 Iiiii = socket . ntohs ( struct . unpack ( "H" , packet [ 20 : 22 ] ) [ 0 ] )
 Ii1 = struct . unpack ( "B" , packet [ 8 ] ) [ 0 ] - 1
 packet = packet [ 28 : : ]
 if 80 - 80: o0oOOo0O0Ooo . I11i % iIii1I11I1II1 + OoOoOO00
 Oo0O = bold ( "Receive(pcap)" , False )
 Iiooo000o0OoOo = bold ( "from " + oo , False )
 i111 = lisp_format_packet ( packet )
 lprint ( "{} {} bytes {} {}, packet: {}" . format ( Oo0O , len ( packet ) , Iiooo000o0OoOo , Iiiii , i111 ) )
 if 87 - 87: I1Ii111 + II111iiii / I1ii11iIi11i + OoOoOO00
 return ( [ packet , oo , Iiiii , Ii1 ] )
 if 71 - 71: I1IiiI + iIii1I11I1II1 + O0 * iII111i % IiII
 if 42 - 42: OOooOOo - I1ii11iIi11i
 if 93 - 93: I1Ii111 + OOooOOo % ooOoO0o / I1Ii111 % OOooOOo . IiII
 if 37 - 37: iII111i * oO0o / oO0o / Ii1I % I11i
 if 12 - 12: i11iIiiIii
 if 62 - 62: oO0o + OOooOOo + oO0o + I1IiiI
 if 10 - 10: IiII - Oo0Ooo % ooOoO0o
 if 38 - 38: oO0o * o0oOOo0O0Ooo . I11i % II111iiii / I11i % Ii1I
 if 19 - 19: II111iiii / i11iIiiIii * II111iiii + OoOoOO00 - OoOoOO00
 if 7 - 7: OoOoOO00 - OoO0O00 % OoOoOO00 . I1ii11iIi11i % Oo0Ooo * iII111i
 if 90 - 90: IiII - OOooOOo + iIii1I11I1II1
def lisp_ipc_write_xtr_parameters ( cp , dp ) :
 if ( lisp_ipc_dp_socket == None ) : return
 if 88 - 88: ooOoO0o . o0oOOo0O0Ooo . OOooOOo - I11i
 oOooOOoo = { "type" : "xtr-parameters" , "control-plane-logging" : cp ,
 "data-plane-logging" : dp , "rtr" : lisp_i_am_rtr }
 if 76 - 76: IiII % I1IiiI . iII111i
 lisp_write_to_dp_socket ( oOooOOoo )
 return
 if 5 - 5: ooOoO0o . oO0o - OoOoOO00 - OoooooooOO
 if 2 - 2: OOooOOo
 if 37 - 37: IiII - iIii1I11I1II1 * i11iIiiIii . ooOoO0o
 if 78 - 78: OOooOOo - I1ii11iIi11i + iII111i % OoOoOO00
 if 28 - 28: I11i + i1IIi / i11iIiiIii * OOooOOo * II111iiii
 if 78 - 78: OoO0O00 - i1IIi % I1Ii111
 if 87 - 87: I11i
 if 37 - 37: iII111i . I1Ii111 - iII111i - I11i - iIii1I11I1II1 - II111iiii
def lisp_external_data_plane ( ) :
 iiI1i = 'egrep "ipc-data-plane = yes" ./lisp.config'
 if ( commands . getoutput ( iiI1i ) != "" ) : return ( True )
 if 80 - 80: I1Ii111 % O0 - IiII / II111iiii + i1IIi
 if ( os . getenv ( "LISP_RUN_LISP_XTR" ) != None ) : return ( True )
 return ( False )
 if 4 - 4: OOooOOo + II111iiii
 if 1 - 1: OoooooooOO * I1Ii111 - I11i / IiII
 if 43 - 43: i11iIiiIii * I1IiiI
 if 48 - 48: Oo0Ooo - OOooOOo / iII111i % I1ii11iIi11i . OoOoOO00
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
def lisp_process_data_plane_restart ( do_clear = False ) :
 os . system ( "touch ./lisp.config" )
 if 51 - 51: OoOoOO00 / iIii1I11I1II1 . oO0o - I1ii11iIi11i - OOooOOo
 Oo0OO = { "type" : "entire-map-cache" , "entries" : [ ] }
 if 94 - 94: I11i / iII111i + o0oOOo0O0Ooo - II111iiii . O0
 if ( do_clear == False ) :
  oO0 = Oo0OO [ "entries" ]
  lisp_map_cache . walk_cache ( lisp_ipc_walk_map_cache , oO0 )
  if 97 - 97: I1IiiI % iII111i * oO0o - i1IIi
  if 7 - 7: oO0o / ooOoO0o / IiII - I1ii11iIi11i * IiII % O0
 lisp_write_to_dp_socket ( Oo0OO )
 return
 if 41 - 41: Ii1I + IiII / O0 . iIii1I11I1II1
 if 71 - 71: oO0o / o0oOOo0O0Ooo % iIii1I11I1II1 * iIii1I11I1II1
 if 29 - 29: ooOoO0o - OoOoOO00 - o0oOOo0O0Ooo
 if 54 - 54: Ii1I + i11iIiiIii + i1IIi - OoooooooOO
 if 100 - 100: oO0o . ooOoO0o
 if 14 - 14: OoooooooOO + iII111i / iIii1I11I1II1 / ooOoO0o % iIii1I11I1II1 - IiII
 if 34 - 34: I1ii11iIi11i + i11iIiiIii - I1ii11iIi11i / OoOoOO00 + i1IIi . i11iIiiIii
 if 48 - 48: I1ii11iIi11i % OoOoOO00 * OoOoOO00 % o0oOOo0O0Ooo * II111iiii / OoOoOO00
 if 73 - 73: OoOoOO00 + OOooOOo * II111iiii . OOooOOo % I1Ii111 % oO0o
 if 79 - 79: I1ii11iIi11i % I11i
 if 78 - 78: i11iIiiIii % I1Ii111 + iIii1I11I1II1 + iII111i
 if 66 - 66: I1IiiI - o0oOOo0O0Ooo
 if 67 - 67: oO0o . iII111i * Ii1I - OOooOOo / oO0o
 if 98 - 98: OoOoOO00 * OoO0O00 . Oo0Ooo
def lisp_process_data_plane_stats ( msg , lisp_sockets , lisp_port ) :
 if ( msg . has_key ( "entries" ) == False ) :
  lprint ( "No 'entries' in stats IPC message" )
  return
  if 6 - 6: I11i % iIii1I11I1II1 + I1Ii111
 if ( type ( msg [ "entries" ] ) != list ) :
  lprint ( "'entries' in stats IPC message must be an array" )
  return
  if 48 - 48: II111iiii . OOooOOo . ooOoO0o - iII111i
  if 90 - 90: OOooOOo
 for msg in msg [ "entries" ] :
  if ( msg . has_key ( "eid-prefix" ) == False ) :
   lprint ( "No 'eid-prefix' in stats IPC message" )
   continue
   if 43 - 43: IiII + ooOoO0o
  oO00oo000O = msg [ "eid-prefix" ]
  if 4 - 4: i1IIi
  if ( msg . has_key ( "instance-id" ) == False ) :
   lprint ( "No 'instance-id' in stats IPC message" )
   continue
   if 89 - 89: Oo0Ooo / iIii1I11I1II1 . OoOoOO00
  II1 = int ( msg [ "instance-id" ] )
  if 6 - 6: Ii1I / iII111i
  if 69 - 69: iIii1I11I1II1 % I1Ii111 % OOooOOo + O0 - OoOoOO00 % oO0o
  if 70 - 70: oO0o - I1IiiI + Ii1I
  if 54 - 54: OoOoOO00 / ooOoO0o - I1IiiI
  Oo00o = lisp_address ( LISP_AFI_NONE , "" , 0 , II1 )
  Oo00o . store_prefix ( oO00oo000O )
  ooooOoo000O = lisp_map_cache_lookup ( None , Oo00o )
  if ( ooooOoo000O == None ) :
   lprint ( "Map-cache entry for {} not found for stats update" . format ( oO00oo000O ) )
   if 37 - 37: o0oOOo0O0Ooo
   continue
   if 57 - 57: iII111i / i1IIi / i1IIi + IiII
   if 75 - 75: IiII / O0
  if ( msg . has_key ( "rlocs" ) == False ) :
   lprint ( "No 'rlocs' in stats IPC message for {}" . format ( oO00oo000O ) )
   if 72 - 72: I11i
   continue
   if 35 - 35: I11i % OoooooooOO / i1IIi * i1IIi / I1IiiI
  if ( type ( msg [ "rlocs" ] ) != list ) :
   lprint ( "'rlocs' in stats IPC message must be an array" )
   continue
   if 42 - 42: I11i - i1IIi - oO0o / I11i + Ii1I + ooOoO0o
  iIIOO0OO = msg [ "rlocs" ]
  if 67 - 67: OoO0O00 . II111iiii * O0
  if 1 - 1: o0oOOo0O0Ooo + Oo0Ooo
  if 20 - 20: O0
  if 77 - 77: I1ii11iIi11i + OoooooooOO * OoO0O00 * iIii1I11I1II1 % I1Ii111
  for iIi1 in iIIOO0OO :
   if ( iIi1 . has_key ( "rloc" ) == False ) : continue
   if 3 - 3: ooOoO0o . Oo0Ooo . ooOoO0o / OoO0O00 / o0oOOo0O0Ooo . I1Ii111
   ooOOo00o0ooO = iIi1 [ "rloc" ]
   if ( ooOOo00o0ooO == "no-address" ) : continue
   if 20 - 20: iII111i + II111iiii + i11iIiiIii
   Oo0o0o0oo = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
   Oo0o0o0oo . store_address ( ooOOo00o0ooO )
   if 75 - 75: OoooooooOO
   O0OO0O = ooooOoo000O . get_rloc ( Oo0o0o0oo )
   if ( O0OO0O == None ) : continue
   if 63 - 63: iII111i % oO0o . ooOoO0o * I1Ii111 + o0oOOo0O0Ooo * II111iiii
   if 61 - 61: oO0o
   if 45 - 45: I11i * OoOoOO00 % Oo0Ooo / iII111i
   if 78 - 78: II111iiii
   i1iI11ii = 0 if iIi1 . has_key ( "packet-count" ) == False else iIi1 [ "packet-count" ]
   if 24 - 24: II111iiii + iII111i . I1Ii111
   OO00o0oo0 = 0 if iIi1 . has_key ( "byte-count" ) == False else iIi1 [ "byte-count" ]
   if 29 - 29: IiII + Oo0Ooo + iII111i / OoO0O00
   OOOO0O00o = 0 if iIi1 . has_key ( "seconds-last-packet" ) == False else iIi1 [ "seconds-last-packet" ]
   if 69 - 69: I1IiiI % I1IiiI . OoooooooOO - ooOoO0o / I11i
   if 32 - 32: iIii1I11I1II1 % oO0o / I1Ii111
   O0OO0O . stats . packet_count += i1iI11ii
   O0OO0O . stats . byte_count += OO00o0oo0
   O0OO0O . stats . last_increment = lisp_get_timestamp ( ) - OOOO0O00o
   if 42 - 42: I11i / I1ii11iIi11i - I1IiiI * iII111i / I1IiiI / i11iIiiIii
   lprint ( "Update stats {}/{}/{}s for {} RLOC {}" . format ( i1iI11ii , OO00o0oo0 ,
 OOOO0O00o , oO00oo000O , ooOOo00o0ooO ) )
   if 75 - 75: Oo0Ooo + IiII / I11i % I11i % IiII / I1Ii111
   if 95 - 95: OoOoOO00
   if 78 - 78: I11i
   if 62 - 62: iIii1I11I1II1 . o0oOOo0O0Ooo . ooOoO0o % oO0o % O0 % oO0o
   if 51 - 51: Oo0Ooo / IiII - Oo0Ooo
  if ( ooooOoo000O . group . is_null ( ) and ooooOoo000O . has_ttl_elapsed ( ) ) :
   oO00oo000O = green ( ooooOoo000O . print_eid_tuple ( ) , False )
   lprint ( "Refresh map-cache entry {}" . format ( oO00oo000O ) )
   lisp_send_map_request ( lisp_sockets , lisp_port , None , ooooOoo000O . eid , None )
   if 71 - 71: I11i * I1ii11iIi11i * OOooOOo * o0oOOo0O0Ooo
   if 53 - 53: I1IiiI % I1IiiI
 return
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
def lisp_process_data_plane_decap_stats ( msg , lisp_ipc_socket ) :
 if 95 - 95: OoO0O00 % iII111i / I1IiiI * OoooooooOO
 if 31 - 31: iIii1I11I1II1
 if 62 - 62: o0oOOo0O0Ooo - iII111i / II111iiii . o0oOOo0O0Ooo
 if 20 - 20: iIii1I11I1II1 % OOooOOo
 if 91 - 91: ooOoO0o
 if ( lisp_i_am_itr ) :
  lprint ( "Send decap-stats IPC message to lisp-etr process" )
  oOooOOoo = "stats%{}" . format ( json . dumps ( msg ) )
  oOooOOoo = lisp_command_ipc ( oOooOOoo , "lisp-itr" )
  lisp_ipc ( oOooOOoo , lisp_ipc_socket , "lisp-etr" )
  return
  if 96 - 96: I1IiiI . OOooOOo
  if 94 - 94: OoooooooOO + II111iiii % ooOoO0o - II111iiii / O0
  if 34 - 34: IiII % oO0o
  if 54 - 54: I1IiiI
  if 80 - 80: OoOoOO00 . I1IiiI / I1ii11iIi11i . iII111i
  if 31 - 31: I11i * o0oOOo0O0Ooo
  if 17 - 17: Ii1I * iIii1I11I1II1
  if 9 - 9: o0oOOo0O0Ooo - IiII
 oOooOOoo = bold ( "IPC" , False )
 lprint ( "Process decap-stats {} message: '{}'" . format ( oOooOOoo , msg ) )
 if 78 - 78: i11iIiiIii . o0oOOo0O0Ooo
 if ( lisp_i_am_etr ) : msg = json . loads ( msg )
 if 72 - 72: Oo0Ooo % II111iiii + O0 * OoOoOO00 - OOooOOo + I1Ii111
 IiIii1ii = [ "good-packets" , "ICV-error" , "checksum-error" ,
 "lisp-header-error" , "no-decrypt-key" , "bad-inner-version" ,
 "outer-header-error" ]
 if 62 - 62: iII111i
 for II1IOOOoO0 in IiIii1ii :
  i1iI11ii = 0 if msg . has_key ( II1IOOOoO0 ) == False else msg [ II1IOOOoO0 ] [ "packet-count" ]
  if 79 - 79: I1Ii111 / I1ii11iIi11i * OoOoOO00 - iIii1I11I1II1
  lisp_decap_stats [ II1IOOOoO0 ] . packet_count += i1iI11ii
  if 98 - 98: i1IIi
  OO00o0oo0 = 0 if msg . has_key ( II1IOOOoO0 ) == False else msg [ II1IOOOoO0 ] [ "byte-count" ]
  if 19 - 19: OoO0O00 % I1ii11iIi11i + I1ii11iIi11i
  lisp_decap_stats [ II1IOOOoO0 ] . byte_count += OO00o0oo0
  if 3 - 3: i11iIiiIii - iIii1I11I1II1 / OoOoOO00
  OOOO0O00o = 0 if msg . has_key ( II1IOOOoO0 ) == False else msg [ II1IOOOoO0 ] [ "seconds-last-packet" ]
  if 34 - 34: I1IiiI . IiII / ooOoO0o + I1Ii111 / iIii1I11I1II1 + OoooooooOO
  lisp_decap_stats [ II1IOOOoO0 ] . last_increment = lisp_get_timestamp ( ) - OOOO0O00o
  if 80 - 80: OoO0O00 - OoOoOO00 % i1IIi / iIii1I11I1II1 . I11i - I11i
 return
 if 76 - 76: ooOoO0o * iII111i / Ii1I * i1IIi . I1Ii111 - o0oOOo0O0Ooo
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
 if 59 - 59: O0
 if 75 - 75: o0oOOo0O0Ooo / OoooooooOO . I1ii11iIi11i * oO0o * I11i / OoooooooOO
def lisp_process_punt ( punt_socket , lisp_send_sockets , lisp_ephem_port ) :
 i1II111ii1i , oo = punt_socket . recvfrom ( 4000 )
 if 8 - 8: i1IIi
 IIOoOO = json . loads ( i1II111ii1i )
 if ( type ( IIOoOO ) != dict ) :
  lprint ( "Invalid punt message from {}, not in JSON format" . format ( oo ) )
  if 61 - 61: i11iIiiIii * Ii1I % iII111i - Ii1I * O0
  return
  if 39 - 39: iII111i + i1IIi * iII111i - iIii1I11I1II1
 I1Ii = bold ( "Punt" , False )
 lprint ( "{} message from '{}': '{}'" . format ( I1Ii , oo , IIOoOO ) )
 if 95 - 95: o0oOOo0O0Ooo
 if ( IIOoOO . has_key ( "type" ) == False ) :
  lprint ( "Punt IPC message has no 'type' key" )
  return
  if 58 - 58: OOooOOo . II111iiii . I1Ii111 . I1IiiI * I11i
  if 29 - 29: OOooOOo + Ii1I % Oo0Ooo % I1ii11iIi11i
  if 72 - 72: IiII / II111iiii
  if 25 - 25: i1IIi + OoOoOO00 + oO0o + OoooooooOO
  if 21 - 21: I1ii11iIi11i
 if ( IIOoOO [ "type" ] == "statistics" ) :
  lisp_process_data_plane_stats ( IIOoOO , lisp_send_sockets , lisp_ephem_port )
  return
  if 60 - 60: i1IIi / OoO0O00 . Ii1I
 if ( IIOoOO [ "type" ] == "decap-statistics" ) :
  lisp_process_data_plane_decap_stats ( IIOoOO , punt_socket )
  return
  if 16 - 16: i11iIiiIii + OoOoOO00 % Oo0Ooo + I1ii11iIi11i * Ii1I / I1Ii111
  if 26 - 26: iII111i
  if 31 - 31: iII111i
  if 45 - 45: OoO0O00
  if 55 - 55: iIii1I11I1II1 % iIii1I11I1II1 + I11i - ooOoO0o + I1IiiI * O0
 if ( IIOoOO [ "type" ] == "restart" ) :
  lisp_process_data_plane_restart ( )
  return
  if 47 - 47: ooOoO0o + iIii1I11I1II1 * OOooOOo . I1IiiI . o0oOOo0O0Ooo
  if 49 - 49: Oo0Ooo . OoOoOO00 * OOooOOo
  if 86 - 86: IiII * OOooOOo + Ii1I
  if 62 - 62: I11i
  if 86 - 86: Oo0Ooo % II111iiii + I1Ii111 / I1ii11iIi11i
 if ( IIOoOO [ "type" ] != "discovery" ) :
  lprint ( "Punt IPC message has wrong format" )
  return
  if 15 - 15: I1IiiI / I1Ii111 % iII111i
 if ( IIOoOO . has_key ( "interface" ) == False ) :
  lprint ( "Invalid punt message from {}, required keys missing" . format ( oo ) )
  if 57 - 57: I1Ii111 . iIii1I11I1II1 / Oo0Ooo / IiII / iII111i * OoOoOO00
  return
  if 35 - 35: i1IIi + I1Ii111 - ooOoO0o . I1ii11iIi11i + Oo0Ooo
  if 43 - 43: oO0o . OoO0O00 * i1IIi
  if 1 - 1: ooOoO0o / i1IIi
  if 42 - 42: I1ii11iIi11i * ooOoO0o + OoOoOO00 % I1ii11iIi11i . IiII
  if 75 - 75: OoO0O00 * i1IIi - OOooOOo % II111iiii % OoO0O00 - OoOoOO00
 oO00O = IIOoOO [ "interface" ]
 if ( oO00O == "" ) :
  II1 = int ( IIOoOO [ "instance-id" ] )
  if ( II1 == - 1 ) : return
 else :
  II1 = lisp_get_interface_instance_id ( oO00O , None )
  if 75 - 75: I11i * IiII * ooOoO0o
  if 31 - 31: Ii1I
  if 72 - 72: OOooOOo * Ii1I % OoO0O00
  if 72 - 72: OoOoOO00 + o0oOOo0O0Ooo - i1IIi - OoO0O00 % OoOoOO00
  if 42 - 42: oO0o / i1IIi . IiII
 oOoO = None
 if ( IIOoOO . has_key ( "source-eid" ) ) :
  IiIiii = IIOoOO [ "source-eid" ]
  oOoO = lisp_address ( LISP_AFI_NONE , IiIiii , 0 , II1 )
  if ( oOoO . is_null ( ) ) :
   lprint ( "Invalid source-EID format '{}'" . format ( IiIiii ) )
   return
   if 12 - 12: i11iIiiIii . ooOoO0o
   if 80 - 80: O0 / iIii1I11I1II1 % iII111i * ooOoO0o / i11iIiiIii . OoOoOO00
 iII1I1iiII11I = None
 if ( IIOoOO . has_key ( "dest-eid" ) ) :
  oooi1IiIiiii = IIOoOO [ "dest-eid" ]
  iII1I1iiII11I = lisp_address ( LISP_AFI_NONE , oooi1IiIiiii , 0 , II1 )
  if ( iII1I1iiII11I . is_null ( ) ) :
   lprint ( "Invalid dest-EID format '{}'" . format ( oooi1IiIiiii ) )
   return
   if 40 - 40: o0oOOo0O0Ooo / I1ii11iIi11i + I1IiiI / Oo0Ooo
   if 83 - 83: i11iIiiIii
   if 86 - 86: OoO0O00 * oO0o + ooOoO0o % iII111i
   if 81 - 81: i11iIiiIii . II111iiii * I11i + Ii1I / O0 . Oo0Ooo
   if 29 - 29: IiII - IiII - OoooooooOO . Ii1I % OoooooooOO - OoOoOO00
   if 33 - 33: oO0o * OoO0O00 / i11iIiiIii - I1IiiI * OoO0O00
   if 19 - 19: OoooooooOO
   if 34 - 34: OoOoOO00 . oO0o
 if ( oOoO ) :
  Oo0ooo0Ooo = green ( oOoO . print_address ( ) , False )
  iIiIIi1i = lisp_db_for_lookups . lookup_cache ( oOoO , False )
  if ( iIiIIi1i != None ) :
   if 53 - 53: oO0o + OoooooooOO * ooOoO0o
   if 85 - 85: I1ii11iIi11i - o0oOOo0O0Ooo % o0oOOo0O0Ooo % iII111i * OoOoOO00
   if 50 - 50: I1Ii111 + I1Ii111 + I11i - OoOoOO00
   if 65 - 65: oO0o / I11i + iII111i - I1ii11iIi11i
   if 80 - 80: II111iiii . i11iIiiIii
   if ( iIiIIi1i . dynamic_eid_configured ( ) ) :
    II111IiiiI1 = lisp_allow_dynamic_eid ( oO00O , oOoO )
    if ( II111IiiiI1 != None and lisp_i_am_itr ) :
     lisp_itr_discover_eid ( iIiIIi1i , oOoO , oO00O , II111IiiiI1 )
    else :
     lprint ( ( "Disallow dynamic source-EID {} " + "on interface {}" ) . format ( Oo0ooo0Ooo , oO00O ) )
     if 66 - 66: ooOoO0o * iII111i * OOooOOo % OoO0O00 / I1ii11iIi11i
     if 33 - 33: iIii1I11I1II1
     if 52 - 52: iIii1I11I1II1 + O0
  else :
   lprint ( "Punt from non-EID source {}" . format ( Oo0ooo0Ooo ) )
   if 84 - 84: OOooOOo / iII111i . I1IiiI / O0 % OOooOOo . iII111i
   if 32 - 32: OoO0O00 + OoO0O00 % o0oOOo0O0Ooo / O0
   if 29 - 29: iII111i % I1Ii111
   if 95 - 95: OOooOOo - ooOoO0o % i1IIi / O0 % I11i . IiII
   if 63 - 63: ooOoO0o
   if 22 - 22: OOooOOo . i11iIiiIii + II111iiii - Oo0Ooo % i1IIi / o0oOOo0O0Ooo
 if ( iII1I1iiII11I ) :
  ooooOoo000O = lisp_map_cache_lookup ( oOoO , iII1I1iiII11I )
  if ( ooooOoo000O == None or ooooOoo000O . action == LISP_SEND_MAP_REQUEST_ACTION ) :
   if 90 - 90: IiII
   if 38 - 38: i1IIi / ooOoO0o / I11i * I1ii11iIi11i / II111iiii . iIii1I11I1II1
   if 52 - 52: I1ii11iIi11i % ooOoO0o * Ii1I * IiII + IiII / i11iIiiIii
   if 51 - 51: iIii1I11I1II1 * o0oOOo0O0Ooo % o0oOOo0O0Ooo . Ii1I / OoooooooOO
   if 23 - 23: oO0o * I1IiiI - oO0o - ooOoO0o . IiII / i11iIiiIii
   if ( lisp_rate_limit_map_request ( oOoO , iII1I1iiII11I ) ) : return
   lisp_send_map_request ( lisp_send_sockets , lisp_ephem_port ,
 oOoO , iII1I1iiII11I , None )
  else :
   Oo0ooo0Ooo = green ( iII1I1iiII11I . print_address ( ) , False )
   lprint ( "Map-cache entry for {} already exists" . format ( Oo0ooo0Ooo ) )
   if 53 - 53: Ii1I * Ii1I . OoOoOO00 . OOooOOo / I1ii11iIi11i % O0
   if 98 - 98: OOooOOo
 return
 if 11 - 11: OOooOOo * iIii1I11I1II1 % IiII - I1IiiI . I11i
 if 29 - 29: OOooOOo % I11i - OOooOOo - OOooOOo * I11i . oO0o
 if 75 - 75: II111iiii . O0 . I1Ii111 * O0 / OoooooooOO
 if 60 - 60: OOooOOo - Oo0Ooo * OOooOOo / OoO0O00
 if 55 - 55: I1ii11iIi11i * II111iiii * iIii1I11I1II1
 if 38 - 38: iIii1I11I1II1 % I1ii11iIi11i . Ii1I + I1IiiI % i11iIiiIii - i11iIiiIii
 if 62 - 62: I1Ii111 + I1IiiI
def lisp_ipc_map_cache_entry ( mc , jdata ) :
 iiIIIIiI111 = lisp_write_ipc_map_cache ( True , mc , dont_send = True )
 jdata . append ( iiIIIIiI111 )
 return ( [ True , jdata ] )
 if 9 - 9: iIii1I11I1II1 / iIii1I11I1II1
 if 24 - 24: OOooOOo . I1IiiI % i11iIiiIii
 if 43 - 43: OoooooooOO . o0oOOo0O0Ooo - I1ii11iIi11i + OoO0O00 . I1Ii111 . iII111i
 if 1 - 1: iII111i / OoO0O00 / OoOoOO00 * Oo0Ooo * OoooooooOO
 if 59 - 59: iII111i
 if 14 - 14: oO0o . IiII + iIii1I11I1II1 - i1IIi
 if 46 - 46: i11iIiiIii * II111iiii / i11iIiiIii % i11iIiiIii * II111iiii + i11iIiiIii
 if 87 - 87: Oo0Ooo + OoO0O00 / II111iiii * OoooooooOO
def lisp_ipc_walk_map_cache ( mc , jdata ) :
 if 95 - 95: I1Ii111 * o0oOOo0O0Ooo + OoO0O00 % OoOoOO00 - ooOoO0o / OoOoOO00
 if 45 - 45: OoooooooOO / oO0o / o0oOOo0O0Ooo + Ii1I + O0 . iII111i
 if 34 - 34: iIii1I11I1II1 . o0oOOo0O0Ooo + ooOoO0o
 if 96 - 96: O0 / ooOoO0o
 if ( mc . group . is_null ( ) ) : return ( lisp_ipc_map_cache_entry ( mc , jdata ) )
 if 82 - 82: OoO0O00 * OOooOOo * I11i * I1Ii111 % iIii1I11I1II1
 if ( mc . source_cache == None ) : return ( [ True , jdata ] )
 if 50 - 50: Ii1I * Ii1I % I11i / iIii1I11I1II1 / ooOoO0o / iII111i
 if 91 - 91: Ii1I - O0 . I11i - OoooooooOO * IiII . II111iiii
 if 38 - 38: I1IiiI + OoO0O00
 if 11 - 11: iIii1I11I1II1 + i1IIi * IiII - Oo0Ooo
 if 66 - 66: I1Ii111 . Ii1I / I1ii11iIi11i / iIii1I11I1II1 + O0 / i1IIi
 jdata = mc . source_cache . walk_cache ( lisp_ipc_map_cache_entry , jdata )
 return ( [ True , jdata ] )
 if 72 - 72: ooOoO0o . II111iiii
 if 32 - 32: I1Ii111 - oO0o + OoooooooOO . OoOoOO00 + i11iIiiIii / i1IIi
 if 26 - 26: I1IiiI + OoooooooOO % OoOoOO00 . IiII - II111iiii . OoOoOO00
 if 37 - 37: OoO0O00 % O0 + OoOoOO00 * I11i . Ii1I * OoO0O00
 if 18 - 18: o0oOOo0O0Ooo / OOooOOo
 if 28 - 28: O0 / Ii1I - oO0o % I1ii11iIi11i % O0 . OoO0O00
 if 100 - 100: O0
def lisp_itr_discover_eid ( db , eid , input_interface , routed_interface ,
 lisp_ipc_listen_socket ) :
 oO00oo000O = eid . print_address ( )
 if ( db . dynamic_eids . has_key ( oO00oo000O ) ) :
  db . dynamic_eids [ oO00oo000O ] . last_packet = lisp_get_timestamp ( )
  return
  if 19 - 19: Ii1I * iIii1I11I1II1 * Oo0Ooo - i11iIiiIii * i11iIiiIii - OOooOOo
  if 88 - 88: O0 . iIii1I11I1II1 . I1ii11iIi11i
  if 80 - 80: oO0o / i1IIi * iIii1I11I1II1
  if 38 - 38: Ii1I
  if 20 - 20: iIii1I11I1II1 + Oo0Ooo - Ii1I / i11iIiiIii . OoO0O00
 oOOo0oO = lisp_dynamic_eid ( )
 oOOo0oO . dynamic_eid . copy_address ( eid )
 oOOo0oO . interface = routed_interface
 oOOo0oO . last_packet = lisp_get_timestamp ( )
 oOOo0oO . get_timeout ( routed_interface )
 db . dynamic_eids [ oO00oo000O ] = oOOo0oO
 if 66 - 66: OoooooooOO - Ii1I / iII111i . I1IiiI + I1ii11iIi11i - I1Ii111
 I1iI1IIi1 = ""
 if ( input_interface != routed_interface ) :
  I1iI1IIi1 = ", routed-interface " + routed_interface
  if 58 - 58: oO0o - iIii1I11I1II1 * i11iIiiIii / i11iIiiIii % I11i
  if 69 - 69: iII111i * i1IIi
 oOOOoo0 = green ( oO00oo000O , False ) + bold ( " discovered" , False )
 lprint ( "Dynamic-EID {} on interface {}{}, timeout {}" . format ( oOOOoo0 , input_interface , I1iI1IIi1 , oOOo0oO . timeout ) )
 if 33 - 33: OoO0O00 . i11iIiiIii * II111iiii - Ii1I * IiII
 if 45 - 45: OoO0O00
 if 15 - 15: iII111i * o0oOOo0O0Ooo * Ii1I % IiII
 if 31 - 31: ooOoO0o . IiII + I1ii11iIi11i * II111iiii * iII111i + Oo0Ooo
 if 35 - 35: oO0o + I1ii11iIi11i / o0oOOo0O0Ooo
 oOooOOoo = "learn%{}%{}" . format ( oO00oo000O , routed_interface )
 oOooOOoo = lisp_command_ipc ( oOooOOoo , "lisp-itr" )
 lisp_ipc ( oOooOOoo , lisp_ipc_listen_socket , "lisp-etr" )
 return
 if 78 - 78: i11iIiiIii
 if 21 - 21: iII111i / ooOoO0o - i11iIiiIii % iII111i
 if 94 - 94: OoooooooOO / iII111i * ooOoO0o / i1IIi * i11iIiiIii * II111iiii
 if 98 - 98: Ii1I * Ii1I / IiII
 if 1 - 1: OOooOOo
 if 47 - 47: i11iIiiIii - I11i
 if 38 - 38: Oo0Ooo % OoooooooOO + iII111i
 if 31 - 31: OoO0O00 + I1Ii111 / iIii1I11I1II1
 if 11 - 11: ooOoO0o - OoOoOO00
 if 19 - 19: O0 . OoOoOO00 - i1IIi . oO0o
 if 96 - 96: o0oOOo0O0Ooo % o0oOOo0O0Ooo - OoO0O00 * iIii1I11I1II1 + ooOoO0o - ooOoO0o
 if 4 - 4: OoO0O00 - OOooOOo
 if 21 - 21: I1Ii111 * i11iIiiIii
def lisp_retry_decap_keys ( addr_str , packet , iv , packet_icv ) :
 if ( lisp_search_decap_keys == False ) : return
 if 63 - 63: oO0o + OoOoOO00
 if 50 - 50: o0oOOo0O0Ooo / Oo0Ooo * ooOoO0o * Ii1I
 if 97 - 97: I1IiiI / oO0o + I1Ii111 + I1Ii111
 if 86 - 86: o0oOOo0O0Ooo % ooOoO0o + OoOoOO00 * ooOoO0o
 if ( addr_str . find ( ":" ) != - 1 ) : return
 if 20 - 20: Ii1I * iII111i / ooOoO0o
 OOooOo00Ooo = lisp_crypto_keys_by_rloc_decap [ addr_str ]
 if 18 - 18: Oo0Ooo * Ii1I / i11iIiiIii . OoO0O00 + OoooooooOO
 for Iiii11 in lisp_crypto_keys_by_rloc_decap :
  if 23 - 23: I1IiiI - I1ii11iIi11i . O0 . OoOoOO00 . OoO0O00
  if 81 - 81: IiII * I11i - iIii1I11I1II1
  if 41 - 41: oO0o * I11i + I1IiiI - OoO0O00
  if 63 - 63: Oo0Ooo * Ii1I - Ii1I
  if ( Iiii11 . find ( addr_str ) == - 1 ) : continue
  if 76 - 76: OoO0O00 . IiII % iIii1I11I1II1 / I1IiiI + iIii1I11I1II1 . I1IiiI
  if 57 - 57: IiII - i1IIi * ooOoO0o
  if 5 - 5: oO0o . O0 * IiII / Ii1I + OoO0O00
  if 75 - 75: OOooOOo * OoOoOO00
  if ( Iiii11 == addr_str ) : continue
  if 82 - 82: Ii1I
  if 83 - 83: I1IiiI
  if 22 - 22: IiII / Ii1I + I1Ii111 % iIii1I11I1II1
  if 75 - 75: OoOoOO00 % OoOoOO00 % o0oOOo0O0Ooo % I1ii11iIi11i + IiII
  iiIIIIiI111 = lisp_crypto_keys_by_rloc_decap [ Iiii11 ]
  if ( iiIIIIiI111 == OOooOo00Ooo ) : continue
  if 45 - 45: I11i - iIii1I11I1II1
  if 20 - 20: OoOoOO00
  if 84 - 84: OoOoOO00
  if 59 - 59: Ii1I / I1Ii111 + i11iIiiIii
  IiI11 = iiIIIIiI111 [ 1 ]
  if ( packet_icv != IiI11 . do_icv ( packet , iv ) ) :
   lprint ( "Test ICV with key {} failed" . format ( red ( Iiii11 , False ) ) )
   continue
   if 68 - 68: IiII
   if 42 - 42: O0 . ooOoO0o + OOooOOo . iIii1I11I1II1 * OoO0O00 . iII111i
  lprint ( "Changing decap crypto key to {}" . format ( red ( Iiii11 , False ) ) )
  lisp_crypto_keys_by_rloc_decap [ addr_str ] = iiIIIIiI111
  if 35 - 35: II111iiii + I11i
 return
 if 15 - 15: Oo0Ooo . i1IIi - o0oOOo0O0Ooo - oO0o / o0oOOo0O0Ooo
 if 97 - 97: oO0o - I1IiiI / Ii1I
 if 48 - 48: o0oOOo0O0Ooo % o0oOOo0O0Ooo - OoOoOO00
 if 13 - 13: OoO0O00 - Ii1I . ooOoO0o / O0 * OoOoOO00
 if 57 - 57: O0 + OoooooooOO % o0oOOo0O0Ooo / I1Ii111 / OOooOOo - OoOoOO00
 if 48 - 48: o0oOOo0O0Ooo - II111iiii + OoOoOO00
 if 54 - 54: II111iiii - OoO0O00 - o0oOOo0O0Ooo - O0 % I1Ii111
 if 9 - 9: i1IIi % iII111i / Ii1I
def lisp_decent_pull_xtr_configured ( ) :
 return ( lisp_decent_modulus != 0 and lisp_decent_dns_suffix != None )
 if 83 - 83: oO0o
 if 1 - 1: oO0o * iIii1I11I1II1 % iIii1I11I1II1 % iIii1I11I1II1 / oO0o + IiII
 if 29 - 29: OoooooooOO
 if 55 - 55: O0 - o0oOOo0O0Ooo % I1ii11iIi11i * I11i * oO0o
 if 83 - 83: iIii1I11I1II1
 if 92 - 92: OoO0O00 - iII111i
 if 97 - 97: ooOoO0o / I11i . IiII + I1Ii111 . iIii1I11I1II1
 if 24 - 24: ooOoO0o - oO0o % OoOoOO00 * Oo0Ooo
def lisp_is_decent_dns_suffix ( dns_name ) :
 if ( lisp_decent_dns_suffix == None ) : return ( False )
 i1i1Ii = dns_name . split ( "." )
 i1i1Ii = "." . join ( i1i1Ii [ 1 : : ] )
 return ( i1i1Ii == lisp_decent_dns_suffix )
 if 54 - 54: Ii1I - OoooooooOO % I1IiiI + oO0o
 if 70 - 70: I1Ii111 % iIii1I11I1II1
 if 74 - 74: i1IIi % i11iIiiIii + oO0o
 if 94 - 94: OoO0O00 * I1IiiI / O0 + I1Ii111 / i11iIiiIii
 if 34 - 34: Oo0Ooo . i1IIi
 if 97 - 97: I11i
 if 89 - 89: iII111i % OoOoOO00 . Oo0Ooo
def lisp_get_decent_index ( eid ) :
 oO00oo000O = eid . print_prefix ( )
 iII1III11ii = hashlib . sha256 ( oO00oo000O ) . hexdigest ( )
 oo0OOo0O = int ( iII1III11ii , 16 ) % lisp_decent_modulus
 return ( oo0OOo0O )
 if 24 - 24: OOooOOo . oO0o / I1Ii111 / IiII - iII111i
 if 23 - 23: iIii1I11I1II1 * ooOoO0o * iII111i * i11iIiiIii * i1IIi
 if 25 - 25: O0 / OoO0O00 - oO0o - I1IiiI * OoOoOO00
 if 98 - 98: OoO0O00 % OoooooooOO + OoooooooOO * OoOoOO00 / OoO0O00 + o0oOOo0O0Ooo
 if 25 - 25: OoO0O00 % OoOoOO00
 if 15 - 15: OoO0O00 + I1ii11iIi11i
 if 88 - 88: OoooooooOO / I11i % II111iiii % OOooOOo - I11i
def lisp_get_decent_dns_name ( eid ) :
 oo0OOo0O = lisp_get_decent_index ( eid )
 return ( str ( oo0OOo0O ) + "." + lisp_decent_dns_suffix )
 if 55 - 55: Oo0Ooo - OOooOOo - O0
 if 40 - 40: OoOoOO00 - OOooOOo
 if 3 - 3: IiII % I11i * I1Ii111 + iIii1I11I1II1 . oO0o
 if 35 - 35: II111iiii
 if 15 - 15: I11i * iIii1I11I1II1 + OOooOOo % IiII . o0oOOo0O0Ooo % Oo0Ooo
 if 96 - 96: O0
 if 15 - 15: i1IIi . iIii1I11I1II1
 if 3 - 3: II111iiii * i11iIiiIii * i1IIi - i1IIi
def lisp_get_decent_dns_name_from_str ( iid , eid_str ) :
 Oo00o = lisp_address ( LISP_AFI_NONE , eid_str , 0 , iid )
 oo0OOo0O = lisp_get_decent_index ( Oo00o )
 return ( str ( oo0OOo0O ) + "." + lisp_decent_dns_suffix )
 if 11 - 11: I1IiiI % Ii1I * i11iIiiIii % OOooOOo + II111iiii
 if 61 - 61: I1Ii111 + I11i + I1IiiI
 if 48 - 48: I11i
 if 67 - 67: o0oOOo0O0Ooo
 if 36 - 36: IiII - I11i - Ii1I / OoOoOO00 % OoO0O00 * iIii1I11I1II1
 if 61 - 61: i11iIiiIii / Ii1I - OOooOOo . I1ii11iIi11i
 if 89 - 89: ooOoO0o % i11iIiiIii
 if 57 - 57: Oo0Ooo / ooOoO0o - O0 . ooOoO0o
 if 61 - 61: o0oOOo0O0Ooo / OoooooooOO . I1ii11iIi11i + Oo0Ooo
 if 75 - 75: Ii1I
def lisp_trace_append ( packet , reason = None , ed = "encap" , lisp_socket = None ,
 rloc_entry = None ) :
 if 79 - 79: i1IIi . I1ii11iIi11i * o0oOOo0O0Ooo / I11i . I11i / ooOoO0o
 ii = 28 if packet . inner_version == 4 else 48
 OO00oo0 = packet . packet [ ii : : ]
 OoOooO00 = lisp_trace ( )
 if ( OoOooO00 . decode ( OO00oo0 ) == False ) :
  lprint ( "Could not decode JSON portion of a LISP-Trace packet" )
  return ( False )
  if 58 - 58: Oo0Ooo % i11iIiiIii . Oo0Ooo / Oo0Ooo - I1IiiI . Ii1I
  if 65 - 65: OoO0O00
 I11iiiiiII1 = "?" if packet . outer_dest . is_null ( ) else packet . outer_dest . print_address_no_iid ( )
 if 6 - 6: I1Ii111 + OoO0O00 + O0 * OoOoOO00 . iIii1I11I1II1 . I1Ii111
 if 93 - 93: ooOoO0o % iIii1I11I1II1 + I1ii11iIi11i
 if 74 - 74: OoOoOO00 + I1ii11iIi11i
 if 82 - 82: II111iiii
 if 55 - 55: I11i . iIii1I11I1II1 / Ii1I - OoO0O00 * I1ii11iIi11i % iIii1I11I1II1
 if 48 - 48: ooOoO0o + Oo0Ooo / Oo0Ooo
 if ( I11iiiiiII1 != "?" and packet . encap_port != LISP_DATA_PORT ) :
  if ( ed == "encap" ) : I11iiiiiII1 += ":{}" . format ( packet . encap_port )
  if 15 - 15: iIii1I11I1II1 . I1Ii111 * OoooooooOO * O0 % OOooOOo
  if 53 - 53: Ii1I
  if 63 - 63: I11i % OoOoOO00
  if 46 - 46: iIii1I11I1II1 . II111iiii / OoooooooOO - ooOoO0o * iII111i
  if 52 - 52: I11i + iII111i
 iiIIIIiI111 = { }
 iiIIIIiI111 [ "node" ] = "ITR" if lisp_i_am_itr else "ETR" if lisp_i_am_etr else "RTR" if lisp_i_am_rtr else "?"
 if 9 - 9: OoOoOO00 % II111iiii . I11i * Oo0Ooo
 OoOo = packet . outer_source
 if ( OoOo . is_null ( ) ) : OoOo = lisp_myrlocs [ 0 ]
 iiIIIIiI111 [ "srloc" ] = OoOo . print_address_no_iid ( )
 if 92 - 92: oO0o . II111iiii
 if 4 - 4: IiII . i1IIi - i1IIi - O0 - OOooOOo * I1Ii111
 if 67 - 67: i11iIiiIii % OoooooooOO - o0oOOo0O0Ooo + OoOoOO00 + OoooooooOO
 if 66 - 66: OoOoOO00 . Ii1I / i11iIiiIii / ooOoO0o
 if 76 - 76: OoO0O00 % OoO0O00 / I1ii11iIi11i * ooOoO0o * o0oOOo0O0Ooo - I1Ii111
 if ( iiIIIIiI111 [ "node" ] == "ITR" and packet . inner_sport != LISP_TRACE_PORT ) :
  iiIIIIiI111 [ "srloc" ] += ":{}" . format ( packet . inner_sport )
  if 53 - 53: OoO0O00 % Oo0Ooo . i1IIi
  if 34 - 34: Ii1I - o0oOOo0O0Ooo * i1IIi
 iiIIIIiI111 [ "hn" ] = lisp_hostname
 Iiii11 = ed + "-ts"
 iiIIIIiI111 [ Iiii11 ] = lisp_get_timestamp ( )
 if 7 - 7: OoO0O00 * I1ii11iIi11i / I1Ii111
 if 98 - 98: II111iiii % I1ii11iIi11i
 if 48 - 48: iII111i % oO0o + oO0o - Oo0Ooo . OOooOOo
 if 38 - 38: iII111i
 if 66 - 66: iII111i + Oo0Ooo + i1IIi * Oo0Ooo
 if 18 - 18: O0 - IiII
 if ( I11iiiiiII1 == "?" and iiIIIIiI111 [ "node" ] == "ETR" ) :
  iIiIIi1i = lisp_db_for_lookups . lookup_cache ( packet . inner_dest , False )
  if ( iIiIIi1i != None and len ( iIiIIi1i . rloc_set ) >= 1 ) :
   I11iiiiiII1 = iIiIIi1i . rloc_set [ 0 ] . rloc . print_address_no_iid ( )
   if 5 - 5: I1ii11iIi11i * iII111i + II111iiii * Oo0Ooo * O0 - I1IiiI
   if 71 - 71: i11iIiiIii % I1IiiI + I1ii11iIi11i + II111iiii + OoooooooOO + oO0o
 iiIIIIiI111 [ "drloc" ] = I11iiiiiII1
 if 12 - 12: I1IiiI + I1Ii111
 if 66 - 66: I1Ii111 + OOooOOo + I1Ii111 . OoooooooOO * oO0o / OoO0O00
 if 74 - 74: O0 % OOooOOo * OoOoOO00 / oO0o - Oo0Ooo
 if 79 - 79: Ii1I + IiII
 if ( I11iiiiiII1 == "?" and reason != None ) :
  iiIIIIiI111 [ "drloc" ] += " ({})" . format ( reason )
  if 21 - 21: o0oOOo0O0Ooo * iII111i * o0oOOo0O0Ooo * o0oOOo0O0Ooo . Oo0Ooo
  if 98 - 98: I1ii11iIi11i
  if 58 - 58: IiII / i11iIiiIii % I11i
  if 74 - 74: OoooooooOO - I1ii11iIi11i + OOooOOo % IiII . o0oOOo0O0Ooo
  if 21 - 21: Ii1I
 if ( rloc_entry != None ) :
  iiIIIIiI111 [ "rtts" ] = rloc_entry . recent_rloc_probe_rtts
  iiIIIIiI111 [ "hops" ] = rloc_entry . recent_rloc_probe_hops
  if 72 - 72: I1Ii111 . OoooooooOO / I1Ii111 - Ii1I / I1ii11iIi11i * I1ii11iIi11i
  if 72 - 72: IiII . Ii1I + OoooooooOO * OoOoOO00 + Oo0Ooo . iII111i
  if 92 - 92: O0 * Ii1I - I1ii11iIi11i - IiII . OoO0O00 + I1IiiI
  if 59 - 59: i1IIi * OOooOOo % Oo0Ooo
  if 44 - 44: iIii1I11I1II1 . OOooOOo
  if 57 - 57: II111iiii + I1Ii111
 oOoO = packet . inner_source . print_address ( )
 iII1I1iiII11I = packet . inner_dest . print_address ( )
 if ( OoOooO00 . packet_json == [ ] ) :
  i11i11 = { }
  i11i11 [ "seid" ] = oOoO
  i11i11 [ "deid" ] = iII1I1iiII11I
  i11i11 [ "paths" ] = [ ]
  OoOooO00 . packet_json . append ( i11i11 )
  if 42 - 42: OoOoOO00 % O0
  if 70 - 70: iIii1I11I1II1 * Oo0Ooo - I1IiiI / OoO0O00 + OoOoOO00
  if 94 - 94: OoooooooOO + O0 * iIii1I11I1II1 * II111iiii
  if 90 - 90: I11i + O0 / I1IiiI . oO0o / O0
  if 46 - 46: O0 . O0 - oO0o . II111iiii * I1IiiI * Ii1I
  if 10 - 10: i1IIi + i1IIi . i1IIi - I1IiiI - I1IiiI
 for i11i11 in OoOooO00 . packet_json :
  if ( i11i11 [ "deid" ] != iII1I1iiII11I ) : continue
  i11i11 [ "paths" ] . append ( iiIIIIiI111 )
  break
  if 26 - 26: Ii1I * I11i / I11i
  if 79 - 79: ooOoO0o / oO0o - oO0o / OoooooooOO
  if 91 - 91: iIii1I11I1II1 - O0 * o0oOOo0O0Ooo * o0oOOo0O0Ooo . II111iiii
  if 69 - 69: II111iiii - Oo0Ooo + i1IIi . II111iiii + o0oOOo0O0Ooo
  if 20 - 20: OoooooooOO - OoO0O00 * ooOoO0o * OoOoOO00 / OOooOOo
  if 64 - 64: O0 + iII111i / I11i * OoOoOO00 + o0oOOo0O0Ooo + I1Ii111
  if 16 - 16: I11i
  if 9 - 9: Ii1I / IiII * I11i - i11iIiiIii * I1ii11iIi11i / iII111i
 oo0Oo00o000 = False
 if ( len ( OoOooO00 . packet_json ) == 1 and iiIIIIiI111 [ "node" ] == "ETR" and
 OoOooO00 . myeid ( packet . inner_dest ) ) :
  i11i11 = { }
  i11i11 [ "seid" ] = iII1I1iiII11I
  i11i11 [ "deid" ] = oOoO
  i11i11 [ "paths" ] = [ ]
  OoOooO00 . packet_json . append ( i11i11 )
  oo0Oo00o000 = True
  if 17 - 17: II111iiii
  if 29 - 29: o0oOOo0O0Ooo - iII111i
  if 49 - 49: O0 . I1ii11iIi11i . OoOoOO00 . I1Ii111 % O0 . iIii1I11I1II1
  if 19 - 19: iIii1I11I1II1
  if 97 - 97: Ii1I . I11i / ooOoO0o + Oo0Ooo
  if 100 - 100: iII111i / I1Ii111 % OoOoOO00 . O0 / OoOoOO00
 OoOooO00 . print_trace ( )
 OO00oo0 = OoOooO00 . encode ( )
 if 81 - 81: OoO0O00 % i11iIiiIii / OoO0O00 + ooOoO0o
 if 100 - 100: O0 . Oo0Ooo % Oo0Ooo % O0 / i11iIiiIii
 if 56 - 56: IiII - OOooOOo - OoOoOO00 - I11i
 if 57 - 57: i1IIi
 if 41 - 41: I11i / Ii1I
 if 1 - 1: II111iiii / iII111i
 if 83 - 83: OoO0O00 / iII111i
 if 59 - 59: I1Ii111 % OOooOOo . I1IiiI + I1ii11iIi11i % oO0o
 oOoOOOO = OoOooO00 . packet_json [ 0 ] [ "paths" ] [ 0 ] [ "srloc" ]
 if ( I11iiiiiII1 == "?" ) :
  lprint ( "LISP-Trace return to sender RLOC {}" . format ( oOoOOOO ) )
  OoOooO00 . return_to_sender ( lisp_socket , oOoOOOO , OO00oo0 )
  return ( False )
  if 27 - 27: OoOoOO00 . I11i - Ii1I
  if 82 - 82: I1IiiI + OoOoOO00 . II111iiii / OoOoOO00 % OoOoOO00 . I1ii11iIi11i
  if 19 - 19: iIii1I11I1II1 . iIii1I11I1II1 + OOooOOo - I1ii11iIi11i
  if 59 - 59: i11iIiiIii / oO0o * IiII . o0oOOo0O0Ooo % Ii1I
  if 95 - 95: OoooooooOO - I1IiiI * I1ii11iIi11i
  if 52 - 52: oO0o % iII111i - I1IiiI - o0oOOo0O0Ooo
 iIi1IIiIII1 = OoOooO00 . packet_length ( )
 if 66 - 66: o0oOOo0O0Ooo - Oo0Ooo - OoooooooOO * o0oOOo0O0Ooo + I1Ii111
 if 82 - 82: I11i * i1IIi / Ii1I + O0
 if 85 - 85: O0 + oO0o / I1Ii111
 if 65 - 65: o0oOOo0O0Ooo . Oo0Ooo . i1IIi / IiII . I11i . O0
 if 69 - 69: Oo0Ooo - i11iIiiIii
 if 87 - 87: Oo0Ooo % OOooOOo - Ii1I
 I1i11i1i1iI = packet . packet [ 0 : ii ]
 i111 = struct . pack ( "HH" , socket . htons ( iIi1IIiIII1 ) , 0 )
 I1i11i1i1iI = I1i11i1i1iI [ 0 : ii - 4 ] + i111
 if ( packet . inner_version == 6 and iiIIIIiI111 [ "node" ] == "ETR" and
 len ( OoOooO00 . packet_json ) == 2 ) :
  OOOOo00oo00O = I1i11i1i1iI [ ii - 8 : : ] + OO00oo0
  OOOOo00oo00O = lisp_udp_checksum ( oOoO , iII1I1iiII11I , OOOOo00oo00O )
  I1i11i1i1iI = I1i11i1i1iI [ 0 : ii - 8 ] + OOOOo00oo00O [ 0 : 8 ]
  if 11 - 11: iIii1I11I1II1 % IiII . I11i
  if 59 - 59: O0 + II111iiii + IiII % Oo0Ooo
  if 71 - 71: oO0o
  if 75 - 75: Oo0Ooo * oO0o + iIii1I11I1II1 / Oo0Ooo
  if 51 - 51: Ii1I * Ii1I + iII111i * oO0o / OOooOOo - ooOoO0o
  if 16 - 16: I1Ii111 + O0 - O0 * iIii1I11I1II1 / iII111i
 if ( oo0Oo00o000 ) :
  if ( packet . inner_version == 4 ) :
   I1i11i1i1iI = I1i11i1i1iI [ 0 : 12 ] + I1i11i1i1iI [ 16 : 20 ] + I1i11i1i1iI [ 12 : 16 ] + I1i11i1i1iI [ 22 : 24 ] + I1i11i1i1iI [ 20 : 22 ] + I1i11i1i1iI [ 24 : : ]
   if 4 - 4: iII111i
  else :
   I1i11i1i1iI = I1i11i1i1iI [ 0 : 8 ] + I1i11i1i1iI [ 24 : 40 ] + I1i11i1i1iI [ 8 : 24 ] + I1i11i1i1iI [ 42 : 44 ] + I1i11i1i1iI [ 40 : 42 ] + I1i11i1i1iI [ 44 : : ]
   if 75 - 75: I1IiiI * IiII % OoO0O00 - ooOoO0o * iII111i
   if 32 - 32: iII111i
  i1 = packet . inner_dest
  packet . inner_dest = packet . inner_source
  packet . inner_source = i1
  if 59 - 59: OoOoOO00 - I1Ii111
  if 34 - 34: ooOoO0o . OoooooooOO / ooOoO0o + OoooooooOO
  if 24 - 24: OoooooooOO * I1ii11iIi11i / O0 / Oo0Ooo * I1IiiI / ooOoO0o
  if 33 - 33: Ii1I
  if 20 - 20: Ii1I + I11i
 ii = 2 if packet . inner_version == 4 else 4
 oOoooOo0O0 = 20 + iIi1IIiIII1 if packet . inner_version == 4 else iIi1IIiIII1
 O0Ooo000 = struct . pack ( "H" , socket . htons ( oOoooOo0O0 ) )
 I1i11i1i1iI = I1i11i1i1iI [ 0 : ii ] + O0Ooo000 + I1i11i1i1iI [ ii + 2 : : ]
 if 63 - 63: OoO0O00
 if 66 - 66: iIii1I11I1II1
 if 98 - 98: iII111i . oO0o % I1Ii111 + Oo0Ooo
 if 83 - 83: Oo0Ooo % oO0o - iII111i
 if ( packet . inner_version == 4 ) :
  iI1I1iII1iII = struct . pack ( "H" , 0 )
  I1i11i1i1iI = I1i11i1i1iI [ 0 : 10 ] + iI1I1iII1iII + I1i11i1i1iI [ 12 : : ]
  O0Ooo000 = lisp_ip_checksum ( I1i11i1i1iI [ 0 : 20 ] )
  I1i11i1i1iI = O0Ooo000 + I1i11i1i1iI [ 20 : : ]
  if 49 - 49: oO0o / OoooooooOO . OoooooooOO
  if 1 - 1: I1IiiI - O0
  if 98 - 98: i11iIiiIii
  if 52 - 52: iIii1I11I1II1 - OoO0O00 * Ii1I - i11iIiiIii
  if 88 - 88: o0oOOo0O0Ooo - I1IiiI / I1IiiI
 packet . packet = I1i11i1i1iI + OO00oo0
 return ( True )
 if 54 - 54: i1IIi + IiII . iIii1I11I1II1 + O0 * IiII - OOooOOo
 if 41 - 41: ooOoO0o . O0 * iII111i / iIii1I11I1II1 * OOooOOo . II111iiii
 if 92 - 92: I1ii11iIi11i / I1ii11iIi11i . o0oOOo0O0Ooo + OoooooooOO . II111iiii
 if 60 - 60: oO0o / OoOoOO00 % I1ii11iIi11i . ooOoO0o + iII111i - iIii1I11I1II1
 if 20 - 20: o0oOOo0O0Ooo . IiII / ooOoO0o / o0oOOo0O0Ooo - OoooooooOO / oO0o
 if 40 - 40: OOooOOo * OoO0O00
 if 21 - 21: oO0o
 if 30 - 30: I1ii11iIi11i . O0 . Oo0Ooo
 if 23 - 23: i11iIiiIii / I11i + i1IIi % I1Ii111
 if 100 - 100: Oo0Ooo
def lisp_allow_gleaning ( eid , rloc ) :
 if ( lisp_glean_mappings == [ ] ) : return ( False , False )
 if 13 - 13: I1IiiI + ooOoO0o * II111iiii
 for iiIIIIiI111 in lisp_glean_mappings :
  if ( iiIIIIiI111 . has_key ( "instance-id" ) ) :
   II1 = eid . instance_id
   ii11 , OO0o = iiIIIIiI111 [ "instance-id" ]
   if ( II1 < ii11 or II1 > OO0o ) : continue
   if 32 - 32: iIii1I11I1II1 + O0 + i1IIi
  if ( iiIIIIiI111 . has_key ( "eid-prefix" ) ) :
   Oo0ooo0Ooo = copy . deepcopy ( iiIIIIiI111 [ "eid-prefix" ] )
   Oo0ooo0Ooo . instance_id = eid . instance_id
   if ( eid . is_more_specific ( Oo0ooo0Ooo ) == False ) : continue
   if 28 - 28: IiII + I11i
  if ( iiIIIIiI111 . has_key ( "rloc-prefix" ) ) :
   if ( rloc != None and rloc . is_more_specific ( iiIIIIiI111 [ "rloc-prefix" ] )
 == False ) : continue
   if 1 - 1: OoooooooOO - i11iIiiIii . OoooooooOO - o0oOOo0O0Ooo - OOooOOo * I1Ii111
  return ( True , iiIIIIiI111 [ "rloc-probe" ] )
  if 56 - 56: Ii1I . OoO0O00
 return ( False , False )
 if 43 - 43: iII111i * iII111i
 if 31 - 31: O0 - iIii1I11I1II1 . I11i . oO0o
 if 96 - 96: OoooooooOO * iIii1I11I1II1 * Oo0Ooo
 if 76 - 76: OoO0O00 / i11iIiiIii % ooOoO0o % I11i * O0
 if 84 - 84: II111iiii - iII111i / IiII . O0 % i1IIi / I1ii11iIi11i
 if 2 - 2: OoooooooOO . OoO0O00 . II111iiii / Ii1I - OOooOOo % Oo0Ooo
 if 47 - 47: OOooOOo * oO0o
def lisp_glean_map_cache ( eid , rloc , encap_port ) :
 if 41 - 41: OoooooooOO * I1IiiI
 if 3 - 3: IiII
 if 96 - 96: I11i - OOooOOo + I11i
 if 71 - 71: Oo0Ooo
 if 48 - 48: o0oOOo0O0Ooo / II111iiii / OoOoOO00 * o0oOOo0O0Ooo + I1IiiI . OoOoOO00
 if 52 - 52: Ii1I / OoOoOO00 . OOooOOo * IiII . OoooooooOO
 ooooOoo000O = lisp_map_cache . lookup_cache ( eid , True )
 if ( ooooOoo000O and len ( ooooOoo000O . rloc_set ) != 0 ) :
  ooooOoo000O . last_refresh_time = lisp_get_timestamp ( )
  if 6 - 6: i1IIi . oO0o % IiII . Oo0Ooo % I11i
  Oo00oO = ooooOoo000O . rloc_set [ 0 ]
  if ( Oo00oO . rloc . is_exact_match ( rloc ) and
 Oo00oO . translated_port == encap_port ) : return
  if 1 - 1: i1IIi * I1ii11iIi11i
  Oo0ooo0Ooo = green ( eid . print_address ( ) , False )
  Oo0O = red ( rloc . print_address_no_iid ( ) + ":" + str ( encap_port ) , False )
  lprint ( "Gleaned EID {} RLOC changed to {}" . format ( Oo0ooo0Ooo , Oo0O ) )
  Oo00oO . delete_from_rloc_probe_list ( ooooOoo000O . eid , ooooOoo000O . group )
 else :
  ooooOoo000O = lisp_mapping ( "" , "" , [ ] )
  ooooOoo000O . eid . copy_address ( eid )
  ooooOoo000O . mapping_source . copy_address ( rloc )
  ooooOoo000O . map_cache_ttl = LISP_GLEAN_TTL
  ooooOoo000O . gleaned = True
  Oo0ooo0Ooo = green ( eid . print_address ( ) , False )
  Oo0O = red ( rloc . print_address_no_iid ( ) + ":" + str ( encap_port ) , False )
  lprint ( "Add gleaned EID {} to map-cache with RLOC {}" . format ( Oo0ooo0Ooo , Oo0O ) )
  ooooOoo000O . add_cache ( )
  if 92 - 92: I1ii11iIi11i + I11i - I11i - IiII . I11i
  if 34 - 34: iIii1I11I1II1 - oO0o * i11iIiiIii * o0oOOo0O0Ooo
  if 15 - 15: I1Ii111
  if 25 - 25: I1ii11iIi11i * O0
  if 8 - 8: i11iIiiIii
  if 95 - 95: ooOoO0o + i1IIi / OOooOOo . i11iIiiIii
 O0OO0O = lisp_rloc ( )
 O0OO0O . store_translated_rloc ( rloc , encap_port )
 O0OO0O . add_to_rloc_probe_list ( ooooOoo000O . eid , ooooOoo000O . group )
 O0OO0O . priority = 253
 O0OO0O . mpriority = 255
 iiiI11II1IiIi = [ O0OO0O ]
 ooooOoo000O . rloc_set = iiiI11II1IiIi
 ooooOoo000O . build_best_rloc_set ( )
 if 31 - 31: iII111i - iII111i - oO0o
 if 62 - 62: Oo0Ooo % Oo0Ooo / OoooooooOO * o0oOOo0O0Ooo . Ii1I
 if 1 - 1: I1ii11iIi11i / II111iiii / II111iiii + o0oOOo0O0Ooo + OoooooooOO
# dd678faae9ac167bc83abf78e5cb2f3f0688d3a3
