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
LISP_DATA_PORT = 4341
LISP_CTRL_PORT = 4342
LISP_L2_DATA_PORT = 8472
LISP_VXLAN_DATA_PORT = 4789
LISP_VXLAN_GPE_PORT = 4790
LISP_TRACE_PORT = 2434
if 49 - 49: I1IiiI - I11i
if 74 - 74: iIii1I11I1II1 * I1ii11iIi11i + OoOoOO00 / i1IIi / II111iiii . Oo0Ooo
if 62 - 62: OoooooooOO * I1IiiI
if 58 - 58: OoOoOO00 % o0oOOo0O0Ooo
LISP_MAP_REQUEST = 1
LISP_MAP_REPLY = 2
LISP_MAP_REGISTER = 3
LISP_MAP_NOTIFY = 4
LISP_MAP_NOTIFY_ACK = 5
LISP_MAP_REFERRAL = 6
LISP_NAT_INFO = 7
LISP_ECM = 8
LISP_TRACE = 9
if 50 - 50: I1Ii111 . o0oOOo0O0Ooo
if 97 - 97: O0 + OoOoOO00
if 89 - 89: o0oOOo0O0Ooo + OoO0O00 * I11i * Ii1I
if 37 - 37: OoooooooOO - O0 - o0oOOo0O0Ooo
LISP_NO_ACTION = 0
LISP_NATIVE_FORWARD_ACTION = 1
LISP_SEND_MAP_REQUEST_ACTION = 2
LISP_DROP_ACTION = 3
LISP_POLICY_DENIED_ACTION = 4
LISP_AUTH_FAILURE_ACTION = 5
if 77 - 77: OOooOOo * iIii1I11I1II1
lisp_map_reply_action_string = [ "no-action" , "native-forward" ,
 "send-map-request" , "drop-action" , "policy-denied" , "auth-failure" ]
if 98 - 98: I1IiiI % Ii1I * OoooooooOO
if 51 - 51: iIii1I11I1II1 . OoOoOO00 / oO0o + o0oOOo0O0Ooo
if 33 - 33: ooOoO0o . II111iiii % iII111i + o0oOOo0O0Ooo
if 71 - 71: Oo0Ooo % OOooOOo
LISP_NONE_ALG_ID = 0
LISP_SHA_1_96_ALG_ID = 1
LISP_SHA_256_128_ALG_ID = 2
LISP_MD5_AUTH_DATA_LEN = 16
LISP_SHA1_160_AUTH_DATA_LEN = 20
LISP_SHA2_256_AUTH_DATA_LEN = 32
if 98 - 98: I11i % i11iIiiIii % ooOoO0o + Ii1I
if 78 - 78: I1ii11iIi11i % oO0o / iII111i - iIii1I11I1II1
if 69 - 69: I1Ii111
if 11 - 11: I1IiiI
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
if 16 - 16: Ii1I + IiII * O0 % i1IIi . I1IiiI
if 67 - 67: OoooooooOO / I1IiiI * Ii1I + I11i
if 65 - 65: OoooooooOO - I1ii11iIi11i / ooOoO0o / II111iiii / i1IIi
if 71 - 71: I1Ii111 + Ii1I
LISP_MR_TTL = ( 24 * 60 )
LISP_REGISTER_TTL = 3
LISP_SHORT_TTL = 1
LISP_NMR_TTL = 15
if 28 - 28: OOooOOo
LISP_SITE_TIMEOUT_CHECK_INTERVAL = 60
LISP_PUBSUB_TIMEOUT_CHECK_INTERVAL = 60
LISP_REFERRAL_TIMEOUT_CHECK_INTERVAL = 60
LISP_TEST_MR_INTERVAL = 60
LISP_MAP_NOTIFY_INTERVAL = 2
LISP_DDT_MAP_REQUEST_INTERVAL = 2
LISP_MAX_MAP_NOTIFY_RETRIES = 3
LISP_INFO_INTERVAL = 15
LISP_MAP_REQUEST_RATE_LIMIT = 5
if 38 - 38: ooOoO0o % II111iiii % I11i / OoO0O00 + OoOoOO00 / i1IIi
LISP_RLOC_PROBE_TTL = 64
LISP_RLOC_PROBE_INTERVAL = 10
LISP_RLOC_PROBE_REPLY_WAIT = 15
if 54 - 54: iIii1I11I1II1 % I1ii11iIi11i - OOooOOo / oO0o - OoO0O00 . I11i
LISP_DEFAULT_DYN_EID_TIMEOUT = 15
LISP_NONCE_ECHO_INTERVAL = 10
if 11 - 11: I1ii11iIi11i . OoO0O00 * IiII * OoooooooOO + ooOoO0o
if 33 - 33: O0 * o0oOOo0O0Ooo - I1Ii111 % I1Ii111
if 18 - 18: I1Ii111 / Oo0Ooo * I1Ii111 + I1Ii111 * i11iIiiIii * I1ii11iIi11i
if 11 - 11: ooOoO0o / OoOoOO00 - IiII * OoooooooOO + OoooooooOO . OoOoOO00
if 26 - 26: Ii1I % I1ii11iIi11i
if 76 - 76: IiII * iII111i
if 52 - 52: OOooOOo
if 19 - 19: I1IiiI
if 25 - 25: Ii1I / ooOoO0o
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
LISP_CS_1024 = 0
LISP_CS_1024_G = 2
LISP_CS_1024_P = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF
if 28 - 28: Oo0Ooo + OoO0O00 * OOooOOo % oO0o . I11i % O0
LISP_CS_2048_CBC = 1
LISP_CS_2048_CBC_G = 2
LISP_CS_2048_CBC_P = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF
if 16 - 16: I11i - iIii1I11I1II1 / I1IiiI . II111iiii + iIii1I11I1II1
LISP_CS_25519_CBC = 2
LISP_CS_2048_GCM = 3
if 19 - 19: OoO0O00 - Oo0Ooo . O0
LISP_CS_3072 = 4
LISP_CS_3072_G = 2
LISP_CS_3072_P = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF
if 60 - 60: II111iiii + Oo0Ooo
LISP_CS_25519_GCM = 5
LISP_CS_25519_CHACHA = 6
if 9 - 9: ooOoO0o * OoooooooOO - iIii1I11I1II1 + OoOoOO00 / OoO0O00 . OoO0O00
LISP_4_32_MASK = 0xFFFFFFFF
LISP_8_64_MASK = 0xFFFFFFFFFFFFFFFF
LISP_16_128_MASK = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
if 49 - 49: II111iiii
if 25 - 25: OoooooooOO - I1IiiI . I1IiiI * oO0o
if 81 - 81: iII111i + IiII
if 98 - 98: I1IiiI
if 95 - 95: ooOoO0o / ooOoO0o
if 30 - 30: I1ii11iIi11i + Oo0Ooo / Oo0Ooo % I1ii11iIi11i . I1ii11iIi11i
if 55 - 55: ooOoO0o - I11i + II111iiii + iII111i % Ii1I
if 41 - 41: i1IIi - I11i - Ii1I
def lisp_record_traceback ( * args ) :
 III11I1 = datetime . datetime . now ( ) . strftime ( "%m/%d/%y %H:%M:%S.%f" ) [ : - 3 ]
 IIi1IIIi = open ( "./logs/lisp-traceback.log" , "a" )
 IIi1IIIi . write ( "---------- Exception occurred: {} ----------\n" . format ( III11I1 ) )
 try :
  traceback . print_last ( file = IIi1IIIi )
 except :
  IIi1IIIi . write ( "traceback.print_last(file=fd) failed" )
  if 99 - 99: Ii1I + OoO0O00 * II111iiii . o0oOOo0O0Ooo - I1ii11iIi11i
 try :
  traceback . print_last ( )
 except :
  print ( "traceback.print_last() failed" )
  if 58 - 58: Ii1I + o0oOOo0O0Ooo - I1IiiI
 IIi1IIIi . close ( )
 return
 if 3 - 3: OoO0O00
 if 97 - 97: I1Ii111
 if 15 - 15: i1IIi + OoOoOO00
 if 48 - 48: I1IiiI % iII111i / iIii1I11I1II1
 if 85 - 85: OoooooooOO % i1IIi * OoooooooOO / I1ii11iIi11i
 if 96 - 96: OoooooooOO + oO0o
 if 44 - 44: oO0o
def lisp_set_exception ( ) :
 sys . excepthook = lisp_record_traceback
 return
 if 20 - 20: I11i + Ii1I / O0 % iIii1I11I1II1
 if 88 - 88: OoOoOO00 / II111iiii
 if 87 - 87: I1ii11iIi11i - I1ii11iIi11i - iII111i + oO0o
 if 82 - 82: oO0o / iIii1I11I1II1 . I1IiiI . OOooOOo / o0oOOo0O0Ooo
 if 42 - 42: Oo0Ooo
 if 19 - 19: oO0o % I1ii11iIi11i * iIii1I11I1II1 + I1IiiI
 if 46 - 46: Oo0Ooo
def lisp_is_raspbian ( ) :
 if ( platform . dist ( ) [ 0 ] != "debian" ) : return ( False )
 return ( platform . machine ( ) in [ "armv6l" , "armv7l" ] )
 if 1 - 1: iII111i
 if 97 - 97: OOooOOo + iII111i + O0 + i11iIiiIii
 if 77 - 77: o0oOOo0O0Ooo / OoooooooOO
 if 46 - 46: o0oOOo0O0Ooo % iIii1I11I1II1 . iII111i % iII111i + i11iIiiIii
 if 72 - 72: iIii1I11I1II1 * Ii1I % ooOoO0o / OoO0O00
 if 35 - 35: ooOoO0o + i1IIi % I1ii11iIi11i % I11i + oO0o
 if 17 - 17: i1IIi
def lisp_is_ubuntu ( ) :
 return ( platform . dist ( ) [ 0 ] == "Ubuntu" )
 if 21 - 21: Oo0Ooo
 if 29 - 29: I11i / II111iiii / ooOoO0o * OOooOOo
 if 10 - 10: I1Ii111 % IiII * IiII . I11i / Ii1I % OOooOOo
 if 49 - 49: OoO0O00 / oO0o + O0 * o0oOOo0O0Ooo
 if 28 - 28: ooOoO0o + i11iIiiIii / I11i % OoOoOO00 % Oo0Ooo - O0
 if 54 - 54: i1IIi + II111iiii
 if 83 - 83: I1ii11iIi11i - I1IiiI + OOooOOo
def lisp_is_fedora ( ) :
 return ( platform . dist ( ) [ 0 ] == "fedora" )
 if 5 - 5: Ii1I
 if 46 - 46: IiII
 if 45 - 45: ooOoO0o
 if 21 - 21: oO0o . I1Ii111 . OOooOOo / Oo0Ooo / I1Ii111
 if 17 - 17: OOooOOo / OOooOOo / I11i
 if 1 - 1: i1IIi . i11iIiiIii % OOooOOo
 if 82 - 82: iIii1I11I1II1 + Oo0Ooo . iIii1I11I1II1 % IiII / Ii1I . Ii1I
def lisp_is_centos ( ) :
 return ( platform . dist ( ) [ 0 ] == "centos" )
 if 14 - 14: o0oOOo0O0Ooo . OOooOOo . I11i + OoooooooOO - OOooOOo + IiII
 if 9 - 9: Ii1I
 if 59 - 59: I1IiiI * II111iiii . O0
 if 56 - 56: Ii1I - iII111i % I1IiiI - o0oOOo0O0Ooo
 if 51 - 51: O0 / ooOoO0o * iIii1I11I1II1 + I1ii11iIi11i + o0oOOo0O0Ooo
 if 98 - 98: iIii1I11I1II1 * I1ii11iIi11i * OOooOOo + ooOoO0o % i11iIiiIii % O0
 if 27 - 27: O0
def lisp_is_debian ( ) :
 return ( platform . dist ( ) [ 0 ] == "debian" )
 if 79 - 79: o0oOOo0O0Ooo - I11i + o0oOOo0O0Ooo . oO0o
 if 28 - 28: i1IIi - iII111i
 if 54 - 54: iII111i - O0 % OOooOOo
 if 73 - 73: O0 . OoOoOO00 + I1IiiI - I11i % I11i . I11i
 if 17 - 17: Ii1I - OoooooooOO % Ii1I . IiII / i11iIiiIii % iII111i
 if 28 - 28: I11i
 if 58 - 58: OoOoOO00
def lisp_is_debian_kali ( ) :
 return ( platform . dist ( ) [ 0 ] == "Kali" )
 if 37 - 37: Oo0Ooo - iIii1I11I1II1 / I1ii11iIi11i
 if 73 - 73: i11iIiiIii - IiII
 if 25 - 25: OoooooooOO + IiII * I1ii11iIi11i
 if 92 - 92: I1IiiI + I11i + O0 / o0oOOo0O0Ooo + I1Ii111
 if 18 - 18: ooOoO0o * OoOoOO00 . iII111i / I1ii11iIi11i / i11iIiiIii
 if 21 - 21: oO0o / I1ii11iIi11i + Ii1I + OoooooooOO
 if 91 - 91: i11iIiiIii / i1IIi + iII111i + ooOoO0o * i11iIiiIii
def lisp_is_macos ( ) :
 return ( platform . uname ( ) [ 0 ] == "Darwin" )
 if 66 - 66: iIii1I11I1II1 % i1IIi - O0 + I11i * I1Ii111 . IiII
 if 52 - 52: ooOoO0o + O0 . iII111i . I1ii11iIi11i . OoO0O00
 if 97 - 97: I1IiiI / iII111i
 if 71 - 71: II111iiii / i1IIi . I1ii11iIi11i % OoooooooOO . OoOoOO00
 if 41 - 41: i1IIi * II111iiii / OoooooooOO . OOooOOo
 if 83 - 83: iII111i . O0 / Oo0Ooo / OOooOOo - II111iiii
 if 100 - 100: OoO0O00
def lisp_is_alpine ( ) :
 return ( os . path . exists ( "/etc/alpine-release" ) )
 if 46 - 46: OoOoOO00 / iIii1I11I1II1 % iII111i . iIii1I11I1II1 * iII111i
 if 38 - 38: I1ii11iIi11i - iII111i / O0 . I1Ii111
 if 45 - 45: I1Ii111
 if 83 - 83: OoOoOO00 . OoooooooOO
 if 58 - 58: i11iIiiIii + OoooooooOO % OoooooooOO / IiII / i11iIiiIii
 if 62 - 62: OoO0O00 / I1ii11iIi11i
 if 7 - 7: OoooooooOO . IiII
def lisp_is_x86 ( ) :
 O000OOO0OOo = platform . machine ( )
 return ( O000OOO0OOo in ( "x86" , "i686" , "x86_64" ) )
 if 32 - 32: Ii1I * O0
 if 100 - 100: ooOoO0o % iIii1I11I1II1 * II111iiii - iII111i
 if 92 - 92: ooOoO0o
 if 22 - 22: Oo0Ooo % iII111i * I1ii11iIi11i / OOooOOo % i11iIiiIii * I11i
 if 95 - 95: OoooooooOO - IiII * I1IiiI + OoOoOO00
 if 10 - 10: o0oOOo0O0Ooo / i11iIiiIii
 if 92 - 92: I11i . I1Ii111
def lisp_is_linux ( ) :
 return ( platform . uname ( ) [ 0 ] == "Linux" )
 if 85 - 85: I1ii11iIi11i . I1Ii111
 if 78 - 78: ooOoO0o * I1Ii111 + iIii1I11I1II1 + iIii1I11I1II1 / I1Ii111 . Ii1I
 if 97 - 97: ooOoO0o / I1Ii111 % i1IIi % I1ii11iIi11i
 if 18 - 18: iIii1I11I1II1 % I11i
 if 95 - 95: ooOoO0o + i11iIiiIii * I1Ii111 - i1IIi * I1Ii111 - iIii1I11I1II1
 if 75 - 75: OoooooooOO * IiII
 if 9 - 9: IiII - II111iiii + O0 / iIii1I11I1II1 / i11iIiiIii
 if 39 - 39: IiII * Oo0Ooo + iIii1I11I1II1 - IiII + OOooOOo
def lisp_process_logfile ( ) :
 o0 = "./logs/lisp-{}.log" . format ( lisp_log_id )
 if ( os . path . exists ( o0 ) ) : return
 if 30 - 30: O0 * OoooooooOO
 sys . stdout . close ( )
 sys . stdout = open ( o0 , "a" )
 if 38 - 38: IiII - I1ii11iIi11i . OoOoOO00 - I1Ii111 . OoooooooOO
 lisp_print_banner ( bold ( "logfile rotation" , False ) )
 return
 if 89 - 89: iIii1I11I1II1
 if 21 - 21: I11i % I11i
 if 27 - 27: i11iIiiIii / I1ii11iIi11i
 if 84 - 84: Oo0Ooo
 if 43 - 43: oO0o - OoooooooOO
 if 3 - 3: O0 / iII111i
 if 31 - 31: OOooOOo + o0oOOo0O0Ooo . OoooooooOO
 if 89 - 89: II111iiii + i1IIi + II111iiii
def lisp_i_am ( name ) :
 global lisp_log_id , lisp_i_am_itr , lisp_i_am_etr , lisp_i_am_rtr
 global lisp_i_am_mr , lisp_i_am_ms , lisp_i_am_ddt , lisp_i_am_core
 global lisp_hostname
 if 7 - 7: O0 % o0oOOo0O0Ooo + I1ii11iIi11i * iII111i - iII111i
 lisp_log_id = name
 if ( name == "itr" ) : lisp_i_am_itr = True
 if ( name == "etr" ) : lisp_i_am_etr = True
 if ( name == "rtr" ) : lisp_i_am_rtr = True
 if ( name == "mr" ) : lisp_i_am_mr = True
 if ( name == "ms" ) : lisp_i_am_ms = True
 if ( name == "ddt" ) : lisp_i_am_ddt = True
 if ( name == "core" ) : lisp_i_am_core = True
 if 42 - 42: OoOoOO00 * OoOoOO00 * I1Ii111 . I11i
 if 51 - 51: OOooOOo % iIii1I11I1II1 - OoooooooOO % ooOoO0o * iIii1I11I1II1 % OoO0O00
 if 99 - 99: oO0o * II111iiii * I1Ii111
 if 92 - 92: Oo0Ooo
 if 40 - 40: OoOoOO00 / IiII
 lisp_hostname = socket . gethostname ( )
 OOOoO000 = lisp_hostname . find ( "." )
 if ( OOOoO000 != - 1 ) : lisp_hostname = lisp_hostname [ 0 : OOOoO000 ]
 return
 if 57 - 57: II111iiii
 if 54 - 54: Oo0Ooo + oO0o + i11iIiiIii
 if 28 - 28: oO0o
 if 70 - 70: IiII
 if 34 - 34: I1Ii111 % IiII
 if 3 - 3: II111iiii / OOooOOo + IiII . ooOoO0o . OoO0O00
 if 83 - 83: oO0o + OoooooooOO
def lprint ( * args ) :
 if ( lisp_debug_logging == False ) : return
 if 22 - 22: Ii1I % iII111i * OoooooooOO - o0oOOo0O0Ooo / iIii1I11I1II1
 lisp_process_logfile ( )
 III11I1 = datetime . datetime . now ( ) . strftime ( "%m/%d/%y %H:%M:%S.%f" )
 III11I1 = III11I1 [ : - 3 ]
 print "{}: {}:" . format ( III11I1 , lisp_log_id ) ,
 for Oo in args : print Oo ,
 print ""
 try : sys . stdout . flush ( )
 except : pass
 return
 if 84 - 84: OoOoOO00 / I11i * iII111i / oO0o - i11iIiiIii . Oo0Ooo
 if 60 - 60: I1ii11iIi11i * I1IiiI
 if 17 - 17: OOooOOo % Oo0Ooo / I1ii11iIi11i . IiII * OOooOOo - II111iiii
 if 41 - 41: Ii1I
 if 77 - 77: I1Ii111
 if 65 - 65: II111iiii . I1IiiI % oO0o * OoO0O00
 if 38 - 38: OoOoOO00 / iII111i % Oo0Ooo
 if 11 - 11: iII111i - oO0o + II111iiii - iIii1I11I1II1
def dprint ( * args ) :
 if ( lisp_data_plane_logging ) : lprint ( * args )
 return
 if 7 - 7: IiII - I11i / II111iiii * Ii1I . iII111i * iII111i
 if 61 - 61: I11i % ooOoO0o - OoO0O00 / Oo0Ooo
 if 4 - 4: OoooooooOO - i1IIi % Ii1I - OOooOOo * o0oOOo0O0Ooo
 if 85 - 85: OoooooooOO * iIii1I11I1II1 . iII111i / OoooooooOO % I1IiiI % O0
 if 36 - 36: Ii1I / II111iiii / IiII / IiII + I1ii11iIi11i
 if 95 - 95: IiII
 if 51 - 51: II111iiii + IiII . i1IIi . I1ii11iIi11i + OoOoOO00 * I1IiiI
 if 72 - 72: oO0o + oO0o / II111iiii . OoooooooOO % Ii1I
def debug ( * args ) :
 lisp_process_logfile ( )
 if 49 - 49: oO0o . OoO0O00 - Oo0Ooo * OoooooooOO . Oo0Ooo
 III11I1 = datetime . datetime . now ( ) . strftime ( "%m/%d/%y %H:%M:%S.%f" )
 III11I1 = III11I1 [ : - 3 ]
 if 2 - 2: OoooooooOO % OOooOOo
 print red ( ">>>" , False ) ,
 print "{}:" . format ( III11I1 ) ,
 for Oo in args : print Oo ,
 print red ( "<<<\n" , False )
 try : sys . stdout . flush ( )
 except : pass
 return
 if 63 - 63: I1IiiI % iIii1I11I1II1
 if 39 - 39: iII111i / II111iiii / I1ii11iIi11i % I1IiiI
 if 89 - 89: I1Ii111 + OoooooooOO + I1Ii111 * i1IIi + iIii1I11I1II1 % I11i
 if 59 - 59: OOooOOo + i11iIiiIii
 if 88 - 88: i11iIiiIii - ooOoO0o
 if 67 - 67: OOooOOo . Oo0Ooo + OoOoOO00 - OoooooooOO
 if 70 - 70: OOooOOo / II111iiii - iIii1I11I1II1 - iII111i
def lisp_print_banner ( string ) :
 global lisp_version , lisp_hostname
 if 11 - 11: iIii1I11I1II1 . OoooooooOO . II111iiii / i1IIi - I11i
 if ( lisp_version == "" ) :
  lisp_version = commands . getoutput ( "cat lisp-version.txt" )
  if 30 - 30: OoOoOO00
 Ii111 = bold ( lisp_hostname , False )
 lprint ( "lispers.net LISP {} {}, version {}, hostname {}" . format ( string ,
 datetime . datetime . now ( ) , lisp_version , Ii111 ) )
 return
 if 67 - 67: O0
 if 52 - 52: II111iiii . ooOoO0o / OoOoOO00 / OoooooooOO . i11iIiiIii
 if 30 - 30: I11i / Ii1I . IiII . OoooooooOO - Oo0Ooo
 if 44 - 44: O0 * OoooooooOO % ooOoO0o + II111iiii
 if 39 - 39: oO0o % iIii1I11I1II1 % O0 % OoooooooOO * I1ii11iIi11i + iII111i
 if 68 - 68: Oo0Ooo + i11iIiiIii
 if 69 - 69: iIii1I11I1II1 * iIii1I11I1II1 * i11iIiiIii + I1IiiI / OOooOOo % Ii1I
def green ( string , html ) :
 if ( html ) : return ( '<font color="green"><b>{}</b></font>' . format ( string ) )
 return ( bold ( "\033[92m" + string + "\033[0m" , html ) )
 if 58 - 58: OOooOOo * o0oOOo0O0Ooo + O0 % OOooOOo
 if 25 - 25: Oo0Ooo % I1ii11iIi11i * ooOoO0o
 if 6 - 6: iII111i . IiII * OoOoOO00 . i1IIi
 if 98 - 98: i1IIi
 if 65 - 65: OoOoOO00 / OoO0O00 % IiII
 if 45 - 45: OoOoOO00
 if 66 - 66: OoO0O00
def green_last_sec ( string ) :
 return ( green ( string , True ) )
 if 56 - 56: O0
 if 61 - 61: o0oOOo0O0Ooo / OOooOOo / Oo0Ooo * O0
 if 23 - 23: oO0o - OOooOOo + I11i
 if 12 - 12: I1IiiI / ooOoO0o % o0oOOo0O0Ooo / i11iIiiIii % OoooooooOO
 if 15 - 15: iIii1I11I1II1 % OoooooooOO - Oo0Ooo * Ii1I + I11i
 if 11 - 11: iII111i * Ii1I - OoOoOO00
 if 66 - 66: OoOoOO00 . i11iIiiIii - iII111i * o0oOOo0O0Ooo + OoooooooOO * I1ii11iIi11i
def green_last_min ( string ) :
 return ( '<font color="#58D68D"><b>{}</b></font>' . format ( string ) )
 if 74 - 74: Oo0Ooo
 if 61 - 61: Oo0Ooo - I1Ii111 * II111iiii % ooOoO0o * iIii1I11I1II1 + OoO0O00
 if 71 - 71: I11i / I11i * oO0o * oO0o / II111iiii
 if 35 - 35: OOooOOo * o0oOOo0O0Ooo * I1IiiI % Oo0Ooo . OoOoOO00
 if 58 - 58: I11i + II111iiii * iII111i * i11iIiiIii - iIii1I11I1II1
 if 68 - 68: OoooooooOO % II111iiii
 if 26 - 26: II111iiii % i11iIiiIii % iIii1I11I1II1 % I11i * I11i * I1ii11iIi11i
def red ( string , html ) :
 if ( html ) : return ( '<font color="red"><b>{}</b></font>' . format ( string ) )
 return ( bold ( "\033[91m" + string + "\033[0m" , html ) )
 if 24 - 24: II111iiii % I1Ii111 - ooOoO0o + I1IiiI * I1ii11iIi11i
 if 2 - 2: Ii1I - IiII
 if 83 - 83: oO0o % o0oOOo0O0Ooo % Ii1I - II111iiii * OOooOOo / OoooooooOO
 if 18 - 18: OoO0O00 + iIii1I11I1II1 - II111iiii - I1IiiI
 if 71 - 71: OoooooooOO
 if 33 - 33: I1Ii111
 if 62 - 62: I1ii11iIi11i + Ii1I + i1IIi / OoooooooOO
def blue ( string , html ) :
 if ( html ) : return ( '<font color="blue"><b>{}</b></font>' . format ( string ) )
 return ( bold ( "\033[94m" + string + "\033[0m" , html ) )
 if 7 - 7: o0oOOo0O0Ooo + i1IIi . I1IiiI / Oo0Ooo
 if 22 - 22: ooOoO0o - ooOoO0o % OOooOOo . I1Ii111 + oO0o
 if 63 - 63: I1IiiI % I1Ii111 * o0oOOo0O0Ooo + I1Ii111 / Oo0Ooo % iII111i
 if 45 - 45: IiII
 if 20 - 20: OoooooooOO * o0oOOo0O0Ooo * O0 . OOooOOo
 if 78 - 78: iIii1I11I1II1 + I11i - Ii1I * I1Ii111 - OoooooooOO % OoOoOO00
 if 34 - 34: O0
def bold ( string , html ) :
 if ( html ) : return ( "<b>{}</b>" . format ( string ) )
 return ( "\033[1m" + string + "\033[0m" )
 if 80 - 80: i1IIi - Oo0Ooo / OoO0O00 - i11iIiiIii
 if 68 - 68: oO0o - I1ii11iIi11i % O0 % I1Ii111
 if 11 - 11: O0 / OoO0O00 % OOooOOo + o0oOOo0O0Ooo + iIii1I11I1II1
 if 40 - 40: ooOoO0o - OOooOOo . Ii1I * Oo0Ooo % I1Ii111
 if 56 - 56: i11iIiiIii . o0oOOo0O0Ooo - I1IiiI * I11i
 if 91 - 91: oO0o + OoooooooOO - i1IIi
 if 84 - 84: Ii1I / IiII
def convert_font ( string ) :
 OOOooo0OooOoO = [ [ "[91m" , red ] , [ "[92m" , green ] , [ "[94m" , blue ] , [ "[1m" , bold ] ]
 oOoOOOo = "[0m"
 if 43 - 43: i1IIi
 for I1i11II in OOOooo0OooOoO :
  II11 = I1i11II [ 0 ]
  I1iii = I1i11II [ 1 ]
  oOO0OO0O = len ( II11 )
  OOOoO000 = string . find ( II11 )
  if ( OOOoO000 != - 1 ) : break
  if 78 - 78: Ii1I / II111iiii % OoOoOO00
  if 52 - 52: OOooOOo - iII111i * oO0o
 while ( OOOoO000 != - 1 ) :
  Ii1I11I = string [ OOOoO000 : : ] . find ( oOoOOOo )
  iiIii1I = string [ OOOoO000 + oOO0OO0O : OOOoO000 + Ii1I11I ]
  string = string [ : OOOoO000 ] + I1iii ( iiIii1I , True ) + string [ OOOoO000 + Ii1I11I + oOO0OO0O : : ]
  if 47 - 47: ooOoO0o . I11i / o0oOOo0O0Ooo
  OOOoO000 = string . find ( II11 )
  if 83 - 83: o0oOOo0O0Ooo / OOooOOo / OOooOOo + o0oOOo0O0Ooo * I1Ii111 + o0oOOo0O0Ooo
  if 36 - 36: OoOoOO00 + o0oOOo0O0Ooo - OoooooooOO . oO0o . OoooooooOO / Oo0Ooo
  if 72 - 72: i1IIi
  if 82 - 82: OoOoOO00 + OoooooooOO / i11iIiiIii * I1ii11iIi11i . OoooooooOO
  if 63 - 63: I1ii11iIi11i
 if ( string . find ( "[1m" ) != - 1 ) : string = convert_font ( string )
 return ( string )
 if 6 - 6: ooOoO0o / I1ii11iIi11i
 if 57 - 57: I11i
 if 67 - 67: OoO0O00 . ooOoO0o
 if 87 - 87: oO0o % Ii1I
 if 83 - 83: II111iiii - I11i
 if 35 - 35: i1IIi - iIii1I11I1II1 + i1IIi
 if 86 - 86: iIii1I11I1II1 + OoOoOO00 . i11iIiiIii - Ii1I
def lisp_space ( num ) :
 ooO000O = ""
 for oO in range ( num ) : ooO000O += "&#160;"
 return ( ooO000O )
 if 23 - 23: Oo0Ooo % I11i - OOooOOo % iIii1I11I1II1 . OoOoOO00
 if 24 - 24: IiII / OoooooooOO + Ii1I % iIii1I11I1II1 - OOooOOo . OOooOOo
 if 32 - 32: OOooOOo . IiII / OoO0O00
 if 37 - 37: Ii1I % OoO0O00
 if 79 - 79: I1ii11iIi11i + I1IiiI / I1IiiI
 if 71 - 71: OOooOOo * OoO0O00 % OoooooooOO % OoO0O00 / I1IiiI
 if 56 - 56: OoooooooOO % i11iIiiIii * iIii1I11I1II1 . OoO0O00 * O0
def lisp_button ( string , url ) :
 iI = '<button style="background-color:transparent;border-radius:10px; ' + 'type="button">'
 if 99 - 99: I11i - I1Ii111 - oO0o % OoO0O00
 if 21 - 21: II111iiii % I1ii11iIi11i . i1IIi - OoooooooOO
 if ( url == None ) :
  ii = iI + string + "</button>"
 else :
  OOOO0o = '<a href="{}">' . format ( url )
  i1I1iIi1IiI = lisp_space ( 2 )
  ii = i1I1iIi1IiI + OOOO0o + iI + string + "</button></a>" + i1I1iIi1IiI
  if 11 - 11: II111iiii
 return ( ii )
 if 95 - 95: IiII * I1ii11iIi11i % ooOoO0o % Ii1I - Ii1I
 if 97 - 97: I1ii11iIi11i + iIii1I11I1II1 . O0
 if 64 - 64: i1IIi % ooOoO0o / i11iIiiIii - i1IIi % OOooOOo . iII111i
 if 8 - 8: Oo0Ooo + II111iiii * OOooOOo * OoOoOO00 * I11i / IiII
 if 21 - 21: oO0o / OoooooooOO
 if 11 - 11: OOooOOo % Ii1I - i11iIiiIii - oO0o + ooOoO0o + IiII
 if 87 - 87: I1Ii111 * i1IIi / I1ii11iIi11i
def lisp_print_cour ( string ) :
 ooO000O = '<font face="Courier New">{}</font>' . format ( string )
 return ( ooO000O )
 if 6 - 6: o0oOOo0O0Ooo + Oo0Ooo - OoooooooOO % OOooOOo * OoOoOO00
 if 69 - 69: i1IIi
 if 59 - 59: II111iiii - o0oOOo0O0Ooo
 if 24 - 24: Oo0Ooo - i1IIi + I11i
 if 38 - 38: OoooooooOO / I1ii11iIi11i . O0 / i1IIi / Oo0Ooo + iIii1I11I1II1
 if 96 - 96: iII111i
 if 18 - 18: iII111i * I11i - Ii1I
def lisp_print_sans ( string ) :
 ooO000O = '<font face="Sans-Serif">{}</font>' . format ( string )
 return ( ooO000O )
 if 31 - 31: Oo0Ooo - O0 % OoOoOO00 % oO0o
 if 45 - 45: I1ii11iIi11i + II111iiii * i11iIiiIii
 if 13 - 13: OoooooooOO * oO0o - Ii1I / OOooOOo + I11i + IiII
 if 39 - 39: iIii1I11I1II1 - OoooooooOO
 if 81 - 81: I1ii11iIi11i - O0 * OoooooooOO
 if 23 - 23: II111iiii / oO0o
 if 28 - 28: Oo0Ooo * ooOoO0o - OoO0O00
def lisp_span ( string , hover_string ) :
 ooO000O = '<span title="{}">{}</span>' . format ( hover_string , string )
 return ( ooO000O )
 if 19 - 19: I11i
 if 67 - 67: O0 % iIii1I11I1II1 / IiII . i11iIiiIii - Ii1I + O0
 if 27 - 27: OOooOOo
 if 89 - 89: II111iiii / oO0o
 if 14 - 14: OOooOOo . I1IiiI * ooOoO0o + II111iiii - ooOoO0o + OOooOOo
 if 18 - 18: oO0o - o0oOOo0O0Ooo - I1IiiI - I1IiiI
 if 54 - 54: Oo0Ooo + I1IiiI / iII111i . I1IiiI * OoOoOO00
def lisp_eid_help_hover ( output ) :
 IIiIiiiIIIIi1 = '''Unicast EID format:
  For longest match lookups: 
    <address> or [<iid>]<address>
  For exact match lookups: 
    <prefix> or [<iid>]<prefix>
Multicast EID format:
  For longest match lookups:
    <address>-><group> or
    [<iid>]<address>->[<iid>]<group>'''
 if 39 - 39: OoO0O00 / Ii1I / I1Ii111
 if 81 - 81: I11i / OoO0O00 % OoooooooOO * oO0o / oO0o
 IiiI = lisp_span ( output , IIiIiiiIIIIi1 )
 return ( IiiI )
 if 19 - 19: II111iiii
 if 72 - 72: OoooooooOO / I1IiiI + Ii1I / OoOoOO00 * Ii1I
 if 34 - 34: O0 * O0 % OoooooooOO + iII111i * iIii1I11I1II1 % Ii1I
 if 25 - 25: I11i + OoOoOO00 . o0oOOo0O0Ooo % OoOoOO00 * OOooOOo
 if 32 - 32: i11iIiiIii - I1Ii111
 if 53 - 53: OoooooooOO - IiII
 if 87 - 87: oO0o . I1IiiI
def lisp_geo_help_hover ( output ) :
 IIiIiiiIIIIi1 = '''EID format:
    <address> or [<iid>]<address>
    '<name>' or [<iid>]'<name>'
Geo-Point format:
    d-m-s-<N|S>-d-m-s-<W|E> or 
    [<iid>]d-m-s-<N|S>-d-m-s-<W|E>
Geo-Prefix format:
    d-m-s-<N|S>-d-m-s-<W|E>/<km> or
    [<iid>]d-m-s-<N|S>-d-m-s-<W|E>/<km>'''
 if 17 - 17: Ii1I . i11iIiiIii
 if 5 - 5: I1ii11iIi11i + O0 + O0 . I1Ii111 - ooOoO0o
 IiiI = lisp_span ( output , IIiIiiiIIIIi1 )
 return ( IiiI )
 if 63 - 63: oO0o
 if 71 - 71: i1IIi . Ii1I * iII111i % OoooooooOO + OOooOOo
 if 36 - 36: IiII
 if 49 - 49: OOooOOo / OoooooooOO / I1IiiI
 if 74 - 74: I1Ii111 % I1ii11iIi11i
 if 7 - 7: II111iiii
 if 27 - 27: oO0o . OoooooooOO + i11iIiiIii
def space ( num ) :
 ooO000O = ""
 for oO in range ( num ) : ooO000O += "&#160;"
 return ( ooO000O )
 if 86 - 86: I11i / o0oOOo0O0Ooo - o0oOOo0O0Ooo + I1ii11iIi11i + oO0o
 if 33 - 33: o0oOOo0O0Ooo . iII111i . IiII . i1IIi
 if 49 - 49: I1ii11iIi11i
 if 84 - 84: I11i - Oo0Ooo / O0 - I1Ii111
 if 21 - 21: O0 * O0 % I1ii11iIi11i
 if 94 - 94: I11i + II111iiii % i11iIiiIii
 if 8 - 8: ooOoO0o * O0
 if 73 - 73: o0oOOo0O0Ooo / oO0o / I11i / OoO0O00
def lisp_get_ephemeral_port ( ) :
 return ( random . randrange ( 32768 , 65535 ) )
 if 11 - 11: OoOoOO00 + IiII - OoooooooOO / OoO0O00
 if 34 - 34: ooOoO0o
 if 45 - 45: ooOoO0o / Oo0Ooo / Ii1I
 if 44 - 44: I1ii11iIi11i - Ii1I / II111iiii * OoO0O00 * Oo0Ooo
 if 73 - 73: o0oOOo0O0Ooo - I1IiiI * i1IIi / i11iIiiIii * OOooOOo % II111iiii
 if 56 - 56: OoooooooOO * Oo0Ooo . Oo0Ooo . I1ii11iIi11i
 if 24 - 24: Oo0Ooo . I11i * Ii1I % iII111i / OOooOOo
def lisp_get_data_nonce ( ) :
 return ( random . randint ( 0 , 0xffffff ) )
 if 58 - 58: I1IiiI - I1ii11iIi11i % O0 . I1IiiI % OoO0O00 % IiII
 if 87 - 87: oO0o - i11iIiiIii
 if 78 - 78: i11iIiiIii / iIii1I11I1II1 - o0oOOo0O0Ooo
 if 23 - 23: I11i
 if 40 - 40: o0oOOo0O0Ooo - II111iiii / Oo0Ooo
 if 14 - 14: I1ii11iIi11i
 if 5 - 5: o0oOOo0O0Ooo . iIii1I11I1II1 % iIii1I11I1II1
def lisp_get_control_nonce ( ) :
 return ( random . randint ( 0 , ( 2 ** 64 ) - 1 ) )
 if 56 - 56: OoooooooOO - I11i - i1IIi
 if 8 - 8: I1Ii111 / OOooOOo . I1IiiI + I1ii11iIi11i / i11iIiiIii
 if 31 - 31: ooOoO0o - iIii1I11I1II1 + iII111i . Oo0Ooo / IiII % iIii1I11I1II1
 if 6 - 6: IiII * i11iIiiIii % iIii1I11I1II1 % i11iIiiIii + o0oOOo0O0Ooo / i1IIi
 if 53 - 53: I11i + iIii1I11I1II1
 if 70 - 70: I1ii11iIi11i
 if 67 - 67: OoooooooOO
 if 29 - 29: O0 - i11iIiiIii - II111iiii + OOooOOo * IiII
 if 2 - 2: i1IIi - ooOoO0o + I1IiiI . o0oOOo0O0Ooo * o0oOOo0O0Ooo / OoOoOO00
def lisp_hex_string ( integer_value ) :
 oOOO = hex ( integer_value ) [ 2 : : ]
 if ( oOOO [ - 1 ] == "L" ) : oOOO = oOOO [ 0 : - 1 ]
 return ( oOOO )
 if 16 - 16: oO0o + ooOoO0o / o0oOOo0O0Ooo
 if 82 - 82: IiII * i11iIiiIii % II111iiii - OoooooooOO
 if 90 - 90: Oo0Ooo . oO0o * i1IIi - i1IIi
 if 16 - 16: I1IiiI * i1IIi - o0oOOo0O0Ooo . IiII % I11i / o0oOOo0O0Ooo
 if 14 - 14: iIii1I11I1II1 * I1Ii111 * I1ii11iIi11i / iIii1I11I1II1 * IiII / I11i
 if 77 - 77: OoO0O00 + I1Ii111 + I1Ii111 * Ii1I / OoooooooOO . Ii1I
 if 62 - 62: i1IIi - i1IIi
def lisp_get_timestamp ( ) :
 return ( time . time ( ) )
 if 69 - 69: OoOoOO00 % oO0o - I11i
 if 38 - 38: iIii1I11I1II1 + i11iIiiIii / i11iIiiIii % OoO0O00 / ooOoO0o % Ii1I
 if 7 - 7: IiII * I1IiiI + i1IIi + i11iIiiIii + Oo0Ooo % I1IiiI
 if 62 - 62: o0oOOo0O0Ooo - Ii1I * OoOoOO00 - i11iIiiIii % ooOoO0o
 if 52 - 52: I1ii11iIi11i % oO0o - i11iIiiIii
 if 30 - 30: iII111i / OoO0O00 + oO0o
 if 6 - 6: iII111i . I11i + Ii1I . I1Ii111
def lisp_set_timestamp ( seconds ) :
 return ( time . time ( ) + seconds )
 if 70 - 70: OoO0O00
 if 46 - 46: I11i - i1IIi
 if 46 - 46: I1Ii111 % Ii1I
 if 72 - 72: iIii1I11I1II1
 if 45 - 45: Oo0Ooo - o0oOOo0O0Ooo % I1Ii111
 if 38 - 38: I1Ii111 % OOooOOo - OoooooooOO
 if 87 - 87: OoO0O00 % I1IiiI
def lisp_print_elapsed ( ts ) :
 if ( ts == 0 or ts == None ) : return ( "never" )
 ooooOoO0O = time . time ( ) - ts
 ooooOoO0O = round ( ooooOoO0O , 0 )
 return ( str ( datetime . timedelta ( seconds = ooooOoO0O ) ) )
 if 1 - 1: I1ii11iIi11i / OoO0O00 + oO0o . o0oOOo0O0Ooo / I1ii11iIi11i - iII111i
 if 5 - 5: OOooOOo
 if 4 - 4: iII111i % I1Ii111 / OoO0O00 . OOooOOo / OOooOOo - I1ii11iIi11i
 if 79 - 79: I1ii11iIi11i + I1Ii111
 if 10 - 10: Oo0Ooo + O0
 if 43 - 43: iIii1I11I1II1 / II111iiii % o0oOOo0O0Ooo - OOooOOo
 if 62 - 62: I11i
def lisp_print_future ( ts ) :
 if ( ts == 0 ) : return ( "never" )
 O000oOo = ts - time . time ( )
 if ( O000oOo < 0 ) : return ( "expired" )
 O000oOo = round ( O000oOo , 0 )
 return ( str ( datetime . timedelta ( seconds = O000oOo ) ) )
 if 53 - 53: iIii1I11I1II1 + o0oOOo0O0Ooo - OoOoOO00 - oO0o / ooOoO0o % i11iIiiIii
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
def lisp_print_eid_tuple ( eid , group ) :
 oo0ooooO = eid . print_prefix ( )
 if ( group . is_null ( ) ) : return ( oo0ooooO )
 if 12 - 12: II111iiii
 IiIii1ii = group . print_prefix ( )
 IIiI1i = group . instance_id
 if 6 - 6: I1ii11iIi11i / iII111i - OOooOOo
 if ( eid . is_null ( ) or eid . is_exact_match ( group ) ) :
  OOOoO000 = IiIii1ii . find ( "]" ) + 1
  return ( "[{}](*, {})" . format ( IIiI1i , IiIii1ii [ OOOoO000 : : ] ) )
  if 62 - 62: I11i % OOooOOo
  if 54 - 54: OoOoOO00 % iII111i . OoOoOO00 * OOooOOo + OoOoOO00 % i1IIi
 I1I1I11Ii = eid . print_sg ( group )
 return ( I1I1I11Ii )
 if 48 - 48: OoooooooOO + oO0o % iIii1I11I1II1
 if 11 - 11: I1IiiI % Ii1I - OoO0O00 - oO0o + o0oOOo0O0Ooo
 if 98 - 98: iII111i + Ii1I - OoO0O00
 if 79 - 79: OOooOOo / I1Ii111 . OoOoOO00 - I1ii11iIi11i
 if 47 - 47: OoooooooOO % O0 * iII111i . Ii1I
 if 38 - 38: O0 - IiII % I1Ii111
 if 64 - 64: iIii1I11I1II1
 if 15 - 15: I1ii11iIi11i + OOooOOo / I1ii11iIi11i / I1Ii111
def lisp_convert_6to4 ( addr_str ) :
 if ( addr_str . find ( "::ffff:" ) == - 1 ) : return ( addr_str )
 I1Iii1I = addr_str . split ( ":" )
 return ( I1Iii1I [ - 1 ] )
 if 13 - 13: o0oOOo0O0Ooo + O0
 if 71 - 71: IiII + i1IIi * Oo0Ooo % Oo0Ooo / Oo0Ooo
 if 55 - 55: OoooooooOO + I1Ii111 + OoooooooOO * ooOoO0o
 if 68 - 68: O0
 if 2 - 2: OoO0O00 + O0 * OoO0O00 - Ii1I + oO0o
 if 43 - 43: I1ii11iIi11i - OoOoOO00
 if 36 - 36: I1ii11iIi11i - iII111i
 if 24 - 24: o0oOOo0O0Ooo + ooOoO0o + I11i - iIii1I11I1II1
 if 49 - 49: I11i . ooOoO0o * OoOoOO00 % IiII . O0
 if 48 - 48: O0 * Ii1I - O0 / Ii1I + OoOoOO00
 if 52 - 52: OoO0O00 % Ii1I * II111iiii
def lisp_convert_4to6 ( addr_str ) :
 I1Iii1I = lisp_address ( LISP_AFI_IPV6 , "" , 128 , 0 )
 if ( I1Iii1I . is_ipv4_string ( addr_str ) ) : addr_str = "::ffff:" + addr_str
 I1Iii1I . store_address ( addr_str )
 return ( I1Iii1I )
 if 4 - 4: I11i % O0 - OoooooooOO + ooOoO0o . oO0o % II111iiii
 if 9 - 9: II111iiii * II111iiii . i11iIiiIii * iIii1I11I1II1
 if 18 - 18: OoO0O00 . II111iiii % OoOoOO00 % Ii1I
 if 87 - 87: iIii1I11I1II1 . OoooooooOO * OoOoOO00
 if 100 - 100: OoO0O00 / i1IIi - I1IiiI % Ii1I - iIii1I11I1II1
 if 17 - 17: I11i / o0oOOo0O0Ooo % Oo0Ooo
 if 71 - 71: IiII . I1Ii111 . OoO0O00
 if 68 - 68: i11iIiiIii % oO0o * OoO0O00 * IiII * II111iiii + O0
 if 66 - 66: I11i % I1ii11iIi11i % OoooooooOO
def lisp_gethostbyname ( string ) :
 II11iIi = string . split ( "." )
 iiO0O0o0oO0O00 = string . split ( ":" )
 o0O0oO0 = string . split ( "-" )
 if 77 - 77: O0 . Ii1I
 if ( len ( II11iIi ) > 1 ) :
  if ( II11iIi [ 0 ] . isdigit ( ) ) : return ( string )
  if 39 - 39: ooOoO0o . II111iiii
 if ( len ( iiO0O0o0oO0O00 ) > 1 ) :
  try :
   int ( iiO0O0o0oO0O00 [ 0 ] , 16 )
   return ( string )
  except :
   pass
   if 45 - 45: oO0o * OoOoOO00 / iIii1I11I1II1
   if 77 - 77: I1Ii111 - I11i
   if 11 - 11: I1ii11iIi11i
   if 26 - 26: iIii1I11I1II1 * I1Ii111 - OOooOOo
   if 27 - 27: I1ii11iIi11i * I1Ii111 - OoO0O00 + Ii1I * Ii1I
   if 55 - 55: ooOoO0o
   if 82 - 82: I1Ii111 - OOooOOo + OoO0O00
 if ( len ( o0O0oO0 ) == 3 ) :
  for oO in range ( 3 ) :
   try : int ( o0O0oO0 [ oO ] , 16 )
   except : break
   if 64 - 64: o0oOOo0O0Ooo . O0 * Ii1I + OoooooooOO - Oo0Ooo . OoooooooOO
   if 70 - 70: Oo0Ooo - oO0o . iIii1I11I1II1 % I11i / OoOoOO00 - O0
   if 55 - 55: iII111i - OoO0O00
 try :
  I1Iii1I = socket . gethostbyname ( string )
  return ( I1Iii1I )
 except :
  if ( lisp_is_alpine ( ) == False ) : return ( "" )
  if 100 - 100: O0
  if 79 - 79: iIii1I11I1II1
  if 81 - 81: OOooOOo + iIii1I11I1II1 * I1Ii111 - iIii1I11I1II1 . OOooOOo
  if 48 - 48: I11i . OoooooooOO . I1IiiI . OoOoOO00 % I1ii11iIi11i / iII111i
  if 11 - 11: i1IIi % OoO0O00 % iII111i
 try :
  I1Iii1I = socket . getaddrinfo ( string , 0 ) [ 0 ]
  if ( I1Iii1I [ 3 ] != string ) : return ( "" )
  I1Iii1I = I1Iii1I [ 4 ] [ 0 ]
 except :
  I1Iii1I = ""
  if 99 - 99: ooOoO0o / iIii1I11I1II1 - Ii1I * I1ii11iIi11i % I1IiiI
 return ( I1Iii1I )
 if 13 - 13: OoO0O00
 if 70 - 70: I1Ii111 + O0 . oO0o * Ii1I
 if 2 - 2: OoooooooOO . OOooOOo . IiII
 if 42 - 42: OOooOOo % oO0o / OoO0O00 - oO0o * i11iIiiIii
 if 19 - 19: oO0o * I1IiiI % i11iIiiIii
 if 24 - 24: o0oOOo0O0Ooo
 if 10 - 10: o0oOOo0O0Ooo % Ii1I / OOooOOo
 if 28 - 28: OOooOOo % ooOoO0o
def lisp_ip_checksum ( data ) :
 if ( len ( data ) < 20 ) :
  lprint ( "IPv4 packet too short, length {}" . format ( len ( data ) ) )
  return ( data )
  if 48 - 48: i11iIiiIii % oO0o
  if 29 - 29: iII111i + i11iIiiIii % I11i
 oOo00Ooo0o0 = binascii . hexlify ( data )
 if 33 - 33: I11i
 if 87 - 87: OoOoOO00 / IiII + iIii1I11I1II1
 if 93 - 93: iIii1I11I1II1 + oO0o % ooOoO0o
 if 21 - 21: OOooOOo
 iIiI1I1IIi11 = 0
 for oO in range ( 0 , 40 , 4 ) :
  iIiI1I1IIi11 += int ( oOo00Ooo0o0 [ oO : oO + 4 ] , 16 )
  if 9 - 9: ooOoO0o + iII111i - I11i / i1IIi % I1ii11iIi11i / IiII
  if 60 - 60: I1ii11iIi11i
  if 1 - 1: OoOoOO00 . i11iIiiIii % OoOoOO00 - iII111i % i1IIi + I1ii11iIi11i
  if 2 - 2: iIii1I11I1II1 * oO0o / OoOoOO00 . I11i / IiII
  if 75 - 75: OoOoOO00
 iIiI1I1IIi11 = ( iIiI1I1IIi11 >> 16 ) + ( iIiI1I1IIi11 & 0xffff )
 iIiI1I1IIi11 += iIiI1I1IIi11 >> 16
 iIiI1I1IIi11 = socket . htons ( ~ iIiI1I1IIi11 & 0xffff )
 if 78 - 78: Ii1I + OoOoOO00 + IiII - IiII . i11iIiiIii / OoO0O00
 if 27 - 27: Ii1I - O0 % I11i * I1Ii111 . IiII % iIii1I11I1II1
 if 37 - 37: OoooooooOO + O0 - i1IIi % ooOoO0o
 if 24 - 24: OoOoOO00
 iIiI1I1IIi11 = struct . pack ( "H" , iIiI1I1IIi11 )
 oOo00Ooo0o0 = data [ 0 : 10 ] + iIiI1I1IIi11 + data [ 12 : : ]
 return ( oOo00Ooo0o0 )
 if 94 - 94: i1IIi * i1IIi % II111iiii + OOooOOo
 if 28 - 28: I1IiiI
 if 49 - 49: I11i . o0oOOo0O0Ooo % oO0o / Ii1I
 if 95 - 95: O0 * OoOoOO00 * IiII . ooOoO0o / iIii1I11I1II1
 if 28 - 28: IiII + oO0o - ooOoO0o / iIii1I11I1II1 - I1IiiI
 if 45 - 45: O0 / i1IIi * oO0o * OoO0O00
 if 35 - 35: I1ii11iIi11i / iII111i % I1IiiI + iIii1I11I1II1
def lisp_get_interface_address ( device ) :
 if 79 - 79: OoOoOO00 / ooOoO0o
 if 77 - 77: Oo0Ooo
 if 46 - 46: I1Ii111
 if 72 - 72: iII111i * OOooOOo
 if ( device not in netifaces . interfaces ( ) ) : return ( None )
 if 67 - 67: i1IIi
 if 5 - 5: II111iiii . OoooooooOO
 if 57 - 57: I1IiiI
 if 35 - 35: OoooooooOO - I1Ii111 / OoO0O00
 iii11i1 = netifaces . ifaddresses ( device )
 if ( iii11i1 . has_key ( netifaces . AF_INET ) == False ) : return ( None )
 if 48 - 48: ooOoO0o * I1ii11iIi11i
 if 15 - 15: OoO0O00 * I11i % iIii1I11I1II1 * I1ii11iIi11i
 if 31 - 31: OoO0O00 * O0 . oO0o
 if 59 - 59: II111iiii * i11iIiiIii
 ooOooO00Oo = lisp_address ( LISP_AFI_IPV4 , "" , 32 , 0 )
 if 86 - 86: II111iiii + ooOoO0o + IiII
 for I1Iii1I in iii11i1 [ netifaces . AF_INET ] :
  I11i11I = I1Iii1I [ "addr" ]
  ooOooO00Oo . store_address ( I11i11I )
  return ( ooOooO00Oo )
  if 90 - 90: I1ii11iIi11i
 return ( None )
 if 9 - 9: IiII + ooOoO0o
 if 7 - 7: O0 % I1Ii111 + I1ii11iIi11i + Ii1I % OoooooooOO . Oo0Ooo
 if 56 - 56: iII111i
 if 84 - 84: OoOoOO00 - i11iIiiIii
 if 1 - 1: iII111i * OoOoOO00
 if 66 - 66: OoOoOO00 + i1IIi % II111iiii . O0 * I1ii11iIi11i % I1ii11iIi11i
 if 87 - 87: OOooOOo + o0oOOo0O0Ooo . iII111i - OoooooooOO
 if 6 - 6: iIii1I11I1II1 * OoooooooOO
 if 28 - 28: Oo0Ooo * o0oOOo0O0Ooo / I1Ii111
 if 52 - 52: O0 / o0oOOo0O0Ooo % iII111i * I1IiiI % OOooOOo
 if 69 - 69: I1ii11iIi11i
 if 83 - 83: o0oOOo0O0Ooo
def lisp_get_input_interface ( packet ) :
 i1iiii = lisp_format_packet ( packet [ 0 : 12 ] ) . replace ( " " , "" )
 OOOO0oOo00O = i1iiii [ 0 : 12 ]
 i1I1I1i1i1i = i1iiii [ 12 : : ]
 if 23 - 23: iIii1I11I1II1
 try : Ii11ii1Iiii = lisp_mymacs . has_key ( i1I1I1i1i1i )
 except : Ii11ii1Iiii = False
 if 7 - 7: Ii1I % i1IIi * OoooooooOO * O0 + iII111i
 if ( lisp_mymacs . has_key ( OOOO0oOo00O ) ) : return ( lisp_mymacs [ OOOO0oOo00O ] , i1I1I1i1i1i , OOOO0oOo00O , Ii11ii1Iiii )
 if ( Ii11ii1Iiii ) : return ( lisp_mymacs [ i1I1I1i1i1i ] , i1I1I1i1i1i , OOOO0oOo00O , Ii11ii1Iiii )
 return ( [ "?" ] , i1I1I1i1i1i , OOOO0oOo00O , Ii11ii1Iiii )
 if 95 - 95: OoooooooOO + I11i - I1ii11iIi11i / I1ii11iIi11i . i1IIi . OoooooooOO
 if 29 - 29: ooOoO0o - i1IIi . I11i - I1ii11iIi11i + ooOoO0o + OoooooooOO
 if 36 - 36: i1IIi / ooOoO0o . iIii1I11I1II1
 if 12 - 12: Ii1I
 if 71 - 71: I1IiiI . II111iiii . I1IiiI - ooOoO0o
 if 45 - 45: IiII / O0 / OoOoOO00 * OOooOOo
 if 18 - 18: iIii1I11I1II1 + OOooOOo + iIii1I11I1II1 . I1ii11iIi11i + I1Ii111 . ooOoO0o
 if 7 - 7: I1ii11iIi11i + iIii1I11I1II1 * I11i * I11i / II111iiii - Ii1I
def lisp_get_local_interfaces ( ) :
 for oOOOo0o in netifaces . interfaces ( ) :
  iiiii11I1 = lisp_interface ( oOOOo0o )
  iiiii11I1 . add_interface ( )
  if 16 - 16: O0 . Ii1I % i1IIi % OOooOOo
 return
 if 50 - 50: IiII + o0oOOo0O0Ooo
 if 96 - 96: OoO0O00
 if 92 - 92: Oo0Ooo / i11iIiiIii + I1ii11iIi11i
 if 87 - 87: OoOoOO00 % iIii1I11I1II1
 if 72 - 72: OOooOOo . OOooOOo - I1ii11iIi11i
 if 48 - 48: Oo0Ooo - ooOoO0o + Oo0Ooo - I1IiiI * i11iIiiIii . iII111i
 if 35 - 35: IiII . O0 + Oo0Ooo + OOooOOo + i1IIi
def lisp_get_loopback_address ( ) :
 for I1Iii1I in netifaces . ifaddresses ( "lo" ) [ netifaces . AF_INET ] :
  if ( I1Iii1I [ "peer" ] == "127.0.0.1" ) : continue
  return ( I1Iii1I [ "peer" ] )
  if 65 - 65: O0 * I1IiiI / I1IiiI . OoOoOO00
 return ( None )
 if 87 - 87: II111iiii * I1ii11iIi11i % Oo0Ooo * Oo0Ooo
 if 58 - 58: OOooOOo . o0oOOo0O0Ooo + I1IiiI % Oo0Ooo - OoO0O00
 if 50 - 50: iII111i % II111iiii - ooOoO0o . i1IIi + O0 % iII111i
 if 10 - 10: iII111i . i1IIi + Ii1I
 if 66 - 66: OoO0O00 % o0oOOo0O0Ooo
 if 21 - 21: OoOoOO00 - OoooooooOO % i11iIiiIii
 if 71 - 71: i1IIi - I11i * I1Ii111 + oO0o - OoO0O00 % I1ii11iIi11i
 if 63 - 63: iIii1I11I1II1 + OOooOOo . OoO0O00 / I1IiiI
def lisp_get_local_macs ( ) :
 for oOOOo0o in netifaces . interfaces ( ) :
  if 84 - 84: i1IIi
  if 42 - 42: II111iiii - OoO0O00 - OoooooooOO . iII111i / OoOoOO00
  if 56 - 56: i11iIiiIii - iIii1I11I1II1 . II111iiii
  if 81 - 81: IiII / OoOoOO00 * IiII . O0
  if 61 - 61: OoO0O00 * OOooOOo + I1Ii111 . iIii1I11I1II1 % I11i . I1Ii111
  O0o0oo0oOO0oO = oOOOo0o . replace ( ":" , "" )
  O0o0oo0oOO0oO = oOOOo0o . replace ( "-" , "" )
  if ( O0o0oo0oOO0oO . isalnum ( ) == False ) : continue
  if 15 - 15: OoO0O00 * II111iiii
  if 59 - 59: I1Ii111 + OoO0O00 / OOooOOo
  if 97 - 97: Oo0Ooo * iII111i % ooOoO0o . iII111i - I1Ii111 - OOooOOo
  if 79 - 79: I1IiiI - ooOoO0o
  if 37 - 37: IiII . Oo0Ooo * Oo0Ooo * II111iiii * O0
  try :
   o00O = netifaces . ifaddresses ( oOOOo0o )
  except :
   continue
   if 88 - 88: i11iIiiIii + iII111i * OoOoOO00 * iII111i + I11i
  if ( o00O . has_key ( netifaces . AF_LINK ) == False ) : continue
  o0O0oO0 = o00O [ netifaces . AF_LINK ] [ 0 ] [ "addr" ]
  o0O0oO0 = o0O0oO0 . replace ( ":" , "" )
  if 88 - 88: OOooOOo % Oo0Ooo - iII111i - OoOoOO00 % i11iIiiIii
  if 6 - 6: Ii1I - OoO0O00 . I1IiiI - O0
  if 16 - 16: iII111i * iII111i % Ii1I % I1IiiI
  if 48 - 48: OOooOOo / Ii1I % OoO0O00 / IiII / I1Ii111
  if 89 - 89: I1Ii111 * oO0o
  if ( len ( o0O0oO0 ) < 12 ) : continue
  if 63 - 63: OoooooooOO * OoooooooOO % OoO0O00 + O0 / I1Ii111 + iIii1I11I1II1
  if ( lisp_mymacs . has_key ( o0O0oO0 ) == False ) : lisp_mymacs [ o0O0oO0 ] = [ ]
  lisp_mymacs [ o0O0oO0 ] . append ( oOOOo0o )
  if 72 - 72: OoOoOO00 * iIii1I11I1II1 % I11i
  if 20 - 20: II111iiii % iIii1I11I1II1 + oO0o * II111iiii * OoO0O00 % OoO0O00
 lprint ( "Local MACs are: {}" . format ( lisp_mymacs ) )
 return
 if 15 - 15: oO0o / I1Ii111
 if 37 - 37: i11iIiiIii + I1IiiI . OOooOOo % I11i % I11i
 if 26 - 26: O0
 if 34 - 34: ooOoO0o * I1Ii111
 if 97 - 97: i11iIiiIii % oO0o / Oo0Ooo / Oo0Ooo
 if 97 - 97: II111iiii - I1Ii111 - iIii1I11I1II1 * I1IiiI
 if 54 - 54: iIii1I11I1II1
 if 5 - 5: IiII
def lisp_get_local_rloc ( ) :
 Oo0O0oo0o00o0 = commands . getoutput ( "netstat -rn | egrep 'default|0.0.0.0'" )
 if ( Oo0O0oo0o00o0 == "" ) : return ( lisp_address ( LISP_AFI_IPV4 , "" , 32 , 0 ) )
 if 66 - 66: iIii1I11I1II1 . i11iIiiIii / I11i / ooOoO0o + I1Ii111
 if 5 - 5: OoOoOO00 % iII111i + IiII
 if 13 - 13: IiII
 if 19 - 19: II111iiii - IiII
 Oo0O0oo0o00o0 = Oo0O0oo0o00o0 . split ( "\n" ) [ 0 ]
 oOOOo0o = Oo0O0oo0o00o0 . split ( ) [ - 1 ]
 if 59 - 59: o0oOOo0O0Ooo * OoO0O00 - Ii1I . OOooOOo
 I1Iii1I = ""
 o0OO00oo0O = lisp_is_macos ( )
 if ( o0OO00oo0O ) :
  Oo0O0oo0o00o0 = commands . getoutput ( "ifconfig {} | egrep 'inet '" . format ( oOOOo0o ) )
  if ( Oo0O0oo0o00o0 == "" ) : return ( lisp_address ( LISP_AFI_IPV4 , "" , 32 , 0 ) )
 else :
  Ii1I1i111 = 'ip addr show | egrep "inet " | egrep "{}"' . format ( oOOOo0o )
  Oo0O0oo0o00o0 = commands . getoutput ( Ii1I1i111 )
  if ( Oo0O0oo0o00o0 == "" ) :
   Ii1I1i111 = 'ip addr show | egrep "inet " | egrep "global lo"'
   Oo0O0oo0o00o0 = commands . getoutput ( Ii1I1i111 )
   if 57 - 57: oO0o . I1IiiI
  if ( Oo0O0oo0o00o0 == "" ) : return ( lisp_address ( LISP_AFI_IPV4 , "" , 32 , 0 ) )
  if 6 - 6: ooOoO0o
  if 39 - 39: ooOoO0o / O0 * IiII
  if 17 - 17: Ii1I / iIii1I11I1II1 - OoO0O00 + I1IiiI % OOooOOo
  if 14 - 14: o0oOOo0O0Ooo % IiII + I1ii11iIi11i + OoO0O00
  if 76 - 76: OoO0O00 - i11iIiiIii + OoOoOO00 + OOooOOo / OoooooooOO
  if 50 - 50: II111iiii - I1Ii111 + iIii1I11I1II1 + iIii1I11I1II1
 I1Iii1I = ""
 Oo0O0oo0o00o0 = Oo0O0oo0o00o0 . split ( "\n" )
 if 91 - 91: II111iiii - O0 . iIii1I11I1II1 . O0 + I1ii11iIi11i - II111iiii
 for iiIiiIi1 in Oo0O0oo0o00o0 :
  OOOO0o = iiIiiIi1 . split ( ) [ 1 ]
  if ( o0OO00oo0O == False ) : OOOO0o = OOOO0o . split ( "/" ) [ 0 ]
  I1Ii11i = lisp_address ( LISP_AFI_IPV4 , OOOO0o , 32 , 0 )
  return ( I1Ii11i )
  if 19 - 19: IiII - o0oOOo0O0Ooo . iIii1I11I1II1 . OoOoOO00 / OOooOOo
 return ( lisp_address ( LISP_AFI_IPV4 , I1Iii1I , 32 , 0 ) )
 if 87 - 87: OoOoOO00 - ooOoO0o - OOooOOo + Oo0Ooo % iIii1I11I1II1 / i11iIiiIii
 if 12 - 12: ooOoO0o
 if 86 - 86: oO0o - OoO0O00
 if 63 - 63: I1IiiI / OoOoOO00 + OoooooooOO . I11i . ooOoO0o
 if 48 - 48: i1IIi - iII111i - i11iIiiIii . I11i - iII111i * I11i
 if 60 - 60: OoOoOO00 / I1ii11iIi11i + OOooOOo - iII111i
 if 49 - 49: OoO0O00 - O0 / OoO0O00 * OoOoOO00 + I1Ii111
 if 35 - 35: II111iiii . I1IiiI / i1IIi / I1IiiI * oO0o
 if 85 - 85: II111iiii . ooOoO0o % OOooOOo % I11i
 if 80 - 80: oO0o * I11i / iIii1I11I1II1 % oO0o / iIii1I11I1II1
 if 42 - 42: i1IIi / i11iIiiIii . Oo0Ooo * iII111i . i11iIiiIii * O0
def lisp_get_local_addresses ( ) :
 global lisp_myrlocs
 if 44 - 44: i1IIi . I1IiiI / i11iIiiIii + IiII
 if 27 - 27: OOooOOo
 if 52 - 52: I1Ii111 % OoOoOO00 + iIii1I11I1II1 * oO0o . Ii1I
 if 95 - 95: iIii1I11I1II1 . IiII - OoooooooOO * OoO0O00 / o0oOOo0O0Ooo
 if 74 - 74: oO0o
 if 34 - 34: iII111i
 if 44 - 44: i1IIi % I1IiiI % o0oOOo0O0Ooo
 if 9 - 9: Oo0Ooo % OoooooooOO - Ii1I
 if 43 - 43: OoO0O00 % OoO0O00
 if 46 - 46: Oo0Ooo % iIii1I11I1II1 . iII111i . O0 * ooOoO0o / OoooooooOO
 II1iI1IIi = None
 OOOoO000 = 1
 Ii11iiI1 = os . getenv ( "LISP_ADDR_SELECT" )
 if ( Ii11iiI1 != None and Ii11iiI1 != "" ) :
  Ii11iiI1 = Ii11iiI1 . split ( ":" )
  if ( len ( Ii11iiI1 ) == 2 ) :
   II1iI1IIi = Ii11iiI1 [ 0 ]
   OOOoO000 = Ii11iiI1 [ 1 ]
  else :
   if ( Ii11iiI1 [ 0 ] . isdigit ( ) ) :
    OOOoO000 = Ii11iiI1 [ 0 ]
   else :
    II1iI1IIi = Ii11iiI1 [ 0 ]
    if 71 - 71: o0oOOo0O0Ooo / OOooOOo % OOooOOo
    if 89 - 89: OoooooooOO + i11iIiiIii / I11i + iIii1I11I1II1 % ooOoO0o
  OOOoO000 = 1 if ( OOOoO000 == "" ) else int ( OOOoO000 )
  if 29 - 29: I1ii11iIi11i
  if 53 - 53: i11iIiiIii . I1ii11iIi11i % Ii1I / ooOoO0o % iIii1I11I1II1
 iIiIii1I1 = [ None , None , None ]
 O0OOOOo0 = lisp_address ( LISP_AFI_IPV4 , "" , 32 , 0 )
 OOooO0Oo00 = lisp_address ( LISP_AFI_IPV6 , "" , 128 , 0 )
 iIIIIIIIiIII = None
 if 94 - 94: iII111i * iIii1I11I1II1 . I11i
 for oOOOo0o in netifaces . interfaces ( ) :
  if ( II1iI1IIi != None and II1iI1IIi != oOOOo0o ) : continue
  iii11i1 = netifaces . ifaddresses ( oOOOo0o )
  if ( iii11i1 == { } ) : continue
  if 13 - 13: iIii1I11I1II1 * OoOoOO00 / I1Ii111 % ooOoO0o + oO0o
  if 41 - 41: I1ii11iIi11i
  if 5 - 5: Oo0Ooo
  if 100 - 100: Ii1I + iIii1I11I1II1
  iIIIIIIIiIII = lisp_get_interface_instance_id ( oOOOo0o , None )
  if 59 - 59: IiII
  if 89 - 89: OoOoOO00 % iIii1I11I1II1
  if 35 - 35: I1ii11iIi11i + I1Ii111 - OoOoOO00 % oO0o % o0oOOo0O0Ooo % OoOoOO00
  if 45 - 45: I1IiiI * OOooOOo % OoO0O00
  if ( iii11i1 . has_key ( netifaces . AF_INET ) ) :
   II11iIi = iii11i1 [ netifaces . AF_INET ]
   i111I11I = 0
   for I1Iii1I in II11iIi :
    O0OOOOo0 . store_address ( I1Iii1I [ "addr" ] )
    if ( O0OOOOo0 . is_ipv4_loopback ( ) ) : continue
    if ( O0OOOOo0 . is_ipv4_link_local ( ) ) : continue
    if ( O0OOOOo0 . address == 0 ) : continue
    i111I11I += 1
    O0OOOOo0 . instance_id = iIIIIIIIiIII
    if ( II1iI1IIi == None and
 lisp_db_for_lookups . lookup_cache ( O0OOOOo0 , False ) ) : continue
    iIiIii1I1 [ 0 ] = O0OOOOo0
    if ( i111I11I == OOOoO000 ) : break
    if 80 - 80: iIii1I11I1II1 - OoooooooOO - I1ii11iIi11i - I1ii11iIi11i . OoooooooOO
    if 48 - 48: I1Ii111 . i11iIiiIii / i1IIi % IiII % iII111i + oO0o
  if ( iii11i1 . has_key ( netifaces . AF_INET6 ) ) :
   iiO0O0o0oO0O00 = iii11i1 [ netifaces . AF_INET6 ]
   i111I11I = 0
   for I1Iii1I in iiO0O0o0oO0O00 :
    I11i11I = I1Iii1I [ "addr" ]
    OOooO0Oo00 . store_address ( I11i11I )
    if ( OOooO0Oo00 . is_ipv6_string_link_local ( I11i11I ) ) : continue
    if ( OOooO0Oo00 . is_ipv6_loopback ( ) ) : continue
    i111I11I += 1
    OOooO0Oo00 . instance_id = iIIIIIIIiIII
    if ( II1iI1IIi == None and
 lisp_db_for_lookups . lookup_cache ( OOooO0Oo00 , False ) ) : continue
    iIiIii1I1 [ 1 ] = OOooO0Oo00
    if ( i111I11I == OOOoO000 ) : break
    if 41 - 41: IiII
    if 3 - 3: IiII + II111iiii / iIii1I11I1II1
    if 10 - 10: II111iiii . O0
    if 31 - 31: oO0o / i11iIiiIii / O0
    if 39 - 39: I1IiiI + Oo0Ooo
    if 83 - 83: i1IIi
  if ( iIiIii1I1 [ 0 ] == None ) : continue
  if 76 - 76: Ii1I + iIii1I11I1II1 + OoOoOO00 . OoO0O00
  iIiIii1I1 [ 2 ] = oOOOo0o
  break
  if 49 - 49: IiII / ooOoO0o / OOooOOo
  if 25 - 25: I1IiiI % O0 + i1IIi - ooOoO0o
 III1IiI1i1i = iIiIii1I1 [ 0 ] . print_address_no_iid ( ) if iIiIii1I1 [ 0 ] else "none"
 o0OOOOOo0 = iIiIii1I1 [ 1 ] . print_address_no_iid ( ) if iIiIii1I1 [ 1 ] else "none"
 oOOOo0o = iIiIii1I1 [ 2 ] if iIiIii1I1 [ 2 ] else "none"
 if 57 - 57: iIii1I11I1II1 + iIii1I11I1II1
 II1iI1IIi = " (user selected)" if II1iI1IIi != None else ""
 if 56 - 56: oO0o + ooOoO0o
 III1IiI1i1i = red ( III1IiI1i1i , False )
 o0OOOOOo0 = red ( o0OOOOOo0 , False )
 oOOOo0o = bold ( oOOOo0o , False )
 lprint ( "Local addresses are IPv4: {}, IPv6: {} from device {}{}, iid {}" . format ( III1IiI1i1i , o0OOOOOo0 , oOOOo0o , II1iI1IIi , iIIIIIIIiIII ) )
 if 32 - 32: II111iiii + OoOoOO00 % ooOoO0o / OoOoOO00 + I1ii11iIi11i
 if 2 - 2: i11iIiiIii - I1Ii111 + OoO0O00 % I11i * Ii1I
 lisp_myrlocs = iIiIii1I1
 return ( ( iIiIii1I1 [ 0 ] != None ) )
 if 54 - 54: O0 - iII111i . OOooOOo % iII111i + iII111i
 if 36 - 36: OOooOOo % i11iIiiIii
 if 47 - 47: i1IIi + II111iiii . Oo0Ooo * oO0o . I11i / i1IIi
 if 50 - 50: I1Ii111 / i1IIi % OoooooooOO
 if 83 - 83: I1ii11iIi11i * I1ii11iIi11i + OOooOOo
 if 57 - 57: O0 - O0 . I1ii11iIi11i / o0oOOo0O0Ooo / Ii1I
 if 20 - 20: OOooOOo * II111iiii - OoOoOO00 - oO0o * I1Ii111
 if 6 - 6: ooOoO0o + OOooOOo / Oo0Ooo + IiII % II111iiii / OoO0O00
 if 45 - 45: OoooooooOO
def lisp_get_all_addresses ( ) :
 I1 = [ ]
 for iiiii11I1 in netifaces . interfaces ( ) :
  try : oo = netifaces . ifaddresses ( iiiii11I1 )
  except : continue
  if 17 - 17: O0 - OoOoOO00
  if ( oo . has_key ( netifaces . AF_INET ) ) :
   for I1Iii1I in oo [ netifaces . AF_INET ] :
    OOOO0o = I1Iii1I [ "addr" ]
    if ( OOOO0o . find ( "127.0.0.1" ) != - 1 ) : continue
    I1 . append ( OOOO0o )
    if 81 - 81: I1IiiI - iIii1I11I1II1 / I1IiiI / O0
    if 34 - 34: Ii1I * Ii1I - I1ii11iIi11i - O0 . i11iIiiIii
  if ( oo . has_key ( netifaces . AF_INET6 ) ) :
   for I1Iii1I in oo [ netifaces . AF_INET6 ] :
    OOOO0o = I1Iii1I [ "addr" ]
    if ( OOOO0o == "::1" ) : continue
    if ( OOOO0o [ 0 : 5 ] == "fe80:" ) : continue
    I1 . append ( OOOO0o )
    if 32 - 32: iIii1I11I1II1 . OoO0O00 * oO0o / OOooOOo . II111iiii - Oo0Ooo
    if 10 - 10: I1ii11iIi11i / i11iIiiIii - Ii1I + oO0o * I1IiiI
    if 94 - 94: I1IiiI + iIii1I11I1II1 / O0 - OoooooooOO % I1ii11iIi11i
 return ( I1 )
 if 64 - 64: I11i + OoO0O00
 if 25 - 25: I1IiiI . ooOoO0o + I1IiiI % Ii1I * iIii1I11I1II1
 if 31 - 31: i11iIiiIii + OOooOOo - O0
 if 51 - 51: OoO0O00 * i1IIi / Ii1I * OOooOOo + ooOoO0o % I1ii11iIi11i
 if 34 - 34: oO0o * OoooooooOO + Ii1I + i11iIiiIii
 if 22 - 22: i1IIi
 if 24 - 24: I11i / I1IiiI * i1IIi % OoooooooOO
 if 99 - 99: i11iIiiIii . II111iiii . OoooooooOO
def lisp_get_all_multicast_rles ( ) :
 Ooi1IIii11i1I1 = [ ]
 Oo0O0oo0o00o0 = commands . getoutput ( 'egrep "rle-address =" ./lisp.config' )
 if ( Oo0O0oo0o00o0 == "" ) : return ( Ooi1IIii11i1I1 )
 if 12 - 12: i1IIi / OOooOOo % ooOoO0o * IiII * O0 * iIii1I11I1II1
 OOOO = Oo0O0oo0o00o0 . split ( "\n" )
 for iiIiiIi1 in OOOO :
  if ( iiIiiIi1 [ 0 ] == "#" ) : continue
  oOIii11111iiI = iiIiiIi1 . split ( "rle-address = " ) [ 1 ]
  o0OOOOoO = int ( oOIii11111iiI . split ( "." ) [ 0 ] )
  if ( o0OOOOoO >= 224 and o0OOOOoO < 240 ) : Ooi1IIii11i1I1 . append ( oOIii11111iiI )
  if 70 - 70: II111iiii + I1Ii111 + i11iIiiIii - i1IIi / IiII
 return ( Ooi1IIii11i1I1 )
 if 40 - 40: I1ii11iIi11i * I1Ii111
 if 38 - 38: O0 . Oo0Ooo + OoOoOO00 - oO0o
 if 43 - 43: iII111i + Oo0Ooo / OoooooooOO
 if 24 - 24: O0 + o0oOOo0O0Ooo * Ii1I - I1Ii111
 if 10 - 10: i11iIiiIii
 if 21 - 21: I1IiiI / iII111i
 if 69 - 69: ooOoO0o % ooOoO0o
 if 76 - 76: i11iIiiIii * iII111i / OoO0O00 % I1ii11iIi11i + OOooOOo
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
  if 48 - 48: iIii1I11I1II1 % i1IIi + OoOoOO00 % o0oOOo0O0Ooo
  if 79 - 79: OoOoOO00 % I1IiiI % Ii1I / i1IIi % OoO0O00
 def encode ( self , nonce ) :
  if 56 - 56: iIii1I11I1II1 - i11iIiiIii * iII111i
  if 84 - 84: OOooOOo + Ii1I + o0oOOo0O0Ooo
  if 33 - 33: Ii1I
  if 93 - 93: ooOoO0o
  if 34 - 34: oO0o - ooOoO0o * Oo0Ooo / o0oOOo0O0Ooo
  if ( self . outer_source . is_null ( ) ) : return ( None )
  if 19 - 19: I1ii11iIi11i
  if 46 - 46: iIii1I11I1II1 . i11iIiiIii - OoOoOO00 % O0 / II111iiii * i1IIi
  if 66 - 66: O0
  if 52 - 52: OoO0O00 * OoooooooOO
  if 12 - 12: O0 + IiII * i1IIi . OoO0O00
  if 71 - 71: I1Ii111 - o0oOOo0O0Ooo - OOooOOo
  if ( nonce == None ) :
   self . lisp_header . nonce ( lisp_get_data_nonce ( ) )
  elif ( self . lisp_header . is_request_nonce ( nonce ) ) :
   self . lisp_header . request_nonce ( nonce )
  else :
   self . lisp_header . nonce ( nonce )
   if 28 - 28: iIii1I11I1II1
  self . lisp_header . instance_id ( self . inner_dest . instance_id )
  if 7 - 7: o0oOOo0O0Ooo % IiII * OoOoOO00
  if 58 - 58: IiII / I11i + II111iiii % iII111i - OoooooooOO
  if 25 - 25: OoOoOO00 % OoooooooOO * Oo0Ooo - i1IIi * II111iiii * oO0o
  if 30 - 30: I11i % OoOoOO00 / I1ii11iIi11i * O0 * Ii1I . I1IiiI
  if 46 - 46: OoOoOO00 - O0
  if 70 - 70: I11i + Oo0Ooo * iIii1I11I1II1 . I1IiiI * I11i
  self . lisp_header . key_id ( 0 )
  ii1i11ii = ( self . lisp_header . get_instance_id ( ) == 0xffffff )
  if ( lisp_data_plane_security and ii1i11ii == False ) :
   I11i11I = self . outer_dest . print_address_no_iid ( ) + ":" + str ( self . encap_port )
   if 11 - 11: Oo0Ooo - O0
   if ( lisp_crypto_keys_by_rloc_encap . has_key ( I11i11I ) ) :
    OOo = lisp_crypto_keys_by_rloc_encap [ I11i11I ]
    if ( OOo [ 1 ] ) :
     OOo [ 1 ] . use_count += 1
     I111 , OOooo000OooO = self . encrypt ( OOo [ 1 ] , I11i11I )
     if ( OOooo000OooO ) : self . packet = I111
     if 99 - 99: OOooOOo / IiII / Ii1I
     if 84 - 84: OoO0O00 / iIii1I11I1II1
     if 33 - 33: i1IIi / I1Ii111 - i1IIi . Oo0Ooo
     if 18 - 18: Oo0Ooo / O0 + iII111i
     if 65 - 65: i1IIi . I1ii11iIi11i / ooOoO0o
     if 11 - 11: IiII * ooOoO0o / ooOoO0o - OOooOOo
     if 68 - 68: I1IiiI % IiII - IiII / I1IiiI + I1ii11iIi11i - Oo0Ooo
     if 65 - 65: ooOoO0o - i1IIi
  self . udp_checksum = 0
  if ( self . encap_port == LISP_DATA_PORT ) :
   if ( lisp_crypto_ephem_port == None ) :
    self . hash_packet ( )
   else :
    self . udp_sport = lisp_crypto_ephem_port
    if 62 - 62: I11i / oO0o % Oo0Ooo . OoooooooOO / i11iIiiIii / I1Ii111
  else :
   self . udp_sport = LISP_DATA_PORT
   if 60 - 60: I1IiiI % oO0o / o0oOOo0O0Ooo % oO0o * i11iIiiIii / iII111i
  self . udp_dport = self . encap_port
  self . udp_length = len ( self . packet ) + 16
  if 34 - 34: I1Ii111 - OOooOOo
  if 25 - 25: oO0o % I1IiiI + i11iIiiIii + O0 * OoooooooOO
  if 64 - 64: i1IIi
  if 10 - 10: I1Ii111 % O0 / I1IiiI % I11i
  if ( self . outer_version == 4 ) :
   iiII = socket . htons ( self . udp_sport )
   I1iI1111i = socket . htons ( self . udp_dport )
  else :
   iiII = self . udp_sport
   I1iI1111i = self . udp_dport
   if 39 - 39: I1Ii111 % OoooooooOO - II111iiii % OoOoOO00 + oO0o + O0
   if 14 - 14: OoooooooOO . o0oOOo0O0Ooo . I11i
  I1iI1111i = socket . htons ( self . udp_dport ) if self . outer_version == 4 else self . udp_dport
  if 50 - 50: ooOoO0o * OoOoOO00 + I1ii11iIi11i - i11iIiiIii + Oo0Ooo * I1ii11iIi11i
  if 20 - 20: I1Ii111 / o0oOOo0O0Ooo % OoOoOO00
  O00oo0O00 = struct . pack ( "HHHH" , iiII , I1iI1111i , socket . htons ( self . udp_length ) ,
 self . udp_checksum )
  if 65 - 65: OOooOOo + II111iiii
  if 61 - 61: i11iIiiIii * oO0o % Oo0Ooo * I1Ii111 - OoooooooOO - OoO0O00
  if 83 - 83: ooOoO0o / OOooOOo
  if 39 - 39: IiII + I11i
  IIi11Ii11ii = self . lisp_header . encode ( )
  if 70 - 70: I11i - Oo0Ooo / OoooooooOO % OoooooooOO
  if 95 - 95: OoooooooOO % OoooooooOO . Ii1I
  if 26 - 26: oO0o + IiII - II111iiii . II111iiii + I1ii11iIi11i + OoOoOO00
  if 68 - 68: O0
  if 76 - 76: I1ii11iIi11i
  if ( self . outer_version == 4 ) :
   ooO000OO = socket . htons ( self . udp_length + 20 )
   i111IIiIiiI1 = socket . htons ( 0x4000 )
   OO0 = struct . pack ( "BBHHHBBH" , 0x45 , self . outer_tos , ooO000OO , 0xdfdf ,
 i111IIiIiiI1 , self . outer_ttl , 17 , 0 )
   OO0 += self . outer_source . pack_address ( )
   OO0 += self . outer_dest . pack_address ( )
   OO0 = lisp_ip_checksum ( OO0 )
  elif ( self . outer_version == 6 ) :
   OO0 = ""
   if 28 - 28: Oo0Ooo % OOooOOo - OoO0O00 + ooOoO0o / ooOoO0o
   if 82 - 82: Oo0Ooo
   if 5 - 5: OoO0O00 / OoO0O00 - O0 - I1Ii111 + I1Ii111
   if 99 - 99: I11i * OoooooooOO / o0oOOo0O0Ooo . IiII - iIii1I11I1II1 - Ii1I
   if 31 - 31: IiII - OoO0O00 / OOooOOo . i1IIi / Ii1I
   if 66 - 66: OoO0O00
   if 72 - 72: I1Ii111
  else :
   return ( None )
   if 91 - 91: II111iiii / IiII + iIii1I11I1II1 . I11i - O0
   if 70 - 70: Ii1I * oO0o - I11i + Oo0Ooo % I1ii11iIi11i - IiII
  self . packet = OO0 + O00oo0O00 + IIi11Ii11ii + self . packet
  return ( self )
  if 81 - 81: O0 . O0
  if 75 - 75: iIii1I11I1II1 % IiII + I1ii11iIi11i * O0 . iII111i - ooOoO0o
 def cipher_pad ( self , packet ) :
  i1IIiIIIi1 = len ( packet )
  if ( ( i1IIiIIIi1 % 16 ) != 0 ) :
   oOoO00O = ( ( i1IIiIIIi1 / 16 ) + 1 ) * 16
   packet = packet . ljust ( oOoO00O )
   if 31 - 31: ooOoO0o . OoOoOO00 % OoOoOO00 % Oo0Ooo % I1IiiI * iII111i
  return ( packet )
  if 22 - 22: I11i % IiII . OoOoOO00 / ooOoO0o + OOooOOo
  if 85 - 85: I1IiiI - ooOoO0o % Oo0Ooo % II111iiii - OoooooooOO % IiII
 def encrypt ( self , key , addr_str ) :
  if ( key == None or key . shared_key == None ) :
   return ( [ self . packet , False ] )
   if 40 - 40: Ii1I
   if 59 - 59: I11i * OoooooooOO + OOooOOo . iIii1I11I1II1 / i1IIi
   if 75 - 75: I11i . OOooOOo - iIii1I11I1II1 * OoO0O00 * iII111i
   if 93 - 93: ooOoO0o
   if 18 - 18: ooOoO0o
  I111 = self . cipher_pad ( self . packet )
  OOOooO00OO00O = key . get_iv ( )
  if 78 - 78: II111iiii - Oo0Ooo - O0 . OOooOOo + i11iIiiIii - I1ii11iIi11i
  III11I1 = lisp_get_timestamp ( )
  o0oOOOOoo0 = None
  if ( key . cipher_suite == LISP_CS_25519_CHACHA ) :
   ooOO0OOO00o = chacha . ChaCha ( key . encrypt_key , OOOooO00OO00O ) . encrypt
  elif ( key . cipher_suite == LISP_CS_25519_GCM ) :
   OoOoO0ooooO0 = binascii . unhexlify ( key . encrypt_key )
   try :
    IIII1ii1 = AES . new ( OoOoO0ooooO0 , AES . MODE_GCM , OOOooO00OO00O )
    ooOO0OOO00o = IIII1ii1 . encrypt
    o0oOOOOoo0 = IIII1ii1 . digest
   except :
    lprint ( "You need AES-GCM, do a 'pip install pycryptodome'" )
    return ( [ self . packet , False ] )
    if 52 - 52: OoO0O00 - OOooOOo - ooOoO0o - o0oOOo0O0Ooo + i1IIi
  else :
   OoOoO0ooooO0 = binascii . unhexlify ( key . encrypt_key )
   ooOO0OOO00o = AES . new ( OoOoO0ooooO0 , AES . MODE_CBC , OOOooO00OO00O ) . encrypt
   if 10 - 10: OoooooooOO / iII111i / oO0o * Oo0Ooo / iIii1I11I1II1
   if 63 - 63: II111iiii
  IiiI1I = ooOO0OOO00o ( I111 )
  if 8 - 8: OOooOOo * Oo0Ooo / iII111i - OoO0O00 - OoooooooOO
  if ( IiiI1I == None ) : return ( [ self . packet , False ] )
  III11I1 = int ( str ( time . time ( ) - III11I1 ) . split ( "." ) [ 1 ] [ 0 : 6 ] )
  if 100 - 100: oO0o . iIii1I11I1II1 . iIii1I11I1II1
  if 55 - 55: oO0o
  if 37 - 37: IiII / i11iIiiIii / Oo0Ooo
  if 97 - 97: I1Ii111 . I11i / I1IiiI
  if 83 - 83: I11i - I1ii11iIi11i * oO0o
  if 90 - 90: Oo0Ooo * I1IiiI
  if ( o0oOOOOoo0 != None ) : IiiI1I += o0oOOOOoo0 ( )
  if 75 - 75: I1ii11iIi11i - OoOoOO00 * i11iIiiIii . OoooooooOO - Oo0Ooo . I11i
  if 6 - 6: I11i * oO0o / OoooooooOO % Ii1I * o0oOOo0O0Ooo
  if 28 - 28: IiII * I1IiiI % IiII
  if 95 - 95: O0 / I11i . I1Ii111
  if 17 - 17: I11i
  self . lisp_header . key_id ( key . key_id )
  IIi11Ii11ii = self . lisp_header . encode ( )
  if 56 - 56: ooOoO0o * o0oOOo0O0Ooo + I11i
  I11II11111i11 = key . do_icv ( IIi11Ii11ii + OOOooO00OO00O + IiiI1I , OOOooO00OO00O )
  if 83 - 83: oO0o - ooOoO0o - IiII % i1IIi - iII111i . o0oOOo0O0Ooo
  oOo0oO = 4 if ( key . do_poly ) else 8
  if 77 - 77: II111iiii
  iIii1I1iII = bold ( "Encrypt" , False )
  iiIi1iIiI = bold ( key . cipher_suite_string , False )
  addr_str = "RLOC: " + red ( addr_str , False )
  IiI = "poly" if key . do_poly else "sha256"
  IiI = bold ( IiI , False )
  IIiI = "ICV({}): 0x{}...{}" . format ( IiI , I11II11111i11 [ 0 : oOo0oO ] , I11II11111i11 [ - oOo0oO : : ] )
  dprint ( "{} for key-id: {}, {}, {}, {}-time: {} usec" . format ( iIii1I1iII , key . key_id , addr_str , IIiI , iiIi1iIiI , III11I1 ) )
  if 19 - 19: OoO0O00 . OoooooooOO * OoO0O00 + IiII + OoooooooOO
  if 19 - 19: Oo0Ooo
  I11II11111i11 = int ( I11II11111i11 , 16 )
  if ( key . do_poly ) :
   OoO = byte_swap_64 ( ( I11II11111i11 >> 64 ) & LISP_8_64_MASK )
   oO00o00 = byte_swap_64 ( I11II11111i11 & LISP_8_64_MASK )
   I11II11111i11 = struct . pack ( "QQ" , OoO , oO00o00 )
  else :
   OoO = byte_swap_64 ( ( I11II11111i11 >> 96 ) & LISP_8_64_MASK )
   oO00o00 = byte_swap_64 ( ( I11II11111i11 >> 32 ) & LISP_8_64_MASK )
   OOooooO0o0O0 = socket . htonl ( I11II11111i11 & 0xffffffff )
   I11II11111i11 = struct . pack ( "QQI" , OoO , oO00o00 , OOooooO0o0O0 )
   if 74 - 74: OoOoOO00 / i1IIi % OoooooooOO
   if 52 - 52: IiII % ooOoO0o
  return ( [ OOOooO00OO00O + IiiI1I + I11II11111i11 , True ] )
  if 25 - 25: I11i / I11i % OoooooooOO - I1ii11iIi11i * oO0o
  if 23 - 23: i11iIiiIii
 def decrypt ( self , packet , header_length , key , addr_str ) :
  if 100 - 100: oO0o + O0 . I1IiiI + i1IIi - OoOoOO00 + o0oOOo0O0Ooo
  if 65 - 65: II111iiii / Oo0Ooo
  if 42 - 42: i11iIiiIii . O0
  if 75 - 75: I1Ii111 + iIii1I11I1II1
  if 19 - 19: I1IiiI + i11iIiiIii . IiII - I11i / Ii1I + o0oOOo0O0Ooo
  if 38 - 38: Oo0Ooo / iIii1I11I1II1 * iIii1I11I1II1 % I1ii11iIi11i
  if ( key . do_poly ) :
   OoO , oO00o00 = struct . unpack ( "QQ" , packet [ - 16 : : ] )
   O00o = byte_swap_64 ( OoO ) << 64
   O00o |= byte_swap_64 ( oO00o00 )
   O00o = lisp_hex_string ( O00o ) . zfill ( 32 )
   packet = packet [ 0 : - 16 ]
   oOo0oO = 4
   o0o0ooOo00 = bold ( "poly" , False )
  else :
   OoO , oO00o00 , OOooooO0o0O0 = struct . unpack ( "QQI" , packet [ - 20 : : ] )
   O00o = byte_swap_64 ( OoO ) << 96
   O00o |= byte_swap_64 ( oO00o00 ) << 32
   O00o |= socket . htonl ( OOooooO0o0O0 )
   O00o = lisp_hex_string ( O00o ) . zfill ( 40 )
   packet = packet [ 0 : - 20 ]
   oOo0oO = 8
   o0o0ooOo00 = bold ( "sha" , False )
   if 91 - 91: OoO0O00 * I1Ii111 % OoO0O00 . o0oOOo0O0Ooo * I1ii11iIi11i . OOooOOo
  IIi11Ii11ii = self . lisp_header . encode ( )
  if 13 - 13: I1ii11iIi11i
  if 80 - 80: Oo0Ooo % IiII % OoooooooOO * Oo0Ooo % Ii1I
  if 41 - 41: OoooooooOO / i1IIi
  if 70 - 70: OoOoOO00 % o0oOOo0O0Ooo % i1IIi / I1ii11iIi11i % i11iIiiIii / i1IIi
  if ( key . cipher_suite == LISP_CS_25519_CHACHA ) :
   i1i1Ii1IiIII = 8
   iiIi1iIiI = bold ( "chacha" , False )
  elif ( key . cipher_suite == LISP_CS_25519_GCM ) :
   i1i1Ii1IiIII = 12
   iiIi1iIiI = bold ( "aes-gcm" , False )
  else :
   i1i1Ii1IiIII = 16
   iiIi1iIiI = bold ( "aes-cbc" , False )
   if 9 - 9: I11i - oO0o + O0 / iII111i % i1IIi
  OOOooO00OO00O = packet [ 0 : i1i1Ii1IiIII ]
  if 97 - 97: o0oOOo0O0Ooo * ooOoO0o
  if 78 - 78: I11i . OOooOOo + oO0o * iII111i - i1IIi
  if 27 - 27: Ii1I % i1IIi . Oo0Ooo % I1Ii111
  if 10 - 10: IiII / OoooooooOO
  IiiiIIiii = key . do_icv ( IIi11Ii11ii + packet , OOOooO00OO00O )
  if 91 - 91: o0oOOo0O0Ooo . iII111i % Oo0Ooo - iII111i . oO0o % i11iIiiIii
  iIi = "0x{}...{}" . format ( O00o [ 0 : oOo0oO ] , O00o [ - oOo0oO : : ] )
  O0O = "0x{}...{}" . format ( IiiiIIiii [ 0 : oOo0oO ] , IiiiIIiii [ - oOo0oO : : ] )
  if 71 - 71: I1ii11iIi11i + OoO0O00
  if ( IiiiIIiii != O00o ) :
   self . packet_error = "ICV-error"
   ii1 = iiIi1iIiI + "/" + o0o0ooOo00
   oooO0o0oOoO = bold ( "ICV failed ({})" . format ( ii1 ) , False )
   IIiI = "packet-ICV {} != computed-ICV {}" . format ( iIi , O0O )
   dprint ( ( "{} from RLOC {}, receive-port: {}, key-id: {}, " + "packet dropped, {}" ) . format ( oooO0o0oOoO , red ( addr_str , False ) ,
   # Oo0Ooo * IiII
 self . udp_sport , key . key_id , IIiI ) )
   dprint ( "{}" . format ( key . print_keys ( ) ) )
   if 83 - 83: OoooooooOO
   if 12 - 12: ooOoO0o
   if 36 - 36: I1Ii111 . IiII * OoooooooOO - o0oOOo0O0Ooo
   if 60 - 60: OOooOOo . iII111i / iIii1I11I1II1 + OOooOOo * I1Ii111
   if 82 - 82: i11iIiiIii . iIii1I11I1II1 * I1IiiI - I11i + Ii1I
   if 48 - 48: I1ii11iIi11i
   lisp_retry_decap_keys ( addr_str , IIi11Ii11ii + packet , OOOooO00OO00O , O00o )
   return ( [ None , False ] )
   if 96 - 96: ooOoO0o . OoooooooOO
   if 39 - 39: OOooOOo + OoO0O00
   if 80 - 80: OOooOOo % OoO0O00 / OoOoOO00
   if 54 - 54: Oo0Ooo % OoO0O00 - OOooOOo - I11i
   if 71 - 71: ooOoO0o . i11iIiiIii
  packet = packet [ i1i1Ii1IiIII : : ]
  if 56 - 56: O0 * iII111i + iII111i * iIii1I11I1II1 / ooOoO0o * I1Ii111
  if 25 - 25: iIii1I11I1II1 . I11i * i11iIiiIii + Oo0Ooo * I11i
  if 67 - 67: iII111i
  if 88 - 88: Oo0Ooo
  III11I1 = lisp_get_timestamp ( )
  if ( key . cipher_suite == LISP_CS_25519_CHACHA ) :
   i1ii111i = chacha . ChaCha ( key . encrypt_key , OOOooO00OO00O ) . decrypt
  elif ( key . cipher_suite == LISP_CS_25519_GCM ) :
   OoOoO0ooooO0 = binascii . unhexlify ( key . encrypt_key )
   try :
    i1ii111i = AES . new ( OoOoO0ooooO0 , AES . MODE_GCM , OOOooO00OO00O ) . decrypt
   except :
    self . packet_error = "no-decrypt-key"
    lprint ( "You need AES-GCM, do a 'pip install pycryptodome'" )
    return ( [ None , False ] )
    if 42 - 42: OOooOOo % OoooooooOO / IiII
  else :
   if ( ( len ( packet ) % 16 ) != 0 ) :
    dprint ( "Ciphertext not multiple of 16 bytes, packet dropped" )
    return ( [ None , False ] )
    if 4 - 4: i11iIiiIii - OOooOOo % I1ii11iIi11i * I1Ii111 % o0oOOo0O0Ooo
   OoOoO0ooooO0 = binascii . unhexlify ( key . encrypt_key )
   i1ii111i = AES . new ( OoOoO0ooooO0 , AES . MODE_CBC , OOOooO00OO00O ) . decrypt
   if 71 - 71: ooOoO0o . ooOoO0o - iIii1I11I1II1
   if 22 - 22: OoooooooOO / I1ii11iIi11i % iII111i * OoOoOO00
  Ii1IiiiI1ii = i1ii111i ( packet )
  III11I1 = int ( str ( time . time ( ) - III11I1 ) . split ( "." ) [ 1 ] [ 0 : 6 ] )
  if 55 - 55: I1ii11iIi11i
  if 76 - 76: oO0o - i11iIiiIii
  if 27 - 27: I1ii11iIi11i - i11iIiiIii % I1Ii111 / Oo0Ooo . Oo0Ooo / OoooooooOO
  if 76 - 76: I11i * OoO0O00 . iIii1I11I1II1 % OoooooooOO % I1ii11iIi11i
  iIii1I1iII = bold ( "Decrypt" , False )
  addr_str = "RLOC: " + red ( addr_str , False )
  IiI = "poly" if key . do_poly else "sha256"
  IiI = bold ( IiI , False )
  IIiI = "ICV({}): {}" . format ( IiI , iIi )
  dprint ( "{} for key-id: {}, {}, {} (good), {}-time: {} usec" . format ( iIii1I1iII , key . key_id , addr_str , IIiI , iiIi1iIiI , III11I1 ) )
  if 39 - 39: II111iiii * OoOoOO00 . O0 * I11i
  if 89 - 89: Ii1I - ooOoO0o . I11i - I1Ii111 - I1IiiI
  if 79 - 79: IiII + IiII + Ii1I
  if 39 - 39: O0 - OoooooooOO
  if 63 - 63: iIii1I11I1II1 % o0oOOo0O0Ooo * ooOoO0o
  if 79 - 79: O0
  if 32 - 32: II111iiii . O0 + Ii1I / OoOoOO00 / IiII / OOooOOo
  self . packet = self . packet [ 0 : header_length ]
  return ( [ Ii1IiiiI1ii , True ] )
  if 15 - 15: I1ii11iIi11i
  if 4 - 4: IiII + iIii1I11I1II1 * iII111i + Oo0Ooo * o0oOOo0O0Ooo % II111iiii
 def fragment_outer ( self , outer_hdr , inner_packet ) :
  OO0o0o0oo = 1000
  if 40 - 40: Oo0Ooo
  if 47 - 47: OoOoOO00
  if 65 - 65: O0 + I1Ii111 % Ii1I * I1IiiI / ooOoO0o / OoOoOO00
  if 71 - 71: i11iIiiIii / OoOoOO00 . oO0o
  if 33 - 33: oO0o
  IIIi11 = [ ]
  oOO0OO0O = 0
  i1IIiIIIi1 = len ( inner_packet )
  while ( oOO0OO0O < i1IIiIIIi1 ) :
   i111IIiIiiI1 = inner_packet [ oOO0OO0O : : ]
   if ( len ( i111IIiIiiI1 ) > OO0o0o0oo ) : i111IIiIiiI1 = i111IIiIiiI1 [ 0 : OO0o0o0oo ]
   IIIi11 . append ( i111IIiIiiI1 )
   oOO0OO0O += len ( i111IIiIiiI1 )
   if 69 - 69: O0 - O0
   if 41 - 41: IiII % o0oOOo0O0Ooo
   if 67 - 67: O0 % I1Ii111
   if 35 - 35: I1IiiI . OoOoOO00 + OoooooooOO % Oo0Ooo % OOooOOo
   if 39 - 39: Ii1I
   if 60 - 60: OOooOOo
  o000ooOo0o0OO = [ ]
  oOO0OO0O = 0
  for i111IIiIiiI1 in IIIi11 :
   if 1 - 1: iIii1I11I1II1 % ooOoO0o + O0
   if 22 - 22: o0oOOo0O0Ooo + Oo0Ooo . ooOoO0o + I1ii11iIi11i * iII111i . i11iIiiIii
   if 90 - 90: OOooOOo * OoOoOO00 - Oo0Ooo + o0oOOo0O0Ooo
   if 53 - 53: OoooooooOO . OoooooooOO + o0oOOo0O0Ooo - iII111i + OOooOOo
   i1111iIII = oOO0OO0O if ( i111IIiIiiI1 == IIIi11 [ - 1 ] ) else 0x2000 + oOO0OO0O
   i1111iIII = socket . htons ( i1111iIII )
   outer_hdr = outer_hdr [ 0 : 6 ] + struct . pack ( "H" , i1111iIII ) + outer_hdr [ 8 : : ]
   if 50 - 50: O0 * I1ii11iIi11i + II111iiii . i1IIi + OoOoOO00
   if 39 - 39: iIii1I11I1II1 + ooOoO0o
   if 92 - 92: I11i % i11iIiiIii % Oo0Ooo
   if 23 - 23: II111iiii * iII111i
   o0Oo = socket . htons ( len ( i111IIiIiiI1 ) + 20 )
   outer_hdr = outer_hdr [ 0 : 2 ] + struct . pack ( "H" , o0Oo ) + outer_hdr [ 4 : : ]
   outer_hdr = lisp_ip_checksum ( outer_hdr )
   o000ooOo0o0OO . append ( outer_hdr + i111IIiIiiI1 )
   oOO0OO0O += len ( i111IIiIiiI1 ) / 8
   if 16 - 16: iII111i % I1IiiI - ooOoO0o
  return ( o000ooOo0o0OO )
  if 100 - 100: OoooooooOO * oO0o
  if 83 - 83: iIii1I11I1II1 - ooOoO0o - I1Ii111 / OoO0O00 - O0
 def fragment ( self ) :
  I111 = self . fix_outer_header ( self . packet )
  if 81 - 81: Ii1I - oO0o * I1ii11iIi11i / I1Ii111
  if 21 - 21: OoO0O00
  if 63 - 63: I11i . O0 * I11i + iIii1I11I1II1
  if 46 - 46: i1IIi + II111iiii * i1IIi - Ii1I
  if 79 - 79: II111iiii - oO0o * I1ii11iIi11i - OoOoOO00 . I1ii11iIi11i
  if 11 - 11: O0 * OoOoOO00
  i1IIiIIIi1 = len ( I111 )
  if ( i1IIiIIIi1 <= 1500 ) : return ( [ I111 ] , "Fragment-None" )
  if 37 - 37: OoOoOO00 + O0 . O0 * Oo0Ooo % I1Ii111 / iII111i
  I111 = self . packet
  if 18 - 18: OoooooooOO
  if 57 - 57: ooOoO0o . OoOoOO00 * o0oOOo0O0Ooo - OoooooooOO
  if 75 - 75: i11iIiiIii / o0oOOo0O0Ooo . IiII . i1IIi . i1IIi / I11i
  if 94 - 94: ooOoO0o + I1IiiI
  if 56 - 56: OoOoOO00 % o0oOOo0O0Ooo
  if ( self . inner_version != 4 ) :
   i11i = random . randint ( 0 , 0xffff )
   Ii11I1I11II = I111 [ 0 : 4 ] + struct . pack ( "H" , i11i ) + I111 [ 6 : 20 ]
   IIiiiI = I111 [ 20 : : ]
   o000ooOo0o0OO = self . fragment_outer ( Ii11I1I11II , IIiiiI )
   return ( o000ooOo0o0OO , "Fragment-Outer" )
   if 59 - 59: oO0o % ooOoO0o
   if 36 - 36: OoooooooOO
   if 33 - 33: O0 + Oo0Ooo - iIii1I11I1II1 % i11iIiiIii / I1IiiI
   if 47 - 47: I1ii11iIi11i * oO0o + iIii1I11I1II1 - oO0o / IiII
   if 86 - 86: IiII
  Iii1I = 56 if ( self . outer_version == 6 ) else 36
  Ii11I1I11II = I111 [ 0 : Iii1I ]
  ooo = I111 [ Iii1I : Iii1I + 20 ]
  IIiiiI = I111 [ Iii1I + 20 : : ]
  if 39 - 39: oO0o / ooOoO0o * II111iiii * iII111i
  if 41 - 41: i11iIiiIii * O0 - iII111i . II111iiii % OoO0O00 % I1ii11iIi11i
  if 32 - 32: OOooOOo + iII111i + iIii1I11I1II1 * Oo0Ooo
  if 62 - 62: i11iIiiIii
  i1Iii = struct . unpack ( "H" , ooo [ 6 : 8 ] ) [ 0 ]
  i1Iii = socket . ntohs ( i1Iii )
  if ( i1Iii & 0x4000 ) :
   o000o0o0ooO0 = bold ( "DF-bit set" , False )
   dprint ( "{} in inner header, packet discarded" . format ( o000o0o0ooO0 ) )
   return ( [ ] , "Fragment-None-DF-bit" )
   if 27 - 27: OoOoOO00 . iIii1I11I1II1
   if 87 - 87: ooOoO0o * OoO0O00 + o0oOOo0O0Ooo . OOooOOo - ooOoO0o
  oOO0OO0O = 0
  i1IIiIIIi1 = len ( IIiiiI )
  o000ooOo0o0OO = [ ]
  while ( oOO0OO0O < i1IIiIIIi1 ) :
   o000ooOo0o0OO . append ( IIiiiI [ oOO0OO0O : oOO0OO0O + 1400 ] )
   oOO0OO0O += 1400
   if 33 - 33: II111iiii / O0 / IiII - I11i - i1IIi
   if 8 - 8: i11iIiiIii . iII111i / iIii1I11I1II1 / I1ii11iIi11i / IiII - Ii1I
   if 32 - 32: o0oOOo0O0Ooo . i1IIi * Oo0Ooo
   if 98 - 98: Ii1I - II111iiii / I1IiiI . oO0o * IiII . I11i
   if 25 - 25: i11iIiiIii / OoOoOO00 - I1Ii111 / OoO0O00 . o0oOOo0O0Ooo . o0oOOo0O0Ooo
  IIIi11 = o000ooOo0o0OO
  o000ooOo0o0OO = [ ]
  iI1 = True if i1Iii & 0x2000 else False
  i1Iii = ( i1Iii & 0x1fff ) * 8
  for i111IIiIiiI1 in IIIi11 :
   if 43 - 43: I1ii11iIi11i + o0oOOo0O0Ooo
   if 50 - 50: oO0o % i1IIi * O0
   if 4 - 4: iIii1I11I1II1 . i1IIi
   if 63 - 63: iIii1I11I1II1 + IiII % i1IIi / I1IiiI % II111iiii
   OO0iiiii1iiIIii = i1Iii / 8
   if ( iI1 ) :
    OO0iiiii1iiIIii |= 0x2000
   elif ( i111IIiIiiI1 != IIIi11 [ - 1 ] ) :
    OO0iiiii1iiIIii |= 0x2000
    if 8 - 8: I1ii11iIi11i * I1ii11iIi11i * i1IIi + iII111i . I1ii11iIi11i
   OO0iiiii1iiIIii = socket . htons ( OO0iiiii1iiIIii )
   ooo = ooo [ 0 : 6 ] + struct . pack ( "H" , OO0iiiii1iiIIii ) + ooo [ 8 : : ]
   if 100 - 100: OoooooooOO - O0 . I11i / I11i + II111iiii * OoOoOO00
   if 37 - 37: Oo0Ooo
   if 72 - 72: IiII % I1ii11iIi11i * OOooOOo . i11iIiiIii % IiII * OOooOOo
   if 15 - 15: I11i / Oo0Ooo * I11i
   if 20 - 20: ooOoO0o - OOooOOo * OoO0O00 * o0oOOo0O0Ooo * OOooOOo / IiII
   if 40 - 40: I1IiiI * o0oOOo0O0Ooo . I1IiiI
   i1IIiIIIi1 = len ( i111IIiIiiI1 )
   i1Iii += i1IIiIIIi1
   o0Oo = socket . htons ( i1IIiIIIi1 + 20 )
   ooo = ooo [ 0 : 2 ] + struct . pack ( "H" , o0Oo ) + ooo [ 4 : 10 ] + struct . pack ( "H" , 0 ) + ooo [ 12 : : ]
   if 62 - 62: ooOoO0o + II111iiii % ooOoO0o
   ooo = lisp_ip_checksum ( ooo )
   Ii1IIii = ooo + i111IIiIiiI1
   if 80 - 80: i11iIiiIii
   if 29 - 29: I1IiiI . OOooOOo + II111iiii . Oo0Ooo
   if 29 - 29: Ii1I - O0 . ooOoO0o / I1ii11iIi11i / i1IIi . OoOoOO00
   if 36 - 36: OoO0O00 - O0 * I1IiiI / I1ii11iIi11i / OOooOOo
   if 33 - 33: OoooooooOO % I1ii11iIi11i . O0 / I1ii11iIi11i
   i1IIiIIIi1 = len ( Ii1IIii )
   if ( self . outer_version == 4 ) :
    o0Oo = i1IIiIIIi1 + Iii1I
    i1IIiIIIi1 += 16
    Ii11I1I11II = Ii11I1I11II [ 0 : 2 ] + struct . pack ( "H" , o0Oo ) + Ii11I1I11II [ 4 : : ]
    if 63 - 63: IiII + iIii1I11I1II1 + I1IiiI + I1Ii111
    Ii11I1I11II = lisp_ip_checksum ( Ii11I1I11II )
    Ii1IIii = Ii11I1I11II + Ii1IIii
    Ii1IIii = self . fix_outer_header ( Ii1IIii )
    if 72 - 72: OoO0O00 + i11iIiiIii + I1ii11iIi11i
    if 96 - 96: oO0o % i1IIi / o0oOOo0O0Ooo
    if 13 - 13: II111iiii - Oo0Ooo % i11iIiiIii + iII111i
    if 88 - 88: O0 . oO0o % I1IiiI
    if 10 - 10: I1IiiI + O0
   Oooo0Oo00o = Iii1I - 12
   o0Oo = socket . htons ( i1IIiIIIi1 )
   Ii1IIii = Ii1IIii [ 0 : Oooo0Oo00o ] + struct . pack ( "H" , o0Oo ) + Ii1IIii [ Oooo0Oo00o + 2 : : ]
   if 32 - 32: OoOoOO00 . iIii1I11I1II1 % oO0o . O0 . OoOoOO00 / iII111i
   o000ooOo0o0OO . append ( Ii1IIii )
   if 45 - 45: iIii1I11I1II1
  return ( o000ooOo0o0OO , "Fragment-Inner" )
  if 41 - 41: iII111i % iII111i - IiII % OoO0O00 - OoooooooOO - iII111i
  if 66 - 66: o0oOOo0O0Ooo % OoOoOO00
 def fix_outer_header ( self , packet ) :
  if 30 - 30: OoOoOO00 * Oo0Ooo % iIii1I11I1II1 % OoO0O00 + i11iIiiIii
  if 46 - 46: I1IiiI . IiII - i11iIiiIii - I1Ii111
  if 97 - 97: II111iiii % Oo0Ooo * IiII
  if 51 - 51: Oo0Ooo % OOooOOo . Oo0Ooo
  if 72 - 72: Ii1I % Ii1I / I1IiiI
  if 40 - 40: Oo0Ooo - OOooOOo + I1Ii111 - o0oOOo0O0Ooo % I1IiiI . ooOoO0o
  if 35 - 35: i11iIiiIii + OoooooooOO * iIii1I11I1II1 . I1Ii111
  if 48 - 48: iII111i * i1IIi % OoooooooOO * Ii1I * OoO0O00
  if ( self . outer_version == 4 or self . inner_version == 4 ) :
   if ( lisp_is_macos ( ) ) :
    packet = packet [ 0 : 2 ] + packet [ 3 ] + packet [ 2 ] + packet [ 4 : 6 ] + packet [ 7 ] + packet [ 6 ] + packet [ 8 : : ]
    if 7 - 7: iII111i . Ii1I . iII111i - I1Ii111
   else :
    packet = packet [ 0 : 2 ] + packet [ 3 ] + packet [ 2 ] + packet [ 4 : : ]
    if 33 - 33: ooOoO0o + OoooooooOO - OoO0O00 / i1IIi / OoooooooOO
    if 82 - 82: I1ii11iIi11i / OOooOOo - iII111i / Oo0Ooo * OoO0O00
  return ( packet )
  if 55 - 55: OoooooooOO
  if 73 - 73: OoOoOO00 - I1ii11iIi11i % Oo0Ooo + I1ii11iIi11i - O0 . OoO0O00
 def send_packet ( self , lisp_raw_socket , dest ) :
  if ( lisp_flow_logging and dest != self . inner_dest ) : self . log_flow ( True )
  if 38 - 38: O0
  dest = dest . print_address_no_iid ( )
  o000ooOo0o0OO , ooO = self . fragment ( )
  if 34 - 34: I1Ii111 * II111iiii
  for Ii1IIii in o000ooOo0o0OO :
   if ( len ( o000ooOo0o0OO ) != 1 ) :
    self . packet = Ii1IIii
    self . print_packet ( ooO , True )
    if 71 - 71: IiII
    if 97 - 97: I1ii11iIi11i
   try : lisp_raw_socket . sendto ( Ii1IIii , ( dest , 0 ) )
   except socket . error , I1i11II :
    lprint ( "socket.sendto() failed: {}" . format ( I1i11II ) )
    if 86 - 86: Oo0Ooo - OOooOOo . OoOoOO00 . II111iiii * I1IiiI . II111iiii
    if 34 - 34: o0oOOo0O0Ooo . I1Ii111 % IiII - O0 / I1Ii111
    if 91 - 91: i11iIiiIii % I1Ii111 * oO0o - I1ii11iIi11i . I1Ii111
    if 28 - 28: i11iIiiIii
 def send_l2_packet ( self , l2_socket , mac_header ) :
  if ( l2_socket == None ) :
   lprint ( "No layer-2 socket, drop IPv6 packet" )
   return
   if 51 - 51: I1IiiI + ooOoO0o * O0 . Ii1I
  if ( mac_header == None ) :
   lprint ( "Could not build MAC header, drop IPv6 packet" )
   return
   if 82 - 82: OOooOOo * I1ii11iIi11i % Ii1I . OOooOOo
   if 43 - 43: OoO0O00 . ooOoO0o * Oo0Ooo
  I111 = mac_header + self . packet
  if 20 - 20: i1IIi . i1IIi - I11i
  if 89 - 89: ooOoO0o - I11i . O0 % OoooooooOO . i11iIiiIii
  if 35 - 35: II111iiii / OoOoOO00 - O0 . II111iiii
  if 55 - 55: Oo0Ooo % i1IIi * I11i
  if 95 - 95: OOooOOo / II111iiii - o0oOOo0O0Ooo % I1Ii111 . I11i
  if 63 - 63: iIii1I11I1II1 / ooOoO0o
  if 24 - 24: Oo0Ooo / iIii1I11I1II1 % OOooOOo * OoOoOO00 - iIii1I11I1II1
  if 50 - 50: II111iiii
  if 39 - 39: II111iiii . OoOoOO00 - Oo0Ooo * i1IIi . OoooooooOO
  if 44 - 44: I1IiiI
  if 55 - 55: oO0o . I1Ii111 * I1Ii111
  l2_socket . write ( I111 )
  return
  if 82 - 82: I1IiiI % OoO0O00 % I11i + I11i
  if 6 - 6: Oo0Ooo
 def bridge_l2_packet ( self , eid , db ) :
  try : O0OOOOoO00oo = db . dynamic_eids [ eid . print_address_no_iid ( ) ]
  except : return
  try : iiiii11I1 = lisp_myinterfaces [ O0OOOOoO00oo . interface ]
  except : return
  try :
   socket = iiiii11I1 . get_bridge_socket ( )
   if ( socket == None ) : return
  except : return
  if 80 - 80: i1IIi . I1IiiI - oO0o + OOooOOo + iII111i % oO0o
  try : socket . send ( self . packet )
  except socket . error , I1i11II :
   lprint ( "bridge_l2_packet(): socket.send() failed: {}" . format ( I1i11II ) )
   if 13 - 13: II111iiii / OoOoOO00 / OoOoOO00 + ooOoO0o
   if 49 - 49: O0 / II111iiii * I1IiiI - OoooooooOO . II111iiii % IiII
   if 13 - 13: oO0o . iIii1I11I1II1 . OOooOOo . IiII
 def decode ( self , is_lisp_packet , lisp_ipc_socket , stats ) :
  self . packet_error = ""
  I111 = self . packet
  oo0oo00O0O = len ( I111 )
  iIiiI1I = Oo0 = True
  if 34 - 34: OoOoOO00 - oO0o * OoooooooOO
  if 5 - 5: i11iIiiIii * iII111i - Ii1I - I1ii11iIi11i - i1IIi + iII111i
  if 4 - 4: ooOoO0o + O0 . i1IIi * I1ii11iIi11i - o0oOOo0O0Ooo
  if 42 - 42: o0oOOo0O0Ooo * OoOoOO00 . OoO0O00 - iII111i / II111iiii
  iII1ii11III = 0
  IIiI1i = self . lisp_header . get_instance_id ( )
  if ( is_lisp_packet ) :
   OOOO0oO0O = struct . unpack ( "B" , I111 [ 0 : 1 ] ) [ 0 ]
   self . outer_version = OOOO0oO0O >> 4
   if ( self . outer_version == 4 ) :
    if 59 - 59: II111iiii
    if 29 - 29: OoO0O00 . ooOoO0o
    if 58 - 58: IiII % i11iIiiIii * II111iiii . I1ii11iIi11i
    if 94 - 94: i11iIiiIii . OOooOOo + iIii1I11I1II1 * I1Ii111 * I1Ii111
    if 36 - 36: I11i - IiII . IiII
    Oo0OOOO0oOoo0 = struct . unpack ( "H" , I111 [ 10 : 12 ] ) [ 0 ]
    I111 = lisp_ip_checksum ( I111 )
    iIiI1I1IIi11 = struct . unpack ( "H" , I111 [ 10 : 12 ] ) [ 0 ]
    if ( iIiI1I1IIi11 != 0 ) :
     if ( Oo0OOOO0oOoo0 != 0 or lisp_is_macos ( ) == False ) :
      self . packet_error = "checksum-error"
      if ( stats ) :
       stats [ self . packet_error ] . increment ( oo0oo00O0O )
       if 92 - 92: IiII . Oo0Ooo - Oo0Ooo - o0oOOo0O0Ooo + I1Ii111 - O0
       if 30 - 30: IiII - iII111i - OoO0O00
      lprint ( "IPv4 header checksum failed for outer header" )
      if ( lisp_flow_logging ) : self . log_flow ( False )
      return ( None )
      if 33 - 33: iIii1I11I1II1 / iII111i
      if 74 - 74: o0oOOo0O0Ooo / oO0o - II111iiii . II111iiii . IiII + II111iiii
      if 92 - 92: I1Ii111 % iIii1I11I1II1 - iII111i / i11iIiiIii % ooOoO0o * o0oOOo0O0Ooo
    ooo0O0O0oo0 = LISP_AFI_IPV4
    oOO0OO0O = 12
    self . outer_tos = struct . unpack ( "B" , I111 [ 1 : 2 ] ) [ 0 ]
    self . outer_ttl = struct . unpack ( "B" , I111 [ 8 : 9 ] ) [ 0 ]
    iII1ii11III = 20
   elif ( self . outer_version == 6 ) :
    ooo0O0O0oo0 = LISP_AFI_IPV6
    oOO0OO0O = 8
    oo000oO = struct . unpack ( "H" , I111 [ 0 : 2 ] ) [ 0 ]
    self . outer_tos = ( socket . ntohs ( oo000oO ) >> 4 ) & 0xff
    self . outer_ttl = struct . unpack ( "B" , I111 [ 7 : 8 ] ) [ 0 ]
    iII1ii11III = 40
   else :
    self . packet_error = "outer-header-error"
    if ( stats ) : stats [ self . packet_error ] . increment ( oo0oo00O0O )
    lprint ( "Cannot decode outer header" )
    return ( None )
    if 8 - 8: I1IiiI % II111iiii - o0oOOo0O0Ooo - I11i % I1IiiI
    if 93 - 93: Ii1I * iII111i / OOooOOo
   self . outer_source . afi = ooo0O0O0oo0
   self . outer_dest . afi = ooo0O0O0oo0
   oooO00oo0 = self . outer_source . addr_length ( )
   if 74 - 74: IiII / ooOoO0o
   self . outer_source . unpack_address ( I111 [ oOO0OO0O : oOO0OO0O + oooO00oo0 ] )
   oOO0OO0O += oooO00oo0
   self . outer_dest . unpack_address ( I111 [ oOO0OO0O : oOO0OO0O + oooO00oo0 ] )
   I111 = I111 [ iII1ii11III : : ]
   self . outer_source . mask_len = self . outer_source . host_mask_len ( )
   self . outer_dest . mask_len = self . outer_dest . host_mask_len ( )
   if 86 - 86: O0 . i1IIi - OoO0O00 / Oo0Ooo / I1ii11iIi11i
   if 64 - 64: OoooooooOO - i1IIi / II111iiii
   if 49 - 49: Oo0Ooo + O0 + IiII . II111iiii % ooOoO0o
   if 33 - 33: OoOoOO00 . iIii1I11I1II1 / I11i % Ii1I
   IIiiI11 = struct . unpack ( "H" , I111 [ 0 : 2 ] ) [ 0 ]
   self . udp_sport = socket . ntohs ( IIiiI11 )
   IIiiI11 = struct . unpack ( "H" , I111 [ 2 : 4 ] ) [ 0 ]
   self . udp_dport = socket . ntohs ( IIiiI11 )
   IIiiI11 = struct . unpack ( "H" , I111 [ 4 : 6 ] ) [ 0 ]
   self . udp_length = socket . ntohs ( IIiiI11 )
   IIiiI11 = struct . unpack ( "H" , I111 [ 6 : 8 ] ) [ 0 ]
   self . udp_checksum = socket . ntohs ( IIiiI11 )
   I111 = I111 [ 8 : : ]
   if 7 - 7: I1IiiI / OoO0O00 + I1Ii111 + I11i / I1IiiI
   if 82 - 82: I1ii11iIi11i + OoooooooOO
   if 21 - 21: oO0o * oO0o / I11i . iII111i
   if 10 - 10: Ii1I * OOooOOo - Oo0Ooo - OoooooooOO / o0oOOo0O0Ooo
   iIiiI1I = ( self . udp_dport == LISP_DATA_PORT or
 self . udp_sport == LISP_DATA_PORT )
   Oo0 = ( self . udp_dport in ( LISP_L2_DATA_PORT , LISP_VXLAN_DATA_PORT ) )
   if 86 - 86: I1Ii111 % I1IiiI
   if 22 - 22: i11iIiiIii * I1Ii111 . Oo0Ooo . OoooooooOO + I1IiiI
   if 24 - 24: II111iiii / Ii1I . iIii1I11I1II1 - II111iiii % O0
   if 8 - 8: OoO0O00 % iII111i . OoooooooOO - Ii1I % OoooooooOO
   if ( self . lisp_header . decode ( I111 ) == False ) :
    self . packet_error = "lisp-header-error"
    if ( stats ) : stats [ self . packet_error ] . increment ( oo0oo00O0O )
    if 61 - 61: o0oOOo0O0Ooo / i11iIiiIii
    if ( lisp_flow_logging ) : self . log_flow ( False )
    lprint ( "Cannot decode LISP header" )
    return ( None )
    if 28 - 28: OOooOOo / OoOoOO00
   I111 = I111 [ 8 : : ]
   IIiI1i = self . lisp_header . get_instance_id ( )
   iII1ii11III += 16
   if 30 - 30: ooOoO0o
  if ( IIiI1i == 0xffffff ) : IIiI1i = 0
  if 57 - 57: o0oOOo0O0Ooo * i11iIiiIii / OoOoOO00
  if 40 - 40: iIii1I11I1II1 - ooOoO0o / Oo0Ooo
  if 24 - 24: oO0o - iII111i / ooOoO0o
  if 10 - 10: OoOoOO00 * i1IIi
  I1Ii1ii = False
  iIIi1 = self . lisp_header . k_bits
  if ( iIIi1 ) :
   I11i11I = lisp_get_crypto_decap_lookup_key ( self . outer_source ,
 self . udp_sport )
   if ( I11i11I == None ) :
    self . packet_error = "no-decrypt-key"
    if ( stats ) : stats [ self . packet_error ] . increment ( oo0oo00O0O )
    if 76 - 76: I1IiiI - I1IiiI - o0oOOo0O0Ooo % ooOoO0o * O0
    self . print_packet ( "Receive" , is_lisp_packet )
    I1i1iI = bold ( "No key available" , False )
    dprint ( "{} for key-id {} to decrypt packet" . format ( I1i1iI , iIIi1 ) )
    if ( lisp_flow_logging ) : self . log_flow ( False )
    return ( None )
    if 98 - 98: OoO0O00
    if 18 - 18: I11i + Oo0Ooo - OoO0O00 / I1Ii111 / OOooOOo
   OOoOoO = lisp_crypto_keys_by_rloc_decap [ I11i11I ] [ iIIi1 ]
   if ( OOoOoO == None ) :
    self . packet_error = "no-decrypt-key"
    if ( stats ) : stats [ self . packet_error ] . increment ( oo0oo00O0O )
    if 72 - 72: OoOoOO00 / I1Ii111 * IiII % iIii1I11I1II1
    self . print_packet ( "Receive" , is_lisp_packet )
    I1i1iI = bold ( "No key available" , False )
    dprint ( "{} to decrypt packet from RLOC {}" . format ( I1i1iI ,
 red ( I11i11I , False ) ) )
    if ( lisp_flow_logging ) : self . log_flow ( False )
    return ( None )
    if 53 - 53: OoO0O00 . O0 . I1IiiI * OOooOOo / o0oOOo0O0Ooo
    if 34 - 34: OoOoOO00
    if 16 - 16: i1IIi - I1Ii111 - II111iiii
    if 83 - 83: I1IiiI - OoO0O00 - o0oOOo0O0Ooo / O0 - I11i . II111iiii
    if 27 - 27: Ii1I
   OOoOoO . use_count += 1
   I111 , I1Ii1ii = self . decrypt ( I111 , iII1ii11III , OOoOoO ,
 I11i11I )
   if ( I1Ii1ii == False ) :
    if ( stats ) : stats [ self . packet_error ] . increment ( oo0oo00O0O )
    if ( lisp_flow_logging ) : self . log_flow ( False )
    return ( None )
    if 59 - 59: Ii1I / II111iiii - IiII % OoOoOO00 % OoooooooOO
    if 79 - 79: iII111i . OoooooooOO . I1IiiI * O0 * OoO0O00 - OOooOOo
    if 33 - 33: I1ii11iIi11i . Oo0Ooo + I1IiiI + o0oOOo0O0Ooo
    if 54 - 54: ooOoO0o * iII111i * iII111i % OoOoOO00 - OOooOOo % I1ii11iIi11i
    if 44 - 44: Oo0Ooo . OOooOOo + I11i
    if 22 - 22: I1Ii111 * OoooooooOO + i11iIiiIii % OoO0O00
  OOOO0oO0O = struct . unpack ( "B" , I111 [ 0 : 1 ] ) [ 0 ]
  self . inner_version = OOOO0oO0O >> 4
  if ( iIiiI1I and self . inner_version == 4 and OOOO0oO0O >= 0x45 ) :
   ooOo0 = socket . ntohs ( struct . unpack ( "H" , I111 [ 2 : 4 ] ) [ 0 ] )
   self . inner_tos = struct . unpack ( "B" , I111 [ 1 : 2 ] ) [ 0 ]
   self . inner_ttl = struct . unpack ( "B" , I111 [ 8 : 9 ] ) [ 0 ]
   self . inner_protocol = struct . unpack ( "B" , I111 [ 9 : 10 ] ) [ 0 ]
   self . inner_source . afi = LISP_AFI_IPV4
   self . inner_dest . afi = LISP_AFI_IPV4
   self . inner_source . unpack_address ( I111 [ 12 : 16 ] )
   self . inner_dest . unpack_address ( I111 [ 16 : 20 ] )
   i1Iii = socket . ntohs ( struct . unpack ( "H" , I111 [ 6 : 8 ] ) [ 0 ] )
   self . inner_is_fragment = ( i1Iii & 0x2000 or i1Iii != 0 )
   if ( self . inner_protocol == LISP_UDP_PROTOCOL ) :
    self . inner_sport = struct . unpack ( "H" , I111 [ 20 : 22 ] ) [ 0 ]
    self . inner_sport = socket . ntohs ( self . inner_sport )
    self . inner_dport = struct . unpack ( "H" , I111 [ 22 : 24 ] ) [ 0 ]
    self . inner_dport = socket . ntohs ( self . inner_dport )
    if 61 - 61: II111iiii
  elif ( iIiiI1I and self . inner_version == 6 and OOOO0oO0O >= 0x60 ) :
   ooOo0 = socket . ntohs ( struct . unpack ( "H" , I111 [ 4 : 6 ] ) [ 0 ] ) + 40
   oo000oO = struct . unpack ( "H" , I111 [ 0 : 2 ] ) [ 0 ]
   self . inner_tos = ( socket . ntohs ( oo000oO ) >> 4 ) & 0xff
   self . inner_ttl = struct . unpack ( "B" , I111 [ 7 : 8 ] ) [ 0 ]
   self . inner_protocol = struct . unpack ( "B" , I111 [ 6 : 7 ] ) [ 0 ]
   self . inner_source . afi = LISP_AFI_IPV6
   self . inner_dest . afi = LISP_AFI_IPV6
   self . inner_source . unpack_address ( I111 [ 8 : 24 ] )
   self . inner_dest . unpack_address ( I111 [ 24 : 40 ] )
   if ( self . inner_protocol == LISP_UDP_PROTOCOL ) :
    self . inner_sport = struct . unpack ( "H" , I111 [ 20 : 22 ] ) [ 0 ]
    self . inner_sport = socket . ntohs ( self . inner_sport )
    self . inner_dport = struct . unpack ( "H" , I111 [ 42 : 44 ] ) [ 0 ]
    self . inner_dport = socket . ntohs ( self . inner_dport )
    if 48 - 48: OOooOOo
  elif ( Oo0 ) :
   ooOo0 = len ( I111 )
   self . inner_tos = 0
   self . inner_ttl = 0
   self . inner_protocol = 0
   self . inner_source . afi = LISP_AFI_MAC
   self . inner_dest . afi = LISP_AFI_MAC
   self . inner_dest . unpack_address ( self . swap_mac ( I111 [ 0 : 6 ] ) )
   self . inner_source . unpack_address ( self . swap_mac ( I111 [ 6 : 12 ] ) )
  elif ( self . lisp_header . get_instance_id ( ) == 0xffffff ) :
   if ( lisp_flow_logging ) : self . log_flow ( False )
   return ( self )
  else :
   self . packet_error = "bad-inner-version"
   if ( stats ) : stats [ self . packet_error ] . increment ( oo0oo00O0O )
   if 26 - 26: iII111i * I1Ii111 * oO0o * OoOoOO00
   lprint ( "Cannot decode encapsulation, header version {}" . format ( hex ( OOOO0oO0O ) ) )
   if 48 - 48: iII111i % i11iIiiIii . OoooooooOO * IiII % OoO0O00 . iII111i
   I111 = lisp_format_packet ( I111 [ 0 : 20 ] )
   lprint ( "Packet header: {}" . format ( I111 ) )
   if ( lisp_flow_logging and is_lisp_packet ) : self . log_flow ( False )
   return ( None )
   if 6 - 6: O0 . ooOoO0o - oO0o / i11iIiiIii
  self . inner_source . mask_len = self . inner_source . host_mask_len ( )
  self . inner_dest . mask_len = self . inner_dest . host_mask_len ( )
  self . inner_source . instance_id = IIiI1i
  self . inner_dest . instance_id = IIiI1i
  if 84 - 84: I11i / I1ii11iIi11i * o0oOOo0O0Ooo * OoO0O00 * OOooOOo * O0
  if 83 - 83: O0 % II111iiii + o0oOOo0O0Ooo / OoooooooOO
  if 75 - 75: II111iiii . I1IiiI + OOooOOo - OoOoOO00 - O0 . I11i
  if 19 - 19: Ii1I * i1IIi % O0 + I11i
  if 25 - 25: I1Ii111 - Ii1I / O0 . OoooooooOO % I1IiiI . i1IIi
  if ( lisp_nonce_echoing and is_lisp_packet ) :
   Ii1i = lisp_get_echo_nonce ( self . outer_source , None )
   if ( Ii1i == None ) :
    IIII1i = self . outer_source . print_address_no_iid ( )
    Ii1i = lisp_echo_nonce ( IIII1i )
    if 84 - 84: i1IIi - I1IiiI % iII111i
   oO00o0oOoo = self . lisp_header . get_nonce ( )
   if ( self . lisp_header . is_e_bit_set ( ) ) :
    Ii1i . receive_request ( lisp_ipc_socket , oO00o0oOoo )
   elif ( Ii1i . request_nonce_sent ) :
    Ii1i . receive_echo ( lisp_ipc_socket , oO00o0oOoo )
    if 66 - 66: I1ii11iIi11i . Oo0Ooo
    if 38 - 38: I11i . IiII - OoO0O00 . I1IiiI
    if 65 - 65: I1Ii111
    if 31 - 31: i11iIiiIii / OoOoOO00 % I1ii11iIi11i
    if 44 - 44: II111iiii * I1IiiI + OOooOOo
    if 31 - 31: Ii1I * o0oOOo0O0Ooo * Ii1I + OoO0O00 * o0oOOo0O0Ooo . I1Ii111
    if 89 - 89: OoooooooOO * Ii1I * I1IiiI . ooOoO0o * Ii1I / iII111i
  if ( I1Ii1ii ) : self . packet += I111 [ : ooOo0 ]
  if 46 - 46: i11iIiiIii
  if 15 - 15: O0 / i1IIi / i1IIi . iII111i % OoOoOO00 + I1IiiI
  if 48 - 48: I1Ii111 % iII111i % Ii1I % iIii1I11I1II1 . Ii1I
  if 14 - 14: iII111i * OoO0O00 % O0 + I11i + I1ii11iIi11i
  if ( lisp_flow_logging and is_lisp_packet ) : self . log_flow ( False )
  return ( self )
  if 23 - 23: Oo0Ooo % iII111i + Ii1I - I1Ii111
  if 65 - 65: OoooooooOO
 def swap_mac ( self , mac ) :
  return ( mac [ 1 ] + mac [ 0 ] + mac [ 3 ] + mac [ 2 ] + mac [ 5 ] + mac [ 4 ] )
  if 22 - 22: OOooOOo + II111iiii + Oo0Ooo
  if 83 - 83: ooOoO0o
 def strip_outer_headers ( self ) :
  oOO0OO0O = 16
  oOO0OO0O += 20 if ( self . outer_version == 4 ) else 40
  self . packet = self . packet [ oOO0OO0O : : ]
  return ( self )
  if 43 - 43: OOooOOo
  if 84 - 84: OOooOOo . IiII . iII111i
 def hash_ports ( self ) :
  I111 = self . packet
  OOOO0oO0O = self . inner_version
  iIII1I1i = 0
  if ( OOOO0oO0O == 4 ) :
   I1IIIIII1 = struct . unpack ( "B" , I111 [ 9 ] ) [ 0 ]
   if ( self . inner_is_fragment ) : return ( I1IIIIII1 )
   if ( I1IIIIII1 in [ 6 , 17 ] ) :
    iIII1I1i = I1IIIIII1
    iIII1I1i += struct . unpack ( "I" , I111 [ 20 : 24 ] ) [ 0 ]
    iIII1I1i = ( iIII1I1i >> 16 ) ^ ( iIII1I1i & 0xffff )
    if 99 - 99: OOooOOo + I1IiiI . I1ii11iIi11i * OoooooooOO
    if 82 - 82: i11iIiiIii + iIii1I11I1II1 / Oo0Ooo + OOooOOo * II111iiii
  if ( OOOO0oO0O == 6 ) :
   I1IIIIII1 = struct . unpack ( "B" , I111 [ 6 ] ) [ 0 ]
   if ( I1IIIIII1 in [ 6 , 17 ] ) :
    iIII1I1i = I1IIIIII1
    iIII1I1i += struct . unpack ( "I" , I111 [ 40 : 44 ] ) [ 0 ]
    iIII1I1i = ( iIII1I1i >> 16 ) ^ ( iIII1I1i & 0xffff )
    if 34 - 34: o0oOOo0O0Ooo % OoooooooOO
    if 36 - 36: I1IiiI
  return ( iIII1I1i )
  if 64 - 64: i11iIiiIii + i1IIi % O0 . I11i
  if 64 - 64: ooOoO0o / i1IIi % iII111i
 def hash_packet ( self ) :
  iIII1I1i = self . inner_source . address ^ self . inner_dest . address
  iIII1I1i += self . hash_ports ( )
  if ( self . inner_version == 4 ) :
   iIII1I1i = ( iIII1I1i >> 16 ) ^ ( iIII1I1i & 0xffff )
  elif ( self . inner_version == 6 ) :
   iIII1I1i = ( iIII1I1i >> 64 ) ^ ( iIII1I1i & 0xffffffffffffffff )
   iIII1I1i = ( iIII1I1i >> 32 ) ^ ( iIII1I1i & 0xffffffff )
   iIII1I1i = ( iIII1I1i >> 16 ) ^ ( iIII1I1i & 0xffff )
   if 84 - 84: OoOoOO00 - Oo0Ooo . ooOoO0o . IiII - Oo0Ooo
  self . udp_sport = 0xf000 | ( iIII1I1i & 0xfff )
  if 99 - 99: I1Ii111
  if 75 - 75: ooOoO0o . OOooOOo / IiII
 def print_packet ( self , s_or_r , is_lisp_packet ) :
  if ( is_lisp_packet == False ) :
   oooIi1II1I11i1I = "{} -> {}" . format ( self . inner_source . print_address ( ) ,
 self . inner_dest . print_address ( ) )
   dprint ( ( "{} {}, tos/ttl: {}/{}, length: {}, packet: {} ..." ) . format ( bold ( s_or_r , False ) ,
   # II111iiii % i11iIiiIii + iIii1I11I1II1 + I1ii11iIi11i / I1IiiI * i1IIi
 green ( oooIi1II1I11i1I , False ) , self . inner_tos ,
 self . inner_ttl , len ( self . packet ) ,
 lisp_format_packet ( self . packet [ 0 : 60 ] ) ) )
   return
   if 2 - 2: II111iiii . I11i
   if 83 - 83: I1IiiI - I1Ii111 + I1IiiI . I1IiiI
  if ( s_or_r . find ( "Receive" ) != - 1 ) :
   ii11ii11II = "decap"
   ii11ii11II += "-vxlan" if self . udp_dport == LISP_VXLAN_DATA_PORT else ""
  else :
   ii11ii11II = s_or_r
   if ( ii11ii11II in [ "Send" , "Replicate" ] or ii11ii11II . find ( "Fragment" ) != - 1 ) :
    ii11ii11II = "encap"
    if 35 - 35: Oo0Ooo * II111iiii
    if 32 - 32: oO0o . Oo0Ooo / ooOoO0o + ooOoO0o . I1ii11iIi11i
  iiI1ii1Iii11I = "{} -> {}" . format ( self . outer_source . print_address_no_iid ( ) ,
 self . outer_dest . print_address_no_iid ( ) )
  if 41 - 41: I1ii11iIi11i + Oo0Ooo / IiII . Ii1I * I1IiiI
  if 54 - 54: OoOoOO00 * iII111i + OoO0O00
  if 93 - 93: o0oOOo0O0Ooo / I1IiiI
  if 47 - 47: Oo0Ooo * OOooOOo
  if 98 - 98: oO0o - oO0o . ooOoO0o
  if ( self . lisp_header . get_instance_id ( ) == 0xffffff ) :
   iiIiiIi1 = ( "{} LISP packet, outer RLOCs: {}, outer tos/ttl: " + "{}/{}, outer UDP: {} -> {}, " )
   if 60 - 60: I1IiiI * I1ii11iIi11i / O0 + I11i + IiII
   iiIiiIi1 += bold ( "control-packet" , False ) + ": {} ..."
   if 66 - 66: IiII * Oo0Ooo . OoooooooOO * I1Ii111
   dprint ( iiIiiIi1 . format ( bold ( s_or_r , False ) , red ( iiI1ii1Iii11I , False ) ,
 self . outer_tos , self . outer_ttl , self . udp_sport ,
 self . udp_dport , lisp_format_packet ( self . packet [ 0 : 56 ] ) ) )
   return
  else :
   iiIiiIi1 = ( "{} LISP packet, outer RLOCs: {}, outer tos/ttl: " + "{}/{}, outer UDP: {} -> {}, inner EIDs: {}, " + "inner tos/ttl: {}/{}, length: {}, {}, packet: {} ..." )
   if 93 - 93: IiII / i1IIi
   if 47 - 47: ooOoO0o - Ii1I
   if 98 - 98: oO0o . I1Ii111 / OoOoOO00 . ooOoO0o
   if 1 - 1: OOooOOo
  if ( self . lisp_header . k_bits ) :
   if ( ii11ii11II == "encap" ) : ii11ii11II = "encrypt/encap"
   if ( ii11ii11II == "decap" ) : ii11ii11II = "decap/decrypt"
   if 87 - 87: O0 * II111iiii + iIii1I11I1II1 % oO0o % i11iIiiIii - OoOoOO00
   if 73 - 73: iII111i + Ii1I
  oooIi1II1I11i1I = "{} -> {}" . format ( self . inner_source . print_address ( ) ,
 self . inner_dest . print_address ( ) )
  if 37 - 37: oO0o - iIii1I11I1II1 + II111iiii . Ii1I % iIii1I11I1II1
  dprint ( iiIiiIi1 . format ( bold ( s_or_r , False ) , red ( iiI1ii1Iii11I , False ) ,
 self . outer_tos , self . outer_ttl , self . udp_sport , self . udp_dport ,
 green ( oooIi1II1I11i1I , False ) , self . inner_tos , self . inner_ttl ,
 len ( self . packet ) , self . lisp_header . print_header ( ii11ii11II ) ,
 lisp_format_packet ( self . packet [ 0 : 56 ] ) ) )
  if 17 - 17: I1Ii111 + i1IIi % O0
  if 65 - 65: IiII
 def print_eid_tuple ( self ) :
  return ( lisp_print_eid_tuple ( self . inner_source , self . inner_dest ) )
  if 50 - 50: II111iiii / OoO0O00
  if 79 - 79: I1ii11iIi11i - iIii1I11I1II1 % i1IIi / Oo0Ooo + II111iiii
 def get_raw_socket ( self ) :
  IIiI1i = str ( self . lisp_header . get_instance_id ( ) )
  if ( IIiI1i == "0" ) : return ( None )
  if ( lisp_iid_to_interface . has_key ( IIiI1i ) == False ) : return ( None )
  if 95 - 95: oO0o
  iiiii11I1 = lisp_iid_to_interface [ IIiI1i ]
  i1I1iIi1IiI = iiiii11I1 . get_socket ( )
  if ( i1I1iIi1IiI == None ) :
   iIii1I1iII = bold ( "SO_BINDTODEVICE" , False )
   i11ii = ( os . getenv ( "LISP_ENFORCE_BINDTODEVICE" ) != None )
   lprint ( "{} required for multi-tenancy support, {} packet" . format ( iIii1I1iII , "drop" if i11ii else "forward" ) )
   if 39 - 39: i1IIi . I1ii11iIi11i / I11i / I11i
   if ( i11ii ) : return ( None )
   if 100 - 100: OoooooooOO - OoooooooOO + IiII
   if 32 - 32: OoOoOO00 * o0oOOo0O0Ooo / OoooooooOO
  IIiI1i = bold ( IIiI1i , False )
  O0o0oo0oOO0oO = bold ( iiiii11I1 . device , False )
  dprint ( "Send packet on instance-id {} interface {}" . format ( IIiI1i , O0o0oo0oOO0oO ) )
  return ( i1I1iIi1IiI )
  if 90 - 90: I1Ii111
  if 35 - 35: II111iiii / Ii1I
 def log_flow ( self , encap ) :
  global lisp_flow_log
  if 79 - 79: OoOoOO00 + I1Ii111 * iII111i * Ii1I
  oOOo = os . path . exists ( "./log-flows" )
  if ( len ( lisp_flow_log ) == LISP_FLOW_LOG_SIZE or oOOo ) :
   iI111iIi = [ lisp_flow_log ]
   lisp_flow_log = [ ]
   threading . Thread ( target = lisp_write_flow_log , args = iI111iIi ) . start ( )
   if ( oOOo ) : os . system ( "rm ./log-flows" )
   return
   if 26 - 26: OOooOOo % OOooOOo / i11iIiiIii + I1ii11iIi11i - O0
   if 20 - 20: I1Ii111 . O0 - I1ii11iIi11i / OoOoOO00 - o0oOOo0O0Ooo
  III11I1 = datetime . datetime . now ( )
  lisp_flow_log . append ( [ III11I1 , encap , self . packet , self ] )
  if 79 - 79: OoooooooOO - iIii1I11I1II1
  if 9 - 9: i1IIi - OoOoOO00
 def print_flow ( self , ts , encap , packet ) :
  ts = ts . strftime ( "%m/%d/%y %H:%M:%S.%f" ) [ : - 3 ]
  Oo00o0OOo0OO = "{}: {}" . format ( ts , "encap" if encap else "decap" )
  if 18 - 18: ooOoO0o - IiII / II111iiii / I1ii11iIi11i
  i1Ii1IiiIi1II = red ( self . outer_source . print_address_no_iid ( ) , False )
  o0oOoOooOOo = red ( self . outer_dest . print_address_no_iid ( ) , False )
  I1Ii11I11i1 = green ( self . inner_source . print_address ( ) , False )
  IiII1 = green ( self . inner_dest . print_address ( ) , False )
  if 45 - 45: OoO0O00 + OoO0O00 % ooOoO0o
  if ( self . lisp_header . get_instance_id ( ) == 0xffffff ) :
   Oo00o0OOo0OO += " {}:{} -> {}:{}, LISP control message type {}\n"
   Oo00o0OOo0OO = Oo00o0OOo0OO . format ( i1Ii1IiiIi1II , self . udp_sport , o0oOoOooOOo , self . udp_dport ,
 self . inner_version )
   return ( Oo00o0OOo0OO )
   if 36 - 36: Ii1I * I11i . I11i / Oo0Ooo / I1IiiI
   if 80 - 80: OoooooooOO - i1IIi
  if ( self . outer_dest . is_null ( ) == False ) :
   Oo00o0OOo0OO += " {}:{} -> {}:{}, len/tos/ttl {}/{}/{}"
   Oo00o0OOo0OO = Oo00o0OOo0OO . format ( i1Ii1IiiIi1II , self . udp_sport , o0oOoOooOOo , self . udp_dport ,
 len ( packet ) , self . outer_tos , self . outer_ttl )
   if 51 - 51: i1IIi . OoOoOO00 / OoOoOO00 % i11iIiiIii * OOooOOo - I1Ii111
   if 49 - 49: Oo0Ooo - iIii1I11I1II1
   if 64 - 64: I1Ii111 + iIii1I11I1II1
   if 14 - 14: Ii1I / OoooooooOO + II111iiii . O0 / i1IIi
   if 58 - 58: o0oOOo0O0Ooo / i11iIiiIii / O0 % I11i % I1IiiI
  if ( self . lisp_header . k_bits != 0 ) :
   O0oOOo0 = "\n"
   if ( self . packet_error != "" ) :
    O0oOOo0 = " ({})" . format ( self . packet_error ) + O0oOOo0
    if 71 - 71: i11iIiiIii % iIii1I11I1II1
   Oo00o0OOo0OO += ", encrypted" + O0oOOo0
   return ( Oo00o0OOo0OO )
   if 42 - 42: i11iIiiIii + I1Ii111 - o0oOOo0O0Ooo
   if 2 - 2: o0oOOo0O0Ooo . Ii1I % OoOoOO00
   if 58 - 58: I1ii11iIi11i % Ii1I * Ii1I - iII111i
   if 9 - 9: ooOoO0o - Ii1I % II111iiii + IiII + OOooOOo % O0
   if 65 - 65: OOooOOo - OoO0O00 % i11iIiiIii
  if ( self . outer_dest . is_null ( ) == False ) :
   packet = packet [ 36 : : ] if self . outer_version == 4 else packet [ 56 : : ]
   if 58 - 58: iII111i
   if 2 - 2: II111iiii + i1IIi
  I1IIIIII1 = packet [ 9 ] if self . inner_version == 4 else packet [ 6 ]
  I1IIIIII1 = struct . unpack ( "B" , I1IIIIII1 ) [ 0 ]
  if 68 - 68: OOooOOo + Ii1I
  Oo00o0OOo0OO += " {} -> {}, len/tos/ttl/prot {}/{}/{}/{}"
  Oo00o0OOo0OO = Oo00o0OOo0OO . format ( I1Ii11I11i1 , IiII1 , len ( packet ) , self . inner_tos ,
 self . inner_ttl , I1IIIIII1 )
  if 58 - 58: IiII * Ii1I . i1IIi
  if 19 - 19: oO0o
  if 85 - 85: ooOoO0o - I1IiiI / i1IIi / OoO0O00 / II111iiii
  if 94 - 94: iIii1I11I1II1 + IiII
  if ( I1IIIIII1 in [ 6 , 17 ] ) :
   II11II = packet [ 20 : 24 ] if self . inner_version == 4 else packet [ 40 : 44 ]
   if ( len ( II11II ) == 4 ) :
    II11II = socket . ntohl ( struct . unpack ( "I" , II11II ) [ 0 ] )
    Oo00o0OOo0OO += ", ports {} -> {}" . format ( II11II >> 16 , II11II & 0xffff )
    if 40 - 40: iII111i + O0
  elif ( I1IIIIII1 == 1 ) :
   Ii1iII1ii1 = packet [ 26 : 28 ] if self . inner_version == 4 else packet [ 46 : 48 ]
   if ( len ( Ii1iII1ii1 ) == 2 ) :
    Ii1iII1ii1 = socket . ntohs ( struct . unpack ( "H" , Ii1iII1ii1 ) [ 0 ] )
    Oo00o0OOo0OO += ", icmp-seq {}" . format ( Ii1iII1ii1 )
    if 80 - 80: iIii1I11I1II1 / i11iIiiIii + iII111i
    if 41 - 41: I1Ii111 + OoO0O00 * I1IiiI * O0 * Oo0Ooo - OoOoOO00
  if ( self . packet_error != "" ) :
   Oo00o0OOo0OO += " ({})" . format ( self . packet_error )
   if 96 - 96: I1IiiI - iIii1I11I1II1
  Oo00o0OOo0OO += "\n"
  return ( Oo00o0OOo0OO )
  if 25 - 25: OoooooooOO . Ii1I % iII111i . IiII
  if 67 - 67: OoooooooOO + I1Ii111 / ooOoO0o
 def is_trace ( self ) :
  II11II = [ self . inner_sport , self . inner_dport ]
  return ( self . inner_protocol == LISP_UDP_PROTOCOL and
 LISP_TRACE_PORT in II11II )
  if 75 - 75: IiII / OoooooooOO . I1IiiI + I1Ii111 - II111iiii
  if 33 - 33: IiII / IiII . i11iIiiIii * I1ii11iIi11i + o0oOOo0O0Ooo
  if 16 - 16: IiII
  if 10 - 10: OoOoOO00 . IiII * iIii1I11I1II1 - oO0o - OoOoOO00 / I1Ii111
  if 13 - 13: oO0o + OoOoOO00 % IiII % OoooooooOO
  if 22 - 22: I1Ii111
  if 23 - 23: O0
  if 41 - 41: i1IIi . OOooOOo / ooOoO0o / o0oOOo0O0Ooo % IiII - Ii1I
  if 14 - 14: I1ii11iIi11i - i11iIiiIii * I1Ii111
  if 39 - 39: OoooooooOO
  if 19 - 19: i11iIiiIii
  if 80 - 80: I1IiiI
  if 58 - 58: oO0o + I1ii11iIi11i % OoOoOO00
  if 22 - 22: iIii1I11I1II1 - Ii1I / I1IiiI * IiII
  if 26 - 26: o0oOOo0O0Ooo + OOooOOo - o0oOOo0O0Ooo + Oo0Ooo . oO0o
  if 97 - 97: i1IIi
LISP_N_BIT = 0x80000000
LISP_L_BIT = 0x40000000
LISP_E_BIT = 0x20000000
LISP_V_BIT = 0x10000000
LISP_I_BIT = 0x08000000
LISP_P_BIT = 0x04000000
LISP_K_BITS = 0x03000000
if 46 - 46: I1ii11iIi11i
class lisp_data_header ( ) :
 def __init__ ( self ) :
  self . first_long = 0
  self . second_long = 0
  self . k_bits = 0
  if 30 - 30: OoO0O00 / O0 * o0oOOo0O0Ooo * I1Ii111 + OoooooooOO * iII111i
  if 23 - 23: I11i
 def print_header ( self , e_or_d ) :
  I1I = lisp_hex_string ( self . first_long & 0xffffff )
  o0OO = lisp_hex_string ( self . second_long ) . zfill ( 8 )
  if 11 - 11: oO0o
  iiIiiIi1 = ( "{} LISP-header -> flags: {}{}{}{}{}{}{}{}, nonce: {}, " + "iid/lsb: {}" )
  if 62 - 62: OoooooooOO % oO0o * II111iiii * I1Ii111 * I1Ii111 / ooOoO0o
  return ( iiIiiIi1 . format ( bold ( e_or_d , False ) ,
 "N" if ( self . first_long & LISP_N_BIT ) else "n" ,
 "L" if ( self . first_long & LISP_L_BIT ) else "l" ,
 "E" if ( self . first_long & LISP_E_BIT ) else "e" ,
 "V" if ( self . first_long & LISP_V_BIT ) else "v" ,
 "I" if ( self . first_long & LISP_I_BIT ) else "i" ,
 "P" if ( self . first_long & LISP_P_BIT ) else "p" ,
 "K" if ( self . k_bits in [ 2 , 3 ] ) else "k" ,
 "K" if ( self . k_bits in [ 1 , 3 ] ) else "k" ,
 I1I , o0OO ) )
  if 90 - 90: I1Ii111 . II111iiii . I1ii11iIi11i
  if 32 - 32: ooOoO0o - OoO0O00 . iII111i . iII111i % i1IIi * Ii1I
 def encode ( self ) :
  o0o0 = "II"
  I1I = socket . htonl ( self . first_long )
  o0OO = socket . htonl ( self . second_long )
  if 28 - 28: I11i . OoooooooOO * OOooOOo + i11iIiiIii % I1IiiI . iIii1I11I1II1
  ooo0Oo00O = struct . pack ( o0o0 , I1I , o0OO )
  return ( ooo0Oo00O )
  if 28 - 28: IiII + OoOoOO00 . IiII - Ii1I % i1IIi % iIii1I11I1II1
  if 100 - 100: Oo0Ooo - OOooOOo * ooOoO0o * OoO0O00
 def decode ( self , packet ) :
  o0o0 = "II"
  O0ooO = struct . calcsize ( o0o0 )
  if ( len ( packet ) < O0ooO ) : return ( False )
  if 42 - 42: O0 * iII111i . OoOoOO00 / OOooOOo - Ii1I . I11i
  I1I , o0OO = struct . unpack ( o0o0 , packet [ : O0ooO ] )
  if 57 - 57: o0oOOo0O0Ooo + Oo0Ooo * I1ii11iIi11i - ooOoO0o % iIii1I11I1II1 - Ii1I
  if 37 - 37: OoO0O00 * I11i + Ii1I + I1ii11iIi11i * o0oOOo0O0Ooo
  self . first_long = socket . ntohl ( I1I )
  self . second_long = socket . ntohl ( o0OO )
  self . k_bits = ( self . first_long & LISP_K_BITS ) >> 24
  return ( True )
  if 95 - 95: Ii1I - i11iIiiIii % i11iIiiIii - O0 * I1Ii111
  if 81 - 81: II111iiii * I1IiiI % i1IIi * i11iIiiIii + OoOoOO00
 def key_id ( self , key_id ) :
  self . first_long &= ~ ( 0x3 << 24 )
  self . first_long |= ( ( key_id & 0x3 ) << 24 )
  self . k_bits = key_id
  if 100 - 100: i1IIi % Ii1I
  if 55 - 55: I1IiiI + iII111i
 def nonce ( self , nonce ) :
  self . first_long |= LISP_N_BIT
  self . first_long |= nonce
  if 85 - 85: oO0o + iII111i % iII111i / I11i . I1IiiI - OoOoOO00
  if 19 - 19: I11i / iII111i + IiII
 def map_version ( self , version ) :
  self . first_long |= LISP_V_BIT
  self . first_long |= version
  if 76 - 76: iIii1I11I1II1 / I1Ii111 - I1ii11iIi11i % o0oOOo0O0Ooo % OOooOOo + OoooooooOO
  if 10 - 10: OoO0O00 * I11i / Oo0Ooo - I1Ii111
 def instance_id ( self , iid ) :
  if ( iid == 0 ) : return
  self . first_long |= LISP_I_BIT
  self . second_long &= 0xff
  self . second_long |= ( iid << 8 )
  if 11 - 11: IiII % I1ii11iIi11i / ooOoO0o . i11iIiiIii + OOooOOo - II111iiii
  if 50 - 50: i1IIi * oO0o / i11iIiiIii / i11iIiiIii / oO0o
 def get_instance_id ( self ) :
  return ( ( self . second_long >> 8 ) & 0xffffff )
  if 84 - 84: I1ii11iIi11i - iII111i + I1ii11iIi11i
  if 63 - 63: I11i * ooOoO0o % II111iiii % I1Ii111 + I1IiiI * Oo0Ooo
 def locator_status_bits ( self , lsbs ) :
  self . first_long |= LISP_L_BIT
  self . second_long &= 0xffffff00
  self . second_long |= ( lsbs & 0xff )
  if 96 - 96: IiII
  if 99 - 99: iIii1I11I1II1 - ooOoO0o
 def is_request_nonce ( self , nonce ) :
  return ( nonce & 0x80000000 )
  if 79 - 79: I1IiiI + oO0o % I11i % oO0o
  if 56 - 56: I1ii11iIi11i + oO0o . OoO0O00 + OoooooooOO * I1ii11iIi11i - O0
 def request_nonce ( self , nonce ) :
  self . first_long |= LISP_E_BIT
  self . first_long |= LISP_N_BIT
  self . first_long |= ( nonce & 0xffffff )
  if 35 - 35: OOooOOo . I11i . I1Ii111 - I11i % I11i + I1Ii111
  if 99 - 99: o0oOOo0O0Ooo + OOooOOo
 def is_e_bit_set ( self ) :
  return ( self . first_long & LISP_E_BIT )
  if 34 - 34: I1Ii111 * o0oOOo0O0Ooo . I1IiiI % i11iIiiIii
  if 61 - 61: iIii1I11I1II1 + oO0o * I11i - i1IIi % oO0o
 def get_nonce ( self ) :
  return ( self . first_long & 0xffffff )
  if 76 - 76: oO0o / OoOoOO00
  if 12 - 12: I1Ii111
  if 58 - 58: OoO0O00 + iIii1I11I1II1 % O0 + I11i + OoOoOO00 * OoooooooOO
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
  if 41 - 41: oO0o * I1IiiI
  if 76 - 76: oO0o . O0 * OoooooooOO + ooOoO0o
 def send_ipc ( self , ipc_socket , ipc ) :
  oo0O00 = "lisp-itr" if lisp_i_am_itr else "lisp-etr"
  IiI1 = "lisp-etr" if lisp_i_am_itr else "lisp-itr"
  ipc = lisp_command_ipc ( ipc , oo0O00 )
  lisp_ipc ( ipc , ipc_socket , IiI1 )
  if 92 - 92: IiII - IiII % iIii1I11I1II1 / iII111i
  if 4 - 4: o0oOOo0O0Ooo
 def send_request_ipc ( self , ipc_socket , nonce ) :
  nonce = lisp_hex_string ( nonce )
  OooOoO0OO00 = "nonce%R%{}%{}" . format ( self . rloc_str , nonce )
  self . send_ipc ( ipc_socket , OooOoO0OO00 )
  if 94 - 94: Oo0Ooo - iIii1I11I1II1 + I1IiiI - i1IIi + OoooooooOO % OoO0O00
  if 36 - 36: iII111i * I11i * O0 * OOooOOo - o0oOOo0O0Ooo / I1ii11iIi11i
 def send_echo_ipc ( self , ipc_socket , nonce ) :
  nonce = lisp_hex_string ( nonce )
  OooOoO0OO00 = "nonce%E%{}%{}" . format ( self . rloc_str , nonce )
  self . send_ipc ( ipc_socket , OooOoO0OO00 )
  if 54 - 54: i1IIi - OoO0O00 / OoooooooOO
  if 95 - 95: O0 + iIii1I11I1II1 . I1ii11iIi11i
 def receive_request ( self , ipc_socket , nonce ) :
  o000Oo0oO0OO0 = self . request_nonce_rcvd
  self . request_nonce_rcvd = nonce
  self . last_request_nonce_rcvd = lisp_get_timestamp ( )
  if ( lisp_i_am_rtr ) : return
  if ( o000Oo0oO0OO0 != nonce ) : self . send_request_ipc ( ipc_socket , nonce )
  if 54 - 54: I1IiiI
  if 19 - 19: iII111i . I11i * OoooooooOO - OOooOOo + O0 * I1Ii111
 def receive_echo ( self , ipc_socket , nonce ) :
  if ( self . request_nonce_sent != nonce ) : return
  self . last_echo_nonce_rcvd = lisp_get_timestamp ( )
  if ( self . echo_nonce_rcvd == nonce ) : return
  if 90 - 90: i1IIi . oO0o / I1Ii111 . OOooOOo / I1Ii111
  self . echo_nonce_rcvd = nonce
  if ( lisp_i_am_rtr ) : return
  self . send_echo_ipc ( ipc_socket , nonce )
  if 1 - 1: iII111i % ooOoO0o
  if 99 - 99: iII111i + iIii1I11I1II1 . OOooOOo / OoO0O00 * I1ii11iIi11i
 def get_request_or_echo_nonce ( self , ipc_socket , remote_rloc ) :
  if 87 - 87: IiII / II111iiii % OoO0O00 % OoO0O00
  if 28 - 28: OoOoOO00 % oO0o - OOooOOo + OOooOOo + oO0o / iIii1I11I1II1
  if 91 - 91: I1IiiI / II111iiii * OOooOOo
  if 94 - 94: II111iiii - iIii1I11I1II1 - iIii1I11I1II1
  if 83 - 83: I1ii11iIi11i * iIii1I11I1II1 + OoOoOO00 * i1IIi . OoooooooOO % Ii1I
  if ( self . request_nonce_sent and self . echo_nonce_sent and remote_rloc ) :
   oOoOo00oo = lisp_myrlocs [ 0 ] if remote_rloc . is_ipv4 ( ) else lisp_myrlocs [ 1 ]
   if 32 - 32: I1IiiI * I1Ii111 * i1IIi + oO0o
   if 40 - 40: II111iiii
   if ( remote_rloc . address > oOoOo00oo . address ) :
    OOOO0o = "exit"
    self . request_nonce_sent = None
   else :
    OOOO0o = "stay in"
    self . echo_nonce_sent = None
    if 7 - 7: OOooOOo / OoO0O00
    if 88 - 88: i1IIi
   O0o = bold ( "collision" , False )
   o0Oo = red ( oOoOo00oo . print_address_no_iid ( ) , False )
   oOo0Oooo = red ( remote_rloc . print_address_no_iid ( ) , False )
   lprint ( "Echo nonce {}, {} -> {}, {} request-nonce mode" . format ( O0o ,
 o0Oo , oOo0Oooo , OOOO0o ) )
   if 39 - 39: Ii1I % i1IIi . I1ii11iIi11i - O0
   if 65 - 65: oO0o * oO0o / I11i + oO0o % ooOoO0o + OoOoOO00
   if 92 - 92: o0oOOo0O0Ooo
   if 37 - 37: oO0o
   if 18 - 18: IiII * i11iIiiIii + iIii1I11I1II1 % I11i + i1IIi - OoO0O00
  if ( self . echo_nonce_sent != None ) :
   oO00o0oOoo = self . echo_nonce_sent
   I1i11II = bold ( "Echoing" , False )
   lprint ( "{} nonce 0x{} to {}" . format ( I1i11II ,
 lisp_hex_string ( oO00o0oOoo ) , red ( self . rloc_str , False ) ) )
   self . last_echo_nonce_sent = lisp_get_timestamp ( )
   self . echo_nonce_sent = None
   return ( oO00o0oOoo )
   if 85 - 85: OoO0O00 * I11i + OoO0O00
   if 39 - 39: Oo0Ooo / i1IIi % i1IIi
   if 20 - 20: OOooOOo * oO0o
   if 91 - 91: OoO0O00 % i1IIi - iIii1I11I1II1 . OOooOOo
   if 31 - 31: oO0o % i1IIi . OoooooooOO - o0oOOo0O0Ooo + OoooooooOO
   if 45 - 45: OOooOOo + I11i / OoooooooOO - Ii1I + OoooooooOO
   if 42 - 42: iIii1I11I1II1 * I1IiiI * I1Ii111
  oO00o0oOoo = self . request_nonce_sent
  O00oo0o0o0oo = self . last_request_nonce_sent
  if ( oO00o0oOoo and O00oo0o0o0oo != None ) :
   if ( time . time ( ) - O00oo0o0o0oo >= LISP_NONCE_ECHO_INTERVAL ) :
    self . request_nonce_sent = None
    lprint ( "Stop request-nonce mode for {}, nonce 0x{}" . format ( red ( self . rloc_str , False ) , lisp_hex_string ( oO00o0oOoo ) ) )
    if 22 - 22: I1Ii111 + iII111i - I11i + iIii1I11I1II1 / I1Ii111 - OoooooooOO
    return ( None )
    if 42 - 42: OoooooooOO - OoOoOO00 - OOooOOo * I1Ii111
    if 98 - 98: OoO0O00 . iIii1I11I1II1 % Oo0Ooo + OoooooooOO
    if 2 - 2: I1Ii111 % OoooooooOO - ooOoO0o * I1ii11iIi11i * IiII
    if 99 - 99: iIii1I11I1II1 . Oo0Ooo / ooOoO0o . OOooOOo % I1IiiI * I11i
    if 95 - 95: oO0o
    if 80 - 80: IiII
    if 42 - 42: OoooooooOO * II111iiii
    if 53 - 53: I1Ii111 + i1IIi . OoO0O00 / i11iIiiIii + Ii1I % OoOoOO00
    if 9 - 9: ooOoO0o . I11i - Oo0Ooo . I1Ii111
  if ( oO00o0oOoo == None ) :
   oO00o0oOoo = lisp_get_data_nonce ( )
   if ( self . recently_requested ( ) ) : return ( oO00o0oOoo )
   if 39 - 39: OOooOOo
   self . request_nonce_sent = oO00o0oOoo
   lprint ( "Start request-nonce mode for {}, nonce 0x{}" . format ( red ( self . rloc_str , False ) , lisp_hex_string ( oO00o0oOoo ) ) )
   if 70 - 70: IiII % OoO0O00 % I1IiiI
   self . last_new_request_nonce_sent = lisp_get_timestamp ( )
   if 95 - 95: OoOoOO00 - I1Ii111 / O0 * I1IiiI - o0oOOo0O0Ooo
   if 12 - 12: iIii1I11I1II1 % Oo0Ooo . iII111i . IiII % i11iIiiIii
   if 2 - 2: oO0o * oO0o . OoOoOO00 * Ii1I * iIii1I11I1II1
   if 13 - 13: I11i / O0 . i11iIiiIii * i1IIi % i11iIiiIii
   if 8 - 8: OoOoOO00 - OoooooooOO
   if ( lisp_i_am_itr == False ) : return ( oO00o0oOoo | 0x80000000 )
   self . send_request_ipc ( ipc_socket , oO00o0oOoo )
  else :
   lprint ( "Continue request-nonce mode for {}, nonce 0x{}" . format ( red ( self . rloc_str , False ) , lisp_hex_string ( oO00o0oOoo ) ) )
   if 99 - 99: II111iiii / IiII % OoooooooOO . i11iIiiIii
   if 18 - 18: o0oOOo0O0Ooo . ooOoO0o
   if 70 - 70: OoooooooOO . ooOoO0o / oO0o . oO0o - o0oOOo0O0Ooo
   if 29 - 29: I11i % OOooOOo - ooOoO0o
   if 26 - 26: O0 . I11i + iII111i - Ii1I . I11i
   if 2 - 2: I1ii11iIi11i . Oo0Ooo * OOooOOo % II111iiii . iII111i
   if 46 - 46: OoOoOO00 + I1IiiI % OoooooooOO * i11iIiiIii - Oo0Ooo
  self . last_request_nonce_sent = lisp_get_timestamp ( )
  return ( oO00o0oOoo | 0x80000000 )
  if 47 - 47: iII111i * OoOoOO00 * IiII
  if 46 - 46: Ii1I
 def request_nonce_timeout ( self ) :
  if ( self . request_nonce_sent == None ) : return ( False )
  if ( self . request_nonce_sent == self . echo_nonce_rcvd ) : return ( False )
  if 42 - 42: iIii1I11I1II1
  ooooOoO0O = time . time ( ) - self . last_request_nonce_sent
  IIi1IiIii = self . last_echo_nonce_rcvd
  return ( ooooOoO0O >= LISP_NONCE_ECHO_INTERVAL and IIi1IiIii == None )
  if 40 - 40: I1IiiI
  if 3 - 3: ooOoO0o / i1IIi - OoOoOO00
 def recently_requested ( self ) :
  IIi1IiIii = self . last_request_nonce_sent
  if ( IIi1IiIii == None ) : return ( False )
  if 73 - 73: OoooooooOO * O0 * ooOoO0o
  ooooOoO0O = time . time ( ) - IIi1IiIii
  return ( ooooOoO0O <= LISP_NONCE_ECHO_INTERVAL )
  if 7 - 7: II111iiii + i1IIi
  if 95 - 95: i11iIiiIii + OoooooooOO / OOooOOo - iIii1I11I1II1 + iIii1I11I1II1
 def recently_echoed ( self ) :
  if ( self . request_nonce_sent == None ) : return ( True )
  if 29 - 29: IiII % ooOoO0o + OoO0O00 . i1IIi + I1IiiI
  if 24 - 24: I1Ii111 / Ii1I * I1ii11iIi11i - OoooooooOO / I1IiiI . oO0o
  if 98 - 98: i1IIi - iII111i
  if 49 - 49: o0oOOo0O0Ooo . Ii1I . oO0o
  IIi1IiIii = self . last_good_echo_nonce_rcvd
  if ( IIi1IiIii == None ) : IIi1IiIii = 0
  ooooOoO0O = time . time ( ) - IIi1IiIii
  if ( ooooOoO0O <= LISP_NONCE_ECHO_INTERVAL ) : return ( True )
  if 9 - 9: IiII - II111iiii * OoO0O00
  if 78 - 78: iIii1I11I1II1 / O0 * oO0o / iII111i / OoOoOO00
  if 15 - 15: ooOoO0o / oO0o
  if 54 - 54: ooOoO0o - iIii1I11I1II1 - I11i % Ii1I / II111iiii
  if 80 - 80: i11iIiiIii % iIii1I11I1II1 / i11iIiiIii
  if 66 - 66: OoOoOO00 . iIii1I11I1II1 * I1ii11iIi11i - Ii1I - iIii1I11I1II1
  IIi1IiIii = self . last_new_request_nonce_sent
  if ( IIi1IiIii == None ) : IIi1IiIii = 0
  ooooOoO0O = time . time ( ) - IIi1IiIii
  return ( ooooOoO0O <= LISP_NONCE_ECHO_INTERVAL )
  if 28 - 28: OoOoOO00 % OoooooooOO
  if 13 - 13: IiII . Oo0Ooo - I11i / oO0o - Oo0Ooo - I1IiiI
 def change_state ( self , rloc ) :
  if ( rloc . up_state ( ) and self . recently_echoed ( ) == False ) :
   oOO0o = bold ( "down" , False )
   ooIi11II1IIIIIi = lisp_print_elapsed ( self . last_good_echo_nonce_rcvd )
   lprint ( "Take {} {}, last good echo: {}" . format ( red ( self . rloc_str , False ) , oOO0o , ooIi11II1IIIIIi ) )
   if 83 - 83: iIii1I11I1II1 + II111iiii * oO0o / O0 - iII111i
   rloc . state = LISP_RLOC_NO_ECHOED_NONCE_STATE
   rloc . last_state_change = lisp_get_timestamp ( )
   return
   if 23 - 23: i1IIi
   if 24 - 24: IiII
  if ( rloc . no_echoed_nonce_state ( ) == False ) : return
  if 51 - 51: OOooOOo % i11iIiiIii
  if ( self . recently_requested ( ) == False ) :
   o0OoOoOo0O = bold ( "up" , False )
   lprint ( "Bring {} {}, retry request-nonce mode" . format ( red ( self . rloc_str , False ) , o0OoOoOo0O ) )
   if 37 - 37: i1IIi . I1Ii111 - II111iiii % o0oOOo0O0Ooo - i1IIi . oO0o
   rloc . state = LISP_RLOC_UP_STATE
   rloc . last_state_change = lisp_get_timestamp ( )
   if 34 - 34: iIii1I11I1II1 / II111iiii
   if 3 - 3: o0oOOo0O0Ooo - OoooooooOO + iII111i . I11i
   if 88 - 88: I11i - iII111i
 def print_echo_nonce ( self ) :
  OOoOO0oOooo = lisp_print_elapsed ( self . last_request_nonce_sent )
  i1II11II11 = lisp_print_elapsed ( self . last_good_echo_nonce_rcvd )
  if 94 - 94: iIii1I11I1II1
  iii11iII1 = lisp_print_elapsed ( self . last_echo_nonce_sent )
  oOooo = lisp_print_elapsed ( self . last_request_nonce_rcvd )
  i1I1iIi1IiI = space ( 4 )
  if 15 - 15: ooOoO0o * iIii1I11I1II1 * oO0o
  ooO000O = "Nonce-Echoing:\n"
  ooO000O += ( "{}Last request-nonce sent: {}\n{}Last echo-nonce " + "received: {}\n" ) . format ( i1I1iIi1IiI , OOoOO0oOooo , i1I1iIi1IiI , i1II11II11 )
  if 96 - 96: I1Ii111 * iIii1I11I1II1 / OoOoOO00 % OOooOOo * II111iiii
  ooO000O += ( "{}Last request-nonce received: {}\n{}Last echo-nonce " + "sent: {}" ) . format ( i1I1iIi1IiI , oOooo , i1I1iIi1IiI , iii11iII1 )
  if 3 - 3: OOooOOo . Oo0Ooo / i11iIiiIii + OoO0O00
  if 47 - 47: IiII . OOooOOo
  return ( ooO000O )
  if 96 - 96: I11i % II111iiii / ooOoO0o % OOooOOo / ooOoO0o % i11iIiiIii
  if 57 - 57: I11i - I11i % II111iiii % Oo0Ooo . o0oOOo0O0Ooo % Oo0Ooo
  if 91 - 91: I1IiiI - OoO0O00 - Oo0Ooo - Ii1I * iIii1I11I1II1
  if 68 - 68: OoO0O00 % O0 * iIii1I11I1II1 / oO0o * o0oOOo0O0Ooo + OOooOOo
  if 89 - 89: ooOoO0o * I1IiiI . oO0o
  if 75 - 75: ooOoO0o - iII111i % iII111i + ooOoO0o * o0oOOo0O0Ooo - I1ii11iIi11i
  if 26 - 26: I11i * Ii1I % I1IiiI + iII111i
  if 38 - 38: iII111i - Oo0Ooo / Ii1I + oO0o . iII111i + IiII
  if 19 - 19: Ii1I
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
    if 51 - 51: iIii1I11I1II1
   self . local_private_key = random . randint ( 0 , 2 ** 128 - 1 )
   OOoOoO = lisp_hex_string ( self . local_private_key ) . zfill ( 32 )
   self . curve25519 = curve25519 . Private ( OOoOoO )
  else :
   self . local_private_key = random . randint ( 0 , 0x1fff )
   if 8 - 8: OoO0O00 / o0oOOo0O0Ooo % iII111i . i11iIiiIii . OoooooooOO . Ii1I
  self . local_public_key = self . compute_public_key ( )
  self . remote_public_key = None
  self . shared_key = None
  self . encrypt_key = None
  self . icv_key = None
  self . icv = poly1305 if do_poly else hashlib . sha256
  self . iv = None
  self . get_iv ( )
  self . do_poly = do_poly
  if 8 - 8: OoO0O00 * Oo0Ooo
  if 41 - 41: Oo0Ooo / OoO0O00 / OoOoOO00 - i11iIiiIii - OoOoOO00
 def copy_keypair ( self , key ) :
  self . local_private_key = key . local_private_key
  self . local_public_key = key . local_public_key
  self . curve25519 = key . curve25519
  if 4 - 4: I11i . IiII
  if 39 - 39: OOooOOo . Oo0Ooo - OoOoOO00 * i11iIiiIii
 def get_iv ( self ) :
  if ( self . iv == None ) :
   self . iv = random . randint ( 0 , LISP_16_128_MASK )
  else :
   self . iv += 1
   if 4 - 4: OoOoOO00 * O0 - I11i
  OOOooO00OO00O = self . iv
  if ( self . cipher_suite == LISP_CS_25519_CHACHA ) :
   OOOooO00OO00O = struct . pack ( "Q" , OOOooO00OO00O & LISP_8_64_MASK )
  elif ( self . cipher_suite == LISP_CS_25519_GCM ) :
   O0o0oo0 = struct . pack ( "I" , ( OOOooO00OO00O >> 64 ) & LISP_4_32_MASK )
   ooo000 = struct . pack ( "Q" , OOOooO00OO00O & LISP_8_64_MASK )
   OOOooO00OO00O = O0o0oo0 + ooo000
  else :
   OOOooO00OO00O = struct . pack ( "QQ" , OOOooO00OO00O >> 64 , OOOooO00OO00O & LISP_8_64_MASK )
  return ( OOOooO00OO00O )
  if 45 - 45: OOooOOo + I1Ii111 + i11iIiiIii - I1ii11iIi11i
  if 70 - 70: II111iiii * II111iiii . I1IiiI
 def key_length ( self , key ) :
  if ( type ( key ) != str ) : key = self . normalize_pub_key ( key )
  return ( len ( key ) / 2 )
  if 11 - 11: iII111i
  if 20 - 20: Ii1I . I1Ii111 % Ii1I
 def print_key ( self , key ) :
  OoOoO0ooooO0 = self . normalize_pub_key ( key )
  return ( "0x{}...{}({})" . format ( OoOoO0ooooO0 [ 0 : 4 ] , OoOoO0ooooO0 [ - 4 : : ] , self . key_length ( OoOoO0ooooO0 ) ) )
  if 5 - 5: OOooOOo + iII111i
  if 23 - 23: I1Ii111 % iIii1I11I1II1 . I11i
 def normalize_pub_key ( self , key ) :
  if ( type ( key ) == str ) :
   if ( self . curve25519 ) : return ( binascii . hexlify ( key ) )
   return ( key )
   if 95 - 95: Oo0Ooo + i11iIiiIii % OOooOOo - oO0o
  key = lisp_hex_string ( key ) . zfill ( 256 )
  return ( key )
  if 11 - 11: I1ii11iIi11i / O0 + II111iiii
  if 95 - 95: I1Ii111 + IiII * iIii1I11I1II1
 def print_keys ( self , do_bold = True ) :
  o0Oo = bold ( "local-key: " , False ) if do_bold else "local-key: "
  if ( self . local_public_key == None ) :
   o0Oo += "none"
  else :
   o0Oo += self . print_key ( self . local_public_key )
   if 17 - 17: OoO0O00 - Oo0Ooo * O0 / Ii1I
  oOo0Oooo = bold ( "remote-key: " , False ) if do_bold else "remote-key: "
  if ( self . remote_public_key == None ) :
   oOo0Oooo += "none"
  else :
   oOo0Oooo += self . print_key ( self . remote_public_key )
   if 19 - 19: i1IIi - iIii1I11I1II1 . I11i
  iiIIi1i111i = "ECDH" if ( self . curve25519 ) else "DH"
  iII = self . cipher_suite
  return ( "{} cipher-suite: {}, {}, {}" . format ( iiIIi1i111i , iII , o0Oo , oOo0Oooo ) )
  if 55 - 55: iIii1I11I1II1 . IiII - o0oOOo0O0Ooo . I1ii11iIi11i * i1IIi
  if 76 - 76: i1IIi + O0 / IiII + i11iIiiIii % I1Ii111 % Oo0Ooo
 def compare_keys ( self , keys ) :
  if ( self . dh_g_value != keys . dh_g_value ) : return ( False )
  if ( self . dh_p_value != keys . dh_p_value ) : return ( False )
  if ( self . remote_public_key != keys . remote_public_key ) : return ( False )
  return ( True )
  if 61 - 61: iIii1I11I1II1 % Ii1I - oO0o * OoooooooOO % II111iiii - Ii1I
  if 44 - 44: O0
 def compute_public_key ( self ) :
  if ( self . curve25519 ) : return ( self . curve25519 . get_public ( ) . public )
  if 9 - 9: oO0o . Oo0Ooo + iII111i + I1IiiI * I1IiiI - I1IiiI
  OOoOoO = self . local_private_key
  O0000O = self . dh_g_value
  OoOOOOo = self . dh_p_value
  return ( int ( ( O0000O ** OOoOoO ) % OoOOOOo ) )
  if 27 - 27: o0oOOo0O0Ooo / I1IiiI
  if 91 - 91: I1IiiI - iII111i / OoO0O00 - OoO0O00 / Ii1I - IiII
 def compute_shared_key ( self , ed , print_shared = False ) :
  OOoOoO = self . local_private_key
  I1IIi = self . remote_public_key
  if 80 - 80: I11i / oO0o * Ii1I / iII111i
  IiIiIIi = bold ( "Compute {} shared-key" . format ( ed ) , False )
  lprint ( "{}, key-material: {}" . format ( IiIiIIi , self . print_keys ( ) ) )
  if 61 - 61: iII111i * ooOoO0o
  if ( self . curve25519 ) :
   i1I1IiIiiI1II = curve25519 . Public ( I1IIi )
   self . shared_key = self . curve25519 . get_shared_key ( i1I1IiIiiI1II )
  else :
   OoOOOOo = self . dh_p_value
   self . shared_key = ( I1IIi ** OOoOoO ) % OoOOOOo
   if 39 - 39: OoooooooOO
   if 37 - 37: iII111i . o0oOOo0O0Ooo / Ii1I / OOooOOo * i1IIi
   if 90 - 90: I1IiiI . II111iiii - i1IIi + oO0o
   if 58 - 58: iII111i - OoooooooOO
   if 56 - 56: iII111i / iII111i
   if 21 - 21: O0 * ooOoO0o % OoOoOO00 / O0
   if 85 - 85: OoooooooOO + OoooooooOO
  if ( print_shared ) :
   OoOoO0ooooO0 = self . print_key ( self . shared_key )
   lprint ( "Computed shared-key: {}" . format ( OoOoO0ooooO0 ) )
   if 23 - 23: i1IIi
   if 31 - 31: Oo0Ooo - iIii1I11I1II1 / I11i . OoO0O00
   if 74 - 74: Oo0Ooo - II111iiii - IiII
   if 50 - 50: I1IiiI - oO0o + oO0o * I11i + oO0o
   if 70 - 70: i1IIi % OoO0O00 / i1IIi
  self . compute_encrypt_icv_keys ( )
  if 30 - 30: OoOoOO00 - i11iIiiIii
  if 94 - 94: OoOoOO00 % iII111i
  if 39 - 39: OoOoOO00 + I1Ii111 % O0
  if 26 - 26: ooOoO0o + OoOoOO00
  self . rekey_count += 1
  self . last_rekey = lisp_get_timestamp ( )
  if 17 - 17: I1ii11iIi11i - iII111i % Oo0Ooo * O0 % O0 * OOooOOo
  if 6 - 6: I1Ii111
 def compute_encrypt_icv_keys ( self ) :
  ii1iiIiiiI11 = hashlib . sha256
  if ( self . curve25519 ) :
   o00o0o0o = self . shared_key
  else :
   o00o0o0o = lisp_hex_string ( self . shared_key )
   if 11 - 11: iIii1I11I1II1 / Ii1I + OoooooooOO % i1IIi * i11iIiiIii
   if 86 - 86: i11iIiiIii - O0 - i11iIiiIii . iIii1I11I1II1 . IiII
   if 84 - 84: i1IIi / iIii1I11I1II1 / oO0o / Ii1I
   if 7 - 7: OoOoOO00 . OOooOOo % Oo0Ooo
   if 55 - 55: ooOoO0o - Oo0Ooo * oO0o
  o0Oo = self . local_public_key
  if ( type ( o0Oo ) != long ) : o0Oo = int ( binascii . hexlify ( o0Oo ) , 16 )
  oOo0Oooo = self . remote_public_key
  if ( type ( oOo0Oooo ) != long ) : oOo0Oooo = int ( binascii . hexlify ( oOo0Oooo ) , 16 )
  OOOOO0oOOoO = "0001" + "lisp-crypto" + lisp_hex_string ( o0Oo ^ oOo0Oooo ) + "0100"
  if 42 - 42: I1IiiI + i11iIiiIii / OoO0O00
  o00OooooOOOO = hmac . new ( OOOOO0oOOoO , o00o0o0o , ii1iiIiiiI11 ) . hexdigest ( )
  o00OooooOOOO = int ( o00OooooOOOO , 16 )
  if 89 - 89: O0 + IiII * I1Ii111
  if 30 - 30: OoOoOO00
  if 39 - 39: I1ii11iIi11i + o0oOOo0O0Ooo + I1Ii111 + IiII
  if 48 - 48: I1Ii111 / ooOoO0o . iIii1I11I1II1
  ooo0OOoo = ( o00OooooOOOO >> 128 ) & LISP_16_128_MASK
  oO0o00O = o00OooooOOOO & LISP_16_128_MASK
  self . encrypt_key = lisp_hex_string ( ooo0OOoo ) . zfill ( 32 )
  IIII1ii1iIIii = 32 if self . do_poly else 40
  self . icv_key = lisp_hex_string ( oO0o00O ) . zfill ( IIII1ii1iIIii )
  if 96 - 96: OoO0O00 - iII111i
  if 16 - 16: I1Ii111 / O0 . II111iiii * OoOoOO00
 def do_icv ( self , packet , nonce ) :
  if ( self . icv_key == None ) : return ( "" )
  if ( self . do_poly ) :
   i1IiI1I111iI1 = self . icv . poly1305aes
   oO00O000o = self . icv . binascii . hexlify
   nonce = oO00O000o ( nonce )
   o0o00 = i1IiI1I111iI1 ( self . encrypt_key , self . icv_key , nonce , packet )
   o0o00 = oO00O000o ( o0o00 )
  else :
   OOoOoO = binascii . unhexlify ( self . icv_key )
   o0o00 = hmac . new ( OOoOoO , packet , self . icv ) . hexdigest ( )
   o0o00 = o0o00 [ 0 : 40 ]
   if 6 - 6: II111iiii % I1ii11iIi11i % i1IIi * ooOoO0o
  return ( o0o00 )
  if 47 - 47: O0
  if 55 - 55: OoO0O00 % O0 / OoooooooOO
 def add_key_by_nonce ( self , nonce ) :
  if ( lisp_crypto_keys_by_nonce . has_key ( nonce ) == False ) :
   lisp_crypto_keys_by_nonce [ nonce ] = [ None , None , None , None ]
   if 49 - 49: I1IiiI . OoO0O00 * OoooooooOO % i11iIiiIii + iIii1I11I1II1 * i1IIi
  lisp_crypto_keys_by_nonce [ nonce ] [ self . key_id ] = self
  if 88 - 88: I1ii11iIi11i * iII111i + II111iiii
  if 62 - 62: OoooooooOO
 def delete_key_by_nonce ( self , nonce ) :
  if ( lisp_crypto_keys_by_nonce . has_key ( nonce ) == False ) : return
  lisp_crypto_keys_by_nonce . pop ( nonce )
  if 33 - 33: O0 . i11iIiiIii % o0oOOo0O0Ooo
  if 50 - 50: ooOoO0o
 def add_key_by_rloc ( self , addr_str , encap ) :
  Oooo0O00OOo0o = lisp_crypto_keys_by_rloc_encap if encap else lisp_crypto_keys_by_rloc_decap
  if 4 - 4: oO0o * OoooooooOO % Oo0Ooo / ooOoO0o
  if 11 - 11: o0oOOo0O0Ooo - II111iiii % oO0o . II111iiii
  if ( Oooo0O00OOo0o . has_key ( addr_str ) == False ) :
   Oooo0O00OOo0o [ addr_str ] = [ None , None , None , None ]
   if 65 - 65: oO0o . i11iIiiIii % OOooOOo * iII111i % Oo0Ooo
  Oooo0O00OOo0o [ addr_str ] [ self . key_id ] = self
  if 51 - 51: OoO0O00 % iII111i
  if 24 - 24: I1IiiI / iIii1I11I1II1 / O0 . iIii1I11I1II1 - OoO0O00 . iIii1I11I1II1
  if 8 - 8: I1ii11iIi11i % OoO0O00 % oO0o . I1ii11iIi11i * I1ii11iIi11i
  if 94 - 94: i11iIiiIii + OoooooooOO
  if 20 - 20: i11iIiiIii
  if ( encap == False ) :
   lisp_write_ipc_decap_key ( addr_str , Oooo0O00OOo0o [ addr_str ] )
   if 86 - 86: OoOoOO00 / OOooOOo
   if 40 - 40: iIii1I11I1II1 / ooOoO0o / I1IiiI + I1ii11iIi11i * OOooOOo
   if 1 - 1: OoO0O00 * ooOoO0o + IiII . oO0o / ooOoO0o
 def encode_lcaf ( self , rloc_addr ) :
  O0O00Oo = self . normalize_pub_key ( self . local_public_key )
  IiiI1II1 = self . key_length ( O0O00Oo )
  OO00O0OO0 = ( 6 + IiiI1II1 + 2 )
  if ( rloc_addr != None ) : OO00O0OO0 += rloc_addr . addr_length ( )
  if 5 - 5: oO0o + Ii1I
  I111 = struct . pack ( "HBBBBHBB" , socket . htons ( LISP_AFI_LCAF ) , 0 , 0 ,
 LISP_LCAF_SECURITY_TYPE , 0 , socket . htons ( OO00O0OO0 ) , 1 , 0 )
  if 48 - 48: I1Ii111 * i1IIi - I1ii11iIi11i / I1IiiI + i11iIiiIii - i1IIi
  if 91 - 91: o0oOOo0O0Ooo / i11iIiiIii
  if 96 - 96: OoO0O00 + iII111i * II111iiii
  if 82 - 82: o0oOOo0O0Ooo + Ii1I * I1IiiI - oO0o
  if 6 - 6: OOooOOo / iIii1I11I1II1 / ooOoO0o / I1IiiI - i1IIi - OOooOOo
  if 8 - 8: i11iIiiIii * I11i . OOooOOo / OOooOOo
  iII = self . cipher_suite
  I111 += struct . pack ( "BBH" , iII , 0 , socket . htons ( IiiI1II1 ) )
  if 42 - 42: OoooooooOO / I1Ii111 . o0oOOo0O0Ooo / O0 - IiII * IiII
  if 1 - 1: Ii1I % I1Ii111
  if 97 - 97: OoOoOO00
  if 13 - 13: OoOoOO00 % OOooOOo . O0 / Oo0Ooo % Oo0Ooo
  for oO in range ( 0 , IiiI1II1 * 2 , 16 ) :
   OOoOoO = int ( O0O00Oo [ oO : oO + 16 ] , 16 )
   I111 += struct . pack ( "Q" , byte_swap_64 ( OOoOoO ) )
   if 19 - 19: I1Ii111 % ooOoO0o - ooOoO0o % I1IiiI . OOooOOo - OoooooooOO
   if 100 - 100: I1IiiI + Ii1I + o0oOOo0O0Ooo . i1IIi % OoooooooOO
   if 64 - 64: O0 % i1IIi * I1Ii111 - Ii1I + Oo0Ooo
   if 65 - 65: OoOoOO00 . i11iIiiIii
   if 36 - 36: oO0o * iII111i + IiII * iII111i . I1ii11iIi11i - iIii1I11I1II1
  if ( rloc_addr ) :
   I111 += struct . pack ( "H" , socket . htons ( rloc_addr . afi ) )
   I111 += rloc_addr . pack_address ( )
   if 14 - 14: I11i * oO0o + i11iIiiIii
  return ( I111 )
  if 84 - 84: iII111i / II111iiii
  if 86 - 86: I1IiiI
 def decode_lcaf ( self , packet , lcaf_len ) :
  if 97 - 97: II111iiii
  if 38 - 38: I1IiiI
  if 42 - 42: o0oOOo0O0Ooo
  if 8 - 8: i11iIiiIii / ooOoO0o
  if ( lcaf_len == 0 ) :
   o0o0 = "HHBBH"
   O0ooO = struct . calcsize ( o0o0 )
   if ( len ( packet ) < O0ooO ) : return ( None )
   if 33 - 33: I1Ii111 * IiII - O0 + I1IiiI / IiII
   ooo0O0O0oo0 , iii1II11II1 , I11i1 , iii1II11II1 , lcaf_len = struct . unpack ( o0o0 , packet [ : O0ooO ] )
   if 43 - 43: O0 / I1Ii111 . iIii1I11I1II1 - OoOoOO00
   if 47 - 47: II111iiii - I1ii11iIi11i - Ii1I
   if ( I11i1 != LISP_LCAF_SECURITY_TYPE ) :
    packet = packet [ lcaf_len + 6 : : ]
    return ( packet )
    if 9 - 9: I1ii11iIi11i - IiII
   lcaf_len = socket . ntohs ( lcaf_len )
   packet = packet [ O0ooO : : ]
   if 64 - 64: i1IIi
   if 71 - 71: IiII * o0oOOo0O0Ooo
   if 99 - 99: o0oOOo0O0Ooo
   if 28 - 28: OoooooooOO % O0 - OOooOOo / o0oOOo0O0Ooo / I1IiiI
   if 41 - 41: II111iiii * IiII / OoO0O00 . oO0o
   if 50 - 50: OoooooooOO + iIii1I11I1II1 / oO0o / OOooOOo . i11iIiiIii . ooOoO0o
  I11i1 = LISP_LCAF_SECURITY_TYPE
  o0o0 = "BBBBH"
  O0ooO = struct . calcsize ( o0o0 )
  if ( len ( packet ) < O0ooO ) : return ( None )
  if 75 - 75: iIii1I11I1II1 % ooOoO0o / OOooOOo - iII111i % i11iIiiIii
  i11 , iii1II11II1 , iII , iii1II11II1 , IiiI1II1 = struct . unpack ( o0o0 ,
 packet [ : O0ooO ] )
  if 87 - 87: OOooOOo + OOooOOo
  if 45 - 45: i1IIi - Oo0Ooo
  if 87 - 87: OoOoOO00 - OoO0O00 * OoO0O00 / Ii1I . I11i * o0oOOo0O0Ooo
  if 21 - 21: II111iiii
  if 29 - 29: OoOoOO00 % Ii1I
  if 7 - 7: i1IIi / IiII / iII111i
  packet = packet [ O0ooO : : ]
  IiiI1II1 = socket . ntohs ( IiiI1II1 )
  if ( len ( packet ) < IiiI1II1 ) : return ( None )
  if 97 - 97: OoO0O00 + iIii1I11I1II1
  if 79 - 79: ooOoO0o + oO0o - II111iiii . Oo0Ooo
  if 26 - 26: IiII
  if 52 - 52: O0 + ooOoO0o
  Ii111OO0o0o0OOoooo = [ LISP_CS_25519_CBC , LISP_CS_25519_GCM , LISP_CS_25519_CHACHA ,
 LISP_CS_1024 ]
  if ( iII not in Ii111OO0o0o0OOoooo ) :
   lprint ( "Cipher-suites {} supported, received {}" . format ( Ii111OO0o0o0OOoooo ,
 iII ) )
   packet = packet [ IiiI1II1 : : ]
   return ( packet )
   if 77 - 77: I1ii11iIi11i % oO0o
   if 67 - 67: Oo0Ooo - oO0o + I1IiiI * Oo0Ooo * o0oOOo0O0Ooo % OoOoOO00
  self . cipher_suite = iII
  if 44 - 44: iIii1I11I1II1 % i1IIi * i1IIi * OoO0O00
  if 100 - 100: OOooOOo
  if 98 - 98: I11i . O0 / II111iiii
  if 92 - 92: oO0o * IiII * O0
  if 93 - 93: II111iiii . I11i - i1IIi * OoOoOO00
  O0O00Oo = 0
  for oO in range ( 0 , IiiI1II1 , 8 ) :
   OOoOoO = byte_swap_64 ( struct . unpack ( "Q" , packet [ oO : oO + 8 ] ) [ 0 ] )
   O0O00Oo <<= 64
   O0O00Oo |= OOoOoO
   if 28 - 28: I11i % I1Ii111
  self . remote_public_key = O0O00Oo
  if 49 - 49: IiII % o0oOOo0O0Ooo . I1ii11iIi11i / OOooOOo . Ii1I * I1ii11iIi11i
  if 17 - 17: I1ii11iIi11i * OoooooooOO % i1IIi % OoooooooOO . iII111i
  if 20 - 20: OoO0O00 . oO0o
  if 4 - 4: Oo0Ooo % Ii1I % OoO0O00 * iII111i % OoooooooOO
  if 38 - 38: OoooooooOO . iII111i
  if ( self . curve25519 ) :
   OOoOoO = lisp_hex_string ( self . remote_public_key )
   OOoOoO = OOoOoO . zfill ( 64 )
   iiI = ""
   for oO in range ( 0 , len ( OOoOoO ) , 2 ) :
    iiI += chr ( int ( OOoOoO [ oO : oO + 2 ] , 16 ) )
    if 44 - 44: I11i . IiII % I1Ii111 - ooOoO0o - I1ii11iIi11i
   self . remote_public_key = iiI
   if 34 - 34: I1ii11iIi11i % i1IIi - OoO0O00
   if 18 - 18: I1IiiI + I1Ii111 - iII111i % II111iiii / OoOoOO00 % O0
  packet = packet [ IiiI1II1 : : ]
  return ( packet )
  if 59 - 59: O0 . o0oOOo0O0Ooo % I1ii11iIi11i * oO0o + I11i
  if 82 - 82: OoooooooOO
  if 88 - 88: O0 / o0oOOo0O0Ooo * o0oOOo0O0Ooo . o0oOOo0O0Ooo . O0
  if 27 - 27: i11iIiiIii % iII111i + Ii1I . OOooOOo
  if 9 - 9: OoO0O00
  if 43 - 43: Ii1I . OOooOOo + I1IiiI * i11iIiiIii
  if 2 - 2: OOooOOo
  if 3 - 3: I1IiiI . iII111i % O0 - ooOoO0o / O0
class lisp_thread ( ) :
 def __init__ ( self , name ) :
  self . thread_name = name
  self . thread_number = - 1
  self . number_of_pcap_threads = 0
  self . number_of_worker_threads = 0
  self . input_queue = Queue . Queue ( )
  self . input_stats = lisp_stats ( )
  self . lisp_packet = lisp_packet ( None )
  if 79 - 79: Ii1I + oO0o % ooOoO0o % I1IiiI
  if 68 - 68: II111iiii - OoooooooOO / iIii1I11I1II1 - o0oOOo0O0Ooo % II111iiii
  if 53 - 53: iII111i . oO0o / Oo0Ooo . OoO0O00 . i11iIiiIii
  if 60 - 60: II111iiii
  if 25 - 25: Oo0Ooo + o0oOOo0O0Ooo - OoO0O00
  if 57 - 57: II111iiii . i1IIi
  if 33 - 33: iII111i + Oo0Ooo % I11i . oO0o
  if 6 - 6: IiII + I1ii11iIi11i
  if 62 - 62: oO0o . I1Ii111 - OoooooooOO * II111iiii . i11iIiiIii
  if 13 - 13: iIii1I11I1II1 * o0oOOo0O0Ooo - i11iIiiIii
  if 63 - 63: OoooooooOO * I1Ii111
  if 50 - 50: Oo0Ooo - o0oOOo0O0Ooo % II111iiii . O0 . oO0o % II111iiii
  if 18 - 18: I11i % OoooooooOO + OoO0O00 / I11i
  if 37 - 37: i1IIi - Ii1I / IiII . II111iiii % ooOoO0o
  if 39 - 39: Ii1I % i11iIiiIii * OoO0O00
  if 23 - 23: OOooOOo + ooOoO0o / i11iIiiIii * Oo0Ooo . OoO0O00
  if 28 - 28: iII111i - o0oOOo0O0Ooo
  if 92 - 92: Oo0Ooo % o0oOOo0O0Ooo - ooOoO0o / ooOoO0o / OoOoOO00
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
  if 84 - 84: OOooOOo
  if 4 - 4: IiII . I1Ii111 / Ii1I / iII111i + II111iiii
 def decode ( self , packet ) :
  o0o0 = "BBBBQ"
  O0ooO = struct . calcsize ( o0o0 )
  if ( len ( packet ) < O0ooO ) : return ( False )
  if 32 - 32: i1IIi + iIii1I11I1II1 . I1ii11iIi11i . I11i - Ii1I
  OOOo , ii111 , OO0oOOOOO , self . record_count , self . nonce = struct . unpack ( o0o0 , packet [ : O0ooO ] )
  if 87 - 87: OoooooooOO . ooOoO0o % iIii1I11I1II1 . iIii1I11I1II1 % I1ii11iIi11i . I1Ii111
  if 25 - 25: I11i + II111iiii / ooOoO0o
  self . type = OOOo >> 4
  if ( self . type == LISP_MAP_REQUEST ) :
   self . smr_bit = True if ( OOOo & 0x01 ) else False
   self . rloc_probe = True if ( OOOo & 0x02 ) else False
   self . smr_invoked_bit = True if ( ii111 & 0x40 ) else False
   if 12 - 12: i11iIiiIii + i1IIi - Ii1I + O0 . I1IiiI
  if ( self . type == LISP_ECM ) :
   self . ddt_bit = True if ( OOOo & 0x04 ) else False
   self . to_etr = True if ( OOOo & 0x02 ) else False
   self . to_ms = True if ( OOOo & 0x01 ) else False
   if 8 - 8: o0oOOo0O0Ooo
  if ( self . type == LISP_NAT_INFO ) :
   self . info_reply = True if ( OOOo & 0x08 ) else False
   if 78 - 78: i1IIi - Oo0Ooo
  return ( True )
  if 48 - 48: Ii1I - OoooooooOO + I1Ii111 % o0oOOo0O0Ooo - OoOoOO00 . I1IiiI
  if 42 - 42: I1Ii111
 def is_info_request ( self ) :
  return ( ( self . type == LISP_NAT_INFO and self . is_info_reply ( ) == False ) )
  if 70 - 70: o0oOOo0O0Ooo / I11i + oO0o % I1IiiI % Oo0Ooo + OoO0O00
  if 80 - 80: OOooOOo
 def is_info_reply ( self ) :
  return ( True if self . info_reply else False )
  if 12 - 12: Ii1I
  if 2 - 2: OoooooooOO
 def is_rloc_probe ( self ) :
  return ( True if self . rloc_probe else False )
  if 100 - 100: Oo0Ooo / O0 * i11iIiiIii * OoooooooOO
  if 46 - 46: O0 % OoooooooOO
 def is_smr ( self ) :
  return ( True if self . smr_bit else False )
  if 22 - 22: iII111i + OoooooooOO - OoOoOO00 - OoO0O00 * I1Ii111 - oO0o
  if 99 - 99: ooOoO0o / I1IiiI . Ii1I - Ii1I * I1IiiI
 def is_smr_invoked ( self ) :
  return ( True if self . smr_invoked_bit else False )
  if 24 - 24: I11i * OoO0O00 - oO0o / iIii1I11I1II1 - Oo0Ooo . OOooOOo
  if 2 - 2: ooOoO0o - O0 - I1ii11iIi11i / I11i * OoOoOO00
 def is_ddt ( self ) :
  return ( True if self . ddt_bit else False )
  if 26 - 26: I1ii11iIi11i + I1Ii111 - oO0o + IiII % OOooOOo
  if 84 - 84: I11i % Ii1I % O0 * o0oOOo0O0Ooo
 def is_to_etr ( self ) :
  return ( True if self . to_etr else False )
  if 15 - 15: oO0o - iIii1I11I1II1 - II111iiii - IiII % I1ii11iIi11i
  if 80 - 80: IiII * iII111i . i1IIi % Ii1I % I1ii11iIi11i + ooOoO0o
 def is_to_ms ( self ) :
  return ( True if self . to_ms else False )
  if 6 - 6: I1ii11iIi11i . oO0o . OoO0O00 + IiII
  if 65 - 65: I1ii11iIi11i / ooOoO0o
  if 23 - 23: OOooOOo / OOooOOo * o0oOOo0O0Ooo * OOooOOo
  if 57 - 57: iII111i
  if 29 - 29: I1IiiI
  if 41 - 41: I1Ii111 * OoO0O00 - iII111i . Ii1I
  if 41 - 41: iIii1I11I1II1 - O0 - I1ii11iIi11i - oO0o + I1Ii111
  if 22 - 22: O0 % IiII % iII111i % I1IiiI
  if 34 - 34: iII111i . Oo0Ooo % I1ii11iIi11i . iII111i % IiII / IiII
  if 84 - 84: Ii1I
  if 1 - 1: oO0o - Oo0Ooo * iIii1I11I1II1 * Oo0Ooo * i1IIi
  if 9 - 9: iII111i - iII111i
  if 3 - 3: O0 + O0 - O0 - O0 % OoooooooOO + oO0o
  if 20 - 20: OoO0O00 + I11i . II111iiii / i11iIiiIii
  if 50 - 50: OoooooooOO / OoO0O00 % iIii1I11I1II1
  if 41 - 41: I1ii11iIi11i % I1ii11iIi11i + IiII . iII111i % I1Ii111 * ooOoO0o
  if 57 - 57: Ii1I . I1Ii111 . II111iiii % OoooooooOO * O0 + iIii1I11I1II1
  if 94 - 94: i1IIi * OoO0O00 * OoOoOO00
  if 93 - 93: ooOoO0o / OOooOOo * O0
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
  if 90 - 90: I1IiiI
  if 4 - 4: OOooOOo % ooOoO0o - OOooOOo - o0oOOo0O0Ooo
  if 30 - 30: IiII
  if 34 - 34: oO0o - II111iiii - o0oOOo0O0Ooo + iII111i + I1Ii111
  if 70 - 70: OoooooooOO + OoO0O00 * Oo0Ooo
  if 20 - 20: i11iIiiIii - II111iiii - ooOoO0o % oO0o . ooOoO0o
  if 50 - 50: iIii1I11I1II1 + I1Ii111 - I11i - OoooooooOO
  if 84 - 84: OoOoOO00 - I11i
  if 80 - 80: i11iIiiIii % OOooOOo - Oo0Ooo % OOooOOo
  if 89 - 89: Ii1I * I11i + OoOoOO00 / i11iIiiIii
  if 68 - 68: OoooooooOO * I11i
  if 86 - 86: o0oOOo0O0Ooo / OoOoOO00
  if 40 - 40: iII111i
  if 62 - 62: ooOoO0o / OOooOOo
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
  if 74 - 74: iII111i % I1Ii111 / I1Ii111 - iIii1I11I1II1 - II111iiii + OOooOOo
  if 92 - 92: I11i % I1Ii111
 def print_map_register ( self ) :
  I1i1i1 = lisp_hex_string ( self . xtr_id )
  if 35 - 35: iIii1I11I1II1 % I1Ii111 * I11i . Oo0Ooo
  iiIiiIi1 = ( "{} -> flags: {}{}{}{}{}{}{}{}{}, record-count: " +
 "{}, nonce: 0x{}, key/alg-id: {}/{}{}, auth-len: {}, xtr-id: " +
 "0x{}, site-id: {}" )
  if 3 - 3: ooOoO0o - I1ii11iIi11i * I1IiiI . OoOoOO00
  lprint ( iiIiiIi1 . format ( bold ( "Map-Register" , False ) , "P" if self . proxy_reply_requested else "p" ,
  # i1IIi % oO0o / OOooOOo . I1ii11iIi11i - I1Ii111
 "S" if self . lisp_sec_present else "s" ,
 "I" if self . xtr_id_present else "i" ,
 "T" if self . use_ttl_for_timeout else "t" ,
 "R" if self . merge_register_requested else "r" ,
 "M" if self . mobile_node else "m" ,
 "N" if self . map_notify_requested else "n" ,
 "F" if self . map_register_refresh else "f" ,
 "E" if self . encrypt_bit else "e" ,
 self . record_count , lisp_hex_string ( self . nonce ) , self . key_id ,
 self . alg_id , " (sha1)" if ( self . key_id == LISP_SHA_1_96_ALG_ID ) else ( " (sha2)" if ( self . key_id == LISP_SHA_256_128_ALG_ID ) else "" ) , self . auth_len , I1i1i1 , self . site_id ) )
  if 12 - 12: i11iIiiIii + I11i - I1ii11iIi11i
  if 27 - 27: iII111i
  if 22 - 22: OoOoOO00 / I1IiiI
  if 33 - 33: I11i
 def encode ( self ) :
  I1I = ( LISP_MAP_REGISTER << 28 ) | self . record_count
  if ( self . proxy_reply_requested ) : I1I |= 0x08000000
  if ( self . lisp_sec_present ) : I1I |= 0x04000000
  if ( self . xtr_id_present ) : I1I |= 0x02000000
  if ( self . map_register_refresh ) : I1I |= 0x1000
  if ( self . use_ttl_for_timeout ) : I1I |= 0x800
  if ( self . merge_register_requested ) : I1I |= 0x400
  if ( self . mobile_node ) : I1I |= 0x200
  if ( self . map_notify_requested ) : I1I |= 0x100
  if ( self . encryption_key_id != None ) :
   I1I |= 0x2000
   I1I |= self . encryption_key_id << 14
   if 37 - 37: OoOoOO00 % o0oOOo0O0Ooo * OoO0O00 / i11iIiiIii * II111iiii * iII111i
   if 70 - 70: ooOoO0o . i11iIiiIii % OoOoOO00 + oO0o
   if 95 - 95: I1ii11iIi11i
   if 48 - 48: I11i
   if 14 - 14: iIii1I11I1II1 / o0oOOo0O0Ooo * IiII
  if ( self . alg_id == LISP_NONE_ALG_ID ) :
   self . auth_len = 0
  else :
   if ( self . alg_id == LISP_SHA_1_96_ALG_ID ) :
    self . auth_len = LISP_SHA1_160_AUTH_DATA_LEN
    if 35 - 35: iIii1I11I1II1
   if ( self . alg_id == LISP_SHA_256_128_ALG_ID ) :
    self . auth_len = LISP_SHA2_256_AUTH_DATA_LEN
    if 34 - 34: OoO0O00 % I1IiiI . o0oOOo0O0Ooo % OoO0O00 % OoO0O00
    if 30 - 30: I1IiiI + I1IiiI
    if 75 - 75: I1IiiI - ooOoO0o - I1IiiI % oO0o % OoooooooOO
  I111 = struct . pack ( "I" , socket . htonl ( I1I ) )
  I111 += struct . pack ( "QBBH" , self . nonce , self . key_id , self . alg_id ,
 socket . htons ( self . auth_len ) )
  if 13 - 13: ooOoO0o * OoO0O00 % iIii1I11I1II1 / IiII * iII111i . Oo0Ooo
  I111 = self . zero_auth ( I111 )
  return ( I111 )
  if 23 - 23: ooOoO0o / IiII . iII111i * Ii1I
  if 87 - 87: i11iIiiIii
 def zero_auth ( self , packet ) :
  oOO0OO0O = struct . calcsize ( "I" ) + struct . calcsize ( "QHH" )
  iIIi = ""
  iIII1II11iII = 0
  if ( self . alg_id == LISP_NONE_ALG_ID ) : return ( packet )
  if ( self . alg_id == LISP_SHA_1_96_ALG_ID ) :
   iIIi = struct . pack ( "QQI" , 0 , 0 , 0 )
   iIII1II11iII = struct . calcsize ( "QQI" )
   if 45 - 45: iIii1I11I1II1 - Oo0Ooo . I11i - Oo0Ooo / ooOoO0o / o0oOOo0O0Ooo
  if ( self . alg_id == LISP_SHA_256_128_ALG_ID ) :
   iIIi = struct . pack ( "QQQQ" , 0 , 0 , 0 , 0 )
   iIII1II11iII = struct . calcsize ( "QQQQ" )
   if 81 - 81: iII111i - I11i
  packet = packet [ 0 : oOO0OO0O ] + iIIi + packet [ oOO0OO0O + iIII1II11iII : : ]
  return ( packet )
  if 20 - 20: i1IIi
  if 15 - 15: I1IiiI . Oo0Ooo . O0 . II111iiii / I11i . OoOoOO00
 def encode_auth ( self , packet ) :
  oOO0OO0O = struct . calcsize ( "I" ) + struct . calcsize ( "QHH" )
  iIII1II11iII = self . auth_len
  iIIi = self . auth_data
  packet = packet [ 0 : oOO0OO0O ] + iIIi + packet [ oOO0OO0O + iIII1II11iII : : ]
  return ( packet )
  if 3 - 3: OoOoOO00
  if 52 - 52: OoOoOO00
 def decode ( self , packet ) :
  Oo0OOOO = packet
  o0o0 = "I"
  O0ooO = struct . calcsize ( o0o0 )
  if ( len ( packet ) < O0ooO ) : return ( [ None , None ] )
  if 87 - 87: oO0o / Ii1I - OoOoOO00 % I1ii11iIi11i * Oo0Ooo % o0oOOo0O0Ooo
  I1I = struct . unpack ( o0o0 , packet [ : O0ooO ] )
  I1I = socket . ntohl ( I1I [ 0 ] )
  packet = packet [ O0ooO : : ]
  if 19 - 19: OoOoOO00 . OOooOOo . OoooooooOO
  o0o0 = "QBBH"
  O0ooO = struct . calcsize ( o0o0 )
  if ( len ( packet ) < O0ooO ) : return ( [ None , None ] )
  if 79 - 79: OOooOOo * ooOoO0o * I1IiiI * I1ii11iIi11i / I1ii11iIi11i
  self . nonce , self . key_id , self . alg_id , self . auth_len = struct . unpack ( o0o0 , packet [ : O0ooO ] )
  if 62 - 62: ooOoO0o * Ii1I % I1ii11iIi11i - i1IIi - I1ii11iIi11i
  if 24 - 24: OOooOOo
  self . auth_len = socket . ntohs ( self . auth_len )
  self . proxy_reply_requested = True if ( I1I & 0x08000000 ) else False
  if 71 - 71: IiII - i1IIi
  self . lisp_sec_present = True if ( I1I & 0x04000000 ) else False
  self . xtr_id_present = True if ( I1I & 0x02000000 ) else False
  self . use_ttl_for_timeout = True if ( I1I & 0x800 ) else False
  self . map_register_refresh = True if ( I1I & 0x1000 ) else False
  self . merge_register_requested = True if ( I1I & 0x400 ) else False
  self . mobile_node = True if ( I1I & 0x200 ) else False
  self . map_notify_requested = True if ( I1I & 0x100 ) else False
  self . record_count = I1I & 0xff
  if 56 - 56: OoOoOO00 + oO0o
  if 74 - 74: iII111i / I1Ii111 / II111iiii - iII111i / oO0o % I11i
  if 19 - 19: IiII % OoooooooOO + OoooooooOO
  if 7 - 7: i1IIi
  self . encrypt_bit = True if I1I & 0x2000 else False
  if ( self . encrypt_bit ) :
   self . encryption_key_id = ( I1I >> 14 ) & 0x7
   if 91 - 91: OoOoOO00 - OoOoOO00 . IiII
   if 33 - 33: I1Ii111 - iIii1I11I1II1 / Ii1I % O0
   if 80 - 80: IiII % OoooooooOO - IiII
   if 27 - 27: I1Ii111 - o0oOOo0O0Ooo * I1ii11iIi11i - I1IiiI
   if 22 - 22: Oo0Ooo % OoooooooOO - Oo0Ooo - iII111i . Ii1I
  if ( self . xtr_id_present ) :
   if ( self . decode_xtr_id ( Oo0OOOO ) == False ) : return ( [ None , None ] )
   if 100 - 100: II111iiii / I1Ii111 / iII111i - I1ii11iIi11i * iIii1I11I1II1
   if 7 - 7: i1IIi . IiII % i11iIiiIii * I1ii11iIi11i . I11i % I1ii11iIi11i
  packet = packet [ O0ooO : : ]
  if 35 - 35: I1IiiI
  if 48 - 48: OoooooooOO % OoooooooOO - OoO0O00 . OoOoOO00
  if 22 - 22: ooOoO0o . i11iIiiIii . OoooooooOO . i1IIi
  if 12 - 12: OoOoOO00 % OOooOOo + oO0o . O0 % iIii1I11I1II1
  if ( self . auth_len != 0 ) :
   if ( len ( packet ) < self . auth_len ) : return ( [ None , None ] )
   if 41 - 41: OoooooooOO
   if ( self . alg_id not in ( LISP_NONE_ALG_ID , LISP_SHA_1_96_ALG_ID ,
 LISP_SHA_256_128_ALG_ID ) ) :
    lprint ( "Invalid authentication alg-id: {}" . format ( self . alg_id ) )
    return ( [ None , None ] )
    if 13 - 13: I11i + I1Ii111 - I1Ii111 % oO0o / I11i
    if 4 - 4: I1IiiI + OOooOOo - IiII + iII111i
   iIII1II11iII = self . auth_len
   if ( self . alg_id == LISP_SHA_1_96_ALG_ID ) :
    O0ooO = struct . calcsize ( "QQI" )
    if ( iIII1II11iII < O0ooO ) :
     lprint ( "Invalid sha1-96 authentication length" )
     return ( [ None , None ] )
     if 78 - 78: Ii1I
    i11Ii , i1iii1I1I , Oo0O0o0Oo0Oo = struct . unpack ( "QQI" , packet [ : iIII1II11iII ] )
    IiIii1ii1 = ""
   elif ( self . alg_id == LISP_SHA_256_128_ALG_ID ) :
    O0ooO = struct . calcsize ( "QQQQ" )
    if ( iIII1II11iII < O0ooO ) :
     lprint ( "Invalid sha2-256 authentication length" )
     return ( [ None , None ] )
     if 89 - 89: ooOoO0o . OoO0O00 * OoooooooOO + OoOoOO00 / O0
    i11Ii , i1iii1I1I , Oo0O0o0Oo0Oo , IiIii1ii1 = struct . unpack ( "QQQQ" ,
 packet [ : iIII1II11iII ] )
   else :
    lprint ( "Unsupported authentication alg-id value {}" . format ( self . alg_id ) )
    if 60 - 60: I11i
    return ( [ None , None ] )
    if 97 - 97: i11iIiiIii * iIii1I11I1II1 / II111iiii
   self . auth_data = lisp_concat_auth_data ( self . alg_id , i11Ii , i1iii1I1I ,
 Oo0O0o0Oo0Oo , IiIii1ii1 )
   Oo0OOOO = self . zero_auth ( Oo0OOOO )
   packet = packet [ self . auth_len : : ]
   if 66 - 66: II111iiii + iII111i * oO0o % I11i / i1IIi / iIii1I11I1II1
  return ( [ Oo0OOOO , packet ] )
  if 62 - 62: OoOoOO00 + oO0o * IiII + O0 / OOooOOo + ooOoO0o
  if 38 - 38: i1IIi / iIii1I11I1II1 + iII111i
 def encode_xtr_id ( self , packet ) :
  iI1Oo = self . xtr_id >> 64
  OoO0ooOO = self . xtr_id & 0xffffffffffffffff
  iI1Oo = byte_swap_64 ( iI1Oo )
  OoO0ooOO = byte_swap_64 ( OoO0ooOO )
  OOoo000Ooo = byte_swap_64 ( self . site_id )
  packet += struct . pack ( "QQQ" , iI1Oo , OoO0ooOO , OOoo000Ooo )
  return ( packet )
  if 46 - 46: i1IIi + O0
  if 5 - 5: o0oOOo0O0Ooo + I1IiiI / OoooooooOO % i11iIiiIii % OoooooooOO - o0oOOo0O0Ooo
 def decode_xtr_id ( self , packet ) :
  O0ooO = struct . calcsize ( "QQQ" )
  if ( len ( packet ) < O0ooO ) : return ( [ None , None ] )
  packet = packet [ len ( packet ) - O0ooO : : ]
  iI1Oo , OoO0ooOO , OOoo000Ooo = struct . unpack ( "QQQ" ,
 packet [ : O0ooO ] )
  iI1Oo = byte_swap_64 ( iI1Oo )
  OoO0ooOO = byte_swap_64 ( OoO0ooOO )
  self . xtr_id = ( iI1Oo << 64 ) | OoO0ooOO
  self . site_id = byte_swap_64 ( OOoo000Ooo )
  return ( True )
  if 53 - 53: OoO0O00 + i11iIiiIii / iIii1I11I1II1
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
  if 54 - 54: IiII - II111iiii . ooOoO0o + Ii1I
  if 45 - 45: oO0o + II111iiii . iII111i / I1ii11iIi11i
  if 76 - 76: Ii1I + iII111i - IiII * iIii1I11I1II1 % i1IIi
  if 72 - 72: ooOoO0o + II111iiii . O0 - iII111i / OoooooooOO . I1Ii111
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
  if 28 - 28: iIii1I11I1II1 . O0
  if 32 - 32: OoooooooOO
 def print_notify ( self ) :
  iIIi = binascii . hexlify ( self . auth_data )
  if ( self . alg_id == LISP_SHA_1_96_ALG_ID and len ( iIIi ) != 40 ) :
   iIIi = self . auth_data
  elif ( self . alg_id == LISP_SHA_256_128_ALG_ID and len ( iIIi ) != 64 ) :
   iIIi = self . auth_data
   if 29 - 29: I1ii11iIi11i
  iiIiiIi1 = ( "{} -> record-count: {}, nonce: 0x{}, key/alg-id: " +
 "{}{}{}, auth-len: {}, auth-data: {}" )
  lprint ( iiIiiIi1 . format ( bold ( "Map-Notify-Ack" , False ) if self . map_notify_ack else bold ( "Map-Notify" , False ) ,
  # Ii1I . I1Ii111 + I11i
 self . record_count , lisp_hex_string ( self . nonce ) , self . key_id ,
 self . alg_id , " (sha1)" if ( self . key_id == LISP_SHA_1_96_ALG_ID ) else ( " (sha2)" if ( self . key_id == LISP_SHA_256_128_ALG_ID ) else "" ) , self . auth_len , iIIi ) )
  if 78 - 78: II111iiii
  if 54 - 54: o0oOOo0O0Ooo - I11i * OoOoOO00 * O0 - O0
  if 28 - 28: Ii1I * oO0o * oO0o * I1Ii111
  if 55 - 55: iII111i - ooOoO0o / oO0o + OoO0O00
 def zero_auth ( self , packet ) :
  if ( self . alg_id == LISP_NONE_ALG_ID ) : return ( packet )
  if ( self . alg_id == LISP_SHA_1_96_ALG_ID ) :
   iIIi = struct . pack ( "QQI" , 0 , 0 , 0 )
   if 94 - 94: IiII / I1IiiI . II111iiii
  if ( self . alg_id == LISP_SHA_256_128_ALG_ID ) :
   iIIi = struct . pack ( "QQQQ" , 0 , 0 , 0 , 0 )
   if 32 - 32: oO0o . OOooOOo % OOooOOo . OoOoOO00
  packet += iIIi
  return ( packet )
  if 37 - 37: OOooOOo + O0 + OOooOOo . iII111i . o0oOOo0O0Ooo
  if 78 - 78: I1IiiI / I11i + o0oOOo0O0Ooo . Oo0Ooo / O0
 def encode ( self , eid_records , password ) :
  if ( self . map_notify_ack ) :
   I1I = ( LISP_MAP_NOTIFY_ACK << 28 ) | self . record_count
  else :
   I1I = ( LISP_MAP_NOTIFY << 28 ) | self . record_count
   if 49 - 49: I1ii11iIi11i
  I111 = struct . pack ( "I" , socket . htonl ( I1I ) )
  I111 += struct . pack ( "QBBH" , self . nonce , self . key_id , self . alg_id ,
 socket . htons ( self . auth_len ) )
  if 66 - 66: o0oOOo0O0Ooo . I1ii11iIi11i
  if ( self . alg_id == LISP_NONE_ALG_ID ) :
   self . packet = I111 + eid_records
   return ( self . packet )
   if 18 - 18: Oo0Ooo + IiII
   if 79 - 79: OoO0O00 - O0 + II111iiii % Ii1I . I1IiiI
   if 43 - 43: I1IiiI % I1ii11iIi11i * Ii1I
   if 31 - 31: Ii1I / iII111i
   if 3 - 3: IiII
  I111 = self . zero_auth ( I111 )
  I111 += eid_records
  if 37 - 37: Ii1I * OoooooooOO * I11i + Oo0Ooo . I1IiiI
  iIII1I1i = lisp_hash_me ( I111 , self . alg_id , password , False )
  if 61 - 61: OOooOOo . OOooOOo
  oOO0OO0O = struct . calcsize ( "I" ) + struct . calcsize ( "QHH" )
  iIII1II11iII = self . auth_len
  self . auth_data = iIII1I1i
  I111 = I111 [ 0 : oOO0OO0O ] + iIII1I1i + I111 [ oOO0OO0O + iIII1II11iII : : ]
  self . packet = I111
  return ( I111 )
  if 17 - 17: II111iiii / ooOoO0o
  if 80 - 80: OOooOOo * OoO0O00 + Ii1I
 def decode ( self , packet ) :
  Oo0OOOO = packet
  o0o0 = "I"
  O0ooO = struct . calcsize ( o0o0 )
  if ( len ( packet ) < O0ooO ) : return ( None )
  if 62 - 62: OoooooooOO . O0 % Oo0Ooo
  I1I = struct . unpack ( o0o0 , packet [ : O0ooO ] )
  I1I = socket . ntohl ( I1I [ 0 ] )
  self . map_notify_ack = ( ( I1I >> 28 ) == LISP_MAP_NOTIFY_ACK )
  self . record_count = I1I & 0xff
  packet = packet [ O0ooO : : ]
  if 98 - 98: o0oOOo0O0Ooo * Oo0Ooo - Ii1I . ooOoO0o
  o0o0 = "QBBH"
  O0ooO = struct . calcsize ( o0o0 )
  if ( len ( packet ) < O0ooO ) : return ( None )
  if 2 - 2: Oo0Ooo - ooOoO0o % iIii1I11I1II1
  self . nonce , self . key_id , self . alg_id , self . auth_len = struct . unpack ( o0o0 , packet [ : O0ooO ] )
  if 88 - 88: I1Ii111 - OoO0O00
  self . nonce_key = lisp_hex_string ( self . nonce )
  self . auth_len = socket . ntohs ( self . auth_len )
  packet = packet [ O0ooO : : ]
  self . eid_records = packet [ self . auth_len : : ]
  if 79 - 79: iII111i
  if ( self . auth_len == 0 ) : return ( self . eid_records )
  if 45 - 45: II111iiii + iII111i . I11i . O0 * i1IIi - Ii1I
  if 48 - 48: I1ii11iIi11i + Oo0Ooo
  if 76 - 76: I1ii11iIi11i
  if 98 - 98: II111iiii + I1IiiI - I1ii11iIi11i . Ii1I
  if ( len ( packet ) < self . auth_len ) : return ( None )
  if 51 - 51: Ii1I + i11iIiiIii * OoO0O00 % Oo0Ooo / I1IiiI - iIii1I11I1II1
  iIII1II11iII = self . auth_len
  if ( self . alg_id == LISP_SHA_1_96_ALG_ID ) :
   i11Ii , i1iii1I1I , Oo0O0o0Oo0Oo = struct . unpack ( "QQI" , packet [ : iIII1II11iII ] )
   IiIii1ii1 = ""
   if 20 - 20: I1Ii111 . I11i . Ii1I + I11i - OOooOOo * oO0o
  if ( self . alg_id == LISP_SHA_256_128_ALG_ID ) :
   i11Ii , i1iii1I1I , Oo0O0o0Oo0Oo , IiIii1ii1 = struct . unpack ( "QQQQ" ,
 packet [ : iIII1II11iII ] )
   if 82 - 82: OoO0O00
  self . auth_data = lisp_concat_auth_data ( self . alg_id , i11Ii , i1iii1I1I ,
 Oo0O0o0Oo0Oo , IiIii1ii1 )
  if 78 - 78: II111iiii / I11i - i11iIiiIii + I1ii11iIi11i * Oo0Ooo
  O0ooO = struct . calcsize ( "I" ) + struct . calcsize ( "QHH" )
  packet = self . zero_auth ( Oo0OOOO [ : O0ooO ] )
  O0ooO += iIII1II11iII
  packet += Oo0OOOO [ O0ooO : : ]
  return ( packet )
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
  if 5 - 5: oO0o - OoooooooOO / OoOoOO00
  if 30 - 30: I11i % o0oOOo0O0Ooo + i1IIi * OoooooooOO * OoO0O00 - II111iiii
 def print_prefix ( self ) :
  if ( self . target_group . is_null ( ) ) :
   return ( green ( self . target_eid . print_prefix ( ) , False ) )
   if 55 - 55: OoO0O00
  return ( green ( self . target_eid . print_sg ( self . target_group ) , False ) )
  if 20 - 20: ooOoO0o * I1Ii111 * o0oOOo0O0Ooo - ooOoO0o
  if 32 - 32: Ii1I * oO0o
 def print_map_request ( self ) :
  I1i1i1 = ""
  if ( self . xtr_id != None and self . subscribe_bit ) :
   I1i1i1 = "subscribe, xtr-id: 0x{}, " . format ( lisp_hex_string ( self . xtr_id ) )
   if 85 - 85: i11iIiiIii . OoO0O00 + OoO0O00
   if 28 - 28: Oo0Ooo
   if 62 - 62: Oo0Ooo + OoooooooOO / iII111i
  iiIiiIi1 = ( "{} -> flags: {}{}{}{}{}{}{}{}{}{}, itr-rloc-" +
 "count: {} (+1), record-count: {}, nonce: 0x{}, source-eid: " +
 "afi {}, {}{}, target-eid: afi {}, {}, {}ITR-RLOCs:" )
  if 60 - 60: Ii1I / OoOoOO00 . I11i % OOooOOo
  lprint ( iiIiiIi1 . format ( bold ( "Map-Request" , False ) , "A" if self . auth_bit else "a" ,
  # O0 * iIii1I11I1II1 . I1Ii111 % O0
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
 self . target_eid . afi , green ( self . print_prefix ( ) , False ) , I1i1i1 ) )
  if 99 - 99: I1IiiI
  OOo = self . keys
  for Ii1ii1Ii11 in self . itr_rlocs :
   lprint ( "  itr-rloc: afi {} {}{}" . format ( Ii1ii1Ii11 . afi ,
 red ( Ii1ii1Ii11 . print_address_no_iid ( ) , False ) ,
 "" if ( OOo == None ) else ", " + OOo [ 1 ] . print_keys ( ) ) )
   OOo = None
   if 70 - 70: OoooooooOO
   if 1 - 1: iIii1I11I1II1
   if 44 - 44: I1ii11iIi11i % IiII
 def sign_map_request ( self , privkey ) :
  i11iii1 = self . signature_eid . print_address ( )
  II1iIIii1I111 = self . source_eid . print_address ( )
  I1IIii1iiI1I1 = self . target_eid . print_address ( )
  oOoO00OO00 = lisp_hex_string ( self . nonce ) + II1iIIii1I111 + I1IIii1iiI1I1
  self . map_request_signature = privkey . sign ( oOoO00OO00 )
  I111II11I = binascii . b2a_base64 ( self . map_request_signature )
  I111II11I = { "source-eid" : II1iIIii1I111 , "signature-eid" : i11iii1 ,
 "signature" : I111II11I }
  return ( json . dumps ( I111II11I ) )
  if 76 - 76: I1ii11iIi11i + iIii1I11I1II1
  if 37 - 37: O0
 def verify_map_request_sig ( self , pubkey ) :
  OOOO00oO = green ( self . signature_eid . print_address ( ) , False )
  if ( pubkey == None ) :
   lprint ( "Public-key not found for signature-EID {}" . format ( OOOO00oO ) )
   return ( False )
   if 72 - 72: OOooOOo . OoOoOO00 / II111iiii
   if 69 - 69: OOooOOo * II111iiii - ooOoO0o - i1IIi + i11iIiiIii
  II1iIIii1I111 = self . source_eid . print_address ( )
  I1IIii1iiI1I1 = self . target_eid . print_address ( )
  oOoO00OO00 = lisp_hex_string ( self . nonce ) + II1iIIii1I111 + I1IIii1iiI1I1
  pubkey = binascii . a2b_base64 ( pubkey )
  if 50 - 50: OoooooooOO * i1IIi / oO0o
  oOo0 = True
  try :
   OOoOoO = ecdsa . VerifyingKey . from_pem ( pubkey )
  except :
   lprint ( "Invalid public-key in mapping system for sig-eid {}" . format ( self . signature_eid . print_address_no_iid ( ) ) )
   if 19 - 19: o0oOOo0O0Ooo
   oOo0 = False
   if 19 - 19: OoooooooOO
   if 95 - 95: Ii1I . IiII / I11i . i11iIiiIii . IiII
  if ( oOo0 ) :
   try :
    oOo0 = OOoOoO . verify ( self . map_request_signature , oOoO00OO00 )
   except :
    oOo0 = False
    if 43 - 43: i11iIiiIii + o0oOOo0O0Ooo % o0oOOo0O0Ooo * OoooooooOO / I1Ii111
    if 9 - 9: iIii1I11I1II1 / II111iiii * OOooOOo
    if 96 - 96: Ii1I + I1ii11iIi11i * OoOoOO00 * IiII * I1ii11iIi11i . I1ii11iIi11i
  i1 = bold ( "passed" if oOo0 else "failed" , False )
  lprint ( "Signature verification {} for EID {}" . format ( i1 , OOOO00oO ) )
  return ( oOo0 )
  if 25 - 25: Ii1I * iIii1I11I1II1 * o0oOOo0O0Ooo + OoOoOO00 . OoOoOO00
  if 3 - 3: OoO0O00 . I1IiiI . I11i . I1ii11iIi11i
 def encode ( self , probe_dest , probe_port ) :
  I1I = ( LISP_MAP_REQUEST << 28 ) | self . record_count
  I1I = I1I | ( self . itr_rloc_count << 8 )
  if ( self . auth_bit ) : I1I |= 0x08000000
  if ( self . map_data_present ) : I1I |= 0x04000000
  if ( self . rloc_probe ) : I1I |= 0x02000000
  if ( self . smr_bit ) : I1I |= 0x01000000
  if ( self . pitr_bit ) : I1I |= 0x00800000
  if ( self . smr_invoked_bit ) : I1I |= 0x00400000
  if ( self . mobile_node ) : I1I |= 0x00200000
  if ( self . xtr_id_present ) : I1I |= 0x00100000
  if ( self . local_xtr ) : I1I |= 0x00004000
  if ( self . dont_reply_bit ) : I1I |= 0x00002000
  if 19 - 19: O0 * I11i % OoooooooOO
  I111 = struct . pack ( "I" , socket . htonl ( I1I ) )
  I111 += struct . pack ( "Q" , self . nonce )
  if 36 - 36: o0oOOo0O0Ooo % I11i * I1ii11iIi11i % Ii1I + i1IIi - Oo0Ooo
  if 56 - 56: I1ii11iIi11i
  if 32 - 32: OoOoOO00 % O0 % i11iIiiIii - ooOoO0o . I1IiiI
  if 24 - 24: oO0o % o0oOOo0O0Ooo / I1Ii111 + o0oOOo0O0Ooo
  if 59 - 59: II111iiii % I1IiiI * O0 . OoooooooOO - OoooooooOO % O0
  if 56 - 56: oO0o - i1IIi * OoooooooOO - II111iiii
  iii1I = False
  iIIiiiIiiii11 = self . privkey_filename
  if ( iIIiiiIiiii11 != None and os . path . exists ( iIIiiiIiiii11 ) ) :
   iI1i1i1i1i = open ( iIIiiiIiiii11 , "r" ) ; OOoOoO = iI1i1i1i1i . read ( ) ; iI1i1i1i1i . close ( )
   try :
    OOoOoO = ecdsa . SigningKey . from_pem ( OOoOoO )
   except :
    return ( None )
    if 10 - 10: II111iiii . OOooOOo / iII111i
   I1II = self . sign_map_request ( OOoOoO )
   iii1I = True
  elif ( self . map_request_signature != None ) :
   I111II11I = binascii . b2a_base64 ( self . map_request_signature )
   I1II = { "source-eid" : self . source_eid . print_address ( ) ,
 "signature-eid" : self . signature_eid . print_address ( ) ,
 "signature" : I111II11I }
   I1II = json . dumps ( I1II )
   iii1I = True
   if 91 - 91: o0oOOo0O0Ooo
  if ( iii1I ) :
   I11i1 = LISP_LCAF_JSON_TYPE
   iio00OOO0o0Oo0 = socket . htons ( LISP_AFI_LCAF )
   I1iIiI1iiI = socket . htons ( len ( I1II ) + 2 )
   oO000O00 = socket . htons ( len ( I1II ) )
   I111 += struct . pack ( "HBBBBHH" , iio00OOO0o0Oo0 , 0 , 0 , I11i1 , 0 ,
 I1iIiI1iiI , oO000O00 )
   I111 += I1II
   I111 += struct . pack ( "H" , 0 )
  else :
   if ( self . source_eid . instance_id != 0 ) :
    I111 += struct . pack ( "H" , socket . htons ( LISP_AFI_LCAF ) )
    I111 += self . source_eid . lcaf_encode_iid ( )
   else :
    I111 += struct . pack ( "H" , socket . htons ( self . source_eid . afi ) )
    I111 += self . source_eid . pack_address ( )
    if 39 - 39: O0 * Oo0Ooo - I1IiiI + Ii1I / II111iiii
    if 66 - 66: ooOoO0o + oO0o % OoooooooOO
    if 23 - 23: oO0o . OoOoOO00 + iIii1I11I1II1
    if 17 - 17: IiII
    if 12 - 12: i1IIi . OoO0O00
    if 14 - 14: OOooOOo + II111iiii % OOooOOo . oO0o * ooOoO0o
    if 54 - 54: ooOoO0o * I11i - I1Ii111
  if ( probe_dest ) :
   if ( probe_port == 0 ) : probe_port = LISP_DATA_PORT
   I11i11I = probe_dest . print_address_no_iid ( ) + ":" + str ( probe_port )
   if 15 - 15: iII111i / O0
   if ( lisp_crypto_keys_by_rloc_encap . has_key ( I11i11I ) ) :
    self . keys = lisp_crypto_keys_by_rloc_encap [ I11i11I ]
    if 61 - 61: i1IIi / i1IIi + ooOoO0o . I1Ii111 * ooOoO0o
    if 19 - 19: o0oOOo0O0Ooo . II111iiii / i1IIi
    if 82 - 82: O0 / iII111i * OoO0O00 - I11i + Oo0Ooo
    if 47 - 47: I1ii11iIi11i * I1IiiI / I1ii11iIi11i + Ii1I * II111iiii
    if 78 - 78: I1Ii111 - i1IIi + OoOoOO00 + Oo0Ooo * I1ii11iIi11i * o0oOOo0O0Ooo
    if 97 - 97: i1IIi
    if 29 - 29: I1IiiI
  for Ii1ii1Ii11 in self . itr_rlocs :
   if ( lisp_data_plane_security and self . itr_rlocs . index ( Ii1ii1Ii11 ) == 0 ) :
    if ( self . keys == None or self . keys [ 1 ] == None ) :
     OOo = lisp_keys ( 1 )
     self . keys = [ None , OOo , None , None ]
     if 37 - 37: I1ii11iIi11i * I1Ii111 * I1IiiI * O0
    OOo = self . keys [ 1 ]
    OOo . add_key_by_nonce ( self . nonce )
    I111 += OOo . encode_lcaf ( Ii1ii1Ii11 )
   else :
    I111 += struct . pack ( "H" , socket . htons ( Ii1ii1Ii11 . afi ) )
    I111 += Ii1ii1Ii11 . pack_address ( )
    if 35 - 35: I1IiiI - I1ii11iIi11i * iII111i + IiII / i1IIi
    if 46 - 46: Oo0Ooo . ooOoO0o % Oo0Ooo / II111iiii * ooOoO0o * OOooOOo
    if 59 - 59: I1Ii111 * iII111i
  i1iIi = 0 if self . target_eid . is_binary ( ) == False else self . target_eid . mask_len
  if 78 - 78: OOooOOo * i11iIiiIii
  if 54 - 54: I1Ii111 . I1Ii111 % iIii1I11I1II1 . o0oOOo0O0Ooo + O0
  oO0 = 0
  if ( self . subscribe_bit ) :
   oO0 = 0x80
   self . xtr_id_present = True
   if ( self . xtr_id == None ) :
    self . xtr_id = random . randint ( 0 , ( 2 ** 128 ) - 1 )
    if 28 - 28: I1Ii111 + II111iiii % OOooOOo * i11iIiiIii % oO0o + OoooooooOO
    if 65 - 65: o0oOOo0O0Ooo . IiII % i1IIi % OoOoOO00 + I1ii11iIi11i
    if 41 - 41: OoOoOO00 / iIii1I11I1II1
  o0o0 = "BB"
  I111 += struct . pack ( o0o0 , oO0 , i1iIi )
  if 92 - 92: Ii1I . iII111i % I1Ii111 % O0
  if ( self . target_group . is_null ( ) == False ) :
   I111 += struct . pack ( "H" , socket . htons ( LISP_AFI_LCAF ) )
   I111 += self . target_eid . lcaf_encode_sg ( self . target_group )
  elif ( self . target_eid . instance_id != 0 or
 self . target_eid . is_geo_prefix ( ) ) :
   I111 += struct . pack ( "H" , socket . htons ( LISP_AFI_LCAF ) )
   I111 += self . target_eid . lcaf_encode_iid ( )
  else :
   I111 += struct . pack ( "H" , socket . htons ( self . target_eid . afi ) )
   I111 += self . target_eid . pack_address ( )
   if 93 - 93: OOooOOo - i11iIiiIii . OoooooooOO
   if 86 - 86: I1IiiI . I1IiiI
   if 67 - 67: i11iIiiIii . ooOoO0o / iIii1I11I1II1 % Ii1I * oO0o - O0
   if 100 - 100: OoooooooOO / Oo0Ooo - Ii1I . I11i / OoooooooOO - I11i
   if 86 - 86: I11i + Oo0Ooo * OOooOOo * i1IIi / OoooooooOO
  if ( self . subscribe_bit ) : I111 = self . encode_xtr_id ( I111 )
  return ( I111 )
  if 64 - 64: OOooOOo + o0oOOo0O0Ooo / i11iIiiIii - OoOoOO00 + OOooOOo
  if 90 - 90: i1IIi % OoO0O00 / ooOoO0o - O0 + i11iIiiIii
 def lcaf_decode_json ( self , packet ) :
  o0o0 = "BBBBHH"
  O0ooO = struct . calcsize ( o0o0 )
  if ( len ( packet ) < O0ooO ) : return ( None )
  if 98 - 98: OoooooooOO
  OOooOo , I1i11Iii1I1I1 , I11i1 , IIi1ii1i1i1 , I1iIiI1iiI , oO000O00 = struct . unpack ( o0o0 , packet [ : O0ooO ] )
  if 92 - 92: Ii1I - ooOoO0o / ooOoO0o + IiII
  if 57 - 57: OOooOOo - OoooooooOO * OoO0O00 * iII111i + oO0o
  if ( I11i1 != LISP_LCAF_JSON_TYPE ) : return ( packet )
  if 100 - 100: I1Ii111 - i1IIi
  if 90 - 90: Ii1I + oO0o . II111iiii - OoOoOO00 % iIii1I11I1II1
  if 24 - 24: IiII / Ii1I * OOooOOo
  if 33 - 33: OOooOOo
  I1iIiI1iiI = socket . ntohs ( I1iIiI1iiI )
  oO000O00 = socket . ntohs ( oO000O00 )
  packet = packet [ O0ooO : : ]
  if ( len ( packet ) < I1iIiI1iiI ) : return ( None )
  if ( I1iIiI1iiI != oO000O00 + 2 ) : return ( None )
  if 22 - 22: O0 + OOooOOo % i1IIi
  if 83 - 83: O0 + Ii1I % i11iIiiIii
  if 32 - 32: I1Ii111 % Oo0Ooo - I11i + O0
  if 57 - 57: OoO0O00 + I1Ii111 . I11i . i1IIi - o0oOOo0O0Ooo / Oo0Ooo
  try :
   I1II = json . loads ( packet [ 0 : oO000O00 ] )
  except :
   return ( None )
   if 19 - 19: iIii1I11I1II1 . OoO0O00 / OoooooooOO
  packet = packet [ oO000O00 : : ]
  if 2 - 2: O0 - O0 % I1Ii111 / I1ii11iIi11i
  if 76 - 76: OoO0O00 * oO0o - OoO0O00
  if 57 - 57: OoooooooOO / OoOoOO00 + oO0o . Ii1I
  if 14 - 14: i11iIiiIii % OOooOOo * o0oOOo0O0Ooo * OoOoOO00
  o0o0 = "H"
  O0ooO = struct . calcsize ( o0o0 )
  ooo0O0O0oo0 = struct . unpack ( o0o0 , packet [ : O0ooO ] ) [ 0 ]
  packet = packet [ O0ooO : : ]
  if ( ooo0O0O0oo0 != 0 ) : return ( packet )
  if 55 - 55: I1Ii111 * OOooOOo * I1Ii111
  if 70 - 70: O0 . Ii1I
  if 33 - 33: OOooOOo * Ii1I
  if 64 - 64: i11iIiiIii . iIii1I11I1II1
  if ( I1II . has_key ( "source-eid" ) == False ) : return ( packet )
  III1II1I1iI = I1II [ "source-eid" ]
  ooo0O0O0oo0 = LISP_AFI_IPV4 if III1II1I1iI . count ( "." ) == 3 else LISP_AFI_IPV6 if III1II1I1iI . count ( ":" ) == 7 else None
  if 57 - 57: OOooOOo / OoO0O00 + I1ii11iIi11i
  if ( ooo0O0O0oo0 == None ) :
   lprint ( "Bad JSON 'source-eid' value: {}" . format ( III1II1I1iI ) )
   return ( None )
   if 60 - 60: O0 * Oo0Ooo % OOooOOo + IiII . OoO0O00 . Oo0Ooo
   if 70 - 70: I11i . I1ii11iIi11i * oO0o
  self . source_eid . afi = ooo0O0O0oo0
  self . source_eid . store_address ( III1II1I1iI )
  if 97 - 97: oO0o . iIii1I11I1II1 - OOooOOo
  if ( I1II . has_key ( "signature-eid" ) == False ) : return ( packet )
  III1II1I1iI = I1II [ "signature-eid" ]
  if ( III1II1I1iI . count ( ":" ) != 7 ) :
   lprint ( "Bad JSON 'signature-eid' value: {}" . format ( III1II1I1iI ) )
   return ( None )
   if 23 - 23: I1ii11iIi11i % I11i
   if 18 - 18: OoooooooOO . i1IIi + II111iiii
  self . signature_eid . afi = LISP_AFI_IPV6
  self . signature_eid . store_address ( III1II1I1iI )
  if 99 - 99: I1Ii111 - I1ii11iIi11i - I1IiiI - I1Ii111 + OoO0O00 + II111iiii
  if ( I1II . has_key ( "signature" ) == False ) : return ( packet )
  I111II11I = binascii . a2b_base64 ( I1II [ "signature" ] )
  self . map_request_signature = I111II11I
  return ( packet )
  if 34 - 34: I1Ii111 * I11i
  if 31 - 31: IiII . oO0o
 def decode ( self , packet , source , port ) :
  o0o0 = "I"
  O0ooO = struct . calcsize ( o0o0 )
  if ( len ( packet ) < O0ooO ) : return ( None )
  if 40 - 40: Ii1I - I11i / II111iiii * i1IIi + IiII * II111iiii
  I1I = struct . unpack ( o0o0 , packet [ : O0ooO ] )
  I1I = I1I [ 0 ]
  packet = packet [ O0ooO : : ]
  if 53 - 53: I1ii11iIi11i - i11iIiiIii . OoO0O00 / OoOoOO00 - I1Ii111
  o0o0 = "Q"
  O0ooO = struct . calcsize ( o0o0 )
  if ( len ( packet ) < O0ooO ) : return ( None )
  if 99 - 99: Ii1I - IiII - i1IIi / i11iIiiIii . IiII
  oO00o0oOoo = struct . unpack ( o0o0 , packet [ : O0ooO ] )
  packet = packet [ O0ooO : : ]
  if 58 - 58: OOooOOo
  I1I = socket . ntohl ( I1I )
  self . auth_bit = True if ( I1I & 0x08000000 ) else False
  self . map_data_present = True if ( I1I & 0x04000000 ) else False
  self . rloc_probe = True if ( I1I & 0x02000000 ) else False
  self . smr_bit = True if ( I1I & 0x01000000 ) else False
  self . pitr_bit = True if ( I1I & 0x00800000 ) else False
  self . smr_invoked_bit = True if ( I1I & 0x00400000 ) else False
  self . mobile_node = True if ( I1I & 0x00200000 ) else False
  self . xtr_id_present = True if ( I1I & 0x00100000 ) else False
  self . local_xtr = True if ( I1I & 0x00004000 ) else False
  self . dont_reply_bit = True if ( I1I & 0x00002000 ) else False
  self . itr_rloc_count = ( ( I1I >> 8 ) & 0x1f ) + 1
  self . record_count = I1I & 0xff
  self . nonce = oO00o0oOoo [ 0 ]
  if 12 - 12: I1IiiI . o0oOOo0O0Ooo * OoooooooOO
  if 64 - 64: OoOoOO00 + IiII - i1IIi . II111iiii . OoO0O00
  if 31 - 31: oO0o . iII111i - I11i . iIii1I11I1II1 + I11i . OoOoOO00
  if 86 - 86: I1ii11iIi11i - I1ii11iIi11i / iII111i - I1ii11iIi11i * iII111i + I1Ii111
  if ( self . xtr_id_present ) :
   if ( self . decode_xtr_id ( packet ) == False ) : return ( None )
   if 61 - 61: Oo0Ooo / II111iiii / Oo0Ooo / i1IIi . Oo0Ooo - IiII
   if 30 - 30: OoooooooOO % OOooOOo
  O0ooO = struct . calcsize ( "H" )
  if ( len ( packet ) < O0ooO ) : return ( None )
  if 14 - 14: OoOoOO00 / OoO0O00 / i11iIiiIii - OoOoOO00 / o0oOOo0O0Ooo - OOooOOo
  ooo0O0O0oo0 = struct . unpack ( "H" , packet [ : O0ooO ] )
  self . source_eid . afi = socket . ntohs ( ooo0O0O0oo0 [ 0 ] )
  packet = packet [ O0ooO : : ]
  if 81 - 81: iII111i % Ii1I . ooOoO0o
  if ( self . source_eid . afi == LISP_AFI_LCAF ) :
   OOo00o0oOO0o = packet
   packet = self . source_eid . lcaf_decode_iid ( packet )
   if ( packet == None ) :
    packet = self . lcaf_decode_json ( OOo00o0oOO0o )
    if ( packet == None ) : return ( None )
    if 27 - 27: iII111i / i1IIi . iII111i % OoooooooOO * oO0o % II111iiii
  elif ( self . source_eid . afi != LISP_AFI_NONE ) :
   packet = self . source_eid . unpack_address ( packet )
   if ( packet == None ) : return ( None )
   if 40 - 40: I11i % Ii1I
  self . source_eid . mask_len = self . source_eid . host_mask_len ( )
  if 76 - 76: ooOoO0o . oO0o
  iI1IiiI = ( os . getenv ( "LISP_NO_CRYPTO" ) != None )
  self . itr_rlocs = [ ]
  while ( self . itr_rloc_count != 0 ) :
   O0ooO = struct . calcsize ( "H" )
   if ( len ( packet ) < O0ooO ) : return ( None )
   if 7 - 7: OoO0O00 % I1Ii111 + IiII . OoOoOO00 . oO0o
   ooo0O0O0oo0 = struct . unpack ( "H" , packet [ : O0ooO ] ) [ 0 ]
   if 76 - 76: O0 * II111iiii
   Ii1ii1Ii11 = lisp_address ( LISP_AFI_NONE , "" , 32 , 0 )
   Ii1ii1Ii11 . afi = socket . ntohs ( ooo0O0O0oo0 )
   if 38 - 38: I1Ii111
   if 18 - 18: Ii1I - iII111i
   if 18 - 18: II111iiii
   if 92 - 92: o0oOOo0O0Ooo . I1Ii111 + iII111i % I1Ii111 % i11iIiiIii
   if 46 - 46: OoooooooOO
   if ( Ii1ii1Ii11 . afi != LISP_AFI_LCAF ) :
    if ( len ( packet ) < Ii1ii1Ii11 . addr_length ( ) ) : return ( None )
    packet = Ii1ii1Ii11 . unpack_address ( packet [ O0ooO : : ] )
    if ( packet == None ) : return ( None )
    if 80 - 80: O0 * iII111i
    if ( iI1IiiI ) :
     self . itr_rlocs . append ( Ii1ii1Ii11 )
     self . itr_rloc_count -= 1
     continue
     if 73 - 73: IiII / Ii1I + I1Ii111 . OOooOOo - II111iiii / iIii1I11I1II1
     if 79 - 79: I1Ii111 * Oo0Ooo . o0oOOo0O0Ooo - I1Ii111
    I11i11I = lisp_build_crypto_decap_lookup_key ( Ii1ii1Ii11 , port )
    if 16 - 16: I1IiiI - O0 * I1ii11iIi11i . I1ii11iIi11i % OOooOOo
    if 39 - 39: II111iiii / I11i - OoOoOO00 * OoOoOO00 - Ii1I
    if 8 - 8: O0 . i11iIiiIii
    if 54 - 54: OOooOOo . I1ii11iIi11i * I11i % I1Ii111 . O0 * IiII
    if 87 - 87: Ii1I % I1ii11iIi11i * Oo0Ooo
    if ( lisp_nat_traversal and Ii1ii1Ii11 . is_private_address ( ) and source ) : Ii1ii1Ii11 = source
    if 59 - 59: Oo0Ooo / I11i - iIii1I11I1II1 * iIii1I11I1II1
    I1iIii1iii11i = lisp_crypto_keys_by_rloc_decap
    if ( I1iIii1iii11i . has_key ( I11i11I ) ) : I1iIii1iii11i . pop ( I11i11I )
    if 88 - 88: I1Ii111 * i11iIiiIii % o0oOOo0O0Ooo
    if 20 - 20: OoO0O00 / i11iIiiIii * o0oOOo0O0Ooo - I1ii11iIi11i - II111iiii / i11iIiiIii
    if 17 - 17: Oo0Ooo - I1IiiI - IiII - OOooOOo / oO0o + I1Ii111
    if 40 - 40: I1Ii111 / I1IiiI - OoooooooOO / I1Ii111
    if 48 - 48: Oo0Ooo . OoO0O00 . I1IiiI * iII111i . iIii1I11I1II1
    if 66 - 66: OoooooooOO * O0 / ooOoO0o * Ii1I
    lisp_write_ipc_decap_key ( I11i11I , None )
   else :
    Oo0OOOO = packet
    i11II = lisp_keys ( 1 )
    packet = i11II . decode_lcaf ( Oo0OOOO , 0 )
    if ( packet == None ) : return ( None )
    if 47 - 47: OoO0O00 . I11i % ooOoO0o - Oo0Ooo . I1IiiI
    if 26 - 26: I1ii11iIi11i - i1IIi . OOooOOo . Ii1I
    if 5 - 5: IiII - I11i
    if 16 - 16: IiII . iII111i . Oo0Ooo % OOooOOo / IiII
    Ii111OO0o0o0OOoooo = [ LISP_CS_25519_CBC , LISP_CS_25519_GCM ,
 LISP_CS_25519_CHACHA ]
    if ( i11II . cipher_suite in Ii111OO0o0o0OOoooo ) :
     if ( i11II . cipher_suite == LISP_CS_25519_CBC or
 i11II . cipher_suite == LISP_CS_25519_GCM ) :
      OOoOoO = lisp_keys ( 1 , do_poly = False , do_chacha = False )
      if 72 - 72: o0oOOo0O0Ooo * ooOoO0o - i11iIiiIii / Ii1I
     if ( i11II . cipher_suite == LISP_CS_25519_CHACHA ) :
      OOoOoO = lisp_keys ( 1 , do_poly = True , do_chacha = True )
      if 11 - 11: O0 - I1IiiI
    else :
     OOoOoO = lisp_keys ( 1 , do_poly = False , do_curve = False ,
 do_chacha = False )
     if 31 - 31: iII111i
    packet = OOoOoO . decode_lcaf ( Oo0OOOO , 0 )
    if ( packet == None ) : return ( None )
    if 1 - 1: I1Ii111 / OoOoOO00 * OoOoOO00 - o0oOOo0O0Ooo % Ii1I
    if ( len ( packet ) < O0ooO ) : return ( None )
    ooo0O0O0oo0 = struct . unpack ( "H" , packet [ : O0ooO ] ) [ 0 ]
    Ii1ii1Ii11 . afi = socket . ntohs ( ooo0O0O0oo0 )
    if ( len ( packet ) < Ii1ii1Ii11 . addr_length ( ) ) : return ( None )
    if 96 - 96: IiII / Ii1I % OoO0O00 . iIii1I11I1II1
    packet = Ii1ii1Ii11 . unpack_address ( packet [ O0ooO : : ] )
    if ( packet == None ) : return ( None )
    if 30 - 30: I11i - OoO0O00
    if ( iI1IiiI ) :
     self . itr_rlocs . append ( Ii1ii1Ii11 )
     self . itr_rloc_count -= 1
     continue
     if 15 - 15: OoooooooOO
     if 31 - 31: II111iiii
    I11i11I = lisp_build_crypto_decap_lookup_key ( Ii1ii1Ii11 , port )
    if 62 - 62: iIii1I11I1II1 % I1Ii111 % I1ii11iIi11i * IiII
    oO0OO0o0oo0o = None
    if ( lisp_nat_traversal and Ii1ii1Ii11 . is_private_address ( ) and source ) : Ii1ii1Ii11 = source
    if 55 - 55: IiII
    if 43 - 43: OOooOOo
    if ( lisp_crypto_keys_by_rloc_decap . has_key ( I11i11I ) ) :
     OOo = lisp_crypto_keys_by_rloc_decap [ I11i11I ]
     oO0OO0o0oo0o = OOo [ 1 ] if OOo and OOo [ 1 ] else None
     if 17 - 17: i11iIiiIii
     if 94 - 94: OoooooooOO - IiII + oO0o . OoooooooOO / i1IIi
    o0OoO0o00o = True
    if ( oO0OO0o0oo0o ) :
     if ( oO0OO0o0oo0o . compare_keys ( OOoOoO ) ) :
      self . keys = [ None , oO0OO0o0oo0o , None , None ]
      lprint ( "Maintain stored decap-keys for RLOC {}" . format ( red ( I11i11I , False ) ) )
      if 46 - 46: iII111i + I1Ii111 % OoooooooOO * I1ii11iIi11i
     else :
      o0OoO0o00o = False
      O000o0O0 = bold ( "Remote decap-rekeying" , False )
      lprint ( "{} for RLOC {}" . format ( O000o0O0 , red ( I11i11I ,
 False ) ) )
      OOoOoO . copy_keypair ( oO0OO0o0oo0o )
      OOoOoO . uptime = oO0OO0o0oo0o . uptime
      oO0OO0o0oo0o = None
      if 51 - 51: ooOoO0o * Ii1I * OoooooooOO % OoOoOO00
      if 25 - 25: iIii1I11I1II1 * OoooooooOO * Ii1I - i1IIi
      if 23 - 23: o0oOOo0O0Ooo . ooOoO0o - OoooooooOO + I11i
    if ( oO0OO0o0oo0o == None ) :
     self . keys = [ None , OOoOoO , None , None ]
     if ( lisp_i_am_etr == False and lisp_i_am_rtr == False ) :
      OOoOoO . local_public_key = None
      lprint ( "{} for {}" . format ( bold ( "Ignoring decap-keys" ,
 False ) , red ( I11i11I , False ) ) )
     elif ( OOoOoO . remote_public_key != None ) :
      if ( o0OoO0o00o ) :
       lprint ( "{} for RLOC {}" . format ( bold ( "New decap-keying" , False ) ,
       # OoOoOO00 . Ii1I % i11iIiiIii * OoOoOO00 * Oo0Ooo
 red ( I11i11I , False ) ) )
       if 66 - 66: Oo0Ooo - i11iIiiIii - IiII
      OOoOoO . compute_shared_key ( "decap" )
      OOoOoO . add_key_by_rloc ( I11i11I , False )
      if 54 - 54: OOooOOo
      if 27 - 27: OoOoOO00 - OoO0O00 + o0oOOo0O0Ooo + ooOoO0o . OoO0O00
      if 86 - 86: II111iiii - OoooooooOO - ooOoO0o % iII111i
      if 16 - 16: ooOoO0o + Oo0Ooo + OoooooooOO
   self . itr_rlocs . append ( Ii1ii1Ii11 )
   self . itr_rloc_count -= 1
   if 87 - 87: I1IiiI . oO0o / IiII - OoooooooOO
   if 33 - 33: oO0o % OoO0O00 . iIii1I11I1II1 / IiII
  O0ooO = struct . calcsize ( "BBH" )
  if ( len ( packet ) < O0ooO ) : return ( None )
  if 3 - 3: Ii1I + OoO0O00
  oO0 , i1iIi , ooo0O0O0oo0 = struct . unpack ( "BBH" , packet [ : O0ooO ] )
  self . subscribe_bit = ( oO0 & 0x80 )
  self . target_eid . afi = socket . ntohs ( ooo0O0O0oo0 )
  packet = packet [ O0ooO : : ]
  if 60 - 60: OoO0O00 . OoOoOO00 - I1ii11iIi11i - I1IiiI - II111iiii % Oo0Ooo
  self . target_eid . mask_len = i1iIi
  if ( self . target_eid . afi == LISP_AFI_LCAF ) :
   packet , OoO000 = self . target_eid . lcaf_decode_eid ( packet )
   if ( packet == None ) : return ( None )
   if ( OoO000 ) : self . target_group = OoO000
  else :
   packet = self . target_eid . unpack_address ( packet )
   if ( packet == None ) : return ( None )
   packet = packet [ O0ooO : : ]
   if 12 - 12: OoOoOO00 / I1IiiI * Oo0Ooo
  return ( packet )
  if 59 - 59: Oo0Ooo . o0oOOo0O0Ooo % I1IiiI / OoooooooOO % oO0o
  if 81 - 81: OoooooooOO / ooOoO0o * iIii1I11I1II1 . Oo0Ooo + oO0o / O0
 def print_eid_tuple ( self ) :
  return ( lisp_print_eid_tuple ( self . target_eid , self . target_group ) )
  if 84 - 84: II111iiii - o0oOOo0O0Ooo
  if 78 - 78: IiII
 def encode_xtr_id ( self , packet ) :
  iI1Oo = self . xtr_id >> 64
  OoO0ooOO = self . xtr_id & 0xffffffffffffffff
  iI1Oo = byte_swap_64 ( iI1Oo )
  OoO0ooOO = byte_swap_64 ( OoO0ooOO )
  packet += struct . pack ( "QQ" , iI1Oo , OoO0ooOO )
  return ( packet )
  if 58 - 58: i11iIiiIii - OoOoOO00
  if 67 - 67: I1ii11iIi11i / iII111i + iIii1I11I1II1 % I1IiiI
 def decode_xtr_id ( self , packet ) :
  O0ooO = struct . calcsize ( "QQ" )
  if ( len ( packet ) < O0ooO ) : return ( None )
  packet = packet [ len ( packet ) - O0ooO : : ]
  iI1Oo , OoO0ooOO = struct . unpack ( "QQ" , packet [ : O0ooO ] )
  iI1Oo = byte_swap_64 ( iI1Oo )
  OoO0ooOO = byte_swap_64 ( OoO0ooOO )
  self . xtr_id = ( iI1Oo << 64 ) | OoO0ooOO
  return ( True )
  if 99 - 99: ooOoO0o . Ii1I
  if 92 - 92: i1IIi
  if 68 - 68: OoO0O00 % IiII - oO0o - ooOoO0o . Oo0Ooo
  if 30 - 30: OoooooooOO % o0oOOo0O0Ooo + ooOoO0o * OoO0O00
  if 57 - 57: I11i + iIii1I11I1II1 . OoO0O00 + oO0o
  if 4 - 4: Ii1I
  if 43 - 43: i1IIi . I1IiiI * iIii1I11I1II1 * i11iIiiIii - OOooOOo + ooOoO0o
  if 56 - 56: Oo0Ooo % i11iIiiIii / Ii1I . I1Ii111 . OoO0O00 - OoOoOO00
  if 32 - 32: I1Ii111 / oO0o / I1IiiI
  if 22 - 22: OoO0O00 - OoOoOO00 . Oo0Ooo + o0oOOo0O0Ooo
  if 69 - 69: oO0o - I1IiiI
  if 10 - 10: i1IIi / iII111i . II111iiii * i1IIi % OoooooooOO
  if 83 - 83: I11i . OOooOOo + I1Ii111 * I11i . I1Ii111 + oO0o
  if 64 - 64: Ii1I . o0oOOo0O0Ooo - i1IIi
  if 35 - 35: I1ii11iIi11i % OoooooooOO
  if 59 - 59: I1IiiI % I11i
  if 32 - 32: I1IiiI * O0 + O0
  if 34 - 34: IiII
  if 5 - 5: OoO0O00 . I1IiiI
  if 48 - 48: Oo0Ooo - OoO0O00 . I11i - iIii1I11I1II1 % Ii1I
  if 47 - 47: iII111i / OoooooooOO - II111iiii
  if 91 - 91: OoOoOO00 + o0oOOo0O0Ooo
  if 23 - 23: i1IIi
  if 9 - 9: i1IIi % I1Ii111 - OoO0O00 * OoOoOO00 . o0oOOo0O0Ooo
  if 18 - 18: Ii1I . OoOoOO00 + iII111i . I1IiiI + OoooooooOO . OoO0O00
  if 31 - 31: I1Ii111 - I11i
  if 49 - 49: iIii1I11I1II1 - iIii1I11I1II1 - OoOoOO00 + IiII / OoOoOO00
  if 74 - 74: OoooooooOO + I1ii11iIi11i % O0
  if 32 - 32: I1ii11iIi11i + I1ii11iIi11i
  if 89 - 89: ooOoO0o + oO0o + Ii1I - OOooOOo
  if 12 - 12: OoOoOO00 - o0oOOo0O0Ooo - I1Ii111 / I11i
  if 17 - 17: OoO0O00 - I1Ii111 - II111iiii / I1Ii111 / Ii1I
class lisp_map_reply ( ) :
 def __init__ ( self ) :
  self . rloc_probe = False
  self . echo_nonce_capable = False
  self . security = False
  self . record_count = 0
  self . hop_count = 0
  self . nonce = 0
  self . keys = None
  if 30 - 30: OOooOOo * I1ii11iIi11i % I1ii11iIi11i + iII111i * IiII
  if 33 - 33: o0oOOo0O0Ooo + I11i * O0 * OoO0O00 . I1ii11iIi11i
 def print_map_reply ( self ) :
  iiIiiIi1 = "{} -> flags: {}{}{}, hop-count: {}, record-count: {}, " + "nonce: 0x{}"
  if 74 - 74: iII111i * iII111i * o0oOOo0O0Ooo / oO0o
  lprint ( iiIiiIi1 . format ( bold ( "Map-Reply" , False ) , "R" if self . rloc_probe else "r" ,
  # O0 + I1IiiI . II111iiii - I1Ii111 * Ii1I % Ii1I
 "E" if self . echo_nonce_capable else "e" ,
 "S" if self . security else "s" , self . hop_count , self . record_count ,
 lisp_hex_string ( self . nonce ) ) )
  if 21 - 21: o0oOOo0O0Ooo * o0oOOo0O0Ooo + O0
  if 73 - 73: o0oOOo0O0Ooo / iII111i % O0 . i1IIi
 def encode ( self ) :
  I1I = ( LISP_MAP_REPLY << 28 ) | self . record_count
  I1I |= self . hop_count << 8
  if ( self . rloc_probe ) : I1I |= 0x08000000
  if ( self . echo_nonce_capable ) : I1I |= 0x04000000
  if ( self . security ) : I1I |= 0x02000000
  if 99 - 99: II111iiii - I1ii11iIi11i * IiII
  I111 = struct . pack ( "I" , socket . htonl ( I1I ) )
  I111 += struct . pack ( "Q" , self . nonce )
  return ( I111 )
  if 3 - 3: IiII - I1ii11iIi11i * iII111i * I1ii11iIi11i + Oo0Ooo
  if 15 - 15: I1ii11iIi11i * Ii1I / iII111i . o0oOOo0O0Ooo / Ii1I % OoOoOO00
 def decode ( self , packet ) :
  o0o0 = "I"
  O0ooO = struct . calcsize ( o0o0 )
  if ( len ( packet ) < O0ooO ) : return ( None )
  if 75 - 75: OoooooooOO % i11iIiiIii % iIii1I11I1II1 % I1ii11iIi11i / i11iIiiIii
  I1I = struct . unpack ( o0o0 , packet [ : O0ooO ] )
  I1I = I1I [ 0 ]
  packet = packet [ O0ooO : : ]
  if 96 - 96: ooOoO0o * oO0o / iIii1I11I1II1 / I11i
  o0o0 = "Q"
  O0ooO = struct . calcsize ( o0o0 )
  if ( len ( packet ) < O0ooO ) : return ( None )
  if 5 - 5: o0oOOo0O0Ooo
  oO00o0oOoo = struct . unpack ( o0o0 , packet [ : O0ooO ] )
  packet = packet [ O0ooO : : ]
  if 83 - 83: I11i * I1IiiI . II111iiii * i1IIi % O0
  I1I = socket . ntohl ( I1I )
  self . rloc_probe = True if ( I1I & 0x08000000 ) else False
  self . echo_nonce_capable = True if ( I1I & 0x04000000 ) else False
  self . security = True if ( I1I & 0x02000000 ) else False
  self . hop_count = ( I1I >> 8 ) & 0xff
  self . record_count = I1I & 0xff
  self . nonce = oO00o0oOoo [ 0 ]
  if 35 - 35: OoOoOO00 % OoO0O00 + O0 * o0oOOo0O0Ooo % I1ii11iIi11i
  if ( lisp_crypto_keys_by_nonce . has_key ( self . nonce ) ) :
   self . keys = lisp_crypto_keys_by_nonce [ self . nonce ]
   self . keys [ 1 ] . delete_key_by_nonce ( self . nonce )
   if 57 - 57: oO0o / I11i
  return ( packet )
  if 63 - 63: ooOoO0o * OoO0O00 * ooOoO0o + OoOoOO00
  if 25 - 25: iII111i * OoOoOO00 / I1IiiI / IiII
  if 11 - 11: OOooOOo + i11iIiiIii
  if 14 - 14: OoOoOO00 / IiII + OoO0O00 - Ii1I
  if 38 - 38: I1Ii111
  if 30 - 30: II111iiii + I11i . i11iIiiIii + iIii1I11I1II1
  if 100 - 100: oO0o * o0oOOo0O0Ooo / iII111i
  if 92 - 92: ooOoO0o / i11iIiiIii * OOooOOo
  if 55 - 55: ooOoO0o
  if 1 - 1: OoO0O00
  if 43 - 43: iIii1I11I1II1 - OOooOOo - o0oOOo0O0Ooo + I1ii11iIi11i - I1Ii111 % I1ii11iIi11i
  if 58 - 58: OoOoOO00
  if 27 - 27: IiII * OOooOOo - OoooooooOO . Ii1I - II111iiii
  if 62 - 62: I1IiiI / iIii1I11I1II1 * I11i
  if 84 - 84: IiII - OoOoOO00 . IiII + ooOoO0o . iII111i
  if 96 - 96: Ii1I % iII111i * Ii1I % I1IiiI . o0oOOo0O0Ooo / o0oOOo0O0Ooo
  if 7 - 7: OoO0O00 - ooOoO0o % i1IIi
  if 24 - 24: OoO0O00 % O0 % I11i
  if 61 - 61: ooOoO0o . iII111i / ooOoO0o * OoooooooOO
  if 13 - 13: II111iiii
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
  if 47 - 47: O0 . I1IiiI / ooOoO0o % i11iIiiIii
  if 47 - 47: Ii1I . OoOoOO00 . iIii1I11I1II1 . o0oOOo0O0Ooo
 def print_prefix ( self ) :
  if ( self . group . is_null ( ) ) :
   return ( green ( self . eid . print_prefix ( ) , False ) )
   if 39 - 39: o0oOOo0O0Ooo
  return ( green ( self . eid . print_sg ( self . group ) , False ) )
  if 89 - 89: OoooooooOO + iII111i . I1Ii111 / Ii1I
  if 75 - 75: iIii1I11I1II1 * iII111i / OoOoOO00 * II111iiii . i1IIi
 def print_ttl ( self ) :
  I1i11iiIiIi = self . record_ttl
  if ( self . record_ttl & 0x80000000 ) :
   I1i11iiIiIi = str ( self . record_ttl & 0x7fffffff ) + " secs"
  elif ( ( I1i11iiIiIi % 60 ) == 0 ) :
   I1i11iiIiIi = str ( I1i11iiIiIi / 60 ) + " hours"
  else :
   I1i11iiIiIi = str ( I1i11iiIiIi ) + " mins"
   if 59 - 59: I11i . I11i * I1IiiI - Ii1I % OoOoOO00
  return ( I1i11iiIiIi )
  if 19 - 19: OoooooooOO / Oo0Ooo - I1Ii111 . OoOoOO00
  if 8 - 8: I11i % ooOoO0o . iIii1I11I1II1
 def store_ttl ( self ) :
  I1i11iiIiIi = self . record_ttl * 60
  if ( self . record_ttl & 0x80000000 ) : I1i11iiIiIi = self . record_ttl & 0x7fffffff
  return ( I1i11iiIiIi )
  if 95 - 95: o0oOOo0O0Ooo + i11iIiiIii . I1ii11iIi11i . ooOoO0o . o0oOOo0O0Ooo
  if 93 - 93: iII111i
 def print_record ( self , indent , ddt ) :
  ooOOOOO000o = ""
  IIiIi1II11ii = ""
  IIi = bold ( "invalid-action" , False )
  if ( ddt ) :
   if ( self . action < len ( lisp_map_referral_action_string ) ) :
    IIi = lisp_map_referral_action_string [ self . action ]
    IIi = bold ( IIi , False )
    ooOOOOO000o = ( ", " + bold ( "ddt-incomplete" , False ) ) if self . ddt_incomplete else ""
    if 41 - 41: I1Ii111 % I1Ii111 % oO0o / iIii1I11I1II1 % OoooooooOO
    IIiIi1II11ii = ( ", sig-count: " + str ( self . signature_count ) ) if ( self . signature_count != 0 ) else ""
    if 33 - 33: o0oOOo0O0Ooo - II111iiii
    if 95 - 95: OoooooooOO
  else :
   if ( self . action < len ( lisp_map_reply_action_string ) ) :
    IIi = lisp_map_reply_action_string [ self . action ]
    if ( self . action != LISP_NO_ACTION ) :
     IIi = bold ( IIi , False )
     if 23 - 23: II111iiii + I11i / O0 . I11i . I1Ii111 + iIii1I11I1II1
     if 2 - 2: i1IIi . O0 / o0oOOo0O0Ooo . II111iiii / OoO0O00 % i1IIi
     if 12 - 12: o0oOOo0O0Ooo
     if 58 - 58: iIii1I11I1II1 * Ii1I . ooOoO0o . Oo0Ooo * Ii1I
  ooo0O0O0oo0 = LISP_AFI_LCAF if ( self . eid . afi < 0 ) else self . eid . afi
  iiIiiIi1 = ( "{}EID-record -> record-ttl: {}, rloc-count: {}, action: " +
 "{}, {}{}{}, map-version: {}, afi: {}, [iid]eid/ml: {}" )
  if 63 - 63: OoOoOO00 . I11i * o0oOOo0O0Ooo - I11i % I11i
  lprint ( iiIiiIi1 . format ( indent , self . print_ttl ( ) , self . rloc_count ,
 IIi , "auth" if ( self . authoritative is True ) else "non-auth" ,
 ooOOOOO000o , IIiIi1II11ii , self . map_version , ooo0O0O0oo0 ,
 green ( self . print_prefix ( ) , False ) ) )
  if 62 - 62: I11i - ooOoO0o / ooOoO0o
  if 95 - 95: OoOoOO00 - i1IIi / I1Ii111 . ooOoO0o % OOooOOo - i1IIi
 def encode ( self ) :
  i1ii1iIIIiI1 = self . action << 13
  if ( self . authoritative ) : i1ii1iIIIiI1 |= 0x1000
  if ( self . ddt_incomplete ) : i1ii1iIIIiI1 |= 0x800
  if 97 - 97: OoooooooOO * II111iiii
  if 85 - 85: Oo0Ooo
  if 33 - 33: i11iIiiIii + I1IiiI
  if 95 - 95: I1ii11iIi11i / IiII % iIii1I11I1II1 + O0
  ooo0O0O0oo0 = self . eid . afi if ( self . eid . instance_id == 0 ) else LISP_AFI_LCAF
  if ( ooo0O0O0oo0 < 0 ) : ooo0O0O0oo0 = LISP_AFI_LCAF
  i111IiI1III1 = ( self . group . is_null ( ) == False )
  if ( i111IiI1III1 ) : ooo0O0O0oo0 = LISP_AFI_LCAF
  if 97 - 97: IiII
  Iiiiii1I = ( self . signature_count << 12 ) | self . map_version
  i1iIi = 0 if self . eid . is_binary ( ) == False else self . eid . mask_len
  if 20 - 20: i1IIi * ooOoO0o
  I111 = struct . pack ( "IBBHHH" , socket . htonl ( self . record_ttl ) ,
 self . rloc_count , i1iIi , socket . htons ( i1ii1iIIIiI1 ) ,
 socket . htons ( Iiiiii1I ) , socket . htons ( ooo0O0O0oo0 ) )
  if 2 - 2: O0 . Ii1I
  if 96 - 96: o0oOOo0O0Ooo / I1Ii111 % Ii1I - ooOoO0o
  if 35 - 35: OOooOOo
  if 90 - 90: i11iIiiIii
  if ( i111IiI1III1 ) :
   I111 += self . eid . lcaf_encode_sg ( self . group )
   return ( I111 )
   if 47 - 47: OoO0O00 . i11iIiiIii
   if 9 - 9: OoOoOO00 - I11i . OoooooooOO % ooOoO0o
   if 13 - 13: OoO0O00 * iIii1I11I1II1 + II111iiii - Oo0Ooo - OoOoOO00
   if 43 - 43: iII111i / I1Ii111 * I1IiiI % ooOoO0o % I1IiiI
   if 18 - 18: OoO0O00
  if ( self . eid . afi == LISP_AFI_GEO_COORD and self . eid . instance_id == 0 ) :
   I111 = I111 [ 0 : - 2 ]
   I111 += self . eid . address . encode_geo ( )
   return ( I111 )
   if 99 - 99: iII111i / oO0o . i11iIiiIii / I11i + i1IIi - I11i
   if 50 - 50: i1IIi
   if 56 - 56: OoO0O00 + I1Ii111 / Ii1I
   if 75 - 75: OoOoOO00
   if 96 - 96: o0oOOo0O0Ooo * I11i * Oo0Ooo
  if ( ooo0O0O0oo0 == LISP_AFI_LCAF ) :
   I111 += self . eid . lcaf_encode_iid ( )
   return ( I111 )
   if 36 - 36: OoooooooOO + ooOoO0o . oO0o * ooOoO0o + IiII
   if 45 - 45: oO0o / iII111i + I1ii11iIi11i - Oo0Ooo - ooOoO0o . iIii1I11I1II1
   if 52 - 52: I1IiiI + i1IIi . iII111i * I1IiiI
   if 31 - 31: Oo0Ooo % iIii1I11I1II1 . O0
   if 80 - 80: I11i / Oo0Ooo + I1ii11iIi11i
  I111 += self . eid . pack_address ( )
  return ( I111 )
  if 18 - 18: II111iiii - iII111i / iIii1I11I1II1 % OoOoOO00 % I1ii11iIi11i / o0oOOo0O0Ooo
  if 47 - 47: OOooOOo
 def decode ( self , packet ) :
  o0o0 = "IBBHHH"
  O0ooO = struct . calcsize ( o0o0 )
  if ( len ( packet ) < O0ooO ) : return ( None )
  if 24 - 24: Ii1I % o0oOOo0O0Ooo
  self . record_ttl , self . rloc_count , self . eid . mask_len , i1ii1iIIIiI1 , self . map_version , self . eid . afi = struct . unpack ( o0o0 , packet [ : O0ooO ] )
  if 87 - 87: o0oOOo0O0Ooo % iII111i / ooOoO0o - IiII + i11iIiiIii
  if 85 - 85: OoooooooOO * IiII . OOooOOo / iII111i / OoooooooOO
  if 87 - 87: OoO0O00
  self . record_ttl = socket . ntohl ( self . record_ttl )
  i1ii1iIIIiI1 = socket . ntohs ( i1ii1iIIIiI1 )
  self . action = ( i1ii1iIIIiI1 >> 13 ) & 0x7
  self . authoritative = True if ( ( i1ii1iIIIiI1 >> 12 ) & 1 ) else False
  self . ddt_incomplete = True if ( ( i1ii1iIIIiI1 >> 11 ) & 1 ) else False
  self . map_version = socket . ntohs ( self . map_version )
  self . signature_count = self . map_version >> 12
  self . map_version = self . map_version & 0xfff
  self . eid . afi = socket . ntohs ( self . eid . afi )
  self . eid . instance_id = 0
  packet = packet [ O0ooO : : ]
  if 32 - 32: i11iIiiIii - OoOoOO00 * I11i . Oo0Ooo * ooOoO0o
  if 21 - 21: OOooOOo
  if 11 - 11: oO0o % i11iIiiIii * O0
  if 28 - 28: I1Ii111 / iIii1I11I1II1 + OOooOOo . I1ii11iIi11i % OOooOOo + OoO0O00
  if ( self . eid . afi == LISP_AFI_LCAF ) :
   packet , oO0000O0o = self . eid . lcaf_decode_eid ( packet )
   if ( oO0000O0o ) : self . group = oO0000O0o
   self . group . instance_id = self . eid . instance_id
   return ( packet )
   if 51 - 51: oO0o
   if 85 - 85: I1IiiI % i11iIiiIii + i1IIi . OoO0O00
  packet = self . eid . unpack_address ( packet )
  return ( packet )
  if 23 - 23: i11iIiiIii % I1ii11iIi11i * iII111i % o0oOOo0O0Ooo
  if 1 - 1: OoOoOO00
 def print_eid_tuple ( self ) :
  return ( lisp_print_eid_tuple ( self . eid , self . group ) )
  if 77 - 77: I1Ii111 + i11iIiiIii . iIii1I11I1II1 % ooOoO0o - OoooooooOO
  if 90 - 90: I1ii11iIi11i * II111iiii * iIii1I11I1II1 + I1IiiI / i1IIi
  if 45 - 45: IiII * Ii1I . o0oOOo0O0Ooo
  if 68 - 68: Oo0Ooo + o0oOOo0O0Ooo * OOooOOo . II111iiii % Ii1I
  if 14 - 14: OoooooooOO * Oo0Ooo % ooOoO0o . Ii1I - iII111i - II111iiii
  if 67 - 67: iII111i
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
  if 79 - 79: I1IiiI / o0oOOo0O0Ooo . Ii1I * I1ii11iIi11i + I11i
  if 96 - 96: OoO0O00 * II111iiii
LISP_UDP_PROTOCOL = 17
LISP_DEFAULT_ECM_TTL = 128
if 1 - 1: I1IiiI - OoOoOO00
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
  if 74 - 74: OoOoOO00 * II111iiii + O0 + I11i
  if 3 - 3: iIii1I11I1II1 - i1IIi / iII111i + i1IIi + O0
 def print_ecm ( self ) :
  iiIiiIi1 = ( "{} -> flags: {}{}{}{}, " + "inner IP: {} -> {}, inner UDP: {} -> {}" )
  if 18 - 18: iIii1I11I1II1 . iII111i % OOooOOo % oO0o + iIii1I11I1II1 * OoooooooOO
  lprint ( iiIiiIi1 . format ( bold ( "ECM" , False ) , "S" if self . security else "s" ,
 "D" if self . ddt else "d" , "E" if self . to_etr else "e" ,
 "M" if self . to_ms else "m" ,
 green ( self . source . print_address ( ) , False ) ,
 green ( self . dest . print_address ( ) , False ) , self . udp_sport ,
 self . udp_dport ) )
  if 78 - 78: IiII
 def encode ( self , packet , inner_source , inner_dest ) :
  self . udp_length = len ( packet ) + 8
  self . source = inner_source
  self . dest = inner_dest
  if ( inner_dest . is_ipv4 ( ) ) :
   self . afi = LISP_AFI_IPV4
   self . length = self . udp_length + 20
   if 38 - 38: OoO0O00 * I1ii11iIi11i
  if ( inner_dest . is_ipv6 ( ) ) :
   self . afi = LISP_AFI_IPV6
   self . length = self . udp_length
   if 4 - 4: OoO0O00 . I1ii11iIi11i
   if 21 - 21: i11iIiiIii / OoO0O00 / I1ii11iIi11i * O0 - II111iiii * OOooOOo
   if 27 - 27: o0oOOo0O0Ooo . OoOoOO00 * Ii1I * iII111i * O0
   if 93 - 93: IiII % I1Ii111 % II111iiii
   if 20 - 20: OoooooooOO * I1Ii111
   if 38 - 38: iII111i . OoooooooOO
  I1I = ( LISP_ECM << 28 )
  if ( self . security ) : I1I |= 0x08000000
  if ( self . ddt ) : I1I |= 0x04000000
  if ( self . to_etr ) : I1I |= 0x02000000
  if ( self . to_ms ) : I1I |= 0x01000000
  if 28 - 28: I1Ii111 * i1IIi . I1ii11iIi11i
  Oo0OO = struct . pack ( "I" , socket . htonl ( I1I ) )
  if 99 - 99: i1IIi % oO0o
  oOo00Ooo0o0 = ""
  if ( self . afi == LISP_AFI_IPV4 ) :
   oOo00Ooo0o0 = struct . pack ( "BBHHHBBH" , 0x45 , 0 , socket . htons ( self . length ) ,
 0 , 0 , self . ttl , self . protocol , socket . htons ( self . ip_checksum ) )
   oOo00Ooo0o0 += self . source . pack_address ( )
   oOo00Ooo0o0 += self . dest . pack_address ( )
   oOo00Ooo0o0 = lisp_ip_checksum ( oOo00Ooo0o0 )
   if 13 - 13: OoOoOO00 * O0 - iIii1I11I1II1 * I1IiiI + i11iIiiIii
  if ( self . afi == LISP_AFI_IPV6 ) :
   oOo00Ooo0o0 = struct . pack ( "BBHHBB" , 0x60 , 0 , 0 , socket . htons ( self . length ) ,
 self . protocol , self . ttl )
   oOo00Ooo0o0 += self . source . pack_address ( )
   oOo00Ooo0o0 += self . dest . pack_address ( )
   if 98 - 98: iIii1I11I1II1 + OoO0O00 + I1IiiI + OoooooooOO
   if 87 - 87: ooOoO0o / II111iiii - I1ii11iIi11i % i11iIiiIii
  i1I1iIi1IiI = socket . htons ( self . udp_sport )
  O0o0oo0oOO0oO = socket . htons ( self . udp_dport )
  o0Oo = socket . htons ( self . udp_length )
  O0o = socket . htons ( self . udp_checksum )
  O00oo0O00 = struct . pack ( "HHHH" , i1I1iIi1IiI , O0o0oo0oOO0oO , o0Oo , O0o )
  return ( Oo0OO + oOo00Ooo0o0 + O00oo0O00 )
  if 73 - 73: I1IiiI - I11i . Ii1I * iII111i
  if 3 - 3: i11iIiiIii
 def decode ( self , packet ) :
  if 72 - 72: ooOoO0o
  if 85 - 85: Ii1I . Ii1I * IiII * i1IIi
  if 4 - 4: i11iIiiIii - i1IIi
  if 90 - 90: i1IIi / OoooooooOO . Oo0Ooo
  o0o0 = "I"
  O0ooO = struct . calcsize ( o0o0 )
  if ( len ( packet ) < O0ooO ) : return ( None )
  if 5 - 5: iII111i * ooOoO0o + IiII . I1IiiI / I1IiiI
  I1I = struct . unpack ( o0o0 , packet [ : O0ooO ] )
  if 72 - 72: OoO0O00 / I1ii11iIi11i - OOooOOo - OoooooooOO / OoooooooOO % OoooooooOO
  I1I = socket . ntohl ( I1I [ 0 ] )
  self . security = True if ( I1I & 0x08000000 ) else False
  self . ddt = True if ( I1I & 0x04000000 ) else False
  self . to_etr = True if ( I1I & 0x02000000 ) else False
  self . to_ms = True if ( I1I & 0x01000000 ) else False
  packet = packet [ O0ooO : : ]
  if 85 - 85: OoO0O00 . o0oOOo0O0Ooo . I1IiiI
  if 75 - 75: iIii1I11I1II1 - Ii1I % O0 % IiII
  if 6 - 6: Oo0Ooo % oO0o * ooOoO0o - i1IIi . OoOoOO00
  if 20 - 20: Oo0Ooo / I1Ii111 . Oo0Ooo
  if ( len ( packet ) < 1 ) : return ( None )
  OOOO0oO0O = struct . unpack ( "B" , packet [ 0 : 1 ] ) [ 0 ]
  OOOO0oO0O = OOOO0oO0O >> 4
  if 60 - 60: I1ii11iIi11i - I1IiiI * O0 * Oo0Ooo . i1IIi . OoOoOO00
  if ( OOOO0oO0O == 4 ) :
   O0ooO = struct . calcsize ( "HHIBBH" )
   if ( len ( packet ) < O0ooO ) : return ( None )
   if 24 - 24: IiII * I1IiiI / OOooOOo
   Oo000 , o0Oo , Oo000 , iiIi1Ii1ii1 , OoOOOOo , O0o = struct . unpack ( "HHIBBH" , packet [ : O0ooO ] )
   self . length = socket . ntohs ( o0Oo )
   self . ttl = iiIi1Ii1ii1
   self . protocol = OoOOOOo
   self . ip_checksum = socket . ntohs ( O0o )
   self . source . afi = self . dest . afi = LISP_AFI_IPV4
   if 7 - 7: Oo0Ooo * II111iiii / iIii1I11I1II1 % iIii1I11I1II1 - i1IIi
   if 85 - 85: I1Ii111 + iIii1I11I1II1 + ooOoO0o + Oo0Ooo
   if 75 - 75: O0 . I11i - Ii1I / I1Ii111 / I1ii11iIi11i % I11i
   if 97 - 97: OoOoOO00 - OoO0O00
   OoOOOOo = struct . pack ( "H" , 0 )
   Oooo = struct . calcsize ( "HHIBB" )
   OOOoO0 = struct . calcsize ( "H" )
   packet = packet [ : Oooo ] + OoOOOOo + packet [ Oooo + OOOoO0 : ]
   if 67 - 67: IiII / o0oOOo0O0Ooo + I11i % iII111i - ooOoO0o - I1IiiI
   packet = packet [ O0ooO : : ]
   packet = self . source . unpack_address ( packet )
   if ( packet == None ) : return ( None )
   packet = self . dest . unpack_address ( packet )
   if ( packet == None ) : return ( None )
   if 44 - 44: Ii1I . o0oOOo0O0Ooo . iIii1I11I1II1 + OoooooooOO - I1IiiI
   if 22 - 22: I11i * I1ii11iIi11i . OoooooooOO / Oo0Ooo / Ii1I
  if ( OOOO0oO0O == 6 ) :
   O0ooO = struct . calcsize ( "IHBB" )
   if ( len ( packet ) < O0ooO ) : return ( None )
   if 54 - 54: I1Ii111 % Ii1I + ooOoO0o
   Oo000 , o0Oo , OoOOOOo , iiIi1Ii1ii1 = struct . unpack ( "IHBB" , packet [ : O0ooO ] )
   self . length = socket . ntohs ( o0Oo )
   self . protocol = OoOOOOo
   self . ttl = iiIi1Ii1ii1
   self . source . afi = self . dest . afi = LISP_AFI_IPV6
   if 45 - 45: Ii1I / oO0o * I1Ii111 . Ii1I
   packet = packet [ O0ooO : : ]
   packet = self . source . unpack_address ( packet )
   if ( packet == None ) : return ( None )
   packet = self . dest . unpack_address ( packet )
   if ( packet == None ) : return ( None )
   if 25 - 25: I1ii11iIi11i / I1ii11iIi11i
   if 79 - 79: Oo0Ooo - OoO0O00 % Oo0Ooo . II111iiii
  self . source . mask_len = self . source . host_mask_len ( )
  self . dest . mask_len = self . dest . host_mask_len ( )
  if 84 - 84: ooOoO0o * OoooooooOO + O0
  O0ooO = struct . calcsize ( "HHHH" )
  if ( len ( packet ) < O0ooO ) : return ( None )
  if 84 - 84: i1IIi . I11i . i1IIi . Oo0Ooo
  i1I1iIi1IiI , O0o0oo0oOO0oO , o0Oo , O0o = struct . unpack ( "HHHH" , packet [ : O0ooO ] )
  self . udp_sport = socket . ntohs ( i1I1iIi1IiI )
  self . udp_dport = socket . ntohs ( O0o0oo0oOO0oO )
  self . udp_length = socket . ntohs ( o0Oo )
  self . udp_checksum = socket . ntohs ( O0o )
  packet = packet [ O0ooO : : ]
  return ( packet )
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
  if 64 - 64: i1IIi / IiII . IiII - I1Ii111 % OOooOOo . II111iiii
  if 78 - 78: I1Ii111 - O0 - I1Ii111 . iIii1I11I1II1 % I1ii11iIi11i . OoooooooOO
  if 64 - 64: IiII
  if 21 - 21: o0oOOo0O0Ooo - ooOoO0o * OoooooooOO . OoooooooOO
  if 17 - 17: OOooOOo - iII111i % I1IiiI * OOooOOo * iIii1I11I1II1 . o0oOOo0O0Ooo
  if 58 - 58: oO0o - II111iiii + O0
  if 54 - 54: iIii1I11I1II1 - IiII - IiII
  if 18 - 18: i11iIiiIii + iIii1I11I1II1 . i11iIiiIii
  if 63 - 63: iII111i - OoO0O00 * OOooOOo
  if 89 - 89: iII111i / Oo0Ooo
  if 66 - 66: o0oOOo0O0Ooo + OoOoOO00 % OoooooooOO . I11i
  if 30 - 30: II111iiii - Oo0Ooo - i11iIiiIii + O0
  if 93 - 93: i1IIi + I1Ii111 / OoO0O00 - I11i % Oo0Ooo / Ii1I
  if 1 - 1: Oo0Ooo / Ii1I . i11iIiiIii % OOooOOo + o0oOOo0O0Ooo + O0
  if 54 - 54: I1Ii111 + ooOoO0o % IiII
  if 83 - 83: o0oOOo0O0Ooo * iIii1I11I1II1
  if 36 - 36: OoOoOO00 + II111iiii - OoO0O00 % ooOoO0o * i1IIi
  if 4 - 4: Ii1I + OoO0O00 * I1ii11iIi11i
  if 13 - 13: OoOoOO00 - IiII * iIii1I11I1II1 * O0
  if 26 - 26: OoooooooOO + oO0o + OoO0O00 . O0
  if 46 - 46: OoooooooOO - Oo0Ooo * I1Ii111 * OOooOOo * I1Ii111 . oO0o
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
  if 80 - 80: o0oOOo0O0Ooo
  if 3 - 3: i11iIiiIii / OOooOOo + oO0o
 def print_rloc_name ( self , cour = False ) :
  if ( self . rloc_name == None ) : return ( "" )
  iIIiii = self . rloc_name
  if ( cour ) : iIIiii = lisp_print_cour ( iIIiii )
  return ( 'rloc-name: {}' . format ( blue ( iIIiii , cour ) ) )
  if 25 - 25: II111iiii + I11i
  if 97 - 97: O0 + OOooOOo % OoOoOO00 * I11i . iIii1I11I1II1
 def print_record ( self , indent ) :
  IIII1i = self . print_rloc_name ( )
  if ( IIII1i != "" ) : IIII1i = ", " + IIII1i
  oOOO000Oo = ""
  if ( self . geo ) :
   IiiIi1II = ""
   if ( self . geo . geo_name ) : IiiIi1II = "'{}' " . format ( self . geo . geo_name )
   oOOO000Oo = ", geo: {}{}" . format ( IiiIi1II , self . geo . print_geo ( ) )
   if 1 - 1: OoooooooOO . I11i / OoOoOO00 + o0oOOo0O0Ooo % i1IIi
  IiIIii11 = ""
  if ( self . elp ) :
   IiiIi1II = ""
   if ( self . elp . elp_name ) : IiiIi1II = "'{}' " . format ( self . elp . elp_name )
   IiIIii11 = ", elp: {}{}" . format ( IiiIi1II , self . elp . print_elp ( True ) )
   if 61 - 61: iIii1I11I1II1 % IiII - II111iiii
  Ii1111IIIiiIi = ""
  if ( self . rle ) :
   IiiIi1II = ""
   if ( self . rle . rle_name ) : IiiIi1II = "'{}' " . format ( self . rle . rle_name )
   Ii1111IIIiiIi = ", rle: {}{}" . format ( IiiIi1II , self . rle . print_rle ( False ) )
   if 94 - 94: I11i
  OoI1iIi = ""
  if ( self . json ) :
   IiiIi1II = ""
   if ( self . json . json_name ) :
    IiiIi1II = "'{}' " . format ( self . json . json_name )
    if 80 - 80: i1IIi / OOooOOo / o0oOOo0O0Ooo - IiII
   OoI1iIi = ", json: {}" . format ( self . json . print_json ( False ) )
   if 1 - 1: I1IiiI / iII111i . iIii1I11I1II1 % I1Ii111 + OoO0O00
   if 44 - 44: i1IIi - iIii1I11I1II1 * iII111i . ooOoO0o % i1IIi
  II11IIi = ""
  if ( self . rloc . is_null ( ) == False and self . keys and self . keys [ 1 ] ) :
   II11IIi = ", " + self . keys [ 1 ] . print_keys ( )
   if 94 - 94: OOooOOo % Oo0Ooo . I1Ii111
   if 74 - 74: iII111i
  iiIiiIi1 = ( "{}RLOC-record -> flags: {}, {}/{}/{}/{}, afi: {}, rloc: "
 + "{}{}{}{}{}{}{}" )
  lprint ( iiIiiIi1 . format ( indent , self . print_flags ( ) , self . priority ,
 self . weight , self . mpriority , self . mweight , self . rloc . afi ,
 red ( self . rloc . print_address_no_iid ( ) , False ) , IIII1i , oOOO000Oo ,
 IiIIii11 , Ii1111IIIiiIi , OoI1iIi , II11IIi ) )
  if 1 - 1: Oo0Ooo . oO0o . o0oOOo0O0Ooo / I1IiiI
  if 64 - 64: iII111i
 def print_flags ( self ) :
  return ( "{}{}{}" . format ( "L" if self . local_bit else "l" , "P" if self . probe_bit else "p" , "R" if self . reach_bit else "r" ) )
  if 65 - 65: O0 / II111iiii * IiII % Ii1I + o0oOOo0O0Ooo
  if 43 - 43: I1Ii111 + OoO0O00 * OoooooooOO
  if 85 - 85: iII111i + OOooOOo
 def store_rloc_entry ( self , rloc_entry ) :
  II1iIiIiIIi = rloc_entry . rloc if ( rloc_entry . translated_rloc . is_null ( ) ) else rloc_entry . translated_rloc
  if 53 - 53: Ii1I - OOooOOo
  self . rloc . copy_address ( II1iIiIiIIi )
  if 75 - 75: iII111i % O0 - I11i - I1ii11iIi11i + I1IiiI - I1IiiI
  if ( rloc_entry . rloc_name ) :
   self . rloc_name = rloc_entry . rloc_name
   if 87 - 87: i1IIi % Ii1I % i1IIi + iIii1I11I1II1
   if 23 - 23: iIii1I11I1II1 * I11i . I1Ii111 - o0oOOo0O0Ooo
  if ( rloc_entry . geo ) :
   self . geo = rloc_entry . geo
  else :
   IiiIi1II = rloc_entry . geo_name
   if ( IiiIi1II and lisp_geo_list . has_key ( IiiIi1II ) ) :
    self . geo = lisp_geo_list [ IiiIi1II ]
    if 66 - 66: I1IiiI * I1Ii111 / i11iIiiIii / OOooOOo
    if 19 - 19: ooOoO0o % iIii1I11I1II1 * OoooooooOO
  if ( rloc_entry . elp ) :
   self . elp = rloc_entry . elp
  else :
   IiiIi1II = rloc_entry . elp_name
   if ( IiiIi1II and lisp_elp_list . has_key ( IiiIi1II ) ) :
    self . elp = lisp_elp_list [ IiiIi1II ]
    if 60 - 60: I1Ii111 * iII111i / OoooooooOO * Oo0Ooo
    if 47 - 47: iII111i + o0oOOo0O0Ooo % iIii1I11I1II1 * OoOoOO00
  if ( rloc_entry . rle ) :
   self . rle = rloc_entry . rle
  else :
   IiiIi1II = rloc_entry . rle_name
   if ( IiiIi1II and lisp_rle_list . has_key ( IiiIi1II ) ) :
    self . rle = lisp_rle_list [ IiiIi1II ]
    if 65 - 65: OOooOOo . II111iiii * i11iIiiIii + OOooOOo
    if 99 - 99: I1ii11iIi11i % Oo0Ooo
  if ( rloc_entry . json ) :
   self . json = rloc_entry . json
  else :
   IiiIi1II = rloc_entry . json_name
   if ( IiiIi1II and lisp_json_list . has_key ( IiiIi1II ) ) :
    self . json = lisp_json_list [ IiiIi1II ]
    if 31 - 31: o0oOOo0O0Ooo - II111iiii * OOooOOo . OOooOOo - oO0o
    if 57 - 57: OOooOOo / i11iIiiIii / I1Ii111 - Oo0Ooo . iIii1I11I1II1
  self . priority = rloc_entry . priority
  self . weight = rloc_entry . weight
  self . mpriority = rloc_entry . mpriority
  self . mweight = rloc_entry . mweight
  if 84 - 84: IiII
  if 42 - 42: O0 . I1Ii111 / I11i
 def encode_lcaf ( self ) :
  iio00OOO0o0Oo0 = socket . htons ( LISP_AFI_LCAF )
  oO00o = ""
  if ( self . geo ) :
   oO00o = self . geo . encode_geo ( )
   if 76 - 76: O0 + II111iiii * OoO0O00
   if 1 - 1: o0oOOo0O0Ooo
  IIi1II = ""
  if ( self . elp ) :
   i11IIii1iI11 = ""
   for I111I1IiI1i1 in self . elp . elp_nodes :
    ooo0O0O0oo0 = socket . htons ( I111I1IiI1i1 . address . afi )
    I1i11Iii1I1I1 = 0
    if ( I111I1IiI1i1 . eid ) : I1i11Iii1I1I1 |= 0x4
    if ( I111I1IiI1i1 . probe ) : I1i11Iii1I1I1 |= 0x2
    if ( I111I1IiI1i1 . strict ) : I1i11Iii1I1I1 |= 0x1
    I1i11Iii1I1I1 = socket . htons ( I1i11Iii1I1I1 )
    i11IIii1iI11 += struct . pack ( "HH" , I1i11Iii1I1I1 , ooo0O0O0oo0 )
    i11IIii1iI11 += I111I1IiI1i1 . address . pack_address ( )
    if 52 - 52: Ii1I / i11iIiiIii / oO0o
    if 54 - 54: oO0o
   O0o0 = socket . htons ( len ( i11IIii1iI11 ) )
   IIi1II = struct . pack ( "HBBBBH" , iio00OOO0o0Oo0 , 0 , 0 , LISP_LCAF_ELP_TYPE ,
 0 , O0o0 )
   IIi1II += i11IIii1iI11
   if 64 - 64: OoOoOO00 + iII111i * OoOoOO00 - I1IiiI * OoooooooOO
   if 27 - 27: II111iiii + i11iIiiIii
  i1I1 = ""
  if ( self . rle ) :
   IIIIiiiI11iII = ""
   for II1ii in self . rle . rle_nodes :
    ooo0O0O0oo0 = socket . htons ( II1ii . address . afi )
    IIIIiiiI11iII += struct . pack ( "HBBH" , 0 , 0 , II1ii . level , ooo0O0O0oo0 )
    IIIIiiiI11iII += II1ii . address . pack_address ( )
    if ( II1ii . rloc_name ) :
     IIIIiiiI11iII += struct . pack ( "H" , socket . htons ( LISP_AFI_NAME ) )
     IIIIiiiI11iII += II1ii . rloc_name + "\0"
     if 10 - 10: Ii1I - II111iiii / i11iIiiIii * I1IiiI / O0 . I11i
     if 67 - 67: OoOoOO00 - ooOoO0o - iIii1I11I1II1
     if 31 - 31: II111iiii + o0oOOo0O0Ooo * i11iIiiIii . o0oOOo0O0Ooo
   OO000 = socket . htons ( len ( IIIIiiiI11iII ) )
   i1I1 = struct . pack ( "HBBBBH" , iio00OOO0o0Oo0 , 0 , 0 , LISP_LCAF_RLE_TYPE ,
 0 , OO000 )
   i1I1 += IIIIiiiI11iII
   if 28 - 28: oO0o . ooOoO0o / I11i + Oo0Ooo
   if 55 - 55: OoooooooOO % OoOoOO00 + i1IIi * OoO0O00 * OOooOOo
  iII1I1I11 = ""
  if ( self . json ) :
   I1iIiI1iiI = socket . htons ( len ( self . json . json_string ) + 2 )
   oO000O00 = socket . htons ( len ( self . json . json_string ) )
   iII1I1I11 = struct . pack ( "HBBBBHH" , iio00OOO0o0Oo0 , 0 , 0 , LISP_LCAF_JSON_TYPE ,
 0 , I1iIiI1iiI , oO000O00 )
   iII1I1I11 += self . json . json_string
   iII1I1I11 += struct . pack ( "H" , 0 )
   if 47 - 47: iIii1I11I1II1 / Oo0Ooo + I1IiiI + oO0o
   if 60 - 60: OoO0O00
  iiIIII11i1 = ""
  if ( self . rloc . is_null ( ) == False and self . keys and self . keys [ 1 ] ) :
   iiIIII11i1 = self . keys [ 1 ] . encode_lcaf ( self . rloc )
   if 58 - 58: iII111i
   if 77 - 77: IiII % oO0o % OoO0O00
  O0O0o0OooO0 = ""
  if ( self . rloc_name ) :
   O0O0o0OooO0 += struct . pack ( "H" , socket . htons ( LISP_AFI_NAME ) )
   O0O0o0OooO0 += self . rloc_name + "\0"
   if 88 - 88: i11iIiiIii - i1IIi + Oo0Ooo - O0
   if 50 - 50: I1ii11iIi11i
  IIi1iiIII11 = len ( oO00o ) + len ( IIi1II ) + len ( i1I1 ) + len ( iiIIII11i1 ) + 2 + len ( iII1I1I11 ) + self . rloc . addr_length ( ) + len ( O0O0o0OooO0 )
  if 69 - 69: I1ii11iIi11i . OoooooooOO % I1Ii111
  IIi1iiIII11 = socket . htons ( IIi1iiIII11 )
  OOo0OoO0O = struct . pack ( "HBBBBHH" , iio00OOO0o0Oo0 , 0 , 0 , LISP_LCAF_AFI_LIST_TYPE ,
 0 , IIi1iiIII11 , socket . htons ( self . rloc . afi ) )
  OOo0OoO0O += self . rloc . pack_address ( )
  return ( OOo0OoO0O + O0O0o0OooO0 + oO00o + IIi1II + i1I1 + iiIIII11i1 + iII1I1I11 )
  if 39 - 39: o0oOOo0O0Ooo % iII111i . OoOoOO00 - I1Ii111
  if 39 - 39: i11iIiiIii * OoOoOO00 . OoOoOO00 . I1ii11iIi11i . Oo0Ooo
 def encode ( self ) :
  I1i11Iii1I1I1 = 0
  if ( self . local_bit ) : I1i11Iii1I1I1 |= 0x0004
  if ( self . probe_bit ) : I1i11Iii1I1I1 |= 0x0002
  if ( self . reach_bit ) : I1i11Iii1I1I1 |= 0x0001
  if 61 - 61: I11i / OOooOOo
  I111 = struct . pack ( "BBBBHH" , self . priority , self . weight ,
 self . mpriority , self . mweight , socket . htons ( I1i11Iii1I1I1 ) ,
 socket . htons ( self . rloc . afi ) )
  if 85 - 85: OoOoOO00 - I11i . OoOoOO00 . OoOoOO00
  if ( self . geo or self . elp or self . rle or self . keys or self . rloc_name or self . json ) :
   if 62 - 62: IiII % OoooooooOO * OoO0O00 + OoO0O00 % Ii1I % iII111i
   I111 = I111 [ 0 : - 2 ] + self . encode_lcaf ( )
  else :
   I111 += self . rloc . pack_address ( )
   if 66 - 66: I1IiiI . OOooOOo - OoO0O00 % Oo0Ooo * o0oOOo0O0Ooo - oO0o
  return ( I111 )
  if 68 - 68: I11i - i11iIiiIii / o0oOOo0O0Ooo + ooOoO0o / I1IiiI
  if 31 - 31: I1Ii111 . OoooooooOO . i1IIi
 def decode_lcaf ( self , packet , nonce ) :
  o0o0 = "HBBBBH"
  O0ooO = struct . calcsize ( o0o0 )
  if ( len ( packet ) < O0ooO ) : return ( None )
  if 65 - 65: OoO0O00 . ooOoO0o
  ooo0O0O0oo0 , OOooOo , I1i11Iii1I1I1 , I11i1 , IIi1ii1i1i1 , I1iIiI1iiI = struct . unpack ( o0o0 , packet [ : O0ooO ] )
  if 12 - 12: I1Ii111 + O0 - oO0o . IiII
  if 46 - 46: IiII . ooOoO0o / iII111i
  I1iIiI1iiI = socket . ntohs ( I1iIiI1iiI )
  packet = packet [ O0ooO : : ]
  if ( I1iIiI1iiI > len ( packet ) ) : return ( None )
  if 63 - 63: II111iiii - I1ii11iIi11i * II111iiii
  if 92 - 92: OoO0O00 % ooOoO0o * O0 % iIii1I11I1II1 / i1IIi / OoOoOO00
  if 67 - 67: I1Ii111 + I11i + I1Ii111 . OOooOOo % o0oOOo0O0Ooo / ooOoO0o
  if 78 - 78: I1ii11iIi11i . O0
  if ( I11i1 == LISP_LCAF_AFI_LIST_TYPE ) :
   while ( I1iIiI1iiI > 0 ) :
    o0o0 = "H"
    O0ooO = struct . calcsize ( o0o0 )
    if ( I1iIiI1iiI < O0ooO ) : return ( None )
    if 56 - 56: oO0o - i1IIi * O0 / I11i * I1IiiI . I11i
    ooOo0 = len ( packet )
    ooo0O0O0oo0 = struct . unpack ( o0o0 , packet [ : O0ooO ] ) [ 0 ]
    ooo0O0O0oo0 = socket . ntohs ( ooo0O0O0oo0 )
    if 54 - 54: i11iIiiIii % i1IIi + Oo0Ooo / OoOoOO00
    if ( ooo0O0O0oo0 == LISP_AFI_LCAF ) :
     packet = self . decode_lcaf ( packet , nonce )
     if ( packet == None ) : return ( None )
    else :
     packet = packet [ O0ooO : : ]
     self . rloc_name = None
     if ( ooo0O0O0oo0 == LISP_AFI_NAME ) :
      packet , iIIiii = lisp_decode_dist_name ( packet )
      self . rloc_name = iIIiii
     else :
      self . rloc . afi = ooo0O0O0oo0
      packet = self . rloc . unpack_address ( packet )
      if ( packet == None ) : return ( None )
      self . rloc . mask_len = self . rloc . host_mask_len ( )
      if 26 - 26: I11i . I1ii11iIi11i
      if 55 - 55: OoOoOO00 * I1Ii111 % OoO0O00 - OoO0O00
      if 34 - 34: O0 * OoO0O00 - oO0o - IiII * Ii1I . II111iiii
    I1iIiI1iiI -= ooOo0 - len ( packet )
    if 28 - 28: O0 % iII111i - i1IIi
    if 49 - 49: ooOoO0o . I11i - iIii1I11I1II1
  elif ( I11i1 == LISP_LCAF_GEO_COORD_TYPE ) :
   if 41 - 41: ooOoO0o * i11iIiiIii % ooOoO0o . oO0o
   if 97 - 97: oO0o - iII111i + IiII . OoOoOO00 + iIii1I11I1II1
   if 75 - 75: ooOoO0o + ooOoO0o . I1Ii111 % iII111i / iIii1I11I1II1 * iII111i
   if 13 - 13: II111iiii * i11iIiiIii - i1IIi * OoO0O00 + i1IIi
   ii1IiIiIii = lisp_geo ( "" )
   packet = ii1IiIiIii . decode_geo ( packet , I1iIiI1iiI , IIi1ii1i1i1 )
   if ( packet == None ) : return ( None )
   self . geo = ii1IiIiIii
   if 17 - 17: O0 * I1IiiI
  elif ( I11i1 == LISP_LCAF_JSON_TYPE ) :
   if 40 - 40: iIii1I11I1II1 * iII111i % iIii1I11I1II1
   if 39 - 39: i1IIi . Ii1I - Oo0Ooo
   if 91 - 91: I1IiiI - OoooooooOO - OoooooooOO
   if 69 - 69: iII111i * i11iIiiIii / i1IIi
   o0o0 = "H"
   O0ooO = struct . calcsize ( o0o0 )
   if ( I1iIiI1iiI < O0ooO ) : return ( None )
   if 86 - 86: I1IiiI % I11i * O0 + i1IIi % I1Ii111
   oO000O00 = struct . unpack ( o0o0 , packet [ : O0ooO ] ) [ 0 ]
   oO000O00 = socket . ntohs ( oO000O00 )
   if ( I1iIiI1iiI < O0ooO + oO000O00 ) : return ( None )
   if 97 - 97: II111iiii * OoOoOO00 - I1Ii111 / i11iIiiIii / OoOoOO00
   packet = packet [ O0ooO : : ]
   self . json = lisp_json ( "" , packet [ 0 : oO000O00 ] )
   packet = packet [ oO000O00 : : ]
   if 25 - 25: Oo0Ooo / Oo0Ooo
  elif ( I11i1 == LISP_LCAF_ELP_TYPE ) :
   if 74 - 74: OOooOOo
   if 30 - 30: O0 . Ii1I / o0oOOo0O0Ooo + I1IiiI - O0
   if 88 - 88: i11iIiiIii
   if 33 - 33: OoO0O00 + O0
   IIi1I1iiiii = lisp_elp ( None )
   IIi1I1iiiii . elp_nodes = [ ]
   while ( I1iIiI1iiI > 0 ) :
    I1i11Iii1I1I1 , ooo0O0O0oo0 = struct . unpack ( "HH" , packet [ : 4 ] )
    if 23 - 23: oO0o + i11iIiiIii * Ii1I
    ooo0O0O0oo0 = socket . ntohs ( ooo0O0O0oo0 )
    if ( ooo0O0O0oo0 == LISP_AFI_LCAF ) : return ( None )
    if 8 - 8: OOooOOo . I1IiiI - I1IiiI
    I111I1IiI1i1 = lisp_elp_node ( )
    IIi1I1iiiii . elp_nodes . append ( I111I1IiI1i1 )
    if 34 - 34: oO0o . i11iIiiIii - IiII
    I1i11Iii1I1I1 = socket . ntohs ( I1i11Iii1I1I1 )
    I111I1IiI1i1 . eid = ( I1i11Iii1I1I1 & 0x4 )
    I111I1IiI1i1 . probe = ( I1i11Iii1I1I1 & 0x2 )
    I111I1IiI1i1 . strict = ( I1i11Iii1I1I1 & 0x1 )
    I111I1IiI1i1 . address . afi = ooo0O0O0oo0
    I111I1IiI1i1 . address . mask_len = I111I1IiI1i1 . address . host_mask_len ( )
    packet = I111I1IiI1i1 . address . unpack_address ( packet [ 4 : : ] )
    I1iIiI1iiI -= I111I1IiI1i1 . address . addr_length ( ) + 4
    if 83 - 83: iII111i / I1Ii111 . I11i / i11iIiiIii
   IIi1I1iiiii . select_elp_node ( )
   self . elp = IIi1I1iiiii
   if 4 - 4: ooOoO0o . OoO0O00
  elif ( I11i1 == LISP_LCAF_RLE_TYPE ) :
   if 34 - 34: I1Ii111 * I1IiiI . OoooooooOO % I11i
   if 10 - 10: OoO0O00 . I1IiiI . I11i / i11iIiiIii - ooOoO0o
   if 41 - 41: I11i / iIii1I11I1II1 . i11iIiiIii . i1IIi * iIii1I11I1II1 * OOooOOo
   if 5 - 5: O0 - oO0o - i11iIiiIii
   oOIii11111iiI = lisp_rle ( None )
   oOIii11111iiI . rle_nodes = [ ]
   while ( I1iIiI1iiI > 0 ) :
    Oo000 , Iiiii , i11i1i , ooo0O0O0oo0 = struct . unpack ( "HBBH" , packet [ : 6 ] )
    if 84 - 84: iIii1I11I1II1 / o0oOOo0O0Ooo / II111iiii
    ooo0O0O0oo0 = socket . ntohs ( ooo0O0O0oo0 )
    if ( ooo0O0O0oo0 == LISP_AFI_LCAF ) : return ( None )
    if 81 - 81: i11iIiiIii + o0oOOo0O0Ooo / II111iiii + I11i
    II1ii = lisp_rle_node ( )
    oOIii11111iiI . rle_nodes . append ( II1ii )
    if 73 - 73: OoO0O00 + OOooOOo + IiII - i1IIi
    II1ii . level = i11i1i
    II1ii . address . afi = ooo0O0O0oo0
    II1ii . address . mask_len = II1ii . address . host_mask_len ( )
    packet = II1ii . address . unpack_address ( packet [ 6 : : ] )
    if 67 - 67: OoooooooOO - i1IIi + Ii1I + I1IiiI
    I1iIiI1iiI -= II1ii . address . addr_length ( ) + 6
    if ( I1iIiI1iiI >= 2 ) :
     ooo0O0O0oo0 = struct . unpack ( "H" , packet [ : 2 ] ) [ 0 ]
     if ( socket . ntohs ( ooo0O0O0oo0 ) == LISP_AFI_NAME ) :
      packet = packet [ 2 : : ]
      packet , II1ii . rloc_name = lisp_decode_dist_name ( packet )
      if 18 - 18: Oo0Ooo * iII111i / II111iiii
      if ( packet == None ) : return ( None )
      I1iIiI1iiI -= len ( II1ii . rloc_name ) + 1 + 2
      if 77 - 77: Ii1I . o0oOOo0O0Ooo * oO0o
      if 42 - 42: Ii1I / Oo0Ooo
      if 25 - 25: OoooooooOO % Ii1I * I1Ii111 * I11i + I1IiiI % I1ii11iIi11i
   self . rle = oOIii11111iiI
   self . rle . build_forwarding_list ( )
   if 70 - 70: Ii1I + I1ii11iIi11i * I11i * i1IIi . I1Ii111
  elif ( I11i1 == LISP_LCAF_SECURITY_TYPE ) :
   if 76 - 76: OoooooooOO * OoOoOO00 . OoooooooOO
   if 46 - 46: ooOoO0o * o0oOOo0O0Ooo % II111iiii / I1Ii111
   if 29 - 29: OoO0O00 - i11iIiiIii % Oo0Ooo % o0oOOo0O0Ooo
   if 30 - 30: oO0o - Ii1I % Ii1I
   if 8 - 8: IiII
   Oo0OOOO = packet
   i11II = lisp_keys ( 1 )
   packet = i11II . decode_lcaf ( Oo0OOOO , I1iIiI1iiI )
   if ( packet == None ) : return ( None )
   if 68 - 68: IiII . OoooooooOO - i11iIiiIii + i11iIiiIii
   if 81 - 81: OoOoOO00 + iII111i . i11iIiiIii
   if 10 - 10: OoOoOO00 + I11i - iIii1I11I1II1 - I11i
   if 58 - 58: ooOoO0o
   Ii111OO0o0o0OOoooo = [ LISP_CS_25519_CBC , LISP_CS_25519_CHACHA ]
   if ( i11II . cipher_suite in Ii111OO0o0o0OOoooo ) :
    if ( i11II . cipher_suite == LISP_CS_25519_CBC ) :
     OOoOoO = lisp_keys ( 1 , do_poly = False , do_chacha = False )
     if 98 - 98: Ii1I / OoO0O00 % OoooooooOO
    if ( i11II . cipher_suite == LISP_CS_25519_CHACHA ) :
     OOoOoO = lisp_keys ( 1 , do_poly = True , do_chacha = True )
     if 65 - 65: ooOoO0o % Oo0Ooo - I1IiiI % I1Ii111 + iIii1I11I1II1 / iIii1I11I1II1
   else :
    OOoOoO = lisp_keys ( 1 , do_poly = False , do_chacha = False )
    if 94 - 94: IiII - Oo0Ooo . o0oOOo0O0Ooo - ooOoO0o - oO0o . I11i
   packet = OOoOoO . decode_lcaf ( Oo0OOOO , I1iIiI1iiI )
   if ( packet == None ) : return ( None )
   if 39 - 39: oO0o + OoOoOO00
   if ( len ( packet ) < 2 ) : return ( None )
   ooo0O0O0oo0 = struct . unpack ( "H" , packet [ : 2 ] ) [ 0 ]
   self . rloc . afi = socket . ntohs ( ooo0O0O0oo0 )
   if ( len ( packet ) < self . rloc . addr_length ( ) ) : return ( None )
   packet = self . rloc . unpack_address ( packet [ 2 : : ] )
   if ( packet == None ) : return ( None )
   self . rloc . mask_len = self . rloc . host_mask_len ( )
   if 68 - 68: i1IIi * oO0o / i11iIiiIii
   if 96 - 96: I1IiiI
   if 78 - 78: OoO0O00
   if 72 - 72: I1ii11iIi11i / O0 % II111iiii / II111iiii
   if 48 - 48: OOooOOo % OOooOOo / iIii1I11I1II1 - i11iIiiIii
   if 57 - 57: I11i / IiII * i1IIi + II111iiii . o0oOOo0O0Ooo
   if ( self . rloc . is_null ( ) ) : return ( packet )
   if 11 - 11: II111iiii
   O0oo0o0oO = self . rloc_name
   if ( O0oo0o0oO ) : O0oo0o0oO = blue ( self . rloc_name , False )
   if 89 - 89: OoO0O00 * i11iIiiIii - IiII * i1IIi - ooOoO0o . Ii1I
   if 26 - 26: I1IiiI * OoooooooOO / I1IiiI . O0 . ooOoO0o + O0
   if 84 - 84: I1Ii111 . O0 + O0 % O0 % i1IIi + iIii1I11I1II1
   if 71 - 71: iII111i / iIii1I11I1II1 . OOooOOo * i11iIiiIii
   if 98 - 98: O0 % iIii1I11I1II1 . IiII - II111iiii
   if 14 - 14: Ii1I % ooOoO0o - OoOoOO00
   oO0OO0o0oo0o = self . keys [ 1 ] if self . keys else None
   if ( oO0OO0o0oo0o == None ) :
    if ( OOoOoO . remote_public_key == None ) :
     iIii1I1iII = bold ( "No remote encap-public-key supplied" , False )
     lprint ( "    {} for {}" . format ( iIii1I1iII , O0oo0o0oO ) )
     OOoOoO = None
    else :
     iIii1I1iII = bold ( "New encap-keying with new state" , False )
     lprint ( "    {} for {}" . format ( iIii1I1iII , O0oo0o0oO ) )
     OOoOoO . compute_shared_key ( "encap" )
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
   if ( oO0OO0o0oo0o ) :
    if ( OOoOoO . remote_public_key == None ) :
     OOoOoO = None
     O000o0O0 = bold ( "Remote encap-unkeying occurred" , False )
     lprint ( "    {} for {}" . format ( O000o0O0 , O0oo0o0oO ) )
    elif ( oO0OO0o0oo0o . compare_keys ( OOoOoO ) ) :
     OOoOoO = oO0OO0o0oo0o
     lprint ( "    Maintain stored encap-keys for {}" . format ( O0oo0o0oO ) )
     if 9 - 9: II111iiii - i11iIiiIii * o0oOOo0O0Ooo % OoO0O00 * i11iIiiIii / I11i
    else :
     if ( oO0OO0o0oo0o . remote_public_key == None ) :
      iIii1I1iII = "New encap-keying for existing state"
     else :
      iIii1I1iII = "Remote encap-rekeying"
      if 45 - 45: i11iIiiIii * iII111i - I1ii11iIi11i + ooOoO0o % iII111i
     lprint ( "    {} for {}" . format ( bold ( iIii1I1iII , False ) ,
 O0oo0o0oO ) )
     oO0OO0o0oo0o . remote_public_key = OOoOoO . remote_public_key
     oO0OO0o0oo0o . compute_shared_key ( "encap" )
     OOoOoO = oO0OO0o0oo0o
     if 11 - 11: iIii1I11I1II1
     if 48 - 48: iIii1I11I1II1 - Oo0Ooo
   self . keys = [ None , OOoOoO , None , None ]
   if 80 - 80: i1IIi
  else :
   if 56 - 56: II111iiii - o0oOOo0O0Ooo
   if 48 - 48: Oo0Ooo - I1ii11iIi11i - II111iiii . Ii1I . oO0o / iIii1I11I1II1
   if 38 - 38: I1Ii111 % i11iIiiIii + Ii1I * ooOoO0o / I1Ii111
   if 93 - 93: oO0o
   packet = packet [ I1iIiI1iiI : : ]
   if 60 - 60: I1Ii111 . oO0o / Oo0Ooo * ooOoO0o + OoOoOO00 - i1IIi
  return ( packet )
  if 13 - 13: i11iIiiIii * oO0o / I11i * I1IiiI
  if 31 - 31: iIii1I11I1II1 * Ii1I % OOooOOo . II111iiii
 def decode ( self , packet , nonce ) :
  o0o0 = "BBBBHH"
  O0ooO = struct . calcsize ( o0o0 )
  if ( len ( packet ) < O0ooO ) : return ( None )
  if 56 - 56: IiII / i11iIiiIii . o0oOOo0O0Ooo . oO0o - i11iIiiIii
  self . priority , self . weight , self . mpriority , self . mweight , I1i11Iii1I1I1 , ooo0O0O0oo0 = struct . unpack ( o0o0 , packet [ : O0ooO ] )
  if 23 - 23: I1ii11iIi11i * i11iIiiIii % ooOoO0o
  if 47 - 47: iIii1I11I1II1 . OOooOOo / I11i % II111iiii
  I1i11Iii1I1I1 = socket . ntohs ( I1i11Iii1I1I1 )
  ooo0O0O0oo0 = socket . ntohs ( ooo0O0O0oo0 )
  self . local_bit = True if ( I1i11Iii1I1I1 & 0x0004 ) else False
  self . probe_bit = True if ( I1i11Iii1I1I1 & 0x0002 ) else False
  self . reach_bit = True if ( I1i11Iii1I1I1 & 0x0001 ) else False
  if 92 - 92: I1ii11iIi11i % i11iIiiIii
  if ( ooo0O0O0oo0 == LISP_AFI_LCAF ) :
   packet = packet [ O0ooO - 2 : : ]
   packet = self . decode_lcaf ( packet , nonce )
  else :
   self . rloc . afi = ooo0O0O0oo0
   packet = packet [ O0ooO : : ]
   packet = self . rloc . unpack_address ( packet )
   if 82 - 82: I1Ii111 * I1ii11iIi11i % Ii1I / o0oOOo0O0Ooo
  self . rloc . mask_len = self . rloc . host_mask_len ( )
  return ( packet )
  if 28 - 28: iII111i % OoO0O00 - OOooOOo - Oo0Ooo
  if 16 - 16: i11iIiiIii - i11iIiiIii . OoOoOO00 / i1IIi
 def end_of_rlocs ( self , packet , rloc_count ) :
  for oO in range ( rloc_count ) :
   packet = self . decode ( packet , None )
   if ( packet == None ) : return ( None )
   if 76 - 76: O0 * OoO0O00 / O0
  return ( packet )
  if 23 - 23: I1ii11iIi11i . iIii1I11I1II1 - i11iIiiIii / II111iiii
  if 48 - 48: oO0o - II111iiii * I1IiiI
  if 78 - 78: I1IiiI * i11iIiiIii * II111iiii
  if 19 - 19: OoooooooOO * i11iIiiIii / O0 . I1IiiI % I11i
  if 35 - 35: iIii1I11I1II1 + I1IiiI - ooOoO0o / Oo0Ooo * I1ii11iIi11i * Oo0Ooo
  if 17 - 17: OoOoOO00
  if 24 - 24: iIii1I11I1II1 / OOooOOo % OoooooooOO / O0 / oO0o
  if 93 - 93: Oo0Ooo
  if 5 - 5: iII111i
  if 61 - 61: OOooOOo * OoO0O00 - O0
  if 30 - 30: iIii1I11I1II1
  if 14 - 14: o0oOOo0O0Ooo + Ii1I
  if 91 - 91: OoooooooOO / oO0o + OoOoOO00
  if 100 - 100: i1IIi
  if 13 - 13: i1IIi . I1ii11iIi11i * o0oOOo0O0Ooo
  if 31 - 31: i11iIiiIii % OoO0O00 . i11iIiiIii % oO0o - i1IIi
  if 62 - 62: oO0o + oO0o . OoooooooOO
  if 59 - 59: iIii1I11I1II1 . Oo0Ooo * I11i
  if 29 - 29: Oo0Ooo - I1IiiI * I11i
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
  if 3 - 3: I11i
class lisp_map_referral ( ) :
 def __init__ ( self ) :
  self . record_count = 0
  self . nonce = 0
  if 46 - 46: I1ii11iIi11i * I1Ii111 - iIii1I11I1II1
  if 25 - 25: II111iiii / OOooOOo + Oo0Ooo - iIii1I11I1II1 - OoOoOO00
 def print_map_referral ( self ) :
  lprint ( "{} -> record-count: {}, nonce: 0x{}" . format ( bold ( "Map-Referral" , False ) , self . record_count ,
  # iIii1I11I1II1 % i1IIi - OoO0O00 % IiII - i1IIi + o0oOOo0O0Ooo
 lisp_hex_string ( self . nonce ) ) )
  if 5 - 5: II111iiii
  if 88 - 88: OoooooooOO % II111iiii + IiII + IiII * Oo0Ooo
 def encode ( self ) :
  I1I = ( LISP_MAP_REFERRAL << 28 ) | self . record_count
  I111 = struct . pack ( "I" , socket . htonl ( I1I ) )
  I111 += struct . pack ( "Q" , self . nonce )
  return ( I111 )
  if 81 - 81: I1IiiI * ooOoO0o + I1Ii111
  if 49 - 49: I1IiiI % oO0o % II111iiii * II111iiii + OoooooooOO + iII111i
 def decode ( self , packet ) :
  o0o0 = "I"
  O0ooO = struct . calcsize ( o0o0 )
  if ( len ( packet ) < O0ooO ) : return ( None )
  if 58 - 58: i11iIiiIii % iIii1I11I1II1 + OoO0O00 . I1ii11iIi11i . I1IiiI
  I1I = struct . unpack ( o0o0 , packet [ : O0ooO ] )
  I1I = socket . ntohl ( I1I [ 0 ] )
  self . record_count = I1I & 0xff
  packet = packet [ O0ooO : : ]
  if 54 - 54: iII111i . OoO0O00 . iIii1I11I1II1
  o0o0 = "Q"
  O0ooO = struct . calcsize ( o0o0 )
  if ( len ( packet ) < O0ooO ) : return ( None )
  if 45 - 45: I1ii11iIi11i + I1IiiI / i11iIiiIii
  self . nonce = struct . unpack ( o0o0 , packet [ : O0ooO ] ) [ 0 ]
  packet = packet [ O0ooO : : ]
  return ( packet )
  if 45 - 45: IiII / O0 * I1IiiI - OOooOOo * I1Ii111
  if 19 - 19: OoOoOO00 / IiII - OOooOOo * i11iIiiIii % I1Ii111
  if 98 - 98: IiII + IiII + OOooOOo / i1IIi + oO0o
  if 53 - 53: OoOoOO00
  if 69 - 69: iIii1I11I1II1 * OoO0O00 / OoooooooOO % I1ii11iIi11i . I1IiiI % I11i
  if 40 - 40: i11iIiiIii % oO0o / OOooOOo
  if 85 - 85: OoO0O00 % O0 . Ii1I . iII111i . iII111i
  if 90 - 90: o0oOOo0O0Ooo - Oo0Ooo / ooOoO0o / i1IIi - Ii1I
class lisp_ddt_entry ( ) :
 def __init__ ( self ) :
  self . eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . group = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . uptime = lisp_get_timestamp ( )
  self . delegation_set = [ ]
  self . source_cache = None
  self . map_referrals_sent = 0
  if 43 - 43: i11iIiiIii - OoooooooOO % ooOoO0o
  if 55 - 55: oO0o % Oo0Ooo % IiII
 def is_auth_prefix ( self ) :
  if ( len ( self . delegation_set ) != 0 ) : return ( False )
  if ( self . is_star_g ( ) ) : return ( False )
  return ( True )
  if 65 - 65: IiII * IiII
  if 60 - 60: ooOoO0o
 def is_ms_peer_entry ( self ) :
  if ( len ( self . delegation_set ) == 0 ) : return ( False )
  return ( self . delegation_set [ 0 ] . is_ms_peer ( ) )
  if 92 - 92: O0 % IiII
  if 15 - 15: O0 % i1IIi - OOooOOo . IiII
 def print_referral_type ( self ) :
  if ( len ( self . delegation_set ) == 0 ) : return ( "unknown" )
  iII1I = self . delegation_set [ 0 ]
  return ( iII1I . print_node_type ( ) )
  if 70 - 70: IiII . o0oOOo0O0Ooo / oO0o - i11iIiiIii % II111iiii
  if 7 - 7: O0 / OoO0O00
 def print_eid_tuple ( self ) :
  return ( lisp_print_eid_tuple ( self . eid , self . group ) )
  if 90 - 90: iII111i % oO0o / iIii1I11I1II1
  if 52 - 52: I1IiiI / o0oOOo0O0Ooo
 def add_cache ( self ) :
  if ( self . group . is_null ( ) ) :
   lisp_ddt_cache . add_cache ( self . eid , self )
  else :
   I1oo0Oo = lisp_ddt_cache . lookup_cache ( self . group , True )
   if ( I1oo0Oo == None ) :
    I1oo0Oo = lisp_ddt_entry ( )
    I1oo0Oo . eid . copy_address ( self . group )
    I1oo0Oo . group . copy_address ( self . group )
    lisp_ddt_cache . add_cache ( self . group , I1oo0Oo )
    if 10 - 10: IiII . OOooOOo % oO0o + oO0o % I11i / OoO0O00
   if ( self . eid . is_null ( ) ) : self . eid . make_default_route ( I1oo0Oo . group )
   I1oo0Oo . add_source_entry ( self )
   if 11 - 11: ooOoO0o + OoO0O00 - I1ii11iIi11i . iII111i
   if 39 - 39: o0oOOo0O0Ooo % OoooooooOO - O0
   if 87 - 87: I1IiiI * i1IIi * Oo0Ooo / I1ii11iIi11i - OoO0O00
 def add_source_entry ( self , source_ddt ) :
  if ( self . source_cache == None ) : self . source_cache = lisp_cache ( )
  self . source_cache . add_cache ( source_ddt . eid , source_ddt )
  if 44 - 44: Oo0Ooo
  if 37 - 37: OOooOOo / Ii1I
 def lookup_source_cache ( self , source , exact ) :
  if ( self . source_cache == None ) : return ( None )
  return ( self . source_cache . lookup_cache ( source , exact ) )
  if 51 - 51: OOooOOo + O0
  if 91 - 91: i11iIiiIii + o0oOOo0O0Ooo % OoO0O00 / oO0o - i1IIi
 def is_star_g ( self ) :
  if ( self . group . is_null ( ) ) : return ( False )
  return ( self . eid . is_exact_match ( self . group ) )
  if 82 - 82: Ii1I . OoooooooOO + OoooooooOO % OoO0O00 % I1ii11iIi11i
  if 65 - 65: Oo0Ooo . I11i
  if 7 - 7: Oo0Ooo * II111iiii
class lisp_ddt_node ( ) :
 def __init__ ( self ) :
  self . delegate_address = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . public_key = ""
  self . map_server_peer = False
  self . map_server_child = False
  self . priority = 0
  self . weight = 0
  if 11 - 11: OoOoOO00 % OoooooooOO
  if 92 - 92: OoOoOO00 - iII111i * Ii1I - i1IIi
 def print_node_type ( self ) :
  if ( self . is_ddt_child ( ) ) : return ( "ddt-child" )
  if ( self . is_ms_child ( ) ) : return ( "map-server-child" )
  if ( self . is_ms_peer ( ) ) : return ( "map-server-peer" )
  if 87 - 87: Ii1I * I1Ii111 + iIii1I11I1II1 * o0oOOo0O0Ooo * iIii1I11I1II1 . I11i
  if 66 - 66: Ii1I / OoO0O00 . O0 . I11i % OoooooooOO / OOooOOo
 def is_ddt_child ( self ) :
  if ( self . map_server_child ) : return ( False )
  if ( self . map_server_peer ) : return ( False )
  return ( True )
  if 49 - 49: I1IiiI * iII111i - OoO0O00 % Ii1I + Ii1I * I1Ii111
  if 94 - 94: OoOoOO00 - I11i + Ii1I + OoOoOO00 + II111iiii
 def is_ms_child ( self ) :
  return ( self . map_server_child )
  if 61 - 61: IiII + Ii1I / oO0o . OoooooooOO + iII111i
  if 29 - 29: OOooOOo
 def is_ms_peer ( self ) :
  return ( self . map_server_peer )
  if 69 - 69: oO0o % OoooooooOO * iII111i
  if 58 - 58: oO0o / i11iIiiIii . OoOoOO00 % O0 / iIii1I11I1II1
  if 50 - 50: I1Ii111 . I11i / O0 . I11i
  if 91 - 91: i11iIiiIii . I1ii11iIi11i + I11i
  if 67 - 67: I1ii11iIi11i * I1Ii111 * I1IiiI / I11i - IiII + oO0o
  if 11 - 11: O0 + i1IIi / o0oOOo0O0Ooo * OoO0O00
  if 64 - 64: i1IIi % IiII . ooOoO0o . iIii1I11I1II1 + OoO0O00 - iIii1I11I1II1
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
  if 52 - 52: II111iiii - IiII
  if 91 - 91: iIii1I11I1II1 + iII111i . I11i % i11iIiiIii - i11iIiiIii + I1IiiI
 def print_ddt_map_request ( self ) :
  lprint ( "Queued Map-Request from {}ITR {}->{}, nonce 0x{}" . format ( "P" if self . from_pitr else "" ,
  # I1IiiI % I1ii11iIi11i - i1IIi + IiII . OoO0O00
 red ( self . itr . print_address ( ) , False ) ,
 green ( self . eid . print_address ( ) , False ) , self . nonce ) )
  if 66 - 66: OOooOOo * i1IIi / iII111i * Oo0Ooo * I11i
  if 84 - 84: I1Ii111 . O0
 def queue_map_request ( self ) :
  self . retransmit_timer = threading . Timer ( LISP_DDT_MAP_REQUEST_INTERVAL ,
 lisp_retransmit_ddt_map_request , [ self ] )
  self . retransmit_timer . start ( )
  lisp_ddt_map_requestQ [ str ( self . nonce ) ] = self
  if 4 - 4: iII111i
  if 59 - 59: OoO0O00
 def dequeue_map_request ( self ) :
  self . retransmit_timer . cancel ( )
  if ( lisp_ddt_map_requestQ . has_key ( str ( self . nonce ) ) ) :
   lisp_ddt_map_requestQ . pop ( str ( self . nonce ) )
   if 12 - 12: I1Ii111
   if 86 - 86: o0oOOo0O0Ooo . i1IIi * II111iiii % I1IiiI
   if 89 - 89: OOooOOo / i1IIi - I11i * oO0o
 def print_eid_tuple ( self ) :
  return ( lisp_print_eid_tuple ( self . eid , self . group ) )
  if 42 - 42: Ii1I
  if 40 - 40: o0oOOo0O0Ooo - iIii1I11I1II1 % oO0o . o0oOOo0O0Ooo
  if 35 - 35: I1IiiI % OOooOOo + OoOoOO00 / I1IiiI . O0 % iII111i
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
LISP_DDT_ACTION_SITE_NOT_FOUND = - 2
LISP_DDT_ACTION_NULL = - 1
LISP_DDT_ACTION_NODE_REFERRAL = 0
LISP_DDT_ACTION_MS_REFERRAL = 1
LISP_DDT_ACTION_MS_ACK = 2
LISP_DDT_ACTION_MS_NOT_REG = 3
LISP_DDT_ACTION_DELEGATION_HOLE = 4
LISP_DDT_ACTION_NOT_AUTH = 5
LISP_DDT_ACTION_MAX = LISP_DDT_ACTION_NOT_AUTH
if 35 - 35: IiII . i1IIi + I1ii11iIi11i . IiII + ooOoO0o . oO0o
lisp_map_referral_action_string = [
 "node-referral" , "ms-referral" , "ms-ack" , "ms-not-registered" ,
 "delegation-hole" , "not-authoritative" ]
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
if 26 - 26: Ii1I * oO0o % I1IiiI - OOooOOo . I1Ii111
if 35 - 35: i1IIi % i11iIiiIii + Ii1I
if 14 - 14: OoO0O00 * OoooooooOO
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
if 30 - 30: I11i
if 15 - 15: O0 - i1IIi . iIii1I11I1II1 - i11iIiiIii / Ii1I
if 11 - 11: iIii1I11I1II1 + I1IiiI
if 15 - 15: o0oOOo0O0Ooo
if 55 - 55: i11iIiiIii / OoooooooOO - I11i
if 89 - 89: I11i - i1IIi - i1IIi * OOooOOo - O0
if 94 - 94: Oo0Ooo / I11i . I1ii11iIi11i
if 31 - 31: i11iIiiIii + iIii1I11I1II1 . II111iiii
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
  if 72 - 72: I1Ii111 * OoO0O00 + Oo0Ooo / Ii1I % OOooOOo
  if 84 - 84: OoOoOO00 / o0oOOo0O0Ooo
 def print_info ( self ) :
  if ( self . info_reply ) :
   i1I1iiIIiII = "Info-Reply"
   II1iIiIiIIi = ( ", ms-port: {}, etr-port: {}, global-rloc: {}, " + "ms-rloc: {}, private-rloc: {}, RTR-list: " ) . format ( self . ms_port , self . etr_port ,
   # OoOoOO00 - i1IIi + OOooOOo + Ii1I . o0oOOo0O0Ooo
   # OoO0O00 . OoO0O00 - iIii1I11I1II1
 red ( self . global_etr_rloc . print_address_no_iid ( ) , False ) ,
 red ( self . global_ms_rloc . print_address_no_iid ( ) , False ) ,
 red ( self . private_etr_rloc . print_address_no_iid ( ) , False ) )
   if ( len ( self . rtr_list ) == 0 ) : II1iIiIiIIi += "empty, "
   for IIiiIiiI1Ii1i in self . rtr_list :
    II1iIiIiIIi += red ( IIiiIiiI1Ii1i . print_address_no_iid ( ) , False ) + ", "
    if 14 - 14: Ii1I * Oo0Ooo / II111iiii . Oo0Ooo + OoOoOO00
   II1iIiIiIIi = II1iIiIiIIi [ 0 : - 2 ]
  else :
   i1I1iiIIiII = "Info-Request"
   i1iI1 = "<none>" if self . hostname == None else self . hostname
   II1iIiIiIIi = ", hostname: {}" . format ( blue ( i1iI1 , False ) )
   if 69 - 69: Oo0Ooo % II111iiii
  lprint ( "{} -> nonce: 0x{}{}" . format ( bold ( i1I1iiIIiII , False ) ,
 lisp_hex_string ( self . nonce ) , II1iIiIiIIi ) )
  if 23 - 23: I11i * I1Ii111 / i11iIiiIii / II111iiii
  if 32 - 32: I1ii11iIi11i - I1Ii111 * I1ii11iIi11i / Ii1I
 def encode ( self ) :
  I1I = ( LISP_NAT_INFO << 28 )
  if ( self . info_reply ) : I1I |= ( 1 << 27 )
  if 24 - 24: o0oOOo0O0Ooo
  if 49 - 49: OoO0O00 - iII111i / I1ii11iIi11i % OoooooooOO
  if 96 - 96: I1Ii111 % oO0o . O0 + i1IIi / O0
  if 91 - 91: I11i
  if 69 - 69: OoOoOO00 . OoooooooOO . o0oOOo0O0Ooo + i11iIiiIii
  I111 = struct . pack ( "I" , socket . htonl ( I1I ) )
  I111 += struct . pack ( "Q" , self . nonce )
  I111 += struct . pack ( "III" , 0 , 0 , 0 )
  if 54 - 54: ooOoO0o - O0 + iII111i
  if 34 - 34: Ii1I - OOooOOo % iII111i
  if 48 - 48: oO0o - O0
  if 17 - 17: iIii1I11I1II1 . IiII / ooOoO0o % I11i + o0oOOo0O0Ooo - iIii1I11I1II1
  if ( self . info_reply == False ) :
   if ( self . hostname == None ) :
    I111 += struct . pack ( "H" , 0 )
   else :
    I111 += struct . pack ( "H" , socket . htons ( LISP_AFI_NAME ) )
    I111 += self . hostname + "\0"
    if 95 - 95: OoOoOO00 + OOooOOo - I11i * i1IIi + i1IIi * O0
   return ( I111 )
   if 60 - 60: Oo0Ooo + I11i % iIii1I11I1II1 % oO0o - I1Ii111 / o0oOOo0O0Ooo
   if 9 - 9: IiII / oO0o % O0 * I1Ii111 - iIii1I11I1II1 % i1IIi
   if 83 - 83: OoOoOO00 + OOooOOo / OoooooooOO
   if 39 - 39: OoO0O00 % iII111i . oO0o . II111iiii - i11iIiiIii
   if 85 - 85: O0 - OoOoOO00
  ooo0O0O0oo0 = socket . htons ( LISP_AFI_LCAF )
  I11i1 = LISP_LCAF_NAT_TYPE
  I1iIiI1iiI = socket . htons ( 16 )
  iIii1 = socket . htons ( self . ms_port )
  OOO0 = socket . htons ( self . etr_port )
  I111 += struct . pack ( "HHBBHHHH" , ooo0O0O0oo0 , 0 , I11i1 , 0 , I1iIiI1iiI ,
 iIii1 , OOO0 , socket . htons ( self . global_etr_rloc . afi ) )
  I111 += self . global_etr_rloc . pack_address ( )
  I111 += struct . pack ( "HH" , 0 , socket . htons ( self . private_etr_rloc . afi ) )
  I111 += self . private_etr_rloc . pack_address ( )
  if ( len ( self . rtr_list ) == 0 ) : I111 += struct . pack ( "H" , 0 )
  if 13 - 13: I11i / OoooooooOO - I1Ii111
  if 78 - 78: iII111i . oO0o . I1IiiI % O0 * ooOoO0o % I1Ii111
  if 26 - 26: OoooooooOO + iII111i * ooOoO0o
  if 71 - 71: OOooOOo . I1ii11iIi11i + II111iiii
  for IIiiIiiI1Ii1i in self . rtr_list :
   I111 += struct . pack ( "H" , socket . htons ( IIiiIiiI1Ii1i . afi ) )
   I111 += IIiiIiiI1Ii1i . pack_address ( )
   if 26 - 26: I1ii11iIi11i % O0 / Ii1I + i11iIiiIii - Ii1I
  return ( I111 )
  if 48 - 48: I1IiiI - i11iIiiIii * I1ii11iIi11i
  if 70 - 70: I1ii11iIi11i * OoOoOO00
 def decode ( self , packet ) :
  Oo0OOOO = packet
  o0o0 = "I"
  O0ooO = struct . calcsize ( o0o0 )
  if ( len ( packet ) < O0ooO ) : return ( None )
  if 63 - 63: ooOoO0o . IiII - OoOoOO00 % IiII - I1Ii111 / I1Ii111
  I1I = struct . unpack ( o0o0 , packet [ : O0ooO ] )
  I1I = I1I [ 0 ]
  packet = packet [ O0ooO : : ]
  if 42 - 42: i1IIi . OoOoOO00 * OoOoOO00 * OoOoOO00
  o0o0 = "Q"
  O0ooO = struct . calcsize ( o0o0 )
  if ( len ( packet ) < O0ooO ) : return ( None )
  if 14 - 14: II111iiii / I1Ii111 . I1IiiI
  oO00o0oOoo = struct . unpack ( o0o0 , packet [ : O0ooO ] )
  if 66 - 66: I1Ii111 % oO0o . iII111i * i1IIi
  I1I = socket . ntohl ( I1I )
  self . nonce = oO00o0oOoo [ 0 ]
  self . info_reply = I1I & 0x08000000
  self . hostname = None
  packet = packet [ O0ooO : : ]
  if 81 - 81: OoooooooOO * I1IiiI / I1Ii111
  if 10 - 10: I1IiiI - II111iiii / IiII * II111iiii
  if 67 - 67: II111iiii . Ii1I % oO0o . Oo0Ooo + IiII
  if 10 - 10: OOooOOo - OoO0O00 * oO0o / iIii1I11I1II1 - OoOoOO00
  if 20 - 20: IiII % I1IiiI + iIii1I11I1II1 % iII111i
  o0o0 = "HH"
  O0ooO = struct . calcsize ( o0o0 )
  if ( len ( packet ) < O0ooO ) : return ( None )
  if 100 - 100: o0oOOo0O0Ooo - Oo0Ooo % I1Ii111 . i11iIiiIii % OoooooooOO
  if 39 - 39: I1ii11iIi11i / i11iIiiIii * i1IIi * Oo0Ooo
  if 39 - 39: OoO0O00 * OoooooooOO / i1IIi + Oo0Ooo
  if 57 - 57: O0
  if 83 - 83: OOooOOo / Ii1I * I1IiiI % oO0o / iIii1I11I1II1
  iIIi1 , iIII1II11iII = struct . unpack ( o0o0 , packet [ : O0ooO ] )
  if ( iIII1II11iII != 0 ) : return ( None )
  if 1 - 1: I11i / OoooooooOO / iII111i
  packet = packet [ O0ooO : : ]
  o0o0 = "IBBH"
  O0ooO = struct . calcsize ( o0o0 )
  if ( len ( packet ) < O0ooO ) : return ( None )
  if 68 - 68: i1IIi / Oo0Ooo / I11i * Oo0Ooo
  I1i11iiIiIi , iii1II11II1 , oOOoOO , oooO0 = struct . unpack ( o0o0 ,
 packet [ : O0ooO ] )
  if 58 - 58: IiII * I1Ii111 - iII111i
  if ( oooO0 != 0 ) : return ( None )
  packet = packet [ O0ooO : : ]
  if 99 - 99: I1Ii111 * IiII * OoO0O00 / I1Ii111
  if 88 - 88: I1IiiI / IiII . OoO0O00
  if 5 - 5: o0oOOo0O0Ooo % Ii1I . Ii1I
  if 35 - 35: o0oOOo0O0Ooo
  if ( self . info_reply == False ) :
   o0o0 = "H"
   O0ooO = struct . calcsize ( o0o0 )
   if ( len ( packet ) >= O0ooO ) :
    ooo0O0O0oo0 = struct . unpack ( o0o0 , packet [ : O0ooO ] ) [ 0 ]
    if ( socket . ntohs ( ooo0O0O0oo0 ) == LISP_AFI_NAME ) :
     packet = packet [ O0ooO : : ]
     packet , self . hostname = lisp_decode_dist_name ( packet )
     if 46 - 46: I11i * OoO0O00 - ooOoO0o + I1ii11iIi11i + II111iiii - i11iIiiIii
     if 71 - 71: oO0o * IiII * OoO0O00
   return ( Oo0OOOO )
   if 6 - 6: I1Ii111 - ooOoO0o . o0oOOo0O0Ooo / ooOoO0o % OoO0O00 * I1IiiI
   if 49 - 49: I1IiiI + O0 - I11i
   if 43 - 43: O0
   if 50 - 50: I11i - OoooooooOO
   if 29 - 29: oO0o * oO0o
  o0o0 = "HHBBHHH"
  O0ooO = struct . calcsize ( o0o0 )
  if ( len ( packet ) < O0ooO ) : return ( None )
  if 44 - 44: ooOoO0o . I1IiiI * oO0o * Ii1I
  ooo0O0O0oo0 , Oo000 , I11i1 , iii1II11II1 , I1iIiI1iiI , iIii1 , OOO0 = struct . unpack ( o0o0 , packet [ : O0ooO ] )
  if 41 - 41: i1IIi % i11iIiiIii + I11i % OoooooooOO / I1ii11iIi11i
  if 8 - 8: OoooooooOO - OoO0O00 / i11iIiiIii / O0 . IiII
  if ( socket . ntohs ( ooo0O0O0oo0 ) != LISP_AFI_LCAF ) : return ( None )
  if 86 - 86: ooOoO0o * OoooooooOO + iII111i + o0oOOo0O0Ooo
  self . ms_port = socket . ntohs ( iIii1 )
  self . etr_port = socket . ntohs ( OOO0 )
  packet = packet [ O0ooO : : ]
  if 79 - 79: i1IIi % I1ii11iIi11i - OoO0O00 % I1ii11iIi11i
  if 6 - 6: Oo0Ooo / iII111i . i11iIiiIii
  if 8 - 8: I1ii11iIi11i + O0 - oO0o % II111iiii . I1Ii111
  if 86 - 86: IiII
  o0o0 = "H"
  O0ooO = struct . calcsize ( o0o0 )
  if ( len ( packet ) < O0ooO ) : return ( None )
  if 71 - 71: Ii1I - i1IIi . I1IiiI
  if 15 - 15: i1IIi % II111iiii / II111iiii - I1ii11iIi11i - I11i % i1IIi
  if 54 - 54: i1IIi . OoO0O00 + iII111i + OoO0O00 * i1IIi
  if 13 - 13: Oo0Ooo / OoO0O00 + OOooOOo
  ooo0O0O0oo0 = struct . unpack ( o0o0 , packet [ : O0ooO ] ) [ 0 ]
  packet = packet [ O0ooO : : ]
  if ( ooo0O0O0oo0 != 0 ) :
   self . global_etr_rloc . afi = socket . ntohs ( ooo0O0O0oo0 )
   packet = self . global_etr_rloc . unpack_address ( packet )
   if ( packet == None ) : return ( None )
   self . global_etr_rloc . mask_len = self . global_etr_rloc . host_mask_len ( )
   if 90 - 90: OoO0O00 * i11iIiiIii / oO0o
   if 91 - 91: iII111i - OoOoOO00 / Oo0Ooo % II111iiii / II111iiii / o0oOOo0O0Ooo
   if 34 - 34: OoO0O00 * II111iiii + i11iIiiIii % Ii1I
   if 25 - 25: OoOoOO00 + IiII . i11iIiiIii
   if 87 - 87: I1IiiI + OoooooooOO + O0
   if 32 - 32: Ii1I / I1ii11iIi11i . Ii1I
  if ( len ( packet ) < O0ooO ) : return ( Oo0OOOO )
  if 65 - 65: IiII
  ooo0O0O0oo0 = struct . unpack ( o0o0 , packet [ : O0ooO ] ) [ 0 ]
  packet = packet [ O0ooO : : ]
  if ( ooo0O0O0oo0 != 0 ) :
   self . global_ms_rloc . afi = socket . ntohs ( ooo0O0O0oo0 )
   packet = self . global_ms_rloc . unpack_address ( packet )
   if ( packet == None ) : return ( Oo0OOOO )
   self . global_ms_rloc . mask_len = self . global_ms_rloc . host_mask_len ( )
   if 74 - 74: Oo0Ooo + i1IIi - II111iiii / ooOoO0o / iII111i
   if 66 - 66: ooOoO0o / IiII * iIii1I11I1II1
   if 42 - 42: I1Ii111 - i11iIiiIii % II111iiii * ooOoO0o . O0 % I11i
   if 82 - 82: Oo0Ooo % O0 + I1ii11iIi11i % I1ii11iIi11i
   if 74 - 74: O0 * IiII . I11i - I1Ii111 + O0 + I11i
  if ( len ( packet ) < O0ooO ) : return ( Oo0OOOO )
  if 48 - 48: oO0o . o0oOOo0O0Ooo - OOooOOo
  ooo0O0O0oo0 = struct . unpack ( o0o0 , packet [ : O0ooO ] ) [ 0 ]
  packet = packet [ O0ooO : : ]
  if ( ooo0O0O0oo0 != 0 ) :
   self . private_etr_rloc . afi = socket . ntohs ( ooo0O0O0oo0 )
   packet = self . private_etr_rloc . unpack_address ( packet )
   if ( packet == None ) : return ( Oo0OOOO )
   self . private_etr_rloc . mask_len = self . private_etr_rloc . host_mask_len ( )
   if 29 - 29: Oo0Ooo - Ii1I - Oo0Ooo
   if 89 - 89: Oo0Ooo . OoO0O00 . I1ii11iIi11i * oO0o . O0
   if 72 - 72: i11iIiiIii % I11i / I1Ii111 + I1IiiI * iII111i
   if 69 - 69: I1Ii111 + O0 . IiII . o0oOOo0O0Ooo
   if 38 - 38: IiII / i1IIi
   if 60 - 60: OoOoOO00
  while ( len ( packet ) >= O0ooO ) :
   ooo0O0O0oo0 = struct . unpack ( o0o0 , packet [ : O0ooO ] ) [ 0 ]
   packet = packet [ O0ooO : : ]
   if ( ooo0O0O0oo0 == 0 ) : continue
   IIiiIiiI1Ii1i = lisp_address ( socket . ntohs ( ooo0O0O0oo0 ) , "" , 0 , 0 )
   packet = IIiiIiiI1Ii1i . unpack_address ( packet )
   if ( packet == None ) : return ( Oo0OOOO )
   IIiiIiiI1Ii1i . mask_len = IIiiIiiI1Ii1i . host_mask_len ( )
   self . rtr_list . append ( IIiiIiiI1Ii1i )
   if 75 - 75: II111iiii / iIii1I11I1II1 / OoooooooOO
  return ( Oo0OOOO )
  if 61 - 61: IiII . IiII
  if 17 - 17: OoOoOO00 % Oo0Ooo / I1Ii111 . Ii1I % OoO0O00
  if 32 - 32: I1IiiI + ooOoO0o / O0 * i11iIiiIii % Oo0Ooo + II111iiii
class lisp_nat_info ( ) :
 def __init__ ( self , addr_str , hostname , port ) :
  self . address = addr_str
  self . hostname = hostname
  self . port = port
  self . uptime = lisp_get_timestamp ( )
  if 95 - 95: iII111i / ooOoO0o + I1Ii111
  if 78 - 78: iIii1I11I1II1 / I1IiiI - IiII
 def timed_out ( self ) :
  ooooOoO0O = time . time ( ) - self . uptime
  return ( ooooOoO0O >= ( LISP_INFO_INTERVAL * 2 ) )
  if 81 - 81: I1ii11iIi11i
  if 31 - 31: O0 % ooOoO0o / I1IiiI * iII111i % iIii1I11I1II1 * OoOoOO00
  if 76 - 76: I1Ii111 - O0
class lisp_info_source ( ) :
 def __init__ ( self , hostname , addr_str , port ) :
  self . address = lisp_address ( LISP_AFI_IPV4 , addr_str , 32 , 0 )
  self . port = port
  self . uptime = lisp_get_timestamp ( )
  self . nonce = None
  self . hostname = hostname
  self . no_timeout = False
  if 23 - 23: O0 * Ii1I * ooOoO0o % ooOoO0o
  if 7 - 7: II111iiii + I11i
 def cache_address_for_info_source ( self ) :
  OOoOoO = self . address . print_address_no_iid ( ) + self . hostname
  lisp_info_sources_by_address [ OOoOoO ] = self
  if 99 - 99: iIii1I11I1II1 * oO0o
  if 37 - 37: ooOoO0o * iII111i * I11i
 def cache_nonce_for_info_source ( self , nonce ) :
  self . nonce = nonce
  lisp_info_sources_by_nonce [ nonce ] = self
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
def lisp_concat_auth_data ( alg_id , auth1 , auth2 , auth3 , auth4 ) :
 if 64 - 64: I11i % i11iIiiIii % I1ii11iIi11i
 if ( lisp_is_x86 ( ) ) :
  if ( auth1 != "" ) : auth1 = byte_swap_64 ( auth1 )
  if ( auth2 != "" ) : auth2 = byte_swap_64 ( auth2 )
  if ( auth3 != "" ) :
   if ( alg_id == LISP_SHA_1_96_ALG_ID ) : auth3 = socket . ntohl ( auth3 )
   else : auth3 = byte_swap_64 ( auth3 )
   if 14 - 14: I1Ii111 - OoOoOO00 - I1ii11iIi11i % I11i + OoooooooOO
  if ( auth4 != "" ) : auth4 = byte_swap_64 ( auth4 )
  if 4 - 4: I1Ii111 - I1IiiI / iIii1I11I1II1 + I1ii11iIi11i % iIii1I11I1II1 * I1IiiI
  if 30 - 30: i11iIiiIii % OOooOOo
 if ( alg_id == LISP_SHA_1_96_ALG_ID ) :
  auth1 = lisp_hex_string ( auth1 )
  auth1 = auth1 . zfill ( 16 )
  auth2 = lisp_hex_string ( auth2 )
  auth2 = auth2 . zfill ( 16 )
  auth3 = lisp_hex_string ( auth3 )
  auth3 = auth3 . zfill ( 8 )
  iIIi = auth1 + auth2 + auth3
  if 52 - 52: I11i - oO0o . i11iIiiIii - II111iiii + Ii1I . iII111i
 if ( alg_id == LISP_SHA_256_128_ALG_ID ) :
  auth1 = lisp_hex_string ( auth1 )
  auth1 = auth1 . zfill ( 16 )
  auth2 = lisp_hex_string ( auth2 )
  auth2 = auth2 . zfill ( 16 )
  auth3 = lisp_hex_string ( auth3 )
  auth3 = auth3 . zfill ( 16 )
  auth4 = lisp_hex_string ( auth4 )
  auth4 = auth4 . zfill ( 16 )
  iIIi = auth1 + auth2 + auth3 + auth4
  if 27 - 27: I1IiiI + OoOoOO00 + iII111i
 return ( iIIi )
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
def lisp_open_listen_socket ( local_addr , port ) :
 if ( port . isdigit ( ) ) :
  if ( local_addr . find ( "." ) != - 1 ) :
   Oo0000ooooOO = socket . socket ( socket . AF_INET , socket . SOCK_DGRAM )
   if 35 - 35: I1Ii111 / I1Ii111 + o0oOOo0O0Ooo - oO0o
  if ( local_addr . find ( ":" ) != - 1 ) :
   if ( lisp_is_raspbian ( ) ) : return ( None )
   Oo0000ooooOO = socket . socket ( socket . AF_INET6 , socket . SOCK_DGRAM )
   if 40 - 40: OoOoOO00 - II111iiii
  Oo0000ooooOO . bind ( ( local_addr , int ( port ) ) )
 else :
  IiiIi1II = port
  if ( os . path . exists ( IiiIi1II ) ) :
   os . system ( "rm " + IiiIi1II )
   time . sleep ( 1 )
   if 29 - 29: I1IiiI - O0
  Oo0000ooooOO = socket . socket ( socket . AF_UNIX , socket . SOCK_DGRAM )
  Oo0000ooooOO . bind ( IiiIi1II )
  if 36 - 36: I1IiiI * I1IiiI
 return ( Oo0000ooooOO )
 if 79 - 79: I1Ii111 - I11i
 if 49 - 49: II111iiii + O0 * ooOoO0o - Oo0Ooo
 if 89 - 89: I1IiiI + I11i . oO0o . II111iiii + oO0o / Oo0Ooo
 if 32 - 32: OoO0O00 % oO0o * I1ii11iIi11i + I11i / I1Ii111
 if 5 - 5: o0oOOo0O0Ooo + iII111i / OoooooooOO + Ii1I . OoOoOO00 / oO0o
 if 18 - 18: II111iiii . o0oOOo0O0Ooo
 if 75 - 75: OoooooooOO - Oo0Ooo
def lisp_open_send_socket ( internal_name , afi ) :
 if ( internal_name == "" ) :
  if ( afi == LISP_AFI_IPV4 ) :
   Oo0000ooooOO = socket . socket ( socket . AF_INET , socket . SOCK_DGRAM )
   if 56 - 56: II111iiii - i11iIiiIii - oO0o . o0oOOo0O0Ooo
  if ( afi == LISP_AFI_IPV6 ) :
   if ( lisp_is_raspbian ( ) ) : return ( None )
   Oo0000ooooOO = socket . socket ( socket . AF_INET6 , socket . SOCK_DGRAM )
   if 4 - 4: i1IIi
 else :
  if ( os . path . exists ( internal_name ) ) : os . system ( "rm " + internal_name )
  Oo0000ooooOO = socket . socket ( socket . AF_UNIX , socket . SOCK_DGRAM )
  Oo0000ooooOO . bind ( internal_name )
  if 91 - 91: IiII . OoO0O00 * Ii1I / o0oOOo0O0Ooo
 return ( Oo0000ooooOO )
 if 41 - 41: I1IiiI . OoO0O00 / i1IIi . Oo0Ooo . oO0o
 if 44 - 44: iII111i * I11i + i11iIiiIii + i1IIi / IiII * II111iiii
 if 58 - 58: OOooOOo
 if 72 - 72: OoO0O00 + OOooOOo - Oo0Ooo % ooOoO0o . IiII
 if 95 - 95: iII111i % OOooOOo - IiII - OoOoOO00 % o0oOOo0O0Ooo * O0
 if 16 - 16: I1Ii111 / Oo0Ooo
 if 48 - 48: Oo0Ooo / oO0o + iII111i % iII111i
def lisp_close_socket ( sock , internal_name ) :
 sock . close ( )
 if ( os . path . exists ( internal_name ) ) : os . system ( "rm " + internal_name )
 return
 if 9 - 9: I1ii11iIi11i - o0oOOo0O0Ooo . Oo0Ooo + I1ii11iIi11i . OOooOOo
 if 30 - 30: OoooooooOO - iIii1I11I1II1 / oO0o * Ii1I / Ii1I
 if 52 - 52: OoOoOO00 - OoO0O00 + I1IiiI + IiII
 if 49 - 49: oO0o / I11i - oO0o
 if 31 - 31: OoOoOO00 + I1IiiI + I1ii11iIi11i + I11i * II111iiii % oO0o
 if 90 - 90: OOooOOo * iIii1I11I1II1 / i1IIi
 if 60 - 60: OOooOOo * I1Ii111 . oO0o
 if 47 - 47: oO0o % OOooOOo / OOooOOo % OoOoOO00 % I1Ii111 / OoOoOO00
def lisp_is_running ( node ) :
 return ( True if ( os . path . exists ( node ) ) else False )
 if 51 - 51: I1IiiI . I11i - OoOoOO00
 if 10 - 10: Oo0Ooo * OOooOOo / IiII . o0oOOo0O0Ooo
 if 97 - 97: Ii1I . Ii1I % iII111i
 if 49 - 49: Oo0Ooo % OOooOOo - OoooooooOO + IiII
 if 54 - 54: iIii1I11I1II1 - OoooooooOO / I11i / oO0o % I1IiiI + OoOoOO00
 if 26 - 26: OoO0O00 * II111iiii % OOooOOo * iII111i + iII111i
 if 25 - 25: I11i - I1ii11iIi11i
 if 100 - 100: I1Ii111 / Ii1I + OoOoOO00 . OoooooooOO
 if 83 - 83: O0
def lisp_packet_ipc ( packet , source , sport ) :
 return ( ( "packet@" + str ( len ( packet ) ) + "@" + source + "@" + str ( sport ) + "@" + packet ) )
 if 35 - 35: i11iIiiIii - I11i . OoOoOO00 * II111iiii % i11iIiiIii
 if 55 - 55: o0oOOo0O0Ooo / O0 / OoooooooOO * Oo0Ooo % iII111i
 if 24 - 24: I1ii11iIi11i % OOooOOo + OoooooooOO + OoO0O00
 if 100 - 100: Oo0Ooo % OoO0O00 - OoOoOO00
 if 46 - 46: o0oOOo0O0Ooo
 if 28 - 28: i1IIi
 if 81 - 81: oO0o % OoooooooOO . I1Ii111 - OoOoOO00 / I1IiiI
 if 62 - 62: I1Ii111 * I11i / I11i
 if 42 - 42: ooOoO0o * ooOoO0o / Ii1I / OOooOOo * OOooOOo
def lisp_control_packet_ipc ( packet , source , dest , dport ) :
 return ( "control-packet@" + dest + "@" + str ( dport ) + "@" + packet )
 if 92 - 92: Oo0Ooo / iII111i - OoooooooOO - o0oOOo0O0Ooo % ooOoO0o
 if 35 - 35: i1IIi % iII111i % I11i * iIii1I11I1II1 % Ii1I - Oo0Ooo
 if 94 - 94: iII111i
 if 68 - 68: OoooooooOO % OOooOOo / OoooooooOO / I1Ii111 + Ii1I - o0oOOo0O0Ooo
 if 81 - 81: I1IiiI
 if 62 - 62: Ii1I * OoOoOO00
 if 27 - 27: Oo0Ooo + Oo0Ooo / II111iiii % I1Ii111
def lisp_data_packet_ipc ( packet , source ) :
 return ( "data-packet@" + str ( len ( packet ) ) + "@" + source + "@@" + packet )
 if 11 - 11: Ii1I
 if 54 - 54: I1IiiI * I1Ii111 / ooOoO0o / iIii1I11I1II1 % iII111i / oO0o
 if 11 - 11: ooOoO0o + I1IiiI + Ii1I . II111iiii
 if 50 - 50: Oo0Ooo
 if 14 - 14: O0
 if 67 - 67: II111iiii / O0
 if 10 - 10: i1IIi / Oo0Ooo
 if 20 - 20: Oo0Ooo * I1Ii111 / I1ii11iIi11i . ooOoO0o
 if 67 - 67: o0oOOo0O0Ooo . Oo0Ooo % I11i
def lisp_command_ipc ( packet , source ) :
 return ( "command@" + str ( len ( packet ) ) + "@" + source + "@@" + packet )
 if 38 - 38: OOooOOo - OoO0O00 . ooOoO0o
 if 50 - 50: o0oOOo0O0Ooo
 if 85 - 85: II111iiii . iII111i - i1IIi
 if 23 - 23: iII111i . Ii1I - OoO0O00 / I1ii11iIi11i / O0
 if 4 - 4: i1IIi % Oo0Ooo % Ii1I * ooOoO0o - I11i
 if 76 - 76: iIii1I11I1II1 / ooOoO0o % I1ii11iIi11i % OOooOOo
 if 13 - 13: IiII
 if 56 - 56: Oo0Ooo
 if 55 - 55: i11iIiiIii + iIii1I11I1II1 / i1IIi / I1ii11iIi11i
def lisp_api_ipc ( source , data ) :
 return ( "api@" + str ( len ( data ) ) + "@" + source + "@@" + data )
 if 64 - 64: IiII . OoO0O00 * i11iIiiIii
 if 18 - 18: Ii1I % o0oOOo0O0Ooo - Oo0Ooo
 if 28 - 28: IiII
 if 93 - 93: Oo0Ooo % i1IIi
 if 51 - 51: oO0o % O0
 if 41 - 41: I1IiiI * I1IiiI . I1Ii111
 if 38 - 38: I1IiiI % i11iIiiIii
 if 17 - 17: i11iIiiIii
 if 81 - 81: I1Ii111
def lisp_ipc ( packet , send_socket , node ) :
 if 25 - 25: I1IiiI
 if 52 - 52: I1ii11iIi11i % i1IIi . IiII % OoOoOO00
 if 50 - 50: OOooOOo * I1IiiI / o0oOOo0O0Ooo
 if 91 - 91: iIii1I11I1II1 / OOooOOo * O0 . o0oOOo0O0Ooo + oO0o / I1ii11iIi11i
 if ( lisp_is_running ( node ) == False ) :
  lprint ( "Suppress sending IPC to {}" . format ( node ) )
  return
  if 33 - 33: II111iiii + Ii1I
  if 46 - 46: IiII + O0 + i1IIi + ooOoO0o / iII111i
 OO00OOo = 1500 if ( packet . find ( "control-packet" ) == - 1 ) else 9000
 if 23 - 23: OoO0O00 - iII111i
 oOO0OO0O = 0
 i1IIiIIIi1 = len ( packet )
 oO00O0ooOoo = 0
 o0O0O00ooO0 = .001
 while ( i1IIiIIIi1 > 0 ) :
  o00OooO0 = min ( i1IIiIIIi1 , OO00OOo )
  ii1III1 = packet [ oOO0OO0O : o00OooO0 + oOO0OO0O ]
  if 16 - 16: II111iiii - I1Ii111 + OOooOOo
  try :
   send_socket . sendto ( ii1III1 , node )
   lprint ( "Send IPC {}-out-of-{} byte to {} succeeded" . format ( len ( ii1III1 ) , len ( packet ) , node ) )
   if 76 - 76: II111iiii - o0oOOo0O0Ooo % OoO0O00 + iII111i
   oO00O0ooOoo = 0
   o0O0O00ooO0 = .001
   if 38 - 38: I1Ii111 - I11i * i1IIi + iIii1I11I1II1
  except socket . error , I1i11II :
   if ( oO00O0ooOoo == 12 ) :
    lprint ( "Giving up on {}, consider it down" . format ( node ) )
    break
    if 41 - 41: Ii1I . OoO0O00 + I1ii11iIi11i + OoOoOO00
    if 76 - 76: iII111i - iIii1I11I1II1
   lprint ( "Send IPC {}-out-of-{} byte to {} failed: {}" . format ( len ( ii1III1 ) , len ( packet ) , node , I1i11II ) )
   if 23 - 23: I11i / OoO0O00 % OOooOOo
   if 9 - 9: ooOoO0o % I1ii11iIi11i . OoooooooOO + OoO0O00 % OOooOOo * OoooooooOO
   oO00O0ooOoo += 1
   time . sleep ( o0O0O00ooO0 )
   if 21 - 21: Ii1I % O0
   lprint ( "Retrying after {} ms ..." . format ( o0O0O00ooO0 * 1000 ) )
   o0O0O00ooO0 *= 2
   continue
   if 15 - 15: II111iiii * Ii1I + IiII % iII111i
   if 96 - 96: II111iiii * I1Ii111 / Oo0Ooo
  oOO0OO0O += o00OooO0
  i1IIiIIIi1 -= o00OooO0
  if 35 - 35: I1IiiI
 return
 if 54 - 54: I1ii11iIi11i % o0oOOo0O0Ooo . i1IIi
 if 72 - 72: Ii1I
 if 87 - 87: iII111i - I1IiiI
 if 54 - 54: iIii1I11I1II1 + oO0o * o0oOOo0O0Ooo % OoooooooOO . Oo0Ooo
 if 32 - 32: iII111i
 if 33 - 33: ooOoO0o + Oo0Ooo * OoOoOO00 % ooOoO0o * oO0o - OoO0O00
 if 40 - 40: I11i . OoooooooOO * O0 / I1Ii111 + O0
def lisp_format_packet ( packet ) :
 packet = binascii . hexlify ( packet )
 oOO0OO0O = 0
 o0OoO0o00o = ""
 i1IIiIIIi1 = len ( packet ) * 2
 while ( oOO0OO0O < i1IIiIIIi1 ) :
  o0OoO0o00o += packet [ oOO0OO0O : oOO0OO0O + 8 ] + " "
  oOO0OO0O += 8
  i1IIiIIIi1 -= 4
  if 97 - 97: ooOoO0o - ooOoO0o * OOooOOo % OoOoOO00 - OoOoOO00 - I1Ii111
 return ( o0OoO0o00o )
 if 52 - 52: O0 % iII111i
 if 81 - 81: OoooooooOO % OoOoOO00 % Oo0Ooo - I1IiiI
 if 43 - 43: o0oOOo0O0Ooo % o0oOOo0O0Ooo
 if 48 - 48: O0
 if 5 - 5: OOooOOo / i11iIiiIii . I11i % OOooOOo
 if 1 - 1: II111iiii + O0 * OoOoOO00 / IiII . O0
 if 87 - 87: IiII + I1IiiI
def lisp_send ( lisp_sockets , dest , port , packet ) :
 OO0Oo0 = lisp_sockets [ 0 ] if dest . is_ipv4 ( ) else lisp_sockets [ 1 ]
 if 23 - 23: o0oOOo0O0Ooo . II111iiii % I1Ii111 - i11iIiiIii / ooOoO0o
 if 51 - 51: OOooOOo * o0oOOo0O0Ooo / oO0o
 if 43 - 43: I1IiiI * OoooooooOO * OoOoOO00 . OOooOOo / I1IiiI
 if 71 - 71: O0 + iIii1I11I1II1 . oO0o + iII111i
 if 49 - 49: oO0o
 if 36 - 36: iII111i . I11i . i1IIi + I11i
 if 97 - 97: II111iiii . OoooooooOO - OoOoOO00
 if 35 - 35: I1Ii111
 if 35 - 35: Oo0Ooo - iIii1I11I1II1 / i1IIi + OoO0O00 - OoooooooOO / i11iIiiIii
 if 79 - 79: I1IiiI * ooOoO0o * ooOoO0o
 if 92 - 92: iII111i % I1ii11iIi11i
 if 16 - 16: oO0o
 I1Ii11i = dest . print_address_no_iid ( )
 if ( I1Ii11i . find ( "::ffff:" ) != - 1 and I1Ii11i . count ( "." ) == 3 ) :
  if ( lisp_i_am_rtr ) : OO0Oo0 = lisp_sockets [ 0 ]
  if ( OO0Oo0 == None ) :
   OO0Oo0 = lisp_sockets [ 0 ]
   I1Ii11i = I1Ii11i . split ( "::ffff:" ) [ - 1 ]
   if 52 - 52: OoooooooOO % ooOoO0o - I1Ii111 * I11i
   if 24 - 24: Ii1I + IiII + OoooooooOO / oO0o / I1IiiI + IiII
   if 52 - 52: ooOoO0o
 lprint ( "{} {} bytes {} {}, packet: {}" . format ( bold ( "Send" , False ) ,
 len ( packet ) , bold ( "to " + I1Ii11i , False ) , port ,
 lisp_format_packet ( packet ) ) )
 if 38 - 38: OoO0O00 + I1IiiI % IiII
 if 87 - 87: oO0o * Ii1I - I1Ii111 / oO0o
 if 65 - 65: OoOoOO00
 if 87 - 87: I11i - i11iIiiIii - OOooOOo . OoOoOO00 + IiII . OoO0O00
 OooooOOo00o = ( LISP_RLOC_PROBE_TTL == 255 )
 if ( OooooOOo00o ) :
  O0oo0oO0O0o0 = struct . unpack ( "B" , packet [ 0 ] ) [ 0 ]
  OooooOOo00o = ( O0oo0oO0O0o0 in [ 0x12 , 0x28 ] )
  if ( OooooOOo00o ) : lisp_set_ttl ( OO0Oo0 , LISP_RLOC_PROBE_TTL )
  if 33 - 33: IiII % o0oOOo0O0Ooo - oO0o . i1IIi
  if 98 - 98: II111iiii * OoooooooOO % oO0o - iII111i
 try : OO0Oo0 . sendto ( packet , ( I1Ii11i , port ) )
 except socket . error , I1i11II :
  lprint ( "socket.sendto() failed: {}" . format ( I1i11II ) )
  if 97 - 97: OoO0O00 / OOooOOo + Ii1I % O0
  if 36 - 36: OoooooooOO . I1Ii111 + OoOoOO00 % OoO0O00 % I11i . iIii1I11I1II1
  if 57 - 57: oO0o % iII111i + IiII + oO0o
  if 31 - 31: iII111i + I1IiiI % OOooOOo
  if 6 - 6: i1IIi / OoOoOO00 + I11i . OoO0O00 . iII111i * II111iiii
 if ( OooooOOo00o ) : lisp_set_ttl ( OO0Oo0 , 64 )
 return
 if 58 - 58: i1IIi / I1ii11iIi11i - IiII / I11i
 if 68 - 68: OOooOOo % OoOoOO00 / I1IiiI % iII111i / O0 % i1IIi
 if 2 - 2: i1IIi / OOooOOo * O0
 if 99 - 99: OoooooooOO . OoOoOO00 / II111iiii
 if 64 - 64: iII111i / i1IIi . I1IiiI + O0
 if 5 - 5: O0 . i11iIiiIii
 if 71 - 71: o0oOOo0O0Ooo + iII111i + ooOoO0o
 if 27 - 27: OoooooooOO . iII111i * I1Ii111 % O0 + OoooooooOO - iII111i
def lisp_receive_segments ( lisp_socket , packet , source , total_length ) :
 if 86 - 86: i1IIi
 if 81 - 81: OoOoOO00
 if 52 - 52: iII111i * IiII % I1IiiI * I11i
 if 73 - 73: I1Ii111 * ooOoO0o
 if 62 - 62: OOooOOo . I1IiiI * iIii1I11I1II1 + OoO0O00 * ooOoO0o / oO0o
 o00OooO0 = total_length - len ( packet )
 if ( o00OooO0 == 0 ) : return ( [ True , packet ] )
 if 14 - 14: iII111i / OoO0O00
 lprint ( "Received {}-out-of-{} byte segment from {}" . format ( len ( packet ) ,
 total_length , source ) )
 if 75 - 75: IiII
 if 68 - 68: IiII - i1IIi % IiII . OoO0O00 . i11iIiiIii . OoooooooOO
 if 32 - 32: iII111i + OoO0O00 % IiII + I1IiiI
 if 69 - 69: I1Ii111 + I11i - iIii1I11I1II1 - II111iiii . Ii1I
 if 74 - 74: I1ii11iIi11i % o0oOOo0O0Ooo + O0 - i11iIiiIii - IiII % OOooOOo
 i1IIiIIIi1 = o00OooO0
 while ( i1IIiIIIi1 > 0 ) :
  try : ii1III1 = lisp_socket . recvfrom ( 9000 )
  except : return ( [ False , None ] )
  if 39 - 39: OoO0O00 - o0oOOo0O0Ooo
  ii1III1 = ii1III1 [ 0 ]
  if 71 - 71: iII111i . OoO0O00 + ooOoO0o - OOooOOo - Oo0Ooo
  if 100 - 100: OoooooooOO - o0oOOo0O0Ooo + I1Ii111 . OoooooooOO % i11iIiiIii
  if 64 - 64: I1Ii111 % OoooooooOO / i1IIi / OoO0O00
  if 2 - 2: I11i % o0oOOo0O0Ooo . OoO0O00 . OoO0O00
  if 89 - 89: ooOoO0o - oO0o + II111iiii + OoO0O00 - IiII
  if ( ii1III1 . find ( "packet@" ) == 0 ) :
   i1IIII1I = ii1III1 . split ( "@" )
   lprint ( "Received new message ({}-out-of-{}) while receiving " + "fragments, old message discarded" , len ( ii1III1 ) ,
   # OoO0O00 . i11iIiiIii + OOooOOo
 i1IIII1I [ 1 ] if len ( i1IIII1I ) > 2 else "?" )
   return ( [ False , ii1III1 ] )
   if 80 - 80: I1IiiI / O0 * oO0o . I1ii11iIi11i + iIii1I11I1II1
   if 72 - 72: o0oOOo0O0Ooo
  i1IIiIIIi1 -= len ( ii1III1 )
  packet += ii1III1
  if 97 - 97: i1IIi % I11i % OoOoOO00
  lprint ( "Received {}-out-of-{} byte segment from {}" . format ( len ( ii1III1 ) , total_length , source ) )
  if 25 - 25: OoOoOO00 . iIii1I11I1II1 - iII111i % II111iiii . OoOoOO00
  if 16 - 16: OOooOOo . Oo0Ooo . I1IiiI % O0 . I1ii11iIi11i + i11iIiiIii
 return ( [ True , packet ] )
 if 100 - 100: I1ii11iIi11i - i1IIi - OoO0O00 * o0oOOo0O0Ooo + OoOoOO00
 if 31 - 31: i1IIi
 if 21 - 21: o0oOOo0O0Ooo / O0 % O0 . OoooooooOO / I1IiiI
 if 94 - 94: ooOoO0o + OoO0O00 / ooOoO0o - ooOoO0o + Oo0Ooo + o0oOOo0O0Ooo
 if 50 - 50: oO0o . Oo0Ooo
 if 15 - 15: Ii1I
 if 64 - 64: OoooooooOO
 if 25 - 25: IiII
def lisp_bit_stuff ( payload ) :
 lprint ( "Bit-stuffing, found {} segments" . format ( len ( payload ) ) )
 I111 = ""
 for ii1III1 in payload : I111 += ii1III1 + "\x40"
 return ( I111 [ : - 1 ] )
 if 29 - 29: OoOoOO00 % ooOoO0o * OoooooooOO
 if 8 - 8: i11iIiiIii - I1Ii111 / IiII
 if 17 - 17: i11iIiiIii * OoO0O00 . o0oOOo0O0Ooo . OoooooooOO . OoOoOO00 - I1ii11iIi11i
 if 78 - 78: I1ii11iIi11i - OoooooooOO + O0
 if 15 - 15: I1ii11iIi11i / IiII % I1IiiI
 if 16 - 16: Ii1I
 if 26 - 26: o0oOOo0O0Ooo / I11i + OoOoOO00 / OoOoOO00
 if 31 - 31: I1Ii111
 if 84 - 84: i11iIiiIii * OOooOOo . iII111i - Ii1I * i1IIi - I1ii11iIi11i
 if 1 - 1: II111iiii
 if 94 - 94: I1ii11iIi11i * iII111i % iII111i % I11i - iII111i
 if 38 - 38: IiII - OoO0O00 % Ii1I - II111iiii
 if 97 - 97: O0 . Ii1I
 if 52 - 52: IiII
 if 86 - 86: I1Ii111 / O0 + OoooooooOO % oO0o
 if 45 - 45: I1IiiI . Oo0Ooo . I11i . Ii1I
 if 81 - 81: II111iiii + OoOoOO00 % i11iIiiIii / iII111i . I1Ii111 + II111iiii
 if 48 - 48: I1IiiI . I1ii11iIi11i * OoOoOO00 % i1IIi / I1Ii111 * II111iiii
 if 62 - 62: o0oOOo0O0Ooo * I1Ii111 . iIii1I11I1II1 / i1IIi
 if 75 - 75: OoooooooOO / ooOoO0o - iII111i . OoooooooOO . OoOoOO00 % i1IIi
def lisp_receive ( lisp_socket , internal ) :
 while ( True ) :
  if 7 - 7: OoOoOO00 . i1IIi * i11iIiiIii % i11iIiiIii
  if 54 - 54: OoO0O00 / I1IiiI . Oo0Ooo
  if 39 - 39: OoO0O00 . ooOoO0o
  if 41 - 41: Oo0Ooo * I1ii11iIi11i - II111iiii - II111iiii
  try : iIi11II1I = lisp_socket . recvfrom ( 9000 )
  except : return ( [ "" , "" , "" , "" ] )
  if 95 - 95: OoOoOO00 / I1IiiI - i1IIi / i11iIiiIii * o0oOOo0O0Ooo
  if 12 - 12: I1ii11iIi11i + iII111i % II111iiii * I1Ii111 . II111iiii / I1Ii111
  if 82 - 82: OoO0O00 - i1IIi / OOooOOo
  if 31 - 31: I11i + I1Ii111 + ooOoO0o / OoOoOO00
  if 68 - 68: Oo0Ooo % IiII * I1IiiI % I1ii11iIi11i % OoooooooOO
  if 63 - 63: Oo0Ooo / I11i . iII111i + ooOoO0o / I1ii11iIi11i / I1IiiI
  if ( internal == False ) :
   I111 = iIi11II1I [ 0 ]
   oo0O00 = lisp_convert_6to4 ( iIi11II1I [ 1 ] [ 0 ] )
   II11i = iIi11II1I [ 1 ] [ 1 ]
   if 75 - 75: o0oOOo0O0Ooo + ooOoO0o * oO0o / IiII
   if ( II11i == LISP_DATA_PORT ) :
    oo000oo = lisp_data_plane_logging
    II1IIIi11Ii1i = lisp_format_packet ( I111 [ 0 : 60 ] ) + " ..."
   else :
    oo000oo = True
    II1IIIi11Ii1i = lisp_format_packet ( I111 )
    if 14 - 14: OOooOOo
    if 59 - 59: Oo0Ooo * I1IiiI / I1ii11iIi11i / OOooOOo
   if ( oo000oo ) :
    lprint ( "{} {} bytes {} {}, packet: {}" . format ( bold ( "Receive" ,
 False ) , len ( I111 ) , bold ( "from " + oo0O00 , False ) , II11i ,
 II1IIIi11Ii1i ) )
    if 45 - 45: II111iiii
   return ( [ "packet" , oo0O00 , II11i , I111 ] )
   if 98 - 98: i11iIiiIii + I1ii11iIi11i * OOooOOo / OoOoOO00
   if 84 - 84: o0oOOo0O0Ooo
   if 40 - 40: OoooooooOO - oO0o / O0 * I1Ii111 . O0 + i11iIiiIii
   if 9 - 9: OOooOOo % O0 % O0 / I1ii11iIi11i . II111iiii / II111iiii
   if 78 - 78: iIii1I11I1II1 - i1IIi . I11i . o0oOOo0O0Ooo
   if 66 - 66: OOooOOo * Oo0Ooo
  o0000Oo0oo = False
  o00o0o0o = iIi11II1I [ 0 ]
  i1IIII1IiI = False
  if 61 - 61: O0
  while ( o0000Oo0oo == False ) :
   o00o0o0o = o00o0o0o . split ( "@" )
   if 100 - 100: i11iIiiIii * O0 / Oo0Ooo % II111iiii
   if ( len ( o00o0o0o ) < 4 ) :
    lprint ( "Possible fragment (length {}), from old message, " + "discarding" , len ( o00o0o0o [ 0 ] ) )
    if 49 - 49: oO0o
    i1IIII1IiI = True
    break
    if 98 - 98: OoooooooOO . II111iiii
    if 12 - 12: OoO0O00 - I1Ii111 / O0 - iII111i
   iiIi = o00o0o0o [ 0 ]
   try :
    oO0O = int ( o00o0o0o [ 1 ] )
   except :
    OOoOOO = bold ( "Internal packet reassembly error" , False )
    lprint ( "{}: {}" . format ( OOoOOO , iIi11II1I ) )
    i1IIII1IiI = True
    break
    if 27 - 27: iII111i - OoooooooOO . oO0o / II111iiii % II111iiii % ooOoO0o
   oo0O00 = o00o0o0o [ 2 ]
   II11i = o00o0o0o [ 3 ]
   if 81 - 81: I11i + o0oOOo0O0Ooo - IiII * Ii1I . i1IIi
   if 5 - 5: o0oOOo0O0Ooo - I1IiiI
   if 50 - 50: I1IiiI
   if 71 - 71: OOooOOo - I1Ii111 % OoooooooOO % OoOoOO00
   if 48 - 48: Oo0Ooo / OoooooooOO . II111iiii % Oo0Ooo
   if 24 - 24: IiII + ooOoO0o
   if 40 - 40: iIii1I11I1II1
   if 33 - 33: i11iIiiIii - oO0o
   if ( len ( o00o0o0o ) > 5 ) :
    I111 = lisp_bit_stuff ( o00o0o0o [ 4 : : ] )
   else :
    I111 = o00o0o0o [ 4 ]
    if 35 - 35: OoOoOO00 - I11i % Ii1I * OoooooooOO
    if 84 - 84: I1IiiI * I1ii11iIi11i + iIii1I11I1II1 - II111iiii % O0 . OOooOOo
    if 99 - 99: i1IIi + iIii1I11I1II1 - ooOoO0o + OoO0O00 + Oo0Ooo . I1ii11iIi11i
    if 74 - 74: i1IIi
    if 80 - 80: ooOoO0o + I1Ii111 . I1ii11iIi11i % OoooooooOO
    if 26 - 26: OoOoOO00 . iII111i * iIii1I11I1II1 / IiII
   o0000Oo0oo , I111 = lisp_receive_segments ( lisp_socket , I111 ,
 oo0O00 , oO0O )
   if ( I111 == None ) : return ( [ "" , "" , "" , "" ] )
   if 69 - 69: OoooooooOO / I11i + Ii1I * II111iiii
   if 35 - 35: i11iIiiIii + oO0o
   if 85 - 85: OoOoOO00 . O0 % OoooooooOO % oO0o
   if 43 - 43: I1IiiI - I11i . I1IiiI / i11iIiiIii % IiII * i11iIiiIii
   if 12 - 12: II111iiii - iIii1I11I1II1
   if ( o0000Oo0oo == False ) :
    o00o0o0o = I111
    continue
    if 43 - 43: i11iIiiIii % OoO0O00
    if 100 - 100: i1IIi
   if ( II11i == "" ) : II11i = "no-port"
   if ( iiIi == "command" and lisp_i_am_core == False ) :
    OOOoO000 = I111 . find ( " {" )
    Ii1111Ii = I111 if OOOoO000 == - 1 else I111 [ : OOOoO000 ]
    Ii1111Ii = ": '" + Ii1111Ii + "'"
   else :
    Ii1111Ii = ""
    if 46 - 46: ooOoO0o - iIii1I11I1II1 % i11iIiiIii * IiII - I11i
    if 23 - 23: OoO0O00 * I1ii11iIi11i + I11i
   lprint ( "{} {} bytes {} {}, {}{}" . format ( bold ( "Receive" , False ) ,
 len ( I111 ) , bold ( "from " + oo0O00 , False ) , II11i , iiIi ,
 Ii1111Ii if ( iiIi in [ "command" , "api" ] ) else ": ... " if ( iiIi == "data-packet" ) else ": " + lisp_format_packet ( I111 ) ) )
   if 31 - 31: II111iiii * II111iiii
   if 26 - 26: OoO0O00 + OoOoOO00 / o0oOOo0O0Ooo . I11i / O0 - I11i
   if 10 - 10: I1Ii111 . OoooooooOO % i11iIiiIii
   if 13 - 13: Oo0Ooo
   if 32 - 32: oO0o
  if ( i1IIII1IiI ) : continue
  return ( [ iiIi , oo0O00 , II11i , I111 ] )
  if 81 - 81: OoO0O00 * Ii1I % iII111i . I11i
  if 38 - 38: iIii1I11I1II1 % I1ii11iIi11i % o0oOOo0O0Ooo . ooOoO0o - oO0o
  if 64 - 64: I11i * ooOoO0o
  if 86 - 86: OoooooooOO * I1IiiI
  if 88 - 88: Ii1I + O0
  if 92 - 92: I1IiiI % iII111i % I11i + OoooooooOO - i11iIiiIii
  if 9 - 9: i11iIiiIii - II111iiii / ooOoO0o
  if 81 - 81: i11iIiiIii % OoOoOO00 % OoO0O00 * Ii1I
def lisp_parse_packet ( lisp_sockets , packet , source , udp_sport , ttl = - 1 ) :
 oo0o0o0o0Ooo = False
 if 80 - 80: OoO0O00 + ooOoO0o - OOooOOo . Ii1I
 ooo0Oo00O = lisp_control_header ( )
 if ( ooo0Oo00O . decode ( packet ) == None ) :
  lprint ( "Could not decode control header" )
  return ( oo0o0o0o0Ooo )
  if 99 - 99: I11i / OoOoOO00 % OoO0O00 * Ii1I / OOooOOo
  if 9 - 9: ooOoO0o - ooOoO0o * I1ii11iIi11i
  if 92 - 92: Ii1I
  if 88 - 88: OoooooooOO * i1IIi % I1ii11iIi11i % Oo0Ooo
  if 1 - 1: OoO0O00 / iIii1I11I1II1 % I1ii11iIi11i - o0oOOo0O0Ooo
 o0o0000O0O = source
 if ( source . find ( "lisp" ) == - 1 ) :
  i1I1iIi1IiI = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  i1I1iIi1IiI . string_to_afi ( source )
  i1I1iIi1IiI . store_address ( source )
  source = i1I1iIi1IiI
  if 89 - 89: iIii1I11I1II1 . I1IiiI * i11iIiiIii + iII111i % OOooOOo / I11i
  if 89 - 89: iIii1I11I1II1 * oO0o + IiII * o0oOOo0O0Ooo - iIii1I11I1II1
 if ( ooo0Oo00O . type == LISP_MAP_REQUEST ) :
  lisp_process_map_request ( lisp_sockets , packet , None , 0 , source ,
 udp_sport , False , ttl )
  if 78 - 78: I1ii11iIi11i / Oo0Ooo
 elif ( ooo0Oo00O . type == LISP_MAP_REPLY ) :
  lisp_process_map_reply ( lisp_sockets , packet , source , ttl )
  if 25 - 25: i11iIiiIii * i1IIi . oO0o - iII111i * I1Ii111
 elif ( ooo0Oo00O . type == LISP_MAP_REGISTER ) :
  lisp_process_map_register ( lisp_sockets , packet , source , udp_sport )
  if 66 - 66: OoOoOO00 / I1Ii111
 elif ( ooo0Oo00O . type == LISP_MAP_NOTIFY ) :
  if ( o0o0000O0O == "lisp-etr" ) :
   lisp_process_multicast_map_notify ( packet , source )
  else :
   if ( lisp_is_running ( "lisp-rtr" ) ) :
    lisp_process_multicast_map_notify ( packet , source )
    if 66 - 66: iIii1I11I1II1 / OoOoOO00 * iII111i - iIii1I11I1II1 % I1Ii111 - II111iiii
   lisp_process_map_notify ( lisp_sockets , packet , source )
   if 24 - 24: ooOoO0o % Oo0Ooo . I11i * I1ii11iIi11i / I1Ii111
   if 21 - 21: oO0o / I1ii11iIi11i % iII111i . I11i
 elif ( ooo0Oo00O . type == LISP_MAP_NOTIFY_ACK ) :
  lisp_process_map_notify_ack ( packet , source )
  if 58 - 58: I1IiiI - i1IIi - OOooOOo
 elif ( ooo0Oo00O . type == LISP_MAP_REFERRAL ) :
  lisp_process_map_referral ( lisp_sockets , packet , source )
  if 33 - 33: O0 % I1IiiI + ooOoO0o % OOooOOo
 elif ( ooo0Oo00O . type == LISP_NAT_INFO and ooo0Oo00O . is_info_reply ( ) ) :
  Oo000 , Iiiii , oo0o0o0o0Ooo = lisp_process_info_reply ( source , packet , True )
  if 49 - 49: ooOoO0o / O0 - OoOoOO00 % O0 * oO0o * OoooooooOO
 elif ( ooo0Oo00O . type == LISP_NAT_INFO and ooo0Oo00O . is_info_reply ( ) == False ) :
  I11i11I = source . print_address_no_iid ( )
  lisp_process_info_request ( lisp_sockets , packet , I11i11I , udp_sport ,
 None )
  if 66 - 66: o0oOOo0O0Ooo . I1ii11iIi11i / OoooooooOO . I11i
 elif ( ooo0Oo00O . type == LISP_ECM ) :
  lisp_process_ecm ( lisp_sockets , packet , source , udp_sport )
  if 33 - 33: I1Ii111
 else :
  lprint ( "Invalid LISP control packet type {}" . format ( ooo0Oo00O . type ) )
  if 41 - 41: ooOoO0o + Ii1I / i1IIi % Ii1I
 return ( oo0o0o0o0Ooo )
 if 97 - 97: Oo0Ooo % OoOoOO00 / OOooOOo / iIii1I11I1II1 / OoooooooOO - I1ii11iIi11i
 if 6 - 6: iIii1I11I1II1
 if 27 - 27: Ii1I / i11iIiiIii / i1IIi
 if 36 - 36: ooOoO0o % ooOoO0o . i11iIiiIii
 if 42 - 42: OoO0O00 . I1Ii111 / Ii1I
 if 57 - 57: iIii1I11I1II1 % I1ii11iIi11i . OOooOOo / oO0o . OoOoOO00
 if 74 - 74: I1IiiI * OoO0O00 + OoooooooOO * ooOoO0o . oO0o
def lisp_process_rloc_probe_request ( lisp_sockets , map_request , source , port ,
 ttl ) :
 if 66 - 66: II111iiii + OOooOOo + i11iIiiIii / II111iiii
 OoOOOOo = bold ( "RLOC-probe" , False )
 if 37 - 37: I1IiiI + OoO0O00 . OoO0O00 % OoOoOO00 + o0oOOo0O0Ooo
 if ( lisp_i_am_etr ) :
  lprint ( "Received {} Map-Request, send RLOC-probe Map-Reply" . format ( OoOOOOo ) )
  lisp_etr_process_map_request ( lisp_sockets , map_request , source , port ,
 ttl )
  return
  if 81 - 81: i1IIi % iIii1I11I1II1
  if 41 - 41: oO0o - iII111i / o0oOOo0O0Ooo . iII111i % Oo0Ooo + OOooOOo
 if ( lisp_i_am_rtr ) :
  lprint ( "Received {} Map-Request, send RLOC-probe Map-Reply" . format ( OoOOOOo ) )
  lisp_rtr_process_map_request ( lisp_sockets , map_request , source , port ,
 ttl )
  return
  if 82 - 82: ooOoO0o
  if 89 - 89: OOooOOo / I1ii11iIi11i . I1IiiI + i11iIiiIii
 lprint ( "Ignoring received {} Map-Request, not an ETR or RTR" . format ( OoOOOOo ) )
 return
 if 11 - 11: oO0o . i11iIiiIii * ooOoO0o % OoooooooOO % O0
 if 59 - 59: i11iIiiIii / OoO0O00
 if 48 - 48: iIii1I11I1II1
 if 19 - 19: oO0o
 if 69 - 69: I1ii11iIi11i % iII111i - OoooooooOO % Ii1I * oO0o
def lisp_process_smr ( map_request ) :
 lprint ( "Received SMR-based Map-Request" )
 return
 if 12 - 12: OoOoOO00 / I1Ii111 . O0 . IiII - OOooOOo - OoO0O00
 if 28 - 28: II111iiii . OoOoOO00 - o0oOOo0O0Ooo
 if 89 - 89: I1Ii111 * OoooooooOO . OOooOOo . I11i % i11iIiiIii
 if 8 - 8: I1ii11iIi11i + II111iiii . OoO0O00 + I1IiiI - II111iiii % OoO0O00
 if 85 - 85: i11iIiiIii % iII111i + II111iiii
def lisp_process_smr_invoked_request ( map_request ) :
 lprint ( "Received SMR-invoked Map-Request" )
 return
 if 16 - 16: ooOoO0o * OoOoOO00 / OoOoOO00 + II111iiii
 if 50 - 50: OoO0O00 / OOooOOo % I1IiiI / Ii1I + OoO0O00 . iIii1I11I1II1
 if 62 - 62: I1Ii111 + OoooooooOO - Ii1I - iIii1I11I1II1
 if 80 - 80: OoO0O00
 if 72 - 72: II111iiii % i11iIiiIii + OoOoOO00 / I1Ii111 - i11iIiiIii
 if 39 - 39: i11iIiiIii - OOooOOo / OoO0O00 * OoOoOO00 / IiII
 if 84 - 84: I1ii11iIi11i . iIii1I11I1II1 / Ii1I / II111iiii
def lisp_build_map_reply ( eid , group , rloc_set , nonce , action , ttl , rloc_probe ,
 keys , enc , auth , mr_ttl = - 1 ) :
 o0o00oO0OooO0 = lisp_map_reply ( )
 o0o00oO0OooO0 . rloc_probe = rloc_probe
 o0o00oO0OooO0 . echo_nonce_capable = enc
 o0o00oO0OooO0 . hop_count = 0 if ( mr_ttl == - 1 ) else mr_ttl
 o0o00oO0OooO0 . record_count = 1
 o0o00oO0OooO0 . nonce = nonce
 I111 = o0o00oO0OooO0 . encode ( )
 o0o00oO0OooO0 . print_map_reply ( )
 if 12 - 12: o0oOOo0O0Ooo
 oooOO0o0ooOO = lisp_eid_record ( )
 oooOO0o0ooOO . rloc_count = len ( rloc_set )
 oooOO0o0ooOO . authoritative = auth
 oooOO0o0ooOO . record_ttl = ttl
 oooOO0o0ooOO . action = action
 oooOO0o0ooOO . eid = eid
 oooOO0o0ooOO . group = group
 if 38 - 38: OOooOOo + II111iiii - O0
 I111 += oooOO0o0ooOO . encode ( )
 oooOO0o0ooOO . print_record ( "  " , False )
 if 6 - 6: I1Ii111 . i11iIiiIii - O0 % I1ii11iIi11i . I11i + i11iIiiIii
 iI11i = lisp_get_all_addresses ( ) + lisp_get_all_translated_rlocs ( )
 if 69 - 69: ooOoO0o . OoooooooOO
 for o0OO0O0OoOo0 in rloc_set :
  O0OO0 = lisp_rloc_record ( )
  I11i11I = o0OO0O0OoOo0 . rloc . print_address_no_iid ( )
  if ( I11i11I in iI11i ) :
   O0OO0 . local_bit = True
   O0OO0 . probe_bit = rloc_probe
   O0OO0 . keys = keys
   if ( o0OO0O0OoOo0 . priority == 254 and lisp_i_am_rtr ) :
    O0OO0 . rloc_name = "RTR"
    if 62 - 62: OoooooooOO % OoO0O00 / Ii1I . II111iiii / I1Ii111
    if 79 - 79: IiII . OoOoOO00 / oO0o % OoO0O00 / Ii1I + I11i
  O0OO0 . store_rloc_entry ( o0OO0O0OoOo0 )
  O0OO0 . reach_bit = True
  O0OO0 . print_record ( "    " )
  I111 += O0OO0 . encode ( )
  if 78 - 78: o0oOOo0O0Ooo + I1Ii111 % i11iIiiIii % I1IiiI - Ii1I
 return ( I111 )
 if 81 - 81: i11iIiiIii - II111iiii + I11i
 if 52 - 52: II111iiii
 if 62 - 62: iII111i / OoO0O00 + i11iIiiIii / Oo0Ooo
 if 26 - 26: I1ii11iIi11i - OoO0O00
 if 19 - 19: iIii1I11I1II1 / I1ii11iIi11i + O0
 if 12 - 12: I11i . OOooOOo + o0oOOo0O0Ooo . OoO0O00 + o0oOOo0O0Ooo
 if 56 - 56: i1IIi / i1IIi . OoO0O00 % i1IIi - OoOoOO00 % OOooOOo
def lisp_build_map_referral ( eid , group , ddt_entry , action , ttl , nonce ) :
 Oo00o0oO0O0o = lisp_map_referral ( )
 Oo00o0oO0O0o . record_count = 1
 Oo00o0oO0O0o . nonce = nonce
 I111 = Oo00o0oO0O0o . encode ( )
 Oo00o0oO0O0o . print_map_referral ( )
 if 86 - 86: iII111i % o0oOOo0O0Ooo
 oooOO0o0ooOO = lisp_eid_record ( )
 if 89 - 89: IiII % iIii1I11I1II1 % O0
 oo0oooooOo000 = 0
 if ( ddt_entry == None ) :
  oooOO0o0ooOO . eid = eid
  oooOO0o0ooOO . group = group
 else :
  oo0oooooOo000 = len ( ddt_entry . delegation_set )
  oooOO0o0ooOO . eid = ddt_entry . eid
  oooOO0o0ooOO . group = ddt_entry . group
  ddt_entry . map_referrals_sent += 1
  if 99 - 99: OoO0O00 . OoOoOO00 + iII111i - iIii1I11I1II1 + OoooooooOO % OoO0O00
 oooOO0o0ooOO . rloc_count = oo0oooooOo000
 oooOO0o0ooOO . authoritative = True
 if 95 - 95: o0oOOo0O0Ooo * I1ii11iIi11i - o0oOOo0O0Ooo
 if 47 - 47: I1IiiI / OoOoOO00 / II111iiii
 if 7 - 7: oO0o . ooOoO0o
 if 73 - 73: i1IIi % I1Ii111 * ooOoO0o % OoO0O00
 if 70 - 70: ooOoO0o * I1ii11iIi11i
 ooOOOOO000o = False
 if ( action == LISP_DDT_ACTION_NULL ) :
  if ( oo0oooooOo000 == 0 ) :
   action = LISP_DDT_ACTION_NODE_REFERRAL
  else :
   iII1I = ddt_entry . delegation_set [ 0 ]
   if ( iII1I . is_ddt_child ( ) ) :
    action = LISP_DDT_ACTION_NODE_REFERRAL
    if 26 - 26: i11iIiiIii - II111iiii . II111iiii * oO0o / Ii1I + I1IiiI
   if ( iII1I . is_ms_child ( ) ) :
    action = LISP_DDT_ACTION_MS_REFERRAL
    if 12 - 12: OoO0O00 * iIii1I11I1II1 % I1Ii111 . O0 * OoOoOO00 * OOooOOo
    if 34 - 34: I1IiiI . i1IIi
    if 38 - 38: iIii1I11I1II1
    if 64 - 64: i1IIi / OoO0O00
    if 68 - 68: I11i * O0 * oO0o + OoOoOO00 / IiII
    if 42 - 42: iIii1I11I1II1 % i1IIi - OoOoOO00 % I1ii11iIi11i * Ii1I + i11iIiiIii
    if 40 - 40: OOooOOo
 if ( action == LISP_DDT_ACTION_NOT_AUTH ) : ooOOOOO000o = True
 if ( action in ( LISP_DDT_ACTION_MS_REFERRAL , LISP_DDT_ACTION_MS_ACK ) ) :
  ooOOOOO000o = ( lisp_i_am_ms and iII1I . is_ms_peer ( ) == False )
  if 30 - 30: o0oOOo0O0Ooo - Oo0Ooo + iII111i / O0
  if 94 - 94: IiII
 oooOO0o0ooOO . action = action
 oooOO0o0ooOO . ddt_incomplete = ooOOOOO000o
 oooOO0o0ooOO . record_ttl = ttl
 if 69 - 69: I1Ii111 . I1Ii111
 I111 += oooOO0o0ooOO . encode ( )
 oooOO0o0ooOO . print_record ( "  " , True )
 if 53 - 53: i11iIiiIii + iII111i * Oo0Ooo - I1Ii111
 if ( oo0oooooOo000 == 0 ) : return ( I111 )
 if 61 - 61: o0oOOo0O0Ooo / OOooOOo . II111iiii - I1IiiI * i11iIiiIii
 for iII1I in ddt_entry . delegation_set :
  O0OO0 = lisp_rloc_record ( )
  O0OO0 . rloc = iII1I . delegate_address
  O0OO0 . priority = iII1I . priority
  O0OO0 . weight = iII1I . weight
  O0OO0 . mpriority = 255
  O0OO0 . mweight = 0
  O0OO0 . reach_bit = True
  I111 += O0OO0 . encode ( )
  O0OO0 . print_record ( "    " )
  if 8 - 8: iII111i % o0oOOo0O0Ooo
 return ( I111 )
 if 87 - 87: Ii1I % I11i / I1Ii111
 if 21 - 21: OoO0O00 + Ii1I / I1Ii111
 if 75 - 75: I1Ii111 . Ii1I % iIii1I11I1II1 / OoOoOO00
 if 38 - 38: i1IIi
 if 1 - 1: I1ii11iIi11i + OoO0O00 % I11i . OOooOOo + i1IIi / oO0o
 if 35 - 35: ooOoO0o % OoOoOO00 % OoO0O00 + OOooOOo / IiII * OoOoOO00
 if 65 - 65: I1IiiI . Oo0Ooo + i1IIi - Ii1I * i1IIi
def lisp_etr_process_map_request ( lisp_sockets , map_request , source , sport ,
 ttl ) :
 if 64 - 64: I1IiiI / OoO0O00 * I1IiiI * II111iiii . Ii1I
 if ( map_request . target_group . is_null ( ) ) :
  o0O00o = lisp_db_for_lookups . lookup_cache ( map_request . target_eid , False )
 else :
  o0O00o = lisp_db_for_lookups . lookup_cache ( map_request . target_group , False )
  if ( o0O00o ) : o0O00o = o0O00o . lookup_source_cache ( map_request . target_eid , False )
  if 58 - 58: OoOoOO00 * iIii1I11I1II1 . OoO0O00
 oo0ooooO = map_request . print_prefix ( )
 if 98 - 98: Oo0Ooo * oO0o - Oo0Ooo * oO0o
 if ( o0O00o == None ) :
  lprint ( "Database-mapping entry not found for requested EID {}" . format ( green ( oo0ooooO , False ) ) )
  if 24 - 24: IiII % i11iIiiIii + ooOoO0o
  return
  if 28 - 28: I11i * I11i + I11i / O0 - OOooOOo
  if 29 - 29: OoOoOO00 + i11iIiiIii % OoO0O00 - OoooooooOO
 o00oo = o0O00o . print_eid_tuple ( )
 if 28 - 28: I1ii11iIi11i . O0 / iIii1I11I1II1
 lprint ( "Found database-mapping EID-prefix {} for requested EID {}" . format ( green ( o00oo , False ) , green ( oo0ooooO , False ) ) )
 if 72 - 72: I1ii11iIi11i * i11iIiiIii
 if 12 - 12: O0 - iIii1I11I1II1 % Oo0Ooo / O0 - IiII
 if 55 - 55: OOooOOo . Oo0Ooo * OoOoOO00 / OoooooooOO * i11iIiiIii + oO0o
 if 45 - 45: Ii1I
 if 8 - 8: oO0o + OOooOOo
 I1IIIIII = map_request . itr_rlocs [ 0 ]
 if ( I1IIIIII . is_private_address ( ) and lisp_nat_traversal ) :
  I1IIIIII = source
  if 90 - 90: OOooOOo - Oo0Ooo
  if 57 - 57: I1IiiI + IiII + IiII * I1ii11iIi11i
 oO00o0oOoo = map_request . nonce
 Oo00o0000O = lisp_nonce_echoing
 OOo = map_request . keys
 if 51 - 51: OOooOOo . O0 . OoooooooOO - I1Ii111 / OoOoOO00
 o0O00o . map_replies_sent += 1
 if 72 - 72: i1IIi . Ii1I
 I111 = lisp_build_map_reply ( o0O00o . eid , o0O00o . group , o0O00o . rloc_set , oO00o0oOoo ,
 LISP_NO_ACTION , 1440 , map_request . rloc_probe , OOo , Oo00o0000O , True , ttl )
 if 67 - 67: oO0o + i1IIi / o0oOOo0O0Ooo
 if 78 - 78: ooOoO0o
 if 19 - 19: i1IIi % O0 % ooOoO0o / II111iiii * I11i
 if 18 - 18: i1IIi % oO0o
 if 80 - 80: II111iiii
 if 18 - 18: I1Ii111 % iII111i + OoOoOO00 . I1ii11iIi11i / I11i
 if 29 - 29: II111iiii - I1Ii111 . OoooooooOO / i11iIiiIii / I1ii11iIi11i
 if 60 - 60: i1IIi % ooOoO0o / II111iiii * Oo0Ooo - i1IIi . Ii1I
 if 63 - 63: OoO0O00 * OoooooooOO + iII111i / iIii1I11I1II1 . i11iIiiIii
 if 17 - 17: OOooOOo
 if ( map_request . rloc_probe and len ( lisp_sockets ) == 4 ) :
  i1I1IiIiiI1II = ( I1IIIIII . is_private_address ( ) == False )
  IIiiIiiI1Ii1i = I1IIIIII . print_address_no_iid ( )
  if ( i1I1IiIiiI1II and lisp_rtr_list . has_key ( IIiiIiiI1Ii1i ) ) :
   lisp_encapsulate_rloc_probe ( lisp_sockets , I1IIIIII , None , I111 )
   return
   if 21 - 21: i1IIi
   if 10 - 10: i11iIiiIii / ooOoO0o - o0oOOo0O0Ooo . o0oOOo0O0Ooo
   if 8 - 8: iII111i + iIii1I11I1II1 . I1ii11iIi11i
   if 68 - 68: OoooooooOO . OoooooooOO % I1ii11iIi11i + i1IIi % OoooooooOO + Ii1I
   if 89 - 89: ooOoO0o + I11i * O0 % OoOoOO00
   if 2 - 2: I1Ii111 % iIii1I11I1II1 . Ii1I - II111iiii
 lisp_send_map_reply ( lisp_sockets , I111 , I1IIIIII , sport )
 return
 if 33 - 33: I11i . i11iIiiIii % i1IIi * II111iiii * i11iIiiIii + OoOoOO00
 if 26 - 26: I1IiiI % OoOoOO00 % I11i + Oo0Ooo
 if 86 - 86: iII111i / i1IIi % Oo0Ooo
 if 84 - 84: o0oOOo0O0Ooo * OOooOOo . I11i * Ii1I
 if 32 - 32: ooOoO0o % ooOoO0o * I1ii11iIi11i % Ii1I + Oo0Ooo . OoOoOO00
 if 2 - 2: I1Ii111 / ooOoO0o * oO0o + IiII
 if 14 - 14: OoOoOO00 / iIii1I11I1II1 . o0oOOo0O0Ooo % i11iIiiIii . OoOoOO00
def lisp_rtr_process_map_request ( lisp_sockets , map_request , source , sport ,
 ttl ) :
 if 92 - 92: OoO0O00 . i1IIi
 if 22 - 22: Ii1I . I1IiiI
 if 54 - 54: OOooOOo / I1ii11iIi11i % oO0o
 if 66 - 66: I11i + iII111i
 I1IIIIII = map_request . itr_rlocs [ 0 ]
 if ( I1IIIIII . is_private_address ( ) ) : I1IIIIII = source
 oO00o0oOoo = map_request . nonce
 if 50 - 50: IiII
 III1II1I1iI = map_request . target_eid
 oO0000O0o = map_request . target_group
 if 33 - 33: OOooOOo % I1IiiI - I1IiiI / IiII
 I1111Ii1II1I = [ ]
 for iIiiiiii in [ lisp_myrlocs [ 0 ] , lisp_myrlocs [ 1 ] ] :
  if ( iIiiiiii == None ) : continue
  II1iIiIiIIi = lisp_rloc ( )
  II1iIiIiIIi . rloc . copy_address ( iIiiiiii )
  II1iIiIiIIi . priority = 254
  I1111Ii1II1I . append ( II1iIiIiIIi )
  if 37 - 37: Ii1I + o0oOOo0O0Ooo
  if 74 - 74: Oo0Ooo / O0 + i1IIi . I1IiiI + OoO0O00 / Oo0Ooo
 Oo00o0000O = lisp_nonce_echoing
 OOo = map_request . keys
 if 13 - 13: o0oOOo0O0Ooo / Ii1I . II111iiii
 I111 = lisp_build_map_reply ( III1II1I1iI , oO0000O0o , I1111Ii1II1I , oO00o0oOoo , LISP_NO_ACTION ,
 1440 , True , OOo , Oo00o0000O , True , ttl )
 lisp_send_map_reply ( lisp_sockets , I111 , I1IIIIII , sport )
 return
 if 8 - 8: I11i - I11i % IiII
 if 8 - 8: I1IiiI . IiII * O0 * o0oOOo0O0Ooo
 if 17 - 17: I1IiiI . oO0o + Oo0Ooo + I11i / o0oOOo0O0Ooo
 if 25 - 25: iII111i / iII111i % OoOoOO00 / ooOoO0o
 if 81 - 81: OOooOOo * oO0o
 if 32 - 32: Oo0Ooo * OoO0O00 + ooOoO0o . O0 * oO0o * iIii1I11I1II1
 if 50 - 50: i1IIi
 if 53 - 53: II111iiii + O0 . ooOoO0o * IiII + i1IIi
 if 80 - 80: Ii1I + O0
 if 59 - 59: i11iIiiIii - OoooooooOO % I11i . OoO0O00 - Oo0Ooo * o0oOOo0O0Ooo
def lisp_get_private_rloc_set ( target_site_eid , seid , group ) :
 I1111Ii1II1I = target_site_eid . registered_rlocs
 if 7 - 7: II111iiii % Ii1I * i11iIiiIii
 Ii111III1 = lisp_site_eid_lookup ( seid , group , False )
 if ( Ii111III1 == None ) : return ( I1111Ii1II1I )
 if 58 - 58: iII111i . Oo0Ooo - I11i / I1IiiI + O0 . I11i
 if 70 - 70: Oo0Ooo % OoOoOO00 + i11iIiiIii / OoO0O00 . IiII * IiII
 if 72 - 72: ooOoO0o
 if 21 - 21: Ii1I - OOooOOo
 iiIii = None
 iI111iiiI1 = [ ]
 for o0OO0O0OoOo0 in I1111Ii1II1I :
  if ( o0OO0O0OoOo0 . is_rtr ( ) ) : continue
  if ( o0OO0O0OoOo0 . rloc . is_private_address ( ) ) :
   III11 = copy . deepcopy ( o0OO0O0OoOo0 )
   iI111iiiI1 . append ( III11 )
   continue
   if 24 - 24: Ii1I * I1IiiI * OOooOOo / OoooooooOO * oO0o % IiII
  iiIii = o0OO0O0OoOo0
  break
  if 25 - 25: Ii1I % IiII * i1IIi / o0oOOo0O0Ooo / OoOoOO00
 if ( iiIii == None ) : return ( I1111Ii1II1I )
 iiIii = iiIii . rloc . print_address_no_iid ( )
 if 36 - 36: ooOoO0o + i1IIi . I1Ii111
 if 42 - 42: OoOoOO00 / I11i
 if 10 - 10: o0oOOo0O0Ooo
 if 13 - 13: iII111i * ooOoO0o * OOooOOo * I1ii11iIi11i - O0
 oo0ooOo0oo = None
 for o0OO0O0OoOo0 in Ii111III1 . registered_rlocs :
  if ( o0OO0O0OoOo0 . is_rtr ( ) ) : continue
  if ( o0OO0O0OoOo0 . rloc . is_private_address ( ) ) : continue
  oo0ooOo0oo = o0OO0O0OoOo0
  break
  if 59 - 59: I1ii11iIi11i . I1IiiI + I1IiiI % I1Ii111
 if ( oo0ooOo0oo == None ) : return ( I1111Ii1II1I )
 oo0ooOo0oo = oo0ooOo0oo . rloc . print_address_no_iid ( )
 if 22 - 22: o0oOOo0O0Ooo % OOooOOo - I11i + ooOoO0o / OOooOOo
 if 98 - 98: I11i * O0 + IiII - oO0o
 if 35 - 35: OoooooooOO * Ii1I
 if 73 - 73: ooOoO0o . OoO0O00 % I1ii11iIi11i - oO0o
 OOoo000Ooo = target_site_eid . site_id
 if ( OOoo000Ooo == 0 ) :
  if ( oo0ooOo0oo == iiIii ) :
   lprint ( "Return private RLOCs for sites behind {}" . format ( iiIii ) )
   if 67 - 67: o0oOOo0O0Ooo . I11i + i1IIi
   return ( iI111iiiI1 )
   if 100 - 100: Oo0Ooo - I1IiiI . OOooOOo % iIii1I11I1II1 . I11i
  return ( I1111Ii1II1I )
  if 83 - 83: OoOoOO00 * iII111i
  if 75 - 75: i11iIiiIii . o0oOOo0O0Ooo / oO0o . OoO0O00 % Ii1I % Ii1I
  if 94 - 94: iII111i . Ii1I
  if 71 - 71: o0oOOo0O0Ooo * II111iiii / OOooOOo . OoO0O00
  if 73 - 73: I1Ii111 * OoO0O00 / OoOoOO00 . II111iiii
  if 87 - 87: OoO0O00 + Oo0Ooo + O0 % OoooooooOO - iIii1I11I1II1
  if 100 - 100: Oo0Ooo + IiII
 if ( OOoo000Ooo == Ii111III1 . site_id ) :
  lprint ( "Return private RLOCs for sites in site-id {}" . format ( OOoo000Ooo ) )
  return ( iI111iiiI1 )
  if 81 - 81: iIii1I11I1II1 + iIii1I11I1II1
 return ( I1111Ii1II1I )
 if 19 - 19: ooOoO0o + i1IIi / Oo0Ooo * II111iiii * I1Ii111 / ooOoO0o
 if 23 - 23: I1Ii111
 if 76 - 76: Ii1I + Ii1I / i1IIi % o0oOOo0O0Ooo . iIii1I11I1II1 . OoOoOO00
 if 75 - 75: I11i . Ii1I / I1ii11iIi11i
 if 99 - 99: Ii1I
 if 85 - 85: I1Ii111 + I1Ii111 + OoOoOO00 / ooOoO0o / o0oOOo0O0Ooo . Oo0Ooo
 if 41 - 41: i1IIi % Ii1I . i1IIi * OoooooooOO % Ii1I
 if 21 - 21: iII111i
 if 72 - 72: I11i % o0oOOo0O0Ooo . iIii1I11I1II1 - I1Ii111 / i11iIiiIii
def lisp_get_partial_rloc_set ( registered_rloc_set , mr_source , multicast ) :
 oo00 = [ ]
 I1111Ii1II1I = [ ]
 if 64 - 64: i1IIi % Oo0Ooo / O0 % Oo0Ooo
 if 49 - 49: II111iiii * iIii1I11I1II1 / I11i - oO0o
 if 76 - 76: I1Ii111 . Oo0Ooo - ooOoO0o . II111iiii - iII111i
 if 36 - 36: iIii1I11I1II1 % Oo0Ooo
 if 67 - 67: oO0o / II111iiii . I11i / oO0o
 if 46 - 46: oO0o * Oo0Ooo - I11i / iIii1I11I1II1
 ooOOO00Ooo0 = False
 iII111111 = False
 for o0OO0O0OoOo0 in registered_rloc_set :
  if ( o0OO0O0OoOo0 . priority != 254 ) : continue
  iII111111 |= True
  if ( o0OO0O0OoOo0 . rloc . is_exact_match ( mr_source ) == False ) : continue
  ooOOO00Ooo0 = True
  break
  if 13 - 13: OoO0O00
  if 88 - 88: oO0o - OoO0O00 % ooOoO0o + OoOoOO00 + IiII
  if 83 - 83: i1IIi - Oo0Ooo - IiII - i11iIiiIii
  if 53 - 53: OoOoOO00 . OoooooooOO
  if 11 - 11: i1IIi % II111iiii % I1ii11iIi11i
  if 99 - 99: oO0o - I1Ii111
  if 29 - 29: I1IiiI - I11i
 if ( iII111111 == False ) : return ( registered_rloc_set )
 if 42 - 42: Oo0Ooo - O0 . OoOoOO00
 if 4 - 4: IiII
 if 2 - 2: iII111i
 if 47 - 47: i1IIi % I11i
 if 17 - 17: OoOoOO00 - iII111i % I11i / o0oOOo0O0Ooo / II111iiii
 if 22 - 22: Oo0Ooo + I1ii11iIi11i % i11iIiiIii . OoO0O00 - I11i % I11i
 if 21 - 21: I1IiiI . OoO0O00 * IiII % OoooooooOO - Oo0Ooo + Oo0Ooo
 if 94 - 94: ooOoO0o
 if 80 - 80: i11iIiiIii - O0 / I1Ii111 + OOooOOo % Oo0Ooo
 if 95 - 95: II111iiii
 OO00oOo0oO = ( os . getenv ( "LISP_RTR_BEHIND_NAT" ) != None )
 if 55 - 55: Ii1I
 if 90 - 90: I1Ii111 . I1IiiI . I1Ii111 + OoooooooOO . o0oOOo0O0Ooo
 if 90 - 90: I1ii11iIi11i + o0oOOo0O0Ooo * OoO0O00 / II111iiii / i11iIiiIii
 if 82 - 82: o0oOOo0O0Ooo - I11i + i1IIi . o0oOOo0O0Ooo
 if 58 - 58: II111iiii % ooOoO0o % I1Ii111 . II111iiii
 for o0OO0O0OoOo0 in registered_rloc_set :
  if ( OO00oOo0oO and o0OO0O0OoOo0 . rloc . is_private_address ( ) ) : continue
  if ( multicast == False and o0OO0O0OoOo0 . priority == 255 ) : continue
  if ( multicast and o0OO0O0OoOo0 . mpriority == 255 ) : continue
  if ( o0OO0O0OoOo0 . priority == 254 ) :
   oo00 . append ( o0OO0O0OoOo0 )
  else :
   I1111Ii1II1I . append ( o0OO0O0OoOo0 )
   if 88 - 88: I1ii11iIi11i - iIii1I11I1II1 / iII111i
   if 69 - 69: o0oOOo0O0Ooo % o0oOOo0O0Ooo . i11iIiiIii
   if 34 - 34: Oo0Ooo - i11iIiiIii
   if 30 - 30: OoO0O00 / OoOoOO00 + I1ii11iIi11i % IiII - OoO0O00
   if 19 - 19: I1IiiI
   if 99 - 99: OOooOOo - OOooOOo
 if ( ooOOO00Ooo0 ) : return ( I1111Ii1II1I )
 if 98 - 98: o0oOOo0O0Ooo + O0 * oO0o - i11iIiiIii
 if 83 - 83: o0oOOo0O0Ooo
 if 23 - 23: o0oOOo0O0Ooo . I11i
 if 67 - 67: iII111i
 if 52 - 52: IiII . OoooooooOO
 if 34 - 34: o0oOOo0O0Ooo / IiII . OoooooooOO . Oo0Ooo / ooOoO0o + O0
 if 38 - 38: I11i
 if 66 - 66: II111iiii
 if 57 - 57: OoO0O00 / Oo0Ooo % I1IiiI * I1ii11iIi11i
 if 68 - 68: iII111i - o0oOOo0O0Ooo - OoO0O00 . O0 - i11iIiiIii
 I1111Ii1II1I = [ ]
 for o0OO0O0OoOo0 in registered_rloc_set :
  if ( o0OO0O0OoOo0 . rloc . is_private_address ( ) ) : I1111Ii1II1I . append ( o0OO0O0OoOo0 )
  if 2 - 2: I1ii11iIi11i * i1IIi
 I1111Ii1II1I += oo00
 return ( I1111Ii1II1I )
 if 17 - 17: I1ii11iIi11i * Ii1I % Oo0Ooo * I1Ii111 + OoO0O00 . OoooooooOO
 if 60 - 60: Ii1I . II111iiii
 if 36 - 36: IiII . iII111i * O0 . i1IIi * O0 * I1Ii111
 if 50 - 50: OoooooooOO + o0oOOo0O0Ooo + iIii1I11I1II1 + OOooOOo
 if 90 - 90: Ii1I * I11i % I1Ii111 - I1ii11iIi11i * I1Ii111 % OoO0O00
 if 50 - 50: iIii1I11I1II1
 if 56 - 56: oO0o
 if 55 - 55: iIii1I11I1II1 % oO0o % OOooOOo / I1Ii111 * OoooooooOO / Oo0Ooo
 if 88 - 88: I11i + OoO0O00 . iIii1I11I1II1 . II111iiii
 if 67 - 67: OOooOOo - ooOoO0o % iII111i % IiII
def lisp_store_pubsub_state ( reply_eid , itr_rloc , mr_sport , nonce , ttl , xtr_id ) :
 OOO0OOoo = lisp_pubsub ( itr_rloc , mr_sport , nonce , ttl , xtr_id )
 OOO0OOoo . add ( reply_eid )
 return
 if 5 - 5: o0oOOo0O0Ooo + OoO0O00
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
def lisp_convert_reply_to_notify ( packet ) :
 if 64 - 64: OOooOOo + Oo0Ooo . OoOoOO00 . OOooOOo + i11iIiiIii
 if 7 - 7: ooOoO0o * I11i / iIii1I11I1II1
 if 15 - 15: OoooooooOO / iII111i
 if 40 - 40: o0oOOo0O0Ooo
 OO0Oo0o0o = struct . unpack ( "I" , packet [ 0 : 4 ] ) [ 0 ]
 OO0Oo0o0o = socket . ntohl ( OO0Oo0o0o ) & 0xff
 oO00o0oOoo = packet [ 4 : 12 ]
 packet = packet [ 12 : : ]
 if 36 - 36: OoooooooOO / I11i . Oo0Ooo - I1IiiI + ooOoO0o
 if 63 - 63: iIii1I11I1II1 . I11i
 if 72 - 72: O0
 if 15 - 15: II111iiii / I11i % II111iiii % Ii1I % i11iIiiIii / I1Ii111
 I1I = ( LISP_MAP_NOTIFY << 28 ) | OO0Oo0o0o
 ooo0Oo00O = struct . pack ( "I" , socket . htonl ( I1I ) )
 IiI = struct . pack ( "I" , 0 )
 if 93 - 93: OOooOOo / OoooooooOO % iII111i
 if 47 - 47: o0oOOo0O0Ooo - I1IiiI % O0 % I1Ii111 . O0 . OoOoOO00
 if 95 - 95: o0oOOo0O0Ooo * OOooOOo - iII111i * OoooooooOO - ooOoO0o / I1IiiI
 if 47 - 47: OoO0O00 % I1IiiI / OoOoOO00 - I1Ii111 / I1IiiI
 packet = ooo0Oo00O + oO00o0oOoo + IiI + packet
 return ( packet )
 if 13 - 13: o0oOOo0O0Ooo % ooOoO0o
 if 15 - 15: iII111i * I1IiiI . iIii1I11I1II1 % I1IiiI / O0
 if 47 - 47: OoooooooOO - i11iIiiIii . I1IiiI / i1IIi
 if 74 - 74: OoooooooOO * ooOoO0o
 if 45 - 45: Oo0Ooo + iIii1I11I1II1 . o0oOOo0O0Ooo
 if 50 - 50: o0oOOo0O0Ooo % O0
 if 67 - 67: OoOoOO00
 if 21 - 21: I11i % Oo0Ooo + Oo0Ooo / iIii1I11I1II1 % iIii1I11I1II1
def lisp_notify_subscribers ( lisp_sockets , eid_record , eid , site ) :
 oo0ooooO = eid . print_prefix ( )
 if ( lisp_pubsub_cache . has_key ( oo0ooooO ) == False ) : return
 if 66 - 66: iII111i
 for OOO0OOoo in lisp_pubsub_cache [ oo0ooooO ] . values ( ) :
  Ii1ii1Ii11 = OOO0OOoo . itr
  II11i = OOO0OOoo . port
  O0oOo = red ( Ii1ii1Ii11 . print_address_no_iid ( ) , False )
  oOO0Oo0o0oOOO = bold ( "subscriber" , False )
  I1i1i1 = "0x" + lisp_hex_string ( OOO0OOoo . xtr_id )
  oO00o0oOoo = "0x" + lisp_hex_string ( OOO0OOoo . nonce )
  if 82 - 82: i1IIi + II111iiii / OoOoOO00 - iII111i - OoOoOO00
  lprint ( "    Notify {} {}:{} xtr-id {} for {}, nonce {}" . format ( oOO0Oo0o0oOOO , O0oOo , II11i , I1i1i1 , green ( oo0ooooO , False ) , oO00o0oOoo ) )
  if 10 - 10: Ii1I % II111iiii / OoOoOO00 - o0oOOo0O0Ooo % Oo0Ooo
  if 56 - 56: o0oOOo0O0Ooo . iII111i - OoOoOO00
  lisp_build_map_notify ( lisp_sockets , eid_record , [ oo0ooooO ] , 1 , Ii1ii1Ii11 ,
 II11i , OOO0OOoo . nonce , 0 , 0 , 0 , site , False )
  OOO0OOoo . map_notify_count += 1
  if 41 - 41: iII111i * Oo0Ooo . OoOoOO00 - OoOoOO00 / i1IIi * iIii1I11I1II1
 return
 if 91 - 91: I1Ii111 . OoooooooOO / IiII / I1IiiI
 if 56 - 56: II111iiii + iIii1I11I1II1 / I1Ii111 / I1Ii111 % Oo0Ooo / OoOoOO00
 if 46 - 46: i11iIiiIii + OoO0O00 . ooOoO0o + OoO0O00 % i11iIiiIii
 if 97 - 97: OoooooooOO % IiII * iIii1I11I1II1
 if 97 - 97: iIii1I11I1II1 - I1Ii111 - o0oOOo0O0Ooo * o0oOOo0O0Ooo * OoOoOO00
 if 80 - 80: II111iiii . I1ii11iIi11i % i11iIiiIii / Ii1I / oO0o
 if 100 - 100: Ii1I . OoO0O00 * ooOoO0o
def lisp_process_pubsub ( lisp_sockets , packet , reply_eid , itr_rloc , port , nonce ,
 ttl , xtr_id ) :
 if 4 - 4: i1IIi + OoooooooOO
 if 26 - 26: I1IiiI / II111iiii % I1ii11iIi11i * o0oOOo0O0Ooo . IiII / OoO0O00
 if 10 - 10: i11iIiiIii / i1IIi + O0 - i11iIiiIii % I11i - i1IIi
 if 38 - 38: O0 - I1IiiI + Oo0Ooo + ooOoO0o
 lisp_store_pubsub_state ( reply_eid , itr_rloc , port , nonce , ttl , xtr_id )
 if 56 - 56: I1Ii111 + oO0o / Ii1I + I1Ii111
 III1II1I1iI = green ( reply_eid . print_prefix ( ) , False )
 Ii1ii1Ii11 = red ( itr_rloc . print_address_no_iid ( ) , False )
 I1IIiIIi1Ii1 = bold ( "Map-Notify" , False )
 xtr_id = "0x" + lisp_hex_string ( xtr_id )
 lprint ( "{} pubsub request for {} to ack ITR {} xtr-id: {}" . format ( I1IIiIIi1Ii1 ,
 III1II1I1iI , Ii1ii1Ii11 , xtr_id ) )
 if 9 - 9: I1ii11iIi11i - i1IIi
 if 82 - 82: OOooOOo * OoooooooOO % IiII % OoooooooOO
 if 61 - 61: iII111i
 if 85 - 85: IiII
 packet = lisp_convert_reply_to_notify ( packet )
 lisp_send_map_notify ( lisp_sockets , packet , itr_rloc , port )
 return
 if 4 - 4: i1IIi
 if 11 - 11: I1IiiI * OoooooooOO
 if 20 - 20: OoooooooOO + ooOoO0o . O0 - o0oOOo0O0Ooo * iII111i + Oo0Ooo
 if 82 - 82: I11i % iII111i . OOooOOo * O0 - ooOoO0o
 if 49 - 49: Oo0Ooo * I1ii11iIi11i - i1IIi + OoOoOO00
 if 98 - 98: i11iIiiIii + OoooooooOO / I1IiiI / OOooOOo
 if 6 - 6: I1ii11iIi11i + IiII * oO0o * OoOoOO00
 if 67 - 67: I1Ii111 + OoooooooOO + OoOoOO00 % iIii1I11I1II1 . I1IiiI
def lisp_ms_process_map_request ( lisp_sockets , packet , map_request , mr_source ,
 mr_sport , ecm_source ) :
 if 68 - 68: ooOoO0o
 if 68 - 68: I11i % IiII
 if 1 - 1: I1IiiI + OOooOOo - OOooOOo * O0 + o0oOOo0O0Ooo * OOooOOo
 if 48 - 48: ooOoO0o - iII111i + I1ii11iIi11i * I1Ii111 % ooOoO0o * OoO0O00
 if 28 - 28: i1IIi / iII111i + OOooOOo
 if 89 - 89: Oo0Ooo + II111iiii * OoO0O00 + Oo0Ooo % II111iiii
 III1II1I1iI = map_request . target_eid
 oO0000O0o = map_request . target_group
 oo0ooooO = lisp_print_eid_tuple ( III1II1I1iI , oO0000O0o )
 I1IIIIII = map_request . itr_rlocs [ 0 ]
 I1i1i1 = map_request . xtr_id
 oO00o0oOoo = map_request . nonce
 i1ii1iIIIiI1 = LISP_NO_ACTION
 OOO0OOoo = map_request . subscribe_bit
 if 59 - 59: O0 + Oo0Ooo
 if 63 - 63: OoO0O00 / I1IiiI / oO0o . Ii1I / i1IIi
 if 50 - 50: I11i . I11i % I1IiiI - i1IIi
 if 63 - 63: OoO0O00 . iII111i
 if 28 - 28: ooOoO0o . Oo0Ooo - OoooooooOO - I1Ii111 - OoooooooOO - oO0o
 I1i11 = True
 i11iI111 = ( lisp_get_eid_hash ( III1II1I1iI ) != None )
 if ( i11iI111 ) :
  I111II11I = map_request . map_request_signature
  if ( I111II11I == None ) :
   I1i11 = False
   lprint ( ( "EID-crypto-hash signature verification {}, " + "no signature found" ) . format ( bold ( "failed" , False ) ) )
   if 32 - 32: I11i
  else :
   i11iii1 = map_request . signature_eid
   iIII , iiI111 , I1i11 = lisp_lookup_public_key ( i11iii1 )
   if ( I1i11 ) :
    I1i11 = map_request . verify_map_request_sig ( iiI111 )
   else :
    lprint ( "Public-key lookup failed for sig-eid {}, hash-eid {}" . format ( i11iii1 . print_address ( ) , iIII . print_address ( ) ) )
    if 40 - 40: i1IIi . iIii1I11I1II1 * OoOoOO00
    if 83 - 83: iIii1I11I1II1 + Ii1I - Ii1I % II111iiii
   ooOI1i = bold ( "passed" , False ) if I1i11 else bold ( "failed" , False )
   lprint ( "EID-crypto-hash signature verification {}" . format ( ooOI1i ) )
   if 40 - 40: IiII / oO0o + OoooooooOO / iII111i / II111iiii + i1IIi
   if 33 - 33: I11i + I1ii11iIi11i + i11iIiiIii * I1IiiI % oO0o % OoooooooOO
   if 4 - 4: OoO0O00 . I1IiiI - O0 % iII111i . OOooOOo
 if ( OOO0OOoo and I1i11 == False ) :
  OOO0OOoo = False
  lprint ( "Suppress creating pubsub state due to signature failure" )
  if 69 - 69: OoooooooOO
  if 19 - 19: O0 + iIii1I11I1II1 / OoOoOO00 / oO0o + II111iiii - OOooOOo
  if 70 - 70: i1IIi * o0oOOo0O0Ooo + I1Ii111 . ooOoO0o - O0 + i11iIiiIii
  if 81 - 81: iIii1I11I1II1 - OoO0O00 . i11iIiiIii
  if 4 - 4: o0oOOo0O0Ooo / OoO0O00 - I11i
  if 52 - 52: II111iiii . iII111i
  if 36 - 36: I1IiiI * II111iiii
  if 68 - 68: oO0o * o0oOOo0O0Ooo + OoooooooOO - I1ii11iIi11i * i1IIi % OOooOOo
  if 39 - 39: I1Ii111 / I11i + oO0o / I1Ii111 % IiII * I1ii11iIi11i
  if 66 - 66: I1ii11iIi11i * ooOoO0o . i11iIiiIii * Oo0Ooo - I11i . I1IiiI
  if 43 - 43: I11i . iII111i . IiII - oO0o
  if 60 - 60: i1IIi + iII111i * i1IIi . iII111i
  if 40 - 40: i1IIi . OoO0O00
  if 65 - 65: Oo0Ooo
 O0ooo0OOo0o = I1IIIIII if ( I1IIIIII . afi == ecm_source . afi ) else ecm_source
 if 3 - 3: O0
 o0O0o = lisp_site_eid_lookup ( III1II1I1iI , oO0000O0o , False )
 if 88 - 88: i1IIi . I1Ii111 * o0oOOo0O0Ooo + i1IIi % o0oOOo0O0Ooo
 if ( o0O0o == None or o0O0o . is_star_g ( ) ) :
  I1II1i1Ii = bold ( "Site not found" , False )
  lprint ( "{} for requested EID {}" . format ( I1II1i1Ii ,
 green ( oo0ooooO , False ) ) )
  if 53 - 53: IiII
  if 54 - 54: OoooooooOO * iIii1I11I1II1 - I1Ii111
  if 86 - 86: O0 * IiII + OoOoOO00 + OoO0O00
  if 53 - 53: I1IiiI % i11iIiiIii + o0oOOo0O0Ooo . I1ii11iIi11i
  lisp_send_negative_map_reply ( lisp_sockets , III1II1I1iI , oO0000O0o , oO00o0oOoo , I1IIIIII ,
 mr_sport , 15 , I1i1i1 , OOO0OOoo )
  if 73 - 73: iII111i - o0oOOo0O0Ooo / OOooOOo + iII111i + o0oOOo0O0Ooo % II111iiii
  return ( [ III1II1I1iI , oO0000O0o , LISP_DDT_ACTION_SITE_NOT_FOUND ] )
  if 74 - 74: I11i * iIii1I11I1II1 - OoO0O00 / i1IIi / OoO0O00 / IiII
  if 60 - 60: oO0o % I1Ii111 % Oo0Ooo
 o00oo = o0O0o . print_eid_tuple ( )
 II1II1i1IIII = o0O0o . site . site_name
 if 88 - 88: iIii1I11I1II1 * OoO0O00 / IiII
 if 74 - 74: I1ii11iIi11i / i11iIiiIii - II111iiii . Oo0Ooo / ooOoO0o
 if 55 - 55: OoO0O00 % IiII
 if 93 - 93: OoO0O00 . I1ii11iIi11i / OOooOOo % OoooooooOO + i1IIi + I1Ii111
 if 94 - 94: II111iiii + i11iIiiIii % Ii1I / ooOoO0o * OoOoOO00
 if ( i11iI111 == False and o0O0o . require_signature ) :
  I111II11I = map_request . map_request_signature
  i11iii1 = map_request . signature_eid
  if ( I111II11I == None or i11iii1 . is_null ( ) ) :
   lprint ( "Signature required for site {}" . format ( II1II1i1IIII ) )
   I1i11 = False
  else :
   i11iii1 = map_request . signature_eid
   iIII , iiI111 , I1i11 = lisp_lookup_public_key ( i11iii1 )
   if ( I1i11 ) :
    I1i11 = map_request . verify_map_request_sig ( iiI111 )
   else :
    lprint ( "Public-key lookup failed for sig-eid {}, hash-eid {}" . format ( i11iii1 . print_address ( ) , iIII . print_address ( ) ) )
    if 68 - 68: O0 / Oo0Ooo / iIii1I11I1II1
    if 63 - 63: I1Ii111 + iII111i
   ooOI1i = bold ( "passed" , False ) if I1i11 else bold ( "failed" , False )
   lprint ( "Required signature verification {}" . format ( ooOI1i ) )
   if 6 - 6: I1ii11iIi11i + Ii1I
   if 36 - 36: iII111i + iII111i * OoO0O00 * I1ii11iIi11i
   if 97 - 97: ooOoO0o + OOooOOo
   if 70 - 70: o0oOOo0O0Ooo + Ii1I - i11iIiiIii + I11i * o0oOOo0O0Ooo . Ii1I
   if 6 - 6: Oo0Ooo + I1IiiI
   if 48 - 48: oO0o . I1ii11iIi11i
 if ( I1i11 and o0O0o . registered == False ) :
  lprint ( "Site '{}' with EID-prefix {} is not registered for EID {}" . format ( II1II1i1IIII , green ( o00oo , False ) , green ( oo0ooooO , False ) ) )
  if 59 - 59: IiII - Ii1I
  if 62 - 62: OOooOOo * o0oOOo0O0Ooo + IiII * o0oOOo0O0Ooo * i11iIiiIii - O0
  if 37 - 37: I1ii11iIi11i - Oo0Ooo . i11iIiiIii / i11iIiiIii + oO0o
  if 19 - 19: i1IIi / i1IIi - OoooooooOO - OOooOOo . i1IIi
  if 57 - 57: OOooOOo / I1ii11iIi11i * oO0o
  if 53 - 53: o0oOOo0O0Ooo * Ii1I
  if ( o0O0o . accept_more_specifics == False ) :
   III1II1I1iI = o0O0o . eid
   oO0000O0o = o0O0o . group
   if 42 - 42: I11i + iII111i / iIii1I11I1II1
   if 1 - 1: O0 - II111iiii
   if 75 - 75: II111iiii / OoO0O00 % II111iiii
   if 3 - 3: Ii1I - Ii1I % I1ii11iIi11i
   if 44 - 44: OOooOOo - o0oOOo0O0Ooo
  I1i11iiIiIi = 1
  if ( o0O0o . force_ttl != None ) :
   I1i11iiIiIi = o0O0o . force_ttl | 0x80000000
   if 69 - 69: IiII + I1ii11iIi11i / o0oOOo0O0Ooo / OOooOOo
   if 31 - 31: oO0o + I1ii11iIi11i * i1IIi % I1IiiI % I1IiiI + iIii1I11I1II1
   if 62 - 62: OoooooooOO
   if 38 - 38: iII111i % iII111i * ooOoO0o / OoO0O00 + ooOoO0o
   if 52 - 52: ooOoO0o . iIii1I11I1II1 / iIii1I11I1II1 % oO0o - oO0o * II111iiii
  lisp_send_negative_map_reply ( lisp_sockets , III1II1I1iI , oO0000O0o , oO00o0oOoo , I1IIIIII ,
 mr_sport , I1i11iiIiIi , I1i1i1 , OOO0OOoo )
  if 57 - 57: I1Ii111
  return ( [ III1II1I1iI , oO0000O0o , LISP_DDT_ACTION_MS_NOT_REG ] )
  if 23 - 23: I1ii11iIi11i + II111iiii
  if 99 - 99: o0oOOo0O0Ooo . I1IiiI + o0oOOo0O0Ooo * o0oOOo0O0Ooo / O0
  if 27 - 27: OOooOOo - I1Ii111
  if 33 - 33: OOooOOo - Ii1I - iII111i + I1ii11iIi11i - i11iIiiIii
  if 89 - 89: iIii1I11I1II1 * I11i + OOooOOo
 iiIiIIi1I = False
 Ooo0 = ""
 ooOooOo = False
 if ( o0O0o . force_nat_proxy_reply ) :
  Ooo0 = ", nat-forced"
  iiIiIIi1I = True
  ooOooOo = True
 elif ( o0O0o . force_proxy_reply ) :
  Ooo0 = ", forced"
  ooOooOo = True
 elif ( o0O0o . proxy_reply_requested ) :
  Ooo0 = ", requested"
  ooOooOo = True
 elif ( map_request . pitr_bit and o0O0o . pitr_proxy_reply_drop ) :
  Ooo0 = ", drop-to-pitr"
  i1ii1iIIIiI1 = LISP_DROP_ACTION
 elif ( o0O0o . proxy_reply_action != "" ) :
  i1ii1iIIIiI1 = o0O0o . proxy_reply_action
  Ooo0 = ", forced, action {}" . format ( i1ii1iIIIiI1 )
  i1ii1iIIIiI1 = LISP_DROP_ACTION if ( i1ii1iIIIiI1 == "drop" ) else LISP_NATIVE_FORWARD_ACTION
  if 98 - 98: i11iIiiIii * Oo0Ooo + iIii1I11I1II1
  if 23 - 23: i11iIiiIii - II111iiii . OoooooooOO / I1ii11iIi11i / OoOoOO00 * OoO0O00
  if 72 - 72: OOooOOo * OOooOOo
  if 5 - 5: o0oOOo0O0Ooo / i11iIiiIii
  if 5 - 5: oO0o % iII111i . Oo0Ooo . O0 . OoOoOO00 / iII111i
  if 78 - 78: Ii1I - I1ii11iIi11i + iIii1I11I1II1 + OoooooooOO . OoO0O00 - ooOoO0o
  if 81 - 81: o0oOOo0O0Ooo * OoooooooOO
 II11iiiIi = False
 oOo0oOiiiiii1iII1ii = None
 if ( ooOooOo and lisp_policies . has_key ( o0O0o . policy ) ) :
  OoOOOOo = lisp_policies [ o0O0o . policy ]
  if ( OoOOOOo . match_policy_map_request ( map_request , mr_source ) ) : oOo0oOiiiiii1iII1ii = OoOOOOo
  if 9 - 9: o0oOOo0O0Ooo + iIii1I11I1II1 + OoOoOO00
  if ( oOo0oOiiiiii1iII1ii ) :
   oOo0oO = bold ( "matched" , False )
   lprint ( "Map-Request {} policy '{}', set-action '{}'" . format ( oOo0oO ,
 OoOOOOo . policy_name , OoOOOOo . set_action ) )
  else :
   oOo0oO = bold ( "no match" , False )
   lprint ( "Map-Request {} for policy '{}', implied drop" . format ( oOo0oO ,
 OoOOOOo . policy_name ) )
   II11iiiIi = True
   if 34 - 34: OoOoOO00
   if 14 - 14: i1IIi
   if 63 - 63: OoOoOO00 . i11iIiiIii / IiII
 if ( Ooo0 != "" ) :
  lprint ( "Proxy-replying for EID {}, found site '{}' EID-prefix {}{}" . format ( green ( oo0ooooO , False ) , II1II1i1IIII , green ( o00oo , False ) ,
  # iII111i % OoO0O00 % OoOoOO00
 Ooo0 ) )
  if 43 - 43: OoOoOO00
  I1111Ii1II1I = o0O0o . registered_rlocs
  I1i11iiIiIi = 1440
  if ( iiIiIIi1I ) :
   if ( o0O0o . site_id != 0 ) :
    i1iI = map_request . source_eid
    I1111Ii1II1I = lisp_get_private_rloc_set ( o0O0o , i1iI , oO0000O0o )
    if 87 - 87: ooOoO0o % Ii1I + i1IIi - OOooOOo
   if ( I1111Ii1II1I == o0O0o . registered_rlocs ) :
    II1111 = ( o0O0o . group . is_null ( ) == False )
    iI111iiiI1 = lisp_get_partial_rloc_set ( I1111Ii1II1I , O0ooo0OOo0o , II1111 )
    if ( iI111iiiI1 != I1111Ii1II1I ) :
     I1i11iiIiIi = 15
     I1111Ii1II1I = iI111iiiI1
     if 42 - 42: OoO0O00 . iIii1I11I1II1 / iIii1I11I1II1
     if 53 - 53: II111iiii
     if 40 - 40: Ii1I % oO0o
     if 69 - 69: iIii1I11I1II1 - O0 . I1Ii111 % I1IiiI / o0oOOo0O0Ooo
     if 78 - 78: oO0o
     if 20 - 20: i1IIi + i1IIi * i1IIi
     if 32 - 32: I1IiiI + IiII + iII111i . iIii1I11I1II1 * Ii1I
     if 27 - 27: oO0o + Ii1I . i11iIiiIii
  if ( o0O0o . force_ttl != None ) :
   I1i11iiIiIi = o0O0o . force_ttl | 0x80000000
   if 97 - 97: iII111i . I1IiiI
   if 71 - 71: OOooOOo - IiII % oO0o * I1ii11iIi11i
   if 48 - 48: o0oOOo0O0Ooo * iIii1I11I1II1 + Oo0Ooo
   if 45 - 45: oO0o
   if 50 - 50: Ii1I * Ii1I / O0 . Oo0Ooo + iII111i
   if 9 - 9: OoooooooOO % O0 % I1ii11iIi11i
  if ( oOo0oOiiiiii1iII1ii ) :
   if ( oOo0oOiiiiii1iII1ii . set_record_ttl ) :
    I1i11iiIiIi = oOo0oOiiiiii1iII1ii . set_record_ttl
    lprint ( "Policy set-record-ttl to {}" . format ( I1i11iiIiIi ) )
    if 100 - 100: i11iIiiIii - iII111i - I11i
   if ( oOo0oOiiiiii1iII1ii . set_action == "drop" ) :
    lprint ( "Policy set-action drop, send negative Map-Reply" )
    i1ii1iIIIiI1 = LISP_POLICY_DENIED_ACTION
    I1111Ii1II1I = [ ]
   else :
    II1iIiIiIIi = oOo0oOiiiiii1iII1ii . set_policy_map_reply ( )
    if ( II1iIiIiIIi ) : I1111Ii1II1I = [ II1iIiIiIIi ]
    if 5 - 5: oO0o % IiII * iII111i
    if 98 - 98: iII111i / OOooOOo + IiII
    if 100 - 100: II111iiii . i11iIiiIii / oO0o - OOooOOo + OoOoOO00 % I1ii11iIi11i
  if ( II11iiiIi ) :
   lprint ( "Implied drop action, send negative Map-Reply" )
   i1ii1iIIIiI1 = LISP_POLICY_DENIED_ACTION
   I1111Ii1II1I = [ ]
   if 82 - 82: ooOoO0o % OOooOOo % Ii1I
   if 82 - 82: I1ii11iIi11i
  Oo00o0000O = o0O0o . echo_nonce_capable
  if 52 - 52: i11iIiiIii % I1Ii111 - iII111i / O0 - I1ii11iIi11i / iII111i
  if 7 - 7: OoooooooOO . OOooOOo . OOooOOo
  if 53 - 53: OOooOOo * OoOoOO00 % iII111i
  if 86 - 86: OOooOOo . OOooOOo + IiII - I1ii11iIi11i . OoO0O00
  if ( I1i11 ) :
   OooOooOO0000 = o0O0o . eid
   i11Ii111I11 = o0O0o . group
  else :
   OooOooOO0000 = III1II1I1iI
   i11Ii111I11 = oO0000O0o
   i1ii1iIIIiI1 = LISP_AUTH_FAILURE_ACTION
   I1111Ii1II1I = [ ]
   if 79 - 79: i11iIiiIii + OoO0O00 + IiII % I11i
   if 42 - 42: iIii1I11I1II1 + iIii1I11I1II1 . I11i
   if 27 - 27: OoOoOO00 * Oo0Ooo - ooOoO0o
   if 93 - 93: OOooOOo * o0oOOo0O0Ooo / oO0o + Ii1I - OoooooooOO
   if 15 - 15: O0
   if 21 - 21: OoO0O00 * iIii1I11I1II1 - iIii1I11I1II1 % OoO0O00 . I1ii11iIi11i
  packet = lisp_build_map_reply ( OooOooOO0000 , i11Ii111I11 , I1111Ii1II1I ,
 oO00o0oOoo , i1ii1iIIIiI1 , I1i11iiIiIi , False , None , Oo00o0000O , False )
  if 19 - 19: i1IIi % Ii1I . OoOoOO00
  if ( OOO0OOoo ) :
   lisp_process_pubsub ( lisp_sockets , packet , OooOooOO0000 , I1IIIIII ,
 mr_sport , oO00o0oOoo , I1i11iiIiIi , I1i1i1 )
  else :
   lisp_send_map_reply ( lisp_sockets , packet , I1IIIIII , mr_sport )
   if 22 - 22: iIii1I11I1II1 + Ii1I
   if 73 - 73: I1IiiI / OoO0O00 / OoooooooOO
  return ( [ o0O0o . eid , o0O0o . group , LISP_DDT_ACTION_MS_ACK ] )
  if 14 - 14: ooOoO0o % o0oOOo0O0Ooo / I1ii11iIi11i . IiII + I1ii11iIi11i
  if 30 - 30: I1ii11iIi11i + iIii1I11I1II1 . I1ii11iIi11i
  if 9 - 9: I1IiiI - Ii1I * II111iiii - I11i
  if 85 - 85: oO0o % ooOoO0o / OOooOOo
  if 50 - 50: O0 * O0 / iIii1I11I1II1
 oo0oooooOo000 = len ( o0O0o . registered_rlocs )
 if ( oo0oooooOo000 == 0 ) :
  lprint ( "Requested EID {} found site '{}' with EID-prefix {} with " + "no registered RLOCs" . format ( green ( oo0ooooO , False ) , II1II1i1IIII ,
  # I1IiiI / I1IiiI
 green ( o00oo , False ) ) )
  return ( [ o0O0o . eid , o0O0o . group , LISP_DDT_ACTION_MS_ACK ] )
  if 51 - 51: I1IiiI . IiII + ooOoO0o . oO0o . o0oOOo0O0Ooo
  if 74 - 74: IiII - OoOoOO00
  if 36 - 36: II111iiii * iIii1I11I1II1 / o0oOOo0O0Ooo
  if 89 - 89: iII111i * I1IiiI - Ii1I + I1Ii111 / oO0o
  if 28 - 28: I11i . iIii1I11I1II1 . I11i + oO0o + I1IiiI
 oo00O0OO0Ooo0 = map_request . target_eid if map_request . source_eid . is_null ( ) else map_request . source_eid
 if 63 - 63: ooOoO0o + i1IIi
 iIII1I1i = map_request . target_eid . hash_address ( oo00O0OO0Ooo0 )
 iIII1I1i %= oo0oooooOo000
 IiiI1iIii = o0O0o . registered_rlocs [ iIII1I1i ]
 if 98 - 98: IiII * OoooooooOO . iII111i
 if ( IiiI1iIii . rloc . is_null ( ) ) :
  lprint ( ( "Suppress forwarding Map-Request for EID {} at site '{}' " + "EID-prefix {}, no RLOC address" ) . format ( green ( oo0ooooO , False ) ,
  # OoO0O00 / I1Ii111 . ooOoO0o
 II1II1i1IIII , green ( o00oo , False ) ) )
 else :
  lprint ( ( "Forwarding Map-Request for EID {} to ETR {} at site '{}' " + "EID-prefix {}" ) . format ( green ( oo0ooooO , False ) ,
  # II111iiii + I11i + OOooOOo / i11iIiiIii - iII111i
 red ( IiiI1iIii . rloc . print_address ( ) , False ) , II1II1i1IIII ,
 green ( o00oo , False ) ) )
  if 9 - 9: i1IIi - I1Ii111 + I1Ii111
  if 81 - 81: II111iiii % I11i % O0 . I1Ii111 % ooOoO0o - O0
  if 58 - 58: OoooooooOO . II111iiii . O0 % I1Ii111 / OoooooooOO
  if 64 - 64: Oo0Ooo + oO0o . OoO0O00
  lisp_send_ecm ( lisp_sockets , packet , map_request . source_eid , mr_sport ,
 map_request . target_eid , IiiI1iIii . rloc , to_etr = True )
  if 67 - 67: I11i
 return ( [ o0O0o . eid , o0O0o . group , LISP_DDT_ACTION_MS_ACK ] )
 if 91 - 91: OOooOOo / OoO0O00
 if 36 - 36: I1IiiI . iII111i * I1Ii111 . IiII % I1ii11iIi11i
 if 44 - 44: I11i % I1ii11iIi11i - OoooooooOO % iII111i
 if 60 - 60: IiII % oO0o
 if 11 - 11: I1Ii111 - II111iiii
 if 12 - 12: i11iIiiIii
 if 9 - 9: OOooOOo * I1ii11iIi11i + iIii1I11I1II1 / OoO0O00 * OoooooooOO
def lisp_ddt_process_map_request ( lisp_sockets , map_request , ecm_source , port ) :
 if 91 - 91: i11iIiiIii % IiII + oO0o . I1IiiI - I1IiiI
 if 62 - 62: Oo0Ooo * II111iiii + o0oOOo0O0Ooo . OoOoOO00
 if 94 - 94: Oo0Ooo / I1IiiI * iIii1I11I1II1 - OoO0O00
 if 96 - 96: ooOoO0o - OoooooooOO * iIii1I11I1II1 . IiII - O0
 III1II1I1iI = map_request . target_eid
 oO0000O0o = map_request . target_group
 oo0ooooO = lisp_print_eid_tuple ( III1II1I1iI , oO0000O0o )
 oO00o0oOoo = map_request . nonce
 i1ii1iIIIiI1 = LISP_DDT_ACTION_NULL
 if 7 - 7: iIii1I11I1II1 . OoO0O00
 if 88 - 88: i1IIi * II111iiii / i11iIiiIii % IiII . IiII
 if 93 - 93: OoOoOO00 * i1IIi . Ii1I
 if 2 - 2: i1IIi
 if 84 - 84: i1IIi / Ii1I + OoOoOO00 % Ii1I . oO0o
 OOOOO0OOO = None
 if ( lisp_i_am_ms ) :
  o0O0o = lisp_site_eid_lookup ( III1II1I1iI , oO0000O0o , False )
  if ( o0O0o == None ) : return
  if 6 - 6: IiII * iIii1I11I1II1 + OOooOOo . OoooooooOO
  if ( o0O0o . registered ) :
   i1ii1iIIIiI1 = LISP_DDT_ACTION_MS_ACK
   I1i11iiIiIi = 1440
  else :
   III1II1I1iI , oO0000O0o , i1ii1iIIIiI1 = lisp_ms_compute_neg_prefix ( III1II1I1iI , oO0000O0o )
   i1ii1iIIIiI1 = LISP_DDT_ACTION_MS_NOT_REG
   I1i11iiIiIi = 1
   if 30 - 30: iII111i . IiII % O0 + iII111i % Ii1I
 else :
  OOOOO0OOO = lisp_ddt_cache_lookup ( III1II1I1iI , oO0000O0o , False )
  if ( OOOOO0OOO == None ) :
   i1ii1iIIIiI1 = LISP_DDT_ACTION_NOT_AUTH
   I1i11iiIiIi = 0
   lprint ( "DDT delegation entry not found for EID {}" . format ( green ( oo0ooooO , False ) ) )
   if 72 - 72: II111iiii * ooOoO0o + I1IiiI
  elif ( OOOOO0OOO . is_auth_prefix ( ) ) :
   if 19 - 19: OoO0O00 * ooOoO0o % I1ii11iIi11i
   if 21 - 21: OoO0O00 * I11i
   if 76 - 76: I1IiiI - I1ii11iIi11i / I1ii11iIi11i . o0oOOo0O0Ooo % OoooooooOO
   if 39 - 39: OoooooooOO % iII111i
   i1ii1iIIIiI1 = LISP_DDT_ACTION_DELEGATION_HOLE
   I1i11iiIiIi = 15
   o0o0O0 = OOOOO0OOO . print_eid_tuple ( )
   lprint ( ( "DDT delegation entry not found but auth-prefix {} " + "found for EID {}" ) . format ( o0o0O0 ,
   # o0oOOo0O0Ooo / I1ii11iIi11i - O0 . I1ii11iIi11i + OoooooooOO
 green ( oo0ooooO , False ) ) )
   if 9 - 9: I11i / I11i
   if ( oO0000O0o . is_null ( ) ) :
    III1II1I1iI = lisp_ddt_compute_neg_prefix ( III1II1I1iI , OOOOO0OOO ,
 lisp_ddt_cache )
   else :
    oO0000O0o = lisp_ddt_compute_neg_prefix ( oO0000O0o , OOOOO0OOO ,
 lisp_ddt_cache )
    III1II1I1iI = lisp_ddt_compute_neg_prefix ( III1II1I1iI , OOOOO0OOO ,
 OOOOO0OOO . source_cache )
    if 35 - 35: ooOoO0o * OoOoOO00 . I1ii11iIi11i . I1Ii111 * I1ii11iIi11i
   OOOOO0OOO = None
  else :
   o0o0O0 = OOOOO0OOO . print_eid_tuple ( )
   lprint ( "DDT delegation entry {} found for EID {}" . format ( o0o0O0 , green ( oo0ooooO , False ) ) )
   if 66 - 66: Oo0Ooo % OoOoOO00 % I11i - OoO0O00
   I1i11iiIiIi = 1440
   if 77 - 77: iII111i * I1Ii111
   if 36 - 36: I1ii11iIi11i % II111iiii % I1Ii111 / I1ii11iIi11i
   if 34 - 34: OoooooooOO * i11iIiiIii
   if 33 - 33: II111iiii
   if 59 - 59: iIii1I11I1II1 % I11i
   if 93 - 93: I1ii11iIi11i
 I111 = lisp_build_map_referral ( III1II1I1iI , oO0000O0o , OOOOO0OOO , i1ii1iIIIiI1 , I1i11iiIiIi , oO00o0oOoo )
 oO00o0oOoo = map_request . nonce >> 32
 if ( map_request . nonce != 0 and oO00o0oOoo != 0xdfdf0e1d ) : port = LISP_CTRL_PORT
 lisp_send_map_referral ( lisp_sockets , I111 , ecm_source , port )
 return
 if 50 - 50: ooOoO0o % OoO0O00 % OoO0O00
 if 36 - 36: I1IiiI * O0 . IiII / I1Ii111
 if 15 - 15: I11i + iII111i
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
def lisp_find_negative_mask_len ( eid , entry_prefix , neg_prefix ) :
 II = eid . hash_address ( entry_prefix )
 oOo0oooO0 = eid . addr_length ( ) * 8
 i1iIi = 0
 if 81 - 81: O0 + oO0o
 if 12 - 12: I1IiiI
 if 34 - 34: iIii1I11I1II1 - Ii1I % OOooOOo * i1IIi . ooOoO0o
 if 43 - 43: iIii1I11I1II1 % Oo0Ooo . I11i % I1ii11iIi11i % I1Ii111 % I1ii11iIi11i
 for i1iIi in range ( oOo0oooO0 ) :
  OOOOOoOOo0O = 1 << ( oOo0oooO0 - i1iIi - 1 )
  if ( II & OOOOOoOOo0O ) : break
  if 9 - 9: OoOoOO00 / OoooooooOO - OoOoOO00 / Oo0Ooo . I1IiiI - I11i
  if 41 - 41: oO0o % iII111i % iIii1I11I1II1 / I1ii11iIi11i
 if ( i1iIi > neg_prefix . mask_len ) : neg_prefix . mask_len = i1iIi
 return
 if 69 - 69: OOooOOo * I11i % i11iIiiIii
 if 63 - 63: OoOoOO00 + I1IiiI / I1ii11iIi11i / o0oOOo0O0Ooo % I1IiiI
 if 67 - 67: I1Ii111 . oO0o % I1ii11iIi11i % OOooOOo + I1IiiI
 if 4 - 4: iII111i - i11iIiiIii * ooOoO0o
 if 74 - 74: Oo0Ooo . OOooOOo + OOooOOo / OOooOOo + I1IiiI + i1IIi
 if 32 - 32: i11iIiiIii % Ii1I
 if 92 - 92: OoOoOO00 % o0oOOo0O0Ooo % ooOoO0o - IiII - oO0o
 if 90 - 90: ooOoO0o
 if 11 - 11: OoOoOO00 % OOooOOo . i11iIiiIii * I1IiiI % O0 % iIii1I11I1II1
 if 18 - 18: Oo0Ooo % OOooOOo + IiII
def lisp_neg_prefix_walk ( entry , parms ) :
 III1II1I1iI , I1iIii1ii , Ooooo = parms
 if 47 - 47: OoooooooOO / i11iIiiIii + II111iiii / i11iIiiIii % i1IIi
 if ( I1iIii1ii == None ) :
  if ( entry . eid . instance_id != III1II1I1iI . instance_id ) :
   return ( [ True , parms ] )
   if 31 - 31: o0oOOo0O0Ooo + IiII * OOooOOo
  if ( entry . eid . afi != III1II1I1iI . afi ) : return ( [ True , parms ] )
 else :
  if ( entry . eid . is_more_specific ( I1iIii1ii ) == False ) :
   return ( [ True , parms ] )
   if 26 - 26: Ii1I % O0 - i1IIi % iII111i * OoO0O00
   if 60 - 60: I1ii11iIi11i * iII111i / OoOoOO00 . o0oOOo0O0Ooo / iIii1I11I1II1
   if 94 - 94: OoO0O00 . ooOoO0o
   if 25 - 25: I1Ii111 % OOooOOo
   if 82 - 82: Ii1I
   if 17 - 17: iII111i . i1IIi . i1IIi
 lisp_find_negative_mask_len ( III1II1I1iI , entry . eid , Ooooo )
 return ( [ True , parms ] )
 if 76 - 76: OoooooooOO % IiII
 if 81 - 81: iII111i . OOooOOo * i1IIi
 if 14 - 14: oO0o
 if 16 - 16: iII111i
 if 26 - 26: iII111i . oO0o * i11iIiiIii . iIii1I11I1II1
 if 74 - 74: Ii1I / iIii1I11I1II1 + OOooOOo . II111iiii
 if 65 - 65: OOooOOo * I11i * Oo0Ooo
 if 21 - 21: Ii1I . iIii1I11I1II1
def lisp_ddt_compute_neg_prefix ( eid , ddt_entry , cache ) :
 if 84 - 84: OOooOOo
 if 67 - 67: I1IiiI % OoO0O00 % o0oOOo0O0Ooo % IiII
 if 33 - 33: ooOoO0o % I1IiiI
 if 98 - 98: oO0o . o0oOOo0O0Ooo + II111iiii
 if ( eid . is_binary ( ) == False ) : return ( eid )
 if 62 - 62: ooOoO0o - OoooooooOO / I1ii11iIi11i / iII111i - o0oOOo0O0Ooo
 Ooooo = lisp_address ( eid . afi , "" , 0 , 0 )
 Ooooo . copy_address ( eid )
 Ooooo . mask_len = 0
 if 70 - 70: oO0o % OoooooooOO * I1IiiI - OoOoOO00 * OoOoOO00 . OOooOOo
 I11I111Ii1II = ddt_entry . print_eid_tuple ( )
 I1iIii1ii = ddt_entry . eid
 if 29 - 29: II111iiii - i11iIiiIii - iII111i + i11iIiiIii . IiII - I1Ii111
 if 40 - 40: I11i . iII111i + OoOoOO00 % I1ii11iIi11i
 if 79 - 79: I1Ii111 - OOooOOo * I1ii11iIi11i + i11iIiiIii . iII111i
 if 3 - 3: Oo0Ooo
 if 81 - 81: OoO0O00 / OoO0O00 . I1ii11iIi11i
 eid , I1iIii1ii , Ooooo = cache . walk_cache ( lisp_neg_prefix_walk ,
 ( eid , I1iIii1ii , Ooooo ) )
 if 100 - 100: iIii1I11I1II1 % II111iiii - I1ii11iIi11i . iIii1I11I1II1 + IiII % iIii1I11I1II1
 if 48 - 48: Ii1I % i1IIi
 if 38 - 38: OOooOOo / I1ii11iIi11i % oO0o / o0oOOo0O0Ooo
 if 54 - 54: OoOoOO00 * OoooooooOO - OoO0O00 * OoOoOO00 % I1ii11iIi11i * I11i
 Ooooo . mask_address ( Ooooo . mask_len )
 if 34 - 34: I11i - oO0o + I11i * OoooooooOO * I11i
 lprint ( ( "Least specific prefix computed from ddt-cache for EID {} " + "using auth-prefix {} is {}" ) . format ( green ( eid . print_address ( ) , False ) ,
 # IiII + IiII % OoO0O00 % i1IIi . IiII
 I11I111Ii1II , Ooooo . print_prefix ( ) ) )
 return ( Ooooo )
 if 94 - 94: i1IIi . ooOoO0o
 if 40 - 40: Oo0Ooo . I1Ii111 + i11iIiiIii / OOooOOo
 if 98 - 98: I1IiiI * Oo0Ooo
 if 9 - 9: O0 / i11iIiiIii . iIii1I11I1II1 . IiII
 if 14 - 14: OoOoOO00 . OOooOOo - Oo0Ooo + I1Ii111 % ooOoO0o
 if 95 - 95: OoO0O00 * II111iiii + i1IIi
 if 22 - 22: Ii1I / ooOoO0o % I11i + OoO0O00 . ooOoO0o
 if 61 - 61: O0 - iIii1I11I1II1 * Oo0Ooo . Ii1I + O0
def lisp_ms_compute_neg_prefix ( eid , group ) :
 Ooooo = lisp_address ( eid . afi , "" , 0 , 0 )
 Ooooo . copy_address ( eid )
 Ooooo . mask_len = 0
 I1I1I = lisp_address ( group . afi , "" , 0 , 0 )
 I1I1I . copy_address ( group )
 I1I1I . mask_len = 0
 I1iIii1ii = None
 if 79 - 79: I1IiiI * O0 * OoOoOO00 * i11iIiiIii . I1ii11iIi11i / I1ii11iIi11i
 if 7 - 7: iII111i . O0 * oO0o
 if 85 - 85: I1Ii111 * iIii1I11I1II1 . OoOoOO00
 if 20 - 20: I11i * O0 - OoooooooOO * OOooOOo % oO0o * iII111i
 if 70 - 70: I11i + O0 . i11iIiiIii . OOooOOo
 if ( group . is_null ( ) ) :
  OOOOO0OOO = lisp_ddt_cache . lookup_cache ( eid , False )
  if ( OOOOO0OOO == None ) :
   Ooooo . mask_len = Ooooo . host_mask_len ( )
   I1I1I . mask_len = I1I1I . host_mask_len ( )
   return ( [ Ooooo , I1I1I , LISP_DDT_ACTION_NOT_AUTH ] )
   if 48 - 48: iIii1I11I1II1 * Ii1I - OoooooooOO / oO0o - OoO0O00 / i11iIiiIii
  iI1I1 = lisp_sites_by_eid
  if ( OOOOO0OOO . is_auth_prefix ( ) ) : I1iIii1ii = OOOOO0OOO . eid
 else :
  OOOOO0OOO = lisp_ddt_cache . lookup_cache ( group , False )
  if ( OOOOO0OOO == None ) :
   Ooooo . mask_len = Ooooo . host_mask_len ( )
   I1I1I . mask_len = I1I1I . host_mask_len ( )
   return ( [ Ooooo , I1I1I , LISP_DDT_ACTION_NOT_AUTH ] )
   if 95 - 95: Oo0Ooo
  if ( OOOOO0OOO . is_auth_prefix ( ) ) : I1iIii1ii = OOOOO0OOO . group
  if 79 - 79: OoooooooOO
  group , I1iIii1ii , I1I1I = lisp_sites_by_eid . walk_cache ( lisp_neg_prefix_walk , ( group , I1iIii1ii , I1I1I ) )
  if 2 - 2: O0 - i11iIiiIii + I1Ii111 - i11iIiiIii + I11i * iIii1I11I1II1
  if 23 - 23: OoO0O00
  I1I1I . mask_address ( I1I1I . mask_len )
  if 63 - 63: o0oOOo0O0Ooo - I1IiiI % OOooOOo
  lprint ( ( "Least specific prefix computed from site-cache for " + "group EID {} using auth-prefix {} is {}" ) . format ( group . print_address ( ) , I1iIii1ii . print_prefix ( ) if ( I1iIii1ii != None ) else "'not found'" ,
  # I1ii11iIi11i * O0 - I1IiiI
  # OoO0O00 % I1Ii111
  # OOooOOo - OoooooooOO . OoO0O00
 I1I1I . print_prefix ( ) ) )
  if 34 - 34: Ii1I . I1IiiI . i1IIi * I1ii11iIi11i
  iI1I1 = OOOOO0OOO . source_cache
  if 77 - 77: ooOoO0o . II111iiii
  if 41 - 41: IiII
  if 27 - 27: IiII / IiII
  if 91 - 91: Ii1I
  if 93 - 93: OoO0O00 * OoO0O00 * I1ii11iIi11i * OoO0O00 * o0oOOo0O0Ooo
 i1ii1iIIIiI1 = LISP_DDT_ACTION_DELEGATION_HOLE if ( I1iIii1ii != None ) else LISP_DDT_ACTION_NOT_AUTH
 if 84 - 84: I1Ii111 * OoO0O00 - ooOoO0o - Oo0Ooo . OoO0O00 % oO0o
 if 98 - 98: OoO0O00 . i1IIi
 if 58 - 58: i1IIi * O0 + I1ii11iIi11i . IiII
 if 11 - 11: OOooOOo + iIii1I11I1II1 - ooOoO0o * OoO0O00 * i11iIiiIii
 if 45 - 45: I1ii11iIi11i + Oo0Ooo
 if 7 - 7: Oo0Ooo + ooOoO0o - I1Ii111 * iIii1I11I1II1
 eid , I1iIii1ii , Ooooo = iI1I1 . walk_cache ( lisp_neg_prefix_walk ,
 ( eid , I1iIii1ii , Ooooo ) )
 if 6 - 6: ooOoO0o % I1Ii111 % ooOoO0o . Ii1I * Oo0Ooo . IiII
 if 100 - 100: i1IIi . Ii1I . o0oOOo0O0Ooo + Ii1I - i1IIi . I11i
 if 19 - 19: i11iIiiIii + I11i - IiII . iII111i * i1IIi
 if 66 - 66: ooOoO0o
 Ooooo . mask_address ( Ooooo . mask_len )
 if 4 - 4: iII111i / iII111i * OOooOOo + o0oOOo0O0Ooo . I1Ii111 + II111iiii
 lprint ( ( "Least specific prefix computed from site-cache for EID {} " + "using auth-prefix {} is {}" ) . format ( green ( eid . print_address ( ) , False ) ,
 # IiII - iII111i * i11iIiiIii % i11iIiiIii + OoOoOO00 . I1Ii111
 # II111iiii
 I1iIii1ii . print_prefix ( ) if ( I1iIii1ii != None ) else "'not found'" , Ooooo . print_prefix ( ) ) )
 if 24 - 24: O0 . I1ii11iIi11i / OOooOOo % IiII * Oo0Ooo / OoO0O00
 if 67 - 67: Oo0Ooo * I11i - IiII + I1Ii111
 return ( [ Ooooo , I1I1I , i1ii1iIIIiI1 ] )
 if 90 - 90: iII111i % II111iiii % o0oOOo0O0Ooo + o0oOOo0O0Ooo + II111iiii
 if 54 - 54: OoooooooOO . IiII - oO0o
 if 26 - 26: o0oOOo0O0Ooo - i1IIi / I1ii11iIi11i / OoooooooOO . i1IIi
 if 22 - 22: o0oOOo0O0Ooo * I1Ii111 * I1ii11iIi11i . OoOoOO00 . i1IIi % ooOoO0o
 if 67 - 67: I11i
 if 95 - 95: OoO0O00 % I1Ii111
 if 49 - 49: II111iiii % OoOoOO00 % OOooOOo
 if 40 - 40: I1ii11iIi11i + i1IIi
def lisp_ms_send_map_referral ( lisp_sockets , map_request , ecm_source , port ,
 action , eid_prefix , group_prefix ) :
 if 9 - 9: OOooOOo
 III1II1I1iI = map_request . target_eid
 oO0000O0o = map_request . target_group
 oO00o0oOoo = map_request . nonce
 if 74 - 74: OoOoOO00 - OOooOOo % OoOoOO00
 if ( action == LISP_DDT_ACTION_MS_ACK ) : I1i11iiIiIi = 1440
 if 82 - 82: I11i % IiII + Oo0Ooo + iIii1I11I1II1 - I11i - I1IiiI
 if 65 - 65: IiII / O0 * II111iiii + oO0o
 if 52 - 52: o0oOOo0O0Ooo - OoOoOO00 * II111iiii / OoooooooOO
 if 44 - 44: OOooOOo - oO0o + o0oOOo0O0Ooo - i1IIi % o0oOOo0O0Ooo
 Oo00o0oO0O0o = lisp_map_referral ( )
 Oo00o0oO0O0o . record_count = 1
 Oo00o0oO0O0o . nonce = oO00o0oOoo
 I111 = Oo00o0oO0O0o . encode ( )
 Oo00o0oO0O0o . print_map_referral ( )
 if 79 - 79: iII111i . iIii1I11I1II1
 ooOOOOO000o = False
 if 42 - 42: i11iIiiIii / IiII . O0 / OOooOOo . iII111i * i1IIi
 if 83 - 83: iIii1I11I1II1 . II111iiii * Oo0Ooo . I1IiiI - I1IiiI - iIii1I11I1II1
 if 29 - 29: Oo0Ooo
 if 35 - 35: OoOoOO00 + II111iiii
 if 46 - 46: O0 / I1ii11iIi11i + OOooOOo - I1Ii111 + I1IiiI - ooOoO0o
 if 96 - 96: IiII + i1IIi - I11i * I11i - OoO0O00 % II111iiii
 if ( action == LISP_DDT_ACTION_SITE_NOT_FOUND ) :
  eid_prefix , group_prefix , action = lisp_ms_compute_neg_prefix ( III1II1I1iI ,
 oO0000O0o )
  I1i11iiIiIi = 15
  if 47 - 47: I1Ii111 . i11iIiiIii + oO0o . I1ii11iIi11i
 if ( action == LISP_DDT_ACTION_MS_NOT_REG ) : I1i11iiIiIi = 1
 if ( action == LISP_DDT_ACTION_MS_ACK ) : I1i11iiIiIi = 1440
 if ( action == LISP_DDT_ACTION_DELEGATION_HOLE ) : I1i11iiIiIi = 15
 if ( action == LISP_DDT_ACTION_NOT_AUTH ) : I1i11iiIiIi = 0
 if 12 - 12: iIii1I11I1II1 % I1Ii111 * OoOoOO00 / OoooooooOO % OoooooooOO
 OoOOo0OO = False
 oo0oooooOo000 = 0
 OOOOO0OOO = lisp_ddt_cache_lookup ( III1II1I1iI , oO0000O0o , False )
 if ( OOOOO0OOO != None ) :
  oo0oooooOo000 = len ( OOOOO0OOO . delegation_set )
  OoOOo0OO = OOOOO0OOO . is_ms_peer_entry ( )
  OOOOO0OOO . map_referrals_sent += 1
  if 57 - 57: i11iIiiIii * i11iIiiIii % I1Ii111 - iII111i * O0 - Ii1I
  if 63 - 63: IiII % OoooooooOO * OoOoOO00 * iIii1I11I1II1 . iII111i % oO0o
  if 58 - 58: I11i * iII111i + I11i % OoO0O00
  if 19 - 19: Oo0Ooo
  if 43 - 43: oO0o % ooOoO0o
 if ( action == LISP_DDT_ACTION_NOT_AUTH ) : ooOOOOO000o = True
 if ( action in ( LISP_DDT_ACTION_MS_REFERRAL , LISP_DDT_ACTION_MS_ACK ) ) :
  ooOOOOO000o = ( OoOOo0OO == False )
  if 36 - 36: I11i / I1IiiI + O0 % II111iiii
  if 24 - 24: I1Ii111 / o0oOOo0O0Ooo - OOooOOo / IiII
  if 7 - 7: OoooooooOO - i11iIiiIii * i11iIiiIii / oO0o * i1IIi % OoooooooOO
  if 6 - 6: I1ii11iIi11i * i11iIiiIii % i11iIiiIii / I1Ii111
  if 21 - 21: oO0o
 oooOO0o0ooOO = lisp_eid_record ( )
 oooOO0o0ooOO . rloc_count = oo0oooooOo000
 oooOO0o0ooOO . authoritative = True
 oooOO0o0ooOO . action = action
 oooOO0o0ooOO . ddt_incomplete = ooOOOOO000o
 oooOO0o0ooOO . eid = eid_prefix
 oooOO0o0ooOO . group = group_prefix
 oooOO0o0ooOO . record_ttl = I1i11iiIiIi
 if 47 - 47: I1ii11iIi11i
 I111 += oooOO0o0ooOO . encode ( )
 oooOO0o0ooOO . print_record ( "  " , True )
 if 24 - 24: I1Ii111 % iIii1I11I1II1
 if 87 - 87: OoOoOO00 - II111iiii + Oo0Ooo
 if 44 - 44: i1IIi + I1ii11iIi11i / iIii1I11I1II1
 if 47 - 47: I1Ii111
 if ( oo0oooooOo000 != 0 ) :
  for iII1I in OOOOO0OOO . delegation_set :
   O0OO0 = lisp_rloc_record ( )
   O0OO0 . rloc = iII1I . delegate_address
   O0OO0 . priority = iII1I . priority
   O0OO0 . weight = iII1I . weight
   O0OO0 . mpriority = 255
   O0OO0 . mweight = 0
   O0OO0 . reach_bit = True
   I111 += O0OO0 . encode ( )
   O0OO0 . print_record ( "    " )
   if 41 - 41: IiII
   if 25 - 25: I11i % iIii1I11I1II1
   if 27 - 27: iIii1I11I1II1 . O0 . oO0o
   if 21 - 21: oO0o * I1ii11iIi11i
   if 44 - 44: o0oOOo0O0Ooo * IiII - o0oOOo0O0Ooo
   if 90 - 90: i1IIi + I1ii11iIi11i * oO0o % i11iIiiIii - OoO0O00
   if 12 - 12: OoO0O00 . I1ii11iIi11i - I1IiiI % OOooOOo
 if ( map_request . nonce != 0 ) : port = LISP_CTRL_PORT
 lisp_send_map_referral ( lisp_sockets , I111 , ecm_source , port )
 return
 if 9 - 9: Ii1I / O0
 if 95 - 95: iII111i / I11i
 if 86 - 86: O0 / II111iiii . Oo0Ooo / Oo0Ooo * II111iiii
 if 22 - 22: Ii1I
 if 81 - 81: iIii1I11I1II1 . ooOoO0o % I11i
 if 64 - 64: I1Ii111 . Oo0Ooo * o0oOOo0O0Ooo
 if 32 - 32: oO0o . I1Ii111 * I1Ii111
 if 32 - 32: I1Ii111 . Ii1I / i1IIi
def lisp_send_negative_map_reply ( sockets , eid , group , nonce , dest , port , ttl ,
 xtr_id , pubsub ) :
 if 2 - 2: OOooOOo * ooOoO0o / I11i + OoO0O00
 lprint ( "Build negative Map-Reply EID-prefix {}, nonce 0x{} to ITR {}" . format ( lisp_print_eid_tuple ( eid , group ) , lisp_hex_string ( nonce ) ,
 # IiII * Oo0Ooo / OoOoOO00 + I1IiiI - i11iIiiIii + II111iiii
 red ( dest . print_address ( ) , False ) ) )
 if 81 - 81: I11i / Oo0Ooo % Ii1I % OoO0O00
 i1ii1iIIIiI1 = LISP_NATIVE_FORWARD_ACTION if group . is_null ( ) else LISP_DROP_ACTION
 if 87 - 87: O0 % II111iiii
 if 42 - 42: I1IiiI . i1IIi
 if 98 - 98: o0oOOo0O0Ooo % I11i . Oo0Ooo * Oo0Ooo % iII111i
 if 37 - 37: OoO0O00 / I1Ii111 . I1Ii111 * i1IIi
 if 22 - 22: I1ii11iIi11i . II111iiii + iIii1I11I1II1 / OoooooooOO . ooOoO0o
 if ( lisp_get_eid_hash ( eid ) != None ) :
  i1ii1iIIIiI1 = LISP_SEND_MAP_REQUEST_ACTION
  if 13 - 13: II111iiii
  if 36 - 36: iII111i - oO0o / Oo0Ooo / O0 . OoO0O00 . i1IIi
 I111 = lisp_build_map_reply ( eid , group , [ ] , nonce , i1ii1iIIIiI1 , ttl , False ,
 None , False , False )
 if 19 - 19: O0 . OoooooooOO % iIii1I11I1II1 - Ii1I . Ii1I + I1IiiI
 if 98 - 98: oO0o . Oo0Ooo
 if 9 - 9: I1Ii111 % IiII - i11iIiiIii - OOooOOo % iII111i % OoooooooOO
 if 6 - 6: i1IIi - II111iiii * OoOoOO00 + oO0o
 if ( pubsub ) :
  lisp_process_pubsub ( sockets , I111 , eid , dest , port , nonce , ttl ,
 xtr_id )
 else :
  lisp_send_map_reply ( sockets , I111 , dest , port )
  if 6 - 6: I1IiiI - ooOoO0o + I1IiiI + OoO0O00 - i11iIiiIii % ooOoO0o
 return
 if 64 - 64: OoooooooOO + OOooOOo
 if 36 - 36: I1IiiI - Ii1I / I1ii11iIi11i + Oo0Ooo % I1ii11iIi11i
 if 86 - 86: iIii1I11I1II1 * OoO0O00
 if 82 - 82: I1IiiI - OoO0O00 % o0oOOo0O0Ooo
 if 72 - 72: O0 + OoOoOO00 % OOooOOo / oO0o / IiII
 if 98 - 98: Oo0Ooo . II111iiii * I11i
 if 39 - 39: IiII * o0oOOo0O0Ooo + Ii1I - I11i
def lisp_retransmit_ddt_map_request ( mr ) :
 OOo0O00000O0O = mr . mr_source . print_address ( )
 oOo0o00oO0 = mr . print_eid_tuple ( )
 oO00o0oOoo = mr . nonce
 if 55 - 55: I1ii11iIi11i . OoOoOO00 / iII111i - oO0o
 if 79 - 79: oO0o * Ii1I
 if 64 - 64: O0 % OoooooooOO % i11iIiiIii * Oo0Ooo
 if 10 - 10: i11iIiiIii / I1ii11iIi11i . i1IIi + i1IIi * iII111i
 if 64 - 64: II111iiii % I1ii11iIi11i . OoOoOO00 . iIii1I11I1II1 / I1ii11iIi11i
 if ( mr . last_request_sent_to ) :
  iiIi1iIIIII1 = mr . last_request_sent_to . print_address ( )
  iI1OO0o00 = lisp_referral_cache_lookup ( mr . last_cached_prefix [ 0 ] ,
 mr . last_cached_prefix [ 1 ] , True )
  if ( iI1OO0o00 and iI1OO0o00 . referral_set . has_key ( iiIi1iIIIII1 ) ) :
   iI1OO0o00 . referral_set [ iiIi1iIIIII1 ] . no_responses += 1
   if 85 - 85: i1IIi / I1Ii111 * Oo0Ooo + O0
   if 29 - 29: iIii1I11I1II1 + oO0o + IiII
   if 69 - 69: iIii1I11I1II1 . I1Ii111 * iII111i
   if 6 - 6: I11i - IiII - I11i - II111iiii
   if 72 - 72: i1IIi / OOooOOo . Oo0Ooo . oO0o
   if 72 - 72: o0oOOo0O0Ooo % iIii1I11I1II1
   if 74 - 74: Oo0Ooo % OOooOOo + i11iIiiIii
 if ( mr . retry_count == LISP_MAX_MAP_NOTIFY_RETRIES ) :
  lprint ( "DDT Map-Request retry limit reached for EID {}, nonce 0x{}" . format ( green ( oOo0o00oO0 , False ) , lisp_hex_string ( oO00o0oOoo ) ) )
  if 17 - 17: OoOoOO00 . I1IiiI
  mr . dequeue_map_request ( )
  return
  if 30 - 30: i1IIi * OoOoOO00 * I11i . O0
  if 45 - 45: iII111i
 mr . retry_count += 1
 if 99 - 99: o0oOOo0O0Ooo % ooOoO0o % i11iIiiIii
 i1I1iIi1IiI = green ( OOo0O00000O0O , False )
 O0o0oo0oOO0oO = green ( oOo0o00oO0 , False )
 lprint ( "Retransmit DDT {} from {}ITR {} EIDs: {} -> {}, nonce 0x{}" . format ( bold ( "Map-Request" , False ) , "P" if mr . from_pitr else "" ,
 # o0oOOo0O0Ooo / IiII
 red ( mr . itr . print_address ( ) , False ) , i1I1iIi1IiI , O0o0oo0oOO0oO ,
 lisp_hex_string ( oO00o0oOoo ) ) )
 if 76 - 76: i11iIiiIii / oO0o / II111iiii
 if 49 - 49: i1IIi * II111iiii * Oo0Ooo % oO0o / II111iiii
 if 8 - 8: I1IiiI . o0oOOo0O0Ooo / OoooooooOO - II111iiii
 if 93 - 93: OoOoOO00 / OoOoOO00 / OoOoOO00
 lisp_send_ddt_map_request ( mr , False )
 if 74 - 74: ooOoO0o % Oo0Ooo - iII111i - I1IiiI
 if 51 - 51: i11iIiiIii % OoOoOO00
 if 17 - 17: ooOoO0o - i1IIi
 if 73 - 73: iIii1I11I1II1 - I1Ii111 % Oo0Ooo . O0
 mr . retransmit_timer = threading . Timer ( LISP_DDT_MAP_REQUEST_INTERVAL ,
 lisp_retransmit_ddt_map_request , [ mr ] )
 mr . retransmit_timer . start ( )
 return
 if 16 - 16: OoO0O00 / Oo0Ooo / IiII . Oo0Ooo - OoooooooOO
 if 5 - 5: OoOoOO00 . I11i
 if 28 - 28: I11i % OOooOOo + Oo0Ooo / OoO0O00 % o0oOOo0O0Ooo + OoO0O00
 if 20 - 20: ooOoO0o . iII111i % OOooOOo + i11iIiiIii
 if 64 - 64: i1IIi . o0oOOo0O0Ooo * I1Ii111 - O0
 if 76 - 76: I1IiiI % Ii1I + OoO0O00 + I1ii11iIi11i * II111iiii + Oo0Ooo
 if 3 - 3: Ii1I - I1IiiI + O0
 if 90 - 90: Ii1I + OoooooooOO . i11iIiiIii / Oo0Ooo % OoOoOO00 / IiII
def lisp_get_referral_node ( referral , source_eid , dest_eid ) :
 if 45 - 45: OoooooooOO / oO0o . I1ii11iIi11i + OOooOOo
 if 54 - 54: Ii1I - o0oOOo0O0Ooo + OoOoOO00 / OoooooooOO
 if 61 - 61: I11i / IiII % OoooooooOO - i11iIiiIii * i1IIi % o0oOOo0O0Ooo
 if 67 - 67: o0oOOo0O0Ooo - Ii1I
 iIII1iii1 = [ ]
 for i1I in referral . referral_set . values ( ) :
  if ( i1I . updown == False ) : continue
  if ( len ( iIII1iii1 ) == 0 or iIII1iii1 [ 0 ] . priority == i1I . priority ) :
   iIII1iii1 . append ( i1I )
  elif ( iIII1iii1 [ 0 ] . priority > i1I . priority ) :
   iIII1iii1 = [ ]
   iIII1iii1 . append ( i1I )
   if 34 - 34: i1IIi / i11iIiiIii / OoooooooOO + OoO0O00 * II111iiii / O0
   if 27 - 27: Oo0Ooo . IiII / OoooooooOO * i1IIi * IiII / I1ii11iIi11i
   if 19 - 19: i11iIiiIii + II111iiii
 I1IiiiIi = len ( iIII1iii1 )
 if ( I1IiiiIi == 0 ) : return ( None )
 if 58 - 58: OoOoOO00 - II111iiii
 iIII1I1i = dest_eid . hash_address ( source_eid )
 iIII1I1i = iIII1I1i % I1IiiiIi
 return ( iIII1iii1 [ iIII1I1i ] )
 if 77 - 77: I1ii11iIi11i
 if 72 - 72: I1IiiI - i1IIi
 if 11 - 11: iIii1I11I1II1 . OoO0O00 * Ii1I
 if 65 - 65: Oo0Ooo / OoooooooOO
 if 60 - 60: II111iiii + I1IiiI % oO0o - o0oOOo0O0Ooo
 if 50 - 50: iIii1I11I1II1 - i11iIiiIii / iII111i + ooOoO0o / OOooOOo
 if 80 - 80: IiII / OoooooooOO
def lisp_send_ddt_map_request ( mr , send_to_root ) :
 oO0ooo = mr . lisp_sockets
 oO00o0oOoo = mr . nonce
 Ii1ii1Ii11 = mr . itr
 Ii1 = mr . mr_source
 oo0ooooO = mr . print_eid_tuple ( )
 if 91 - 91: oO0o + iII111i
 if 39 - 39: i11iIiiIii / iII111i
 if 8 - 8: OoO0O00 + I11i
 if 60 - 60: i11iIiiIii
 if 81 - 81: I11i + oO0o * iIii1I11I1II1 * IiII
 if ( mr . send_count == 8 ) :
  lprint ( "Giving up on map-request-queue entry {}, nonce 0x{}" . format ( green ( oo0ooooO , False ) , lisp_hex_string ( oO00o0oOoo ) ) )
  if 7 - 7: I11i - I1IiiI . iII111i + O0 / iIii1I11I1II1 - I1Ii111
  mr . dequeue_map_request ( )
  return
  if 32 - 32: ooOoO0o
  if 9 - 9: I1Ii111
  if 77 - 77: OoooooooOO * I1Ii111
  if 63 - 63: IiII * oO0o * iIii1I11I1II1
  if 18 - 18: II111iiii * o0oOOo0O0Ooo % i11iIiiIii . OoOoOO00
  if 40 - 40: oO0o - o0oOOo0O0Ooo * II111iiii
 if ( send_to_root ) :
  iioOoOo0 = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  oOo0000OOoOO0 = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  mr . tried_root = True
  lprint ( "Jumping up to root for EID {}" . format ( green ( oo0ooooO , False ) ) )
 else :
  iioOoOo0 = mr . eid
  oOo0000OOoOO0 = mr . group
  if 90 - 90: OoooooooOO - I1IiiI / I1ii11iIi11i + oO0o - o0oOOo0O0Ooo
  if 84 - 84: OoOoOO00 + O0 % Oo0Ooo
  if 22 - 22: iIii1I11I1II1 % i11iIiiIii
  if 29 - 29: ooOoO0o - iII111i + IiII % Ii1I - oO0o - ooOoO0o
  if 43 - 43: oO0o
 i1iI11i = lisp_referral_cache_lookup ( iioOoOo0 , oOo0000OOoOO0 , False )
 if ( i1iI11i == None ) :
  lprint ( "No referral cache entry found" )
  lisp_send_negative_map_reply ( oO0ooo , iioOoOo0 , oOo0000OOoOO0 ,
 oO00o0oOoo , Ii1ii1Ii11 , mr . sport , 15 , None , False )
  return
  if 9 - 9: OOooOOo + Oo0Ooo
  if 84 - 84: i11iIiiIii . Ii1I
 oO0Oo = i1iI11i . print_eid_tuple ( )
 lprint ( "Found referral cache entry {}, referral-type: {}" . format ( oO0Oo ,
 i1iI11i . print_referral_type ( ) ) )
 if 41 - 41: II111iiii . i1IIi
 i1I = lisp_get_referral_node ( i1iI11i , Ii1 , mr . eid )
 if ( i1I == None ) :
  lprint ( "No reachable referral-nodes found" )
  mr . dequeue_map_request ( )
  lisp_send_negative_map_reply ( oO0ooo , i1iI11i . eid ,
 i1iI11i . group , oO00o0oOoo , Ii1ii1Ii11 , mr . sport , 1 , None , False )
  return
  if 78 - 78: I1IiiI * I11i % OOooOOo + Ii1I + OoOoOO00
  if 23 - 23: iII111i / Oo0Ooo % OoooooooOO * OoooooooOO . iII111i / I1ii11iIi11i
 lprint ( "Send DDT Map-Request to {} {} for EID {}, nonce 0x{}" . format ( i1I . referral_address . print_address ( ) ,
 # I1ii11iIi11i + oO0o
 i1iI11i . print_referral_type ( ) , green ( oo0ooooO , False ) ,
 lisp_hex_string ( oO00o0oOoo ) ) )
 if 9 - 9: OoooooooOO / OoOoOO00 . Ii1I
 if 91 - 91: Ii1I - I1IiiI * Ii1I . Oo0Ooo
 if 26 - 26: I1ii11iIi11i * O0 . o0oOOo0O0Ooo / OoO0O00 / II111iiii . O0
 if 58 - 58: iIii1I11I1II1
 I1i1I = ( i1iI11i . referral_type == LISP_DDT_ACTION_MS_REFERRAL or
 i1iI11i . referral_type == LISP_DDT_ACTION_MS_ACK )
 lisp_send_ecm ( oO0ooo , mr . packet , Ii1 , mr . sport , mr . eid ,
 i1I . referral_address , to_ms = I1i1I , ddt = True )
 if 71 - 71: IiII * Oo0Ooo
 if 25 - 25: II111iiii
 if 8 - 8: OoO0O00
 if 17 - 17: iIii1I11I1II1 - Oo0Ooo
 mr . last_request_sent_to = i1I . referral_address
 mr . last_sent = lisp_get_timestamp ( )
 mr . send_count += 1
 i1I . map_requests_sent += 1
 return
 if 25 - 25: O0 + I1ii11iIi11i
 if 53 - 53: OoooooooOO . Oo0Ooo
 if 35 - 35: OOooOOo % i11iIiiIii % ooOoO0o . O0
 if 9 - 9: ooOoO0o + iII111i / i1IIi % Oo0Ooo - o0oOOo0O0Ooo / I1IiiI
 if 42 - 42: OOooOOo + oO0o % O0 * I1ii11iIi11i + i11iIiiIii
 if 16 - 16: i1IIi . I11i + OoO0O00 % Ii1I * IiII + I1IiiI
 if 96 - 96: II111iiii + O0 - II111iiii
 if 97 - 97: I1IiiI
def lisp_mr_process_map_request ( lisp_sockets , packet , map_request , ecm_source ,
 sport , mr_source ) :
 if 87 - 87: I11i + iIii1I11I1II1
 III1II1I1iI = map_request . target_eid
 oO0000O0o = map_request . target_group
 oOo0o00oO0 = map_request . print_eid_tuple ( )
 OOo0O00000O0O = mr_source . print_address ( )
 oO00o0oOoo = map_request . nonce
 if 91 - 91: oO0o
 i1I1iIi1IiI = green ( OOo0O00000O0O , False )
 O0o0oo0oOO0oO = green ( oOo0o00oO0 , False )
 lprint ( "Received Map-Request from {}ITR {} EIDs: {} -> {}, nonce 0x{}" . format ( "P" if map_request . pitr_bit else "" ,
 # i1IIi + oO0o . OoooooooOO % i1IIi
 red ( ecm_source . print_address ( ) , False ) , i1I1iIi1IiI , O0o0oo0oOO0oO ,
 lisp_hex_string ( oO00o0oOoo ) ) )
 if 66 - 66: OOooOOo / I1IiiI * I1IiiI - i11iIiiIii % Oo0Ooo . i11iIiiIii
 if 14 - 14: OoO0O00 . I1IiiI % I11i * iII111i / OoOoOO00
 if 16 - 16: OoO0O00 * ooOoO0o / II111iiii % OOooOOo . I1ii11iIi11i * i1IIi
 if 18 - 18: I1IiiI + OoOoOO00
 iiOoOoOoo0 = lisp_ddt_map_request ( lisp_sockets , packet , III1II1I1iI , oO0000O0o , oO00o0oOoo )
 iiOoOoOoo0 . packet = packet
 iiOoOoOoo0 . itr = ecm_source
 iiOoOoOoo0 . mr_source = mr_source
 iiOoOoOoo0 . sport = sport
 iiOoOoOoo0 . from_pitr = map_request . pitr_bit
 iiOoOoOoo0 . queue_map_request ( )
 if 56 - 56: IiII - ooOoO0o % oO0o / Oo0Ooo * oO0o % O0
 lisp_send_ddt_map_request ( iiOoOoOoo0 , False )
 return
 if 71 - 71: iII111i / II111iiii - II111iiii / I1IiiI
 if 24 - 24: O0 . I1IiiI + IiII . IiII
 if 53 - 53: II111iiii + Ii1I * o0oOOo0O0Ooo
 if 47 - 47: Ii1I % OOooOOo . Oo0Ooo
 if 94 - 94: Ii1I - iIii1I11I1II1 + I1IiiI - iIii1I11I1II1 . o0oOOo0O0Ooo
 if 3 - 3: O0 / I11i + OoOoOO00 % IiII / i11iIiiIii
 if 25 - 25: II111iiii / I1ii11iIi11i % iIii1I11I1II1
def lisp_process_map_request ( lisp_sockets , packet , ecm_source , ecm_port ,
 mr_source , mr_port , ddt_request , ttl ) :
 if 69 - 69: IiII
 Oo0OOOO = packet
 iII1 = lisp_map_request ( )
 packet = iII1 . decode ( packet , mr_source , mr_port )
 if ( packet == None ) :
  lprint ( "Could not decode Map-Request packet" )
  return
  if 72 - 72: iIii1I11I1II1 / Oo0Ooo - o0oOOo0O0Ooo % I1Ii111
  if 96 - 96: IiII + o0oOOo0O0Ooo - I11i + I1IiiI . iII111i
 iII1 . print_map_request ( )
 if 68 - 68: OoO0O00
 if 56 - 56: i11iIiiIii / I1Ii111 / II111iiii / oO0o
 if 35 - 35: OOooOOo / I1Ii111 . I1ii11iIi11i / OoooooooOO + I1Ii111 . I1Ii111
 if 52 - 52: O0 - I1Ii111 . oO0o
 if ( iII1 . rloc_probe ) :
  lisp_process_rloc_probe_request ( lisp_sockets , iII1 ,
 mr_source , mr_port , ttl )
  return
  if 43 - 43: IiII * Ii1I - I1ii11iIi11i * I1ii11iIi11i
  if 53 - 53: oO0o % I11i * OoO0O00 . i1IIi
  if 35 - 35: I11i . IiII + ooOoO0o
  if 19 - 19: O0 - i1IIi / I1Ii111
  if 14 - 14: I11i - i11iIiiIii
 if ( iII1 . smr_bit ) :
  lisp_process_smr ( iII1 )
  if 49 - 49: oO0o . I1ii11iIi11i
  if 51 - 51: OOooOOo + o0oOOo0O0Ooo . OOooOOo
  if 23 - 23: iIii1I11I1II1 + OoO0O00 / I1IiiI
  if 48 - 48: OoOoOO00 + I11i + oO0o . I1IiiI
  if 7 - 7: iII111i * i1IIi % OoOoOO00 % Ii1I . I1IiiI
 if ( iII1 . smr_invoked_bit ) :
  lisp_process_smr_invoked_request ( iII1 )
  if 53 - 53: OOooOOo / I11i + OOooOOo / I1IiiI / OoO0O00
  if 12 - 12: i11iIiiIii % ooOoO0o / iII111i . IiII
  if 68 - 68: OOooOOo / iIii1I11I1II1 + I1IiiI . ooOoO0o * IiII
  if 72 - 72: I1Ii111
  if 51 - 51: OoOoOO00
 if ( lisp_i_am_etr ) :
  lisp_etr_process_map_request ( lisp_sockets , iII1 , mr_source ,
 mr_port , ttl )
  if 61 - 61: Oo0Ooo / i1IIi + I1Ii111 - OoooooooOO / O0
  if 25 - 25: I1ii11iIi11i * i11iIiiIii / i1IIi
  if 69 - 69: OOooOOo % ooOoO0o - i1IIi . Oo0Ooo
  if 35 - 35: iIii1I11I1II1 - I11i / iIii1I11I1II1 % ooOoO0o % I1IiiI
  if 46 - 46: oO0o
 if ( lisp_i_am_ms ) :
  packet = Oo0OOOO
  III1II1I1iI , oO0000O0o , IiIIIIi11ii = lisp_ms_process_map_request ( lisp_sockets ,
 Oo0OOOO , iII1 , mr_source , mr_port , ecm_source )
  if ( ddt_request ) :
   lisp_ms_send_map_referral ( lisp_sockets , iII1 , ecm_source ,
 ecm_port , IiIIIIi11ii , III1II1I1iI , oO0000O0o )
   if 86 - 86: O0 - Oo0Ooo
  return
  if 80 - 80: o0oOOo0O0Ooo - I1Ii111 * O0 * iIii1I11I1II1
  if 59 - 59: I1ii11iIi11i + I11i / OoO0O00
  if 36 - 36: o0oOOo0O0Ooo + ooOoO0o * I11i
  if 81 - 81: OOooOOo * I11i - I1ii11iIi11i
  if 82 - 82: I1ii11iIi11i * II111iiii - OoooooooOO % iII111i * I1IiiI % OoOoOO00
 if ( lisp_i_am_mr and not ddt_request ) :
  lisp_mr_process_map_request ( lisp_sockets , Oo0OOOO , iII1 ,
 ecm_source , mr_port , mr_source )
  if 81 - 81: I11i + o0oOOo0O0Ooo / iII111i
  if 35 - 35: ooOoO0o % I11i * I1ii11iIi11i
  if 10 - 10: OoO0O00 + OoooooooOO + I1Ii111
  if 57 - 57: Ii1I % Ii1I * Oo0Ooo % i11iIiiIii
  if 12 - 12: oO0o . Oo0Ooo . I1IiiI - i11iIiiIii / o0oOOo0O0Ooo
 if ( lisp_i_am_ddt or ddt_request ) :
  packet = Oo0OOOO
  lisp_ddt_process_map_request ( lisp_sockets , iII1 , ecm_source ,
 ecm_port )
  if 54 - 54: i11iIiiIii + I1Ii111 . I1Ii111 * I1ii11iIi11i % I1Ii111 - OoooooooOO
 return
 if 76 - 76: IiII + i1IIi + i11iIiiIii . oO0o
 if 23 - 23: ooOoO0o - OoO0O00 + oO0o . OOooOOo - I1IiiI
 if 66 - 66: iII111i % iII111i
 if 59 - 59: II111iiii . i1IIi % i1IIi
 if 40 - 40: I1Ii111 . II111iiii * o0oOOo0O0Ooo + I11i - i1IIi
 if 67 - 67: o0oOOo0O0Ooo - O0 - i1IIi . ooOoO0o . iII111i
 if 43 - 43: II111iiii . o0oOOo0O0Ooo + i11iIiiIii . O0 / O0 . II111iiii
 if 13 - 13: Ii1I % i11iIiiIii
def lisp_store_mr_stats ( source , nonce ) :
 iiOoOoOoo0 = lisp_get_map_resolver ( source , None )
 if ( iiOoOoOoo0 == None ) : return
 if 3 - 3: ooOoO0o % OoOoOO00 * I1Ii111 - OoO0O00 / i1IIi % I1IiiI
 if 50 - 50: I1ii11iIi11i + iII111i
 if 64 - 64: oO0o
 if 11 - 11: o0oOOo0O0Ooo
 iiOoOoOoo0 . neg_map_replies_received += 1
 iiOoOoOoo0 . last_reply = lisp_get_timestamp ( )
 if 95 - 95: i1IIi . ooOoO0o . Oo0Ooo
 if 13 - 13: OOooOOo - Oo0Ooo % O0 . I1Ii111
 if 66 - 66: I1IiiI + I11i
 if 58 - 58: I1ii11iIi11i
 if ( ( iiOoOoOoo0 . neg_map_replies_received % 100 ) == 0 ) : iiOoOoOoo0 . total_rtt = 0
 if 7 - 7: oO0o - I11i
 if 59 - 59: Ii1I / o0oOOo0O0Ooo / OoO0O00 + IiII + i11iIiiIii
 if 64 - 64: o0oOOo0O0Ooo * IiII * IiII * iII111i % i11iIiiIii
 if 22 - 22: I1ii11iIi11i * II111iiii - OOooOOo % i11iIiiIii
 if ( iiOoOoOoo0 . last_nonce == nonce ) :
  iiOoOoOoo0 . total_rtt += ( time . time ( ) - iiOoOoOoo0 . last_used )
  iiOoOoOoo0 . last_nonce = 0
  if 10 - 10: OOooOOo / I1ii11iIi11i
 if ( ( iiOoOoOoo0 . neg_map_replies_received % 10 ) == 0 ) : iiOoOoOoo0 . last_nonce = 0
 return
 if 21 - 21: OoO0O00 % Oo0Ooo . o0oOOo0O0Ooo + IiII
 if 48 - 48: O0 / i1IIi / iII111i
 if 11 - 11: O0 - OoO0O00 + OoOoOO00 * ooOoO0o - Ii1I
 if 82 - 82: Ii1I - O0 * ooOoO0o . ooOoO0o
 if 32 - 32: o0oOOo0O0Ooo . OoooooooOO % OOooOOo
 if 2 - 2: OoOoOO00 + I1ii11iIi11i + oO0o
 if 27 - 27: OoooooooOO - Ii1I / OoooooooOO + OoO0O00
def lisp_process_map_reply ( lisp_sockets , packet , source , ttl ) :
 global lisp_map_cache
 if 58 - 58: OOooOOo * I11i . I1IiiI
 o0o00oO0OooO0 = lisp_map_reply ( )
 packet = o0o00oO0OooO0 . decode ( packet )
 if ( packet == None ) :
  lprint ( "Could not decode Map-Reply packet" )
  return
  if 46 - 46: I11i + II111iiii * iII111i % ooOoO0o - I1IiiI
 o0o00oO0OooO0 . print_map_reply ( )
 if 73 - 73: I1ii11iIi11i * iIii1I11I1II1 . I1Ii111 - Ii1I
 if 11 - 11: I11i
 if 48 - 48: IiII / O0
 if 46 - 46: ooOoO0o + oO0o
 i1iIi111iI1i = None
 for oO in range ( o0o00oO0OooO0 . record_count ) :
  oooOO0o0ooOO = lisp_eid_record ( )
  packet = oooOO0o0ooOO . decode ( packet )
  if ( packet == None ) :
   lprint ( "Could not decode EID-record in Map-Reply packet" )
   return
   if 49 - 49: i1IIi + I11i - Oo0Ooo * OOooOOo
  oooOO0o0ooOO . print_record ( "  " , False )
  if 86 - 86: i1IIi - IiII - Ii1I . I1IiiI + I1IiiI
  if 89 - 89: o0oOOo0O0Ooo + iIii1I11I1II1 * OoooooooOO
  if 55 - 55: OoooooooOO / OOooOOo / iIii1I11I1II1 * iIii1I11I1II1 . o0oOOo0O0Ooo
  if 68 - 68: OOooOOo % Oo0Ooo * ooOoO0o * OoO0O00 / iII111i
  if 96 - 96: i11iIiiIii - I1IiiI % OoOoOO00 * Ii1I % OoO0O00 % O0
  if ( oooOO0o0ooOO . rloc_count == 0 ) :
   lisp_store_mr_stats ( source , o0o00oO0OooO0 . nonce )
   if 100 - 100: oO0o . OoooooooOO
   if 58 - 58: I11i % OoooooooOO
  o0000ooO = ( oooOO0o0ooOO . group . is_null ( ) == False )
  if 87 - 87: o0oOOo0O0Ooo
  if 28 - 28: o0oOOo0O0Ooo . o0oOOo0O0Ooo . o0oOOo0O0Ooo
  if 93 - 93: i11iIiiIii / IiII
  if 35 - 35: I1Ii111 / o0oOOo0O0Ooo
  if 44 - 44: IiII % i11iIiiIii
  if ( lisp_decent_push_configured ) :
   i1ii1iIIIiI1 = oooOO0o0ooOO . action
   if ( o0000ooO and i1ii1iIIIiI1 == LISP_DROP_ACTION ) :
    if ( oooOO0o0ooOO . eid . is_local ( ) ) : continue
    if 99 - 99: ooOoO0o % iIii1I11I1II1 + o0oOOo0O0Ooo % I11i
    if 66 - 66: iIii1I11I1II1
    if 74 - 74: OoooooooOO - I1Ii111 - I1IiiI
    if 30 - 30: Oo0Ooo / o0oOOo0O0Ooo % o0oOOo0O0Ooo * i1IIi
    if 58 - 58: OoooooooOO - OOooOOo - OoOoOO00 / i1IIi * Oo0Ooo / i1IIi
    if 86 - 86: OoOoOO00 . I11i
    if 97 - 97: Ii1I
  if ( oooOO0o0ooOO . eid . is_null ( ) ) : continue
  if 24 - 24: I1IiiI * i11iIiiIii
  if 83 - 83: OoOoOO00 * I1ii11iIi11i
  if 64 - 64: II111iiii * i1IIi - ooOoO0o
  if 4 - 4: ooOoO0o . OoO0O00 . OoO0O00 % ooOoO0o * Oo0Ooo - I1IiiI
  if 8 - 8: I1IiiI - I1Ii111 - OoooooooOO * Oo0Ooo * Ii1I
  if ( o0000ooO ) :
   iIi11 = lisp_map_cache_lookup ( oooOO0o0ooOO . eid , oooOO0o0ooOO . group )
  else :
   iIi11 = lisp_map_cache . lookup_cache ( oooOO0o0ooOO . eid , True )
   if 75 - 75: OoooooooOO % i11iIiiIii + i11iIiiIii + II111iiii . OOooOOo
  I111iiiiI = ( iIi11 == None )
  if 50 - 50: OoOoOO00 / iII111i * O0 . I1IiiI
  if 88 - 88: IiII / I1ii11iIi11i % I11i + i11iIiiIii * O0 . I1Ii111
  if 69 - 69: Oo0Ooo - OOooOOo / I1IiiI . i11iIiiIii * OoO0O00
  if 45 - 45: I1Ii111 + OOooOOo
  I1111Ii1II1I = [ ]
  for oOooO0Oo0Oo0 in range ( oooOO0o0ooOO . rloc_count ) :
   O0OO0 = lisp_rloc_record ( )
   O0OO0 . keys = o0o00oO0OooO0 . keys
   packet = O0OO0 . decode ( packet , o0o00oO0OooO0 . nonce )
   if ( packet == None ) :
    lprint ( "Could not decode RLOC-record in Map-Reply packet" )
    return
    if 18 - 18: O0 * OoooooooOO % IiII - iIii1I11I1II1 % IiII * o0oOOo0O0Ooo
   O0OO0 . print_record ( "    " )
   if 13 - 13: OoO0O00 + i11iIiiIii + O0 / ooOoO0o % iIii1I11I1II1
   OOoo = None
   if ( iIi11 ) : OOoo = iIi11 . get_rloc ( O0OO0 . rloc )
   if ( OOoo ) :
    II1iIiIiIIi = OOoo
   else :
    II1iIiIiIIi = lisp_rloc ( )
    if 97 - 97: I11i + II111iiii / OoooooooOO + I1ii11iIi11i * o0oOOo0O0Ooo
    if 29 - 29: I1Ii111
    if 95 - 95: OoOoOO00 * II111iiii + I1ii11iIi11i - I11i . I11i % i11iIiiIii
    if 23 - 23: OoO0O00
    if 26 - 26: I1ii11iIi11i
    if 66 - 66: i11iIiiIii - i11iIiiIii / Ii1I * OOooOOo / IiII
    if 67 - 67: I1IiiI . I1Ii111 - OoOoOO00
   II11i = II1iIiIiIIi . store_rloc_from_record ( O0OO0 , o0o00oO0OooO0 . nonce ,
 source )
   II1iIiIiIIi . echo_nonce_capable = o0o00oO0OooO0 . echo_nonce_capable
   if 18 - 18: O0
   if ( II1iIiIiIIi . echo_nonce_capable ) :
    I11i11I = II1iIiIiIIi . rloc . print_address_no_iid ( )
    if ( lisp_get_echo_nonce ( None , I11i11I ) == None ) :
     lisp_echo_nonce ( I11i11I )
     if 26 - 26: i1IIi - iIii1I11I1II1
     if 8 - 8: I1Ii111
     if 86 - 86: i1IIi
     if 26 - 26: o0oOOo0O0Ooo % I1Ii111 / Oo0Ooo
     if 68 - 68: II111iiii / Oo0Ooo / Oo0Ooo
     if 1 - 1: Oo0Ooo
     if 73 - 73: Ii1I * iIii1I11I1II1 / o0oOOo0O0Ooo - o0oOOo0O0Ooo / i1IIi
     if 64 - 64: Ii1I * I1ii11iIi11i % II111iiii
     if 31 - 31: iIii1I11I1II1 % Oo0Ooo . I1IiiI % ooOoO0o
     if 38 - 38: I1ii11iIi11i + I1Ii111 * I11i / OoO0O00 + o0oOOo0O0Ooo
   if ( o0o00oO0OooO0 . rloc_probe and O0OO0 . probe_bit ) :
    if ( II1iIiIiIIi . rloc . afi == source . afi ) :
     lisp_process_rloc_probe_reply ( II1iIiIiIIi . rloc , source , II11i ,
 o0o00oO0OooO0 . nonce , o0o00oO0OooO0 . hop_count , ttl )
     if 46 - 46: iII111i
     if 56 - 56: Oo0Ooo / II111iiii
     if 61 - 61: Ii1I - i1IIi / ooOoO0o - Oo0Ooo / IiII % Oo0Ooo
     if 53 - 53: OoooooooOO + iII111i % II111iiii * IiII
     if 10 - 10: OoOoOO00 % I11i
     if 46 - 46: i1IIi % IiII
   I1111Ii1II1I . append ( II1iIiIiIIi )
   if 45 - 45: I1ii11iIi11i / I1ii11iIi11i - OoO0O00
   if 54 - 54: Ii1I + I1IiiI * OoOoOO00 + oO0o
   if 10 - 10: Ii1I - I1IiiI / IiII / iII111i - I1Ii111 - o0oOOo0O0Ooo
   if 75 - 75: OOooOOo . ooOoO0o
   if ( lisp_data_plane_security and II1iIiIiIIi . rloc_recent_rekey ( ) ) :
    i1iIi111iI1i = II1iIiIiIIi
    if 32 - 32: i1IIi / I11i + iIii1I11I1II1 . OOooOOo
    if 67 - 67: iII111i - OoO0O00 % I1ii11iIi11i * Oo0Ooo
    if 51 - 51: I1IiiI + O0
    if 4 - 4: ooOoO0o / OoO0O00 * iIii1I11I1II1 * iIii1I11I1II1
    if 33 - 33: iII111i . iIii1I11I1II1 - Ii1I
    if 85 - 85: OoOoOO00
    if 57 - 57: Oo0Ooo - II111iiii - I1ii11iIi11i * oO0o
    if 41 - 41: I11i / ooOoO0o + IiII % OoooooooOO
    if 72 - 72: Ii1I
    if 22 - 22: o0oOOo0O0Ooo / OoO0O00 + OoOoOO00 + Ii1I . II111iiii * I11i
    if 85 - 85: i11iIiiIii / I11i
  if ( o0o00oO0OooO0 . rloc_probe == False and lisp_nat_traversal ) :
   iI111iiiI1 = [ ]
   Iii1i1 = [ ]
   for II1iIiIiIIi in I1111Ii1II1I :
    if 32 - 32: ooOoO0o + I1ii11iIi11i + OoooooooOO - o0oOOo0O0Ooo % IiII
    if 75 - 75: i1IIi + II111iiii
    if 100 - 100: I11i - IiII . IiII . OoOoOO00 * OoooooooOO
    if 42 - 42: ooOoO0o * I1Ii111 + iII111i - iII111i
    if 71 - 71: i1IIi * I1Ii111 % iII111i * ooOoO0o / iIii1I11I1II1 % oO0o
    if ( II1iIiIiIIi . rloc . is_private_address ( ) ) :
     II1iIiIiIIi . priority = 1
     II1iIiIiIIi . state = LISP_RLOC_UNREACH_STATE
     iI111iiiI1 . append ( II1iIiIiIIi )
     Iii1i1 . append ( II1iIiIiIIi . rloc . print_address_no_iid ( ) )
     continue
     if 60 - 60: OoOoOO00 % I1IiiI . i11iIiiIii % OoOoOO00 - I1Ii111
     if 71 - 71: OoooooooOO * Oo0Ooo
     if 80 - 80: iIii1I11I1II1
     if 91 - 91: OoOoOO00 + OoOoOO00 + ooOoO0o
     if 44 - 44: I1ii11iIi11i * OOooOOo % OoO0O00 . I1IiiI % Ii1I + II111iiii
     if 100 - 100: oO0o - II111iiii . o0oOOo0O0Ooo
    if ( II1iIiIiIIi . priority == 254 and lisp_i_am_rtr == False ) :
     iI111iiiI1 . append ( II1iIiIiIIi )
     Iii1i1 . append ( II1iIiIiIIi . rloc . print_address_no_iid ( ) )
     if 63 - 63: OoOoOO00 % IiII . iII111i
    if ( II1iIiIiIIi . priority != 254 and lisp_i_am_rtr ) :
     iI111iiiI1 . append ( II1iIiIiIIi )
     Iii1i1 . append ( II1iIiIiIIi . rloc . print_address_no_iid ( ) )
     if 44 - 44: I1IiiI
     if 25 - 25: oO0o
     if 100 - 100: I1IiiI / IiII + OoO0O00 . iII111i
   if ( Iii1i1 != [ ] ) :
    I1111Ii1II1I = iI111iiiI1
    lprint ( "NAT-traversal optimized RLOC-set: {}" . format ( Iii1i1 ) )
    if 39 - 39: OoooooooOO * OOooOOo - OoO0O00
    if 3 - 3: I11i . i11iIiiIii % Oo0Ooo % II111iiii . I11i
    if 88 - 88: iIii1I11I1II1 . OOooOOo % iII111i
    if 72 - 72: ooOoO0o + i11iIiiIii / i1IIi
    if 64 - 64: OOooOOo - OOooOOo
    if 42 - 42: i1IIi / ooOoO0o . I1Ii111 % OoOoOO00
    if 67 - 67: i1IIi * i11iIiiIii * I1IiiI
  iI111iiiI1 = [ ]
  for II1iIiIiIIi in I1111Ii1II1I :
   if ( II1iIiIiIIi . json != None ) : continue
   iI111iiiI1 . append ( II1iIiIiIIi )
   if 23 - 23: Oo0Ooo
  if ( iI111iiiI1 != [ ] ) :
   i111I11I = len ( I1111Ii1II1I ) - len ( iI111iiiI1 )
   lprint ( "Pruning {} no-address RLOC-records for map-cache" . format ( i111I11I ) )
   if 81 - 81: I1Ii111 % II111iiii - Oo0Ooo / I1IiiI + i11iIiiIii . I11i
   I1111Ii1II1I = iI111iiiI1
   if 67 - 67: ooOoO0o . I1Ii111 . Oo0Ooo . Ii1I + iIii1I11I1II1 / OoooooooOO
   if 93 - 93: ooOoO0o * OoO0O00 - I1Ii111 / I1ii11iIi11i
   if 60 - 60: OoO0O00 / oO0o . I1IiiI + OoOoOO00 + I1ii11iIi11i % Ii1I
   if 70 - 70: i1IIi * II111iiii * I1IiiI
   if 7 - 7: OoooooooOO + II111iiii % o0oOOo0O0Ooo * O0 . OoO0O00 * OoooooooOO
   if 20 - 20: Oo0Ooo % OOooOOo
   if 8 - 8: OOooOOo
   if 92 - 92: iII111i / OOooOOo . IiII / I11i + o0oOOo0O0Ooo
  if ( o0o00oO0OooO0 . rloc_probe and iIi11 != None ) : I1111Ii1II1I = iIi11 . rloc_set
  if 99 - 99: II111iiii
  if 70 - 70: O0 % I1ii11iIi11i
  if 28 - 28: IiII - i1IIi - I1Ii111 % Ii1I - IiII
  if 73 - 73: iIii1I11I1II1 . iIii1I11I1II1 + oO0o % i11iIiiIii . IiII
  if 33 - 33: IiII - OOooOOo / i11iIiiIii * iIii1I11I1II1
  ii1I111I11 = I111iiiiI
  if ( iIi11 and I1111Ii1II1I != iIi11 . rloc_set ) :
   iIi11 . delete_rlocs_from_rloc_probe_list ( )
   ii1I111I11 = True
   if 35 - 35: OOooOOo % I1ii11iIi11i % OoooooooOO . iIii1I11I1II1
   if 24 - 24: OoO0O00
   if 42 - 42: iIii1I11I1II1 . oO0o
   if 17 - 17: OoO0O00 / OoO0O00 + o0oOOo0O0Ooo / OOooOOo . I1ii11iIi11i % IiII
   if 40 - 40: OoOoOO00
  O0o00O0O0oo = iIi11 . uptime if ( iIi11 ) else None
  iIi11 = lisp_mapping ( oooOO0o0ooOO . eid , oooOO0o0ooOO . group , I1111Ii1II1I )
  iIi11 . mapping_source = source
  iIi11 . map_cache_ttl = oooOO0o0ooOO . store_ttl ( )
  iIi11 . action = oooOO0o0ooOO . action
  iIi11 . add_cache ( ii1I111I11 )
  if 8 - 8: Oo0Ooo % Oo0Ooo * IiII % Oo0Ooo % IiII + o0oOOo0O0Ooo
  iI1i1I1iiiiI1 = "Add"
  if ( O0o00O0O0oo ) :
   iIi11 . uptime = O0o00O0O0oo
   iI1i1I1iiiiI1 = "Replace"
   if 71 - 71: Ii1I / iIii1I11I1II1 . OoOoOO00 / iIii1I11I1II1
   if 28 - 28: I1Ii111 * O0 + O0 / IiII / Oo0Ooo
  lprint ( "{} {} map-cache with {} RLOCs" . format ( iI1i1I1iiiiI1 ,
 green ( iIi11 . print_eid_tuple ( ) , False ) , len ( I1111Ii1II1I ) ) )
  if 84 - 84: I1IiiI + o0oOOo0O0Ooo + I1IiiI . I1ii11iIi11i - I1IiiI
  if 97 - 97: oO0o + iII111i * OoOoOO00 % o0oOOo0O0Ooo
  if 57 - 57: OoooooooOO . Oo0Ooo + OoooooooOO + I1Ii111 + iIii1I11I1II1 + OoOoOO00
  if 69 - 69: OoO0O00
  if 24 - 24: i1IIi + o0oOOo0O0Ooo / oO0o - I1IiiI % I1IiiI
  if ( lisp_ipc_dp_socket and i1iIi111iI1i != None ) :
   lisp_write_ipc_keys ( i1iIi111iI1i )
   if 100 - 100: Ii1I % I1Ii111 . iII111i % IiII * IiII . OoOoOO00
   if 68 - 68: iIii1I11I1II1
   if 30 - 30: I11i . I1ii11iIi11i - i1IIi / i1IIi + IiII . oO0o
   if 70 - 70: i1IIi . I11i * o0oOOo0O0Ooo . iII111i
   if 75 - 75: oO0o * OoO0O00 * I11i + oO0o + O0 . I1Ii111
   if 8 - 8: I1ii11iIi11i / i1IIi - I1ii11iIi11i + Ii1I + OoO0O00 - I11i
   if 79 - 79: OoooooooOO - I1Ii111 * I1IiiI . I1Ii111 - iIii1I11I1II1
  if ( I111iiiiI ) :
   iI1IiIIii1I = bold ( "RLOC-probe" , False )
   for II1iIiIiIIi in iIi11 . best_rloc_set :
    I11i11I = red ( II1iIiIiIIi . rloc . print_address_no_iid ( ) , False )
    lprint ( "Trigger {} to {}" . format ( iI1IiIIii1I , I11i11I ) )
    lisp_send_map_request ( lisp_sockets , 0 , iIi11 . eid , iIi11 . group , II1iIiIiIIi )
    if 35 - 35: I1Ii111
    if 29 - 29: i1IIi * Oo0Ooo
    if 54 - 54: Ii1I + iII111i + OoooooooOO * Ii1I
 return
 if 76 - 76: I1IiiI / OOooOOo % I1ii11iIi11i - o0oOOo0O0Ooo + I1ii11iIi11i
 if 45 - 45: I1ii11iIi11i * iII111i * OOooOOo
 if 18 - 18: oO0o . ooOoO0o . I1IiiI
 if 41 - 41: I11i % ooOoO0o + ooOoO0o + o0oOOo0O0Ooo - o0oOOo0O0Ooo % Ii1I
 if 52 - 52: I11i % i1IIi . I1ii11iIi11i
 if 62 - 62: ooOoO0o - I1ii11iIi11i
 if 71 - 71: I11i
 if 34 - 34: oO0o / O0 * oO0o
def lisp_compute_auth ( packet , map_register , password ) :
 if ( map_register . alg_id == LISP_NONE_ALG_ID ) : return ( packet )
 if 47 - 47: iIii1I11I1II1 - o0oOOo0O0Ooo % Ii1I
 packet = map_register . zero_auth ( packet )
 iIII1I1i = lisp_hash_me ( packet , map_register . alg_id , password , False )
 if 38 - 38: ooOoO0o / IiII * I1ii11iIi11i % I1ii11iIi11i % oO0o
 if 82 - 82: I1ii11iIi11i . i11iIiiIii - I11i . iII111i / OOooOOo
 if 60 - 60: I1IiiI / I1IiiI / II111iiii
 if 59 - 59: OOooOOo . oO0o + ooOoO0o % o0oOOo0O0Ooo . i11iIiiIii
 map_register . auth_data = iIII1I1i
 packet = map_register . encode_auth ( packet )
 return ( packet )
 if 27 - 27: OoOoOO00 - OoooooooOO / IiII / II111iiii * OOooOOo * ooOoO0o
 if 43 - 43: II111iiii . IiII - I1IiiI * I1ii11iIi11i + OoooooooOO
 if 34 - 34: I1Ii111 / i1IIi
 if 95 - 95: OoOoOO00 * OOooOOo
 if 68 - 68: I1Ii111 / iIii1I11I1II1 % Ii1I
 if 77 - 77: i11iIiiIii + i11iIiiIii - I1ii11iIi11i % I1ii11iIi11i
 if 26 - 26: oO0o + OoooooooOO % o0oOOo0O0Ooo
def lisp_hash_me ( packet , alg_id , password , do_hex ) :
 if ( alg_id == LISP_NONE_ALG_ID ) : return ( True )
 if 96 - 96: ooOoO0o * OoOoOO00 - II111iiii
 if ( alg_id == LISP_SHA_1_96_ALG_ID ) :
  III1I111I1i1I = hashlib . sha1
  if 43 - 43: ooOoO0o / OoooooooOO . Oo0Ooo % ooOoO0o
 if ( alg_id == LISP_SHA_256_128_ALG_ID ) :
  III1I111I1i1I = hashlib . sha256
  if 92 - 92: Oo0Ooo . I11i - IiII
  if 49 - 49: ooOoO0o . Ii1I
 if ( do_hex ) :
  iIII1I1i = hmac . new ( password , packet , III1I111I1i1I ) . hexdigest ( )
 else :
  iIII1I1i = hmac . new ( password , packet , III1I111I1i1I ) . digest ( )
  if 75 - 75: OOooOOo / II111iiii - Oo0Ooo + I1Ii111
 return ( iIII1I1i )
 if 42 - 42: OoooooooOO * II111iiii + Ii1I % OoO0O00 / I1Ii111
 if 11 - 11: ooOoO0o / Oo0Ooo + i1IIi / IiII
 if 4 - 4: iII111i - Oo0Ooo
 if 100 - 100: OOooOOo . i1IIi
 if 15 - 15: O0 % Oo0Ooo % o0oOOo0O0Ooo . ooOoO0o * iII111i % O0
 if 31 - 31: i1IIi . Ii1I - OoooooooOO * I11i * ooOoO0o % oO0o
 if 61 - 61: I1Ii111 . Ii1I * I1ii11iIi11i
 if 59 - 59: OoOoOO00 + Oo0Ooo . I1ii11iIi11i - Ii1I
def lisp_verify_auth ( packet , alg_id , auth_data , password ) :
 if ( alg_id == LISP_NONE_ALG_ID ) : return ( True )
 if 48 - 48: I1Ii111 % Ii1I + I1IiiI * OoooooooOO % OoOoOO00 % i11iIiiIii
 iIII1I1i = lisp_hash_me ( packet , alg_id , password , True )
 i1iiIi1Iii1 = ( iIII1I1i == auth_data )
 if 85 - 85: OoOoOO00 + OOooOOo
 if 75 - 75: OoooooooOO - Oo0Ooo - Oo0Ooo % O0 + ooOoO0o + Oo0Ooo
 if 56 - 56: i1IIi
 if 37 - 37: I1IiiI % i11iIiiIii + OoO0O00 * OOooOOo . o0oOOo0O0Ooo % IiII
 if ( i1iiIi1Iii1 == False ) :
  lprint ( "Hashed value: {} does not match packet value: {}" . format ( iIII1I1i , auth_data ) )
  if 18 - 18: Oo0Ooo % IiII . OoOoOO00 - IiII + I1Ii111 + oO0o
  if 31 - 31: OOooOOo + OoOoOO00 * OOooOOo + OoOoOO00 / o0oOOo0O0Ooo . iIii1I11I1II1
 return ( i1iiIi1Iii1 )
 if 1 - 1: I1Ii111 * i11iIiiIii % I1Ii111 - OoO0O00 + I1Ii111 / Oo0Ooo
 if 3 - 3: OOooOOo - i11iIiiIii / I1Ii111 . OOooOOo - OoO0O00
 if 60 - 60: OoOoOO00 / i1IIi . Ii1I - OoO0O00 - OoooooooOO
 if 39 - 39: I1IiiI + i1IIi * OoO0O00 % I11i
 if 41 - 41: I1ii11iIi11i * IiII
 if 16 - 16: I1Ii111 % iIii1I11I1II1 / I1IiiI * OoOoOO00 / IiII / OoOoOO00
 if 29 - 29: OoooooooOO / oO0o
def lisp_retransmit_map_notify ( map_notify ) :
 IiI1 = map_notify . etr
 II11i = map_notify . etr_port
 if 1 - 1: OoOoOO00 . i11iIiiIii % I1Ii111 + OoooooooOO - Oo0Ooo . I1ii11iIi11i
 if 46 - 46: i11iIiiIii + I11i - iIii1I11I1II1 / OoO0O00 - ooOoO0o / i1IIi
 if 44 - 44: o0oOOo0O0Ooo + Oo0Ooo
 if 46 - 46: OOooOOo % I1IiiI
 if 66 - 66: iIii1I11I1II1 . o0oOOo0O0Ooo - ooOoO0o
 if ( map_notify . retry_count == LISP_MAX_MAP_NOTIFY_RETRIES ) :
  lprint ( "Map-Notify with nonce 0x{} retry limit reached for ETR {}" . format ( map_notify . nonce_key , red ( IiI1 . print_address ( ) , False ) ) )
  if 27 - 27: Oo0Ooo - i1IIi * OoooooooOO - OoOoOO00 + OoOoOO00
  if 24 - 24: i1IIi . OoOoOO00 / I1Ii111 + O0
  OOoOoO = map_notify . nonce_key
  if ( lisp_map_notify_queue . has_key ( OOoOoO ) ) :
   map_notify . retransmit_timer . cancel ( )
   lprint ( "Dequeue Map-Notify from retransmit queue, key is: {}" . format ( OOoOoO ) )
   if 86 - 86: Ii1I * OoOoOO00 % I1ii11iIi11i + OOooOOo
   try :
    lisp_map_notify_queue . pop ( OOoOoO )
   except :
    lprint ( "Key not found in Map-Notify queue" )
    if 85 - 85: iII111i % i11iIiiIii
    if 78 - 78: i11iIiiIii / I11i / Oo0Ooo + II111iiii - I1ii11iIi11i / I1ii11iIi11i
  return
  if 28 - 28: iIii1I11I1II1 / IiII - iIii1I11I1II1 . i1IIi - O0 * ooOoO0o
  if 41 - 41: Ii1I + IiII
 oO0ooo = map_notify . lisp_sockets
 map_notify . retry_count += 1
 if 37 - 37: I1Ii111 / o0oOOo0O0Ooo - ooOoO0o - OoooooooOO . I1ii11iIi11i % I1Ii111
 lprint ( "Retransmit {} with nonce 0x{} to xTR {}, retry {}" . format ( bold ( "Map-Notify" , False ) , map_notify . nonce_key ,
 # Ii1I - OoOoOO00 / I1ii11iIi11i - Ii1I
 red ( IiI1 . print_address ( ) , False ) , map_notify . retry_count ) )
 if 79 - 79: I1Ii111 + I1ii11iIi11i / i1IIi + o0oOOo0O0Ooo - OoO0O00 / Oo0Ooo
 lisp_send_map_notify ( oO0ooo , map_notify . packet , IiI1 , II11i )
 if ( map_notify . site ) : map_notify . site . map_notifies_sent += 1
 if 3 - 3: OoOoOO00 - I1Ii111 % ooOoO0o
 if 80 - 80: II111iiii % OOooOOo * iIii1I11I1II1 + I1Ii111 + IiII
 if 73 - 73: OOooOOo % OoO0O00 . OoooooooOO / OoO0O00 * o0oOOo0O0Ooo . I1IiiI
 if 39 - 39: oO0o
 map_notify . retransmit_timer = threading . Timer ( LISP_MAP_NOTIFY_INTERVAL ,
 lisp_retransmit_map_notify , [ map_notify ] )
 map_notify . retransmit_timer . start ( )
 return
 if 68 - 68: iIii1I11I1II1 + I1IiiI + iII111i - I1Ii111 * OoO0O00
 if 28 - 28: I11i - iII111i - OOooOOo - ooOoO0o
 if 68 - 68: I11i + Ii1I
 if 70 - 70: I11i + oO0o + o0oOOo0O0Ooo . I1Ii111 * i11iIiiIii
 if 46 - 46: O0 . i11iIiiIii / OoO0O00 - iIii1I11I1II1 . iIii1I11I1II1
 if 39 - 39: i11iIiiIii + I1Ii111
 if 49 - 49: i1IIi * iII111i - iIii1I11I1II1 % I11i * O0 / OoOoOO00
def lisp_send_merged_map_notify ( lisp_sockets , parent , map_register ,
 eid_record ) :
 if 48 - 48: IiII
 if 69 - 69: o0oOOo0O0Ooo % i11iIiiIii - OOooOOo - o0oOOo0O0Ooo
 if 98 - 98: o0oOOo0O0Ooo * OoO0O00 . OoooooooOO
 if 40 - 40: I1Ii111 + Oo0Ooo + I1Ii111
 eid_record . rloc_count = len ( parent . registered_rlocs )
 o00o = eid_record . encode ( )
 eid_record . print_record ( "Merged Map-Notify " , False )
 if 82 - 82: oO0o % IiII
 if 49 - 49: i11iIiiIii + I1IiiI . I11i % OOooOOo
 if 74 - 74: o0oOOo0O0Ooo . I1IiiI / i1IIi + OoOoOO00
 if 30 - 30: iIii1I11I1II1 + OoooooooOO - I1Ii111
 for i111ii in parent . registered_rlocs :
  O0OO0 = lisp_rloc_record ( )
  O0OO0 . store_rloc_entry ( i111ii )
  o00o += O0OO0 . encode ( )
  O0OO0 . print_record ( "  " )
  del ( O0OO0 )
  if 41 - 41: OOooOOo
  if 43 - 43: I1IiiI . Oo0Ooo + i1IIi + I11i / OoO0O00
  if 66 - 66: i11iIiiIii
  if 83 - 83: I1Ii111 / iIii1I11I1II1 - oO0o
  if 3 - 3: OOooOOo - Oo0Ooo * I1IiiI - OoO0O00 / OOooOOo + IiII
 for i111ii in parent . registered_rlocs :
  IiI1 = i111ii . rloc
  OoOoooooO00oo = lisp_map_notify ( lisp_sockets )
  OoOoooooO00oo . record_count = 1
  iIIi1 = map_register . key_id
  OoOoooooO00oo . key_id = iIIi1
  OoOoooooO00oo . alg_id = map_register . alg_id
  OoOoooooO00oo . auth_len = map_register . auth_len
  OoOoooooO00oo . nonce = map_register . nonce
  OoOoooooO00oo . nonce_key = lisp_hex_string ( OoOoooooO00oo . nonce )
  OoOoooooO00oo . etr . copy_address ( IiI1 )
  OoOoooooO00oo . etr_port = map_register . sport
  OoOoooooO00oo . site = parent . site
  I111 = OoOoooooO00oo . encode ( o00o , parent . site . auth_key [ iIIi1 ] )
  OoOoooooO00oo . print_notify ( )
  if 73 - 73: Ii1I . II111iiii
  if 65 - 65: oO0o / Ii1I
  if 64 - 64: i1IIi + Ii1I - II111iiii % I1Ii111 / I11i
  if 2 - 2: I11i * o0oOOo0O0Ooo * OoOoOO00 % I1IiiI . I1IiiI
  OOoOoO = OoOoooooO00oo . nonce_key
  if ( lisp_map_notify_queue . has_key ( OOoOoO ) ) :
   ooO0oOoO00 = lisp_map_notify_queue [ OOoOoO ]
   ooO0oOoO00 . retransmit_timer . cancel ( )
   del ( ooO0oOoO00 )
   if 97 - 97: iIii1I11I1II1 * i1IIi * II111iiii - OOooOOo - Oo0Ooo - iIii1I11I1II1
  lisp_map_notify_queue [ OOoOoO ] = OoOoooooO00oo
  if 26 - 26: ooOoO0o + Oo0Ooo
  if 24 - 24: I1IiiI
  if 43 - 43: OoO0O00
  if 51 - 51: OoooooooOO % IiII % Oo0Ooo
  lprint ( "Send merged Map-Notify to ETR {}" . format ( red ( IiI1 . print_address ( ) , False ) ) )
  if 50 - 50: I1IiiI - i11iIiiIii / I1ii11iIi11i . Ii1I - iIii1I11I1II1
  lisp_send ( lisp_sockets , IiI1 , LISP_CTRL_PORT , I111 )
  if 91 - 91: I1IiiI . I1Ii111 + II111iiii . Oo0Ooo
  parent . site . map_notifies_sent += 1
  if 95 - 95: iII111i
  if 77 - 77: I1IiiI * II111iiii * iIii1I11I1II1
  if 19 - 19: OOooOOo * o0oOOo0O0Ooo
  if 64 - 64: I11i % ooOoO0o / OOooOOo / iII111i
  OoOoooooO00oo . retransmit_timer = threading . Timer ( LISP_MAP_NOTIFY_INTERVAL ,
 lisp_retransmit_map_notify , [ OoOoooooO00oo ] )
  OoOoooooO00oo . retransmit_timer . start ( )
  if 80 - 80: i1IIi
 return
 if 74 - 74: I1ii11iIi11i . OoO0O00 + i11iIiiIii
 if 19 - 19: i1IIi / I1IiiI + IiII . iII111i
 if 68 - 68: iII111i
 if 29 - 29: II111iiii / II111iiii % OoO0O00 % Oo0Ooo . II111iiii
 if 33 - 33: OoooooooOO . OoO0O00 % OoooooooOO
 if 9 - 9: IiII * O0 + OOooOOo . II111iiii
 if 14 - 14: iIii1I11I1II1 + i11iIiiIii + o0oOOo0O0Ooo + o0oOOo0O0Ooo - IiII / I1Ii111
def lisp_build_map_notify ( lisp_sockets , eid_records , eid_list , record_count ,
 source , port , nonce , key_id , alg_id , auth_len , site , map_register_ack ) :
 if 70 - 70: OoooooooOO + I1IiiI / OOooOOo
 OOoOoO = lisp_hex_string ( nonce ) + source . print_address ( )
 if 19 - 19: I1Ii111 + i1IIi % OoooooooOO + i1IIi
 if 16 - 16: I1Ii111 + II111iiii + IiII
 if 34 - 34: iIii1I11I1II1 - II111iiii - ooOoO0o + oO0o
 if 46 - 46: ooOoO0o % II111iiii
 if 61 - 61: OoO0O00 . I1IiiI
 if 89 - 89: IiII
 lisp_remove_eid_from_map_notify_queue ( eid_list )
 if ( lisp_map_notify_queue . has_key ( OOoOoO ) ) :
  OoOoooooO00oo = lisp_map_notify_queue [ OOoOoO ]
  i1I1iIi1IiI = red ( source . print_address_no_iid ( ) , False )
  lprint ( "Map-Notify with nonce 0x{} pending for xTR {}" . format ( lisp_hex_string ( OoOoooooO00oo . nonce ) , i1I1iIi1IiI ) )
  if 73 - 73: II111iiii + ooOoO0o % OOooOOo . oO0o / oO0o * i1IIi
  return
  if 19 - 19: I1Ii111 + I11i
  if 21 - 21: OoOoOO00
 OoOoooooO00oo = lisp_map_notify ( lisp_sockets )
 OoOoooooO00oo . record_count = record_count
 key_id = key_id
 OoOoooooO00oo . key_id = key_id
 OoOoooooO00oo . alg_id = alg_id
 OoOoooooO00oo . auth_len = auth_len
 OoOoooooO00oo . nonce = nonce
 OoOoooooO00oo . nonce_key = lisp_hex_string ( nonce )
 OoOoooooO00oo . etr . copy_address ( source )
 OoOoooooO00oo . etr_port = port
 OoOoooooO00oo . site = site
 OoOoooooO00oo . eid_list = eid_list
 if 2 - 2: i1IIi . OOooOOo
 if 23 - 23: Ii1I - OOooOOo
 if 89 - 89: i11iIiiIii
 if 40 - 40: OoooooooOO % OoO0O00
 if ( map_register_ack == False ) :
  OOoOoO = OoOoooooO00oo . nonce_key
  lisp_map_notify_queue [ OOoOoO ] = OoOoooooO00oo
  if 54 - 54: i1IIi * OOooOOo - oO0o * OoooooooOO + II111iiii . IiII
  if 90 - 90: O0 - II111iiii + I1IiiI . iII111i
 if ( map_register_ack ) :
  lprint ( "Send Map-Notify to ack Map-Register" )
 else :
  lprint ( "Send Map-Notify for RLOC-set change" )
  if 3 - 3: o0oOOo0O0Ooo + i1IIi * Oo0Ooo
  if 6 - 6: OoO0O00 * OoooooooOO * iIii1I11I1II1
  if 87 - 87: iIii1I11I1II1 - ooOoO0o * iIii1I11I1II1
  if 79 - 79: ooOoO0o . oO0o + Ii1I * ooOoO0o + O0 . II111iiii
  if 8 - 8: IiII * OOooOOo + I11i + O0 * oO0o - oO0o
 I111 = OoOoooooO00oo . encode ( eid_records , site . auth_key [ key_id ] )
 OoOoooooO00oo . print_notify ( )
 if 19 - 19: OoO0O00 - ooOoO0o + I1ii11iIi11i / I1ii11iIi11i % I1Ii111 % iIii1I11I1II1
 if ( map_register_ack == False ) :
  oooOO0o0ooOO = lisp_eid_record ( )
  oooOO0o0ooOO . decode ( eid_records )
  oooOO0o0ooOO . print_record ( "  " , False )
  if 5 - 5: OoooooooOO + ooOoO0o - II111iiii . i11iIiiIii / oO0o - ooOoO0o
  if 3 - 3: iII111i
  if 74 - 74: i11iIiiIii + OoooooooOO . OOooOOo
  if 29 - 29: IiII % OoO0O00
  if 53 - 53: OoooooooOO - OoOoOO00 / IiII - I1Ii111
 lisp_send_map_notify ( lisp_sockets , I111 , OoOoooooO00oo . etr , port )
 site . map_notifies_sent += 1
 if 16 - 16: iIii1I11I1II1 / OOooOOo + I1IiiI * II111iiii . OOooOOo
 if ( map_register_ack ) : return
 if 68 - 68: IiII * IiII + oO0o / o0oOOo0O0Ooo
 if 41 - 41: OoOoOO00 - O0
 if 48 - 48: OoooooooOO % Ii1I * OoO0O00 / I1ii11iIi11i
 if 53 - 53: ooOoO0o + oO0o - II111iiii
 if 92 - 92: Oo0Ooo - I11i . ooOoO0o % oO0o
 if 6 - 6: iIii1I11I1II1 + oO0o
 OoOoooooO00oo . retransmit_timer = threading . Timer ( LISP_MAP_NOTIFY_INTERVAL ,
 lisp_retransmit_map_notify , [ OoOoooooO00oo ] )
 OoOoooooO00oo . retransmit_timer . start ( )
 return
 if 8 - 8: I1ii11iIi11i + o0oOOo0O0Ooo
 if 29 - 29: Ii1I . OOooOOo
 if 59 - 59: O0 . OoO0O00
 if 10 - 10: I1Ii111 / OoooooooOO / OoO0O00 * ooOoO0o
 if 81 - 81: i1IIi % I11i * iIii1I11I1II1
 if 39 - 39: iIii1I11I1II1 / O0 . OoooooooOO - O0 . OoO0O00 . oO0o
 if 59 - 59: II111iiii * I1IiiI
 if 12 - 12: i11iIiiIii - IiII . iII111i . Ii1I
def lisp_send_map_notify_ack ( lisp_sockets , eid_records , map_notify , ms ) :
 map_notify . map_notify_ack = True
 if 34 - 34: i1IIi % iII111i + Oo0Ooo * OoOoOO00 + OoO0O00
 if 37 - 37: I1Ii111 / OoooooooOO
 if 19 - 19: Ii1I - O0 + I1IiiI + OoooooooOO + ooOoO0o - Oo0Ooo
 if 45 - 45: I1IiiI . OoOoOO00 . OoOoOO00
 I111 = map_notify . encode ( eid_records , ms . password )
 map_notify . print_notify ( )
 if 20 - 20: OoOoOO00
 if 69 - 69: OoOoOO00 * Ii1I % ooOoO0o . OoOoOO00 / oO0o * I1Ii111
 if 93 - 93: OoO0O00 % IiII % ooOoO0o . I1IiiI
 if 96 - 96: II111iiii
 IiI1 = ms . map_server
 lprint ( "Send Map-Notify-Ack to {}" . format (
 red ( IiI1 . print_address ( ) , False ) ) )
 lisp_send ( lisp_sockets , IiI1 , LISP_CTRL_PORT , I111 )
 return
 if 73 - 73: II111iiii
 if 81 - 81: I1IiiI + OoO0O00
 if 22 - 22: OoO0O00 * OoOoOO00 * I11i * IiII . OoO0O00 . I1ii11iIi11i
 if 32 - 32: o0oOOo0O0Ooo - iII111i + i11iIiiIii / ooOoO0o . OoOoOO00 . IiII
 if 9 - 9: iIii1I11I1II1
 if 66 - 66: iIii1I11I1II1
 if 13 - 13: O0 / ooOoO0o
 if 64 - 64: i11iIiiIii + I1IiiI / Oo0Ooo - iII111i
def lisp_send_multicast_map_notify ( lisp_sockets , site_eid , eid_list , xtr ) :
 if 26 - 26: I1ii11iIi11i
 OoOoooooO00oo = lisp_map_notify ( lisp_sockets )
 OoOoooooO00oo . record_count = 1
 OoOoooooO00oo . nonce = lisp_get_control_nonce ( )
 OoOoooooO00oo . nonce_key = lisp_hex_string ( OoOoooooO00oo . nonce )
 OoOoooooO00oo . etr . copy_address ( xtr )
 OoOoooooO00oo . etr_port = LISP_CTRL_PORT
 OoOoooooO00oo . eid_list = eid_list
 OOoOoO = OoOoooooO00oo . nonce_key
 if 67 - 67: I1Ii111 * iIii1I11I1II1 / O0 + OoO0O00 * iIii1I11I1II1 % II111iiii
 if 13 - 13: Ii1I / ooOoO0o / iII111i % II111iiii * I1IiiI * II111iiii
 if 40 - 40: Ii1I / i1IIi . iII111i
 if 65 - 65: iIii1I11I1II1 * O0 . II111iiii * o0oOOo0O0Ooo . I1ii11iIi11i * I1IiiI
 if 63 - 63: II111iiii . Oo0Ooo % iIii1I11I1II1
 if 85 - 85: I1IiiI + i1IIi % I1Ii111
 lisp_remove_eid_from_map_notify_queue ( OoOoooooO00oo . eid_list )
 if ( lisp_map_notify_queue . has_key ( OOoOoO ) ) :
  OoOoooooO00oo = lisp_map_notify_queue [ OOoOoO ]
  lprint ( "Map-Notify with nonce 0x{} pending for ITR {}" . format ( OoOoooooO00oo . nonce , red ( xtr . print_address_no_iid ( ) , False ) ) )
  if 76 - 76: i11iIiiIii % i11iIiiIii
  return
  if 33 - 33: OOooOOo . ooOoO0o / iIii1I11I1II1 * OOooOOo / oO0o
  if 75 - 75: Ii1I - OoOoOO00 . OOooOOo - o0oOOo0O0Ooo - I1ii11iIi11i
  if 69 - 69: O0 % I1ii11iIi11i
  if 77 - 77: iIii1I11I1II1 . OOooOOo
  if 64 - 64: OoOoOO00 - i1IIi * i1IIi / iII111i * OoOoOO00 * OoO0O00
 lisp_map_notify_queue [ OOoOoO ] = OoOoooooO00oo
 if 61 - 61: OOooOOo
 if 51 - 51: Oo0Ooo * OOooOOo / iII111i
 if 49 - 49: ooOoO0o . i1IIi % I1Ii111 . I1IiiI . I1ii11iIi11i + OoO0O00
 if 65 - 65: I1ii11iIi11i + Ii1I / i11iIiiIii * I1Ii111 + OoooooooOO
 iIIIi1I1iI = site_eid . rtrs_in_rloc_set ( )
 if ( iIIIi1I1iI ) :
  if ( site_eid . is_rtr_in_rloc_set ( xtr ) ) : iIIIi1I1iI = False
  if 64 - 64: I1IiiI
  if 27 - 27: I1Ii111 % I1Ii111 - I11i + IiII - oO0o
  if 52 - 52: OOooOOo % Ii1I + iIii1I11I1II1 . ooOoO0o
  if 83 - 83: oO0o - iIii1I11I1II1 * iII111i
  if 17 - 17: I1IiiI . OoOoOO00
 oooOO0o0ooOO = lisp_eid_record ( )
 oooOO0o0ooOO . record_ttl = 1440
 oooOO0o0ooOO . eid . copy_address ( site_eid . eid )
 oooOO0o0ooOO . group . copy_address ( site_eid . group )
 oooOO0o0ooOO . rloc_count = 0
 for o0OO0O0OoOo0 in site_eid . registered_rlocs :
  if ( iIIIi1I1iI ^ o0OO0O0OoOo0 . is_rtr ( ) ) : continue
  oooOO0o0ooOO . rloc_count += 1
  if 14 - 14: OOooOOo
 I111 = oooOO0o0ooOO . encode ( )
 if 84 - 84: Ii1I + OoO0O00 + OOooOOo % ooOoO0o
 if 27 - 27: OoOoOO00 % I11i
 if 19 - 19: i1IIi - OoOoOO00
 if 26 - 26: IiII . i11iIiiIii % i11iIiiIii / IiII - Oo0Ooo / o0oOOo0O0Ooo
 OoOoooooO00oo . print_notify ( )
 oooOO0o0ooOO . print_record ( "  " , False )
 if 7 - 7: I1IiiI / OOooOOo * iIii1I11I1II1 * Ii1I * i1IIi
 if 87 - 87: IiII * Oo0Ooo - OOooOOo * OoOoOO00
 if 61 - 61: Oo0Ooo - OoooooooOO % I1ii11iIi11i / i1IIi + O0 % ooOoO0o
 if 79 - 79: I1ii11iIi11i
 for o0OO0O0OoOo0 in site_eid . registered_rlocs :
  if ( iIIIi1I1iI ^ o0OO0O0OoOo0 . is_rtr ( ) ) : continue
  O0OO0 = lisp_rloc_record ( )
  O0OO0 . store_rloc_entry ( o0OO0O0OoOo0 )
  I111 += O0OO0 . encode ( )
  O0OO0 . print_record ( "    " )
  if 9 - 9: IiII . O0
  if 66 - 66: i11iIiiIii
  if 33 - 33: i11iIiiIii % OoO0O00 * I1ii11iIi11i
  if 96 - 96: I11i % OoooooooOO * I11i . IiII / I1Ii111
  if 56 - 56: I1IiiI - iII111i % Ii1I . I1ii11iIi11i % i1IIi
 I111 = OoOoooooO00oo . encode ( I111 , "" )
 if ( I111 == None ) : return
 if 84 - 84: OoOoOO00
 if 99 - 99: OoO0O00 - OoOoOO00 - i1IIi / OoO0O00 * I1ii11iIi11i * iIii1I11I1II1
 if 65 - 65: iII111i - O0 / i1IIi . I1Ii111
 if 85 - 85: o0oOOo0O0Ooo % Ii1I
 lisp_send_map_notify ( lisp_sockets , I111 , xtr , LISP_CTRL_PORT )
 if 81 - 81: oO0o / OoO0O00 * i1IIi % iIii1I11I1II1
 if 23 - 23: II111iiii . II111iiii
 if 17 - 17: i11iIiiIii / IiII * I1IiiI . Oo0Ooo / o0oOOo0O0Ooo - iIii1I11I1II1
 if 21 - 21: OOooOOo % Ii1I
 OoOoooooO00oo . retransmit_timer = threading . Timer ( LISP_MAP_NOTIFY_INTERVAL ,
 lisp_retransmit_map_notify , [ OoOoooooO00oo ] )
 OoOoooooO00oo . retransmit_timer . start ( )
 return
 if 3 - 3: OOooOOo / ooOoO0o / I1Ii111 . I11i
 if 54 - 54: I1ii11iIi11i - I1IiiI . OoOoOO00
 if 36 - 36: OoO0O00 * I1IiiI / iII111i
 if 95 - 95: Ii1I . Oo0Ooo
 if 42 - 42: IiII . i1IIi % O0 * ooOoO0o - OOooOOo % ooOoO0o
 if 99 - 99: i1IIi + OoOoOO00 - iII111i % II111iiii
 if 6 - 6: ooOoO0o - I1Ii111 . OoOoOO00
def lisp_queue_multicast_map_notify ( lisp_sockets , rle_list ) :
 o0O00oOo = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
 if 10 - 10: ooOoO0o / II111iiii
 for i111IiI1III1 in rle_list :
  IiI1i111III1I = lisp_site_eid_lookup ( i111IiI1III1 [ 0 ] , i111IiI1III1 [ 1 ] , True )
  if ( IiI1i111III1I == None ) : continue
  if 92 - 92: iIii1I11I1II1 - ooOoO0o % I1Ii111
  if 75 - 75: I1IiiI
  if 55 - 55: iII111i - ooOoO0o / I1Ii111 / o0oOOo0O0Ooo
  if 57 - 57: iII111i % iII111i - II111iiii * I1IiiI / I11i
  if 100 - 100: Ii1I % OoO0O00 % OoooooooOO / II111iiii * I1Ii111
  if 64 - 64: I1Ii111 * OOooOOo * Ii1I + I1ii11iIi11i / iIii1I11I1II1 / Oo0Ooo
  if 50 - 50: OOooOOo % i11iIiiIii
  o0o0OOoOooo0 = IiI1i111III1I . registered_rlocs
  if ( len ( o0o0OOoOooo0 ) == 0 ) :
   oooooo0o = { }
   for I1i11I in IiI1i111III1I . individual_registrations . values ( ) :
    for o0OO0O0OoOo0 in I1i11I . registered_rlocs :
     if ( o0OO0O0OoOo0 . is_rtr ( ) == False ) : continue
     oooooo0o [ o0OO0O0OoOo0 . rloc . print_address ( ) ] = o0OO0O0OoOo0
     if 37 - 37: ooOoO0o
     if 56 - 56: Oo0Ooo * OoO0O00 . ooOoO0o . o0oOOo0O0Ooo
   o0o0OOoOooo0 = oooooo0o . values ( )
   if 70 - 70: O0 % OoooooooOO - Ii1I * Oo0Ooo
   if 18 - 18: OOooOOo . I1IiiI + i1IIi . I1IiiI
   if 3 - 3: O0 * O0 + II111iiii + OoOoOO00 * I11i % Oo0Ooo
   if 19 - 19: oO0o % IiII % OoooooooOO % I1ii11iIi11i / OoO0O00
   if 6 - 6: O0 * I1Ii111 - II111iiii
   if 60 - 60: oO0o % oO0o
  o0Oo0 = [ ]
  iiIi11iI11i = False
  if ( IiI1i111III1I . eid . address == 0 and IiI1i111III1I . eid . mask_len == 0 ) :
   OO0o0 = [ ]
   Oo0OoO0O = [ ] if len ( o0o0OOoOooo0 ) == 0 else o0o0OOoOooo0 [ 0 ] . rle . rle_nodes
   if 90 - 90: I1ii11iIi11i * oO0o
   for II1ii in Oo0OoO0O :
    o0Oo0 . append ( II1ii . address )
    OO0o0 . append ( II1ii . address . print_address_no_iid ( ) )
    if 29 - 29: OoOoOO00 % ooOoO0o . OoOoOO00 % OOooOOo - OoOoOO00
   lprint ( "Notify existing RLE-nodes {}" . format ( OO0o0 ) )
  else :
   if 81 - 81: i1IIi + I1IiiI - iIii1I11I1II1 / O0 . iIii1I11I1II1 - iIii1I11I1II1
   if 54 - 54: iII111i + OOooOOo + OoO0O00
   if 6 - 6: oO0o - OoooooooOO * iIii1I11I1II1 * I1ii11iIi11i
   if 65 - 65: IiII + OoOoOO00
   if 93 - 93: Ii1I
   for o0OO0O0OoOo0 in o0o0OOoOooo0 :
    if ( o0OO0O0OoOo0 . is_rtr ( ) ) : o0Oo0 . append ( o0OO0O0OoOo0 . rloc )
    if 43 - 43: iIii1I11I1II1 / iII111i - Ii1I + I11i % iII111i - OoO0O00
    if 5 - 5: OoO0O00 / ooOoO0o
    if 92 - 92: Oo0Ooo / iII111i + O0 * ooOoO0o * OOooOOo % Oo0Ooo
    if 97 - 97: oO0o / Ii1I
    if 70 - 70: iII111i / Oo0Ooo . OoOoOO00 - II111iiii * II111iiii % I1IiiI
   iiIi11iI11i = ( len ( o0Oo0 ) != 0 )
   if ( iiIi11iI11i == False ) :
    o0O0o = lisp_site_eid_lookup ( i111IiI1III1 [ 0 ] , o0O00oOo , False )
    if ( o0O0o == None ) : continue
    if 34 - 34: I1Ii111 + OOooOOo * iII111i / ooOoO0o % i11iIiiIii
    for o0OO0O0OoOo0 in o0O0o . registered_rlocs :
     if ( o0OO0O0OoOo0 . rloc . is_null ( ) ) : continue
     o0Oo0 . append ( o0OO0O0OoOo0 . rloc )
     if 91 - 91: IiII * Ii1I * OOooOOo
     if 17 - 17: o0oOOo0O0Ooo + Ii1I % I1ii11iIi11i + IiII % I1Ii111 + I1ii11iIi11i
     if 100 - 100: I11i * OoO0O00 - i1IIi + iII111i * Ii1I - OoooooooOO
     if 47 - 47: o0oOOo0O0Ooo / Ii1I - iII111i * OOooOOo / i11iIiiIii
     if 97 - 97: iIii1I11I1II1 + OoOoOO00 + OoOoOO00 * o0oOOo0O0Ooo
     if 14 - 14: II111iiii + I1ii11iIi11i * Oo0Ooo
   if ( len ( o0Oo0 ) == 0 ) :
    lprint ( "No ITRs or RTRs found for {}, Map-Notify suppressed" . format ( green ( IiI1i111III1I . print_eid_tuple ( ) , False ) ) )
    if 95 - 95: IiII + iII111i % I1IiiI
    continue
    if 18 - 18: Oo0Ooo
    if 8 - 8: O0 + iIii1I11I1II1 - O0
    if 67 - 67: O0
    if 22 - 22: I11i / i1IIi . II111iiii % ooOoO0o / I11i - Ii1I
    if 28 - 28: O0 - Oo0Ooo
    if 58 - 58: iIii1I11I1II1 - OoooooooOO - iII111i
  for i111ii in o0Oo0 :
   lprint ( "Build Map-Notify to {}TR {} for {}" . format ( "R" if iiIi11iI11i else "x" , red ( i111ii . print_address_no_iid ( ) , False ) ,
   # i1IIi / o0oOOo0O0Ooo * I1ii11iIi11i
 green ( IiI1i111III1I . print_eid_tuple ( ) , False ) ) )
   if 100 - 100: I1Ii111 / O0 - iIii1I11I1II1 . iII111i % I1Ii111 - ooOoO0o
   OOOOoO = [ IiI1i111III1I . print_eid_tuple ( ) ]
   lisp_send_multicast_map_notify ( lisp_sockets , IiI1i111III1I , OOOOoO , i111ii )
   time . sleep ( .001 )
   if 93 - 93: i1IIi - IiII + IiII % OoooooooOO / o0oOOo0O0Ooo
   if 39 - 39: I1IiiI + Ii1I - O0
 return
 if 25 - 25: IiII % iIii1I11I1II1 + ooOoO0o % iII111i - OoO0O00
 if 36 - 36: OoooooooOO / oO0o + IiII . I1IiiI - o0oOOo0O0Ooo % OOooOOo
 if 15 - 15: Ii1I % IiII + IiII % iII111i - O0 * OoooooooOO
 if 53 - 53: OoOoOO00 . Ii1I / Oo0Ooo
 if 62 - 62: i11iIiiIii
 if 38 - 38: I1ii11iIi11i % ooOoO0o * OoooooooOO + iIii1I11I1II1 % i1IIi / OOooOOo
 if 6 - 6: i11iIiiIii
 if 8 - 8: iIii1I11I1II1 + I1ii11iIi11i . i1IIi % OoOoOO00 % OoooooooOO * Oo0Ooo
def lisp_find_sig_in_rloc_set ( packet , rloc_count ) :
 for oO in range ( rloc_count ) :
  O0OO0 = lisp_rloc_record ( )
  packet = O0OO0 . decode ( packet , None )
  ooOoOO0Oo = O0OO0 . json
  if ( ooOoOO0Oo == None ) : continue
  if 12 - 12: Oo0Ooo / iII111i
  try :
   ooOoOO0Oo = json . loads ( ooOoOO0Oo . json_string )
  except :
   lprint ( "Found corrupted JSON signature" )
   continue
   if 96 - 96: i1IIi
   if 6 - 6: OOooOOo
  if ( ooOoOO0Oo . has_key ( "signature" ) == False ) : continue
  return ( O0OO0 )
  if 7 - 7: I1ii11iIi11i + ooOoO0o . ooOoO0o + iII111i
 return ( None )
 if 100 - 100: I1Ii111
 if 71 - 71: ooOoO0o * i1IIi / OoOoOO00 * i11iIiiIii - iII111i
 if 88 - 88: IiII
 if 29 - 29: iII111i . ooOoO0o
 if 62 - 62: IiII
 if 95 - 95: ooOoO0o / i1IIi + II111iiii + OoO0O00 % OoO0O00
 if 18 - 18: ooOoO0o * I1IiiI / iII111i % iII111i
 if 9 - 9: i11iIiiIii % ooOoO0o % O0 + i1IIi / O0
 if 12 - 12: I1Ii111 - iII111i * iII111i + OoO0O00 . Ii1I % I11i
 if 28 - 28: ooOoO0o % OoO0O00 - II111iiii * IiII - I1IiiI + I1IiiI
 if 84 - 84: IiII / Ii1I
 if 39 - 39: OOooOOo - iIii1I11I1II1 + OoOoOO00 % IiII * OoooooooOO % Ii1I
 if 11 - 11: I1ii11iIi11i
 if 83 - 83: O0
 if 97 - 97: O0
 if 50 - 50: I1Ii111 / OoooooooOO . o0oOOo0O0Ooo + I1IiiI * i11iIiiIii
 if 28 - 28: I1Ii111 * II111iiii
 if 14 - 14: iIii1I11I1II1 / Ii1I + o0oOOo0O0Ooo . iII111i % iII111i . i1IIi
 if 67 - 67: IiII * II111iiii + ooOoO0o - i11iIiiIii
def lisp_get_eid_hash ( eid ) :
 iIii1i1IiI = None
 for IiII1i11I11i in lisp_eid_hashes :
  if 13 - 13: i11iIiiIii . OoO0O00 % O0
  if 84 - 84: iIii1I11I1II1 % IiII % i11iIiiIii
  if 45 - 45: o0oOOo0O0Ooo / Oo0Ooo * OoO0O00
  if 53 - 53: Ii1I + OoOoOO00 + OOooOOo
  IIiI1i = IiII1i11I11i . instance_id
  if ( IIiI1i == - 1 ) : IiII1i11I11i . instance_id = eid . instance_id
  if 61 - 61: iII111i
  ooo0OoOOo = eid . is_more_specific ( IiII1i11I11i )
  IiII1i11I11i . instance_id = IIiI1i
  if ( ooo0OoOOo ) :
   iIii1i1IiI = 128 - IiII1i11I11i . mask_len
   break
   if 37 - 37: OoO0O00 / I1Ii111 % II111iiii
   if 69 - 69: iIii1I11I1II1 % i11iIiiIii % iII111i - OOooOOo % Ii1I - I1ii11iIi11i
 if ( iIii1i1IiI == None ) : return ( None )
 if 85 - 85: O0 - OoooooooOO % Ii1I % i1IIi . i11iIiiIii . I1ii11iIi11i
 I1Ii11i = eid . address
 iiiII11Iii1 = ""
 for oO in range ( 0 , iIii1i1IiI / 16 ) :
  I1Iii1I = I1Ii11i & 0xffff
  I1Iii1I = hex ( I1Iii1I ) [ 2 : - 1 ]
  iiiII11Iii1 = I1Iii1I . zfill ( 4 ) + ":" + iiiII11Iii1
  I1Ii11i >>= 16
  if 93 - 93: oO0o * Oo0Ooo / Ii1I * OoO0O00
 if ( iIii1i1IiI % 16 != 0 ) :
  I1Iii1I = I1Ii11i & 0xff
  I1Iii1I = hex ( I1Iii1I ) [ 2 : - 1 ]
  iiiII11Iii1 = I1Iii1I . zfill ( 2 ) + ":" + iiiII11Iii1
  if 42 - 42: iII111i + IiII + I11i * ooOoO0o + Oo0Ooo . ooOoO0o
 return ( iiiII11Iii1 [ 0 : - 1 ] )
 if 38 - 38: iII111i * OoooooooOO - IiII
 if 36 - 36: I1Ii111 * II111iiii + I1ii11iIi11i - iII111i * iII111i
 if 91 - 91: O0 + I1Ii111 * II111iiii - O0 . i11iIiiIii . Oo0Ooo
 if 54 - 54: ooOoO0o * I11i / I1ii11iIi11i % ooOoO0o
 if 76 - 76: I11i . I1IiiI
 if 66 - 66: oO0o % oO0o * IiII
 if 39 - 39: i1IIi * Ii1I + OoOoOO00 / oO0o
 if 6 - 6: I1ii11iIi11i / II111iiii / OoOoOO00 . i11iIiiIii - iII111i
 if 43 - 43: i11iIiiIii * i11iIiiIii * I1Ii111
 if 80 - 80: oO0o . I1IiiI * II111iiii + o0oOOo0O0Ooo / o0oOOo0O0Ooo % OoooooooOO
 if 31 - 31: o0oOOo0O0Ooo - OoO0O00 % I1IiiI
def lisp_lookup_public_key ( eid ) :
 IIiI1i = eid . instance_id
 if 23 - 23: OOooOOo
 if 97 - 97: Oo0Ooo / OoooooooOO . OoooooooOO
 if 47 - 47: OoO0O00
 if 52 - 52: I1IiiI * iIii1I11I1II1 % oO0o * IiII % oO0o
 if 9 - 9: I11i
 o0ooo0oOO0o = lisp_get_eid_hash ( eid )
 if ( o0ooo0oOO0o == None ) : return ( [ None , None , False ] )
 if 78 - 78: iIii1I11I1II1 % I1ii11iIi11i % IiII
 o0ooo0oOO0o = "hash-" + o0ooo0oOO0o
 iIII = lisp_address ( LISP_AFI_NAME , o0ooo0oOO0o , len ( o0ooo0oOO0o ) , IIiI1i )
 oO0000O0o = lisp_address ( LISP_AFI_NONE , "" , 0 , IIiI1i )
 if 59 - 59: iII111i - I1ii11iIi11i / OoooooooOO
 if 37 - 37: Oo0Ooo - OoO0O00 . i11iIiiIii + I1IiiI . iIii1I11I1II1 % OoOoOO00
 if 61 - 61: oO0o . o0oOOo0O0Ooo
 if 82 - 82: Oo0Ooo * OoooooooOO / ooOoO0o / I1IiiI
 o0O0o = lisp_site_eid_lookup ( iIII , oO0000O0o , True )
 if ( o0O0o == None ) : return ( [ iIII , None , False ] )
 if 70 - 70: I1IiiI
 if 74 - 74: ooOoO0o * II111iiii
 if 96 - 96: i11iIiiIii . I1IiiI - II111iiii . I11i
 if 79 - 79: OoO0O00 . OoOoOO00 - i1IIi + Ii1I * i11iIiiIii . OoooooooOO
 iiI111 = None
 for II1iIiIiIIi in o0O0o . registered_rlocs :
  oOOoooO0ooo0o00 = II1iIiIiIIi . json
  if ( oOOoooO0ooo0o00 == None ) : continue
  try :
   oOOoooO0ooo0o00 = json . loads ( oOOoooO0ooo0o00 . json_string )
  except :
   lprint ( "Registered RLOC JSON format is invalid for {}" . format ( o0ooo0oOO0o ) )
   if 93 - 93: i11iIiiIii / OoooooooOO + i11iIiiIii
   return ( [ iIII , None , False ] )
   if 17 - 17: oO0o % ooOoO0o
  if ( oOOoooO0ooo0o00 . has_key ( "public-key" ) == False ) : continue
  iiI111 = oOOoooO0ooo0o00 [ "public-key" ]
  break
  if 21 - 21: ooOoO0o + o0oOOo0O0Ooo + Ii1I * ooOoO0o
 return ( [ iIII , iiI111 , True ] )
 if 15 - 15: I1ii11iIi11i * i11iIiiIii
 if 61 - 61: II111iiii - oO0o + O0 + Oo0Ooo % I1ii11iIi11i . OOooOOo
 if 88 - 88: iII111i * o0oOOo0O0Ooo + OoooooooOO * oO0o
 if 7 - 7: Oo0Ooo * Ii1I . IiII
 if 86 - 86: O0 * OoOoOO00 * I11i . OoooooooOO
 if 18 - 18: o0oOOo0O0Ooo + o0oOOo0O0Ooo . OoO0O00 . oO0o . iIii1I11I1II1
 if 62 - 62: OoO0O00 * i11iIiiIii / i1IIi . i11iIiiIii - o0oOOo0O0Ooo
 if 86 - 86: I1Ii111 / I1ii11iIi11i * iII111i . IiII * OoooooooOO - OoO0O00
def lisp_verify_cga_sig ( eid , rloc_record ) :
 if 80 - 80: OoOoOO00 * iIii1I11I1II1 % O0 . O0
 if 100 - 100: OoO0O00 + II111iiii % oO0o / OoOoOO00 * OOooOOo
 if 23 - 23: OoOoOO00
 if 56 - 56: o0oOOo0O0Ooo / oO0o * I1Ii111 + iIii1I11I1II1 / IiII + o0oOOo0O0Ooo
 if 50 - 50: I1IiiI * ooOoO0o
 I111II11I = json . loads ( rloc_record . json . json_string )
 if 49 - 49: oO0o . I11i + OoooooooOO / iII111i * Oo0Ooo % iIii1I11I1II1
 if ( lisp_get_eid_hash ( eid ) ) :
  i11iii1 = eid
 elif ( I111II11I . has_key ( "signature-eid" ) ) :
  Iiii1ii1I1IIi = I111II11I [ "signature-eid" ]
  i11iii1 = lisp_address ( LISP_AFI_IPV6 , Iiii1ii1I1IIi , 0 , 0 )
 else :
  lprint ( "  No signature-eid found in RLOC-record" )
  return ( False )
  if 31 - 31: I1Ii111
  if 53 - 53: IiII + I1IiiI % OoO0O00 + iIii1I11I1II1 + oO0o
  if 49 - 49: I1IiiI * I1Ii111 . I1IiiI - II111iiii
  if 57 - 57: oO0o + O0 - OoOoOO00
  if 14 - 14: II111iiii + i11iIiiIii + Ii1I / o0oOOo0O0Ooo . OoO0O00
 iIII , iiI111 , oOoooo = lisp_lookup_public_key ( i11iii1 )
 if ( iIII == None ) :
  oo0ooooO = green ( i11iii1 . print_address ( ) , False )
  lprint ( "  Could not parse hash in EID {}" . format ( oo0ooooO ) )
  return ( False )
  if 54 - 54: iIii1I11I1II1 - IiII + o0oOOo0O0Ooo + I1ii11iIi11i + IiII
  if 99 - 99: Oo0Ooo
 iIiI111I = "found" if oOoooo else bold ( "not found" , False )
 oo0ooooO = green ( iIII . print_address ( ) , False )
 lprint ( "  Lookup for crypto-hashed EID {} {}" . format ( oo0ooooO , iIiI111I ) )
 if ( oOoooo == False ) : return ( False )
 if 42 - 42: i11iIiiIii - O0 + O0
 if ( iiI111 == None ) :
  lprint ( "  RLOC-record with public-key not found" )
  return ( False )
  if 83 - 83: Oo0Ooo / I1ii11iIi11i % OoO0O00
  if 29 - 29: IiII - I1ii11iIi11i . Oo0Ooo + IiII - I1IiiI
 OoOO = iiI111 [ 0 : 8 ] + "..." + iiI111 [ - 8 : : ]
 lprint ( "  RLOC-record with public-key '{}' found" . format ( OoOO ) )
 if 27 - 27: IiII - IiII % OOooOOo
 if 16 - 16: I1IiiI * iIii1I11I1II1 % o0oOOo0O0Ooo - IiII - OOooOOo
 if 83 - 83: Ii1I
 if 20 - 20: ooOoO0o
 if 38 - 38: IiII + OoO0O00 . OOooOOo - I1Ii111 + IiII
 ooOO0Oo000 = I111II11I [ "signature" ]
 if 26 - 26: I1IiiI - OOooOOo
 try :
  I111II11I = binascii . a2b_base64 ( ooOO0Oo000 )
 except :
  lprint ( "  Incorrect padding in signature string" )
  return ( False )
  if 34 - 34: I1Ii111 % I1IiiI . OoOoOO00 / iII111i + ooOoO0o . i11iIiiIii
  if 51 - 51: OoooooooOO * I1Ii111 * I11i - I1ii11iIi11i + I1Ii111
 iiiiIi1111ii1 = len ( I111II11I )
 if ( iiiiIi1111ii1 & 1 ) :
  lprint ( "  Signature length is odd, length {}" . format ( iiiiIi1111ii1 ) )
  return ( False )
  if 10 - 10: i1IIi / i1IIi * iIii1I11I1II1 * OoOoOO00 * oO0o / II111iiii
  if 23 - 23: I11i . OoOoOO00 + I1Ii111 + oO0o + II111iiii
  if 71 - 71: OoOoOO00 * OoOoOO00
  if 27 - 27: II111iiii + OoooooooOO - I11i * o0oOOo0O0Ooo
  if 67 - 67: i11iIiiIii - OoOoOO00
 oOoO00OO00 = i11iii1 . print_address ( )
 if 90 - 90: i11iIiiIii . I1ii11iIi11i - OoooooooOO / o0oOOo0O0Ooo
 if 58 - 58: II111iiii + iIii1I11I1II1
 if 51 - 51: ooOoO0o - Ii1I + ooOoO0o
 if 87 - 87: O0 - I1IiiI
 iiI111 = binascii . a2b_base64 ( iiI111 )
 try :
  OOoOoO = ecdsa . VerifyingKey . from_pem ( iiI111 )
 except :
  II1Iii11 = bold ( "Bad public-key" , False )
  lprint ( "  {}, not in PEM format" . format ( II1Iii11 ) )
  return ( False )
  if 36 - 36: iIii1I11I1II1
  if 78 - 78: II111iiii * I11i
  if 47 - 47: Ii1I
  if 42 - 42: I11i . oO0o - I1IiiI / OoO0O00
  if 75 - 75: I1IiiI / OoOoOO00 . I11i * iIii1I11I1II1
  if 53 - 53: iIii1I11I1II1
  if 8 - 8: O0 - O0 - II111iiii
  if 77 - 77: i1IIi - ooOoO0o + O0 . OoO0O00 * I1Ii111 - I11i
  if 64 - 64: i1IIi + OoooooooOO + OOooOOo / ooOoO0o % I1IiiI . OoooooooOO
  if 96 - 96: II111iiii - OoOoOO00 + oO0o
  if 80 - 80: oO0o / OoOoOO00 - I11i / oO0o - iII111i - OoooooooOO
 try :
  oOo0 = OOoOoO . verify ( I111II11I , oOoO00OO00 , hashfunc = hashlib . sha256 )
 except :
  lprint ( "  Signature library failed for signature data '{}'" . format ( oOoO00OO00 ) )
  if 57 - 57: o0oOOo0O0Ooo
  lprint ( "  Signature used '{}'" . format ( ooOO0Oo000 ) )
  return ( False )
  if 37 - 37: iII111i * o0oOOo0O0Ooo
 return ( oOo0 )
 if 23 - 23: ooOoO0o + OoooooooOO * iII111i . I11i
 if 2 - 2: iIii1I11I1II1 * I1ii11iIi11i - OoooooooOO
 if 93 - 93: iII111i % ooOoO0o * Oo0Ooo
 if 34 - 34: O0 * oO0o
 if 58 - 58: OOooOOo . iII111i - Oo0Ooo / iII111i . I11i
 if 86 - 86: iIii1I11I1II1 - iII111i % Ii1I
 if 18 - 18: oO0o / IiII - OOooOOo % Ii1I
 if 88 - 88: i11iIiiIii
 if 13 - 13: I1IiiI
 if 52 - 52: Ii1I * oO0o / I1Ii111 . IiII
def lisp_remove_eid_from_map_notify_queue ( eid_list ) :
 if 84 - 84: OoooooooOO - oO0o - I1Ii111
 if 69 - 69: OoOoOO00 * Ii1I % OoooooooOO % OOooOOo * OoOoOO00
 if 20 - 20: IiII
 if 17 - 17: o0oOOo0O0Ooo % iIii1I11I1II1
 if 66 - 66: OoooooooOO + IiII . II111iiii
 oo0Oo0O00OO = [ ]
 for OO in eid_list :
  for OOO0O0OOoOo in lisp_map_notify_queue :
   OoOoooooO00oo = lisp_map_notify_queue [ OOO0O0OOoOo ]
   if ( OO not in OoOoooooO00oo . eid_list ) : continue
   if 68 - 68: O0 . Ii1I * O0 * OoOoOO00 - OoOoOO00 * I1ii11iIi11i
   oo0Oo0O00OO . append ( OOO0O0OOoOo )
   II1I11 = OoOoooooO00oo . retransmit_timer
   if ( II1I11 ) : II1I11 . cancel ( )
   if 69 - 69: I11i * II111iiii . i11iIiiIii / ooOoO0o . Oo0Ooo
   lprint ( "Remove from Map-Notify queue nonce 0x{} for EID {}" . format ( OoOoooooO00oo . nonce_key , green ( OO , False ) ) )
   if 38 - 38: OoOoOO00 % oO0o + Ii1I
   if 93 - 93: OoooooooOO + oO0o . OoOoOO00
   if 31 - 31: OoO0O00 + i11iIiiIii / I11i % O0 / Ii1I
   if 90 - 90: iIii1I11I1II1 % oO0o % IiII
   if 84 - 84: I1IiiI * IiII * iII111i / i1IIi . II111iiii * o0oOOo0O0Ooo
   if 1 - 1: oO0o - iIii1I11I1II1 % i1IIi
   if 94 - 94: Oo0Ooo + iIii1I11I1II1 . OoO0O00 * oO0o . i1IIi
 for OOO0O0OOoOo in oo0Oo0O00OO : lisp_map_notify_queue . pop ( OOO0O0OOoOo )
 return
 if 85 - 85: O0 / OoOoOO00 . iII111i
 if 64 - 64: OoO0O00 + I1ii11iIi11i / OoO0O00 * I1Ii111 . Oo0Ooo
 if 5 - 5: iII111i - iIii1I11I1II1 * IiII
 if 52 - 52: OOooOOo
 if 50 - 50: OoOoOO00 % o0oOOo0O0Ooo - II111iiii - i1IIi
 if 35 - 35: Oo0Ooo - ooOoO0o % OoO0O00
 if 26 - 26: i1IIi * I1Ii111 * OoO0O00 - IiII
 if 26 - 26: Oo0Ooo - ooOoO0o . iII111i * OoOoOO00 / OoooooooOO
def lisp_decrypt_map_register ( packet ) :
 if 66 - 66: I1IiiI
 if 45 - 45: II111iiii * I1Ii111 - II111iiii / I1IiiI % oO0o
 if 83 - 83: oO0o % OoO0O00 + I1ii11iIi11i / OoooooooOO % iII111i
 if 22 - 22: I1Ii111
 if 41 - 41: O0 * i1IIi
 ooo0Oo00O = socket . ntohl ( struct . unpack ( "I" , packet [ 0 : 4 ] ) [ 0 ] )
 OoOOooOo = ( ooo0Oo00O >> 13 ) & 0x1
 if ( OoOOooOo == 0 ) : return ( packet )
 if 44 - 44: O0 - I1IiiI
 o0O = ( ooo0Oo00O >> 14 ) & 0x7
 if 91 - 91: O0 - oO0o * O0
 if 98 - 98: Ii1I
 if 54 - 54: oO0o
 if 85 - 85: oO0o % o0oOOo0O0Ooo % IiII
 try :
  o0III = lisp_ms_encryption_keys [ o0O ]
  o0III = o0III . zfill ( 32 )
  OOOooO00OO00O = "0" * 8
 except :
  lprint ( "Cannot decrypt Map-Register with key-id {}" . format ( o0O ) )
  return ( None )
  if 16 - 16: i11iIiiIii . OoOoOO00 * i11iIiiIii - I11i
  if 75 - 75: ooOoO0o . oO0o . OoOoOO00
 O0o0oo0oOO0oO = bold ( "Decrypt" , False )
 lprint ( "{} Map-Register with key-id {}" . format ( O0o0oo0oOO0oO , o0O ) )
 if 72 - 72: I11i % ooOoO0o / O0 . O0
 Ii1IiiiI1ii = chacha . ChaCha ( o0III , OOOooO00OO00O ) . decrypt ( packet [ 4 : : ] )
 return ( packet [ 0 : 4 ] + Ii1IiiiI1ii )
 if 7 - 7: O0 * I1ii11iIi11i + Ii1I + oO0o % oO0o
 if 47 - 47: oO0o * I1ii11iIi11i
 if 85 - 85: OoooooooOO * I1ii11iIi11i + i11iIiiIii . iII111i * II111iiii / oO0o
 if 14 - 14: I1Ii111
 if 49 - 49: I1IiiI . OOooOOo / OoooooooOO + I11i - I11i
 if 27 - 27: Ii1I / o0oOOo0O0Ooo . iIii1I11I1II1 . I1IiiI - OoO0O00
 if 28 - 28: ooOoO0o
def lisp_process_map_register ( lisp_sockets , packet , source , sport ) :
 global lisp_registered_count
 if 88 - 88: oO0o
 if 77 - 77: ooOoO0o + I1Ii111 . OoOoOO00
 if 2 - 2: i1IIi - IiII + iIii1I11I1II1 % i1IIi * II111iiii
 if 26 - 26: I11i
 if 57 - 57: I1ii11iIi11i + I1Ii111 + i11iIiiIii . i1IIi / i11iIiiIii
 if 43 - 43: Ii1I % I11i
 packet = lisp_decrypt_map_register ( packet )
 if ( packet == None ) : return
 if 5 - 5: OoooooooOO % i11iIiiIii * o0oOOo0O0Ooo * OoooooooOO - o0oOOo0O0Ooo % I11i
 OoO0OOOOoo = lisp_map_register ( )
 Oo0OOOO , packet = OoO0OOOOoo . decode ( packet )
 if ( packet == None ) :
  lprint ( "Could not decode Map-Register packet" )
  return
  if 7 - 7: OOooOOo . Ii1I + I1Ii111
 OoO0OOOOoo . sport = sport
 if 67 - 67: Oo0Ooo * O0 . iIii1I11I1II1 / I11i * i1IIi * I1IiiI
 OoO0OOOOoo . print_map_register ( )
 if 10 - 10: I1Ii111 / I1IiiI + OOooOOo + OOooOOo - OoOoOO00 / i1IIi
 if 44 - 44: i11iIiiIii - iII111i . I1IiiI * o0oOOo0O0Ooo
 if 54 - 54: O0 % OoooooooOO / i1IIi % OOooOOo
 if 62 - 62: OOooOOo / OoooooooOO + Ii1I - iII111i + I1IiiI
 i1iI1i = True
 if ( OoO0OOOOoo . auth_len == LISP_SHA1_160_AUTH_DATA_LEN ) :
  i1iI1i = True
  if 29 - 29: II111iiii / I1ii11iIi11i * OOooOOo
 if ( OoO0OOOOoo . alg_id == LISP_SHA_256_128_ALG_ID ) :
  i1iI1i = False
  if 39 - 39: O0 . OOooOOo
  if 95 - 95: I11i
  if 58 - 58: I1ii11iIi11i / i11iIiiIii + iII111i + I11i / oO0o
  if 8 - 8: I1ii11iIi11i
  if 100 - 100: OoooooooOO / I11i - Ii1I
 iiiIi11 = [ ]
 if 92 - 92: I1ii11iIi11i . oO0o
 if 8 - 8: o0oOOo0O0Ooo / oO0o
 if 68 - 68: I1Ii111 % Ii1I * Oo0Ooo - O0 . IiII
 if 1 - 1: I1ii11iIi11i
 Ii1IiI1Ii1 = None
 I11i11Ii1i11i1iiIii = packet
 OO0O0ooo = [ ]
 OO0Oo0o0o = OoO0OOOOoo . record_count
 for oO in range ( OO0Oo0o0o ) :
  oooOO0o0ooOO = lisp_eid_record ( )
  O0OO0 = lisp_rloc_record ( )
  packet = oooOO0o0ooOO . decode ( packet )
  if ( packet == None ) :
   lprint ( "Could not decode EID-record in Map-Register packet" )
   return
   if 76 - 76: iII111i
  oooOO0o0ooOO . print_record ( "  " , False )
  if 85 - 85: I1ii11iIi11i + OOooOOo % i1IIi
  if 13 - 13: OOooOOo + i11iIiiIii / OOooOOo . O0 . OoO0O00 - Ii1I
  if 31 - 31: OoOoOO00 * o0oOOo0O0Ooo / O0 . iII111i / i11iIiiIii
  if 22 - 22: I1IiiI . OoooooooOO * I1ii11iIi11i + i11iIiiIii - O0 + i11iIiiIii
  o0O0o = lisp_site_eid_lookup ( oooOO0o0ooOO . eid , oooOO0o0ooOO . group ,
 False )
  if 98 - 98: OOooOOo + I1IiiI / IiII / OoooooooOO / OOooOOo
  Ii1II11ii1iIi = o0O0o . print_eid_tuple ( ) if o0O0o else None
  if 71 - 71: OoOoOO00 . OoOoOO00 . I11i . OOooOOo + I1ii11iIi11i
  if 56 - 56: i1IIi * IiII % i1IIi
  if 97 - 97: OoO0O00 . iIii1I11I1II1 / ooOoO0o
  if 4 - 4: Oo0Ooo - i1IIi . Oo0Ooo * I11i . i1IIi + OOooOOo
  if 3 - 3: IiII / iII111i * iII111i
  if 15 - 15: O0 + I1IiiI * OoO0O00 - i1IIi + Ii1I . i1IIi
  if 99 - 99: II111iiii + iIii1I11I1II1 / o0oOOo0O0Ooo / i11iIiiIii % iIii1I11I1II1 - iIii1I11I1II1
  if ( o0O0o and o0O0o . accept_more_specifics == False ) :
   if ( o0O0o . eid_record_matches ( oooOO0o0ooOO ) == False ) :
    iiIo00ooO = o0O0o . parent_for_more_specifics
    if ( iiIo00ooO ) : o0O0o = iiIo00ooO
    if 99 - 99: I11i + ooOoO0o % I11i + O0 - Ii1I - I1Ii111
    if 3 - 3: Oo0Ooo . I1IiiI
    if 61 - 61: OoO0O00 - I1ii11iIi11i . Ii1I * i11iIiiIii
    if 97 - 97: ooOoO0o
    if 58 - 58: iII111i
    if 47 - 47: II111iiii % Oo0Ooo . iIii1I11I1II1 . oO0o
    if 52 - 52: I11i * I1IiiI % I11i - iII111i - Ii1I - OoooooooOO
    if 15 - 15: iII111i
  OoIiIii1 = ( o0O0o and o0O0o . accept_more_specifics )
  if ( OoIiIii1 ) :
   Oo000OooOO = lisp_site_eid ( o0O0o . site )
   Oo000OooOO . dynamic = True
   Oo000OooOO . eid . copy_address ( oooOO0o0ooOO . eid )
   Oo000OooOO . group . copy_address ( oooOO0o0ooOO . group )
   Oo000OooOO . parent_for_more_specifics = o0O0o
   Oo000OooOO . add_cache ( )
   Oo000OooOO . inherit_from_ams_parent ( )
   o0O0o . more_specific_registrations . append ( Oo000OooOO )
   o0O0o = Oo000OooOO
  else :
   o0O0o = lisp_site_eid_lookup ( oooOO0o0ooOO . eid , oooOO0o0ooOO . group ,
 True )
   if 96 - 96: oO0o . ooOoO0o * Oo0Ooo % ooOoO0o + I1Ii111 + iIii1I11I1II1
   if 45 - 45: II111iiii
  oo0ooooO = oooOO0o0ooOO . print_eid_tuple ( )
  if 42 - 42: ooOoO0o
  if ( o0O0o == None ) :
   I1II1i1Ii = bold ( "Site not found" , False )
   lprint ( "  {} for EID {}{}" . format ( I1II1i1Ii , green ( oo0ooooO , False ) ,
 ", matched non-ams {}" . format ( green ( Ii1II11ii1iIi , False ) if Ii1II11ii1iIi else "" ) ) )
   if 62 - 62: II111iiii * o0oOOo0O0Ooo . OoO0O00 / II111iiii
   if 5 - 5: OoO0O00 + O0 . OoooooooOO + I1IiiI + i1IIi * OOooOOo
   if 19 - 19: OoooooooOO + i11iIiiIii / II111iiii - Oo0Ooo . OOooOOo
   if 10 - 10: oO0o * Oo0Ooo
   if 55 - 55: OoO0O00 - i1IIi - I11i * oO0o
   packet = O0OO0 . end_of_rlocs ( packet , oooOO0o0ooOO . rloc_count )
   if ( packet == None ) :
    lprint ( "  Could not decode RLOC-record in Map-Register packet" )
    return
    if 91 - 91: I1Ii111
   continue
   if 77 - 77: I1ii11iIi11i . ooOoO0o - iIii1I11I1II1 + Ii1I % II111iiii * II111iiii
   if 41 - 41: II111iiii + Oo0Ooo - IiII / I1Ii111 - OOooOOo . oO0o
  Ii1IiI1Ii1 = o0O0o . site
  if 100 - 100: ooOoO0o / I1ii11iIi11i * OoOoOO00 . I1ii11iIi11i . o0oOOo0O0Ooo * iIii1I11I1II1
  if ( OoIiIii1 ) :
   I1i11II = o0O0o . parent_for_more_specifics . print_eid_tuple ( )
   lprint ( "  Found ams {} for site '{}' for registering prefix {}" . format ( green ( I1i11II , False ) , Ii1IiI1Ii1 . site_name , green ( oo0ooooO , False ) ) )
   if 15 - 15: iII111i + o0oOOo0O0Ooo / IiII
  else :
   I1i11II = green ( o0O0o . print_eid_tuple ( ) , False )
   lprint ( "  Found {} for site '{}' for registering prefix {}" . format ( I1i11II , Ii1IiI1Ii1 . site_name , green ( oo0ooooO , False ) ) )
   if 33 - 33: OoooooooOO . IiII * o0oOOo0O0Ooo
   if 41 - 41: Ii1I . iII111i . o0oOOo0O0Ooo % OoooooooOO % IiII
   if 81 - 81: IiII * i11iIiiIii + i1IIi + OOooOOo . i1IIi
   if 6 - 6: i11iIiiIii - oO0o % OoO0O00 + iIii1I11I1II1
   if 69 - 69: IiII
   if 13 - 13: i11iIiiIii
  if ( Ii1IiI1Ii1 . shutdown ) :
   lprint ( ( "  Rejecting registration for site '{}', configured in " +
 "admin-shutdown state" ) . format ( Ii1IiI1Ii1 . site_name ) )
   packet = O0OO0 . end_of_rlocs ( packet , oooOO0o0ooOO . rloc_count )
   continue
   if 49 - 49: OoOoOO00
   if 61 - 61: I1Ii111 / I1Ii111 / iII111i / ooOoO0o - I1IiiI . o0oOOo0O0Ooo
   if 80 - 80: I1IiiI - OOooOOo . oO0o
   if 75 - 75: oO0o + OoOoOO00 - OoooooooOO
   if 38 - 38: I11i / ooOoO0o / OoOoOO00 * OOooOOo . oO0o
   if 8 - 8: OoO0O00 . OOooOOo % I1Ii111 * OOooOOo / I1IiiI
   if 3 - 3: IiII - I1ii11iIi11i . o0oOOo0O0Ooo
   if 39 - 39: oO0o . I1Ii111 + oO0o % OoOoOO00 - i11iIiiIii
  iIIi1 = OoO0OOOOoo . key_id
  if ( Ii1IiI1Ii1 . auth_key . has_key ( iIIi1 ) == False ) : iIIi1 = 0
  o0O0 = Ii1IiI1Ii1 . auth_key [ iIIi1 ]
  if 22 - 22: i1IIi . O0
  oOO0ooo0O0oOo = lisp_verify_auth ( Oo0OOOO , OoO0OOOOoo . alg_id ,
 OoO0OOOOoo . auth_data , o0O0 )
  O0oo000Oo00 = "dynamic " if o0O0o . dynamic else ""
  if 7 - 7: Oo0Ooo
  i1 = bold ( "passed" if oOO0ooo0O0oOo else "failed" , False )
  iIIi1 = "key-id {}" . format ( iIIi1 ) if iIIi1 == OoO0OOOOoo . key_id else "bad key-id {}" . format ( OoO0OOOOoo . key_id )
  if 54 - 54: i1IIi + i11iIiiIii - oO0o - IiII
  lprint ( "  Authentication {} for {}EID-prefix {}, {}" . format ( i1 , O0oo000Oo00 , green ( oo0ooooO , False ) , iIIi1 ) )
  if 27 - 27: II111iiii . OoOoOO00 % IiII % OoO0O00
  if 91 - 91: o0oOOo0O0Ooo
  if 5 - 5: IiII * oO0o - OOooOOo % I1Ii111 / iII111i
  if 19 - 19: O0 / OOooOOo / I1Ii111 . o0oOOo0O0Ooo
  if 22 - 22: O0 * OOooOOo - OoooooooOO - Ii1I * I1ii11iIi11i
  if 21 - 21: I1IiiI . i11iIiiIii - o0oOOo0O0Ooo * II111iiii % iIii1I11I1II1
  iI1i1I = True
  o0O0iIII1Ii1Ii = ( lisp_get_eid_hash ( oooOO0o0ooOO . eid ) != None )
  if ( o0O0iIII1Ii1Ii or o0O0o . require_signature ) :
   iIIii1I = "Required " if o0O0o . require_signature else ""
   oo0ooooO = green ( oo0ooooO , False )
   II1iIiIiIIi = lisp_find_sig_in_rloc_set ( packet , oooOO0o0ooOO . rloc_count )
   if ( II1iIiIiIIi == None ) :
    iI1i1I = False
    lprint ( ( "  {}EID-crypto-hash signature verification {} " + "for EID-prefix {}, no signature found" ) . format ( iIIii1I ,
    # OoooooooOO + I1ii11iIi11i + OoooooooOO . I1Ii111
 bold ( "failed" , False ) , oo0ooooO ) )
   else :
    iI1i1I = lisp_verify_cga_sig ( oooOO0o0ooOO . eid , II1iIiIiIIi )
    i1 = bold ( "passed" if iI1i1I else "failed" , False )
    lprint ( ( "  {}EID-crypto-hash signature verification {} " + "for EID-prefix {}" ) . format ( iIIii1I , i1 , oo0ooooO ) )
    if 69 - 69: I1IiiI . I1ii11iIi11i . o0oOOo0O0Ooo + OoooooooOO
    if 52 - 52: i1IIi - oO0o
    if 33 - 33: Ii1I / I1ii11iIi11i . ooOoO0o . OoooooooOO
    if 45 - 45: OoO0O00 . I1ii11iIi11i + Ii1I / I11i - ooOoO0o / OoooooooOO
  if ( oOO0ooo0O0oOo == False or iI1i1I == False ) :
   packet = O0OO0 . end_of_rlocs ( packet , oooOO0o0ooOO . rloc_count )
   if ( packet == None ) :
    lprint ( "  Could not decode RLOC-record in Map-Register packet" )
    return
    if 44 - 44: OoO0O00 % O0 * IiII + iII111i
   continue
   if 79 - 79: ooOoO0o
   if 82 - 82: O0 - Oo0Ooo - i11iIiiIii
   if 9 - 9: OoooooooOO . i11iIiiIii * iIii1I11I1II1 / IiII * i11iIiiIii
   if 57 - 57: o0oOOo0O0Ooo . I1IiiI / iII111i / ooOoO0o - OoO0O00
   if 8 - 8: iIii1I11I1II1 % ooOoO0o + OoO0O00 . oO0o % I1IiiI - O0
   if 25 - 25: i11iIiiIii * OoOoOO00 + OoO0O00 . o0oOOo0O0Ooo
  if ( OoO0OOOOoo . merge_register_requested ) :
   iiIo00ooO = o0O0o
   iiIo00ooO . inconsistent_registration = False
   if 65 - 65: I1Ii111 + i1IIi / iII111i % O0 + II111iiii * i1IIi
   if 49 - 49: o0oOOo0O0Ooo + OOooOOo - II111iiii
   if 34 - 34: ooOoO0o . I1Ii111
   if 52 - 52: I1IiiI + I1Ii111 * oO0o / i11iIiiIii * iIii1I11I1II1
   if 27 - 27: Oo0Ooo
   if ( o0O0o . group . is_null ( ) ) :
    if ( iiIo00ooO . site_id != OoO0OOOOoo . site_id ) :
     iiIo00ooO . site_id = OoO0OOOOoo . site_id
     iiIo00ooO . registered = False
     iiIo00ooO . individual_registrations = { }
     iiIo00ooO . registered_rlocs = [ ]
     lisp_registered_count -= 1
     if 85 - 85: iIii1I11I1II1 . o0oOOo0O0Ooo + oO0o
     if 79 - 79: O0 - iIii1I11I1II1 + i1IIi . I11i
     if 21 - 21: II111iiii
   OOoOoO = source . address + OoO0OOOOoo . xtr_id
   if ( o0O0o . individual_registrations . has_key ( OOoOoO ) ) :
    o0O0o = o0O0o . individual_registrations [ OOoOoO ]
   else :
    o0O0o = lisp_site_eid ( Ii1IiI1Ii1 )
    o0O0o . eid . copy_address ( iiIo00ooO . eid )
    o0O0o . group . copy_address ( iiIo00ooO . group )
    iiIo00ooO . individual_registrations [ OOoOoO ] = o0O0o
    if 23 - 23: I11i * i1IIi . oO0o / IiII + o0oOOo0O0Ooo
  else :
   o0O0o . inconsistent_registration = o0O0o . merge_register_requested
   if 1 - 1: IiII / OoO0O00 . oO0o * I1Ii111 - i11iIiiIii
   if 50 - 50: oO0o - O0 / I1IiiI . OoOoOO00 . Oo0Ooo
   if 30 - 30: IiII . OoO0O00 + Oo0Ooo
  o0O0o . map_registers_received += 1
  if 48 - 48: iIii1I11I1II1 / i11iIiiIii . OoOoOO00 * I11i
  if 1 - 1: IiII . OoOoOO00 * o0oOOo0O0Ooo
  if 63 - 63: O0 / Ii1I + I1Ii111 % OoO0O00 % OOooOOo * O0
  if 35 - 35: OoO0O00 + OoooooooOO % Oo0Ooo / I11i - O0 . i1IIi
  if 76 - 76: IiII % I1IiiI * Ii1I / Ii1I / OoooooooOO + Ii1I
  II1Iii11 = ( o0O0o . is_rloc_in_rloc_set ( source ) == False )
  if ( oooOO0o0ooOO . record_ttl == 0 and II1Iii11 ) :
   lprint ( "  Ignore deregistration request from {}" . format ( red ( source . print_address_no_iid ( ) , False ) ) )
   if 19 - 19: OoooooooOO
   continue
   if 88 - 88: I1IiiI % ooOoO0o % Oo0Ooo - O0
   if 71 - 71: OOooOOo % Ii1I - i11iIiiIii - oO0o . ooOoO0o / I1Ii111
   if 53 - 53: iII111i . Oo0Ooo
   if 91 - 91: oO0o * OoooooooOO * oO0o % oO0o * II111iiii % I1Ii111
   if 8 - 8: Ii1I
   if 28 - 28: iII111i / I1ii11iIi11i - OoOoOO00 * Oo0Ooo + Ii1I * OoOoOO00
  o0O00Oo0o = o0O0o . registered_rlocs
  o0O0o . registered_rlocs = [ ]
  if 79 - 79: OoOoOO00 / OoOoOO00
  if 38 - 38: I1ii11iIi11i + i1IIi % iIii1I11I1II1
  if 96 - 96: OoOoOO00 - OoOoOO00
  if 59 - 59: OoOoOO00 / iII111i * i11iIiiIii
  o0OO00o0OO = packet
  for oOooO0Oo0Oo0 in range ( oooOO0o0ooOO . rloc_count ) :
   O0OO0 = lisp_rloc_record ( )
   packet = O0OO0 . decode ( packet , None )
   if ( packet == None ) :
    lprint ( "  Could not decode RLOC-record in Map-Register packet" )
    return
    if 59 - 59: iIii1I11I1II1 / Oo0Ooo % II111iiii
   O0OO0 . print_record ( "    " )
   if 55 - 55: ooOoO0o - IiII + o0oOOo0O0Ooo
   if 48 - 48: O0 - iIii1I11I1II1 * OOooOOo
   if 33 - 33: I11i
   if 63 - 63: Ii1I % II111iiii / OoOoOO00 + Oo0Ooo
   if ( len ( Ii1IiI1Ii1 . allowed_rlocs ) > 0 ) :
    I11i11I = O0OO0 . rloc . print_address ( )
    if ( Ii1IiI1Ii1 . allowed_rlocs . has_key ( I11i11I ) == False ) :
     lprint ( ( "  Reject registration, RLOC {} not " + "configured in allowed RLOC-set" ) . format ( red ( I11i11I , False ) ) )
     if 28 - 28: OoO0O00 + I1IiiI . oO0o + II111iiii - O0
     if 32 - 32: oO0o
     o0O0o . registered = False
     packet = O0OO0 . end_of_rlocs ( packet ,
 oooOO0o0ooOO . rloc_count - oOooO0Oo0Oo0 - 1 )
     break
     if 62 - 62: i11iIiiIii + OoooooooOO + IiII - OoO0O00 / oO0o * iIii1I11I1II1
     if 91 - 91: o0oOOo0O0Ooo - i11iIiiIii + Oo0Ooo % iIii1I11I1II1
     if 58 - 58: iII111i / ooOoO0o - I1Ii111 + I1Ii111 * ooOoO0o
     if 48 - 48: iII111i % O0 % Ii1I * OoO0O00 . OoO0O00
     if 74 - 74: OoO0O00 * i1IIi + I1ii11iIi11i / o0oOOo0O0Ooo / i1IIi
     if 94 - 94: Ii1I
   II1iIiIiIIi = lisp_rloc ( )
   II1iIiIiIIi . store_rloc_from_record ( O0OO0 , None , source )
   if 13 - 13: OoO0O00 - II111iiii . iII111i + OoOoOO00 / i11iIiiIii
   if 32 - 32: ooOoO0o / II111iiii / I1ii11iIi11i
   if 34 - 34: iIii1I11I1II1
   if 47 - 47: OOooOOo * iII111i
   if 71 - 71: IiII - OoooooooOO * i11iIiiIii . OoooooooOO % i1IIi . Oo0Ooo
   if 3 - 3: OoO0O00 + i11iIiiIii + oO0o * IiII
   if ( source . is_exact_match ( II1iIiIiIIi . rloc ) ) :
    II1iIiIiIIi . map_notify_requested = OoO0OOOOoo . map_notify_requested
    if 19 - 19: iII111i / II111iiii . I1Ii111 * I1IiiI - OOooOOo
    if 70 - 70: OoO0O00
    if 42 - 42: OoooooooOO - I1Ii111 + I1ii11iIi11i * iII111i * iII111i / OoO0O00
    if 85 - 85: O0 . II111iiii
    if 80 - 80: O0 * I11i * I1Ii111
   o0O0o . registered_rlocs . append ( II1iIiIiIIi )
   if 89 - 89: Ii1I * OoO0O00 . i1IIi . O0 - IiII - OoOoOO00
   if 25 - 25: iII111i + i1IIi
  o0o0oOo0O0 = ( o0O0o . do_rloc_sets_match ( o0O00Oo0o ) == False )
  if 42 - 42: I1IiiI + IiII . Ii1I * I11i - o0oOOo0O0Ooo
  if 61 - 61: iII111i % I1IiiI * II111iiii % oO0o / OoO0O00 * iII111i
  if 54 - 54: oO0o % ooOoO0o + Ii1I . ooOoO0o % I11i / Ii1I
  if 85 - 85: Ii1I % OoOoOO00
  if 28 - 28: IiII
  if 32 - 32: IiII * II111iiii . Ii1I
  if ( OoO0OOOOoo . map_register_refresh and o0o0oOo0O0 and
 o0O0o . registered ) :
   lprint ( "  Reject registration, refreshes cannot change RLOC-set" )
   o0O0o . registered_rlocs = o0O00Oo0o
   continue
   if 68 - 68: I11i / O0
   if 6 - 6: oO0o - oO0o . I1IiiI % I1ii11iIi11i
   if 22 - 22: Ii1I / I1IiiI / II111iiii
   if 31 - 31: II111iiii - Ii1I * OOooOOo - i11iIiiIii / OoooooooOO - I1Ii111
   if 76 - 76: Oo0Ooo
   if 93 - 93: i1IIi - I1IiiI * i11iIiiIii / Ii1I . Ii1I - i1IIi
  if ( o0O0o . registered == False ) :
   o0O0o . first_registered = lisp_get_timestamp ( )
   lisp_registered_count += 1
   if 19 - 19: iIii1I11I1II1 * OOooOOo * Oo0Ooo % I1IiiI
  o0O0o . last_registered = lisp_get_timestamp ( )
  o0O0o . registered = ( oooOO0o0ooOO . record_ttl != 0 )
  o0O0o . last_registerer = source
  if 93 - 93: IiII % OoOoOO00 / I1IiiI + o0oOOo0O0Ooo * ooOoO0o / i1IIi
  if 25 - 25: O0 / Oo0Ooo - o0oOOo0O0Ooo * Oo0Ooo
  if 45 - 45: Ii1I * IiII - OOooOOo
  if 57 - 57: iII111i % OoO0O00 / OoooooooOO
  o0O0o . auth_sha1_or_sha2 = i1iI1i
  o0O0o . proxy_reply_requested = OoO0OOOOoo . proxy_reply_requested
  o0O0o . lisp_sec_present = OoO0OOOOoo . lisp_sec_present
  o0O0o . map_notify_requested = OoO0OOOOoo . map_notify_requested
  o0O0o . mobile_node_requested = OoO0OOOOoo . mobile_node
  o0O0o . merge_register_requested = OoO0OOOOoo . merge_register_requested
  if 69 - 69: oO0o
  o0O0o . use_register_ttl_requested = OoO0OOOOoo . use_ttl_for_timeout
  if ( o0O0o . use_register_ttl_requested ) :
   o0O0o . register_ttl = oooOO0o0ooOO . store_ttl ( )
  else :
   o0O0o . register_ttl = LISP_SITE_TIMEOUT_CHECK_INTERVAL * 3
   if 44 - 44: IiII - II111iiii % Ii1I
  o0O0o . xtr_id_present = OoO0OOOOoo . xtr_id_present
  if ( o0O0o . xtr_id_present ) :
   o0O0o . xtr_id = OoO0OOOOoo . xtr_id
   o0O0o . site_id = OoO0OOOOoo . site_id
   if 64 - 64: Ii1I % OoO0O00 + OOooOOo % OoOoOO00 + IiII
   if 92 - 92: iII111i * Oo0Ooo - OoOoOO00
   if 33 - 33: i11iIiiIii - OoOoOO00 . OOooOOo * II111iiii . Ii1I
   if 59 - 59: OoOoOO00
   if 29 - 29: iII111i - II111iiii * OoooooooOO * OoooooooOO
  if ( OoO0OOOOoo . merge_register_requested ) :
   if ( iiIo00ooO . merge_in_site_eid ( o0O0o ) ) :
    iiiIi11 . append ( [ oooOO0o0ooOO . eid , oooOO0o0ooOO . group ] )
    if 15 - 15: IiII / OOooOOo / iIii1I11I1II1 / OoOoOO00
   if ( OoO0OOOOoo . map_notify_requested ) :
    lisp_send_merged_map_notify ( lisp_sockets , iiIo00ooO , OoO0OOOOoo ,
 oooOO0o0ooOO )
    if 91 - 91: i11iIiiIii % O0 . Oo0Ooo / I1Ii111
    if 62 - 62: Oo0Ooo . II111iiii % OoO0O00 . Ii1I * OOooOOo + II111iiii
    if 7 - 7: OOooOOo
  if ( o0o0oOo0O0 == False ) : continue
  if ( len ( iiiIi11 ) != 0 ) : continue
  if 22 - 22: Oo0Ooo + ooOoO0o
  OO0O0ooo . append ( o0O0o . print_eid_tuple ( ) )
  if 71 - 71: OOooOOo . Ii1I * i11iIiiIii . I11i
  if 9 - 9: O0 / I1ii11iIi11i . iII111i . O0 + IiII % I11i
  if 27 - 27: i11iIiiIii - I1ii11iIi11i / O0 - i1IIi + I1IiiI * iII111i
  if 26 - 26: Oo0Ooo . Ii1I
  if 7 - 7: OoOoOO00 - o0oOOo0O0Ooo + oO0o
  if 8 - 8: iIii1I11I1II1
  if 6 - 6: oO0o
  oooOO0o0ooOO = oooOO0o0ooOO . encode ( )
  oooOO0o0ooOO += o0OO00o0OO
  OOOOoO = [ o0O0o . print_eid_tuple ( ) ]
  lprint ( "    Changed RLOC-set, Map-Notifying old RLOC-set" )
  if 51 - 51: I1Ii111 - o0oOOo0O0Ooo
  for II1iIiIiIIi in o0O00Oo0o :
   if ( II1iIiIiIIi . map_notify_requested == False ) : continue
   if ( II1iIiIiIIi . rloc . is_exact_match ( source ) ) : continue
   lisp_build_map_notify ( lisp_sockets , oooOO0o0ooOO , OOOOoO , 1 , II1iIiIiIIi . rloc ,
 LISP_CTRL_PORT , OoO0OOOOoo . nonce , OoO0OOOOoo . key_id ,
 OoO0OOOOoo . alg_id , OoO0OOOOoo . auth_len , Ii1IiI1Ii1 , False )
   if 5 - 5: O0
   if 7 - 7: OoOoOO00 + OoO0O00 * I1IiiI
   if 63 - 63: I1ii11iIi11i + iII111i * i1IIi
   if 63 - 63: I1ii11iIi11i / II111iiii % oO0o + ooOoO0o . Ii1I % I11i
   if 59 - 59: I1Ii111 % o0oOOo0O0Ooo - I1IiiI * i1IIi
  lisp_notify_subscribers ( lisp_sockets , oooOO0o0ooOO , o0O0o . eid , Ii1IiI1Ii1 )
  if 5 - 5: I1IiiI
  if 22 - 22: II111iiii / iII111i
  if 18 - 18: i11iIiiIii * ooOoO0o . I1IiiI + i1IIi + I11i
  if 62 - 62: O0 % o0oOOo0O0Ooo + iIii1I11I1II1 + iIii1I11I1II1 * ooOoO0o
  if 21 - 21: o0oOOo0O0Ooo % O0
 if ( len ( iiiIi11 ) != 0 ) :
  lisp_queue_multicast_map_notify ( lisp_sockets , iiiIi11 )
  if 81 - 81: i1IIi + i1IIi
  if 3 - 3: I1Ii111 . I1ii11iIi11i * iII111i * i11iIiiIii * IiII
  if 52 - 52: iIii1I11I1II1 % o0oOOo0O0Ooo % I1IiiI
  if 71 - 71: I1IiiI + iII111i
  if 47 - 47: iIii1I11I1II1 . OoO0O00 . iIii1I11I1II1
  if 57 - 57: IiII * ooOoO0o * ooOoO0o * iIii1I11I1II1 * I1Ii111 + OoOoOO00
 if ( OoO0OOOOoo . merge_register_requested ) : return
 if 83 - 83: OoOoOO00 . Oo0Ooo . OoO0O00
 if 65 - 65: iII111i * iIii1I11I1II1
 if 48 - 48: iII111i * OoO0O00
 if 57 - 57: ooOoO0o + I1IiiI
 if 32 - 32: I1ii11iIi11i + OOooOOo - I11i
 if ( OoO0OOOOoo . map_notify_requested and Ii1IiI1Ii1 != None ) :
  lisp_build_map_notify ( lisp_sockets , I11i11Ii1i11i1iiIii , OO0O0ooo ,
 OoO0OOOOoo . record_count , source , sport , OoO0OOOOoo . nonce ,
 OoO0OOOOoo . key_id , OoO0OOOOoo . alg_id , OoO0OOOOoo . auth_len ,
 Ii1IiI1Ii1 , True )
  if 82 - 82: Oo0Ooo % Oo0Ooo
 return
 if 91 - 91: I11i
 if 98 - 98: I11i - II111iiii . IiII % Oo0Ooo
 if 65 - 65: OoO0O00
 if 65 - 65: oO0o
 if 77 - 77: I11i * i1IIi - OOooOOo / OoOoOO00
 if 50 - 50: O0 - oO0o . oO0o
 if 98 - 98: IiII % Ii1I / Ii1I
 if 10 - 10: Ii1I
 if 69 - 69: I1Ii111 * OoooooooOO . o0oOOo0O0Ooo % I1IiiI
 if 70 - 70: iII111i . i11iIiiIii * I1Ii111
def lisp_process_multicast_map_notify ( packet , source ) :
 OoOoooooO00oo = lisp_map_notify ( "" )
 packet = OoOoooooO00oo . decode ( packet )
 if ( packet == None ) :
  lprint ( "Could not decode Map-Notify packet" )
  return
  if 54 - 54: o0oOOo0O0Ooo . i1IIi / iII111i
  if 21 - 21: O0 + ooOoO0o
 OoOoooooO00oo . print_notify ( )
 if ( OoOoooooO00oo . record_count == 0 ) : return
 if 53 - 53: Ii1I - II111iiii * iIii1I11I1II1
 oOo0OooOOo = OoOoooooO00oo . eid_records
 if 65 - 65: o0oOOo0O0Ooo
 for oO in range ( OoOoooooO00oo . record_count ) :
  oooOO0o0ooOO = lisp_eid_record ( )
  oOo0OooOOo = oooOO0o0ooOO . decode ( oOo0OooOOo )
  if ( packet == None ) : return
  oooOO0o0ooOO . print_record ( "  " , False )
  if 73 - 73: I11i . I1ii11iIi11i - OoO0O00 + OoooooooOO
  if 71 - 71: I1IiiI
  if 27 - 27: OoO0O00 + i1IIi * OoooooooOO * iIii1I11I1II1 - Ii1I
  if 85 - 85: OoO0O00 + II111iiii / OoO0O00 . II111iiii * OoOoOO00 * I1IiiI
  iIi11 = lisp_map_cache_lookup ( oooOO0o0ooOO . eid , oooOO0o0ooOO . group )
  if ( iIi11 == None ) :
   iIi11 = lisp_mapping ( oooOO0o0ooOO . eid , oooOO0o0ooOO . group , [ ] )
   iIi11 . add_cache ( )
   if 19 - 19: iII111i / Ii1I + iIii1I11I1II1 * O0 - Oo0Ooo
   if 47 - 47: iIii1I11I1II1 % I1ii11iIi11i
  iIi11 . mapping_source = None if source == "lisp-etr" else source
  iIi11 . map_cache_ttl = oooOO0o0ooOO . store_ttl ( )
  if 33 - 33: oO0o . oO0o / IiII + II111iiii
  if 34 - 34: OoO0O00 . OoOoOO00 / i1IIi / OOooOOo
  if 12 - 12: o0oOOo0O0Ooo . Oo0Ooo / II111iiii
  if 18 - 18: I1Ii111 % II111iiii + Ii1I * Oo0Ooo - OoooooooOO . Oo0Ooo
  if 25 - 25: OoO0O00
  if ( len ( iIi11 . rloc_set ) != 0 and oooOO0o0ooOO . rloc_count == 0 ) :
   iIi11 . rloc_set = [ ]
   iIi11 . build_best_rloc_set ( )
   lisp_write_ipc_map_cache ( True , iIi11 )
   lprint ( "Update {} map-cache entry with no RLOC-set" . format ( green ( iIi11 . print_eid_tuple ( ) , False ) ) )
   if 83 - 83: II111iiii . iIii1I11I1II1
   continue
   if 77 - 77: O0 . OoOoOO00 % oO0o / OOooOOo
   if 8 - 8: iII111i - i1IIi
  O000o = iIi11 . rtrs_in_rloc_set ( )
  if 48 - 48: OoO0O00
  if 49 - 49: I1IiiI
  if 65 - 65: iII111i / I1ii11iIi11i . II111iiii % I1Ii111 + I1Ii111 / i11iIiiIii
  if 20 - 20: Ii1I * OoooooooOO - i11iIiiIii - iII111i + oO0o
  if 77 - 77: i11iIiiIii % OOooOOo
  for oOooO0Oo0Oo0 in range ( oooOO0o0ooOO . rloc_count ) :
   O0OO0 = lisp_rloc_record ( )
   oOo0OooOOo = O0OO0 . decode ( oOo0OooOOo , None )
   O0OO0 . print_record ( "    " )
   if ( oooOO0o0ooOO . group . is_null ( ) ) : continue
   if ( O0OO0 . rle == None ) : continue
   if 25 - 25: iII111i / I1ii11iIi11i - ooOoO0o
   if 53 - 53: IiII / OoooooooOO / ooOoO0o + Oo0Ooo - OOooOOo - iIii1I11I1II1
   if 53 - 53: OOooOOo . I1IiiI . o0oOOo0O0Ooo / o0oOOo0O0Ooo
   if 40 - 40: OoooooooOO + iII111i % I1Ii111 . ooOoO0o
   if 2 - 2: ooOoO0o
   O00o0O0 = iIi11 . rloc_set [ 0 ] . stats if len ( iIi11 . rloc_set ) != 0 else None
   if 40 - 40: II111iiii
   if 35 - 35: I1ii11iIi11i . OoO0O00 - OOooOOo * I11i . OoooooooOO - iII111i
   if 60 - 60: OOooOOo * I1IiiI + i1IIi % I11i - I1ii11iIi11i + Ii1I
   if 64 - 64: II111iiii - oO0o / iIii1I11I1II1 . Ii1I
   II1iIiIiIIi = lisp_rloc ( )
   II1iIiIiIIi . store_rloc_from_record ( O0OO0 , None , iIi11 . mapping_source )
   if ( O00o0O0 != None ) : II1iIiIiIIi . stats = copy . deepcopy ( O00o0O0 )
   if 23 - 23: o0oOOo0O0Ooo + I1IiiI
   if ( O000o and II1iIiIiIIi . is_rtr ( ) == False ) : continue
   if 85 - 85: o0oOOo0O0Ooo
   iIi11 . rloc_set = [ II1iIiIiIIi ]
   iIi11 . build_best_rloc_set ( )
   lisp_write_ipc_map_cache ( True , iIi11 )
   if 23 - 23: o0oOOo0O0Ooo / IiII - O0
   lprint ( "Update {} map-cache entry with RLE {}" . format ( green ( iIi11 . print_eid_tuple ( ) , False ) , II1iIiIiIIi . rle . print_rle ( False ) ) )
   if 60 - 60: I1ii11iIi11i * i11iIiiIii + oO0o
   if 59 - 59: I11i
   if 61 - 61: IiII * I1Ii111 * OoO0O00 / oO0o - OoooooooOO
 return
 if 5 - 5: o0oOOo0O0Ooo % OOooOOo % II111iiii
 if 86 - 86: O0 . ooOoO0o * OoooooooOO + Ii1I / I11i / II111iiii
 if 26 - 26: OoooooooOO - I1Ii111 / Oo0Ooo - iII111i % OoOoOO00 * OoooooooOO
 if 3 - 3: oO0o
 if 3 - 3: I1ii11iIi11i . IiII + ooOoO0o
 if 66 - 66: OOooOOo + oO0o - ooOoO0o / Ii1I * OoO0O00 * i11iIiiIii
 if 69 - 69: I11i % i11iIiiIii
 if 34 - 34: Ii1I . OoooooooOO + II111iiii % oO0o
def lisp_process_map_notify ( lisp_sockets , orig_packet , source ) :
 OoOoooooO00oo = lisp_map_notify ( "" )
 I111 = OoOoooooO00oo . decode ( orig_packet )
 if ( I111 == None ) :
  lprint ( "Could not decode Map-Notify packet" )
  return
  if 69 - 69: i11iIiiIii % I1IiiI * i11iIiiIii - OoO0O00 * iIii1I11I1II1
  if 70 - 70: I1Ii111 . OoOoOO00 % OoooooooOO + OoOoOO00 / II111iiii
 OoOoooooO00oo . print_notify ( )
 if 39 - 39: I1Ii111 * I1IiiI - o0oOOo0O0Ooo . oO0o . OOooOOo * i11iIiiIii
 if 70 - 70: OoOoOO00 / OOooOOo - o0oOOo0O0Ooo
 if 82 - 82: OOooOOo . i11iIiiIii . I1ii11iIi11i % OoOoOO00 * Ii1I / OoO0O00
 if 56 - 56: o0oOOo0O0Ooo / I1IiiI + I11i + I1IiiI
 if 34 - 34: Oo0Ooo / i11iIiiIii - ooOoO0o
 i1I1iIi1IiI = source . print_address ( )
 if ( OoOoooooO00oo . alg_id != 0 or OoOoooooO00oo . auth_len != 0 ) :
  ooo0OoOOo = None
  for OOoOoO in lisp_map_servers_list :
   if ( OOoOoO . find ( i1I1iIi1IiI ) == - 1 ) : continue
   ooo0OoOOo = lisp_map_servers_list [ OOoOoO ]
   if 77 - 77: OoOoOO00 * OoooooooOO
  if ( ooo0OoOOo == None ) :
   lprint ( ( "  Could not find Map-Server {} to authenticate " + "Map-Notify" ) . format ( i1I1iIi1IiI ) )
   if 41 - 41: iIii1I11I1II1 - O0 . II111iiii + I1IiiI - II111iiii / oO0o
   return
   if 35 - 35: ooOoO0o - OoOoOO00 / iIii1I11I1II1 / OOooOOo
   if 38 - 38: i1IIi % OoooooooOO
  ooo0OoOOo . map_notifies_received += 1
  if 5 - 5: iIii1I11I1II1 + iIii1I11I1II1 . iIii1I11I1II1 + o0oOOo0O0Ooo
  oOO0ooo0O0oOo = lisp_verify_auth ( I111 , OoOoooooO00oo . alg_id ,
 OoOoooooO00oo . auth_data , ooo0OoOOo . password )
  if 45 - 45: I1IiiI - OoooooooOO - I1Ii111 - i1IIi - OoooooooOO * O0
  lprint ( "  Authentication {} for Map-Notify" . format ( "succeeded" if oOO0ooo0O0oOo else "failed" ) )
  if 67 - 67: OoOoOO00 * o0oOOo0O0Ooo . IiII
  if ( oOO0ooo0O0oOo == False ) : return
 else :
  ooo0OoOOo = lisp_ms ( i1I1iIi1IiI , None , "" , 0 , "" , False , False , False , False , 0 , 0 , 0 ,
 None )
  if 72 - 72: OoOoOO00 % OoooooooOO * O0
  if 27 - 27: I1ii11iIi11i . OoooooooOO / II111iiii . OOooOOo
  if 58 - 58: oO0o / ooOoO0o
  if 31 - 31: o0oOOo0O0Ooo % I11i - OoO0O00
  if 40 - 40: o0oOOo0O0Ooo % OoOoOO00 + I11i / O0 - II111iiii
  if 9 - 9: OoooooooOO - OOooOOo . I11i * oO0o
 oOo0OooOOo = OoOoooooO00oo . eid_records
 if ( OoOoooooO00oo . record_count == 0 ) :
  lisp_send_map_notify_ack ( lisp_sockets , oOo0OooOOo , OoOoooooO00oo , ooo0OoOOo )
  return
  if 3 - 3: iIii1I11I1II1 - OoO0O00
  if 38 - 38: O0 + ooOoO0o * I1Ii111 - oO0o * o0oOOo0O0Ooo
  if 97 - 97: Oo0Ooo - O0 * OoooooooOO
  if 52 - 52: i1IIi + IiII
  if 11 - 11: I1IiiI % iIii1I11I1II1 * Ii1I % ooOoO0o
  if 33 - 33: iII111i / O0 % II111iiii % OoOoOO00 / I1Ii111
  if 77 - 77: OoOoOO00 % I1IiiI % II111iiii * iII111i . OoOoOO00 / O0
  if 21 - 21: ooOoO0o - I11i . i11iIiiIii
 oooOO0o0ooOO = lisp_eid_record ( )
 I111 = oooOO0o0ooOO . decode ( oOo0OooOOo )
 if ( I111 == None ) : return
 if 39 - 39: Oo0Ooo * II111iiii % OOooOOo / oO0o . ooOoO0o
 oooOO0o0ooOO . print_record ( "  " , False )
 if 75 - 75: I11i / O0 + OoooooooOO + OOooOOo % iII111i + I1IiiI
 for oOooO0Oo0Oo0 in range ( oooOO0o0ooOO . rloc_count ) :
  O0OO0 = lisp_rloc_record ( )
  I111 = O0OO0 . decode ( I111 , None )
  if ( I111 == None ) :
   lprint ( "  Could not decode RLOC-record in Map-Notify packet" )
   return
   if 10 - 10: II111iiii * I11i - IiII * iIii1I11I1II1 . OoooooooOO
  O0OO0 . print_record ( "    " )
  if 39 - 39: I11i . I1IiiI % Oo0Ooo + oO0o
  if 76 - 76: I1IiiI * OoooooooOO - i11iIiiIii / I11i / Oo0Ooo
  if 82 - 82: IiII % ooOoO0o
  if 100 - 100: Oo0Ooo . oO0o - iII111i + OoooooooOO
  if 27 - 27: Oo0Ooo . I1Ii111 - i1IIi * I1IiiI
 if ( oooOO0o0ooOO . group . is_null ( ) == False ) :
  if 96 - 96: I1ii11iIi11i - Ii1I . I1ii11iIi11i
  if 89 - 89: II111iiii % I1ii11iIi11i % IiII . I11i
  if 49 - 49: iII111i % i11iIiiIii * I11i - oO0o . OOooOOo . i11iIiiIii
  if 26 - 26: iIii1I11I1II1 + i11iIiiIii % iII111i + I1IiiI + oO0o - ooOoO0o
  if 4 - 4: Oo0Ooo - IiII - I11i
  lprint ( "Send {} Map-Notify IPC message to ITR process" . format ( green ( oooOO0o0ooOO . print_eid_tuple ( ) , False ) ) )
  if 72 - 72: OoooooooOO
  if 19 - 19: Oo0Ooo . OOooOOo
  OooOoO0OO00 = lisp_control_packet_ipc ( orig_packet , i1I1iIi1IiI , "lisp-itr" , 0 )
  lisp_ipc ( OooOoO0OO00 , lisp_sockets [ 2 ] , "lisp-core-pkt" )
  if 58 - 58: IiII % iII111i + i1IIi % I1IiiI % OOooOOo . iII111i
  if 85 - 85: i11iIiiIii . o0oOOo0O0Ooo * iII111i . I1ii11iIi11i / I1Ii111 % Ii1I
  if 27 - 27: II111iiii . iIii1I11I1II1 / I1ii11iIi11i / i1IIi / iIii1I11I1II1
  if 70 - 70: i11iIiiIii . OoO0O00 / OoooooooOO * OoooooooOO - OOooOOo
  if 34 - 34: I1ii11iIi11i * i1IIi % OoooooooOO / I1IiiI
 lisp_send_map_notify_ack ( lisp_sockets , oOo0OooOOo , OoOoooooO00oo , ooo0OoOOo )
 return
 if 39 - 39: OoO0O00 + IiII - II111iiii % I11i
 if 80 - 80: o0oOOo0O0Ooo * ooOoO0o
 if 87 - 87: I1Ii111 + O0 / I1ii11iIi11i / OoOoOO00 . Oo0Ooo - IiII
 if 24 - 24: OoOoOO00
 if 19 - 19: ooOoO0o
 if 43 - 43: O0 . I1Ii111 % OoooooooOO / I1IiiI . o0oOOo0O0Ooo - OoOoOO00
 if 46 - 46: I11i - OoooooooOO % o0oOOo0O0Ooo
 if 7 - 7: OoooooooOO - I1Ii111 * IiII
def lisp_process_map_notify_ack ( packet , source ) :
 OoOoooooO00oo = lisp_map_notify ( "" )
 packet = OoOoooooO00oo . decode ( packet )
 if ( packet == None ) :
  lprint ( "Could not decode Map-Notify-Ack packet" )
  return
  if 20 - 20: o0oOOo0O0Ooo . OoooooooOO * I1IiiI . Oo0Ooo * OoOoOO00
  if 3 - 3: I1Ii111 % i11iIiiIii % O0 % II111iiii
 OoOoooooO00oo . print_notify ( )
 if 8 - 8: OoooooooOO * ooOoO0o
 if 26 - 26: i11iIiiIii + oO0o - i1IIi
 if 71 - 71: I1IiiI % I1Ii111 / oO0o % oO0o / iIii1I11I1II1 + I1Ii111
 if 86 - 86: IiII % i1IIi * o0oOOo0O0Ooo - I1Ii111
 if 37 - 37: iII111i % I1IiiI - I1ii11iIi11i % I11i
 if ( OoOoooooO00oo . record_count < 1 ) :
  lprint ( "No EID-prefix found, cannot authenticate Map-Notify-Ack" )
  return
  if 35 - 35: O0 - OoooooooOO % iII111i
  if 48 - 48: OOooOOo % i11iIiiIii
 oooOO0o0ooOO = lisp_eid_record ( )
 if 49 - 49: O0 * iII111i + II111iiii - OOooOOo
 if ( oooOO0o0ooOO . decode ( OoOoooooO00oo . eid_records ) == None ) :
  lprint ( "Could not decode EID-record, cannot authenticate " +
 "Map-Notify-Ack" )
  return
  if 29 - 29: OoooooooOO % II111iiii - Oo0Ooo / IiII - i11iIiiIii
 oooOO0o0ooOO . print_record ( "  " , False )
 if 64 - 64: iII111i . I1Ii111 + I1Ii111
 oo0ooooO = oooOO0o0ooOO . print_eid_tuple ( )
 if 1 - 1: OOooOOo % Oo0Ooo
 if 81 - 81: oO0o / I11i % Ii1I . I11i + OoooooooOO
 if 31 - 31: OoO0O00
 if 41 - 41: i11iIiiIii - I1ii11iIi11i - II111iiii
 if ( OoOoooooO00oo . alg_id != LISP_NONE_ALG_ID and OoOoooooO00oo . auth_len != 0 ) :
  o0O0o = lisp_sites_by_eid . lookup_cache ( oooOO0o0ooOO . eid , True )
  if ( o0O0o == None ) :
   I1II1i1Ii = bold ( "Site not found" , False )
   lprint ( ( "{} for EID {}, cannot authenticate Map-Notify-Ack" ) . format ( I1II1i1Ii , green ( oo0ooooO , False ) ) )
   if 5 - 5: OoOoOO00 + i1IIi
   return
   if 43 - 43: iII111i * I1IiiI
  Ii1IiI1Ii1 = o0O0o . site
  if 20 - 20: I1IiiI . I11i * OoO0O00 . ooOoO0o . II111iiii
  if 6 - 6: Ii1I * OoOoOO00 % IiII + I11i
  if 20 - 20: oO0o
  if 34 - 34: i1IIi + oO0o * Oo0Ooo * I1Ii111 % OoooooooOO % ooOoO0o
  Ii1IiI1Ii1 . map_notify_acks_received += 1
  if 17 - 17: I1ii11iIi11i + o0oOOo0O0Ooo / OoO0O00 . Oo0Ooo - o0oOOo0O0Ooo / oO0o
  iIIi1 = OoOoooooO00oo . key_id
  if ( Ii1IiI1Ii1 . auth_key . has_key ( iIIi1 ) == False ) : iIIi1 = 0
  o0O0 = Ii1IiI1Ii1 . auth_key [ iIIi1 ]
  if 87 - 87: ooOoO0o
  oOO0ooo0O0oOo = lisp_verify_auth ( packet , OoOoooooO00oo . alg_id ,
 OoOoooooO00oo . auth_data , o0O0 )
  if 74 - 74: i11iIiiIii . i11iIiiIii . iIii1I11I1II1
  iIIi1 = "key-id {}" . format ( iIIi1 ) if iIIi1 == OoOoooooO00oo . key_id else "bad key-id {}" . format ( OoOoooooO00oo . key_id )
  if 100 - 100: i11iIiiIii - oO0o + iIii1I11I1II1 * OoOoOO00 % OOooOOo % i11iIiiIii
  if 26 - 26: O0
  lprint ( "  Authentication {} for Map-Notify-Ack, {}" . format ( "succeeded" if oOO0ooo0O0oOo else "failed" , iIIi1 ) )
  if 97 - 97: OOooOOo + I11i % I1Ii111 % i11iIiiIii / I1ii11iIi11i
  if ( oOO0ooo0O0oOo == False ) : return
  if 21 - 21: O0 + iIii1I11I1II1 / i11iIiiIii . OOooOOo * i1IIi
  if 3 - 3: i1IIi % o0oOOo0O0Ooo + OoOoOO00
  if 32 - 32: OoO0O00 . Oo0Ooo * iIii1I11I1II1
  if 12 - 12: O0 + I1ii11iIi11i + I11i . I1Ii111
  if 48 - 48: Ii1I . iIii1I11I1II1 - iIii1I11I1II1 * I11i . OoooooooOO
 if ( OoOoooooO00oo . retransmit_timer ) : OoOoooooO00oo . retransmit_timer . cancel ( )
 if 73 - 73: Ii1I / II111iiii - iIii1I11I1II1 . ooOoO0o * II111iiii . OOooOOo
 IiiI1iIii = source . print_address ( )
 OOoOoO = OoOoooooO00oo . nonce_key
 if 50 - 50: iIii1I11I1II1 + OoOoOO00 % O0 + OoO0O00 . i11iIiiIii / oO0o
 if ( lisp_map_notify_queue . has_key ( OOoOoO ) ) :
  OoOoooooO00oo = lisp_map_notify_queue . pop ( OOoOoO )
  if ( OoOoooooO00oo . retransmit_timer ) : OoOoooooO00oo . retransmit_timer . cancel ( )
  lprint ( "Dequeue Map-Notify from retransmit queue, key is: {}" . format ( OOoOoO ) )
  if 31 - 31: I1IiiI % o0oOOo0O0Ooo . i11iIiiIii % OOooOOo - iIii1I11I1II1
 else :
  lprint ( "Map-Notify with nonce 0x{} queue entry not found for {}" . format ( OoOoooooO00oo . nonce_key , red ( IiiI1iIii , False ) ) )
  if 77 - 77: i11iIiiIii / OOooOOo
  if 93 - 93: I1ii11iIi11i - iII111i % O0 - Ii1I
 return
 if 84 - 84: I1ii11iIi11i . iIii1I11I1II1 % IiII * I11i + ooOoO0o
 if 59 - 59: oO0o * OoO0O00 - I11i * I1IiiI
 if 60 - 60: iII111i - OoooooooOO / iII111i % OoO0O00 . OoOoOO00 - o0oOOo0O0Ooo
 if 71 - 71: iII111i * o0oOOo0O0Ooo * i11iIiiIii * O0
 if 77 - 77: OOooOOo % iII111i + I11i / OoOoOO00
 if 50 - 50: OoOoOO00 - i11iIiiIii - OOooOOo . iIii1I11I1II1
 if 97 - 97: oO0o % OOooOOo . OoooooooOO * Ii1I
 if 100 - 100: I1ii11iIi11i / Ii1I % Oo0Ooo
def lisp_map_referral_loop ( mr , eid , group , action , s ) :
 if ( action not in ( LISP_DDT_ACTION_NODE_REFERRAL ,
 LISP_DDT_ACTION_MS_REFERRAL ) ) : return ( False )
 if 83 - 83: O0 . I1Ii111 % I1ii11iIi11i
 if ( mr . last_cached_prefix [ 0 ] == None ) : return ( False )
 if 97 - 97: Oo0Ooo % OoO0O00 * I1ii11iIi11i * ooOoO0o * OoO0O00
 if 12 - 12: ooOoO0o
 if 56 - 56: i1IIi
 if 3 - 3: OOooOOo - Oo0Ooo * Ii1I + i11iIiiIii
 i1IIII1IiI = False
 if ( group . is_null ( ) == False ) :
  i1IIII1IiI = mr . last_cached_prefix [ 1 ] . is_more_specific ( group )
  if 53 - 53: i1IIi % I1ii11iIi11i
 if ( i1IIII1IiI == False ) :
  i1IIII1IiI = mr . last_cached_prefix [ 0 ] . is_more_specific ( eid )
  if 65 - 65: I11i + OoOoOO00 - i11iIiiIii
  if 72 - 72: i11iIiiIii - iII111i . i11iIiiIii
 if ( i1IIII1IiI ) :
  o00oo = lisp_print_eid_tuple ( eid , group )
  OOi11I1IIi1I = lisp_print_eid_tuple ( mr . last_cached_prefix [ 0 ] ,
 mr . last_cached_prefix [ 1 ] )
  if 75 - 75: II111iiii * Oo0Ooo + OOooOOo + Ii1I - I1ii11iIi11i
  lprint ( ( "Map-Referral prefix {} from {} is not more-specific " + "than cached prefix {}" ) . format ( green ( o00oo , False ) , s ,
  # O0 + oO0o . IiII . IiII / OoOoOO00 / II111iiii
 OOi11I1IIi1I ) )
  if 2 - 2: I1Ii111
 return ( i1IIII1IiI )
 if 45 - 45: OOooOOo * ooOoO0o
 if 77 - 77: i11iIiiIii / OOooOOo % i11iIiiIii
 if 19 - 19: OoooooooOO - I1IiiI * OoO0O00
 if 65 - 65: OoooooooOO . I11i / I1ii11iIi11i / i11iIiiIii
 if 20 - 20: OoOoOO00 / OoO0O00 - Oo0Ooo + ooOoO0o
 if 86 - 86: O0 / II111iiii / ooOoO0o % I1ii11iIi11i / iIii1I11I1II1
 if 1 - 1: O0
def lisp_process_map_referral ( lisp_sockets , packet , source ) :
 if 55 - 55: i1IIi % IiII - i1IIi . IiII . o0oOOo0O0Ooo
 Oo00o0oO0O0o = lisp_map_referral ( )
 packet = Oo00o0oO0O0o . decode ( packet )
 if ( packet == None ) :
  lprint ( "Could not decode Map-Referral packet" )
  return
  if 85 - 85: Ii1I . i11iIiiIii
 Oo00o0oO0O0o . print_map_referral ( )
 if 69 - 69: OoOoOO00
 i1I1iIi1IiI = source . print_address ( )
 oO00o0oOoo = Oo00o0oO0O0o . nonce
 if 49 - 49: Oo0Ooo % Oo0Ooo * OoOoOO00 - Oo0Ooo
 if 32 - 32: i1IIi . I11i - IiII % OoO0O00 % iIii1I11I1II1 - OoooooooOO
 if 47 - 47: OoO0O00 + II111iiii . IiII - I11i . iII111i . o0oOOo0O0Ooo
 if 31 - 31: I1IiiI + O0 . I1IiiI - iII111i - I1Ii111
 for oO in range ( Oo00o0oO0O0o . record_count ) :
  oooOO0o0ooOO = lisp_eid_record ( )
  packet = oooOO0o0ooOO . decode ( packet )
  if ( packet == None ) :
   lprint ( "Could not decode EID-record in Map-Referral packet" )
   return
   if 88 - 88: iII111i * OoO0O00 % OoooooooOO / oO0o
  oooOO0o0ooOO . print_record ( "  " , True )
  if 7 - 7: i1IIi
  if 30 - 30: oO0o . i1IIi / I11i
  if 23 - 23: i1IIi + oO0o % iII111i - OoO0O00 - i1IIi
  if 74 - 74: Ii1I + I11i . OoooooooOO - I1ii11iIi11i
  OOoOoO = str ( oO00o0oOoo )
  if ( OOoOoO not in lisp_ddt_map_requestQ ) :
   lprint ( ( "Map-Referral nonce 0x{} from {} not found in " + "Map-Request queue, EID-record ignored" ) . format ( lisp_hex_string ( oO00o0oOoo ) , i1I1iIi1IiI ) )
   if 2 - 2: oO0o - o0oOOo0O0Ooo
   if 80 - 80: i1IIi
   continue
   if 40 - 40: O0 . ooOoO0o * iII111i . I11i + I1Ii111 % OoO0O00
  iiOoOoOoo0 = lisp_ddt_map_requestQ [ OOoOoO ]
  if ( iiOoOoOoo0 == None ) :
   lprint ( ( "No Map-Request queue entry found for Map-Referral " +
 "nonce 0x{} from {}, EID-record ignored" ) . format ( lisp_hex_string ( oO00o0oOoo ) , i1I1iIi1IiI ) )
   if 9 - 9: IiII * oO0o - o0oOOo0O0Ooo
   continue
   if 17 - 17: iII111i % Oo0Ooo
   if 14 - 14: I1IiiI - I1Ii111 % I1IiiI - II111iiii
   if 34 - 34: I1ii11iIi11i * IiII / II111iiii / ooOoO0o * oO0o
   if 3 - 3: II111iiii
   if 61 - 61: oO0o . I1IiiI + i1IIi
   if 69 - 69: O0 / i1IIi - OoOoOO00 + ooOoO0o - oO0o
  if ( lisp_map_referral_loop ( iiOoOoOoo0 , oooOO0o0ooOO . eid , oooOO0o0ooOO . group ,
 oooOO0o0ooOO . action , i1I1iIi1IiI ) ) :
   iiOoOoOoo0 . dequeue_map_request ( )
   continue
   if 80 - 80: o0oOOo0O0Ooo % O0 * I11i . i1IIi - ooOoO0o
   if 93 - 93: OoooooooOO / o0oOOo0O0Ooo
  iiOoOoOoo0 . last_cached_prefix [ 0 ] = oooOO0o0ooOO . eid
  iiOoOoOoo0 . last_cached_prefix [ 1 ] = oooOO0o0ooOO . group
  if 61 - 61: II111iiii / i1IIi . I1ii11iIi11i % iIii1I11I1II1
  if 66 - 66: iIii1I11I1II1 % OoOoOO00 + i1IIi * i11iIiiIii * OoooooooOO
  if 36 - 36: iII111i - OoO0O00 + I1IiiI + Ii1I . OoooooooOO
  if 75 - 75: oO0o * Oo0Ooo * O0
  iI1i1I1iiiiI1 = False
  i1iI11i = lisp_referral_cache_lookup ( oooOO0o0ooOO . eid , oooOO0o0ooOO . group ,
 True )
  if ( i1iI11i == None ) :
   iI1i1I1iiiiI1 = True
   i1iI11i = lisp_referral ( )
   i1iI11i . eid = oooOO0o0ooOO . eid
   i1iI11i . group = oooOO0o0ooOO . group
   if ( oooOO0o0ooOO . ddt_incomplete == False ) : i1iI11i . add_cache ( )
  elif ( i1iI11i . referral_source . not_set ( ) ) :
   lprint ( "Do not replace static referral entry {}" . format ( green ( i1iI11i . print_eid_tuple ( ) , False ) ) )
   if 22 - 22: ooOoO0o / OoooooooOO . II111iiii / Ii1I * OoO0O00 . i1IIi
   iiOoOoOoo0 . dequeue_map_request ( )
   continue
   if 62 - 62: oO0o % Ii1I - Ii1I
   if 16 - 16: OoO0O00 - O0 - OOooOOo - I11i % OoOoOO00
  i1ii1iIIIiI1 = oooOO0o0ooOO . action
  i1iI11i . referral_source = source
  i1iI11i . referral_type = i1ii1iIIIiI1
  I1i11iiIiIi = oooOO0o0ooOO . store_ttl ( )
  i1iI11i . referral_ttl = I1i11iiIiIi
  i1iI11i . expires = lisp_set_timestamp ( I1i11iiIiIi )
  if 7 - 7: I1Ii111 / OoOoOO00 . II111iiii
  if 9 - 9: I11i . I11i . OoooooooOO
  if 42 - 42: iII111i / oO0o / iII111i * OoO0O00
  if 25 - 25: OoOoOO00 - II111iiii + II111iiii . Ii1I * II111iiii
  i11I1 = i1iI11i . is_referral_negative ( )
  if ( i1iI11i . referral_set . has_key ( i1I1iIi1IiI ) ) :
   i1I = i1iI11i . referral_set [ i1I1iIi1IiI ]
   if 42 - 42: Ii1I % OoooooooOO * i1IIi
   if ( i1I . updown == False and i11I1 == False ) :
    i1I . updown = True
    lprint ( "Change up/down status for referral-node {} to up" . format ( i1I1iIi1IiI ) )
    if 67 - 67: OoOoOO00 + I1IiiI % iII111i
   elif ( i1I . updown == True and i11I1 == True ) :
    i1I . updown = False
    lprint ( ( "Change up/down status for referral-node {} " + "to down, received negative referral" ) . format ( i1I1iIi1IiI ) )
    if 2 - 2: ooOoO0o - ooOoO0o % OoO0O00 / I1IiiI - Oo0Ooo
    if 30 - 30: i11iIiiIii / OoO0O00 - IiII / Oo0Ooo + I11i - i1IIi
    if 67 - 67: i11iIiiIii * I11i * Ii1I + OoooooooOO * OoO0O00
    if 28 - 28: I1Ii111 - iIii1I11I1II1
    if 88 - 88: Oo0Ooo * i1IIi % OOooOOo
    if 65 - 65: iII111i . oO0o
    if 67 - 67: I1IiiI / iII111i / O0 % ooOoO0o - IiII / Ii1I
    if 31 - 31: I11i - oO0o * ooOoO0o
  oO000ooOOo = { }
  for OOoOoO in i1iI11i . referral_set : oO000ooOOo [ OOoOoO ] = None
  if 45 - 45: I1Ii111 + IiII . iIii1I11I1II1
  if 89 - 89: I11i
  if 22 - 22: i1IIi * OoOoOO00 - i11iIiiIii . i1IIi - OOooOOo . iIii1I11I1II1
  if 43 - 43: OoO0O00 % OOooOOo / I11i + I1ii11iIi11i - OoOoOO00 % I1Ii111
  for oO in range ( oooOO0o0ooOO . rloc_count ) :
   O0OO0 = lisp_rloc_record ( )
   packet = O0OO0 . decode ( packet , None )
   if ( packet == None ) :
    lprint ( "Could not decode RLOC-record in Map-Referral packet" )
    return
    if 18 - 18: OoooooooOO - ooOoO0o + iIii1I11I1II1 - OOooOOo + IiII
   O0OO0 . print_record ( "    " )
   if 56 - 56: OoOoOO00 * OoO0O00 + oO0o
   if 52 - 52: iIii1I11I1II1 + Oo0Ooo + ooOoO0o / ooOoO0o
   if 60 - 60: ooOoO0o
   if 79 - 79: i1IIi % OoO0O00
   I11i11I = O0OO0 . rloc . print_address ( )
   if ( i1iI11i . referral_set . has_key ( I11i11I ) == False ) :
    i1I = lisp_referral_node ( )
    i1I . referral_address . copy_address ( O0OO0 . rloc )
    i1iI11i . referral_set [ I11i11I ] = i1I
    if ( i1I1iIi1IiI == I11i11I and i11I1 ) : i1I . updown = False
   else :
    i1I = i1iI11i . referral_set [ I11i11I ]
    if ( oO000ooOOo . has_key ( I11i11I ) ) : oO000ooOOo . pop ( I11i11I )
    if 26 - 26: OoOoOO00 * IiII
   i1I . priority = O0OO0 . priority
   i1I . weight = O0OO0 . weight
   if 76 - 76: I1IiiI + IiII * I1ii11iIi11i * I1IiiI % Ii1I + ooOoO0o
   if 46 - 46: OoOoOO00
   if 66 - 66: iII111i - O0 . I1Ii111 * i1IIi / OoO0O00 / II111iiii
   if 35 - 35: ooOoO0o * OOooOOo / I11i % I11i / OoooooooOO . I1Ii111
   if 70 - 70: I1ii11iIi11i % I1ii11iIi11i / oO0o
  for OOoOoO in oO000ooOOo : i1iI11i . referral_set . pop ( OOoOoO )
  if 85 - 85: OoOoOO00 % I11i / Oo0Ooo + I11i - Oo0Ooo
  oo0ooooO = i1iI11i . print_eid_tuple ( )
  if 20 - 20: IiII
  if ( iI1i1I1iiiiI1 ) :
   if ( oooOO0o0ooOO . ddt_incomplete ) :
    lprint ( "Suppress add {} to referral-cache" . format ( green ( oo0ooooO , False ) ) )
    if 81 - 81: Oo0Ooo / I1Ii111
   else :
    lprint ( "Add {}, referral-count {} to referral-cache" . format ( green ( oo0ooooO , False ) , oooOO0o0ooOO . rloc_count ) )
    if 20 - 20: o0oOOo0O0Ooo + ooOoO0o % i1IIi
    if 51 - 51: iII111i - ooOoO0o
  else :
   lprint ( "Replace {}, referral-count: {} in referral-cache" . format ( green ( oo0ooooO , False ) , oooOO0o0ooOO . rloc_count ) )
   if 32 - 32: IiII - i11iIiiIii
   if 41 - 41: Ii1I % Ii1I * oO0o - I11i + iIii1I11I1II1 . ooOoO0o
   if 30 - 30: Ii1I * iII111i . II111iiii / i1IIi
   if 77 - 77: oO0o . IiII + I1ii11iIi11i . i1IIi
   if 49 - 49: I1Ii111 . OoooooooOO / o0oOOo0O0Ooo - iII111i - iII111i - i11iIiiIii
   if 37 - 37: OOooOOo
  if ( i1ii1iIIIiI1 == LISP_DDT_ACTION_DELEGATION_HOLE ) :
   lisp_send_negative_map_reply ( iiOoOoOoo0 . lisp_sockets , i1iI11i . eid ,
 i1iI11i . group , iiOoOoOoo0 . nonce , iiOoOoOoo0 . itr , iiOoOoOoo0 . sport , 15 , None , False )
   iiOoOoOoo0 . dequeue_map_request ( )
   if 79 - 79: I1Ii111 - OoO0O00 + ooOoO0o + oO0o . i11iIiiIii + i1IIi
   if 32 - 32: IiII . ooOoO0o / OoO0O00 / iII111i . iIii1I11I1II1 % IiII
  if ( i1ii1iIIIiI1 == LISP_DDT_ACTION_NOT_AUTH ) :
   if ( iiOoOoOoo0 . tried_root ) :
    lisp_send_negative_map_reply ( iiOoOoOoo0 . lisp_sockets , i1iI11i . eid ,
 i1iI11i . group , iiOoOoOoo0 . nonce , iiOoOoOoo0 . itr , iiOoOoOoo0 . sport , 0 , None , False )
    iiOoOoOoo0 . dequeue_map_request ( )
   else :
    lisp_send_ddt_map_request ( iiOoOoOoo0 , True )
    if 28 - 28: I1Ii111 + OoooooooOO + IiII . ooOoO0o . I1IiiI / oO0o
    if 66 - 66: Ii1I - I11i + Oo0Ooo . ooOoO0o
    if 89 - 89: IiII . II111iiii / OoO0O00 + I1ii11iIi11i * i11iIiiIii
  if ( i1ii1iIIIiI1 == LISP_DDT_ACTION_MS_NOT_REG ) :
   if ( i1iI11i . referral_set . has_key ( i1I1iIi1IiI ) ) :
    i1I = i1iI11i . referral_set [ i1I1iIi1IiI ]
    i1I . updown = False
    if 85 - 85: o0oOOo0O0Ooo - Oo0Ooo / I1Ii111
   if ( len ( i1iI11i . referral_set ) == 0 ) :
    iiOoOoOoo0 . dequeue_map_request ( )
   else :
    lisp_send_ddt_map_request ( iiOoOoOoo0 , False )
    if 100 - 100: OoO0O00 * iIii1I11I1II1 - IiII . i1IIi % i11iIiiIii % Oo0Ooo
    if 22 - 22: ooOoO0o - OOooOOo
    if 90 - 90: i11iIiiIii . i11iIiiIii - iIii1I11I1II1
  if ( i1ii1iIIIiI1 in ( LISP_DDT_ACTION_NODE_REFERRAL ,
 LISP_DDT_ACTION_MS_REFERRAL ) ) :
   if ( iiOoOoOoo0 . eid . is_exact_match ( oooOO0o0ooOO . eid ) ) :
    if ( not iiOoOoOoo0 . tried_root ) :
     lisp_send_ddt_map_request ( iiOoOoOoo0 , True )
    else :
     lisp_send_negative_map_reply ( iiOoOoOoo0 . lisp_sockets ,
 i1iI11i . eid , i1iI11i . group , iiOoOoOoo0 . nonce , iiOoOoOoo0 . itr ,
 iiOoOoOoo0 . sport , 15 , None , False )
     iiOoOoOoo0 . dequeue_map_request ( )
     if 20 - 20: ooOoO0o - i11iIiiIii
   else :
    lisp_send_ddt_map_request ( iiOoOoOoo0 , False )
    if 23 - 23: OoO0O00 + I1IiiI / I1ii11iIi11i * I1ii11iIi11i % ooOoO0o
    if 83 - 83: I1IiiI * i11iIiiIii - I1ii11iIi11i + I11i
    if 33 - 33: OoO0O00 . OoooooooOO % iII111i / oO0o * Ii1I + ooOoO0o
  if ( i1ii1iIIIiI1 == LISP_DDT_ACTION_MS_ACK ) : iiOoOoOoo0 . dequeue_map_request ( )
  if 29 - 29: oO0o
 return
 if 21 - 21: i11iIiiIii . o0oOOo0O0Ooo
 if 78 - 78: Oo0Ooo
 if 77 - 77: oO0o % Oo0Ooo % O0
 if 51 - 51: IiII % IiII + OOooOOo . II111iiii / I1ii11iIi11i
 if 4 - 4: o0oOOo0O0Ooo % I1IiiI * o0oOOo0O0Ooo * OoOoOO00 - Ii1I
 if 61 - 61: OoooooooOO - OoOoOO00 . O0 / ooOoO0o . Ii1I
 if 41 - 41: Oo0Ooo / OoOoOO00 % I1Ii111 - O0
 if 19 - 19: I1IiiI % I1Ii111 - O0 . iIii1I11I1II1 . I11i % O0
def lisp_process_ecm ( lisp_sockets , packet , source , ecm_port ) :
 Oo0OO = lisp_ecm ( 0 )
 packet = Oo0OO . decode ( packet )
 if ( packet == None ) :
  lprint ( "Could not decode ECM packet" )
  return
  if 88 - 88: ooOoO0o
  if 52 - 52: iIii1I11I1II1 % ooOoO0o * iIii1I11I1II1
 Oo0OO . print_ecm ( )
 if 20 - 20: i11iIiiIii * I11i
 ooo0Oo00O = lisp_control_header ( )
 if ( ooo0Oo00O . decode ( packet ) == None ) :
  lprint ( "Could not decode control header" )
  return
  if 29 - 29: IiII / OOooOOo
  if 39 - 39: O0 + II111iiii
 O00OOo0OOo = ooo0Oo00O . type
 del ( ooo0Oo00O )
 if 15 - 15: OoO0O00 + iIii1I11I1II1
 if ( O00OOo0OOo != LISP_MAP_REQUEST ) :
  lprint ( "Received ECM without Map-Request inside" )
  return
  if 89 - 89: OoooooooOO * Ii1I
  if 4 - 4: Ii1I + OoO0O00 * O0
  if 13 - 13: I11i + O0 / oO0o % O0 . I11i
  if 22 - 22: OoOoOO00 . I1IiiI % ooOoO0o + I1Ii111 - OoooooooOO
  if 55 - 55: OoooooooOO * O0 - II111iiii / IiII
 IiIi1I111i = Oo0OO . udp_sport
 lisp_process_map_request ( lisp_sockets , packet , source , ecm_port ,
 Oo0OO . source , IiIi1I111i , Oo0OO . ddt , - 1 )
 return
 if 74 - 74: I1Ii111 - II111iiii % o0oOOo0O0Ooo
 if 7 - 7: I1IiiI + OoooooooOO + o0oOOo0O0Ooo . OoooooooOO
 if 29 - 29: iII111i * O0 + I1IiiI * IiII + iII111i - IiII
 if 38 - 38: I1ii11iIi11i - Ii1I % OoooooooOO
 if 43 - 43: iIii1I11I1II1 / OoOoOO00
 if 13 - 13: o0oOOo0O0Ooo / I1Ii111
 if 67 - 67: OoooooooOO . oO0o * OoOoOO00 - OoooooooOO
 if 32 - 32: oO0o
 if 72 - 72: I1IiiI
 if 34 - 34: ooOoO0o % II111iiii / ooOoO0o
def lisp_send_map_register ( lisp_sockets , packet , map_register , ms ) :
 if 87 - 87: Oo0Ooo
 if 7 - 7: iIii1I11I1II1
 if 85 - 85: iIii1I11I1II1 . O0
 if 43 - 43: II111iiii / OoOoOO00 + OOooOOo % Oo0Ooo * OOooOOo
 if 62 - 62: ooOoO0o * OOooOOo . I11i + Oo0Ooo - I1Ii111
 if 48 - 48: I1Ii111 * Oo0Ooo % OoO0O00 % Ii1I
 if 8 - 8: OoO0O00 . OoO0O00
 IiI1 = ms . map_server
 if ( lisp_decent_push_configured and IiI1 . is_multicast_address ( ) and
 ( ms . map_registers_multicast_sent == 1 or ms . map_registers_sent == 1 ) ) :
  IiI1 = copy . deepcopy ( IiI1 )
  IiI1 . address = 0x7f000001
  iI = bold ( "Bootstrap" , False )
  O0000O = ms . map_server . print_address_no_iid ( )
  lprint ( "{} mapping system for peer-group {}" . format ( iI , O0000O ) )
  if 29 - 29: I11i + OoooooooOO % o0oOOo0O0Ooo - I1Ii111
  if 45 - 45: II111iiii - OOooOOo / oO0o % O0 . iII111i . iII111i
  if 82 - 82: iIii1I11I1II1 % Oo0Ooo * i1IIi - I1Ii111 - I1ii11iIi11i / iII111i
  if 24 - 24: IiII
  if 95 - 95: IiII + OoOoOO00 * OOooOOo
  if 92 - 92: OoOoOO00 + ooOoO0o . iII111i
 packet = lisp_compute_auth ( packet , map_register , ms . password )
 if 59 - 59: iIii1I11I1II1 % I1Ii111 + I1ii11iIi11i . OoOoOO00 * Oo0Ooo / I1Ii111
 if 41 - 41: i1IIi / IiII
 if 73 - 73: o0oOOo0O0Ooo % ooOoO0o
 if 72 - 72: OoO0O00 * OoOoOO00 % I1IiiI - OOooOOo . Oo0Ooo
 if 70 - 70: ooOoO0o . o0oOOo0O0Ooo * II111iiii - O0
 if ( ms . ekey != None ) :
  o0III = ms . ekey . zfill ( 32 )
  OOOooO00OO00O = "0" * 8
  IiiI1I = chacha . ChaCha ( o0III , OOOooO00OO00O ) . encrypt ( packet [ 4 : : ] )
  packet = packet [ 0 : 4 ] + IiiI1I
  I1i11II = bold ( "Encrypt" , False )
  lprint ( "{} Map-Register with key-id {}" . format ( I1i11II , ms . ekey_id ) )
  if 74 - 74: oO0o % I1IiiI / oO0o / Oo0Ooo / ooOoO0o
  if 29 - 29: ooOoO0o + iIii1I11I1II1 + OoO0O00 - o0oOOo0O0Ooo
 OoOoO00Oo = ""
 if ( lisp_decent_pull_xtr_configured ( ) ) :
  OoOoO00Oo = ", decent-index {}" . format ( bold ( ms . dns_name , False ) )
  if 90 - 90: oO0o / o0oOOo0O0Ooo . o0oOOo0O0Ooo % OoOoOO00 / IiII
  if 13 - 13: oO0o + IiII
 lprint ( "Send Map-Register to map-server {}{}{}" . format ( IiI1 . print_address ( ) , ", ms-name '{}'" . format ( ms . ms_name ) , OoOoO00Oo ) )
 if 36 - 36: oO0o - OoOoOO00 . O0 % IiII
 lisp_send ( lisp_sockets , IiI1 , LISP_CTRL_PORT , packet )
 return
 if 65 - 65: Oo0Ooo - i11iIiiIii * OoOoOO00 . I1Ii111 . iIii1I11I1II1
 if 48 - 48: iIii1I11I1II1 - oO0o / OoO0O00 + O0 . Ii1I + I1Ii111
 if 17 - 17: OoOoOO00 . Oo0Ooo - I1Ii111 / I1Ii111 + I11i % i1IIi
 if 31 - 31: OoooooooOO . O0 / OoO0O00 . I1Ii111
 if 41 - 41: OoooooooOO + iII111i . OOooOOo
 if 73 - 73: oO0o + i1IIi + i11iIiiIii / I1ii11iIi11i
 if 100 - 100: I1IiiI % ooOoO0o % OoooooooOO / i11iIiiIii + i11iIiiIii % IiII
 if 39 - 39: Ii1I % o0oOOo0O0Ooo + OOooOOo / iIii1I11I1II1
def lisp_send_ipc_to_core ( lisp_socket , packet , dest , port ) :
 oo0O00 = lisp_socket . getsockname ( )
 dest = dest . print_address_no_iid ( )
 if 40 - 40: iIii1I11I1II1 / iII111i % OOooOOo % i11iIiiIii
 lprint ( "Send IPC {} bytes to {} {}, control-packet: {}" . format ( len ( packet ) , dest , port , lisp_format_packet ( packet ) ) )
 if 57 - 57: II111iiii % OoO0O00 * i1IIi
 if 19 - 19: ooOoO0o . iIii1I11I1II1 + I1ii11iIi11i + I1ii11iIi11i / o0oOOo0O0Ooo . Oo0Ooo
 packet = lisp_control_packet_ipc ( packet , oo0O00 , dest , port )
 lisp_ipc ( packet , lisp_socket , "lisp-core-pkt" )
 return
 if 9 - 9: II111iiii % OoooooooOO
 if 4 - 4: i1IIi * i11iIiiIii % OoooooooOO + OoOoOO00 . oO0o
 if 95 - 95: I1ii11iIi11i * OoOoOO00 % o0oOOo0O0Ooo / O0 + ooOoO0o % OOooOOo
 if 48 - 48: i1IIi + IiII - iIii1I11I1II1 . i11iIiiIii % OOooOOo + I1ii11iIi11i
 if 95 - 95: ooOoO0o + OoOoOO00 . II111iiii + Ii1I
 if 81 - 81: OoooooooOO / OOooOOo / Oo0Ooo
 if 26 - 26: iII111i
 if 93 - 93: Oo0Ooo + I1IiiI % OoOoOO00 / OOooOOo / I1ii11iIi11i
def lisp_send_map_reply ( lisp_sockets , packet , dest , port ) :
 lprint ( "Send Map-Reply to {}" . format ( dest . print_address_no_iid ( ) ) )
 lisp_send_ipc_to_core ( lisp_sockets [ 2 ] , packet , dest , port )
 return
 if 6 - 6: IiII
 if 68 - 68: Oo0Ooo
 if 83 - 83: OOooOOo / iIii1I11I1II1 . OoO0O00 - oO0o % Oo0Ooo
 if 30 - 30: Ii1I . OoOoOO00 / oO0o . OoO0O00
 if 93 - 93: i11iIiiIii
 if 33 - 33: i1IIi % OoooooooOO + Oo0Ooo % I1IiiI / ooOoO0o
 if 40 - 40: IiII % IiII
 if 9 - 9: I1IiiI * i1IIi + OOooOOo * OoOoOO00
def lisp_send_map_referral ( lisp_sockets , packet , dest , port ) :
 lprint ( "Send Map-Referral to {}" . format ( dest . print_address ( ) ) )
 lisp_send_ipc_to_core ( lisp_sockets [ 2 ] , packet , dest , port )
 return
 if 8 - 8: iII111i
 if 51 - 51: I1IiiI
 if 72 - 72: ooOoO0o / I1ii11iIi11i . Ii1I * iII111i . iIii1I11I1II1
 if 35 - 35: OoO0O00 . OoOoOO00 % O0 * OoO0O00
 if 68 - 68: OOooOOo
 if 87 - 87: IiII * IiII - OoO0O00 / I1ii11iIi11i + OOooOOo / i11iIiiIii
 if 21 - 21: o0oOOo0O0Ooo / oO0o + oO0o + Oo0Ooo / o0oOOo0O0Ooo
 if 39 - 39: i11iIiiIii - OoO0O00 - i11iIiiIii / OoooooooOO
def lisp_send_map_notify ( lisp_sockets , packet , dest , port ) :
 lprint ( "Send Map-Notify to xTR {}" . format ( dest . print_address ( ) ) )
 lisp_send_ipc_to_core ( lisp_sockets [ 2 ] , packet , dest , port )
 return
 if 15 - 15: i1IIi . iII111i + IiII / I1ii11iIi11i - i1IIi / iII111i
 if 27 - 27: OoOoOO00 / OoooooooOO + i1IIi % iIii1I11I1II1 / OoO0O00
 if 73 - 73: I1ii11iIi11i / OoOoOO00 / IiII + oO0o
 if 73 - 73: I11i * o0oOOo0O0Ooo * I1IiiI . OoooooooOO % I1Ii111
 if 9 - 9: oO0o % I1Ii111 . O0 + I1ii11iIi11i - Ii1I - I1ii11iIi11i
 if 57 - 57: i11iIiiIii
 if 21 - 21: iIii1I11I1II1 / I1IiiI / iII111i
def lisp_send_ecm ( lisp_sockets , packet , inner_source , inner_sport , inner_dest ,
 outer_dest , to_etr = False , to_ms = False , ddt = False ) :
 if 19 - 19: Oo0Ooo / iIii1I11I1II1 / I11i
 if ( inner_source == None or inner_source . is_null ( ) ) :
  inner_source = inner_dest
  if 71 - 71: iIii1I11I1II1 * I1IiiI
  if 35 - 35: O0
  if 10 - 10: Ii1I - I1Ii111 / Oo0Ooo + O0
  if 67 - 67: Ii1I % i11iIiiIii . Oo0Ooo
  if 78 - 78: I1IiiI - iIii1I11I1II1
  if 20 - 20: i11iIiiIii % I1IiiI % OoOoOO00
 if ( lisp_nat_traversal ) :
  iiII = lisp_get_any_translated_port ( )
  if ( iiII != None ) : inner_sport = iiII
  if 85 - 85: I11i + OoOoOO00 * O0 * O0
 Oo0OO = lisp_ecm ( inner_sport )
 if 92 - 92: i11iIiiIii
 Oo0OO . to_etr = to_etr if lisp_is_running ( "lisp-etr" ) else False
 Oo0OO . to_ms = to_ms if lisp_is_running ( "lisp-ms" ) else False
 Oo0OO . ddt = ddt
 I1IooOoOO = Oo0OO . encode ( packet , inner_source , inner_dest )
 if ( I1IooOoOO == None ) :
  lprint ( "Could not encode ECM message" )
  return
  if 51 - 51: ooOoO0o % I11i + IiII + oO0o + O0 % ooOoO0o
 Oo0OO . print_ecm ( )
 if 38 - 38: OoO0O00 - iIii1I11I1II1 % ooOoO0o + I1ii11iIi11i - Ii1I
 packet = I1IooOoOO + packet
 if 69 - 69: OOooOOo / OoooooooOO % ooOoO0o % iIii1I11I1II1 / OoO0O00 + iIii1I11I1II1
 I11i11I = outer_dest . print_address_no_iid ( )
 lprint ( "Send Encapsulated-Control-Message to {}" . format ( I11i11I ) )
 IiI1 = lisp_convert_4to6 ( I11i11I )
 lisp_send ( lisp_sockets , IiI1 , LISP_CTRL_PORT , packet )
 return
 if 47 - 47: II111iiii % O0 / I1IiiI / iIii1I11I1II1 * I11i
 if 60 - 60: O0 * iII111i % I1ii11iIi11i
 if 92 - 92: OoOoOO00 / iIii1I11I1II1
 if 67 - 67: i1IIi + i11iIiiIii - i1IIi % OoOoOO00
 if 3 - 3: I1IiiI % ooOoO0o
 if 32 - 32: OOooOOo / i1IIi / OOooOOo
 if 97 - 97: ooOoO0o * Oo0Ooo * OoooooooOO * I1IiiI
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
if 45 - 45: Oo0Ooo
LISP_RLOC_UNKNOWN_STATE = 0
LISP_RLOC_UP_STATE = 1
LISP_RLOC_DOWN_STATE = 2
LISP_RLOC_UNREACH_STATE = 3
LISP_RLOC_NO_ECHOED_NONCE_STATE = 4
LISP_RLOC_ADMIN_DOWN_STATE = 5
if 27 - 27: oO0o / IiII - iIii1I11I1II1 / o0oOOo0O0Ooo % OOooOOo * iIii1I11I1II1
LISP_AUTH_NONE = 0
LISP_AUTH_MD5 = 1
LISP_AUTH_SHA1 = 2
LISP_AUTH_SHA2 = 3
if 40 - 40: oO0o - II111iiii * OOooOOo % OoooooooOO
if 52 - 52: OOooOOo + OoO0O00
if 96 - 96: OOooOOo % O0 - Oo0Ooo % oO0o / I1IiiI . i1IIi
if 42 - 42: i1IIi
if 52 - 52: OoO0O00 % iII111i % O0
if 11 - 11: i1IIi / i11iIiiIii + Ii1I % Oo0Ooo % O0
if 50 - 50: oO0o . I1Ii111
LISP_IPV4_HOST_MASK_LEN = 32
LISP_IPV6_HOST_MASK_LEN = 128
LISP_MAC_HOST_MASK_LEN = 48
LISP_E164_HOST_MASK_LEN = 60
if 38 - 38: iIii1I11I1II1 . Ii1I
if 82 - 82: OOooOOo * Ii1I + I1ii11iIi11i . OoO0O00
if 15 - 15: O0
if 44 - 44: Ii1I . Oo0Ooo . I1Ii111 + oO0o
if 32 - 32: OOooOOo - II111iiii + IiII * iIii1I11I1II1 - Oo0Ooo
if 25 - 25: ooOoO0o
def byte_swap_64 ( address ) :
 I1Iii1I = ( ( address & 0x00000000000000ff ) << 56 ) | ( ( address & 0x000000000000ff00 ) << 40 ) | ( ( address & 0x0000000000ff0000 ) << 24 ) | ( ( address & 0x00000000ff000000 ) << 8 ) | ( ( address & 0x000000ff00000000 ) >> 8 ) | ( ( address & 0x0000ff0000000000 ) >> 24 ) | ( ( address & 0x00ff000000000000 ) >> 40 ) | ( ( address & 0xff00000000000000 ) >> 56 )
 if 33 - 33: Oo0Ooo
 if 11 - 11: I11i
 if 55 - 55: i11iIiiIii * OoOoOO00 - OoOoOO00 * OoO0O00 / iII111i
 if 64 - 64: iIii1I11I1II1 . Ii1I * Oo0Ooo - OoO0O00
 if 74 - 74: I1IiiI / o0oOOo0O0Ooo
 if 53 - 53: iIii1I11I1II1 * oO0o
 if 43 - 43: IiII * Oo0Ooo / OOooOOo % oO0o
 if 11 - 11: OoOoOO00 * Oo0Ooo / I11i * OOooOOo
 return ( I1Iii1I )
 if 15 - 15: ooOoO0o - OOooOOo / OoooooooOO
 if 41 - 41: OoOoOO00 . iII111i . i1IIi + oO0o
 if 60 - 60: oO0o * I1Ii111
 if 81 - 81: oO0o - OOooOOo - oO0o
 if 54 - 54: oO0o % I11i
 if 71 - 71: oO0o / I1ii11iIi11i . Ii1I % II111iiii
 if 22 - 22: iIii1I11I1II1 - OoooooooOO
 if 8 - 8: ooOoO0o % i11iIiiIii
 if 41 - 41: I1Ii111 . ooOoO0o - i11iIiiIii + Ii1I . OOooOOo . OoOoOO00
 if 70 - 70: i1IIi % OoOoOO00 / iII111i + i11iIiiIii % ooOoO0o + IiII
 if 58 - 58: OOooOOo / i11iIiiIii . Oo0Ooo % iII111i
 if 92 - 92: OoOoOO00 / ooOoO0o % iII111i / iIii1I11I1II1
 if 73 - 73: O0 % i11iIiiIii
 if 16 - 16: O0
 if 15 - 15: i1IIi % i11iIiiIii
class lisp_cache_entries ( ) :
 def __init__ ( self ) :
  self . entries = { }
  self . entries_sorted = [ ]
  if 18 - 18: Ii1I . OoO0O00 . iII111i * oO0o + O0
  if 35 - 35: OoOoOO00 . oO0o / II111iiii
  if 97 - 97: Ii1I + I1Ii111 / II111iiii
class lisp_cache ( ) :
 def __init__ ( self ) :
  self . cache = { }
  self . cache_sorted = [ ]
  self . cache_count = 0
  if 14 - 14: iII111i / IiII / oO0o
  if 55 - 55: OoO0O00 % O0
 def cache_size ( self ) :
  return ( self . cache_count )
  if 92 - 92: OoooooooOO / O0
  if 14 - 14: i11iIiiIii
 def build_key ( self , prefix ) :
  if ( prefix . afi == LISP_AFI_ULTIMATE_ROOT ) :
   oOOoOO = 0
  elif ( prefix . afi == LISP_AFI_IID_RANGE ) :
   oOOoOO = prefix . mask_len
  else :
   oOOoOO = prefix . mask_len + 48
   if 43 - 43: OOooOOo
   if 79 - 79: iII111i % Oo0Ooo . i1IIi % ooOoO0o
  IIiI1i = lisp_hex_string ( prefix . instance_id ) . zfill ( 8 )
  ooo0O0O0oo0 = lisp_hex_string ( prefix . afi ) . zfill ( 4 )
  if 93 - 93: OoOoOO00
  if ( prefix . afi > 0 ) :
   if ( prefix . is_binary ( ) ) :
    i1IIiIIIi1 = prefix . addr_length ( ) * 2
    I1Iii1I = lisp_hex_string ( prefix . address ) . zfill ( i1IIiIIIi1 )
   else :
    I1Iii1I = prefix . address
    if 49 - 49: i1IIi * OOooOOo % I11i * Ii1I . I1Ii111 * iIii1I11I1II1
  elif ( prefix . afi == LISP_AFI_GEO_COORD ) :
   ooo0O0O0oo0 = "8003"
   I1Iii1I = prefix . address . print_geo ( )
  else :
   ooo0O0O0oo0 = ""
   I1Iii1I = ""
   if 72 - 72: ooOoO0o
   if 63 - 63: Oo0Ooo . OoO0O00 . OoooooooOO / i1IIi
  OOoOoO = IIiI1i + ooo0O0O0oo0 + I1Iii1I
  return ( [ oOOoOO , OOoOoO ] )
  if 53 - 53: OOooOOo * O0 . iII111i
  if 3 - 3: OoooooooOO * I1Ii111 * IiII - OOooOOo * I1Ii111
 def add_cache ( self , prefix , entry ) :
  if ( prefix . is_binary ( ) ) : prefix . zero_host_bits ( )
  oOOoOO , OOoOoO = self . build_key ( prefix )
  if ( self . cache . has_key ( oOOoOO ) == False ) :
   self . cache [ oOOoOO ] = lisp_cache_entries ( )
   self . cache [ oOOoOO ] . entries = { }
   self . cache [ oOOoOO ] . entries_sorted = [ ]
   self . cache_sorted = sorted ( self . cache )
   if 78 - 78: iII111i
  if ( self . cache [ oOOoOO ] . entries . has_key ( OOoOoO ) == False ) :
   self . cache_count += 1
   if 80 - 80: i1IIi * I1IiiI + OOooOOo
  self . cache [ oOOoOO ] . entries [ OOoOoO ] = entry
  self . cache [ oOOoOO ] . entries_sorted = sorted ( self . cache [ oOOoOO ] . entries )
  if 91 - 91: I1IiiI % OoOoOO00 * Oo0Ooo / I1ii11iIi11i
  if 57 - 57: i11iIiiIii / o0oOOo0O0Ooo . II111iiii
 def lookup_cache ( self , prefix , exact ) :
  oOoo , OOoOoO = self . build_key ( prefix )
  if ( exact ) :
   if ( self . cache . has_key ( oOoo ) == False ) : return ( None )
   if ( self . cache [ oOoo ] . entries . has_key ( OOoOoO ) == False ) : return ( None )
   return ( self . cache [ oOoo ] . entries [ OOoOoO ] )
   if 65 - 65: Oo0Ooo - o0oOOo0O0Ooo + i1IIi + I1IiiI
   if 58 - 58: iII111i * IiII . i1IIi + I1Ii111
  iIiI111I = None
  for oOOoOO in self . cache_sorted :
   if ( oOoo < oOOoOO ) : return ( iIiI111I )
   for i11i111III1iI in self . cache [ oOOoOO ] . entries_sorted :
    Ooo0000000 = self . cache [ oOOoOO ] . entries
    if ( i11i111III1iI in Ooo0000000 ) :
     oo = Ooo0000000 [ i11i111III1iI ]
     if ( oo == None ) : continue
     if ( prefix . is_more_specific ( oo . eid ) ) : iIiI111I = oo
     if 31 - 31: OoOoOO00 * iIii1I11I1II1
     if 45 - 45: iIii1I11I1II1
     if 73 - 73: OoOoOO00 * OOooOOo * I11i / I1IiiI + oO0o
  return ( iIiI111I )
  if 14 - 14: oO0o % o0oOOo0O0Ooo * i11iIiiIii - OoooooooOO * OOooOOo
  if 11 - 11: oO0o
 def delete_cache ( self , prefix ) :
  oOOoOO , OOoOoO = self . build_key ( prefix )
  if ( self . cache . has_key ( oOOoOO ) == False ) : return
  if ( self . cache [ oOOoOO ] . entries . has_key ( OOoOoO ) == False ) : return
  self . cache [ oOOoOO ] . entries . pop ( OOoOoO )
  self . cache [ oOOoOO ] . entries_sorted . remove ( OOoOoO )
  self . cache_count -= 1
  if 14 - 14: OoooooooOO . I1ii11iIi11i % I1IiiI / I1IiiI % Oo0Ooo
  if 97 - 97: i1IIi
 def walk_cache ( self , function , parms ) :
  for oOOoOO in self . cache_sorted :
   for OOoOoO in self . cache [ oOOoOO ] . entries_sorted :
    oo = self . cache [ oOOoOO ] . entries [ OOoOoO ]
    iI1Ii11iiII , parms = function ( oo , parms )
    if ( iI1Ii11iiII == False ) : return ( parms )
    if 54 - 54: OoooooooOO . OoooooooOO / i1IIi * Oo0Ooo
    if 90 - 90: oO0o / Oo0Ooo + Oo0Ooo
  return ( parms )
  if 16 - 16: I1Ii111 / I1ii11iIi11i / I11i - I1IiiI
  if 30 - 30: I1Ii111 + OoO0O00 % OoOoOO00 / I11i - iII111i
 def print_cache ( self ) :
  lprint ( "Printing contents of {}: " . format ( self ) )
  if ( self . cache_size ( ) == 0 ) :
   lprint ( "  Cache is empty" )
   return
   if 35 - 35: o0oOOo0O0Ooo / I1Ii111 - ooOoO0o
  for oOOoOO in self . cache_sorted :
   for OOoOoO in self . cache [ oOOoOO ] . entries_sorted :
    oo = self . cache [ oOOoOO ] . entries [ OOoOoO ]
    lprint ( "  Mask-length: {}, key: {}, entry: {}" . format ( oOOoOO , OOoOoO ,
 oo ) )
    if 44 - 44: I1IiiI * I11i + I1ii11iIi11i / IiII
    if 95 - 95: OoOoOO00
    if 73 - 73: IiII * Oo0Ooo . I1IiiI - iIii1I11I1II1
    if 100 - 100: i11iIiiIii - IiII
    if 43 - 43: oO0o - I11i . i11iIiiIii
    if 78 - 78: i11iIiiIii + Oo0Ooo * Ii1I - o0oOOo0O0Ooo % i11iIiiIii
    if 30 - 30: I1IiiI % oO0o * OoooooooOO
    if 64 - 64: I1IiiI
lisp_referral_cache = lisp_cache ( )
lisp_ddt_cache = lisp_cache ( )
lisp_sites_by_eid = lisp_cache ( )
lisp_map_cache = lisp_cache ( )
lisp_db_for_lookups = lisp_cache ( )
if 11 - 11: I1ii11iIi11i % iII111i / II111iiii % ooOoO0o % IiII
if 14 - 14: ooOoO0o / IiII . o0oOOo0O0Ooo
if 27 - 27: I1IiiI - OOooOOo . II111iiii * I1ii11iIi11i % ooOoO0o / I1IiiI
if 90 - 90: o0oOOo0O0Ooo / I1ii11iIi11i - oO0o - Ii1I - I1IiiI + I1Ii111
if 93 - 93: I1IiiI - I11i . I1IiiI - iIii1I11I1II1
if 1 - 1: O0 . Ii1I % Ii1I + II111iiii . oO0o
if 24 - 24: o0oOOo0O0Ooo . I1Ii111 % O0
def lisp_map_cache_lookup ( source , dest ) :
 if 67 - 67: I1IiiI * Ii1I
 o0000ooO = dest . is_multicast_address ( )
 if 64 - 64: OOooOOo
 if 90 - 90: iII111i . OoOoOO00 + i1IIi % ooOoO0o * I11i + OoooooooOO
 if 2 - 2: o0oOOo0O0Ooo . II111iiii
 if 9 - 9: I1Ii111 - II111iiii + OoOoOO00 . OoO0O00
 iIi11 = lisp_map_cache . lookup_cache ( dest , False )
 if ( iIi11 == None ) :
  oo0ooooO = source . print_sg ( dest ) if o0000ooO else dest . print_address ( )
  oo0ooooO = green ( oo0ooooO , False )
  dprint ( "Lookup for EID {} not found in map-cache" . format ( oo0ooooO ) )
  return ( None )
  if 33 - 33: Oo0Ooo
  if 12 - 12: i11iIiiIii . Oo0Ooo / OoOoOO00 + iII111i . Ii1I + ooOoO0o
  if 66 - 66: IiII
  if 41 - 41: II111iiii + Oo0Ooo / iII111i . IiII / iII111i / I1IiiI
  if 78 - 78: o0oOOo0O0Ooo % OoOoOO00 . O0
 if ( o0000ooO == False ) :
  II1111 = green ( iIi11 . eid . print_prefix ( ) , False )
  dprint ( "Lookup for EID {} found map-cache entry {}" . format ( green ( dest . print_address ( ) , False ) , II1111 ) )
  if 41 - 41: iIii1I11I1II1 . OOooOOo - Oo0Ooo % OOooOOo
  return ( iIi11 )
  if 90 - 90: i11iIiiIii + OoooooooOO - i11iIiiIii + OoooooooOO
  if 23 - 23: i11iIiiIii - IiII - I1ii11iIi11i + I1ii11iIi11i % I1IiiI
  if 79 - 79: II111iiii / OoooooooOO
  if 35 - 35: i1IIi + IiII + II111iiii % OOooOOo
  if 25 - 25: I11i + i11iIiiIii + O0 - Ii1I
 iIi11 = iIi11 . lookup_source_cache ( source , False )
 if ( iIi11 == None ) :
  oo0ooooO = source . print_sg ( dest )
  dprint ( "Lookup for EID {} not found in map-cache" . format ( oo0ooooO ) )
  return ( None )
  if 69 - 69: I11i . OoOoOO00 / OOooOOo / i1IIi . II111iiii
  if 17 - 17: I1Ii111
  if 2 - 2: O0 % OoOoOO00 + oO0o
  if 24 - 24: iII111i + iII111i - OoooooooOO % OoooooooOO * O0
  if 51 - 51: IiII
 II1111 = green ( iIi11 . print_eid_tuple ( ) , False )
 dprint ( "Lookup for EID {} found map-cache entry {}" . format ( green ( source . print_sg ( dest ) , False ) , II1111 ) )
 if 31 - 31: I11i - iIii1I11I1II1 * Ii1I + Ii1I
 return ( iIi11 )
 if 10 - 10: OoOoOO00 - i11iIiiIii % iIii1I11I1II1 / ooOoO0o * i11iIiiIii - Ii1I
 if 64 - 64: II111iiii . i11iIiiIii . iII111i . OOooOOo
 if 95 - 95: O0 - OoOoOO00
 if 68 - 68: ooOoO0o . I1Ii111
 if 84 - 84: OoooooooOO + oO0o % i1IIi + o0oOOo0O0Ooo * i1IIi
 if 51 - 51: oO0o . OoooooooOO + OOooOOo * I1ii11iIi11i - ooOoO0o
 if 41 - 41: Oo0Ooo
def lisp_referral_cache_lookup ( eid , group , exact ) :
 if ( group and group . is_null ( ) ) :
  iI1OO0o00 = lisp_referral_cache . lookup_cache ( eid , exact )
  return ( iI1OO0o00 )
  if 46 - 46: i11iIiiIii + iIii1I11I1II1 . i11iIiiIii . iII111i
  if 66 - 66: oO0o % i1IIi % OoooooooOO
  if 58 - 58: OOooOOo
  if 89 - 89: iIii1I11I1II1 - i1IIi
  if 26 - 26: OOooOOo - iII111i * I1ii11iIi11i / iII111i
 if ( eid == None or eid . is_null ( ) ) : return ( None )
 if 9 - 9: I1Ii111 / II111iiii * I1Ii111 / I11i - OoO0O00
 if 36 - 36: IiII . OoOoOO00 . Ii1I
 if 31 - 31: iIii1I11I1II1
 if 84 - 84: I1ii11iIi11i - iII111i * I1IiiI
 if 88 - 88: OOooOOo / Oo0Ooo
 if 31 - 31: II111iiii
 iI1OO0o00 = lisp_referral_cache . lookup_cache ( group , exact )
 if ( iI1OO0o00 == None ) : return ( None )
 if 32 - 32: o0oOOo0O0Ooo % o0oOOo0O0Ooo
 o00O0o = iI1OO0o00 . lookup_source_cache ( eid , exact )
 if ( o00O0o ) : return ( o00O0o )
 if 99 - 99: OoooooooOO - I1ii11iIi11i / i1IIi
 if ( exact ) : iI1OO0o00 = None
 return ( iI1OO0o00 )
 if 44 - 44: I1IiiI * oO0o - OoOoOO00 + ooOoO0o
 if 75 - 75: ooOoO0o % OoooooooOO / OoooooooOO / Ii1I / I11i % IiII
 if 68 - 68: II111iiii . iIii1I11I1II1
 if 23 - 23: iIii1I11I1II1 + I1Ii111 + I1IiiI - i11iIiiIii % IiII % i1IIi
 if 24 - 24: OOooOOo - OoOoOO00 - i1IIi + O0 + I1IiiI . o0oOOo0O0Ooo
 if 97 - 97: I1Ii111 + Ii1I * ooOoO0o
 if 95 - 95: O0
def lisp_ddt_cache_lookup ( eid , group , exact ) :
 if ( group . is_null ( ) ) :
  I1oo0Oo = lisp_ddt_cache . lookup_cache ( eid , exact )
  return ( I1oo0Oo )
  if 61 - 61: Oo0Ooo % O0 . Ii1I - OOooOOo - o0oOOo0O0Ooo
  if 71 - 71: iIii1I11I1II1
  if 10 - 10: OoooooooOO - iII111i . i1IIi % oO0o . OoooooooOO + OOooOOo
  if 59 - 59: I1IiiI * OoooooooOO % OOooOOo / I11i
  if 77 - 77: II111iiii - IiII % OOooOOo
 if ( eid . is_null ( ) ) : return ( None )
 if 22 - 22: OoooooooOO / oO0o
 if 78 - 78: oO0o * I11i . i1IIi % i1IIi + i1IIi / OOooOOo
 if 66 - 66: OoooooooOO % o0oOOo0O0Ooo / I11i * I1Ii111
 if 12 - 12: I1Ii111
 if 17 - 17: I1Ii111 % oO0o + O0
 if 15 - 15: o0oOOo0O0Ooo - OoooooooOO % ooOoO0o % oO0o / i11iIiiIii / Oo0Ooo
 I1oo0Oo = lisp_ddt_cache . lookup_cache ( group , exact )
 if ( I1oo0Oo == None ) : return ( None )
 if 59 - 59: iII111i + O0 - I1ii11iIi11i * I1ii11iIi11i + iIii1I11I1II1
 Ii = I1oo0Oo . lookup_source_cache ( eid , exact )
 if ( Ii ) : return ( Ii )
 if 54 - 54: II111iiii
 if ( exact ) : I1oo0Oo = None
 return ( I1oo0Oo )
 if 98 - 98: Oo0Ooo + IiII . Oo0Ooo / OoOoOO00 + O0
 if 99 - 99: Oo0Ooo
 if 42 - 42: I1IiiI + I1Ii111 - oO0o + o0oOOo0O0Ooo
 if 86 - 86: Ii1I - o0oOOo0O0Ooo % iII111i
 if 37 - 37: Oo0Ooo
 if 87 - 87: I1ii11iIi11i . OoooooooOO . ooOoO0o + iIii1I11I1II1 + O0 % I1ii11iIi11i
 if 53 - 53: IiII
def lisp_site_eid_lookup ( eid , group , exact ) :
 if 96 - 96: Oo0Ooo . i11iIiiIii / Ii1I . I1ii11iIi11i % I1Ii111
 if ( group . is_null ( ) ) :
  o0O0o = lisp_sites_by_eid . lookup_cache ( eid , exact )
  return ( o0O0o )
  if 68 - 68: ooOoO0o
  if 58 - 58: iII111i * I1IiiI
  if 82 - 82: Oo0Ooo / OoO0O00 % Oo0Ooo . ooOoO0o * O0
  if 39 - 39: I1Ii111 * IiII
  if 16 - 16: ooOoO0o + OoO0O00 / I11i * OoO0O00 . Oo0Ooo % OoOoOO00
 if ( eid . is_null ( ) ) : return ( None )
 if 65 - 65: Oo0Ooo / I1Ii111 % II111iiii % Ii1I
 if 70 - 70: II111iiii % Oo0Ooo * oO0o
 if 54 - 54: O0 / ooOoO0o * I1Ii111
 if 5 - 5: Ii1I / OoOoOO00 - O0 * OoO0O00
 if 13 - 13: IiII + Oo0Ooo - I1Ii111
 if 10 - 10: OOooOOo % OoooooooOO / I1IiiI . II111iiii % iII111i
 o0O0o = lisp_sites_by_eid . lookup_cache ( group , exact )
 if ( o0O0o == None ) : return ( None )
 if 47 - 47: o0oOOo0O0Ooo . i11iIiiIii * i1IIi % I11i - ooOoO0o * oO0o
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
 if 63 - 63: I11i + i11iIiiIii . o0oOOo0O0Ooo . i1IIi + OoOoOO00
 if 1 - 1: i11iIiiIii
 i1iI = o0O0o . lookup_source_cache ( eid , exact )
 if ( i1iI ) : return ( i1iI )
 if 1 - 1: iIii1I11I1II1
 if ( exact ) :
  o0O0o = None
 else :
  iiIo00ooO = o0O0o . parent_for_more_specifics
  if ( iiIo00ooO and iiIo00ooO . accept_more_specifics ) :
   if ( group . is_more_specific ( iiIo00ooO . group ) ) : o0O0o = iiIo00ooO
   if 73 - 73: iII111i + IiII
   if 95 - 95: O0
 return ( o0O0o )
 if 75 - 75: ooOoO0o
 if 8 - 8: O0 - OoooooooOO + I1ii11iIi11i / Oo0Ooo . oO0o + I1Ii111
 if 85 - 85: ooOoO0o
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
 if 97 - 97: oO0o % iIii1I11I1II1
 if 87 - 87: II111iiii % I1IiiI + oO0o - I11i / I11i
 if 16 - 16: I1IiiI
 if 39 - 39: ooOoO0o * II111iiii
 if 90 - 90: OoooooooOO * ooOoO0o
class lisp_address ( ) :
 def __init__ ( self , afi , addr_str , mask_len , iid ) :
  self . afi = afi
  self . mask_len = mask_len
  self . instance_id = iid
  self . iid_list = [ ]
  self . address = 0
  if ( addr_str != "" ) : self . store_address ( addr_str )
  if 14 - 14: I1IiiI % i1IIi
  if 35 - 35: ooOoO0o % o0oOOo0O0Ooo % ooOoO0o
 def copy_address ( self , addr ) :
  if ( addr == None ) : return
  self . afi = addr . afi
  self . address = addr . address
  self . mask_len = addr . mask_len
  self . instance_id = addr . instance_id
  self . iid_list = addr . iid_list
  if 77 - 77: OOooOOo % I1Ii111 / i11iIiiIii . i1IIi % OOooOOo
  if 55 - 55: i1IIi
 def make_default_route ( self , addr ) :
  self . afi = addr . afi
  self . instance_id = addr . instance_id
  self . mask_len = 0
  self . address = 0
  if 64 - 64: oO0o . OOooOOo * i11iIiiIii + I1Ii111
  if 88 - 88: O0
 def make_default_multicast_route ( self , addr ) :
  self . afi = addr . afi
  self . instance_id = addr . instance_id
  if ( self . afi == LISP_AFI_IPV4 ) :
   self . address = 0xe0000000
   self . mask_len = 4
   if 75 - 75: iII111i - Oo0Ooo / OoooooooOO - O0
  if ( self . afi == LISP_AFI_IPV6 ) :
   self . address = 0xff << 120
   self . mask_len = 8
   if 36 - 36: OoO0O00 % Ii1I . Oo0Ooo
  if ( self . afi == LISP_AFI_MAC ) :
   self . address = 0xffffffffffff
   self . mask_len = 48
   if 90 - 90: i11iIiiIii - iII111i * oO0o
   if 79 - 79: IiII
   if 38 - 38: I1Ii111
 def not_set ( self ) :
  return ( self . afi == LISP_AFI_NONE )
  if 56 - 56: i11iIiiIii
  if 58 - 58: i11iIiiIii / OoOoOO00
 def is_private_address ( self ) :
  if ( self . is_ipv4 ( ) == False ) : return ( False )
  I1Iii1I = self . address
  if ( ( ( I1Iii1I & 0xff000000 ) >> 24 ) == 10 ) : return ( True )
  if ( ( ( I1Iii1I & 0xff000000 ) >> 24 ) == 172 ) :
   IIIiIII1II = ( I1Iii1I & 0x00ff0000 ) >> 16
   if ( IIIiIII1II >= 16 and IIIiIII1II <= 31 ) : return ( True )
   if 20 - 20: Oo0Ooo
  if ( ( ( I1Iii1I & 0xffff0000 ) >> 16 ) == 0xc0a8 ) : return ( True )
  return ( False )
  if 45 - 45: iIii1I11I1II1 % O0 / I1IiiI . o0oOOo0O0Ooo * IiII
  if 87 - 87: II111iiii / OoooooooOO * II111iiii % i11iIiiIii - ooOoO0o + II111iiii
 def is_multicast_address ( self ) :
  if ( self . is_ipv4 ( ) ) : return ( self . is_ipv4_multicast ( ) )
  if ( self . is_ipv6 ( ) ) : return ( self . is_ipv6_multicast ( ) )
  if ( self . is_mac ( ) ) : return ( self . is_mac_multicast ( ) )
  return ( False )
  if 39 - 39: I1Ii111
  if 51 - 51: o0oOOo0O0Ooo * I11i
 def host_mask_len ( self ) :
  if ( self . afi == LISP_AFI_IPV4 ) : return ( LISP_IPV4_HOST_MASK_LEN )
  if ( self . afi == LISP_AFI_IPV6 ) : return ( LISP_IPV6_HOST_MASK_LEN )
  if ( self . afi == LISP_AFI_MAC ) : return ( LISP_MAC_HOST_MASK_LEN )
  if ( self . afi == LISP_AFI_E164 ) : return ( LISP_E164_HOST_MASK_LEN )
  if ( self . afi == LISP_AFI_NAME ) : return ( len ( self . address ) * 8 )
  if ( self . afi == LISP_AFI_GEO_COORD ) :
   return ( len ( self . address . print_geo ( ) ) * 8 )
   if 42 - 42: OOooOOo % I11i
  return ( 0 )
  if 84 - 84: Oo0Ooo * OoOoOO00 / Ii1I / IiII / o0oOOo0O0Ooo . I1ii11iIi11i
  if 81 - 81: I1IiiI
 def is_iana_eid ( self ) :
  if ( self . is_ipv6 ( ) == False ) : return ( False )
  I1Iii1I = self . address >> 96
  return ( I1Iii1I == 0x20010005 )
  if 82 - 82: I1Ii111 - OoooooooOO - Ii1I
  if 34 - 34: OOooOOo . iIii1I11I1II1 / I1IiiI . Oo0Ooo - iIii1I11I1II1
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
   if 83 - 83: iII111i - I1ii11iIi11i + iII111i
  return ( 0 )
  if 4 - 4: o0oOOo0O0Ooo % iIii1I11I1II1 + I11i
  if 60 - 60: I1ii11iIi11i / I1Ii111 % i11iIiiIii % oO0o % I1IiiI . Oo0Ooo
 def afi_to_version ( self ) :
  if ( self . afi == LISP_AFI_IPV4 ) : return ( 4 )
  if ( self . afi == LISP_AFI_IPV6 ) : return ( 6 )
  return ( 0 )
  if 20 - 20: IiII - OOooOOo + OoOoOO00
  if 83 - 83: OoooooooOO / I1IiiI + iII111i - iIii1I11I1II1 % ooOoO0o
 def packet_format ( self ) :
  if 74 - 74: OoO0O00
  if 13 - 13: I1ii11iIi11i / OoO0O00
  if 90 - 90: iIii1I11I1II1 - OoO0O00 . i1IIi / o0oOOo0O0Ooo + O0
  if 94 - 94: IiII * i1IIi
  if 90 - 90: O0 % I1IiiI . o0oOOo0O0Ooo % ooOoO0o % I1IiiI
  if ( self . afi == LISP_AFI_IPV4 ) : return ( "I" )
  if ( self . afi == LISP_AFI_IPV6 ) : return ( "QQ" )
  if ( self . afi == LISP_AFI_MAC ) : return ( "HHH" )
  if ( self . afi == LISP_AFI_E164 ) : return ( "II" )
  if ( self . afi == LISP_AFI_LCAF ) : return ( "I" )
  return ( "" )
  if 16 - 16: OoO0O00 / OOooOOo / iIii1I11I1II1 / OoooooooOO . oO0o - I1Ii111
  if 43 - 43: OoOoOO00 % OOooOOo / I1IiiI + I1IiiI
 def pack_address ( self ) :
  o0o0 = self . packet_format ( )
  I111 = ""
  if ( self . is_ipv4 ( ) ) :
   I111 = struct . pack ( o0o0 , socket . htonl ( self . address ) )
  elif ( self . is_ipv6 ( ) ) :
   III1IiI1i1i = byte_swap_64 ( self . address >> 64 )
   o0OOOOOo0 = byte_swap_64 ( self . address & 0xffffffffffffffff )
   I111 = struct . pack ( o0o0 , III1IiI1i1i , o0OOOOOo0 )
  elif ( self . is_mac ( ) ) :
   I1Iii1I = self . address
   III1IiI1i1i = ( I1Iii1I >> 32 ) & 0xffff
   o0OOOOOo0 = ( I1Iii1I >> 16 ) & 0xffff
   i1IOO = I1Iii1I & 0xffff
   I111 = struct . pack ( o0o0 , III1IiI1i1i , o0OOOOOo0 , i1IOO )
  elif ( self . is_e164 ( ) ) :
   I1Iii1I = self . address
   III1IiI1i1i = ( I1Iii1I >> 32 ) & 0xffffffff
   o0OOOOOo0 = ( I1Iii1I & 0xffffffff )
   I111 = struct . pack ( o0o0 , III1IiI1i1i , o0OOOOOo0 )
  elif ( self . is_dist_name ( ) ) :
   I111 += self . address + "\0"
   if 62 - 62: I1Ii111
  return ( I111 )
  if 13 - 13: IiII / I1IiiI + II111iiii * iII111i + i1IIi
  if 10 - 10: Oo0Ooo . o0oOOo0O0Ooo - i11iIiiIii / iII111i + i11iIiiIii . I11i
 def unpack_address ( self , packet ) :
  o0o0 = self . packet_format ( )
  O0ooO = struct . calcsize ( o0o0 )
  if ( len ( packet ) < O0ooO ) : return ( None )
  if 66 - 66: i1IIi
  I1Iii1I = struct . unpack ( o0o0 , packet [ : O0ooO ] )
  if 98 - 98: Oo0Ooo / iIii1I11I1II1
  if ( self . is_ipv4 ( ) ) :
   self . address = socket . ntohl ( I1Iii1I [ 0 ] )
   if 33 - 33: O0 - iII111i
  elif ( self . is_ipv6 ( ) ) :
   if 40 - 40: iII111i * I11i
   if 25 - 25: O0 * o0oOOo0O0Ooo % ooOoO0o % I1IiiI
   if 87 - 87: OoOoOO00
   if 30 - 30: IiII % OoOoOO00 + I1Ii111
   if 13 - 13: iII111i * Ii1I % o0oOOo0O0Ooo * i1IIi . IiII % i1IIi
   if 79 - 79: OoooooooOO % I11i / o0oOOo0O0Ooo + IiII + O0 + iII111i
   if 87 - 87: I11i
   if 39 - 39: I1ii11iIi11i * i11iIiiIii % I1Ii111
   if ( I1Iii1I [ 0 ] <= 0xffff and ( I1Iii1I [ 0 ] & 0xff ) == 0 ) :
    oOOO00o0ooo0o = ( I1Iii1I [ 0 ] << 48 ) << 64
   else :
    oOOO00o0ooo0o = byte_swap_64 ( I1Iii1I [ 0 ] ) << 64
    if 68 - 68: Ii1I
   IIiI1iii = byte_swap_64 ( I1Iii1I [ 1 ] )
   self . address = oOOO00o0ooo0o | IIiI1iii
   if 67 - 67: I1Ii111
  elif ( self . is_mac ( ) ) :
   i1ii = I1Iii1I [ 0 ]
   Ooo = I1Iii1I [ 1 ]
   O00O0oOo = I1Iii1I [ 2 ]
   self . address = ( i1ii << 32 ) + ( Ooo << 16 ) + O00O0oOo
   if 85 - 85: Oo0Ooo + i11iIiiIii + ooOoO0o - OoO0O00 + I11i * iIii1I11I1II1
  elif ( self . is_e164 ( ) ) :
   self . address = ( I1Iii1I [ 0 ] << 32 ) + I1Iii1I [ 1 ]
   if 14 - 14: iIii1I11I1II1 . i1IIi - I1Ii111 - ooOoO0o
  elif ( self . is_dist_name ( ) ) :
   packet , self . address = lisp_decode_dist_name ( packet )
   self . mask_len = len ( self . address ) * 8
   O0ooO = 0
   if 41 - 41: O0 % i1IIi * i1IIi
  packet = packet [ O0ooO : : ]
  return ( packet )
  if 85 - 85: II111iiii + i1IIi / ooOoO0o . OOooOOo % OoO0O00
  if 19 - 19: i1IIi + OOooOOo + IiII . I1IiiI * Ii1I
 def is_ipv4 ( self ) :
  return ( True if ( self . afi == LISP_AFI_IPV4 ) else False )
  if 43 - 43: i1IIi . OoooooooOO . I1IiiI . OoooooooOO - OoooooooOO
  if 10 - 10: II111iiii * I1IiiI / II111iiii / OoOoOO00 . ooOoO0o
 def is_ipv4_link_local ( self ) :
  if ( self . is_ipv4 ( ) == False ) : return ( False )
  return ( ( ( self . address >> 16 ) & 0xffff ) == 0xa9fe )
  if 42 - 42: I1IiiI - I11i / I1IiiI + I11i
  if 54 - 54: iII111i
 def is_ipv4_loopback ( self ) :
  if ( self . is_ipv4 ( ) == False ) : return ( False )
  return ( self . address == 0x7f000001 )
  if 86 - 86: I1ii11iIi11i - Ii1I / IiII
  if 91 - 91: ooOoO0o * i11iIiiIii / O0 % Ii1I
 def is_ipv4_multicast ( self ) :
  if ( self . is_ipv4 ( ) == False ) : return ( False )
  return ( ( ( self . address >> 24 ) & 0xf0 ) == 0xe0 )
  if 35 - 35: Oo0Ooo % O0
  if 71 - 71: oO0o % OOooOOo * i1IIi
 def is_ipv4_string ( self , addr_str ) :
  return ( addr_str . find ( "." ) != - 1 )
  if 50 - 50: OoOoOO00 + i1IIi
  if 9 - 9: iII111i / I1Ii111 * Ii1I
 def is_ipv6 ( self ) :
  return ( True if ( self . afi == LISP_AFI_IPV6 ) else False )
  if 25 - 25: OoO0O00 . iII111i % I11i . oO0o * iII111i + Oo0Ooo
  if 77 - 77: IiII % oO0o % IiII * ooOoO0o / OOooOOo + OoOoOO00
 def is_ipv6_link_local ( self ) :
  if ( self . is_ipv6 ( ) == False ) : return ( False )
  return ( ( ( self . address >> 112 ) & 0xffff ) == 0xfe80 )
  if 32 - 32: IiII
  if 90 - 90: I1ii11iIi11i / I11i * o0oOOo0O0Ooo % O0 * i11iIiiIii
 def is_ipv6_string_link_local ( self , addr_str ) :
  return ( addr_str . find ( "fe80::" ) != - 1 )
  if 68 - 68: I11i . Ii1I + I11i / IiII . I11i / iIii1I11I1II1
  if 96 - 96: O0
 def is_ipv6_loopback ( self ) :
  if ( self . is_ipv6 ( ) == False ) : return ( False )
  return ( self . address == 1 )
  if 2 - 2: OoO0O00 / iII111i + o0oOOo0O0Ooo
  if 27 - 27: I11i - OoOoOO00 - ooOoO0o - I1IiiI
 def is_ipv6_multicast ( self ) :
  if ( self . is_ipv6 ( ) == False ) : return ( False )
  return ( ( ( self . address >> 120 ) & 0xff ) == 0xff )
  if 51 - 51: I11i + I11i + O0 + O0 * I1Ii111
  if 61 - 61: IiII . O0
 def is_ipv6_string ( self , addr_str ) :
  return ( addr_str . find ( ":" ) != - 1 )
  if 38 - 38: Ii1I * I1ii11iIi11i - i11iIiiIii + ooOoO0o * I11i
  if 74 - 74: OoOoOO00 . o0oOOo0O0Ooo
 def is_mac ( self ) :
  return ( True if ( self . afi == LISP_AFI_MAC ) else False )
  if 40 - 40: ooOoO0o + I1ii11iIi11i * i11iIiiIii / i1IIi
  if 95 - 95: oO0o / IiII * II111iiii * Ii1I . OoO0O00 . OoO0O00
 def is_mac_multicast ( self ) :
  if ( self . is_mac ( ) == False ) : return ( False )
  return ( ( self . address & 0x010000000000 ) != 0 )
  if 85 - 85: I1IiiI / II111iiii * OoO0O00 + ooOoO0o / OoO0O00 % OOooOOo
  if 100 - 100: I1Ii111 % OoooooooOO % OoOoOO00 % I1IiiI
 def is_mac_broadcast ( self ) :
  if ( self . is_mac ( ) == False ) : return ( False )
  return ( self . address == 0xffffffffffff )
  if 32 - 32: OoO0O00 + OOooOOo . OoO0O00 - Oo0Ooo
  if 12 - 12: I1IiiI * OoO0O00 - II111iiii . i1IIi
 def is_mac_string ( self , addr_str ) :
  return ( len ( addr_str ) == 15 and addr_str . find ( "-" ) != - 1 )
  if 86 - 86: OOooOOo / OoooooooOO - IiII
  if 56 - 56: I1ii11iIi11i - i1IIi * OoooooooOO * O0 * I1IiiI - I1Ii111
 def is_link_local_multicast ( self ) :
  if ( self . is_ipv4 ( ) ) :
   return ( ( 0xe0ffff00 & self . address ) == 0xe0000000 )
   if 32 - 32: OoooooooOO . OOooOOo . OoO0O00 . IiII / I11i % i1IIi
  if ( self . is_ipv6 ( ) ) :
   return ( ( self . address >> 112 ) & 0xffff == 0xff02 )
   if 21 - 21: O0 . OoO0O00 * I1ii11iIi11i % iII111i + OoooooooOO
  return ( False )
  if 8 - 8: oO0o * iII111i * I11i
  if 30 - 30: I1Ii111
 def is_null ( self ) :
  return ( True if ( self . afi == LISP_AFI_NONE ) else False )
  if 61 - 61: iII111i
  if 50 - 50: Ii1I / I1IiiI . O0
 def is_ultimate_root ( self ) :
  return ( True if self . afi == LISP_AFI_ULTIMATE_ROOT else False )
  if 49 - 49: I1Ii111 . OoO0O00 % O0
  if 15 - 15: I11i - Oo0Ooo / I1Ii111 . ooOoO0o % I1IiiI
 def is_iid_range ( self ) :
  return ( True if self . afi == LISP_AFI_IID_RANGE else False )
  if 62 - 62: II111iiii + ooOoO0o + I1IiiI
  if 70 - 70: o0oOOo0O0Ooo + Ii1I . OoO0O00 * Ii1I + OOooOOo + ooOoO0o
 def is_e164 ( self ) :
  return ( True if ( self . afi == LISP_AFI_E164 ) else False )
  if 13 - 13: I1ii11iIi11i
  if 97 - 97: oO0o - Oo0Ooo . i11iIiiIii % ooOoO0o * i11iIiiIii - OoooooooOO
 def is_dist_name ( self ) :
  return ( True if ( self . afi == LISP_AFI_NAME ) else False )
  if 44 - 44: I11i % OoooooooOO / iII111i - i11iIiiIii * i1IIi * o0oOOo0O0Ooo
  if 51 - 51: Ii1I + IiII / I1ii11iIi11i + O0 % Ii1I
 def is_geo_prefix ( self ) :
  return ( True if ( self . afi == LISP_AFI_GEO_COORD ) else False )
  if 55 - 55: iII111i % o0oOOo0O0Ooo - oO0o % OoooooooOO
  if 18 - 18: OoooooooOO - I1ii11iIi11i
 def is_binary ( self ) :
  if ( self . is_dist_name ( ) ) : return ( False )
  if ( self . is_geo_prefix ( ) ) : return ( False )
  return ( True )
  if 94 - 94: OOooOOo . Oo0Ooo + Ii1I * o0oOOo0O0Ooo
  if 79 - 79: OOooOOo + Oo0Ooo
 def store_address ( self , addr_str ) :
  if ( self . afi == LISP_AFI_NONE ) : self . string_to_afi ( addr_str )
  if 33 - 33: iIii1I11I1II1
  if 75 - 75: I1Ii111 / iIii1I11I1II1 . OoooooooOO
  if 98 - 98: iIii1I11I1II1 / I1IiiI + i1IIi
  if 80 - 80: II111iiii . Oo0Ooo * oO0o % II111iiii / I1ii11iIi11i
  oO = addr_str . find ( "[" )
  oOooO0Oo0Oo0 = addr_str . find ( "]" )
  if ( oO != - 1 and oOooO0Oo0Oo0 != - 1 ) :
   self . instance_id = int ( addr_str [ oO + 1 : oOooO0Oo0Oo0 ] )
   addr_str = addr_str [ oOooO0Oo0Oo0 + 1 : : ]
   if ( self . is_dist_name ( ) == False ) :
    addr_str = addr_str . replace ( " " , "" )
    if 66 - 66: iII111i / OoO0O00 / i11iIiiIii
    if 99 - 99: OOooOOo
    if 51 - 51: i11iIiiIii . o0oOOo0O0Ooo / iII111i
    if 53 - 53: oO0o / i1IIi - Oo0Ooo - i1IIi + IiII
    if 79 - 79: oO0o % o0oOOo0O0Ooo / o0oOOo0O0Ooo % iII111i
    if 56 - 56: Oo0Ooo % I1ii11iIi11i
  if ( self . is_ipv4 ( ) ) :
   oOO = addr_str . split ( "." )
   oOOO = int ( oOO [ 0 ] ) << 24
   oOOO += int ( oOO [ 1 ] ) << 16
   oOOO += int ( oOO [ 2 ] ) << 8
   oOOO += int ( oOO [ 3 ] )
   self . address = oOOO
  elif ( self . is_ipv6 ( ) ) :
   if 72 - 72: ooOoO0o . I11i + i11iIiiIii / oO0o % oO0o * i1IIi
   if 55 - 55: Oo0Ooo % oO0o . i11iIiiIii
   if 95 - 95: OoO0O00 * OOooOOo
   if 93 - 93: I1Ii111 / I11i % Oo0Ooo . I11i . oO0o + OoooooooOO
   if 9 - 9: OoO0O00
   if 46 - 46: o0oOOo0O0Ooo % OoO0O00 + I11i % o0oOOo0O0Ooo + oO0o . Oo0Ooo
   if 58 - 58: I1Ii111 + I1ii11iIi11i
   if 57 - 57: OOooOOo + II111iiii
   if 67 - 67: II111iiii
   if 39 - 39: i1IIi
   if 16 - 16: OoOoOO00 % iIii1I11I1II1 + Ii1I - o0oOOo0O0Ooo . Oo0Ooo + i1IIi
   if 59 - 59: i1IIi
   if 37 - 37: OoO0O00 / I1ii11iIi11i / OoOoOO00
   if 15 - 15: I1IiiI % iIii1I11I1II1 . I1Ii111
   if 71 - 71: I11i - Ii1I + i11iIiiIii % I1ii11iIi11i - OoO0O00 - OOooOOo
   if 71 - 71: OOooOOo
   if 27 - 27: OOooOOo * O0 * i11iIiiIii / OoOoOO00 - i1IIi
   o00o0 = ( addr_str [ 2 : 4 ] == "::" )
   try :
    addr_str = socket . inet_pton ( socket . AF_INET6 , addr_str )
   except :
    addr_str = socket . inet_pton ( socket . AF_INET6 , "0::0" )
    if 85 - 85: I11i + I11i + oO0o - OoOoOO00
   addr_str = binascii . hexlify ( addr_str )
   if 15 - 15: OoO0O00
   if ( o00o0 ) :
    addr_str = addr_str [ 2 : 4 ] + addr_str [ 0 : 2 ] + addr_str [ 4 : : ]
    if 88 - 88: Ii1I % i1IIi / I1Ii111
   self . address = int ( addr_str , 16 )
   if 2 - 2: Ii1I . IiII % OoOoOO00
  elif ( self . is_geo_prefix ( ) ) :
   ii1IiIiIii = lisp_geo ( None )
   ii1IiIiIii . name = "geo-prefix-{}" . format ( ii1IiIiIii )
   ii1IiIiIii . parse_geo_string ( addr_str )
   self . address = ii1IiIiIii
  elif ( self . is_mac ( ) ) :
   addr_str = addr_str . replace ( "-" , "" )
   oOOO = int ( addr_str , 16 )
   self . address = oOOO
  elif ( self . is_e164 ( ) ) :
   addr_str = addr_str [ 1 : : ]
   oOOO = int ( addr_str , 16 )
   self . address = oOOO << 4
  elif ( self . is_dist_name ( ) ) :
   self . address = addr_str . replace ( "'" , "" )
   if 42 - 42: OoOoOO00 * OoO0O00 * IiII - IiII % Oo0Ooo . IiII
  self . mask_len = self . host_mask_len ( )
  if 38 - 38: I1Ii111 . IiII - ooOoO0o . i11iIiiIii
  if 35 - 35: i11iIiiIii
 def store_prefix ( self , prefix_str ) :
  if ( self . is_geo_string ( prefix_str ) ) :
   OOOoO000 = prefix_str . find ( "]" )
   i1iIi = len ( prefix_str [ OOOoO000 + 1 : : ] ) * 8
  elif ( prefix_str . find ( "/" ) != - 1 ) :
   prefix_str , i1iIi = prefix_str . split ( "/" )
  else :
   II11 = prefix_str . find ( "'" )
   if ( II11 == - 1 ) : return
   oOoOOOo = prefix_str . find ( "'" , II11 + 1 )
   if ( oOoOOOo == - 1 ) : return
   i1iIi = len ( prefix_str [ II11 + 1 : oOoOOOo ] ) * 8
   if 62 - 62: O0 - o0oOOo0O0Ooo + I1Ii111 * I1ii11iIi11i / OOooOOo
   if 87 - 87: Oo0Ooo / OoooooooOO + O0 / o0oOOo0O0Ooo % II111iiii - O0
  self . string_to_afi ( prefix_str )
  self . store_address ( prefix_str )
  self . mask_len = int ( i1iIi )
  if 63 - 63: OOooOOo - OoO0O00 * i1IIi - I1ii11iIi11i . I1IiiI
  if 59 - 59: i11iIiiIii . OOooOOo % Oo0Ooo + O0
 def zero_host_bits ( self ) :
  O0Oo = ( 2 ** self . mask_len ) - 1
  I1IiI = self . addr_length ( ) * 8 - self . mask_len
  O0Oo <<= I1IiI
  self . address &= O0Oo
  if 20 - 20: Oo0Ooo
  if 80 - 80: O0 - I1IiiI
 def is_geo_string ( self , addr_str ) :
  OOOoO000 = addr_str . find ( "]" )
  if ( OOOoO000 != - 1 ) : addr_str = addr_str [ OOOoO000 + 1 : : ]
  if 55 - 55: I1ii11iIi11i % IiII % o0oOOo0O0Ooo + i1IIi * OoooooooOO % II111iiii
  ii1IiIiIii = addr_str . split ( "/" )
  if ( len ( ii1IiIiIii ) == 2 ) :
   if ( ii1IiIiIii [ 1 ] . isdigit ( ) == False ) : return ( False )
   if 37 - 37: Oo0Ooo
  ii1IiIiIii = ii1IiIiIii [ 0 ]
  ii1IiIiIii = ii1IiIiIii . split ( "-" )
  IiiiIi1I = len ( ii1IiIiIii )
  if ( IiiiIi1I < 8 or IiiiIi1I > 9 ) : return ( False )
  if 75 - 75: II111iiii + O0 * II111iiii * i11iIiiIii
  for OO0OOoO0o0oOO in range ( 0 , IiiiIi1I ) :
   if ( OO0OOoO0o0oOO == 3 ) :
    if ( ii1IiIiIii [ OO0OOoO0o0oOO ] in [ "N" , "S" ] ) : continue
    return ( False )
    if 4 - 4: i11iIiiIii . I11i % iII111i
   if ( OO0OOoO0o0oOO == 7 ) :
    if ( ii1IiIiIii [ OO0OOoO0o0oOO ] in [ "W" , "E" ] ) : continue
    return ( False )
    if 40 - 40: oO0o
   if ( ii1IiIiIii [ OO0OOoO0o0oOO ] . isdigit ( ) == False ) : return ( False )
   if 31 - 31: Oo0Ooo * iIii1I11I1II1 * Ii1I * Ii1I
  return ( True )
  if 23 - 23: oO0o + OoO0O00 * O0
  if 99 - 99: oO0o * IiII * oO0o
 def string_to_afi ( self , addr_str ) :
  if ( addr_str . count ( "'" ) == 2 ) :
   self . afi = LISP_AFI_NAME
   return
   if 70 - 70: IiII + iII111i / I1ii11iIi11i
  if ( addr_str . find ( ":" ) != - 1 ) : self . afi = LISP_AFI_IPV6
  elif ( addr_str . find ( "." ) != - 1 ) : self . afi = LISP_AFI_IPV4
  elif ( addr_str . find ( "+" ) != - 1 ) : self . afi = LISP_AFI_E164
  elif ( self . is_geo_string ( addr_str ) ) : self . afi = LISP_AFI_GEO_COORD
  elif ( addr_str . find ( "-" ) != - 1 ) : self . afi = LISP_AFI_MAC
  else : self . afi = LISP_AFI_NONE
  if 97 - 97: I1IiiI * OoOoOO00 / iII111i * i11iIiiIii
  if 20 - 20: Ii1I . I11i % iII111i * iIii1I11I1II1 . OoO0O00 . Ii1I
 def print_address ( self ) :
  I1Iii1I = self . print_address_no_iid ( )
  IIiI1i = "[" + str ( self . instance_id )
  for oO in self . iid_list : IIiI1i += "," + str ( oO )
  IIiI1i += "]"
  I1Iii1I = "{}{}" . format ( IIiI1i , I1Iii1I )
  return ( I1Iii1I )
  if 50 - 50: I1IiiI % OOooOOo / iIii1I11I1II1 / I1ii11iIi11i % oO0o . Ii1I
  if 14 - 14: oO0o / Ii1I - I1Ii111
 def print_address_no_iid ( self ) :
  if ( self . is_ipv4 ( ) ) :
   I1Iii1I = self . address
   oOoo0oO0oooo = I1Iii1I >> 24
   OoOo0 = ( I1Iii1I >> 16 ) & 0xff
   ooOOOo00OO0 = ( I1Iii1I >> 8 ) & 0xff
   O00oo = I1Iii1I & 0xff
   return ( "{}.{}.{}.{}" . format ( oOoo0oO0oooo , OoOo0 , ooOOOo00OO0 , O00oo ) )
  elif ( self . is_ipv6 ( ) ) :
   I11i11I = lisp_hex_string ( self . address ) . zfill ( 32 )
   I11i11I = binascii . unhexlify ( I11i11I )
   I11i11I = socket . inet_ntop ( socket . AF_INET6 , I11i11I )
   if 32 - 32: OOooOOo - iII111i
   if 34 - 34: i11iIiiIii - oO0o + iII111i * oO0o
   if 73 - 73: II111iiii
   if 54 - 54: I1IiiI % oO0o % iIii1I11I1II1 % II111iiii
   if ( I11i11I [ 2 : 6 ] == "00::" ) :
    I11i11I = I11i11I [ 0 : 2 ] + I11i11I [ 4 : : ]
    if 43 - 43: I1ii11iIi11i
   return ( "{}" . format ( I11i11I ) )
  elif ( self . is_geo_prefix ( ) ) :
   return ( "{}" . format ( self . address . print_geo ( ) ) )
  elif ( self . is_mac ( ) ) :
   I11i11I = lisp_hex_string ( self . address ) . zfill ( 12 )
   I11i11I = "{}-{}-{}" . format ( I11i11I [ 0 : 4 ] , I11i11I [ 4 : 8 ] ,
 I11i11I [ 8 : 12 ] )
   return ( "{}" . format ( I11i11I ) )
  elif ( self . is_e164 ( ) ) :
   I11i11I = lisp_hex_string ( self . address ) . zfill ( 15 )
   return ( "+{}" . format ( I11i11I ) )
  elif ( self . is_dist_name ( ) ) :
   return ( "'{}'" . format ( self . address ) )
  elif ( self . is_null ( ) ) :
   return ( "no-address" )
   if 60 - 60: i11iIiiIii + IiII
  return ( "unknown-afi:{}" . format ( self . afi ) )
  if 41 - 41: I1Ii111 * o0oOOo0O0Ooo + Oo0Ooo
  if 86 - 86: Ii1I / oO0o
 def print_prefix ( self ) :
  if ( self . is_ultimate_root ( ) ) : return ( "[*]" )
  if ( self . is_iid_range ( ) ) :
   if ( self . mask_len == 32 ) : return ( "[{}]" . format ( self . instance_id ) )
   iIIIIIiii1i = self . instance_id + ( 2 ** ( 32 - self . mask_len ) - 1 )
   return ( "[{}-{}]" . format ( self . instance_id , iIIIIIiii1i ) )
   if 90 - 90: OoooooooOO * ooOoO0o + I1IiiI - oO0o
  I1Iii1I = self . print_address ( )
  if ( self . is_dist_name ( ) ) : return ( I1Iii1I )
  if ( self . is_geo_prefix ( ) ) : return ( I1Iii1I )
  if 53 - 53: IiII / i1IIi - i1IIi
  OOOoO000 = I1Iii1I . find ( "no-address" )
  if ( OOOoO000 == - 1 ) :
   I1Iii1I = "{}/{}" . format ( I1Iii1I , str ( self . mask_len ) )
  else :
   I1Iii1I = I1Iii1I [ 0 : OOOoO000 ]
   if 34 - 34: Ii1I - OOooOOo / OoooooooOO . OoooooooOO % iII111i + I1Ii111
  return ( I1Iii1I )
  if 90 - 90: o0oOOo0O0Ooo
  if 48 - 48: iII111i + Ii1I
 def print_prefix_no_iid ( self ) :
  I1Iii1I = self . print_address_no_iid ( )
  if ( self . is_dist_name ( ) ) : return ( I1Iii1I )
  if ( self . is_geo_prefix ( ) ) : return ( I1Iii1I )
  return ( "{}/{}" . format ( I1Iii1I , str ( self . mask_len ) ) )
  if 45 - 45: oO0o / iIii1I11I1II1 % O0 % IiII % I1ii11iIi11i
  if 89 - 89: OOooOOo - I1Ii111 - iII111i
 def print_prefix_url ( self ) :
  if ( self . is_ultimate_root ( ) ) : return ( "0--0" )
  I1Iii1I = self . print_address ( )
  OOOoO000 = I1Iii1I . find ( "]" )
  if ( OOOoO000 != - 1 ) : I1Iii1I = I1Iii1I [ OOOoO000 + 1 : : ]
  if ( self . is_geo_prefix ( ) ) :
   I1Iii1I = I1Iii1I . replace ( "/" , "-" )
   return ( "{}-{}" . format ( self . instance_id , I1Iii1I ) )
   if 67 - 67: oO0o
  return ( "{}-{}-{}" . format ( self . instance_id , I1Iii1I , self . mask_len ) )
  if 76 - 76: I1IiiI % I1IiiI - IiII / OoOoOO00 / I1ii11iIi11i
  if 42 - 42: I1IiiI + I1ii11iIi11i + Oo0Ooo * i1IIi - II111iiii
 def print_sg ( self , g ) :
  i1I1iIi1IiI = self . print_prefix ( )
  iIiiI1ii = i1I1iIi1IiI . find ( "]" ) + 1
  g = g . print_prefix ( )
  OoooO00 = g . find ( "]" ) + 1
  I1I1I11Ii = "[{}]({}, {})" . format ( self . instance_id , i1I1iIi1IiI [ iIiiI1ii : : ] , g [ OoooO00 : : ] )
  return ( I1I1I11Ii )
  if 5 - 5: II111iiii % I1IiiI * ooOoO0o / ooOoO0o + iII111i
  if 3 - 3: O0 + OOooOOo + I1Ii111 + Oo0Ooo * OoOoOO00
 def hash_address ( self , addr ) :
  III1IiI1i1i = self . address
  o0OOOOOo0 = addr . address
  if 19 - 19: II111iiii * O0 % II111iiii
  if ( self . is_geo_prefix ( ) ) : III1IiI1i1i = self . address . print_geo ( )
  if ( addr . is_geo_prefix ( ) ) : o0OOOOOo0 = addr . address . print_geo ( )
  if 63 - 63: i11iIiiIii . Oo0Ooo . OOooOOo - II111iiii
  if ( type ( III1IiI1i1i ) == str ) :
   III1IiI1i1i = int ( binascii . hexlify ( III1IiI1i1i [ 0 : 1 ] ) )
   if 35 - 35: II111iiii + IiII
  if ( type ( o0OOOOOo0 ) == str ) :
   o0OOOOOo0 = int ( binascii . hexlify ( o0OOOOOo0 [ 0 : 1 ] ) )
   if 66 - 66: o0oOOo0O0Ooo % IiII
  return ( III1IiI1i1i ^ o0OOOOOo0 )
  if 39 - 39: IiII
  if 18 - 18: iII111i % o0oOOo0O0Ooo - i1IIi
  if 53 - 53: o0oOOo0O0Ooo + IiII - ooOoO0o % i11iIiiIii - i11iIiiIii - I1Ii111
  if 79 - 79: II111iiii + i11iIiiIii . OOooOOo . I11i / iIii1I11I1II1
  if 62 - 62: O0
  if 52 - 52: OoooooooOO . oO0o
 def is_more_specific ( self , prefix ) :
  if ( prefix . afi == LISP_AFI_ULTIMATE_ROOT ) : return ( True )
  if 38 - 38: ooOoO0o . i1IIi / iII111i + I1IiiI - II111iiii
  i1iIi = prefix . mask_len
  if ( prefix . afi == LISP_AFI_IID_RANGE ) :
   IiIiii = 2 ** ( 32 - i1iIi )
   oOOOo0000O0 = prefix . instance_id
   iIIIIIiii1i = oOOOo0000O0 + IiIiii
   return ( self . instance_id in range ( oOOOo0000O0 , iIIIIIiii1i ) )
   if 77 - 77: OOooOOo . oO0o + iIii1I11I1II1 + Oo0Ooo . i11iIiiIii . I1ii11iIi11i
   if 71 - 71: II111iiii
  if ( self . instance_id != prefix . instance_id ) : return ( False )
  if ( self . afi != prefix . afi ) :
   if ( prefix . afi != LISP_AFI_NONE ) : return ( False )
   if 2 - 2: OOooOOo / iIii1I11I1II1
   if 86 - 86: oO0o % IiII
   if 71 - 71: I11i + ooOoO0o * OoooooooOO
   if 37 - 37: OoO0O00 % i11iIiiIii
   if 13 - 13: OoooooooOO - II111iiii / OoOoOO00 + OoooooooOO * oO0o
  if ( self . is_binary ( ) == False ) :
   if ( prefix . afi == LISP_AFI_NONE ) : return ( True )
   if ( type ( self . address ) != type ( prefix . address ) ) : return ( False )
   I1Iii1I = self . address
   I1IiiIoOOOoo000 = prefix . address
   if ( self . is_geo_prefix ( ) ) :
    I1Iii1I = self . address . print_geo ( )
    I1IiiIoOOOoo000 = prefix . address . print_geo ( )
    if 62 - 62: o0oOOo0O0Ooo + OoO0O00
   if ( len ( I1Iii1I ) < len ( I1IiiIoOOOoo000 ) ) : return ( False )
   return ( I1Iii1I . find ( I1IiiIoOOOoo000 ) == 0 )
   if 41 - 41: i1IIi + O0 % iIii1I11I1II1
   if 8 - 8: OOooOOo % o0oOOo0O0Ooo
   if 36 - 36: Ii1I % OoooooooOO
   if 31 - 31: Ii1I / Ii1I / Ii1I / o0oOOo0O0Ooo / I11i
   if 24 - 24: i1IIi - Oo0Ooo % Oo0Ooo
  if ( self . mask_len < i1iIi ) : return ( False )
  if 29 - 29: IiII
  I1IiI = ( prefix . addr_length ( ) * 8 ) - i1iIi
  O0Oo = ( 2 ** i1iIi - 1 ) << I1IiI
  return ( ( self . address & O0Oo ) == prefix . address )
  if 94 - 94: I1IiiI * Oo0Ooo * OOooOOo + Oo0Ooo / I1Ii111
  if 3 - 3: I11i * iII111i - OoooooooOO % OoOoOO00 % ooOoO0o
 def mask_address ( self , mask_len ) :
  I1IiI = ( self . addr_length ( ) * 8 ) - mask_len
  O0Oo = ( 2 ** mask_len - 1 ) << I1IiI
  self . address &= O0Oo
  if 48 - 48: i11iIiiIii * i11iIiiIii
  if 92 - 92: i1IIi
 def is_exact_match ( self , prefix ) :
  if ( self . instance_id != prefix . instance_id ) : return ( False )
  iiIo0O = self . print_prefix ( )
  i1i11Iii = prefix . print_prefix ( ) if prefix else ""
  return ( iiIo0O == i1i11Iii )
  if 75 - 75: II111iiii . OoOoOO00 / i11iIiiIii + iII111i / Oo0Ooo
  if 55 - 55: iII111i - ooOoO0o % OOooOOo
 def is_local ( self ) :
  if ( self . is_ipv4 ( ) ) :
   OoOIII1I1i11I = lisp_myrlocs [ 0 ]
   if ( OoOIII1I1i11I == None ) : return ( False )
   OoOIII1I1i11I = OoOIII1I1i11I . print_address_no_iid ( )
   return ( self . print_address_no_iid ( ) == OoOIII1I1i11I )
   if 19 - 19: IiII
  if ( self . is_ipv6 ( ) ) :
   OoOIII1I1i11I = lisp_myrlocs [ 1 ]
   if ( OoOIII1I1i11I == None ) : return ( False )
   OoOIII1I1i11I = OoOIII1I1i11I . print_address_no_iid ( )
   return ( self . print_address_no_iid ( ) == OoOIII1I1i11I )
   if 35 - 35: OoOoOO00
  return ( False )
  if 18 - 18: II111iiii . OoOoOO00 + I1ii11iIi11i * oO0o + OoooooooOO
  if 39 - 39: I1IiiI * ooOoO0o / i11iIiiIii - oO0o - oO0o + O0
 def store_iid_range ( self , iid , mask_len ) :
  if ( self . afi == LISP_AFI_NONE ) :
   if ( iid is 0 and mask_len is 0 ) : self . afi = LISP_AFI_ULTIMATE_ROOT
   else : self . afi = LISP_AFI_IID_RANGE
   if 73 - 73: OOooOOo
  self . instance_id = iid
  self . mask_len = mask_len
  if 44 - 44: I1ii11iIi11i * i1IIi - iIii1I11I1II1 - oO0o - oO0o * II111iiii
  if 98 - 98: Oo0Ooo + ooOoO0o / OOooOOo . iIii1I11I1II1 . I1IiiI . OoOoOO00
 def lcaf_length ( self , lcaf_type ) :
  i1IIiIIIi1 = self . addr_length ( ) + 2
  if ( lcaf_type == LISP_LCAF_AFI_LIST_TYPE ) : i1IIiIIIi1 += 4
  if ( lcaf_type == LISP_LCAF_INSTANCE_ID_TYPE ) : i1IIiIIIi1 += 4
  if ( lcaf_type == LISP_LCAF_ASN_TYPE ) : i1IIiIIIi1 += 4
  if ( lcaf_type == LISP_LCAF_APP_DATA_TYPE ) : i1IIiIIIi1 += 8
  if ( lcaf_type == LISP_LCAF_GEO_COORD_TYPE ) : i1IIiIIIi1 += 12
  if ( lcaf_type == LISP_LCAF_OPAQUE_TYPE ) : i1IIiIIIi1 += 0
  if ( lcaf_type == LISP_LCAF_NAT_TYPE ) : i1IIiIIIi1 += 4
  if ( lcaf_type == LISP_LCAF_NONCE_LOC_TYPE ) : i1IIiIIIi1 += 4
  if ( lcaf_type == LISP_LCAF_MCAST_INFO_TYPE ) : i1IIiIIIi1 = i1IIiIIIi1 * 2 + 8
  if ( lcaf_type == LISP_LCAF_ELP_TYPE ) : i1IIiIIIi1 += 0
  if ( lcaf_type == LISP_LCAF_SECURITY_TYPE ) : i1IIiIIIi1 += 6
  if ( lcaf_type == LISP_LCAF_SOURCE_DEST_TYPE ) : i1IIiIIIi1 += 4
  if ( lcaf_type == LISP_LCAF_RLE_TYPE ) : i1IIiIIIi1 += 4
  return ( i1IIiIIIi1 )
  if 92 - 92: i1IIi + OoOoOO00 * i1IIi / IiII
  if 4 - 4: oO0o % OoO0O00 + IiII + o0oOOo0O0Ooo
  if 82 - 82: O0 / I1Ii111 + OOooOOo . IiII + Ii1I
  if 31 - 31: i1IIi * OoO0O00 - Ii1I + I11i
  if 8 - 8: O0 + i1IIi . O0
  if 67 - 67: I1IiiI
  if 42 - 42: ooOoO0o - o0oOOo0O0Ooo % oO0o - ooOoO0o
  if 87 - 87: OoooooooOO / O0
  if 57 - 57: iIii1I11I1II1 / IiII + OoO0O00 * oO0o + Ii1I
  if 76 - 76: i11iIiiIii . OOooOOo / I11i * oO0o % iIii1I11I1II1 . ooOoO0o
  if 75 - 75: O0 + I1IiiI
  if 67 - 67: OoOoOO00 % OoooooooOO / OoO0O00 - OoO0O00 / O0
  if 19 - 19: iIii1I11I1II1 / OOooOOo % I11i % I1IiiI / I1ii11iIi11i
  if 73 - 73: II111iiii
  if 26 - 26: II111iiii . iIii1I11I1II1 - I1Ii111 % OOooOOo
  if 83 - 83: OOooOOo + OoooooooOO % I1Ii111 % IiII + i11iIiiIii
  if 10 - 10: OoooooooOO . Ii1I % I1Ii111 + IiII
 def lcaf_encode_iid ( self ) :
  I11i1 = LISP_LCAF_INSTANCE_ID_TYPE
  oooO00oo0 = socket . htons ( self . lcaf_length ( I11i1 ) )
  IIiI1i = self . instance_id
  ooo0O0O0oo0 = self . afi
  oOOoOO = 0
  if ( ooo0O0O0oo0 < 0 ) :
   if ( self . afi == LISP_AFI_GEO_COORD ) :
    ooo0O0O0oo0 = LISP_AFI_LCAF
    oOOoOO = 0
   else :
    ooo0O0O0oo0 = 0
    oOOoOO = self . mask_len
    if 78 - 78: OoOoOO00 - oO0o . I1ii11iIi11i * i11iIiiIii
    if 44 - 44: iIii1I11I1II1 * iII111i
    if 32 - 32: OoOoOO00
  oo00oOo = struct . pack ( "BBBBH" , 0 , 0 , I11i1 , oOOoOO , oooO00oo0 )
  oo00oOo += struct . pack ( "IH" , socket . htonl ( IIiI1i ) , socket . htons ( ooo0O0O0oo0 ) )
  if ( ooo0O0O0oo0 == 0 ) : return ( oo00oOo )
  if 39 - 39: OoOoOO00 - OoOoOO00
  if ( self . afi == LISP_AFI_GEO_COORD ) :
   oo00oOo = oo00oOo [ 0 : - 2 ]
   oo00oOo += self . address . encode_geo ( )
   return ( oo00oOo )
   if 35 - 35: OoooooooOO % iIii1I11I1II1 . OOooOOo
   if 33 - 33: OoooooooOO . IiII
  oo00oOo += self . pack_address ( )
  return ( oo00oOo )
  if 34 - 34: OoO0O00 * II111iiii + I1Ii111
  if 20 - 20: iIii1I11I1II1 . OoO0O00 . II111iiii / Ii1I - iIii1I11I1II1 / OOooOOo
 def lcaf_decode_iid ( self , packet ) :
  o0o0 = "BBBBH"
  O0ooO = struct . calcsize ( o0o0 )
  if ( len ( packet ) < O0ooO ) : return ( None )
  if 20 - 20: i11iIiiIii * oO0o * ooOoO0o
  Oo000 , Iiiii , I11i1 , OOoOO , i1IIiIIIi1 = struct . unpack ( o0o0 ,
 packet [ : O0ooO ] )
  packet = packet [ O0ooO : : ]
  if 35 - 35: OoO0O00 % OoO0O00 . I1Ii111 + O0 / I1IiiI * OoooooooOO
  if ( I11i1 != LISP_LCAF_INSTANCE_ID_TYPE ) : return ( None )
  if 76 - 76: iIii1I11I1II1
  o0o0 = "IH"
  O0ooO = struct . calcsize ( o0o0 )
  if ( len ( packet ) < O0ooO ) : return ( None )
  if 33 - 33: OOooOOo / I11i
  IIiI1i , ooo0O0O0oo0 = struct . unpack ( o0o0 , packet [ : O0ooO ] )
  packet = packet [ O0ooO : : ]
  if 83 - 83: I1ii11iIi11i % I1ii11iIi11i % ooOoO0o + OoOoOO00
  i1IIiIIIi1 = socket . ntohs ( i1IIiIIIi1 )
  self . instance_id = socket . ntohl ( IIiI1i )
  ooo0O0O0oo0 = socket . ntohs ( ooo0O0O0oo0 )
  self . afi = ooo0O0O0oo0
  if ( OOoOO != 0 and ooo0O0O0oo0 == 0 ) : self . mask_len = OOoOO
  if ( ooo0O0O0oo0 == 0 ) :
   self . afi = LISP_AFI_IID_RANGE if OOoOO else LISP_AFI_ULTIMATE_ROOT
   if 55 - 55: OoooooooOO / OoOoOO00 % Oo0Ooo * OoO0O00 . OoooooooOO . OOooOOo
   if 79 - 79: i11iIiiIii / ooOoO0o / i11iIiiIii - I1Ii111
   if 89 - 89: Oo0Ooo
   if 15 - 15: OOooOOo * II111iiii - OOooOOo * iIii1I11I1II1
   if 95 - 95: I1Ii111 / OoooooooOO * I11i * OoooooooOO
  if ( ooo0O0O0oo0 == 0 ) : return ( packet )
  if 88 - 88: I1IiiI / Oo0Ooo / oO0o + oO0o % OOooOOo + Oo0Ooo
  if 63 - 63: o0oOOo0O0Ooo + i11iIiiIii % OOooOOo % iIii1I11I1II1 / I1ii11iIi11i - iII111i
  if 72 - 72: iII111i % oO0o . IiII + I1ii11iIi11i . IiII . II111iiii
  if 10 - 10: I11i . ooOoO0o + I11i * Ii1I
  if ( self . is_dist_name ( ) ) :
   packet , self . address = lisp_decode_dist_name ( packet )
   self . mask_len = len ( self . address ) * 8
   return ( packet )
   if 55 - 55: OOooOOo / iII111i + OoooooooOO - OoooooooOO
   if 51 - 51: O0 % Ii1I % Oo0Ooo - O0
   if 94 - 94: OoooooooOO - ooOoO0o % I1ii11iIi11i + I1Ii111
   if 51 - 51: I1ii11iIi11i . iII111i / i1IIi * ooOoO0o % I11i
   if 82 - 82: O0 % OoOoOO00 . iII111i . i1IIi . iII111i - Oo0Ooo
  if ( ooo0O0O0oo0 == LISP_AFI_LCAF ) :
   o0o0 = "BBBBH"
   O0ooO = struct . calcsize ( o0o0 )
   if ( len ( packet ) < O0ooO ) : return ( None )
   if 58 - 58: O0 * OOooOOo
   OOooOo , I1i11Iii1I1I1 , I11i1 , IIi1ii1i1i1 , I1iIiI1iiI = struct . unpack ( o0o0 , packet [ : O0ooO ] )
   if 60 - 60: ooOoO0o
   if 47 - 47: i11iIiiIii
   if ( I11i1 != LISP_LCAF_GEO_COORD_TYPE ) : return ( None )
   if 21 - 21: i1IIi - oO0o - Oo0Ooo
   I1iIiI1iiI = socket . ntohs ( I1iIiI1iiI )
   packet = packet [ O0ooO : : ]
   if ( I1iIiI1iiI > len ( packet ) ) : return ( None )
   if 11 - 11: i1IIi
   ii1IiIiIii = lisp_geo ( "" )
   self . afi = LISP_AFI_GEO_COORD
   self . address = ii1IiIiIii
   packet = ii1IiIiIii . decode_geo ( packet , I1iIiI1iiI , IIi1ii1i1i1 )
   self . mask_len = self . host_mask_len ( )
   return ( packet )
   if 77 - 77: I11i + i1IIi * OoOoOO00 % OoooooooOO
   if 56 - 56: I1Ii111 * i1IIi % i11iIiiIii
  oooO00oo0 = self . addr_length ( )
  if ( len ( packet ) < oooO00oo0 ) : return ( None )
  if 56 - 56: Ii1I . iII111i
  packet = self . unpack_address ( packet )
  return ( packet )
  if 76 - 76: I1IiiI / Ii1I % OoOoOO00 + IiII / i11iIiiIii . o0oOOo0O0Ooo
  if 31 - 31: oO0o * oO0o % o0oOOo0O0Ooo . O0 + iII111i
  if 52 - 52: i11iIiiIii
  if 1 - 1: i1IIi * iIii1I11I1II1
  if 29 - 29: I11i
  if 12 - 12: oO0o % i1IIi - oO0o / ooOoO0o * II111iiii % ooOoO0o
  if 6 - 6: IiII / OoO0O00
  if 83 - 83: IiII - iIii1I11I1II1 * ooOoO0o - oO0o
  if 77 - 77: Ii1I
  if 9 - 9: OOooOOo / OoooooooOO + iII111i
  if 52 - 52: IiII / OOooOOo * iIii1I11I1II1 + o0oOOo0O0Ooo
  if 20 - 20: I1Ii111
  if 33 - 33: i11iIiiIii / I1Ii111 + IiII / II111iiii + I11i
  if 13 - 13: i1IIi % iII111i + OoOoOO00 / Ii1I . Ii1I + II111iiii
  if 44 - 44: OoOoOO00 / OoooooooOO % O0 * Ii1I * IiII
  if 84 - 84: o0oOOo0O0Ooo * IiII * OOooOOo * iII111i
  if 56 - 56: iII111i * II111iiii . OoooooooOO . I11i
  if 25 - 25: ooOoO0o % o0oOOo0O0Ooo - i11iIiiIii
  if 79 - 79: iII111i - I1IiiI % O0 / Oo0Ooo + OoOoOO00 . Oo0Ooo
  if 59 - 59: I1ii11iIi11i * OoOoOO00 / Ii1I
  if 80 - 80: IiII - ooOoO0o / OoOoOO00 / I11i * O0 + oO0o
 def lcaf_encode_sg ( self , group ) :
  I11i1 = LISP_LCAF_MCAST_INFO_TYPE
  IIiI1i = socket . htonl ( self . instance_id )
  oooO00oo0 = socket . htons ( self . lcaf_length ( I11i1 ) )
  oo00oOo = struct . pack ( "BBBBHIHBB" , 0 , 0 , I11i1 , 0 , oooO00oo0 , IIiI1i ,
 0 , self . mask_len , group . mask_len )
  if 77 - 77: ooOoO0o + I1ii11iIi11i * o0oOOo0O0Ooo / i1IIi * I11i
  oo00oOo += struct . pack ( "H" , socket . htons ( self . afi ) )
  oo00oOo += self . pack_address ( )
  oo00oOo += struct . pack ( "H" , socket . htons ( group . afi ) )
  oo00oOo += group . pack_address ( )
  return ( oo00oOo )
  if 70 - 70: oO0o / iII111i * i1IIi / II111iiii / OoOoOO00 + oO0o
  if 30 - 30: i1IIi - iII111i - i11iIiiIii . OoOoOO00 . o0oOOo0O0Ooo
 def lcaf_decode_sg ( self , packet ) :
  o0o0 = "BBBBHIHBB"
  O0ooO = struct . calcsize ( o0o0 )
  if ( len ( packet ) < O0ooO ) : return ( [ None , None ] )
  if 74 - 74: i11iIiiIii / II111iiii
  Oo000 , Iiiii , I11i1 , iii1II11II1 , i1IIiIIIi1 , IIiI1i , oOo , iII1I1 , o0O000 = struct . unpack ( o0o0 , packet [ : O0ooO ] )
  if 94 - 94: I1IiiI . iII111i - iIii1I11I1II1 . Oo0Ooo
  packet = packet [ O0ooO : : ]
  if 40 - 40: Ii1I
  if ( I11i1 != LISP_LCAF_MCAST_INFO_TYPE ) : return ( [ None , None ] )
  if 26 - 26: OoO0O00 / IiII
  self . instance_id = socket . ntohl ( IIiI1i )
  i1IIiIIIi1 = socket . ntohs ( i1IIiIIIi1 ) - 8
  if 31 - 31: Ii1I / OoO0O00 % ooOoO0o / I11i . I1ii11iIi11i
  if 41 - 41: I1ii11iIi11i * ooOoO0o * I11i + O0 * O0 - O0
  if 81 - 81: I1Ii111 % OoO0O00 / O0
  if 55 - 55: i1IIi - I1Ii111 + I11i
  if 93 - 93: I1IiiI % IiII . OoOoOO00 + iII111i
  o0o0 = "H"
  O0ooO = struct . calcsize ( o0o0 )
  if ( len ( packet ) < O0ooO ) : return ( [ None , None ] )
  if ( i1IIiIIIi1 < O0ooO ) : return ( [ None , None ] )
  if 81 - 81: ooOoO0o / I1Ii111 + OOooOOo / Oo0Ooo / OoOoOO00
  ooo0O0O0oo0 = struct . unpack ( o0o0 , packet [ : O0ooO ] ) [ 0 ]
  packet = packet [ O0ooO : : ]
  i1IIiIIIi1 -= O0ooO
  self . afi = socket . ntohs ( ooo0O0O0oo0 )
  self . mask_len = iII1I1
  oooO00oo0 = self . addr_length ( )
  if ( i1IIiIIIi1 < oooO00oo0 ) : return ( [ None , None ] )
  if 34 - 34: ooOoO0o * iIii1I11I1II1 % i11iIiiIii * OOooOOo - OOooOOo
  packet = self . unpack_address ( packet )
  if ( packet == None ) : return ( [ None , None ] )
  if 63 - 63: Oo0Ooo / oO0o + iII111i % OoooooooOO * I11i
  i1IIiIIIi1 -= oooO00oo0
  if 34 - 34: I1IiiI + I1Ii111 % ooOoO0o
  if 24 - 24: Ii1I % II111iiii - i11iIiiIii
  if 52 - 52: OoO0O00
  if 76 - 76: ooOoO0o - iII111i % ooOoO0o / oO0o . OOooOOo
  if 50 - 50: IiII . i11iIiiIii % I11i
  o0o0 = "H"
  O0ooO = struct . calcsize ( o0o0 )
  if ( len ( packet ) < O0ooO ) : return ( [ None , None ] )
  if ( i1IIiIIIi1 < O0ooO ) : return ( [ None , None ] )
  if 22 - 22: i1IIi - II111iiii - OoOoOO00 . iII111i
  ooo0O0O0oo0 = struct . unpack ( o0o0 , packet [ : O0ooO ] ) [ 0 ]
  packet = packet [ O0ooO : : ]
  i1IIiIIIi1 -= O0ooO
  oO0000O0o = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  oO0000O0o . afi = socket . ntohs ( ooo0O0O0oo0 )
  oO0000O0o . mask_len = o0O000
  oO0000O0o . instance_id = self . instance_id
  oooO00oo0 = self . addr_length ( )
  if ( i1IIiIIIi1 < oooO00oo0 ) : return ( [ None , None ] )
  if 43 - 43: I1Ii111 * OOooOOo - IiII . i11iIiiIii
  packet = oO0000O0o . unpack_address ( packet )
  if ( packet == None ) : return ( [ None , None ] )
  if 34 - 34: iII111i . OoOoOO00
  return ( [ packet , oO0000O0o ] )
  if 49 - 49: I1ii11iIi11i % oO0o - I1Ii111 . I1ii11iIi11i % II111iiii
  if 20 - 20: I1ii11iIi11i . iIii1I11I1II1 - Ii1I % OoO0O00
 def lcaf_decode_eid ( self , packet ) :
  o0o0 = "BBB"
  O0ooO = struct . calcsize ( o0o0 )
  if ( len ( packet ) < O0ooO ) : return ( [ None , None ] )
  if 27 - 27: iIii1I11I1II1 / I1Ii111 - I11i . OoO0O00 + ooOoO0o
  if 89 - 89: I1IiiI % I11i - OOooOOo
  if 71 - 71: OOooOOo % Oo0Ooo - o0oOOo0O0Ooo / I1Ii111 - O0 - oO0o
  if 10 - 10: I1IiiI
  if 17 - 17: i11iIiiIii % o0oOOo0O0Ooo . ooOoO0o
  iii1II11II1 , I1i11Iii1I1I1 , I11i1 = struct . unpack ( o0o0 ,
 packet [ : O0ooO ] )
  if 34 - 34: OoooooooOO / iII111i / O0
  if ( I11i1 == LISP_LCAF_INSTANCE_ID_TYPE ) :
   return ( [ self . lcaf_decode_iid ( packet ) , None ] )
  elif ( I11i1 == LISP_LCAF_MCAST_INFO_TYPE ) :
   packet , oO0000O0o = self . lcaf_decode_sg ( packet )
   return ( [ packet , oO0000O0o ] )
  elif ( I11i1 == LISP_LCAF_GEO_COORD_TYPE ) :
   o0o0 = "BBBBH"
   O0ooO = struct . calcsize ( o0o0 )
   if ( len ( packet ) < O0ooO ) : return ( None )
   if 75 - 75: I11i % OOooOOo - OoO0O00 * I11i * IiII
   OOooOo , I1i11Iii1I1I1 , I11i1 , IIi1ii1i1i1 , I1iIiI1iiI = struct . unpack ( o0o0 , packet [ : O0ooO ] )
   if 11 - 11: I1ii11iIi11i . O0 - iII111i * IiII . i1IIi . iII111i
   if 82 - 82: i1IIi * I11i * Ii1I - IiII . i11iIiiIii
   if ( I11i1 != LISP_LCAF_GEO_COORD_TYPE ) : return ( None )
   if 40 - 40: OOooOOo - OoooooooOO
   I1iIiI1iiI = socket . ntohs ( I1iIiI1iiI )
   packet = packet [ O0ooO : : ]
   if ( I1iIiI1iiI > len ( packet ) ) : return ( None )
   if 36 - 36: i1IIi % OoOoOO00 - i1IIi
   ii1IiIiIii = lisp_geo ( "" )
   self . instance_id = 0
   self . afi = LISP_AFI_GEO_COORD
   self . address = ii1IiIiIii
   packet = ii1IiIiIii . decode_geo ( packet , I1iIiI1iiI , IIi1ii1i1i1 )
   self . mask_len = self . host_mask_len ( )
   if 5 - 5: I1IiiI . I1IiiI % II111iiii - I1Ii111
  return ( [ packet , None ] )
  if 97 - 97: I11i . ooOoO0o
  if 87 - 87: oO0o / iIii1I11I1II1 - I11i + OoooooooOO
  if 79 - 79: I1ii11iIi11i * IiII . I1ii11iIi11i
  if 65 - 65: iII111i - Ii1I - II111iiii * O0 + I1ii11iIi11i . iIii1I11I1II1
  if 76 - 76: OoO0O00 * ooOoO0o
  if 32 - 32: O0 . oO0o * o0oOOo0O0Ooo . Ii1I + IiII
class lisp_elp_node ( ) :
 def __init__ ( self ) :
  self . address = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . probe = False
  self . strict = False
  self . eid = False
  self . we_are_last = False
  if 98 - 98: iII111i . II111iiii % O0
  if 43 - 43: OOooOOo % I1Ii111 . IiII % OoO0O00 + I1Ii111 % OoooooooOO
 def copy_elp_node ( self ) :
  I111I1IiI1i1 = lisp_elp_node ( )
  I111I1IiI1i1 . copy_address ( self . address )
  I111I1IiI1i1 . probe = self . probe
  I111I1IiI1i1 . strict = self . strict
  I111I1IiI1i1 . eid = self . eid
  I111I1IiI1i1 . we_are_last = self . we_are_last
  return ( I111I1IiI1i1 )
  if 17 - 17: OoooooooOO - i1IIi * I11i
  if 33 - 33: i1IIi . Oo0Ooo + I11i
  if 97 - 97: OOooOOo / IiII / ooOoO0o / OoooooooOO
class lisp_elp ( ) :
 def __init__ ( self , name ) :
  self . elp_name = name
  self . elp_nodes = [ ]
  self . use_elp_node = None
  self . we_are_last = False
  if 78 - 78: I1Ii111 + I1Ii111
  if 43 - 43: I1Ii111 * o0oOOo0O0Ooo + i1IIi
 def copy_elp ( self ) :
  IIi1I1iiiii = lisp_elp ( self . elp_name )
  IIi1I1iiiii . use_elp_node = self . use_elp_node
  IIi1I1iiiii . we_are_last = self . we_are_last
  for I111I1IiI1i1 in self . elp_nodes :
   IIi1I1iiiii . elp_nodes . append ( I111I1IiI1i1 . copy_elp_node ( ) )
   if 19 - 19: Ii1I
  return ( IIi1I1iiiii )
  if 51 - 51: oO0o
  if 57 - 57: i11iIiiIii - Oo0Ooo + I1Ii111 * OoO0O00
 def print_elp ( self , want_marker ) :
  IiIIii11 = ""
  for I111I1IiI1i1 in self . elp_nodes :
   iIIii1iiIi = ""
   if ( want_marker ) :
    if ( I111I1IiI1i1 == self . use_elp_node ) :
     iIIii1iiIi = "*"
    elif ( I111I1IiI1i1 . we_are_last ) :
     iIIii1iiIi = "x"
     if 54 - 54: OOooOOo
     if 67 - 67: I1IiiI . o0oOOo0O0Ooo / i1IIi * I1ii11iIi11i . Oo0Ooo + II111iiii
   IiIIii11 += "{}{}({}{}{}), " . format ( iIIii1iiIi ,
 I111I1IiI1i1 . address . print_address_no_iid ( ) ,
 "r" if I111I1IiI1i1 . eid else "R" , "P" if I111I1IiI1i1 . probe else "p" ,
 "S" if I111I1IiI1i1 . strict else "s" )
   if 63 - 63: OoOoOO00 - OoOoOO00
  return ( IiIIii11 [ 0 : - 2 ] if IiIIii11 != "" else "" )
  if 31 - 31: I1ii11iIi11i % O0 - i11iIiiIii * o0oOOo0O0Ooo . ooOoO0o * ooOoO0o
  if 18 - 18: OoO0O00 - OoO0O00 . o0oOOo0O0Ooo
 def select_elp_node ( self ) :
  O0o00o0 , O0Oooo0 , oOOOo0o = lisp_myrlocs
  OOOoO000 = None
  if 34 - 34: I1IiiI + i1IIi . II111iiii . O0
  for I111I1IiI1i1 in self . elp_nodes :
   if ( O0o00o0 and I111I1IiI1i1 . address . is_exact_match ( O0o00o0 ) ) :
    OOOoO000 = self . elp_nodes . index ( I111I1IiI1i1 )
    break
    if 86 - 86: oO0o . OoOoOO00 - I11i . OOooOOo % OoO0O00
   if ( O0Oooo0 and I111I1IiI1i1 . address . is_exact_match ( O0Oooo0 ) ) :
    OOOoO000 = self . elp_nodes . index ( I111I1IiI1i1 )
    break
    if 79 - 79: iII111i / Ii1I % i11iIiiIii . I1IiiI % OoO0O00 / i11iIiiIii
    if 100 - 100: OOooOOo + Oo0Ooo . iIii1I11I1II1 . ooOoO0o * Oo0Ooo
    if 16 - 16: Oo0Ooo % OoOoOO00 + I1Ii111 % I1Ii111
    if 12 - 12: I1Ii111 . Ii1I / iIii1I11I1II1 + i1IIi
    if 9 - 9: iIii1I11I1II1
    if 75 - 75: I11i . II111iiii * I1IiiI * IiII
    if 36 - 36: OOooOOo / I1ii11iIi11i / oO0o / ooOoO0o / I11i
  if ( OOOoO000 == None ) :
   self . use_elp_node = self . elp_nodes [ 0 ]
   I111I1IiI1i1 . we_are_last = False
   return
   if 7 - 7: OoO0O00 - I11i - o0oOOo0O0Ooo / o0oOOo0O0Ooo + i11iIiiIii
   if 28 - 28: OoOoOO00 % ooOoO0o . I1IiiI + II111iiii
   if 34 - 34: iIii1I11I1II1
   if 65 - 65: II111iiii - iII111i / o0oOOo0O0Ooo
   if 35 - 35: i11iIiiIii - Oo0Ooo . I1ii11iIi11i % OoOoOO00
   if 20 - 20: OoO0O00
  if ( self . elp_nodes [ - 1 ] == self . elp_nodes [ OOOoO000 ] ) :
   self . use_elp_node = None
   I111I1IiI1i1 . we_are_last = True
   return
   if 93 - 93: ooOoO0o + o0oOOo0O0Ooo - I1ii11iIi11i
   if 56 - 56: Ii1I / Oo0Ooo
   if 96 - 96: o0oOOo0O0Ooo . II111iiii
   if 14 - 14: OoooooooOO - i1IIi / i11iIiiIii - OOooOOo - i11iIiiIii . ooOoO0o
   if 8 - 8: oO0o * O0 - II111iiii + I1IiiI
  self . use_elp_node = self . elp_nodes [ OOOoO000 + 1 ]
  return
  if 85 - 85: OoooooooOO % i11iIiiIii / IiII % OoOoOO00 + O0
  if 6 - 6: OoooooooOO
  if 97 - 97: II111iiii + o0oOOo0O0Ooo * II111iiii
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
  if 17 - 17: o0oOOo0O0Ooo / ooOoO0o + i1IIi
  if 78 - 78: iIii1I11I1II1 * o0oOOo0O0Ooo * Oo0Ooo - OoO0O00 / OoO0O00
 def copy_geo ( self ) :
  ii1IiIiIii = lisp_geo ( self . geo_name )
  ii1IiIiIii . latitude = self . latitude
  ii1IiIiIii . lat_mins = self . lat_mins
  ii1IiIiIii . lat_secs = self . lat_secs
  ii1IiIiIii . longitude = self . longitude
  ii1IiIiIii . long_mins = self . long_mins
  ii1IiIiIii . long_secs = self . long_secs
  ii1IiIiIii . altitude = self . altitude
  ii1IiIiIii . radius = self . radius
  return ( ii1IiIiIii )
  if 89 - 89: o0oOOo0O0Ooo % o0oOOo0O0Ooo
  if 8 - 8: Ii1I % oO0o - o0oOOo0O0Ooo
 def no_geo_altitude ( self ) :
  return ( self . altitude == - 1 )
  if 14 - 14: OOooOOo * IiII
  if 15 - 15: o0oOOo0O0Ooo + OoooooooOO - OOooOOo - o0oOOo0O0Ooo . iIii1I11I1II1 / Ii1I
 def parse_geo_string ( self , geo_str ) :
  OOOoO000 = geo_str . find ( "]" )
  if ( OOOoO000 != - 1 ) : geo_str = geo_str [ OOOoO000 + 1 : : ]
  if 33 - 33: OoO0O00
  if 91 - 91: I11i % I11i % iII111i
  if 19 - 19: I11i / I11i + I1IiiI * OoO0O00 - iII111i . Oo0Ooo
  if 76 - 76: iII111i % OOooOOo / OoooooooOO . I1IiiI % OoO0O00 % i1IIi
  if 95 - 95: Oo0Ooo - O0 / I1ii11iIi11i . I1IiiI / o0oOOo0O0Ooo % OoOoOO00
  if ( geo_str . find ( "/" ) != - 1 ) :
   geo_str , IIiiIIIi1i = geo_str . split ( "/" )
   self . radius = int ( IIiiIIIi1i )
   if 55 - 55: IiII . o0oOOo0O0Ooo * OoOoOO00
   if 44 - 44: Ii1I % I1ii11iIi11i - OoOoOO00
  geo_str = geo_str . split ( "-" )
  if ( len ( geo_str ) < 8 ) : return ( False )
  if 38 - 38: I11i / I11i . I1ii11iIi11i - OoO0O00
  o0oOoooooo = geo_str [ 0 : 4 ]
  OoIii = geo_str [ 4 : 8 ]
  if 24 - 24: I1ii11iIi11i . Oo0Ooo - i11iIiiIii * i11iIiiIii - OoO0O00
  if 8 - 8: i11iIiiIii * OoOoOO00 . o0oOOo0O0Ooo
  if 27 - 27: I1ii11iIi11i + Ii1I % I1Ii111
  if 20 - 20: Oo0Ooo
  if ( len ( geo_str ) > 8 ) : self . altitude = int ( geo_str [ 8 ] )
  if 33 - 33: oO0o - OoOoOO00 - i11iIiiIii + I1Ii111 + iIii1I11I1II1
  if 2 - 2: OoooooooOO + IiII / iII111i . iIii1I11I1II1 * OoOoOO00
  if 84 - 84: OOooOOo
  if 68 - 68: I1Ii111
  self . latitude = int ( o0oOoooooo [ 0 ] )
  self . lat_mins = int ( o0oOoooooo [ 1 ] )
  self . lat_secs = int ( o0oOoooooo [ 2 ] )
  if ( o0oOoooooo [ 3 ] == "N" ) : self . latitude = - self . latitude
  if 92 - 92: oO0o * Ii1I / OoO0O00 % II111iiii
  if 54 - 54: oO0o + I11i - OoO0O00
  if 86 - 86: OoooooooOO
  if 51 - 51: i11iIiiIii
  self . longitude = int ( OoIii [ 0 ] )
  self . long_mins = int ( OoIii [ 1 ] )
  self . long_secs = int ( OoIii [ 2 ] )
  if ( OoIii [ 3 ] == "E" ) : self . longitude = - self . longitude
  return ( True )
  if 91 - 91: OOooOOo
  if 22 - 22: OoooooooOO + OoOoOO00 - Ii1I . iII111i / OoooooooOO / I1IiiI
 def print_geo ( self ) :
  OoO00Oo0 = "N" if self . latitude < 0 else "S"
  oOiII1i1 = "E" if self . longitude < 0 else "W"
  if 6 - 6: Oo0Ooo
  oOOO000Oo = "{}-{}-{}-{}-{}-{}-{}-{}" . format ( abs ( self . latitude ) ,
 self . lat_mins , self . lat_secs , OoO00Oo0 , abs ( self . longitude ) ,
 self . long_mins , self . long_secs , oOiII1i1 )
  if 9 - 9: Oo0Ooo - II111iiii - i1IIi - ooOoO0o / o0oOOo0O0Ooo * I1ii11iIi11i
  if ( self . no_geo_altitude ( ) == False ) :
   oOOO000Oo += "-" + str ( self . altitude )
   if 29 - 29: ooOoO0o
   if 65 - 65: i1IIi * ooOoO0o * I1IiiI
   if 36 - 36: o0oOOo0O0Ooo - Ii1I + O0 + OOooOOo
   if 11 - 11: I11i / OoooooooOO . I11i . II111iiii / oO0o - i11iIiiIii
   if 67 - 67: o0oOOo0O0Ooo . I1Ii111 % iIii1I11I1II1 / I1Ii111
  if ( self . radius != 0 ) : oOOO000Oo += "/{}" . format ( self . radius )
  return ( oOOO000Oo )
  if 18 - 18: I11i * ooOoO0o
  if 46 - 46: IiII
 def geo_url ( self ) :
  O0OoiI11Ii = os . getenv ( "LISP_GEO_ZOOM_LEVEL" )
  O0OoiI11Ii = "10" if ( O0OoiI11Ii == "" or O0OoiI11Ii . isdigit ( ) == False ) else O0OoiI11Ii
  ooIi11I11 , iI1I1i11i = self . dms_to_decimal ( )
  O0oOoOoOo0 = ( "http://maps.googleapis.com/maps/api/staticmap?center={},{}" + "&markers=color:blue%7Clabel:lisp%7C{},{}" + "&zoom={}&size=1024x1024&sensor=false" ) . format ( ooIi11I11 , iI1I1i11i , ooIi11I11 , iI1I1i11i ,
  # ooOoO0o / ooOoO0o - oO0o . I1ii11iIi11i + o0oOOo0O0Ooo
  # I1IiiI - OoO0O00 + II111iiii
 O0OoiI11Ii )
  return ( O0oOoOoOo0 )
  if 32 - 32: Oo0Ooo - II111iiii
  if 69 - 69: iII111i + I1ii11iIi11i
 def print_geo_url ( self ) :
  ii1IiIiIii = self . print_geo ( )
  if ( self . radius == 0 ) :
   O0oOoOoOo0 = self . geo_url ( )
   iIii1I1iII = "<a href='{}'>{}</a>" . format ( O0oOoOoOo0 , ii1IiIiIii )
  else :
   O0oOoOoOo0 = ii1IiIiIii . replace ( "/" , "-" )
   iIii1I1iII = "<a href='/lisp/geo-map/{}'>{}</a>" . format ( O0oOoOoOo0 , ii1IiIiIii )
   if 77 - 77: I1IiiI + O0 % iII111i / o0oOOo0O0Ooo
  return ( iIii1I1iII )
  if 67 - 67: Oo0Ooo % ooOoO0o - II111iiii / IiII . i11iIiiIii
  if 52 - 52: I1ii11iIi11i / I1Ii111 - iII111i * OoO0O00 * I1Ii111 * iII111i
 def dms_to_decimal ( self ) :
  ooO0Oo0O0oO , Iiiii1I , iI1iI = self . latitude , self . lat_mins , self . lat_secs
  iii11ii1 = float ( abs ( ooO0Oo0O0oO ) )
  iii11ii1 += float ( Iiiii1I * 60 + iI1iI ) / 3600
  if ( ooO0Oo0O0oO > 0 ) : iii11ii1 = - iii11ii1
  o0Oi1i = iii11ii1
  if 79 - 79: Oo0Ooo . IiII - I1ii11iIi11i * OoOoOO00
  ooO0Oo0O0oO , Iiiii1I , iI1iI = self . longitude , self . long_mins , self . long_secs
  iii11ii1 = float ( abs ( ooO0Oo0O0oO ) )
  iii11ii1 += float ( Iiiii1I * 60 + iI1iI ) / 3600
  if ( ooO0Oo0O0oO > 0 ) : iii11ii1 = - iii11ii1
  iI11iI1IIi1I1i1 = iii11ii1
  return ( ( o0Oi1i , iI11iI1IIi1I1i1 ) )
  if 95 - 95: OoOoOO00 + ooOoO0o . iIii1I11I1II1 * o0oOOo0O0Ooo
  if 75 - 75: OOooOOo - i11iIiiIii - i1IIi - IiII * iII111i
 def get_distance ( self , geo_point ) :
  iI1IIiII = self . dms_to_decimal ( )
  oOOo0OOo00 = geo_point . dms_to_decimal ( )
  I1111I = vincenty ( iI1IIiII , oOOo0OOo00 )
  return ( I1111I . km )
  if 60 - 60: oO0o * OoOoOO00 * OoOoOO00
  if 70 - 70: i11iIiiIii - I1IiiI * OoO0O00 % OOooOOo . i1IIi
 def point_in_circle ( self , geo_point ) :
  IiIi = self . get_distance ( geo_point )
  return ( IiIi <= self . radius )
  if 10 - 10: OoOoOO00 / iII111i - OoO0O00 + oO0o
  if 55 - 55: OoO0O00 / Ii1I % ooOoO0o . I1Ii111 * i1IIi . i11iIiiIii
 def encode_geo ( self ) :
  iio00OOO0o0Oo0 = socket . htons ( LISP_AFI_LCAF )
  IiiiIi1I = socket . htons ( 20 + 2 )
  I1i11Iii1I1I1 = 0
  if 34 - 34: I1ii11iIi11i % o0oOOo0O0Ooo % ooOoO0o * Ii1I * I1Ii111
  ooIi11I11 = abs ( self . latitude )
  O00O0o = ( ( self . lat_mins * 60 ) + self . lat_secs ) * 1000
  if ( self . latitude < 0 ) : I1i11Iii1I1I1 |= 0x40
  if 53 - 53: i11iIiiIii % I1ii11iIi11i
  iI1I1i11i = abs ( self . longitude )
  oO0OoOo0oo = ( ( self . long_mins * 60 ) + self . long_secs ) * 1000
  if ( self . longitude < 0 ) : I1i11Iii1I1I1 |= 0x20
  if 63 - 63: IiII + oO0o + II111iiii * I11i
  i1iIiIi = 0
  if ( self . no_geo_altitude ( ) == False ) :
   i1iIiIi = socket . htonl ( self . altitude )
   I1i11Iii1I1I1 |= 0x10
   if 21 - 21: I11i % oO0o . iIii1I11I1II1
  IIiiIIIi1i = socket . htons ( self . radius )
  if ( IIiiIIIi1i != 0 ) : I1i11Iii1I1I1 |= 0x06
  if 94 - 94: Ii1I % OoooooooOO * oO0o . OoooooooOO
  oo0O0Oo0OOoo = struct . pack ( "HBBBBH" , iio00OOO0o0Oo0 , 0 , 0 , LISP_LCAF_GEO_COORD_TYPE ,
 0 , IiiiIi1I )
  oo0O0Oo0OOoo += struct . pack ( "BBHBBHBBHIHHH" , I1i11Iii1I1I1 , 0 , 0 , ooIi11I11 , O00O0o >> 16 ,
 socket . htons ( O00O0o & 0x0ffff ) , iI1I1i11i , oO0OoOo0oo >> 16 ,
 socket . htons ( oO0OoOo0oo & 0xffff ) , i1iIiIi , IIiiIIIi1i , 0 , 0 )
  if 27 - 27: iII111i - IiII . OoOoOO00
  return ( oo0O0Oo0OOoo )
  if 8 - 8: I1Ii111 - iIii1I11I1II1 * iIii1I11I1II1 . I1ii11iIi11i
  if 65 - 65: i11iIiiIii
 def decode_geo ( self , packet , lcaf_len , radius_hi ) :
  o0o0 = "BBHBBHBBHIHHH"
  O0ooO = struct . calcsize ( o0o0 )
  if ( lcaf_len < O0ooO ) : return ( None )
  if 92 - 92: oO0o * II111iiii + I1Ii111
  I1i11Iii1I1I1 , Ii1Iii1111II , IIIIi , ooIi11I11 , oOoO , O00O0o , iI1I1i11i , iii11 , oO0OoOo0oo , i1iIiIi , IIiiIIIi1i , III , ooo0O0O0oo0 = struct . unpack ( o0o0 ,
  # OOooOOo % iII111i - oO0o
 packet [ : O0ooO ] )
  if 68 - 68: iII111i - O0 / Ii1I
  if 15 - 15: I1Ii111 / I1ii11iIi11i / I1IiiI % i11iIiiIii + II111iiii . ooOoO0o
  if 74 - 74: o0oOOo0O0Ooo
  if 4 - 4: I1ii11iIi11i * II111iiii - Oo0Ooo % i1IIi % O0 * i11iIiiIii
  ooo0O0O0oo0 = socket . ntohs ( ooo0O0O0oo0 )
  if ( ooo0O0O0oo0 == LISP_AFI_LCAF ) : return ( None )
  if 62 - 62: OoO0O00 * I1Ii111 * Ii1I / ooOoO0o
  if ( I1i11Iii1I1I1 & 0x40 ) : ooIi11I11 = - ooIi11I11
  self . latitude = ooIi11I11
  iIII1iIiI1i = ( ( oOoO << 16 ) | socket . ntohs ( O00O0o ) ) / 1000
  self . lat_mins = iIII1iIiI1i / 60
  self . lat_secs = iIII1iIiI1i % 60
  if 25 - 25: I1IiiI + iIii1I11I1II1 * Oo0Ooo - iIii1I11I1II1 % IiII * oO0o
  if ( I1i11Iii1I1I1 & 0x20 ) : iI1I1i11i = - iI1I1i11i
  self . longitude = iI1I1i11i
  Oo00o0O00o = ( ( iii11 << 16 ) | socket . ntohs ( oO0OoOo0oo ) ) / 1000
  self . long_mins = Oo00o0O00o / 60
  self . long_secs = Oo00o0O00o % 60
  if 22 - 22: OoooooooOO - OoO0O00 + OoOoOO00 - OOooOOo + i11iIiiIii - oO0o
  self . altitude = socket . ntohl ( i1iIiIi ) if ( I1i11Iii1I1I1 & 0x10 ) else - 1
  IIiiIIIi1i = socket . ntohs ( IIiiIIIi1i )
  self . radius = IIiiIIIi1i if ( I1i11Iii1I1I1 & 0x02 ) else IIiiIIIi1i * 1000
  if 9 - 9: I1Ii111 - i1IIi . ooOoO0o
  self . geo_name = None
  packet = packet [ O0ooO : : ]
  if 33 - 33: I11i
  if ( ooo0O0O0oo0 != 0 ) :
   self . rloc . afi = ooo0O0O0oo0
   packet = self . rloc . unpack_address ( packet )
   self . rloc . mask_len = self . rloc . host_mask_len ( )
   if 37 - 37: Oo0Ooo
  return ( packet )
  if 36 - 36: IiII % I11i
  if 72 - 72: oO0o % I11i % OOooOOo * iIii1I11I1II1 - OOooOOo % O0
  if 84 - 84: oO0o - o0oOOo0O0Ooo / II111iiii . o0oOOo0O0Ooo
  if 82 - 82: OoooooooOO
  if 14 - 14: OoO0O00 / oO0o - OOooOOo
  if 100 - 100: IiII - I11i . iIii1I11I1II1 / iIii1I11I1II1
class lisp_rle_node ( ) :
 def __init__ ( self ) :
  self . address = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . level = 0
  self . translated_port = 0
  self . rloc_name = None
  if 16 - 16: IiII + Oo0Ooo % I11i
  if 16 - 16: ooOoO0o / I1Ii111
 def copy_rle_node ( self ) :
  II1ii = lisp_rle_node ( )
  II1ii . address . copy_address ( self . address )
  II1ii . level = self . level
  II1ii . translated_port = self . translated_port
  II1ii . rloc_name = self . rloc_name
  return ( II1ii )
  if 78 - 78: OoOoOO00 - II111iiii - OOooOOo + I1IiiI + O0 / I1IiiI
  if 59 - 59: OOooOOo . I1IiiI / i1IIi / II111iiii . II111iiii
 def store_translated_rloc ( self , rloc , port ) :
  self . address . copy_address ( rloc )
  self . translated_port = port
  if 54 - 54: iIii1I11I1II1 % ooOoO0o
  if 37 - 37: OOooOOo % OoOoOO00 - II111iiii * o0oOOo0O0Ooo . I1IiiI . OoOoOO00
 def get_encap_keys ( self ) :
  II11i = "4341" if self . translated_port == 0 else str ( self . translated_port )
  if 92 - 92: I11i + OoO0O00 . OoooooooOO
  I11i11I = self . address . print_address_no_iid ( ) + ":" + II11i
  if 3 - 3: OoO0O00 % iIii1I11I1II1
  try :
   OOo = lisp_crypto_keys_by_rloc_encap [ I11i11I ]
   if ( OOo [ 1 ] ) : return ( OOo [ 1 ] . encrypt_key , OOo [ 1 ] . icv_key )
   return ( None , None )
  except :
   return ( None , None )
   if 62 - 62: OoooooooOO * o0oOOo0O0Ooo
   if 59 - 59: iIii1I11I1II1
   if 18 - 18: ooOoO0o % I1IiiI / iIii1I11I1II1 + O0
   if 99 - 99: i11iIiiIii - o0oOOo0O0Ooo + o0oOOo0O0Ooo . OoooooooOO * iII111i . Oo0Ooo
class lisp_rle ( ) :
 def __init__ ( self , name ) :
  self . rle_name = name
  self . rle_nodes = [ ]
  self . rle_forwarding_list = [ ]
  if 63 - 63: I11i
  if 60 - 60: I1IiiI / I1ii11iIi11i / I11i / Ii1I + iIii1I11I1II1
 def copy_rle ( self ) :
  oOIii11111iiI = lisp_rle ( self . rle_name )
  for II1ii in self . rle_nodes :
   oOIii11111iiI . rle_nodes . append ( II1ii . copy_rle_node ( ) )
   if 85 - 85: O0 / OOooOOo . OoOoOO00 / I1ii11iIi11i
  oOIii11111iiI . build_forwarding_list ( )
  return ( oOIii11111iiI )
  if 80 - 80: I1ii11iIi11i * iII111i % i1IIi * OOooOOo % II111iiii % i1IIi
  if 44 - 44: OoooooooOO
 def print_rle ( self , html ) :
  Ii1111IIIiiIi = ""
  for II1ii in self . rle_nodes :
   II11i = II1ii . translated_port
   iIi1ii = blue ( II1ii . rloc_name , html ) if II1ii . rloc_name != None else ""
   if 35 - 35: iIii1I11I1II1 - o0oOOo0O0Ooo + I1ii11iIi11i * iII111i - OOooOOo . o0oOOo0O0Ooo
   I11i11I = II1ii . address . print_address_no_iid ( )
   if ( II1ii . address . is_local ( ) ) : I11i11I = red ( I11i11I , html )
   Ii1111IIIiiIi += "{}{}(L{}){}, " . format ( I11i11I , "" if II11i == 0 else "-" + str ( II11i ) , II1ii . level ,
   # Oo0Ooo
 "" if II1ii . rloc_name == None else iIi1ii )
   if 79 - 79: IiII
  return ( Ii1111IIIiiIi [ 0 : - 2 ] if Ii1111IIIiiIi != "" else "" )
  if 42 - 42: ooOoO0o . I11i - ooOoO0o
  if 29 - 29: Ii1I . iIii1I11I1II1
 def build_forwarding_list ( self ) :
  i11i1i = - 1
  for II1ii in self . rle_nodes :
   if ( i11i1i == - 1 ) :
    if ( II1ii . address . is_local ( ) ) : i11i1i = II1ii . level
   else :
    if ( II1ii . level > i11i1i ) : break
    if 100 - 100: II111iiii / I11i * iIii1I11I1II1 / OOooOOo + i11iIiiIii - iIii1I11I1II1
    if 32 - 32: o0oOOo0O0Ooo - Ii1I / ooOoO0o % I1Ii111
  i11i1i = 0 if i11i1i == - 1 else II1ii . level
  if 69 - 69: oO0o - I1IiiI . OOooOOo * OoooooooOO
  self . rle_forwarding_list = [ ]
  for II1ii in self . rle_nodes :
   if ( II1ii . level == i11i1i or ( i11i1i == 0 and
 II1ii . level == 128 ) ) :
    if ( lisp_i_am_rtr == False and II1ii . address . is_local ( ) ) :
     I11i11I = II1ii . address . print_address_no_iid ( )
     lprint ( "Exclude local RLE RLOC {}" . format ( I11i11I ) )
     continue
     if 83 - 83: IiII % I1Ii111 % IiII - O0 % I1ii11iIi11i
    self . rle_forwarding_list . append ( II1ii )
    if 44 - 44: i11iIiiIii + oO0o * oO0o . i11iIiiIii % i1IIi + iII111i
    if 91 - 91: I1Ii111 . II111iiii / Ii1I * O0
    if 33 - 33: oO0o * i1IIi + ooOoO0o * OOooOOo - O0 - iIii1I11I1II1
    if 35 - 35: I1Ii111
    if 12 - 12: Ii1I % I1IiiI - I11i / iIii1I11I1II1 . I1IiiI % I1ii11iIi11i
class lisp_json ( ) :
 def __init__ ( self , name , string ) :
  self . json_name = name
  self . json_string = string
  if 12 - 12: Oo0Ooo + I1IiiI
  if 12 - 12: OoOoOO00 / II111iiii
 def add ( self ) :
  self . delete ( )
  lisp_json_list [ self . json_name ] = self
  if 100 - 100: I1ii11iIi11i % iIii1I11I1II1 . IiII . OoooooooOO / II111iiii
  if 28 - 28: I1IiiI
 def delete ( self ) :
  if ( lisp_json_list . has_key ( self . json_name ) ) :
   del ( lisp_json_list [ self . json_name ] )
   lisp_json_list [ self . json_name ] = None
   if 27 - 27: I1IiiI % oO0o - iIii1I11I1II1 - o0oOOo0O0Ooo - IiII - O0
   if 46 - 46: II111iiii
   if 24 - 24: i11iIiiIii * i1IIi - I11i + o0oOOo0O0Ooo
 def print_json ( self , html ) :
  oOoo0ooOOOO0o = self . json_string
  II1Iii11 = "***"
  if ( html ) : II1Iii11 = red ( II1Iii11 , html )
  OO0I11ii = II1Iii11 + self . json_string + II1Iii11
  if ( self . valid_json ( ) ) : return ( oOoo0ooOOOO0o )
  return ( OO0I11ii )
  if 35 - 35: I1ii11iIi11i % OoO0O00 - i11iIiiIii
  if 12 - 12: I1ii11iIi11i . Oo0Ooo + O0
 def valid_json ( self ) :
  try :
   json . loads ( self . json_string )
  except :
   return ( False )
   if 81 - 81: iII111i - Oo0Ooo . OoOoOO00 / Oo0Ooo - o0oOOo0O0Ooo + I1ii11iIi11i
  return ( True )
  if 9 - 9: OoO0O00 * I1IiiI % IiII
  if 97 - 97: o0oOOo0O0Ooo + Ii1I
  if 77 - 77: I11i - oO0o . Ii1I
  if 75 - 75: I11i * OoooooooOO % OoOoOO00 . i1IIi - Ii1I + iIii1I11I1II1
  if 74 - 74: ooOoO0o
  if 18 - 18: iIii1I11I1II1 - I11i - oO0o
class lisp_stats ( ) :
 def __init__ ( self ) :
  self . packet_count = 0
  self . byte_count = 0
  self . last_rate_check = 0
  self . last_packet_count = 0
  self . last_byte_count = 0
  self . last_increment = None
  if 12 - 12: O0 + O0 + ooOoO0o . I1IiiI * II111iiii
  if 47 - 47: i11iIiiIii % OOooOOo / ooOoO0o . IiII - I1IiiI
 def increment ( self , octets ) :
  self . packet_count += 1
  self . byte_count += octets
  self . last_increment = lisp_get_timestamp ( )
  if 10 - 10: Oo0Ooo / ooOoO0o / I1ii11iIi11i
  if 98 - 98: O0 - I1Ii111 - i11iIiiIii
 def recent_packet_sec ( self ) :
  if ( self . last_increment == None ) : return ( False )
  ooooOoO0O = time . time ( ) - self . last_increment
  return ( ooooOoO0O <= 1 )
  if 85 - 85: II111iiii - I1ii11iIi11i % I1IiiI . I1IiiI - OoooooooOO - I11i
  if 38 - 38: i1IIi + oO0o * ooOoO0o % Ii1I % ooOoO0o
 def recent_packet_min ( self ) :
  if ( self . last_increment == None ) : return ( False )
  ooooOoO0O = time . time ( ) - self . last_increment
  return ( ooooOoO0O <= 60 )
  if 80 - 80: OoO0O00 + OoOoOO00 % iII111i % OoooooooOO - ooOoO0o
  if 25 - 25: OoOoOO00 % i11iIiiIii - I1IiiI * iIii1I11I1II1 - Oo0Ooo . O0
 def stat_colors ( self , c1 , c2 , html ) :
  if ( self . recent_packet_sec ( ) ) :
   return ( green_last_sec ( c1 ) , green_last_sec ( c2 ) )
   if 48 - 48: I1IiiI + oO0o % i11iIiiIii % iIii1I11I1II1
  if ( self . recent_packet_min ( ) ) :
   return ( green_last_min ( c1 ) , green_last_min ( c2 ) )
   if 14 - 14: iIii1I11I1II1
  return ( c1 , c2 )
  if 78 - 78: I1Ii111 / Oo0Ooo - I1Ii111
  if 1 - 1: OoO0O00 - I1IiiI * o0oOOo0O0Ooo
 def normalize ( self , count ) :
  count = str ( count )
  oOoOooO0o00 = len ( count )
  if ( oOoOooO0o00 > 12 ) :
   count = count [ 0 : - 10 ] + "." + count [ - 10 : - 7 ] + "T"
   return ( count )
   if 85 - 85: i1IIi
  if ( oOoOooO0o00 > 9 ) :
   count = count [ 0 : - 9 ] + "." + count [ - 9 : - 7 ] + "B"
   return ( count )
   if 78 - 78: oO0o
  if ( oOoOooO0o00 > 6 ) :
   count = count [ 0 : - 6 ] + "." + count [ - 6 ] + "M"
   return ( count )
   if 6 - 6: IiII
  return ( count )
  if 69 - 69: iII111i
  if 87 - 87: i11iIiiIii % o0oOOo0O0Ooo + Ii1I
 def get_stats ( self , summary , html ) :
  o0Ooo00OOo = self . last_rate_check
  I1iIIii1 = self . last_packet_count
  oO0OoO = self . last_byte_count
  self . last_rate_check = lisp_get_timestamp ( )
  self . last_packet_count = self . packet_count
  self . last_byte_count = self . byte_count
  if 72 - 72: O0 . Ii1I
  OoO00 = self . last_rate_check - o0Ooo00OOo
  if ( OoO00 == 0 ) :
   o0000 = 0
   oO0ooOo0o0OOOOO = 0
  else :
   o0000 = int ( ( self . packet_count - I1iIIii1 ) / OoO00 )
   oO0ooOo0o0OOOOO = ( self . byte_count - oO0OoO ) / OoO00
   oO0ooOo0o0OOOOO = ( oO0ooOo0o0OOOOO * 8 ) / 1000000
   oO0ooOo0o0OOOOO = round ( oO0ooOo0o0OOOOO , 2 )
   if 59 - 59: i1IIi . iIii1I11I1II1 + I11i + I1IiiI . Oo0Ooo
   if 98 - 98: ooOoO0o . Oo0Ooo + iII111i * OoooooooOO % ooOoO0o
   if 5 - 5: II111iiii
   if 18 - 18: O0 * ooOoO0o
   if 32 - 32: OoooooooOO - ooOoO0o % O0 + oO0o - OoooooooOO - O0
  ii1i1I1ii1Iii = self . normalize ( self . packet_count )
  O0OOooOo00OooOoO = self . normalize ( self . byte_count )
  if 83 - 83: OoO0O00 - i11iIiiIii + I1ii11iIi11i - OOooOOo / OoOoOO00 / I11i
  if 53 - 53: I11i * I1IiiI . I1IiiI / o0oOOo0O0Ooo - I1Ii111
  if 50 - 50: I11i - OoOoOO00 + I1IiiI % Oo0Ooo / OoooooooOO - I1ii11iIi11i
  if 26 - 26: IiII . Ii1I
  if 35 - 35: I1ii11iIi11i + OOooOOo
  if ( summary ) :
   ooO0oooOo = "<br>" if html else ""
   ii1i1I1ii1Iii , O0OOooOo00OooOoO = self . stat_colors ( ii1i1I1ii1Iii , O0OOooOo00OooOoO , html )
   II11I = "packet-count: {}{}byte-count: {}" . format ( ii1i1I1ii1Iii , ooO0oooOo , O0OOooOo00OooOoO )
   O00o0O0 = "packet-rate: {} pps\nbit-rate: {} Mbps" . format ( o0000 , oO0ooOo0o0OOOOO )
   if 53 - 53: oO0o + I1IiiI * O0 * iIii1I11I1II1 / Oo0Ooo
   if ( html != "" ) : O00o0O0 = lisp_span ( II11I , O00o0O0 )
  else :
   Ii1iiiII1Ii1iI = str ( o0000 )
   iIiIIiii111I1 = str ( oO0ooOo0o0OOOOO )
   if ( html ) :
    ii1i1I1ii1Iii = lisp_print_cour ( ii1i1I1ii1Iii )
    Ii1iiiII1Ii1iI = lisp_print_cour ( Ii1iiiII1Ii1iI )
    O0OOooOo00OooOoO = lisp_print_cour ( O0OOooOo00OooOoO )
    iIiIIiii111I1 = lisp_print_cour ( iIiIIiii111I1 )
    if 22 - 22: OoOoOO00 * IiII . i1IIi - Oo0Ooo + OoOoOO00 . ooOoO0o
   ooO0oooOo = "<br>" if html else ", "
   if 95 - 95: O0 % oO0o - o0oOOo0O0Ooo * OoooooooOO
   O00o0O0 = ( "packet-count: {}{}packet-rate: {} pps{}byte-count: " + "{}{}bit-rate: {} mbps" ) . format ( ii1i1I1ii1Iii , ooO0oooOo , Ii1iiiII1Ii1iI , ooO0oooOo , O0OOooOo00OooOoO , ooO0oooOo ,
   # O0 - i1IIi * I1IiiI * oO0o + oO0o / I1IiiI
 iIiIIiii111I1 )
   if 2 - 2: o0oOOo0O0Ooo
  return ( O00o0O0 )
  if 35 - 35: iIii1I11I1II1 / I1IiiI * oO0o % OoOoOO00 . I1Ii111
  if 76 - 76: IiII % i1IIi / iIii1I11I1II1 - II111iiii * IiII + ooOoO0o
  if 9 - 9: oO0o / OOooOOo + II111iiii . i1IIi % I1IiiI / I1IiiI
  if 1 - 1: iIii1I11I1II1
  if 8 - 8: o0oOOo0O0Ooo % II111iiii * O0 . ooOoO0o
  if 96 - 96: I1ii11iIi11i / I11i - I1ii11iIi11i . I1Ii111 . i11iIiiIii . I11i
  if 93 - 93: OoO0O00 % I1ii11iIi11i * Ii1I . OoO0O00 % OOooOOo - OoooooooOO
  if 17 - 17: O0 + OOooOOo * ooOoO0o - i1IIi + OOooOOo
lisp_decap_stats = {
 "good-packets" : lisp_stats ( ) , "ICV-error" : lisp_stats ( ) ,
 "checksum-error" : lisp_stats ( ) , "lisp-header-error" : lisp_stats ( ) ,
 "no-decrypt-key" : lisp_stats ( ) , "bad-inner-version" : lisp_stats ( ) ,
 "outer-header-error" : lisp_stats ( )
 }
if 30 - 30: OOooOOo / I1ii11iIi11i - iIii1I11I1II1 % i1IIi
if 34 - 34: I1IiiI . II111iiii
if 100 - 100: OoO0O00 / O0 / OoOoOO00
if 33 - 33: i1IIi / o0oOOo0O0Ooo . OoooooooOO
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
  if 8 - 8: I1IiiI * OOooOOo * IiII / I1IiiI + i1IIi
  if ( recurse == False ) : return
  if 11 - 11: I11i * Ii1I * I1IiiI - I1IiiI % OoooooooOO
  if 83 - 83: i11iIiiIii % iII111i * O0 % OoooooooOO
  if 99 - 99: I1ii11iIi11i % I1ii11iIi11i * iII111i % oO0o
  if 56 - 56: Oo0Ooo + i11iIiiIii - oO0o . Ii1I + IiII
  if 19 - 19: I11i * OoooooooOO . i1IIi
  if 100 - 100: II111iiii
  o0oOOo000o0 = lisp_get_default_route_next_hops ( )
  if ( o0oOOo000o0 == [ ] or len ( o0oOOo000o0 ) == 1 ) : return
  if 89 - 89: OoooooooOO + iII111i - I1Ii111 . I1ii11iIi11i
  self . rloc_next_hop = o0oOOo000o0 [ 0 ]
  O00oo0o0o0oo = self
  for O0Oo0OO in o0oOOo000o0 [ 1 : : ] :
   OOI1IIi = lisp_rloc ( False )
   OOI1IIi = copy . deepcopy ( self )
   OOI1IIi . rloc_next_hop = O0Oo0OO
   O00oo0o0o0oo . next_rloc = OOI1IIi
   O00oo0o0o0oo = OOI1IIi
   if 77 - 77: i11iIiiIii . Ii1I - Ii1I
   if 47 - 47: iII111i % OOooOOo . I1ii11iIi11i + I1ii11iIi11i . I1Ii111
   if 20 - 20: oO0o - o0oOOo0O0Ooo + I1IiiI % OoOoOO00
 def up_state ( self ) :
  return ( self . state == LISP_RLOC_UP_STATE )
  if 41 - 41: oO0o . ooOoO0o
  if 59 - 59: iIii1I11I1II1 - I1IiiI . ooOoO0o
 def unreach_state ( self ) :
  return ( self . state == LISP_RLOC_UNREACH_STATE )
  if 58 - 58: I1IiiI * I1Ii111 + iII111i + iIii1I11I1II1 + I1IiiI
  if 78 - 78: Oo0Ooo + ooOoO0o
 def no_echoed_nonce_state ( self ) :
  return ( self . state == LISP_RLOC_NO_ECHOED_NONCE_STATE )
  if 56 - 56: OoO0O00 / i1IIi + ooOoO0o . ooOoO0o . iII111i
  if 37 - 37: iIii1I11I1II1 * OoOoOO00 . OoOoOO00 + OoooooooOO + OoO0O00
 def down_state ( self ) :
  return ( self . state in [ LISP_RLOC_DOWN_STATE , LISP_RLOC_ADMIN_DOWN_STATE ] )
  if 25 - 25: I1IiiI / IiII . OOooOOo . I1ii11iIi11i % i1IIi
  if 12 - 12: O0 % O0
  if 9 - 9: O0 . I1IiiI + I1ii11iIi11i / OOooOOo * I1ii11iIi11i
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
  if 10 - 10: IiII % o0oOOo0O0Ooo / O0 / II111iiii
  if 81 - 81: Ii1I / o0oOOo0O0Ooo % OoOoOO00 . I1ii11iIi11i
 def print_rloc ( self , indent ) :
  III11I1 = lisp_print_elapsed ( self . uptime )
  lprint ( "{}rloc {}, uptime {}, {}, parms {}/{}/{}/{}" . format ( indent ,
 red ( self . rloc . print_address ( ) , False ) , III11I1 , self . print_state ( ) ,
 self . priority , self . weight , self . mpriority , self . mweight ) )
  if 47 - 47: II111iiii + OOooOOo / II111iiii . OOooOOo
  if 68 - 68: OoooooooOO
 def print_rloc_name ( self , cour = False ) :
  if ( self . rloc_name == None ) : return ( "" )
  iIIiii = self . rloc_name
  if ( cour ) : iIIiii = lisp_print_cour ( iIIiii )
  return ( 'rloc-name: {}' . format ( blue ( iIIiii , cour ) ) )
  if 63 - 63: I1IiiI
  if 80 - 80: oO0o + iIii1I11I1II1
 def store_rloc_from_record ( self , rloc_record , nonce , source ) :
  II11i = LISP_DATA_PORT
  self . rloc . copy_address ( rloc_record . rloc )
  self . rloc_name = rloc_record . rloc_name
  if 87 - 87: I1ii11iIi11i % Ii1I . Ii1I
  if 71 - 71: OoO0O00 - IiII . i1IIi * I1IiiI % I11i
  if 36 - 36: IiII * OoooooooOO . i11iIiiIii * i1IIi
  if 52 - 52: IiII + ooOoO0o - II111iiii - OoooooooOO * OoO0O00 - iIii1I11I1II1
  II1iIiIiIIi = self . rloc
  if ( II1iIiIiIIi . is_null ( ) == False ) :
   Ii1i111Iii = lisp_get_nat_info ( II1iIiIiIIi , self . rloc_name )
   if ( Ii1i111Iii ) :
    II11i = Ii1i111Iii . port
    iIi1i1iI1i1i = lisp_nat_state_info [ self . rloc_name ] [ 0 ]
    I11i11I = II1iIiIiIIi . print_address_no_iid ( )
    IIII1i = red ( I11i11I , False )
    ooOoO0OOOO = "" if self . rloc_name == None else blue ( self . rloc_name , False )
    if 21 - 21: ooOoO0o . o0oOOo0O0Ooo . oO0o . i1IIi
    if 96 - 96: Ii1I % I11i * OoooooooOO . I1IiiI . iIii1I11I1II1
    if 8 - 8: O0 + o0oOOo0O0Ooo / O0 - I1ii11iIi11i % I1ii11iIi11i
    if 55 - 55: OoooooooOO * OoooooooOO % I1Ii111 / Ii1I / ooOoO0o
    if 12 - 12: i11iIiiIii + Ii1I % iIii1I11I1II1 + I1Ii111
    if 12 - 12: Ii1I + I1Ii111 / O0 * II111iiii
    if ( Ii1i111Iii . timed_out ( ) ) :
     lprint ( ( "    Matched stored NAT state timed out for " + "RLOC {}:{}, {}" ) . format ( IIII1i , II11i , ooOoO0OOOO ) )
     if 67 - 67: iIii1I11I1II1 / I11i + ooOoO0o * I1Ii111 * oO0o
     if 100 - 100: OoooooooOO % I1IiiI / OoOoOO00 % OoOoOO00 . o0oOOo0O0Ooo
     Ii1i111Iii = None if ( Ii1i111Iii == iIi1i1iI1i1i ) else iIi1i1iI1i1i
     if ( Ii1i111Iii and Ii1i111Iii . timed_out ( ) ) :
      II11i = Ii1i111Iii . port
      IIII1i = red ( Ii1i111Iii . address , False )
      lprint ( ( "    Youngest stored NAT state timed out " + " for RLOC {}:{}, {}" ) . format ( IIII1i , II11i ,
      # o0oOOo0O0Ooo - OoO0O00 % i1IIi / Ii1I % IiII
 ooOoO0OOOO ) )
      Ii1i111Iii = None
      if 100 - 100: oO0o . i11iIiiIii - ooOoO0o
      if 49 - 49: Oo0Ooo % ooOoO0o % o0oOOo0O0Ooo + ooOoO0o * I1Ii111 % I1IiiI
      if 85 - 85: i1IIi / i1IIi
      if 77 - 77: i1IIi . ooOoO0o % ooOoO0o - Ii1I
      if 6 - 6: OOooOOo % Ii1I + ooOoO0o
      if 17 - 17: iIii1I11I1II1 * I1Ii111 % oO0o + o0oOOo0O0Ooo . Ii1I * Oo0Ooo
      if 16 - 16: I1IiiI % OoO0O00 . ooOoO0o / OoooooooOO
    if ( Ii1i111Iii ) :
     if ( Ii1i111Iii . address != I11i11I ) :
      lprint ( "RLOC conflict, RLOC-record {}, NAT state {}" . format ( IIII1i , red ( Ii1i111Iii . address , False ) ) )
      if 8 - 8: I1Ii111 % OoO0O00 . I1IiiI - OoOoOO00 + i1IIi / iIii1I11I1II1
      self . rloc . store_address ( Ii1i111Iii . address )
      if 89 - 89: II111iiii / Ii1I % Ii1I
     IIII1i = red ( Ii1i111Iii . address , False )
     II11i = Ii1i111Iii . port
     lprint ( "    Use NAT translated RLOC {}:{} for {}" . format ( IIII1i , II11i , ooOoO0OOOO ) )
     if 57 - 57: I11i
     self . store_translated_rloc ( II1iIiIiIIi , II11i )
     if 95 - 95: OoOoOO00 + I11i * i1IIi - ooOoO0o % ooOoO0o
     if 58 - 58: OOooOOo
     if 74 - 74: i1IIi . IiII / ooOoO0o + I11i % i11iIiiIii % iII111i
     if 62 - 62: i1IIi % I1Ii111
  self . geo = rloc_record . geo
  self . elp = rloc_record . elp
  self . json = rloc_record . json
  if 94 - 94: i1IIi + iII111i
  if 25 - 25: I1Ii111 . Ii1I - Ii1I . o0oOOo0O0Ooo - IiII
  if 91 - 91: o0oOOo0O0Ooo % I1ii11iIi11i % OoOoOO00 * iIii1I11I1II1
  if 18 - 18: OoOoOO00 * I1ii11iIi11i . i1IIi * iII111i
  self . rle = rloc_record . rle
  if ( self . rle ) :
   for II1ii in self . rle . rle_nodes :
    iIIiii = II1ii . rloc_name
    Ii1i111Iii = lisp_get_nat_info ( II1ii . address , iIIiii )
    if ( Ii1i111Iii == None ) : continue
    if 67 - 67: IiII + i11iIiiIii . II111iiii / OoOoOO00 + OoooooooOO + i11iIiiIii
    II11i = Ii1i111Iii . port
    O0oo0o0oO = iIIiii
    if ( O0oo0o0oO ) : O0oo0o0oO = blue ( iIIiii , False )
    if 23 - 23: Oo0Ooo
    lprint ( ( "      Store translated encap-port {} for RLE-" + "node {}, rloc-name '{}'" ) . format ( II11i ,
    # I1ii11iIi11i
 II1ii . address . print_address_no_iid ( ) , O0oo0o0oO ) )
    II1ii . translated_port = II11i
    if 26 - 26: oO0o . I1Ii111 % I11i
    if 85 - 85: II111iiii / o0oOOo0O0Ooo . iIii1I11I1II1 . OoooooooOO / Ii1I
    if 18 - 18: i11iIiiIii + o0oOOo0O0Ooo . i11iIiiIii
  self . priority = rloc_record . priority
  self . mpriority = rloc_record . mpriority
  self . weight = rloc_record . weight
  self . mweight = rloc_record . mweight
  if ( rloc_record . reach_bit and rloc_record . local_bit and
 rloc_record . probe_bit == False ) : self . state = LISP_RLOC_UP_STATE
  if 50 - 50: IiII / OoooooooOO . I11i
  if 93 - 93: OOooOOo / OoooooooOO % iII111i % Ii1I / I1Ii111 % OOooOOo
  if 25 - 25: i1IIi % Oo0Ooo . i1IIi * OoOoOO00 . Ii1I % OoO0O00
  if 47 - 47: o0oOOo0O0Ooo - i11iIiiIii / OoooooooOO
  Oo0o0oOOoO00O = source . is_exact_match ( rloc_record . rloc ) if source != None else None
  if 49 - 49: ooOoO0o / oO0o % I1ii11iIi11i
  if ( rloc_record . keys != None and Oo0o0oOOoO00O ) :
   OOoOoO = rloc_record . keys [ 1 ]
   if ( OOoOoO != None ) :
    I11i11I = rloc_record . rloc . print_address_no_iid ( ) + ":" + str ( II11i )
    if 77 - 77: Ii1I / Ii1I / I1ii11iIi11i
    OOoOoO . add_key_by_rloc ( I11i11I , True )
    lprint ( "    Store encap-keys for nonce 0x{}, RLOC {}" . format ( lisp_hex_string ( nonce ) , red ( I11i11I , False ) ) )
    if 92 - 92: O0 * i11iIiiIii . OoOoOO00 * IiII / o0oOOo0O0Ooo * ooOoO0o
    if 74 - 74: O0 - o0oOOo0O0Ooo
    if 68 - 68: I1Ii111
  return ( II11i )
  if 19 - 19: o0oOOo0O0Ooo
  if 63 - 63: OoooooooOO % ooOoO0o
 def store_translated_rloc ( self , rloc , port ) :
  self . rloc . copy_address ( rloc )
  self . translated_rloc . copy_address ( rloc )
  self . translated_port = port
  if 26 - 26: OOooOOo + Oo0Ooo
  if 97 - 97: I1Ii111 * I1Ii111 + iII111i % Ii1I / iII111i
 def is_rloc_translated ( self ) :
  return ( self . translated_rloc . is_null ( ) == False )
  if 73 - 73: OoOoOO00 % I1Ii111 . I1ii11iIi11i
  if 45 - 45: iIii1I11I1II1 % Ii1I . OoOoOO00 . o0oOOo0O0Ooo - OoooooooOO
 def rloc_exists ( self ) :
  if ( self . rloc . is_null ( ) == False ) : return ( True )
  if ( self . rle_name or self . geo_name or self . elp_name or self . json_name ) :
   return ( False )
   if 46 - 46: I1ii11iIi11i
  return ( True )
  if 32 - 32: iII111i * i11iIiiIii / IiII + i11iIiiIii + O0
  if 51 - 51: I1Ii111
 def is_rtr ( self ) :
  return ( ( self . priority == 254 and self . mpriority == 255 and self . weight == 0 and self . mweight == 0 ) )
  if 95 - 95: Ii1I / Ii1I * OoO0O00 . OoooooooOO . OoooooooOO * I11i
  if 76 - 76: OoooooooOO - Ii1I + IiII % OoOoOO00 / OoooooooOO
  if 55 - 55: i11iIiiIii - IiII * OOooOOo + II111iiii . I1ii11iIi11i / O0
 def print_state_change ( self , new_state ) :
  Ii1iIIi1IIiIi1I = self . print_state ( )
  iIii1I1iII = "{} -> {}" . format ( Ii1iIIi1IIiIi1I , new_state )
  if ( new_state == "up" and self . unreach_state ( ) ) :
   iIii1I1iII = bold ( iIii1I1iII , False )
   if 22 - 22: o0oOOo0O0Ooo * o0oOOo0O0Ooo % I1IiiI
  return ( iIii1I1iII )
  if 66 - 66: OoOoOO00 % ooOoO0o - II111iiii . oO0o / i11iIiiIii
  if 73 - 73: OoO0O00 - i1IIi
 def print_rloc_probe_rtt ( self ) :
  if ( self . rloc_probe_rtt == - 1 ) : return ( "none" )
  return ( self . rloc_probe_rtt )
  if 52 - 52: I1ii11iIi11i
  if 4 - 4: Ii1I - iII111i + i1IIi - I1Ii111 / iII111i . Oo0Ooo
 def print_recent_rloc_probe_rtts ( self ) :
  iIIi1I1Iiii = str ( self . recent_rloc_probe_rtts )
  iIIi1I1Iiii = iIIi1I1Iiii . replace ( "-1" , "?" )
  return ( iIIi1I1Iiii )
  if 62 - 62: OOooOOo % OoooooooOO * Oo0Ooo + OOooOOo * Oo0Ooo - I1IiiI
  if 2 - 2: I1IiiI + II111iiii . ooOoO0o + oO0o . OoO0O00
 def compute_rloc_probe_rtt ( self ) :
  O00oo0o0o0oo = self . rloc_probe_rtt
  self . rloc_probe_rtt = - 1
  if ( self . last_rloc_probe_reply == None ) : return
  if ( self . last_rloc_probe == None ) : return
  self . rloc_probe_rtt = self . last_rloc_probe_reply - self . last_rloc_probe
  self . rloc_probe_rtt = round ( self . rloc_probe_rtt , 3 )
  iIoOo0OoOO = self . recent_rloc_probe_rtts
  self . recent_rloc_probe_rtts = [ O00oo0o0o0oo ] + iIoOo0OoOO [ 0 : - 1 ]
  if 86 - 86: i1IIi
  if 73 - 73: iIii1I11I1II1 * Oo0Ooo
 def print_rloc_probe_hops ( self ) :
  return ( self . rloc_probe_hops )
  if 54 - 54: oO0o . Ii1I
  if 31 - 31: I11i
 def print_recent_rloc_probe_hops ( self ) :
  OOo00oo0o = str ( self . recent_rloc_probe_hops )
  return ( OOo00oo0o )
  if 18 - 18: i1IIi
  if 33 - 33: iIii1I11I1II1 % ooOoO0o - I1Ii111
 def store_rloc_probe_hops ( self , to_hops , from_ttl ) :
  if ( to_hops == 0 ) :
   to_hops = "?"
  elif ( to_hops < LISP_RLOC_PROBE_TTL / 2 ) :
   to_hops = "!"
  else :
   to_hops = str ( LISP_RLOC_PROBE_TTL - to_hops )
   if 9 - 9: I1Ii111 / OoO0O00 - OoO0O00
  if ( from_ttl < LISP_RLOC_PROBE_TTL / 2 ) :
   IIi1 = "!"
  else :
   IIi1 = str ( LISP_RLOC_PROBE_TTL - from_ttl )
   if 85 - 85: iIii1I11I1II1 % Oo0Ooo
   if 20 - 20: IiII + i11iIiiIii * OOooOOo
  O00oo0o0o0oo = self . rloc_probe_hops
  self . rloc_probe_hops = to_hops + "/" + IIi1
  iIoOo0OoOO = self . recent_rloc_probe_hops
  self . recent_rloc_probe_hops = [ O00oo0o0o0oo ] + iIoOo0OoOO [ 0 : - 1 ]
  if 27 - 27: O0 * OoO0O00 * I1ii11iIi11i
  if 40 - 40: O0 + oO0o - ooOoO0o + I1IiiI - IiII
 def process_rloc_probe_reply ( self , nonce , eid , group , hop_count , ttl ) :
  II1iIiIiIIi = self
  while ( True ) :
   if ( II1iIiIiIIi . last_rloc_probe_nonce == nonce ) : break
   II1iIiIiIIi = II1iIiIiIIi . next_rloc
   if ( II1iIiIiIIi == None ) :
    lprint ( "    No matching nonce state found for nonce 0x{}" . format ( lisp_hex_string ( nonce ) ) )
    if 60 - 60: I1Ii111 * OoO0O00 * oO0o + oO0o
    return
    if 34 - 34: o0oOOo0O0Ooo
    if 76 - 76: oO0o + OoooooooOO % OoOoOO00 / OoOoOO00
    if 51 - 51: II111iiii / OoOoOO00
  II1iIiIiIIi . last_rloc_probe_reply = lisp_get_timestamp ( )
  II1iIiIiIIi . compute_rloc_probe_rtt ( )
  o0OOoOOO00 = II1iIiIiIIi . print_state_change ( "up" )
  if ( II1iIiIiIIi . state != LISP_RLOC_UP_STATE ) :
   lisp_update_rtr_updown ( II1iIiIiIIi . rloc , True )
   II1iIiIiIIi . state = LISP_RLOC_UP_STATE
   II1iIiIiIIi . last_state_change = lisp_get_timestamp ( )
   iIi11 = lisp_map_cache . lookup_cache ( eid , True )
   if ( iIi11 ) : lisp_write_ipc_map_cache ( True , iIi11 )
   if 93 - 93: I1IiiI % O0 * OoO0O00 % OoOoOO00 . I1Ii111 * I1IiiI
   if 95 - 95: IiII + o0oOOo0O0Ooo - o0oOOo0O0Ooo
  II1iIiIiIIi . store_rloc_probe_hops ( hop_count , ttl )
  if 83 - 83: ooOoO0o
  iI1IiIIii1I = bold ( "RLOC-probe reply" , False )
  I11i11I = II1iIiIiIIi . rloc . print_address_no_iid ( )
  oooo0000 = bold ( str ( II1iIiIiIIi . print_rloc_probe_rtt ( ) ) , False )
  OoOOOOo = ":{}" . format ( self . translated_port ) if self . translated_port != 0 else ""
  if 4 - 4: I1IiiI + IiII % I1IiiI / o0oOOo0O0Ooo % i1IIi - iII111i
  O0Oo0OO = ""
  if ( II1iIiIiIIi . rloc_next_hop != None ) :
   O0o0oo0oOO0oO , iIIiiIi1 = II1iIiIiIIi . rloc_next_hop
   O0Oo0OO = ", nh {}({})" . format ( iIIiiIi1 , O0o0oo0oOO0oO )
   if 97 - 97: I1Ii111 . Oo0Ooo
   if 44 - 44: OoO0O00 + OOooOOo
  I1i11II = green ( lisp_print_eid_tuple ( eid , group ) , False )
  lprint ( ( "    Received {} from {}{} for {}, {}, rtt {}{}, " + "to-ttl/from-ttl {}" ) . format ( iI1IiIIii1I , red ( I11i11I , False ) , OoOOOOo , I1i11II ,
  # I1ii11iIi11i
 o0OOoOOO00 , oooo0000 , O0Oo0OO , str ( hop_count ) + "/" + str ( ttl ) ) )
  if 3 - 3: i11iIiiIii * IiII . Oo0Ooo % OoOoOO00 * I11i . iII111i
  if ( II1iIiIiIIi . rloc_next_hop == None ) : return
  if 80 - 80: I11i - IiII
  if 40 - 40: OOooOOo * I1IiiI % I11i . I1Ii111 % O0 . O0
  if 14 - 14: ooOoO0o . OoOoOO00 + ooOoO0o * OoOoOO00 . OoOoOO00 * Oo0Ooo
  if 40 - 40: OoooooooOO
  II1iIiIiIIi = None
  IIi1ooO0oOOoOO = None
  while ( True ) :
   II1iIiIiIIi = self if II1iIiIiIIi == None else II1iIiIiIIi . next_rloc
   if ( II1iIiIiIIi == None ) : break
   if ( II1iIiIiIIi . up_state ( ) == False ) : continue
   if ( II1iIiIiIIi . rloc_probe_rtt == - 1 ) : continue
   if 58 - 58: OoOoOO00 / I1Ii111 % O0
   if ( IIi1ooO0oOOoOO == None ) : IIi1ooO0oOOoOO = II1iIiIiIIi
   if ( II1iIiIiIIi . rloc_probe_rtt < IIi1ooO0oOOoOO . rloc_probe_rtt ) : IIi1ooO0oOOoOO = II1iIiIiIIi
   if 14 - 14: I1IiiI . OOooOOo
   if 28 - 28: iII111i / oO0o / iII111i
  if ( IIi1ooO0oOOoOO != None ) :
   O0o0oo0oOO0oO , iIIiiIi1 = IIi1ooO0oOOoOO . rloc_next_hop
   O0Oo0OO = bold ( "nh {}({})" . format ( iIIiiIi1 , O0o0oo0oOO0oO ) , False )
   lprint ( "    Install host-route via best {}" . format ( O0Oo0OO ) )
   lisp_install_host_route ( I11i11I , None , False )
   lisp_install_host_route ( I11i11I , iIIiiIi1 , True )
   if 97 - 97: II111iiii + Oo0Ooo
   if 57 - 57: o0oOOo0O0Ooo % OoooooooOO - oO0o * IiII + OoooooooOO
   if 65 - 65: OoooooooOO + OOooOOo - I1Ii111
 def add_to_rloc_probe_list ( self , eid , group ) :
  I11i11I = self . rloc . print_address_no_iid ( )
  II11i = self . translated_port
  if ( II11i != 0 ) : I11i11I += ":" + str ( II11i )
  if 78 - 78: Oo0Ooo * OOooOOo + i11iIiiIii
  if ( lisp_rloc_probe_list . has_key ( I11i11I ) == False ) :
   lisp_rloc_probe_list [ I11i11I ] = [ ]
   if 15 - 15: I1ii11iIi11i % I1Ii111 . I1ii11iIi11i - iIii1I11I1II1
   if 20 - 20: i1IIi - Ii1I . II111iiii + O0 % oO0o % II111iiii
  if ( group . is_null ( ) ) : group . instance_id = 0
  for oOo0Oooo , I1i11II , O0000O in lisp_rloc_probe_list [ I11i11I ] :
   if ( I1i11II . is_exact_match ( eid ) and O0000O . is_exact_match ( group ) ) :
    if ( oOo0Oooo == self ) :
     if ( lisp_rloc_probe_list [ I11i11I ] == [ ] ) :
      lisp_rloc_probe_list . pop ( I11i11I )
      if 26 - 26: iIii1I11I1II1 - Ii1I / iIii1I11I1II1 . i1IIi - o0oOOo0O0Ooo
     return
     if 48 - 48: iII111i . i11iIiiIii - iIii1I11I1II1 / iIii1I11I1II1
    lisp_rloc_probe_list [ I11i11I ] . remove ( [ oOo0Oooo , I1i11II , O0000O ] )
    break
    if 92 - 92: II111iiii . oO0o - O0 + o0oOOo0O0Ooo * I1ii11iIi11i
    if 32 - 32: I1IiiI % OoO0O00
  lisp_rloc_probe_list [ I11i11I ] . append ( [ self , eid , group ] )
  if 71 - 71: OoooooooOO . I11i . I1IiiI
  if 27 - 27: i11iIiiIii + Oo0Ooo * I11i / OOooOOo - iII111i
  if 42 - 42: ooOoO0o . II111iiii % OoOoOO00 - I11i
  if 34 - 34: Ii1I % I1Ii111 % I1ii11iIi11i - IiII
  if 89 - 89: IiII
  II1iIiIiIIi = lisp_rloc_probe_list [ I11i11I ] [ 0 ] [ 0 ]
  if ( II1iIiIiIIi . state == LISP_RLOC_UNREACH_STATE ) :
   self . state = LISP_RLOC_UNREACH_STATE
   self . last_state_change = lisp_get_timestamp ( )
   if 64 - 64: OoOoOO00
   if 3 - 3: i11iIiiIii / I1Ii111
   if 40 - 40: OoooooooOO / o0oOOo0O0Ooo + OoOoOO00
 def delete_from_rloc_probe_list ( self , eid , group ) :
  I11i11I = self . rloc . print_address_no_iid ( )
  II11i = self . translated_port
  if ( II11i != 0 ) : I11i11I += ":" + str ( II11i )
  if ( lisp_rloc_probe_list . has_key ( I11i11I ) == False ) : return
  if 73 - 73: OOooOOo / Oo0Ooo
  OO0ooo = [ ]
  for oo in lisp_rloc_probe_list [ I11i11I ] :
   if ( oo [ 0 ] != self ) : continue
   if ( oo [ 1 ] . is_exact_match ( eid ) == False ) : continue
   if ( oo [ 2 ] . is_exact_match ( group ) == False ) : continue
   OO0ooo = oo
   break
   if 75 - 75: i1IIi * II111iiii . II111iiii * I1Ii111 + I1Ii111
  if ( OO0ooo == [ ] ) : return
  if 25 - 25: oO0o
  try :
   lisp_rloc_probe_list [ I11i11I ] . remove ( OO0ooo )
   if ( lisp_rloc_probe_list [ I11i11I ] == [ ] ) :
    lisp_rloc_probe_list . pop ( I11i11I )
    if 33 - 33: o0oOOo0O0Ooo * OOooOOo
  except :
   return
   if 7 - 7: i11iIiiIii . OOooOOo * Ii1I . i1IIi
   if 4 - 4: O0 - IiII - II111iiii / iII111i - OOooOOo
   if 6 - 6: ooOoO0o + OOooOOo - I1IiiI + OOooOOo
 def print_rloc_probe_state ( self , trailing_linefeed ) :
  ooO000O = ""
  II1iIiIiIIi = self
  while ( True ) :
   iIIIII1i1III = II1iIiIiIIi . last_rloc_probe
   if ( iIIIII1i1III == None ) : iIIIII1i1III = 0
   iiIIIii1iII = II1iIiIiIIi . last_rloc_probe_reply
   if ( iiIIIii1iII == None ) : iiIIIii1iII = 0
   oooo0000 = II1iIiIiIIi . print_rloc_probe_rtt ( )
   i1I1iIi1IiI = space ( 4 )
   if 90 - 90: iIii1I11I1II1 - II111iiii
   if ( II1iIiIiIIi . rloc_next_hop == None ) :
    ooO000O += "RLOC-Probing:\n"
   else :
    O0o0oo0oOO0oO , iIIiiIi1 = II1iIiIiIIi . rloc_next_hop
    ooO000O += "RLOC-Probing for nh {}({}):\n" . format ( iIIiiIi1 , O0o0oo0oOO0oO )
    if 55 - 55: II111iiii
    if 75 - 75: OOooOOo % OoOoOO00 + iIii1I11I1II1 - II111iiii / i1IIi
   ooO000O += ( "{}RLOC-probe request sent: {}\n{}RLOC-probe reply " + "received: {}, rtt {}" ) . format ( i1I1iIi1IiI , lisp_print_elapsed ( iIIIII1i1III ) ,
   # Oo0Ooo * ooOoO0o % I1Ii111
 i1I1iIi1IiI , lisp_print_elapsed ( iiIIIii1iII ) , oooo0000 )
   if 34 - 34: OoOoOO00 / I1Ii111 - ooOoO0o
   if ( trailing_linefeed ) : ooO000O += "\n"
   if 66 - 66: I11i * OoO0O00
   II1iIiIiIIi = II1iIiIiIIi . next_rloc
   if ( II1iIiIiIIi == None ) : break
   ooO000O += "\n"
   if 98 - 98: IiII . Oo0Ooo + I1Ii111
  return ( ooO000O )
  if 63 - 63: oO0o * I1IiiI * oO0o
  if 56 - 56: oO0o - Ii1I % I1Ii111
 def get_encap_keys ( self ) :
  II11i = "4341" if self . translated_port == 0 else str ( self . translated_port )
  if 100 - 100: OOooOOo * IiII % IiII / o0oOOo0O0Ooo * OoO0O00 % OoOoOO00
  I11i11I = self . rloc . print_address_no_iid ( ) + ":" + II11i
  if 12 - 12: I1IiiI
  try :
   OOo = lisp_crypto_keys_by_rloc_encap [ I11i11I ]
   if ( OOo [ 1 ] ) : return ( OOo [ 1 ] . encrypt_key , OOo [ 1 ] . icv_key )
   return ( None , None )
  except :
   return ( None , None )
   if 32 - 32: I1Ii111
   if 35 - 35: O0 + II111iiii + o0oOOo0O0Ooo - OoO0O00 - Ii1I
   if 88 - 88: I1ii11iIi11i . O0 - o0oOOo0O0Ooo . I1ii11iIi11i * iII111i * I11i
 def rloc_recent_rekey ( self ) :
  II11i = "4341" if self . translated_port == 0 else str ( self . translated_port )
  if 89 - 89: Oo0Ooo - oO0o + O0 / i11iIiiIii
  I11i11I = self . rloc . print_address_no_iid ( ) + ":" + II11i
  if 64 - 64: OoO0O00 % OoOoOO00 % I1IiiI - Ii1I / IiII * Ii1I
  try :
   OOoOoO = lisp_crypto_keys_by_rloc_encap [ I11i11I ] [ 1 ]
   if ( OOoOoO == None ) : return ( False )
   if ( OOoOoO . last_rekey == None ) : return ( True )
   return ( time . time ( ) - OOoOoO . last_rekey < 1 )
  except :
   return ( False )
   if 74 - 74: IiII - O0 % OOooOOo % OoooooooOO - I11i
   if 4 - 4: i1IIi + OoOoOO00 + iIii1I11I1II1 - i1IIi * i11iIiiIii
   if 99 - 99: I1ii11iIi11i - O0 % II111iiii + ooOoO0o % OoO0O00 * Ii1I
   if 8 - 8: OOooOOo
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
  if 85 - 85: O0 % OOooOOo . Ii1I
  if 74 - 74: I1ii11iIi11i - I1Ii111 + i11iIiiIii / I1Ii111 / OoooooooOO + o0oOOo0O0Ooo
 def print_mapping ( self , eid_indent , rloc_indent ) :
  III11I1 = lisp_print_elapsed ( self . uptime )
  oO0000O0o = "" if self . group . is_null ( ) else ", group {}" . format ( self . group . print_prefix ( ) )
  if 23 - 23: Oo0Ooo
  lprint ( "{}eid {}{}, uptime {}, {} rlocs:" . format ( eid_indent ,
 green ( self . eid . print_prefix ( ) , False ) , oO0000O0o , III11I1 ,
 len ( self . rloc_set ) ) )
  for II1iIiIiIIi in self . rloc_set : II1iIiIiIIi . print_rloc ( rloc_indent )
  if 91 - 91: I1Ii111
  if 59 - 59: i1IIi % OOooOOo
 def print_eid_tuple ( self ) :
  return ( lisp_print_eid_tuple ( self . eid , self . group ) )
  if 81 - 81: i11iIiiIii / OoO0O00 * OoOoOO00 % iII111i - iIii1I11I1II1 + I1ii11iIi11i
  if 20 - 20: O0 . I1Ii111 * Ii1I * II111iiii
 def print_ttl ( self ) :
  I1i11iiIiIi = self . map_cache_ttl
  if ( I1i11iiIiIi == None ) : return ( "forever" )
  if 66 - 66: Ii1I % OoO0O00 % II111iiii - OOooOOo * o0oOOo0O0Ooo
  if ( I1i11iiIiIi >= 3600 ) :
   if ( ( I1i11iiIiIi % 3600 ) == 0 ) :
    I1i11iiIiIi = str ( I1i11iiIiIi / 3600 ) + " hours"
   else :
    I1i11iiIiIi = str ( I1i11iiIiIi * 60 ) + " mins"
    if 33 - 33: OoooooooOO / I11i
  elif ( I1i11iiIiIi >= 60 ) :
   if ( ( I1i11iiIiIi % 60 ) == 0 ) :
    I1i11iiIiIi = str ( I1i11iiIiIi / 60 ) + " mins"
   else :
    I1i11iiIiIi = str ( I1i11iiIiIi ) + " secs"
    if 98 - 98: I1ii11iIi11i . Ii1I . iIii1I11I1II1 * I1ii11iIi11i / Ii1I
  else :
   I1i11iiIiIi = str ( I1i11iiIiIi ) + " secs"
   if 74 - 74: Oo0Ooo * I1Ii111
  return ( I1i11iiIiIi )
  if 72 - 72: OoOoOO00 + O0 - IiII * ooOoO0o
  if 20 - 20: II111iiii % OoOoOO00 * i11iIiiIii
 def has_ttl_elapsed ( self ) :
  if ( self . map_cache_ttl == None ) : return ( False )
  ooooOoO0O = time . time ( ) - self . last_refresh_time
  return ( ooooOoO0O >= self . map_cache_ttl )
  if 68 - 68: IiII / ooOoO0o
  if 100 - 100: ooOoO0o / I1IiiI
 def is_active ( self ) :
  if ( self . stats . last_increment == None ) : return ( False )
  ooooOoO0O = time . time ( ) - self . stats . last_increment
  return ( ooooOoO0O <= 60 )
  if 69 - 69: ooOoO0o + OoO0O00 * o0oOOo0O0Ooo - ooOoO0o
  if 66 - 66: OoooooooOO / iII111i / I1IiiI % ooOoO0o / OoO0O00 + OOooOOo
 def match_eid_tuple ( self , db ) :
  if ( self . eid . is_exact_match ( db . eid ) == False ) : return ( False )
  if ( self . group . is_exact_match ( db . group ) == False ) : return ( False )
  return ( True )
  if 64 - 64: i1IIi
  if 26 - 26: OoOoOO00 / o0oOOo0O0Ooo . OOooOOo + I1IiiI + Ii1I . iII111i
 def sort_rloc_set ( self ) :
  self . rloc_set . sort ( key = operator . attrgetter ( 'rloc.address' ) )
  if 89 - 89: I1Ii111 * I1IiiI . i1IIi - iIii1I11I1II1 * I1Ii111
  if 5 - 5: OoOoOO00 % i1IIi
 def delete_rlocs_from_rloc_probe_list ( self ) :
  for II1iIiIiIIi in self . best_rloc_set :
   II1iIiIiIIi . delete_from_rloc_probe_list ( self . eid , self . group )
   if 31 - 31: Oo0Ooo * O0 . OOooOOo . o0oOOo0O0Ooo + OoO0O00 + II111iiii
   if 76 - 76: Oo0Ooo + I1IiiI - O0
   if 58 - 58: IiII * i1IIi . I1IiiI - iII111i
 def build_best_rloc_set ( self ) :
  oOOi1IiI = self . best_rloc_set
  self . best_rloc_set = [ ]
  if ( self . rloc_set == None ) : return
  if 53 - 53: OoO0O00 + iII111i / OoooooooOO
  if 52 - 52: O0
  if 34 - 34: OoooooooOO + OoOoOO00 - Oo0Ooo . OOooOOo * iIii1I11I1II1
  if 93 - 93: i11iIiiIii / Oo0Ooo * OoOoOO00 / ooOoO0o + OoO0O00 * OOooOOo
  O0O0Ooo0O0ooO = 256
  for II1iIiIiIIi in self . rloc_set :
   if ( II1iIiIiIIi . up_state ( ) ) : O0O0Ooo0O0ooO = min ( II1iIiIiIIi . priority , O0O0Ooo0O0ooO )
   if 43 - 43: o0oOOo0O0Ooo + OoooooooOO
   if 96 - 96: iII111i . II111iiii
   if 41 - 41: OoO0O00 + Oo0Ooo % Ii1I
   if 9 - 9: OOooOOo * i1IIi
   if 93 - 93: OoOoOO00 / I1ii11iIi11i
   if 39 - 39: o0oOOo0O0Ooo % OOooOOo . iIii1I11I1II1 * I1ii11iIi11i / I1Ii111
   if 96 - 96: OOooOOo - o0oOOo0O0Ooo - Ii1I / Oo0Ooo . OOooOOo
   if 43 - 43: II111iiii * o0oOOo0O0Ooo % o0oOOo0O0Ooo + iIii1I11I1II1 + OoOoOO00
   if 54 - 54: II111iiii + OOooOOo * Oo0Ooo * I1Ii111 - o0oOOo0O0Ooo % Ii1I
   if 69 - 69: I11i + OoOoOO00 - i11iIiiIii * O0 % O0
  for II1iIiIiIIi in self . rloc_set :
   if ( II1iIiIiIIi . priority <= O0O0Ooo0O0ooO ) :
    if ( II1iIiIiIIi . unreach_state ( ) and II1iIiIiIIi . last_rloc_probe == None ) :
     II1iIiIiIIi . last_rloc_probe = lisp_get_timestamp ( )
     if 81 - 81: I11i - o0oOOo0O0Ooo % Ii1I / I1Ii111 * II111iiii
    self . best_rloc_set . append ( II1iIiIiIIi )
    if 40 - 40: OoO0O00 . i11iIiiIii
    if 36 - 36: o0oOOo0O0Ooo * iII111i / I1ii11iIi11i % i1IIi % I1ii11iIi11i + i11iIiiIii
    if 24 - 24: I1Ii111 / ooOoO0o - i11iIiiIii
    if 32 - 32: II111iiii * Ii1I . ooOoO0o * Oo0Ooo - I1ii11iIi11i % I11i
    if 96 - 96: Ii1I / OOooOOo / O0
    if 8 - 8: iII111i + OOooOOo / I1ii11iIi11i . iII111i
    if 45 - 45: i1IIi
    if 28 - 28: iII111i
  for II1iIiIiIIi in oOOi1IiI :
   if ( II1iIiIiIIi . priority < O0O0Ooo0O0ooO ) : continue
   II1iIiIiIIi . delete_from_rloc_probe_list ( self . eid , self . group )
   if 28 - 28: i1IIi - iII111i + o0oOOo0O0Ooo / Oo0Ooo * oO0o
  for II1iIiIiIIi in self . best_rloc_set :
   if ( II1iIiIiIIi . rloc . is_null ( ) ) : continue
   II1iIiIiIIi . add_to_rloc_probe_list ( self . eid , self . group )
   if 8 - 8: ooOoO0o + OOooOOo * ooOoO0o / i1IIi . I1ii11iIi11i
   if 4 - 4: Ii1I - Oo0Ooo . i1IIi + iIii1I11I1II1
   if 28 - 28: O0 / ooOoO0o / IiII - I11i + IiII + OoO0O00
 def select_rloc ( self , lisp_packet , ipc_socket ) :
  I111 = lisp_packet . packet
  OOoOo0O = lisp_packet . inner_version
  i1IIiIIIi1 = len ( self . best_rloc_set )
  if ( i1IIiIIIi1 is 0 ) :
   self . stats . increment ( len ( I111 ) )
   return ( [ None , None , None , self . action , None ] )
   if 26 - 26: Oo0Ooo
   if 61 - 61: Ii1I * oO0o * i11iIiiIii + OoO0O00
  iI1IIiiI11IiI = 4 if lisp_load_split_pings else 0
  iIII1I1i = lisp_packet . hash_ports ( )
  if ( OOoOo0O == 4 ) :
   for oO in range ( 8 + iI1IIiiI11IiI ) :
    iIII1I1i = iIII1I1i ^ struct . unpack ( "B" , I111 [ oO + 12 ] ) [ 0 ]
    if 94 - 94: i1IIi - i11iIiiIii + I1Ii111 % Oo0Ooo % Oo0Ooo . OoO0O00
  elif ( OOoOo0O == 6 ) :
   for oO in range ( 0 , 32 + iI1IIiiI11IiI , 4 ) :
    iIII1I1i = iIII1I1i ^ struct . unpack ( "I" , I111 [ oO + 8 : oO + 12 ] ) [ 0 ]
    if 65 - 65: IiII * I11i * o0oOOo0O0Ooo * o0oOOo0O0Ooo + OoOoOO00 % OoOoOO00
   iIII1I1i = ( iIII1I1i >> 16 ) + ( iIII1I1i & 0xffff )
   iIII1I1i = ( iIII1I1i >> 8 ) + ( iIII1I1i & 0xff )
  else :
   for oO in range ( 0 , 12 + iI1IIiiI11IiI , 4 ) :
    iIII1I1i = iIII1I1i ^ struct . unpack ( "I" , I111 [ oO : oO + 4 ] ) [ 0 ]
    if 55 - 55: i11iIiiIii * II111iiii
    if 41 - 41: iIii1I11I1II1
    if 26 - 26: Oo0Ooo / i1IIi + Oo0Ooo
  if ( lisp_data_plane_logging ) :
   oO0oO000ooo0o = [ ]
   for oOo0Oooo in self . best_rloc_set :
    if ( oOo0Oooo . rloc . is_null ( ) ) : continue
    oO0oO000ooo0o . append ( [ oOo0Oooo . rloc . print_address_no_iid ( ) , oOo0Oooo . print_state ( ) ] )
    if 24 - 24: I1ii11iIi11i * I1Ii111 % o0oOOo0O0Ooo / I1ii11iIi11i
   dprint ( "Packet hash {}, index {}, best-rloc-list: {}" . format ( hex ( iIII1I1i ) , iIII1I1i % i1IIiIIIi1 , red ( str ( oO0oO000ooo0o ) , False ) ) )
   if 72 - 72: I1Ii111 % O0
   if 24 - 24: I11i + I11i % I11i
   if 63 - 63: i11iIiiIii + iIii1I11I1II1 / oO0o % IiII - O0
   if 21 - 21: II111iiii
   if 89 - 89: OOooOOo % i11iIiiIii * OoOoOO00 % oO0o / O0 * i1IIi
   if 16 - 16: IiII
  II1iIiIiIIi = self . best_rloc_set [ iIII1I1i % i1IIiIIIi1 ]
  if 42 - 42: i1IIi / Ii1I * I1ii11iIi11i
  if 9 - 9: I11i % i1IIi / i1IIi / OoO0O00
  if 46 - 46: I1Ii111 * II111iiii + II111iiii * O0 % II111iiii
  if 37 - 37: OOooOOo . iIii1I11I1II1 / O0 . ooOoO0o + OOooOOo - OoooooooOO
  if 96 - 96: I1Ii111 / oO0o . I1ii11iIi11i % I1IiiI * OOooOOo
  Ii1i = lisp_get_echo_nonce ( II1iIiIiIIi . rloc , None )
  if ( Ii1i ) :
   Ii1i . change_state ( II1iIiIiIIi )
   if ( II1iIiIiIIi . no_echoed_nonce_state ( ) ) :
    Ii1i . request_nonce_sent = None
    if 99 - 99: i11iIiiIii - I1Ii111
    if 4 - 4: o0oOOo0O0Ooo - i11iIiiIii . iIii1I11I1II1 . OOooOOo % IiII
    if 68 - 68: I11i / iII111i - IiII . iIii1I11I1II1 / o0oOOo0O0Ooo
    if 54 - 54: II111iiii * I1IiiI
    if 49 - 49: I1ii11iIi11i
    if 31 - 31: o0oOOo0O0Ooo - OoOoOO00 + I1ii11iIi11i . oO0o - O0
  if ( II1iIiIiIIi . up_state ( ) == False ) :
   oOoooO00o000 = iIII1I1i % i1IIiIIIi1
   OOOoO000 = ( oOoooO00o000 + 1 ) % i1IIiIIIi1
   while ( OOOoO000 != oOoooO00o000 ) :
    II1iIiIiIIi = self . best_rloc_set [ OOOoO000 ]
    if ( II1iIiIiIIi . up_state ( ) ) : break
    OOOoO000 = ( OOOoO000 + 1 ) % i1IIiIIIi1
    if 3 - 3: IiII . i11iIiiIii . Oo0Ooo - I1Ii111 . Ii1I
   if ( OOOoO000 == oOoooO00o000 ) :
    self . build_best_rloc_set ( )
    return ( [ None , None , None , None , None ] )
    if 43 - 43: O0 / Ii1I - OoO0O00 + OOooOOo
    if 54 - 54: I1Ii111 % OoO0O00 - OoooooooOO
    if 96 - 96: IiII
    if 31 - 31: Ii1I + O0 - OOooOOo * O0 * I11i
    if 53 - 53: I1ii11iIi11i + i11iIiiIii / iIii1I11I1II1 + OoooooooOO + IiII * I1IiiI
    if 16 - 16: i11iIiiIii - oO0o . i11iIiiIii + OoO0O00 + i11iIiiIii
  II1iIiIiIIi . stats . increment ( len ( I111 ) )
  if 85 - 85: I1ii11iIi11i - ooOoO0o + I1Ii111 + I1Ii111
  if 13 - 13: II111iiii
  if 22 - 22: o0oOOo0O0Ooo
  if 45 - 45: I1Ii111 + OoooooooOO + o0oOOo0O0Ooo * II111iiii
  if ( II1iIiIiIIi . rle_name and II1iIiIiIIi . rle == None ) :
   if ( lisp_rle_list . has_key ( II1iIiIiIIi . rle_name ) ) :
    II1iIiIiIIi . rle = lisp_rle_list [ II1iIiIiIIi . rle_name ]
    if 12 - 12: I1ii11iIi11i / O0
    if 18 - 18: OoOoOO00 . i11iIiiIii + i1IIi / OoooooooOO - IiII % OoO0O00
  if ( II1iIiIiIIi . rle ) : return ( [ None , None , None , None , II1iIiIiIIi . rle ] )
  if 47 - 47: iII111i % IiII + I1Ii111 * o0oOOo0O0Ooo * OoooooooOO
  if 100 - 100: Oo0Ooo / I1IiiI / iII111i / I1Ii111 / oO0o % o0oOOo0O0Ooo
  if 16 - 16: I1IiiI + I11i
  if 66 - 66: OoooooooOO % II111iiii / I1Ii111 . i11iIiiIii
  if ( II1iIiIiIIi . elp and II1iIiIiIIi . elp . use_elp_node ) :
   return ( [ II1iIiIiIIi . elp . use_elp_node . address , None , None , None , None ] )
   if 67 - 67: Ii1I + Oo0Ooo - I1IiiI - IiII + oO0o + Oo0Ooo
   if 84 - 84: I1ii11iIi11i % oO0o - OOooOOo * Ii1I
   if 78 - 78: i1IIi / ooOoO0o / oO0o
   if 21 - 21: IiII % Ii1I + OOooOOo + IiII
   if 90 - 90: o0oOOo0O0Ooo
  II111 = None if ( II1iIiIiIIi . rloc . is_null ( ) ) else II1iIiIiIIi . rloc
  II11i = II1iIiIiIIi . translated_port
  i1ii1iIIIiI1 = self . action if ( II111 == None ) else None
  if 16 - 16: IiII . I11i * O0 + OoooooooOO
  if 37 - 37: OoO0O00 . i11iIiiIii - i11iIiiIii % I1Ii111 + II111iiii * i11iIiiIii
  if 83 - 83: OOooOOo % O0 - I11i . Ii1I % IiII
  if 45 - 45: I11i % OoO0O00
  if 18 - 18: Ii1I / Ii1I * IiII
  oO00o0oOoo = None
  if ( Ii1i and Ii1i . request_nonce_timeout ( ) == False ) :
   oO00o0oOoo = Ii1i . get_request_or_echo_nonce ( ipc_socket , II111 )
   if 33 - 33: ooOoO0o
   if 14 - 14: Oo0Ooo % I1Ii111 % ooOoO0o . oO0o * iIii1I11I1II1 . I1ii11iIi11i
   if 50 - 50: O0 * i11iIiiIii / iIii1I11I1II1 . I11i + i11iIiiIii
   if 68 - 68: oO0o + o0oOOo0O0Ooo * iIii1I11I1II1 / i1IIi
   if 9 - 9: I11i % OoO0O00 . oO0o / I1ii11iIi11i
  return ( [ II111 , II11i , oO00o0oOoo , i1ii1iIIIiI1 , None ] )
  if 88 - 88: Oo0Ooo / IiII / II111iiii / I1ii11iIi11i + OoooooooOO
  if 65 - 65: iII111i % oO0o * IiII
 def do_rloc_sets_match ( self , rloc_address_set ) :
  if ( len ( self . rloc_set ) != len ( rloc_address_set ) ) : return ( False )
  if 16 - 16: iII111i % I11i % OoOoOO00
  if 80 - 80: OoooooooOO * i11iIiiIii % oO0o / Oo0Ooo - I1ii11iIi11i
  if 92 - 92: o0oOOo0O0Ooo % i1IIi / I1Ii111 % ooOoO0o / oO0o
  if 2 - 2: i11iIiiIii / Ii1I - i1IIi % O0
  if 12 - 12: Oo0Ooo + I1ii11iIi11i
  for o0OO0O0OoOo0 in self . rloc_set :
   for II1iIiIiIIi in rloc_address_set :
    if ( II1iIiIiIIi . is_exact_match ( o0OO0O0OoOo0 . rloc ) == False ) : continue
    II1iIiIiIIi = None
    break
    if 54 - 54: OoO0O00 . o0oOOo0O0Ooo / I11i
   if ( II1iIiIiIIi == rloc_address_set [ - 1 ] ) : return ( False )
   if 95 - 95: i1IIi . I1Ii111
  return ( True )
  if 94 - 94: I1IiiI + Ii1I + i1IIi . iIii1I11I1II1
  if 64 - 64: O0 * OOooOOo * I1IiiI - o0oOOo0O0Ooo
 def get_rloc ( self , rloc ) :
  for o0OO0O0OoOo0 in self . rloc_set :
   oOo0Oooo = o0OO0O0OoOo0 . rloc
   if ( rloc . is_exact_match ( oOo0Oooo ) ) : return ( o0OO0O0OoOo0 )
   if 86 - 86: i1IIi
  return ( None )
  if 84 - 84: OoOoOO00
  if 31 - 31: iIii1I11I1II1 + I1IiiI
 def get_rloc_by_interface ( self , interface ) :
  for o0OO0O0OoOo0 in self . rloc_set :
   if ( o0OO0O0OoOo0 . interface == interface ) : return ( o0OO0O0OoOo0 )
   if 82 - 82: I1Ii111 / Ii1I % OoooooooOO - IiII / OoooooooOO
  return ( None )
  if 23 - 23: iIii1I11I1II1
  if 7 - 7: IiII / OOooOOo + Oo0Ooo . I1IiiI
 def add_db ( self ) :
  if ( self . group . is_null ( ) ) :
   lisp_db_for_lookups . add_cache ( self . eid , self )
  else :
   o0O00o = lisp_db_for_lookups . lookup_cache ( self . group , True )
   if ( o0O00o == None ) :
    o0O00o = lisp_mapping ( self . group , self . group , [ ] )
    lisp_db_for_lookups . add_cache ( self . group , o0O00o )
    if 33 - 33: I1Ii111 + OoooooooOO
   o0O00o . add_source_entry ( self )
   if 73 - 73: O0 . Oo0Ooo
   if 28 - 28: I1IiiI . O0 % o0oOOo0O0Ooo / I11i
   if 48 - 48: II111iiii % I1ii11iIi11i - II111iiii
 def add_cache ( self , do_ipc = True ) :
  if ( self . group . is_null ( ) ) :
   lisp_map_cache . add_cache ( self . eid , self )
   if ( lisp_program_hardware ) : lisp_program_vxlan_hardware ( self )
  else :
   iIi11 = lisp_map_cache . lookup_cache ( self . group , True )
   if ( iIi11 == None ) :
    iIi11 = lisp_mapping ( self . group , self . group , [ ] )
    iIi11 . eid . copy_address ( self . group )
    iIi11 . group . copy_address ( self . group )
    lisp_map_cache . add_cache ( self . group , iIi11 )
    if 29 - 29: I1Ii111 - I1Ii111 - I11i * iIii1I11I1II1 % OoO0O00 % IiII
   if ( self . eid . is_null ( ) ) : self . eid . make_default_route ( iIi11 . group )
   iIi11 . add_source_entry ( self )
   if 73 - 73: i1IIi . OoooooooOO / OoOoOO00 % Ii1I / Ii1I / Ii1I
  if ( do_ipc ) : lisp_write_ipc_map_cache ( True , self )
  if 40 - 40: I1Ii111 - iIii1I11I1II1
  if 88 - 88: OOooOOo * O0 * OoOoOO00
 def delete_cache ( self ) :
  self . delete_rlocs_from_rloc_probe_list ( )
  lisp_write_ipc_map_cache ( False , self )
  if 26 - 26: Ii1I
  if ( self . group . is_null ( ) ) :
   lisp_map_cache . delete_cache ( self . eid )
   if ( lisp_program_hardware ) :
    O0OoOoo000OoO = self . eid . print_prefix_no_iid ( )
    os . system ( "ip route delete {}" . format ( O0OoOoo000OoO ) )
    if 38 - 38: OOooOOo * ooOoO0o - i11iIiiIii
  else :
   iIi11 = lisp_map_cache . lookup_cache ( self . group , True )
   if ( iIi11 == None ) : return
   if 43 - 43: iII111i / Ii1I
   I1ii = iIi11 . lookup_source_cache ( self . eid , True )
   if ( I1ii == None ) : return
   if 10 - 10: O0 . oO0o * I1IiiI
   iIi11 . source_cache . delete_cache ( self . eid )
   if ( iIi11 . source_cache . cache_size ( ) == 0 ) :
    lisp_map_cache . delete_cache ( self . group )
    if 21 - 21: OoooooooOO
    if 76 - 76: i1IIi * i11iIiiIii / OOooOOo + I1Ii111
    if 50 - 50: oO0o % OoOoOO00 + I1IiiI
    if 15 - 15: II111iiii - iII111i / I1ii11iIi11i
 def add_source_entry ( self , source_mc ) :
  if ( self . source_cache == None ) : self . source_cache = lisp_cache ( )
  self . source_cache . add_cache ( source_mc . eid , source_mc )
  if 81 - 81: Ii1I - i1IIi % oO0o * Oo0Ooo * OoOoOO00
  if 79 - 79: oO0o + I1IiiI % iII111i + II111iiii % OoO0O00 % iII111i
 def lookup_source_cache ( self , source , exact ) :
  if ( self . source_cache == None ) : return ( None )
  return ( self . source_cache . lookup_cache ( source , exact ) )
  if 46 - 46: o0oOOo0O0Ooo
  if 61 - 61: OoO0O00 . O0 + I1ii11iIi11i + OoO0O00
 def dynamic_eid_configured ( self ) :
  return ( self . dynamic_eids != None )
  if 44 - 44: I11i . oO0o
  if 65 - 65: I1ii11iIi11i * II111iiii % I11i + II111iiii . i1IIi / ooOoO0o
 def star_secondary_iid ( self , prefix ) :
  if ( self . secondary_iid == None ) : return ( prefix )
  IIiI1i = "," + str ( self . secondary_iid )
  return ( prefix . replace ( IIiI1i , IIiI1i + "*" ) )
  if 74 - 74: OoOoOO00 % OoO0O00 . OoOoOO00
  if 16 - 16: OoO0O00 / Ii1I * i11iIiiIii / o0oOOo0O0Ooo + I1Ii111
 def increment_decap_stats ( self , packet ) :
  II11i = packet . udp_dport
  if ( II11i == LISP_DATA_PORT ) :
   II1iIiIiIIi = self . get_rloc ( packet . outer_dest )
  else :
   if 21 - 21: I11i % I1ii11iIi11i
   if 8 - 8: OOooOOo % OoO0O00 + O0 - o0oOOo0O0Ooo
   if 46 - 46: Oo0Ooo . ooOoO0o + OoOoOO00 - I11i / i11iIiiIii . iII111i
   if 80 - 80: II111iiii + OoO0O00 % ooOoO0o + i11iIiiIii
   for II1iIiIiIIi in self . rloc_set :
    if ( II1iIiIiIIi . translated_port != 0 ) : break
    if 30 - 30: Ii1I / I1ii11iIi11i % IiII - Oo0Ooo
    if 100 - 100: IiII . I1Ii111 * oO0o % OoO0O00 . iIii1I11I1II1 * Oo0Ooo
  if ( II1iIiIiIIi != None ) : II1iIiIiIIi . stats . increment ( len ( packet . packet ) )
  self . stats . increment ( len ( packet . packet ) )
  if 100 - 100: IiII - OoOoOO00 % iII111i
  if 24 - 24: Oo0Ooo / OoO0O00 + i11iIiiIii
 def rtrs_in_rloc_set ( self ) :
  for II1iIiIiIIi in self . rloc_set :
   if ( II1iIiIiIIi . is_rtr ( ) ) : return ( True )
   if 81 - 81: i11iIiiIii . iIii1I11I1II1 - OoooooooOO
  return ( False )
  if 52 - 52: O0 - I1Ii111 + oO0o % ooOoO0o . oO0o
  if 60 - 60: oO0o + o0oOOo0O0Ooo - OOooOOo % o0oOOo0O0Ooo . I11i + OoO0O00
  if 27 - 27: i11iIiiIii - I1ii11iIi11i * I1Ii111 . I1IiiI / OoO0O00 * ooOoO0o
class lisp_dynamic_eid ( ) :
 def __init__ ( self ) :
  self . dynamic_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . uptime = lisp_get_timestamp ( )
  self . interface = None
  self . last_packet = None
  self . timeout = LISP_DEFAULT_DYN_EID_TIMEOUT
  if 42 - 42: OOooOOo
  if 36 - 36: OoooooooOO + ooOoO0o + iII111i
 def get_timeout ( self , interface ) :
  try :
   ii1i11IiIi1 = lisp_myinterfaces [ interface ]
   self . timeout = ii1i11IiIi1 . dynamic_eid_timeout
  except :
   self . timeout = LISP_DEFAULT_DYN_EID_TIMEOUT
   if 90 - 90: OoO0O00
   if 26 - 26: ooOoO0o + OoO0O00 / I1ii11iIi11i * ooOoO0o
   if 96 - 96: IiII % iII111i . OoOoOO00 / oO0o . OoO0O00
   if 85 - 85: iIii1I11I1II1 / OoOoOO00 * I1ii11iIi11i
class lisp_group_mapping ( ) :
 def __init__ ( self , group_name , ms_name , group_prefix , sources , rle_addr ) :
  self . group_name = group_name
  self . group_prefix = group_prefix
  self . use_ms_name = ms_name
  self . sources = sources
  self . rle_address = rle_addr
  if 26 - 26: iII111i - OoO0O00 . o0oOOo0O0Ooo
  if 50 - 50: I1Ii111 . O0 . OoOoOO00 + I1Ii111 + OoooooooOO . i11iIiiIii
 def add_group ( self ) :
  lisp_group_mapping_list [ self . group_name ] = self
  if 65 - 65: I1IiiI % iIii1I11I1II1
  if 52 - 52: I1IiiI
  if 19 - 19: I1IiiI
lisp_site_flags = {
 "P" : "ETR is {}Requesting Map-Server to Proxy Map-Reply" ,
 "S" : "ETR is {}LISP-SEC capable" ,
 "I" : "xTR-ID and site-ID are {}included in Map-Register" ,
 "T" : "Use Map-Register TTL field to timeout registration is {}set" ,
 "R" : "Merging registrations are {}requested" ,
 "M" : "ETR is {}a LISP Mobile-Node" ,
 "N" : "ETR is {}requesting Map-Notify messages from Map-Server"
 }
if 17 - 17: I11i + OoooooooOO
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
  if 63 - 63: IiII
  if 3 - 3: oO0o * II111iiii . O0
  if 19 - 19: I1IiiI / I1IiiI / Oo0Ooo + oO0o + i1IIi
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
  if 31 - 31: iII111i / OoooooooOO - I1Ii111 . iII111i
  if 38 - 38: ooOoO0o . OoooooooOO - II111iiii * i11iIiiIii / i1IIi . OoooooooOO
 def print_eid_tuple ( self ) :
  return ( lisp_print_eid_tuple ( self . eid , self . group ) )
  if 51 - 51: oO0o - I1ii11iIi11i + I1ii11iIi11i
  if 100 - 100: I11i - I1ii11iIi11i . i1IIi
 def print_flags ( self , html ) :
  if ( html == False ) :
   ooO000O = "{}-{}-{}-{}-{}-{}-{}" . format ( "P" if self . proxy_reply_requested else "p" ,
   # II111iiii . OoOoOO00 - i1IIi - OoO0O00 + O0 * ooOoO0o
 "S" if self . lisp_sec_present else "s" ,
 "I" if self . xtr_id_present else "i" ,
 "T" if self . use_register_ttl_requested else "t" ,
 "R" if self . merge_register_requested else "r" ,
 "M" if self . mobile_node_requested else "m" ,
 "N" if self . map_notify_requested else "n" )
  else :
   ii111 = self . print_flags ( False )
   ii111 = ii111 . split ( "-" )
   ooO000O = ""
   for Oo0ooOO in ii111 :
    OoO0O0O = lisp_site_flags [ Oo0ooOO . upper ( ) ]
    OoO0O0O = OoO0O0O . format ( "" if Oo0ooOO . isupper ( ) else "not " )
    ooO000O += lisp_span ( Oo0ooOO , OoO0O0O )
    if ( Oo0ooOO . lower ( ) != "n" ) : ooO000O += "-"
    if 74 - 74: iII111i / OoOoOO00
    if 96 - 96: OoOoOO00 % Ii1I
  return ( ooO000O )
  if 50 - 50: IiII - II111iiii
  if 10 - 10: OoooooooOO % Ii1I * OOooOOo + IiII * oO0o
 def copy_state_to_parent ( self , child ) :
  self . xtr_id = child . xtr_id
  self . site_id = child . site_id
  self . first_registered = child . first_registered
  self . last_registered = child . last_registered
  self . last_registerer = child . last_registerer
  self . register_ttl = child . register_ttl
  if ( self . registered == False ) :
   self . first_registered = lisp_get_timestamp ( )
   if 13 - 13: II111iiii
  self . auth_sha1_or_sha2 = child . auth_sha1_or_sha2
  self . registered = child . registered
  self . proxy_reply_requested = child . proxy_reply_requested
  self . lisp_sec_present = child . lisp_sec_present
  self . xtr_id_present = child . xtr_id_present
  self . use_register_ttl_requested = child . use_register_ttl_requested
  self . merge_register_requested = child . merge_register_requested
  self . mobile_node_requested = child . mobile_node_requested
  self . map_notify_requested = child . map_notify_requested
  if 14 - 14: i11iIiiIii . IiII
  if 70 - 70: Oo0Ooo * OOooOOo + I1Ii111 % OoOoOO00 / O0
 def build_sort_key ( self ) :
  IiiIIi1i1iIi = lisp_cache ( )
  oOOoOO , OOoOoO = IiiIIi1i1iIi . build_key ( self . eid )
  o0oooOOo0000O = ""
  if ( self . group . is_null ( ) == False ) :
   o0O000 , o0oooOOo0000O = IiiIIi1i1iIi . build_key ( self . group )
   o0oooOOo0000O = "-" + o0oooOOo0000O [ 0 : 12 ] + "-" + str ( o0O000 ) + "-" + o0oooOOo0000O [ 12 : : ]
   if 5 - 5: I11i % i11iIiiIii
  OOoOoO = OOoOoO [ 0 : 12 ] + "-" + str ( oOOoOO ) + "-" + OOoOoO [ 12 : : ] + o0oooOOo0000O
  del ( IiiIIi1i1iIi )
  return ( OOoOoO )
  if 34 - 34: iIii1I11I1II1 * OoOoOO00 + II111iiii
  if 40 - 40: I1IiiI + ooOoO0o . OoooooooOO / I1Ii111 % I1Ii111 * iII111i
 def merge_in_site_eid ( self , child ) :
  OOOOoOoooo0o = False
  if ( self . group . is_null ( ) ) :
   self . merge_rlocs_in_site_eid ( )
  else :
   OOOOoOoooo0o = self . merge_rles_in_site_eid ( )
   if 67 - 67: oO0o . ooOoO0o - oO0o + OoO0O00 / o0oOOo0O0Ooo
   if 19 - 19: I1ii11iIi11i . iII111i
   if 62 - 62: o0oOOo0O0Ooo * o0oOOo0O0Ooo + I11i + I1Ii111 . i11iIiiIii
   if 95 - 95: ooOoO0o + o0oOOo0O0Ooo % OoO0O00
   if 42 - 42: ooOoO0o % iIii1I11I1II1 % ooOoO0o * oO0o * I1Ii111 * Ii1I
   if 16 - 16: i11iIiiIii
  if ( child != None ) :
   self . copy_state_to_parent ( child )
   self . map_registers_received += 1
   if 83 - 83: Oo0Ooo / Oo0Ooo . I11i + oO0o % Ii1I
  return ( OOOOoOoooo0o )
  if 22 - 22: ooOoO0o
  if 83 - 83: OOooOOo - i11iIiiIii - i1IIi / oO0o
 def copy_rloc_records ( self ) :
  iI1I1iI = [ ]
  for o0OO0O0OoOo0 in self . registered_rlocs :
   iI1I1iI . append ( copy . deepcopy ( o0OO0O0OoOo0 ) )
   if 33 - 33: oO0o * ooOoO0o * Ii1I * IiII
  return ( iI1I1iI )
  if 39 - 39: i1IIi
  if 79 - 79: ooOoO0o - II111iiii - oO0o
 def merge_rlocs_in_site_eid ( self ) :
  self . registered_rlocs = [ ]
  for o0O0o in self . individual_registrations . values ( ) :
   if ( self . site_id != o0O0o . site_id ) : continue
   if ( o0O0o . registered == False ) : continue
   self . registered_rlocs += o0O0o . copy_rloc_records ( )
   if 55 - 55: iII111i % iIii1I11I1II1 + Ii1I + oO0o . i11iIiiIii - OOooOOo
   if 14 - 14: oO0o - i11iIiiIii / OoOoOO00 % o0oOOo0O0Ooo / IiII * I1IiiI
   if 2 - 2: i1IIi / I1Ii111 + I1IiiI + I1ii11iIi11i - o0oOOo0O0Ooo + iIii1I11I1II1
   if 78 - 78: I1ii11iIi11i % i1IIi . I1Ii111 + Oo0Ooo . o0oOOo0O0Ooo % II111iiii
   if 65 - 65: Ii1I . OoOoOO00 + O0 / iIii1I11I1II1 % Ii1I % I1Ii111
   if 31 - 31: o0oOOo0O0Ooo - Oo0Ooo
  iI1I1iI = [ ]
  for o0OO0O0OoOo0 in self . registered_rlocs :
   if ( o0OO0O0OoOo0 . rloc . is_null ( ) or len ( iI1I1iI ) == 0 ) :
    iI1I1iI . append ( o0OO0O0OoOo0 )
    continue
    if 15 - 15: O0 + OOooOOo
   for Iii in iI1I1iI :
    if ( Iii . rloc . is_null ( ) ) : continue
    if ( o0OO0O0OoOo0 . rloc . is_exact_match ( Iii . rloc ) ) : break
    if 90 - 90: I11i - I1Ii111 / oO0o
   if ( Iii == iI1I1iI [ - 1 ] ) : iI1I1iI . append ( o0OO0O0OoOo0 )
   if 34 - 34: I1IiiI
  self . registered_rlocs = iI1I1iI
  if 95 - 95: IiII + I1IiiI / i1IIi
  if 18 - 18: II111iiii / iIii1I11I1II1 * I1ii11iIi11i . ooOoO0o * ooOoO0o
  if 89 - 89: I1IiiI - Oo0Ooo
  if 28 - 28: OoooooooOO . i1IIi . I1Ii111
  if ( len ( self . registered_rlocs ) == 0 ) : self . registered = False
  return
  if 53 - 53: OoO0O00 * Oo0Ooo + Oo0Ooo
  if 62 - 62: OOooOOo - i1IIi + i11iIiiIii * I11i / OoO0O00
 def merge_rles_in_site_eid ( self ) :
  if 84 - 84: IiII * OOooOOo
  if 1 - 1: iII111i * I1IiiI . o0oOOo0O0Ooo . IiII
  if 6 - 6: OOooOOo . oO0o / Oo0Ooo / o0oOOo0O0Ooo
  if 24 - 24: Oo0Ooo % OoooooooOO
  OooooOO0 = { }
  for o0OO0O0OoOo0 in self . registered_rlocs :
   if ( o0OO0O0OoOo0 . rle == None ) : continue
   for II1ii in o0OO0O0OoOo0 . rle . rle_nodes :
    I1Iii1I = II1ii . address . print_address_no_iid ( )
    OooooOO0 [ I1Iii1I ] = II1ii . address
    if 73 - 73: OOooOOo % I1Ii111 + OoooooooOO / I1ii11iIi11i * oO0o % oO0o
   break
   if 25 - 25: I1Ii111
   if 93 - 93: OoO0O00
   if 62 - 62: Oo0Ooo . iII111i
   if 15 - 15: i11iIiiIii * I11i + oO0o
   if 67 - 67: IiII . OoO0O00
  self . merge_rlocs_in_site_eid ( )
  if 59 - 59: oO0o * o0oOOo0O0Ooo
  if 76 - 76: I1IiiI
  if 94 - 94: OoooooooOO * I1ii11iIi11i
  if 28 - 28: II111iiii / II111iiii / II111iiii
  if 70 - 70: OoO0O00 + O0 * OoO0O00
  if 25 - 25: OoooooooOO . Oo0Ooo + OOooOOo + Oo0Ooo * O0 % i1IIi
  if 71 - 71: II111iiii / Ii1I + i1IIi - OoOoOO00 + Ii1I
  if 31 - 31: OoooooooOO * Ii1I - iII111i . oO0o % Ii1I
  oOOoo0O0OOO = [ ]
  for o0OO0O0OoOo0 in self . registered_rlocs :
   if ( self . registered_rlocs . index ( o0OO0O0OoOo0 ) == 0 ) :
    oOOoo0O0OOO . append ( o0OO0O0OoOo0 )
    continue
    if 29 - 29: O0 * IiII / I1ii11iIi11i + OoOoOO00 / O0 + i11iIiiIii
   if ( o0OO0O0OoOo0 . rle == None ) : oOOoo0O0OOO . append ( o0OO0O0OoOo0 )
   if 92 - 92: ooOoO0o + Ii1I . o0oOOo0O0Ooo * II111iiii
  self . registered_rlocs = oOOoo0O0OOO
  if 8 - 8: OoOoOO00 . Oo0Ooo * I1Ii111
  if 62 - 62: Ii1I % OoO0O00 - I1Ii111 / i11iIiiIii
  if 27 - 27: i11iIiiIii . OoO0O00 + Ii1I
  if 47 - 47: I1Ii111 . iIii1I11I1II1 + i11iIiiIii
  if 75 - 75: iIii1I11I1II1 / OoO0O00 * OOooOOo % O0
  if 82 - 82: Oo0Ooo / i1IIi . i1IIi / oO0o
  if 7 - 7: Oo0Ooo . iII111i % I1ii11iIi11i / iII111i
  oOIii11111iiI = lisp_rle ( "" )
  oo0o00000O0 = { }
  iIIiii = None
  for o0O0o in self . individual_registrations . values ( ) :
   if ( o0O0o . registered == False ) : continue
   Iii1IIIIi1 = o0O0o . registered_rlocs [ 0 ] . rle
   if ( Iii1IIIIi1 == None ) : continue
   if 83 - 83: iIii1I11I1II1
   iIIiii = o0O0o . registered_rlocs [ 0 ] . rloc_name
   for IIi1I1 in Iii1IIIIi1 . rle_nodes :
    I1Iii1I = IIi1I1 . address . print_address_no_iid ( )
    if ( oo0o00000O0 . has_key ( I1Iii1I ) ) : break
    if 19 - 19: oO0o . I1Ii111 - IiII * IiII - OoOoOO00 % iIii1I11I1II1
    II1ii = lisp_rle_node ( )
    II1ii . address . copy_address ( IIi1I1 . address )
    II1ii . level = IIi1I1 . level
    II1ii . rloc_name = iIIiii
    oOIii11111iiI . rle_nodes . append ( II1ii )
    oo0o00000O0 [ I1Iii1I ] = IIi1I1 . address
    if 77 - 77: II111iiii + OOooOOo % iII111i * O0 % i1IIi / I1Ii111
    if 39 - 39: II111iiii % OoOoOO00 / O0 / II111iiii
    if 15 - 15: I11i + I1IiiI / I11i + iIii1I11I1II1 * Oo0Ooo / I1ii11iIi11i
    if 8 - 8: ooOoO0o . O0 / OoO0O00
    if 50 - 50: Ii1I . OoOoOO00 * o0oOOo0O0Ooo
    if 68 - 68: IiII * oO0o / OoOoOO00 / I1Ii111
  if ( len ( oOIii11111iiI . rle_nodes ) == 0 ) : oOIii11111iiI = None
  if ( len ( self . registered_rlocs ) != 0 ) :
   self . registered_rlocs [ 0 ] . rle = oOIii11111iiI
   if ( iIIiii ) : self . registered_rlocs [ 0 ] . rloc_name = None
   if 72 - 72: I1ii11iIi11i
   if 74 - 74: I1Ii111 * iIii1I11I1II1 / oO0o - IiII - I1IiiI
   if 84 - 84: iIii1I11I1II1 % Oo0Ooo / I1ii11iIi11i + o0oOOo0O0Ooo * II111iiii
   if 81 - 81: I1IiiI / I1ii11iIi11i / OOooOOo
   if 89 - 89: Oo0Ooo % IiII
  if ( OooooOO0 . keys ( ) == oo0o00000O0 . keys ( ) ) : return ( False )
  if 36 - 36: IiII % OoOoOO00 % I1ii11iIi11i
  lprint ( "{} {} from {} to {}" . format ( green ( self . print_eid_tuple ( ) , False ) , bold ( "RLE change" , False ) ,
  # oO0o
 OooooOO0 . keys ( ) , oo0o00000O0 . keys ( ) ) )
  if 72 - 72: OoOoOO00 - O0 . O0 * oO0o
  return ( True )
  if 13 - 13: OoooooooOO / ooOoO0o + IiII / oO0o + oO0o
  if 78 - 78: iII111i * o0oOOo0O0Ooo + OOooOOo
 def add_cache ( self ) :
  if ( self . group . is_null ( ) ) :
   lisp_sites_by_eid . add_cache ( self . eid , self )
  else :
   I1i11I = lisp_sites_by_eid . lookup_cache ( self . group , True )
   if ( I1i11I == None ) :
    I1i11I = lisp_site_eid ( self . site )
    I1i11I . eid . copy_address ( self . group )
    I1i11I . group . copy_address ( self . group )
    lisp_sites_by_eid . add_cache ( self . group , I1i11I )
    if 39 - 39: ooOoO0o + o0oOOo0O0Ooo + OOooOOo * OoOoOO00
    if 98 - 98: iIii1I11I1II1 - oO0o
    if 91 - 91: iII111i % iII111i . ooOoO0o / iII111i
    if 29 - 29: OoooooooOO + i11iIiiIii
    if 11 - 11: OoooooooOO % oO0o - OoO0O00
    I1i11I . parent_for_more_specifics = self . parent_for_more_specifics
    if 49 - 49: ooOoO0o + iII111i % OoooooooOO / Oo0Ooo % i1IIi
   if ( self . eid . is_null ( ) ) : self . eid . make_default_route ( I1i11I . group )
   I1i11I . add_source_entry ( self )
   if 50 - 50: OoO0O00
   if 52 - 52: o0oOOo0O0Ooo + O0
   if 13 - 13: OoO0O00
 def delete_cache ( self ) :
  if ( self . group . is_null ( ) ) :
   lisp_sites_by_eid . delete_cache ( self . eid )
  else :
   I1i11I = lisp_sites_by_eid . lookup_cache ( self . group , True )
   if ( I1i11I == None ) : return
   if 56 - 56: OoOoOO00 . ooOoO0o * oO0o - I11i
   o0O0o = I1i11I . lookup_source_cache ( self . eid , True )
   if ( o0O0o == None ) : return
   if 47 - 47: oO0o . i1IIi * I1ii11iIi11i % OOooOOo % IiII / Oo0Ooo
   if ( I1i11I . source_cache == None ) : return
   if 39 - 39: i11iIiiIii . OOooOOo + Oo0Ooo
   I1i11I . source_cache . delete_cache ( self . eid )
   if ( I1i11I . source_cache . cache_size ( ) == 0 ) :
    lisp_sites_by_eid . delete_cache ( self . group )
    if 92 - 92: O0 * Oo0Ooo / o0oOOo0O0Ooo % OoO0O00
    if 87 - 87: OoooooooOO / I11i . O0
    if 77 - 77: OOooOOo + oO0o * iIii1I11I1II1 / oO0o / OOooOOo . i11iIiiIii
    if 92 - 92: Oo0Ooo . o0oOOo0O0Ooo % OoooooooOO * i11iIiiIii * OoO0O00 * o0oOOo0O0Ooo
 def add_source_entry ( self , source_se ) :
  if ( self . source_cache == None ) : self . source_cache = lisp_cache ( )
  self . source_cache . add_cache ( source_se . eid , source_se )
  if 48 - 48: iII111i * I1ii11iIi11i * oO0o % O0 . OoO0O00
  if 11 - 11: OOooOOo / o0oOOo0O0Ooo
 def lookup_source_cache ( self , source , exact ) :
  if ( self . source_cache == None ) : return ( None )
  return ( self . source_cache . lookup_cache ( source , exact ) )
  if 98 - 98: oO0o + I11i . oO0o
  if 10 - 10: iII111i + i1IIi . I11i % ooOoO0o / ooOoO0o
 def is_star_g ( self ) :
  if ( self . group . is_null ( ) ) : return ( False )
  return ( self . eid . is_exact_match ( self . group ) )
  if 86 - 86: Oo0Ooo
  if 7 - 7: iIii1I11I1II1
 def eid_record_matches ( self , eid_record ) :
  if ( self . eid . is_exact_match ( eid_record . eid ) == False ) : return ( False )
  if ( eid_record . group . is_null ( ) ) : return ( True )
  return ( eid_record . group . is_exact_match ( self . group ) )
  if 86 - 86: IiII + iII111i * II111iiii - IiII - o0oOOo0O0Ooo
  if 8 - 8: OOooOOo . Ii1I
 def inherit_from_ams_parent ( self ) :
  iiIo00ooO = self . parent_for_more_specifics
  if ( iiIo00ooO == None ) : return
  self . force_proxy_reply = iiIo00ooO . force_proxy_reply
  self . force_nat_proxy_reply = iiIo00ooO . force_nat_proxy_reply
  self . force_ttl = iiIo00ooO . force_ttl
  self . pitr_proxy_reply_drop = iiIo00ooO . pitr_proxy_reply_drop
  self . proxy_reply_action = iiIo00ooO . proxy_reply_action
  self . echo_nonce_capable = iiIo00ooO . echo_nonce_capable
  self . policy = iiIo00ooO . policy
  self . require_signature = iiIo00ooO . require_signature
  if 15 - 15: ooOoO0o / OOooOOo + i1IIi / Ii1I / OOooOOo
  if 47 - 47: Oo0Ooo + oO0o % OoooooooOO
 def rtrs_in_rloc_set ( self ) :
  for o0OO0O0OoOo0 in self . registered_rlocs :
   if ( o0OO0O0OoOo0 . is_rtr ( ) ) : return ( True )
   if 23 - 23: I1Ii111 / i11iIiiIii - ooOoO0o * iII111i - Ii1I . iIii1I11I1II1
  return ( False )
  if 11 - 11: I11i % OoOoOO00 * Oo0Ooo
  if 48 - 48: OOooOOo
 def is_rtr_in_rloc_set ( self , rtr_rloc ) :
  for o0OO0O0OoOo0 in self . registered_rlocs :
   if ( o0OO0O0OoOo0 . rloc . is_exact_match ( rtr_rloc ) == False ) : continue
   if ( o0OO0O0OoOo0 . is_rtr ( ) ) : return ( True )
   if 66 - 66: iII111i - I1Ii111 - i11iIiiIii . o0oOOo0O0Ooo + Oo0Ooo
  return ( False )
  if 90 - 90: O0 - i11iIiiIii * ooOoO0o . I1ii11iIi11i . Ii1I - OoooooooOO
  if 23 - 23: o0oOOo0O0Ooo
 def is_rloc_in_rloc_set ( self , rloc ) :
  for o0OO0O0OoOo0 in self . registered_rlocs :
   if ( o0OO0O0OoOo0 . rle ) :
    for oOIii11111iiI in o0OO0O0OoOo0 . rle . rle_nodes :
     if ( oOIii11111iiI . address . is_exact_match ( rloc ) ) : return ( True )
     if 88 - 88: I1Ii111 + iIii1I11I1II1 / o0oOOo0O0Ooo
     if 93 - 93: ooOoO0o % iIii1I11I1II1 - OOooOOo . IiII + ooOoO0o
   if ( o0OO0O0OoOo0 . rloc . is_exact_match ( rloc ) ) : return ( True )
   if 63 - 63: I1ii11iIi11i / OOooOOo
  return ( False )
  if 28 - 28: I11i / I1Ii111 + IiII * OoooooooOO - iIii1I11I1II1
  if 6 - 6: I11i % o0oOOo0O0Ooo / OoooooooOO . I1Ii111
 def do_rloc_sets_match ( self , prev_rloc_set ) :
  if ( len ( self . registered_rlocs ) != len ( prev_rloc_set ) ) : return ( False )
  if 17 - 17: I1ii11iIi11i + OoooooooOO / iIii1I11I1II1 . II111iiii + Oo0Ooo
  for o0OO0O0OoOo0 in prev_rloc_set :
   OOoo = o0OO0O0OoOo0 . rloc
   if ( self . is_rloc_in_rloc_set ( OOoo ) == False ) : return ( False )
   if 7 - 7: O0 - I1ii11iIi11i - iIii1I11I1II1
  return ( True )
  if 96 - 96: OoOoOO00 . I1IiiI . I11i * OoooooooOO + OoooooooOO * O0
  if 90 - 90: I11i + I1ii11iIi11i + OoooooooOO + OoOoOO00 + IiII / iII111i
  if 75 - 75: i11iIiiIii
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
   if 27 - 27: I11i - IiII - I1Ii111
  self . last_used = 0
  self . last_reply = 0
  self . last_nonce = 0
  self . map_requests_sent = 0
  self . neg_map_replies_received = 0
  self . total_rtt = 0
  if 90 - 90: OoO0O00 . oO0o * O0 / I11i % O0 + I1Ii111
  if 48 - 48: iIii1I11I1II1 . i11iIiiIii / OoooooooOO . i1IIi . o0oOOo0O0Ooo
 def resolve_dns_name ( self ) :
  if ( self . dns_name == None ) : return
  if ( self . last_dns_resolve and
 time . time ( ) - self . last_dns_resolve < 30 ) : return
  if 84 - 84: Ii1I
  try :
   iii11i1 = socket . gethostbyname_ex ( self . dns_name )
   self . last_dns_resolve = lisp_get_timestamp ( )
   oO0o00000o = iii11i1 [ 2 ]
  except :
   return
   if 10 - 10: IiII
   if 60 - 60: i1IIi + i1IIi
   if 47 - 47: iII111i - I1Ii111 - I1Ii111 . ooOoO0o
   if 5 - 5: i1IIi
   if 47 - 47: I11i * I11i . OoOoOO00
   if 68 - 68: OoooooooOO + OoOoOO00 + i11iIiiIii
  if ( len ( oO0o00000o ) <= self . a_record_index ) :
   self . delete_mr ( )
   return
   if 89 - 89: Oo0Ooo + Ii1I * O0 - I1Ii111
   if 33 - 33: iIii1I11I1II1 . I11i
  I1Iii1I = oO0o00000o [ self . a_record_index ]
  if ( I1Iii1I != self . map_resolver . print_address_no_iid ( ) ) :
   self . delete_mr ( )
   self . map_resolver . store_address ( I1Iii1I )
   self . insert_mr ( )
   if 63 - 63: oO0o - iII111i
   if 13 - 13: I1Ii111 / i1IIi % OoooooooOO / I11i
   if 66 - 66: I1Ii111 % o0oOOo0O0Ooo . iII111i . ooOoO0o + OOooOOo * II111iiii
   if 33 - 33: oO0o
   if 64 - 64: OoO0O00 % Oo0Ooo % I11i . iII111i % I1IiiI
   if 50 - 50: i1IIi + ooOoO0o - iIii1I11I1II1
  if ( lisp_is_decent_dns_suffix ( self . dns_name ) == False ) : return
  if ( self . a_record_index != 0 ) : return
  if 45 - 45: OoooooooOO / o0oOOo0O0Ooo / iII111i
  for I1Iii1I in oO0o00000o [ 1 : : ] :
   OOOO0o = lisp_address ( LISP_AFI_NONE , I1Iii1I , 0 , 0 )
   iiOoOoOoo0 = lisp_get_map_resolver ( OOOO0o , None )
   if ( iiOoOoOoo0 != None and iiOoOoOoo0 . a_record_index == oO0o00000o . index ( I1Iii1I ) ) :
    continue
    if 72 - 72: I1Ii111
   iiOoOoOoo0 = lisp_mr ( I1Iii1I , None , None )
   iiOoOoOoo0 . a_record_index = oO0o00000o . index ( I1Iii1I )
   iiOoOoOoo0 . dns_name = self . dns_name
   iiOoOoOoo0 . last_dns_resolve = lisp_get_timestamp ( )
   if 94 - 94: ooOoO0o . IiII - Ii1I + I1ii11iIi11i / ooOoO0o
   if 10 - 10: ooOoO0o . OOooOOo * O0 % II111iiii
   if 12 - 12: oO0o + I1IiiI * Oo0Ooo - iII111i
   if 88 - 88: OOooOOo . OoO0O00
   if 86 - 86: OoOoOO00 . o0oOOo0O0Ooo / ooOoO0o * I1IiiI . OoO0O00 / I1Ii111
  I1OOoO0OoOOo0 = [ ]
  for iiOoOoOoo0 in lisp_map_resolvers_list . values ( ) :
   if ( self . dns_name != iiOoOoOoo0 . dns_name ) : continue
   OOOO0o = iiOoOoOoo0 . map_resolver . print_address_no_iid ( )
   if ( OOOO0o in oO0o00000o ) : continue
   I1OOoO0OoOOo0 . append ( iiOoOoOoo0 )
   if 97 - 97: IiII - iII111i
  for iiOoOoOoo0 in I1OOoO0OoOOo0 : iiOoOoOoo0 . delete_mr ( )
  if 37 - 37: i1IIi * I1Ii111 / I11i * II111iiii + OoooooooOO . OoO0O00
  if 22 - 22: OoOoOO00 + OoooooooOO - I1Ii111
 def insert_mr ( self ) :
  OOoOoO = self . mr_name + self . map_resolver . print_address ( )
  lisp_map_resolvers_list [ OOoOoO ] = self
  if 82 - 82: Ii1I % I1Ii111 / ooOoO0o
  if 86 - 86: II111iiii - iIii1I11I1II1 + oO0o + I1IiiI
 def delete_mr ( self ) :
  OOoOoO = self . mr_name + self . map_resolver . print_address ( )
  if ( lisp_map_resolvers_list . has_key ( OOoOoO ) == False ) : return
  lisp_map_resolvers_list . pop ( OOoOoO )
  if 29 - 29: Ii1I % OoooooooOO * II111iiii
  if 88 - 88: I1Ii111 + I11i + I1Ii111 % OoO0O00 / I1ii11iIi11i - I11i
  if 15 - 15: Oo0Ooo - i1IIi
class lisp_ddt_root ( ) :
 def __init__ ( self ) :
  self . root_address = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . public_key = ""
  self . priority = 0
  self . weight = 0
  if 87 - 87: O0 . o0oOOo0O0Ooo % OOooOOo / I11i - I1Ii111 % i11iIiiIii
  if 3 - 3: oO0o + iII111i + OOooOOo
  if 54 - 54: i11iIiiIii + OoO0O00 - IiII - iII111i / I11i
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
  if 85 - 85: OOooOOo * OOooOOo * I1Ii111 - ooOoO0o . O0 % iII111i
  if 5 - 5: i1IIi * iII111i . o0oOOo0O0Ooo - I1ii11iIi11i
 def print_referral ( self , eid_indent , referral_indent ) :
  ooOO = lisp_print_elapsed ( self . uptime )
  OoO0O00oo00 = lisp_print_future ( self . expires )
  lprint ( "{}Referral EID {}, uptime/expires {}/{}, {} referrals:" . format ( eid_indent , green ( self . eid . print_prefix ( ) , False ) , ooOO ,
  # iIii1I11I1II1 - iIii1I11I1II1 * I1ii11iIi11i
 OoO0O00oo00 , len ( self . referral_set ) ) )
  if 96 - 96: iII111i / i11iIiiIii / oO0o + Oo0Ooo
  for i1I in self . referral_set . values ( ) :
   i1I . print_ref_node ( referral_indent )
   if 65 - 65: OoOoOO00
   if 87 - 87: I11i % i1IIi + i11iIiiIii * II111iiii
   if 58 - 58: OoO0O00 * I1IiiI - II111iiii / Ii1I - I1IiiI % OoooooooOO
 def print_referral_type ( self ) :
  if ( self . eid . afi == LISP_AFI_ULTIMATE_ROOT ) : return ( "root" )
  if ( self . referral_type == LISP_DDT_ACTION_NULL ) :
   return ( "null-referral" )
   if 33 - 33: IiII / i1IIi + I1Ii111
  if ( self . referral_type == LISP_DDT_ACTION_SITE_NOT_FOUND ) :
   return ( "no-site-action" )
   if 5 - 5: O0 / iII111i % II111iiii . Oo0Ooo - I11i
  if ( self . referral_type > LISP_DDT_ACTION_MAX ) :
   return ( "invalid-action" )
   if 84 - 84: oO0o * iII111i % i11iIiiIii - O0 . iIii1I11I1II1 - OoOoOO00
  return ( lisp_map_referral_action_string [ self . referral_type ] )
  if 73 - 73: OoOoOO00
  if 66 - 66: Oo0Ooo
 def print_eid_tuple ( self ) :
  return ( lisp_print_eid_tuple ( self . eid , self . group ) )
  if 42 - 42: i11iIiiIii / II111iiii . OOooOOo
  if 65 - 65: OoOoOO00 % II111iiii + Oo0Ooo
 def print_ttl ( self ) :
  I1i11iiIiIi = self . referral_ttl
  if ( I1i11iiIiIi < 60 ) : return ( str ( I1i11iiIiIi ) + " secs" )
  if 24 - 24: OoO0O00 % OoooooooOO
  if ( ( I1i11iiIiIi % 60 ) == 0 ) :
   I1i11iiIiIi = str ( I1i11iiIiIi / 60 ) + " mins"
  else :
   I1i11iiIiIi = str ( I1i11iiIiIi ) + " secs"
   if 16 - 16: OoOoOO00 % Oo0Ooo * OoOoOO00 . Ii1I
  return ( I1i11iiIiIi )
  if 91 - 91: I1Ii111 - OoooooooOO . i1IIi . I1ii11iIi11i
  if 37 - 37: IiII - oO0o
 def is_referral_negative ( self ) :
  return ( self . referral_type in ( LISP_DDT_ACTION_MS_NOT_REG , LISP_DDT_ACTION_DELEGATION_HOLE ,
  # I1IiiI . oO0o - OoO0O00 + Oo0Ooo - OOooOOo + I1ii11iIi11i
 LISP_DDT_ACTION_NOT_AUTH ) )
  if 32 - 32: I1ii11iIi11i % OoOoOO00 + Oo0Ooo
  if 92 - 92: II111iiii . O0 . iIii1I11I1II1 % IiII - i11iIiiIii
 def add_cache ( self ) :
  if ( self . group . is_null ( ) ) :
   lisp_referral_cache . add_cache ( self . eid , self )
  else :
   iI1OO0o00 = lisp_referral_cache . lookup_cache ( self . group , True )
   if ( iI1OO0o00 == None ) :
    iI1OO0o00 = lisp_referral ( )
    iI1OO0o00 . eid . copy_address ( self . group )
    iI1OO0o00 . group . copy_address ( self . group )
    lisp_referral_cache . add_cache ( self . group , iI1OO0o00 )
    if 9 - 9: OoO0O00
   if ( self . eid . is_null ( ) ) : self . eid . make_default_route ( iI1OO0o00 . group )
   iI1OO0o00 . add_source_entry ( self )
   if 60 - 60: O0 / OoOoOO00 % i11iIiiIii % II111iiii / OoooooooOO
   if 52 - 52: ooOoO0o
   if 100 - 100: Oo0Ooo - o0oOOo0O0Ooo + iIii1I11I1II1 / ooOoO0o % iIii1I11I1II1
 def delete_cache ( self ) :
  if ( self . group . is_null ( ) ) :
   lisp_referral_cache . delete_cache ( self . eid )
  else :
   iI1OO0o00 = lisp_referral_cache . lookup_cache ( self . group , True )
   if ( iI1OO0o00 == None ) : return
   if 4 - 4: OoOoOO00 / Oo0Ooo - OoO0O00 . OoOoOO00 / I1Ii111
   o00O0o = iI1OO0o00 . lookup_source_cache ( self . eid , True )
   if ( o00O0o == None ) : return
   if 60 - 60: OOooOOo * I1Ii111
   iI1OO0o00 . source_cache . delete_cache ( self . eid )
   if ( iI1OO0o00 . source_cache . cache_size ( ) == 0 ) :
    lisp_referral_cache . delete_cache ( self . group )
    if 17 - 17: iII111i * I11i / iIii1I11I1II1 - II111iiii
    if 97 - 97: II111iiii * o0oOOo0O0Ooo
    if 13 - 13: o0oOOo0O0Ooo . II111iiii
    if 76 - 76: II111iiii + I1Ii111 . OoooooooOO / IiII % i11iIiiIii
 def add_source_entry ( self , source_ref ) :
  if ( self . source_cache == None ) : self . source_cache = lisp_cache ( )
  self . source_cache . add_cache ( source_ref . eid , source_ref )
  if 87 - 87: Ii1I / OoOoOO00 / OOooOOo
  if 11 - 11: o0oOOo0O0Ooo * OoO0O00 . o0oOOo0O0Ooo - I1IiiI / IiII - OOooOOo
 def lookup_source_cache ( self , source , exact ) :
  if ( self . source_cache == None ) : return ( None )
  return ( self . source_cache . lookup_cache ( source , exact ) )
  if 19 - 19: i1IIi + IiII . OoO0O00 / O0 - I1Ii111 - Oo0Ooo
  if 24 - 24: iII111i + i1IIi
  if 31 - 31: OoOoOO00
class lisp_referral_node ( ) :
 def __init__ ( self ) :
  self . referral_address = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . priority = 0
  self . weight = 0
  self . updown = True
  self . map_requests_sent = 0
  self . no_responses = 0
  self . uptime = lisp_get_timestamp ( )
  if 37 - 37: iIii1I11I1II1 % IiII / i11iIiiIii - oO0o
  if 43 - 43: II111iiii - OoooooooOO
 def print_ref_node ( self , indent ) :
  III11I1 = lisp_print_elapsed ( self . uptime )
  lprint ( "{}referral {}, uptime {}, {}, priority/weight: {}/{}" . format ( indent , red ( self . referral_address . print_address ( ) , False ) , III11I1 ,
  # i11iIiiIii
 "up" if self . updown else "down" , self . priority , self . weight ) )
  if 35 - 35: oO0o - Ii1I * i11iIiiIii / I1Ii111 + oO0o
  if 22 - 22: OoO0O00 + I1IiiI * Oo0Ooo . O0
  if 75 - 75: iII111i * II111iiii - I1IiiI
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
   if 30 - 30: i1IIi / ooOoO0o . ooOoO0o
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
   if 22 - 22: I11i % iIii1I11I1II1 - i11iIiiIii * OoOoOO00 - I1Ii111
   if 97 - 97: i11iIiiIii . OoOoOO00 + oO0o * O0 % OoO0O00 - Ii1I
   if 46 - 46: I1Ii111
 def resolve_dns_name ( self ) :
  if ( self . dns_name == None ) : return
  if ( self . last_dns_resolve and
 time . time ( ) - self . last_dns_resolve < 30 ) : return
  if 87 - 87: o0oOOo0O0Ooo - iII111i * OoO0O00 * o0oOOo0O0Ooo . o0oOOo0O0Ooo / OOooOOo
  try :
   iii11i1 = socket . gethostbyname_ex ( self . dns_name )
   self . last_dns_resolve = lisp_get_timestamp ( )
   oO0o00000o = iii11i1 [ 2 ]
  except :
   return
   if 50 - 50: i11iIiiIii - II111iiii * OoooooooOO + II111iiii - ooOoO0o
   if 52 - 52: i1IIi + i1IIi * i1IIi / OoOoOO00
   if 98 - 98: iII111i . i1IIi + o0oOOo0O0Ooo * OoooooooOO - i11iIiiIii
   if 21 - 21: i11iIiiIii . oO0o * o0oOOo0O0Ooo + Oo0Ooo * OoOoOO00 * o0oOOo0O0Ooo
   if 33 - 33: I1IiiI + O0 - I11i
   if 90 - 90: I1Ii111 * OoooooooOO . iIii1I11I1II1 % OoO0O00 / I11i + iII111i
  if ( len ( oO0o00000o ) <= self . a_record_index ) :
   self . delete_ms ( )
   return
   if 63 - 63: o0oOOo0O0Ooo . IiII . Oo0Ooo - iIii1I11I1II1 / I1Ii111
   if 66 - 66: ooOoO0o * I1Ii111 - II111iiii
  I1Iii1I = oO0o00000o [ self . a_record_index ]
  if ( I1Iii1I != self . map_server . print_address_no_iid ( ) ) :
   self . delete_ms ( )
   self . map_server . store_address ( I1Iii1I )
   self . insert_ms ( )
   if 38 - 38: O0 % I1ii11iIi11i + O0
   if 37 - 37: Oo0Ooo / I1IiiI
   if 23 - 23: II111iiii / iII111i
   if 55 - 55: i11iIiiIii - Ii1I % OoooooooOO * OoooooooOO
   if 92 - 92: iIii1I11I1II1
   if 47 - 47: Oo0Ooo + Oo0Ooo * ooOoO0o - OoOoOO00 + II111iiii
  if ( lisp_is_decent_dns_suffix ( self . dns_name ) == False ) : return
  if ( self . a_record_index != 0 ) : return
  if 10 - 10: II111iiii / ooOoO0o . Ii1I / I1Ii111 / oO0o
  for I1Iii1I in oO0o00000o [ 1 : : ] :
   OOOO0o = lisp_address ( LISP_AFI_NONE , I1Iii1I , 0 , 0 )
   ooo0OoOOo = lisp_get_map_server ( OOOO0o )
   if ( ooo0OoOOo != None and ooo0OoOOo . a_record_index == oO0o00000o . index ( I1Iii1I ) ) :
    continue
    if 8 - 8: OOooOOo / ooOoO0o * I11i + OOooOOo * i1IIi
   ooo0OoOOo = copy . deepcopy ( self )
   ooo0OoOOo . map_server . store_address ( I1Iii1I )
   ooo0OoOOo . a_record_index = oO0o00000o . index ( I1Iii1I )
   ooo0OoOOo . last_dns_resolve = lisp_get_timestamp ( )
   ooo0OoOOo . insert_ms ( )
   if 48 - 48: o0oOOo0O0Ooo - I1ii11iIi11i / iII111i
   if 63 - 63: O0 - IiII . OOooOOo % IiII . I1IiiI / oO0o
   if 79 - 79: OoOoOO00
   if 88 - 88: oO0o * o0oOOo0O0Ooo
   if 5 - 5: I11i - I1Ii111 * I11i - II111iiii + OOooOOo + II111iiii
  I1OOoO0OoOOo0 = [ ]
  for ooo0OoOOo in lisp_map_servers_list . values ( ) :
   if ( self . dns_name != ooo0OoOOo . dns_name ) : continue
   OOOO0o = ooo0OoOOo . map_server . print_address_no_iid ( )
   if ( OOOO0o in oO0o00000o ) : continue
   I1OOoO0OoOOo0 . append ( ooo0OoOOo )
   if 91 - 91: i1IIi + Oo0Ooo - I1ii11iIi11i + I1ii11iIi11i * O0 / O0
  for ooo0OoOOo in I1OOoO0OoOOo0 : ooo0OoOOo . delete_ms ( )
  if 78 - 78: OoooooooOO
  if 8 - 8: Oo0Ooo - Oo0Ooo % O0 - Ii1I / o0oOOo0O0Ooo % Oo0Ooo
 def insert_ms ( self ) :
  OOoOoO = self . ms_name + self . map_server . print_address ( )
  lisp_map_servers_list [ OOoOoO ] = self
  if 51 - 51: iIii1I11I1II1 / iIii1I11I1II1 * I1ii11iIi11i / I11i
  if 18 - 18: Ii1I - i11iIiiIii + OoO0O00 . O0 - iII111i
 def delete_ms ( self ) :
  OOoOoO = self . ms_name + self . map_server . print_address ( )
  if ( lisp_map_servers_list . has_key ( OOoOoO ) == False ) : return
  lisp_map_servers_list . pop ( OOoOoO )
  if 9 - 9: OoooooooOO / iII111i + o0oOOo0O0Ooo / II111iiii / I1Ii111
  if 44 - 44: I1IiiI / iII111i / Oo0Ooo
  if 66 - 66: I1Ii111 + OoooooooOO % I1IiiI . iII111i * Oo0Ooo + o0oOOo0O0Ooo
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
  if 96 - 96: OoO0O00 - ooOoO0o * Ii1I
  if 34 - 34: OoO0O00 . Oo0Ooo % Ii1I . IiII + OoOoOO00
 def add_interface ( self ) :
  lisp_myinterfaces [ self . device ] = self
  if 10 - 10: OoooooooOO * iII111i * ooOoO0o . Ii1I % I1Ii111 / I1ii11iIi11i
  if 71 - 71: Ii1I + IiII
 def get_instance_id ( self ) :
  return ( self . instance_id )
  if 10 - 10: II111iiii % o0oOOo0O0Ooo . o0oOOo0O0Ooo % iII111i
  if 2 - 2: OoooooooOO / IiII % Oo0Ooo % iIii1I11I1II1
 def get_socket ( self ) :
  return ( self . raw_socket )
  if 62 - 62: oO0o
  if 47 - 47: I1IiiI - O0 - I1ii11iIi11i . OoOoOO00
 def get_bridge_socket ( self ) :
  return ( self . bridge_socket )
  if 98 - 98: o0oOOo0O0Ooo - OoO0O00 . I1ii11iIi11i / OOooOOo
  if 43 - 43: I1IiiI + OOooOOo + o0oOOo0O0Ooo
 def does_dynamic_eid_match ( self , eid ) :
  if ( self . dynamic_eid . is_null ( ) ) : return ( False )
  return ( eid . is_more_specific ( self . dynamic_eid ) )
  if 44 - 44: o0oOOo0O0Ooo % OoO0O00 . OoooooooOO
  if 21 - 21: Oo0Ooo * Oo0Ooo - iII111i - O0
 def set_socket ( self , device ) :
  i1I1iIi1IiI = socket . socket ( socket . AF_INET , socket . SOCK_RAW , socket . IPPROTO_RAW )
  i1I1iIi1IiI . setsockopt ( socket . SOL_IP , socket . IP_HDRINCL , 1 )
  try :
   i1I1iIi1IiI . setsockopt ( socket . SOL_SOCKET , socket . SO_BINDTODEVICE , device )
  except :
   i1I1iIi1IiI . close ( )
   i1I1iIi1IiI = None
   if 87 - 87: OOooOOo / I1Ii111 - Ii1I + O0 - oO0o - O0
  self . raw_socket = i1I1iIi1IiI
  if 68 - 68: iII111i + II111iiii + I1ii11iIi11i * OOooOOo / oO0o
  if 41 - 41: OOooOOo + Oo0Ooo % I1IiiI
 def set_bridge_socket ( self , device ) :
  i1I1iIi1IiI = socket . socket ( socket . PF_PACKET , socket . SOCK_RAW )
  try :
   i1I1iIi1IiI = i1I1iIi1IiI . bind ( ( device , 0 ) )
   self . bridge_socket = i1I1iIi1IiI
  except :
   return
   if 3 - 3: ooOoO0o * Ii1I
   if 29 - 29: OoooooooOO + OOooOOo
   if 68 - 68: O0 + IiII / iII111i - OoOoOO00
   if 5 - 5: I1IiiI * OoooooooOO - II111iiii
class lisp_datetime ( ) :
 def __init__ ( self , datetime_str ) :
  self . datetime_name = datetime_str
  self . datetime = None
  self . parse_datetime ( )
  if 64 - 64: i1IIi
  if 77 - 77: OOooOOo - i1IIi / II111iiii . I1Ii111 + O0
 def valid_datetime ( self ) :
  ii1iIiI111 = self . datetime_name
  if ( ii1iIiI111 . find ( ":" ) == - 1 ) : return ( False )
  if ( ii1iIiI111 . find ( "-" ) == - 1 ) : return ( False )
  iiIoo00oOOoOo , oooo0O00oO0o0 , ooO0o , time = ii1iIiI111 [ 0 : 4 ] , ii1iIiI111 [ 5 : 7 ] , ii1iIiI111 [ 8 : 10 ] , ii1iIiI111 [ 11 : : ]
  if 58 - 58: II111iiii . oO0o + O0
  if ( ( iiIoo00oOOoOo + oooo0O00oO0o0 + ooO0o ) . isdigit ( ) == False ) : return ( False )
  if ( oooo0O00oO0o0 < "01" and oooo0O00oO0o0 > "12" ) : return ( False )
  if ( ooO0o < "01" and ooO0o > "31" ) : return ( False )
  if 59 - 59: I1Ii111
  oO0o0Oo0OO , OO0O00Oo , Iiiiii1Iiiii = time . split ( ":" )
  if 41 - 41: i11iIiiIii / ooOoO0o - Ii1I + I11i
  if ( ( oO0o0Oo0OO + OO0O00Oo + Iiiiii1Iiiii ) . isdigit ( ) == False ) : return ( False )
  if ( oO0o0Oo0OO < "00" and oO0o0Oo0OO > "23" ) : return ( False )
  if ( OO0O00Oo < "00" and OO0O00Oo > "59" ) : return ( False )
  if ( Iiiiii1Iiiii < "00" and Iiiiii1Iiiii > "59" ) : return ( False )
  return ( True )
  if 15 - 15: I1ii11iIi11i
  if 22 - 22: iIii1I11I1II1 - i1IIi - i11iIiiIii / I1IiiI + o0oOOo0O0Ooo
 def parse_datetime ( self ) :
  ooo0oOO0O0O0o = self . datetime_name
  ooo0oOO0O0O0o = ooo0oOO0O0O0o . replace ( "-" , "" )
  ooo0oOO0O0O0o = ooo0oOO0O0O0o . replace ( ":" , "" )
  self . datetime = int ( ooo0oOO0O0O0o )
  if 96 - 96: I11i - II111iiii
  if 66 - 66: OoooooooOO * OoooooooOO
 def now ( self ) :
  III11I1 = datetime . datetime . now ( ) . strftime ( "%Y-%m-%d-%H:%M:%S" )
  III11I1 = lisp_datetime ( III11I1 )
  return ( III11I1 )
  if 54 - 54: iII111i / OoO0O00 . O0 * iII111i % OoOoOO00 % iIii1I11I1II1
  if 37 - 37: iII111i - ooOoO0o * Ii1I + II111iiii * i11iIiiIii
 def print_datetime ( self ) :
  return ( self . datetime_name )
  if 8 - 8: OoooooooOO % I11i - iII111i * OOooOOo . O0
  if 40 - 40: I1Ii111 . oO0o + OoO0O00 % Oo0Ooo / II111iiii
 def future ( self ) :
  return ( self . datetime > self . now ( ) . datetime )
  if 19 - 19: i11iIiiIii
  if 20 - 20: i11iIiiIii . II111iiii - I1ii11iIi11i / ooOoO0o % i11iIiiIii
 def past ( self ) :
  return ( self . future ( ) == False )
  if 35 - 35: Oo0Ooo - I1ii11iIi11i . Oo0Ooo
  if 13 - 13: II111iiii / OoOoOO00 * iII111i % O0 % I1ii11iIi11i * i11iIiiIii
 def now_in_range ( self , upper ) :
  return ( self . past ( ) and upper . future ( ) )
  if 92 - 92: i11iIiiIii + OoO0O00
  if 94 - 94: I1ii11iIi11i + OoO0O00 . II111iiii + oO0o . II111iiii
 def this_year ( self ) :
  oOOO0O0ooOoOoo0 = str ( self . now ( ) . datetime ) [ 0 : 4 ]
  III11I1 = str ( self . datetime ) [ 0 : 4 ]
  return ( III11I1 == oOOO0O0ooOoOoo0 )
  if 73 - 73: OoOoOO00
  if 42 - 42: I1ii11iIi11i - iIii1I11I1II1 . Ii1I % OoO0O00 % i11iIiiIii * i11iIiiIii
 def this_month ( self ) :
  oOOO0O0ooOoOoo0 = str ( self . now ( ) . datetime ) [ 0 : 6 ]
  III11I1 = str ( self . datetime ) [ 0 : 6 ]
  return ( III11I1 == oOOO0O0ooOoOoo0 )
  if 86 - 86: Oo0Ooo % iIii1I11I1II1 . II111iiii / I11i % OoO0O00 % OoO0O00
  if 40 - 40: o0oOOo0O0Ooo . iIii1I11I1II1 * Oo0Ooo * i1IIi
 def today ( self ) :
  oOOO0O0ooOoOoo0 = str ( self . now ( ) . datetime ) [ 0 : 8 ]
  III11I1 = str ( self . datetime ) [ 0 : 8 ]
  return ( III11I1 == oOOO0O0ooOoOoo0 )
  if 94 - 94: oO0o - II111iiii + OoOoOO00
  if 90 - 90: Oo0Ooo + Oo0Ooo + I1Ii111
  if 81 - 81: i1IIi % iIii1I11I1II1 % Ii1I * ooOoO0o % i1IIi * I1IiiI
  if 15 - 15: ooOoO0o
  if 26 - 26: IiII % ooOoO0o / OOooOOo
  if 14 - 14: i11iIiiIii . I1ii11iIi11i
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
  if 20 - 20: O0 . iIii1I11I1II1 * I1ii11iIi11i - O0 + I1ii11iIi11i / I1IiiI
  if 67 - 67: OoO0O00 / OoOoOO00 / i11iIiiIii % OoOoOO00
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
  if 54 - 54: o0oOOo0O0Ooo . i11iIiiIii + I1IiiI * ooOoO0o - ooOoO0o
  if 28 - 28: I1Ii111 . i11iIiiIii * oO0o % ooOoO0o / iII111i . OOooOOo
 def match_policy_map_request ( self , mr , srloc ) :
  for II1111 in self . match_clauses :
   OoOOOOo = II1111 . source_eid
   iiIi1Ii1ii1 = mr . source_eid
   if ( OoOOOOo and iiIi1Ii1ii1 and iiIi1Ii1ii1 . is_more_specific ( OoOOOOo ) == False ) : continue
   if 57 - 57: OoooooooOO . iIii1I11I1II1 % iII111i % Oo0Ooo
   OoOOOOo = II1111 . dest_eid
   iiIi1Ii1ii1 = mr . target_eid
   if ( OoOOOOo and iiIi1Ii1ii1 and iiIi1Ii1ii1 . is_more_specific ( OoOOOOo ) == False ) : continue
   if 92 - 92: I1Ii111 - Ii1I + I1Ii111
   OoOOOOo = II1111 . source_rloc
   iiIi1Ii1ii1 = srloc
   if ( OoOOOOo and iiIi1Ii1ii1 and iiIi1Ii1ii1 . is_more_specific ( OoOOOOo ) == False ) : continue
   o0Oo = II1111 . datetime_lower
   IIioO = II1111 . datetime_upper
   if ( o0Oo and IIioO and o0Oo . now_in_range ( IIioO ) == False ) : continue
   return ( True )
   if 11 - 11: iIii1I11I1II1 . i1IIi . OOooOOo
  return ( False )
  if 21 - 21: II111iiii . ooOoO0o
  if 70 - 70: OoooooooOO + OoO0O00 . iII111i . ooOoO0o
 def set_policy_map_reply ( self ) :
  i11IIiiIIiII = ( self . set_rloc_address == None and
 self . set_rloc_record_name == None and self . set_geo_name == None and
 self . set_elp_name == None and self . set_rle_name == None )
  if ( i11IIiiIIiII ) : return ( None )
  if 77 - 77: i1IIi . I1IiiI
  II1iIiIiIIi = lisp_rloc ( )
  if ( self . set_rloc_address ) :
   II1iIiIiIIi . rloc . copy_address ( self . set_rloc_address )
   I1Iii1I = II1iIiIiIIi . rloc . print_address_no_iid ( )
   lprint ( "Policy set-rloc-address to {}" . format ( I1Iii1I ) )
   if 59 - 59: O0 + OoooooooOO - i1IIi
  if ( self . set_rloc_record_name ) :
   II1iIiIiIIi . rloc_name = self . set_rloc_record_name
   IiiIi1II = blue ( II1iIiIiIIi . rloc_name , False )
   lprint ( "Policy set-rloc-record-name to {}" . format ( IiiIi1II ) )
   if 87 - 87: IiII * OoooooooOO / Oo0Ooo % iIii1I11I1II1 % oO0o
  if ( self . set_geo_name ) :
   II1iIiIiIIi . geo_name = self . set_geo_name
   IiiIi1II = II1iIiIiIIi . geo_name
   O0ooo0oOo0O = "" if lisp_geo_list . has_key ( IiiIi1II ) else "(not configured)"
   if 12 - 12: I1IiiI
   lprint ( "Policy set-geo-name '{}' {}" . format ( IiiIi1II , O0ooo0oOo0O ) )
   if 99 - 99: II111iiii - OoOoOO00
  if ( self . set_elp_name ) :
   II1iIiIiIIi . elp_name = self . set_elp_name
   IiiIi1II = II1iIiIiIIi . elp_name
   O0ooo0oOo0O = "" if lisp_elp_list . has_key ( IiiIi1II ) else "(not configured)"
   if 22 - 22: i11iIiiIii * II111iiii
   lprint ( "Policy set-elp-name '{}' {}" . format ( IiiIi1II , O0ooo0oOo0O ) )
   if 11 - 11: Oo0Ooo % i1IIi
  if ( self . set_rle_name ) :
   II1iIiIiIIi . rle_name = self . set_rle_name
   IiiIi1II = II1iIiIiIIi . rle_name
   O0ooo0oOo0O = "" if lisp_rle_list . has_key ( IiiIi1II ) else "(not configured)"
   if 70 - 70: II111iiii * Oo0Ooo * OOooOOo - I1IiiI + iIii1I11I1II1 + ooOoO0o
   lprint ( "Policy set-rle-name '{}' {}" . format ( IiiIi1II , O0ooo0oOo0O ) )
   if 27 - 27: I1ii11iIi11i - I1Ii111 * O0 % ooOoO0o / I1IiiI
  if ( self . set_json_name ) :
   II1iIiIiIIi . json_name = self . set_json_name
   IiiIi1II = II1iIiIiIIi . json_name
   O0ooo0oOo0O = "" if lisp_json_list . has_key ( IiiIi1II ) else "(not configured)"
   if 53 - 53: i11iIiiIii * i11iIiiIii % O0 % IiII
   lprint ( "Policy set-json-name '{}' {}" . format ( IiiIi1II , O0ooo0oOo0O ) )
   if 57 - 57: I1IiiI % i1IIi * OoO0O00 + I1Ii111 . I11i % I11i
  return ( II1iIiIiIIi )
  if 69 - 69: I1ii11iIi11i / OoOoOO00 + iIii1I11I1II1
  if 8 - 8: OoooooooOO
 def save_policy ( self ) :
  lisp_policies [ self . policy_name ] = self
  if 72 - 72: OoooooooOO % I1ii11iIi11i - OoO0O00 . OoooooooOO
  if 83 - 83: o0oOOo0O0Ooo * Ii1I - Oo0Ooo * iII111i - i11iIiiIii
  if 6 - 6: I1IiiI + i11iIiiIii + O0 / i1IIi
class lisp_pubsub ( ) :
 def __init__ ( self , itr , port , nonce , ttl , xtr_id ) :
  self . itr = itr
  self . port = port
  self . nonce = nonce
  self . uptime = lisp_get_timestamp ( )
  self . ttl = ttl
  self . xtr_id = xtr_id
  self . map_notify_count = 0
  if 50 - 50: iII111i . II111iiii % I1Ii111 % I1IiiI / o0oOOo0O0Ooo . I1IiiI
  if 76 - 76: OOooOOo % iII111i
 def add ( self , eid_prefix ) :
  I1i11iiIiIi = self . ttl
  III1II1I1iI = eid_prefix . print_prefix ( )
  if ( lisp_pubsub_cache . has_key ( III1II1I1iI ) == False ) :
   lisp_pubsub_cache [ III1II1I1iI ] = { }
   if 80 - 80: iIii1I11I1II1 + o0oOOo0O0Ooo + iIii1I11I1II1
  OOO0OOoo = lisp_pubsub_cache [ III1II1I1iI ]
  if 63 - 63: OoOoOO00 - o0oOOo0O0Ooo % II111iiii - Ii1I
  o00OO0OO0O = "Add"
  if ( OOO0OOoo . has_key ( self . xtr_id ) ) :
   o00OO0OO0O = "Replace"
   del ( OOO0OOoo [ self . xtr_id ] )
   if 19 - 19: I1IiiI - iII111i - oO0o / II111iiii
  OOO0OOoo [ self . xtr_id ] = self
  if 98 - 98: IiII * OoOoOO00
  III1II1I1iI = green ( III1II1I1iI , False )
  Ii1ii1Ii11 = red ( self . itr . print_address_no_iid ( ) , False )
  I1i1i1 = "0x" + lisp_hex_string ( self . xtr_id )
  lprint ( "{} pubsub state {} for {}, xtr-id: {}, ttl {}" . format ( o00OO0OO0O , III1II1I1iI ,
 Ii1ii1Ii11 , I1i1i1 , I1i11iiIiIi ) )
  if 13 - 13: O0 + oO0o - iIii1I11I1II1 - Oo0Ooo % I1IiiI
  if 45 - 45: O0
 def delete ( self , eid_prefix ) :
  III1II1I1iI = eid_prefix . print_prefix ( )
  Ii1ii1Ii11 = red ( self . itr . print_address_no_iid ( ) , False )
  I1i1i1 = "0x" + lisp_hex_string ( self . xtr_id )
  if ( lisp_pubsub_cache . has_key ( III1II1I1iI ) ) :
   OOO0OOoo = lisp_pubsub_cache [ III1II1I1iI ]
   if ( OOO0OOoo . has_key ( self . xtr_id ) ) :
    OOO0OOoo . pop ( self . xtr_id )
    lprint ( "Remove pubsub state {} for {}, xtr-id: {}" . format ( III1II1I1iI ,
 Ii1ii1Ii11 , I1i1i1 ) )
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
  I1I = socket . htonl ( 0x90000000 )
  I111 = struct . pack ( "II" , I1I , 0 )
  I111 += struct . pack ( "Q" , self . nonce )
  I111 += json . dumps ( self . packet_json )
  return ( I111 )
  if 95 - 95: OoooooooOO % I1ii11iIi11i . I1Ii111 . IiII
  if 98 - 98: OoooooooOO - OoO0O00 . oO0o - iIii1I11I1II1 * iIii1I11I1II1 % Ii1I
 def decode ( self , packet ) :
  o0o0 = "I"
  O0ooO = struct . calcsize ( o0o0 )
  if ( len ( packet ) < O0ooO ) : return ( False )
  I1I = struct . unpack ( o0o0 , packet [ : O0ooO ] ) [ 0 ]
  packet = packet [ O0ooO : : ]
  I1I = socket . ntohl ( I1I )
  if ( ( I1I & 0xff000000 ) != 0x90000000 ) : return ( False )
  if 87 - 87: O0 % iII111i
  if ( len ( packet ) < O0ooO ) : return ( False )
  I1Iii1I = struct . unpack ( o0o0 , packet [ : O0ooO ] ) [ 0 ]
  packet = packet [ O0ooO : : ]
  if 57 - 57: Ii1I
  I1Iii1I = socket . ntohl ( I1Iii1I )
  ii11IIIIi1 = I1Iii1I >> 24
  IiIiiIi1i1 = ( I1Iii1I >> 16 ) & 0xff
  iIiiI = ( I1Iii1I >> 8 ) & 0xff
  O0o00o0 = I1Iii1I & 0xff
  self . local_rloc = "{}.{}.{}.{}" . format ( ii11IIIIi1 , IiIiiIi1i1 , iIiiI , O0o00o0 )
  self . local_port = str ( I1I & 0xffff )
  if 57 - 57: i1IIi / I11i + OoO0O00 * OOooOOo + OoooooooOO
  o0o0 = "Q"
  O0ooO = struct . calcsize ( o0o0 )
  if ( len ( packet ) < O0ooO ) : return ( False )
  self . nonce = struct . unpack ( o0o0 , packet [ : O0ooO ] ) [ 0 ]
  packet = packet [ O0ooO : : ]
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
  II1iIiIiIIi , II11i = self . rtr_cache_nat_trace_find ( rts_rloc )
  if ( II1iIiIiIIi == None ) :
   II1iIiIiIIi , II11i = rts_rloc . split ( ":" )
   II11i = int ( II11i )
   lprint ( "Send LISP-Trace to address {}:{}" . format ( II1iIiIiIIi , II11i ) )
  else :
   lprint ( "Send LISP-Trace to translated address {}:{}" . format ( II1iIiIiIIi ,
 II11i ) )
   if 27 - 27: I11i % Ii1I / iII111i . OoOoOO00
   if 88 - 88: iII111i - i11iIiiIii * I1Ii111 * i11iIiiIii - O0
  if ( lisp_socket == None ) :
   i1I1iIi1IiI = socket . socket ( socket . AF_INET , socket . SOCK_DGRAM )
   i1I1iIi1IiI . bind ( ( "0.0.0.0" , LISP_TRACE_PORT ) )
   i1I1iIi1IiI . sendto ( packet , ( II1iIiIiIIi , II11i ) )
   i1I1iIi1IiI . close ( )
  else :
   lisp_socket . sendto ( packet , ( II1iIiIiIIi , II11i ) )
   if 8 - 8: oO0o + O0
   if 52 - 52: I11i * OOooOOo - OoOoOO00 % iIii1I11I1II1 . II111iiii
   if 1 - 1: OOooOOo / I1IiiI / Ii1I * iII111i
 def packet_length ( self ) :
  O00oo0O00 = 8 ; i11I1iII = 4 + 4 + 8
  return ( O00oo0O00 + i11I1iII + len ( json . dumps ( self . packet_json ) ) )
  if 69 - 69: IiII + I1Ii111 - I1IiiI . iII111i . OoooooooOO
  if 88 - 88: i11iIiiIii
 def rtr_cache_nat_trace ( self , translated_rloc , translated_port ) :
  OOoOoO = self . local_rloc + ":" + self . local_port
  oOOO = ( translated_rloc , translated_port )
  lisp_rtr_nat_trace_cache [ OOoOoO ] = oOOO
  lprint ( "Cache NAT Trace addresses {} -> {}" . format ( OOoOoO , oOOO ) )
  if 54 - 54: OOooOOo % oO0o * Ii1I / I1IiiI
  if 46 - 46: o0oOOo0O0Ooo . ooOoO0o / Ii1I
 def rtr_cache_nat_trace_find ( self , local_rloc_and_port ) :
  OOoOoO = local_rloc_and_port
  try : oOOO = lisp_rtr_nat_trace_cache [ OOoOoO ]
  except : oOOO = ( None , None )
  return ( oOOO )
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
 for ooo0OoOOo in lisp_map_servers_list . values ( ) :
  if ( ooo0OoOOo . map_server . is_exact_match ( address ) ) : return ( ooo0OoOOo )
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
 for ooo0OoOOo in lisp_map_servers_list . values ( ) : return ( ooo0OoOOo )
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
  I1Iii1I = address . print_address ( )
  iiOoOoOoo0 = None
  for OOoOoO in lisp_map_resolvers_list :
   if ( OOoOoO . find ( I1Iii1I ) == - 1 ) : continue
   iiOoOoOoo0 = lisp_map_resolvers_list [ OOoOoO ]
   if 14 - 14: I1ii11iIi11i . OoO0O00
  return ( iiOoOoOoo0 )
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
  o0O00o = lisp_db_for_lookups . lookup_cache ( eid , False )
  iiiIIi1Iii = "all" if o0O00o == None else o0O00o . use_mr_name
  if 39 - 39: iII111i - I1ii11iIi11i % ooOoO0o - OoOoOO00 + OoOoOO00
  if 97 - 97: I11i * I1Ii111 * oO0o
 IiI1I = None
 for iiOoOoOoo0 in lisp_map_resolvers_list . values ( ) :
  if ( iiiIIi1Iii == "" ) : return ( iiOoOoOoo0 )
  if ( iiOoOoOoo0 . mr_name != iiiIIi1Iii ) : continue
  if ( IiI1I == None or iiOoOoOoo0 . last_used < IiI1I . last_used ) : IiI1I = iiOoOoOoo0
  if 100 - 100: Oo0Ooo / OOooOOo - i1IIi / I1ii11iIi11i . IiII
 return ( IiI1I )
 if 98 - 98: I11i + Oo0Ooo . IiII / iII111i % OoooooooOO
 if 35 - 35: O0 . Oo0Ooo / Oo0Ooo / Ii1I / i1IIi * I11i
 if 93 - 93: O0 + IiII
 if 91 - 91: iIii1I11I1II1
 if 66 - 66: i1IIi . ooOoO0o
 if 84 - 84: O0 % ooOoO0o / I1Ii111
 if 75 - 75: I11i - iII111i . O0
 if 52 - 52: I1ii11iIi11i
def lisp_get_decent_map_resolver ( eid ) :
 OOOoO000 = lisp_get_decent_index ( eid )
 IIiiiIiI = str ( OOOoO000 ) + "." + lisp_decent_dns_suffix
 if 65 - 65: oO0o
 lprint ( "Use LISP-Decent map-resolver {} for EID {}" . format ( bold ( IIiiiIiI , False ) , eid . print_prefix ( ) ) )
 if 57 - 57: I1Ii111 + IiII . o0oOOo0O0Ooo % OoO0O00 - I11i * oO0o
 if 55 - 55: I1IiiI / ooOoO0o
 IiI1I = None
 for iiOoOoOoo0 in lisp_map_resolvers_list . values ( ) :
  if ( IIiiiIiI != iiOoOoOoo0 . dns_name ) : continue
  if ( IiI1I == None or iiOoOoOoo0 . last_used < IiI1I . last_used ) : IiI1I = iiOoOoOoo0
  if 81 - 81: ooOoO0o + I1Ii111 / I1ii11iIi11i - o0oOOo0O0Ooo + OoOoOO00 * OOooOOo
 return ( IiI1I )
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
 iIiI1I1IIi11 = struct . unpack ( "H" , packet [ 10 : 12 ] ) [ 0 ]
 if ( iIiI1I1IIi11 == 0 ) :
  dprint ( "Packet arrived with checksum of 0!" )
 else :
  packet = lisp_ip_checksum ( packet )
  iIiI1I1IIi11 = struct . unpack ( "H" , packet [ 10 : 12 ] ) [ 0 ]
  if ( iIiI1I1IIi11 != 0 ) :
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
 I1i11iiIiIi = struct . unpack ( "B" , packet [ 8 : 9 ] ) [ 0 ]
 if ( I1i11iiIiIi == 0 ) :
  dprint ( "IPv4 packet arrived with ttl 0, packet discarded" )
  return ( None )
 elif ( I1i11iiIiIi == 1 ) :
  dprint ( "IPv4 packet {}, packet discarded" . format ( bold ( "ttl expiry" , False ) ) )
  if 4 - 4: iII111i + OoooooooOO / I1Ii111
  return ( None )
  if 57 - 57: I1IiiI . iIii1I11I1II1 % iII111i * iII111i / I1Ii111
  if 30 - 30: O0 / I11i % OoOoOO00 * I1Ii111 / O0 % ooOoO0o
 I1i11iiIiIi -= 1
 packet = packet [ 0 : 8 ] + struct . pack ( "B" , I1i11iiIiIi ) + packet [ 9 : : ]
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
 IiI1 = packet . inner_dest
 packet = packet . packet
 if 74 - 74: o0oOOo0O0Ooo % Ii1I - II111iiii / ooOoO0o
 if 84 - 84: I1IiiI + OOooOOo
 if 80 - 80: OOooOOo / OoOoOO00
 if 93 - 93: OOooOOo
 if 82 - 82: iIii1I11I1II1 + OoO0O00 / iIii1I11I1II1 . iIii1I11I1II1
 I1i11iiIiIi = struct . unpack ( "B" , packet [ 7 : 8 ] ) [ 0 ]
 if ( I1i11iiIiIi == 0 ) :
  dprint ( "IPv6 packet arrived with hop-limit 0, packet discarded" )
  return ( None )
 elif ( I1i11iiIiIi == 1 ) :
  dprint ( "IPv6 packet {}, packet discarded" . format ( bold ( "ttl expiry" , False ) ) )
  if 36 - 36: iII111i % I1ii11iIi11i + OoOoOO00 - i11iIiiIii % II111iiii % I11i
  return ( None )
  if 92 - 92: O0 * OoooooooOO + I1ii11iIi11i / IiII
  if 97 - 97: o0oOOo0O0Ooo . Ii1I + I1Ii111
  if 72 - 72: i11iIiiIii . iII111i . Ii1I * I1ii11iIi11i
  if 49 - 49: OoOoOO00 - O0 % I11i - ooOoO0o * OOooOOo
  if 58 - 58: OoooooooOO - OOooOOo * oO0o / Ii1I . IiII
 if ( IiI1 . is_ipv6_link_local ( ) ) :
  dprint ( "Do not encapsulate IPv6 link-local packets" )
  return ( None )
  if 50 - 50: IiII . OOooOOo + I1ii11iIi11i - OoooooooOO
  if 2 - 2: o0oOOo0O0Ooo % ooOoO0o / O0 / i11iIiiIii
 I1i11iiIiIi -= 1
 packet = packet [ 0 : 7 ] + struct . pack ( "B" , I1i11iiIiIi ) + packet [ 8 : : ]
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
 oOOO0O0ooOoOoo0 = lisp_get_timestamp ( )
 ooooOoO0O = oOOO0O0ooOoOoo0 - lisp_last_map_request_sent
 Iii1ii11iiii1 = ( ooooOoO0O < LISP_MAP_REQUEST_RATE_LIMIT )
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
 I1i = oOo0oO0O0 = None
 if ( rloc ) :
  I1i = rloc . rloc
  oOo0oO0O0 = rloc . translated_port if lisp_i_am_rtr else LISP_DATA_PORT
  if 84 - 84: I1Ii111 - I11i % iIii1I11I1II1 * o0oOOo0O0Ooo % I1IiiI
  if 5 - 5: OoO0O00
  if 10 - 10: o0oOOo0O0Ooo % OOooOOo / Ii1I . iIii1I11I1II1 % o0oOOo0O0Ooo + o0oOOo0O0Ooo
  if 63 - 63: i11iIiiIii
  if 34 - 34: OoooooooOO - O0 + ooOoO0o * I1IiiI
 o00ooOOooo0 , IiIIIIii1i1 , oOOOo0o = lisp_myrlocs
 if ( o00ooOOooo0 == None ) :
  lprint ( "Suppress sending Map-Request, IPv4 RLOC not found" )
  return
  if 5 - 5: oO0o . I1IiiI + o0oOOo0O0Ooo
 if ( IiIIIIii1i1 == None and I1i != None and I1i . is_ipv6 ( ) ) :
  lprint ( "Suppress sending Map-Request, IPv6 RLOC not found" )
  return
  if 99 - 99: o0oOOo0O0Ooo . Oo0Ooo
  if 36 - 36: I1ii11iIi11i + II111iiii + oO0o / I1IiiI
 iII1 = lisp_map_request ( )
 iII1 . record_count = 1
 iII1 . nonce = lisp_get_control_nonce ( )
 iII1 . rloc_probe = ( I1i != None )
 if 4 - 4: I11i / OOooOOo % I11i * I11i % Ii1I % i11iIiiIii
 if 38 - 38: oO0o / OoooooooOO
 if 53 - 53: O0
 if 46 - 46: I1Ii111 * I1Ii111 - OoooooooOO * iIii1I11I1II1 - oO0o
 if 34 - 34: IiII + ooOoO0o . IiII * iII111i
 if 42 - 42: oO0o * I1IiiI
 if 65 - 65: ooOoO0o
 if ( rloc ) : rloc . last_rloc_probe_nonce = iII1 . nonce
 if 88 - 88: OOooOOo - O0 % o0oOOo0O0Ooo + o0oOOo0O0Ooo % i11iIiiIii * I11i
 i111IiI1III1 = deid . is_multicast_address ( )
 if ( i111IiI1III1 ) :
  iII1 . target_eid = seid
  iII1 . target_group = deid
 else :
  iII1 . target_eid = deid
  if 34 - 34: I1IiiI % iIii1I11I1II1 . I1ii11iIi11i * Oo0Ooo * iIii1I11I1II1 / O0
  if 98 - 98: iII111i % IiII + OoO0O00
  if 23 - 23: OOooOOo
  if 83 - 83: I1ii11iIi11i / O0 * II111iiii + IiII + Oo0Ooo
  if 99 - 99: II111iiii + O0
  if 94 - 94: ooOoO0o * ooOoO0o + o0oOOo0O0Ooo . iII111i % iIii1I11I1II1 + Ii1I
  if 88 - 88: Oo0Ooo . iII111i
  if 89 - 89: OOooOOo + I1Ii111 % i11iIiiIii + Oo0Ooo / Oo0Ooo + OoO0O00
  if 9 - 9: OoOoOO00 % i1IIi + IiII
 if ( iII1 . rloc_probe == False ) :
  o0O00o = lisp_get_signature_eid ( )
  if ( o0O00o ) :
   iII1 . signature_eid . copy_address ( o0O00o . eid )
   iII1 . privkey_filename = "./lisp-sig.pem"
   if 19 - 19: I1Ii111 - II111iiii / I1Ii111 + I1IiiI - OoooooooOO + o0oOOo0O0Ooo
   if 100 - 100: OoO0O00 / OoOoOO00 / OOooOOo / OoO0O00
   if 95 - 95: ooOoO0o
   if 95 - 95: Ii1I + i1IIi . I1IiiI % I1Ii111 / Ii1I * O0
   if 68 - 68: I1Ii111 - IiII - oO0o - Oo0Ooo - o0oOOo0O0Ooo
   if 32 - 32: OoOoOO00 % i11iIiiIii
 if ( seid == None or i111IiI1III1 ) :
  iII1 . source_eid . afi = LISP_AFI_NONE
 else :
  iII1 . source_eid = seid
  if 53 - 53: I1Ii111 * Ii1I / IiII . i1IIi * II111iiii / o0oOOo0O0Ooo
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
 if ( I1i != None and lisp_nat_traversal and lisp_i_am_rtr == False ) :
  if ( I1i . is_private_address ( ) == False ) :
   o00ooOOooo0 = lisp_get_any_translated_rloc ( )
   if 23 - 23: Oo0Ooo . OoO0O00
  if ( o00ooOOooo0 == None ) :
   lprint ( "Suppress sending Map-Request, translated RLOC not found" )
   return
   if 49 - 49: oO0o % i11iIiiIii * Ii1I
   if 9 - 9: Oo0Ooo - OoO0O00 + ooOoO0o / o0oOOo0O0Ooo
   if 61 - 61: O0 - i11iIiiIii * o0oOOo0O0Ooo
   if 92 - 92: Oo0Ooo + OOooOOo - i11iIiiIii
   if 26 - 26: O0 % Oo0Ooo + ooOoO0o - Ii1I . Oo0Ooo
   if 33 - 33: I1Ii111 / iII111i . I1Ii111 % II111iiii
   if 52 - 52: I1ii11iIi11i
   if 1 - 1: II111iiii + I1ii11iIi11i * OoOoOO00 % ooOoO0o - iII111i % OoooooooOO
 if ( I1i == None or I1i . is_ipv4 ( ) ) :
  if ( lisp_nat_traversal and I1i == None ) :
   o0OOoOo = lisp_get_any_translated_rloc ( )
   if ( o0OOoOo != None ) : o00ooOOooo0 = o0OOoOo
   if 67 - 67: OOooOOo % I1Ii111 + IiII * I1IiiI - I11i
  iII1 . itr_rlocs . append ( o00ooOOooo0 )
  if 91 - 91: iIii1I11I1II1 . I11i
 if ( I1i == None or I1i . is_ipv6 ( ) ) :
  if ( IiIIIIii1i1 == None or IiIIIIii1i1 . is_ipv6_link_local ( ) ) :
   IiIIIIii1i1 = None
  else :
   iII1 . itr_rloc_count = 1 if ( I1i == None ) else 0
   iII1 . itr_rlocs . append ( IiIIIIii1i1 )
   if 33 - 33: I11i % OoO0O00 % o0oOOo0O0Ooo
   if 83 - 83: OoO0O00 - i11iIiiIii + iIii1I11I1II1
   if 52 - 52: OoooooooOO
   if 44 - 44: O0 / OoooooooOO + ooOoO0o * I1ii11iIi11i
   if 36 - 36: I1ii11iIi11i / OoO0O00 - oO0o % O0
   if 12 - 12: i1IIi * ooOoO0o / oO0o + I1IiiI / OoooooooOO
   if 86 - 86: Oo0Ooo / OoO0O00
   if 78 - 78: I1IiiI * I1IiiI
   if 13 - 13: oO0o
 if ( I1i != None and iII1 . itr_rlocs != [ ] ) :
  I1IIIIII = iII1 . itr_rlocs [ 0 ]
 else :
  if ( deid . is_ipv4 ( ) ) :
   I1IIIIII = o00ooOOooo0
  elif ( deid . is_ipv6 ( ) ) :
   I1IIIIII = IiIIIIii1i1
  else :
   I1IIIIII = o00ooOOooo0
   if 43 - 43: oO0o / Ii1I % OOooOOo
   if 45 - 45: II111iiii
   if 41 - 41: Ii1I / OOooOOo * Oo0Ooo . O0 - i11iIiiIii
   if 77 - 77: o0oOOo0O0Ooo + I1IiiI + I1Ii111 / I1ii11iIi11i * i1IIi
   if 37 - 37: O0 + iIii1I11I1II1 % IiII * oO0o
   if 43 - 43: OOooOOo . O0
 I111 = iII1 . encode ( I1i , oOo0oO0O0 )
 iII1 . print_map_request ( )
 if 76 - 76: OOooOOo * OoooooooOO / IiII . OoO0O00 + II111iiii
 if 23 - 23: OoO0O00 - OoooooooOO * I11i . iIii1I11I1II1 / o0oOOo0O0Ooo + oO0o
 if 74 - 74: II111iiii / I1IiiI * O0 * OoO0O00 . I11i
 if 74 - 74: O0 . i1IIi / I1ii11iIi11i + o0oOOo0O0Ooo
 if 24 - 24: ooOoO0o % I1Ii111 + OoO0O00 * o0oOOo0O0Ooo % O0 - i11iIiiIii
 if 49 - 49: o0oOOo0O0Ooo / OoOoOO00 + iII111i
 if ( I1i != None ) :
  if ( rloc . is_rloc_translated ( ) ) :
   Ii1i111Iii = lisp_get_nat_info ( I1i , rloc . rloc_name )
   if ( Ii1i111Iii and len ( lisp_sockets ) == 4 ) :
    lisp_encapsulate_rloc_probe ( lisp_sockets , I1i ,
 Ii1i111Iii , I111 )
    return
    if 85 - 85: I1IiiI - o0oOOo0O0Ooo
    if 86 - 86: II111iiii + Ii1I * Ii1I
    if 26 - 26: o0oOOo0O0Ooo + oO0o * i11iIiiIii / II111iiii
  I11i11I = I1i . print_address_no_iid ( )
  IiI1 = lisp_convert_4to6 ( I11i11I )
  lisp_send ( lisp_sockets , IiI1 , LISP_CTRL_PORT , I111 )
  return
  if 86 - 86: Ii1I
  if 69 - 69: oO0o % o0oOOo0O0Ooo / o0oOOo0O0Ooo
  if 1 - 1: Ii1I
  if 43 - 43: o0oOOo0O0Ooo
  if 78 - 78: I1Ii111 % i1IIi * I11i
  if 59 - 59: OoOoOO00 % OoO0O00 % i11iIiiIii . II111iiii % I1ii11iIi11i + i1IIi
 O000O0 = None if lisp_i_am_rtr else seid
 if ( lisp_decent_pull_xtr_configured ( ) ) :
  iiOoOoOoo0 = lisp_get_decent_map_resolver ( deid )
 else :
  iiOoOoOoo0 = lisp_get_map_resolver ( None , O000O0 )
  if 64 - 64: Ii1I / i11iIiiIii - i1IIi % i1IIi * OoO0O00
 if ( iiOoOoOoo0 == None ) :
  lprint ( "Cannot find Map-Resolver for source-EID {}" . format ( green ( seid . print_address ( ) , False ) ) )
  if 92 - 92: ooOoO0o
  return
  if 39 - 39: iII111i / OoO0O00 * ooOoO0o - O0
 iiOoOoOoo0 . last_used = lisp_get_timestamp ( )
 iiOoOoOoo0 . map_requests_sent += 1
 if ( iiOoOoOoo0 . last_nonce == 0 ) : iiOoOoOoo0 . last_nonce = iII1 . nonce
 if 64 - 64: I1IiiI / OoooooooOO . I1Ii111 - II111iiii - i11iIiiIii
 if 45 - 45: OOooOOo / I1ii11iIi11i
 if 10 - 10: IiII + o0oOOo0O0Ooo + I11i % O0 % I1Ii111
 if 85 - 85: O0 % OoOoOO00 . I1ii11iIi11i
 if ( seid == None ) : seid = I1IIIIII
 lisp_send_ecm ( lisp_sockets , I111 , seid , lisp_ephem_port , deid ,
 iiOoOoOoo0 . map_resolver )
 if 46 - 46: OOooOOo * iIii1I11I1II1
 if 33 - 33: OoO0O00 * II111iiii / i1IIi
 if 93 - 93: I1Ii111 % I11i
 if 64 - 64: I1IiiI % OoOoOO00 / Oo0Ooo
 lisp_last_map_request_sent = lisp_get_timestamp ( )
 if 40 - 40: Ii1I + iIii1I11I1II1 / oO0o . II111iiii % O0 - IiII
 if 49 - 49: IiII - OOooOOo * OOooOOo . O0
 if 60 - 60: OoOoOO00 % iIii1I11I1II1 + IiII % o0oOOo0O0Ooo
 if 64 - 64: OoOoOO00 * I1ii11iIi11i . OoooooooOO . i1IIi
 iiOoOoOoo0 . resolve_dns_name ( )
 return
 if 61 - 61: OoO0O00
 if 100 - 100: OoOoOO00
 if 97 - 97: OoooooooOO
 if 91 - 91: o0oOOo0O0Ooo / O0 % OoO0O00
 if 35 - 35: iII111i % OoO0O00 * O0
 if 37 - 37: OOooOOo
 if 100 - 100: Oo0Ooo * I1IiiI . ooOoO0o
 if 53 - 53: OOooOOo + o0oOOo0O0Ooo * Ii1I + O0
def lisp_send_info_request ( lisp_sockets , dest , port , device_name ) :
 if 75 - 75: OoooooooOO
 if 24 - 24: I1Ii111 % i11iIiiIii % oO0o . OOooOOo % IiII
 if 23 - 23: o0oOOo0O0Ooo * II111iiii - Oo0Ooo - I1IiiI
 if 86 - 86: I1IiiI - II111iiii * II111iiii * oO0o % OoooooooOO * OoOoOO00
 Oo0OOo0 = lisp_info ( )
 Oo0OOo0 . nonce = lisp_get_control_nonce ( )
 if ( device_name ) : Oo0OOo0 . hostname += "-" + device_name
 if 100 - 100: iIii1I11I1II1 - I1IiiI
 I11i11I = dest . print_address_no_iid ( )
 if 9 - 9: I11i % i1IIi / ooOoO0o % iII111i - oO0o - II111iiii
 if 29 - 29: ooOoO0o . II111iiii . i1IIi % oO0o
 if 11 - 11: OoOoOO00 . OoO0O00 % I11i * iII111i % I1Ii111 . O0
 if 17 - 17: OOooOOo / i11iIiiIii - i11iIiiIii . II111iiii . ooOoO0o
 if 38 - 38: OOooOOo . OoooooooOO . II111iiii + OoO0O00 / oO0o . OoooooooOO
 if 100 - 100: OoO0O00
 if 36 - 36: oO0o + Ii1I - O0
 if 19 - 19: O0 + I1Ii111 . I1Ii111 * IiII * ooOoO0o + i1IIi
 if 51 - 51: ooOoO0o % OoOoOO00 % i1IIi / O0
 if 11 - 11: OOooOOo . I1ii11iIi11i * OOooOOo * OoO0O00
 if 11 - 11: I11i
 if 85 - 85: OoOoOO00 - Ii1I / Oo0Ooo % I1ii11iIi11i
 if 12 - 12: i1IIi + o0oOOo0O0Ooo / oO0o . O0
 if 37 - 37: IiII
 if 99 - 99: i11iIiiIii % i11iIiiIii . I11i * I1ii11iIi11i . OoO0O00 / I1IiiI
 if 44 - 44: iII111i - OoO0O00 / i11iIiiIii
 oo0Oooo0OoO0o = False
 if ( device_name ) :
  oo0oooo00000 = lisp_get_host_route_next_hop ( I11i11I )
  if 99 - 99: Oo0Ooo . i1IIi . ooOoO0o . i1IIi * iIii1I11I1II1 . I11i
  if 82 - 82: I11i . ooOoO0o - ooOoO0o
  if 11 - 11: I1ii11iIi11i / o0oOOo0O0Ooo % I1ii11iIi11i / OoooooooOO
  if 35 - 35: i1IIi % I11i * I1Ii111 + IiII
  if 53 - 53: I1IiiI
  if 62 - 62: o0oOOo0O0Ooo
  if 54 - 54: iIii1I11I1II1 / OoooooooOO + o0oOOo0O0Ooo . i1IIi - OoooooooOO
  if 70 - 70: Ii1I / OoOoOO00 * Oo0Ooo
  if 32 - 32: I1Ii111 . OoOoOO00 % OoooooooOO + I1Ii111 * OoO0O00
  if ( port == LISP_CTRL_PORT and oo0oooo00000 != None ) :
   while ( True ) :
    time . sleep ( .01 )
    oo0oooo00000 = lisp_get_host_route_next_hop ( I11i11I )
    if ( oo0oooo00000 == None ) : break
    if 84 - 84: OoOoOO00
    if 80 - 80: oO0o
    if 59 - 59: iIii1I11I1II1 / IiII % I1ii11iIi11i + OoO0O00 - I11i % OOooOOo
  o00oOoOOOOoO = lisp_get_default_route_next_hops ( )
  for oOOOo0o , O0Oo0OO in o00oOoOOOOoO :
   if ( oOOOo0o != device_name ) : continue
   if 91 - 91: OoOoOO00 + II111iiii / I11i * iIii1I11I1II1
   if 92 - 92: I1Ii111 - IiII / IiII
   if 42 - 42: IiII
   if 7 - 7: iIii1I11I1II1
   if 35 - 35: IiII + O0 % I1Ii111 - I1ii11iIi11i - i1IIi
   if 100 - 100: I1Ii111 + i11iIiiIii - IiII / I1ii11iIi11i / iII111i
   if ( oo0oooo00000 != O0Oo0OO ) :
    if ( oo0oooo00000 != None ) :
     lisp_install_host_route ( I11i11I , oo0oooo00000 , False )
     if 56 - 56: iII111i
    lisp_install_host_route ( I11i11I , O0Oo0OO , True )
    oo0Oooo0OoO0o = True
    if 91 - 91: Oo0Ooo . I11i . I1ii11iIi11i
   break
   if 60 - 60: i11iIiiIii - OOooOOo
   if 78 - 78: I1IiiI * ooOoO0o % iIii1I11I1II1 / I1ii11iIi11i
   if 61 - 61: I1Ii111 . Ii1I + OoooooooOO
   if 98 - 98: OOooOOo . ooOoO0o . OoOoOO00 - I1Ii111 . i1IIi - iIii1I11I1II1
   if 89 - 89: II111iiii * I1ii11iIi11i - I1IiiI
   if 58 - 58: Ii1I / Oo0Ooo % IiII
 I111 = Oo0OOo0 . encode ( )
 Oo0OOo0 . print_info ( )
 if 33 - 33: II111iiii . OOooOOo % iIii1I11I1II1 - Oo0Ooo - OoOoOO00 % i11iIiiIii
 if 60 - 60: iII111i . o0oOOo0O0Ooo
 if 56 - 56: I1ii11iIi11i
 if 89 - 89: Oo0Ooo + I1ii11iIi11i * o0oOOo0O0Ooo * oO0o % O0 % OoO0O00
 oO0ooOo = "(for control)" if port == LISP_CTRL_PORT else "(for data)"
 oO0ooOo = bold ( oO0ooOo , False )
 OoOOOOo = bold ( "{}" . format ( port ) , False )
 OOOO0o = red ( I11i11I , False )
 IIiiIiiI1Ii1i = "RTR " if port == LISP_DATA_PORT else "MS "
 lprint ( "Send Info-Request to {}{}, port {} {}" . format ( IIiiIiiI1Ii1i , OOOO0o , OoOOOOo , oO0ooOo ) )
 if 80 - 80: iII111i . OoooooooOO / II111iiii . OoO0O00 / OoooooooOO + ooOoO0o
 if 25 - 25: I1IiiI - IiII . o0oOOo0O0Ooo / I1Ii111 % I1ii11iIi11i
 if 21 - 21: OoooooooOO % I1ii11iIi11i / OoooooooOO - I1ii11iIi11i * i1IIi
 if 35 - 35: I11i . Ii1I / Ii1I . OoOoOO00
 if 59 - 59: OoOoOO00 / i1IIi / iIii1I11I1II1 + i1IIi
 if 33 - 33: iIii1I11I1II1 * i11iIiiIii
 if ( port == LISP_CTRL_PORT ) :
  lisp_send ( lisp_sockets , dest , LISP_CTRL_PORT , I111 )
 else :
  ooo0Oo00O = lisp_data_header ( )
  ooo0Oo00O . instance_id ( 0xffffff )
  ooo0Oo00O = ooo0Oo00O . encode ( )
  if ( ooo0Oo00O ) :
   I111 = ooo0Oo00O + I111
   if 7 - 7: oO0o
   if 89 - 89: i11iIiiIii / o0oOOo0O0Ooo / I1ii11iIi11i % iII111i . OoooooooOO - iIii1I11I1II1
   if 63 - 63: Ii1I % I1Ii111 + O0 * OoO0O00 . oO0o
   if 34 - 34: I1IiiI . I1ii11iIi11i . O0 - OoOoOO00 - i11iIiiIii / iII111i
   if 63 - 63: OOooOOo
   if 84 - 84: i11iIiiIii * iIii1I11I1II1 % I11i % iII111i + OoooooooOO . o0oOOo0O0Ooo
   if 78 - 78: o0oOOo0O0Ooo . iII111i + O0 / I1ii11iIi11i + I1ii11iIi11i + II111iiii
   if 96 - 96: iIii1I11I1II1 * II111iiii . iIii1I11I1II1
   if 13 - 13: Ii1I - OoOoOO00 . Ii1I
   lisp_send ( lisp_sockets , dest , LISP_DATA_PORT , I111 )
   if 7 - 7: Ii1I - I11i / I1ii11iIi11i + iII111i
   if 47 - 47: I11i * IiII / oO0o - OoooooooOO . OoooooooOO / I11i
   if 73 - 73: Ii1I . IiII % IiII
   if 56 - 56: I1Ii111 + iII111i + iII111i
   if 99 - 99: o0oOOo0O0Ooo % I1ii11iIi11i / Oo0Ooo . O0 + OoO0O00 * OoOoOO00
   if 48 - 48: iIii1I11I1II1 + O0 * I11i * i11iIiiIii . Ii1I / i1IIi
   if 48 - 48: i1IIi % iIii1I11I1II1 + I1IiiI - OoOoOO00 % I11i . I1Ii111
 if ( oo0Oooo0OoO0o ) :
  lisp_install_host_route ( I11i11I , None , False )
  if ( oo0oooo00000 != None ) : lisp_install_host_route ( I11i11I , oo0oooo00000 , True )
  if 66 - 66: I1Ii111 * i11iIiiIii + I1IiiI % II111iiii
 return
 if 47 - 47: II111iiii % o0oOOo0O0Ooo
 if 26 - 26: I1ii11iIi11i / I11i / Oo0Ooo / i1IIi + O0 * ooOoO0o
 if 53 - 53: IiII / II111iiii / oO0o % O0 / I1Ii111
 if 91 - 91: oO0o * OoOoOO00 + O0 % Oo0Ooo
 if 62 - 62: iIii1I11I1II1 - i11iIiiIii % iIii1I11I1II1 . ooOoO0o / OOooOOo * OoOoOO00
 if 45 - 45: OOooOOo - OOooOOo % iII111i - IiII . O0
 if 6 - 6: iIii1I11I1II1 * II111iiii / O0 % IiII - I1Ii111
def lisp_process_info_request ( lisp_sockets , packet , addr_str , sport , rtr_list ) :
 if 64 - 64: ooOoO0o
 if 28 - 28: i11iIiiIii - IiII * I1ii11iIi11i + IiII * iII111i
 if 75 - 75: o0oOOo0O0Ooo * OoOoOO00 % I1ii11iIi11i + OOooOOo . II111iiii
 if 12 - 12: ooOoO0o
 Oo0OOo0 = lisp_info ( )
 packet = Oo0OOo0 . decode ( packet )
 if ( packet == None ) : return
 Oo0OOo0 . print_info ( )
 if 83 - 83: I1Ii111 % ooOoO0o + OoooooooOO
 if 50 - 50: i11iIiiIii % I1IiiI * iII111i / Ii1I
 if 12 - 12: iII111i / OoO0O00 - II111iiii + Oo0Ooo
 if 78 - 78: i1IIi
 if 25 - 25: Ii1I * II111iiii / OoOoOO00
 Oo0OOo0 . info_reply = True
 Oo0OOo0 . global_etr_rloc . store_address ( addr_str )
 Oo0OOo0 . etr_port = sport
 if 86 - 86: i1IIi + I1IiiI + I1Ii111 % II111iiii . IiII - iIii1I11I1II1
 if 54 - 54: i11iIiiIii . Ii1I % I1IiiI . I1Ii111 . OoooooooOO
 if 49 - 49: OOooOOo % I11i - OOooOOo + Ii1I . I1ii11iIi11i + ooOoO0o
 if 15 - 15: i11iIiiIii
 if 85 - 85: I1Ii111 + iII111i - oO0o
 Oo0OOo0 . private_etr_rloc . afi = LISP_AFI_NAME
 Oo0OOo0 . private_etr_rloc . store_address ( Oo0OOo0 . hostname )
 if 59 - 59: IiII . oO0o / i11iIiiIii . I1Ii111
 if ( rtr_list != None ) : Oo0OOo0 . rtr_list = rtr_list
 packet = Oo0OOo0 . encode ( )
 Oo0OOo0 . print_info ( )
 if 64 - 64: OoOoOO00
 if 20 - 20: OoOoOO00 / O0 * OOooOOo % I11i + OoO0O00 + o0oOOo0O0Ooo
 if 51 - 51: Ii1I - OoOoOO00 / i11iIiiIii + O0
 if 71 - 71: ooOoO0o
 if 35 - 35: OoOoOO00
 lprint ( "Send Info-Reply to {}" . format ( red ( addr_str , False ) ) )
 IiI1 = lisp_convert_4to6 ( addr_str )
 lisp_send ( lisp_sockets , IiI1 , sport , packet )
 if 55 - 55: iII111i - o0oOOo0O0Ooo + IiII * II111iiii
 if 6 - 6: I1Ii111 / i1IIi / IiII . o0oOOo0O0Ooo
 if 69 - 69: ooOoO0o - OoOoOO00 . I1IiiI . I11i + OoOoOO00 / i11iIiiIii
 if 20 - 20: OoO0O00 . OoooooooOO - ooOoO0o . I11i / Oo0Ooo
 if 89 - 89: iIii1I11I1II1 . ooOoO0o
 OOoo0O00 = lisp_info_source ( Oo0OOo0 . hostname , addr_str , sport )
 OOoo0O00 . cache_address_for_info_source ( )
 return
 if 22 - 22: oO0o + O0 + I11i . OoO0O00 - II111iiii
 if 20 - 20: Ii1I * I1Ii111 . I1IiiI % OoOoOO00 / OoO0O00 % II111iiii
 if 43 - 43: IiII + II111iiii + oO0o / I1ii11iIi11i % i1IIi - OoO0O00
 if 59 - 59: Oo0Ooo + O0 + iII111i
 if 71 - 71: IiII - OoO0O00
 if 90 - 90: Oo0Ooo
 if 83 - 83: iIii1I11I1II1 % ooOoO0o % OOooOOo * i1IIi - o0oOOo0O0Ooo * i1IIi
 if 60 - 60: Ii1I . I1ii11iIi11i - I11i + i11iIiiIii / iII111i
def lisp_get_signature_eid ( ) :
 for o0O00o in lisp_db_list :
  if ( o0O00o . signature_eid ) : return ( o0O00o )
  if 9 - 9: I1Ii111 . oO0o . OoO0O00 / IiII - oO0o / oO0o
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
 for o0O00o in lisp_db_list :
  for o0OO0O0OoOo0 in o0O00o . rloc_set :
   if ( o0OO0O0OoOo0 . translated_rloc . is_null ( ) ) : continue
   return ( o0OO0O0OoOo0 . translated_port )
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
 for o0O00o in lisp_db_list :
  for o0OO0O0OoOo0 in o0O00o . rloc_set :
   if ( o0OO0O0OoOo0 . translated_rloc . is_null ( ) ) : continue
   return ( o0OO0O0OoOo0 . translated_rloc )
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
 oOoI1Iii11iI1111 = [ ]
 for o0O00o in lisp_db_list :
  for o0OO0O0OoOo0 in o0O00o . rloc_set :
   if ( o0OO0O0OoOo0 . is_rloc_translated ( ) == False ) : continue
   I1Iii1I = o0OO0O0OoOo0 . translated_rloc . print_address_no_iid ( )
   oOoI1Iii11iI1111 . append ( I1Iii1I )
   if 52 - 52: I11i
   if 71 - 71: I1Ii111 / II111iiii - OoooooooOO % i1IIi + OoOoOO00 % OoooooooOO
 return ( oOoI1Iii11iI1111 )
 if 52 - 52: Ii1I . OoOoOO00 / o0oOOo0O0Ooo / iII111i
 if 83 - 83: OoO0O00 - Oo0Ooo + I1Ii111 . I1IiiI
 if 78 - 78: I11i / ooOoO0o . OoOoOO00 * i1IIi
 if 15 - 15: i1IIi . II111iiii * OoOoOO00 / Oo0Ooo
 if 99 - 99: iII111i - o0oOOo0O0Ooo / O0
 if 97 - 97: iIii1I11I1II1 * I1Ii111
 if 39 - 39: I1Ii111 . II111iiii
 if 94 - 94: OoO0O00 - OoO0O00 + iIii1I11I1II1 + O0 * oO0o
def lisp_update_default_routes ( map_resolver , iid , rtr_list ) :
 OO00oOo0oO = ( os . getenv ( "LISP_RTR_BEHIND_NAT" ) != None )
 if 9 - 9: Ii1I * Oo0Ooo / oO0o / Ii1I
 iIi11i = { }
 for II1iIiIiIIi in rtr_list :
  if ( II1iIiIiIIi == None ) : continue
  I1Iii1I = rtr_list [ II1iIiIiIIi ]
  if ( OO00oOo0oO and I1Iii1I . is_private_address ( ) ) : continue
  iIi11i [ II1iIiIiIIi ] = I1Iii1I
  if 27 - 27: i1IIi
 rtr_list = iIi11i
 if 20 - 20: OOooOOo . iIii1I11I1II1 - I1Ii111 . i1IIi
 OO0o0OO0O0Oo = [ ]
 for ooo0O0O0oo0 in [ LISP_AFI_IPV4 , LISP_AFI_IPV6 , LISP_AFI_MAC ] :
  if ( ooo0O0O0oo0 == LISP_AFI_MAC and lisp_l2_overlay == False ) : break
  if 76 - 76: oO0o
  if 42 - 42: OoO0O00 * i1IIi
  if 60 - 60: I1IiiI * I1Ii111 + oO0o - Ii1I
  if 58 - 58: i11iIiiIii . o0oOOo0O0Ooo - i1IIi - I1IiiI * i1IIi % I1Ii111
  if 37 - 37: I11i
  O0OoOoo000OoO = lisp_address ( ooo0O0O0oo0 , "" , 0 , iid )
  O0OoOoo000OoO . make_default_route ( O0OoOoo000OoO )
  iIi11 = lisp_map_cache . lookup_cache ( O0OoOoo000OoO , True )
  if ( iIi11 ) :
   if ( iIi11 . checkpoint_entry ) :
    lprint ( "Updating checkpoint entry for {}" . format ( green ( iIi11 . print_eid_tuple ( ) , False ) ) )
    if 61 - 61: OoooooooOO % iIii1I11I1II1 % O0 % I1Ii111 / Oo0Ooo . I1IiiI
   elif ( iIi11 . do_rloc_sets_match ( rtr_list . values ( ) ) ) :
    continue
    if 20 - 20: ooOoO0o - I1Ii111
   iIi11 . delete_cache ( )
   if 97 - 97: O0
   if 56 - 56: Ii1I * I1IiiI * ooOoO0o
  OO0o0OO0O0Oo . append ( [ O0OoOoo000OoO , "" ] )
  if 39 - 39: iII111i % Ii1I * iIii1I11I1II1 - Ii1I - I1Ii111
  if 60 - 60: i11iIiiIii + i11iIiiIii - OoooooooOO + OoooooooOO
  if 5 - 5: o0oOOo0O0Ooo
  if 78 - 78: OOooOOo * O0 * II111iiii % OoOoOO00
  oO0000O0o = lisp_address ( ooo0O0O0oo0 , "" , 0 , iid )
  oO0000O0o . make_default_multicast_route ( oO0000O0o )
  IIOo0Oo00o0 = lisp_map_cache . lookup_cache ( oO0000O0o , True )
  if ( IIOo0Oo00o0 ) : IIOo0Oo00o0 = IIOo0Oo00o0 . source_cache . lookup_cache ( O0OoOoo000OoO , True )
  if ( IIOo0Oo00o0 ) : IIOo0Oo00o0 . delete_cache ( )
  if 82 - 82: OoO0O00 + Ii1I
  OO0o0OO0O0Oo . append ( [ O0OoOoo000OoO , oO0000O0o ] )
  if 3 - 3: iIii1I11I1II1 * I1ii11iIi11i * i1IIi - O0 - iII111i * O0
 if ( len ( OO0o0OO0O0Oo ) == 0 ) : return
 if 10 - 10: I1Ii111 . IiII * I1ii11iIi11i
 if 81 - 81: i11iIiiIii + I1Ii111
 if 65 - 65: OOooOOo - iII111i * I1Ii111 + i1IIi % ooOoO0o
 if 6 - 6: O0 + Ii1I % II111iiii % i1IIi . iII111i / OoooooooOO
 I1111Ii1II1I = [ ]
 for IIiiIiiI1Ii1i in rtr_list :
  I1IIIIi = rtr_list [ IIiiIiiI1Ii1i ]
  o0OO0O0OoOo0 = lisp_rloc ( )
  o0OO0O0OoOo0 . rloc . copy_address ( I1IIIIi )
  o0OO0O0OoOo0 . priority = 254
  o0OO0O0OoOo0 . mpriority = 255
  o0OO0O0OoOo0 . rloc_name = "RTR"
  I1111Ii1II1I . append ( o0OO0O0OoOo0 )
  if 23 - 23: Ii1I
  if 92 - 92: II111iiii - IiII / II111iiii
 for O0OoOoo000OoO in OO0o0OO0O0Oo :
  iIi11 = lisp_mapping ( O0OoOoo000OoO [ 0 ] , O0OoOoo000OoO [ 1 ] , I1111Ii1II1I )
  iIi11 . mapping_source = map_resolver
  iIi11 . map_cache_ttl = LISP_MR_TTL * 60
  iIi11 . add_cache ( )
  lprint ( "Add {} to map-cache with RTR RLOC-set: {}" . format ( green ( iIi11 . print_eid_tuple ( ) , False ) , rtr_list . keys ( ) ) )
  if 23 - 23: Ii1I * II111iiii - I1ii11iIi11i
  I1111Ii1II1I = copy . deepcopy ( I1111Ii1II1I )
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
 Oo0OOo0 = lisp_info ( )
 packet = Oo0OOo0 . decode ( packet )
 if ( packet == None ) : return ( [ None , None , False ] )
 if 37 - 37: i11iIiiIii - OoooooooOO - OoOoOO00 * oO0o / Ii1I
 Oo0OOo0 . print_info ( )
 if 100 - 100: II111iiii / Oo0Ooo / iII111i / OOooOOo
 if 100 - 100: iIii1I11I1II1
 if 50 - 50: I1Ii111 / ooOoO0o * I11i
 if 53 - 53: II111iiii . IiII
 ii1iII111i = False
 for IIiiIiiI1Ii1i in Oo0OOo0 . rtr_list :
  I11i11I = IIiiIiiI1Ii1i . print_address_no_iid ( )
  if ( lisp_rtr_list . has_key ( I11i11I ) ) :
   if ( lisp_register_all_rtrs == False ) : continue
   if ( lisp_rtr_list [ I11i11I ] != None ) : continue
   if 80 - 80: IiII - i11iIiiIii % I11i
  ii1iII111i = True
  lisp_rtr_list [ I11i11I ] = IIiiIiiI1Ii1i
  if 5 - 5: OoooooooOO
  if 5 - 5: iII111i + oO0o % O0 . OoooooooOO + i1IIi
  if 55 - 55: I1ii11iIi11i
  if 34 - 34: OoO0O00 * iIii1I11I1II1 . iIii1I11I1II1
  if 39 - 39: o0oOOo0O0Ooo
 if ( lisp_i_am_itr and ii1iII111i ) :
  if ( lisp_iid_to_interface == { } ) :
   lisp_update_default_routes ( source , lisp_default_iid , lisp_rtr_list )
  else :
   for IIiI1i in lisp_iid_to_interface . keys ( ) :
    lisp_update_default_routes ( source , int ( IIiI1i ) , lisp_rtr_list )
    if 29 - 29: Oo0Ooo . Oo0Ooo * OoO0O00 % Ii1I - ooOoO0o
    if 67 - 67: I1IiiI % O0 + I1IiiI * I1Ii111 * OoOoOO00 * II111iiii
    if 79 - 79: I1IiiI
    if 37 - 37: I1Ii111 + Ii1I
    if 50 - 50: i11iIiiIii
    if 57 - 57: O0 * i1IIi - I1IiiI
    if 48 - 48: IiII / iIii1I11I1II1
 if ( store == False ) :
  return ( [ Oo0OOo0 . global_etr_rloc , Oo0OOo0 . etr_port , ii1iII111i ] )
  if 20 - 20: oO0o / OoooooooOO
  if 95 - 95: Oo0Ooo . i11iIiiIii
  if 50 - 50: iII111i . i11iIiiIii - i1IIi
  if 24 - 24: i11iIiiIii % iII111i . oO0o
  if 44 - 44: II111iiii - OoO0O00 + i11iIiiIii
  if 34 - 34: I1ii11iIi11i % ooOoO0o / II111iiii * O0 % OOooOOo
 for o0O00o in lisp_db_list :
  for o0OO0O0OoOo0 in o0O00o . rloc_set :
   II1iIiIiIIi = o0OO0O0OoOo0 . rloc
   iiiii11I1 = o0OO0O0OoOo0 . interface
   if ( iiiii11I1 == None ) :
    if ( II1iIiIiIIi . is_null ( ) ) : continue
    if ( II1iIiIiIIi . is_local ( ) == False ) : continue
    if ( Oo0OOo0 . private_etr_rloc . is_null ( ) == False and
 II1iIiIiIIi . is_exact_match ( Oo0OOo0 . private_etr_rloc ) == False ) :
     continue
     if 9 - 9: I1ii11iIi11i / I1ii11iIi11i - OOooOOo . iIii1I11I1II1
   elif ( Oo0OOo0 . private_etr_rloc . is_dist_name ( ) ) :
    iIIiii = Oo0OOo0 . private_etr_rloc . address
    if ( iIIiii != o0OO0O0OoOo0 . rloc_name ) : continue
    if 33 - 33: I1IiiI + oO0o % I1IiiI / iII111i - ooOoO0o - i11iIiiIii
    if 39 - 39: i11iIiiIii / oO0o
   oo0ooooO = green ( o0O00o . eid . print_prefix ( ) , False )
   IIII1i = red ( II1iIiIiIIi . print_address_no_iid ( ) , False )
   if 71 - 71: I1Ii111 * iIii1I11I1II1 - I1Ii111
   oo0O = Oo0OOo0 . global_etr_rloc . is_exact_match ( II1iIiIiIIi )
   if ( o0OO0O0OoOo0 . translated_port == 0 and oo0O ) :
    lprint ( "No NAT for {} ({}), EID-prefix {}" . format ( IIII1i ,
 iiiii11I1 , oo0ooooO ) )
    continue
    if 27 - 27: Ii1I / II111iiii
    if 27 - 27: OoO0O00 - II111iiii - I1Ii111
    if 80 - 80: OoO0O00 - ooOoO0o . Oo0Ooo - OOooOOo + OoOoOO00 . iII111i
    if 26 - 26: OOooOOo
    if 89 - 89: i11iIiiIii . o0oOOo0O0Ooo % iIii1I11I1II1 * O0 + OOooOOo . o0oOOo0O0Ooo
   iI1iI1II1i1i = Oo0OOo0 . global_etr_rloc
   o00O00O0OO0O = o0OO0O0OoOo0 . translated_rloc
   if ( o00O00O0OO0O . is_exact_match ( iI1iI1II1i1i ) and
 Oo0OOo0 . etr_port == o0OO0O0OoOo0 . translated_port ) : continue
   if 3 - 3: iIii1I11I1II1 + iIii1I11I1II1 + OoO0O00
   lprint ( "Store translation {}:{} for {} ({}), EID-prefix {}" . format ( red ( Oo0OOo0 . global_etr_rloc . print_address_no_iid ( ) , False ) ,
   # iII111i . Ii1I . o0oOOo0O0Ooo * oO0o
 Oo0OOo0 . etr_port , IIII1i , iiiii11I1 , oo0ooooO ) )
   if 18 - 18: iII111i % I1Ii111 / I1Ii111 % OoOoOO00 - OoOoOO00 + I1IiiI
   o0OO0O0OoOo0 . store_translated_rloc ( Oo0OOo0 . global_etr_rloc ,
 Oo0OOo0 . etr_port )
   if 13 - 13: oO0o - o0oOOo0O0Ooo * oO0o
   if 27 - 27: OOooOOo * iII111i * I11i
 return ( [ Oo0OOo0 . global_etr_rloc , Oo0OOo0 . etr_port , ii1iII111i ] )
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
 III1II1I1iI = lisp_address ( LISP_AFI_IPV4 , "" , 0 , 0 )
 O00oiI1i1iIII11 = lisp_address ( LISP_AFI_IPV6 , "" , 0 , 0 )
 if 67 - 67: OOooOOo - II111iiii * OoO0O00 . I1ii11iIi11i
 if 9 - 9: OoO0O00 - OoO0O00 / i11iIiiIii . iII111i / I1ii11iIi11i . OoOoOO00
 if 89 - 89: I11i * iIii1I11I1II1 - I1ii11iIi11i
 if 82 - 82: iIii1I11I1II1
 III1II1I1iI . store_address ( "10.0.0.1" )
 lisp_send_map_request ( lisp_sockets , port , None , III1II1I1iI , None )
 III1II1I1iI . store_address ( "192.168.0.1" )
 lisp_send_map_request ( lisp_sockets , port , None , III1II1I1iI , None )
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
 I1Iii1I = lisp_get_interface_address ( rloc . interface )
 if ( I1Iii1I == None ) : return
 if 82 - 82: OOooOOo / I11i % Ii1I * OoOoOO00
 oOOo0oo0OOO = rloc . rloc . print_address_no_iid ( )
 o0OoO0o00o = I1Iii1I . print_address_no_iid ( )
 if 23 - 23: i11iIiiIii
 if ( oOOo0oo0OOO == o0OoO0o00o ) : return
 if 14 - 14: I1ii11iIi11i + I1IiiI % I1Ii111
 lprint ( "Local interface address changed on {} from {} to {}" . format ( rloc . interface , oOOo0oo0OOO , o0OoO0o00o ) )
 if 48 - 48: o0oOOo0O0Ooo . OoooooooOO * Oo0Ooo
 if 14 - 14: OoO0O00
 rloc . rloc . copy_address ( I1Iii1I )
 lisp_myrlocs [ 0 ] = I1Iii1I
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
 for II1iIiIiIIi in mc . rloc_set :
  Ii1i111Iii = lisp_get_nat_info ( II1iIiIiIIi . rloc , II1iIiIiIIi . rloc_name )
  if ( Ii1i111Iii == None ) : continue
  if ( II1iIiIiIIi . translated_port == Ii1i111Iii . port ) : continue
  if 72 - 72: OoOoOO00 * OoooooooOO % O0 / I1ii11iIi11i % Ii1I - I11i
  lprint ( ( "Encap-port changed from {} to {} for RLOC {}, " + "EID-prefix {}" ) . format ( II1iIiIiIIi . translated_port , Ii1i111Iii . port ,
  # OoOoOO00 % ooOoO0o . I1Ii111 / OoO0O00
 red ( II1iIiIiIIi . rloc . print_address_no_iid ( ) , False ) ,
 green ( mc . print_eid_tuple ( ) , False ) ) )
  if 21 - 21: IiII
  II1iIiIiIIi . store_translated_rloc ( II1iIiIiIIi . rloc , Ii1i111Iii . port )
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
  oOOO0O0ooOoOoo0 = lisp_get_timestamp ( )
  if ( mc . last_refresh_time + mc . map_cache_ttl > oOOO0O0ooOoOoo0 ) :
   lisp_update_encap_port ( mc )
   return ( [ True , delete_list ] )
   if 8 - 8: iII111i . oO0o . OOooOOo + iII111i . Ii1I
   if 46 - 46: OoO0O00
   if 21 - 21: iIii1I11I1II1 - iII111i
   if 15 - 15: O0 + iII111i + i11iIiiIii
   if 31 - 31: iIii1I11I1II1 * iIii1I11I1II1 . I11i
   if 52 - 52: i11iIiiIii / oO0o / IiII
 ooooOoO0O = lisp_print_elapsed ( mc . last_refresh_time )
 o00oo = mc . print_eid_tuple ( )
 lprint ( "Map-cache entry for EID-prefix {} has {}, had uptime of {}" . format ( green ( o00oo , False ) , bold ( "timed out" , False ) , ooooOoO0O ) )
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
 I1OOoO0OoOOo0 = parms [ 0 ]
 iI111I = parms [ 1 ]
 if 84 - 84: OoooooooOO . I1IiiI / I11i + i1IIi - ooOoO0o
 if 72 - 72: OoooooooOO
 if 57 - 57: I1Ii111 * O0 / o0oOOo0O0Ooo * iII111i * ooOoO0o - I11i
 if 53 - 53: iIii1I11I1II1 . OoOoOO00 % i11iIiiIii % I1IiiI / OoO0O00 % I1Ii111
 if ( mc . group . is_null ( ) ) :
  iI1Ii11iiII , I1OOoO0OoOOo0 = lisp_timeout_map_cache_entry ( mc , I1OOoO0OoOOo0 )
  if ( I1OOoO0OoOOo0 == [ ] or mc != I1OOoO0OoOOo0 [ - 1 ] ) :
   iI111I = lisp_write_checkpoint_entry ( iI111I , mc )
   if 11 - 11: I1IiiI + I11i . OoOoOO00 - II111iiii
  return ( [ iI1Ii11iiII , parms ] )
  if 10 - 10: iII111i - IiII + OoOoOO00 + I1IiiI + Oo0Ooo
  if 25 - 25: I1IiiI / I1ii11iIi11i % iII111i / O0 % II111iiii
 if ( mc . source_cache == None ) : return ( [ True , parms ] )
 if 20 - 20: O0 % I11i * iII111i
 if 6 - 6: OoooooooOO % ooOoO0o % OoO0O00 * IiII
 if 62 - 62: i1IIi . I11i / I11i
 if 90 - 90: O0 * OOooOOo / oO0o . Oo0Ooo * I11i
 if 93 - 93: oO0o / ooOoO0o - I1Ii111
 parms = mc . source_cache . walk_cache ( lisp_timeout_map_cache_entry , parms )
 return ( [ True , parms ] )
 if 70 - 70: OOooOOo / Ii1I - ooOoO0o + OoooooooOO / OoO0O00 - i11iIiiIii
 if 26 - 26: O0 + Oo0Ooo
 if 30 - 30: IiII
 if 6 - 6: O0
 if 92 - 92: I11i
 if 76 - 76: I11i / iIii1I11I1II1 - i11iIiiIii / O0 / O0
 if 19 - 19: Ii1I . I1IiiI - i1IIi * ooOoO0o . iIii1I11I1II1
def lisp_timeout_map_cache ( lisp_map_cache ) :
 o00O = [ [ ] , [ ] ]
 o00O = lisp_map_cache . walk_cache ( lisp_timeout_map_cache_walk , o00O )
 if 87 - 87: ooOoO0o % I1ii11iIi11i . I1IiiI
 if 42 - 42: iII111i % i11iIiiIii % o0oOOo0O0Ooo . O0 % iII111i
 if 72 - 72: Oo0Ooo . Oo0Ooo . IiII . Oo0Ooo
 if 80 - 80: I1Ii111 + IiII + O0 - I1Ii111 . iIii1I11I1II1
 if 53 - 53: OoO0O00 / i11iIiiIii * I1Ii111
 I1OOoO0OoOOo0 = o00O [ 0 ]
 for iIi11 in I1OOoO0OoOOo0 : iIi11 . delete_cache ( )
 if 62 - 62: oO0o / Oo0Ooo / IiII + I11i * ooOoO0o
 if 84 - 84: ooOoO0o + OoOoOO00 * I1ii11iIi11i % OoooooooOO . O0
 if 27 - 27: OoO0O00 * OoooooooOO - II111iiii / o0oOOo0O0Ooo
 if 76 - 76: I11i % I1Ii111 % iII111i + IiII * iII111i + OoOoOO00
 iI111I = o00O [ 1 ]
 lisp_checkpoint ( iI111I )
 return
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
 if 93 - 93: OoO0O00 - I1Ii111 - OoO0O00
def lisp_store_nat_info ( hostname , rloc , port ) :
 I11i11I = rloc . print_address_no_iid ( )
 II1 = "{} NAT state for {}, RLOC {}, port {}" . format ( "{}" ,
 blue ( hostname , False ) , red ( I11i11I , False ) , port )
 if 63 - 63: OOooOOo . oO0o * OoooooooOO + ooOoO0o / iIii1I11I1II1 + iII111i
 I11i1iIII = lisp_nat_info ( I11i11I , hostname , port )
 if 63 - 63: OOooOOo - oO0o * I1IiiI
 if ( lisp_nat_state_info . has_key ( hostname ) == False ) :
  lisp_nat_state_info [ hostname ] = [ I11i1iIII ]
  lprint ( II1 . format ( "Store initial" ) )
  return ( True )
  if 60 - 60: II111iiii - Oo0Ooo
  if 43 - 43: I1IiiI - IiII - OOooOOo
  if 19 - 19: I1Ii111 / I1Ii111 - i1IIi
  if 99 - 99: O0
  if 37 - 37: iIii1I11I1II1 / I1Ii111 + OoO0O00
  if 85 - 85: ooOoO0o / I1IiiI
 Ii1i111Iii = lisp_nat_state_info [ hostname ] [ 0 ]
 if ( Ii1i111Iii . address == I11i11I and Ii1i111Iii . port == port ) :
  Ii1i111Iii . uptime = lisp_get_timestamp ( )
  lprint ( II1 . format ( "Refresh existing" ) )
  return ( False )
  if 7 - 7: Oo0Ooo - iIii1I11I1II1 / I1ii11iIi11i * I1IiiI + Ii1I
  if 99 - 99: i11iIiiIii - I1ii11iIi11i
  if 64 - 64: IiII . OoOoOO00 . Oo0Ooo . I1Ii111 / I11i / Ii1I
  if 95 - 95: iIii1I11I1II1 . Ii1I % oO0o - I11i % IiII
  if 42 - 42: OoOoOO00 + oO0o * i1IIi + i11iIiiIii
  if 25 - 25: Ii1I - Ii1I - I1ii11iIi11i / i1IIi . OoOoOO00 % Oo0Ooo
  if 76 - 76: I1Ii111 / OoOoOO00
 oOoooIiii1i1ii1iii = None
 for Ii1i111Iii in lisp_nat_state_info [ hostname ] :
  if ( Ii1i111Iii . address == I11i11I and Ii1i111Iii . port == port ) :
   oOoooIiii1i1ii1iii = Ii1i111Iii
   break
   if 16 - 16: iIii1I11I1II1 . oO0o . ooOoO0o
   if 1 - 1: iIii1I11I1II1 . OOooOOo
   if 39 - 39: OoOoOO00 % ooOoO0o * IiII - I1IiiI
 if ( oOoooIiii1i1ii1iii == None ) :
  lprint ( II1 . format ( "Store new" ) )
 else :
  lisp_nat_state_info [ hostname ] . remove ( oOoooIiii1i1ii1iii )
  lprint ( II1 . format ( "Use previous" ) )
  if 53 - 53: I11i % OoO0O00 * IiII % IiII % IiII
  if 81 - 81: I1ii11iIi11i
 o0oOoOo = lisp_nat_state_info [ hostname ]
 lisp_nat_state_info [ hostname ] = [ I11i1iIII ] + o0oOoOo
 return ( True )
 if 87 - 87: ooOoO0o * II111iiii * O0 % I1IiiI
 if 69 - 69: ooOoO0o . OoooooooOO
 if 17 - 17: ooOoO0o / OoO0O00 / I1IiiI / OOooOOo % IiII
 if 88 - 88: i1IIi - OoOoOO00
 if 66 - 66: OoooooooOO - OoooooooOO * I11i / II111iiii + oO0o / Ii1I
 if 7 - 7: Ii1I / iIii1I11I1II1
 if 36 - 36: iIii1I11I1II1 % i11iIiiIii
 if 35 - 35: Oo0Ooo + I1IiiI - O0 - I1Ii111
def lisp_get_nat_info ( rloc , hostname ) :
 if ( lisp_nat_state_info . has_key ( hostname ) == False ) : return ( None )
 if 64 - 64: i1IIi * OoOoOO00 / II111iiii * oO0o
 I11i11I = rloc . print_address_no_iid ( )
 for Ii1i111Iii in lisp_nat_state_info [ hostname ] :
  if ( Ii1i111Iii . address == I11i11I ) : return ( Ii1i111Iii )
  if 35 - 35: i1IIi - Ii1I - Ii1I . O0 % iII111i * iII111i
 return ( None )
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
 if 41 - 41: OoooooooOO . OoOoOO00 * iIii1I11I1II1
 if 18 - 18: IiII / I1Ii111 % i1IIi * i11iIiiIii
def lisp_build_info_requests ( lisp_sockets , dest , port ) :
 if ( lisp_nat_traversal == False ) : return
 if 16 - 16: Oo0Ooo
 if 24 - 24: o0oOOo0O0Ooo . OoOoOO00
 if 50 - 50: I1ii11iIi11i / iIii1I11I1II1 - Oo0Ooo - i11iIiiIii % o0oOOo0O0Ooo - ooOoO0o
 if 92 - 92: OoooooooOO - I1ii11iIi11i . I11i / O0 % iII111i
 if 96 - 96: I1IiiI . oO0o % O0
 if 19 - 19: iIii1I11I1II1 + I1Ii111 / OoooooooOO % OOooOOo - i1IIi + I11i
 o0O0ooO0OoOo0OOO = [ ]
 ooOoOOOooOO0O = [ ]
 if ( dest == None ) :
  for iiOoOoOoo0 in lisp_map_resolvers_list . values ( ) :
   ooOoOOOooOO0O . append ( iiOoOoOoo0 . map_resolver )
   if 92 - 92: I1Ii111
  o0O0ooO0OoOo0OOO = ooOoOOOooOO0O
  if ( o0O0ooO0OoOo0OOO == [ ] ) :
   for ooo0OoOOo in lisp_map_servers_list . values ( ) :
    o0O0ooO0OoOo0OOO . append ( ooo0OoOOo . map_server )
    if 4 - 4: OoOoOO00 % o0oOOo0O0Ooo * i11iIiiIii - OOooOOo
    if 68 - 68: iII111i + I1ii11iIi11i / II111iiii * I1ii11iIi11i
  if ( o0O0ooO0OoOo0OOO == [ ] ) : return
 else :
  o0O0ooO0OoOo0OOO . append ( dest )
  if 45 - 45: II111iiii . iII111i
  if 55 - 55: ooOoO0o / iII111i / O0
  if 98 - 98: O0 % iII111i + II111iiii
  if 13 - 13: I1IiiI * oO0o - o0oOOo0O0Ooo
  if 23 - 23: iIii1I11I1II1 + oO0o . oO0o / o0oOOo0O0Ooo
 oOoI1Iii11iI1111 = { }
 for o0O00o in lisp_db_list :
  for o0OO0O0OoOo0 in o0O00o . rloc_set :
   lisp_update_local_rloc ( o0OO0O0OoOo0 )
   if ( o0OO0O0OoOo0 . rloc . is_null ( ) ) : continue
   if ( o0OO0O0OoOo0 . interface == None ) : continue
   if 77 - 77: i1IIi * o0oOOo0O0Ooo * IiII
   I1Iii1I = o0OO0O0OoOo0 . rloc . print_address_no_iid ( )
   if ( I1Iii1I in oOoI1Iii11iI1111 ) : continue
   oOoI1Iii11iI1111 [ I1Iii1I ] = o0OO0O0OoOo0 . interface
   if 24 - 24: i11iIiiIii / iIii1I11I1II1 / iII111i
   if 31 - 31: OOooOOo . iIii1I11I1II1 - oO0o
 if ( oOoI1Iii11iI1111 == { } ) :
  lprint ( 'Suppress Info-Request, no "interface = <device>" RLOC ' + "found in any database-mappings" )
  if 36 - 36: O0
  return
  if 30 - 30: i11iIiiIii * Oo0Ooo . IiII
  if 65 - 65: oO0o * IiII * OOooOOo / OoooooooOO % I11i / I1Ii111
  if 21 - 21: i1IIi * iII111i + OoO0O00
  if 27 - 27: I11i / oO0o . iII111i + o0oOOo0O0Ooo - OOooOOo
  if 85 - 85: OoooooooOO
  if 83 - 83: iII111i * I11i . OOooOOo - OoO0O00 % IiII
 for I1Iii1I in oOoI1Iii11iI1111 :
  iiiii11I1 = oOoI1Iii11iI1111 [ I1Iii1I ]
  OOOO0o = red ( I1Iii1I , False )
  lprint ( "Build Info-Request for private address {} ({})" . format ( OOOO0o ,
 iiiii11I1 ) )
  oOOOo0o = iiiii11I1 if len ( oOoI1Iii11iI1111 ) > 1 else None
  for dest in o0O0ooO0OoOo0OOO :
   lisp_send_info_request ( lisp_sockets , dest , port , oOOOo0o )
   if 8 - 8: I1Ii111
   if 86 - 86: ooOoO0o + iII111i * O0 % OoO0O00 + OoOoOO00
   if 49 - 49: OOooOOo / i1IIi - II111iiii . iIii1I11I1II1 + I11i . OOooOOo
   if 9 - 9: iIii1I11I1II1 + Ii1I + I11i
   if 96 - 96: OoO0O00 + i11iIiiIii + OoO0O00
   if 7 - 7: i1IIi . I1IiiI
 if ( ooOoOOOooOO0O != [ ] ) :
  for iiOoOoOoo0 in lisp_map_resolvers_list . values ( ) :
   iiOoOoOoo0 . resolve_dns_name ( )
   if 68 - 68: OoooooooOO
   if 91 - 91: IiII . ooOoO0o * I11i
 return
 if 39 - 39: o0oOOo0O0Ooo + i11iIiiIii
 if 69 - 69: iIii1I11I1II1 . II111iiii
 if 36 - 36: I1IiiI * i1IIi + OoOoOO00
 if 63 - 63: OoOoOO00 - iII111i
 if 83 - 83: i1IIi / iII111i % ooOoO0o % i11iIiiIii + I1ii11iIi11i
 if 82 - 82: iIii1I11I1II1 / OOooOOo
 if 7 - 7: OoooooooOO
 if 71 - 71: OOooOOo * Oo0Ooo . Oo0Ooo % iIii1I11I1II1
def lisp_valid_address_format ( kw , value ) :
 if ( kw != "address" ) : return ( True )
 if 56 - 56: IiII * iIii1I11I1II1 - iIii1I11I1II1 . O0
 if 56 - 56: I1Ii111 / iIii1I11I1II1 % IiII * iIii1I11I1II1 . I1ii11iIi11i . OOooOOo
 if 1 - 1: Ii1I . Ii1I % II111iiii + I11i + OoOoOO00
 if 52 - 52: OoooooooOO - OoO0O00
 if 24 - 24: iII111i / Oo0Ooo - I1ii11iIi11i + o0oOOo0O0Ooo
 if ( value [ 0 ] == "'" and value [ - 1 ] == "'" ) : return ( True )
 if 44 - 44: OoOoOO00 + I1IiiI . I1ii11iIi11i / i1IIi + II111iiii . Oo0Ooo
 if 39 - 39: o0oOOo0O0Ooo
 if 64 - 64: oO0o - i11iIiiIii
 if 62 - 62: OoooooooOO - OoooooooOO / OoO0O00 - II111iiii . iIii1I11I1II1
 if ( value . find ( "." ) != - 1 ) :
  I1Iii1I = value . split ( "." )
  if ( len ( I1Iii1I ) != 4 ) : return ( False )
  if 2 - 2: O0 + o0oOOo0O0Ooo % OOooOOo . ooOoO0o % i1IIi
  for IIIiI in I1Iii1I :
   if ( IIIiI . isdigit ( ) == False ) : return ( False )
   if ( int ( IIIiI ) > 255 ) : return ( False )
   if 95 - 95: I1Ii111 - Oo0Ooo % iII111i + OoooooooOO - I1ii11iIi11i % Ii1I
  return ( True )
  if 84 - 84: o0oOOo0O0Ooo
  if 78 - 78: II111iiii * Ii1I + II111iiii
  if 9 - 9: I1Ii111
  if 69 - 69: i1IIi + ooOoO0o + Ii1I
  if 88 - 88: OoOoOO00 + iII111i % O0 + OOooOOo / OoooooooOO / OOooOOo
 if ( value . find ( "-" ) != - 1 ) :
  I1Iii1I = value . split ( "-" )
  for oO in [ "N" , "S" , "W" , "E" ] :
   if ( oO in I1Iii1I ) :
    if ( len ( I1Iii1I ) < 8 ) : return ( False )
    return ( True )
    if 95 - 95: ooOoO0o . Oo0Ooo % IiII + iII111i
    if 16 - 16: I11i * OoO0O00 % o0oOOo0O0Ooo - O0 % II111iiii - I1IiiI
    if 72 - 72: OoooooooOO * OoOoOO00 . OOooOOo + Ii1I . OOooOOo / II111iiii
    if 8 - 8: i1IIi
    if 1 - 1: OoOoOO00 . OoO0O00 . OoO0O00 * O0
    if 97 - 97: OoooooooOO % ooOoO0o . I1Ii111 / iII111i
    if 59 - 59: II111iiii + O0 . I1ii11iIi11i . Oo0Ooo * OoO0O00
 if ( value . find ( "-" ) != - 1 ) :
  I1Iii1I = value . split ( "-" )
  if ( len ( I1Iii1I ) != 3 ) : return ( False )
  if 35 - 35: oO0o / I1Ii111 * OOooOOo + OoooooooOO . IiII
  for Iii1iIi in I1Iii1I :
   try : int ( Iii1iIi , 16 )
   except : return ( False )
   if 80 - 80: I1ii11iIi11i - o0oOOo0O0Ooo
  return ( True )
  if 16 - 16: OoOoOO00 * oO0o * Oo0Ooo / OOooOOo
  if 18 - 18: II111iiii - I1Ii111
  if 13 - 13: i11iIiiIii - O0 % OoOoOO00 + OOooOOo * ooOoO0o
  if 55 - 55: i1IIi - OOooOOo / I11i * Ii1I
  if 20 - 20: OoOoOO00 * iIii1I11I1II1 % O0 - i1IIi
 if ( value . find ( ":" ) != - 1 ) :
  I1Iii1I = value . split ( ":" )
  if ( len ( I1Iii1I ) < 2 ) : return ( False )
  if 51 - 51: I1ii11iIi11i * Ii1I - oO0o / O0 * OoooooooOO
  Iiii = False
  i111I11I = 0
  for Iii1iIi in I1Iii1I :
   i111I11I += 1
   if ( Iii1iIi == "" ) :
    if ( Iiii ) :
     if ( len ( I1Iii1I ) == i111I11I ) : break
     if ( i111I11I > 2 ) : return ( False )
     if 92 - 92: OoO0O00
    Iiii = True
    continue
    if 15 - 15: i11iIiiIii / IiII + Ii1I % OOooOOo % I1ii11iIi11i * oO0o
   try : int ( Iii1iIi , 16 )
   except : return ( False )
   if 24 - 24: OOooOOo / OOooOOo + I11i / iII111i . oO0o - iII111i
  return ( True )
  if 59 - 59: I1ii11iIi11i % II111iiii - i11iIiiIii - I1Ii111
  if 34 - 34: II111iiii + iII111i / IiII
  if 47 - 47: OoO0O00
  if 40 - 40: o0oOOo0O0Ooo / iII111i . o0oOOo0O0Ooo
  if 63 - 63: o0oOOo0O0Ooo * iIii1I11I1II1 * II111iiii . OoO0O00 - oO0o / OoOoOO00
 if ( value [ 0 ] == "+" ) :
  I1Iii1I = value [ 1 : : ]
  for OooO in I1Iii1I :
   if ( OooO . isdigit ( ) == False ) : return ( False )
   if 5 - 5: ooOoO0o . OoO0O00
  return ( True )
  if 2 - 2: IiII . I11i
 return ( False )
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
 if 95 - 95: ooOoO0o . I1ii11iIi11i . ooOoO0o / I1IiiI * OoOoOO00 . O0
def lisp_process_api ( process , lisp_socket , data_structure ) :
 oooOOoooo , o00O = data_structure . split ( "%" )
 if 71 - 71: Ii1I * I1IiiI
 lprint ( "Process API request '{}', parameters: '{}'" . format ( oooOOoooo ,
 o00O ) )
 if 62 - 62: II111iiii / I1IiiI . I1ii11iIi11i
 o00o0o0o = [ ]
 if ( oooOOoooo == "map-cache" ) :
  if ( o00O == "" ) :
   o00o0o0o = lisp_map_cache . walk_cache ( lisp_process_api_map_cache , o00o0o0o )
  else :
   o00o0o0o = lisp_process_api_map_cache_entry ( json . loads ( o00O ) )
   if 49 - 49: IiII / OoOoOO00 / O0 * i11iIiiIii
   if 47 - 47: i11iIiiIii + iII111i + i11iIiiIii
 if ( oooOOoooo == "site-cache" ) :
  if ( o00O == "" ) :
   o00o0o0o = lisp_sites_by_eid . walk_cache ( lisp_process_api_site_cache ,
 o00o0o0o )
  else :
   o00o0o0o = lisp_process_api_site_cache_entry ( json . loads ( o00O ) )
   if 66 - 66: o0oOOo0O0Ooo . I1IiiI + OoooooooOO . iII111i / OoooooooOO - IiII
   if 47 - 47: o0oOOo0O0Ooo / II111iiii * i11iIiiIii * OoO0O00 . iIii1I11I1II1
 if ( oooOOoooo == "map-server" ) :
  o00O = { } if ( o00O == "" ) else json . loads ( o00O )
  o00o0o0o = lisp_process_api_ms_or_mr ( True , o00O )
  if 34 - 34: I11i / o0oOOo0O0Ooo * OOooOOo * OOooOOo
 if ( oooOOoooo == "map-resolver" ) :
  o00O = { } if ( o00O == "" ) else json . loads ( o00O )
  o00o0o0o = lisp_process_api_ms_or_mr ( False , o00O )
  if 89 - 89: I1ii11iIi11i . OoooooooOO
 if ( oooOOoooo == "database-mapping" ) :
  o00o0o0o = lisp_process_api_database_mapping ( )
  if 61 - 61: i1IIi + i11iIiiIii
  if 59 - 59: i11iIiiIii * OOooOOo + i1IIi * iIii1I11I1II1 + I11i
  if 97 - 97: OoO0O00 - I11i . OoooooooOO
  if 58 - 58: I1ii11iIi11i / II111iiii / i11iIiiIii
  if 27 - 27: iIii1I11I1II1 - O0 + OoOoOO00
 o00o0o0o = json . dumps ( o00o0o0o )
 OooOoO0OO00 = lisp_api_ipc ( process , o00o0o0o )
 lisp_ipc ( OooOoO0OO00 , lisp_socket , "lisp-core" )
 return
 if 28 - 28: oO0o . IiII * iII111i % Oo0Ooo - OoO0O00 / I11i
 if 67 - 67: i11iIiiIii + i11iIiiIii / ooOoO0o - o0oOOo0O0Ooo
 if 94 - 94: O0 + OoO0O00 / I1IiiI * II111iiii * i11iIiiIii
 if 55 - 55: OoooooooOO * O0 + i1IIi % I1IiiI
 if 10 - 10: II111iiii - Ii1I . I11i . O0 + Ii1I
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
 oo = { }
 oo [ "instance-id" ] = str ( mc . eid . instance_id )
 oo [ "eid-prefix" ] = mc . eid . print_prefix_no_iid ( )
 if ( mc . group . is_null ( ) == False ) :
  oo [ "group-prefix" ] = mc . group . print_prefix_no_iid ( )
  if 93 - 93: i1IIi / Ii1I * II111iiii - Oo0Ooo . OoOoOO00 - OOooOOo
 oo [ "uptime" ] = lisp_print_elapsed ( mc . uptime )
 oo [ "expires" ] = lisp_print_elapsed ( mc . uptime )
 oo [ "action" ] = lisp_map_reply_action_string [ mc . action ]
 oo [ "ttl" ] = "--" if mc . map_cache_ttl == None else str ( mc . map_cache_ttl / 60 )
 if 25 - 25: I11i / ooOoO0o % ooOoO0o - OOooOOo
 if 59 - 59: I1IiiI + o0oOOo0O0Ooo . iIii1I11I1II1 - O0 - i11iIiiIii
 if 4 - 4: I1IiiI
 if 36 - 36: Ii1I
 if 76 - 76: i11iIiiIii + i1IIi
 I1111Ii1II1I = [ ]
 for II1iIiIiIIi in mc . rloc_set :
  oOo0Oooo = { }
  if ( II1iIiIiIIi . rloc_exists ( ) ) :
   oOo0Oooo [ "address" ] = II1iIiIiIIi . rloc . print_address_no_iid ( )
   if 56 - 56: OoOoOO00 + II111iiii / i11iIiiIii * OoOoOO00 * OoooooooOO
   if 15 - 15: OoOoOO00 / OoooooooOO + OOooOOo
  if ( II1iIiIiIIi . translated_port != 0 ) :
   oOo0Oooo [ "encap-port" ] = str ( II1iIiIiIIi . translated_port )
   if 76 - 76: Ii1I * iII111i . OoooooooOO
  oOo0Oooo [ "state" ] = II1iIiIiIIi . print_state ( )
  if ( II1iIiIiIIi . geo ) : oOo0Oooo [ "geo" ] = II1iIiIiIIi . geo . print_geo ( )
  if ( II1iIiIiIIi . elp ) : oOo0Oooo [ "elp" ] = II1iIiIiIIi . elp . print_elp ( False )
  if ( II1iIiIiIIi . rle ) : oOo0Oooo [ "rle" ] = II1iIiIiIIi . rle . print_rle ( False )
  if ( II1iIiIiIIi . json ) : oOo0Oooo [ "json" ] = II1iIiIiIIi . json . print_json ( False )
  if ( II1iIiIiIIi . rloc_name ) : oOo0Oooo [ "rloc-name" ] = II1iIiIiIIi . rloc_name
  O00o0O0 = II1iIiIiIIi . stats . get_stats ( False , False )
  if ( O00o0O0 ) : oOo0Oooo [ "stats" ] = O00o0O0
  oOo0Oooo [ "uptime" ] = lisp_print_elapsed ( II1iIiIiIIi . uptime )
  oOo0Oooo [ "upriority" ] = str ( II1iIiIiIIi . priority )
  oOo0Oooo [ "uweight" ] = str ( II1iIiIiIIi . weight )
  oOo0Oooo [ "mpriority" ] = str ( II1iIiIiIIi . mpriority )
  oOo0Oooo [ "mweight" ] = str ( II1iIiIiIIi . mweight )
  OoOOOO0O0 = II1iIiIiIIi . last_rloc_probe_reply
  if ( OoOOOO0O0 ) :
   oOo0Oooo [ "last-rloc-probe-reply" ] = lisp_print_elapsed ( OoOOOO0O0 )
   oOo0Oooo [ "rloc-probe-rtt" ] = str ( II1iIiIiIIi . rloc_probe_rtt )
   if 44 - 44: I1Ii111 - II111iiii / OOooOOo
  oOo0Oooo [ "rloc-hop-count" ] = II1iIiIiIIi . rloc_probe_hops
  oOo0Oooo [ "recent-rloc-hop-counts" ] = II1iIiIiIIi . recent_rloc_probe_hops
  if 50 - 50: I11i / I1ii11iIi11i
  OoO0 = [ ]
  for oooo0000 in II1iIiIiIIi . recent_rloc_probe_rtts : OoO0 . append ( str ( oooo0000 ) )
  oOo0Oooo [ "recent-rloc-probe-rtts" ] = OoO0
  if 78 - 78: I1IiiI * i1IIi / II111iiii
  I1111Ii1II1I . append ( oOo0Oooo )
  if 91 - 91: I1IiiI * I1Ii111 * i11iIiiIii - oO0o - IiII + I1ii11iIi11i
 oo [ "rloc-set" ] = I1111Ii1II1I
 if 99 - 99: OoO0O00 % o0oOOo0O0Ooo
 data . append ( oo )
 return ( [ True , data ] )
 if 3 - 3: OOooOOo / OoOoOO00 % iIii1I11I1II1
 if 47 - 47: ooOoO0o . i11iIiiIii / OoO0O00
 if 48 - 48: O0
 if 89 - 89: i11iIiiIii % OoO0O00 . OoOoOO00 + Oo0Ooo + OoOoOO00
 if 53 - 53: Ii1I / OoOoOO00 % iII111i * OoooooooOO + Oo0Ooo
 if 70 - 70: OoO0O00 % OoO0O00 * OoooooooOO
 if 96 - 96: ooOoO0o * Ii1I + I11i + II111iiii * I1IiiI / iII111i
def lisp_process_api_map_cache_entry ( parms ) :
 IIiI1i = parms [ "instance-id" ]
 IIiI1i = 0 if ( IIiI1i == "" ) else int ( IIiI1i )
 if 40 - 40: OoooooooOO - I11i % OOooOOo - I1IiiI . I1IiiI + Ii1I
 if 97 - 97: OOooOOo . OoooooooOO . OOooOOo . i11iIiiIii
 if 71 - 71: oO0o + I1ii11iIi11i * I1ii11iIi11i
 if 79 - 79: oO0o
 III1II1I1iI = lisp_address ( LISP_AFI_NONE , "" , 0 , IIiI1i )
 III1II1I1iI . store_prefix ( parms [ "eid-prefix" ] )
 IiI1 = III1II1I1iI
 oo0O00 = III1II1I1iI
 if 47 - 47: OoooooooOO - i1IIi * OOooOOo
 if 11 - 11: I11i / OOooOOo . o0oOOo0O0Ooo - O0 * OoooooooOO % iII111i
 if 7 - 7: OoOoOO00 . IiII + OoooooooOO - I1Ii111 / oO0o
 if 32 - 32: iIii1I11I1II1 + I11i + OOooOOo - OoooooooOO + i11iIiiIii * o0oOOo0O0Ooo
 if 8 - 8: iII111i
 oO0000O0o = lisp_address ( LISP_AFI_NONE , "" , 0 , IIiI1i )
 if ( parms . has_key ( "group-prefix" ) ) :
  oO0000O0o . store_prefix ( parms [ "group-prefix" ] )
  IiI1 = oO0000O0o
  if 10 - 10: OoOoOO00 % I11i
  if 49 - 49: oO0o % ooOoO0o + II111iiii
 o00o0o0o = [ ]
 iIi11 = lisp_map_cache_lookup ( oo0O00 , IiI1 )
 if ( iIi11 ) : iI1Ii11iiII , o00o0o0o = lisp_process_api_map_cache ( iIi11 , o00o0o0o )
 return ( o00o0o0o )
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
 I1Ii11i = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
 IIiiiIiI = data [ "dns-name" ] if data . has_key ( "dns-name" ) else None
 if ( data . has_key ( "address" ) ) :
  I1Ii11i . store_address ( data [ "address" ] )
  if 33 - 33: OoOoOO00 / i11iIiiIii - I1IiiI - OoooooooOO + i1IIi * I1Ii111
  if 92 - 92: iII111i + OoO0O00
 oOOO = { }
 if ( ms_or_mr ) :
  for ooo0OoOOo in lisp_map_servers_list . values ( ) :
   if ( IIiiiIiI ) :
    if ( IIiiiIiI != ooo0OoOOo . dns_name ) : continue
   else :
    if ( I1Ii11i . is_exact_match ( ooo0OoOOo . map_server ) == False ) : continue
    if 70 - 70: iIii1I11I1II1
    if 100 - 100: OOooOOo . oO0o % ooOoO0o * ooOoO0o . I1Ii111 - oO0o
   oOOO [ "dns-name" ] = ooo0OoOOo . dns_name
   oOOO [ "address" ] = ooo0OoOOo . map_server . print_address_no_iid ( )
   oOOO [ "ms-name" ] = "" if ooo0OoOOo . ms_name == None else ooo0OoOOo . ms_name
   return ( [ oOOO ] )
   if 33 - 33: Oo0Ooo . i1IIi - OoooooooOO
 else :
  for iiOoOoOoo0 in lisp_map_resolvers_list . values ( ) :
   if ( IIiiiIiI ) :
    if ( IIiiiIiI != iiOoOoOoo0 . dns_name ) : continue
   else :
    if ( I1Ii11i . is_exact_match ( iiOoOoOoo0 . map_resolver ) == False ) : continue
    if 14 - 14: I1Ii111 + Oo0Ooo
    if 35 - 35: i11iIiiIii * Ii1I
   oOOO [ "dns-name" ] = iiOoOoOoo0 . dns_name
   oOOO [ "address" ] = iiOoOoOoo0 . map_resolver . print_address_no_iid ( )
   oOOO [ "mr-name" ] = "" if iiOoOoOoo0 . mr_name == None else iiOoOoOoo0 . mr_name
   return ( [ oOOO ] )
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
 o00o0o0o = [ ]
 if 9 - 9: OoooooooOO * OOooOOo % OoO0O00 - ooOoO0o + Ii1I
 for o0O00o in lisp_db_list :
  oo = { }
  oo [ "eid-prefix" ] = o0O00o . eid . print_prefix ( )
  if ( o0O00o . group . is_null ( ) == False ) :
   oo [ "group-prefix" ] = o0O00o . group . print_prefix ( )
   if 39 - 39: iIii1I11I1II1 / i1IIi % I11i % I1ii11iIi11i * IiII
   if 11 - 11: II111iiii + i1IIi
  iIiIii1I1 = [ ]
  for oOo0Oooo in o0O00o . rloc_set :
   II1iIiIiIIi = { }
   if ( oOo0Oooo . rloc . is_null ( ) == False ) :
    II1iIiIiIIi [ "rloc" ] = oOo0Oooo . rloc . print_address_no_iid ( )
    if 1 - 1: OOooOOo
   if ( oOo0Oooo . rloc_name != None ) : II1iIiIiIIi [ "rloc-name" ] = oOo0Oooo . rloc_name
   if ( oOo0Oooo . interface != None ) : II1iIiIiIIi [ "interface" ] = oOo0Oooo . interface
   Ii1iiI = oOo0Oooo . translated_rloc
   if ( Ii1iiI . is_null ( ) == False ) :
    II1iIiIiIIi [ "translated-rloc" ] = Ii1iiI . print_address_no_iid ( )
    if 37 - 37: OoooooooOO . o0oOOo0O0Ooo - o0oOOo0O0Ooo - Oo0Ooo / I1IiiI
   if ( II1iIiIiIIi != { } ) : iIiIii1I1 . append ( II1iIiIiIIi )
   if 87 - 87: IiII
   if 68 - 68: I1Ii111 + I1ii11iIi11i * IiII . OoO0O00 / I11i
   if 39 - 39: Oo0Ooo + OOooOOo . I1IiiI + OoO0O00 . OoooooooOO
   if 31 - 31: OoO0O00
   if 55 - 55: OoOoOO00 + I1Ii111 * o0oOOo0O0Ooo - I1ii11iIi11i + OoOoOO00
  oo [ "rlocs" ] = iIiIii1I1
  if 6 - 6: II111iiii % iIii1I11I1II1 * I1Ii111
  if 2 - 2: IiII - I1Ii111 . iIii1I11I1II1 - Ii1I * I11i
  if 58 - 58: i1IIi % iIii1I11I1II1 % i11iIiiIii - o0oOOo0O0Ooo + ooOoO0o
  if 23 - 23: Oo0Ooo % Oo0Ooo / IiII
  o00o0o0o . append ( oo )
  if 63 - 63: I11i % Oo0Ooo * I1Ii111 - Oo0Ooo % i11iIiiIii . II111iiii
 return ( o00o0o0o )
 if 44 - 44: I11i . I1Ii111 . I1ii11iIi11i . oO0o
 if 1 - 1: I11i % II111iiii / OoO0O00 + OoO0O00
 if 46 - 46: Oo0Ooo * Ii1I / IiII % O0 * iII111i
 if 74 - 74: OoooooooOO + Ii1I
 if 100 - 100: I1IiiI
 if 59 - 59: I1IiiI - OoOoOO00 * ooOoO0o / O0
 if 54 - 54: Oo0Ooo % iIii1I11I1II1 * Oo0Ooo
def lisp_gather_site_cache_data ( se , data ) :
 oo = { }
 oo [ "site-name" ] = se . site . site_name
 oo [ "instance-id" ] = str ( se . eid . instance_id )
 oo [ "eid-prefix" ] = se . eid . print_prefix_no_iid ( )
 if ( se . group . is_null ( ) == False ) :
  oo [ "group-prefix" ] = se . group . print_prefix_no_iid ( )
  if 80 - 80: I1ii11iIi11i - I1ii11iIi11i
 oo [ "registered" ] = "yes" if se . registered else "no"
 oo [ "first-registered" ] = lisp_print_elapsed ( se . first_registered )
 oo [ "last-registered" ] = lisp_print_elapsed ( se . last_registered )
 if 26 - 26: I1ii11iIi11i - I1IiiI * I1Ii111 % iIii1I11I1II1
 I1Iii1I = se . last_registerer
 I1Iii1I = "none" if I1Iii1I . is_null ( ) else I1Iii1I . print_address ( )
 oo [ "last-registerer" ] = I1Iii1I
 oo [ "ams" ] = "yes" if ( se . accept_more_specifics ) else "no"
 oo [ "dynamic" ] = "yes" if ( se . dynamic ) else "no"
 oo [ "site-id" ] = str ( se . site_id )
 if ( se . xtr_id_present ) :
  oo [ "xtr-id" ] = "0x" + lisp_hex_string ( se . xtr_id )
  if 77 - 77: o0oOOo0O0Ooo + I1Ii111 . OOooOOo . i1IIi . I1IiiI
  if 100 - 100: ooOoO0o . i11iIiiIii + Ii1I - OOooOOo - i11iIiiIii - OoooooooOO
  if 42 - 42: OoOoOO00 . I1IiiI / OoOoOO00 / I1ii11iIi11i . OoO0O00
  if 67 - 67: Ii1I - O0 . OoooooooOO . I1Ii111 . o0oOOo0O0Ooo
  if 73 - 73: I11i - oO0o . I1Ii111 + oO0o
 I1111Ii1II1I = [ ]
 for II1iIiIiIIi in se . registered_rlocs :
  oOo0Oooo = { }
  oOo0Oooo [ "address" ] = II1iIiIiIIi . rloc . print_address_no_iid ( ) if II1iIiIiIIi . rloc_exists ( ) else "none"
  if 48 - 48: IiII . IiII * o0oOOo0O0Ooo * II111iiii % ooOoO0o
  if 40 - 40: I1ii11iIi11i
  if ( II1iIiIiIIi . geo ) : oOo0Oooo [ "geo" ] = II1iIiIiIIi . geo . print_geo ( )
  if ( II1iIiIiIIi . elp ) : oOo0Oooo [ "elp" ] = II1iIiIiIIi . elp . print_elp ( False )
  if ( II1iIiIiIIi . rle ) : oOo0Oooo [ "rle" ] = II1iIiIiIIi . rle . print_rle ( False )
  if ( II1iIiIiIIi . json ) : oOo0Oooo [ "json" ] = II1iIiIiIIi . json . print_json ( False )
  if ( II1iIiIiIIi . rloc_name ) : oOo0Oooo [ "rloc-name" ] = II1iIiIiIIi . rloc_name
  oOo0Oooo [ "uptime" ] = lisp_print_elapsed ( II1iIiIiIIi . uptime )
  oOo0Oooo [ "upriority" ] = str ( II1iIiIiIIi . priority )
  oOo0Oooo [ "uweight" ] = str ( II1iIiIiIIi . weight )
  oOo0Oooo [ "mpriority" ] = str ( II1iIiIiIIi . mpriority )
  oOo0Oooo [ "mweight" ] = str ( II1iIiIiIIi . mweight )
  if 76 - 76: Oo0Ooo - I11i
  I1111Ii1II1I . append ( oOo0Oooo )
  if 82 - 82: OoO0O00 % oO0o . I11i / O0 - I1Ii111
 oo [ "registered-rlocs" ] = I1111Ii1II1I
 if 39 - 39: I1IiiI
 data . append ( oo )
 return ( [ True , data ] )
 if 8 - 8: IiII * i1IIi * i1IIi * O0
 if 69 - 69: Oo0Ooo
 if 48 - 48: iII111i
 if 11 - 11: i11iIiiIii * OoOoOO00 . OoO0O00
 if 47 - 47: Oo0Ooo % I1Ii111 + ooOoO0o
 if 89 - 89: iII111i
 if 29 - 29: I1ii11iIi11i . ooOoO0o * II111iiii / iII111i . OoooooooOO - OoOoOO00
def lisp_process_api_site_cache_entry ( parms ) :
 IIiI1i = parms [ "instance-id" ]
 IIiI1i = 0 if ( IIiI1i == "" ) else int ( IIiI1i )
 if 99 - 99: IiII % O0 - I1Ii111 * OoO0O00
 if 77 - 77: OoooooooOO - I11i / I1IiiI % OoOoOO00 - OOooOOo
 if 37 - 37: ooOoO0o
 if 22 - 22: I1ii11iIi11i + II111iiii / OoooooooOO % o0oOOo0O0Ooo * OoOoOO00 . Oo0Ooo
 III1II1I1iI = lisp_address ( LISP_AFI_NONE , "" , 0 , IIiI1i )
 III1II1I1iI . store_prefix ( parms [ "eid-prefix" ] )
 if 26 - 26: OoO0O00 % oO0o * Ii1I % OoooooooOO - oO0o
 if 46 - 46: I1IiiI + OoO0O00 - O0 * O0
 if 75 - 75: OOooOOo + iIii1I11I1II1 * OOooOOo
 if 82 - 82: iII111i - I1Ii111 - OoOoOO00
 if 96 - 96: Oo0Ooo . Oo0Ooo % o0oOOo0O0Ooo - I1IiiI * iIii1I11I1II1
 oO0000O0o = lisp_address ( LISP_AFI_NONE , "" , 0 , IIiI1i )
 if ( parms . has_key ( "group-prefix" ) ) :
  oO0000O0o . store_prefix ( parms [ "group-prefix" ] )
  if 29 - 29: i1IIi / Ii1I / oO0o * iII111i
  if 44 - 44: O0
 o00o0o0o = [ ]
 I1i11I = lisp_site_eid_lookup ( III1II1I1iI , oO0000O0o , False )
 if ( I1i11I ) : lisp_gather_site_cache_data ( I1i11I , o00o0o0o )
 return ( o00o0o0o )
 if 95 - 95: OOooOOo + OOooOOo - OoOoOO00
 if 83 - 83: II111iiii * ooOoO0o - O0 - i11iIiiIii
 if 62 - 62: I1IiiI + II111iiii * iIii1I11I1II1 % iII111i + IiII / ooOoO0o
 if 14 - 14: iIii1I11I1II1 * I1ii11iIi11i + OOooOOo + O0
 if 79 - 79: II111iiii - iII111i
 if 89 - 89: O0 - OoO0O00
 if 8 - 8: I1ii11iIi11i / oO0o - OoooooooOO + ooOoO0o + o0oOOo0O0Ooo % i11iIiiIii
def lisp_get_interface_instance_id ( device , source_eid ) :
 iiiii11I1 = None
 if ( lisp_myinterfaces . has_key ( device ) ) :
  iiiii11I1 = lisp_myinterfaces [ device ]
  if 32 - 32: O0 + IiII
  if 93 - 93: OoOoOO00 - I11i / iII111i - iIii1I11I1II1 + I11i % oO0o
  if 24 - 24: Ii1I / iIii1I11I1II1 + o0oOOo0O0Ooo
  if 17 - 17: OOooOOo
  if 75 - 75: Ii1I / i1IIi % I1ii11iIi11i . Ii1I
  if 46 - 46: II111iiii * OoO0O00
 if ( iiiii11I1 == None or iiiii11I1 . instance_id == None ) :
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
 IIiI1i = iiiii11I1 . get_instance_id ( )
 if ( source_eid == None ) : return ( IIiI1i )
 if 94 - 94: II111iiii . II111iiii / OoOoOO00 % oO0o * i1IIi % Oo0Ooo
 o0OO0OOO = source_eid . instance_id
 oO0oO000ooo0o = None
 for iiiii11I1 in lisp_multi_tenant_interfaces :
  if ( iiiii11I1 . device != device ) : continue
  O0OoOoo000OoO = iiiii11I1 . multi_tenant_eid
  source_eid . instance_id = O0OoOoo000OoO . instance_id
  if ( source_eid . is_more_specific ( O0OoOoo000OoO ) == False ) : continue
  if ( oO0oO000ooo0o == None or oO0oO000ooo0o . multi_tenant_eid . mask_len < O0OoOoo000OoO . mask_len ) :
   oO0oO000ooo0o = iiiii11I1
   if 21 - 21: Ii1I * iIii1I11I1II1 % O0 % I11i + Ii1I
   if 40 - 40: o0oOOo0O0Ooo / IiII
 source_eid . instance_id = o0OO0OOO
 if 25 - 25: i1IIi + o0oOOo0O0Ooo
 if ( oO0oO000ooo0o == None ) : return ( IIiI1i )
 return ( oO0oO000ooo0o . get_instance_id ( ) )
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
 iiiii11I1 = lisp_myinterfaces [ device ]
 oo0Oo = device if iiiii11I1 . dynamic_eid_device == None else iiiii11I1 . dynamic_eid_device
 if 70 - 70: OoO0O00 * II111iiii / I11i + I11i
 if 23 - 23: I1IiiI
 if ( iiiii11I1 . does_dynamic_eid_match ( eid ) ) : return ( oo0Oo )
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
 II1I11 = threading . Timer ( interval , I1iIi1II1i , [ lisp_sockets ] )
 lisp_rloc_probe_timer = II1I11
 II1I11 . start ( )
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
 for OOoOoO in lisp_rloc_probe_list :
  OOoOo0 = lisp_rloc_probe_list [ OOoOoO ]
  lprint ( "RLOC {}:" . format ( OOoOoO ) )
  for oOo0Oooo , I1i11II , O0000O in OOoOo0 :
   lprint ( "  [{}, {}, {}, {}]" . format ( hex ( id ( oOo0Oooo ) ) , I1i11II . print_prefix ( ) ,
 O0000O . print_prefix ( ) , oOo0Oooo . translated_port ) )
   if 17 - 17: i11iIiiIii % O0 * Ii1I
   if 49 - 49: I1ii11iIi11i . i1IIi + OoO0O00 % O0 + OoO0O00
 lprint ( bold ( "---------------------------" , False ) )
 return
 if 21 - 21: ooOoO0o * oO0o / OoooooooOO % ooOoO0o / O0
 if 24 - 24: OoO0O00 - i11iIiiIii / i11iIiiIii * I1Ii111
 if 20 - 20: IiII % iIii1I11I1II1 . iII111i + iIii1I11I1II1 + O0
 if 96 - 96: I1ii11iIi11i - IiII % OoooooooOO . iII111i
 if 30 - 30: Oo0Ooo . OoooooooOO / Oo0Ooo / oO0o
 if 44 - 44: I1ii11iIi11i % o0oOOo0O0Ooo / iIii1I11I1II1 - o0oOOo0O0Ooo / I11i * I1Ii111
 if 49 - 49: iII111i / iII111i - OoOoOO00
 if 89 - 89: ooOoO0o
 if 16 - 16: oO0o + oO0o + i1IIi + iIii1I11I1II1
def lisp_mark_rlocs_for_other_eids ( eid_list ) :
 if 93 - 93: I1IiiI - i11iIiiIii * I1Ii111 - O0 + iII111i
 if 11 - 11: iII111i
 if 100 - 100: OoooooooOO / ooOoO0o . OoO0O00
 if 89 - 89: I11i % II111iiii
 II1iIiIiIIi , I1i11II , O0000O = eid_list [ 0 ]
 iIii1IiII = [ lisp_print_eid_tuple ( I1i11II , O0000O ) ]
 if 45 - 45: iIii1I11I1II1 % II111iiii . iIii1I11I1II1 * IiII
 for II1iIiIiIIi , I1i11II , O0000O in eid_list [ 1 : : ] :
  II1iIiIiIIi . state = LISP_RLOC_UNREACH_STATE
  II1iIiIiIIi . last_state_change = lisp_get_timestamp ( )
  iIii1IiII . append ( lisp_print_eid_tuple ( I1i11II , O0000O ) )
  if 17 - 17: iII111i - OOooOOo / OOooOOo % OoO0O00 + i11iIiiIii % OoO0O00
  if 13 - 13: I1IiiI + Oo0Ooo * I1IiiI . i1IIi * I1ii11iIi11i + iII111i
 o0oOoO00O0OoO = bold ( "unreachable" , False )
 IIII1i = red ( II1iIiIiIIi . rloc . print_address_no_iid ( ) , False )
 if 5 - 5: IiII % I1Ii111 - OoO0O00 * oO0o / IiII
 for III1II1I1iI in iIii1IiII :
  I1i11II = green ( III1II1I1iI , False )
  lprint ( "RLOC {} went {} for EID {}" . format ( IIII1i , o0oOoO00O0OoO , I1i11II ) )
  if 50 - 50: I1Ii111
  if 25 - 25: i11iIiiIii * I11i % o0oOOo0O0Ooo + OoooooooOO
  if 88 - 88: OoooooooOO % OOooOOo . iIii1I11I1II1 - I1IiiI
  if 42 - 42: II111iiii
  if 49 - 49: OoooooooOO
  if 48 - 48: i1IIi . IiII - O0 + OoooooooOO
 for II1iIiIiIIi , I1i11II , O0000O in eid_list :
  iIi11 = lisp_map_cache . lookup_cache ( I1i11II , True )
  if ( iIi11 ) : lisp_write_ipc_map_cache ( True , iIi11 )
  if 6 - 6: I1Ii111 * OOooOOo + o0oOOo0O0Ooo . I1ii11iIi11i * I1Ii111
 return
 if 6 - 6: oO0o / II111iiii
 if 23 - 23: IiII - OoooooooOO / oO0o
 if 69 - 69: O0 - OoooooooOO
 if 31 - 31: o0oOOo0O0Ooo . i1IIi - i1IIi % i1IIi - iIii1I11I1II1
 if 50 - 50: IiII - OOooOOo % OoOoOO00
 if 66 - 66: IiII * i11iIiiIii
 if 64 - 64: i11iIiiIii . I1Ii111 % i11iIiiIii % I11i
 if 56 - 56: o0oOOo0O0Ooo + ooOoO0o + OoooooooOO
 if 64 - 64: OOooOOo / OoOoOO00
 if 30 - 30: OOooOOo % I1Ii111 - i11iIiiIii
def lisp_process_rloc_probe_timer ( lisp_sockets ) :
 lisp_set_exception ( )
 if 20 - 20: i1IIi * I11i / OoO0O00 / i1IIi / I1Ii111 * O0
 lisp_start_rloc_probe_timer ( LISP_RLOC_PROBE_INTERVAL , lisp_sockets )
 if ( lisp_rloc_probing == False ) : return
 if 95 - 95: Ii1I + Ii1I % IiII - IiII / OOooOOo
 if 46 - 46: IiII + iII111i + II111iiii . iII111i - i11iIiiIii % OoO0O00
 if 24 - 24: oO0o + IiII . o0oOOo0O0Ooo . OoooooooOO . i11iIiiIii / I1ii11iIi11i
 if 49 - 49: IiII
 if ( lisp_print_rloc_probe_list ) : lisp_show_rloc_probe_list ( )
 if 1 - 1: oO0o / I11i
 if 99 - 99: OoO0O00 % IiII + I1Ii111 - oO0o
 if 28 - 28: OOooOOo - O0 - O0 % i11iIiiIii * OoooooooOO
 if 60 - 60: OoooooooOO / i1IIi / i1IIi / Ii1I . IiII
 iiooooo = lisp_get_default_route_next_hops ( )
 if 1 - 1: oO0o - i11iIiiIii . OoOoOO00
 lprint ( "---------- Start RLOC Probing for {} entries ----------" . format ( len ( lisp_rloc_probe_list ) ) )
 if 16 - 16: OOooOOo
 if 33 - 33: o0oOOo0O0Ooo / OoO0O00 + OoooooooOO
 if 82 - 82: o0oOOo0O0Ooo / i1IIi / i11iIiiIii * Oo0Ooo / OoO0O00
 if 95 - 95: I11i . OoOoOO00 * Ii1I
 if 94 - 94: OoOoOO00 / OoO0O00 / ooOoO0o + II111iiii
 i111I11I = 0
 iI1IiIIii1I = bold ( "RLOC-probe" , False )
 for oo0oO0Oo in lisp_rloc_probe_list . values ( ) :
  if 80 - 80: i11iIiiIii * i1IIi
  if 53 - 53: OoooooooOO - i1IIi - Ii1I
  if 73 - 73: I1ii11iIi11i - Ii1I * o0oOOo0O0Ooo
  if 29 - 29: o0oOOo0O0Ooo % IiII % OOooOOo + OoooooooOO - o0oOOo0O0Ooo
  if 34 - 34: Ii1I
  iiIo0Oo0o00OoO00O0O = None
  for IIii1IIiIi , III1II1I1iI , oO0000O0o in oo0oO0Oo :
   I11i11I = IIii1IIiIi . rloc . print_address_no_iid ( )
   if 35 - 35: ooOoO0o % iIii1I11I1II1 * OOooOOo
   if 44 - 44: Oo0Ooo + iIii1I11I1II1
   if 67 - 67: iII111i . OOooOOo / ooOoO0o * iIii1I11I1II1
   if 29 - 29: I1Ii111 / OoOoOO00 % I1ii11iIi11i * IiII / II111iiii
   if 10 - 10: O0 / I11i
   if 29 - 29: i11iIiiIii % I11i
   if ( IIii1IIiIi . down_state ( ) ) : continue
   if 49 - 49: I11i
   if 69 - 69: o0oOOo0O0Ooo . O0 * I11i
   if 92 - 92: OoO0O00 . O0 / Ii1I % Oo0Ooo . Ii1I
   if 40 - 40: o0oOOo0O0Ooo - Ii1I . iII111i - O0
   if 53 - 53: Oo0Ooo - I1IiiI * O0 . II111iiii
   if 72 - 72: ooOoO0o - Ii1I . Ii1I . I11i / OoooooooOO + Ii1I
   if 32 - 32: O0
   if 42 - 42: i1IIi * I1ii11iIi11i * OoOoOO00
   if 43 - 43: I1ii11iIi11i % I1ii11iIi11i % i1IIi
   if 56 - 56: I1IiiI - OoO0O00 - iII111i . o0oOOo0O0Ooo . I1Ii111
   if 70 - 70: iIii1I11I1II1 - I11i
   if ( iiIo0Oo0o00OoO00O0O ) :
    IIii1IIiIi . last_rloc_probe_nonce = iiIo0Oo0o00OoO00O0O . last_rloc_probe_nonce
    if 2 - 2: oO0o / II111iiii * OoO0O00
    if ( iiIo0Oo0o00OoO00O0O . translated_port == IIii1IIiIi . translated_port and iiIo0Oo0o00OoO00O0O . rloc_name == IIii1IIiIi . rloc_name ) :
     if 71 - 71: i1IIi + I11i * OoO0O00 . OOooOOo + oO0o
     I1i11II = green ( lisp_print_eid_tuple ( III1II1I1iI , oO0000O0o ) , False )
     lprint ( "Suppress probe to duplicate RLOC {} for {}" . format ( red ( I11i11I , False ) , I1i11II ) )
     if 40 - 40: OOooOOo
     continue
     if 14 - 14: OoooooooOO - OoooooooOO % i11iIiiIii % ooOoO0o / ooOoO0o
     if 33 - 33: iII111i / i1IIi . II111iiii % I1ii11iIi11i
     if 74 - 74: iII111i / OOooOOo / O0 / iIii1I11I1II1 + IiII
   O0Oo0OO = None
   II1iIiIiIIi = None
   while ( True ) :
    II1iIiIiIIi = IIii1IIiIi if II1iIiIiIIi == None else II1iIiIiIIi . next_rloc
    if ( II1iIiIiIIi == None ) : break
    if 26 - 26: OOooOOo % i1IIi . I1Ii111 / O0 + I1Ii111
    if 39 - 39: I1ii11iIi11i * I1IiiI * II111iiii . Oo0Ooo % I1IiiI
    if 100 - 100: iIii1I11I1II1 - OoooooooOO * OoooooooOO - iII111i / ooOoO0o
    if 98 - 98: OoO0O00 + oO0o - II111iiii
    if 84 - 84: Oo0Ooo . OoOoOO00 - iII111i
    if ( II1iIiIiIIi . rloc_next_hop != None ) :
     if ( II1iIiIiIIi . rloc_next_hop not in iiooooo ) :
      if ( II1iIiIiIIi . up_state ( ) ) :
       O0o0oo0oOO0oO , iIIiiIi1 = II1iIiIiIIi . rloc_next_hop
       II1iIiIiIIi . state = LISP_RLOC_UNREACH_STATE
       II1iIiIiIIi . last_state_change = lisp_get_timestamp ( )
       lisp_update_rtr_updown ( II1iIiIiIIi . rloc , False )
       if 5 - 5: OoooooooOO . O0 / OOooOOo + I11i - Ii1I
      o0oOoO00O0OoO = bold ( "unreachable" , False )
      lprint ( "Next-hop {}({}) for RLOC {} is {}" . format ( iIIiiIi1 , O0o0oo0oOO0oO ,
 red ( I11i11I , False ) , o0oOoO00O0OoO ) )
      continue
      if 77 - 77: iIii1I11I1II1 * Oo0Ooo . IiII / oO0o + O0
      if 76 - 76: iII111i + o0oOOo0O0Ooo - OoooooooOO * oO0o % OoooooooOO - O0
      if 18 - 18: Ii1I
      if 82 - 82: OoOoOO00 + OoO0O00 - IiII / ooOoO0o
      if 70 - 70: OoO0O00
      if 43 - 43: ooOoO0o + OOooOOo + II111iiii - I1IiiI
    O00oo0o0o0oo = II1iIiIiIIi . last_rloc_probe
    o0oOO0O00O = 0 if O00oo0o0o0oo == None else time . time ( ) - O00oo0o0o0oo
    if ( II1iIiIiIIi . unreach_state ( ) and o0oOO0O00O < LISP_RLOC_PROBE_INTERVAL ) :
     lprint ( "Waiting for probe-reply from RLOC {}" . format ( red ( I11i11I , False ) ) )
     if 56 - 56: ooOoO0o - O0 + iII111i % I11i / i1IIi
     continue
     if 78 - 78: i1IIi . iIii1I11I1II1
     if 70 - 70: O0 + II111iiii % IiII / I1Ii111 - IiII
     if 58 - 58: II111iiii * oO0o - i1IIi . I11i
     if 23 - 23: OoO0O00 - I1IiiI * i11iIiiIii
     if 62 - 62: OoO0O00 . i11iIiiIii / i1IIi
     if 3 - 3: OoO0O00 + O0 % Oo0Ooo * Oo0Ooo % i11iIiiIii
    Ii1i = lisp_get_echo_nonce ( None , I11i11I )
    if ( Ii1i and Ii1i . request_nonce_timeout ( ) ) :
     II1iIiIiIIi . state = LISP_RLOC_NO_ECHOED_NONCE_STATE
     II1iIiIiIIi . last_state_change = lisp_get_timestamp ( )
     o0oOoO00O0OoO = bold ( "unreachable" , False )
     lprint ( "RLOC {} went {}, nonce-echo failed" . format ( red ( I11i11I , False ) , o0oOoO00O0OoO ) )
     if 29 - 29: ooOoO0o / iII111i / OOooOOo - iIii1I11I1II1
     lisp_update_rtr_updown ( II1iIiIiIIi . rloc , False )
     continue
     if 31 - 31: i1IIi * Ii1I
     if 94 - 94: oO0o / Ii1I % iIii1I11I1II1 + i1IIi / O0 - iII111i
     if 77 - 77: o0oOOo0O0Ooo - IiII . i1IIi
     if 70 - 70: i1IIi . I1Ii111 . iII111i - OoOoOO00 + II111iiii + OOooOOo
     if 52 - 52: OOooOOo . OoOoOO00 - ooOoO0o % i1IIi
     if 15 - 15: oO0o
    if ( Ii1i and Ii1i . recently_echoed ( ) ) :
     lprint ( ( "Suppress RLOC-probe to {}, nonce-echo " + "received" ) . format ( red ( I11i11I , False ) ) )
     if 6 - 6: oO0o . iIii1I11I1II1 - I1ii11iIi11i % IiII
     continue
     if 58 - 58: iII111i * oO0o / iII111i - Oo0Ooo / I1Ii111 * oO0o
     if 63 - 63: oO0o . IiII . o0oOOo0O0Ooo
     if 16 - 16: iII111i . I11i - Oo0Ooo / I1IiiI + OoOoOO00
     if 14 - 14: iIii1I11I1II1 / i11iIiiIii - o0oOOo0O0Ooo . iII111i * OoO0O00
     if 5 - 5: Ii1I + OoOoOO00 % I11i + IiII
     if 55 - 55: OoooooooOO + oO0o . o0oOOo0O0Ooo % iIii1I11I1II1 - I1Ii111
    if ( II1iIiIiIIi . last_rloc_probe != None ) :
     O00oo0o0o0oo = II1iIiIiIIi . last_rloc_probe_reply
     if ( O00oo0o0o0oo == None ) : O00oo0o0o0oo = 0
     o0oOO0O00O = time . time ( ) - O00oo0o0o0oo
     if ( II1iIiIiIIi . up_state ( ) and o0oOO0O00O >= LISP_RLOC_PROBE_REPLY_WAIT ) :
      if 40 - 40: I1IiiI . o0oOOo0O0Ooo - Oo0Ooo
      II1iIiIiIIi . state = LISP_RLOC_UNREACH_STATE
      II1iIiIiIIi . last_state_change = lisp_get_timestamp ( )
      lisp_update_rtr_updown ( II1iIiIiIIi . rloc , False )
      o0oOoO00O0OoO = bold ( "unreachable" , False )
      lprint ( "RLOC {} went {}, probe it" . format ( red ( I11i11I , False ) , o0oOoO00O0OoO ) )
      if 44 - 44: Ii1I % OoO0O00 * oO0o * OoO0O00
      if 7 - 7: I1Ii111 % i1IIi . I11i . O0 / i1IIi
      lisp_mark_rlocs_for_other_eids ( oo0oO0Oo )
      if 56 - 56: Oo0Ooo
      if 21 - 21: i11iIiiIii * o0oOOo0O0Ooo + Oo0Ooo
      if 20 - 20: IiII / OoooooooOO / O0 / I1Ii111 * ooOoO0o
    II1iIiIiIIi . last_rloc_probe = lisp_get_timestamp ( )
    if 45 - 45: ooOoO0o / Oo0Ooo % o0oOOo0O0Ooo . ooOoO0o
    iIi1I11IIi = "" if II1iIiIiIIi . unreach_state ( ) == False else " unreachable"
    if 73 - 73: Ii1I - II111iiii + I1IiiI % i11iIiiIii * I11i
    if 69 - 69: I1Ii111 . Ii1I * I1ii11iIi11i % I11i - o0oOOo0O0Ooo
    if 30 - 30: ooOoO0o / Oo0Ooo * iII111i % OoooooooOO / I1ii11iIi11i
    if 64 - 64: OoooooooOO
    if 41 - 41: Ii1I . I11i / oO0o * OoooooooOO
    if 98 - 98: I1ii11iIi11i - O0 + i11iIiiIii
    if 71 - 71: O0 - OoooooooOO
    oo0o00Oo00o0 = ""
    iIIiiIi1 = None
    if ( II1iIiIiIIi . rloc_next_hop != None ) :
     O0o0oo0oOO0oO , iIIiiIi1 = II1iIiIiIIi . rloc_next_hop
     lisp_install_host_route ( I11i11I , iIIiiIi1 , True )
     oo0o00Oo00o0 = ", send on nh {}({})" . format ( iIIiiIi1 , O0o0oo0oOO0oO )
     if 62 - 62: IiII - I1Ii111 % iII111i / oO0o
     if 27 - 27: o0oOOo0O0Ooo + iIii1I11I1II1 + OoooooooOO - iII111i
     if 80 - 80: Ii1I . iII111i * I1IiiI * Ii1I
     if 82 - 82: OoO0O00 % OoOoOO00 * i11iIiiIii . OoO0O00 . I1ii11iIi11i + Ii1I
     if 60 - 60: i1IIi / iII111i
    oooo0000 = II1iIiIiIIi . print_rloc_probe_rtt ( )
    I11I = I11i11I
    if ( II1iIiIiIIi . translated_port != 0 ) :
     I11I += ":{}" . format ( II1iIiIiIIi . translated_port )
     if 72 - 72: o0oOOo0O0Ooo . OoOoOO00 / i11iIiiIii - iIii1I11I1II1 . iII111i
    I11I = red ( I11I , False )
    if ( II1iIiIiIIi . rloc_name != None ) :
     I11I += " (" + blue ( II1iIiIiIIi . rloc_name , False ) + ")"
     if 29 - 29: ooOoO0o . I1IiiI + o0oOOo0O0Ooo - I1IiiI
    lprint ( "Send {}{} {}, last rtt: {}{}" . format ( iI1IiIIii1I , iIi1I11IIi ,
 I11I , oooo0000 , oo0o00Oo00o0 ) )
    if 47 - 47: i11iIiiIii * iII111i . OoOoOO00 * I1Ii111 % i11iIiiIii + Ii1I
    if 65 - 65: Ii1I % i11iIiiIii
    if 98 - 98: iII111i * o0oOOo0O0Ooo % Oo0Ooo
    if 7 - 7: oO0o * OoooooooOO % o0oOOo0O0Ooo . I1Ii111 + O0
    if 14 - 14: I11i * II111iiii % o0oOOo0O0Ooo / iII111i . OoooooooOO % iII111i
    if 88 - 88: iII111i
    if 94 - 94: OoooooooOO
    if 32 - 32: I1ii11iIi11i
    if ( II1iIiIiIIi . rloc_next_hop != None ) :
     O0Oo0OO = lisp_get_host_route_next_hop ( I11i11I )
     if ( O0Oo0OO ) : lisp_install_host_route ( I11i11I , O0Oo0OO , False )
     if 8 - 8: I11i * i11iIiiIii - ooOoO0o
     if 47 - 47: ooOoO0o . I1IiiI / i11iIiiIii * iII111i * I1IiiI
     if 8 - 8: oO0o % oO0o . iII111i / i1IIi % IiII
     if 71 - 71: OoOoOO00 + oO0o % O0 + Oo0Ooo
     if 62 - 62: i1IIi . Ii1I * i1IIi * O0 . I1IiiI % o0oOOo0O0Ooo
     if 16 - 16: I11i . Ii1I - ooOoO0o . OOooOOo % O0 / oO0o
    if ( II1iIiIiIIi . rloc . is_null ( ) ) :
     II1iIiIiIIi . rloc . copy_address ( IIii1IIiIi . rloc )
     if 42 - 42: II111iiii . iII111i
     if 67 - 67: i1IIi - i11iIiiIii / ooOoO0o * oO0o
     if 64 - 64: oO0o / IiII
     if 86 - 86: I11i
     if 36 - 36: o0oOOo0O0Ooo / OoO0O00
    i1iI = None if ( oO0000O0o . is_null ( ) ) else III1II1I1iI
    I1II11iii1I = III1II1I1iI if ( oO0000O0o . is_null ( ) ) else oO0000O0o
    lisp_send_map_request ( lisp_sockets , 0 , i1iI , I1II11iii1I , II1iIiIiIIi )
    iiIo0Oo0o00OoO00O0O = IIii1IIiIi
    if 20 - 20: Ii1I % O0 . o0oOOo0O0Ooo + i11iIiiIii % iII111i / o0oOOo0O0Ooo
    if 34 - 34: iIii1I11I1II1
    if 26 - 26: iII111i / IiII * iII111i
    if 91 - 91: Oo0Ooo
    if ( iIIiiIi1 ) : lisp_install_host_route ( I11i11I , iIIiiIi1 , False )
    if 98 - 98: iIii1I11I1II1 . OoO0O00
    if 1 - 1: OOooOOo % Oo0Ooo
    if 86 - 86: i11iIiiIii
    if 57 - 57: iII111i - OoooooooOO - ooOoO0o % II111iiii
    if 62 - 62: i11iIiiIii . Oo0Ooo / Oo0Ooo . IiII . OoooooooOO
   if ( O0Oo0OO ) : lisp_install_host_route ( I11i11I , O0Oo0OO , True )
   if 86 - 86: I1ii11iIi11i * OoOoOO00 + iII111i
   if 79 - 79: I11i - II111iiii
   if 27 - 27: I1IiiI + o0oOOo0O0Ooo * oO0o % I1IiiI
   if 66 - 66: OoO0O00 + IiII . o0oOOo0O0Ooo . IiII
   i111I11I += 1
   if ( ( i111I11I % 10 ) == 0 ) : time . sleep ( 0.020 )
   if 88 - 88: oO0o + oO0o % OoO0O00 . OoooooooOO - OoooooooOO . Oo0Ooo
   if 44 - 44: I1IiiI * IiII . OoooooooOO
   if 62 - 62: I11i - Ii1I / i11iIiiIii * I1IiiI + ooOoO0o + o0oOOo0O0Ooo
 lprint ( "---------- End RLOC Probing ----------" )
 return
 if 10 - 10: i1IIi + o0oOOo0O0Ooo
 if 47 - 47: OOooOOo * IiII % I1Ii111 . OoOoOO00 - OoooooooOO / OoooooooOO
 if 79 - 79: I11i % i11iIiiIii % I1IiiI . OoooooooOO * oO0o . Ii1I
 if 14 - 14: iIii1I11I1II1 / I11i - o0oOOo0O0Ooo / IiII / o0oOOo0O0Ooo . OoO0O00
 if 2 - 2: I11i
 if 12 - 12: i1IIi . I1Ii111
 if 99 - 99: Oo0Ooo / i11iIiiIii
 if 81 - 81: Ii1I . i1IIi % iII111i . OoO0O00 % IiII
def lisp_update_rtr_updown ( rtr , updown ) :
 global lisp_ipc_socket
 if 42 - 42: iII111i / Oo0Ooo
 if 14 - 14: O0 . Oo0Ooo
 if 8 - 8: i11iIiiIii
 if 80 - 80: I1ii11iIi11i + Ii1I
 if ( lisp_i_am_itr == False ) : return
 if 16 - 16: i11iIiiIii * Oo0Ooo
 if 76 - 76: iII111i . oO0o - i1IIi
 if 94 - 94: O0 % iII111i
 if 90 - 90: IiII
 if 1 - 1: I1ii11iIi11i % OoOoOO00 . I1ii11iIi11i . OoooooooOO % oO0o + Ii1I
 if ( lisp_register_all_rtrs ) : return
 if 46 - 46: I1IiiI + OoO0O00 - Oo0Ooo
 i111ii1 = rtr . print_address_no_iid ( )
 if 36 - 36: iII111i * IiII
 if 90 - 90: oO0o * I1Ii111 / O0
 if 15 - 15: o0oOOo0O0Ooo * O0 . OOooOOo / Oo0Ooo
 if 28 - 28: OoooooooOO + OoooooooOO
 if 27 - 27: I11i . oO0o / OoooooooOO - OoO0O00 . I11i
 if ( lisp_rtr_list . has_key ( i111ii1 ) == False ) : return
 if 15 - 15: II111iiii * OoO0O00
 updown = "up" if updown else "down"
 lprint ( "Send ETR IPC message, RTR {} has done {}" . format (
 red ( i111ii1 , False ) , bold ( updown , False ) ) )
 if 33 - 33: OoooooooOO . o0oOOo0O0Ooo . I1IiiI / I1ii11iIi11i . OoOoOO00
 if 58 - 58: Ii1I
 if 20 - 20: OOooOOo
 if 93 - 93: i1IIi . IiII % O0 * iII111i
 OooOoO0OO00 = "rtr%{}%{}" . format ( i111ii1 , updown )
 OooOoO0OO00 = lisp_command_ipc ( OooOoO0OO00 , "lisp-itr" )
 lisp_ipc ( OooOoO0OO00 , lisp_ipc_socket , "lisp-etr" )
 return
 if 84 - 84: I11i
 if 99 - 99: I1ii11iIi11i
 if 78 - 78: I1Ii111 . IiII - OOooOOo
 if 93 - 93: iIii1I11I1II1
 if 33 - 33: OOooOOo . i1IIi
 if 63 - 63: II111iiii . oO0o * IiII
 if 73 - 73: iII111i . i1IIi + oO0o + OOooOOo + ooOoO0o - iIii1I11I1II1
def lisp_process_rloc_probe_reply ( rloc_addr , source , port , nonce , hop_count ,
 ttl ) :
 iI1IiIIii1I = bold ( "RLOC-probe reply" , False )
 i1iIIi1i1I = rloc_addr . print_address_no_iid ( )
 II1111I1iI1iI = source . print_address_no_iid ( )
 ii1oo0OO = lisp_rloc_probe_list
 if 81 - 81: i11iIiiIii / iIii1I11I1II1
 if 73 - 73: i11iIiiIii . I1ii11iIi11i * OoOoOO00
 if 95 - 95: i1IIi + iIii1I11I1II1 . I1Ii111 / I1Ii111
 if 84 - 84: Oo0Ooo . OoO0O00 * IiII
 if 95 - 95: OoO0O00
 if 100 - 100: II111iiii
 I1Iii1I = i1iIIi1i1I
 if ( ii1oo0OO . has_key ( I1Iii1I ) == False ) :
  I1Iii1I += ":" + str ( port )
  if ( ii1oo0OO . has_key ( I1Iii1I ) == False ) :
   I1Iii1I = II1111I1iI1iI
   if ( ii1oo0OO . has_key ( I1Iii1I ) == False ) :
    I1Iii1I += ":" + str ( port )
    lprint ( "    Received unsolicited {} from {}/{}" . format ( iI1IiIIii1I ,
 red ( i1iIIi1i1I , False ) , red ( II1111I1iI1iI , False ) ) )
    return
    if 34 - 34: I11i % OOooOOo - iII111i % II111iiii
    if 14 - 14: I11i * o0oOOo0O0Ooo % II111iiii
    if 36 - 36: ooOoO0o - iIii1I11I1II1 / IiII + OoOoOO00
    if 42 - 42: ooOoO0o + I1IiiI * iII111i / OoOoOO00 . i1IIi - OoooooooOO
    if 8 - 8: iIii1I11I1II1 - Oo0Ooo + iII111i
    if 40 - 40: o0oOOo0O0Ooo * I1IiiI
    if 75 - 75: O0 * OOooOOo / ooOoO0o + I11i
    if 56 - 56: I1IiiI % OoooooooOO % Oo0Ooo
 for II1iIiIiIIi , III1II1I1iI , oO0000O0o in lisp_rloc_probe_list [ I1Iii1I ] :
  if ( lisp_i_am_rtr and II1iIiIiIIi . translated_port != 0 and
 II1iIiIiIIi . translated_port != port ) : continue
  if 19 - 19: i11iIiiIii - iIii1I11I1II1 . i1IIi . I1Ii111 / I1IiiI * I1Ii111
  II1iIiIiIIi . process_rloc_probe_reply ( nonce , III1II1I1iI , oO0000O0o , hop_count , ttl )
  if 41 - 41: oO0o . o0oOOo0O0Ooo . I11i * OoOoOO00
 return
 if 16 - 16: oO0o
 if 32 - 32: OoooooooOO
 if 77 - 77: Oo0Ooo . i1IIi - I11i
 if 98 - 98: O0
 if 87 - 87: OoO0O00 % I1Ii111 - OOooOOo - II111iiii + iII111i
 if 54 - 54: i1IIi % iII111i
 if 16 - 16: II111iiii - Oo0Ooo
 if 44 - 44: OOooOOo / Oo0Ooo - I1ii11iIi11i + I11i . oO0o
def lisp_db_list_length ( ) :
 i111I11I = 0
 for o0O00o in lisp_db_list :
  i111I11I += len ( o0O00o . dynamic_eids ) if o0O00o . dynamic_eid_configured ( ) else 1
  i111I11I += len ( o0O00o . eid . iid_list )
  if 85 - 85: iIii1I11I1II1 / Ii1I
 return ( i111I11I )
 if 43 - 43: I1IiiI % I1Ii111 - oO0o . II111iiii / iIii1I11I1II1
 if 97 - 97: I1Ii111 + I1ii11iIi11i
 if 21 - 21: O0 + o0oOOo0O0Ooo * OoooooooOO % IiII % I1ii11iIi11i
 if 80 - 80: I11i
 if 28 - 28: OoOoOO00 * OoooooooOO * i11iIiiIii
 if 88 - 88: ooOoO0o + ooOoO0o / I1Ii111
 if 69 - 69: O0 * o0oOOo0O0Ooo + i1IIi * ooOoO0o . o0oOOo0O0Ooo
def lisp_is_myeid ( eid ) :
 for o0O00o in lisp_db_list :
  if ( o0O00o . eid . is_exact_match ( eid ) ) : return ( True )
  if 46 - 46: Oo0Ooo / Oo0Ooo * IiII
 return ( False )
 if 65 - 65: iIii1I11I1II1 * o0oOOo0O0Ooo - iII111i % II111iiii - I1ii11iIi11i
 if 65 - 65: I11i
 if 92 - 92: iII111i . IiII + i1IIi % i1IIi
 if 11 - 11: I1ii11iIi11i + iIii1I11I1II1 - I1Ii111 * iIii1I11I1II1 * IiII + oO0o
 if 6 - 6: I1Ii111 * OOooOOo + i1IIi - Ii1I / oO0o
 if 81 - 81: I1Ii111 % oO0o * i1IIi * OoooooooOO / Oo0Ooo
 if 70 - 70: I1IiiI
 if 35 - 35: i11iIiiIii
 if 59 - 59: ooOoO0o . iII111i - II111iiii
def lisp_format_macs ( sa , da ) :
 sa = sa [ 0 : 4 ] + "-" + sa [ 4 : 8 ] + "-" + sa [ 8 : 12 ]
 da = da [ 0 : 4 ] + "-" + da [ 4 : 8 ] + "-" + da [ 8 : 12 ]
 return ( "{} -> {}" . format ( sa , da ) )
 if 30 - 30: o0oOOo0O0Ooo % iII111i - i11iIiiIii
 if 25 - 25: i11iIiiIii + OoOoOO00 + oO0o / Ii1I * Oo0Ooo + Oo0Ooo
 if 26 - 26: I1IiiI % I1ii11iIi11i + o0oOOo0O0Ooo / I1ii11iIi11i - I1IiiI
 if 55 - 55: OoooooooOO
 if 2 - 2: Oo0Ooo + I11i / OOooOOo + OOooOOo
 if 62 - 62: OOooOOo . iIii1I11I1II1 + I1IiiI / OOooOOo
 if 90 - 90: OOooOOo
def lisp_get_echo_nonce ( rloc , rloc_str ) :
 if ( lisp_nonce_echoing == False ) : return ( None )
 if 29 - 29: OoOoOO00 - I1IiiI / oO0o + Oo0Ooo + I1Ii111 + O0
 if ( rloc ) : rloc_str = rloc . print_address_no_iid ( )
 Ii1i = None
 if ( lisp_nonce_echo_list . has_key ( rloc_str ) ) :
  Ii1i = lisp_nonce_echo_list [ rloc_str ]
  if 65 - 65: oO0o
 return ( Ii1i )
 if 38 - 38: iIii1I11I1II1 / I1Ii111 + ooOoO0o . II111iiii - iIii1I11I1II1
 if 13 - 13: Ii1I
 if 34 - 34: I1IiiI / iIii1I11I1II1
 if 35 - 35: oO0o / oO0o
 if 86 - 86: o0oOOo0O0Ooo . Oo0Ooo - Ii1I / i11iIiiIii
 if 63 - 63: oO0o - O0 + I1ii11iIi11i + Ii1I / i1IIi
 if 77 - 77: O0
 if 49 - 49: o0oOOo0O0Ooo / i11iIiiIii
def lisp_decode_dist_name ( packet ) :
 i111I11I = 0
 i1III = ""
 if 97 - 97: i1IIi
 while ( packet [ 0 : 1 ] != "\0" ) :
  if ( i111I11I == 255 ) : return ( [ None , None ] )
  i1III += packet [ 0 : 1 ]
  packet = packet [ 1 : : ]
  i111I11I += 1
  if 7 - 7: i11iIiiIii
  if 49 - 49: I1IiiI - oO0o % OOooOOo / O0 / II111iiii
 packet = packet [ 1 : : ]
 return ( packet , i1III )
 if 41 - 41: IiII % II111iiii
 if 99 - 99: IiII - O0
 if 59 - 59: iII111i % O0 + OOooOOo * ooOoO0o
 if 27 - 27: I1Ii111 % i11iIiiIii * I1IiiI
 if 19 - 19: OoOoOO00 / o0oOOo0O0Ooo - iII111i / OoO0O00
 if 12 - 12: I1ii11iIi11i - I11i * O0 % I1IiiI + O0 - II111iiii
 if 13 - 13: iII111i / OOooOOo * i11iIiiIii / oO0o / OoooooooOO
 if 89 - 89: Ii1I * Oo0Ooo / I1Ii111 * I1ii11iIi11i + O0 * Oo0Ooo
def lisp_write_flow_log ( flow_log ) :
 iI1i1i1i1i = open ( "./logs/lisp-flow.log" , "a" )
 if 74 - 74: I11i . I11i
 i111I11I = 0
 for Oo00o0OOo0OO in flow_log :
  I111 = Oo00o0OOo0OO [ 3 ]
  oO000OO0oOO0 = I111 . print_flow ( Oo00o0OOo0OO [ 0 ] , Oo00o0OOo0OO [ 1 ] , Oo00o0OOo0OO [ 2 ] )
  iI1i1i1i1i . write ( oO000OO0oOO0 )
  i111I11I += 1
  if 62 - 62: IiII - i1IIi + I11i / OOooOOo - iII111i
 iI1i1i1i1i . close ( )
 del ( flow_log )
 if 19 - 19: i1IIi
 i111I11I = bold ( str ( i111I11I ) , False )
 lprint ( "Wrote {} flow entries to ./logs/lisp-flow.log" . format ( i111I11I ) )
 return
 if 32 - 32: I1IiiI
 if 97 - 97: iII111i
 if 26 - 26: i1IIi - I1Ii111 - ooOoO0o
 if 73 - 73: o0oOOo0O0Ooo . OoooooooOO
 if 96 - 96: i1IIi - OOooOOo / I11i % OoOoOO00 - i11iIiiIii % II111iiii
 if 47 - 47: I1Ii111 * iII111i
 if 90 - 90: i1IIi * Ii1I . OoO0O00 % I11i * ooOoO0o . OOooOOo
def lisp_policy_command ( kv_pair ) :
 OoOOOOo = lisp_policy ( "" )
 Oo0I1Iii = None
 if 52 - 52: I1Ii111
 o0ooO0 = [ ]
 for oO in range ( len ( kv_pair [ "datetime-range" ] ) ) :
  o0ooO0 . append ( lisp_policy_match ( ) )
  if 7 - 7: I11i % O0 * i11iIiiIii % I1Ii111 - I1Ii111 % Oo0Ooo
  if 83 - 83: i1IIi
 for iI1iii1I1i11 in kv_pair . keys ( ) :
  oOOO = kv_pair [ iI1iii1I1i11 ]
  if 25 - 25: ooOoO0o + OoO0O00 % iII111i % I1ii11iIi11i . I1ii11iIi11i % OoO0O00
  if 90 - 90: OOooOOo
  if 91 - 91: OoooooooOO % I11i - OOooOOo
  if 88 - 88: Ii1I / i11iIiiIii
  if ( iI1iii1I1i11 == "instance-id" ) :
   for oO in range ( len ( o0ooO0 ) ) :
    o0Oo000O00OOo = oOOO [ oO ]
    if ( o0Oo000O00OOo == "" ) : continue
    IiiI1iI1Iiii = o0ooO0 [ oO ]
    if ( IiiI1iI1Iiii . source_eid == None ) :
     IiiI1iI1Iiii . source_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
     if 4 - 4: i11iIiiIii + OoooooooOO * i1IIi * iIii1I11I1II1 - OOooOOo
    if ( IiiI1iI1Iiii . dest_eid == None ) :
     IiiI1iI1Iiii . dest_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
     if 23 - 23: ooOoO0o + Oo0Ooo
    IiiI1iI1Iiii . source_eid . instance_id = int ( o0Oo000O00OOo )
    IiiI1iI1Iiii . dest_eid . instance_id = int ( o0Oo000O00OOo )
    if 43 - 43: Ii1I
    if 87 - 87: OoO0O00
  if ( iI1iii1I1i11 == "source-eid" ) :
   for oO in range ( len ( o0ooO0 ) ) :
    o0Oo000O00OOo = oOOO [ oO ]
    if ( o0Oo000O00OOo == "" ) : continue
    IiiI1iI1Iiii = o0ooO0 [ oO ]
    if ( IiiI1iI1Iiii . source_eid == None ) :
     IiiI1iI1Iiii . source_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
     if 32 - 32: I11i
    IIiI1i = IiiI1iI1Iiii . source_eid . instance_id
    IiiI1iI1Iiii . source_eid . store_prefix ( o0Oo000O00OOo )
    IiiI1iI1Iiii . source_eid . instance_id = IIiI1i
    if 78 - 78: ooOoO0o * iII111i
    if 31 - 31: I1IiiI + OOooOOo . OoooooooOO
  if ( iI1iii1I1i11 == "destination-eid" ) :
   for oO in range ( len ( o0ooO0 ) ) :
    o0Oo000O00OOo = oOOO [ oO ]
    if ( o0Oo000O00OOo == "" ) : continue
    IiiI1iI1Iiii = o0ooO0 [ oO ]
    if ( IiiI1iI1Iiii . dest_eid == None ) :
     IiiI1iI1Iiii . dest_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
     if 24 - 24: ooOoO0o
    IIiI1i = IiiI1iI1Iiii . dest_eid . instance_id
    IiiI1iI1Iiii . dest_eid . store_prefix ( o0Oo000O00OOo )
    IiiI1iI1Iiii . dest_eid . instance_id = IIiI1i
    if 53 - 53: I1ii11iIi11i % OOooOOo
    if 92 - 92: I1IiiI / ooOoO0o
  if ( iI1iii1I1i11 == "source-rloc" ) :
   for oO in range ( len ( o0ooO0 ) ) :
    o0Oo000O00OOo = oOOO [ oO ]
    if ( o0Oo000O00OOo == "" ) : continue
    IiiI1iI1Iiii = o0ooO0 [ oO ]
    IiiI1iI1Iiii . source_rloc = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
    IiiI1iI1Iiii . source_rloc . store_prefix ( o0Oo000O00OOo )
    if 5 - 5: OoooooooOO - oO0o
    if 52 - 52: I11i . OOooOOo * ooOoO0o / i11iIiiIii . OoO0O00 * ooOoO0o
  if ( iI1iii1I1i11 == "destination-rloc" ) :
   for oO in range ( len ( o0ooO0 ) ) :
    o0Oo000O00OOo = oOOO [ oO ]
    if ( o0Oo000O00OOo == "" ) : continue
    IiiI1iI1Iiii = o0ooO0 [ oO ]
    IiiI1iI1Iiii . dest_rloc = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
    IiiI1iI1Iiii . dest_rloc . store_prefix ( o0Oo000O00OOo )
    if 58 - 58: i1IIi - OoO0O00 * II111iiii
    if 92 - 92: ooOoO0o / I1Ii111 . iII111i
  if ( iI1iii1I1i11 == "rloc-record-name" ) :
   for oO in range ( len ( o0ooO0 ) ) :
    o0Oo000O00OOo = oOOO [ oO ]
    if ( o0Oo000O00OOo == "" ) : continue
    IiiI1iI1Iiii = o0ooO0 [ oO ]
    IiiI1iI1Iiii . rloc_record_name = o0Oo000O00OOo
    if 59 - 59: Ii1I - OoO0O00 % iII111i + I1ii11iIi11i * iII111i
    if 51 - 51: ooOoO0o - Oo0Ooo / iII111i . I11i - Ii1I / OOooOOo
  if ( iI1iii1I1i11 == "geo-name" ) :
   for oO in range ( len ( o0ooO0 ) ) :
    o0Oo000O00OOo = oOOO [ oO ]
    if ( o0Oo000O00OOo == "" ) : continue
    IiiI1iI1Iiii = o0ooO0 [ oO ]
    IiiI1iI1Iiii . geo_name = o0Oo000O00OOo
    if 4 - 4: II111iiii + OoOoOO00 . ooOoO0o - I11i . I1IiiI
    if 46 - 46: II111iiii
  if ( iI1iii1I1i11 == "elp-name" ) :
   for oO in range ( len ( o0ooO0 ) ) :
    o0Oo000O00OOo = oOOO [ oO ]
    if ( o0Oo000O00OOo == "" ) : continue
    IiiI1iI1Iiii = o0ooO0 [ oO ]
    IiiI1iI1Iiii . elp_name = o0Oo000O00OOo
    if 38 - 38: OOooOOo % II111iiii
    if 82 - 82: i11iIiiIii . OoooooooOO % OoOoOO00 * O0 - I1Ii111
  if ( iI1iii1I1i11 == "rle-name" ) :
   for oO in range ( len ( o0ooO0 ) ) :
    o0Oo000O00OOo = oOOO [ oO ]
    if ( o0Oo000O00OOo == "" ) : continue
    IiiI1iI1Iiii = o0ooO0 [ oO ]
    IiiI1iI1Iiii . rle_name = o0Oo000O00OOo
    if 78 - 78: OoOoOO00 % Ii1I % OOooOOo % Oo0Ooo % I11i . Ii1I
    if 73 - 73: OoooooooOO / i1IIi . iIii1I11I1II1
  if ( iI1iii1I1i11 == "json-name" ) :
   for oO in range ( len ( o0ooO0 ) ) :
    o0Oo000O00OOo = oOOO [ oO ]
    if ( o0Oo000O00OOo == "" ) : continue
    IiiI1iI1Iiii = o0ooO0 [ oO ]
    IiiI1iI1Iiii . json_name = o0Oo000O00OOo
    if 89 - 89: I1Ii111
    if 29 - 29: I11i * ooOoO0o - OoooooooOO
  if ( iI1iii1I1i11 == "datetime-range" ) :
   for oO in range ( len ( o0ooO0 ) ) :
    o0Oo000O00OOo = oOOO [ oO ]
    IiiI1iI1Iiii = o0ooO0 [ oO ]
    if ( o0Oo000O00OOo == "" ) : continue
    o0Oo = lisp_datetime ( o0Oo000O00OOo [ 0 : 19 ] )
    IIioO = lisp_datetime ( o0Oo000O00OOo [ 19 : : ] )
    if ( o0Oo . valid_datetime ( ) and IIioO . valid_datetime ( ) ) :
     IiiI1iI1Iiii . datetime_lower = o0Oo
     IiiI1iI1Iiii . datetime_upper = IIioO
     if 92 - 92: O0 % i1IIi / OOooOOo - oO0o
     if 83 - 83: o0oOOo0O0Ooo . OoO0O00 % iIii1I11I1II1 % OoOoOO00 - i11iIiiIii
     if 71 - 71: I1ii11iIi11i - II111iiii / O0 % i1IIi + oO0o
     if 73 - 73: OoooooooOO
     if 25 - 25: i1IIi . II111iiii . I1Ii111
     if 81 - 81: II111iiii + OoOoOO00 * II111iiii / iIii1I11I1II1 - Oo0Ooo % oO0o
     if 66 - 66: ooOoO0o % O0 + iIii1I11I1II1 * I1Ii111 - I1Ii111
  if ( iI1iii1I1i11 == "set-action" ) :
   OoOOOOo . set_action = oOOO
   if 61 - 61: I1ii11iIi11i
  if ( iI1iii1I1i11 == "set-record-ttl" ) :
   OoOOOOo . set_record_ttl = int ( oOOO )
   if 12 - 12: OoO0O00
  if ( iI1iii1I1i11 == "set-instance-id" ) :
   if ( OoOOOOo . set_source_eid == None ) :
    OoOOOOo . set_source_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
    if 97 - 97: OOooOOo . Oo0Ooo . oO0o * i1IIi
   if ( OoOOOOo . set_dest_eid == None ) :
    OoOOOOo . set_dest_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
    if 7 - 7: Oo0Ooo
   Oo0I1Iii = int ( oOOO )
   OoOOOOo . set_source_eid . instance_id = Oo0I1Iii
   OoOOOOo . set_dest_eid . instance_id = Oo0I1Iii
   if 38 - 38: Oo0Ooo - I1ii11iIi11i
  if ( iI1iii1I1i11 == "set-source-eid" ) :
   if ( OoOOOOo . set_source_eid == None ) :
    OoOOOOo . set_source_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
    if 19 - 19: Ii1I * OoO0O00 / OoO0O00 . II111iiii % iIii1I11I1II1
   OoOOOOo . set_source_eid . store_prefix ( oOOO )
   if ( Oo0I1Iii != None ) : OoOOOOo . set_source_eid . instance_id = Oo0I1Iii
   if 61 - 61: I1ii11iIi11i * oO0o % iII111i + IiII + i11iIiiIii * I11i
  if ( iI1iii1I1i11 == "set-destination-eid" ) :
   if ( OoOOOOo . set_dest_eid == None ) :
    OoOOOOo . set_dest_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
    if 3 - 3: Ii1I
   OoOOOOo . set_dest_eid . store_prefix ( oOOO )
   if ( Oo0I1Iii != None ) : OoOOOOo . set_dest_eid . instance_id = Oo0I1Iii
   if 71 - 71: iIii1I11I1II1 . OOooOOo / I11i / i1IIi
  if ( iI1iii1I1i11 == "set-rloc-address" ) :
   OoOOOOo . set_rloc_address = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
   OoOOOOo . set_rloc_address . store_address ( oOOO )
   if 69 - 69: i1IIi / iII111i + Ii1I + I11i + IiII
  if ( iI1iii1I1i11 == "set-rloc-record-name" ) :
   OoOOOOo . set_rloc_record_name = oOOO
   if 86 - 86: Oo0Ooo
  if ( iI1iii1I1i11 == "set-elp-name" ) :
   OoOOOOo . set_elp_name = oOOO
   if 97 - 97: I1IiiI
  if ( iI1iii1I1i11 == "set-geo-name" ) :
   OoOOOOo . set_geo_name = oOOO
   if 91 - 91: ooOoO0o / oO0o * OOooOOo . II111iiii - I11i - I11i
  if ( iI1iii1I1i11 == "set-rle-name" ) :
   OoOOOOo . set_rle_name = oOOO
   if 5 - 5: O0 + OoooooooOO + i11iIiiIii * Oo0Ooo * OoOoOO00 . oO0o
  if ( iI1iii1I1i11 == "set-json-name" ) :
   OoOOOOo . set_json_name = oOOO
   if 6 - 6: OoO0O00 % Oo0Ooo % I1IiiI % o0oOOo0O0Ooo % O0 % Oo0Ooo
  if ( iI1iii1I1i11 == "policy-name" ) :
   OoOOOOo . policy_name = oOOO
   if 94 - 94: I11i . i1IIi / II111iiii + OOooOOo
   if 64 - 64: I1IiiI % ooOoO0o
   if 72 - 72: O0 * II111iiii % OoO0O00 - I1IiiI * OOooOOo
   if 80 - 80: OOooOOo * I11i / OOooOOo - oO0o
   if 18 - 18: i1IIi - OOooOOo - o0oOOo0O0Ooo - iIii1I11I1II1
   if 72 - 72: OoooooooOO % I1IiiI . OoO0O00
 OoOOOOo . match_clauses = o0ooO0
 OoOOOOo . save_policy ( )
 return
 if 28 - 28: II111iiii / iIii1I11I1II1 / iII111i - o0oOOo0O0Ooo . I1IiiI / O0
 if 16 - 16: ooOoO0o * oO0o . OoooooooOO
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
if 44 - 44: iIii1I11I1II1 * OOooOOo + OoO0O00 - OoooooooOO
if 13 - 13: Oo0Ooo . I11i . II111iiii
if 6 - 6: OOooOOo . IiII / OoO0O00 * oO0o - I1Ii111 . OoOoOO00
if 85 - 85: i11iIiiIii + OoOoOO00
if 4 - 4: OOooOOo . OoO0O00 * II111iiii + OoO0O00 % Oo0Ooo
if 60 - 60: OOooOOo . Ii1I
if 13 - 13: i1IIi . iII111i / OoOoOO00 . I1Ii111
def lisp_send_to_arista ( command , interface ) :
 interface = "" if ( interface == None ) else "interface " + interface
 if 65 - 65: oO0o % I1Ii111 % OoO0O00 . iIii1I11I1II1
 I1i1 = command
 if ( interface != "" ) : I1i1 = interface + ": " + I1i1
 lprint ( "Send CLI command '{}' to hardware" . format ( I1i1 ) )
 if 89 - 89: II111iiii * oO0o . OoooooooOO / IiII / IiII + iII111i
 commands = '''
        enable
        configure
        {}
        {}
    ''' . format ( interface , command )
 if 15 - 15: OoOoOO00 . IiII / iIii1I11I1II1 . OoooooooOO
 os . system ( "FastCli -c '{}'" . format ( commands ) )
 return
 if 14 - 14: IiII * OoooooooOO - iIii1I11I1II1
 if 11 - 11: I1IiiI + Oo0Ooo % I1Ii111 * Ii1I - iIii1I11I1II1 % I1ii11iIi11i
 if 43 - 43: o0oOOo0O0Ooo * o0oOOo0O0Ooo . iII111i / Oo0Ooo - i11iIiiIii
 if 66 - 66: I1IiiI / i1IIi + o0oOOo0O0Ooo % IiII - OoOoOO00 / Oo0Ooo
 if 22 - 22: oO0o % I1Ii111 - I1Ii111 / I1Ii111
 if 25 - 25: OoooooooOO / oO0o / ooOoO0o / I1IiiI * I1ii11iIi11i . o0oOOo0O0Ooo
 if 30 - 30: o0oOOo0O0Ooo / i11iIiiIii
def lisp_arista_is_alive ( prefix ) :
 Ii1I1i111 = "enable\nsh plat trident l3 software routes {}\n" . format ( prefix )
 ooO000O = commands . getoutput ( "FastCli -c '{}'" . format ( Ii1I1i111 ) )
 if 33 - 33: OOooOOo % OoooooooOO
 if 98 - 98: Ii1I
 if 38 - 38: ooOoO0o - iII111i * OOooOOo % I1ii11iIi11i + Oo0Ooo
 if 95 - 95: iIii1I11I1II1 / O0 % O0
 ooO000O = ooO000O . split ( "\n" ) [ 1 ]
 o0O0o00ooOOOO0 = ooO000O . split ( " " )
 o0O0o00ooOOOO0 = o0O0o00ooOOOO0 [ - 1 ] . replace ( "\r" , "" )
 if 18 - 18: OoO0O00 * ooOoO0o
 if 32 - 32: oO0o . OoooooooOO - o0oOOo0O0Ooo + II111iiii
 if 4 - 4: OOooOOo * I1IiiI - I11i - I11i
 if 67 - 67: I1IiiI
 return ( o0O0o00ooOOOO0 == "Y" )
 if 32 - 32: oO0o * i11iIiiIii - I11i % Oo0Ooo * I1ii11iIi11i
 if 79 - 79: II111iiii / Oo0Ooo / I1ii11iIi11i
 if 30 - 30: I11i . o0oOOo0O0Ooo / II111iiii
 if 59 - 59: i11iIiiIii
 if 5 - 5: i11iIiiIii + o0oOOo0O0Ooo . OoO0O00 % OoOoOO00 + I11i
 if 59 - 59: I1ii11iIi11i
 if 47 - 47: I1IiiI + Oo0Ooo
 if 78 - 78: i1IIi / I1ii11iIi11i % ooOoO0o * OoO0O00
 if 10 - 10: i1IIi % ooOoO0o / iII111i
 if 98 - 98: IiII / o0oOOo0O0Ooo - i1IIi - OOooOOo
 if 65 - 65: Ii1I + OoOoOO00 * Oo0Ooo . O0 . IiII
 if 33 - 33: i11iIiiIii . i1IIi . I1Ii111 - OoOoOO00 + OOooOOo
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
def lisp_program_vxlan_hardware ( mc ) :
 if 83 - 83: Ii1I % iIii1I11I1II1 / I1ii11iIi11i + I11i
 if 23 - 23: iIii1I11I1II1 - I1IiiI
 if 51 - 51: OoooooooOO / IiII / I1ii11iIi11i . Oo0Ooo - o0oOOo0O0Ooo * OoooooooOO
 if 40 - 40: OoO0O00 / IiII . O0 / I1IiiI + OoO0O00 . o0oOOo0O0Ooo
 if 25 - 25: ooOoO0o * I1Ii111 * oO0o
 if 64 - 64: Ii1I / I1ii11iIi11i
 if ( os . path . exists ( "/persist/local/lispers.net" ) == False ) : return
 if 30 - 30: OoooooooOO + O0 / I1ii11iIi11i * o0oOOo0O0Ooo
 if 11 - 11: O0 + OoO0O00 - Oo0Ooo - Oo0Ooo . i11iIiiIii
 if 15 - 15: Ii1I % i11iIiiIii / OoOoOO00
 if 85 - 85: ooOoO0o . i1IIi / iII111i % iIii1I11I1II1 / II111iiii / I1Ii111
 if ( len ( mc . best_rloc_set ) == 0 ) : return
 if 60 - 60: iIii1I11I1II1 - iIii1I11I1II1 . I11i
 if 55 - 55: OoO0O00
 if 87 - 87: Ii1I - iII111i / O0 - o0oOOo0O0Ooo - iIii1I11I1II1 % Ii1I
 if 47 - 47: iII111i * I1Ii111 % o0oOOo0O0Ooo / OoOoOO00 / OoO0O00 % OoO0O00
 IiII1i11I11i = mc . eid . print_prefix_no_iid ( )
 II1iIiIiIIi = mc . best_rloc_set [ 0 ] . rloc . print_address_no_iid ( )
 if 43 - 43: Oo0Ooo
 if 34 - 34: OoO0O00 . i1IIi + IiII * IiII
 if 76 - 76: OOooOOo
 if 54 - 54: O0 * II111iiii * OOooOOo
 iIiII = commands . getoutput ( "ip route get {} | egrep vlan4094" . format ( IiII1i11I11i ) )
 if 20 - 20: Ii1I % iIii1I11I1II1 + i11iIiiIii * OoOoOO00 + I1ii11iIi11i / iII111i
 if ( iIiII != "" ) :
  lprint ( "Route {} already in hardware: '{}'" . format ( green ( IiII1i11I11i , False ) , iIiII ) )
  if 74 - 74: i1IIi - I1ii11iIi11i % Oo0Ooo . I1ii11iIi11i % O0 . I1ii11iIi11i
  return
  if 37 - 37: O0 . II111iiii
  if 70 - 70: o0oOOo0O0Ooo / iII111i + i1IIi + I11i % iIii1I11I1II1 % Oo0Ooo
  if 1 - 1: O0 + OoO0O00 . i11iIiiIii + I1Ii111 - OoO0O00 - IiII
  if 1 - 1: I1ii11iIi11i / i1IIi . I1IiiI / Ii1I
  if 19 - 19: iIii1I11I1II1 / Oo0Ooo . O0 - Oo0Ooo
  if 74 - 74: I1ii11iIi11i * OoooooooOO . iII111i
  if 45 - 45: I1IiiI - IiII % ooOoO0o - IiII . Oo0Ooo - o0oOOo0O0Ooo
 iI1Iii111iI = commands . getoutput ( "ifconfig | egrep 'vxlan|vlan4094'" )
 if ( iI1Iii111iI . find ( "vxlan" ) == - 1 ) :
  lprint ( "No VXLAN interface found, cannot program hardware" )
  return
  if 80 - 80: IiII / iIii1I11I1II1
 if ( iI1Iii111iI . find ( "vlan4094" ) == - 1 ) :
  lprint ( "No vlan4094 interface found, cannot program hardware" )
  return
  if 17 - 17: I11i * I11i - O0 / IiII + OoOoOO00
 o0ooo0O0o0o00 = commands . getoutput ( "ip addr | egrep vlan4094 | egrep inet" )
 if ( o0ooo0O0o0o00 == "" ) :
  lprint ( "No IP address found on vlan4094, cannot program hardware" )
  return
  if 19 - 19: OoOoOO00
 o0ooo0O0o0o00 = o0ooo0O0o0o00 . split ( "inet " ) [ 1 ]
 o0ooo0O0o0o00 = o0ooo0O0o0o00 . split ( "/" ) [ 0 ]
 if 98 - 98: I1IiiI % iII111i * OOooOOo - I1ii11iIi11i
 if 27 - 27: OOooOOo % oO0o . i1IIi + i1IIi % I1ii11iIi11i
 if 38 - 38: i1IIi . I1IiiI + II111iiii * OoO0O00 / IiII
 if 60 - 60: II111iiii
 if 68 - 68: O0 / I1IiiI / OoOoOO00 / iIii1I11I1II1 % O0 + I1IiiI
 if 23 - 23: OoooooooOO . OoO0O00 . OoooooooOO * I1ii11iIi11i - Oo0Ooo - iIii1I11I1II1
 if 91 - 91: iIii1I11I1II1 * Ii1I
 I11iIIi = [ ]
 O0OOo0000 = commands . getoutput ( "arp -i vlan4094" ) . split ( "\n" )
 for iiIiiIi1 in O0OOo0000 :
  if ( iiIiiIi1 . find ( "vlan4094" ) == - 1 ) : continue
  if ( iiIiiIi1 . find ( "(incomplete)" ) == - 1 ) : continue
  O0Oo0OO = iiIiiIi1 . split ( " " ) [ 0 ]
  I11iIIi . append ( O0Oo0OO )
  if 32 - 32: i1IIi . iII111i - Ii1I % iII111i % II111iiii - oO0o
  if 36 - 36: OoooooooOO * OoooooooOO . ooOoO0o . O0
 O0Oo0OO = None
 OoOIII1I1i11I = o0ooo0O0o0o00
 o0ooo0O0o0o00 = o0ooo0O0o0o00 . split ( "." )
 for oO in range ( 1 , 255 ) :
  o0ooo0O0o0o00 [ 3 ] = str ( oO )
  I1Iii1I = "." . join ( o0ooo0O0o0o00 )
  if ( I1Iii1I in I11iIIi ) : continue
  if ( I1Iii1I == OoOIII1I1i11I ) : continue
  O0Oo0OO = I1Iii1I
  break
  if 5 - 5: I11i % I1IiiI - OoO0O00 . Oo0Ooo
 if ( O0Oo0OO == None ) :
  lprint ( "Address allocation failed for vlan4094, cannot program " + "hardware" )
  if 79 - 79: iII111i + IiII % I11i . Oo0Ooo / IiII * iII111i
  return
  if 40 - 40: iII111i - I1IiiI + OoOoOO00
  if 2 - 2: I11i - II111iiii / I1Ii111
  if 27 - 27: OoO0O00 - I1ii11iIi11i * i11iIiiIii + Oo0Ooo
  if 29 - 29: I1ii11iIi11i / IiII . I1Ii111 + Ii1I + OoO0O00
  if 76 - 76: ooOoO0o . I11i * OoO0O00
  if 53 - 53: II111iiii / OoOoOO00 / IiII * oO0o
  if 52 - 52: O0 % iII111i * iIii1I11I1II1 / I11i / I1IiiI * ooOoO0o
 Oo0Iii1II1iI = II1iIiIiIIi . split ( "." )
 iI1i1iIi = lisp_hex_string ( Oo0Iii1II1iI [ 1 ] ) . zfill ( 2 )
 iIIIiIIi1I11i = lisp_hex_string ( Oo0Iii1II1iI [ 2 ] ) . zfill ( 2 )
 OoooOooOO0o0 = lisp_hex_string ( Oo0Iii1II1iI [ 3 ] ) . zfill ( 2 )
 o0O0oO0 = "00:00:00:{}:{}:{}" . format ( iI1i1iIi , iIIIiIIi1I11i , OoooOooOO0o0 )
 IiIII1Iiiii1I = "0000.00{}.{}{}" . format ( iI1i1iIi , iIIIiIIi1I11i , OoooOooOO0o0 )
 i11iIIi = "arp -i vlan4094 -s {} {}" . format ( O0Oo0OO , o0O0oO0 )
 os . system ( i11iIIi )
 if 83 - 83: OOooOOo . ooOoO0o - oO0o . OoO0O00 . o0oOOo0O0Ooo / Oo0Ooo
 if 78 - 78: OoOoOO00 - II111iiii - o0oOOo0O0Ooo * iII111i . o0oOOo0O0Ooo
 if 9 - 9: iIii1I11I1II1 . iII111i % OoOoOO00 + o0oOOo0O0Ooo
 if 77 - 77: OoO0O00 - OoooooooOO . iIii1I11I1II1 * ooOoO0o
 OO0OooOOO = ( "mac address-table static {} vlan 4094 " + "interface vxlan 1 vtep {}" ) . format ( IiIII1Iiiii1I , II1iIiIiIIi )
 if 33 - 33: OoO0O00 + II111iiii . Oo0Ooo * I1Ii111
 lisp_send_to_arista ( OO0OooOOO , None )
 if 63 - 63: OoooooooOO + OoOoOO00 - OoooooooOO
 if 54 - 54: OoO0O00 + I1IiiI % O0 + OoO0O00
 if 37 - 37: II111iiii / I1ii11iIi11i * I1IiiI - OoooooooOO
 if 55 - 55: IiII / ooOoO0o * I1IiiI / I1Ii111 - Oo0Ooo % o0oOOo0O0Ooo
 if 82 - 82: OoO0O00 - iIii1I11I1II1 . Oo0Ooo / IiII . OoO0O00
 i11i1I = "ip route add {} via {}" . format ( IiII1i11I11i , O0Oo0OO )
 os . system ( i11i1I )
 if 37 - 37: iII111i / OoOoOO00 . Oo0Ooo + i1IIi * ooOoO0o
 lprint ( "Hardware programmed with commands:" )
 i11i1I = i11i1I . replace ( IiII1i11I11i , green ( IiII1i11I11i , False ) )
 lprint ( "  " + i11i1I )
 lprint ( "  " + i11iIIi )
 OO0OooOOO = OO0OooOOO . replace ( II1iIiIiIIi , red ( II1iIiIiIIi , False ) )
 lprint ( "  " + OO0OooOOO )
 return
 if 89 - 89: OoOoOO00 / I1ii11iIi11i - i11iIiiIii % i11iIiiIii
 if 31 - 31: iII111i
 if 64 - 64: Ii1I
 if 4 - 4: OoOoOO00
 if 78 - 78: i1IIi - iII111i + O0 - I1IiiI % o0oOOo0O0Ooo
 if 48 - 48: iII111i / II111iiii * I1Ii111 + I11i / ooOoO0o . OoOoOO00
 if 45 - 45: OOooOOo / Ii1I % O0
def lisp_clear_hardware_walk ( mc , parms ) :
 O0OoOoo000OoO = mc . eid . print_prefix_no_iid ( )
 os . system ( "ip route delete {}" . format ( O0OoOoo000OoO ) )
 return ( [ True , None ] )
 if 7 - 7: oO0o * i11iIiiIii + OoooooooOO + I11i
 if 9 - 9: II111iiii * Oo0Ooo * I1Ii111 . IiII
 if 80 - 80: i11iIiiIii . i11iIiiIii . i11iIiiIii . OoooooooOO - OOooOOo * OoooooooOO
 if 96 - 96: oO0o
 if 80 - 80: IiII - oO0o % Ii1I - iIii1I11I1II1 . OoO0O00
 if 64 - 64: I1IiiI % i11iIiiIii / oO0o
 if 78 - 78: II111iiii - Oo0Ooo . iIii1I11I1II1 - ooOoO0o . oO0o
 if 84 - 84: iII111i . ooOoO0o * I1IiiI * Oo0Ooo / I1Ii111
def lisp_clear_map_cache ( ) :
 global lisp_map_cache , lisp_rloc_probe_list
 global lisp_crypto_keys_by_rloc_encap , lisp_crypto_keys_by_rloc_decap
 global lisp_rtr_list
 if 93 - 93: i1IIi * i11iIiiIii % OoOoOO00 % iII111i
 i1iiiIi = bold ( "User cleared" , False )
 i111I11I = lisp_map_cache . cache_count
 lprint ( "{} map-cache with {} entries" . format ( i1iiiIi , i111I11I ) )
 if 66 - 66: IiII - O0 + oO0o - OoO0O00 % I11i
 if ( lisp_program_hardware ) :
  lisp_map_cache . walk_cache ( lisp_clear_hardware_walk , None )
  if 50 - 50: OoooooooOO - iII111i
 lisp_map_cache = lisp_cache ( )
 if 40 - 40: Ii1I . I1Ii111 % i11iIiiIii / II111iiii . i11iIiiIii * II111iiii
 if 2 - 2: ooOoO0o
 if 65 - 65: O0 - o0oOOo0O0Ooo - OoO0O00
 if 8 - 8: IiII
 if 52 - 52: i11iIiiIii / O0 + oO0o . I11i
 lisp_rloc_probe_list = { }
 if 73 - 73: OoooooooOO / I1IiiI % Oo0Ooo . oO0o + OoooooooOO
 if 84 - 84: I1ii11iIi11i - OOooOOo * II111iiii
 if 28 - 28: I1ii11iIi11i . oO0o / o0oOOo0O0Ooo - iII111i
 if 65 - 65: I1ii11iIi11i * OOooOOo * ooOoO0o + oO0o - OOooOOo
 lisp_crypto_keys_by_rloc_encap = { }
 lisp_crypto_keys_by_rloc_decap = { }
 if 100 - 100: iII111i
 if 12 - 12: OoooooooOO - I1ii11iIi11i * iII111i / ooOoO0o
 if 99 - 99: I1ii11iIi11i + I11i
 if 29 - 29: I1ii11iIi11i / oO0o
 if 2 - 2: Oo0Ooo / IiII - OoooooooOO
 lisp_rtr_list = { }
 if 65 - 65: OoO0O00 - Ii1I
 if 98 - 98: OoOoOO00 * I1Ii111 * iIii1I11I1II1 * OoOoOO00
 if 15 - 15: Oo0Ooo
 if 100 - 100: IiII + I1ii11iIi11i + iII111i . i1IIi . I1ii11iIi11i / OoooooooOO
 lisp_process_data_plane_restart ( True )
 return
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
def lisp_encapsulate_rloc_probe ( lisp_sockets , rloc , nat_info , packet ) :
 if ( len ( lisp_sockets ) != 4 ) : return
 if 25 - 25: oO0o
 I11IIIii = lisp_myrlocs [ 0 ]
 if 93 - 93: OoO0O00
 if 18 - 18: OoOoOO00 - OoOoOO00 . iII111i / Oo0Ooo % Ii1I / iIii1I11I1II1
 if 97 - 97: ooOoO0o * ooOoO0o / IiII / iII111i . i11iIiiIii
 if 29 - 29: Oo0Ooo % i1IIi - I11i * OoooooooOO + iII111i
 if 82 - 82: IiII - I1Ii111 - I1ii11iIi11i
 i1IIiIIIi1 = len ( packet ) + 28
 oOo00Ooo0o0 = struct . pack ( "BBHIBBHII" , 0x45 , 0 , socket . htons ( i1IIiIIIi1 ) , 0 , 64 ,
 17 , 0 , socket . htonl ( I11IIIii . address ) , socket . htonl ( rloc . address ) )
 oOo00Ooo0o0 = lisp_ip_checksum ( oOo00Ooo0o0 )
 if 35 - 35: oO0o % OoOoOO00 + iII111i . I1Ii111 . IiII - OoooooooOO
 O00oo0O00 = struct . pack ( "HHHH" , 0 , socket . htons ( LISP_CTRL_PORT ) ,
 socket . htons ( i1IIiIIIi1 - 20 ) , 0 )
 if 69 - 69: O0 . Ii1I / O0
 if 61 - 61: OoooooooOO / OOooOOo / iII111i % II111iiii
 if 97 - 97: I1Ii111 / iIii1I11I1II1 * OOooOOo + i11iIiiIii
 if 86 - 86: OoO0O00 - I1Ii111 * OoO0O00
 packet = lisp_packet ( oOo00Ooo0o0 + O00oo0O00 + packet )
 if 29 - 29: I1Ii111 % OoOoOO00 . oO0o / oO0o % I11i
 if 91 - 91: o0oOOo0O0Ooo
 if 59 - 59: I11i . I11i
 if 98 - 98: II111iiii
 packet . inner_dest . copy_address ( rloc )
 packet . inner_dest . instance_id = 0xffffff
 packet . inner_source . copy_address ( I11IIIii )
 packet . inner_ttl = 64
 packet . outer_dest . copy_address ( rloc )
 packet . outer_source . copy_address ( I11IIIii )
 packet . outer_version = packet . outer_dest . afi_to_version ( )
 packet . outer_ttl = 64
 packet . encap_port = nat_info . port if nat_info else LISP_DATA_PORT
 if 20 - 20: iIii1I11I1II1
 IIII1i = red ( rloc . print_address_no_iid ( ) , False )
 if ( nat_info ) :
  i1iI1 = " {}" . format ( blue ( nat_info . hostname , False ) )
  iI1IiIIii1I = bold ( "RLOC-probe request" , False )
 else :
  i1iI1 = ""
  iI1IiIIii1I = bold ( "RLOC-probe reply" , False )
  if 17 - 17: OoOoOO00 + ooOoO0o * II111iiii * OoOoOO00 + I1IiiI + i11iIiiIii
  if 46 - 46: i1IIi - II111iiii . I1IiiI . i11iIiiIii
 lprint ( ( "Data encapsulate {} to {}{} port {} for " + "NAT-traversal" ) . format ( iI1IiIIii1I , IIII1i , i1iI1 , packet . encap_port ) )
 if 54 - 54: O0 * I1ii11iIi11i / OOooOOo / IiII * IiII
 if 69 - 69: Oo0Ooo * OoooooooOO / I1IiiI
 if 16 - 16: o0oOOo0O0Ooo
 if 3 - 3: i11iIiiIii . I1ii11iIi11i
 if 65 - 65: II111iiii * iII111i - OoO0O00 + oO0o % OoO0O00
 if ( packet . encode ( None ) == None ) : return
 packet . print_packet ( "Send" , True )
 if 83 - 83: OoooooooOO % I1ii11iIi11i . IiII + OOooOOo . iII111i - ooOoO0o
 o0O000Oo = lisp_sockets [ 3 ]
 packet . send_packet ( o0O000Oo , packet . outer_dest )
 del ( packet )
 return
 if 100 - 100: iII111i . o0oOOo0O0Ooo - I1Ii111 % oO0o
 if 11 - 11: o0oOOo0O0Ooo . OoooooooOO - i1IIi
 if 71 - 71: I1IiiI . OOooOOo . I1ii11iIi11i
 if 90 - 90: i11iIiiIii + I1Ii111 % II111iiii
 if 67 - 67: OoOoOO00 / iII111i * OoO0O00 % i11iIiiIii
 if 76 - 76: OoO0O00
 if 92 - 92: iIii1I11I1II1 * O0 % I11i
 if 92 - 92: OoOoOO00 + oO0o
def lisp_get_default_route_next_hops ( ) :
 if 89 - 89: IiII % iII111i / iIii1I11I1II1 . Ii1I . Oo0Ooo + ooOoO0o
 if 28 - 28: I1IiiI . iIii1I11I1II1
 if 12 - 12: I1Ii111 * OOooOOo
 if 11 - 11: II111iiii % O0 % O0 % o0oOOo0O0Ooo
 if ( lisp_is_macos ( ) ) :
  Ii1I1i111 = "route -n get default"
  iiI1111i1III = commands . getoutput ( Ii1I1i111 ) . split ( "\n" )
  ooOII = iiiii11I1 = None
  for iI1i1i1i1i in iiI1111i1III :
   if ( iI1i1i1i1i . find ( "gateway: " ) != - 1 ) : ooOII = iI1i1i1i1i . split ( ": " ) [ 1 ]
   if ( iI1i1i1i1i . find ( "interface: " ) != - 1 ) : iiiii11I1 = iI1i1i1i1i . split ( ": " ) [ 1 ]
   if 18 - 18: II111iiii / oO0o / o0oOOo0O0Ooo + I11i
  return ( [ [ iiiii11I1 , ooOII ] ] )
  if 4 - 4: OoooooooOO % I1ii11iIi11i . OoO0O00 * o0oOOo0O0Ooo + I1ii11iIi11i * IiII
  if 67 - 67: I1IiiI
  if 93 - 93: ooOoO0o . Ii1I + IiII / Oo0Ooo % I11i
  if 40 - 40: Oo0Ooo % OoOoOO00 . IiII / I1IiiI % OoooooooOO
  if 33 - 33: OOooOOo - OoooooooOO . iII111i
 Ii1I1i111 = "ip route | egrep 'default via'"
 o00oOoOOOOoO = commands . getoutput ( Ii1I1i111 ) . split ( "\n" )
 if 2 - 2: I11i + i1IIi
 o0oOOo000o0 = [ ]
 for iIiII in o00oOoOOOOoO :
  if ( iIiII . find ( " metric " ) != - 1 ) : continue
  oOo0Oooo = iIiII . split ( " " )
  try :
   O00Oo000 = oOo0Oooo . index ( "via" ) + 1
   if ( O00Oo000 >= len ( oOo0Oooo ) ) : continue
   OoI1ii = oOo0Oooo . index ( "dev" ) + 1
   if ( OoI1ii >= len ( oOo0Oooo ) ) : continue
  except :
   continue
   if 51 - 51: ooOoO0o % iII111i % iIii1I11I1II1 + OOooOOo
   if 51 - 51: Ii1I
  o0oOOo000o0 . append ( [ oOo0Oooo [ OoI1ii ] , oOo0Oooo [ O00Oo000 ] ] )
  if 39 - 39: o0oOOo0O0Ooo * iII111i
 return ( o0oOOo000o0 )
 if 95 - 95: II111iiii / iII111i + i1IIi
 if 70 - 70: IiII . I1Ii111
 if 29 - 29: Oo0Ooo . i11iIiiIii + OoOoOO00 - Oo0Ooo
 if 13 - 13: ooOoO0o
 if 56 - 56: I1Ii111 / I1ii11iIi11i . i1IIi + I1ii11iIi11i / OoooooooOO - I1IiiI
 if 3 - 3: ooOoO0o
 if 68 - 68: o0oOOo0O0Ooo
def lisp_get_host_route_next_hop ( rloc ) :
 Ii1I1i111 = "ip route | egrep '{} via'" . format ( rloc )
 iIiII = commands . getoutput ( Ii1I1i111 ) . split ( " " )
 if 36 - 36: Oo0Ooo . I11i + I1IiiI * i1IIi % Ii1I + OOooOOo
 try : OOOoO000 = iIiII . index ( "via" ) + 1
 except : return ( None )
 if 5 - 5: o0oOOo0O0Ooo % oO0o / OoO0O00
 if ( OOOoO000 >= len ( iIiII ) ) : return ( None )
 return ( iIiII [ OOOoO000 ] )
 if 17 - 17: OoooooooOO - I1ii11iIi11i / OoO0O00 - I1Ii111 + i1IIi
 if 6 - 6: Oo0Ooo - II111iiii
 if 33 - 33: I1Ii111 - I1IiiI + iII111i . OoOoOO00
 if 91 - 91: OOooOOo / Ii1I / IiII * OOooOOo
 if 68 - 68: I11i
 if 91 - 91: I11i
 if 24 - 24: ooOoO0o . i1IIi - O0 + I11i
def lisp_install_host_route ( dest , nh , install ) :
 install = "add" if install else "delete"
 oo0o00Oo00o0 = "none" if nh == None else nh
 if 71 - 71: OoOoOO00
 lprint ( "{} host-route {}, nh {}" . format ( install . title ( ) , dest , oo0o00Oo00o0 ) )
 if 29 - 29: O0 . i11iIiiIii
 if ( nh == None ) :
  o00OO0OO0O = "ip route {} {}/32" . format ( install , dest )
 else :
  o00OO0OO0O = "ip route {} {}/32 via {}" . format ( install , dest , nh )
  if 51 - 51: IiII
 os . system ( o00OO0OO0O )
 return
 if 53 - 53: O0
 if 19 - 19: o0oOOo0O0Ooo / iII111i % OoOoOO00
 if 65 - 65: o0oOOo0O0Ooo
 if 89 - 89: iIii1I11I1II1 + OoooooooOO + i1IIi + OoooooooOO % IiII * OoO0O00
 if 53 - 53: OOooOOo . IiII % I11i - OoO0O00 - Oo0Ooo
 if 58 - 58: I1Ii111 / OoooooooOO . I11i % I1Ii111
 if 8 - 8: Oo0Ooo % ooOoO0o / i11iIiiIii
 if 54 - 54: IiII
def lisp_checkpoint ( checkpoint_list ) :
 if ( lisp_checkpoint_map_cache == False ) : return
 if 85 - 85: OOooOOo - i1IIi
 iI1i1i1i1i = open ( lisp_checkpoint_filename , "w" )
 for oo in checkpoint_list :
  iI1i1i1i1i . write ( oo + "\n" )
  if 10 - 10: I1ii11iIi11i
 iI1i1i1i1i . close ( )
 lprint ( "{} {} entries to file '{}'" . format ( bold ( "Checkpoint" , False ) ,
 len ( checkpoint_list ) , lisp_checkpoint_filename ) )
 return
 if 3 - 3: ooOoO0o * O0 / o0oOOo0O0Ooo
 if 22 - 22: OoOoOO00 + OOooOOo . iII111i % iIii1I11I1II1 - I11i
 if 23 - 23: OoOoOO00 * I1Ii111
 if 18 - 18: o0oOOo0O0Ooo % i11iIiiIii . Ii1I . O0
 if 85 - 85: I1ii11iIi11i * iIii1I11I1II1 + o0oOOo0O0Ooo * OoO0O00
 if 25 - 25: o0oOOo0O0Ooo / Ii1I / Oo0Ooo . ooOoO0o - ooOoO0o * O0
 if 14 - 14: O0 - Ii1I + iIii1I11I1II1 + II111iiii . ooOoO0o + Ii1I
 if 25 - 25: OoO0O00 * oO0o
def lisp_load_checkpoint ( ) :
 if ( lisp_checkpoint_map_cache == False ) : return
 if ( os . path . exists ( lisp_checkpoint_filename ) == False ) : return
 if 29 - 29: OOooOOo - I1Ii111 - i11iIiiIii % i1IIi
 iI1i1i1i1i = open ( lisp_checkpoint_filename , "r" )
 if 2 - 2: i11iIiiIii % iIii1I11I1II1 * OOooOOo
 i111I11I = 0
 for oo in iI1i1i1i1i :
  i111I11I += 1
  I1i11II = oo . split ( " rloc " )
  iIiIii1I1 = [ ] if ( I1i11II [ 1 ] in [ "native-forward\n" , "\n" ] ) else I1i11II [ 1 ] . split ( ", " )
  if 45 - 45: oO0o + i1IIi + iII111i + o0oOOo0O0Ooo * OOooOOo + ooOoO0o
  if 83 - 83: OoO0O00 - ooOoO0o / OoooooooOO % iIii1I11I1II1 - II111iiii
  I1111Ii1II1I = [ ]
  for II1iIiIiIIi in iIiIii1I1 :
   o0OO0O0OoOo0 = lisp_rloc ( False )
   oOo0Oooo = II1iIiIiIIi . split ( " " )
   o0OO0O0OoOo0 . rloc . store_address ( oOo0Oooo [ 0 ] )
   o0OO0O0OoOo0 . priority = int ( oOo0Oooo [ 1 ] )
   o0OO0O0OoOo0 . weight = int ( oOo0Oooo [ 2 ] )
   I1111Ii1II1I . append ( o0OO0O0OoOo0 )
   if 73 - 73: Oo0Ooo + II111iiii - IiII
   if 60 - 60: i1IIi . i11iIiiIii / i1IIi . I11i % OOooOOo
  iIi11 = lisp_mapping ( "" , "" , I1111Ii1II1I )
  if ( iIi11 != None ) :
   iIi11 . eid . store_prefix ( I1i11II [ 0 ] )
   iIi11 . checkpoint_entry = True
   iIi11 . map_cache_ttl = LISP_NMR_TTL * 60
   if ( I1111Ii1II1I == [ ] ) : iIi11 . action = LISP_NATIVE_FORWARD_ACTION
   iIi11 . add_cache ( )
   continue
   if 47 - 47: oO0o + IiII * I1Ii111 % o0oOOo0O0Ooo - O0 % IiII
   if 66 - 66: II111iiii * I1IiiI . Oo0Ooo * OoooooooOO % OoOoOO00 . II111iiii
  i111I11I -= 1
  if 4 - 4: iII111i + I1Ii111 % OoOoOO00 / Ii1I
  if 94 - 94: OoO0O00
 iI1i1i1i1i . close ( )
 lprint ( "{} {} map-cache entries from file '{}'" . format (
 bold ( "Loaded" , False ) , i111I11I , lisp_checkpoint_filename ) )
 return
 if 35 - 35: I1ii11iIi11i % OoO0O00 + II111iiii % II111iiii / IiII - iII111i
 if 9 - 9: I1ii11iIi11i * o0oOOo0O0Ooo . oO0o
 if 48 - 48: IiII . I1Ii111 + OoooooooOO - I1Ii111 . Ii1I . I1Ii111
 if 24 - 24: ooOoO0o * iIii1I11I1II1
 if 1 - 1: I1ii11iIi11i . O0
 if 3 - 3: iIii1I11I1II1 * ooOoO0o - OoOoOO00 * I1ii11iIi11i % OoOoOO00 - OoooooooOO
 if 42 - 42: I1Ii111 - i1IIi
 if 91 - 91: iII111i . OOooOOo / iIii1I11I1II1 . Oo0Ooo . II111iiii . OoOoOO00
 if 31 - 31: OoO0O00 . I1ii11iIi11i % I11i - II111iiii
 if 70 - 70: ooOoO0o - IiII - OoO0O00 / I11i
 if 59 - 59: IiII % ooOoO0o . iII111i / Ii1I * Ii1I
 if 73 - 73: I1ii11iIi11i . oO0o % I11i . I1ii11iIi11i / I1Ii111 / II111iiii
 if 23 - 23: OoooooooOO . o0oOOo0O0Ooo
 if 76 - 76: I1Ii111
def lisp_write_checkpoint_entry ( checkpoint_list , mc ) :
 if ( lisp_checkpoint_map_cache == False ) : return
 if 91 - 91: iIii1I11I1II1 / Ii1I . I1IiiI
 oo = "{} rloc " . format ( mc . eid . print_prefix ( ) )
 if 63 - 63: ooOoO0o . Ii1I - I1Ii111 - oO0o * I1Ii111 + ooOoO0o
 for o0OO0O0OoOo0 in mc . rloc_set :
  if ( o0OO0O0OoOo0 . rloc . is_null ( ) ) : continue
  oo += "{} {} {}, " . format ( o0OO0O0OoOo0 . rloc . print_address_no_iid ( ) ,
 o0OO0O0OoOo0 . priority , o0OO0O0OoOo0 . weight )
  if 85 - 85: II111iiii + I1ii11iIi11i
  if 33 - 33: iII111i
 if ( mc . rloc_set != [ ] ) :
  oo = oo [ 0 : - 2 ]
 elif ( mc . action == LISP_NATIVE_FORWARD_ACTION ) :
  oo += "native-forward"
  if 14 - 14: O0 * Oo0Ooo / i1IIi
  if 95 - 95: O0 % i1IIi % ooOoO0o % oO0o - I1IiiI
 checkpoint_list . append ( oo )
 return
 if 78 - 78: II111iiii % OOooOOo
 if 6 - 6: OOooOOo
 if 21 - 21: I1Ii111 - Ii1I - i1IIi % oO0o
 if 55 - 55: OOooOOo + oO0o - II111iiii
 if 5 - 5: iII111i * OoooooooOO . OoO0O00 % ooOoO0o + Ii1I
 if 59 - 59: OoOoOO00
 if 96 - 96: I1IiiI
def lisp_check_dp_socket ( ) :
 ii1i = lisp_ipc_dp_socket_name
 if ( os . path . exists ( ii1i ) == False ) :
  OoIiIi111i1i1I = bold ( "does not exist" , False )
  lprint ( "Socket '{}' {}" . format ( ii1i , OoIiIi111i1i1I ) )
  return ( False )
  if 93 - 93: iIii1I11I1II1 . OoOoOO00 / I1ii11iIi11i
 return ( True )
 if 17 - 17: Ii1I * I1Ii111 * OoooooooOO
 if 29 - 29: Oo0Ooo
 if 68 - 68: o0oOOo0O0Ooo * OoOoOO00 . I1ii11iIi11i
 if 32 - 32: OoooooooOO * I11i
 if 86 - 86: I1Ii111 - i1IIi % O0
 if 38 - 38: I1IiiI + OoO0O00 % iII111i / ooOoO0o
 if 93 - 93: OoOoOO00 . o0oOOo0O0Ooo - OoooooooOO
def lisp_write_to_dp_socket ( entry ) :
 try :
  OoIiiO0Oo0oo00O = json . dumps ( entry )
  oooooOoO00 = bold ( "Write IPC" , False )
  lprint ( "{} record to named socket: '{}'" . format ( oooooOoO00 , OoIiiO0Oo0oo00O ) )
  lisp_ipc_dp_socket . sendto ( OoIiiO0Oo0oo00O , lisp_ipc_dp_socket_name )
 except :
  lprint ( "Failed to write IPC record to named socket: '{}'" . format ( OoIiiO0Oo0oo00O ) )
  if 98 - 98: i1IIi
 return
 if 83 - 83: oO0o % O0 . I11i / I11i / I1IiiI - OoOoOO00
 if 91 - 91: iIii1I11I1II1 - IiII + iIii1I11I1II1 % Oo0Ooo % I1IiiI
 if 84 - 84: iIii1I11I1II1 . Oo0Ooo - OoooooooOO % Oo0Ooo
 if 27 - 27: I1ii11iIi11i - ooOoO0o + I11i - I1ii11iIi11i
 if 57 - 57: Oo0Ooo
 if 31 - 31: I1IiiI % Ii1I / OOooOOo + OoooooooOO . i11iIiiIii
 if 87 - 87: iII111i + IiII * I1ii11iIi11i . iII111i + Ii1I - II111iiii
 if 87 - 87: OoOoOO00 . o0oOOo0O0Ooo + I1ii11iIi11i
 if 53 - 53: o0oOOo0O0Ooo * II111iiii + i1IIi
def lisp_write_ipc_keys ( rloc ) :
 I11i11I = rloc . rloc . print_address_no_iid ( )
 II11i = rloc . translated_port
 if ( II11i != 0 ) : I11i11I += ":" + str ( II11i )
 if ( lisp_rloc_probe_list . has_key ( I11i11I ) == False ) : return
 if 83 - 83: I11i * o0oOOo0O0Ooo * Ii1I + OoooooooOO
 for oOo0Oooo , I1i11II , O0000O in lisp_rloc_probe_list [ I11i11I ] :
  iIi11 = lisp_map_cache . lookup_cache ( I1i11II , True )
  if ( iIi11 == None ) : continue
  lisp_write_ipc_map_cache ( True , iIi11 )
  if 76 - 76: I1ii11iIi11i . OoooooooOO + ooOoO0o / I1IiiI
 return
 if 56 - 56: Ii1I % I11i / O0 % O0 % iIii1I11I1II1 + I1IiiI
 if 51 - 51: O0 * Ii1I / oO0o * OoooooooOO
 if 93 - 93: I1ii11iIi11i . OOooOOo + i1IIi
 if 30 - 30: Oo0Ooo + I1Ii111 / OOooOOo
 if 74 - 74: iIii1I11I1II1
 if 69 - 69: ooOoO0o % iIii1I11I1II1 * o0oOOo0O0Ooo + OoOoOO00 % I1Ii111 % Oo0Ooo
 if 64 - 64: iIii1I11I1II1 * Ii1I * ooOoO0o * i11iIiiIii
def lisp_write_ipc_map_cache ( add_or_delete , mc , dont_send = False ) :
 if ( lisp_i_am_etr ) : return
 if ( lisp_ipc_dp_socket == None ) : return
 if ( lisp_check_dp_socket ( ) == False ) : return
 if 54 - 54: IiII . Ii1I
 if 54 - 54: iII111i
 if 2 - 2: OoOoOO00 + I1IiiI . ooOoO0o - oO0o . iIii1I11I1II1
 if 76 - 76: Ii1I
 i1iiIII1Ii1II = "add" if add_or_delete else "delete"
 oo = { "type" : "map-cache" , "opcode" : i1iiIII1Ii1II }
 if 7 - 7: IiII / ooOoO0o + I11i
 o0000ooO = ( mc . group . is_null ( ) == False )
 if ( o0000ooO ) :
  oo [ "eid-prefix" ] = mc . group . print_prefix_no_iid ( )
  oo [ "rles" ] = [ ]
 else :
  oo [ "eid-prefix" ] = mc . eid . print_prefix_no_iid ( )
  oo [ "rlocs" ] = [ ]
  if 40 - 40: I1IiiI + I1ii11iIi11i * I1IiiI % Ii1I
 oo [ "instance-id" ] = str ( mc . eid . instance_id )
 if 27 - 27: O0 / Oo0Ooo . oO0o
 if ( o0000ooO ) :
  if ( len ( mc . rloc_set ) >= 1 and mc . rloc_set [ 0 ] . rle ) :
   for II1ii in mc . rloc_set [ 0 ] . rle . rle_forwarding_list :
    I1Iii1I = II1ii . address . print_address_no_iid ( )
    II11i = str ( 4341 ) if II1ii . translated_port == 0 else str ( II1ii . translated_port )
    if 34 - 34: I1Ii111 % Ii1I / Oo0Ooo % ooOoO0o / i11iIiiIii * I1IiiI
    oOo0Oooo = { "rle" : I1Iii1I , "port" : II11i }
    o0III , Ii1ii1II11I1 = II1ii . get_encap_keys ( )
    oOo0Oooo = lisp_build_json_keys ( oOo0Oooo , o0III , Ii1ii1II11I1 , "encrypt-key" )
    oo [ "rles" ] . append ( oOo0Oooo )
    if 24 - 24: I1ii11iIi11i
    if 20 - 20: o0oOOo0O0Ooo + II111iiii * Ii1I . OoooooooOO
 else :
  for II1iIiIiIIi in mc . rloc_set :
   if ( II1iIiIiIIi . rloc . is_ipv4 ( ) == False and II1iIiIiIIi . rloc . is_ipv6 ( ) == False ) :
    continue
    if 88 - 88: O0 + iIii1I11I1II1 . o0oOOo0O0Ooo . iIii1I11I1II1 - Ii1I
   if ( II1iIiIiIIi . up_state ( ) == False ) : continue
   if 74 - 74: Ii1I . IiII
   II11i = str ( 4341 ) if II1iIiIiIIi . translated_port == 0 else str ( II1iIiIiIIi . translated_port )
   if 67 - 67: oO0o
   oOo0Oooo = { "rloc" : II1iIiIiIIi . rloc . print_address_no_iid ( ) , "priority" :
 str ( II1iIiIiIIi . priority ) , "weight" : str ( II1iIiIiIIi . weight ) , "port" :
 II11i }
   o0III , Ii1ii1II11I1 = II1iIiIiIIi . get_encap_keys ( )
   oOo0Oooo = lisp_build_json_keys ( oOo0Oooo , o0III , Ii1ii1II11I1 , "encrypt-key" )
   oo [ "rlocs" ] . append ( oOo0Oooo )
   if 12 - 12: I1IiiI + OoooooooOO
   if 25 - 25: iIii1I11I1II1 - I1IiiI . i11iIiiIii + ooOoO0o
   if 19 - 19: OoooooooOO / IiII
 if ( dont_send == False ) : lisp_write_to_dp_socket ( oo )
 return ( oo )
 if 40 - 40: OoOoOO00 / OoooooooOO * iIii1I11I1II1 / i1IIi . OoooooooOO
 if 88 - 88: I1IiiI % I1IiiI / II111iiii - IiII
 if 72 - 72: OoO0O00 - I1ii11iIi11i . Oo0Ooo / OoO0O00
 if 86 - 86: i11iIiiIii - oO0o . i11iIiiIii
 if 51 - 51: OoO0O00 - OoO0O00 * IiII
 if 24 - 24: OoooooooOO . II111iiii
 if 97 - 97: II111iiii . O0
def lisp_write_ipc_decap_key ( rloc_addr , keys ) :
 if ( lisp_i_am_itr ) : return
 if ( lisp_ipc_dp_socket == None ) : return
 if ( lisp_check_dp_socket ( ) == False ) : return
 if 18 - 18: iII111i
 if 35 - 35: ooOoO0o / O0 / iIii1I11I1II1 - iIii1I11I1II1 + I11i
 if 8 - 8: I1Ii111 . oO0o % Oo0Ooo * OoooooooOO
 if 25 - 25: OoO0O00
 if ( keys == None or len ( keys ) == 0 or keys [ 1 ] == None ) : return
 if 54 - 54: O0
 o0III = keys [ 1 ] . encrypt_key
 Ii1ii1II11I1 = keys [ 1 ] . icv_key
 if 20 - 20: ooOoO0o + Oo0Ooo - Oo0Ooo
 if 2 - 2: i1IIi - IiII . I1ii11iIi11i / i1IIi
 if 92 - 92: ooOoO0o - iII111i
 if 69 - 69: iII111i
 IiiIII = rloc_addr . split ( ":" )
 if ( len ( IiiIII ) == 1 ) :
  oo = { "type" : "decap-keys" , "rloc" : IiiIII [ 0 ] }
 else :
  oo = { "type" : "decap-keys" , "rloc" : IiiIII [ 0 ] , "port" : IiiIII [ 1 ] }
  if 99 - 99: OoooooooOO . oO0o + I1Ii111 + iII111i - oO0o + I1IiiI
 oo = lisp_build_json_keys ( oo , o0III , Ii1ii1II11I1 , "decrypt-key" )
 if 15 - 15: iII111i * I11i . IiII
 lisp_write_to_dp_socket ( oo )
 return
 if 89 - 89: iIii1I11I1II1
 if 50 - 50: OOooOOo / i11iIiiIii / I1ii11iIi11i * OoooooooOO . OoO0O00
 if 6 - 6: II111iiii % Ii1I / iIii1I11I1II1 % I1IiiI / iII111i % o0oOOo0O0Ooo
 if 46 - 46: i11iIiiIii - Ii1I / OoooooooOO - OoO0O00
 if 36 - 36: Ii1I * ooOoO0o * OoooooooOO + OoOoOO00
 if 43 - 43: I1Ii111 - Oo0Ooo % i1IIi . II111iiii
 if 80 - 80: IiII . iII111i + I1Ii111 + iII111i % Oo0Ooo
 if 98 - 98: i11iIiiIii . II111iiii + OoOoOO00
def lisp_build_json_keys ( entry , ekey , ikey , key_type ) :
 if ( ekey == None ) : return ( entry )
 if 25 - 25: I1IiiI + i11iIiiIii . I1Ii111 - I1ii11iIi11i
 entry [ "keys" ] = [ ]
 OOoOoO = { "key-id" : "1" , key_type : ekey , "icv-key" : ikey }
 entry [ "keys" ] . append ( OOoOoO )
 return ( entry )
 if 67 - 67: OOooOOo - OOooOOo * I1IiiI - II111iiii . i1IIi + Oo0Ooo
 if 97 - 97: O0 / i11iIiiIii - o0oOOo0O0Ooo - OoOoOO00 . oO0o
 if 77 - 77: oO0o * oO0o . OoOoOO00 . i1IIi
 if 90 - 90: OOooOOo . Ii1I . II111iiii + Ii1I
 if 2 - 2: I1Ii111 * OOooOOo + II111iiii - OoOoOO00
 if 94 - 94: Ii1I - iII111i . I1ii11iIi11i - Oo0Ooo % o0oOOo0O0Ooo + I1Ii111
 if 58 - 58: oO0o . ooOoO0o . I1IiiI . Oo0Ooo * iIii1I11I1II1 - iII111i
def lisp_write_ipc_database_mappings ( ephem_port ) :
 if ( lisp_i_am_etr == False ) : return
 if ( lisp_ipc_dp_socket == None ) : return
 if ( lisp_check_dp_socket ( ) == False ) : return
 if 96 - 96: OOooOOo % o0oOOo0O0Ooo / iIii1I11I1II1
 if 60 - 60: i1IIi / iIii1I11I1II1 + I11i % iII111i
 if 64 - 64: I11i . i11iIiiIii / iIii1I11I1II1 . I11i
 if 73 - 73: OoO0O00 % iIii1I11I1II1 + IiII * I1Ii111 % II111iiii
 oo = { "type" : "database-mappings" , "database-mappings" : [ ] }
 if 20 - 20: I11i % I1ii11iIi11i . OoO0O00 % OoOoOO00
 if 84 - 84: OoooooooOO / i11iIiiIii . IiII / I1IiiI
 if 62 - 62: iII111i - I1IiiI + OoooooooOO
 if 59 - 59: iIii1I11I1II1 + i11iIiiIii * oO0o . Oo0Ooo . I1Ii111
 for o0O00o in lisp_db_list :
  if ( o0O00o . eid . is_ipv4 ( ) == False and o0O00o . eid . is_ipv6 ( ) == False ) : continue
  i1iiI = { "instance-id" : str ( o0O00o . eid . instance_id ) ,
 "eid-prefix" : o0O00o . eid . print_prefix_no_iid ( ) }
  oo [ "database-mappings" ] . append ( i1iiI )
  if 69 - 69: O0 - OoOoOO00 + I1ii11iIi11i * II111iiii - II111iiii % Ii1I
 lisp_write_to_dp_socket ( oo )
 if 6 - 6: o0oOOo0O0Ooo . I1ii11iIi11i % OoO0O00 / Ii1I * iII111i * i1IIi
 if 76 - 76: II111iiii + OoO0O00 - I11i + OoooooooOO . I1ii11iIi11i % Ii1I
 if 92 - 92: I1ii11iIi11i / I1IiiI * Oo0Ooo
 if 28 - 28: I1ii11iIi11i . OoOoOO00 % OoOoOO00
 if 61 - 61: Ii1I % I1ii11iIi11i . I1ii11iIi11i / Oo0Ooo - I1Ii111 * OoOoOO00
 oo = { "type" : "etr-nat-port" , "port" : ephem_port }
 lisp_write_to_dp_socket ( oo )
 return
 if 47 - 47: IiII
 if 76 - 76: iII111i / II111iiii / I11i
 if 62 - 62: I1ii11iIi11i
 if 100 - 100: iII111i / ooOoO0o / IiII % II111iiii
 if 6 - 6: OoooooooOO - I1IiiI + OoooooooOO
 if 89 - 89: oO0o % Oo0Ooo . O0 . ooOoO0o
 if 46 - 46: IiII * I11i - OoO0O00 - Ii1I
def lisp_write_ipc_interfaces ( ) :
 if ( lisp_i_am_etr ) : return
 if ( lisp_ipc_dp_socket == None ) : return
 if ( lisp_check_dp_socket ( ) == False ) : return
 if 93 - 93: iIii1I11I1II1 / o0oOOo0O0Ooo - I11i - OOooOOo % ooOoO0o
 if 16 - 16: ooOoO0o * o0oOOo0O0Ooo - IiII + I1ii11iIi11i / o0oOOo0O0Ooo - O0
 if 71 - 71: i1IIi
 if 79 - 79: iII111i * O0 / Ii1I / O0 % i1IIi
 oo = { "type" : "interfaces" , "interfaces" : [ ] }
 if 52 - 52: OoooooooOO % oO0o - I11i % OoOoOO00 . II111iiii
 for iiiii11I1 in lisp_myinterfaces . values ( ) :
  if ( iiiii11I1 . instance_id == None ) : continue
  i1iiI = { "interface" : iiiii11I1 . device ,
 "instance-id" : str ( iiiii11I1 . instance_id ) }
  oo [ "interfaces" ] . append ( i1iiI )
  if 62 - 62: Ii1I . I1ii11iIi11i . iII111i + I11i * o0oOOo0O0Ooo
  if 56 - 56: oO0o * iIii1I11I1II1 . II111iiii - II111iiii + II111iiii - i11iIiiIii
 lisp_write_to_dp_socket ( oo )
 return
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
 if 4 - 4: iII111i
 if 23 - 23: i1IIi . iIii1I11I1II1 / I1IiiI . OoOoOO00 . iII111i / IiII
 if 65 - 65: Ii1I + IiII + I11i / I1Ii111 % iIii1I11I1II1
def lisp_parse_auth_key ( value ) :
 oo0oO0Oo = value . split ( "[" )
 iI1Iii1i1i1i = { }
 if ( len ( oo0oO0Oo ) == 1 ) :
  iI1Iii1i1i1i [ 0 ] = value
  return ( iI1Iii1i1i1i )
  if 39 - 39: i1IIi - I1ii11iIi11i / iIii1I11I1II1 + I11i / iIii1I11I1II1 % o0oOOo0O0Ooo
  if 67 - 67: I1Ii111 % Ii1I * ooOoO0o / OoO0O00 - oO0o % o0oOOo0O0Ooo
 for o0Oo000O00OOo in oo0oO0Oo :
  if ( o0Oo000O00OOo == "" ) : continue
  OOOoO000 = o0Oo000O00OOo . find ( "]" )
  iIIi1 = o0Oo000O00OOo [ 0 : OOOoO000 ]
  try : iIIi1 = int ( iIIi1 )
  except : return
  if 5 - 5: IiII / Ii1I * o0oOOo0O0Ooo % o0oOOo0O0Ooo - i11iIiiIii
  iI1Iii1i1i1i [ iIIi1 ] = o0Oo000O00OOo [ OOOoO000 + 1 : : ]
  if 35 - 35: OoOoOO00
 return ( iI1Iii1i1i1i )
 if 86 - 86: OoooooooOO * OoO0O00 . II111iiii + OoO0O00 . iII111i + o0oOOo0O0Ooo
 if 6 - 6: O0 - iII111i % IiII + IiII - I11i
 if 7 - 7: iIii1I11I1II1
 if 14 - 14: I1IiiI * Ii1I % OoOoOO00 / I1IiiI
 if 87 - 87: OOooOOo - i1IIi
 if 65 - 65: I11i - ooOoO0o / i1IIi - OOooOOo
 if 74 - 74: O0 - II111iiii + iIii1I11I1II1 % I1IiiI % OoOoOO00
 if 57 - 57: O0 * Ii1I / I1IiiI
 if 54 - 54: iIii1I11I1II1 + iII111i % OoOoOO00 % OOooOOo
 if 67 - 67: iII111i . II111iiii - I1IiiI / iII111i . Ii1I
 if 42 - 42: I1IiiI % I1Ii111 % iII111i + iII111i
 if 71 - 71: Oo0Ooo / OoOoOO00 - I1ii11iIi11i
 if 32 - 32: iII111i
 if 99 - 99: o0oOOo0O0Ooo . oO0o
 if 9 - 9: oO0o % OoooooooOO
 if 62 - 62: OoO0O00 / OoOoOO00 / I1Ii111 + Oo0Ooo - Ii1I
def lisp_reassemble ( packet ) :
 i1111iIII = socket . ntohs ( struct . unpack ( "H" , packet [ 6 : 8 ] ) [ 0 ] )
 if 72 - 72: OoO0O00 + I11i / iII111i % OOooOOo
 if 5 - 5: oO0o % OOooOOo
 if 95 - 95: OoOoOO00 + OoooooooOO - O0 + o0oOOo0O0Ooo
 if 88 - 88: i11iIiiIii . iIii1I11I1II1
 if ( i1111iIII == 0 or i1111iIII == 0x4000 ) : return ( packet )
 if 57 - 57: Ii1I * iIii1I11I1II1
 if 92 - 92: Ii1I % Ii1I . I11i / i1IIi % Oo0Ooo
 if 25 - 25: o0oOOo0O0Ooo - OoO0O00 - OoOoOO00 - ooOoO0o
 if 28 - 28: OOooOOo * ooOoO0o * OoooooooOO % IiII
 i11i = socket . ntohs ( struct . unpack ( "H" , packet [ 4 : 6 ] ) [ 0 ] )
 i1II = socket . ntohs ( struct . unpack ( "H" , packet [ 2 : 4 ] ) [ 0 ] )
 if 92 - 92: Ii1I . IiII + I1IiiI
 oOOOoO0oOOO = ( i1111iIII & 0x2000 == 0 and ( i1111iIII & 0x1fff ) != 0 )
 oo = [ ( i1111iIII & 0x1fff ) * 8 , i1II - 20 , packet , oOOOoO0oOOO ]
 if 96 - 96: i1IIi * OoO0O00
 if 89 - 89: O0 * OoOoOO00 * i11iIiiIii . iII111i
 if 28 - 28: ooOoO0o % i1IIi % I1ii11iIi11i
 if 58 - 58: I1IiiI
 if 100 - 100: I11i % ooOoO0o - OOooOOo - I1IiiI * oO0o + I1IiiI
 if 7 - 7: iIii1I11I1II1 * o0oOOo0O0Ooo / I1Ii111 % Oo0Ooo + OoO0O00 % OOooOOo
 if 85 - 85: I1IiiI . i11iIiiIii - ooOoO0o * I11i * OoOoOO00 * I11i
 if 29 - 29: I1Ii111 * I1Ii111 . iII111i + o0oOOo0O0Ooo
 if ( i1111iIII == 0x2000 ) :
  iiII , I1iI1111i = struct . unpack ( "HH" , packet [ 20 : 24 ] )
  iiII = socket . ntohs ( iiII )
  I1iI1111i = socket . ntohs ( I1iI1111i )
  if ( I1iI1111i not in [ 4341 , 8472 , 4789 ] and iiII != 4341 ) :
   lisp_reassembly_queue [ i11i ] = [ ]
   oo [ 2 ] = None
   if 57 - 57: I1Ii111 - IiII
   if 89 - 89: oO0o + iII111i
   if 52 - 52: OOooOOo % O0 * I1ii11iIi11i . I1ii11iIi11i / IiII
   if 7 - 7: II111iiii
   if 7 - 7: iIii1I11I1II1 . O0 + Ii1I % I1IiiI * O0 + OoO0O00
   if 3 - 3: Oo0Ooo * OoooooooOO * oO0o % OoOoOO00 * OoOoOO00 . ooOoO0o
 if ( lisp_reassembly_queue . has_key ( i11i ) == False ) :
  lisp_reassembly_queue [ i11i ] = [ ]
  if 16 - 16: ooOoO0o / o0oOOo0O0Ooo - O0 * I1IiiI
  if 13 - 13: iII111i . iII111i % O0 % o0oOOo0O0Ooo
  if 99 - 99: OoO0O00 - OoOoOO00 + OoO0O00
  if 67 - 67: I1Ii111
  if 31 - 31: OoO0O00 * Oo0Ooo % O0 * II111iiii + ooOoO0o * I1IiiI
 o00O00O0OO00o = lisp_reassembly_queue [ i11i ]
 if 47 - 47: iIii1I11I1II1 % iII111i
 if 2 - 2: i1IIi
 if 60 - 60: OOooOOo + I1ii11iIi11i / OoOoOO00 * i1IIi / O0
 if 24 - 24: Oo0Ooo . IiII % o0oOOo0O0Ooo . OOooOOo . I1IiiI + I1Ii111
 if 51 - 51: Oo0Ooo * I11i % i1IIi / iIii1I11I1II1 . OoooooooOO
 if ( len ( o00O00O0OO00o ) == 1 and o00O00O0OO00o [ 0 ] [ 2 ] == None ) :
  dprint ( "Drop non-LISP encapsulated fragment 0x{}" . format ( lisp_hex_string ( i11i ) . zfill ( 4 ) ) )
  if 5 - 5: iIii1I11I1II1 % oO0o - II111iiii - OoOoOO00 / i1IIi
  return ( None )
  if 20 - 20: II111iiii * OoOoOO00 . Ii1I . I1ii11iIi11i
  if 91 - 91: oO0o / OoOoOO00 % I1Ii111 % I1Ii111 / ooOoO0o
  if 39 - 39: OoO0O00 + OoO0O00 * iIii1I11I1II1 + I11i / OoO0O00
  if 82 - 82: I1IiiI / I1IiiI - iII111i % I1ii11iIi11i
  if 84 - 84: iII111i
 o00O00O0OO00o . append ( oo )
 o00O00O0OO00o = sorted ( o00O00O0OO00o )
 if 24 - 24: oO0o - OoO0O00 + I1Ii111
 if 98 - 98: iII111i . oO0o - O0 % I1IiiI . I1ii11iIi11i / i1IIi
 if 72 - 72: I1IiiI / Oo0Ooo % IiII - O0 / O0 * O0
 if 83 - 83: O0 / I1Ii111 - OoooooooOO
 I1Iii1I = lisp_address ( LISP_AFI_IPV4 , "" , 32 , 0 )
 I1Iii1I . address = socket . ntohl ( struct . unpack ( "I" , packet [ 12 : 16 ] ) [ 0 ] )
 I1Ii = I1Iii1I . print_address_no_iid ( )
 I1Iii1I . address = socket . ntohl ( struct . unpack ( "I" , packet [ 16 : 20 ] ) [ 0 ] )
 IIiii1IiiI11i = I1Iii1I . print_address_no_iid ( )
 I1Iii1I = red ( "{} -> {}" . format ( I1Ii , IIiii1IiiI11i ) , False )
 if 20 - 20: Oo0Ooo + II111iiii + II111iiii . o0oOOo0O0Ooo
 dprint ( "{}{} fragment, RLOCs: {}, packet 0x{}, frag-offset: 0x{}" . format ( bold ( "Received" , False ) , " non-LISP encapsulated" if oo [ 2 ] == None else "" , I1Iii1I , lisp_hex_string ( i11i ) . zfill ( 4 ) ,
 # o0oOOo0O0Ooo * I1ii11iIi11i % OoOoOO00 . Ii1I . OoO0O00 * I1Ii111
 # I11i % ooOoO0o
 lisp_hex_string ( i1111iIII ) . zfill ( 4 ) ) )
 if 96 - 96: OoO0O00 * O0 . i1IIi
 if 32 - 32: i11iIiiIii
 if 43 - 43: iIii1I11I1II1 + oO0o + OoooooooOO
 if 69 - 69: Oo0Ooo - o0oOOo0O0Ooo
 if 18 - 18: OoooooooOO
 if ( o00O00O0OO00o [ 0 ] [ 0 ] != 0 or o00O00O0OO00o [ - 1 ] [ 3 ] == False ) : return ( None )
 Ooooooo0 = o00O00O0OO00o [ 0 ]
 for i111IIiIiiI1 in o00O00O0OO00o [ 1 : : ] :
  i1111iIII = i111IIiIiiI1 [ 0 ]
  oOooo00Oo0oo , oooo = Ooooooo0 [ 0 ] , Ooooooo0 [ 1 ]
  if ( oOooo00Oo0oo + oooo != i1111iIII ) : return ( None )
  Ooooooo0 = i111IIiIiiI1
  if 5 - 5: Ii1I / O0 + iIii1I11I1II1
 lisp_reassembly_queue . pop ( i11i )
 if 22 - 22: ooOoO0o . ooOoO0o * OOooOOo % OoOoOO00
 if 51 - 51: OoOoOO00 . oO0o - OoOoOO00
 if 79 - 79: iII111i
 if 71 - 71: i1IIi / OoO0O00 / OOooOOo + I1Ii111
 if 80 - 80: Oo0Ooo . iIii1I11I1II1 . OoooooooOO % iII111i . oO0o
 packet = o00O00O0OO00o [ 0 ] [ 2 ]
 for i111IIiIiiI1 in o00O00O0OO00o [ 1 : : ] : packet += i111IIiIiiI1 [ 2 ] [ 20 : : ]
 if 10 - 10: i11iIiiIii * OoooooooOO . i11iIiiIii
 dprint ( "{} fragments arrived for packet 0x{}, length {}" . format ( bold ( "All" , False ) , lisp_hex_string ( i11i ) . zfill ( 4 ) , len ( packet ) ) )
 if 35 - 35: OOooOOo * OOooOOo + o0oOOo0O0Ooo / i1IIi - I11i
 if 12 - 12: I1ii11iIi11i - i11iIiiIii + I1IiiI . Oo0Ooo
 if 26 - 26: oO0o + I1Ii111 + IiII * o0oOOo0O0Ooo . oO0o
 if 95 - 95: OoOoOO00 . I1Ii111 / Ii1I . I1Ii111 % OoO0O00
 if 16 - 16: Ii1I / I1IiiI / I1IiiI - OoooooooOO
 i1IIiIIIi1 = socket . htons ( len ( packet ) )
 ooo0Oo00O = packet [ 0 : 2 ] + struct . pack ( "H" , i1IIiIIIi1 ) + packet [ 4 : 6 ] + struct . pack ( "H" , 0 ) + packet [ 8 : 10 ] + struct . pack ( "H" , 0 ) + packet [ 12 : 20 ]
 if 13 - 13: OOooOOo / OoooooooOO
 if 7 - 7: II111iiii - ooOoO0o
 ooo0Oo00O = lisp_ip_checksum ( ooo0Oo00O )
 return ( ooo0Oo00O + packet [ 20 : : ] )
 if 72 - 72: Ii1I
 if 27 - 27: ooOoO0o / IiII + OoO0O00 + Ii1I % I1Ii111
 if 86 - 86: O0 % i11iIiiIii - Ii1I * oO0o % OOooOOo * i1IIi
 if 87 - 87: II111iiii
 if 53 - 53: OoOoOO00 * i11iIiiIii / I1Ii111
 if 100 - 100: ooOoO0o + I1IiiI * oO0o + ooOoO0o
 if 24 - 24: i11iIiiIii + ooOoO0o
 if 80 - 80: IiII % I11i % oO0o
def lisp_get_crypto_decap_lookup_key ( addr , port ) :
 I11i11I = addr . print_address_no_iid ( ) + ":" + str ( port )
 if ( lisp_crypto_keys_by_rloc_decap . has_key ( I11i11I ) ) : return ( I11i11I )
 if 97 - 97: i1IIi * i11iIiiIii / Ii1I - I1IiiI % IiII
 I11i11I = addr . print_address_no_iid ( )
 if ( lisp_crypto_keys_by_rloc_decap . has_key ( I11i11I ) ) : return ( I11i11I )
 if 70 - 70: iIii1I11I1II1
 if 2 - 2: IiII - i1IIi * IiII % O0 / Ii1I
 if 64 - 64: iII111i - Oo0Ooo
 if 73 - 73: iIii1I11I1II1 * I1Ii111 * OoO0O00
 if 68 - 68: ooOoO0o * Ii1I / I1ii11iIi11i * OoooooooOO + OoooooooOO . OoooooooOO
 for iiIiiiiiI11 in lisp_crypto_keys_by_rloc_decap :
  OOOO0o = iiIiiiiiI11 . split ( ":" )
  if ( len ( OOOO0o ) == 1 ) : continue
  OOOO0o = OOOO0o [ 0 ] if len ( OOOO0o ) == 2 else ":" . join ( OOOO0o [ 0 : - 1 ] )
  if ( OOOO0o == I11i11I ) :
   OOo = lisp_crypto_keys_by_rloc_decap [ iiIiiiiiI11 ]
   lisp_crypto_keys_by_rloc_decap [ I11i11I ] = OOo
   return ( I11i11I )
   if 50 - 50: iII111i % OoOoOO00 - II111iiii + II111iiii / OoO0O00
   if 69 - 69: Ii1I * II111iiii
 return ( None )
 if 24 - 24: I1Ii111 * I1ii11iIi11i . OOooOOo . I1IiiI - I1ii11iIi11i
 if 56 - 56: I1IiiI * Oo0Ooo + OoO0O00 - oO0o * I1Ii111
 if 68 - 68: ooOoO0o * i11iIiiIii * OOooOOo % iII111i
 if 10 - 10: Ii1I / Oo0Ooo - i1IIi
 if 11 - 11: I11i * iII111i
 if 28 - 28: II111iiii + IiII / Oo0Ooo * I1IiiI - OOooOOo
 if 2 - 2: oO0o + I11i / I1Ii111 . I11i
 if 59 - 59: Ii1I
 if 47 - 47: iII111i % iII111i
 if 81 - 81: oO0o / I1ii11iIi11i . OoooooooOO % II111iiii / oO0o
 if 23 - 23: IiII + oO0o + o0oOOo0O0Ooo . I1ii11iIi11i / i11iIiiIii + iIii1I11I1II1
def lisp_build_crypto_decap_lookup_key ( addr , port ) :
 addr = addr . print_address_no_iid ( )
 o0OOOOoOoo = addr + ":" + str ( port )
 if 90 - 90: I1ii11iIi11i . OoO0O00 * iIii1I11I1II1 - Oo0Ooo
 if ( lisp_i_am_rtr ) :
  if ( lisp_rloc_probe_list . has_key ( addr ) ) : return ( addr )
  if 28 - 28: I1IiiI . ooOoO0o - ooOoO0o * OOooOOo . IiII
  if 16 - 16: iIii1I11I1II1 % i11iIiiIii / Ii1I % iIii1I11I1II1 / iII111i
  if 27 - 27: II111iiii * OoooooooOO / Oo0Ooo % O0
  if 41 - 41: oO0o / iIii1I11I1II1 % iII111i - I1Ii111 % I11i * i11iIiiIii
  if 21 - 21: O0
  if 14 - 14: IiII / I1ii11iIi11i + Ii1I
  for Ii1i111Iii in lisp_nat_state_info . values ( ) :
   for iiIiIIi1I in Ii1i111Iii :
    if ( addr == iiIiIIi1I . address ) : return ( o0OOOOoOoo )
    if 48 - 48: I1Ii111 * oO0o / o0oOOo0O0Ooo * OoOoOO00 * ooOoO0o
    if 38 - 38: I1IiiI * Ii1I + Oo0Ooo - OoooooooOO
  return ( addr )
  if 63 - 63: I1ii11iIi11i
 return ( o0OOOOoOoo )
 if 99 - 99: I1Ii111 % oO0o - II111iiii . ooOoO0o
 if 26 - 26: I1ii11iIi11i * iII111i . OoooooooOO - Oo0Ooo - IiII
 if 6 - 6: OOooOOo - I1IiiI . IiII
 if 40 - 40: II111iiii
 if 13 - 13: OoOoOO00
 if 23 - 23: Oo0Ooo / II111iiii % OOooOOo % iII111i - Oo0Ooo / OoO0O00
 if 7 - 7: Ii1I / I11i / II111iiii % I11i * I11i + iIii1I11I1II1
def lisp_set_ttl ( lisp_socket , ttl ) :
 try :
  lisp_socket . setsockopt ( socket . SOL_IP , socket . IP_TTL , ttl )
 except :
  lprint ( "socket.setsockopt(IP_TTL) not supported" )
  pass
  if 6 - 6: iIii1I11I1II1 * oO0o - iIii1I11I1II1 . O0 . O0
 return
 if 96 - 96: I1Ii111 * II111iiii % i11iIiiIii - oO0o
 if 32 - 32: i11iIiiIii * o0oOOo0O0Ooo . OoooooooOO / O0
 if 14 - 14: i11iIiiIii . I1Ii111 % I1ii11iIi11i . I1ii11iIi11i % IiII
 if 93 - 93: iIii1I11I1II1 / IiII
 if 91 - 91: i11iIiiIii % ooOoO0o - iII111i * I1Ii111 . i11iIiiIii
 if 1 - 1: IiII + iIii1I11I1II1 * I1ii11iIi11i - IiII - i1IIi
 if 75 - 75: II111iiii * o0oOOo0O0Ooo / I1ii11iIi11i
def lisp_is_rloc_probe_request ( lisp_type ) :
 lisp_type = struct . unpack ( "B" , lisp_type ) [ 0 ]
 return ( lisp_type == 0x12 )
 if 46 - 46: OOooOOo
 if 67 - 67: OoO0O00 . I11i % OOooOOo + Oo0Ooo
 if 40 - 40: OoO0O00 / I11i % iIii1I11I1II1 - ooOoO0o
 if 51 - 51: Oo0Ooo % iIii1I11I1II1 % oO0o + o0oOOo0O0Ooo
 if 32 - 32: I1Ii111 * I1IiiI + Ii1I
 if 30 - 30: OoooooooOO / I1IiiI . iIii1I11I1II1 / ooOoO0o
 if 20 - 20: OoooooooOO * OOooOOo
def lisp_is_rloc_probe_reply ( lisp_type ) :
 lisp_type = struct . unpack ( "B" , lisp_type ) [ 0 ]
 return ( lisp_type == 0x28 )
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
 if 95 - 95: OoOoOO00 * iIii1I11I1II1 / OoooooooOO % i1IIi
 if 91 - 91: OOooOOo - OoOoOO00
 if 58 - 58: II111iiii . OOooOOo % II111iiii * oO0o % OoO0O00 % I11i
def lisp_is_rloc_probe ( packet , rr ) :
 O00oo0O00 = ( struct . unpack ( "B" , packet [ 9 ] ) [ 0 ] == 17 )
 if ( O00oo0O00 == False ) : return ( [ packet , None , None , None ] )
 if 71 - 71: Ii1I * II111iiii * I1IiiI
 if ( rr == 0 ) :
  iI1IiIIii1I = lisp_is_rloc_probe_request ( packet [ 28 ] )
  if ( iI1IiIIii1I == False ) : return ( [ packet , None , None , None ] )
 elif ( rr == 1 ) :
  iI1IiIIii1I = lisp_is_rloc_probe_reply ( packet [ 28 ] )
  if ( iI1IiIIii1I == False ) : return ( [ packet , None , None , None ] )
 elif ( rr == - 1 ) :
  iI1IiIIii1I = lisp_is_rloc_probe_request ( packet [ 28 ] )
  if ( iI1IiIIii1I == False ) :
   iI1IiIIii1I = lisp_is_rloc_probe_reply ( packet [ 28 ] )
   if ( iI1IiIIii1I == False ) : return ( [ packet , None , None , None ] )
   if 22 - 22: oO0o
   if 96 - 96: ooOoO0o * iII111i . IiII
   if 77 - 77: OOooOOo - I11i % o0oOOo0O0Ooo
   if 46 - 46: I1IiiI % oO0o . OoooooooOO . IiII / I11i - i1IIi
   if 43 - 43: OoOoOO00 - o0oOOo0O0Ooo
   if 22 - 22: i1IIi
 oo0O00 = lisp_address ( LISP_AFI_IPV4 , "" , 32 , 0 )
 oo0O00 . address = socket . ntohl ( struct . unpack ( "I" , packet [ 12 : 16 ] ) [ 0 ] )
 if 33 - 33: O0
 if 34 - 34: I1Ii111 . IiII % iII111i
 if 94 - 94: OOooOOo % i11iIiiIii . OOooOOo
 if 55 - 55: OoOoOO00 . OoOoOO00 % o0oOOo0O0Ooo . I11i . I1ii11iIi11i - o0oOOo0O0Ooo
 if ( oo0O00 . is_local ( ) ) : return ( [ None , None , None , None ] )
 if 1 - 1: i11iIiiIii - i1IIi * oO0o - iIii1I11I1II1
 if 75 - 75: i1IIi * i11iIiiIii
 if 40 - 40: I1ii11iIi11i + OoO0O00
 if 8 - 8: i11iIiiIii - iIii1I11I1II1
 oo0O00 = oo0O00 . print_address_no_iid ( )
 II11i = socket . ntohs ( struct . unpack ( "H" , packet [ 20 : 22 ] ) [ 0 ] )
 I1i11iiIiIi = struct . unpack ( "B" , packet [ 8 ] ) [ 0 ] - 1
 packet = packet [ 28 : : ]
 if 73 - 73: OoOoOO00
 oOo0Oooo = bold ( "Receive(pcap)" , False )
 iI1i1i1i1i = bold ( "from " + oo0O00 , False )
 OoOOOOo = lisp_format_packet ( packet )
 lprint ( "{} {} bytes {} {}, packet: {}" . format ( oOo0Oooo , len ( packet ) , iI1i1i1i1i , II11i , OoOOOOo ) )
 if 25 - 25: iII111i / oO0o
 return ( [ packet , oo0O00 , II11i , I1i11iiIiIi ] )
 if 61 - 61: OoooooooOO . Ii1I . I11i + oO0o
 if 73 - 73: II111iiii % i11iIiiIii * I1ii11iIi11i + O0
 if 61 - 61: I1IiiI / OOooOOo
 if 67 - 67: OoOoOO00
 if 22 - 22: Ii1I * I1ii11iIi11i * o0oOOo0O0Ooo - I1IiiI . i11iIiiIii
 if 30 - 30: O0 / oO0o * i11iIiiIii + iIii1I11I1II1 + O0 % I1IiiI
 if 95 - 95: ooOoO0o % OOooOOo
 if 17 - 17: i1IIi + Ii1I
 if 35 - 35: iIii1I11I1II1 - Oo0Ooo - OoooooooOO % I1ii11iIi11i
 if 27 - 27: Oo0Ooo * II111iiii - OOooOOo + o0oOOo0O0Ooo
 if 26 - 26: oO0o / I1ii11iIi11i - oO0o
def lisp_ipc_write_xtr_parameters ( cp , dp ) :
 if ( lisp_ipc_dp_socket == None ) : return
 if 9 - 9: ooOoO0o * iIii1I11I1II1 * OoooooooOO
 OooOoO0OO00 = { "type" : "xtr-parameters" , "control-plane-logging" : cp ,
 "data-plane-logging" : dp , "rtr" : lisp_i_am_rtr }
 if 13 - 13: iII111i . i11iIiiIii * o0oOOo0O0Ooo . iII111i
 lisp_write_to_dp_socket ( OooOoO0OO00 )
 return
 if 96 - 96: Ii1I
 if 90 - 90: II111iiii
 if 93 - 93: i11iIiiIii / Ii1I * Oo0Ooo . iII111i % iII111i / IiII
 if 15 - 15: OoOoOO00 % I1Ii111 - iIii1I11I1II1
 if 52 - 52: i11iIiiIii * ooOoO0o
 if 15 - 15: OoooooooOO . oO0o . i11iIiiIii / o0oOOo0O0Ooo
 if 91 - 91: ooOoO0o
 if 47 - 47: II111iiii + I11i + ooOoO0o % Oo0Ooo / iII111i
def lisp_external_data_plane ( ) :
 Ii1I1i111 = 'egrep "ipc-data-plane = yes" ./lisp.config'
 if ( commands . getoutput ( Ii1I1i111 ) != "" ) : return ( True )
 if 9 - 9: O0 + IiII
 if ( os . getenv ( "LISP_RUN_LISP_XTR" ) != None ) : return ( True )
 return ( False )
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
def lisp_process_data_plane_restart ( do_clear = False ) :
 os . system ( "touch ./lisp.config" )
 if 64 - 64: I1ii11iIi11i . i1IIi % II111iiii % Oo0Ooo + oO0o - I1IiiI
 I1iiii = { "type" : "entire-map-cache" , "entries" : [ ] }
 if 8 - 8: I1ii11iIi11i % I11i - i1IIi . Oo0Ooo * I1Ii111
 if ( do_clear == False ) :
  Ooo0000000 = I1iiii [ "entries" ]
  lisp_map_cache . walk_cache ( lisp_ipc_walk_map_cache , Ooo0000000 )
  if 44 - 44: iII111i
  if 56 - 56: II111iiii / Oo0Ooo % IiII * II111iiii - iIii1I11I1II1 + ooOoO0o
 lisp_write_to_dp_socket ( I1iiii )
 return
 if 33 - 33: o0oOOo0O0Ooo . I11i / I1IiiI
 if 29 - 29: o0oOOo0O0Ooo - ooOoO0o
 if 59 - 59: I11i / IiII * OoO0O00 / IiII . I1Ii111
 if 82 - 82: OOooOOo . iIii1I11I1II1 + I1Ii111
 if 14 - 14: IiII . i11iIiiIii
 if 17 - 17: ooOoO0o % ooOoO0o * oO0o
 if 8 - 8: ooOoO0o + OoO0O00 . II111iiii / iIii1I11I1II1 - OOooOOo
 if 87 - 87: iIii1I11I1II1 . IiII % I1IiiI . OoO0O00 - I1Ii111
 if 53 - 53: I1Ii111 % i11iIiiIii
 if 99 - 99: I1IiiI - i1IIi * i11iIiiIii + OoO0O00
 if 80 - 80: o0oOOo0O0Ooo . I11i % iIii1I11I1II1 + OoOoOO00
 if 87 - 87: I1Ii111 + II111iiii / I1ii11iIi11i + OoOoOO00
 if 71 - 71: I1IiiI + iIii1I11I1II1 + O0 * iII111i % IiII
 if 42 - 42: OOooOOo - I1ii11iIi11i
def lisp_process_data_plane_stats ( msg , lisp_sockets , lisp_port ) :
 if ( msg . has_key ( "entries" ) == False ) :
  lprint ( "No 'entries' in stats IPC message" )
  return
  if 93 - 93: I1Ii111 + OOooOOo % ooOoO0o / I1Ii111 % OOooOOo . IiII
 if ( type ( msg [ "entries" ] ) != list ) :
  lprint ( "'entries' in stats IPC message must be an array" )
  return
  if 37 - 37: iII111i * oO0o / oO0o / Ii1I % I11i
  if 12 - 12: i11iIiiIii
 for msg in msg [ "entries" ] :
  if ( msg . has_key ( "eid-prefix" ) == False ) :
   lprint ( "No 'eid-prefix' in stats IPC message" )
   continue
   if 62 - 62: oO0o + OOooOOo + oO0o + I1IiiI
  oo0ooooO = msg [ "eid-prefix" ]
  if 10 - 10: IiII - Oo0Ooo % ooOoO0o
  if ( msg . has_key ( "instance-id" ) == False ) :
   lprint ( "No 'instance-id' in stats IPC message" )
   continue
   if 38 - 38: oO0o * o0oOOo0O0Ooo . I11i % II111iiii / I11i % Ii1I
  IIiI1i = int ( msg [ "instance-id" ] )
  if 19 - 19: II111iiii / i11iIiiIii * II111iiii + OoOoOO00 - OoOoOO00
  if 7 - 7: OoOoOO00 - OoO0O00 % OoOoOO00 . I1ii11iIi11i % Oo0Ooo * iII111i
  if 90 - 90: IiII - OOooOOo + iIii1I11I1II1
  if 88 - 88: ooOoO0o . o0oOOo0O0Ooo . OOooOOo - I11i
  III1II1I1iI = lisp_address ( LISP_AFI_NONE , "" , 0 , IIiI1i )
  III1II1I1iI . store_prefix ( oo0ooooO )
  iIi11 = lisp_map_cache_lookup ( None , III1II1I1iI )
  if ( iIi11 == None ) :
   lprint ( "Map-cache entry for {} not found for stats update" . format ( oo0ooooO ) )
   if 76 - 76: IiII % I1IiiI . iII111i
   continue
   if 5 - 5: ooOoO0o . oO0o - OoOoOO00 - OoooooooOO
   if 2 - 2: OOooOOo
  if ( msg . has_key ( "rlocs" ) == False ) :
   lprint ( "No 'rlocs' in stats IPC message for {}" . format ( oo0ooooO ) )
   if 37 - 37: IiII - iIii1I11I1II1 * i11iIiiIii . ooOoO0o
   continue
   if 78 - 78: OOooOOo - I1ii11iIi11i + iII111i % OoOoOO00
  if ( type ( msg [ "rlocs" ] ) != list ) :
   lprint ( "'rlocs' in stats IPC message must be an array" )
   continue
   if 28 - 28: I11i + i1IIi / i11iIiiIii * OOooOOo * II111iiii
  oO0o00o0O = msg [ "rlocs" ]
  if 87 - 87: iII111i
  if 63 - 63: iII111i - I11i - iIii1I11I1II1 - Ii1I / iII111i % I1Ii111
  if 59 - 59: OoooooooOO
  if 89 - 89: i1IIi / OoooooooOO . I1IiiI
  for oOo0o00Oo0 in oO0o00o0O :
   if ( oOo0o00Oo0 . has_key ( "rloc" ) == False ) : continue
   if 4 - 4: Ii1I + I1ii11iIi11i
   IIII1i = oOo0o00Oo0 [ "rloc" ]
   if ( IIII1i == "no-address" ) : continue
   if 40 - 40: OOooOOo % iII111i
   II1iIiIiIIi = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
   II1iIiIiIIi . store_address ( IIII1i )
   if 5 - 5: O0 + i11iIiiIii . IiII - OOooOOo
   o0OO0O0OoOo0 = iIi11 . get_rloc ( II1iIiIiIIi )
   if ( o0OO0O0OoOo0 == None ) : continue
   if 51 - 51: OOooOOo . I1IiiI % OoO0O00 . I1IiiI
   if 88 - 88: O0 . iIii1I11I1II1 . iIii1I11I1II1 - ooOoO0o * iIii1I11I1II1 . Oo0Ooo
   if 8 - 8: iII111i
   if 78 - 78: i11iIiiIii % oO0o % ooOoO0o - I1Ii111
   OOooOoO = 0 if oOo0o00Oo0 . has_key ( "packet-count" ) == False else oOo0o00Oo0 [ "packet-count" ]
   if 45 - 45: ooOoO0o / OoooooooOO . Oo0Ooo
   O0OOooOo00OooOoO = 0 if oOo0o00Oo0 . has_key ( "byte-count" ) == False else oOo0o00Oo0 [ "byte-count" ]
   if 35 - 35: i11iIiiIii / o0oOOo0O0Ooo / oO0o / I11i . O0
   III11I1 = 0 if oOo0o00Oo0 . has_key ( "seconds-last-packet" ) == False else oOo0o00Oo0 [ "seconds-last-packet" ]
   if 53 - 53: i1IIi
   if 51 - 51: OoOoOO00 / iIii1I11I1II1 . oO0o - I1ii11iIi11i - OOooOOo
   o0OO0O0OoOo0 . stats . packet_count += OOooOoO
   o0OO0O0OoOo0 . stats . byte_count += O0OOooOo00OooOoO
   o0OO0O0OoOo0 . stats . last_increment = lisp_get_timestamp ( ) - III11I1
   if 90 - 90: i1IIi / oO0o * I1Ii111 + II111iiii % I11i
   lprint ( "Update stats {}/{}/{}s for {} RLOC {}" . format ( OOooOoO , O0OOooOo00OooOoO ,
 III11I1 , oo0ooooO , IIII1i ) )
   if 41 - 41: o0oOOo0O0Ooo - II111iiii . ooOoO0o . iII111i - ooOoO0o / iII111i
   if 59 - 59: O0 / II111iiii * II111iiii - ooOoO0o
   if 63 - 63: I1ii11iIi11i * IiII % OoO0O00 . OoOoOO00 - II111iiii % IiII
   if 8 - 8: iIii1I11I1II1
   if 71 - 71: oO0o / o0oOOo0O0Ooo % iIii1I11I1II1 * iIii1I11I1II1
  if ( iIi11 . group . is_null ( ) and iIi11 . has_ttl_elapsed ( ) ) :
   oo0ooooO = green ( iIi11 . print_eid_tuple ( ) , False )
   lprint ( "Refresh map-cache entry {}" . format ( oo0ooooO ) )
   lisp_send_map_request ( lisp_sockets , lisp_port , None , iIi11 . eid , None )
   if 29 - 29: ooOoO0o - OoOoOO00 - o0oOOo0O0Ooo
   if 54 - 54: Ii1I + i11iIiiIii + i1IIi - OoooooooOO
 return
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
 if 6 - 6: I11i % iIii1I11I1II1 + I1Ii111
 if 48 - 48: II111iiii . OOooOOo . ooOoO0o - iII111i
 if 90 - 90: OOooOOo
 if 43 - 43: IiII + ooOoO0o
 if 4 - 4: i1IIi
 if 89 - 89: Oo0Ooo / iIii1I11I1II1 . OoOoOO00
 if 6 - 6: Ii1I / iII111i
 if 69 - 69: iIii1I11I1II1 % I1Ii111 % OOooOOo + O0 - OoOoOO00 % oO0o
 if 70 - 70: oO0o - I1IiiI + Ii1I
 if 54 - 54: OoOoOO00 / ooOoO0o - I1IiiI
 if 37 - 37: o0oOOo0O0Ooo
 if 57 - 57: iII111i / i1IIi / i1IIi + IiII
 if 75 - 75: IiII / O0
def lisp_process_data_plane_decap_stats ( msg , lisp_ipc_socket ) :
 if 72 - 72: I11i
 if 35 - 35: I11i % OoooooooOO / i1IIi * i1IIi / I1IiiI
 if 42 - 42: I11i - i1IIi - oO0o / I11i + Ii1I + ooOoO0o
 if 23 - 23: OoOoOO00 . oO0o - iII111i
 if 27 - 27: Oo0Ooo * OOooOOo - OoOoOO00
 if ( lisp_i_am_itr ) :
  lprint ( "Send decap-stats IPC message to lisp-etr process" )
  OooOoO0OO00 = "stats%{}" . format ( json . dumps ( msg ) )
  OooOoO0OO00 = lisp_command_ipc ( OooOoO0OO00 , "lisp-itr" )
  lisp_ipc ( OooOoO0OO00 , lisp_ipc_socket , "lisp-etr" )
  return
  if 1 - 1: II111iiii * i11iIiiIii . OoooooooOO
  if 37 - 37: OoooooooOO + O0 . I11i % OoOoOO00
  if 57 - 57: I1Ii111 . OOooOOo + I1Ii111 . iIii1I11I1II1 / oO0o / O0
  if 88 - 88: I1Ii111
  if 16 - 16: Oo0Ooo . ooOoO0o / OoO0O00 / o0oOOo0O0Ooo . OoooooooOO * OoO0O00
  if 50 - 50: II111iiii + I11i . OoooooooOO . I1Ii111 - OOooOOo
  if 83 - 83: oO0o
  if 100 - 100: I1Ii111 + o0oOOo0O0Ooo * oO0o / oO0o . oO0o + iII111i
 OooOoO0OO00 = bold ( "IPC" , False )
 lprint ( "Process decap-stats {} message: '{}'" . format ( OooOoO0OO00 , msg ) )
 if 71 - 71: II111iiii + iII111i + O0 % Oo0Ooo / I1IiiI
 if ( lisp_i_am_etr ) : msg = json . loads ( msg )
 if 52 - 52: Oo0Ooo . I1Ii111 * i1IIi / Oo0Ooo / OoO0O00
 i1iII1IIi1I = [ "good-packets" , "ICV-error" , "checksum-error" ,
 "lisp-header-error" , "no-decrypt-key" , "bad-inner-version" ,
 "outer-header-error" ]
 if 69 - 69: I1IiiI % I1IiiI . OoooooooOO - ooOoO0o / I11i
 for iiiI1I1i1II in i1iII1IIi1I :
  OOooOoO = 0 if msg . has_key ( iiiI1I1i1II ) == False else msg [ iiiI1I1i1II ] [ "packet-count" ]
  if 92 - 92: iII111i / I1IiiI / i11iIiiIii
  lisp_decap_stats [ iiiI1I1i1II ] . packet_count += OOooOoO
  if 75 - 75: Oo0Ooo + IiII / I11i % I11i % IiII / I1Ii111
  O0OOooOo00OooOoO = 0 if msg . has_key ( iiiI1I1i1II ) == False else msg [ iiiI1I1i1II ] [ "byte-count" ]
  if 95 - 95: OoOoOO00
  lisp_decap_stats [ iiiI1I1i1II ] . byte_count += O0OOooOo00OooOoO
  if 78 - 78: I11i
  III11I1 = 0 if msg . has_key ( iiiI1I1i1II ) == False else msg [ iiiI1I1i1II ] [ "seconds-last-packet" ]
  if 62 - 62: iIii1I11I1II1 . o0oOOo0O0Ooo . ooOoO0o % oO0o % O0 % oO0o
  lisp_decap_stats [ iiiI1I1i1II ] . last_increment = lisp_get_timestamp ( ) - III11I1
  if 51 - 51: Oo0Ooo / IiII - Oo0Ooo
 return
 if 71 - 71: I11i * I1ii11iIi11i * OOooOOo * o0oOOo0O0Ooo
 if 53 - 53: I1IiiI % I1IiiI
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
def lisp_process_punt ( punt_socket , lisp_send_sockets , lisp_ephem_port ) :
 IiI11i , oo0O00 = punt_socket . recvfrom ( 4000 )
 if 10 - 10: oO0o - I11i
 II1 = json . loads ( IiI11i )
 if ( type ( II1 ) != dict ) :
  lprint ( "Invalid punt message from {}, not in JSON format" . format ( oo0O00 ) )
  if 1 - 1: OoOoOO00 . I1IiiI * ooOoO0o . iII111i * Oo0Ooo
  return
  if 16 - 16: OoooooooOO % OoO0O00 - oO0o + ooOoO0o
 iI1II1i = bold ( "Punt" , False )
 lprint ( "{} message from '{}': '{}'" . format ( iI1II1i , oo0O00 , II1 ) )
 if 64 - 64: OoOoOO00 % I11i / I1IiiI . o0oOOo0O0Ooo + IiII + O0
 if ( II1 . has_key ( "type" ) == False ) :
  lprint ( "Punt IPC message has no 'type' key" )
  return
  if 32 - 32: Oo0Ooo % O0 * I1Ii111 . I11i - OoO0O00
  if 22 - 22: I1IiiI * I1IiiI / iIii1I11I1II1 . o0oOOo0O0Ooo - I1ii11iIi11i
  if 53 - 53: iIii1I11I1II1 * II111iiii
  if 52 - 52: I11i / iIii1I11I1II1
  if 69 - 69: ooOoO0o . i1IIi * I1IiiI . I1Ii111 % OoOoOO00 % OoooooooOO
 if ( II1 [ "type" ] == "statistics" ) :
  lisp_process_data_plane_stats ( II1 , lisp_send_sockets , lisp_ephem_port )
  return
  if 81 - 81: ooOoO0o - II111iiii
 if ( II1 [ "type" ] == "decap-statistics" ) :
  lisp_process_data_plane_decap_stats ( II1 , punt_socket )
  return
  if 26 - 26: I1IiiI
  if 20 - 20: oO0o * O0 - Ii1I + i11iIiiIii - OoOoOO00
  if 18 - 18: I1ii11iIi11i . iII111i
  if 31 - 31: I11i * o0oOOo0O0Ooo
  if 17 - 17: Ii1I * iIii1I11I1II1
 if ( II1 [ "type" ] == "restart" ) :
  lisp_process_data_plane_restart ( )
  return
  if 9 - 9: o0oOOo0O0Ooo - IiII
  if 78 - 78: i11iIiiIii . o0oOOo0O0Ooo
  if 72 - 72: Oo0Ooo % II111iiii + O0 * OoOoOO00 - OOooOOo + I1Ii111
  if 23 - 23: I1IiiI - O0 - iII111i . II111iiii / oO0o
  if 1 - 1: I11i . OOooOOo / oO0o % I11i * Oo0Ooo + Oo0Ooo
 if ( II1 [ "type" ] != "discovery" ) :
  lprint ( "Punt IPC message has wrong format" )
  return
  if 23 - 23: Ii1I % i1IIi - I1Ii111
 if ( II1 . has_key ( "interface" ) == False ) :
  lprint ( "Invalid punt message from {}, required keys missing" . format ( oo0O00 ) )
  if 95 - 95: OoOoOO00 - ooOoO0o . i1IIi . OoooooooOO
  return
  if 38 - 38: I1IiiI + I1ii11iIi11i - Oo0Ooo . i11iIiiIii - i1IIi
  if 11 - 11: IiII / I1IiiI . I1IiiI
  if 87 - 87: OoooooooOO * OoO0O00 * iIii1I11I1II1
  if 16 - 16: o0oOOo0O0Ooo * I11i + OoooooooOO + O0 / iIii1I11I1II1
  if 60 - 60: Ii1I % IiII * OoooooooOO * ooOoO0o * Ii1I
 oOOOo0o = II1 [ "interface" ]
 if ( oOOOo0o == "" ) :
  IIiI1i = int ( II1 [ "instance-id" ] )
  if ( IIiI1i == - 1 ) : return
 else :
  IIiI1i = lisp_get_interface_instance_id ( oOOOo0o , None )
  if 8 - 8: I1Ii111 - o0oOOo0O0Ooo
  if 52 - 52: OoOoOO00 % O0 + I1ii11iIi11i . i11iIiiIii
  if 59 - 59: Ii1I - I1Ii111 . ooOoO0o - OoOoOO00 + oO0o . OoO0O00
  if 88 - 88: OOooOOo - ooOoO0o * o0oOOo0O0Ooo . OoooooooOO
  if 3 - 3: I1Ii111
 i1iI = None
 if ( II1 . has_key ( "source-eid" ) ) :
  II1iIIii1I111 = II1 [ "source-eid" ]
  i1iI = lisp_address ( LISP_AFI_NONE , II1iIIii1I111 , 0 , IIiI1i )
  if ( i1iI . is_null ( ) ) :
   lprint ( "Invalid source-EID format '{}'" . format ( II1iIIii1I111 ) )
   return
   if 24 - 24: Ii1I + i11iIiiIii * I1Ii111 - OoOoOO00 / Ii1I - OoOoOO00
   if 69 - 69: I11i - I1IiiI . oO0o - OoooooooOO
 I1II11iii1I = None
 if ( II1 . has_key ( "dest-eid" ) ) :
  iIIIIiiI = II1 [ "dest-eid" ]
  I1II11iii1I = lisp_address ( LISP_AFI_NONE , iIIIIiiI , 0 , IIiI1i )
  if ( I1II11iii1I . is_null ( ) ) :
   lprint ( "Invalid dest-EID format '{}'" . format ( iIIIIiiI ) )
   return
   if 88 - 88: OoOoOO00 - IiII
   if 96 - 96: Ii1I % iIii1I11I1II1
   if 22 - 22: I1Ii111 - I1ii11iIi11i . Ii1I + o0oOOo0O0Ooo * OoooooooOO % iIii1I11I1II1
   if 87 - 87: OoO0O00 + o0oOOo0O0Ooo
   if 46 - 46: oO0o + OoOoOO00
   if 17 - 17: Ii1I . Oo0Ooo - oO0o % OOooOOo
   if 59 - 59: O0
   if 75 - 75: o0oOOo0O0Ooo / OoooooooOO . I1ii11iIi11i * oO0o * I11i / OoooooooOO
 if ( i1iI ) :
  I1i11II = green ( i1iI . print_address ( ) , False )
  o0O00o = lisp_db_for_lookups . lookup_cache ( i1iI , False )
  if ( o0O00o != None ) :
   if 17 - 17: Ii1I % I1ii11iIi11i + I11i
   if 80 - 80: i1IIi . OoooooooOO % OoooooooOO . oO0o / OOooOOo
   if 85 - 85: OOooOOo
   if 80 - 80: ooOoO0o % O0 % I1ii11iIi11i + Oo0Ooo
   if 82 - 82: oO0o / iIii1I11I1II1 % ooOoO0o . Ii1I / i1IIi - I1Ii111
   if ( o0O00o . dynamic_eid_configured ( ) ) :
    iiiii11I1 = lisp_allow_dynamic_eid ( oOOOo0o , i1iI )
    if ( iiiii11I1 != None and lisp_i_am_itr ) :
     lisp_itr_discover_eid ( o0O00o , i1iI , oOOOo0o , iiiii11I1 )
    else :
     lprint ( ( "Disallow dynamic source-EID {} " + "on interface {}" ) . format ( I1i11II , oOOOo0o ) )
     if 15 - 15: I11i - OOooOOo . II111iiii . iIii1I11I1II1
     if 93 - 93: I11i + o0oOOo0O0Ooo / OOooOOo + Ii1I % Oo0Ooo % I1ii11iIi11i
     if 72 - 72: IiII / II111iiii
  else :
   lprint ( "Punt from non-EID source {}" . format ( I1i11II ) )
   if 25 - 25: i1IIi + OoOoOO00 + oO0o + OoooooooOO
   if 21 - 21: I1ii11iIi11i
   if 60 - 60: i1IIi / OoO0O00 . Ii1I
   if 16 - 16: i11iIiiIii + OoOoOO00 % Oo0Ooo + I1ii11iIi11i * Ii1I / I1Ii111
   if 26 - 26: iII111i
   if 31 - 31: iII111i
 if ( I1II11iii1I ) :
  iIi11 = lisp_map_cache_lookup ( i1iI , I1II11iii1I )
  if ( iIi11 == None or iIi11 . action == LISP_SEND_MAP_REQUEST_ACTION ) :
   if 45 - 45: OoO0O00
   if 55 - 55: iIii1I11I1II1 % iIii1I11I1II1 + I11i - ooOoO0o + I1IiiI * O0
   if 47 - 47: ooOoO0o + iIii1I11I1II1 * OOooOOo . I1IiiI . o0oOOo0O0Ooo
   if 49 - 49: Oo0Ooo . OoOoOO00 * OOooOOo
   if 86 - 86: IiII * OOooOOo + Ii1I
   if ( lisp_rate_limit_map_request ( i1iI , I1II11iii1I ) ) : return
   lisp_send_map_request ( lisp_send_sockets , lisp_ephem_port ,
 i1iI , I1II11iii1I , None )
  else :
   I1i11II = green ( I1II11iii1I . print_address ( ) , False )
   lprint ( "Map-cache entry for {} already exists" . format ( I1i11II ) )
   if 62 - 62: I11i
   if 86 - 86: Oo0Ooo % II111iiii + I1Ii111 / I1ii11iIi11i
 return
 if 15 - 15: I1IiiI / I1Ii111 % iII111i
 if 57 - 57: I1Ii111 . iIii1I11I1II1 / Oo0Ooo / IiII / iII111i * OoOoOO00
 if 35 - 35: i1IIi + I1Ii111 - ooOoO0o . I1ii11iIi11i + Oo0Ooo
 if 43 - 43: oO0o . OoO0O00 * i1IIi
 if 1 - 1: ooOoO0o / i1IIi
 if 42 - 42: I1ii11iIi11i * ooOoO0o + OoOoOO00 % I1ii11iIi11i . IiII
 if 75 - 75: OoO0O00 * i1IIi - OOooOOo % II111iiii % OoO0O00 - OoOoOO00
def lisp_ipc_map_cache_entry ( mc , jdata ) :
 oo = lisp_write_ipc_map_cache ( True , mc , dont_send = True )
 jdata . append ( oo )
 return ( [ True , jdata ] )
 if 75 - 75: I11i * IiII * ooOoO0o
 if 31 - 31: Ii1I
 if 72 - 72: OOooOOo * Ii1I % OoO0O00
 if 72 - 72: OoOoOO00 + o0oOOo0O0Ooo - i1IIi - OoO0O00 % OoOoOO00
 if 42 - 42: oO0o / i1IIi . IiII
 if 12 - 12: i11iIiiIii . ooOoO0o
 if 80 - 80: O0 / iIii1I11I1II1 % iII111i * ooOoO0o / i11iIiiIii . OoOoOO00
 if 88 - 88: OoooooooOO . I1IiiI
def lisp_ipc_walk_map_cache ( mc , jdata ) :
 if 6 - 6: I1Ii111 - i11iIiiIii - oO0o
 if 7 - 7: i1IIi
 if 6 - 6: OoooooooOO - Oo0Ooo - I1ii11iIi11i
 if 34 - 34: iII111i + i11iIiiIii . IiII
 if ( mc . group . is_null ( ) ) : return ( lisp_ipc_map_cache_entry ( mc , jdata ) )
 if 54 - 54: Oo0Ooo + I11i - iII111i * ooOoO0o % i11iIiiIii . IiII
 if ( mc . source_cache == None ) : return ( [ True , jdata ] )
 if 29 - 29: II111iiii % i11iIiiIii % O0
 if 38 - 38: o0oOOo0O0Ooo * IiII
 if 51 - 51: OoooooooOO . Ii1I % OoooooooOO - I1IiiI + I1Ii111 % oO0o
 if 28 - 28: i11iIiiIii - I1IiiI * OoO0O00
 if 19 - 19: OoooooooOO
 jdata = mc . source_cache . walk_cache ( lisp_ipc_map_cache_entry , jdata )
 return ( [ True , jdata ] )
 if 34 - 34: OoOoOO00 . oO0o
 if 53 - 53: oO0o + OoooooooOO * ooOoO0o
 if 85 - 85: I1ii11iIi11i - o0oOOo0O0Ooo % o0oOOo0O0Ooo % iII111i * OoOoOO00
 if 50 - 50: I1Ii111 + I1Ii111 + I11i - OoOoOO00
 if 65 - 65: oO0o / I11i + iII111i - I1ii11iIi11i
 if 80 - 80: II111iiii . i11iIiiIii
 if 66 - 66: ooOoO0o * iII111i * OOooOOo % OoO0O00 / I1ii11iIi11i
def lisp_itr_discover_eid ( db , eid , input_interface , routed_interface ,
 lisp_ipc_listen_socket ) :
 oo0ooooO = eid . print_address ( )
 if ( db . dynamic_eids . has_key ( oo0ooooO ) ) :
  db . dynamic_eids [ oo0ooooO ] . last_packet = lisp_get_timestamp ( )
  return
  if 33 - 33: iIii1I11I1II1
  if 52 - 52: iIii1I11I1II1 + O0
  if 84 - 84: OOooOOo / iII111i . I1IiiI / O0 % OOooOOo . iII111i
  if 32 - 32: OoO0O00 + OoO0O00 % o0oOOo0O0Ooo / O0
  if 29 - 29: iII111i % I1Ii111
 O0OOOOoO00oo = lisp_dynamic_eid ( )
 O0OOOOoO00oo . dynamic_eid . copy_address ( eid )
 O0OOOOoO00oo . interface = routed_interface
 O0OOOOoO00oo . last_packet = lisp_get_timestamp ( )
 O0OOOOoO00oo . get_timeout ( routed_interface )
 db . dynamic_eids [ oo0ooooO ] = O0OOOOoO00oo
 if 95 - 95: OOooOOo - ooOoO0o % i1IIi / O0 % I11i . IiII
 oo0o0OoOo0Ooo = ""
 if ( input_interface != routed_interface ) :
  oo0o0OoOo0Ooo = ", routed-interface " + routed_interface
  if 55 - 55: IiII . ooOoO0o + i1IIi / ooOoO0o / I11i * I1IiiI
  if 59 - 59: II111iiii
 I1I1111I1i1iI = green ( oo0ooooO , False ) + bold ( " discovered" , False )
 lprint ( "Dynamic-EID {} on interface {}{}, timeout {}" . format ( I1I1111I1i1iI , input_interface , oo0o0OoOo0Ooo , O0OOOOoO00oo . timeout ) )
 if 71 - 71: iII111i . OoooooooOO - II111iiii - OoooooooOO % IiII / I1Ii111
 if 63 - 63: oO0o / O0 - II111iiii * IiII
 if 4 - 4: IiII * O0 % i11iIiiIii % OoOoOO00
 if 29 - 29: I1ii11iIi11i % ooOoO0o . OOooOOo . Ii1I . IiII
 if 69 - 69: o0oOOo0O0Ooo . i11iIiiIii * I11i + IiII / I11i
 OooOoO0OO00 = "learn%{}%{}" . format ( oo0ooooO , routed_interface )
 OooOoO0OO00 = lisp_command_ipc ( OooOoO0OO00 , "lisp-itr" )
 lisp_ipc ( OooOoO0OO00 , lisp_ipc_listen_socket , "lisp-etr" )
 return
 if 66 - 66: I1ii11iIi11i % I1Ii111 - i11iIiiIii % I11i
 if 62 - 62: i11iIiiIii % iIii1I11I1II1 / IiII . I1IiiI * O0
 if 17 - 17: I1ii11iIi11i - I1Ii111 % II111iiii + OOooOOo
 if 45 - 45: I1Ii111 + iII111i - iIii1I11I1II1 / Oo0Ooo
 if 92 - 92: iIii1I11I1II1 . OoO0O00 - I11i % I1ii11iIi11i / i11iIiiIii
 if 4 - 4: Oo0Ooo / I1IiiI * i1IIi . II111iiii
 if 13 - 13: i1IIi
 if 39 - 39: OOooOOo
 if 73 - 73: OoO0O00 . ooOoO0o
 if 13 - 13: o0oOOo0O0Ooo - OoOoOO00
 if 60 - 60: OoO0O00
 if 17 - 17: i11iIiiIii % i1IIi % I1IiiI % ooOoO0o + I1Ii111 + Oo0Ooo
 if 16 - 16: iII111i . I1ii11iIi11i . oO0o . OoO0O00
def lisp_retry_decap_keys ( addr_str , packet , iv , packet_icv ) :
 if ( lisp_search_decap_keys == False ) : return
 if 90 - 90: i1IIi . ooOoO0o + i11iIiiIii * OoooooooOO
 if 30 - 30: iII111i . OoO0O00 . i11iIiiIii / I1ii11iIi11i * Oo0Ooo
 if 38 - 38: IiII + II111iiii
 if 20 - 20: iII111i * I1IiiI * iII111i - o0oOOo0O0Ooo + i1IIi + ooOoO0o
 if ( addr_str . find ( ":" ) != - 1 ) : return
 if 49 - 49: II111iiii * I1IiiI / oO0o
 iiIo00ooO = lisp_crypto_keys_by_rloc_decap [ addr_str ]
 if 50 - 50: Ii1I + O0 . I1IiiI * Oo0Ooo
 for OOoOoO in lisp_crypto_keys_by_rloc_decap :
  if 15 - 15: Oo0Ooo
  if 53 - 53: OoooooooOO * O0 / iII111i * ooOoO0o % I1Ii111 + OOooOOo
  if 95 - 95: I1Ii111 % OoOoOO00 . IiII * iII111i % Ii1I
  if 18 - 18: iIii1I11I1II1 / ooOoO0o / I1Ii111 % oO0o * Ii1I
  if ( OOoOoO . find ( addr_str ) == - 1 ) : continue
  if 14 - 14: oO0o
  if 72 - 72: iIii1I11I1II1 / II111iiii * II111iiii + I1IiiI + iIii1I11I1II1 + oO0o
  if 46 - 46: I1Ii111
  if 23 - 23: Oo0Ooo * IiII - I1Ii111 . OoooooooOO
  if ( OOoOoO == addr_str ) : continue
  if 78 - 78: OoOoOO00 - iIii1I11I1II1
  if 20 - 20: i1IIi
  if 72 - 72: ooOoO0o . II111iiii
  if 32 - 32: I1Ii111 - oO0o + OoooooooOO . OoOoOO00 + i11iIiiIii / i1IIi
  oo = lisp_crypto_keys_by_rloc_decap [ OOoOoO ]
  if ( oo == iiIo00ooO ) : continue
  if 26 - 26: I1IiiI + OoooooooOO % OoOoOO00 . IiII - II111iiii . OoOoOO00
  if 37 - 37: OoO0O00 % O0 + OoOoOO00 * I11i . Ii1I * OoO0O00
  if 18 - 18: o0oOOo0O0Ooo / OOooOOo
  if 28 - 28: O0 / Ii1I - oO0o % I1ii11iIi11i % O0 . OoO0O00
  ooO0oOO0oOo00 = oo [ 1 ]
  if ( packet_icv != ooO0oOO0oOo00 . do_icv ( packet , iv ) ) :
   lprint ( "Test ICV with key {} failed" . format ( red ( OOoOoO , False ) ) )
   continue
   if 44 - 44: O0
   if 12 - 12: I1ii11iIi11i
  lprint ( "Changing decap crypto key to {}" . format ( red ( OOoOoO , False ) ) )
  lisp_crypto_keys_by_rloc_decap [ addr_str ] = oo
  if 80 - 80: oO0o / i1IIi * iIii1I11I1II1
 return
 if 38 - 38: Ii1I
 if 20 - 20: iIii1I11I1II1 + Oo0Ooo - Ii1I / i11iIiiIii . OoO0O00
 if 66 - 66: OoooooooOO - Ii1I / iII111i . I1IiiI + I1ii11iIi11i - I1Ii111
 if 36 - 36: I1Ii111 - OoO0O00 . I1ii11iIi11i * I1ii11iIi11i
 if 9 - 9: OOooOOo - oO0o - iIii1I11I1II1 * i11iIiiIii / I11i
 if 2 - 2: i1IIi % iII111i * ooOoO0o / OoOoOO00 + Oo0Ooo
 if 59 - 59: i11iIiiIii / I1IiiI * iII111i
 if 16 - 16: i11iIiiIii * II111iiii - ooOoO0o
def lisp_decent_pull_xtr_configured ( ) :
 return ( lisp_decent_modulus != 0 and lisp_decent_dns_suffix != None )
 if 80 - 80: iIii1I11I1II1 + iIii1I11I1II1 + I1Ii111 - IiII * iII111i - Ii1I
 if 89 - 89: O0 * ooOoO0o
 if 36 - 36: I1ii11iIi11i * II111iiii * iII111i + I1IiiI + OoO0O00 + oO0o
 if 28 - 28: Ii1I - i11iIiiIii . oO0o / II111iiii
 if 82 - 82: iII111i * iII111i . IiII * II111iiii
 if 17 - 17: OoooooooOO % I1Ii111 * I1Ii111 / II111iiii . OoOoOO00 * iII111i
 if 80 - 80: IiII % i11iIiiIii
 if 6 - 6: II111iiii + i11iIiiIii - Oo0Ooo % OOooOOo + Oo0Ooo
def lisp_is_decent_dns_suffix ( dns_name ) :
 if ( lisp_decent_dns_suffix == None ) : return ( False )
 IiiIi1II = dns_name . split ( "." )
 IiiIi1II = "." . join ( IiiIi1II [ 1 : : ] )
 return ( IiiIi1II == lisp_decent_dns_suffix )
 if 46 - 46: iII111i
 if 31 - 31: OoO0O00 + I1Ii111 / iIii1I11I1II1
 if 11 - 11: ooOoO0o - OoOoOO00
 if 19 - 19: O0 . OoOoOO00 - i1IIi . oO0o
 if 96 - 96: o0oOOo0O0Ooo % o0oOOo0O0Ooo - OoO0O00 * iIii1I11I1II1 + ooOoO0o - ooOoO0o
 if 4 - 4: OoO0O00 - OOooOOo
 if 21 - 21: I1Ii111 * i11iIiiIii
def lisp_get_decent_index ( eid ) :
 oo0ooooO = eid . print_prefix ( )
 oOOOOo = hashlib . sha256 ( oo0ooooO ) . hexdigest ( )
 OOOoO000 = int ( oOOOOo , 16 ) % lisp_decent_modulus
 return ( OOOoO000 )
 if 51 - 51: ooOoO0o + Ii1I * o0oOOo0O0Ooo * I1IiiI / oO0o + OoO0O00
 if 92 - 92: oO0o * o0oOOo0O0Ooo % ooOoO0o + OoOoOO00 * OoooooooOO * Oo0Ooo
 if 86 - 86: iII111i / OoooooooOO * I1Ii111 % I1IiiI + Ii1I
 if 16 - 16: OoO0O00
 if 41 - 41: i1IIi
 if 72 - 72: OoooooooOO / i11iIiiIii - O0 . OoOoOO00
 if 41 - 41: IiII + oO0o * iIii1I11I1II1 % oO0o + IiII
def lisp_get_decent_dns_name ( eid ) :
 OOOoO000 = lisp_get_decent_index ( eid )
 return ( str ( OOOoO000 ) + "." + lisp_decent_dns_suffix )
 if 64 - 64: I1ii11iIi11i % OoO0O00 + oO0o
 if 47 - 47: I1ii11iIi11i + Ii1I % I1Ii111 % OoO0O00 . IiII % i1IIi
 if 14 - 14: O0 / I1IiiI . I1ii11iIi11i
 if 47 - 47: I1Ii111 * ooOoO0o / iII111i . O0
 if 61 - 61: II111iiii . OoO0O00 * OoO0O00 % II111iiii % OOooOOo * OoOoOO00
 if 82 - 82: Ii1I
 if 83 - 83: I1IiiI
 if 22 - 22: IiII / Ii1I + I1Ii111 % iIii1I11I1II1
def lisp_get_decent_dns_name_from_str ( iid , eid_str ) :
 III1II1I1iI = lisp_address ( LISP_AFI_NONE , eid_str , 0 , iid )
 OOOoO000 = lisp_get_decent_index ( III1II1I1iI )
 return ( str ( OOOoO000 ) + "." + lisp_decent_dns_suffix )
 if 75 - 75: OoOoOO00 % OoOoOO00 % o0oOOo0O0Ooo % I1ii11iIi11i + IiII
 if 45 - 45: I11i - iIii1I11I1II1
 if 20 - 20: OoOoOO00
 if 84 - 84: OoOoOO00
 if 59 - 59: Ii1I / I1Ii111 + i11iIiiIii
 if 20 - 20: O0 / I1Ii111 - OOooOOo % iIii1I11I1II1
 if 89 - 89: O0 * OoOoOO00 . ooOoO0o
 if 11 - 11: iIii1I11I1II1 * OoO0O00 . I1IiiI * OoOoOO00 / II111iiii
 if 72 - 72: I11i
 if 7 - 7: i1IIi - o0oOOo0O0Ooo - I1IiiI
def lisp_trace_append ( packet , reason = None , ed = "encap" , lisp_socket = None ) :
 oOO0OO0O = 28 if packet . inner_version == 4 else 48
 OOOOoO0OO0OOO = packet . packet [ oOO0OO0O : : ]
 i11I1iII = lisp_trace ( )
 if ( i11I1iII . decode ( OOOOoO0OO0OOO ) == False ) :
  lprint ( "Could not decode JSON portion of a LISP-Trace packet" )
  return ( False )
  if 47 - 47: OOooOOo
  if 58 - 58: Ii1I . ooOoO0o / IiII
 i1Ii1iiI = "?" if packet . outer_dest . is_null ( ) else packet . outer_dest . print_address_no_iid ( )
 if 26 - 26: OOooOOo - OoOoOO00 + I1ii11iIi11i + OoO0O00 - OoOoOO00 / o0oOOo0O0Ooo
 if 76 - 76: I1ii11iIi11i / oO0o + Ii1I - O0
 if 95 - 95: OoOoOO00
 if 69 - 69: iII111i / Ii1I
 if 83 - 83: oO0o
 if 1 - 1: oO0o * iIii1I11I1II1 % iIii1I11I1II1 % iIii1I11I1II1 / oO0o + IiII
 if ( i1Ii1iiI != "?" and packet . encap_port != LISP_DATA_PORT ) :
  if ( ed == "encap" ) : i1Ii1iiI += ":{}" . format ( packet . encap_port )
  if 29 - 29: OoooooooOO
  if 55 - 55: O0 - o0oOOo0O0Ooo % I1ii11iIi11i * I11i * oO0o
  if 83 - 83: iIii1I11I1II1
  if 92 - 92: OoO0O00 - iII111i
  if 97 - 97: ooOoO0o / I11i . IiII + I1Ii111 . iIii1I11I1II1
 oo = { }
 oo [ "node" ] = "ITR" if lisp_i_am_itr else "ETR" if lisp_i_am_etr else "RTR" if lisp_i_am_rtr else "?"
 if 24 - 24: ooOoO0o - oO0o % OoOoOO00 * Oo0Ooo
 O00oOoO0o = packet . outer_source
 if ( O00oOoO0o . is_null ( ) ) : O00oOoO0o = lisp_myrlocs [ 0 ]
 oo [ "srloc" ] = O00oOoO0o . print_address_no_iid ( )
 if 75 - 75: I11i . iII111i + OoOoOO00 / oO0o . OOooOOo * I1Ii111
 if 45 - 45: OoO0O00 + O0
 if 20 - 20: I1IiiI . O0 / i1IIi + i11iIiiIii * IiII % OoOoOO00
 if 78 - 78: OoOoOO00 . OoooooooOO + iII111i / OoOoOO00 - I1Ii111
 if 52 - 52: iII111i - II111iiii % i1IIi / iII111i
 if ( oo [ "node" ] == "ITR" and packet . inner_sport != LISP_TRACE_PORT ) :
  oo [ "srloc" ] += ":{}" . format ( packet . inner_sport )
  if 14 - 14: oO0o / I1Ii111 / IiII - i1IIi * Ii1I
  if 90 - 90: ooOoO0o
 oo [ "hostname" ] = lisp_hostname
 OOoOoO = ed + "-timestamp"
 oo [ OOoOoO ] = lisp_get_timestamp ( )
 if 100 - 100: iII111i * i1IIi . iII111i / O0 / OoO0O00 - oO0o
 if 65 - 65: OoOoOO00 + ooOoO0o * OoO0O00 % OoooooooOO + OoooooooOO * OoooooooOO
 if 49 - 49: o0oOOo0O0Ooo + i1IIi / iII111i
 if 43 - 43: i1IIi . OoO0O00 + I1ii11iIi11i
 if 88 - 88: OoooooooOO / I11i % II111iiii % OOooOOo - I11i
 if 55 - 55: Oo0Ooo - OOooOOo - O0
 if ( i1Ii1iiI == "?" and oo [ "node" ] == "ETR" ) :
  o0O00o = lisp_db_for_lookups . lookup_cache ( packet . inner_dest , False )
  if ( o0O00o != None and len ( o0O00o . rloc_set ) >= 1 ) :
   i1Ii1iiI = o0O00o . rloc_set [ 0 ] . rloc . print_address_no_iid ( )
   if 40 - 40: OoOoOO00 - OOooOOo
   if 3 - 3: IiII % I11i * I1Ii111 + iIii1I11I1II1 . oO0o
 oo [ "drloc" ] = i1Ii1iiI
 if 35 - 35: II111iiii
 if 15 - 15: I11i * iIii1I11I1II1 + OOooOOo % IiII . o0oOOo0O0Ooo % Oo0Ooo
 if 96 - 96: O0
 if 15 - 15: i1IIi . iIii1I11I1II1
 if ( i1Ii1iiI == "?" and reason != None ) :
  oo [ "drloc" ] += " ({})" . format ( reason )
  if 3 - 3: II111iiii * i11iIiiIii * i1IIi - i1IIi
  if 11 - 11: I1IiiI % Ii1I * i11iIiiIii % OOooOOo + II111iiii
  if 61 - 61: I1Ii111 + I11i + I1IiiI
  if 48 - 48: I11i
  if 67 - 67: o0oOOo0O0Ooo
  if 36 - 36: IiII - I11i - Ii1I / OoOoOO00 % OoO0O00 * iIii1I11I1II1
 i1iI = packet . inner_source . print_address ( )
 I1II11iii1I = packet . inner_dest . print_address ( )
 if ( i11I1iII . packet_json == [ ] ) :
  OoIiiO0Oo0oo00O = { }
  OoIiiO0Oo0oo00O [ "seid" ] = i1iI
  OoIiiO0Oo0oo00O [ "deid" ] = I1II11iii1I
  OoIiiO0Oo0oo00O [ "paths" ] = [ ]
  i11I1iII . packet_json . append ( OoIiiO0Oo0oo00O )
  if 61 - 61: i11iIiiIii / Ii1I - OOooOOo . I1ii11iIi11i
  if 89 - 89: ooOoO0o % i11iIiiIii
  if 57 - 57: Oo0Ooo / ooOoO0o - O0 . ooOoO0o
  if 61 - 61: o0oOOo0O0Ooo / OoooooooOO . I1ii11iIi11i + Oo0Ooo
  if 75 - 75: Ii1I
  if 79 - 79: i1IIi . I1ii11iIi11i * o0oOOo0O0Ooo / I11i . I11i / ooOoO0o
 for OoIiiO0Oo0oo00O in i11I1iII . packet_json :
  if ( OoIiiO0Oo0oo00O [ "deid" ] != I1II11iii1I ) : continue
  OoIiiO0Oo0oo00O [ "paths" ] . append ( oo )
  break
  if 99 - 99: oO0o + I11i % i1IIi . iII111i
  if 58 - 58: Oo0Ooo % i11iIiiIii . Oo0Ooo / Oo0Ooo - I1IiiI . Ii1I
  if 65 - 65: OoO0O00
  if 16 - 16: IiII % I1IiiI % iIii1I11I1II1 . I1IiiI . I1ii11iIi11i - IiII
  if 6 - 6: I1Ii111 + OoO0O00 + O0 * OoOoOO00 . iIii1I11I1II1 . I1Ii111
  if 93 - 93: ooOoO0o % iIii1I11I1II1 + I1ii11iIi11i
  if 74 - 74: OoOoOO00 + I1ii11iIi11i
  if 82 - 82: II111iiii
 O0oI1I1IiIII1i = False
 if ( len ( i11I1iII . packet_json ) == 1 and i11I1iII . myeid ( packet . inner_dest ) ) :
  OoIiiO0Oo0oo00O = { }
  OoIiiO0Oo0oo00O [ "seid" ] = I1II11iii1I
  OoIiiO0Oo0oo00O [ "deid" ] = i1iI
  OoIiiO0Oo0oo00O [ "paths" ] = [ ]
  i11I1iII . packet_json . append ( OoIiiO0Oo0oo00O )
  O0oI1I1IiIII1i = True
  if 39 - 39: OOooOOo . iIii1I11I1II1 . iII111i
  if 95 - 95: iII111i . OOooOOo . OoooooooOO - oO0o % I11i / I11i
  if 47 - 47: iIii1I11I1II1 % II111iiii . II111iiii
  if 54 - 54: ooOoO0o * iII111i
  if 52 - 52: I11i + iII111i
  if 9 - 9: OoOoOO00 % II111iiii . I11i * Oo0Ooo
 i11I1iII . print_trace ( )
 OOOOoO0OO0OOO = i11I1iII . encode ( )
 if 53 - 53: II111iiii / i1IIi + OoooooooOO * O0
 if 62 - 62: IiII . O0
 if 87 - 87: I1ii11iIi11i / oO0o / IiII . OOooOOo
 if 91 - 91: OOooOOo % oO0o . OoOoOO00 . I1IiiI - OoOoOO00
 if 18 - 18: O0 - I1IiiI + i1IIi % i11iIiiIii
 if 97 - 97: iII111i * OoooooooOO + I1Ii111 + ooOoO0o - ooOoO0o
 if 63 - 63: o0oOOo0O0Ooo * OOooOOo + iIii1I11I1II1 + Oo0Ooo
 if 25 - 25: oO0o + IiII % o0oOOo0O0Ooo
 i1IiI11 = i11I1iII . packet_json [ 0 ] [ "paths" ] [ 0 ] [ "srloc" ]
 if ( i1Ii1iiI == "?" ) :
  lprint ( "LISP-Trace return to sender RLOC {}" . format ( i1IiI11 ) )
  i11I1iII . return_to_sender ( lisp_socket , i1IiI11 , OOOOoO0OO0OOO )
  return ( False )
  if 22 - 22: I1ii11iIi11i / I11i + iII111i % oO0o + I1ii11iIi11i
  if 65 - 65: Oo0Ooo
  if 66 - 66: iII111i . I1ii11iIi11i - Oo0Ooo
  if 84 - 84: IiII + Oo0Ooo / OoooooooOO
  if 20 - 20: IiII . ooOoO0o . I1ii11iIi11i * I1IiiI
  if 84 - 84: IiII / OOooOOo + I1IiiI . IiII % i11iIiiIii % I1IiiI
 iIiIiIii = i11I1iII . packet_length ( )
 if 41 - 41: OOooOOo * ooOoO0o
 if 47 - 47: OOooOOo + I1Ii111 . OoooooooOO * oO0o / I11i + Ii1I
 if 75 - 75: IiII
 if 66 - 66: o0oOOo0O0Ooo + oO0o
 II11II111IiII1iII = packet . packet [ 0 : oOO0OO0O ]
 OoOOOOo = struct . pack ( "HH" , socket . htons ( iIiIiIii ) , 0 )
 II11II111IiII1iII = II11II111IiII1iII [ 0 : oOO0OO0O - 4 ] + OoOOOOo
 if 43 - 43: iII111i * i11iIiiIii
 if 71 - 71: o0oOOo0O0Ooo % OoOoOO00 / iII111i - OoooooooOO - IiII
 if 54 - 54: Ii1I . I11i
 if 97 - 97: I1Ii111
 if 18 - 18: I1Ii111 - i1IIi
 if ( O0oI1I1IiIII1i ) :
  II11II111IiII1iII = II11II111IiII1iII [ 0 : 12 ] + II11II111IiII1iII [ 16 : 20 ] + II11II111IiII1iII [ 12 : 16 ] + II11II111IiII1iII [ 22 : 24 ] + II11II111IiII1iII [ 20 : 22 ] + II11II111IiII1iII [ 24 : : ]
  if 76 - 76: I1ii11iIi11i - I1Ii111 % IiII . Ii1I + OoooooooOO * OoOoOO00
  O0o0oo0oOO0oO = packet . inner_dest
  packet . inner_dest = packet . inner_source
  packet . inner_source = O0o0oo0oOO0oO
  if 47 - 47: Oo0Ooo
  if 81 - 81: I1Ii111 * o0oOOo0O0Ooo . oO0o % iIii1I11I1II1 - OoOoOO00 * OoO0O00
  if 32 - 32: I1Ii111 + Ii1I / Oo0Ooo - OoO0O00
  if 30 - 30: iIii1I11I1II1
  if 68 - 68: Oo0Ooo / I1Ii111 / i1IIi + iII111i
 oOO0OO0O = 2 if packet . inner_version == 4 else 4
 i11iIIiIII = 20 + iIiIiIii if packet . inner_version == 4 else 40 + iIiIiIii
 ooO0oooOo = struct . pack ( "H" , socket . htons ( i11iIIiIII ) )
 II11II111IiII1iII = II11II111IiII1iII [ 0 : oOO0OO0O ] + ooO0oooOo + II11II111IiII1iII [ oOO0OO0O + 2 : : ]
 if 50 - 50: OoOoOO00 - I1Ii111 / ooOoO0o . II111iiii . OOooOOo * OoO0O00
 if 75 - 75: iIii1I11I1II1 . I1IiiI
 if 22 - 22: OoOoOO00 . OoooooooOO * oO0o . O0
 if 14 - 14: II111iiii * I1IiiI * O0 % I11i
 if ( packet . inner_version == 4 ) :
  O0o = struct . pack ( "H" , 0 )
  II11II111IiII1iII = II11II111IiII1iII [ 0 : 10 ] + O0o + II11II111IiII1iII [ 12 : : ]
  ooO0oooOo = lisp_ip_checksum ( II11II111IiII1iII [ 0 : 20 ] )
  II11II111IiII1iII = ooO0oooOo + II11II111IiII1iII [ 20 : : ]
  if 48 - 48: i1IIi . o0oOOo0O0Ooo
  if 21 - 21: I1IiiI + Oo0Ooo / Ii1I * OoooooooOO
  if 71 - 71: o0oOOo0O0Ooo % ooOoO0o / oO0o - oO0o / OoooooooOO
  if 91 - 91: iIii1I11I1II1 - O0 * o0oOOo0O0Ooo * o0oOOo0O0Ooo . II111iiii
  if 69 - 69: II111iiii - Oo0Ooo + i1IIi . II111iiii + o0oOOo0O0Ooo
 packet . packet = II11II111IiII1iII + OOOOoO0OO0OOO
 return ( True )
 if 20 - 20: OoooooooOO - OoO0O00 * ooOoO0o * OoOoOO00 / OOooOOo
 if 64 - 64: O0 + iII111i / I11i * OoOoOO00 + o0oOOo0O0Ooo + I1Ii111
 if 16 - 16: I11i
# dd678faae9ac167bc83abf78e5cb2f3f0688d3a3
