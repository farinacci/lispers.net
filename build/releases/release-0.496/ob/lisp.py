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
 if 79 - 79: OoOoOO00 / ooOoO0o
 if 77 - 77: Oo0Ooo
 if 46 - 46: I1Ii111
 if 72 - 72: iII111i * OOooOOo
 if 67 - 67: i1IIi
 if 5 - 5: II111iiii . OoooooooOO
 if 57 - 57: I1IiiI
 if 35 - 35: OoooooooOO - I1Ii111 / OoO0O00
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
def lisp_udp_checksum ( source , dest , data ) :
 if 38 - 38: I1Ii111 + OoooooooOO . i1IIi
 if 19 - 19: iII111i - o0oOOo0O0Ooo - Ii1I - OoOoOO00 . iII111i . I1Ii111
 if 48 - 48: iII111i + IiII
 if 60 - 60: I11i + iII111i . IiII / i1IIi . iIii1I11I1II1
 i1I1iIi1IiI = lisp_address ( LISP_AFI_IPV6 , source , LISP_IPV6_HOST_MASK_LEN , 0 )
 i1i11ii1Ii = lisp_address ( LISP_AFI_IPV6 , dest , LISP_IPV6_HOST_MASK_LEN , 0 )
 i1 = socket . htonl ( len ( data ) )
 Oo0oOo000OoO0 = socket . htonl ( LISP_UDP_PROTOCOL )
 IIi = i1I1iIi1IiI . pack_address ( )
 IIi += i1i11ii1Ii . pack_address ( )
 IIi += struct . pack ( "II" , i1 , Oo0oOo000OoO0 )
 if 22 - 22: I1Ii111 / o0oOOo0O0Ooo
 if 98 - 98: i1IIi
 if 51 - 51: I1ii11iIi11i + ooOoO0o + Oo0Ooo / i1IIi + i1IIi
 if 12 - 12: iIii1I11I1II1 . Ii1I . I1ii11iIi11i % I1IiiI . II111iiii . oO0o
 IIi1ii1 = binascii . hexlify ( IIi + data )
 I1Ii = len ( IIi1ii1 ) % 4
 for oO in range ( 0 , I1Ii ) : IIi1ii1 += "0"
 if 44 - 44: iIii1I11I1II1 . I1ii11iIi11i + I1Ii111 . ooOoO0o
 if 7 - 7: I1ii11iIi11i + iIii1I11I1II1 * I11i * I11i / II111iiii - Ii1I
 if 65 - 65: oO0o + OoOoOO00 + II111iiii
 if 77 - 77: II111iiii
 iIiI1I1IIi11 = 0
 for oO in range ( 0 , len ( IIi1ii1 ) , 4 ) :
  iIiI1I1IIi11 += int ( IIi1ii1 [ oO : oO + 4 ] , 16 )
  if 50 - 50: O0 . O0 . ooOoO0o % Oo0Ooo
  if 68 - 68: oO0o
  if 10 - 10: Ii1I
  if 77 - 77: OOooOOo / II111iiii + IiII + ooOoO0o - i11iIiiIii
  if 44 - 44: I1IiiI + OoOoOO00 + I1ii11iIi11i . I1IiiI * OoOoOO00 % iIii1I11I1II1
 iIiI1I1IIi11 = ( iIiI1I1IIi11 >> 16 ) + ( iIiI1I1IIi11 & 0xffff )
 iIiI1I1IIi11 += iIiI1I1IIi11 >> 16
 iIiI1I1IIi11 = socket . htons ( ~ iIiI1I1IIi11 & 0xffff )
 if 72 - 72: OOooOOo . OOooOOo - I1ii11iIi11i
 if 48 - 48: Oo0Ooo - ooOoO0o + Oo0Ooo - I1IiiI * i11iIiiIii . iII111i
 if 35 - 35: IiII . O0 + Oo0Ooo + OOooOOo + i1IIi
 if 65 - 65: O0 * I1IiiI / I1IiiI . OoOoOO00
 iIiI1I1IIi11 = struct . pack ( "H" , iIiI1I1IIi11 )
 IIi1ii1 = data [ 0 : 6 ] + iIiI1I1IIi11 + data [ 8 : : ]
 return ( IIi1ii1 )
 if 87 - 87: II111iiii * I1ii11iIi11i % Oo0Ooo * Oo0Ooo
 if 58 - 58: OOooOOo . o0oOOo0O0Ooo + I1IiiI % Oo0Ooo - OoO0O00
 if 50 - 50: iII111i % II111iiii - ooOoO0o . i1IIi + O0 % iII111i
 if 10 - 10: iII111i . i1IIi + Ii1I
 if 66 - 66: OoO0O00 % o0oOOo0O0Ooo
 if 21 - 21: OoOoOO00 - OoooooooOO % i11iIiiIii
 if 71 - 71: i1IIi - I11i * I1Ii111 + oO0o - OoO0O00 % I1ii11iIi11i
def lisp_get_interface_address ( device ) :
 if 63 - 63: iIii1I11I1II1 + OOooOOo . OoO0O00 / I1IiiI
 if 84 - 84: i1IIi
 if 42 - 42: II111iiii - OoO0O00 - OoooooooOO . iII111i / OoOoOO00
 if 56 - 56: i11iIiiIii - iIii1I11I1II1 . II111iiii
 if ( device not in netifaces . interfaces ( ) ) : return ( None )
 if 81 - 81: IiII / OoOoOO00 * IiII . O0
 if 61 - 61: OoO0O00 * OOooOOo + I1Ii111 . iIii1I11I1II1 % I11i . I1Ii111
 if 53 - 53: I1Ii111 * IiII / iIii1I11I1II1 / I1IiiI % I1ii11iIi11i
 if 39 - 39: OoO0O00 / OoooooooOO . OoO0O00 * I1ii11iIi11i / OoOoOO00
 II111 = netifaces . ifaddresses ( device )
 if ( II111 . has_key ( netifaces . AF_INET ) == False ) : return ( None )
 if 94 - 94: iII111i % ooOoO0o . oO0o
 if 85 - 85: OOooOOo * i1IIi % I1IiiI - ooOoO0o
 if 37 - 37: IiII . Oo0Ooo * Oo0Ooo * II111iiii * O0
 if 83 - 83: IiII / I1Ii111
 OOo000OO000 = lisp_address ( LISP_AFI_IPV4 , "" , 32 , 0 )
 if 83 - 83: o0oOOo0O0Ooo % oO0o + I11i % i11iIiiIii + O0
 for I1Iii1I in II111 [ netifaces . AF_INET ] :
  OoOOoooO000 = I1Iii1I [ "addr" ]
  OOo000OO000 . store_address ( OoOOoooO000 )
  return ( OOo000OO000 )
  if 85 - 85: I1IiiI % I11i + OOooOOo / Ii1I % OoooooooOO
 return ( None )
 if 42 - 42: I1Ii111 * IiII
 if 23 - 23: oO0o * I1Ii111 - OoooooooOO * OoooooooOO % OoO0O00 + II111iiii
 if 9 - 9: iIii1I11I1II1 * OoO0O00 % I1Ii111
 if 46 - 46: I11i . IiII / II111iiii % iIii1I11I1II1 + IiII
 if 61 - 61: OOooOOo / OoO0O00 + II111iiii . oO0o / Oo0Ooo * OOooOOo
 if 46 - 46: iIii1I11I1II1
 if 33 - 33: I11i % I11i % O0 / I1IiiI . i1IIi
 if 91 - 91: ooOoO0o * I11i - II111iiii . I1IiiI - Oo0Ooo + ooOoO0o
 if 56 - 56: o0oOOo0O0Ooo / IiII * I1IiiI . o0oOOo0O0Ooo
 if 15 - 15: i11iIiiIii
 if 13 - 13: I11i * II111iiii * oO0o * II111iiii % IiII / I1IiiI
 if 100 - 100: IiII . Ii1I - iIii1I11I1II1 . i11iIiiIii / II111iiii
def lisp_get_input_interface ( packet ) :
 o0oO0OO00oo0o = lisp_format_packet ( packet [ 0 : 12 ] ) . replace ( " " , "" )
 I1II1 = o0oO0OO00oo0o [ 0 : 12 ]
 Oo000o = o0oO0OO00oo0o [ 12 : : ]
 if 69 - 69: I1ii11iIi11i + iII111i * O0 . OOooOOo % OoOoOO00
 try : O0O000O = lisp_mymacs . has_key ( Oo000o )
 except : O0O000O = False
 if 22 - 22: oO0o
 if ( lisp_mymacs . has_key ( I1II1 ) ) : return ( lisp_mymacs [ I1II1 ] , Oo000o , I1II1 , O0O000O )
 if ( O0O000O ) : return ( lisp_mymacs [ Oo000o ] , Oo000o , I1II1 , O0O000O )
 return ( [ "?" ] , Oo000o , I1II1 , O0O000O )
 if 33 - 33: O0
 if 96 - 96: OoooooooOO + IiII * O0
 if 86 - 86: Ii1I
 if 29 - 29: iIii1I11I1II1 - OoO0O00 + I1IiiI % iIii1I11I1II1 % OOooOOo
 if 84 - 84: IiII + I1ii11iIi11i + Ii1I + iII111i
 if 62 - 62: i11iIiiIii + OoOoOO00 + i1IIi
 if 69 - 69: OoOoOO00
 if 63 - 63: OoO0O00 / OoOoOO00 * iIii1I11I1II1 . I1Ii111
def lisp_get_local_interfaces ( ) :
 for Ooooo in netifaces . interfaces ( ) :
  iIiiiIiIi = lisp_interface ( Ooooo )
  iIiiiIiIi . add_interface ( )
  if 19 - 19: IiII . I1ii11iIi11i / OoOoOO00
 return
 if 68 - 68: ooOoO0o / OoooooooOO * I11i / oO0o
 if 88 - 88: o0oOOo0O0Ooo
 if 1 - 1: OoooooooOO
 if 48 - 48: ooOoO0o * OoOoOO00 - ooOoO0o - OOooOOo + OOooOOo
 if 40 - 40: i11iIiiIii . iIii1I11I1II1
 if 2 - 2: i1IIi * oO0o - oO0o + OoooooooOO % OoOoOO00 / OoOoOO00
 if 3 - 3: OoooooooOO
def lisp_get_loopback_address ( ) :
 for I1Iii1I in netifaces . ifaddresses ( "lo" ) [ netifaces . AF_INET ] :
  if ( I1Iii1I [ "peer" ] == "127.0.0.1" ) : continue
  return ( I1Iii1I [ "peer" ] )
  if 71 - 71: IiII + i1IIi - iII111i - i11iIiiIii . I11i - ooOoO0o
 return ( None )
 if 85 - 85: I1ii11iIi11i - OoOoOO00 / I1ii11iIi11i + OOooOOo - iII111i
 if 49 - 49: OoO0O00 - O0 / OoO0O00 * OoOoOO00 + I1Ii111
 if 35 - 35: II111iiii . I1IiiI / i1IIi / I1IiiI * oO0o
 if 85 - 85: II111iiii . ooOoO0o % OOooOOo % I11i
 if 80 - 80: oO0o * I11i / iIii1I11I1II1 % oO0o / iIii1I11I1II1
 if 42 - 42: i1IIi / i11iIiiIii . Oo0Ooo * iII111i . i11iIiiIii * O0
 if 44 - 44: i1IIi . I1IiiI / i11iIiiIii + IiII
 if 27 - 27: OOooOOo
def lisp_get_local_macs ( ) :
 for Ooooo in netifaces . interfaces ( ) :
  if 52 - 52: I1Ii111 % OoOoOO00 + iIii1I11I1II1 * oO0o . Ii1I
  if 95 - 95: iIii1I11I1II1 . IiII - OoooooooOO * OoO0O00 / o0oOOo0O0Ooo
  if 74 - 74: oO0o
  if 34 - 34: iII111i
  if 44 - 44: i1IIi % I1IiiI % o0oOOo0O0Ooo
  i1i11ii1Ii = Ooooo . replace ( ":" , "" )
  i1i11ii1Ii = Ooooo . replace ( "-" , "" )
  if ( i1i11ii1Ii . isalnum ( ) == False ) : continue
  if 9 - 9: Oo0Ooo % OoooooooOO - Ii1I
  if 43 - 43: OoO0O00 % OoO0O00
  if 46 - 46: Oo0Ooo % iIii1I11I1II1 . iII111i . O0 * ooOoO0o / OoooooooOO
  if 7 - 7: oO0o - O0 * I11i - o0oOOo0O0Ooo - II111iiii
  if 41 - 41: I1IiiI - I1Ii111 % II111iiii . I1Ii111 - I11i
  try :
   i1I111Ii = netifaces . ifaddresses ( Ooooo )
  except :
   continue
   if 31 - 31: I1IiiI
  if ( i1I111Ii . has_key ( netifaces . AF_LINK ) == False ) : continue
  o0O0oO0 = i1I111Ii [ netifaces . AF_LINK ] [ 0 ] [ "addr" ]
  o0O0oO0 = o0O0oO0 . replace ( ":" , "" )
  if 73 - 73: ooOoO0o . O0 / o0oOOo0O0Ooo - OoooooooOO % i11iIiiIii
  if 80 - 80: Ii1I / ooOoO0o % O0 . Oo0Ooo
  if 63 - 63: OOooOOo . II111iiii . I11i
  if 46 - 46: ooOoO0o % IiII - o0oOOo0O0Ooo - Oo0Ooo - Ii1I / I11i
  if 68 - 68: i1IIi - I1ii11iIi11i / Oo0Ooo % I11i . iII111i
  if ( len ( o0O0oO0 ) < 12 ) : continue
  if 9 - 9: IiII
  if ( lisp_mymacs . has_key ( o0O0oO0 ) == False ) : lisp_mymacs [ o0O0oO0 ] = [ ]
  lisp_mymacs [ o0O0oO0 ] . append ( Ooooo )
  if 48 - 48: o0oOOo0O0Ooo + o0oOOo0O0Ooo - Oo0Ooo
  if 27 - 27: OoO0O00 + OoOoOO00 * ooOoO0o
 lprint ( "Local MACs are: {}" . format ( lisp_mymacs ) )
 return
 if 83 - 83: iIii1I11I1II1
 if 72 - 72: I11i
 if 87 - 87: i1IIi
 if 48 - 48: Oo0Ooo * oO0o * iIii1I11I1II1 + i11iIiiIii - OoooooooOO
 if 38 - 38: OoOoOO00 / iIii1I11I1II1 % i11iIiiIii - IiII * iII111i / OoOoOO00
 if 13 - 13: OoO0O00 * I1ii11iIi11i - I1Ii111
 if 79 - 79: oO0o % o0oOOo0O0Ooo % OoOoOO00
 if 45 - 45: I1IiiI * OOooOOo % OoO0O00
def lisp_get_local_rloc ( ) :
 i111I11I = commands . getoutput ( "netstat -rn | egrep 'default|0.0.0.0'" )
 if ( i111I11I == "" ) : return ( lisp_address ( LISP_AFI_IPV4 , "" , 32 , 0 ) )
 if 80 - 80: iIii1I11I1II1 - OoooooooOO - I1ii11iIi11i - I1ii11iIi11i . OoooooooOO
 if 48 - 48: I1Ii111 . i11iIiiIii / i1IIi % IiII % iII111i + oO0o
 if 41 - 41: IiII
 if 3 - 3: IiII + II111iiii / iIii1I11I1II1
 i111I11I = i111I11I . split ( "\n" ) [ 0 ]
 Ooooo = i111I11I . split ( ) [ - 1 ]
 if 10 - 10: II111iiii . O0
 I1Iii1I = ""
 iIii = lisp_is_macos ( )
 if ( iIii ) :
  i111I11I = commands . getoutput ( "ifconfig {} | egrep 'inet '" . format ( Ooooo ) )
  if ( i111I11I == "" ) : return ( lisp_address ( LISP_AFI_IPV4 , "" , 32 , 0 ) )
 else :
  iIiI1 = 'ip addr show | egrep "inet " | egrep "{}"' . format ( Ooooo )
  i111I11I = commands . getoutput ( iIiI1 )
  if ( i111I11I == "" ) :
   iIiI1 = 'ip addr show | egrep "inet " | egrep "global lo"'
   i111I11I = commands . getoutput ( iIiI1 )
   if 13 - 13: I1ii11iIi11i % OoOoOO00
  if ( i111I11I == "" ) : return ( lisp_address ( LISP_AFI_IPV4 , "" , 32 , 0 ) )
  if 76 - 76: O0 . OoO0O00 + OoOoOO00
  if 41 - 41: II111iiii * ooOoO0o
  if 68 - 68: Ii1I - I1IiiI
  if 41 - 41: oO0o
  if 21 - 21: ooOoO0o + o0oOOo0O0Ooo % I1Ii111 + i11iIiiIii + iII111i + II111iiii
  if 98 - 98: I1Ii111
 I1Iii1I = ""
 i111I11I = i111I11I . split ( "\n" )
 if 49 - 49: Oo0Ooo * oO0o + o0oOOo0O0Ooo - i11iIiiIii
 for OOooO in i111I11I :
  OOOO0o = OOooO . split ( ) [ 1 ]
  if ( iIii == False ) : OOOO0o = OOOO0o . split ( "/" ) [ 0 ]
  i1i1Ii1Ii = lisp_address ( LISP_AFI_IPV4 , OOOO0o , 32 , 0 )
  return ( i1i1Ii1Ii )
  if 99 - 99: I1ii11iIi11i + OOooOOo . oO0o
 return ( lisp_address ( LISP_AFI_IPV4 , I1Iii1I , 32 , 0 ) )
 if 1 - 1: OOooOOo * IiII + I11i
 if 77 - 77: oO0o % i11iIiiIii . OOooOOo % OOooOOo
 if 36 - 36: Oo0Ooo % Ii1I / i11iIiiIii % I1Ii111 + OoO0O00
 if 23 - 23: II111iiii
 if 93 - 93: oO0o . I11i / i1IIi
 if 50 - 50: I1Ii111 / i1IIi % OoooooooOO
 if 83 - 83: I1ii11iIi11i * I1ii11iIi11i + OOooOOo
 if 57 - 57: O0 - O0 . I1ii11iIi11i / o0oOOo0O0Ooo / Ii1I
 if 20 - 20: OOooOOo * II111iiii - OoOoOO00 - oO0o * I1Ii111
 if 6 - 6: ooOoO0o + OOooOOo / Oo0Ooo + IiII % II111iiii / OoO0O00
 if 45 - 45: OoooooooOO
def lisp_get_local_addresses ( ) :
 global lisp_myrlocs
 if 9 - 9: I11i . OoO0O00 * i1IIi . OoooooooOO
 if 32 - 32: OoOoOO00 . I1ii11iIi11i % I1IiiI - II111iiii
 if 11 - 11: O0 + I1IiiI
 if 80 - 80: oO0o % oO0o % O0 - i11iIiiIii . iII111i / O0
 if 13 - 13: I1IiiI + O0 - I1ii11iIi11i % Oo0Ooo / Ii1I . i1IIi
 if 60 - 60: Oo0Ooo . IiII % I1IiiI - I1Ii111
 if 79 - 79: OoooooooOO / I1ii11iIi11i . O0
 if 79 - 79: oO0o - II111iiii
 if 43 - 43: i1IIi + O0 % OoO0O00 / Ii1I * I1IiiI
 if 89 - 89: I1IiiI . Oo0Ooo + I1ii11iIi11i . O0 % o0oOOo0O0Ooo
 Ooo00O0 = None
 OOOoO000 = 1
 OoO0OOoO0 = os . getenv ( "LISP_ADDR_SELECT" )
 if ( OoO0OOoO0 != None and OoO0OOoO0 != "" ) :
  OoO0OOoO0 = OoO0OOoO0 . split ( ":" )
  if ( len ( OoO0OOoO0 ) == 2 ) :
   Ooo00O0 = OoO0OOoO0 [ 0 ]
   OOOoO000 = OoO0OOoO0 [ 1 ]
  else :
   if ( OoO0OOoO0 [ 0 ] . isdigit ( ) ) :
    OOOoO000 = OoO0OOoO0 [ 0 ]
   else :
    Ooo00O0 = OoO0OOoO0 [ 0 ]
    if 5 - 5: i1IIi . i1IIi
    if 63 - 63: ooOoO0o % I1IiiI
  OOOoO000 = 1 if ( OOOoO000 == "" ) else int ( OOOoO000 )
  if 75 - 75: ooOoO0o / Oo0Ooo
  if 8 - 8: iIii1I11I1II1
 i1iiii11I = [ None , None , None ]
 o0oO0o0oo0O0 = lisp_address ( LISP_AFI_IPV4 , "" , 32 , 0 )
 O0oo00oOOO0o = lisp_address ( LISP_AFI_IPV6 , "" , 128 , 0 )
 II1i = None
 if 6 - 6: IiII * IiII * O0 / OOooOOo + O0
 for Ooooo in netifaces . interfaces ( ) :
  if ( Ooo00O0 != None and Ooo00O0 != Ooooo ) : continue
  II111 = netifaces . ifaddresses ( Ooooo )
  if ( II111 == { } ) : continue
  if 51 - 51: o0oOOo0O0Ooo - OoOoOO00 + Oo0Ooo / I11i % OoOoOO00
  if 27 - 27: I1ii11iIi11i * i1IIi . i1IIi
  if 87 - 87: IiII / I1Ii111 - Oo0Ooo
  if 56 - 56: O0
  II1i = lisp_get_interface_instance_id ( Ooooo , None )
  if 45 - 45: OoOoOO00 - OoO0O00 - OoOoOO00
  if 41 - 41: Oo0Ooo / i1IIi / Oo0Ooo - iII111i . o0oOOo0O0Ooo
  if 65 - 65: O0 * i11iIiiIii . OoooooooOO / I1IiiI / iII111i
  if 69 - 69: ooOoO0o % ooOoO0o
  if ( II111 . has_key ( netifaces . AF_INET ) ) :
   II11iIi = II111 [ netifaces . AF_INET ]
   Ooo00OOOOOO0 = 0
   for I1Iii1I in II11iIi :
    o0oO0o0oo0O0 . store_address ( I1Iii1I [ "addr" ] )
    if ( o0oO0o0oo0O0 . is_ipv4_loopback ( ) ) : continue
    if ( o0oO0o0oo0O0 . is_ipv4_link_local ( ) ) : continue
    if ( o0oO0o0oo0O0 . address == 0 ) : continue
    Ooo00OOOOOO0 += 1
    o0oO0o0oo0O0 . instance_id = II1i
    if ( Ooo00O0 == None and
 lisp_db_for_lookups . lookup_cache ( o0oO0o0oo0O0 , False ) ) : continue
    i1iiii11I [ 0 ] = o0oO0o0oo0O0
    if ( Ooo00OOOOOO0 == OOOoO000 ) : break
    if 15 - 15: I11i / o0oOOo0O0Ooo + Ii1I
    if 76 - 76: Ii1I + OoooooooOO / OOooOOo % OoO0O00 / I1ii11iIi11i
  if ( II111 . has_key ( netifaces . AF_INET6 ) ) :
   iiO0O0o0oO0O00 = II111 [ netifaces . AF_INET6 ]
   Ooo00OOOOOO0 = 0
   for I1Iii1I in iiO0O0o0oO0O00 :
    OoOOoooO000 = I1Iii1I [ "addr" ]
    O0oo00oOOO0o . store_address ( OoOOoooO000 )
    if ( O0oo00oOOO0o . is_ipv6_string_link_local ( OoOOoooO000 ) ) : continue
    if ( O0oo00oOOO0o . is_ipv6_loopback ( ) ) : continue
    Ooo00OOOOOO0 += 1
    O0oo00oOOO0o . instance_id = II1i
    if ( Ooo00O0 == None and
 lisp_db_for_lookups . lookup_cache ( O0oo00oOOO0o , False ) ) : continue
    i1iiii11I [ 1 ] = O0oo00oOOO0o
    if ( Ooo00OOOOOO0 == OOOoO000 ) : break
    if 38 - 38: I1Ii111 . iII111i . I1IiiI * OoO0O00
    if 69 - 69: o0oOOo0O0Ooo % i11iIiiIii / Ii1I
    if 93 - 93: ooOoO0o
    if 34 - 34: oO0o - ooOoO0o * Oo0Ooo / o0oOOo0O0Ooo
    if 19 - 19: I1ii11iIi11i
    if 46 - 46: iIii1I11I1II1 . i11iIiiIii - OoOoOO00 % O0 / II111iiii * i1IIi
  if ( i1iiii11I [ 0 ] == None ) : continue
  if 66 - 66: O0
  i1iiii11I [ 2 ] = Ooooo
  break
  if 52 - 52: OoO0O00 * OoooooooOO
  if 12 - 12: O0 + IiII * i1IIi . OoO0O00
 o0OO0oooo = i1iiii11I [ 0 ] . print_address_no_iid ( ) if i1iiii11I [ 0 ] else "none"
 I11II1i1 = i1iiii11I [ 1 ] . print_address_no_iid ( ) if i1iiii11I [ 1 ] else "none"
 Ooooo = i1iiii11I [ 2 ] if i1iiii11I [ 2 ] else "none"
 if 46 - 46: II111iiii % iII111i - i1IIi / I11i * OoOoOO00
 Ooo00O0 = " (user selected)" if Ooo00O0 != None else ""
 if 92 - 92: Oo0Ooo - I1Ii111
 o0OO0oooo = red ( o0OO0oooo , False )
 I11II1i1 = red ( I11II1i1 , False )
 Ooooo = bold ( Ooooo , False )
 lprint ( "Local addresses are IPv4: {}, IPv6: {} from device {}{}, iid {}" . format ( o0OO0oooo , I11II1i1 , Ooooo , Ooo00O0 , II1i ) )
 if 24 - 24: oO0o / I1Ii111 / I11i % OoOoOO00 / I1ii11iIi11i * ooOoO0o
 if 8 - 8: Ii1I
 lisp_myrlocs = i1iiii11I
 return ( ( i1iiii11I [ 0 ] != None ) )
 if 33 - 33: o0oOOo0O0Ooo / O0 + OOooOOo
 if 75 - 75: IiII % i11iIiiIii + iIii1I11I1II1
 if 92 - 92: OoOoOO00 % O0
 if 55 - 55: iIii1I11I1II1 * iII111i
 if 85 - 85: iIii1I11I1II1 . II111iiii
 if 54 - 54: Ii1I . OoooooooOO % Oo0Ooo
 if 22 - 22: OOooOOo
 if 22 - 22: iII111i * I11i - Oo0Ooo * O0 / i11iIiiIii
 if 78 - 78: Oo0Ooo * O0 / ooOoO0o + OoooooooOO + OOooOOo
def lisp_get_all_addresses ( ) :
 I1iiIiiIiiI = [ ]
 for iIiiiIiIi in netifaces . interfaces ( ) :
  try : oOoO = netifaces . ifaddresses ( iIiiiIiIi )
  except : continue
  if 32 - 32: O0 + oO0o % Oo0Ooo
  if ( oOoO . has_key ( netifaces . AF_INET ) ) :
   for I1Iii1I in oOoO [ netifaces . AF_INET ] :
    OOOO0o = I1Iii1I [ "addr" ]
    if ( OOOO0o . find ( "127.0.0.1" ) != - 1 ) : continue
    I1iiIiiIiiI . append ( OOOO0o )
    if 7 - 7: I1ii11iIi11i / ooOoO0o
    if 11 - 11: IiII * ooOoO0o / ooOoO0o - OOooOOo
  if ( oOoO . has_key ( netifaces . AF_INET6 ) ) :
   for I1Iii1I in oOoO [ netifaces . AF_INET6 ] :
    OOOO0o = I1Iii1I [ "addr" ]
    if ( OOOO0o == "::1" ) : continue
    if ( OOOO0o [ 0 : 5 ] == "fe80:" ) : continue
    I1iiIiiIiiI . append ( OOOO0o )
    if 68 - 68: I1IiiI % IiII - IiII / I1IiiI + I1ii11iIi11i - Oo0Ooo
    if 65 - 65: ooOoO0o - i1IIi
    if 62 - 62: I11i / oO0o % Oo0Ooo . OoooooooOO / i11iIiiIii / I1Ii111
 return ( I1iiIiiIiiI )
 if 60 - 60: I1IiiI % oO0o / o0oOOo0O0Ooo % oO0o * i11iIiiIii / iII111i
 if 34 - 34: I1Ii111 - OOooOOo
 if 25 - 25: oO0o % I1IiiI + i11iIiiIii + O0 * OoooooooOO
 if 64 - 64: i1IIi
 if 10 - 10: I1Ii111 % O0 / I1IiiI % I11i
 if 25 - 25: II111iiii / OoO0O00
 if 64 - 64: O0 % ooOoO0o
 if 40 - 40: o0oOOo0O0Ooo + I11i
def lisp_get_all_multicast_rles ( ) :
 OoO000Oo0oO = [ ]
 i111I11I = commands . getoutput ( 'egrep "rle-address =" ./lisp.config' )
 if ( i111I11I == "" ) : return ( OoO000Oo0oO )
 if 46 - 46: O0 - OoOoOO00 . OoooooooOO
 i1I111II = i111I11I . split ( "\n" )
 for OOooO in i1I111II :
  if ( OOooO [ 0 ] == "#" ) : continue
  Oo0OOo = OOooO . split ( "rle-address = " ) [ 1 ]
  i1II11I11ii1 = int ( Oo0OOo . split ( "." ) [ 0 ] )
  if ( i1II11I11ii1 >= 224 and i1II11I11ii1 < 240 ) : OoO000Oo0oO . append ( Oo0OOo )
  if 64 - 64: oO0o % OoOoOO00 / II111iiii % ooOoO0o - iII111i
 return ( OoO000Oo0oO )
 if 2 - 2: I1Ii111 - I1ii11iIi11i + o0oOOo0O0Ooo * OoO0O00 / iII111i
 if 26 - 26: OOooOOo * Oo0Ooo
 if 31 - 31: I11i * oO0o . Ii1I
 if 35 - 35: I11i
 if 94 - 94: ooOoO0o / i11iIiiIii % O0
 if 70 - 70: I11i - Oo0Ooo / OoooooooOO % OoooooooOO
 if 95 - 95: OoooooooOO % OoooooooOO . Ii1I
 if 26 - 26: oO0o + IiII - II111iiii . II111iiii + I1ii11iIi11i + OoOoOO00
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
  if 68 - 68: O0
  if 76 - 76: I1ii11iIi11i
 def encode ( self , nonce ) :
  if 99 - 99: o0oOOo0O0Ooo
  if 1 - 1: Ii1I * OoOoOO00 * OoO0O00 + Oo0Ooo
  if 90 - 90: I1Ii111 % Oo0Ooo - Oo0Ooo . iIii1I11I1II1 / OOooOOo + I11i
  if 89 - 89: oO0o
  if 87 - 87: iII111i % Oo0Ooo
  if ( self . outer_source . is_null ( ) ) : return ( None )
  if 62 - 62: OoO0O00 + ooOoO0o / iII111i * i11iIiiIii
  if 37 - 37: iII111i
  if 33 - 33: OoO0O00 - O0 - OoO0O00
  if 94 - 94: IiII * I11i * OoooooooOO / o0oOOo0O0Ooo . IiII - o0oOOo0O0Ooo
  if 13 - 13: OOooOOo / IiII - OoO0O00 / OOooOOo . i1IIi
  if 22 - 22: O0 - I11i + I1Ii111 . Ii1I * i1IIi
  if ( nonce == None ) :
   self . lisp_header . nonce ( lisp_get_data_nonce ( ) )
  elif ( self . lisp_header . is_request_nonce ( nonce ) ) :
   self . lisp_header . request_nonce ( nonce )
  else :
   self . lisp_header . nonce ( nonce )
   if 26 - 26: iIii1I11I1II1 * o0oOOo0O0Ooo . I11i
  self . lisp_header . instance_id ( self . inner_dest . instance_id )
  if 10 - 10: I1Ii111 * oO0o % Oo0Ooo - I11i % Oo0Ooo
  if 65 - 65: iII111i * iIii1I11I1II1 / O0 . I11i
  if 94 - 94: Oo0Ooo . ooOoO0o * i11iIiiIii - o0oOOo0O0Ooo . iII111i
  if 98 - 98: OOooOOo + Ii1I
  if 52 - 52: Oo0Ooo / OoOoOO00 - I1Ii111 . iII111i
  if 50 - 50: iIii1I11I1II1 - iII111i - I11i
  self . lisp_header . key_id ( 0 )
  oo00O0O0O0o0o = ( self . lisp_header . get_instance_id ( ) == 0xffffff )
  if ( lisp_data_plane_security and oo00O0O0O0o0o == False ) :
   OoOOoooO000 = self . outer_dest . print_address_no_iid ( ) + ":" + str ( self . encap_port )
   if 74 - 74: O0 % OoooooooOO * Oo0Ooo + OOooOOo * iII111i
   if ( lisp_crypto_keys_by_rloc_encap . has_key ( OoOOoooO000 ) ) :
    O000OO = lisp_crypto_keys_by_rloc_encap [ OoOOoooO000 ]
    if ( O000OO [ 1 ] ) :
     O000OO [ 1 ] . use_count += 1
     I1IiO00Ooo0ooo0 , oO00o0O00o = self . encrypt ( O000OO [ 1 ] , OoOOoooO000 )
     if ( oO00o0O00o ) : self . packet = I1IiO00Ooo0ooo0
     if 98 - 98: ooOoO0o . OOooOOo
     if 60 - 60: OoO0O00 - i1IIi . OOooOOo + OOooOOo * OOooOOo + Ii1I
     if 66 - 66: OOooOOo * OOooOOo / iIii1I11I1II1 + OoOoOO00 . OOooOOo
     if 51 - 51: I1ii11iIi11i
     if 58 - 58: Ii1I % OoooooooOO
     if 49 - 49: I1ii11iIi11i + O0 . Ii1I * OoooooooOO
     if 82 - 82: I1ii11iIi11i
     if 54 - 54: o0oOOo0O0Ooo + I11i - iIii1I11I1II1 % ooOoO0o % IiII
  self . udp_checksum = 0
  if ( self . encap_port == LISP_DATA_PORT ) :
   if ( lisp_crypto_ephem_port == None ) :
    self . hash_packet ( )
   else :
    self . udp_sport = lisp_crypto_ephem_port
    if 19 - 19: I1ii11iIi11i / iIii1I11I1II1 % i1IIi . OoooooooOO
  else :
   self . udp_sport = LISP_DATA_PORT
   if 57 - 57: ooOoO0o . Oo0Ooo - OoO0O00 - i11iIiiIii * I1Ii111 / o0oOOo0O0Ooo
  self . udp_dport = self . encap_port
  self . udp_length = len ( self . packet ) + 16
  if 79 - 79: I1ii11iIi11i + o0oOOo0O0Ooo % Oo0Ooo * o0oOOo0O0Ooo
  if 21 - 21: iII111i
  if 24 - 24: iII111i / ooOoO0o
  if 61 - 61: iIii1I11I1II1 + oO0o
  if ( self . outer_version == 4 ) :
   i1IiiI = socket . htons ( self . udp_sport )
   O0OOO0 = socket . htons ( self . udp_dport )
  else :
   i1IiiI = self . udp_sport
   O0OOO0 = self . udp_dport
   if 61 - 61: ooOoO0o . i11iIiiIii + oO0o
   if 8 - 8: iIii1I11I1II1
  O0OOO0 = socket . htons ( self . udp_dport ) if self . outer_version == 4 else self . udp_dport
  if 55 - 55: oO0o
  if 37 - 37: IiII / i11iIiiIii / Oo0Ooo
  IIi1ii1 = struct . pack ( "HHHH" , i1IiiI , O0OOO0 , socket . htons ( self . udp_length ) ,
 self . udp_checksum )
  if 97 - 97: I1Ii111 . I11i / I1IiiI
  if 83 - 83: I11i - I1ii11iIi11i * oO0o
  if 90 - 90: Oo0Ooo * I1IiiI
  if 75 - 75: I1ii11iIi11i - OoOoOO00 * i11iIiiIii . OoooooooOO - Oo0Ooo . I11i
  I1iI1i11IiI11 = self . lisp_header . encode ( )
  if 82 - 82: I1Ii111 * OoO0O00
  if 32 - 32: O0
  if 73 - 73: O0 . I1ii11iIi11i % IiII + OoO0O00 * I11i - OoOoOO00
  if 52 - 52: OOooOOo * oO0o + I11i * I11i % i1IIi % I11i
  if 96 - 96: o0oOOo0O0Ooo * oO0o - OOooOOo * o0oOOo0O0Ooo * i1IIi
  if ( self . outer_version == 4 ) :
   I1IIIi1i = socket . htons ( self . udp_length + 20 )
   Ooo = socket . htons ( 0x4000 )
   Iii1I1iI = struct . pack ( "BBHHHBBH" , 0x45 , self . outer_tos , I1IIIi1i , 0xdfdf ,
 Ooo , self . outer_ttl , 17 , 0 )
   Iii1I1iI += self . outer_source . pack_address ( )
   Iii1I1iI += self . outer_dest . pack_address ( )
   Iii1I1iI = lisp_ip_checksum ( Iii1I1iI )
  elif ( self . outer_version == 6 ) :
   Iii1I1iI = ""
   if 62 - 62: oO0o + Oo0Ooo / i11iIiiIii
   if 90 - 90: iIii1I11I1II1 + OoOoOO00
   if 9 - 9: iIii1I11I1II1 . OoooooooOO + i1IIi - Oo0Ooo
   if 30 - 30: iII111i / OoO0O00 . iII111i
   if 17 - 17: Oo0Ooo + OoooooooOO * OoooooooOO
   if 5 - 5: I1Ii111 % OoooooooOO . OoOoOO00
   if 67 - 67: I1ii11iIi11i + Ii1I
  else :
   return ( None )
   if 72 - 72: IiII % o0oOOo0O0Ooo
   if 93 - 93: iIii1I11I1II1 + i11iIiiIii . o0oOOo0O0Ooo . i1IIi % I1IiiI % ooOoO0o
  self . packet = Iii1I1iI + IIi1ii1 + I1iI1i11IiI11 + self . packet
  return ( self )
  if 74 - 74: OoOoOO00 / i1IIi % OoooooooOO
  if 52 - 52: IiII % ooOoO0o
 def cipher_pad ( self , packet ) :
  I111 = len ( packet )
  if ( ( I111 % 16 ) != 0 ) :
   oOOooo00OOooO = ( ( I111 / 16 ) + 1 ) * 16
   packet = packet . ljust ( oOOooo00OOooO )
   if 31 - 31: I1IiiI / o0oOOo0O0Ooo + I1IiiI - II111iiii
  return ( packet )
  if 29 - 29: I1IiiI + i11iIiiIii . O0
  if 75 - 75: I1Ii111 + iIii1I11I1II1
 def encrypt ( self , key , addr_str ) :
  if ( key == None or key . shared_key == None ) :
   return ( [ self . packet , False ] )
   if 19 - 19: I1IiiI + i11iIiiIii . IiII - I11i / Ii1I + o0oOOo0O0Ooo
   if 38 - 38: Oo0Ooo / iIii1I11I1II1 * iIii1I11I1II1 % I1ii11iIi11i
   if 92 - 92: I11i / O0 * I1IiiI - I11i
   if 99 - 99: i11iIiiIii % OoooooooOO
   if 56 - 56: IiII * I1Ii111
  I1IiO00Ooo0ooo0 = self . cipher_pad ( self . packet )
  O00oO0O = key . get_iv ( )
  if 3 - 3: iIii1I11I1II1 % I1ii11iIi11i . OOooOOo % I11i
  III11I1 = lisp_get_timestamp ( )
  I1i1I1Iiiii1 = None
  if ( key . cipher_suite == LISP_CS_25519_CHACHA ) :
   O0Ooo0O = chacha . ChaCha ( key . encrypt_key , O00oO0O ) . encrypt
  elif ( key . cipher_suite == LISP_CS_25519_GCM ) :
   iii1 = binascii . unhexlify ( key . encrypt_key )
   try :
    oOo0OoOOOo0 = AES . new ( iii1 , AES . MODE_GCM , O00oO0O )
    O0Ooo0O = oOo0OoOOOo0 . encrypt
    I1i1I1Iiiii1 = oOo0OoOOOo0 . digest
   except :
    lprint ( "You need AES-GCM, do a 'pip install pycryptodome'" )
    return ( [ self . packet , False ] )
    if 55 - 55: oO0o + O0 / iII111i % ooOoO0o / OoooooooOO
  else :
   iii1 = binascii . unhexlify ( key . encrypt_key )
   O0Ooo0O = AES . new ( iii1 , AES . MODE_CBC , O00oO0O ) . encrypt
   if 98 - 98: Ii1I * iIii1I11I1II1 % Oo0Ooo % OOooOOo
   if 88 - 88: iII111i - II111iiii / iII111i - Ii1I
  iI1iii1iI1 = O0Ooo0O ( I1IiO00Ooo0ooo0 )
  if 65 - 65: OoooooooOO
  if ( iI1iii1iI1 == None ) : return ( [ self . packet , False ] )
  III11I1 = int ( str ( time . time ( ) - III11I1 ) . split ( "." ) [ 1 ] [ 0 : 6 ] )
  if 18 - 18: O0 - i1IIi . I1Ii111
  if 98 - 98: o0oOOo0O0Ooo
  if 73 - 73: Oo0Ooo - iII111i . oO0o % i1IIi . O0
  if 15 - 15: ooOoO0o . iIii1I11I1II1 * I1IiiI % I11i
  if 21 - 21: OoO0O00 - I1IiiI . OoooooooOO
  if 6 - 6: iIii1I11I1II1 - iIii1I11I1II1 % o0oOOo0O0Ooo / iIii1I11I1II1 * I1Ii111
  if ( I1i1I1Iiiii1 != None ) : iI1iii1iI1 += I1i1I1Iiiii1 ( )
  if 3 - 3: OOooOOo . IiII / Oo0Ooo
  if 89 - 89: OoooooooOO . iIii1I11I1II1 . Oo0Ooo * iIii1I11I1II1 - I1Ii111
  if 92 - 92: OoooooooOO - I1ii11iIi11i - OoooooooOO % I1IiiI % I1IiiI % iIii1I11I1II1
  if 92 - 92: iII111i * O0 % I1Ii111 . iIii1I11I1II1
  if 66 - 66: I11i + Ii1I
  self . lisp_header . key_id ( key . key_id )
  I1iI1i11IiI11 = self . lisp_header . encode ( )
  if 48 - 48: I1ii11iIi11i
  o0o = key . do_icv ( I1iI1i11IiI11 + O00oO0O + iI1iii1iI1 , O00oO0O )
  if 39 - 39: OOooOOo + OoO0O00
  oOoOOOO0OOO = 4 if ( key . do_poly ) else 8
  if 58 - 58: I11i % i11iIiiIii / i11iIiiIii * ooOoO0o - I1Ii111
  i11ii111i1ii = bold ( "Encrypt" , False )
  Oo0O0O = bold ( key . cipher_suite_string , False )
  addr_str = "RLOC: " + red ( addr_str , False )
  IiIiiI1ii111 = "poly" if key . do_poly else "sha256"
  IiIiiI1ii111 = bold ( IiIiiI1ii111 , False )
  i11ii1 = "ICV({}): 0x{}...{}" . format ( IiIiiI1ii111 , o0o [ 0 : oOoOOOO0OOO ] , o0o [ - oOoOOOO0OOO : : ] )
  dprint ( "{} for key-id: {}, {}, {}, {}-time: {} usec" . format ( i11ii111i1ii , key . key_id , addr_str , i11ii1 , Oo0O0O , III11I1 ) )
  if 4 - 4: i11iIiiIii - OOooOOo % I1ii11iIi11i * I1Ii111 % o0oOOo0O0Ooo
  if 71 - 71: ooOoO0o . ooOoO0o - iIii1I11I1II1
  o0o = int ( o0o , 16 )
  if ( key . do_poly ) :
   Ii1IOoO0o0O = byte_swap_64 ( ( o0o >> 64 ) & LISP_8_64_MASK )
   iIoOoO0 = byte_swap_64 ( o0o & LISP_8_64_MASK )
   o0o = struct . pack ( "QQ" , Ii1IOoO0o0O , iIoOoO0 )
  else :
   Ii1IOoO0o0O = byte_swap_64 ( ( o0o >> 96 ) & LISP_8_64_MASK )
   iIoOoO0 = byte_swap_64 ( ( o0o >> 32 ) & LISP_8_64_MASK )
   Iii1II1ii = socket . htonl ( o0o & 0xffffffff )
   o0o = struct . pack ( "QQI" , Ii1IOoO0o0O , iIoOoO0 , Iii1II1ii )
   if 95 - 95: Oo0Ooo
   if 29 - 29: Ii1I / ooOoO0o % I11i
  return ( [ O00oO0O + iI1iii1iI1 + o0o , True ] )
  if 10 - 10: iIii1I11I1II1 % OoooooooOO % I1ii11iIi11i
  if 39 - 39: II111iiii * OoOoOO00 . O0 * I11i
 def decrypt ( self , packet , header_length , key , addr_str ) :
  if 89 - 89: Ii1I - ooOoO0o . I11i - I1Ii111 - I1IiiI
  if 79 - 79: IiII + IiII + Ii1I
  if 39 - 39: O0 - OoooooooOO
  if 63 - 63: iIii1I11I1II1 % o0oOOo0O0Ooo * ooOoO0o
  if 79 - 79: O0
  if 32 - 32: II111iiii . O0 + Ii1I / OoOoOO00 / IiII / OOooOOo
  if ( key . do_poly ) :
   Ii1IOoO0o0O , iIoOoO0 = struct . unpack ( "QQ" , packet [ - 16 : : ] )
   ii1I11iI = byte_swap_64 ( Ii1IOoO0o0O ) << 64
   ii1I11iI |= byte_swap_64 ( iIoOoO0 )
   ii1I11iI = lisp_hex_string ( ii1I11iI ) . zfill ( 32 )
   packet = packet [ 0 : - 16 ]
   oOoOOOO0OOO = 4
   O0Oo00 = bold ( "poly" , False )
  else :
   Ii1IOoO0o0O , iIoOoO0 , Iii1II1ii = struct . unpack ( "QQI" , packet [ - 20 : : ] )
   ii1I11iI = byte_swap_64 ( Ii1IOoO0o0O ) << 96
   ii1I11iI |= byte_swap_64 ( iIoOoO0 ) << 32
   ii1I11iI |= socket . htonl ( Iii1II1ii )
   ii1I11iI = lisp_hex_string ( ii1I11iI ) . zfill ( 40 )
   packet = packet [ 0 : - 20 ]
   oOoOOOO0OOO = 8
   O0Oo00 = bold ( "sha" , False )
   if 63 - 63: i1IIi % i11iIiiIii % II111iiii * OoooooooOO
  I1iI1i11IiI11 = self . lisp_header . encode ( )
  if 40 - 40: Oo0Ooo
  if 47 - 47: OoOoOO00
  if 65 - 65: O0 + I1Ii111 % Ii1I * I1IiiI / ooOoO0o / OoOoOO00
  if 71 - 71: i11iIiiIii / OoOoOO00 . oO0o
  if ( key . cipher_suite == LISP_CS_25519_CHACHA ) :
   iI1IIIi11 = 8
   Oo0O0O = bold ( "chacha" , False )
  elif ( key . cipher_suite == LISP_CS_25519_GCM ) :
   iI1IIIi11 = 12
   Oo0O0O = bold ( "aes-gcm" , False )
  else :
   iI1IIIi11 = 16
   Oo0O0O = bold ( "aes-cbc" , False )
   if 69 - 69: O0 - O0
  O00oO0O = packet [ 0 : iI1IIIi11 ]
  if 41 - 41: IiII % o0oOOo0O0Ooo
  if 67 - 67: O0 % I1Ii111
  if 35 - 35: I1IiiI . OoOoOO00 + OoooooooOO % Oo0Ooo % OOooOOo
  if 39 - 39: Ii1I
  oOo0000ooO = key . do_icv ( I1iI1i11IiI11 + packet , O00oO0O )
  if 15 - 15: ooOoO0o . o0oOOo0O0Ooo + OoOoOO00 . iIii1I11I1II1 % ooOoO0o + O0
  IIiII11 = "0x{}...{}" . format ( ii1I11iI [ 0 : oOoOOOO0OOO ] , ii1I11iI [ - oOoOOOO0OOO : : ] )
  oo0O00OOOOO = "0x{}...{}" . format ( oOo0000ooO [ 0 : oOoOOOO0OOO ] , oOo0000ooO [ - oOoOOOO0OOO : : ] )
  if 53 - 53: OoooooooOO . OoooooooOO + o0oOOo0O0Ooo - iII111i + OOooOOo
  if ( oOo0000ooO != ii1I11iI ) :
   self . packet_error = "ICV-error"
   i1111iIII = Oo0O0O + "/" + O0Oo00
   IiIIiiIiIIiIi = bold ( "ICV failed ({})" . format ( i1111iIII ) , False )
   i11ii1 = "packet-ICV {} != computed-ICV {}" . format ( IIiII11 , oo0O00OOOOO )
   dprint ( ( "{} from RLOC {}, receive-port: {}, key-id: {}, " + "packet dropped, {}" ) . format ( IiIIiiIiIIiIi , red ( addr_str , False ) ,
   # OoO0O00 * I11i % i11iIiiIii % i1IIi + IiII / II111iiii
 self . udp_sport , key . key_id , i11ii1 ) )
   dprint ( "{}" . format ( key . print_keys ( ) ) )
   if 84 - 84: i1IIi + OoO0O00 * OoooooooOO . iII111i + iII111i
   if 60 - 60: ooOoO0o * ooOoO0o / OoooooooOO
   if 65 - 65: I1ii11iIi11i % oO0o . OoooooooOO * o0oOOo0O0Ooo * OoO0O00
   if 10 - 10: oO0o - iII111i % II111iiii - I1Ii111 - i1IIi
   if 10 - 10: I1ii11iIi11i - I11i . I1Ii111
   if 8 - 8: iIii1I11I1II1 % oO0o + Oo0Ooo
   lisp_retry_decap_keys ( addr_str , I1iI1i11IiI11 + packet , O00oO0O , ii1I11iI )
   return ( [ None , False ] )
   if 24 - 24: o0oOOo0O0Ooo / Ii1I / Ii1I % II111iiii - oO0o * oO0o
   if 58 - 58: OoOoOO00
   if 60 - 60: II111iiii
   if 90 - 90: OoOoOO00
   if 37 - 37: OoOoOO00 + O0 . O0 * Oo0Ooo % I1Ii111 / iII111i
  packet = packet [ iI1IIIi11 : : ]
  if 18 - 18: OoooooooOO
  if 57 - 57: ooOoO0o . OoOoOO00 * o0oOOo0O0Ooo - OoooooooOO
  if 75 - 75: i11iIiiIii / o0oOOo0O0Ooo . IiII . i1IIi . i1IIi / I11i
  if 94 - 94: ooOoO0o + I1IiiI
  III11I1 = lisp_get_timestamp ( )
  if ( key . cipher_suite == LISP_CS_25519_CHACHA ) :
   oOOOoo00oO = chacha . ChaCha ( key . encrypt_key , O00oO0O ) . decrypt
  elif ( key . cipher_suite == LISP_CS_25519_GCM ) :
   iii1 = binascii . unhexlify ( key . encrypt_key )
   try :
    oOOOoo00oO = AES . new ( iii1 , AES . MODE_GCM , O00oO0O ) . decrypt
   except :
    self . packet_error = "no-decrypt-key"
    lprint ( "You need AES-GCM, do a 'pip install pycryptodome'" )
    return ( [ None , False ] )
    if 59 - 59: Ii1I / OoOoOO00 * OoO0O00 * iII111i % oO0o
  else :
   if ( ( len ( packet ) % 16 ) != 0 ) :
    dprint ( "Ciphertext not multiple of 16 bytes, packet dropped" )
    return ( [ None , False ] )
    if 61 - 61: Oo0Ooo - O0 - OoooooooOO
   iii1 = binascii . unhexlify ( key . encrypt_key )
   oOOOoo00oO = AES . new ( iii1 , AES . MODE_CBC , O00oO0O ) . decrypt
   if 4 - 4: II111iiii - oO0o % Oo0Ooo * i11iIiiIii
   if 18 - 18: Oo0Ooo % O0
  oooooO00OOO = oOOOoo00oO ( packet )
  III11I1 = int ( str ( time . time ( ) - III11I1 ) . split ( "." ) [ 1 ] [ 0 : 6 ] )
  if 53 - 53: II111iiii
  if 61 - 61: O0 * OoO0O00 * I1IiiI % OoooooooOO / OoOoOO00 % ooOoO0o
  if 43 - 43: OoooooooOO
  if 33 - 33: II111iiii - IiII - ooOoO0o
  i11ii111i1ii = bold ( "Decrypt" , False )
  addr_str = "RLOC: " + red ( addr_str , False )
  IiIiiI1ii111 = "poly" if key . do_poly else "sha256"
  IiIiiI1ii111 = bold ( IiIiiI1ii111 , False )
  i11ii1 = "ICV({}): {}" . format ( IiIiiI1ii111 , IIiII11 )
  dprint ( "{} for key-id: {}, {}, {} (good), {}-time: {} usec" . format ( i11ii111i1ii , key . key_id , addr_str , i11ii1 , Oo0O0O , III11I1 ) )
  if 92 - 92: OoO0O00 * IiII
  if 92 - 92: oO0o
  if 7 - 7: iII111i
  if 73 - 73: OoO0O00 % I1ii11iIi11i
  if 32 - 32: OOooOOo + iII111i + iIii1I11I1II1 * Oo0Ooo
  if 62 - 62: i11iIiiIii
  if 2 - 2: I1IiiI
  self . packet = self . packet [ 0 : header_length ]
  return ( [ oooooO00OOO , True ] )
  if 69 - 69: OoooooooOO / Oo0Ooo * I1Ii111
  if 99 - 99: II111iiii * iIii1I11I1II1 % O0 * oO0o / II111iiii % OoooooooOO
 def fragment_outer ( self , outer_hdr , inner_packet ) :
  i11 = 1000
  if 89 - 89: OoO0O00 + o0oOOo0O0Ooo . OOooOOo - I1IiiI * i1IIi % II111iiii
  if 30 - 30: I1ii11iIi11i
  if 88 - 88: i1IIi % ooOoO0o . i11iIiiIii . i1IIi
  if 82 - 82: i1IIi . I1ii11iIi11i
  if 53 - 53: I1IiiI % OoooooooOO + I1Ii111 - Oo0Ooo / IiII * o0oOOo0O0Ooo
  ooo0O = [ ]
  oOO0OO0O = 0
  I111 = len ( inner_packet )
  while ( oOO0OO0O < I111 ) :
   Ooo = inner_packet [ oOO0OO0O : : ]
   if ( len ( Ooo ) > i11 ) : Ooo = Ooo [ 0 : i11 ]
   ooo0O . append ( Ooo )
   oOO0OO0O += len ( Ooo )
   if 15 - 15: i1IIi % OoooooooOO * OOooOOo . II111iiii + O0 * OoO0O00
   if 16 - 16: O0 - O0 / I11i - OoO0O00
   if 30 - 30: o0oOOo0O0Ooo - OoO0O00 + OOooOOo
   if 65 - 65: O0 / II111iiii . iIii1I11I1II1 . oO0o / Oo0Ooo % iIii1I11I1II1
   if 74 - 74: i1IIi / I1IiiI % I1ii11iIi11i / O0 % I11i - OoOoOO00
   if 31 - 31: I1IiiI / OoooooooOO . iIii1I11I1II1 * OoOoOO00 . OoooooooOO + II111iiii
  II1IIii1I11I = [ ]
  oOO0OO0O = 0
  for Ooo in ooo0O :
   if 17 - 17: O0
   if 31 - 31: I11i + II111iiii * Oo0Ooo + Oo0Ooo . I11i
   if 90 - 90: I1Ii111 * iIii1I11I1II1 - I11i % ooOoO0o . IiII
   if 66 - 66: OoOoOO00
   II1i1I1111I1I = oOO0OO0O if ( Ooo == ooo0O [ - 1 ] ) else 0x2000 + oOO0OO0O
   II1i1I1111I1I = socket . htons ( II1i1I1111I1I )
   outer_hdr = outer_hdr [ 0 : 6 ] + struct . pack ( "H" , II1i1I1111I1I ) + outer_hdr [ 8 : : ]
   if 27 - 27: Oo0Ooo * ooOoO0o + i11iIiiIii / I1IiiI - oO0o
   if 44 - 44: Ii1I * ooOoO0o / OoOoOO00
   if 69 - 69: ooOoO0o . OOooOOo - I1IiiI
   if 29 - 29: i11iIiiIii . I1ii11iIi11i / I1IiiI . OOooOOo + i11iIiiIii
   i1I1i = socket . htons ( len ( Ooo ) + 20 )
   outer_hdr = outer_hdr [ 0 : 2 ] + struct . pack ( "H" , i1I1i ) + outer_hdr [ 4 : : ]
   outer_hdr = lisp_ip_checksum ( outer_hdr )
   II1IIii1I11I . append ( outer_hdr + Ooo )
   oOO0OO0O += len ( Ooo ) / 8
   if 9 - 9: OoooooooOO * I1ii11iIi11i
  return ( II1IIii1I11I )
  if 9 - 9: Oo0Ooo + iII111i
  if 64 - 64: O0 * I1IiiI / I1IiiI
 def fragment ( self ) :
  I1IiO00Ooo0ooo0 = self . fix_outer_header ( self . packet )
  if 57 - 57: I1ii11iIi11i / OoooooooOO % I1ii11iIi11i . O0 / I1ii11iIi11i
  if 63 - 63: IiII + iIii1I11I1II1 + I1IiiI + I1Ii111
  if 72 - 72: OoO0O00 + i11iIiiIii + I1ii11iIi11i
  if 96 - 96: oO0o % i1IIi / o0oOOo0O0Ooo
  if 13 - 13: II111iiii - Oo0Ooo % i11iIiiIii + iII111i
  if 88 - 88: O0 . oO0o % I1IiiI
  I111 = len ( I1IiO00Ooo0ooo0 )
  if ( I111 <= 1500 ) : return ( [ I1IiO00Ooo0ooo0 ] , "Fragment-None" )
  if 10 - 10: I1IiiI + O0
  I1IiO00Ooo0ooo0 = self . packet
  if 75 - 75: O0 % iIii1I11I1II1 / OoOoOO00 % OOooOOo / IiII
  if 31 - 31: i11iIiiIii * OoOoOO00
  if 69 - 69: i11iIiiIii
  if 61 - 61: O0
  if 21 - 21: OoO0O00 % iIii1I11I1II1 . OoO0O00
  if ( self . inner_version != 4 ) :
   OO000OOOo0Oo = random . randint ( 0 , 0xffff )
   Oo00O0O = I1IiO00Ooo0ooo0 [ 0 : 4 ] + struct . pack ( "H" , OO000OOOo0Oo ) + I1IiO00Ooo0ooo0 [ 6 : 20 ]
   oOoOOoo = I1IiO00Ooo0ooo0 [ 20 : : ]
   II1IIii1I11I = self . fragment_outer ( Oo00O0O , oOoOOoo )
   return ( II1IIii1I11I , "Fragment-Outer" )
   if 65 - 65: i11iIiiIii - ooOoO0o * I11i + ooOoO0o / IiII + o0oOOo0O0Ooo
   if 35 - 35: O0 + Oo0Ooo - I1IiiI % Ii1I % II111iiii
   if 77 - 77: I1Ii111 + oO0o
   if 38 - 38: I1ii11iIi11i - Ii1I * o0oOOo0O0Ooo
   if 13 - 13: I1IiiI * oO0o
  iiii1I1111i1 = 56 if ( self . outer_version == 6 ) else 36
  Oo00O0O = I1IiO00Ooo0ooo0 [ 0 : iiii1I1111i1 ]
  IIiIi1i1I11 = I1IiO00Ooo0ooo0 [ iiii1I1111i1 : iiii1I1111i1 + 20 ]
  oOoOOoo = I1IiO00Ooo0ooo0 [ iiii1I1111i1 + 20 : : ]
  if 33 - 33: ooOoO0o + OoooooooOO - OoO0O00 / i1IIi / OoooooooOO
  if 82 - 82: I1ii11iIi11i / OOooOOo - iII111i / Oo0Ooo * OoO0O00
  if 55 - 55: OoooooooOO
  if 73 - 73: OoOoOO00 - I1ii11iIi11i % Oo0Ooo + I1ii11iIi11i - O0 . OoO0O00
  i1iIii = struct . unpack ( "H" , IIiIi1i1I11 [ 6 : 8 ] ) [ 0 ]
  i1iIii = socket . ntohs ( i1iIii )
  if ( i1iIii & 0x4000 ) :
   O0o00 = bold ( "DF-bit set" , False )
   dprint ( "{} in inner header, packet discarded" . format ( O0o00 ) )
   return ( [ ] , "Fragment-None-DF-bit" )
   if 8 - 8: I1Ii111 * Oo0Ooo - OOooOOo . iIii1I11I1II1
   if 48 - 48: i11iIiiIii / II111iiii + Ii1I + o0oOOo0O0Ooo . I1Ii111 % OOooOOo
  oOO0OO0O = 0
  I111 = len ( oOoOOoo )
  II1IIii1I11I = [ ]
  while ( oOO0OO0O < I111 ) :
   II1IIii1I11I . append ( oOoOOoo [ oOO0OO0O : oOO0OO0O + 1400 ] )
   oOO0OO0O += 1400
   if 88 - 88: I1Ii111 . I1Ii111
   if 71 - 71: ooOoO0o . I1ii11iIi11i * O0 - I1Ii111 - II111iiii
   if 5 - 5: o0oOOo0O0Ooo
   if 66 - 66: iII111i / i11iIiiIii * O0
   if 78 - 78: IiII - I11i % O0 - OOooOOo % OoO0O00
  ooo0O = II1IIii1I11I
  II1IIii1I11I = [ ]
  i11IiIi = True if i1iIii & 0x2000 else False
  i1iIii = ( i1iIii & 0x1fff ) * 8
  for Ooo in ooo0O :
   if 24 - 24: I11i / Ii1I * ooOoO0o - i11iIiiIii
   if 72 - 72: iIii1I11I1II1 . i11iIiiIii / OOooOOo + II111iiii / oO0o
   if 48 - 48: O0
   if 26 - 26: I11i + I1Ii111 + I11i / I1Ii111
   oOo0Oo00O = i1iIii / 8
   if ( i11IiIi ) :
    oOo0Oo00O |= 0x2000
   elif ( Ooo != ooo0O [ - 1 ] ) :
    oOo0Oo00O |= 0x2000
    if 28 - 28: ooOoO0o . i1IIi
   oOo0Oo00O = socket . htons ( oOo0Oo00O )
   IIiIi1i1I11 = IIiIi1i1I11 [ 0 : 6 ] + struct . pack ( "H" , oOo0Oo00O ) + IIiIi1i1I11 [ 8 : : ]
   if 75 - 75: iII111i + iIii1I11I1II1
   if 98 - 98: OoOoOO00 - OoOoOO00 . II111iiii . iII111i + O0
   if 28 - 28: IiII + i11iIiiIii + OoooooooOO / OoO0O00
   if 6 - 6: I1IiiI - i11iIiiIii
   if 61 - 61: I1Ii111 * I1ii11iIi11i % I1IiiI % OoO0O00 % I11i + I11i
   if 6 - 6: Oo0Ooo
   I111 = len ( Ooo )
   i1iIii += I111
   i1I1i = socket . htons ( I111 + 20 )
   IIiIi1i1I11 = IIiIi1i1I11 [ 0 : 2 ] + struct . pack ( "H" , i1I1i ) + IIiIi1i1I11 [ 4 : 10 ] + struct . pack ( "H" , 0 ) + IIiIi1i1I11 [ 12 : : ]
   if 73 - 73: I1Ii111 * I1ii11iIi11i + o0oOOo0O0Ooo - Oo0Ooo . I11i
   IIiIi1i1I11 = lisp_ip_checksum ( IIiIi1i1I11 )
   o0oOOO = IIiIi1i1I11 + Ooo
   if 62 - 62: Ii1I - oO0o % iIii1I11I1II1
   if 57 - 57: OoooooooOO / OoOoOO00
   if 44 - 44: OoOoOO00 * i1IIi * O0
   if 94 - 94: I1IiiI - O0
   if 18 - 18: IiII / oO0o . oO0o . iIii1I11I1II1 . i11iIiiIii
   I111 = len ( o0oOOO )
   if ( self . outer_version == 4 ) :
    i1I1i = I111 + iiii1I1111i1
    I111 += 16
    Oo00O0O = Oo00O0O [ 0 : 2 ] + struct . pack ( "H" , i1I1i ) + Oo00O0O [ 4 : : ]
    if 69 - 69: i11iIiiIii - O0 % II111iiii % OOooOOo / Oo0Ooo * I11i
    Oo00O0O = lisp_ip_checksum ( Oo00O0O )
    o0oOOO = Oo00O0O + o0oOOO
    o0oOOO = self . fix_outer_header ( o0oOOO )
    if 61 - 61: OoO0O00 . i1IIi - I1IiiI
    if 38 - 38: oO0o + iIii1I11I1II1 * Ii1I / OoO0O00 + OOooOOo
    if 48 - 48: OoooooooOO - I1Ii111 . i11iIiiIii * iII111i - Ii1I - o0oOOo0O0Ooo
    if 59 - 59: iII111i / I11i . Oo0Ooo
    if 100 - 100: O0
   oOOO00Oo = iiii1I1111i1 - 12
   i1I1i = socket . htons ( I111 )
   o0oOOO = o0oOOO [ 0 : oOOO00Oo ] + struct . pack ( "H" , i1I1i ) + o0oOOO [ oOOO00Oo + 2 : : ]
   if 48 - 48: II111iiii + II111iiii * i1IIi / Ii1I
   II1IIii1I11I . append ( o0oOOO )
   if 37 - 37: iIii1I11I1II1 % I11i / IiII
  return ( II1IIii1I11I , "Fragment-Inner" )
  if 37 - 37: I1Ii111 - oO0o - OoO0O00
  if 42 - 42: iIii1I11I1II1 % Ii1I - I1ii11iIi11i + iIii1I11I1II1
 def fix_outer_header ( self , packet ) :
  if 27 - 27: O0 / OoO0O00
  if 99 - 99: Ii1I - IiII * iIii1I11I1II1 . II111iiii
  if 56 - 56: iIii1I11I1II1 % OoO0O00 . ooOoO0o % IiII . I1Ii111 * Oo0Ooo
  if 41 - 41: iIii1I11I1II1 % IiII * oO0o - ooOoO0o
  if 5 - 5: OoO0O00 + OoO0O00 + II111iiii * iIii1I11I1II1 + OoooooooOO
  if 77 - 77: O0 * I1ii11iIi11i * oO0o + OoO0O00 + I1ii11iIi11i - I1Ii111
  if 10 - 10: I1ii11iIi11i + IiII
  if 58 - 58: I1IiiI + OoooooooOO / iII111i . ooOoO0o % o0oOOo0O0Ooo / I1ii11iIi11i
  if ( self . outer_version == 4 or self . inner_version == 4 ) :
   if ( lisp_is_macos ( ) ) :
    packet = packet [ 0 : 2 ] + packet [ 3 ] + packet [ 2 ] + packet [ 4 : 6 ] + packet [ 7 ] + packet [ 6 ] + packet [ 8 : : ]
    if 62 - 62: II111iiii
   else :
    packet = packet [ 0 : 2 ] + packet [ 3 ] + packet [ 2 ] + packet [ 4 : : ]
    if 12 - 12: IiII + II111iiii
    if 92 - 92: I1Ii111 % iIii1I11I1II1 - iII111i / i11iIiiIii % ooOoO0o * o0oOOo0O0Ooo
  return ( packet )
  if 80 - 80: iII111i
  if 3 - 3: I1ii11iIi11i * I11i
 def send_packet ( self , lisp_raw_socket , dest ) :
  if ( lisp_flow_logging and dest != self . inner_dest ) : self . log_flow ( True )
  if 53 - 53: iIii1I11I1II1 / iII111i % OoO0O00 + IiII / ooOoO0o
  dest = dest . print_address_no_iid ( )
  II1IIii1I11I , oo00oO = self . fragment ( )
  if 28 - 28: Ii1I - I1IiiI % OoO0O00 * I1Ii111
  for o0oOOO in II1IIii1I11I :
   if ( len ( II1IIii1I11I ) != 1 ) :
    self . packet = o0oOOO
    self . print_packet ( oo00oO , True )
    if 80 - 80: OOooOOo * IiII
    if 4 - 4: iIii1I11I1II1 . I1Ii111 + II111iiii % OoooooooOO
   try : lisp_raw_socket . sendto ( o0oOOO , ( dest , 0 ) )
   except socket . error , I1i11II :
    lprint ( "socket.sendto() failed: {}" . format ( I1i11II ) )
    if 82 - 82: OoooooooOO / ooOoO0o * I11i * O0 . I1ii11iIi11i
    if 21 - 21: II111iiii + Oo0Ooo
    if 59 - 59: OOooOOo + I1IiiI / II111iiii / OoOoOO00
    if 80 - 80: OoOoOO00 + iIii1I11I1II1 . IiII
 def send_l2_packet ( self , l2_socket , mac_header ) :
  if ( l2_socket == None ) :
   lprint ( "No layer-2 socket, drop IPv6 packet" )
   return
   if 76 - 76: I1IiiI * OOooOOo
  if ( mac_header == None ) :
   lprint ( "Could not build MAC header, drop IPv6 packet" )
   return
   if 12 - 12: iIii1I11I1II1 / I11i % Ii1I
   if 49 - 49: OoO0O00 + II111iiii / IiII - O0 % Ii1I
  I1IiO00Ooo0ooo0 = mac_header + self . packet
  if 27 - 27: OoO0O00 + Oo0Ooo
  if 92 - 92: I1IiiI % iII111i
  if 31 - 31: OoooooooOO - oO0o / I1Ii111
  if 62 - 62: i11iIiiIii - I11i
  if 81 - 81: I11i
  if 92 - 92: OOooOOo - Oo0Ooo - OoooooooOO / IiII - i1IIi
  if 81 - 81: i1IIi / I1Ii111 % i11iIiiIii . iIii1I11I1II1 * OoOoOO00 + OoooooooOO
  if 31 - 31: i1IIi % II111iiii
  if 13 - 13: iIii1I11I1II1 - II111iiii % O0 . Ii1I % OoO0O00
  if 2 - 2: OoooooooOO - Ii1I % oO0o / I1IiiI / o0oOOo0O0Ooo
  if 3 - 3: II111iiii / OOooOOo
  l2_socket . write ( I1IiO00Ooo0ooo0 )
  return
  if 48 - 48: ooOoO0o . I1ii11iIi11i
  if 49 - 49: i1IIi - OoOoOO00 . Oo0Ooo + iIii1I11I1II1 - ooOoO0o / Oo0Ooo
 def bridge_l2_packet ( self , eid , db ) :
  try : iIi11ii1 = db . dynamic_eids [ eid . print_address_no_iid ( ) ]
  except : return
  try : iIiiiIiIi = lisp_myinterfaces [ iIi11ii1 . interface ]
  except : return
  try :
   socket = iIiiiIiIi . get_bridge_socket ( )
   if ( socket == None ) : return
  except : return
  if 49 - 49: oO0o . OoOoOO00
  try : socket . send ( self . packet )
  except socket . error , I1i11II :
   lprint ( "bridge_l2_packet(): socket.send() failed: {}" . format ( I1i11II ) )
   if 73 - 73: Ii1I / I1IiiI / OoooooooOO + I1IiiI
   if 57 - 57: OOooOOo . Ii1I % o0oOOo0O0Ooo
   if 32 - 32: I11i / IiII - O0 * iIii1I11I1II1
 def decode ( self , is_lisp_packet , lisp_ipc_socket , stats ) :
  self . packet_error = ""
  I1IiO00Ooo0ooo0 = self . packet
  oo0oO0oOo0O = len ( I1IiO00Ooo0ooo0 )
  OoOo00 = OOoOoO = True
  if 72 - 72: OoOoOO00 / I1Ii111 * IiII % iIii1I11I1II1
  if 53 - 53: OoO0O00 . O0 . I1IiiI * OOooOOo / o0oOOo0O0Ooo
  if 34 - 34: OoOoOO00
  if 16 - 16: i1IIi - I1Ii111 - II111iiii
  OoOOoOOoo = 0
  IIiI1i = self . lisp_header . get_instance_id ( )
  if ( is_lisp_packet ) :
   oo0O0 = struct . unpack ( "B" , I1IiO00Ooo0ooo0 [ 0 : 1 ] ) [ 0 ]
   self . outer_version = oo0O0 >> 4
   if ( self . outer_version == 4 ) :
    if 34 - 34: II111iiii - IiII % OoOoOO00 % Ii1I / ooOoO0o
    if 10 - 10: OoooooooOO . I1IiiI * O0 * OoO0O00 - OOooOOo
    if 33 - 33: I1ii11iIi11i . Oo0Ooo + I1IiiI + o0oOOo0O0Ooo
    if 54 - 54: ooOoO0o * iII111i * iII111i % OoOoOO00 - OOooOOo % I1ii11iIi11i
    if 44 - 44: Oo0Ooo . OOooOOo + I11i
    I1Ii1iIIiiiIi = struct . unpack ( "H" , I1IiO00Ooo0ooo0 [ 10 : 12 ] ) [ 0 ]
    I1IiO00Ooo0ooo0 = lisp_ip_checksum ( I1IiO00Ooo0ooo0 )
    iIiI1I1IIi11 = struct . unpack ( "H" , I1IiO00Ooo0ooo0 [ 10 : 12 ] ) [ 0 ]
    if ( iIiI1I1IIi11 != 0 ) :
     if ( I1Ii1iIIiiiIi != 0 or lisp_is_macos ( ) == False ) :
      self . packet_error = "checksum-error"
      if ( stats ) :
       stats [ self . packet_error ] . increment ( oo0oO0oOo0O )
       if 93 - 93: II111iiii . i11iIiiIii + II111iiii % oO0o
       if 98 - 98: I1Ii111 * oO0o * OoOoOO00 + Ii1I * iII111i
      lprint ( "IPv4 header checksum failed for outer header" )
      if ( lisp_flow_logging ) : self . log_flow ( False )
      return ( None )
      if 4 - 4: IiII
      if 16 - 16: iIii1I11I1II1 * iII111i + oO0o . O0 . o0oOOo0O0Ooo
      if 99 - 99: i11iIiiIii - iII111i
    o0O0O0O00o = LISP_AFI_IPV4
    oOO0OO0O = 12
    self . outer_tos = struct . unpack ( "B" , I1IiO00Ooo0ooo0 [ 1 : 2 ] ) [ 0 ]
    self . outer_ttl = struct . unpack ( "B" , I1IiO00Ooo0ooo0 [ 8 : 9 ] ) [ 0 ]
    OoOOoOOoo = 20
   elif ( self . outer_version == 6 ) :
    o0O0O0O00o = LISP_AFI_IPV6
    oOO0OO0O = 8
    OoOooOo00o = struct . unpack ( "H" , I1IiO00Ooo0ooo0 [ 0 : 2 ] ) [ 0 ]
    self . outer_tos = ( socket . ntohs ( OoOooOo00o ) >> 4 ) & 0xff
    self . outer_ttl = struct . unpack ( "B" , I1IiO00Ooo0ooo0 [ 7 : 8 ] ) [ 0 ]
    OoOOoOOoo = 40
   else :
    self . packet_error = "outer-header-error"
    if ( stats ) : stats [ self . packet_error ] . increment ( oo0oO0oOo0O )
    lprint ( "Cannot decode outer header" )
    return ( None )
    if 28 - 28: I1ii11iIi11i + I1ii11iIi11i % OoOoOO00
    if 12 - 12: I11i
   self . outer_source . afi = o0O0O0O00o
   self . outer_dest . afi = o0O0O0O00o
   I11iIi1i1I1i1 = self . outer_source . addr_length ( )
   if 14 - 14: I11i
   self . outer_source . unpack_address ( I1IiO00Ooo0ooo0 [ oOO0OO0O : oOO0OO0O + I11iIi1i1I1i1 ] )
   oOO0OO0O += I11iIi1i1I1i1
   self . outer_dest . unpack_address ( I1IiO00Ooo0ooo0 [ oOO0OO0O : oOO0OO0O + I11iIi1i1I1i1 ] )
   I1IiO00Ooo0ooo0 = I1IiO00Ooo0ooo0 [ OoOOoOOoo : : ]
   self . outer_source . mask_len = self . outer_source . host_mask_len ( )
   self . outer_dest . mask_len = self . outer_dest . host_mask_len ( )
   if 18 - 18: I1IiiI
   if 23 - 23: OoooooooOO * II111iiii
   if 70 - 70: I1ii11iIi11i + I1IiiI
   if 65 - 65: iII111i - iII111i . Oo0Ooo
   oO00o0O00ooooOooO = struct . unpack ( "H" , I1IiO00Ooo0ooo0 [ 0 : 2 ] ) [ 0 ]
   self . udp_sport = socket . ntohs ( oO00o0O00ooooOooO )
   oO00o0O00ooooOooO = struct . unpack ( "H" , I1IiO00Ooo0ooo0 [ 2 : 4 ] ) [ 0 ]
   self . udp_dport = socket . ntohs ( oO00o0O00ooooOooO )
   oO00o0O00ooooOooO = struct . unpack ( "H" , I1IiO00Ooo0ooo0 [ 4 : 6 ] ) [ 0 ]
   self . udp_length = socket . ntohs ( oO00o0O00ooooOooO )
   oO00o0O00ooooOooO = struct . unpack ( "H" , I1IiO00Ooo0ooo0 [ 6 : 8 ] ) [ 0 ]
   self . udp_checksum = socket . ntohs ( oO00o0O00ooooOooO )
   I1IiO00Ooo0ooo0 = I1IiO00Ooo0ooo0 [ 8 : : ]
   if 38 - 38: i11iIiiIii - oO0o % IiII
   if 1 - 1: oO0o + I1Ii111 . I1IiiI
   if 47 - 47: iII111i . OoOoOO00
   if 58 - 58: iII111i + Oo0Ooo / I1IiiI
   OoOo00 = ( self . udp_dport == LISP_DATA_PORT or
 self . udp_sport == LISP_DATA_PORT )
   OOoOoO = ( self . udp_dport in ( LISP_L2_DATA_PORT , LISP_VXLAN_DATA_PORT ) )
   if 68 - 68: IiII * Ii1I
   if 91 - 91: Ii1I + OoO0O00 * o0oOOo0O0Ooo . I1Ii111
   if 89 - 89: OoooooooOO * Ii1I * I1IiiI . ooOoO0o * Ii1I / iII111i
   if 46 - 46: i11iIiiIii
   if ( self . lisp_header . decode ( I1IiO00Ooo0ooo0 ) == False ) :
    self . packet_error = "lisp-header-error"
    if ( stats ) : stats [ self . packet_error ] . increment ( oo0oO0oOo0O )
    if 15 - 15: O0 / i1IIi / i1IIi . iII111i % OoOoOO00 + I1IiiI
    if ( lisp_flow_logging ) : self . log_flow ( False )
    lprint ( "Cannot decode LISP header" )
    return ( None )
    if 48 - 48: I1Ii111 % iII111i % Ii1I % iIii1I11I1II1 . Ii1I
   I1IiO00Ooo0ooo0 = I1IiO00Ooo0ooo0 [ 8 : : ]
   IIiI1i = self . lisp_header . get_instance_id ( )
   OoOOoOOoo += 16
   if 14 - 14: iII111i * OoO0O00 % O0 + I11i + I1ii11iIi11i
  if ( IIiI1i == 0xffffff ) : IIiI1i = 0
  if 23 - 23: Oo0Ooo % iII111i + Ii1I - I1Ii111
  if 65 - 65: OoooooooOO
  if 22 - 22: OOooOOo + II111iiii + Oo0Ooo
  if 83 - 83: ooOoO0o
  i1Ii1i11ii = False
  oO0O0oo = self . lisp_header . k_bits
  if ( oO0O0oo ) :
   OoOOoooO000 = lisp_get_crypto_decap_lookup_key ( self . outer_source ,
 self . udp_sport )
   if ( OoOOoooO000 == None ) :
    self . packet_error = "no-decrypt-key"
    if ( stats ) : stats [ self . packet_error ] . increment ( oo0oO0oOo0O )
    if 64 - 64: OoOoOO00 % OoOoOO00 + o0oOOo0O0Ooo + Oo0Ooo
    self . print_packet ( "Receive" , is_lisp_packet )
    OO0oO0Oo = bold ( "No key available" , False )
    dprint ( "{} for key-id {} to decrypt packet" . format ( OO0oO0Oo , oO0O0oo ) )
    if ( lisp_flow_logging ) : self . log_flow ( False )
    return ( None )
    if 82 - 82: i11iIiiIii + iIii1I11I1II1 / Oo0Ooo + OOooOOo * II111iiii
    if 34 - 34: o0oOOo0O0Ooo % OoooooooOO
   iIIIi = lisp_crypto_keys_by_rloc_decap [ OoOOoooO000 ] [ oO0O0oo ]
   if ( iIIIi == None ) :
    self . packet_error = "no-decrypt-key"
    if ( stats ) : stats [ self . packet_error ] . increment ( oo0oO0oOo0O )
    if 74 - 74: O0 . I11i
    self . print_packet ( "Receive" , is_lisp_packet )
    OO0oO0Oo = bold ( "No key available" , False )
    dprint ( "{} to decrypt packet from RLOC {}" . format ( OO0oO0Oo ,
 red ( OoOOoooO000 , False ) ) )
    if ( lisp_flow_logging ) : self . log_flow ( False )
    return ( None )
    if 64 - 64: ooOoO0o / i1IIi % iII111i
    if 84 - 84: OoOoOO00 - Oo0Ooo . ooOoO0o . IiII - Oo0Ooo
    if 99 - 99: I1Ii111
    if 75 - 75: ooOoO0o . OOooOOo / IiII
    if 84 - 84: OoooooooOO . I1IiiI / o0oOOo0O0Ooo
   iIIIi . use_count += 1
   I1IiO00Ooo0ooo0 , i1Ii1i11ii = self . decrypt ( I1IiO00Ooo0ooo0 , OoOOoOOoo , iIIIi ,
 OoOOoooO000 )
   if ( i1Ii1i11ii == False ) :
    if ( stats ) : stats [ self . packet_error ] . increment ( oo0oO0oOo0O )
    if ( lisp_flow_logging ) : self . log_flow ( False )
    return ( None )
    if 86 - 86: Oo0Ooo % OoOoOO00
    if 77 - 77: Ii1I % OOooOOo / oO0o
    if 91 - 91: OoO0O00 / OoO0O00 . II111iiii . ooOoO0o - I1IiiI
    if 23 - 23: I1IiiI
    if 7 - 7: iII111i % I1ii11iIi11i
    if 64 - 64: I1Ii111 + i11iIiiIii
  oo0O0 = struct . unpack ( "B" , I1IiO00Ooo0ooo0 [ 0 : 1 ] ) [ 0 ]
  self . inner_version = oo0O0 >> 4
  if ( OoOo00 and self . inner_version == 4 and oo0O0 >= 0x45 ) :
   iI1i11i = socket . ntohs ( struct . unpack ( "H" , I1IiO00Ooo0ooo0 [ 2 : 4 ] ) [ 0 ] )
   self . inner_tos = struct . unpack ( "B" , I1IiO00Ooo0ooo0 [ 1 : 2 ] ) [ 0 ]
   self . inner_ttl = struct . unpack ( "B" , I1IiO00Ooo0ooo0 [ 8 : 9 ] ) [ 0 ]
   self . inner_protocol = struct . unpack ( "B" , I1IiO00Ooo0ooo0 [ 9 : 10 ] ) [ 0 ]
   self . inner_source . afi = LISP_AFI_IPV4
   self . inner_dest . afi = LISP_AFI_IPV4
   self . inner_source . unpack_address ( I1IiO00Ooo0ooo0 [ 12 : 16 ] )
   self . inner_dest . unpack_address ( I1IiO00Ooo0ooo0 [ 16 : 20 ] )
   i1iIii = socket . ntohs ( struct . unpack ( "H" , I1IiO00Ooo0ooo0 [ 6 : 8 ] ) [ 0 ] )
   self . inner_is_fragment = ( i1iIii & 0x2000 or i1iIii != 0 )
   if ( self . inner_protocol == LISP_UDP_PROTOCOL ) :
    self . inner_sport = struct . unpack ( "H" , I1IiO00Ooo0ooo0 [ 20 : 22 ] ) [ 0 ]
    self . inner_sport = socket . ntohs ( self . inner_sport )
    self . inner_dport = struct . unpack ( "H" , I1IiO00Ooo0ooo0 [ 22 : 24 ] ) [ 0 ]
    self . inner_dport = socket . ntohs ( self . inner_dport )
    if 4 - 4: oO0o * I1IiiI - ooOoO0o / II111iiii + OOooOOo / i11iIiiIii
  elif ( OoOo00 and self . inner_version == 6 and oo0O0 >= 0x60 ) :
   iI1i11i = socket . ntohs ( struct . unpack ( "H" , I1IiO00Ooo0ooo0 [ 4 : 6 ] ) [ 0 ] ) + 40
   OoOooOo00o = struct . unpack ( "H" , I1IiO00Ooo0ooo0 [ 0 : 2 ] ) [ 0 ]
   self . inner_tos = ( socket . ntohs ( OoOooOo00o ) >> 4 ) & 0xff
   self . inner_ttl = struct . unpack ( "B" , I1IiO00Ooo0ooo0 [ 7 : 8 ] ) [ 0 ]
   self . inner_protocol = struct . unpack ( "B" , I1IiO00Ooo0ooo0 [ 6 : 7 ] ) [ 0 ]
   self . inner_source . afi = LISP_AFI_IPV6
   self . inner_dest . afi = LISP_AFI_IPV6
   self . inner_source . unpack_address ( I1IiO00Ooo0ooo0 [ 8 : 24 ] )
   self . inner_dest . unpack_address ( I1IiO00Ooo0ooo0 [ 24 : 40 ] )
   if ( self . inner_protocol == LISP_UDP_PROTOCOL ) :
    self . inner_sport = struct . unpack ( "H" , I1IiO00Ooo0ooo0 [ 40 : 42 ] ) [ 0 ]
    self . inner_sport = socket . ntohs ( self . inner_sport )
    self . inner_dport = struct . unpack ( "H" , I1IiO00Ooo0ooo0 [ 42 : 44 ] ) [ 0 ]
    self . inner_dport = socket . ntohs ( self . inner_dport )
    if 63 - 63: OoO0O00 + ooOoO0o
  elif ( OOoOoO ) :
   iI1i11i = len ( I1IiO00Ooo0ooo0 )
   self . inner_tos = 0
   self . inner_ttl = 0
   self . inner_protocol = 0
   self . inner_source . afi = LISP_AFI_MAC
   self . inner_dest . afi = LISP_AFI_MAC
   self . inner_dest . unpack_address ( self . swap_mac ( I1IiO00Ooo0ooo0 [ 0 : 6 ] ) )
   self . inner_source . unpack_address ( self . swap_mac ( I1IiO00Ooo0ooo0 [ 6 : 12 ] ) )
  elif ( self . lisp_header . get_instance_id ( ) == 0xffffff ) :
   if ( lisp_flow_logging ) : self . log_flow ( False )
   return ( self )
  else :
   self . packet_error = "bad-inner-version"
   if ( stats ) : stats [ self . packet_error ] . increment ( oo0oO0oOo0O )
   if 3 - 3: OoOoOO00 - I1Ii111 / oO0o . O0 * ooOoO0o / I1ii11iIi11i
   lprint ( "Cannot decode encapsulation, header version {}" . format ( hex ( oo0O0 ) ) )
   if 18 - 18: Ii1I
   I1IiO00Ooo0ooo0 = lisp_format_packet ( I1IiO00Ooo0ooo0 [ 0 : 20 ] )
   lprint ( "Packet header: {}" . format ( I1IiO00Ooo0ooo0 ) )
   if ( lisp_flow_logging and is_lisp_packet ) : self . log_flow ( False )
   return ( None )
   if 74 - 74: Ii1I + I1ii11iIi11i + I1IiiI
  self . inner_source . mask_len = self . inner_source . host_mask_len ( )
  self . inner_dest . mask_len = self . inner_dest . host_mask_len ( )
  self . inner_source . instance_id = IIiI1i
  self . inner_dest . instance_id = IIiI1i
  if 37 - 37: IiII
  if 97 - 97: o0oOOo0O0Ooo / IiII + OoOoOO00 + OoO0O00 % I1Ii111
  if 18 - 18: I1IiiI - OoOoOO00
  if 18 - 18: OOooOOo + OoO0O00 * oO0o - oO0o . I1ii11iIi11i * I11i
  if 95 - 95: I1ii11iIi11i / OoOoOO00
  if ( lisp_nonce_echoing and is_lisp_packet ) :
   i1II11iI1i = lisp_get_echo_nonce ( self . outer_source , None )
   if ( i1II11iI1i == None ) :
    Oo0oO = self . outer_source . print_address_no_iid ( )
    i1II11iI1i = lisp_echo_nonce ( Oo0oO )
    if 25 - 25: Ii1I * o0oOOo0O0Ooo * oO0o . I1IiiI
   o0oo000 = self . lisp_header . get_nonce ( )
   if ( self . lisp_header . is_e_bit_set ( ) ) :
    i1II11iI1i . receive_request ( lisp_ipc_socket , o0oo000 )
   elif ( i1II11iI1i . request_nonce_sent ) :
    i1II11iI1i . receive_echo ( lisp_ipc_socket , o0oo000 )
    if 87 - 87: OoO0O00
    if 27 - 27: Ii1I . o0oOOo0O0Ooo - OoOoOO00 . II111iiii % Oo0Ooo
    if 83 - 83: I11i + oO0o - iIii1I11I1II1 + II111iiii . iII111i
    if 76 - 76: OoooooooOO
    if 42 - 42: Ii1I * O0 / oO0o
    if 8 - 8: i1IIi + II111iiii / Ii1I + I1ii11iIi11i % Ii1I - iIii1I11I1II1
    if 29 - 29: Oo0Ooo + II111iiii
  if ( i1Ii1i11ii ) : self . packet += I1IiO00Ooo0ooo0 [ : iI1i11i ]
  if 95 - 95: oO0o
  if 48 - 48: I11i / iIii1I11I1II1 % II111iiii
  if 39 - 39: i1IIi . I1ii11iIi11i / I11i / I11i
  if 100 - 100: OoooooooOO - OoooooooOO + IiII
  if ( lisp_flow_logging and is_lisp_packet ) : self . log_flow ( False )
  return ( self )
  if 32 - 32: OoOoOO00 * o0oOOo0O0Ooo / OoooooooOO
  if 90 - 90: I1Ii111
 def swap_mac ( self , mac ) :
  return ( mac [ 1 ] + mac [ 0 ] + mac [ 3 ] + mac [ 2 ] + mac [ 5 ] + mac [ 4 ] )
  if 35 - 35: II111iiii / Ii1I
  if 79 - 79: OoOoOO00 + I1Ii111 * iII111i * Ii1I
 def strip_outer_headers ( self ) :
  oOO0OO0O = 16
  oOO0OO0O += 20 if ( self . outer_version == 4 ) else 40
  self . packet = self . packet [ oOO0OO0O : : ]
  return ( self )
  if 53 - 53: OOooOOo / Oo0Ooo
  if 10 - 10: I1ii11iIi11i . o0oOOo0O0Ooo
 def hash_ports ( self ) :
  I1IiO00Ooo0ooo0 = self . packet
  oo0O0 = self . inner_version
  OoOoo00Oo0OoO = 0
  if ( oo0O0 == 4 ) :
   o0o0 = struct . unpack ( "B" , I1IiO00Ooo0ooo0 [ 9 ] ) [ 0 ]
   if ( self . inner_is_fragment ) : return ( o0o0 )
   if ( o0o0 in [ 6 , 17 ] ) :
    OoOoo00Oo0OoO = o0o0
    OoOoo00Oo0OoO += struct . unpack ( "I" , I1IiO00Ooo0ooo0 [ 20 : 24 ] ) [ 0 ]
    OoOoo00Oo0OoO = ( OoOoo00Oo0OoO >> 16 ) ^ ( OoOoo00Oo0OoO & 0xffff )
    if 53 - 53: i1IIi
    if 59 - 59: o0oOOo0O0Ooo + I1IiiI % OoooooooOO - iIii1I11I1II1
  if ( oo0O0 == 6 ) :
   o0o0 = struct . unpack ( "B" , I1IiO00Ooo0ooo0 [ 6 ] ) [ 0 ]
   if ( o0o0 in [ 6 , 17 ] ) :
    OoOoo00Oo0OoO = o0o0
    OoOoo00Oo0OoO += struct . unpack ( "I" , I1IiO00Ooo0ooo0 [ 40 : 44 ] ) [ 0 ]
    OoOoo00Oo0OoO = ( OoOoo00Oo0OoO >> 16 ) ^ ( OoOoo00Oo0OoO & 0xffff )
    if 9 - 9: i1IIi - OoOoOO00
    if 57 - 57: iIii1I11I1II1 * Ii1I * iII111i / oO0o
  return ( OoOoo00Oo0OoO )
  if 46 - 46: Ii1I
  if 61 - 61: o0oOOo0O0Ooo / ooOoO0o - II111iiii
 def hash_packet ( self ) :
  OoOoo00Oo0OoO = self . inner_source . address ^ self . inner_dest . address
  OoOoo00Oo0OoO += self . hash_ports ( )
  if ( self . inner_version == 4 ) :
   OoOoo00Oo0OoO = ( OoOoo00Oo0OoO >> 16 ) ^ ( OoOoo00Oo0OoO & 0xffff )
  elif ( self . inner_version == 6 ) :
   OoOoo00Oo0OoO = ( OoOoo00Oo0OoO >> 64 ) ^ ( OoOoo00Oo0OoO & 0xffffffffffffffff )
   OoOoo00Oo0OoO = ( OoOoo00Oo0OoO >> 32 ) ^ ( OoOoo00Oo0OoO & 0xffffffff )
   OoOoo00Oo0OoO = ( OoOoo00Oo0OoO >> 16 ) ^ ( OoOoo00Oo0OoO & 0xffff )
   if 87 - 87: I1ii11iIi11i / I1IiiI
  self . udp_sport = 0xf000 | ( OoOoo00Oo0OoO & 0xfff )
  if 45 - 45: OoOoOO00 * ooOoO0o / OoooooooOO + OoO0O00 . I1Ii111 / OoO0O00
  if 64 - 64: Ii1I / i1IIi % I1IiiI - o0oOOo0O0Ooo
 def print_packet ( self , s_or_r , is_lisp_packet ) :
  if ( is_lisp_packet == False ) :
   iIii111Ii = "{} -> {}" . format ( self . inner_source . print_address ( ) ,
 self . inner_dest . print_address ( ) )
   dprint ( ( "{} {}, tos/ttl: {}/{}, length: {}, packet: {} ..." ) . format ( bold ( s_or_r , False ) ,
   # OOooOOo * Ii1I % I1Ii111 / IiII + iIii1I11I1II1 / I1IiiI
 green ( iIii111Ii , False ) , self . inner_tos ,
 self . inner_ttl , len ( self . packet ) ,
 lisp_format_packet ( self . packet [ 0 : 60 ] ) ) )
   return
   if 36 - 36: OoO0O00 + OoO0O00 + OoO0O00 % Oo0Ooo * iII111i
   if 98 - 98: I11i . I11i / Oo0Ooo / Ii1I / I1IiiI
  if ( s_or_r . find ( "Receive" ) != - 1 ) :
   oO0oi1I1iI1 = "decap"
   oO0oi1I1iI1 += "-vxlan" if self . udp_dport == LISP_VXLAN_DATA_PORT else ""
  else :
   oO0oi1I1iI1 = s_or_r
   if ( oO0oi1I1iI1 in [ "Send" , "Replicate" ] or oO0oi1I1iI1 . find ( "Fragment" ) != - 1 ) :
    oO0oi1I1iI1 = "encap"
    if 91 - 91: oO0o / iIii1I11I1II1 + oO0o
    if 28 - 28: iIii1I11I1II1 * I11i . I1IiiI
  ooo = "{} -> {}" . format ( self . outer_source . print_address_no_iid ( ) ,
 self . outer_dest . print_address_no_iid ( ) )
  if 20 - 20: i1IIi
  if 58 - 58: o0oOOo0O0Ooo / i11iIiiIii / O0 % I11i % I1IiiI
  if 86 - 86: IiII + OoOoOO00 / I1IiiI + I11i % I11i / i11iIiiIii
  if 12 - 12: OoOoOO00 + o0oOOo0O0Ooo . I1Ii111
  if 52 - 52: OoO0O00
  if ( self . lisp_header . get_instance_id ( ) == 0xffffff ) :
   OOooO = ( "{} LISP packet, outer RLOCs: {}, outer tos/ttl: " + "{}/{}, outer UDP: {} -> {}, " )
   if 4 - 4: Ii1I % I1ii11iIi11i + I11i - I1ii11iIi11i
   OOooO += bold ( "control-packet" , False ) + ": {} ..."
   if 98 - 98: Ii1I - O0 * oO0o * Ii1I * Ii1I
   dprint ( OOooO . format ( bold ( s_or_r , False ) , red ( ooo , False ) ,
 self . outer_tos , self . outer_ttl , self . udp_sport ,
 self . udp_dport , lisp_format_packet ( self . packet [ 0 : 56 ] ) ) )
   return
  else :
   OOooO = ( "{} LISP packet, outer RLOCs: {}, outer tos/ttl: " + "{}/{}, outer UDP: {} -> {}, inner EIDs: {}, " + "inner tos/ttl: {}/{}, length: {}, {}, packet: {} ..." )
   if 44 - 44: IiII + I11i
   if 66 - 66: oO0o
   if 34 - 34: iII111i % i11iIiiIii + i11iIiiIii - iII111i
   if 2 - 2: II111iiii + i1IIi
  if ( self . lisp_header . k_bits ) :
   if ( oO0oi1I1iI1 == "encap" ) : oO0oi1I1iI1 = "encrypt/encap"
   if ( oO0oi1I1iI1 == "decap" ) : oO0oi1I1iI1 = "decap/decrypt"
   if 68 - 68: OOooOOo + Ii1I
   if 58 - 58: IiII * Ii1I . i1IIi
  iIii111Ii = "{} -> {}" . format ( self . inner_source . print_address ( ) ,
 self . inner_dest . print_address ( ) )
  if 19 - 19: oO0o
  dprint ( OOooO . format ( bold ( s_or_r , False ) , red ( ooo , False ) ,
 self . outer_tos , self . outer_ttl , self . udp_sport , self . udp_dport ,
 green ( iIii111Ii , False ) , self . inner_tos , self . inner_ttl ,
 len ( self . packet ) , self . lisp_header . print_header ( oO0oi1I1iI1 ) ,
 lisp_format_packet ( self . packet [ 0 : 56 ] ) ) )
  if 85 - 85: ooOoO0o - I1IiiI / i1IIi / OoO0O00 / II111iiii
  if 94 - 94: iIii1I11I1II1 + IiII
 def print_eid_tuple ( self ) :
  return ( lisp_print_eid_tuple ( self . inner_source , self . inner_dest ) )
  if 44 - 44: OoO0O00 + I11i % OoO0O00 + i1IIi + iII111i + O0
  if 18 - 18: iIii1I11I1II1 % iIii1I11I1II1 % oO0o + I1IiiI % ooOoO0o / Ii1I
 def get_raw_socket ( self ) :
  IIiI1i = str ( self . lisp_header . get_instance_id ( ) )
  if ( IIiI1i == "0" ) : return ( None )
  if ( lisp_iid_to_interface . has_key ( IIiI1i ) == False ) : return ( None )
  if 36 - 36: OoOoOO00 . i11iIiiIii
  iIiiiIiIi = lisp_iid_to_interface [ IIiI1i ]
  i1I1iIi1IiI = iIiiiIiIi . get_socket ( )
  if ( i1I1iIi1IiI == None ) :
   i11ii111i1ii = bold ( "SO_BINDTODEVICE" , False )
   oO00O0o0oOOO = ( os . getenv ( "LISP_ENFORCE_BINDTODEVICE" ) != None )
   lprint ( "{} required for multi-tenancy support, {} packet" . format ( i11ii111i1ii , "drop" if oO00O0o0oOOO else "forward" ) )
   if 96 - 96: I1IiiI - iIii1I11I1II1
   if ( oO00O0o0oOOO ) : return ( None )
   if 25 - 25: OoooooooOO . Ii1I % iII111i . IiII
   if 67 - 67: OoooooooOO + I1Ii111 / ooOoO0o
  IIiI1i = bold ( IIiI1i , False )
  i1i11ii1Ii = bold ( iIiiiIiIi . device , False )
  dprint ( "Send packet on instance-id {} interface {}" . format ( IIiI1i , i1i11ii1Ii ) )
  return ( i1I1iIi1IiI )
  if 75 - 75: IiII / OoooooooOO . I1IiiI + I1Ii111 - II111iiii
  if 33 - 33: IiII / IiII . i11iIiiIii * I1ii11iIi11i + o0oOOo0O0Ooo
 def log_flow ( self , encap ) :
  global lisp_flow_log
  if 16 - 16: IiII
  II1 = os . path . exists ( "./log-flows" )
  if ( len ( lisp_flow_log ) == LISP_FLOW_LOG_SIZE or II1 ) :
   OOO = [ lisp_flow_log ]
   lisp_flow_log = [ ]
   threading . Thread ( target = lisp_write_flow_log , args = OOO ) . start ( )
   if ( II1 ) : os . system ( "rm ./log-flows" )
   return
   if 32 - 32: iIii1I11I1II1 * Oo0Ooo - oO0o
   if 72 - 72: IiII % i1IIi / iIii1I11I1II1
  III11I1 = datetime . datetime . now ( )
  lisp_flow_log . append ( [ III11I1 , encap , self . packet , self ] )
  if 95 - 95: O0 . OoO0O00
  if 89 - 89: i1IIi
 def print_flow ( self , ts , encap , packet ) :
  ts = ts . strftime ( "%m/%d/%y %H:%M:%S.%f" ) [ : - 3 ]
  I11II = "{}: {}" . format ( ts , "encap" if encap else "decap" )
  if 89 - 89: OoO0O00 . I1ii11iIi11i - i11iIiiIii * Oo0Ooo * i11iIiiIii
  ii1 = red ( self . outer_source . print_address_no_iid ( ) , False )
  iIII1IIi = red ( self . outer_dest . print_address_no_iid ( ) , False )
  Oo0 = green ( self . inner_source . print_address ( ) , False )
  oo0OOO0OOoOO = green ( self . inner_dest . print_address ( ) , False )
  if 97 - 97: i1IIi
  if ( self . lisp_header . get_instance_id ( ) == 0xffffff ) :
   I11II += " {}:{} -> {}:{}, LISP control message type {}\n"
   I11II = I11II . format ( ii1 , self . udp_sport , iIII1IIi , self . udp_dport ,
 self . inner_version )
   return ( I11II )
   if 46 - 46: I1ii11iIi11i
   if 30 - 30: OoO0O00 / O0 * o0oOOo0O0Ooo * I1Ii111 + OoooooooOO * iII111i
  if ( self . outer_dest . is_null ( ) == False ) :
   I11II += " {}:{} -> {}:{}, len/tos/ttl {}/{}/{}"
   I11II = I11II . format ( ii1 , self . udp_sport , iIII1IIi , self . udp_dport ,
 len ( packet ) , self . outer_tos , self . outer_ttl )
   if 23 - 23: I11i
   if 36 - 36: IiII . iII111i - i1IIi + I1Ii111
   if 54 - 54: OoooooooOO . oO0o - iII111i
   if 76 - 76: I1Ii111
   if 61 - 61: ooOoO0o / II111iiii * ooOoO0o * OoOoOO00 * I1Ii111 . i11iIiiIii
  if ( self . lisp_header . k_bits != 0 ) :
   I1I1i = "\n"
   if ( self . packet_error != "" ) :
    I1I1i = " ({})" . format ( self . packet_error ) + I1I1i
    if 42 - 42: iII111i
   I11II += ", encrypted" + I1I1i
   return ( I11II )
   if 77 - 77: i1IIi * oO0o % OoooooooOO + O0 * ooOoO0o
   if 28 - 28: I11i . OoooooooOO * OOooOOo + i11iIiiIii % I1IiiI . iIii1I11I1II1
   if 63 - 63: II111iiii - I11i . OoOoOO00
   if 8 - 8: I1IiiI * ooOoO0o / IiII + OoOoOO00 . IiII - OOooOOo
   if 80 - 80: iIii1I11I1II1 / oO0o * Oo0Ooo - OOooOOo * iII111i
  if ( self . outer_dest . is_null ( ) == False ) :
   packet = packet [ 36 : : ] if self . outer_version == 4 else packet [ 56 : : ]
   if 97 - 97: IiII - I11i / II111iiii
   if 26 - 26: iII111i + O0 * iII111i . i1IIi
  o0o0 = packet [ 9 ] if self . inner_version == 4 else packet [ 6 ]
  o0o0 = struct . unpack ( "B" , o0o0 ) [ 0 ]
  if 50 - 50: iIii1I11I1II1 - I11i % iII111i - Oo0Ooo
  I11II += " {} -> {}, len/tos/ttl/prot {}/{}/{}/{}"
  I11II = I11II . format ( Oo0 , oo0OOO0OOoOO , len ( packet ) , self . inner_tos ,
 self . inner_ttl , o0o0 )
  if 52 - 52: oO0o + Ii1I - I1ii11iIi11i * Ii1I . OOooOOo + I1Ii111
  if 43 - 43: I1IiiI % IiII % I1ii11iIi11i
  if 53 - 53: oO0o % OOooOOo % I1ii11iIi11i . I1Ii111 . I1Ii111 . iII111i
  if 73 - 73: iII111i / ooOoO0o + OoO0O00 / OoOoOO00 . II111iiii * Ii1I
  if ( o0o0 in [ 6 , 17 ] ) :
   IiII111I = packet [ 20 : 24 ] if self . inner_version == 4 else packet [ 40 : 44 ]
   if ( len ( IiII111I ) == 4 ) :
    IiII111I = socket . ntohl ( struct . unpack ( "I" , IiII111I ) [ 0 ] )
    I11II += ", ports {} -> {}" . format ( IiII111I >> 16 , IiII111I & 0xffff )
    if 62 - 62: i1IIi * iIii1I11I1II1 % oO0o % OoOoOO00 / OoooooooOO
  elif ( o0o0 == 1 ) :
   iI1111iiI1 = packet [ 26 : 28 ] if self . inner_version == 4 else packet [ 46 : 48 ]
   if ( len ( iI1111iiI1 ) == 2 ) :
    iI1111iiI1 = socket . ntohs ( struct . unpack ( "H" , iI1111iiI1 ) [ 0 ] )
    I11II += ", icmp-seq {}" . format ( iI1111iiI1 )
    if 71 - 71: o0oOOo0O0Ooo % OOooOOo + O0 / I1ii11iIi11i
    if 88 - 88: I11i / Oo0Ooo - I1Ii111
  if ( self . packet_error != "" ) :
   I11II += " ({})" . format ( self . packet_error )
   if 11 - 11: IiII % I1ii11iIi11i / ooOoO0o . i11iIiiIii + OOooOOo - II111iiii
  I11II += "\n"
  return ( I11II )
  if 50 - 50: i1IIi * oO0o / i11iIiiIii / i11iIiiIii / oO0o
  if 84 - 84: I1ii11iIi11i - iII111i + I1ii11iIi11i
 def is_trace ( self ) :
  IiII111I = [ self . inner_sport , self . inner_dport ]
  return ( self . inner_protocol == LISP_UDP_PROTOCOL and
 LISP_TRACE_PORT in IiII111I )
  if 63 - 63: I11i * ooOoO0o % II111iiii % I1Ii111 + I1IiiI * Oo0Ooo
  if 96 - 96: IiII
  if 99 - 99: iIii1I11I1II1 - ooOoO0o
  if 79 - 79: I1IiiI + oO0o % I11i % oO0o
  if 56 - 56: I1ii11iIi11i + oO0o . OoO0O00 + OoooooooOO * I1ii11iIi11i - O0
  if 35 - 35: OOooOOo . I11i . I1Ii111 - I11i % I11i + I1Ii111
  if 99 - 99: o0oOOo0O0Ooo + OOooOOo
  if 34 - 34: I1Ii111 * o0oOOo0O0Ooo . I1IiiI % i11iIiiIii
  if 61 - 61: iIii1I11I1II1 + oO0o * I11i - i1IIi % oO0o
  if 76 - 76: oO0o / OoOoOO00
  if 12 - 12: I1Ii111
  if 58 - 58: OoO0O00 + iIii1I11I1II1 % O0 + I11i + OoOoOO00 * OoooooooOO
  if 41 - 41: oO0o * I1IiiI
  if 76 - 76: oO0o . O0 * OoooooooOO + ooOoO0o
  if 53 - 53: Oo0Ooo
  if 3 - 3: IiII - OoooooooOO * OoooooooOO - I1IiiI / I1Ii111 * I1ii11iIi11i
LISP_N_BIT = 0x80000000
LISP_L_BIT = 0x40000000
LISP_E_BIT = 0x20000000
LISP_V_BIT = 0x10000000
LISP_I_BIT = 0x08000000
LISP_P_BIT = 0x04000000
LISP_K_BITS = 0x03000000
if 58 - 58: IiII % iIii1I11I1II1 / i11iIiiIii % o0oOOo0O0Ooo . I1Ii111 * iII111i
class lisp_data_header ( ) :
 def __init__ ( self ) :
  self . first_long = 0
  self . second_long = 0
  self . k_bits = 0
  if 32 - 32: OoooooooOO + o0oOOo0O0Ooo
  if 91 - 91: ooOoO0o - I1Ii111 * I1Ii111
 def print_header ( self , e_or_d ) :
  ooOOOo0 = lisp_hex_string ( self . first_long & 0xffffff )
  i11111 = lisp_hex_string ( self . second_long ) . zfill ( 8 )
  if 84 - 84: o0oOOo0O0Ooo
  OOooO = ( "{} LISP-header -> flags: {}{}{}{}{}{}{}{}, nonce: {}, " + "iid/lsb: {}" )
  if 67 - 67: I1ii11iIi11i - o0oOOo0O0Ooo
  return ( OOooO . format ( bold ( e_or_d , False ) ,
 "N" if ( self . first_long & LISP_N_BIT ) else "n" ,
 "L" if ( self . first_long & LISP_L_BIT ) else "l" ,
 "E" if ( self . first_long & LISP_E_BIT ) else "e" ,
 "V" if ( self . first_long & LISP_V_BIT ) else "v" ,
 "I" if ( self . first_long & LISP_I_BIT ) else "i" ,
 "P" if ( self . first_long & LISP_P_BIT ) else "p" ,
 "K" if ( self . k_bits in [ 2 , 3 ] ) else "k" ,
 "K" if ( self . k_bits in [ 1 , 3 ] ) else "k" ,
 ooOOOo0 , i11111 ) )
  if 40 - 40: I1IiiI / OoooooooOO + OoO0O00 * OoO0O00
  if 9 - 9: iIii1I11I1II1
 def encode ( self ) :
  O0000 = "II"
  ooOOOo0 = socket . htonl ( self . first_long )
  i11111 = socket . htonl ( self . second_long )
  if 53 - 53: I1Ii111
  III1Iiii1i11 = struct . pack ( O0000 , ooOOOo0 , i11111 )
  return ( III1Iiii1i11 )
  if 74 - 74: Oo0Ooo / I1Ii111 % I1Ii111 . IiII
  if 72 - 72: i1IIi
 def decode ( self , packet ) :
  O0000 = "II"
  I1 = struct . calcsize ( O0000 )
  if ( len ( packet ) < I1 ) : return ( False )
  if 21 - 21: i11iIiiIii * iII111i / ooOoO0o % iII111i * Oo0Ooo
  ooOOOo0 , i11111 = struct . unpack ( O0000 , packet [ : I1 ] )
  if 84 - 84: iIii1I11I1II1
  if 25 - 25: OoO0O00 * IiII - i1IIi - I11i * II111iiii
  self . first_long = socket . ntohl ( ooOOOo0 )
  self . second_long = socket . ntohl ( i11111 )
  self . k_bits = ( self . first_long & LISP_K_BITS ) >> 24
  return ( True )
  if 70 - 70: II111iiii + iII111i * OoOoOO00
  if 61 - 61: OOooOOo + OOooOOo + oO0o / iIii1I11I1II1
 def key_id ( self , key_id ) :
  self . first_long &= ~ ( 0x3 << 24 )
  self . first_long |= ( ( key_id & 0x3 ) << 24 )
  self . k_bits = key_id
  if 91 - 91: I1IiiI / II111iiii * OOooOOo
  if 94 - 94: II111iiii - iIii1I11I1II1 - iIii1I11I1II1
 def nonce ( self , nonce ) :
  self . first_long |= LISP_N_BIT
  self . first_long |= nonce
  if 83 - 83: I1ii11iIi11i * iIii1I11I1II1 + OoOoOO00 * i1IIi . OoooooooOO % Ii1I
  if 81 - 81: OoO0O00 - iIii1I11I1II1
 def map_version ( self , version ) :
  self . first_long |= LISP_V_BIT
  self . first_long |= version
  if 60 - 60: I1Ii111
  if 77 - 77: I1IiiI / I1ii11iIi11i
 def instance_id ( self , iid ) :
  if ( iid == 0 ) : return
  self . first_long |= LISP_I_BIT
  self . second_long &= 0xff
  self . second_long |= ( iid << 8 )
  if 95 - 95: I1Ii111 * i1IIi + oO0o
  if 40 - 40: II111iiii
 def get_instance_id ( self ) :
  return ( ( self . second_long >> 8 ) & 0xffffff )
  if 7 - 7: OOooOOo / OoO0O00
  if 88 - 88: i1IIi
 def locator_status_bits ( self , lsbs ) :
  self . first_long |= LISP_L_BIT
  self . second_long &= 0xffffff00
  self . second_long |= ( lsbs & 0xff )
  if 53 - 53: ooOoO0o . OOooOOo . o0oOOo0O0Ooo + oO0o
  if 17 - 17: iIii1I11I1II1 + i1IIi . I1ii11iIi11i + Ii1I % i1IIi . oO0o
 def is_request_nonce ( self , nonce ) :
  return ( nonce & 0x80000000 )
  if 57 - 57: oO0o
  if 92 - 92: II111iiii - OoO0O00 - OOooOOo % I1IiiI - OoOoOO00 * I1Ii111
 def request_nonce ( self , nonce ) :
  self . first_long |= LISP_E_BIT
  self . first_long |= LISP_N_BIT
  self . first_long |= ( nonce & 0xffffff )
  if 16 - 16: iIii1I11I1II1 + OoooooooOO - ooOoO0o * IiII
  if 37 - 37: iII111i
 def is_e_bit_set ( self ) :
  return ( self . first_long & LISP_E_BIT )
  if 15 - 15: o0oOOo0O0Ooo % OoO0O00 / iII111i
  if 36 - 36: OoO0O00 + OoO0O00 % Oo0Ooo + Oo0Ooo / i1IIi % i1IIi
 def get_nonce ( self ) :
  return ( self . first_long & 0xffffff )
  if 20 - 20: OOooOOo * oO0o
  if 91 - 91: OoO0O00 % i1IIi - iIii1I11I1II1 . OOooOOo
  if 31 - 31: oO0o % i1IIi . OoooooooOO - o0oOOo0O0Ooo + OoooooooOO
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
  if 45 - 45: OOooOOo + I11i / OoooooooOO - Ii1I + OoooooooOO
  if 42 - 42: iIii1I11I1II1 * I1IiiI * I1Ii111
 def send_ipc ( self , ipc_socket , ipc ) :
  O00oo0o0o0oo = "lisp-itr" if lisp_i_am_itr else "lisp-etr"
  I1I1I1 = "lisp-etr" if lisp_i_am_itr else "lisp-itr"
  ipc = lisp_command_ipc ( ipc , O00oo0o0o0oo )
  lisp_ipc ( ipc , ipc_socket , I1I1I1 )
  if 29 - 29: I1ii11iIi11i
  if 91 - 91: OoO0O00
 def send_request_ipc ( self , ipc_socket , nonce ) :
  nonce = lisp_hex_string ( nonce )
  OOOO0OoO0oOOoo0 = "nonce%R%{}%{}" . format ( self . rloc_str , nonce )
  self . send_ipc ( ipc_socket , OOOO0OoO0oOOoo0 )
  if 82 - 82: OoooooooOO - ooOoO0o * I1ii11iIi11i * ooOoO0o * O0 * iIii1I11I1II1
  if 31 - 31: ooOoO0o . OOooOOo % ooOoO0o
 def send_echo_ipc ( self , ipc_socket , nonce ) :
  nonce = lisp_hex_string ( nonce )
  OOOO0OoO0oOOoo0 = "nonce%E%{}%{}" . format ( self . rloc_str , nonce )
  self . send_ipc ( ipc_socket , OOOO0OoO0oOOoo0 )
  if 33 - 33: O0 * Ii1I - IiII . OoooooooOO + IiII
  if 20 - 20: I1Ii111 - OoOoOO00
 def receive_request ( self , ipc_socket , nonce ) :
  ooOO = self . request_nonce_rcvd
  self . request_nonce_rcvd = nonce
  self . last_request_nonce_rcvd = lisp_get_timestamp ( )
  if ( lisp_i_am_rtr ) : return
  if ( ooOO != nonce ) : self . send_request_ipc ( ipc_socket , nonce )
  if 5 - 5: OoOoOO00 % I1ii11iIi11i . ooOoO0o . I11i - i11iIiiIii
  if 39 - 39: i11iIiiIii + OOooOOo % iII111i + Ii1I * I1IiiI + I1Ii111
 def receive_echo ( self , ipc_socket , nonce ) :
  if ( self . request_nonce_sent != nonce ) : return
  self . last_echo_nonce_rcvd = lisp_get_timestamp ( )
  if ( self . echo_nonce_rcvd == nonce ) : return
  if 72 - 72: II111iiii + I1Ii111 * OOooOOo . I1IiiI
  self . echo_nonce_rcvd = nonce
  if ( lisp_i_am_rtr ) : return
  self . send_echo_ipc ( ipc_socket , nonce )
  if 51 - 51: iII111i
  if 81 - 81: O0
 def get_request_or_echo_nonce ( self , ipc_socket , remote_rloc ) :
  if 38 - 38: iII111i
  if 78 - 78: i11iIiiIii . IiII % OoooooooOO - IiII - IiII + Ii1I
  if 11 - 11: I11i
  if 20 - 20: O0 . i11iIiiIii * i1IIi % O0 . I1IiiI
  if 53 - 53: ooOoO0o / OoooooooOO - II111iiii
  if ( self . request_nonce_sent and self . echo_nonce_sent and remote_rloc ) :
   OoiiI1 = lisp_myrlocs [ 0 ] if remote_rloc . is_ipv4 ( ) else lisp_myrlocs [ 1 ]
   if 70 - 70: OoooooooOO . ooOoO0o / oO0o . oO0o - o0oOOo0O0Ooo
   if 29 - 29: I11i % OOooOOo - ooOoO0o
   if ( remote_rloc . address > OoiiI1 . address ) :
    OOOO0o = "exit"
    self . request_nonce_sent = None
   else :
    OOOO0o = "stay in"
    self . echo_nonce_sent = None
    if 26 - 26: O0 . I11i + iII111i - Ii1I . I11i
    if 2 - 2: I1ii11iIi11i . Oo0Ooo * OOooOOo % II111iiii . iII111i
   II1i1iI = bold ( "collision" , False )
   i1I1i = red ( OoiiI1 . print_address_no_iid ( ) , False )
   iI111I1 = red ( remote_rloc . print_address_no_iid ( ) , False )
   lprint ( "Echo nonce {}, {} -> {}, {} request-nonce mode" . format ( II1i1iI ,
 i1I1i , iI111I1 , OOOO0o ) )
   if 46 - 46: Ii1I
   if 42 - 42: iIii1I11I1II1
   if 32 - 32: Oo0Ooo - Ii1I . OoooooooOO - OoooooooOO - Oo0Ooo . iIii1I11I1II1
   if 34 - 34: Oo0Ooo
   if 31 - 31: i1IIi - I11i + I1Ii111 + ooOoO0o . ooOoO0o . O0
  if ( self . echo_nonce_sent != None ) :
   o0oo000 = self . echo_nonce_sent
   I1i11II = bold ( "Echoing" , False )
   lprint ( "{} nonce 0x{} to {}" . format ( I1i11II ,
 lisp_hex_string ( o0oo000 ) , red ( self . rloc_str , False ) ) )
   self . last_echo_nonce_sent = lisp_get_timestamp ( )
   self . echo_nonce_sent = None
   return ( o0oo000 )
   if 33 - 33: i1IIi / iII111i * OoO0O00
   if 2 - 2: oO0o . OOooOOo
   if 43 - 43: iIii1I11I1II1
   if 29 - 29: IiII % ooOoO0o + OoO0O00 . i1IIi + I1IiiI
   if 24 - 24: I1Ii111 / Ii1I * I1ii11iIi11i - OoooooooOO / I1IiiI . oO0o
   if 98 - 98: i1IIi - iII111i
   if 49 - 49: o0oOOo0O0Ooo . Ii1I . oO0o
  o0oo000 = self . request_nonce_sent
  i11iI11ii = self . last_request_nonce_sent
  if ( o0oo000 and i11iI11ii != None ) :
   if ( time . time ( ) - i11iI11ii >= LISP_NONCE_ECHO_INTERVAL ) :
    self . request_nonce_sent = None
    lprint ( "Stop request-nonce mode for {}, nonce 0x{}" . format ( red ( self . rloc_str , False ) , lisp_hex_string ( o0oo000 ) ) )
    if 85 - 85: i1IIi
    return ( None )
    if 64 - 64: OoOoOO00 % iIii1I11I1II1
    if 28 - 28: oO0o * o0oOOo0O0Ooo
    if 83 - 83: I1ii11iIi11i * I11i . OoooooooOO % Ii1I
    if 29 - 29: iII111i + II111iiii . i11iIiiIii . Ii1I - O0
    if 47 - 47: oO0o . I1ii11iIi11i - iIii1I11I1II1 % II111iiii / OoOoOO00 % OoooooooOO
    if 13 - 13: IiII . Oo0Ooo - I11i / oO0o - Oo0Ooo - I1IiiI
    if 84 - 84: II111iiii
    if 57 - 57: O0 * iIii1I11I1II1 % O0 . OoooooooOO
    if 53 - 53: Ii1I / I1IiiI * Ii1I + o0oOOo0O0Ooo + oO0o - Oo0Ooo
  if ( o0oo000 == None ) :
   o0oo000 = lisp_get_data_nonce ( )
   if ( self . recently_requested ( ) ) : return ( o0oo000 )
   if 16 - 16: OoO0O00 % I1Ii111 . i1IIi / I1ii11iIi11i - O0
   self . request_nonce_sent = o0oo000
   lprint ( "Start request-nonce mode for {}, nonce 0x{}" . format ( red ( self . rloc_str , False ) , lisp_hex_string ( o0oo000 ) ) )
   if 85 - 85: i1IIi . i1IIi
   self . last_new_request_nonce_sent = lisp_get_timestamp ( )
   if 16 - 16: I1IiiI - OOooOOo % Ii1I . OOooOOo + I1ii11iIi11i % i11iIiiIii
   if 59 - 59: i11iIiiIii - I11i
   if 59 - 59: OoooooooOO * o0oOOo0O0Ooo / I1Ii111
   if 75 - 75: o0oOOo0O0Ooo - OoooooooOO
   if 21 - 21: I1IiiI + iIii1I11I1II1 / i11iIiiIii / oO0o
   if ( lisp_i_am_itr == False ) : return ( o0oo000 | 0x80000000 )
   self . send_request_ipc ( ipc_socket , o0oo000 )
  else :
   lprint ( "Continue request-nonce mode for {}, nonce 0x{}" . format ( red ( self . rloc_str , False ) , lisp_hex_string ( o0oo000 ) ) )
   if 66 - 66: OoooooooOO + iII111i . IiII % i1IIi
   if 58 - 58: OOooOOo % iII111i * O0 + I1ii11iIi11i - IiII
   if 26 - 26: i1IIi / I1IiiI / I11i + I11i
   if 46 - 46: I1Ii111 % I1ii11iIi11i + Ii1I
   if 67 - 67: iIii1I11I1II1 . i11iIiiIii . i11iIiiIii . i11iIiiIii / I11i + ooOoO0o
   if 10 - 10: ooOoO0o - Oo0Ooo % II111iiii
   if 66 - 66: iIii1I11I1II1 . iIii1I11I1II1
  self . last_request_nonce_sent = lisp_get_timestamp ( )
  return ( o0oo000 | 0x80000000 )
  if 46 - 46: I1Ii111 * oO0o . Ii1I * I1Ii111 * iIii1I11I1II1 / I11i
  if 46 - 46: II111iiii % I1ii11iIi11i . OOooOOo . Oo0Ooo / i11iIiiIii + OoO0O00
 def request_nonce_timeout ( self ) :
  if ( self . request_nonce_sent == None ) : return ( False )
  if ( self . request_nonce_sent == self . echo_nonce_rcvd ) : return ( False )
  if 47 - 47: IiII . OOooOOo
  ooooOoO0O = time . time ( ) - self . last_request_nonce_sent
  O0oo00o000 = self . last_echo_nonce_rcvd
  return ( ooooOoO0O >= LISP_NONCE_ECHO_INTERVAL and O0oo00o000 == None )
  if 5 - 5: I1ii11iIi11i * Ii1I % I11i % II111iiii
  if 9 - 9: o0oOOo0O0Ooo % I1Ii111 + I11i
 def recently_requested ( self ) :
  O0oo00o000 = self . last_request_nonce_sent
  if ( O0oo00o000 == None ) : return ( False )
  if 55 - 55: OoO0O00 - I1ii11iIi11i
  ooooOoO0O = time . time ( ) - O0oo00o000
  return ( ooooOoO0O <= LISP_NONCE_ECHO_INTERVAL )
  if 38 - 38: iIii1I11I1II1 % IiII % OoO0O00 % O0 * iIii1I11I1II1 / I1Ii111
  if 65 - 65: OOooOOo - I1IiiI * I1Ii111
 def recently_echoed ( self ) :
  if ( self . request_nonce_sent == None ) : return ( True )
  if 99 - 99: I1IiiI
  if 64 - 64: I1ii11iIi11i * Ii1I * Oo0Ooo % IiII % ooOoO0o
  if 55 - 55: II111iiii - I1Ii111 - OOooOOo % Ii1I
  if 49 - 49: Oo0Ooo * I1Ii111
  O0oo00o000 = self . last_good_echo_nonce_rcvd
  if ( O0oo00o000 == None ) : O0oo00o000 = 0
  ooooOoO0O = time . time ( ) - O0oo00o000
  if ( ooooOoO0O <= LISP_NONCE_ECHO_INTERVAL ) : return ( True )
  if 53 - 53: Oo0Ooo / Ii1I + oO0o . iII111i + IiII
  if 19 - 19: Ii1I
  if 51 - 51: iIii1I11I1II1
  if 8 - 8: OoO0O00 / o0oOOo0O0Ooo % iII111i . i11iIiiIii . OoooooooOO . Ii1I
  if 8 - 8: OoO0O00 * Oo0Ooo
  if 41 - 41: Oo0Ooo / OoO0O00 / OoOoOO00 - i11iIiiIii - OoOoOO00
  O0oo00o000 = self . last_new_request_nonce_sent
  if ( O0oo00o000 == None ) : O0oo00o000 = 0
  ooooOoO0O = time . time ( ) - O0oo00o000
  return ( ooooOoO0O <= LISP_NONCE_ECHO_INTERVAL )
  if 4 - 4: I11i . IiII
  if 39 - 39: OOooOOo . Oo0Ooo - OoOoOO00 * i11iIiiIii
 def change_state ( self , rloc ) :
  if ( rloc . up_state ( ) and self . recently_echoed ( ) == False ) :
   iIIi111I1i1i = bold ( "down" , False )
   IiIii111III1 = lisp_print_elapsed ( self . last_good_echo_nonce_rcvd )
   lprint ( "Take {} {}, last good echo: {}" . format ( red ( self . rloc_str , False ) , iIIi111I1i1i , IiIii111III1 ) )
   if 39 - 39: i11iIiiIii - OOooOOo - I1Ii111 + OoooooooOO / I1IiiI / iIii1I11I1II1
   rloc . state = LISP_RLOC_NO_ECHOED_NONCE_STATE
   rloc . last_state_change = lisp_get_timestamp ( )
   return
   if 16 - 16: OoOoOO00 / Ii1I . I1Ii111 % i11iIiiIii % I1IiiI / OOooOOo
   if 85 - 85: I11i + I1Ii111
  if ( rloc . no_echoed_nonce_state ( ) == False ) : return
  if 11 - 11: I11i
  if ( self . recently_requested ( ) == False ) :
   OO0oO0O = bold ( "up" , False )
   lprint ( "Bring {} {}, retry request-nonce mode" . format ( red ( self . rloc_str , False ) , OO0oO0O ) )
   if 11 - 11: I1ii11iIi11i / O0 + II111iiii
   rloc . state = LISP_RLOC_UP_STATE
   rloc . last_state_change = lisp_get_timestamp ( )
   if 95 - 95: I1Ii111 + IiII * iIii1I11I1II1
   if 17 - 17: OoO0O00 - Oo0Ooo * O0 / Ii1I
   if 19 - 19: i1IIi - iIii1I11I1II1 . I11i
 def print_echo_nonce ( self ) :
  iiIIi1i111i = lisp_print_elapsed ( self . last_request_nonce_sent )
  iII = lisp_print_elapsed ( self . last_good_echo_nonce_rcvd )
  if 55 - 55: iIii1I11I1II1 . IiII - o0oOOo0O0Ooo . I1ii11iIi11i * i1IIi
  OoooO0 = lisp_print_elapsed ( self . last_echo_nonce_sent )
  o0OO00oO00 = lisp_print_elapsed ( self . last_request_nonce_rcvd )
  i1I1iIi1IiI = space ( 4 )
  if 65 - 65: I1ii11iIi11i . Ii1I / i11iIiiIii + O0 . IiII
  ooO000O = "Nonce-Echoing:\n"
  ooO000O += ( "{}Last request-nonce sent: {}\n{}Last echo-nonce " + "received: {}\n" ) . format ( i1I1iIi1IiI , iiIIi1i111i , i1I1iIi1IiI , iII )
  if 15 - 15: Oo0Ooo + iII111i + I1IiiI * o0oOOo0O0Ooo
  ooO000O += ( "{}Last request-nonce received: {}\n{}Last echo-nonce " + "sent: {}" ) . format ( i1I1iIi1IiI , o0OO00oO00 , i1I1iIi1IiI , OoooO0 )
  if 33 - 33: o0oOOo0O0Ooo * Oo0Ooo
  if 88 - 88: I1Ii111 % OOooOOo - OoOoOO00 - OoOoOO00 . I1IiiI
  return ( ooO000O )
  if 52 - 52: II111iiii / II111iiii / I1IiiI - I1Ii111
  if 91 - 91: I1IiiI + o0oOOo0O0Ooo % II111iiii + OoO0O00
  if 66 - 66: iIii1I11I1II1 * II111iiii % Oo0Ooo % I1IiiI - Ii1I
  if 59 - 59: IiII % oO0o
  if 21 - 21: OoooooooOO % OoOoOO00 - OoOoOO00 / I1ii11iIi11i / o0oOOo0O0Ooo
  if 15 - 15: ooOoO0o / ooOoO0o % OoooooooOO . I1Ii111
  if 93 - 93: I1ii11iIi11i * I1ii11iIi11i / OoooooooOO
  if 6 - 6: I1ii11iIi11i * Oo0Ooo + iIii1I11I1II1
  if 19 - 19: O0 % II111iiii * o0oOOo0O0Ooo
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
    if 27 - 27: OOooOOo * IiII / i11iIiiIii - oO0o + II111iiii
   self . local_private_key = random . randint ( 0 , 2 ** 128 - 1 )
   iIIIi = lisp_hex_string ( self . local_private_key ) . zfill ( 32 )
   self . curve25519 = curve25519 . Private ( iIIIi )
  else :
   self . local_private_key = random . randint ( 0 , 0x1fff )
   if 43 - 43: I1ii11iIi11i - II111iiii
  self . local_public_key = self . compute_public_key ( )
  self . remote_public_key = None
  self . shared_key = None
  self . encrypt_key = None
  self . icv_key = None
  self . icv = poly1305 if do_poly else hashlib . sha256
  self . iv = None
  self . get_iv ( )
  self . do_poly = do_poly
  if 56 - 56: I1ii11iIi11i . i1IIi / iII111i % oO0o / O0 * I11i
  if 98 - 98: O0 + iII111i
 def copy_keypair ( self , key ) :
  self . local_private_key = key . local_private_key
  self . local_public_key = key . local_public_key
  self . curve25519 = key . curve25519
  if 23 - 23: OoooooooOO . iIii1I11I1II1 / i1IIi
  if 31 - 31: Oo0Ooo - iIii1I11I1II1 / I11i . OoO0O00
 def get_iv ( self ) :
  if ( self . iv == None ) :
   self . iv = random . randint ( 0 , LISP_16_128_MASK )
  else :
   self . iv += 1
   if 74 - 74: Oo0Ooo - II111iiii - IiII
  O00oO0O = self . iv
  if ( self . cipher_suite == LISP_CS_25519_CHACHA ) :
   O00oO0O = struct . pack ( "Q" , O00oO0O & LISP_8_64_MASK )
  elif ( self . cipher_suite == LISP_CS_25519_GCM ) :
   IiII1II1 = struct . pack ( "I" , ( O00oO0O >> 64 ) & LISP_4_32_MASK )
   O0ooOo = struct . pack ( "Q" , O00oO0O & LISP_8_64_MASK )
   O00oO0O = IiII1II1 + O0ooOo
  else :
   O00oO0O = struct . pack ( "QQ" , O00oO0O >> 64 , O00oO0O & LISP_8_64_MASK )
  return ( O00oO0O )
  if 30 - 30: OoOoOO00 - i11iIiiIii
  if 94 - 94: OoOoOO00 % iII111i
 def key_length ( self , key ) :
  if ( type ( key ) != str ) : key = self . normalize_pub_key ( key )
  return ( len ( key ) / 2 )
  if 39 - 39: OoOoOO00 + I1Ii111 % O0
  if 26 - 26: ooOoO0o + OoOoOO00
 def print_key ( self , key ) :
  iii1 = self . normalize_pub_key ( key )
  return ( "0x{}...{}({})" . format ( iii1 [ 0 : 4 ] , iii1 [ - 4 : : ] , self . key_length ( iii1 ) ) )
  if 17 - 17: I1ii11iIi11i - iII111i % Oo0Ooo * O0 % O0 * OOooOOo
  if 6 - 6: I1Ii111
 def normalize_pub_key ( self , key ) :
  if ( type ( key ) == str ) :
   if ( self . curve25519 ) : return ( binascii . hexlify ( key ) )
   return ( key )
   if 46 - 46: II111iiii * I1Ii111
  key = lisp_hex_string ( key ) . zfill ( 256 )
  return ( key )
  if 23 - 23: i1IIi - O0
  if 6 - 6: ooOoO0o % OoooooooOO * I1Ii111 - IiII
 def print_keys ( self , do_bold = True ) :
  i1I1i = bold ( "local-key: " , False ) if do_bold else "local-key: "
  if ( self . local_public_key == None ) :
   i1I1i += "none"
  else :
   i1I1i += self . print_key ( self . local_public_key )
   if 24 - 24: I11i / iIii1I11I1II1 . OoooooooOO % OoOoOO00 . Ii1I
  iI111I1 = bold ( "remote-key: " , False ) if do_bold else "remote-key: "
  if ( self . remote_public_key == None ) :
   iI111I1 += "none"
  else :
   iI111I1 += self . print_key ( self . remote_public_key )
   if 73 - 73: I1Ii111
  i1IiIiiiii11 = "ECDH" if ( self . curve25519 ) else "DH"
  oooo = self . cipher_suite
  return ( "{} cipher-suite: {}, {}, {}" . format ( i1IiIiiiii11 , oooo , i1I1i , iI111I1 ) )
  if 65 - 65: Oo0Ooo . OoOoOO00 . OOooOOo % o0oOOo0O0Ooo + OoO0O00
  if 53 - 53: Oo0Ooo * I11i - Ii1I % OoO0O00 - OoOoOO00 - iII111i
 def compare_keys ( self , keys ) :
  if ( self . dh_g_value != keys . dh_g_value ) : return ( False )
  if ( self . dh_p_value != keys . dh_p_value ) : return ( False )
  if ( self . remote_public_key != keys . remote_public_key ) : return ( False )
  return ( True )
  if 21 - 21: II111iiii + OoO0O00 - Oo0Ooo + I1IiiI
  if 20 - 20: OoO0O00
 def compute_public_key ( self ) :
  if ( self . curve25519 ) : return ( self . curve25519 . get_public ( ) . public )
  if 64 - 64: IiII
  iIIIi = self . local_private_key
  OooooOOOO = self . dh_g_value
  oo000o = self . dh_p_value
  return ( int ( ( OooooOOOO ** iIIIi ) % oo000o ) )
  if 6 - 6: OOooOOo + I1ii11iIi11i + Oo0Ooo
  if 52 - 52: IiII * Oo0Ooo + OoooooooOO
 def compute_shared_key ( self , ed , print_shared = False ) :
  iIIIi = self . local_private_key
  oo0oooOoO0OOo = self . remote_public_key
  if 6 - 6: OoO0O00 . Ii1I + Ii1I . I11i
  o0OOO0oo0oOOo = bold ( "Compute {} shared-key" . format ( ed ) , False )
  lprint ( "{}, key-material: {}" . format ( o0OOO0oo0oOOo , self . print_keys ( ) ) )
  if 31 - 31: I1ii11iIi11i / iII111i + o0oOOo0O0Ooo . I1Ii111 / O0 . IiII
  if ( self . curve25519 ) :
   iIOoO0O00 = curve25519 . Public ( oo0oooOoO0OOo )
   self . shared_key = self . curve25519 . get_shared_key ( iIOoO0O00 )
  else :
   oo000o = self . dh_p_value
   self . shared_key = ( oo0oooOoO0OOo ** iIIIi ) % oo000o
   if 96 - 96: IiII - iII111i
   if 34 - 34: OOooOOo - I1ii11iIi11i * iII111i % Ii1I
   if 25 - 25: II111iiii + I1IiiI * ooOoO0o * I1ii11iIi11i . iII111i
   if 26 - 26: iII111i - ooOoO0o / OoooooooOO + o0oOOo0O0Ooo . Oo0Ooo
   if 75 - 75: O0 / OoOoOO00 . I1Ii111
   if 7 - 7: OoO0O00 * iII111i
   if 16 - 16: I1Ii111 . i1IIi . IiII
  if ( print_shared ) :
   iii1 = self . print_key ( self . shared_key )
   lprint ( "Computed shared-key: {}" . format ( iii1 ) )
   if 50 - 50: OoO0O00 - II111iiii * OoooooooOO - I1IiiI . O0 + O0
   if 80 - 80: o0oOOo0O0Ooo
   if 50 - 50: ooOoO0o
   if 81 - 81: i11iIiiIii * iIii1I11I1II1 / Oo0Ooo * OOooOOo
   if 83 - 83: i11iIiiIii - I1IiiI * i11iIiiIii
  self . compute_encrypt_icv_keys ( )
  if 59 - 59: iII111i - OoooooooOO / ooOoO0o + I1ii11iIi11i . o0oOOo0O0Ooo - iII111i
  if 29 - 29: oO0o
  if 26 - 26: O0 % OOooOOo - IiII . OOooOOo
  if 70 - 70: o0oOOo0O0Ooo + I11i / iII111i + ooOoO0o / I1IiiI
  self . rekey_count += 1
  self . last_rekey = lisp_get_timestamp ( )
  if 33 - 33: OoooooooOO . O0
  if 59 - 59: iIii1I11I1II1
 def compute_encrypt_icv_keys ( self ) :
  i1OOoO0OO0oO = hashlib . sha256
  if ( self . curve25519 ) :
   iii1iII1iii = self . shared_key
  else :
   iii1iII1iii = lisp_hex_string ( self . shared_key )
   if 97 - 97: I1Ii111 / OOooOOo - i11iIiiIii
   if 79 - 79: OoOoOO00 + iIii1I11I1II1 * i1IIi * ooOoO0o - I11i * OoO0O00
   if 78 - 78: iII111i % i11iIiiIii + iII111i + o0oOOo0O0Ooo
   if 22 - 22: I11i - o0oOOo0O0Ooo
   if 54 - 54: oO0o * OoO0O00 - iII111i * I11i + o0oOOo0O0Ooo - Ii1I
  i1I1i = self . local_public_key
  if ( type ( i1I1i ) != long ) : i1I1i = int ( binascii . hexlify ( i1I1i ) , 16 )
  iI111I1 = self . remote_public_key
  if ( type ( iI111I1 ) != long ) : iI111I1 = int ( binascii . hexlify ( iI111I1 ) , 16 )
  iI1I11 = "0001" + "lisp-crypto" + lisp_hex_string ( i1I1i ^ iI111I1 ) + "0100"
  if 92 - 92: I1IiiI / OoO0O00 - OOooOOo / i11iIiiIii
  IiIi1 = hmac . new ( iI1I11 , iii1iII1iii , i1OOoO0OO0oO ) . hexdigest ( )
  IiIi1 = int ( IiIi1 , 16 )
  if 45 - 45: ooOoO0o + II111iiii % iII111i
  if 55 - 55: ooOoO0o - oO0o % I1IiiI
  if 61 - 61: ooOoO0o
  if 22 - 22: iIii1I11I1II1 / ooOoO0o / I1IiiI - o0oOOo0O0Ooo
  II = ( IiIi1 >> 128 ) & LISP_16_128_MASK
  o0oO0ooo0 = IiIi1 & LISP_16_128_MASK
  self . encrypt_key = lisp_hex_string ( II ) . zfill ( 32 )
  Ii111ii1 = 32 if self . do_poly else 40
  self . icv_key = lisp_hex_string ( o0oO0ooo0 ) . zfill ( Ii111ii1 )
  if 80 - 80: iIii1I11I1II1 * iIii1I11I1II1 + Ii1I % iIii1I11I1II1 + II111iiii % O0
  if 79 - 79: OoooooooOO + I11i * I1Ii111
 def do_icv ( self , packet , nonce ) :
  if ( self . icv_key == None ) : return ( "" )
  if ( self . do_poly ) :
   O0oOO0o00OO = self . icv . poly1305aes
   II1i11i1iI1I = self . icv . binascii . hexlify
   nonce = II1i11i1iI1I ( nonce )
   oooOoO00O = O0oOO0o00OO ( self . encrypt_key , self . icv_key , nonce , packet )
   oooOoO00O = II1i11i1iI1I ( oooOoO00O )
  else :
   iIIIi = binascii . unhexlify ( self . icv_key )
   oooOoO00O = hmac . new ( iIIIi , packet , self . icv ) . hexdigest ( )
   oooOoO00O = oooOoO00O [ 0 : 40 ]
   if 42 - 42: IiII * iII111i . I1ii11iIi11i - iIii1I11I1II1 . ooOoO0o + I11i
  return ( oooOoO00O )
  if 35 - 35: iII111i . I1IiiI / II111iiii % IiII
  if 6 - 6: iIii1I11I1II1 * II111iiii
 def add_key_by_nonce ( self , nonce ) :
  if ( lisp_crypto_keys_by_nonce . has_key ( nonce ) == False ) :
   lisp_crypto_keys_by_nonce [ nonce ] = [ None , None , None , None ]
   if 38 - 38: I1IiiI
  lisp_crypto_keys_by_nonce [ nonce ] [ self . key_id ] = self
  if 42 - 42: o0oOOo0O0Ooo
  if 8 - 8: i11iIiiIii / ooOoO0o
 def delete_key_by_nonce ( self , nonce ) :
  if ( lisp_crypto_keys_by_nonce . has_key ( nonce ) == False ) : return
  lisp_crypto_keys_by_nonce . pop ( nonce )
  if 33 - 33: I1Ii111 * IiII - O0 + I1IiiI / IiII
  if 19 - 19: i1IIi % II111iiii
 def add_key_by_rloc ( self , addr_str , encap ) :
  O00OO0oO = lisp_crypto_keys_by_rloc_encap if encap else lisp_crypto_keys_by_rloc_decap
  if 30 - 30: i11iIiiIii % OoO0O00 * II111iiii - O0 . I1ii11iIi11i * iIii1I11I1II1
  if 48 - 48: o0oOOo0O0Ooo + I1ii11iIi11i / I1ii11iIi11i
  if ( O00OO0oO . has_key ( addr_str ) == False ) :
   O00OO0oO [ addr_str ] = [ None , None , None , None ]
   if 80 - 80: OoooooooOO
  O00OO0oO [ addr_str ] [ self . key_id ] = self
  if 65 - 65: oO0o * i1IIi . OoooooooOO % ooOoO0o
  if 87 - 87: i11iIiiIii * II111iiii - Ii1I % OoooooooOO
  if 55 - 55: i1IIi
  if 67 - 67: I1IiiI - OoO0O00
  if 60 - 60: i1IIi / iIii1I11I1II1 * oO0o + ooOoO0o + OoooooooOO + II111iiii
  if ( encap == False ) :
   lisp_write_ipc_decap_key ( addr_str , O00OO0oO [ addr_str ] )
   if 13 - 13: iIii1I11I1II1 - OOooOOo
   if 14 - 14: ooOoO0o
   if 75 - 75: iIii1I11I1II1 % ooOoO0o / OOooOOo - iII111i % i11iIiiIii
 def encode_lcaf ( self , rloc_addr ) :
  i11oO0OoO = self . normalize_pub_key ( self . local_public_key )
  i1II1IiIi111 = self . key_length ( i11oO0OoO )
  oooI1iIiii = ( 6 + i1II1IiIi111 + 2 )
  if ( rloc_addr != None ) : oooI1iIiii += rloc_addr . addr_length ( )
  if 87 - 87: II111iiii * OoO0O00 + Ii1I . Oo0Ooo - I1ii11iIi11i * oO0o
  I1IiO00Ooo0ooo0 = struct . pack ( "HBBBBHBB" , socket . htons ( LISP_AFI_LCAF ) , 0 , 0 ,
 LISP_LCAF_SECURITY_TYPE , 0 , socket . htons ( oooI1iIiii ) , 1 , 0 )
  if 15 - 15: II111iiii + O0
  if 87 - 87: OoO0O00 / ooOoO0o . IiII . II111iiii
  if 25 - 25: IiII * I1Ii111 - oO0o * i11iIiiIii * I1IiiI * OOooOOo
  if 56 - 56: OoooooooOO . I1IiiI . II111iiii % iII111i
  if 59 - 59: ooOoO0o % Oo0Ooo - oO0o + IiII
  if 33 - 33: Ii1I + OoOoOO00 - I1ii11iIi11i + iIii1I11I1II1 % i1IIi * IiII
  oooo = self . cipher_suite
  I1IiO00Ooo0ooo0 += struct . pack ( "BBH" , oooo , 0 , socket . htons ( i1II1IiIi111 ) )
  if 21 - 21: O0 * ooOoO0o % OoO0O00
  if 14 - 14: O0 / I1Ii111 / ooOoO0o + IiII - IiII
  if 10 - 10: O0 - I1ii11iIi11i / I1Ii111 % OoOoOO00 / OoooooooOO / Ii1I
  if 73 - 73: ooOoO0o + IiII % o0oOOo0O0Ooo . I1ii11iIi11i / OOooOOo . I1Ii111
  for oO in range ( 0 , i1II1IiIi111 * 2 , 16 ) :
   iIIIi = int ( i11oO0OoO [ oO : oO + 16 ] , 16 )
   I1IiO00Ooo0ooo0 += struct . pack ( "Q" , byte_swap_64 ( iIIIi ) )
   if 76 - 76: I11i . I1ii11iIi11i * OoooooooOO % iII111i
   if 24 - 24: OoooooooOO
   if 83 - 83: O0 / OoO0O00
   if 62 - 62: I11i
   if 73 - 73: Ii1I % OoO0O00 * OOooOOo
  if ( rloc_addr ) :
   I1IiO00Ooo0ooo0 += struct . pack ( "H" , socket . htons ( rloc_addr . afi ) )
   I1IiO00Ooo0ooo0 += rloc_addr . pack_address ( )
   if 84 - 84: Oo0Ooo
  return ( I1IiO00Ooo0ooo0 )
  if 18 - 18: OoooooooOO
  if 85 - 85: OoooooooOO . OoO0O00 . OoO0O00
 def decode_lcaf ( self , packet , lcaf_len ) :
  if 70 - 70: I11i
  if 72 - 72: I1Ii111 - ooOoO0o - I1IiiI - iII111i + OOooOOo - i1IIi
  if 45 - 45: OoO0O00 * I1IiiI
  if 61 - 61: iII111i % II111iiii / OoOoOO00 % I1ii11iIi11i . iIii1I11I1II1 % O0
  if ( lcaf_len == 0 ) :
   O0000 = "HHBBH"
   I1 = struct . calcsize ( O0000 )
   if ( len ( packet ) < I1 ) : return ( None )
   if 74 - 74: I1ii11iIi11i * oO0o + iII111i % O0
   o0O0O0O00o , Iii1IiIiIii , OO , Iii1IiIiIii , lcaf_len = struct . unpack ( O0000 , packet [ : I1 ] )
   if 84 - 84: Ii1I
   if 70 - 70: iIii1I11I1II1
   if ( OO != LISP_LCAF_SECURITY_TYPE ) :
    packet = packet [ lcaf_len + 6 : : ]
    return ( packet )
    if 45 - 45: O0 - OoOoOO00 % OOooOOo
   lcaf_len = socket . ntohs ( lcaf_len )
   packet = packet [ I1 : : ]
   if 100 - 100: i11iIiiIii . OOooOOo . i11iIiiIii
   if 81 - 81: I1IiiI
   if 76 - 76: O0 - ooOoO0o / Ii1I . Oo0Ooo - Ii1I
   if 75 - 75: ooOoO0o % OOooOOo / o0oOOo0O0Ooo % II111iiii
   if 30 - 30: o0oOOo0O0Ooo
   if 15 - 15: II111iiii - Ii1I - iII111i . oO0o / i11iIiiIii
  OO = LISP_LCAF_SECURITY_TYPE
  O0000 = "BBBBH"
  I1 = struct . calcsize ( O0000 )
  if ( len ( packet ) < I1 ) : return ( None )
  if 38 - 38: OoO0O00
  Ii , Iii1IiIiIii , oooo , Iii1IiIiIii , i1II1IiIi111 = struct . unpack ( O0000 ,
 packet [ : I1 ] )
  if 25 - 25: Oo0Ooo + o0oOOo0O0Ooo - OoO0O00
  if 57 - 57: II111iiii . i1IIi
  if 33 - 33: iII111i + Oo0Ooo % I11i . oO0o
  if 6 - 6: IiII + I1ii11iIi11i
  if 62 - 62: oO0o . I1Ii111 - OoooooooOO * II111iiii . i11iIiiIii
  if 13 - 13: iIii1I11I1II1 * o0oOOo0O0Ooo - i11iIiiIii
  packet = packet [ I1 : : ]
  i1II1IiIi111 = socket . ntohs ( i1II1IiIi111 )
  if ( len ( packet ) < i1II1IiIi111 ) : return ( None )
  if 63 - 63: OoooooooOO * I1Ii111
  if 50 - 50: Oo0Ooo - o0oOOo0O0Ooo % II111iiii . O0 . oO0o % II111iiii
  if 18 - 18: I11i % OoooooooOO + OoO0O00 / I11i
  if 37 - 37: i1IIi - Ii1I / IiII . II111iiii % ooOoO0o
  i11iIi1I1i1 = [ LISP_CS_25519_CBC , LISP_CS_25519_GCM , LISP_CS_25519_CHACHA ,
 LISP_CS_1024 ]
  if ( oooo not in i11iIi1I1i1 ) :
   lprint ( "Cipher-suites {} supported, received {}" . format ( i11iIi1I1i1 ,
 oooo ) )
   packet = packet [ i1II1IiIi111 : : ]
   return ( packet )
   if 92 - 92: O0
   if 38 - 38: II111iiii / iII111i - o0oOOo0O0Ooo
  self . cipher_suite = oooo
  if 92 - 92: Oo0Ooo % o0oOOo0O0Ooo - ooOoO0o / ooOoO0o / OoOoOO00
  if 84 - 84: OOooOOo
  if 4 - 4: IiII . I1Ii111 / Ii1I / iII111i + II111iiii
  if 32 - 32: i1IIi + iIii1I11I1II1 . I1ii11iIi11i . I11i - Ii1I
  if 55 - 55: I1ii11iIi11i / OoooooooOO - OoO0O00 / I1IiiI
  i11oO0OoO = 0
  for oO in range ( 0 , i1II1IiIi111 , 8 ) :
   iIIIi = byte_swap_64 ( struct . unpack ( "Q" , packet [ oO : oO + 8 ] ) [ 0 ] )
   i11oO0OoO <<= 64
   i11oO0OoO |= iIIIi
   if 23 - 23: I11i * I1Ii111 * o0oOOo0O0Ooo - I1IiiI % OoOoOO00 + o0oOOo0O0Ooo
  self . remote_public_key = i11oO0OoO
  if 41 - 41: IiII * OoooooooOO . ooOoO0o % i11iIiiIii
  if 11 - 11: iIii1I11I1II1 . I1Ii111 - Oo0Ooo / I11i + II111iiii
  if 29 - 29: I11i . i11iIiiIii + i1IIi - Ii1I + O0 . I1IiiI
  if 8 - 8: o0oOOo0O0Ooo
  if 78 - 78: i1IIi - Oo0Ooo
  if ( self . curve25519 ) :
   iIIIi = lisp_hex_string ( self . remote_public_key )
   iIIIi = iIIIi . zfill ( 64 )
   I1Ii11IIi = ""
   for oO in range ( 0 , len ( iIIIi ) , 2 ) :
    I1Ii11IIi += chr ( int ( iIIIi [ oO : oO + 2 ] , 16 ) )
    if 46 - 46: O0 + OOooOOo * IiII
   self . remote_public_key = I1Ii11IIi
   if 30 - 30: I11i + oO0o % I1IiiI % OoOoOO00
   if 40 - 40: i11iIiiIii % iIii1I11I1II1 % iIii1I11I1II1
  packet = packet [ i1II1IiIi111 : : ]
  return ( packet )
  if 79 - 79: i11iIiiIii
  if 20 - 20: i1IIi - IiII + IiII . OoooooooOO . I1IiiI + I11i
  if 10 - 10: IiII / Oo0Ooo
  if 82 - 82: I1ii11iIi11i / iII111i + I1ii11iIi11i + I1Ii111
  if 63 - 63: II111iiii % iIii1I11I1II1 * I1ii11iIi11i / ooOoO0o % I1IiiI % i1IIi
  if 87 - 87: o0oOOo0O0Ooo % i1IIi + oO0o - iIii1I11I1II1 . OOooOOo + i11iIiiIii
  if 83 - 83: I1ii11iIi11i * II111iiii . I1Ii111 - I11i
  if 46 - 46: OoO0O00 % I1ii11iIi11i
class lisp_thread ( ) :
 def __init__ ( self , name ) :
  self . thread_name = name
  self . thread_number = - 1
  self . number_of_pcap_threads = 0
  self . number_of_worker_threads = 0
  self . input_queue = Queue . Queue ( )
  self . input_stats = lisp_stats ( )
  self . lisp_packet = lisp_packet ( None )
  if 58 - 58: oO0o + IiII % iII111i - Ii1I - OOooOOo % Ii1I
  if 86 - 86: o0oOOo0O0Ooo
  if 15 - 15: oO0o - iIii1I11I1II1 - II111iiii - IiII % I1ii11iIi11i
  if 80 - 80: IiII * iII111i . i1IIi % Ii1I % I1ii11iIi11i + ooOoO0o
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
  if 50 - 50: OoooooooOO / OoO0O00 % iIii1I11I1II1
  if 41 - 41: I1ii11iIi11i % I1ii11iIi11i + IiII . iII111i % I1Ii111 * ooOoO0o
 def decode ( self , packet ) :
  O0000 = "BBBBQ"
  I1 = struct . calcsize ( O0000 )
  if ( len ( packet ) < I1 ) : return ( False )
  if 57 - 57: Ii1I . I1Ii111 . II111iiii % OoooooooOO * O0 + iIii1I11I1II1
  oo0OO0Oo000oo , i11iII1 , i1IiI1i , self . record_count , self . nonce = struct . unpack ( O0000 , packet [ : I1 ] )
  if 58 - 58: IiII
  if 30 - 30: iII111i
  self . type = oo0OO0Oo000oo >> 4
  if ( self . type == LISP_MAP_REQUEST ) :
   self . smr_bit = True if ( oo0OO0Oo000oo & 0x01 ) else False
   self . rloc_probe = True if ( oo0OO0Oo000oo & 0x02 ) else False
   self . smr_invoked_bit = True if ( i11iII1 & 0x40 ) else False
   if 44 - 44: OoOoOO00 . OOooOOo
  if ( self . type == LISP_ECM ) :
   self . ddt_bit = True if ( oo0OO0Oo000oo & 0x04 ) else False
   self . to_etr = True if ( oo0OO0Oo000oo & 0x02 ) else False
   self . to_ms = True if ( oo0OO0Oo000oo & 0x01 ) else False
   if 84 - 84: I1Ii111 - I11i * OoOoOO00
  if ( self . type == LISP_NAT_INFO ) :
   self . info_reply = True if ( oo0OO0Oo000oo & 0x08 ) else False
   if 52 - 52: iII111i . IiII - I1ii11iIi11i * iIii1I11I1II1 % o0oOOo0O0Ooo / ooOoO0o
  return ( True )
  if 18 - 18: OoOoOO00 % oO0o % OoO0O00 / iII111i
  if 88 - 88: iII111i * OOooOOo / i11iIiiIii / i1IIi
 def is_info_request ( self ) :
  return ( ( self . type == LISP_NAT_INFO and self . is_info_reply ( ) == False ) )
  if 76 - 76: Ii1I . I11i - OOooOOo + OoOoOO00 * OoO0O00 % I1Ii111
  if 24 - 24: iIii1I11I1II1 % Oo0Ooo % i11iIiiIii
 def is_info_reply ( self ) :
  return ( True if self . info_reply else False )
  if 55 - 55: iII111i
  if 19 - 19: OoooooooOO / OOooOOo * i11iIiiIii - I1IiiI
 def is_rloc_probe ( self ) :
  return ( True if self . rloc_probe else False )
  if 99 - 99: OoO0O00 % O0 . I1Ii111 - I1ii11iIi11i . Oo0Ooo / OoOoOO00
  if 60 - 60: I1ii11iIi11i
 def is_smr ( self ) :
  return ( True if self . smr_bit else False )
  if 78 - 78: oO0o + II111iiii
  if 55 - 55: OoooooooOO
 def is_smr_invoked ( self ) :
  return ( True if self . smr_invoked_bit else False )
  if 90 - 90: I1IiiI
  if 4 - 4: OOooOOo % ooOoO0o - OOooOOo - o0oOOo0O0Ooo
 def is_ddt ( self ) :
  return ( True if self . ddt_bit else False )
  if 30 - 30: IiII
  if 34 - 34: oO0o - II111iiii - o0oOOo0O0Ooo + iII111i + I1Ii111
 def is_to_etr ( self ) :
  return ( True if self . to_etr else False )
  if 70 - 70: OoooooooOO + OoO0O00 * Oo0Ooo
  if 20 - 20: i11iIiiIii - II111iiii - ooOoO0o % oO0o . ooOoO0o
 def is_to_ms ( self ) :
  return ( True if self . to_ms else False )
  if 50 - 50: iIii1I11I1II1 + I1Ii111 - I11i - OoooooooOO
  if 84 - 84: OoOoOO00 - I11i
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
  if 85 - 85: I1IiiI * iIii1I11I1II1 . iII111i / iII111i
  if 43 - 43: I1IiiI
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
  if 80 - 80: IiII % OoooooooOO - IiII
  if 27 - 27: I1Ii111 - o0oOOo0O0Ooo * I1ii11iIi11i - I1IiiI
 def print_map_register ( self ) :
  IIIiIIi111 = lisp_hex_string ( self . xtr_id )
  if 77 - 77: I1IiiI / I1Ii111
  OOooO = ( "{} -> flags: {}{}{}{}{}{}{}{}{}, record-count: " +
 "{}, nonce: 0x{}, key/alg-id: {}/{}{}, auth-len: {}, xtr-id: " +
 "0x{}, site-id: {}" )
  if 65 - 65: I1ii11iIi11i * O0 . OoooooooOO * I11i / IiII
  lprint ( OOooO . format ( bold ( "Map-Register" , False ) , "P" if self . proxy_reply_requested else "p" ,
  # iIii1I11I1II1 . Ii1I - I1ii11iIi11i % i11iIiiIii + OoOoOO00 / OOooOOo
 "S" if self . lisp_sec_present else "s" ,
 "I" if self . xtr_id_present else "i" ,
 "T" if self . use_ttl_for_timeout else "t" ,
 "R" if self . merge_register_requested else "r" ,
 "M" if self . mobile_node else "m" ,
 "N" if self . map_notify_requested else "n" ,
 "F" if self . map_register_refresh else "f" ,
 "E" if self . encrypt_bit else "e" ,
 self . record_count , lisp_hex_string ( self . nonce ) , self . key_id ,
 self . alg_id , " (sha1)" if ( self . key_id == LISP_SHA_1_96_ALG_ID ) else ( " (sha2)" if ( self . key_id == LISP_SHA_256_128_ALG_ID ) else "" ) , self . auth_len , IIIiIIi111 , self . site_id ) )
  if 74 - 74: OoooooooOO - i11iIiiIii
  if 42 - 42: I1ii11iIi11i / ooOoO0o . iIii1I11I1II1
  if 5 - 5: OoooooooOO
  if 21 - 21: OOooOOo
 def encode ( self ) :
  ooOOOo0 = ( LISP_MAP_REGISTER << 28 ) | self . record_count
  if ( self . proxy_reply_requested ) : ooOOOo0 |= 0x08000000
  if ( self . lisp_sec_present ) : ooOOOo0 |= 0x04000000
  if ( self . xtr_id_present ) : ooOOOo0 |= 0x02000000
  if ( self . map_register_refresh ) : ooOOOo0 |= 0x1000
  if ( self . use_ttl_for_timeout ) : ooOOOo0 |= 0x800
  if ( self . merge_register_requested ) : ooOOOo0 |= 0x400
  if ( self . mobile_node ) : ooOOOo0 |= 0x200
  if ( self . map_notify_requested ) : ooOOOo0 |= 0x100
  if ( self . encryption_key_id != None ) :
   ooOOOo0 |= 0x2000
   ooOOOo0 |= self . encryption_key_id << 14
   if 71 - 71: OOooOOo + oO0o . I11i
   if 9 - 9: OoO0O00
   if 13 - 13: I11i . OoO0O00
   if 73 - 73: Ii1I * OoooooooOO * I11i - i11iIiiIii
   if 58 - 58: o0oOOo0O0Ooo + OoOoOO00 - IiII
  if ( self . alg_id == LISP_NONE_ALG_ID ) :
   self . auth_len = 0
  else :
   if ( self . alg_id == LISP_SHA_1_96_ALG_ID ) :
    self . auth_len = LISP_SHA1_160_AUTH_DATA_LEN
    if 82 - 82: Ii1I . iIii1I11I1II1 / Ii1I / oO0o % iIii1I11I1II1
   if ( self . alg_id == LISP_SHA_256_128_ALG_ID ) :
    self . auth_len = LISP_SHA2_256_AUTH_DATA_LEN
    if 34 - 34: OOooOOo
    if 99 - 99: II111iiii
    if 13 - 13: I11i - ooOoO0o + iII111i % I11i . iII111i - i1IIi
  I1IiO00Ooo0ooo0 = struct . pack ( "I" , socket . htonl ( ooOOOo0 ) )
  I1IiO00Ooo0ooo0 += struct . pack ( "QBBH" , self . nonce , self . key_id , self . alg_id ,
 socket . htons ( self . auth_len ) )
  if 67 - 67: OOooOOo . i11iIiiIii + ooOoO0o . iIii1I11I1II1
  I1IiO00Ooo0ooo0 = self . zero_auth ( I1IiO00Ooo0ooo0 )
  return ( I1IiO00Ooo0ooo0 )
  if 28 - 28: I1IiiI + I1IiiI + I1Ii111
  if 22 - 22: I1Ii111
 def zero_auth ( self , packet ) :
  oOO0OO0O = struct . calcsize ( "I" ) + struct . calcsize ( "QHH" )
  O0oooOoO = ""
  II1iiiiI1Ii11 = 0
  if ( self . alg_id == LISP_NONE_ALG_ID ) : return ( packet )
  if ( self . alg_id == LISP_SHA_1_96_ALG_ID ) :
   O0oooOoO = struct . pack ( "QQI" , 0 , 0 , 0 )
   II1iiiiI1Ii11 = struct . calcsize ( "QQI" )
   if 69 - 69: I11i / i1IIi / oO0o . I1Ii111
  if ( self . alg_id == LISP_SHA_256_128_ALG_ID ) :
   O0oooOoO = struct . pack ( "QQQQ" , 0 , 0 , 0 , 0 )
   II1iiiiI1Ii11 = struct . calcsize ( "QQQQ" )
   if 41 - 41: oO0o * IiII + I1IiiI
  packet = packet [ 0 : oOO0OO0O ] + O0oooOoO + packet [ oOO0OO0O + II1iiiiI1Ii11 : : ]
  return ( packet )
  if 7 - 7: ooOoO0o % OoO0O00 + OoooooooOO
  if 25 - 25: iII111i . OoO0O00 / iIii1I11I1II1
 def encode_auth ( self , packet ) :
  oOO0OO0O = struct . calcsize ( "I" ) + struct . calcsize ( "QHH" )
  II1iiiiI1Ii11 = self . auth_len
  O0oooOoO = self . auth_data
  packet = packet [ 0 : oOO0OO0O ] + O0oooOoO + packet [ oOO0OO0O + II1iiiiI1Ii11 : : ]
  return ( packet )
  if 56 - 56: o0oOOo0O0Ooo % i11iIiiIii . Ii1I * iIii1I11I1II1 - Oo0Ooo
  if 77 - 77: OoooooooOO
 def decode ( self , packet ) :
  O00Ooo00 = packet
  O0000 = "I"
  I1 = struct . calcsize ( O0000 )
  if ( len ( packet ) < I1 ) : return ( [ None , None ] )
  if 71 - 71: i11iIiiIii / i1IIi + OoOoOO00
  ooOOOo0 = struct . unpack ( O0000 , packet [ : I1 ] )
  ooOOOo0 = socket . ntohl ( ooOOOo0 [ 0 ] )
  packet = packet [ I1 : : ]
  if 23 - 23: i11iIiiIii
  O0000 = "QBBH"
  I1 = struct . calcsize ( O0000 )
  if ( len ( packet ) < I1 ) : return ( [ None , None ] )
  if 88 - 88: II111iiii - iII111i / OoooooooOO
  self . nonce , self . key_id , self . alg_id , self . auth_len = struct . unpack ( O0000 , packet [ : I1 ] )
  if 71 - 71: I1ii11iIi11i
  if 19 - 19: Oo0Ooo - OoO0O00 + i11iIiiIii / iIii1I11I1II1
  self . auth_len = socket . ntohs ( self . auth_len )
  self . proxy_reply_requested = True if ( ooOOOo0 & 0x08000000 ) else False
  if 1 - 1: IiII % i1IIi
  self . lisp_sec_present = True if ( ooOOOo0 & 0x04000000 ) else False
  self . xtr_id_present = True if ( ooOOOo0 & 0x02000000 ) else False
  self . use_ttl_for_timeout = True if ( ooOOOo0 & 0x800 ) else False
  self . map_register_refresh = True if ( ooOOOo0 & 0x1000 ) else False
  self . merge_register_requested = True if ( ooOOOo0 & 0x400 ) else False
  self . mobile_node = True if ( ooOOOo0 & 0x200 ) else False
  self . map_notify_requested = True if ( ooOOOo0 & 0x100 ) else False
  self . record_count = ooOOOo0 & 0xff
  if 41 - 41: OoO0O00 * OoO0O00 / iII111i + I1ii11iIi11i . o0oOOo0O0Ooo
  if 84 - 84: i11iIiiIii + OoO0O00 * I1IiiI + I1ii11iIi11i / Ii1I
  if 80 - 80: I1ii11iIi11i
  if 67 - 67: II111iiii
  self . encrypt_bit = True if ooOOOo0 & 0x2000 else False
  if ( self . encrypt_bit ) :
   self . encryption_key_id = ( ooOOOo0 >> 14 ) & 0x7
   if 2 - 2: o0oOOo0O0Ooo - O0 * Ii1I % IiII
   if 64 - 64: i1IIi . ooOoO0o
   if 7 - 7: oO0o . iII111i - iII111i / I1Ii111 % Oo0Ooo
   if 61 - 61: oO0o - I1ii11iIi11i / iII111i % I1ii11iIi11i + OoO0O00 / Oo0Ooo
   if 10 - 10: i11iIiiIii / OoOoOO00
  if ( self . xtr_id_present ) :
   if ( self . decode_xtr_id ( O00Ooo00 ) == False ) : return ( [ None , None ] )
   if 27 - 27: I1IiiI / OoooooooOO
   if 74 - 74: I1ii11iIi11i % I1Ii111 - OoO0O00 * I11i . OoooooooOO * OoO0O00
  packet = packet [ I1 : : ]
  if 99 - 99: OoOoOO00 . iII111i - OoooooooOO - O0
  if 6 - 6: OOooOOo
  if 3 - 3: O0 - I1Ii111 * Ii1I * OOooOOo / Ii1I
  if 58 - 58: Ii1I * iIii1I11I1II1 + ooOoO0o . ooOoO0o
  if ( self . auth_len != 0 ) :
   if ( len ( packet ) < self . auth_len ) : return ( [ None , None ] )
   if 74 - 74: ooOoO0o - o0oOOo0O0Ooo * IiII % ooOoO0o
   if ( self . alg_id not in ( LISP_NONE_ALG_ID , LISP_SHA_1_96_ALG_ID ,
 LISP_SHA_256_128_ALG_ID ) ) :
    lprint ( "Invalid authentication alg-id: {}" . format ( self . alg_id ) )
    return ( [ None , None ] )
    if 93 - 93: iIii1I11I1II1 / OoOoOO00 % Oo0Ooo * I1Ii111 - OoO0O00 - o0oOOo0O0Ooo
    if 44 - 44: OoooooooOO
   II1iiiiI1Ii11 = self . auth_len
   if ( self . alg_id == LISP_SHA_1_96_ALG_ID ) :
    I1 = struct . calcsize ( "QQI" )
    if ( II1iiiiI1Ii11 < I1 ) :
     lprint ( "Invalid sha1-96 authentication length" )
     return ( [ None , None ] )
     if 82 - 82: OoOoOO00 . OoOoOO00
    IIiIiIii11I1 , oo0O000OooO0 , IIIi1Iii11I = struct . unpack ( "QQI" , packet [ : II1iiiiI1Ii11 ] )
    i1I = ""
   elif ( self . alg_id == LISP_SHA_256_128_ALG_ID ) :
    I1 = struct . calcsize ( "QQQQ" )
    if ( II1iiiiI1Ii11 < I1 ) :
     lprint ( "Invalid sha2-256 authentication length" )
     return ( [ None , None ] )
     if 86 - 86: OoooooooOO - IiII - I11i * II111iiii
    IIiIiIii11I1 , oo0O000OooO0 , IIIi1Iii11I , i1I = struct . unpack ( "QQQQ" ,
 packet [ : II1iiiiI1Ii11 ] )
   else :
    lprint ( "Unsupported authentication alg-id value {}" . format ( self . alg_id ) )
    if 61 - 61: II111iiii / i11iIiiIii - OoOoOO00
    return ( [ None , None ] )
    if 32 - 32: i11iIiiIii
   self . auth_data = lisp_concat_auth_data ( self . alg_id , IIiIiIii11I1 , oo0O000OooO0 ,
 IIIi1Iii11I , i1I )
   O00Ooo00 = self . zero_auth ( O00Ooo00 )
   packet = packet [ self . auth_len : : ]
   if 57 - 57: iIii1I11I1II1
  return ( [ O00Ooo00 , packet ] )
  if 99 - 99: iII111i % o0oOOo0O0Ooo + iIii1I11I1II1
  if 51 - 51: i1IIi % o0oOOo0O0Ooo - oO0o - IiII
 def encode_xtr_id ( self , packet ) :
  i11IIII = self . xtr_id >> 64
  i1I1 = self . xtr_id & 0xffffffffffffffff
  i11IIII = byte_swap_64 ( i11IIII )
  i1I1 = byte_swap_64 ( i1I1 )
  oO0000oo00O = byte_swap_64 ( self . site_id )
  packet += struct . pack ( "QQQ" , i11IIII , i1I1 , oO0000oo00O )
  return ( packet )
  if 99 - 99: II111iiii
  if 56 - 56: I1IiiI
 def decode_xtr_id ( self , packet ) :
  I1 = struct . calcsize ( "QQQ" )
  if ( len ( packet ) < I1 ) : return ( [ None , None ] )
  packet = packet [ len ( packet ) - I1 : : ]
  i11IIII , i1I1 , oO0000oo00O = struct . unpack ( "QQQ" ,
 packet [ : I1 ] )
  i11IIII = byte_swap_64 ( i11IIII )
  i1I1 = byte_swap_64 ( i1I1 )
  self . xtr_id = ( i11IIII << 64 ) | i1I1
  self . site_id = byte_swap_64 ( oO0000oo00O )
  return ( True )
  if 84 - 84: OoooooooOO
  if 91 - 91: iIii1I11I1II1 / iIii1I11I1II1
  if 10 - 10: OoooooooOO . II111iiii
  if 3 - 3: O0 + OoOoOO00 % I11i * Ii1I
  if 13 - 13: Ii1I - oO0o
  if 55 - 55: IiII % I1ii11iIi11i + O0 . o0oOOo0O0Ooo / Ii1I * iII111i
  if 63 - 63: I1Ii111 - oO0o - iII111i - ooOoO0o / oO0o + OoO0O00
  if 94 - 94: IiII / I1IiiI . II111iiii
  if 32 - 32: oO0o . OOooOOo % OOooOOo . OoOoOO00
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
  if 82 - 82: OoO0O00
  if 78 - 78: II111iiii / I11i - i11iIiiIii + I1ii11iIi11i * Oo0Ooo
 def print_notify ( self ) :
  O0oooOoO = binascii . hexlify ( self . auth_data )
  if ( self . alg_id == LISP_SHA_1_96_ALG_ID and len ( O0oooOoO ) != 40 ) :
   O0oooOoO = self . auth_data
  elif ( self . alg_id == LISP_SHA_256_128_ALG_ID and len ( O0oooOoO ) != 64 ) :
   O0oooOoO = self . auth_data
   if 17 - 17: OoOoOO00
  OOooO = ( "{} -> record-count: {}, nonce: 0x{}, key/alg-id: " +
 "{}{}{}, auth-len: {}, auth-data: {}" )
  lprint ( OOooO . format ( bold ( "Map-Notify-Ack" , False ) if self . map_notify_ack else bold ( "Map-Notify" , False ) ,
  # O0 - oO0o * i1IIi + I1IiiI . oO0o
 self . record_count , lisp_hex_string ( self . nonce ) , self . key_id ,
 self . alg_id , " (sha1)" if ( self . key_id == LISP_SHA_1_96_ALG_ID ) else ( " (sha2)" if ( self . key_id == LISP_SHA_256_128_ALG_ID ) else "" ) , self . auth_len , O0oooOoO ) )
  if 4 - 4: i1IIi % o0oOOo0O0Ooo % oO0o . i1IIi
  if 85 - 85: IiII . Ii1I * o0oOOo0O0Ooo % Oo0Ooo % II111iiii + I1Ii111
  if 85 - 85: II111iiii / ooOoO0o * II111iiii
  if 43 - 43: o0oOOo0O0Ooo / O0 + i1IIi - I1ii11iIi11i % i11iIiiIii
 def zero_auth ( self , packet ) :
  if ( self . alg_id == LISP_NONE_ALG_ID ) : return ( packet )
  if ( self . alg_id == LISP_SHA_1_96_ALG_ID ) :
   O0oooOoO = struct . pack ( "QQI" , 0 , 0 , 0 )
   if 69 - 69: OOooOOo % I1ii11iIi11i / OoOoOO00 . OOooOOo - IiII
  if ( self . alg_id == LISP_SHA_256_128_ALG_ID ) :
   O0oooOoO = struct . pack ( "QQQQ" , 0 , 0 , 0 , 0 )
   if 74 - 74: OoO0O00 - o0oOOo0O0Ooo - IiII . O0 % ooOoO0o
  packet += O0oooOoO
  return ( packet )
  if 32 - 32: OoOoOO00 . OoO0O00 / Oo0Ooo . i11iIiiIii
  if 9 - 9: I11i - II111iiii + I1Ii111 / oO0o % I1ii11iIi11i
 def encode ( self , eid_records , password ) :
  if ( self . map_notify_ack ) :
   ooOOOo0 = ( LISP_MAP_NOTIFY_ACK << 28 ) | self . record_count
  else :
   ooOOOo0 = ( LISP_MAP_NOTIFY << 28 ) | self . record_count
   if 17 - 17: iIii1I11I1II1 - ooOoO0o
  I1IiO00Ooo0ooo0 = struct . pack ( "I" , socket . htonl ( ooOOOo0 ) )
  I1IiO00Ooo0ooo0 += struct . pack ( "QBBH" , self . nonce , self . key_id , self . alg_id ,
 socket . htons ( self . auth_len ) )
  if 99 - 99: Oo0Ooo + I1Ii111 % ooOoO0o - o0oOOo0O0Ooo
  if ( self . alg_id == LISP_NONE_ALG_ID ) :
   self . packet = I1IiO00Ooo0ooo0 + eid_records
   return ( self . packet )
   if 52 - 52: I1ii11iIi11i
   if 93 - 93: iII111i . i11iIiiIii
   if 24 - 24: OOooOOo . OoO0O00 + I1Ii111 . oO0o - I1ii11iIi11i % iII111i
   if 49 - 49: O0 . Oo0Ooo / Ii1I
   if 29 - 29: I1ii11iIi11i / oO0o * O0 - i11iIiiIii - OoO0O00 + Ii1I
  I1IiO00Ooo0ooo0 = self . zero_auth ( I1IiO00Ooo0ooo0 )
  I1IiO00Ooo0ooo0 += eid_records
  if 86 - 86: I1IiiI / I1ii11iIi11i * Ii1I % i11iIiiIii
  OoOoo00Oo0OoO = lisp_hash_me ( I1IiO00Ooo0ooo0 , self . alg_id , password , False )
  if 20 - 20: iII111i . OoooooooOO + iII111i + ooOoO0o * I1ii11iIi11i
  oOO0OO0O = struct . calcsize ( "I" ) + struct . calcsize ( "QHH" )
  II1iiiiI1Ii11 = self . auth_len
  self . auth_data = OoOoo00Oo0OoO
  I1IiO00Ooo0ooo0 = I1IiO00Ooo0ooo0 [ 0 : oOO0OO0O ] + OoOoo00Oo0OoO + I1IiO00Ooo0ooo0 [ oOO0OO0O + II1iiiiI1Ii11 : : ]
  self . packet = I1IiO00Ooo0ooo0
  return ( I1IiO00Ooo0ooo0 )
  if 44 - 44: i11iIiiIii
  if 69 - 69: OOooOOo * O0 + i11iIiiIii
 def decode ( self , packet ) :
  O00Ooo00 = packet
  O0000 = "I"
  I1 = struct . calcsize ( O0000 )
  if ( len ( packet ) < I1 ) : return ( None )
  if 65 - 65: O0 / iII111i . i1IIi * iII111i / iIii1I11I1II1 - oO0o
  ooOOOo0 = struct . unpack ( O0000 , packet [ : I1 ] )
  ooOOOo0 = socket . ntohl ( ooOOOo0 [ 0 ] )
  self . map_notify_ack = ( ( ooOOOo0 >> 28 ) == LISP_MAP_NOTIFY_ACK )
  self . record_count = ooOOOo0 & 0xff
  packet = packet [ I1 : : ]
  if 93 - 93: OoOoOO00 % i11iIiiIii - Ii1I % OoO0O00
  O0000 = "QBBH"
  I1 = struct . calcsize ( O0000 )
  if ( len ( packet ) < I1 ) : return ( None )
  if 55 - 55: o0oOOo0O0Ooo . I1ii11iIi11i
  self . nonce , self . key_id , self . alg_id , self . auth_len = struct . unpack ( O0000 , packet [ : I1 ] )
  if 63 - 63: oO0o
  self . nonce_key = lisp_hex_string ( self . nonce )
  self . auth_len = socket . ntohs ( self . auth_len )
  packet = packet [ I1 : : ]
  self . eid_records = packet [ self . auth_len : : ]
  if 79 - 79: I1ii11iIi11i - oO0o - o0oOOo0O0Ooo . OOooOOo
  if ( self . auth_len == 0 ) : return ( self . eid_records )
  if 65 - 65: i11iIiiIii . OoO0O00 % iII111i + IiII - i11iIiiIii
  if 60 - 60: I1Ii111
  if 14 - 14: Oo0Ooo % oO0o * iII111i - i11iIiiIii / I1ii11iIi11i * i11iIiiIii
  if 95 - 95: iIii1I11I1II1 + OoOoOO00 . I1IiiI + OoOoOO00 * I11i + OOooOOo
  if ( len ( packet ) < self . auth_len ) : return ( None )
  if 14 - 14: Ii1I - O0
  II1iiiiI1Ii11 = self . auth_len
  if ( self . alg_id == LISP_SHA_1_96_ALG_ID ) :
   IIiIiIii11I1 , oo0O000OooO0 , IIIi1Iii11I = struct . unpack ( "QQI" , packet [ : II1iiiiI1Ii11 ] )
   i1I = ""
   if 68 - 68: II111iiii - I1ii11iIi11i - OoO0O00 * iIii1I11I1II1 / I1IiiI * I1ii11iIi11i
  if ( self . alg_id == LISP_SHA_256_128_ALG_ID ) :
   IIiIiIii11I1 , oo0O000OooO0 , IIIi1Iii11I , i1I = struct . unpack ( "QQQQ" ,
 packet [ : II1iiiiI1Ii11 ] )
   if 45 - 45: I1Ii111 * I11i / iIii1I11I1II1 / I1IiiI % II111iiii
  self . auth_data = lisp_concat_auth_data ( self . alg_id , IIiIiIii11I1 , oo0O000OooO0 ,
 IIIi1Iii11I , i1I )
  if 49 - 49: Ii1I / iII111i . iII111i . iII111i + i11iIiiIii % I11i
  I1 = struct . calcsize ( "I" ) + struct . calcsize ( "QHH" )
  packet = self . zero_auth ( O00Ooo00 [ : I1 ] )
  I1 += II1iiiiI1Ii11
  packet += O00Ooo00 [ I1 : : ]
  return ( packet )
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
  if 62 - 62: Oo0Ooo + OoooooooOO / iII111i
  if 60 - 60: Ii1I / OoOoOO00 . I11i % OOooOOo
  if 61 - 61: O0 . Ii1I . O0 * i11iIiiIii * II111iiii / I1Ii111
  if 69 - 69: I11i
  if 17 - 17: I11i
  if 38 - 38: I1Ii111 % OOooOOo
  if 9 - 9: O0 . iIii1I11I1II1
  if 44 - 44: I1ii11iIi11i % IiII
  if 6 - 6: OoO0O00
  if 82 - 82: iIii1I11I1II1 . I11i / IiII / OOooOOo * II111iiii % oO0o
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
  if 68 - 68: IiII % Oo0Ooo . O0 - OoOoOO00 + I1ii11iIi11i . i11iIiiIii
  if 45 - 45: I1IiiI
 def print_prefix ( self ) :
  if ( self . target_group . is_null ( ) ) :
   return ( green ( self . target_eid . print_prefix ( ) , False ) )
   if 17 - 17: OoooooooOO - ooOoO0o + Ii1I . OoooooooOO % Oo0Ooo
  return ( green ( self . target_eid . print_sg ( self . target_group ) , False ) )
  if 92 - 92: I1Ii111 - OOooOOo % OoO0O00 - o0oOOo0O0Ooo % i1IIi
  if 38 - 38: I1ii11iIi11i . I11i / OoOoOO00 % I11i
 def print_map_request ( self ) :
  IIIiIIi111 = ""
  if ( self . xtr_id != None and self . subscribe_bit ) :
   IIIiIIi111 = "subscribe, xtr-id: 0x{}, " . format ( lisp_hex_string ( self . xtr_id ) )
   if 10 - 10: O0 . I1IiiI * o0oOOo0O0Ooo / iII111i
   if 61 - 61: Oo0Ooo - I1Ii111
   if 51 - 51: iII111i * ooOoO0o / O0 / O0
  OOooO = ( "{} -> flags: {}{}{}{}{}{}{}{}{}{}, itr-rloc-" +
 "count: {} (+1), record-count: {}, nonce: 0x{}, source-eid: " +
 "afi {}, {}{}, target-eid: afi {}, {}, {}ITR-RLOCs:" )
  if 52 - 52: OoooooooOO % O0
  lprint ( OOooO . format ( bold ( "Map-Request" , False ) , "A" if self . auth_bit else "a" ,
  # o0oOOo0O0Ooo - iII111i - OOooOOo / OoooooooOO
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
 self . target_eid . afi , green ( self . print_prefix ( ) , False ) , IIIiIIi111 ) )
  if 26 - 26: II111iiii + i1IIi
  O000OO = self . keys
  for IiI1IIii in self . itr_rlocs :
   lprint ( "  itr-rloc: afi {} {}{}" . format ( IiI1IIii . afi ,
 red ( IiI1IIii . print_address_no_iid ( ) , False ) ,
 "" if ( O000OO == None ) else ", " + O000OO [ 1 ] . print_keys ( ) ) )
   O000OO = None
   if 13 - 13: i11iIiiIii . O0 / OOooOOo * i1IIi
   if 14 - 14: IiII + IiII . I11i / Ii1I . iIii1I11I1II1
   if 10 - 10: II111iiii . OOooOOo / iII111i
 def sign_map_request ( self , privkey ) :
  I1II = self . signature_eid . print_address ( )
  oooooOO0 = self . source_eid . print_address ( )
  OOO0o0O = self . target_eid . print_address ( )
  I111i = lisp_hex_string ( self . nonce ) + oooooOO0 + OOO0o0O
  self . map_request_signature = privkey . sign ( I111i )
  i1iiIIII = binascii . b2a_base64 ( self . map_request_signature )
  i1iiIIII = { "source-eid" : oooooOO0 , "signature-eid" : I1II ,
 "signature" : i1iiIIII }
  return ( json . dumps ( i1iiIIII ) )
  if 37 - 37: I1Ii111 * Ii1I + Oo0Ooo * I1Ii111 % o0oOOo0O0Ooo . Oo0Ooo
  if 37 - 37: Ii1I / II111iiii
 def verify_map_request_sig ( self , pubkey ) :
  o00OooO = green ( self . signature_eid . print_address ( ) , False )
  if ( pubkey == None ) :
   lprint ( "Public-key not found for signature-EID {}" . format ( o00OooO ) )
   return ( False )
   if 1 - 1: OoOoOO00 + OoooooooOO . IiII . iIii1I11I1II1
   if 30 - 30: i1IIi
  oooooOO0 = self . source_eid . print_address ( )
  OOO0o0O = self . target_eid . print_address ( )
  I111i = lisp_hex_string ( self . nonce ) + oooooOO0 + OOO0o0O
  pubkey = binascii . a2b_base64 ( pubkey )
  if 42 - 42: iII111i
  Iii11I1II1 = True
  try :
   iIIIi = ecdsa . VerifyingKey . from_pem ( pubkey )
  except :
   lprint ( "Invalid public-key in mapping system for sig-eid {}" . format ( self . signature_eid . print_address_no_iid ( ) ) )
   if 96 - 96: I1Ii111 % i1IIi . iII111i / O0
   Iii11I1II1 = False
   if 61 - 61: i1IIi / i1IIi + ooOoO0o . I1Ii111 * ooOoO0o
   if 19 - 19: o0oOOo0O0Ooo . II111iiii / i1IIi
  if ( Iii11I1II1 ) :
   try :
    Iii11I1II1 = iIIIi . verify ( self . map_request_signature , I111i )
   except :
    Iii11I1II1 = False
    if 82 - 82: O0 / iII111i * OoO0O00 - I11i + Oo0Ooo
    if 47 - 47: I1ii11iIi11i * I1IiiI / I1ii11iIi11i + Ii1I * II111iiii
    if 78 - 78: I1Ii111 - i1IIi + OoOoOO00 + Oo0Ooo * I1ii11iIi11i * o0oOOo0O0Ooo
  oooO = bold ( "passed" if Iii11I1II1 else "failed" , False )
  lprint ( "Signature verification {} for EID {}" . format ( oooO , o00OooO ) )
  return ( Iii11I1II1 )
  if 37 - 37: I1ii11iIi11i * I1Ii111 * I1IiiI * O0
  if 35 - 35: I1IiiI - I1ii11iIi11i * iII111i + IiII / i1IIi
 def encode ( self , probe_dest , probe_port ) :
  ooOOOo0 = ( LISP_MAP_REQUEST << 28 ) | self . record_count
  ooOOOo0 = ooOOOo0 | ( self . itr_rloc_count << 8 )
  if ( self . auth_bit ) : ooOOOo0 |= 0x08000000
  if ( self . map_data_present ) : ooOOOo0 |= 0x04000000
  if ( self . rloc_probe ) : ooOOOo0 |= 0x02000000
  if ( self . smr_bit ) : ooOOOo0 |= 0x01000000
  if ( self . pitr_bit ) : ooOOOo0 |= 0x00800000
  if ( self . smr_invoked_bit ) : ooOOOo0 |= 0x00400000
  if ( self . mobile_node ) : ooOOOo0 |= 0x00200000
  if ( self . xtr_id_present ) : ooOOOo0 |= 0x00100000
  if ( self . local_xtr ) : ooOOOo0 |= 0x00004000
  if ( self . dont_reply_bit ) : ooOOOo0 |= 0x00002000
  if 46 - 46: Oo0Ooo . ooOoO0o % Oo0Ooo / II111iiii * ooOoO0o * OOooOOo
  I1IiO00Ooo0ooo0 = struct . pack ( "I" , socket . htonl ( ooOOOo0 ) )
  I1IiO00Ooo0ooo0 += struct . pack ( "Q" , self . nonce )
  if 59 - 59: I1Ii111 * iII111i
  if 31 - 31: I11i / O0
  if 57 - 57: i1IIi % ooOoO0o
  if 69 - 69: o0oOOo0O0Ooo
  if 69 - 69: I1Ii111
  if 83 - 83: iIii1I11I1II1 . o0oOOo0O0Ooo + I1Ii111 . OoooooooOO / ooOoO0o + II111iiii
  o0o0O0oOOoO0 = False
  I11iIIIIiiI = self . privkey_filename
  if ( I11iIIIIiiI != None and os . path . exists ( I11iIIIIiiI ) ) :
   Ii11111i1 = open ( I11iIIIIiiI , "r" ) ; iIIIi = Ii11111i1 . read ( ) ; Ii11111i1 . close ( )
   try :
    iIIIi = ecdsa . SigningKey . from_pem ( iIIIi )
   except :
    return ( None )
    if 37 - 37: i11iIiiIii - OoooooooOO . OoooooooOO * iIii1I11I1II1
   i1iii11i1 = self . sign_map_request ( iIIIi )
   o0o0O0oOOoO0 = True
  elif ( self . map_request_signature != None ) :
   i1iiIIII = binascii . b2a_base64 ( self . map_request_signature )
   i1iii11i1 = { "source-eid" : self . source_eid . print_address ( ) ,
 "signature-eid" : self . signature_eid . print_address ( ) ,
 "signature" : i1iiIIII }
   i1iii11i1 = json . dumps ( i1iii11i1 )
   o0o0O0oOOoO0 = True
   if 77 - 77: O0 - I1Ii111 * OoooooooOO / oO0o
  if ( o0o0O0oOOoO0 ) :
   OO = LISP_LCAF_JSON_TYPE
   ii1Ii111I11 = socket . htons ( LISP_AFI_LCAF )
   IiiiI1I1i = socket . htons ( len ( i1iii11i1 ) + 2 )
   OOI11iiII1Iii1 = socket . htons ( len ( i1iii11i1 ) )
   I1IiO00Ooo0ooo0 += struct . pack ( "HBBBBHH" , ii1Ii111I11 , 0 , 0 , OO , 0 ,
 IiiiI1I1i , OOI11iiII1Iii1 )
   I1IiO00Ooo0ooo0 += i1iii11i1
   I1IiO00Ooo0ooo0 += struct . pack ( "H" , 0 )
  else :
   if ( self . source_eid . instance_id != 0 ) :
    I1IiO00Ooo0ooo0 += struct . pack ( "H" , socket . htons ( LISP_AFI_LCAF ) )
    I1IiO00Ooo0ooo0 += self . source_eid . lcaf_encode_iid ( )
   else :
    I1IiO00Ooo0ooo0 += struct . pack ( "H" , socket . htons ( self . source_eid . afi ) )
    I1IiO00Ooo0ooo0 += self . source_eid . pack_address ( )
    if 5 - 5: Ii1I - iIii1I11I1II1
    if 51 - 51: IiII
    if 39 - 39: OoOoOO00
    if 16 - 16: oO0o
    if 96 - 96: ooOoO0o / oO0o % O0 / OOooOOo * OoO0O00 * I11i
    if 27 - 27: OoOoOO00 % Ii1I / i1IIi . i1IIi * OoooooooOO % ooOoO0o
    if 92 - 92: Ii1I - ooOoO0o / ooOoO0o + IiII
  if ( probe_dest ) :
   if ( probe_port == 0 ) : probe_port = LISP_DATA_PORT
   OoOOoooO000 = probe_dest . print_address_no_iid ( ) + ":" + str ( probe_port )
   if 57 - 57: OOooOOo - OoooooooOO * OoO0O00 * iII111i + oO0o
   if ( lisp_crypto_keys_by_rloc_encap . has_key ( OoOOoooO000 ) ) :
    self . keys = lisp_crypto_keys_by_rloc_encap [ OoOOoooO000 ]
    if 100 - 100: I1Ii111 - i1IIi
    if 90 - 90: Ii1I + oO0o . II111iiii - OoOoOO00 % iIii1I11I1II1
    if 24 - 24: IiII / Ii1I * OOooOOo
    if 33 - 33: OOooOOo
    if 22 - 22: O0 + OOooOOo % i1IIi
    if 83 - 83: O0 + Ii1I % i11iIiiIii
    if 32 - 32: I1Ii111 % Oo0Ooo - I11i + O0
  for IiI1IIii in self . itr_rlocs :
   if ( lisp_data_plane_security and self . itr_rlocs . index ( IiI1IIii ) == 0 ) :
    if ( self . keys == None or self . keys [ 1 ] == None ) :
     O000OO = lisp_keys ( 1 )
     self . keys = [ None , O000OO , None , None ]
     if 57 - 57: OoO0O00 + I1Ii111 . I11i . i1IIi - o0oOOo0O0Ooo / Oo0Ooo
    O000OO = self . keys [ 1 ]
    O000OO . add_key_by_nonce ( self . nonce )
    I1IiO00Ooo0ooo0 += O000OO . encode_lcaf ( IiI1IIii )
   else :
    I1IiO00Ooo0ooo0 += struct . pack ( "H" , socket . htons ( IiI1IIii . afi ) )
    I1IiO00Ooo0ooo0 += IiI1IIii . pack_address ( )
    if 19 - 19: iIii1I11I1II1 . OoO0O00 / OoooooooOO
    if 2 - 2: O0 - O0 % I1Ii111 / I1ii11iIi11i
    if 76 - 76: OoO0O00 * oO0o - OoO0O00
  OoOO = 0 if self . target_eid . is_binary ( ) == False else self . target_eid . mask_len
  if 8 - 8: iIii1I11I1II1 % OOooOOo - ooOoO0o . OOooOOo
  if 97 - 97: o0oOOo0O0Ooo + iII111i + I1Ii111 * OOooOOo
  Ooo0o = 0
  if ( self . subscribe_bit ) :
   Ooo0o = 0x80
   self . xtr_id_present = True
   if ( self . xtr_id == None ) :
    self . xtr_id = random . randint ( 0 , ( 2 ** 128 ) - 1 )
    if 19 - 19: Ii1I % OoooooooOO - i11iIiiIii . O0 . Ii1I * OoOoOO00
    if 38 - 38: OoOoOO00 - OoOoOO00 * i11iIiiIii % I1ii11iIi11i + I1IiiI + OOooOOo
    if 44 - 44: I1ii11iIi11i - IiII * O0
  O0000 = "BB"
  I1IiO00Ooo0ooo0 += struct . pack ( O0000 , Ooo0o , OoOO )
  if 82 - 82: OOooOOo + IiII . i11iIiiIii
  if ( self . target_group . is_null ( ) == False ) :
   I1IiO00Ooo0ooo0 += struct . pack ( "H" , socket . htons ( LISP_AFI_LCAF ) )
   I1IiO00Ooo0ooo0 += self . target_eid . lcaf_encode_sg ( self . target_group )
  elif ( self . target_eid . instance_id != 0 or
 self . target_eid . is_geo_prefix ( ) ) :
   I1IiO00Ooo0ooo0 += struct . pack ( "H" , socket . htons ( LISP_AFI_LCAF ) )
   I1IiO00Ooo0ooo0 += self . target_eid . lcaf_encode_iid ( )
  else :
   I1IiO00Ooo0ooo0 += struct . pack ( "H" , socket . htons ( self . target_eid . afi ) )
   I1IiO00Ooo0ooo0 += self . target_eid . pack_address ( )
   if 41 - 41: OoOoOO00 % I11i . ooOoO0o
   if 57 - 57: OoO0O00 * oO0o . iIii1I11I1II1 - OOooOOo
   if 23 - 23: I1ii11iIi11i % I11i
   if 18 - 18: OoooooooOO . i1IIi + II111iiii
   if 99 - 99: I1Ii111 - I1ii11iIi11i - I1IiiI - I1Ii111 + OoO0O00 + II111iiii
  if ( self . subscribe_bit ) : I1IiO00Ooo0ooo0 = self . encode_xtr_id ( I1IiO00Ooo0ooo0 )
  return ( I1IiO00Ooo0ooo0 )
  if 34 - 34: I1Ii111 * I11i
  if 31 - 31: IiII . oO0o
 def lcaf_decode_json ( self , packet ) :
  O0000 = "BBBBHH"
  I1 = struct . calcsize ( O0000 )
  if ( len ( packet ) < I1 ) : return ( None )
  if 40 - 40: Ii1I - I11i / II111iiii * i1IIi + IiII * II111iiii
  OOoooOOO0 , O0O0oooo , OO , O0o , IiiiI1I1i , OOI11iiII1Iii1 = struct . unpack ( O0000 , packet [ : I1 ] )
  if 48 - 48: I1IiiI
  if 90 - 90: oO0o / Oo0Ooo % I1ii11iIi11i + IiII
  if ( OO != LISP_LCAF_JSON_TYPE ) : return ( packet )
  if 13 - 13: II111iiii . OoO0O00
  if 31 - 31: oO0o . iII111i - I11i . iIii1I11I1II1 + I11i . OoOoOO00
  if 86 - 86: I1ii11iIi11i - I1ii11iIi11i / iII111i - I1ii11iIi11i * iII111i + I1Ii111
  if 61 - 61: Oo0Ooo / II111iiii / Oo0Ooo / i1IIi . Oo0Ooo - IiII
  IiiiI1I1i = socket . ntohs ( IiiiI1I1i )
  OOI11iiII1Iii1 = socket . ntohs ( OOI11iiII1Iii1 )
  packet = packet [ I1 : : ]
  if ( len ( packet ) < IiiiI1I1i ) : return ( None )
  if ( IiiiI1I1i != OOI11iiII1Iii1 + 2 ) : return ( None )
  if 30 - 30: OoooooooOO % OOooOOo
  if 14 - 14: OoOoOO00 / OoO0O00 / i11iIiiIii - OoOoOO00 / o0oOOo0O0Ooo - OOooOOo
  if 81 - 81: iII111i % Ii1I . ooOoO0o
  if 66 - 66: I1ii11iIi11i * Ii1I / OoooooooOO * O0 % OOooOOo
  try :
   i1iii11i1 = json . loads ( packet [ 0 : OOI11iiII1Iii1 ] )
  except :
   return ( None )
   if 49 - 49: II111iiii . I1IiiI * O0 * Ii1I / I1Ii111 * OoooooooOO
  packet = packet [ OOI11iiII1Iii1 : : ]
  if 82 - 82: Oo0Ooo / Ii1I / Ii1I % Ii1I
  if 20 - 20: ooOoO0o
  if 63 - 63: iIii1I11I1II1 . OoO0O00
  if 100 - 100: i1IIi * i1IIi
  O0000 = "H"
  I1 = struct . calcsize ( O0000 )
  o0O0O0O00o = struct . unpack ( O0000 , packet [ : I1 ] ) [ 0 ]
  packet = packet [ I1 : : ]
  if ( o0O0O0O00o != 0 ) : return ( packet )
  if 26 - 26: OOooOOo . OoO0O00 % OoOoOO00
  if 94 - 94: IiII
  if 15 - 15: Ii1I - IiII / O0
  if 28 - 28: I1Ii111 . i1IIi / I1ii11iIi11i
  if ( i1iii11i1 . has_key ( "source-eid" ) == False ) : return ( packet )
  Ooo0 = i1iii11i1 [ "source-eid" ]
  o0O0O0O00o = LISP_AFI_IPV4 if Ooo0 . count ( "." ) == 3 else LISP_AFI_IPV6 if Ooo0 . count ( ":" ) == 7 else None
  if 80 - 80: o0oOOo0O0Ooo
  if ( o0O0O0O00o == None ) :
   lprint ( "Bad JSON 'source-eid' value: {}" . format ( Ooo0 ) )
   return ( None )
   if 46 - 46: iII111i % I1Ii111 % OoOoOO00 . OoooooooOO . II111iiii % IiII
   if 6 - 6: I1Ii111 % IiII / Ii1I + I1Ii111 . oO0o
  self . source_eid . afi = o0O0O0O00o
  self . source_eid . store_address ( Ooo0 )
  if 70 - 70: iIii1I11I1II1 / Ii1I
  if ( i1iii11i1 . has_key ( "signature-eid" ) == False ) : return ( packet )
  Ooo0 = i1iii11i1 [ "signature-eid" ]
  if ( Ooo0 . count ( ":" ) != 7 ) :
   lprint ( "Bad JSON 'signature-eid' value: {}" . format ( Ooo0 ) )
   return ( None )
   if 61 - 61: O0 * o0oOOo0O0Ooo + I1Ii111 - OOooOOo . I1IiiI - IiII
   if 7 - 7: I1ii11iIi11i
  self . signature_eid . afi = LISP_AFI_IPV6
  self . signature_eid . store_address ( Ooo0 )
  if 81 - 81: Oo0Ooo % II111iiii % o0oOOo0O0Ooo / I11i
  if ( i1iii11i1 . has_key ( "signature" ) == False ) : return ( packet )
  i1iiIIII = binascii . a2b_base64 ( i1iii11i1 [ "signature" ] )
  self . map_request_signature = i1iiIIII
  return ( packet )
  if 95 - 95: OoOoOO00 - O0 % OoooooooOO
  if 13 - 13: i11iIiiIii
 def decode ( self , packet , source , port ) :
  O0000 = "I"
  I1 = struct . calcsize ( O0000 )
  if ( len ( packet ) < I1 ) : return ( None )
  if 54 - 54: OOooOOo . I1ii11iIi11i * I11i % I1Ii111 . O0 * IiII
  ooOOOo0 = struct . unpack ( O0000 , packet [ : I1 ] )
  ooOOOo0 = ooOOOo0 [ 0 ]
  packet = packet [ I1 : : ]
  if 87 - 87: Ii1I % I1ii11iIi11i * Oo0Ooo
  O0000 = "Q"
  I1 = struct . calcsize ( O0000 )
  if ( len ( packet ) < I1 ) : return ( None )
  if 59 - 59: Oo0Ooo / I11i - iIii1I11I1II1 * iIii1I11I1II1
  o0oo000 = struct . unpack ( O0000 , packet [ : I1 ] )
  packet = packet [ I1 : : ]
  if 18 - 18: I11i * I1ii11iIi11i / i11iIiiIii / iIii1I11I1II1 * OoooooooOO . OOooOOo
  ooOOOo0 = socket . ntohl ( ooOOOo0 )
  self . auth_bit = True if ( ooOOOo0 & 0x08000000 ) else False
  self . map_data_present = True if ( ooOOOo0 & 0x04000000 ) else False
  self . rloc_probe = True if ( ooOOOo0 & 0x02000000 ) else False
  self . smr_bit = True if ( ooOOOo0 & 0x01000000 ) else False
  self . pitr_bit = True if ( ooOOOo0 & 0x00800000 ) else False
  self . smr_invoked_bit = True if ( ooOOOo0 & 0x00400000 ) else False
  self . mobile_node = True if ( ooOOOo0 & 0x00200000 ) else False
  self . xtr_id_present = True if ( ooOOOo0 & 0x00100000 ) else False
  self . local_xtr = True if ( ooOOOo0 & 0x00004000 ) else False
  self . dont_reply_bit = True if ( ooOOOo0 & 0x00002000 ) else False
  self . itr_rloc_count = ( ( ooOOOo0 >> 8 ) & 0x1f ) + 1
  self . record_count = ooOOOo0 & 0xff
  self . nonce = o0oo000 [ 0 ]
  if 69 - 69: Oo0Ooo * ooOoO0o
  if 91 - 91: o0oOOo0O0Ooo . ooOoO0o / OoO0O00 / i11iIiiIii * o0oOOo0O0Ooo
  if 52 - 52: I1IiiI - i11iIiiIii / IiII . oO0o
  if 38 - 38: oO0o + OoooooooOO * OoOoOO00 % oO0o
  if ( self . xtr_id_present ) :
   if ( self . decode_xtr_id ( packet ) == False ) : return ( None )
   if 91 - 91: i1IIi - I1ii11iIi11i * I1IiiI
   if 24 - 24: OoOoOO00 * Ii1I
  I1 = struct . calcsize ( "H" )
  if ( len ( packet ) < I1 ) : return ( None )
  if 17 - 17: OoO0O00 . I1IiiI * O0
  o0O0O0O00o = struct . unpack ( "H" , packet [ : I1 ] )
  self . source_eid . afi = socket . ntohs ( o0O0O0O00o [ 0 ] )
  packet = packet [ I1 : : ]
  if 81 - 81: OOooOOo
  if ( self . source_eid . afi == LISP_AFI_LCAF ) :
   OooOooo00OOO0o = packet
   packet = self . source_eid . lcaf_decode_iid ( packet )
   if ( packet == None ) :
    packet = self . lcaf_decode_json ( OooOooo00OOO0o )
    if ( packet == None ) : return ( None )
    if 41 - 41: OOooOOo % i11iIiiIii * I1IiiI + o0oOOo0O0Ooo / oO0o
  elif ( self . source_eid . afi != LISP_AFI_NONE ) :
   packet = self . source_eid . unpack_address ( packet )
   if ( packet == None ) : return ( None )
   if 56 - 56: i1IIi
  self . source_eid . mask_len = self . source_eid . host_mask_len ( )
  if 11 - 11: i11iIiiIii % o0oOOo0O0Ooo / I11i * OoooooooOO
  oo00OoO00O0O = ( os . getenv ( "LISP_NO_CRYPTO" ) != None )
  self . itr_rlocs = [ ]
  while ( self . itr_rloc_count != 0 ) :
   I1 = struct . calcsize ( "H" )
   if ( len ( packet ) < I1 ) : return ( None )
   if 54 - 54: i11iIiiIii / iIii1I11I1II1 % I1ii11iIi11i / I1IiiI . iIii1I11I1II1 / iII111i
   o0O0O0O00o = struct . unpack ( "H" , packet [ : I1 ] ) [ 0 ]
   if 1 - 1: I1Ii111 / OoOoOO00 * OoOoOO00 - o0oOOo0O0Ooo % Ii1I
   IiI1IIii = lisp_address ( LISP_AFI_NONE , "" , 32 , 0 )
   IiI1IIii . afi = socket . ntohs ( o0O0O0O00o )
   if 96 - 96: IiII / Ii1I % OoO0O00 . iIii1I11I1II1
   if 30 - 30: I11i - OoO0O00
   if 15 - 15: OoooooooOO
   if 31 - 31: II111iiii
   if 62 - 62: iIii1I11I1II1 % I1Ii111 % I1ii11iIi11i * IiII
   if ( IiI1IIii . afi != LISP_AFI_LCAF ) :
    if ( len ( packet ) < IiI1IIii . addr_length ( ) ) : return ( None )
    packet = IiI1IIii . unpack_address ( packet [ I1 : : ] )
    if ( packet == None ) : return ( None )
    if 87 - 87: IiII
    if ( oo00OoO00O0O ) :
     self . itr_rlocs . append ( IiI1IIii )
     self . itr_rloc_count -= 1
     continue
     if 45 - 45: oO0o + II111iiii * O0 % OOooOOo . iIii1I11I1II1
     if 55 - 55: IiII
    OoOOoooO000 = lisp_build_crypto_decap_lookup_key ( IiI1IIii , port )
    if 43 - 43: OOooOOo
    if 17 - 17: i11iIiiIii
    if 94 - 94: OoooooooOO - IiII + oO0o . OoooooooOO / i1IIi
    if 53 - 53: I1Ii111 % I1ii11iIi11i
    if 17 - 17: OoooooooOO % Ii1I % O0
    if ( lisp_nat_traversal and IiI1IIii . is_private_address ( ) and source ) : IiI1IIii = source
    if 46 - 46: iII111i + I1Ii111 % OoooooooOO * I1ii11iIi11i
    O000o0O0 = lisp_crypto_keys_by_rloc_decap
    if ( O000o0O0 . has_key ( OoOOoooO000 ) ) : O000o0O0 . pop ( OoOOoooO000 )
    if 51 - 51: ooOoO0o * Ii1I * OoooooooOO % OoOoOO00
    if 25 - 25: iIii1I11I1II1 * OoooooooOO * Ii1I - i1IIi
    if 23 - 23: o0oOOo0O0Ooo . ooOoO0o - OoooooooOO + I11i
    if 73 - 73: OoOoOO00
    if 71 - 71: i11iIiiIii * OoOoOO00 * OOooOOo + oO0o + Oo0Ooo
    if 59 - 59: IiII
    lisp_write_ipc_decap_key ( OoOOoooO000 , None )
   else :
    O00Ooo00 = packet
    oo0OOOOOO = lisp_keys ( 1 )
    packet = oo0OOOOOO . decode_lcaf ( O00Ooo00 , 0 )
    if ( packet == None ) : return ( None )
    if 12 - 12: IiII + o0oOOo0O0Ooo - OOooOOo / OOooOOo / iII111i * OoooooooOO
    if 40 - 40: Oo0Ooo * OoooooooOO + IiII
    if 58 - 58: I1IiiI
    if 21 - 21: IiII - I1IiiI . OOooOOo - oO0o
    i11iIi1I1i1 = [ LISP_CS_25519_CBC , LISP_CS_25519_GCM ,
 LISP_CS_25519_CHACHA ]
    if ( oo0OOOOOO . cipher_suite in i11iIi1I1i1 ) :
     if ( oo0OOOOOO . cipher_suite == LISP_CS_25519_CBC or
 oo0OOOOOO . cipher_suite == LISP_CS_25519_GCM ) :
      iIIIi = lisp_keys ( 1 , do_poly = False , do_chacha = False )
      if 1 - 1: iIii1I11I1II1 / i11iIiiIii * II111iiii
     if ( oo0OOOOOO . cipher_suite == LISP_CS_25519_CHACHA ) :
      iIIIi = lisp_keys ( 1 , do_poly = True , do_chacha = True )
      if 48 - 48: I1ii11iIi11i + O0 * oO0o + I1ii11iIi11i + I1ii11iIi11i
    else :
     iIIIi = lisp_keys ( 1 , do_poly = False , do_curve = False ,
 do_chacha = False )
     if 60 - 60: II111iiii % Oo0Ooo
    packet = iIIIi . decode_lcaf ( O00Ooo00 , 0 )
    if ( packet == None ) : return ( None )
    if 62 - 62: O0 + iII111i - iII111i % iIii1I11I1II1
    if ( len ( packet ) < I1 ) : return ( None )
    o0O0O0O00o = struct . unpack ( "H" , packet [ : I1 ] ) [ 0 ]
    IiI1IIii . afi = socket . ntohs ( o0O0O0O00o )
    if ( len ( packet ) < IiI1IIii . addr_length ( ) ) : return ( None )
    if 47 - 47: I1Ii111 + I1IiiI
    packet = IiI1IIii . unpack_address ( packet [ I1 : : ] )
    if ( packet == None ) : return ( None )
    if 40 - 40: iIii1I11I1II1 % Ii1I + II111iiii - I1IiiI
    if ( oo00OoO00O0O ) :
     self . itr_rlocs . append ( IiI1IIii )
     self . itr_rloc_count -= 1
     continue
     if 80 - 80: oO0o
     if 81 - 81: OoooooooOO / ooOoO0o * iIii1I11I1II1 . Oo0Ooo + oO0o / O0
    OoOOoooO000 = lisp_build_crypto_decap_lookup_key ( IiI1IIii , port )
    if 84 - 84: II111iiii - o0oOOo0O0Ooo
    oOoOoO0OoOO0 = None
    if ( lisp_nat_traversal and IiI1IIii . is_private_address ( ) and source ) : IiI1IIii = source
    if 75 - 75: I1IiiI
    if 99 - 99: ooOoO0o . Ii1I
    if ( lisp_crypto_keys_by_rloc_decap . has_key ( OoOOoooO000 ) ) :
     O000OO = lisp_crypto_keys_by_rloc_decap [ OoOOoooO000 ]
     oOoOoO0OoOO0 = O000OO [ 1 ] if O000OO and O000OO [ 1 ] else None
     if 92 - 92: i1IIi
     if 68 - 68: OoO0O00 % IiII - oO0o - ooOoO0o . Oo0Ooo
    IiII11IIII1 = True
    if ( oOoOoO0OoOO0 ) :
     if ( oOoOoO0OoOO0 . compare_keys ( iIIIi ) ) :
      self . keys = [ None , oOoOoO0OoOO0 , None , None ]
      lprint ( "Maintain stored decap-keys for RLOC {}" . format ( red ( OoOOoooO000 , False ) ) )
      if 2 - 2: OoOoOO00
     else :
      IiII11IIII1 = False
      Iiooo0o0oOoOO0 = bold ( "Remote decap-rekeying" , False )
      lprint ( "{} for RLOC {}" . format ( Iiooo0o0oOoOO0 , red ( OoOOoooO000 ,
 False ) ) )
      iIIIi . copy_keypair ( oOoOoO0OoOO0 )
      iIIIi . uptime = oOoOoO0OoOO0 . uptime
      oOoOoO0OoOO0 = None
      if 56 - 56: Oo0Ooo % i11iIiiIii / Ii1I . I1Ii111 . OoO0O00 - OoOoOO00
      if 32 - 32: I1Ii111 / oO0o / I1IiiI
      if 22 - 22: OoO0O00 - OoOoOO00 . Oo0Ooo + o0oOOo0O0Ooo
    if ( oOoOoO0OoOO0 == None ) :
     self . keys = [ None , iIIIi , None , None ]
     if ( lisp_i_am_etr == False and lisp_i_am_rtr == False ) :
      iIIIi . local_public_key = None
      lprint ( "{} for {}" . format ( bold ( "Ignoring decap-keys" ,
 False ) , red ( OoOOoooO000 , False ) ) )
     elif ( iIIIi . remote_public_key != None ) :
      if ( IiII11IIII1 ) :
       lprint ( "{} for RLOC {}" . format ( bold ( "New decap-keying" , False ) ,
       # I1ii11iIi11i / I1IiiI - iII111i . i1IIi / i11iIiiIii
 red ( OoOOoooO000 , False ) ) )
       if 84 - 84: I11i / OoooooooOO / IiII % I11i . OOooOOo + I1Ii111
      iIIIi . compute_shared_key ( "decap" )
      iIIIi . add_key_by_rloc ( OoOOoooO000 , False )
      if 94 - 94: I11i
      if 48 - 48: oO0o - OoooooooOO + o0oOOo0O0Ooo % i1IIi - I1IiiI + OOooOOo
      if 56 - 56: I1IiiI - OOooOOo
      if 35 - 35: OoO0O00 / I1IiiI * O0 + I1IiiI . O0
   self . itr_rlocs . append ( IiI1IIii )
   self . itr_rloc_count -= 1
   if 86 - 86: I1IiiI
   if 10 - 10: OoOoOO00 / oO0o % Oo0Ooo
  I1 = struct . calcsize ( "BBH" )
  if ( len ( packet ) < I1 ) : return ( None )
  if 15 - 15: I11i - iIii1I11I1II1 % Ii1I
  Ooo0o , OoOO , o0O0O0O00o = struct . unpack ( "BBH" , packet [ : I1 ] )
  self . subscribe_bit = ( Ooo0o & 0x80 )
  self . target_eid . afi = socket . ntohs ( o0O0O0O00o )
  packet = packet [ I1 : : ]
  if 47 - 47: iII111i / OoooooooOO - II111iiii
  self . target_eid . mask_len = OoOO
  if ( self . target_eid . afi == LISP_AFI_LCAF ) :
   packet , oOOooo = self . target_eid . lcaf_decode_eid ( packet )
   if ( packet == None ) : return ( None )
   if ( oOOooo ) : self . target_group = oOOooo
  else :
   packet = self . target_eid . unpack_address ( packet )
   if ( packet == None ) : return ( None )
   packet = packet [ I1 : : ]
   if 9 - 9: i1IIi % I1Ii111 - OoO0O00 * OoOoOO00 . o0oOOo0O0Ooo
  return ( packet )
  if 18 - 18: Ii1I . OoOoOO00 + iII111i . I1IiiI + OoooooooOO . OoO0O00
  if 31 - 31: I1Ii111 - I11i
 def print_eid_tuple ( self ) :
  return ( lisp_print_eid_tuple ( self . target_eid , self . target_group ) )
  if 49 - 49: iIii1I11I1II1 - iIii1I11I1II1 - OoOoOO00 + IiII / OoOoOO00
  if 74 - 74: OoooooooOO + I1ii11iIi11i % O0
 def encode_xtr_id ( self , packet ) :
  i11IIII = self . xtr_id >> 64
  i1I1 = self . xtr_id & 0xffffffffffffffff
  i11IIII = byte_swap_64 ( i11IIII )
  i1I1 = byte_swap_64 ( i1I1 )
  packet += struct . pack ( "QQ" , i11IIII , i1I1 )
  return ( packet )
  if 32 - 32: I1ii11iIi11i + I1ii11iIi11i
  if 89 - 89: ooOoO0o + oO0o + Ii1I - OOooOOo
 def decode_xtr_id ( self , packet ) :
  I1 = struct . calcsize ( "QQ" )
  if ( len ( packet ) < I1 ) : return ( None )
  packet = packet [ len ( packet ) - I1 : : ]
  i11IIII , i1I1 = struct . unpack ( "QQ" , packet [ : I1 ] )
  i11IIII = byte_swap_64 ( i11IIII )
  i1I1 = byte_swap_64 ( i1I1 )
  self . xtr_id = ( i11IIII << 64 ) | i1I1
  return ( True )
  if 12 - 12: OoOoOO00 - o0oOOo0O0Ooo - I1Ii111 / I11i
  if 17 - 17: OoO0O00 - I1Ii111 - II111iiii / I1Ii111 / Ii1I
  if 30 - 30: OOooOOo * I1ii11iIi11i % I1ii11iIi11i + iII111i * IiII
  if 33 - 33: o0oOOo0O0Ooo + I11i * O0 * OoO0O00 . I1ii11iIi11i
  if 74 - 74: iII111i * iII111i * o0oOOo0O0Ooo / oO0o
  if 91 - 91: i11iIiiIii . I1ii11iIi11i / II111iiii
  if 97 - 97: Ii1I % i1IIi % IiII + Oo0Ooo - O0 - I11i
  if 64 - 64: Ii1I - iII111i
  if 12 - 12: i1IIi
  if 99 - 99: II111iiii - I1ii11iIi11i * IiII
  if 3 - 3: IiII - I1ii11iIi11i * iII111i * I1ii11iIi11i + Oo0Ooo
  if 15 - 15: I1ii11iIi11i * Ii1I / iII111i . o0oOOo0O0Ooo / Ii1I % OoOoOO00
  if 75 - 75: OoooooooOO % i11iIiiIii % iIii1I11I1II1 % I1ii11iIi11i / i11iIiiIii
  if 96 - 96: ooOoO0o * oO0o / iIii1I11I1II1 / I11i
  if 5 - 5: o0oOOo0O0Ooo
  if 83 - 83: I11i * I1IiiI . II111iiii * i1IIi % O0
  if 35 - 35: OoOoOO00 % OoO0O00 + O0 * o0oOOo0O0Ooo % I1ii11iIi11i
  if 57 - 57: oO0o / I11i
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
class lisp_map_reply ( ) :
 def __init__ ( self ) :
  self . rloc_probe = False
  self . echo_nonce_capable = False
  self . security = False
  self . record_count = 0
  self . hop_count = 0
  self . nonce = 0
  self . keys = None
  if 84 - 84: IiII - OoOoOO00 . IiII + ooOoO0o . iII111i
  if 96 - 96: Ii1I % iII111i * Ii1I % I1IiiI . o0oOOo0O0Ooo / o0oOOo0O0Ooo
 def print_map_reply ( self ) :
  OOooO = "{} -> flags: {}{}{}, hop-count: {}, record-count: {}, " + "nonce: 0x{}"
  if 7 - 7: OoO0O00 - ooOoO0o % i1IIi
  lprint ( OOooO . format ( bold ( "Map-Reply" , False ) , "R" if self . rloc_probe else "r" ,
  # Ii1I + OoO0O00
 "E" if self . echo_nonce_capable else "e" ,
 "S" if self . security else "s" , self . hop_count , self . record_count ,
 lisp_hex_string ( self . nonce ) ) )
  if 83 - 83: I11i
  if 61 - 61: ooOoO0o . iII111i / ooOoO0o * OoooooooOO
 def encode ( self ) :
  ooOOOo0 = ( LISP_MAP_REPLY << 28 ) | self . record_count
  ooOOOo0 |= self . hop_count << 8
  if ( self . rloc_probe ) : ooOOOo0 |= 0x08000000
  if ( self . echo_nonce_capable ) : ooOOOo0 |= 0x04000000
  if ( self . security ) : ooOOOo0 |= 0x02000000
  if 13 - 13: II111iiii
  I1IiO00Ooo0ooo0 = struct . pack ( "I" , socket . htonl ( ooOOOo0 ) )
  I1IiO00Ooo0ooo0 += struct . pack ( "Q" , self . nonce )
  return ( I1IiO00Ooo0ooo0 )
  if 17 - 17: II111iiii
  if 66 - 66: IiII * oO0o
 def decode ( self , packet ) :
  O0000 = "I"
  I1 = struct . calcsize ( O0000 )
  if ( len ( packet ) < I1 ) : return ( None )
  if 73 - 73: i11iIiiIii + O0 % O0
  ooOOOo0 = struct . unpack ( O0000 , packet [ : I1 ] )
  ooOOOo0 = ooOOOo0 [ 0 ]
  packet = packet [ I1 : : ]
  if 70 - 70: II111iiii * OoooooooOO - Ii1I + oO0o * O0
  O0000 = "Q"
  I1 = struct . calcsize ( O0000 )
  if ( len ( packet ) < I1 ) : return ( None )
  if 49 - 49: oO0o . Ii1I . OoOoOO00 - I1ii11iIi11i
  o0oo000 = struct . unpack ( O0000 , packet [ : I1 ] )
  packet = packet [ I1 : : ]
  if 74 - 74: ooOoO0o % I1ii11iIi11i * i1IIi
  ooOOOo0 = socket . ntohl ( ooOOOo0 )
  self . rloc_probe = True if ( ooOOOo0 & 0x08000000 ) else False
  self . echo_nonce_capable = True if ( ooOOOo0 & 0x04000000 ) else False
  self . security = True if ( ooOOOo0 & 0x02000000 ) else False
  self . hop_count = ( ooOOOo0 >> 8 ) & 0xff
  self . record_count = ooOOOo0 & 0xff
  self . nonce = o0oo000 [ 0 ]
  if 18 - 18: OoOoOO00
  if ( lisp_crypto_keys_by_nonce . has_key ( self . nonce ) ) :
   self . keys = lisp_crypto_keys_by_nonce [ self . nonce ]
   self . keys [ 1 ] . delete_key_by_nonce ( self . nonce )
   if 30 - 30: II111iiii
  return ( packet )
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
  if 12 - 12: o0oOOo0O0Ooo
  if 58 - 58: iIii1I11I1II1 * Ii1I . ooOoO0o . Oo0Ooo * Ii1I
  if 63 - 63: OoOoOO00 . I11i * o0oOOo0O0Ooo - I11i % I11i
  if 62 - 62: I11i - ooOoO0o / ooOoO0o
  if 95 - 95: OoOoOO00 - i1IIi / I1Ii111 . ooOoO0o % OOooOOo - i1IIi
  if 12 - 12: iII111i
  if 96 - 96: O0
  if 89 - 89: I1ii11iIi11i - Oo0Ooo
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
  if 26 - 26: ooOoO0o % ooOoO0o / II111iiii / iII111i
  if 2 - 2: i1IIi / i11iIiiIii + I1IiiI
 def print_prefix ( self ) :
  if ( self . group . is_null ( ) ) :
   return ( green ( self . eid . print_prefix ( ) , False ) )
   if 95 - 95: I1ii11iIi11i / IiII % iIii1I11I1II1 + O0
  return ( green ( self . eid . print_sg ( self . group ) , False ) )
  if 6 - 6: IiII
  if 73 - 73: o0oOOo0O0Ooo % o0oOOo0O0Ooo . OOooOOo * I1ii11iIi11i - Ii1I
 def print_ttl ( self ) :
  ooOOooooo0Oo = self . record_ttl
  if ( self . record_ttl & 0x80000000 ) :
   ooOOooooo0Oo = str ( self . record_ttl & 0x7fffffff ) + " secs"
  elif ( ( ooOOooooo0Oo % 60 ) == 0 ) :
   ooOOooooo0Oo = str ( ooOOooooo0Oo / 60 ) + " hours"
  else :
   ooOOooooo0Oo = str ( ooOOooooo0Oo ) + " mins"
   if 32 - 32: ooOoO0o / II111iiii . O0 . ooOoO0o % I1IiiI - o0oOOo0O0Ooo
  return ( ooOOooooo0Oo )
  if 69 - 69: Ii1I - I1IiiI * OOooOOo . iIii1I11I1II1 * OoOoOO00 . OoooooooOO
  if 6 - 6: O0 . o0oOOo0O0Ooo - OoOoOO00
 def store_ttl ( self ) :
  ooOOooooo0Oo = self . record_ttl * 60
  if ( self . record_ttl & 0x80000000 ) : ooOOooooo0Oo = self . record_ttl & 0x7fffffff
  return ( ooOOooooo0Oo )
  if 3 - 3: OoooooooOO % iIii1I11I1II1 * I1Ii111 % Oo0Ooo + iIii1I11I1II1
  if 66 - 66: Oo0Ooo - OoOoOO00
 def print_record ( self , indent , ddt ) :
  I111o0oooO00o0 = ""
  IiI1I = ""
  IiiIIII = bold ( "invalid-action" , False )
  if ( ddt ) :
   if ( self . action < len ( lisp_map_referral_action_string ) ) :
    IiiIIII = lisp_map_referral_action_string [ self . action ]
    IiiIIII = bold ( IiiIIII , False )
    I111o0oooO00o0 = ( ", " + bold ( "ddt-incomplete" , False ) ) if self . ddt_incomplete else ""
    if 17 - 17: I11i % OoOoOO00 . Oo0Ooo * o0oOOo0O0Ooo * I11i * Oo0Ooo
    IiI1I = ( ", sig-count: " + str ( self . signature_count ) ) if ( self . signature_count != 0 ) else ""
    if 36 - 36: OoooooooOO + ooOoO0o . oO0o * ooOoO0o + IiII
    if 45 - 45: oO0o / iII111i + I1ii11iIi11i - Oo0Ooo - ooOoO0o . iIii1I11I1II1
  else :
   if ( self . action < len ( lisp_map_reply_action_string ) ) :
    IiiIIII = lisp_map_reply_action_string [ self . action ]
    if ( self . action != LISP_NO_ACTION ) :
     IiiIIII = bold ( IiiIIII , False )
     if 52 - 52: I1IiiI + i1IIi . iII111i * I1IiiI
     if 31 - 31: Oo0Ooo % iIii1I11I1II1 . O0
     if 80 - 80: I11i / Oo0Ooo + I1ii11iIi11i
     if 18 - 18: II111iiii - iII111i / iIii1I11I1II1 % OoOoOO00 % I1ii11iIi11i / o0oOOo0O0Ooo
  o0O0O0O00o = LISP_AFI_LCAF if ( self . eid . afi < 0 ) else self . eid . afi
  OOooO = ( "{}EID-record -> record-ttl: {}, rloc-count: {}, action: " +
 "{}, {}{}{}, map-version: {}, afi: {}, [iid]eid/ml: {}" )
  if 47 - 47: OOooOOo
  lprint ( OOooO . format ( indent , self . print_ttl ( ) , self . rloc_count ,
 IiiIIII , "auth" if ( self . authoritative is True ) else "non-auth" ,
 I111o0oooO00o0 , IiI1I , self . map_version , o0O0O0O00o ,
 green ( self . print_prefix ( ) , False ) ) )
  if 24 - 24: Ii1I % o0oOOo0O0Ooo
  if 87 - 87: o0oOOo0O0Ooo % iII111i / ooOoO0o - IiII + i11iIiiIii
 def encode ( self ) :
  Ooo0oOo0o0oOo = self . action << 13
  if ( self . authoritative ) : Ooo0oOo0o0oOo |= 0x1000
  if ( self . ddt_incomplete ) : Ooo0oOo0o0oOo |= 0x800
  if 75 - 75: I1Ii111 . iIii1I11I1II1 + IiII % Oo0Ooo
  if 99 - 99: OOooOOo . iIii1I11I1II1
  if 45 - 45: I1Ii111 - O0 . I1Ii111 / I1Ii111 / OoOoOO00
  if 12 - 12: OOooOOo
  o0O0O0O00o = self . eid . afi if ( self . eid . instance_id == 0 ) else LISP_AFI_LCAF
  if ( o0O0O0O00o < 0 ) : o0O0O0O00o = LISP_AFI_LCAF
  OOO0oOO = ( self . group . is_null ( ) == False )
  if ( OOO0oOO ) : o0O0O0O00o = LISP_AFI_LCAF
  if 93 - 93: OOooOOo * Ii1I - o0oOOo0O0Ooo . oO0o . iII111i
  OOooo = ( self . signature_count << 12 ) | self . map_version
  OoOO = 0 if self . eid . is_binary ( ) == False else self . eid . mask_len
  if 44 - 44: I11i - i11iIiiIii
  I1IiO00Ooo0ooo0 = struct . pack ( "IBBHHH" , socket . htonl ( self . record_ttl ) ,
 self . rloc_count , OoOO , socket . htons ( Ooo0oOo0o0oOo ) ,
 socket . htons ( OOooo ) , socket . htons ( o0O0O0O00o ) )
  if 93 - 93: iII111i % i11iIiiIii - OoOoOO00 . Ii1I
  if 72 - 72: iIii1I11I1II1 * OOooOOo . iIii1I11I1II1
  if 62 - 62: IiII . IiII % ooOoO0o - OoOoOO00 / OoooooooOO . I1IiiI
  if 23 - 23: IiII + i11iIiiIii * Ii1I
  if ( OOO0oOO ) :
   I1IiO00Ooo0ooo0 += self . eid . lcaf_encode_sg ( self . group )
   return ( I1IiO00Ooo0ooo0 )
   if 55 - 55: Oo0Ooo % IiII + i11iIiiIii - OOooOOo - II111iiii
   if 80 - 80: IiII
   if 97 - 97: iII111i
   if 40 - 40: ooOoO0o
   if 61 - 61: iII111i - OOooOOo / iII111i . Oo0Ooo % OoO0O00
  if ( self . eid . afi == LISP_AFI_GEO_COORD and self . eid . instance_id == 0 ) :
   I1IiO00Ooo0ooo0 = I1IiO00Ooo0ooo0 [ 0 : - 2 ]
   I1IiO00Ooo0ooo0 += self . eid . address . encode_geo ( )
   return ( I1IiO00Ooo0ooo0 )
   if 70 - 70: I1Ii111 * Oo0Ooo
   if 75 - 75: I1IiiI . iII111i % iII111i * i11iIiiIii + i1IIi * Oo0Ooo
   if 98 - 98: Ii1I - OoooooooOO * I11i * oO0o % I1ii11iIi11i * II111iiii
   if 86 - 86: i11iIiiIii / I11i * iII111i - iII111i
   if 32 - 32: Oo0Ooo . O0
  if ( o0O0O0O00o == LISP_AFI_LCAF ) :
   I1IiO00Ooo0ooo0 += self . eid . lcaf_encode_iid ( )
   return ( I1IiO00Ooo0ooo0 )
   if 48 - 48: I1ii11iIi11i % II111iiii + I11i
   if 25 - 25: IiII * o0oOOo0O0Ooo / I1IiiI . IiII % II111iiii
   if 50 - 50: OoOoOO00 * iII111i
   if 59 - 59: I1IiiI * I1IiiI / I11i
   if 92 - 92: o0oOOo0O0Ooo
  I1IiO00Ooo0ooo0 += self . eid . pack_address ( )
  return ( I1IiO00Ooo0ooo0 )
  if 8 - 8: iII111i + I1ii11iIi11i . Ii1I
  if 50 - 50: Oo0Ooo
 def decode ( self , packet ) :
  O0000 = "IBBHHH"
  I1 = struct . calcsize ( O0000 )
  if ( len ( packet ) < I1 ) : return ( None )
  if 16 - 16: Ii1I - OoOoOO00 % Oo0Ooo / Ii1I . I11i + ooOoO0o
  self . record_ttl , self . rloc_count , self . eid . mask_len , Ooo0oOo0o0oOo , self . map_version , self . eid . afi = struct . unpack ( O0000 , packet [ : I1 ] )
  if 78 - 78: iIii1I11I1II1 + OoO0O00 + i11iIiiIii
  if 21 - 21: Oo0Ooo + Ii1I % ooOoO0o + OoOoOO00 % I11i
  if 22 - 22: i1IIi / OoooooooOO . OoO0O00
  self . record_ttl = socket . ntohl ( self . record_ttl )
  Ooo0oOo0o0oOo = socket . ntohs ( Ooo0oOo0o0oOo )
  self . action = ( Ooo0oOo0o0oOo >> 13 ) & 0x7
  self . authoritative = True if ( ( Ooo0oOo0o0oOo >> 12 ) & 1 ) else False
  self . ddt_incomplete = True if ( ( Ooo0oOo0o0oOo >> 11 ) & 1 ) else False
  self . map_version = socket . ntohs ( self . map_version )
  self . signature_count = self . map_version >> 12
  self . map_version = self . map_version & 0xfff
  self . eid . afi = socket . ntohs ( self . eid . afi )
  self . eid . instance_id = 0
  packet = packet [ I1 : : ]
  if 83 - 83: I1IiiI - OoooooooOO + I1ii11iIi11i . Ii1I / o0oOOo0O0Ooo + ooOoO0o
  if 90 - 90: I1IiiI - i11iIiiIii
  if 42 - 42: OOooOOo . Oo0Ooo
  if 21 - 21: iII111i . I1IiiI / I11i
  if ( self . eid . afi == LISP_AFI_LCAF ) :
   packet , ooOoO00 = self . eid . lcaf_decode_eid ( packet )
   if ( ooOoO00 ) : self . group = ooOoO00
   self . group . instance_id = self . eid . instance_id
   return ( packet )
   if 61 - 61: i11iIiiIii % I1Ii111 / o0oOOo0O0Ooo
   if 40 - 40: OOooOOo / Ii1I % I1IiiI / o0oOOo0O0Ooo . iII111i
  packet = self . eid . unpack_address ( packet )
  return ( packet )
  if 78 - 78: I11i - I1IiiI * IiII
  if 43 - 43: OoooooooOO . OOooOOo
 def print_eid_tuple ( self ) :
  return ( lisp_print_eid_tuple ( self . eid , self . group ) )
  if 33 - 33: o0oOOo0O0Ooo % OoOoOO00 * I1IiiI
  if 26 - 26: I11i . iII111i . o0oOOo0O0Ooo
  if 15 - 15: OoO0O00 / iII111i
  if 46 - 46: OoooooooOO . I1Ii111
  if 15 - 15: Ii1I
  if 84 - 84: OoOoOO00 - ooOoO0o - OoooooooOO . OoooooooOO % IiII
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
LISP_UDP_PROTOCOL = 17
LISP_DEFAULT_ECM_TTL = 128
if 60 - 60: I1ii11iIi11i - I1IiiI * O0 * Oo0Ooo . i1IIi . OoOoOO00
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
  if 24 - 24: IiII * I1IiiI / OOooOOo
  if 51 - 51: iIii1I11I1II1 / I11i * OoO0O00 * Ii1I + I1ii11iIi11i . OoooooooOO
 def print_ecm ( self ) :
  OOooO = ( "{} -> flags: {}{}{}{}, " + "inner IP: {} -> {}, inner UDP: {} -> {}" )
  if 75 - 75: IiII / OoooooooOO / O0 % OOooOOo
  lprint ( OOooO . format ( bold ( "ECM" , False ) , "S" if self . security else "s" ,
 "D" if self . ddt else "d" , "E" if self . to_etr else "e" ,
 "M" if self . to_ms else "m" ,
 green ( self . source . print_address ( ) , False ) ,
 green ( self . dest . print_address ( ) , False ) , self . udp_sport ,
 self . udp_dport ) )
  if 87 - 87: II111iiii / iIii1I11I1II1 % I1ii11iIi11i
 def encode ( self , packet , inner_source , inner_dest ) :
  self . udp_length = len ( packet ) + 8
  self . source = inner_source
  self . dest = inner_dest
  if ( inner_dest . is_ipv4 ( ) ) :
   self . afi = LISP_AFI_IPV4
   self . length = self . udp_length + 20
   if 11 - 11: o0oOOo0O0Ooo * OoO0O00
  if ( inner_dest . is_ipv6 ( ) ) :
   self . afi = LISP_AFI_IPV6
   self . length = self . udp_length
   if 92 - 92: OoOoOO00 . Oo0Ooo * I11i
   if 86 - 86: O0
   if 55 - 55: Ii1I / I1Ii111 / I1ii11iIi11i % ooOoO0o % I1IiiI
   if 55 - 55: oO0o + OoooooooOO % i1IIi
   if 24 - 24: I1ii11iIi11i - Oo0Ooo
   if 36 - 36: I1IiiI . OOooOOo % II111iiii * IiII
  ooOOOo0 = ( LISP_ECM << 28 )
  if ( self . security ) : ooOOOo0 |= 0x08000000
  if ( self . ddt ) : ooOOOo0 |= 0x04000000
  if ( self . to_etr ) : ooOOOo0 |= 0x02000000
  if ( self . to_ms ) : ooOOOo0 |= 0x01000000
  if 34 - 34: I11i % iII111i - ooOoO0o - I1IiiI
  I1i = struct . pack ( "I" , socket . htonl ( ooOOOo0 ) )
  if 51 - 51: I1ii11iIi11i . I1IiiI / i1IIi
  oOo00Ooo0o0 = ""
  if ( self . afi == LISP_AFI_IPV4 ) :
   oOo00Ooo0o0 = struct . pack ( "BBHHHBBH" , 0x45 , 0 , socket . htons ( self . length ) ,
 0 , 0 , self . ttl , self . protocol , socket . htons ( self . ip_checksum ) )
   oOo00Ooo0o0 += self . source . pack_address ( )
   oOo00Ooo0o0 += self . dest . pack_address ( )
   oOo00Ooo0o0 = lisp_ip_checksum ( oOo00Ooo0o0 )
   if 79 - 79: O0 % OoooooooOO - OoooooooOO . Ii1I + Oo0Ooo - Ii1I
  if ( self . afi == LISP_AFI_IPV6 ) :
   oOo00Ooo0o0 = struct . pack ( "BBHHBB" , 0x60 , 0 , 0 , socket . htons ( self . length ) ,
 self . protocol , self . ttl )
   oOo00Ooo0o0 += self . source . pack_address ( )
   oOo00Ooo0o0 += self . dest . pack_address ( )
   if 94 - 94: ooOoO0o % I1ii11iIi11i + OoooooooOO
   if 77 - 77: O0 - Ii1I * II111iiii / I1ii11iIi11i / Ii1I - oO0o
  i1I1iIi1IiI = socket . htons ( self . udp_sport )
  i1i11ii1Ii = socket . htons ( self . udp_dport )
  i1I1i = socket . htons ( self . udp_length )
  II1i1iI = socket . htons ( self . udp_checksum )
  IIi1ii1 = struct . pack ( "HHHH" , i1I1iIi1IiI , i1i11ii1Ii , i1I1i , II1i1iI )
  return ( I1i + oOo00Ooo0o0 + IIi1ii1 )
  if 66 - 66: OoO0O00 % Oo0Ooo . II111iiii
  if 84 - 84: ooOoO0o * OoooooooOO + O0
 def decode ( self , packet ) :
  if 84 - 84: i1IIi . I11i . i1IIi . Oo0Ooo
  if 21 - 21: II111iiii . O0 + Oo0Ooo - i11iIiiIii
  if 5 - 5: iIii1I11I1II1 * i11iIiiIii + OoO0O00 + I11i * O0 % ooOoO0o
  if 88 - 88: o0oOOo0O0Ooo / i11iIiiIii * I1ii11iIi11i
  O0000 = "I"
  I1 = struct . calcsize ( O0000 )
  if ( len ( packet ) < I1 ) : return ( None )
  if 23 - 23: O0 / iII111i
  ooOOOo0 = struct . unpack ( O0000 , packet [ : I1 ] )
  if 66 - 66: i1IIi % OoooooooOO * i11iIiiIii + oO0o * O0 / OoO0O00
  ooOOOo0 = socket . ntohl ( ooOOOo0 [ 0 ] )
  self . security = True if ( ooOOOo0 & 0x08000000 ) else False
  self . ddt = True if ( ooOOOo0 & 0x04000000 ) else False
  self . to_etr = True if ( ooOOOo0 & 0x02000000 ) else False
  self . to_ms = True if ( ooOOOo0 & 0x01000000 ) else False
  packet = packet [ I1 : : ]
  if 14 - 14: I1IiiI . IiII
  if 29 - 29: OoooooooOO / IiII + OoOoOO00 - I1Ii111 + IiII . i1IIi
  if 26 - 26: i11iIiiIii - II111iiii
  if 43 - 43: I1IiiI
  if ( len ( packet ) < 1 ) : return ( None )
  oo0O0 = struct . unpack ( "B" , packet [ 0 : 1 ] ) [ 0 ]
  oo0O0 = oo0O0 >> 4
  if 35 - 35: ooOoO0o + OoOoOO00 * OoooooooOO - II111iiii
  if ( oo0O0 == 4 ) :
   I1 = struct . calcsize ( "HHIBBH" )
   if ( len ( packet ) < I1 ) : return ( None )
   if 19 - 19: i1IIi / Ii1I / OoOoOO00 . I1IiiI / Ii1I % o0oOOo0O0Ooo
   i1i11Ii1 , i1I1i , i1i11Ii1 , I1IiI1iIII1I , oo000o , II1i1iI = struct . unpack ( "HHIBBH" , packet [ : I1 ] )
   self . length = socket . ntohs ( i1I1i )
   self . ttl = I1IiI1iIII1I
   self . protocol = oo000o
   self . ip_checksum = socket . ntohs ( II1i1iI )
   self . source . afi = self . dest . afi = LISP_AFI_IPV4
   if 95 - 95: II111iiii + I1IiiI
   if 59 - 59: Ii1I
   if 59 - 59: II111iiii - OoO0O00
   if 31 - 31: I11i - OoOoOO00 / o0oOOo0O0Ooo * OoOoOO00 / Oo0Ooo + o0oOOo0O0Ooo
   oo000o = struct . pack ( "H" , 0 )
   I1iII1IiI11i = struct . calcsize ( "HHIBB" )
   OOOoO = struct . calcsize ( "H" )
   packet = packet [ : I1iII1IiI11i ] + oo000o + packet [ I1iII1IiI11i + OOOoO : ]
   if 93 - 93: i11iIiiIii * o0oOOo0O0Ooo
   packet = packet [ I1 : : ]
   packet = self . source . unpack_address ( packet )
   if ( packet == None ) : return ( None )
   packet = self . dest . unpack_address ( packet )
   if ( packet == None ) : return ( None )
   if 34 - 34: iII111i - II111iiii + OoO0O00 / i11iIiiIii * IiII
   if 23 - 23: OoO0O00 / o0oOOo0O0Ooo
  if ( oo0O0 == 6 ) :
   I1 = struct . calcsize ( "IHBB" )
   if ( len ( packet ) < I1 ) : return ( None )
   if 22 - 22: OOooOOo - OoO0O00 . I11i
   i1i11Ii1 , i1I1i , oo000o , I1IiI1iIII1I = struct . unpack ( "IHBB" , packet [ : I1 ] )
   self . length = socket . ntohs ( i1I1i )
   self . protocol = oo000o
   self . ttl = I1IiI1iIII1I
   self . source . afi = self . dest . afi = LISP_AFI_IPV6
   if 89 - 89: I1Ii111
   packet = packet [ I1 : : ]
   packet = self . source . unpack_address ( packet )
   if ( packet == None ) : return ( None )
   packet = self . dest . unpack_address ( packet )
   if ( packet == None ) : return ( None )
   if 19 - 19: IiII + I1Ii111
   if 65 - 65: Ii1I - oO0o + i1IIi + OOooOOo % iII111i
  self . source . mask_len = self . source . host_mask_len ( )
  self . dest . mask_len = self . dest . host_mask_len ( )
  if 5 - 5: OoO0O00 / iII111i / OOooOOo
  I1 = struct . calcsize ( "HHHH" )
  if ( len ( packet ) < I1 ) : return ( None )
  if 70 - 70: OoOoOO00 - I11i + ooOoO0o / i11iIiiIii / I1IiiI % iIii1I11I1II1
  i1I1iIi1IiI , i1i11ii1Ii , i1I1i , II1i1iI = struct . unpack ( "HHHH" , packet [ : I1 ] )
  self . udp_sport = socket . ntohs ( i1I1iIi1IiI )
  self . udp_dport = socket . ntohs ( i1i11ii1Ii )
  self . udp_length = socket . ntohs ( i1I1i )
  self . udp_checksum = socket . ntohs ( II1i1iI )
  packet = packet [ I1 : : ]
  return ( packet )
  if 83 - 83: oO0o . Ii1I - o0oOOo0O0Ooo % I11i + i11iIiiIii
  if 40 - 40: O0 . Ii1I
  if 58 - 58: i11iIiiIii * iII111i / Ii1I - oO0o - I1ii11iIi11i % o0oOOo0O0Ooo
  if 16 - 16: OoooooooOO
  if 71 - 71: Ii1I % O0 / I1Ii111 % iII111i - II111iiii / OoO0O00
  if 30 - 30: I11i
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
  if 75 - 75: iII111i % O0 - I11i - I1ii11iIi11i + I1IiiI - I1IiiI
  if 87 - 87: i1IIi % Ii1I % i1IIi + iIii1I11I1II1
 def print_rloc_name ( self , cour = False ) :
  if ( self . rloc_name == None ) : return ( "" )
  Iii1I1III1ii = self . rloc_name
  if ( cour ) : Iii1I1III1ii = lisp_print_cour ( Iii1I1III1ii )
  return ( 'rloc-name: {}' . format ( blue ( Iii1I1III1ii , cour ) ) )
  if 94 - 94: OOooOOo . OoooooooOO
  if 46 - 46: IiII * OoooooooOO . o0oOOo0O0Ooo - I1Ii111 * I1IiiI
 def print_record ( self , indent ) :
  Oo0oO = self . print_rloc_name ( )
  if ( Oo0oO != "" ) : Oo0oO = ", " + Oo0oO
  OOOo0O0oOOOoO0o = ""
  if ( self . geo ) :
   i1i1IIi1II = ""
   if ( self . geo . geo_name ) : i1i1IIi1II = "'{}' " . format ( self . geo . geo_name )
   OOOo0O0oOOOoO0o = ", geo: {}{}" . format ( i1i1IIi1II , self . geo . print_geo ( ) )
   if 87 - 87: OOooOOo . o0oOOo0O0Ooo
  O0o0ooO0 = ""
  if ( self . elp ) :
   i1i1IIi1II = ""
   if ( self . elp . elp_name ) : i1i1IIi1II = "'{}' " . format ( self . elp . elp_name )
   O0o0ooO0 = ", elp: {}{}" . format ( i1i1IIi1II , self . elp . print_elp ( True ) )
   if 16 - 16: iII111i . IiII . OoO0O00
  ii1OoO00o = ""
  if ( self . rle ) :
   i1i1IIi1II = ""
   if ( self . rle . rle_name ) : i1i1IIi1II = "'{}' " . format ( self . rle . rle_name )
   ii1OoO00o = ", rle: {}{}" . format ( i1i1IIi1II , self . rle . print_rle ( False ) )
   if 76 - 76: O0 + II111iiii * OoO0O00
  iI1IIi1I = ""
  if ( self . json ) :
   i1i1IIi1II = ""
   if ( self . json . json_name ) :
    i1i1IIi1II = "'{}' " . format ( self . json . json_name )
    if 42 - 42: OoooooooOO / IiII * II111iiii
   iI1IIi1I = ", json: {}" . format ( self . json . print_json ( False ) )
   if 77 - 77: II111iiii + iII111i . o0oOOo0O0Ooo / I1Ii111
   if 100 - 100: Ii1I
  O0O0OoO0o0OO = ""
  if ( self . rloc . is_null ( ) == False and self . keys and self . keys [ 1 ] ) :
   O0O0OoO0o0OO = ", " + self . keys [ 1 ] . print_keys ( )
   if 18 - 18: i11iIiiIii / o0oOOo0O0Ooo - oO0o . I11i * i1IIi
   if 67 - 67: Ii1I
  OOooO = ( "{}RLOC-record -> flags: {}, {}/{}/{}/{}, afi: {}, rloc: "
 + "{}{}{}{}{}{}{}" )
  lprint ( OOooO . format ( indent , self . print_flags ( ) , self . priority ,
 self . weight , self . mpriority , self . mweight , self . rloc . afi ,
 red ( self . rloc . print_address_no_iid ( ) , False ) , Oo0oO , OOOo0O0oOOOoO0o ,
 O0o0ooO0 , ii1OoO00o , iI1IIi1I , O0O0OoO0o0OO ) )
  if 64 - 64: OoOoOO00 + iII111i * OoOoOO00 - I1IiiI * OoooooooOO
  if 27 - 27: II111iiii + i11iIiiIii
 def print_flags ( self ) :
  return ( "{}{}{}" . format ( "L" if self . local_bit else "l" , "P" if self . probe_bit else "p" , "R" if self . reach_bit else "r" ) )
  if 32 - 32: i1IIi
  if 76 - 76: II111iiii % ooOoO0o - I1ii11iIi11i
  if 50 - 50: II111iiii / I1IiiI . Ii1I % i11iIiiIii
 def store_rloc_entry ( self , rloc_entry ) :
  oOoOoo0O = rloc_entry . rloc if ( rloc_entry . translated_rloc . is_null ( ) ) else rloc_entry . translated_rloc
  if 77 - 77: iII111i / i11iIiiIii
  self . rloc . copy_address ( oOoOoo0O )
  if 20 - 20: O0 . I11i
  if ( rloc_entry . rloc_name ) :
   self . rloc_name = rloc_entry . rloc_name
   if 67 - 67: OoOoOO00 - ooOoO0o - iIii1I11I1II1
   if 31 - 31: II111iiii + o0oOOo0O0Ooo * i11iIiiIii . o0oOOo0O0Ooo
  if ( rloc_entry . geo ) :
   self . geo = rloc_entry . geo
  else :
   i1i1IIi1II = rloc_entry . geo_name
   if ( i1i1IIi1II and lisp_geo_list . has_key ( i1i1IIi1II ) ) :
    self . geo = lisp_geo_list [ i1i1IIi1II ]
    if 73 - 73: oO0o / OOooOOo * II111iiii % OoooooooOO - i1IIi - ooOoO0o
    if 43 - 43: o0oOOo0O0Ooo + Ii1I % OoO0O00 . I1Ii111 + i1IIi
  if ( rloc_entry . elp ) :
   self . elp = rloc_entry . elp
  else :
   i1i1IIi1II = rloc_entry . elp_name
   if ( i1i1IIi1II and lisp_elp_list . has_key ( i1i1IIi1II ) ) :
    self . elp = lisp_elp_list [ i1i1IIi1II ]
    if 85 - 85: Oo0Ooo % I1ii11iIi11i / OOooOOo
    if 65 - 65: ooOoO0o + IiII - OoOoOO00 % II111iiii - iIii1I11I1II1
  if ( rloc_entry . rle ) :
   self . rle = rloc_entry . rle
  else :
   i1i1IIi1II = rloc_entry . rle_name
   if ( i1i1IIi1II and lisp_rle_list . has_key ( i1i1IIi1II ) ) :
    self . rle = lisp_rle_list [ i1i1IIi1II ]
    if 39 - 39: I1IiiI + I1ii11iIi11i - i11iIiiIii
    if 43 - 43: iIii1I11I1II1
  if ( rloc_entry . json ) :
   self . json = rloc_entry . json
  else :
   i1i1IIi1II = rloc_entry . json_name
   if ( i1i1IIi1II and lisp_json_list . has_key ( i1i1IIi1II ) ) :
    self . json = lisp_json_list [ i1i1IIi1II ]
    if 73 - 73: OoOoOO00 + o0oOOo0O0Ooo
    if 58 - 58: i1IIi * I1ii11iIi11i % iII111i . OoO0O00 % IiII % I11i
  self . priority = rloc_entry . priority
  self . weight = rloc_entry . weight
  self . mpriority = rloc_entry . mpriority
  self . mweight = rloc_entry . mweight
  if 63 - 63: I1ii11iIi11i % ooOoO0o % I1ii11iIi11i
  if 71 - 71: Ii1I
 def encode_lcaf ( self ) :
  ii1Ii111I11 = socket . htons ( LISP_AFI_LCAF )
  iI11 = ""
  if ( self . geo ) :
   iI11 = self . geo . encode_geo ( )
   if 55 - 55: OoOoOO00 . o0oOOo0O0Ooo / O0 + OoOoOO00
   if 6 - 6: ooOoO0o + oO0o % iII111i / i1IIi
  II111I = ""
  if ( self . elp ) :
   Ii11IIIi1I = ""
   for IIII1Ii1II1 in self . elp . elp_nodes :
    o0O0O0O00o = socket . htons ( IIII1Ii1II1 . address . afi )
    O0O0oooo = 0
    if ( IIII1Ii1II1 . eid ) : O0O0oooo |= 0x4
    if ( IIII1Ii1II1 . probe ) : O0O0oooo |= 0x2
    if ( IIII1Ii1II1 . strict ) : O0O0oooo |= 0x1
    O0O0oooo = socket . htons ( O0O0oooo )
    Ii11IIIi1I += struct . pack ( "HH" , O0O0oooo , o0O0O0O00o )
    Ii11IIIi1I += IIII1Ii1II1 . address . pack_address ( )
    if 39 - 39: i11iIiiIii * OoOoOO00 . OoOoOO00 . I1ii11iIi11i . Oo0Ooo
    if 61 - 61: I11i / OOooOOo
   OOo0oOOO0 = socket . htons ( len ( Ii11IIIi1I ) )
   II111I = struct . pack ( "HBBBBH" , ii1Ii111I11 , 0 , 0 , LISP_LCAF_ELP_TYPE ,
 0 , OOo0oOOO0 )
   II111I += Ii11IIIi1I
   if 79 - 79: OoooooooOO * OoO0O00 + OoO0O00 % Ii1I % OOooOOo * IiII
   if 11 - 11: OOooOOo - Ii1I
  IIII11 = ""
  if ( self . rle ) :
   OoOOo = ""
   for oOo0o in self . rle . rle_nodes :
    o0O0O0O00o = socket . htons ( oOo0o . address . afi )
    OoOOo += struct . pack ( "HBBH" , 0 , 0 , oOo0o . level , o0O0O0O00o )
    OoOOo += oOo0o . address . pack_address ( )
    if ( oOo0o . rloc_name ) :
     OoOOo += struct . pack ( "H" , socket . htons ( LISP_AFI_NAME ) )
     OoOOo += oOo0o . rloc_name + "\0"
     if 16 - 16: I1IiiI - i11iIiiIii
     if 41 - 41: oO0o . I1Ii111 + O0 - oO0o . OoOoOO00 * OoO0O00
     if 6 - 6: ooOoO0o / oO0o % o0oOOo0O0Ooo + ooOoO0o / II111iiii - I1Ii111
   O000ooo = socket . htons ( len ( OoOOo ) )
   IIII11 = struct . pack ( "HBBBBH" , ii1Ii111I11 , 0 , 0 , LISP_LCAF_RLE_TYPE ,
 0 , O000ooo )
   IIII11 += OoOOo
   if 32 - 32: OOooOOo + IiII
   if 36 - 36: I11i + I1Ii111 . OOooOOo % o0oOOo0O0Ooo / Ii1I * i1IIi
  II1Oooo00oO0OO0o = ""
  if ( self . json ) :
   IiiiI1I1i = socket . htons ( len ( self . json . json_string ) + 2 )
   OOI11iiII1Iii1 = socket . htons ( len ( self . json . json_string ) )
   II1Oooo00oO0OO0o = struct . pack ( "HBBBBHH" , ii1Ii111I11 , 0 , 0 , LISP_LCAF_JSON_TYPE ,
 0 , IiiiI1I1i , OOI11iiII1Iii1 )
   II1Oooo00oO0OO0o += self . json . json_string
   II1Oooo00oO0OO0o += struct . pack ( "H" , 0 )
   if 47 - 47: Oo0Ooo / OoOoOO00
   if 26 - 26: I11i . I1ii11iIi11i
  OO00OOOO00oOO = ""
  if ( self . rloc . is_null ( ) == False and self . keys and self . keys [ 1 ] ) :
   OO00OOOO00oOO = self . keys [ 1 ] . encode_lcaf ( self . rloc )
   if 56 - 56: IiII * Ii1I . II111iiii / OoOoOO00
   if 70 - 70: I1ii11iIi11i
  oOo0O0o = ""
  if ( self . rloc_name ) :
   oOo0O0o += struct . pack ( "H" , socket . htons ( LISP_AFI_NAME ) )
   oOo0O0o += self . rloc_name + "\0"
   if 41 - 41: ooOoO0o * i11iIiiIii % ooOoO0o . oO0o
   if 97 - 97: oO0o - iII111i + IiII . OoOoOO00 + iIii1I11I1II1
  O0o000 = len ( iI11 ) + len ( II111I ) + len ( IIII11 ) + len ( OO00OOOO00oOO ) + 2 + len ( II1Oooo00oO0OO0o ) + self . rloc . addr_length ( ) + len ( oOo0O0o )
  if 28 - 28: iIii1I11I1II1 * iIii1I11I1II1 * ooOoO0o % I1ii11iIi11i / i11iIiiIii
  O0o000 = socket . htons ( O0o000 )
  oOoOO0o = struct . pack ( "HBBBBHH" , ii1Ii111I11 , 0 , 0 , LISP_LCAF_AFI_LIST_TYPE ,
 0 , O0o000 , socket . htons ( self . rloc . afi ) )
  oOoOO0o += self . rloc . pack_address ( )
  return ( oOoOO0o + oOo0O0o + iI11 + II111I + IIII11 + OO00OOOO00oOO + II1Oooo00oO0OO0o )
  if 87 - 87: oO0o / OoO0O00 / i11iIiiIii / OoooooooOO
  if 25 - 25: I1IiiI . Oo0Ooo + iIii1I11I1II1 * iII111i % Oo0Ooo . OoOoOO00
 def encode ( self ) :
  O0O0oooo = 0
  if ( self . local_bit ) : O0O0oooo |= 0x0004
  if ( self . probe_bit ) : O0O0oooo |= 0x0002
  if ( self . reach_bit ) : O0O0oooo |= 0x0001
  if 13 - 13: Ii1I - Oo0Ooo
  I1IiO00Ooo0ooo0 = struct . pack ( "BBBBHH" , self . priority , self . weight ,
 self . mpriority , self . mweight , socket . htons ( O0O0oooo ) ,
 socket . htons ( self . rloc . afi ) )
  if 91 - 91: I1IiiI - OoooooooOO - OoooooooOO
  if ( self . geo or self . elp or self . rle or self . keys or self . rloc_name or self . json ) :
   if 69 - 69: iII111i * i11iIiiIii / i1IIi
   I1IiO00Ooo0ooo0 = I1IiO00Ooo0ooo0 [ 0 : - 2 ] + self . encode_lcaf ( )
  else :
   I1IiO00Ooo0ooo0 += self . rloc . pack_address ( )
   if 86 - 86: I1IiiI % I11i * O0 + i1IIi % I1Ii111
  return ( I1IiO00Ooo0ooo0 )
  if 97 - 97: II111iiii * OoOoOO00 - I1Ii111 / i11iIiiIii / OoOoOO00
  if 25 - 25: Oo0Ooo / Oo0Ooo
 def decode_lcaf ( self , packet , nonce ) :
  O0000 = "HBBBBH"
  I1 = struct . calcsize ( O0000 )
  if ( len ( packet ) < I1 ) : return ( None )
  if 74 - 74: OOooOOo
  o0O0O0O00o , OOoooOOO0 , O0O0oooo , OO , O0o , IiiiI1I1i = struct . unpack ( O0000 , packet [ : I1 ] )
  if 30 - 30: O0 . Ii1I / o0oOOo0O0Ooo + I1IiiI - O0
  if 88 - 88: i11iIiiIii
  IiiiI1I1i = socket . ntohs ( IiiiI1I1i )
  packet = packet [ I1 : : ]
  if ( IiiiI1I1i > len ( packet ) ) : return ( None )
  if 33 - 33: OoO0O00 + O0
  if 20 - 20: o0oOOo0O0Ooo % I11i . ooOoO0o - i1IIi . O0
  if 10 - 10: i1IIi
  if 49 - 49: I1Ii111 - Ii1I . O0
  if ( OO == LISP_LCAF_AFI_LIST_TYPE ) :
   while ( IiiiI1I1i > 0 ) :
    O0000 = "H"
    I1 = struct . calcsize ( O0000 )
    if ( IiiiI1I1i < I1 ) : return ( None )
    if 46 - 46: OOooOOo
    iI1i11i = len ( packet )
    o0O0O0O00o = struct . unpack ( O0000 , packet [ : I1 ] ) [ 0 ]
    o0O0O0O00o = socket . ntohs ( o0O0O0O00o )
    if 64 - 64: I1IiiI / OoOoOO00
    if ( o0O0O0O00o == LISP_AFI_LCAF ) :
     packet = self . decode_lcaf ( packet , nonce )
     if ( packet == None ) : return ( None )
    else :
     packet = packet [ I1 : : ]
     self . rloc_name = None
     if ( o0O0O0O00o == LISP_AFI_NAME ) :
      packet , Iii1I1III1ii = lisp_decode_dist_name ( packet )
      self . rloc_name = Iii1I1III1ii
     else :
      self . rloc . afi = o0O0O0O00o
      packet = self . rloc . unpack_address ( packet )
      if ( packet == None ) : return ( None )
      self . rloc . mask_len = self . rloc . host_mask_len ( )
      if 6 - 6: i11iIiiIii - iII111i * i1IIi - iII111i
      if 8 - 8: I11i / i11iIiiIii . O0 / OoO0O00 * oO0o + I1Ii111
      if 91 - 91: I1IiiI
    IiiiI1I1i -= iI1i11i - len ( packet )
    if 84 - 84: O0 % Ii1I
    if 3 - 3: I1IiiI . I11i / I1ii11iIi11i
  elif ( OO == LISP_LCAF_GEO_COORD_TYPE ) :
   if 2 - 2: IiII + I11i / iIii1I11I1II1 . i11iIiiIii . i1IIi * ooOoO0o
   if 14 - 14: Oo0Ooo . O0 - oO0o - i11iIiiIii
   if 8 - 8: I1IiiI / iIii1I11I1II1 / OoooooooOO / Oo0Ooo / ooOoO0o
   if 80 - 80: I11i
   IiiiIi = lisp_geo ( "" )
   packet = IiiiIi . decode_geo ( packet , IiiiI1I1i , O0o )
   if ( packet == None ) : return ( None )
   self . geo = IiiiIi
   if 81 - 81: i11iIiiIii + o0oOOo0O0Ooo / II111iiii + I11i
  elif ( OO == LISP_LCAF_JSON_TYPE ) :
   if 73 - 73: OoO0O00 + OOooOOo + IiII - i1IIi
   if 67 - 67: OoooooooOO - i1IIi + Ii1I + I1IiiI
   if 18 - 18: Oo0Ooo * iII111i / II111iiii
   if 77 - 77: Ii1I . o0oOOo0O0Ooo * oO0o
   O0000 = "H"
   I1 = struct . calcsize ( O0000 )
   if ( IiiiI1I1i < I1 ) : return ( None )
   if 42 - 42: Ii1I / Oo0Ooo
   OOI11iiII1Iii1 = struct . unpack ( O0000 , packet [ : I1 ] ) [ 0 ]
   OOI11iiII1Iii1 = socket . ntohs ( OOI11iiII1Iii1 )
   if ( IiiiI1I1i < I1 + OOI11iiII1Iii1 ) : return ( None )
   if 25 - 25: OoooooooOO % Ii1I * I1Ii111 * I11i + I1IiiI % I1ii11iIi11i
   packet = packet [ I1 : : ]
   self . json = lisp_json ( "" , packet [ 0 : OOI11iiII1Iii1 ] )
   packet = packet [ OOI11iiII1Iii1 : : ]
   if 70 - 70: Ii1I + I1ii11iIi11i * I11i * i1IIi . I1Ii111
  elif ( OO == LISP_LCAF_ELP_TYPE ) :
   if 76 - 76: OoooooooOO * OoOoOO00 . OoooooooOO
   if 46 - 46: ooOoO0o * o0oOOo0O0Ooo % II111iiii / I1Ii111
   if 29 - 29: OoO0O00 - i11iIiiIii % Oo0Ooo % o0oOOo0O0Ooo
   if 30 - 30: oO0o - Ii1I % Ii1I
   i1Ii1IiIii1I = lisp_elp ( None )
   i1Ii1IiIii1I . elp_nodes = [ ]
   while ( IiiiI1I1i > 0 ) :
    O0O0oooo , o0O0O0O00o = struct . unpack ( "HH" , packet [ : 4 ] )
    if 38 - 38: iII111i . O0 . o0oOOo0O0Ooo
    o0O0O0O00o = socket . ntohs ( o0O0O0O00o )
    if ( o0O0O0O00o == LISP_AFI_LCAF ) : return ( None )
    if 43 - 43: I11i - iIii1I11I1II1 - I11i
    IIII1Ii1II1 = lisp_elp_node ( )
    i1Ii1IiIii1I . elp_nodes . append ( IIII1Ii1II1 )
    if 58 - 58: ooOoO0o
    O0O0oooo = socket . ntohs ( O0O0oooo )
    IIII1Ii1II1 . eid = ( O0O0oooo & 0x4 )
    IIII1Ii1II1 . probe = ( O0O0oooo & 0x2 )
    IIII1Ii1II1 . strict = ( O0O0oooo & 0x1 )
    IIII1Ii1II1 . address . afi = o0O0O0O00o
    IIII1Ii1II1 . address . mask_len = IIII1Ii1II1 . address . host_mask_len ( )
    packet = IIII1Ii1II1 . address . unpack_address ( packet [ 4 : : ] )
    IiiiI1I1i -= IIII1Ii1II1 . address . addr_length ( ) + 4
    if 98 - 98: Ii1I / OoO0O00 % OoooooooOO
   i1Ii1IiIii1I . select_elp_node ( )
   self . elp = i1Ii1IiIii1I
   if 65 - 65: ooOoO0o % Oo0Ooo - I1IiiI % I1Ii111 + iIii1I11I1II1 / iIii1I11I1II1
  elif ( OO == LISP_LCAF_RLE_TYPE ) :
   if 94 - 94: IiII - Oo0Ooo . o0oOOo0O0Ooo - ooOoO0o - oO0o . I11i
   if 39 - 39: oO0o + OoOoOO00
   if 68 - 68: i1IIi * oO0o / i11iIiiIii
   if 96 - 96: I1IiiI
   Oo0OOo = lisp_rle ( None )
   Oo0OOo . rle_nodes = [ ]
   while ( IiiiI1I1i > 0 ) :
    i1i11Ii1 , o0OoO0 , iiII1 , o0O0O0O00o = struct . unpack ( "HBBH" , packet [ : 6 ] )
    if 66 - 66: o0oOOo0O0Ooo % iIii1I11I1II1
    o0O0O0O00o = socket . ntohs ( o0O0O0O00o )
    if ( o0O0O0O00o == LISP_AFI_LCAF ) : return ( None )
    if 5 - 5: II111iiii % ooOoO0o % OoOoOO00 * i1IIi
    oOo0o = lisp_rle_node ( )
    Oo0OOo . rle_nodes . append ( oOo0o )
    if 8 - 8: iIii1I11I1II1 - i11iIiiIii
    oOo0o . level = iiII1
    oOo0o . address . afi = o0O0O0O00o
    oOo0o . address . mask_len = oOo0o . address . host_mask_len ( )
    packet = oOo0o . address . unpack_address ( packet [ 6 : : ] )
    if 29 - 29: OOooOOo - i11iIiiIii % IiII / OoooooooOO
    IiiiI1I1i -= oOo0o . address . addr_length ( ) + 6
    if ( IiiiI1I1i >= 2 ) :
     o0O0O0O00o = struct . unpack ( "H" , packet [ : 2 ] ) [ 0 ]
     if ( socket . ntohs ( o0O0O0O00o ) == LISP_AFI_NAME ) :
      packet = packet [ 2 : : ]
      packet , oOo0o . rloc_name = lisp_decode_dist_name ( packet )
      if 92 - 92: I1ii11iIi11i
      if ( packet == None ) : return ( None )
      IiiiI1I1i -= len ( oOo0o . rloc_name ) + 1 + 2
      if 89 - 89: OoO0O00 * i11iIiiIii - IiII * i1IIi - ooOoO0o . Ii1I
      if 26 - 26: I1IiiI * OoooooooOO / I1IiiI . O0 . ooOoO0o + O0
      if 84 - 84: I1Ii111 . O0 + O0 % O0 % i1IIi + iIii1I11I1II1
   self . rle = Oo0OOo
   self . rle . build_forwarding_list ( )
   if 71 - 71: iII111i / iIii1I11I1II1 . OOooOOo * i11iIiiIii
  elif ( OO == LISP_LCAF_SECURITY_TYPE ) :
   if 98 - 98: O0 % iIii1I11I1II1 . IiII - II111iiii
   if 14 - 14: Ii1I % ooOoO0o - OoOoOO00
   if 52 - 52: OoO0O00 / i1IIi - Ii1I
   if 8 - 8: oO0o + ooOoO0o . I1ii11iIi11i . i1IIi / I1IiiI . IiII
   if 8 - 8: i1IIi * O0
   O00Ooo00 = packet
   oo0OOOOOO = lisp_keys ( 1 )
   packet = oo0OOOOOO . decode_lcaf ( O00Ooo00 , IiiiI1I1i )
   if ( packet == None ) : return ( None )
   if 60 - 60: Oo0Ooo - II111iiii + I1IiiI
   if 17 - 17: OoOoOO00 % I1IiiI
   if 8 - 8: Oo0Ooo
   if 49 - 49: OoOoOO00 * I11i - o0oOOo0O0Ooo / OoO0O00 * oO0o
   i11iIi1I1i1 = [ LISP_CS_25519_CBC , LISP_CS_25519_CHACHA ]
   if ( oo0OOOOOO . cipher_suite in i11iIi1I1i1 ) :
    if ( oo0OOOOOO . cipher_suite == LISP_CS_25519_CBC ) :
     iIIIi = lisp_keys ( 1 , do_poly = False , do_chacha = False )
     if 51 - 51: ooOoO0o - iIii1I11I1II1 . I11i * OoOoOO00 + I1Ii111 * i1IIi
    if ( oo0OOOOOO . cipher_suite == LISP_CS_25519_CHACHA ) :
     iIIIi = lisp_keys ( 1 , do_poly = True , do_chacha = True )
     if 37 - 37: IiII * oO0o / OoooooooOO . OoO0O00
   else :
    iIIIi = lisp_keys ( 1 , do_poly = False , do_chacha = False )
    if 77 - 77: II111iiii + OoOoOO00 * OOooOOo
   packet = iIIIi . decode_lcaf ( O00Ooo00 , IiiiI1I1i )
   if ( packet == None ) : return ( None )
   if 9 - 9: II111iiii - i11iIiiIii * o0oOOo0O0Ooo % OoO0O00 * i11iIiiIii / I11i
   if ( len ( packet ) < 2 ) : return ( None )
   o0O0O0O00o = struct . unpack ( "H" , packet [ : 2 ] ) [ 0 ]
   self . rloc . afi = socket . ntohs ( o0O0O0O00o )
   if ( len ( packet ) < self . rloc . addr_length ( ) ) : return ( None )
   packet = self . rloc . unpack_address ( packet [ 2 : : ] )
   if ( packet == None ) : return ( None )
   self . rloc . mask_len = self . rloc . host_mask_len ( )
   if 45 - 45: i11iIiiIii * iII111i - I1ii11iIi11i + ooOoO0o % iII111i
   if 11 - 11: iIii1I11I1II1
   if 48 - 48: iIii1I11I1II1 - Oo0Ooo
   if 80 - 80: i1IIi
   if 56 - 56: II111iiii - o0oOOo0O0Ooo
   if 48 - 48: Oo0Ooo - I1ii11iIi11i - II111iiii . Ii1I . oO0o / iIii1I11I1II1
   if ( self . rloc . is_null ( ) ) : return ( packet )
   if 38 - 38: I1Ii111 % i11iIiiIii + Ii1I * ooOoO0o / I1Ii111
   oO0o0oO0O = self . rloc_name
   if ( oO0o0oO0O ) : oO0o0oO0O = blue ( self . rloc_name , False )
   if 49 - 49: OoOoOO00 - iIii1I11I1II1 / IiII - I1IiiI . I1Ii111 - I11i
   if 33 - 33: IiII - iIii1I11I1II1
   if 77 - 77: OOooOOo . I1ii11iIi11i / II111iiii % iIii1I11I1II1 * i11iIiiIii
   if 9 - 9: oO0o - i1IIi . ooOoO0o + I1ii11iIi11i
   if 72 - 72: ooOoO0o
   if 47 - 47: iIii1I11I1II1 . OOooOOo / I11i % II111iiii
   oOoOoO0OoOO0 = self . keys [ 1 ] if self . keys else None
   if ( oOoOoO0OoOO0 == None ) :
    if ( iIIIi . remote_public_key == None ) :
     i11ii111i1ii = bold ( "No remote encap-public-key supplied" , False )
     lprint ( "    {} for {}" . format ( i11ii111i1ii , oO0o0oO0O ) )
     iIIIi = None
    else :
     i11ii111i1ii = bold ( "New encap-keying with new state" , False )
     lprint ( "    {} for {}" . format ( i11ii111i1ii , oO0o0oO0O ) )
     iIIIi . compute_shared_key ( "encap" )
     if 92 - 92: I1ii11iIi11i % i11iIiiIii
     if 82 - 82: I1Ii111 * I1ii11iIi11i % Ii1I / o0oOOo0O0Ooo
     if 28 - 28: iII111i % OoO0O00 - OOooOOo - Oo0Ooo
     if 16 - 16: i11iIiiIii - i11iIiiIii . OoOoOO00 / i1IIi
     if 76 - 76: O0 * OoO0O00 / O0
     if 23 - 23: I1ii11iIi11i . iIii1I11I1II1 - i11iIiiIii / II111iiii
     if 48 - 48: oO0o - II111iiii * I1IiiI
     if 78 - 78: I1IiiI * i11iIiiIii * II111iiii
     if 19 - 19: OoooooooOO * i11iIiiIii / O0 . I1IiiI % I11i
     if 35 - 35: iIii1I11I1II1 + I1IiiI - ooOoO0o / Oo0Ooo * I1ii11iIi11i * Oo0Ooo
   if ( oOoOoO0OoOO0 ) :
    if ( iIIIi . remote_public_key == None ) :
     iIIIi = None
     Iiooo0o0oOoOO0 = bold ( "Remote encap-unkeying occurred" , False )
     lprint ( "    {} for {}" . format ( Iiooo0o0oOoOO0 , oO0o0oO0O ) )
    elif ( oOoOoO0OoOO0 . compare_keys ( iIIIi ) ) :
     iIIIi = oOoOoO0OoOO0
     lprint ( "    Maintain stored encap-keys for {}" . format ( oO0o0oO0O ) )
     if 17 - 17: OoOoOO00
    else :
     if ( oOoOoO0OoOO0 . remote_public_key == None ) :
      i11ii111i1ii = "New encap-keying for existing state"
     else :
      i11ii111i1ii = "Remote encap-rekeying"
      if 24 - 24: iIii1I11I1II1 / OOooOOo % OoooooooOO / O0 / oO0o
     lprint ( "    {} for {}" . format ( bold ( i11ii111i1ii , False ) ,
 oO0o0oO0O ) )
     oOoOoO0OoOO0 . remote_public_key = iIIIi . remote_public_key
     oOoOoO0OoOO0 . compute_shared_key ( "encap" )
     iIIIi = oOoOoO0OoOO0
     if 93 - 93: Oo0Ooo
     if 5 - 5: iII111i
   self . keys = [ None , iIIIi , None , None ]
   if 61 - 61: OOooOOo * OoO0O00 - O0
  else :
   if 30 - 30: iIii1I11I1II1
   if 14 - 14: o0oOOo0O0Ooo + Ii1I
   if 91 - 91: OoooooooOO / oO0o + OoOoOO00
   if 100 - 100: i1IIi
   packet = packet [ IiiiI1I1i : : ]
   if 13 - 13: i1IIi . I1ii11iIi11i * o0oOOo0O0Ooo
  return ( packet )
  if 31 - 31: i11iIiiIii % OoO0O00 . i11iIiiIii % oO0o - i1IIi
  if 62 - 62: oO0o + oO0o . OoooooooOO
 def decode ( self , packet , nonce ) :
  O0000 = "BBBBHH"
  I1 = struct . calcsize ( O0000 )
  if ( len ( packet ) < I1 ) : return ( None )
  if 59 - 59: iIii1I11I1II1 . Oo0Ooo * I11i
  self . priority , self . weight , self . mpriority , self . mweight , O0O0oooo , o0O0O0O00o = struct . unpack ( O0000 , packet [ : I1 ] )
  if 29 - 29: Oo0Ooo - I1IiiI * I11i
  if 58 - 58: i1IIi * Ii1I / ooOoO0o % iIii1I11I1II1
  O0O0oooo = socket . ntohs ( O0O0oooo )
  o0O0O0O00o = socket . ntohs ( o0O0O0O00o )
  self . local_bit = True if ( O0O0oooo & 0x0004 ) else False
  self . probe_bit = True if ( O0O0oooo & 0x0002 ) else False
  self . reach_bit = True if ( O0O0oooo & 0x0001 ) else False
  if 24 - 24: OoOoOO00 - o0oOOo0O0Ooo * I1IiiI . I11i / OoO0O00 * Ii1I
  if ( o0O0O0O00o == LISP_AFI_LCAF ) :
   packet = packet [ I1 - 2 : : ]
   packet = self . decode_lcaf ( packet , nonce )
  else :
   self . rloc . afi = o0O0O0O00o
   packet = packet [ I1 : : ]
   packet = self . rloc . unpack_address ( packet )
   if 12 - 12: OoooooooOO % oO0o
  self . rloc . mask_len = self . rloc . host_mask_len ( )
  return ( packet )
  if 92 - 92: ooOoO0o % OoO0O00 + O0 + OoOoOO00 / OoO0O00 * iIii1I11I1II1
  if 79 - 79: O0
 def end_of_rlocs ( self , packet , rloc_count ) :
  for oO in range ( rloc_count ) :
   packet = self . decode ( packet , None )
   if ( packet == None ) : return ( None )
   if 71 - 71: OoO0O00 - O0
  return ( packet )
  if 73 - 73: iIii1I11I1II1
  if 7 - 7: OoOoOO00
  if 55 - 55: oO0o . OoO0O00 + iIii1I11I1II1 + OoOoOO00 / I1ii11iIi11i - O0
  if 14 - 14: II111iiii - OoO0O00 - O0 * OoooooooOO / I1IiiI
  if 3 - 3: I11i
  if 46 - 46: I1ii11iIi11i * I1Ii111 - iIii1I11I1II1
  if 25 - 25: II111iiii / OOooOOo + Oo0Ooo - iIii1I11I1II1 - OoOoOO00
  if 97 - 97: OOooOOo . OOooOOo / I1ii11iIi11i + I1IiiI * i1IIi
  if 53 - 53: O0
  if 28 - 28: iII111i % OoO0O00 . OoO0O00 / IiII * Oo0Ooo * iII111i
  if 49 - 49: I1IiiI / I1Ii111 * iII111i + I1IiiI % oO0o % ooOoO0o
  if 27 - 27: OoO0O00 / iII111i . I1ii11iIi11i
  if 71 - 71: OoO0O00 . i11iIiiIii . iIii1I11I1II1 + I1IiiI - o0oOOo0O0Ooo
  if 34 - 34: iII111i
  if 6 - 6: OoO0O00 . OoOoOO00 + I1ii11iIi11i
  if 24 - 24: OoO0O00 . Ii1I
  if 26 - 26: O0 * I1IiiI - OOooOOo * OoooooooOO * II111iiii % OoOoOO00
  if 56 - 56: OOooOOo * i11iIiiIii % ooOoO0o * OoOoOO00 % Oo0Ooo * IiII
  if 30 - 30: i1IIi + o0oOOo0O0Ooo - OoOoOO00 . OOooOOo
  if 95 - 95: i1IIi . I11i + O0 . I11i - I11i / Oo0Ooo
  if 41 - 41: OoooooooOO . OOooOOo - Ii1I * OoO0O00 % i11iIiiIii
  if 7 - 7: Ii1I
  if 16 - 16: IiII * o0oOOo0O0Ooo % II111iiii - II111iiii + ooOoO0o
  if 55 - 55: OoO0O00 % OoOoOO00
  if 58 - 58: Ii1I
  if 17 - 17: OoO0O00 - oO0o % Oo0Ooo % oO0o * I1Ii111 / IiII
  if 88 - 88: ooOoO0o . II111iiii * O0 % IiII
  if 15 - 15: O0 % i1IIi - OOooOOo . IiII
  if 1 - 1: I1IiiI
  if 40 - 40: o0oOOo0O0Ooo % I11i % O0
class lisp_map_referral ( ) :
 def __init__ ( self ) :
  self . record_count = 0
  self . nonce = 0
  if 88 - 88: o0oOOo0O0Ooo - oO0o
  if 73 - 73: II111iiii
 def print_map_referral ( self ) :
  lprint ( "{} -> record-count: {}, nonce: 0x{}" . format ( bold ( "Map-Referral" , False ) , self . record_count ,
  # II111iiii
 lisp_hex_string ( self . nonce ) ) )
  if 28 - 28: OoO0O00
  if 90 - 90: iII111i % oO0o / iIii1I11I1II1
 def encode ( self ) :
  ooOOOo0 = ( LISP_MAP_REFERRAL << 28 ) | self . record_count
  I1IiO00Ooo0ooo0 = struct . pack ( "I" , socket . htonl ( ooOOOo0 ) )
  I1IiO00Ooo0ooo0 += struct . pack ( "Q" , self . nonce )
  return ( I1IiO00Ooo0ooo0 )
  if 52 - 52: I1IiiI / o0oOOo0O0Ooo
  if 20 - 20: I1Ii111 . I1IiiI - iIii1I11I1II1 / iII111i
 def decode ( self , packet ) :
  O0000 = "I"
  I1 = struct . calcsize ( O0000 )
  if ( len ( packet ) < I1 ) : return ( None )
  if 46 - 46: I1Ii111 . i11iIiiIii
  ooOOOo0 = struct . unpack ( O0000 , packet [ : I1 ] )
  ooOOOo0 = socket . ntohl ( ooOOOo0 [ 0 ] )
  self . record_count = ooOOOo0 & 0xff
  packet = packet [ I1 : : ]
  if 89 - 89: OoO0O00 - OOooOOo - i1IIi - OoO0O00 % iIii1I11I1II1
  O0000 = "Q"
  I1 = struct . calcsize ( O0000 )
  if ( len ( packet ) < I1 ) : return ( None )
  if 52 - 52: o0oOOo0O0Ooo * O0 + I1ii11iIi11i
  self . nonce = struct . unpack ( O0000 , packet [ : I1 ] ) [ 0 ]
  packet = packet [ I1 : : ]
  return ( packet )
  if 83 - 83: I11i + OOooOOo - OoooooooOO
  if 7 - 7: IiII % ooOoO0o / OoooooooOO / o0oOOo0O0Ooo + OoO0O00 - OoO0O00
  if 15 - 15: i1IIi + OOooOOo / Ii1I
  if 51 - 51: OOooOOo + O0
  if 91 - 91: i11iIiiIii + o0oOOo0O0Ooo % OoO0O00 / oO0o - i1IIi
  if 82 - 82: Ii1I . OoooooooOO + OoooooooOO % OoO0O00 % I1ii11iIi11i
  if 65 - 65: Oo0Ooo . I11i
  if 7 - 7: Oo0Ooo * II111iiii
class lisp_ddt_entry ( ) :
 def __init__ ( self ) :
  self . eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . group = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . uptime = lisp_get_timestamp ( )
  self . delegation_set = [ ]
  self . source_cache = None
  self . map_referrals_sent = 0
  if 11 - 11: OoOoOO00 % OoooooooOO
  if 92 - 92: OoOoOO00 - iII111i * Ii1I - i1IIi
 def is_auth_prefix ( self ) :
  if ( len ( self . delegation_set ) != 0 ) : return ( False )
  if ( self . is_star_g ( ) ) : return ( False )
  return ( True )
  if 87 - 87: Ii1I * I1Ii111 + iIii1I11I1II1 * o0oOOo0O0Ooo * iIii1I11I1II1 . I11i
  if 66 - 66: Ii1I / OoO0O00 . O0 . I11i % OoooooooOO / OOooOOo
 def is_ms_peer_entry ( self ) :
  if ( len ( self . delegation_set ) == 0 ) : return ( False )
  return ( self . delegation_set [ 0 ] . is_ms_peer ( ) )
  if 49 - 49: I1IiiI * iII111i - OoO0O00 % Ii1I + Ii1I * I1Ii111
  if 94 - 94: OoOoOO00 - I11i + Ii1I + OoOoOO00 + II111iiii
 def print_referral_type ( self ) :
  if ( len ( self . delegation_set ) == 0 ) : return ( "unknown" )
  O0o0oO = self . delegation_set [ 0 ]
  return ( O0o0oO . print_node_type ( ) )
  if 37 - 37: iII111i
  if 29 - 29: OOooOOo
 def print_eid_tuple ( self ) :
  return ( lisp_print_eid_tuple ( self . eid , self . group ) )
  if 69 - 69: oO0o % OoooooooOO * iII111i
  if 58 - 58: oO0o / i11iIiiIii . OoOoOO00 % O0 / iIii1I11I1II1
 def add_cache ( self ) :
  if ( self . group . is_null ( ) ) :
   lisp_ddt_cache . add_cache ( self . eid , self )
  else :
   I1io0 = lisp_ddt_cache . lookup_cache ( self . group , True )
   if ( I1io0 == None ) :
    I1io0 = lisp_ddt_entry ( )
    I1io0 . eid . copy_address ( self . group )
    I1io0 . group . copy_address ( self . group )
    lisp_ddt_cache . add_cache ( self . group , I1io0 )
    if 91 - 91: i11iIiiIii . I1ii11iIi11i + I11i
   if ( self . eid . is_null ( ) ) : self . eid . make_default_route ( I1io0 . group )
   I1io0 . add_source_entry ( self )
   if 67 - 67: I1ii11iIi11i * I1Ii111 * I1IiiI / I11i - IiII + oO0o
   if 11 - 11: O0 + i1IIi / o0oOOo0O0Ooo * OoO0O00
   if 64 - 64: i1IIi % IiII . ooOoO0o . iIii1I11I1II1 + OoO0O00 - iIii1I11I1II1
 def add_source_entry ( self , source_ddt ) :
  if ( self . source_cache == None ) : self . source_cache = lisp_cache ( )
  self . source_cache . add_cache ( source_ddt . eid , source_ddt )
  if 52 - 52: II111iiii - IiII
  if 91 - 91: iIii1I11I1II1 + iII111i . I11i % i11iIiiIii - i11iIiiIii + I1IiiI
 def lookup_source_cache ( self , source , exact ) :
  if ( self . source_cache == None ) : return ( None )
  return ( self . source_cache . lookup_cache ( source , exact ) )
  if 75 - 75: I1ii11iIi11i / I1IiiI - iIii1I11I1II1 / OoO0O00 * OOooOOo
  if 73 - 73: OoooooooOO % IiII / I1Ii111 * I11i + i1IIi % i11iIiiIii
 def is_star_g ( self ) :
  if ( self . group . is_null ( ) ) : return ( False )
  return ( self . eid . is_exact_match ( self . group ) )
  if 91 - 91: i11iIiiIii
  if 6 - 6: O0 - iIii1I11I1II1 + I1Ii111 . o0oOOo0O0Ooo * i11iIiiIii
  if 53 - 53: OOooOOo / I1IiiI / oO0o * OOooOOo / i1IIi - I1Ii111
class lisp_ddt_node ( ) :
 def __init__ ( self ) :
  self . delegate_address = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . public_key = ""
  self . map_server_peer = False
  self . map_server_child = False
  self . priority = 0
  self . weight = 0
  if 71 - 71: O0 + Oo0Ooo % oO0o - o0oOOo0O0Ooo
  if 82 - 82: iIii1I11I1II1
 def print_node_type ( self ) :
  if ( self . is_ddt_child ( ) ) : return ( "ddt-child" )
  if ( self . is_ms_child ( ) ) : return ( "map-server-child" )
  if ( self . is_ms_peer ( ) ) : return ( "map-server-peer" )
  if 64 - 64: ooOoO0o + I1IiiI % OOooOOo + II111iiii
  if 46 - 46: I1IiiI
 def is_ddt_child ( self ) :
  if ( self . map_server_child ) : return ( False )
  if ( self . map_server_peer ) : return ( False )
  return ( True )
  if 72 - 72: iII111i
  if 100 - 100: I1IiiI
 def is_ms_child ( self ) :
  return ( self . map_server_child )
  if 55 - 55: i1IIi % IiII
  if 44 - 44: oO0o - iIii1I11I1II1 / ooOoO0o - iIii1I11I1II1 % i1IIi + ooOoO0o
 def is_ms_peer ( self ) :
  return ( self . map_server_peer )
  if 74 - 74: I11i . OoOoOO00 + OoOoOO00
  if 87 - 87: IiII + o0oOOo0O0Ooo . i1IIi % I1Ii111
  if 44 - 44: Oo0Ooo - OOooOOo . Ii1I * OoooooooOO
  if 93 - 93: OoO0O00 . OoO0O00
  if 52 - 52: OOooOOo . oO0o / Oo0Ooo . OoooooooOO % I1ii11iIi11i
  if 65 - 65: ooOoO0o % II111iiii . iII111i - iIii1I11I1II1 - I1IiiI
  if 63 - 63: I1IiiI . OoOoOO00 - II111iiii
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
  if 55 - 55: ooOoO0o - o0oOOo0O0Ooo
  if 32 - 32: I1Ii111 * Ii1I / I1Ii111 . OoOoOO00 + I1ii11iIi11i - ooOoO0o
 def print_ddt_map_request ( self ) :
  lprint ( "Queued Map-Request from {}ITR {}->{}, nonce 0x{}" . format ( "P" if self . from_pitr else "" ,
  # ooOoO0o
 red ( self . itr . print_address ( ) , False ) ,
 green ( self . eid . print_address ( ) , False ) , self . nonce ) )
  if 87 - 87: O0 + O0 - ooOoO0o . i11iIiiIii - Oo0Ooo * i11iIiiIii
  if 72 - 72: I11i / OoooooooOO
 def queue_map_request ( self ) :
  self . retransmit_timer = threading . Timer ( LISP_DDT_MAP_REQUEST_INTERVAL ,
 lisp_retransmit_ddt_map_request , [ self ] )
  self . retransmit_timer . start ( )
  lisp_ddt_map_requestQ [ str ( self . nonce ) ] = self
  if 95 - 95: I1IiiI * i11iIiiIii + i11iIiiIii / iIii1I11I1II1
  if 20 - 20: I11i
 def dequeue_map_request ( self ) :
  self . retransmit_timer . cancel ( )
  if ( lisp_ddt_map_requestQ . has_key ( str ( self . nonce ) ) ) :
   lisp_ddt_map_requestQ . pop ( str ( self . nonce ) )
   if 15 - 15: o0oOOo0O0Ooo . i11iIiiIii * I1ii11iIi11i / ooOoO0o
   if 41 - 41: ooOoO0o + IiII . i1IIi + iIii1I11I1II1
   if 57 - 57: i11iIiiIii * oO0o * i11iIiiIii
 def print_eid_tuple ( self ) :
  return ( lisp_print_eid_tuple ( self . eid , self . group ) )
  if 14 - 14: Oo0Ooo / I11i
  if 14 - 14: Oo0Ooo - Ii1I + ooOoO0o - I1IiiI % IiII
  if 70 - 70: I1IiiI % ooOoO0o * OoO0O00 + OoOoOO00 % i11iIiiIii
  if 39 - 39: Oo0Ooo % I1Ii111 / I1IiiI / Oo0Ooo . o0oOOo0O0Ooo + o0oOOo0O0Ooo
  if 83 - 83: OoooooooOO * II111iiii % OoooooooOO
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
LISP_DDT_ACTION_SITE_NOT_FOUND = - 2
LISP_DDT_ACTION_NULL = - 1
LISP_DDT_ACTION_NODE_REFERRAL = 0
LISP_DDT_ACTION_MS_REFERRAL = 1
LISP_DDT_ACTION_MS_ACK = 2
LISP_DDT_ACTION_MS_NOT_REG = 3
LISP_DDT_ACTION_DELEGATION_HOLE = 4
LISP_DDT_ACTION_NOT_AUTH = 5
LISP_DDT_ACTION_MAX = LISP_DDT_ACTION_NOT_AUTH
if 19 - 19: O0 . i1IIi + I11i / II111iiii + ooOoO0o
lisp_map_referral_action_string = [
 "node-referral" , "ms-referral" , "ms-ack" , "ms-not-registered" ,
 "delegation-hole" , "not-authoritative" ]
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
  if 48 - 48: oO0o - O0
  if 17 - 17: iIii1I11I1II1 . IiII / ooOoO0o % I11i + o0oOOo0O0Ooo - iIii1I11I1II1
 def print_info ( self ) :
  if ( self . info_reply ) :
   OOO000O = "Info-Reply"
   oOoOoo0O = ( ", ms-port: {}, etr-port: {}, global-rloc: {}, " + "ms-rloc: {}, private-rloc: {}, RTR-list: " ) . format ( self . ms_port , self . etr_port ,
   # i1IIi * O0
   # Oo0Ooo * iII111i + Ii1I % iIii1I11I1II1
 red ( self . global_etr_rloc . print_address_no_iid ( ) , False ) ,
 red ( self . global_ms_rloc . print_address_no_iid ( ) , False ) ,
 red ( self . private_etr_rloc . print_address_no_iid ( ) , False ) )
   if ( len ( self . rtr_list ) == 0 ) : oOoOoo0O += "empty, "
   for O0Oo in self . rtr_list :
    oOoOoo0O += red ( O0Oo . print_address_no_iid ( ) , False ) + ", "
    if 84 - 84: I11i * oO0o
   oOoOoo0O = oOoOoo0O [ 0 : - 2 ]
  else :
   OOO000O = "Info-Request"
   o00oo0OO = "<none>" if self . hostname == None else self . hostname
   oOoOoo0O = ", hostname: {}" . format ( blue ( o00oo0OO , False ) )
   if 50 - 50: OoooooooOO % Oo0Ooo
  lprint ( "{} -> nonce: 0x{}{}" . format ( bold ( OOO000O , False ) ,
 lisp_hex_string ( self . nonce ) , oOoOoo0O ) )
  if 81 - 81: iIii1I11I1II1 + O0 * o0oOOo0O0Ooo - i11iIiiIii / iII111i
  if 32 - 32: OoOoOO00 . Oo0Ooo . o0oOOo0O0Ooo / I1IiiI
 def encode ( self ) :
  ooOOOo0 = ( LISP_NAT_INFO << 28 )
  if ( self . info_reply ) : ooOOOo0 |= ( 1 << 27 )
  if 23 - 23: iII111i * I1ii11iIi11i / Ii1I - OoOoOO00 . II111iiii
  if 74 - 74: I1Ii111 . IiII % iII111i . O0
  if 61 - 61: IiII / I11i . I1Ii111 * OoOoOO00 / OoO0O00
  if 18 - 18: ooOoO0o % OoO0O00 % OOooOOo . I1ii11iIi11i + II111iiii / iII111i
  if 73 - 73: O0 / Ii1I + i11iIiiIii - Ii1I
  I1IiO00Ooo0ooo0 = struct . pack ( "I" , socket . htonl ( ooOOOo0 ) )
  I1IiO00Ooo0ooo0 += struct . pack ( "Q" , self . nonce )
  I1IiO00Ooo0ooo0 += struct . pack ( "III" , 0 , 0 , 0 )
  if 48 - 48: I1IiiI - i11iIiiIii * I1ii11iIi11i
  if 70 - 70: I1ii11iIi11i * OoOoOO00
  if 63 - 63: ooOoO0o . IiII - OoOoOO00 % IiII - I1Ii111 / I1Ii111
  if 42 - 42: i1IIi . OoOoOO00 * OoOoOO00 * OoOoOO00
  if ( self . info_reply == False ) :
   if ( self . hostname == None ) :
    I1IiO00Ooo0ooo0 += struct . pack ( "H" , 0 )
   else :
    I1IiO00Ooo0ooo0 += struct . pack ( "H" , socket . htons ( LISP_AFI_NAME ) )
    I1IiO00Ooo0ooo0 += self . hostname + "\0"
    if 14 - 14: II111iiii / I1Ii111 . I1IiiI
   return ( I1IiO00Ooo0ooo0 )
   if 66 - 66: I1Ii111 % oO0o . iII111i * i1IIi
   if 81 - 81: OoooooooOO * I1IiiI / I1Ii111
   if 10 - 10: I1IiiI - II111iiii / IiII * II111iiii
   if 67 - 67: II111iiii . Ii1I % oO0o . Oo0Ooo + IiII
   if 10 - 10: OOooOOo - OoO0O00 * oO0o / iIii1I11I1II1 - OoOoOO00
  o0O0O0O00o = socket . htons ( LISP_AFI_LCAF )
  OO = LISP_LCAF_NAT_TYPE
  IiiiI1I1i = socket . htons ( 16 )
  I1Ii1i111I = socket . htons ( self . ms_port )
  Oo00oo = socket . htons ( self . etr_port )
  I1IiO00Ooo0ooo0 += struct . pack ( "HHBBHHHH" , o0O0O0O00o , 0 , OO , 0 , IiiiI1I1i ,
 I1Ii1i111I , Oo00oo , socket . htons ( self . global_etr_rloc . afi ) )
  I1IiO00Ooo0ooo0 += self . global_etr_rloc . pack_address ( )
  I1IiO00Ooo0ooo0 += struct . pack ( "HH" , 0 , socket . htons ( self . private_etr_rloc . afi ) )
  I1IiO00Ooo0ooo0 += self . private_etr_rloc . pack_address ( )
  if ( len ( self . rtr_list ) == 0 ) : I1IiO00Ooo0ooo0 += struct . pack ( "H" , 0 )
  if 39 - 39: I1ii11iIi11i / i11iIiiIii * i1IIi * Oo0Ooo
  if 39 - 39: OoO0O00 * OoooooooOO / i1IIi + Oo0Ooo
  if 57 - 57: O0
  if 83 - 83: OOooOOo / Ii1I * I1IiiI % oO0o / iIii1I11I1II1
  for O0Oo in self . rtr_list :
   I1IiO00Ooo0ooo0 += struct . pack ( "H" , socket . htons ( O0Oo . afi ) )
   I1IiO00Ooo0ooo0 += O0Oo . pack_address ( )
   if 1 - 1: I11i / OoooooooOO / iII111i
  return ( I1IiO00Ooo0ooo0 )
  if 68 - 68: i1IIi / Oo0Ooo / I11i * Oo0Ooo
  if 91 - 91: OoO0O00 . iII111i
 def decode ( self , packet ) :
  O00Ooo00 = packet
  O0000 = "I"
  I1 = struct . calcsize ( O0000 )
  if ( len ( packet ) < I1 ) : return ( None )
  if 82 - 82: I1ii11iIi11i / Oo0Ooo
  ooOOOo0 = struct . unpack ( O0000 , packet [ : I1 ] )
  ooOOOo0 = ooOOOo0 [ 0 ]
  packet = packet [ I1 : : ]
  if 63 - 63: I1IiiI
  O0000 = "Q"
  I1 = struct . calcsize ( O0000 )
  if ( len ( packet ) < I1 ) : return ( None )
  if 3 - 3: iII111i + I1ii11iIi11i
  o0oo000 = struct . unpack ( O0000 , packet [ : I1 ] )
  if 35 - 35: oO0o * iII111i * oO0o * I1Ii111 * IiII * i1IIi
  ooOOOo0 = socket . ntohl ( ooOOOo0 )
  self . nonce = o0oo000 [ 0 ]
  self . info_reply = ooOOOo0 & 0x08000000
  self . hostname = None
  packet = packet [ I1 : : ]
  if 43 - 43: OoO0O00 * I1IiiI / IiII . i11iIiiIii + iII111i + o0oOOo0O0Ooo
  if 1 - 1: I1IiiI % o0oOOo0O0Ooo . I1Ii111 + I11i * oO0o
  if 41 - 41: OoO0O00 * oO0o - II111iiii
  if 2 - 2: IiII + IiII - OoO0O00 * iII111i . oO0o
  if 91 - 91: ooOoO0o
  O0000 = "HH"
  I1 = struct . calcsize ( O0000 )
  if ( len ( packet ) < I1 ) : return ( None )
  if 22 - 22: ooOoO0o % OoO0O00 * OoOoOO00 + Oo0Ooo
  if 44 - 44: O0 - I11i
  if 43 - 43: O0
  if 50 - 50: I11i - OoooooooOO
  if 29 - 29: oO0o * oO0o
  oO0O0oo , II1iiiiI1Ii11 = struct . unpack ( O0000 , packet [ : I1 ] )
  if ( II1iiiiI1Ii11 != 0 ) : return ( None )
  if 44 - 44: ooOoO0o . I1IiiI * oO0o * Ii1I
  packet = packet [ I1 : : ]
  O0000 = "IBBH"
  I1 = struct . calcsize ( O0000 )
  if ( len ( packet ) < I1 ) : return ( None )
  if 41 - 41: i1IIi % i11iIiiIii + I11i % OoooooooOO / I1ii11iIi11i
  ooOOooooo0Oo , Iii1IiIiIii , IiiIiiii , O00OoO0O = struct . unpack ( O0000 ,
 packet [ : I1 ] )
  if 79 - 79: i1IIi % I1ii11iIi11i - OoO0O00 % I1ii11iIi11i
  if ( O00OoO0O != 0 ) : return ( None )
  packet = packet [ I1 : : ]
  if 6 - 6: Oo0Ooo / iII111i . i11iIiiIii
  if 8 - 8: I1ii11iIi11i + O0 - oO0o % II111iiii . I1Ii111
  if 86 - 86: IiII
  if 71 - 71: Ii1I - i1IIi . I1IiiI
  if ( self . info_reply == False ) :
   O0000 = "H"
   I1 = struct . calcsize ( O0000 )
   if ( len ( packet ) >= I1 ) :
    o0O0O0O00o = struct . unpack ( O0000 , packet [ : I1 ] ) [ 0 ]
    if ( socket . ntohs ( o0O0O0O00o ) == LISP_AFI_NAME ) :
     packet = packet [ I1 : : ]
     packet , self . hostname = lisp_decode_dist_name ( packet )
     if 15 - 15: i1IIi % II111iiii / II111iiii - I1ii11iIi11i - I11i % i1IIi
     if 54 - 54: i1IIi . OoO0O00 + iII111i + OoO0O00 * i1IIi
   return ( O00Ooo00 )
   if 13 - 13: Oo0Ooo / OoO0O00 + OOooOOo
   if 90 - 90: OoO0O00 * i11iIiiIii / oO0o
   if 91 - 91: iII111i - OoOoOO00 / Oo0Ooo % II111iiii / II111iiii / o0oOOo0O0Ooo
   if 34 - 34: OoO0O00 * II111iiii + i11iIiiIii % Ii1I
   if 25 - 25: OoOoOO00 + IiII . i11iIiiIii
  O0000 = "HHBBHHH"
  I1 = struct . calcsize ( O0000 )
  if ( len ( packet ) < I1 ) : return ( None )
  if 87 - 87: I1IiiI + OoooooooOO + O0
  o0O0O0O00o , i1i11Ii1 , OO , Iii1IiIiIii , IiiiI1I1i , I1Ii1i111I , Oo00oo = struct . unpack ( O0000 , packet [ : I1 ] )
  if 32 - 32: Ii1I / I1ii11iIi11i . Ii1I
  if 65 - 65: IiII
  if ( socket . ntohs ( o0O0O0O00o ) != LISP_AFI_LCAF ) : return ( None )
  if 74 - 74: Oo0Ooo + i1IIi - II111iiii / ooOoO0o / iII111i
  self . ms_port = socket . ntohs ( I1Ii1i111I )
  self . etr_port = socket . ntohs ( Oo00oo )
  packet = packet [ I1 : : ]
  if 66 - 66: ooOoO0o / IiII * iIii1I11I1II1
  if 42 - 42: I1Ii111 - i11iIiiIii % II111iiii * ooOoO0o . O0 % I11i
  if 82 - 82: Oo0Ooo % O0 + I1ii11iIi11i % I1ii11iIi11i
  if 74 - 74: O0 * IiII . I11i - I1Ii111 + O0 + I11i
  O0000 = "H"
  I1 = struct . calcsize ( O0000 )
  if ( len ( packet ) < I1 ) : return ( None )
  if 48 - 48: oO0o . o0oOOo0O0Ooo - OOooOOo
  if 29 - 29: Oo0Ooo - Ii1I - Oo0Ooo
  if 89 - 89: Oo0Ooo . OoO0O00 . I1ii11iIi11i * oO0o . O0
  if 72 - 72: i11iIiiIii % I11i / I1Ii111 + I1IiiI * iII111i
  o0O0O0O00o = struct . unpack ( O0000 , packet [ : I1 ] ) [ 0 ]
  packet = packet [ I1 : : ]
  if ( o0O0O0O00o != 0 ) :
   self . global_etr_rloc . afi = socket . ntohs ( o0O0O0O00o )
   packet = self . global_etr_rloc . unpack_address ( packet )
   if ( packet == None ) : return ( None )
   self . global_etr_rloc . mask_len = self . global_etr_rloc . host_mask_len ( )
   if 69 - 69: I1Ii111 + O0 . IiII . o0oOOo0O0Ooo
   if 38 - 38: IiII / i1IIi
   if 60 - 60: OoOoOO00
   if 75 - 75: II111iiii / iIii1I11I1II1 / OoooooooOO
   if 61 - 61: IiII . IiII
   if 17 - 17: OoOoOO00 % Oo0Ooo / I1Ii111 . Ii1I % OoO0O00
  if ( len ( packet ) < I1 ) : return ( O00Ooo00 )
  if 32 - 32: I1IiiI + ooOoO0o / O0 * i11iIiiIii % Oo0Ooo + II111iiii
  o0O0O0O00o = struct . unpack ( O0000 , packet [ : I1 ] ) [ 0 ]
  packet = packet [ I1 : : ]
  if ( o0O0O0O00o != 0 ) :
   self . global_ms_rloc . afi = socket . ntohs ( o0O0O0O00o )
   packet = self . global_ms_rloc . unpack_address ( packet )
   if ( packet == None ) : return ( O00Ooo00 )
   self . global_ms_rloc . mask_len = self . global_ms_rloc . host_mask_len ( )
   if 95 - 95: iII111i / ooOoO0o + I1Ii111
   if 78 - 78: iIii1I11I1II1 / I1IiiI - IiII
   if 81 - 81: I1ii11iIi11i
   if 31 - 31: O0 % ooOoO0o / I1IiiI * iII111i % iIii1I11I1II1 * OoOoOO00
   if 76 - 76: I1Ii111 - O0
  if ( len ( packet ) < I1 ) : return ( O00Ooo00 )
  if 23 - 23: O0 * Ii1I * ooOoO0o % ooOoO0o
  o0O0O0O00o = struct . unpack ( O0000 , packet [ : I1 ] ) [ 0 ]
  packet = packet [ I1 : : ]
  if ( o0O0O0O00o != 0 ) :
   self . private_etr_rloc . afi = socket . ntohs ( o0O0O0O00o )
   packet = self . private_etr_rloc . unpack_address ( packet )
   if ( packet == None ) : return ( O00Ooo00 )
   self . private_etr_rloc . mask_len = self . private_etr_rloc . host_mask_len ( )
   if 7 - 7: II111iiii + I11i
   if 99 - 99: iIii1I11I1II1 * oO0o
   if 37 - 37: ooOoO0o * iII111i * I11i
   if 11 - 11: I1IiiI
   if 48 - 48: O0 . I11i
   if 9 - 9: oO0o / Oo0Ooo
  while ( len ( packet ) >= I1 ) :
   o0O0O0O00o = struct . unpack ( O0000 , packet [ : I1 ] ) [ 0 ]
   packet = packet [ I1 : : ]
   if ( o0O0O0O00o == 0 ) : continue
   O0Oo = lisp_address ( socket . ntohs ( o0O0O0O00o ) , "" , 0 , 0 )
   packet = O0Oo . unpack_address ( packet )
   if ( packet == None ) : return ( O00Ooo00 )
   O0Oo . mask_len = O0Oo . host_mask_len ( )
   self . rtr_list . append ( O0Oo )
   if 85 - 85: i11iIiiIii / I1IiiI . OoO0O00 . I11i . oO0o * IiII
  return ( O00Ooo00 )
  if 41 - 41: Ii1I / OoO0O00 / OoO0O00 * I11i
  if 31 - 31: Ii1I / OoooooooOO % iIii1I11I1II1 - IiII * I1IiiI - O0
  if 31 - 31: oO0o
class lisp_nat_info ( ) :
 def __init__ ( self , addr_str , hostname , port ) :
  self . address = addr_str
  self . hostname = hostname
  self . port = port
  self . uptime = lisp_get_timestamp ( )
  if 74 - 74: OoO0O00
  if 11 - 11: oO0o + O0 % Ii1I . I11i * o0oOOo0O0Ooo
 def timed_out ( self ) :
  ooooOoO0O = time . time ( ) - self . uptime
  return ( ooooOoO0O >= ( LISP_INFO_INTERVAL * 2 ) )
  if 14 - 14: I11i . iIii1I11I1II1 + I1Ii111 % OoooooooOO
  if 9 - 9: oO0o + Ii1I / I1ii11iIi11i * iIii1I11I1II1 + o0oOOo0O0Ooo
  if 64 - 64: I11i % i11iIiiIii % I1ii11iIi11i
class lisp_info_source ( ) :
 def __init__ ( self , hostname , addr_str , port ) :
  self . address = lisp_address ( LISP_AFI_IPV4 , addr_str , 32 , 0 )
  self . port = port
  self . uptime = lisp_get_timestamp ( )
  self . nonce = None
  self . hostname = hostname
  self . no_timeout = False
  if 14 - 14: I1Ii111 - OoOoOO00 - I1ii11iIi11i % I11i + OoooooooOO
  if 4 - 4: I1Ii111 - I1IiiI / iIii1I11I1II1 + I1ii11iIi11i % iIii1I11I1II1 * I1IiiI
 def cache_address_for_info_source ( self ) :
  iIIIi = self . address . print_address_no_iid ( ) + self . hostname
  lisp_info_sources_by_address [ iIIIi ] = self
  if 30 - 30: i11iIiiIii % OOooOOo
  if 52 - 52: I11i - oO0o . i11iIiiIii - II111iiii + Ii1I . iII111i
 def cache_nonce_for_info_source ( self , nonce ) :
  self . nonce = nonce
  lisp_info_sources_by_nonce [ nonce ] = self
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
def lisp_concat_auth_data ( alg_id , auth1 , auth2 , auth3 , auth4 ) :
 if 67 - 67: OoooooooOO * I11i * Ii1I * iIii1I11I1II1
 if ( lisp_is_x86 ( ) ) :
  if ( auth1 != "" ) : auth1 = byte_swap_64 ( auth1 )
  if ( auth2 != "" ) : auth2 = byte_swap_64 ( auth2 )
  if ( auth3 != "" ) :
   if ( alg_id == LISP_SHA_1_96_ALG_ID ) : auth3 = socket . ntohl ( auth3 )
   else : auth3 = byte_swap_64 ( auth3 )
   if 22 - 22: OoO0O00 / o0oOOo0O0Ooo
  if ( auth4 != "" ) : auth4 = byte_swap_64 ( auth4 )
  if 35 - 35: I1Ii111 / I1Ii111 + o0oOOo0O0Ooo - oO0o
  if 40 - 40: OoOoOO00 - II111iiii
 if ( alg_id == LISP_SHA_1_96_ALG_ID ) :
  auth1 = lisp_hex_string ( auth1 )
  auth1 = auth1 . zfill ( 16 )
  auth2 = lisp_hex_string ( auth2 )
  auth2 = auth2 . zfill ( 16 )
  auth3 = lisp_hex_string ( auth3 )
  auth3 = auth3 . zfill ( 8 )
  O0oooOoO = auth1 + auth2 + auth3
  if 29 - 29: I1IiiI - O0
 if ( alg_id == LISP_SHA_256_128_ALG_ID ) :
  auth1 = lisp_hex_string ( auth1 )
  auth1 = auth1 . zfill ( 16 )
  auth2 = lisp_hex_string ( auth2 )
  auth2 = auth2 . zfill ( 16 )
  auth3 = lisp_hex_string ( auth3 )
  auth3 = auth3 . zfill ( 16 )
  auth4 = lisp_hex_string ( auth4 )
  auth4 = auth4 . zfill ( 16 )
  O0oooOoO = auth1 + auth2 + auth3 + auth4
  if 36 - 36: I1IiiI * I1IiiI
 return ( O0oooOoO )
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
def lisp_open_listen_socket ( local_addr , port ) :
 if ( port . isdigit ( ) ) :
  if ( local_addr . find ( "." ) != - 1 ) :
   IIiiiII = socket . socket ( socket . AF_INET , socket . SOCK_DGRAM )
   if 44 - 44: iII111i * I11i + i11iIiiIii + i1IIi / IiII * II111iiii
  if ( local_addr . find ( ":" ) != - 1 ) :
   if ( lisp_is_raspbian ( ) ) : return ( None )
   IIiiiII = socket . socket ( socket . AF_INET6 , socket . SOCK_DGRAM )
   if 58 - 58: OOooOOo
  IIiiiII . bind ( ( local_addr , int ( port ) ) )
 else :
  i1i1IIi1II = port
  if ( os . path . exists ( i1i1IIi1II ) ) :
   os . system ( "rm " + i1i1IIi1II )
   time . sleep ( 1 )
   if 72 - 72: OoO0O00 + OOooOOo - Oo0Ooo % ooOoO0o . IiII
  IIiiiII = socket . socket ( socket . AF_UNIX , socket . SOCK_DGRAM )
  IIiiiII . bind ( i1i1IIi1II )
  if 95 - 95: iII111i % OOooOOo - IiII - OoOoOO00 % o0oOOo0O0Ooo * O0
 return ( IIiiiII )
 if 16 - 16: I1Ii111 / Oo0Ooo
 if 48 - 48: Oo0Ooo / oO0o + iII111i % iII111i
 if 9 - 9: I1ii11iIi11i - o0oOOo0O0Ooo . Oo0Ooo + I1ii11iIi11i . OOooOOo
 if 30 - 30: OoooooooOO - iIii1I11I1II1 / oO0o * Ii1I / Ii1I
 if 52 - 52: OoOoOO00 - OoO0O00 + I1IiiI + IiII
 if 49 - 49: oO0o / I11i - oO0o
 if 31 - 31: OoOoOO00 + I1IiiI + I1ii11iIi11i + I11i * II111iiii % oO0o
def lisp_open_send_socket ( internal_name , afi ) :
 if ( internal_name == "" ) :
  if ( afi == LISP_AFI_IPV4 ) :
   IIiiiII = socket . socket ( socket . AF_INET , socket . SOCK_DGRAM )
   if 90 - 90: OOooOOo * iIii1I11I1II1 / i1IIi
  if ( afi == LISP_AFI_IPV6 ) :
   if ( lisp_is_raspbian ( ) ) : return ( None )
   IIiiiII = socket . socket ( socket . AF_INET6 , socket . SOCK_DGRAM )
   if 60 - 60: OOooOOo * I1Ii111 . oO0o
 else :
  if ( os . path . exists ( internal_name ) ) : os . system ( "rm " + internal_name )
  IIiiiII = socket . socket ( socket . AF_UNIX , socket . SOCK_DGRAM )
  IIiiiII . bind ( internal_name )
  if 47 - 47: oO0o % OOooOOo / OOooOOo % OoOoOO00 % I1Ii111 / OoOoOO00
 return ( IIiiiII )
 if 51 - 51: I1IiiI . I11i - OoOoOO00
 if 10 - 10: Oo0Ooo * OOooOOo / IiII . o0oOOo0O0Ooo
 if 97 - 97: Ii1I . Ii1I % iII111i
 if 49 - 49: Oo0Ooo % OOooOOo - OoooooooOO + IiII
 if 54 - 54: iIii1I11I1II1 - OoooooooOO / I11i / oO0o % I1IiiI + OoOoOO00
 if 26 - 26: OoO0O00 * II111iiii % OOooOOo * iII111i + iII111i
 if 25 - 25: I11i - I1ii11iIi11i
def lisp_close_socket ( sock , internal_name ) :
 sock . close ( )
 if ( os . path . exists ( internal_name ) ) : os . system ( "rm " + internal_name )
 return
 if 100 - 100: I1Ii111 / Ii1I + OoOoOO00 . OoooooooOO
 if 83 - 83: O0
 if 35 - 35: i11iIiiIii - I11i . OoOoOO00 * II111iiii % i11iIiiIii
 if 55 - 55: o0oOOo0O0Ooo / O0 / OoooooooOO * Oo0Ooo % iII111i
 if 24 - 24: I1ii11iIi11i % OOooOOo + OoooooooOO + OoO0O00
 if 100 - 100: Oo0Ooo % OoO0O00 - OoOoOO00
 if 46 - 46: o0oOOo0O0Ooo
 if 28 - 28: i1IIi
def lisp_is_running ( node ) :
 return ( True if ( os . path . exists ( node ) ) else False )
 if 81 - 81: oO0o % OoooooooOO . I1Ii111 - OoOoOO00 / I1IiiI
 if 62 - 62: I1Ii111 * I11i / I11i
 if 42 - 42: ooOoO0o * ooOoO0o / Ii1I / OOooOOo * OOooOOo
 if 92 - 92: Oo0Ooo / iII111i - OoooooooOO - o0oOOo0O0Ooo % ooOoO0o
 if 35 - 35: i1IIi % iII111i % I11i * iIii1I11I1II1 % Ii1I - Oo0Ooo
 if 94 - 94: iII111i
 if 68 - 68: OoooooooOO % OOooOOo / OoooooooOO / I1Ii111 + Ii1I - o0oOOo0O0Ooo
 if 81 - 81: I1IiiI
 if 62 - 62: Ii1I * OoOoOO00
def lisp_packet_ipc ( packet , source , sport ) :
 return ( ( "packet@" + str ( len ( packet ) ) + "@" + source + "@" + str ( sport ) + "@" + packet ) )
 if 27 - 27: Oo0Ooo + Oo0Ooo / II111iiii % I1Ii111
 if 11 - 11: Ii1I
 if 54 - 54: I1IiiI * I1Ii111 / ooOoO0o / iIii1I11I1II1 % iII111i / oO0o
 if 11 - 11: ooOoO0o + I1IiiI + Ii1I . II111iiii
 if 50 - 50: Oo0Ooo
 if 14 - 14: O0
 if 67 - 67: II111iiii / O0
 if 10 - 10: i1IIi / Oo0Ooo
 if 20 - 20: Oo0Ooo * I1Ii111 / I1ii11iIi11i . ooOoO0o
def lisp_control_packet_ipc ( packet , source , dest , dport ) :
 return ( "control-packet@" + dest + "@" + str ( dport ) + "@" + packet )
 if 67 - 67: o0oOOo0O0Ooo . Oo0Ooo % I11i
 if 38 - 38: OOooOOo - OoO0O00 . ooOoO0o
 if 50 - 50: o0oOOo0O0Ooo
 if 85 - 85: II111iiii . iII111i - i1IIi
 if 23 - 23: iII111i . Ii1I - OoO0O00 / I1ii11iIi11i / O0
 if 4 - 4: i1IIi % Oo0Ooo % Ii1I * ooOoO0o - I11i
 if 76 - 76: iIii1I11I1II1 / ooOoO0o % I1ii11iIi11i % OOooOOo
def lisp_data_packet_ipc ( packet , source ) :
 return ( "data-packet@" + str ( len ( packet ) ) + "@" + source + "@@" + packet )
 if 13 - 13: IiII
 if 56 - 56: Oo0Ooo
 if 55 - 55: i11iIiiIii + iIii1I11I1II1 / i1IIi / I1ii11iIi11i
 if 64 - 64: IiII . OoO0O00 * i11iIiiIii
 if 18 - 18: Ii1I % o0oOOo0O0Ooo - Oo0Ooo
 if 28 - 28: IiII
 if 93 - 93: Oo0Ooo % i1IIi
 if 51 - 51: oO0o % O0
 if 41 - 41: I1IiiI * I1IiiI . I1Ii111
def lisp_command_ipc ( packet , source ) :
 return ( "command@" + str ( len ( packet ) ) + "@" + source + "@@" + packet )
 if 38 - 38: I1IiiI % i11iIiiIii
 if 17 - 17: i11iIiiIii
 if 81 - 81: I1Ii111
 if 25 - 25: I1IiiI
 if 52 - 52: I1ii11iIi11i % i1IIi . IiII % OoOoOO00
 if 50 - 50: OOooOOo * I1IiiI / o0oOOo0O0Ooo
 if 91 - 91: iIii1I11I1II1 / OOooOOo * O0 . o0oOOo0O0Ooo + oO0o / I1ii11iIi11i
 if 33 - 33: II111iiii + Ii1I
 if 46 - 46: IiII + O0 + i1IIi + ooOoO0o / iII111i
def lisp_api_ipc ( source , data ) :
 return ( "api@" + str ( len ( data ) ) + "@" + source + "@@" + data )
 if 94 - 94: oO0o + iII111i * OoOoOO00 - i1IIi / OoooooooOO
 if 59 - 59: I11i % Ii1I / OoOoOO00
 if 99 - 99: Ii1I + II111iiii / i11iIiiIii - IiII / iII111i + iII111i
 if 55 - 55: IiII + OoooooooOO * I1ii11iIi11i . IiII * I1ii11iIi11i + IiII
 if 81 - 81: iIii1I11I1II1 . ooOoO0o + OoOoOO00
 if 31 - 31: I11i / OoOoOO00 + o0oOOo0O0Ooo
 if 80 - 80: Oo0Ooo
 if 58 - 58: I1Ii111 + OOooOOo
 if 76 - 76: II111iiii - o0oOOo0O0Ooo % OoO0O00 + iII111i
def lisp_ipc ( packet , send_socket , node ) :
 if 38 - 38: I1Ii111 - I11i * i1IIi + iIii1I11I1II1
 if 41 - 41: Ii1I . OoO0O00 + I1ii11iIi11i + OoOoOO00
 if 76 - 76: iII111i - iIii1I11I1II1
 if 23 - 23: I11i / OoO0O00 % OOooOOo
 if ( lisp_is_running ( node ) == False ) :
  lprint ( "Suppress sending IPC to {}" . format ( node ) )
  return
  if 9 - 9: ooOoO0o % I1ii11iIi11i . OoooooooOO + OoO0O00 % OOooOOo * OoooooooOO
  if 21 - 21: Ii1I % O0
 IiI11111I1ii1 = 1500 if ( packet . find ( "control-packet" ) == - 1 ) else 9000
 if 40 - 40: I1IiiI . Oo0Ooo - Ii1I
 oOO0OO0O = 0
 I111 = len ( packet )
 oo0o00oO = 0
 o0Oo0O0O = .001
 while ( I111 > 0 ) :
  iii1i1 = min ( I111 , IiI11111I1ii1 )
  II1I11IIII1i1 = packet [ oOO0OO0O : iii1i1 + oOO0OO0O ]
  if 96 - 96: O0 / OoOoOO00
  try :
   send_socket . sendto ( II1I11IIII1i1 , node )
   lprint ( "Send IPC {}-out-of-{} byte to {} succeeded" . format ( len ( II1I11IIII1i1 ) , len ( packet ) , node ) )
   if 91 - 91: ooOoO0o
   oo0o00oO = 0
   o0Oo0O0O = .001
   if 91 - 91: I1Ii111 * Ii1I * o0oOOo0O0Ooo - OoOoOO00
  except socket . error , I1i11II :
   if ( oo0o00oO == 12 ) :
    lprint ( "Giving up on {}, consider it down" . format ( node ) )
    break
    if 53 - 53: o0oOOo0O0Ooo * Ii1I / O0
    if 81 - 81: Ii1I - iII111i / OOooOOo + I1IiiI + OoO0O00
   lprint ( "Send IPC {}-out-of-{} byte to {} failed: {}" . format ( len ( II1I11IIII1i1 ) , len ( packet ) , node , I1i11II ) )
   if 24 - 24: o0oOOo0O0Ooo - i11iIiiIii + i11iIiiIii . I1IiiI - OOooOOo
   if 16 - 16: OOooOOo
   oo0o00oO += 1
   time . sleep ( o0Oo0O0O )
   if 74 - 74: I11i . II111iiii + O0 * II111iiii
   lprint ( "Retrying after {} ms ..." . format ( o0Oo0O0O * 1000 ) )
   o0Oo0O0O *= 2
   continue
   if 50 - 50: IiII
   if 7 - 7: OoO0O00 / I1IiiI * Ii1I % OoO0O00 + OoO0O00 % II111iiii
  oOO0OO0O += iii1i1
  I111 -= iii1i1
  if 83 - 83: O0 % o0oOOo0O0Ooo
 return
 if 77 - 77: I1Ii111 - OoooooooOO
 if 2 - 2: OoOoOO00 - OOooOOo * o0oOOo0O0Ooo / OoO0O00 - IiII % I1IiiI
 if 98 - 98: iIii1I11I1II1
 if 49 - 49: I1IiiI - I11i
 if 63 - 63: i11iIiiIii . OoO0O00 . oO0o
 if 85 - 85: oO0o . I1ii11iIi11i + i11iIiiIii
 if 85 - 85: I11i
def lisp_format_packet ( packet ) :
 packet = binascii . hexlify ( packet )
 oOO0OO0O = 0
 IiII11IIII1 = ""
 I111 = len ( packet ) * 2
 while ( oOO0OO0O < I111 ) :
  IiII11IIII1 += packet [ oOO0OO0O : oOO0OO0O + 8 ] + " "
  oOO0OO0O += 8
  I111 -= 4
  if 36 - 36: ooOoO0o % OoO0O00
 return ( IiII11IIII1 )
 if 1 - 1: OoooooooOO - OoOoOO00
 if 35 - 35: I1Ii111
 if 35 - 35: Oo0Ooo - iIii1I11I1II1 / i1IIi + OoO0O00 - OoooooooOO / i11iIiiIii
 if 79 - 79: I1IiiI * ooOoO0o * ooOoO0o
 if 92 - 92: iII111i % I1ii11iIi11i
 if 16 - 16: oO0o
 if 52 - 52: OoooooooOO % ooOoO0o - I1Ii111 * I11i
def lisp_send ( lisp_sockets , dest , port , packet ) :
 I1I1iii = lisp_sockets [ 0 ] if dest . is_ipv4 ( ) else lisp_sockets [ 1 ]
 if 63 - 63: IiII / OoooooooOO - ooOoO0o
 if 38 - 38: OoO0O00 + I1IiiI % IiII
 if 87 - 87: oO0o * Ii1I - I1Ii111 / oO0o
 if 65 - 65: OoOoOO00
 if 87 - 87: I11i - i11iIiiIii - OOooOOo . OoOoOO00 + IiII . OoO0O00
 if 70 - 70: iIii1I11I1II1 % OoooooooOO / OoO0O00 . O0 - I11i % II111iiii
 if 84 - 84: OOooOOo * i1IIi . iIii1I11I1II1 * iII111i + I1Ii111 + II111iiii
 if 97 - 97: Ii1I - IiII
 if 64 - 64: oO0o . ooOoO0o / ooOoO0o - II111iiii
 if 81 - 81: I1ii11iIi11i
 if 64 - 64: oO0o * OoO0O00 / OOooOOo + Ii1I % Oo0Ooo . IiII
 if 2 - 2: I1Ii111 + I11i
 i1i1Ii1Ii = dest . print_address_no_iid ( )
 if ( i1i1Ii1Ii . find ( "::ffff:" ) != - 1 and i1i1Ii1Ii . count ( "." ) == 3 ) :
  if ( lisp_i_am_rtr ) : I1I1iii = lisp_sockets [ 0 ]
  if ( I1I1iii == None ) :
   I1I1iii = lisp_sockets [ 0 ]
   i1i1Ii1Ii = i1i1Ii1Ii . split ( "::ffff:" ) [ - 1 ]
   if 47 - 47: i11iIiiIii + iIii1I11I1II1 % I1ii11iIi11i - oO0o % OoO0O00
   if 85 - 85: oO0o * OoOoOO00 / OoOoOO00
   if 85 - 85: OOooOOo / I1Ii111 . i1IIi / OoOoOO00 + iIii1I11I1II1
 lprint ( "{} {} bytes {} {}, packet: {}" . format ( bold ( "Send" , False ) ,
 len ( packet ) , bold ( "to " + i1i1Ii1Ii , False ) , port ,
 lisp_format_packet ( packet ) ) )
 if 71 - 71: OoO0O00
 if 96 - 96: I1ii11iIi11i / I1IiiI - I1ii11iIi11i / II111iiii - IiII
 if 74 - 74: Ii1I * OoooooooOO % OOooOOo + OoooooooOO + iII111i
 if 83 - 83: i1IIi
 ii11i = ( LISP_RLOC_PROBE_TTL == 255 )
 if ( ii11i ) :
  oooiIi1iiIii = struct . unpack ( "B" , packet [ 0 ] ) [ 0 ]
  ii11i = ( oooiIi1iiIii in [ 0x12 , 0x28 ] )
  if ( ii11i ) : lisp_set_ttl ( I1I1iii , LISP_RLOC_PROBE_TTL )
  if 5 - 5: O0 . i11iIiiIii
  if 71 - 71: o0oOOo0O0Ooo + iII111i + ooOoO0o
 try : I1I1iii . sendto ( packet , ( i1i1Ii1Ii , port ) )
 except socket . error , I1i11II :
  lprint ( "socket.sendto() failed: {}" . format ( I1i11II ) )
  if 27 - 27: OoooooooOO . iII111i * I1Ii111 % O0 + OoooooooOO - iII111i
  if 86 - 86: i1IIi
  if 81 - 81: OoOoOO00
  if 52 - 52: iII111i * IiII % I1IiiI * I11i
  if 73 - 73: I1Ii111 * ooOoO0o
 if ( ii11i ) : lisp_set_ttl ( I1I1iii , 64 )
 return
 if 62 - 62: OOooOOo . I1IiiI * iIii1I11I1II1 + OoO0O00 * ooOoO0o / oO0o
 if 14 - 14: iII111i / OoO0O00
 if 75 - 75: IiII
 if 68 - 68: IiII - i1IIi % IiII . OoO0O00 . i11iIiiIii . OoooooooOO
 if 32 - 32: iII111i + OoO0O00 % IiII + I1IiiI
 if 69 - 69: I1Ii111 + I11i - iIii1I11I1II1 - II111iiii . Ii1I
 if 74 - 74: I1ii11iIi11i % o0oOOo0O0Ooo + O0 - i11iIiiIii - IiII % OOooOOo
 if 39 - 39: OoO0O00 - o0oOOo0O0Ooo
def lisp_receive_segments ( lisp_socket , packet , source , total_length ) :
 if 71 - 71: iII111i . OoO0O00 + ooOoO0o - OOooOOo - Oo0Ooo
 if 100 - 100: OoooooooOO - o0oOOo0O0Ooo + I1Ii111 . OoooooooOO % i11iIiiIii
 if 64 - 64: I1Ii111 % OoooooooOO / i1IIi / OoO0O00
 if 2 - 2: I11i % o0oOOo0O0Ooo . OoO0O00 . OoO0O00
 if 89 - 89: ooOoO0o - oO0o + II111iiii + OoO0O00 - IiII
 iii1i1 = total_length - len ( packet )
 if ( iii1i1 == 0 ) : return ( [ True , packet ] )
 if 27 - 27: I1Ii111 - o0oOOo0O0Ooo + OoO0O00
 lprint ( "Received {}-out-of-{} byte segment from {}" . format ( len ( packet ) ,
 total_length , source ) )
 if 38 - 38: OoOoOO00 + OoO0O00 . i11iIiiIii + Ii1I % i1IIi % I1IiiI
 if 93 - 93: i11iIiiIii
 if 63 - 63: iIii1I11I1II1 - iIii1I11I1II1 % o0oOOo0O0Ooo
 if 97 - 97: i1IIi % I11i % OoOoOO00
 if 25 - 25: OoOoOO00 . iIii1I11I1II1 - iII111i % II111iiii . OoOoOO00
 I111 = iii1i1
 while ( I111 > 0 ) :
  try : II1I11IIII1i1 = lisp_socket . recvfrom ( 9000 )
  except : return ( [ False , None ] )
  if 16 - 16: OOooOOo . Oo0Ooo . I1IiiI % O0 . I1ii11iIi11i + i11iIiiIii
  II1I11IIII1i1 = II1I11IIII1i1 [ 0 ]
  if 100 - 100: I1ii11iIi11i - i1IIi - OoO0O00 * o0oOOo0O0Ooo + OoOoOO00
  if 31 - 31: i1IIi
  if 21 - 21: o0oOOo0O0Ooo / O0 % O0 . OoooooooOO / I1IiiI
  if 94 - 94: ooOoO0o + OoO0O00 / ooOoO0o - ooOoO0o + Oo0Ooo + o0oOOo0O0Ooo
  if 50 - 50: oO0o . Oo0Ooo
  if ( II1I11IIII1i1 . find ( "packet@" ) == 0 ) :
   iIiiii1iI1I = II1I11IIII1i1 . split ( "@" )
   lprint ( "Received new message ({}-out-of-{}) while receiving " + "fragments, old message discarded" , len ( II1I11IIII1i1 ) ,
   # OoooooooOO * Oo0Ooo . i11iIiiIii - I1Ii111 / OoooooooOO * IiII
 iIiiii1iI1I [ 1 ] if len ( iIiiii1iI1I ) > 2 else "?" )
   return ( [ False , II1I11IIII1i1 ] )
   if 89 - 89: O0
   if 41 - 41: o0oOOo0O0Ooo
  I111 -= len ( II1I11IIII1i1 )
  packet += II1I11IIII1i1
  if 12 - 12: OoOoOO00 - I1ii11iIi11i
  lprint ( "Received {}-out-of-{} byte segment from {}" . format ( len ( II1I11IIII1i1 ) , total_length , source ) )
  if 78 - 78: I1ii11iIi11i - OoooooooOO + O0
  if 15 - 15: I1ii11iIi11i / IiII % I1IiiI
 return ( [ True , packet ] )
 if 16 - 16: Ii1I
 if 26 - 26: o0oOOo0O0Ooo / I11i + OoOoOO00 / OoOoOO00
 if 31 - 31: I1Ii111
 if 84 - 84: i11iIiiIii * OOooOOo . iII111i - Ii1I * i1IIi - I1ii11iIi11i
 if 1 - 1: II111iiii
 if 94 - 94: I1ii11iIi11i * iII111i % iII111i % I11i - iII111i
 if 38 - 38: IiII - OoO0O00 % Ii1I - II111iiii
 if 97 - 97: O0 . Ii1I
def lisp_bit_stuff ( payload ) :
 lprint ( "Bit-stuffing, found {} segments" . format ( len ( payload ) ) )
 I1IiO00Ooo0ooo0 = ""
 for II1I11IIII1i1 in payload : I1IiO00Ooo0ooo0 += II1I11IIII1i1 + "\x40"
 return ( I1IiO00Ooo0ooo0 [ : - 1 ] )
 if 52 - 52: IiII
 if 86 - 86: I1Ii111 / O0 + OoooooooOO % oO0o
 if 45 - 45: I1IiiI . Oo0Ooo . I11i . Ii1I
 if 81 - 81: II111iiii + OoOoOO00 % i11iIiiIii / iII111i . I1Ii111 + II111iiii
 if 48 - 48: I1IiiI . I1ii11iIi11i * OoOoOO00 % i1IIi / I1Ii111 * II111iiii
 if 62 - 62: o0oOOo0O0Ooo * I1Ii111 . iIii1I11I1II1 / i1IIi
 if 75 - 75: OoooooooOO / ooOoO0o - iII111i . OoooooooOO . OoOoOO00 % i1IIi
 if 7 - 7: OoOoOO00 . i1IIi * i11iIiiIii % i11iIiiIii
 if 54 - 54: OoO0O00 / I1IiiI . Oo0Ooo
 if 39 - 39: OoO0O00 . ooOoO0o
 if 41 - 41: Oo0Ooo * I1ii11iIi11i - II111iiii - II111iiii
 if 7 - 7: oO0o
 if 41 - 41: ooOoO0o
 if 93 - 93: Ii1I + I1Ii111 + Ii1I
 if 23 - 23: I1IiiI - i1IIi / ooOoO0o
 if 4 - 4: IiII . I1ii11iIi11i + iII111i % ooOoO0o
 if 28 - 28: I1Ii111
 if 27 - 27: iII111i * I1IiiI
 if 60 - 60: i1IIi / I1IiiI - I1ii11iIi11i
 if 41 - 41: I1Ii111 + ooOoO0o / OOooOOo + I11i % Oo0Ooo
def lisp_receive ( lisp_socket , internal ) :
 while ( True ) :
  if 91 - 91: I1IiiI % I1ii11iIi11i % oO0o / i1IIi * iIii1I11I1II1 + I11i
  if 48 - 48: ooOoO0o / I1ii11iIi11i / OoO0O00 / II111iiii * OoOoOO00
  if 73 - 73: I11i / I1IiiI - IiII - i1IIi * IiII - OOooOOo
  if 39 - 39: I11i . ooOoO0o * II111iiii
  try : i1I1IIIi11I = lisp_socket . recvfrom ( 9000 )
  except : return ( [ "" , "" , "" , "" ] )
  if 13 - 13: iIii1I11I1II1 . OOooOOo . oO0o - Oo0Ooo * I1IiiI / i1IIi
  if 60 - 60: iIii1I11I1II1 + ooOoO0o / Oo0Ooo - IiII . I1ii11iIi11i
  if 24 - 24: iII111i + o0oOOo0O0Ooo . ooOoO0o + I1ii11iIi11i
  if 16 - 16: IiII - O0
  if 3 - 3: O0 + O0 . iII111i * I11i % I1IiiI . O0
  if 8 - 8: II111iiii / Ii1I / o0oOOo0O0Ooo - iIii1I11I1II1
  if ( internal == False ) :
   I1IiO00Ooo0ooo0 = i1I1IIIi11I [ 0 ]
   O00oo0o0o0oo = lisp_convert_6to4 ( i1I1IIIi11I [ 1 ] [ 0 ] )
   i1O0OO = i1I1IIIi11I [ 1 ] [ 1 ]
   if 58 - 58: OOooOOo
   if ( i1O0OO == LISP_DATA_PORT ) :
    O0Oo0oooo00 = lisp_data_plane_logging
    II1IiIIii = lisp_format_packet ( I1IiO00Ooo0ooo0 [ 0 : 60 ] ) + " ..."
   else :
    O0Oo0oooo00 = True
    II1IiIIii = lisp_format_packet ( I1IiO00Ooo0ooo0 )
    if 100 - 100: i11iIiiIii * O0 / Oo0Ooo % II111iiii
    if 49 - 49: oO0o
   if ( O0Oo0oooo00 ) :
    lprint ( "{} {} bytes {} {}, packet: {}" . format ( bold ( "Receive" ,
 False ) , len ( I1IiO00Ooo0ooo0 ) , bold ( "from " + O00oo0o0o0oo , False ) , i1O0OO ,
 II1IiIIii ) )
    if 98 - 98: OoooooooOO . II111iiii
   return ( [ "packet" , O00oo0o0o0oo , i1O0OO , I1IiO00Ooo0ooo0 ] )
   if 12 - 12: OoO0O00 - I1Ii111 / O0 - iII111i
   if 44 - 44: i1IIi
   if 23 - 23: I1ii11iIi11i . OoooooooOO / Ii1I + o0oOOo0O0Ooo
   if 89 - 89: OoOoOO00 + Oo0Ooo . OoOoOO00 - II111iiii
   if 85 - 85: OoooooooOO * OoooooooOO / Ii1I - II111iiii
   if 69 - 69: iII111i * I11i
  II11i1ii = False
  iii1iII1iii = i1I1IIIi11I [ 0 ]
  IiIiI1II = False
  if 70 - 70: OOooOOo * OoOoOO00 / oO0o + Oo0Ooo / O0
  while ( II11i1ii == False ) :
   iii1iII1iii = iii1iII1iii . split ( "@" )
   if 16 - 16: Oo0Ooo / OoooooooOO / IiII + Oo0Ooo * i11iIiiIii
   if ( len ( iii1iII1iii ) < 4 ) :
    lprint ( "Possible fragment (length {}), from old message, " + "discarding" , len ( iii1iII1iii [ 0 ] ) )
    if 15 - 15: o0oOOo0O0Ooo / i11iIiiIii
    IiIiI1II = True
    break
    if 63 - 63: I1ii11iIi11i - Ii1I + I11i
    if 98 - 98: iII111i / IiII * I1IiiI / oO0o - iIii1I11I1II1
   oo0 = iii1iII1iii [ 0 ]
   try :
    OoOoO0O = int ( iii1iII1iii [ 1 ] )
   except :
    iI1ii1 = bold ( "Internal packet reassembly error" , False )
    lprint ( "{}: {}" . format ( iI1ii1 , i1I1IIIi11I ) )
    IiIiI1II = True
    break
    if 55 - 55: i11iIiiIii * OOooOOo * I1ii11iIi11i
   O00oo0o0o0oo = iii1iII1iii [ 2 ]
   i1O0OO = iii1iII1iii [ 3 ]
   if 17 - 17: iIii1I11I1II1 - OoOoOO00
   if 97 - 97: iIii1I11I1II1 / OOooOOo * i1IIi - OoO0O00 / ooOoO0o % Ii1I
   if 30 - 30: OoOoOO00 / oO0o . iII111i
   if 56 - 56: OoOoOO00
   if 83 - 83: OOooOOo
   if 17 - 17: IiII + I1IiiI - I11i . I1IiiI
   if 34 - 34: ooOoO0o . i11iIiiIii * I1IiiI . II111iiii - iIii1I11I1II1
   if 43 - 43: i11iIiiIii % OoO0O00
   if ( len ( iii1iII1iii ) > 5 ) :
    I1IiO00Ooo0ooo0 = lisp_bit_stuff ( iii1iII1iii [ 4 : : ] )
   else :
    I1IiO00Ooo0ooo0 = iii1iII1iii [ 4 ]
    if 100 - 100: i1IIi
    if 4 - 4: i11iIiiIii - OOooOOo * IiII % OoooooooOO - OoOoOO00
    if 81 - 81: Ii1I * ooOoO0o . oO0o . IiII
    if 71 - 71: IiII + OoO0O00
    if 39 - 39: I1IiiI % IiII / II111iiii / II111iiii
    if 95 - 95: II111iiii + i11iIiiIii + o0oOOo0O0Ooo
   II11i1ii , I1IiO00Ooo0ooo0 = lisp_receive_segments ( lisp_socket , I1IiO00Ooo0ooo0 ,
 O00oo0o0o0oo , OoOoO0O )
   if ( I1IiO00Ooo0ooo0 == None ) : return ( [ "" , "" , "" , "" ] )
   if 30 - 30: O0 - O0 % iIii1I11I1II1 + iII111i * OoooooooOO
   if 1 - 1: O0
   if 36 - 36: oO0o . iII111i
   if 62 - 62: I11i + iIii1I11I1II1 % I11i * OOooOOo + iIii1I11I1II1 % Ii1I
   if 56 - 56: o0oOOo0O0Ooo
   if ( II11i1ii == False ) :
    iii1iII1iii = I1IiO00Ooo0ooo0
    continue
    if 55 - 55: oO0o - I1Ii111 / ooOoO0o % I1IiiI * OoooooooOO * I1IiiI
    if 88 - 88: Ii1I + O0
   if ( i1O0OO == "" ) : i1O0OO = "no-port"
   if ( oo0 == "command" and lisp_i_am_core == False ) :
    OOOoO000 = I1IiO00Ooo0ooo0 . find ( " {" )
    Oo00O0OoooO = I1IiO00Ooo0ooo0 if OOOoO000 == - 1 else I1IiO00Ooo0ooo0 [ : OOOoO000 ]
    Oo00O0OoooO = ": '" + Oo00O0OoooO + "'"
   else :
    Oo00O0OoooO = ""
    if 54 - 54: i1IIi
    if 26 - 26: o0oOOo0O0Ooo % i11iIiiIii % OoOoOO00 % OoO0O00 * iII111i % I1IiiI
   lprint ( "{} {} bytes {} {}, {}{}" . format ( bold ( "Receive" , False ) ,
 len ( I1IiO00Ooo0ooo0 ) , bold ( "from " + O00oo0o0o0oo , False ) , i1O0OO , oo0 ,
 Oo00O0OoooO if ( oo0 in [ "command" , "api" ] ) else ": ... " if ( oo0 == "data-packet" ) else ": " + lisp_format_packet ( I1IiO00Ooo0ooo0 ) ) )
   if 91 - 91: i1IIi * ooOoO0o
   if 33 - 33: I11i / OoooooooOO - Ii1I / OoO0O00 - OoO0O00
   if 60 - 60: OOooOOo . ooOoO0o % i1IIi % Ii1I % ooOoO0o + OoO0O00
   if 26 - 26: O0 % o0oOOo0O0Ooo + iII111i * I1ii11iIi11i * I1Ii111
   if 4 - 4: OOooOOo * OoooooooOO * i1IIi % I1ii11iIi11i % Oo0Ooo
  if ( IiIiI1II ) : continue
  return ( [ oo0 , O00oo0o0o0oo , i1O0OO , I1IiO00Ooo0ooo0 ] )
  if 1 - 1: OoO0O00 / iIii1I11I1II1 % I1ii11iIi11i - o0oOOo0O0Ooo
  if 62 - 62: I1Ii111 % II111iiii
  if 91 - 91: I11i % Ii1I - IiII + iIii1I11I1II1 * iIii1I11I1II1
  if 91 - 91: i11iIiiIii + Ii1I
  if 85 - 85: I11i % IiII
  if 68 - 68: Oo0Ooo . I1Ii111 - o0oOOo0O0Ooo * iIii1I11I1II1 - II111iiii % i1IIi
  if 58 - 58: I11i / i11iIiiIii * i11iIiiIii
  if 24 - 24: ooOoO0o - I1Ii111 * II111iiii - II111iiii
def lisp_parse_packet ( lisp_sockets , packet , source , udp_sport , ttl = - 1 ) :
 I1ii1II11 = False
 if 14 - 14: II111iiii * Ii1I / ooOoO0o % iIii1I11I1II1
 III1Iiii1i11 = lisp_control_header ( )
 if ( III1Iiii1i11 . decode ( packet ) == None ) :
  lprint ( "Could not decode control header" )
  return ( I1ii1II11 )
  if 40 - 40: i1IIi % I1Ii111 - oO0o / oO0o / I1ii11iIi11i % O0
  if 82 - 82: OoO0O00 - I1IiiI - i1IIi - I1IiiI % OOooOOo
  if 80 - 80: OoOoOO00
  if 31 - 31: OOooOOo * ooOoO0o + ooOoO0o / O0 - OOooOOo
  if 47 - 47: I1Ii111 . OoooooooOO - oO0o - o0oOOo0O0Ooo . I1ii11iIi11i / iIii1I11I1II1
 Ii1II = source
 if ( source . find ( "lisp" ) == - 1 ) :
  i1I1iIi1IiI = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  i1I1iIi1IiI . string_to_afi ( source )
  i1I1iIi1IiI . store_address ( source )
  source = i1I1iIi1IiI
  if 35 - 35: Ii1I / i1IIi % ooOoO0o % OOooOOo * OoooooooOO + OoOoOO00
  if 32 - 32: iIii1I11I1II1 / OoooooooOO - O0 - iIii1I11I1II1 . II111iiii
 if ( III1Iiii1i11 . type == LISP_MAP_REQUEST ) :
  lisp_process_map_request ( lisp_sockets , packet , None , 0 , source ,
 udp_sport , False , ttl )
  if 49 - 49: I1IiiI % i11iIiiIii
 elif ( III1Iiii1i11 . type == LISP_MAP_REPLY ) :
  lisp_process_map_reply ( lisp_sockets , packet , source , ttl )
  if 25 - 25: OOooOOo + i11iIiiIii * ooOoO0o
 elif ( III1Iiii1i11 . type == LISP_MAP_REGISTER ) :
  lisp_process_map_register ( lisp_sockets , packet , source , udp_sport )
  if 4 - 4: O0 + I1IiiI + I1Ii111
 elif ( III1Iiii1i11 . type == LISP_MAP_NOTIFY ) :
  if ( Ii1II == "lisp-etr" ) :
   lisp_process_multicast_map_notify ( packet , source )
  else :
   if ( lisp_is_running ( "lisp-rtr" ) ) :
    lisp_process_multicast_map_notify ( packet , source )
    if 80 - 80: Ii1I % OoooooooOO . i1IIi - OOooOOo
   lisp_process_map_notify ( lisp_sockets , packet , source )
   if 10 - 10: I11i + iII111i % OoO0O00 / OoO0O00
   if 91 - 91: ooOoO0o . oO0o
 elif ( III1Iiii1i11 . type == LISP_MAP_NOTIFY_ACK ) :
  lisp_process_map_notify_ack ( packet , source )
  if 66 - 66: II111iiii + OOooOOo + i11iIiiIii / II111iiii
 elif ( III1Iiii1i11 . type == LISP_MAP_REFERRAL ) :
  lisp_process_map_referral ( lisp_sockets , packet , source )
  if 37 - 37: I1IiiI + OoO0O00 . OoO0O00 % OoOoOO00 + o0oOOo0O0Ooo
 elif ( III1Iiii1i11 . type == LISP_NAT_INFO and III1Iiii1i11 . is_info_reply ( ) ) :
  i1i11Ii1 , o0OoO0 , I1ii1II11 = lisp_process_info_reply ( source , packet , True )
  if 81 - 81: i1IIi % iIii1I11I1II1
 elif ( III1Iiii1i11 . type == LISP_NAT_INFO and III1Iiii1i11 . is_info_reply ( ) == False ) :
  OoOOoooO000 = source . print_address_no_iid ( )
  lisp_process_info_request ( lisp_sockets , packet , OoOOoooO000 , udp_sport ,
 None )
  if 41 - 41: oO0o - iII111i / o0oOOo0O0Ooo . iII111i % Oo0Ooo + OOooOOo
 elif ( III1Iiii1i11 . type == LISP_ECM ) :
  lisp_process_ecm ( lisp_sockets , packet , source , udp_sport )
  if 82 - 82: ooOoO0o
 else :
  lprint ( "Invalid LISP control packet type {}" . format ( III1Iiii1i11 . type ) )
  if 89 - 89: OOooOOo / I1ii11iIi11i . I1IiiI + i11iIiiIii
 return ( I1ii1II11 )
 if 11 - 11: oO0o . i11iIiiIii * ooOoO0o % OoooooooOO % O0
 if 59 - 59: i11iIiiIii / OoO0O00
 if 48 - 48: iIii1I11I1II1
 if 19 - 19: oO0o
 if 69 - 69: I1ii11iIi11i % iII111i - OoooooooOO % Ii1I * oO0o
 if 12 - 12: OoOoOO00 / I1Ii111 . O0 . IiII - OOooOOo - OoO0O00
 if 28 - 28: II111iiii . OoOoOO00 - o0oOOo0O0Ooo
def lisp_process_rloc_probe_request ( lisp_sockets , map_request , source , port ,
 ttl ) :
 if 89 - 89: I1Ii111 * OoooooooOO . OOooOOo . I11i % i11iIiiIii
 oo000o = bold ( "RLOC-probe" , False )
 if 8 - 8: I1ii11iIi11i + II111iiii . OoO0O00 + I1IiiI - II111iiii % OoO0O00
 if ( lisp_i_am_etr ) :
  lprint ( "Received {} Map-Request, send RLOC-probe Map-Reply" . format ( oo000o ) )
  lisp_etr_process_map_request ( lisp_sockets , map_request , source , port ,
 ttl )
  return
  if 85 - 85: i11iIiiIii % iII111i + II111iiii
  if 16 - 16: ooOoO0o * OoOoOO00 / OoOoOO00 + II111iiii
 if ( lisp_i_am_rtr ) :
  lprint ( "Received {} Map-Request, send RLOC-probe Map-Reply" . format ( oo000o ) )
  lisp_rtr_process_map_request ( lisp_sockets , map_request , source , port ,
 ttl )
  return
  if 50 - 50: OoO0O00 / OOooOOo % I1IiiI / Ii1I + OoO0O00 . iIii1I11I1II1
  if 62 - 62: I1Ii111 + OoooooooOO - Ii1I - iIii1I11I1II1
 lprint ( "Ignoring received {} Map-Request, not an ETR or RTR" . format ( oo000o ) )
 return
 if 80 - 80: OoO0O00
 if 72 - 72: II111iiii % i11iIiiIii + OoOoOO00 / I1Ii111 - i11iIiiIii
 if 39 - 39: i11iIiiIii - OOooOOo / OoO0O00 * OoOoOO00 / IiII
 if 84 - 84: I1ii11iIi11i . iIii1I11I1II1 / Ii1I / II111iiii
 if 56 - 56: OOooOOo * iII111i / Ii1I
def lisp_process_smr ( map_request ) :
 lprint ( "Received SMR-based Map-Request" )
 return
 if 9 - 9: I1ii11iIi11i * i11iIiiIii / I1Ii111 + iIii1I11I1II1
 if 1 - 1: OoO0O00 % iIii1I11I1II1 * OoOoOO00 / oO0o
 if 73 - 73: iII111i
 if 6 - 6: o0oOOo0O0Ooo + Oo0Ooo
 if 45 - 45: oO0o % O0 / O0
def lisp_process_smr_invoked_request ( map_request ) :
 lprint ( "Received SMR-invoked Map-Request" )
 return
 if 98 - 98: I1Ii111
 if 58 - 58: OOooOOo
 if 6 - 6: I1ii11iIi11i
 if 37 - 37: i11iIiiIii . II111iiii + OOooOOo + i1IIi * OOooOOo
 if 18 - 18: ooOoO0o
 if 18 - 18: I1Ii111 + OoOoOO00 % OOooOOo - IiII - i1IIi + I1ii11iIi11i
 if 33 - 33: I11i * Ii1I / Oo0Ooo + oO0o % OOooOOo % OoooooooOO
def lisp_build_map_reply ( eid , group , rloc_set , nonce , action , ttl , rloc_probe ,
 keys , enc , auth , mr_ttl = - 1 ) :
 i1i = lisp_map_reply ( )
 i1i . rloc_probe = rloc_probe
 i1i . echo_nonce_capable = enc
 i1i . hop_count = 0 if ( mr_ttl == - 1 ) else mr_ttl
 i1i . record_count = 1
 i1i . nonce = nonce
 I1IiO00Ooo0ooo0 = i1i . encode ( )
 i1i . print_map_reply ( )
 if 30 - 30: IiII % IiII . OoOoOO00 / oO0o % OoO0O00 / OoO0O00
 O0OO000oOO0 = lisp_eid_record ( )
 O0OO000oOO0 . rloc_count = len ( rloc_set )
 O0OO000oOO0 . authoritative = auth
 O0OO000oOO0 . record_ttl = ttl
 O0OO000oOO0 . action = action
 O0OO000oOO0 . eid = eid
 O0OO000oOO0 . group = group
 if 81 - 81: i11iIiiIii - II111iiii + I11i
 I1IiO00Ooo0ooo0 += O0OO000oOO0 . encode ( )
 O0OO000oOO0 . print_record ( "  " , False )
 if 52 - 52: II111iiii
 O0OO = lisp_get_all_addresses ( ) + lisp_get_all_translated_rlocs ( )
 if 29 - 29: Oo0Ooo
 for iIIiIiiI in rloc_set :
  o0oooOOOOO0oo = lisp_rloc_record ( )
  OoOOoooO000 = iIIiIiiI . rloc . print_address_no_iid ( )
  if ( OoOOoooO000 in O0OO ) :
   o0oooOOOOO0oo . local_bit = True
   o0oooOOOOO0oo . probe_bit = rloc_probe
   o0oooOOOOO0oo . keys = keys
   if ( iIIiIiiI . priority == 254 and lisp_i_am_rtr ) :
    o0oooOOOOO0oo . rloc_name = "RTR"
    if 17 - 17: OoO0O00 % o0oOOo0O0Ooo
    if 21 - 21: OOooOOo + OOooOOo - i11iIiiIii * IiII % iIii1I11I1II1
  o0oooOOOOO0oo . store_rloc_entry ( iIIiIiiI )
  o0oooOOOOO0oo . reach_bit = True
  o0oooOOOOO0oo . print_record ( "    " )
  I1IiO00Ooo0ooo0 += o0oooOOOOO0oo . encode ( )
  if 86 - 86: ooOoO0o + OoOoOO00
 return ( I1IiO00Ooo0ooo0 )
 if 94 - 94: IiII
 if 30 - 30: o0oOOo0O0Ooo % OoOoOO00 * IiII % iIii1I11I1II1 % O0
 if 76 - 76: II111iiii * I11i
 if 29 - 29: OoooooooOO . i1IIi
 if 46 - 46: I11i
 if 92 - 92: IiII * OoO0O00 . OoOoOO00 + iII111i - I1IiiI
 if 15 - 15: OoO0O00 / OoO0O00 * o0oOOo0O0Ooo * I1ii11iIi11i - o0oOOo0O0Ooo
def lisp_build_map_referral ( eid , group , ddt_entry , action , ttl , nonce ) :
 iiiIi = lisp_map_referral ( )
 iiiIi . record_count = 1
 iiiIi . nonce = nonce
 I1IiO00Ooo0ooo0 = iiiIi . encode ( )
 iiiIi . print_map_referral ( )
 if 7 - 7: oO0o . ooOoO0o
 O0OO000oOO0 = lisp_eid_record ( )
 if 73 - 73: i1IIi % I1Ii111 * ooOoO0o % OoO0O00
 o0Oo0Oooo0ooO = 0
 if ( ddt_entry == None ) :
  O0OO000oOO0 . eid = eid
  O0OO000oOO0 . group = group
 else :
  o0Oo0Oooo0ooO = len ( ddt_entry . delegation_set )
  O0OO000oOO0 . eid = ddt_entry . eid
  O0OO000oOO0 . group = ddt_entry . group
  ddt_entry . map_referrals_sent += 1
  if 43 - 43: iIii1I11I1II1 + ooOoO0o * iII111i + iIii1I11I1II1 . I1Ii111
 O0OO000oOO0 . rloc_count = o0Oo0Oooo0ooO
 O0OO000oOO0 . authoritative = True
 if 87 - 87: I1Ii111
 if 47 - 47: II111iiii + I1IiiI . Oo0Ooo / iIii1I11I1II1
 if 14 - 14: i1IIi / OoO0O00 / iII111i % I1Ii111
 if 72 - 72: OoO0O00 . II111iiii - IiII + IiII + iIii1I11I1II1 % oO0o
 if 21 - 21: iII111i + OoOoOO00 - i11iIiiIii % O0 + OOooOOo
 I111o0oooO00o0 = False
 if ( action == LISP_DDT_ACTION_NULL ) :
  if ( o0Oo0Oooo0ooO == 0 ) :
   action = LISP_DDT_ACTION_NODE_REFERRAL
  else :
   O0o0oO = ddt_entry . delegation_set [ 0 ]
   if ( O0o0oO . is_ddt_child ( ) ) :
    action = LISP_DDT_ACTION_NODE_REFERRAL
    if 30 - 30: o0oOOo0O0Ooo - Oo0Ooo + iII111i / O0
   if ( O0o0oO . is_ms_child ( ) ) :
    action = LISP_DDT_ACTION_MS_REFERRAL
    if 94 - 94: IiII
    if 69 - 69: I1Ii111 . I1Ii111
    if 53 - 53: i11iIiiIii + iII111i * Oo0Ooo - I1Ii111
    if 61 - 61: o0oOOo0O0Ooo / OOooOOo . II111iiii - I1IiiI * i11iIiiIii
    if 8 - 8: iII111i % o0oOOo0O0Ooo
    if 87 - 87: Ii1I % I11i / I1Ii111
    if 21 - 21: OoO0O00 + Ii1I / I1Ii111
 if ( action == LISP_DDT_ACTION_NOT_AUTH ) : I111o0oooO00o0 = True
 if ( action in ( LISP_DDT_ACTION_MS_REFERRAL , LISP_DDT_ACTION_MS_ACK ) ) :
  I111o0oooO00o0 = ( lisp_i_am_ms and O0o0oO . is_ms_peer ( ) == False )
  if 75 - 75: I1Ii111 . Ii1I % iIii1I11I1II1 / OoOoOO00
  if 38 - 38: i1IIi
 O0OO000oOO0 . action = action
 O0OO000oOO0 . ddt_incomplete = I111o0oooO00o0
 O0OO000oOO0 . record_ttl = ttl
 if 1 - 1: I1ii11iIi11i + OoO0O00 % I11i . OOooOOo + i1IIi / oO0o
 I1IiO00Ooo0ooo0 += O0OO000oOO0 . encode ( )
 O0OO000oOO0 . print_record ( "  " , True )
 if 35 - 35: ooOoO0o % OoOoOO00 % OoO0O00 + OOooOOo / IiII * OoOoOO00
 if ( o0Oo0Oooo0ooO == 0 ) : return ( I1IiO00Ooo0ooo0 )
 if 65 - 65: I1IiiI . Oo0Ooo + i1IIi - Ii1I * i1IIi
 for O0o0oO in ddt_entry . delegation_set :
  o0oooOOOOO0oo = lisp_rloc_record ( )
  o0oooOOOOO0oo . rloc = O0o0oO . delegate_address
  o0oooOOOOO0oo . priority = O0o0oO . priority
  o0oooOOOOO0oo . weight = O0o0oO . weight
  o0oooOOOOO0oo . mpriority = 255
  o0oooOOOOO0oo . mweight = 0
  o0oooOOOOO0oo . reach_bit = True
  I1IiO00Ooo0ooo0 += o0oooOOOOO0oo . encode ( )
  o0oooOOOOO0oo . print_record ( "    " )
  if 64 - 64: I1IiiI / OoO0O00 * I1IiiI * II111iiii . Ii1I
 return ( I1IiO00Ooo0ooo0 )
 if 98 - 98: I1Ii111 + o0oOOo0O0Ooo
 if 73 - 73: I1ii11iIi11i / I1Ii111 + i11iIiiIii + OoO0O00 . ooOoO0o
 if 54 - 54: I1ii11iIi11i + IiII - oO0o + Oo0Ooo / IiII % Oo0Ooo
 if 2 - 2: OOooOOo / I11i * I11i + I11i / O0 - OOooOOo
 if 29 - 29: OoOoOO00 + i11iIiiIii % OoO0O00 - OoooooooOO
 if 68 - 68: iII111i / OOooOOo
 if 28 - 28: II111iiii
def lisp_etr_process_map_request ( lisp_sockets , map_request , source , sport ,
 ttl ) :
 if 49 - 49: I1ii11iIi11i
 if ( map_request . target_group . is_null ( ) ) :
  i1iOo = lisp_db_for_lookups . lookup_cache ( map_request . target_eid , False )
 else :
  i1iOo = lisp_db_for_lookups . lookup_cache ( map_request . target_group , False )
  if ( i1iOo ) : i1iOo = i1iOo . lookup_source_cache ( map_request . target_eid , False )
  if 73 - 73: Ii1I . i1IIi . o0oOOo0O0Ooo + O0
 oo0ooooO = map_request . print_prefix ( )
 if 90 - 90: i11iIiiIii * I1Ii111 % i1IIi + OoOoOO00
 if ( i1iOo == None ) :
  lprint ( "Database-mapping entry not found for requested EID {}" . format ( green ( oo0ooooO , False ) ) )
  if 84 - 84: i11iIiiIii + oO0o
  return
  if 45 - 45: Ii1I
  if 8 - 8: oO0o + OOooOOo
 I1IIIIII = i1iOo . print_eid_tuple ( )
 if 90 - 90: OOooOOo - Oo0Ooo
 lprint ( "Found database-mapping EID-prefix {} for requested EID {}" . format ( green ( I1IIIIII , False ) , green ( oo0ooooO , False ) ) )
 if 57 - 57: I1IiiI + IiII + IiII * I1ii11iIi11i
 if 63 - 63: iIii1I11I1II1 % IiII * I1Ii111 . IiII * oO0o % o0oOOo0O0Ooo
 if 78 - 78: OOooOOo
 if 10 - 10: oO0o
 if 19 - 19: OoOoOO00 * I11i
 i1II = map_request . itr_rlocs [ 0 ]
 if ( i1II . is_private_address ( ) and lisp_nat_traversal ) :
  i1II = source
  if 39 - 39: i1IIi / Ii1I - ooOoO0o . OoooooooOO
  if 73 - 73: I11i / OoooooooOO . IiII * I11i / OoooooooOO
 o0oo000 = map_request . nonce
 II1ii11I1iIiI1 = lisp_nonce_echoing
 O000OO = map_request . keys
 if 29 - 29: II111iiii - I1Ii111 . OoooooooOO / i11iIiiIii / I1ii11iIi11i
 i1iOo . map_replies_sent += 1
 if 60 - 60: i1IIi % ooOoO0o / II111iiii * Oo0Ooo - i1IIi . Ii1I
 I1IiO00Ooo0ooo0 = lisp_build_map_reply ( i1iOo . eid , i1iOo . group , i1iOo . rloc_set , o0oo000 ,
 LISP_NO_ACTION , 1440 , map_request . rloc_probe , O000OO , II1ii11I1iIiI1 , True , ttl )
 if 63 - 63: OoO0O00 * OoooooooOO + iII111i / iIii1I11I1II1 . i11iIiiIii
 if 17 - 17: OOooOOo
 if 21 - 21: i1IIi
 if 10 - 10: i11iIiiIii / ooOoO0o - o0oOOo0O0Ooo . o0oOOo0O0Ooo
 if 8 - 8: iII111i + iIii1I11I1II1 . I1ii11iIi11i
 if 68 - 68: OoooooooOO . OoooooooOO % I1ii11iIi11i + i1IIi % OoooooooOO + Ii1I
 if 89 - 89: ooOoO0o + I11i * O0 % OoOoOO00
 if 2 - 2: I1Ii111 % iIii1I11I1II1 . Ii1I - II111iiii
 if 33 - 33: I11i . i11iIiiIii % i1IIi * II111iiii * i11iIiiIii + OoOoOO00
 if 26 - 26: I1IiiI % OoOoOO00 % I11i + Oo0Ooo
 if ( map_request . rloc_probe and len ( lisp_sockets ) == 4 ) :
  iIOoO0O00 = ( i1II . is_private_address ( ) == False )
  O0Oo = i1II . print_address_no_iid ( )
  if ( iIOoO0O00 and lisp_rtr_list . has_key ( O0Oo ) ) :
   lisp_encapsulate_rloc_probe ( lisp_sockets , i1II , None , I1IiO00Ooo0ooo0 )
   return
   if 86 - 86: iII111i / i1IIi % Oo0Ooo
   if 84 - 84: o0oOOo0O0Ooo * OOooOOo . I11i * Ii1I
   if 32 - 32: ooOoO0o % ooOoO0o * I1ii11iIi11i % Ii1I + Oo0Ooo . OoOoOO00
   if 2 - 2: I1Ii111 / ooOoO0o * oO0o + IiII
   if 14 - 14: OoOoOO00 / iIii1I11I1II1 . o0oOOo0O0Ooo % i11iIiiIii . OoOoOO00
   if 92 - 92: OoO0O00 . i1IIi
 lisp_send_map_reply ( lisp_sockets , I1IiO00Ooo0ooo0 , i1II , sport )
 return
 if 22 - 22: Ii1I . I1IiiI
 if 54 - 54: OOooOOo / I1ii11iIi11i % oO0o
 if 66 - 66: I11i + iII111i
 if 50 - 50: IiII
 if 33 - 33: OOooOOo % I1IiiI - I1IiiI / IiII
 if 22 - 22: ooOoO0o * ooOoO0o % o0oOOo0O0Ooo * Ii1I . OoO0O00
 if 55 - 55: OoOoOO00 - I1ii11iIi11i + iIii1I11I1II1 - i11iIiiIii / i1IIi / II111iiii
def lisp_rtr_process_map_request ( lisp_sockets , map_request , source , sport ,
 ttl ) :
 if 37 - 37: Ii1I + o0oOOo0O0Ooo
 if 74 - 74: Oo0Ooo / O0 + i1IIi . I1IiiI + OoO0O00 / Oo0Ooo
 if 13 - 13: o0oOOo0O0Ooo / Ii1I . II111iiii
 if 8 - 8: I11i - I11i % IiII
 i1II = map_request . itr_rlocs [ 0 ]
 if ( i1II . is_private_address ( ) ) : i1II = source
 o0oo000 = map_request . nonce
 if 8 - 8: I1IiiI . IiII * O0 * o0oOOo0O0Ooo
 Ooo0 = map_request . target_eid
 ooOoO00 = map_request . target_group
 if 17 - 17: I1IiiI . oO0o + Oo0Ooo + I11i / o0oOOo0O0Ooo
 I111iIi11Ii11III = [ ]
 for Ii1IiIiiI1Ii in [ lisp_myrlocs [ 0 ] , lisp_myrlocs [ 1 ] ] :
  if ( Ii1IiIiiI1Ii == None ) : continue
  oOoOoo0O = lisp_rloc ( )
  oOoOoo0O . rloc . copy_address ( Ii1IiIiiI1Ii )
  oOoOoo0O . priority = 254
  I111iIi11Ii11III . append ( oOoOoo0O )
  if 13 - 13: IiII
  if 97 - 97: i1IIi * i1IIi % Oo0Ooo
 II1ii11I1iIiI1 = lisp_nonce_echoing
 O000OO = map_request . keys
 if 79 - 79: I1ii11iIi11i
 I1IiO00Ooo0ooo0 = lisp_build_map_reply ( Ooo0 , ooOoO00 , I111iIi11Ii11III , o0oo000 , LISP_NO_ACTION ,
 1440 , True , O000OO , II1ii11I1iIiI1 , True , ttl )
 lisp_send_map_reply ( lisp_sockets , I1IiO00Ooo0ooo0 , i1II , sport )
 return
 if 84 - 84: Ii1I . i11iIiiIii / I1ii11iIi11i % OoO0O00
 if 92 - 92: O0 - OOooOOo + II111iiii
 if 90 - 90: II111iiii . II111iiii - IiII / iII111i * i11iIiiIii
 if 70 - 70: I1ii11iIi11i + I11i
 if 58 - 58: iII111i . Oo0Ooo - I11i / I1IiiI + O0 . I11i
 if 70 - 70: Oo0Ooo % OoOoOO00 + i11iIiiIii / OoO0O00 . IiII * IiII
 if 72 - 72: ooOoO0o
 if 21 - 21: Ii1I - OOooOOo
 if 32 - 32: iIii1I11I1II1 / OoO0O00
 if 22 - 22: II111iiii . I11i
def lisp_get_private_rloc_set ( target_site_eid , seid , group ) :
 I111iIi11Ii11III = target_site_eid . registered_rlocs
 if 61 - 61: OOooOOo % O0 . I1ii11iIi11i . iIii1I11I1II1 * I11i
 I11i111 = lisp_site_eid_lookup ( seid , group , False )
 if ( I11i111 == None ) : return ( I111iIi11Ii11III )
 if 94 - 94: OOooOOo / IiII
 if 18 - 18: IiII - I11i / Ii1I % IiII * i1IIi
 if 22 - 22: OoOoOO00 - Oo0Ooo
 if 41 - 41: iIii1I11I1II1 * I1Ii111 / OoO0O00
 i1iiIi1 = None
 O000OOo0o0o0 = [ ]
 for iIIiIiiI in I111iIi11Ii11III :
  if ( iIIiIiiI . is_rtr ( ) ) : continue
  if ( iIIiIiiI . rloc . is_private_address ( ) ) :
   ii1iiI = copy . deepcopy ( iIIiIiiI )
   O000OOo0o0o0 . append ( ii1iiI )
   continue
   if 51 - 51: I1ii11iIi11i
  i1iiIi1 = iIIiIiiI
  break
  if 37 - 37: I1IiiI % I1Ii111
 if ( i1iiIi1 == None ) : return ( I111iIi11Ii11III )
 i1iiIi1 = i1iiIi1 . rloc . print_address_no_iid ( )
 if 22 - 22: o0oOOo0O0Ooo % OOooOOo - I11i + ooOoO0o / OOooOOo
 if 98 - 98: I11i * O0 + IiII - oO0o
 if 35 - 35: OoooooooOO * Ii1I
 if 73 - 73: ooOoO0o . OoO0O00 % I1ii11iIi11i - oO0o
 oOI11I = None
 for iIIiIiiI in I11i111 . registered_rlocs :
  if ( iIIiIiiI . is_rtr ( ) ) : continue
  if ( iIIiIiiI . rloc . is_private_address ( ) ) : continue
  oOI11I = iIIiIiiI
  break
  if 37 - 37: I1IiiI
 if ( oOI11I == None ) : return ( I111iIi11Ii11III )
 oOI11I = oOI11I . rloc . print_address_no_iid ( )
 if 76 - 76: iIii1I11I1II1 . iII111i % ooOoO0o / iII111i + I11i
 if 85 - 85: i11iIiiIii
 if 25 - 25: oO0o . OoO0O00 % Ii1I % Ii1I
 if 94 - 94: iII111i . Ii1I
 oO0000oo00O = target_site_eid . site_id
 if ( oO0000oo00O == 0 ) :
  if ( oOI11I == i1iiIi1 ) :
   lprint ( "Return private RLOCs for sites behind {}" . format ( i1iiIi1 ) )
   if 71 - 71: o0oOOo0O0Ooo * II111iiii / OOooOOo . OoO0O00
   return ( O000OOo0o0o0 )
   if 73 - 73: I1Ii111 * OoO0O00 / OoOoOO00 . II111iiii
  return ( I111iIi11Ii11III )
  if 87 - 87: OoO0O00 + Oo0Ooo + O0 % OoooooooOO - iIii1I11I1II1
  if 100 - 100: Oo0Ooo + IiII
  if 81 - 81: iIii1I11I1II1 + iIii1I11I1II1
  if 19 - 19: ooOoO0o + i1IIi / Oo0Ooo * II111iiii * I1Ii111 / ooOoO0o
  if 23 - 23: I1Ii111
  if 76 - 76: Ii1I + Ii1I / i1IIi % o0oOOo0O0Ooo . iIii1I11I1II1 . OoOoOO00
  if 75 - 75: I11i . Ii1I / I1ii11iIi11i
 if ( oO0000oo00O == I11i111 . site_id ) :
  lprint ( "Return private RLOCs for sites in site-id {}" . format ( oO0000oo00O ) )
  return ( O000OOo0o0o0 )
  if 99 - 99: Ii1I
 return ( I111iIi11Ii11III )
 if 85 - 85: I1Ii111 + I1Ii111 + OoOoOO00 / ooOoO0o / o0oOOo0O0Ooo . Oo0Ooo
 if 41 - 41: i1IIi % Ii1I . i1IIi * OoooooooOO % Ii1I
 if 21 - 21: iII111i
 if 72 - 72: I11i % o0oOOo0O0Ooo . iIii1I11I1II1 - I1Ii111 / i11iIiiIii
 if 75 - 75: OoooooooOO
 if 24 - 24: oO0o % iII111i - II111iiii / Ii1I + O0
 if 37 - 37: I1Ii111 - i1IIi / iIii1I11I1II1
 if 53 - 53: Ii1I - iIii1I11I1II1 % I1ii11iIi11i * i11iIiiIii + ooOoO0o
 if 63 - 63: Oo0Ooo * I1IiiI
def lisp_get_partial_rloc_set ( registered_rloc_set , mr_source , multicast ) :
 oOOoOo = [ ]
 I111iIi11Ii11III = [ ]
 if 29 - 29: oO0o % OoOoOO00
 if 65 - 65: o0oOOo0O0Ooo - i1IIi + iIii1I11I1II1 % i1IIi * i11iIiiIii % oO0o
 if 62 - 62: OOooOOo * i1IIi - OOooOOo / i11iIiiIii
 if 17 - 17: I1ii11iIi11i + ooOoO0o % Ii1I % OOooOOo
 if 73 - 73: i11iIiiIii
 if 44 - 44: o0oOOo0O0Ooo % Ii1I - OoOoOO00 + OoOoOO00 * IiII + iII111i
 OOOO = False
 oooOooO0 = False
 for iIIiIiiI in registered_rloc_set :
  if ( iIIiIiiI . priority != 254 ) : continue
  oooOooO0 |= True
  if ( iIIiIiiI . rloc . is_exact_match ( mr_source ) == False ) : continue
  OOOO = True
  break
  if 25 - 25: I1ii11iIi11i / i1IIi * oO0o - II111iiii * i1IIi
  if 57 - 57: OoO0O00 % OoO0O00
  if 67 - 67: O0 . i11iIiiIii + iIii1I11I1II1
  if 86 - 86: iIii1I11I1II1
  if 81 - 81: OOooOOo / I11i / OoooooooOO
  if 74 - 74: I11i + OoooooooOO % II111iiii % o0oOOo0O0Ooo
  if 27 - 27: OoO0O00 * Oo0Ooo
 if ( oooOooO0 == False ) : return ( registered_rloc_set )
 if 80 - 80: i11iIiiIii . OoO0O00 - I11i % I11i
 if 21 - 21: I1IiiI . OoO0O00 * IiII % OoooooooOO - Oo0Ooo + Oo0Ooo
 if 94 - 94: ooOoO0o
 if 80 - 80: i11iIiiIii - O0 / I1Ii111 + OOooOOo % Oo0Ooo
 if 95 - 95: II111iiii
 if 76 - 76: OoO0O00 % iII111i * OoOoOO00 / ooOoO0o / i1IIi
 if 45 - 45: Ii1I . I11i * I1Ii111 . i11iIiiIii
 if 34 - 34: O0 * o0oOOo0O0Ooo / IiII
 if 75 - 75: I1Ii111 - i1IIi - OoO0O00
 if 25 - 25: iII111i . o0oOOo0O0Ooo
 O0ooOO = ( os . getenv ( "LISP_RTR_BEHIND_NAT" ) != None )
 if 60 - 60: iII111i / OoooooooOO * II111iiii * Oo0Ooo * o0oOOo0O0Ooo
 if 60 - 60: iII111i . OOooOOo
 if 39 - 39: O0 - i11iIiiIii - I1IiiI / Oo0Ooo - i11iIiiIii
 if 30 - 30: OoO0O00 / OoOoOO00 + I1ii11iIi11i % IiII - OoO0O00
 if 19 - 19: I1IiiI
 for iIIiIiiI in registered_rloc_set :
  if ( O0ooOO and iIIiIiiI . rloc . is_private_address ( ) ) : continue
  if ( multicast == False and iIIiIiiI . priority == 255 ) : continue
  if ( multicast and iIIiIiiI . mpriority == 255 ) : continue
  if ( iIIiIiiI . priority == 254 ) :
   oOOoOo . append ( iIIiIiiI )
  else :
   I111iIi11Ii11III . append ( iIIiIiiI )
   if 99 - 99: OOooOOo - OOooOOo
   if 98 - 98: o0oOOo0O0Ooo + O0 * oO0o - i11iIiiIii
   if 83 - 83: o0oOOo0O0Ooo
   if 23 - 23: o0oOOo0O0Ooo . I11i
   if 67 - 67: iII111i
   if 52 - 52: IiII . OoooooooOO
 if ( OOOO ) : return ( I111iIi11Ii11III )
 if 34 - 34: o0oOOo0O0Ooo / IiII . OoooooooOO . Oo0Ooo / ooOoO0o + O0
 if 38 - 38: I11i
 if 66 - 66: II111iiii
 if 57 - 57: OoO0O00 / Oo0Ooo % I1IiiI * I1ii11iIi11i
 if 68 - 68: iII111i - o0oOOo0O0Ooo - OoO0O00 . O0 - i11iIiiIii
 if 2 - 2: I1ii11iIi11i * i1IIi
 if 17 - 17: I1ii11iIi11i * Ii1I % Oo0Ooo * I1Ii111 + OoO0O00 . OoooooooOO
 if 60 - 60: Ii1I . II111iiii
 if 36 - 36: IiII . iII111i * O0 . i1IIi * O0 * I1Ii111
 if 50 - 50: OoooooooOO + o0oOOo0O0Ooo + iIii1I11I1II1 + OOooOOo
 I111iIi11Ii11III = [ ]
 for iIIiIiiI in registered_rloc_set :
  if ( iIIiIiiI . rloc . is_private_address ( ) ) : I111iIi11Ii11III . append ( iIIiIiiI )
  if 90 - 90: Ii1I * I11i % I1Ii111 - I1ii11iIi11i * I1Ii111 % OoO0O00
 I111iIi11Ii11III += oOOoOo
 return ( I111iIi11Ii11III )
 if 50 - 50: iIii1I11I1II1
 if 56 - 56: oO0o
 if 55 - 55: iIii1I11I1II1 % oO0o % OOooOOo / I1Ii111 * OoooooooOO / Oo0Ooo
 if 88 - 88: I11i + OoO0O00 . iIii1I11I1II1 . II111iiii
 if 67 - 67: OOooOOo - ooOoO0o % iII111i % IiII
 if 71 - 71: OoO0O00 - ooOoO0o - I1IiiI + O0
 if 15 - 15: i1IIi
 if 43 - 43: II111iiii + OOooOOo . i11iIiiIii - II111iiii
 if 80 - 80: o0oOOo0O0Ooo . oO0o . I1Ii111
 if 26 - 26: i1IIi - I1IiiI + IiII / OoO0O00 . I1ii11iIi11i
def lisp_store_pubsub_state ( reply_eid , itr_rloc , mr_sport , nonce , ttl , xtr_id ) :
 O0o00OOOO0O = lisp_pubsub ( itr_rloc , mr_sport , nonce , ttl , xtr_id )
 O0o00OOOO0O . add ( reply_eid )
 return
 if 92 - 92: OoOoOO00 - ooOoO0o . O0
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
 if 15 - 15: OoooooooOO / iII111i
 if 40 - 40: o0oOOo0O0Ooo
 if 75 - 75: oO0o - OoOoOO00 * ooOoO0o . O0
 if 78 - 78: Oo0Ooo
def lisp_convert_reply_to_notify ( packet ) :
 if 74 - 74: O0 / I11i
 if 52 - 52: I1IiiI + oO0o * II111iiii
 if 15 - 15: I11i
 if 72 - 72: O0
 Ii111Iii11Ii11i1 = struct . unpack ( "I" , packet [ 0 : 4 ] ) [ 0 ]
 Ii111Iii11Ii11i1 = socket . ntohl ( Ii111Iii11Ii11i1 ) & 0xff
 o0oo000 = packet [ 4 : 12 ]
 packet = packet [ 12 : : ]
 if 47 - 47: o0oOOo0O0Ooo - I1IiiI % O0 % I1Ii111 . O0 . OoOoOO00
 if 95 - 95: o0oOOo0O0Ooo * OOooOOo - iII111i * OoooooooOO - ooOoO0o / I1IiiI
 if 47 - 47: OoO0O00 % I1IiiI / OoOoOO00 - I1Ii111 / I1IiiI
 if 13 - 13: o0oOOo0O0Ooo % ooOoO0o
 ooOOOo0 = ( LISP_MAP_NOTIFY << 28 ) | Ii111Iii11Ii11i1
 III1Iiii1i11 = struct . pack ( "I" , socket . htonl ( ooOOOo0 ) )
 IiIiiI1ii111 = struct . pack ( "I" , 0 )
 if 15 - 15: iII111i * I1IiiI . iIii1I11I1II1 % I1IiiI / O0
 if 47 - 47: OoooooooOO - i11iIiiIii . I1IiiI / i1IIi
 if 74 - 74: OoooooooOO * ooOoO0o
 if 45 - 45: Oo0Ooo + iIii1I11I1II1 . o0oOOo0O0Ooo
 packet = III1Iiii1i11 + o0oo000 + IiIiiI1ii111 + packet
 return ( packet )
 if 50 - 50: o0oOOo0O0Ooo % O0
 if 67 - 67: OoOoOO00
 if 21 - 21: I11i % Oo0Ooo + Oo0Ooo / iIii1I11I1II1 % iIii1I11I1II1
 if 66 - 66: iII111i
 if 72 - 72: ooOoO0o / oO0o / iII111i . I1Ii111 . I1ii11iIi11i + IiII
 if 39 - 39: I1IiiI % I1Ii111
 if 22 - 22: OoOoOO00 - OOooOOo % i1IIi + i1IIi
 if 28 - 28: oO0o + OoOoOO00 * Ii1I . I11i
def lisp_notify_subscribers ( lisp_sockets , eid_record , eid , site ) :
 oo0ooooO = eid . print_prefix ( )
 if ( lisp_pubsub_cache . has_key ( oo0ooooO ) == False ) : return
 if 80 - 80: I1ii11iIi11i / OoOoOO00
 for O0o00OOOO0O in lisp_pubsub_cache [ oo0ooooO ] . values ( ) :
  IiI1IIii = O0o00OOOO0O . itr
  i1O0OO = O0o00OOOO0O . port
  OOOoOO = red ( IiI1IIii . print_address_no_iid ( ) , False )
  o000oO = bold ( "subscriber" , False )
  IIIiIIi111 = "0x" + lisp_hex_string ( O0o00OOOO0O . xtr_id )
  o0oo000 = "0x" + lisp_hex_string ( O0o00OOOO0O . nonce )
  if 60 - 60: OoOoOO00 / i1IIi * iIii1I11I1II1
  lprint ( "    Notify {} {}:{} xtr-id {} for {}, nonce {}" . format ( o000oO , OOOoOO , i1O0OO , IIIiIIi111 , green ( oo0ooooO , False ) , o0oo000 ) )
  if 91 - 91: I1Ii111 . OoooooooOO / IiII / I1IiiI
  if 56 - 56: II111iiii + iIii1I11I1II1 / I1Ii111 / I1Ii111 % Oo0Ooo / OoOoOO00
  lisp_build_map_notify ( lisp_sockets , eid_record , [ oo0ooooO ] , 1 , IiI1IIii ,
 i1O0OO , O0o00OOOO0O . nonce , 0 , 0 , 0 , site , False )
  O0o00OOOO0O . map_notify_count += 1
  if 46 - 46: i11iIiiIii + OoO0O00 . ooOoO0o + OoO0O00 % i11iIiiIii
 return
 if 97 - 97: OoooooooOO % IiII * iIii1I11I1II1
 if 97 - 97: iIii1I11I1II1 - I1Ii111 - o0oOOo0O0Ooo * o0oOOo0O0Ooo * OoOoOO00
 if 80 - 80: II111iiii . I1ii11iIi11i % i11iIiiIii / Ii1I / oO0o
 if 100 - 100: Ii1I . OoO0O00 * ooOoO0o
 if 4 - 4: i1IIi + OoooooooOO
 if 26 - 26: I1IiiI / II111iiii % I1ii11iIi11i * o0oOOo0O0Ooo . IiII / OoO0O00
 if 10 - 10: i11iIiiIii / i1IIi + O0 - i11iIiiIii % I11i - i1IIi
def lisp_process_pubsub ( lisp_sockets , packet , reply_eid , itr_rloc , port , nonce ,
 ttl , xtr_id ) :
 if 38 - 38: O0 - I1IiiI + Oo0Ooo + ooOoO0o
 if 56 - 56: I1Ii111 + oO0o / Ii1I + I1Ii111
 if 21 - 21: OOooOOo / OoOoOO00 + OoOoOO00 + OoOoOO00 - i1IIi + Ii1I
 if 43 - 43: O0 % II111iiii
 lisp_store_pubsub_state ( reply_eid , itr_rloc , port , nonce , ttl , xtr_id )
 if 60 - 60: iII111i / ooOoO0o - Ii1I - OoooooooOO
 Ooo0 = green ( reply_eid . print_prefix ( ) , False )
 IiI1IIii = red ( itr_rloc . print_address_no_iid ( ) , False )
 OOo0 = bold ( "Map-Notify" , False )
 xtr_id = "0x" + lisp_hex_string ( xtr_id )
 lprint ( "{} pubsub request for {} to ack ITR {} xtr-id: {}" . format ( OOo0 ,
 Ooo0 , IiI1IIii , xtr_id ) )
 if 85 - 85: IiII
 if 4 - 4: i1IIi
 if 11 - 11: I1IiiI * OoooooooOO
 if 20 - 20: OoooooooOO + ooOoO0o . O0 - o0oOOo0O0Ooo * iII111i + Oo0Ooo
 packet = lisp_convert_reply_to_notify ( packet )
 lisp_send_map_notify ( lisp_sockets , packet , itr_rloc , port )
 return
 if 82 - 82: I11i % iII111i . OOooOOo * O0 - ooOoO0o
 if 49 - 49: Oo0Ooo * I1ii11iIi11i - i1IIi + OoOoOO00
 if 98 - 98: i11iIiiIii + OoooooooOO / I1IiiI / OOooOOo
 if 6 - 6: I1ii11iIi11i + IiII * oO0o * OoOoOO00
 if 67 - 67: I1Ii111 + OoooooooOO + OoOoOO00 % iIii1I11I1II1 . I1IiiI
 if 68 - 68: ooOoO0o
 if 68 - 68: I11i % IiII
 if 1 - 1: I1IiiI + OOooOOo - OOooOOo * O0 + o0oOOo0O0Ooo * OOooOOo
def lisp_ms_process_map_request ( lisp_sockets , packet , map_request , mr_source ,
 mr_sport , ecm_source ) :
 if 48 - 48: ooOoO0o - iII111i + I1ii11iIi11i * I1Ii111 % ooOoO0o * OoO0O00
 if 28 - 28: i1IIi / iII111i + OOooOOo
 if 89 - 89: Oo0Ooo + II111iiii * OoO0O00 + Oo0Ooo % II111iiii
 if 59 - 59: O0 + Oo0Ooo
 if 63 - 63: OoO0O00 / I1IiiI / oO0o . Ii1I / i1IIi
 if 50 - 50: I11i . I11i % I1IiiI - i1IIi
 Ooo0 = map_request . target_eid
 ooOoO00 = map_request . target_group
 oo0ooooO = lisp_print_eid_tuple ( Ooo0 , ooOoO00 )
 i1II = map_request . itr_rlocs [ 0 ]
 IIIiIIi111 = map_request . xtr_id
 o0oo000 = map_request . nonce
 Ooo0oOo0o0oOo = LISP_NO_ACTION
 O0o00OOOO0O = map_request . subscribe_bit
 if 63 - 63: OoO0O00 . iII111i
 if 28 - 28: ooOoO0o . Oo0Ooo - OoooooooOO - I1Ii111 - OoooooooOO - oO0o
 if 25 - 25: I11i / I1Ii111 . i11iIiiIii % i1IIi
 if 21 - 21: O0 * IiII . iII111i / iII111i % i11iIiiIii / I11i
 if 15 - 15: o0oOOo0O0Ooo / OoO0O00 - i1IIi
 iI111 = True
 iio0OOoO0 = ( lisp_get_eid_hash ( Ooo0 ) != None )
 if ( iio0OOoO0 ) :
  i1iiIIII = map_request . map_request_signature
  if ( i1iiIIII == None ) :
   iI111 = False
   lprint ( ( "EID-crypto-hash signature verification {}, " + "no signature found" ) . format ( bold ( "failed" , False ) ) )
   if 71 - 71: iII111i / O0 . OoOoOO00 / iII111i . iIii1I11I1II1
  else :
   I1II = map_request . signature_eid
   o0o0OO , i1Ii , iI111 = lisp_lookup_public_key ( I1II )
   if ( iI111 ) :
    iI111 = map_request . verify_map_request_sig ( i1Ii )
   else :
    lprint ( "Public-key lookup failed for sig-eid {}, hash-eid {}" . format ( I1II . print_address ( ) , o0o0OO . print_address ( ) ) )
    if 22 - 22: Oo0Ooo * I11i
    if 48 - 48: i11iIiiIii * I1IiiI % oO0o % OoooooooOO
   IIooo000ooo0O = bold ( "passed" , False ) if iI111 else bold ( "failed" , False )
   lprint ( "EID-crypto-hash signature verification {}" . format ( IIooo000ooo0O ) )
   if 10 - 10: OoooooooOO . OoOoOO00
   if 37 - 37: II111iiii - OOooOOo % I1Ii111 * i1IIi
   if 42 - 42: I1Ii111 . ooOoO0o - O0 + i11iIiiIii
 if ( O0o00OOOO0O and iI111 == False ) :
  O0o00OOOO0O = False
  lprint ( "Suppress creating pubsub state due to signature failure" )
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
  if 81 - 81: OOooOOo % OoooooooOO / IiII . Oo0Ooo - ooOoO0o . I1IiiI
  if 3 - 3: O0
  if 95 - 95: i11iIiiIii
 Oo0o00oo00OO0 = i1II if ( i1II . afi == ecm_source . afi ) else ecm_source
 if 22 - 22: iII111i + IiII - o0oOOo0O0Ooo - I11i
 IiIi1II1i = lisp_site_eid_lookup ( Ooo0 , ooOoO00 , False )
 if 52 - 52: I1Ii111
 if ( IiIi1II1i == None or IiIi1II1i . is_star_g ( ) ) :
  OoO0OOOOO0OO = bold ( "Site not found" , False )
  lprint ( "{} for requested EID {}" . format ( OoO0OOOOO0OO ,
 green ( oo0ooooO , False ) ) )
  if 5 - 5: o0oOOo0O0Ooo
  if 58 - 58: oO0o * II111iiii * Oo0Ooo - I1IiiI % iII111i
  if 77 - 77: I11i / iII111i * o0oOOo0O0Ooo % iIii1I11I1II1
  if 26 - 26: i1IIi / OoO0O00 / IiII
  lisp_send_negative_map_reply ( lisp_sockets , Ooo0 , ooOoO00 , o0oo000 , i1II ,
 mr_sport , 15 , IIIiIIi111 , O0o00OOOO0O )
  if 60 - 60: oO0o % I1Ii111 % Oo0Ooo
  return ( [ Ooo0 , ooOoO00 , LISP_DDT_ACTION_SITE_NOT_FOUND ] )
  if 34 - 34: o0oOOo0O0Ooo * OOooOOo % Ii1I + I1IiiI
  if 77 - 77: OoOoOO00 + IiII + Oo0Ooo
 I1IIIIII = IiIi1II1i . print_eid_tuple ( )
 oO00 = IiIi1II1i . site . site_name
 if 82 - 82: oO0o - i11iIiiIii
 if 7 - 7: Oo0Ooo / ooOoO0o
 if 55 - 55: OoO0O00 % IiII
 if 93 - 93: OoO0O00 . I1ii11iIi11i / OOooOOo % OoooooooOO + i1IIi + I1Ii111
 if 94 - 94: II111iiii + i11iIiiIii % Ii1I / ooOoO0o * OoOoOO00
 if ( iio0OOoO0 == False and IiIi1II1i . require_signature ) :
  i1iiIIII = map_request . map_request_signature
  I1II = map_request . signature_eid
  if ( i1iiIIII == None or I1II . is_null ( ) ) :
   lprint ( "Signature required for site {}" . format ( oO00 ) )
   iI111 = False
  else :
   I1II = map_request . signature_eid
   o0o0OO , i1Ii , iI111 = lisp_lookup_public_key ( I1II )
   if ( iI111 ) :
    iI111 = map_request . verify_map_request_sig ( i1Ii )
   else :
    lprint ( "Public-key lookup failed for sig-eid {}, hash-eid {}" . format ( I1II . print_address ( ) , o0o0OO . print_address ( ) ) )
    if 68 - 68: O0 / Oo0Ooo / iIii1I11I1II1
    if 63 - 63: I1Ii111 + iII111i
   IIooo000ooo0O = bold ( "passed" , False ) if iI111 else bold ( "failed" , False )
   lprint ( "Required signature verification {}" . format ( IIooo000ooo0O ) )
   if 6 - 6: I1ii11iIi11i + Ii1I
   if 36 - 36: iII111i + iII111i * OoO0O00 * I1ii11iIi11i
   if 97 - 97: ooOoO0o + OOooOOo
   if 70 - 70: o0oOOo0O0Ooo + Ii1I - i11iIiiIii + I11i * o0oOOo0O0Ooo . Ii1I
   if 6 - 6: Oo0Ooo + I1IiiI
   if 48 - 48: oO0o . I1ii11iIi11i
 if ( iI111 and IiIi1II1i . registered == False ) :
  lprint ( "Site '{}' with EID-prefix {} is not registered for EID {}" . format ( oO00 , green ( I1IIIIII , False ) , green ( oo0ooooO , False ) ) )
  if 59 - 59: IiII - Ii1I
  if 62 - 62: OOooOOo * o0oOOo0O0Ooo + IiII * o0oOOo0O0Ooo * i11iIiiIii - O0
  if 37 - 37: I1ii11iIi11i - Oo0Ooo . i11iIiiIii / i11iIiiIii + oO0o
  if 19 - 19: i1IIi / i1IIi - OoooooooOO - OOooOOo . i1IIi
  if 57 - 57: OOooOOo / I1ii11iIi11i * oO0o
  if 53 - 53: o0oOOo0O0Ooo * Ii1I
  if ( IiIi1II1i . accept_more_specifics == False ) :
   Ooo0 = IiIi1II1i . eid
   ooOoO00 = IiIi1II1i . group
   if 42 - 42: I11i + iII111i / iIii1I11I1II1
   if 1 - 1: O0 - II111iiii
   if 75 - 75: II111iiii / OoO0O00 % II111iiii
   if 3 - 3: Ii1I - Ii1I % I1ii11iIi11i
   if 44 - 44: OOooOOo - o0oOOo0O0Ooo
  ooOOooooo0Oo = 1
  if ( IiIi1II1i . force_ttl != None ) :
   ooOOooooo0Oo = IiIi1II1i . force_ttl | 0x80000000
   if 69 - 69: IiII + I1ii11iIi11i / o0oOOo0O0Ooo / OOooOOo
   if 31 - 31: oO0o + I1ii11iIi11i * i1IIi % I1IiiI % I1IiiI + iIii1I11I1II1
   if 62 - 62: OoooooooOO
   if 38 - 38: iII111i % iII111i * ooOoO0o / OoO0O00 + ooOoO0o
   if 52 - 52: ooOoO0o . iIii1I11I1II1 / iIii1I11I1II1 % oO0o - oO0o * II111iiii
  lisp_send_negative_map_reply ( lisp_sockets , Ooo0 , ooOoO00 , o0oo000 , i1II ,
 mr_sport , ooOOooooo0Oo , IIIiIIi111 , O0o00OOOO0O )
  if 57 - 57: I1Ii111
  return ( [ Ooo0 , ooOoO00 , LISP_DDT_ACTION_MS_NOT_REG ] )
  if 23 - 23: I1ii11iIi11i + II111iiii
  if 99 - 99: o0oOOo0O0Ooo . I1IiiI + o0oOOo0O0Ooo * o0oOOo0O0Ooo / O0
  if 27 - 27: OOooOOo - I1Ii111
  if 33 - 33: OOooOOo - Ii1I - iII111i + I1ii11iIi11i - i11iIiiIii
  if 89 - 89: iIii1I11I1II1 * I11i + OOooOOo
 iiIiIIi1I = False
 Ooo0ooOooOo = ""
 ooOOoo0Oooooo = False
 if ( IiIi1II1i . force_nat_proxy_reply ) :
  Ooo0ooOooOo = ", nat-forced"
  iiIiIIi1I = True
  ooOOoo0Oooooo = True
 elif ( IiIi1II1i . force_proxy_reply ) :
  Ooo0ooOooOo = ", forced"
  ooOOoo0Oooooo = True
 elif ( IiIi1II1i . proxy_reply_requested ) :
  Ooo0ooOooOo = ", requested"
  ooOOoo0Oooooo = True
 elif ( map_request . pitr_bit and IiIi1II1i . pitr_proxy_reply_drop ) :
  Ooo0ooOooOo = ", drop-to-pitr"
  Ooo0oOo0o0oOo = LISP_DROP_ACTION
 elif ( IiIi1II1i . proxy_reply_action != "" ) :
  Ooo0oOo0o0oOo = IiIi1II1i . proxy_reply_action
  Ooo0ooOooOo = ", forced, action {}" . format ( Ooo0oOo0o0oOo )
  Ooo0oOo0o0oOo = LISP_DROP_ACTION if ( Ooo0oOo0o0oOo == "drop" ) else LISP_NATIVE_FORWARD_ACTION
  if 19 - 19: OoOoOO00 * I11i + IiII / OOooOOo
  if 70 - 70: II111iiii
  if 21 - 21: i11iIiiIii . iII111i * O0 - iII111i
  if 5 - 5: O0 . OoOoOO00 / iII111i
  if 78 - 78: Ii1I - I1ii11iIi11i + iIii1I11I1II1 + OoooooooOO . OoO0O00 - ooOoO0o
  if 81 - 81: o0oOOo0O0Ooo * OoooooooOO
  if 32 - 32: OoOoOO00 - I11i * i11iIiiIii . I1ii11iIi11i . IiII . iIii1I11I1II1
 I1iIi = False
 Iii = None
 if ( ooOOoo0Oooooo and lisp_policies . has_key ( IiIi1II1i . policy ) ) :
  oo000o = lisp_policies [ IiIi1II1i . policy ]
  if ( oo000o . match_policy_map_request ( map_request , mr_source ) ) : Iii = oo000o
  if 13 - 13: OoooooooOO % OoO0O00
  if ( Iii ) :
   oOoOOOO0OOO = bold ( "matched" , False )
   lprint ( "Map-Request {} policy '{}', set-action '{}'" . format ( oOoOOOO0OOO ,
 oo000o . policy_name , oo000o . set_action ) )
  else :
   oOoOOOO0OOO = bold ( "no match" , False )
   lprint ( "Map-Request {} for policy '{}', implied drop" . format ( oOoOOOO0OOO ,
 oo000o . policy_name ) )
   I1iIi = True
   if 36 - 36: i1IIi / OoO0O00 . o0oOOo0O0Ooo + iIii1I11I1II1 + I1IiiI + iIii1I11I1II1
   if 46 - 46: O0
   if 25 - 25: O0 + I1IiiI + IiII . Oo0Ooo
 if ( Ooo0ooOooOo != "" ) :
  lprint ( "Proxy-replying for EID {}, found site '{}' EID-prefix {}{}" . format ( green ( oo0ooooO , False ) , oO00 , green ( I1IIIIII , False ) ,
  # OOooOOo * OoOoOO00 + i11iIiiIii + O0 + O0
 Ooo0ooOooOo ) )
  if 18 - 18: Oo0Ooo . I1ii11iIi11i * ooOoO0o % Ii1I + I1ii11iIi11i
  I111iIi11Ii11III = IiIi1II1i . registered_rlocs
  ooOOooooo0Oo = 1440
  if ( iiIiIIi1I ) :
   if ( IiIi1II1i . site_id != 0 ) :
    IIII = map_request . source_eid
    I111iIi11Ii11III = lisp_get_private_rloc_set ( IiIi1II1i , IIII , ooOoO00 )
    if 74 - 74: IiII * OoOoOO00 + OoO0O00 . iIii1I11I1II1 / iIii1I11I1II1
   if ( I111iIi11Ii11III == IiIi1II1i . registered_rlocs ) :
    oOo00 = ( IiIi1II1i . group . is_null ( ) == False )
    O000OOo0o0o0 = lisp_get_partial_rloc_set ( I111iIi11Ii11III , Oo0o00oo00OO0 , oOo00 )
    if ( O000OOo0o0o0 != I111iIi11Ii11III ) :
     ooOOooooo0Oo = 15
     I111iIi11Ii11III = O000OOo0o0o0
     if 63 - 63: I1ii11iIi11i % i11iIiiIii . Ii1I . I1IiiI * I1IiiI
     if 51 - 51: oO0o . Oo0Ooo / i1IIi + i1IIi * i1IIi
     if 32 - 32: I1IiiI + IiII + iII111i . iIii1I11I1II1 * Ii1I
     if 27 - 27: oO0o + Ii1I . i11iIiiIii
     if 97 - 97: iII111i . I1IiiI
     if 71 - 71: OOooOOo - IiII % oO0o * I1ii11iIi11i
     if 48 - 48: o0oOOo0O0Ooo * iIii1I11I1II1 + Oo0Ooo
     if 45 - 45: oO0o
  if ( IiIi1II1i . force_ttl != None ) :
   ooOOooooo0Oo = IiIi1II1i . force_ttl | 0x80000000
   if 50 - 50: Ii1I * Ii1I / O0 . Oo0Ooo + iII111i
   if 9 - 9: OoooooooOO % O0 % I1ii11iIi11i
   if 100 - 100: i11iIiiIii - iII111i - I11i
   if 5 - 5: oO0o % IiII * iII111i
   if 98 - 98: iII111i / OOooOOo + IiII
   if 100 - 100: II111iiii . i11iIiiIii / oO0o - OOooOOo + OoOoOO00 % I1ii11iIi11i
  if ( Iii ) :
   if ( Iii . set_record_ttl ) :
    ooOOooooo0Oo = Iii . set_record_ttl
    lprint ( "Policy set-record-ttl to {}" . format ( ooOOooooo0Oo ) )
    if 82 - 82: ooOoO0o % OOooOOo % Ii1I
   if ( Iii . set_action == "drop" ) :
    lprint ( "Policy set-action drop, send negative Map-Reply" )
    Ooo0oOo0o0oOo = LISP_POLICY_DENIED_ACTION
    I111iIi11Ii11III = [ ]
   else :
    oOoOoo0O = Iii . set_policy_map_reply ( )
    if ( oOoOoo0O ) : I111iIi11Ii11III = [ oOoOoo0O ]
    if 82 - 82: I1ii11iIi11i
    if 52 - 52: i11iIiiIii % I1Ii111 - iII111i / O0 - I1ii11iIi11i / iII111i
    if 7 - 7: OoooooooOO . OOooOOo . OOooOOo
  if ( I1iIi ) :
   lprint ( "Implied drop action, send negative Map-Reply" )
   Ooo0oOo0o0oOo = LISP_POLICY_DENIED_ACTION
   I111iIi11Ii11III = [ ]
   if 53 - 53: OOooOOo * OoOoOO00 % iII111i
   if 86 - 86: OOooOOo . OOooOOo + IiII - I1ii11iIi11i . OoO0O00
  II1ii11I1iIiI1 = IiIi1II1i . echo_nonce_capable
  if 66 - 66: I1IiiI * OoOoOO00 . I1IiiI / Oo0Ooo - Ii1I
  if 69 - 69: iIii1I11I1II1 % iII111i + ooOoO0o * i1IIi + iII111i * I1Ii111
  if 67 - 67: Ii1I % Oo0Ooo - Oo0Ooo . I11i + IiII
  if 73 - 73: Oo0Ooo + iIii1I11I1II1 . iIii1I11I1II1
  if ( iI111 ) :
   o0OOO00 = IiIi1II1i . eid
   OoOOOO0oo = IiIi1II1i . group
  else :
   o0OOO00 = Ooo0
   OoOOOO0oo = ooOoO00
   Ooo0oOo0o0oOo = LISP_AUTH_FAILURE_ACTION
   I111iIi11Ii11III = [ ]
   if 4 - 4: i1IIi
   if 70 - 70: I1ii11iIi11i + iII111i . O0 . I1ii11iIi11i + Oo0Ooo / OOooOOo
   if 22 - 22: Ii1I
   if 48 - 48: Oo0Ooo / iIii1I11I1II1
   if 80 - 80: i1IIi + I1IiiI / OoooooooOO + OOooOOo . Ii1I
   if 96 - 96: iIii1I11I1II1 - I1ii11iIi11i
  packet = lisp_build_map_reply ( o0OOO00 , OoOOOO0oo , I111iIi11Ii11III ,
 o0oo000 , Ooo0oOo0o0oOo , ooOOooooo0Oo , False , None , II1ii11I1iIiI1 , False )
  if 41 - 41: II111iiii - OoOoOO00 + OoooooooOO - I1ii11iIi11i . oO0o . o0oOOo0O0Ooo
  if ( O0o00OOOO0O ) :
   lisp_process_pubsub ( lisp_sockets , packet , o0OOO00 , i1II ,
 mr_sport , o0oo000 , ooOOooooo0Oo , IIIiIIi111 )
  else :
   lisp_send_map_reply ( lisp_sockets , packet , i1II , mr_sport )
   if 34 - 34: I1ii11iIi11i % I11i / Oo0Ooo * oO0o % ooOoO0o / OOooOOo
   if 50 - 50: O0 * O0 / iIii1I11I1II1
  return ( [ IiIi1II1i . eid , IiIi1II1i . group , LISP_DDT_ACTION_MS_ACK ] )
  if 31 - 31: I1IiiI / o0oOOo0O0Ooo
  if 70 - 70: I1IiiI
  if 36 - 36: ooOoO0o . oO0o . I11i - I1ii11iIi11i / OoOoOO00 * Oo0Ooo
  if 42 - 42: OoooooooOO / o0oOOo0O0Ooo . Ii1I * iII111i * I1IiiI - Oo0Ooo
  if 76 - 76: oO0o * II111iiii
 o0Oo0Oooo0ooO = len ( IiIi1II1i . registered_rlocs )
 if ( o0Oo0Oooo0ooO == 0 ) :
  lprint ( "Requested EID {} found site '{}' with EID-prefix {} with " + "no registered RLOCs" . format ( green ( oo0ooooO , False ) , oO00 ,
  # I11i . iIii1I11I1II1 . I11i + oO0o + I1IiiI
 green ( I1IIIIII , False ) ) )
  return ( [ IiIi1II1i . eid , IiIi1II1i . group , LISP_DDT_ACTION_MS_ACK ] )
  if 85 - 85: I1Ii111
  if 1 - 1: o0oOOo0O0Ooo % oO0o * I1Ii111 - i1IIi - iII111i . oO0o
  if 25 - 25: i1IIi * o0oOOo0O0Ooo / oO0o
  if 11 - 11: IiII + II111iiii
  if 37 - 37: O0
 o0oo0OoOo000 = map_request . target_eid if map_request . source_eid . is_null ( ) else map_request . source_eid
 if 35 - 35: I11i + OoooooooOO
 OoOoo00Oo0OoO = map_request . target_eid . hash_address ( o0oo0OoOo000 )
 OoOoo00Oo0OoO %= o0Oo0Oooo0ooO
 O0iiI11111i = IiIi1II1i . registered_rlocs [ OoOoo00Oo0OoO ]
 if 69 - 69: O0 . I1Ii111 % ooOoO0o - I1ii11iIi11i . Ii1I
 if ( O0iiI11111i . rloc . is_null ( ) ) :
  lprint ( ( "Suppress forwarding Map-Request for EID {} at site '{}' " + "EID-prefix {}, no RLOC address" ) . format ( green ( oo0ooooO , False ) ,
  # OoooooooOO
 oO00 , green ( I1IIIIII , False ) ) )
 else :
  lprint ( ( "Forwarding Map-Request for EID {} to ETR {} at site '{}' " + "EID-prefix {}" ) . format ( green ( oo0ooooO , False ) ,
  # II111iiii
 red ( O0iiI11111i . rloc . print_address ( ) , False ) , oO00 ,
 green ( I1IIIIII , False ) ) )
  if 77 - 77: OoooooooOO
  if 92 - 92: oO0o
  if 49 - 49: i11iIiiIii + OoO0O00 - OOooOOo
  if 9 - 9: II111iiii * OOooOOo / Oo0Ooo + iIii1I11I1II1 % I1IiiI
  lisp_send_ecm ( lisp_sockets , packet , map_request . source_eid , mr_sport ,
 map_request . target_eid , O0iiI11111i . rloc , to_etr = True )
  if 95 - 95: I1Ii111 . IiII % OoO0O00 - OOooOOo - I11i
 return ( [ IiIi1II1i . eid , IiIi1II1i . group , LISP_DDT_ACTION_MS_ACK ] )
 if 55 - 55: OoooooooOO % I1ii11iIi11i % iII111i / IiII
 if 65 - 65: II111iiii
 if 58 - 58: iIii1I11I1II1 / i11iIiiIii . iII111i . OOooOOo * I1ii11iIi11i + OoooooooOO
 if 13 - 13: OoooooooOO + iII111i * i11iIiiIii % IiII + oO0o . o0oOOo0O0Ooo
 if 31 - 31: o0oOOo0O0Ooo - ooOoO0o
 if 40 - 40: O0 / OoOoOO00 - I1Ii111
 if 60 - 60: IiII + I1IiiI
def lisp_ddt_process_map_request ( lisp_sockets , map_request , ecm_source , port ) :
 if 61 - 61: OoO0O00
 if 96 - 96: ooOoO0o - OoooooooOO * iIii1I11I1II1 . IiII - O0
 if 7 - 7: iIii1I11I1II1 . OoO0O00
 if 88 - 88: i1IIi * II111iiii / i11iIiiIii % IiII . IiII
 Ooo0 = map_request . target_eid
 ooOoO00 = map_request . target_group
 oo0ooooO = lisp_print_eid_tuple ( Ooo0 , ooOoO00 )
 o0oo000 = map_request . nonce
 Ooo0oOo0o0oOo = LISP_DDT_ACTION_NULL
 if 93 - 93: OoOoOO00 * i1IIi . Ii1I
 if 2 - 2: i1IIi
 if 84 - 84: i1IIi / Ii1I + OoOoOO00 % Ii1I . oO0o
 if 74 - 74: OOooOOo - o0oOOo0O0Ooo - I1Ii111 - OoO0O00
 if 40 - 40: o0oOOo0O0Ooo . IiII * OoOoOO00
 iii1i111I = None
 if ( lisp_i_am_ms ) :
  IiIi1II1i = lisp_site_eid_lookup ( Ooo0 , ooOoO00 , False )
  if ( IiIi1II1i == None ) : return
  if 8 - 8: Ii1I % OoOoOO00 % II111iiii * ooOoO0o + I1IiiI
  if ( IiIi1II1i . registered ) :
   Ooo0oOo0o0oOo = LISP_DDT_ACTION_MS_ACK
   ooOOooooo0Oo = 1440
  else :
   Ooo0 , ooOoO00 , Ooo0oOo0o0oOo = lisp_ms_compute_neg_prefix ( Ooo0 , ooOoO00 )
   Ooo0oOo0o0oOo = LISP_DDT_ACTION_MS_NOT_REG
   ooOOooooo0Oo = 1
   if 19 - 19: OoO0O00 * ooOoO0o % I1ii11iIi11i
 else :
  iii1i111I = lisp_ddt_cache_lookup ( Ooo0 , ooOoO00 , False )
  if ( iii1i111I == None ) :
   Ooo0oOo0o0oOo = LISP_DDT_ACTION_NOT_AUTH
   ooOOooooo0Oo = 0
   lprint ( "DDT delegation entry not found for EID {}" . format ( green ( oo0ooooO , False ) ) )
   if 21 - 21: OoO0O00 * I11i
  elif ( iii1i111I . is_auth_prefix ( ) ) :
   if 76 - 76: I1IiiI - I1ii11iIi11i / I1ii11iIi11i . o0oOOo0O0Ooo % OoooooooOO
   if 39 - 39: OoooooooOO % iII111i
   if 55 - 55: IiII . i11iIiiIii % OoooooooOO
   if 88 - 88: Ii1I * o0oOOo0O0Ooo / oO0o
   Ooo0oOo0o0oOo = LISP_DDT_ACTION_DELEGATION_HOLE
   ooOOooooo0Oo = 15
   oOoo = iii1i111I . print_eid_tuple ( )
   lprint ( ( "DDT delegation entry not found but auth-prefix {} " + "found for EID {}" ) . format ( oOoo ,
   # I11i % I1IiiI
 green ( oo0ooooO , False ) ) )
   if 82 - 82: i11iIiiIii * i11iIiiIii + I1Ii111 - I1ii11iIi11i * oO0o - Ii1I
   if ( ooOoO00 . is_null ( ) ) :
    Ooo0 = lisp_ddt_compute_neg_prefix ( Ooo0 , iii1i111I ,
 lisp_ddt_cache )
   else :
    ooOoO00 = lisp_ddt_compute_neg_prefix ( ooOoO00 , iii1i111I ,
 lisp_ddt_cache )
    Ooo0 = lisp_ddt_compute_neg_prefix ( Ooo0 , iii1i111I ,
 iii1i111I . source_cache )
    if 40 - 40: o0oOOo0O0Ooo + OoO0O00 % i1IIi % iII111i * I1Ii111
   iii1i111I = None
  else :
   oOoo = iii1i111I . print_eid_tuple ( )
   lprint ( "DDT delegation entry {} found for EID {}" . format ( oOoo , green ( oo0ooooO , False ) ) )
   if 36 - 36: I1ii11iIi11i % II111iiii % I1Ii111 / I1ii11iIi11i
   ooOOooooo0Oo = 1440
   if 34 - 34: OoooooooOO * i11iIiiIii
   if 33 - 33: II111iiii
   if 59 - 59: iIii1I11I1II1 % I11i
   if 93 - 93: I1ii11iIi11i
   if 50 - 50: ooOoO0o % OoO0O00 % OoO0O00
   if 36 - 36: I1IiiI * O0 . IiII / I1Ii111
 I1IiO00Ooo0ooo0 = lisp_build_map_referral ( Ooo0 , ooOoO00 , iii1i111I , Ooo0oOo0o0oOo , ooOOooooo0Oo , o0oo000 )
 o0oo000 = map_request . nonce >> 32
 if ( map_request . nonce != 0 and o0oo000 != 0xdfdf0e1d ) : port = LISP_CTRL_PORT
 lisp_send_map_referral ( lisp_sockets , I1IiO00Ooo0ooo0 , ecm_source , port )
 return
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
 if 48 - 48: OOooOOo . II111iiii * OOooOOo - I11i / iIii1I11I1II1 / i11iIiiIii
 if 37 - 37: II111iiii % O0 + iIii1I11I1II1 - I1IiiI . I11i + I1ii11iIi11i
def lisp_find_negative_mask_len ( eid , entry_prefix , neg_prefix ) :
 I11ii1I11ii = eid . hash_address ( entry_prefix )
 I1I11I111I = eid . addr_length ( ) * 8
 OoOO = 0
 if 48 - 48: O0 + OoOoOO00 - O0
 if 79 - 79: ooOoO0o . OoOoOO00 / OoooooooOO - II111iiii
 if 48 - 48: Oo0Ooo
 if 59 - 59: OoO0O00 % o0oOOo0O0Ooo
 for OoOO in range ( I1I11I111I ) :
  O0ooO0O0O00 = 1 << ( I1I11I111I - OoOO - 1 )
  if ( I11ii1I11ii & O0ooO0O0O00 ) : break
  if 5 - 5: I1IiiI % I1IiiI + OoooooooOO / I1ii11iIi11i
  if 77 - 77: OOooOOo / i11iIiiIii % iII111i * oO0o
 if ( OoOO > neg_prefix . mask_len ) : neg_prefix . mask_len = OoOO
 return
 if 77 - 77: OOooOOo + i11iIiiIii / o0oOOo0O0Ooo + iII111i
 if 90 - 90: ooOoO0o
 if 74 - 74: Oo0Ooo . OOooOOo + OOooOOo / OOooOOo + I1IiiI + i1IIi
 if 32 - 32: i11iIiiIii % Ii1I
 if 92 - 92: OoOoOO00 % o0oOOo0O0Ooo % ooOoO0o - IiII - oO0o
 if 90 - 90: ooOoO0o
 if 11 - 11: OoOoOO00 % OOooOOo . i11iIiiIii * I1IiiI % O0 % iIii1I11I1II1
 if 18 - 18: Oo0Ooo % OOooOOo + IiII
 if 28 - 28: OOooOOo . OoO0O00 / o0oOOo0O0Ooo + II111iiii / iIii1I11I1II1 * II111iiii
 if 83 - 83: II111iiii . OoOoOO00 - i11iIiiIii . OoOoOO00 . i1IIi % OoooooooOO
def lisp_neg_prefix_walk ( entry , parms ) :
 Ooo0 , ii1ii , iI11Ii1 = parms
 if 68 - 68: O0 - i1IIi % iII111i * I1ii11iIi11i + I11i
 if ( ii1ii == None ) :
  if ( entry . eid . instance_id != Ooo0 . instance_id ) :
   return ( [ True , parms ] )
   if 94 - 94: iII111i / OoOoOO00 . o0oOOo0O0Ooo / iIii1I11I1II1
  if ( entry . eid . afi != Ooo0 . afi ) : return ( [ True , parms ] )
 else :
  if ( entry . eid . is_more_specific ( ii1ii ) == False ) :
   return ( [ True , parms ] )
   if 94 - 94: OoO0O00 . ooOoO0o
   if 25 - 25: I1Ii111 % OOooOOo
   if 82 - 82: Ii1I
   if 17 - 17: iII111i . i1IIi . i1IIi
   if 76 - 76: OoooooooOO % IiII
   if 81 - 81: iII111i . OOooOOo * i1IIi
 lisp_find_negative_mask_len ( Ooo0 , entry . eid , iI11Ii1 )
 return ( [ True , parms ] )
 if 14 - 14: oO0o
 if 16 - 16: iII111i
 if 26 - 26: iII111i . oO0o * i11iIiiIii . iIii1I11I1II1
 if 74 - 74: Ii1I / iIii1I11I1II1 + OOooOOo . II111iiii
 if 65 - 65: OOooOOo * I11i * Oo0Ooo
 if 21 - 21: Ii1I . iIii1I11I1II1
 if 84 - 84: OOooOOo
 if 67 - 67: I1IiiI % OoO0O00 % o0oOOo0O0Ooo % IiII
def lisp_ddt_compute_neg_prefix ( eid , ddt_entry , cache ) :
 if 33 - 33: ooOoO0o % I1IiiI
 if 98 - 98: oO0o . o0oOOo0O0Ooo + II111iiii
 if 62 - 62: ooOoO0o - OoooooooOO / I1ii11iIi11i / iII111i - o0oOOo0O0Ooo
 if 70 - 70: oO0o % OoooooooOO * I1IiiI - OoOoOO00 * OoOoOO00 . OOooOOo
 if ( eid . is_binary ( ) == False ) : return ( eid )
 if 9 - 9: iII111i * Oo0Ooo % iII111i % Oo0Ooo * II111iiii
 iI11Ii1 = lisp_address ( eid . afi , "" , 0 , 0 )
 iI11Ii1 . copy_address ( eid )
 iI11Ii1 . mask_len = 0
 if 71 - 71: II111iiii + I1ii11iIi11i * II111iiii
 o0ooO00 = ddt_entry . print_eid_tuple ( )
 ii1ii = ddt_entry . eid
 if 40 - 40: I11i . iII111i + OoOoOO00 % I1ii11iIi11i
 if 79 - 79: I1Ii111 - OOooOOo * I1ii11iIi11i + i11iIiiIii . iII111i
 if 3 - 3: Oo0Ooo
 if 81 - 81: OoO0O00 / OoO0O00 . I1ii11iIi11i
 if 100 - 100: iIii1I11I1II1 % II111iiii - I1ii11iIi11i . iIii1I11I1II1 + IiII % iIii1I11I1II1
 eid , ii1ii , iI11Ii1 = cache . walk_cache ( lisp_neg_prefix_walk ,
 ( eid , ii1ii , iI11Ii1 ) )
 if 48 - 48: Ii1I % i1IIi
 if 38 - 38: OOooOOo / I1ii11iIi11i % oO0o / o0oOOo0O0Ooo
 if 54 - 54: OoOoOO00 * OoooooooOO - OoO0O00 * OoOoOO00 % I1ii11iIi11i * I11i
 if 34 - 34: I11i - oO0o + I11i * OoooooooOO * I11i
 iI11Ii1 . mask_address ( iI11Ii1 . mask_len )
 if 73 - 73: OOooOOo * iII111i * OoO0O00
 lprint ( ( "Least specific prefix computed from ddt-cache for EID {} " + "using auth-prefix {} is {}" ) . format ( green ( eid . print_address ( ) , False ) ,
 # i1IIi
 o0ooO00 , iI11Ii1 . print_prefix ( ) ) )
 return ( iI11Ii1 )
 if 86 - 86: i11iIiiIii / ooOoO0o / OOooOOo + Oo0Ooo . I1Ii111 + II111iiii
 if 4 - 4: II111iiii * I1IiiI * O0 + I1ii11iIi11i
 if 24 - 24: iIii1I11I1II1
 if 2 - 2: iIii1I11I1II1
 if 87 - 87: I11i
 if 17 - 17: OOooOOo - Oo0Ooo + Ii1I
 if 94 - 94: OoO0O00 * OoO0O00 * II111iiii + i1IIi / i1IIi % Ii1I
 if 82 - 82: I11i + OoO0O00 . oO0o * I1ii11iIi11i % ooOoO0o . iIii1I11I1II1
def lisp_ms_compute_neg_prefix ( eid , group ) :
 iI11Ii1 = lisp_address ( eid . afi , "" , 0 , 0 )
 iI11Ii1 . copy_address ( eid )
 iI11Ii1 . mask_len = 0
 i1iiIi1O000O0o0 = lisp_address ( group . afi , "" , 0 , 0 )
 i1iiIi1O000O0o0 . copy_address ( group )
 i1iiIi1O000O0o0 . mask_len = 0
 ii1ii = None
 if 48 - 48: i11iIiiIii
 if 19 - 19: O0 - i11iIiiIii + ooOoO0o % O0
 if 63 - 63: iII111i + iIii1I11I1II1 * OoOoOO00 . I1Ii111 / I11i * o0oOOo0O0Ooo
 if 6 - 6: OOooOOo . ooOoO0o % iII111i - o0oOOo0O0Ooo % I11i + i11iIiiIii
 if 6 - 6: i11iIiiIii
 if ( group . is_null ( ) ) :
  iii1i111I = lisp_ddt_cache . lookup_cache ( eid , False )
  if ( iii1i111I == None ) :
   iI11Ii1 . mask_len = iI11Ii1 . host_mask_len ( )
   i1iiIi1O000O0o0 . mask_len = i1iiIi1O000O0o0 . host_mask_len ( )
   return ( [ iI11Ii1 , i1iiIi1O000O0o0 , LISP_DDT_ACTION_NOT_AUTH ] )
   if 66 - 66: I1Ii111 * I1ii11iIi11i . Ii1I
  iIiIiiiiI = lisp_sites_by_eid
  if ( iii1i111I . is_auth_prefix ( ) ) : ii1ii = iii1i111I . eid
 else :
  iii1i111I = lisp_ddt_cache . lookup_cache ( group , False )
  if ( iii1i111I == None ) :
   iI11Ii1 . mask_len = iI11Ii1 . host_mask_len ( )
   i1iiIi1O000O0o0 . mask_len = i1iiIi1O000O0o0 . host_mask_len ( )
   return ( [ iI11Ii1 , i1iiIi1O000O0o0 , LISP_DDT_ACTION_NOT_AUTH ] )
   if 78 - 78: I1Ii111 % Oo0Ooo . i11iIiiIii % OoooooooOO
  if ( iii1i111I . is_auth_prefix ( ) ) : ii1ii = iii1i111I . group
  if 2 - 2: O0 - i11iIiiIii + I1Ii111 - i11iIiiIii + I11i * iIii1I11I1II1
  group , ii1ii , i1iiIi1O000O0o0 = lisp_sites_by_eid . walk_cache ( lisp_neg_prefix_walk , ( group , ii1ii , i1iiIi1O000O0o0 ) )
  if 23 - 23: OoO0O00
  if 63 - 63: o0oOOo0O0Ooo - I1IiiI % OOooOOo
  i1iiIi1O000O0o0 . mask_address ( i1iiIi1O000O0o0 . mask_len )
  if 34 - 34: I1ii11iIi11i - I1IiiI . iII111i / I1Ii111 + oO0o + OOooOOo
  lprint ( ( "Least specific prefix computed from site-cache for " + "group EID {} using auth-prefix {} is {}" ) . format ( group . print_address ( ) , ii1ii . print_prefix ( ) if ( ii1ii != None ) else "'not found'" ,
  # OoooooooOO
  # o0oOOo0O0Ooo + Ii1I . iIii1I11I1II1
  # i1IIi * I1ii11iIi11i
 i1iiIi1O000O0o0 . print_prefix ( ) ) )
  if 77 - 77: ooOoO0o . II111iiii
  iIiIiiiiI = iii1i111I . source_cache
  if 41 - 41: IiII
  if 27 - 27: IiII / IiII
  if 91 - 91: Ii1I
  if 93 - 93: OoO0O00 * OoO0O00 * I1ii11iIi11i * OoO0O00 * o0oOOo0O0Ooo
  if 84 - 84: I1Ii111 * OoO0O00 - ooOoO0o - Oo0Ooo . OoO0O00 % oO0o
 Ooo0oOo0o0oOo = LISP_DDT_ACTION_DELEGATION_HOLE if ( ii1ii != None ) else LISP_DDT_ACTION_NOT_AUTH
 if 98 - 98: OoO0O00 . i1IIi
 if 58 - 58: i1IIi * O0 + I1ii11iIi11i . IiII
 if 11 - 11: OOooOOo + iIii1I11I1II1 - ooOoO0o * OoO0O00 * i11iIiiIii
 if 45 - 45: I1ii11iIi11i + Oo0Ooo
 if 7 - 7: Oo0Ooo + ooOoO0o - I1Ii111 * iIii1I11I1II1
 if 6 - 6: ooOoO0o % I1Ii111 % ooOoO0o . Ii1I * Oo0Ooo . IiII
 eid , ii1ii , iI11Ii1 = iIiIiiiiI . walk_cache ( lisp_neg_prefix_walk ,
 ( eid , ii1ii , iI11Ii1 ) )
 if 100 - 100: i1IIi . Ii1I . o0oOOo0O0Ooo + Ii1I - i1IIi . I11i
 if 19 - 19: i11iIiiIii + I11i - IiII . iII111i * i1IIi
 if 66 - 66: ooOoO0o
 if 4 - 4: iII111i / iII111i * OOooOOo + o0oOOo0O0Ooo . I1Ii111 + II111iiii
 iI11Ii1 . mask_address ( iI11Ii1 . mask_len )
 if 90 - 90: IiII * iII111i % OoOoOO00 . i11iIiiIii
 lprint ( ( "Least specific prefix computed from site-cache for EID {} " + "using auth-prefix {} is {}" ) . format ( green ( eid . print_address ( ) , False ) ,
 # OoOoOO00
 # II111iiii . IiII / O0 . I1ii11iIi11i / OOooOOo % ooOoO0o
 ii1ii . print_prefix ( ) if ( ii1ii != None ) else "'not found'" , iI11Ii1 . print_prefix ( ) ) )
 if 90 - 90: OoO0O00 + OOooOOo
 if 64 - 64: o0oOOo0O0Ooo + OoO0O00 % I1Ii111 * I11i * iII111i % I11i
 return ( [ iI11Ii1 , i1iiIi1O000O0o0 , Ooo0oOo0o0oOo ] )
 if 26 - 26: OoO0O00 - II111iiii - o0oOOo0O0Ooo
 if 50 - 50: OoooooooOO
 if 51 - 51: II111iiii - oO0o % OoooooooOO - II111iiii / O0 - OoooooooOO
 if 21 - 21: iII111i * o0oOOo0O0Ooo
 if 85 - 85: I1ii11iIi11i . OoOoOO00 . i1IIi % OOooOOo * I11i . I1Ii111
 if 26 - 26: I1Ii111 + Oo0Ooo + II111iiii % OoOoOO00 % OOooOOo
 if 40 - 40: I1ii11iIi11i + i1IIi
 if 9 - 9: OOooOOo
def lisp_ms_send_map_referral ( lisp_sockets , map_request , ecm_source , port ,
 action , eid_prefix , group_prefix ) :
 if 74 - 74: OoOoOO00 - OOooOOo % OoOoOO00
 Ooo0 = map_request . target_eid
 ooOoO00 = map_request . target_group
 o0oo000 = map_request . nonce
 if 82 - 82: I11i % IiII + Oo0Ooo + iIii1I11I1II1 - I11i - I1IiiI
 if ( action == LISP_DDT_ACTION_MS_ACK ) : ooOOooooo0Oo = 1440
 if 65 - 65: IiII / O0 * II111iiii + oO0o
 if 52 - 52: o0oOOo0O0Ooo - OoOoOO00 * II111iiii / OoooooooOO
 if 44 - 44: OOooOOo - oO0o + o0oOOo0O0Ooo - i1IIi % o0oOOo0O0Ooo
 if 79 - 79: iII111i . iIii1I11I1II1
 iiiIi = lisp_map_referral ( )
 iiiIi . record_count = 1
 iiiIi . nonce = o0oo000
 I1IiO00Ooo0ooo0 = iiiIi . encode ( )
 iiiIi . print_map_referral ( )
 if 42 - 42: i11iIiiIii / IiII . O0 / OOooOOo . iII111i * i1IIi
 I111o0oooO00o0 = False
 if 83 - 83: iIii1I11I1II1 . II111iiii * Oo0Ooo . I1IiiI - I1IiiI - iIii1I11I1II1
 if 29 - 29: Oo0Ooo
 if 35 - 35: OoOoOO00 + II111iiii
 if 46 - 46: O0 / I1ii11iIi11i + OOooOOo - I1Ii111 + I1IiiI - ooOoO0o
 if 96 - 96: IiII + i1IIi - I11i * I11i - OoO0O00 % II111iiii
 if 47 - 47: I1Ii111 . i11iIiiIii + oO0o . I1ii11iIi11i
 if ( action == LISP_DDT_ACTION_SITE_NOT_FOUND ) :
  eid_prefix , group_prefix , action = lisp_ms_compute_neg_prefix ( Ooo0 ,
 ooOoO00 )
  ooOOooooo0Oo = 15
  if 12 - 12: iIii1I11I1II1 % I1Ii111 * OoOoOO00 / OoooooooOO % OoooooooOO
 if ( action == LISP_DDT_ACTION_MS_NOT_REG ) : ooOOooooo0Oo = 1
 if ( action == LISP_DDT_ACTION_MS_ACK ) : ooOOooooo0Oo = 1440
 if ( action == LISP_DDT_ACTION_DELEGATION_HOLE ) : ooOOooooo0Oo = 15
 if ( action == LISP_DDT_ACTION_NOT_AUTH ) : ooOOooooo0Oo = 0
 if 81 - 81: iIii1I11I1II1 - Oo0Ooo - ooOoO0o . OoO0O00 + I1ii11iIi11i
 O0I11Ii1I1111i1 = False
 o0Oo0Oooo0ooO = 0
 iii1i111I = lisp_ddt_cache_lookup ( Ooo0 , ooOoO00 , False )
 if ( iii1i111I != None ) :
  o0Oo0Oooo0ooO = len ( iii1i111I . delegation_set )
  O0I11Ii1I1111i1 = iii1i111I . is_ms_peer_entry ( )
  iii1i111I . map_referrals_sent += 1
  if 46 - 46: iIii1I11I1II1
  if 78 - 78: I1ii11iIi11i - IiII - Oo0Ooo % iII111i % I11i
  if 42 - 42: Oo0Ooo . OoO0O00
  if 22 - 22: ooOoO0o - o0oOOo0O0Ooo + I11i / I1IiiI + OOooOOo
  if 10 - 10: oO0o / I1IiiI
 if ( action == LISP_DDT_ACTION_NOT_AUTH ) : I111o0oooO00o0 = True
 if ( action in ( LISP_DDT_ACTION_MS_REFERRAL , LISP_DDT_ACTION_MS_ACK ) ) :
  I111o0oooO00o0 = ( O0I11Ii1I1111i1 == False )
  if 95 - 95: II111iiii - IiII % IiII . o0oOOo0O0Ooo
  if 19 - 19: II111iiii . ooOoO0o . I11i - OoooooooOO / I1ii11iIi11i . I1Ii111
  if 57 - 57: II111iiii . I1Ii111 . i11iIiiIii / OoOoOO00 - O0
  if 56 - 56: OOooOOo / I1Ii111
  if 13 - 13: oO0o + Oo0Ooo + Oo0Ooo / OoO0O00 + i1IIi + I1IiiI
 O0OO000oOO0 = lisp_eid_record ( )
 O0OO000oOO0 . rloc_count = o0Oo0Oooo0ooO
 O0OO000oOO0 . authoritative = True
 O0OO000oOO0 . action = action
 O0OO000oOO0 . ddt_incomplete = I111o0oooO00o0
 O0OO000oOO0 . eid = eid_prefix
 O0OO000oOO0 . group = group_prefix
 O0OO000oOO0 . record_ttl = ooOOooooo0Oo
 if 56 - 56: OoOoOO00
 I1IiO00Ooo0ooo0 += O0OO000oOO0 . encode ( )
 O0OO000oOO0 . print_record ( "  " , True )
 if 10 - 10: iIii1I11I1II1 + i1IIi * Ii1I / iIii1I11I1II1 % OoOoOO00 / O0
 if 14 - 14: O0
 if 65 - 65: IiII / oO0o
 if 57 - 57: IiII + oO0o - IiII
 if ( o0Oo0Oooo0ooO != 0 ) :
  for O0o0oO in iii1i111I . delegation_set :
   o0oooOOOOO0oo = lisp_rloc_record ( )
   o0oooOOOOO0oo . rloc = O0o0oO . delegate_address
   o0oooOOOOO0oo . priority = O0o0oO . priority
   o0oooOOOOO0oo . weight = O0o0oO . weight
   o0oooOOOOO0oo . mpriority = 255
   o0oooOOOOO0oo . mweight = 0
   o0oooOOOOO0oo . reach_bit = True
   I1IiO00Ooo0ooo0 += o0oooOOOOO0oo . encode ( )
   o0oooOOOOO0oo . print_record ( "    " )
   if 51 - 51: OoOoOO00 % IiII / iII111i - oO0o - OoO0O00 . iIii1I11I1II1
   if 61 - 61: OoO0O00
   if 60 - 60: I1IiiI % O0 % OoooooooOO / Ii1I
   if 9 - 9: OoooooooOO / I11i % I11i * O0 / II111iiii . II111iiii
   if 40 - 40: II111iiii + OoooooooOO / iII111i % O0 + OOooOOo . ooOoO0o
   if 71 - 71: OoooooooOO + ooOoO0o * o0oOOo0O0Ooo + I1IiiI
   if 47 - 47: oO0o
 if ( map_request . nonce != 0 ) : port = LISP_CTRL_PORT
 lisp_send_map_referral ( lisp_sockets , I1IiO00Ooo0ooo0 , ecm_source , port )
 return
 if 91 - 91: I1IiiI * O0 + OoooooooOO * i1IIi % I1ii11iIi11i . IiII
 if 67 - 67: I1IiiI * I11i
 if 43 - 43: IiII * Oo0Ooo / OoOoOO00 + I1IiiI - i11iIiiIii + II111iiii
 if 81 - 81: I11i / Oo0Ooo % Ii1I % OoO0O00
 if 87 - 87: O0 % II111iiii
 if 42 - 42: I1IiiI . i1IIi
 if 98 - 98: o0oOOo0O0Ooo % I11i . Oo0Ooo * Oo0Ooo % iII111i
 if 37 - 37: OoO0O00 / I1Ii111 . I1Ii111 * i1IIi
def lisp_send_negative_map_reply ( sockets , eid , group , nonce , dest , port , ttl ,
 xtr_id , pubsub ) :
 if 22 - 22: I1ii11iIi11i . II111iiii + iIii1I11I1II1 / OoooooooOO . ooOoO0o
 lprint ( "Build negative Map-Reply EID-prefix {}, nonce 0x{} to ITR {}" . format ( lisp_print_eid_tuple ( eid , group ) , lisp_hex_string ( nonce ) ,
 # O0
 red ( dest . print_address ( ) , False ) ) )
 if 27 - 27: oO0o * OoooooooOO * oO0o
 Ooo0oOo0o0oOo = LISP_NATIVE_FORWARD_ACTION if group . is_null ( ) else LISP_DROP_ACTION
 if 23 - 23: O0 . OoO0O00 . i1IIi
 if 19 - 19: O0 . OoooooooOO % iIii1I11I1II1 - Ii1I . Ii1I + I1IiiI
 if 98 - 98: oO0o . Oo0Ooo
 if 9 - 9: I1Ii111 % IiII - i11iIiiIii - OOooOOo % iII111i % OoooooooOO
 if 6 - 6: i1IIi - II111iiii * OoOoOO00 + oO0o
 if ( lisp_get_eid_hash ( eid ) != None ) :
  Ooo0oOo0o0oOo = LISP_SEND_MAP_REQUEST_ACTION
  if 6 - 6: I1IiiI - ooOoO0o + I1IiiI + OoO0O00 - i11iIiiIii % ooOoO0o
  if 64 - 64: OoooooooOO + OOooOOo
 I1IiO00Ooo0ooo0 = lisp_build_map_reply ( eid , group , [ ] , nonce , Ooo0oOo0o0oOo , ttl , False ,
 None , False , False )
 if 36 - 36: I1IiiI - Ii1I / I1ii11iIi11i + Oo0Ooo % I1ii11iIi11i
 if 86 - 86: iIii1I11I1II1 * OoO0O00
 if 82 - 82: I1IiiI - OoO0O00 % o0oOOo0O0Ooo
 if 72 - 72: O0 + OoOoOO00 % OOooOOo / oO0o / IiII
 if ( pubsub ) :
  lisp_process_pubsub ( sockets , I1IiO00Ooo0ooo0 , eid , dest , port , nonce , ttl ,
 xtr_id )
 else :
  lisp_send_map_reply ( sockets , I1IiO00Ooo0ooo0 , dest , port )
  if 98 - 98: Oo0Ooo . II111iiii * I11i
 return
 if 39 - 39: IiII * o0oOOo0O0Ooo + Ii1I - I11i
 if 70 - 70: oO0o * ooOoO0o / ooOoO0o - Ii1I * Ii1I % OOooOOo
 if 91 - 91: OoO0O00 - OoO0O00 % O0
 if 67 - 67: ooOoO0o * i1IIi
 if 66 - 66: o0oOOo0O0Ooo - I1ii11iIi11i . OoOoOO00 / iII111i - Ii1I - i1IIi
 if 97 - 97: oO0o % iII111i - OOooOOo . OoooooooOO
 if 94 - 94: Oo0Ooo
def lisp_retransmit_ddt_map_request ( mr ) :
 IiiIii1I11iiIiIii = mr . mr_source . print_address ( )
 o0oO = mr . print_eid_tuple ( )
 o0oo000 = mr . nonce
 if 2 - 2: OOooOOo / oO0o + I1ii11iIi11i + i11iIiiIii % iIii1I11I1II1 . I1ii11iIi11i
 if 100 - 100: Oo0Ooo * ooOoO0o + Ii1I / iII111i * o0oOOo0O0Ooo
 if 26 - 26: I1Ii111 * OoOoOO00
 if 38 - 38: II111iiii
 if 50 - 50: OoOoOO00 . IiII - OOooOOo
 if ( mr . last_request_sent_to ) :
  i11oO0O0O0o0 = mr . last_request_sent_to . print_address ( )
  ooOo = lisp_referral_cache_lookup ( mr . last_cached_prefix [ 0 ] ,
 mr . last_cached_prefix [ 1 ] , True )
  if ( ooOo and ooOo . referral_set . has_key ( i11oO0O0O0o0 ) ) :
   ooOo . referral_set [ i11oO0O0O0o0 ] . no_responses += 1
   if 38 - 38: OoooooooOO % o0oOOo0O0Ooo % I11i . Oo0Ooo
   if 72 - 72: OOooOOo + OoooooooOO . i1IIi
   if 10 - 10: II111iiii + I1Ii111 - i1IIi
   if 90 - 90: I11i . OoO0O00 . iIii1I11I1II1
   if 81 - 81: iII111i + I11i - i11iIiiIii * I1IiiI / IiII - Ii1I
   if 44 - 44: OoooooooOO . oO0o
   if 30 - 30: I1Ii111 % IiII / II111iiii
 if ( mr . retry_count == LISP_MAX_MAP_NOTIFY_RETRIES ) :
  lprint ( "DDT Map-Request retry limit reached for EID {}, nonce 0x{}" . format ( green ( o0oO , False ) , lisp_hex_string ( o0oo000 ) ) )
  if 68 - 68: oO0o / O0 / OOooOOo
  mr . dequeue_map_request ( )
  return
  if 3 - 3: o0oOOo0O0Ooo / o0oOOo0O0Ooo
  if 17 - 17: OoO0O00 * i1IIi
 mr . retry_count += 1
 if 50 - 50: OoOoOO00 + I11i
 i1I1iIi1IiI = green ( IiiIii1I11iiIiIii , False )
 i1i11ii1Ii = green ( o0oO , False )
 lprint ( "Retransmit DDT {} from {}ITR {} EIDs: {} -> {}, nonce 0x{}" . format ( bold ( "Map-Request" , False ) , "P" if mr . from_pitr else "" ,
 # ooOoO0o % Oo0Ooo - iII111i - I1IiiI
 red ( mr . itr . print_address ( ) , False ) , i1I1iIi1IiI , i1i11ii1Ii ,
 lisp_hex_string ( o0oo000 ) ) )
 if 51 - 51: i11iIiiIii % OoOoOO00
 if 17 - 17: ooOoO0o - i1IIi
 if 73 - 73: iIii1I11I1II1 - I1Ii111 % Oo0Ooo . O0
 if 16 - 16: OoO0O00 / Oo0Ooo / IiII . Oo0Ooo - OoooooooOO
 lisp_send_ddt_map_request ( mr , False )
 if 5 - 5: OoOoOO00 . I11i
 if 28 - 28: I11i % OOooOOo + Oo0Ooo / OoO0O00 % o0oOOo0O0Ooo + OoO0O00
 if 20 - 20: ooOoO0o . iII111i % OOooOOo + i11iIiiIii
 if 64 - 64: i1IIi . o0oOOo0O0Ooo * I1Ii111 - O0
 mr . retransmit_timer = threading . Timer ( LISP_DDT_MAP_REQUEST_INTERVAL ,
 lisp_retransmit_ddt_map_request , [ mr ] )
 mr . retransmit_timer . start ( )
 return
 if 76 - 76: I1IiiI % Ii1I + OoO0O00 + I1ii11iIi11i * II111iiii + Oo0Ooo
 if 3 - 3: Ii1I - I1IiiI + O0
 if 90 - 90: Ii1I + OoooooooOO . i11iIiiIii / Oo0Ooo % OoOoOO00 / IiII
 if 45 - 45: OoooooooOO / oO0o . I1ii11iIi11i + OOooOOo
 if 54 - 54: Ii1I - o0oOOo0O0Ooo + OoOoOO00 / OoooooooOO
 if 61 - 61: I11i / IiII % OoooooooOO - i11iIiiIii * i1IIi % o0oOOo0O0Ooo
 if 67 - 67: o0oOOo0O0Ooo - Ii1I
 if 29 - 29: OoOoOO00 . I1ii11iIi11i
def lisp_get_referral_node ( referral , source_eid , dest_eid ) :
 if 24 - 24: OOooOOo + i1IIi . I11i . OoOoOO00 + OoooooooOO
 if 98 - 98: ooOoO0o + i1IIi / I1IiiI
 if 1 - 1: IiII . OoooooooOO + II111iiii
 if 6 - 6: O0 * Oo0Ooo
 Ii1ii1IiiIiiI = [ ]
 for oOoooooOoOoO in referral . referral_set . values ( ) :
  if ( oOoooooOoOoO . updown == False ) : continue
  if ( len ( Ii1ii1IiiIiiI ) == 0 or Ii1ii1IiiIiiI [ 0 ] . priority == oOoooooOoOoO . priority ) :
   Ii1ii1IiiIiiI . append ( oOoooooOoOoO )
  elif ( Ii1ii1IiiIiiI [ 0 ] . priority > oOoooooOoOoO . priority ) :
   Ii1ii1IiiIiiI = [ ]
   Ii1ii1IiiIiiI . append ( oOoooooOoOoO )
   if 48 - 48: O0 % I1ii11iIi11i
   if 72 - 72: I1IiiI - i1IIi
   if 11 - 11: iIii1I11I1II1 . OoO0O00 * Ii1I
 oOoOO = len ( Ii1ii1IiiIiiI )
 if ( oOoOO == 0 ) : return ( None )
 if 45 - 45: I1IiiI % OOooOOo
 OoOoo00Oo0OoO = dest_eid . hash_address ( source_eid )
 OoOoo00Oo0OoO = OoOoo00Oo0OoO % oOoOO
 return ( Ii1ii1IiiIiiI [ OoOoo00Oo0OoO ] )
 if 63 - 63: Ii1I + iIii1I11I1II1 - i11iIiiIii / OoOoOO00
 if 81 - 81: OOooOOo * Ii1I
 if 23 - 23: OoooooooOO * OOooOOo
 if 24 - 24: IiII + I1IiiI / OoooooooOO
 if 8 - 8: II111iiii . I1Ii111 * OoOoOO00 / iII111i - Oo0Ooo
 if 17 - 17: iII111i . O0
 if 27 - 27: I11i + iIii1I11I1II1 - i11iIiiIii
def lisp_send_ddt_map_request ( mr , send_to_root ) :
 O00O0o = mr . lisp_sockets
 o0oo000 = mr . nonce
 IiI1IIii = mr . itr
 oO0oOO0ooOo0 = mr . mr_source
 oo0ooooO = mr . print_eid_tuple ( )
 if 32 - 32: ooOoO0o
 if 9 - 9: I1Ii111
 if 77 - 77: OoooooooOO * I1Ii111
 if 63 - 63: IiII * oO0o * iIii1I11I1II1
 if 18 - 18: II111iiii * o0oOOo0O0Ooo % i11iIiiIii . OoOoOO00
 if ( mr . send_count == 8 ) :
  lprint ( "Giving up on map-request-queue entry {}, nonce 0x{}" . format ( green ( oo0ooooO , False ) , lisp_hex_string ( o0oo000 ) ) )
  if 40 - 40: oO0o - o0oOOo0O0Ooo * II111iiii
  mr . dequeue_map_request ( )
  return
  if 4 - 4: O0
  if 9 - 9: Oo0Ooo . i1IIi - i1IIi + I1Ii111 * ooOoO0o . I1ii11iIi11i
  if 17 - 17: I11i * I1ii11iIi11i % I1IiiI + OoO0O00 + IiII
  if 90 - 90: OoooooooOO - I1IiiI / I1ii11iIi11i + oO0o - o0oOOo0O0Ooo
  if 84 - 84: OoOoOO00 + O0 % Oo0Ooo
  if 22 - 22: iIii1I11I1II1 % i11iIiiIii
 if ( send_to_root ) :
  I1I111I1 = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  OOoOooO0oO00o = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  mr . tried_root = True
  lprint ( "Jumping up to root for EID {}" . format ( green ( oo0ooooO , False ) ) )
 else :
  I1I111I1 = mr . eid
  OOoOooO0oO00o = mr . group
  if 9 - 9: OOooOOo + Oo0Ooo
  if 84 - 84: i11iIiiIii . Ii1I
  if 86 - 86: o0oOOo0O0Ooo / oO0o * i1IIi
  if 41 - 41: II111iiii . i1IIi
  if 78 - 78: I1IiiI * I11i % OOooOOo + Ii1I + OoOoOO00
 I11I1 = lisp_referral_cache_lookup ( I1I111I1 , OOoOooO0oO00o , False )
 if ( I11I1 == None ) :
  lprint ( "No referral cache entry found" )
  lisp_send_negative_map_reply ( O00O0o , I1I111I1 , OOoOooO0oO00o ,
 o0oo000 , IiI1IIii , mr . sport , 15 , None , False )
  return
  if 16 - 16: OoooooooOO
  if 34 - 34: II111iiii - I1ii11iIi11i + O0 - I1IiiI + OoooooooOO
 i1II11ii1Ii = I11I1 . print_eid_tuple ( )
 lprint ( "Found referral cache entry {}, referral-type: {}" . format ( i1II11ii1Ii ,
 I11I1 . print_referral_type ( ) ) )
 if 88 - 88: O0 - i1IIi . II111iiii - O0 + O0 / I1ii11iIi11i
 oOoooooOoOoO = lisp_get_referral_node ( I11I1 , oO0oOO0ooOo0 , mr . eid )
 if ( oOoooooOoOoO == None ) :
  lprint ( "No reachable referral-nodes found" )
  mr . dequeue_map_request ( )
  lisp_send_negative_map_reply ( O00O0o , I11I1 . eid ,
 I11I1 . group , o0oo000 , IiI1IIii , mr . sport , 1 , None , False )
  return
  if 9 - 9: iIii1I11I1II1
  if 57 - 57: i1IIi * OOooOOo
 lprint ( "Send DDT Map-Request to {} {} for EID {}, nonce 0x{}" . format ( oOoooooOoOoO . referral_address . print_address ( ) ,
 # i1IIi % IiII * Oo0Ooo
 I11I1 . print_referral_type ( ) , green ( oo0ooooO , False ) ,
 lisp_hex_string ( o0oo000 ) ) )
 if 25 - 25: II111iiii
 if 8 - 8: OoO0O00
 if 17 - 17: iIii1I11I1II1 - Oo0Ooo
 if 25 - 25: O0 + I1ii11iIi11i
 ooO = ( I11I1 . referral_type == LISP_DDT_ACTION_MS_REFERRAL or
 I11I1 . referral_type == LISP_DDT_ACTION_MS_ACK )
 lisp_send_ecm ( O00O0o , mr . packet , oO0oOO0ooOo0 , mr . sport , mr . eid ,
 oOoooooOoOoO . referral_address , to_ms = ooO , ddt = True )
 if 35 - 35: OOooOOo % i11iIiiIii % ooOoO0o . O0
 if 9 - 9: ooOoO0o + iII111i / i1IIi % Oo0Ooo - o0oOOo0O0Ooo / I1IiiI
 if 42 - 42: OOooOOo + oO0o % O0 * I1ii11iIi11i + i11iIiiIii
 if 16 - 16: i1IIi . I11i + OoO0O00 % Ii1I * IiII + I1IiiI
 mr . last_request_sent_to = oOoooooOoOoO . referral_address
 mr . last_sent = lisp_get_timestamp ( )
 mr . send_count += 1
 oOoooooOoOoO . map_requests_sent += 1
 return
 if 96 - 96: II111iiii + O0 - II111iiii
 if 97 - 97: I1IiiI
 if 87 - 87: I11i + iIii1I11I1II1
 if 91 - 91: oO0o
 if 58 - 58: i11iIiiIii / Ii1I - OoooooooOO
 if 25 - 25: i1IIi * ooOoO0o % OOooOOo / I1IiiI
 if 75 - 75: i11iIiiIii
 if 38 - 38: iIii1I11I1II1
def lisp_mr_process_map_request ( lisp_sockets , packet , map_request , ecm_source ,
 sport , mr_source ) :
 if 80 - 80: OoO0O00
 Ooo0 = map_request . target_eid
 ooOoO00 = map_request . target_group
 o0oO = map_request . print_eid_tuple ( )
 IiiIii1I11iiIiIii = mr_source . print_address ( )
 o0oo000 = map_request . nonce
 if 72 - 72: I11i * II111iiii
 i1I1iIi1IiI = green ( IiiIii1I11iiIiIii , False )
 i1i11ii1Ii = green ( o0oO , False )
 lprint ( "Received Map-Request from {}ITR {} EIDs: {} -> {}, nonce 0x{}" . format ( "P" if map_request . pitr_bit else "" ,
 # OoooooooOO + I1Ii111 * II111iiii + I11i * II111iiii
 red ( ecm_source . print_address ( ) , False ) , i1I1iIi1IiI , i1i11ii1Ii ,
 lisp_hex_string ( o0oo000 ) ) )
 if 14 - 14: I1ii11iIi11i * OoooooooOO / OoO0O00 / OoOoOO00 / OoooooooOO
 if 17 - 17: i1IIi
 if 80 - 80: i1IIi - iIii1I11I1II1 + OoooooooOO + ooOoO0o / IiII - I1ii11iIi11i
 if 90 - 90: I1IiiI * ooOoO0o - I11i + O0 - I11i
 oOoooooOooO = lisp_ddt_map_request ( lisp_sockets , packet , Ooo0 , ooOoO00 , o0oo000 )
 oOoooooOooO . packet = packet
 oOoooooOooO . itr = ecm_source
 oOoooooOooO . mr_source = mr_source
 oOoooooOooO . sport = sport
 oOoooooOooO . from_pitr = map_request . pitr_bit
 oOoooooOooO . queue_map_request ( )
 if 31 - 31: IiII
 lisp_send_ddt_map_request ( oOoooooOooO , False )
 return
 if 86 - 86: Oo0Ooo + IiII / o0oOOo0O0Ooo % OoOoOO00
 if 49 - 49: iIii1I11I1II1 % Oo0Ooo % I11i * Ii1I - OoO0O00
 if 15 - 15: i11iIiiIii + o0oOOo0O0Ooo . Ii1I . I1IiiI
 if 8 - 8: iII111i % II111iiii + IiII
 if 5 - 5: i1IIi + II111iiii
 if 75 - 75: OOooOOo . IiII . I1IiiI + OoooooooOO
 if 35 - 35: I11i % i1IIi - I1ii11iIi11i . Oo0Ooo
def lisp_process_map_request ( lisp_sockets , packet , ecm_source , ecm_port ,
 mr_source , mr_port , ddt_request , ttl ) :
 if 69 - 69: ooOoO0o * OoO0O00 % o0oOOo0O0Ooo * o0oOOo0O0Ooo
 O00Ooo00 = packet
 Ii1 = lisp_map_request ( )
 packet = Ii1 . decode ( packet , mr_source , mr_port )
 if ( packet == None ) :
  lprint ( "Could not decode Map-Request packet" )
  return
  if 68 - 68: OoO0O00
  if 56 - 56: i11iIiiIii / I1Ii111 / II111iiii / oO0o
 Ii1 . print_map_request ( )
 if 35 - 35: OOooOOo / I1Ii111 . I1ii11iIi11i / OoooooooOO + I1Ii111 . I1Ii111
 if 52 - 52: O0 - I1Ii111 . oO0o
 if 43 - 43: IiII * Ii1I - I1ii11iIi11i * I1ii11iIi11i
 if 53 - 53: oO0o % I11i * OoO0O00 . i1IIi
 if ( Ii1 . rloc_probe ) :
  lisp_process_rloc_probe_request ( lisp_sockets , Ii1 ,
 mr_source , mr_port , ttl )
  return
  if 35 - 35: I11i . IiII + ooOoO0o
  if 19 - 19: O0 - i1IIi / I1Ii111
  if 14 - 14: I11i - i11iIiiIii
  if 49 - 49: oO0o . I1ii11iIi11i
  if 51 - 51: OOooOOo + o0oOOo0O0Ooo . OOooOOo
 if ( Ii1 . smr_bit ) :
  lisp_process_smr ( Ii1 )
  if 23 - 23: iIii1I11I1II1 + OoO0O00 / I1IiiI
  if 48 - 48: OoOoOO00 + I11i + oO0o . I1IiiI
  if 7 - 7: iII111i * i1IIi % OoOoOO00 % Ii1I . I1IiiI
  if 53 - 53: OOooOOo / I11i + OOooOOo / I1IiiI / OoO0O00
  if 12 - 12: i11iIiiIii % ooOoO0o / iII111i . IiII
 if ( Ii1 . smr_invoked_bit ) :
  lisp_process_smr_invoked_request ( Ii1 )
  if 68 - 68: OOooOOo / iIii1I11I1II1 + I1IiiI . ooOoO0o * IiII
  if 72 - 72: I1Ii111
  if 51 - 51: OoOoOO00
  if 61 - 61: Oo0Ooo / i1IIi + I1Ii111 - OoooooooOO / O0
  if 25 - 25: I1ii11iIi11i * i11iIiiIii / i1IIi
 if ( lisp_i_am_etr ) :
  lisp_etr_process_map_request ( lisp_sockets , Ii1 , mr_source ,
 mr_port , ttl )
  if 69 - 69: OOooOOo % ooOoO0o - i1IIi . Oo0Ooo
  if 35 - 35: iIii1I11I1II1 - I11i / iIii1I11I1II1 % ooOoO0o % I1IiiI
  if 46 - 46: oO0o
  if 5 - 5: i1IIi % o0oOOo0O0Ooo + OoOoOO00 - I11i . Ii1I
  if 33 - 33: II111iiii * o0oOOo0O0Ooo
 if ( lisp_i_am_ms ) :
  packet = O00Ooo00
  Ooo0 , ooOoO00 , iIII111iiII = lisp_ms_process_map_request ( lisp_sockets ,
 O00Ooo00 , Ii1 , mr_source , mr_port , ecm_source )
  if ( ddt_request ) :
   lisp_ms_send_map_referral ( lisp_sockets , Ii1 , ecm_source ,
 ecm_port , iIII111iiII , Ooo0 , ooOoO00 )
   if 42 - 42: I11i / Oo0Ooo + I1IiiI + o0oOOo0O0Ooo
  return
  if 100 - 100: iII111i % iII111i + OOooOOo - I1ii11iIi11i % IiII % ooOoO0o
  if 57 - 57: Ii1I / IiII / I11i % I1IiiI
  if 49 - 49: Oo0Ooo + i1IIi % iII111i - I1IiiI + Ii1I
  if 96 - 96: I1ii11iIi11i % Oo0Ooo . OoO0O00 + OoooooooOO + I1ii11iIi11i * OOooOOo
  if 75 - 75: Ii1I * Oo0Ooo % iIii1I11I1II1 . O0 % oO0o
 if ( lisp_i_am_mr and not ddt_request ) :
  lisp_mr_process_map_request ( lisp_sockets , O00Ooo00 , Ii1 ,
 ecm_source , mr_port , mr_source )
  if 4 - 4: I1IiiI - i11iIiiIii / o0oOOo0O0Ooo
  if 54 - 54: i11iIiiIii + I1Ii111 . I1Ii111 * I1ii11iIi11i % I1Ii111 - OoooooooOO
  if 76 - 76: IiII + i1IIi + i11iIiiIii . oO0o
  if 23 - 23: ooOoO0o - OoO0O00 + oO0o . OOooOOo - I1IiiI
  if 66 - 66: iII111i % iII111i
 if ( lisp_i_am_ddt or ddt_request ) :
  packet = O00Ooo00
  lisp_ddt_process_map_request ( lisp_sockets , Ii1 , ecm_source ,
 ecm_port )
  if 59 - 59: II111iiii . i1IIi % i1IIi
 return
 if 40 - 40: I1Ii111 . II111iiii * o0oOOo0O0Ooo + I11i - i1IIi
 if 67 - 67: o0oOOo0O0Ooo - O0 - i1IIi . ooOoO0o . iII111i
 if 43 - 43: II111iiii . o0oOOo0O0Ooo + i11iIiiIii . O0 / O0 . II111iiii
 if 13 - 13: Ii1I % i11iIiiIii
 if 3 - 3: ooOoO0o % OoOoOO00 * I1Ii111 - OoO0O00 / i1IIi % I1IiiI
 if 50 - 50: I1ii11iIi11i + iII111i
 if 64 - 64: oO0o
 if 11 - 11: o0oOOo0O0Ooo
def lisp_store_mr_stats ( source , nonce ) :
 oOoooooOooO = lisp_get_map_resolver ( source , None )
 if ( oOoooooOooO == None ) : return
 if 95 - 95: i1IIi . ooOoO0o . Oo0Ooo
 if 13 - 13: OOooOOo - Oo0Ooo % O0 . I1Ii111
 if 66 - 66: I1IiiI + I11i
 if 58 - 58: I1ii11iIi11i
 oOoooooOooO . neg_map_replies_received += 1
 oOoooooOooO . last_reply = lisp_get_timestamp ( )
 if 7 - 7: oO0o - I11i
 if 59 - 59: Ii1I / o0oOOo0O0Ooo / OoO0O00 + IiII + i11iIiiIii
 if 64 - 64: o0oOOo0O0Ooo * IiII * IiII * iII111i % i11iIiiIii
 if 22 - 22: I1ii11iIi11i * II111iiii - OOooOOo % i11iIiiIii
 if ( ( oOoooooOooO . neg_map_replies_received % 100 ) == 0 ) : oOoooooOooO . total_rtt = 0
 if 10 - 10: OOooOOo / I1ii11iIi11i
 if 21 - 21: OoO0O00 % Oo0Ooo . o0oOOo0O0Ooo + IiII
 if 48 - 48: O0 / i1IIi / iII111i
 if 11 - 11: O0 - OoO0O00 + OoOoOO00 * ooOoO0o - Ii1I
 if ( oOoooooOooO . last_nonce == nonce ) :
  oOoooooOooO . total_rtt += ( time . time ( ) - oOoooooOooO . last_used )
  oOoooooOooO . last_nonce = 0
  if 82 - 82: Ii1I - O0 * ooOoO0o . ooOoO0o
 if ( ( oOoooooOooO . neg_map_replies_received % 10 ) == 0 ) : oOoooooOooO . last_nonce = 0
 return
 if 32 - 32: o0oOOo0O0Ooo . OoooooooOO % OOooOOo
 if 2 - 2: OoOoOO00 + I1ii11iIi11i + oO0o
 if 27 - 27: OoooooooOO - Ii1I / OoooooooOO + OoO0O00
 if 58 - 58: OOooOOo * I11i . I1IiiI
 if 46 - 46: I11i + II111iiii * iII111i % ooOoO0o - I1IiiI
 if 73 - 73: I1ii11iIi11i * iIii1I11I1II1 . I1Ii111 - Ii1I
 if 11 - 11: I11i
def lisp_process_map_reply ( lisp_sockets , packet , source , ttl ) :
 global lisp_map_cache
 if 48 - 48: IiII / O0
 i1i = lisp_map_reply ( )
 packet = i1i . decode ( packet )
 if ( packet == None ) :
  lprint ( "Could not decode Map-Reply packet" )
  return
  if 46 - 46: ooOoO0o + oO0o
 i1i . print_map_reply ( )
 if 7 - 7: ooOoO0o * oO0o . i1IIi
 if 74 - 74: i1IIi * I11i + OoOoOO00 / OoO0O00 - oO0o / I11i
 if 90 - 90: IiII % I1ii11iIi11i % i1IIi
 if 63 - 63: Ii1I . I1IiiI + IiII / OoOoOO00 + ooOoO0o - iIii1I11I1II1
 Iiii11iiiI1 = None
 for oO in range ( i1i . record_count ) :
  O0OO000oOO0 = lisp_eid_record ( )
  packet = O0OO000oOO0 . decode ( packet )
  if ( packet == None ) :
   lprint ( "Could not decode EID-record in Map-Reply packet" )
   return
   if 78 - 78: I1Ii111 % I1Ii111 + II111iiii * iII111i + ooOoO0o
  O0OO000oOO0 . print_record ( "  " , False )
  if 100 - 100: OOooOOo . ooOoO0o + Ii1I + Ii1I
  if 70 - 70: ooOoO0o . iIii1I11I1II1 / oO0o
  if 18 - 18: Ii1I / OoooooooOO % i1IIi * o0oOOo0O0Ooo
  if 70 - 70: IiII % i1IIi / IiII - o0oOOo0O0Ooo . Oo0Ooo / O0
  if 54 - 54: o0oOOo0O0Ooo
  if ( O0OO000oOO0 . rloc_count == 0 ) :
   lisp_store_mr_stats ( source , i1i . nonce )
   if 53 - 53: II111iiii / IiII . i1IIi + I1Ii111 / OoO0O00 - OoooooooOO
   if 67 - 67: ooOoO0o . Ii1I - Oo0Ooo * iII111i . I11i - OOooOOo
  iIIiI1iiIi = ( O0OO000oOO0 . group . is_null ( ) == False )
  if 39 - 39: IiII - i1IIi - IiII - OoooooooOO - I1ii11iIi11i
  if 66 - 66: IiII + i1IIi
  if 21 - 21: IiII / i11iIiiIii / OoOoOO00
  if 75 - 75: Ii1I . i1IIi / I1IiiI * iII111i . IiII / OoOoOO00
  if 58 - 58: ooOoO0o + OOooOOo / ooOoO0o / i11iIiiIii
  if ( lisp_decent_push_configured ) :
   Ooo0oOo0o0oOo = O0OO000oOO0 . action
   if ( iIIiI1iiIi and Ooo0oOo0o0oOo == LISP_DROP_ACTION ) :
    if ( O0OO000oOO0 . eid . is_local ( ) ) : continue
    if 95 - 95: ooOoO0o
    if 10 - 10: OoO0O00 % ooOoO0o * o0oOOo0O0Ooo
    if 37 - 37: Ii1I . o0oOOo0O0Ooo
    if 34 - 34: ooOoO0o * IiII . Ii1I + iIii1I11I1II1
    if 1 - 1: i11iIiiIii + I11i
    if 78 - 78: Ii1I % Oo0Ooo / OoO0O00 . iIii1I11I1II1 . II111iiii
    if 67 - 67: oO0o % I1Ii111
  if ( O0OO000oOO0 . eid . is_null ( ) ) : continue
  if 72 - 72: I1IiiI . i11iIiiIii . OoOoOO00 + I1IiiI - I1Ii111 + iII111i
  if 15 - 15: I1IiiI
  if 88 - 88: IiII / I1ii11iIi11i % I11i + i11iIiiIii * O0 . I1Ii111
  if 69 - 69: Oo0Ooo - OOooOOo / I1IiiI . i11iIiiIii * OoO0O00
  if 45 - 45: I1Ii111 + OOooOOo
  if ( iIIiI1iiIi ) :
   oOooO0Oo0Oo0 = lisp_map_cache_lookup ( O0OO000oOO0 . eid , O0OO000oOO0 . group )
  else :
   oOooO0Oo0Oo0 = lisp_map_cache . lookup_cache ( O0OO000oOO0 . eid , True )
   if 18 - 18: O0 * OoooooooOO % IiII - iIii1I11I1II1 % IiII * o0oOOo0O0Ooo
  IIIiii1 = ( oOooO0Oo0Oo0 == None )
  if 99 - 99: I11i
  if 61 - 61: i1IIi - i1IIi
  if 97 - 97: I11i + II111iiii / OoooooooOO + I1ii11iIi11i * o0oOOo0O0Ooo
  if 29 - 29: I1Ii111
  I111iIi11Ii11III = [ ]
  for OOOoOOo000oo in range ( O0OO000oOO0 . rloc_count ) :
   o0oooOOOOO0oo = lisp_rloc_record ( )
   o0oooOOOOO0oo . keys = i1i . keys
   packet = o0oooOOOOO0oo . decode ( packet , i1i . nonce )
   if ( packet == None ) :
    lprint ( "Could not decode RLOC-record in Map-Reply packet" )
    return
    if 3 - 3: O0 / OOooOOo - iII111i
   o0oooOOOOO0oo . print_record ( "    " )
   if 60 - 60: I1IiiI
   Ii11IIiiI1I = None
   if ( oOooO0Oo0Oo0 ) : Ii11IIiiI1I = oOooO0Oo0Oo0 . get_rloc ( o0oooOOOOO0oo . rloc )
   if ( Ii11IIiiI1I ) :
    oOoOoo0O = Ii11IIiiI1I
   else :
    oOoOoo0O = lisp_rloc ( )
    if 18 - 18: O0
    if 26 - 26: i1IIi - iIii1I11I1II1
    if 8 - 8: I1Ii111
    if 86 - 86: i1IIi
    if 26 - 26: o0oOOo0O0Ooo % I1Ii111 / Oo0Ooo
    if 68 - 68: II111iiii / Oo0Ooo / Oo0Ooo
    if 1 - 1: Oo0Ooo
   i1O0OO = oOoOoo0O . store_rloc_from_record ( o0oooOOOOO0oo , i1i . nonce ,
 source )
   oOoOoo0O . echo_nonce_capable = i1i . echo_nonce_capable
   if 73 - 73: Ii1I * iIii1I11I1II1 / o0oOOo0O0Ooo - o0oOOo0O0Ooo / i1IIi
   if ( oOoOoo0O . echo_nonce_capable ) :
    OoOOoooO000 = oOoOoo0O . rloc . print_address_no_iid ( )
    if ( lisp_get_echo_nonce ( None , OoOOoooO000 ) == None ) :
     lisp_echo_nonce ( OoOOoooO000 )
     if 64 - 64: Ii1I * I1ii11iIi11i % II111iiii
     if 31 - 31: iIii1I11I1II1 % Oo0Ooo . I1IiiI % ooOoO0o
     if 38 - 38: I1ii11iIi11i + I1Ii111 * I11i / OoO0O00 + o0oOOo0O0Ooo
     if 46 - 46: iII111i
     if 56 - 56: Oo0Ooo / II111iiii
     if 61 - 61: Ii1I - i1IIi / ooOoO0o - Oo0Ooo / IiII % Oo0Ooo
     if 53 - 53: OoooooooOO + iII111i % II111iiii * IiII
     if 10 - 10: OoOoOO00 % I11i
     if 46 - 46: i1IIi % IiII
     if 45 - 45: I1ii11iIi11i / I1ii11iIi11i - OoO0O00
   if ( i1i . rloc_probe and o0oooOOOOO0oo . probe_bit ) :
    if ( oOoOoo0O . rloc . afi == source . afi ) :
     lisp_process_rloc_probe_reply ( oOoOoo0O . rloc , source , i1O0OO ,
 i1i . nonce , i1i . hop_count , ttl )
     if 54 - 54: Ii1I + I1IiiI * OoOoOO00 + oO0o
     if 10 - 10: Ii1I - I1IiiI / IiII / iII111i - I1Ii111 - o0oOOo0O0Ooo
     if 75 - 75: OOooOOo . ooOoO0o
     if 32 - 32: i1IIi / I11i + iIii1I11I1II1 . OOooOOo
     if 67 - 67: iII111i - OoO0O00 % I1ii11iIi11i * Oo0Ooo
     if 51 - 51: I1IiiI + O0
   I111iIi11Ii11III . append ( oOoOoo0O )
   if 4 - 4: ooOoO0o / OoO0O00 * iIii1I11I1II1 * iIii1I11I1II1
   if 33 - 33: iII111i . iIii1I11I1II1 - Ii1I
   if 85 - 85: OoOoOO00
   if 57 - 57: Oo0Ooo - II111iiii - I1ii11iIi11i * oO0o
   if ( lisp_data_plane_security and oOoOoo0O . rloc_recent_rekey ( ) ) :
    Iiii11iiiI1 = oOoOoo0O
    if 41 - 41: I11i / ooOoO0o + IiII % OoooooooOO
    if 72 - 72: Ii1I
    if 22 - 22: o0oOOo0O0Ooo / OoO0O00 + OoOoOO00 + Ii1I . II111iiii * I11i
    if 85 - 85: i11iIiiIii / I11i
    if 28 - 28: i11iIiiIii + IiII / I11i . Ii1I / OoO0O00
    if 100 - 100: o0oOOo0O0Ooo - I11i . o0oOOo0O0Ooo
    if 90 - 90: OoOoOO00 / II111iiii / I11i * I11i - iIii1I11I1II1
    if 87 - 87: IiII
    if 92 - 92: OoO0O00 / IiII - ooOoO0o
    if 45 - 45: iII111i - I11i * ooOoO0o * OOooOOo / I1Ii111 * iII111i
    if 33 - 33: iIii1I11I1II1 % I1ii11iIi11i - OOooOOo % iIii1I11I1II1 + I11i / i11iIiiIii
  if ( i1i . rloc_probe == False and lisp_nat_traversal ) :
   O000OOo0o0o0 = [ ]
   o0o0oO0oo0OOO = [ ]
   for oOoOoo0O in I111iIi11Ii11III :
    if 36 - 36: OoO0O00 * IiII * I1ii11iIi11i
    if 71 - 71: OoO0O00 . I1IiiI % Ii1I + ooOoO0o / OoOoOO00
    if 57 - 57: II111iiii . oO0o - I11i + OoOoOO00
    if 14 - 14: OoO0O00 * I1IiiI . O0 / ooOoO0o - I1IiiI - I1IiiI
    if 43 - 43: OoO0O00 . Oo0Ooo % IiII + OOooOOo . OoO0O00 % i11iIiiIii
    if ( oOoOoo0O . rloc . is_private_address ( ) ) :
     oOoOoo0O . priority = 1
     oOoOoo0O . state = LISP_RLOC_UNREACH_STATE
     O000OOo0o0o0 . append ( oOoOoo0O )
     o0o0oO0oo0OOO . append ( oOoOoo0O . rloc . print_address_no_iid ( ) )
     continue
     if 70 - 70: I11i
     if 71 - 71: iII111i
     if 40 - 40: II111iiii
     if 71 - 71: O0 + Ii1I . iII111i % Oo0Ooo % ooOoO0o + II111iiii
     if 1 - 1: II111iiii - oO0o
     if 66 - 66: I1ii11iIi11i + i1IIi / ooOoO0o . I1Ii111 % OoOoOO00
    if ( oOoOoo0O . priority == 254 and lisp_i_am_rtr == False ) :
     O000OOo0o0o0 . append ( oOoOoo0O )
     o0o0oO0oo0OOO . append ( oOoOoo0O . rloc . print_address_no_iid ( ) )
     if 67 - 67: i1IIi * i11iIiiIii * I1IiiI
    if ( oOoOoo0O . priority != 254 and lisp_i_am_rtr ) :
     O000OOo0o0o0 . append ( oOoOoo0O )
     o0o0oO0oo0OOO . append ( oOoOoo0O . rloc . print_address_no_iid ( ) )
     if 23 - 23: Oo0Ooo
     if 81 - 81: I1Ii111 % II111iiii - Oo0Ooo / I1IiiI + i11iIiiIii . I11i
     if 67 - 67: ooOoO0o . I1Ii111 . Oo0Ooo . Ii1I + iIii1I11I1II1 / OoooooooOO
   if ( o0o0oO0oo0OOO != [ ] ) :
    I111iIi11Ii11III = O000OOo0o0o0
    lprint ( "NAT-traversal optimized RLOC-set: {}" . format ( o0o0oO0oo0OOO ) )
    if 93 - 93: ooOoO0o * OoO0O00 - I1Ii111 / I1ii11iIi11i
    if 60 - 60: OoO0O00 / oO0o . I1IiiI + OoOoOO00 + I1ii11iIi11i % Ii1I
    if 70 - 70: i1IIi * II111iiii * I1IiiI
    if 7 - 7: OoooooooOO + II111iiii % o0oOOo0O0Ooo * O0 . OoO0O00 * OoooooooOO
    if 20 - 20: Oo0Ooo % OOooOOo
    if 8 - 8: OOooOOo
    if 92 - 92: iII111i / OOooOOo . IiII / I11i + o0oOOo0O0Ooo
  O000OOo0o0o0 = [ ]
  for oOoOoo0O in I111iIi11Ii11III :
   if ( oOoOoo0O . json != None ) : continue
   O000OOo0o0o0 . append ( oOoOoo0O )
   if 99 - 99: II111iiii
  if ( O000OOo0o0o0 != [ ] ) :
   Ooo00OOOOOO0 = len ( I111iIi11Ii11III ) - len ( O000OOo0o0o0 )
   lprint ( "Pruning {} no-address RLOC-records for map-cache" . format ( Ooo00OOOOOO0 ) )
   if 70 - 70: O0 % I1ii11iIi11i
   I111iIi11Ii11III = O000OOo0o0o0
   if 28 - 28: IiII - i1IIi - I1Ii111 % Ii1I - IiII
   if 73 - 73: iIii1I11I1II1 . iIii1I11I1II1 + oO0o % i11iIiiIii . IiII
   if 33 - 33: IiII - OOooOOo / i11iIiiIii * iIii1I11I1II1
   if 2 - 2: i11iIiiIii % ooOoO0o
   if 56 - 56: IiII % ooOoO0o + I1IiiI % I11i - OOooOOo
   if 82 - 82: OoooooooOO . i1IIi . OoO0O00 . OoO0O00
   if 31 - 31: iIii1I11I1II1
   if 64 - 64: ooOoO0o
  if ( i1i . rloc_probe and oOooO0Oo0Oo0 != None ) : I111iIi11Ii11III = oOooO0Oo0Oo0 . rloc_set
  if 30 - 30: OoO0O00 + o0oOOo0O0Ooo / iIii1I11I1II1
  if 69 - 69: IiII - OoooooooOO + iII111i + iII111i - Ii1I
  if 27 - 27: I1ii11iIi11i % Oo0Ooo * iIii1I11I1II1 * O0 / I11i * Oo0Ooo
  if 97 - 97: IiII % Oo0Ooo % OoOoOO00
  if 87 - 87: i11iIiiIii . oO0o * I1IiiI * I1Ii111
  OoooO = IIIiii1
  if ( oOooO0Oo0Oo0 and I111iIi11Ii11III != oOooO0Oo0Oo0 . rloc_set ) :
   oOooO0Oo0Oo0 . delete_rlocs_from_rloc_probe_list ( )
   OoooO = True
   if 88 - 88: I1IiiI - iIii1I11I1II1 % i1IIi . iIii1I11I1II1 + II111iiii
   if 73 - 73: Oo0Ooo * OoooooooOO . i1IIi . Oo0Ooo * Ii1I * OoOoOO00
   if 33 - 33: i11iIiiIii - o0oOOo0O0Ooo / I1ii11iIi11i
   if 32 - 32: Oo0Ooo - I1Ii111 - OOooOOo * o0oOOo0O0Ooo + I1Ii111 - iIii1I11I1II1
   if 18 - 18: Oo0Ooo + Oo0Ooo / I1Ii111
  i1iIi1I = oOooO0Oo0Oo0 . uptime if ( oOooO0Oo0Oo0 ) else None
  oOooO0Oo0Oo0 = lisp_mapping ( O0OO000oOO0 . eid , O0OO000oOO0 . group , I111iIi11Ii11III )
  oOooO0Oo0Oo0 . mapping_source = source
  oOooO0Oo0Oo0 . map_cache_ttl = O0OO000oOO0 . store_ttl ( )
  oOooO0Oo0Oo0 . action = O0OO000oOO0 . action
  oOooO0Oo0Oo0 . add_cache ( OoooO )
  if 24 - 24: oO0o - oO0o
  o0000o = "Add"
  if ( i1iIi1I ) :
   oOooO0Oo0Oo0 . uptime = i1iIi1I
   o0000o = "Replace"
   if 91 - 91: iII111i % i11iIiiIii * OoOoOO00 * i11iIiiIii % iIii1I11I1II1
   if 30 - 30: I11i . I1ii11iIi11i - i1IIi / i1IIi + IiII . oO0o
  lprint ( "{} {} map-cache with {} RLOCs" . format ( o0000o ,
 green ( oOooO0Oo0Oo0 . print_eid_tuple ( ) , False ) , len ( I111iIi11Ii11III ) ) )
  if 70 - 70: i1IIi . I11i * o0oOOo0O0Ooo . iII111i
  if 75 - 75: oO0o * OoO0O00 * I11i + oO0o + O0 . I1Ii111
  if 8 - 8: I1ii11iIi11i / i1IIi - I1ii11iIi11i + Ii1I + OoO0O00 - I11i
  if 79 - 79: OoooooooOO - I1Ii111 * I1IiiI . I1Ii111 - iIii1I11I1II1
  if 27 - 27: OoOoOO00 % OoOoOO00 % II111iiii
  if ( lisp_ipc_dp_socket and Iiii11iiiI1 != None ) :
   lisp_write_ipc_keys ( Iiii11iiiI1 )
   if 45 - 45: iIii1I11I1II1 . o0oOOo0O0Ooo % I1IiiI
   if 10 - 10: I1IiiI / i1IIi * o0oOOo0O0Ooo + Oo0Ooo - OoOoOO00 % iII111i
   if 88 - 88: Ii1I % Ii1I
   if 29 - 29: OOooOOo % I1ii11iIi11i
   if 57 - 57: I1ii11iIi11i - OoOoOO00 + IiII
   if 58 - 58: OOooOOo % I1IiiI / oO0o . ooOoO0o . OoO0O00 / IiII
   if 72 - 72: ooOoO0o + ooOoO0o + o0oOOo0O0Ooo - o0oOOo0O0Ooo % Ii1I
  if ( IIIiii1 ) :
   o0ooOOoO0O = bold ( "RLOC-probe" , False )
   for oOoOoo0O in oOooO0Oo0Oo0 . best_rloc_set :
    OoOOoooO000 = red ( oOoOoo0O . rloc . print_address_no_iid ( ) , False )
    lprint ( "Trigger {} to {}" . format ( o0ooOOoO0O , OoOOoooO000 ) )
    lisp_send_map_request ( lisp_sockets , 0 , oOooO0Oo0Oo0 . eid , oOooO0Oo0Oo0 . group , oOoOoo0O )
    if 71 - 71: I11i
    if 34 - 34: oO0o / O0 * oO0o
    if 47 - 47: iIii1I11I1II1 - o0oOOo0O0Ooo % Ii1I
 return
 if 38 - 38: ooOoO0o / IiII * I1ii11iIi11i % I1ii11iIi11i % oO0o
 if 82 - 82: I1ii11iIi11i . i11iIiiIii - I11i . iII111i / OOooOOo
 if 60 - 60: I1IiiI / I1IiiI / II111iiii
 if 59 - 59: OOooOOo . oO0o + ooOoO0o % o0oOOo0O0Ooo . i11iIiiIii
 if 27 - 27: OoOoOO00 - OoooooooOO / IiII / II111iiii * OOooOOo * ooOoO0o
 if 43 - 43: II111iiii . IiII - I1IiiI * I1ii11iIi11i + OoooooooOO
 if 34 - 34: I1Ii111 / i1IIi
 if 95 - 95: OoOoOO00 * OOooOOo
def lisp_compute_auth ( packet , map_register , password ) :
 if ( map_register . alg_id == LISP_NONE_ALG_ID ) : return ( packet )
 if 68 - 68: I1Ii111 / iIii1I11I1II1 % Ii1I
 packet = map_register . zero_auth ( packet )
 OoOoo00Oo0OoO = lisp_hash_me ( packet , map_register . alg_id , password , False )
 if 77 - 77: i11iIiiIii + i11iIiiIii - I1ii11iIi11i % I1ii11iIi11i
 if 26 - 26: oO0o + OoooooooOO % o0oOOo0O0Ooo
 if 96 - 96: ooOoO0o * OoOoOO00 - II111iiii
 if 40 - 40: oO0o * OOooOOo + Ii1I + I11i * Ii1I + OoooooooOO
 map_register . auth_data = OoOoo00Oo0OoO
 packet = map_register . encode_auth ( packet )
 return ( packet )
 if 77 - 77: OOooOOo + ooOoO0o / O0
 if 16 - 16: ooOoO0o + Oo0Ooo * Oo0Ooo . I11i - IiII
 if 49 - 49: ooOoO0o . Ii1I
 if 75 - 75: OOooOOo / II111iiii - Oo0Ooo + I1Ii111
 if 42 - 42: OoooooooOO * II111iiii + Ii1I % OoO0O00 / I1Ii111
 if 11 - 11: ooOoO0o / Oo0Ooo + i1IIi / IiII
 if 4 - 4: iII111i - Oo0Ooo
def lisp_hash_me ( packet , alg_id , password , do_hex ) :
 if ( alg_id == LISP_NONE_ALG_ID ) : return ( True )
 if 100 - 100: OOooOOo . i1IIi
 if ( alg_id == LISP_SHA_1_96_ALG_ID ) :
  Ii1IiI1111i = hashlib . sha1
  if 31 - 31: i1IIi . Ii1I - OoooooooOO * I11i * ooOoO0o % oO0o
 if ( alg_id == LISP_SHA_256_128_ALG_ID ) :
  Ii1IiI1111i = hashlib . sha256
  if 61 - 61: I1Ii111 . Ii1I * I1ii11iIi11i
  if 59 - 59: OoOoOO00 + Oo0Ooo . I1ii11iIi11i - Ii1I
 if ( do_hex ) :
  OoOoo00Oo0OoO = hmac . new ( password , packet , Ii1IiI1111i ) . hexdigest ( )
 else :
  OoOoo00Oo0OoO = hmac . new ( password , packet , Ii1IiI1111i ) . digest ( )
  if 48 - 48: I1Ii111 % Ii1I + I1IiiI * OoooooooOO % OoOoOO00 % i11iIiiIii
 return ( OoOoo00Oo0OoO )
 if 13 - 13: iII111i % i1IIi
 if 13 - 13: iII111i / OoooooooOO + Ii1I / iII111i
 if 29 - 29: OOooOOo + ooOoO0o % o0oOOo0O0Ooo
 if 18 - 18: I11i + OoO0O00 + OoO0O00 . ooOoO0o
 if 37 - 37: i1IIi . IiII + I1IiiI % OoOoOO00
 if 3 - 3: i11iIiiIii + Ii1I % IiII - I1Ii111 / Oo0Ooo % iIii1I11I1II1
 if 86 - 86: Oo0Ooo + Oo0Ooo * oO0o * I1IiiI
 if 95 - 95: IiII - OoO0O00 + OOooOOo
def lisp_verify_auth ( packet , alg_id , auth_data , password ) :
 if ( alg_id == LISP_NONE_ALG_ID ) : return ( True )
 if 33 - 33: o0oOOo0O0Ooo . i11iIiiIii . ooOoO0o
 OoOoo00Oo0OoO = lisp_hash_me ( packet , alg_id , password , True )
 OoO0OOo0Oo = ( OoOoo00Oo0OoO == auth_data )
 if 68 - 68: I1IiiI - i11iIiiIii . I1ii11iIi11i * OOooOOo
 if 43 - 43: II111iiii % O0 + o0oOOo0O0Ooo / Ii1I
 if 55 - 55: Oo0Ooo / Oo0Ooo - I1IiiI
 if 94 - 94: OoO0O00 % I11i
 if ( OoO0OOo0Oo == False ) :
  lprint ( "Hashed value: {} does not match packet value: {}" . format ( OoOoo00Oo0OoO , auth_data ) )
  if 41 - 41: I1ii11iIi11i * IiII
  if 16 - 16: I1Ii111 % iIii1I11I1II1 / I1IiiI * OoOoOO00 / IiII / OoOoOO00
 return ( OoO0OOo0Oo )
 if 29 - 29: OoooooooOO / oO0o
 if 1 - 1: OoOoOO00 . i11iIiiIii % I1Ii111 + OoooooooOO - Oo0Ooo . I1ii11iIi11i
 if 46 - 46: i11iIiiIii + I11i - iIii1I11I1II1 / OoO0O00 - ooOoO0o / i1IIi
 if 44 - 44: o0oOOo0O0Ooo + Oo0Ooo
 if 46 - 46: OOooOOo % I1IiiI
 if 66 - 66: iIii1I11I1II1 . o0oOOo0O0Ooo - ooOoO0o
 if 27 - 27: Oo0Ooo - i1IIi * OoooooooOO - OoOoOO00 + OoOoOO00
def lisp_retransmit_map_notify ( map_notify ) :
 I1I1I1 = map_notify . etr
 i1O0OO = map_notify . etr_port
 if 24 - 24: i1IIi . OoOoOO00 / I1Ii111 + O0
 if 86 - 86: Ii1I * OoOoOO00 % I1ii11iIi11i + OOooOOo
 if 85 - 85: iII111i % i11iIiiIii
 if 78 - 78: i11iIiiIii / I11i / Oo0Ooo + II111iiii - I1ii11iIi11i / I1ii11iIi11i
 if 28 - 28: iIii1I11I1II1 / IiII - iIii1I11I1II1 . i1IIi - O0 * ooOoO0o
 if ( map_notify . retry_count == LISP_MAX_MAP_NOTIFY_RETRIES ) :
  lprint ( "Map-Notify with nonce 0x{} retry limit reached for ETR {}" . format ( map_notify . nonce_key , red ( I1I1I1 . print_address ( ) , False ) ) )
  if 41 - 41: Ii1I + IiII
  if 37 - 37: I1Ii111 / o0oOOo0O0Ooo - ooOoO0o - OoooooooOO . I1ii11iIi11i % I1Ii111
  iIIIi = map_notify . nonce_key
  if ( lisp_map_notify_queue . has_key ( iIIIi ) ) :
   map_notify . retransmit_timer . cancel ( )
   lprint ( "Dequeue Map-Notify from retransmit queue, key is: {}" . format ( iIIIi ) )
   if 53 - 53: I1IiiI % OOooOOo + Ii1I - Ii1I
   try :
    lisp_map_notify_queue . pop ( iIIIi )
   except :
    lprint ( "Key not found in Map-Notify queue" )
    if 99 - 99: i1IIi * OoOoOO00 - i1IIi
    if 65 - 65: OoO0O00 / i11iIiiIii + I1ii11iIi11i + OoOoOO00
  return
  if 82 - 82: Ii1I * OOooOOo % ooOoO0o / OoO0O00 - Oo0Ooo . I1Ii111
  if 90 - 90: I11i * i11iIiiIii % i1IIi + I1Ii111 / OoO0O00
 O00O0o = map_notify . lisp_sockets
 map_notify . retry_count += 1
 if 15 - 15: Oo0Ooo + oO0o . I11i % OoO0O00
 lprint ( "Retransmit {} with nonce 0x{} to xTR {}, retry {}" . format ( bold ( "Map-Notify" , False ) , map_notify . nonce_key ,
 # OoOoOO00
 red ( I1I1I1 . print_address ( ) , False ) , map_notify . retry_count ) )
 if 32 - 32: ooOoO0o * OoO0O00 * oO0o / I1ii11iIi11i
 lisp_send_map_notify ( O00O0o , map_notify . packet , I1I1I1 , i1O0OO )
 if ( map_notify . site ) : map_notify . site . map_notifies_sent += 1
 if 72 - 72: I1ii11iIi11i * ooOoO0o % I1IiiI % OoOoOO00
 if 72 - 72: iII111i % I11i + oO0o + o0oOOo0O0Ooo . IiII
 if 95 - 95: OoOoOO00
 if 70 - 70: O0
 map_notify . retransmit_timer = threading . Timer ( LISP_MAP_NOTIFY_INTERVAL ,
 lisp_retransmit_map_notify , [ map_notify ] )
 map_notify . retransmit_timer . start ( )
 return
 if 19 - 19: oO0o
 if 45 - 45: iIii1I11I1II1
 if 11 - 11: OoO0O00 / I1Ii111 . OoOoOO00
 if 95 - 95: I1ii11iIi11i / Ii1I % ooOoO0o . OoooooooOO % OoOoOO00 . OoOoOO00
 if 1 - 1: I1ii11iIi11i % o0oOOo0O0Ooo % i11iIiiIii - OOooOOo - ooOoO0o - OoO0O00
 if 94 - 94: OoO0O00 . Oo0Ooo / OoO0O00 + I1Ii111
 if 48 - 48: I1ii11iIi11i * i1IIi + I1Ii111
def lisp_send_merged_map_notify ( lisp_sockets , parent , map_register ,
 eid_record ) :
 if 80 - 80: I1IiiI % I11i
 if 64 - 64: OOooOOo + i11iIiiIii + I1IiiI . I11i % I11i - o0oOOo0O0Ooo
 if 3 - 3: I1IiiI / i1IIi + II111iiii + Oo0Ooo
 if 48 - 48: o0oOOo0O0Ooo
 eid_record . rloc_count = len ( parent . registered_rlocs )
 IiI1iiIi1I1i = eid_record . encode ( )
 eid_record . print_record ( "Merged Map-Notify " , False )
 if 35 - 35: OoO0O00 + II111iiii / I11i
 if 45 - 45: i11iIiiIii . I1IiiI % I1Ii111 / I1ii11iIi11i
 if 14 - 14: IiII . OOooOOo - Oo0Ooo * oO0o
 if 31 - 31: I1IiiI + OOooOOo
 for O0oOoooooO00o in parent . registered_rlocs :
  o0oooOOOOO0oo = lisp_rloc_record ( )
  o0oooOOOOO0oo . store_rloc_entry ( O0oOoooooO00o )
  IiI1iiIi1I1i += o0oooOOOOO0oo . encode ( )
  o0oooOOOOO0oo . print_record ( "  " )
  del ( o0oooOOOOO0oo )
  if 4 - 4: O0 / II111iiii % OoooooooOO - oO0o / Ii1I
  if 64 - 64: i1IIi + Ii1I - II111iiii % I1Ii111 / I11i
  if 2 - 2: I11i * o0oOOo0O0Ooo * OoOoOO00 % I1IiiI . I1IiiI
  if 69 - 69: O0 % I1Ii111 - i1IIi
  if 50 - 50: I1ii11iIi11i
 for O0oOoooooO00o in parent . registered_rlocs :
  I1I1I1 = O0oOoooooO00o . rloc
  O00o0oOoO0OOo = lisp_map_notify ( lisp_sockets )
  O00o0oOoO0OOo . record_count = 1
  oO0O0oo = map_register . key_id
  O00o0oOoO0OOo . key_id = oO0O0oo
  O00o0oOoO0OOo . alg_id = map_register . alg_id
  O00o0oOoO0OOo . auth_len = map_register . auth_len
  O00o0oOoO0OOo . nonce = map_register . nonce
  O00o0oOoO0OOo . nonce_key = lisp_hex_string ( O00o0oOoO0OOo . nonce )
  O00o0oOoO0OOo . etr . copy_address ( I1I1I1 )
  O00o0oOoO0OOo . etr_port = map_register . sport
  O00o0oOoO0OOo . site = parent . site
  I1IiO00Ooo0ooo0 = O00o0oOoO0OOo . encode ( IiI1iiIi1I1i , parent . site . auth_key [ oO0O0oo ] )
  O00o0oOoO0OOo . print_notify ( )
  if 26 - 26: ooOoO0o + Oo0Ooo
  if 24 - 24: I1IiiI
  if 43 - 43: OoO0O00
  if 51 - 51: OoooooooOO % IiII % Oo0Ooo
  iIIIi = O00o0oOoO0OOo . nonce_key
  if ( lisp_map_notify_queue . has_key ( iIIIi ) ) :
   IiiiiII1i = lisp_map_notify_queue [ iIIIi ]
   IiiiiII1i . retransmit_timer . cancel ( )
   del ( IiiiiII1i )
   if 91 - 91: I1IiiI . I1Ii111 + II111iiii . Oo0Ooo
  lisp_map_notify_queue [ iIIIi ] = O00o0oOoO0OOo
  if 95 - 95: iII111i
  if 77 - 77: I1IiiI * II111iiii * iIii1I11I1II1
  if 19 - 19: OOooOOo * o0oOOo0O0Ooo
  if 64 - 64: I11i % ooOoO0o / OOooOOo / iII111i
  lprint ( "Send merged Map-Notify to ETR {}" . format ( red ( I1I1I1 . print_address ( ) , False ) ) )
  if 80 - 80: i1IIi
  lisp_send ( lisp_sockets , I1I1I1 , LISP_CTRL_PORT , I1IiO00Ooo0ooo0 )
  if 74 - 74: I1ii11iIi11i . OoO0O00 + i11iIiiIii
  parent . site . map_notifies_sent += 1
  if 19 - 19: i1IIi / I1IiiI + IiII . iII111i
  if 68 - 68: iII111i
  if 29 - 29: II111iiii / II111iiii % OoO0O00 % Oo0Ooo . II111iiii
  if 33 - 33: OoooooooOO . OoO0O00 % OoooooooOO
  O00o0oOoO0OOo . retransmit_timer = threading . Timer ( LISP_MAP_NOTIFY_INTERVAL ,
 lisp_retransmit_map_notify , [ O00o0oOoO0OOo ] )
  O00o0oOoO0OOo . retransmit_timer . start ( )
  if 9 - 9: IiII * O0 + OOooOOo . II111iiii
 return
 if 14 - 14: iIii1I11I1II1 + i11iIiiIii + o0oOOo0O0Ooo + o0oOOo0O0Ooo - IiII / I1Ii111
 if 70 - 70: OoooooooOO + I1IiiI / OOooOOo
 if 19 - 19: I1Ii111 + i1IIi % OoooooooOO + i1IIi
 if 16 - 16: I1Ii111 + II111iiii + IiII
 if 34 - 34: iIii1I11I1II1 - II111iiii - ooOoO0o + oO0o
 if 46 - 46: ooOoO0o % II111iiii
 if 61 - 61: OoO0O00 . I1IiiI
def lisp_build_map_notify ( lisp_sockets , eid_records , eid_list , record_count ,
 source , port , nonce , key_id , alg_id , auth_len , site , map_register_ack ) :
 if 89 - 89: IiII
 iIIIi = lisp_hex_string ( nonce ) + source . print_address ( )
 if 73 - 73: II111iiii + ooOoO0o % OOooOOo . oO0o / oO0o * i1IIi
 if 19 - 19: I1Ii111 + I11i
 if 21 - 21: OoOoOO00
 if 2 - 2: i1IIi . OOooOOo
 if 23 - 23: Ii1I - OOooOOo
 if 89 - 89: i11iIiiIii
 lisp_remove_eid_from_map_notify_queue ( eid_list )
 if ( lisp_map_notify_queue . has_key ( iIIIi ) ) :
  O00o0oOoO0OOo = lisp_map_notify_queue [ iIIIi ]
  i1I1iIi1IiI = red ( source . print_address_no_iid ( ) , False )
  lprint ( "Map-Notify with nonce 0x{} pending for xTR {}" . format ( lisp_hex_string ( O00o0oOoO0OOo . nonce ) , i1I1iIi1IiI ) )
  if 40 - 40: OoooooooOO % OoO0O00
  return
  if 54 - 54: i1IIi * OOooOOo - oO0o * OoooooooOO + II111iiii . IiII
  if 90 - 90: O0 - II111iiii + I1IiiI . iII111i
 O00o0oOoO0OOo = lisp_map_notify ( lisp_sockets )
 O00o0oOoO0OOo . record_count = record_count
 key_id = key_id
 O00o0oOoO0OOo . key_id = key_id
 O00o0oOoO0OOo . alg_id = alg_id
 O00o0oOoO0OOo . auth_len = auth_len
 O00o0oOoO0OOo . nonce = nonce
 O00o0oOoO0OOo . nonce_key = lisp_hex_string ( nonce )
 O00o0oOoO0OOo . etr . copy_address ( source )
 O00o0oOoO0OOo . etr_port = port
 O00o0oOoO0OOo . site = site
 O00o0oOoO0OOo . eid_list = eid_list
 if 3 - 3: o0oOOo0O0Ooo + i1IIi * Oo0Ooo
 if 6 - 6: OoO0O00 * OoooooooOO * iIii1I11I1II1
 if 87 - 87: iIii1I11I1II1 - ooOoO0o * iIii1I11I1II1
 if 79 - 79: ooOoO0o . oO0o + Ii1I * ooOoO0o + O0 . II111iiii
 if ( map_register_ack == False ) :
  iIIIi = O00o0oOoO0OOo . nonce_key
  lisp_map_notify_queue [ iIIIi ] = O00o0oOoO0OOo
  if 8 - 8: IiII * OOooOOo + I11i + O0 * oO0o - oO0o
  if 19 - 19: OoO0O00 - ooOoO0o + I1ii11iIi11i / I1ii11iIi11i % I1Ii111 % iIii1I11I1II1
 if ( map_register_ack ) :
  lprint ( "Send Map-Notify to ack Map-Register" )
 else :
  lprint ( "Send Map-Notify for RLOC-set change" )
  if 5 - 5: OoooooooOO + ooOoO0o - II111iiii . i11iIiiIii / oO0o - ooOoO0o
  if 3 - 3: iII111i
  if 74 - 74: i11iIiiIii + OoooooooOO . OOooOOo
  if 29 - 29: IiII % OoO0O00
  if 53 - 53: OoooooooOO - OoOoOO00 / IiII - I1Ii111
 I1IiO00Ooo0ooo0 = O00o0oOoO0OOo . encode ( eid_records , site . auth_key [ key_id ] )
 O00o0oOoO0OOo . print_notify ( )
 if 16 - 16: iIii1I11I1II1 / OOooOOo + I1IiiI * II111iiii . OOooOOo
 if ( map_register_ack == False ) :
  O0OO000oOO0 = lisp_eid_record ( )
  O0OO000oOO0 . decode ( eid_records )
  O0OO000oOO0 . print_record ( "  " , False )
  if 68 - 68: IiII * IiII + oO0o / o0oOOo0O0Ooo
  if 41 - 41: OoOoOO00 - O0
  if 48 - 48: OoooooooOO % Ii1I * OoO0O00 / I1ii11iIi11i
  if 53 - 53: ooOoO0o + oO0o - II111iiii
  if 92 - 92: Oo0Ooo - I11i . ooOoO0o % oO0o
 lisp_send_map_notify ( lisp_sockets , I1IiO00Ooo0ooo0 , O00o0oOoO0OOo . etr , port )
 site . map_notifies_sent += 1
 if 6 - 6: iIii1I11I1II1 + oO0o
 if ( map_register_ack ) : return
 if 8 - 8: I1ii11iIi11i + o0oOOo0O0Ooo
 if 29 - 29: Ii1I . OOooOOo
 if 59 - 59: O0 . OoO0O00
 if 10 - 10: I1Ii111 / OoooooooOO / OoO0O00 * ooOoO0o
 if 81 - 81: i1IIi % I11i * iIii1I11I1II1
 if 39 - 39: iIii1I11I1II1 / O0 . OoooooooOO - O0 . OoO0O00 . oO0o
 O00o0oOoO0OOo . retransmit_timer = threading . Timer ( LISP_MAP_NOTIFY_INTERVAL ,
 lisp_retransmit_map_notify , [ O00o0oOoO0OOo ] )
 O00o0oOoO0OOo . retransmit_timer . start ( )
 return
 if 59 - 59: II111iiii * I1IiiI
 if 12 - 12: i11iIiiIii - IiII . iII111i . Ii1I
 if 34 - 34: i1IIi % iII111i + Oo0Ooo * OoOoOO00 + OoO0O00
 if 37 - 37: I1Ii111 / OoooooooOO
 if 19 - 19: Ii1I - O0 + I1IiiI + OoooooooOO + ooOoO0o - Oo0Ooo
 if 45 - 45: I1IiiI . OoOoOO00 . OoOoOO00
 if 20 - 20: OoOoOO00
 if 69 - 69: OoOoOO00 * Ii1I % ooOoO0o . OoOoOO00 / oO0o * I1Ii111
def lisp_send_map_notify_ack ( lisp_sockets , eid_records , map_notify , ms ) :
 map_notify . map_notify_ack = True
 if 93 - 93: OoO0O00 % IiII % ooOoO0o . I1IiiI
 if 96 - 96: II111iiii
 if 73 - 73: II111iiii
 if 81 - 81: I1IiiI + OoO0O00
 I1IiO00Ooo0ooo0 = map_notify . encode ( eid_records , ms . password )
 map_notify . print_notify ( )
 if 22 - 22: OoO0O00 * OoOoOO00 * I11i * IiII . OoO0O00 . I1ii11iIi11i
 if 32 - 32: o0oOOo0O0Ooo - iII111i + i11iIiiIii / ooOoO0o . OoOoOO00 . IiII
 if 9 - 9: iIii1I11I1II1
 if 66 - 66: iIii1I11I1II1
 I1I1I1 = ms . map_server
 lprint ( "Send Map-Notify-Ack to {}" . format (
 red ( I1I1I1 . print_address ( ) , False ) ) )
 lisp_send ( lisp_sockets , I1I1I1 , LISP_CTRL_PORT , I1IiO00Ooo0ooo0 )
 return
 if 13 - 13: O0 / ooOoO0o
 if 64 - 64: i11iIiiIii + I1IiiI / Oo0Ooo - iII111i
 if 26 - 26: I1ii11iIi11i
 if 67 - 67: I1Ii111 * iIii1I11I1II1 / O0 + OoO0O00 * iIii1I11I1II1 % II111iiii
 if 13 - 13: Ii1I / ooOoO0o / iII111i % II111iiii * I1IiiI * II111iiii
 if 40 - 40: Ii1I / i1IIi . iII111i
 if 65 - 65: iIii1I11I1II1 * O0 . II111iiii * o0oOOo0O0Ooo . I1ii11iIi11i * I1IiiI
 if 63 - 63: II111iiii . Oo0Ooo % iIii1I11I1II1
def lisp_send_multicast_map_notify ( lisp_sockets , site_eid , eid_list , xtr ) :
 if 85 - 85: I1IiiI + i1IIi % I1Ii111
 O00o0oOoO0OOo = lisp_map_notify ( lisp_sockets )
 O00o0oOoO0OOo . record_count = 1
 O00o0oOoO0OOo . nonce = lisp_get_control_nonce ( )
 O00o0oOoO0OOo . nonce_key = lisp_hex_string ( O00o0oOoO0OOo . nonce )
 O00o0oOoO0OOo . etr . copy_address ( xtr )
 O00o0oOoO0OOo . etr_port = LISP_CTRL_PORT
 O00o0oOoO0OOo . eid_list = eid_list
 iIIIi = O00o0oOoO0OOo . nonce_key
 if 76 - 76: i11iIiiIii % i11iIiiIii
 if 33 - 33: OOooOOo . ooOoO0o / iIii1I11I1II1 * OOooOOo / oO0o
 if 75 - 75: Ii1I - OoOoOO00 . OOooOOo - o0oOOo0O0Ooo - I1ii11iIi11i
 if 69 - 69: O0 % I1ii11iIi11i
 if 77 - 77: iIii1I11I1II1 . OOooOOo
 if 64 - 64: OoOoOO00 - i1IIi * i1IIi / iII111i * OoOoOO00 * OoO0O00
 lisp_remove_eid_from_map_notify_queue ( O00o0oOoO0OOo . eid_list )
 if ( lisp_map_notify_queue . has_key ( iIIIi ) ) :
  O00o0oOoO0OOo = lisp_map_notify_queue [ iIIIi ]
  lprint ( "Map-Notify with nonce 0x{} pending for ITR {}" . format ( O00o0oOoO0OOo . nonce , red ( xtr . print_address_no_iid ( ) , False ) ) )
  if 61 - 61: OOooOOo
  return
  if 51 - 51: Oo0Ooo * OOooOOo / iII111i
  if 49 - 49: ooOoO0o . i1IIi % I1Ii111 . I1IiiI . I1ii11iIi11i + OoO0O00
  if 65 - 65: I1ii11iIi11i + Ii1I / i11iIiiIii * I1Ii111 + OoooooooOO
  if 7 - 7: Oo0Ooo % o0oOOo0O0Ooo
  if 40 - 40: oO0o * IiII
 lisp_map_notify_queue [ iIIIi ] = O00o0oOoO0OOo
 if 29 - 29: O0 - II111iiii + iII111i
 if 73 - 73: I1Ii111 - I11i + IiII - o0oOOo0O0Ooo - I11i - OOooOOo
 if 40 - 40: iIii1I11I1II1 . iII111i * I1ii11iIi11i + IiII - iIii1I11I1II1
 if 83 - 83: i1IIi
 iii11II = site_eid . rtrs_in_rloc_set ( )
 if ( iii11II ) :
  if ( site_eid . is_rtr_in_rloc_set ( xtr ) ) : iii11II = False
  if 76 - 76: OOooOOo + ooOoO0o % II111iiii
  if 19 - 19: I11i + i1IIi / i1IIi - II111iiii + I1Ii111
  if 11 - 11: i11iIiiIii % i11iIiiIii / IiII - Oo0Ooo / O0 - I11i
  if 29 - 29: OOooOOo * iIii1I11I1II1 * ooOoO0o
  if 80 - 80: oO0o * I1Ii111
 O0OO000oOO0 = lisp_eid_record ( )
 O0OO000oOO0 . record_ttl = 1440
 O0OO000oOO0 . eid . copy_address ( site_eid . eid )
 O0OO000oOO0 . group . copy_address ( site_eid . group )
 O0OO000oOO0 . rloc_count = 0
 for iIIiIiiI in site_eid . registered_rlocs :
  if ( iii11II ^ iIIiIiiI . is_rtr ( ) ) : continue
  O0OO000oOO0 . rloc_count += 1
  if 87 - 87: iII111i + OoOoOO00 % ooOoO0o - oO0o
 I1IiO00Ooo0ooo0 = O0OO000oOO0 . encode ( )
 if 40 - 40: i1IIi / OoOoOO00 - I11i / ooOoO0o . Ii1I
 if 8 - 8: I1IiiI . IiII . OOooOOo . O0
 if 3 - 3: Ii1I + i11iIiiIii
 if 87 - 87: ooOoO0o - iII111i % I11i
 O00o0oOoO0OOo . print_notify ( )
 O0OO000oOO0 . print_record ( "  " , False )
 if 88 - 88: I11i . OoooooooOO
 if 86 - 86: Ii1I - I1IiiI - iII111i % Ii1I . I1ii11iIi11i % i1IIi
 if 84 - 84: OoOoOO00
 if 99 - 99: OoO0O00 - OoOoOO00 - i1IIi / OoO0O00 * I1ii11iIi11i * iIii1I11I1II1
 for iIIiIiiI in site_eid . registered_rlocs :
  if ( iii11II ^ iIIiIiiI . is_rtr ( ) ) : continue
  o0oooOOOOO0oo = lisp_rloc_record ( )
  o0oooOOOOO0oo . store_rloc_entry ( iIIiIiiI )
  I1IiO00Ooo0ooo0 += o0oooOOOOO0oo . encode ( )
  o0oooOOOOO0oo . print_record ( "    " )
  if 65 - 65: iII111i - O0 / i1IIi . I1Ii111
  if 85 - 85: o0oOOo0O0Ooo % Ii1I
  if 81 - 81: oO0o / OoO0O00 * i1IIi % iIii1I11I1II1
  if 23 - 23: II111iiii . II111iiii
  if 17 - 17: i11iIiiIii / IiII * I1IiiI . Oo0Ooo / o0oOOo0O0Ooo - iIii1I11I1II1
 I1IiO00Ooo0ooo0 = O00o0oOoO0OOo . encode ( I1IiO00Ooo0ooo0 , "" )
 if ( I1IiO00Ooo0ooo0 == None ) : return
 if 21 - 21: OOooOOo % Ii1I
 if 3 - 3: OOooOOo / ooOoO0o / I1Ii111 . I11i
 if 54 - 54: I1ii11iIi11i - I1IiiI . OoOoOO00
 if 36 - 36: OoO0O00 * I1IiiI / iII111i
 lisp_send_map_notify ( lisp_sockets , I1IiO00Ooo0ooo0 , xtr , LISP_CTRL_PORT )
 if 95 - 95: Ii1I . Oo0Ooo
 if 42 - 42: IiII . i1IIi % O0 * ooOoO0o - OOooOOo % ooOoO0o
 if 99 - 99: i1IIi + OoOoOO00 - iII111i % II111iiii
 if 6 - 6: ooOoO0o - I1Ii111 . OoOoOO00
 O00o0oOoO0OOo . retransmit_timer = threading . Timer ( LISP_MAP_NOTIFY_INTERVAL ,
 lisp_retransmit_map_notify , [ O00o0oOoO0OOo ] )
 O00o0oOoO0OOo . retransmit_timer . start ( )
 return
 if 64 - 64: iII111i + I1ii11iIi11i
 if 88 - 88: I1Ii111 / i11iIiiIii - O0 . II111iiii / II111iiii * II111iiii
 if 56 - 56: Oo0Ooo / I1IiiI % I1Ii111 % I1ii11iIi11i * I1IiiI - IiII
 if 39 - 39: oO0o + iII111i . I1Ii111 * i11iIiiIii % o0oOOo0O0Ooo + OOooOOo
 if 61 - 61: ooOoO0o / I1Ii111 / I1ii11iIi11i - Ii1I % o0oOOo0O0Ooo * iII111i
 if 94 - 94: I1IiiI / I11i
 if 100 - 100: Ii1I % OoO0O00 % OoooooooOO / II111iiii * I1Ii111
def lisp_queue_multicast_map_notify ( lisp_sockets , rle_list ) :
 O00OO0oOooOOo = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
 if 74 - 74: ooOoO0o . IiII . O0 * I1IiiI * oO0o
 for OOO0oOO in rle_list :
  IiIIIiiiii1iIII = lisp_site_eid_lookup ( OOO0oOO [ 0 ] , OOO0oOO [ 1 ] , True )
  if ( IiIIIiiiii1iIII == None ) : continue
  if 80 - 80: iII111i * Oo0Ooo
  if 37 - 37: ooOoO0o
  if 56 - 56: Oo0Ooo * OoO0O00 . ooOoO0o . o0oOOo0O0Ooo
  if 70 - 70: O0 % OoooooooOO - Ii1I * Oo0Ooo
  if 18 - 18: OOooOOo . I1IiiI + i1IIi . I1IiiI
  if 3 - 3: O0 * O0 + II111iiii + OoOoOO00 * I11i % Oo0Ooo
  if 19 - 19: oO0o % IiII % OoooooooOO % I1ii11iIi11i / OoO0O00
  iiI1iIi1II1ii = IiIIIiiiii1iIII . registered_rlocs
  if ( len ( iiI1iIi1II1ii ) == 0 ) :
   O0oo = { }
   for oo00oO0 in IiIIIiiiii1iIII . individual_registrations . values ( ) :
    for iIIiIiiI in oo00oO0 . registered_rlocs :
     if ( iIIiIiiI . is_rtr ( ) == False ) : continue
     O0oo [ iIIiIiiI . rloc . print_address ( ) ] = iIIiIiiI
     if 82 - 82: I1ii11iIi11i
     if 75 - 75: I11i - II111iiii
   iiI1iIi1II1ii = O0oo . values ( )
   if 84 - 84: I1ii11iIi11i * IiII / I1IiiI - Ii1I + IiII - i1IIi
   if 98 - 98: II111iiii - iII111i % i11iIiiIii + ooOoO0o
   if 76 - 76: OOooOOo - iII111i + IiII
   if 48 - 48: I1IiiI - II111iiii
   if 15 - 15: O0
   if 54 - 54: iIii1I11I1II1
  o0O0OoO = [ ]
  Oo0oOOoO0O0o = False
  if ( IiIIIiiiii1iIII . eid . address == 0 and IiIIIiiiii1iIII . eid . mask_len == 0 ) :
   oooO0O000O0O = [ ]
   iI111i11i111 = [ ] if len ( iiI1iIi1II1ii ) == 0 else iiI1iIi1II1ii [ 0 ] . rle . rle_nodes
   if 70 - 70: II111iiii * oO0o / Ii1I
   for oOo0o in iI111i11i111 :
    o0O0OoO . append ( oOo0o . address )
    oooO0O000O0O . append ( oOo0o . address . print_address_no_iid ( ) )
    if 70 - 70: iII111i / Oo0Ooo . OoOoOO00 - II111iiii * II111iiii % I1IiiI
   lprint ( "Notify existing RLE-nodes {}" . format ( oooO0O000O0O ) )
  else :
   if 34 - 34: I1Ii111 + OOooOOo * iII111i / ooOoO0o % i11iIiiIii
   if 91 - 91: IiII * Ii1I * OOooOOo
   if 17 - 17: o0oOOo0O0Ooo + Ii1I % I1ii11iIi11i + IiII % I1Ii111 + I1ii11iIi11i
   if 100 - 100: I11i * OoO0O00 - i1IIi + iII111i * Ii1I - OoooooooOO
   if 47 - 47: o0oOOo0O0Ooo / Ii1I - iII111i * OOooOOo / i11iIiiIii
   for iIIiIiiI in iiI1iIi1II1ii :
    if ( iIIiIiiI . is_rtr ( ) ) : o0O0OoO . append ( iIIiIiiI . rloc )
    if 97 - 97: iIii1I11I1II1 + OoOoOO00 + OoOoOO00 * o0oOOo0O0Ooo
    if 14 - 14: II111iiii + I1ii11iIi11i * Oo0Ooo
    if 95 - 95: IiII + iII111i % I1IiiI
    if 18 - 18: Oo0Ooo
    if 8 - 8: O0 + iIii1I11I1II1 - O0
   Oo0oOOoO0O0o = ( len ( o0O0OoO ) != 0 )
   if ( Oo0oOOoO0O0o == False ) :
    IiIi1II1i = lisp_site_eid_lookup ( OOO0oOO [ 0 ] , O00OO0oOooOOo , False )
    if ( IiIi1II1i == None ) : continue
    if 67 - 67: O0
    for iIIiIiiI in IiIi1II1i . registered_rlocs :
     if ( iIIiIiiI . rloc . is_null ( ) ) : continue
     o0O0OoO . append ( iIIiIiiI . rloc )
     if 22 - 22: I11i / i1IIi . II111iiii % ooOoO0o / I11i - Ii1I
     if 28 - 28: O0 - Oo0Ooo
     if 58 - 58: iIii1I11I1II1 - OoooooooOO - iII111i
     if 43 - 43: ooOoO0o / o0oOOo0O0Ooo
     if 56 - 56: II111iiii * I1ii11iIi11i * O0 . iII111i . I1ii11iIi11i % I1Ii111
     if 99 - 99: Oo0Ooo - OoO0O00 + OoooooooOO - I1Ii111 - I1ii11iIi11i % i1IIi
   if ( len ( o0O0OoO ) == 0 ) :
    lprint ( "No ITRs or RTRs found for {}, Map-Notify suppressed" . format ( green ( IiIIIiiiii1iIII . print_eid_tuple ( ) , False ) ) )
    if 49 - 49: IiII % OoooooooOO / Oo0Ooo - OoOoOO00 + o0oOOo0O0Ooo / Ii1I
    continue
    if 6 - 6: I11i % IiII
    if 48 - 48: Ii1I
    if 100 - 100: OoO0O00 % I1Ii111 + OoooooooOO / OoO0O00
    if 62 - 62: IiII
    if 66 - 66: o0oOOo0O0Ooo % OOooOOo
    if 15 - 15: Ii1I % IiII + IiII % iII111i - O0 * OoooooooOO
  for O0oOoooooO00o in o0O0OoO :
   lprint ( "Build Map-Notify to {}TR {} for {}" . format ( "R" if Oo0oOOoO0O0o else "x" , red ( O0oOoooooO00o . print_address_no_iid ( ) , False ) ,
   # OoooooooOO + II111iiii + Oo0Ooo % oO0o
 green ( IiIIIiiiii1iIII . print_eid_tuple ( ) , False ) ) )
   if 6 - 6: Oo0Ooo
   O00Oo0ooo = [ IiIIIiiiii1iIII . print_eid_tuple ( ) ]
   lisp_send_multicast_map_notify ( lisp_sockets , IiIIIiiiii1iIII , O00Oo0ooo , O0oOoooooO00o )
   time . sleep ( .001 )
   if 67 - 67: i11iIiiIii
   if 3 - 3: IiII
 return
 if 47 - 47: O0
 if 60 - 60: OOooOOo / ooOoO0o + Oo0Ooo / O0 - oO0o
 if 23 - 23: I1ii11iIi11i . I1Ii111 + OOooOOo
 if 4 - 4: I1IiiI
 if 31 - 31: ooOoO0o * i1IIi . O0
 if 5 - 5: OOooOOo . I1ii11iIi11i + ooOoO0o . ooOoO0o + iII111i
 if 100 - 100: I1Ii111
 if 71 - 71: ooOoO0o * i1IIi / OoOoOO00 * i11iIiiIii - iII111i
def lisp_find_sig_in_rloc_set ( packet , rloc_count ) :
 for oO in range ( rloc_count ) :
  o0oooOOOOO0oo = lisp_rloc_record ( )
  packet = o0oooOOOOO0oo . decode ( packet , None )
  oooo00Oo000o = o0oooOOOOO0oo . json
  if ( oooo00Oo000o == None ) : continue
  if 99 - 99: Oo0Ooo / OOooOOo / OoO0O00
  try :
   oooo00Oo000o = json . loads ( oooo00Oo000o . json_string )
  except :
   lprint ( "Found corrupted JSON signature" )
   continue
   if 41 - 41: IiII - ooOoO0o
   if 28 - 28: iII111i % O0 % iII111i
  if ( oooo00Oo000o . has_key ( "signature" ) == False ) : continue
  return ( o0oooOOOOO0oo )
  if 72 - 72: Ii1I
 return ( None )
 if 96 - 96: I1IiiI . O0 / iIii1I11I1II1
 if 95 - 95: ooOoO0o * OoO0O00 % OoooooooOO % OoO0O00
 if 79 - 79: II111iiii % Ii1I * oO0o * iII111i + II111iiii
 if 51 - 51: I1IiiI + iII111i + I1IiiI / Ii1I * IiII + OOooOOo
 if 70 - 70: I11i . IiII + IiII
 if 74 - 74: Ii1I
 if 11 - 11: I1ii11iIi11i
 if 83 - 83: O0
 if 97 - 97: O0
 if 50 - 50: I1Ii111 / OoooooooOO . o0oOOo0O0Ooo + I1IiiI * i11iIiiIii
 if 28 - 28: I1Ii111 * II111iiii
 if 14 - 14: iIii1I11I1II1 / Ii1I + o0oOOo0O0Ooo . iII111i % iII111i . i1IIi
 if 67 - 67: IiII * II111iiii + ooOoO0o - i11iIiiIii
 if 15 - 15: I11i
 if 67 - 67: iIii1I11I1II1
 if 91 - 91: ooOoO0o
 if 66 - 66: OOooOOo
 if 5 - 5: i1IIi * OoOoOO00 + i1IIi % I11i
 if 79 - 79: OOooOOo % iIii1I11I1II1 / OoOoOO00
def lisp_get_eid_hash ( eid ) :
 iIi1I1i11iI = None
 for i1IIIII1 in lisp_eid_hashes :
  if 44 - 44: oO0o % iII111i . I1ii11iIi11i
  if 24 - 24: i1IIi . I1ii11iIi11i * Oo0Ooo . OoOoOO00
  if 18 - 18: i1IIi + iII111i + I1Ii111
  if 29 - 29: OOooOOo * OOooOOo . I1ii11iIi11i . iII111i % OOooOOo
  IIiI1i = i1IIIII1 . instance_id
  if ( IIiI1i == - 1 ) : i1IIIII1 . instance_id = eid . instance_id
  if 63 - 63: iII111i - o0oOOo0O0Ooo * OOooOOo . Ii1I . Ii1I
  iiI = eid . is_more_specific ( i1IIIII1 )
  i1IIIII1 . instance_id = IIiI1i
  if ( iiI ) :
   iIi1I1i11iI = 128 - i1IIIII1 . mask_len
   break
   if 4 - 4: i11iIiiIii % OoO0O00 . oO0o
   if 72 - 72: i1IIi + I1Ii111 . oO0o * oO0o * I1IiiI
 if ( iIi1I1i11iI == None ) : return ( None )
 if 40 - 40: OoO0O00 % ooOoO0o + iII111i + IiII + I11i * Oo0Ooo
 i1i1Ii1Ii = eid . address
 o0OO00 = ""
 for oO in range ( 0 , iIi1I1i11iI / 16 ) :
  I1Iii1I = i1i1Ii1Ii & 0xffff
  I1Iii1I = hex ( I1Iii1I ) [ 2 : - 1 ]
  o0OO00 = I1Iii1I . zfill ( 4 ) + ":" + o0OO00
  i1i1Ii1Ii >>= 16
  if 62 - 62: Oo0Ooo * iII111i
 if ( iIi1I1i11iI % 16 != 0 ) :
  I1Iii1I = i1i1Ii1Ii & 0xff
  I1Iii1I = hex ( I1Iii1I ) [ 2 : - 1 ]
  o0OO00 = I1Iii1I . zfill ( 2 ) + ":" + o0OO00
  if 100 - 100: II111iiii + I1ii11iIi11i - iII111i * I1Ii111 % OoOoOO00 * O0
 return ( o0OO00 [ 0 : - 1 ] )
 if 85 - 85: II111iiii - O0 . i11iIiiIii . o0oOOo0O0Ooo + ooOoO0o - ooOoO0o
 if 25 - 25: I1ii11iIi11i % Ii1I * O0 / I1IiiI % OOooOOo
 if 42 - 42: IiII - IiII - I1ii11iIi11i + i1IIi * Oo0Ooo
 if 80 - 80: oO0o + O0
 if 84 - 84: i1IIi - II111iiii
 if 2 - 2: i11iIiiIii - OoO0O00 * Oo0Ooo
 if 100 - 100: I1Ii111
 if 5 - 5: IiII % oO0o . I1IiiI * II111iiii + o0oOOo0O0Ooo / Ii1I
 if 55 - 55: Oo0Ooo / o0oOOo0O0Ooo
 if 51 - 51: I1IiiI + i11iIiiIii / ooOoO0o % I1IiiI + Oo0Ooo
 if 6 - 6: OoOoOO00 . O0
def lisp_lookup_public_key ( eid ) :
 IIiI1i = eid . instance_id
 if 44 - 44: ooOoO0o % I11i + ooOoO0o . oO0o
 if 70 - 70: O0 - I11i . iIii1I11I1II1 % I11i . OoOoOO00 % oO0o
 if 5 - 5: O0 * OoO0O00
 if 61 - 61: Ii1I / I11i + Ii1I . IiII - OoO0O00 - o0oOOo0O0Ooo
 if 84 - 84: OoooooooOO - Oo0Ooo
 OoOOoo = lisp_get_eid_hash ( eid )
 if ( OoOOoo == None ) : return ( [ None , None , False ] )
 if 31 - 31: OoOoOO00 . II111iiii - oO0o . iII111i - I1ii11iIi11i
 OoOOoo = "hash-" + OoOOoo
 o0o0OO = lisp_address ( LISP_AFI_NAME , OoOOoo , len ( OoOOoo ) , IIiI1i )
 ooOoO00 = lisp_address ( LISP_AFI_NONE , "" , 0 , IIiI1i )
 if 90 - 90: OoooooooOO / ooOoO0o / I1IiiI
 if 70 - 70: I1IiiI
 if 74 - 74: ooOoO0o * II111iiii
 if 96 - 96: i11iIiiIii . I1IiiI - II111iiii . I11i
 IiIi1II1i = lisp_site_eid_lookup ( o0o0OO , ooOoO00 , True )
 if ( IiIi1II1i == None ) : return ( [ o0o0OO , None , False ] )
 if 79 - 79: OoO0O00 . OoOoOO00 - i1IIi + Ii1I * i11iIiiIii . OoooooooOO
 if 83 - 83: o0oOOo0O0Ooo / oO0o
 if 24 - 24: Ii1I + oO0o / OoooooooOO % i11iIiiIii
 if 1 - 1: iII111i / I1Ii111 * I1IiiI + OoOoOO00 . OoooooooOO
 i1Ii = None
 for oOoOoo0O in IiIi1II1i . registered_rlocs :
  i1I1ioOO000oo0OoO0 = oOoOoo0O . json
  if ( i1I1ioOO000oo0OoO0 == None ) : continue
  try :
   i1I1ioOO000oo0OoO0 = json . loads ( i1I1ioOO000oo0OoO0 . json_string )
  except :
   lprint ( "Registered RLOC JSON format is invalid for {}" . format ( OoOOoo ) )
   if 55 - 55: oO0o + OoOoOO00
   return ( [ o0o0OO , None , False ] )
   if 10 - 10: iIii1I11I1II1 + OOooOOo - OOooOOo * iII111i * OoO0O00
  if ( i1I1ioOO000oo0OoO0 . has_key ( "public-key" ) == False ) : continue
  i1Ii = i1I1ioOO000oo0OoO0 [ "public-key" ]
  break
  if 53 - 53: oO0o / OoO0O00 . Oo0Ooo * Ii1I . IiII * o0oOOo0O0Ooo
 return ( [ o0o0OO , i1Ii , True ] )
 if 91 - 91: I1Ii111
 if 49 - 49: I11i
 if 17 - 17: Oo0Ooo % o0oOOo0O0Ooo
 if 3 - 3: OoO0O00 . oO0o . oO0o . Ii1I
 if 100 - 100: i11iIiiIii / i1IIi . I1ii11iIi11i
 if 1 - 1: IiII * I1Ii111 / I1ii11iIi11i * i11iIiiIii
 if 82 - 82: o0oOOo0O0Ooo * OoO0O00 / o0oOOo0O0Ooo % OoOoOO00 * iIii1I11I1II1 % O0
 if 10 - 10: ooOoO0o
def lisp_verify_cga_sig ( eid , rloc_record ) :
 if 69 - 69: I11i + I1IiiI / oO0o
 if 89 - 89: i1IIi % OoOoOO00 . I1ii11iIi11i
 if 85 - 85: I1Ii111 - oO0o
 if 34 - 34: iIii1I11I1II1 / IiII + OoOoOO00 - IiII / ooOoO0o + OoOoOO00
 if 96 - 96: oO0o
 i1iiIIII = json . loads ( rloc_record . json . json_string )
 if 44 - 44: OoooooooOO / iII111i * Oo0Ooo % OoOoOO00 . oO0o
 if ( lisp_get_eid_hash ( eid ) ) :
  I1II = eid
 elif ( i1iiIIII . has_key ( "signature-eid" ) ) :
  oo0o = i1iiIIII [ "signature-eid" ]
  I1II = lisp_address ( LISP_AFI_IPV6 , oo0o , 0 , 0 )
 else :
  lprint ( "  No signature-eid found in RLOC-record" )
  return ( False )
  if 23 - 23: IiII + OoO0O00 + I1IiiI . I1Ii111 . o0oOOo0O0Ooo
  if 72 - 72: Ii1I * OoO0O00 / OoO0O00
  if 39 - 39: oO0o
  if 49 - 49: I1IiiI * I1Ii111 . I1IiiI - II111iiii
  if 57 - 57: oO0o + O0 - OoOoOO00
 o0o0OO , i1Ii , IiIii1i = lisp_lookup_public_key ( I1II )
 if ( o0o0OO == None ) :
  oo0ooooO = green ( I1II . print_address ( ) , False )
  lprint ( "  Could not parse hash in EID {}" . format ( oo0ooooO ) )
  return ( False )
  if 52 - 52: i1IIi * o0oOOo0O0Ooo + i1IIi
  if 24 - 24: i1IIi
 OoO0OOOO = "found" if IiIii1i else bold ( "not found" , False )
 oo0ooooO = green ( o0o0OO . print_address ( ) , False )
 lprint ( "  Lookup for crypto-hashed EID {} {}" . format ( oo0ooooO , OoO0OOOO ) )
 if ( IiIii1i == False ) : return ( False )
 if 90 - 90: Oo0Ooo . II111iiii + I1ii11iIi11i - OoOoOO00 / I11i * iII111i
 if ( i1Ii == None ) :
  lprint ( "  RLOC-record with public-key not found" )
  return ( False )
  if 58 - 58: oO0o + Oo0Ooo . O0
  if 8 - 8: II111iiii + iII111i + OoO0O00 - Ii1I / I1ii11iIi11i
 oOOO0o00o = i1Ii [ 0 : 8 ] + "..." + i1Ii [ - 8 : : ]
 lprint ( "  RLOC-record with public-key '{}' found" . format ( oOOO0o00o ) )
 if 6 - 6: II111iiii - OOooOOo + IiII
 if 73 - 73: OoooooooOO - I1Ii111 % iII111i / OOooOOo . o0oOOo0O0Ooo - IiII
 if 69 - 69: Ii1I . iIii1I11I1II1 / Oo0Ooo * Oo0Ooo % IiII
 if 5 - 5: OOooOOo - I1Ii111 + IiII
 if 82 - 82: OOooOOo
 I1Ii11 = i1iiIIII [ "signature" ]
 if 91 - 91: I1ii11iIi11i / I1IiiI
 try :
  i1iiIIII = binascii . a2b_base64 ( I1Ii11 )
 except :
  lprint ( "  Incorrect padding in signature string" )
  return ( False )
  if 68 - 68: OOooOOo * O0 * I1IiiI
  if 20 - 20: iII111i + ooOoO0o . i11iIiiIii
 Oo00O0OO0Oo0 = len ( i1iiIIII )
 if ( Oo00O0OO0Oo0 & 1 ) :
  lprint ( "  Signature length is odd, length {}" . format ( Oo00O0OO0Oo0 ) )
  return ( False )
  if 19 - 19: I1IiiI . I1IiiI
  if 97 - 97: iII111i % i1IIi . O0 % II111iiii * I1Ii111 / i1IIi
  if 97 - 97: ooOoO0o
  if 46 - 46: II111iiii - i1IIi
  if 72 - 72: I11i
 I111i = I1II . print_address ( )
 if 35 - 35: I1Ii111 + oO0o + II111iiii
 if 71 - 71: OoOoOO00 * OoOoOO00
 if 27 - 27: II111iiii + OoooooooOO - I11i * o0oOOo0O0Ooo
 if 67 - 67: i11iIiiIii - OoOoOO00
 i1Ii = binascii . a2b_base64 ( i1Ii )
 try :
  iIIIi = ecdsa . VerifyingKey . from_pem ( i1Ii )
 except :
  OoOoOOo = bold ( "Bad public-key" , False )
  lprint ( "  {}, not in PEM format" . format ( OoOoOOo ) )
  return ( False )
  if 38 - 38: o0oOOo0O0Ooo . OoO0O00
  if 51 - 51: Ii1I + IiII * o0oOOo0O0Ooo / I1IiiI . I1ii11iIi11i + I1ii11iIi11i
  if 37 - 37: II111iiii - ooOoO0o / Oo0Ooo * iIii1I11I1II1 . II111iiii % I1Ii111
  if 28 - 28: i11iIiiIii + OoO0O00 % O0 - I1ii11iIi11i % oO0o
  if 30 - 30: I11i + OOooOOo
  if 27 - 27: OoOoOO00 . ooOoO0o
  if 73 - 73: o0oOOo0O0Ooo
  if 8 - 8: O0
  if 40 - 40: OOooOOo . II111iiii . ooOoO0o % o0oOOo0O0Ooo
  if 22 - 22: O0 * IiII . OoO0O00
  if 63 - 63: oO0o % Oo0Ooo * OoO0O00 / II111iiii / Ii1I - ooOoO0o
 try :
  Iii11I1II1 = iIIIi . verify ( i1iiIIII , I111i , hashfunc = hashlib . sha256 )
 except :
  lprint ( "  Signature library failed for signature data '{}'" . format ( I111i ) )
  if 14 - 14: ooOoO0o . o0oOOo0O0Ooo + II111iiii
  lprint ( "  Signature used '{}'" . format ( I1Ii11 ) )
  return ( False )
  if 50 - 50: Ii1I - i1IIi * oO0o
 return ( Iii11I1II1 )
 if 52 - 52: I11i / oO0o - oO0o
 if 84 - 84: iIii1I11I1II1 - o0oOOo0O0Ooo
 if 37 - 37: iII111i * o0oOOo0O0Ooo
 if 23 - 23: ooOoO0o + OoooooooOO * iII111i . I11i
 if 2 - 2: iIii1I11I1II1 * I1ii11iIi11i - OoooooooOO
 if 93 - 93: iII111i % ooOoO0o * Oo0Ooo
 if 34 - 34: O0 * oO0o
 if 58 - 58: OOooOOo . iII111i - Oo0Ooo / iII111i . I11i
 if 86 - 86: iIii1I11I1II1 - iII111i % Ii1I
 if 18 - 18: oO0o / IiII - OOooOOo % Ii1I
def lisp_remove_eid_from_map_notify_queue ( eid_list ) :
 if 88 - 88: i11iIiiIii
 if 13 - 13: I1IiiI
 if 52 - 52: Ii1I * oO0o / I1Ii111 . IiII
 if 84 - 84: OoooooooOO - oO0o - I1Ii111
 if 69 - 69: OoOoOO00 * Ii1I % OoooooooOO % OOooOOo * OoOoOO00
 iii1IiIIIii1 = [ ]
 for I1i1I in eid_list :
  for I11II1Ii in lisp_map_notify_queue :
   O00o0oOoO0OOo = lisp_map_notify_queue [ I11II1Ii ]
   if ( I1i1I not in O00o0oOoO0OOo . eid_list ) : continue
   if 58 - 58: Ii1I % OOooOOo + OoOoOO00 * OOooOOo * I1IiiI + oO0o
   iii1IiIIIii1 . append ( I11II1Ii )
   Iii111iII1II = O00o0oOoO0OOo . retransmit_timer
   if ( Iii111iII1II ) : Iii111iII1II . cancel ( )
   if 28 - 28: OoO0O00 + oO0o * I11i % Ii1I % ooOoO0o
   lprint ( "Remove from Map-Notify queue nonce 0x{} for EID {}" . format ( O00o0oOoO0OOo . nonce_key , green ( I1i1I , False ) ) )
   if 72 - 72: II111iiii
   if 28 - 28: O0
   if 99 - 99: OoOoOO00 + OoOoOO00 % OoO0O00
   if 65 - 65: Oo0Ooo * OoooooooOO + oO0o . I1IiiI + Ii1I
   if 34 - 34: i11iIiiIii / I11i % i1IIi
   if 6 - 6: OoO0O00 * iIii1I11I1II1 % oO0o % iII111i * iII111i
   if 96 - 96: IiII * iII111i / i11iIiiIii
 for I11II1Ii in iii1IiIIIii1 : lisp_map_notify_queue . pop ( I11II1Ii )
 return
 if 21 - 21: o0oOOo0O0Ooo / OoOoOO00 . oO0o - iIii1I11I1II1 % I1Ii111 / iII111i
 if 38 - 38: iIii1I11I1II1 . OoO0O00 * iIii1I11I1II1
 if 61 - 61: OoOoOO00 * I1IiiI
 if 6 - 6: OoOoOO00
 if 84 - 84: OoO0O00 % i1IIi + ooOoO0o - OoO0O00
 if 4 - 4: i11iIiiIii + oO0o + IiII % IiII . i11iIiiIii - OOooOOo
 if 50 - 50: OoOoOO00 % o0oOOo0O0Ooo - II111iiii - i1IIi
 if 35 - 35: Oo0Ooo - ooOoO0o % OoO0O00
def lisp_decrypt_map_register ( packet ) :
 if 26 - 26: i1IIi * I1Ii111 * OoO0O00 - IiII
 if 26 - 26: Oo0Ooo - ooOoO0o . iII111i * OoOoOO00 / OoooooooOO
 if 66 - 66: I1IiiI
 if 45 - 45: II111iiii * I1Ii111 - II111iiii / I1IiiI % oO0o
 if 83 - 83: oO0o % OoO0O00 + I1ii11iIi11i / OoooooooOO % iII111i
 III1Iiii1i11 = socket . ntohl ( struct . unpack ( "I" , packet [ 0 : 4 ] ) [ 0 ] )
 iIi1ii11ii11 = ( III1Iiii1i11 >> 13 ) & 0x1
 if ( iIi1ii11ii11 == 0 ) : return ( packet )
 if 39 - 39: II111iiii . i11iIiiIii + I1IiiI + I1ii11iIi11i
 iii1I1IIi1I = ( III1Iiii1i11 >> 14 ) & 0x7
 if 8 - 8: Ii1I . O0 - iII111i - OOooOOo + iII111i - o0oOOo0O0Ooo
 if 90 - 90: O0 / OoO0O00 * O0 % OoOoOO00 + OoooooooOO
 if 61 - 61: i11iIiiIii
 if 89 - 89: i11iIiiIii - I11i % I1IiiI
 try :
  III11i1iiii = lisp_ms_encryption_keys [ iii1I1IIi1I ]
  III11i1iiii = III11i1iiii . zfill ( 32 )
  O00oO0O = "0" * 8
 except :
  lprint ( "Cannot decrypt Map-Register with key-id {}" . format ( iii1I1IIi1I ) )
  return ( None )
  if 79 - 79: I1IiiI . OoO0O00 - OOooOOo % oO0o - II111iiii + ooOoO0o
  if 62 - 62: IiII * OoooooooOO * I1ii11iIi11i + i11iIiiIii
 i1i11ii1Ii = bold ( "Decrypt" , False )
 lprint ( "{} Map-Register with key-id {}" . format ( i1i11ii1Ii , iii1I1IIi1I ) )
 if 2 - 2: i1IIi % oO0o / iIii1I11I1II1 . OoOoOO00 * O0 % I1IiiI
 oooooO00OOO = chacha . ChaCha ( III11i1iiii , O00oO0O ) . decrypt ( packet [ 4 : : ] )
 return ( packet [ 0 : 4 ] + oooooO00OOO )
 if 31 - 31: OoooooooOO + I11i - II111iiii % II111iiii % Ii1I
 if 10 - 10: iIii1I11I1II1 . I1IiiI - II111iiii + O0
 if 97 - 97: oO0o . Oo0Ooo % ooOoO0o + I1Ii111 . i11iIiiIii + Ii1I
 if 61 - 61: IiII + iII111i
 if 15 - 15: II111iiii / iIii1I11I1II1 / I1ii11iIi11i % OoOoOO00 % OoO0O00 - I1Ii111
 if 17 - 17: OoooooooOO
 if 23 - 23: OoO0O00
def lisp_process_map_register ( lisp_sockets , packet , source , sport ) :
 global lisp_registered_count
 if 26 - 26: I11i % IiII . OoooooooOO % i11iIiiIii * IiII
 if 55 - 55: I11i / I11i - IiII - I11i
 if 3 - 3: oO0o % o0oOOo0O0Ooo + OoOoOO00
 if 22 - 22: O0
 if 36 - 36: OOooOOo
 if 42 - 42: OOooOOo * ooOoO0o * i11iIiiIii + OoooooooOO . iIii1I11I1II1
 packet = lisp_decrypt_map_register ( packet )
 if ( packet == None ) : return
 if 95 - 95: i1IIi * O0 / II111iiii * OoOoOO00 * I1IiiI
 I1iIiIII = lisp_map_register ( )
 O00Ooo00 , packet = I1iIiIII . decode ( packet )
 if ( packet == None ) :
  lprint ( "Could not decode Map-Register packet" )
  return
  if 1 - 1: iII111i
 I1iIiIII . sport = sport
 if 98 - 98: o0oOOo0O0Ooo - I1ii11iIi11i
 I1iIiIII . print_map_register ( )
 if 74 - 74: OoooooooOO
 if 16 - 16: OOooOOo / iII111i - OOooOOo / OoooooooOO + oO0o
 if 80 - 80: I1IiiI % I1IiiI . Oo0Ooo
 if 94 - 94: o0oOOo0O0Ooo
 oOoo0 = True
 if ( I1iIiIII . auth_len == LISP_SHA1_160_AUTH_DATA_LEN ) :
  oOoo0 = True
  if 59 - 59: i1IIi + O0 . I1Ii111 % I11i . I1ii11iIi11i
 if ( I1iIiIII . alg_id == LISP_SHA_256_128_ALG_ID ) :
  oOoo0 = False
  if 80 - 80: I1IiiI - i11iIiiIii
  if 39 - 39: I11i / O0 - I1ii11iIi11i . Oo0Ooo * OoooooooOO / o0oOOo0O0Ooo
  if 71 - 71: O0 . OoooooooOO + Oo0Ooo . ooOoO0o / Ii1I
  if 92 - 92: I1ii11iIi11i . oO0o
  if 8 - 8: o0oOOo0O0Ooo / oO0o
 O000OOoo0o = [ ]
 if 10 - 10: ooOoO0o / i11iIiiIii % OoO0O00 % i11iIiiIii
 if 66 - 66: II111iiii - II111iiii % OoOoOO00 % iII111i % IiII / I11i
 if 50 - 50: IiII + i1IIi % I1Ii111
 if 72 - 72: I1Ii111
 iii11II1 = None
 Iii1i = packet
 OOO00oo = [ ]
 Ii111Iii11Ii11i1 = I1iIiIII . record_count
 for oO in range ( Ii111Iii11Ii11i1 ) :
  O0OO000oOO0 = lisp_eid_record ( )
  o0oooOOOOO0oo = lisp_rloc_record ( )
  packet = O0OO000oOO0 . decode ( packet )
  if ( packet == None ) :
   lprint ( "Could not decode EID-record in Map-Register packet" )
   return
   if 97 - 97: I1IiiI % O0 . OOooOOo
  O0OO000oOO0 . print_record ( "  " , False )
  if 11 - 11: o0oOOo0O0Ooo
  if 45 - 45: I11i / OoOoOO00 * o0oOOo0O0Ooo / O0 . I1IiiI
  if 82 - 82: i1IIi
  if 86 - 86: I1IiiI
  IiIi1II1i = lisp_site_eid_lookup ( O0OO000oOO0 . eid , O0OO000oOO0 . group ,
 False )
  if 87 - 87: I1ii11iIi11i + I1ii11iIi11i
  ii1oooo0ooOo = IiIi1II1i . print_eid_tuple ( ) if IiIi1II1i else None
  if 67 - 67: IiII / I1ii11iIi11i - iII111i * O0 / II111iiii * oO0o
  if 9 - 9: i11iIiiIii % iIii1I11I1II1 + i11iIiiIii + Oo0Ooo % OOooOOo
  if 58 - 58: iII111i + OOooOOo / i1IIi * ooOoO0o
  if 37 - 37: OoO0O00
  if 19 - 19: ooOoO0o
  if 4 - 4: Oo0Ooo - i1IIi . Oo0Ooo * I11i . i1IIi + OOooOOo
  if 3 - 3: IiII / iII111i * iII111i
  if ( IiIi1II1i and IiIi1II1i . accept_more_specifics == False ) :
   if ( IiIi1II1i . eid_record_matches ( O0OO000oOO0 ) == False ) :
    Ii1IIII = IiIi1II1i . parent_for_more_specifics
    if ( Ii1IIII ) : IiIi1II1i = Ii1IIII
    if 24 - 24: Ii1I
    if 23 - 23: Oo0Ooo * i1IIi / I1IiiI . I11i - I1ii11iIi11i . iIii1I11I1II1
    if 15 - 15: O0 + o0oOOo0O0Ooo / oO0o
    if 27 - 27: Ii1I * II111iiii / oO0o
    if 99 - 99: I11i + ooOoO0o % I11i + O0 - Ii1I - I1Ii111
    if 3 - 3: Oo0Ooo . I1IiiI
    if 61 - 61: OoO0O00 - I1ii11iIi11i . Ii1I * i11iIiiIii
    if 97 - 97: ooOoO0o
  oOO0ooOooOO = ( IiIi1II1i and IiIi1II1i . accept_more_specifics )
  if ( oOO0ooOooOO ) :
   O0OO0O0O0o = lisp_site_eid ( IiIi1II1i . site )
   O0OO0O0O0o . dynamic = True
   O0OO0O0O0o . eid . copy_address ( O0OO000oOO0 . eid )
   O0OO0O0O0o . group . copy_address ( O0OO000oOO0 . group )
   O0OO0O0O0o . parent_for_more_specifics = IiIi1II1i
   O0OO0O0O0o . add_cache ( )
   O0OO0O0O0o . inherit_from_ams_parent ( )
   IiIi1II1i . more_specific_registrations . append ( O0OO0O0O0o )
   IiIi1II1i = O0OO0O0O0o
  else :
   IiIi1II1i = lisp_site_eid_lookup ( O0OO000oOO0 . eid , O0OO000oOO0 . group ,
 True )
   if 15 - 15: iII111i
   if 95 - 95: i11iIiiIii . Ii1I / II111iiii + II111iiii + Ii1I / I11i
  oo0ooooO = O0OO000oOO0 . print_eid_tuple ( )
  if 72 - 72: I1Ii111 . I1Ii111 * O0 + I1ii11iIi11i / Oo0Ooo
  if ( IiIi1II1i == None ) :
   OoO0OOOOO0OO = bold ( "Site not found" , False )
   lprint ( "  {} for EID {}{}" . format ( OoO0OOOOO0OO , green ( oo0ooooO , False ) ,
 ", matched non-ams {}" . format ( green ( ii1oooo0ooOo , False ) if ii1oooo0ooOo else "" ) ) )
   if 96 - 96: oO0o . ooOoO0o * Oo0Ooo % ooOoO0o + I1Ii111 + iIii1I11I1II1
   if 45 - 45: II111iiii
   if 42 - 42: ooOoO0o
   if 62 - 62: II111iiii * o0oOOo0O0Ooo . OoO0O00 / II111iiii
   if 5 - 5: OoO0O00 + O0 . OoooooooOO + I1IiiI + i1IIi * OOooOOo
   packet = o0oooOOOOO0oo . end_of_rlocs ( packet , O0OO000oOO0 . rloc_count )
   if ( packet == None ) :
    lprint ( "  Could not decode RLOC-record in Map-Register packet" )
    return
    if 19 - 19: OoooooooOO + i11iIiiIii / II111iiii - Oo0Ooo . OOooOOo
   continue
   if 10 - 10: oO0o * Oo0Ooo
   if 55 - 55: OoO0O00 - i1IIi - I11i * oO0o
  iii11II1 = IiIi1II1i . site
  if 91 - 91: I1Ii111
  if ( oOO0ooOooOO ) :
   I1i11II = IiIi1II1i . parent_for_more_specifics . print_eid_tuple ( )
   lprint ( "  Found ams {} for site '{}' for registering prefix {}" . format ( green ( I1i11II , False ) , iii11II1 . site_name , green ( oo0ooooO , False ) ) )
   if 77 - 77: I1ii11iIi11i . ooOoO0o - iIii1I11I1II1 + Ii1I % II111iiii * II111iiii
  else :
   I1i11II = green ( IiIi1II1i . print_eid_tuple ( ) , False )
   lprint ( "  Found {} for site '{}' for registering prefix {}" . format ( I1i11II , iii11II1 . site_name , green ( oo0ooooO , False ) ) )
   if 41 - 41: II111iiii + Oo0Ooo - IiII / I1Ii111 - OOooOOo . oO0o
   if 100 - 100: ooOoO0o / I1ii11iIi11i * OoOoOO00 . I1ii11iIi11i . o0oOOo0O0Ooo * iIii1I11I1II1
   if 15 - 15: iII111i + o0oOOo0O0Ooo / IiII
   if 33 - 33: OoooooooOO . IiII * o0oOOo0O0Ooo
   if 41 - 41: Ii1I . iII111i . o0oOOo0O0Ooo % OoooooooOO % IiII
   if 81 - 81: IiII * i11iIiiIii + i1IIi + OOooOOo . i1IIi
  if ( iii11II1 . shutdown ) :
   lprint ( ( "  Rejecting registration for site '{}', configured in " +
 "admin-shutdown state" ) . format ( iii11II1 . site_name ) )
   packet = o0oooOOOOO0oo . end_of_rlocs ( packet , O0OO000oOO0 . rloc_count )
   continue
   if 6 - 6: i11iIiiIii - oO0o % OoO0O00 + iIii1I11I1II1
   if 69 - 69: IiII
   if 13 - 13: i11iIiiIii
   if 49 - 49: OoOoOO00
   if 61 - 61: I1Ii111 / I1Ii111 / iII111i / ooOoO0o - I1IiiI . o0oOOo0O0Ooo
   if 80 - 80: I1IiiI - OOooOOo . oO0o
   if 75 - 75: oO0o + OoOoOO00 - OoooooooOO
   if 38 - 38: I11i / ooOoO0o / OoOoOO00 * OOooOOo . oO0o
  oO0O0oo = I1iIiIII . key_id
  if ( iii11II1 . auth_key . has_key ( oO0O0oo ) == False ) : oO0O0oo = 0
  IIO0o0ooOO0oOOO = iii11II1 . auth_key [ oO0O0oo ]
  if 70 - 70: oO0o
  IIIIi1ii1I1 = lisp_verify_auth ( O00Ooo00 , I1iIiIII . alg_id ,
 I1iIiIII . auth_data , IIO0o0ooOO0oOOO )
  iiIiI1 = "dynamic " if IiIi1II1i . dynamic else ""
  if 72 - 72: iIii1I11I1II1 % iIii1I11I1II1 . OoOoOO00 * OoooooooOO * OoO0O00
  oooO = bold ( "passed" if IIIIi1ii1I1 else "failed" , False )
  oO0O0oo = "key-id {}" . format ( oO0O0oo ) if oO0O0oo == I1iIiIII . key_id else "bad key-id {}" . format ( I1iIiIII . key_id )
  if 26 - 26: Ii1I * I1IiiI % ooOoO0o / I1Ii111
  lprint ( "  Authentication {} for {}EID-prefix {}, {}" . format ( oooO , iiIiI1 , green ( oo0ooooO , False ) , oO0O0oo ) )
  if 80 - 80: I1Ii111 / O0 * O0
  if 40 - 40: OoO0O00 - oO0o / o0oOOo0O0Ooo . oO0o
  if 89 - 89: i11iIiiIii - II111iiii
  if 67 - 67: IiII % I1Ii111 + i11iIiiIii
  if 53 - 53: OOooOOo
  if 95 - 95: oO0o - OOooOOo % I1Ii111 / OoooooooOO % OoooooooOO - O0
  I1o0oO0Oo00Oo = True
  oOo0O0 = ( lisp_get_eid_hash ( O0OO000oOO0 . eid ) != None )
  if ( oOo0O0 or IiIi1II1i . require_signature ) :
   iiIi1I1ii1I1 = "Required " if IiIi1II1i . require_signature else ""
   oo0ooooO = green ( oo0ooooO , False )
   oOoOoo0O = lisp_find_sig_in_rloc_set ( packet , O0OO000oOO0 . rloc_count )
   if ( oOoOoo0O == None ) :
    I1o0oO0Oo00Oo = False
    lprint ( ( "  {}EID-crypto-hash signature verification {} " + "for EID-prefix {}, no signature found" ) . format ( iiIi1I1ii1I1 ,
    # OoOoOO00
 bold ( "failed" , False ) , oo0ooooO ) )
   else :
    I1o0oO0Oo00Oo = lisp_verify_cga_sig ( O0OO000oOO0 . eid , oOoOoo0O )
    oooO = bold ( "passed" if I1o0oO0Oo00Oo else "failed" , False )
    lprint ( ( "  {}EID-crypto-hash signature verification {} " + "for EID-prefix {}" ) . format ( iiIi1I1ii1I1 , oooO , oo0ooooO ) )
    if 70 - 70: Oo0Ooo - OOooOOo * OOooOOo / o0oOOo0O0Ooo
    if 4 - 4: OoOoOO00 / OoO0O00
    if 66 - 66: I1Ii111 / OoOoOO00
    if 53 - 53: OoOoOO00 . i11iIiiIii - OoooooooOO
  if ( IIIIi1ii1I1 == False or I1o0oO0Oo00Oo == False ) :
   packet = o0oooOOOOO0oo . end_of_rlocs ( packet , O0OO000oOO0 . rloc_count )
   if ( packet == None ) :
    lprint ( "  Could not decode RLOC-record in Map-Register packet" )
    return
    if 92 - 92: O0 - i11iIiiIii + OoO0O00 - OoooooooOO - o0oOOo0O0Ooo
   continue
   if 25 - 25: oO0o / oO0o / Ii1I / O0
   if 56 - 56: ooOoO0o
   if 19 - 19: O0 * I1IiiI + I1ii11iIi11i
   if 25 - 25: I11i - ooOoO0o / OoO0O00 / iII111i - OoO0O00
   if 86 - 86: OoO0O00
   if 89 - 89: OoooooooOO % iII111i * I1ii11iIi11i + I1ii11iIi11i . Oo0Ooo
  if ( I1iIiIII . merge_register_requested ) :
   Ii1IIII = IiIi1II1i
   Ii1IIII . inconsistent_registration = False
   if 4 - 4: I11i
   if 8 - 8: IiII
   if 1 - 1: ooOoO0o . IiII
   if 4 - 4: iIii1I11I1II1 % I1IiiI - OoooooooOO / iII111i
   if 55 - 55: O0 + iII111i * OoOoOO00 . i11iIiiIii * Ii1I + oO0o
   if ( IiIi1II1i . group . is_null ( ) ) :
    if ( Ii1IIII . site_id != I1iIiIII . site_id ) :
     Ii1IIII . site_id = I1iIiIII . site_id
     Ii1IIII . registered = False
     Ii1IIII . individual_registrations = { }
     Ii1IIII . registered_rlocs = [ ]
     lisp_registered_count -= 1
     if 66 - 66: i1IIi . I1ii11iIi11i
     if 86 - 86: Oo0Ooo
     if 48 - 48: OoO0O00
   iIIIi = source . address + I1iIiIII . xtr_id
   if ( IiIi1II1i . individual_registrations . has_key ( iIIIi ) ) :
    IiIi1II1i = IiIi1II1i . individual_registrations [ iIIIi ]
   else :
    IiIi1II1i = lisp_site_eid ( iii11II1 )
    IiIi1II1i . eid . copy_address ( Ii1IIII . eid )
    IiIi1II1i . group . copy_address ( Ii1IIII . group )
    Ii1IIII . individual_registrations [ iIIIi ] = IiIi1II1i
    if 55 - 55: OoO0O00 * i1IIi * I11i / iII111i
  else :
   IiIi1II1i . inconsistent_registration = IiIi1II1i . merge_register_requested
   if 42 - 42: IiII
   if 28 - 28: OoOoOO00 + OoOoOO00
   if 53 - 53: II111iiii % i1IIi + ooOoO0o . I1Ii111
  IiIi1II1i . map_registers_received += 1
  if 52 - 52: I1IiiI + I1Ii111 * oO0o / i11iIiiIii * iIii1I11I1II1
  if 27 - 27: Oo0Ooo
  if 85 - 85: iIii1I11I1II1 . o0oOOo0O0Ooo + oO0o
  if 79 - 79: O0 - iIii1I11I1II1 + i1IIi . I11i
  if 21 - 21: II111iiii
  OoOoOOo = ( IiIi1II1i . is_rloc_in_rloc_set ( source ) == False )
  if ( O0OO000oOO0 . record_ttl == 0 and OoOoOOo ) :
   lprint ( "  Ignore deregistration request from {}" . format ( red ( source . print_address_no_iid ( ) , False ) ) )
   if 23 - 23: I11i * i1IIi . oO0o / IiII + o0oOOo0O0Ooo
   continue
   if 1 - 1: IiII / OoO0O00 . oO0o * I1Ii111 - i11iIiiIii
   if 50 - 50: oO0o - O0 / I1IiiI . OoOoOO00 . Oo0Ooo
   if 30 - 30: IiII . OoO0O00 + Oo0Ooo
   if 48 - 48: iIii1I11I1II1 / i11iIiiIii . OoOoOO00 * I11i
   if 1 - 1: IiII . OoOoOO00 * o0oOOo0O0Ooo
   if 63 - 63: O0 / Ii1I + I1Ii111 % OoO0O00 % OOooOOo * O0
  II1iiII = IiIi1II1i . registered_rlocs
  IiIi1II1i . registered_rlocs = [ ]
  if 71 - 71: O0
  if 22 - 22: iII111i * ooOoO0o * I1IiiI / II111iiii % Ii1I
  if 39 - 39: OoooooooOO % i11iIiiIii
  if 20 - 20: iII111i - I11i / I1ii11iIi11i * O0 + IiII % I11i
  OOooOo00Ooo = packet
  for OOOoOOo000oo in range ( O0OO000oOO0 . rloc_count ) :
   o0oooOOOOO0oo = lisp_rloc_record ( )
   packet = o0oooOOOOO0oo . decode ( packet , None )
   if ( packet == None ) :
    lprint ( "  Could not decode RLOC-record in Map-Register packet" )
    return
    if 81 - 81: IiII * oO0o * IiII
   o0oooOOOOO0oo . print_record ( "    " )
   if 16 - 16: IiII - OOooOOo - I1Ii111 / OoooooooOO . Ii1I
   if 28 - 28: iII111i / I1ii11iIi11i - OoOoOO00 * Oo0Ooo + Ii1I * OoOoOO00
   if 94 - 94: oO0o
   if 95 - 95: ooOoO0o * O0 + OOooOOo
   if ( len ( iii11II1 . allowed_rlocs ) > 0 ) :
    OoOOoooO000 = o0oooOOOOO0oo . rloc . print_address ( )
    if ( iii11II1 . allowed_rlocs . has_key ( OoOOoooO000 ) == False ) :
     lprint ( ( "  Reject registration, RLOC {} not " + "configured in allowed RLOC-set" ) . format ( red ( OoOOoooO000 , False ) ) )
     if 11 - 11: i1IIi / OoOoOO00 + OoOoOO00 + I1ii11iIi11i + OOooOOo
     if 21 - 21: ooOoO0o
     IiIi1II1i . registered = False
     packet = o0oooOOOOO0oo . end_of_rlocs ( packet ,
 O0OO000oOO0 . rloc_count - OOOoOOo000oo - 1 )
     break
     if 28 - 28: OoOoOO00 + OoOoOO00 - OoOoOO00 / ooOoO0o
     if 81 - 81: oO0o
     if 34 - 34: o0oOOo0O0Ooo * OOooOOo - i1IIi * o0oOOo0O0Ooo * Oo0Ooo
     if 59 - 59: iIii1I11I1II1 / Oo0Ooo % II111iiii
     if 55 - 55: ooOoO0o - IiII + o0oOOo0O0Ooo
     if 48 - 48: O0 - iIii1I11I1II1 * OOooOOo
   oOoOoo0O = lisp_rloc ( )
   oOoOoo0O . store_rloc_from_record ( o0oooOOOOO0oo , None , source )
   if 33 - 33: I11i
   if 63 - 63: Ii1I % II111iiii / OoOoOO00 + Oo0Ooo
   if 28 - 28: OoO0O00 + I1IiiI . oO0o + II111iiii - O0
   if 32 - 32: oO0o
   if 62 - 62: i11iIiiIii + OoooooooOO + IiII - OoO0O00 / oO0o * iIii1I11I1II1
   if 91 - 91: o0oOOo0O0Ooo - i11iIiiIii + Oo0Ooo % iIii1I11I1II1
   if ( source . is_exact_match ( oOoOoo0O . rloc ) ) :
    oOoOoo0O . map_notify_requested = I1iIiIII . map_notify_requested
    if 58 - 58: iII111i / ooOoO0o - I1Ii111 + I1Ii111 * ooOoO0o
    if 48 - 48: iII111i % O0 % Ii1I * OoO0O00 . OoO0O00
    if 74 - 74: OoO0O00 * i1IIi + I1ii11iIi11i / o0oOOo0O0Ooo / i1IIi
    if 94 - 94: Ii1I
    if 13 - 13: OoO0O00 - II111iiii . iII111i + OoOoOO00 / i11iIiiIii
   IiIi1II1i . registered_rlocs . append ( oOoOoo0O )
   if 32 - 32: ooOoO0o / II111iiii / I1ii11iIi11i
   if 34 - 34: iIii1I11I1II1
  iI111I11iii1 = ( IiIi1II1i . do_rloc_sets_match ( II1iiII ) == False )
  if 17 - 17: i1IIi
  if 39 - 39: oO0o
  if 40 - 40: i11iIiiIii + oO0o * IiII
  if 19 - 19: iII111i / II111iiii . I1Ii111 * I1IiiI - OOooOOo
  if 70 - 70: OoO0O00
  if 42 - 42: OoooooooOO - I1Ii111 + I1ii11iIi11i * iII111i * iII111i / OoO0O00
  if ( I1iIiIII . map_register_refresh and iI111I11iii1 and
 IiIi1II1i . registered ) :
   lprint ( "  Reject registration, refreshes cannot change RLOC-set" )
   IiIi1II1i . registered_rlocs = II1iiII
   continue
   if 85 - 85: O0 . II111iiii
   if 80 - 80: O0 * I11i * I1Ii111
   if 89 - 89: Ii1I * OoO0O00 . i1IIi . O0 - IiII - OoOoOO00
   if 25 - 25: iII111i + i1IIi
   if 64 - 64: IiII % I11i / iIii1I11I1II1
   if 66 - 66: Ii1I
  if ( IiIi1II1i . registered == False ) :
   IiIi1II1i . first_registered = lisp_get_timestamp ( )
   lisp_registered_count += 1
   if 55 - 55: OOooOOo + I1IiiI + IiII . Ii1I * oO0o
  IiIi1II1i . last_registered = lisp_get_timestamp ( )
  IiIi1II1i . registered = ( O0OO000oOO0 . record_ttl != 0 )
  IiIi1II1i . last_registerer = source
  if 71 - 71: IiII - iII111i % I1IiiI * iII111i
  if 27 - 27: ooOoO0o - OoO0O00
  if 83 - 83: iII111i * OoOoOO00 - O0 * Ii1I
  if 79 - 79: I11i / iII111i % Ii1I / OoOoOO00 % O0 / IiII
  IiIi1II1i . auth_sha1_or_sha2 = oOoo0
  IiIi1II1i . proxy_reply_requested = I1iIiIII . proxy_reply_requested
  IiIi1II1i . lisp_sec_present = I1iIiIII . lisp_sec_present
  IiIi1II1i . map_notify_requested = I1iIiIII . map_notify_requested
  IiIi1II1i . mobile_node_requested = I1iIiIII . mobile_node
  IiIi1II1i . merge_register_requested = I1iIiIII . merge_register_requested
  if 32 - 32: IiII * II111iiii . Ii1I
  IiIi1II1i . use_register_ttl_requested = I1iIiIII . use_ttl_for_timeout
  if ( IiIi1II1i . use_register_ttl_requested ) :
   IiIi1II1i . register_ttl = O0OO000oOO0 . store_ttl ( )
  else :
   IiIi1II1i . register_ttl = LISP_SITE_TIMEOUT_CHECK_INTERVAL * 3
   if 68 - 68: I11i / O0
  IiIi1II1i . xtr_id_present = I1iIiIII . xtr_id_present
  if ( IiIi1II1i . xtr_id_present ) :
   IiIi1II1i . xtr_id = I1iIiIII . xtr_id
   IiIi1II1i . site_id = I1iIiIII . site_id
   if 6 - 6: oO0o - oO0o . I1IiiI % I1ii11iIi11i
   if 22 - 22: Ii1I / I1IiiI / II111iiii
   if 31 - 31: II111iiii - Ii1I * OOooOOo - i11iIiiIii / OoooooooOO - I1Ii111
   if 76 - 76: Oo0Ooo
   if 93 - 93: i1IIi - I1IiiI * i11iIiiIii / Ii1I . Ii1I - i1IIi
  if ( I1iIiIII . merge_register_requested ) :
   if ( Ii1IIII . merge_in_site_eid ( IiIi1II1i ) ) :
    O000OOoo0o . append ( [ O0OO000oOO0 . eid , O0OO000oOO0 . group ] )
    if 19 - 19: iIii1I11I1II1 * OOooOOo * Oo0Ooo % I1IiiI
   if ( I1iIiIII . map_notify_requested ) :
    lisp_send_merged_map_notify ( lisp_sockets , Ii1IIII , I1iIiIII ,
 O0OO000oOO0 )
    if 93 - 93: IiII % OoOoOO00 / I1IiiI + o0oOOo0O0Ooo * ooOoO0o / i1IIi
    if 25 - 25: O0 / Oo0Ooo - o0oOOo0O0Ooo * Oo0Ooo
    if 45 - 45: Ii1I * IiII - OOooOOo
  if ( iI111I11iii1 == False ) : continue
  if ( len ( O000OOoo0o ) != 0 ) : continue
  if 57 - 57: iII111i % OoO0O00 / OoooooooOO
  OOO00oo . append ( IiIi1II1i . print_eid_tuple ( ) )
  if 69 - 69: oO0o
  if 44 - 44: IiII - II111iiii % Ii1I
  if 64 - 64: Ii1I % OoO0O00 + OOooOOo % OoOoOO00 + IiII
  if 92 - 92: iII111i * Oo0Ooo - OoOoOO00
  if 33 - 33: i11iIiiIii - OoOoOO00 . OOooOOo * II111iiii . Ii1I
  if 59 - 59: OoOoOO00
  if 29 - 29: iII111i - II111iiii * OoooooooOO * OoooooooOO
  O0OO000oOO0 = O0OO000oOO0 . encode ( )
  O0OO000oOO0 += OOooOo00Ooo
  O00Oo0ooo = [ IiIi1II1i . print_eid_tuple ( ) ]
  lprint ( "    Changed RLOC-set, Map-Notifying old RLOC-set" )
  if 15 - 15: IiII / OOooOOo / iIii1I11I1II1 / OoOoOO00
  for oOoOoo0O in II1iiII :
   if ( oOoOoo0O . map_notify_requested == False ) : continue
   if ( oOoOoo0O . rloc . is_exact_match ( source ) ) : continue
   lisp_build_map_notify ( lisp_sockets , O0OO000oOO0 , O00Oo0ooo , 1 , oOoOoo0O . rloc ,
 LISP_CTRL_PORT , I1iIiIII . nonce , I1iIiIII . key_id ,
 I1iIiIII . alg_id , I1iIiIII . auth_len , iii11II1 , False )
   if 91 - 91: i11iIiiIii % O0 . Oo0Ooo / I1Ii111
   if 62 - 62: Oo0Ooo . II111iiii % OoO0O00 . Ii1I * OOooOOo + II111iiii
   if 7 - 7: OOooOOo
   if 22 - 22: Oo0Ooo + ooOoO0o
   if 71 - 71: OOooOOo . Ii1I * i11iIiiIii . I11i
  lisp_notify_subscribers ( lisp_sockets , O0OO000oOO0 , IiIi1II1i . eid , iii11II1 )
  if 9 - 9: O0 / I1ii11iIi11i . iII111i . O0 + IiII % I11i
  if 27 - 27: i11iIiiIii - I1ii11iIi11i / O0 - i1IIi + I1IiiI * iII111i
  if 26 - 26: Oo0Ooo . Ii1I
  if 7 - 7: OoOoOO00 - o0oOOo0O0Ooo + oO0o
  if 8 - 8: iIii1I11I1II1
 if ( len ( O000OOoo0o ) != 0 ) :
  lisp_queue_multicast_map_notify ( lisp_sockets , O000OOoo0o )
  if 6 - 6: oO0o
  if 51 - 51: I1Ii111 - o0oOOo0O0Ooo
  if 5 - 5: O0
  if 7 - 7: OoOoOO00 + OoO0O00 * I1IiiI
  if 63 - 63: I1ii11iIi11i + iII111i * i1IIi
  if 63 - 63: I1ii11iIi11i / II111iiii % oO0o + ooOoO0o . Ii1I % I11i
 if ( I1iIiIII . merge_register_requested ) : return
 if 59 - 59: I1Ii111 % o0oOOo0O0Ooo - I1IiiI * i1IIi
 if 5 - 5: I1IiiI
 if 22 - 22: II111iiii / iII111i
 if 18 - 18: i11iIiiIii * ooOoO0o . I1IiiI + i1IIi + I11i
 if 62 - 62: O0 % o0oOOo0O0Ooo + iIii1I11I1II1 + iIii1I11I1II1 * ooOoO0o
 if ( I1iIiIII . map_notify_requested and iii11II1 != None ) :
  lisp_build_map_notify ( lisp_sockets , Iii1i , OOO00oo ,
 I1iIiIII . record_count , source , sport , I1iIiIII . nonce ,
 I1iIiIII . key_id , I1iIiIII . alg_id , I1iIiIII . auth_len ,
 iii11II1 , True )
  if 21 - 21: o0oOOo0O0Ooo % O0
 return
 if 81 - 81: i1IIi + i1IIi
 if 3 - 3: I1Ii111 . I1ii11iIi11i * iII111i * i11iIiiIii * IiII
 if 52 - 52: iIii1I11I1II1 % o0oOOo0O0Ooo % I1IiiI
 if 71 - 71: I1IiiI + iII111i
 if 47 - 47: iIii1I11I1II1 . OoO0O00 . iIii1I11I1II1
 if 57 - 57: IiII * ooOoO0o * ooOoO0o * iIii1I11I1II1 * I1Ii111 + OoOoOO00
 if 83 - 83: OoOoOO00 . Oo0Ooo . OoO0O00
 if 65 - 65: iII111i * iIii1I11I1II1
 if 48 - 48: iII111i * OoO0O00
 if 57 - 57: ooOoO0o + I1IiiI
def lisp_process_multicast_map_notify ( packet , source ) :
 O00o0oOoO0OOo = lisp_map_notify ( "" )
 packet = O00o0oOoO0OOo . decode ( packet )
 if ( packet == None ) :
  lprint ( "Could not decode Map-Notify packet" )
  return
  if 32 - 32: I1ii11iIi11i + OOooOOo - I11i
  if 82 - 82: Oo0Ooo % Oo0Ooo
 O00o0oOoO0OOo . print_notify ( )
 if ( O00o0oOoO0OOo . record_count == 0 ) : return
 if 91 - 91: I11i
 O0oo00OOo = O00o0oOoO0OOo . eid_records
 if 44 - 44: oO0o . oO0o % I11i * oO0o
 for oO in range ( O00o0oOoO0OOo . record_count ) :
  O0OO000oOO0 = lisp_eid_record ( )
  O0oo00OOo = O0OO000oOO0 . decode ( O0oo00OOo )
  if ( packet == None ) : return
  O0OO000oOO0 . print_record ( "  " , False )
  if 23 - 23: OoOoOO00 - OoOoOO00
  if 34 - 34: O0 . oO0o - I1IiiI * OOooOOo
  if 86 - 86: Ii1I % O0
  if 13 - 13: I1ii11iIi11i % I1Ii111 * OoooooooOO . o0oOOo0O0Ooo % I1IiiI
  oOooO0Oo0Oo0 = lisp_map_cache_lookup ( O0OO000oOO0 . eid , O0OO000oOO0 . group )
  if ( oOooO0Oo0Oo0 == None ) :
   oOooO0Oo0Oo0 = lisp_mapping ( O0OO000oOO0 . eid , O0OO000oOO0 . group , [ ] )
   oOooO0Oo0Oo0 . add_cache ( )
   if 70 - 70: iII111i . i11iIiiIii * I1Ii111
   if 54 - 54: o0oOOo0O0Ooo . i1IIi / iII111i
  oOooO0Oo0Oo0 . mapping_source = None if source == "lisp-etr" else source
  oOooO0Oo0Oo0 . map_cache_ttl = O0OO000oOO0 . store_ttl ( )
  if 21 - 21: O0 + ooOoO0o
  if 53 - 53: Ii1I - II111iiii * iIii1I11I1II1
  if 91 - 91: OoOoOO00 % iIii1I11I1II1
  if 81 - 81: i11iIiiIii / OoOoOO00 + iIii1I11I1II1
  if 65 - 65: o0oOOo0O0Ooo
  if ( len ( oOooO0Oo0Oo0 . rloc_set ) != 0 and O0OO000oOO0 . rloc_count == 0 ) :
   oOooO0Oo0Oo0 . rloc_set = [ ]
   oOooO0Oo0Oo0 . build_best_rloc_set ( )
   lisp_write_ipc_map_cache ( True , oOooO0Oo0Oo0 )
   lprint ( "Update {} map-cache entry with no RLOC-set" . format ( green ( oOooO0Oo0Oo0 . print_eid_tuple ( ) , False ) ) )
   if 73 - 73: I11i . I1ii11iIi11i - OoO0O00 + OoooooooOO
   continue
   if 71 - 71: I1IiiI
   if 27 - 27: OoO0O00 + i1IIi * OoooooooOO * iIii1I11I1II1 - Ii1I
  OOoooO = oOooO0Oo0Oo0 . rtrs_in_rloc_set ( )
  if 87 - 87: OoOoOO00 * I1IiiI
  if 19 - 19: iII111i / Ii1I + iIii1I11I1II1 * O0 - Oo0Ooo
  if 47 - 47: iIii1I11I1II1 % I1ii11iIi11i
  if 33 - 33: oO0o . oO0o / IiII + II111iiii
  if 34 - 34: OoO0O00 . OoOoOO00 / i1IIi / OOooOOo
  for OOOoOOo000oo in range ( O0OO000oOO0 . rloc_count ) :
   o0oooOOOOO0oo = lisp_rloc_record ( )
   O0oo00OOo = o0oooOOOOO0oo . decode ( O0oo00OOo , None )
   o0oooOOOOO0oo . print_record ( "    " )
   if ( O0OO000oOO0 . group . is_null ( ) ) : continue
   if ( o0oooOOOOO0oo . rle == None ) : continue
   if 12 - 12: o0oOOo0O0Ooo . Oo0Ooo / II111iiii
   if 18 - 18: I1Ii111 % II111iiii + Ii1I * Oo0Ooo - OoooooooOO . Oo0Ooo
   if 25 - 25: OoO0O00
   if 83 - 83: II111iiii . iIii1I11I1II1
   if 77 - 77: O0 . OoOoOO00 % oO0o / OOooOOo
   i1i1Ii11 = oOooO0Oo0Oo0 . rloc_set [ 0 ] . stats if len ( oOooO0Oo0Oo0 . rloc_set ) != 0 else None
   if 68 - 68: OoOoOO00
   if 14 - 14: iIii1I11I1II1 + oO0o / ooOoO0o
   if 20 - 20: I1ii11iIi11i . II111iiii % I1Ii111 + I1Ii111 / OoooooooOO . Ii1I
   if 98 - 98: OoooooooOO - i11iIiiIii - iII111i + Ii1I - I1IiiI
   oOoOoo0O = lisp_rloc ( )
   oOoOoo0O . store_rloc_from_record ( o0oooOOOOO0oo , None , oOooO0Oo0Oo0 . mapping_source )
   if ( i1i1Ii11 != None ) : oOoOoo0O . stats = copy . deepcopy ( i1i1Ii11 )
   if 75 - 75: OOooOOo
   if ( OOoooO and oOoOoo0O . is_rtr ( ) == False ) : continue
   if 25 - 25: iII111i / I1ii11iIi11i - ooOoO0o
   oOooO0Oo0Oo0 . rloc_set = [ oOoOoo0O ]
   oOooO0Oo0Oo0 . build_best_rloc_set ( )
   lisp_write_ipc_map_cache ( True , oOooO0Oo0Oo0 )
   if 53 - 53: IiII / OoooooooOO / ooOoO0o + Oo0Ooo - OOooOOo - iIii1I11I1II1
   lprint ( "Update {} map-cache entry with RLE {}" . format ( green ( oOooO0Oo0Oo0 . print_eid_tuple ( ) , False ) , oOoOoo0O . rle . print_rle ( False ) ) )
   if 53 - 53: OOooOOo . I1IiiI . o0oOOo0O0Ooo / o0oOOo0O0Ooo
   if 40 - 40: OoooooooOO + iII111i % I1Ii111 . ooOoO0o
   if 2 - 2: ooOoO0o
 return
 if 55 - 55: I11i + i1IIi * OoOoOO00 % Oo0Ooo * II111iiii . I1IiiI
 if 98 - 98: I1ii11iIi11i
 if 57 - 57: OOooOOo * I11i . oO0o
 if 17 - 17: iII111i - OOooOOo * I1IiiI + i1IIi % I1ii11iIi11i
 if 71 - 71: Ii1I - o0oOOo0O0Ooo - oO0o
 if 27 - 27: O0 - iIii1I11I1II1
 if 78 - 78: Oo0Ooo / o0oOOo0O0Ooo
 if 35 - 35: o0oOOo0O0Ooo . OoO0O00 / o0oOOo0O0Ooo / IiII - I1ii11iIi11i . Oo0Ooo
def lisp_process_map_notify ( lisp_sockets , orig_packet , source ) :
 O00o0oOoO0OOo = lisp_map_notify ( "" )
 I1IiO00Ooo0ooo0 = O00o0oOoO0OOo . decode ( orig_packet )
 if ( I1IiO00Ooo0ooo0 == None ) :
  lprint ( "Could not decode Map-Notify packet" )
  return
  if 97 - 97: i11iIiiIii + I1ii11iIi11i - I11i . oO0o
  if 76 - 76: IiII * II111iiii * I1ii11iIi11i + OoooooooOO - OoOoOO00 . Ii1I
 O00o0oOoO0OOo . print_notify ( )
 if 51 - 51: II111iiii % I1Ii111 * O0 . ooOoO0o * OoOoOO00
 if 17 - 17: I1IiiI % I11i
 if 28 - 28: I1ii11iIi11i * OoooooooOO
 if 19 - 19: Oo0Ooo - iII111i % OoOoOO00 * i11iIiiIii / oO0o . i11iIiiIii
 if 46 - 46: I1ii11iIi11i
 i1I1iIi1IiI = source . print_address ( )
 if ( O00o0oOoO0OOo . alg_id != 0 or O00o0oOoO0OOo . auth_len != 0 ) :
  iiI = None
  for iIIIi in lisp_map_servers_list :
   if ( iIIIi . find ( i1I1iIi1IiI ) == - 1 ) : continue
   iiI = lisp_map_servers_list [ iIIIi ]
   if 50 - 50: OOooOOo * OoO0O00 * OOooOOo % I1IiiI - I1Ii111 * Ii1I
  if ( iiI == None ) :
   lprint ( ( "  Could not find Map-Server {} to authenticate " + "Map-Notify" ) . format ( i1I1iIi1IiI ) )
   if 88 - 88: OOooOOo . iII111i / I11i
   return
   if 1 - 1: iIii1I11I1II1 - Oo0Ooo % OoooooooOO
   if 71 - 71: OOooOOo - Ii1I
  iiI . map_notifies_received += 1
  if 68 - 68: ooOoO0o
  IIIIi1ii1I1 = lisp_verify_auth ( I1IiO00Ooo0ooo0 , O00o0oOoO0OOo . alg_id ,
 O00o0oOoO0OOo . auth_data , iiI . password )
  if 35 - 35: IiII . iIii1I11I1II1 + Ii1I % O0
  lprint ( "  Authentication {} for Map-Notify" . format ( "succeeded" if IIIIi1ii1I1 else "failed" ) )
  if 94 - 94: OoOoOO00 + II111iiii . II111iiii + ooOoO0o + ooOoO0o
  if ( IIIIi1ii1I1 == False ) : return
 else :
  iiI = lisp_ms ( i1I1iIi1IiI , None , "" , 0 , "" , False , False , False , False , 0 , 0 , 0 ,
 None )
  if 95 - 95: iIii1I11I1II1 / i11iIiiIii - IiII - OOooOOo
  if 4 - 4: II111iiii + oO0o + o0oOOo0O0Ooo % IiII % iIii1I11I1II1
  if 68 - 68: i11iIiiIii
  if 79 - 79: OoOoOO00 * Ii1I / I1ii11iIi11i + OOooOOo
  if 19 - 19: I1IiiI + I11i + I1IiiI + OoO0O00
  if 33 - 33: i11iIiiIii - Ii1I * II111iiii
 O0oo00OOo = O00o0oOoO0OOo . eid_records
 if ( O00o0oOoO0OOo . record_count == 0 ) :
  lisp_send_map_notify_ack ( lisp_sockets , O0oo00OOo , O00o0oOoO0OOo , iiI )
  return
  if 97 - 97: OoO0O00 / o0oOOo0O0Ooo * iIii1I11I1II1
  if 5 - 5: I1IiiI
  if 27 - 27: i1IIi + oO0o / I1ii11iIi11i + oO0o
  if 98 - 98: II111iiii + iIii1I11I1II1
  if 70 - 70: I11i / OoooooooOO / i11iIiiIii
  if 61 - 61: O0 . Oo0Ooo . iIii1I11I1II1
  if 54 - 54: OOooOOo * I1ii11iIi11i + OoooooooOO
  if 58 - 58: i1IIi - OoooooooOO * OOooOOo . ooOoO0o + O0 + o0oOOo0O0Ooo
 O0OO000oOO0 = lisp_eid_record ( )
 I1IiO00Ooo0ooo0 = O0OO000oOO0 . decode ( O0oo00OOo )
 if ( I1IiO00Ooo0ooo0 == None ) : return
 if 87 - 87: OOooOOo + I1Ii111 + O0 / oO0o / i11iIiiIii
 O0OO000oOO0 . print_record ( "  " , False )
 if 60 - 60: O0 . II111iiii
 for OOOoOOo000oo in range ( O0OO000oOO0 . rloc_count ) :
  o0oooOOOOO0oo = lisp_rloc_record ( )
  I1IiO00Ooo0ooo0 = o0oooOOOOO0oo . decode ( I1IiO00Ooo0ooo0 , None )
  if ( I1IiO00Ooo0ooo0 == None ) :
   lprint ( "  Could not decode RLOC-record in Map-Notify packet" )
   return
   if 69 - 69: II111iiii / ooOoO0o - OoOoOO00 / OOooOOo
  o0oooOOOOO0oo . print_record ( "    " )
  if 52 - 52: OoO0O00 % I11i + o0oOOo0O0Ooo % OoOoOO00
  if 46 - 46: o0oOOo0O0Ooo % O0
  if 30 - 30: oO0o
  if 64 - 64: O0
  if 70 - 70: oO0o % I1IiiI . iIii1I11I1II1 - Oo0Ooo + OoOoOO00 % O0
 if ( O0OO000oOO0 . group . is_null ( ) == False ) :
  if 91 - 91: I1Ii111 - oO0o * ooOoO0o - I1ii11iIi11i + IiII + O0
  if 18 - 18: OoOoOO00 / IiII / o0oOOo0O0Ooo . OOooOOo
  if 35 - 35: I11i . ooOoO0o % I11i / iII111i / O0 % I11i
  if 29 - 29: I1Ii111 + Ii1I
  if 100 - 100: Ii1I + I1Ii111 / iIii1I11I1II1 / i1IIi % OoOoOO00
  lprint ( "Send {} Map-Notify IPC message to ITR process" . format ( green ( O0OO000oOO0 . print_eid_tuple ( ) , False ) ) )
  if 6 - 6: oO0o + ooOoO0o
  if 13 - 13: Oo0Ooo . IiII % iII111i + i1IIi / OOooOOo
  OOOO0OoO0oOOoo0 = lisp_control_packet_ipc ( orig_packet , i1I1iIi1IiI , "lisp-itr" , 0 )
  lisp_ipc ( OOOO0OoO0oOOoo0 , lisp_sockets [ 2 ] , "lisp-core-pkt" )
  if 1 - 1: I11i * i1IIi * Oo0Ooo % O0
  if 41 - 41: OOooOOo % OoOoOO00
  if 82 - 82: I11i . IiII
  if 27 - 27: I1Ii111 % O0 * OoooooooOO . Oo0Ooo
  if 51 - 51: I11i
 lisp_send_map_notify_ack ( lisp_sockets , O0oo00OOo , O00o0oOoO0OOo , iiI )
 return
 if 80 - 80: Oo0Ooo + oO0o
 if 76 - 76: I1IiiI * OoooooooOO - i11iIiiIii / I11i / Oo0Ooo
 if 82 - 82: IiII % ooOoO0o
 if 100 - 100: Oo0Ooo . oO0o - iII111i + OoooooooOO
 if 27 - 27: Oo0Ooo . I1Ii111 - i1IIi * I1IiiI
 if 96 - 96: I1ii11iIi11i - Ii1I . I1ii11iIi11i
 if 89 - 89: II111iiii % I1ii11iIi11i % IiII . I11i
 if 49 - 49: iII111i % i11iIiiIii * I11i - oO0o . OOooOOo . i11iIiiIii
def lisp_process_map_notify_ack ( packet , source ) :
 O00o0oOoO0OOo = lisp_map_notify ( "" )
 packet = O00o0oOoO0OOo . decode ( packet )
 if ( packet == None ) :
  lprint ( "Could not decode Map-Notify-Ack packet" )
  return
  if 26 - 26: iIii1I11I1II1 + i11iIiiIii % iII111i + I1IiiI + oO0o - ooOoO0o
  if 4 - 4: Oo0Ooo - IiII - I11i
 O00o0oOoO0OOo . print_notify ( )
 if 72 - 72: OoooooooOO
 if 19 - 19: Oo0Ooo . OOooOOo
 if 58 - 58: IiII % iII111i + i1IIi % I1IiiI % OOooOOo . iII111i
 if 85 - 85: i11iIiiIii . o0oOOo0O0Ooo * iII111i . I1ii11iIi11i / I1Ii111 % Ii1I
 if 27 - 27: II111iiii . iIii1I11I1II1 / I1ii11iIi11i / i1IIi / iIii1I11I1II1
 if ( O00o0oOoO0OOo . record_count < 1 ) :
  lprint ( "No EID-prefix found, cannot authenticate Map-Notify-Ack" )
  return
  if 70 - 70: i11iIiiIii . OoO0O00 / OoooooooOO * OoooooooOO - OOooOOo
  if 34 - 34: I1ii11iIi11i * i1IIi % OoooooooOO / I1IiiI
 O0OO000oOO0 = lisp_eid_record ( )
 if 39 - 39: OoO0O00 + IiII - II111iiii % I11i
 if ( O0OO000oOO0 . decode ( O00o0oOoO0OOo . eid_records ) == None ) :
  lprint ( "Could not decode EID-record, cannot authenticate " +
 "Map-Notify-Ack" )
  return
  if 80 - 80: o0oOOo0O0Ooo * ooOoO0o
 O0OO000oOO0 . print_record ( "  " , False )
 if 87 - 87: I1Ii111 + O0 / I1ii11iIi11i / OoOoOO00 . Oo0Ooo - IiII
 oo0ooooO = O0OO000oOO0 . print_eid_tuple ( )
 if 24 - 24: OoOoOO00
 if 19 - 19: ooOoO0o
 if 43 - 43: O0 . I1Ii111 % OoooooooOO / I1IiiI . o0oOOo0O0Ooo - OoOoOO00
 if 46 - 46: I11i - OoooooooOO % o0oOOo0O0Ooo
 if ( O00o0oOoO0OOo . alg_id != LISP_NONE_ALG_ID and O00o0oOoO0OOo . auth_len != 0 ) :
  IiIi1II1i = lisp_sites_by_eid . lookup_cache ( O0OO000oOO0 . eid , True )
  if ( IiIi1II1i == None ) :
   OoO0OOOOO0OO = bold ( "Site not found" , False )
   lprint ( ( "{} for EID {}, cannot authenticate Map-Notify-Ack" ) . format ( OoO0OOOOO0OO , green ( oo0ooooO , False ) ) )
   if 7 - 7: OoooooooOO - I1Ii111 * IiII
   return
   if 20 - 20: o0oOOo0O0Ooo . OoooooooOO * I1IiiI . Oo0Ooo * OoOoOO00
  iii11II1 = IiIi1II1i . site
  if 3 - 3: I1Ii111 % i11iIiiIii % O0 % II111iiii
  if 8 - 8: OoooooooOO * ooOoO0o
  if 26 - 26: i11iIiiIii + oO0o - i1IIi
  if 71 - 71: I1IiiI % I1Ii111 / oO0o % oO0o / iIii1I11I1II1 + I1Ii111
  iii11II1 . map_notify_acks_received += 1
  if 86 - 86: IiII % i1IIi * o0oOOo0O0Ooo - I1Ii111
  oO0O0oo = O00o0oOoO0OOo . key_id
  if ( iii11II1 . auth_key . has_key ( oO0O0oo ) == False ) : oO0O0oo = 0
  IIO0o0ooOO0oOOO = iii11II1 . auth_key [ oO0O0oo ]
  if 37 - 37: iII111i % I1IiiI - I1ii11iIi11i % I11i
  IIIIi1ii1I1 = lisp_verify_auth ( packet , O00o0oOoO0OOo . alg_id ,
 O00o0oOoO0OOo . auth_data , IIO0o0ooOO0oOOO )
  if 35 - 35: O0 - OoooooooOO % iII111i
  oO0O0oo = "key-id {}" . format ( oO0O0oo ) if oO0O0oo == O00o0oOoO0OOo . key_id else "bad key-id {}" . format ( O00o0oOoO0OOo . key_id )
  if 48 - 48: OOooOOo % i11iIiiIii
  if 49 - 49: O0 * iII111i + II111iiii - OOooOOo
  lprint ( "  Authentication {} for Map-Notify-Ack, {}" . format ( "succeeded" if IIIIi1ii1I1 else "failed" , oO0O0oo ) )
  if 29 - 29: OoooooooOO % II111iiii - Oo0Ooo / IiII - i11iIiiIii
  if ( IIIIi1ii1I1 == False ) : return
  if 64 - 64: iII111i . I1Ii111 + I1Ii111
  if 1 - 1: OOooOOo % Oo0Ooo
  if 81 - 81: oO0o / I11i % Ii1I . I11i + OoooooooOO
  if 31 - 31: OoO0O00
  if 41 - 41: i11iIiiIii - I1ii11iIi11i - II111iiii
 if ( O00o0oOoO0OOo . retransmit_timer ) : O00o0oOoO0OOo . retransmit_timer . cancel ( )
 if 5 - 5: OoOoOO00 + i1IIi
 O0iiI11111i = source . print_address ( )
 iIIIi = O00o0oOoO0OOo . nonce_key
 if 43 - 43: iII111i * I1IiiI
 if ( lisp_map_notify_queue . has_key ( iIIIi ) ) :
  O00o0oOoO0OOo = lisp_map_notify_queue . pop ( iIIIi )
  if ( O00o0oOoO0OOo . retransmit_timer ) : O00o0oOoO0OOo . retransmit_timer . cancel ( )
  lprint ( "Dequeue Map-Notify from retransmit queue, key is: {}" . format ( iIIIi ) )
  if 20 - 20: I1IiiI . I11i * OoO0O00 . ooOoO0o . II111iiii
 else :
  lprint ( "Map-Notify with nonce 0x{} queue entry not found for {}" . format ( O00o0oOoO0OOo . nonce_key , red ( O0iiI11111i , False ) ) )
  if 6 - 6: Ii1I * OoOoOO00 % IiII + I11i
  if 20 - 20: oO0o
 return
 if 34 - 34: i1IIi + oO0o * Oo0Ooo * I1Ii111 % OoooooooOO % ooOoO0o
 if 17 - 17: I1ii11iIi11i + o0oOOo0O0Ooo / OoO0O00 . Oo0Ooo - o0oOOo0O0Ooo / oO0o
 if 87 - 87: ooOoO0o
 if 74 - 74: i11iIiiIii . i11iIiiIii . iIii1I11I1II1
 if 100 - 100: i11iIiiIii - oO0o + iIii1I11I1II1 * OoOoOO00 % OOooOOo % i11iIiiIii
 if 26 - 26: O0
 if 97 - 97: OOooOOo + I11i % I1Ii111 % i11iIiiIii / I1ii11iIi11i
 if 21 - 21: O0 + iIii1I11I1II1 / i11iIiiIii . OOooOOo * i1IIi
def lisp_map_referral_loop ( mr , eid , group , action , s ) :
 if ( action not in ( LISP_DDT_ACTION_NODE_REFERRAL ,
 LISP_DDT_ACTION_MS_REFERRAL ) ) : return ( False )
 if 3 - 3: i1IIi % o0oOOo0O0Ooo + OoOoOO00
 if ( mr . last_cached_prefix [ 0 ] == None ) : return ( False )
 if 32 - 32: OoO0O00 . Oo0Ooo * iIii1I11I1II1
 if 12 - 12: O0 + I1ii11iIi11i + I11i . I1Ii111
 if 48 - 48: Ii1I . iIii1I11I1II1 - iIii1I11I1II1 * I11i . OoooooooOO
 if 73 - 73: Ii1I / II111iiii - iIii1I11I1II1 . ooOoO0o * II111iiii . OOooOOo
 IiIiI1II = False
 if ( group . is_null ( ) == False ) :
  IiIiI1II = mr . last_cached_prefix [ 1 ] . is_more_specific ( group )
  if 50 - 50: iIii1I11I1II1 + OoOoOO00 % O0 + OoO0O00 . i11iIiiIii / oO0o
 if ( IiIiI1II == False ) :
  IiIiI1II = mr . last_cached_prefix [ 0 ] . is_more_specific ( eid )
  if 31 - 31: I1IiiI % o0oOOo0O0Ooo . i11iIiiIii % OOooOOo - iIii1I11I1II1
  if 77 - 77: i11iIiiIii / OOooOOo
 if ( IiIiI1II ) :
  I1IIIIII = lisp_print_eid_tuple ( eid , group )
  OO00Oo000 = lisp_print_eid_tuple ( mr . last_cached_prefix [ 0 ] ,
 mr . last_cached_prefix [ 1 ] )
  if 3 - 3: iIii1I11I1II1 % IiII * I11i + ooOoO0o
  lprint ( ( "Map-Referral prefix {} from {} is not more-specific " + "than cached prefix {}" ) . format ( green ( I1IIIIII , False ) , s ,
  # iII111i - o0oOOo0O0Ooo - IiII + I11i
 OO00Oo000 ) )
  if 34 - 34: oO0o * II111iiii % I11i / iII111i
 return ( IiIiI1II )
 if 15 - 15: OoOoOO00 - I11i - oO0o
 if 86 - 86: o0oOOo0O0Ooo * i11iIiiIii * Ii1I . I11i - OoOoOO00 % iII111i
 if 19 - 19: OoOoOO00 + OOooOOo - o0oOOo0O0Ooo + i11iIiiIii . OOooOOo
 if 14 - 14: Ii1I - O0 - IiII % Ii1I / OoOoOO00 * OoooooooOO
 if 57 - 57: Oo0Ooo % Oo0Ooo % O0 . I1Ii111 % I1ii11iIi11i
 if 97 - 97: Oo0Ooo % OoO0O00 * I1ii11iIi11i * ooOoO0o * OoO0O00
 if 12 - 12: ooOoO0o
def lisp_process_map_referral ( lisp_sockets , packet , source ) :
 if 56 - 56: i1IIi
 iiiIi = lisp_map_referral ( )
 packet = iiiIi . decode ( packet )
 if ( packet == None ) :
  lprint ( "Could not decode Map-Referral packet" )
  return
  if 3 - 3: OOooOOo - Oo0Ooo * Ii1I + i11iIiiIii
 iiiIi . print_map_referral ( )
 if 53 - 53: i1IIi % I1ii11iIi11i
 i1I1iIi1IiI = source . print_address ( )
 o0oo000 = iiiIi . nonce
 if 65 - 65: I11i + OoOoOO00 - i11iIiiIii
 if 72 - 72: i11iIiiIii - iII111i . i11iIiiIii
 if 61 - 61: oO0o . i11iIiiIii / Ii1I % iII111i
 if 36 - 36: OoO0O00 + Ii1I / I11i - iII111i % OoO0O00 / Oo0Ooo
 for oO in range ( iiiIi . record_count ) :
  O0OO000oOO0 = lisp_eid_record ( )
  packet = O0OO000oOO0 . decode ( packet )
  if ( packet == None ) :
   lprint ( "Could not decode EID-record in Map-Referral packet" )
   return
   if 38 - 38: Ii1I - ooOoO0o - O0 + oO0o . iIii1I11I1II1
  O0OO000oOO0 . print_record ( "  " , True )
  if 90 - 90: i1IIi * OoOoOO00
  if 27 - 27: iIii1I11I1II1
  if 95 - 95: iII111i / ooOoO0o % Ii1I
  if 44 - 44: OOooOOo . OOooOOo
  iIIIi = str ( o0oo000 )
  if ( iIIIi not in lisp_ddt_map_requestQ ) :
   lprint ( ( "Map-Referral nonce 0x{} from {} not found in " + "Map-Request queue, EID-record ignored" ) . format ( lisp_hex_string ( o0oo000 ) , i1I1iIi1IiI ) )
   if 5 - 5: oO0o + OoooooooOO
   if 88 - 88: oO0o + OOooOOo
   continue
   if 14 - 14: I11i / i1IIi
  oOoooooOooO = lisp_ddt_map_requestQ [ iIIIi ]
  if ( oOoooooOooO == None ) :
   lprint ( ( "No Map-Request queue entry found for Map-Referral " +
 "nonce 0x{} from {}, EID-record ignored" ) . format ( lisp_hex_string ( o0oo000 ) , i1I1iIi1IiI ) )
   if 56 - 56: OoooooooOO
   continue
   if 59 - 59: I1ii11iIi11i + OoO0O00
   if 37 - 37: IiII * I1IiiI % O0
   if 32 - 32: ooOoO0o % II111iiii
   if 60 - 60: i11iIiiIii
   if 11 - 11: o0oOOo0O0Ooo
   if 77 - 77: o0oOOo0O0Ooo / iIii1I11I1II1 * iIii1I11I1II1 / o0oOOo0O0Ooo * iII111i
  if ( lisp_map_referral_loop ( oOoooooOooO , O0OO000oOO0 . eid , O0OO000oOO0 . group ,
 O0OO000oOO0 . action , i1I1iIi1IiI ) ) :
   oOoooooOooO . dequeue_map_request ( )
   continue
   if 26 - 26: Ii1I
   if 1 - 1: OoOoOO00 . o0oOOo0O0Ooo + Oo0Ooo % Oo0Ooo * I1ii11iIi11i
  oOoooooOooO . last_cached_prefix [ 0 ] = O0OO000oOO0 . eid
  oOoooooOooO . last_cached_prefix [ 1 ] = O0OO000oOO0 . group
  if 50 - 50: IiII / i1IIi . I1ii11iIi11i
  if 75 - 75: I11i * oO0o + OoooooooOO . iII111i + OoO0O00
  if 44 - 44: II111iiii
  if 65 - 65: I11i . iII111i . I1IiiI - Oo0Ooo % iIii1I11I1II1 / O0
  o0000o = False
  I11I1 = lisp_referral_cache_lookup ( O0OO000oOO0 . eid , O0OO000oOO0 . group ,
 True )
  if ( I11I1 == None ) :
   o0000o = True
   I11I1 = lisp_referral ( )
   I11I1 . eid = O0OO000oOO0 . eid
   I11I1 . group = O0OO000oOO0 . group
   if ( O0OO000oOO0 . ddt_incomplete == False ) : I11I1 . add_cache ( )
  elif ( I11I1 . referral_source . not_set ( ) ) :
   lprint ( "Do not replace static referral entry {}" . format ( green ( I11I1 . print_eid_tuple ( ) , False ) ) )
   if 54 - 54: iII111i - I1Ii111
   oOoooooOooO . dequeue_map_request ( )
   continue
   if 88 - 88: iII111i * OoO0O00 % OoooooooOO / oO0o
   if 7 - 7: i1IIi
  Ooo0oOo0o0oOo = O0OO000oOO0 . action
  I11I1 . referral_source = source
  I11I1 . referral_type = Ooo0oOo0o0oOo
  ooOOooooo0Oo = O0OO000oOO0 . store_ttl ( )
  I11I1 . referral_ttl = ooOOooooo0Oo
  I11I1 . expires = lisp_set_timestamp ( ooOOooooo0Oo )
  if 30 - 30: oO0o . i1IIi / I11i
  if 23 - 23: i1IIi + oO0o % iII111i - OoO0O00 - i1IIi
  if 74 - 74: Ii1I + I11i . OoooooooOO - I1ii11iIi11i
  if 2 - 2: oO0o - o0oOOo0O0Ooo
  oO0oIi1I111IiI11I = I11I1 . is_referral_negative ( )
  if ( I11I1 . referral_set . has_key ( i1I1iIi1IiI ) ) :
   oOoooooOoOoO = I11I1 . referral_set [ i1I1iIi1IiI ]
   if 63 - 63: I1IiiI . iII111i % iIii1I11I1II1 + I1ii11iIi11i
   if ( oOoooooOoOoO . updown == False and oO0oIi1I111IiI11I == False ) :
    oOoooooOoOoO . updown = True
    lprint ( "Change up/down status for referral-node {} to up" . format ( i1I1iIi1IiI ) )
    if 56 - 56: I1Ii111 % oO0o
   elif ( oOoooooOoOoO . updown == True and oO0oIi1I111IiI11I == True ) :
    oOoooooOoOoO . updown = False
    lprint ( ( "Change up/down status for referral-node {} " + "to down, received negative referral" ) . format ( i1I1iIi1IiI ) )
    if 31 - 31: OOooOOo + IiII
    if 56 - 56: OoooooooOO * II111iiii
    if 99 - 99: i11iIiiIii - II111iiii . Oo0Ooo - oO0o . I1IiiI + i1IIi
    if 69 - 69: O0 / i1IIi - OoOoOO00 + ooOoO0o - oO0o
    if 80 - 80: o0oOOo0O0Ooo % O0 * I11i . i1IIi - ooOoO0o
    if 93 - 93: OoooooooOO / o0oOOo0O0Ooo
    if 61 - 61: II111iiii / i1IIi . I1ii11iIi11i % iIii1I11I1II1
    if 66 - 66: iIii1I11I1II1 % OoOoOO00 + i1IIi * i11iIiiIii * OoooooooOO
  I1IIIii1i = { }
  for iIIIi in I11I1 . referral_set : I1IIIii1i [ iIIIi ] = None
  if 75 - 75: oO0o * Oo0Ooo * O0
  if 22 - 22: ooOoO0o / OoooooooOO . II111iiii / Ii1I * OoO0O00 . i1IIi
  if 62 - 62: oO0o % Ii1I - Ii1I
  if 16 - 16: OoO0O00 - O0 - OOooOOo - I11i % OoOoOO00
  for oO in range ( O0OO000oOO0 . rloc_count ) :
   o0oooOOOOO0oo = lisp_rloc_record ( )
   packet = o0oooOOOOO0oo . decode ( packet , None )
   if ( packet == None ) :
    lprint ( "Could not decode RLOC-record in Map-Referral packet" )
    return
    if 7 - 7: I1Ii111 / OoOoOO00 . II111iiii
   o0oooOOOOO0oo . print_record ( "    " )
   if 9 - 9: I11i . I11i . OoooooooOO
   if 42 - 42: iII111i / oO0o / iII111i * OoO0O00
   if 25 - 25: OoOoOO00 - II111iiii + II111iiii . Ii1I * II111iiii
   if 12 - 12: IiII / Ii1I
   OoOOoooO000 = o0oooOOOOO0oo . rloc . print_address ( )
   if ( I11I1 . referral_set . has_key ( OoOOoooO000 ) == False ) :
    oOoooooOoOoO = lisp_referral_node ( )
    oOoooooOoOoO . referral_address . copy_address ( o0oooOOOOO0oo . rloc )
    I11I1 . referral_set [ OoOOoooO000 ] = oOoooooOoOoO
    if ( i1I1iIi1IiI == OoOOoooO000 and oO0oIi1I111IiI11I ) : oOoooooOoOoO . updown = False
   else :
    oOoooooOoOoO = I11I1 . referral_set [ OoOOoooO000 ]
    if ( I1IIIii1i . has_key ( OoOOoooO000 ) ) : I1IIIii1i . pop ( OoOOoooO000 )
    if 54 - 54: Oo0Ooo + Ii1I % OoooooooOO * OOooOOo / OoOoOO00
   oOoooooOoOoO . priority = o0oooOOOOO0oo . priority
   oOoooooOoOoO . weight = o0oooOOOOO0oo . weight
   if 39 - 39: I1IiiI % i11iIiiIii % Ii1I
   if 59 - 59: ooOoO0o % OoO0O00 / I1IiiI - II111iiii + OoooooooOO * i11iIiiIii
   if 58 - 58: IiII / Oo0Ooo + o0oOOo0O0Ooo
   if 71 - 71: Ii1I - IiII
   if 2 - 2: OoOoOO00 % IiII % OoO0O00 . i1IIi / I1Ii111 - iIii1I11I1II1
  for iIIIi in I1IIIii1i : I11I1 . referral_set . pop ( iIIIi )
  if 88 - 88: Oo0Ooo * i1IIi % OOooOOo
  oo0ooooO = I11I1 . print_eid_tuple ( )
  if 65 - 65: iII111i . oO0o
  if ( o0000o ) :
   if ( O0OO000oOO0 . ddt_incomplete ) :
    lprint ( "Suppress add {} to referral-cache" . format ( green ( oo0ooooO , False ) ) )
    if 67 - 67: I1IiiI / iII111i / O0 % ooOoO0o - IiII / Ii1I
   else :
    lprint ( "Add {}, referral-count {} to referral-cache" . format ( green ( oo0ooooO , False ) , O0OO000oOO0 . rloc_count ) )
    if 31 - 31: I11i - oO0o * ooOoO0o
    if 64 - 64: I11i
  else :
   lprint ( "Replace {}, referral-count: {} in referral-cache" . format ( green ( oo0ooooO , False ) , O0OO000oOO0 . rloc_count ) )
   if 41 - 41: I1Ii111 * OoooooooOO / OoOoOO00 + OoO0O00 . OoOoOO00 + I1Ii111
   if 9 - 9: IiII . I11i . I1Ii111 / i1IIi * OoOoOO00 - O0
   if 3 - 3: O0 / iIii1I11I1II1 % IiII + I11i
   if 43 - 43: Oo0Ooo % I11i
   if 53 - 53: OoOoOO00 % OoooooooOO * o0oOOo0O0Ooo % OoooooooOO
   if 47 - 47: iIii1I11I1II1 - OOooOOo + I1ii11iIi11i * ooOoO0o + Oo0Ooo + OoO0O00
  if ( Ooo0oOo0o0oOo == LISP_DDT_ACTION_DELEGATION_HOLE ) :
   lisp_send_negative_map_reply ( oOoooooOooO . lisp_sockets , I11I1 . eid ,
 I11I1 . group , oOoooooOooO . nonce , oOoooooOooO . itr , oOoooooOooO . sport , 15 , None , False )
   oOoooooOooO . dequeue_map_request ( )
   if 64 - 64: OoOoOO00 - OoOoOO00 . OoooooooOO + ooOoO0o
   if 100 - 100: ooOoO0o . OoooooooOO % i1IIi % OoO0O00
  if ( Ooo0oOo0o0oOo == LISP_DDT_ACTION_NOT_AUTH ) :
   if ( oOoooooOooO . tried_root ) :
    lisp_send_negative_map_reply ( oOoooooOooO . lisp_sockets , I11I1 . eid ,
 I11I1 . group , oOoooooOooO . nonce , oOoooooOooO . itr , oOoooooOooO . sport , 0 , None , False )
    oOoooooOooO . dequeue_map_request ( )
   else :
    lisp_send_ddt_map_request ( oOoooooOooO , True )
    if 26 - 26: OoOoOO00 * IiII
    if 76 - 76: I1IiiI + IiII * I1ii11iIi11i * I1IiiI % Ii1I + ooOoO0o
    if 46 - 46: OoOoOO00
  if ( Ooo0oOo0o0oOo == LISP_DDT_ACTION_MS_NOT_REG ) :
   if ( I11I1 . referral_set . has_key ( i1I1iIi1IiI ) ) :
    oOoooooOoOoO = I11I1 . referral_set [ i1I1iIi1IiI ]
    oOoooooOoOoO . updown = False
    if 66 - 66: iII111i - O0 . I1Ii111 * i1IIi / OoO0O00 / II111iiii
   if ( len ( I11I1 . referral_set ) == 0 ) :
    oOoooooOooO . dequeue_map_request ( )
   else :
    lisp_send_ddt_map_request ( oOoooooOooO , False )
    if 35 - 35: ooOoO0o * OOooOOo / I11i % I11i / OoooooooOO . I1Ii111
    if 70 - 70: I1ii11iIi11i % I1ii11iIi11i / oO0o
    if 85 - 85: OoOoOO00 % I11i / Oo0Ooo + I11i - Oo0Ooo
  if ( Ooo0oOo0o0oOo in ( LISP_DDT_ACTION_NODE_REFERRAL ,
 LISP_DDT_ACTION_MS_REFERRAL ) ) :
   if ( oOoooooOooO . eid . is_exact_match ( O0OO000oOO0 . eid ) ) :
    if ( not oOoooooOooO . tried_root ) :
     lisp_send_ddt_map_request ( oOoooooOooO , True )
    else :
     lisp_send_negative_map_reply ( oOoooooOooO . lisp_sockets ,
 I11I1 . eid , I11I1 . group , oOoooooOooO . nonce , oOoooooOooO . itr ,
 oOoooooOooO . sport , 15 , None , False )
     oOoooooOooO . dequeue_map_request ( )
     if 20 - 20: IiII
   else :
    lisp_send_ddt_map_request ( oOoooooOooO , False )
    if 81 - 81: Oo0Ooo / I1Ii111
    if 20 - 20: o0oOOo0O0Ooo + ooOoO0o % i1IIi
    if 51 - 51: iII111i - ooOoO0o
  if ( Ooo0oOo0o0oOo == LISP_DDT_ACTION_MS_ACK ) : oOoooooOooO . dequeue_map_request ( )
  if 32 - 32: IiII - i11iIiiIii
 return
 if 41 - 41: Ii1I % Ii1I * oO0o - I11i + iIii1I11I1II1 . ooOoO0o
 if 30 - 30: Ii1I * iII111i . II111iiii / i1IIi
 if 77 - 77: oO0o . IiII + I1ii11iIi11i . i1IIi
 if 49 - 49: I1Ii111 . OoooooooOO / o0oOOo0O0Ooo - iII111i - iII111i - i11iIiiIii
 if 37 - 37: OOooOOo
 if 79 - 79: I1Ii111 - OoO0O00 + ooOoO0o + oO0o . i11iIiiIii + i1IIi
 if 32 - 32: IiII . ooOoO0o / OoO0O00 / iII111i . iIii1I11I1II1 % IiII
 if 28 - 28: I1Ii111 + OoooooooOO + IiII . ooOoO0o . I1IiiI / oO0o
def lisp_process_ecm ( lisp_sockets , packet , source , ecm_port ) :
 I1i = lisp_ecm ( 0 )
 packet = I1i . decode ( packet )
 if ( packet == None ) :
  lprint ( "Could not decode ECM packet" )
  return
  if 66 - 66: Ii1I - I11i + Oo0Ooo . ooOoO0o
  if 89 - 89: IiII . II111iiii / OoO0O00 + I1ii11iIi11i * i11iIiiIii
 I1i . print_ecm ( )
 if 85 - 85: o0oOOo0O0Ooo - Oo0Ooo / I1Ii111
 III1Iiii1i11 = lisp_control_header ( )
 if ( III1Iiii1i11 . decode ( packet ) == None ) :
  lprint ( "Could not decode control header" )
  return
  if 100 - 100: OoO0O00 * iIii1I11I1II1 - IiII . i1IIi % i11iIiiIii % Oo0Ooo
  if 22 - 22: ooOoO0o - OOooOOo
 ooOiiI1 = III1Iiii1i11 . type
 del ( III1Iiii1i11 )
 if 3 - 3: I1IiiI % OoO0O00
 if ( ooOiiI1 != LISP_MAP_REQUEST ) :
  lprint ( "Received ECM without Map-Request inside" )
  return
  if 18 - 18: I1ii11iIi11i * I11i
  if 57 - 57: o0oOOo0O0Ooo % I1IiiI * i11iIiiIii - I1ii11iIi11i + I1IiiI % ooOoO0o
  if 10 - 10: OoooooooOO % iII111i / IiII
  if 64 - 64: ooOoO0o % O0 / oO0o
  if 21 - 21: i11iIiiIii . o0oOOo0O0Ooo
 o0O0O0 = I1i . udp_sport
 lisp_process_map_request ( lisp_sockets , packet , source , ecm_port ,
 I1i . source , o0O0O0 , I1i . ddt , - 1 )
 return
 if 37 - 37: o0oOOo0O0Ooo
 if 84 - 84: Oo0Ooo * i11iIiiIii * OoooooooOO % I1ii11iIi11i / i11iIiiIii
 if 80 - 80: ooOoO0o - I1Ii111 / oO0o - Ii1I + oO0o
 if 82 - 82: i11iIiiIii / i1IIi + O0 . ooOoO0o
 if 80 - 80: I1IiiI - OOooOOo + OoOoOO00
 if 53 - 53: OoooooooOO . I11i * OOooOOo + i11iIiiIii * O0 . iIii1I11I1II1
 if 72 - 72: IiII . ooOoO0o . Oo0Ooo - iIii1I11I1II1 % IiII
 if 97 - 97: OoooooooOO
 if 26 - 26: I11i . I1IiiI / IiII / Oo0Ooo % Oo0Ooo / O0
 if 27 - 27: I11i - I11i % OoO0O00 - iII111i . OOooOOo - iIii1I11I1II1
def lisp_send_map_register ( lisp_sockets , packet , map_register , ms ) :
 if 15 - 15: OoO0O00 + iIii1I11I1II1
 if 89 - 89: OoooooooOO * Ii1I
 if 4 - 4: Ii1I + OoO0O00 * O0
 if 13 - 13: I11i + O0 / oO0o % O0 . I11i
 if 22 - 22: OoOoOO00 . I1IiiI % ooOoO0o + I1Ii111 - OoooooooOO
 if 55 - 55: OoooooooOO * O0 - II111iiii / IiII
 if 18 - 18: II111iiii % O0 - o0oOOo0O0Ooo * ooOoO0o
 I1I1I1 = ms . map_server
 if ( lisp_decent_push_configured and I1I1I1 . is_multicast_address ( ) and
 ( ms . map_registers_multicast_sent == 1 or ms . map_registers_sent == 1 ) ) :
  I1I1I1 = copy . deepcopy ( I1I1I1 )
  I1I1I1 . address = 0x7f000001
  iI = bold ( "Bootstrap" , False )
  OooooOOOO = ms . map_server . print_address_no_iid ( )
  lprint ( "{} mapping system for peer-group {}" . format ( iI , OooooOOOO ) )
  if 74 - 74: I11i . oO0o + I11i * o0oOOo0O0Ooo / O0
  if 55 - 55: OoO0O00 / i11iIiiIii / o0oOOo0O0Ooo
  if 19 - 19: ooOoO0o * iII111i
  if 38 - 38: ooOoO0o
  if 35 - 35: o0oOOo0O0Ooo * IiII * Oo0Ooo
  if 34 - 34: I11i - OoooooooOO % i1IIi + I1IiiI
 packet = lisp_compute_auth ( packet , map_register , ms . password )
 if 14 - 14: I1IiiI . o0oOOo0O0Ooo / I1Ii111
 if 67 - 67: OoooooooOO . oO0o * OoOoOO00 - OoooooooOO
 if 32 - 32: oO0o
 if 72 - 72: I1IiiI
 if 34 - 34: ooOoO0o % II111iiii / ooOoO0o
 if ( ms . ekey != None ) :
  III11i1iiii = ms . ekey . zfill ( 32 )
  O00oO0O = "0" * 8
  iI1iii1iI1 = chacha . ChaCha ( III11i1iiii , O00oO0O ) . encrypt ( packet [ 4 : : ] )
  packet = packet [ 0 : 4 ] + iI1iii1iI1
  I1i11II = bold ( "Encrypt" , False )
  lprint ( "{} Map-Register with key-id {}" . format ( I1i11II , ms . ekey_id ) )
  if 87 - 87: Oo0Ooo
  if 7 - 7: iIii1I11I1II1
 oo = ""
 if ( lisp_decent_pull_xtr_configured ( ) ) :
  oo = ", decent-index {}" . format ( bold ( ms . dns_name , False ) )
  if 7 - 7: OoooooooOO % OoOoOO00 / OoOoOO00
  if 68 - 68: Oo0Ooo * oO0o - IiII % i11iIiiIii * OOooOOo
 lprint ( "Send Map-Register to map-server {}{}{}" . format ( I1I1I1 . print_address ( ) , ", ms-name '{}'" . format ( ms . ms_name ) , oo ) )
 if 43 - 43: Oo0Ooo - OoOoOO00 * ooOoO0o - OOooOOo * Oo0Ooo
 lisp_send ( lisp_sockets , I1I1I1 , LISP_CTRL_PORT , packet )
 return
 if 68 - 68: O0 % i11iIiiIii / OoO0O00
 if 44 - 44: OoOoOO00 - I11i
 if 71 - 71: o0oOOo0O0Ooo - I1Ii111
 if 45 - 45: II111iiii - OOooOOo / oO0o % O0 . iII111i . iII111i
 if 82 - 82: iIii1I11I1II1 % Oo0Ooo * i1IIi - I1Ii111 - I1ii11iIi11i / iII111i
 if 24 - 24: IiII
 if 95 - 95: IiII + OoOoOO00 * OOooOOo
 if 92 - 92: OoOoOO00 + ooOoO0o . iII111i
def lisp_send_ipc_to_core ( lisp_socket , packet , dest , port ) :
 O00oo0o0o0oo = lisp_socket . getsockname ( )
 dest = dest . print_address_no_iid ( )
 if 59 - 59: iIii1I11I1II1 % I1Ii111 + I1ii11iIi11i . OoOoOO00 * Oo0Ooo / I1Ii111
 lprint ( "Send IPC {} bytes to {} {}, control-packet: {}" . format ( len ( packet ) , dest , port , lisp_format_packet ( packet ) ) )
 if 41 - 41: i1IIi / IiII
 if 73 - 73: o0oOOo0O0Ooo % ooOoO0o
 packet = lisp_control_packet_ipc ( packet , O00oo0o0o0oo , dest , port )
 lisp_ipc ( packet , lisp_socket , "lisp-core-pkt" )
 return
 if 72 - 72: OoO0O00 * OoOoOO00 % I1IiiI - OOooOOo . Oo0Ooo
 if 70 - 70: ooOoO0o . o0oOOo0O0Ooo * II111iiii - O0
 if 74 - 74: oO0o % I1IiiI / oO0o / Oo0Ooo / ooOoO0o
 if 29 - 29: ooOoO0o + iIii1I11I1II1 + OoO0O00 - o0oOOo0O0Ooo
 if 74 - 74: II111iiii - II111iiii + ooOoO0o + Oo0Ooo % iIii1I11I1II1
 if 90 - 90: oO0o / o0oOOo0O0Ooo . o0oOOo0O0Ooo % OoOoOO00 / IiII
 if 13 - 13: oO0o + IiII
 if 36 - 36: oO0o - OoOoOO00 . O0 % IiII
def lisp_send_map_reply ( lisp_sockets , packet , dest , port ) :
 lprint ( "Send Map-Reply to {}" . format ( dest . print_address_no_iid ( ) ) )
 lisp_send_ipc_to_core ( lisp_sockets [ 2 ] , packet , dest , port )
 return
 if 65 - 65: Oo0Ooo - i11iIiiIii * OoOoOO00 . I1Ii111 . iIii1I11I1II1
 if 48 - 48: iIii1I11I1II1 - oO0o / OoO0O00 + O0 . Ii1I + I1Ii111
 if 17 - 17: OoOoOO00 . Oo0Ooo - I1Ii111 / I1Ii111 + I11i % i1IIi
 if 31 - 31: OoooooooOO . O0 / OoO0O00 . I1Ii111
 if 41 - 41: OoooooooOO + iII111i . OOooOOo
 if 73 - 73: oO0o + i1IIi + i11iIiiIii / I1ii11iIi11i
 if 100 - 100: I1IiiI % ooOoO0o % OoooooooOO / i11iIiiIii + i11iIiiIii % IiII
 if 39 - 39: Ii1I % o0oOOo0O0Ooo + OOooOOo / iIii1I11I1II1
def lisp_send_map_referral ( lisp_sockets , packet , dest , port ) :
 lprint ( "Send Map-Referral to {}" . format ( dest . print_address ( ) ) )
 lisp_send_ipc_to_core ( lisp_sockets [ 2 ] , packet , dest , port )
 return
 if 40 - 40: iIii1I11I1II1 / iII111i % OOooOOo % i11iIiiIii
 if 57 - 57: II111iiii % OoO0O00 * i1IIi
 if 19 - 19: ooOoO0o . iIii1I11I1II1 + I1ii11iIi11i + I1ii11iIi11i / o0oOOo0O0Ooo . Oo0Ooo
 if 9 - 9: II111iiii % OoooooooOO
 if 4 - 4: i1IIi * i11iIiiIii % OoooooooOO + OoOoOO00 . oO0o
 if 95 - 95: I1ii11iIi11i * OoOoOO00 % o0oOOo0O0Ooo / O0 + ooOoO0o % OOooOOo
 if 48 - 48: i1IIi + IiII - iIii1I11I1II1 . i11iIiiIii % OOooOOo + I1ii11iIi11i
 if 95 - 95: ooOoO0o + OoOoOO00 . II111iiii + Ii1I
def lisp_send_map_notify ( lisp_sockets , packet , dest , port ) :
 lprint ( "Send Map-Notify to xTR {}" . format ( dest . print_address ( ) ) )
 lisp_send_ipc_to_core ( lisp_sockets [ 2 ] , packet , dest , port )
 return
 if 81 - 81: OoooooooOO / OOooOOo / Oo0Ooo
 if 26 - 26: iII111i
 if 93 - 93: Oo0Ooo + I1IiiI % OoOoOO00 / OOooOOo / I1ii11iIi11i
 if 6 - 6: IiII
 if 68 - 68: Oo0Ooo
 if 83 - 83: OOooOOo / iIii1I11I1II1 . OoO0O00 - oO0o % Oo0Ooo
 if 30 - 30: Ii1I . OoOoOO00 / oO0o . OoO0O00
def lisp_send_ecm ( lisp_sockets , packet , inner_source , inner_sport , inner_dest ,
 outer_dest , to_etr = False , to_ms = False , ddt = False ) :
 if 93 - 93: i11iIiiIii
 if ( inner_source == None or inner_source . is_null ( ) ) :
  inner_source = inner_dest
  if 33 - 33: i1IIi % OoooooooOO + Oo0Ooo % I1IiiI / ooOoO0o
  if 40 - 40: IiII % IiII
  if 9 - 9: I1IiiI * i1IIi + OOooOOo * OoOoOO00
  if 8 - 8: iII111i
  if 51 - 51: I1IiiI
  if 72 - 72: ooOoO0o / I1ii11iIi11i . Ii1I * iII111i . iIii1I11I1II1
 if ( lisp_nat_traversal ) :
  i1IiiI = lisp_get_any_translated_port ( )
  if ( i1IiiI != None ) : inner_sport = i1IiiI
  if 35 - 35: OoO0O00 . OoOoOO00 % O0 * OoO0O00
 I1i = lisp_ecm ( inner_sport )
 if 68 - 68: OOooOOo
 I1i . to_etr = to_etr if lisp_is_running ( "lisp-etr" ) else False
 I1i . to_ms = to_ms if lisp_is_running ( "lisp-ms" ) else False
 I1i . ddt = ddt
 O0O0oOOOoOoo = I1i . encode ( packet , inner_source , inner_dest )
 if ( O0O0oOOOoOoo == None ) :
  lprint ( "Could not encode ECM message" )
  return
  if 82 - 82: Oo0Ooo - oO0o
 I1i . print_ecm ( )
 if 36 - 36: Oo0Ooo / Oo0Ooo - o0oOOo0O0Ooo - i11iIiiIii
 packet = O0O0oOOOoOoo + packet
 if 59 - 59: i11iIiiIii / iIii1I11I1II1 / ooOoO0o
 OoOOoooO000 = outer_dest . print_address_no_iid ( )
 lprint ( "Send Encapsulated-Control-Message to {}" . format ( OoOOoooO000 ) )
 I1I1I1 = lisp_convert_4to6 ( OoOOoooO000 )
 lisp_send ( lisp_sockets , I1I1I1 , LISP_CTRL_PORT , packet )
 return
 if 2 - 2: iII111i + II111iiii
 if 88 - 88: i1IIi - iII111i / OOooOOo / i1IIi
 if 48 - 48: iII111i / OoooooooOO / iIii1I11I1II1
 if 41 - 41: II111iiii - II111iiii - OoO0O00 + oO0o * I11i
 if 77 - 77: IiII % iIii1I11I1II1 - OOooOOo / I1Ii111 / ooOoO0o . iII111i
 if 62 - 62: I1Ii111
 if 42 - 42: o0oOOo0O0Ooo
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
if 59 - 59: I1ii11iIi11i % O0 - i1IIi . Oo0Ooo
LISP_RLOC_UNKNOWN_STATE = 0
LISP_RLOC_UP_STATE = 1
LISP_RLOC_DOWN_STATE = 2
LISP_RLOC_UNREACH_STATE = 3
LISP_RLOC_NO_ECHOED_NONCE_STATE = 4
LISP_RLOC_ADMIN_DOWN_STATE = 5
if 18 - 18: II111iiii
LISP_AUTH_NONE = 0
LISP_AUTH_MD5 = 1
LISP_AUTH_SHA1 = 2
LISP_AUTH_SHA2 = 3
if 31 - 31: Oo0Ooo / Oo0Ooo / iIii1I11I1II1 / I11i % OoooooooOO
if 90 - 90: I1IiiI
if 35 - 35: O0
if 10 - 10: Ii1I - I1Ii111 / Oo0Ooo + O0
if 67 - 67: Ii1I % i11iIiiIii . Oo0Ooo
if 78 - 78: I1IiiI - iIii1I11I1II1
if 20 - 20: i11iIiiIii % I1IiiI % OoOoOO00
LISP_IPV4_HOST_MASK_LEN = 32
LISP_IPV6_HOST_MASK_LEN = 128
LISP_MAC_HOST_MASK_LEN = 48
LISP_E164_HOST_MASK_LEN = 60
if 85 - 85: I11i + OoOoOO00 * O0 * O0
if 92 - 92: i11iIiiIii
if 16 - 16: I11i . ooOoO0o - Oo0Ooo / OoO0O00 . i1IIi
if 59 - 59: ooOoO0o - ooOoO0o % I11i + OoO0O00
if 88 - 88: Ii1I - ooOoO0o . Oo0Ooo
if 83 - 83: I11i + Oo0Ooo . I1ii11iIi11i * I1ii11iIi11i
def byte_swap_64 ( address ) :
 I1Iii1I = ( ( address & 0x00000000000000ff ) << 56 ) | ( ( address & 0x000000000000ff00 ) << 40 ) | ( ( address & 0x0000000000ff0000 ) << 24 ) | ( ( address & 0x00000000ff000000 ) << 8 ) | ( ( address & 0x000000ff00000000 ) >> 8 ) | ( ( address & 0x0000ff0000000000 ) >> 24 ) | ( ( address & 0x00ff000000000000 ) >> 40 ) | ( ( address & 0xff00000000000000 ) >> 56 )
 if 80 - 80: i1IIi * I11i - OOooOOo / II111iiii * iIii1I11I1II1
 if 42 - 42: OoOoOO00 . I11i % II111iiii
 if 19 - 19: OoooooooOO
 if 31 - 31: I11i . OoOoOO00 - O0 * iII111i % I1Ii111 - II111iiii
 if 21 - 21: OOooOOo . Oo0Ooo - i1IIi
 if 56 - 56: I11i
 if 24 - 24: I1IiiI . I1IiiI % ooOoO0o
 if 32 - 32: OOooOOo / i1IIi / OOooOOo
 return ( I1Iii1I )
 if 97 - 97: ooOoO0o * Oo0Ooo * OoooooooOO * I1IiiI
 if 45 - 45: Oo0Ooo
 if 27 - 27: oO0o / IiII - iIii1I11I1II1 / o0oOOo0O0Ooo % OOooOOo * iIii1I11I1II1
 if 40 - 40: oO0o - II111iiii * OOooOOo % OoooooooOO
 if 52 - 52: OOooOOo + OoO0O00
 if 96 - 96: OOooOOo % O0 - Oo0Ooo % oO0o / I1IiiI . i1IIi
 if 42 - 42: i1IIi
 if 52 - 52: OoO0O00 % iII111i % O0
 if 11 - 11: i1IIi / i11iIiiIii + Ii1I % Oo0Ooo % O0
 if 50 - 50: oO0o . I1Ii111
 if 38 - 38: iIii1I11I1II1 . Ii1I
 if 82 - 82: OOooOOo * Ii1I + I1ii11iIi11i . OoO0O00
 if 15 - 15: O0
 if 44 - 44: Ii1I . Oo0Ooo . I1Ii111 + oO0o
 if 32 - 32: OOooOOo - II111iiii + IiII * iIii1I11I1II1 - Oo0Ooo
class lisp_cache_entries ( ) :
 def __init__ ( self ) :
  self . entries = { }
  self . entries_sorted = [ ]
  if 25 - 25: ooOoO0o
  if 33 - 33: Oo0Ooo
  if 11 - 11: I11i
class lisp_cache ( ) :
 def __init__ ( self ) :
  self . cache = { }
  self . cache_sorted = [ ]
  self . cache_count = 0
  if 55 - 55: i11iIiiIii * OoOoOO00 - OoOoOO00 * OoO0O00 / iII111i
  if 64 - 64: iIii1I11I1II1 . Ii1I * Oo0Ooo - OoO0O00
 def cache_size ( self ) :
  return ( self . cache_count )
  if 74 - 74: I1IiiI / o0oOOo0O0Ooo
  if 53 - 53: iIii1I11I1II1 * oO0o
 def build_key ( self , prefix ) :
  if ( prefix . afi == LISP_AFI_ULTIMATE_ROOT ) :
   IiiIiiii = 0
  elif ( prefix . afi == LISP_AFI_IID_RANGE ) :
   IiiIiiii = prefix . mask_len
  else :
   IiiIiiii = prefix . mask_len + 48
   if 43 - 43: IiII * Oo0Ooo / OOooOOo % oO0o
   if 11 - 11: OoOoOO00 * Oo0Ooo / I11i * OOooOOo
  IIiI1i = lisp_hex_string ( prefix . instance_id ) . zfill ( 8 )
  o0O0O0O00o = lisp_hex_string ( prefix . afi ) . zfill ( 4 )
  if 15 - 15: ooOoO0o - OOooOOo / OoooooooOO
  if ( prefix . afi > 0 ) :
   if ( prefix . is_binary ( ) ) :
    I111 = prefix . addr_length ( ) * 2
    I1Iii1I = lisp_hex_string ( prefix . address ) . zfill ( I111 )
   else :
    I1Iii1I = prefix . address
    if 41 - 41: OoOoOO00 . iII111i . i1IIi + oO0o
  elif ( prefix . afi == LISP_AFI_GEO_COORD ) :
   o0O0O0O00o = "8003"
   I1Iii1I = prefix . address . print_geo ( )
  else :
   o0O0O0O00o = ""
   I1Iii1I = ""
   if 60 - 60: oO0o * I1Ii111
   if 81 - 81: oO0o - OOooOOo - oO0o
  iIIIi = IIiI1i + o0O0O0O00o + I1Iii1I
  return ( [ IiiIiiii , iIIIi ] )
  if 54 - 54: oO0o % I11i
  if 71 - 71: oO0o / I1ii11iIi11i . Ii1I % II111iiii
 def add_cache ( self , prefix , entry ) :
  if ( prefix . is_binary ( ) ) : prefix . zero_host_bits ( )
  IiiIiiii , iIIIi = self . build_key ( prefix )
  if ( self . cache . has_key ( IiiIiiii ) == False ) :
   self . cache [ IiiIiiii ] = lisp_cache_entries ( )
   self . cache [ IiiIiiii ] . entries = { }
   self . cache [ IiiIiiii ] . entries_sorted = [ ]
   self . cache_sorted = sorted ( self . cache )
   if 22 - 22: iIii1I11I1II1 - OoooooooOO
  if ( self . cache [ IiiIiiii ] . entries . has_key ( iIIIi ) == False ) :
   self . cache_count += 1
   if 8 - 8: ooOoO0o % i11iIiiIii
  self . cache [ IiiIiiii ] . entries [ iIIIi ] = entry
  self . cache [ IiiIiiii ] . entries_sorted = sorted ( self . cache [ IiiIiiii ] . entries )
  if 41 - 41: I1Ii111 . ooOoO0o - i11iIiiIii + Ii1I . OOooOOo . OoOoOO00
  if 70 - 70: i1IIi % OoOoOO00 / iII111i + i11iIiiIii % ooOoO0o + IiII
 def lookup_cache ( self , prefix , exact ) :
  O0oo0 , iIIIi = self . build_key ( prefix )
  if ( exact ) :
   if ( self . cache . has_key ( O0oo0 ) == False ) : return ( None )
   if ( self . cache [ O0oo0 ] . entries . has_key ( iIIIi ) == False ) : return ( None )
   return ( self . cache [ O0oo0 ] . entries [ iIIIi ] )
   if 36 - 36: oO0o * OoOoOO00 / ooOoO0o % iII111i / iIii1I11I1II1
   if 73 - 73: O0 % i11iIiiIii
  OoO0OOOO = None
  for IiiIiiii in self . cache_sorted :
   if ( O0oo0 < IiiIiiii ) : return ( OoO0OOOO )
   for iiIii1 in self . cache [ IiiIiiii ] . entries_sorted :
    II1ooOOoOoOo = self . cache [ IiiIiiii ] . entries
    if ( iiIii1 in II1ooOOoOoOo ) :
     oOoO = II1ooOOoOoOo [ iiIii1 ]
     if ( oOoO == None ) : continue
     if ( prefix . is_more_specific ( oOoO . eid ) ) : OoO0OOOO = oOoO
     if 97 - 97: Ii1I + I1Ii111 / II111iiii
     if 14 - 14: iII111i / IiII / oO0o
     if 55 - 55: OoO0O00 % O0
  return ( OoO0OOOO )
  if 92 - 92: OoooooooOO / O0
  if 14 - 14: i11iIiiIii
 def delete_cache ( self , prefix ) :
  IiiIiiii , iIIIi = self . build_key ( prefix )
  if ( self . cache . has_key ( IiiIiiii ) == False ) : return
  if ( self . cache [ IiiIiiii ] . entries . has_key ( iIIIi ) == False ) : return
  self . cache [ IiiIiiii ] . entries . pop ( iIIIi )
  self . cache [ IiiIiiii ] . entries_sorted . remove ( iIIIi )
  self . cache_count -= 1
  if 43 - 43: OOooOOo
  if 79 - 79: iII111i % Oo0Ooo . i1IIi % ooOoO0o
 def walk_cache ( self , function , parms ) :
  for IiiIiiii in self . cache_sorted :
   for iIIIi in self . cache [ IiiIiiii ] . entries_sorted :
    oOoO = self . cache [ IiiIiiii ] . entries [ iIIIi ]
    oO00o0O , parms = function ( oOoO , parms )
    if ( oO00o0O == False ) : return ( parms )
    if 94 - 94: Ii1I . I1Ii111 * I11i . ooOoO0o . oO0o
    if 54 - 54: Oo0Ooo
  return ( parms )
  if 2 - 2: OoooooooOO / o0oOOo0O0Ooo / Oo0Ooo
  if 100 - 100: O0 . i11iIiiIii % I1Ii111 % OoooooooOO
 def print_cache ( self ) :
  lprint ( "Printing contents of {}: " . format ( self ) )
  if ( self . cache_size ( ) == 0 ) :
   lprint ( "  Cache is empty" )
   return
   if 88 - 88: IiII - OOooOOo * Ii1I * iII111i . OoO0O00 % IiII
  for IiiIiiii in self . cache_sorted :
   for iIIIi in self . cache [ IiiIiiii ] . entries_sorted :
    oOoO = self . cache [ IiiIiiii ] . entries [ iIIIi ]
    lprint ( "  Mask-length: {}, key: {}, entry: {}" . format ( IiiIiiii , iIIIi ,
 oOoO ) )
    if 24 - 24: OOooOOo / oO0o * OOooOOo
    if 35 - 35: OoooooooOO + I1ii11iIi11i + Oo0Ooo - i11iIiiIii / o0oOOo0O0Ooo . II111iiii
    if 63 - 63: O0
    if 64 - 64: i11iIiiIii / oO0o . oO0o - Oo0Ooo
    if 48 - 48: i1IIi + I1ii11iIi11i + I1Ii111 - iII111i
    if 3 - 3: i1IIi + OoooooooOO * ooOoO0o + I1Ii111 % OOooOOo / IiII
    if 70 - 70: oO0o + i1IIi % o0oOOo0O0Ooo - I11i
    if 74 - 74: i11iIiiIii
lisp_referral_cache = lisp_cache ( )
lisp_ddt_cache = lisp_cache ( )
lisp_sites_by_eid = lisp_cache ( )
lisp_map_cache = lisp_cache ( )
lisp_db_for_lookups = lisp_cache ( )
if 93 - 93: I1Ii111 % OOooOOo * I1IiiI % iII111i / iIii1I11I1II1 + OoO0O00
if 6 - 6: I11i
if 70 - 70: ooOoO0o + OoooooooOO % OoOoOO00 % oO0o / Ii1I . I11i
if 63 - 63: I1ii11iIi11i - ooOoO0o . OOooOOo / O0 . iIii1I11I1II1 - Ii1I
if 6 - 6: Ii1I
if 60 - 60: iII111i + I1IiiI
if 36 - 36: i1IIi . O0 . OoO0O00 % OOooOOo * I11i / Ii1I
def lisp_map_cache_lookup ( source , dest ) :
 if 16 - 16: Oo0Ooo
 iIIiI1iiIi = dest . is_multicast_address ( )
 if 44 - 44: iIii1I11I1II1 - II111iiii . IiII . i1IIi
 if 37 - 37: OoooooooOO + Oo0Ooo - Oo0Ooo + I1ii11iIi11i . I1Ii111 / I1IiiI
 if 60 - 60: I1IiiI % Ii1I / I1Ii111 + Ii1I
 if 43 - 43: I1ii11iIi11i + I11i
 oOooO0Oo0Oo0 = lisp_map_cache . lookup_cache ( dest , False )
 if ( oOooO0Oo0Oo0 == None ) :
  oo0ooooO = source . print_sg ( dest ) if iIIiI1iiIi else dest . print_address ( )
  oo0ooooO = green ( oo0ooooO , False )
  dprint ( "Lookup for EID {} not found in map-cache" . format ( oo0ooooO ) )
  return ( None )
  if 83 - 83: II111iiii + o0oOOo0O0Ooo - I1Ii111
  if 100 - 100: IiII - OoOoOO00 / I11i
  if 33 - 33: I1Ii111 * OoOoOO00 . I1ii11iIi11i % I1Ii111
  if 87 - 87: Oo0Ooo
  if 65 - 65: ooOoO0o . I1IiiI
 if ( iIIiI1iiIi == False ) :
  oOo00 = green ( oOooO0Oo0Oo0 . eid . print_prefix ( ) , False )
  dprint ( "Lookup for EID {} found map-cache entry {}" . format ( green ( dest . print_address ( ) , False ) , oOo00 ) )
  if 51 - 51: IiII
  return ( oOooO0Oo0Oo0 )
  if 43 - 43: oO0o - I11i . i11iIiiIii
  if 78 - 78: i11iIiiIii + Oo0Ooo * Ii1I - o0oOOo0O0Ooo % i11iIiiIii
  if 30 - 30: I1IiiI % oO0o * OoooooooOO
  if 64 - 64: I1IiiI
  if 11 - 11: I1ii11iIi11i % iII111i / II111iiii % ooOoO0o % IiII
 oOooO0Oo0Oo0 = oOooO0Oo0Oo0 . lookup_source_cache ( source , False )
 if ( oOooO0Oo0Oo0 == None ) :
  oo0ooooO = source . print_sg ( dest )
  dprint ( "Lookup for EID {} not found in map-cache" . format ( oo0ooooO ) )
  return ( None )
  if 14 - 14: ooOoO0o / IiII . o0oOOo0O0Ooo
  if 27 - 27: I1IiiI - OOooOOo . II111iiii * I1ii11iIi11i % ooOoO0o / I1IiiI
  if 90 - 90: o0oOOo0O0Ooo / I1ii11iIi11i - oO0o - Ii1I - I1IiiI + I1Ii111
  if 93 - 93: I1IiiI - I11i . I1IiiI - iIii1I11I1II1
  if 1 - 1: O0 . Ii1I % Ii1I + II111iiii . oO0o
 oOo00 = green ( oOooO0Oo0Oo0 . print_eid_tuple ( ) , False )
 dprint ( "Lookup for EID {} found map-cache entry {}" . format ( green ( source . print_sg ( dest ) , False ) , oOo00 ) )
 if 24 - 24: o0oOOo0O0Ooo . I1Ii111 % O0
 return ( oOooO0Oo0Oo0 )
 if 67 - 67: I1IiiI * Ii1I
 if 64 - 64: OOooOOo
 if 90 - 90: iII111i . OoOoOO00 + i1IIi % ooOoO0o * I11i + OoooooooOO
 if 2 - 2: o0oOOo0O0Ooo . II111iiii
 if 9 - 9: I1Ii111 - II111iiii + OoOoOO00 . OoO0O00
 if 33 - 33: Oo0Ooo
 if 12 - 12: i11iIiiIii . Oo0Ooo / OoOoOO00 + iII111i . Ii1I + ooOoO0o
def lisp_referral_cache_lookup ( eid , group , exact ) :
 if ( group and group . is_null ( ) ) :
  ooOo = lisp_referral_cache . lookup_cache ( eid , exact )
  return ( ooOo )
  if 66 - 66: IiII
  if 41 - 41: II111iiii + Oo0Ooo / iII111i . IiII / iII111i / I1IiiI
  if 78 - 78: o0oOOo0O0Ooo % OoOoOO00 . O0
  if 41 - 41: iIii1I11I1II1 . OOooOOo - Oo0Ooo % OOooOOo
  if 90 - 90: i11iIiiIii + OoooooooOO - i11iIiiIii + OoooooooOO
 if ( eid == None or eid . is_null ( ) ) : return ( None )
 if 23 - 23: i11iIiiIii - IiII - I1ii11iIi11i + I1ii11iIi11i % I1IiiI
 if 79 - 79: II111iiii / OoooooooOO
 if 35 - 35: i1IIi + IiII + II111iiii % OOooOOo
 if 25 - 25: I11i + i11iIiiIii + O0 - Ii1I
 if 69 - 69: I11i . OoOoOO00 / OOooOOo / i1IIi . II111iiii
 if 17 - 17: I1Ii111
 ooOo = lisp_referral_cache . lookup_cache ( group , exact )
 if ( ooOo == None ) : return ( None )
 if 2 - 2: O0 % OoOoOO00 + oO0o
 I1I11i1 = ooOo . lookup_source_cache ( eid , exact )
 if ( I1I11i1 ) : return ( I1I11i1 )
 if 18 - 18: o0oOOo0O0Ooo
 if ( exact ) : ooOo = None
 return ( ooOo )
 if 15 - 15: o0oOOo0O0Ooo / I11i - iIii1I11I1II1 * Ii1I + O0 % IiII
 if 59 - 59: i11iIiiIii % iIii1I11I1II1 / IiII
 if 100 - 100: Ii1I . o0oOOo0O0Ooo - II111iiii . O0
 if 5 - 5: iII111i
 if 66 - 66: oO0o / OoOoOO00 . i1IIi % ooOoO0o . iII111i * I11i
 if 48 - 48: oO0o % OoOoOO00
 if 23 - 23: i1IIi - Ii1I - oO0o . OoooooooOO + OOooOOo * oO0o
def lisp_ddt_cache_lookup ( eid , group , exact ) :
 if ( group . is_null ( ) ) :
  I1io0 = lisp_ddt_cache . lookup_cache ( eid , exact )
  return ( I1io0 )
  if 56 - 56: O0 + OoOoOO00 + OoO0O00 - iIii1I11I1II1 . iIii1I11I1II1 . i11iIiiIii
  if 84 - 84: I11i + OOooOOo - OoooooooOO / I1ii11iIi11i
  if 12 - 12: I1IiiI * iIii1I11I1II1 - II111iiii / o0oOOo0O0Ooo - OOooOOo
  if 99 - 99: I1ii11iIi11i / O0 % II111iiii % I1Ii111 * II111iiii
  if 28 - 28: I11i - Oo0Ooo + iIii1I11I1II1 + O0 * Ii1I + I1IiiI
 if ( eid . is_null ( ) ) : return ( None )
 if 13 - 13: iII111i
 if 42 - 42: I1Ii111 - I1IiiI % I1IiiI * I1IiiI
 if 70 - 70: O0 / I1IiiI / I1IiiI
 if 71 - 71: OOooOOo - Oo0Ooo + IiII * oO0o
 if 90 - 90: OoOoOO00 * I1ii11iIi11i
 if 16 - 16: i1IIi - OoO0O00
 I1io0 = lisp_ddt_cache . lookup_cache ( group , exact )
 if ( I1io0 == None ) : return ( None )
 if 61 - 61: o0oOOo0O0Ooo + OoOoOO00 - ooOoO0o + ooOoO0o % ooOoO0o % II111iiii
 ii1O0ooooo0OoO0 = I1io0 . lookup_source_cache ( eid , exact )
 if ( ii1O0ooooo0OoO0 ) : return ( ii1O0ooooo0OoO0 )
 if 60 - 60: i11iIiiIii % IiII % i1IIi
 if ( exact ) : I1io0 = None
 return ( I1io0 )
 if 24 - 24: OOooOOo - OoOoOO00 - i1IIi + O0 + I1IiiI . o0oOOo0O0Ooo
 if 97 - 97: I1Ii111 + Ii1I * ooOoO0o
 if 95 - 95: O0
 if 61 - 61: Oo0Ooo % O0 . Ii1I - OOooOOo - o0oOOo0O0Ooo
 if 71 - 71: iIii1I11I1II1
 if 10 - 10: OoooooooOO - iII111i . i1IIi % oO0o . OoooooooOO + OOooOOo
 if 59 - 59: I1IiiI * OoooooooOO % OOooOOo / I11i
def lisp_site_eid_lookup ( eid , group , exact ) :
 if 77 - 77: II111iiii - IiII % OOooOOo
 if ( group . is_null ( ) ) :
  IiIi1II1i = lisp_sites_by_eid . lookup_cache ( eid , exact )
  return ( IiIi1II1i )
  if 22 - 22: OoooooooOO / oO0o
  if 78 - 78: oO0o * I11i . i1IIi % i1IIi + i1IIi / OOooOOo
  if 66 - 66: OoooooooOO % o0oOOo0O0Ooo / I11i * I1Ii111
  if 12 - 12: I1Ii111
  if 17 - 17: I1Ii111 % oO0o + O0
 if ( eid . is_null ( ) ) : return ( None )
 if 15 - 15: o0oOOo0O0Ooo - OoooooooOO % ooOoO0o % oO0o / i11iIiiIii / Oo0Ooo
 if 59 - 59: iII111i + O0 - I1ii11iIi11i * I1ii11iIi11i + iIii1I11I1II1
 if 41 - 41: iIii1I11I1II1 . O0 - ooOoO0o / OoOoOO00 % iIii1I11I1II1 + IiII
 if 23 - 23: OoOoOO00 + ooOoO0o . i11iIiiIii
 if 39 - 39: OoOoOO00 - I1ii11iIi11i / I1Ii111
 if 48 - 48: IiII - oO0o + I11i % o0oOOo0O0Ooo
 IiIi1II1i = lisp_sites_by_eid . lookup_cache ( group , exact )
 if ( IiIi1II1i == None ) : return ( None )
 if 81 - 81: Oo0Ooo . I1Ii111 * iIii1I11I1II1
 if 60 - 60: OoooooooOO
 if 41 - 41: iIii1I11I1II1 + O0 % o0oOOo0O0Ooo - IiII . I11i * O0
 if 39 - 39: i11iIiiIii . Ii1I
 if 68 - 68: OOooOOo * ooOoO0o . I1IiiI - iII111i
 if 81 - 81: I11i % Oo0Ooo / iII111i
 if 44 - 44: Oo0Ooo
 if 90 - 90: Oo0Ooo . ooOoO0o / IiII * I1Ii111 . ooOoO0o + II111iiii
 if 43 - 43: iIii1I11I1II1 % OOooOOo + OoOoOO00 + I1ii11iIi11i - Oo0Ooo / Ii1I
 if 94 - 94: Ii1I / Oo0Ooo % II111iiii % Oo0Ooo * oO0o
 if 54 - 54: O0 / ooOoO0o * I1Ii111
 if 5 - 5: Ii1I / OoOoOO00 - O0 * OoO0O00
 if 13 - 13: IiII + Oo0Ooo - I1Ii111
 if 10 - 10: OOooOOo % OoooooooOO / I1IiiI . II111iiii % iII111i
 if 47 - 47: o0oOOo0O0Ooo . i11iIiiIii * i1IIi % I11i - ooOoO0o * oO0o
 if 95 - 95: oO0o / Ii1I + OoO0O00
 if 57 - 57: iIii1I11I1II1 + I1Ii111 % oO0o - Ii1I . I1IiiI
 if 39 - 39: OoO0O00 + II111iiii
 IIII = IiIi1II1i . lookup_source_cache ( eid , exact )
 if ( IIII ) : return ( IIII )
 if 98 - 98: O0 - I1Ii111 % oO0o - iII111i + Ii1I * i1IIi
 if ( exact ) :
  IiIi1II1i = None
 else :
  Ii1IIII = IiIi1II1i . parent_for_more_specifics
  if ( Ii1IIII and Ii1IIII . accept_more_specifics ) :
   if ( group . is_more_specific ( Ii1IIII . group ) ) : IiIi1II1i = Ii1IIII
   if 76 - 76: o0oOOo0O0Ooo
   if 55 - 55: OOooOOo + I1ii11iIi11i * Oo0Ooo
 return ( IiIi1II1i )
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
 if 1 - 1: iIii1I11I1II1
 if 73 - 73: iII111i + IiII
 if 95 - 95: O0
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
class lisp_address ( ) :
 def __init__ ( self , afi , addr_str , mask_len , iid ) :
  self . afi = afi
  self . mask_len = mask_len
  self . instance_id = iid
  self . iid_list = [ ]
  self . address = 0
  if ( addr_str != "" ) : self . store_address ( addr_str )
  if 17 - 17: i11iIiiIii + oO0o * iII111i . II111iiii
  if 44 - 44: I1ii11iIi11i
 def copy_address ( self , addr ) :
  if ( addr == None ) : return
  self . afi = addr . afi
  self . address = addr . address
  self . mask_len = addr . mask_len
  self . instance_id = addr . instance_id
  self . iid_list = addr . iid_list
  if 39 - 39: iII111i + Oo0Ooo / oO0o
  if 95 - 95: I1Ii111 * oO0o / ooOoO0o . Ii1I . OoOoOO00
 def make_default_route ( self , addr ) :
  self . afi = addr . afi
  self . instance_id = addr . instance_id
  self . mask_len = 0
  self . address = 0
  if 99 - 99: I1IiiI * II111iiii
  if 84 - 84: II111iiii - I1IiiI
 def make_default_multicast_route ( self , addr ) :
  self . afi = addr . afi
  self . instance_id = addr . instance_id
  if ( self . afi == LISP_AFI_IPV4 ) :
   self . address = 0xe0000000
   self . mask_len = 4
   if 41 - 41: iIii1I11I1II1 % I1Ii111 % OoOoOO00
  if ( self . afi == LISP_AFI_IPV6 ) :
   self . address = 0xff << 120
   self . mask_len = 8
   if 35 - 35: I11i + i1IIi
  if ( self . afi == LISP_AFI_MAC ) :
   self . address = 0xffffffffffff
   self . mask_len = 48
   if 85 - 85: Ii1I * Ii1I . OoOoOO00 / Oo0Ooo
   if 97 - 97: oO0o % iIii1I11I1II1
   if 87 - 87: II111iiii % I1IiiI + oO0o - I11i / I11i
 def not_set ( self ) :
  return ( self . afi == LISP_AFI_NONE )
  if 16 - 16: I1IiiI
  if 39 - 39: ooOoO0o * II111iiii
 def is_private_address ( self ) :
  if ( self . is_ipv4 ( ) == False ) : return ( False )
  I1Iii1I = self . address
  if ( ( ( I1Iii1I & 0xff000000 ) >> 24 ) == 10 ) : return ( True )
  if ( ( ( I1Iii1I & 0xff000000 ) >> 24 ) == 172 ) :
   oo0oo0ooOO000 = ( I1Iii1I & 0x00ff0000 ) >> 16
   if ( oo0oo0ooOO000 >= 16 and oo0oo0ooOO000 <= 31 ) : return ( True )
   if 53 - 53: iII111i % OOooOOo % I1Ii111 / i11iIiiIii . i1IIi % OOooOOo
  if ( ( ( I1Iii1I & 0xffff0000 ) >> 16 ) == 0xc0a8 ) : return ( True )
  return ( False )
  if 55 - 55: i1IIi
  if 64 - 64: oO0o . OOooOOo * i11iIiiIii + I1Ii111
 def is_multicast_address ( self ) :
  if ( self . is_ipv4 ( ) ) : return ( self . is_ipv4_multicast ( ) )
  if ( self . is_ipv6 ( ) ) : return ( self . is_ipv6_multicast ( ) )
  if ( self . is_mac ( ) ) : return ( self . is_mac_multicast ( ) )
  return ( False )
  if 88 - 88: O0
  if 75 - 75: iII111i - Oo0Ooo / OoooooooOO - O0
 def host_mask_len ( self ) :
  if ( self . afi == LISP_AFI_IPV4 ) : return ( LISP_IPV4_HOST_MASK_LEN )
  if ( self . afi == LISP_AFI_IPV6 ) : return ( LISP_IPV6_HOST_MASK_LEN )
  if ( self . afi == LISP_AFI_MAC ) : return ( LISP_MAC_HOST_MASK_LEN )
  if ( self . afi == LISP_AFI_E164 ) : return ( LISP_E164_HOST_MASK_LEN )
  if ( self . afi == LISP_AFI_NAME ) : return ( len ( self . address ) * 8 )
  if ( self . afi == LISP_AFI_GEO_COORD ) :
   return ( len ( self . address . print_geo ( ) ) * 8 )
   if 36 - 36: OoO0O00 % Ii1I . Oo0Ooo
  return ( 0 )
  if 90 - 90: i11iIiiIii - iII111i * oO0o
  if 79 - 79: IiII
 def is_iana_eid ( self ) :
  if ( self . is_ipv6 ( ) == False ) : return ( False )
  I1Iii1I = self . address >> 96
  return ( I1Iii1I == 0x20010005 )
  if 38 - 38: I1Ii111
  if 56 - 56: i11iIiiIii
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
   if 58 - 58: i11iIiiIii / OoOoOO00
  return ( 0 )
  if 23 - 23: I1IiiI % iIii1I11I1II1 - oO0o - iII111i - o0oOOo0O0Ooo
  if 39 - 39: Oo0Ooo . OoO0O00
 def afi_to_version ( self ) :
  if ( self . afi == LISP_AFI_IPV4 ) : return ( 4 )
  if ( self . afi == LISP_AFI_IPV6 ) : return ( 6 )
  return ( 0 )
  if 74 - 74: I1IiiI . O0 . IiII + IiII - IiII
  if 100 - 100: ooOoO0o / OoooooooOO
 def packet_format ( self ) :
  if 73 - 73: i11iIiiIii - Oo0Ooo
  if 100 - 100: iIii1I11I1II1 + I1Ii111
  if 51 - 51: o0oOOo0O0Ooo * I11i
  if 42 - 42: OOooOOo % I11i
  if 84 - 84: Oo0Ooo * OoOoOO00 / Ii1I / IiII / o0oOOo0O0Ooo . I1ii11iIi11i
  if ( self . afi == LISP_AFI_IPV4 ) : return ( "I" )
  if ( self . afi == LISP_AFI_IPV6 ) : return ( "QQ" )
  if ( self . afi == LISP_AFI_MAC ) : return ( "HHH" )
  if ( self . afi == LISP_AFI_E164 ) : return ( "II" )
  if ( self . afi == LISP_AFI_LCAF ) : return ( "I" )
  return ( "" )
  if 81 - 81: I1IiiI
  if 82 - 82: I1Ii111 - OoooooooOO - Ii1I
 def pack_address ( self ) :
  O0000 = self . packet_format ( )
  I1IiO00Ooo0ooo0 = ""
  if ( self . is_ipv4 ( ) ) :
   I1IiO00Ooo0ooo0 = struct . pack ( O0000 , socket . htonl ( self . address ) )
  elif ( self . is_ipv6 ( ) ) :
   o0OO0oooo = byte_swap_64 ( self . address >> 64 )
   I11II1i1 = byte_swap_64 ( self . address & 0xffffffffffffffff )
   I1IiO00Ooo0ooo0 = struct . pack ( O0000 , o0OO0oooo , I11II1i1 )
  elif ( self . is_mac ( ) ) :
   I1Iii1I = self . address
   o0OO0oooo = ( I1Iii1I >> 32 ) & 0xffff
   I11II1i1 = ( I1Iii1I >> 16 ) & 0xffff
   IIii = I1Iii1I & 0xffff
   I1IiO00Ooo0ooo0 = struct . pack ( O0000 , o0OO0oooo , I11II1i1 , IIii )
  elif ( self . is_e164 ( ) ) :
   I1Iii1I = self . address
   o0OO0oooo = ( I1Iii1I >> 32 ) & 0xffffffff
   I11II1i1 = ( I1Iii1I & 0xffffffff )
   I1IiO00Ooo0ooo0 = struct . pack ( O0000 , o0OO0oooo , I11II1i1 )
  elif ( self . is_dist_name ( ) ) :
   I1IiO00Ooo0ooo0 += self . address + "\0"
   if 60 - 60: iII111i . o0oOOo0O0Ooo + iII111i
  return ( I1IiO00Ooo0ooo0 )
  if 38 - 38: i11iIiiIii * I11i + Oo0Ooo - iIii1I11I1II1
  if 75 - 75: i1IIi * iII111i - I11i * i11iIiiIii
 def unpack_address ( self , packet ) :
  O0000 = self . packet_format ( )
  I1 = struct . calcsize ( O0000 )
  if ( len ( packet ) < I1 ) : return ( None )
  if 75 - 75: I1IiiI . OoooooooOO + OOooOOo + IiII
  I1Iii1I = struct . unpack ( O0000 , packet [ : I1 ] )
  if 37 - 37: iII111i + i1IIi % Oo0Ooo / o0oOOo0O0Ooo / iII111i
  if ( self . is_ipv4 ( ) ) :
   self . address = socket . ntohl ( I1Iii1I [ 0 ] )
   if 81 - 81: ooOoO0o
  elif ( self . is_ipv6 ( ) ) :
   if 74 - 74: OoO0O00
   if 13 - 13: I1ii11iIi11i / OoO0O00
   if 90 - 90: iIii1I11I1II1 - OoO0O00 . i1IIi / o0oOOo0O0Ooo + O0
   if 94 - 94: IiII * i1IIi
   if 90 - 90: O0 % I1IiiI . o0oOOo0O0Ooo % ooOoO0o % I1IiiI
   if 16 - 16: OoO0O00 / OOooOOo / iIii1I11I1II1 / OoooooooOO . oO0o - I1Ii111
   if 43 - 43: OoOoOO00 % OOooOOo / I1IiiI + I1IiiI
   if 40 - 40: OOooOOo . I1Ii111 + I1Ii111
   if ( I1Iii1I [ 0 ] <= 0xffff and ( I1Iii1I [ 0 ] & 0xff ) == 0 ) :
    ii1i1i1Ii = ( I1Iii1I [ 0 ] << 48 ) << 64
   else :
    ii1i1i1Ii = byte_swap_64 ( I1Iii1I [ 0 ] ) << 64
    if 87 - 87: iII111i + i1IIi
   III = byte_swap_64 ( I1Iii1I [ 1 ] )
   self . address = ii1i1i1Ii | III
   if 55 - 55: Oo0Ooo . iII111i
  elif ( self . is_mac ( ) ) :
   iIii1iiIii = I1Iii1I [ 0 ]
   I1I = I1Iii1I [ 1 ]
   I1iI1i1I11i1 = I1Iii1I [ 2 ]
   self . address = ( iIii1iiIii << 32 ) + ( I1I << 16 ) + I1iI1i1I11i1
   if 3 - 3: I1IiiI / IiII % OoOoOO00
  elif ( self . is_e164 ( ) ) :
   self . address = ( I1Iii1I [ 0 ] << 32 ) + I1Iii1I [ 1 ]
   if 49 - 49: IiII . iII111i * Ii1I % o0oOOo0O0Ooo * i1IIi . Ii1I
  elif ( self . is_dist_name ( ) ) :
   packet , self . address = lisp_decode_dist_name ( packet )
   self . mask_len = len ( self . address ) * 8
   I1 = 0
   if 89 - 89: IiII % I11i
  packet = packet [ I1 : : ]
  return ( packet )
  if 20 - 20: OoOoOO00 % o0oOOo0O0Ooo
  if 38 - 38: O0 + IiII % I11i . OoO0O00 + I1ii11iIi11i * OOooOOo
 def is_ipv4 ( self ) :
  return ( True if ( self . afi == LISP_AFI_IPV4 ) else False )
  if 2 - 2: OoO0O00 % OoO0O00 * Oo0Ooo - I11i * Ii1I . II111iiii
  if 28 - 28: I11i
 def is_ipv4_link_local ( self ) :
  if ( self . is_ipv4 ( ) == False ) : return ( False )
  return ( ( ( self . address >> 16 ) & 0xffff ) == 0xa9fe )
  if 7 - 7: Ii1I . I1ii11iIi11i / o0oOOo0O0Ooo - I1ii11iIi11i / Ii1I
  if 6 - 6: O0
 def is_ipv4_loopback ( self ) :
  if ( self . is_ipv4 ( ) == False ) : return ( False )
  return ( self . address == 0x7f000001 )
  if 67 - 67: I1Ii111
  if 49 - 49: IiII / i1IIi . OOooOOo
 def is_ipv4_multicast ( self ) :
  if ( self . is_ipv4 ( ) == False ) : return ( False )
  return ( ( ( self . address >> 24 ) & 0xf0 ) == 0xe0 )
  if 64 - 64: O0
  if 10 - 10: I1ii11iIi11i % ooOoO0o * IiII - iIii1I11I1II1
 def is_ipv4_string ( self , addr_str ) :
  return ( addr_str . find ( "." ) != - 1 )
  if 42 - 42: iII111i
  if 96 - 96: OoO0O00 + o0oOOo0O0Ooo . ooOoO0o
 def is_ipv6 ( self ) :
  return ( True if ( self . afi == LISP_AFI_IPV6 ) else False )
  if 44 - 44: I11i * iIii1I11I1II1 . I1ii11iIi11i
  if 9 - 9: o0oOOo0O0Ooo
 def is_ipv6_link_local ( self ) :
  if ( self . is_ipv6 ( ) == False ) : return ( False )
  return ( ( ( self . address >> 112 ) & 0xffff ) == 0xfe80 )
  if 23 - 23: ooOoO0o * OoO0O00 + O0 % I1Ii111
  if 21 - 21: Ii1I * OoOoOO00
 def is_ipv6_string_link_local ( self , addr_str ) :
  return ( addr_str . find ( "fe80::" ) != - 1 )
  if 29 - 29: iIii1I11I1II1 / ooOoO0o
  if 75 - 75: OoooooooOO + I1IiiI % OoOoOO00 / O0 - IiII
 def is_ipv6_loopback ( self ) :
  if ( self . is_ipv6 ( ) == False ) : return ( False )
  return ( self . address == 1 )
  if 88 - 88: OoO0O00 % Ii1I
  if 12 - 12: OoooooooOO . O0
 def is_ipv6_multicast ( self ) :
  if ( self . is_ipv6 ( ) == False ) : return ( False )
  return ( ( ( self . address >> 120 ) & 0xff ) == 0xff )
  if 33 - 33: OoooooooOO / I11i . II111iiii * i1IIi
  if 34 - 34: i11iIiiIii / OoOoOO00
 def is_ipv6_string ( self , addr_str ) :
  return ( addr_str . find ( ":" ) != - 1 )
  if 100 - 100: o0oOOo0O0Ooo - I1IiiI / I11i
  if 43 - 43: o0oOOo0O0Ooo % iIii1I11I1II1
 def is_mac ( self ) :
  return ( True if ( self . afi == LISP_AFI_MAC ) else False )
  if 85 - 85: oO0o + OoooooooOO - IiII % o0oOOo0O0Ooo * ooOoO0o * II111iiii
  if 4 - 4: Ii1I . i1IIi + Oo0Ooo % I11i . OoO0O00
 def is_mac_multicast ( self ) :
  if ( self . is_mac ( ) == False ) : return ( False )
  return ( ( self . address & 0x010000000000 ) != 0 )
  if 70 - 70: OOooOOo * OoOoOO00 / OoOoOO00 / OoOoOO00
  if 23 - 23: I1IiiI
 def is_mac_broadcast ( self ) :
  if ( self . is_mac ( ) == False ) : return ( False )
  return ( self . address == 0xffffffffffff )
  if 24 - 24: I1Ii111 * i1IIi % O0 * Ii1I + iII111i
  if 14 - 14: oO0o * iII111i + Ii1I + Ii1I * IiII
 def is_mac_string ( self , addr_str ) :
  return ( len ( addr_str ) == 15 and addr_str . find ( "-" ) != - 1 )
  if 82 - 82: IiII * ooOoO0o / OOooOOo + OoOoOO00
  if 32 - 32: IiII
 def is_link_local_multicast ( self ) :
  if ( self . is_ipv4 ( ) ) :
   return ( ( 0xe0ffff00 & self . address ) == 0xe0000000 )
   if 90 - 90: I1ii11iIi11i / I11i * o0oOOo0O0Ooo % O0 * i11iIiiIii
  if ( self . is_ipv6 ( ) ) :
   return ( ( self . address >> 112 ) & 0xffff == 0xff02 )
   if 68 - 68: I11i . Ii1I + I11i / IiII . I11i / iIii1I11I1II1
  return ( False )
  if 96 - 96: O0
  if 2 - 2: OoO0O00 / iII111i + o0oOOo0O0Ooo
 def is_null ( self ) :
  return ( True if ( self . afi == LISP_AFI_NONE ) else False )
  if 27 - 27: I11i - OoOoOO00 - ooOoO0o - I1IiiI
  if 51 - 51: I11i + I11i + O0 + O0 * I1Ii111
 def is_ultimate_root ( self ) :
  return ( True if self . afi == LISP_AFI_ULTIMATE_ROOT else False )
  if 61 - 61: IiII . O0
  if 38 - 38: Ii1I * I1ii11iIi11i - i11iIiiIii + ooOoO0o * I11i
 def is_iid_range ( self ) :
  return ( True if self . afi == LISP_AFI_IID_RANGE else False )
  if 74 - 74: OoOoOO00 . o0oOOo0O0Ooo
  if 40 - 40: ooOoO0o + I1ii11iIi11i * i11iIiiIii / i1IIi
 def is_e164 ( self ) :
  return ( True if ( self . afi == LISP_AFI_E164 ) else False )
  if 95 - 95: oO0o / IiII * II111iiii * Ii1I . OoO0O00 . OoO0O00
  if 85 - 85: I1IiiI / II111iiii * OoO0O00 + ooOoO0o / OoO0O00 % OOooOOo
 def is_dist_name ( self ) :
  return ( True if ( self . afi == LISP_AFI_NAME ) else False )
  if 100 - 100: I1Ii111 % OoooooooOO % OoOoOO00 % I1IiiI
  if 32 - 32: OoO0O00 + OOooOOo . OoO0O00 - Oo0Ooo
 def is_geo_prefix ( self ) :
  return ( True if ( self . afi == LISP_AFI_GEO_COORD ) else False )
  if 12 - 12: I1IiiI * OoO0O00 - II111iiii . i1IIi
  if 86 - 86: OOooOOo / OoooooooOO - IiII
 def is_binary ( self ) :
  if ( self . is_dist_name ( ) ) : return ( False )
  if ( self . is_geo_prefix ( ) ) : return ( False )
  return ( True )
  if 56 - 56: I1ii11iIi11i - i1IIi * OoooooooOO * O0 * I1IiiI - I1Ii111
  if 32 - 32: OoooooooOO . OOooOOo . OoO0O00 . IiII / I11i % i1IIi
 def store_address ( self , addr_str ) :
  if ( self . afi == LISP_AFI_NONE ) : self . string_to_afi ( addr_str )
  if 21 - 21: O0 . OoO0O00 * I1ii11iIi11i % iII111i + OoooooooOO
  if 8 - 8: oO0o * iII111i * I11i
  if 30 - 30: I1Ii111
  if 61 - 61: iII111i
  oO = addr_str . find ( "[" )
  OOOoOOo000oo = addr_str . find ( "]" )
  if ( oO != - 1 and OOOoOOo000oo != - 1 ) :
   self . instance_id = int ( addr_str [ oO + 1 : OOOoOOo000oo ] )
   addr_str = addr_str [ OOOoOOo000oo + 1 : : ]
   if ( self . is_dist_name ( ) == False ) :
    addr_str = addr_str . replace ( " " , "" )
    if 50 - 50: Ii1I / I1IiiI . O0
    if 49 - 49: I1Ii111 . OoO0O00 % O0
    if 15 - 15: I11i - Oo0Ooo / I1Ii111 . ooOoO0o % I1IiiI
    if 62 - 62: II111iiii + ooOoO0o + I1IiiI
    if 70 - 70: o0oOOo0O0Ooo + Ii1I . OoO0O00 * Ii1I + OOooOOo + ooOoO0o
    if 13 - 13: I1ii11iIi11i
  if ( self . is_ipv4 ( ) ) :
   OOoO0o00O = addr_str . split ( "." )
   oOOO = int ( OOoO0o00O [ 0 ] ) << 24
   oOOO += int ( OOoO0o00O [ 1 ] ) << 16
   oOOO += int ( OOoO0o00O [ 2 ] ) << 8
   oOOO += int ( OOoO0o00O [ 3 ] )
   self . address = oOOO
  elif ( self . is_ipv6 ( ) ) :
   if 1 - 1: IiII + Ii1I
   if 74 - 74: o0oOOo0O0Ooo / iII111i
   if 95 - 95: ooOoO0o
   if 22 - 22: Ii1I - Ii1I + IiII / I1IiiI
   if 57 - 57: Ii1I . o0oOOo0O0Ooo - iII111i % o0oOOo0O0Ooo - OOooOOo
   if 61 - 61: i1IIi / I1ii11iIi11i
   if 17 - 17: o0oOOo0O0Ooo * OOooOOo . Oo0Ooo + ooOoO0o
   if 80 - 80: II111iiii % OOooOOo + I1IiiI + i11iIiiIii
   if 15 - 15: i1IIi + iIii1I11I1II1 * OoooooooOO . Oo0Ooo * II111iiii
   if 14 - 14: i1IIi / I11i % i11iIiiIii
   if 29 - 29: I11i + i1IIi - I1ii11iIi11i / OoO0O00 - iII111i / II111iiii
   if 44 - 44: ooOoO0o
   if 16 - 16: OoOoOO00 - i11iIiiIii . o0oOOo0O0Ooo / o0oOOo0O0Ooo * Ii1I
   if 28 - 28: i1IIi - Oo0Ooo - i1IIi + IiII
   if 79 - 79: oO0o % o0oOOo0O0Ooo / o0oOOo0O0Ooo % iII111i
   if 56 - 56: Oo0Ooo % I1ii11iIi11i
   if 53 - 53: OoO0O00 . I11i - ooOoO0o
   I1ii1I = ( addr_str [ 2 : 4 ] == "::" )
   try :
    addr_str = socket . inet_pton ( socket . AF_INET6 , addr_str )
   except :
    addr_str = socket . inet_pton ( socket . AF_INET6 , "0::0" )
    if 84 - 84: o0oOOo0O0Ooo / I11i + iIii1I11I1II1 + oO0o
   addr_str = binascii . hexlify ( addr_str )
   if 3 - 3: I1Ii111 / OOooOOo + I1Ii111 * I1Ii111 / I11i % O0
   if ( I1ii1I ) :
    addr_str = addr_str [ 2 : 4 ] + addr_str [ 0 : 2 ] + addr_str [ 4 : : ]
    if 40 - 40: I11i
   self . address = int ( addr_str , 16 )
   if 41 - 41: O0 / OoO0O00 . ooOoO0o + iII111i
  elif ( self . is_geo_prefix ( ) ) :
   IiiiIi = lisp_geo ( None )
   IiiiIi . name = "geo-prefix-{}" . format ( IiiiIi )
   IiiiIi . parse_geo_string ( addr_str )
   self . address = IiiiIi
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
   if 54 - 54: I11i + OoOoOO00 % o0oOOo0O0Ooo
  self . mask_len = self . host_mask_len ( )
  if 7 - 7: I1ii11iIi11i + OoO0O00 / I1ii11iIi11i * I1ii11iIi11i
  if 22 - 22: II111iiii % OoooooooOO % II111iiii
 def store_prefix ( self , prefix_str ) :
  if ( self . is_geo_string ( prefix_str ) ) :
   OOOoO000 = prefix_str . find ( "]" )
   OoOO = len ( prefix_str [ OOOoO000 + 1 : : ] ) * 8
  elif ( prefix_str . find ( "/" ) != - 1 ) :
   prefix_str , OoOO = prefix_str . split ( "/" )
  else :
   II11 = prefix_str . find ( "'" )
   if ( II11 == - 1 ) : return
   oOoOOOo = prefix_str . find ( "'" , II11 + 1 )
   if ( oOoOOOo == - 1 ) : return
   OoOO = len ( prefix_str [ II11 + 1 : oOoOOOo ] ) * 8
   if 39 - 39: i1IIi
   if 16 - 16: OoOoOO00 % iIii1I11I1II1 + Ii1I - o0oOOo0O0Ooo . Oo0Ooo + i1IIi
  self . string_to_afi ( prefix_str )
  self . store_address ( prefix_str )
  self . mask_len = int ( OoOO )
  if 59 - 59: i1IIi
  if 37 - 37: OoO0O00 / I1ii11iIi11i / OoOoOO00
 def zero_host_bits ( self ) :
  iiii111I1I = ( 2 ** self . mask_len ) - 1
  OOO00o0o0 = self . addr_length ( ) * 8 - self . mask_len
  iiii111I1I <<= OOO00o0o0
  self . address &= iiii111I1I
  if 99 - 99: O0 * i11iIiiIii / OoOoOO00 - I11i / OoOoOO00
  if 28 - 28: I1IiiI * iII111i * Oo0Ooo - OoOoOO00 % I1ii11iIi11i % oO0o
 def is_geo_string ( self , addr_str ) :
  OOOoO000 = addr_str . find ( "]" )
  if ( OOOoO000 != - 1 ) : addr_str = addr_str [ OOOoO000 + 1 : : ]
  if 46 - 46: iIii1I11I1II1
  IiiiIi = addr_str . split ( "/" )
  if ( len ( IiiiIi ) == 2 ) :
   if ( IiiiIi [ 1 ] . isdigit ( ) == False ) : return ( False )
   if 43 - 43: OOooOOo + I1IiiI % I1Ii111 / OoOoOO00 . Ii1I . I11i
  IiiiIi = IiiiIi [ 0 ]
  IiiiIi = IiiiIi . split ( "-" )
  o00O0OO = len ( IiiiIi )
  if ( o00O0OO < 8 or o00O0OO > 9 ) : return ( False )
  if 86 - 86: iIii1I11I1II1 * IiII + I1ii11iIi11i + I1Ii111 . o0oOOo0O0Ooo
  for ooOooO0OoOO00 in range ( 0 , o00O0OO ) :
   if ( ooOooO0OoOO00 == 3 ) :
    if ( IiiiIi [ ooOooO0OoOO00 ] in [ "N" , "S" ] ) : continue
    return ( False )
    if 22 - 22: IiII - II111iiii * OoO0O00 + OoooooooOO
   if ( ooOooO0OoOO00 == 7 ) :
    if ( IiiiIi [ ooOooO0OoOO00 ] in [ "W" , "E" ] ) : continue
    return ( False )
    if 19 - 19: I11i
   if ( IiiiIi [ ooOooO0OoOO00 ] . isdigit ( ) == False ) : return ( False )
   if 54 - 54: O0 / Ii1I - OOooOOo - I1Ii111
  return ( True )
  if 41 - 41: O0 / I1IiiI - I1ii11iIi11i - i11iIiiIii
  if 2 - 2: OoO0O00 % O0 + iII111i * I1Ii111 / OOooOOo
 def string_to_afi ( self , addr_str ) :
  if ( addr_str . count ( "'" ) == 2 ) :
   self . afi = LISP_AFI_NAME
   return
   if 7 - 7: IiII
  if ( addr_str . find ( ":" ) != - 1 ) : self . afi = LISP_AFI_IPV6
  elif ( addr_str . find ( "." ) != - 1 ) : self . afi = LISP_AFI_IPV4
  elif ( addr_str . find ( "+" ) != - 1 ) : self . afi = LISP_AFI_E164
  elif ( self . is_geo_string ( addr_str ) ) : self . afi = LISP_AFI_GEO_COORD
  elif ( addr_str . find ( "-" ) != - 1 ) : self . afi = LISP_AFI_MAC
  else : self . afi = LISP_AFI_NONE
  if 30 - 30: iIii1I11I1II1 - OoooooooOO + Oo0Ooo . i1IIi % o0oOOo0O0Ooo
  if 7 - 7: IiII - iII111i
 def print_address ( self ) :
  I1Iii1I = self . print_address_no_iid ( )
  IIiI1i = "[" + str ( self . instance_id )
  for oO in self . iid_list : IIiI1i += "," + str ( oO )
  IIiI1i += "]"
  I1Iii1I = "{}{}" . format ( IIiI1i , I1Iii1I )
  return ( I1Iii1I )
  if 59 - 59: Oo0Ooo * ooOoO0o - Ii1I / II111iiii / Oo0Ooo
  if 8 - 8: IiII / OoooooooOO - iIii1I11I1II1
 def print_address_no_iid ( self ) :
  if ( self . is_ipv4 ( ) ) :
   I1Iii1I = self . address
   I1OOo0o0oo = I1Iii1I >> 24
   OO0OOoO0o0oOO = ( I1Iii1I >> 16 ) & 0xff
   ii1OoOoO0 = ( I1Iii1I >> 8 ) & 0xff
   I11 = I1Iii1I & 0xff
   return ( "{}.{}.{}.{}" . format ( I1OOo0o0oo , OO0OOoO0o0oOO , ii1OoOoO0 , I11 ) )
  elif ( self . is_ipv6 ( ) ) :
   OoOOoooO000 = lisp_hex_string ( self . address ) . zfill ( 32 )
   OoOOoooO000 = binascii . unhexlify ( OoOOoooO000 )
   OoOOoooO000 = socket . inet_ntop ( socket . AF_INET6 , OoOOoooO000 )
   return ( "{}" . format ( OoOOoooO000 ) )
  elif ( self . is_geo_prefix ( ) ) :
   return ( "{}" . format ( self . address . print_geo ( ) ) )
  elif ( self . is_mac ( ) ) :
   OoOOoooO000 = lisp_hex_string ( self . address ) . zfill ( 12 )
   OoOOoooO000 = "{}-{}-{}" . format ( OoOOoooO000 [ 0 : 4 ] , OoOOoooO000 [ 4 : 8 ] ,
 OoOOoooO000 [ 8 : 12 ] )
   return ( "{}" . format ( OoOOoooO000 ) )
  elif ( self . is_e164 ( ) ) :
   OoOOoooO000 = lisp_hex_string ( self . address ) . zfill ( 15 )
   return ( "+{}" . format ( OoOOoooO000 ) )
  elif ( self . is_dist_name ( ) ) :
   return ( "'{}'" . format ( self . address ) )
  elif ( self . is_null ( ) ) :
   return ( "no-address" )
   if 78 - 78: OoO0O00 + oO0o
  return ( "unknown-afi:{}" . format ( self . afi ) )
  if 86 - 86: ooOoO0o . ooOoO0o + oO0o
  if 84 - 84: OOooOOo - OoOoOO00 + i1IIi * I1ii11iIi11i % I1ii11iIi11i * I1Ii111
 def print_prefix ( self ) :
  if ( self . is_ultimate_root ( ) ) : return ( "[*]" )
  if ( self . is_iid_range ( ) ) :
   if ( self . mask_len == 32 ) : return ( "[{}]" . format ( self . instance_id ) )
   i11ii1i = self . instance_id + ( 2 ** ( 32 - self . mask_len ) - 1 )
   return ( "[{}-{}]" . format ( self . instance_id , i11ii1i ) )
   if 80 - 80: I1Ii111 % i11iIiiIii % iIii1I11I1II1 . Ii1I + OoOoOO00
  I1Iii1I = self . print_address ( )
  if ( self . is_dist_name ( ) ) : return ( I1Iii1I )
  if ( self . is_geo_prefix ( ) ) : return ( I1Iii1I )
  if 91 - 91: II111iiii / OoooooooOO - iII111i . iIii1I11I1II1 - oO0o
  OOOoO000 = I1Iii1I . find ( "no-address" )
  if ( OOOoO000 == - 1 ) :
   I1Iii1I = "{}/{}" . format ( I1Iii1I , str ( self . mask_len ) )
  else :
   I1Iii1I = I1Iii1I [ 0 : OOOoO000 ]
   if 77 - 77: OoOoOO00
  return ( I1Iii1I )
  if 20 - 20: Ii1I - Ii1I * I1Ii111 . o0oOOo0O0Ooo
  if 10 - 10: i1IIi * o0oOOo0O0Ooo
 def print_prefix_no_iid ( self ) :
  I1Iii1I = self . print_address_no_iid ( )
  if ( self . is_dist_name ( ) ) : return ( I1Iii1I )
  if ( self . is_geo_prefix ( ) ) : return ( I1Iii1I )
  return ( "{}/{}" . format ( I1Iii1I , str ( self . mask_len ) ) )
  if 77 - 77: I1IiiI
  if 22 - 22: o0oOOo0O0Ooo * II111iiii
 def print_prefix_url ( self ) :
  if ( self . is_ultimate_root ( ) ) : return ( "0--0" )
  I1Iii1I = self . print_address ( )
  OOOoO000 = I1Iii1I . find ( "]" )
  if ( OOOoO000 != - 1 ) : I1Iii1I = I1Iii1I [ OOOoO000 + 1 : : ]
  if ( self . is_geo_prefix ( ) ) :
   I1Iii1I = I1Iii1I . replace ( "/" , "-" )
   return ( "{}-{}" . format ( self . instance_id , I1Iii1I ) )
   if 16 - 16: ooOoO0o / Oo0Ooo * Ii1I
  return ( "{}-{}-{}" . format ( self . instance_id , I1Iii1I , self . mask_len ) )
  if 4 - 4: I1ii11iIi11i + I11i . I1ii11iIi11i * I1IiiI
  if 89 - 89: I1IiiI - IiII % O0 . i1IIi / o0oOOo0O0Ooo
 def print_sg ( self , g ) :
  i1I1iIi1IiI = self . print_prefix ( )
  OOOoOOO0ooOO0O0O = i1I1iIi1IiI . find ( "]" ) + 1
  g = g . print_prefix ( )
  oOoOOi1 = g . find ( "]" ) + 1
  I1I1I11Ii = "[{}]({}, {})" . format ( self . instance_id , i1I1iIi1IiI [ OOOoOOO0ooOO0O0O : : ] , g [ oOoOOi1 : : ] )
  return ( I1I1I11Ii )
  if 41 - 41: I1Ii111 * o0oOOo0O0Ooo + Oo0Ooo
  if 86 - 86: Ii1I / oO0o
 def hash_address ( self , addr ) :
  o0OO0oooo = self . address
  I11II1i1 = addr . address
  if 40 - 40: OoO0O00 % oO0o + Oo0Ooo
  if ( self . is_geo_prefix ( ) ) : o0OO0oooo = self . address . print_geo ( )
  if ( addr . is_geo_prefix ( ) ) : I11II1i1 = addr . address . print_geo ( )
  if 60 - 60: II111iiii / Ii1I
  if ( type ( o0OO0oooo ) == str ) :
   o0OO0oooo = int ( binascii . hexlify ( o0OO0oooo [ 0 : 1 ] ) )
   if 14 - 14: iII111i - Oo0Ooo / o0oOOo0O0Ooo * oO0o / Oo0Ooo - I1IiiI
  if ( type ( I11II1i1 ) == str ) :
   I11II1i1 = int ( binascii . hexlify ( I11II1i1 [ 0 : 1 ] ) )
   if 89 - 89: i1IIi / I1Ii111 + Ii1I - i1IIi
  return ( o0OO0oooo ^ I11II1i1 )
  if 66 - 66: OoooooooOO
  if 68 - 68: iII111i + I1Ii111
  if 90 - 90: o0oOOo0O0Ooo
  if 48 - 48: iII111i + Ii1I
  if 45 - 45: oO0o / iIii1I11I1II1 % O0 % IiII % I1ii11iIi11i
  if 89 - 89: OOooOOo - I1Ii111 - iII111i
 def is_more_specific ( self , prefix ) :
  if ( prefix . afi == LISP_AFI_ULTIMATE_ROOT ) : return ( True )
  if 67 - 67: oO0o
  OoOO = prefix . mask_len
  if ( prefix . afi == LISP_AFI_IID_RANGE ) :
   OoOoo0oOOO = 2 ** ( 32 - OoOO )
   oOO0OO = prefix . instance_id
   i11ii1i = oOO0OO + OoOoo0oOOO
   return ( self . instance_id in range ( oOO0OO , i11ii1i ) )
   if 25 - 25: iIii1I11I1II1 . o0oOOo0O0Ooo
   if 60 - 60: I1ii11iIi11i / I1Ii111
  if ( self . instance_id != prefix . instance_id ) : return ( False )
  if ( self . afi != prefix . afi ) :
   if ( prefix . afi != LISP_AFI_NONE ) : return ( False )
   if 13 - 13: I1Ii111
   if 52 - 52: II111iiii / OoO0O00 . Ii1I
   if 68 - 68: iII111i
   if 67 - 67: I1IiiI * I1IiiI
   if 100 - 100: iII111i * iII111i . Oo0Ooo
  if ( self . is_binary ( ) == False ) :
   if ( prefix . afi == LISP_AFI_NONE ) : return ( True )
   if ( type ( self . address ) != type ( prefix . address ) ) : return ( False )
   I1Iii1I = self . address
   iI11IIiI1i = prefix . address
   if ( self . is_geo_prefix ( ) ) :
    I1Iii1I = self . address . print_geo ( )
    iI11IIiI1i = prefix . address . print_geo ( )
    if 73 - 73: II111iiii
   if ( len ( I1Iii1I ) < len ( iI11IIiI1i ) ) : return ( False )
   return ( I1Iii1I . find ( iI11IIiI1i ) == 0 )
   if 63 - 63: i11iIiiIii . Oo0Ooo . OOooOOo - II111iiii
   if 35 - 35: II111iiii + IiII
   if 66 - 66: o0oOOo0O0Ooo % IiII
   if 39 - 39: IiII
   if 18 - 18: iII111i % o0oOOo0O0Ooo - i1IIi
  if ( self . mask_len < OoOO ) : return ( False )
  if 53 - 53: o0oOOo0O0Ooo + IiII - ooOoO0o % i11iIiiIii - i11iIiiIii - I1Ii111
  OOO00o0o0 = ( prefix . addr_length ( ) * 8 ) - OoOO
  iiii111I1I = ( 2 ** OoOO - 1 ) << OOO00o0o0
  return ( ( self . address & iiii111I1I ) == prefix . address )
  if 79 - 79: II111iiii + i11iIiiIii . OOooOOo . I11i / iIii1I11I1II1
  if 62 - 62: O0
 def mask_address ( self , mask_len ) :
  OOO00o0o0 = ( self . addr_length ( ) * 8 ) - mask_len
  iiii111I1I = ( 2 ** mask_len - 1 ) << OOO00o0o0
  self . address &= iiii111I1I
  if 52 - 52: OoooooooOO . oO0o
  if 38 - 38: ooOoO0o . i1IIi / iII111i + I1IiiI - II111iiii
 def is_exact_match ( self , prefix ) :
  if ( self . instance_id != prefix . instance_id ) : return ( False )
  IiIiii = self . print_prefix ( )
  oOOOo0000O0 = prefix . print_prefix ( ) if prefix else ""
  return ( IiIiii == oOOOo0000O0 )
  if 77 - 77: OOooOOo . oO0o + iIii1I11I1II1 + Oo0Ooo . i11iIiiIii . I1ii11iIi11i
  if 71 - 71: II111iiii
 def is_local ( self ) :
  if ( self . is_ipv4 ( ) ) :
   i1i1i = lisp_myrlocs [ 0 ]
   if ( i1i1i == None ) : return ( False )
   i1i1i = i1i1i . print_address_no_iid ( )
   return ( self . print_address_no_iid ( ) == i1i1i )
   if 80 - 80: I11i * OoO0O00 + ooOoO0o % ooOoO0o
  if ( self . is_ipv6 ( ) ) :
   i1i1i = lisp_myrlocs [ 1 ]
   if ( i1i1i == None ) : return ( False )
   i1i1i = i1i1i . print_address_no_iid ( )
   return ( self . print_address_no_iid ( ) == i1i1i )
   if 16 - 16: iII111i / i11iIiiIii + iIii1I11I1II1
  return ( False )
  if 76 - 76: OoooooooOO / Oo0Ooo / I1Ii111 + OoooooooOO
  if 65 - 65: Oo0Ooo - I1Ii111
 def store_iid_range ( self , iid , mask_len ) :
  if ( self . afi == LISP_AFI_NONE ) :
   if ( iid is 0 and mask_len is 0 ) : self . afi = LISP_AFI_ULTIMATE_ROOT
   else : self . afi = LISP_AFI_IID_RANGE
   if 57 - 57: O0
  self . instance_id = iid
  self . mask_len = mask_len
  if 49 - 49: I1ii11iIi11i / OoOoOO00 - I1IiiI + iII111i . OOooOOo % oO0o
  if 34 - 34: OoO0O00 - I1IiiI + OoOoOO00
 def lcaf_length ( self , lcaf_type ) :
  I111 = self . addr_length ( ) + 2
  if ( lcaf_type == LISP_LCAF_AFI_LIST_TYPE ) : I111 += 4
  if ( lcaf_type == LISP_LCAF_INSTANCE_ID_TYPE ) : I111 += 4
  if ( lcaf_type == LISP_LCAF_ASN_TYPE ) : I111 += 4
  if ( lcaf_type == LISP_LCAF_APP_DATA_TYPE ) : I111 += 8
  if ( lcaf_type == LISP_LCAF_GEO_COORD_TYPE ) : I111 += 12
  if ( lcaf_type == LISP_LCAF_OPAQUE_TYPE ) : I111 += 0
  if ( lcaf_type == LISP_LCAF_NAT_TYPE ) : I111 += 4
  if ( lcaf_type == LISP_LCAF_NONCE_LOC_TYPE ) : I111 += 4
  if ( lcaf_type == LISP_LCAF_MCAST_INFO_TYPE ) : I111 = I111 * 2 + 8
  if ( lcaf_type == LISP_LCAF_ELP_TYPE ) : I111 += 0
  if ( lcaf_type == LISP_LCAF_SECURITY_TYPE ) : I111 += 6
  if ( lcaf_type == LISP_LCAF_SOURCE_DEST_TYPE ) : I111 += 4
  if ( lcaf_type == LISP_LCAF_RLE_TYPE ) : I111 += 4
  return ( I111 )
  if 22 - 22: iIii1I11I1II1 . i1IIi . OOooOOo % Oo0Ooo - i1IIi
  if 78 - 78: I1IiiI / i1IIi % II111iiii % I1IiiI % Ii1I
  if 29 - 29: i1IIi % o0oOOo0O0Ooo + OOooOOo / Oo0Ooo
  if 38 - 38: IiII . I1Ii111
  if 69 - 69: ooOoO0o + OoOoOO00 + II111iiii % I1Ii111 + Ii1I . ooOoO0o
  if 73 - 73: I11i % I11i . ooOoO0o + OoOoOO00
  if 33 - 33: i11iIiiIii . i11iIiiIii * i11iIiiIii / iIii1I11I1II1 / I1ii11iIi11i . ooOoO0o
  if 11 - 11: iII111i
  if 60 - 60: I1ii11iIi11i / I1Ii111
  if 10 - 10: OoO0O00 * iIii1I11I1II1 / I11i % II111iiii . OoOoOO00 / I1IiiI
  if 4 - 4: Oo0Ooo * o0oOOo0O0Ooo
  if 45 - 45: Ii1I % OOooOOo * Ii1I - iIii1I11I1II1
  if 18 - 18: I1Ii111 / Oo0Ooo % Ii1I + OoO0O00
  if 69 - 69: iII111i % I1ii11iIi11i
  if 19 - 19: IiII
  if 35 - 35: OoOoOO00
  if 18 - 18: II111iiii . OoOoOO00 + I1ii11iIi11i * oO0o + OoooooooOO
 def lcaf_encode_iid ( self ) :
  OO = LISP_LCAF_INSTANCE_ID_TYPE
  I11iIi1i1I1i1 = socket . htons ( self . lcaf_length ( OO ) )
  IIiI1i = self . instance_id
  o0O0O0O00o = self . afi
  IiiIiiii = 0
  if ( o0O0O0O00o < 0 ) :
   if ( self . afi == LISP_AFI_GEO_COORD ) :
    o0O0O0O00o = LISP_AFI_LCAF
    IiiIiiii = 0
   else :
    o0O0O0O00o = 0
    IiiIiiii = self . mask_len
    if 39 - 39: I1IiiI * ooOoO0o / i11iIiiIii - oO0o - oO0o + O0
    if 73 - 73: OOooOOo
    if 44 - 44: I1ii11iIi11i * i1IIi - iIii1I11I1II1 - oO0o - oO0o * II111iiii
  OOo0o0o = struct . pack ( "BBBBH" , 0 , 0 , OO , IiiIiiii , I11iIi1i1I1i1 )
  OOo0o0o += struct . pack ( "IH" , socket . htonl ( IIiI1i ) , socket . htons ( o0O0O0O00o ) )
  if ( o0O0O0O00o == 0 ) : return ( OOo0o0o )
  if 15 - 15: I1IiiI
  if ( self . afi == LISP_AFI_GEO_COORD ) :
   OOo0o0o = OOo0o0o [ 0 : - 2 ]
   OOo0o0o += self . address . encode_geo ( )
   return ( OOo0o0o )
   if 50 - 50: Oo0Ooo - I1Ii111 / I1IiiI + IiII / o0oOOo0O0Ooo . iII111i
   if 61 - 61: OoO0O00 + o0oOOo0O0Ooo * iII111i
  OOo0o0o += self . pack_address ( )
  return ( OOo0o0o )
  if 84 - 84: Oo0Ooo . I1Ii111
  if 6 - 6: IiII + I1IiiI % iII111i - oO0o / OoO0O00
 def lcaf_decode_iid ( self , packet ) :
  O0000 = "BBBBH"
  I1 = struct . calcsize ( O0000 )
  if ( len ( packet ) < I1 ) : return ( None )
  if 37 - 37: O0 % OoO0O00 + i11iIiiIii . O0 / OOooOOo
  i1i11Ii1 , o0OoO0 , OO , iII11I , I111 = struct . unpack ( O0000 ,
 packet [ : I1 ] )
  packet = packet [ I1 : : ]
  if 61 - 61: IiII * II111iiii / O0 . I1ii11iIi11i
  if ( OO != LISP_LCAF_INSTANCE_ID_TYPE ) : return ( None )
  if 77 - 77: I1IiiI . IiII
  O0000 = "IH"
  I1 = struct . calcsize ( O0000 )
  if ( len ( packet ) < I1 ) : return ( None )
  if 94 - 94: oO0o + Ii1I % IiII
  IIiI1i , o0O0O0O00o = struct . unpack ( O0000 , packet [ : I1 ] )
  packet = packet [ I1 : : ]
  if 11 - 11: II111iiii
  I111 = socket . ntohs ( I111 )
  self . instance_id = socket . ntohl ( IIiI1i )
  o0O0O0O00o = socket . ntohs ( o0O0O0O00o )
  self . afi = o0O0O0O00o
  if ( iII11I != 0 and o0O0O0O00o == 0 ) : self . mask_len = iII11I
  if ( o0O0O0O00o == 0 ) :
   self . afi = LISP_AFI_IID_RANGE if iII11I else LISP_AFI_ULTIMATE_ROOT
   if 66 - 66: I11i % iIii1I11I1II1 - ooOoO0o . II111iiii % O0 + I1IiiI
   if 67 - 67: OoOoOO00 % OoooooooOO / OoO0O00 - OoO0O00 / O0
   if 19 - 19: iIii1I11I1II1 / OOooOOo % I11i % I1IiiI / I1ii11iIi11i
   if 73 - 73: II111iiii
   if 26 - 26: II111iiii . iIii1I11I1II1 - I1Ii111 % OOooOOo
  if ( o0O0O0O00o == 0 ) : return ( packet )
  if 83 - 83: OOooOOo + OoooooooOO % I1Ii111 % IiII + i11iIiiIii
  if 10 - 10: OoooooooOO . Ii1I % I1Ii111 + IiII
  if 78 - 78: OoOoOO00 - oO0o . I1ii11iIi11i * i11iIiiIii
  if 44 - 44: iIii1I11I1II1 * iII111i
  if ( self . is_dist_name ( ) ) :
   packet , self . address = lisp_decode_dist_name ( packet )
   self . mask_len = len ( self . address ) * 8
   return ( packet )
   if 32 - 32: OoOoOO00
   if 65 - 65: iIii1I11I1II1 + iII111i
   if 90 - 90: i11iIiiIii - Oo0Ooo
   if 31 - 31: OoOoOO00 + OoOoOO00 + OoooooooOO % O0
   if 14 - 14: i1IIi / OoooooooOO . I1IiiI * I1Ii111 + OoO0O00
  if ( o0O0O0O00o == LISP_AFI_LCAF ) :
   O0000 = "BBBBH"
   I1 = struct . calcsize ( O0000 )
   if ( len ( packet ) < I1 ) : return ( None )
   if 45 - 45: OoooooooOO * I1Ii111
   OOoooOOO0 , O0O0oooo , OO , O0o , IiiiI1I1i = struct . unpack ( O0000 , packet [ : I1 ] )
   if 7 - 7: O0
   if 42 - 42: o0oOOo0O0Ooo / Ii1I
   if ( OO != LISP_LCAF_GEO_COORD_TYPE ) : return ( None )
   if 31 - 31: OOooOOo
   IiiiI1I1i = socket . ntohs ( IiiiI1I1i )
   packet = packet [ I1 : : ]
   if ( IiiiI1I1i > len ( packet ) ) : return ( None )
   if 20 - 20: i11iIiiIii * oO0o * ooOoO0o
   IiiiIi = lisp_geo ( "" )
   self . afi = LISP_AFI_GEO_COORD
   self . address = IiiiIi
   packet = IiiiIi . decode_geo ( packet , IiiiI1I1i , O0o )
   self . mask_len = self . host_mask_len ( )
   return ( packet )
   if 65 - 65: I1ii11iIi11i / Oo0Ooo / I1IiiI + IiII
   if 71 - 71: OoO0O00 . I1Ii111 + OoooooooOO
  I11iIi1i1I1i1 = self . addr_length ( )
  if ( len ( packet ) < I11iIi1i1I1i1 ) : return ( None )
  if 9 - 9: OoooooooOO / iIii1I11I1II1 % I1IiiI . I1IiiI / I11i - iII111i
  packet = self . unpack_address ( packet )
  return ( packet )
  if 60 - 60: I11i - OoO0O00 - OoOoOO00 * ooOoO0o - i1IIi
  if 18 - 18: ooOoO0o + i11iIiiIii + O0 + OOooOOo / Ii1I
  if 65 - 65: I1IiiI . ooOoO0o
  if 51 - 51: I1Ii111
  if 89 - 89: Oo0Ooo
  if 15 - 15: OOooOOo * II111iiii - OOooOOo * iIii1I11I1II1
  if 95 - 95: I1Ii111 / OoooooooOO * I11i * OoooooooOO
  if 88 - 88: I1IiiI / Oo0Ooo / oO0o + oO0o % OOooOOo + Oo0Ooo
  if 63 - 63: o0oOOo0O0Ooo + i11iIiiIii % OOooOOo % iIii1I11I1II1 / I1ii11iIi11i - iII111i
  if 72 - 72: iII111i % oO0o . IiII + I1ii11iIi11i . IiII . II111iiii
  if 10 - 10: I11i . ooOoO0o + I11i * Ii1I
  if 55 - 55: OOooOOo / iII111i + OoooooooOO - OoooooooOO
  if 51 - 51: O0 % Ii1I % Oo0Ooo - O0
  if 94 - 94: OoooooooOO - ooOoO0o % I1ii11iIi11i + I1Ii111
  if 51 - 51: I1ii11iIi11i . iII111i / i1IIi * ooOoO0o % I11i
  if 82 - 82: O0 % OoOoOO00 . iII111i . i1IIi . iII111i - Oo0Ooo
  if 58 - 58: O0 * OOooOOo
  if 60 - 60: ooOoO0o
  if 47 - 47: i11iIiiIii
  if 21 - 21: i1IIi - oO0o - Oo0Ooo
  if 11 - 11: i1IIi
 def lcaf_encode_sg ( self , group ) :
  OO = LISP_LCAF_MCAST_INFO_TYPE
  IIiI1i = socket . htonl ( self . instance_id )
  I11iIi1i1I1i1 = socket . htons ( self . lcaf_length ( OO ) )
  OOo0o0o = struct . pack ( "BBBBHIHBB" , 0 , 0 , OO , 0 , I11iIi1i1I1i1 , IIiI1i ,
 0 , self . mask_len , group . mask_len )
  if 77 - 77: I11i + i1IIi * OoOoOO00 % OoooooooOO
  OOo0o0o += struct . pack ( "H" , socket . htons ( self . afi ) )
  OOo0o0o += self . pack_address ( )
  OOo0o0o += struct . pack ( "H" , socket . htons ( group . afi ) )
  OOo0o0o += group . pack_address ( )
  return ( OOo0o0o )
  if 56 - 56: I1Ii111 * i1IIi % i11iIiiIii
  if 56 - 56: Ii1I . iII111i
 def lcaf_decode_sg ( self , packet ) :
  O0000 = "BBBBHIHBB"
  I1 = struct . calcsize ( O0000 )
  if ( len ( packet ) < I1 ) : return ( [ None , None ] )
  if 76 - 76: I1IiiI / Ii1I % OoOoOO00 + IiII / i11iIiiIii . o0oOOo0O0Ooo
  i1i11Ii1 , o0OoO0 , OO , Iii1IiIiIii , I111 , IIiI1i , II1IiIIi1Iii , iiiii1i11IIii , O0o0ooo0O0OO0 = struct . unpack ( O0000 , packet [ : I1 ] )
  if 97 - 97: o0oOOo0O0Ooo
  packet = packet [ I1 : : ]
  if 98 - 98: iIii1I11I1II1 % O0 % i1IIi + OOooOOo
  if ( OO != LISP_LCAF_MCAST_INFO_TYPE ) : return ( [ None , None ] )
  if 41 - 41: o0oOOo0O0Ooo % o0oOOo0O0Ooo
  self . instance_id = socket . ntohl ( IIiI1i )
  I111 = socket . ntohs ( I111 ) - 8
  if 34 - 34: OOooOOo * iIii1I11I1II1 + OoooooooOO - I1Ii111 . I11i / II111iiii
  if 4 - 4: OoooooooOO * I1IiiI * II111iiii
  if 72 - 72: I1Ii111
  if 80 - 80: iII111i + i1IIi
  if 50 - 50: Ii1I
  O0000 = "H"
  I1 = struct . calcsize ( O0000 )
  if ( len ( packet ) < I1 ) : return ( [ None , None ] )
  if ( I111 < I1 ) : return ( [ None , None ] )
  if 42 - 42: OoO0O00 / II111iiii % iII111i + I1Ii111 / O0
  o0O0O0O00o = struct . unpack ( O0000 , packet [ : I1 ] ) [ 0 ]
  packet = packet [ I1 : : ]
  I111 -= I1
  self . afi = socket . ntohs ( o0O0O0O00o )
  self . mask_len = iiiii1i11IIii
  I11iIi1i1I1i1 = self . addr_length ( )
  if ( I111 < I11iIi1i1I1i1 ) : return ( [ None , None ] )
  if 91 - 91: iII111i * I1Ii111 - IiII - IiII * OOooOOo
  packet = self . unpack_address ( packet )
  if ( packet == None ) : return ( [ None , None ] )
  if 84 - 84: I1Ii111 - O0 % i11iIiiIii / OoooooooOO
  I111 -= I11iIi1i1I1i1
  if 75 - 75: Ii1I + ooOoO0o
  if 51 - 51: Ii1I . o0oOOo0O0Ooo * OOooOOo * I1IiiI
  if 23 - 23: OoOoOO00
  if 39 - 39: OoOoOO00
  if 40 - 40: IiII + II111iiii - Ii1I + Ii1I
  O0000 = "H"
  I1 = struct . calcsize ( O0000 )
  if ( len ( packet ) < I1 ) : return ( [ None , None ] )
  if ( I111 < I1 ) : return ( [ None , None ] )
  if 96 - 96: OoooooooOO * i1IIi * IiII + I11i
  o0O0O0O00o = struct . unpack ( O0000 , packet [ : I1 ] ) [ 0 ]
  packet = packet [ I1 : : ]
  I111 -= I1
  ooOoO00 = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  ooOoO00 . afi = socket . ntohs ( o0O0O0O00o )
  ooOoO00 . mask_len = O0o0ooo0O0OO0
  ooOoO00 . instance_id = self . instance_id
  I11iIi1i1I1i1 = self . addr_length ( )
  if ( I111 < I11iIi1i1I1i1 ) : return ( [ None , None ] )
  if 35 - 35: oO0o
  packet = ooOoO00 . unpack_address ( packet )
  if ( packet == None ) : return ( [ None , None ] )
  if 77 - 77: ooOoO0o + I1ii11iIi11i * o0oOOo0O0Ooo / i1IIi * I11i
  return ( [ packet , ooOoO00 ] )
  if 70 - 70: oO0o / iII111i * i1IIi / II111iiii / OoOoOO00 + oO0o
  if 30 - 30: i1IIi - iII111i - i11iIiiIii . OoOoOO00 . o0oOOo0O0Ooo
 def lcaf_decode_eid ( self , packet ) :
  O0000 = "BBB"
  I1 = struct . calcsize ( O0000 )
  if ( len ( packet ) < I1 ) : return ( [ None , None ] )
  if 74 - 74: i11iIiiIii / II111iiii
  if 62 - 62: O0
  if 63 - 63: Oo0Ooo + Oo0Ooo
  if 48 - 48: Oo0Ooo * I1ii11iIi11i % II111iiii
  if 42 - 42: I1Ii111 - ooOoO0o % o0oOOo0O0Ooo * I1IiiI . o0oOOo0O0Ooo
  Iii1IiIiIii , O0O0oooo , OO = struct . unpack ( O0000 ,
 packet [ : I1 ] )
  if 84 - 84: iIii1I11I1II1
  if ( OO == LISP_LCAF_INSTANCE_ID_TYPE ) :
   return ( [ self . lcaf_decode_iid ( packet ) , None ] )
  elif ( OO == LISP_LCAF_MCAST_INFO_TYPE ) :
   packet , ooOoO00 = self . lcaf_decode_sg ( packet )
   return ( [ packet , ooOoO00 ] )
  elif ( OO == LISP_LCAF_GEO_COORD_TYPE ) :
   O0000 = "BBBBH"
   I1 = struct . calcsize ( O0000 )
   if ( len ( packet ) < I1 ) : return ( None )
   if 39 - 39: Ii1I . II111iiii / I1IiiI
   OOoooOOO0 , O0O0oooo , OO , O0o , IiiiI1I1i = struct . unpack ( O0000 , packet [ : I1 ] )
   if 44 - 44: Ii1I / Ii1I / OoO0O00 % ooOoO0o / I11i . I1ii11iIi11i
   if 41 - 41: I1ii11iIi11i * ooOoO0o * I11i + O0 * O0 - O0
   if ( OO != LISP_LCAF_GEO_COORD_TYPE ) : return ( None )
   if 81 - 81: I1Ii111 % OoO0O00 / O0
   IiiiI1I1i = socket . ntohs ( IiiiI1I1i )
   packet = packet [ I1 : : ]
   if ( IiiiI1I1i > len ( packet ) ) : return ( None )
   if 55 - 55: i1IIi - I1Ii111 + I11i
   IiiiIi = lisp_geo ( "" )
   self . instance_id = 0
   self . afi = LISP_AFI_GEO_COORD
   self . address = IiiiIi
   packet = IiiiIi . decode_geo ( packet , IiiiI1I1i , O0o )
   self . mask_len = self . host_mask_len ( )
   if 93 - 93: I1IiiI % IiII . OoOoOO00 + iII111i
  return ( [ packet , None ] )
  if 81 - 81: ooOoO0o / I1Ii111 + OOooOOo / Oo0Ooo / OoOoOO00
  if 34 - 34: ooOoO0o * iIii1I11I1II1 % i11iIiiIii * OOooOOo - OOooOOo
  if 63 - 63: Oo0Ooo / oO0o + iII111i % OoooooooOO * I11i
  if 34 - 34: I1IiiI + I1Ii111 % ooOoO0o
  if 24 - 24: Ii1I % II111iiii - i11iIiiIii
  if 52 - 52: OoO0O00
class lisp_elp_node ( ) :
 def __init__ ( self ) :
  self . address = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . probe = False
  self . strict = False
  self . eid = False
  self . we_are_last = False
  if 76 - 76: ooOoO0o - iII111i % ooOoO0o / oO0o . OOooOOo
  if 50 - 50: IiII . i11iIiiIii % I11i
 def copy_elp_node ( self ) :
  IIII1Ii1II1 = lisp_elp_node ( )
  IIII1Ii1II1 . copy_address ( self . address )
  IIII1Ii1II1 . probe = self . probe
  IIII1Ii1II1 . strict = self . strict
  IIII1Ii1II1 . eid = self . eid
  IIII1Ii1II1 . we_are_last = self . we_are_last
  return ( IIII1Ii1II1 )
  if 22 - 22: i1IIi - II111iiii - OoOoOO00 . iII111i
  if 43 - 43: I1Ii111 * OOooOOo - IiII . i11iIiiIii
  if 34 - 34: iII111i . OoOoOO00
class lisp_elp ( ) :
 def __init__ ( self , name ) :
  self . elp_name = name
  self . elp_nodes = [ ]
  self . use_elp_node = None
  self . we_are_last = False
  if 49 - 49: I1ii11iIi11i % oO0o - I1Ii111 . I1ii11iIi11i % II111iiii
  if 20 - 20: I1ii11iIi11i . iIii1I11I1II1 - Ii1I % OoO0O00
 def copy_elp ( self ) :
  i1Ii1IiIii1I = lisp_elp ( self . elp_name )
  i1Ii1IiIii1I . use_elp_node = self . use_elp_node
  i1Ii1IiIii1I . we_are_last = self . we_are_last
  for IIII1Ii1II1 in self . elp_nodes :
   i1Ii1IiIii1I . elp_nodes . append ( IIII1Ii1II1 . copy_elp_node ( ) )
   if 27 - 27: iIii1I11I1II1 / I1Ii111 - I11i . OoO0O00 + ooOoO0o
  return ( i1Ii1IiIii1I )
  if 89 - 89: I1IiiI % I11i - OOooOOo
  if 71 - 71: OOooOOo % Oo0Ooo - o0oOOo0O0Ooo / I1Ii111 - O0 - oO0o
 def print_elp ( self , want_marker ) :
  O0o0ooO0 = ""
  for IIII1Ii1II1 in self . elp_nodes :
   iiI1i = ""
   if ( want_marker ) :
    if ( IIII1Ii1II1 == self . use_elp_node ) :
     iiI1i = "*"
    elif ( IIII1Ii1II1 . we_are_last ) :
     iiI1i = "x"
     if 4 - 4: I1IiiI * I1IiiI + II111iiii . iII111i
     if 9 - 9: I11i % o0oOOo0O0Ooo % I1Ii111 - ooOoO0o + I11i
   O0o0ooO0 += "{}{}({}{}{}), " . format ( iiI1i ,
 IIII1Ii1II1 . address . print_address_no_iid ( ) ,
 "r" if IIII1Ii1II1 . eid else "R" , "P" if IIII1Ii1II1 . probe else "p" ,
 "S" if IIII1Ii1II1 . strict else "s" )
   if 87 - 87: IiII
  return ( O0o0ooO0 [ 0 : - 2 ] if O0o0ooO0 != "" else "" )
  if 12 - 12: O0 - iII111i * IiII . i11iIiiIii
  if 25 - 25: Ii1I % i1IIi * I11i * Ii1I - IiII . i11iIiiIii
 def select_elp_node ( self ) :
  i1iII1iI , iIiiIi11ii111 , Ooooo = lisp_myrlocs
  OOOoO000 = None
  if 60 - 60: I1ii11iIi11i - iIii1I11I1II1
  for IIII1Ii1II1 in self . elp_nodes :
   if ( i1iII1iI and IIII1Ii1II1 . address . is_exact_match ( i1iII1iI ) ) :
    OOOoO000 = self . elp_nodes . index ( IIII1Ii1II1 )
    break
    if 47 - 47: Ii1I / I1Ii111 + O0 - I1ii11iIi11i * oO0o
   if ( iIiiIi11ii111 and IIII1Ii1II1 . address . is_exact_match ( iIiiIi11ii111 ) ) :
    OOOoO000 = self . elp_nodes . index ( IIII1Ii1II1 )
    break
    if 98 - 98: o0oOOo0O0Ooo * I1Ii111 % OoO0O00 / O0
    if 2 - 2: Ii1I . iII111i / ooOoO0o + I1IiiI
    if 70 - 70: O0
    if 100 - 100: o0oOOo0O0Ooo . Ii1I + ooOoO0o * I1IiiI
    if 3 - 3: II111iiii % OoO0O00 . Ii1I * i11iIiiIii % I1Ii111
    if 73 - 73: OoO0O00 + I1Ii111 % OoooooooOO / o0oOOo0O0Ooo + I1Ii111 / i1IIi
    if 71 - 71: iIii1I11I1II1 + i1IIi
  if ( OOOoO000 == None ) :
   self . use_elp_node = self . elp_nodes [ 0 ]
   IIII1Ii1II1 . we_are_last = False
   return
   if 48 - 48: ooOoO0o % OoooooooOO - OOooOOo
   if 22 - 22: ooOoO0o / Ii1I / OoOoOO00 / I1Ii111 * OoOoOO00 + I1Ii111
   if 94 - 94: i1IIi - iIii1I11I1II1 / Ii1I
   if 51 - 51: oO0o
   if 57 - 57: i11iIiiIii - Oo0Ooo + I1Ii111 * OoO0O00
   if 35 - 35: o0oOOo0O0Ooo % II111iiii + O0
  if ( self . elp_nodes [ - 1 ] == self . elp_nodes [ OOOoO000 ] ) :
   self . use_elp_node = None
   IIII1Ii1II1 . we_are_last = True
   return
   if 70 - 70: I1ii11iIi11i . II111iiii
   if 54 - 54: OOooOOo
   if 67 - 67: I1IiiI . o0oOOo0O0Ooo / i1IIi * I1ii11iIi11i . Oo0Ooo + II111iiii
   if 63 - 63: OoOoOO00 - OoOoOO00
   if 31 - 31: I1ii11iIi11i % O0 - i11iIiiIii * o0oOOo0O0Ooo . ooOoO0o * ooOoO0o
  self . use_elp_node = self . elp_nodes [ OOOoO000 + 1 ]
  return
  if 18 - 18: OoO0O00 - OoO0O00 . o0oOOo0O0Ooo
  if 80 - 80: I11i + I1Ii111 / I1IiiI * OOooOOo % iII111i
  if 48 - 48: iIii1I11I1II1 + i1IIi . I1IiiI % OoO0O00 - iIii1I11I1II1 / i1IIi
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
  if 14 - 14: IiII . I11i
  if 13 - 13: OoOoOO00 - I11i . OOooOOo % OoO0O00
 def copy_geo ( self ) :
  IiiiIi = lisp_geo ( self . geo_name )
  IiiiIi . latitude = self . latitude
  IiiiIi . lat_mins = self . lat_mins
  IiiiIi . lat_secs = self . lat_secs
  IiiiIi . longitude = self . longitude
  IiiiIi . long_mins = self . long_mins
  IiiiIi . long_secs = self . long_secs
  IiiiIi . altitude = self . altitude
  IiiiIi . radius = self . radius
  return ( IiiiIi )
  if 79 - 79: iII111i / Ii1I % i11iIiiIii . I1IiiI % OoO0O00 / i11iIiiIii
  if 100 - 100: OOooOOo + Oo0Ooo . iIii1I11I1II1 . ooOoO0o * Oo0Ooo
 def no_geo_altitude ( self ) :
  return ( self . altitude == - 1 )
  if 16 - 16: Oo0Ooo % OoOoOO00 + I1Ii111 % I1Ii111
  if 12 - 12: I1Ii111 . Ii1I / iIii1I11I1II1 + i1IIi
 def parse_geo_string ( self , geo_str ) :
  OOOoO000 = geo_str . find ( "]" )
  if ( OOOoO000 != - 1 ) : geo_str = geo_str [ OOOoO000 + 1 : : ]
  if 9 - 9: iIii1I11I1II1
  if 75 - 75: I11i . II111iiii * I1IiiI * IiII
  if 36 - 36: OOooOOo / I1ii11iIi11i / oO0o / ooOoO0o / I11i
  if 7 - 7: OoO0O00 - I11i - o0oOOo0O0Ooo / o0oOOo0O0Ooo + i11iIiiIii
  if 28 - 28: OoOoOO00 % ooOoO0o . I1IiiI + II111iiii
  if ( geo_str . find ( "/" ) != - 1 ) :
   geo_str , iIIo0OOO = geo_str . split ( "/" )
   self . radius = int ( iIIo0OOO )
   if 62 - 62: O0
   if 40 - 40: OoOoOO00 - O0 / I1Ii111 + OoO0O00 + ooOoO0o
  geo_str = geo_str . split ( "-" )
  if ( len ( geo_str ) < 8 ) : return ( False )
  if 51 - 51: I1ii11iIi11i - II111iiii / Oo0Ooo % ooOoO0o
  iii1Iiii = geo_str [ 0 : 4 ]
  o0oo0oO0 = geo_str [ 4 : 8 ]
  if 65 - 65: Oo0Ooo . I1IiiI / I11i * OOooOOo
  if 17 - 17: Ii1I . IiII
  if 46 - 46: O0 . OoooooooOO . ooOoO0o
  if 44 - 44: IiII / II111iiii - OoooooooOO
  if ( len ( geo_str ) > 8 ) : self . altitude = int ( geo_str [ 8 ] )
  if 47 - 47: OoO0O00 - ooOoO0o
  if 22 - 22: ooOoO0o % ooOoO0o . OOooOOo - II111iiii + OoO0O00
  if 44 - 44: I11i / o0oOOo0O0Ooo - OoO0O00 . Ii1I % oO0o - o0oOOo0O0Ooo
  if 14 - 14: OOooOOo * IiII
  self . latitude = int ( iii1Iiii [ 0 ] )
  self . lat_mins = int ( iii1Iiii [ 1 ] )
  self . lat_secs = int ( iii1Iiii [ 2 ] )
  if ( iii1Iiii [ 3 ] == "N" ) : self . latitude = - self . latitude
  if 15 - 15: o0oOOo0O0Ooo + OoooooooOO - OOooOOo - o0oOOo0O0Ooo . iIii1I11I1II1 / Ii1I
  if 33 - 33: OoO0O00
  if 91 - 91: I11i % I11i % iII111i
  if 19 - 19: I11i / I11i + I1IiiI * OoO0O00 - iII111i . Oo0Ooo
  self . longitude = int ( o0oo0oO0 [ 0 ] )
  self . long_mins = int ( o0oo0oO0 [ 1 ] )
  self . long_secs = int ( o0oo0oO0 [ 2 ] )
  if ( o0oo0oO0 [ 3 ] == "E" ) : self . longitude = - self . longitude
  return ( True )
  if 76 - 76: iII111i % OOooOOo / OoooooooOO . I1IiiI % OoO0O00 % i1IIi
  if 95 - 95: Oo0Ooo - O0 / I1ii11iIi11i . I1IiiI / o0oOOo0O0Ooo % OoOoOO00
 def print_geo ( self ) :
  IIiiIIIi1i = "N" if self . latitude < 0 else "S"
  o00 = "E" if self . longitude < 0 else "W"
  if 55 - 55: OoO0O00 + Ii1I % oO0o
  OOOo0O0oOOOoO0o = "{}-{}-{}-{}-{}-{}-{}-{}" . format ( abs ( self . latitude ) ,
 self . lat_mins , self . lat_secs , IIiiIIIi1i , abs ( self . longitude ) ,
 self . long_mins , self . long_secs , o00 )
  if 57 - 57: oO0o + I11i / i11iIiiIii
  if ( self . no_geo_altitude ( ) == False ) :
   OOOo0O0oOOOoO0o += "-" + str ( self . altitude )
   if 74 - 74: OoO0O00 - II111iiii - ooOoO0o % i1IIi
   if 42 - 42: i11iIiiIii / O0
   if 8 - 8: I1Ii111
   if 51 - 51: i11iIiiIii
   if 1 - 1: iIii1I11I1II1 . i1IIi . i11iIiiIii % I1ii11iIi11i
  if ( self . radius != 0 ) : OOOo0O0oOOOoO0o += "/{}" . format ( self . radius )
  return ( OOOo0O0oOOOoO0o )
  if 58 - 58: i11iIiiIii * i11iIiiIii - OoO0O00
  if 8 - 8: i11iIiiIii * OoOoOO00 . o0oOOo0O0Ooo
 def geo_url ( self ) :
  iI111i = os . getenv ( "LISP_GEO_ZOOM_LEVEL" )
  iI111i = "10" if ( iI111i == "" or iI111i . isdigit ( ) == False ) else iI111i
  i1III , iIo0 = self . dms_to_decimal ( )
  i1i11 = ( "http://maps.googleapis.com/maps/api/staticmap?center={},{}" + "&markers=color:blue%7Clabel:lisp%7C{},{}" + "&zoom={}&size=1024x1024&sensor=false" ) . format ( i1III , iIo0 , i1III , iIo0 ,
  # OoOoOO00
  # OOooOOo . OoooooooOO % I1Ii111 * I1Ii111 - II111iiii - Ii1I
 iI111i )
  return ( i1i11 )
  if 75 - 75: o0oOOo0O0Ooo / Oo0Ooo + oO0o
  if 67 - 67: IiII + OoooooooOO . i11iIiiIii - I1Ii111 . i11iIiiIii
 def print_geo_url ( self ) :
  IiiiIi = self . print_geo ( )
  if ( self . radius == 0 ) :
   i1i11 = self . geo_url ( )
   i11ii111i1ii = "<a href='{}'>{}</a>" . format ( i1i11 , IiiiIi )
  else :
   i1i11 = IiiiIi . replace ( "/" , "-" )
   i11ii111i1ii = "<a href='/lisp/geo-map/{}'>{}</a>" . format ( i1i11 , IiiiIi )
   if 70 - 70: OoO0O00 * OoooooooOO
  return ( i11ii111i1ii )
  if 52 - 52: Ii1I . iII111i / OoooooooOO
  if 19 - 19: OOooOOo % o0oOOo0O0Ooo
 def dms_to_decimal ( self ) :
  i1Ii11iiIiI , I1i1iiI , IIIiIii1 = self . latitude , self . lat_mins , self . lat_secs
  Ooo0OO0o = float ( abs ( i1Ii11iiIiI ) )
  Ooo0OO0o += float ( I1i1iiI * 60 + IIIiIii1 ) / 3600
  if ( i1Ii11iiIiI > 0 ) : Ooo0OO0o = - Ooo0OO0o
  OOOOOO = Ooo0OO0o
  if 78 - 78: OOooOOo . I1Ii111 . i1IIi
  i1Ii11iiIiI , I1i1iiI , IIIiIii1 = self . longitude , self . long_mins , self . long_secs
  Ooo0OO0o = float ( abs ( i1Ii11iiIiI ) )
  Ooo0OO0o += float ( I1i1iiI * 60 + IIIiIii1 ) / 3600
  if ( i1Ii11iiIiI > 0 ) : Ooo0OO0o = - Ooo0OO0o
  oo0oIi1IiI11i = Ooo0OO0o
  return ( ( OOOOOO , oo0oIi1IiI11i ) )
  if 11 - 11: i1IIi / I11i * OoOoOO00 * IiII . ooOoO0o * i1IIi
  if 85 - 85: i11iIiiIii . OoO0O00 + I1IiiI
 def get_distance ( self , geo_point ) :
  OoOoooO = self . dms_to_decimal ( )
  o00O0 = geo_point . dms_to_decimal ( )
  ooI1 = vincenty ( OoOoooO , o00O0 )
  return ( ooI1 . km )
  if 39 - 39: iII111i . OoooooooOO * IiII - ooOoO0o % OoO0O00 / i1IIi
  if 57 - 57: I1IiiI - ooOoO0o
 def point_in_circle ( self , geo_point ) :
  oO0oOOOOOOoOO = self . get_distance ( geo_point )
  return ( oO0oOOOOOOoOO <= self . radius )
  if 26 - 26: I1ii11iIi11i / Oo0Ooo
  if 28 - 28: OoO0O00 / I1ii11iIi11i % OOooOOo % I1IiiI + Ii1I
 def encode_geo ( self ) :
  ii1Ii111I11 = socket . htons ( LISP_AFI_LCAF )
  o00O0OO = socket . htons ( 20 + 2 )
  O0O0oooo = 0
  if 6 - 6: o0oOOo0O0Ooo % OOooOOo
  i1III = abs ( self . latitude )
  OO0ooo = ( ( self . lat_mins * 60 ) + self . lat_secs ) * 1000
  if ( self . latitude < 0 ) : O0O0oooo |= 0x40
  if 86 - 86: o0oOOo0O0Ooo
  iIo0 = abs ( self . longitude )
  oO0000O0 = ( ( self . long_mins * 60 ) + self . long_secs ) * 1000
  if ( self . longitude < 0 ) : O0O0oooo |= 0x20
  if 94 - 94: OoO0O00 % II111iiii % iII111i + OoooooooOO - o0oOOo0O0Ooo * I1Ii111
  I1Iii1Ii = 0
  if ( self . no_geo_altitude ( ) == False ) :
   I1Iii1Ii = socket . htonl ( self . altitude )
   O0O0oooo |= 0x10
   if 7 - 7: ooOoO0o + iIii1I11I1II1
  iIIo0OOO = socket . htons ( self . radius )
  if ( iIIo0OOO != 0 ) : O0O0oooo |= 0x06
  if 63 - 63: II111iiii
  o0o00o = struct . pack ( "HBBBBH" , ii1Ii111I11 , 0 , 0 , LISP_LCAF_GEO_COORD_TYPE ,
 0 , o00O0OO )
  o0o00o += struct . pack ( "BBHBBHBBHIHHH" , O0O0oooo , 0 , 0 , i1III , OO0ooo >> 16 ,
 socket . htons ( OO0ooo & 0x0ffff ) , iIo0 , oO0000O0 >> 16 ,
 socket . htons ( oO0000O0 & 0xffff ) , I1Iii1Ii , iIIo0OOO , 0 , 0 )
  if 12 - 12: II111iiii - O0 . i1IIi % oO0o % OoooooooOO
  return ( o0o00o )
  if 36 - 36: IiII * OoOoOO00 - iIii1I11I1II1 + II111iiii
  if 65 - 65: I1IiiI * I11i . I1Ii111 % I1ii11iIi11i + O0
 def decode_geo ( self , packet , lcaf_len , radius_hi ) :
  O0000 = "BBHBBHBBHIHHH"
  I1 = struct . calcsize ( O0000 )
  if ( lcaf_len < I1 ) : return ( None )
  if 91 - 91: OoooooooOO % I1Ii111 * OoO0O00 - OoOoOO00
  O0O0oooo , IiI11I1IiIi11 , oOO0OOo , i1III , ii1IIi1II , OO0ooo , iIo0 , II1I1111III , oO0000O0 , I1Iii1Ii , iIIo0OOO , OOO00Oo0o0Oo , o0O0O0O00o = struct . unpack ( O0000 ,
  # OoOoOO00 / i1IIi * OoOoOO00 / II111iiii
 packet [ : I1 ] )
  if 10 - 10: OoOoOO00 / iII111i - OoO0O00 + oO0o
  if 55 - 55: OoO0O00 / Ii1I % ooOoO0o . I1Ii111 * i1IIi . i11iIiiIii
  if 34 - 34: I1ii11iIi11i % o0oOOo0O0Ooo % ooOoO0o * Ii1I * I1Ii111
  if 59 - 59: Ii1I + Oo0Ooo % O0 % i1IIi - iII111i
  o0O0O0O00o = socket . ntohs ( o0O0O0O00o )
  if ( o0O0O0O00o == LISP_AFI_LCAF ) : return ( None )
  if 4 - 4: O0 - oO0o % OoO0O00 % OoooooooOO
  if ( O0O0oooo & 0x40 ) : i1III = - i1III
  self . latitude = i1III
  oooOOO0OO0 = ( ( ii1IIi1II << 16 ) | socket . ntohs ( OO0ooo ) ) / 1000
  self . lat_mins = oooOOO0OO0 / 60
  self . lat_secs = oooOOO0OO0 % 60
  if 29 - 29: iIii1I11I1II1 + Ii1I + o0oOOo0O0Ooo / I1ii11iIi11i / i1IIi
  if ( O0O0oooo & 0x20 ) : iIo0 = - iIo0
  self . longitude = iIo0
  i1iIi1I111i = ( ( II1I1111III << 16 ) | socket . ntohs ( oO0000O0 ) ) / 1000
  self . long_mins = i1iIi1I111i / 60
  self . long_secs = i1iIi1I111i % 60
  if 2 - 2: OOooOOo . IiII . iII111i / Oo0Ooo
  self . altitude = socket . ntohl ( I1Iii1Ii ) if ( O0O0oooo & 0x10 ) else - 1
  iIIo0OOO = socket . ntohs ( iIIo0OOO )
  self . radius = iIIo0OOO if ( O0O0oooo & 0x02 ) else iIIo0OOO * 1000
  if 86 - 86: OOooOOo . o0oOOo0O0Ooo - iIii1I11I1II1
  self . geo_name = None
  packet = packet [ I1 : : ]
  if 12 - 12: oO0o + iII111i
  if ( o0O0O0O00o != 0 ) :
   self . rloc . afi = o0O0O0O00o
   packet = self . rloc . unpack_address ( packet )
   self . rloc . mask_len = self . rloc . host_mask_len ( )
   if 16 - 16: O0 + oO0o - ooOoO0o * O0 . I1ii11iIi11i . oO0o
  return ( packet )
  if 4 - 4: I1Ii111
  if 39 - 39: OoOoOO00 - I1Ii111 / I11i + II111iiii * I1IiiI * I1IiiI
  if 9 - 9: IiII * I1IiiI * OoO0O00 - I1IiiI * I1IiiI - OoO0O00
  if 20 - 20: i1IIi + I1IiiI + i11iIiiIii + II111iiii + i1IIi
  if 18 - 18: i11iIiiIii * O0 * Oo0Ooo + iII111i + OOooOOo
  if 62 - 62: OOooOOo - oO0o + i1IIi % Ii1I . I1Ii111 . II111iiii
class lisp_rle_node ( ) :
 def __init__ ( self ) :
  self . address = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . level = 0
  self . translated_port = 0
  self . rloc_name = None
  if 94 - 94: OOooOOo - I1IiiI
  if 35 - 35: i11iIiiIii
 def copy_rle_node ( self ) :
  oOo0o = lisp_rle_node ( )
  oOo0o . address . copy_address ( self . address )
  oOo0o . level = self . level
  oOo0o . translated_port = self . translated_port
  oOo0o . rloc_name = self . rloc_name
  return ( oOo0o )
  if 27 - 27: O0 % i11iIiiIii - I1Ii111 * oO0o - I11i / Oo0Ooo
  if 78 - 78: O0 * i11iIiiIii
 def store_translated_rloc ( self , rloc , port ) :
  self . address . copy_address ( rloc )
  self . translated_port = port
  if 62 - 62: OoO0O00 * I1Ii111 * Ii1I / ooOoO0o
  if 27 - 27: oO0o . iII111i . oO0o
 def get_encap_keys ( self ) :
  i1O0OO = "4341" if self . translated_port == 0 else str ( self . translated_port )
  if 37 - 37: Oo0Ooo . I1ii11iIi11i / OoooooooOO % ooOoO0o / I1IiiI + ooOoO0o
  OoOOoooO000 = self . address . print_address_no_iid ( ) + ":" + i1O0OO
  if 14 - 14: I11i + ooOoO0o . oO0o * I11i
  try :
   O000OO = lisp_crypto_keys_by_rloc_encap [ OoOOoooO000 ]
   if ( O000OO [ 1 ] ) : return ( O000OO [ 1 ] . encrypt_key , O000OO [ 1 ] . icv_key )
   return ( None , None )
  except :
   return ( None , None )
   if 98 - 98: Ii1I . i1IIi * OoO0O00 * Ii1I * iIii1I11I1II1
   if 22 - 22: OoooooooOO - OoO0O00 + OoOoOO00 - OOooOOo + i11iIiiIii - oO0o
   if 9 - 9: I1Ii111 - i1IIi . ooOoO0o
   if 33 - 33: I11i
class lisp_rle ( ) :
 def __init__ ( self , name ) :
  self . rle_name = name
  self . rle_nodes = [ ]
  self . rle_forwarding_list = [ ]
  if 37 - 37: Oo0Ooo
  if 36 - 36: IiII % I11i
 def copy_rle ( self ) :
  Oo0OOo = lisp_rle ( self . rle_name )
  for oOo0o in self . rle_nodes :
   Oo0OOo . rle_nodes . append ( oOo0o . copy_rle_node ( ) )
   if 72 - 72: oO0o % I11i % OOooOOo * iIii1I11I1II1 - OOooOOo % O0
  Oo0OOo . build_forwarding_list ( )
  return ( Oo0OOo )
  if 84 - 84: oO0o - o0oOOo0O0Ooo / II111iiii . o0oOOo0O0Ooo
  if 82 - 82: OoooooooOO
 def print_rle ( self , html ) :
  ii1OoO00o = ""
  for oOo0o in self . rle_nodes :
   i1O0OO = oOo0o . translated_port
   iIII = blue ( oOo0o . rloc_name , html ) if oOo0o . rloc_name != None else ""
   if 70 - 70: oO0o - iIii1I11I1II1 * i1IIi % iIii1I11I1II1 . OoO0O00 . OoOoOO00
   OoOOoooO000 = oOo0o . address . print_address_no_iid ( )
   if ( oOo0o . address . is_local ( ) ) : OoOOoooO000 = red ( OoOOoooO000 , html )
   ii1OoO00o += "{}{}(L{}){}, " . format ( OoOOoooO000 , "" if i1O0OO == 0 else "-" + str ( i1O0OO ) , oOo0o . level ,
   # Oo0Ooo % OoooooooOO % II111iiii / I1Ii111 * I1Ii111 % o0oOOo0O0Ooo
 "" if oOo0o . rloc_name == None else iIII )
   if 48 - 48: OoOoOO00 / OoO0O00 % II111iiii / O0
  return ( ii1OoO00o [ 0 : - 2 ] if ii1OoO00o != "" else "" )
  if 35 - 35: i11iIiiIii % OoooooooOO % OoooooooOO + i1IIi
  if 13 - 13: o0oOOo0O0Ooo / i1IIi
 def build_forwarding_list ( self ) :
  iiII1 = - 1
  for oOo0o in self . rle_nodes :
   if ( iiII1 == - 1 ) :
    if ( oOo0o . address . is_local ( ) ) : iiII1 = oOo0o . level
   else :
    if ( oOo0o . level > iiII1 ) : break
    if 73 - 73: ooOoO0o
    if 37 - 37: OOooOOo % OoOoOO00 - II111iiii * o0oOOo0O0Ooo . I1IiiI . OoOoOO00
  iiII1 = 0 if iiII1 == - 1 else oOo0o . level
  if 92 - 92: I11i + OoO0O00 . OoooooooOO
  self . rle_forwarding_list = [ ]
  for oOo0o in self . rle_nodes :
   if ( oOo0o . level == iiII1 or ( iiII1 == 0 and
 oOo0o . level == 128 ) ) :
    if ( lisp_i_am_rtr == False and oOo0o . address . is_local ( ) ) :
     OoOOoooO000 = oOo0o . address . print_address_no_iid ( )
     lprint ( "Exclude local RLE RLOC {}" . format ( OoOOoooO000 ) )
     continue
     if 3 - 3: OoO0O00 % iIii1I11I1II1
    self . rle_forwarding_list . append ( oOo0o )
    if 62 - 62: OoooooooOO * o0oOOo0O0Ooo
    if 59 - 59: iIii1I11I1II1
    if 18 - 18: ooOoO0o % I1IiiI / iIii1I11I1II1 + O0
    if 99 - 99: i11iIiiIii - o0oOOo0O0Ooo + o0oOOo0O0Ooo . OoooooooOO * iII111i . Oo0Ooo
    if 63 - 63: I11i
class lisp_json ( ) :
 def __init__ ( self , name , string ) :
  self . json_name = name
  self . json_string = string
  if 60 - 60: I1IiiI / I1ii11iIi11i / I11i / Ii1I + iIii1I11I1II1
  if 85 - 85: O0 / OOooOOo . OoOoOO00 / I1ii11iIi11i
 def add ( self ) :
  self . delete ( )
  lisp_json_list [ self . json_name ] = self
  if 80 - 80: I1ii11iIi11i * iII111i % i1IIi * OOooOOo % II111iiii % i1IIi
  if 44 - 44: OoooooooOO
 def delete ( self ) :
  if ( lisp_json_list . has_key ( self . json_name ) ) :
   del ( lisp_json_list [ self . json_name ] )
   lisp_json_list [ self . json_name ] = None
   if 18 - 18: i11iIiiIii
   if 65 - 65: i1IIi . iIii1I11I1II1 % iIii1I11I1II1
   if 35 - 35: iIii1I11I1II1 - o0oOOo0O0Ooo + I1ii11iIi11i * iII111i - OOooOOo . o0oOOo0O0Ooo
 def print_json ( self , html ) :
  ii1IIi1I11i = self . json_string
  OoOoOOo = "***"
  if ( html ) : OoOoOOo = red ( OoOoOOo , html )
  ii11ii11iiI = OoOoOOo + self . json_string + OoOoOOo
  if ( self . valid_json ( ) ) : return ( ii1IIi1I11i )
  return ( ii11ii11iiI )
  if 68 - 68: iIii1I11I1II1 . I1ii11iIi11i / o0oOOo0O0Ooo - i1IIi
  if 77 - 77: I1Ii111 * o0oOOo0O0Ooo % oO0o - I1IiiI . I1Ii111
 def valid_json ( self ) :
  try :
   json . loads ( self . json_string )
  except :
   return ( False )
   if 66 - 66: iII111i % OOooOOo
  return ( True )
  if 90 - 90: I1ii11iIi11i * iII111i * I1ii11iIi11i . IiII + OoOoOO00
  if 5 - 5: O0 - I11i - Oo0Ooo . iII111i / oO0o * iIii1I11I1II1
  if 94 - 94: ooOoO0o / Ii1I
  if 9 - 9: I1Ii111 * oO0o
  if 44 - 44: ooOoO0o * oO0o
  if 67 - 67: iIii1I11I1II1 . iIii1I11I1II1 + iIii1I11I1II1 * iII111i
class lisp_stats ( ) :
 def __init__ ( self ) :
  self . packet_count = 0
  self . byte_count = 0
  self . last_rate_check = 0
  self . last_packet_count = 0
  self . last_byte_count = 0
  self . last_increment = None
  if 70 - 70: I1IiiI - I11i / iIii1I11I1II1 . I1IiiI % I1ii11iIi11i
  if 12 - 12: Oo0Ooo + I1IiiI
 def increment ( self , octets ) :
  self . packet_count += 1
  self . byte_count += octets
  self . last_increment = lisp_get_timestamp ( )
  if 12 - 12: OoOoOO00 / II111iiii
  if 100 - 100: I1ii11iIi11i % iIii1I11I1II1 . IiII . OoooooooOO / II111iiii
 def recent_packet_sec ( self ) :
  if ( self . last_increment == None ) : return ( False )
  ooooOoO0O = time . time ( ) - self . last_increment
  return ( ooooOoO0O <= 1 )
  if 28 - 28: I1IiiI
  if 27 - 27: I1IiiI % oO0o - iIii1I11I1II1 - o0oOOo0O0Ooo - IiII - O0
 def recent_packet_min ( self ) :
  if ( self . last_increment == None ) : return ( False )
  ooooOoO0O = time . time ( ) - self . last_increment
  return ( ooooOoO0O <= 60 )
  if 46 - 46: II111iiii
  if 24 - 24: i11iIiiIii * i1IIi - I11i + o0oOOo0O0Ooo
 def stat_colors ( self , c1 , c2 , html ) :
  if ( self . recent_packet_sec ( ) ) :
   return ( green_last_sec ( c1 ) , green_last_sec ( c2 ) )
   if 60 - 60: ooOoO0o
  if ( self . recent_packet_min ( ) ) :
   return ( green_last_min ( c1 ) , green_last_min ( c2 ) )
   if 62 - 62: i11iIiiIii
  return ( c1 , c2 )
  if 88 - 88: i11iIiiIii
  if 59 - 59: oO0o - OoooooooOO % ooOoO0o
 def normalize ( self , count ) :
  count = str ( count )
  o0o0o00 = len ( count )
  if ( o0o0o00 > 12 ) :
   count = count [ 0 : - 10 ] + "." + count [ - 10 : - 7 ] + "T"
   return ( count )
   if 24 - 24: I1IiiI
  if ( o0o0o00 > 9 ) :
   count = count [ 0 : - 9 ] + "." + count [ - 9 : - 7 ] + "B"
   return ( count )
   if 34 - 34: OOooOOo - i11iIiiIii + Oo0Ooo . I1ii11iIi11i . OoO0O00
  if ( o0o0o00 > 6 ) :
   count = count [ 0 : - 6 ] + "." + count [ - 6 ] + "M"
   return ( count )
   if 38 - 38: iII111i
  return ( count )
  if 100 - 100: i11iIiiIii % i1IIi + I1ii11iIi11i + Oo0Ooo
  if 36 - 36: O0 - iII111i + I11i + I1IiiI
 def get_stats ( self , summary , html ) :
  OOO00 = self . last_rate_check
  IiI111111i = self . last_packet_count
  iiI1i1i1i = self . last_byte_count
  self . last_rate_check = lisp_get_timestamp ( )
  self . last_packet_count = self . packet_count
  self . last_byte_count = self . byte_count
  if 34 - 34: oO0o . oO0o % I11i . OoOoOO00
  ii1oO00o = self . last_rate_check - OOO00
  if ( ii1oO00o == 0 ) :
   I1IoOo = 0
   iI1IIiI1i11Ii = 0
  else :
   I1IoOo = int ( ( self . packet_count - IiI111111i ) / ii1oO00o )
   iI1IIiI1i11Ii = ( self . byte_count - iiI1i1i1i ) / ii1oO00o
   iI1IIiI1i11Ii = ( iI1IIiI1i11Ii * 8 ) / 1000000
   iI1IIiI1i11Ii = round ( iI1IIiI1i11Ii , 2 )
   if 70 - 70: I1IiiI . I1IiiI - OoooooooOO - I11i
   if 38 - 38: i1IIi + oO0o * ooOoO0o % Ii1I % ooOoO0o
   if 80 - 80: OoO0O00 + OoOoOO00 % iII111i % OoooooooOO - ooOoO0o
   if 25 - 25: OoOoOO00 % i11iIiiIii - I1IiiI * iIii1I11I1II1 - Oo0Ooo . O0
   if 48 - 48: I1IiiI + oO0o % i11iIiiIii % iIii1I11I1II1
  i1III1iIII1I = self . normalize ( self . packet_count )
  O0OooO0 = self . normalize ( self . byte_count )
  if 1 - 1: iII111i * i1IIi . iIii1I11I1II1 % O0 - OoooooooOO
  if 87 - 87: iII111i . Oo0Ooo * i11iIiiIii % o0oOOo0O0Ooo + Ii1I
  if 72 - 72: Ii1I / II111iiii + o0oOOo0O0Ooo
  if 33 - 33: I1Ii111 * OoOoOO00 - OoooooooOO
  if 11 - 11: I1Ii111 - Oo0Ooo / iIii1I11I1II1 - OoooooooOO
  if ( summary ) :
   OOO0Oo = "<br>" if html else ""
   i1III1iIII1I , O0OooO0 = self . stat_colors ( i1III1iIII1I , O0OooO0 , html )
   Ooo0Oo = "packet-count: {}{}byte-count: {}" . format ( i1III1iIII1I , OOO0Oo , O0OooO0 )
   i1i1Ii11 = "packet-rate: {} pps\nbit-rate: {} Mbps" . format ( I1IoOo , iI1IIiI1i11Ii )
   if 52 - 52: I11i . iII111i * II111iiii + OOooOOo % I1Ii111 * Ii1I
   if ( html != "" ) : i1i1Ii11 = lisp_span ( Ooo0Oo , i1i1Ii11 )
  else :
   i11i1iIi = str ( I1IoOo )
   oOOOOOO0oo = str ( iI1IIiI1i11Ii )
   if ( html ) :
    i1III1iIII1I = lisp_print_cour ( i1III1iIII1I )
    i11i1iIi = lisp_print_cour ( i11i1iIi )
    O0OooO0 = lisp_print_cour ( O0OooO0 )
    oOOOOOO0oo = lisp_print_cour ( oOOOOOO0oo )
    if 46 - 46: OoOoOO00
   OOO0Oo = "<br>" if html else ", "
   if 75 - 75: I1IiiI
   i1i1Ii11 = ( "packet-count: {}{}packet-rate: {} pps{}byte-count: " + "{}{}bit-rate: {} mbps" ) . format ( i1III1iIII1I , OOO0Oo , i11i1iIi , OOO0Oo , O0OooO0 , OOO0Oo ,
   # OOooOOo * ooOoO0o . OoO0O00
 oOOOOOO0oo )
   if 39 - 39: I11i % ooOoO0o / iIii1I11I1II1 . OoooooooOO / ooOoO0o / O0
  return ( i1i1Ii11 )
  if 100 - 100: OOooOOo * OoooooooOO
  if 80 - 80: O0 + oO0o - OoooooooOO - O0 . ooOoO0o . OoooooooOO
  if 76 - 76: Ii1I
  if 62 - 62: O0 / OoO0O00 % i11iIiiIii / OOooOOo * iIii1I11I1II1
  if 78 - 78: OOooOOo % O0 * O0
  if 62 - 62: ooOoO0o
  if 77 - 77: I1IiiI . i11iIiiIii - I1ii11iIi11i
  if 83 - 83: OoO0O00 - i11iIiiIii + I1ii11iIi11i - OOooOOo / OoOoOO00 / I11i
lisp_decap_stats = {
 "good-packets" : lisp_stats ( ) , "ICV-error" : lisp_stats ( ) ,
 "checksum-error" : lisp_stats ( ) , "lisp-header-error" : lisp_stats ( ) ,
 "no-decrypt-key" : lisp_stats ( ) , "bad-inner-version" : lisp_stats ( ) ,
 "outer-header-error" : lisp_stats ( )
 }
if 53 - 53: I11i * I1IiiI . I1IiiI / o0oOOo0O0Ooo - I1Ii111
if 50 - 50: I11i - OoOoOO00 + I1IiiI % Oo0Ooo / OoooooooOO - I1ii11iIi11i
if 26 - 26: IiII . Ii1I
if 35 - 35: I1ii11iIi11i + OOooOOo
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
  if 88 - 88: O0
  if ( recurse == False ) : return
  if 4 - 4: OoOoOO00 % iIii1I11I1II1 % OoooooooOO . oO0o
  if 27 - 27: II111iiii - OoOoOO00
  if 81 - 81: o0oOOo0O0Ooo - Oo0Ooo % IiII - ooOoO0o / O0
  if 27 - 27: Oo0Ooo
  if 15 - 15: iIii1I11I1II1 . OoOoOO00 % Ii1I / i1IIi . o0oOOo0O0Ooo
  if 45 - 45: iIii1I11I1II1 - i1IIi % I1IiiI - I1Ii111 + oO0o
  iiii111I = lisp_get_default_route_next_hops ( )
  if ( iiii111I == [ ] or len ( iiii111I ) == 1 ) : return
  if 87 - 87: ooOoO0o * OoOoOO00
  self . rloc_next_hop = iiii111I [ 0 ]
  i11iI11ii = self
  for IiIIiI11I in iiii111I [ 1 : : ] :
   oO0Oo0Oo0 = lisp_rloc ( False )
   oO0Oo0Oo0 = copy . deepcopy ( self )
   oO0Oo0Oo0 . rloc_next_hop = IiIIiI11I
   i11iI11ii . next_rloc = oO0Oo0Oo0
   i11iI11ii = oO0Oo0Oo0
   if 22 - 22: OoO0O00 / I1IiiI - I1IiiI - i11iIiiIii . I1IiiI - OOooOOo
   if 27 - 27: ooOoO0o
   if 34 - 34: OoooooooOO - I1Ii111 + I1Ii111 % IiII % OoooooooOO
 def up_state ( self ) :
  return ( self . state == LISP_RLOC_UP_STATE )
  if 24 - 24: I1Ii111 . Oo0Ooo / ooOoO0o * O0
  if 85 - 85: I1IiiI - OOooOOo
 def unreach_state ( self ) :
  return ( self . state == LISP_RLOC_UNREACH_STATE )
  if 7 - 7: i1IIi % II111iiii
  if 33 - 33: iIii1I11I1II1 . O0 . oO0o
 def no_echoed_nonce_state ( self ) :
  return ( self . state == LISP_RLOC_NO_ECHOED_NONCE_STATE )
  if 69 - 69: II111iiii * O0 . ooOoO0o * IiII
  if 25 - 25: I11i - I1ii11iIi11i . I1Ii111 . OoooooooOO
 def down_state ( self ) :
  return ( self . state in [ LISP_RLOC_DOWN_STATE , LISP_RLOC_ADMIN_DOWN_STATE ] )
  if 4 - 4: IiII * OoO0O00 % I1ii11iIi11i * Ii1I . iII111i
  if 41 - 41: OoooooooOO % I11i . O0 + I1Ii111
  if 67 - 67: OoOoOO00 * OOooOOo / OOooOOo / OoooooooOO
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
  if 67 - 67: I11i - i1IIi . OoooooooOO / iIii1I11I1II1
  if 34 - 34: OoO0O00 * II111iiii
 def print_rloc ( self , indent ) :
  III11I1 = lisp_print_elapsed ( self . uptime )
  lprint ( "{}rloc {}, uptime {}, {}, parms {}/{}/{}/{}" . format ( indent ,
 red ( self . rloc . print_address ( ) , False ) , III11I1 , self . print_state ( ) ,
 self . priority , self . weight , self . mpriority , self . mweight ) )
  if 43 - 43: OoOoOO00 . I1IiiI
  if 44 - 44: O0 / o0oOOo0O0Ooo
 def print_rloc_name ( self , cour = False ) :
  if ( self . rloc_name == None ) : return ( "" )
  Iii1I1III1ii = self . rloc_name
  if ( cour ) : Iii1I1III1ii = lisp_print_cour ( Iii1I1III1ii )
  return ( 'rloc-name: {}' . format ( blue ( Iii1I1III1ii , cour ) ) )
  if 19 - 19: I11i
  if 91 - 91: OOooOOo * OoooooooOO
 def store_rloc_from_record ( self , rloc_record , nonce , source ) :
  i1O0OO = LISP_DATA_PORT
  self . rloc . copy_address ( rloc_record . rloc )
  self . rloc_name = rloc_record . rloc_name
  if 89 - 89: i1IIi / iII111i . I1Ii111
  if 74 - 74: I1ii11iIi11i % iII111i / OoooooooOO / I1ii11iIi11i % i11iIiiIii % ooOoO0o
  if 82 - 82: OoooooooOO . o0oOOo0O0Ooo * I1ii11iIi11i % I1ii11iIi11i * Ii1I
  if 83 - 83: I11i - Oo0Ooo + i11iIiiIii - i11iIiiIii
  oOoOoo0O = self . rloc
  if ( oOoOoo0O . is_null ( ) == False ) :
   o0oO00ooo0o = lisp_get_nat_info ( oOoOoo0O , self . rloc_name )
   if ( o0oO00ooo0o ) :
    i1O0OO = o0oO00ooo0o . port
    I11ii111i1 = lisp_nat_state_info [ self . rloc_name ] [ 0 ]
    OoOOoooO000 = oOoOoo0O . print_address_no_iid ( )
    Oo0oO = red ( OoOOoooO000 , False )
    OoO0o0 = "" if self . rloc_name == None else blue ( self . rloc_name , False )
    if 58 - 58: OoO0O00 - o0oOOo0O0Ooo % I1Ii111 . I1ii11iIi11i - Ii1I * i11iIiiIii
    if 36 - 36: II111iiii * Ii1I
    if 53 - 53: Ii1I / iIii1I11I1II1 + o0oOOo0O0Ooo . Ii1I
    if 79 - 79: Ii1I % O0 * OOooOOo
    if 41 - 41: I1ii11iIi11i . OoooooooOO * I1ii11iIi11i - oO0o
    if 40 - 40: I1IiiI % OoO0O00 + i11iIiiIii / oO0o
    if ( o0oO00ooo0o . timed_out ( ) ) :
     lprint ( ( "    Matched stored NAT state timed out for " + "RLOC {}:{}, {}" ) . format ( Oo0oO , i1O0OO , OoO0o0 ) )
     if 98 - 98: oO0o + iIii1I11I1II1 . ooOoO0o / I1ii11iIi11i
     if 77 - 77: OoOoOO00 / Oo0Ooo * OoOoOO00 % I1IiiI . II111iiii % OoO0O00
     o0oO00ooo0o = None if ( o0oO00ooo0o == I11ii111i1 ) else I11ii111i1
     if ( o0oO00ooo0o and o0oO00ooo0o . timed_out ( ) ) :
      i1O0OO = o0oO00ooo0o . port
      Oo0oO = red ( o0oO00ooo0o . address , False )
      lprint ( ( "    Youngest stored NAT state timed out " + " for RLOC {}:{}, {}" ) . format ( Oo0oO , i1O0OO ,
      # I1ii11iIi11i * i1IIi % OoO0O00
 OoO0o0 ) )
      o0oO00ooo0o = None
      if 38 - 38: ooOoO0o . iIii1I11I1II1
      if 96 - 96: iII111i + iIii1I11I1II1 * OoOoOO00 . OoOoOO00 + OoOoOO00
      if 17 - 17: I11i / I1IiiI / i11iIiiIii
      if 86 - 86: OOooOOo
      if 81 - 81: iIii1I11I1II1 / OOooOOo / O0 . O0
      if 75 - 75: O0
      if 46 - 46: I1ii11iIi11i / ooOoO0o
    if ( o0oO00ooo0o ) :
     if ( o0oO00ooo0o . address != OoOOoooO000 ) :
      lprint ( "RLOC conflict, RLOC-record {}, NAT state {}" . format ( Oo0oO , red ( o0oO00ooo0o . address , False ) ) )
      if 69 - 69: I1ii11iIi11i . IiII % o0oOOo0O0Ooo / OoooooooOO
      self . rloc . store_address ( o0oO00ooo0o . address )
      if 7 - 7: o0oOOo0O0Ooo % II111iiii
     Oo0oO = red ( o0oO00ooo0o . address , False )
     i1O0OO = o0oO00ooo0o . port
     lprint ( "    Use NAT translated RLOC {}:{} for {}" . format ( Oo0oO , i1O0OO , OoO0o0 ) )
     if 78 - 78: i11iIiiIii - I1ii11iIi11i + oO0o + II111iiii + OoooooooOO
     self . store_translated_rloc ( oOoOoo0O , i1O0OO )
     if 70 - 70: II111iiii
     if 68 - 68: OoooooooOO . iIii1I11I1II1 - Ii1I / OoO0O00 / oO0o
     if 14 - 14: OOooOOo + iIii1I11I1II1 - Ii1I % I11i % OoO0O00 - i11iIiiIii
     if 88 - 88: iII111i / I11i / I1ii11iIi11i + IiII * OoooooooOO . IiII
  self . geo = rloc_record . geo
  self . elp = rloc_record . elp
  self . json = rloc_record . json
  if 3 - 3: ooOoO0o - Oo0Ooo
  if 86 - 86: I1ii11iIi11i * I1Ii111 / o0oOOo0O0Ooo . OoO0O00
  if 14 - 14: I11i * IiII / iIii1I11I1II1
  if 88 - 88: OoOoOO00 % II111iiii . I1IiiI / oO0o * IiII / i11iIiiIii
  self . rle = rloc_record . rle
  if ( self . rle ) :
   for oOo0o in self . rle . rle_nodes :
    Iii1I1III1ii = oOo0o . rloc_name
    o0oO00ooo0o = lisp_get_nat_info ( oOo0o . address , Iii1I1III1ii )
    if ( o0oO00ooo0o == None ) : continue
    if 76 - 76: o0oOOo0O0Ooo
    i1O0OO = o0oO00ooo0o . port
    oO0o0oO0O = Iii1I1III1ii
    if ( oO0o0oO0O ) : oO0o0oO0O = blue ( Iii1I1III1ii , False )
    if 80 - 80: OOooOOo
    lprint ( ( "      Store translated encap-port {} for RLE-" + "node {}, rloc-name '{}'" ) . format ( i1O0OO ,
    # ooOoO0o
 oOo0o . address . print_address_no_iid ( ) , oO0o0oO0O ) )
    oOo0o . translated_port = i1O0OO
    if 2 - 2: OoOoOO00 / oO0o . I1ii11iIi11i % OoO0O00 - oO0o
    if 21 - 21: ooOoO0o . o0oOOo0O0Ooo . oO0o . i1IIi
    if 96 - 96: Ii1I % I11i * OoooooooOO . I1IiiI . iIii1I11I1II1
  self . priority = rloc_record . priority
  self . mpriority = rloc_record . mpriority
  self . weight = rloc_record . weight
  self . mweight = rloc_record . mweight
  if ( rloc_record . reach_bit and rloc_record . local_bit and
 rloc_record . probe_bit == False ) : self . state = LISP_RLOC_UP_STATE
  if 8 - 8: O0 + o0oOOo0O0Ooo / O0 - I1ii11iIi11i % I1ii11iIi11i
  if 55 - 55: OoooooooOO * OoooooooOO % I1Ii111 / Ii1I / ooOoO0o
  if 12 - 12: i11iIiiIii + Ii1I % iIii1I11I1II1 + I1Ii111
  if 12 - 12: Ii1I + I1Ii111 / O0 * II111iiii
  OoO00 = source . is_exact_match ( rloc_record . rloc ) if source != None else None
  if 100 - 100: oO0o * iII111i * OoooooooOO % I1IiiI / OoOoOO00 % i11iIiiIii
  if ( rloc_record . keys != None and OoO00 ) :
   iIIIi = rloc_record . keys [ 1 ]
   if ( iIIIi != None ) :
    OoOOoooO000 = rloc_record . rloc . print_address_no_iid ( ) + ":" + str ( i1O0OO )
    if 50 - 50: oO0o % Ii1I - II111iiii + i1IIi
    iIIIi . add_key_by_rloc ( OoOOoooO000 , True )
    lprint ( "    Store encap-keys for nonce 0x{}, RLOC {}" . format ( lisp_hex_string ( nonce ) , red ( OoOOoooO000 , False ) ) )
    if 74 - 74: ooOoO0o * i11iIiiIii + I1ii11iIi11i - ooOoO0o . OoOoOO00
    if 96 - 96: Ii1I + Oo0Ooo * I1Ii111 - I11i * I1Ii111
    if 32 - 32: I1IiiI / i1IIi / I1ii11iIi11i % i1IIi . ooOoO0o % I1ii11iIi11i
  return ( i1O0OO )
  if 97 - 97: OoO0O00 . OOooOOo % Ii1I + OoooooooOO * I1Ii111
  if 89 - 89: I11i
 def store_translated_rloc ( self , rloc , port ) :
  self . rloc . copy_address ( rloc )
  self . translated_rloc . copy_address ( rloc )
  self . translated_port = port
  if 91 - 91: OoooooooOO - IiII - Ii1I
  if 36 - 36: OOooOOo
 def is_rloc_translated ( self ) :
  return ( self . translated_rloc . is_null ( ) == False )
  if 76 - 76: OoO0O00 . i1IIi
  if 98 - 98: O0
 def rloc_exists ( self ) :
  if ( self . rloc . is_null ( ) == False ) : return ( True )
  if ( self . rle_name or self . geo_name or self . elp_name or self . json_name ) :
   return ( False )
   if 86 - 86: O0 * oO0o + Oo0Ooo / II111iiii + i1IIi
  return ( True )
  if 12 - 12: I1IiiI + OOooOOo / Ii1I % i11iIiiIii - I1Ii111 % I11i
  if 49 - 49: I11i * i1IIi - iII111i
 def is_rtr ( self ) :
  return ( ( self . priority == 254 and self . mpriority == 255 and self . weight == 0 and self . mweight == 0 ) )
  if 98 - 98: iIii1I11I1II1 - I11i % i11iIiiIii * I1IiiI / OoOoOO00 * ooOoO0o
  if 78 - 78: i11iIiiIii % oO0o % Ii1I / I1Ii111 / I1Ii111
  if 20 - 20: iII111i / I11i / iIii1I11I1II1
 def print_state_change ( self , new_state ) :
  Oo0OO00O0O0 = self . print_state ( )
  i11ii111i1ii = "{} -> {}" . format ( Oo0OO00O0O0 , new_state )
  if ( new_state == "up" and self . unreach_state ( ) ) :
   i11ii111i1ii = bold ( i11ii111i1ii , False )
   if 57 - 57: iIii1I11I1II1 + I1ii11iIi11i / OoOoOO00 * I1ii11iIi11i . i1IIi * iII111i
  return ( i11ii111i1ii )
  if 67 - 67: IiII + i11iIiiIii . II111iiii / OoOoOO00 + OoooooooOO + i11iIiiIii
  if 23 - 23: Oo0Ooo
 def print_rloc_probe_rtt ( self ) :
  if ( self . rloc_probe_rtt == - 1 ) : return ( "none" )
  return ( self . rloc_probe_rtt )
  if 7 - 7: Oo0Ooo / oO0o . I1Ii111 % I11i
  if 85 - 85: II111iiii / o0oOOo0O0Ooo . iIii1I11I1II1 . OoooooooOO / Ii1I
 def print_recent_rloc_probe_rtts ( self ) :
  iiiIiII = str ( self . recent_rloc_probe_rtts )
  iiiIiII = iiiIiII . replace ( "-1" , "?" )
  return ( iiiIiII )
  if 31 - 31: OoooooooOO . I1Ii111 % OoooooooOO * iII111i % OOooOOo . iII111i
  if 17 - 17: I1Ii111 % i1IIi % I11i * O0 / Oo0Ooo
 def compute_rloc_probe_rtt ( self ) :
  i11iI11ii = self . rloc_probe_rtt
  self . rloc_probe_rtt = - 1
  if ( self . last_rloc_probe_reply == None ) : return
  if ( self . last_rloc_probe == None ) : return
  self . rloc_probe_rtt = self . last_rloc_probe_reply - self . last_rloc_probe
  self . rloc_probe_rtt = round ( self . rloc_probe_rtt , 3 )
  oO0 = self . recent_rloc_probe_rtts
  self . recent_rloc_probe_rtts = [ i11iI11ii ] + oO0 [ 0 : - 1 ]
  if 80 - 80: OoOoOO00 + o0oOOo0O0Ooo - II111iiii
  if 3 - 3: ooOoO0o * I1Ii111
 def print_rloc_probe_hops ( self ) :
  return ( self . rloc_probe_hops )
  if 34 - 34: Ii1I / Oo0Ooo . II111iiii - ooOoO0o - I1ii11iIi11i % OoOoOO00
  if 43 - 43: Ii1I * oO0o
 def print_recent_rloc_probe_hops ( self ) :
  Oo0o0O0 = str ( self . recent_rloc_probe_hops )
  return ( Oo0o0O0 )
  if 99 - 99: i11iIiiIii . iII111i . i1IIi + ooOoO0o * ooOoO0o - I11i
  if 21 - 21: o0oOOo0O0Ooo . i11iIiiIii % OoooooooOO * O0
 def store_rloc_probe_hops ( self , to_hops , from_ttl ) :
  if ( to_hops == 0 ) :
   to_hops = "?"
  elif ( to_hops < LISP_RLOC_PROBE_TTL / 2 ) :
   to_hops = "!"
  else :
   to_hops = str ( LISP_RLOC_PROBE_TTL - to_hops )
   if 52 - 52: OOooOOo / ooOoO0o . II111iiii / Oo0Ooo
  if ( from_ttl < LISP_RLOC_PROBE_TTL / 2 ) :
   o000O000o000O = "!"
  else :
   o000O000o000O = str ( LISP_RLOC_PROBE_TTL - from_ttl )
   if 82 - 82: I1Ii111 . OoO0O00 - Ii1I
   if 75 - 75: i11iIiiIii
  i11iI11ii = self . rloc_probe_hops
  self . rloc_probe_hops = to_hops + "/" + o000O000o000O
  oO0 = self . recent_rloc_probe_hops
  self . recent_rloc_probe_hops = [ i11iI11ii ] + oO0 [ 0 : - 1 ]
  if 78 - 78: OoOoOO00
  if 61 - 61: OoOoOO00 . I1ii11iIi11i . I11i / IiII
 def process_rloc_probe_reply ( self , nonce , eid , group , hop_count , ttl ) :
  oOoOoo0O = self
  while ( True ) :
   if ( oOoOoo0O . last_rloc_probe_nonce == nonce ) : break
   oOoOoo0O = oOoOoo0O . next_rloc
   if ( oOoOoo0O == None ) :
    lprint ( "    No matching nonce state found for nonce 0x{}" . format ( lisp_hex_string ( nonce ) ) )
    if 84 - 84: OoOoOO00 . IiII
    return
    if 50 - 50: O0
    if 51 - 51: I1Ii111
    if 95 - 95: Ii1I / Ii1I * OoO0O00 . OoooooooOO . OoooooooOO * I11i
  oOoOoo0O . last_rloc_probe_reply = lisp_get_timestamp ( )
  oOoOoo0O . compute_rloc_probe_rtt ( )
  OoO000oOo = oOoOoo0O . print_state_change ( "up" )
  if ( oOoOoo0O . state != LISP_RLOC_UP_STATE ) :
   lisp_update_rtr_updown ( oOoOoo0O . rloc , True )
   oOoOoo0O . state = LISP_RLOC_UP_STATE
   oOoOoo0O . last_state_change = lisp_get_timestamp ( )
   oOooO0Oo0Oo0 = lisp_map_cache . lookup_cache ( eid , True )
   if ( oOooO0Oo0Oo0 ) : lisp_write_ipc_map_cache ( True , oOooO0Oo0Oo0 )
   if 55 - 55: i11iIiiIii - IiII * OOooOOo + II111iiii . I1ii11iIi11i / O0
   if 16 - 16: II111iiii . Oo0Ooo * I1Ii111 + o0oOOo0O0Ooo - i11iIiiIii
  oOoOoo0O . store_rloc_probe_hops ( hop_count , ttl )
  if 98 - 98: II111iiii - i1IIi - ooOoO0o
  o0ooOOoO0O = bold ( "RLOC-probe reply" , False )
  OoOOoooO000 = oOoOoo0O . rloc . print_address_no_iid ( )
  i1I1Ii = bold ( str ( oOoOoo0O . print_rloc_probe_rtt ( ) ) , False )
  oo000o = ":{}" . format ( self . translated_port ) if self . translated_port != 0 else ""
  if 66 - 66: OoOoOO00 % ooOoO0o - II111iiii . oO0o / i11iIiiIii
  IiIIiI11I = ""
  if ( oOoOoo0O . rloc_next_hop != None ) :
   i1i11ii1Ii , oOoOoOo0O = oOoOoo0O . rloc_next_hop
   IiIIiI11I = ", nh {}({})" . format ( oOoOoOo0O , i1i11ii1Ii )
   if 76 - 76: I1ii11iIi11i % II111iiii / I1Ii111
   if 10 - 10: OoooooooOO + iII111i + OoOoOO00 - ooOoO0o . Ii1I + OOooOOo
  I1i11II = green ( lisp_print_eid_tuple ( eid , group ) , False )
  lprint ( ( "    Received {} from {}{} for {}, {}, rtt {}{}, " + "to-ttl/from-ttl {}" ) . format ( o0ooOOoO0O , red ( OoOOoooO000 , False ) , oo000o , I1i11II ,
  # OoooooooOO . oO0o
 OoO000oOo , i1I1Ii , IiIIiI11I , str ( hop_count ) + "/" + str ( ttl ) ) )
  if 90 - 90: IiII - OoOoOO00 / IiII + I1ii11iIi11i % Oo0Ooo
  if ( oOoOoo0O . rloc_next_hop == None ) : return
  if 32 - 32: OOooOOo
  if 46 - 46: II111iiii . OoO0O00
  if 97 - 97: oO0o
  if 45 - 45: i11iIiiIii / IiII + OoO0O00
  oOoOoo0O = None
  o0Oo = None
  while ( True ) :
   oOoOoo0O = self if oOoOoo0O == None else oOoOoo0O . next_rloc
   if ( oOoOoo0O == None ) : break
   if ( oOoOoo0O . up_state ( ) == False ) : continue
   if ( oOoOoo0O . rloc_probe_rtt == - 1 ) : continue
   if 61 - 61: i11iIiiIii * I11i / ooOoO0o / iIii1I11I1II1
   if ( o0Oo == None ) : o0Oo = oOoOoo0O
   if ( oOoOoo0O . rloc_probe_rtt < o0Oo . rloc_probe_rtt ) : o0Oo = oOoOoo0O
   if 40 - 40: O0 / Ii1I - i11iIiiIii / I11i
   if 60 - 60: Oo0Ooo - iII111i . II111iiii % ooOoO0o / OoooooooOO / iIii1I11I1II1
  if ( o0Oo != None ) :
   i1i11ii1Ii , oOoOoOo0O = o0Oo . rloc_next_hop
   IiIIiI11I = bold ( "nh {}({})" . format ( oOoOoOo0O , i1i11ii1Ii ) , False )
   lprint ( "    Install host-route via best {}" . format ( IiIIiI11I ) )
   lisp_install_host_route ( OoOOoooO000 , None , False )
   lisp_install_host_route ( OoOOoooO000 , oOoOoOo0O , True )
   if 23 - 23: I11i + iIii1I11I1II1
   if 60 - 60: O0 * I1IiiI + o0oOOo0O0Ooo * OoO0O00 + o0oOOo0O0Ooo / i11iIiiIii
   if 54 - 54: i11iIiiIii . iII111i * i1IIi
 def add_to_rloc_probe_list ( self , eid , group ) :
  OoOOoooO000 = self . rloc . print_address_no_iid ( )
  i1O0OO = self . translated_port
  if ( i1O0OO != 0 ) : OoOOoooO000 += ":" + str ( i1O0OO )
  if 68 - 68: Oo0Ooo
  if ( lisp_rloc_probe_list . has_key ( OoOOoooO000 ) == False ) :
   lisp_rloc_probe_list [ OoOOoooO000 ] = [ ]
   if 20 - 20: IiII + i11iIiiIii * OOooOOo
   if 27 - 27: O0 * OoO0O00 * I1ii11iIi11i
  if ( group . is_null ( ) ) : group . instance_id = 0
  for iI111I1 , I1i11II , OooooOOOO in lisp_rloc_probe_list [ OoOOoooO000 ] :
   if ( I1i11II . is_exact_match ( eid ) and OooooOOOO . is_exact_match ( group ) ) :
    if ( iI111I1 == self ) :
     if ( lisp_rloc_probe_list [ OoOOoooO000 ] == [ ] ) :
      lisp_rloc_probe_list . pop ( OoOOoooO000 )
      if 40 - 40: O0 + oO0o - ooOoO0o + I1IiiI - IiII
     return
     if 60 - 60: I1Ii111 * OoO0O00 * oO0o + oO0o
    lisp_rloc_probe_list [ OoOOoooO000 ] . remove ( [ iI111I1 , I1i11II , OooooOOOO ] )
    break
    if 34 - 34: o0oOOo0O0Ooo
    if 76 - 76: oO0o + OoooooooOO % OoOoOO00 / OoOoOO00
  lisp_rloc_probe_list [ OoOOoooO000 ] . append ( [ self , eid , group ] )
  if 51 - 51: II111iiii / OoOoOO00
  if 69 - 69: i11iIiiIii
  if 77 - 77: I1ii11iIi11i % OoooooooOO - Oo0Ooo - Ii1I + I11i
  if 93 - 93: I1IiiI % O0 * OoO0O00 % OoOoOO00 . I1Ii111 * I1IiiI
  if 95 - 95: IiII + o0oOOo0O0Ooo - o0oOOo0O0Ooo
  oOoOoo0O = lisp_rloc_probe_list [ OoOOoooO000 ] [ 0 ] [ 0 ]
  if ( oOoOoo0O . state == LISP_RLOC_UNREACH_STATE ) :
   self . state = LISP_RLOC_UNREACH_STATE
   self . last_state_change = lisp_get_timestamp ( )
   if 83 - 83: ooOoO0o
   if 59 - 59: I1ii11iIi11i
   if 26 - 26: I11i . Ii1I
 def delete_from_rloc_probe_list ( self , eid , group ) :
  OoOOoooO000 = self . rloc . print_address_no_iid ( )
  i1O0OO = self . translated_port
  if ( i1O0OO != 0 ) : OoOOoooO000 += ":" + str ( i1O0OO )
  if ( lisp_rloc_probe_list . has_key ( OoOOoooO000 ) == False ) : return
  if 94 - 94: ooOoO0o . I1IiiI + IiII % I1IiiI / o0oOOo0O0Ooo % o0oOOo0O0Ooo
  IiIIiIi11 = [ ]
  for oOoO in lisp_rloc_probe_list [ OoOOoooO000 ] :
   if ( oOoO [ 0 ] != self ) : continue
   if ( oOoO [ 1 ] . is_exact_match ( eid ) == False ) : continue
   if ( oOoO [ 2 ] . is_exact_match ( group ) == False ) : continue
   IiIIiIi11 = oOoO
   break
   if 18 - 18: I1Ii111
  if ( IiIIiIi11 == [ ] ) : return
  if 40 - 40: OoOoOO00 / OOooOOo + O0
  try :
   lisp_rloc_probe_list [ OoOOoooO000 ] . remove ( IiIIiIi11 )
   if ( lisp_rloc_probe_list [ OoOOoooO000 ] == [ ] ) :
    lisp_rloc_probe_list . pop ( OoOOoooO000 )
    if 57 - 57: iII111i
  except :
   return
   if 94 - 94: i11iIiiIii
   if 90 - 90: iII111i + i11iIiiIii + iII111i % I1IiiI % oO0o
   if 71 - 71: ooOoO0o + OOooOOo * I1IiiI % I11i . I1Ii111 % OoooooooOO
 def print_rloc_probe_state ( self , trailing_linefeed ) :
  ooO000O = ""
  oOoOoo0O = self
  while ( True ) :
   i1io00oO0O = oOoOoo0O . last_rloc_probe
   if ( i1io00oO0O == None ) : i1io00oO0O = 0
   iii = oOoOoo0O . last_rloc_probe_reply
   if ( iii == None ) : iii = 0
   i1I1Ii = oOoOoo0O . print_rloc_probe_rtt ( )
   i1I1iIi1IiI = space ( 4 )
   if 76 - 76: iIii1I11I1II1 - OOooOOo
   if ( oOoOoo0O . rloc_next_hop == None ) :
    ooO000O += "RLOC-Probing:\n"
   else :
    i1i11ii1Ii , oOoOoOo0O = oOoOoo0O . rloc_next_hop
    ooO000O += "RLOC-Probing for nh {}({}):\n" . format ( oOoOoOo0O , i1i11ii1Ii )
    if 77 - 77: iIii1I11I1II1 % I1Ii111 + II111iiii
    if 40 - 40: I1ii11iIi11i / I1ii11iIi11i + I1IiiI + OoOoOO00
   ooO000O += ( "{}RLOC-probe request sent: {}\n{}RLOC-probe reply " + "received: {}, rtt {}" ) . format ( i1I1iIi1IiI , lisp_print_elapsed ( i1io00oO0O ) ,
   # O0 * i1IIi . I1IiiI . II111iiii % OoOoOO00
 i1I1iIi1IiI , lisp_print_elapsed ( iii ) , i1I1Ii )
   if 18 - 18: oO0o / ooOoO0o * I1IiiI / Oo0Ooo / I11i - OOooOOo
   if ( trailing_linefeed ) : ooO000O += "\n"
   if 53 - 53: ooOoO0o / OoOoOO00 - OoooooooOO * oO0o
   oOoOoo0O = oOoOoo0O . next_rloc
   if ( oOoOoo0O == None ) : break
   ooO000O += "\n"
   if 45 - 45: o0oOOo0O0Ooo . I1Ii111 % Ii1I
  return ( ooO000O )
  if 42 - 42: Oo0Ooo + i11iIiiIii - OOooOOo . I1ii11iIi11i % I1Ii111 . I1ii11iIi11i
  if 59 - 59: OoooooooOO
 def get_encap_keys ( self ) :
  i1O0OO = "4341" if self . translated_port == 0 else str ( self . translated_port )
  if 91 - 91: i11iIiiIii / Oo0Ooo % I11i / O0
  OoOOoooO000 = self . rloc . print_address_no_iid ( ) + ":" + i1O0OO
  if 80 - 80: II111iiii / I1ii11iIi11i % I1IiiI . Ii1I
  try :
   O000OO = lisp_crypto_keys_by_rloc_encap [ OoOOoooO000 ]
   if ( O000OO [ 1 ] ) : return ( O000OO [ 1 ] . encrypt_key , O000OO [ 1 ] . icv_key )
   return ( None , None )
  except :
   return ( None , None )
   if 8 - 8: oO0o
   if 21 - 21: oO0o + iII111i . i11iIiiIii - II111iiii
   if 14 - 14: I1Ii111
 def rloc_recent_rekey ( self ) :
  i1O0OO = "4341" if self . translated_port == 0 else str ( self . translated_port )
  if 81 - 81: II111iiii
  OoOOoooO000 = self . rloc . print_address_no_iid ( ) + ":" + i1O0OO
  if 55 - 55: O0 + o0oOOo0O0Ooo * I1IiiI - OoooooooOO
  try :
   iIIIi = lisp_crypto_keys_by_rloc_encap [ OoOOoooO000 ] [ 1 ]
   if ( iIIIi == None ) : return ( False )
   if ( iIIIi . last_rekey == None ) : return ( True )
   return ( time . time ( ) - iIIIi . last_rekey < 1 )
  except :
   return ( False )
   if 68 - 68: I11i + Oo0Ooo
   if 15 - 15: O0
   if 75 - 75: iII111i / OoOoOO00
   if 2 - 2: i1IIi + oO0o % iII111i % I1ii11iIi11i + ooOoO0o . iII111i
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
  if 26 - 26: I11i + o0oOOo0O0Ooo + Ii1I % I11i
  if 95 - 95: IiII - O0 * oO0o * O0
 def print_mapping ( self , eid_indent , rloc_indent ) :
  III11I1 = lisp_print_elapsed ( self . uptime )
  ooOoO00 = "" if self . group . is_null ( ) else ", group {}" . format ( self . group . print_prefix ( ) )
  if 47 - 47: I1IiiI
  lprint ( "{}eid {}{}, uptime {}, {} rlocs:" . format ( eid_indent ,
 green ( self . eid . print_prefix ( ) , False ) , ooOoO00 , III11I1 ,
 len ( self . rloc_set ) ) )
  for oOoOoo0O in self . rloc_set : oOoOoo0O . print_rloc ( rloc_indent )
  if 20 - 20: I1Ii111
  if 40 - 40: OoooooooOO / o0oOOo0O0Ooo + OoOoOO00
 def print_eid_tuple ( self ) :
  return ( lisp_print_eid_tuple ( self . eid , self . group ) )
  if 73 - 73: OOooOOo / Oo0Ooo
  if 80 - 80: OoO0O00 + I1IiiI % i1IIi / I11i % i1IIi * i11iIiiIii
 def print_ttl ( self ) :
  ooOOooooo0Oo = self . map_cache_ttl
  if ( ooOOooooo0Oo == None ) : return ( "forever" )
  if 27 - 27: OoOoOO00 / I1Ii111 * O0 / I1IiiI - IiII / o0oOOo0O0Ooo
  if ( ooOOooooo0Oo >= 3600 ) :
   if ( ( ooOOooooo0Oo % 3600 ) == 0 ) :
    ooOOooooo0Oo = str ( ooOOooooo0Oo / 3600 ) + " hours"
   else :
    ooOOooooo0Oo = str ( ooOOooooo0Oo * 60 ) + " mins"
    if 70 - 70: I1ii11iIi11i
  elif ( ooOOooooo0Oo >= 60 ) :
   if ( ( ooOOooooo0Oo % 60 ) == 0 ) :
    ooOOooooo0Oo = str ( ooOOooooo0Oo / 60 ) + " mins"
   else :
    ooOOooooo0Oo = str ( ooOOooooo0Oo ) + " secs"
    if 11 - 11: I1Ii111
  else :
   ooOOooooo0Oo = str ( ooOOooooo0Oo ) + " secs"
   if 70 - 70: Ii1I
  return ( ooOOooooo0Oo )
  if 22 - 22: Ii1I
  if 59 - 59: I1ii11iIi11i
 def has_ttl_elapsed ( self ) :
  if ( self . map_cache_ttl == None ) : return ( False )
  ooooOoO0O = time . time ( ) - self . last_refresh_time
  return ( ooooOoO0O >= self . map_cache_ttl )
  if 90 - 90: OOooOOo / iII111i
  if 70 - 70: o0oOOo0O0Ooo
 def is_active ( self ) :
  if ( self . stats . last_increment == None ) : return ( False )
  ooooOoO0O = time . time ( ) - self . stats . last_increment
  return ( ooooOoO0O <= 60 )
  if 49 - 49: OOooOOo - I1IiiI + OoooooooOO % iII111i + o0oOOo0O0Ooo + OoOoOO00
  if 37 - 37: II111iiii % I1ii11iIi11i * OoOoOO00
 def match_eid_tuple ( self , db ) :
  if ( self . eid . is_exact_match ( db . eid ) == False ) : return ( False )
  if ( self . group . is_exact_match ( db . group ) == False ) : return ( False )
  return ( True )
  if 35 - 35: i1IIi
  if 81 - 81: OoO0O00
 def sort_rloc_set ( self ) :
  self . rloc_set . sort ( key = operator . attrgetter ( 'rloc.address' ) )
  if 45 - 45: OoooooooOO . O0 * oO0o + IiII
  if 18 - 18: II111iiii . O0 - I11i / I11i
 def delete_rlocs_from_rloc_probe_list ( self ) :
  for oOoOoo0O in self . best_rloc_set :
   oOoOoo0O . delete_from_rloc_probe_list ( self . eid , self . group )
   if 71 - 71: OoOoOO00 + iIii1I11I1II1 - II111iiii / i1IIi
   if 39 - 39: Ii1I + I1Ii111 * Oo0Ooo + OoOoOO00 / I1Ii111 - ooOoO0o
   if 66 - 66: I11i * OoO0O00
 def build_best_rloc_set ( self ) :
  o0O = self . best_rloc_set
  self . best_rloc_set = [ ]
  if ( self . rloc_set == None ) : return
  if 36 - 36: Oo0Ooo - oO0o * I1IiiI * I1ii11iIi11i - oO0o + oO0o
  if 72 - 72: ooOoO0o * I1Ii111 * OOooOOo % I1IiiI * IiII
  if 95 - 95: OoO0O00 % iIii1I11I1II1 + I1IiiI . I1IiiI
  if 8 - 8: Ii1I + O0 + II111iiii + o0oOOo0O0Ooo - OoO0O00 - Ii1I
  OOOi1I1111I = 256
  for oOoOoo0O in self . rloc_set :
   if ( oOoOoo0O . up_state ( ) ) : OOOi1I1111I = min ( oOoOoo0O . priority , OOOi1I1111I )
   if 65 - 65: oO0o + O0 / i11iIiiIii
   if 64 - 64: OoO0O00 % OoOoOO00 % I1IiiI - Ii1I / IiII * Ii1I
   if 74 - 74: IiII - O0 % OOooOOo % OoooooooOO - I11i
   if 4 - 4: i1IIi + OoOoOO00 + iIii1I11I1II1 - i1IIi * i11iIiiIii
   if 99 - 99: I1ii11iIi11i - O0 % II111iiii + ooOoO0o % OoO0O00 * Ii1I
   if 8 - 8: OOooOOo
   if 85 - 85: O0 % OOooOOo . Ii1I
   if 74 - 74: I1ii11iIi11i - I1Ii111 + i11iIiiIii / I1Ii111 / OoooooooOO + o0oOOo0O0Ooo
   if 23 - 23: Oo0Ooo
   if 91 - 91: I1Ii111
  for oOoOoo0O in self . rloc_set :
   if ( oOoOoo0O . priority <= OOOi1I1111I ) :
    if ( oOoOoo0O . unreach_state ( ) and oOoOoo0O . last_rloc_probe == None ) :
     oOoOoo0O . last_rloc_probe = lisp_get_timestamp ( )
     if 59 - 59: i1IIi % OOooOOo
    self . best_rloc_set . append ( oOoOoo0O )
    if 81 - 81: i11iIiiIii / OoO0O00 * OoOoOO00 % iII111i - iIii1I11I1II1 + I1ii11iIi11i
    if 20 - 20: O0 . I1Ii111 * Ii1I * II111iiii
    if 66 - 66: Ii1I % OoO0O00 % II111iiii - OOooOOo * o0oOOo0O0Ooo
    if 33 - 33: OoooooooOO / I11i
    if 98 - 98: I1ii11iIi11i . Ii1I . iIii1I11I1II1 * I1ii11iIi11i / Ii1I
    if 74 - 74: Oo0Ooo * I1Ii111
    if 72 - 72: OoOoOO00 + O0 - IiII * ooOoO0o
    if 20 - 20: II111iiii % OoOoOO00 * i11iIiiIii
  for oOoOoo0O in o0O :
   if ( oOoOoo0O . priority < OOOi1I1111I ) : continue
   oOoOoo0O . delete_from_rloc_probe_list ( self . eid , self . group )
   if 68 - 68: IiII / ooOoO0o
  for oOoOoo0O in self . best_rloc_set :
   if ( oOoOoo0O . rloc . is_null ( ) ) : continue
   oOoOoo0O . add_to_rloc_probe_list ( self . eid , self . group )
   if 100 - 100: ooOoO0o / I1IiiI
   if 69 - 69: ooOoO0o + OoO0O00 * o0oOOo0O0Ooo - ooOoO0o
   if 66 - 66: OoooooooOO / iII111i / I1IiiI % ooOoO0o / OoO0O00 + OOooOOo
 def select_rloc ( self , lisp_packet , ipc_socket ) :
  I1IiO00Ooo0ooo0 = lisp_packet . packet
  oo0oiI1IIi11 = lisp_packet . inner_version
  I111 = len ( self . best_rloc_set )
  if ( I111 is 0 ) :
   self . stats . increment ( len ( I1IiO00Ooo0ooo0 ) )
   return ( [ None , None , None , self . action , None ] )
   if 89 - 89: I1Ii111 * I1IiiI . i1IIi - iIii1I11I1II1 * I1Ii111
   if 5 - 5: OoOoOO00 % i1IIi
  IIiiiIIIIIi1 = 4 if lisp_load_split_pings else 0
  OoOoo00Oo0OoO = lisp_packet . hash_ports ( )
  if ( oo0oiI1IIi11 == 4 ) :
   for oO in range ( 8 + IIiiiIIIIIi1 ) :
    OoOoo00Oo0OoO = OoOoo00Oo0OoO ^ struct . unpack ( "B" , I1IiO00Ooo0ooo0 [ oO + 12 ] ) [ 0 ]
    if 41 - 41: oO0o + O0 / I1ii11iIi11i
  elif ( oo0oiI1IIi11 == 6 ) :
   for oO in range ( 0 , 32 + IIiiiIIIIIi1 , 4 ) :
    OoOoo00Oo0OoO = OoOoo00Oo0OoO ^ struct . unpack ( "I" , I1IiO00Ooo0ooo0 [ oO + 8 : oO + 12 ] ) [ 0 ]
    if 55 - 55: iIii1I11I1II1 * oO0o / iII111i / i1IIi % Oo0Ooo . OoOoOO00
   OoOoo00Oo0OoO = ( OoOoo00Oo0OoO >> 16 ) + ( OoOoo00Oo0OoO & 0xffff )
   OoOoo00Oo0OoO = ( OoOoo00Oo0OoO >> 8 ) + ( OoOoo00Oo0OoO & 0xff )
  else :
   for oO in range ( 0 , 12 + IIiiiIIIIIi1 , 4 ) :
    OoOoo00Oo0OoO = OoOoo00Oo0OoO ^ struct . unpack ( "I" , I1IiO00Ooo0ooo0 [ oO : oO + 4 ] ) [ 0 ]
    if 50 - 50: IiII / o0oOOo0O0Ooo
    if 9 - 9: Oo0Ooo - OoO0O00 + iII111i / OoooooooOO
    if 52 - 52: O0
  if ( lisp_data_plane_logging ) :
   IiIIiI = [ ]
   for iI111I1 in self . best_rloc_set :
    if ( iI111I1 . rloc . is_null ( ) ) : continue
    IiIIiI . append ( [ iI111I1 . rloc . print_address_no_iid ( ) , iI111I1 . print_state ( ) ] )
    if 99 - 99: I1Ii111 . II111iiii * IiII . II111iiii + OoOoOO00
   dprint ( "Packet hash {}, index {}, best-rloc-list: {}" . format ( hex ( OoOoo00Oo0OoO ) , OoOoo00Oo0OoO % I111 , red ( str ( IiIIiI ) , False ) ) )
   if 36 - 36: OoO0O00 * iII111i % ooOoO0o % OoOoOO00 * I1IiiI % i1IIi
   if 25 - 25: iII111i + I1IiiI / OoO0O00 - I1IiiI / OoooooooOO - ooOoO0o
   if 22 - 22: iII111i
   if 30 - 30: OoO0O00 + I11i + Oo0Ooo
   if 77 - 77: II111iiii
   if 92 - 92: I1Ii111 / I1IiiI / I1ii11iIi11i + I11i + Ii1I
  oOoOoo0O = self . best_rloc_set [ OoOoo00Oo0OoO % I111 ]
  if 51 - 51: OOooOOo
  if 85 - 85: II111iiii
  if 60 - 60: Ii1I * OOooOOo - o0oOOo0O0Ooo - Ii1I / Oo0Ooo . OOooOOo
  if 43 - 43: II111iiii * o0oOOo0O0Ooo % o0oOOo0O0Ooo + iIii1I11I1II1 + OoOoOO00
  if 54 - 54: II111iiii + OOooOOo * Oo0Ooo * I1Ii111 - o0oOOo0O0Ooo % Ii1I
  i1II11iI1i = lisp_get_echo_nonce ( oOoOoo0O . rloc , None )
  if ( i1II11iI1i ) :
   i1II11iI1i . change_state ( oOoOoo0O )
   if ( oOoOoo0O . no_echoed_nonce_state ( ) ) :
    i1II11iI1i . request_nonce_sent = None
    if 69 - 69: I11i + OoOoOO00 - i11iIiiIii * O0 % O0
    if 81 - 81: I11i - o0oOOo0O0Ooo % Ii1I / I1Ii111 * II111iiii
    if 40 - 40: OoO0O00 . i11iIiiIii
    if 36 - 36: o0oOOo0O0Ooo * iII111i / I1ii11iIi11i % i1IIi % I1ii11iIi11i + i11iIiiIii
    if 24 - 24: I1Ii111 / ooOoO0o - i11iIiiIii
    if 32 - 32: II111iiii * Ii1I . ooOoO0o * Oo0Ooo - I1ii11iIi11i % I11i
  if ( oOoOoo0O . up_state ( ) == False ) :
   o0oOiI1i1iI1 = OoOoo00Oo0OoO % I111
   OOOoO000 = ( o0oOiI1i1iI1 + 1 ) % I111
   while ( OOOoO000 != o0oOiI1i1iI1 ) :
    oOoOoo0O = self . best_rloc_set [ OOOoO000 ]
    if ( oOoOoo0O . up_state ( ) ) : break
    OOOoO000 = ( OOOoO000 + 1 ) % I111
    if 45 - 45: i1IIi
   if ( OOOoO000 == o0oOiI1i1iI1 ) :
    self . build_best_rloc_set ( )
    return ( [ None , None , None , None , None ] )
    if 28 - 28: iII111i
    if 28 - 28: i1IIi - iII111i + o0oOOo0O0Ooo / Oo0Ooo * oO0o
    if 8 - 8: ooOoO0o + OOooOOo * ooOoO0o / i1IIi . I1ii11iIi11i
    if 4 - 4: Ii1I - Oo0Ooo . i1IIi + iIii1I11I1II1
    if 28 - 28: O0 / ooOoO0o / IiII - I11i + IiII + OoO0O00
    if 84 - 84: Oo0Ooo + OoOoOO00 / iII111i . I1ii11iIi11i
  oOoOoo0O . stats . increment ( len ( I1IiO00Ooo0ooo0 ) )
  if 26 - 26: Oo0Ooo
  if 61 - 61: Ii1I * oO0o * i11iIiiIii + OoO0O00
  if 43 - 43: OoO0O00 * OoO0O00 * oO0o
  if 24 - 24: oO0o
  if ( oOoOoo0O . rle_name and oOoOoo0O . rle == None ) :
   if ( lisp_rle_list . has_key ( oOoOoo0O . rle_name ) ) :
    oOoOoo0O . rle = lisp_rle_list [ oOoOoo0O . rle_name ]
    if 77 - 77: i11iIiiIii - I1Ii111 - I1ii11iIi11i * Oo0Ooo / i11iIiiIii
    if 79 - 79: Oo0Ooo % Oo0Ooo . oO0o + ooOoO0o * iII111i * I11i
  if ( oOoOoo0O . rle ) : return ( [ None , None , None , None , oOoOoo0O . rle ] )
  if 87 - 87: o0oOOo0O0Ooo + OoOoOO00 % o0oOOo0O0Ooo + I1IiiI
  if 89 - 89: II111iiii
  if 41 - 41: iIii1I11I1II1
  if 26 - 26: Oo0Ooo / i1IIi + Oo0Ooo
  if ( oOoOoo0O . elp and oOoOoo0O . elp . use_elp_node ) :
   return ( [ oOoOoo0O . elp . use_elp_node . address , None , None , None , None ] )
   if 76 - 76: I1ii11iIi11i * i1IIi % oO0o
   if 80 - 80: i1IIi * II111iiii . O0 % I1ii11iIi11i / ooOoO0o
   if 58 - 58: I1IiiI * I1ii11iIi11i - i1IIi % I1Ii111 % O0
   if 24 - 24: I11i + I11i % I11i
   if 63 - 63: i11iIiiIii + iIii1I11I1II1 / oO0o % IiII - O0
  i111I = None if ( oOoOoo0O . rloc . is_null ( ) ) else oOoOoo0O . rloc
  i1O0OO = oOoOoo0O . translated_port
  Ooo0oOo0o0oOo = self . action if ( i111I == None ) else None
  if 89 - 89: I11i
  if 48 - 48: I1Ii111 - O0
  if 23 - 23: iIii1I11I1II1
  if 88 - 88: I1IiiI + iII111i / Ii1I
  if 57 - 57: o0oOOo0O0Ooo
  o0oo000 = None
  if ( i1II11iI1i and i1II11iI1i . request_nonce_timeout ( ) == False ) :
   o0oo000 = i1II11iI1i . get_request_or_echo_nonce ( ipc_socket , i111I )
   if 69 - 69: i1IIi / i1IIi / OoOoOO00 + ooOoO0o % I1Ii111
   if 41 - 41: II111iiii * OOooOOo
   if 8 - 8: I1Ii111 + O0
   if 67 - 67: iIii1I11I1II1 . O0
   if 40 - 40: OOooOOo - ooOoO0o . OoooooooOO % O0 * I11i - I1ii11iIi11i
  return ( [ i111I , i1O0OO , o0oo000 , Ooo0oOo0o0oOo , None ] )
  if 92 - 92: ooOoO0o % oO0o / i11iIiiIii
  if 91 - 91: OOooOOo
 def do_rloc_sets_match ( self , rloc_address_set ) :
  if ( len ( self . rloc_set ) != len ( rloc_address_set ) ) : return ( False )
  if 60 - 60: i11iIiiIii . iIii1I11I1II1 . OOooOOo % IiII
  if 68 - 68: I11i / iII111i - IiII . iIii1I11I1II1 / o0oOOo0O0Ooo
  if 54 - 54: II111iiii * I1IiiI
  if 49 - 49: I1ii11iIi11i
  if 31 - 31: o0oOOo0O0Ooo - OoOoOO00 + I1ii11iIi11i . oO0o - O0
  for iIIiIiiI in self . rloc_set :
   for oOoOoo0O in rloc_address_set :
    if ( oOoOoo0O . is_exact_match ( iIIiIiiI . rloc ) == False ) : continue
    oOoOoo0O = None
    break
    if 61 - 61: I1ii11iIi11i * II111iiii . i1IIi
   if ( oOoOoo0O == rloc_address_set [ - 1 ] ) : return ( False )
   if 60 - 60: OoooooooOO % ooOoO0o * i11iIiiIii * OoooooooOO % IiII
  return ( True )
  if 15 - 15: oO0o
  if 40 - 40: I1Ii111
 def get_rloc ( self , rloc ) :
  for iIIiIiiI in self . rloc_set :
   iI111I1 = iIIiIiiI . rloc
   if ( rloc . is_exact_match ( iI111I1 ) ) : return ( iIIiIiiI )
   if 77 - 77: II111iiii - o0oOOo0O0Ooo . Ii1I
  return ( None )
  if 47 - 47: o0oOOo0O0Ooo % OOooOOo + I1Ii111
  if 64 - 64: ooOoO0o / IiII . I1IiiI
 def get_rloc_by_interface ( self , interface ) :
  for iIIiIiiI in self . rloc_set :
   if ( iIIiIiiI . interface == interface ) : return ( iIIiIiiI )
   if 77 - 77: o0oOOo0O0Ooo % I1Ii111 . OOooOOo
  return ( None )
  if 90 - 90: I11i
  if 53 - 53: I1ii11iIi11i + i11iIiiIii / iIii1I11I1II1 + OoooooooOO + IiII * I1IiiI
 def add_db ( self ) :
  if ( self . group . is_null ( ) ) :
   lisp_db_for_lookups . add_cache ( self . eid , self )
  else :
   i1iOo = lisp_db_for_lookups . lookup_cache ( self . group , True )
   if ( i1iOo == None ) :
    i1iOo = lisp_mapping ( self . group , self . group , [ ] )
    lisp_db_for_lookups . add_cache ( self . group , i1iOo )
    if 16 - 16: i11iIiiIii - oO0o . i11iIiiIii + OoO0O00 + i11iIiiIii
   i1iOo . add_source_entry ( self )
   if 85 - 85: I1ii11iIi11i - ooOoO0o + I1Ii111 + I1Ii111
   if 13 - 13: II111iiii
   if 22 - 22: o0oOOo0O0Ooo
 def add_cache ( self , do_ipc = True ) :
  if ( self . group . is_null ( ) ) :
   lisp_map_cache . add_cache ( self . eid , self )
   if ( lisp_program_hardware ) : lisp_program_vxlan_hardware ( self )
  else :
   oOooO0Oo0Oo0 = lisp_map_cache . lookup_cache ( self . group , True )
   if ( oOooO0Oo0Oo0 == None ) :
    oOooO0Oo0Oo0 = lisp_mapping ( self . group , self . group , [ ] )
    oOooO0Oo0Oo0 . eid . copy_address ( self . group )
    oOooO0Oo0Oo0 . group . copy_address ( self . group )
    lisp_map_cache . add_cache ( self . group , oOooO0Oo0Oo0 )
    if 45 - 45: I1Ii111 + OoooooooOO + o0oOOo0O0Ooo * II111iiii
   if ( self . eid . is_null ( ) ) : self . eid . make_default_route ( oOooO0Oo0Oo0 . group )
   oOooO0Oo0Oo0 . add_source_entry ( self )
   if 12 - 12: I1ii11iIi11i / O0
  if ( do_ipc ) : lisp_write_ipc_map_cache ( True , self )
  if 18 - 18: OoOoOO00 . i11iIiiIii + i1IIi / OoooooooOO - IiII % OoO0O00
  if 47 - 47: iII111i % IiII + I1Ii111 * o0oOOo0O0Ooo * OoooooooOO
 def delete_cache ( self ) :
  self . delete_rlocs_from_rloc_probe_list ( )
  lisp_write_ipc_map_cache ( False , self )
  if 100 - 100: Oo0Ooo / I1IiiI / iII111i / I1Ii111 / oO0o % o0oOOo0O0Ooo
  if ( self . group . is_null ( ) ) :
   lisp_map_cache . delete_cache ( self . eid )
   if ( lisp_program_hardware ) :
    ii1II1 = self . eid . print_prefix_no_iid ( )
    os . system ( "ip route delete {}" . format ( ii1II1 ) )
    if 20 - 20: i11iIiiIii / I1Ii111
  else :
   oOooO0Oo0Oo0 = lisp_map_cache . lookup_cache ( self . group , True )
   if ( oOooO0Oo0Oo0 == None ) : return
   if 5 - 5: I1IiiI * o0oOOo0O0Ooo % o0oOOo0O0Ooo + I1IiiI
   III1I1I = oOooO0Oo0Oo0 . lookup_source_cache ( self . eid , True )
   if ( III1I1I == None ) : return
   if 60 - 60: OOooOOo * Ii1I % OoooooooOO + i1IIi
   oOooO0Oo0Oo0 . source_cache . delete_cache ( self . eid )
   if ( oOooO0Oo0Oo0 . source_cache . cache_size ( ) == 0 ) :
    lisp_map_cache . delete_cache ( self . group )
    if 18 - 18: i1IIi - I11i - I1IiiI * I1IiiI % IiII - IiII
    if 1 - 1: o0oOOo0O0Ooo + OoOoOO00 / OOooOOo % IiII
    if 16 - 16: IiII . I11i * O0 + OoooooooOO
    if 37 - 37: OoO0O00 . i11iIiiIii - i11iIiiIii % I1Ii111 + II111iiii * i11iIiiIii
 def add_source_entry ( self , source_mc ) :
  if ( self . source_cache == None ) : self . source_cache = lisp_cache ( )
  self . source_cache . add_cache ( source_mc . eid , source_mc )
  if 83 - 83: OOooOOo % O0 - I11i . Ii1I % IiII
  if 45 - 45: I11i % OoO0O00
 def lookup_source_cache ( self , source , exact ) :
  if ( self . source_cache == None ) : return ( None )
  return ( self . source_cache . lookup_cache ( source , exact ) )
  if 18 - 18: Ii1I / Ii1I * IiII
  if 33 - 33: ooOoO0o
 def dynamic_eid_configured ( self ) :
  return ( self . dynamic_eids != None )
  if 14 - 14: Oo0Ooo % I1Ii111 % ooOoO0o . oO0o * iIii1I11I1II1 . I1ii11iIi11i
  if 50 - 50: O0 * i11iIiiIii / iIii1I11I1II1 . I11i + i11iIiiIii
 def star_secondary_iid ( self , prefix ) :
  if ( self . secondary_iid == None ) : return ( prefix )
  IIiI1i = "," + str ( self . secondary_iid )
  return ( prefix . replace ( IIiI1i , IIiI1i + "*" ) )
  if 68 - 68: oO0o + o0oOOo0O0Ooo * iIii1I11I1II1 / i1IIi
  if 9 - 9: I11i % OoO0O00 . oO0o / I1ii11iIi11i
 def increment_decap_stats ( self , packet ) :
  i1O0OO = packet . udp_dport
  if ( i1O0OO == LISP_DATA_PORT ) :
   oOoOoo0O = self . get_rloc ( packet . outer_dest )
  else :
   if 88 - 88: Oo0Ooo / IiII / II111iiii / I1ii11iIi11i + OoooooooOO
   if 65 - 65: iII111i % oO0o * IiII
   if 16 - 16: iII111i % I11i % OoOoOO00
   if 80 - 80: OoooooooOO * i11iIiiIii % oO0o / Oo0Ooo - I1ii11iIi11i
   for oOoOoo0O in self . rloc_set :
    if ( oOoOoo0O . translated_port != 0 ) : break
    if 92 - 92: o0oOOo0O0Ooo % i1IIi / I1Ii111 % ooOoO0o / oO0o
    if 2 - 2: i11iIiiIii / Ii1I - i1IIi % O0
  if ( oOoOoo0O != None ) : oOoOoo0O . stats . increment ( len ( packet . packet ) )
  self . stats . increment ( len ( packet . packet ) )
  if 12 - 12: Oo0Ooo + I1ii11iIi11i
  if 54 - 54: OoO0O00 . o0oOOo0O0Ooo / I11i
 def rtrs_in_rloc_set ( self ) :
  for oOoOoo0O in self . rloc_set :
   if ( oOoOoo0O . is_rtr ( ) ) : return ( True )
   if 95 - 95: i1IIi . I1Ii111
  return ( False )
  if 94 - 94: I1IiiI + Ii1I + i1IIi . iIii1I11I1II1
  if 64 - 64: O0 * OOooOOo * I1IiiI - o0oOOo0O0Ooo
  if 86 - 86: i1IIi
class lisp_dynamic_eid ( ) :
 def __init__ ( self ) :
  self . dynamic_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . uptime = lisp_get_timestamp ( )
  self . interface = None
  self . last_packet = None
  self . timeout = LISP_DEFAULT_DYN_EID_TIMEOUT
  if 84 - 84: OoOoOO00
  if 31 - 31: iIii1I11I1II1 + I1IiiI
 def get_timeout ( self , interface ) :
  try :
   O000 = lisp_myinterfaces [ interface ]
   self . timeout = O000 . dynamic_eid_timeout
  except :
   self . timeout = LISP_DEFAULT_DYN_EID_TIMEOUT
   if 55 - 55: IiII / OoooooooOO
   if 23 - 23: iIii1I11I1II1
   if 7 - 7: IiII / OOooOOo + Oo0Ooo . I1IiiI
   if 33 - 33: I1Ii111 + OoooooooOO
class lisp_group_mapping ( ) :
 def __init__ ( self , group_name , ms_name , group_prefix , sources , rle_addr ) :
  self . group_name = group_name
  self . group_prefix = group_prefix
  self . use_ms_name = ms_name
  self . sources = sources
  self . rle_address = rle_addr
  if 73 - 73: O0 . Oo0Ooo
  if 28 - 28: I1IiiI . O0 % o0oOOo0O0Ooo / I11i
 def add_group ( self ) :
  lisp_group_mapping_list [ self . group_name ] = self
  if 48 - 48: II111iiii % I1ii11iIi11i - II111iiii
  if 29 - 29: I1Ii111 - I1Ii111 - I11i * iIii1I11I1II1 % OoO0O00 % IiII
  if 73 - 73: i1IIi . OoooooooOO / OoOoOO00 % Ii1I / Ii1I / Ii1I
lisp_site_flags = {
 "P" : "ETR is {}Requesting Map-Server to Proxy Map-Reply" ,
 "S" : "ETR is {}LISP-SEC capable" ,
 "I" : "xTR-ID and site-ID are {}included in Map-Register" ,
 "T" : "Use Map-Register TTL field to timeout registration is {}set" ,
 "R" : "Merging registrations are {}requested" ,
 "M" : "ETR is {}a LISP Mobile-Node" ,
 "N" : "ETR is {}requesting Map-Notify messages from Map-Server"
 }
if 40 - 40: I1Ii111 - iIii1I11I1II1
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
  if 88 - 88: OOooOOo * O0 * OoOoOO00
  if 26 - 26: Ii1I
  if 65 - 65: iII111i / iIii1I11I1II1 + I11i - iIii1I11I1II1 - Ii1I . I1Ii111
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
  if 77 - 77: OoOoOO00 / I1IiiI + IiII
  if 66 - 66: i11iIiiIii * OoooooooOO + iII111i / Ii1I
 def print_eid_tuple ( self ) :
  return ( lisp_print_eid_tuple ( self . eid , self . group ) )
  if 42 - 42: Ii1I / iIii1I11I1II1 / Oo0Ooo . O0 . oO0o * I1IiiI
  if 21 - 21: OoooooooOO
 def print_flags ( self , html ) :
  if ( html == False ) :
   ooO000O = "{}-{}-{}-{}-{}-{}-{}" . format ( "P" if self . proxy_reply_requested else "p" ,
   # IiII - i1IIi / OoO0O00 . I1Ii111 % OoOoOO00
 "S" if self . lisp_sec_present else "s" ,
 "I" if self . xtr_id_present else "i" ,
 "T" if self . use_register_ttl_requested else "t" ,
 "R" if self . merge_register_requested else "r" ,
 "M" if self . mobile_node_requested else "m" ,
 "N" if self . map_notify_requested else "n" )
  else :
   i11iII1 = self . print_flags ( False )
   i11iII1 = i11iII1 . split ( "-" )
   ooO000O = ""
   for IIIiiIIii in i11iII1 :
    O0O00o0O0OO = lisp_site_flags [ IIIiiIIii . upper ( ) ]
    O0O00o0O0OO = O0O00o0O0OO . format ( "" if IIIiiIIii . isupper ( ) else "not " )
    ooO000O += lisp_span ( IIIiiIIii , O0O00o0O0OO )
    if ( IIIiiIIii . lower ( ) != "n" ) : ooO000O += "-"
    if 79 - 79: oO0o + I1IiiI % iII111i + II111iiii % OoO0O00 % iII111i
    if 46 - 46: o0oOOo0O0Ooo
  return ( ooO000O )
  if 61 - 61: OoO0O00 . O0 + I1ii11iIi11i + OoO0O00
  if 44 - 44: I11i . oO0o
 def copy_state_to_parent ( self , child ) :
  self . xtr_id = child . xtr_id
  self . site_id = child . site_id
  self . first_registered = child . first_registered
  self . last_registered = child . last_registered
  self . last_registerer = child . last_registerer
  self . register_ttl = child . register_ttl
  if ( self . registered == False ) :
   self . first_registered = lisp_get_timestamp ( )
   if 65 - 65: I1ii11iIi11i * II111iiii % I11i + II111iiii . i1IIi / ooOoO0o
  self . auth_sha1_or_sha2 = child . auth_sha1_or_sha2
  self . registered = child . registered
  self . proxy_reply_requested = child . proxy_reply_requested
  self . lisp_sec_present = child . lisp_sec_present
  self . xtr_id_present = child . xtr_id_present
  self . use_register_ttl_requested = child . use_register_ttl_requested
  self . merge_register_requested = child . merge_register_requested
  self . mobile_node_requested = child . mobile_node_requested
  self . map_notify_requested = child . map_notify_requested
  if 74 - 74: OoOoOO00 % OoO0O00 . OoOoOO00
  if 16 - 16: OoO0O00 / Ii1I * i11iIiiIii / o0oOOo0O0Ooo + I1Ii111
 def build_sort_key ( self ) :
  i1IiI1IIIIi = lisp_cache ( )
  IiiIiiii , iIIIi = i1IiI1IIIIi . build_key ( self . eid )
  ooOO0OOo0oo0 = ""
  if ( self . group . is_null ( ) == False ) :
   O0o0ooo0O0OO0 , ooOO0OOo0oo0 = i1IiI1IIIIi . build_key ( self . group )
   ooOO0OOo0oo0 = "-" + ooOO0OOo0oo0 [ 0 : 12 ] + "-" + str ( O0o0ooo0O0OO0 ) + "-" + ooOO0OOo0oo0 [ 12 : : ]
   if 80 - 80: II111iiii + OoO0O00 % ooOoO0o + i11iIiiIii
  iIIIi = iIIIi [ 0 : 12 ] + "-" + str ( IiiIiiii ) + "-" + iIIIi [ 12 : : ] + ooOO0OOo0oo0
  del ( i1IiI1IIIIi )
  return ( iIIIi )
  if 30 - 30: Ii1I / I1ii11iIi11i % IiII - Oo0Ooo
  if 100 - 100: IiII . I1Ii111 * oO0o % OoO0O00 . iIii1I11I1II1 * Oo0Ooo
 def merge_in_site_eid ( self , child ) :
  o00O0oOoO = False
  if ( self . group . is_null ( ) ) :
   self . merge_rlocs_in_site_eid ( )
  else :
   o00O0oOoO = self . merge_rles_in_site_eid ( )
   if 48 - 48: iII111i . i11iIiiIii + i11iIiiIii
   if 56 - 56: OoooooooOO
   if 52 - 52: O0 - I1Ii111 + oO0o % ooOoO0o . oO0o
   if 60 - 60: oO0o + o0oOOo0O0Ooo - OOooOOo % o0oOOo0O0Ooo . I11i + OoO0O00
   if 27 - 27: i11iIiiIii - I1ii11iIi11i * I1Ii111 . I1IiiI / OoO0O00 * ooOoO0o
   if 42 - 42: OOooOOo
  if ( child != None ) :
   self . copy_state_to_parent ( child )
   self . map_registers_received += 1
   if 36 - 36: OoooooooOO + ooOoO0o + iII111i
  return ( o00O0oOoO )
  if 30 - 30: i1IIi % Ii1I
  if 18 - 18: o0oOOo0O0Ooo % I1ii11iIi11i . Ii1I . O0 * II111iiii + I1ii11iIi11i
 def copy_rloc_records ( self ) :
  II1I1 = [ ]
  for iIIiIiiI in self . registered_rlocs :
   II1I1 . append ( copy . deepcopy ( iIIiIiiI ) )
   if 96 - 96: IiII % iII111i . OoOoOO00 / oO0o . OoO0O00
  return ( II1I1 )
  if 85 - 85: iIii1I11I1II1 / OoOoOO00 * I1ii11iIi11i
  if 26 - 26: iII111i - OoO0O00 . o0oOOo0O0Ooo
 def merge_rlocs_in_site_eid ( self ) :
  self . registered_rlocs = [ ]
  for IiIi1II1i in self . individual_registrations . values ( ) :
   if ( self . site_id != IiIi1II1i . site_id ) : continue
   if ( IiIi1II1i . registered == False ) : continue
   self . registered_rlocs += IiIi1II1i . copy_rloc_records ( )
   if 50 - 50: I1Ii111 . O0 . OoOoOO00 + I1Ii111 + OoooooooOO . i11iIiiIii
   if 65 - 65: I1IiiI % iIii1I11I1II1
   if 52 - 52: I1IiiI
   if 19 - 19: I1IiiI
   if 17 - 17: I11i + OoooooooOO
   if 63 - 63: IiII
  II1I1 = [ ]
  for iIIiIiiI in self . registered_rlocs :
   if ( iIIiIiiI . rloc . is_null ( ) or len ( II1I1 ) == 0 ) :
    II1I1 . append ( iIIiIiiI )
    continue
    if 3 - 3: oO0o * II111iiii . O0
   for IIiiI in II1I1 :
    if ( IIiiI . rloc . is_null ( ) ) : continue
    if ( iIIiIiiI . rloc . is_exact_match ( IIiiI . rloc ) ) : break
    if 39 - 39: i1IIi - oO0o / I1IiiI
   if ( IIiiI == II1I1 [ - 1 ] ) : II1I1 . append ( iIIiIiiI )
   if 83 - 83: iIii1I11I1II1 / iII111i * ooOoO0o + OoooooooOO
  self . registered_rlocs = II1I1
  if 97 - 97: IiII / OoooooooOO / iIii1I11I1II1 . i1IIi
  if 18 - 18: o0oOOo0O0Ooo + OoOoOO00 - I1ii11iIi11i - ooOoO0o
  if 42 - 42: iIii1I11I1II1 % i1IIi - O0 * II111iiii
  if 58 - 58: i1IIi - OoO0O00 + ooOoO0o
  if ( len ( self . registered_rlocs ) == 0 ) : self . registered = False
  return
  if 6 - 6: IiII % I1IiiI + OoooooooOO * oO0o . iII111i + oO0o
  if 4 - 4: I11i % I1IiiI
 def merge_rles_in_site_eid ( self ) :
  if 72 - 72: I1IiiI % II111iiii % iII111i / OoOoOO00
  if 96 - 96: OoOoOO00 % Ii1I
  if 50 - 50: IiII - II111iiii
  if 10 - 10: OoooooooOO % Ii1I * OOooOOo + IiII * oO0o
  iiiii = { }
  for iIIiIiiI in self . registered_rlocs :
   if ( iIIiIiiI . rle == None ) : continue
   for oOo0o in iIIiIiiI . rle . rle_nodes :
    I1Iii1I = oOo0o . address . print_address_no_iid ( )
    iiiii [ I1Iii1I ] = oOo0o . address
    if 90 - 90: ooOoO0o % Oo0Ooo + OOooOOo % II111iiii * OoOoOO00
   break
   if 7 - 7: IiII * O0
   if 29 - 29: I1IiiI + i1IIi * O0 % oO0o
   if 11 - 11: I1Ii111 . OoooooooOO * iIii1I11I1II1 / I1ii11iIi11i - ooOoO0o . iII111i
   if 71 - 71: i11iIiiIii + I11i / i11iIiiIii % Oo0Ooo / iIii1I11I1II1 * OoO0O00
   if 49 - 49: iII111i + OoOoOO00
  self . merge_rlocs_in_site_eid ( )
  if 33 - 33: ooOoO0o
  if 19 - 19: I1Ii111 % IiII
  if 94 - 94: I1Ii111 * I1ii11iIi11i * I1ii11iIi11i - o0oOOo0O0Ooo . i11iIiiIii
  if 16 - 16: i1IIi
  if 88 - 88: OOooOOo
  if 79 - 79: oO0o
  if 52 - 52: oO0o + OoO0O00 / OoooooooOO - iIii1I11I1II1 / iII111i - oO0o
  if 68 - 68: I1IiiI - OoOoOO00 - iIii1I11I1II1 % i11iIiiIii * OoOoOO00 * OoO0O00
  OOO0000o = [ ]
  for iIIiIiiI in self . registered_rlocs :
   if ( self . registered_rlocs . index ( iIIiIiiI ) == 0 ) :
    OOO0000o . append ( iIIiIiiI )
    continue
    if 85 - 85: oO0o * I1Ii111 * OoooooooOO % i11iIiiIii . Ii1I % i1IIi
   if ( iIIiIiiI . rle == None ) : OOO0000o . append ( iIIiIiiI )
   if 40 - 40: Oo0Ooo
  self . registered_rlocs = OOO0000o
  if 40 - 40: oO0o % i1IIi % ooOoO0o . oO0o % oO0o
  if 69 - 69: OoooooooOO . oO0o / OoooooooOO / OoOoOO00
  if 41 - 41: ooOoO0o + o0oOOo0O0Ooo . o0oOOo0O0Ooo / oO0o * IiII
  if 96 - 96: IiII % O0 + Ii1I / o0oOOo0O0Ooo + I1ii11iIi11i * II111iiii
  if 65 - 65: Ii1I * Oo0Ooo * Oo0Ooo . Ii1I
  if 4 - 4: i11iIiiIii - iIii1I11I1II1 % o0oOOo0O0Ooo * oO0o
  if 19 - 19: Ii1I
  Oo0OOo = lisp_rle ( "" )
  i11ii1ii = { }
  Iii1I1III1ii = None
  for IiIi1II1i in self . individual_registrations . values ( ) :
   if ( IiIi1II1i . registered == False ) : continue
   IIIIIIi = IiIi1II1i . registered_rlocs [ 0 ] . rle
   if ( IIIIIIi == None ) : continue
   if 78 - 78: I1ii11iIi11i % i1IIi . I1Ii111 + Oo0Ooo . o0oOOo0O0Ooo % II111iiii
   Iii1I1III1ii = IiIi1II1i . registered_rlocs [ 0 ] . rloc_name
   for O0ii1i in IIIIIIi . rle_nodes :
    I1Iii1I = O0ii1i . address . print_address_no_iid ( )
    if ( i11ii1ii . has_key ( I1Iii1I ) ) : break
    if 75 - 75: I1IiiI * oO0o / Oo0Ooo - II111iiii . OoO0O00
    oOo0o = lisp_rle_node ( )
    oOo0o . address . copy_address ( O0ii1i . address )
    oOo0o . level = O0ii1i . level
    oOo0o . rloc_name = Iii1I1III1ii
    Oo0OOo . rle_nodes . append ( oOo0o )
    i11ii1ii [ I1Iii1I ] = O0ii1i . address
    if 8 - 8: iII111i . i11iIiiIii . IiII . I1ii11iIi11i + I11i
    if 24 - 24: I1IiiI - I1IiiI . Oo0Ooo * IiII + I1IiiI / i1IIi
    if 18 - 18: II111iiii / iIii1I11I1II1 * I1ii11iIi11i . ooOoO0o * ooOoO0o
    if 89 - 89: I1IiiI - Oo0Ooo
    if 28 - 28: OoooooooOO . i1IIi . I1Ii111
    if 53 - 53: OoO0O00 * Oo0Ooo + Oo0Ooo
  if ( len ( Oo0OOo . rle_nodes ) == 0 ) : Oo0OOo = None
  if ( len ( self . registered_rlocs ) != 0 ) :
   self . registered_rlocs [ 0 ] . rle = Oo0OOo
   if ( Iii1I1III1ii ) : self . registered_rlocs [ 0 ] . rloc_name = None
   if 62 - 62: OOooOOo - i1IIi + i11iIiiIii * I11i / OoO0O00
   if 84 - 84: IiII * OOooOOo
   if 1 - 1: iII111i * I1IiiI . o0oOOo0O0Ooo . IiII
   if 6 - 6: OOooOOo . oO0o / Oo0Ooo / o0oOOo0O0Ooo
   if 24 - 24: Oo0Ooo % OoooooooOO
  if ( iiiii . keys ( ) == i11ii1ii . keys ( ) ) : return ( False )
  if 78 - 78: OoooooooOO - II111iiii . OoO0O00 / I1ii11iIi11i
  lprint ( "{} {} from {} to {}" . format ( green ( self . print_eid_tuple ( ) , False ) , bold ( "RLE change" , False ) ,
  # ooOoO0o % OOooOOo % I1Ii111 + OoooooooOO / I1ii11iIi11i * I11i
 iiiii . keys ( ) , i11ii1ii . keys ( ) ) )
  if 61 - 61: iIii1I11I1II1 / I1Ii111 * OoO0O00 . oO0o
  return ( True )
  if 29 - 29: Oo0Ooo
  if 82 - 82: OoO0O00
 def add_cache ( self ) :
  if ( self . group . is_null ( ) ) :
   lisp_sites_by_eid . add_cache ( self . eid , self )
  else :
   oo00oO0 = lisp_sites_by_eid . lookup_cache ( self . group , True )
   if ( oo00oO0 == None ) :
    oo00oO0 = lisp_site_eid ( self . site )
    oo00oO0 . eid . copy_address ( self . group )
    oo00oO0 . group . copy_address ( self . group )
    lisp_sites_by_eid . add_cache ( self . group , oo00oO0 )
    if 93 - 93: Oo0Ooo
    if 71 - 71: OoooooooOO - IiII . I1ii11iIi11i + OoooooooOO
    if 97 - 97: Ii1I - I1IiiI . OoooooooOO * IiII
    if 17 - 17: OoO0O00 / II111iiii / II111iiii / II111iiii
    if 70 - 70: OoO0O00 + O0 * OoO0O00
    oo00oO0 . parent_for_more_specifics = self . parent_for_more_specifics
    if 25 - 25: OoooooooOO . Oo0Ooo + OOooOOo + Oo0Ooo * O0 % i1IIi
   if ( self . eid . is_null ( ) ) : self . eid . make_default_route ( oo00oO0 . group )
   oo00oO0 . add_source_entry ( self )
   if 71 - 71: II111iiii / Ii1I + i1IIi - OoOoOO00 + Ii1I
   if 31 - 31: OoooooooOO * Ii1I - iII111i . oO0o % Ii1I
   if 97 - 97: Ii1I
 def delete_cache ( self ) :
  if ( self . group . is_null ( ) ) :
   lisp_sites_by_eid . delete_cache ( self . eid )
  else :
   oo00oO0 = lisp_sites_by_eid . lookup_cache ( self . group , True )
   if ( oo00oO0 == None ) : return
   if 51 - 51: II111iiii . oO0o % iII111i
   IiIi1II1i = oo00oO0 . lookup_source_cache ( self . eid , True )
   if ( IiIi1II1i == None ) : return
   if 47 - 47: II111iiii - iII111i * I1IiiI . IiII
   if ( oo00oO0 . source_cache == None ) : return
   if 41 - 41: OoOoOO00 / O0 + I1Ii111 . I1ii11iIi11i
   oo00oO0 . source_cache . delete_cache ( self . eid )
   if ( oo00oO0 . source_cache . cache_size ( ) == 0 ) :
    lisp_sites_by_eid . delete_cache ( self . group )
    if 48 - 48: Ii1I . o0oOOo0O0Ooo * O0 / OoooooooOO + I1Ii111 + Oo0Ooo
    if 92 - 92: Ii1I - o0oOOo0O0Ooo % I1IiiI + I1Ii111
    if 3 - 3: iIii1I11I1II1 + i11iIiiIii
    if 49 - 49: OoOoOO00 % iIii1I11I1II1 + I1Ii111
 def add_source_entry ( self , source_se ) :
  if ( self . source_cache == None ) : self . source_cache = lisp_cache ( )
  self . source_cache . add_cache ( source_se . eid , source_se )
  if 38 - 38: i11iIiiIii
  if 75 - 75: iIii1I11I1II1 / OoO0O00 * OOooOOo % O0
 def lookup_source_cache ( self , source , exact ) :
  if ( self . source_cache == None ) : return ( None )
  return ( self . source_cache . lookup_cache ( source , exact ) )
  if 82 - 82: Oo0Ooo / i1IIi . i1IIi / oO0o
  if 7 - 7: Oo0Ooo . iII111i % I1ii11iIi11i / iII111i
 def is_star_g ( self ) :
  if ( self . group . is_null ( ) ) : return ( False )
  return ( self . eid . is_exact_match ( self . group ) )
  if 93 - 93: iII111i
  if 5 - 5: iII111i . I11i % I11i * Ii1I - I1ii11iIi11i . i11iIiiIii
 def eid_record_matches ( self , eid_record ) :
  if ( self . eid . is_exact_match ( eid_record . eid ) == False ) : return ( False )
  if ( eid_record . group . is_null ( ) ) : return ( True )
  return ( eid_record . group . is_exact_match ( self . group ) )
  if 32 - 32: II111iiii
  if 58 - 58: I1IiiI - o0oOOo0O0Ooo - I1Ii111 . O0 % OoO0O00 . I11i
 def inherit_from_ams_parent ( self ) :
  Ii1IIII = self . parent_for_more_specifics
  if ( Ii1IIII == None ) : return
  self . force_proxy_reply = Ii1IIII . force_proxy_reply
  self . force_nat_proxy_reply = Ii1IIII . force_nat_proxy_reply
  self . force_ttl = Ii1IIII . force_ttl
  self . pitr_proxy_reply_drop = Ii1IIII . pitr_proxy_reply_drop
  self . proxy_reply_action = Ii1IIII . proxy_reply_action
  self . echo_nonce_capable = Ii1IIII . echo_nonce_capable
  self . policy = Ii1IIII . policy
  self . require_signature = Ii1IIII . require_signature
  if 41 - 41: iII111i . I1Ii111 - IiII / O0
  if 62 - 62: IiII * I1ii11iIi11i * iII111i * OoOoOO00
 def rtrs_in_rloc_set ( self ) :
  for iIIiIiiI in self . registered_rlocs :
   if ( iIIiIiiI . is_rtr ( ) ) : return ( True )
   if 12 - 12: Oo0Ooo * Ii1I / ooOoO0o % I11i % O0
  return ( False )
  if 25 - 25: Oo0Ooo * oO0o
  if 78 - 78: OoOoOO00 / II111iiii
 def is_rtr_in_rloc_set ( self , rtr_rloc ) :
  for iIIiIiiI in self . registered_rlocs :
   if ( iIIiIiiI . rloc . is_exact_match ( rtr_rloc ) == False ) : continue
   if ( iIIiIiiI . is_rtr ( ) ) : return ( True )
   if 6 - 6: I1Ii111 . OoOoOO00
  return ( False )
  if 75 - 75: Oo0Ooo + I11i
  if 87 - 87: I1IiiI
 def is_rloc_in_rloc_set ( self , rloc ) :
  for iIIiIiiI in self . registered_rlocs :
   if ( iIIiIiiI . rle ) :
    for Oo0OOo in iIIiIiiI . rle . rle_nodes :
     if ( Oo0OOo . address . is_exact_match ( rloc ) ) : return ( True )
     if 36 - 36: OoO0O00 . ooOoO0o . O0 / OoO0O00
     if 50 - 50: Ii1I . OoOoOO00 * o0oOOo0O0Ooo
   if ( iIIiIiiI . rloc . is_exact_match ( rloc ) ) : return ( True )
   if 68 - 68: IiII * oO0o / OoOoOO00 / I1Ii111
  return ( False )
  if 72 - 72: I1ii11iIi11i
  if 74 - 74: I1Ii111 * iIii1I11I1II1 / oO0o - IiII - I1IiiI
 def do_rloc_sets_match ( self , prev_rloc_set ) :
  if ( len ( self . registered_rlocs ) != len ( prev_rloc_set ) ) : return ( False )
  if 84 - 84: iIii1I11I1II1 % Oo0Ooo / I1ii11iIi11i + o0oOOo0O0Ooo * II111iiii
  for iIIiIiiI in prev_rloc_set :
   Ii11IIiiI1I = iIIiIiiI . rloc
   if ( self . is_rloc_in_rloc_set ( Ii11IIiiI1I ) == False ) : return ( False )
   if 81 - 81: I1IiiI / I1ii11iIi11i / OOooOOo
  return ( True )
  if 89 - 89: Oo0Ooo % IiII
  if 36 - 36: IiII % OoOoOO00 % I1ii11iIi11i
  if 7 - 7: I1ii11iIi11i % OoOoOO00 - O0 . I1Ii111
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
   if 9 - 9: Ii1I . OoooooooOO / ooOoO0o + i1IIi
  self . last_used = 0
  self . last_reply = 0
  self . last_nonce = 0
  self . map_requests_sent = 0
  self . neg_map_replies_received = 0
  self . total_rtt = 0
  if 90 - 90: oO0o - OoOoOO00 % ooOoO0o
  if 83 - 83: OOooOOo - I1ii11iIi11i + OoO0O00
 def resolve_dns_name ( self ) :
  if ( self . dns_name == None ) : return
  if ( self . last_dns_resolve and
 time . time ( ) - self . last_dns_resolve < 30 ) : return
  if 99 - 99: iII111i - OoOoOO00 % ooOoO0o
  try :
   II111 = socket . gethostbyname_ex ( self . dns_name )
   self . last_dns_resolve = lisp_get_timestamp ( )
   II1Oo0o00ooOooo = II111 [ 2 ]
  except :
   return
   if 39 - 39: oO0o / OoO0O00 - Ii1I + ooOoO0o + OOooOOo
   if 84 - 84: iII111i / Oo0Ooo
   if 21 - 21: OoO0O00 . I1IiiI - OoO0O00
   if 51 - 51: iIii1I11I1II1
   if 5 - 5: oO0o - OoOoOO00 . ooOoO0o
   if 97 - 97: I11i - ooOoO0o + oO0o . I1Ii111
  if ( len ( II1Oo0o00ooOooo ) <= self . a_record_index ) :
   self . delete_mr ( )
   return
   if 22 - 22: Ii1I - II111iiii % Oo0Ooo * OoOoOO00 + iIii1I11I1II1
   if 5 - 5: Oo0Ooo % o0oOOo0O0Ooo * I1Ii111
  I1Iii1I = II1Oo0o00ooOooo [ self . a_record_index ]
  if ( I1Iii1I != self . map_resolver . print_address_no_iid ( ) ) :
   self . delete_mr ( )
   self . map_resolver . store_address ( I1Iii1I )
   self . insert_mr ( )
   if 6 - 6: OOooOOo + o0oOOo0O0Ooo
   if 41 - 41: OoooooooOO + iIii1I11I1II1 . O0 % I1Ii111 % OOooOOo + I1Ii111
   if 65 - 65: II111iiii . oO0o
   if 9 - 9: I1Ii111 . i11iIiiIii * I11i + o0oOOo0O0Ooo
   if 85 - 85: i11iIiiIii * iII111i
   if 43 - 43: Ii1I + iII111i * I1ii11iIi11i * Ii1I
  if ( lisp_is_decent_dns_suffix ( self . dns_name ) == False ) : return
  if ( self . a_record_index != 0 ) : return
  if 62 - 62: O0
  for I1Iii1I in II1Oo0o00ooOooo [ 1 : : ] :
   OOOO0o = lisp_address ( LISP_AFI_NONE , I1Iii1I , 0 , 0 )
   oOoooooOooO = lisp_get_map_resolver ( OOOO0o , None )
   if ( oOoooooOooO != None and oOoooooOooO . a_record_index == II1Oo0o00ooOooo . index ( I1Iii1I ) ) :
    continue
    if 44 - 44: i1IIi
   oOoooooOooO = lisp_mr ( I1Iii1I , None , None )
   oOoooooOooO . a_record_index = II1Oo0o00ooOooo . index ( I1Iii1I )
   oOoooooOooO . dns_name = self . dns_name
   oOoooooOooO . last_dns_resolve = lisp_get_timestamp ( )
   if 27 - 27: ooOoO0o - Oo0Ooo + i11iIiiIii - oO0o % O0
   if 68 - 68: iIii1I11I1II1 % Ii1I / I11i
   if 17 - 17: IiII * Oo0Ooo . i11iIiiIii . IiII . Oo0Ooo % IiII
   if 93 - 93: II111iiii - IiII - O0 - i11iIiiIii / OOooOOo
   if 76 - 76: OOooOOo
  I1iii11 = [ ]
  for oOoooooOooO in lisp_map_resolvers_list . values ( ) :
   if ( self . dns_name != oOoooooOooO . dns_name ) : continue
   OOOO0o = oOoooooOooO . map_resolver . print_address_no_iid ( )
   if ( OOOO0o in II1Oo0o00ooOooo ) : continue
   I1iii11 . append ( oOoooooOooO )
   if 47 - 47: Oo0Ooo + oO0o % OoooooooOO
  for oOoooooOooO in I1iii11 : oOoooooOooO . delete_mr ( )
  if 23 - 23: I1Ii111 / i11iIiiIii - ooOoO0o * iII111i - Ii1I . iIii1I11I1II1
  if 11 - 11: I11i % OoOoOO00 * Oo0Ooo
 def insert_mr ( self ) :
  iIIIi = self . mr_name + self . map_resolver . print_address ( )
  lisp_map_resolvers_list [ iIIIi ] = self
  if 48 - 48: OOooOOo
  if 66 - 66: iII111i - I1Ii111 - i11iIiiIii . o0oOOo0O0Ooo + Oo0Ooo
 def delete_mr ( self ) :
  iIIIi = self . mr_name + self . map_resolver . print_address ( )
  if ( lisp_map_resolvers_list . has_key ( iIIIi ) == False ) : return
  lisp_map_resolvers_list . pop ( iIIIi )
  if 90 - 90: O0 - i11iIiiIii * ooOoO0o . I1ii11iIi11i . Ii1I - OoooooooOO
  if 23 - 23: o0oOOo0O0Ooo
  if 88 - 88: I1Ii111 + iIii1I11I1II1 / o0oOOo0O0Ooo
class lisp_ddt_root ( ) :
 def __init__ ( self ) :
  self . root_address = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . public_key = ""
  self . priority = 0
  self . weight = 0
  if 93 - 93: ooOoO0o % iIii1I11I1II1 - OOooOOo . IiII + ooOoO0o
  if 63 - 63: I1ii11iIi11i / OOooOOo
  if 28 - 28: I11i / I1Ii111 + IiII * OoooooooOO - iIii1I11I1II1
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
  if 6 - 6: I11i % o0oOOo0O0Ooo / OoooooooOO . I1Ii111
  if 17 - 17: I1ii11iIi11i + OoooooooOO / iIii1I11I1II1 . II111iiii + Oo0Ooo
 def print_referral ( self , eid_indent , referral_indent ) :
  iiIIi11i = lisp_print_elapsed ( self . uptime )
  i11Ii1 = lisp_print_future ( self . expires )
  lprint ( "{}Referral EID {}, uptime/expires {}/{}, {} referrals:" . format ( eid_indent , green ( self . eid . print_prefix ( ) , False ) , iiIIi11i ,
  # O0
 i11Ii1 , len ( self . referral_set ) ) )
  if 90 - 90: I11i + I1ii11iIi11i + OoooooooOO + OoOoOO00 + IiII / iII111i
  for oOoooooOoOoO in self . referral_set . values ( ) :
   oOoooooOoOoO . print_ref_node ( referral_indent )
   if 75 - 75: i11iIiiIii
   if 27 - 27: I11i - IiII - I1Ii111
   if 90 - 90: OoO0O00 . oO0o * O0 / I11i % O0 + I1Ii111
 def print_referral_type ( self ) :
  if ( self . eid . afi == LISP_AFI_ULTIMATE_ROOT ) : return ( "root" )
  if ( self . referral_type == LISP_DDT_ACTION_NULL ) :
   return ( "null-referral" )
   if 48 - 48: iIii1I11I1II1 . i11iIiiIii / OoooooooOO . i1IIi . o0oOOo0O0Ooo
  if ( self . referral_type == LISP_DDT_ACTION_SITE_NOT_FOUND ) :
   return ( "no-site-action" )
   if 84 - 84: Ii1I
  if ( self . referral_type > LISP_DDT_ACTION_MAX ) :
   return ( "invalid-action" )
   if 92 - 92: I11i
  return ( lisp_map_referral_action_string [ self . referral_type ] )
  if 64 - 64: iII111i / iII111i * iII111i % O0 / IiII . I1ii11iIi11i
  if 23 - 23: i1IIi / I1ii11iIi11i + o0oOOo0O0Ooo
 def print_eid_tuple ( self ) :
  return ( lisp_print_eid_tuple ( self . eid , self . group ) )
  if 82 - 82: O0 * ooOoO0o * iIii1I11I1II1 . i1IIi
  if 47 - 47: I11i * I11i . OoOoOO00
 def print_ttl ( self ) :
  ooOOooooo0Oo = self . referral_ttl
  if ( ooOOooooo0Oo < 60 ) : return ( str ( ooOOooooo0Oo ) + " secs" )
  if 68 - 68: OoooooooOO + OoOoOO00 + i11iIiiIii
  if ( ( ooOOooooo0Oo % 60 ) == 0 ) :
   ooOOooooo0Oo = str ( ooOOooooo0Oo / 60 ) + " mins"
  else :
   ooOOooooo0Oo = str ( ooOOooooo0Oo ) + " secs"
   if 89 - 89: Oo0Ooo + Ii1I * O0 - I1Ii111
  return ( ooOOooooo0Oo )
  if 33 - 33: iIii1I11I1II1 . I11i
  if 63 - 63: oO0o - iII111i
 def is_referral_negative ( self ) :
  return ( self . referral_type in ( LISP_DDT_ACTION_MS_NOT_REG , LISP_DDT_ACTION_DELEGATION_HOLE ,
  # I1ii11iIi11i
 LISP_DDT_ACTION_NOT_AUTH ) )
  if 26 - 26: i1IIi % OoooooooOO / OOooOOo % Ii1I * i11iIiiIii * o0oOOo0O0Ooo
  if 16 - 16: ooOoO0o + OOooOOo * I1IiiI / oO0o . oO0o
 def add_cache ( self ) :
  if ( self . group . is_null ( ) ) :
   lisp_referral_cache . add_cache ( self . eid , self )
  else :
   ooOo = lisp_referral_cache . lookup_cache ( self . group , True )
   if ( ooOo == None ) :
    ooOo = lisp_referral ( )
    ooOo . eid . copy_address ( self . group )
    ooOo . group . copy_address ( self . group )
    lisp_referral_cache . add_cache ( self . group , ooOo )
    if 79 - 79: OOooOOo + i11iIiiIii + OOooOOo % I1IiiI % OoOoOO00
   if ( self . eid . is_null ( ) ) : self . eid . make_default_route ( ooOo . group )
   ooOo . add_source_entry ( self )
   if 50 - 50: o0oOOo0O0Ooo / iIii1I11I1II1 * OoO0O00
   if 44 - 44: II111iiii / o0oOOo0O0Ooo
   if 81 - 81: I1Ii111 . Ii1I * ooOoO0o . IiII - OoOoOO00
 def delete_cache ( self ) :
  if ( self . group . is_null ( ) ) :
   lisp_referral_cache . delete_cache ( self . eid )
  else :
   ooOo = lisp_referral_cache . lookup_cache ( self . group , True )
   if ( ooOo == None ) : return
   if 79 - 79: ooOoO0o - O0
   I1I11i1 = ooOo . lookup_source_cache ( self . eid , True )
   if ( I1I11i1 == None ) : return
   if 56 - 56: ooOoO0o
   ooOo . source_cache . delete_cache ( self . eid )
   if ( ooOo . source_cache . cache_size ( ) == 0 ) :
    lisp_referral_cache . delete_cache ( self . group )
    if 89 - 89: O0 % iIii1I11I1II1 / OoOoOO00 - I1Ii111 - I1IiiI
    if 60 - 60: IiII % i11iIiiIii / OOooOOo
    if 43 - 43: i11iIiiIii * II111iiii + ooOoO0o - OoooooooOO * II111iiii / OoO0O00
    if 92 - 92: O0 - ooOoO0o % iII111i
 def add_source_entry ( self , source_ref ) :
  if ( self . source_cache == None ) : self . source_cache = lisp_cache ( )
  self . source_cache . add_cache ( source_ref . eid , source_ref )
  if 83 - 83: I1ii11iIi11i / OoOoOO00 % OoooooooOO
  if 54 - 54: I11i / I1IiiI * IiII - iII111i
 def lookup_source_cache ( self , source , exact ) :
  if ( self . source_cache == None ) : return ( None )
  return ( self . source_cache . lookup_cache ( source , exact ) )
  if 37 - 37: i1IIi * I1Ii111 / I11i * II111iiii + OoooooooOO . OoO0O00
  if 22 - 22: OoOoOO00 + OoooooooOO - I1Ii111
  if 82 - 82: Ii1I % I1Ii111 / ooOoO0o
class lisp_referral_node ( ) :
 def __init__ ( self ) :
  self . referral_address = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . priority = 0
  self . weight = 0
  self . updown = True
  self . map_requests_sent = 0
  self . no_responses = 0
  self . uptime = lisp_get_timestamp ( )
  if 86 - 86: II111iiii - iIii1I11I1II1 + oO0o + I1IiiI
  if 29 - 29: Ii1I % OoooooooOO * II111iiii
 def print_ref_node ( self , indent ) :
  III11I1 = lisp_print_elapsed ( self . uptime )
  lprint ( "{}referral {}, uptime {}, {}, priority/weight: {}/{}" . format ( indent , red ( self . referral_address . print_address ( ) , False ) , III11I1 ,
  # OoOoOO00 * OoO0O00 * OOooOOo % I1IiiI * o0oOOo0O0Ooo + I1ii11iIi11i
 "up" if self . updown else "down" , self . priority , self . weight ) )
  if 73 - 73: i1IIi
  if 52 - 52: IiII / i11iIiiIii * O0
  if 67 - 67: OOooOOo / I11i - I1Ii111 % i11iIiiIii
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
   if 3 - 3: oO0o + iII111i + OOooOOo
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
   if 54 - 54: i11iIiiIii + OoO0O00 - IiII - iII111i / I11i
   if 85 - 85: OOooOOo * OOooOOo * I1Ii111 - ooOoO0o . O0 % iII111i
   if 5 - 5: i1IIi * iII111i . o0oOOo0O0Ooo - I1ii11iIi11i
 def resolve_dns_name ( self ) :
  if ( self . dns_name == None ) : return
  if ( self . last_dns_resolve and
 time . time ( ) - self . last_dns_resolve < 30 ) : return
  if 84 - 84: i1IIi
  try :
   II111 = socket . gethostbyname_ex ( self . dns_name )
   self . last_dns_resolve = lisp_get_timestamp ( )
   II1Oo0o00ooOooo = II111 [ 2 ]
  except :
   return
   if 17 - 17: IiII + iII111i * OoO0O00 / iII111i
   if 67 - 67: i1IIi * IiII . OoOoOO00 % iIii1I11I1II1 - iIii1I11I1II1 * I1ii11iIi11i
   if 96 - 96: iII111i / i11iIiiIii / oO0o + Oo0Ooo
   if 65 - 65: OoOoOO00
   if 87 - 87: I11i % i1IIi + i11iIiiIii * II111iiii
   if 58 - 58: OoO0O00 * I1IiiI - II111iiii / Ii1I - I1IiiI % OoooooooOO
  if ( len ( II1Oo0o00ooOooo ) <= self . a_record_index ) :
   self . delete_ms ( )
   return
   if 33 - 33: IiII / i1IIi + I1Ii111
   if 5 - 5: O0 / iII111i % II111iiii . Oo0Ooo - I11i
  I1Iii1I = II1Oo0o00ooOooo [ self . a_record_index ]
  if ( I1Iii1I != self . map_server . print_address_no_iid ( ) ) :
   self . delete_ms ( )
   self . map_server . store_address ( I1Iii1I )
   self . insert_ms ( )
   if 84 - 84: oO0o * iII111i % i11iIiiIii - O0 . iIii1I11I1II1 - OoOoOO00
   if 73 - 73: OoOoOO00
   if 66 - 66: Oo0Ooo
   if 42 - 42: i11iIiiIii / II111iiii . OOooOOo
   if 65 - 65: OoOoOO00 % II111iiii + Oo0Ooo
   if 24 - 24: OoO0O00 % OoooooooOO
  if ( lisp_is_decent_dns_suffix ( self . dns_name ) == False ) : return
  if ( self . a_record_index != 0 ) : return
  if 16 - 16: OoOoOO00 % Oo0Ooo * OoOoOO00 . Ii1I
  for I1Iii1I in II1Oo0o00ooOooo [ 1 : : ] :
   OOOO0o = lisp_address ( LISP_AFI_NONE , I1Iii1I , 0 , 0 )
   iiI = lisp_get_map_server ( OOOO0o )
   if ( iiI != None and iiI . a_record_index == II1Oo0o00ooOooo . index ( I1Iii1I ) ) :
    continue
    if 91 - 91: I1Ii111 - OoooooooOO . i1IIi . I1ii11iIi11i
   iiI = copy . deepcopy ( self )
   iiI . map_server . store_address ( I1Iii1I )
   iiI . a_record_index = II1Oo0o00ooOooo . index ( I1Iii1I )
   iiI . last_dns_resolve = lisp_get_timestamp ( )
   iiI . insert_ms ( )
   if 37 - 37: IiII - oO0o
   if 92 - 92: I1IiiI
   if 51 - 51: OoO0O00 + Oo0Ooo - OOooOOo + I1ii11iIi11i
   if 32 - 32: I1ii11iIi11i % OoOoOO00 + Oo0Ooo
   if 92 - 92: II111iiii . O0 . iIii1I11I1II1 % IiII - i11iIiiIii
  I1iii11 = [ ]
  for iiI in lisp_map_servers_list . values ( ) :
   if ( self . dns_name != iiI . dns_name ) : continue
   OOOO0o = iiI . map_server . print_address_no_iid ( )
   if ( OOOO0o in II1Oo0o00ooOooo ) : continue
   I1iii11 . append ( iiI )
   if 9 - 9: OoO0O00
  for iiI in I1iii11 : iiI . delete_ms ( )
  if 60 - 60: O0 / OoOoOO00 % i11iIiiIii % II111iiii / OoooooooOO
  if 52 - 52: ooOoO0o
 def insert_ms ( self ) :
  iIIIi = self . ms_name + self . map_server . print_address ( )
  lisp_map_servers_list [ iIIIi ] = self
  if 100 - 100: Oo0Ooo - o0oOOo0O0Ooo + iIii1I11I1II1 / ooOoO0o % iIii1I11I1II1
  if 4 - 4: OoOoOO00 / Oo0Ooo - OoO0O00 . OoOoOO00 / I1Ii111
 def delete_ms ( self ) :
  iIIIi = self . ms_name + self . map_server . print_address ( )
  if ( lisp_map_servers_list . has_key ( iIIIi ) == False ) : return
  lisp_map_servers_list . pop ( iIIIi )
  if 60 - 60: OOooOOo * I1Ii111
  if 17 - 17: iII111i * I11i / iIii1I11I1II1 - II111iiii
  if 97 - 97: II111iiii * o0oOOo0O0Ooo
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
  if 13 - 13: o0oOOo0O0Ooo . II111iiii
  if 76 - 76: II111iiii + I1Ii111 . OoooooooOO / IiII % i11iIiiIii
 def add_interface ( self ) :
  lisp_myinterfaces [ self . device ] = self
  if 87 - 87: Ii1I / OoOoOO00 / OOooOOo
  if 11 - 11: o0oOOo0O0Ooo * OoO0O00 . o0oOOo0O0Ooo - I1IiiI / IiII - OOooOOo
 def get_instance_id ( self ) :
  return ( self . instance_id )
  if 19 - 19: i1IIi + IiII . OoO0O00 / O0 - I1Ii111 - Oo0Ooo
  if 24 - 24: iII111i + i1IIi
 def get_socket ( self ) :
  return ( self . raw_socket )
  if 31 - 31: OoOoOO00
  if 37 - 37: iIii1I11I1II1 % IiII / i11iIiiIii - oO0o
 def get_bridge_socket ( self ) :
  return ( self . bridge_socket )
  if 43 - 43: II111iiii - OoooooooOO
  if 11 - 11: I1IiiI
 def does_dynamic_eid_match ( self , eid ) :
  if ( self . dynamic_eid . is_null ( ) ) : return ( False )
  return ( eid . is_more_specific ( self . dynamic_eid ) )
  if 76 - 76: iII111i - II111iiii % Oo0Ooo . I1Ii111
  if 64 - 64: OoO0O00 - OoO0O00
 def set_socket ( self , device ) :
  i1I1iIi1IiI = socket . socket ( socket . AF_INET , socket . SOCK_RAW , socket . IPPROTO_RAW )
  i1I1iIi1IiI . setsockopt ( socket . SOL_IP , socket . IP_HDRINCL , 1 )
  try :
   i1I1iIi1IiI . setsockopt ( socket . SOL_SOCKET , socket . SO_BINDTODEVICE , device )
  except :
   i1I1iIi1IiI . close ( )
   i1I1iIi1IiI = None
   if 93 - 93: Oo0Ooo . O0
  self . raw_socket = i1I1iIi1IiI
  if 75 - 75: iII111i * II111iiii - I1IiiI
  if 30 - 30: i1IIi / ooOoO0o . ooOoO0o
 def set_bridge_socket ( self , device ) :
  i1I1iIi1IiI = socket . socket ( socket . PF_PACKET , socket . SOCK_RAW )
  try :
   i1I1iIi1IiI = i1I1iIi1IiI . bind ( ( device , 0 ) )
   self . bridge_socket = i1I1iIi1IiI
  except :
   return
   if 22 - 22: I11i % iIii1I11I1II1 - i11iIiiIii * OoOoOO00 - I1Ii111
   if 97 - 97: i11iIiiIii . OoOoOO00 + oO0o * O0 % OoO0O00 - Ii1I
   if 46 - 46: I1Ii111
   if 87 - 87: o0oOOo0O0Ooo - iII111i * OoO0O00 * o0oOOo0O0Ooo . o0oOOo0O0Ooo / OOooOOo
class lisp_datetime ( ) :
 def __init__ ( self , datetime_str ) :
  self . datetime_name = datetime_str
  self . datetime = None
  self . parse_datetime ( )
  if 50 - 50: i11iIiiIii - II111iiii * OoooooooOO + II111iiii - ooOoO0o
  if 52 - 52: i1IIi + i1IIi * i1IIi / OoOoOO00
 def valid_datetime ( self ) :
  O0iIIiii1ii1III = self . datetime_name
  if ( O0iIIiii1ii1III . find ( ":" ) == - 1 ) : return ( False )
  if ( O0iIIiii1ii1III . find ( "-" ) == - 1 ) : return ( False )
  oOOoOOOOo000 , Oo0iI11I1 , I1oo0OO , time = O0iIIiii1ii1III [ 0 : 4 ] , O0iIIiii1ii1III [ 5 : 7 ] , O0iIIiii1ii1III [ 8 : 10 ] , O0iIIiii1ii1III [ 11 : : ]
  if 85 - 85: I1Ii111 - Oo0Ooo / I11i + OoOoOO00 . O0 - Oo0Ooo
  if ( ( oOOoOOOOo000 + Oo0iI11I1 + I1oo0OO ) . isdigit ( ) == False ) : return ( False )
  if ( Oo0iI11I1 < "01" and Oo0iI11I1 > "12" ) : return ( False )
  if ( I1oo0OO < "01" and I1oo0OO > "31" ) : return ( False )
  if 24 - 24: I1IiiI + i1IIi
  i1IIII1ii1iiI1II , o0OOoo0o , ii1i1Ii1iI11I = time . split ( ":" )
  if 73 - 73: i1IIi % OoO0O00 + o0oOOo0O0Ooo - I1ii11iIi11i / oO0o * I1Ii111
  if ( ( i1IIII1ii1iiI1II + o0OOoo0o + ii1i1Ii1iI11I ) . isdigit ( ) == False ) : return ( False )
  if ( i1IIII1ii1iiI1II < "00" and i1IIII1ii1iiI1II > "23" ) : return ( False )
  if ( o0OOoo0o < "00" and o0OOoo0o > "59" ) : return ( False )
  if ( ii1i1Ii1iI11I < "00" and ii1i1Ii1iI11I > "59" ) : return ( False )
  return ( True )
  if 60 - 60: OoooooooOO
  if 88 - 88: iIii1I11I1II1 % I1IiiI * oO0o / i11iIiiIii % OoOoOO00
 def parse_datetime ( self ) :
  oOOo0O000O0O = self . datetime_name
  oOOo0O000O0O = oOOo0O000O0O . replace ( "-" , "" )
  oOOo0O000O0O = oOOo0O000O0O . replace ( ":" , "" )
  self . datetime = int ( oOOo0O000O0O )
  if 30 - 30: II111iiii - I1Ii111 * Oo0Ooo
  if 21 - 21: OoOoOO00 + IiII - i1IIi - O0
 def now ( self ) :
  III11I1 = datetime . datetime . now ( ) . strftime ( "%Y-%m-%d-%H:%M:%S" )
  III11I1 = lisp_datetime ( III11I1 )
  return ( III11I1 )
  if 8 - 8: OoooooooOO . IiII . Oo0Ooo - Oo0Ooo % o0oOOo0O0Ooo
  if 8 - 8: I11i % o0oOOo0O0Ooo
 def print_datetime ( self ) :
  return ( self . datetime_name )
  if 39 - 39: OoooooooOO - I1Ii111 . i1IIi . I1ii11iIi11i
  if 72 - 72: I1ii11iIi11i % Ii1I
 def future ( self ) :
  return ( self . datetime > self . now ( ) . datetime )
  if 37 - 37: O0
  if 41 - 41: iII111i . Ii1I . OoooooooOO / OoOoOO00
 def past ( self ) :
  return ( self . future ( ) == False )
  if 85 - 85: II111iiii - II111iiii
  if 95 - 95: II111iiii + II111iiii + iII111i
 def now_in_range ( self , upper ) :
  return ( self . past ( ) and upper . future ( ) )
  if 38 - 38: OoO0O00 * Ii1I * O0 / I1IiiI
  if 99 - 99: Oo0Ooo + ooOoO0o - I1ii11iIi11i + I1Ii111 + Ii1I * I1IiiI
 def this_year ( self ) :
  o0Oo0O0 = str ( self . now ( ) . datetime ) [ 0 : 4 ]
  III11I1 = str ( self . datetime ) [ 0 : 4 ]
  return ( III11I1 == o0Oo0O0 )
  if 49 - 49: I1Ii111
  if 92 - 92: ooOoO0o
 def this_month ( self ) :
  o0Oo0O0 = str ( self . now ( ) . datetime ) [ 0 : 6 ]
  III11I1 = str ( self . datetime ) [ 0 : 6 ]
  return ( III11I1 == o0Oo0O0 )
  if 82 - 82: ooOoO0o
  if 80 - 80: I1Ii111 / I11i - Oo0Ooo / IiII % O0
 def today ( self ) :
  o0Oo0O0 = str ( self . now ( ) . datetime ) [ 0 : 8 ]
  III11I1 = str ( self . datetime ) [ 0 : 8 ]
  return ( III11I1 == o0Oo0O0 )
  if 67 - 67: i11iIiiIii / I11i - iII111i - OOooOOo . II111iiii
  if 16 - 16: Ii1I * iIii1I11I1II1 + i11iIiiIii - OoOoOO00 - o0oOOo0O0Ooo
  if 60 - 60: O0 - iIii1I11I1II1
  if 56 - 56: OOooOOo * o0oOOo0O0Ooo - O0
  if 45 - 45: OOooOOo - OoO0O00
  if 49 - 49: OoOoOO00 / o0oOOo0O0Ooo % OoO0O00
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
  if 50 - 50: iIii1I11I1II1 - OoooooooOO + I1ii11iIi11i / Oo0Ooo * OOooOOo
  if 37 - 37: O0 % I1Ii111 * OOooOOo / OOooOOo
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
  if 95 - 95: I1ii11iIi11i % o0oOOo0O0Ooo . oO0o
  if 9 - 9: OoOoOO00 % OoOoOO00 * ooOoO0o / I1IiiI - OOooOOo
 def match_policy_map_request ( self , mr , srloc ) :
  for oOo00 in self . match_clauses :
   oo000o = oOo00 . source_eid
   I1IiI1iIII1I = mr . source_eid
   if ( oo000o and I1IiI1iIII1I and I1IiI1iIII1I . is_more_specific ( oo000o ) == False ) : continue
   if 62 - 62: Oo0Ooo + OOooOOo - Oo0Ooo
   oo000o = oOo00 . dest_eid
   I1IiI1iIII1I = mr . target_eid
   if ( oo000o and I1IiI1iIII1I and I1IiI1iIII1I . is_more_specific ( oo000o ) == False ) : continue
   if 32 - 32: OoooooooOO
   oo000o = oOo00 . source_rloc
   I1IiI1iIII1I = srloc
   if ( oo000o and I1IiI1iIII1I and I1IiI1iIII1I . is_more_specific ( oo000o ) == False ) : continue
   i1I1i = oOo00 . datetime_lower
   OooOoO0OOoo = oOo00 . datetime_upper
   if ( i1I1i and OooOoO0OOoo and i1I1i . now_in_range ( OooOoO0OOoo ) == False ) : continue
   return ( True )
   if 90 - 90: OoOoOO00 % OoO0O00 . I1IiiI * oO0o
  return ( False )
  if 17 - 17: O0 - i1IIi
  if 77 - 77: OOooOOo - i1IIi / II111iiii . I1Ii111 + O0
 def set_policy_map_reply ( self ) :
  ii1iIiI111 = ( self . set_rloc_address == None and
 self . set_rloc_record_name == None and self . set_geo_name == None and
 self . set_elp_name == None and self . set_rle_name == None )
  if ( ii1iIiI111 ) : return ( None )
  if 21 - 21: i11iIiiIii . IiII - OoooooooOO
  oOoOoo0O = lisp_rloc ( )
  if ( self . set_rloc_address ) :
   oOoOoo0O . rloc . copy_address ( self . set_rloc_address )
   I1Iii1I = oOoOoo0O . rloc . print_address_no_iid ( )
   lprint ( "Policy set-rloc-address to {}" . format ( I1Iii1I ) )
   if 72 - 72: iII111i
  if ( self . set_rloc_record_name ) :
   oOoOoo0O . rloc_name = self . set_rloc_record_name
   i1i1IIi1II = blue ( oOoOoo0O . rloc_name , False )
   lprint ( "Policy set-rloc-record-name to {}" . format ( i1i1IIi1II ) )
   if 80 - 80: Oo0Ooo
  if ( self . set_geo_name ) :
   oOoOoo0O . geo_name = self . set_geo_name
   i1i1IIi1II = oOoOoo0O . geo_name
   ii1I1iii = "" if lisp_geo_list . has_key ( i1i1IIi1II ) else "(not configured)"
   if 78 - 78: OOooOOo % o0oOOo0O0Ooo . I11i
   lprint ( "Policy set-geo-name '{}' {}" . format ( i1i1IIi1II , ii1I1iii ) )
   if 21 - 21: iIii1I11I1II1 - iIii1I11I1II1 / IiII + I1ii11iIi11i / OoO0O00
  if ( self . set_elp_name ) :
   oOoOoo0O . elp_name = self . set_elp_name
   i1i1IIi1II = oOoOoo0O . elp_name
   ii1I1iii = "" if lisp_elp_list . has_key ( i1i1IIi1II ) else "(not configured)"
   if 15 - 15: oO0o + O0
   lprint ( "Policy set-elp-name '{}' {}" . format ( i1i1IIi1II , ii1I1iii ) )
   if 59 - 59: I1Ii111
  if ( self . set_rle_name ) :
   oOoOoo0O . rle_name = self . set_rle_name
   i1i1IIi1II = oOoOoo0O . rle_name
   ii1I1iii = "" if lisp_rle_list . has_key ( i1i1IIi1II ) else "(not configured)"
   if 88 - 88: o0oOOo0O0Ooo % I1Ii111
   lprint ( "Policy set-rle-name '{}' {}" . format ( i1i1IIi1II , ii1I1iii ) )
   if 4 - 4: i11iIiiIii + o0oOOo0O0Ooo % I11i - I1ii11iIi11i * I1ii11iIi11i
  if ( self . set_json_name ) :
   oOoOoo0O . json_name = self . set_json_name
   i1i1IIi1II = oOoOoo0O . json_name
   ii1I1iii = "" if lisp_json_list . has_key ( i1i1IIi1II ) else "(not configured)"
   if 87 - 87: I1Ii111 % i11iIiiIii + O0
   lprint ( "Policy set-json-name '{}' {}" . format ( i1i1IIi1II , ii1I1iii ) )
   if 67 - 67: OoooooooOO / i1IIi / ooOoO0o . i1IIi - i11iIiiIii . i1IIi
  return ( oOoOoo0O )
  if 41 - 41: i11iIiiIii / ooOoO0o - Ii1I + I11i
  if 15 - 15: I1ii11iIi11i
 def save_policy ( self ) :
  lisp_policies [ self . policy_name ] = self
  if 22 - 22: iIii1I11I1II1 - i1IIi - i11iIiiIii / I1IiiI + o0oOOo0O0Ooo
  if 56 - 56: I1IiiI . ooOoO0o
  if 35 - 35: iIii1I11I1II1 % Oo0Ooo + o0oOOo0O0Ooo * o0oOOo0O0Ooo % ooOoO0o
class lisp_pubsub ( ) :
 def __init__ ( self , itr , port , nonce , ttl , xtr_id ) :
  self . itr = itr
  self . port = port
  self . nonce = nonce
  self . uptime = lisp_get_timestamp ( )
  self . ttl = ttl
  self . xtr_id = xtr_id
  self . map_notify_count = 0
  if 10 - 10: I1ii11iIi11i / II111iiii % II111iiii - OoooooooOO * o0oOOo0O0Ooo / ooOoO0o
  if 26 - 26: OoO0O00 . O0 * iII111i % OoOoOO00 % iIii1I11I1II1
 def add ( self , eid_prefix ) :
  ooOOooooo0Oo = self . ttl
  Ooo0 = eid_prefix . print_prefix ( )
  if ( lisp_pubsub_cache . has_key ( Ooo0 ) == False ) :
   lisp_pubsub_cache [ Ooo0 ] = { }
   if 37 - 37: iII111i - ooOoO0o * Ii1I + II111iiii * i11iIiiIii
  O0o00OOOO0O = lisp_pubsub_cache [ Ooo0 ]
  if 8 - 8: OoooooooOO % I11i - iII111i * OOooOOo . O0
  I1IIiIiiiii1 = "Add"
  if ( O0o00OOOO0O . has_key ( self . xtr_id ) ) :
   I1IIiIiiiii1 = "Replace"
   del ( O0o00OOOO0O [ self . xtr_id ] )
   if 7 - 7: I1ii11iIi11i
  O0o00OOOO0O [ self . xtr_id ] = self
  if 29 - 29: I11i - ooOoO0o
  Ooo0 = green ( Ooo0 , False )
  IiI1IIii = red ( self . itr . print_address_no_iid ( ) , False )
  IIIiIIi111 = "0x" + lisp_hex_string ( self . xtr_id )
  lprint ( "{} pubsub state {} for {}, xtr-id: {}, ttl {}" . format ( I1IIiIiiiii1 , Ooo0 ,
 IiI1IIii , IIIiIIi111 , ooOOooooo0Oo ) )
  if 1 - 1: o0oOOo0O0Ooo + iIii1I11I1II1 + I1ii11iIi11i
  if 40 - 40: I1Ii111
 def delete ( self , eid_prefix ) :
  Ooo0 = eid_prefix . print_prefix ( )
  IiI1IIii = red ( self . itr . print_address_no_iid ( ) , False )
  IIIiIIi111 = "0x" + lisp_hex_string ( self . xtr_id )
  if ( lisp_pubsub_cache . has_key ( Ooo0 ) ) :
   O0o00OOOO0O = lisp_pubsub_cache [ Ooo0 ]
   if ( O0o00OOOO0O . has_key ( self . xtr_id ) ) :
    O0o00OOOO0O . pop ( self . xtr_id )
    lprint ( "Remove pubsub state {} for {}, xtr-id: {}" . format ( Ooo0 ,
 IiI1IIii , IIIiIIi111 ) )
    if 18 - 18: OoOoOO00 * Ii1I
    if 81 - 81: IiII . i11iIiiIii - I1IiiI * i11iIiiIii + OoO0O00
    if 94 - 94: I1ii11iIi11i + OoO0O00 . II111iiii + oO0o . II111iiii
    if 96 - 96: i11iIiiIii
    if 66 - 66: ooOoO0o * iII111i - iII111i - O0 . o0oOOo0O0Ooo
    if 23 - 23: iIii1I11I1II1 / I11i % OoOoOO00 . OoO0O00
    if 90 - 90: iIii1I11I1II1 - OOooOOo . Ii1I % OoO0O00
    if 89 - 89: i11iIiiIii
    if 86 - 86: Oo0Ooo % iIii1I11I1II1 . II111iiii / I11i % OoO0O00 % OoO0O00
    if 40 - 40: o0oOOo0O0Ooo . iIii1I11I1II1 * Oo0Ooo * i1IIi
    if 94 - 94: oO0o - II111iiii + OoOoOO00
    if 90 - 90: Oo0Ooo + Oo0Ooo + I1Ii111
    if 81 - 81: i1IIi % iIii1I11I1II1 % Ii1I * ooOoO0o % i1IIi * I1IiiI
    if 15 - 15: ooOoO0o
    if 26 - 26: IiII % ooOoO0o / OOooOOo
    if 14 - 14: i11iIiiIii . I1ii11iIi11i
    if 20 - 20: O0 . iIii1I11I1II1 * I1ii11iIi11i - O0 + I1ii11iIi11i / I1IiiI
    if 67 - 67: OoO0O00 / OoOoOO00 / i11iIiiIii % OoOoOO00
    if 54 - 54: o0oOOo0O0Ooo . i11iIiiIii + I1IiiI * ooOoO0o - ooOoO0o
    if 28 - 28: I1Ii111 . i11iIiiIii * oO0o % ooOoO0o / iII111i . OOooOOo
    if 57 - 57: OoooooooOO . iIii1I11I1II1 % iII111i % Oo0Ooo
    if 92 - 92: I1Ii111 - Ii1I + I1Ii111
class lisp_trace ( ) :
 def __init__ ( self ) :
  self . nonce = lisp_get_control_nonce ( )
  self . packet_json = [ ]
  self . local_rloc = None
  self . local_port = None
  self . lisp_socket = None
  if 8 - 8: Oo0Ooo . iII111i / i11iIiiIii + iIii1I11I1II1 - OoOoOO00
  if 1 - 1: i11iIiiIii
 def print_trace ( self ) :
  Iiii = self . packet_json
  lprint ( "LISP-Trace JSON: '{}'" . format ( Iiii ) )
  if 98 - 98: OoOoOO00 - O0 . O0 + ooOoO0o * iIii1I11I1II1
  if 7 - 7: IiII * OoOoOO00 + iIii1I11I1II1 / OoOoOO00 + Oo0Ooo / o0oOOo0O0Ooo
 def encode ( self ) :
  ooOOOo0 = socket . htonl ( 0x90000000 )
  I1IiO00Ooo0ooo0 = struct . pack ( "II" , ooOOOo0 , 0 )
  I1IiO00Ooo0ooo0 += struct . pack ( "Q" , self . nonce )
  I1IiO00Ooo0ooo0 += json . dumps ( self . packet_json )
  return ( I1IiO00Ooo0ooo0 )
  if 77 - 77: i1IIi . I1IiiI
  if 59 - 59: O0 + OoooooooOO - i1IIi
 def decode ( self , packet ) :
  O0000 = "I"
  I1 = struct . calcsize ( O0000 )
  if ( len ( packet ) < I1 ) : return ( False )
  ooOOOo0 = struct . unpack ( O0000 , packet [ : I1 ] ) [ 0 ]
  packet = packet [ I1 : : ]
  ooOOOo0 = socket . ntohl ( ooOOOo0 )
  if ( ( ooOOOo0 & 0xff000000 ) != 0x90000000 ) : return ( False )
  if 87 - 87: IiII * OoooooooOO / Oo0Ooo % iIii1I11I1II1 % oO0o
  if ( len ( packet ) < I1 ) : return ( False )
  I1Iii1I = struct . unpack ( O0000 , packet [ : I1 ] ) [ 0 ]
  packet = packet [ I1 : : ]
  if 97 - 97: ooOoO0o % i1IIi . IiII / Oo0Ooo . I1Ii111 . OoO0O00
  I1Iii1I = socket . ntohl ( I1Iii1I )
  i1iIiI = I1Iii1I >> 24
  iiiii1Ii111i = ( I1Iii1I >> 16 ) & 0xff
  o0OOOo0o = ( I1Iii1I >> 8 ) & 0xff
  i1iII1iI = I1Iii1I & 0xff
  self . local_rloc = "{}.{}.{}.{}" . format ( i1iIiI , iiiii1Ii111i , o0OOOo0o , i1iII1iI )
  self . local_port = str ( ooOOOo0 & 0xffff )
  if 74 - 74: ooOoO0o - iII111i * OoooooooOO . ooOoO0o
  O0000 = "Q"
  I1 = struct . calcsize ( O0000 )
  if ( len ( packet ) < I1 ) : return ( False )
  self . nonce = struct . unpack ( O0000 , packet [ : I1 ] ) [ 0 ]
  packet = packet [ I1 : : ]
  if ( len ( packet ) == 0 ) : return ( True )
  if 35 - 35: I1Ii111 - iII111i . I11i . O0
  try :
   self . packet_json = json . loads ( packet )
  except :
   return ( False )
   if 87 - 87: OOooOOo * ooOoO0o / OoO0O00 / OoO0O00
  return ( True )
  if 10 - 10: I11i % OOooOOo % i1IIi + I1IiiI - iIii1I11I1II1 + O0
  if 9 - 9: oO0o % Ii1I
 def myeid ( self , eid ) :
  return ( lisp_is_myeid ( eid ) )
  if 20 - 20: OoooooooOO - OoooooooOO + Ii1I % I1Ii111
  if 54 - 54: IiII % oO0o + i11iIiiIii % O0
 def return_to_sender ( self , lisp_socket , rts_rloc , packet ) :
  oOoOoo0O , i1O0OO = self . rtr_cache_nat_trace_find ( rts_rloc )
  if ( oOoOoo0O == None ) :
   oOoOoo0O , i1O0OO = rts_rloc . split ( ":" )
   i1O0OO = int ( i1O0OO )
   lprint ( "Send LISP-Trace to address {}:{}" . format ( oOoOoo0O , i1O0OO ) )
  else :
   lprint ( "Send LISP-Trace to translated address {}:{}" . format ( oOoOoo0O ,
 i1O0OO ) )
   if 56 - 56: OoOoOO00 / II111iiii . O0
   if 24 - 24: OoooooooOO * Ii1I * II111iiii
  if ( lisp_socket == None ) :
   i1I1iIi1IiI = socket . socket ( socket . AF_INET , socket . SOCK_DGRAM )
   i1I1iIi1IiI . bind ( ( "0.0.0.0" , LISP_TRACE_PORT ) )
   i1I1iIi1IiI . sendto ( packet , ( oOoOoo0O , i1O0OO ) )
   i1I1iIi1IiI . close ( )
  else :
   lisp_socket . sendto ( packet , ( oOoOoo0O , i1O0OO ) )
   if 75 - 75: I1IiiI / o0oOOo0O0Ooo . Ii1I / Ii1I / iII111i - Ii1I
   if 39 - 39: OoO0O00 . iIii1I11I1II1 - oO0o
   if 60 - 60: OOooOOo + OOooOOo - Ii1I / iII111i
 def packet_length ( self ) :
  IIi1ii1 = 8 ; I1II1II1IiI = 4 + 4 + 8
  return ( IIi1ii1 + I1II1II1IiI + len ( json . dumps ( self . packet_json ) ) )
  if 60 - 60: iII111i - OoooooooOO
  if 65 - 65: II111iiii * iII111i
 def rtr_cache_nat_trace ( self , translated_rloc , translated_port ) :
  iIIIi = self . local_rloc + ":" + self . local_port
  oOOO = ( translated_rloc , translated_port )
  lisp_rtr_nat_trace_cache [ iIIIi ] = oOOO
  lprint ( "Cache NAT Trace addresses {} -> {}" . format ( iIIIi , oOOO ) )
  if 90 - 90: I11i . O0 + oO0o
  if 63 - 63: I11i . I1IiiI + OoooooooOO + O0
 def rtr_cache_nat_trace_find ( self , local_rloc_and_port ) :
  iIIIi = local_rloc_and_port
  try : oOOO = lisp_rtr_nat_trace_cache [ iIIIi ]
  except : oOOO = ( None , None )
  return ( oOOO )
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
def lisp_get_map_server ( address ) :
 for iiI in lisp_map_servers_list . values ( ) :
  if ( iiI . map_server . is_exact_match ( address ) ) : return ( iiI )
  if 17 - 17: OoO0O00
 return ( None )
 if 79 - 79: Ii1I - II111iiii
 if 57 - 57: II111iiii / OoooooooOO
 if 4 - 4: I11i * OoOoOO00
 if 18 - 18: iIii1I11I1II1 % OOooOOo - I1ii11iIi11i * i1IIi + Oo0Ooo
 if 87 - 87: oO0o . I11i
 if 15 - 15: oO0o
 if 45 - 45: Oo0Ooo * IiII * OoO0O00 + iIii1I11I1II1
def lisp_get_any_map_server ( ) :
 for iiI in lisp_map_servers_list . values ( ) : return ( iiI )
 return ( None )
 if 89 - 89: IiII . IiII . oO0o % iII111i
 if 27 - 27: OoOoOO00 + O0 % i1IIi - Oo0Ooo
 if 96 - 96: O0 % o0oOOo0O0Ooo + OOooOOo % I1IiiI
 if 51 - 51: i1IIi . o0oOOo0O0Ooo % I1IiiI - OoooooooOO / OoOoOO00 - I11i
 if 45 - 45: O0 * II111iiii / i11iIiiIii
 if 38 - 38: OoooooooOO % i11iIiiIii - O0 / O0
 if 59 - 59: OoO0O00 % iII111i + oO0o * II111iiii . OOooOOo
 if 26 - 26: OOooOOo % OoooooooOO . Ii1I / iIii1I11I1II1 * I1IiiI
 if 85 - 85: IiII / Ii1I - I1ii11iIi11i * OOooOOo
 if 19 - 19: I1ii11iIi11i
def lisp_get_map_resolver ( address , eid ) :
 if ( address != None ) :
  I1Iii1I = address . print_address ( )
  oOoooooOooO = None
  for iIIIi in lisp_map_resolvers_list :
   if ( iIIIi . find ( I1Iii1I ) == - 1 ) : continue
   oOoooooOooO = lisp_map_resolvers_list [ iIIIi ]
   if 12 - 12: ooOoO0o * I1ii11iIi11i * O0 / oO0o + iII111i - iIii1I11I1II1
  return ( oOoooooOooO )
  if 81 - 81: Ii1I
  if 87 - 87: O0 % iII111i
  if 57 - 57: Ii1I
  if 49 - 49: I11i
  if 22 - 22: Oo0Ooo % OOooOOo + O0 - OoO0O00 % I11i * O0
  if 42 - 42: O0
  if 55 - 55: i11iIiiIii % OOooOOo
 if ( eid == "" ) :
  iIiiI = ""
 elif ( eid == None ) :
  iIiiI = "all"
 else :
  i1iOo = lisp_db_for_lookups . lookup_cache ( eid , False )
  iIiiI = "all" if i1iOo == None else i1iOo . use_mr_name
  if 57 - 57: i1IIi / I11i + OoO0O00 * OOooOOo + OoooooooOO
  if 30 - 30: I1Ii111 . IiII . iIii1I11I1II1 % o0oOOo0O0Ooo + iIii1I11I1II1
 ooOOO000OO = None
 for oOoooooOooO in lisp_map_resolvers_list . values ( ) :
  if ( iIiiI == "" ) : return ( oOoooooOooO )
  if ( oOoooooOooO . mr_name != iIiiI ) : continue
  if ( ooOOO000OO == None or oOoooooOooO . last_used < ooOOO000OO . last_used ) : ooOOO000OO = oOoooooOooO
  if 33 - 33: I1Ii111
 return ( ooOOO000OO )
 if 97 - 97: Ii1I / iII111i - ooOoO0o + IiII * OoOoOO00 - OOooOOo
 if 43 - 43: oO0o / II111iiii - iII111i / oO0o
 if 98 - 98: OoOoOO00 / OOooOOo
 if 31 - 31: II111iiii % I11i - I11i
 if 17 - 17: iII111i . IiII + OOooOOo % I1Ii111 % i11iIiiIii
 if 100 - 100: i11iIiiIii - O0 . OoO0O00 / O0 - Ii1I - IiII
 if 72 - 72: Ii1I % O0 + II111iiii . i11iIiiIii
 if 66 - 66: II111iiii % I1IiiI
def lisp_get_decent_map_resolver ( eid ) :
 OOOoO000 = lisp_get_decent_index ( eid )
 OoOo00o0o0oO = str ( OOOoO000 ) + "." + lisp_decent_dns_suffix
 if 37 - 37: OoO0O00 % o0oOOo0O0Ooo * O0 * O0 + iII111i
 lprint ( "Use LISP-Decent map-resolver {} for EID {}" . format ( bold ( OoOo00o0o0oO , False ) , eid . print_prefix ( ) ) )
 if 18 - 18: i11iIiiIii . o0oOOo0O0Ooo - OOooOOo % oO0o * Ii1I / I1IiiI
 if 46 - 46: o0oOOo0O0Ooo . ooOoO0o / Ii1I
 ooOOO000OO = None
 for oOoooooOooO in lisp_map_resolvers_list . values ( ) :
  if ( OoOo00o0o0oO != oOoooooOooO . dns_name ) : continue
  if ( ooOOO000OO == None or oOoooooOooO . last_used < ooOOO000OO . last_used ) : ooOOO000OO = oOoooooOooO
  if 97 - 97: Ii1I . Oo0Ooo - O0 - I1Ii111 . i1IIi
 return ( ooOOO000OO )
 if 47 - 47: IiII * ooOoO0o - i1IIi % OoOoOO00 * i11iIiiIii . OoooooooOO
 if 84 - 84: OoOoOO00 / IiII - i1IIi - I1IiiI * OOooOOo
 if 35 - 35: II111iiii
 if 28 - 28: I1Ii111 + IiII + I1ii11iIi11i . Ii1I
 if 82 - 82: ooOoO0o - ooOoO0o . Ii1I . i11iIiiIii % Ii1I + OOooOOo
 if 33 - 33: Oo0Ooo - OOooOOo / OoOoOO00 % II111iiii % OOooOOo + I1Ii111
 if 41 - 41: I11i + Oo0Ooo . Oo0Ooo / iII111i . OoOoOO00
def lisp_ipv4_input ( packet ) :
 if 1 - 1: ooOoO0o + iII111i % i11iIiiIii / OoOoOO00
 if 98 - 98: IiII
 if 75 - 75: OoooooooOO % IiII + Ii1I - i1IIi / OoooooooOO
 if 57 - 57: iII111i
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
   if 18 - 18: II111iiii % i11iIiiIii + I11i - OOooOOo
   if 100 - 100: o0oOOo0O0Ooo / Ii1I - iIii1I11I1II1 / oO0o
   if 68 - 68: I11i / II111iiii * oO0o . II111iiii * OOooOOo
   if 78 - 78: I11i * OoO0O00 / II111iiii
   if 86 - 86: I1Ii111 % II111iiii
   if 90 - 90: OoO0O00 / I11i - Oo0Ooo
   if 76 - 76: O0 + OoO0O00 / ooOoO0o . II111iiii * iIii1I11I1II1 . I1Ii111
 ooOOooooo0Oo = struct . unpack ( "B" , packet [ 8 : 9 ] ) [ 0 ]
 if ( ooOOooooo0Oo == 0 ) :
  dprint ( "IPv4 packet arrived with ttl 0, packet discarded" )
  return ( None )
 elif ( ooOOooooo0Oo == 1 ) :
  dprint ( "IPv4 packet {}, packet discarded" . format ( bold ( "ttl expiry" , False ) ) )
  if 43 - 43: Oo0Ooo + o0oOOo0O0Ooo % o0oOOo0O0Ooo % I1ii11iIi11i / iIii1I11I1II1 . I1ii11iIi11i
  return ( None )
  if 59 - 59: IiII . OoO0O00 - OoooooooOO . O0
  if 33 - 33: Ii1I
 ooOOooooo0Oo -= 1
 packet = packet [ 0 : 8 ] + struct . pack ( "B" , ooOOooooo0Oo ) + packet [ 9 : : ]
 packet = packet [ 0 : 10 ] + struct . pack ( "H" , 0 ) + packet [ 12 : : ]
 packet = lisp_ip_checksum ( packet )
 return ( packet )
 if 95 - 95: OoooooooOO + OoO0O00 * ooOoO0o
 if 40 - 40: I1IiiI / OOooOOo * Ii1I
 if 98 - 98: I1IiiI
 if 4 - 4: I1IiiI % O0 / Oo0Ooo / O0
 if 90 - 90: ooOoO0o - O0 . IiII - O0 . iIii1I11I1II1
 if 42 - 42: I1ii11iIi11i
 if 51 - 51: iII111i % i11iIiiIii . OoO0O00 . IiII - OoOoOO00 * i1IIi
def lisp_ipv6_input ( packet ) :
 I1I1I1 = packet . inner_dest
 packet = packet . packet
 if 14 - 14: I1ii11iIi11i . OoO0O00
 if 26 - 26: iII111i / ooOoO0o / Oo0Ooo / Oo0Ooo . I1ii11iIi11i * OOooOOo
 if 25 - 25: IiII % I1IiiI / O0 % OOooOOo - OoooooooOO
 if 29 - 29: O0 + iII111i
 if 4 - 4: I11i * I11i - Ii1I * oO0o . I1ii11iIi11i % o0oOOo0O0Ooo
 ooOOooooo0Oo = struct . unpack ( "B" , packet [ 7 : 8 ] ) [ 0 ]
 if ( ooOOooooo0Oo == 0 ) :
  dprint ( "IPv6 packet arrived with hop-limit 0, packet discarded" )
  return ( None )
 elif ( ooOOooooo0Oo == 1 ) :
  dprint ( "IPv6 packet {}, packet discarded" . format ( bold ( "ttl expiry" , False ) ) )
  if 33 - 33: Ii1I * i11iIiiIii / O0 . Oo0Ooo + i1IIi . OoOoOO00
  return ( None )
  if 76 - 76: OoooooooOO - O0
  if 17 - 17: Oo0Ooo % I1Ii111 . oO0o - O0
  if 32 - 32: O0 % O0
  if 66 - 66: iII111i / i1IIi - Oo0Ooo . Ii1I
  if 65 - 65: I1ii11iIi11i % ooOoO0o - OoOoOO00 + ooOoO0o + Oo0Ooo
 if ( I1I1I1 . is_ipv6_link_local ( ) ) :
  dprint ( "Do not encapsulate IPv6 link-local packets" )
  return ( None )
  if 95 - 95: I1Ii111 * i11iIiiIii - I1IiiI - OoOoOO00 . ooOoO0o
  if 34 - 34: OoooooooOO % I1ii11iIi11i + OoooooooOO % i11iIiiIii / IiII - ooOoO0o
 ooOOooooo0Oo -= 1
 packet = packet [ 0 : 7 ] + struct . pack ( "B" , ooOOooooo0Oo ) + packet [ 8 : : ]
 return ( packet )
 if 74 - 74: iIii1I11I1II1 % II111iiii + IiII
 if 71 - 71: I1IiiI / O0 * i1IIi . i1IIi + Oo0Ooo
 if 32 - 32: i1IIi * I1Ii111 % I1IiiI / IiII . I1Ii111
 if 11 - 11: OOooOOo
 if 25 - 25: i1IIi
 if 99 - 99: OOooOOo + OoooooooOO . I1Ii111 * Oo0Ooo % oO0o
 if 75 - 75: iII111i
 if 8 - 8: I1ii11iIi11i . I11i / I1ii11iIi11i - i1IIi
def lisp_mac_input ( packet ) :
 return ( packet )
 if 22 - 22: OOooOOo
 if 7 - 7: O0 - I1ii11iIi11i - OoO0O00 * I1Ii111
 if 17 - 17: o0oOOo0O0Ooo % OoO0O00 - I11i * o0oOOo0O0Ooo - i1IIi / I1IiiI
 if 100 - 100: OoO0O00 * i1IIi * o0oOOo0O0Ooo * Oo0Ooo - o0oOOo0O0Ooo
 if 100 - 100: iII111i - i11iIiiIii + OoO0O00
 if 50 - 50: II111iiii
 if 42 - 42: OOooOOo * I1Ii111
 if 53 - 53: II111iiii % OOooOOo / I1ii11iIi11i * OoOoOO00 % I1ii11iIi11i * iII111i
 if 91 - 91: iII111i . OoooooooOO
def lisp_rate_limit_map_request ( source , dest ) :
 if ( lisp_last_map_request_sent == None ) : return ( False )
 o0Oo0O0 = lisp_get_timestamp ( )
 ooooOoO0O = o0Oo0O0 - lisp_last_map_request_sent
 oooOO000 = ( ooooOoO0O < LISP_MAP_REQUEST_RATE_LIMIT )
 if 20 - 20: I1IiiI % Oo0Ooo - OoO0O00 - I1Ii111 - II111iiii
 if ( oooOO000 ) :
  if ( source != None ) : source = source . print_address ( )
  dest = dest . print_address ( )
  dprint ( "Rate-limiting Map-Request for {} -> {}" . format ( source , dest ) )
  if 79 - 79: II111iiii - II111iiii + OoOoOO00 / iII111i % OoooooooOO - OoO0O00
 return ( oooOO000 )
 if 22 - 22: o0oOOo0O0Ooo + I1Ii111 . Oo0Ooo
 if 84 - 84: O0 + I1IiiI % Oo0Ooo + OOooOOo
 if 94 - 94: OOooOOo
 if 81 - 81: i11iIiiIii + iIii1I11I1II1 . i11iIiiIii / OOooOOo / iII111i
 if 34 - 34: i11iIiiIii - o0oOOo0O0Ooo * OoooooooOO * I1ii11iIi11i * Oo0Ooo % I1ii11iIi11i
 if 31 - 31: I11i . o0oOOo0O0Ooo
 if 82 - 82: I11i - Oo0Ooo
def lisp_send_map_request ( lisp_sockets , lisp_ephem_port , seid , deid , rloc ) :
 global lisp_last_map_request_sent
 if 77 - 77: I1IiiI + OoO0O00 % iIii1I11I1II1 - OOooOOo
 if 80 - 80: oO0o % I1ii11iIi11i * I1Ii111 + i1IIi
 if 79 - 79: oO0o + IiII
 if 4 - 4: iII111i + OoooooooOO / I1Ii111
 if 57 - 57: I1IiiI . iIii1I11I1II1 % iII111i * iII111i / I1Ii111
 if 30 - 30: O0 / I11i % OoOoOO00 * I1Ii111 / O0 % ooOoO0o
 IiOo = oO0ooO0O00OO = None
 if ( rloc ) :
  IiOo = rloc . rloc
  oO0ooO0O00OO = rloc . translated_port if lisp_i_am_rtr else LISP_DATA_PORT
  if 55 - 55: Oo0Ooo * i11iIiiIii / OOooOOo
  if 10 - 10: OoooooooOO * i1IIi . I1IiiI
  if 8 - 8: I1ii11iIi11i . OoO0O00 % o0oOOo0O0Ooo / O0
  if 51 - 51: oO0o + Ii1I * Ii1I * I1ii11iIi11i % I11i - I1ii11iIi11i
  if 15 - 15: i1IIi / OoO0O00 - Oo0Ooo
 OOO0oo00oO , Iii1I1i11II , Ooooo = lisp_myrlocs
 if ( OOO0oo00oO == None ) :
  lprint ( "Suppress sending Map-Request, IPv4 RLOC not found" )
  return
  if 13 - 13: iIii1I11I1II1 + iIii1I11I1II1
 if ( Iii1I1i11II == None and IiOo != None and IiOo . is_ipv6 ( ) ) :
  lprint ( "Suppress sending Map-Request, IPv6 RLOC not found" )
  return
  if 11 - 11: Ii1I * OoO0O00 % I1ii11iIi11i
  if 60 - 60: i11iIiiIii % II111iiii % I11i
 Ii1 = lisp_map_request ( )
 Ii1 . record_count = 1
 Ii1 . nonce = lisp_get_control_nonce ( )
 Ii1 . rloc_probe = ( IiOo != None )
 if 92 - 92: O0 * OoooooooOO + I1ii11iIi11i / IiII
 if 97 - 97: o0oOOo0O0Ooo . Ii1I + I1Ii111
 if 72 - 72: i11iIiiIii . iII111i . Ii1I * I1ii11iIi11i
 if 49 - 49: OoOoOO00 - O0 % I11i - ooOoO0o * OOooOOo
 if 58 - 58: OoooooooOO - OOooOOo * oO0o / Ii1I . IiII
 if 50 - 50: IiII . OOooOOo + I1ii11iIi11i - OoooooooOO
 if 2 - 2: o0oOOo0O0Ooo % ooOoO0o / O0 / i11iIiiIii
 if ( rloc ) : rloc . last_rloc_probe_nonce = Ii1 . nonce
 if 91 - 91: II111iiii * o0oOOo0O0Ooo
 OOO0oOO = deid . is_multicast_address ( )
 if ( OOO0oOO ) :
  Ii1 . target_eid = seid
  Ii1 . target_group = deid
 else :
  Ii1 . target_eid = deid
  if 20 - 20: iIii1I11I1II1 % Oo0Ooo * OoOoOO00 % IiII
  if 93 - 93: I11i * iIii1I11I1II1 * oO0o
  if 74 - 74: I1IiiI
  if 39 - 39: iII111i * IiII / iII111i * IiII % I1ii11iIi11i
  if 27 - 27: iIii1I11I1II1 . ooOoO0o
  if 74 - 74: i1IIi % OoOoOO00
  if 98 - 98: IiII * OOooOOo / O0 - I1Ii111 . I1Ii111 + OOooOOo
  if 61 - 61: iII111i * Ii1I % Ii1I + I1IiiI
  if 23 - 23: oO0o + I1Ii111 / OoooooooOO / O0 + IiII
 if ( Ii1 . rloc_probe == False ) :
  i1iOo = lisp_get_signature_eid ( )
  if ( i1iOo ) :
   Ii1 . signature_eid . copy_address ( i1iOo . eid )
   Ii1 . privkey_filename = "./lisp-sig.pem"
   if 80 - 80: i11iIiiIii - OoooooooOO + II111iiii / i1IIi - oO0o
   if 100 - 100: Ii1I
   if 73 - 73: IiII - O0
   if 54 - 54: OOooOOo
   if 28 - 28: i1IIi - Oo0Ooo * OoO0O00 + OoooooooOO - Ii1I * i11iIiiIii
   if 71 - 71: iII111i - OOooOOo / iIii1I11I1II1 % i11iIiiIii
 if ( seid == None or OOO0oOO ) :
  Ii1 . source_eid . afi = LISP_AFI_NONE
 else :
  Ii1 . source_eid = seid
  if 39 - 39: o0oOOo0O0Ooo
  if 32 - 32: iIii1I11I1II1 . II111iiii / IiII % O0 / iII111i
  if 97 - 97: iIii1I11I1II1
  if 18 - 18: OOooOOo
  if 87 - 87: O0 - i1IIi . I11i / Ii1I % iIii1I11I1II1
  if 57 - 57: I11i . IiII / iIii1I11I1II1 - ooOoO0o
  if 50 - 50: O0 / II111iiii
  if 94 - 94: O0 + O0 % I1ii11iIi11i % i1IIi
  if 15 - 15: I1IiiI
  if 48 - 48: Ii1I * IiII % O0 - II111iiii
  if 66 - 66: iIii1I11I1II1 / OOooOOo
  if 65 - 65: IiII . oO0o + O0 - i11iIiiIii + iIii1I11I1II1
 if ( IiOo != None and lisp_nat_traversal and lisp_i_am_rtr == False ) :
  if ( IiOo . is_private_address ( ) == False ) :
   OOO0oo00oO = lisp_get_any_translated_rloc ( )
   if 82 - 82: iIii1I11I1II1 * iII111i + iIii1I11I1II1 / OoO0O00 + O0
  if ( OOO0oo00oO == None ) :
   lprint ( "Suppress sending Map-Request, translated RLOC not found" )
   return
   if 67 - 67: I1Ii111
   if 94 - 94: I1Ii111 % iIii1I11I1II1 - II111iiii . ooOoO0o + i11iIiiIii - i11iIiiIii
   if 55 - 55: OoooooooOO % iIii1I11I1II1 % I1ii11iIi11i % i1IIi
   if 46 - 46: I11i - ooOoO0o . I1IiiI
   if 36 - 36: I11i + OoO0O00 * O0 * OoOoOO00 * iII111i
   if 90 - 90: i11iIiiIii / i1IIi
   if 35 - 35: Ii1I . I11i / oO0o / OoOoOO00
   if 5 - 5: I1ii11iIi11i . o0oOOo0O0Ooo * iII111i * I1ii11iIi11i % I1Ii111
 if ( IiOo == None or IiOo . is_ipv4 ( ) ) :
  if ( lisp_nat_traversal and IiOo == None ) :
   Oo0OOooOo00Oo = lisp_get_any_translated_rloc ( )
   if ( Oo0OOooOo00Oo != None ) : OOO0oo00oO = Oo0OOooOo00Oo
   if 69 - 69: Ii1I
  Ii1 . itr_rlocs . append ( OOO0oo00oO )
  if 75 - 75: I1IiiI
 if ( IiOo == None or IiOo . is_ipv6 ( ) ) :
  if ( Iii1I1i11II == None or Iii1I1i11II . is_ipv6_link_local ( ) ) :
   Iii1I1i11II = None
  else :
   Ii1 . itr_rloc_count = 1 if ( IiOo == None ) else 0
   Ii1 . itr_rlocs . append ( Iii1I1i11II )
   if 55 - 55: i11iIiiIii - I1IiiI . oO0o - OoooooooOO
   if 44 - 44: I1Ii111
   if 98 - 98: I1IiiI % OOooOOo % iII111i
   if 15 - 15: OoO0O00
   if 52 - 52: II111iiii / ooOoO0o
   if 23 - 23: i11iIiiIii % OoO0O00 - o0oOOo0O0Ooo + OoooooooOO
   if 12 - 12: Ii1I / I1IiiI . oO0o . I1IiiI + ooOoO0o - II111iiii
   if 6 - 6: Oo0Ooo + Oo0Ooo - OoOoOO00 - II111iiii
   if 25 - 25: i11iIiiIii + II111iiii * OOooOOo % OOooOOo
 if ( IiOo != None and Ii1 . itr_rlocs != [ ] ) :
  i1II = Ii1 . itr_rlocs [ 0 ]
 else :
  if ( deid . is_ipv4 ( ) ) :
   i1II = OOO0oo00oO
  elif ( deid . is_ipv6 ( ) ) :
   i1II = Iii1I1i11II
  else :
   i1II = OOO0oo00oO
   if 87 - 87: I11i % Ii1I % Oo0Ooo . II111iiii / oO0o
   if 19 - 19: O0 . OOooOOo + I1Ii111 * I1ii11iIi11i
   if 91 - 91: o0oOOo0O0Ooo / oO0o . o0oOOo0O0Ooo + IiII + ooOoO0o . I1Ii111
   if 90 - 90: i1IIi + oO0o * oO0o / ooOoO0o . IiII
   if 98 - 98: I11i % OoO0O00 . iII111i - o0oOOo0O0Ooo
   if 92 - 92: I11i
 I1IiO00Ooo0ooo0 = Ii1 . encode ( IiOo , oO0ooO0O00OO )
 Ii1 . print_map_request ( )
 if 34 - 34: I1IiiI % iIii1I11I1II1 . I1ii11iIi11i * Oo0Ooo * iIii1I11I1II1 / O0
 if 98 - 98: iII111i % IiII + OoO0O00
 if 23 - 23: OOooOOo
 if 83 - 83: I1ii11iIi11i / O0 * II111iiii + IiII + Oo0Ooo
 if 99 - 99: II111iiii + O0
 if 94 - 94: ooOoO0o * ooOoO0o + o0oOOo0O0Ooo . iII111i % iIii1I11I1II1 + Ii1I
 if ( IiOo != None ) :
  if ( rloc . is_rloc_translated ( ) ) :
   o0oO00ooo0o = lisp_get_nat_info ( IiOo , rloc . rloc_name )
   if ( o0oO00ooo0o and len ( lisp_sockets ) == 4 ) :
    lisp_encapsulate_rloc_probe ( lisp_sockets , IiOo ,
 o0oO00ooo0o , I1IiO00Ooo0ooo0 )
    return
    if 88 - 88: Oo0Ooo . iII111i
    if 89 - 89: OOooOOo + I1Ii111 % i11iIiiIii + Oo0Ooo / Oo0Ooo + OoO0O00
    if 9 - 9: OoOoOO00 % i1IIi + IiII
  OoOOoooO000 = IiOo . print_address_no_iid ( )
  I1I1I1 = lisp_convert_4to6 ( OoOOoooO000 )
  lisp_send ( lisp_sockets , I1I1I1 , LISP_CTRL_PORT , I1IiO00Ooo0ooo0 )
  return
  if 19 - 19: I1Ii111 - II111iiii / I1Ii111 + I1IiiI - OoooooooOO + o0oOOo0O0Ooo
  if 100 - 100: OoO0O00 / OoOoOO00 / OOooOOo / OoO0O00
  if 95 - 95: ooOoO0o
  if 95 - 95: Ii1I + i1IIi . I1IiiI % I1Ii111 / Ii1I * O0
  if 68 - 68: I1Ii111 - IiII - oO0o - Oo0Ooo - o0oOOo0O0Ooo
  if 32 - 32: OoOoOO00 % i11iIiiIii
 O0o0o00oooOO = None if lisp_i_am_rtr else seid
 if ( lisp_decent_pull_xtr_configured ( ) ) :
  oOoooooOooO = lisp_get_decent_map_resolver ( deid )
 else :
  oOoooooOooO = lisp_get_map_resolver ( None , O0o0o00oooOO )
  if 18 - 18: ooOoO0o * OoOoOO00 . OoO0O00
 if ( oOoooooOooO == None ) :
  lprint ( "Cannot find Map-Resolver for source-EID {}" . format ( green ( seid . print_address ( ) , False ) ) )
  if 75 - 75: OoOoOO00 + O0 * I1Ii111
  return
  if 78 - 78: OoOoOO00
 oOoooooOooO . last_used = lisp_get_timestamp ( )
 oOoooooOooO . map_requests_sent += 1
 if ( oOoooooOooO . last_nonce == 0 ) : oOoooooOooO . last_nonce = Ii1 . nonce
 if 16 - 16: I1Ii111 % OoO0O00 - OoO0O00 % OoOoOO00 * OoO0O00
 if 36 - 36: OoOoOO00 * II111iiii . OoooooooOO * I11i . I11i
 if 13 - 13: I1ii11iIi11i * II111iiii
 if 93 - 93: OOooOOo / O0 - o0oOOo0O0Ooo + OoO0O00 * I1IiiI
 if ( seid == None ) : seid = i1II
 lisp_send_ecm ( lisp_sockets , I1IiO00Ooo0ooo0 , seid , lisp_ephem_port , deid ,
 oOoooooOooO . map_resolver )
 if 53 - 53: I1ii11iIi11i
 if 91 - 91: o0oOOo0O0Ooo - I1ii11iIi11i . i1IIi
 if 64 - 64: ooOoO0o
 if 23 - 23: Oo0Ooo . OoO0O00
 lisp_last_map_request_sent = lisp_get_timestamp ( )
 if 49 - 49: oO0o % i11iIiiIii * Ii1I
 if 9 - 9: Oo0Ooo - OoO0O00 + ooOoO0o / o0oOOo0O0Ooo
 if 61 - 61: O0 - i11iIiiIii * o0oOOo0O0Ooo
 if 92 - 92: Oo0Ooo + OOooOOo - i11iIiiIii
 oOoooooOooO . resolve_dns_name ( )
 return
 if 26 - 26: O0 % Oo0Ooo + ooOoO0o - Ii1I . Oo0Ooo
 if 33 - 33: I1Ii111 / iII111i . I1Ii111 % II111iiii
 if 52 - 52: I1ii11iIi11i
 if 1 - 1: II111iiii + I1ii11iIi11i * OoOoOO00 % ooOoO0o - iII111i % OoooooooOO
 if 77 - 77: iII111i + o0oOOo0O0Ooo
 if 60 - 60: I1ii11iIi11i
 if 23 - 23: iII111i % I1IiiI % I1Ii111 * oO0o * I1IiiI
 if 74 - 74: O0 / I11i . Oo0Ooo / I11i % OoO0O00 % o0oOOo0O0Ooo
def lisp_send_info_request ( lisp_sockets , dest , port , device_name ) :
 if 83 - 83: OoO0O00 - i11iIiiIii + iIii1I11I1II1
 if 52 - 52: OoooooooOO
 if 44 - 44: O0 / OoooooooOO + ooOoO0o * I1ii11iIi11i
 if 36 - 36: I1ii11iIi11i / OoO0O00 - oO0o % O0
 Iii1IIiii1ii = lisp_info ( )
 Iii1IIiii1ii . nonce = lisp_get_control_nonce ( )
 if ( device_name ) : Iii1IIiii1ii . hostname += "-" + device_name
 if 37 - 37: OoooooooOO % I1IiiI * I1IiiI
 OoOOoooO000 = dest . print_address_no_iid ( )
 if 13 - 13: oO0o
 if 43 - 43: oO0o / Ii1I % OOooOOo
 if 45 - 45: II111iiii
 if 41 - 41: Ii1I / OOooOOo * Oo0Ooo . O0 - i11iIiiIii
 if 77 - 77: o0oOOo0O0Ooo + I1IiiI + I1Ii111 / I1ii11iIi11i * i1IIi
 if 37 - 37: O0 + iIii1I11I1II1 % IiII * oO0o
 if 43 - 43: OOooOOo . O0
 if 76 - 76: OOooOOo * OoooooooOO / IiII . OoO0O00 + II111iiii
 if 23 - 23: OoO0O00 - OoooooooOO * I11i . iIii1I11I1II1 / o0oOOo0O0Ooo + oO0o
 if 74 - 74: II111iiii / I1IiiI * O0 * OoO0O00 . I11i
 if 74 - 74: O0 . i1IIi / I1ii11iIi11i + o0oOOo0O0Ooo
 if 24 - 24: ooOoO0o % I1Ii111 + OoO0O00 * o0oOOo0O0Ooo % O0 - i11iIiiIii
 if 49 - 49: o0oOOo0O0Ooo / OoOoOO00 + iII111i
 if 85 - 85: I1IiiI - o0oOOo0O0Ooo
 if 86 - 86: II111iiii + Ii1I * Ii1I
 if 26 - 26: o0oOOo0O0Ooo + oO0o * i11iIiiIii / II111iiii
 o0O0OoOOoo0 = False
 if ( device_name ) :
  i1I111i1 = lisp_get_host_route_next_hop ( OoOOoooO000 )
  if 59 - 59: OoOoOO00 % OoO0O00 % i11iIiiIii . II111iiii % I1ii11iIi11i + i1IIi
  if 99 - 99: I11i + IiII * I1Ii111 - OOooOOo - i1IIi
  if 77 - 77: I11i . IiII / OoO0O00 / I1Ii111
  if 8 - 8: o0oOOo0O0Ooo + iII111i / OoO0O00 * ooOoO0o - oO0o . iII111i
  if 32 - 32: OoooooooOO . I1Ii111 - I1ii11iIi11i
  if 29 - 29: OoO0O00
  if 33 - 33: I1ii11iIi11i - O0
  if 72 - 72: Oo0Ooo * iII111i - I11i
  if 81 - 81: I1Ii111
  if ( port == LISP_CTRL_PORT and i1I111i1 != None ) :
   while ( True ) :
    time . sleep ( .01 )
    i1I111i1 = lisp_get_host_route_next_hop ( OoOOoooO000 )
    if ( i1I111i1 == None ) : break
    if 85 - 85: O0 % OoOoOO00 . I1ii11iIi11i
    if 46 - 46: OOooOOo * iIii1I11I1II1
    if 33 - 33: OoO0O00 * II111iiii / i1IIi
  o00OO0OoOOO = lisp_get_default_route_next_hops ( )
  for Ooooo , IiIIiI11I in o00OO0OoOOO :
   if ( Ooooo != device_name ) : continue
   if 91 - 91: i1IIi % O0 . oO0o
   if 72 - 72: O0 - IiII
   if 49 - 49: IiII - OOooOOo * OOooOOo . O0
   if 60 - 60: OoOoOO00 % iIii1I11I1II1 + IiII % o0oOOo0O0Ooo
   if 64 - 64: OoOoOO00 * I1ii11iIi11i . OoooooooOO . i1IIi
   if 61 - 61: OoO0O00
   if ( i1I111i1 != IiIIiI11I ) :
    if ( i1I111i1 != None ) :
     lisp_install_host_route ( OoOOoooO000 , i1I111i1 , False )
     if 100 - 100: OoOoOO00
    lisp_install_host_route ( OoOOoooO000 , IiIIiI11I , True )
    o0O0OoOOoo0 = True
    if 97 - 97: OoooooooOO
   break
   if 91 - 91: o0oOOo0O0Ooo / O0 % OoO0O00
   if 35 - 35: iII111i % OoO0O00 * O0
   if 37 - 37: OOooOOo
   if 100 - 100: Oo0Ooo * I1IiiI . ooOoO0o
   if 53 - 53: OOooOOo + o0oOOo0O0Ooo * Ii1I + O0
   if 75 - 75: OoooooooOO
 I1IiO00Ooo0ooo0 = Iii1IIiii1ii . encode ( )
 Iii1IIiii1ii . print_info ( )
 if 24 - 24: I1Ii111 % i11iIiiIii % oO0o . OOooOOo % IiII
 if 23 - 23: o0oOOo0O0Ooo * II111iiii - Oo0Ooo - I1IiiI
 if 86 - 86: I1IiiI - II111iiii * II111iiii * oO0o % OoooooooOO * OoOoOO00
 if 93 - 93: I1IiiI + OoO0O00 % O0 - ooOoO0o * i1IIi
 oo000 = "(for control)" if port == LISP_CTRL_PORT else "(for data)"
 oo000 = bold ( oo000 , False )
 oo000o = bold ( "{}" . format ( port ) , False )
 OOOO0o = red ( OoOOoooO000 , False )
 O0Oo = "RTR " if port == LISP_DATA_PORT else "MS "
 lprint ( "Send Info-Request to {}{}, port {} {}" . format ( O0Oo , OOOO0o , oo000o , oo000 ) )
 if 21 - 21: ooOoO0o % OOooOOo
 if 84 - 84: II111iiii - I1ii11iIi11i / ooOoO0o . i11iIiiIii
 if 30 - 30: oO0o / ooOoO0o . OoOoOO00 . OoO0O00 % I1Ii111
 if 71 - 71: OoooooooOO % O0 * Ii1I / OOooOOo / o0oOOo0O0Ooo
 if 3 - 3: i11iIiiIii
 if 16 - 16: Oo0Ooo * I1Ii111
 if ( port == LISP_CTRL_PORT ) :
  lisp_send ( lisp_sockets , dest , LISP_CTRL_PORT , I1IiO00Ooo0ooo0 )
 else :
  III1Iiii1i11 = lisp_data_header ( )
  III1Iiii1i11 . instance_id ( 0xffffff )
  III1Iiii1i11 = III1Iiii1i11 . encode ( )
  if ( III1Iiii1i11 ) :
   I1IiO00Ooo0ooo0 = III1Iiii1i11 + I1IiO00Ooo0ooo0
   if 7 - 7: OoooooooOO . II111iiii + OoO0O00 / OoooooooOO
   if 61 - 61: ooOoO0o
   if 4 - 4: Oo0Ooo + oO0o + oO0o
   if 79 - 79: OoooooooOO
   if 98 - 98: O0 . ooOoO0o * I1Ii111
   if 98 - 98: ooOoO0o + o0oOOo0O0Ooo / I11i - Ii1I * II111iiii + i1IIi
   if 10 - 10: oO0o
   if 8 - 8: I1ii11iIi11i * OOooOOo * iIii1I11I1II1 + I11i . iII111i
   if 55 - 55: I1IiiI + Ii1I % I1ii11iIi11i + iIii1I11I1II1
   lisp_send ( lisp_sockets , dest , LISP_DATA_PORT , I1IiO00Ooo0ooo0 )
   if 64 - 64: i1IIi / O0 - oO0o
   if 7 - 7: IiII . IiII * Ii1I
   if 1 - 1: i11iIiiIii
   if 91 - 91: I1ii11iIi11i . OoO0O00 / OoO0O00 / I1ii11iIi11i + iII111i
   if 20 - 20: o0oOOo0O0Ooo . I1Ii111 + O0
   if 99 - 99: O0 / IiII . oO0o
   if 18 - 18: OoooooooOO * OoO0O00 * I1Ii111
 if ( o0O0OoOOoo0 ) :
  lisp_install_host_route ( OoOOoooO000 , None , False )
  if ( i1I111i1 != None ) : lisp_install_host_route ( OoOOoooO000 , i1I111i1 , True )
  if 12 - 12: i11iIiiIii / iIii1I11I1II1 . I11i % I1Ii111 * ooOoO0o % ooOoO0o
 return
 if 13 - 13: i1IIi . ooOoO0o . ooOoO0o
 if 24 - 24: iIii1I11I1II1
 if 72 - 72: i11iIiiIii + o0oOOo0O0Ooo % ooOoO0o * I1ii11iIi11i . i1IIi
 if 59 - 59: OoooooooOO - OoooooooOO - o0oOOo0O0Ooo + i1IIi % I1Ii111
 if 74 - 74: IiII * iIii1I11I1II1 - I1IiiI
 if 62 - 62: o0oOOo0O0Ooo
 if 54 - 54: iIii1I11I1II1 / OoooooooOO + o0oOOo0O0Ooo . i1IIi - OoooooooOO
def lisp_process_info_request ( lisp_sockets , packet , addr_str , sport , rtr_list ) :
 if 70 - 70: Ii1I / OoOoOO00 * Oo0Ooo
 if 32 - 32: I1Ii111 . OoOoOO00 % OoooooooOO + I1Ii111 * OoO0O00
 if 84 - 84: OoOoOO00
 if 80 - 80: oO0o
 Iii1IIiii1ii = lisp_info ( )
 packet = Iii1IIiii1ii . decode ( packet )
 if ( packet == None ) : return
 Iii1IIiii1ii . print_info ( )
 if 59 - 59: iIii1I11I1II1 / IiII % I1ii11iIi11i + OoO0O00 - I11i % OOooOOo
 if 92 - 92: iII111i
 if 96 - 96: OoOoOO00 / OoOoOO00 / OoOoOO00 + OoooooooOO + Oo0Ooo
 if 91 - 91: OoOoOO00 + II111iiii / I11i * iIii1I11I1II1
 if 92 - 92: I1Ii111 - IiII / IiII
 Iii1IIiii1ii . info_reply = True
 Iii1IIiii1ii . global_etr_rloc . store_address ( addr_str )
 Iii1IIiii1ii . etr_port = sport
 if 42 - 42: IiII
 if 7 - 7: iIii1I11I1II1
 if 35 - 35: IiII + O0 % I1Ii111 - I1ii11iIi11i - i1IIi
 if 100 - 100: I1Ii111 + i11iIiiIii - IiII / I1ii11iIi11i / iII111i
 if 56 - 56: iII111i
 Iii1IIiii1ii . private_etr_rloc . afi = LISP_AFI_NAME
 Iii1IIiii1ii . private_etr_rloc . store_address ( Iii1IIiii1ii . hostname )
 if 91 - 91: Oo0Ooo . I11i . I1ii11iIi11i
 if ( rtr_list != None ) : Iii1IIiii1ii . rtr_list = rtr_list
 packet = Iii1IIiii1ii . encode ( )
 Iii1IIiii1ii . print_info ( )
 if 60 - 60: i11iIiiIii - OOooOOo
 if 78 - 78: I1IiiI * ooOoO0o % iIii1I11I1II1 / I1ii11iIi11i
 if 61 - 61: I1Ii111 . Ii1I + OoooooooOO
 if 98 - 98: OOooOOo . ooOoO0o . OoOoOO00 - I1Ii111 . i1IIi - iIii1I11I1II1
 if 89 - 89: II111iiii * I1ii11iIi11i - I1IiiI
 lprint ( "Send Info-Reply to {}" . format ( red ( addr_str , False ) ) )
 I1I1I1 = lisp_convert_4to6 ( addr_str )
 lisp_send ( lisp_sockets , I1I1I1 , sport , packet )
 if 58 - 58: Ii1I / Oo0Ooo % IiII
 if 33 - 33: II111iiii . OOooOOo % iIii1I11I1II1 - Oo0Ooo - OoOoOO00 % i11iIiiIii
 if 60 - 60: iII111i . o0oOOo0O0Ooo
 if 56 - 56: I1ii11iIi11i
 if 89 - 89: Oo0Ooo + I1ii11iIi11i * o0oOOo0O0Ooo * oO0o % O0 % OoO0O00
 oO0ooOo = lisp_info_source ( Iii1IIiii1ii . hostname , addr_str , sport )
 oO0ooOo . cache_address_for_info_source ( )
 return
 if 80 - 80: iII111i . OoooooooOO / II111iiii . OoO0O00 / OoooooooOO + ooOoO0o
 if 25 - 25: I1IiiI - IiII . o0oOOo0O0Ooo / I1Ii111 % I1ii11iIi11i
 if 21 - 21: OoooooooOO % I1ii11iIi11i / OoooooooOO - I1ii11iIi11i * i1IIi
 if 35 - 35: I11i . Ii1I / Ii1I . OoOoOO00
 if 59 - 59: OoOoOO00 / i1IIi / iIii1I11I1II1 + i1IIi
 if 33 - 33: iIii1I11I1II1 * i11iIiiIii
 if 7 - 7: oO0o
 if 89 - 89: i11iIiiIii / o0oOOo0O0Ooo / I1ii11iIi11i % iII111i . OoooooooOO - iIii1I11I1II1
def lisp_get_signature_eid ( ) :
 for i1iOo in lisp_db_list :
  if ( i1iOo . signature_eid ) : return ( i1iOo )
  if 63 - 63: Ii1I % I1Ii111 + O0 * OoO0O00 . oO0o
 return ( None )
 if 34 - 34: I1IiiI . I1ii11iIi11i . O0 - OoOoOO00 - i11iIiiIii / iII111i
 if 63 - 63: OOooOOo
 if 84 - 84: i11iIiiIii * iIii1I11I1II1 % I11i % iII111i + OoooooooOO . o0oOOo0O0Ooo
 if 78 - 78: o0oOOo0O0Ooo . iII111i + O0 / I1ii11iIi11i + I1ii11iIi11i + II111iiii
 if 96 - 96: iIii1I11I1II1 * II111iiii . iIii1I11I1II1
 if 13 - 13: Ii1I - OoOoOO00 . Ii1I
 if 7 - 7: Ii1I - I11i / I1ii11iIi11i + iII111i
 if 47 - 47: I11i * IiII / oO0o - OoooooooOO . OoooooooOO / I11i
def lisp_get_any_translated_port ( ) :
 for i1iOo in lisp_db_list :
  for iIIiIiiI in i1iOo . rloc_set :
   if ( iIIiIiiI . translated_rloc . is_null ( ) ) : continue
   return ( iIIiIiiI . translated_port )
   if 73 - 73: Ii1I . IiII % IiII
   if 56 - 56: I1Ii111 + iII111i + iII111i
 return ( None )
 if 99 - 99: o0oOOo0O0Ooo % I1ii11iIi11i / Oo0Ooo . O0 + OoO0O00 * OoOoOO00
 if 48 - 48: iIii1I11I1II1 + O0 * I11i * i11iIiiIii . Ii1I / i1IIi
 if 48 - 48: i1IIi % iIii1I11I1II1 + I1IiiI - OoOoOO00 % I11i . I1Ii111
 if 66 - 66: I1Ii111 * i11iIiiIii + I1IiiI % II111iiii
 if 47 - 47: II111iiii % o0oOOo0O0Ooo
 if 26 - 26: I1ii11iIi11i / I11i / Oo0Ooo / i1IIi + O0 * ooOoO0o
 if 53 - 53: IiII / II111iiii / oO0o % O0 / I1Ii111
 if 91 - 91: oO0o * OoOoOO00 + O0 % Oo0Ooo
 if 62 - 62: iIii1I11I1II1 - i11iIiiIii % iIii1I11I1II1 . ooOoO0o / OOooOOo * OoOoOO00
def lisp_get_any_translated_rloc ( ) :
 for i1iOo in lisp_db_list :
  for iIIiIiiI in i1iOo . rloc_set :
   if ( iIIiIiiI . translated_rloc . is_null ( ) ) : continue
   return ( iIIiIiiI . translated_rloc )
   if 45 - 45: OOooOOo - OOooOOo % iII111i - IiII . O0
   if 6 - 6: iIii1I11I1II1 * II111iiii / O0 % IiII - I1Ii111
 return ( None )
 if 64 - 64: ooOoO0o
 if 28 - 28: i11iIiiIii - IiII * I1ii11iIi11i + IiII * iII111i
 if 75 - 75: o0oOOo0O0Ooo * OoOoOO00 % I1ii11iIi11i + OOooOOo . II111iiii
 if 12 - 12: ooOoO0o
 if 83 - 83: I1Ii111 % ooOoO0o + OoooooooOO
 if 50 - 50: i11iIiiIii % I1IiiI * iII111i / Ii1I
 if 12 - 12: iII111i / OoO0O00 - II111iiii + Oo0Ooo
def lisp_get_all_translated_rlocs ( ) :
 ooO0 = [ ]
 for i1iOo in lisp_db_list :
  for iIIiIiiI in i1iOo . rloc_set :
   if ( iIIiIiiI . is_rloc_translated ( ) == False ) : continue
   I1Iii1I = iIIiIiiI . translated_rloc . print_address_no_iid ( )
   ooO0 . append ( I1Iii1I )
   if 78 - 78: OoOoOO00 / IiII
   if 92 - 92: OoOoOO00 / I11i / I1Ii111
 return ( ooO0 )
 if 2 - 2: IiII - iIii1I11I1II1
 if 54 - 54: i11iIiiIii . Ii1I % I1IiiI . I1Ii111 . OoooooooOO
 if 49 - 49: OOooOOo % I11i - OOooOOo + Ii1I . I1ii11iIi11i + ooOoO0o
 if 15 - 15: i11iIiiIii
 if 85 - 85: I1Ii111 + iII111i - oO0o
 if 59 - 59: IiII . oO0o / i11iIiiIii . I1Ii111
 if 64 - 64: OoOoOO00
 if 20 - 20: OoOoOO00 / O0 * OOooOOo % I11i + OoO0O00 + o0oOOo0O0Ooo
def lisp_update_default_routes ( map_resolver , iid , rtr_list ) :
 O0ooOO = ( os . getenv ( "LISP_RTR_BEHIND_NAT" ) != None )
 if 51 - 51: Ii1I - OoOoOO00 / i11iIiiIii + O0
 oOoOOOO0OO00o = { }
 for oOoOoo0O in rtr_list :
  if ( oOoOoo0O == None ) : continue
  I1Iii1I = rtr_list [ oOoOoo0O ]
  if ( O0ooOO and I1Iii1I . is_private_address ( ) ) : continue
  oOoOOOO0OO00o [ oOoOoo0O ] = I1Iii1I
  if 6 - 6: I1Ii111 / i1IIi / IiII . o0oOOo0O0Ooo
 rtr_list = oOoOOOO0OO00o
 if 69 - 69: ooOoO0o - OoOoOO00 . I1IiiI . I11i + OoOoOO00 / i11iIiiIii
 IIo0 = [ ]
 for o0O0O0O00o in [ LISP_AFI_IPV4 , LISP_AFI_IPV6 , LISP_AFI_MAC ] :
  if ( o0O0O0O00o == LISP_AFI_MAC and lisp_l2_overlay == False ) : break
  if 21 - 21: IiII + i11iIiiIii / ooOoO0o . I1ii11iIi11i % o0oOOo0O0Ooo
  if 46 - 46: II111iiii
  if 93 - 93: Ii1I * iII111i / OoOoOO00
  if 65 - 65: iIii1I11I1II1 . o0oOOo0O0Ooo % OoO0O00
  if 27 - 27: I1Ii111 * Ii1I
  ii1II1 = lisp_address ( o0O0O0O00o , "" , 0 , iid )
  ii1II1 . make_default_route ( ii1II1 )
  oOooO0Oo0Oo0 = lisp_map_cache . lookup_cache ( ii1II1 , True )
  if ( oOooO0Oo0Oo0 ) :
   if ( oOooO0Oo0Oo0 . checkpoint_entry ) :
    lprint ( "Updating checkpoint entry for {}" . format ( green ( oOooO0Oo0Oo0 . print_eid_tuple ( ) , False ) ) )
    if 11 - 11: I1IiiI % OoOoOO00 / OoO0O00 % OoO0O00 / OoO0O00 * IiII
   elif ( oOooO0Oo0Oo0 . do_rloc_sets_match ( rtr_list . values ( ) ) ) :
    continue
    if 37 - 37: oO0o / iII111i
   oOooO0Oo0Oo0 . delete_cache ( )
   if 58 - 58: OoO0O00 / OoOoOO00 - Oo0Ooo + OoOoOO00
   if 8 - 8: II111iiii % IiII - IiII + Oo0Ooo . iII111i
  IIo0 . append ( [ ii1II1 , "" ] )
  if 90 - 90: OOooOOo . ooOoO0o * oO0o % ooOoO0o / o0oOOo0O0Ooo
  if 25 - 25: i11iIiiIii % o0oOOo0O0Ooo % OoO0O00 - I11i
  if 18 - 18: iII111i
  if 9 - 9: I1Ii111 . oO0o . OoO0O00 / IiII - oO0o / oO0o
  ooOoO00 = lisp_address ( o0O0O0O00o , "" , 0 , iid )
  ooOoO00 . make_default_multicast_route ( ooOoO00 )
  iiIiiI1 = lisp_map_cache . lookup_cache ( ooOoO00 , True )
  if ( iiIiiI1 ) : iiIiiI1 = iiIiiI1 . source_cache . lookup_cache ( ii1II1 , True )
  if ( iiIiiI1 ) : iiIiiI1 . delete_cache ( )
  if 58 - 58: II111iiii * Ii1I
  IIo0 . append ( [ ii1II1 , ooOoO00 ] )
  if 44 - 44: OoOoOO00 . OoO0O00
 if ( len ( IIo0 ) == 0 ) : return
 if 27 - 27: o0oOOo0O0Ooo / iIii1I11I1II1 + ooOoO0o . iII111i - I1IiiI / oO0o
 if 57 - 57: iII111i / i11iIiiIii / OoooooooOO . OOooOOo
 if 96 - 96: I11i * ooOoO0o / OoooooooOO * i1IIi . Oo0Ooo * i11iIiiIii
 if 5 - 5: iIii1I11I1II1 / oO0o - Oo0Ooo - I1IiiI + iIii1I11I1II1
 I111iIi11Ii11III = [ ]
 for O0Oo in rtr_list :
  OoO0 = rtr_list [ O0Oo ]
  iIIiIiiI = lisp_rloc ( )
  iIIiIiiI . rloc . copy_address ( OoO0 )
  iIIiIiiI . priority = 254
  iIIiIiiI . mpriority = 255
  iIIiIiiI . rloc_name = "RTR"
  I111iIi11Ii11III . append ( iIIiIiiI )
  if 61 - 61: o0oOOo0O0Ooo
  if 31 - 31: Ii1I
 for ii1II1 in IIo0 :
  oOooO0Oo0Oo0 = lisp_mapping ( ii1II1 [ 0 ] , ii1II1 [ 1 ] , I111iIi11Ii11III )
  oOooO0Oo0Oo0 . mapping_source = map_resolver
  oOooO0Oo0Oo0 . map_cache_ttl = LISP_MR_TTL * 60
  oOooO0Oo0Oo0 . add_cache ( )
  lprint ( "Add {} to map-cache with RTR RLOC-set: {}" . format ( green ( oOooO0Oo0Oo0 . print_eid_tuple ( ) , False ) , rtr_list . keys ( ) ) )
  if 76 - 76: OoO0O00 / II111iiii
  I111iIi11Ii11III = copy . deepcopy ( I111iIi11Ii11III )
  if 92 - 92: o0oOOo0O0Ooo . i1IIi . OoOoOO00 / OoO0O00 % Ii1I
 return
 if 61 - 61: i1IIi / Ii1I . OoOoOO00 + i11iIiiIii
 if 69 - 69: i11iIiiIii - iIii1I11I1II1
 if 40 - 40: I1IiiI / oO0o + ooOoO0o
 if 100 - 100: OoOoOO00 % iII111i * ooOoO0o . O0
 if 37 - 37: I1ii11iIi11i
 if 24 - 24: O0 . I1Ii111 * i11iIiiIii
 if 84 - 84: ooOoO0o / I1ii11iIi11i - o0oOOo0O0Ooo . OoooooooOO * iIii1I11I1II1
 if 16 - 16: I11i % O0
 if 56 - 56: Ii1I * OoOoOO00 . i1IIi
 if 15 - 15: I1Ii111
def lisp_process_info_reply ( source , packet , store ) :
 if 64 - 64: OOooOOo * Oo0Ooo
 if 96 - 96: Oo0Ooo / I1ii11iIi11i * iIii1I11I1II1 / iII111i
 if 18 - 18: I1Ii111
 if 29 - 29: i1IIi - I1IiiI / i1IIi
 Iii1IIiii1ii = lisp_info ( )
 packet = Iii1IIiii1ii . decode ( packet )
 if ( packet == None ) : return ( [ None , None , False ] )
 if 64 - 64: IiII
 Iii1IIiii1ii . print_info ( )
 if 69 - 69: OOooOOo . I1IiiI
 if 11 - 11: I1Ii111 * I1IiiI - I1Ii111 / iII111i
 if 22 - 22: iII111i % I11i % O0 - I11i
 if 71 - 71: I1Ii111 / II111iiii - OoooooooOO % i1IIi + OoOoOO00 % OoooooooOO
 O0oi11IIIII = False
 for O0Oo in Iii1IIiii1ii . rtr_list :
  OoOOoooO000 = O0Oo . print_address_no_iid ( )
  if ( lisp_rtr_list . has_key ( OoOOoooO000 ) ) :
   if ( lisp_register_all_rtrs == False ) : continue
   if ( lisp_rtr_list [ OoOOoooO000 ] != None ) : continue
   if 9 - 9: Ii1I + II111iiii - iIii1I11I1II1 % I1Ii111 * i1IIi + iIii1I11I1II1
  O0oi11IIIII = True
  lisp_rtr_list [ OoOOoooO000 ] = O0Oo
  if 57 - 57: i1IIi
  if 98 - 98: OoOoOO00 / Oo0Ooo
  if 99 - 99: iII111i - o0oOOo0O0Ooo / O0
  if 97 - 97: iIii1I11I1II1 * I1Ii111
  if 39 - 39: I1Ii111 . II111iiii
 if ( lisp_i_am_itr and O0oi11IIIII ) :
  if ( lisp_iid_to_interface == { } ) :
   lisp_update_default_routes ( source , lisp_default_iid , lisp_rtr_list )
  else :
   for IIiI1i in lisp_iid_to_interface . keys ( ) :
    lisp_update_default_routes ( source , int ( IIiI1i ) , lisp_rtr_list )
    if 94 - 94: OoO0O00 - OoO0O00 + iIii1I11I1II1 + O0 * oO0o
    if 9 - 9: Ii1I * Oo0Ooo / oO0o / Ii1I
    if 34 - 34: I1IiiI
    if 56 - 56: Ii1I
    if 71 - 71: O0 / i1IIi
    if 20 - 20: OOooOOo . iIii1I11I1II1 - I1Ii111 . i1IIi
    if 82 - 82: oO0o * i11iIiiIii % o0oOOo0O0Ooo % IiII - I11i - OoO0O00
 if ( store == False ) :
  return ( [ Iii1IIiii1ii . global_etr_rloc , Iii1IIiii1ii . etr_port , O0oi11IIIII ] )
  if 24 - 24: oO0o . II111iiii + OoO0O00 * I1ii11iIi11i / oO0o
  if 86 - 86: I1Ii111 + I1ii11iIi11i
  if 63 - 63: ooOoO0o - i11iIiiIii . o0oOOo0O0Ooo - i1IIi - IiII
  if 32 - 32: I1Ii111 / iIii1I11I1II1 + oO0o % I11i * OoooooooOO
  if 69 - 69: OOooOOo
  if 9 - 9: i11iIiiIii * Oo0Ooo
 for i1iOo in lisp_db_list :
  for iIIiIiiI in i1iOo . rloc_set :
   oOoOoo0O = iIIiIiiI . rloc
   iIiiiIiIi = iIIiIiiI . interface
   if ( iIiiiIiIi == None ) :
    if ( oOoOoo0O . is_null ( ) ) : continue
    if ( oOoOoo0O . is_local ( ) == False ) : continue
    if ( Iii1IIiii1ii . private_etr_rloc . is_null ( ) == False and
 oOoOoo0O . is_exact_match ( Iii1IIiii1ii . private_etr_rloc ) == False ) :
     continue
     if 33 - 33: oO0o / ooOoO0o
   elif ( Iii1IIiii1ii . private_etr_rloc . is_dist_name ( ) ) :
    Iii1I1III1ii = Iii1IIiii1ii . private_etr_rloc . address
    if ( Iii1I1III1ii != iIIiIiiI . rloc_name ) : continue
    if 92 - 92: O0 . Oo0Ooo - Ii1I * I1IiiI * Oo0Ooo * iII111i
    if 78 - 78: Ii1I * iIii1I11I1II1 - Ii1I - I1ii11iIi11i * I1ii11iIi11i
   oo0ooooO = green ( i1iOo . eid . print_prefix ( ) , False )
   Oo0oO = red ( oOoOoo0O . print_address_no_iid ( ) , False )
   if 44 - 44: o0oOOo0O0Ooo
   iiii = Iii1IIiii1ii . global_etr_rloc . is_exact_match ( oOoOoo0O )
   if ( iIIiIiiI . translated_port == 0 and iiii ) :
    lprint ( "No NAT for {} ({}), EID-prefix {}" . format ( Oo0oO ,
 iIiiiIiIi , oo0ooooO ) )
    continue
    if 53 - 53: IiII - I1Ii111 - OOooOOo . OoOoOO00 / iIii1I11I1II1
    if 89 - 89: Oo0Ooo
    if 57 - 57: i1IIi - oO0o % IiII . I11i
    if 17 - 17: i1IIi % OoO0O00 + i11iIiiIii % I1Ii111 * ooOoO0o . I1ii11iIi11i
    if 64 - 64: O0 - iII111i
   oOo = Iii1IIiii1ii . global_etr_rloc
   OO0oOo0O0O00 = iIIiIiiI . translated_rloc
   if ( OO0oOo0O0O00 . is_exact_match ( oOo ) and
 Iii1IIiii1ii . etr_port == iIIiIiiI . translated_port ) : continue
   if 84 - 84: OOooOOo * ooOoO0o / O0
   lprint ( "Store translation {}:{} for {} ({}), EID-prefix {}" . format ( red ( Iii1IIiii1ii . global_etr_rloc . print_address_no_iid ( ) , False ) ,
   # O0 + Ii1I % II111iiii % i1IIi . iII111i / OoooooooOO
 Iii1IIiii1ii . etr_port , Oo0oO , iIiiiIiIi , oo0ooooO ) )
   if 8 - 8: OOooOOo + I1IiiI - Oo0Ooo + i1IIi . Ii1I . I1Ii111
   iIIiIiiI . store_translated_rloc ( Iii1IIiii1ii . global_etr_rloc ,
 Iii1IIiii1ii . etr_port )
   if 38 - 38: I1IiiI / II111iiii * OoOoOO00 / I1Ii111
   if 80 - 80: I1ii11iIi11i / ooOoO0o * ooOoO0o . Oo0Ooo
 return ( [ Iii1IIiii1ii . global_etr_rloc , Iii1IIiii1ii . etr_port , O0oi11IIIII ] )
 if 44 - 44: Ii1I * i1IIi % OoOoOO00 . OoOoOO00
 if 16 - 16: Oo0Ooo / i1IIi / iIii1I11I1II1 / iIii1I11I1II1 % o0oOOo0O0Ooo / I1ii11iIi11i
 if 11 - 11: I1IiiI
 if 45 - 45: OOooOOo / i1IIi * IiII * I1Ii111
 if 34 - 34: ooOoO0o / iIii1I11I1II1 . iII111i
 if 91 - 91: OoO0O00
 if 8 - 8: oO0o
 if 96 - 96: IiII
def lisp_test_mr ( lisp_sockets , port ) :
 return
 lprint ( "Test Map-Resolvers" )
 if 37 - 37: Ii1I % i11iIiiIii + iIii1I11I1II1 % Oo0Ooo - iIii1I11I1II1
 Ooo0 = lisp_address ( LISP_AFI_IPV4 , "" , 0 , 0 )
 iIi = lisp_address ( LISP_AFI_IPV6 , "" , 0 , 0 )
 if 62 - 62: IiII * I1ii11iIi11i % iIii1I11I1II1 / II111iiii - OoO0O00
 if 52 - 52: iII111i . I11i - I11i + oO0o + iIii1I11I1II1
 if 83 - 83: I11i * iIii1I11I1II1 + OoOoOO00
 if 81 - 81: ooOoO0o * OOooOOo / OoO0O00 + I1ii11iIi11i % I1Ii111
 Ooo0 . store_address ( "10.0.0.1" )
 lisp_send_map_request ( lisp_sockets , port , None , Ooo0 , None )
 Ooo0 . store_address ( "192.168.0.1" )
 lisp_send_map_request ( lisp_sockets , port , None , Ooo0 , None )
 if 37 - 37: i11iIiiIii - OoooooooOO - OoOoOO00 * oO0o / Ii1I
 if 100 - 100: II111iiii / Oo0Ooo / iII111i / OOooOOo
 if 100 - 100: iIii1I11I1II1
 if 50 - 50: I1Ii111 / ooOoO0o * I11i
 iIi . store_address ( "0100::1" )
 lisp_send_map_request ( lisp_sockets , port , None , iIi , None )
 iIi . store_address ( "8000::1" )
 lisp_send_map_request ( lisp_sockets , port , None , iIi , None )
 if 53 - 53: II111iiii . IiII
 if 5 - 5: i1IIi % IiII
 if 16 - 16: ooOoO0o - iII111i % Ii1I . OoOoOO00
 if 56 - 56: i11iIiiIii % i11iIiiIii % OoooooooOO . Ii1I . iII111i + I11i
 oOoII = threading . Timer ( LISP_TEST_MR_INTERVAL , lisp_test_mr ,
 [ lisp_sockets , port ] )
 oOoII . start ( )
 return
 if 34 - 34: OoO0O00 * iIii1I11I1II1 . iIii1I11I1II1
 if 39 - 39: o0oOOo0O0Ooo
 if 29 - 29: Oo0Ooo . Oo0Ooo * OoO0O00 % Ii1I - ooOoO0o
 if 67 - 67: I1IiiI % O0 + I1IiiI * I1Ii111 * OoOoOO00 * II111iiii
 if 79 - 79: I1IiiI
 if 37 - 37: I1Ii111 + Ii1I
 if 50 - 50: i11iIiiIii
 if 57 - 57: O0 * i1IIi - I1IiiI
 if 48 - 48: IiII / iIii1I11I1II1
 if 20 - 20: oO0o / OoooooooOO
 if 95 - 95: Oo0Ooo . i11iIiiIii
 if 50 - 50: iII111i . i11iIiiIii - i1IIi
 if 24 - 24: i11iIiiIii % iII111i . oO0o
def lisp_update_local_rloc ( rloc ) :
 if ( rloc . interface == None ) : return
 if 44 - 44: II111iiii - OoO0O00 + i11iIiiIii
 I1Iii1I = lisp_get_interface_address ( rloc . interface )
 if ( I1Iii1I == None ) : return
 if 34 - 34: I1ii11iIi11i % ooOoO0o / II111iiii * O0 % OOooOOo
 IIIIIi1 = rloc . rloc . print_address_no_iid ( )
 IiII11IIII1 = I1Iii1I . print_address_no_iid ( )
 if 45 - 45: oO0o % II111iiii
 if ( IIIIIi1 == IiII11IIII1 ) : return
 if 35 - 35: o0oOOo0O0Ooo * i11iIiiIii * i1IIi + i1IIi
 lprint ( "Local interface address changed on {} from {} to {}" . format ( rloc . interface , IIIIIi1 , IiII11IIII1 ) )
 if 2 - 2: Oo0Ooo % I1Ii111 * iIii1I11I1II1 - I1Ii111
 if 87 - 87: I1IiiI / Ii1I
 rloc . rloc . copy_address ( I1Iii1I )
 lisp_myrlocs [ 0 ] = I1Iii1I
 return
 if 54 - 54: OoooooooOO / Ii1I
 if 26 - 26: o0oOOo0O0Ooo + OoO0O00
 if 59 - 59: Ii1I * IiII
 if 64 - 64: ooOoO0o . Oo0Ooo - OoOoOO00
 if 66 - 66: OoOoOO00
 if 83 - 83: OOooOOo . IiII
 if 98 - 98: i11iIiiIii
 if 74 - 74: iIii1I11I1II1 * O0 + OOooOOo . o0oOOo0O0Ooo
def lisp_update_encap_port ( mc ) :
 for oOoOoo0O in mc . rloc_set :
  o0oO00ooo0o = lisp_get_nat_info ( oOoOoo0O . rloc , oOoOoo0O . rloc_name )
  if ( o0oO00ooo0o == None ) : continue
  if ( oOoOoo0O . translated_port == o0oO00ooo0o . port ) : continue
  if 17 - 17: I1Ii111
  lprint ( ( "Encap-port changed from {} to {} for RLOC {}, " + "EID-prefix {}" ) . format ( oOoOoo0O . translated_port , o0oO00ooo0o . port ,
  # O0 % ooOoO0o + oO0o + iII111i
 red ( oOoOoo0O . rloc . print_address_no_iid ( ) , False ) ,
 green ( mc . print_eid_tuple ( ) , False ) ) )
  if 4 - 4: OOooOOo . iII111i . I11i % I1Ii111 - Ii1I
  oOoOoo0O . store_translated_rloc ( oOoOoo0O . rloc , o0oO00ooo0o . port )
  if 43 - 43: OOooOOo + OoO0O00 % OoO0O00 . iIii1I11I1II1 + OoO0O00
 return
 if 14 - 14: O0 - O0 * Ii1I
 if 87 - 87: OoooooooOO - Ii1I * II111iiii % I1Ii111
 if 82 - 82: OoOoOO00 - OoOoOO00 + iIii1I11I1II1 + o0oOOo0O0Ooo + IiII - o0oOOo0O0Ooo
 if 65 - 65: I1Ii111 + OOooOOo
 if 97 - 97: oO0o % OoOoOO00 * oO0o % II111iiii + iIii1I11I1II1
 if 11 - 11: ooOoO0o . o0oOOo0O0Ooo
 if 94 - 94: ooOoO0o . oO0o * OoooooooOO % oO0o
 if 77 - 77: ooOoO0o % I1IiiI
 if 26 - 26: o0oOOo0O0Ooo
 if 72 - 72: I1IiiI
 if 90 - 90: ooOoO0o
 if 67 - 67: iIii1I11I1II1 + i1IIi * I1IiiI * OoooooooOO
def lisp_timeout_map_cache_entry ( mc , delete_list ) :
 if ( mc . map_cache_ttl == None ) :
  lisp_update_encap_port ( mc )
  return ( [ True , delete_list ] )
  if 23 - 23: IiII
  if 32 - 32: OoOoOO00 - iII111i % oO0o / I1ii11iIi11i - o0oOOo0O0Ooo
  if 52 - 52: Ii1I / OoooooooOO % i11iIiiIii + iII111i
  if 59 - 59: Ii1I / o0oOOo0O0Ooo / oO0o + iII111i * I1ii11iIi11i - o0oOOo0O0Ooo
  if 70 - 70: O0 / I1ii11iIi11i + ooOoO0o . OoO0O00 - OoO0O00 / i11iIiiIii
 if ( mc . action == LISP_NO_ACTION ) :
  o0Oo0O0 = lisp_get_timestamp ( )
  if ( mc . last_refresh_time + mc . map_cache_ttl > o0Oo0O0 ) :
   lisp_update_encap_port ( mc )
   return ( [ True , delete_list ] )
   if 1 - 1: iIii1I11I1II1 % I1ii11iIi11i
   if 49 - 49: iII111i + o0oOOo0O0Ooo % I1ii11iIi11i . O0 % OoooooooOO . o0oOOo0O0Ooo
   if 3 - 3: i11iIiiIii - i1IIi * o0oOOo0O0Ooo / OoOoOO00 % Oo0Ooo
   if 65 - 65: OoooooooOO + iII111i - i11iIiiIii - IiII + oO0o
   if 67 - 67: i1IIi * I1Ii111 * O0
   if 16 - 16: OoO0O00 + iII111i + i1IIi + I1ii11iIi11i - I1IiiI
 ooooOoO0O = lisp_print_elapsed ( mc . last_refresh_time )
 I1IIIIII = mc . print_eid_tuple ( )
 lprint ( "Map-cache entry for EID-prefix {} has {}, had uptime of {}" . format ( green ( I1IIIIII , False ) , bold ( "timed out" , False ) , ooooOoO0O ) )
 if 88 - 88: oO0o % iII111i + I1ii11iIi11i - II111iiii . I11i
 if 18 - 18: I1ii11iIi11i - i1IIi - IiII * II111iiii % I1Ii111 . II111iiii
 if 80 - 80: oO0o + OoO0O00 + o0oOOo0O0Ooo . OoOoOO00
 if 75 - 75: i11iIiiIii
 if 58 - 58: iII111i
 delete_list . append ( mc )
 return ( [ True , delete_list ] )
 if 48 - 48: OoO0O00 * OOooOOo / iII111i
 if 90 - 90: I1IiiI * i11iIiiIii . OOooOOo / o0oOOo0O0Ooo
 if 82 - 82: Oo0Ooo
 if 50 - 50: I1Ii111 * OOooOOo * OoOoOO00 / OoooooooOO % iII111i
 if 80 - 80: I1Ii111
 if 35 - 35: Ii1I . O0 % i11iIiiIii * oO0o - OoooooooOO
 if 87 - 87: iII111i * ooOoO0o - OOooOOo . O0
 if 20 - 20: OoOoOO00 - IiII
def lisp_timeout_map_cache_walk ( mc , parms ) :
 I1iii11 = parms [ 0 ]
 Ii1OOOO0oOo = parms [ 1 ]
 if 33 - 33: I1Ii111 + oO0o
 if 39 - 39: I11i * OoooooooOO . Oo0Ooo + IiII + ooOoO0o
 if 35 - 35: o0oOOo0O0Ooo % OOooOOo / I11i % Ii1I * IiII + i1IIi
 if 78 - 78: II111iiii + I1IiiI * Ii1I / Oo0Ooo
 if ( mc . group . is_null ( ) ) :
  oO00o0O , I1iii11 = lisp_timeout_map_cache_entry ( mc , I1iii11 )
  if ( I1iii11 == [ ] or mc != I1iii11 [ - 1 ] ) :
   Ii1OOOO0oOo = lisp_write_checkpoint_entry ( Ii1OOOO0oOo , mc )
   if 37 - 37: O0 / iIii1I11I1II1 . OoO0O00
  return ( [ oO00o0O , parms ] )
  if 43 - 43: I1IiiI % OoOoOO00 * O0 + o0oOOo0O0Ooo
  if 97 - 97: iIii1I11I1II1 + O0
 if ( mc . source_cache == None ) : return ( [ True , parms ] )
 if 41 - 41: OoOoOO00 - II111iiii
 if 46 - 46: OOooOOo
 if 73 - 73: iII111i - IiII + II111iiii
 if 58 - 58: Oo0Ooo % I1IiiI
 if 78 - 78: iII111i / iIii1I11I1II1 * IiII . ooOoO0o / I1Ii111 % I11i
 parms = mc . source_cache . walk_cache ( lisp_timeout_map_cache_entry , parms )
 return ( [ True , parms ] )
 if 14 - 14: II111iiii % iIii1I11I1II1 - I1IiiI % i11iIiiIii . OOooOOo * I1ii11iIi11i
 if 12 - 12: I1ii11iIi11i % I1ii11iIi11i . OoO0O00 . OoOoOO00
 if 73 - 73: I1ii11iIi11i * i1IIi * Oo0Ooo / O0
 if 1 - 1: iII111i * OOooOOo + II111iiii / Ii1I . I1ii11iIi11i
 if 61 - 61: oO0o % OoOoOO00 % ooOoO0o . I1Ii111 / OoO0O00
 if 21 - 21: IiII
 if 15 - 15: OoOoOO00 % O0 - OOooOOo - oO0o . iII111i . OoO0O00
def lisp_timeout_map_cache ( lisp_map_cache ) :
 i1I111Ii = [ [ ] , [ ] ]
 i1I111Ii = lisp_map_cache . walk_cache ( lisp_timeout_map_cache_walk , i1I111Ii )
 if 52 - 52: II111iiii * o0oOOo0O0Ooo
 if 95 - 95: I1Ii111 - OoooooooOO
 if 99 - 99: OoooooooOO % IiII . I11i + OoooooooOO
 if 57 - 57: Ii1I / I1IiiI * i1IIi
 if 21 - 21: I11i . O0 * OoooooooOO + ooOoO0o * oO0o % i11iIiiIii
 I1iii11 = i1I111Ii [ 0 ]
 for oOooO0Oo0Oo0 in I1iii11 : oOooO0Oo0Oo0 . delete_cache ( )
 if 30 - 30: ooOoO0o * I1Ii111 + OoO0O00
 if 30 - 30: Ii1I / iII111i * Ii1I
 if 11 - 11: OoOoOO00 - OoOoOO00 % oO0o
 if 3 - 3: I1IiiI - OoooooooOO % iIii1I11I1II1 + I1Ii111 + OoOoOO00
 Ii1OOOO0oOo = i1I111Ii [ 1 ]
 lisp_checkpoint ( Ii1OOOO0oOo )
 return
 if 71 - 71: i1IIi % O0 % ooOoO0o
 if 24 - 24: O0
 if 88 - 88: OoooooooOO / Oo0Ooo / oO0o
 if 99 - 99: I1Ii111 % OoOoOO00 % IiII - Ii1I
 if 79 - 79: ooOoO0o + Oo0Ooo
 if 80 - 80: OoOoOO00 % OoO0O00 . OoO0O00 * OoO0O00 * O0
 if 18 - 18: II111iiii . o0oOOo0O0Ooo + OoO0O00
 if 69 - 69: OoO0O00 . ooOoO0o * ooOoO0o * iIii1I11I1II1
 if 8 - 8: iII111i . oO0o . OOooOOo + iII111i . Ii1I
 if 46 - 46: OoO0O00
 if 21 - 21: iIii1I11I1II1 - iII111i
 if 15 - 15: O0 + iII111i + i11iIiiIii
 if 31 - 31: iIii1I11I1II1 * iIii1I11I1II1 . I11i
 if 52 - 52: i11iIiiIii / oO0o / IiII
 if 84 - 84: I11i . oO0o + ooOoO0o
 if 75 - 75: I1Ii111
def lisp_store_nat_info ( hostname , rloc , port ) :
 OoOOoooO000 = rloc . print_address_no_iid ( )
 o0oOOo00oO0 = "{} NAT state for {}, RLOC {}, port {}" . format ( "{}" ,
 blue ( hostname , False ) , red ( OoOOoooO000 , False ) , port )
 if 58 - 58: iII111i + I1IiiI . O0
 O0Ooo0 = lisp_nat_info ( OoOOoooO000 , hostname , port )
 if 48 - 48: Oo0Ooo - oO0o
 if ( lisp_nat_state_info . has_key ( hostname ) == False ) :
  lisp_nat_state_info [ hostname ] = [ O0Ooo0 ]
  lprint ( o0oOOo00oO0 . format ( "Store initial" ) )
  return ( True )
  if 80 - 80: OoO0O00 * OoOoOO00 - OoooooooOO * iII111i % ooOoO0o
  if 17 - 17: OoO0O00 % II111iiii . i1IIi . OOooOOo
  if 49 - 49: II111iiii / OoOoOO00 * IiII % OoO0O00
  if 77 - 77: OoOoOO00 + OOooOOo % o0oOOo0O0Ooo
  if 3 - 3: ooOoO0o / i1IIi
  if 71 - 71: Ii1I + oO0o % IiII
 o0oO00ooo0o = lisp_nat_state_info [ hostname ] [ 0 ]
 if ( o0oO00ooo0o . address == OoOOoooO000 and o0oO00ooo0o . port == port ) :
  o0oO00ooo0o . uptime = lisp_get_timestamp ( )
  lprint ( o0oOOo00oO0 . format ( "Refresh existing" ) )
  return ( False )
  if 15 - 15: ooOoO0o . Oo0Ooo
  if 42 - 42: OOooOOo . i11iIiiIii % O0 - OoO0O00
  if 34 - 34: OOooOOo % oO0o * OOooOOo * iIii1I11I1II1
  if 18 - 18: I1IiiI / I11i
  if 64 - 64: I11i * i11iIiiIii
  if 16 - 16: I1Ii111 * II111iiii * I1Ii111 . o0oOOo0O0Ooo
  if 96 - 96: ooOoO0o - o0oOOo0O0Ooo % O0 * Ii1I . OoOoOO00
 oo0O0Iii1IIi = None
 for o0oO00ooo0o in lisp_nat_state_info [ hostname ] :
  if ( o0oO00ooo0o . address == OoOOoooO000 and o0oO00ooo0o . port == port ) :
   oo0O0Iii1IIi = o0oO00ooo0o
   break
   if 10 - 10: iII111i - IiII + OoOoOO00 + I1IiiI + Oo0Ooo
   if 25 - 25: I1IiiI / I1ii11iIi11i % iII111i / O0 % II111iiii
   if 20 - 20: O0 % I11i * iII111i
 if ( oo0O0Iii1IIi == None ) :
  lprint ( o0oOOo00oO0 . format ( "Store new" ) )
 else :
  lisp_nat_state_info [ hostname ] . remove ( oo0O0Iii1IIi )
  lprint ( o0oOOo00oO0 . format ( "Use previous" ) )
  if 6 - 6: OoooooooOO % ooOoO0o % OoO0O00 * IiII
  if 62 - 62: i1IIi . I11i / I11i
 Ooo0oO0O00OoO = lisp_nat_state_info [ hostname ]
 lisp_nat_state_info [ hostname ] = [ O0Ooo0 ] + Ooo0oO0O00OoO
 return ( True )
 if 66 - 66: OOooOOo * i1IIi * o0oOOo0O0Ooo % OoOoOO00 % OoooooooOO * OoooooooOO
 if 51 - 51: II111iiii . OoOoOO00 / O0
 if 39 - 39: IiII . O0
 if 4 - 4: I1Ii111
 if 15 - 15: I11i % I11i / iIii1I11I1II1 - i11iIiiIii / i1IIi
 if 9 - 9: OoooooooOO
 if 71 - 71: Ii1I
 if 59 - 59: i1IIi * ooOoO0o . iIii1I11I1II1
def lisp_get_nat_info ( rloc , hostname ) :
 if ( lisp_nat_state_info . has_key ( hostname ) == False ) : return ( None )
 if 87 - 87: ooOoO0o % I1ii11iIi11i . I1IiiI
 OoOOoooO000 = rloc . print_address_no_iid ( )
 for o0oO00ooo0o in lisp_nat_state_info [ hostname ] :
  if ( o0oO00ooo0o . address == OoOOoooO000 ) : return ( o0oO00ooo0o )
  if 42 - 42: iII111i % i11iIiiIii % o0oOOo0O0Ooo . O0 % iII111i
 return ( None )
 if 72 - 72: Oo0Ooo . Oo0Ooo . IiII . Oo0Ooo
 if 80 - 80: I1Ii111 + IiII + O0 - I1Ii111 . iIii1I11I1II1
 if 53 - 53: OoO0O00 / i11iIiiIii * I1Ii111
 if 62 - 62: oO0o / Oo0Ooo / IiII + I11i * ooOoO0o
 if 84 - 84: ooOoO0o + OoOoOO00 * I1ii11iIi11i % OoooooooOO . O0
 if 27 - 27: OoO0O00 * OoooooooOO - II111iiii / o0oOOo0O0Ooo
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
def lisp_build_info_requests ( lisp_sockets , dest , port ) :
 if ( lisp_nat_traversal == False ) : return
 if 86 - 86: OoOoOO00
 if 4 - 4: OoooooooOO * OoO0O00
 if 93 - 93: OoO0O00 - I1Ii111 - OoO0O00
 if 1 - 1: o0oOOo0O0Ooo . oO0o * i11iIiiIii * IiII - OoO0O00 - OoooooooOO
 if 29 - 29: iIii1I11I1II1 + OoO0O00 * II111iiii * Ii1I * iII111i . O0
 if 6 - 6: I1IiiI - OoOoOO00
 oO0OoOoO = [ ]
 iIIII11 = [ ]
 if ( dest == None ) :
  for oOoooooOooO in lisp_map_resolvers_list . values ( ) :
   iIIII11 . append ( oOoooooOooO . map_resolver )
   if 19 - 19: I1Ii111 / I1Ii111 - i1IIi
  oO0OoOoO = iIIII11
  if ( oO0OoOoO == [ ] ) :
   for iiI in lisp_map_servers_list . values ( ) :
    oO0OoOoO . append ( iiI . map_server )
    if 99 - 99: O0
    if 37 - 37: iIii1I11I1II1 / I1Ii111 + OoO0O00
  if ( oO0OoOoO == [ ] ) : return
 else :
  oO0OoOoO . append ( dest )
  if 85 - 85: ooOoO0o / I1IiiI
  if 7 - 7: Oo0Ooo - iIii1I11I1II1 / I1ii11iIi11i * I1IiiI + Ii1I
  if 99 - 99: i11iIiiIii - I1ii11iIi11i
  if 64 - 64: IiII . OoOoOO00 . Oo0Ooo . I1Ii111 / I11i / Ii1I
  if 95 - 95: iIii1I11I1II1 . Ii1I % oO0o - I11i % IiII
 ooO0 = { }
 for i1iOo in lisp_db_list :
  for iIIiIiiI in i1iOo . rloc_set :
   lisp_update_local_rloc ( iIIiIiiI )
   if ( iIIiIiiI . rloc . is_null ( ) ) : continue
   if ( iIIiIiiI . interface == None ) : continue
   if 42 - 42: OoOoOO00 + oO0o * i1IIi + i11iIiiIii
   I1Iii1I = iIIiIiiI . rloc . print_address_no_iid ( )
   if ( I1Iii1I in ooO0 ) : continue
   ooO0 [ I1Iii1I ] = iIIiIiiI . interface
   if 25 - 25: Ii1I - Ii1I - I1ii11iIi11i / i1IIi . OoOoOO00 % Oo0Ooo
   if 76 - 76: I1Ii111 / OoOoOO00
 if ( ooO0 == { } ) :
  lprint ( 'Suppress Info-Request, no "interface = <device>" RLOC ' + "found in any database-mappings" )
  if 61 - 61: Oo0Ooo . i1IIi
  return
  if 78 - 78: i11iIiiIii
  if 20 - 20: Ii1I
  if 100 - 100: OoooooooOO . I1Ii111
  if 32 - 32: iIii1I11I1II1 . iIii1I11I1II1 % II111iiii / Oo0Ooo . iIii1I11I1II1 . O0
  if 63 - 63: I1IiiI . iIii1I11I1II1 . Oo0Ooo % OOooOOo - iII111i + ooOoO0o
  if 64 - 64: o0oOOo0O0Ooo / Ii1I % I1Ii111 % iII111i + OOooOOo * IiII
 for I1Iii1I in ooO0 :
  iIiiiIiIi = ooO0 [ I1Iii1I ]
  OOOO0o = red ( I1Iii1I , False )
  lprint ( "Build Info-Request for private address {} ({})" . format ( OOOO0o ,
 iIiiiIiIi ) )
  Ooooo = iIiiiIiIi if len ( ooO0 ) > 1 else None
  for dest in oO0OoOoO :
   lisp_send_info_request ( lisp_sockets , dest , port , Ooooo )
   if 87 - 87: I1ii11iIi11i . i1IIi - I11i + OoOoOO00 . O0
   if 37 - 37: IiII
   if 65 - 65: ooOoO0o * Ii1I / I1IiiI . i1IIi % ooOoO0o . OoooooooOO
   if 17 - 17: ooOoO0o / OoO0O00 / I1IiiI / OOooOOo % IiII
   if 88 - 88: i1IIi - OoOoOO00
   if 66 - 66: OoooooooOO - OoooooooOO * I11i / II111iiii + oO0o / Ii1I
 if ( iIIII11 != [ ] ) :
  for oOoooooOooO in lisp_map_resolvers_list . values ( ) :
   oOoooooOooO . resolve_dns_name ( )
   if 7 - 7: Ii1I / iIii1I11I1II1
   if 36 - 36: iIii1I11I1II1 % i11iIiiIii
 return
 if 35 - 35: Oo0Ooo + I1IiiI - O0 - I1Ii111
 if 64 - 64: i1IIi * OoOoOO00 / II111iiii * oO0o
 if 35 - 35: i1IIi - Ii1I - Ii1I . O0 % iII111i * iII111i
 if 15 - 15: OoooooooOO . Ii1I * I1Ii111 . ooOoO0o % OoO0O00 * Oo0Ooo
 if 10 - 10: iII111i + i11iIiiIii . OOooOOo % iII111i - i1IIi
 if 10 - 10: iIii1I11I1II1 * i11iIiiIii - O0
 if 45 - 45: oO0o % OOooOOo - IiII + o0oOOo0O0Ooo + i11iIiiIii
 if 79 - 79: IiII % I1Ii111 . I1IiiI + O0 * oO0o * ooOoO0o
def lisp_valid_address_format ( kw , value ) :
 if ( kw != "address" ) : return ( True )
 if 38 - 38: IiII
 if 78 - 78: Oo0Ooo * I1ii11iIi11i % OOooOOo / Oo0Ooo + I1ii11iIi11i * IiII
 if 2 - 2: Oo0Ooo - OoOoOO00
 if 22 - 22: OoO0O00 - oO0o - O0
 if 49 - 49: iIii1I11I1II1 + I1Ii111 / i11iIiiIii
 if ( value [ 0 ] == "'" and value [ - 1 ] == "'" ) : return ( True )
 if 62 - 62: ooOoO0o . I1IiiI * i11iIiiIii
 if 2 - 2: i11iIiiIii
 if 86 - 86: I1Ii111 + o0oOOo0O0Ooo
 if 17 - 17: iIii1I11I1II1
 if ( value . find ( "." ) != - 1 ) :
  I1Iii1I = value . split ( "." )
  if ( len ( I1Iii1I ) != 4 ) : return ( False )
  if 32 - 32: IiII - OoOoOO00
  for OOOo0oOO in I1Iii1I :
   if ( OOOo0oOO . isdigit ( ) == False ) : return ( False )
   if ( int ( OOOo0oOO ) > 255 ) : return ( False )
   if 70 - 70: OOooOOo * IiII * iII111i
  return ( True )
  if 45 - 45: iII111i * i11iIiiIii - IiII + I1ii11iIi11i % I1ii11iIi11i
  if 26 - 26: i11iIiiIii + ooOoO0o / OoOoOO00
  if 15 - 15: II111iiii - IiII
  if 74 - 74: i1IIi * OoooooooOO . Oo0Ooo . I1IiiI / o0oOOo0O0Ooo . OoOoOO00
  if 50 - 50: I1ii11iIi11i / iIii1I11I1II1 - Oo0Ooo - i11iIiiIii % o0oOOo0O0Ooo - ooOoO0o
 if ( value . find ( "-" ) != - 1 ) :
  I1Iii1I = value . split ( "-" )
  for oO in [ "N" , "S" , "W" , "E" ] :
   if ( oO in I1Iii1I ) :
    if ( len ( I1Iii1I ) < 8 ) : return ( False )
    return ( True )
    if 92 - 92: OoooooooOO - I1ii11iIi11i . I11i / O0 % iII111i
    if 96 - 96: I1IiiI . oO0o % O0
    if 19 - 19: iIii1I11I1II1 + I1Ii111 / OoooooooOO % OOooOOo - i1IIi + I11i
    if 87 - 87: OoooooooOO
    if 97 - 97: ooOoO0o * IiII / iIii1I11I1II1
    if 65 - 65: i1IIi - i11iIiiIii + oO0o % I1IiiI - OoO0O00 % ooOoO0o
    if 23 - 23: o0oOOo0O0Ooo . o0oOOo0O0Ooo - iIii1I11I1II1 / o0oOOo0O0Ooo
 if ( value . find ( "-" ) != - 1 ) :
  I1Iii1I = value . split ( "-" )
  if ( len ( I1Iii1I ) != 3 ) : return ( False )
  if 65 - 65: I1Ii111 + I1Ii111 . I1ii11iIi11i . OoOoOO00 % o0oOOo0O0Ooo * o0oOOo0O0Ooo
  for III1iI1iII in I1Iii1I :
   try : int ( III1iI1iII , 16 )
   except : return ( False )
   if 21 - 21: II111iiii
  return ( True )
  if 81 - 81: i1IIi + II111iiii * O0 * ooOoO0o
  if 46 - 46: OoOoOO00 . II111iiii * OoO0O00 . I1IiiI * o0oOOo0O0Ooo
  if 62 - 62: I1ii11iIi11i / iIii1I11I1II1 + oO0o . II111iiii
  if 65 - 65: Oo0Ooo % i1IIi * o0oOOo0O0Ooo * IiII
  if 24 - 24: i11iIiiIii / iIii1I11I1II1 / iII111i
 if ( value . find ( ":" ) != - 1 ) :
  I1Iii1I = value . split ( ":" )
  if ( len ( I1Iii1I ) < 2 ) : return ( False )
  if 31 - 31: OOooOOo . iIii1I11I1II1 - oO0o
  iiIi = False
  Ooo00OOOOOO0 = 0
  for III1iI1iII in I1Iii1I :
   Ooo00OOOOOO0 += 1
   if ( III1iI1iII == "" ) :
    if ( iiIi ) :
     if ( len ( I1Iii1I ) == Ooo00OOOOOO0 ) : break
     if ( Ooo00OOOOOO0 > 2 ) : return ( False )
     if 36 - 36: ooOoO0o - oO0o * IiII * OOooOOo / OoooooooOO % i1IIi
    iiIi = True
    continue
    if 73 - 73: OoOoOO00 / i1IIi * iII111i + II111iiii + II111iiii % I11i
   try : int ( III1iI1iII , 16 )
   except : return ( False )
   if 11 - 11: iII111i + o0oOOo0O0Ooo - iII111i - OoooooooOO
  return ( True )
  if 19 - 19: ooOoO0o % O0 % oO0o % OOooOOo % OoO0O00
  if 90 - 90: O0
  if 91 - 91: I1IiiI % ooOoO0o * iII111i % OoOoOO00 . OoOoOO00 + OoOoOO00
  if 95 - 95: o0oOOo0O0Ooo % i1IIi
  if 14 - 14: iIii1I11I1II1 + iIii1I11I1II1
 if ( value [ 0 ] == "+" ) :
  I1Iii1I = value [ 1 : : ]
  for OOOi11IIIIiIii in I1Iii1I :
   if ( OOOi11IIIIiIii . isdigit ( ) == False ) : return ( False )
   if 13 - 13: OOooOOo / O0
  return ( True )
  if 19 - 19: iIii1I11I1II1 + IiII * I11i * II111iiii + o0oOOo0O0Ooo + i11iIiiIii
 return ( False )
 if 69 - 69: iIii1I11I1II1 . II111iiii
 if 36 - 36: I1IiiI * i1IIi + OoOoOO00
 if 63 - 63: OoOoOO00 - iII111i
 if 83 - 83: i1IIi / iII111i % ooOoO0o % i11iIiiIii + I1ii11iIi11i
 if 82 - 82: iIii1I11I1II1 / OOooOOo
 if 7 - 7: OoooooooOO
 if 71 - 71: OOooOOo * Oo0Ooo . Oo0Ooo % iIii1I11I1II1
 if 56 - 56: IiII * iIii1I11I1II1 - iIii1I11I1II1 . O0
 if 56 - 56: I1Ii111 / iIii1I11I1II1 % IiII * iIii1I11I1II1 . I1ii11iIi11i . OOooOOo
 if 1 - 1: Ii1I . Ii1I % II111iiii + I11i + OoOoOO00
 if 52 - 52: OoooooooOO - OoO0O00
 if 24 - 24: iII111i / Oo0Ooo - I1ii11iIi11i + o0oOOo0O0Ooo
def lisp_process_api ( process , lisp_socket , data_structure ) :
 IIiIiII , i1I111Ii = data_structure . split ( "%" )
 if 24 - 24: II111iiii
 lprint ( "Process API request '{}', parameters: '{}'" . format ( IIiIiII ,
 i1I111Ii ) )
 if 40 - 40: o0oOOo0O0Ooo . I1IiiI - o0oOOo0O0Ooo
 iii1iII1iii = [ ]
 if ( IIiIiII == "map-cache" ) :
  if ( i1I111Ii == "" ) :
   iii1iII1iii = lisp_map_cache . walk_cache ( lisp_process_api_map_cache , iii1iII1iii )
  else :
   iii1iII1iii = lisp_process_api_map_cache_entry ( json . loads ( i1I111Ii ) )
   if 62 - 62: oO0o
   if 71 - 71: i1IIi . I1ii11iIi11i / i11iIiiIii + II111iiii
 if ( IIiIiII == "site-cache" ) :
  if ( i1I111Ii == "" ) :
   iii1iII1iii = lisp_sites_by_eid . walk_cache ( lisp_process_api_site_cache ,
 iii1iII1iii )
  else :
   iii1iII1iii = lisp_process_api_site_cache_entry ( json . loads ( i1I111Ii ) )
   if 14 - 14: iII111i
   if 35 - 35: Ii1I
 if ( IIiIiII == "map-server" ) :
  i1I111Ii = { } if ( i1I111Ii == "" ) else json . loads ( i1I111Ii )
  iii1iII1iii = lisp_process_api_ms_or_mr ( True , i1I111Ii )
  if 54 - 54: OOooOOo
 if ( IIiIiII == "map-resolver" ) :
  i1I111Ii = { } if ( i1I111Ii == "" ) else json . loads ( i1I111Ii )
  iii1iII1iii = lisp_process_api_ms_or_mr ( False , i1I111Ii )
  if 83 - 83: i1IIi / II111iiii - I1IiiI + I1ii11iIi11i . IiII * oO0o
 if ( IIiIiII == "database-mapping" ) :
  iii1iII1iii = lisp_process_api_database_mapping ( )
  if 92 - 92: OoOoOO00 + oO0o % Ii1I / Ii1I - iII111i
  if 11 - 11: Oo0Ooo % II111iiii * Ii1I + II111iiii
  if 9 - 9: I1Ii111
  if 69 - 69: i1IIi + ooOoO0o + Ii1I
  if 88 - 88: OoOoOO00 + iII111i % O0 + OOooOOo / OoooooooOO / OOooOOo
 iii1iII1iii = json . dumps ( iii1iII1iii )
 OOOO0OoO0oOOoo0 = lisp_api_ipc ( process , iii1iII1iii )
 lisp_ipc ( OOOO0OoO0oOOoo0 , lisp_socket , "lisp-core" )
 return
 if 95 - 95: ooOoO0o . Oo0Ooo % IiII + iII111i
 if 16 - 16: I11i * OoO0O00 % o0oOOo0O0Ooo - O0 % II111iiii - I1IiiI
 if 72 - 72: OoooooooOO * OoOoOO00 . OOooOOo + Ii1I . OOooOOo / II111iiii
 if 8 - 8: i1IIi
 if 1 - 1: OoOoOO00 . OoO0O00 . OoO0O00 * O0
 if 97 - 97: OoooooooOO % ooOoO0o . I1Ii111 / iII111i
 if 59 - 59: II111iiii + O0 . I1ii11iIi11i . Oo0Ooo * OoO0O00
def lisp_process_api_map_cache ( mc , data ) :
 if 35 - 35: oO0o / I1Ii111 * OOooOOo + OoooooooOO . IiII
 if 1 - 1: I1IiiI + I1Ii111 / OOooOOo . Ii1I . oO0o / I1ii11iIi11i
 if 54 - 54: OOooOOo
 if 86 - 86: oO0o * Oo0Ooo / OOooOOo
 if ( mc . group . is_null ( ) ) : return ( lisp_gather_map_cache_data ( mc , data ) )
 if 18 - 18: II111iiii - I1Ii111
 if ( mc . source_cache == None ) : return ( [ True , data ] )
 if 13 - 13: i11iIiiIii - O0 % OoOoOO00 + OOooOOo * ooOoO0o
 if 55 - 55: i1IIi - OOooOOo / I11i * Ii1I
 if 20 - 20: OoOoOO00 * iIii1I11I1II1 % O0 - i1IIi
 if 51 - 51: I1ii11iIi11i * Ii1I - oO0o / O0 * OoooooooOO
 if 12 - 12: i1IIi / iIii1I11I1II1 / O0 * OoO0O00
 data = mc . source_cache . walk_cache ( lisp_gather_map_cache_data , data )
 return ( [ True , data ] )
 if 15 - 15: i11iIiiIii / IiII + Ii1I % OOooOOo % I1ii11iIi11i * oO0o
 if 24 - 24: OOooOOo / OOooOOo + I11i / iII111i . oO0o - iII111i
 if 59 - 59: I1ii11iIi11i % II111iiii - i11iIiiIii - I1Ii111
 if 34 - 34: II111iiii + iII111i / IiII
 if 47 - 47: OoO0O00
 if 40 - 40: o0oOOo0O0Ooo / iII111i . o0oOOo0O0Ooo
 if 63 - 63: o0oOOo0O0Ooo * iIii1I11I1II1 * II111iiii . OoO0O00 - oO0o / OoOoOO00
def lisp_gather_map_cache_data ( mc , data ) :
 oOoO = { }
 oOoO [ "instance-id" ] = str ( mc . eid . instance_id )
 oOoO [ "eid-prefix" ] = mc . eid . print_prefix_no_iid ( )
 if ( mc . group . is_null ( ) == False ) :
  oOoO [ "group-prefix" ] = mc . group . print_prefix_no_iid ( )
  if 78 - 78: i11iIiiIii / OoO0O00 / i1IIi . i11iIiiIii
 oOoO [ "uptime" ] = lisp_print_elapsed ( mc . uptime )
 oOoO [ "expires" ] = lisp_print_elapsed ( mc . uptime )
 oOoO [ "action" ] = lisp_map_reply_action_string [ mc . action ]
 oOoO [ "ttl" ] = "--" if mc . map_cache_ttl == None else str ( mc . map_cache_ttl / 60 )
 if 100 - 100: II111iiii . IiII . I11i
 if 60 - 60: OoOoOO00 % OOooOOo * i1IIi
 if 3 - 3: OoooooooOO
 if 75 - 75: OoooooooOO * I1Ii111 * o0oOOo0O0Ooo + I1ii11iIi11i . iIii1I11I1II1 / O0
 if 23 - 23: oO0o - O0 * IiII + i11iIiiIii * Ii1I
 I111iIi11Ii11III = [ ]
 for oOoOoo0O in mc . rloc_set :
  iI111I1 = { }
  if ( oOoOoo0O . rloc_exists ( ) ) :
   iI111I1 [ "address" ] = oOoOoo0O . rloc . print_address_no_iid ( )
   if 8 - 8: ooOoO0o / II111iiii . I1ii11iIi11i * ooOoO0o % oO0o
   if 36 - 36: I1ii11iIi11i % OOooOOo - ooOoO0o - I11i + I1IiiI
  if ( oOoOoo0O . translated_port != 0 ) :
   iI111I1 [ "encap-port" ] = str ( oOoOoo0O . translated_port )
   if 37 - 37: I1ii11iIi11i * IiII
  iI111I1 [ "state" ] = oOoOoo0O . print_state ( )
  if ( oOoOoo0O . geo ) : iI111I1 [ "geo" ] = oOoOoo0O . geo . print_geo ( )
  if ( oOoOoo0O . elp ) : iI111I1 [ "elp" ] = oOoOoo0O . elp . print_elp ( False )
  if ( oOoOoo0O . rle ) : iI111I1 [ "rle" ] = oOoOoo0O . rle . print_rle ( False )
  if ( oOoOoo0O . json ) : iI111I1 [ "json" ] = oOoOoo0O . json . print_json ( False )
  if ( oOoOoo0O . rloc_name ) : iI111I1 [ "rloc-name" ] = oOoOoo0O . rloc_name
  i1i1Ii11 = oOoOoo0O . stats . get_stats ( False , False )
  if ( i1i1Ii11 ) : iI111I1 [ "stats" ] = i1i1Ii11
  iI111I1 [ "uptime" ] = lisp_print_elapsed ( oOoOoo0O . uptime )
  iI111I1 [ "upriority" ] = str ( oOoOoo0O . priority )
  iI111I1 [ "uweight" ] = str ( oOoOoo0O . weight )
  iI111I1 [ "mpriority" ] = str ( oOoOoo0O . mpriority )
  iI111I1 [ "mweight" ] = str ( oOoOoo0O . mweight )
  O0ooOoOO0OoO0O0 = oOoOoo0O . last_rloc_probe_reply
  if ( O0ooOoOO0OoO0O0 ) :
   iI111I1 [ "last-rloc-probe-reply" ] = lisp_print_elapsed ( O0ooOoOO0OoO0O0 )
   iI111I1 [ "rloc-probe-rtt" ] = str ( oOoOoo0O . rloc_probe_rtt )
   if 86 - 86: I11i * iIii1I11I1II1 - I1ii11iIi11i % IiII . OOooOOo * I1Ii111
  iI111I1 [ "rloc-hop-count" ] = oOoOoo0O . rloc_probe_hops
  iI111I1 [ "recent-rloc-hop-counts" ] = oOoOoo0O . recent_rloc_probe_hops
  if 49 - 49: OoOoOO00 * OoOoOO00
  oO0O0o = [ ]
  for i1I1Ii in oOoOoo0O . recent_rloc_probe_rtts : oO0O0o . append ( str ( i1I1Ii ) )
  iI111I1 [ "recent-rloc-probe-rtts" ] = oO0O0o
  if 57 - 57: iII111i * I1IiiI
  I111iIi11Ii11III . append ( iI111I1 )
  if 11 - 11: Ii1I . oO0o . I1IiiI
 oOoO [ "rloc-set" ] = I111iIi11Ii11III
 if 19 - 19: i1IIi - O0 / iIii1I11I1II1
 data . append ( oOoO )
 return ( [ True , data ] )
 if 71 - 71: Ii1I * I1IiiI
 if 62 - 62: II111iiii / I1IiiI . I1ii11iIi11i
 if 49 - 49: IiII / OoOoOO00 / O0 * i11iIiiIii
 if 47 - 47: i11iIiiIii + iII111i + i11iIiiIii
 if 66 - 66: o0oOOo0O0Ooo . I1IiiI + OoooooooOO . iII111i / OoooooooOO - IiII
 if 47 - 47: o0oOOo0O0Ooo / II111iiii * i11iIiiIii * OoO0O00 . iIii1I11I1II1
 if 34 - 34: I11i / o0oOOo0O0Ooo * OOooOOo * OOooOOo
def lisp_process_api_map_cache_entry ( parms ) :
 IIiI1i = parms [ "instance-id" ]
 IIiI1i = 0 if ( IIiI1i == "" ) else int ( IIiI1i )
 if 89 - 89: I1ii11iIi11i . OoooooooOO
 if 61 - 61: i1IIi + i11iIiiIii
 if 59 - 59: i11iIiiIii * OOooOOo + i1IIi * iIii1I11I1II1 + I11i
 if 97 - 97: OoO0O00 - I11i . OoooooooOO
 Ooo0 = lisp_address ( LISP_AFI_NONE , "" , 0 , IIiI1i )
 Ooo0 . store_prefix ( parms [ "eid-prefix" ] )
 I1I1I1 = Ooo0
 O00oo0o0o0oo = Ooo0
 if 58 - 58: I1ii11iIi11i / II111iiii / i11iIiiIii
 if 27 - 27: iIii1I11I1II1 - O0 + OoOoOO00
 if 28 - 28: oO0o . IiII * iII111i % Oo0Ooo - OoO0O00 / I11i
 if 67 - 67: i11iIiiIii + i11iIiiIii / ooOoO0o - o0oOOo0O0Ooo
 if 94 - 94: O0 + OoO0O00 / I1IiiI * II111iiii * i11iIiiIii
 ooOoO00 = lisp_address ( LISP_AFI_NONE , "" , 0 , IIiI1i )
 if ( parms . has_key ( "group-prefix" ) ) :
  ooOoO00 . store_prefix ( parms [ "group-prefix" ] )
  I1I1I1 = ooOoO00
  if 55 - 55: OoooooooOO * O0 + i1IIi % I1IiiI
  if 10 - 10: II111iiii - Ii1I . I11i . O0 + Ii1I
 iii1iII1iii = [ ]
 oOooO0Oo0Oo0 = lisp_map_cache_lookup ( O00oo0o0o0oo , I1I1I1 )
 if ( oOooO0Oo0Oo0 ) : oO00o0O , iii1iII1iii = lisp_process_api_map_cache ( oOooO0Oo0Oo0 , iii1iII1iii )
 return ( iii1iII1iii )
 if 50 - 50: iIii1I11I1II1 / Ii1I . ooOoO0o / ooOoO0o * OoOoOO00 * iII111i
 if 15 - 15: o0oOOo0O0Ooo % II111iiii + I1IiiI
 if 21 - 21: I1ii11iIi11i - ooOoO0o
 if 81 - 81: iII111i / i11iIiiIii / I1Ii111
 if 70 - 70: I1ii11iIi11i / i11iIiiIii
 if 90 - 90: II111iiii / OoOoOO00 . Ii1I . OoooooooOO
 if 76 - 76: OoooooooOO
def lisp_process_api_site_cache ( se , data ) :
 if 78 - 78: IiII % i11iIiiIii
 if 23 - 23: iIii1I11I1II1 - o0oOOo0O0Ooo - Ii1I % OOooOOo
 if 100 - 100: oO0o . OoO0O00 . i11iIiiIii % II111iiii * IiII
 if 81 - 81: OOooOOo - OOooOOo + OoOoOO00
 if ( se . group . is_null ( ) ) : return ( lisp_gather_site_cache_data ( se , data ) )
 if 19 - 19: o0oOOo0O0Ooo
 if ( se . source_cache == None ) : return ( [ True , data ] )
 if 20 - 20: I1Ii111 + iIii1I11I1II1 % I1IiiI + ooOoO0o
 if 86 - 86: o0oOOo0O0Ooo * i11iIiiIii - I11i
 if 71 - 71: OoO0O00 - I11i
 if 96 - 96: I1Ii111 / Ii1I
 if 65 - 65: I1ii11iIi11i * O0 . IiII
 data = se . source_cache . walk_cache ( lisp_gather_site_cache_data , data )
 return ( [ True , data ] )
 if 11 - 11: I11i / Ii1I % oO0o
 if 50 - 50: i11iIiiIii
 if 93 - 93: i1IIi / Ii1I * II111iiii - Oo0Ooo . OoOoOO00 - OOooOOo
 if 25 - 25: I11i / ooOoO0o % ooOoO0o - OOooOOo
 if 59 - 59: I1IiiI + o0oOOo0O0Ooo . iIii1I11I1II1 - O0 - i11iIiiIii
 if 4 - 4: I1IiiI
 if 36 - 36: Ii1I
def lisp_process_api_ms_or_mr ( ms_or_mr , data ) :
 i1i1Ii1Ii = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
 OoOo00o0o0oO = data [ "dns-name" ] if data . has_key ( "dns-name" ) else None
 if ( data . has_key ( "address" ) ) :
  i1i1Ii1Ii . store_address ( data [ "address" ] )
  if 76 - 76: i11iIiiIii + i1IIi
  if 56 - 56: OoOoOO00 + II111iiii / i11iIiiIii * OoOoOO00 * OoooooooOO
 oOOO = { }
 if ( ms_or_mr ) :
  for iiI in lisp_map_servers_list . values ( ) :
   if ( OoOo00o0o0oO ) :
    if ( OoOo00o0o0oO != iiI . dns_name ) : continue
   else :
    if ( i1i1Ii1Ii . is_exact_match ( iiI . map_server ) == False ) : continue
    if 15 - 15: OoOoOO00 / OoooooooOO + OOooOOo
    if 76 - 76: Ii1I * iII111i . OoooooooOO
   oOOO [ "dns-name" ] = iiI . dns_name
   oOOO [ "address" ] = iiI . map_server . print_address_no_iid ( )
   oOOO [ "ms-name" ] = "" if iiI . ms_name == None else iiI . ms_name
   return ( [ oOOO ] )
   if 92 - 92: iIii1I11I1II1 - Oo0Ooo - I1IiiI - OOooOOo * I1Ii111
 else :
  for oOoooooOooO in lisp_map_resolvers_list . values ( ) :
   if ( OoOo00o0o0oO ) :
    if ( OoOo00o0o0oO != oOoooooOooO . dns_name ) : continue
   else :
    if ( i1i1Ii1Ii . is_exact_match ( oOoooooOooO . map_resolver ) == False ) : continue
    if 44 - 44: I1Ii111 - II111iiii / OOooOOo
    if 50 - 50: I11i / I1ii11iIi11i
   oOOO [ "dns-name" ] = oOoooooOooO . dns_name
   oOOO [ "address" ] = oOoooooOooO . map_resolver . print_address_no_iid ( )
   oOOO [ "mr-name" ] = "" if oOoooooOooO . mr_name == None else oOoooooOooO . mr_name
   return ( [ oOOO ] )
   if 60 - 60: II111iiii / Ii1I + OoO0O00 % I1IiiI * i1IIi / II111iiii
   if 91 - 91: I1IiiI * I1Ii111 * i11iIiiIii - oO0o - IiII + I1ii11iIi11i
 return ( [ ] )
 if 99 - 99: OoO0O00 % o0oOOo0O0Ooo
 if 3 - 3: OOooOOo / OoOoOO00 % iIii1I11I1II1
 if 47 - 47: ooOoO0o . i11iIiiIii / OoO0O00
 if 48 - 48: O0
 if 89 - 89: i11iIiiIii % OoO0O00 . OoOoOO00 + Oo0Ooo + OoOoOO00
 if 53 - 53: Ii1I / OoOoOO00 % iII111i * OoooooooOO + Oo0Ooo
 if 70 - 70: OoO0O00 % OoO0O00 * OoooooooOO
 if 96 - 96: ooOoO0o * Ii1I + I11i + II111iiii * I1IiiI / iII111i
def lisp_process_api_database_mapping ( ) :
 iii1iII1iii = [ ]
 if 40 - 40: OoooooooOO - I11i % OOooOOo - I1IiiI . I1IiiI + Ii1I
 for i1iOo in lisp_db_list :
  oOoO = { }
  oOoO [ "eid-prefix" ] = i1iOo . eid . print_prefix ( )
  if ( i1iOo . group . is_null ( ) == False ) :
   oOoO [ "group-prefix" ] = i1iOo . group . print_prefix ( )
   if 97 - 97: OOooOOo . OoooooooOO . OOooOOo . i11iIiiIii
   if 71 - 71: oO0o + I1ii11iIi11i * I1ii11iIi11i
  i1iiii11I = [ ]
  for iI111I1 in i1iOo . rloc_set :
   oOoOoo0O = { }
   if ( iI111I1 . rloc . is_null ( ) == False ) :
    oOoOoo0O [ "rloc" ] = iI111I1 . rloc . print_address_no_iid ( )
    if 79 - 79: oO0o
   if ( iI111I1 . rloc_name != None ) : oOoOoo0O [ "rloc-name" ] = iI111I1 . rloc_name
   if ( iI111I1 . interface != None ) : oOoOoo0O [ "interface" ] = iI111I1 . interface
   ii1i1i1i1 = iI111I1 . translated_rloc
   if ( ii1i1i1i1 . is_null ( ) == False ) :
    oOoOoo0O [ "translated-rloc" ] = ii1i1i1i1 . print_address_no_iid ( )
    if 4 - 4: o0oOOo0O0Ooo - O0 * OoooooooOO % O0 * Ii1I
   if ( oOoOoo0O != { } ) : i1iiii11I . append ( oOoOoo0O )
   if 3 - 3: IiII + OoooooooOO - i1IIi
   if 94 - 94: ooOoO0o / iIii1I11I1II1 + I11i + I1ii11iIi11i
   if 67 - 67: IiII / o0oOOo0O0Ooo . O0
   if 7 - 7: II111iiii . OoOoOO00 % OoOoOO00 % Ii1I + Oo0Ooo - ooOoO0o
   if 29 - 29: OoOoOO00 - i1IIi
  oOoO [ "rlocs" ] = i1iiii11I
  if 5 - 5: I1IiiI - ooOoO0o + O0
  if 47 - 47: i1IIi - II111iiii - II111iiii
  if 31 - 31: Ii1I
  if 37 - 37: I1ii11iIi11i - Ii1I / oO0o . I1IiiI % I1Ii111
  iii1iII1iii . append ( oOoO )
  if 8 - 8: oO0o
 return ( iii1iII1iii )
 if 46 - 46: I1Ii111 + IiII + II111iiii . o0oOOo0O0Ooo + i11iIiiIii
 if 97 - 97: o0oOOo0O0Ooo % OoOoOO00 * O0 / iIii1I11I1II1 * OoO0O00 / i11iIiiIii
 if 1 - 1: OoooooooOO . Ii1I
 if 68 - 68: Ii1I
 if 98 - 98: iII111i
 if 33 - 33: OoO0O00 - ooOoO0o % O0 % iIii1I11I1II1 * iII111i - iII111i
 if 27 - 27: i11iIiiIii + I1ii11iIi11i + i1IIi
def lisp_gather_site_cache_data ( se , data ) :
 oOoO = { }
 oOoO [ "site-name" ] = se . site . site_name
 oOoO [ "instance-id" ] = str ( se . eid . instance_id )
 oOoO [ "eid-prefix" ] = se . eid . print_prefix_no_iid ( )
 if ( se . group . is_null ( ) == False ) :
  oOoO [ "group-prefix" ] = se . group . print_prefix_no_iid ( )
  if 67 - 67: o0oOOo0O0Ooo
 oOoO [ "registered" ] = "yes" if se . registered else "no"
 oOoO [ "first-registered" ] = lisp_print_elapsed ( se . first_registered )
 oOoO [ "last-registered" ] = lisp_print_elapsed ( se . last_registered )
 if 58 - 58: IiII % o0oOOo0O0Ooo + i1IIi
 I1Iii1I = se . last_registerer
 I1Iii1I = "none" if I1Iii1I . is_null ( ) else I1Iii1I . print_address ( )
 oOoO [ "last-registerer" ] = I1Iii1I
 oOoO [ "ams" ] = "yes" if ( se . accept_more_specifics ) else "no"
 oOoO [ "dynamic" ] = "yes" if ( se . dynamic ) else "no"
 oOoO [ "site-id" ] = str ( se . site_id )
 if ( se . xtr_id_present ) :
  oOoO [ "xtr-id" ] = "0x" + lisp_hex_string ( se . xtr_id )
  if 33 - 33: II111iiii
  if 61 - 61: I1Ii111
  if 56 - 56: I1ii11iIi11i - OoooooooOO
  if 52 - 52: Oo0Ooo - I11i - IiII - OoOoOO00
  if 21 - 21: oO0o % o0oOOo0O0Ooo + I1Ii111 . OOooOOo / OOooOOo
 I111iIi11Ii11III = [ ]
 for oOoOoo0O in se . registered_rlocs :
  iI111I1 = { }
  iI111I1 [ "address" ] = oOoOoo0O . rloc . print_address_no_iid ( ) if oOoOoo0O . rloc_exists ( ) else "none"
  if 41 - 41: Oo0Ooo . ooOoO0o * oO0o
  if 31 - 31: Oo0Ooo * IiII / IiII
  if ( oOoOoo0O . geo ) : iI111I1 [ "geo" ] = oOoOoo0O . geo . print_geo ( )
  if ( oOoOoo0O . elp ) : iI111I1 [ "elp" ] = oOoOoo0O . elp . print_elp ( False )
  if ( oOoOoo0O . rle ) : iI111I1 [ "rle" ] = oOoOoo0O . rle . print_rle ( False )
  if ( oOoOoo0O . json ) : iI111I1 [ "json" ] = oOoOoo0O . json . print_json ( False )
  if ( oOoOoo0O . rloc_name ) : iI111I1 [ "rloc-name" ] = oOoOoo0O . rloc_name
  iI111I1 [ "uptime" ] = lisp_print_elapsed ( oOoOoo0O . uptime )
  iI111I1 [ "upriority" ] = str ( oOoOoo0O . priority )
  iI111I1 [ "uweight" ] = str ( oOoOoo0O . weight )
  iI111I1 [ "mpriority" ] = str ( oOoOoo0O . mpriority )
  iI111I1 [ "mweight" ] = str ( oOoOoo0O . mweight )
  if 3 - 3: I1Ii111
  I111iIi11Ii11III . append ( iI111I1 )
  if 65 - 65: iIii1I11I1II1 % Oo0Ooo % I11i / OoooooooOO
 oOoO [ "registered-rlocs" ] = I111iIi11Ii11III
 if 82 - 82: o0oOOo0O0Ooo
 data . append ( oOoO )
 return ( [ True , data ] )
 if 33 - 33: OoOoOO00 / i11iIiiIii - I1IiiI - OoooooooOO + i1IIi * I1Ii111
 if 92 - 92: iII111i + OoO0O00
 if 70 - 70: iIii1I11I1II1
 if 100 - 100: OOooOOo . oO0o % ooOoO0o * ooOoO0o . I1Ii111 - oO0o
 if 33 - 33: Oo0Ooo . i1IIi - OoooooooOO
 if 14 - 14: I1Ii111 + Oo0Ooo
 if 35 - 35: i11iIiiIii * Ii1I
def lisp_process_api_site_cache_entry ( parms ) :
 IIiI1i = parms [ "instance-id" ]
 IIiI1i = 0 if ( IIiI1i == "" ) else int ( IIiI1i )
 if 100 - 100: O0 . iII111i / iIii1I11I1II1
 if 47 - 47: ooOoO0o + OoOoOO00
 if 67 - 67: IiII - I1ii11iIi11i * i1IIi - ooOoO0o
 if 91 - 91: I11i
 Ooo0 = lisp_address ( LISP_AFI_NONE , "" , 0 , IIiI1i )
 Ooo0 . store_prefix ( parms [ "eid-prefix" ] )
 if 54 - 54: I1ii11iIi11i / i1IIi
 if 14 - 14: iIii1I11I1II1 * I11i . I11i * ooOoO0o * iII111i
 if 60 - 60: iIii1I11I1II1 + i1IIi + oO0o - iIii1I11I1II1 . i11iIiiIii * OoooooooOO
 if 23 - 23: iII111i - IiII % i11iIiiIii
 if 81 - 81: OoooooooOO % OoOoOO00 / IiII / OoooooooOO + i1IIi - O0
 ooOoO00 = lisp_address ( LISP_AFI_NONE , "" , 0 , IIiI1i )
 if ( parms . has_key ( "group-prefix" ) ) :
  ooOoO00 . store_prefix ( parms [ "group-prefix" ] )
  if 60 - 60: OOooOOo - I1Ii111 * Oo0Ooo
  if 9 - 9: OoooooooOO * OOooOOo % OoO0O00 - ooOoO0o + Ii1I
 iii1iII1iii = [ ]
 oo00oO0 = lisp_site_eid_lookup ( Ooo0 , ooOoO00 , False )
 if ( oo00oO0 ) : lisp_gather_site_cache_data ( oo00oO0 , iii1iII1iii )
 return ( iii1iII1iii )
 if 39 - 39: iIii1I11I1II1 / i1IIi % I11i % I1ii11iIi11i * IiII
 if 11 - 11: II111iiii + i1IIi
 if 1 - 1: OOooOOo
 if 23 - 23: i1IIi + OoooooooOO * OOooOOo . Oo0Ooo
 if 83 - 83: OoooooooOO
 if 53 - 53: o0oOOo0O0Ooo - Oo0Ooo / IiII + O0
 if 88 - 88: Oo0Ooo % I1Ii111 * O0 - i1IIi * OoO0O00
def lisp_get_interface_instance_id ( device , source_eid ) :
 iIiiiIiIi = None
 if ( lisp_myinterfaces . has_key ( device ) ) :
  iIiiiIiIi = lisp_myinterfaces [ device ]
  if 74 - 74: Oo0Ooo % iIii1I11I1II1 + OOooOOo
  if 50 - 50: OoO0O00 . OoooooooOO
  if 31 - 31: OoO0O00
  if 55 - 55: OoOoOO00 + I1Ii111 * o0oOOo0O0Ooo - I1ii11iIi11i + OoOoOO00
  if 6 - 6: II111iiii % iIii1I11I1II1 * I1Ii111
  if 2 - 2: IiII - I1Ii111 . iIii1I11I1II1 - Ii1I * I11i
 if ( iIiiiIiIi == None or iIiiiIiIi . instance_id == None ) :
  return ( lisp_default_iid )
  if 58 - 58: i1IIi % iIii1I11I1II1 % i11iIiiIii - o0oOOo0O0Ooo + ooOoO0o
  if 23 - 23: Oo0Ooo % Oo0Ooo / IiII
  if 63 - 63: I11i % Oo0Ooo * I1Ii111 - Oo0Ooo % i11iIiiIii . II111iiii
  if 44 - 44: I11i . I1Ii111 . I1ii11iIi11i . oO0o
  if 1 - 1: I11i % II111iiii / OoO0O00 + OoO0O00
  if 46 - 46: Oo0Ooo * Ii1I / IiII % O0 * iII111i
  if 74 - 74: OoooooooOO + Ii1I
  if 100 - 100: I1IiiI
  if 59 - 59: I1IiiI - OoOoOO00 * ooOoO0o / O0
 IIiI1i = iIiiiIiIi . get_instance_id ( )
 if ( source_eid == None ) : return ( IIiI1i )
 if 54 - 54: Oo0Ooo % iIii1I11I1II1 * Oo0Ooo
 oOOoOOO0 = source_eid . instance_id
 IiIIiI = None
 for iIiiiIiIi in lisp_multi_tenant_interfaces :
  if ( iIiiiIiIi . device != device ) : continue
  ii1II1 = iIiiiIiIi . multi_tenant_eid
  source_eid . instance_id = ii1II1 . instance_id
  if ( source_eid . is_more_specific ( ii1II1 ) == False ) : continue
  if ( IiIIiI == None or IiIIiI . multi_tenant_eid . mask_len < ii1II1 . mask_len ) :
   IiIIiI = iIiiiIiIi
   if 31 - 31: iIii1I11I1II1 * OOooOOo % o0oOOo0O0Ooo + I1Ii111 . i11iIiiIii
   if 69 - 69: i1IIi
 source_eid . instance_id = oOOoOOO0
 if 32 - 32: i11iIiiIii * I1IiiI * OOooOOo . I1ii11iIi11i % o0oOOo0O0Ooo % i11iIiiIii
 if ( IiIIiI == None ) : return ( IIiI1i )
 return ( IiIIiI . get_instance_id ( ) )
 if 17 - 17: i11iIiiIii % OoooooooOO + I1IiiI
 if 27 - 27: I1ii11iIi11i . OOooOOo + I11i
 if 66 - 66: O0 . OoooooooOO . I1Ii111 . I11i - o0oOOo0O0Ooo
 if 53 - 53: oO0o . I1Ii111 + OoOoOO00 - iIii1I11I1II1 % IiII
 if 88 - 88: o0oOOo0O0Ooo * II111iiii % Oo0Ooo * I1ii11iIi11i . I1IiiI % I1ii11iIi11i
 if 37 - 37: OOooOOo % OoO0O00 % oO0o . I11i / OOooOOo
 if 8 - 8: iIii1I11I1II1 + O0 + IiII - IiII * I1Ii111 / i1IIi
 if 10 - 10: Oo0Ooo . i11iIiiIii + iIii1I11I1II1 % iII111i + i11iIiiIii
 if 6 - 6: OoOoOO00 + OOooOOo + Oo0Ooo
def lisp_allow_dynamic_eid ( device , eid ) :
 if ( lisp_myinterfaces . has_key ( device ) == False ) : return ( None )
 if 43 - 43: IiII * iII111i . ooOoO0o / I1ii11iIi11i . ooOoO0o * II111iiii
 iIiiiIiIi = lisp_myinterfaces [ device ]
 iIiI1I11Ii1 = device if iIiiiIiIi . dynamic_eid_device == None else iIiiiIiIi . dynamic_eid_device
 if 95 - 95: iII111i % OoooooooOO - II111iiii
 if 75 - 75: oO0o / OOooOOo + iIii1I11I1II1 + i1IIi * I1Ii111
 if ( iIiiiIiIi . does_dynamic_eid_match ( eid ) ) : return ( iIiI1I11Ii1 )
 return ( None )
 if 36 - 36: II111iiii / OoooooooOO % o0oOOo0O0Ooo * O0
 if 49 - 49: I11i / OoO0O00 % IiII
 if 62 - 62: oO0o % oO0o / o0oOOo0O0Ooo + I1IiiI + OOooOOo
 if 45 - 45: O0 . OoO0O00 % OOooOOo + iIii1I11I1II1 * iII111i % OoO0O00
 if 62 - 62: I1Ii111 - ooOoO0o + iIii1I11I1II1 % OOooOOo + Oo0Ooo
 if 59 - 59: I1IiiI * II111iiii . i1IIi - i1IIi
 if 23 - 23: oO0o * OoO0O00 % O0 . OoOoOO00 * Oo0Ooo
def lisp_start_rloc_probe_timer ( interval , lisp_sockets ) :
 global lisp_rloc_probe_timer
 if 69 - 69: OoOoOO00 % I1ii11iIi11i % II111iiii * oO0o
 if ( lisp_rloc_probe_timer != None ) : lisp_rloc_probe_timer . cancel ( )
 if 100 - 100: i11iIiiIii . IiII - I1IiiI + I1Ii111
 II1IiI1iIII1i1iI = lisp_process_rloc_probe_timer
 Iii111iII1II = threading . Timer ( interval , II1IiI1iIII1i1iI , [ lisp_sockets ] )
 lisp_rloc_probe_timer = Iii111iII1II
 Iii111iII1II . start ( )
 return
 if 28 - 28: i1IIi * O0 - O0 + II111iiii * I1ii11iIi11i
 if 64 - 64: OoooooooOO + ooOoO0o + o0oOOo0O0Ooo % i11iIiiIii
 if 32 - 32: O0 + IiII
 if 93 - 93: OoOoOO00 - I11i / iII111i - iIii1I11I1II1 + I11i % oO0o
 if 24 - 24: Ii1I / iIii1I11I1II1 + o0oOOo0O0Ooo
 if 17 - 17: OOooOOo
 if 75 - 75: Ii1I / i1IIi % I1ii11iIi11i . Ii1I
def lisp_show_rloc_probe_list ( ) :
 lprint ( bold ( "----- RLOC-probe-list -----" , False ) )
 for iIIIi in lisp_rloc_probe_list :
  iiI1i111111II = lisp_rloc_probe_list [ iIIIi ]
  lprint ( "RLOC {}:" . format ( iIIIi ) )
  for iI111I1 , I1i11II , OooooOOOO in iiI1i111111II :
   lprint ( "  [{}, {}, {}, {}]" . format ( hex ( id ( iI111I1 ) ) , I1i11II . print_prefix ( ) ,
 OooooOOOO . print_prefix ( ) , iI111I1 . translated_port ) )
   if 94 - 94: o0oOOo0O0Ooo . iIii1I11I1II1
   if 47 - 47: Ii1I % II111iiii
 lprint ( bold ( "---------------------------" , False ) )
 return
 if 88 - 88: OoOoOO00 / oO0o - OoOoOO00 / OoOoOO00 % II111iiii
 if 47 - 47: i11iIiiIii . iII111i + o0oOOo0O0Ooo % iII111i
 if 93 - 93: OoO0O00 / i11iIiiIii / oO0o - o0oOOo0O0Ooo
 if 56 - 56: I11i + oO0o . i1IIi - II111iiii - o0oOOo0O0Ooo + OOooOOo
 if 24 - 24: ooOoO0o
 if 7 - 7: ooOoO0o . OoooooooOO . iII111i * II111iiii . II111iiii / OOooOOo
 if 46 - 46: Ii1I - Oo0Ooo / i1IIi % IiII - I1ii11iIi11i + OOooOOo
 if 42 - 42: i1IIi - IiII % OOooOOo % iIii1I11I1II1
 if 71 - 71: OoO0O00
def lisp_mark_rlocs_for_other_eids ( eid_list ) :
 if 72 - 72: II111iiii + o0oOOo0O0Ooo / i1IIi * Oo0Ooo / i1IIi
 if 52 - 52: I1Ii111 % OoO0O00 . I1Ii111 * I1ii11iIi11i * OoOoOO00 + i1IIi
 if 54 - 54: Ii1I / I1IiiI
 if 7 - 7: iIii1I11I1II1 . O0 + OOooOOo . Ii1I * Oo0Ooo
 oOoOoo0O , I1i11II , OooooOOOO = eid_list [ 0 ]
 I11iI1ii = [ lisp_print_eid_tuple ( I1i11II , OooooOOOO ) ]
 if 19 - 19: OOooOOo - OOooOOo / iIii1I11I1II1 / I1ii11iIi11i - I1ii11iIi11i / iIii1I11I1II1
 for oOoOoo0O , I1i11II , OooooOOOO in eid_list [ 1 : : ] :
  oOoOoo0O . state = LISP_RLOC_UNREACH_STATE
  oOoOoo0O . last_state_change = lisp_get_timestamp ( )
  I11iI1ii . append ( lisp_print_eid_tuple ( I1i11II , OooooOOOO ) )
  if 42 - 42: iIii1I11I1II1 / OOooOOo - O0 * OoooooooOO / i1IIi
  if 33 - 33: OOooOOo . o0oOOo0O0Ooo % OoO0O00 - I1Ii111 . OoooooooOO
 Ooo0O0oOooo = bold ( "unreachable" , False )
 Oo0oO = red ( oOoOoo0O . rloc . print_address_no_iid ( ) , False )
 if 89 - 89: OOooOOo . IiII - OoooooooOO + II111iiii
 for Ooo0 in I11iI1ii :
  I1i11II = green ( Ooo0 , False )
  lprint ( "RLOC {} went {} for EID {}" . format ( Oo0oO , Ooo0O0oOooo , I1i11II ) )
  if 35 - 35: i1IIi % I1IiiI . Ii1I - i11iIiiIii / oO0o
  if 98 - 98: OoOoOO00 . oO0o + I1ii11iIi11i
  if 14 - 14: OoooooooOO
  if 73 - 73: OoOoOO00 % o0oOOo0O0Ooo
  if 28 - 28: OoO0O00
  if 15 - 15: OoO0O00 . I11i
 for oOoOoo0O , I1i11II , OooooOOOO in eid_list :
  oOooO0Oo0Oo0 = lisp_map_cache . lookup_cache ( I1i11II , True )
  if ( oOooO0Oo0Oo0 ) : lisp_write_ipc_map_cache ( True , oOooO0Oo0Oo0 )
  if 64 - 64: OOooOOo + I1Ii111 - o0oOOo0O0Ooo . II111iiii * Ii1I
 return
 if 88 - 88: I1ii11iIi11i + OoooooooOO % I1ii11iIi11i
 if 3 - 3: I1Ii111 . O0 * OOooOOo * I11i + Ii1I * I1IiiI
 if 18 - 18: iIii1I11I1II1 % ooOoO0o . o0oOOo0O0Ooo * iII111i % iII111i
 if 64 - 64: I1Ii111 . I11i
 if 32 - 32: I1ii11iIi11i + IiII % OoOoOO00 . O0
 if 70 - 70: IiII + iII111i . i11iIiiIii + OoO0O00
 if 45 - 45: o0oOOo0O0Ooo - ooOoO0o
 if 2 - 2: OOooOOo + iII111i * ooOoO0o + II111iiii
 if 88 - 88: ooOoO0o * OoO0O00 * I1ii11iIi11i - I1IiiI * IiII * I11i
 if 37 - 37: iIii1I11I1II1
def lisp_process_rloc_probe_timer ( lisp_sockets ) :
 lisp_set_exception ( )
 if 50 - 50: o0oOOo0O0Ooo - OOooOOo * IiII % Oo0Ooo
 lisp_start_rloc_probe_timer ( LISP_RLOC_PROBE_INTERVAL , lisp_sockets )
 if ( lisp_rloc_probing == False ) : return
 if 81 - 81: OoooooooOO - OoOoOO00 % I1ii11iIi11i % I1ii11iIi11i + OoOoOO00
 if 49 - 49: Ii1I + iIii1I11I1II1 . O0 * OOooOOo * OoooooooOO - OOooOOo
 if 23 - 23: iIii1I11I1II1 % I11i . OoO0O00 / i11iIiiIii % O0 * Ii1I
 if 49 - 49: I1ii11iIi11i . i1IIi + OoO0O00 % O0 + OoO0O00
 if ( lisp_print_rloc_probe_list ) : lisp_show_rloc_probe_list ( )
 if 21 - 21: ooOoO0o * oO0o / OoooooooOO % ooOoO0o / O0
 if 24 - 24: OoO0O00 - i11iIiiIii / i11iIiiIii * I1Ii111
 if 20 - 20: IiII % iIii1I11I1II1 . iII111i + iIii1I11I1II1 + O0
 if 96 - 96: I1ii11iIi11i - IiII % OoooooooOO . iII111i
 IIiIII1 = lisp_get_default_route_next_hops ( )
 if 73 - 73: o0oOOo0O0Ooo / iIii1I11I1II1 - o0oOOo0O0Ooo / iII111i
 lprint ( "---------- Start RLOC Probing for {} entries ----------" . format ( len ( lisp_rloc_probe_list ) ) )
 if 71 - 71: Oo0Ooo + iII111i / iII111i - IiII + ooOoO0o . OoooooooOO
 if 66 - 66: OoOoOO00 - Oo0Ooo - i1IIi
 if 12 - 12: oO0o % IiII / I1ii11iIi11i . OoO0O00 * iII111i . iIii1I11I1II1
 if 5 - 5: Oo0Ooo * OoooooooOO / ooOoO0o . IiII + I1IiiI
 if 81 - 81: I1IiiI / oO0o . iIii1I11I1II1 - IiII / I1IiiI
 Ooo00OOOOOO0 = 0
 o0ooOOoO0O = bold ( "RLOC-probe" , False )
 for III1iii1i in lisp_rloc_probe_list . values ( ) :
  if 90 - 90: oO0o * iII111i
  if 19 - 19: OOooOOo % OoO0O00 + i11iIiiIii % iIii1I11I1II1 + I1Ii111
  if 41 - 41: Oo0Ooo * I1IiiI . I1Ii111
  if 24 - 24: iII111i - O0 - ooOoO0o
  if 68 - 68: Oo0Ooo
  i1I1IiIi11 = None
  for O0OoO0Oo0oO0o , Ooo0 , ooOoO00 in III1iii1i :
   OoOOoooO000 = O0OoO0Oo0oO0o . rloc . print_address_no_iid ( )
   if 68 - 68: o0oOOo0O0Ooo + IiII / iII111i - i11iIiiIii / OOooOOo
   if 62 - 62: I1IiiI
   if 42 - 42: II111iiii
   if 49 - 49: OoooooooOO
   if 48 - 48: i1IIi . IiII - O0 + OoooooooOO
   if 6 - 6: I1Ii111 * OOooOOo + o0oOOo0O0Ooo . I1ii11iIi11i * I1Ii111
   if ( O0OoO0Oo0oO0o . down_state ( ) ) : continue
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
   if 20 - 20: i1IIi * I11i / OoO0O00 / i1IIi / I1Ii111 * O0
   if ( i1I1IiIi11 ) :
    O0OoO0Oo0oO0o . last_rloc_probe_nonce = i1I1IiIi11 . last_rloc_probe_nonce
    if 95 - 95: Ii1I + Ii1I % IiII - IiII / OOooOOo
    if ( i1I1IiIi11 . translated_port == O0OoO0Oo0oO0o . translated_port and i1I1IiIi11 . rloc_name == O0OoO0Oo0oO0o . rloc_name ) :
     if 46 - 46: IiII + iII111i + II111iiii . iII111i - i11iIiiIii % OoO0O00
     I1i11II = green ( lisp_print_eid_tuple ( Ooo0 , ooOoO00 ) , False )
     lprint ( "Suppress probe to duplicate RLOC {} for {}" . format ( red ( OoOOoooO000 , False ) , I1i11II ) )
     if 24 - 24: oO0o + IiII . o0oOOo0O0Ooo . OoooooooOO . i11iIiiIii / I1ii11iIi11i
     continue
     if 49 - 49: IiII
     if 1 - 1: oO0o / I11i
     if 99 - 99: OoO0O00 % IiII + I1Ii111 - oO0o
   IiIIiI11I = None
   oOoOoo0O = None
   while ( True ) :
    oOoOoo0O = O0OoO0Oo0oO0o if oOoOoo0O == None else oOoOoo0O . next_rloc
    if ( oOoOoo0O == None ) : break
    if 28 - 28: OOooOOo - O0 - O0 % i11iIiiIii * OoooooooOO
    if 60 - 60: OoooooooOO / i1IIi / i1IIi / Ii1I . IiII
    if 24 - 24: O0
    if 6 - 6: I1IiiI . i11iIiiIii . OoooooooOO . I1IiiI . o0oOOo0O0Ooo
    if 65 - 65: i11iIiiIii
    if ( oOoOoo0O . rloc_next_hop != None ) :
     if ( oOoOoo0O . rloc_next_hop not in IIiIII1 ) :
      if ( oOoOoo0O . up_state ( ) ) :
       i1i11ii1Ii , oOoOoOo0O = oOoOoo0O . rloc_next_hop
       oOoOoo0O . state = LISP_RLOC_UNREACH_STATE
       oOoOoo0O . last_state_change = lisp_get_timestamp ( )
       lisp_update_rtr_updown ( oOoOoo0O . rloc , False )
       if 46 - 46: i11iIiiIii
      Ooo0O0oOooo = bold ( "unreachable" , False )
      lprint ( "Next-hop {}({}) for RLOC {} is {}" . format ( oOoOoOo0O , i1i11ii1Ii ,
 red ( OoOOoooO000 , False ) , Ooo0O0oOooo ) )
      continue
      if 70 - 70: i1IIi + o0oOOo0O0Ooo
      if 44 - 44: iII111i . II111iiii % o0oOOo0O0Ooo
      if 29 - 29: i11iIiiIii * i1IIi
      if 36 - 36: OoO0O00 * I11i . ooOoO0o
      if 50 - 50: oO0o * OoOoOO00 / OoO0O00 / ooOoO0o + II111iiii
      if 55 - 55: II111iiii - IiII
    i11iI11ii = oOoOoo0O . last_rloc_probe
    iIi1i1iiIII = 0 if i11iI11ii == None else time . time ( ) - i11iI11ii
    if ( oOoOoo0O . unreach_state ( ) and iIi1i1iiIII < LISP_RLOC_PROBE_INTERVAL ) :
     lprint ( "Waiting for probe-reply from RLOC {}" . format ( red ( OoOOoooO000 , False ) ) )
     if 17 - 17: Ii1I / OoOoOO00 % I1ii11iIi11i - IiII
     continue
     if 76 - 76: Ii1I / o0oOOo0O0Ooo % IiII % Oo0Ooo
     if 68 - 68: o0oOOo0O0Ooo / O0 + i11iIiiIii % II111iiii
     if 10 - 10: iII111i - Oo0Ooo
     if 10 - 10: IiII + I1Ii111 / OoooooooOO % I1Ii111 * i11iIiiIii - oO0o
     if 73 - 73: IiII - II111iiii - OOooOOo % II111iiii + iIii1I11I1II1
     if 81 - 81: i11iIiiIii - O0 + I1IiiI
    i1II11iI1i = lisp_get_echo_nonce ( None , OoOOoooO000 )
    if ( i1II11iI1i and i1II11iI1i . request_nonce_timeout ( ) ) :
     oOoOoo0O . state = LISP_RLOC_NO_ECHOED_NONCE_STATE
     oOoOoo0O . last_state_change = lisp_get_timestamp ( )
     Ooo0O0oOooo = bold ( "unreachable" , False )
     lprint ( "RLOC {} went {}, nonce-echo failed" . format ( red ( OoOOoooO000 , False ) , Ooo0O0oOooo ) )
     if 39 - 39: IiII * OOooOOo . OoooooooOO + Oo0Ooo + iIii1I11I1II1
     lisp_update_rtr_updown ( oOoOoo0O . rloc , False )
     continue
     if 67 - 67: iII111i . OOooOOo / ooOoO0o * iIii1I11I1II1
     if 29 - 29: I1Ii111 / OoOoOO00 % I1ii11iIi11i * IiII / II111iiii
     if 10 - 10: O0 / I11i
     if 29 - 29: i11iIiiIii % I11i
     if 49 - 49: I11i
     if 69 - 69: o0oOOo0O0Ooo . O0 * I11i
    if ( i1II11iI1i and i1II11iI1i . recently_echoed ( ) ) :
     lprint ( ( "Suppress RLOC-probe to {}, nonce-echo " + "received" ) . format ( red ( OoOOoooO000 , False ) ) )
     if 92 - 92: OoO0O00 . O0 / Ii1I % Oo0Ooo . Ii1I
     continue
     if 40 - 40: o0oOOo0O0Ooo - Ii1I . iII111i - O0
     if 53 - 53: Oo0Ooo - I1IiiI * O0 . II111iiii
     if 72 - 72: ooOoO0o - Ii1I . Ii1I . I11i / OoooooooOO + Ii1I
     if 32 - 32: O0
     if 42 - 42: i1IIi * I1ii11iIi11i * OoOoOO00
     if 43 - 43: I1ii11iIi11i % I1ii11iIi11i % i1IIi
    if ( oOoOoo0O . last_rloc_probe != None ) :
     i11iI11ii = oOoOoo0O . last_rloc_probe_reply
     if ( i11iI11ii == None ) : i11iI11ii = 0
     iIi1i1iiIII = time . time ( ) - i11iI11ii
     if ( oOoOoo0O . up_state ( ) and iIi1i1iiIII >= LISP_RLOC_PROBE_REPLY_WAIT ) :
      if 56 - 56: I1IiiI - OoO0O00 - iII111i . o0oOOo0O0Ooo . I1Ii111
      oOoOoo0O . state = LISP_RLOC_UNREACH_STATE
      oOoOoo0O . last_state_change = lisp_get_timestamp ( )
      lisp_update_rtr_updown ( oOoOoo0O . rloc , False )
      Ooo0O0oOooo = bold ( "unreachable" , False )
      lprint ( "RLOC {} went {}, probe it" . format ( red ( OoOOoooO000 , False ) , Ooo0O0oOooo ) )
      if 70 - 70: iIii1I11I1II1 - I11i
      if 2 - 2: oO0o / II111iiii * OoO0O00
      lisp_mark_rlocs_for_other_eids ( III1iii1i )
      if 71 - 71: i1IIi + I11i * OoO0O00 . OOooOOo + oO0o
      if 40 - 40: OOooOOo
      if 14 - 14: OoooooooOO - OoooooooOO % i11iIiiIii % ooOoO0o / ooOoO0o
    oOoOoo0O . last_rloc_probe = lisp_get_timestamp ( )
    if 33 - 33: iII111i / i1IIi . II111iiii % I1ii11iIi11i
    O0o0 = "" if oOoOoo0O . unreach_state ( ) == False else " unreachable"
    if 27 - 27: Oo0Ooo
    if 15 - 15: Ii1I / OOooOOo % i1IIi . I1Ii111 / O0 + I1Ii111
    if 39 - 39: I1ii11iIi11i * I1IiiI * II111iiii . Oo0Ooo % I1IiiI
    if 100 - 100: iIii1I11I1II1 - OoooooooOO * OoooooooOO - iII111i / ooOoO0o
    if 98 - 98: OoO0O00 + oO0o - II111iiii
    if 84 - 84: Oo0Ooo . OoOoOO00 - iII111i
    if 5 - 5: OoooooooOO . O0 / OOooOOo + I11i - Ii1I
    OooOo0OOo00O0 = ""
    oOoOoOo0O = None
    if ( oOoOoo0O . rloc_next_hop != None ) :
     i1i11ii1Ii , oOoOoOo0O = oOoOoo0O . rloc_next_hop
     lisp_install_host_route ( OoOOoooO000 , oOoOoOo0O , True )
     OooOo0OOo00O0 = ", send on nh {}({})" . format ( oOoOoOo0O , i1i11ii1Ii )
     if 57 - 57: OoooooooOO * oO0o % OoooooooOO - O0
     if 18 - 18: Ii1I
     if 82 - 82: OoOoOO00 + OoO0O00 - IiII / ooOoO0o
     if 70 - 70: OoO0O00
     if 43 - 43: ooOoO0o + OOooOOo + II111iiii - I1IiiI
    i1I1Ii = oOoOoo0O . print_rloc_probe_rtt ( )
    o0oOO0O00O = OoOOoooO000
    if ( oOoOoo0O . translated_port != 0 ) :
     o0oOO0O00O += ":{}" . format ( oOoOoo0O . translated_port )
     if 56 - 56: ooOoO0o - O0 + iII111i % I11i / i1IIi
    o0oOO0O00O = red ( o0oOO0O00O , False )
    if ( oOoOoo0O . rloc_name != None ) :
     o0oOO0O00O += " (" + blue ( oOoOoo0O . rloc_name , False ) + ")"
     if 78 - 78: i1IIi . iIii1I11I1II1
    lprint ( "Send {}{} {}, last rtt: {}{}" . format ( o0ooOOoO0O , O0o0 ,
 o0oOO0O00O , i1I1Ii , OooOo0OOo00O0 ) )
    if 70 - 70: O0 + II111iiii % IiII / I1Ii111 - IiII
    if 58 - 58: II111iiii * oO0o - i1IIi . I11i
    if 23 - 23: OoO0O00 - I1IiiI * i11iIiiIii
    if 62 - 62: OoO0O00 . i11iIiiIii / i1IIi
    if 3 - 3: OoO0O00 + O0 % Oo0Ooo * Oo0Ooo % i11iIiiIii
    if 29 - 29: ooOoO0o / iII111i / OOooOOo - iIii1I11I1II1
    if 31 - 31: i1IIi * Ii1I
    if 94 - 94: oO0o / Ii1I % iIii1I11I1II1 + i1IIi / O0 - iII111i
    if ( oOoOoo0O . rloc_next_hop != None ) :
     IiIIiI11I = lisp_get_host_route_next_hop ( OoOOoooO000 )
     if ( IiIIiI11I ) : lisp_install_host_route ( OoOOoooO000 , IiIIiI11I , False )
     if 77 - 77: o0oOOo0O0Ooo - IiII . i1IIi
     if 70 - 70: i1IIi . I1Ii111 . iII111i - OoOoOO00 + II111iiii + OOooOOo
     if 52 - 52: OOooOOo . OoOoOO00 - ooOoO0o % i1IIi
     if 15 - 15: oO0o
     if 6 - 6: oO0o . iIii1I11I1II1 - I1ii11iIi11i % IiII
     if 58 - 58: iII111i * oO0o / iII111i - Oo0Ooo / I1Ii111 * oO0o
    if ( oOoOoo0O . rloc . is_null ( ) ) :
     oOoOoo0O . rloc . copy_address ( O0OoO0Oo0oO0o . rloc )
     if 63 - 63: oO0o . IiII . o0oOOo0O0Ooo
     if 16 - 16: iII111i . I11i - Oo0Ooo / I1IiiI + OoOoOO00
     if 14 - 14: iIii1I11I1II1 / i11iIiiIii - o0oOOo0O0Ooo . iII111i * OoO0O00
     if 5 - 5: Ii1I + OoOoOO00 % I11i + IiII
     if 55 - 55: OoooooooOO + oO0o . o0oOOo0O0Ooo % iIii1I11I1II1 - I1Ii111
    IIII = None if ( ooOoO00 . is_null ( ) ) else Ooo0
    iIIoO000O0 = Ooo0 if ( ooOoO00 . is_null ( ) ) else ooOoO00
    lisp_send_map_request ( lisp_sockets , 0 , IIII , iIIoO000O0 , oOoOoo0O )
    i1I1IiIi11 = O0OoO0Oo0oO0o
    if 64 - 64: I11i . I1Ii111 % i11iIiiIii
    if 22 - 22: I11i
    if 30 - 30: i1IIi
    if 56 - 56: Oo0Ooo
    if ( oOoOoOo0O ) : lisp_install_host_route ( OoOOoooO000 , oOoOoOo0O , False )
    if 21 - 21: i11iIiiIii * o0oOOo0O0Ooo + Oo0Ooo
    if 20 - 20: IiII / OoooooooOO / O0 / I1Ii111 * ooOoO0o
    if 45 - 45: ooOoO0o / Oo0Ooo % o0oOOo0O0Ooo . ooOoO0o
    if 19 - 19: o0oOOo0O0Ooo % I11i . I1ii11iIi11i
    if 70 - 70: Oo0Ooo - I11i / I1ii11iIi11i % OoO0O00 % II111iiii
   if ( IiIIiI11I ) : lisp_install_host_route ( OoOOoooO000 , IiIIiI11I , True )
   if 72 - 72: i11iIiiIii * I11i
   if 69 - 69: I1Ii111 . Ii1I * I1ii11iIi11i % I11i - o0oOOo0O0Ooo
   if 30 - 30: ooOoO0o / Oo0Ooo * iII111i % OoooooooOO / I1ii11iIi11i
   if 64 - 64: OoooooooOO
   Ooo00OOOOOO0 += 1
   if ( ( Ooo00OOOOOO0 % 10 ) == 0 ) : time . sleep ( 0.020 )
   if 41 - 41: Ii1I . I11i / oO0o * OoooooooOO
   if 98 - 98: I1ii11iIi11i - O0 + i11iIiiIii
   if 71 - 71: O0 - OoooooooOO
 lprint ( "---------- End RLOC Probing ----------" )
 return
 if 82 - 82: i11iIiiIii * II111iiii % IiII
 if 80 - 80: Ii1I . i11iIiiIii % oO0o * o0oOOo0O0Ooo
 if 56 - 56: I1Ii111 % iII111i / II111iiii - Oo0Ooo - Oo0Ooo - iIii1I11I1II1
 if 67 - 67: iII111i
 if 80 - 80: Ii1I . iII111i * I1IiiI * Ii1I
 if 82 - 82: OoO0O00 % OoOoOO00 * i11iIiiIii . OoO0O00 . I1ii11iIi11i + Ii1I
 if 60 - 60: i1IIi / iII111i
 if 10 - 10: I1Ii111 / OoOoOO00 * Ii1I % o0oOOo0O0Ooo . OoOoOO00 / I1ii11iIi11i
def lisp_update_rtr_updown ( rtr , updown ) :
 global lisp_ipc_socket
 if 2 - 2: iIii1I11I1II1
 if 85 - 85: O0 - ooOoO0o
 if 35 - 35: o0oOOo0O0Ooo - I1IiiI
 if 47 - 47: i11iIiiIii * iII111i . OoOoOO00 * I1Ii111 % i11iIiiIii + Ii1I
 if ( lisp_i_am_itr == False ) : return
 if 65 - 65: Ii1I % i11iIiiIii
 if 98 - 98: iII111i * o0oOOo0O0Ooo % Oo0Ooo
 if 7 - 7: oO0o * OoooooooOO % o0oOOo0O0Ooo . I1Ii111 + O0
 if 14 - 14: I11i * II111iiii % o0oOOo0O0Ooo / iII111i . OoooooooOO % iII111i
 if 88 - 88: iII111i
 if ( lisp_register_all_rtrs ) : return
 if 94 - 94: OoooooooOO
 iiI11Ii1I = rtr . print_address_no_iid ( )
 if 71 - 71: ooOoO0o
 if 19 - 19: i11iIiiIii * I1Ii111
 if 82 - 82: OOooOOo . iII111i
 if 65 - 65: oO0o
 if 18 - 18: i1IIi % I11i * OoOoOO00 - I11i + OoO0O00 - O0
 if ( lisp_rtr_list . has_key ( iiI11Ii1I ) == False ) : return
 if 36 - 36: iIii1I11I1II1 * iII111i / IiII % i1IIi
 updown = "up" if updown else "down"
 lprint ( "Send ETR IPC message, RTR {} has done {}" . format (
 red ( iiI11Ii1I , False ) , bold ( updown , False ) ) )
 if 8 - 8: I11i
 if 33 - 33: I1Ii111 . I11i . Ii1I - iIii1I11I1II1
 if 96 - 96: II111iiii % oO0o . i1IIi + II111iiii . iII111i
 if 67 - 67: i1IIi - i11iIiiIii / ooOoO0o * oO0o
 OOOO0OoO0oOOoo0 = "rtr%{}%{}" . format ( iiI11Ii1I , updown )
 OOOO0OoO0oOOoo0 = lisp_command_ipc ( OOOO0OoO0oOOoo0 , "lisp-itr" )
 lisp_ipc ( OOOO0OoO0oOOoo0 , lisp_ipc_socket , "lisp-etr" )
 return
 if 64 - 64: oO0o / IiII
 if 86 - 86: I11i
 if 36 - 36: o0oOOo0O0Ooo / OoO0O00
 if 6 - 6: I11i % I1IiiI + iII111i * OoooooooOO . O0
 if 87 - 87: ooOoO0o / Ii1I % O0 . OoO0O00
 if 55 - 55: i1IIi . o0oOOo0O0Ooo % OoooooooOO + II111iiii . OoOoOO00
 if 32 - 32: IiII * I1Ii111 * Oo0Ooo . i1IIi * OoooooooOO
def lisp_process_rloc_probe_reply ( rloc_addr , source , port , nonce , hop_count ,
 ttl ) :
 o0ooOOoO0O = bold ( "RLOC-probe reply" , False )
 iiO0ooOO = rloc_addr . print_address_no_iid ( )
 Oo00oO0oo = source . print_address_no_iid ( )
 iII1I = lisp_rloc_probe_list
 if 93 - 93: OoOoOO00 + Ii1I % OOooOOo / I11i
 if 26 - 26: OoO0O00 - I1IiiI
 if 87 - 87: oO0o % OOooOOo / Oo0Ooo - OoO0O00
 if 8 - 8: o0oOOo0O0Ooo . IiII * OoO0O00 * Ii1I - i11iIiiIii - OoO0O00
 if 56 - 56: i11iIiiIii
 if 19 - 19: OoOoOO00 + I1IiiI * iIii1I11I1II1
 I1Iii1I = iiO0ooOO
 if ( iII1I . has_key ( I1Iii1I ) == False ) :
  I1Iii1I += ":" + str ( port )
  if ( iII1I . has_key ( I1Iii1I ) == False ) :
   I1Iii1I = Oo00oO0oo
   if ( iII1I . has_key ( I1Iii1I ) == False ) :
    I1Iii1I += ":" + str ( port )
    lprint ( "    Received unsolicited {} from {}/{}" . format ( o0ooOOoO0O ,
 red ( iiO0ooOO , False ) , red ( Oo00oO0oo , False ) ) )
    return
    if 88 - 88: I1Ii111 - oO0o
    if 74 - 74: I1Ii111 % i11iIiiIii
    if 44 - 44: ooOoO0o + o0oOOo0O0Ooo
    if 10 - 10: i1IIi + o0oOOo0O0Ooo
    if 47 - 47: OOooOOo * IiII % I1Ii111 . OoOoOO00 - OoooooooOO / OoooooooOO
    if 79 - 79: I11i % i11iIiiIii % I1IiiI . OoooooooOO * oO0o . Ii1I
    if 14 - 14: iIii1I11I1II1 / I11i - o0oOOo0O0Ooo / IiII / o0oOOo0O0Ooo . OoO0O00
    if 2 - 2: I11i
 for oOoOoo0O , Ooo0 , ooOoO00 in lisp_rloc_probe_list [ I1Iii1I ] :
  if ( lisp_i_am_rtr and oOoOoo0O . translated_port != 0 and
 oOoOoo0O . translated_port != port ) : continue
  if 12 - 12: i1IIi . I1Ii111
  oOoOoo0O . process_rloc_probe_reply ( nonce , Ooo0 , ooOoO00 , hop_count , ttl )
  if 99 - 99: Oo0Ooo / i11iIiiIii
 return
 if 81 - 81: Ii1I . i1IIi % iII111i . OoO0O00 % IiII
 if 42 - 42: iII111i / Oo0Ooo
 if 14 - 14: O0 . Oo0Ooo
 if 8 - 8: i11iIiiIii
 if 80 - 80: I1ii11iIi11i + Ii1I
 if 16 - 16: i11iIiiIii * Oo0Ooo
 if 76 - 76: iII111i . oO0o - i1IIi
 if 94 - 94: O0 % iII111i
def lisp_db_list_length ( ) :
 Ooo00OOOOOO0 = 0
 for i1iOo in lisp_db_list :
  Ooo00OOOOOO0 += len ( i1iOo . dynamic_eids ) if i1iOo . dynamic_eid_configured ( ) else 1
  Ooo00OOOOOO0 += len ( i1iOo . eid . iid_list )
  if 90 - 90: IiII
 return ( Ooo00OOOOOO0 )
 if 1 - 1: I1ii11iIi11i % OoOoOO00 . I1ii11iIi11i . OoooooooOO % oO0o + Ii1I
 if 46 - 46: I1IiiI + OoO0O00 - Oo0Ooo
 if 13 - 13: OoOoOO00
 if 72 - 72: II111iiii * iII111i . II111iiii + iII111i * IiII
 if 90 - 90: oO0o * I1Ii111 / O0
 if 15 - 15: o0oOOo0O0Ooo * O0 . OOooOOo / Oo0Ooo
 if 28 - 28: OoooooooOO + OoooooooOO
def lisp_is_myeid ( eid ) :
 for i1iOo in lisp_db_list :
  if ( i1iOo . eid . is_exact_match ( eid ) ) : return ( True )
  if 27 - 27: I11i . oO0o / OoooooooOO - OoO0O00 . I11i
 return ( False )
 if 15 - 15: II111iiii * OoO0O00
 if 33 - 33: OoooooooOO . o0oOOo0O0Ooo . I1IiiI / I1ii11iIi11i . OoOoOO00
 if 58 - 58: Ii1I
 if 20 - 20: OOooOOo
 if 93 - 93: i1IIi . IiII % O0 * iII111i
 if 84 - 84: I11i
 if 99 - 99: I1ii11iIi11i
 if 78 - 78: I1Ii111 . IiII - OOooOOo
 if 93 - 93: iIii1I11I1II1
def lisp_format_macs ( sa , da ) :
 sa = sa [ 0 : 4 ] + "-" + sa [ 4 : 8 ] + "-" + sa [ 8 : 12 ]
 da = da [ 0 : 4 ] + "-" + da [ 4 : 8 ] + "-" + da [ 8 : 12 ]
 return ( "{} -> {}" . format ( sa , da ) )
 if 33 - 33: OOooOOo . i1IIi
 if 63 - 63: II111iiii . oO0o * IiII
 if 73 - 73: iII111i . i1IIi + oO0o + OOooOOo + ooOoO0o - iIii1I11I1II1
 if 47 - 47: I11i
 if 88 - 88: OoO0O00 - OoooooooOO
 if 93 - 93: Oo0Ooo * I1IiiI
 if 60 - 60: I1Ii111 + OOooOOo % iII111i
def lisp_get_echo_nonce ( rloc , rloc_str ) :
 if ( lisp_nonce_echoing == False ) : return ( None )
 if 40 - 40: I11i + oO0o . O0 % oO0o
 if ( rloc ) : rloc_str = rloc . print_address_no_iid ( )
 i1II11iI1i = None
 if ( lisp_nonce_echo_list . has_key ( rloc_str ) ) :
  i1II11iI1i = lisp_nonce_echo_list [ rloc_str ]
  if 12 - 12: iIii1I11I1II1
 return ( i1II11iI1i )
 if 9 - 9: OoOoOO00 * II111iiii / o0oOOo0O0Ooo * iII111i - II111iiii / i11iIiiIii
 if 14 - 14: i11iIiiIii + I1Ii111 . OoOoOO00 - oO0o * OoO0O00
 if 23 - 23: iIii1I11I1II1
 if 32 - 32: iII111i * iIii1I11I1II1 + I1Ii111 + IiII + O0 * OoO0O00
 if 100 - 100: II111iiii
 if 34 - 34: I11i % OOooOOo - iII111i % II111iiii
 if 14 - 14: I11i * o0oOOo0O0Ooo % II111iiii
 if 36 - 36: ooOoO0o - iIii1I11I1II1 / IiII + OoOoOO00
def lisp_decode_dist_name ( packet ) :
 Ooo00OOOOOO0 = 0
 I11Ii1i = ""
 if 47 - 47: OoooooooOO / Oo0Ooo . iIii1I11I1II1 - OoO0O00
 while ( packet [ 0 : 1 ] != "\0" ) :
  if ( Ooo00OOOOOO0 == 255 ) : return ( [ None , None ] )
  I11Ii1i += packet [ 0 : 1 ]
  packet = packet [ 1 : : ]
  Ooo00OOOOOO0 += 1
  if 38 - 38: II111iiii + o0oOOo0O0Ooo * I11i + I1Ii111 - II111iiii . OOooOOo
  if 38 - 38: I1ii11iIi11i % OOooOOo + iII111i / Oo0Ooo / IiII / oO0o
 packet = packet [ 1 : : ]
 return ( packet , I11Ii1i )
 if 2 - 2: iIii1I11I1II1
 if 9 - 9: I1Ii111 / IiII
 if 33 - 33: o0oOOo0O0Ooo + oO0o . o0oOOo0O0Ooo . I11i * OoooooooOO + iIii1I11I1II1
 if 64 - 64: OoooooooOO . Ii1I
 if 38 - 38: Oo0Ooo
 if 64 - 64: ooOoO0o % i11iIiiIii
 if 10 - 10: Ii1I % oO0o + oO0o * OoOoOO00 % iII111i / o0oOOo0O0Ooo
 if 17 - 17: iII111i / I1IiiI . II111iiii - OoO0O00 + iII111i
def lisp_write_flow_log ( flow_log ) :
 Ii11111i1 = open ( "./logs/lisp-flow.log" , "a" )
 if 22 - 22: Oo0Ooo - I1ii11iIi11i + I11i . oO0o
 Ooo00OOOOOO0 = 0
 for I11II in flow_log :
  I1IiO00Ooo0ooo0 = I11II [ 3 ]
  oo0O0o0oOooo0o = I1IiO00Ooo0ooo0 . print_flow ( I11II [ 0 ] , I11II [ 1 ] , I11II [ 2 ] )
  Ii11111i1 . write ( oo0O0o0oOooo0o )
  Ooo00OOOOOO0 += 1
  if 38 - 38: i1IIi - I1IiiI % I1Ii111 . I11i - iII111i / IiII
 Ii11111i1 . close ( )
 del ( flow_log )
 if 60 - 60: I11i . OoOoOO00 / OoOoOO00 * OoooooooOO * i11iIiiIii
 Ooo00OOOOOO0 = bold ( str ( Ooo00OOOOOO0 ) , False )
 lprint ( "Wrote {} flow entries to ./logs/lisp-flow.log" . format ( Ooo00OOOOOO0 ) )
 return
 if 88 - 88: ooOoO0o + ooOoO0o / I1Ii111
 if 69 - 69: O0 * o0oOOo0O0Ooo + i1IIi * ooOoO0o . o0oOOo0O0Ooo
 if 46 - 46: Oo0Ooo / Oo0Ooo * IiII
 if 65 - 65: iIii1I11I1II1 * o0oOOo0O0Ooo - iII111i % II111iiii - I1ii11iIi11i
 if 65 - 65: I11i
 if 92 - 92: iII111i . IiII + i1IIi % i1IIi
 if 11 - 11: I1ii11iIi11i + iIii1I11I1II1 - I1Ii111 * iIii1I11I1II1 * IiII + oO0o
def lisp_policy_command ( kv_pair ) :
 oo000o = lisp_policy ( "" )
 I1I1Iii1I1111 = None
 if 90 - 90: i1IIi * OoooooooOO / OOooOOo + O0
 iio0O = [ ]
 for oO in range ( len ( kv_pair [ "datetime-range" ] ) ) :
  iio0O . append ( lisp_policy_match ( ) )
  if 84 - 84: OoOoOO00 / iII111i
  if 51 - 51: i11iIiiIii % I1Ii111 / i11iIiiIii + OoOoOO00
 for i11IIIi11 in kv_pair . keys ( ) :
  oOOO = kv_pair [ i11IIIi11 ]
  if 32 - 32: i1IIi - o0oOOo0O0Ooo - I1ii11iIi11i
  if 31 - 31: OoooooooOO . oO0o . Oo0Ooo + i1IIi
  if 71 - 71: OOooOOo - I1ii11iIi11i - iIii1I11I1II1
  if 68 - 68: i1IIi . OOooOOo / IiII
  if ( i11IIIi11 == "instance-id" ) :
   for oO in range ( len ( iio0O ) ) :
    I1IIi = oOOO [ oO ]
    if ( I1IIi == "" ) : continue
    iIII1iIiI = iio0O [ oO ]
    if ( iIII1iIiI . source_eid == None ) :
     iIII1iIiI . source_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
     if 38 - 38: iIii1I11I1II1 / I1Ii111 + ooOoO0o . II111iiii - iIii1I11I1II1
    if ( iIII1iIiI . dest_eid == None ) :
     iIII1iIiI . dest_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
     if 13 - 13: Ii1I
    iIII1iIiI . source_eid . instance_id = int ( I1IIi )
    iIII1iIiI . dest_eid . instance_id = int ( I1IIi )
    if 34 - 34: I1IiiI / iIii1I11I1II1
    if 35 - 35: oO0o / oO0o
  if ( i11IIIi11 == "source-eid" ) :
   for oO in range ( len ( iio0O ) ) :
    I1IIi = oOOO [ oO ]
    if ( I1IIi == "" ) : continue
    iIII1iIiI = iio0O [ oO ]
    if ( iIII1iIiI . source_eid == None ) :
     iIII1iIiI . source_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
     if 86 - 86: o0oOOo0O0Ooo . Oo0Ooo - Ii1I / i11iIiiIii
    IIiI1i = iIII1iIiI . source_eid . instance_id
    iIII1iIiI . source_eid . store_prefix ( I1IIi )
    iIII1iIiI . source_eid . instance_id = IIiI1i
    if 63 - 63: oO0o - O0 + I1ii11iIi11i + Ii1I / i1IIi
    if 77 - 77: O0
  if ( i11IIIi11 == "destination-eid" ) :
   for oO in range ( len ( iio0O ) ) :
    I1IIi = oOOO [ oO ]
    if ( I1IIi == "" ) : continue
    iIII1iIiI = iio0O [ oO ]
    if ( iIII1iIiI . dest_eid == None ) :
     iIII1iIiI . dest_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
     if 49 - 49: o0oOOo0O0Ooo / i11iIiiIii
    IIiI1i = iIII1iIiI . dest_eid . instance_id
    iIII1iIiI . dest_eid . store_prefix ( I1IIi )
    iIII1iIiI . dest_eid . instance_id = IIiI1i
    if 36 - 36: II111iiii
    if 78 - 78: OoO0O00 + iIii1I11I1II1 * i1IIi
  if ( i11IIIi11 == "source-rloc" ) :
   for oO in range ( len ( iio0O ) ) :
    I1IIi = oOOO [ oO ]
    if ( I1IIi == "" ) : continue
    iIII1iIiI = iio0O [ oO ]
    iIII1iIiI . source_rloc = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
    iIII1iIiI . source_rloc . store_prefix ( I1IIi )
    if 7 - 7: i11iIiiIii
    if 49 - 49: I1IiiI - oO0o % OOooOOo / O0 / II111iiii
  if ( i11IIIi11 == "destination-rloc" ) :
   for oO in range ( len ( iio0O ) ) :
    I1IIi = oOOO [ oO ]
    if ( I1IIi == "" ) : continue
    iIII1iIiI = iio0O [ oO ]
    iIII1iIiI . dest_rloc = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
    iIII1iIiI . dest_rloc . store_prefix ( I1IIi )
    if 41 - 41: IiII % II111iiii
    if 99 - 99: IiII - O0
  if ( i11IIIi11 == "rloc-record-name" ) :
   for oO in range ( len ( iio0O ) ) :
    I1IIi = oOOO [ oO ]
    if ( I1IIi == "" ) : continue
    iIII1iIiI = iio0O [ oO ]
    iIII1iIiI . rloc_record_name = I1IIi
    if 59 - 59: iII111i % O0 + OOooOOo * ooOoO0o
    if 27 - 27: I1Ii111 % i11iIiiIii * I1IiiI
  if ( i11IIIi11 == "geo-name" ) :
   for oO in range ( len ( iio0O ) ) :
    I1IIi = oOOO [ oO ]
    if ( I1IIi == "" ) : continue
    iIII1iIiI = iio0O [ oO ]
    iIII1iIiI . geo_name = I1IIi
    if 19 - 19: OoOoOO00 / o0oOOo0O0Ooo - iII111i / OoO0O00
    if 12 - 12: I1ii11iIi11i - I11i * O0 % I1IiiI + O0 - II111iiii
  if ( i11IIIi11 == "elp-name" ) :
   for oO in range ( len ( iio0O ) ) :
    I1IIi = oOOO [ oO ]
    if ( I1IIi == "" ) : continue
    iIII1iIiI = iio0O [ oO ]
    iIII1iIiI . elp_name = I1IIi
    if 13 - 13: iII111i / OOooOOo * i11iIiiIii / oO0o / OoooooooOO
    if 89 - 89: Ii1I * Oo0Ooo / I1Ii111 * I1ii11iIi11i + O0 * Oo0Ooo
  if ( i11IIIi11 == "rle-name" ) :
   for oO in range ( len ( iio0O ) ) :
    I1IIi = oOOO [ oO ]
    if ( I1IIi == "" ) : continue
    iIII1iIiI = iio0O [ oO ]
    iIII1iIiI . rle_name = I1IIi
    if 74 - 74: I11i . I11i
    if 74 - 74: OoOoOO00 * ooOoO0o * I1Ii111
  if ( i11IIIi11 == "json-name" ) :
   for oO in range ( len ( iio0O ) ) :
    I1IIi = oOOO [ oO ]
    if ( I1IIi == "" ) : continue
    iIII1iIiI = iio0O [ oO ]
    iIII1iIiI . json_name = I1IIi
    if 56 - 56: iIii1I11I1II1 * OoO0O00 - oO0o * Ii1I
    if 62 - 62: i1IIi + I11i / OOooOOo - OoooooooOO % i1IIi . I1IiiI
  if ( i11IIIi11 == "datetime-range" ) :
   for oO in range ( len ( iio0O ) ) :
    I1IIi = oOOO [ oO ]
    iIII1iIiI = iio0O [ oO ]
    if ( I1IIi == "" ) : continue
    i1I1i = lisp_datetime ( I1IIi [ 0 : 19 ] )
    OooOoO0OOoo = lisp_datetime ( I1IIi [ 19 : : ] )
    if ( i1I1i . valid_datetime ( ) and OooOoO0OOoo . valid_datetime ( ) ) :
     iIII1iIiI . datetime_lower = i1I1i
     iIII1iIiI . datetime_upper = OooOoO0OOoo
     if 13 - 13: O0 * iII111i
     if 26 - 26: i1IIi - I1Ii111 - ooOoO0o
     if 73 - 73: o0oOOo0O0Ooo . OoooooooOO
     if 96 - 96: i1IIi - OOooOOo / I11i % OoOoOO00 - i11iIiiIii % II111iiii
     if 47 - 47: I1Ii111 * iII111i
     if 90 - 90: i1IIi * Ii1I . OoO0O00 % I11i * ooOoO0o . OOooOOo
     if 76 - 76: iIii1I11I1II1 . i11iIiiIii * II111iiii - iII111i
  if ( i11IIIi11 == "set-action" ) :
   oo000o . set_action = oOOO
   if 51 - 51: I1IiiI
  if ( i11IIIi11 == "set-record-ttl" ) :
   oo000o . set_record_ttl = int ( oOOO )
   if 52 - 52: I1Ii111
  if ( i11IIIi11 == "set-instance-id" ) :
   if ( oo000o . set_source_eid == None ) :
    oo000o . set_source_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
    if 82 - 82: iII111i + II111iiii
   if ( oo000o . set_dest_eid == None ) :
    oo000o . set_dest_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
    if 29 - 29: O0 % Ii1I * ooOoO0o % O0
   I1I1Iii1I1111 = int ( oOOO )
   oo000o . set_source_eid . instance_id = I1I1Iii1I1111
   oo000o . set_dest_eid . instance_id = I1I1Iii1I1111
   if 83 - 83: oO0o
  if ( i11IIIi11 == "set-source-eid" ) :
   if ( oo000o . set_source_eid == None ) :
    oo000o . set_source_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
    if 95 - 95: Oo0Ooo * O0 % i1IIi / iII111i + oO0o
   oo000o . set_source_eid . store_prefix ( oOOO )
   if ( I1I1Iii1I1111 != None ) : oo000o . set_source_eid . instance_id = I1I1Iii1I1111
   if 85 - 85: iIii1I11I1II1 / I11i
  if ( i11IIIi11 == "set-destination-eid" ) :
   if ( oo000o . set_dest_eid == None ) :
    oo000o . set_dest_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
    if 65 - 65: I11i / i1IIi * OoOoOO00 * Ii1I * OoO0O00
   oo000o . set_dest_eid . store_prefix ( oOOO )
   if ( I1I1Iii1I1111 != None ) : oo000o . set_dest_eid . instance_id = I1I1Iii1I1111
   if 74 - 74: I1ii11iIi11i . I1ii11iIi11i % IiII + OOooOOo . OoO0O00 * I11i
  if ( i11IIIi11 == "set-rloc-address" ) :
   oo000o . set_rloc_address = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
   oo000o . set_rloc_address . store_address ( oOOO )
   if 20 - 20: OOooOOo % i1IIi * Ii1I / i11iIiiIii
  if ( i11IIIi11 == "set-rloc-record-name" ) :
   oo000o . set_rloc_record_name = oOOO
   if 89 - 89: ooOoO0o
  if ( i11IIIi11 == "set-elp-name" ) :
   oo000o . set_elp_name = oOOO
   if 83 - 83: I11i . I11i * OOooOOo - OOooOOo
  if ( i11IIIi11 == "set-geo-name" ) :
   oo000o . set_geo_name = oOOO
   if 46 - 46: iIii1I11I1II1 . I1Ii111 % I1IiiI
  if ( i11IIIi11 == "set-rle-name" ) :
   oo000o . set_rle_name = oOOO
   if 22 - 22: i1IIi * I11i + II111iiii + II111iiii
  if ( i11IIIi11 == "set-json-name" ) :
   oo000o . set_json_name = oOOO
   if 20 - 20: I11i
  if ( i11IIIi11 == "policy-name" ) :
   oo000o . policy_name = oOOO
   if 37 - 37: I1Ii111
   if 19 - 19: I1ii11iIi11i / OOooOOo . I1IiiI / ooOoO0o + OoO0O00 + i11iIiiIii
   if 80 - 80: OoO0O00 . O0 / Ii1I % I1Ii111 / iII111i * I1IiiI
   if 41 - 41: O0 / OoooooooOO - i1IIi
   if 6 - 6: i1IIi - I1ii11iIi11i % I1Ii111 - II111iiii / ooOoO0o / i11iIiiIii
   if 32 - 32: oO0o / IiII - I11i . ooOoO0o
 oo000o . match_clauses = iio0O
 oo000o . save_policy ( )
 return
 if 69 - 69: i11iIiiIii * i11iIiiIii
 if 100 - 100: I1ii11iIi11i * I1ii11iIi11i + i1IIi
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
if 96 - 96: I1Ii111 / I1IiiI + ooOoO0o
if 16 - 16: I1ii11iIi11i % o0oOOo0O0Ooo % OOooOOo % OoOoOO00 + ooOoO0o % I1ii11iIi11i
if 85 - 85: oO0o * OoooooooOO * iIii1I11I1II1 + iII111i
if 67 - 67: Ii1I / i11iIiiIii % OoOoOO00 % O0 / OoOoOO00
if 54 - 54: I11i . OoOoOO00 / II111iiii . i1IIi + OOooOOo % II111iiii
if 82 - 82: i11iIiiIii . OoooooooOO % OoOoOO00 * O0 - I1Ii111
if 78 - 78: OoOoOO00 % Ii1I % OOooOOo % Oo0Ooo % I11i . Ii1I
def lisp_send_to_arista ( command , interface ) :
 interface = "" if ( interface == None ) else "interface " + interface
 if 73 - 73: OoooooooOO / i1IIi . iIii1I11I1II1
 ooO00O0o0O0o = command
 if ( interface != "" ) : ooO00O0o0O0o = interface + ": " + ooO00O0o0O0o
 lprint ( "Send CLI command '{}' to hardware" . format ( ooO00O0o0O0o ) )
 if 28 - 28: OOooOOo - oO0o
 commands = '''
        enable
        configure
        {}
        {}
    ''' . format ( interface , command )
 if 83 - 83: o0oOOo0O0Ooo . OoO0O00 % iIii1I11I1II1 % OoOoOO00 - i11iIiiIii
 os . system ( "FastCli -c '{}'" . format ( commands ) )
 return
 if 71 - 71: I1ii11iIi11i - II111iiii / O0 % i1IIi + oO0o
 if 73 - 73: OoooooooOO
 if 25 - 25: i1IIi . II111iiii . I1Ii111
 if 81 - 81: II111iiii + OoOoOO00 * II111iiii / iIii1I11I1II1 - Oo0Ooo % oO0o
 if 66 - 66: ooOoO0o % O0 + iIii1I11I1II1 * I1Ii111 - I1Ii111
 if 61 - 61: I1ii11iIi11i
 if 12 - 12: OoO0O00
def lisp_arista_is_alive ( prefix ) :
 iIiI1 = "enable\nsh plat trident l3 software routes {}\n" . format ( prefix )
 ooO000O = commands . getoutput ( "FastCli -c '{}'" . format ( iIiI1 ) )
 if 97 - 97: OOooOOo . Oo0Ooo . oO0o * i1IIi
 if 7 - 7: Oo0Ooo
 if 38 - 38: Oo0Ooo - I1ii11iIi11i
 if 19 - 19: Ii1I * OoO0O00 / OoO0O00 . II111iiii % iIii1I11I1II1
 ooO000O = ooO000O . split ( "\n" ) [ 1 ]
 OO0OO0O00o0o = ooO000O . split ( " " )
 OO0OO0O00o0o = OO0OO0O00o0o [ - 1 ] . replace ( "\r" , "" )
 if 10 - 10: oO0o % iIii1I11I1II1 . OOooOOo / I11i / i1IIi
 if 69 - 69: i1IIi / iII111i + Ii1I + I11i + IiII
 if 86 - 86: Oo0Ooo
 if 97 - 97: I1IiiI
 return ( OO0OO0O00o0o == "Y" )
 if 91 - 91: ooOoO0o / oO0o * OOooOOo . II111iiii - I11i - I11i
 if 5 - 5: O0 + OoooooooOO + i11iIiiIii * Oo0Ooo * OoOoOO00 . oO0o
 if 6 - 6: OoO0O00 % Oo0Ooo % I1IiiI % o0oOOo0O0Ooo % O0 % Oo0Ooo
 if 94 - 94: I11i . i1IIi / II111iiii + OOooOOo
 if 64 - 64: I1IiiI % ooOoO0o
 if 72 - 72: O0 * II111iiii % OoO0O00 - I1IiiI * OOooOOo
 if 80 - 80: OOooOOo * I11i / OOooOOo - oO0o
 if 18 - 18: i1IIi - OOooOOo - o0oOOo0O0Ooo - iIii1I11I1II1
 if 72 - 72: OoooooooOO % I1IiiI . OoO0O00
 if 28 - 28: II111iiii / iIii1I11I1II1 / iII111i - o0oOOo0O0Ooo . I1IiiI / O0
 if 16 - 16: ooOoO0o * oO0o . OoooooooOO
 if 44 - 44: iIii1I11I1II1 * OOooOOo + OoO0O00 - OoooooooOO
 if 13 - 13: Oo0Ooo . I11i . II111iiii
 if 6 - 6: OOooOOo . IiII / OoO0O00 * oO0o - I1Ii111 . OoOoOO00
 if 85 - 85: i11iIiiIii + OoOoOO00
 if 4 - 4: OOooOOo . OoO0O00 * II111iiii + OoO0O00 % Oo0Ooo
 if 60 - 60: OOooOOo . Ii1I
 if 13 - 13: i1IIi . iII111i / OoOoOO00 . I1Ii111
 if 65 - 65: oO0o % I1Ii111 % OoO0O00 . iIii1I11I1II1
 if 38 - 38: IiII / I11i / IiII * iII111i
 if 30 - 30: oO0o
 if 30 - 30: IiII / OoO0O00
 if 89 - 89: oO0o . OoOoOO00 . IiII / iIii1I11I1II1 . iIii1I11I1II1 / OoOoOO00
 if 86 - 86: OoooooooOO - iIii1I11I1II1 . OoO0O00 * Ii1I / I1Ii111 + I1Ii111
 if 52 - 52: iIii1I11I1II1 % OoO0O00 - IiII % i11iIiiIii - o0oOOo0O0Ooo
 if 25 - 25: Oo0Ooo - OOooOOo . i1IIi * OoOoOO00 / I11i / o0oOOo0O0Ooo
 if 54 - 54: OoOoOO00 / i1IIi + OOooOOo - I1ii11iIi11i - I1IiiI * I1Ii111
 if 91 - 91: OoooooooOO * OoooooooOO
 if 27 - 27: ooOoO0o / I1IiiI * I1ii11iIi11i . o0oOOo0O0Ooo
 if 30 - 30: o0oOOo0O0Ooo / i11iIiiIii
 if 33 - 33: OOooOOo % OoooooooOO
 if 98 - 98: Ii1I
 if 38 - 38: ooOoO0o - iII111i * OOooOOo % I1ii11iIi11i + Oo0Ooo
 if 95 - 95: iIii1I11I1II1 / O0 % O0
 if 53 - 53: ooOoO0o . ooOoO0o
 if 80 - 80: i11iIiiIii % I1Ii111 % I1IiiI / I1IiiI + oO0o + iII111i
 if 18 - 18: OoO0O00 * ooOoO0o
 if 32 - 32: oO0o . OoooooooOO - o0oOOo0O0Ooo + II111iiii
 if 4 - 4: OOooOOo * I1IiiI - I11i - I11i
 if 67 - 67: I1IiiI
 if 32 - 32: oO0o * i11iIiiIii - I11i % Oo0Ooo * I1ii11iIi11i
 if 79 - 79: II111iiii / Oo0Ooo / I1ii11iIi11i
 if 30 - 30: I11i . o0oOOo0O0Ooo / II111iiii
 if 59 - 59: i11iIiiIii
def lisp_program_vxlan_hardware ( mc ) :
 if 5 - 5: i11iIiiIii + o0oOOo0O0Ooo . OoO0O00 % OoOoOO00 + I11i
 if 59 - 59: I1ii11iIi11i
 if 47 - 47: I1IiiI + Oo0Ooo
 if 78 - 78: i1IIi / I1ii11iIi11i % ooOoO0o * OoO0O00
 if 10 - 10: i1IIi % ooOoO0o / iII111i
 if 98 - 98: IiII / o0oOOo0O0Ooo - i1IIi - OOooOOo
 if ( os . path . exists ( "/persist/local/lispers.net" ) == False ) : return
 if 65 - 65: Ii1I + OoOoOO00 * Oo0Ooo . O0 . IiII
 if 33 - 33: i11iIiiIii . i1IIi . I1Ii111 - OoOoOO00 + OOooOOo
 if 34 - 34: I1ii11iIi11i . i1IIi * O0 / OoooooooOO
 if 22 - 22: OOooOOo % o0oOOo0O0Ooo - i11iIiiIii
 if ( len ( mc . best_rloc_set ) == 0 ) : return
 if 58 - 58: IiII . Ii1I + II111iiii
 if 31 - 31: i11iIiiIii + i11iIiiIii + I11i * Oo0Ooo . I11i
 if 28 - 28: OOooOOo * iIii1I11I1II1 * OoOoOO00
 if 75 - 75: Oo0Ooo % IiII + II111iiii + oO0o
 i1IIIII1 = mc . eid . print_prefix_no_iid ( )
 oOoOoo0O = mc . best_rloc_set [ 0 ] . rloc . print_address_no_iid ( )
 if 35 - 35: I1ii11iIi11i - oO0o - O0 / iII111i % IiII
 if 10 - 10: OOooOOo + oO0o - I1Ii111 . I1IiiI
 if 11 - 11: I1ii11iIi11i . I1Ii111 / o0oOOo0O0Ooo + IiII
 if 73 - 73: OoO0O00 . i11iIiiIii * OoO0O00 * i1IIi + I11i
 Ii1IiiI = commands . getoutput ( "ip route get {} | egrep vlan4094" . format ( i1IIIII1 ) )
 if 75 - 75: i1IIi - oO0o * Ii1I / iIii1I11I1II1 - O0 - ooOoO0o
 if ( Ii1IiiI != "" ) :
  lprint ( "Route {} already in hardware: '{}'" . format ( green ( i1IIIII1 , False ) , Ii1IiiI ) )
  if 88 - 88: ooOoO0o / ooOoO0o . I11i
  return
  if 2 - 2: OoO0O00 * OoO0O00 * Ii1I + iII111i + OOooOOo - II111iiii
  if 76 - 76: II111iiii * o0oOOo0O0Ooo - IiII
  if 93 - 93: iIii1I11I1II1 % Ii1I * Ii1I + i11iIiiIii . o0oOOo0O0Ooo / iII111i
  if 7 - 7: ooOoO0o
  if 11 - 11: iII111i . oO0o % I11i
  if 42 - 42: I1ii11iIi11i
  if 77 - 77: iIii1I11I1II1 * i11iIiiIii + Ii1I . ooOoO0o / OOooOOo * O0
 iIII1I1111Ii1 = commands . getoutput ( "ifconfig | egrep 'vxlan|vlan4094'" )
 if ( iIII1I1111Ii1 . find ( "vxlan" ) == - 1 ) :
  lprint ( "No VXLAN interface found, cannot program hardware" )
  return
  if 83 - 83: Ii1I * I1Ii111 * i11iIiiIii / iIii1I11I1II1 % I1ii11iIi11i
 if ( iIII1I1111Ii1 . find ( "vlan4094" ) == - 1 ) :
  lprint ( "No vlan4094 interface found, cannot program hardware" )
  return
  if 40 - 40: iII111i
 I1I1ii1iiiI1I = commands . getoutput ( "ip addr | egrep vlan4094 | egrep inet" )
 if ( I1I1ii1iiiI1I == "" ) :
  lprint ( "No IP address found on vlan4094, cannot program hardware" )
  return
  if 1 - 1: OoooooooOO
 I1I1ii1iiiI1I = I1I1ii1iiiI1I . split ( "inet " ) [ 1 ]
 I1I1ii1iiiI1I = I1I1ii1iiiI1I . split ( "/" ) [ 0 ]
 if 25 - 25: i11iIiiIii % iIii1I11I1II1 * OoO0O00 - I1Ii111 / I1ii11iIi11i - I1IiiI
 if 87 - 87: i11iIiiIii + iII111i - I1Ii111 * I1Ii111
 if 47 - 47: i11iIiiIii - O0 / I1Ii111 + o0oOOo0O0Ooo % OoooooooOO
 if 5 - 5: OOooOOo * I1ii11iIi11i
 if 63 - 63: Ii1I - II111iiii % OoOoOO00 . I11i - i1IIi
 if 31 - 31: I1IiiI . I1Ii111 - OoooooooOO / i1IIi
 if 89 - 89: I1ii11iIi11i
 oOoO0oOo0ooOo = [ ]
 iiI1111I = commands . getoutput ( "arp -i vlan4094" ) . split ( "\n" )
 for OOooO in iiI1111I :
  if ( OOooO . find ( "vlan4094" ) == - 1 ) : continue
  if ( OOooO . find ( "(incomplete)" ) == - 1 ) : continue
  IiIIiI11I = OOooO . split ( " " ) [ 0 ]
  oOoO0oOo0ooOo . append ( IiIIiI11I )
  if 64 - 64: Ii1I / I1ii11iIi11i
  if 30 - 30: OoooooooOO + O0 / I1ii11iIi11i * o0oOOo0O0Ooo
 IiIIiI11I = None
 i1i1i = I1I1ii1iiiI1I
 I1I1ii1iiiI1I = I1I1ii1iiiI1I . split ( "." )
 for oO in range ( 1 , 255 ) :
  I1I1ii1iiiI1I [ 3 ] = str ( oO )
  I1Iii1I = "." . join ( I1I1ii1iiiI1I )
  if ( I1Iii1I in oOoO0oOo0ooOo ) : continue
  if ( I1Iii1I == i1i1i ) : continue
  IiIIiI11I = I1Iii1I
  break
  if 11 - 11: O0 + OoO0O00 - Oo0Ooo - Oo0Ooo . i11iIiiIii
 if ( IiIIiI11I == None ) :
  lprint ( "Address allocation failed for vlan4094, cannot program " + "hardware" )
  if 15 - 15: Ii1I % i11iIiiIii / OoOoOO00
  return
  if 85 - 85: ooOoO0o . i1IIi / iII111i % iIii1I11I1II1 / II111iiii / I1Ii111
  if 60 - 60: iIii1I11I1II1 - iIii1I11I1II1 . I11i
  if 55 - 55: OoO0O00
  if 87 - 87: Ii1I - iII111i / O0 - o0oOOo0O0Ooo - iIii1I11I1II1 % Ii1I
  if 47 - 47: iII111i * I1Ii111 % o0oOOo0O0Ooo / OoOoOO00 / OoO0O00 % OoO0O00
  if 43 - 43: Oo0Ooo
  if 34 - 34: OoO0O00 . i1IIi + IiII * IiII
 oOO0o0o0O = oOoOoo0O . split ( "." )
 iiIIi111I = lisp_hex_string ( oOO0o0o0O [ 1 ] ) . zfill ( 2 )
 IIi111Ii1I = lisp_hex_string ( oOO0o0o0O [ 2 ] ) . zfill ( 2 )
 iIiiIIiiii1 = lisp_hex_string ( oOO0o0o0O [ 3 ] ) . zfill ( 2 )
 o0O0oO0 = "00:00:00:{}:{}:{}" . format ( iiIIi111I , IIi111Ii1I , iIiiIIiiii1 )
 oO0Oo000 = "0000.00{}.{}{}" . format ( iiIIi111I , IIi111Ii1I , iIiiIIiiii1 )
 i1iII = "arp -i vlan4094 -s {} {}" . format ( IiIIiI11I , o0O0oO0 )
 os . system ( i1iII )
 if 4 - 4: OOooOOo * IiII + I1ii11iIi11i . i1IIi
 if 56 - 56: i1IIi
 if 32 - 32: OoooooooOO % I1IiiI - iIii1I11I1II1
 if 10 - 10: O0 - I11i + OoOoOO00
 Oo0II11I1i1I = ( "mac address-table static {} vlan 4094 " + "interface vxlan 1 vtep {}" ) . format ( oO0Oo000 , oOoOoo0O )
 if 39 - 39: O0 / oO0o % oO0o * iIii1I11I1II1
 lisp_send_to_arista ( Oo0II11I1i1I , None )
 if 7 - 7: iII111i % o0oOOo0O0Ooo / II111iiii % IiII / iIii1I11I1II1
 if 17 - 17: I11i * I11i - O0 / IiII + OoOoOO00
 if 65 - 65: I1Ii111 * i1IIi
 if 10 - 10: OOooOOo % IiII
 if 20 - 20: I11i / OoooooooOO % OoOoOO00 . oO0o * I1IiiI % IiII
 OOo000oOOo = "ip route add {} via {}" . format ( i1IIIII1 , IiIIiI11I )
 os . system ( OOo000oOOo )
 if 77 - 77: Oo0Ooo - I11i
 lprint ( "Hardware programmed with commands:" )
 OOo000oOOo = OOo000oOOo . replace ( i1IIIII1 , green ( i1IIIII1 , False ) )
 lprint ( "  " + OOo000oOOo )
 lprint ( "  " + i1iII )
 Oo0II11I1i1I = Oo0II11I1i1I . replace ( oOoOoo0O , red ( oOoOoo0O , False ) )
 lprint ( "  " + Oo0II11I1i1I )
 return
 if 5 - 5: I1IiiI + ooOoO0o
 if 29 - 29: IiII + I1ii11iIi11i
 if 8 - 8: IiII % I1IiiI
 if 10 - 10: OoooooooOO / OoOoOO00
 if 77 - 77: OoOoOO00
 if 10 - 10: IiII / i11iIiiIii
 if 19 - 19: OoO0O00
def lisp_clear_hardware_walk ( mc , parms ) :
 ii1II1 = mc . eid . print_prefix_no_iid ( )
 os . system ( "ip route delete {}" . format ( ii1II1 ) )
 return ( [ True , None ] )
 if 100 - 100: I1ii11iIi11i - I1ii11iIi11i
 if 38 - 38: I1Ii111
 if 23 - 23: Ii1I . I1ii11iIi11i + I1Ii111 + i1IIi * o0oOOo0O0Ooo - i11iIiiIii
 if 92 - 92: I1Ii111 - I1IiiI + Ii1I / iII111i % OOooOOo
 if 32 - 32: i1IIi . iII111i - Ii1I % iII111i % II111iiii - oO0o
 if 36 - 36: OoooooooOO * OoooooooOO . ooOoO0o . O0
 if 5 - 5: I11i % I1IiiI - OoO0O00 . Oo0Ooo
 if 79 - 79: iII111i + IiII % I11i . Oo0Ooo / IiII * iII111i
def lisp_clear_map_cache ( ) :
 global lisp_map_cache , lisp_rloc_probe_list
 global lisp_crypto_keys_by_rloc_encap , lisp_crypto_keys_by_rloc_decap
 global lisp_rtr_list
 if 40 - 40: iII111i - I1IiiI + OoOoOO00
 i1ii1iIII = bold ( "User cleared" , False )
 Ooo00OOOOOO0 = lisp_map_cache . cache_count
 lprint ( "{} map-cache with {} entries" . format ( i1ii1iIII , Ooo00OOOOOO0 ) )
 if 90 - 90: i11iIiiIii + II111iiii + I1IiiI % I1ii11iIi11i
 if ( lisp_program_hardware ) :
  lisp_map_cache . walk_cache ( lisp_clear_hardware_walk , None )
  if 3 - 3: I1Ii111 + Ii1I + Ii1I + iIii1I11I1II1 + I1Ii111 * I11i
 lisp_map_cache = lisp_cache ( )
 if 44 - 44: i1IIi - I1IiiI / IiII + IiII
 if 65 - 65: OOooOOo * I1Ii111 . i1IIi % iIii1I11I1II1
 if 31 - 31: I1IiiI * I1Ii111 * O0 * I1Ii111 . II111iiii
 if 52 - 52: iIii1I11I1II1 . oO0o % I1Ii111 + i11iIiiIii
 if 43 - 43: I1ii11iIi11i + I11i - iIii1I11I1II1
 lisp_rloc_probe_list = { }
 if 100 - 100: OoOoOO00
 if 28 - 28: ooOoO0o + Oo0Ooo - I1ii11iIi11i
 if 16 - 16: O0 - OoO0O00 % Ii1I % O0
 if 51 - 51: iIii1I11I1II1 * i11iIiiIii . I1IiiI + o0oOOo0O0Ooo / iII111i - I1IiiI
 lisp_crypto_keys_by_rloc_encap = { }
 lisp_crypto_keys_by_rloc_decap = { }
 if 73 - 73: OOooOOo
 if 100 - 100: o0oOOo0O0Ooo - OoOoOO00
 if 91 - 91: II111iiii / i11iIiiIii . Oo0Ooo * iIii1I11I1II1
 if 6 - 6: ooOoO0o * Oo0Ooo . OoO0O00
 if 24 - 24: O0 * oO0o % O0 * iIii1I11I1II1 - OoO0O00
 lisp_rtr_list = { }
 if 18 - 18: Ii1I + I1ii11iIi11i % I1ii11iIi11i + II111iiii
 if 86 - 86: iII111i . O0 - iIii1I11I1II1 - iIii1I11I1II1
 if 79 - 79: OoOoOO00 + Ii1I - oO0o - iIii1I11I1II1 + OoooooooOO
 if 87 - 87: ooOoO0o
 lisp_process_data_plane_restart ( True )
 return
 if 74 - 74: o0oOOo0O0Ooo - o0oOOo0O0Ooo % OoooooooOO . o0oOOo0O0Ooo - I1IiiI - I1ii11iIi11i
 if 40 - 40: II111iiii . Oo0Ooo * I1Ii111
 if 63 - 63: OoooooooOO + OoOoOO00 - OoooooooOO
 if 54 - 54: OoO0O00 + I1IiiI % O0 + OoO0O00
 if 37 - 37: II111iiii / I1ii11iIi11i * I1IiiI - OoooooooOO
 if 55 - 55: IiII / ooOoO0o * I1IiiI / I1Ii111 - Oo0Ooo % o0oOOo0O0Ooo
 if 82 - 82: OoO0O00 - iIii1I11I1II1 . Oo0Ooo / IiII . OoO0O00
 if 47 - 47: OOooOOo + IiII
 if 11 - 11: Oo0Ooo + I1IiiI % i11iIiiIii % Oo0Ooo + ooOoO0o + i1IIi
 if 100 - 100: II111iiii - OOooOOo + iII111i - i11iIiiIii . O0 / iII111i
 if 64 - 64: Ii1I
def lisp_encapsulate_rloc_probe ( lisp_sockets , rloc , nat_info , packet ) :
 if ( len ( lisp_sockets ) != 4 ) : return
 if 4 - 4: OoOoOO00
 OoO0Oo0o = lisp_myrlocs [ 0 ]
 if 52 - 52: OoooooooOO * I1Ii111 % II111iiii
 if 40 - 40: I11i / ooOoO0o . OoO0O00 + i1IIi + iII111i - Ii1I
 if 9 - 9: o0oOOo0O0Ooo
 if 92 - 92: i11iIiiIii + OoooooooOO + O0 % oO0o
 if 90 - 90: Oo0Ooo * i11iIiiIii
 I111 = len ( packet ) + 28
 oOo00Ooo0o0 = struct . pack ( "BBHIBBHII" , 0x45 , 0 , socket . htons ( I111 ) , 0 , 64 ,
 17 , 0 , socket . htonl ( OoO0Oo0o . address ) , socket . htonl ( rloc . address ) )
 oOo00Ooo0o0 = lisp_ip_checksum ( oOo00Ooo0o0 )
 if 95 - 95: I1Ii111 % i11iIiiIii . i11iIiiIii . i11iIiiIii . OoooooooOO - I1Ii111
 IIi1ii1 = struct . pack ( "HHHH" , 0 , socket . htons ( LISP_CTRL_PORT ) ,
 socket . htons ( I111 - 20 ) , 0 )
 if 69 - 69: iIii1I11I1II1 * oO0o
 if 80 - 80: IiII - oO0o % Ii1I - iIii1I11I1II1 . OoO0O00
 if 64 - 64: I1IiiI % i11iIiiIii / oO0o
 if 78 - 78: II111iiii - Oo0Ooo . iIii1I11I1II1 - ooOoO0o . oO0o
 packet = lisp_packet ( oOo00Ooo0o0 + IIi1ii1 + packet )
 if 84 - 84: iII111i . ooOoO0o * I1IiiI * Oo0Ooo / I1Ii111
 if 93 - 93: i1IIi * i11iIiiIii % OoOoOO00 % iII111i
 if 31 - 31: OoO0O00
 if 89 - 89: II111iiii
 packet . inner_dest . copy_address ( rloc )
 packet . inner_dest . instance_id = 0xffffff
 packet . inner_source . copy_address ( OoO0Oo0o )
 packet . inner_ttl = 64
 packet . outer_dest . copy_address ( rloc )
 packet . outer_source . copy_address ( OoO0Oo0o )
 packet . outer_version = packet . outer_dest . afi_to_version ( )
 packet . outer_ttl = 64
 packet . encap_port = nat_info . port if nat_info else LISP_DATA_PORT
 if 33 - 33: OOooOOo / oO0o % OoOoOO00 * O0
 Oo0oO = red ( rloc . print_address_no_iid ( ) , False )
 if ( nat_info ) :
  o00oo0OO = " {}" . format ( blue ( nat_info . hostname , False ) )
  o0ooOOoO0O = bold ( "RLOC-probe request" , False )
 else :
  o00oo0OO = ""
  o0ooOOoO0O = bold ( "RLOC-probe reply" , False )
  if 65 - 65: OoO0O00 % OoOoOO00 % I1ii11iIi11i / OoooooooOO
  if 85 - 85: O0 * OOooOOo % I1Ii111
 lprint ( ( "Data encapsulate {} to {}{} port {} for " + "NAT-traversal" ) . format ( o0ooOOoO0O , Oo0oO , o00oo0OO , packet . encap_port ) )
 if 33 - 33: O0
 if 30 - 30: II111iiii . O0 . oO0o * I1ii11iIi11i + oO0o . o0oOOo0O0Ooo
 if 43 - 43: iIii1I11I1II1
 if 88 - 88: I1IiiI - OoO0O00 . O0 . oO0o
 if 75 - 75: II111iiii % OOooOOo / iIii1I11I1II1 / OoO0O00 + oO0o
 if ( packet . encode ( None ) == None ) : return
 packet . print_packet ( "Send" , True )
 if 16 - 16: oO0o + I1Ii111 - II111iiii - o0oOOo0O0Ooo / i11iIiiIii
 oOO0O00O0 = lisp_sockets [ 3 ]
 packet . send_packet ( oOO0O00O0 , packet . outer_dest )
 del ( packet )
 return
 if 69 - 69: o0oOOo0O0Ooo * OOooOOo - ooOoO0o
 if 14 - 14: o0oOOo0O0Ooo . OoooooooOO - I1ii11iIi11i * iII111i / ooOoO0o
 if 99 - 99: I1ii11iIi11i + I11i
 if 29 - 29: I1ii11iIi11i / oO0o
 if 2 - 2: Oo0Ooo / IiII - OoooooooOO
 if 65 - 65: OoO0O00 - Ii1I
 if 98 - 98: OoOoOO00 * I1Ii111 * iIii1I11I1II1 * OoOoOO00
 if 15 - 15: Oo0Ooo
def lisp_get_default_route_next_hops ( ) :
 if 100 - 100: IiII + I1ii11iIi11i + iII111i . i1IIi . I1ii11iIi11i / OoooooooOO
 if 84 - 84: o0oOOo0O0Ooo * I11i
 if 22 - 22: i1IIi + OOooOOo % OoooooooOO
 if 34 - 34: oO0o / O0 - II111iiii % Oo0Ooo + I11i
 if ( lisp_is_macos ( ) ) :
  iIiI1 = "route -n get default"
  IIiiIi = commands . getoutput ( iIiI1 ) . split ( "\n" )
  iiIIi1I = iIiiiIiIi = None
  for Ii11111i1 in IIiiIi :
   if ( Ii11111i1 . find ( "gateway: " ) != - 1 ) : iiIIi1I = Ii11111i1 . split ( ": " ) [ 1 ]
   if ( Ii11111i1 . find ( "interface: " ) != - 1 ) : iIiiiIiIi = Ii11111i1 . split ( ": " ) [ 1 ]
   if 3 - 3: i1IIi * OOooOOo
  return ( [ [ iIiiiIiIi , iiIIi1I ] ] )
  if 86 - 86: OoOoOO00 * Oo0Ooo / iIii1I11I1II1
  if 63 - 63: IiII - ooOoO0o % OoO0O00 * i11iIiiIii % OOooOOo
  if 90 - 90: oO0o / Oo0Ooo + iII111i - O0
  if 76 - 76: ooOoO0o + IiII / I1ii11iIi11i . iIii1I11I1II1
  if 52 - 52: iIii1I11I1II1 * OOooOOo % i1IIi
 iIiI1 = "ip route | egrep 'default via'"
 o00OO0OoOOO = commands . getoutput ( iIiI1 ) . split ( "\n" )
 if 1 - 1: o0oOOo0O0Ooo + Ii1I - o0oOOo0O0Ooo % I1ii11iIi11i
 iiii111I = [ ]
 for Ii1IiiI in o00OO0OoOOO :
  if ( Ii1IiiI . find ( " metric " ) != - 1 ) : continue
  iI111I1 = Ii1IiiI . split ( " " )
  try :
   o0oOIIiIi11I = iI111I1 . index ( "via" ) + 1
   if ( o0oOIIiIi11I >= len ( iI111I1 ) ) : continue
   I11O0o0 = iI111I1 . index ( "dev" ) + 1
   if ( I11O0o0 >= len ( iI111I1 ) ) : continue
  except :
   continue
   if 6 - 6: II111iiii . iII111i % I1ii11iIi11i + IiII / I11i
   if 35 - 35: iII111i * Oo0Ooo
  iiii111I . append ( [ iI111I1 [ I11O0o0 ] , iI111I1 [ o0oOIIiIi11I ] ] )
  if 61 - 61: I1Ii111 - I1IiiI - I11i * OoO0O00 - O0 + iII111i
 return ( iiii111I )
 if 9 - 9: IiII - OOooOOo / O0 + i1IIi . O0 % oO0o
 if 57 - 57: i1IIi . OOooOOo
 if 72 - 72: ooOoO0o / I1IiiI - ooOoO0o * OoO0O00 . OOooOOo
 if 1 - 1: o0oOOo0O0Ooo + I1Ii111 + OoO0O00 * OOooOOo / I1Ii111 % i11iIiiIii
 if 49 - 49: OOooOOo - oO0o
 if 73 - 73: o0oOOo0O0Ooo . I1IiiI - I11i . ooOoO0o % II111iiii . OoooooooOO
 if 8 - 8: OoooooooOO
def lisp_get_host_route_next_hop ( rloc ) :
 iIiI1 = "ip route | egrep '{} via'" . format ( rloc )
 Ii1IiiI = commands . getoutput ( iIiI1 ) . split ( " " )
 if 92 - 92: ooOoO0o + IiII * II111iiii
 try : OOOoO000 = Ii1IiiI . index ( "via" ) + 1
 except : return ( None )
 if 41 - 41: I1IiiI + OoOoOO00 . OOooOOo
 if ( OOOoO000 >= len ( Ii1IiiI ) ) : return ( None )
 return ( Ii1IiiI [ OOOoO000 ] )
 if 57 - 57: II111iiii . iIii1I11I1II1
 if 32 - 32: o0oOOo0O0Ooo
 if 75 - 75: I1IiiI . II111iiii - iII111i % IiII * OoO0O00 % ooOoO0o
 if 38 - 38: I1IiiI / OoooooooOO
 if 16 - 16: i1IIi . i11iIiiIii . oO0o - I11i
 if 96 - 96: iII111i - OoOoOO00
 if 43 - 43: OoO0O00 - I1Ii111 % OoooooooOO % I1ii11iIi11i . OoOoOO00
def lisp_install_host_route ( dest , nh , install ) :
 install = "add" if install else "delete"
 OooOo0OOo00O0 = "none" if nh == None else nh
 if 87 - 87: OOooOOo
 lprint ( "{} host-route {}, nh {}" . format ( install . title ( ) , dest , OooOo0OOo00O0 ) )
 if 60 - 60: ooOoO0o * o0oOOo0O0Ooo . OoO0O00 * iII111i * oO0o * i1IIi
 if ( nh == None ) :
  I1IIiIiiiii1 = "ip route {} {}/32" . format ( install , dest )
 else :
  I1IIiIiiiii1 = "ip route {} {}/32 via {}" . format ( install , dest , nh )
  if 100 - 100: iII111i . o0oOOo0O0Ooo - I1Ii111 % oO0o
 os . system ( I1IIiIiiiii1 )
 return
 if 11 - 11: o0oOOo0O0Ooo . OoooooooOO - i1IIi
 if 71 - 71: I1IiiI . OOooOOo . I1ii11iIi11i
 if 90 - 90: i11iIiiIii + I1Ii111 % II111iiii
 if 67 - 67: OoOoOO00 / iII111i * OoO0O00 % i11iIiiIii
 if 76 - 76: OoO0O00
 if 92 - 92: iIii1I11I1II1 * O0 % I11i
 if 92 - 92: OoOoOO00 + oO0o
 if 89 - 89: IiII % iII111i / iIii1I11I1II1 . Ii1I . Oo0Ooo + ooOoO0o
def lisp_checkpoint ( checkpoint_list ) :
 if ( lisp_checkpoint_map_cache == False ) : return
 if 28 - 28: I1IiiI . iIii1I11I1II1
 Ii11111i1 = open ( lisp_checkpoint_filename , "w" )
 for oOoO in checkpoint_list :
  Ii11111i1 . write ( oOoO + "\n" )
  if 12 - 12: I1Ii111 * OOooOOo
 Ii11111i1 . close ( )
 lprint ( "{} {} entries to file '{}'" . format ( bold ( "Checkpoint" , False ) ,
 len ( checkpoint_list ) , lisp_checkpoint_filename ) )
 return
 if 11 - 11: II111iiii % O0 % O0 % o0oOOo0O0Ooo
 if 45 - 45: OoooooooOO * oO0o
 if 74 - 74: ooOoO0o * I11i / oO0o - IiII + OoOoOO00
 if 16 - 16: Oo0Ooo
 if 29 - 29: Oo0Ooo . I1ii11iIi11i / II111iiii / oO0o / o0oOOo0O0Ooo + I11i
 if 4 - 4: OoooooooOO % I1ii11iIi11i . OoO0O00 * o0oOOo0O0Ooo + I1ii11iIi11i * IiII
 if 67 - 67: I1IiiI
 if 93 - 93: ooOoO0o . Ii1I + IiII / Oo0Ooo % I11i
def lisp_load_checkpoint ( ) :
 if ( lisp_checkpoint_map_cache == False ) : return
 if ( os . path . exists ( lisp_checkpoint_filename ) == False ) : return
 if 40 - 40: Oo0Ooo % OoOoOO00 . IiII / I1IiiI % OoooooooOO
 Ii11111i1 = open ( lisp_checkpoint_filename , "r" )
 if 33 - 33: OOooOOo - OoooooooOO . iII111i
 Ooo00OOOOOO0 = 0
 for oOoO in Ii11111i1 :
  Ooo00OOOOOO0 += 1
  I1i11II = oOoO . split ( " rloc " )
  i1iiii11I = [ ] if ( I1i11II [ 1 ] in [ "native-forward\n" , "\n" ] ) else I1i11II [ 1 ] . split ( ", " )
  if 2 - 2: I11i + i1IIi
  if 52 - 52: I11i - OoO0O00 % I1Ii111 . OOooOOo
  I111iIi11Ii11III = [ ]
  for oOoOoo0O in i1iiii11I :
   iIIiIiiI = lisp_rloc ( False )
   iI111I1 = oOoOoo0O . split ( " " )
   iIIiIiiI . rloc . store_address ( iI111I1 [ 0 ] )
   iIIiIiiI . priority = int ( iI111I1 [ 1 ] )
   iIIiIiiI . weight = int ( iI111I1 [ 2 ] )
   I111iIi11Ii11III . append ( iIIiIiiI )
   if 90 - 90: O0 - Oo0Ooo / i1IIi * iIii1I11I1II1 % o0oOOo0O0Ooo / oO0o
   if 73 - 73: iII111i % iIii1I11I1II1 + o0oOOo0O0Ooo % Ii1I . II111iiii + IiII
  oOooO0Oo0Oo0 = lisp_mapping ( "" , "" , I111iIi11Ii11III )
  if ( oOooO0Oo0Oo0 != None ) :
   oOooO0Oo0Oo0 . eid . store_prefix ( I1i11II [ 0 ] )
   oOooO0Oo0Oo0 . checkpoint_entry = True
   oOooO0Oo0Oo0 . map_cache_ttl = LISP_NMR_TTL * 60
   if ( I111iIi11Ii11III == [ ] ) : oOooO0Oo0Oo0 . action = LISP_NATIVE_FORWARD_ACTION
   oOooO0Oo0Oo0 . add_cache ( )
   continue
   if 55 - 55: OoOoOO00 * II111iiii / iII111i + OOooOOo / OoooooooOO
   if 12 - 12: II111iiii * O0 - Oo0Ooo + o0oOOo0O0Ooo . Oo0Ooo + iIii1I11I1II1
  Ooo00OOOOOO0 -= 1
  if 4 - 4: I1Ii111 - I1Ii111 / I1ii11iIi11i . i1IIi + I1ii11iIi11i / oO0o
  if 18 - 18: iIii1I11I1II1 . ooOoO0o
 Ii11111i1 . close ( )
 lprint ( "{} {} map-cache entries from file '{}'" . format (
 bold ( "Loaded" , False ) , Ooo00OOOOOO0 , lisp_checkpoint_filename ) )
 return
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
def lisp_write_checkpoint_entry ( checkpoint_list , mc ) :
 if ( lisp_checkpoint_map_cache == False ) : return
 if 19 - 19: o0oOOo0O0Ooo / iII111i % OoOoOO00
 oOoO = "{} rloc " . format ( mc . eid . print_prefix ( ) )
 if 65 - 65: o0oOOo0O0Ooo
 for iIIiIiiI in mc . rloc_set :
  if ( iIIiIiiI . rloc . is_null ( ) ) : continue
  oOoO += "{} {} {}, " . format ( iIIiIiiI . rloc . print_address_no_iid ( ) ,
 iIIiIiiI . priority , iIIiIiiI . weight )
  if 89 - 89: iIii1I11I1II1 + OoooooooOO + i1IIi + OoooooooOO % IiII * OoO0O00
  if 53 - 53: OOooOOo . IiII % I11i - OoO0O00 - Oo0Ooo
 if ( mc . rloc_set != [ ] ) :
  oOoO = oOoO [ 0 : - 2 ]
 elif ( mc . action == LISP_NATIVE_FORWARD_ACTION ) :
  oOoO += "native-forward"
  if 58 - 58: I1Ii111 / OoooooooOO . I11i % I1Ii111
  if 8 - 8: Oo0Ooo % ooOoO0o / i11iIiiIii
 checkpoint_list . append ( oOoO )
 return
 if 54 - 54: IiII
 if 85 - 85: OOooOOo - i1IIi
 if 10 - 10: I1ii11iIi11i
 if 3 - 3: ooOoO0o * O0 / o0oOOo0O0Ooo
 if 22 - 22: OoOoOO00 + OOooOOo . iII111i % iIii1I11I1II1 - I11i
 if 23 - 23: OoOoOO00 * I1Ii111
 if 18 - 18: o0oOOo0O0Ooo % i11iIiiIii . Ii1I . O0
def lisp_check_dp_socket ( ) :
 OOOo0OOo0oOo0 = lisp_ipc_dp_socket_name
 if ( os . path . exists ( OOOo0OOo0oOo0 ) == False ) :
  i111ii1I = bold ( "does not exist" , False )
  lprint ( "Socket '{}' {}" . format ( OOOo0OOo0oOo0 , i111ii1I ) )
  return ( False )
  if 8 - 8: Oo0Ooo % O0 . II111iiii
 return ( True )
 if 45 - 45: i1IIi % ooOoO0o / oO0o + oO0o / OOooOOo - oO0o
 if 91 - 91: i1IIi . Oo0Ooo . i11iIiiIii % iIii1I11I1II1 * OOooOOo
 if 45 - 45: oO0o + i1IIi + iII111i + o0oOOo0O0Ooo * OOooOOo + ooOoO0o
 if 83 - 83: OoO0O00 - ooOoO0o / OoooooooOO % iIii1I11I1II1 - II111iiii
 if 73 - 73: Oo0Ooo + II111iiii - IiII
 if 60 - 60: i1IIi . i11iIiiIii / i1IIi . I11i % OOooOOo
 if 47 - 47: oO0o + IiII * I1Ii111 % o0oOOo0O0Ooo - O0 % IiII
def lisp_write_to_dp_socket ( entry ) :
 try :
  Oooo0O0ooOooO = json . dumps ( entry )
  I1iI11iII11 = bold ( "Write IPC" , False )
  lprint ( "{} record to named socket: '{}'" . format ( I1iI11iII11 , Oooo0O0ooOooO ) )
  lisp_ipc_dp_socket . sendto ( Oooo0O0ooOooO , lisp_ipc_dp_socket_name )
 except :
  lprint ( "Failed to write IPC record to named socket: '{}'" . format ( Oooo0O0ooOooO ) )
  if 56 - 56: Ii1I + i1IIi / II111iiii
 return
 if 54 - 54: O0 * IiII + i11iIiiIii - oO0o - ooOoO0o + i11iIiiIii
 if 87 - 87: I1ii11iIi11i * iIii1I11I1II1 / I1Ii111
 if 5 - 5: i1IIi * IiII / iIii1I11I1II1 * OoooooooOO . O0
 if 57 - 57: i11iIiiIii
 if 89 - 89: o0oOOo0O0Ooo . I1Ii111 * I11i + oO0o - OoooooooOO + OoO0O00
 if 25 - 25: i1IIi * I1Ii111 * iII111i . OoooooooOO
 if 70 - 70: iIii1I11I1II1
 if 1 - 1: II111iiii . I1IiiI + o0oOOo0O0Ooo
 if 5 - 5: I1ii11iIi11i % I11i - II111iiii
def lisp_write_ipc_keys ( rloc ) :
 OoOOoooO000 = rloc . rloc . print_address_no_iid ( )
 i1O0OO = rloc . translated_port
 if ( i1O0OO != 0 ) : OoOOoooO000 += ":" + str ( i1O0OO )
 if ( lisp_rloc_probe_list . has_key ( OoOOoooO000 ) == False ) : return
 if 70 - 70: ooOoO0o - IiII - OoO0O00 / I11i
 for iI111I1 , I1i11II , OooooOOOO in lisp_rloc_probe_list [ OoOOoooO000 ] :
  oOooO0Oo0Oo0 = lisp_map_cache . lookup_cache ( I1i11II , True )
  if ( oOooO0Oo0Oo0 == None ) : continue
  lisp_write_ipc_map_cache ( True , oOooO0Oo0Oo0 )
  if 59 - 59: IiII % ooOoO0o . iII111i / Ii1I * Ii1I
 return
 if 73 - 73: I1ii11iIi11i . oO0o % I11i . I1ii11iIi11i / I1Ii111 / II111iiii
 if 23 - 23: OoooooooOO . o0oOOo0O0Ooo
 if 76 - 76: I1Ii111
 if 91 - 91: iIii1I11I1II1 / Ii1I . I1IiiI
 if 63 - 63: ooOoO0o . Ii1I - I1Ii111 - oO0o * I1Ii111 + ooOoO0o
 if 85 - 85: II111iiii + I1ii11iIi11i
 if 33 - 33: iII111i
def lisp_write_ipc_map_cache ( add_or_delete , mc , dont_send = False ) :
 if ( lisp_i_am_etr ) : return
 if ( lisp_ipc_dp_socket == None ) : return
 if ( lisp_check_dp_socket ( ) == False ) : return
 if 14 - 14: O0 * Oo0Ooo / i1IIi
 if 95 - 95: O0 % i1IIi % ooOoO0o % oO0o - I1IiiI
 if 78 - 78: II111iiii % OOooOOo
 if 6 - 6: OOooOOo
 I1Ii = "add" if add_or_delete else "delete"
 oOoO = { "type" : "map-cache" , "opcode" : I1Ii }
 if 21 - 21: I1Ii111 - Ii1I - i1IIi % oO0o
 iIIiI1iiIi = ( mc . group . is_null ( ) == False )
 if ( iIIiI1iiIi ) :
  oOoO [ "eid-prefix" ] = mc . group . print_prefix_no_iid ( )
  oOoO [ "rles" ] = [ ]
 else :
  oOoO [ "eid-prefix" ] = mc . eid . print_prefix_no_iid ( )
  oOoO [ "rlocs" ] = [ ]
  if 55 - 55: OOooOOo + oO0o - II111iiii
 oOoO [ "instance-id" ] = str ( mc . eid . instance_id )
 if 5 - 5: iII111i * OoooooooOO . OoO0O00 % ooOoO0o + Ii1I
 if ( iIIiI1iiIi ) :
  if ( len ( mc . rloc_set ) >= 1 and mc . rloc_set [ 0 ] . rle ) :
   for oOo0o in mc . rloc_set [ 0 ] . rle . rle_forwarding_list :
    I1Iii1I = oOo0o . address . print_address_no_iid ( )
    i1O0OO = str ( 4341 ) if oOo0o . translated_port == 0 else str ( oOo0o . translated_port )
    if 59 - 59: OoOoOO00
    iI111I1 = { "rle" : I1Iii1I , "port" : i1O0OO }
    III11i1iiii , ooooo = oOo0o . get_encap_keys ( )
    iI111I1 = lisp_build_json_keys ( iI111I1 , III11i1iiii , ooooo , "encrypt-key" )
    oOoO [ "rles" ] . append ( iI111I1 )
    if 68 - 68: ooOoO0o * O0
    if 1 - 1: I1ii11iIi11i
 else :
  for oOoOoo0O in mc . rloc_set :
   if ( oOoOoo0O . rloc . is_ipv4 ( ) == False and oOoOoo0O . rloc . is_ipv6 ( ) == False ) :
    continue
    if 85 - 85: I1ii11iIi11i
   if ( oOoOoo0O . up_state ( ) == False ) : continue
   if 6 - 6: IiII % ooOoO0o . IiII . I1Ii111 - iIii1I11I1II1 + iIii1I11I1II1
   i1O0OO = str ( 4341 ) if oOoOoo0O . translated_port == 0 else str ( oOoOoo0O . translated_port )
   if 30 - 30: OoooooooOO - ooOoO0o + Ii1I
   iI111I1 = { "rloc" : oOoOoo0O . rloc . print_address_no_iid ( ) , "priority" :
 str ( oOoOoo0O . priority ) , "weight" : str ( oOoOoo0O . weight ) , "port" :
 i1O0OO }
   III11i1iiii , ooooo = oOoOoo0O . get_encap_keys ( )
   iI111I1 = lisp_build_json_keys ( iI111I1 , III11i1iiii , ooooo , "encrypt-key" )
   oOoO [ "rlocs" ] . append ( iI111I1 )
   if 88 - 88: II111iiii / Oo0Ooo . Oo0Ooo % o0oOOo0O0Ooo * OoOoOO00 . I1ii11iIi11i
   if 32 - 32: OoooooooOO * I11i
   if 86 - 86: I1Ii111 - i1IIi % O0
 if ( dont_send == False ) : lisp_write_to_dp_socket ( oOoO )
 return ( oOoO )
 if 38 - 38: I1IiiI + OoO0O00 % iII111i / ooOoO0o
 if 93 - 93: OoOoOO00 . o0oOOo0O0Ooo - OoooooooOO
 if 90 - 90: iIii1I11I1II1 . Ii1I / i11iIiiIii . oO0o . I11i - I11i
 if 46 - 46: I11i
 if 2 - 2: I1Ii111 * oO0o
 if 93 - 93: I11i
 if 2 - 2: i1IIi / I1IiiI
def lisp_write_ipc_decap_key ( rloc_addr , keys ) :
 if ( lisp_i_am_itr ) : return
 if ( lisp_ipc_dp_socket == None ) : return
 if ( lisp_check_dp_socket ( ) == False ) : return
 if 29 - 29: Ii1I * iIii1I11I1II1 * i1IIi
 if 83 - 83: oO0o % O0 . I11i / I11i / I1IiiI - OoOoOO00
 if 91 - 91: iIii1I11I1II1 - IiII + iIii1I11I1II1 % Oo0Ooo % I1IiiI
 if 84 - 84: iIii1I11I1II1 . Oo0Ooo - OoooooooOO % Oo0Ooo
 if ( keys == None or len ( keys ) == 0 or keys [ 1 ] == None ) : return
 if 27 - 27: I1ii11iIi11i - ooOoO0o + I11i - I1ii11iIi11i
 III11i1iiii = keys [ 1 ] . encrypt_key
 ooooo = keys [ 1 ] . icv_key
 if 57 - 57: Oo0Ooo
 if 31 - 31: I1IiiI % Ii1I / OOooOOo + OoooooooOO . i11iIiiIii
 if 87 - 87: iII111i + IiII * I1ii11iIi11i . iII111i + Ii1I - II111iiii
 if 87 - 87: OoOoOO00 . o0oOOo0O0Ooo + I1ii11iIi11i
 oOOoo0O000OO = rloc_addr . split ( ":" )
 if ( len ( oOOoo0O000OO ) == 1 ) :
  oOoO = { "type" : "decap-keys" , "rloc" : oOOoo0O000OO [ 0 ] }
 else :
  oOoO = { "type" : "decap-keys" , "rloc" : oOOoo0O000OO [ 0 ] , "port" : oOOoo0O000OO [ 1 ] }
  if 79 - 79: Ii1I
 oOoO = lisp_build_json_keys ( oOoO , III11i1iiii , ooooo , "decrypt-key" )
 if 56 - 56: I1ii11iIi11i
 lisp_write_to_dp_socket ( oOoO )
 return
 if 40 - 40: OoooooooOO
 if 100 - 100: IiII - I11i
 if 79 - 79: iII111i % O0
 if 73 - 73: Oo0Ooo
 if 13 - 13: OOooOOo - ooOoO0o
 if 8 - 8: I1Ii111 % oO0o
 if 19 - 19: O0 + OoO0O00 - i1IIi % OoOoOO00 / Oo0Ooo + OoooooooOO
 if 93 - 93: i11iIiiIii % OOooOOo . I11i * ooOoO0o
def lisp_build_json_keys ( entry , ekey , ikey , key_type ) :
 if ( ekey == None ) : return ( entry )
 if 90 - 90: OoO0O00
 entry [ "keys" ] = [ ]
 iIIIi = { "key-id" : "1" , key_type : ekey , "icv-key" : ikey }
 entry [ "keys" ] . append ( iIIIi )
 return ( entry )
 if 54 - 54: OOooOOo + Oo0Ooo * o0oOOo0O0Ooo - iIii1I11I1II1 * ooOoO0o
 if 76 - 76: i11iIiiIii * I1IiiI - IiII . o0oOOo0O0Ooo % iII111i . i11iIiiIii
 if 69 - 69: O0 + o0oOOo0O0Ooo / ooOoO0o
 if 7 - 7: Ii1I . Ii1I . iIii1I11I1II1 / ooOoO0o
 if 70 - 70: O0
 if 42 - 42: I1Ii111 + OoooooooOO + I11i
 if 48 - 48: Oo0Ooo . IiII / ooOoO0o + I11i
def lisp_write_ipc_database_mappings ( ephem_port ) :
 if ( lisp_i_am_etr == False ) : return
 if ( lisp_ipc_dp_socket == None ) : return
 if ( lisp_check_dp_socket ( ) == False ) : return
 if 40 - 40: I1IiiI + I1ii11iIi11i * I1IiiI % Ii1I
 if 27 - 27: O0 / Oo0Ooo . oO0o
 if 34 - 34: I1Ii111 % Ii1I / Oo0Ooo % ooOoO0o / i11iIiiIii * I1IiiI
 if 36 - 36: i11iIiiIii * i1IIi % iII111i . Oo0Ooo
 oOoO = { "type" : "database-mappings" , "database-mappings" : [ ] }
 if 54 - 54: o0oOOo0O0Ooo % i1IIi % I1ii11iIi11i . o0oOOo0O0Ooo / OoOoOO00
 if 55 - 55: O0 / OoooooooOO % Ii1I * O0 + iIii1I11I1II1 . iIii1I11I1II1
 if 55 - 55: Ii1I . OoooooooOO % Ii1I . IiII
 if 67 - 67: oO0o
 for i1iOo in lisp_db_list :
  if ( i1iOo . eid . is_ipv4 ( ) == False and i1iOo . eid . is_ipv6 ( ) == False ) : continue
  iiiiII = { "instance-id" : str ( i1iOo . eid . instance_id ) ,
 "eid-prefix" : i1iOo . eid . print_prefix_no_iid ( ) }
  oOoO [ "database-mappings" ] . append ( iiiiII )
  if 12 - 12: I1IiiI
 lisp_write_to_dp_socket ( oOoO )
 if 50 - 50: ooOoO0o
 if 19 - 19: OoooooooOO / IiII
 if 40 - 40: OoOoOO00 / OoooooooOO * iIii1I11I1II1 / i1IIi . OoooooooOO
 if 88 - 88: I1IiiI % I1IiiI / II111iiii - IiII
 if 72 - 72: OoO0O00 - I1ii11iIi11i . Oo0Ooo / OoO0O00
 oOoO = { "type" : "etr-nat-port" , "port" : ephem_port }
 lisp_write_to_dp_socket ( oOoO )
 return
 if 86 - 86: i11iIiiIii - oO0o . i11iIiiIii
 if 51 - 51: OoO0O00 - OoO0O00 * IiII
 if 24 - 24: OoooooooOO . II111iiii
 if 97 - 97: II111iiii . O0
 if 18 - 18: iII111i
 if 35 - 35: ooOoO0o / O0 / iIii1I11I1II1 - iIii1I11I1II1 + I11i
 if 8 - 8: I1Ii111 . oO0o % Oo0Ooo * OoooooooOO
def lisp_write_ipc_interfaces ( ) :
 if ( lisp_i_am_etr ) : return
 if ( lisp_ipc_dp_socket == None ) : return
 if ( lisp_check_dp_socket ( ) == False ) : return
 if 25 - 25: OoO0O00
 if 54 - 54: O0
 if 20 - 20: ooOoO0o + Oo0Ooo - Oo0Ooo
 if 2 - 2: i1IIi - IiII . I1ii11iIi11i / i1IIi
 oOoO = { "type" : "interfaces" , "interfaces" : [ ] }
 if 92 - 92: ooOoO0o - iII111i
 for iIiiiIiIi in lisp_myinterfaces . values ( ) :
  if ( iIiiiIiIi . instance_id == None ) : continue
  iiiiII = { "interface" : iIiiiIiIi . device ,
 "instance-id" : str ( iIiiiIiIi . instance_id ) }
  oOoO [ "interfaces" ] . append ( iiiiII )
  if 69 - 69: iII111i
  if 48 - 48: O0 + o0oOOo0O0Ooo . oO0o - IiII * OoooooooOO . OoO0O00
 lisp_write_to_dp_socket ( oOoO )
 return
 if 63 - 63: oO0o * OoO0O00 * oO0o
 if 31 - 31: Oo0Ooo
 if 90 - 90: I11i . IiII * iIii1I11I1II1 . I11i + i1IIi
 if 67 - 67: I1Ii111 . I1ii11iIi11i
 if 2 - 2: O0 + I1Ii111
 if 82 - 82: Ii1I / iII111i
 if 13 - 13: I11i + iII111i
 if 54 - 54: I1ii11iIi11i - I1IiiI . Ii1I
 if 59 - 59: Oo0Ooo + I1ii11iIi11i
 if 87 - 87: ooOoO0o * OoooooooOO + OoO0O00 + oO0o - I1Ii111
 if 70 - 70: i1IIi . Ii1I / Ii1I
 if 9 - 9: iII111i + I1Ii111 + iII111i % ooOoO0o + i11iIiiIii + i11iIiiIii
 if 45 - 45: i1IIi + I1ii11iIi11i
 if 49 - 49: i11iIiiIii . I1ii11iIi11i
def lisp_parse_auth_key ( value ) :
 III1iii1i = value . split ( "[" )
 O0O000Ooo = { }
 if ( len ( III1iii1i ) == 1 ) :
  O0O000Ooo [ 0 ] = value
  return ( O0O000Ooo )
  if 26 - 26: Oo0Ooo / I11i * i1IIi
  if 7 - 7: I1ii11iIi11i . i11iIiiIii - oO0o + Ii1I
 for I1IIi in III1iii1i :
  if ( I1IIi == "" ) : continue
  OOOoO000 = I1IIi . find ( "]" )
  oO0O0oo = I1IIi [ 0 : OOOoO000 ]
  try : oO0O0oo = int ( oO0O0oo )
  except : return
  if 52 - 52: iIii1I11I1II1 - O0 - i1IIi + o0oOOo0O0Ooo * OOooOOo . O0
  O0O000Ooo [ oO0O0oo ] = I1IIi [ OOOoO000 + 1 : : ]
  if 76 - 76: Ii1I / oO0o . I1Ii111
 return ( O0O000Ooo )
 if 94 - 94: o0oOOo0O0Ooo - OoOoOO00 / I1Ii111
 if 99 - 99: O0 % oO0o % OOooOOo - Oo0Ooo
 if 45 - 45: I1ii11iIi11i * O0 * O0 - ooOoO0o
 if 6 - 6: Oo0Ooo * I1ii11iIi11i
 if 11 - 11: OoOoOO00 * OOooOOo % o0oOOo0O0Ooo / I1ii11iIi11i . o0oOOo0O0Ooo
 if 23 - 23: iIii1I11I1II1 + OOooOOo
 if 74 - 74: oO0o - I11i . i11iIiiIii / iIii1I11I1II1 . I11i
 if 73 - 73: OoO0O00 % iIii1I11I1II1 + IiII * I1Ii111 % II111iiii
 if 20 - 20: I11i % I1ii11iIi11i . OoO0O00 % OoOoOO00
 if 84 - 84: OoooooooOO / i11iIiiIii . IiII / I1IiiI
 if 62 - 62: iII111i - I1IiiI + OoooooooOO
 if 59 - 59: iIii1I11I1II1 + i11iIiiIii * oO0o . Oo0Ooo . I1Ii111
 if 49 - 49: II111iiii
 if 99 - 99: Oo0Ooo . OOooOOo
 if 85 - 85: OoOoOO00 . IiII + oO0o - II111iiii
 if 70 - 70: O0 % I1Ii111
def lisp_reassemble ( packet ) :
 II1i1I1111I1I = socket . ntohs ( struct . unpack ( "H" , packet [ 6 : 8 ] ) [ 0 ] )
 if 13 - 13: I1ii11iIi11i % OoO0O00 / Ii1I * IiII
 if 82 - 82: ooOoO0o % Oo0Ooo
 if 26 - 26: OoO0O00 + i11iIiiIii % I11i . I1ii11iIi11i
 if 76 - 76: i1IIi + ooOoO0o - Oo0Ooo + OoOoOO00 / I1ii11iIi11i . OOooOOo
 if ( II1i1I1111I1I == 0 or II1i1I1111I1I == 0x4000 ) : return ( packet )
 if 50 - 50: IiII - Ii1I % iIii1I11I1II1
 if 60 - 60: o0oOOo0O0Ooo - Oo0Ooo
 if 92 - 92: OoOoOO00 + IiII . OoO0O00 % iII111i / II111iiii / I11i
 if 62 - 62: I1ii11iIi11i
 OO000OOOo0Oo = socket . ntohs ( struct . unpack ( "H" , packet [ 4 : 6 ] ) [ 0 ] )
 O0o00oO = socket . ntohs ( struct . unpack ( "H" , packet [ 2 : 4 ] ) [ 0 ] )
 if 61 - 61: I1IiiI
 iI1IiIii1II1 = ( II1i1I1111I1I & 0x2000 == 0 and ( II1i1I1111I1I & 0x1fff ) != 0 )
 oOoO = [ ( II1i1I1111I1I & 0x1fff ) * 8 , O0o00oO - 20 , packet , iI1IiIii1II1 ]
 if 90 - 90: o0oOOo0O0Ooo % Ii1I + Ii1I * OoooooooOO
 if 13 - 13: oO0o - OOooOOo % ooOoO0o % OoooooooOO
 if 95 - 95: I1ii11iIi11i * Oo0Ooo - OoooooooOO * oO0o - O0 - I11i
 if 3 - 3: Ii1I % IiII
 if 84 - 84: II111iiii . Ii1I
 if 70 - 70: i1IIi
 if 52 - 52: OoooooooOO % oO0o - I11i % OoOoOO00 . II111iiii
 if 62 - 62: Ii1I . I1ii11iIi11i . iII111i + I11i * o0oOOo0O0Ooo
 if ( II1i1I1111I1I == 0x2000 ) :
  i1IiiI , O0OOO0 = struct . unpack ( "HH" , packet [ 20 : 24 ] )
  i1IiiI = socket . ntohs ( i1IiiI )
  O0OOO0 = socket . ntohs ( O0OOO0 )
  if ( O0OOO0 not in [ 4341 , 8472 , 4789 ] and i1IiiI != 4341 ) :
   lisp_reassembly_queue [ OO000OOOo0Oo ] = [ ]
   oOoO [ 2 ] = None
   if 56 - 56: oO0o * iIii1I11I1II1 . II111iiii - II111iiii + II111iiii - i11iIiiIii
   if 79 - 79: iII111i
   if 29 - 29: Ii1I * I1Ii111 / OoO0O00 - O0 - i11iIiiIii * I1IiiI
   if 2 - 2: OoOoOO00 . I1ii11iIi11i * I1ii11iIi11i
   if 42 - 42: OoO0O00 . OoO0O00 + II111iiii - IiII - OOooOOo * Oo0Ooo
   if 47 - 47: oO0o - OoooooooOO + iII111i
 if ( lisp_reassembly_queue . has_key ( OO000OOOo0Oo ) == False ) :
  lisp_reassembly_queue [ OO000OOOo0Oo ] = [ ]
  if 69 - 69: I1ii11iIi11i - I1IiiI % oO0o + OOooOOo - I1Ii111
  if 5 - 5: ooOoO0o . OoO0O00
  if 40 - 40: iII111i
  if 87 - 87: IiII / II111iiii
  if 44 - 44: OoO0O00 . I1Ii111 - OoooooooOO * OoOoOO00 . OoO0O00
 O0oO00OOooo0 = lisp_reassembly_queue [ OO000OOOo0Oo ]
 if 23 - 23: i1IIi . iIii1I11I1II1 / I1IiiI . OoOoOO00 . iII111i / IiII
 if 65 - 65: Ii1I + IiII + I11i / I1Ii111 % iIii1I11I1II1
 if 17 - 17: I1ii11iIi11i * OOooOOo % II111iiii
 if 30 - 30: I1Ii111 . Ii1I . Oo0Ooo / OOooOOo * OoooooooOO / I1ii11iIi11i
 if 41 - 41: i1IIi
 if ( len ( O0oO00OOooo0 ) == 1 and O0oO00OOooo0 [ 0 ] [ 2 ] == None ) :
  dprint ( "Drop non-LISP encapsulated fragment 0x{}" . format ( lisp_hex_string ( OO000OOOo0Oo ) . zfill ( 4 ) ) )
  if 75 - 75: o0oOOo0O0Ooo . I1Ii111 - I1Ii111 % Ii1I * OoooooooOO
  return ( None )
  if 99 - 99: OOooOOo + o0oOOo0O0Ooo - OOooOOo . i1IIi
  if 86 - 86: Ii1I % oO0o - i11iIiiIii - O0 + IiII + iII111i
  if 100 - 100: OoO0O00 . Oo0Ooo
  if 29 - 29: OoO0O00
  if 34 - 34: O0 - o0oOOo0O0Ooo % OOooOOo . OoO0O00 % IiII
 O0oO00OOooo0 . append ( oOoO )
 O0oO00OOooo0 = sorted ( O0oO00OOooo0 )
 if 63 - 63: O0 % iIii1I11I1II1 . o0oOOo0O0Ooo . I1IiiI * Ii1I % i1IIi
 if 47 - 47: II111iiii * I1ii11iIi11i
 if 70 - 70: I1ii11iIi11i - o0oOOo0O0Ooo
 if 71 - 71: I1ii11iIi11i * i1IIi
 I1Iii1I = lisp_address ( LISP_AFI_IPV4 , "" , 32 , 0 )
 I1Iii1I . address = socket . ntohl ( struct . unpack ( "I" , packet [ 12 : 16 ] ) [ 0 ] )
 OOoOo0o0oO = I1Iii1I . print_address_no_iid ( )
 I1Iii1I . address = socket . ntohl ( struct . unpack ( "I" , packet [ 16 : 20 ] ) [ 0 ] )
 ooo0OOOOo000 = I1Iii1I . print_address_no_iid ( )
 I1Iii1I = red ( "{} -> {}" . format ( OOoOo0o0oO , ooo0OOOOo000 ) , False )
 if 49 - 49: iII111i % iII111i . II111iiii - I1IiiI / O0
 dprint ( "{}{} fragment, RLOCs: {}, packet 0x{}, frag-offset: 0x{}" . format ( bold ( "Received" , False ) , " non-LISP encapsulated" if oOoO [ 2 ] == None else "" , I1Iii1I , lisp_hex_string ( OO000OOOo0Oo ) . zfill ( 4 ) ,
 # OoO0O00 % iII111i - OOooOOo / Oo0Ooo * iII111i
 # Oo0Ooo % Oo0Ooo / OoOoOO00 - I1IiiI - i11iIiiIii
 lisp_hex_string ( II1i1I1111I1I ) . zfill ( 4 ) ) )
 if 82 - 82: O0 / oO0o - I1IiiI . oO0o % oO0o / OOooOOo
 if 20 - 20: OoOoOO00 / I1Ii111 + I1ii11iIi11i
 if 36 - 36: I1ii11iIi11i % OoO0O00 + I11i / iII111i % OOooOOo
 if 5 - 5: oO0o % OOooOOo
 if 95 - 95: OoOoOO00 + OoooooooOO - O0 + o0oOOo0O0Ooo
 if ( O0oO00OOooo0 [ 0 ] [ 0 ] != 0 or O0oO00OOooo0 [ - 1 ] [ 3 ] == False ) : return ( None )
 ooI11i1 = O0oO00OOooo0 [ 0 ]
 for Ooo in O0oO00OOooo0 [ 1 : : ] :
  II1i1I1111I1I = Ooo [ 0 ]
  Oo0o00oOoOO , OOO0oO0 = ooI11i1 [ 0 ] , ooI11i1 [ 1 ]
  if ( Oo0o00oOoOO + OOO0oO0 != II1i1I1111I1I ) : return ( None )
  ooI11i1 = Ooo
  if 69 - 69: iII111i * IiII / i11iIiiIii . I1Ii111 / OoO0O00 - I1Ii111
 lisp_reassembly_queue . pop ( OO000OOOo0Oo )
 if 42 - 42: Ii1I
 if 42 - 42: I11i / Ii1I / Oo0Ooo - I1IiiI - I11i - i11iIiiIii
 if 45 - 45: ooOoO0o - IiII / OoO0O00 / IiII
 if 63 - 63: ooOoO0o . i11iIiiIii + iII111i . OoO0O00 / ooOoO0o % iII111i
 if 23 - 23: iIii1I11I1II1 - ooOoO0o / I11i * I11i
 packet = O0oO00OOooo0 [ 0 ] [ 2 ]
 for Ooo in O0oO00OOooo0 [ 1 : : ] : packet += Ooo [ 2 ] [ 20 : : ]
 if 62 - 62: OOooOOo - I1IiiI * oO0o + O0 / ooOoO0o * iIii1I11I1II1
 dprint ( "{} fragments arrived for packet 0x{}, length {}" . format ( bold ( "All" , False ) , lisp_hex_string ( OO000OOOo0Oo ) . zfill ( 4 ) , len ( packet ) ) )
 if 25 - 25: I1Ii111 % Oo0Ooo + OoO0O00 % OOooOOo
 if 85 - 85: I1IiiI . i11iIiiIii - ooOoO0o * I11i * OoOoOO00 * I11i
 if 29 - 29: I1Ii111 * I1Ii111 . iII111i + o0oOOo0O0Ooo
 if 57 - 57: I1Ii111 - IiII
 if 89 - 89: oO0o + iII111i
 I111 = socket . htons ( len ( packet ) )
 III1Iiii1i11 = packet [ 0 : 2 ] + struct . pack ( "H" , I111 ) + packet [ 4 : 6 ] + struct . pack ( "H" , 0 ) + packet [ 8 : 10 ] + struct . pack ( "H" , 0 ) + packet [ 12 : 20 ]
 if 52 - 52: OOooOOo % O0 * I1ii11iIi11i . I1ii11iIi11i / IiII
 if 7 - 7: II111iiii
 III1Iiii1i11 = lisp_ip_checksum ( III1Iiii1i11 )
 return ( III1Iiii1i11 + packet [ 20 : : ] )
 if 7 - 7: iIii1I11I1II1 . O0 + Ii1I % I1IiiI * O0 + OoO0O00
 if 3 - 3: Oo0Ooo * OoooooooOO * oO0o % OoOoOO00 * OoOoOO00 . ooOoO0o
 if 16 - 16: ooOoO0o / o0oOOo0O0Ooo - O0 * I1IiiI
 if 13 - 13: iII111i . iII111i % O0 % o0oOOo0O0Ooo
 if 99 - 99: OoO0O00 - OoOoOO00 + OoO0O00
 if 67 - 67: I1Ii111
 if 31 - 31: OoO0O00 * Oo0Ooo % O0 * II111iiii + ooOoO0o * I1IiiI
 if 77 - 77: ooOoO0o
def lisp_get_crypto_decap_lookup_key ( addr , port ) :
 OoOOoooO000 = addr . print_address_no_iid ( ) + ":" + str ( port )
 if ( lisp_crypto_keys_by_rloc_decap . has_key ( OoOOoooO000 ) ) : return ( OoOOoooO000 )
 if 98 - 98: I1Ii111 + I1ii11iIi11i % OoO0O00 * Ii1I + iII111i
 OoOOoooO000 = addr . print_address_no_iid ( )
 if ( lisp_crypto_keys_by_rloc_decap . has_key ( OoOOoooO000 ) ) : return ( OoOOoooO000 )
 if 6 - 6: iII111i / iII111i . i11iIiiIii
 if 12 - 12: I11i - OoO0O00
 if 68 - 68: IiII - OoOoOO00
 if 22 - 22: i1IIi . IiII
 if 8 - 8: IiII % o0oOOo0O0Ooo . i11iIiiIii
 for o0O00 in lisp_crypto_keys_by_rloc_decap :
  OOOO0o = o0O00 . split ( ":" )
  if ( len ( OOOO0o ) == 1 ) : continue
  OOOO0o = OOOO0o [ 0 ] if len ( OOOO0o ) == 2 else ":" . join ( OOOO0o [ 0 : - 1 ] )
  if ( OOOO0o == OoOOoooO000 ) :
   O000OO = lisp_crypto_keys_by_rloc_decap [ o0O00 ]
   lisp_crypto_keys_by_rloc_decap [ OoOOoooO000 ] = O000OO
   return ( OoOOoooO000 )
   if 38 - 38: II111iiii % OoooooooOO / OoooooooOO . Ii1I . Ii1I
   if 13 - 13: oO0o - i1IIi / i1IIi + OoooooooOO
 return ( None )
 if 57 - 57: OoooooooOO / O0 + I1ii11iIi11i % I11i * oO0o / Ii1I
 if 49 - 49: I1IiiI * ooOoO0o * OOooOOo + OoO0O00 + ooOoO0o
 if 42 - 42: i1IIi . OoO0O00 % iII111i
 if 57 - 57: I1ii11iIi11i / I1IiiI
 if 69 - 69: iII111i - iII111i . OoO0O00 / oO0o - OoO0O00 + I1Ii111
 if 98 - 98: iII111i . oO0o - O0 % I1IiiI . I1ii11iIi11i / i1IIi
 if 72 - 72: I1IiiI / Oo0Ooo % IiII - O0 / O0 * O0
 if 83 - 83: O0 / I1Ii111 - OoooooooOO
 if 42 - 42: Ii1I / i1IIi - IiII / I1Ii111
 if 39 - 39: OoooooooOO
 if 4 - 4: iIii1I11I1II1 - Oo0Ooo / OOooOOo % OoooooooOO . Oo0Ooo - Oo0Ooo
def lisp_build_crypto_decap_lookup_key ( addr , port ) :
 addr = addr . print_address_no_iid ( )
 iiOO0OoOo00O0o = addr + ":" + str ( port )
 if 71 - 71: ooOoO0o * I1Ii111 + i11iIiiIii + i1IIi . I1IiiI
 if ( lisp_i_am_rtr ) :
  if ( lisp_rloc_probe_list . has_key ( addr ) ) : return ( addr )
  if 15 - 15: OoO0O00
  if 37 - 37: OoO0O00 . OoooooooOO - OOooOOo
  if 34 - 34: o0oOOo0O0Ooo + iIii1I11I1II1 / o0oOOo0O0Ooo / ooOoO0o
  if 53 - 53: II111iiii / iIii1I11I1II1
  if 25 - 25: I1Ii111
  if 58 - 58: OoOoOO00 * i1IIi
  for o0oO00ooo0o in lisp_nat_state_info . values ( ) :
   for iiIiIIi1I in o0oO00ooo0o :
    if ( addr == iiIiIIi1I . address ) : return ( iiOO0OoOo00O0o )
    if 20 - 20: IiII
    if 81 - 81: I1Ii111 . i1IIi / o0oOOo0O0Ooo
  return ( addr )
  if 30 - 30: i11iIiiIii . I1IiiI
 return ( iiOO0OoOo00O0o )
 if 5 - 5: Ii1I / O0 + iIii1I11I1II1
 if 22 - 22: ooOoO0o . ooOoO0o * OOooOOo % OoOoOO00
 if 51 - 51: OoOoOO00 . oO0o - OoOoOO00
 if 79 - 79: iII111i
 if 71 - 71: i1IIi / OoO0O00 / OOooOOo + I1Ii111
 if 80 - 80: Oo0Ooo . iIii1I11I1II1 . OoooooooOO % iII111i . oO0o
 if 10 - 10: i11iIiiIii * OoooooooOO . i11iIiiIii
def lisp_set_ttl ( lisp_socket , ttl ) :
 try :
  lisp_socket . setsockopt ( socket . SOL_IP , socket . IP_TTL , ttl )
 except :
  lprint ( "socket.setsockopt(IP_TTL) not supported" )
  pass
  if 35 - 35: OOooOOo * OOooOOo + o0oOOo0O0Ooo / i1IIi - I11i
 return
 if 12 - 12: I1ii11iIi11i - i11iIiiIii + I1IiiI . Oo0Ooo
 if 26 - 26: oO0o + I1Ii111 + IiII * o0oOOo0O0Ooo . oO0o
 if 95 - 95: OoOoOO00 . I1Ii111 / Ii1I . I1Ii111 % OoO0O00
 if 16 - 16: Ii1I / I1IiiI / I1IiiI - OoooooooOO
 if 13 - 13: OOooOOo / OoooooooOO
 if 7 - 7: II111iiii - ooOoO0o
 if 72 - 72: Ii1I
def lisp_is_rloc_probe_request ( lisp_type ) :
 lisp_type = struct . unpack ( "B" , lisp_type ) [ 0 ]
 return ( lisp_type == 0x12 )
 if 27 - 27: ooOoO0o / IiII + OoO0O00 + Ii1I % I1Ii111
 if 86 - 86: O0 % i11iIiiIii - Ii1I * oO0o % OOooOOo * i1IIi
 if 87 - 87: II111iiii
 if 53 - 53: OoOoOO00 * i11iIiiIii / I1Ii111
 if 100 - 100: ooOoO0o + I1IiiI * oO0o + ooOoO0o
 if 24 - 24: i11iIiiIii + ooOoO0o
 if 80 - 80: IiII % I11i % oO0o
def lisp_is_rloc_probe_reply ( lisp_type ) :
 lisp_type = struct . unpack ( "B" , lisp_type ) [ 0 ]
 return ( lisp_type == 0x28 )
 if 97 - 97: i1IIi * i11iIiiIii / Ii1I - I1IiiI % IiII
 if 70 - 70: iIii1I11I1II1
 if 2 - 2: IiII - i1IIi * IiII % O0 / Ii1I
 if 64 - 64: iII111i - Oo0Ooo
 if 73 - 73: iIii1I11I1II1 * I1Ii111 * OoO0O00
 if 68 - 68: ooOoO0o * Ii1I / I1ii11iIi11i * OoooooooOO + OoooooooOO . OoooooooOO
 if 50 - 50: I1IiiI % o0oOOo0O0Ooo
 if 1 - 1: II111iiii
 if 22 - 22: I1Ii111 + iII111i
 if 50 - 50: iII111i % OoOoOO00 - II111iiii + II111iiii / OoO0O00
 if 69 - 69: Ii1I * II111iiii
 if 24 - 24: I1Ii111 * I1ii11iIi11i . OOooOOo . I1IiiI - I1ii11iIi11i
 if 56 - 56: I1IiiI * Oo0Ooo + OoO0O00 - oO0o * I1Ii111
 if 68 - 68: ooOoO0o * i11iIiiIii * OOooOOo % iII111i
 if 10 - 10: Ii1I / Oo0Ooo - i1IIi
 if 11 - 11: I11i * iII111i
 if 28 - 28: II111iiii + IiII / Oo0Ooo * I1IiiI - OOooOOo
 if 2 - 2: oO0o + I11i / I1Ii111 . I11i
 if 59 - 59: Ii1I
def lisp_is_rloc_probe ( packet , rr ) :
 IIi1ii1 = ( struct . unpack ( "B" , packet [ 9 ] ) [ 0 ] == 17 )
 if ( IIi1ii1 == False ) : return ( [ packet , None , None , None ] )
 if 47 - 47: iII111i % iII111i
 if ( rr == 0 ) :
  o0ooOOoO0O = lisp_is_rloc_probe_request ( packet [ 28 ] )
  if ( o0ooOOoO0O == False ) : return ( [ packet , None , None , None ] )
 elif ( rr == 1 ) :
  o0ooOOoO0O = lisp_is_rloc_probe_reply ( packet [ 28 ] )
  if ( o0ooOOoO0O == False ) : return ( [ packet , None , None , None ] )
 elif ( rr == - 1 ) :
  o0ooOOoO0O = lisp_is_rloc_probe_request ( packet [ 28 ] )
  if ( o0ooOOoO0O == False ) :
   o0ooOOoO0O = lisp_is_rloc_probe_reply ( packet [ 28 ] )
   if ( o0ooOOoO0O == False ) : return ( [ packet , None , None , None ] )
   if 81 - 81: oO0o / I1ii11iIi11i . OoooooooOO % II111iiii / oO0o
   if 23 - 23: IiII + oO0o + o0oOOo0O0Ooo . I1ii11iIi11i / i11iIiiIii + iIii1I11I1II1
   if 74 - 74: I11i % OOooOOo
   if 57 - 57: O0 + I1IiiI + i11iIiiIii
   if 90 - 90: I1ii11iIi11i . OoO0O00 * iIii1I11I1II1 - Oo0Ooo
   if 28 - 28: I1IiiI . ooOoO0o - ooOoO0o * OOooOOo . IiII
 O00oo0o0o0oo = lisp_address ( LISP_AFI_IPV4 , "" , 32 , 0 )
 O00oo0o0o0oo . address = socket . ntohl ( struct . unpack ( "I" , packet [ 12 : 16 ] ) [ 0 ] )
 if 16 - 16: iIii1I11I1II1 % i11iIiiIii / Ii1I % iIii1I11I1II1 / iII111i
 if 27 - 27: II111iiii * OoooooooOO / Oo0Ooo % O0
 if 41 - 41: oO0o / iIii1I11I1II1 % iII111i - I1Ii111 % I11i * i11iIiiIii
 if 21 - 21: O0
 if ( O00oo0o0o0oo . is_local ( ) ) : return ( [ None , None , None , None ] )
 if 14 - 14: IiII / I1ii11iIi11i + Ii1I
 if 48 - 48: I1Ii111 * oO0o / o0oOOo0O0Ooo * OoOoOO00 * ooOoO0o
 if 38 - 38: I1IiiI * Ii1I + Oo0Ooo - OoooooooOO
 if 63 - 63: I1ii11iIi11i
 O00oo0o0o0oo = O00oo0o0o0oo . print_address_no_iid ( )
 i1O0OO = socket . ntohs ( struct . unpack ( "H" , packet [ 20 : 22 ] ) [ 0 ] )
 ooOOooooo0Oo = struct . unpack ( "B" , packet [ 8 ] ) [ 0 ] - 1
 packet = packet [ 28 : : ]
 if 99 - 99: I1Ii111 % oO0o - II111iiii . ooOoO0o
 iI111I1 = bold ( "Receive(pcap)" , False )
 Ii11111i1 = bold ( "from " + O00oo0o0o0oo , False )
 oo000o = lisp_format_packet ( packet )
 lprint ( "{} {} bytes {} {}, packet: {}" . format ( iI111I1 , len ( packet ) , Ii11111i1 , i1O0OO , oo000o ) )
 if 26 - 26: I1ii11iIi11i * iII111i . OoooooooOO - Oo0Ooo - IiII
 return ( [ packet , O00oo0o0o0oo , i1O0OO , ooOOooooo0Oo ] )
 if 6 - 6: OOooOOo - I1IiiI . IiII
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
def lisp_ipc_write_xtr_parameters ( cp , dp ) :
 if ( lisp_ipc_dp_socket == None ) : return
 if 1 - 1: IiII + iIii1I11I1II1 * I1ii11iIi11i - IiII - i1IIi
 OOOO0OoO0oOOoo0 = { "type" : "xtr-parameters" , "control-plane-logging" : cp ,
 "data-plane-logging" : dp , "rtr" : lisp_i_am_rtr }
 if 75 - 75: II111iiii * o0oOOo0O0Ooo / I1ii11iIi11i
 lisp_write_to_dp_socket ( OOOO0OoO0oOOoo0 )
 return
 if 46 - 46: OOooOOo
 if 67 - 67: OoO0O00 . I11i % OOooOOo + Oo0Ooo
 if 40 - 40: OoO0O00 / I11i % iIii1I11I1II1 - ooOoO0o
 if 51 - 51: Oo0Ooo % iIii1I11I1II1 % oO0o + o0oOOo0O0Ooo
 if 32 - 32: I1Ii111 * I1IiiI + Ii1I
 if 30 - 30: OoooooooOO / I1IiiI . iIii1I11I1II1 / ooOoO0o
 if 20 - 20: OoooooooOO * OOooOOo
 if 77 - 77: Ii1I - OoooooooOO . OoOoOO00
def lisp_external_data_plane ( ) :
 iIiI1 = 'egrep "ipc-data-plane = yes" ./lisp.config'
 if ( commands . getoutput ( iIiI1 ) != "" ) : return ( True )
 if 93 - 93: OoooooooOO / I1Ii111
 if ( os . getenv ( "LISP_RUN_LISP_XTR" ) != None ) : return ( True )
 return ( False )
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
def lisp_process_data_plane_restart ( do_clear = False ) :
 os . system ( "touch ./lisp.config" )
 if 95 - 95: OoOoOO00 * iIii1I11I1II1 / OoooooooOO % i1IIi
 o0OO0oo00 = { "type" : "entire-map-cache" , "entries" : [ ] }
 if 97 - 97: oO0o % iII111i
 if ( do_clear == False ) :
  II1ooOOoOoOo = o0OO0oo00 [ "entries" ]
  lisp_map_cache . walk_cache ( lisp_ipc_walk_map_cache , II1ooOOoOoOo )
  if 43 - 43: OoOoOO00 % Ii1I * II111iiii * i1IIi / O0
  if 64 - 64: I1Ii111 + O0 * IiII % OoOoOO00 % OOooOOo - iII111i
 lisp_write_to_dp_socket ( o0OO0oo00 )
 return
 if 73 - 73: ooOoO0o + I1IiiI % oO0o . O0
 if 18 - 18: o0oOOo0O0Ooo * I11i
 if 24 - 24: oO0o / o0oOOo0O0Ooo + i1IIi
 if 15 - 15: i11iIiiIii / O0
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
def lisp_process_data_plane_stats ( msg , lisp_sockets , lisp_port ) :
 if ( msg . has_key ( "entries" ) == False ) :
  lprint ( "No 'entries' in stats IPC message" )
  return
  if 73 - 73: II111iiii % i11iIiiIii * I1ii11iIi11i + O0
 if ( type ( msg [ "entries" ] ) != list ) :
  lprint ( "'entries' in stats IPC message must be an array" )
  return
  if 61 - 61: I1IiiI / OOooOOo
  if 67 - 67: OoOoOO00
 for msg in msg [ "entries" ] :
  if ( msg . has_key ( "eid-prefix" ) == False ) :
   lprint ( "No 'eid-prefix' in stats IPC message" )
   continue
   if 22 - 22: Ii1I * I1ii11iIi11i * o0oOOo0O0Ooo - I1IiiI . i11iIiiIii
  oo0ooooO = msg [ "eid-prefix" ]
  if 30 - 30: O0 / oO0o * i11iIiiIii + iIii1I11I1II1 + O0 % I1IiiI
  if ( msg . has_key ( "instance-id" ) == False ) :
   lprint ( "No 'instance-id' in stats IPC message" )
   continue
   if 95 - 95: ooOoO0o % OOooOOo
  IIiI1i = int ( msg [ "instance-id" ] )
  if 17 - 17: i1IIi + Ii1I
  if 35 - 35: iIii1I11I1II1 - Oo0Ooo - OoooooooOO % I1ii11iIi11i
  if 27 - 27: Oo0Ooo * II111iiii - OOooOOo + o0oOOo0O0Ooo
  if 26 - 26: oO0o / I1ii11iIi11i - oO0o
  Ooo0 = lisp_address ( LISP_AFI_NONE , "" , 0 , IIiI1i )
  Ooo0 . store_prefix ( oo0ooooO )
  oOooO0Oo0Oo0 = lisp_map_cache_lookup ( None , Ooo0 )
  if ( oOooO0Oo0Oo0 == None ) :
   lprint ( "Map-cache entry for {} not found for stats update" . format ( oo0ooooO ) )
   if 9 - 9: ooOoO0o * iIii1I11I1II1 * OoooooooOO
   continue
   if 13 - 13: iII111i . i11iIiiIii * o0oOOo0O0Ooo . iII111i
   if 96 - 96: Ii1I
  if ( msg . has_key ( "rlocs" ) == False ) :
   lprint ( "No 'rlocs' in stats IPC message for {}" . format ( oo0ooooO ) )
   if 90 - 90: II111iiii
   continue
   if 93 - 93: i11iIiiIii / Ii1I * Oo0Ooo . iII111i % iII111i / IiII
  if ( type ( msg [ "rlocs" ] ) != list ) :
   lprint ( "'rlocs' in stats IPC message must be an array" )
   continue
   if 15 - 15: OoOoOO00 % I1Ii111 - iIii1I11I1II1
  oo0oOoooOooO0 = msg [ "rlocs" ]
  if 13 - 13: OOooOOo + II111iiii + I11i + ooOoO0o % Oo0Ooo / iII111i
  if 9 - 9: O0 + IiII
  if 69 - 69: I1IiiI
  if 11 - 11: I11i % I1Ii111 + O0 . Ii1I . I1ii11iIi11i % I1Ii111
  for I1IOoOO0000OOoO in oo0oOoooOooO0 :
   if ( I1IOoOO0000OOoO . has_key ( "rloc" ) == False ) : continue
   if 80 - 80: IiII % I1Ii111
   Oo0oO = I1IOoOO0000OOoO [ "rloc" ]
   if ( Oo0oO == "no-address" ) : continue
   if 86 - 86: I1IiiI
   oOoOoo0O = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
   oOoOoo0O . store_address ( Oo0oO )
   if 76 - 76: OOooOOo + OoOoOO00
   iIIiIiiI = oOooO0Oo0Oo0 . get_rloc ( oOoOoo0O )
   if ( iIIiIiiI == None ) : continue
   if 100 - 100: I11i . II111iiii + IiII . I11i . OoooooooOO
   if 16 - 16: i1IIi + OoOoOO00 / oO0o * OoOoOO00
   if 57 - 57: ooOoO0o * ooOoO0o + I11i + i11iIiiIii % I1Ii111 * I1IiiI
   if 73 - 73: Oo0Ooo * iIii1I11I1II1 - II111iiii
   IiIi = 0 if I1IOoOO0000OOoO . has_key ( "packet-count" ) == False else I1IOoOO0000OOoO [ "packet-count" ]
   if 44 - 44: ooOoO0o * I1IiiI / II111iiii / OoooooooOO
   O0OooO0 = 0 if I1IOoOO0000OOoO . has_key ( "byte-count" ) == False else I1IOoOO0000OOoO [ "byte-count" ]
   if 12 - 12: I1ii11iIi11i . OoOoOO00 * I1Ii111 - I1IiiI / oO0o * ooOoO0o
   III11I1 = 0 if I1IOoOO0000OOoO . has_key ( "seconds-last-packet" ) == False else I1IOoOO0000OOoO [ "seconds-last-packet" ]
   if 6 - 6: i1IIi % II111iiii % Oo0Ooo + o0oOOo0O0Ooo
   if 61 - 61: I11i / i11iIiiIii
   iIIiIiiI . stats . packet_count += IiIi
   iIIiIiiI . stats . byte_count += O0OooO0
   iIIiIiiI . stats . last_increment = lisp_get_timestamp ( ) - III11I1
   if 89 - 89: II111iiii
   lprint ( "Update stats {}/{}/{}s for {} RLOC {}" . format ( IiIi , O0OooO0 ,
 III11I1 , oo0ooooO , Oo0oO ) )
   if 2 - 2: OoOoOO00 . i11iIiiIii
   if 11 - 11: Ii1I
   if 82 - 82: I11i - i1IIi . Oo0Ooo * I1Ii111
   if 44 - 44: iII111i
   if 56 - 56: II111iiii / Oo0Ooo % IiII * II111iiii - iIii1I11I1II1 + ooOoO0o
  if ( oOooO0Oo0Oo0 . group . is_null ( ) and oOooO0Oo0Oo0 . has_ttl_elapsed ( ) ) :
   oo0ooooO = green ( oOooO0Oo0Oo0 . print_eid_tuple ( ) , False )
   lprint ( "Refresh map-cache entry {}" . format ( oo0ooooO ) )
   lisp_send_map_request ( lisp_sockets , lisp_port , None , oOooO0Oo0Oo0 . eid , None )
   if 33 - 33: o0oOOo0O0Ooo . I11i / I1IiiI
   if 29 - 29: o0oOOo0O0Ooo - ooOoO0o
 return
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
 if 93 - 93: I1Ii111 + OOooOOo % ooOoO0o / I1Ii111 % OOooOOo . IiII
 if 37 - 37: iII111i * oO0o / oO0o / Ii1I % I11i
 if 12 - 12: i11iIiiIii
 if 62 - 62: oO0o + OOooOOo + oO0o + I1IiiI
 if 10 - 10: IiII - Oo0Ooo % ooOoO0o
 if 38 - 38: oO0o * o0oOOo0O0Ooo . I11i % II111iiii / I11i % Ii1I
 if 19 - 19: II111iiii / i11iIiiIii * II111iiii + OoOoOO00 - OoOoOO00
 if 7 - 7: OoOoOO00 - OoO0O00 % OoOoOO00 . I1ii11iIi11i % Oo0Ooo * iII111i
 if 90 - 90: IiII - OOooOOo + iIii1I11I1II1
 if 88 - 88: ooOoO0o . o0oOOo0O0Ooo . OOooOOo - I11i
 if 76 - 76: IiII % I1IiiI . iII111i
def lisp_process_data_plane_decap_stats ( msg , lisp_ipc_socket ) :
 if 5 - 5: ooOoO0o . oO0o - OoOoOO00 - OoooooooOO
 if 2 - 2: OOooOOo
 if 37 - 37: IiII - iIii1I11I1II1 * i11iIiiIii . ooOoO0o
 if 78 - 78: OOooOOo - I1ii11iIi11i + iII111i % OoOoOO00
 if 28 - 28: I11i + i1IIi / i11iIiiIii * OOooOOo * II111iiii
 if ( lisp_i_am_itr ) :
  lprint ( "Send decap-stats IPC message to lisp-etr process" )
  OOOO0OoO0oOOoo0 = "stats%{}" . format ( json . dumps ( msg ) )
  OOOO0OoO0oOOoo0 = lisp_command_ipc ( OOOO0OoO0oOOoo0 , "lisp-itr" )
  lisp_ipc ( OOOO0OoO0oOOoo0 , lisp_ipc_socket , "lisp-etr" )
  return
  if 78 - 78: OoO0O00 - i1IIi % I1Ii111
  if 87 - 87: I11i
  if 37 - 37: iII111i . I1Ii111 - iII111i - I11i - iIii1I11I1II1 - II111iiii
  if 80 - 80: I1Ii111 % O0 - IiII / II111iiii + i1IIi
  if 4 - 4: OOooOOo + II111iiii
  if 1 - 1: OoooooooOO * I1Ii111 - I11i / IiII
  if 43 - 43: i11iIiiIii * I1IiiI
  if 48 - 48: Oo0Ooo - OOooOOo / iII111i % I1ii11iIi11i . OoOoOO00
 OOOO0OoO0oOOoo0 = bold ( "IPC" , False )
 lprint ( "Process decap-stats {} message: '{}'" . format ( OOOO0OoO0oOOoo0 , msg ) )
 if 6 - 6: i11iIiiIii
 if ( lisp_i_am_etr ) : msg = json . loads ( msg )
 if 51 - 51: o0oOOo0O0Ooo - OoooooooOO - I11i % i11iIiiIii / I1IiiI + IiII
 ooI11 = [ "good-packets" , "ICV-error" , "checksum-error" ,
 "lisp-header-error" , "no-decrypt-key" , "bad-inner-version" ,
 "outer-header-error" ]
 if 12 - 12: Oo0Ooo
 for i1I1i1II11I in ooI11 :
  IiIi = 0 if msg . has_key ( i1I1i1II11I ) == False else msg [ i1I1i1II11I ] [ "packet-count" ]
  if 70 - 70: i11iIiiIii - OoO0O00 / i11iIiiIii
  lisp_decap_stats [ i1I1i1II11I ] . packet_count += IiIi
  if 46 - 46: II111iiii + O0 * OoooooooOO
  O0OooO0 = 0 if msg . has_key ( i1I1i1II11I ) == False else msg [ i1I1i1II11I ] [ "byte-count" ]
  if 39 - 39: OoooooooOO % II111iiii . o0oOOo0O0Ooo
  lisp_decap_stats [ i1I1i1II11I ] . byte_count += O0OooO0
  if 29 - 29: I11i . o0oOOo0O0Ooo . i1IIi . o0oOOo0O0Ooo
  III11I1 = 0 if msg . has_key ( i1I1i1II11I ) == False else msg [ i1I1i1II11I ] [ "seconds-last-packet" ]
  if 77 - 77: iIii1I11I1II1 + iIii1I11I1II1
  lisp_decap_stats [ i1I1i1II11I ] . last_increment = lisp_get_timestamp ( ) - III11I1
  if 52 - 52: I1ii11iIi11i - IiII % I1IiiI % i1IIi
 return
 if 98 - 98: I1Ii111 + II111iiii % OoO0O00 % iII111i
 if 54 - 54: II111iiii . ooOoO0o . iII111i - I1IiiI
 if 97 - 97: oO0o - O0 / II111iiii * II111iiii - oO0o * IiII
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
def lisp_process_punt ( punt_socket , lisp_send_sockets , lisp_ephem_port ) :
 oO00O0oO0O , O00oo0o0o0oo = punt_socket . recvfrom ( 4000 )
 if 12 - 12: i1IIi - I1IiiI - OOooOOo - i11iIiiIii % oO0o
 o0oOOo00oO0 = json . loads ( oO00O0oO0O )
 if ( type ( o0oOOo00oO0 ) != dict ) :
  lprint ( "Invalid punt message from {}, not in JSON format" . format ( O00oo0o0o0oo ) )
  if 89 - 89: Ii1I - OOooOOo / ooOoO0o - IiII + iIii1I11I1II1 + OoO0O00
  return
  if 40 - 40: OoO0O00
 Oo0OOoo = bold ( "Punt" , False )
 lprint ( "{} message from '{}': '{}'" . format ( Oo0OOoo , O00oo0o0o0oo , o0oOOo00oO0 ) )
 if 16 - 16: ooOoO0o - IiII % OOooOOo . OoO0O00
 if ( o0oOOo00oO0 . has_key ( "type" ) == False ) :
  lprint ( "Punt IPC message has no 'type' key" )
  return
  if 29 - 29: ooOoO0o * iIii1I11I1II1 . i1IIi
  if 89 - 89: Oo0Ooo / iIii1I11I1II1 . OoOoOO00
  if 6 - 6: Ii1I / iII111i
  if 69 - 69: iIii1I11I1II1 % I1Ii111 % OOooOOo + O0 - OoOoOO00 % oO0o
  if 70 - 70: oO0o - I1IiiI + Ii1I
 if ( o0oOOo00oO0 [ "type" ] == "statistics" ) :
  lisp_process_data_plane_stats ( o0oOOo00oO0 , lisp_send_sockets , lisp_ephem_port )
  return
  if 54 - 54: OoOoOO00 / ooOoO0o - I1IiiI
 if ( o0oOOo00oO0 [ "type" ] == "decap-statistics" ) :
  lisp_process_data_plane_decap_stats ( o0oOOo00oO0 , punt_socket )
  return
  if 37 - 37: o0oOOo0O0Ooo
  if 57 - 57: iII111i / i1IIi / i1IIi + IiII
  if 75 - 75: IiII / O0
  if 72 - 72: I11i
  if 35 - 35: I11i % OoooooooOO / i1IIi * i1IIi / I1IiiI
 if ( o0oOOo00oO0 [ "type" ] == "restart" ) :
  lisp_process_data_plane_restart ( )
  return
  if 42 - 42: I11i - i1IIi - oO0o / I11i + Ii1I + ooOoO0o
  if 23 - 23: OoOoOO00 . oO0o - iII111i
  if 27 - 27: Oo0Ooo * OOooOOo - OoOoOO00
  if 1 - 1: II111iiii * i11iIiiIii . OoooooooOO
  if 37 - 37: OoooooooOO + O0 . I11i % OoOoOO00
 if ( o0oOOo00oO0 [ "type" ] != "discovery" ) :
  lprint ( "Punt IPC message has wrong format" )
  return
  if 57 - 57: I1Ii111 . OOooOOo + I1Ii111 . iIii1I11I1II1 / oO0o / O0
 if ( o0oOOo00oO0 . has_key ( "interface" ) == False ) :
  lprint ( "Invalid punt message from {}, required keys missing" . format ( O00oo0o0o0oo ) )
  if 88 - 88: I1Ii111
  return
  if 16 - 16: Oo0Ooo . ooOoO0o / OoO0O00 / o0oOOo0O0Ooo . OoooooooOO * OoO0O00
  if 50 - 50: II111iiii + I11i . OoooooooOO . I1Ii111 - OOooOOo
  if 83 - 83: oO0o
  if 100 - 100: I1Ii111 + o0oOOo0O0Ooo * oO0o / oO0o . oO0o + iII111i
  if 71 - 71: II111iiii + iII111i + O0 % Oo0Ooo / I1IiiI
 Ooooo = o0oOOo00oO0 [ "interface" ]
 if ( Ooooo == "" ) :
  IIiI1i = int ( o0oOOo00oO0 [ "instance-id" ] )
  if ( IIiI1i == - 1 ) : return
 else :
  IIiI1i = lisp_get_interface_instance_id ( Ooooo , None )
  if 52 - 52: Oo0Ooo . I1Ii111 * i1IIi / Oo0Ooo / OoO0O00
  if 29 - 29: iII111i
  if 91 - 91: Oo0Ooo - IiII
  if 47 - 47: iII111i / OOooOOo + iII111i
  if 69 - 69: I1IiiI . I1ii11iIi11i
 IIII = None
 if ( o0oOOo00oO0 . has_key ( "source-eid" ) ) :
  oooooOO0 = o0oOOo00oO0 [ "source-eid" ]
  IIII = lisp_address ( LISP_AFI_NONE , oooooOO0 , 0 , IIiI1i )
  if ( IIII . is_null ( ) ) :
   lprint ( "Invalid source-EID format '{}'" . format ( oooooOO0 ) )
   return
   if 18 - 18: I11i * I1IiiI
   if 42 - 42: i1IIi . I1Ii111 - ooOoO0o + I11i / oO0o
 iIIoO000O0 = None
 if ( o0oOOo00oO0 . has_key ( "dest-eid" ) ) :
  Oo0ooo = o0oOOo00oO0 [ "dest-eid" ]
  iIIoO000O0 = lisp_address ( LISP_AFI_NONE , Oo0ooo , 0 , IIiI1i )
  if ( iIIoO000O0 . is_null ( ) ) :
   lprint ( "Invalid dest-EID format '{}'" . format ( Oo0ooo ) )
   return
   if 75 - 75: Oo0Ooo + IiII / I11i % I11i % IiII / I1Ii111
   if 95 - 95: OoOoOO00
   if 78 - 78: I11i
   if 62 - 62: iIii1I11I1II1 . o0oOOo0O0Ooo . ooOoO0o % oO0o % O0 % oO0o
   if 51 - 51: Oo0Ooo / IiII - Oo0Ooo
   if 71 - 71: I11i * I1ii11iIi11i * OOooOOo * o0oOOo0O0Ooo
   if 53 - 53: I1IiiI % I1IiiI
   if 80 - 80: OoO0O00 - i11iIiiIii / iII111i * I1ii11iIi11i / I1IiiI - I1Ii111
 if ( IIII ) :
  I1i11II = green ( IIII . print_address ( ) , False )
  i1iOo = lisp_db_for_lookups . lookup_cache ( IIII , False )
  if ( i1iOo != None ) :
   if 85 - 85: IiII
   if 72 - 72: iII111i * OoOoOO00
   if 65 - 65: iIii1I11I1II1 / iIii1I11I1II1 % O0 / II111iiii . OOooOOo . O0
   if 65 - 65: I11i
   if 35 - 35: o0oOOo0O0Ooo - i11iIiiIii
   if ( i1iOo . dynamic_eid_configured ( ) ) :
    iIiiiIiIi = lisp_allow_dynamic_eid ( Ooooo , IIII )
    if ( iIiiiIiIi != None and lisp_i_am_itr ) :
     lisp_itr_discover_eid ( i1iOo , IIII , Ooooo , iIiiiIiIi )
    else :
     lprint ( ( "Disallow dynamic source-EID {} " + "on interface {}" ) . format ( I1i11II , Ooooo ) )
     if 78 - 78: ooOoO0o - II111iiii - i1IIi
     if 18 - 18: OoooooooOO % OoOoOO00 - IiII / oO0o . OOooOOo . I1IiiI
     if 77 - 77: I1ii11iIi11i . OoO0O00 / OoOoOO00 / O0
  else :
   lprint ( "Punt from non-EID source {}" . format ( I1i11II ) )
   if 67 - 67: ooOoO0o % I11i % oO0o
   if 74 - 74: II111iiii
   if 44 - 44: Oo0Ooo + OoO0O00 + OoOoOO00 - I1IiiI
   if 68 - 68: i11iIiiIii / OOooOOo . i1IIi . i11iIiiIii . I11i
   if 56 - 56: iIii1I11I1II1 - II111iiii * i1IIi / Ii1I
   if 65 - 65: OOooOOo / I1IiiI . OoooooooOO + I1IiiI + OoooooooOO + i11iIiiIii
 if ( iIIoO000O0 ) :
  oOooO0Oo0Oo0 = lisp_map_cache_lookup ( IIII , iIIoO000O0 )
  if ( oOooO0Oo0Oo0 == None or oOooO0Oo0Oo0 . action == LISP_SEND_MAP_REQUEST_ACTION ) :
   if 20 - 20: I1IiiI + iII111i + O0 * O0
   if 18 - 18: I11i - I11i . OoOoOO00 . ooOoO0o
   if 31 - 31: ooOoO0o
   if 87 - 87: OoooooooOO + OOooOOo - I1ii11iIi11i / I1IiiI + ooOoO0o - Oo0Ooo
   if 19 - 19: ooOoO0o + I1ii11iIi11i - ooOoO0o
   if ( lisp_rate_limit_map_request ( IIII , iIIoO000O0 ) ) : return
   lisp_send_map_request ( lisp_send_sockets , lisp_ephem_port ,
 IIII , iIIoO000O0 , None )
  else :
   I1i11II = green ( iIIoO000O0 . print_address ( ) , False )
   lprint ( "Map-cache entry for {} already exists" . format ( I1i11II ) )
   if 17 - 17: I11i * i1IIi + iIii1I11I1II1 % I1IiiI
   if 44 - 44: IiII + I1IiiI . Ii1I % Oo0Ooo
 return
 if 97 - 97: O0
 if 95 - 95: OoO0O00 % iII111i / I1IiiI * OoooooooOO
 if 31 - 31: iIii1I11I1II1
 if 62 - 62: o0oOOo0O0Ooo - iII111i / II111iiii . o0oOOo0O0Ooo
 if 20 - 20: iIii1I11I1II1 % OOooOOo
 if 91 - 91: ooOoO0o
 if 96 - 96: I1IiiI . OOooOOo
def lisp_ipc_map_cache_entry ( mc , jdata ) :
 oOoO = lisp_write_ipc_map_cache ( True , mc , dont_send = True )
 jdata . append ( oOoO )
 return ( [ True , jdata ] )
 if 94 - 94: OoooooooOO + II111iiii % ooOoO0o - II111iiii / O0
 if 34 - 34: IiII % oO0o
 if 54 - 54: I1IiiI
 if 80 - 80: OoOoOO00 . I1IiiI / I1ii11iIi11i . iII111i
 if 31 - 31: I11i * o0oOOo0O0Ooo
 if 17 - 17: Ii1I * iIii1I11I1II1
 if 9 - 9: o0oOOo0O0Ooo - IiII
 if 78 - 78: i11iIiiIii . o0oOOo0O0Ooo
def lisp_ipc_walk_map_cache ( mc , jdata ) :
 if 72 - 72: Oo0Ooo % II111iiii + O0 * OoOoOO00 - OOooOOo + I1Ii111
 if 23 - 23: I1IiiI - O0 - iII111i . II111iiii / oO0o
 if 1 - 1: I11i . OOooOOo / oO0o % I11i * Oo0Ooo + Oo0Ooo
 if 23 - 23: Ii1I % i1IIi - I1Ii111
 if ( mc . group . is_null ( ) ) : return ( lisp_ipc_map_cache_entry ( mc , jdata ) )
 if 95 - 95: OoOoOO00 - ooOoO0o . i1IIi . OoooooooOO
 if ( mc . source_cache == None ) : return ( [ True , jdata ] )
 if 38 - 38: I1IiiI + I1ii11iIi11i - Oo0Ooo . i11iIiiIii - i1IIi
 if 11 - 11: IiII / I1IiiI . I1IiiI
 if 87 - 87: OoooooooOO * OoO0O00 * iIii1I11I1II1
 if 16 - 16: o0oOOo0O0Ooo * I11i + OoooooooOO + O0 / iIii1I11I1II1
 if 60 - 60: Ii1I % IiII * OoooooooOO * ooOoO0o * Ii1I
 jdata = mc . source_cache . walk_cache ( lisp_ipc_map_cache_entry , jdata )
 return ( [ True , jdata ] )
 if 8 - 8: I1Ii111 - o0oOOo0O0Ooo
 if 52 - 52: OoOoOO00 % O0 + I1ii11iIi11i . i11iIiiIii
 if 59 - 59: Ii1I - I1Ii111 . ooOoO0o - OoOoOO00 + oO0o . OoO0O00
 if 88 - 88: OOooOOo - ooOoO0o * o0oOOo0O0Ooo . OoooooooOO
 if 3 - 3: I1Ii111
 if 24 - 24: Ii1I + i11iIiiIii * I1Ii111 - OoOoOO00 / Ii1I - OoOoOO00
 if 69 - 69: I11i - I1IiiI . oO0o - OoooooooOO
def lisp_itr_discover_eid ( db , eid , input_interface , routed_interface ,
 lisp_ipc_listen_socket ) :
 oo0ooooO = eid . print_address ( )
 if ( db . dynamic_eids . has_key ( oo0ooooO ) ) :
  db . dynamic_eids [ oo0ooooO ] . last_packet = lisp_get_timestamp ( )
  return
  if 33 - 33: o0oOOo0O0Ooo - o0oOOo0O0Ooo
  if 55 - 55: OoooooooOO / IiII + i1IIi
  if 54 - 54: ooOoO0o * Ii1I / Ii1I
  if 15 - 15: oO0o * I1Ii111
  if 11 - 11: Ii1I + o0oOOo0O0Ooo * OoooooooOO % iIii1I11I1II1
 iIi11ii1 = lisp_dynamic_eid ( )
 iIi11ii1 . dynamic_eid . copy_address ( eid )
 iIi11ii1 . interface = routed_interface
 iIi11ii1 . last_packet = lisp_get_timestamp ( )
 iIi11ii1 . get_timeout ( routed_interface )
 db . dynamic_eids [ oo0ooooO ] = iIi11ii1
 if 87 - 87: OoO0O00 + o0oOOo0O0Ooo
 iIIiIi = ""
 if ( input_interface != routed_interface ) :
  iIIiIi = ", routed-interface " + routed_interface
  if 78 - 78: OOooOOo + OOooOOo - i11iIiiIii - O0
  if 75 - 75: o0oOOo0O0Ooo / OoooooooOO . I1ii11iIi11i * oO0o * I11i / OoooooooOO
 i1II111ii1i = green ( oo0ooooO , False ) + bold ( " discovered" , False )
 lprint ( "Dynamic-EID {} on interface {}{}, timeout {}" . format ( i1II111ii1i , input_interface , iIIiIi , iIi11ii1 . timeout ) )
 if 8 - 8: i1IIi
 if 61 - 61: i11iIiiIii * Ii1I % iII111i - Ii1I * O0
 if 39 - 39: iII111i + i1IIi * iII111i - iIii1I11I1II1
 if 5 - 5: Ii1I / i1IIi - iIii1I11I1II1 * I1ii11iIi11i - O0 % OOooOOo
 if 17 - 17: I1Ii111 . ooOoO0o
 OOOO0OoO0oOOoo0 = "learn%{}%{}" . format ( oo0ooooO , routed_interface )
 OOOO0OoO0oOOoo0 = lisp_command_ipc ( OOOO0OoO0oOOoo0 , "lisp-itr" )
 lisp_ipc ( OOOO0OoO0oOOoo0 , lisp_ipc_listen_socket , "lisp-etr" )
 return
 if 34 - 34: o0oOOo0O0Ooo / OOooOOo + Ii1I % Oo0Ooo % I1ii11iIi11i
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
 if 86 - 86: IiII * OOooOOo + Ii1I
def lisp_retry_decap_keys ( addr_str , packet , iv , packet_icv ) :
 if ( lisp_search_decap_keys == False ) : return
 if 62 - 62: I11i
 if 86 - 86: Oo0Ooo % II111iiii + I1Ii111 / I1ii11iIi11i
 if 15 - 15: I1IiiI / I1Ii111 % iII111i
 if 57 - 57: I1Ii111 . iIii1I11I1II1 / Oo0Ooo / IiII / iII111i * OoOoOO00
 if ( addr_str . find ( ":" ) != - 1 ) : return
 if 35 - 35: i1IIi + I1Ii111 - ooOoO0o . I1ii11iIi11i + Oo0Ooo
 Ii1IIII = lisp_crypto_keys_by_rloc_decap [ addr_str ]
 if 43 - 43: oO0o . OoO0O00 * i1IIi
 for iIIIi in lisp_crypto_keys_by_rloc_decap :
  if 1 - 1: ooOoO0o / i1IIi
  if 42 - 42: I1ii11iIi11i * ooOoO0o + OoOoOO00 % I1ii11iIi11i . IiII
  if 75 - 75: OoO0O00 * i1IIi - OOooOOo % II111iiii % OoO0O00 - OoOoOO00
  if 75 - 75: I11i * IiII * ooOoO0o
  if ( iIIIi . find ( addr_str ) == - 1 ) : continue
  if 31 - 31: Ii1I
  if 72 - 72: OOooOOo * Ii1I % OoO0O00
  if 72 - 72: OoOoOO00 + o0oOOo0O0Ooo - i1IIi - OoO0O00 % OoOoOO00
  if 42 - 42: oO0o / i1IIi . IiII
  if ( iIIIi == addr_str ) : continue
  if 12 - 12: i11iIiiIii . ooOoO0o
  if 80 - 80: O0 / iIii1I11I1II1 % iII111i * ooOoO0o / i11iIiiIii . OoOoOO00
  if 88 - 88: OoooooooOO . I1IiiI
  if 6 - 6: I1Ii111 - i11iIiiIii - oO0o
  oOoO = lisp_crypto_keys_by_rloc_decap [ iIIIi ]
  if ( oOoO == Ii1IIII ) : continue
  if 7 - 7: i1IIi
  if 6 - 6: OoooooooOO - Oo0Ooo - I1ii11iIi11i
  if 34 - 34: iII111i + i11iIiiIii . IiII
  if 54 - 54: Oo0Ooo + I11i - iII111i * ooOoO0o % i11iIiiIii . IiII
  ii1iiIi1I1 = oOoO [ 1 ]
  if ( packet_icv != ii1iiIi1I1 . do_icv ( packet , iv ) ) :
   lprint ( "Test ICV with key {} failed" . format ( red ( iIIIi , False ) ) )
   continue
   if 51 - 51: OoooooooOO . Ii1I % OoooooooOO - I1IiiI + I1Ii111 % oO0o
   if 28 - 28: i11iIiiIii - I1IiiI * OoO0O00
  lprint ( "Changing decap crypto key to {}" . format ( red ( iIIIi , False ) ) )
  lisp_crypto_keys_by_rloc_decap [ addr_str ] = oOoO
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
def lisp_decent_pull_xtr_configured ( ) :
 return ( lisp_decent_modulus != 0 and lisp_decent_dns_suffix != None )
 if 52 - 52: iIii1I11I1II1 + O0
 if 84 - 84: OOooOOo / iII111i . I1IiiI / O0 % OOooOOo . iII111i
 if 32 - 32: OoO0O00 + OoO0O00 % o0oOOo0O0Ooo / O0
 if 29 - 29: iII111i % I1Ii111
 if 95 - 95: OOooOOo - ooOoO0o % i1IIi / O0 % I11i . IiII
 if 63 - 63: ooOoO0o
 if 22 - 22: OOooOOo . i11iIiiIii + II111iiii - Oo0Ooo % i1IIi / o0oOOo0O0Ooo
 if 90 - 90: IiII
def lisp_is_decent_dns_suffix ( dns_name ) :
 if ( lisp_decent_dns_suffix == None ) : return ( False )
 i1i1IIi1II = dns_name . split ( "." )
 i1i1IIi1II = "." . join ( i1i1IIi1II [ 1 : : ] )
 return ( i1i1IIi1II == lisp_decent_dns_suffix )
 if 38 - 38: i1IIi / ooOoO0o / I11i * I1ii11iIi11i / II111iiii . iIii1I11I1II1
 if 52 - 52: I1ii11iIi11i % ooOoO0o * Ii1I * IiII + IiII / i11iIiiIii
 if 51 - 51: iIii1I11I1II1 * o0oOOo0O0Ooo % o0oOOo0O0Ooo . Ii1I / OoooooooOO
 if 23 - 23: oO0o * I1IiiI - oO0o - ooOoO0o . IiII / i11iIiiIii
 if 53 - 53: Ii1I * Ii1I . OoOoOO00 . OOooOOo / I1ii11iIi11i % O0
 if 98 - 98: OOooOOo
 if 11 - 11: OOooOOo * iIii1I11I1II1 % IiII - I1IiiI . I11i
def lisp_get_decent_index ( eid ) :
 oo0ooooO = eid . print_prefix ( )
 III1II11i1 = hashlib . sha256 ( oo0ooooO ) . hexdigest ( )
 OOOoO000 = int ( III1II11i1 , 16 ) % lisp_decent_modulus
 return ( OOOoO000 )
 if 62 - 62: i11iIiiIii % iIii1I11I1II1 / IiII . I1IiiI * O0
 if 17 - 17: I1ii11iIi11i - I1Ii111 % II111iiii + OOooOOo
 if 45 - 45: I1Ii111 + iII111i - iIii1I11I1II1 / Oo0Ooo
 if 92 - 92: iIii1I11I1II1 . OoO0O00 - I11i % I1ii11iIi11i / i11iIiiIii
 if 4 - 4: Oo0Ooo / I1IiiI * i1IIi . II111iiii
 if 13 - 13: i1IIi
 if 39 - 39: OOooOOo
def lisp_get_decent_dns_name ( eid ) :
 OOOoO000 = lisp_get_decent_index ( eid )
 return ( str ( OOOoO000 ) + "." + lisp_decent_dns_suffix )
 if 73 - 73: OoO0O00 . ooOoO0o
 if 13 - 13: o0oOOo0O0Ooo - OoOoOO00
 if 60 - 60: OoO0O00
 if 17 - 17: i11iIiiIii % i1IIi % I1IiiI % ooOoO0o + I1Ii111 + Oo0Ooo
 if 16 - 16: iII111i . I1ii11iIi11i . oO0o . OoO0O00
 if 90 - 90: i1IIi . ooOoO0o + i11iIiiIii * OoooooooOO
 if 30 - 30: iII111i . OoO0O00 . i11iIiiIii / I1ii11iIi11i * Oo0Ooo
 if 38 - 38: IiII + II111iiii
def lisp_get_decent_dns_name_from_str ( iid , eid_str ) :
 Ooo0 = lisp_address ( LISP_AFI_NONE , eid_str , 0 , iid )
 OOOoO000 = lisp_get_decent_index ( Ooo0 )
 return ( str ( OOOoO000 ) + "." + lisp_decent_dns_suffix )
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
def lisp_trace_append ( packet , reason = None , ed = "encap" , lisp_socket = None ) :
 oOO0OO0O = 28 if packet . inner_version == 4 else 48
 III1i1i1iIIi = packet . packet [ oOO0OO0O : : ]
 I1II1II1IiI = lisp_trace ( )
 if ( I1II1II1IiI . decode ( III1i1i1iIIi ) == False ) :
  lprint ( "Could not decode JSON portion of a LISP-Trace packet" )
  return ( False )
  if 20 - 20: i1IIi
  if 72 - 72: ooOoO0o . II111iiii
 I1IIiiII = "?" if packet . outer_dest . is_null ( ) else packet . outer_dest . print_address_no_iid ( )
 if 23 - 23: i1IIi
 if 26 - 26: I1IiiI + OoooooooOO % OoOoOO00 . IiII - II111iiii . OoOoOO00
 if 37 - 37: OoO0O00 % O0 + OoOoOO00 * I11i . Ii1I * OoO0O00
 if 18 - 18: o0oOOo0O0Ooo / OOooOOo
 if 28 - 28: O0 / Ii1I - oO0o % I1ii11iIi11i % O0 . OoO0O00
 if 100 - 100: O0
 if ( I1IIiiII != "?" and packet . encap_port != LISP_DATA_PORT ) :
  if ( ed == "encap" ) : I1IIiiII += ":{}" . format ( packet . encap_port )
  if 19 - 19: Ii1I * iIii1I11I1II1 * Oo0Ooo - i11iIiiIii * i11iIiiIii - OOooOOo
  if 88 - 88: O0 . iIii1I11I1II1 . I1ii11iIi11i
  if 80 - 80: oO0o / i1IIi * iIii1I11I1II1
  if 38 - 38: Ii1I
  if 20 - 20: iIii1I11I1II1 + Oo0Ooo - Ii1I / i11iIiiIii . OoO0O00
 oOoO = { }
 oOoO [ "node" ] = "ITR" if lisp_i_am_itr else "ETR" if lisp_i_am_etr else "RTR" if lisp_i_am_rtr else "?"
 if 66 - 66: OoooooooOO - Ii1I / iII111i . I1IiiI + I1ii11iIi11i - I1Ii111
 I1iI1IIi1 = packet . outer_source
 if ( I1iI1IIi1 . is_null ( ) ) : I1iI1IIi1 = lisp_myrlocs [ 0 ]
 oOoO [ "srloc" ] = I1iI1IIi1 . print_address_no_iid ( )
 if 58 - 58: oO0o - iIii1I11I1II1 * i11iIiiIii / i11iIiiIii % I11i
 if 69 - 69: iII111i * i1IIi
 if 100 - 100: Oo0Ooo + Oo0Ooo - II111iiii
 if 4 - 4: iII111i / OoO0O00 . i11iIiiIii * II111iiii - Ii1I * IiII
 if 45 - 45: OoO0O00
 if ( oOoO [ "node" ] == "ITR" and packet . inner_sport != LISP_TRACE_PORT ) :
  oOoO [ "srloc" ] += ":{}" . format ( packet . inner_sport )
  if 15 - 15: iII111i * o0oOOo0O0Ooo * Ii1I % IiII
  if 31 - 31: ooOoO0o . IiII + I1ii11iIi11i * II111iiii * iII111i + Oo0Ooo
 oOoO [ "hostname" ] = lisp_hostname
 iIIIi = ed + "-timestamp"
 oOoO [ iIIIi ] = lisp_get_timestamp ( )
 if 35 - 35: oO0o + I1ii11iIi11i / o0oOOo0O0Ooo
 if 78 - 78: i11iIiiIii
 if 21 - 21: iII111i / ooOoO0o - i11iIiiIii % iII111i
 if 94 - 94: OoooooooOO / iII111i * ooOoO0o / i1IIi * i11iIiiIii * II111iiii
 if 98 - 98: Ii1I * Ii1I / IiII
 if 1 - 1: OOooOOo
 if ( I1IIiiII == "?" and oOoO [ "node" ] == "ETR" ) :
  i1iOo = lisp_db_for_lookups . lookup_cache ( packet . inner_dest , False )
  if ( i1iOo != None and len ( i1iOo . rloc_set ) >= 1 ) :
   I1IIiiII = i1iOo . rloc_set [ 0 ] . rloc . print_address_no_iid ( )
   if 47 - 47: i11iIiiIii - I11i
   if 38 - 38: Oo0Ooo % OoooooooOO + iII111i
 oOoO [ "drloc" ] = I1IIiiII
 if 31 - 31: OoO0O00 + I1Ii111 / iIii1I11I1II1
 if 11 - 11: ooOoO0o - OoOoOO00
 if 19 - 19: O0 . OoOoOO00 - i1IIi . oO0o
 if 96 - 96: o0oOOo0O0Ooo % o0oOOo0O0Ooo - OoO0O00 * iIii1I11I1II1 + ooOoO0o - ooOoO0o
 if ( I1IIiiII == "?" and reason != None ) :
  oOoO [ "drloc" ] += " ({})" . format ( reason )
  if 4 - 4: OoO0O00 - OOooOOo
  if 21 - 21: I1Ii111 * i11iIiiIii
  if 63 - 63: oO0o + OoOoOO00
  if 50 - 50: o0oOOo0O0Ooo / Oo0Ooo * ooOoO0o * Ii1I
  if 97 - 97: I1IiiI / oO0o + I1Ii111 + I1Ii111
  if 86 - 86: o0oOOo0O0Ooo % ooOoO0o + OoOoOO00 * ooOoO0o
 IIII = packet . inner_source . print_address ( )
 iIIoO000O0 = packet . inner_dest . print_address ( )
 if ( I1II1II1IiI . packet_json == [ ] ) :
  Oooo0O0ooOooO = { }
  Oooo0O0ooOooO [ "seid" ] = IIII
  Oooo0O0ooOooO [ "deid" ] = iIIoO000O0
  Oooo0O0ooOooO [ "paths" ] = [ ]
  I1II1II1IiI . packet_json . append ( Oooo0O0ooOooO )
  if 20 - 20: Ii1I * iII111i / ooOoO0o
  if 18 - 18: Oo0Ooo * Ii1I / i11iIiiIii . OoO0O00 + OoooooooOO
  if 23 - 23: I1IiiI - I1ii11iIi11i . O0 . OoOoOO00 . OoO0O00
  if 81 - 81: IiII * I11i - iIii1I11I1II1
  if 41 - 41: oO0o * I11i + I1IiiI - OoO0O00
  if 63 - 63: Oo0Ooo * Ii1I - Ii1I
 for Oooo0O0ooOooO in I1II1II1IiI . packet_json :
  if ( Oooo0O0ooOooO [ "deid" ] != iIIoO000O0 ) : continue
  Oooo0O0ooOooO [ "paths" ] . append ( oOoO )
  break
  if 76 - 76: OoO0O00 . IiII % iIii1I11I1II1 / I1IiiI + iIii1I11I1II1 . I1IiiI
  if 57 - 57: IiII - i1IIi * ooOoO0o
  if 5 - 5: oO0o . O0 * IiII / Ii1I + OoO0O00
  if 75 - 75: OOooOOo * OoOoOO00
  if 82 - 82: Ii1I
  if 83 - 83: I1IiiI
  if 22 - 22: IiII / Ii1I + I1Ii111 % iIii1I11I1II1
  if 75 - 75: OoOoOO00 % OoOoOO00 % o0oOOo0O0Ooo % I1ii11iIi11i + IiII
 i1iiiI1i = False
 if ( len ( I1II1II1IiI . packet_json ) == 1 and I1II1II1IiI . myeid ( packet . inner_dest ) ) :
  Oooo0O0ooOooO = { }
  Oooo0O0ooOooO [ "seid" ] = iIIoO000O0
  Oooo0O0ooOooO [ "deid" ] = IIII
  Oooo0O0ooOooO [ "paths" ] = [ ]
  I1II1II1IiI . packet_json . append ( Oooo0O0ooOooO )
  i1iiiI1i = True
  if 48 - 48: OoooooooOO + OoO0O00 % i11iIiiIii * OoooooooOO
  if 64 - 64: I1ii11iIi11i . I1Ii111
  if 81 - 81: IiII . ooOoO0o + O0 . ooOoO0o + iIii1I11I1II1
  if 68 - 68: i11iIiiIii . iII111i + OoooooooOO + II111iiii + iIii1I11I1II1 % I11i
  if 7 - 7: i1IIi - o0oOOo0O0Ooo - I1IiiI
  if 62 - 62: OoOoOO00 * oO0o - I1IiiI / Ii1I
 I1II1II1IiI . print_trace ( )
 III1i1i1iIIi = I1II1II1IiI . encode ( )
 if 48 - 48: o0oOOo0O0Ooo % o0oOOo0O0Ooo - OoOoOO00
 if 13 - 13: OoO0O00 - Ii1I . ooOoO0o / O0 * OoOoOO00
 if 57 - 57: O0 + OoooooooOO % o0oOOo0O0Ooo / I1Ii111 / OOooOOo - OoOoOO00
 if 48 - 48: o0oOOo0O0Ooo - II111iiii + OoOoOO00
 if 54 - 54: II111iiii - OoO0O00 - o0oOOo0O0Ooo - O0 % I1Ii111
 if 9 - 9: i1IIi % iII111i / Ii1I
 if 83 - 83: oO0o
 if 1 - 1: oO0o * iIii1I11I1II1 % iIii1I11I1II1 % iIii1I11I1II1 / oO0o + IiII
 iI1 = I1II1II1IiI . packet_json [ 0 ] [ "paths" ] [ 0 ] [ "srloc" ]
 if ( I1IIiiII == "?" ) :
  lprint ( "LISP-Trace return to sender RLOC {}" . format ( iI1 ) )
  I1II1II1IiI . return_to_sender ( lisp_socket , iI1 , III1i1i1iIIi )
  return ( False )
  if 57 - 57: Ii1I
  if 51 - 51: iII111i - oO0o % iIii1I11I1II1 % I1Ii111 . OOooOOo / OoO0O00
  if 81 - 81: II111iiii % O0 * OoO0O00 % O0 * iIii1I11I1II1 * i1IIi
  if 53 - 53: I11i * ooOoO0o - Oo0Ooo + o0oOOo0O0Ooo
  if 52 - 52: Ii1I % OoOoOO00 / oO0o / OOooOOo
  if 22 - 22: iIii1I11I1II1 * Oo0Ooo % i1IIi % i11iIiiIii + oO0o
 i1 = I1II1II1IiI . packet_length ( )
 if 94 - 94: OoO0O00 * I1IiiI / O0 + I1Ii111 / i11iIiiIii
 if 34 - 34: Oo0Ooo . i1IIi
 if 97 - 97: I11i
 if 89 - 89: iII111i % OoOoOO00 . Oo0Ooo
 if 20 - 20: oO0o % OoOoOO00
 if 93 - 93: I1ii11iIi11i - Ii1I % i1IIi / i1IIi
 ooOo0O00o0 = packet . packet [ 0 : oOO0OO0O ]
 oo000o = struct . pack ( "HH" , socket . htons ( i1 ) , 0 )
 ooOo0O00o0 = ooOo0O00o0 [ 0 : oOO0OO0O - 4 ] + oo000o
 if ( packet . inner_version == 6 and oOoO [ "node" ] == "ETR" and
 len ( I1II1II1IiI . packet_json ) == 2 ) :
  IIi1ii1 = ooOo0O00o0 [ oOO0OO0O - 8 : : ] + III1i1i1iIIi
  IIi1ii1 = lisp_udp_checksum ( IIII , iIIoO000O0 , IIi1ii1 )
  ooOo0O00o0 = ooOo0O00o0 [ 0 : oOO0OO0O - 8 ] + IIi1ii1 [ 0 : 8 ]
  if 90 - 90: ooOoO0o
  if 100 - 100: iII111i * i1IIi . iII111i / O0 / OoO0O00 - oO0o
  if 65 - 65: OoOoOO00 + ooOoO0o * OoO0O00 % OoooooooOO + OoooooooOO * OoooooooOO
  if 49 - 49: o0oOOo0O0Ooo + i1IIi / iII111i
  if 43 - 43: i1IIi . OoO0O00 + I1ii11iIi11i
  if 88 - 88: OoooooooOO / I11i % II111iiii % OOooOOo - I11i
 if ( i1iiiI1i ) :
  if ( packet . inner_version == 4 ) :
   ooOo0O00o0 = ooOo0O00o0 [ 0 : 12 ] + ooOo0O00o0 [ 16 : 20 ] + ooOo0O00o0 [ 12 : 16 ] + ooOo0O00o0 [ 22 : 24 ] + ooOo0O00o0 [ 20 : 22 ] + ooOo0O00o0 [ 24 : : ]
   if 55 - 55: Oo0Ooo - OOooOOo - O0
  else :
   ooOo0O00o0 = ooOo0O00o0 [ 0 : 8 ] + ooOo0O00o0 [ 24 : 40 ] + ooOo0O00o0 [ 8 : 24 ] + ooOo0O00o0 [ 42 : 44 ] + ooOo0O00o0 [ 40 : 42 ] + ooOo0O00o0 [ 44 : : ]
   if 40 - 40: OoOoOO00 - OOooOOo
   if 3 - 3: IiII % I11i * I1Ii111 + iIii1I11I1II1 . oO0o
  i1i11ii1Ii = packet . inner_dest
  packet . inner_dest = packet . inner_source
  packet . inner_source = i1i11ii1Ii
  if 35 - 35: II111iiii
  if 15 - 15: I11i * iIii1I11I1II1 + OOooOOo % IiII . o0oOOo0O0Ooo % Oo0Ooo
  if 96 - 96: O0
  if 15 - 15: i1IIi . iIii1I11I1II1
  if 3 - 3: II111iiii * i11iIiiIii * i1IIi - i1IIi
 oOO0OO0O = 2 if packet . inner_version == 4 else 4
 II111iIIiI = 20 + i1 if packet . inner_version == 4 else i1
 OOO0Oo = struct . pack ( "H" , socket . htons ( II111iIIiI ) )
 ooOo0O00o0 = ooOo0O00o0 [ 0 : oOO0OO0O ] + OOO0Oo + ooOo0O00o0 [ oOO0OO0O + 2 : : ]
 if 42 - 42: Oo0Ooo * I1IiiI % OoOoOO00
 if 9 - 9: OoooooooOO - Oo0Ooo - I1ii11iIi11i * o0oOOo0O0Ooo * I11i
 if 27 - 27: OoOoOO00 % OoO0O00 * oO0o . II111iiii - i11iIiiIii
 if 56 - 56: OOooOOo . IiII - OOooOOo / i11iIiiIii * I1ii11iIi11i
 if ( packet . inner_version == 4 ) :
  II1i1iI = struct . pack ( "H" , 0 )
  ooOo0O00o0 = ooOo0O00o0 [ 0 : 10 ] + II1i1iI + ooOo0O00o0 [ 12 : : ]
  OOO0Oo = lisp_ip_checksum ( ooOo0O00o0 [ 0 : 20 ] )
  ooOo0O00o0 = OOO0Oo + ooOo0O00o0 [ 20 : : ]
  if 66 - 66: oO0o + ooOoO0o
  if 1 - 1: ooOoO0o
  if 61 - 61: o0oOOo0O0Ooo / OoooooooOO . I1ii11iIi11i + Oo0Ooo
  if 75 - 75: Ii1I
  if 79 - 79: i1IIi . I1ii11iIi11i * o0oOOo0O0Ooo / I11i . I11i / ooOoO0o
 packet . packet = ooOo0O00o0 + III1i1i1iIIi
 return ( True )
 if 99 - 99: oO0o + I11i % i1IIi . iII111i
 if 58 - 58: Oo0Ooo % i11iIiiIii . Oo0Ooo / Oo0Ooo - I1IiiI . Ii1I
 if 65 - 65: OoO0O00
# dd678faae9ac167bc83abf78e5cb2f3f0688d3a3
