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
def lisp_is_mac_string ( mac_str ) :
 o0O0oO0 = mac_str . split ( "/" )
 if ( len ( o0O0oO0 ) == 2 ) : mac_str = o0O0oO0 [ 0 ]
 return ( len ( mac_str ) == 14 and mac_str . count ( "-" ) == 2 )
 if 52 - 52: I1Ii111 % OoOoOO00 + iIii1I11I1II1 * oO0o . Ii1I
 if 95 - 95: iIii1I11I1II1 . IiII - OoooooooOO * OoO0O00 / o0oOOo0O0Ooo
 if 74 - 74: oO0o
 if 34 - 34: iII111i
 if 44 - 44: i1IIi % I1IiiI % o0oOOo0O0Ooo
 if 9 - 9: Oo0Ooo % OoooooooOO - Ii1I
 if 43 - 43: OoO0O00 % OoO0O00
 if 46 - 46: Oo0Ooo % iIii1I11I1II1 . iII111i . O0 * ooOoO0o / OoooooooOO
def lisp_get_local_macs ( ) :
 for Ooooo in netifaces . interfaces ( ) :
  if 7 - 7: oO0o - O0 * I11i - o0oOOo0O0Ooo - II111iiii
  if 41 - 41: I1IiiI - I1Ii111 % II111iiii . I1Ii111 - I11i
  if 45 - 45: Ii1I - OOooOOo
  if 70 - 70: OoO0O00 % I1IiiI / I1IiiI . I11i % ooOoO0o . II111iiii
  if 10 - 10: Ii1I - i11iIiiIii . I1ii11iIi11i % i1IIi
  i1i11ii1Ii = Ooooo . replace ( ":" , "" )
  i1i11ii1Ii = Ooooo . replace ( "-" , "" )
  if ( i1i11ii1Ii . isalnum ( ) == False ) : continue
  if 78 - 78: iIii1I11I1II1 * Oo0Ooo . Oo0Ooo - OOooOOo . iIii1I11I1II1
  if 30 - 30: ooOoO0o + ooOoO0o % IiII - o0oOOo0O0Ooo - I1ii11iIi11i
  if 36 - 36: I11i % OOooOOo
  if 72 - 72: I1IiiI / iII111i - O0 + I11i
  if 83 - 83: O0
  try :
   oOOOOOo = netifaces . ifaddresses ( Ooooo )
  except :
   continue
   if 50 - 50: I1Ii111 + ooOoO0o + iII111i
  if ( oOOOOOo . has_key ( netifaces . AF_LINK ) == False ) : continue
  o0O0oO0 = oOOOOOo [ netifaces . AF_LINK ] [ 0 ] [ "addr" ]
  o0O0oO0 = o0O0oO0 . replace ( ":" , "" )
  if 15 - 15: I11i
  if 13 - 13: iIii1I11I1II1 * OoOoOO00 / I1Ii111 % ooOoO0o + oO0o
  if 41 - 41: I1ii11iIi11i
  if 5 - 5: Oo0Ooo
  if 100 - 100: Ii1I + iIii1I11I1II1
  if ( len ( o0O0oO0 ) < 12 ) : continue
  if 59 - 59: IiII
  if ( lisp_mymacs . has_key ( o0O0oO0 ) == False ) : lisp_mymacs [ o0O0oO0 ] = [ ]
  lisp_mymacs [ o0O0oO0 ] . append ( Ooooo )
  if 89 - 89: OoOoOO00 % iIii1I11I1II1
  if 35 - 35: I1ii11iIi11i + I1Ii111 - OoOoOO00 % oO0o % o0oOOo0O0Ooo % OoOoOO00
 lprint ( "Local MACs are: {}" . format ( lisp_mymacs ) )
 return
 if 45 - 45: I1IiiI * OOooOOo % OoO0O00
 if 24 - 24: ooOoO0o - I11i * oO0o
 if 87 - 87: Ii1I - I1ii11iIi11i % I1ii11iIi11i . oO0o / I1ii11iIi11i
 if 6 - 6: OoOoOO00 / iIii1I11I1II1 * OoooooooOO * i11iIiiIii
 if 79 - 79: IiII % OoO0O00
 if 81 - 81: i11iIiiIii + i11iIiiIii * OoO0O00 + IiII
 if 32 - 32: O0 . OoooooooOO
 if 15 - 15: I1IiiI . OoO0O00
def lisp_get_local_rloc ( ) :
 IiiIi = commands . getoutput ( "netstat -rn | egrep 'default|0.0.0.0'" )
 if ( IiiIi == "" ) : return ( lisp_address ( LISP_AFI_IPV4 , "" , 32 , 0 ) )
 if 42 - 42: iII111i + iIii1I11I1II1
 if 21 - 21: OoOoOO00 - Oo0Ooo % O0 . OoO0O00 + OoOoOO00
 if 41 - 41: II111iiii * ooOoO0o
 if 68 - 68: Ii1I - I1IiiI
 IiiIi = IiiIi . split ( "\n" ) [ 0 ]
 Ooooo = IiiIi . split ( ) [ - 1 ]
 if 41 - 41: oO0o
 I1Iii1I = ""
 I11II1 = lisp_is_macos ( )
 if ( I11II1 ) :
  IiiIi = commands . getoutput ( "ifconfig {} | egrep 'inet '" . format ( Ooooo ) )
  if ( IiiIi == "" ) : return ( lisp_address ( LISP_AFI_IPV4 , "" , 32 , 0 ) )
 else :
  i1i1i1I = 'ip addr show | egrep "inet " | egrep "{}"' . format ( Ooooo )
  IiiIi = commands . getoutput ( i1i1i1I )
  if ( IiiIi == "" ) :
   i1i1i1I = 'ip addr show | egrep "inet " | egrep "global lo"'
   IiiIi = commands . getoutput ( i1i1i1I )
   if 60 - 60: Oo0Ooo + I1ii11iIi11i - i11iIiiIii - I1ii11iIi11i % Oo0Ooo / iIii1I11I1II1
  if ( IiiIi == "" ) : return ( lisp_address ( LISP_AFI_IPV4 , "" , 32 , 0 ) )
  if 14 - 14: OoO0O00 / ooOoO0o - OOooOOo / I1IiiI
  if 27 - 27: i1IIi + I1IiiI * I1ii11iIi11i + OOooOOo . oO0o
  if 1 - 1: OOooOOo * IiII + I11i
  if 77 - 77: oO0o % i11iIiiIii . OOooOOo % OOooOOo
  if 36 - 36: Oo0Ooo % Ii1I / i11iIiiIii % I1Ii111 + OoO0O00
  if 23 - 23: II111iiii
 I1Iii1I = ""
 IiiIi = IiiIi . split ( "\n" )
 if 93 - 93: oO0o . I11i / i1IIi
 for i11ii in IiiIi :
  OOOO0o = i11ii . split ( ) [ 1 ]
  if ( I11II1 == False ) : OOOO0o = OOOO0o . split ( "/" ) [ 0 ]
  oOOOOO0Ooooo = lisp_address ( LISP_AFI_IPV4 , OOOO0o , 32 , 0 )
  return ( oOOOOO0Ooooo )
  if 57 - 57: Ii1I - OoooooooOO
 return ( lisp_address ( LISP_AFI_IPV4 , I1Iii1I , 32 , 0 ) )
 if 68 - 68: o0oOOo0O0Ooo % I1ii11iIi11i / I1Ii111 + I1Ii111 - I1Ii111 . OoO0O00
 if 100 - 100: OoOoOO00 % Oo0Ooo
 if 76 - 76: II111iiii / OoO0O00 + OoooooooOO . I1ii11iIi11i . I11i . ooOoO0o
 if 43 - 43: i1IIi
 if 17 - 17: O0 - OoOoOO00
 if 81 - 81: I1IiiI - iIii1I11I1II1 / I1IiiI / O0
 if 34 - 34: Ii1I * Ii1I - I1ii11iIi11i - O0 . i11iIiiIii
 if 32 - 32: iIii1I11I1II1 . OoO0O00 * oO0o / OOooOOo . II111iiii - Oo0Ooo
 if 10 - 10: I1ii11iIi11i / i11iIiiIii - Ii1I + oO0o * I1IiiI
 if 94 - 94: I1IiiI + iIii1I11I1II1 / O0 - OoooooooOO % I1ii11iIi11i
 if 64 - 64: I11i + OoO0O00
def lisp_get_local_addresses ( ) :
 global lisp_myrlocs
 if 25 - 25: I1IiiI . ooOoO0o + I1IiiI % Ii1I * iIii1I11I1II1
 if 31 - 31: i11iIiiIii + OOooOOo - O0
 if 51 - 51: OoO0O00 * i1IIi / Ii1I * OOooOOo + ooOoO0o % I1ii11iIi11i
 if 34 - 34: oO0o * OoooooooOO + Ii1I + i11iIiiIii
 if 22 - 22: i1IIi
 if 24 - 24: I11i / I1IiiI * i1IIi % OoooooooOO
 if 99 - 99: i11iIiiIii . II111iiii . OoooooooOO
 if 59 - 59: i11iIiiIii . OoooooooOO / I11i * I1ii11iIi11i + OoooooooOO
 if 3 - 3: i11iIiiIii * Oo0Ooo % iIii1I11I1II1 % I1IiiI * iII111i / OOooOOo
 if 95 - 95: IiII * O0 * I1Ii111 . OoooooooOO % Oo0Ooo + I1ii11iIi11i
 oOIii11111iiI = None
 OOOoO000 = 1
 o0OOOOoO = os . getenv ( "LISP_ADDR_SELECT" )
 if ( o0OOOOoO != None and o0OOOOoO != "" ) :
  o0OOOOoO = o0OOOOoO . split ( ":" )
  if ( len ( o0OOOOoO ) == 2 ) :
   oOIii11111iiI = o0OOOOoO [ 0 ]
   OOOoO000 = o0OOOOoO [ 1 ]
  else :
   if ( o0OOOOoO [ 0 ] . isdigit ( ) ) :
    OOOoO000 = o0OOOOoO [ 0 ]
   else :
    oOIii11111iiI = o0OOOOoO [ 0 ]
    if 70 - 70: II111iiii + I1Ii111 + i11iIiiIii - i1IIi / IiII
    if 40 - 40: I1ii11iIi11i * I1Ii111
  OOOoO000 = 1 if ( OOOoO000 == "" ) else int ( OOOoO000 )
  if 38 - 38: O0 . Oo0Ooo + OoOoOO00 - oO0o
  if 43 - 43: iII111i + Oo0Ooo / OoooooooOO
 Ii1II1 = [ None , None , None ]
 oo = lisp_address ( LISP_AFI_IPV4 , "" , 32 , 0 )
 ii11i = lisp_address ( LISP_AFI_IPV6 , "" , 128 , 0 )
 O000oo00OOOOO = None
 if 52 - 52: Oo0Ooo . I11i / o0oOOo0O0Ooo + Ii1I % I11i
 for Ooooo in netifaces . interfaces ( ) :
  if ( oOIii11111iiI != None and oOIii11111iiI != Ooooo ) : continue
  II111 = netifaces . ifaddresses ( Ooooo )
  if ( II111 == { } ) : continue
  if 47 - 47: OoooooooOO / OOooOOo % OoO0O00 / Oo0Ooo - I1ii11iIi11i
  if 13 - 13: iII111i . I1IiiI * OOooOOo + Ii1I + I1IiiI - i11iIiiIii
  if 79 - 79: ooOoO0o . oO0o / oO0o - ooOoO0o * Oo0Ooo / o0oOOo0O0Ooo
  if 19 - 19: I1ii11iIi11i
  O000oo00OOOOO = lisp_get_interface_instance_id ( Ooooo , None )
  if 46 - 46: iIii1I11I1II1 . i11iIiiIii - OoOoOO00 % O0 / II111iiii * i1IIi
  if 66 - 66: O0
  if 52 - 52: OoO0O00 * OoooooooOO
  if 12 - 12: O0 + IiII * i1IIi . OoO0O00
  if ( II111 . has_key ( netifaces . AF_INET ) ) :
   II11iIi = II111 [ netifaces . AF_INET ]
   o0OO0oooo = 0
   for I1Iii1I in II11iIi :
    oo . store_address ( I1Iii1I [ "addr" ] )
    if ( oo . is_ipv4_loopback ( ) ) : continue
    if ( oo . is_ipv4_link_local ( ) ) : continue
    if ( oo . address == 0 ) : continue
    o0OO0oooo += 1
    oo . instance_id = O000oo00OOOOO
    if ( oOIii11111iiI == None and
 lisp_db_for_lookups . lookup_cache ( oo , False ) ) : continue
    Ii1II1 [ 0 ] = oo
    if ( o0OO0oooo == OOOoO000 ) : break
    if 40 - 40: I1Ii111 - OoOoOO00 * I11i - IiII / OoOoOO00
    if 71 - 71: oO0o / OoooooooOO % IiII / OoOoOO00 % I1Ii111
  if ( II111 . has_key ( netifaces . AF_INET6 ) ) :
   iiO0O0o0oO0O00 = II111 [ netifaces . AF_INET6 ]
   o0OO0oooo = 0
   for I1Iii1I in iiO0O0o0oO0O00 :
    OoOOoooO000 = I1Iii1I [ "addr" ]
    ii11i . store_address ( OoOOoooO000 )
    if ( ii11i . is_ipv6_string_link_local ( OoOOoooO000 ) ) : continue
    if ( ii11i . is_ipv6_loopback ( ) ) : continue
    o0OO0oooo += 1
    ii11i . instance_id = O000oo00OOOOO
    if ( oOIii11111iiI == None and
 lisp_db_for_lookups . lookup_cache ( ii11i , False ) ) : continue
    Ii1II1 [ 1 ] = ii11i
    if ( o0OO0oooo == OOOoO000 ) : break
    if 19 - 19: I1Ii111 + IiII / oO0o / II111iiii
    if 92 - 92: i1IIi % ooOoO0o + ooOoO0o - iIii1I11I1II1 . Ii1I
    if 33 - 33: o0oOOo0O0Ooo / O0 + OOooOOo
    if 75 - 75: IiII % i11iIiiIii + iIii1I11I1II1
    if 92 - 92: OoOoOO00 % O0
    if 55 - 55: iIii1I11I1II1 * iII111i
  if ( Ii1II1 [ 0 ] == None ) : continue
  if 85 - 85: iIii1I11I1II1 . II111iiii
  Ii1II1 [ 2 ] = Ooooo
  break
  if 54 - 54: Ii1I . OoooooooOO % Oo0Ooo
  if 22 - 22: OOooOOo
 I1I11Iiii111 = Ii1II1 [ 0 ] . print_address_no_iid ( ) if Ii1II1 [ 0 ] else "none"
 iI1 = Ii1II1 [ 1 ] . print_address_no_iid ( ) if Ii1II1 [ 1 ] else "none"
 Ooooo = Ii1II1 [ 2 ] if Ii1II1 [ 2 ] else "none"
 if 34 - 34: i1IIi % IiII
 oOIii11111iiI = " (user selected)" if oOIii11111iiI != None else ""
 if 80 - 80: OoooooooOO / iIii1I11I1II1 + I1ii11iIi11i / i1IIi / o0oOOo0O0Ooo
 I1I11Iiii111 = red ( I1I11Iiii111 , False )
 iI1 = red ( iI1 , False )
 Ooooo = bold ( Ooooo , False )
 lprint ( "Local addresses are IPv4: {}, IPv6: {} from device {}{}, iid {}" . format ( I1I11Iiii111 , iI1 , Ooooo , oOIii11111iiI , O000oo00OOOOO ) )
 if 94 - 94: i1IIi
 if 36 - 36: I1IiiI + Oo0Ooo
 lisp_myrlocs = Ii1II1
 return ( ( Ii1II1 [ 0 ] != None ) )
 if 46 - 46: iII111i
 if 65 - 65: i1IIi . I1ii11iIi11i / ooOoO0o
 if 11 - 11: IiII * ooOoO0o / ooOoO0o - OOooOOo
 if 68 - 68: I1IiiI % IiII - IiII / I1IiiI + I1ii11iIi11i - Oo0Ooo
 if 65 - 65: ooOoO0o - i1IIi
 if 62 - 62: I11i / oO0o % Oo0Ooo . OoooooooOO / i11iIiiIii / I1Ii111
 if 60 - 60: I1IiiI % oO0o / o0oOOo0O0Ooo % oO0o * i11iIiiIii / iII111i
 if 34 - 34: I1Ii111 - OOooOOo
 if 25 - 25: oO0o % I1IiiI + i11iIiiIii + O0 * OoooooooOO
def lisp_get_all_addresses ( ) :
 ooO0 = [ ]
 for iIiiiIiIi in netifaces . interfaces ( ) :
  try : o0Iiii = netifaces . ifaddresses ( iIiiiIiIi )
  except : continue
  if 45 - 45: Ii1I / ooOoO0o . OoooooooOO + OoO0O00
  if ( o0Iiii . has_key ( netifaces . AF_INET ) ) :
   for I1Iii1I in o0Iiii [ netifaces . AF_INET ] :
    OOOO0o = I1Iii1I [ "addr" ]
    if ( OOOO0o . find ( "127.0.0.1" ) != - 1 ) : continue
    ooO0 . append ( OOOO0o )
    if 51 - 51: iII111i % i11iIiiIii % IiII + I1Ii111 % I1ii11iIi11i
    if 16 - 16: OoOoOO00 / Oo0Ooo + O0 - OoOoOO00 . OoooooooOO
  if ( o0Iiii . has_key ( netifaces . AF_INET6 ) ) :
   for I1Iii1I in o0Iiii [ netifaces . AF_INET6 ] :
    OOOO0o = I1Iii1I [ "addr" ]
    if ( OOOO0o == "::1" ) : continue
    if ( OOOO0o [ 0 : 5 ] == "fe80:" ) : continue
    ooO0 . append ( OOOO0o )
    if 19 - 19: o0oOOo0O0Ooo
    if 73 - 73: I1Ii111 * Oo0Ooo * OoOoOO00
    if 65 - 65: i11iIiiIii + Oo0Ooo * OoooooooOO - OoO0O00
 return ( ooO0 )
 if 26 - 26: o0oOOo0O0Ooo % OOooOOo + OOooOOo % I11i * i11iIiiIii / iII111i
 if 64 - 64: oO0o % OoOoOO00 / II111iiii % ooOoO0o - iII111i
 if 2 - 2: I1Ii111 - I1ii11iIi11i + o0oOOo0O0Ooo * OoO0O00 / iII111i
 if 26 - 26: OOooOOo * Oo0Ooo
 if 31 - 31: I11i * oO0o . Ii1I
 if 35 - 35: I11i
 if 94 - 94: ooOoO0o / i11iIiiIii % O0
 if 70 - 70: I11i - Oo0Ooo / OoooooooOO % OoooooooOO
def lisp_get_all_multicast_rles ( ) :
 oooo0o0OOO0 = [ ]
 IiiIi = commands . getoutput ( 'egrep "rle-address =" ./lisp.config' )
 if ( IiiIi == "" ) : return ( oooo0o0OOO0 )
 if 17 - 17: II111iiii + I1IiiI
 ooo0oO0oOo = IiiIi . split ( "\n" )
 for i11ii in ooo0oO0oOo :
  if ( i11ii [ 0 ] == "#" ) : continue
  O0OOOO0000O = i11ii . split ( "rle-address = " ) [ 1 ]
  iiiI11 = int ( O0OOOO0000O . split ( "." ) [ 0 ] )
  if ( iiiI11 >= 224 and iiiI11 < 240 ) : oooo0o0OOO0 . append ( O0OOOO0000O )
  if 89 - 89: oO0o
 return ( oooo0o0OOO0 )
 if 87 - 87: iII111i % Oo0Ooo
 if 62 - 62: OoO0O00 + ooOoO0o / iII111i * i11iIiiIii
 if 37 - 37: iII111i
 if 33 - 33: OoO0O00 - O0 - OoO0O00
 if 94 - 94: IiII * I11i * OoooooooOO / o0oOOo0O0Ooo . IiII - o0oOOo0O0Ooo
 if 13 - 13: OOooOOo / IiII - OoO0O00 / OOooOOo . i1IIi
 if 22 - 22: O0 - I11i + I1Ii111 . Ii1I * i1IIi
 if 26 - 26: iIii1I11I1II1 * o0oOOo0O0Ooo . I11i
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
  if 10 - 10: I1Ii111 * oO0o % Oo0Ooo - I11i % Oo0Ooo
  if 65 - 65: iII111i * iIii1I11I1II1 / O0 . I11i
 def encode ( self , nonce ) :
  if 94 - 94: Oo0Ooo . ooOoO0o * i11iIiiIii - o0oOOo0O0Ooo . iII111i
  if 98 - 98: OOooOOo + Ii1I
  if 52 - 52: Oo0Ooo / OoOoOO00 - I1Ii111 . iII111i
  if 50 - 50: iIii1I11I1II1 - iII111i - I11i
  if 60 - 60: iIii1I11I1II1 * ooOoO0o
  if ( self . outer_source . is_null ( ) ) : return ( None )
  if 71 - 71: OoOoOO00 % Oo0Ooo % ooOoO0o
  if 34 - 34: I11i / I11i % IiII . OoOoOO00 / Oo0Ooo
  if 99 - 99: ooOoO0o * I1IiiI - ooOoO0o % Ii1I
  if 40 - 40: OOooOOo / IiII / iIii1I11I1II1 + Ii1I
  if 59 - 59: I11i * OoooooooOO + OOooOOo . iIii1I11I1II1 / i1IIi
  if 75 - 75: I11i . OOooOOo - iIii1I11I1II1 * OoO0O00 * iII111i
  if ( nonce == None ) :
   self . lisp_header . nonce ( lisp_get_data_nonce ( ) )
  elif ( self . lisp_header . is_request_nonce ( nonce ) ) :
   self . lisp_header . request_nonce ( nonce )
  else :
   self . lisp_header . nonce ( nonce )
   if 93 - 93: ooOoO0o
  self . lisp_header . instance_id ( self . inner_dest . instance_id )
  if 18 - 18: ooOoO0o
  if 66 - 66: oO0o * i11iIiiIii + OoOoOO00 / OOooOOo
  if 96 - 96: OOooOOo + OOooOOo % IiII % OOooOOo
  if 28 - 28: iIii1I11I1II1 + OoOoOO00 . o0oOOo0O0Ooo % i11iIiiIii
  if 58 - 58: I11i / OoooooooOO % oO0o + OoO0O00
  if 58 - 58: O0
  self . lisp_header . key_id ( 0 )
  O0oO = ( self . lisp_header . get_instance_id ( ) == 0xffffff )
  if ( lisp_data_plane_security and O0oO == False ) :
   OoOOoooO000 = self . outer_dest . print_address_no_iid ( ) + ":" + str ( self . encap_port )
   if 54 - 54: o0oOOo0O0Ooo + I11i - iIii1I11I1II1 % ooOoO0o % IiII
   if ( lisp_crypto_keys_by_rloc_encap . has_key ( OoOOoooO000 ) ) :
    II1i = lisp_crypto_keys_by_rloc_encap [ OoOOoooO000 ]
    if ( II1i [ 1 ] ) :
     II1i [ 1 ] . use_count += 1
     iI1IIII1ii1 , OOO0O0OOo = self . encrypt ( II1i [ 1 ] , OoOOoooO000 )
     if ( OOO0O0OOo ) : self . packet = iI1IIII1ii1
     if 10 - 10: OoooooooOO / iII111i / oO0o * Oo0Ooo / iIii1I11I1II1
     if 63 - 63: II111iiii
     if 39 - 39: O0 + OoO0O00 / o0oOOo0O0Ooo % I11i . OOooOOo * OoooooooOO
     if 38 - 38: oO0o % OoooooooOO + OoO0O00 * i11iIiiIii
     if 61 - 61: iIii1I11I1II1
     if 11 - 11: oO0o . I1IiiI + IiII / i1IIi
     if 1 - 1: Oo0Ooo * I1Ii111 . OoooooooOO
     if 73 - 73: OoOoOO00 % o0oOOo0O0Ooo
  self . udp_checksum = 0
  if ( self . encap_port == LISP_DATA_PORT ) :
   if ( lisp_crypto_ephem_port == None ) :
    self . hash_packet ( )
   else :
    self . udp_sport = lisp_crypto_ephem_port
    if 71 - 71: oO0o - OoooooooOO * Oo0Ooo * I11i + o0oOOo0O0Ooo * I1ii11iIi11i
  else :
   self . udp_sport = LISP_DATA_PORT
   if 85 - 85: i11iIiiIii . OoooooooOO - iIii1I11I1II1
  self . udp_dport = self . encap_port
  self . udp_length = len ( self . packet ) + 16
  if 38 - 38: I11i . I11i * oO0o / OoooooooOO % ooOoO0o
  if 80 - 80: OoO0O00 / IiII * I1IiiI % IiII
  if 95 - 95: O0 / I11i . I1Ii111
  if 17 - 17: I11i
  if ( self . outer_version == 4 ) :
   o0OO0OO000OO = socket . htons ( self . udp_sport )
   O00o0000OO = socket . htons ( self . udp_dport )
  else :
   o0OO0OO000OO = self . udp_sport
   O00o0000OO = self . udp_dport
   if 61 - 61: IiII % i1IIi - iII111i . ooOoO0o - Oo0Ooo + Oo0Ooo
   if 12 - 12: o0oOOo0O0Ooo / iIii1I11I1II1 % II111iiii / I11i / i1IIi - I1IiiI
  O00o0000OO = socket . htons ( self . udp_dport ) if self . outer_version == 4 else self . udp_dport
  if 94 - 94: i11iIiiIii % oO0o + Oo0Ooo + oO0o
  if 33 - 33: IiII . Oo0Ooo / iIii1I11I1II1
  IIi1ii1 = struct . pack ( "HHHH" , o0OO0OO000OO , O00o0000OO , socket . htons ( self . udp_length ) ,
 self . udp_checksum )
  if 50 - 50: o0oOOo0O0Ooo
  if 16 - 16: OoOoOO00
  if 16 - 16: Oo0Ooo / OoO0O00 / iII111i / iIii1I11I1II1
  if 44 - 44: Oo0Ooo . Oo0Ooo + OoooooooOO * i11iIiiIii / I11i + I1Ii111
  iIiII11 = self . lisp_header . encode ( )
  if 33 - 33: o0oOOo0O0Ooo * iII111i * iIii1I11I1II1 + i11iIiiIii . OoooooooOO
  if 51 - 51: OOooOOo / ooOoO0o + OoO0O00 % OoOoOO00 / Ii1I
  if 25 - 25: o0oOOo0O0Ooo
  if 25 - 25: ooOoO0o * iII111i / I11i / I11i % o0oOOo0O0Ooo
  if 19 - 19: oO0o - iIii1I11I1II1 / ooOoO0o . OoO0O00 * O0 - O0
  if ( self . outer_version == 4 ) :
   iiIIIIiii = socket . htons ( self . udp_length + 20 )
   iiii1 = socket . htons ( 0x4000 )
   iii1IiiiI1i1 = struct . pack ( "BBHHHBBH" , 0x45 , self . outer_tos , iiIIIIiii , 0xdfdf ,
 iiii1 , self . outer_ttl , 17 , 0 )
   iii1IiiiI1i1 += self . outer_source . pack_address ( )
   iii1IiiiI1i1 += self . outer_dest . pack_address ( )
   iii1IiiiI1i1 = lisp_ip_checksum ( iii1IiiiI1i1 )
  elif ( self . outer_version == 6 ) :
   iii1IiiiI1i1 = ""
   if 37 - 37: Oo0Ooo - i1IIi - IiII + I11i . iIii1I11I1II1
   if 59 - 59: OoooooooOO - I1Ii111 % o0oOOo0O0Ooo . I11i + i1IIi * I11i
   if 5 - 5: II111iiii - IiII
   if 86 - 86: IiII * I11i + O0 * I1Ii111 + i11iIiiIii - I1ii11iIi11i
   if 70 - 70: i11iIiiIii
   if 57 - 57: I11i % OOooOOo + ooOoO0o * Ii1I . Oo0Ooo
   if 78 - 78: OoooooooOO / i1IIi . OOooOOo
  else :
   return ( None )
   if 88 - 88: I11i + I1IiiI - I11i / OoooooooOO - i11iIiiIii
   if 24 - 24: iIii1I11I1II1
  self . packet = iii1IiiiI1i1 + IIi1ii1 + iIiII11 + self . packet
  return ( self )
  if 89 - 89: Ii1I / i1IIi - o0oOOo0O0Ooo % I1IiiI . Oo0Ooo - O0
  if 71 - 71: OoO0O00 % I1IiiI - iII111i . iII111i
 def cipher_pad ( self , packet ) :
  I1I1 = len ( packet )
  if ( ( I1I1 % 16 ) != 0 ) :
   O0O = ( ( I1I1 / 16 ) + 1 ) * 16
   packet = packet . ljust ( O0O )
   if 66 - 66: I1ii11iIi11i - i1IIi % I1ii11iIi11i / Ii1I % i1IIi . I11i
  return ( packet )
  if 37 - 37: OoooooooOO . IiII / OoOoOO00 / oO0o % OoooooooOO . OoooooooOO
  if 40 - 40: O0 . I1Ii111 / iIii1I11I1II1 * o0oOOo0O0Ooo
 def encrypt ( self , key , addr_str ) :
  if ( key == None or key . shared_key == None ) :
   return ( [ self . packet , False ] )
   if 73 - 73: Oo0Ooo - iII111i . oO0o % i1IIi . O0
   if 15 - 15: ooOoO0o . iIii1I11I1II1 * I1IiiI % I11i
   if 21 - 21: OoO0O00 - I1IiiI . OoooooooOO
   if 6 - 6: iIii1I11I1II1 - iIii1I11I1II1 % o0oOOo0O0Ooo / iIii1I11I1II1 * I1Ii111
   if 3 - 3: OOooOOo . IiII / Oo0Ooo
  iI1IIII1ii1 = self . cipher_pad ( self . packet )
  Ooo = key . get_iv ( )
  if 11 - 11: oO0o + I1Ii111 . IiII * OoooooooOO - I1ii11iIi11i - OOooOOo
  III11I1 = lisp_get_timestamp ( )
  I1Ii1 = None
  if ( key . cipher_suite == LISP_CS_25519_CHACHA ) :
   O0oo0oOoO00 = chacha . ChaCha ( key . encrypt_key , Ooo ) . encrypt
  elif ( key . cipher_suite == LISP_CS_25519_GCM ) :
   i1ii1iIi = binascii . unhexlify ( key . encrypt_key )
   try :
    I1I1Ii = AES . new ( i1ii1iIi , AES . MODE_GCM , Ooo )
    O0oo0oOoO00 = I1I1Ii . encrypt
    I1Ii1 = I1I1Ii . digest
   except :
    lprint ( "You need AES-GCM, do a 'pip install pycryptodome'" )
    return ( [ self . packet , False ] )
    if 42 - 42: o0oOOo0O0Ooo - Oo0Ooo % I1ii11iIi11i
  else :
   i1ii1iIi = binascii . unhexlify ( key . encrypt_key )
   O0oo0oOoO00 = AES . new ( i1ii1iIi , AES . MODE_CBC , Ooo ) . encrypt
   if 43 - 43: I11i % i1IIi % ooOoO0o . i11iIiiIii
   if 56 - 56: O0 * iII111i + iII111i * iIii1I11I1II1 / ooOoO0o * I1Ii111
  Ii = O0oo0oOoO00 ( iI1IIII1ii1 )
  if 97 - 97: i11iIiiIii + Oo0Ooo * OOooOOo % iII111i . IiII
  if ( Ii == None ) : return ( [ self . packet , False ] )
  III11I1 = int ( str ( time . time ( ) - III11I1 ) . split ( "." ) [ 1 ] [ 0 : 6 ] )
  if 4 - 4: O0 . iII111i - iIii1I11I1II1
  if 19 - 19: OOooOOo % OoO0O00 / Ii1I + II111iiii % OoooooooOO
  if 89 - 89: Ii1I
  if 51 - 51: iII111i
  if 68 - 68: iII111i - o0oOOo0O0Ooo * OoO0O00 % ooOoO0o . ooOoO0o - iIii1I11I1II1
  if 22 - 22: OoooooooOO / I1ii11iIi11i % iII111i * OoOoOO00
  if ( I1Ii1 != None ) : Ii += I1Ii1 ( )
  if 32 - 32: OoooooooOO % oO0o % iIii1I11I1II1 / O0
  if 61 - 61: II111iiii . O0 - Ii1I - I1ii11iIi11i / i11iIiiIii - II111iiii
  if 98 - 98: Ii1I - I1IiiI . i11iIiiIii * Oo0Ooo
  if 29 - 29: Ii1I / ooOoO0o % I11i
  if 10 - 10: iIii1I11I1II1 % OoooooooOO % I1ii11iIi11i
  self . lisp_header . key_id ( key . key_id )
  iIiII11 = self . lisp_header . encode ( )
  if 39 - 39: II111iiii * OoOoOO00 . O0 * I11i
  O0o0O0O0O = key . do_icv ( iIiII11 + Ooo + Ii , Ooo )
  if 79 - 79: IiII + IiII + Ii1I
  iiiII1i1I = 4 if ( key . do_poly ) else 8
  if 97 - 97: O0 . I1Ii111 / II111iiii . O0 + OoooooooOO
  oo0OooO = bold ( "Encrypt" , False )
  I11iI1 = bold ( key . cipher_suite_string , False )
  addr_str = "RLOC: " + red ( addr_str , False )
  oOo00OO0o0 = "poly" if key . do_poly else "sha256"
  oOo00OO0o0 = bold ( oOo00OO0o0 , False )
  IiIiI = "ICV({}): 0x{}...{}" . format ( oOo00OO0o0 , O0o0O0O0O [ 0 : iiiII1i1I ] , O0o0O0O0O [ - iiiII1i1I : : ] )
  dprint ( "{} for key-id: {}, {}, {}, {}-time: {} usec" . format ( oo0OooO , key . key_id , addr_str , IiIiI , I11iI1 , III11I1 ) )
  if 47 - 47: OoOoOO00
  if 65 - 65: O0 + I1Ii111 % Ii1I * I1IiiI / ooOoO0o / OoOoOO00
  O0o0O0O0O = int ( O0o0O0O0O , 16 )
  if ( key . do_poly ) :
   oooOO = byte_swap_64 ( ( O0o0O0O0O >> 64 ) & LISP_8_64_MASK )
   iI1IIIi11 = byte_swap_64 ( O0o0O0O0O & LISP_8_64_MASK )
   O0o0O0O0O = struct . pack ( "QQ" , oooOO , iI1IIIi11 )
  else :
   oooOO = byte_swap_64 ( ( O0o0O0O0O >> 96 ) & LISP_8_64_MASK )
   iI1IIIi11 = byte_swap_64 ( ( O0o0O0O0O >> 32 ) & LISP_8_64_MASK )
   oooOo00O0 = socket . htonl ( O0o0O0O0O & 0xffffffff )
   O0o0O0O0O = struct . pack ( "QQI" , oooOO , iI1IIIi11 , oooOo00O0 )
   if 26 - 26: I1Ii111 . Ii1I + I1IiiI . OoOoOO00 + OOooOOo
   if 17 - 17: OOooOOo + i11iIiiIii + I1ii11iIi11i % OOooOOo . oO0o
  return ( [ Ooo + Ii + O0o0O0O0O , True ] )
  if 33 - 33: I11i * I1IiiI % OoOoOO00 . IiII . ooOoO0o . OoO0O00
  if 53 - 53: OoOoOO00
 def decrypt ( self , packet , header_length , key , addr_str ) :
  if 84 - 84: OoO0O00
  if 97 - 97: i1IIi
  if 98 - 98: OoooooooOO - I1IiiI + ooOoO0o
  if 98 - 98: iII111i . IiII . IiII - OOooOOo
  if 65 - 65: Oo0Ooo + o0oOOo0O0Ooo - Ii1I
  if 12 - 12: OoooooooOO + I1ii11iIi11i
  if ( key . do_poly ) :
   oooOO , iI1IIIi11 = struct . unpack ( "QQ" , packet [ - 16 : : ] )
   o0OoO0000oOO = byte_swap_64 ( oooOO ) << 64
   o0OoO0000oOO |= byte_swap_64 ( iI1IIIi11 )
   o0OoO0000oOO = lisp_hex_string ( o0OoO0000oOO ) . zfill ( 32 )
   packet = packet [ 0 : - 16 ]
   iiiII1i1I = 4
   i1iIIiiIiII = bold ( "poly" , False )
  else :
   oooOO , iI1IIIi11 , oooOo00O0 = struct . unpack ( "QQI" , packet [ - 20 : : ] )
   o0OoO0000oOO = byte_swap_64 ( oooOO ) << 96
   o0OoO0000oOO |= byte_swap_64 ( iI1IIIi11 ) << 32
   o0OoO0000oOO |= socket . htonl ( oooOo00O0 )
   o0OoO0000oOO = lisp_hex_string ( o0OoO0000oOO ) . zfill ( 40 )
   packet = packet [ 0 : - 20 ]
   iiiII1i1I = 8
   i1iIIiiIiII = bold ( "sha" , False )
   if 20 - 20: ooOoO0o . OoO0O00 * iII111i
  iIiII11 = self . lisp_header . encode ( )
  if 71 - 71: Oo0Ooo . II111iiii / II111iiii * Ii1I * OoO0O00
  if 25 - 25: i11iIiiIii + Oo0Ooo . iII111i % I1IiiI - ooOoO0o * i1IIi
  if 98 - 98: iII111i - iII111i
  if 58 - 58: oO0o
  if ( key . cipher_suite == LISP_CS_25519_CHACHA ) :
   oOOo0OO00OoO = 8
   I11iI1 = bold ( "chacha" , False )
  elif ( key . cipher_suite == LISP_CS_25519_GCM ) :
   oOOo0OO00OoO = 12
   I11iI1 = bold ( "aes-gcm" , False )
  else :
   oOOo0OO00OoO = 16
   I11iI1 = bold ( "aes-cbc" , False )
   if 95 - 95: OoO0O00 . oO0o
  Ooo = packet [ 0 : oOOo0OO00OoO ]
  if 60 - 60: I11i
  if 93 - 93: Oo0Ooo
  if 75 - 75: OoOoOO00
  if 64 - 64: IiII / o0oOOo0O0Ooo / i1IIi
  OOo0OOOoOOo = key . do_icv ( iIiII11 + packet , Ooo )
  if 29 - 29: OoOoOO00 . iII111i + OoOoOO00 + O0 . O0 * OOooOOo
  i1iiiIIi11II = "0x{}...{}" . format ( o0OoO0000oOO [ 0 : iiiII1i1I ] , o0OoO0000oOO [ - iiiII1i1I : : ] )
  o0oooOo0oo = "0x{}...{}" . format ( OOo0OOOoOOo [ 0 : iiiII1i1I ] , OOo0OOOoOOo [ - iiiII1i1I : : ] )
  if 33 - 33: I1Ii111 % II111iiii
  if ( OOo0OOOoOOo != o0OoO0000oOO ) :
   self . packet_error = "ICV-error"
   IIi1II = I11iI1 + "/" + i1iIIiiIiII
   i11i = bold ( "ICV failed ({})" . format ( IIi1II ) , False )
   IiIiI = "packet-ICV {} != computed-ICV {}" . format ( i1iiiIIi11II , o0oooOo0oo )
   dprint ( ( "{} from RLOC {}, receive-port: {}, key-id: {}, " + "packet dropped, {}" ) . format ( i11i , red ( addr_str , False ) ,
   # Ii1I - Ii1I / ooOoO0o
 self . udp_sport , key . key_id , IiIiI ) )
   dprint ( "{}" . format ( key . print_keys ( ) ) )
   if 49 - 49: I11i + oO0o % OoO0O00 - Oo0Ooo - O0 - OoooooooOO
   if 4 - 4: II111iiii - oO0o % Oo0Ooo * i11iIiiIii
   if 18 - 18: Oo0Ooo % O0
   if 66 - 66: iIii1I11I1II1 % i11iIiiIii / I1IiiI
   if 47 - 47: I1ii11iIi11i * oO0o + iIii1I11I1II1 - oO0o / IiII
   if 86 - 86: IiII
   lisp_retry_decap_keys ( addr_str , iIiII11 + packet , Ooo , o0OoO0000oOO )
   return ( [ None , False ] )
   if 43 - 43: I1IiiI / iII111i / ooOoO0o + iIii1I11I1II1 + OoooooooOO
   if 33 - 33: II111iiii - IiII - ooOoO0o
   if 92 - 92: OoO0O00 * IiII
   if 92 - 92: oO0o
   if 7 - 7: iII111i
  packet = packet [ oOOo0OO00OoO : : ]
  if 73 - 73: OoO0O00 % I1ii11iIi11i
  if 32 - 32: OOooOOo + iII111i + iIii1I11I1II1 * Oo0Ooo
  if 62 - 62: i11iIiiIii
  if 2 - 2: I1IiiI
  III11I1 = lisp_get_timestamp ( )
  if ( key . cipher_suite == LISP_CS_25519_CHACHA ) :
   oo0O = chacha . ChaCha ( key . encrypt_key , Ooo ) . decrypt
  elif ( key . cipher_suite == LISP_CS_25519_GCM ) :
   i1ii1iIi = binascii . unhexlify ( key . encrypt_key )
   try :
    oo0O = AES . new ( i1ii1iIi , AES . MODE_GCM , Ooo ) . decrypt
   except :
    self . packet_error = "no-decrypt-key"
    lprint ( "You need AES-GCM, do a 'pip install pycryptodome'" )
    return ( [ None , False ] )
    if 91 - 91: IiII * Ii1I / I1Ii111 . I1IiiI . iII111i - II111iiii
  else :
   if ( ( len ( packet ) % 16 ) != 0 ) :
    dprint ( "Ciphertext not multiple of 16 bytes, packet dropped" )
    return ( [ None , False ] )
    if 18 - 18: OoOoOO00
   i1ii1iIi = binascii . unhexlify ( key . encrypt_key )
   oo0O = AES . new ( i1ii1iIi , AES . MODE_CBC , Ooo ) . decrypt
   if 13 - 13: IiII % OoO0O00 * iIii1I11I1II1 + I1ii11iIi11i - ooOoO0o - I1IiiI
   if 74 - 74: II111iiii / O0
  O0oo0ooo0 = oo0O ( packet )
  III11I1 = int ( str ( time . time ( ) - III11I1 ) . split ( "." ) [ 1 ] [ 0 : 6 ] )
  if 19 - 19: i1IIi
  if 60 - 60: Ii1I * OoOoOO00 / o0oOOo0O0Ooo . I1Ii111
  if 22 - 22: IiII * Ii1I - OoooooooOO
  if 28 - 28: I1IiiI
  oo0OooO = bold ( "Decrypt" , False )
  addr_str = "RLOC: " + red ( addr_str , False )
  oOo00OO0o0 = "poly" if key . do_poly else "sha256"
  oOo00OO0o0 = bold ( oOo00OO0o0 , False )
  IiIiI = "ICV({}): {}" . format ( oOo00OO0o0 , i1iiiIIi11II )
  dprint ( "{} for key-id: {}, {}, {} (good), {}-time: {} usec" . format ( oo0OooO , key . key_id , addr_str , IiIiI , I11iI1 , III11I1 ) )
  if 87 - 87: IiII . i1IIi % OoooooooOO * i11iIiiIii
  if 67 - 67: I1Ii111 / OoO0O00 . OoooooooOO
  if 51 - 51: II111iiii . oO0o . OoO0O00 % II111iiii
  if 41 - 41: OoOoOO00 - OOooOOo + ooOoO0o - i1IIi
  if 6 - 6: II111iiii
  if 7 - 7: i1IIi
  if 63 - 63: iIii1I11I1II1 + IiII % i1IIi / I1IiiI % II111iiii
  self . packet = self . packet [ 0 : header_length ]
  return ( [ O0oo0ooo0 , True ] )
  if 60 - 60: o0oOOo0O0Ooo . OoOoOO00 % I1Ii111 / I1IiiI / O0
  if 19 - 19: i11iIiiIii . I1IiiI + II111iiii / OOooOOo . I1ii11iIi11i * ooOoO0o
 def fragment_outer ( self , outer_hdr , inner_packet ) :
  oo0OOoooo0O0 = 1000
  if 99 - 99: Oo0Ooo + i11iIiiIii
  if 36 - 36: Ii1I * I1Ii111 * iIii1I11I1II1 - I11i % i11iIiiIii
  if 98 - 98: iIii1I11I1II1 - i1IIi + ooOoO0o % I11i + ooOoO0o / oO0o
  if 97 - 97: IiII % ooOoO0o + II111iiii - IiII % OoO0O00 + ooOoO0o
  if 31 - 31: o0oOOo0O0Ooo
  II11i1I = [ ]
  oOO0OO0O = 0
  I1I1 = len ( inner_packet )
  while ( oOO0OO0O < I1I1 ) :
   iiii1 = inner_packet [ oOO0OO0O : : ]
   if ( len ( iiii1 ) > oo0OOoooo0O0 ) : iiii1 = iiii1 [ 0 : oo0OOoooo0O0 ]
   II11i1I . append ( iiii1 )
   oOO0OO0O += len ( iiii1 )
   if 69 - 69: ooOoO0o . OOooOOo - I1IiiI
   if 29 - 29: i11iIiiIii . I1ii11iIi11i / I1IiiI . OOooOOo + i11iIiiIii
   if 26 - 26: IiII / Ii1I - OoooooooOO
   if 9 - 9: OoooooooOO * I1ii11iIi11i
   if 9 - 9: Oo0Ooo + iII111i
   if 64 - 64: O0 * I1IiiI / I1IiiI
  OO0oo = [ ]
  oOO0OO0O = 0
  for iiii1 in II11i1I :
   if 56 - 56: I1ii11iIi11i . oO0o
   if 55 - 55: OoO0O00 * OoO0O00 . I1IiiI
   if 94 - 94: OoO0O00 + OoO0O00 + I1ii11iIi11i . OoO0O00 * Ii1I
   if 62 - 62: o0oOOo0O0Ooo / iIii1I11I1II1
   O0OOo = oOO0OO0O if ( iiii1 == II11i1I [ - 1 ] ) else 0x2000 + oOO0OO0O
   O0OOo = socket . htons ( O0OOo )
   outer_hdr = outer_hdr [ 0 : 6 ] + struct . pack ( "H" , O0OOo ) + outer_hdr [ 8 : : ]
   if 81 - 81: O0 + iII111i . I1IiiI - II111iiii . I1IiiI + O0
   if 75 - 75: O0 % iIii1I11I1II1 / OoOoOO00 % OOooOOo / IiII
   if 31 - 31: i11iIiiIii * OoOoOO00
   if 69 - 69: i11iIiiIii
   ooO = socket . htons ( len ( iiii1 ) + 20 )
   outer_hdr = outer_hdr [ 0 : 2 ] + struct . pack ( "H" , ooO ) + outer_hdr [ 4 : : ]
   outer_hdr = lisp_ip_checksum ( outer_hdr )
   OO0oo . append ( outer_hdr + iiii1 )
   oOO0OO0O += len ( iiii1 ) / 8
   if 84 - 84: iIii1I11I1II1 . ooOoO0o + iII111i
  return ( OO0oo )
  if 85 - 85: OOooOOo % oO0o * oO0o + OoooooooOO
  if 82 - 82: I11i / OoOoOO00 - OOooOOo / ooOoO0o
 def fragment ( self ) :
  iI1IIII1ii1 = self . fix_outer_header ( self . packet )
  if 50 - 50: OOooOOo + OoO0O00 . i11iIiiIii + I1ii11iIi11i + i11iIiiIii
  if 31 - 31: oO0o * I1Ii111 . OoOoOO00 * I11i
  if 28 - 28: IiII + I1IiiI - Oo0Ooo % OOooOOo . I11i + I1IiiI
  if 72 - 72: Ii1I / Oo0Ooo / oO0o * OoOoOO00 + OOooOOo
  if 58 - 58: o0oOOo0O0Ooo % I1IiiI . I1IiiI * OoO0O00 - IiII . OoooooooOO
  if 10 - 10: I1Ii111
  I1I1 = len ( iI1IIII1ii1 )
  if ( I1I1 <= 1500 ) : return ( [ iI1IIII1ii1 ] , "Fragment-None" )
  if 48 - 48: iII111i * i1IIi % OoooooooOO * Ii1I * OoO0O00
  iI1IIII1ii1 = self . packet
  if 7 - 7: iII111i . Ii1I . iII111i - I1Ii111
  if 33 - 33: ooOoO0o + OoooooooOO - OoO0O00 / i1IIi / OoooooooOO
  if 82 - 82: I1ii11iIi11i / OOooOOo - iII111i / Oo0Ooo * OoO0O00
  if 55 - 55: OoooooooOO
  if 73 - 73: OoOoOO00 - I1ii11iIi11i % Oo0Ooo + I1ii11iIi11i - O0 . OoO0O00
  if ( self . inner_version != 4 ) :
   i1iIii = random . randint ( 0 , 0xffff )
   O0o00 = iI1IIII1ii1 [ 0 : 4 ] + struct . pack ( "H" , i1iIii ) + iI1IIII1ii1 [ 6 : 20 ]
   I1IIi1iI1iiI = iI1IIII1ii1 [ 20 : : ]
   OO0oo = self . fragment_outer ( O0o00 , I1IIi1iI1iiI )
   return ( OO0oo , "Fragment-Outer" )
   if 27 - 27: iIii1I11I1II1 % I11i - I1Ii111
   if 67 - 67: O0 / I1Ii111 * Ii1I % ooOoO0o . I1ii11iIi11i * oO0o
   if 9 - 9: II111iiii * i11iIiiIii . OOooOOo - OoO0O00
   if 31 - 31: i11iIiiIii * Ii1I . o0oOOo0O0Ooo % OOooOOo * I1ii11iIi11i % O0
   if 77 - 77: OoO0O00 + OoO0O00 . ooOoO0o * OoooooooOO + OoO0O00
  ii111I1i1 = 56 if ( self . outer_version == 6 ) else 36
  O0o00 = iI1IIII1ii1 [ 0 : ii111I1i1 ]
  ooo = iI1IIII1ii1 [ ii111I1i1 : ii111I1i1 + 20 ]
  I1IIi1iI1iiI = iI1IIII1ii1 [ ii111I1i1 + 20 : : ]
  if 35 - 35: II111iiii / OoOoOO00 - O0 . II111iiii
  if 55 - 55: Oo0Ooo % i1IIi * I11i
  if 95 - 95: OOooOOo / II111iiii - o0oOOo0O0Ooo % I1Ii111 . I11i
  if 63 - 63: iIii1I11I1II1 / ooOoO0o
  II1iOOoOooO0o = struct . unpack ( "H" , ooo [ 6 : 8 ] ) [ 0 ]
  II1iOOoOooO0o = socket . ntohs ( II1iOOoOooO0o )
  if ( II1iOOoOooO0o & 0x4000 ) :
   I1IiiiI = bold ( "DF-bit set" , False )
   dprint ( "{} in inner header, packet discarded" . format ( I1IiiiI ) )
   return ( [ ] , "Fragment-None-DF-bit" )
   if 6 - 6: I1IiiI - i11iIiiIii
   if 61 - 61: I1Ii111 * I1ii11iIi11i % I1IiiI % OoO0O00 % I11i + I11i
  oOO0OO0O = 0
  I1I1 = len ( I1IIi1iI1iiI )
  OO0oo = [ ]
  while ( oOO0OO0O < I1I1 ) :
   OO0oo . append ( I1IIi1iI1iiI [ oOO0OO0O : oOO0OO0O + 1400 ] )
   oOO0OO0O += 1400
   if 6 - 6: Oo0Ooo
   if 73 - 73: I1Ii111 * I1ii11iIi11i + o0oOOo0O0Ooo - Oo0Ooo . I11i
   if 93 - 93: i11iIiiIii
   if 80 - 80: i1IIi . I1IiiI - oO0o + OOooOOo + iII111i % oO0o
   if 13 - 13: II111iiii / OoOoOO00 / OoOoOO00 + ooOoO0o
  II11i1I = OO0oo
  OO0oo = [ ]
  Ii1i = True if II1iOOoOooO0o & 0x2000 else False
  II1iOOoOooO0o = ( II1iOOoOooO0o & 0x1fff ) * 8
  for iiii1 in II11i1I :
   if 62 - 62: OoooooooOO . Ii1I
   if 28 - 28: oO0o . oO0o . iIii1I11I1II1 . OOooOOo . I1ii11iIi11i * i11iIiiIii
   if 72 - 72: I11i
   if 26 - 26: IiII % Oo0Ooo
   OoOOoo = II1iOOoOooO0o / 8
   if ( Ii1i ) :
    OoOOoo |= 0x2000
   elif ( iiii1 != II11i1I [ - 1 ] ) :
    OoOOoo |= 0x2000
    if 38 - 38: oO0o + iIii1I11I1II1 * Ii1I / OoO0O00 + OOooOOo
   OoOOoo = socket . htons ( OoOOoo )
   ooo = ooo [ 0 : 6 ] + struct . pack ( "H" , OoOOoo ) + ooo [ 8 : : ]
   if 48 - 48: OoooooooOO - I1Ii111 . i11iIiiIii * iII111i - Ii1I - o0oOOo0O0Ooo
   if 59 - 59: iII111i / I11i . Oo0Ooo
   if 100 - 100: O0
   if 94 - 94: I1ii11iIi11i - o0oOOo0O0Ooo
   if 42 - 42: o0oOOo0O0Ooo * OoOoOO00 . OoO0O00 - iII111i / II111iiii
   if 25 - 25: Oo0Ooo % OoOoOO00
   I1I1 = len ( iiii1 )
   II1iOOoOooO0o += I1I1
   ooO = socket . htons ( I1I1 + 20 )
   ooo = ooo [ 0 : 2 ] + struct . pack ( "H" , ooO ) + ooo [ 4 : 10 ] + struct . pack ( "H" , 0 ) + ooo [ 12 : : ]
   if 75 - 75: i1IIi
   ooo = lisp_ip_checksum ( ooo )
   OOO0OO = ooo + iiii1
   if 45 - 45: iII111i - o0oOOo0O0Ooo . Ii1I
   if 41 - 41: II111iiii . I1IiiI / OoO0O00 . ooOoO0o
   if 58 - 58: IiII % i11iIiiIii * II111iiii . I1ii11iIi11i
   if 94 - 94: i11iIiiIii . OOooOOo + iIii1I11I1II1 * I1Ii111 * I1Ii111
   if 36 - 36: I11i - IiII . IiII
   I1I1 = len ( OOO0OO )
   if ( self . outer_version == 4 ) :
    ooO = I1I1 + ii111I1i1
    I1I1 += 16
    O0o00 = O0o00 [ 0 : 2 ] + struct . pack ( "H" , ooO ) + O0o00 [ 4 : : ]
    if 60 - 60: i11iIiiIii * Oo0Ooo % OoO0O00 + OoO0O00
    O0o00 = lisp_ip_checksum ( O0o00 )
    OOO0OO = O0o00 + OOO0OO
    OOO0OO = self . fix_outer_header ( OOO0OO )
    if 84 - 84: iIii1I11I1II1 + OoooooooOO
    if 77 - 77: O0 * I1ii11iIi11i * oO0o + OoO0O00 + I1ii11iIi11i - I1Ii111
    if 10 - 10: I1ii11iIi11i + IiII
    if 58 - 58: I1IiiI + OoooooooOO / iII111i . ooOoO0o % o0oOOo0O0Ooo / I1ii11iIi11i
    if 62 - 62: II111iiii
   i1i1111 = ii111I1i1 - 12
   ooO = socket . htons ( I1I1 )
   OOO0OO = OOO0OO [ 0 : i1i1111 ] + struct . pack ( "H" , ooO ) + OOO0OO [ i1i1111 + 2 : : ]
   if 67 - 67: i1IIi
   OO0oo . append ( OOO0OO )
   if 84 - 84: I1Ii111 . o0oOOo0O0Ooo * i11iIiiIii % i11iIiiIii % i1IIi
  return ( OO0oo , "Fragment-Inner" )
  if 95 - 95: o0oOOo0O0Ooo % II111iiii % I11i . iII111i
  if 45 - 45: IiII / I11i * iIii1I11I1II1
 def fix_outer_header ( self , packet ) :
  if 36 - 36: Ii1I
  if 73 - 73: II111iiii - oO0o
  if 52 - 52: I1IiiI % OoO0O00 * Ii1I * iII111i / OOooOOo
  if 88 - 88: oO0o
  if 1 - 1: Oo0Ooo
  if 95 - 95: OoooooooOO / I11i % OoooooooOO / ooOoO0o * IiII
  if 75 - 75: O0
  if 56 - 56: OoO0O00 / II111iiii
  if ( self . outer_version == 4 or self . inner_version == 4 ) :
   if ( lisp_is_macos ( ) ) :
    packet = packet [ 0 : 2 ] + packet [ 3 ] + packet [ 2 ] + packet [ 4 : 6 ] + packet [ 7 ] + packet [ 6 ] + packet [ 8 : : ]
    if 39 - 39: OoOoOO00 - OoooooooOO - i1IIi / II111iiii
   else :
    packet = packet [ 0 : 2 ] + packet [ 3 ] + packet [ 2 ] + packet [ 4 : : ]
    if 49 - 49: Oo0Ooo + O0 + IiII . II111iiii % ooOoO0o
    if 33 - 33: OoOoOO00 . iIii1I11I1II1 / I11i % Ii1I
  return ( packet )
  if 49 - 49: OoO0O00 + II111iiii / IiII - O0 % Ii1I
  if 27 - 27: OoO0O00 + Oo0Ooo
 def send_packet ( self , lisp_raw_socket , dest ) :
  if ( lisp_flow_logging and dest != self . inner_dest ) : self . log_flow ( True )
  if 92 - 92: I1IiiI % iII111i
  dest = dest . print_address_no_iid ( )
  OO0oo , iiiI1IiI = self . fragment ( )
  if 2 - 2: O0 % I1Ii111 % I1ii11iIi11i % o0oOOo0O0Ooo - Oo0Ooo
  for OOO0OO in OO0oo :
   if ( len ( OO0oo ) != 1 ) :
    self . packet = OOO0OO
    self . print_packet ( iiiI1IiI , True )
    if 20 - 20: o0oOOo0O0Ooo
    if 86 - 86: I1Ii111 % I1IiiI
   try : lisp_raw_socket . sendto ( OOO0OO , ( dest , 0 ) )
   except socket . error , I1i11II :
    lprint ( "socket.sendto() failed: {}" . format ( I1i11II ) )
    if 22 - 22: i11iIiiIii * I1Ii111 . Oo0Ooo . OoooooooOO + I1IiiI
    if 24 - 24: II111iiii / Ii1I . iIii1I11I1II1 - II111iiii % O0
    if 8 - 8: OoO0O00 % iII111i . OoooooooOO - Ii1I % OoooooooOO
    if 61 - 61: o0oOOo0O0Ooo / i11iIiiIii
 def send_l2_packet ( self , l2_socket , mac_header ) :
  if ( l2_socket == None ) :
   lprint ( "No layer-2 socket, drop IPv6 packet" )
   return
   if 28 - 28: OOooOOo / OoOoOO00
  if ( mac_header == None ) :
   lprint ( "Could not build MAC header, drop IPv6 packet" )
   return
   if 30 - 30: ooOoO0o
   if 57 - 57: o0oOOo0O0Ooo * i11iIiiIii / OoOoOO00
  iI1IIII1ii1 = mac_header + self . packet
  if 40 - 40: iIii1I11I1II1 - ooOoO0o / Oo0Ooo
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
  l2_socket . write ( iI1IIII1ii1 )
  return
  if 52 - 52: I1Ii111 + I1Ii111
  if 73 - 73: o0oOOo0O0Ooo . i11iIiiIii % OoooooooOO + ooOoO0o . OoooooooOO / OOooOOo
 def bridge_l2_packet ( self , eid , db ) :
  try : oOiiI1i11I = db . dynamic_eids [ eid . print_address_no_iid ( ) ]
  except : return
  try : iIiiiIiIi = lisp_myinterfaces [ oOiiI1i11I . interface ]
  except : return
  try :
   socket = iIiiiIiIi . get_bridge_socket ( )
   if ( socket == None ) : return
  except : return
  if 31 - 31: II111iiii + OOooOOo - OoooooooOO . I11i
  try : socket . send ( self . packet )
  except socket . error , I1i11II :
   lprint ( "bridge_l2_packet(): socket.send() failed: {}" . format ( I1i11II ) )
   if 28 - 28: Ii1I . I1ii11iIi11i
   if 77 - 77: I1ii11iIi11i % II111iiii
   if 81 - 81: OoOoOO00 % Ii1I / O0 * iIii1I11I1II1 % IiII . I1IiiI
 def decode ( self , is_lisp_packet , lisp_ipc_socket , stats ) :
  self . packet_error = ""
  iI1IIII1ii1 = self . packet
  oOOoOoOO = len ( iI1IIII1ii1 )
  iII11 = O00OO00OOOoO = True
  if 47 - 47: i1IIi % ooOoO0o - Oo0Ooo * I11i / i11iIiiIii
  if 45 - 45: I1IiiI . Oo0Ooo . I1Ii111 / oO0o
  if 4 - 4: i11iIiiIii + OOooOOo
  if 26 - 26: iII111i * I1Ii111 * oO0o * OoOoOO00
  I1ii1i11iI1 = 0
  IIiI1i = self . lisp_header . get_instance_id ( )
  if ( is_lisp_packet ) :
   IiOOo0 = struct . unpack ( "B" , iI1IIII1ii1 [ 0 : 1 ] ) [ 0 ]
   self . outer_version = IiOOo0 >> 4
   if ( self . outer_version == 4 ) :
    if 85 - 85: I1Ii111 % I1ii11iIi11i
    if 95 - 95: OoO0O00 * OOooOOo * iII111i . o0oOOo0O0Ooo
    if 73 - 73: OoO0O00
    if 28 - 28: OoooooooOO - I11i
    if 84 - 84: II111iiii
    i1IIii1i = struct . unpack ( "H" , iI1IIII1ii1 [ 10 : 12 ] ) [ 0 ]
    iI1IIII1ii1 = lisp_ip_checksum ( iI1IIII1ii1 )
    iIiI1I1IIi11 = struct . unpack ( "H" , iI1IIII1ii1 [ 10 : 12 ] ) [ 0 ]
    if ( iIiI1I1IIi11 != 0 ) :
     if ( i1IIii1i != 0 or lisp_is_macos ( ) == False ) :
      self . packet_error = "checksum-error"
      if ( stats ) :
       stats [ self . packet_error ] . increment ( oOOoOoOO )
       if 60 - 60: Ii1I % Oo0Ooo / I11i . iII111i / I1Ii111 - OoooooooOO
       if 76 - 76: O0
      lprint ( "IPv4 header checksum failed for outer header" )
      if ( lisp_flow_logging ) : self . log_flow ( False )
      return ( None )
      if 71 - 71: I1IiiI . i1IIi
      if 19 - 19: II111iiii / II111iiii % I1ii11iIi11i + oO0o + oO0o + iII111i
      if 4 - 4: o0oOOo0O0Ooo + I11i / iII111i + i1IIi % o0oOOo0O0Ooo % iII111i
    ooOooOooOOO = LISP_AFI_IPV4
    oOO0OO0O = 12
    self . outer_tos = struct . unpack ( "B" , iI1IIII1ii1 [ 1 : 2 ] ) [ 0 ]
    self . outer_ttl = struct . unpack ( "B" , iI1IIII1ii1 [ 8 : 9 ] ) [ 0 ]
    I1ii1i11iI1 = 20
   elif ( self . outer_version == 6 ) :
    ooOooOooOOO = LISP_AFI_IPV6
    oOO0OO0O = 8
    oO0oOOOo0o = struct . unpack ( "H" , iI1IIII1ii1 [ 0 : 2 ] ) [ 0 ]
    self . outer_tos = ( socket . ntohs ( oO0oOOOo0o ) >> 4 ) & 0xff
    self . outer_ttl = struct . unpack ( "B" , iI1IIII1ii1 [ 7 : 8 ] ) [ 0 ]
    I1ii1i11iI1 = 40
   else :
    self . packet_error = "outer-header-error"
    if ( stats ) : stats [ self . packet_error ] . increment ( oOOoOoOO )
    lprint ( "Cannot decode outer header" )
    return ( None )
    if 47 - 47: iII111i . OoOoOO00
    if 58 - 58: iII111i + Oo0Ooo / I1IiiI
   self . outer_source . afi = ooOooOooOOO
   self . outer_dest . afi = ooOooOooOOO
   o000OO00OoO00 = self . outer_source . addr_length ( )
   if 97 - 97: ooOoO0o / iIii1I11I1II1 % ooOoO0o / I1IiiI * iII111i % OoOoOO00
   self . outer_source . unpack_address ( iI1IIII1ii1 [ oOO0OO0O : oOO0OO0O + o000OO00OoO00 ] )
   oOO0OO0O += o000OO00OoO00
   self . outer_dest . unpack_address ( iI1IIII1ii1 [ oOO0OO0O : oOO0OO0O + o000OO00OoO00 ] )
   iI1IIII1ii1 = iI1IIII1ii1 [ I1ii1i11iI1 : : ]
   self . outer_source . mask_len = self . outer_source . host_mask_len ( )
   self . outer_dest . mask_len = self . outer_dest . host_mask_len ( )
   if 17 - 17: iIii1I11I1II1
   if 89 - 89: i1IIi . i1IIi
   if 10 - 10: iII111i % Oo0Ooo
   if 48 - 48: OOooOOo + I1Ii111 % OOooOOo
   Ooo0o0000OO = struct . unpack ( "H" , iI1IIII1ii1 [ 0 : 2 ] ) [ 0 ]
   self . udp_sport = socket . ntohs ( Ooo0o0000OO )
   Ooo0o0000OO = struct . unpack ( "H" , iI1IIII1ii1 [ 2 : 4 ] ) [ 0 ]
   self . udp_dport = socket . ntohs ( Ooo0o0000OO )
   Ooo0o0000OO = struct . unpack ( "H" , iI1IIII1ii1 [ 4 : 6 ] ) [ 0 ]
   self . udp_length = socket . ntohs ( Ooo0o0000OO )
   Ooo0o0000OO = struct . unpack ( "H" , iI1IIII1ii1 [ 6 : 8 ] ) [ 0 ]
   self . udp_checksum = socket . ntohs ( Ooo0o0000OO )
   iI1IIII1ii1 = iI1IIII1ii1 [ 8 : : ]
   if 8 - 8: I1ii11iIi11i % oO0o / Ii1I
   if 37 - 37: oO0o % I1Ii111 % oO0o
   if 14 - 14: OoO0O00 / I1IiiI
   if 66 - 66: Oo0Ooo / i11iIiiIii % ooOoO0o
   iII11 = ( self . udp_dport == LISP_DATA_PORT or
 self . udp_sport == LISP_DATA_PORT )
   O00OO00OOOoO = ( self . udp_dport in ( LISP_L2_DATA_PORT , LISP_VXLAN_DATA_PORT ) )
   if 43 - 43: OOooOOo
   if 84 - 84: OOooOOo . IiII . iII111i
   if 2 - 2: Oo0Ooo - OoOoOO00
   if 49 - 49: Ii1I + II111iiii / oO0o - OoOoOO00 % OoOoOO00 + I1IiiI
   if ( self . lisp_header . decode ( iI1IIII1ii1 ) == False ) :
    self . packet_error = "lisp-header-error"
    if ( stats ) : stats [ self . packet_error ] . increment ( oOOoOoOO )
    if 54 - 54: ooOoO0o % Oo0Ooo - OOooOOo
    if ( lisp_flow_logging ) : self . log_flow ( False )
    lprint ( "Cannot decode LISP header" )
    return ( None )
    if 16 - 16: I1ii11iIi11i * iII111i / I11i
   iI1IIII1ii1 = iI1IIII1ii1 [ 8 : : ]
   IIiI1i = self . lisp_header . get_instance_id ( )
   I1ii1i11iI1 += 16
   if 46 - 46: II111iiii
  if ( IIiI1i == 0xffffff ) : IIiI1i = 0
  if 13 - 13: IiII + II111iiii % I1IiiI
  if 30 - 30: OoooooooOO - i11iIiiIii + oO0o / Oo0Ooo - i11iIiiIii
  if 74 - 74: O0 . I11i
  if 64 - 64: ooOoO0o / i1IIi % iII111i
  OOoOo0O0 = False
  I1 = self . lisp_header . k_bits
  if ( I1 ) :
   OoOOoooO000 = lisp_get_crypto_decap_lookup_key ( self . outer_source ,
 self . udp_sport )
   if ( OoOOoooO000 == None ) :
    self . packet_error = "no-decrypt-key"
    if ( stats ) : stats [ self . packet_error ] . increment ( oOOoOoOO )
    if 75 - 75: ooOoO0o . OOooOOo / IiII
    self . print_packet ( "Receive" , is_lisp_packet )
    oooIi1II1I11i1I = bold ( "No key available" , False )
    dprint ( "{} for key-id {} to decrypt packet" . format ( oooIi1II1I11i1I , I1 ) )
    if ( lisp_flow_logging ) : self . log_flow ( False )
    return ( None )
    if 91 - 91: OoO0O00 / OoO0O00 . II111iiii . ooOoO0o - I1IiiI
    if 23 - 23: I1IiiI
   i1IIiI1iII = lisp_crypto_keys_by_rloc_decap [ OoOOoooO000 ] [ I1 ]
   if ( i1IIiI1iII == None ) :
    self . packet_error = "no-decrypt-key"
    if ( stats ) : stats [ self . packet_error ] . increment ( oOOoOoOO )
    if 45 - 45: i1IIi % OOooOOo % II111iiii
    self . print_packet ( "Receive" , is_lisp_packet )
    oooIi1II1I11i1I = bold ( "No key available" , False )
    dprint ( "{} to decrypt packet from RLOC {}" . format ( oooIi1II1I11i1I ,
 red ( OoOOoooO000 , False ) ) )
    if ( lisp_flow_logging ) : self . log_flow ( False )
    return ( None )
    if 4 - 4: oO0o * I1IiiI - ooOoO0o / II111iiii + OOooOOo / i11iIiiIii
    if 63 - 63: OoO0O00 + ooOoO0o
    if 3 - 3: OoOoOO00 - I1Ii111 / oO0o . O0 * ooOoO0o / I1ii11iIi11i
    if 18 - 18: Ii1I
    if 74 - 74: Ii1I + I1ii11iIi11i + I1IiiI
   i1IIiI1iII . use_count += 1
   iI1IIII1ii1 , OOoOo0O0 = self . decrypt ( iI1IIII1ii1 , I1ii1i11iI1 , i1IIiI1iII ,
 OoOOoooO000 )
   if ( OOoOo0O0 == False ) :
    if ( stats ) : stats [ self . packet_error ] . increment ( oOOoOoOO )
    if ( lisp_flow_logging ) : self . log_flow ( False )
    return ( None )
    if 37 - 37: IiII
    if 97 - 97: o0oOOo0O0Ooo / IiII + OoOoOO00 + OoO0O00 % I1Ii111
    if 18 - 18: I1IiiI - OoOoOO00
    if 18 - 18: OOooOOo + OoO0O00 * oO0o - oO0o . I1ii11iIi11i * I11i
    if 95 - 95: I1ii11iIi11i / OoOoOO00
    if 10 - 10: IiII % I1ii11iIi11i - IiII
  IiOOo0 = struct . unpack ( "B" , iI1IIII1ii1 [ 0 : 1 ] ) [ 0 ]
  self . inner_version = IiOOo0 >> 4
  if ( iII11 and self . inner_version == 4 and IiOOo0 >= 0x45 ) :
   o0o00o = socket . ntohs ( struct . unpack ( "H" , iI1IIII1ii1 [ 2 : 4 ] ) [ 0 ] )
   self . inner_tos = struct . unpack ( "B" , iI1IIII1ii1 [ 1 : 2 ] ) [ 0 ]
   self . inner_ttl = struct . unpack ( "B" , iI1IIII1ii1 [ 8 : 9 ] ) [ 0 ]
   self . inner_protocol = struct . unpack ( "B" , iI1IIII1ii1 [ 9 : 10 ] ) [ 0 ]
   self . inner_source . afi = LISP_AFI_IPV4
   self . inner_dest . afi = LISP_AFI_IPV4
   self . inner_source . unpack_address ( iI1IIII1ii1 [ 12 : 16 ] )
   self . inner_dest . unpack_address ( iI1IIII1ii1 [ 16 : 20 ] )
   II1iOOoOooO0o = socket . ntohs ( struct . unpack ( "H" , iI1IIII1ii1 [ 6 : 8 ] ) [ 0 ] )
   self . inner_is_fragment = ( II1iOOoOooO0o & 0x2000 or II1iOOoOooO0o != 0 )
   if ( self . inner_protocol == LISP_UDP_PROTOCOL ) :
    self . inner_sport = struct . unpack ( "H" , iI1IIII1ii1 [ 20 : 22 ] ) [ 0 ]
    self . inner_sport = socket . ntohs ( self . inner_sport )
    self . inner_dport = struct . unpack ( "H" , iI1IIII1ii1 [ 22 : 24 ] ) [ 0 ]
    self . inner_dport = socket . ntohs ( self . inner_dport )
    if 30 - 30: OoOoOO00 / oO0o / Ii1I * o0oOOo0O0Ooo * oO0o . I1IiiI
  elif ( iII11 and self . inner_version == 6 and IiOOo0 >= 0x60 ) :
   o0o00o = socket . ntohs ( struct . unpack ( "H" , iI1IIII1ii1 [ 4 : 6 ] ) [ 0 ] ) + 40
   oO0oOOOo0o = struct . unpack ( "H" , iI1IIII1ii1 [ 0 : 2 ] ) [ 0 ]
   self . inner_tos = ( socket . ntohs ( oO0oOOOo0o ) >> 4 ) & 0xff
   self . inner_ttl = struct . unpack ( "B" , iI1IIII1ii1 [ 7 : 8 ] ) [ 0 ]
   self . inner_protocol = struct . unpack ( "B" , iI1IIII1ii1 [ 6 : 7 ] ) [ 0 ]
   self . inner_source . afi = LISP_AFI_IPV6
   self . inner_dest . afi = LISP_AFI_IPV6
   self . inner_source . unpack_address ( iI1IIII1ii1 [ 8 : 24 ] )
   self . inner_dest . unpack_address ( iI1IIII1ii1 [ 24 : 40 ] )
   if ( self . inner_protocol == LISP_UDP_PROTOCOL ) :
    self . inner_sport = struct . unpack ( "H" , iI1IIII1ii1 [ 40 : 42 ] ) [ 0 ]
    self . inner_sport = socket . ntohs ( self . inner_sport )
    self . inner_dport = struct . unpack ( "H" , iI1IIII1ii1 [ 42 : 44 ] ) [ 0 ]
    self . inner_dport = socket . ntohs ( self . inner_dport )
    if 93 - 93: OoOoOO00
  elif ( O00OO00OOOoO ) :
   o0o00o = len ( iI1IIII1ii1 )
   self . inner_tos = 0
   self . inner_ttl = 0
   self . inner_protocol = 0
   self . inner_source . afi = LISP_AFI_MAC
   self . inner_dest . afi = LISP_AFI_MAC
   self . inner_dest . unpack_address ( self . swap_mac ( iI1IIII1ii1 [ 0 : 6 ] ) )
   self . inner_source . unpack_address ( self . swap_mac ( iI1IIII1ii1 [ 6 : 12 ] ) )
  elif ( self . lisp_header . get_instance_id ( ) == 0xffffff ) :
   if ( lisp_flow_logging ) : self . log_flow ( False )
   return ( self )
  else :
   self . packet_error = "bad-inner-version"
   if ( stats ) : stats [ self . packet_error ] . increment ( oOOoOoOO )
   if 97 - 97: i11iIiiIii
   lprint ( "Cannot decode encapsulation, header version {}" . format ( hex ( IiOOo0 ) ) )
   if 68 - 68: IiII * OoO0O00 . I11i / Ii1I . o0oOOo0O0Ooo - i11iIiiIii
   iI1IIII1ii1 = lisp_format_packet ( iI1IIII1ii1 [ 0 : 20 ] )
   lprint ( "Packet header: {}" . format ( iI1IIII1ii1 ) )
   if ( lisp_flow_logging and is_lisp_packet ) : self . log_flow ( False )
   return ( None )
   if 49 - 49: Oo0Ooo / Ii1I % I11i + oO0o - OoO0O00
  self . inner_source . mask_len = self . inner_source . host_mask_len ( )
  self . inner_dest . mask_len = self . inner_dest . host_mask_len ( )
  self . inner_source . instance_id = IIiI1i
  self . inner_dest . instance_id = IIiI1i
  if 13 - 13: II111iiii
  if 83 - 83: OoooooooOO . I1IiiI + Ii1I * O0 / oO0o
  if 8 - 8: i1IIi + II111iiii / Ii1I + I1ii11iIi11i % Ii1I - iIii1I11I1II1
  if 29 - 29: Oo0Ooo + II111iiii
  if 95 - 95: oO0o
  if ( lisp_nonce_echoing and is_lisp_packet ) :
   i11iiIi = lisp_get_echo_nonce ( self . outer_source , None )
   if ( i11iiIi == None ) :
    I111I = self . outer_source . print_address_no_iid ( )
    i11iiIi = lisp_echo_nonce ( I111I )
    if 62 - 62: OoooooooOO + IiII
   iIiIi1i1Iiii = self . lisp_header . get_nonce ( )
   if ( self . lisp_header . is_e_bit_set ( ) ) :
    i11iiIi . receive_request ( lisp_ipc_socket , iIiIi1i1Iiii )
   elif ( i11iiIi . request_nonce_sent ) :
    i11iiIi . receive_echo ( lisp_ipc_socket , iIiIi1i1Iiii )
    if 78 - 78: Oo0Ooo - I1Ii111 + iII111i * Ii1I * o0oOOo0O0Ooo
    if 23 - 23: Oo0Ooo - O0
    if 33 - 33: I1ii11iIi11i
    if 54 - 54: ooOoO0o * I1ii11iIi11i . II111iiii / OOooOOo % OOooOOo
    if 25 - 25: i11iIiiIii + I1ii11iIi11i - OoooooooOO . O0 % I1Ii111
    if 53 - 53: i1IIi
    if 59 - 59: o0oOOo0O0Ooo + I1IiiI % OoooooooOO - iIii1I11I1II1
  if ( OOoOo0O0 ) : self . packet += iI1IIII1ii1 [ : o0o00o ]
  if 9 - 9: i1IIi - OoOoOO00
  if 57 - 57: iIii1I11I1II1 * Ii1I * iII111i / oO0o
  if 46 - 46: Ii1I
  if 61 - 61: o0oOOo0O0Ooo / ooOoO0o - II111iiii
  if ( lisp_flow_logging and is_lisp_packet ) : self . log_flow ( False )
  return ( self )
  if 87 - 87: I1ii11iIi11i / I1IiiI
  if 45 - 45: OoOoOO00 * ooOoO0o / OoooooooOO + OoO0O00 . I1Ii111 / OoO0O00
 def swap_mac ( self , mac ) :
  return ( mac [ 1 ] + mac [ 0 ] + mac [ 3 ] + mac [ 2 ] + mac [ 5 ] + mac [ 4 ] )
  if 64 - 64: Ii1I / i1IIi % I1IiiI - o0oOOo0O0Ooo
  if 11 - 11: I1ii11iIi11i - OoooooooOO
 def strip_outer_headers ( self ) :
  oOO0OO0O = 16
  oOO0OO0O += 20 if ( self . outer_version == 4 ) else 40
  self . packet = self . packet [ oOO0OO0O : : ]
  return ( self )
  if 16 - 16: IiII % OoooooooOO - ooOoO0o * Ii1I - Ii1I
  if 27 - 27: IiII + iIii1I11I1II1 / Oo0Ooo + OoO0O00 % Oo0Ooo + OoO0O00
 def hash_ports ( self ) :
  iI1IIII1ii1 = self . packet
  IiOOo0 = self . inner_version
  oO000o0o0oOo0 = 0
  if ( IiOOo0 == 4 ) :
   IiI1 = struct . unpack ( "B" , iI1IIII1ii1 [ 9 ] ) [ 0 ]
   if ( self . inner_is_fragment ) : return ( IiI1 )
   if ( IiI1 in [ 6 , 17 ] ) :
    oO000o0o0oOo0 = IiI1
    oO000o0o0oOo0 += struct . unpack ( "I" , iI1IIII1ii1 [ 20 : 24 ] ) [ 0 ]
    oO000o0o0oOo0 = ( oO000o0o0oOo0 >> 16 ) ^ ( oO000o0o0oOo0 & 0xffff )
    if 11 - 11: OoOoOO00 / I11i
    if 47 - 47: OOooOOo . I1Ii111 % II111iiii + Oo0Ooo - oO0o . II111iiii
  if ( IiOOo0 == 6 ) :
   IiI1 = struct . unpack ( "B" , iI1IIII1ii1 [ 6 ] ) [ 0 ]
   if ( IiI1 in [ 6 , 17 ] ) :
    oO000o0o0oOo0 = IiI1
    oO000o0o0oOo0 += struct . unpack ( "I" , iI1IIII1ii1 [ 40 : 44 ] ) [ 0 ]
    oO000o0o0oOo0 = ( oO000o0o0oOo0 >> 16 ) ^ ( oO000o0o0oOo0 & 0xffff )
    if 37 - 37: iIii1I11I1II1 . I1IiiI % OoO0O00 % OoooooooOO . OoooooooOO / O0
    if 25 - 25: II111iiii % II111iiii - Ii1I . O0
  return ( oO000o0o0oOo0 )
  if 79 - 79: IiII / OoO0O00 * OoooooooOO * OoOoOO00 + I1IiiI
  if 68 - 68: I11i / iIii1I11I1II1 . Oo0Ooo + i11iIiiIii + o0oOOo0O0Ooo
 def hash_packet ( self ) :
  oO000o0o0oOo0 = self . inner_source . address ^ self . inner_dest . address
  oO000o0o0oOo0 += self . hash_ports ( )
  if ( self . inner_version == 4 ) :
   oO000o0o0oOo0 = ( oO000o0o0oOo0 >> 16 ) ^ ( oO000o0o0oOo0 & 0xffff )
  elif ( self . inner_version == 6 ) :
   oO000o0o0oOo0 = ( oO000o0o0oOo0 >> 64 ) ^ ( oO000o0o0oOo0 & 0xffffffffffffffff )
   oO000o0o0oOo0 = ( oO000o0o0oOo0 >> 32 ) ^ ( oO000o0o0oOo0 & 0xffffffff )
   oO000o0o0oOo0 = ( oO000o0o0oOo0 >> 16 ) ^ ( oO000o0o0oOo0 & 0xffff )
   if 92 - 92: OoO0O00 . o0oOOo0O0Ooo . Ii1I % OoOoOO00
  self . udp_sport = 0xf000 | ( oO000o0o0oOo0 & 0xfff )
  if 58 - 58: I1ii11iIi11i % Ii1I * Ii1I - iII111i
  if 9 - 9: ooOoO0o - Ii1I % II111iiii + IiII + OOooOOo % O0
 def print_packet ( self , s_or_r , is_lisp_packet ) :
  if ( is_lisp_packet == False ) :
   o00OoOo0 = "{} -> {}" . format ( self . inner_source . print_address ( ) ,
 self . inner_dest . print_address ( ) )
   dprint ( ( "{} {}, tos/ttl: {}/{}, length: {}, packet: {} ..." ) . format ( bold ( s_or_r , False ) ,
   # i1IIi
 green ( o00OoOo0 , False ) , self . inner_tos ,
 self . inner_ttl , len ( self . packet ) ,
 lisp_format_packet ( self . packet [ 0 : 60 ] ) ) )
   return
   if 43 - 43: OOooOOo / I1IiiI
   if 46 - 46: I1ii11iIi11i % IiII + OoooooooOO * Ii1I
  if ( s_or_r . find ( "Receive" ) != - 1 ) :
   iIO0oooooO = "decap"
   iIO0oooooO += "-vxlan" if self . udp_dport == LISP_VXLAN_DATA_PORT else ""
  else :
   iIO0oooooO = s_or_r
   if ( iIO0oooooO in [ "Send" , "Replicate" ] or iIO0oooooO . find ( "Fragment" ) != - 1 ) :
    iIO0oooooO = "encap"
    if 28 - 28: Oo0Ooo / IiII . iII111i + OoO0O00 + I11i % Oo0Ooo
    if 45 - 45: Oo0Ooo / O0 % OoooooooOO
  O0o = "{} -> {}" . format ( self . outer_source . print_address_no_iid ( ) ,
 self . outer_dest . print_address_no_iid ( ) )
  if 49 - 49: I1IiiI % ooOoO0o / Oo0Ooo % II111iiii
  if 12 - 12: iII111i . IiII + Oo0Ooo
  if 95 - 95: iII111i + ooOoO0o / oO0o . OoOoOO00 + II111iiii * oO0o
  if 33 - 33: i1IIi
  if 57 - 57: OoooooooOO
  if ( self . lisp_header . get_instance_id ( ) == 0xffffff ) :
   i11ii = ( "{} LISP packet, outer RLOCs: {}, outer tos/ttl: " + "{}/{}, outer UDP: {} -> {}, " )
   if 70 - 70: iII111i . OOooOOo * OoO0O00 + OoooooooOO . I1Ii111
   i11ii += bold ( "control-packet" , False ) + ": {} ..."
   if 97 - 97: OoooooooOO % iIii1I11I1II1 * OoOoOO00 . oO0o / I1Ii111
   dprint ( i11ii . format ( bold ( s_or_r , False ) , red ( O0o , False ) ,
 self . outer_tos , self . outer_ttl , self . udp_sport ,
 self . udp_dport , lisp_format_packet ( self . packet [ 0 : 56 ] ) ) )
   return
  else :
   i11ii = ( "{} LISP packet, outer RLOCs: {}, outer tos/ttl: " + "{}/{}, outer UDP: {} -> {}, inner EIDs: {}, " + "inner tos/ttl: {}/{}, length: {}, {}, packet: {} ..." )
   if 27 - 27: I1IiiI % IiII
   if 4 - 4: i11iIiiIii * I1ii11iIi11i + OoooooooOO - IiII . ooOoO0o . iIii1I11I1II1
   if 48 - 48: o0oOOo0O0Ooo * oO0o . I1IiiI - I1Ii111 + OOooOOo . Oo0Ooo
   if 62 - 62: I11i + OoooooooOO * iIii1I11I1II1 / i1IIi * O0
  if ( self . lisp_header . k_bits ) :
   if ( iIO0oooooO == "encap" ) : iIO0oooooO = "encrypt/encap"
   if ( iIO0oooooO == "decap" ) : iIO0oooooO = "decap/decrypt"
   if 10 - 10: iIii1I11I1II1 * OoooooooOO / OOooOOo
   if 33 - 33: o0oOOo0O0Ooo % IiII - iIii1I11I1II1 % OOooOOo + I1Ii111 - i11iIiiIii
  o00OoOo0 = "{} -> {}" . format ( self . inner_source . print_address ( ) ,
 self . inner_dest . print_address ( ) )
  if 91 - 91: OoooooooOO . iIii1I11I1II1 / i11iIiiIii
  dprint ( i11ii . format ( bold ( s_or_r , False ) , red ( O0o , False ) ,
 self . outer_tos , self . outer_ttl , self . udp_sport , self . udp_dport ,
 green ( o00OoOo0 , False ) , self . inner_tos , self . inner_ttl ,
 len ( self . packet ) , self . lisp_header . print_header ( iIO0oooooO ) ,
 lisp_format_packet ( self . packet [ 0 : 56 ] ) ) )
  if 80 - 80: I1IiiI
  if 58 - 58: oO0o + I1ii11iIi11i % OoOoOO00
 def print_eid_tuple ( self ) :
  return ( lisp_print_eid_tuple ( self . inner_source , self . inner_dest ) )
  if 22 - 22: iIii1I11I1II1 - Ii1I / I1IiiI * IiII
  if 26 - 26: o0oOOo0O0Ooo + OOooOOo - o0oOOo0O0Ooo + Oo0Ooo . oO0o
 def get_raw_socket ( self ) :
  IIiI1i = str ( self . lisp_header . get_instance_id ( ) )
  if ( IIiI1i == "0" ) : return ( None )
  if ( lisp_iid_to_interface . has_key ( IIiI1i ) == False ) : return ( None )
  if 97 - 97: i1IIi
  iIiiiIiIi = lisp_iid_to_interface [ IIiI1i ]
  i1I1iIi1IiI = iIiiiIiIi . get_socket ( )
  if ( i1I1iIi1IiI == None ) :
   oo0OooO = bold ( "SO_BINDTODEVICE" , False )
   ii1iI1i1 = ( os . getenv ( "LISP_ENFORCE_BINDTODEVICE" ) != None )
   lprint ( "{} required for multi-tenancy support, {} packet" . format ( oo0OooO , "drop" if ii1iI1i1 else "forward" ) )
   if 51 - 51: ooOoO0o * iII111i / i1IIi
   if ( ii1iI1i1 ) : return ( None )
   if 2 - 2: oO0o + IiII . iII111i - i1IIi + I1Ii111
   if 54 - 54: OoooooooOO . oO0o - iII111i
  IIiI1i = bold ( IIiI1i , False )
  i1i11ii1Ii = bold ( iIiiiIiIi . device , False )
  dprint ( "Send packet on instance-id {} interface {}" . format ( IIiI1i , i1i11ii1Ii ) )
  return ( i1I1iIi1IiI )
  if 76 - 76: I1Ii111
  if 61 - 61: ooOoO0o / II111iiii * ooOoO0o * OoOoOO00 * I1Ii111 . i11iIiiIii
 def log_flow ( self , encap ) :
  global lisp_flow_log
  if 26 - 26: I1Ii111 / ooOoO0o - OoO0O00 . iIii1I11I1II1
  O0o0OOo0o0o = os . path . exists ( "./log-flows" )
  if ( len ( lisp_flow_log ) == LISP_FLOW_LOG_SIZE or O0o0OOo0o0o ) :
   o0oO00oooo = [ lisp_flow_log ]
   lisp_flow_log = [ ]
   threading . Thread ( target = lisp_write_flow_log , args = o0oO00oooo ) . start ( )
   if ( O0o0OOo0o0o ) : os . system ( "rm ./log-flows" )
   return
   if 63 - 63: II111iiii - I11i . OoOoOO00
   if 8 - 8: I1IiiI * ooOoO0o / IiII + OoOoOO00 . IiII - OOooOOo
  III11I1 = datetime . datetime . now ( )
  lisp_flow_log . append ( [ III11I1 , encap , self . packet , self ] )
  if 80 - 80: iIii1I11I1II1 / oO0o * Oo0Ooo - OOooOOo * iII111i
  if 97 - 97: IiII - I11i / II111iiii
 def print_flow ( self , ts , encap , packet ) :
  ts = ts . strftime ( "%m/%d/%y %H:%M:%S.%f" ) [ : - 3 ]
  I11ii1i = "{}: {}" . format ( ts , "encap" if encap else "decap" )
  if 50 - 50: iIii1I11I1II1 - I11i % iII111i - Oo0Ooo
  OOO00O = red ( self . outer_source . print_address_no_iid ( ) , False )
  I11II1III11I11iIi1 = red ( self . outer_dest . print_address_no_iid ( ) , False )
  I11i1I1iIiI = green ( self . inner_source . print_address ( ) , False )
  oo0OoOO000O = green ( self . inner_dest . print_address ( ) , False )
  if 62 - 62: i1IIi * iIii1I11I1II1 % oO0o % OoOoOO00 / OoooooooOO
  if ( self . lisp_header . get_instance_id ( ) == 0xffffff ) :
   I11ii1i += " {}:{} -> {}:{}, LISP control message type {}\n"
   I11ii1i = I11ii1i . format ( OOO00O , self . udp_sport , I11II1III11I11iIi1 , self . udp_dport ,
 self . inner_version )
   return ( I11ii1i )
   if 39 - 39: Oo0Ooo % iII111i
   if 90 - 90: I1IiiI * I1ii11iIi11i . I11i * Ii1I - o0oOOo0O0Ooo
  if ( self . outer_dest . is_null ( ) == False ) :
   I11ii1i += " {}:{} -> {}:{}, len/tos/ttl {}/{}/{}"
   I11ii1i = I11ii1i . format ( OOO00O , self . udp_sport , I11II1III11I11iIi1 , self . udp_dport ,
 len ( packet ) , self . outer_tos , self . outer_ttl )
   if 40 - 40: O0 / IiII - II111iiii + o0oOOo0O0Ooo % Oo0Ooo
   if 93 - 93: ooOoO0o
   if 82 - 82: I1ii11iIi11i / ooOoO0o . i11iIiiIii + OOooOOo - OoOoOO00 / iII111i
   if 99 - 99: oO0o / i1IIi
   if 2 - 2: oO0o . iII111i
  if ( self . lisp_header . k_bits != 0 ) :
   II1II111 = "\n"
   if ( self . packet_error != "" ) :
    II1II111 = " ({})" . format ( self . packet_error ) + II1II111
    if 71 - 71: II111iiii % I1Ii111 + I1IiiI * ooOoO0o + IiII . ooOoO0o
   I11ii1i += ", encrypted" + II1II111
   return ( I11ii1i )
   if 25 - 25: ooOoO0o . o0oOOo0O0Ooo % I1IiiI + iII111i
   if 61 - 61: oO0o % ooOoO0o - I1ii11iIi11i + oO0o . OoOoOO00
   if 44 - 44: I1ii11iIi11i / O0 - IiII + OOooOOo . I11i . I1ii11iIi11i
   if 95 - 95: OoOoOO00 % I1Ii111 % i1IIi * o0oOOo0O0Ooo + OOooOOo
   if 34 - 34: I1Ii111 * o0oOOo0O0Ooo . I1IiiI % i11iIiiIii
  if ( self . outer_dest . is_null ( ) == False ) :
   packet = packet [ 36 : : ] if self . outer_version == 4 else packet [ 56 : : ]
   if 61 - 61: iIii1I11I1II1 + oO0o * I11i - i1IIi % oO0o
   if 76 - 76: oO0o / OoOoOO00
  IiI1 = packet [ 9 ] if self . inner_version == 4 else packet [ 6 ]
  IiI1 = struct . unpack ( "B" , IiI1 ) [ 0 ]
  if 12 - 12: I1Ii111
  I11ii1i += " {} -> {}, len/tos/ttl/prot {}/{}/{}/{}"
  I11ii1i = I11ii1i . format ( I11i1I1iIiI , oo0OoOO000O , len ( packet ) , self . inner_tos ,
 self . inner_ttl , IiI1 )
  if 58 - 58: OoO0O00 + iIii1I11I1II1 % O0 + I11i + OoOoOO00 * OoooooooOO
  if 41 - 41: oO0o * I1IiiI
  if 76 - 76: oO0o . O0 * OoooooooOO + ooOoO0o
  if 53 - 53: Oo0Ooo
  if ( IiI1 in [ 6 , 17 ] ) :
   I11iIiiI = packet [ 20 : 24 ] if self . inner_version == 4 else packet [ 40 : 44 ]
   if ( len ( I11iIiiI ) == 4 ) :
    I11iIiiI = socket . ntohl ( struct . unpack ( "I" , I11iIiiI ) [ 0 ] )
    I11ii1i += ", ports {} -> {}" . format ( I11iIiiI >> 16 , I11iIiiI & 0xffff )
    if 88 - 88: I1ii11iIi11i - I11i * OoooooooOO * iII111i . i11iIiiIii . o0oOOo0O0Ooo
  elif ( IiI1 == 1 ) :
   OooOoO0OO00 = packet [ 26 : 28 ] if self . inner_version == 4 else packet [ 46 : 48 ]
   if ( len ( OooOoO0OO00 ) == 2 ) :
    OooOoO0OO00 = socket . ntohs ( struct . unpack ( "H" , OooOoO0OO00 ) [ 0 ] )
    I11ii1i += ", icmp-seq {}" . format ( OooOoO0OO00 )
    if 94 - 94: Oo0Ooo - iIii1I11I1II1 + I1IiiI - i1IIi + OoooooooOO % OoO0O00
    if 36 - 36: iII111i * I11i * O0 * OOooOOo - o0oOOo0O0Ooo / I1ii11iIi11i
  if ( self . packet_error != "" ) :
   I11ii1i += " ({})" . format ( self . packet_error )
   if 54 - 54: i1IIi - OoO0O00 / OoooooooOO
  I11ii1i += "\n"
  return ( I11ii1i )
  if 95 - 95: O0 + iIii1I11I1II1 . I1ii11iIi11i
  if 61 - 61: Ii1I * Ii1I
 def is_trace ( self ) :
  I11iIiiI = [ self . inner_sport , self . inner_dport ]
  return ( self . inner_protocol == LISP_UDP_PROTOCOL and
 LISP_TRACE_PORT in I11iIiiI )
  if 70 - 70: I1Ii111 . I1ii11iIi11i / o0oOOo0O0Ooo * oO0o
  if 74 - 74: I1IiiI . ooOoO0o / iII111i . IiII
  if 74 - 74: Oo0Ooo / I1Ii111 % I1Ii111 . IiII
  if 72 - 72: i1IIi
  if 21 - 21: I1Ii111 . OOooOOo / i11iIiiIii * i1IIi
  if 82 - 82: ooOoO0o * Oo0Ooo % i11iIiiIii * i1IIi . OOooOOo
  if 89 - 89: IiII - i1IIi - IiII
  if 74 - 74: OoO0O00 % OoO0O00
  if 28 - 28: OoOoOO00 % oO0o - OOooOOo + OOooOOo + oO0o / iIii1I11I1II1
  if 91 - 91: I1IiiI / II111iiii * OOooOOo
  if 94 - 94: II111iiii - iIii1I11I1II1 - iIii1I11I1II1
  if 83 - 83: I1ii11iIi11i * iIii1I11I1II1 + OoOoOO00 * i1IIi . OoooooooOO % Ii1I
  if 81 - 81: OoO0O00 - iIii1I11I1II1
  if 60 - 60: I1Ii111
  if 77 - 77: I1IiiI / I1ii11iIi11i
  if 95 - 95: I1Ii111 * i1IIi + oO0o
LISP_N_BIT = 0x80000000
LISP_L_BIT = 0x40000000
LISP_E_BIT = 0x20000000
LISP_V_BIT = 0x10000000
LISP_I_BIT = 0x08000000
LISP_P_BIT = 0x04000000
LISP_K_BITS = 0x03000000
if 40 - 40: II111iiii
class lisp_data_header ( ) :
 def __init__ ( self ) :
  self . first_long = 0
  self . second_long = 0
  self . k_bits = 0
  if 7 - 7: OOooOOo / OoO0O00
  if 88 - 88: i1IIi
 def print_header ( self , e_or_d ) :
  O0ooOo0Oooo = lisp_hex_string ( self . first_long & 0xffffff )
  I1iiIIiI11I = lisp_hex_string ( self . second_long ) . zfill ( 8 )
  if 29 - 29: I11i + oO0o % ooOoO0o + OoOoOO00
  i11ii = ( "{} LISP-header -> flags: {}{}{}{}{}{}{}{}, nonce: {}, " + "iid/lsb: {}" )
  if 92 - 92: o0oOOo0O0Ooo
  return ( i11ii . format ( bold ( e_or_d , False ) ,
 "N" if ( self . first_long & LISP_N_BIT ) else "n" ,
 "L" if ( self . first_long & LISP_L_BIT ) else "l" ,
 "E" if ( self . first_long & LISP_E_BIT ) else "e" ,
 "V" if ( self . first_long & LISP_V_BIT ) else "v" ,
 "I" if ( self . first_long & LISP_I_BIT ) else "i" ,
 "P" if ( self . first_long & LISP_P_BIT ) else "p" ,
 "K" if ( self . k_bits in [ 2 , 3 ] ) else "k" ,
 "K" if ( self . k_bits in [ 1 , 3 ] ) else "k" ,
 O0ooOo0Oooo , I1iiIIiI11I ) )
  if 37 - 37: oO0o
  if 18 - 18: IiII * i11iIiiIii + iIii1I11I1II1 % I11i + i1IIi - OoO0O00
 def encode ( self ) :
  oOO0OOOoO0ooo = "II"
  O0ooOo0Oooo = socket . htonl ( self . first_long )
  I1iiIIiI11I = socket . htonl ( self . second_long )
  if 20 - 20: oO0o - o0oOOo0O0Ooo * OoO0O00 % i1IIi - iIii1I11I1II1 . OOooOOo
  IIiiIiIIiI1 = struct . pack ( oOO0OOOoO0ooo , O0ooOo0Oooo , I1iiIIiI11I )
  return ( IIiiIiIIiI1 )
  if 39 - 39: I11i / OoooooooOO - Ii1I + OoO0O00 / OoOoOO00
  if 87 - 87: I1Ii111
 def decode ( self , packet ) :
  oOO0OOOoO0ooo = "II"
  I1111ii1i = struct . calcsize ( oOO0OOOoO0ooo )
  if ( len ( packet ) < I1111ii1i ) : return ( False )
  if 86 - 86: i1IIi * OoooooooOO
  O0ooOo0Oooo , I1iiIIiI11I = struct . unpack ( oOO0OOOoO0ooo , packet [ : I1111ii1i ] )
  if 22 - 22: I1Ii111 + iII111i - I11i + iIii1I11I1II1 / I1Ii111 - OoooooooOO
  if 42 - 42: OoooooooOO - OoOoOO00 - OOooOOo * I1Ii111
  self . first_long = socket . ntohl ( O0ooOo0Oooo )
  self . second_long = socket . ntohl ( I1iiIIiI11I )
  self . k_bits = ( self . first_long & LISP_K_BITS ) >> 24
  return ( True )
  if 98 - 98: OoO0O00 . iIii1I11I1II1 % Oo0Ooo + OoooooooOO
  if 2 - 2: I1Ii111 % OoooooooOO - ooOoO0o * I1ii11iIi11i * IiII
 def key_id ( self , key_id ) :
  self . first_long &= ~ ( 0x3 << 24 )
  self . first_long |= ( ( key_id & 0x3 ) << 24 )
  self . k_bits = key_id
  if 99 - 99: iIii1I11I1II1 . Oo0Ooo / ooOoO0o . OOooOOo % I1IiiI * I11i
  if 95 - 95: oO0o
 def nonce ( self , nonce ) :
  self . first_long |= LISP_N_BIT
  self . first_long |= nonce
  if 80 - 80: IiII
  if 42 - 42: OoooooooOO * II111iiii
 def map_version ( self , version ) :
  self . first_long |= LISP_V_BIT
  self . first_long |= version
  if 53 - 53: I1Ii111 + i1IIi . OoO0O00 / i11iIiiIii + Ii1I % OoOoOO00
  if 9 - 9: ooOoO0o . I11i - Oo0Ooo . I1Ii111
 def instance_id ( self , iid ) :
  if ( iid == 0 ) : return
  self . first_long |= LISP_I_BIT
  self . second_long &= 0xff
  self . second_long |= ( iid << 8 )
  if 39 - 39: OOooOOo
  if 70 - 70: IiII % OoO0O00 % I1IiiI
 def get_instance_id ( self ) :
  return ( ( self . second_long >> 8 ) & 0xffffff )
  if 95 - 95: OoOoOO00 - I1Ii111 / O0 * I1IiiI - o0oOOo0O0Ooo
  if 12 - 12: iIii1I11I1II1 % Oo0Ooo . iII111i . IiII % i11iIiiIii
 def locator_status_bits ( self , lsbs ) :
  self . first_long |= LISP_L_BIT
  self . second_long &= 0xffffff00
  self . second_long |= ( lsbs & 0xff )
  if 2 - 2: oO0o * oO0o . OoOoOO00 * Ii1I * iIii1I11I1II1
  if 13 - 13: I11i / O0 . i11iIiiIii * i1IIi % i11iIiiIii
 def is_request_nonce ( self , nonce ) :
  return ( nonce & 0x80000000 )
  if 8 - 8: OoOoOO00 - OoooooooOO
  if 99 - 99: II111iiii / IiII % OoooooooOO . i11iIiiIii
 def request_nonce ( self , nonce ) :
  self . first_long |= LISP_E_BIT
  self . first_long |= LISP_N_BIT
  self . first_long |= ( nonce & 0xffffff )
  if 18 - 18: o0oOOo0O0Ooo . ooOoO0o
  if 70 - 70: OoooooooOO . ooOoO0o / oO0o . oO0o - o0oOOo0O0Ooo
 def is_e_bit_set ( self ) :
  return ( self . first_long & LISP_E_BIT )
  if 29 - 29: I11i % OOooOOo - ooOoO0o
  if 26 - 26: O0 . I11i + iII111i - Ii1I . I11i
 def get_nonce ( self ) :
  return ( self . first_long & 0xffffff )
  if 2 - 2: I1ii11iIi11i . Oo0Ooo * OOooOOo % II111iiii . iII111i
  if 46 - 46: OoOoOO00 + I1IiiI % OoooooooOO * i11iIiiIii - Oo0Ooo
  if 47 - 47: iII111i * OoOoOO00 * IiII
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
  if 46 - 46: Ii1I
  if 42 - 42: iIii1I11I1II1
 def send_ipc ( self , ipc_socket , ipc ) :
  IIi1IiIii = "lisp-itr" if lisp_i_am_itr else "lisp-etr"
  iiIi1I = "lisp-etr" if lisp_i_am_itr else "lisp-itr"
  ipc = lisp_command_ipc ( ipc , IIi1IiIii )
  lisp_ipc ( ipc , ipc_socket , iiIi1I )
  if 23 - 23: OoO0O00 % OoooooooOO * ooOoO0o
  if 6 - 6: I1IiiI . II111iiii + I1Ii111 / OoO0O00 % I1IiiI . OoooooooOO
 def send_request_ipc ( self , ipc_socket , nonce ) :
  nonce = lisp_hex_string ( nonce )
  Oooo000 = "nonce%R%{}%{}" . format ( self . rloc_str , nonce )
  self . send_ipc ( ipc_socket , Oooo000 )
  if 37 - 37: OoO0O00 . i1IIi + i1IIi / I1IiiI * ooOoO0o * Ii1I
  if 56 - 56: OoooooooOO / I1IiiI . ooOoO0o - i1IIi
 def send_echo_ipc ( self , ipc_socket , nonce ) :
  nonce = lisp_hex_string ( nonce )
  Oooo000 = "nonce%E%{}%{}" . format ( self . rloc_str , nonce )
  self . send_ipc ( ipc_socket , Oooo000 )
  if 60 - 60: OoOoOO00 % OoOoOO00
  if 2 - 2: Ii1I . O0 - oO0o + IiII
 def receive_request ( self , ipc_socket , nonce ) :
  o00oo0o = self . request_nonce_rcvd
  self . request_nonce_rcvd = nonce
  self . last_request_nonce_rcvd = lisp_get_timestamp ( )
  if ( lisp_i_am_rtr ) : return
  if ( o00oo0o != nonce ) : self . send_request_ipc ( ipc_socket , nonce )
  if 25 - 25: iII111i / iIii1I11I1II1 + I1IiiI / ooOoO0o
  if 61 - 61: oO0o % I1ii11iIi11i * I11i . I11i
 def receive_echo ( self , ipc_socket , nonce ) :
  if ( self . request_nonce_sent != nonce ) : return
  self . last_echo_nonce_rcvd = lisp_get_timestamp ( )
  if ( self . echo_nonce_rcvd == nonce ) : return
  if 20 - 20: Ii1I / iII111i + II111iiii . i11iIiiIii . OOooOOo
  self . echo_nonce_rcvd = nonce
  if ( lisp_i_am_rtr ) : return
  self . send_echo_ipc ( ipc_socket , nonce )
  if 77 - 77: OoOoOO00
  if 91 - 91: oO0o
 def get_request_or_echo_nonce ( self , ipc_socket , remote_rloc ) :
  if 56 - 56: iIii1I11I1II1 % II111iiii / OoOoOO00 % OoooooooOO
  if 13 - 13: IiII . Oo0Ooo - I11i / oO0o - Oo0Ooo - I1IiiI
  if 84 - 84: II111iiii
  if 57 - 57: O0 * iIii1I11I1II1 % O0 . OoooooooOO
  if 53 - 53: Ii1I / I1IiiI * Ii1I + o0oOOo0O0Ooo + oO0o - Oo0Ooo
  if ( self . request_nonce_sent and self . echo_nonce_sent and remote_rloc ) :
   IIi1iiIIi1i = lisp_myrlocs [ 0 ] if remote_rloc . is_ipv4 ( ) else lisp_myrlocs [ 1 ]
   if 5 - 5: OoooooooOO / IiII
   if 51 - 51: OOooOOo % i11iIiiIii
   if ( remote_rloc . address > IIi1iiIIi1i . address ) :
    OOOO0o = "exit"
    self . request_nonce_sent = None
   else :
    OOOO0o = "stay in"
    self . echo_nonce_sent = None
    if 77 - 77: OOooOOo % i11iIiiIii - I1ii11iIi11i
    if 21 - 21: I11i . Oo0Ooo - OoooooooOO * i1IIi
   OoOOooOOoo = bold ( "collision" , False )
   ooO = red ( IIi1iiIIi1i . print_address_no_iid ( ) , False )
   iIOoo000 = red ( remote_rloc . print_address_no_iid ( ) , False )
   lprint ( "Echo nonce {}, {} -> {}, {} request-nonce mode" . format ( OoOOooOOoo ,
 ooO , iIOoo000 , OOOO0o ) )
   if 21 - 21: iII111i % IiII % Oo0Ooo % O0
   if 63 - 63: II111iiii * I1IiiI - OoooooooOO / I1IiiI
   if 50 - 50: OoOoOO00 % Ii1I + OoOoOO00 * Ii1I - OOooOOo
   if 94 - 94: iIii1I11I1II1
   if 1 - 1: O0
  if ( self . echo_nonce_sent != None ) :
   iIiIi1i1Iiii = self . echo_nonce_sent
   I1i11II = bold ( "Echoing" , False )
   lprint ( "{} nonce 0x{} to {}" . format ( I1i11II ,
 lisp_hex_string ( iIiIi1i1Iiii ) , red ( self . rloc_str , False ) ) )
   self . last_echo_nonce_sent = lisp_get_timestamp ( )
   self . echo_nonce_sent = None
   return ( iIiIi1i1Iiii )
   if 2 - 2: OoO0O00 . I11i
   if 97 - 97: Oo0Ooo
   if 65 - 65: Oo0Ooo % OOooOOo / i11iIiiIii / iIii1I11I1II1 . I1Ii111 + ooOoO0o
   if 92 - 92: oO0o
   if 96 - 96: I1Ii111 * iIii1I11I1II1 / OoOoOO00 % OOooOOo * II111iiii
   if 3 - 3: OOooOOo . Oo0Ooo / i11iIiiIii + OoO0O00
   if 47 - 47: IiII . OOooOOo
  iIiIi1i1Iiii = self . request_nonce_sent
  O0oo00o000 = self . last_request_nonce_sent
  if ( iIiIi1i1Iiii and O0oo00o000 != None ) :
   if ( time . time ( ) - O0oo00o000 >= LISP_NONCE_ECHO_INTERVAL ) :
    self . request_nonce_sent = None
    lprint ( "Stop request-nonce mode for {}, nonce 0x{}" . format ( red ( self . rloc_str , False ) , lisp_hex_string ( iIiIi1i1Iiii ) ) )
    if 5 - 5: I1ii11iIi11i * Ii1I % I11i % II111iiii
    return ( None )
    if 9 - 9: o0oOOo0O0Ooo % I1Ii111 + I11i
    if 55 - 55: OoO0O00 - I1ii11iIi11i
    if 38 - 38: iIii1I11I1II1 % IiII % OoO0O00 % O0 * iIii1I11I1II1 / I1Ii111
    if 65 - 65: OOooOOo - I1IiiI * I1Ii111
    if 99 - 99: I1IiiI
    if 64 - 64: I1ii11iIi11i * Ii1I * Oo0Ooo % IiII % ooOoO0o
    if 55 - 55: II111iiii - I1Ii111 - OOooOOo % Ii1I
    if 49 - 49: Oo0Ooo * I1Ii111
    if 53 - 53: Oo0Ooo / Ii1I + oO0o . iII111i + IiII
  if ( iIiIi1i1Iiii == None ) :
   iIiIi1i1Iiii = lisp_get_data_nonce ( )
   if ( self . recently_requested ( ) ) : return ( iIiIi1i1Iiii )
   if 19 - 19: Ii1I
   self . request_nonce_sent = iIiIi1i1Iiii
   lprint ( "Start request-nonce mode for {}, nonce 0x{}" . format ( red ( self . rloc_str , False ) , lisp_hex_string ( iIiIi1i1Iiii ) ) )
   if 51 - 51: iIii1I11I1II1
   self . last_new_request_nonce_sent = lisp_get_timestamp ( )
   if 8 - 8: OoO0O00 / o0oOOo0O0Ooo % iII111i . i11iIiiIii . OoooooooOO . Ii1I
   if 8 - 8: OoO0O00 * Oo0Ooo
   if 41 - 41: Oo0Ooo / OoO0O00 / OoOoOO00 - i11iIiiIii - OoOoOO00
   if 4 - 4: I11i . IiII
   if 39 - 39: OOooOOo . Oo0Ooo - OoOoOO00 * i11iIiiIii
   if ( lisp_i_am_itr == False ) : return ( iIiIi1i1Iiii | 0x80000000 )
   self . send_request_ipc ( ipc_socket , iIiIi1i1Iiii )
  else :
   lprint ( "Continue request-nonce mode for {}, nonce 0x{}" . format ( red ( self . rloc_str , False ) , lisp_hex_string ( iIiIi1i1Iiii ) ) )
   if 4 - 4: OoOoOO00 * O0 - I11i
   if 72 - 72: I11i + ooOoO0o / I1IiiI . IiII % OoO0O00 / i11iIiiIii
   if 13 - 13: I1Ii111 % o0oOOo0O0Ooo + OOooOOo + I1Ii111 + i11iIiiIii - I1ii11iIi11i
   if 70 - 70: II111iiii * II111iiii . I1IiiI
   if 11 - 11: iII111i
   if 20 - 20: Ii1I . I1Ii111 % Ii1I
   if 5 - 5: OOooOOo + iII111i
  self . last_request_nonce_sent = lisp_get_timestamp ( )
  return ( iIiIi1i1Iiii | 0x80000000 )
  if 23 - 23: I1Ii111 % iIii1I11I1II1 . I11i
  if 95 - 95: Oo0Ooo + i11iIiiIii % OOooOOo - oO0o
 def request_nonce_timeout ( self ) :
  if ( self . request_nonce_sent == None ) : return ( False )
  if ( self . request_nonce_sent == self . echo_nonce_rcvd ) : return ( False )
  if 11 - 11: I1ii11iIi11i / O0 + II111iiii
  ooooOoO0O = time . time ( ) - self . last_request_nonce_sent
  o000oo = self . last_echo_nonce_rcvd
  return ( ooooOoO0O >= LISP_NONCE_ECHO_INTERVAL and o000oo == None )
  if 58 - 58: ooOoO0o + II111iiii + Ii1I . OoooooooOO
  if 42 - 42: iIii1I11I1II1 / I11i . O0 . Ii1I
 def recently_requested ( self ) :
  o000oo = self . last_request_nonce_sent
  if ( o000oo == None ) : return ( False )
  if 12 - 12: i11iIiiIii - iIii1I11I1II1 * IiII * iII111i
  ooooOoO0O = time . time ( ) - o000oo
  return ( ooooOoO0O <= LISP_NONCE_ECHO_INTERVAL )
  if 19 - 19: O0 + oO0o + o0oOOo0O0Ooo
  if 81 - 81: iIii1I11I1II1
 def recently_echoed ( self ) :
  if ( self . request_nonce_sent == None ) : return ( True )
  if 51 - 51: o0oOOo0O0Ooo . I1ii11iIi11i * Ii1I / Oo0Ooo * II111iiii / O0
  if 44 - 44: i11iIiiIii % I1Ii111 % oO0o + I11i * oO0o . Ii1I
  if 89 - 89: OoooooooOO % II111iiii - OoO0O00 % i11iIiiIii
  if 7 - 7: IiII
  o000oo = self . last_good_echo_nonce_rcvd
  if ( o000oo == None ) : o000oo = 0
  ooooOoO0O = time . time ( ) - o000oo
  if ( ooooOoO0O <= LISP_NONCE_ECHO_INTERVAL ) : return ( True )
  if 15 - 15: Oo0Ooo + iII111i + I1IiiI * o0oOOo0O0Ooo
  if 33 - 33: o0oOOo0O0Ooo * Oo0Ooo
  if 88 - 88: I1Ii111 % OOooOOo - OoOoOO00 - OoOoOO00 . I1IiiI
  if 52 - 52: II111iiii / II111iiii / I1IiiI - I1Ii111
  if 91 - 91: I1IiiI + o0oOOo0O0Ooo % II111iiii + OoO0O00
  if 66 - 66: iIii1I11I1II1 * II111iiii % Oo0Ooo % I1IiiI - Ii1I
  o000oo = self . last_new_request_nonce_sent
  if ( o000oo == None ) : o000oo = 0
  ooooOoO0O = time . time ( ) - o000oo
  return ( ooooOoO0O <= LISP_NONCE_ECHO_INTERVAL )
  if 59 - 59: IiII % oO0o
  if 21 - 21: OoooooooOO % OoOoOO00 - OoOoOO00 / I1ii11iIi11i / o0oOOo0O0Ooo
 def change_state ( self , rloc ) :
  if ( rloc . up_state ( ) and self . recently_echoed ( ) == False ) :
   I111i = bold ( "down" , False )
   II1IiIiiI1III = lisp_print_elapsed ( self . last_good_echo_nonce_rcvd )
   lprint ( "Take {} {}, last good echo: {}" . format ( red ( self . rloc_str , False ) , I111i , II1IiIiiI1III ) )
   if 12 - 12: iII111i + O0
   rloc . state = LISP_RLOC_NO_ECHOED_NONCE_STATE
   rloc . last_state_change = lisp_get_timestamp ( )
   return
   if 85 - 85: II111iiii - Ii1I
   if 93 - 93: IiII / i11iIiiIii - oO0o + OoO0O00 / i1IIi
  if ( rloc . no_echoed_nonce_state ( ) == False ) : return
  if 62 - 62: I1ii11iIi11i / OoooooooOO * I1IiiI - i1IIi
  if ( self . recently_requested ( ) == False ) :
   OO0o = bold ( "up" , False )
   lprint ( "Bring {} {}, retry request-nonce mode" . format ( red ( self . rloc_str , False ) , OO0o ) )
   if 75 - 75: OoOoOO00 / iII111i . OoOoOO00 / OoooooooOO . iIii1I11I1II1 / i1IIi
   rloc . state = LISP_RLOC_UP_STATE
   rloc . last_state_change = lisp_get_timestamp ( )
   if 31 - 31: Oo0Ooo - iIii1I11I1II1 / I11i . OoO0O00
   if 74 - 74: Oo0Ooo - II111iiii - IiII
   if 50 - 50: I1IiiI - oO0o + oO0o * I11i + oO0o
 def print_echo_nonce ( self ) :
  oooOoooOOo0 = lisp_print_elapsed ( self . last_request_nonce_sent )
  I1IIII1 = lisp_print_elapsed ( self . last_good_echo_nonce_rcvd )
  if 91 - 91: II111iiii
  iIi1II111I1i1 = lisp_print_elapsed ( self . last_echo_nonce_sent )
  Iio0o0o = lisp_print_elapsed ( self . last_request_nonce_rcvd )
  i1I1iIi1IiI = space ( 4 )
  if 32 - 32: O0 / OOooOOo . ooOoO0o % I1Ii111
  ooO000O = "Nonce-Echoing:\n"
  ooO000O += ( "{}Last request-nonce sent: {}\n{}Last echo-nonce " + "received: {}\n" ) . format ( i1I1iIi1IiI , oooOoooOOo0 , i1I1iIi1IiI , I1IIII1 )
  if 18 - 18: IiII * iII111i / I11i / O0
  ooO000O += ( "{}Last request-nonce received: {}\n{}Last echo-nonce " + "sent: {}" ) . format ( i1I1iIi1IiI , Iio0o0o , i1I1iIi1IiI , iIi1II111I1i1 )
  if 11 - 11: iIii1I11I1II1 / Ii1I + OoooooooOO % i1IIi * i11iIiiIii
  if 86 - 86: i11iIiiIii - O0 - i11iIiiIii . iIii1I11I1II1 . IiII
  return ( ooO000O )
  if 84 - 84: i1IIi / iIii1I11I1II1 / oO0o / Ii1I
  if 7 - 7: OoOoOO00 . OOooOOo % Oo0Ooo
  if 55 - 55: ooOoO0o - Oo0Ooo * oO0o
  if 72 - 72: o0oOOo0O0Ooo % o0oOOo0O0Ooo + iII111i + I1ii11iIi11i / Oo0Ooo
  if 30 - 30: Oo0Ooo + I1IiiI + i11iIiiIii / OoO0O00
  if 64 - 64: IiII
  if 80 - 80: I1IiiI - i11iIiiIii / OoO0O00 / OoOoOO00 + OoOoOO00
  if 89 - 89: O0 + IiII * I1Ii111
  if 30 - 30: OoOoOO00
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
    if 39 - 39: I1ii11iIi11i + o0oOOo0O0Ooo + I1Ii111 + IiII
   self . local_private_key = random . randint ( 0 , 2 ** 128 - 1 )
   i1IIiI1iII = lisp_hex_string ( self . local_private_key ) . zfill ( 32 )
   self . curve25519 = curve25519 . Private ( i1IIiI1iII )
  else :
   self . local_private_key = random . randint ( 0 , 0x1fff )
   if 48 - 48: I1Ii111 / ooOoO0o . iIii1I11I1II1
  self . local_public_key = self . compute_public_key ( )
  self . remote_public_key = None
  self . shared_key = None
  self . encrypt_key = None
  self . icv_key = None
  self . icv = poly1305 if do_poly else hashlib . sha256
  self . iv = None
  self . get_iv ( )
  self . do_poly = do_poly
  if 72 - 72: i1IIi . o0oOOo0O0Ooo
  if 3 - 3: OoOoOO00 % II111iiii - O0
 def copy_keypair ( self , key ) :
  self . local_private_key = key . local_private_key
  self . local_public_key = key . local_public_key
  self . curve25519 = key . curve25519
  if 52 - 52: OoO0O00
  if 49 - 49: Ii1I . I1ii11iIi11i % ooOoO0o . Oo0Ooo * OOooOOo
 def get_iv ( self ) :
  if ( self . iv == None ) :
   self . iv = random . randint ( 0 , LISP_16_128_MASK )
  else :
   self . iv += 1
   if 44 - 44: iIii1I11I1II1 / O0 * Oo0Ooo + I1IiiI . ooOoO0o
  Ooo = self . iv
  if ( self . cipher_suite == LISP_CS_25519_CHACHA ) :
   Ooo = struct . pack ( "Q" , Ooo & LISP_8_64_MASK )
  elif ( self . cipher_suite == LISP_CS_25519_GCM ) :
   I1iIi1i = struct . pack ( "I" , ( Ooo >> 64 ) & LISP_4_32_MASK )
   IIiI1 = struct . pack ( "Q" , Ooo & LISP_8_64_MASK )
   Ooo = I1iIi1i + IIiI1
  else :
   Ooo = struct . pack ( "QQ" , Ooo >> 64 , Ooo & LISP_8_64_MASK )
  return ( Ooo )
  if 93 - 93: OoOoOO00 . oO0o * ooOoO0o
  if 86 - 86: I1ii11iIi11i / iII111i * OOooOOo / OOooOOo - I1ii11iIi11i * OOooOOo
 def key_length ( self , key ) :
  if ( type ( key ) != str ) : key = self . normalize_pub_key ( key )
  return ( len ( key ) / 2 )
  if 81 - 81: iII111i / II111iiii + I1IiiI * ooOoO0o * O0
  if 60 - 60: iII111i / iII111i - ooOoO0o / OoooooooOO + O0
 def print_key ( self , key ) :
  i1ii1iIi = self . normalize_pub_key ( key )
  return ( "0x{}...{}({})" . format ( i1ii1iIi [ 0 : 4 ] , i1ii1iIi [ - 4 : : ] , self . key_length ( i1ii1iIi ) ) )
  if 55 - 55: OoO0O00 % O0 / OoooooooOO
  if 49 - 49: I1IiiI . OoO0O00 * OoooooooOO % i11iIiiIii + iIii1I11I1II1 * i1IIi
 def normalize_pub_key ( self , key ) :
  if ( type ( key ) == str ) :
   if ( self . curve25519 ) : return ( binascii . hexlify ( key ) )
   return ( key )
   if 88 - 88: I1ii11iIi11i * iII111i + II111iiii
  key = lisp_hex_string ( key ) . zfill ( 256 )
  return ( key )
  if 62 - 62: OoooooooOO
  if 33 - 33: O0 . i11iIiiIii % o0oOOo0O0Ooo
 def print_keys ( self , do_bold = True ) :
  ooO = bold ( "local-key: " , False ) if do_bold else "local-key: "
  if ( self . local_public_key == None ) :
   ooO += "none"
  else :
   ooO += self . print_key ( self . local_public_key )
   if 50 - 50: ooOoO0o
  iIOoo000 = bold ( "remote-key: " , False ) if do_bold else "remote-key: "
  if ( self . remote_public_key == None ) :
   iIOoo000 += "none"
  else :
   iIOoo000 += self . print_key ( self . remote_public_key )
   if 81 - 81: i11iIiiIii * iIii1I11I1II1 / Oo0Ooo * OOooOOo
  oo0ooO0O = "ECDH" if ( self . curve25519 ) else "DH"
  oO0oO0ooOoO0 = self . cipher_suite
  return ( "{} cipher-suite: {}, {}, {}" . format ( oo0ooO0O , oO0oO0ooOoO0 , ooO , iIOoo000 ) )
  if 10 - 10: i11iIiiIii % OOooOOo * iII111i % Oo0Ooo
  if 51 - 51: OoO0O00 % iII111i
 def compare_keys ( self , keys ) :
  if ( self . dh_g_value != keys . dh_g_value ) : return ( False )
  if ( self . dh_p_value != keys . dh_p_value ) : return ( False )
  if ( self . remote_public_key != keys . remote_public_key ) : return ( False )
  return ( True )
  if 24 - 24: I1IiiI / iIii1I11I1II1 / O0 . iIii1I11I1II1 - OoO0O00 . iIii1I11I1II1
  if 8 - 8: I1ii11iIi11i % OoO0O00 % oO0o . I1ii11iIi11i * I1ii11iIi11i
 def compute_public_key ( self ) :
  if ( self . curve25519 ) : return ( self . curve25519 . get_public ( ) . public )
  if 94 - 94: i11iIiiIii + OoooooooOO
  i1IIiI1iII = self . local_private_key
  i1iII1iii = self . dh_g_value
  o0O0o = self . dh_p_value
  return ( int ( ( i1iII1iii ** i1IIiI1iII ) % o0O0o ) )
  if 79 - 79: OoOoOO00 + iIii1I11I1II1 * i1IIi * ooOoO0o - I11i * OoO0O00
  if 78 - 78: iII111i % i11iIiiIii + iII111i + o0oOOo0O0Ooo
 def compute_shared_key ( self , ed , print_shared = False ) :
  i1IIiI1iII = self . local_private_key
  i1II11III = self . remote_public_key
  if 95 - 95: I11i + o0oOOo0O0Ooo - i11iIiiIii % OoO0O00 / oO0o
  o00OooOOoOoo = bold ( "Compute {} shared-key" . format ( ed ) , False )
  lprint ( "{}, key-material: {}" . format ( o00OooOOoOoo , self . print_keys ( ) ) )
  if 91 - 91: o0oOOo0O0Ooo / i11iIiiIii
  if ( self . curve25519 ) :
   oO00o0 = curve25519 . Public ( i1II11III )
   self . shared_key = self . curve25519 . get_shared_key ( oO00o0 )
  else :
   o0O0o = self . dh_p_value
   self . shared_key = ( i1II11III ** i1IIiI1iII ) % o0O0o
   if 55 - 55: ooOoO0o - oO0o % I1IiiI
   if 61 - 61: ooOoO0o
   if 22 - 22: iIii1I11I1II1 / ooOoO0o / I1IiiI - o0oOOo0O0Ooo
   if 21 - 21: oO0o . i11iIiiIii * I11i . OOooOOo / OOooOOo
   if 42 - 42: OoooooooOO / I1Ii111 . o0oOOo0O0Ooo / O0 - IiII * IiII
   if 1 - 1: Ii1I % I1Ii111
   if 97 - 97: OoOoOO00
  if ( print_shared ) :
   i1ii1iIi = self . print_key ( self . shared_key )
   lprint ( "Computed shared-key: {}" . format ( i1ii1iIi ) )
   if 13 - 13: OoOoOO00 % OOooOOo . O0 / Oo0Ooo % Oo0Ooo
   if 19 - 19: I1Ii111 % ooOoO0o - ooOoO0o % I1IiiI . OOooOOo - OoooooooOO
   if 100 - 100: I1IiiI + Ii1I + o0oOOo0O0Ooo . i1IIi % OoooooooOO
   if 64 - 64: O0 % i1IIi * I1Ii111 - Ii1I + Oo0Ooo
   if 65 - 65: OoOoOO00 . i11iIiiIii
  self . compute_encrypt_icv_keys ( )
  if 36 - 36: oO0o * iII111i + IiII * iII111i . I1ii11iIi11i - iIii1I11I1II1
  if 14 - 14: I11i * oO0o + i11iIiiIii
  if 84 - 84: iII111i / II111iiii
  if 86 - 86: I1IiiI
  self . rekey_count += 1
  self . last_rekey = lisp_get_timestamp ( )
  if 97 - 97: II111iiii
  if 38 - 38: I1IiiI
 def compute_encrypt_icv_keys ( self ) :
  iiiii1i1 = hashlib . sha256
  if ( self . curve25519 ) :
   O0OooO0oo = self . shared_key
  else :
   O0OooO0oo = lisp_hex_string ( self . shared_key )
   if 81 - 81: iII111i / I1ii11iIi11i
   if 55 - 55: o0oOOo0O0Ooo % OOooOOo - I1ii11iIi11i / IiII / i11iIiiIii % I1Ii111
   if 43 - 43: O0 / I1Ii111 . iIii1I11I1II1 - OoOoOO00
   if 47 - 47: II111iiii - I1ii11iIi11i - Ii1I
   if 9 - 9: I1ii11iIi11i - IiII
  ooO = self . local_public_key
  if ( type ( ooO ) != long ) : ooO = int ( binascii . hexlify ( ooO ) , 16 )
  iIOoo000 = self . remote_public_key
  if ( type ( iIOoo000 ) != long ) : iIOoo000 = int ( binascii . hexlify ( iIOoo000 ) , 16 )
  o0o0 = "0001" + "lisp-crypto" + lisp_hex_string ( ooO ^ iIOoo000 ) + "0100"
  if 87 - 87: i11iIiiIii * II111iiii - Ii1I % OoooooooOO
  o0oO = hmac . new ( o0o0 , O0OooO0oo , iiiii1i1 ) . hexdigest ( )
  o0oO = int ( o0oO , 16 )
  if 35 - 35: I1Ii111 - i1IIi / IiII
  if 13 - 13: OoOoOO00 - OoO0O00 * OoooooooOO
  if 26 - 26: OoooooooOO
  if 65 - 65: OOooOOo
  i111ii1II11ii = ( o0oO >> 128 ) & LISP_16_128_MASK
  i11iII1IiI = o0oO & LISP_16_128_MASK
  self . encrypt_key = lisp_hex_string ( i111ii1II11ii ) . zfill ( 32 )
  i1II1IiIi111 = 32 if self . do_poly else 40
  self . icv_key = lisp_hex_string ( i11iII1IiI ) . zfill ( i1II1IiIi111 )
  if 53 - 53: II111iiii . II111iiii
  if 18 - 18: Ii1I + OoOoOO00 . i1IIi / IiII / iII111i
 def do_icv ( self , packet , nonce ) :
  if ( self . icv_key == None ) : return ( "" )
  if ( self . do_poly ) :
   oOo0OO0 = self . icv . poly1305aes
   OoO = self . icv . binascii . hexlify
   nonce = OoO ( nonce )
   iIiIi1i1ii11 = oOo0OO0 ( self . encrypt_key , self . icv_key , nonce , packet )
   iIiIi1i1ii11 = OoO ( iIiIi1i1ii11 )
  else :
   i1IIiI1iII = binascii . unhexlify ( self . icv_key )
   iIiIi1i1ii11 = hmac . new ( i1IIiI1iII , packet , self . icv ) . hexdigest ( )
   iIiIi1i1ii11 = iIiIi1i1ii11 [ 0 : 40 ]
   if 86 - 86: I1Ii111 * ooOoO0o - ooOoO0o . I1IiiI
  return ( iIiIi1i1ii11 )
  if 69 - 69: i11iIiiIii - iIii1I11I1II1 / Ii1I / II111iiii
  if 81 - 81: OOooOOo - I1ii11iIi11i * Oo0Ooo + oO0o
 def add_key_by_nonce ( self , nonce ) :
  if ( lisp_crypto_keys_by_nonce . has_key ( nonce ) == False ) :
   lisp_crypto_keys_by_nonce [ nonce ] = [ None , None , None , None ]
   if 90 - 90: Oo0Ooo * Ii1I
  lisp_crypto_keys_by_nonce [ nonce ] [ self . key_id ] = self
  if 54 - 54: I1ii11iIi11i + iIii1I11I1II1 % IiII
  if 24 - 24: OoO0O00 / O0 * ooOoO0o % iIii1I11I1II1 + i1IIi % O0
 def delete_key_by_nonce ( self , nonce ) :
  if ( lisp_crypto_keys_by_nonce . has_key ( nonce ) == False ) : return
  lisp_crypto_keys_by_nonce . pop ( nonce )
  if 26 - 26: ooOoO0o + IiII - O0 * oO0o * II111iiii . I1ii11iIi11i
  if 75 - 75: OoOoOO00 / OoooooooOO / I11i % OoOoOO00 * Ii1I * IiII
 def add_key_by_rloc ( self , addr_str , encap ) :
  IIi1 = lisp_crypto_keys_by_rloc_encap if encap else lisp_crypto_keys_by_rloc_decap
  if 94 - 94: OoooooooOO - ooOoO0o % OOooOOo - iII111i / i1IIi
  if 5 - 5: OoooooooOO % II111iiii
  if ( IIi1 . has_key ( addr_str ) == False ) :
   IIi1 [ addr_str ] = [ None , None , None , None ]
   if 7 - 7: i11iIiiIii - I11i % Oo0Ooo
  IIi1 [ addr_str ] [ self . key_id ] = self
  if 76 - 76: OoO0O00 * iII111i % Oo0Ooo . i11iIiiIii / OoooooooOO
  if 85 - 85: OoooooooOO . OoO0O00 . OoO0O00
  if 70 - 70: I11i
  if 72 - 72: I1Ii111 - ooOoO0o - I1IiiI - iII111i + OOooOOo - i1IIi
  if 45 - 45: OoO0O00 * I1IiiI
  if ( encap == False ) :
   lisp_write_ipc_decap_key ( addr_str , IIi1 [ addr_str ] )
   if 61 - 61: iII111i % II111iiii / OoOoOO00 % I1ii11iIi11i . iIii1I11I1II1 % O0
   if 74 - 74: I1ii11iIi11i * oO0o + iII111i % O0
   if 18 - 18: i1IIi % IiII . O0 - O0 - O0 - II111iiii
 def encode_lcaf ( self , rloc_addr ) :
  OO = self . normalize_pub_key ( self . local_public_key )
  o0ooOOOo0O0 = self . key_length ( OO )
  ooI1 = ( 6 + o0ooOOOo0O0 + 2 )
  if ( rloc_addr != None ) : ooI1 += rloc_addr . addr_length ( )
  if 4 - 4: iII111i % I1ii11iIi11i
  iI1IIII1ii1 = struct . pack ( "HBBBBHBB" , socket . htons ( LISP_AFI_LCAF ) , 0 , 0 ,
 LISP_LCAF_SECURITY_TYPE , 0 , socket . htons ( ooI1 ) , 1 , 0 )
  if 9 - 9: O0 * Ii1I
  if 54 - 54: I11i % I11i - ooOoO0o
  if 32 - 32: o0oOOo0O0Ooo % II111iiii / o0oOOo0O0Ooo . OOooOOo . o0oOOo0O0Ooo
  if 29 - 29: OoooooooOO % II111iiii % i11iIiiIii - Oo0Ooo
  if 5 - 5: I1ii11iIi11i . II111iiii . i1IIi
  if 35 - 35: o0oOOo0O0Ooo + OoO0O00 - I1ii11iIi11i
  oO0oO0ooOoO0 = self . cipher_suite
  iI1IIII1ii1 += struct . pack ( "BBH" , oO0oO0ooOoO0 , 0 , socket . htons ( o0ooOOOo0O0 ) )
  if 24 - 24: II111iiii
  if 23 - 23: Oo0Ooo - iII111i
  if 79 - 79: I11i . O0 - i1IIi
  if 42 - 42: oO0o - i11iIiiIii % oO0o - I1Ii111 * O0 / II111iiii
  for oO in range ( 0 , o0ooOOOo0O0 * 2 , 16 ) :
   i1IIiI1iII = int ( OO [ oO : oO + 16 ] , 16 )
   iI1IIII1ii1 += struct . pack ( "Q" , byte_swap_64 ( i1IIiI1iII ) )
   if 5 - 5: Oo0Ooo
   if 84 - 84: I1ii11iIi11i
   if 53 - 53: oO0o
   if 26 - 26: I1Ii111 / I1Ii111 + Oo0Ooo - o0oOOo0O0Ooo % II111iiii . OoooooooOO
   if 7 - 7: II111iiii - I1ii11iIi11i / I11i % OoooooooOO + i1IIi
  if ( rloc_addr ) :
   iI1IIII1ii1 += struct . pack ( "H" , socket . htons ( rloc_addr . afi ) )
   iI1IIII1ii1 += rloc_addr . pack_address ( )
   if 42 - 42: I11i + i1IIi - Ii1I / IiII . iII111i
  return ( iI1IIII1ii1 )
  if 30 - 30: Oo0Ooo + Ii1I % i11iIiiIii * i1IIi + I1IiiI % OOooOOo
  if 30 - 30: i11iIiiIii * Oo0Ooo . II111iiii + I1ii11iIi11i / o0oOOo0O0Ooo % I1Ii111
 def decode_lcaf ( self , packet , lcaf_len ) :
  if 78 - 78: I1ii11iIi11i + OoooooooOO - I1IiiI * OoOoOO00 * iII111i
  if 7 - 7: OOooOOo . IiII . I1Ii111 / Ii1I / Oo0Ooo
  if 83 - 83: I11i / Oo0Ooo
  if 23 - 23: iIii1I11I1II1
  if ( lcaf_len == 0 ) :
   oOO0OOOoO0ooo = "HHBBH"
   I1111ii1i = struct . calcsize ( oOO0OOOoO0ooo )
   if ( len ( packet ) < I1111ii1i ) : return ( None )
   if 10 - 10: I11i - o0oOOo0O0Ooo % OoooooooOO - I1ii11iIi11i
   ooOooOooOOO , oOoo , O00OO0oOOO , oOoo , lcaf_len = struct . unpack ( oOO0OOOoO0ooo , packet [ : I1111ii1i ] )
   if 41 - 41: IiII * OoooooooOO . ooOoO0o % i11iIiiIii
   if 11 - 11: iIii1I11I1II1 . I1Ii111 - Oo0Ooo / I11i + II111iiii
   if ( O00OO0oOOO != LISP_LCAF_SECURITY_TYPE ) :
    packet = packet [ lcaf_len + 6 : : ]
    return ( packet )
    if 29 - 29: I11i . i11iIiiIii + i1IIi - Ii1I + O0 . I1IiiI
   lcaf_len = socket . ntohs ( lcaf_len )
   packet = packet [ I1111ii1i : : ]
   if 8 - 8: o0oOOo0O0Ooo
   if 78 - 78: i1IIi - Oo0Ooo
   if 48 - 48: Ii1I - OoooooooOO + I1Ii111 % o0oOOo0O0Ooo - OoOoOO00 . I1IiiI
   if 42 - 42: I1Ii111
   if 70 - 70: o0oOOo0O0Ooo / I11i + oO0o % I1IiiI % Oo0Ooo + OoO0O00
   if 80 - 80: OOooOOo
  O00OO0oOOO = LISP_LCAF_SECURITY_TYPE
  oOO0OOOoO0ooo = "BBBBH"
  I1111ii1i = struct . calcsize ( oOO0OOOoO0ooo )
  if ( len ( packet ) < I1111ii1i ) : return ( None )
  if 12 - 12: Ii1I
  i1Ii , oOoo , oO0oO0ooOoO0 , oOoo , o0ooOOOo0O0 = struct . unpack ( oOO0OOOoO0ooo ,
 packet [ : I1111ii1i ] )
  if 40 - 40: IiII . OoooooooOO . I1IiiI + O0 % i1IIi / IiII
  if 36 - 36: OoooooooOO - OoOoOO00 - OoO0O00 * I1Ii111 - oO0o
  if 99 - 99: ooOoO0o / I1IiiI . Ii1I - Ii1I * I1IiiI
  if 24 - 24: I11i * OoO0O00 - oO0o / iIii1I11I1II1 - Oo0Ooo . OOooOOo
  if 2 - 2: ooOoO0o - O0 - I1ii11iIi11i / I11i * OoOoOO00
  if 26 - 26: I1ii11iIi11i + I1Ii111 - oO0o + IiII % OOooOOo
  packet = packet [ I1111ii1i : : ]
  o0ooOOOo0O0 = socket . ntohs ( o0ooOOOo0O0 )
  if ( len ( packet ) < o0ooOOOo0O0 ) : return ( None )
  if 84 - 84: I11i % Ii1I % O0 * o0oOOo0O0Ooo
  if 15 - 15: oO0o - iIii1I11I1II1 - II111iiii - IiII % I1ii11iIi11i
  if 80 - 80: IiII * iII111i . i1IIi % Ii1I % I1ii11iIi11i + ooOoO0o
  if 6 - 6: I1ii11iIi11i . oO0o . OoO0O00 + IiII
  oO0oo0O0OOOo0 = [ LISP_CS_25519_CBC , LISP_CS_25519_GCM , LISP_CS_25519_CHACHA ,
 LISP_CS_1024 ]
  if ( oO0oO0ooOoO0 not in oO0oo0O0OOOo0 ) :
   lprint ( "Cipher-suites {} supported, received {}" . format ( oO0oo0O0OOOo0 ,
 oO0oO0ooOoO0 ) )
   packet = packet [ o0ooOOOo0O0 : : ]
   return ( packet )
   if 29 - 29: I1IiiI
   if 41 - 41: I1Ii111 * OoO0O00 - iII111i . Ii1I
  self . cipher_suite = oO0oO0ooOoO0
  if 41 - 41: iIii1I11I1II1 - O0 - I1ii11iIi11i - oO0o + I1Ii111
  if 22 - 22: O0 % IiII % iII111i % I1IiiI
  if 34 - 34: iII111i . Oo0Ooo % I1ii11iIi11i . iII111i % IiII / IiII
  if 84 - 84: Ii1I
  if 1 - 1: oO0o - Oo0Ooo * iIii1I11I1II1 * Oo0Ooo * i1IIi
  OO = 0
  for oO in range ( 0 , o0ooOOOo0O0 , 8 ) :
   i1IIiI1iII = byte_swap_64 ( struct . unpack ( "Q" , packet [ oO : oO + 8 ] ) [ 0 ] )
   OO <<= 64
   OO |= i1IIiI1iII
   if 9 - 9: iII111i - iII111i
  self . remote_public_key = OO
  if 3 - 3: O0 + O0 - O0 - O0 % OoooooooOO + oO0o
  if 20 - 20: OoO0O00 + I11i . II111iiii / i11iIiiIii
  if 50 - 50: OoooooooOO / OoO0O00 % iIii1I11I1II1
  if 41 - 41: I1ii11iIi11i % I1ii11iIi11i + IiII . iII111i % I1Ii111 * ooOoO0o
  if 57 - 57: Ii1I . I1Ii111 . II111iiii % OoooooooOO * O0 + iIii1I11I1II1
  if ( self . curve25519 ) :
   i1IIiI1iII = lisp_hex_string ( self . remote_public_key )
   i1IIiI1iII = i1IIiI1iII . zfill ( 64 )
   oo0OO0Oo000oo = ""
   for oO in range ( 0 , len ( i1IIiI1iII ) , 2 ) :
    oo0OO0Oo000oo += chr ( int ( i1IIiI1iII [ oO : oO + 2 ] , 16 ) )
    if 38 - 38: iII111i + ooOoO0o
   self . remote_public_key = oo0OO0Oo000oo
   if 32 - 32: ooOoO0o - OoooooooOO + OoO0O00
   if 90 - 90: I1ii11iIi11i / OoooooooOO % i11iIiiIii - IiII
  packet = packet [ o0ooOOOo0O0 : : ]
  return ( packet )
  if 30 - 30: iII111i
  if 44 - 44: OoOoOO00 . OOooOOo
  if 84 - 84: I1Ii111 - I11i * OoOoOO00
  if 52 - 52: iII111i . IiII - I1ii11iIi11i * iIii1I11I1II1 % o0oOOo0O0Ooo / ooOoO0o
  if 18 - 18: OoOoOO00 % oO0o % OoO0O00 / iII111i
  if 88 - 88: iII111i * OOooOOo / i11iIiiIii / i1IIi
  if 76 - 76: Ii1I . I11i - OOooOOo + OoOoOO00 * OoO0O00 % I1Ii111
  if 24 - 24: iIii1I11I1II1 % Oo0Ooo % i11iIiiIii
class lisp_thread ( ) :
 def __init__ ( self , name ) :
  self . thread_name = name
  self . thread_number = - 1
  self . number_of_pcap_threads = 0
  self . number_of_worker_threads = 0
  self . input_queue = Queue . Queue ( )
  self . input_stats = lisp_stats ( )
  self . lisp_packet = lisp_packet ( None )
  if 55 - 55: iII111i
  if 19 - 19: OoooooooOO / OOooOOo * i11iIiiIii - I1IiiI
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
  if 40 - 40: iII111i
  if 62 - 62: ooOoO0o / OOooOOo
 def decode ( self , packet ) :
  oOO0OOOoO0ooo = "BBBBQ"
  I1111ii1i = struct . calcsize ( oOO0OOOoO0ooo )
  if ( len ( packet ) < I1111ii1i ) : return ( False )
  if 74 - 74: iII111i % I1Ii111 / I1Ii111 - iIii1I11I1II1 - II111iiii + OOooOOo
  o00o0O0o0o0 , Ii11i1IiII , OooO00oo , self . record_count , self . nonce = struct . unpack ( oOO0OOOoO0ooo , packet [ : I1111ii1i ] )
  if 63 - 63: OOooOOo
  if 52 - 52: iIii1I11I1II1 * OoOoOO00 + o0oOOo0O0Ooo . I11i
  self . type = o00o0O0o0o0 >> 4
  if ( self . type == LISP_MAP_REQUEST ) :
   self . smr_bit = True if ( o00o0O0o0o0 & 0x01 ) else False
   self . rloc_probe = True if ( o00o0O0o0o0 & 0x02 ) else False
   self . smr_invoked_bit = True if ( Ii11i1IiII & 0x40 ) else False
   if 59 - 59: iII111i . i1IIi
  if ( self . type == LISP_ECM ) :
   self . ddt_bit = True if ( o00o0O0o0o0 & 0x04 ) else False
   self . to_etr = True if ( o00o0O0o0o0 & 0x02 ) else False
   self . to_ms = True if ( o00o0O0o0o0 & 0x01 ) else False
   if 31 - 31: I1IiiI + I1IiiI
  if ( self . type == LISP_NAT_INFO ) :
   self . info_reply = True if ( o00o0O0o0o0 & 0x08 ) else False
   if 11 - 11: IiII + OoOoOO00 % o0oOOo0O0Ooo * OoO0O00 / IiII
  return ( True )
  if 5 - 5: iII111i / oO0o % ooOoO0o . i11iIiiIii % OoOoOO00 + oO0o
  if 95 - 95: I1ii11iIi11i
 def is_info_request ( self ) :
  return ( ( self . type == LISP_NAT_INFO and self . is_info_reply ( ) == False ) )
  if 48 - 48: I11i
  if 14 - 14: iIii1I11I1II1 / o0oOOo0O0Ooo * IiII
 def is_info_reply ( self ) :
  return ( True if self . info_reply else False )
  if 35 - 35: iIii1I11I1II1
  if 34 - 34: OoO0O00 % I1IiiI . o0oOOo0O0Ooo % OoO0O00 % OoO0O00
 def is_rloc_probe ( self ) :
  return ( True if self . rloc_probe else False )
  if 30 - 30: I1IiiI + I1IiiI
  if 75 - 75: I1IiiI - ooOoO0o - I1IiiI % oO0o % OoooooooOO
 def is_smr ( self ) :
  return ( True if self . smr_bit else False )
  if 13 - 13: ooOoO0o * OoO0O00 % iIii1I11I1II1 / IiII * iII111i . Oo0Ooo
  if 23 - 23: ooOoO0o / IiII . iII111i * Ii1I
 def is_smr_invoked ( self ) :
  return ( True if self . smr_invoked_bit else False )
  if 87 - 87: i11iIiiIii
  if 34 - 34: i1IIi
 def is_ddt ( self ) :
  return ( True if self . ddt_bit else False )
  if 64 - 64: iIii1I11I1II1 / IiII / Oo0Ooo - I1ii11iIi11i
  if 100 - 100: IiII + i1IIi * OoO0O00
 def is_to_etr ( self ) :
  return ( True if self . to_etr else False )
  if 64 - 64: oO0o * i11iIiiIii . Oo0Ooo
  if 52 - 52: Oo0Ooo / ooOoO0o / iII111i - o0oOOo0O0Ooo / iII111i
 def is_to_ms ( self ) :
  return ( True if self . to_ms else False )
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
  if 65 - 65: II111iiii % i1IIi
  if 13 - 13: OoO0O00 * I1Ii111 + Oo0Ooo - IiII
  if 31 - 31: OoO0O00
  if 68 - 68: OoO0O00 + i1IIi / iIii1I11I1II1 + II111iiii * iIii1I11I1II1 + I1ii11iIi11i
  if 77 - 77: i11iIiiIii - I1Ii111 . I1ii11iIi11i % Oo0Ooo . Ii1I
  if 9 - 9: o0oOOo0O0Ooo
  if 55 - 55: OOooOOo % iIii1I11I1II1 + I11i . ooOoO0o
  if 71 - 71: i11iIiiIii / i1IIi + OoOoOO00
  if 23 - 23: i11iIiiIii
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
  if 88 - 88: II111iiii - iII111i / OoooooooOO
  if 71 - 71: I1ii11iIi11i
 def print_map_register ( self ) :
  IIIIiiii = lisp_hex_string ( self . xtr_id )
  if 20 - 20: i1IIi * iII111i + OoO0O00 * OoO0O00 / Oo0Ooo
  i11ii = ( "{} -> flags: {}{}{}{}{}{}{}{}{}, record-count: " +
 "{}, nonce: 0x{}, key/alg-id: {}/{}{}, auth-len: {}, xtr-id: " +
 "0x{}, site-id: {}" )
  if 83 - 83: I1ii11iIi11i
  lprint ( i11ii . format ( bold ( "Map-Register" , False ) , "P" if self . proxy_reply_requested else "p" ,
  # OOooOOo % i11iIiiIii + OoO0O00 * OoO0O00
 "S" if self . lisp_sec_present else "s" ,
 "I" if self . xtr_id_present else "i" ,
 "T" if self . use_ttl_for_timeout else "t" ,
 "R" if self . merge_register_requested else "r" ,
 "M" if self . mobile_node else "m" ,
 "N" if self . map_notify_requested else "n" ,
 "F" if self . map_register_refresh else "f" ,
 "E" if self . encrypt_bit else "e" ,
 self . record_count , lisp_hex_string ( self . nonce ) , self . key_id ,
 self . alg_id , " (sha1)" if ( self . key_id == LISP_SHA_1_96_ALG_ID ) else ( " (sha2)" if ( self . key_id == LISP_SHA_256_128_ALG_ID ) else "" ) , self . auth_len , IIIIiiii , self . site_id ) )
  if 32 - 32: Ii1I - Ii1I
  if 6 - 6: iIii1I11I1II1 - i11iIiiIii / I1ii11iIi11i - o0oOOo0O0Ooo
  if 95 - 95: I11i
  if 76 - 76: II111iiii - i1IIi . O0 * i11iIiiIii % o0oOOo0O0Ooo - iII111i
 def encode ( self ) :
  O0ooOo0Oooo = ( LISP_MAP_REGISTER << 28 ) | self . record_count
  if ( self . proxy_reply_requested ) : O0ooOo0Oooo |= 0x08000000
  if ( self . lisp_sec_present ) : O0ooOo0Oooo |= 0x04000000
  if ( self . xtr_id_present ) : O0ooOo0Oooo |= 0x02000000
  if ( self . map_register_refresh ) : O0ooOo0Oooo |= 0x1000
  if ( self . use_ttl_for_timeout ) : O0ooOo0Oooo |= 0x800
  if ( self . merge_register_requested ) : O0ooOo0Oooo |= 0x400
  if ( self . mobile_node ) : O0ooOo0Oooo |= 0x200
  if ( self . map_notify_requested ) : O0ooOo0Oooo |= 0x100
  if ( self . encryption_key_id != None ) :
   O0ooOo0Oooo |= 0x2000
   O0ooOo0Oooo |= self . encryption_key_id << 14
   if 30 - 30: I1Ii111 % oO0o + oO0o * OoooooooOO - I1ii11iIi11i
   if 69 - 69: I1ii11iIi11i + OoO0O00 / O0 + II111iiii / i11iIiiIii
   if 48 - 48: OoooooooOO / I1IiiI
   if 19 - 19: OOooOOo * I1ii11iIi11i - ooOoO0o * i11iIiiIii + I11i
   if 92 - 92: OoO0O00
  if ( self . alg_id == LISP_NONE_ALG_ID ) :
   self . auth_len = 0
  else :
   if ( self . alg_id == LISP_SHA_1_96_ALG_ID ) :
    self . auth_len = LISP_SHA1_160_AUTH_DATA_LEN
    if 99 - 99: OoOoOO00 . iII111i - OoooooooOO - O0
   if ( self . alg_id == LISP_SHA_256_128_ALG_ID ) :
    self . auth_len = LISP_SHA2_256_AUTH_DATA_LEN
    if 6 - 6: OOooOOo
    if 3 - 3: O0 - I1Ii111 * Ii1I * OOooOOo / Ii1I
    if 58 - 58: Ii1I * iIii1I11I1II1 + ooOoO0o . ooOoO0o
  iI1IIII1ii1 = struct . pack ( "I" , socket . htonl ( O0ooOo0Oooo ) )
  iI1IIII1ii1 += struct . pack ( "QBBH" , self . nonce , self . key_id , self . alg_id ,
 socket . htons ( self . auth_len ) )
  if 74 - 74: ooOoO0o - o0oOOo0O0Ooo * IiII % ooOoO0o
  iI1IIII1ii1 = self . zero_auth ( iI1IIII1ii1 )
  return ( iI1IIII1ii1 )
  if 93 - 93: iIii1I11I1II1 / OoOoOO00 % Oo0Ooo * I1Ii111 - OoO0O00 - o0oOOo0O0Ooo
  if 44 - 44: OoooooooOO
 def zero_auth ( self , packet ) :
  oOO0OO0O = struct . calcsize ( "I" ) + struct . calcsize ( "QHH" )
  oOi1IiIiIii11I = ""
  O0o0O00 = 0
  if ( self . alg_id == LISP_NONE_ALG_ID ) : return ( packet )
  if ( self . alg_id == LISP_SHA_1_96_ALG_ID ) :
   oOi1IiIiIii11I = struct . pack ( "QQI" , 0 , 0 , 0 )
   O0o0O00 = struct . calcsize ( "QQI" )
   if 85 - 85: i11iIiiIii . I11i + Ii1I / Ii1I
  if ( self . alg_id == LISP_SHA_256_128_ALG_ID ) :
   oOi1IiIiIii11I = struct . pack ( "QQQQ" , 0 , 0 , 0 , 0 )
   O0o0O00 = struct . calcsize ( "QQQQ" )
   if 43 - 43: IiII . OoooooooOO - II111iiii
  packet = packet [ 0 : oOO0OO0O ] + oOi1IiIiIii11I + packet [ oOO0OO0O + O0o0O00 : : ]
  return ( packet )
  if 90 - 90: I1IiiI - iIii1I11I1II1 + I1ii11iIi11i * OOooOOo * oO0o
  if 19 - 19: I1Ii111 * II111iiii % Oo0Ooo - i1IIi
 def encode_auth ( self , packet ) :
  oOO0OO0O = struct . calcsize ( "I" ) + struct . calcsize ( "QHH" )
  O0o0O00 = self . auth_len
  oOi1IiIiIii11I = self . auth_data
  packet = packet [ 0 : oOO0OO0O ] + oOi1IiIiIii11I + packet [ oOO0OO0O + O0o0O00 : : ]
  return ( packet )
  if 27 - 27: OoOoOO00 . O0 / I1ii11iIi11i . iIii1I11I1II1
  if 15 - 15: Ii1I + OoO0O00 % iIii1I11I1II1 - I1ii11iIi11i - i1IIi % o0oOOo0O0Ooo
 def decode ( self , packet ) :
  O0ooO00OO = packet
  oOO0OOOoO0ooo = "I"
  I1111ii1i = struct . calcsize ( oOO0OOOoO0ooo )
  if ( len ( packet ) < I1111ii1i ) : return ( [ None , None ] )
  if 43 - 43: II111iiii . iII111i / Ii1I - I11i
  O0ooOo0Oooo = struct . unpack ( oOO0OOOoO0ooo , packet [ : I1111ii1i ] )
  O0ooOo0Oooo = socket . ntohl ( O0ooOo0Oooo [ 0 ] )
  packet = packet [ I1111ii1i : : ]
  if 36 - 36: iII111i - IiII * iIii1I11I1II1 % I11i / IiII
  oOO0OOOoO0ooo = "QBBH"
  I1111ii1i = struct . calcsize ( oOO0OOOoO0ooo )
  if ( len ( packet ) < I1111ii1i ) : return ( [ None , None ] )
  if 35 - 35: II111iiii . O0 - iII111i / OoooooooOO . II111iiii * I1IiiI
  self . nonce , self . key_id , self . alg_id , self . auth_len = struct . unpack ( oOO0OOOoO0ooo , packet [ : I1111ii1i ] )
  if 15 - 15: O0
  if 32 - 32: OoooooooOO
  self . auth_len = socket . ntohs ( self . auth_len )
  self . proxy_reply_requested = True if ( O0ooOo0Oooo & 0x08000000 ) else False
  if 29 - 29: I1ii11iIi11i
  self . lisp_sec_present = True if ( O0ooOo0Oooo & 0x04000000 ) else False
  self . xtr_id_present = True if ( O0ooOo0Oooo & 0x02000000 ) else False
  self . use_ttl_for_timeout = True if ( O0ooOo0Oooo & 0x800 ) else False
  self . map_register_refresh = True if ( O0ooOo0Oooo & 0x1000 ) else False
  self . merge_register_requested = True if ( O0ooOo0Oooo & 0x400 ) else False
  self . mobile_node = True if ( O0ooOo0Oooo & 0x200 ) else False
  self . map_notify_requested = True if ( O0ooOo0Oooo & 0x100 ) else False
  self . record_count = O0ooOo0Oooo & 0xff
  if 41 - 41: Ii1I
  if 49 - 49: Ii1I % II111iiii . Ii1I - o0oOOo0O0Ooo - I11i * IiII
  if 47 - 47: O0 . o0oOOo0O0Ooo / Ii1I * iII111i
  if 63 - 63: I1Ii111 - oO0o - iII111i - ooOoO0o / oO0o + OoO0O00
  self . encrypt_bit = True if O0ooOo0Oooo & 0x2000 else False
  if ( self . encrypt_bit ) :
   self . encryption_key_id = ( O0ooOo0Oooo >> 14 ) & 0x7
   if 94 - 94: IiII / I1IiiI . II111iiii
   if 32 - 32: oO0o . OOooOOo % OOooOOo . OoOoOO00
   if 37 - 37: OOooOOo + O0 + OOooOOo . iII111i . o0oOOo0O0Ooo
   if 78 - 78: I1IiiI / I11i + o0oOOo0O0Ooo . Oo0Ooo / O0
   if 49 - 49: I1ii11iIi11i
  if ( self . xtr_id_present ) :
   if ( self . decode_xtr_id ( O0ooO00OO ) == False ) : return ( [ None , None ] )
   if 66 - 66: o0oOOo0O0Ooo . I1ii11iIi11i
   if 18 - 18: Oo0Ooo + IiII
  packet = packet [ I1111ii1i : : ]
  if 79 - 79: OoO0O00 - O0 + II111iiii % Ii1I . I1IiiI
  if 43 - 43: I1IiiI % I1ii11iIi11i * Ii1I
  if 31 - 31: Ii1I / iII111i
  if 3 - 3: IiII
  if ( self . auth_len != 0 ) :
   if ( len ( packet ) < self . auth_len ) : return ( [ None , None ] )
   if 37 - 37: Ii1I * OoooooooOO * I11i + Oo0Ooo . I1IiiI
   if ( self . alg_id not in ( LISP_NONE_ALG_ID , LISP_SHA_1_96_ALG_ID ,
 LISP_SHA_256_128_ALG_ID ) ) :
    lprint ( "Invalid authentication alg-id: {}" . format ( self . alg_id ) )
    return ( [ None , None ] )
    if 61 - 61: OOooOOo . OOooOOo
    if 17 - 17: II111iiii / ooOoO0o
   O0o0O00 = self . auth_len
   if ( self . alg_id == LISP_SHA_1_96_ALG_ID ) :
    I1111ii1i = struct . calcsize ( "QQI" )
    if ( O0o0O00 < I1111ii1i ) :
     lprint ( "Invalid sha1-96 authentication length" )
     return ( [ None , None ] )
     if 80 - 80: OOooOOo * OoO0O00 + Ii1I
    oo0 , iI1IIIi11iIII , O0oO0o0O0O = struct . unpack ( "QQI" , packet [ : O0o0O00 ] )
    ii11iIi1IiI = ""
   elif ( self . alg_id == LISP_SHA_256_128_ALG_ID ) :
    I1111ii1i = struct . calcsize ( "QQQQ" )
    if ( O0o0O00 < I1111ii1i ) :
     lprint ( "Invalid sha2-256 authentication length" )
     return ( [ None , None ] )
     if 59 - 59: i11iIiiIii % ooOoO0o - oO0o
    oo0 , iI1IIIi11iIII , O0oO0o0O0O , ii11iIi1IiI = struct . unpack ( "QQQQ" ,
 packet [ : O0o0O00 ] )
   else :
    lprint ( "Unsupported authentication alg-id value {}" . format ( self . alg_id ) )
    if 37 - 37: I1IiiI - iIii1I11I1II1
    return ( [ None , None ] )
    if 56 - 56: IiII - Ii1I + i11iIiiIii * OoO0O00 % I1IiiI
   self . auth_data = lisp_concat_auth_data ( self . alg_id , oo0 , iI1IIIi11iIII ,
 O0oO0o0O0O , ii11iIi1IiI )
   O0ooO00OO = self . zero_auth ( O0ooO00OO )
   packet = packet [ self . auth_len : : ]
   if 37 - 37: iIii1I11I1II1 + IiII / I1Ii111 . OoooooooOO
  return ( [ O0ooO00OO , packet ] )
  if 72 - 72: oO0o % ooOoO0o % OOooOOo
  if 63 - 63: OoO0O00 . Ii1I % II111iiii / I11i - OoOoOO00
 def encode_xtr_id ( self , packet ) :
  IIiiI1Ii = self . xtr_id >> 64
  OoooOo = self . xtr_id & 0xffffffffffffffff
  IIiiI1Ii = byte_swap_64 ( IIiiI1Ii )
  OoooOo = byte_swap_64 ( OoooOo )
  O0Oo = byte_swap_64 ( self . site_id )
  packet += struct . pack ( "QQQ" , IIiiI1Ii , OoooOo , O0Oo )
  return ( packet )
  if 63 - 63: IiII * i11iIiiIii
  if 86 - 86: I11i % I11i - OoOoOO00 + I1Ii111 / I1IiiI * OoooooooOO
 def decode_xtr_id ( self , packet ) :
  I1111ii1i = struct . calcsize ( "QQQ" )
  if ( len ( packet ) < I1111ii1i ) : return ( [ None , None ] )
  packet = packet [ len ( packet ) - I1111ii1i : : ]
  IIiiI1Ii , OoooOo , O0Oo = struct . unpack ( "QQQ" ,
 packet [ : I1111ii1i ] )
  IIiiI1Ii = byte_swap_64 ( IIiiI1Ii )
  OoooOo = byte_swap_64 ( OoooOo )
  self . xtr_id = ( IIiiI1Ii << 64 ) | OoooOo
  self . site_id = byte_swap_64 ( O0Oo )
  return ( True )
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
  if 48 - 48: I1ii11iIi11i . I1IiiI
  if 73 - 73: O0 . I1Ii111 - OoooooooOO % I11i % i1IIi
 def print_notify ( self ) :
  oOi1IiIiIii11I = binascii . hexlify ( self . auth_data )
  if ( self . alg_id == LISP_SHA_1_96_ALG_ID and len ( oOi1IiIiIii11I ) != 40 ) :
   oOi1IiIiIii11I = self . auth_data
  elif ( self . alg_id == LISP_SHA_256_128_ALG_ID and len ( oOi1IiIiIii11I ) != 64 ) :
   oOi1IiIiIii11I = self . auth_data
   if 14 - 14: I1Ii111 + Ii1I * Oo0Ooo
  i11ii = ( "{} -> record-count: {}, nonce: 0x{}, key/alg-id: " +
 "{}{}{}, auth-len: {}, auth-data: {}" )
  lprint ( i11ii . format ( bold ( "Map-Notify-Ack" , False ) if self . map_notify_ack else bold ( "Map-Notify" , False ) ,
  # Oo0Ooo . OOooOOo - I1Ii111
 self . record_count , lisp_hex_string ( self . nonce ) , self . key_id ,
 self . alg_id , " (sha1)" if ( self . key_id == LISP_SHA_1_96_ALG_ID ) else ( " (sha2)" if ( self . key_id == LISP_SHA_256_128_ALG_ID ) else "" ) , self . auth_len , oOi1IiIiIii11I ) )
  if 10 - 10: oO0o * IiII * iII111i . O0
  if 19 - 19: IiII
  if 75 - 75: Ii1I % O0
  if 57 - 57: O0 . OoO0O00
 def zero_auth ( self , packet ) :
  if ( self . alg_id == LISP_NONE_ALG_ID ) : return ( packet )
  if ( self . alg_id == LISP_SHA_1_96_ALG_ID ) :
   oOi1IiIiIii11I = struct . pack ( "QQI" , 0 , 0 , 0 )
   if 32 - 32: ooOoO0o
  if ( self . alg_id == LISP_SHA_256_128_ALG_ID ) :
   oOi1IiIiIii11I = struct . pack ( "QQQQ" , 0 , 0 , 0 , 0 )
   if 26 - 26: O0 * Ii1I - I1IiiI - iII111i / iIii1I11I1II1
  packet += oOi1IiIiIii11I
  return ( packet )
  if 57 - 57: I1ii11iIi11i - OoO0O00 * iIii1I11I1II1
  if 26 - 26: OoO0O00 % ooOoO0o % o0oOOo0O0Ooo % OoOoOO00 . iII111i % O0
 def encode ( self , eid_records , password ) :
  if ( self . map_notify_ack ) :
   O0ooOo0Oooo = ( LISP_MAP_NOTIFY_ACK << 28 ) | self . record_count
  else :
   O0ooOo0Oooo = ( LISP_MAP_NOTIFY << 28 ) | self . record_count
   if 91 - 91: II111iiii . Oo0Ooo . oO0o - OoooooooOO / OoOoOO00
  iI1IIII1ii1 = struct . pack ( "I" , socket . htonl ( O0ooOo0Oooo ) )
  iI1IIII1ii1 += struct . pack ( "QBBH" , self . nonce , self . key_id , self . alg_id ,
 socket . htons ( self . auth_len ) )
  if 30 - 30: I11i % o0oOOo0O0Ooo + i1IIi * OoooooooOO * OoO0O00 - II111iiii
  if ( self . alg_id == LISP_NONE_ALG_ID ) :
   self . packet = iI1IIII1ii1 + eid_records
   return ( self . packet )
   if 55 - 55: OoO0O00
   if 20 - 20: ooOoO0o * I1Ii111 * o0oOOo0O0Ooo - ooOoO0o
   if 32 - 32: Ii1I * oO0o
   if 85 - 85: i11iIiiIii . OoO0O00 + OoO0O00
   if 28 - 28: Oo0Ooo
  iI1IIII1ii1 = self . zero_auth ( iI1IIII1ii1 )
  iI1IIII1ii1 += eid_records
  if 62 - 62: Oo0Ooo + OoooooooOO / iII111i
  oO000o0o0oOo0 = lisp_hash_me ( iI1IIII1ii1 , self . alg_id , password , False )
  if 60 - 60: Ii1I / OoOoOO00 . I11i % OOooOOo
  oOO0OO0O = struct . calcsize ( "I" ) + struct . calcsize ( "QHH" )
  O0o0O00 = self . auth_len
  self . auth_data = oO000o0o0oOo0
  iI1IIII1ii1 = iI1IIII1ii1 [ 0 : oOO0OO0O ] + oO000o0o0oOo0 + iI1IIII1ii1 [ oOO0OO0O + O0o0O00 : : ]
  self . packet = iI1IIII1ii1
  return ( iI1IIII1ii1 )
  if 61 - 61: O0 . Ii1I . O0 * i11iIiiIii * II111iiii / I1Ii111
  if 69 - 69: I11i
 def decode ( self , packet ) :
  O0ooO00OO = packet
  oOO0OOOoO0ooo = "I"
  I1111ii1i = struct . calcsize ( oOO0OOOoO0ooo )
  if ( len ( packet ) < I1111ii1i ) : return ( None )
  if 17 - 17: I11i
  O0ooOo0Oooo = struct . unpack ( oOO0OOOoO0ooo , packet [ : I1111ii1i ] )
  O0ooOo0Oooo = socket . ntohl ( O0ooOo0Oooo [ 0 ] )
  self . map_notify_ack = ( ( O0ooOo0Oooo >> 28 ) == LISP_MAP_NOTIFY_ACK )
  self . record_count = O0ooOo0Oooo & 0xff
  packet = packet [ I1111ii1i : : ]
  if 38 - 38: I1Ii111 % OOooOOo
  oOO0OOOoO0ooo = "QBBH"
  I1111ii1i = struct . calcsize ( oOO0OOOoO0ooo )
  if ( len ( packet ) < I1111ii1i ) : return ( None )
  if 9 - 9: O0 . iIii1I11I1II1
  self . nonce , self . key_id , self . alg_id , self . auth_len = struct . unpack ( oOO0OOOoO0ooo , packet [ : I1111ii1i ] )
  if 44 - 44: I1ii11iIi11i % IiII
  self . nonce_key = lisp_hex_string ( self . nonce )
  self . auth_len = socket . ntohs ( self . auth_len )
  packet = packet [ I1111ii1i : : ]
  self . eid_records = packet [ self . auth_len : : ]
  if 6 - 6: OoO0O00
  if ( self . auth_len == 0 ) : return ( self . eid_records )
  if 82 - 82: iIii1I11I1II1 . I11i / IiII / OOooOOo * II111iiii % oO0o
  if 62 - 62: II111iiii
  if 96 - 96: I11i % OoOoOO00 * I1ii11iIi11i
  if 94 - 94: Oo0Ooo - i1IIi . O0 % Oo0Ooo . ooOoO0o
  if ( len ( packet ) < self . auth_len ) : return ( None )
  if 63 - 63: i11iIiiIii % I1ii11iIi11i % I1IiiI . IiII * o0oOOo0O0Ooo + OOooOOo
  O0o0O00 = self . auth_len
  if ( self . alg_id == LISP_SHA_1_96_ALG_ID ) :
   oo0 , iI1IIIi11iIII , O0oO0o0O0O = struct . unpack ( "QQI" , packet [ : O0o0O00 ] )
   ii11iIi1IiI = ""
   if 77 - 77: o0oOOo0O0Ooo
  if ( self . alg_id == LISP_SHA_256_128_ALG_ID ) :
   oo0 , iI1IIIi11iIII , O0oO0o0O0O , ii11iIi1IiI = struct . unpack ( "QQQQ" ,
 packet [ : O0o0O00 ] )
   if 63 - 63: ooOoO0o * oO0o + ooOoO0o * Ii1I + Oo0Ooo / I1ii11iIi11i
  self . auth_data = lisp_concat_auth_data ( self . alg_id , oo0 , iI1IIIi11iIII ,
 O0oO0o0O0O , ii11iIi1IiI )
  if 15 - 15: O0 . I1ii11iIi11i * I1ii11iIi11i
  I1111ii1i = struct . calcsize ( "I" ) + struct . calcsize ( "QHH" )
  packet = self . zero_auth ( O0ooO00OO [ : I1111ii1i ] )
  I1111ii1i += O0o0O00
  packet += O0ooO00OO [ I1111ii1i : : ]
  return ( packet )
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
  if 82 - 82: O0 / iII111i * OoO0O00 - I11i + Oo0Ooo
  if 47 - 47: I1ii11iIi11i * I1IiiI / I1ii11iIi11i + Ii1I * II111iiii
  if 78 - 78: I1Ii111 - i1IIi + OoOoOO00 + Oo0Ooo * I1ii11iIi11i * o0oOOo0O0Ooo
  if 97 - 97: i1IIi
  if 29 - 29: I1IiiI
  if 37 - 37: I1ii11iIi11i * I1Ii111 * I1IiiI * O0
  if 35 - 35: I1IiiI - I1ii11iIi11i * iII111i + IiII / i1IIi
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
  if 46 - 46: Oo0Ooo . ooOoO0o % Oo0Ooo / II111iiii * ooOoO0o * OOooOOo
  if 59 - 59: I1Ii111 * iII111i
 def print_prefix ( self ) :
  if ( self . target_group . is_null ( ) ) :
   return ( green ( self . target_eid . print_prefix ( ) , False ) )
   if 31 - 31: I11i / O0
  return ( green ( self . target_eid . print_sg ( self . target_group ) , False ) )
  if 57 - 57: i1IIi % ooOoO0o
  if 69 - 69: o0oOOo0O0Ooo
 def print_map_request ( self ) :
  IIIIiiii = ""
  if ( self . xtr_id != None and self . subscribe_bit ) :
   IIIIiiii = "subscribe, xtr-id: 0x{}, " . format ( lisp_hex_string ( self . xtr_id ) )
   if 69 - 69: I1Ii111
   if 83 - 83: iIii1I11I1II1 . o0oOOo0O0Ooo + I1Ii111 . OoooooooOO / ooOoO0o + II111iiii
   if 90 - 90: Ii1I * iII111i / OOooOOo
  i11ii = ( "{} -> flags: {}{}{}{}{}{}{}{}{}{}, itr-rloc-" +
 "count: {} (+1), record-count: {}, nonce: 0x{}, source-eid: " +
 "afi {}, {}{}, target-eid: afi {}, {}, {}ITR-RLOCs:" )
  if 68 - 68: OoOoOO00
  lprint ( i11ii . format ( bold ( "Map-Request" , False ) , "A" if self . auth_bit else "a" ,
  # oO0o . i11iIiiIii % Ii1I - IiII
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
 self . target_eid . afi , green ( self . print_prefix ( ) , False ) , IIIIiiii ) )
  if 83 - 83: OoOoOO00 + I1ii11iIi11i
  II1i = self . keys
  for iIi1 in self . itr_rlocs :
   lprint ( "  itr-rloc: afi {} {}{}" . format ( iIi1 . afi ,
 red ( iIi1 . print_address_no_iid ( ) , False ) ,
 "" if ( II1i == None ) else ", " + II1i [ 1 ] . print_keys ( ) ) )
   II1i = None
   if 65 - 65: Ii1I
   if 71 - 71: I1Ii111 % I1Ii111 . oO0o + i11iIiiIii - i11iIiiIii
   if 16 - 16: iIii1I11I1II1 / I1IiiI / I1Ii111 - i11iIiiIii . ooOoO0o / OOooOOo
 def sign_map_request ( self , privkey ) :
  IIIi11iiIIi = self . signature_eid . print_address ( )
  oOo000O00O = self . source_eid . print_address ( )
  OooO = self . target_eid . print_address ( )
  ooOOoOO000 = lisp_hex_string ( self . nonce ) + oOo000O00O + OooO
  self . map_request_signature = privkey . sign ( ooOOoOO000 )
  oOO0 = binascii . b2a_base64 ( self . map_request_signature )
  oOO0 = { "source-eid" : oOo000O00O , "signature-eid" : IIIi11iiIIi ,
 "signature" : oOO0 }
  return ( json . dumps ( oOO0 ) )
  if 47 - 47: i11iIiiIii
  if 98 - 98: OoooooooOO
 def verify_map_request_sig ( self , pubkey ) :
  OOo = green ( self . signature_eid . print_address ( ) , False )
  if ( pubkey == None ) :
   lprint ( "Public-key not found for signature-EID {}" . format ( OOo ) )
   return ( False )
   if 86 - 86: OoOoOO00 . O0 . oO0o
   if 96 - 96: ooOoO0o / oO0o % O0 / OOooOOo * OoO0O00 * I11i
  oOo000O00O = self . source_eid . print_address ( )
  OooO = self . target_eid . print_address ( )
  ooOOoOO000 = lisp_hex_string ( self . nonce ) + oOo000O00O + OooO
  pubkey = binascii . a2b_base64 ( pubkey )
  if 27 - 27: OoOoOO00 % Ii1I / i1IIi . i1IIi * OoooooooOO % ooOoO0o
  O0o0O00O0 = True
  try :
   i1IIiI1iII = ecdsa . VerifyingKey . from_pem ( pubkey )
  except :
   lprint ( "Invalid public-key in mapping system for sig-eid {}" . format ( self . signature_eid . print_address_no_iid ( ) ) )
   if 67 - 67: OoooooooOO * OoO0O00 * iII111i + ooOoO0o - i1IIi
   O0o0O00O0 = False
   if 66 - 66: IiII / OoOoOO00 % O0 % o0oOOo0O0Ooo - OOooOOo / OoOoOO00
   if 11 - 11: I1IiiI + IiII
  if ( O0o0O00O0 ) :
   try :
    O0o0O00O0 = i1IIiI1iII . verify ( self . map_request_signature , ooOOoOO000 )
   except :
    O0o0O00O0 = False
    if 95 - 95: I1IiiI - OOooOOo . Oo0Ooo / O0 + Ii1I
    if 67 - 67: OoOoOO00 % Oo0Ooo
    if 7 - 7: i11iIiiIii % I1ii11iIi11i / I1Ii111 % Oo0Ooo - OoO0O00
  o0OOo0o0 = bold ( "passed" if O0o0O00O0 else "failed" , False )
  lprint ( "Signature verification {} for EID {}" . format ( o0OOo0o0 , OOo ) )
  return ( O0o0O00O0 )
  if 60 - 60: o0oOOo0O0Ooo / Oo0Ooo
  if 19 - 19: iIii1I11I1II1 . OoO0O00 / OoooooooOO
 def encode ( self , probe_dest , probe_port ) :
  O0ooOo0Oooo = ( LISP_MAP_REQUEST << 28 ) | self . record_count
  O0ooOo0Oooo = O0ooOo0Oooo | ( self . itr_rloc_count << 8 )
  if ( self . auth_bit ) : O0ooOo0Oooo |= 0x08000000
  if ( self . map_data_present ) : O0ooOo0Oooo |= 0x04000000
  if ( self . rloc_probe ) : O0ooOo0Oooo |= 0x02000000
  if ( self . smr_bit ) : O0ooOo0Oooo |= 0x01000000
  if ( self . pitr_bit ) : O0ooOo0Oooo |= 0x00800000
  if ( self . smr_invoked_bit ) : O0ooOo0Oooo |= 0x00400000
  if ( self . mobile_node ) : O0ooOo0Oooo |= 0x00200000
  if ( self . xtr_id_present ) : O0ooOo0Oooo |= 0x00100000
  if ( self . local_xtr ) : O0ooOo0Oooo |= 0x00004000
  if ( self . dont_reply_bit ) : O0ooOo0Oooo |= 0x00002000
  if 2 - 2: O0 - O0 % I1Ii111 / I1ii11iIi11i
  iI1IIII1ii1 = struct . pack ( "I" , socket . htonl ( O0ooOo0Oooo ) )
  iI1IIII1ii1 += struct . pack ( "Q" , self . nonce )
  if 76 - 76: OoO0O00 * oO0o - OoO0O00
  if 57 - 57: OoooooooOO / OoOoOO00 + oO0o . Ii1I
  if 14 - 14: i11iIiiIii % OOooOOo * o0oOOo0O0Ooo * OoOoOO00
  if 55 - 55: I1Ii111 * OOooOOo * I1Ii111
  if 70 - 70: O0 . Ii1I
  if 33 - 33: OOooOOo * Ii1I
  oooIII1II1I1iI = False
  oOOOO = self . privkey_filename
  if ( oOOOO != None and os . path . exists ( oOOOO ) ) :
   Oo0OO0o0oOO0 = open ( oOOOO , "r" ) ; i1IIiI1iII = Oo0OO0o0oOO0 . read ( ) ; Oo0OO0o0oOO0 . close ( )
   try :
    i1IIiI1iII = ecdsa . SigningKey . from_pem ( i1IIiI1iII )
   except :
    return ( None )
    if 48 - 48: I11i
   O0OoOOo0o = self . sign_map_request ( i1IIiI1iII )
   oooIII1II1I1iI = True
  elif ( self . map_request_signature != None ) :
   oOO0 = binascii . b2a_base64 ( self . map_request_signature )
   O0OoOOo0o = { "source-eid" : self . source_eid . print_address ( ) ,
 "signature-eid" : self . signature_eid . print_address ( ) ,
 "signature" : oOO0 }
   O0OoOOo0o = json . dumps ( O0OoOOo0o )
   oooIII1II1I1iI = True
   if 21 - 21: I11i - I1IiiI / OoooooooOO . i1IIi + II111iiii
  if ( oooIII1II1I1iI ) :
   O00OO0oOOO = LISP_LCAF_JSON_TYPE
   O0OOOOO0O = socket . htons ( LISP_AFI_LCAF )
   ii111 = socket . htons ( len ( O0OoOOo0o ) + 2 )
   i1oO0o00oOo00oO = socket . htons ( len ( O0OoOOo0o ) )
   iI1IIII1ii1 += struct . pack ( "HBBBBHH" , O0OOOOO0O , 0 , 0 , O00OO0oOOO , 0 ,
 ii111 , i1oO0o00oOo00oO )
   iI1IIII1ii1 += O0OoOOo0o
   iI1IIII1ii1 += struct . pack ( "H" , 0 )
  else :
   if ( self . source_eid . instance_id != 0 ) :
    iI1IIII1ii1 += struct . pack ( "H" , socket . htons ( LISP_AFI_LCAF ) )
    iI1IIII1ii1 += self . source_eid . lcaf_encode_iid ( )
   else :
    iI1IIII1ii1 += struct . pack ( "H" , socket . htons ( self . source_eid . afi ) )
    iI1IIII1ii1 += self . source_eid . pack_address ( )
    if 68 - 68: iIii1I11I1II1 - I1IiiI . oO0o + OoOoOO00
    if 94 - 94: o0oOOo0O0Ooo % o0oOOo0O0Ooo % II111iiii * iIii1I11I1II1 / IiII . I1ii11iIi11i
    if 13 - 13: OoOoOO00 . I1IiiI . o0oOOo0O0Ooo * oO0o / Ii1I
    if 38 - 38: IiII - i1IIi . i11iIiiIii
    if 28 - 28: I1Ii111 / oO0o . I1ii11iIi11i
    if 83 - 83: I11i
    if 36 - 36: iIii1I11I1II1
  if ( probe_dest ) :
   if ( probe_port == 0 ) : probe_port = LISP_DATA_PORT
   OoOOoooO000 = probe_dest . print_address_no_iid ( ) + ":" + str ( probe_port )
   if 74 - 74: IiII * I1ii11iIi11i - OoooooooOO
   if ( lisp_crypto_keys_by_rloc_encap . has_key ( OoOOoooO000 ) ) :
    self . keys = lisp_crypto_keys_by_rloc_encap [ OoOOoooO000 ]
    if 59 - 59: ooOoO0o * OoO0O00 - I1Ii111 % oO0o
    if 95 - 95: II111iiii + II111iiii
    if 33 - 33: i1IIi . Oo0Ooo - IiII
    if 30 - 30: OoooooooOO % OOooOOo
    if 14 - 14: OoOoOO00 / OoO0O00 / i11iIiiIii - OoOoOO00 / o0oOOo0O0Ooo - OOooOOo
    if 81 - 81: iII111i % Ii1I . ooOoO0o
    if 66 - 66: I1ii11iIi11i * Ii1I / OoooooooOO * O0 % OOooOOo
  for iIi1 in self . itr_rlocs :
   if ( lisp_data_plane_security and self . itr_rlocs . index ( iIi1 ) == 0 ) :
    if ( self . keys == None or self . keys [ 1 ] == None ) :
     II1i = lisp_keys ( 1 )
     self . keys = [ None , II1i , None , None ]
     if 49 - 49: II111iiii . I1IiiI * O0 * Ii1I / I1Ii111 * OoooooooOO
    II1i = self . keys [ 1 ]
    II1i . add_key_by_nonce ( self . nonce )
    iI1IIII1ii1 += II1i . encode_lcaf ( iIi1 )
   else :
    iI1IIII1ii1 += struct . pack ( "H" , socket . htons ( iIi1 . afi ) )
    iI1IIII1ii1 += iIi1 . pack_address ( )
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
  oOO0OOOoO0ooo = "BB"
  iI1IIII1ii1 += struct . pack ( oOO0OOOoO0ooo , Oooo00oOO00 , ooooOo00OO0o )
  if 87 - 87: Oo0Ooo . o0oOOo0O0Ooo - OoooooooOO * oO0o % IiII + O0
  if ( self . target_group . is_null ( ) == False ) :
   iI1IIII1ii1 += struct . pack ( "H" , socket . htons ( LISP_AFI_LCAF ) )
   iI1IIII1ii1 += self . target_eid . lcaf_encode_sg ( self . target_group )
  elif ( self . target_eid . instance_id != 0 or
 self . target_eid . is_geo_prefix ( ) ) :
   iI1IIII1ii1 += struct . pack ( "H" , socket . htons ( LISP_AFI_LCAF ) )
   iI1IIII1ii1 += self . target_eid . lcaf_encode_iid ( )
  else :
   iI1IIII1ii1 += struct . pack ( "H" , socket . htons ( self . target_eid . afi ) )
   iI1IIII1ii1 += self . target_eid . pack_address ( )
   if 16 - 16: I1ii11iIi11i % Oo0Ooo % II111iiii % II111iiii
   if 51 - 51: OoOoOO00 * OoOoOO00 - O0 % iIii1I11I1II1 / O0
   if 5 - 5: i11iIiiIii * ooOoO0o % iII111i - I11i
   if 5 - 5: O0 * IiII * OOooOOo + I1Ii111 % Oo0Ooo - I1ii11iIi11i
   if 62 - 62: I1ii11iIi11i + I11i
  if ( self . subscribe_bit ) : iI1IIII1ii1 = self . encode_xtr_id ( iI1IIII1ii1 )
  return ( iI1IIII1ii1 )
  if 90 - 90: iIii1I11I1II1
  if 18 - 18: I11i * I1ii11iIi11i / i11iIiiIii / iIii1I11I1II1 * OoooooooOO . OOooOOo
 def lcaf_decode_json ( self , packet ) :
  oOO0OOOoO0ooo = "BBBBHH"
  I1111ii1i = struct . calcsize ( oOO0OOOoO0ooo )
  if ( len ( packet ) < I1111ii1i ) : return ( None )
  if 69 - 69: Oo0Ooo * ooOoO0o
  OOII1iI , Ooooo0OO , O00OO0oOOO , o0o0OO0OO , ii111 , i1oO0o00oOo00oO = struct . unpack ( oOO0OOOoO0ooo , packet [ : I1111ii1i ] )
  if 21 - 21: I1IiiI - OoooooooOO / OoOoOO00 * OoooooooOO % OoooooooOO + OoO0O00
  if 89 - 89: iII111i . OOooOOo . I1ii11iIi11i
  if ( O00OO0oOOO != LISP_LCAF_JSON_TYPE ) : return ( packet )
  if 93 - 93: II111iiii
  if 8 - 8: Ii1I * OoooooooOO / Ii1I / OoO0O00 % OoOoOO00 + I11i
  if 16 - 16: I11i % ooOoO0o - i11iIiiIii
  if 38 - 38: o0oOOo0O0Ooo / I1ii11iIi11i - O0
  ii111 = socket . ntohs ( ii111 )
  i1oO0o00oOo00oO = socket . ntohs ( i1oO0o00oOo00oO )
  packet = packet [ I1111ii1i : : ]
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
  oOO0OOOoO0ooo = "H"
  I1111ii1i = struct . calcsize ( oOO0OOOoO0ooo )
  ooOooOooOOO = struct . unpack ( oOO0OOOoO0ooo , packet [ : I1111ii1i ] ) [ 0 ]
  packet = packet [ I1111ii1i : : ]
  if ( ooOooOooOOO != 0 ) : return ( packet )
  if 87 - 87: IiII
  if 45 - 45: oO0o + II111iiii * O0 % OOooOOo . iIii1I11I1II1
  if 55 - 55: IiII
  if 43 - 43: OOooOOo
  if ( O0OoOOo0o . has_key ( "source-eid" ) == False ) : return ( packet )
  i1OO0o = O0OoOOo0o [ "source-eid" ]
  ooOooOooOOO = LISP_AFI_IPV4 if i1OO0o . count ( "." ) == 3 else LISP_AFI_IPV6 if i1OO0o . count ( ":" ) == 7 else None
  if 64 - 64: i1IIi / o0oOOo0O0Ooo
  if ( ooOooOooOOO == None ) :
   lprint ( "Bad JSON 'source-eid' value: {}" . format ( i1OO0o ) )
   return ( None )
   if 24 - 24: I1ii11iIi11i * OoO0O00 . OoooooooOO % Ii1I % O0
   if 46 - 46: iII111i + I1Ii111 % OoooooooOO * I1ii11iIi11i
  self . source_eid . afi = ooOooOooOOO
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
  oOO0 = binascii . a2b_base64 ( O0OoOOo0o [ "signature" ] )
  self . map_request_signature = oOO0
  return ( packet )
  if 71 - 71: i11iIiiIii * OoOoOO00 * OOooOOo + oO0o + Oo0Ooo
  if 59 - 59: IiII
 def decode ( self , packet , source , port ) :
  oOO0OOOoO0ooo = "I"
  I1111ii1i = struct . calcsize ( oOO0OOOoO0ooo )
  if ( len ( packet ) < I1111ii1i ) : return ( None )
  if 54 - 54: OOooOOo
  O0ooOo0Oooo = struct . unpack ( oOO0OOOoO0ooo , packet [ : I1111ii1i ] )
  O0ooOo0Oooo = O0ooOo0Oooo [ 0 ]
  packet = packet [ I1111ii1i : : ]
  if 27 - 27: OoOoOO00 - OoO0O00 + o0oOOo0O0Ooo + ooOoO0o . OoO0O00
  oOO0OOOoO0ooo = "Q"
  I1111ii1i = struct . calcsize ( oOO0OOOoO0ooo )
  if ( len ( packet ) < I1111ii1i ) : return ( None )
  if 86 - 86: II111iiii - OoooooooOO - ooOoO0o % iII111i
  iIiIi1i1Iiii = struct . unpack ( oOO0OOOoO0ooo , packet [ : I1111ii1i ] )
  packet = packet [ I1111ii1i : : ]
  if 16 - 16: ooOoO0o + Oo0Ooo + OoooooooOO
  O0ooOo0Oooo = socket . ntohl ( O0ooOo0Oooo )
  self . auth_bit = True if ( O0ooOo0Oooo & 0x08000000 ) else False
  self . map_data_present = True if ( O0ooOo0Oooo & 0x04000000 ) else False
  self . rloc_probe = True if ( O0ooOo0Oooo & 0x02000000 ) else False
  self . smr_bit = True if ( O0ooOo0Oooo & 0x01000000 ) else False
  self . pitr_bit = True if ( O0ooOo0Oooo & 0x00800000 ) else False
  self . smr_invoked_bit = True if ( O0ooOo0Oooo & 0x00400000 ) else False
  self . mobile_node = True if ( O0ooOo0Oooo & 0x00200000 ) else False
  self . xtr_id_present = True if ( O0ooOo0Oooo & 0x00100000 ) else False
  self . local_xtr = True if ( O0ooOo0Oooo & 0x00004000 ) else False
  self . dont_reply_bit = True if ( O0ooOo0Oooo & 0x00002000 ) else False
  self . itr_rloc_count = ( ( O0ooOo0Oooo >> 8 ) & 0x1f ) + 1
  self . record_count = O0ooOo0Oooo & 0xff
  self . nonce = iIiIi1i1Iiii [ 0 ]
  if 87 - 87: I1IiiI . oO0o / IiII - OoooooooOO
  if 33 - 33: oO0o % OoO0O00 . iIii1I11I1II1 / IiII
  if 3 - 3: Ii1I + OoO0O00
  if 60 - 60: OoO0O00 . OoOoOO00 - I1ii11iIi11i - I1IiiI - II111iiii % Oo0Ooo
  if ( self . xtr_id_present ) :
   if ( self . decode_xtr_id ( packet ) == False ) : return ( None )
   if 62 - 62: O0 + iII111i - iII111i % iIii1I11I1II1
   if 47 - 47: I1Ii111 + I1IiiI
  I1111ii1i = struct . calcsize ( "H" )
  if ( len ( packet ) < I1111ii1i ) : return ( None )
  if 40 - 40: iIii1I11I1II1 % Ii1I + II111iiii - I1IiiI
  ooOooOooOOO = struct . unpack ( "H" , packet [ : I1111ii1i ] )
  self . source_eid . afi = socket . ntohs ( ooOooOooOOO [ 0 ] )
  packet = packet [ I1111ii1i : : ]
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
   I1111ii1i = struct . calcsize ( "H" )
   if ( len ( packet ) < I1111ii1i ) : return ( None )
   if 75 - 75: I1IiiI
   ooOooOooOOO = struct . unpack ( "H" , packet [ : I1111ii1i ] ) [ 0 ]
   if 99 - 99: ooOoO0o . Ii1I
   iIi1 = lisp_address ( LISP_AFI_NONE , "" , 32 , 0 )
   iIi1 . afi = socket . ntohs ( ooOooOooOOO )
   if 92 - 92: i1IIi
   if 68 - 68: OoO0O00 % IiII - oO0o - ooOoO0o . Oo0Ooo
   if 30 - 30: OoooooooOO % o0oOOo0O0Ooo + ooOoO0o * OoO0O00
   if 57 - 57: I11i + iIii1I11I1II1 . OoO0O00 + oO0o
   if 4 - 4: Ii1I
   if ( iIi1 . afi != LISP_AFI_LCAF ) :
    if ( len ( packet ) < iIi1 . addr_length ( ) ) : return ( None )
    packet = iIi1 . unpack_address ( packet [ I1111ii1i : : ] )
    if ( packet == None ) : return ( None )
    if 43 - 43: i1IIi . I1IiiI * iIii1I11I1II1 * i11iIiiIii - OOooOOo + ooOoO0o
    if ( OOO0 ) :
     self . itr_rlocs . append ( iIi1 )
     self . itr_rloc_count -= 1
     continue
     if 56 - 56: Oo0Ooo % i11iIiiIii / Ii1I . I1Ii111 . OoO0O00 - OoOoOO00
     if 32 - 32: I1Ii111 / oO0o / I1IiiI
    OoOOoooO000 = lisp_build_crypto_decap_lookup_key ( iIi1 , port )
    if 22 - 22: OoO0O00 - OoOoOO00 . Oo0Ooo + o0oOOo0O0Ooo
    if 69 - 69: oO0o - I1IiiI
    if 10 - 10: i1IIi / iII111i . II111iiii * i1IIi % OoooooooOO
    if 83 - 83: I11i . OOooOOo + I1Ii111 * I11i . I1Ii111 + oO0o
    if 64 - 64: Ii1I . o0oOOo0O0Ooo - i1IIi
    if ( lisp_nat_traversal and iIi1 . is_private_address ( ) and source ) : iIi1 = source
    if 35 - 35: I1ii11iIi11i % OoooooooOO
    oO0oO0oOoo = lisp_crypto_keys_by_rloc_decap
    if ( oO0oO0oOoo . has_key ( OoOOoooO000 ) ) : oO0oO0oOoo . pop ( OoOOoooO000 )
    if 34 - 34: IiII
    if 5 - 5: OoO0O00 . I1IiiI
    if 48 - 48: Oo0Ooo - OoO0O00 . I11i - iIii1I11I1II1 % Ii1I
    if 47 - 47: iII111i / OoooooooOO - II111iiii
    if 91 - 91: OoOoOO00 + o0oOOo0O0Ooo
    if 23 - 23: i1IIi
    lisp_write_ipc_decap_key ( OoOOoooO000 , None )
   else :
    O0ooO00OO = packet
    IiI11IiIIi = lisp_keys ( 1 )
    packet = IiI11IiIIi . decode_lcaf ( O0ooO00OO , 0 )
    if ( packet == None ) : return ( None )
    if 92 - 92: Ii1I
    if 48 - 48: iII111i . I1IiiI + O0
    if 19 - 19: I1IiiI / I1Ii111 - I11i
    if 49 - 49: iIii1I11I1II1 - iIii1I11I1II1 - OoOoOO00 + IiII / OoOoOO00
    oO0oo0O0OOOo0 = [ LISP_CS_25519_CBC , LISP_CS_25519_GCM ,
 LISP_CS_25519_CHACHA ]
    if ( IiI11IiIIi . cipher_suite in oO0oo0O0OOOo0 ) :
     if ( IiI11IiIIi . cipher_suite == LISP_CS_25519_CBC or
 IiI11IiIIi . cipher_suite == LISP_CS_25519_GCM ) :
      i1IIiI1iII = lisp_keys ( 1 , do_poly = False , do_chacha = False )
      if 74 - 74: OoooooooOO + I1ii11iIi11i % O0
     if ( IiI11IiIIi . cipher_suite == LISP_CS_25519_CHACHA ) :
      i1IIiI1iII = lisp_keys ( 1 , do_poly = True , do_chacha = True )
      if 32 - 32: I1ii11iIi11i + I1ii11iIi11i
    else :
     i1IIiI1iII = lisp_keys ( 1 , do_poly = False , do_curve = False ,
 do_chacha = False )
     if 89 - 89: ooOoO0o + oO0o + Ii1I - OOooOOo
    packet = i1IIiI1iII . decode_lcaf ( O0ooO00OO , 0 )
    if ( packet == None ) : return ( None )
    if 12 - 12: OoOoOO00 - o0oOOo0O0Ooo - I1Ii111 / I11i
    if ( len ( packet ) < I1111ii1i ) : return ( None )
    ooOooOooOOO = struct . unpack ( "H" , packet [ : I1111ii1i ] ) [ 0 ]
    iIi1 . afi = socket . ntohs ( ooOooOooOOO )
    if ( len ( packet ) < iIi1 . addr_length ( ) ) : return ( None )
    if 17 - 17: OoO0O00 - I1Ii111 - II111iiii / I1Ii111 / Ii1I
    packet = iIi1 . unpack_address ( packet [ I1111ii1i : : ] )
    if ( packet == None ) : return ( None )
    if 30 - 30: OOooOOo * I1ii11iIi11i % I1ii11iIi11i + iII111i * IiII
    if ( OOO0 ) :
     self . itr_rlocs . append ( iIi1 )
     self . itr_rloc_count -= 1
     continue
     if 33 - 33: o0oOOo0O0Ooo + I11i * O0 * OoO0O00 . I1ii11iIi11i
     if 74 - 74: iII111i * iII111i * o0oOOo0O0Ooo / oO0o
    OoOOoooO000 = lisp_build_crypto_decap_lookup_key ( iIi1 , port )
    if 91 - 91: i11iIiiIii . I1ii11iIi11i / II111iiii
    O00oO0OOOo0 = None
    if ( lisp_nat_traversal and iIi1 . is_private_address ( ) and source ) : iIi1 = source
    if 64 - 64: Ii1I - iII111i
    if 12 - 12: i1IIi
    if ( lisp_crypto_keys_by_rloc_decap . has_key ( OoOOoooO000 ) ) :
     II1i = lisp_crypto_keys_by_rloc_decap [ OoOOoooO000 ]
     O00oO0OOOo0 = II1i [ 1 ] if II1i and II1i [ 1 ] else None
     if 99 - 99: II111iiii - I1ii11iIi11i * IiII
     if 3 - 3: IiII - I1ii11iIi11i * iII111i * I1ii11iIi11i + Oo0Ooo
    IIi1i1iI11I11 = True
    if ( O00oO0OOOo0 ) :
     if ( O00oO0OOOo0 . compare_keys ( i1IIiI1iII ) ) :
      self . keys = [ None , O00oO0OOOo0 , None , None ]
      lprint ( "Maintain stored decap-keys for RLOC {}" . format ( red ( OoOOoooO000 , False ) ) )
      if 67 - 67: i11iIiiIii % I11i
     else :
      IIi1i1iI11I11 = False
      ii1I11iIi = bold ( "Remote decap-rekeying" , False )
      lprint ( "{} for RLOC {}" . format ( ii1I11iIi , red ( OoOOoooO000 ,
 False ) ) )
      i1IIiI1iII . copy_keypair ( O00oO0OOOo0 )
      i1IIiI1iII . uptime = O00oO0OOOo0 . uptime
      O00oO0OOOo0 = None
      if 13 - 13: O0 . iII111i - IiII % i11iIiiIii % I1IiiI
      if 88 - 88: i1IIi % O0
      if 35 - 35: OoOoOO00 % OoO0O00 + O0 * o0oOOo0O0Ooo % I1ii11iIi11i
    if ( O00oO0OOOo0 == None ) :
     self . keys = [ None , i1IIiI1iII , None , None ]
     if ( lisp_i_am_etr == False and lisp_i_am_rtr == False ) :
      i1IIiI1iII . local_public_key = None
      lprint ( "{} for {}" . format ( bold ( "Ignoring decap-keys" ,
 False ) , red ( OoOOoooO000 , False ) ) )
     elif ( i1IIiI1iII . remote_public_key != None ) :
      if ( IIi1i1iI11I11 ) :
       lprint ( "{} for RLOC {}" . format ( bold ( "New decap-keying" , False ) ,
       # i1IIi / I11i - o0oOOo0O0Ooo - ooOoO0o
 red ( OoOOoooO000 , False ) ) )
       if 98 - 98: Oo0Ooo + OoOoOO00 * OOooOOo / iII111i * OoOoOO00 / OoooooooOO
      i1IIiI1iII . compute_shared_key ( "decap" )
      i1IIiI1iII . add_key_by_rloc ( OoOOoooO000 , False )
      if 35 - 35: II111iiii . OOooOOo + iIii1I11I1II1 . i1IIi - OoOoOO00 + IiII
      if 55 - 55: Oo0Ooo % I1Ii111 . II111iiii
      if 53 - 53: O0 / OoO0O00 % i11iIiiIii
      if 11 - 11: I1Ii111 + i1IIi - iII111i - OoO0O00 * ooOoO0o / ooOoO0o
   self . itr_rlocs . append ( iIi1 )
   self . itr_rloc_count -= 1
   if 4 - 4: iIii1I11I1II1 - i11iIiiIii * OoO0O00 . I1Ii111 + o0oOOo0O0Ooo
   if 11 - 11: OoOoOO00 % I1ii11iIi11i - Ii1I - I1Ii111
  I1111ii1i = struct . calcsize ( "BBH" )
  if ( len ( packet ) < I1111ii1i ) : return ( None )
  if 58 - 58: OoOoOO00 . Ii1I / IiII * oO0o
  Oooo00oOO00 , ooooOo00OO0o , ooOooOooOOO = struct . unpack ( "BBH" , packet [ : I1111ii1i ] )
  self . subscribe_bit = ( Oooo00oOO00 & 0x80 )
  self . target_eid . afi = socket . ntohs ( ooOooOooOOO )
  packet = packet [ I1111ii1i : : ]
  if 70 - 70: OoooooooOO
  self . target_eid . mask_len = ooooOo00OO0o
  if ( self . target_eid . afi == LISP_AFI_LCAF ) :
   packet , OOOoo = self . target_eid . lcaf_decode_eid ( packet )
   if ( packet == None ) : return ( None )
   if ( OOOoo ) : self . target_group = OOOoo
  else :
   packet = self . target_eid . unpack_address ( packet )
   if ( packet == None ) : return ( None )
   packet = packet [ I1111ii1i : : ]
   if 97 - 97: I11i
  return ( packet )
  if 84 - 84: IiII - OoOoOO00 . IiII + ooOoO0o . iII111i
  if 96 - 96: Ii1I % iII111i * Ii1I % I1IiiI . o0oOOo0O0Ooo / o0oOOo0O0Ooo
 def print_eid_tuple ( self ) :
  return ( lisp_print_eid_tuple ( self . target_eid , self . target_group ) )
  if 7 - 7: OoO0O00 - ooOoO0o % i1IIi
  if 24 - 24: OoO0O00 % O0 % I11i
 def encode_xtr_id ( self , packet ) :
  IIiiI1Ii = self . xtr_id >> 64
  OoooOo = self . xtr_id & 0xffffffffffffffff
  IIiiI1Ii = byte_swap_64 ( IIiiI1Ii )
  OoooOo = byte_swap_64 ( OoooOo )
  packet += struct . pack ( "QQ" , IIiiI1Ii , OoooOo )
  return ( packet )
  if 61 - 61: ooOoO0o . iII111i / ooOoO0o * OoooooooOO
  if 13 - 13: II111iiii
 def decode_xtr_id ( self , packet ) :
  I1111ii1i = struct . calcsize ( "QQ" )
  if ( len ( packet ) < I1111ii1i ) : return ( None )
  packet = packet [ len ( packet ) - I1111ii1i : : ]
  IIiiI1Ii , OoooOo = struct . unpack ( "QQ" , packet [ : I1111ii1i ] )
  IIiiI1Ii = byte_swap_64 ( IIiiI1Ii )
  OoooOo = byte_swap_64 ( OoooOo )
  self . xtr_id = ( IIiiI1Ii << 64 ) | OoooOo
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
  i11ii = "{} -> flags: {}{}{}, hop-count: {}, record-count: {}, " + "nonce: 0x{}"
  if 63 - 63: OoOoOO00 . I11i * o0oOOo0O0Ooo - I11i % I11i
  lprint ( i11ii . format ( bold ( "Map-Reply" , False ) , "R" if self . rloc_probe else "r" ,
  # o0oOOo0O0Ooo + I1IiiI % ooOoO0o * I1Ii111
 "E" if self . echo_nonce_capable else "e" ,
 "S" if self . security else "s" , self . hop_count , self . record_count ,
 lisp_hex_string ( self . nonce ) ) )
  if 87 - 87: II111iiii + O0 / iII111i * ooOoO0o
  if 52 - 52: iIii1I11I1II1 / iII111i . O0 * IiII . I1IiiI
 def encode ( self ) :
  O0ooOo0Oooo = ( LISP_MAP_REPLY << 28 ) | self . record_count
  O0ooOo0Oooo |= self . hop_count << 8
  if ( self . rloc_probe ) : O0ooOo0Oooo |= 0x08000000
  if ( self . echo_nonce_capable ) : O0ooOo0Oooo |= 0x04000000
  if ( self . security ) : O0ooOo0Oooo |= 0x02000000
  if 67 - 67: II111iiii + Ii1I - I1IiiI * ooOoO0o
  iI1IIII1ii1 = struct . pack ( "I" , socket . htonl ( O0ooOo0Oooo ) )
  iI1IIII1ii1 += struct . pack ( "Q" , self . nonce )
  return ( iI1IIII1ii1 )
  if 19 - 19: i11iIiiIii * Oo0Ooo
  if 33 - 33: i11iIiiIii + I1IiiI
 def decode ( self , packet ) :
  oOO0OOOoO0ooo = "I"
  I1111ii1i = struct . calcsize ( oOO0OOOoO0ooo )
  if ( len ( packet ) < I1111ii1i ) : return ( None )
  if 95 - 95: I1ii11iIi11i / IiII % iIii1I11I1II1 + O0
  O0ooOo0Oooo = struct . unpack ( oOO0OOOoO0ooo , packet [ : I1111ii1i ] )
  O0ooOo0Oooo = O0ooOo0Oooo [ 0 ]
  packet = packet [ I1111ii1i : : ]
  if 6 - 6: IiII
  oOO0OOOoO0ooo = "Q"
  I1111ii1i = struct . calcsize ( oOO0OOOoO0ooo )
  if ( len ( packet ) < I1111ii1i ) : return ( None )
  if 73 - 73: o0oOOo0O0Ooo % o0oOOo0O0Ooo . OOooOOo * I1ii11iIi11i - Ii1I
  iIiIi1i1Iiii = struct . unpack ( oOO0OOOoO0ooo , packet [ : I1111ii1i ] )
  packet = packet [ I1111ii1i : : ]
  if 97 - 97: IiII
  O0ooOo0Oooo = socket . ntohl ( O0ooOo0Oooo )
  self . rloc_probe = True if ( O0ooOo0Oooo & 0x08000000 ) else False
  self . echo_nonce_capable = True if ( O0ooOo0Oooo & 0x04000000 ) else False
  self . security = True if ( O0ooOo0Oooo & 0x02000000 ) else False
  self . hop_count = ( O0ooOo0Oooo >> 8 ) & 0xff
  self . record_count = O0ooOo0Oooo & 0xff
  self . nonce = iIiIi1i1Iiii [ 0 ]
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
  Oo0 = bold ( "invalid-action" , False )
  if ( ddt ) :
   if ( self . action < len ( lisp_map_referral_action_string ) ) :
    Oo0 = lisp_map_referral_action_string [ self . action ]
    Oo0 = bold ( Oo0 , False )
    O0oOo00O = ( ", " + bold ( "ddt-incomplete" , False ) ) if self . ddt_incomplete else ""
    if 84 - 84: Oo0Ooo % I1Ii111 . Oo0Ooo / ooOoO0o * Ii1I - IiII
    I11I = ( ", sig-count: " + str ( self . signature_count ) ) if ( self . signature_count != 0 ) else ""
    if 16 - 16: OOooOOo % IiII - II111iiii - o0oOOo0O0Ooo * i11iIiiIii / I1Ii111
    if 74 - 74: iII111i % i1IIi / Oo0Ooo . O0
  else :
   if ( self . action < len ( lisp_map_reply_action_string ) ) :
    Oo0 = lisp_map_reply_action_string [ self . action ]
    if ( self . action != LISP_NO_ACTION ) :
     Oo0 = bold ( Oo0 , False )
     if 48 - 48: I1ii11iIi11i % II111iiii + I11i
     if 25 - 25: IiII * o0oOOo0O0Ooo / I1IiiI . IiII % II111iiii
     if 50 - 50: OoOoOO00 * iII111i
     if 59 - 59: I1IiiI * I1IiiI / I11i
  ooOooOooOOO = LISP_AFI_LCAF if ( self . eid . afi < 0 ) else self . eid . afi
  i11ii = ( "{}EID-record -> record-ttl: {}, rloc-count: {}, action: " +
 "{}, {}{}{}, map-version: {}, afi: {}, [iid]eid/ml: {}" )
  if 92 - 92: o0oOOo0O0Ooo
  lprint ( i11ii . format ( indent , self . print_ttl ( ) , self . rloc_count ,
 Oo0 , "auth" if ( self . authoritative is True ) else "non-auth" ,
 O0oOo00O , I11I , self . map_version , ooOooOooOOO ,
 green ( self . print_prefix ( ) , False ) ) )
  if 8 - 8: iII111i + I1ii11iIi11i . Ii1I
  if 50 - 50: Oo0Ooo
 def encode ( self ) :
  I11IiIi1I = self . action << 13
  if ( self . authoritative ) : I11IiIi1I |= 0x1000
  if ( self . ddt_incomplete ) : I11IiIi1I |= 0x800
  if 74 - 74: OoO0O00 % iIii1I11I1II1 + OoO0O00 + i1IIi . OoOoOO00 % Oo0Ooo
  if 81 - 81: ooOoO0o + OoOoOO00 % i1IIi % I1IiiI + i1IIi
  if 2 - 2: iII111i + iII111i
  if 51 - 51: OoooooooOO + i11iIiiIii
  ooOooOooOOO = self . eid . afi if ( self . eid . instance_id == 0 ) else LISP_AFI_LCAF
  if ( ooOooOooOOO < 0 ) : ooOooOooOOO = LISP_AFI_LCAF
  oOO00oOooOo = ( self . group . is_null ( ) == False )
  if ( oOO00oOooOo ) : ooOooOooOOO = LISP_AFI_LCAF
  if 2 - 2: i1IIi + O0 + i1IIi * I1IiiI
  OOoOoO = ( self . signature_count << 12 ) | self . map_version
  ooooOo00OO0o = 0 if self . eid . is_binary ( ) == False else self . eid . mask_len
  if 73 - 73: OoO0O00 - i11iIiiIii % I1Ii111 / Oo0Ooo - OoooooooOO % OOooOOo
  iI1IIII1ii1 = struct . pack ( "IBBHHH" , socket . htonl ( self . record_ttl ) ,
 self . rloc_count , ooooOo00OO0o , socket . htons ( I11IiIi1I ) ,
 socket . htons ( OOoOoO ) , socket . htons ( ooOooOooOOO ) )
  if 79 - 79: I1IiiI / o0oOOo0O0Ooo . Ii1I * I1ii11iIi11i + I11i
  if 96 - 96: OoO0O00 * II111iiii
  if 1 - 1: I1IiiI - OoOoOO00
  if 74 - 74: OoOoOO00 * II111iiii + O0 + I11i
  if ( oOO00oOooOo ) :
   iI1IIII1ii1 += self . eid . lcaf_encode_sg ( self . group )
   return ( iI1IIII1ii1 )
   if 3 - 3: iIii1I11I1II1 - i1IIi / iII111i + i1IIi + O0
   if 18 - 18: iIii1I11I1II1 . iII111i % OOooOOo % oO0o + iIii1I11I1II1 * OoooooooOO
   if 78 - 78: IiII
   if 38 - 38: OoO0O00 * I1ii11iIi11i
   if 4 - 4: OoO0O00 . I1ii11iIi11i
  if ( self . eid . afi == LISP_AFI_GEO_COORD and self . eid . instance_id == 0 ) :
   iI1IIII1ii1 = iI1IIII1ii1 [ 0 : - 2 ]
   iI1IIII1ii1 += self . eid . address . encode_geo ( )
   return ( iI1IIII1ii1 )
   if 21 - 21: i11iIiiIii / OoO0O00 / I1ii11iIi11i * O0 - II111iiii * OOooOOo
   if 27 - 27: o0oOOo0O0Ooo . OoOoOO00 * Ii1I * iII111i * O0
   if 93 - 93: IiII % I1Ii111 % II111iiii
   if 20 - 20: OoooooooOO * I1Ii111
   if 38 - 38: iII111i . OoooooooOO
  if ( ooOooOooOOO == LISP_AFI_LCAF ) :
   iI1IIII1ii1 += self . eid . lcaf_encode_iid ( )
   return ( iI1IIII1ii1 )
   if 28 - 28: I1Ii111 * i1IIi . I1ii11iIi11i
   if 75 - 75: O0 / oO0o * ooOoO0o - OOooOOo / i1IIi
   if 61 - 61: I11i
   if 100 - 100: O0 - iIii1I11I1II1 * Oo0Ooo
   if 35 - 35: ooOoO0o
  iI1IIII1ii1 += self . eid . pack_address ( )
  return ( iI1IIII1ii1 )
  if 57 - 57: OoO0O00 . Oo0Ooo + I1IiiI
  if 18 - 18: I1IiiI - I1ii11iIi11i * I11i / i11iIiiIii - o0oOOo0O0Ooo % o0oOOo0O0Ooo
 def decode ( self , packet ) :
  oOO0OOOoO0ooo = "IBBHHH"
  I1111ii1i = struct . calcsize ( oOO0OOOoO0ooo )
  if ( len ( packet ) < I1111ii1i ) : return ( None )
  if 31 - 31: I11i
  self . record_ttl , self . rloc_count , self . eid . mask_len , I11IiIi1I , self . map_version , self . eid . afi = struct . unpack ( oOO0OOOoO0ooo , packet [ : I1111ii1i ] )
  if 100 - 100: i11iIiiIii * i11iIiiIii . iIii1I11I1II1 % iII111i * I1ii11iIi11i
  if 17 - 17: Ii1I * IiII * i11iIiiIii / I1ii11iIi11i / i11iIiiIii
  if 23 - 23: OoooooooOO + i11iIiiIii / Oo0Ooo / iII111i . iII111i * I1IiiI
  self . record_ttl = socket . ntohl ( self . record_ttl )
  I11IiIi1I = socket . ntohs ( I11IiIi1I )
  self . action = ( I11IiIi1I >> 13 ) & 0x7
  self . authoritative = True if ( ( I11IiIi1I >> 12 ) & 1 ) else False
  self . ddt_incomplete = True if ( ( I11IiIi1I >> 11 ) & 1 ) else False
  self . map_version = socket . ntohs ( self . map_version )
  self . signature_count = self . map_version >> 12
  self . map_version = self . map_version & 0xfff
  self . eid . afi = socket . ntohs ( self . eid . afi )
  self . eid . instance_id = 0
  packet = packet [ I1111ii1i : : ]
  if 98 - 98: IiII
  if 23 - 23: I11i / i1IIi * OoO0O00
  if 51 - 51: OOooOOo - OoooooooOO / OoooooooOO % OoooooooOO
  if 85 - 85: OoO0O00 . o0oOOo0O0Ooo . I1IiiI
  if ( self . eid . afi == LISP_AFI_LCAF ) :
   packet , Oo000o0o0 = self . eid . lcaf_decode_eid ( packet )
   if ( Oo000o0o0 ) : self . group = Oo000o0o0
   self . group . instance_id = self . eid . instance_id
   return ( packet )
   if 76 - 76: oO0o * ooOoO0o - iIii1I11I1II1
   if 25 - 25: OoOoOO00 / Oo0Ooo / OoooooooOO
  packet = self . eid . unpack_address ( packet )
  return ( packet )
  if 91 - 91: IiII - I1ii11iIi11i - I1Ii111
  if 35 - 35: iIii1I11I1II1 . O0 + OoOoOO00 / OoO0O00 / IiII * II111iiii
 def print_eid_tuple ( self ) :
  return ( lisp_print_eid_tuple ( self . eid , self . group ) )
  if 32 - 32: I1Ii111 - iIii1I11I1II1 / I11i * OoO0O00 * OoO0O00
  if 77 - 77: I1ii11iIi11i
  if 16 - 16: II111iiii - II111iiii * I11i / OOooOOo . IiII
  if 36 - 36: I11i / iIii1I11I1II1
  if 59 - 59: i1IIi
  if 85 - 85: I1Ii111 + iIii1I11I1II1 + ooOoO0o + Oo0Ooo
  if 75 - 75: O0 . I11i - Ii1I / I1Ii111 / I1ii11iIi11i % I11i
  if 97 - 97: OoOoOO00 - OoO0O00
  if 64 - 64: i1IIi / OoooooooOO / I1ii11iIi11i - Oo0Ooo + oO0o
  if 6 - 6: OOooOOo % II111iiii * IiII
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
LISP_UDP_PROTOCOL = 17
LISP_DEFAULT_ECM_TTL = 128
if 88 - 88: i1IIi + iIii1I11I1II1 * i11iIiiIii - OoooooooOO % o0oOOo0O0Ooo
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
  if 74 - 74: ooOoO0o - i11iIiiIii
  if 34 - 34: IiII + I1Ii111 + Oo0Ooo / II111iiii
 def print_ecm ( self ) :
  i11ii = ( "{} -> flags: {}{}{}{}, " + "inner IP: {} -> {}, inner UDP: {} -> {}" )
  if 33 - 33: Ii1I . i1IIi - II111iiii - OoO0O00
  lprint ( i11ii . format ( bold ( "ECM" , False ) , "S" if self . security else "s" ,
 "D" if self . ddt else "d" , "E" if self . to_etr else "e" ,
 "M" if self . to_ms else "m" ,
 green ( self . source . print_address ( ) , False ) ,
 green ( self . dest . print_address ( ) , False ) , self . udp_sport ,
 self . udp_dport ) )
  if 31 - 31: I11i - OoOoOO00 / o0oOOo0O0Ooo * OoOoOO00 / Oo0Ooo + o0oOOo0O0Ooo
 def encode ( self , packet , inner_source , inner_dest ) :
  self . udp_length = len ( packet ) + 8
  self . source = inner_source
  self . dest = inner_dest
  if ( inner_dest . is_ipv4 ( ) ) :
   self . afi = LISP_AFI_IPV4
   self . length = self . udp_length + 20
   if 46 - 46: IiII * OoO0O00 / OOooOOo + Oo0Ooo
  if ( inner_dest . is_ipv6 ( ) ) :
   self . afi = LISP_AFI_IPV6
   self . length = self . udp_length
   if 24 - 24: ooOoO0o % OOooOOo . O0 * Oo0Ooo
   if 52 - 52: O0 . I1Ii111 + iII111i / i11iIiiIii
   if 52 - 52: oO0o % Oo0Ooo * II111iiii
   if 24 - 24: i11iIiiIii * i1IIi * i1IIi
   if 27 - 27: i1IIi - oO0o + OOooOOo
   if 3 - 3: IiII % I1Ii111 . OoooooooOO
  O0ooOo0Oooo = ( LISP_ECM << 28 )
  if ( self . security ) : O0ooOo0Oooo |= 0x08000000
  if ( self . ddt ) : O0ooOo0Oooo |= 0x04000000
  if ( self . to_etr ) : O0ooOo0Oooo |= 0x02000000
  if ( self . to_ms ) : O0ooOo0Oooo |= 0x01000000
  if 19 - 19: I1Ii111 * Ii1I - oO0o
  oOo000oOo = struct . pack ( "I" , socket . htonl ( O0ooOo0Oooo ) )
  if 42 - 42: OOooOOo % OOooOOo
  oOo00Ooo0o0 = ""
  if ( self . afi == LISP_AFI_IPV4 ) :
   oOo00Ooo0o0 = struct . pack ( "BBHHHBBH" , 0x45 , 0 , socket . htons ( self . length ) ,
 0 , 0 , self . ttl , self . protocol , socket . htons ( self . ip_checksum ) )
   oOo00Ooo0o0 += self . source . pack_address ( )
   oOo00Ooo0o0 += self . dest . pack_address ( )
   oOo00Ooo0o0 = lisp_ip_checksum ( oOo00Ooo0o0 )
   if 87 - 87: Oo0Ooo + I1IiiI % I1IiiI * i11iIiiIii
  if ( self . afi == LISP_AFI_IPV6 ) :
   oOo00Ooo0o0 = struct . pack ( "BBHHBB" , 0x60 , 0 , 0 , socket . htons ( self . length ) ,
 self . protocol , self . ttl )
   oOo00Ooo0o0 += self . source . pack_address ( )
   oOo00Ooo0o0 += self . dest . pack_address ( )
   if 68 - 68: iII111i . OOooOOo
   if 6 - 6: Ii1I - o0oOOo0O0Ooo % I11i + i11iIiiIii
  i1I1iIi1IiI = socket . htons ( self . udp_sport )
  i1i11ii1Ii = socket . htons ( self . udp_dport )
  ooO = socket . htons ( self . udp_length )
  OoOOooOOoo = socket . htons ( self . udp_checksum )
  IIi1ii1 = struct . pack ( "HHHH" , i1I1iIi1IiI , i1i11ii1Ii , ooO , OoOOooOOoo )
  return ( oOo000oOo + oOo00Ooo0o0 + IIi1ii1 )
  if 40 - 40: O0 . Ii1I
  if 58 - 58: i11iIiiIii * iII111i / Ii1I - oO0o - I1ii11iIi11i % o0oOOo0O0Ooo
 def decode ( self , packet ) :
  if 16 - 16: OoooooooOO
  if 71 - 71: Ii1I % O0 / I1Ii111 % iII111i - II111iiii / OoO0O00
  if 30 - 30: I11i
  if 60 - 60: ooOoO0o - Ii1I . I1IiiI * oO0o * i11iIiiIii
  oOO0OOOoO0ooo = "I"
  I1111ii1i = struct . calcsize ( oOO0OOOoO0ooo )
  if ( len ( packet ) < I1111ii1i ) : return ( None )
  if 29 - 29: OoO0O00 - Oo0Ooo . oO0o / OoO0O00 % i11iIiiIii
  O0ooOo0Oooo = struct . unpack ( oOO0OOOoO0ooo , packet [ : I1111ii1i ] )
  if 26 - 26: ooOoO0o . I1Ii111 / II111iiii % Ii1I
  O0ooOo0Oooo = socket . ntohl ( O0ooOo0Oooo [ 0 ] )
  self . security = True if ( O0ooOo0Oooo & 0x08000000 ) else False
  self . ddt = True if ( O0ooOo0Oooo & 0x04000000 ) else False
  self . to_etr = True if ( O0ooOo0Oooo & 0x02000000 ) else False
  self . to_ms = True if ( O0ooOo0Oooo & 0x01000000 ) else False
  packet = packet [ I1111ii1i : : ]
  if 82 - 82: OOooOOo % O0 % iIii1I11I1II1 % IiII + i11iIiiIii
  if 64 - 64: i1IIi / IiII . IiII - I1Ii111 % OOooOOo . II111iiii
  if 78 - 78: I1Ii111 - O0 - I1Ii111 . iIii1I11I1II1 % I1ii11iIi11i . OoooooooOO
  if 64 - 64: IiII
  if ( len ( packet ) < 1 ) : return ( None )
  IiOOo0 = struct . unpack ( "B" , packet [ 0 : 1 ] ) [ 0 ]
  IiOOo0 = IiOOo0 >> 4
  if 21 - 21: o0oOOo0O0Ooo - ooOoO0o * OoooooooOO . OoooooooOO
  if ( IiOOo0 == 4 ) :
   I1111ii1i = struct . calcsize ( "HHIBBH" )
   if ( len ( packet ) < I1111ii1i ) : return ( None )
   if 17 - 17: OOooOOo - iII111i % I1IiiI * OOooOOo * iIii1I11I1II1 . o0oOOo0O0Ooo
   oOOooOOO , ooO , oOOooOOO , I1iIIiiiiIII , o0O0o , OoOOooOOoo = struct . unpack ( "HHIBBH" , packet [ : I1111ii1i ] )
   self . length = socket . ntohs ( ooO )
   self . ttl = I1iIIiiiiIII
   self . protocol = o0O0o
   self . ip_checksum = socket . ntohs ( OoOOooOOoo )
   self . source . afi = self . dest . afi = LISP_AFI_IPV4
   if 81 - 81: OOooOOo + II111iiii * iII111i / OOooOOo + I1IiiI - o0oOOo0O0Ooo
   if 83 - 83: OoooooooOO . II111iiii % OOooOOo
   if 66 - 66: Oo0Ooo - OoO0O00
   if 2 - 2: I1Ii111
   o0O0o = struct . pack ( "H" , 0 )
   oo0OIiI1i1iIi1 = struct . calcsize ( "HHIBB" )
   o0OOoO = struct . calcsize ( "H" )
   packet = packet [ : oo0OIiI1i1iIi1 ] + o0O0o + packet [ oo0OIiI1i1iIi1 + o0OOoO : ]
   if 44 - 44: OOooOOo * IiII * iII111i
   packet = packet [ I1111ii1i : : ]
   packet = self . source . unpack_address ( packet )
   if ( packet == None ) : return ( None )
   packet = self . dest . unpack_address ( packet )
   if ( packet == None ) : return ( None )
   if 28 - 28: iIii1I11I1II1 - I11i + OoOoOO00 + II111iiii - OoO0O00 % ooOoO0o
   if 97 - 97: OoO0O00 . OoOoOO00
  if ( IiOOo0 == 6 ) :
   I1111ii1i = struct . calcsize ( "IHBB" )
   if ( len ( packet ) < I1111ii1i ) : return ( None )
   if 78 - 78: I1ii11iIi11i + I1ii11iIi11i . OoOoOO00 - IiII * iIii1I11I1II1 * O0
   oOOooOOO , ooO , o0O0o , I1iIIiiiiIII = struct . unpack ( "IHBB" , packet [ : I1111ii1i ] )
   self . length = socket . ntohs ( ooO )
   self . protocol = o0O0o
   self . ttl = I1iIIiiiiIII
   self . source . afi = self . dest . afi = LISP_AFI_IPV6
   if 26 - 26: OoooooooOO + oO0o + OoO0O00 . O0
   packet = packet [ I1111ii1i : : ]
   packet = self . source . unpack_address ( packet )
   if ( packet == None ) : return ( None )
   packet = self . dest . unpack_address ( packet )
   if ( packet == None ) : return ( None )
   if 46 - 46: OoooooooOO - Oo0Ooo * I1Ii111 * OOooOOo * I1Ii111 . oO0o
   if 96 - 96: Ii1I / IiII % o0oOOo0O0Ooo + I11i
  self . source . mask_len = self . source . host_mask_len ( )
  self . dest . mask_len = self . dest . host_mask_len ( )
  if 46 - 46: OoO0O00 * I1IiiI
  I1111ii1i = struct . calcsize ( "HHHH" )
  if ( len ( packet ) < I1111ii1i ) : return ( None )
  if 25 - 25: I1Ii111 . IiII % O0 % i1IIi
  i1I1iIi1IiI , i1i11ii1Ii , ooO , OoOOooOOoo = struct . unpack ( "HHHH" , packet [ : I1111ii1i ] )
  self . udp_sport = socket . ntohs ( i1I1iIi1IiI )
  self . udp_dport = socket . ntohs ( i1i11ii1Ii )
  self . udp_length = socket . ntohs ( ooO )
  self . udp_checksum = socket . ntohs ( OoOOooOOoo )
  packet = packet [ I1111ii1i : : ]
  return ( packet )
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
  if 67 - 67: OoOoOO00 - ooOoO0o - iIii1I11I1II1
  if 31 - 31: II111iiii + o0oOOo0O0Ooo * i11iIiiIii . o0oOOo0O0Ooo
  if 73 - 73: oO0o / OOooOOo * II111iiii % OoooooooOO - i1IIi - ooOoO0o
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
  if 43 - 43: o0oOOo0O0Ooo + Ii1I % OoO0O00 . I1Ii111 + i1IIi
  if 85 - 85: Oo0Ooo % I1ii11iIi11i / OOooOOo
 def print_rloc_name ( self , cour = False ) :
  if ( self . rloc_name == None ) : return ( "" )
  O0O00O = self . rloc_name
  if ( cour ) : O0O00O = lisp_print_cour ( O0O00O )
  return ( 'rloc-name: {}' . format ( blue ( O0O00O , cour ) ) )
  if 51 - 51: Oo0Ooo . Oo0Ooo
  if 34 - 34: I1ii11iIi11i - i11iIiiIii
 def print_record ( self , indent ) :
  I111I = self . print_rloc_name ( )
  if ( I111I != "" ) : I111I = ", " + I111I
  i1i = ""
  if ( self . geo ) :
   iI11i1Ii = ""
   if ( self . geo . geo_name ) : iI11i1Ii = "'{}' " . format ( self . geo . geo_name )
   i1i = ", geo: {}{}" . format ( iI11i1Ii , self . geo . print_geo ( ) )
   if 82 - 82: iII111i + I11i * OoO0O00 - I1ii11iIi11i % iII111i
  Oo0OooO00O = ""
  if ( self . elp ) :
   iI11i1Ii = ""
   if ( self . elp . elp_name ) : iI11i1Ii = "'{}' " . format ( self . elp . elp_name )
   Oo0OooO00O = ", elp: {}{}" . format ( iI11i1Ii , self . elp . print_elp ( True ) )
   if 63 - 63: OoOoOO00
  IiIiII = ""
  if ( self . rle ) :
   iI11i1Ii = ""
   if ( self . rle . rle_name ) : iI11i1Ii = "'{}' " . format ( self . rle . rle_name )
   IiIiII = ", rle: {}{}" . format ( iI11i1Ii , self . rle . print_rle ( False ) )
   if 99 - 99: OoooooooOO - i1IIi % o0oOOo0O0Ooo / o0oOOo0O0Ooo + IiII
  OoO0o0 = ""
  if ( self . json ) :
   iI11i1Ii = ""
   if ( self . json . json_name ) :
    iI11i1Ii = "'{}' " . format ( self . json . json_name )
    if 79 - 79: I1IiiI - IiII . OoooooooOO - I1ii11iIi11i
   OoO0o0 = ", json: {}" . format ( self . json . print_json ( False ) )
   if 79 - 79: OOooOOo + o0oOOo0O0Ooo % iII111i . oO0o
   if 49 - 49: Ii1I + i11iIiiIii * OoOoOO00 . OoOoOO00 . I1ii11iIi11i . Oo0Ooo
  o0O0O = ""
  if ( self . rloc . is_null ( ) == False and self . keys and self . keys [ 1 ] ) :
   o0O0O = ", " + self . keys [ 1 ] . print_keys ( )
   if 61 - 61: I11i . OoOoOO00 . OoOoOO00
   if 62 - 62: IiII % OoooooooOO * OoO0O00 + OoO0O00 % Ii1I % iII111i
  i11ii = ( "{}RLOC-record -> flags: {}, {}/{}/{}/{}, afi: {}, rloc: "
 + "{}{}{}{}{}{}{}" )
  lprint ( i11ii . format ( indent , self . print_flags ( ) , self . priority ,
 self . weight , self . mpriority , self . mweight , self . rloc . afi ,
 red ( self . rloc . print_address_no_iid ( ) , False ) , I111I , i1i ,
 Oo0OooO00O , IiIiII , OoO0o0 , o0O0O ) )
  if 66 - 66: I1IiiI . OOooOOo - OoO0O00 % Oo0Ooo * o0oOOo0O0Ooo - oO0o
  if 68 - 68: I11i - i11iIiiIii / o0oOOo0O0Ooo + ooOoO0o / I1IiiI
 def print_flags ( self ) :
  return ( "{}{}{}" . format ( "L" if self . local_bit else "l" , "P" if self . probe_bit else "p" , "R" if self . reach_bit else "r" ) )
  if 31 - 31: I1Ii111 . OoooooooOO . i1IIi
  if 65 - 65: OoO0O00 . ooOoO0o
  if 12 - 12: I1Ii111 + O0 - oO0o . IiII
 def store_rloc_entry ( self , rloc_entry ) :
  i1IIIIi1Ii111 = rloc_entry . rloc if ( rloc_entry . translated_rloc . is_null ( ) ) else rloc_entry . translated_rloc
  if 43 - 43: iII111i * i1IIi . I1IiiI . OoOoOO00 / IiII - Oo0Ooo
  self . rloc . copy_address ( i1IIIIi1Ii111 )
  if 95 - 95: OoooooooOO % OOooOOo * OOooOOo
  if ( rloc_entry . rloc_name ) :
   self . rloc_name = rloc_entry . rloc_name
   if 24 - 24: Ii1I * i11iIiiIii / O0 - I1ii11iIi11i
   if 93 - 93: ooOoO0o - OoooooooOO / IiII . I11i
  if ( rloc_entry . geo ) :
   self . geo = rloc_entry . geo
  else :
   iI11i1Ii = rloc_entry . geo_name
   if ( iI11i1Ii and lisp_geo_list . has_key ( iI11i1Ii ) ) :
    self . geo = lisp_geo_list [ iI11i1Ii ]
    if 7 - 7: o0oOOo0O0Ooo % Ii1I - i11iIiiIii
    if 47 - 47: Oo0Ooo / OoOoOO00
  if ( rloc_entry . elp ) :
   self . elp = rloc_entry . elp
  else :
   iI11i1Ii = rloc_entry . elp_name
   if ( iI11i1Ii and lisp_elp_list . has_key ( iI11i1Ii ) ) :
    self . elp = lisp_elp_list [ iI11i1Ii ]
    if 26 - 26: I11i . I1ii11iIi11i
    if 55 - 55: OoOoOO00 * I1Ii111 % OoO0O00 - OoO0O00
  if ( rloc_entry . rle ) :
   self . rle = rloc_entry . rle
  else :
   iI11i1Ii = rloc_entry . rle_name
   if ( iI11i1Ii and lisp_rle_list . has_key ( iI11i1Ii ) ) :
    self . rle = lisp_rle_list [ iI11i1Ii ]
    if 34 - 34: O0 * OoO0O00 - oO0o - IiII * Ii1I . II111iiii
    if 28 - 28: O0 % iII111i - i1IIi
  if ( rloc_entry . json ) :
   self . json = rloc_entry . json
  else :
   iI11i1Ii = rloc_entry . json_name
   if ( iI11i1Ii and lisp_json_list . has_key ( iI11i1Ii ) ) :
    self . json = lisp_json_list [ iI11i1Ii ]
    if 49 - 49: ooOoO0o . I11i - iIii1I11I1II1
    if 41 - 41: ooOoO0o * i11iIiiIii % ooOoO0o . oO0o
  self . priority = rloc_entry . priority
  self . weight = rloc_entry . weight
  self . mpriority = rloc_entry . mpriority
  self . mweight = rloc_entry . mweight
  if 97 - 97: oO0o - iII111i + IiII . OoOoOO00 + iIii1I11I1II1
  if 75 - 75: ooOoO0o + ooOoO0o . I1Ii111 % iII111i / iIii1I11I1II1 * iII111i
 def encode_lcaf ( self ) :
  O0OOOOO0O = socket . htons ( LISP_AFI_LCAF )
  IiIi1iIIiII1i = ""
  if ( self . geo ) :
   IiIi1iIIiII1i = self . geo . encode_geo ( )
   if 87 - 87: oO0o / OoO0O00 / i11iIiiIii / OoooooooOO
   if 25 - 25: I1IiiI . Oo0Ooo + iIii1I11I1II1 * iII111i % Oo0Ooo . OoOoOO00
  i1I1IIII = ""
  if ( self . elp ) :
   iI11iii111 = ""
   for IIi1i1111i in self . elp . elp_nodes :
    ooOooOooOOO = socket . htons ( IIi1i1111i . address . afi )
    Ooooo0OO = 0
    if ( IIi1i1111i . eid ) : Ooooo0OO |= 0x4
    if ( IIi1i1111i . probe ) : Ooooo0OO |= 0x2
    if ( IIi1i1111i . strict ) : Ooooo0OO |= 0x1
    Ooooo0OO = socket . htons ( Ooooo0OO )
    iI11iii111 += struct . pack ( "HH" , Ooooo0OO , ooOooOooOOO )
    iI11iii111 += IIi1i1111i . address . pack_address ( )
    if 55 - 55: I1Ii111 / i11iIiiIii / OoOoOO00
    if 25 - 25: Oo0Ooo / Oo0Ooo
   oo0ooo0OOO = socket . htons ( len ( iI11iii111 ) )
   i1I1IIII = struct . pack ( "HBBBBH" , O0OOOOO0O , 0 , 0 , LISP_LCAF_ELP_TYPE ,
 0 , oo0ooo0OOO )
   i1I1IIII += iI11iii111
   if 32 - 32: IiII
   if 1 - 1: I1IiiI
  iii11Ii = ""
  if ( self . rle ) :
   OooooooOOO0o0 = ""
   for i1ooOoO in self . rle . rle_nodes :
    ooOooOooOOO = socket . htons ( i1ooOoO . address . afi )
    OooooooOOO0o0 += struct . pack ( "HBBH" , 0 , 0 , i1ooOoO . level , ooOooOooOOO )
    OooooooOOO0o0 += i1ooOoO . address . pack_address ( )
    if ( i1ooOoO . rloc_name ) :
     OooooooOOO0o0 += struct . pack ( "H" , socket . htons ( LISP_AFI_NAME ) )
     OooooooOOO0o0 += i1ooOoO . rloc_name + "\0"
     if 66 - 66: IiII
     if 83 - 83: iII111i / I1Ii111 . I11i / i11iIiiIii
     if 4 - 4: ooOoO0o . OoO0O00
   I1ii1i1i1iIii = socket . htons ( len ( OooooooOOO0o0 ) )
   iii11Ii = struct . pack ( "HBBBBH" , O0OOOOO0O , 0 , 0 , LISP_LCAF_RLE_TYPE ,
 0 , I1ii1i1i1iIii )
   iii11Ii += OooooooOOO0o0
   if 26 - 26: i11iIiiIii - OoO0O00 * i1IIi * iIii1I11I1II1 % iIii1I11I1II1
   if 14 - 14: ooOoO0o
  IIiIII = ""
  if ( self . json ) :
   ii111 = socket . htons ( len ( self . json . json_string ) + 2 )
   i1oO0o00oOo00oO = socket . htons ( len ( self . json . json_string ) )
   IIiIII = struct . pack ( "HBBBBHH" , O0OOOOO0O , 0 , 0 , LISP_LCAF_JSON_TYPE ,
 0 , ii111 , i1oO0o00oOo00oO )
   IIiIII += self . json . json_string
   IIiIII += struct . pack ( "H" , 0 )
   if 5 - 5: Ii1I
   if 26 - 26: iIii1I11I1II1 / i1IIi
  i11i1i = ""
  if ( self . rloc . is_null ( ) == False and self . keys and self . keys [ 1 ] ) :
   i11i1i = self . keys [ 1 ] . encode_lcaf ( self . rloc )
   if 84 - 84: iIii1I11I1II1 / o0oOOo0O0Ooo / II111iiii
   if 81 - 81: i11iIiiIii + o0oOOo0O0Ooo / II111iiii + I11i
  OOO0O0 = ""
  if ( self . rloc_name ) :
   OOO0O0 += struct . pack ( "H" , socket . htons ( LISP_AFI_NAME ) )
   OOO0O0 += self . rloc_name + "\0"
   if 25 - 25: oO0o - OoOoOO00 / OoO0O00 / Ii1I
   if 34 - 34: ooOoO0o + Oo0Ooo
  I1Ii1OOoo0Oo00 = len ( IiIi1iIIiII1i ) + len ( i1I1IIII ) + len ( iii11Ii ) + len ( i11i1i ) + 2 + len ( IIiIII ) + self . rloc . addr_length ( ) + len ( OOO0O0 )
  if 16 - 16: I1Ii111 % Oo0Ooo * OOooOOo % I1ii11iIi11i + OOooOOo % OoO0O00
  I1Ii1OOoo0Oo00 = socket . htons ( I1Ii1OOoo0Oo00 )
  O00oo00O = struct . pack ( "HBBBBHH" , O0OOOOO0O , 0 , 0 , LISP_LCAF_AFI_LIST_TYPE ,
 0 , I1Ii1OOoo0Oo00 , socket . htons ( self . rloc . afi ) )
  O00oo00O += self . rloc . pack_address ( )
  return ( O00oo00O + OOO0O0 + IiIi1iIIiII1i + i1I1IIII + iii11Ii + i11i1i + IIiIII )
  if 93 - 93: iIii1I11I1II1
  if 48 - 48: OoOoOO00
 def encode ( self ) :
  Ooooo0OO = 0
  if ( self . local_bit ) : Ooooo0OO |= 0x0004
  if ( self . probe_bit ) : Ooooo0OO |= 0x0002
  if ( self . reach_bit ) : Ooooo0OO |= 0x0001
  if 65 - 65: I11i * i1IIi - I1Ii111 / o0oOOo0O0Ooo / OoO0O00 - OOooOOo
  iI1IIII1ii1 = struct . pack ( "BBBBHH" , self . priority , self . weight ,
 self . mpriority , self . mweight , socket . htons ( Ooooo0OO ) ,
 socket . htons ( self . rloc . afi ) )
  if 3 - 3: o0oOOo0O0Ooo + OoOoOO00 / oO0o - Ii1I % Ii1I
  if ( self . geo or self . elp or self . rle or self . keys or self . rloc_name or self . json ) :
   if 8 - 8: IiII
   iI1IIII1ii1 = iI1IIII1ii1 [ 0 : - 2 ] + self . encode_lcaf ( )
  else :
   iI1IIII1ii1 += self . rloc . pack_address ( )
   if 68 - 68: IiII . OoooooooOO - i11iIiiIii + i11iIiiIii
  return ( iI1IIII1ii1 )
  if 81 - 81: OoOoOO00 + iII111i . i11iIiiIii
  if 10 - 10: OoOoOO00 + I11i - iIii1I11I1II1 - I11i
 def decode_lcaf ( self , packet , nonce ) :
  oOO0OOOoO0ooo = "HBBBBH"
  I1111ii1i = struct . calcsize ( oOO0OOOoO0ooo )
  if ( len ( packet ) < I1111ii1i ) : return ( None )
  if 58 - 58: ooOoO0o
  ooOooOooOOO , OOII1iI , Ooooo0OO , O00OO0oOOO , o0o0OO0OO , ii111 = struct . unpack ( oOO0OOOoO0ooo , packet [ : I1111ii1i ] )
  if 98 - 98: Ii1I / OoO0O00 % OoooooooOO
  if 65 - 65: ooOoO0o % Oo0Ooo - I1IiiI % I1Ii111 + iIii1I11I1II1 / iIii1I11I1II1
  ii111 = socket . ntohs ( ii111 )
  packet = packet [ I1111ii1i : : ]
  if ( ii111 > len ( packet ) ) : return ( None )
  if 94 - 94: IiII - Oo0Ooo . o0oOOo0O0Ooo - ooOoO0o - oO0o . I11i
  if 39 - 39: oO0o + OoOoOO00
  if 68 - 68: i1IIi * oO0o / i11iIiiIii
  if 96 - 96: I1IiiI
  if ( O00OO0oOOO == LISP_LCAF_AFI_LIST_TYPE ) :
   while ( ii111 > 0 ) :
    oOO0OOOoO0ooo = "H"
    I1111ii1i = struct . calcsize ( oOO0OOOoO0ooo )
    if ( ii111 < I1111ii1i ) : return ( None )
    if 78 - 78: OoO0O00
    o0o00o = len ( packet )
    ooOooOooOOO = struct . unpack ( oOO0OOOoO0ooo , packet [ : I1111ii1i ] ) [ 0 ]
    ooOooOooOOO = socket . ntohs ( ooOooOooOOO )
    if 72 - 72: I1ii11iIi11i / O0 % II111iiii / II111iiii
    if ( ooOooOooOOO == LISP_AFI_LCAF ) :
     packet = self . decode_lcaf ( packet , nonce )
     if ( packet == None ) : return ( None )
    else :
     packet = packet [ I1111ii1i : : ]
     self . rloc_name = None
     if ( ooOooOooOOO == LISP_AFI_NAME ) :
      packet , O0O00O = lisp_decode_dist_name ( packet )
      self . rloc_name = O0O00O
     else :
      self . rloc . afi = ooOooOooOOO
      packet = self . rloc . unpack_address ( packet )
      if ( packet == None ) : return ( None )
      self . rloc . mask_len = self . rloc . host_mask_len ( )
      if 48 - 48: OOooOOo % OOooOOo / iIii1I11I1II1 - i11iIiiIii
      if 57 - 57: I11i / IiII * i1IIi + II111iiii . o0oOOo0O0Ooo
      if 11 - 11: II111iiii
    ii111 -= o0o00o - len ( packet )
    if 66 - 66: Ii1I - I1IiiI . OoooooooOO * I1Ii111
    if 16 - 16: IiII * OoO0O00 * i11iIiiIii - ooOoO0o
  elif ( O00OO0oOOO == LISP_LCAF_GEO_COORD_TYPE ) :
   if 88 - 88: iIii1I11I1II1 / Ii1I * IiII / I1Ii111
   if 31 - 31: O0 . I1IiiI
   if 8 - 8: OoOoOO00
   if 99 - 99: iII111i
   oOo0o0oOoo0Oo = lisp_geo ( "" )
   packet = oOo0o0oOoo0Oo . decode_geo ( packet , ii111 , o0o0OO0OO )
   if ( packet == None ) : return ( None )
   self . geo = oOo0o0oOoo0Oo
   if 85 - 85: iIii1I11I1II1
  elif ( O00OO0oOOO == LISP_LCAF_JSON_TYPE ) :
   if 91 - 91: ooOoO0o . iII111i - O0 . o0oOOo0O0Ooo . IiII
   if 30 - 30: OoOoOO00
   if 70 - 70: ooOoO0o - o0oOOo0O0Ooo + II111iiii + oO0o + i1IIi
   if 79 - 79: I1Ii111
   oOO0OOOoO0ooo = "H"
   I1111ii1i = struct . calcsize ( oOO0OOOoO0ooo )
   if ( ii111 < I1111ii1i ) : return ( None )
   if 50 - 50: ooOoO0o . I1ii11iIi11i . i1IIi / OoooooooOO
   i1oO0o00oOo00oO = struct . unpack ( oOO0OOOoO0ooo , packet [ : I1111ii1i ] ) [ 0 ]
   i1oO0o00oOo00oO = socket . ntohs ( i1oO0o00oOo00oO )
   if ( ii111 < I1111ii1i + i1oO0o00oOo00oO ) : return ( None )
   if 35 - 35: i1IIi . i1IIi * I1ii11iIi11i . OOooOOo + OoO0O00 + II111iiii
   packet = packet [ I1111ii1i : : ]
   self . json = lisp_json ( "" , packet [ 0 : i1oO0o00oOo00oO ] )
   packet = packet [ i1oO0o00oOo00oO : : ]
   if 35 - 35: Ii1I / OoOoOO00
  elif ( O00OO0oOOO == LISP_LCAF_ELP_TYPE ) :
   if 32 - 32: iIii1I11I1II1
   if 37 - 37: I1Ii111 % o0oOOo0O0Ooo + I11i
   if 28 - 28: OoO0O00 * o0oOOo0O0Ooo - I1ii11iIi11i * ooOoO0o
   if 4 - 4: ooOoO0o
   o00oOO0 = lisp_elp ( None )
   o00oOO0 . elp_nodes = [ ]
   while ( ii111 > 0 ) :
    Ooooo0OO , ooOooOooOOO = struct . unpack ( "HH" , packet [ : 4 ] )
    if 86 - 86: O0 - OoooooooOO
    ooOooOooOOO = socket . ntohs ( ooOooOooOOO )
    if ( ooOooOooOOO == LISP_AFI_LCAF ) : return ( None )
    if 41 - 41: Oo0Ooo + IiII / OOooOOo + IiII . OOooOOo
    IIi1i1111i = lisp_elp_node ( )
    o00oOO0 . elp_nodes . append ( IIi1i1111i )
    if 28 - 28: iII111i . ooOoO0o - OoooooooOO + I11i . iII111i + IiII
    Ooooo0OO = socket . ntohs ( Ooooo0OO )
    IIi1i1111i . eid = ( Ooooo0OO & 0x4 )
    IIi1i1111i . probe = ( Ooooo0OO & 0x2 )
    IIi1i1111i . strict = ( Ooooo0OO & 0x1 )
    IIi1i1111i . address . afi = ooOooOooOOO
    IIi1i1111i . address . mask_len = IIi1i1111i . address . host_mask_len ( )
    packet = IIi1i1111i . address . unpack_address ( packet [ 4 : : ] )
    ii111 -= IIi1i1111i . address . addr_length ( ) + 4
    if 1 - 1: OoO0O00 % OOooOOo - iII111i * iIii1I11I1II1
   o00oOO0 . select_elp_node ( )
   self . elp = o00oOO0
   if 14 - 14: OoOoOO00
  elif ( O00OO0oOOO == LISP_LCAF_RLE_TYPE ) :
   if 17 - 17: Oo0Ooo . OoooooooOO % I1ii11iIi11i / OoooooooOO
   if 56 - 56: OoOoOO00 - IiII
   if 53 - 53: I1ii11iIi11i - II111iiii . i11iIiiIii
   if 76 - 76: iIii1I11I1II1 - Oo0Ooo
   O0OOOO0000O = lisp_rle ( None )
   O0OOOO0000O . rle_nodes = [ ]
   while ( ii111 > 0 ) :
    oOOooOOO , OOo00o000oOO0 , II1II , ooOooOooOOO = struct . unpack ( "HBBH" , packet [ : 6 ] )
    if 99 - 99: i1IIi + o0oOOo0O0Ooo . i11iIiiIii * I1IiiI
    ooOooOooOOO = socket . ntohs ( ooOooOooOOO )
    if ( ooOooOooOOO == LISP_AFI_LCAF ) : return ( None )
    if 63 - 63: I1IiiI % oO0o / iIii1I11I1II1 * Ii1I % OOooOOo . II111iiii
    i1ooOoO = lisp_rle_node ( )
    O0OOOO0000O . rle_nodes . append ( i1ooOoO )
    if 56 - 56: IiII / i11iIiiIii . o0oOOo0O0Ooo . oO0o - i11iIiiIii
    i1ooOoO . level = II1II
    i1ooOoO . address . afi = ooOooOooOOO
    i1ooOoO . address . mask_len = i1ooOoO . address . host_mask_len ( )
    packet = i1ooOoO . address . unpack_address ( packet [ 6 : : ] )
    if 23 - 23: I1ii11iIi11i * i11iIiiIii % ooOoO0o
    ii111 -= i1ooOoO . address . addr_length ( ) + 6
    if ( ii111 >= 2 ) :
     ooOooOooOOO = struct . unpack ( "H" , packet [ : 2 ] ) [ 0 ]
     if ( socket . ntohs ( ooOooOooOOO ) == LISP_AFI_NAME ) :
      packet = packet [ 2 : : ]
      packet , i1ooOoO . rloc_name = lisp_decode_dist_name ( packet )
      if 47 - 47: iIii1I11I1II1 . OOooOOo / I11i % II111iiii
      if ( packet == None ) : return ( None )
      ii111 -= len ( i1ooOoO . rloc_name ) + 1 + 2
      if 92 - 92: I1ii11iIi11i % i11iIiiIii
      if 82 - 82: I1Ii111 * I1ii11iIi11i % Ii1I / o0oOOo0O0Ooo
      if 28 - 28: iII111i % OoO0O00 - OOooOOo - Oo0Ooo
   self . rle = O0OOOO0000O
   self . rle . build_forwarding_list ( )
   if 16 - 16: i11iIiiIii - i11iIiiIii . OoOoOO00 / i1IIi
  elif ( O00OO0oOOO == LISP_LCAF_SECURITY_TYPE ) :
   if 76 - 76: O0 * OoO0O00 / O0
   if 23 - 23: I1ii11iIi11i . iIii1I11I1II1 - i11iIiiIii / II111iiii
   if 48 - 48: oO0o - II111iiii * I1IiiI
   if 78 - 78: I1IiiI * i11iIiiIii * II111iiii
   if 19 - 19: OoooooooOO * i11iIiiIii / O0 . I1IiiI % I11i
   O0ooO00OO = packet
   IiI11IiIIi = lisp_keys ( 1 )
   packet = IiI11IiIIi . decode_lcaf ( O0ooO00OO , ii111 )
   if ( packet == None ) : return ( None )
   if 35 - 35: iIii1I11I1II1 + I1IiiI - ooOoO0o / Oo0Ooo * I1ii11iIi11i * Oo0Ooo
   if 17 - 17: OoOoOO00
   if 24 - 24: iIii1I11I1II1 / OOooOOo % OoooooooOO / O0 / oO0o
   if 93 - 93: Oo0Ooo
   oO0oo0O0OOOo0 = [ LISP_CS_25519_CBC , LISP_CS_25519_CHACHA ]
   if ( IiI11IiIIi . cipher_suite in oO0oo0O0OOOo0 ) :
    if ( IiI11IiIIi . cipher_suite == LISP_CS_25519_CBC ) :
     i1IIiI1iII = lisp_keys ( 1 , do_poly = False , do_chacha = False )
     if 5 - 5: iII111i
    if ( IiI11IiIIi . cipher_suite == LISP_CS_25519_CHACHA ) :
     i1IIiI1iII = lisp_keys ( 1 , do_poly = True , do_chacha = True )
     if 61 - 61: OOooOOo * OoO0O00 - O0
   else :
    i1IIiI1iII = lisp_keys ( 1 , do_poly = False , do_chacha = False )
    if 30 - 30: iIii1I11I1II1
   packet = i1IIiI1iII . decode_lcaf ( O0ooO00OO , ii111 )
   if ( packet == None ) : return ( None )
   if 14 - 14: o0oOOo0O0Ooo + Ii1I
   if ( len ( packet ) < 2 ) : return ( None )
   ooOooOooOOO = struct . unpack ( "H" , packet [ : 2 ] ) [ 0 ]
   self . rloc . afi = socket . ntohs ( ooOooOooOOO )
   if ( len ( packet ) < self . rloc . addr_length ( ) ) : return ( None )
   packet = self . rloc . unpack_address ( packet [ 2 : : ] )
   if ( packet == None ) : return ( None )
   self . rloc . mask_len = self . rloc . host_mask_len ( )
   if 91 - 91: OoooooooOO / oO0o + OoOoOO00
   if 100 - 100: i1IIi
   if 13 - 13: i1IIi . I1ii11iIi11i * o0oOOo0O0Ooo
   if 31 - 31: i11iIiiIii % OoO0O00 . i11iIiiIii % oO0o - i1IIi
   if 62 - 62: oO0o + oO0o . OoooooooOO
   if 59 - 59: iIii1I11I1II1 . Oo0Ooo * I11i
   if ( self . rloc . is_null ( ) ) : return ( packet )
   if 29 - 29: Oo0Ooo - I1IiiI * I11i
   Ooo000oo0OO0 = self . rloc_name
   if ( Ooo000oo0OO0 ) : Ooo000oo0OO0 = blue ( self . rloc_name , False )
   if 54 - 54: I1IiiI
   if 29 - 29: OoO0O00 * iIii1I11I1II1 % Ii1I / oO0o / I1Ii111
   if 92 - 92: OoO0O00 * OoO0O00 + OoooooooOO . IiII + OoO0O00
   if 13 - 13: O0 . I1IiiI % OoO0O00 - I11i . O0
   if 14 - 14: iIii1I11I1II1
   if 48 - 48: i11iIiiIii * OoOoOO00 - I1IiiI + iIii1I11I1II1
   O00oO0OOOo0 = self . keys [ 1 ] if self . keys else None
   if ( O00oO0OOOo0 == None ) :
    if ( i1IIiI1iII . remote_public_key == None ) :
     oo0OooO = bold ( "No remote encap-public-key supplied" , False )
     lprint ( "    {} for {}" . format ( oo0OooO , Ooo000oo0OO0 ) )
     i1IIiI1iII = None
    else :
     oo0OooO = bold ( "New encap-keying with new state" , False )
     lprint ( "    {} for {}" . format ( oo0OooO , Ooo000oo0OO0 ) )
     i1IIiI1iII . compute_shared_key ( "encap" )
     if 20 - 20: I1ii11iIi11i - iIii1I11I1II1 . iII111i
     if 52 - 52: OoO0O00 - I1Ii111
     if 9 - 9: I1IiiI . i11iIiiIii
     if 3 - 3: I1IiiI + I1ii11iIi11i * I1Ii111 - i1IIi . OOooOOo
     if 21 - 21: OOooOOo + o0oOOo0O0Ooo
     if 39 - 39: OoOoOO00 . I11i * OOooOOo . i1IIi
     if 69 - 69: IiII - i1IIi + o0oOOo0O0Ooo
     if 5 - 5: II111iiii
     if 88 - 88: OoooooooOO % II111iiii + IiII + IiII * Oo0Ooo
     if 81 - 81: I1IiiI * ooOoO0o + I1Ii111
   if ( O00oO0OOOo0 ) :
    if ( i1IIiI1iII . remote_public_key == None ) :
     i1IIiI1iII = None
     ii1I11iIi = bold ( "Remote encap-unkeying occurred" , False )
     lprint ( "    {} for {}" . format ( ii1I11iIi , Ooo000oo0OO0 ) )
    elif ( O00oO0OOOo0 . compare_keys ( i1IIiI1iII ) ) :
     i1IIiI1iII = O00oO0OOOo0
     lprint ( "    Maintain stored encap-keys for {}" . format ( Ooo000oo0OO0 ) )
     if 49 - 49: I1IiiI % oO0o % II111iiii * II111iiii + OoooooooOO + iII111i
    else :
     if ( O00oO0OOOo0 . remote_public_key == None ) :
      oo0OooO = "New encap-keying for existing state"
     else :
      oo0OooO = "Remote encap-rekeying"
      if 58 - 58: i11iIiiIii % iIii1I11I1II1 + OoO0O00 . I1ii11iIi11i . I1IiiI
     lprint ( "    {} for {}" . format ( bold ( oo0OooO , False ) ,
 Ooo000oo0OO0 ) )
     O00oO0OOOo0 . remote_public_key = i1IIiI1iII . remote_public_key
     O00oO0OOOo0 . compute_shared_key ( "encap" )
     i1IIiI1iII = O00oO0OOOo0
     if 54 - 54: iII111i . OoO0O00 . iIii1I11I1II1
     if 45 - 45: I1ii11iIi11i + I1IiiI / i11iIiiIii
   self . keys = [ None , i1IIiI1iII , None , None ]
   if 45 - 45: IiII / O0 * I1IiiI - OOooOOo * I1Ii111
  else :
   if 19 - 19: OoOoOO00 / IiII - OOooOOo * i11iIiiIii % I1Ii111
   if 98 - 98: IiII + IiII + OOooOOo / i1IIi + oO0o
   if 53 - 53: OoOoOO00
   if 69 - 69: iIii1I11I1II1 * OoO0O00 / OoooooooOO % I1ii11iIi11i . I1IiiI % I11i
   packet = packet [ ii111 : : ]
   if 40 - 40: i11iIiiIii % oO0o / OOooOOo
  return ( packet )
  if 85 - 85: OoO0O00 % O0 . Ii1I . iII111i . iII111i
  if 90 - 90: o0oOOo0O0Ooo - Oo0Ooo / ooOoO0o / i1IIi - Ii1I
 def decode ( self , packet , nonce ) :
  oOO0OOOoO0ooo = "BBBBHH"
  I1111ii1i = struct . calcsize ( oOO0OOOoO0ooo )
  if ( len ( packet ) < I1111ii1i ) : return ( None )
  if 43 - 43: i11iIiiIii - OoooooooOO % ooOoO0o
  self . priority , self . weight , self . mpriority , self . mweight , Ooooo0OO , ooOooOooOOO = struct . unpack ( oOO0OOOoO0ooo , packet [ : I1111ii1i ] )
  if 55 - 55: oO0o % Oo0Ooo % IiII
  if 65 - 65: IiII * IiII
  Ooooo0OO = socket . ntohs ( Ooooo0OO )
  ooOooOooOOO = socket . ntohs ( ooOooOooOOO )
  self . local_bit = True if ( Ooooo0OO & 0x0004 ) else False
  self . probe_bit = True if ( Ooooo0OO & 0x0002 ) else False
  self . reach_bit = True if ( Ooooo0OO & 0x0001 ) else False
  if 60 - 60: ooOoO0o
  if ( ooOooOooOOO == LISP_AFI_LCAF ) :
   packet = packet [ I1111ii1i - 2 : : ]
   packet = self . decode_lcaf ( packet , nonce )
  else :
   self . rloc . afi = ooOooOooOOO
   packet = packet [ I1111ii1i : : ]
   packet = self . rloc . unpack_address ( packet )
   if 92 - 92: O0 % IiII
  self . rloc . mask_len = self . rloc . host_mask_len ( )
  return ( packet )
  if 15 - 15: O0 % i1IIi - OOooOOo . IiII
  if 1 - 1: I1IiiI
 def end_of_rlocs ( self , packet , rloc_count ) :
  for oO in range ( rloc_count ) :
   packet = self . decode ( packet , None )
   if ( packet == None ) : return ( None )
   if 40 - 40: o0oOOo0O0Ooo % I11i % O0
  return ( packet )
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
  if 29 - 29: OOooOOo
  if 69 - 69: oO0o % OoooooooOO * iII111i
  if 58 - 58: oO0o / i11iIiiIii . OoOoOO00 % O0 / iIii1I11I1II1
  if 50 - 50: I1Ii111 . I11i / O0 . I11i
  if 91 - 91: i11iIiiIii . I1ii11iIi11i + I11i
  if 67 - 67: I1ii11iIi11i * I1Ii111 * I1IiiI / I11i - IiII + oO0o
class lisp_map_referral ( ) :
 def __init__ ( self ) :
  self . record_count = 0
  self . nonce = 0
  if 11 - 11: O0 + i1IIi / o0oOOo0O0Ooo * OoO0O00
  if 64 - 64: i1IIi % IiII . ooOoO0o . iIii1I11I1II1 + OoO0O00 - iIii1I11I1II1
 def print_map_referral ( self ) :
  lprint ( "{} -> record-count: {}, nonce: 0x{}" . format ( bold ( "Map-Referral" , False ) , self . record_count ,
  # o0oOOo0O0Ooo / IiII / ooOoO0o * OoOoOO00
 lisp_hex_string ( self . nonce ) ) )
  if 13 - 13: iII111i
  if 69 - 69: i11iIiiIii - i11iIiiIii + I11i / I1IiiI % I1ii11iIi11i
 def encode ( self ) :
  O0ooOo0Oooo = ( LISP_MAP_REFERRAL << 28 ) | self . record_count
  iI1IIII1ii1 = struct . pack ( "I" , socket . htonl ( O0ooOo0Oooo ) )
  iI1IIII1ii1 += struct . pack ( "Q" , self . nonce )
  return ( iI1IIII1ii1 )
  if 56 - 56: iIii1I11I1II1 / OoO0O00 * OOooOOo
  if 73 - 73: OoooooooOO % IiII / I1Ii111 * I11i + i1IIi % i11iIiiIii
 def decode ( self , packet ) :
  oOO0OOOoO0ooo = "I"
  I1111ii1i = struct . calcsize ( oOO0OOOoO0ooo )
  if ( len ( packet ) < I1111ii1i ) : return ( None )
  if 91 - 91: i11iIiiIii
  O0ooOo0Oooo = struct . unpack ( oOO0OOOoO0ooo , packet [ : I1111ii1i ] )
  O0ooOo0Oooo = socket . ntohl ( O0ooOo0Oooo [ 0 ] )
  self . record_count = O0ooOo0Oooo & 0xff
  packet = packet [ I1111ii1i : : ]
  if 6 - 6: O0 - iIii1I11I1II1 + I1Ii111 . o0oOOo0O0Ooo * i11iIiiIii
  oOO0OOOoO0ooo = "Q"
  I1111ii1i = struct . calcsize ( oOO0OOOoO0ooo )
  if ( len ( packet ) < I1111ii1i ) : return ( None )
  if 53 - 53: OOooOOo / I1IiiI / oO0o * OOooOOo / i1IIi - I1Ii111
  self . nonce = struct . unpack ( oOO0OOOoO0ooo , packet [ : I1111ii1i ] ) [ 0 ]
  packet = packet [ I1111ii1i : : ]
  return ( packet )
  if 71 - 71: O0 + Oo0Ooo % oO0o - o0oOOo0O0Ooo
  if 82 - 82: iIii1I11I1II1
  if 64 - 64: ooOoO0o + I1IiiI % OOooOOo + II111iiii
  if 46 - 46: I1IiiI
  if 72 - 72: iII111i
  if 100 - 100: I1IiiI
  if 55 - 55: i1IIi % IiII
  if 44 - 44: oO0o - iIii1I11I1II1 / ooOoO0o - iIii1I11I1II1 % i1IIi + ooOoO0o
class lisp_ddt_entry ( ) :
 def __init__ ( self ) :
  self . eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . group = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . uptime = lisp_get_timestamp ( )
  self . delegation_set = [ ]
  self . source_cache = None
  self . map_referrals_sent = 0
  if 74 - 74: I11i . OoOoOO00 + OoOoOO00
  if 87 - 87: IiII + o0oOOo0O0Ooo . i1IIi % I1Ii111
 def is_auth_prefix ( self ) :
  if ( len ( self . delegation_set ) != 0 ) : return ( False )
  if ( self . is_star_g ( ) ) : return ( False )
  return ( True )
  if 44 - 44: Oo0Ooo - OOooOOo . Ii1I * OoooooooOO
  if 93 - 93: OoO0O00 . OoO0O00
 def is_ms_peer_entry ( self ) :
  if ( len ( self . delegation_set ) == 0 ) : return ( False )
  return ( self . delegation_set [ 0 ] . is_ms_peer ( ) )
  if 52 - 52: OOooOOo . oO0o / Oo0Ooo . OoooooooOO % I1ii11iIi11i
  if 65 - 65: ooOoO0o % II111iiii . iII111i - iIii1I11I1II1 - I1IiiI
 def print_referral_type ( self ) :
  if ( len ( self . delegation_set ) == 0 ) : return ( "unknown" )
  ooOiiI1Ii11 = self . delegation_set [ 0 ]
  return ( ooOiiI1Ii11 . print_node_type ( ) )
  if 95 - 95: iIii1I11I1II1 % I1Ii111
  if 39 - 39: I1ii11iIi11i - iIii1I11I1II1 * ooOoO0o
 def print_eid_tuple ( self ) :
  return ( lisp_print_eid_tuple ( self . eid , self . group ) )
  if 87 - 87: O0 + O0 - ooOoO0o . i11iIiiIii - Oo0Ooo * i11iIiiIii
  if 72 - 72: I11i / OoooooooOO
 def add_cache ( self ) :
  if ( self . group . is_null ( ) ) :
   lisp_ddt_cache . add_cache ( self . eid , self )
  else :
   OOOoooooo0oO = lisp_ddt_cache . lookup_cache ( self . group , True )
   if ( OOOoooooo0oO == None ) :
    OOOoooooo0oO = lisp_ddt_entry ( )
    OOOoooooo0oO . eid . copy_address ( self . group )
    OOOoooooo0oO . group . copy_address ( self . group )
    lisp_ddt_cache . add_cache ( self . group , OOOoooooo0oO )
    if 7 - 7: i11iIiiIii * I1ii11iIi11i / OoO0O00 * oO0o
   if ( self . eid . is_null ( ) ) : self . eid . make_default_route ( OOOoooooo0oO . group )
   OOOoooooo0oO . add_source_entry ( self )
   if 35 - 35: IiII . i1IIi + I1ii11iIi11i . IiII + ooOoO0o . oO0o
   if 2 - 2: II111iiii
   if 18 - 18: iIii1I11I1II1 % I1ii11iIi11i % Oo0Ooo
 def add_source_entry ( self , source_ddt ) :
  if ( self . source_cache == None ) : self . source_cache = lisp_cache ( )
  self . source_cache . add_cache ( source_ddt . eid , source_ddt )
  if 47 - 47: ooOoO0o - I1IiiI % OOooOOo * Ii1I % I1IiiI
  if 95 - 95: OoO0O00 + OoOoOO00 % Oo0Ooo . Ii1I * I1IiiI + I1Ii111
 def lookup_source_cache ( self , source , exact ) :
  if ( self . source_cache == None ) : return ( None )
  return ( self . source_cache . lookup_cache ( source , exact ) )
  if 22 - 22: Oo0Ooo . OoO0O00
  if 55 - 55: Oo0Ooo % OoooooooOO * II111iiii % OoooooooOO
 def is_star_g ( self ) :
  if ( self . group . is_null ( ) ) : return ( False )
  return ( self . eid . is_exact_match ( self . group ) )
  if 30 - 30: I1Ii111 / o0oOOo0O0Ooo + OoooooooOO + OoOoOO00 + OoO0O00
  if 40 - 40: OoooooooOO / IiII
  if 82 - 82: i11iIiiIii - oO0o - i1IIi
class lisp_ddt_node ( ) :
 def __init__ ( self ) :
  self . delegate_address = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . public_key = ""
  self . map_server_peer = False
  self . map_server_child = False
  self . priority = 0
  self . weight = 0
  if 78 - 78: oO0o % iII111i / i1IIi / ooOoO0o
  if 44 - 44: o0oOOo0O0Ooo + Ii1I + I1IiiI % O0
 def print_node_type ( self ) :
  if ( self . is_ddt_child ( ) ) : return ( "ddt-child" )
  if ( self . is_ms_child ( ) ) : return ( "map-server-child" )
  if ( self . is_ms_peer ( ) ) : return ( "map-server-peer" )
  if 100 - 100: OoooooooOO
  if 27 - 27: i11iIiiIii % II111iiii + I1Ii111
 def is_ddt_child ( self ) :
  if ( self . map_server_child ) : return ( False )
  if ( self . map_server_peer ) : return ( False )
  return ( True )
  if 76 - 76: OOooOOo - I1Ii111 + iIii1I11I1II1 + I1IiiI * oO0o
  if 93 - 93: i11iIiiIii * i11iIiiIii - I1IiiI + iIii1I11I1II1 * i11iIiiIii
 def is_ms_child ( self ) :
  return ( self . map_server_child )
  if 14 - 14: ooOoO0o . OoooooooOO . I1IiiI - IiII + iIii1I11I1II1
  if 47 - 47: OOooOOo % i1IIi
 def is_ms_peer ( self ) :
  return ( self . map_server_peer )
  if 23 - 23: Ii1I * Ii1I / I11i
  if 11 - 11: OOooOOo
  if 58 - 58: OoO0O00 * OoooooooOO
  if 47 - 47: iII111i - Oo0Ooo
  if 19 - 19: O0 . i1IIi + I11i / II111iiii + ooOoO0o
  if 26 - 26: Ii1I * oO0o % I1IiiI - OOooOOo . I1Ii111
  if 35 - 35: i1IIi % i11iIiiIii + Ii1I
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
  if 14 - 14: OoO0O00 * OoooooooOO
  if 45 - 45: iIii1I11I1II1 * I1IiiI . OoOoOO00
 def print_ddt_map_request ( self ) :
  lprint ( "Queued Map-Request from {}ITR {}->{}, nonce 0x{}" . format ( "P" if self . from_pitr else "" ,
  # Ii1I % Ii1I % iIii1I11I1II1 / i11iIiiIii % iIii1I11I1II1 / ooOoO0o
 red ( self . itr . print_address ( ) , False ) ,
 green ( self . eid . print_address ( ) , False ) , self . nonce ) )
  if 66 - 66: oO0o . I1ii11iIi11i . O0
  if 84 - 84: i1IIi % oO0o
 def queue_map_request ( self ) :
  self . retransmit_timer = threading . Timer ( LISP_DDT_MAP_REQUEST_INTERVAL ,
 lisp_retransmit_ddt_map_request , [ self ] )
  self . retransmit_timer . start ( )
  lisp_ddt_map_requestQ [ str ( self . nonce ) ] = self
  if 34 - 34: I11i
  if 95 - 95: I1IiiI . oO0o
 def dequeue_map_request ( self ) :
  self . retransmit_timer . cancel ( )
  if ( lisp_ddt_map_requestQ . has_key ( str ( self . nonce ) ) ) :
   lisp_ddt_map_requestQ . pop ( str ( self . nonce ) )
   if 60 - 60: iII111i
   if 92 - 92: i1IIi + I1Ii111 % i1IIi * iII111i % o0oOOo0O0Ooo
   if 56 - 56: I1IiiI / OOooOOo * O0 - iII111i + Oo0Ooo + IiII
 def print_eid_tuple ( self ) :
  return ( lisp_print_eid_tuple ( self . eid , self . group ) )
  if 15 - 15: iIii1I11I1II1 % II111iiii
  if 48 - 48: OoOoOO00 + O0 - II111iiii % II111iiii . II111iiii
  if 90 - 90: oO0o % IiII / I1Ii111 + O0
  if 4 - 4: ooOoO0o . iIii1I11I1II1 + I1IiiI - OoO0O00
  if 69 - 69: OOooOOo
  if 47 - 47: I1Ii111
  if 96 - 96: i1IIi * iIii1I11I1II1 . OOooOOo + O0 . o0oOOo0O0Ooo
  if 23 - 23: I1ii11iIi11i . I1ii11iIi11i / I1IiiI . i1IIi
  if 47 - 47: i11iIiiIii . o0oOOo0O0Ooo . i11iIiiIii + I1IiiI - I1ii11iIi11i
  if 62 - 62: OoooooooOO + I1IiiI / ooOoO0o . Ii1I . Oo0Ooo
  if 81 - 81: oO0o + IiII
  if 75 - 75: O0 + I1ii11iIi11i
  if 51 - 51: i1IIi + II111iiii % oO0o
  if 72 - 72: OOooOOo + OOooOOo
  if 30 - 30: I11i
  if 15 - 15: O0 - i1IIi . iIii1I11I1II1 - i11iIiiIii / Ii1I
  if 11 - 11: iIii1I11I1II1 + I1IiiI
  if 15 - 15: o0oOOo0O0Ooo
  if 55 - 55: i11iIiiIii / OoooooooOO - I11i
  if 89 - 89: I11i - i1IIi - i1IIi * OOooOOo - O0
LISP_DDT_ACTION_SITE_NOT_FOUND = - 2
LISP_DDT_ACTION_NULL = - 1
LISP_DDT_ACTION_NODE_REFERRAL = 0
LISP_DDT_ACTION_MS_REFERRAL = 1
LISP_DDT_ACTION_MS_ACK = 2
LISP_DDT_ACTION_MS_NOT_REG = 3
LISP_DDT_ACTION_DELEGATION_HOLE = 4
LISP_DDT_ACTION_NOT_AUTH = 5
LISP_DDT_ACTION_MAX = LISP_DDT_ACTION_NOT_AUTH
if 94 - 94: Oo0Ooo / I11i . I1ii11iIi11i
lisp_map_referral_action_string = [
 "node-referral" , "ms-referral" , "ms-ack" , "ms-not-registered" ,
 "delegation-hole" , "not-authoritative" ]
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
if 39 - 39: I1ii11iIi11i / i11iIiiIii * i1IIi * Oo0Ooo
if 39 - 39: OoO0O00 * OoooooooOO / i1IIi + Oo0Ooo
if 57 - 57: O0
if 83 - 83: OOooOOo / Ii1I * I1IiiI % oO0o / iIii1I11I1II1
if 1 - 1: I11i / OoooooooOO / iII111i
if 68 - 68: i1IIi / Oo0Ooo / I11i * Oo0Ooo
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
  if 91 - 91: OoO0O00 . iII111i
  if 82 - 82: I1ii11iIi11i / Oo0Ooo
 def print_info ( self ) :
  if ( self . info_reply ) :
   oooO0 = "Info-Reply"
   i1IIIIi1Ii111 = ( ", ms-port: {}, etr-port: {}, global-rloc: {}, " + "ms-rloc: {}, private-rloc: {}, RTR-list: " ) . format ( self . ms_port , self . etr_port ,
   # ooOoO0o + oO0o * iII111i * ooOoO0o
   # I1Ii111 * IiII * OoO0O00 / I1Ii111
 red ( self . global_etr_rloc . print_address_no_iid ( ) , False ) ,
 red ( self . global_ms_rloc . print_address_no_iid ( ) , False ) ,
 red ( self . private_etr_rloc . print_address_no_iid ( ) , False ) )
   if ( len ( self . rtr_list ) == 0 ) : i1IIIIi1Ii111 += "empty, "
   for ooo0O in self . rtr_list :
    i1IIIIi1Ii111 += red ( ooo0O . print_address_no_iid ( ) , False ) + ", "
    if 5 - 5: o0oOOo0O0Ooo % Ii1I . Ii1I
   i1IIIIi1Ii111 = i1IIIIi1Ii111 [ 0 : - 2 ]
  else :
   oooO0 = "Info-Request"
   iI111III = "<none>" if self . hostname == None else self . hostname
   i1IIIIi1Ii111 = ", hostname: {}" . format ( blue ( iI111III , False ) )
   if 97 - 97: oO0o - i11iIiiIii / I11i
  lprint ( "{} -> nonce: 0x{}{}" . format ( bold ( oooO0 , False ) ,
 lisp_hex_string ( self . nonce ) , i1IIIIi1Ii111 ) )
  if 46 - 46: IiII - OoO0O00 * iII111i . I1Ii111 - ooOoO0o . i1IIi
  if 53 - 53: I1Ii111 * I1IiiI + Oo0Ooo + I1IiiI + OOooOOo
 def encode ( self ) :
  O0ooOo0Oooo = ( LISP_NAT_INFO << 28 )
  if ( self . info_reply ) : O0ooOo0Oooo |= ( 1 << 27 )
  if 8 - 8: i11iIiiIii + OoOoOO00 . I1ii11iIi11i / OoooooooOO % II111iiii
  if 21 - 21: oO0o - o0oOOo0O0Ooo + ooOoO0o . I1IiiI * oO0o * Ii1I
  if 41 - 41: i1IIi % i11iIiiIii + I11i % OoooooooOO / I1ii11iIi11i
  if 8 - 8: OoooooooOO - OoO0O00 / i11iIiiIii / O0 . IiII
  if 86 - 86: ooOoO0o * OoooooooOO + iII111i + o0oOOo0O0Ooo
  iI1IIII1ii1 = struct . pack ( "I" , socket . htonl ( O0ooOo0Oooo ) )
  iI1IIII1ii1 += struct . pack ( "Q" , self . nonce )
  iI1IIII1ii1 += struct . pack ( "III" , 0 , 0 , 0 )
  if 79 - 79: i1IIi % I1ii11iIi11i - OoO0O00 % I1ii11iIi11i
  if 6 - 6: Oo0Ooo / iII111i . i11iIiiIii
  if 8 - 8: I1ii11iIi11i + O0 - oO0o % II111iiii . I1Ii111
  if 86 - 86: IiII
  if ( self . info_reply == False ) :
   if ( self . hostname == None ) :
    iI1IIII1ii1 += struct . pack ( "H" , 0 )
   else :
    iI1IIII1ii1 += struct . pack ( "H" , socket . htons ( LISP_AFI_NAME ) )
    iI1IIII1ii1 += self . hostname + "\0"
    if 71 - 71: Ii1I - i1IIi . I1IiiI
   return ( iI1IIII1ii1 )
   if 15 - 15: i1IIi % II111iiii / II111iiii - I1ii11iIi11i - I11i % i1IIi
   if 54 - 54: i1IIi . OoO0O00 + iII111i + OoO0O00 * i1IIi
   if 13 - 13: Oo0Ooo / OoO0O00 + OOooOOo
   if 90 - 90: OoO0O00 * i11iIiiIii / oO0o
   if 91 - 91: iII111i - OoOoOO00 / Oo0Ooo % II111iiii / II111iiii / o0oOOo0O0Ooo
  ooOooOooOOO = socket . htons ( LISP_AFI_LCAF )
  O00OO0oOOO = LISP_LCAF_NAT_TYPE
  ii111 = socket . htons ( 16 )
  IIIi1i1iIIIi = socket . htons ( self . ms_port )
  oOOoOoooOo0o = socket . htons ( self . etr_port )
  iI1IIII1ii1 += struct . pack ( "HHBBHHHH" , ooOooOooOOO , 0 , O00OO0oOOO , 0 , ii111 ,
 IIIi1i1iIIIi , oOOoOoooOo0o , socket . htons ( self . global_etr_rloc . afi ) )
  iI1IIII1ii1 += self . global_etr_rloc . pack_address ( )
  iI1IIII1ii1 += struct . pack ( "HH" , 0 , socket . htons ( self . private_etr_rloc . afi ) )
  iI1IIII1ii1 += self . private_etr_rloc . pack_address ( )
  if ( len ( self . rtr_list ) == 0 ) : iI1IIII1ii1 += struct . pack ( "H" , 0 )
  if 59 - 59: i11iIiiIii - I11i * Oo0Ooo % o0oOOo0O0Ooo + i1IIi
  if 30 - 30: ooOoO0o / iII111i
  if 66 - 66: ooOoO0o / IiII * iIii1I11I1II1
  if 42 - 42: I1Ii111 - i11iIiiIii % II111iiii * ooOoO0o . O0 % I11i
  for ooo0O in self . rtr_list :
   iI1IIII1ii1 += struct . pack ( "H" , socket . htons ( ooo0O . afi ) )
   iI1IIII1ii1 += ooo0O . pack_address ( )
   if 82 - 82: Oo0Ooo % O0 + I1ii11iIi11i % I1ii11iIi11i
  return ( iI1IIII1ii1 )
  if 74 - 74: O0 * IiII . I11i - I1Ii111 + O0 + I11i
  if 48 - 48: oO0o . o0oOOo0O0Ooo - OOooOOo
 def decode ( self , packet ) :
  O0ooO00OO = packet
  oOO0OOOoO0ooo = "I"
  I1111ii1i = struct . calcsize ( oOO0OOOoO0ooo )
  if ( len ( packet ) < I1111ii1i ) : return ( None )
  if 29 - 29: Oo0Ooo - Ii1I - Oo0Ooo
  O0ooOo0Oooo = struct . unpack ( oOO0OOOoO0ooo , packet [ : I1111ii1i ] )
  O0ooOo0Oooo = O0ooOo0Oooo [ 0 ]
  packet = packet [ I1111ii1i : : ]
  if 89 - 89: Oo0Ooo . OoO0O00 . I1ii11iIi11i * oO0o . O0
  oOO0OOOoO0ooo = "Q"
  I1111ii1i = struct . calcsize ( oOO0OOOoO0ooo )
  if ( len ( packet ) < I1111ii1i ) : return ( None )
  if 72 - 72: i11iIiiIii % I11i / I1Ii111 + I1IiiI * iII111i
  iIiIi1i1Iiii = struct . unpack ( oOO0OOOoO0ooo , packet [ : I1111ii1i ] )
  if 69 - 69: I1Ii111 + O0 . IiII . o0oOOo0O0Ooo
  O0ooOo0Oooo = socket . ntohl ( O0ooOo0Oooo )
  self . nonce = iIiIi1i1Iiii [ 0 ]
  self . info_reply = O0ooOo0Oooo & 0x08000000
  self . hostname = None
  packet = packet [ I1111ii1i : : ]
  if 38 - 38: IiII / i1IIi
  if 60 - 60: OoOoOO00
  if 75 - 75: II111iiii / iIii1I11I1II1 / OoooooooOO
  if 61 - 61: IiII . IiII
  if 17 - 17: OoOoOO00 % Oo0Ooo / I1Ii111 . Ii1I % OoO0O00
  oOO0OOOoO0ooo = "HH"
  I1111ii1i = struct . calcsize ( oOO0OOOoO0ooo )
  if ( len ( packet ) < I1111ii1i ) : return ( None )
  if 32 - 32: I1IiiI + ooOoO0o / O0 * i11iIiiIii % Oo0Ooo + II111iiii
  if 95 - 95: iII111i / ooOoO0o + I1Ii111
  if 78 - 78: iIii1I11I1II1 / I1IiiI - IiII
  if 81 - 81: I1ii11iIi11i
  if 31 - 31: O0 % ooOoO0o / I1IiiI * iII111i % iIii1I11I1II1 * OoOoOO00
  I1 , O0o0O00 = struct . unpack ( oOO0OOOoO0ooo , packet [ : I1111ii1i ] )
  if ( O0o0O00 != 0 ) : return ( None )
  if 76 - 76: I1Ii111 - O0
  packet = packet [ I1111ii1i : : ]
  oOO0OOOoO0ooo = "IBBH"
  I1111ii1i = struct . calcsize ( oOO0OOOoO0ooo )
  if ( len ( packet ) < I1111ii1i ) : return ( None )
  if 23 - 23: O0 * Ii1I * ooOoO0o % ooOoO0o
  iiI , oOoo , ii11i1 , II1111 = struct . unpack ( oOO0OOOoO0ooo ,
 packet [ : I1111ii1i ] )
  if 74 - 74: O0
  if ( II1111 != 0 ) : return ( None )
  packet = packet [ I1111ii1i : : ]
  if 32 - 32: O0 / I11i . O0
  if 25 - 25: Oo0Ooo - iII111i
  if 96 - 96: O0 . I1IiiI
  if 2 - 2: I11i . oO0o * IiII
  if ( self . info_reply == False ) :
   oOO0OOOoO0ooo = "H"
   I1111ii1i = struct . calcsize ( oOO0OOOoO0ooo )
   if ( len ( packet ) >= I1111ii1i ) :
    ooOooOooOOO = struct . unpack ( oOO0OOOoO0ooo , packet [ : I1111ii1i ] ) [ 0 ]
    if ( socket . ntohs ( ooOooOooOOO ) == LISP_AFI_NAME ) :
     packet = packet [ I1111ii1i : : ]
     packet , self . hostname = lisp_decode_dist_name ( packet )
     if 41 - 41: Ii1I / OoO0O00 / OoO0O00 * I11i
     if 31 - 31: Ii1I / OoooooooOO % iIii1I11I1II1 - IiII * I1IiiI - O0
   return ( O0ooO00OO )
   if 31 - 31: oO0o
   if 74 - 74: OoO0O00
   if 11 - 11: oO0o + O0 % Ii1I . I11i * o0oOOo0O0Ooo
   if 14 - 14: I11i . iIii1I11I1II1 + I1Ii111 % OoooooooOO
   if 9 - 9: oO0o + Ii1I / I1ii11iIi11i * iIii1I11I1II1 + o0oOOo0O0Ooo
  oOO0OOOoO0ooo = "HHBBHHH"
  I1111ii1i = struct . calcsize ( oOO0OOOoO0ooo )
  if ( len ( packet ) < I1111ii1i ) : return ( None )
  if 64 - 64: I11i % i11iIiiIii % I1ii11iIi11i
  ooOooOooOOO , oOOooOOO , O00OO0oOOO , oOoo , ii111 , IIIi1i1iIIIi , oOOoOoooOo0o = struct . unpack ( oOO0OOOoO0ooo , packet [ : I1111ii1i ] )
  if 14 - 14: I1Ii111 - OoOoOO00 - I1ii11iIi11i % I11i + OoooooooOO
  if 4 - 4: I1Ii111 - I1IiiI / iIii1I11I1II1 + I1ii11iIi11i % iIii1I11I1II1 * I1IiiI
  if ( socket . ntohs ( ooOooOooOOO ) != LISP_AFI_LCAF ) : return ( None )
  if 30 - 30: i11iIiiIii % OOooOOo
  self . ms_port = socket . ntohs ( IIIi1i1iIIIi )
  self . etr_port = socket . ntohs ( oOOoOoooOo0o )
  packet = packet [ I1111ii1i : : ]
  if 52 - 52: I11i - oO0o . i11iIiiIii - II111iiii + Ii1I . iII111i
  if 27 - 27: I1IiiI + OoOoOO00 + iII111i
  if 70 - 70: I11i + IiII . ooOoO0o - I1ii11iIi11i
  if 34 - 34: i1IIi % Oo0Ooo . oO0o
  oOO0OOOoO0ooo = "H"
  I1111ii1i = struct . calcsize ( oOO0OOOoO0ooo )
  if ( len ( packet ) < I1111ii1i ) : return ( None )
  if 36 - 36: I1ii11iIi11i / I1Ii111 - IiII + OOooOOo + I1Ii111
  if 62 - 62: Oo0Ooo . OoO0O00 * I1Ii111 . i11iIiiIii * O0
  if 10 - 10: Oo0Ooo / OoOoOO00 * OOooOOo - IiII + Ii1I
  if 62 - 62: I1IiiI . Ii1I
  ooOooOooOOO = struct . unpack ( oOO0OOOoO0ooo , packet [ : I1111ii1i ] ) [ 0 ]
  packet = packet [ I1111ii1i : : ]
  if ( ooOooOooOOO != 0 ) :
   self . global_etr_rloc . afi = socket . ntohs ( ooOooOooOOO )
   packet = self . global_etr_rloc . unpack_address ( packet )
   if ( packet == None ) : return ( None )
   self . global_etr_rloc . mask_len = self . global_etr_rloc . host_mask_len ( )
   if 74 - 74: Ii1I - I11i % ooOoO0o - I1IiiI - Ii1I - II111iiii
   if 81 - 81: i1IIi * I1ii11iIi11i + IiII - OoO0O00 * i1IIi
   if 6 - 6: iIii1I11I1II1 % OoOoOO00 % II111iiii % o0oOOo0O0Ooo
   if 52 - 52: Ii1I - I1IiiI * iIii1I11I1II1 % Oo0Ooo * OOooOOo
   if 67 - 67: OoooooooOO * I11i * Ii1I * iIii1I11I1II1
   if 22 - 22: OoO0O00 / o0oOOo0O0Ooo
  if ( len ( packet ) < I1111ii1i ) : return ( O0ooO00OO )
  if 35 - 35: I1Ii111 / I1Ii111 + o0oOOo0O0Ooo - oO0o
  ooOooOooOOO = struct . unpack ( oOO0OOOoO0ooo , packet [ : I1111ii1i ] ) [ 0 ]
  packet = packet [ I1111ii1i : : ]
  if ( ooOooOooOOO != 0 ) :
   self . global_ms_rloc . afi = socket . ntohs ( ooOooOooOOO )
   packet = self . global_ms_rloc . unpack_address ( packet )
   if ( packet == None ) : return ( O0ooO00OO )
   self . global_ms_rloc . mask_len = self . global_ms_rloc . host_mask_len ( )
   if 40 - 40: OoOoOO00 - II111iiii
   if 29 - 29: I1IiiI - O0
   if 36 - 36: I1IiiI * I1IiiI
   if 79 - 79: I1Ii111 - I11i
   if 49 - 49: II111iiii + O0 * ooOoO0o - Oo0Ooo
  if ( len ( packet ) < I1111ii1i ) : return ( O0ooO00OO )
  if 89 - 89: I1IiiI + I11i . oO0o . II111iiii + oO0o / Oo0Ooo
  ooOooOooOOO = struct . unpack ( oOO0OOOoO0ooo , packet [ : I1111ii1i ] ) [ 0 ]
  packet = packet [ I1111ii1i : : ]
  if ( ooOooOooOOO != 0 ) :
   self . private_etr_rloc . afi = socket . ntohs ( ooOooOooOOO )
   packet = self . private_etr_rloc . unpack_address ( packet )
   if ( packet == None ) : return ( O0ooO00OO )
   self . private_etr_rloc . mask_len = self . private_etr_rloc . host_mask_len ( )
   if 32 - 32: OoO0O00 % oO0o * I1ii11iIi11i + I11i / I1Ii111
   if 5 - 5: o0oOOo0O0Ooo + iII111i / OoooooooOO + Ii1I . OoOoOO00 / oO0o
   if 18 - 18: II111iiii . o0oOOo0O0Ooo
   if 75 - 75: OoooooooOO - Oo0Ooo
   if 56 - 56: II111iiii - i11iIiiIii - oO0o . o0oOOo0O0Ooo
   if 4 - 4: i1IIi
  while ( len ( packet ) >= I1111ii1i ) :
   ooOooOooOOO = struct . unpack ( oOO0OOOoO0ooo , packet [ : I1111ii1i ] ) [ 0 ]
   packet = packet [ I1111ii1i : : ]
   if ( ooOooOooOOO == 0 ) : continue
   ooo0O = lisp_address ( socket . ntohs ( ooOooOooOOO ) , "" , 0 , 0 )
   packet = ooo0O . unpack_address ( packet )
   if ( packet == None ) : return ( O0ooO00OO )
   ooo0O . mask_len = ooo0O . host_mask_len ( )
   self . rtr_list . append ( ooo0O )
   if 91 - 91: IiII . OoO0O00 * Ii1I / o0oOOo0O0Ooo
  return ( O0ooO00OO )
  if 41 - 41: I1IiiI . OoO0O00 / i1IIi . Oo0Ooo . oO0o
  if 44 - 44: iII111i * I11i + i11iIiiIii + i1IIi / IiII * II111iiii
  if 58 - 58: OOooOOo
class lisp_nat_info ( ) :
 def __init__ ( self , addr_str , hostname , port ) :
  self . address = addr_str
  self . hostname = hostname
  self . port = port
  self . uptime = lisp_get_timestamp ( )
  if 72 - 72: OoO0O00 + OOooOOo - Oo0Ooo % ooOoO0o . IiII
  if 95 - 95: iII111i % OOooOOo - IiII - OoOoOO00 % o0oOOo0O0Ooo * O0
 def timed_out ( self ) :
  ooooOoO0O = time . time ( ) - self . uptime
  return ( ooooOoO0O >= ( LISP_INFO_INTERVAL * 2 ) )
  if 16 - 16: I1Ii111 / Oo0Ooo
  if 48 - 48: Oo0Ooo / oO0o + iII111i % iII111i
  if 9 - 9: I1ii11iIi11i - o0oOOo0O0Ooo . Oo0Ooo + I1ii11iIi11i . OOooOOo
class lisp_info_source ( ) :
 def __init__ ( self , hostname , addr_str , port ) :
  self . address = lisp_address ( LISP_AFI_IPV4 , addr_str , 32 , 0 )
  self . port = port
  self . uptime = lisp_get_timestamp ( )
  self . nonce = None
  self . hostname = hostname
  self . no_timeout = False
  if 30 - 30: OoooooooOO - iIii1I11I1II1 / oO0o * Ii1I / Ii1I
  if 52 - 52: OoOoOO00 - OoO0O00 + I1IiiI + IiII
 def cache_address_for_info_source ( self ) :
  i1IIiI1iII = self . address . print_address_no_iid ( ) + self . hostname
  lisp_info_sources_by_address [ i1IIiI1iII ] = self
  if 49 - 49: oO0o / I11i - oO0o
  if 31 - 31: OoOoOO00 + I1IiiI + I1ii11iIi11i + I11i * II111iiii % oO0o
 def cache_nonce_for_info_source ( self , nonce ) :
  self . nonce = nonce
  lisp_info_sources_by_nonce [ nonce ] = self
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
def lisp_concat_auth_data ( alg_id , auth1 , auth2 , auth3 , auth4 ) :
 if 83 - 83: O0
 if ( lisp_is_x86 ( ) ) :
  if ( auth1 != "" ) : auth1 = byte_swap_64 ( auth1 )
  if ( auth2 != "" ) : auth2 = byte_swap_64 ( auth2 )
  if ( auth3 != "" ) :
   if ( alg_id == LISP_SHA_1_96_ALG_ID ) : auth3 = socket . ntohl ( auth3 )
   else : auth3 = byte_swap_64 ( auth3 )
   if 35 - 35: i11iIiiIii - I11i . OoOoOO00 * II111iiii % i11iIiiIii
  if ( auth4 != "" ) : auth4 = byte_swap_64 ( auth4 )
  if 55 - 55: o0oOOo0O0Ooo / O0 / OoooooooOO * Oo0Ooo % iII111i
  if 24 - 24: I1ii11iIi11i % OOooOOo + OoooooooOO + OoO0O00
 if ( alg_id == LISP_SHA_1_96_ALG_ID ) :
  auth1 = lisp_hex_string ( auth1 )
  auth1 = auth1 . zfill ( 16 )
  auth2 = lisp_hex_string ( auth2 )
  auth2 = auth2 . zfill ( 16 )
  auth3 = lisp_hex_string ( auth3 )
  auth3 = auth3 . zfill ( 8 )
  oOi1IiIiIii11I = auth1 + auth2 + auth3
  if 100 - 100: Oo0Ooo % OoO0O00 - OoOoOO00
 if ( alg_id == LISP_SHA_256_128_ALG_ID ) :
  auth1 = lisp_hex_string ( auth1 )
  auth1 = auth1 . zfill ( 16 )
  auth2 = lisp_hex_string ( auth2 )
  auth2 = auth2 . zfill ( 16 )
  auth3 = lisp_hex_string ( auth3 )
  auth3 = auth3 . zfill ( 16 )
  auth4 = lisp_hex_string ( auth4 )
  auth4 = auth4 . zfill ( 16 )
  oOi1IiIiIii11I = auth1 + auth2 + auth3 + auth4
  if 46 - 46: o0oOOo0O0Ooo
 return ( oOi1IiIiIii11I )
 if 28 - 28: i1IIi
 if 81 - 81: oO0o % OoooooooOO . I1Ii111 - OoOoOO00 / I1IiiI
 if 62 - 62: I1Ii111 * I11i / I11i
 if 42 - 42: ooOoO0o * ooOoO0o / Ii1I / OOooOOo * OOooOOo
 if 92 - 92: Oo0Ooo / iII111i - OoooooooOO - o0oOOo0O0Ooo % ooOoO0o
 if 35 - 35: i1IIi % iII111i % I11i * iIii1I11I1II1 % Ii1I - Oo0Ooo
 if 94 - 94: iII111i
 if 68 - 68: OoooooooOO % OOooOOo / OoooooooOO / I1Ii111 + Ii1I - o0oOOo0O0Ooo
 if 81 - 81: I1IiiI
 if 62 - 62: Ii1I * OoOoOO00
def lisp_open_listen_socket ( local_addr , port ) :
 if ( port . isdigit ( ) ) :
  if ( local_addr . find ( "." ) != - 1 ) :
   IIiI1io0O = socket . socket ( socket . AF_INET , socket . SOCK_DGRAM )
   if 86 - 86: i1IIi + OoooooooOO * OOooOOo * i1IIi . oO0o % iIii1I11I1II1
  if ( local_addr . find ( ":" ) != - 1 ) :
   if ( lisp_is_raspbian ( ) ) : return ( None )
   IIiI1io0O = socket . socket ( socket . AF_INET6 , socket . SOCK_DGRAM )
   if 60 - 60: OoO0O00 * O0 / Ii1I
  IIiI1io0O . bind ( ( local_addr , int ( port ) ) )
 else :
  iI11i1Ii = port
  if ( os . path . exists ( iI11i1Ii ) ) :
   os . system ( "rm " + iI11i1Ii )
   time . sleep ( 1 )
   if 28 - 28: Oo0Ooo . i11iIiiIii . O0
  IIiI1io0O = socket . socket ( socket . AF_UNIX , socket . SOCK_DGRAM )
  IIiI1io0O . bind ( iI11i1Ii )
  if 67 - 67: II111iiii / O0
 return ( IIiI1io0O )
 if 10 - 10: i1IIi / Oo0Ooo
 if 20 - 20: Oo0Ooo * I1Ii111 / I1ii11iIi11i . ooOoO0o
 if 67 - 67: o0oOOo0O0Ooo . Oo0Ooo % I11i
 if 38 - 38: OOooOOo - OoO0O00 . ooOoO0o
 if 50 - 50: o0oOOo0O0Ooo
 if 85 - 85: II111iiii . iII111i - i1IIi
 if 23 - 23: iII111i . Ii1I - OoO0O00 / I1ii11iIi11i / O0
def lisp_open_send_socket ( internal_name , afi ) :
 if ( internal_name == "" ) :
  if ( afi == LISP_AFI_IPV4 ) :
   IIiI1io0O = socket . socket ( socket . AF_INET , socket . SOCK_DGRAM )
   if 4 - 4: i1IIi % Oo0Ooo % Ii1I * ooOoO0o - I11i
  if ( afi == LISP_AFI_IPV6 ) :
   if ( lisp_is_raspbian ( ) ) : return ( None )
   IIiI1io0O = socket . socket ( socket . AF_INET6 , socket . SOCK_DGRAM )
   if 76 - 76: iIii1I11I1II1 / ooOoO0o % I1ii11iIi11i % OOooOOo
 else :
  if ( os . path . exists ( internal_name ) ) : os . system ( "rm " + internal_name )
  IIiI1io0O = socket . socket ( socket . AF_UNIX , socket . SOCK_DGRAM )
  IIiI1io0O . bind ( internal_name )
  if 13 - 13: IiII
 return ( IIiI1io0O )
 if 56 - 56: Oo0Ooo
 if 55 - 55: i11iIiiIii + iIii1I11I1II1 / i1IIi / I1ii11iIi11i
 if 64 - 64: IiII . OoO0O00 * i11iIiiIii
 if 18 - 18: Ii1I % o0oOOo0O0Ooo - Oo0Ooo
 if 28 - 28: IiII
 if 93 - 93: Oo0Ooo % i1IIi
 if 51 - 51: oO0o % O0
def lisp_close_socket ( sock , internal_name ) :
 sock . close ( )
 if ( os . path . exists ( internal_name ) ) : os . system ( "rm " + internal_name )
 return
 if 41 - 41: I1IiiI * I1IiiI . I1Ii111
 if 38 - 38: I1IiiI % i11iIiiIii
 if 17 - 17: i11iIiiIii
 if 81 - 81: I1Ii111
 if 25 - 25: I1IiiI
 if 52 - 52: I1ii11iIi11i % i1IIi . IiII % OoOoOO00
 if 50 - 50: OOooOOo * I1IiiI / o0oOOo0O0Ooo
 if 91 - 91: iIii1I11I1II1 / OOooOOo * O0 . o0oOOo0O0Ooo + oO0o / I1ii11iIi11i
def lisp_is_running ( node ) :
 return ( True if ( os . path . exists ( node ) ) else False )
 if 33 - 33: II111iiii + Ii1I
 if 46 - 46: IiII + O0 + i1IIi + ooOoO0o / iII111i
 if 94 - 94: oO0o + iII111i * OoOoOO00 - i1IIi / OoooooooOO
 if 59 - 59: I11i % Ii1I / OoOoOO00
 if 99 - 99: Ii1I + II111iiii / i11iIiiIii - IiII / iII111i + iII111i
 if 55 - 55: IiII + OoooooooOO * I1ii11iIi11i . IiII * I1ii11iIi11i + IiII
 if 81 - 81: iIii1I11I1II1 . ooOoO0o + OoOoOO00
 if 31 - 31: I11i / OoOoOO00 + o0oOOo0O0Ooo
 if 80 - 80: Oo0Ooo
def lisp_packet_ipc ( packet , source , sport ) :
 return ( ( "packet@" + str ( len ( packet ) ) + "@" + source + "@" + str ( sport ) + "@" + packet ) )
 if 58 - 58: I1Ii111 + OOooOOo
 if 76 - 76: II111iiii - o0oOOo0O0Ooo % OoO0O00 + iII111i
 if 38 - 38: I1Ii111 - I11i * i1IIi + iIii1I11I1II1
 if 41 - 41: Ii1I . OoO0O00 + I1ii11iIi11i + OoOoOO00
 if 76 - 76: iII111i - iIii1I11I1II1
 if 23 - 23: I11i / OoO0O00 % OOooOOo
 if 9 - 9: ooOoO0o % I1ii11iIi11i . OoooooooOO + OoO0O00 % OOooOOo * OoooooooOO
 if 21 - 21: Ii1I % O0
 if 15 - 15: II111iiii * Ii1I + IiII % iII111i
def lisp_control_packet_ipc ( packet , source , dest , dport ) :
 return ( "control-packet@" + dest + "@" + str ( dport ) + "@" + packet )
 if 96 - 96: II111iiii * I1Ii111 / Oo0Ooo
 if 35 - 35: I1IiiI
 if 54 - 54: I1ii11iIi11i % o0oOOo0O0Ooo . i1IIi
 if 72 - 72: Ii1I
 if 87 - 87: iII111i - I1IiiI
 if 54 - 54: iIii1I11I1II1 + oO0o * o0oOOo0O0Ooo % OoooooooOO . Oo0Ooo
 if 32 - 32: iII111i
def lisp_data_packet_ipc ( packet , source ) :
 return ( "data-packet@" + str ( len ( packet ) ) + "@" + source + "@@" + packet )
 if 33 - 33: ooOoO0o + Oo0Ooo * OoOoOO00 % ooOoO0o * oO0o - OoO0O00
 if 40 - 40: I11i . OoooooooOO * O0 / I1Ii111 + O0
 if 97 - 97: ooOoO0o - ooOoO0o * OOooOOo % OoOoOO00 - OoOoOO00 - I1Ii111
 if 52 - 52: O0 % iII111i
 if 81 - 81: OoooooooOO % OoOoOO00 % Oo0Ooo - I1IiiI
 if 43 - 43: o0oOOo0O0Ooo % o0oOOo0O0Ooo
 if 48 - 48: O0
 if 5 - 5: OOooOOo / i11iIiiIii . I11i % OOooOOo
 if 1 - 1: II111iiii + O0 * OoOoOO00 / IiII . O0
def lisp_command_ipc ( packet , source ) :
 return ( "command@" + str ( len ( packet ) ) + "@" + source + "@@" + packet )
 if 87 - 87: IiII + I1IiiI
 if 74 - 74: OoO0O00 + OoO0O00 % iII111i / I11i / O0
 if 54 - 54: o0oOOo0O0Ooo / OoooooooOO * ooOoO0o . OoOoOO00 - I1Ii111
 if 69 - 69: oO0o - OoO0O00
 if 80 - 80: ooOoO0o + iIii1I11I1II1 . II111iiii + I1IiiI - oO0o % OoOoOO00
 if 10 - 10: iIii1I11I1II1
 if 44 - 44: OoOoOO00 * oO0o . I1ii11iIi11i + i11iIiiIii
 if 85 - 85: I11i
 if 36 - 36: ooOoO0o % OoO0O00
def lisp_api_ipc ( source , data ) :
 return ( "api@" + str ( len ( data ) ) + "@" + source + "@@" + data )
 if 1 - 1: OoooooooOO - OoOoOO00
 if 35 - 35: I1Ii111
 if 35 - 35: Oo0Ooo - iIii1I11I1II1 / i1IIi + OoO0O00 - OoooooooOO / i11iIiiIii
 if 79 - 79: I1IiiI * ooOoO0o * ooOoO0o
 if 92 - 92: iII111i % I1ii11iIi11i
 if 16 - 16: oO0o
 if 52 - 52: OoooooooOO % ooOoO0o - I1Ii111 * I11i
 if 24 - 24: Ii1I + IiII + OoooooooOO / oO0o / I1IiiI + IiII
 if 52 - 52: ooOoO0o
def lisp_ipc ( packet , send_socket , node ) :
 if 38 - 38: OoO0O00 + I1IiiI % IiII
 if 87 - 87: oO0o * Ii1I - I1Ii111 / oO0o
 if 65 - 65: OoOoOO00
 if 87 - 87: I11i - i11iIiiIii - OOooOOo . OoOoOO00 + IiII . OoO0O00
 if ( lisp_is_running ( node ) == False ) :
  lprint ( "Suppress sending IPC to {}" . format ( node ) )
  return
  if 70 - 70: iIii1I11I1II1 % OoooooooOO / OoO0O00 . O0 - I11i % II111iiii
  if 84 - 84: OOooOOo * i1IIi . iIii1I11I1II1 * iII111i + I1Ii111 + II111iiii
 o00OOoOo = 1500 if ( packet . find ( "control-packet" ) == - 1 ) else 9000
 if 98 - 98: II111iiii * OoooooooOO % oO0o - iII111i
 oOO0OO0O = 0
 I1I1 = len ( packet )
 OOO00 = 0
 o0ooO0 = .001
 while ( I1I1 > 0 ) :
  oOo0oOO0OO0 = min ( I1I1 , o00OOoOo )
  IiII11iIi = packet [ oOO0OO0O : oOo0oOO0OO0 + oOO0OO0O ]
  if 93 - 93: OoO0O00 / OoOoOO00
  try :
   send_socket . sendto ( IiII11iIi , node )
   lprint ( "Send IPC {}-out-of-{} byte to {} succeeded" . format ( len ( IiII11iIi ) , len ( packet ) , node ) )
   if 15 - 15: OoO0O00 . iII111i * I1ii11iIi11i / I1IiiI - i1IIi
   OOO00 = 0
   o0ooO0 = .001
   if 58 - 58: IiII / OOooOOo % Ii1I * OOooOOo
  except socket . error , I1i11II :
   if ( OOO00 == 12 ) :
    lprint ( "Giving up on {}, consider it down" . format ( node ) )
    break
    if 18 - 18: I1IiiI % iII111i / iII111i
    if 10 - 10: OoOoOO00 . II111iiii
   lprint ( "Send IPC {}-out-of-{} byte to {} failed: {}" . format ( len ( IiII11iIi ) , len ( packet ) , node , I1i11II ) )
   if 25 - 25: O0 % OoO0O00 * OoooooooOO . OoOoOO00 / oO0o / o0oOOo0O0Ooo
   if 20 - 20: i1IIi . I1IiiI + i11iIiiIii . iIii1I11I1II1 / O0
   OOO00 += 1
   time . sleep ( o0ooO0 )
   if 3 - 3: Oo0Ooo + OoOoOO00 - ooOoO0o % ooOoO0o / O0
   lprint ( "Retrying after {} ms ..." . format ( o0ooO0 * 1000 ) )
   o0ooO0 *= 2
   continue
   if 16 - 16: OOooOOo % Oo0Ooo * I1ii11iIi11i . iII111i . iIii1I11I1II1 * i1IIi
   if 81 - 81: OoOoOO00
  oOO0OO0O += oOo0oOO0OO0
  I1I1 -= oOo0oOO0OO0
  if 52 - 52: iII111i * IiII % I1IiiI * I11i
 return
 if 73 - 73: I1Ii111 * ooOoO0o
 if 62 - 62: OOooOOo . I1IiiI * iIii1I11I1II1 + OoO0O00 * ooOoO0o / oO0o
 if 14 - 14: iII111i / OoO0O00
 if 75 - 75: IiII
 if 68 - 68: IiII - i1IIi % IiII . OoO0O00 . i11iIiiIii . OoooooooOO
 if 32 - 32: iII111i + OoO0O00 % IiII + I1IiiI
 if 69 - 69: I1Ii111 + I11i - iIii1I11I1II1 - II111iiii . Ii1I
def lisp_format_packet ( packet ) :
 packet = binascii . hexlify ( packet )
 oOO0OO0O = 0
 IIi1i1iI11I11 = ""
 I1I1 = len ( packet ) * 2
 while ( oOO0OO0O < I1I1 ) :
  IIi1i1iI11I11 += packet [ oOO0OO0O : oOO0OO0O + 8 ] + " "
  oOO0OO0O += 8
  I1I1 -= 4
  if 74 - 74: I1ii11iIi11i % o0oOOo0O0Ooo + O0 - i11iIiiIii - IiII % OOooOOo
 return ( IIi1i1iI11I11 )
 if 39 - 39: OoO0O00 - o0oOOo0O0Ooo
 if 71 - 71: iII111i . OoO0O00 + ooOoO0o - OOooOOo - Oo0Ooo
 if 100 - 100: OoooooooOO - o0oOOo0O0Ooo + I1Ii111 . OoooooooOO % i11iIiiIii
 if 64 - 64: I1Ii111 % OoooooooOO / i1IIi / OoO0O00
 if 2 - 2: I11i % o0oOOo0O0Ooo . OoO0O00 . OoO0O00
 if 89 - 89: ooOoO0o - oO0o + II111iiii + OoO0O00 - IiII
 if 27 - 27: I1Ii111 - o0oOOo0O0Ooo + OoO0O00
def lisp_send ( lisp_sockets , dest , port , packet ) :
 IIiIIi = lisp_sockets [ 0 ] if dest . is_ipv4 ( ) else lisp_sockets [ 1 ]
 if 67 - 67: i1IIi % I1Ii111 / i11iIiiIii . OoO0O00 - I1ii11iIi11i
 if 15 - 15: o0oOOo0O0Ooo . OoO0O00 * i1IIi % I11i % OoOoOO00
 if 25 - 25: OoOoOO00 . iIii1I11I1II1 - iII111i % II111iiii . OoOoOO00
 if 16 - 16: OOooOOo . Oo0Ooo . I1IiiI % O0 . I1ii11iIi11i + i11iIiiIii
 if 100 - 100: I1ii11iIi11i - i1IIi - OoO0O00 * o0oOOo0O0Ooo + OoOoOO00
 if 31 - 31: i1IIi
 if 21 - 21: o0oOOo0O0Ooo / O0 % O0 . OoooooooOO / I1IiiI
 if 94 - 94: ooOoO0o + OoO0O00 / ooOoO0o - ooOoO0o + Oo0Ooo + o0oOOo0O0Ooo
 if 50 - 50: oO0o . Oo0Ooo
 if 15 - 15: Ii1I
 if 64 - 64: OoooooooOO
 if 25 - 25: IiII
 oOOOOO0Ooooo = dest . print_address_no_iid ( )
 if ( oOOOOO0Ooooo . find ( "::ffff:" ) != - 1 and oOOOOO0Ooooo . count ( "." ) == 3 ) :
  if ( lisp_i_am_rtr ) : IIiIIi = lisp_sockets [ 0 ]
  if ( IIiIIi == None ) :
   IIiIIi = lisp_sockets [ 0 ]
   oOOOOO0Ooooo = oOOOOO0Ooooo . split ( "::ffff:" ) [ - 1 ]
   if 29 - 29: OoOoOO00 % ooOoO0o * OoooooooOO
   if 8 - 8: i11iIiiIii - I1Ii111 / IiII
   if 17 - 17: i11iIiiIii * OoO0O00 . o0oOOo0O0Ooo . OoooooooOO . OoOoOO00 - I1ii11iIi11i
 lprint ( "{} {} bytes {} {}, packet: {}" . format ( bold ( "Send" , False ) ,
 len ( packet ) , bold ( "to " + oOOOOO0Ooooo , False ) , port ,
 lisp_format_packet ( packet ) ) )
 if 78 - 78: I1ii11iIi11i - OoooooooOO + O0
 if 15 - 15: I1ii11iIi11i / IiII % I1IiiI
 if 16 - 16: Ii1I
 if 26 - 26: o0oOOo0O0Ooo / I11i + OoOoOO00 / OoOoOO00
 i111ii1I111Ii = ( LISP_RLOC_PROBE_TTL == 255 )
 if ( i111ii1I111Ii ) :
  oo0O0000O00 = struct . unpack ( "B" , packet [ 0 ] ) [ 0 ]
  i111ii1I111Ii = ( oo0O0000O00 in [ 0x12 , 0x28 ] )
  if ( i111ii1I111Ii ) : lisp_set_ttl ( IIiIIi , LISP_RLOC_PROBE_TTL )
  if 38 - 38: IiII - OoO0O00 % Ii1I - II111iiii
  if 97 - 97: O0 . Ii1I
 try : IIiIIi . sendto ( packet , ( oOOOOO0Ooooo , port ) )
 except socket . error , I1i11II :
  lprint ( "socket.sendto() failed: {}" . format ( I1i11II ) )
  if 52 - 52: IiII
  if 86 - 86: I1Ii111 / O0 + OoooooooOO % oO0o
  if 45 - 45: I1IiiI . Oo0Ooo . I11i . Ii1I
  if 81 - 81: II111iiii + OoOoOO00 % i11iIiiIii / iII111i . I1Ii111 + II111iiii
  if 48 - 48: I1IiiI . I1ii11iIi11i * OoOoOO00 % i1IIi / I1Ii111 * II111iiii
 if ( i111ii1I111Ii ) : lisp_set_ttl ( IIiIIi , 64 )
 return
 if 62 - 62: o0oOOo0O0Ooo * I1Ii111 . iIii1I11I1II1 / i1IIi
 if 75 - 75: OoooooooOO / ooOoO0o - iII111i . OoooooooOO . OoOoOO00 % i1IIi
 if 7 - 7: OoOoOO00 . i1IIi * i11iIiiIii % i11iIiiIii
 if 54 - 54: OoO0O00 / I1IiiI . Oo0Ooo
 if 39 - 39: OoO0O00 . ooOoO0o
 if 41 - 41: Oo0Ooo * I1ii11iIi11i - II111iiii - II111iiii
 if 7 - 7: oO0o
 if 41 - 41: ooOoO0o
def lisp_receive_segments ( lisp_socket , packet , source , total_length ) :
 if 93 - 93: Ii1I + I1Ii111 + Ii1I
 if 23 - 23: I1IiiI - i1IIi / ooOoO0o
 if 4 - 4: IiII . I1ii11iIi11i + iII111i % ooOoO0o
 if 28 - 28: I1Ii111
 if 27 - 27: iII111i * I1IiiI
 oOo0oOO0OO0 = total_length - len ( packet )
 if ( oOo0oOO0OO0 == 0 ) : return ( [ True , packet ] )
 if 60 - 60: i1IIi / I1IiiI - I1ii11iIi11i
 lprint ( "Received {}-out-of-{} byte segment from {}" . format ( len ( packet ) ,
 total_length , source ) )
 if 41 - 41: I1Ii111 + ooOoO0o / OOooOOo + I11i % Oo0Ooo
 if 91 - 91: I1IiiI % I1ii11iIi11i % oO0o / i1IIi * iIii1I11I1II1 + I11i
 if 48 - 48: ooOoO0o / I1ii11iIi11i / OoO0O00 / II111iiii * OoOoOO00
 if 73 - 73: I11i / I1IiiI - IiII - i1IIi * IiII - OOooOOo
 if 39 - 39: I11i . ooOoO0o * II111iiii
 I1I1 = oOo0oOO0OO0
 while ( I1I1 > 0 ) :
  try : IiII11iIi = lisp_socket . recvfrom ( 9000 )
  except : return ( [ False , None ] )
  if 21 - 21: Ii1I
  IiII11iIi = IiII11iIi [ 0 ]
  if 92 - 92: OoO0O00 * I1ii11iIi11i + iIii1I11I1II1
  if 88 - 88: iIii1I11I1II1 + iIii1I11I1II1 * i11iIiiIii . I1ii11iIi11i % oO0o
  if 94 - 94: I1IiiI / I1ii11iIi11i / OOooOOo
  if 45 - 45: II111iiii
  if 98 - 98: i11iIiiIii + I1ii11iIi11i * OOooOOo / OoOoOO00
  if ( IiII11iIi . find ( "packet@" ) == 0 ) :
   oO0OooO0 = IiII11iIi . split ( "@" )
   lprint ( "Received new message ({}-out-of-{}) while receiving " + "fragments, old message discarded" , len ( IiII11iIi ) ,
   # i11iIiiIii
 oO0OooO0 [ 1 ] if len ( oO0OooO0 ) > 2 else "?" )
   return ( [ False , IiII11iIi ] )
   if 93 - 93: i11iIiiIii . ooOoO0o . iII111i
   if 67 - 67: I1IiiI . O0 . OoooooooOO - II111iiii / Ii1I
  I1I1 -= len ( IiII11iIi )
  packet += IiII11iIi
  if 63 - 63: O0 . i11iIiiIii / o0oOOo0O0Ooo % OOooOOo
  lprint ( "Received {}-out-of-{} byte segment from {}" . format ( len ( IiII11iIi ) , total_length , source ) )
  if 20 - 20: Oo0Ooo - O0 - ooOoO0o % iII111i * OoOoOO00 * OoooooooOO
  if 94 - 94: II111iiii
 return ( [ True , packet ] )
 if 27 - 27: OOooOOo
 if 95 - 95: oO0o - I1Ii111 + Oo0Ooo
 if 32 - 32: iIii1I11I1II1 - ooOoO0o . o0oOOo0O0Ooo
 if 88 - 88: i1IIi
 if 9 - 9: II111iiii + O0 + ooOoO0o - i11iIiiIii / OoooooooOO
 if 27 - 27: oO0o
 if 61 - 61: I1Ii111 / O0 - iII111i
 if 44 - 44: i1IIi
def lisp_bit_stuff ( payload ) :
 lprint ( "Bit-stuffing, found {} segments" . format ( len ( payload ) ) )
 iI1IIII1ii1 = ""
 for IiII11iIi in payload : iI1IIII1ii1 += IiII11iIi + "\x40"
 return ( iI1IIII1ii1 [ : - 1 ] )
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
 if 98 - 98: iII111i / IiII * I1IiiI / oO0o - iIii1I11I1II1
 if 72 - 72: O0 . OOooOOo
 if 99 - 99: i1IIi + iIii1I11I1II1 - ooOoO0o + OoO0O00 + Oo0Ooo . I1ii11iIi11i
 if 74 - 74: i1IIi
 if 80 - 80: ooOoO0o + I1Ii111 . I1ii11iIi11i % OoooooooOO
 if 26 - 26: OoOoOO00 . iII111i * iIii1I11I1II1 / IiII
 if 69 - 69: OoooooooOO / I11i + Ii1I * II111iiii
 if 35 - 35: i11iIiiIii + oO0o
 if 85 - 85: OoOoOO00 . O0 % OoooooooOO % oO0o
 if 43 - 43: I1IiiI - I11i . I1IiiI / i11iIiiIii % IiII * i11iIiiIii
def lisp_receive ( lisp_socket , internal ) :
 while ( True ) :
  if 12 - 12: II111iiii - iIii1I11I1II1
  if 43 - 43: i11iIiiIii % OoO0O00
  if 100 - 100: i1IIi
  if 4 - 4: i11iIiiIii - OOooOOo * IiII % OoooooooOO - OoOoOO00
  try : O0o0oO00oO0OO = lisp_socket . recvfrom ( 9000 )
  except : return ( [ "" , "" , "" , "" ] )
  if 56 - 56: i1IIi / II111iiii * II111iiii / Oo0Ooo * OoO0O00
  if 27 - 27: o0oOOo0O0Ooo . I11i / I1ii11iIi11i
  if 10 - 10: OoO0O00 . I1Ii111 . OoooooooOO % iIii1I11I1II1 . O0
  if 36 - 36: oO0o . iII111i
  if 62 - 62: I11i + iIii1I11I1II1 % I11i * OOooOOo + iIii1I11I1II1 % Ii1I
  if 56 - 56: o0oOOo0O0Ooo
  if ( internal == False ) :
   iI1IIII1ii1 = O0o0oO00oO0OO [ 0 ]
   IIi1IiIii = lisp_convert_6to4 ( O0o0oO00oO0OO [ 1 ] [ 0 ] )
   OOo0000o0 = O0o0oO00oO0OO [ 1 ] [ 1 ]
   if 18 - 18: OoooooooOO * Ii1I + O0
   if ( OOo0000o0 == LISP_DATA_PORT ) :
    Oo00O0OoooO = lisp_data_plane_logging
    oo00 = lisp_format_packet ( iI1IIII1ii1 [ 0 : 60 ] ) + " ..."
   else :
    Oo00O0OoooO = True
    oo00 = lisp_format_packet ( iI1IIII1ii1 )
    if 54 - 54: Ii1I . iII111i + Ii1I + I1IiiI * I1Ii111
    if 18 - 18: ooOoO0o / OOooOOo / I11i / OoooooooOO - Ii1I / I1ii11iIi11i
   if ( Oo00O0OoooO ) :
    lprint ( "{} {} bytes {} {}, packet: {}" . format ( bold ( "Receive" ,
 False ) , len ( iI1IIII1ii1 ) , bold ( "from " + IIi1IiIii , False ) , OOo0000o0 ,
 oo00 ) )
    if 45 - 45: ooOoO0o - OOooOOo . Ii1I
   return ( [ "packet" , IIi1IiIii , OOo0000o0 , iI1IIII1ii1 ] )
   if 99 - 99: I11i / OoOoOO00 % OoO0O00 * Ii1I / OOooOOo
   if 9 - 9: ooOoO0o - ooOoO0o * I1ii11iIi11i
   if 92 - 92: Ii1I
   if 88 - 88: OoooooooOO * i1IIi % I1ii11iIi11i % Oo0Ooo
   if 1 - 1: OoO0O00 / iIii1I11I1II1 % I1ii11iIi11i - o0oOOo0O0Ooo
   if 62 - 62: I1Ii111 % II111iiii
  O0O0O00oo0 = False
  O0OooO0oo = O0o0oO00oO0OO [ 0 ]
  i1o0000oOO00 = False
  if 52 - 52: Ii1I . i1IIi / Oo0Ooo - i1IIi
  while ( O0O0O00oo0 == False ) :
   O0OooO0oo = O0OooO0oo . split ( "@" )
   if 72 - 72: i11iIiiIii . I1ii11iIi11i / ooOoO0o - I1Ii111 * II111iiii - II111iiii
   if ( len ( O0OooO0oo ) < 4 ) :
    lprint ( "Possible fragment (length {}), from old message, " + "discarding" , len ( O0OooO0oo [ 0 ] ) )
    if 47 - 47: IiII - iIii1I11I1II1 / OoOoOO00 * iII111i - iIii1I11I1II1 % oO0o
    i1o0000oOO00 = True
    break
    if 93 - 93: Ii1I / iII111i
    if 100 - 100: Oo0Ooo
   OO0oo0Oo00OOO = O0OooO0oo [ 0 ]
   try :
    I1iI = int ( O0OooO0oo [ 1 ] )
   except :
    oo000O0 = bold ( "Internal packet reassembly error" , False )
    lprint ( "{}: {}" . format ( oo000O0 , O0o0oO00oO0OO ) )
    i1o0000oOO00 = True
    break
    if 22 - 22: O0 - OoOoOO00 % O0 * oO0o * OOooOOo / oO0o
   IIi1IiIii = O0OooO0oo [ 2 ]
   OOo0000o0 = O0OooO0oo [ 3 ]
   if 1 - 1: I1ii11iIi11i / OoooooooOO . I1IiiI % i11iIiiIii
   if 91 - 91: I1IiiI - I1IiiI * Ii1I
   if 73 - 73: ooOoO0o % I1Ii111
   if 69 - 69: OoOoOO00 / OOooOOo / I1IiiI
   if 12 - 12: I1ii11iIi11i . iIii1I11I1II1 . II111iiii . OoOoOO00
   if 30 - 30: i11iIiiIii / Oo0Ooo / OOooOOo + i11iIiiIii * ooOoO0o
   if 4 - 4: O0 + I1IiiI + I1Ii111
   if 80 - 80: Ii1I % OoooooooOO . i1IIi - OOooOOo
   if ( len ( O0OooO0oo ) > 5 ) :
    iI1IIII1ii1 = lisp_bit_stuff ( O0OooO0oo [ 4 : : ] )
   else :
    iI1IIII1ii1 = O0OooO0oo [ 4 ]
    if 10 - 10: I11i + iII111i % OoO0O00 / OoO0O00
    if 91 - 91: ooOoO0o . oO0o
    if 66 - 66: II111iiii + OOooOOo + i11iIiiIii / II111iiii
    if 37 - 37: I1IiiI + OoO0O00 . OoO0O00 % OoOoOO00 + o0oOOo0O0Ooo
    if 81 - 81: i1IIi % iIii1I11I1II1
    if 41 - 41: oO0o - iII111i / o0oOOo0O0Ooo . iII111i % Oo0Ooo + OOooOOo
   O0O0O00oo0 , iI1IIII1ii1 = lisp_receive_segments ( lisp_socket , iI1IIII1ii1 ,
 IIi1IiIii , I1iI )
   if ( iI1IIII1ii1 == None ) : return ( [ "" , "" , "" , "" ] )
   if 82 - 82: ooOoO0o
   if 89 - 89: OOooOOo / I1ii11iIi11i . I1IiiI + i11iIiiIii
   if 11 - 11: oO0o . i11iIiiIii * ooOoO0o % OoooooooOO % O0
   if 59 - 59: i11iIiiIii / OoO0O00
   if 48 - 48: iIii1I11I1II1
   if ( O0O0O00oo0 == False ) :
    O0OooO0oo = iI1IIII1ii1
    continue
    if 19 - 19: oO0o
    if 69 - 69: I1ii11iIi11i % iII111i - OoooooooOO % Ii1I * oO0o
   if ( OOo0000o0 == "" ) : OOo0000o0 = "no-port"
   if ( OO0oo0Oo00OOO == "command" and lisp_i_am_core == False ) :
    OOOoO000 = iI1IIII1ii1 . find ( " {" )
    IIi1i1IIIiIi = iI1IIII1ii1 if OOOoO000 == - 1 else iI1IIII1ii1 [ : OOOoO000 ]
    IIi1i1IIIiIi = ": '" + IIi1i1IIIiIi + "'"
   else :
    IIi1i1IIIiIi = ""
    if 29 - 29: o0oOOo0O0Ooo + Ii1I * I1Ii111 * O0
    if 20 - 20: OOooOOo
   lprint ( "{} {} bytes {} {}, {}{}" . format ( bold ( "Receive" , False ) ,
 len ( iI1IIII1ii1 ) , bold ( "from " + IIi1IiIii , False ) , OOo0000o0 , OO0oo0Oo00OOO ,
 IIi1i1IIIiIi if ( OO0oo0Oo00OOO in [ "command" , "api" ] ) else ": ... " if ( OO0oo0Oo00OOO == "data-packet" ) else ": " + lisp_format_packet ( iI1IIII1ii1 ) ) )
   if 84 - 84: O0 . OoO0O00 * O0 - OoO0O00 / OoO0O00
   if 51 - 51: II111iiii % OoO0O00
   if 85 - 85: i11iIiiIii % iII111i + II111iiii
   if 16 - 16: ooOoO0o * OoOoOO00 / OoOoOO00 + II111iiii
   if 50 - 50: OoO0O00 / OOooOOo % I1IiiI / Ii1I + OoO0O00 . iIii1I11I1II1
  if ( i1o0000oOO00 ) : continue
  return ( [ OO0oo0Oo00OOO , IIi1IiIii , OOo0000o0 , iI1IIII1ii1 ] )
  if 62 - 62: I1Ii111 + OoooooooOO - Ii1I - iIii1I11I1II1
  if 80 - 80: OoO0O00
  if 72 - 72: II111iiii % i11iIiiIii + OoOoOO00 / I1Ii111 - i11iIiiIii
  if 39 - 39: i11iIiiIii - OOooOOo / OoO0O00 * OoOoOO00 / IiII
  if 84 - 84: I1ii11iIi11i . iIii1I11I1II1 / Ii1I / II111iiii
  if 56 - 56: OOooOOo * iII111i / Ii1I
  if 9 - 9: I1ii11iIi11i * i11iIiiIii / I1Ii111 + iIii1I11I1II1
  if 1 - 1: OoO0O00 % iIii1I11I1II1 * OoOoOO00 / oO0o
def lisp_parse_packet ( lisp_sockets , packet , source , udp_sport , ttl = - 1 ) :
 oooOOOOO0Oo = False
 if 9 - 9: ooOoO0o
 IIiiIiIIiI1 = lisp_control_header ( )
 if ( IIiiIiIIiI1 . decode ( packet ) == None ) :
  lprint ( "Could not decode control header" )
  return ( oooOOOOO0Oo )
  if 10 - 10: i11iIiiIii - O0 % I1ii11iIi11i . I11i + i11iIiiIii . I1IiiI
  if 29 - 29: I1Ii111 % OOooOOo / OoooooooOO
  if 9 - 9: I1Ii111 / I1Ii111 + OoOoOO00 % OOooOOo - IiII - I1IiiI
  if 24 - 24: IiII / I11i * Ii1I / I1IiiI
  if 39 - 39: I11i - OoooooooOO % OoO0O00 / Ii1I . i1IIi
 I1i1iI1IiII = source
 if ( source . find ( "lisp" ) == - 1 ) :
  i1I1iIi1IiI = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  i1I1iIi1IiI . string_to_afi ( source )
  i1I1iIi1IiI . store_address ( source )
  source = i1I1iIi1IiI
  if 76 - 76: OOooOOo % o0oOOo0O0Ooo + I1Ii111 % i11iIiiIii % o0oOOo0O0Ooo
  if 35 - 35: OoOoOO00 % i11iIiiIii - II111iiii + o0oOOo0O0Ooo % O0
 if ( IIiiIiIIiI1 . type == LISP_MAP_REQUEST ) :
  lisp_process_map_request ( lisp_sockets , packet , None , 0 , source ,
 udp_sport , False , ttl )
  if 28 - 28: i1IIi - I1IiiI % II111iiii + i11iIiiIii
 elif ( IIiiIiIIiI1 . type == LISP_MAP_REPLY ) :
  lisp_process_map_reply ( lisp_sockets , packet , source , ttl )
  if 36 - 36: I1ii11iIi11i / I1ii11iIi11i
 elif ( IIiiIiIIiI1 . type == LISP_MAP_REGISTER ) :
  lisp_process_map_register ( lisp_sockets , packet , source , udp_sport )
  if 44 - 44: i1IIi + iIii1I11I1II1
 elif ( IIiiIiIIiI1 . type == LISP_MAP_NOTIFY ) :
  if ( I1i1iI1IiII == "lisp-etr" ) :
   lisp_process_multicast_map_notify ( packet , source )
  else :
   if ( lisp_is_running ( "lisp-rtr" ) ) :
    lisp_process_multicast_map_notify ( packet , source )
    if 45 - 45: iIii1I11I1II1 . O0 % Oo0Ooo % OOooOOo
   lisp_process_map_notify ( lisp_sockets , packet , source )
   if 8 - 8: OoO0O00 + I1ii11iIi11i - I1IiiI * i1IIi
   if 17 - 17: OoO0O00 % o0oOOo0O0Ooo
 elif ( IIiiIiIIiI1 . type == LISP_MAP_NOTIFY_ACK ) :
  lisp_process_map_notify_ack ( packet , source )
  if 21 - 21: OOooOOo + OOooOOo - i11iIiiIii * IiII % iIii1I11I1II1
 elif ( IIiiIiIIiI1 . type == LISP_MAP_REFERRAL ) :
  lisp_process_map_referral ( lisp_sockets , packet , source )
  if 86 - 86: ooOoO0o + OoOoOO00
 elif ( IIiiIiIIiI1 . type == LISP_NAT_INFO and IIiiIiIIiI1 . is_info_reply ( ) ) :
  oOOooOOO , OOo00o000oOO0 , oooOOOOO0Oo = lisp_process_info_reply ( source , packet , True )
  if 94 - 94: IiII
 elif ( IIiiIiIIiI1 . type == LISP_NAT_INFO and IIiiIiIIiI1 . is_info_reply ( ) == False ) :
  OoOOoooO000 = source . print_address_no_iid ( )
  lisp_process_info_request ( lisp_sockets , packet , OoOOoooO000 , udp_sport ,
 None )
  if 30 - 30: o0oOOo0O0Ooo % OoOoOO00 * IiII % iIii1I11I1II1 % O0
 elif ( IIiiIiIIiI1 . type == LISP_ECM ) :
  lisp_process_ecm ( lisp_sockets , packet , source , udp_sport )
  if 76 - 76: II111iiii * I11i
 else :
  lprint ( "Invalid LISP control packet type {}" . format ( IIiiIiIIiI1 . type ) )
  if 29 - 29: OoooooooOO . i1IIi
 return ( oooOOOOO0Oo )
 if 46 - 46: I11i
 if 92 - 92: IiII * OoO0O00 . OoOoOO00 + iII111i - I1IiiI
 if 15 - 15: OoO0O00 / OoO0O00 * o0oOOo0O0Ooo * I1ii11iIi11i - o0oOOo0O0Ooo
 if 47 - 47: I1IiiI / OoOoOO00 / II111iiii
 if 7 - 7: oO0o . ooOoO0o
 if 73 - 73: i1IIi % I1Ii111 * ooOoO0o % OoO0O00
 if 70 - 70: ooOoO0o * I1ii11iIi11i
def lisp_process_rloc_probe_request ( lisp_sockets , map_request , source , port ,
 ttl ) :
 if 26 - 26: i11iIiiIii - II111iiii . II111iiii * oO0o / Ii1I + I1IiiI
 o0O0o = bold ( "RLOC-probe" , False )
 if 12 - 12: OoO0O00 * iIii1I11I1II1 % I1Ii111 . O0 * OoOoOO00 * OOooOOo
 if ( lisp_i_am_etr ) :
  lprint ( "Received {} Map-Request, send RLOC-probe Map-Reply" . format ( o0O0o ) )
  lisp_etr_process_map_request ( lisp_sockets , map_request , source , port ,
 ttl )
  return
  if 34 - 34: I1IiiI . i1IIi
  if 38 - 38: iIii1I11I1II1
 if ( lisp_i_am_rtr ) :
  lprint ( "Received {} Map-Request, send RLOC-probe Map-Reply" . format ( o0O0o ) )
  lisp_rtr_process_map_request ( lisp_sockets , map_request , source , port ,
 ttl )
  return
  if 64 - 64: i1IIi / OoO0O00
  if 68 - 68: I11i * O0 * oO0o + OoOoOO00 / IiII
 lprint ( "Ignoring received {} Map-Request, not an ETR or RTR" . format ( o0O0o ) )
 return
 if 42 - 42: iIii1I11I1II1 % i1IIi - OoOoOO00 % I1ii11iIi11i * Ii1I + i11iIiiIii
 if 40 - 40: OOooOOo
 if 30 - 30: o0oOOo0O0Ooo - Oo0Ooo + iII111i / O0
 if 94 - 94: IiII
 if 69 - 69: I1Ii111 . I1Ii111
def lisp_process_smr ( map_request ) :
 lprint ( "Received SMR-based Map-Request" )
 return
 if 53 - 53: i11iIiiIii + iII111i * Oo0Ooo - I1Ii111
 if 61 - 61: o0oOOo0O0Ooo / OOooOOo . II111iiii - I1IiiI * i11iIiiIii
 if 8 - 8: iII111i % o0oOOo0O0Ooo
 if 87 - 87: Ii1I % I11i / I1Ii111
 if 21 - 21: OoO0O00 + Ii1I / I1Ii111
def lisp_process_smr_invoked_request ( map_request ) :
 lprint ( "Received SMR-invoked Map-Request" )
 return
 if 75 - 75: I1Ii111 . Ii1I % iIii1I11I1II1 / OoOoOO00
 if 38 - 38: i1IIi
 if 1 - 1: I1ii11iIi11i + OoO0O00 % I11i . OOooOOo + i1IIi / oO0o
 if 35 - 35: ooOoO0o % OoOoOO00 % OoO0O00 + OOooOOo / IiII * OoOoOO00
 if 65 - 65: I1IiiI . Oo0Ooo + i1IIi - Ii1I * i1IIi
 if 64 - 64: I1IiiI / OoO0O00 * I1IiiI * II111iiii . Ii1I
 if 98 - 98: I1Ii111 + o0oOOo0O0Ooo
def lisp_build_map_reply ( eid , group , rloc_set , nonce , action , ttl , rloc_probe ,
 keys , enc , auth , mr_ttl = - 1 ) :
 OOO0iI1 = lisp_map_reply ( )
 OOO0iI1 . rloc_probe = rloc_probe
 OOO0iI1 . echo_nonce_capable = enc
 OOO0iI1 . hop_count = 0 if ( mr_ttl == - 1 ) else mr_ttl
 OOO0iI1 . record_count = 1
 OOO0iI1 . nonce = nonce
 iI1IIII1ii1 = OOO0iI1 . encode ( )
 OOO0iI1 . print_map_reply ( )
 if 54 - 54: I1ii11iIi11i + IiII - oO0o + Oo0Ooo / IiII % Oo0Ooo
 I111IoOo0oOOO0o = lisp_eid_record ( )
 I111IoOo0oOOO0o . rloc_count = len ( rloc_set )
 I111IoOo0oOOO0o . authoritative = auth
 I111IoOo0oOOO0o . record_ttl = ttl
 I111IoOo0oOOO0o . action = action
 I111IoOo0oOOO0o . eid = eid
 I111IoOo0oOOO0o . group = group
 if 66 - 66: OOooOOo . I1IiiI / iII111i
 iI1IIII1ii1 += I111IoOo0oOOO0o . encode ( )
 I111IoOo0oOOO0o . print_record ( "  " , False )
 if 68 - 68: II111iiii . OoOoOO00
 Iii1i = lisp_get_all_addresses ( ) + lisp_get_all_translated_rlocs ( )
 if 96 - 96: iIii1I11I1II1 . o0oOOo0O0Ooo % Ii1I . iIii1I11I1II1
 for ii1I1i11 in rloc_set :
  i1iIiII = lisp_rloc_record ( )
  OoOOoooO000 = ii1I1i11 . rloc . print_address_no_iid ( )
  if ( OoOOoooO000 in Iii1i ) :
   i1iIiII . local_bit = True
   i1iIiII . probe_bit = rloc_probe
   i1iIiII . keys = keys
   if ( ii1I1i11 . priority == 254 and lisp_i_am_rtr ) :
    i1iIiII . rloc_name = "RTR"
    if 17 - 17: I1IiiI . oO0o + Oo0Ooo - I1ii11iIi11i % IiII
    if 36 - 36: oO0o - Oo0Ooo + IiII
  i1iIiII . store_rloc_entry ( ii1I1i11 )
  i1iIiII . reach_bit = True
  i1iIiII . print_record ( "    " )
  iI1IIII1ii1 += i1iIiII . encode ( )
  if 33 - 33: Oo0Ooo % oO0o - I1IiiI + Oo0Ooo
 return ( iI1IIII1ii1 )
 if 90 - 90: I1ii11iIi11i * I1Ii111 - iIii1I11I1II1 % IiII * I1Ii111 . I1Ii111
 if 90 - 90: o0oOOo0O0Ooo - O0 % O0 - oO0o . OoooooooOO
 if 30 - 30: I11i + O0 / Ii1I / OoOoOO00 - oO0o + II111iiii
 if 21 - 21: iIii1I11I1II1 % OoooooooOO * OOooOOo % i1IIi
 if 73 - 73: OoooooooOO
 if 100 - 100: I11i / i1IIi / i1IIi % Ii1I - II111iiii . OoooooooOO
 if 72 - 72: Oo0Ooo * OoooooooOO % I1IiiI + I11i - II111iiii
def lisp_build_map_referral ( eid , group , ddt_entry , action , ttl , nonce ) :
 Oo0oo = lisp_map_referral ( )
 Oo0oo . record_count = 1
 Oo0oo . nonce = nonce
 iI1IIII1ii1 = Oo0oo . encode ( )
 Oo0oo . print_map_referral ( )
 if 31 - 31: I1ii11iIi11i
 I111IoOo0oOOO0o = lisp_eid_record ( )
 if 60 - 60: i1IIi % ooOoO0o / II111iiii * Oo0Ooo - i1IIi . Ii1I
 OOOoo0ooooo0 = 0
 if ( ddt_entry == None ) :
  I111IoOo0oOOO0o . eid = eid
  I111IoOo0oOOO0o . group = group
 else :
  OOOoo0ooooo0 = len ( ddt_entry . delegation_set )
  I111IoOo0oOOO0o . eid = ddt_entry . eid
  I111IoOo0oOOO0o . group = ddt_entry . group
  ddt_entry . map_referrals_sent += 1
  if 21 - 21: i1IIi
 I111IoOo0oOOO0o . rloc_count = OOOoo0ooooo0
 I111IoOo0oOOO0o . authoritative = True
 if 10 - 10: i11iIiiIii / ooOoO0o - o0oOOo0O0Ooo . o0oOOo0O0Ooo
 if 8 - 8: iII111i + iIii1I11I1II1 . I1ii11iIi11i
 if 68 - 68: OoooooooOO . OoooooooOO % I1ii11iIi11i + i1IIi % OoooooooOO + Ii1I
 if 89 - 89: ooOoO0o + I11i * O0 % OoOoOO00
 if 2 - 2: I1Ii111 % iIii1I11I1II1 . Ii1I - II111iiii
 O0oOo00O = False
 if ( action == LISP_DDT_ACTION_NULL ) :
  if ( OOOoo0ooooo0 == 0 ) :
   action = LISP_DDT_ACTION_NODE_REFERRAL
  else :
   ooOiiI1Ii11 = ddt_entry . delegation_set [ 0 ]
   if ( ooOiiI1Ii11 . is_ddt_child ( ) ) :
    action = LISP_DDT_ACTION_NODE_REFERRAL
    if 33 - 33: I11i . i11iIiiIii % i1IIi * II111iiii * i11iIiiIii + OoOoOO00
   if ( ooOiiI1Ii11 . is_ms_child ( ) ) :
    action = LISP_DDT_ACTION_MS_REFERRAL
    if 26 - 26: I1IiiI % OoOoOO00 % I11i + Oo0Ooo
    if 86 - 86: iII111i / i1IIi % Oo0Ooo
    if 84 - 84: o0oOOo0O0Ooo * OOooOOo . I11i * Ii1I
    if 32 - 32: ooOoO0o % ooOoO0o * I1ii11iIi11i % Ii1I + Oo0Ooo . OoOoOO00
    if 2 - 2: I1Ii111 / ooOoO0o * oO0o + IiII
    if 14 - 14: OoOoOO00 / iIii1I11I1II1 . o0oOOo0O0Ooo % i11iIiiIii . OoOoOO00
    if 92 - 92: OoO0O00 . i1IIi
 if ( action == LISP_DDT_ACTION_NOT_AUTH ) : O0oOo00O = True
 if ( action in ( LISP_DDT_ACTION_MS_REFERRAL , LISP_DDT_ACTION_MS_ACK ) ) :
  O0oOo00O = ( lisp_i_am_ms and ooOiiI1Ii11 . is_ms_peer ( ) == False )
  if 22 - 22: Ii1I . I1IiiI
  if 54 - 54: OOooOOo / I1ii11iIi11i % oO0o
 I111IoOo0oOOO0o . action = action
 I111IoOo0oOOO0o . ddt_incomplete = O0oOo00O
 I111IoOo0oOOO0o . record_ttl = ttl
 if 66 - 66: I11i + iII111i
 iI1IIII1ii1 += I111IoOo0oOOO0o . encode ( )
 I111IoOo0oOOO0o . print_record ( "  " , True )
 if 50 - 50: IiII
 if ( OOOoo0ooooo0 == 0 ) : return ( iI1IIII1ii1 )
 if 33 - 33: OOooOOo % I1IiiI - I1IiiI / IiII
 for ooOiiI1Ii11 in ddt_entry . delegation_set :
  i1iIiII = lisp_rloc_record ( )
  i1iIiII . rloc = ooOiiI1Ii11 . delegate_address
  i1iIiII . priority = ooOiiI1Ii11 . priority
  i1iIiII . weight = ooOiiI1Ii11 . weight
  i1iIiII . mpriority = 255
  i1iIiII . mweight = 0
  i1iIiII . reach_bit = True
  iI1IIII1ii1 += i1iIiII . encode ( )
  i1iIiII . print_record ( "    " )
  if 22 - 22: ooOoO0o * ooOoO0o % o0oOOo0O0Ooo * Ii1I . OoO0O00
 return ( iI1IIII1ii1 )
 if 55 - 55: OoOoOO00 - I1ii11iIi11i + iIii1I11I1II1 - i11iIiiIii / i1IIi / II111iiii
 if 37 - 37: Ii1I + o0oOOo0O0Ooo
 if 74 - 74: Oo0Ooo / O0 + i1IIi . I1IiiI + OoO0O00 / Oo0Ooo
 if 13 - 13: o0oOOo0O0Ooo / Ii1I . II111iiii
 if 8 - 8: I11i - I11i % IiII
 if 8 - 8: I1IiiI . IiII * O0 * o0oOOo0O0Ooo
 if 17 - 17: I1IiiI . oO0o + Oo0Ooo + I11i / o0oOOo0O0Ooo
def lisp_etr_process_map_request ( lisp_sockets , map_request , source , sport ,
 ttl ) :
 if 25 - 25: iII111i / iII111i % OoOoOO00 / ooOoO0o
 if ( map_request . target_group . is_null ( ) ) :
  o0Oo00OOOo00 = lisp_db_for_lookups . lookup_cache ( map_request . target_eid , False )
 else :
  o0Oo00OOOo00 = lisp_db_for_lookups . lookup_cache ( map_request . target_group , False )
  if ( o0Oo00OOOo00 ) : o0Oo00OOOo00 = o0Oo00OOOo00 . lookup_source_cache ( map_request . target_eid , False )
  if 10 - 10: iIii1I11I1II1 - iIii1I11I1II1 + o0oOOo0O0Ooo / OoOoOO00 % iIii1I11I1II1 / O0
 oo0ooooO = map_request . print_prefix ( )
 if 86 - 86: IiII + Ii1I / Oo0Ooo / O0 % iII111i - oO0o
 if ( o0Oo00OOOo00 == None ) :
  lprint ( "Database-mapping entry not found for requested EID {}" . format ( green ( oo0ooooO , False ) ) )
  if 3 - 3: i11iIiiIii / I1ii11iIi11i % I1Ii111 + o0oOOo0O0Ooo + O0
  return
  if 42 - 42: IiII / i11iIiiIii % o0oOOo0O0Ooo / II111iiii / IiII
  if 97 - 97: OOooOOo . OoOoOO00 / I11i - IiII - iIii1I11I1II1
 Oo0OooI11IIIiiiI = o0Oo00OOOo00 . print_eid_tuple ( )
 if 94 - 94: I11i * ooOoO0o . I1IiiI / Ii1I - I1IiiI % OoooooooOO
 lprint ( "Found database-mapping EID-prefix {} for requested EID {}" . format ( green ( Oo0OooI11IIIiiiI , False ) , green ( oo0ooooO , False ) ) )
 if 32 - 32: OoO0O00
 if 22 - 22: II111iiii . I11i
 if 61 - 61: OOooOOo % O0 . I1ii11iIi11i . iIii1I11I1II1 * I11i
 if 29 - 29: ooOoO0o + i1IIi % IiII * Ii1I
 if 94 - 94: OOooOOo / IiII
 I1i11111i = map_request . itr_rlocs [ 0 ]
 if ( I1i11111i . is_private_address ( ) and lisp_nat_traversal ) :
  I1i11111i = source
  if 22 - 22: OoOoOO00 - Oo0Ooo
  if 41 - 41: iIii1I11I1II1 * I1Ii111 / OoO0O00
 iIiIi1i1Iiii = map_request . nonce
 i1iiIi1 = lisp_nonce_echoing
 II1i = map_request . keys
 if 99 - 99: ooOoO0o * OOooOOo * I1ii11iIi11i - I11i . I11i . iIii1I11I1II1
 o0Oo00OOOo00 . map_replies_sent += 1
 if 99 - 99: I1IiiI
 iI1IIII1ii1 = lisp_build_map_reply ( o0Oo00OOOo00 . eid , o0Oo00OOOo00 . group , o0Oo00OOOo00 . rloc_set , iIiIi1i1Iiii ,
 LISP_NO_ACTION , 1440 , map_request . rloc_probe , II1i , i1iiIi1 , True , ttl )
 if 41 - 41: O0 % iIii1I11I1II1
 if 59 - 59: I1ii11iIi11i . I1IiiI + I1IiiI % I1Ii111
 if 22 - 22: o0oOOo0O0Ooo % OOooOOo - I11i + ooOoO0o / OOooOOo
 if 98 - 98: I11i * O0 + IiII - oO0o
 if 35 - 35: OoooooooOO * Ii1I
 if 73 - 73: ooOoO0o . OoO0O00 % I1ii11iIi11i - oO0o
 if 67 - 67: o0oOOo0O0Ooo . I11i + i1IIi
 if 100 - 100: Oo0Ooo - I1IiiI . OOooOOo % iIii1I11I1II1 . I11i
 if 83 - 83: OoOoOO00 * iII111i
 if 75 - 75: i11iIiiIii . o0oOOo0O0Ooo / oO0o . OoO0O00 % Ii1I % Ii1I
 if ( map_request . rloc_probe and len ( lisp_sockets ) == 4 ) :
  oO00o0 = ( I1i11111i . is_private_address ( ) == False )
  ooo0O = I1i11111i . print_address_no_iid ( )
  if ( oO00o0 and lisp_rtr_list . has_key ( ooo0O ) ) :
   lisp_encapsulate_rloc_probe ( lisp_sockets , I1i11111i , None , iI1IIII1ii1 )
   return
   if 94 - 94: iII111i . Ii1I
   if 71 - 71: o0oOOo0O0Ooo * II111iiii / OOooOOo . OoO0O00
   if 73 - 73: I1Ii111 * OoO0O00 / OoOoOO00 . II111iiii
   if 87 - 87: OoO0O00 + Oo0Ooo + O0 % OoooooooOO - iIii1I11I1II1
   if 100 - 100: Oo0Ooo + IiII
   if 81 - 81: iIii1I11I1II1 + iIii1I11I1II1
 lisp_send_map_reply ( lisp_sockets , iI1IIII1ii1 , I1i11111i , sport )
 return
 if 19 - 19: ooOoO0o + i1IIi / Oo0Ooo * II111iiii * I1Ii111 / ooOoO0o
 if 23 - 23: I1Ii111
 if 76 - 76: Ii1I + Ii1I / i1IIi % o0oOOo0O0Ooo . iIii1I11I1II1 . OoOoOO00
 if 75 - 75: I11i . Ii1I / I1ii11iIi11i
 if 99 - 99: Ii1I
 if 85 - 85: I1Ii111 + I1Ii111 + OoOoOO00 / ooOoO0o / o0oOOo0O0Ooo . Oo0Ooo
 if 41 - 41: i1IIi % Ii1I . i1IIi * OoooooooOO % Ii1I
def lisp_rtr_process_map_request ( lisp_sockets , map_request , source , sport ,
 ttl ) :
 if 21 - 21: iII111i
 if 72 - 72: I11i % o0oOOo0O0Ooo . iIii1I11I1II1 - I1Ii111 / i11iIiiIii
 if 75 - 75: OoooooooOO
 if 24 - 24: oO0o % iII111i - II111iiii / Ii1I + O0
 I1i11111i = map_request . itr_rlocs [ 0 ]
 if ( I1i11111i . is_private_address ( ) ) : I1i11111i = source
 iIiIi1i1Iiii = map_request . nonce
 if 37 - 37: I1Ii111 - i1IIi / iIii1I11I1II1
 i1OO0o = map_request . target_eid
 Oo000o0o0 = map_request . target_group
 if 53 - 53: Ii1I - iIii1I11I1II1 % I1ii11iIi11i * i11iIiiIii + ooOoO0o
 oOo0oOOOoOoo = [ ]
 for III1IIIi1 in [ lisp_myrlocs [ 0 ] , lisp_myrlocs [ 1 ] ] :
  if ( III1IIIi1 == None ) : continue
  i1IIIIi1Ii111 = lisp_rloc ( )
  i1IIIIi1Ii111 . rloc . copy_address ( III1IIIi1 )
  i1IIIIi1Ii111 . priority = 254
  oOo0oOOOoOoo . append ( i1IIIIi1Ii111 )
  if 14 - 14: iII111i / oO0o . oO0o - OOooOOo * i1IIi - i1IIi
  if 70 - 70: OoooooooOO
 i1iiIi1 = lisp_nonce_echoing
 II1i = map_request . keys
 if 60 - 60: OOooOOo - Ii1I * Ii1I
 iI1IIII1ii1 = lisp_build_map_reply ( i1OO0o , Oo000o0o0 , oOo0oOOOoOoo , iIiIi1i1Iiii , LISP_NO_ACTION ,
 1440 , True , II1i , i1iiIi1 , True , ttl )
 lisp_send_map_reply ( lisp_sockets , iI1IIII1ii1 , I1i11111i , sport )
 return
 if 69 - 69: i11iIiiIii . IiII + o0oOOo0O0Ooo % Ii1I - OoO0O00
 if 46 - 46: OoOoOO00 + iII111i * o0oOOo0O0Ooo - I1ii11iIi11i / oO0o + IiII
 if 1 - 1: iIii1I11I1II1 / OoooooooOO + Oo0Ooo . Ii1I
 if 25 - 25: I1ii11iIi11i / i1IIi * oO0o - II111iiii * i1IIi
 if 57 - 57: OoO0O00 % OoO0O00
 if 67 - 67: O0 . i11iIiiIii + iIii1I11I1II1
 if 86 - 86: iIii1I11I1II1
 if 81 - 81: OOooOOo / I11i / OoooooooOO
 if 74 - 74: I11i + OoooooooOO % II111iiii % o0oOOo0O0Ooo
 if 27 - 27: OoO0O00 * Oo0Ooo
def lisp_get_private_rloc_set ( target_site_eid , seid , group ) :
 oOo0oOOOoOoo = target_site_eid . registered_rlocs
 if 80 - 80: i11iIiiIii . OoO0O00 - I11i % I11i
 Ii1 = lisp_site_eid_lookup ( seid , group , False )
 if ( Ii1 == None ) : return ( oOo0oOOOoOoo )
 if 45 - 45: oO0o * OoOoOO00 / Oo0Ooo + O0 * ooOoO0o
 if 80 - 80: i11iIiiIii - O0 / I1Ii111 + OOooOOo % Oo0Ooo
 if 95 - 95: II111iiii
 if 76 - 76: OoO0O00 % iII111i * OoOoOO00 / ooOoO0o / i1IIi
 I1O0o = None
 iiiI11II1IiIi = [ ]
 for ii1I1i11 in oOo0oOOOoOoo :
  if ( ii1I1i11 . is_rtr ( ) ) : continue
  if ( ii1I1i11 . rloc . is_private_address ( ) ) :
   iIIII1iiIII = copy . deepcopy ( ii1I1i11 )
   iiiI11II1IiIi . append ( iIIII1iiIII )
   continue
   if 68 - 68: ooOoO0o % OoooooooOO
  I1O0o = ii1I1i11
  break
  if 94 - 94: Oo0Ooo * o0oOOo0O0Ooo
 if ( I1O0o == None ) : return ( oOo0oOOOoOoo )
 I1O0o = I1O0o . rloc . print_address_no_iid ( )
 if 60 - 60: iII111i . OOooOOo
 if 39 - 39: O0 - i11iIiiIii - I1IiiI / Oo0Ooo - i11iIiiIii
 if 30 - 30: OoO0O00 / OoOoOO00 + I1ii11iIi11i % IiII - OoO0O00
 if 19 - 19: I1IiiI
 o000OOO0 = None
 for ii1I1i11 in Ii1 . registered_rlocs :
  if ( ii1I1i11 . is_rtr ( ) ) : continue
  if ( ii1I1i11 . rloc . is_private_address ( ) ) : continue
  o000OOO0 = ii1I1i11
  break
  if 8 - 8: i11iIiiIii - iIii1I11I1II1 % i1IIi - i1IIi
 if ( o000OOO0 == None ) : return ( oOo0oOOOoOoo )
 o000OOO0 = o000OOO0 . rloc . print_address_no_iid ( )
 if 14 - 14: OOooOOo % iII111i . I1IiiI - i11iIiiIii
 if 87 - 87: IiII + OoooooooOO
 if 52 - 52: IiII
 if 4 - 4: Oo0Ooo / OoOoOO00
 O0Oo = target_site_eid . site_id
 if ( O0Oo == 0 ) :
  if ( o000OOO0 == I1O0o ) :
   lprint ( "Return private RLOCs for sites behind {}" . format ( I1O0o ) )
   if 97 - 97: Oo0Ooo
   return ( iiiI11II1IiIi )
   if 6 - 6: O0 - I1ii11iIi11i / OoooooooOO - Ii1I + Oo0Ooo
  return ( oOo0oOOOoOoo )
  if 88 - 88: OOooOOo - I1ii11iIi11i % iII111i
  if 58 - 58: OoO0O00 . O0 - i11iIiiIii . I1IiiI
  if 95 - 95: OoooooooOO / ooOoO0o * I11i - Ii1I
  if 94 - 94: I1Ii111 + OoO0O00 . OoooooooOO
  if 60 - 60: Ii1I . II111iiii
  if 36 - 36: IiII . iII111i * O0 . i1IIi * O0 * I1Ii111
  if 50 - 50: OoooooooOO + o0oOOo0O0Ooo + iIii1I11I1II1 + OOooOOo
 if ( O0Oo == Ii1 . site_id ) :
  lprint ( "Return private RLOCs for sites in site-id {}" . format ( O0Oo ) )
  return ( iiiI11II1IiIi )
  if 90 - 90: Ii1I * I11i % I1Ii111 - I1ii11iIi11i * I1Ii111 % OoO0O00
 return ( oOo0oOOOoOoo )
 if 50 - 50: iIii1I11I1II1
 if 56 - 56: oO0o
 if 55 - 55: iIii1I11I1II1 % oO0o % OOooOOo / I1Ii111 * OoooooooOO / Oo0Ooo
 if 88 - 88: I11i + OoO0O00 . iIii1I11I1II1 . II111iiii
 if 67 - 67: OOooOOo - ooOoO0o % iII111i % IiII
 if 71 - 71: OoO0O00 - ooOoO0o - I1IiiI + O0
 if 15 - 15: i1IIi
 if 43 - 43: II111iiii + OOooOOo . i11iIiiIii - II111iiii
 if 80 - 80: o0oOOo0O0Ooo . oO0o . I1Ii111
def lisp_get_partial_rloc_set ( registered_rloc_set , mr_source , multicast ) :
 IiIii1iI = [ ]
 oOo0oOOOoOoo = [ ]
 if 60 - 60: iII111i % i11iIiiIii * OOooOOo % I1IiiI + OoO0O00
 if 56 - 56: I1Ii111 - OOooOOo + iIii1I11I1II1 + O0 * iIii1I11I1II1
 if 62 - 62: oO0o
 if 46 - 46: I1Ii111 - iII111i / oO0o % OoO0O00 / O0 + oO0o
 if 35 - 35: Oo0Ooo
 if 86 - 86: ooOoO0o . OoO0O00
 i1i1i11i11 = False
 I1II1i = False
 for ii1I1i11 in registered_rloc_set :
  if ( ii1I1i11 . priority != 254 ) : continue
  I1II1i |= True
  if ( ii1I1i11 . rloc . is_exact_match ( mr_source ) == False ) : continue
  i1i1i11i11 = True
  break
  if 53 - 53: IiII * I1ii11iIi11i
  if 64 - 64: OOooOOo + Oo0Ooo . OoOoOO00 . OOooOOo + i11iIiiIii
  if 7 - 7: ooOoO0o * I11i / iIii1I11I1II1
  if 15 - 15: OoooooooOO / iII111i
  if 40 - 40: o0oOOo0O0Ooo
  if 75 - 75: oO0o - OoOoOO00 * ooOoO0o . O0
  if 78 - 78: Oo0Ooo
 if ( I1II1i == False ) : return ( registered_rloc_set )
 if 74 - 74: O0 / I11i
 if 52 - 52: I1IiiI + oO0o * II111iiii
 if 15 - 15: I11i
 if 72 - 72: O0
 if 15 - 15: II111iiii / I11i % II111iiii % Ii1I % i11iIiiIii / I1Ii111
 if 93 - 93: OOooOOo / OoooooooOO % iII111i
 if 47 - 47: o0oOOo0O0Ooo - I1IiiI % O0 % I1Ii111 . O0 . OoOoOO00
 if 95 - 95: o0oOOo0O0Ooo * OOooOOo - iII111i * OoooooooOO - ooOoO0o / I1IiiI
 if 47 - 47: OoO0O00 % I1IiiI / OoOoOO00 - I1Ii111 / I1IiiI
 if 13 - 13: o0oOOo0O0Ooo % ooOoO0o
 I1ii1iiiiIIIi = ( os . getenv ( "LISP_RTR_BEHIND_NAT" ) != None )
 if 3 - 3: i1IIi
 if 34 - 34: OoooooooOO % ooOoO0o
 if 16 - 16: OoOoOO00 + Oo0Ooo + iIii1I11I1II1 . OoOoOO00 - OOooOOo / o0oOOo0O0Ooo
 if 8 - 8: OoOoOO00 . OOooOOo / I11i % Oo0Ooo
 if 36 - 36: Ii1I + iIii1I11I1II1
 for ii1I1i11 in registered_rloc_set :
  if ( I1ii1iiiiIIIi and ii1I1i11 . rloc . is_private_address ( ) ) : continue
  if ( multicast == False and ii1I1i11 . priority == 255 ) : continue
  if ( multicast and ii1I1i11 . mpriority == 255 ) : continue
  if ( ii1I1i11 . priority == 254 ) :
   IiIii1iI . append ( ii1I1i11 )
  else :
   oOo0oOOOoOoo . append ( ii1I1i11 )
   if 13 - 13: iII111i . I1Ii111 % ooOoO0o / i1IIi
   if 64 - 64: iII111i
   if 9 - 9: I1ii11iIi11i + Oo0Ooo * I11i / I1Ii111 / I1ii11iIi11i / oO0o
   if 48 - 48: Oo0Ooo % i1IIi / I1ii11iIi11i / oO0o + iII111i
   if 47 - 47: Ii1I
   if 75 - 75: II111iiii / OoOoOO00 - o0oOOo0O0Ooo % I1ii11iIi11i + OoO0O00
 if ( i1i1i11i11 ) : return ( oOo0oOOOoOoo )
 if 7 - 7: iII111i - OoO0O00 + ooOoO0o * iII111i
 if 14 - 14: OoOoOO00 - OoOoOO00 / ooOoO0o
 if 22 - 22: I1Ii111
 if 59 - 59: I1Ii111
 if 22 - 22: OoooooooOO
 if 88 - 88: I1Ii111 - OoO0O00
 if 29 - 29: I1IiiI . I1Ii111
 if 74 - 74: Oo0Ooo / OoOoOO00 + OoOoOO00 % i11iIiiIii . OoO0O00 + ooOoO0o
 if 77 - 77: ooOoO0o . I11i + OoooooooOO
 if 100 - 100: ooOoO0o . oO0o % I1ii11iIi11i . IiII * IiII - o0oOOo0O0Ooo
 oOo0oOOOoOoo = [ ]
 for ii1I1i11 in registered_rloc_set :
  if ( ii1I1i11 . rloc . is_private_address ( ) ) : oOo0oOOOoOoo . append ( ii1I1i11 )
  if 49 - 49: iIii1I11I1II1 % Ii1I / OoooooooOO - II111iiii . Ii1I
 oOo0oOOOoOoo += IiIii1iI
 return ( oOo0oOOOoOoo )
 if 65 - 65: OoooooooOO + I1Ii111 % ooOoO0o + II111iiii . i1IIi + OoooooooOO
 if 26 - 26: I1IiiI / II111iiii % I1ii11iIi11i * o0oOOo0O0Ooo . IiII / OoO0O00
 if 10 - 10: i11iIiiIii / i1IIi + O0 - i11iIiiIii % I11i - i1IIi
 if 38 - 38: O0 - I1IiiI + Oo0Ooo + ooOoO0o
 if 56 - 56: I1Ii111 + oO0o / Ii1I + I1Ii111
 if 21 - 21: OOooOOo / OoOoOO00 + OoOoOO00 + OoOoOO00 - i1IIi + Ii1I
 if 43 - 43: O0 % II111iiii
 if 60 - 60: iII111i / ooOoO0o - Ii1I - OoooooooOO
 if 79 - 79: oO0o / iII111i . iIii1I11I1II1 * i11iIiiIii * i1IIi . iIii1I11I1II1
 if 31 - 31: OoooooooOO / ooOoO0o / OoooooooOO + ooOoO0o . O0 - IiII
def lisp_store_pubsub_state ( reply_eid , itr_rloc , mr_sport , nonce , ttl , xtr_id ) :
 oO0000o00OO = lisp_pubsub ( itr_rloc , mr_sport , nonce , ttl , xtr_id )
 oO0000o00OO . add ( reply_eid )
 return
 if 9 - 9: o0oOOo0O0Ooo + Oo0Ooo * I1ii11iIi11i - i1IIi + ooOoO0o + I1ii11iIi11i
 if 40 - 40: OoooooooOO
 if 20 - 20: OOooOOo / O0
 if 51 - 51: ooOoO0o - I1Ii111 * oO0o
 if 47 - 47: Oo0Ooo % OoO0O00 * Ii1I / OoOoOO00
 if 1 - 1: I1IiiI
 if 68 - 68: ooOoO0o
 if 68 - 68: I11i % IiII
 if 1 - 1: I1IiiI + OOooOOo - OOooOOo * O0 + o0oOOo0O0Ooo * OOooOOo
 if 48 - 48: ooOoO0o - iII111i + I1ii11iIi11i * I1Ii111 % ooOoO0o * OoO0O00
 if 28 - 28: i1IIi / iII111i + OOooOOo
 if 89 - 89: Oo0Ooo + II111iiii * OoO0O00 + Oo0Ooo % II111iiii
 if 59 - 59: O0 + Oo0Ooo
 if 63 - 63: OoO0O00 / I1IiiI / oO0o . Ii1I / i1IIi
 if 50 - 50: I11i . I11i % I1IiiI - i1IIi
def lisp_convert_reply_to_notify ( packet ) :
 if 63 - 63: OoO0O00 . iII111i
 if 28 - 28: ooOoO0o . Oo0Ooo - OoooooooOO - I1Ii111 - OoooooooOO - oO0o
 if 25 - 25: I11i / I1Ii111 . i11iIiiIii % i1IIi
 if 21 - 21: O0 * IiII . iII111i / iII111i % i11iIiiIii / I11i
 iIII = struct . unpack ( "I" , packet [ 0 : 4 ] ) [ 0 ]
 iIII = socket . ntohl ( iIII ) & 0xff
 iIiIi1i1Iiii = packet [ 4 : 12 ]
 packet = packet [ 12 : : ]
 if 21 - 21: II111iiii + OoO0O00
 if 70 - 70: Oo0Ooo * i11iIiiIii + IiII / OoOoOO00 . I1ii11iIi11i % OoOoOO00
 if 12 - 12: I11i % II111iiii % O0 % O0
 if 18 - 18: iII111i . IiII . I1IiiI
 O0ooOo0Oooo = ( LISP_MAP_NOTIFY << 28 ) | iIII
 IIiiIiIIiI1 = struct . pack ( "I" , socket . htonl ( O0ooOo0Oooo ) )
 oOo00OO0o0 = struct . pack ( "I" , 0 )
 if 40 - 40: IiII / oO0o + OoooooooOO / iII111i / II111iiii + i1IIi
 if 33 - 33: I11i + I1ii11iIi11i + i11iIiiIii * I1IiiI % oO0o % OoooooooOO
 if 4 - 4: OoO0O00 . I1IiiI - O0 % iII111i . OOooOOo
 if 69 - 69: OoooooooOO
 packet = IIiiIiIIiI1 + iIiIi1i1Iiii + oOo00OO0o0 + packet
 return ( packet )
 if 19 - 19: O0 + iIii1I11I1II1 / OoOoOO00 / oO0o + II111iiii - OOooOOo
 if 70 - 70: i1IIi * o0oOOo0O0Ooo + I1Ii111 . ooOoO0o - O0 + i11iIiiIii
 if 81 - 81: iIii1I11I1II1 - OoO0O00 . i11iIiiIii
 if 4 - 4: o0oOOo0O0Ooo / OoO0O00 - I11i
 if 52 - 52: II111iiii . iII111i
 if 36 - 36: I1IiiI * II111iiii
 if 68 - 68: oO0o * o0oOOo0O0Ooo + OoooooooOO - I1ii11iIi11i * i1IIi % OOooOOo
 if 39 - 39: I1Ii111 / I11i + oO0o / I1Ii111 % IiII * I1ii11iIi11i
def lisp_notify_subscribers ( lisp_sockets , eid_record , eid , site ) :
 oo0ooooO = eid . print_prefix ( )
 if ( lisp_pubsub_cache . has_key ( oo0ooooO ) == False ) : return
 if 66 - 66: I1ii11iIi11i * ooOoO0o . i11iIiiIii * Oo0Ooo - I11i . I1IiiI
 for oO0000o00OO in lisp_pubsub_cache [ oo0ooooO ] . values ( ) :
  iIi1 = oO0000o00OO . itr
  OOo0000o0 = oO0000o00OO . port
  I1I1IIIIi11 = red ( iIi1 . print_address_no_iid ( ) , False )
  iIiiiIIiI111 = bold ( "subscriber" , False )
  IIIIiiii = "0x" + lisp_hex_string ( oO0000o00OO . xtr_id )
  iIiIi1i1Iiii = "0x" + lisp_hex_string ( oO0000o00OO . nonce )
  if 69 - 69: iIii1I11I1II1 . IiII
  lprint ( "    Notify {} {}:{} xtr-id {} for {}, nonce {}" . format ( iIiiiIIiI111 , I1I1IIIIi11 , OOo0000o0 , IIIIiiii , green ( oo0ooooO , False ) , iIiIi1i1Iiii ) )
  if 63 - 63: ooOoO0o . i11iIiiIii / iIii1I11I1II1
  if 8 - 8: i11iIiiIii . IiII * iIii1I11I1II1 * I1IiiI * Ii1I * i11iIiiIii
  lisp_build_map_notify ( lisp_sockets , eid_record , [ oo0ooooO ] , 1 , iIi1 ,
 OOo0000o0 , oO0000o00OO . nonce , 0 , 0 , 0 , site , False )
  oO0000o00OO . map_notify_count += 1
  if 24 - 24: I1IiiI * I11i - o0oOOo0O0Ooo / iII111i + IiII - I1ii11iIi11i
 return
 if 53 - 53: I11i / I1IiiI - iIii1I11I1II1 - o0oOOo0O0Ooo * OoOoOO00
 if 86 - 86: iIii1I11I1II1 - I1Ii111
 if 86 - 86: O0 * IiII + OoOoOO00 + OoO0O00
 if 53 - 53: I1IiiI % i11iIiiIii + o0oOOo0O0Ooo . I1ii11iIi11i
 if 73 - 73: iII111i - o0oOOo0O0Ooo / OOooOOo + iII111i + o0oOOo0O0Ooo % II111iiii
 if 74 - 74: I11i * iIii1I11I1II1 - OoO0O00 / i1IIi / OoO0O00 / IiII
 if 60 - 60: oO0o % I1Ii111 % Oo0Ooo
def lisp_process_pubsub ( lisp_sockets , packet , reply_eid , itr_rloc , port , nonce ,
 ttl , xtr_id ) :
 if 34 - 34: o0oOOo0O0Ooo * OOooOOo % Ii1I + I1IiiI
 if 77 - 77: OoOoOO00 + IiII + Oo0Ooo
 if 88 - 88: i1IIi
 if 45 - 45: iII111i % I1ii11iIi11i / i11iIiiIii - II111iiii . Oo0Ooo / ooOoO0o
 lisp_store_pubsub_state ( reply_eid , itr_rloc , port , nonce , ttl , xtr_id )
 if 55 - 55: OoO0O00 % IiII
 i1OO0o = green ( reply_eid . print_prefix ( ) , False )
 iIi1 = red ( itr_rloc . print_address_no_iid ( ) , False )
 OOoOOoOo000O = bold ( "Map-Notify" , False )
 xtr_id = "0x" + lisp_hex_string ( xtr_id )
 lprint ( "{} pubsub request for {} to ack ITR {} xtr-id: {}" . format ( OOoOOoOo000O ,
 i1OO0o , iIi1 , xtr_id ) )
 if 27 - 27: I1IiiI . I1Ii111 % OoOoOO00 * Oo0Ooo % OoooooooOO
 if 7 - 7: iIii1I11I1II1 + oO0o
 if 28 - 28: iII111i * II111iiii . Oo0Ooo
 if 56 - 56: oO0o + iII111i + iII111i * OoO0O00 * I1ii11iIi11i
 packet = lisp_convert_reply_to_notify ( packet )
 lisp_send_map_notify ( lisp_sockets , packet , itr_rloc , port )
 return
 if 97 - 97: ooOoO0o + OOooOOo
 if 70 - 70: o0oOOo0O0Ooo + Ii1I - i11iIiiIii + I11i * o0oOOo0O0Ooo . Ii1I
 if 6 - 6: Oo0Ooo + I1IiiI
 if 48 - 48: oO0o . I1ii11iIi11i
 if 59 - 59: IiII - Ii1I
 if 62 - 62: OOooOOo * o0oOOo0O0Ooo + IiII * o0oOOo0O0Ooo * i11iIiiIii - O0
 if 37 - 37: I1ii11iIi11i - Oo0Ooo . i11iIiiIii / i11iIiiIii + oO0o
 if 19 - 19: i1IIi / i1IIi - OoooooooOO - OOooOOo . i1IIi
def lisp_ms_process_map_request ( lisp_sockets , packet , map_request , mr_source ,
 mr_sport , ecm_source ) :
 if 57 - 57: OOooOOo / I1ii11iIi11i * oO0o
 if 53 - 53: o0oOOo0O0Ooo * Ii1I
 if 42 - 42: I11i + iII111i / iIii1I11I1II1
 if 1 - 1: O0 - II111iiii
 if 75 - 75: II111iiii / OoO0O00 % II111iiii
 if 3 - 3: Ii1I - Ii1I % I1ii11iIi11i
 i1OO0o = map_request . target_eid
 Oo000o0o0 = map_request . target_group
 oo0ooooO = lisp_print_eid_tuple ( i1OO0o , Oo000o0o0 )
 I1i11111i = map_request . itr_rlocs [ 0 ]
 IIIIiiii = map_request . xtr_id
 iIiIi1i1Iiii = map_request . nonce
 I11IiIi1I = LISP_NO_ACTION
 oO0000o00OO = map_request . subscribe_bit
 if 44 - 44: OOooOOo - o0oOOo0O0Ooo
 if 69 - 69: IiII + I1ii11iIi11i / o0oOOo0O0Ooo / OOooOOo
 if 31 - 31: oO0o + I1ii11iIi11i * i1IIi % I1IiiI % I1IiiI + iIii1I11I1II1
 if 62 - 62: OoooooooOO
 if 38 - 38: iII111i % iII111i * ooOoO0o / OoO0O00 + ooOoO0o
 O0oIII = True
 OOo0o = ( lisp_get_eid_hash ( i1OO0o ) != None )
 if ( OOo0o ) :
  oOO0 = map_request . map_request_signature
  if ( oOO0 == None ) :
   O0oIII = False
   lprint ( ( "EID-crypto-hash signature verification {}, " + "no signature found" ) . format ( bold ( "failed" , False ) ) )
   if 21 - 21: II111iiii - OOooOOo * O0
  else :
   IIIi11iiIIi = map_request . signature_eid
   o0OoO , iI11i , O0oIII = lisp_lookup_public_key ( IIIi11iiIIi )
   if ( O0oIII ) :
    O0oIII = map_request . verify_map_request_sig ( iI11i )
   else :
    lprint ( "Public-key lookup failed for sig-eid {}, hash-eid {}" . format ( IIIi11iiIIi . print_address ( ) , o0OoO . print_address ( ) ) )
    if 78 - 78: OOooOOo - Oo0Ooo % o0oOOo0O0Ooo % I1ii11iIi11i
    if 1 - 1: iII111i + Oo0Ooo . OOooOOo % II111iiii / i1IIi - OoO0O00
   ii1I11 = bold ( "passed" , False ) if O0oIII else bold ( "failed" , False )
   lprint ( "EID-crypto-hash signature verification {}" . format ( ii1I11 ) )
   if 18 - 18: OoooooooOO
   if 99 - 99: OoOoOO00 + Oo0Ooo . I1IiiI . oO0o
   if 10 - 10: I1Ii111 + I1IiiI . iIii1I11I1II1 + IiII / i11iIiiIii - O0
 if ( oO0000o00OO and O0oIII == False ) :
  oO0000o00OO = False
  lprint ( "Suppress creating pubsub state due to signature failure" )
  if 27 - 27: OoooooooOO / I1ii11iIi11i
  if 87 - 87: I11i + IiII / OOooOOo
  if 70 - 70: II111iiii
  if 21 - 21: i11iIiiIii . iII111i * O0 - iII111i
  if 5 - 5: O0 . OoOoOO00 / iII111i
  if 78 - 78: Ii1I - I1ii11iIi11i + iIii1I11I1II1 + OoooooooOO . OoO0O00 - ooOoO0o
  if 81 - 81: o0oOOo0O0Ooo * OoooooooOO
  if 32 - 32: OoOoOO00 - I11i * i11iIiiIii . I1ii11iIi11i . IiII . iIii1I11I1II1
  if 41 - 41: iII111i / OoOoOO00 / OoO0O00 / ooOoO0o
  if 16 - 16: iIii1I11I1II1 . II111iiii
  if 80 - 80: Oo0Ooo + IiII
  if 18 - 18: OoO0O00 . Oo0Ooo
  if 52 - 52: OoOoOO00 . iIii1I11I1II1 / OoOoOO00
  if 14 - 14: i1IIi
 oOiI111IIIiIii = I1i11111i if ( I1i11111i . afi == ecm_source . afi ) else ecm_source
 if 18 - 18: Oo0Ooo . I1ii11iIi11i * ooOoO0o % Ii1I + I1ii11iIi11i
 IIII = lisp_site_eid_lookup ( i1OO0o , Oo000o0o0 , False )
 if 74 - 74: IiII * OoOoOO00 + OoO0O00 . iIii1I11I1II1 / iIii1I11I1II1
 if ( IIII == None or IIII . is_star_g ( ) ) :
  oOo00 = bold ( "Site not found" , False )
  lprint ( "{} for requested EID {}" . format ( oOo00 ,
 green ( oo0ooooO , False ) ) )
  if 63 - 63: I1ii11iIi11i % i11iIiiIii . Ii1I . I1IiiI * I1IiiI
  if 51 - 51: oO0o . Oo0Ooo / i1IIi + i1IIi * i1IIi
  if 32 - 32: I1IiiI + IiII + iII111i . iIii1I11I1II1 * Ii1I
  if 27 - 27: oO0o + Ii1I . i11iIiiIii
  lisp_send_negative_map_reply ( lisp_sockets , i1OO0o , Oo000o0o0 , iIiIi1i1Iiii , I1i11111i ,
 mr_sport , 15 , IIIIiiii , oO0000o00OO )
  if 97 - 97: iII111i . I1IiiI
  return ( [ i1OO0o , Oo000o0o0 , LISP_DDT_ACTION_SITE_NOT_FOUND ] )
  if 71 - 71: OOooOOo - IiII % oO0o * I1ii11iIi11i
  if 48 - 48: o0oOOo0O0Ooo * iIii1I11I1II1 + Oo0Ooo
 Oo0OooI11IIIiiiI = IIII . print_eid_tuple ( )
 iI111i1ii = IIII . site . site_name
 if 35 - 35: O0 % Ii1I + OoooooooOO
 if 72 - 72: I1ii11iIi11i
 if 100 - 100: i11iIiiIii - iII111i - I11i
 if 5 - 5: oO0o % IiII * iII111i
 if 98 - 98: iII111i / OOooOOo + IiII
 if ( OOo0o == False and IIII . require_signature ) :
  oOO0 = map_request . map_request_signature
  IIIi11iiIIi = map_request . signature_eid
  if ( oOO0 == None or IIIi11iiIIi . is_null ( ) ) :
   lprint ( "Signature required for site {}" . format ( iI111i1ii ) )
   O0oIII = False
  else :
   IIIi11iiIIi = map_request . signature_eid
   o0OoO , iI11i , O0oIII = lisp_lookup_public_key ( IIIi11iiIIi )
   if ( O0oIII ) :
    O0oIII = map_request . verify_map_request_sig ( iI11i )
   else :
    lprint ( "Public-key lookup failed for sig-eid {}, hash-eid {}" . format ( IIIi11iiIIi . print_address ( ) , o0OoO . print_address ( ) ) )
    if 100 - 100: II111iiii . i11iIiiIii / oO0o - OOooOOo + OoOoOO00 % I1ii11iIi11i
    if 82 - 82: ooOoO0o % OOooOOo % Ii1I
   ii1I11 = bold ( "passed" , False ) if O0oIII else bold ( "failed" , False )
   lprint ( "Required signature verification {}" . format ( ii1I11 ) )
   if 82 - 82: I1ii11iIi11i
   if 52 - 52: i11iIiiIii % I1Ii111 - iII111i / O0 - I1ii11iIi11i / iII111i
   if 7 - 7: OoooooooOO . OOooOOo . OOooOOo
   if 53 - 53: OOooOOo * OoOoOO00 % iII111i
   if 86 - 86: OOooOOo . OOooOOo + IiII - I1ii11iIi11i . OoO0O00
   if 66 - 66: I1IiiI * OoOoOO00 . I1IiiI / Oo0Ooo - Ii1I
 if ( O0oIII and IIII . registered == False ) :
  lprint ( "Site '{}' with EID-prefix {} is not registered for EID {}" . format ( iI111i1ii , green ( Oo0OooI11IIIiiiI , False ) , green ( oo0ooooO , False ) ) )
  if 69 - 69: iIii1I11I1II1 % iII111i + ooOoO0o * i1IIi + iII111i * I1Ii111
  if 67 - 67: Ii1I % Oo0Ooo - Oo0Ooo . I11i + IiII
  if 73 - 73: Oo0Ooo + iIii1I11I1II1 . iIii1I11I1II1
  if 73 - 73: ooOoO0o + OoOoOO00
  if 61 - 61: I1Ii111 * I1Ii111 % OOooOOo
  if 31 - 31: oO0o + Ii1I - iIii1I11I1II1 / i11iIiiIii
  if ( IIII . accept_more_specifics == False ) :
   i1OO0o = IIII . eid
   Oo000o0o0 = IIII . group
   if 9 - 9: IiII % OoO0O00
   if 58 - 58: iII111i
   if 12 - 12: OoO0O00
   if 59 - 59: OOooOOo + i1IIi
   if 8 - 8: i1IIi + Oo0Ooo / Ii1I . OoOoOO00 % i1IIi
  iiI = 1
  if ( IIII . force_ttl != None ) :
   iiI = IIII . force_ttl | 0x80000000
   if 33 - 33: OoooooooOO + iIii1I11I1II1
   if 68 - 68: II111iiii * iIii1I11I1II1 - OoO0O00 - I1ii11iIi11i * II111iiii
   if 37 - 37: OoooooooOO - I1ii11iIi11i . O0
   if 65 - 65: I1Ii111 + I1ii11iIi11i % I11i / iII111i
   if 38 - 38: I1IiiI - OOooOOo * OoOoOO00 + O0 * I1IiiI
  lisp_send_negative_map_reply ( lisp_sockets , i1OO0o , Oo000o0o0 , iIiIi1i1Iiii , I1i11111i ,
 mr_sport , iiI , IIIIiiii , oO0000o00OO )
  if 8 - 8: I1IiiI
  return ( [ i1OO0o , Oo000o0o0 , LISP_DDT_ACTION_MS_NOT_REG ] )
  if 31 - 31: o0oOOo0O0Ooo + OOooOOo
  if 7 - 7: IiII + iIii1I11I1II1
  if 97 - 97: oO0o
  if 52 - 52: I1ii11iIi11i / OoOoOO00 * OoO0O00 + II111iiii * OoooooooOO
  if 11 - 11: Ii1I * iII111i * I1IiiI - Oo0Ooo
 oOo0o0ooO0OOO = False
 oo00O0OO0Ooo0 = ""
 o0ooOOo = False
 if ( IIII . force_nat_proxy_reply ) :
  oo00O0OO0Ooo0 = ", nat-forced"
  oOo0o0ooO0OOO = True
  o0ooOOo = True
 elif ( IIII . force_proxy_reply ) :
  oo00O0OO0Ooo0 = ", forced"
  o0ooOOo = True
 elif ( IIII . proxy_reply_requested ) :
  oo00O0OO0Ooo0 = ", requested"
  o0ooOOo = True
 elif ( map_request . pitr_bit and IIII . pitr_proxy_reply_drop ) :
  oo00O0OO0Ooo0 = ", drop-to-pitr"
  I11IiIi1I = LISP_DROP_ACTION
 elif ( IIII . proxy_reply_action != "" ) :
  I11IiIi1I = IIII . proxy_reply_action
  oo00O0OO0Ooo0 = ", forced, action {}" . format ( I11IiIi1I )
  I11IiIi1I = LISP_DROP_ACTION if ( I11IiIi1I == "drop" ) else LISP_NATIVE_FORWARD_ACTION
  if 33 - 33: II111iiii * O0 + O0
  if 98 - 98: IiII * OoooooooOO . iII111i
  if 34 - 34: OoooooooOO + I1Ii111
  if 97 - 97: II111iiii + I11i + OOooOOo / i11iIiiIii - iII111i
  if 9 - 9: i1IIi - I1Ii111 + I1Ii111
  if 81 - 81: II111iiii % I11i % O0 . I1Ii111 % ooOoO0o - O0
  if 58 - 58: OoooooooOO . II111iiii . O0 % I1Ii111 / OoooooooOO
 oOoOOO = False
 Iii1II1iI11i = None
 if ( o0ooOOo and lisp_policies . has_key ( IIII . policy ) ) :
  o0O0o = lisp_policies [ IIII . policy ]
  if ( o0O0o . match_policy_map_request ( map_request , mr_source ) ) : Iii1II1iI11i = o0O0o
  if 91 - 91: I1ii11iIi11i * oO0o + I11i % I1ii11iIi11i - I11i
  if ( Iii1II1iI11i ) :
   iiiII1i1I = bold ( "matched" , False )
   lprint ( "Map-Request {} policy '{}', set-action '{}'" . format ( iiiII1i1I ,
 o0O0o . policy_name , o0O0o . set_action ) )
  else :
   iiiII1i1I = bold ( "no match" , False )
   lprint ( "Map-Request {} for policy '{}', implied drop" . format ( iiiII1i1I ,
 o0O0o . policy_name ) )
   oOoOOO = True
   if 18 - 18: OoooooooOO - IiII % iIii1I11I1II1 - I1ii11iIi11i / I1Ii111
   if 28 - 28: iIii1I11I1II1
   if 1 - 1: iII111i
 if ( oo00O0OO0Ooo0 != "" ) :
  lprint ( "Proxy-replying for EID {}, found site '{}' EID-prefix {}{}" . format ( green ( oo0ooooO , False ) , iI111i1ii , green ( Oo0OooI11IIIiiiI , False ) ,
  # Oo0Ooo % OoooooooOO - IiII . OoooooooOO + iII111i * iII111i
 oo00O0OO0Ooo0 ) )
  if 4 - 4: OoooooooOO * o0oOOo0O0Ooo - I1IiiI
  oOo0oOOOoOoo = IIII . registered_rlocs
  iiI = 1440
  if ( oOo0o0ooO0OOO ) :
   if ( IIII . site_id != 0 ) :
    I1IIiiII = map_request . source_eid
    oOo0oOOOoOoo = lisp_get_private_rloc_set ( IIII , I1IIiiII , Oo000o0o0 )
    if 94 - 94: Oo0Ooo / I1IiiI * iIii1I11I1II1 - OoO0O00
   if ( oOo0oOOOoOoo == IIII . registered_rlocs ) :
    O00oooO0 = ( IIII . group . is_null ( ) == False )
    iiiI11II1IiIi = lisp_get_partial_rloc_set ( oOo0oOOOoOoo , oOiI111IIIiIii , O00oooO0 )
    if ( iiiI11II1IiIi != oOo0oOOOoOoo ) :
     iiI = 15
     oOo0oOOOoOoo = iiiI11II1IiIi
     if 10 - 10: I1IiiI
     if 14 - 14: OoO0O00
     if 88 - 88: i1IIi * II111iiii / i11iIiiIii % IiII . IiII
     if 93 - 93: OoOoOO00 * i1IIi . Ii1I
     if 2 - 2: i1IIi
     if 84 - 84: i1IIi / Ii1I + OoOoOO00 % Ii1I . oO0o
     if 74 - 74: OOooOOo - o0oOOo0O0Ooo - I1Ii111 - OoO0O00
     if 40 - 40: o0oOOo0O0Ooo . IiII * OoOoOO00
  if ( IIII . force_ttl != None ) :
   iiI = IIII . force_ttl | 0x80000000
   if 14 - 14: OOooOOo
   if 18 - 18: i11iIiiIii % iII111i
   if 70 - 70: O0 + iII111i % I11i % I1Ii111 + OoOoOO00 / ooOoO0o
   if 35 - 35: IiII + OoO0O00
   if 82 - 82: i1IIi - ooOoO0o / I11i + I11i % I1IiiI - OoooooooOO
   if 56 - 56: I1ii11iIi11i
  if ( Iii1II1iI11i ) :
   if ( Iii1II1iI11i . set_record_ttl ) :
    iiI = Iii1II1iI11i . set_record_ttl
    lprint ( "Policy set-record-ttl to {}" . format ( iiI ) )
    if 80 - 80: Oo0Ooo / OOooOOo / iII111i . o0oOOo0O0Ooo
   if ( Iii1II1iI11i . set_action == "drop" ) :
    lprint ( "Policy set-action drop, send negative Map-Reply" )
    I11IiIi1I = LISP_POLICY_DENIED_ACTION
    oOo0oOOOoOoo = [ ]
   else :
    i1IIIIi1Ii111 = Iii1II1iI11i . set_policy_map_reply ( )
    if ( i1IIIIi1Ii111 ) : oOo0oOOOoOoo = [ i1IIIIi1Ii111 ]
    if 43 - 43: IiII
    if 74 - 74: OoooooooOO
    if 88 - 88: Ii1I * o0oOOo0O0Ooo / oO0o
  if ( oOoOOO ) :
   lprint ( "Implied drop action, send negative Map-Reply" )
   I11IiIi1I = LISP_POLICY_DENIED_ACTION
   oOo0oOOOoOoo = [ ]
   if 58 - 58: O0
   if 43 - 43: O0 / i1IIi / I11i % I1IiiI
  i1iiIi1 = IIII . echo_nonce_capable
  if 82 - 82: i11iIiiIii * i11iIiiIii + I1Ii111 - I1ii11iIi11i * oO0o - Ii1I
  if 40 - 40: o0oOOo0O0Ooo + OoO0O00 % i1IIi % iII111i * I1Ii111
  if 36 - 36: I1ii11iIi11i % II111iiii % I1Ii111 / I1ii11iIi11i
  if 34 - 34: OoooooooOO * i11iIiiIii
  if ( O0oIII ) :
   iIi1i = IIII . eid
   OOO = IIII . group
  else :
   iIi1i = i1OO0o
   OOO = Oo000o0o0
   I11IiIi1I = LISP_AUTH_FAILURE_ACTION
   oOo0oOOOoOoo = [ ]
   if 35 - 35: iII111i * OoO0O00 + oO0o + I1IiiI * i11iIiiIii
   if 7 - 7: I1Ii111 * iIii1I11I1II1
   if 27 - 27: iII111i % OoOoOO00 % ooOoO0o
   if 4 - 4: iII111i * oO0o / iIii1I11I1II1 - O0 . Ii1I
   if 53 - 53: Ii1I % IiII + I11i % IiII
   if 33 - 33: iII111i
  packet = lisp_build_map_reply ( iIi1i , OOO , oOo0oOOOoOoo ,
 iIiIi1i1Iiii , I11IiIi1I , iiI , False , None , i1iiIi1 , False )
  if 8 - 8: I11i
  if ( oO0000o00OO ) :
   lisp_process_pubsub ( lisp_sockets , packet , iIi1i , I1i11111i ,
 mr_sport , iIiIi1i1Iiii , iiI , IIIIiiii )
  else :
   lisp_send_map_reply ( lisp_sockets , packet , I1i11111i , mr_sport )
   if 95 - 95: OoOoOO00 % O0 % I1IiiI
   if 85 - 85: iIii1I11I1II1 * i11iIiiIii
  return ( [ IIII . eid , IIII . group , LISP_DDT_ACTION_MS_ACK ] )
  if 54 - 54: O0 * Ii1I + Ii1I
  if 59 - 59: i11iIiiIii % iII111i
  if 54 - 54: I11i . ooOoO0o / OOooOOo % I1Ii111
  if 13 - 13: I11i / O0 . o0oOOo0O0Ooo . ooOoO0o
  if 7 - 7: OoO0O00 + OoooooooOO % II111iiii % oO0o
 OOOoo0ooooo0 = len ( IIII . registered_rlocs )
 if ( OOOoo0ooooo0 == 0 ) :
  lprint ( "Requested EID {} found site '{}' with EID-prefix {} with " + "no registered RLOCs" . format ( green ( oo0ooooO , False ) , iI111i1ii ,
  # i11iIiiIii * ooOoO0o - II111iiii
 green ( Oo0OooI11IIIiiiI , False ) ) )
  return ( [ IIII . eid , IIII . group , LISP_DDT_ACTION_MS_ACK ] )
  if 65 - 65: I11i / iIii1I11I1II1 / Oo0Ooo . IiII
  if 81 - 81: O0 + oO0o
  if 12 - 12: I1IiiI
  if 34 - 34: iIii1I11I1II1 - Ii1I % OOooOOo * i1IIi . ooOoO0o
  if 43 - 43: iIii1I11I1II1 % Oo0Ooo . I11i % I1ii11iIi11i % I1Ii111 % I1ii11iIi11i
 OOOOOoOOo0O = map_request . target_eid if map_request . source_eid . is_null ( ) else map_request . source_eid
 if 9 - 9: OoOoOO00 / OoooooooOO - OoOoOO00 / Oo0Ooo . I1IiiI - I11i
 oO000o0o0oOo0 = map_request . target_eid . hash_address ( OOOOOoOOo0O )
 oO000o0o0oOo0 %= OOOoo0ooooo0
 II11iiI1I1I = IIII . registered_rlocs [ oO000o0o0oOo0 ]
 if 78 - 78: oO0o . I1IiiI % I1IiiI + OoooooooOO / I1ii11iIi11i
 if ( II11iiI1I1I . rloc . is_null ( ) ) :
  lprint ( ( "Suppress forwarding Map-Request for EID {} at site '{}' " + "EID-prefix {}, no RLOC address" ) . format ( green ( oo0ooooO , False ) ,
  # I1IiiI - I11i - I1Ii111 . oO0o % Ii1I
 iI111i1ii , green ( Oo0OooI11IIIiiiI , False ) ) )
 else :
  lprint ( ( "Forwarding Map-Request for EID {} to ETR {} at site '{}' " + "EID-prefix {}" ) . format ( green ( oo0ooooO , False ) ,
  # OOooOOo + i11iIiiIii / o0oOOo0O0Ooo + iII111i
 red ( II11iiI1I1I . rloc . print_address ( ) , False ) , iI111i1ii ,
 green ( Oo0OooI11IIIiiiI , False ) ) )
  if 90 - 90: ooOoO0o
  if 74 - 74: Oo0Ooo . OOooOOo + OOooOOo / OOooOOo + I1IiiI + i1IIi
  if 32 - 32: i11iIiiIii % Ii1I
  if 92 - 92: OoOoOO00 % o0oOOo0O0Ooo % ooOoO0o - IiII - oO0o
  lisp_send_ecm ( lisp_sockets , packet , map_request . source_eid , mr_sport ,
 map_request . target_eid , II11iiI1I1I . rloc , to_etr = True )
  if 90 - 90: ooOoO0o
 return ( [ IIII . eid , IIII . group , LISP_DDT_ACTION_MS_ACK ] )
 if 11 - 11: OoOoOO00 % OOooOOo . i11iIiiIii * I1IiiI % O0 % iIii1I11I1II1
 if 18 - 18: Oo0Ooo % OOooOOo + IiII
 if 28 - 28: OOooOOo . OoO0O00 / o0oOOo0O0Ooo + II111iiii / iIii1I11I1II1 * II111iiii
 if 83 - 83: II111iiii . OoOoOO00 - i11iIiiIii . OoOoOO00 . i1IIi % OoooooooOO
 if 47 - 47: II111iiii
 if 30 - 30: i1IIi . Oo0Ooo / o0oOOo0O0Ooo + IiII * OOooOOo
 if 26 - 26: Ii1I % O0 - i1IIi % iII111i * OoO0O00
def lisp_ddt_process_map_request ( lisp_sockets , map_request , ecm_source , port ) :
 if 60 - 60: I1ii11iIi11i * iII111i / OoOoOO00 . o0oOOo0O0Ooo / iIii1I11I1II1
 if 94 - 94: OoO0O00 . ooOoO0o
 if 25 - 25: I1Ii111 % OOooOOo
 if 82 - 82: Ii1I
 i1OO0o = map_request . target_eid
 Oo000o0o0 = map_request . target_group
 oo0ooooO = lisp_print_eid_tuple ( i1OO0o , Oo000o0o0 )
 iIiIi1i1Iiii = map_request . nonce
 I11IiIi1I = LISP_DDT_ACTION_NULL
 if 17 - 17: iII111i . i1IIi . i1IIi
 if 76 - 76: OoooooooOO % IiII
 if 81 - 81: iII111i . OOooOOo * i1IIi
 if 14 - 14: oO0o
 if 16 - 16: iII111i
 I11 = None
 if ( lisp_i_am_ms ) :
  IIII = lisp_site_eid_lookup ( i1OO0o , Oo000o0o0 , False )
  if ( IIII == None ) : return
  if 65 - 65: i11iIiiIii
  if ( IIII . registered ) :
   I11IiIi1I = LISP_DDT_ACTION_MS_ACK
   iiI = 1440
  else :
   i1OO0o , Oo000o0o0 , I11IiIi1I = lisp_ms_compute_neg_prefix ( i1OO0o , Oo000o0o0 )
   I11IiIi1I = LISP_DDT_ACTION_MS_NOT_REG
   iiI = 1
   if 11 - 11: i1IIi - Oo0Ooo % O0 . II111iiii % oO0o
 else :
  I11 = lisp_ddt_cache_lookup ( i1OO0o , Oo000o0o0 , False )
  if ( I11 == None ) :
   I11IiIi1I = LISP_DDT_ACTION_NOT_AUTH
   iiI = 0
   lprint ( "DDT delegation entry not found for EID {}" . format ( green ( oo0ooooO , False ) ) )
   if 43 - 43: I1Ii111 - Oo0Ooo % II111iiii / Ii1I . iII111i . iIii1I11I1II1
  elif ( I11 . is_auth_prefix ( ) ) :
   if 69 - 69: I11i - I11i / I11i + IiII - I1IiiI
   if 21 - 21: I1IiiI * OoO0O00 * oO0o . o0oOOo0O0Ooo + II111iiii
   if 62 - 62: ooOoO0o - OoooooooOO / I1ii11iIi11i / iII111i - o0oOOo0O0Ooo
   if 70 - 70: oO0o % OoooooooOO * I1IiiI - OoOoOO00 * OoOoOO00 . OOooOOo
   I11IiIi1I = LISP_DDT_ACTION_DELEGATION_HOLE
   iiI = 15
   I11I111Ii1II = I11 . print_eid_tuple ( )
   lprint ( ( "DDT delegation entry not found but auth-prefix {} " + "found for EID {}" ) . format ( I11I111Ii1II ,
   # I1ii11iIi11i * II111iiii
 green ( oo0ooooO , False ) ) )
   if 59 - 59: OoO0O00
   if ( Oo000o0o0 . is_null ( ) ) :
    i1OO0o = lisp_ddt_compute_neg_prefix ( i1OO0o , I11 ,
 lisp_ddt_cache )
   else :
    Oo000o0o0 = lisp_ddt_compute_neg_prefix ( Oo000o0o0 , I11 ,
 lisp_ddt_cache )
    i1OO0o = lisp_ddt_compute_neg_prefix ( i1OO0o , I11 ,
 I11 . source_cache )
    if 81 - 81: i11iIiiIii
   I11 = None
  else :
   I11I111Ii1II = I11 . print_eid_tuple ( )
   lprint ( "DDT delegation entry {} found for EID {}" . format ( I11I111Ii1II , green ( oo0ooooO , False ) ) )
   if 57 - 57: Oo0Ooo * iIii1I11I1II1 - OoOoOO00 % iII111i % I1ii11iIi11i + Ii1I
   iiI = 1440
   if 82 - 82: IiII * Oo0Ooo - iIii1I11I1II1 - i11iIiiIii
   if 85 - 85: OoooooooOO
   if 37 - 37: OoooooooOO + O0 + I1ii11iIi11i + IiII * iII111i
   if 15 - 15: i11iIiiIii / Oo0Ooo - OOooOOo . IiII
   if 11 - 11: OOooOOo / i1IIi % Oo0Ooo
   if 65 - 65: OOooOOo % I1ii11iIi11i
 iI1IIII1ii1 = lisp_build_map_referral ( i1OO0o , Oo000o0o0 , I11 , I11IiIi1I , iiI , iIiIi1i1Iiii )
 iIiIi1i1Iiii = map_request . nonce >> 32
 if ( map_request . nonce != 0 and iIiIi1i1Iiii != 0xdfdf0e1d ) : port = LISP_CTRL_PORT
 lisp_send_map_referral ( lisp_sockets , iI1IIII1ii1 , ecm_source , port )
 return
 if 25 - 25: o0oOOo0O0Ooo - I1Ii111 * I1ii11iIi11i + OoooooooOO
 if 93 - 93: OoOoOO00 % I1ii11iIi11i * I11i
 if 34 - 34: I11i - oO0o + I11i * OoooooooOO * I11i
 if 73 - 73: OOooOOo * iII111i * OoO0O00
 if 11 - 11: I1Ii111 * II111iiii
 if 3 - 3: Oo0Ooo * OOooOOo
 if 13 - 13: I1Ii111 + i11iIiiIii / OOooOOo
 if 98 - 98: I1IiiI * Oo0Ooo
 if 9 - 9: O0 / i11iIiiIii . iIii1I11I1II1 . IiII
 if 14 - 14: OoOoOO00 . OOooOOo - Oo0Ooo + I1Ii111 % ooOoO0o
 if 95 - 95: OoO0O00 * II111iiii + i1IIi
 if 22 - 22: Ii1I / ooOoO0o % I11i + OoO0O00 . ooOoO0o
 if 61 - 61: O0 - iIii1I11I1II1 * Oo0Ooo . Ii1I + O0
def lisp_find_negative_mask_len ( eid , entry_prefix , neg_prefix ) :
 I1I1I = eid . hash_address ( entry_prefix )
 OO0o0OoooOOoO = eid . addr_length ( ) * 8
 ooooOo00OO0o = 0
 if 4 - 4: O0 * iII111i - iII111i + iIii1I11I1II1 * iIii1I11I1II1
 if 48 - 48: I1Ii111 * I11i
 if 52 - 52: ooOoO0o
 if 16 - 16: ooOoO0o % iII111i - o0oOOo0O0Ooo % I11i + i11iIiiIii
 for ooooOo00OO0o in range ( OO0o0OoooOOoO ) :
  iIIiI1iiIIiIiii = 1 << ( OO0o0OoooOOoO - ooooOo00OO0o - 1 )
  if ( I1I1I & iIIiI1iiIIiIiii ) : break
  if 33 - 33: oO0o % I1Ii111 % Oo0Ooo . Ii1I
  if 3 - 3: I1Ii111 . o0oOOo0O0Ooo
 if ( ooooOo00OO0o > neg_prefix . mask_len ) : neg_prefix . mask_len = ooooOo00OO0o
 return
 if 6 - 6: oO0o . OoOoOO00 * i11iIiiIii
 if 96 - 96: i1IIi . OoO0O00 . OoO0O00 - o0oOOo0O0Ooo - Ii1I
 if 33 - 33: ooOoO0o + I1ii11iIi11i - I1IiiI . iII111i / OoO0O00
 if 91 - 91: OOooOOo - OoooooooOO . OoO0O00
 if 34 - 34: Ii1I . I1IiiI . i1IIi * I1ii11iIi11i
 if 77 - 77: ooOoO0o . II111iiii
 if 41 - 41: IiII
 if 27 - 27: IiII / IiII
 if 91 - 91: Ii1I
 if 93 - 93: OoO0O00 * OoO0O00 * I1ii11iIi11i * OoO0O00 * o0oOOo0O0Ooo
def lisp_neg_prefix_walk ( entry , parms ) :
 i1OO0o , O0OOO0oO0OO0 , iiII1iI = parms
 if 8 - 8: I1ii11iIi11i
 if ( O0OOO0oO0OO0 == None ) :
  if ( entry . eid . instance_id != i1OO0o . instance_id ) :
   return ( [ True , parms ] )
   if 88 - 88: I11i
  if ( entry . eid . afi != i1OO0o . afi ) : return ( [ True , parms ] )
 else :
  if ( entry . eid . is_more_specific ( O0OOO0oO0OO0 ) == False ) :
   return ( [ True , parms ] )
   if 36 - 36: iIii1I11I1II1 - ooOoO0o * OoO0O00 * OoO0O00 . II111iiii
   if 49 - 49: O0 + OoO0O00 - I1ii11iIi11i + ooOoO0o
   if 90 - 90: O0 . Ii1I * OOooOOo * OoooooooOO * ooOoO0o * Ii1I
   if 12 - 12: ooOoO0o * OoooooooOO * i1IIi
   if 3 - 3: o0oOOo0O0Ooo + Ii1I - i1IIi . OoooooooOO % Ii1I
   if 39 - 39: o0oOOo0O0Ooo
 lisp_find_negative_mask_len ( i1OO0o , entry . eid , iiII1iI )
 return ( [ True , parms ] )
 if 73 - 73: IiII
 if 92 - 92: OOooOOo / ooOoO0o . I1Ii111 . iII111i / ooOoO0o
 if 83 - 83: iIii1I11I1II1 - OoO0O00 - I1Ii111
 if 27 - 27: IiII - iII111i * i11iIiiIii % i11iIiiIii + OoOoOO00 . I1Ii111
 if 10 - 10: IiII / i11iIiiIii
 if 6 - 6: I11i - OOooOOo
 if 100 - 100: Oo0Ooo / OOooOOo + iII111i - o0oOOo0O0Ooo + OoO0O00 % IiII
 if 91 - 91: Ii1I % I11i % Oo0Ooo / OoO0O00 - II111iiii - o0oOOo0O0Ooo
def lisp_ddt_compute_neg_prefix ( eid , ddt_entry , cache ) :
 if 50 - 50: OoooooooOO
 if 51 - 51: II111iiii - oO0o % OoooooooOO - II111iiii / O0 - OoooooooOO
 if 21 - 21: iII111i * o0oOOo0O0Ooo
 if 85 - 85: I1ii11iIi11i . OoOoOO00 . i1IIi % OOooOOo * I11i . I1Ii111
 if ( eid . is_binary ( ) == False ) : return ( eid )
 if 26 - 26: I1Ii111 + Oo0Ooo + II111iiii % OoOoOO00 % OOooOOo
 iiII1iI = lisp_address ( eid . afi , "" , 0 , 0 )
 iiII1iI . copy_address ( eid )
 iiII1iI . mask_len = 0
 if 40 - 40: I1ii11iIi11i + i1IIi
 i1III11I11 = ddt_entry . print_eid_tuple ( )
 O0OOO0oO0OO0 = ddt_entry . eid
 if 82 - 82: IiII + Oo0Ooo + iIii1I11I1II1 - I11i - I1IiiI
 if 65 - 65: IiII / O0 * II111iiii + oO0o
 if 52 - 52: o0oOOo0O0Ooo - OoOoOO00 * II111iiii / OoooooooOO
 if 44 - 44: OOooOOo - oO0o + o0oOOo0O0Ooo - i1IIi % o0oOOo0O0Ooo
 if 79 - 79: iII111i . iIii1I11I1II1
 eid , O0OOO0oO0OO0 , iiII1iI = cache . walk_cache ( lisp_neg_prefix_walk ,
 ( eid , O0OOO0oO0OO0 , iiII1iI ) )
 if 42 - 42: i11iIiiIii / IiII . O0 / OOooOOo . iII111i * i1IIi
 if 83 - 83: iIii1I11I1II1 . II111iiii * Oo0Ooo . I1IiiI - I1IiiI - iIii1I11I1II1
 if 29 - 29: Oo0Ooo
 if 35 - 35: OoOoOO00 + II111iiii
 iiII1iI . mask_address ( iiII1iI . mask_len )
 if 46 - 46: O0 / I1ii11iIi11i + OOooOOo - I1Ii111 + I1IiiI - ooOoO0o
 lprint ( ( "Least specific prefix computed from ddt-cache for EID {} " + "using auth-prefix {} is {}" ) . format ( green ( eid . print_address ( ) , False ) ,
 # OoO0O00 * OOooOOo * iII111i / I1ii11iIi11i % I11i % OoO0O00
 i1III11I11 , iiII1iI . print_prefix ( ) ) )
 return ( iiII1iI )
 if 26 - 26: iIii1I11I1II1 - Oo0Ooo * i11iIiiIii
 if 13 - 13: iIii1I11I1II1 - I11i % IiII . I1Ii111
 if 31 - 31: OoooooooOO % iII111i / OOooOOo
 if 54 - 54: o0oOOo0O0Ooo
 if 37 - 37: ooOoO0o
 if 46 - 46: iII111i - i11iIiiIii * iII111i
 if 1 - 1: iII111i * oO0o % Ii1I . oO0o
 if 86 - 86: iII111i * ooOoO0o / iIii1I11I1II1 + Ii1I . iII111i
def lisp_ms_compute_neg_prefix ( eid , group ) :
 iiII1iI = lisp_address ( eid . afi , "" , 0 , 0 )
 iiII1iI . copy_address ( eid )
 iiII1iI . mask_len = 0
 O00O000Oo = lisp_address ( group . afi , "" , 0 , 0 )
 O00O000Oo . copy_address ( group )
 O00O000Oo . mask_len = 0
 O0OOO0oO0OO0 = None
 if 4 - 4: i1IIi + oO0o % ooOoO0o
 if 36 - 36: I11i / I1IiiI + O0 % II111iiii
 if 24 - 24: I1Ii111 / o0oOOo0O0Ooo - OOooOOo / IiII
 if 7 - 7: OoooooooOO - i11iIiiIii * i11iIiiIii / oO0o * i1IIi % OoooooooOO
 if 6 - 6: I1ii11iIi11i * i11iIiiIii % i11iIiiIii / I1Ii111
 if ( group . is_null ( ) ) :
  I11 = lisp_ddt_cache . lookup_cache ( eid , False )
  if ( I11 == None ) :
   iiII1iI . mask_len = iiII1iI . host_mask_len ( )
   O00O000Oo . mask_len = O00O000Oo . host_mask_len ( )
   return ( [ iiII1iI , O00O000Oo , LISP_DDT_ACTION_NOT_AUTH ] )
   if 21 - 21: oO0o
  iii11i1I = lisp_sites_by_eid
  if ( I11 . is_auth_prefix ( ) ) : O0OOO0oO0OO0 = I11 . eid
 else :
  I11 = lisp_ddt_cache . lookup_cache ( group , False )
  if ( I11 == None ) :
   iiII1iI . mask_len = iiII1iI . host_mask_len ( )
   O00O000Oo . mask_len = O00O000Oo . host_mask_len ( )
   return ( [ iiII1iI , O00O000Oo , LISP_DDT_ACTION_NOT_AUTH ] )
   if 65 - 65: II111iiii + OoO0O00 + OoO0O00
  if ( I11 . is_auth_prefix ( ) ) : O0OOO0oO0OO0 = I11 . group
  if 48 - 48: I1ii11iIi11i / iIii1I11I1II1
  group , O0OOO0oO0OO0 , O00O000Oo = lisp_sites_by_eid . walk_cache ( lisp_neg_prefix_walk , ( group , O0OOO0oO0OO0 , O00O000Oo ) )
  if 47 - 47: I1Ii111
  if 41 - 41: IiII
  O00O000Oo . mask_address ( O00O000Oo . mask_len )
  if 25 - 25: I11i % iIii1I11I1II1
  lprint ( ( "Least specific prefix computed from site-cache for " + "group EID {} using auth-prefix {} is {}" ) . format ( group . print_address ( ) , O0OOO0oO0OO0 . print_prefix ( ) if ( O0OOO0oO0OO0 != None ) else "'not found'" ,
  # O0 + iIii1I11I1II1
  # O0
  # II111iiii / oO0o * OoO0O00 - OoOoOO00
 O00O000Oo . print_prefix ( ) ) )
  if 86 - 86: IiII - IiII - OoOoOO00 % i1IIi
  iii11i1I = I11 . source_cache
  if 89 - 89: oO0o % i11iIiiIii - iIii1I11I1II1 + oO0o
  if 15 - 15: I1ii11iIi11i - I1IiiI % OOooOOo
  if 9 - 9: Ii1I / O0
  if 95 - 95: iII111i / I11i
  if 86 - 86: O0 / II111iiii . Oo0Ooo / Oo0Ooo * II111iiii
 I11IiIi1I = LISP_DDT_ACTION_DELEGATION_HOLE if ( O0OOO0oO0OO0 != None ) else LISP_DDT_ACTION_NOT_AUTH
 if 22 - 22: Ii1I
 if 81 - 81: iIii1I11I1II1 . ooOoO0o % I11i
 if 64 - 64: I1Ii111 . Oo0Ooo * o0oOOo0O0Ooo
 if 32 - 32: oO0o . I1Ii111 * I1Ii111
 if 32 - 32: I1Ii111 . Ii1I / i1IIi
 if 2 - 2: OOooOOo * ooOoO0o / I11i + OoO0O00
 eid , O0OOO0oO0OO0 , iiII1iI = iii11i1I . walk_cache ( lisp_neg_prefix_walk ,
 ( eid , O0OOO0oO0OO0 , iiII1iI ) )
 if 96 - 96: II111iiii * OoO0O00 + I1ii11iIi11i + OoOoOO00 / II111iiii . iII111i
 if 64 - 64: iII111i % Oo0Ooo
 if 79 - 79: IiII + iII111i / II111iiii . i1IIi + iIii1I11I1II1
 if 32 - 32: Ii1I * iII111i
 iiII1iI . mask_address ( iiII1iI . mask_len )
 if 52 - 52: I11i
 lprint ( ( "Least specific prefix computed from site-cache for EID {} " + "using auth-prefix {} is {}" ) . format ( green ( eid . print_address ( ) , False ) ,
 # OOooOOo + iII111i + I1ii11iIi11i + OoO0O00 / I1Ii111 . I1Ii111
 # i1IIi / OoooooooOO % Oo0Ooo - II111iiii / i11iIiiIii . OoooooooOO
 O0OOO0oO0OO0 . print_prefix ( ) if ( O0OOO0oO0OO0 != None ) else "'not found'" , iiII1iI . print_prefix ( ) ) )
 if 98 - 98: O0
 if 27 - 27: oO0o * OoooooooOO * oO0o
 return ( [ iiII1iI , O00O000Oo , I11IiIi1I ] )
 if 23 - 23: O0 . OoO0O00 . i1IIi
 if 19 - 19: O0 . OoooooooOO % iIii1I11I1II1 - Ii1I . Ii1I + I1IiiI
 if 98 - 98: oO0o . Oo0Ooo
 if 9 - 9: I1Ii111 % IiII - i11iIiiIii - OOooOOo % iII111i % OoooooooOO
 if 6 - 6: i1IIi - II111iiii * OoOoOO00 + oO0o
 if 6 - 6: I1IiiI - ooOoO0o + I1IiiI + OoO0O00 - i11iIiiIii % ooOoO0o
 if 64 - 64: OoooooooOO + OOooOOo
 if 36 - 36: I1IiiI - Ii1I / I1ii11iIi11i + Oo0Ooo % I1ii11iIi11i
def lisp_ms_send_map_referral ( lisp_sockets , map_request , ecm_source , port ,
 action , eid_prefix , group_prefix ) :
 if 86 - 86: iIii1I11I1II1 * OoO0O00
 i1OO0o = map_request . target_eid
 Oo000o0o0 = map_request . target_group
 iIiIi1i1Iiii = map_request . nonce
 if 82 - 82: I1IiiI - OoO0O00 % o0oOOo0O0Ooo
 if ( action == LISP_DDT_ACTION_MS_ACK ) : iiI = 1440
 if 72 - 72: O0 + OoOoOO00 % OOooOOo / oO0o / IiII
 if 98 - 98: Oo0Ooo . II111iiii * I11i
 if 39 - 39: IiII * o0oOOo0O0Ooo + Ii1I - I11i
 if 70 - 70: oO0o * ooOoO0o / ooOoO0o - Ii1I * Ii1I % OOooOOo
 Oo0oo = lisp_map_referral ( )
 Oo0oo . record_count = 1
 Oo0oo . nonce = iIiIi1i1Iiii
 iI1IIII1ii1 = Oo0oo . encode ( )
 Oo0oo . print_map_referral ( )
 if 91 - 91: OoO0O00 - OoO0O00 % O0
 O0oOo00O = False
 if 67 - 67: ooOoO0o * i1IIi
 if 66 - 66: o0oOOo0O0Ooo - I1ii11iIi11i . OoOoOO00 / iII111i - Ii1I - i1IIi
 if 97 - 97: oO0o % iII111i - OOooOOo . OoooooooOO
 if 94 - 94: Oo0Ooo
 if 10 - 10: i11iIiiIii / I1ii11iIi11i . i1IIi + i1IIi * iII111i
 if 64 - 64: II111iiii % I1ii11iIi11i . OoOoOO00 . iIii1I11I1II1 / I1ii11iIi11i
 if ( action == LISP_DDT_ACTION_SITE_NOT_FOUND ) :
  eid_prefix , group_prefix , action = lisp_ms_compute_neg_prefix ( i1OO0o ,
 Oo000o0o0 )
  iiI = 15
  if 43 - 43: OoooooooOO * I1IiiI
 if ( action == LISP_DDT_ACTION_MS_NOT_REG ) : iiI = 1
 if ( action == LISP_DDT_ACTION_MS_ACK ) : iiI = 1440
 if ( action == LISP_DDT_ACTION_DELEGATION_HOLE ) : iiI = 15
 if ( action == LISP_DDT_ACTION_NOT_AUTH ) : iiI = 0
 if 2 - 2: OOooOOo / oO0o + I1ii11iIi11i + i11iIiiIii % iIii1I11I1II1 . I1ii11iIi11i
 OOO0o000Ooo00 = False
 OOOoo0ooooo0 = 0
 I11 = lisp_ddt_cache_lookup ( i1OO0o , Oo000o0o0 , False )
 if ( I11 != None ) :
  OOOoo0ooooo0 = len ( I11 . delegation_set )
  OOO0o000Ooo00 = I11 . is_ms_peer_entry ( )
  I11 . map_referrals_sent += 1
  if 49 - 49: II111iiii . OoO0O00 + iIii1I11I1II1
  if 47 - 47: OOooOOo * iIii1I11I1II1 + ooOoO0o . I1Ii111
  if 85 - 85: oO0o
  if 66 - 66: IiII - I11i - I11i / OoooooooOO - i1IIi
  if 12 - 12: Oo0Ooo . I11i - OOooOOo / o0oOOo0O0Ooo
 if ( action == LISP_DDT_ACTION_NOT_AUTH ) : O0oOo00O = True
 if ( action in ( LISP_DDT_ACTION_MS_REFERRAL , LISP_DDT_ACTION_MS_ACK ) ) :
  O0oOo00O = ( OOO0o000Ooo00 == False )
  if 14 - 14: I11i + Oo0Ooo + i11iIiiIii - i1IIi . O0
  if 47 - 47: o0oOOo0O0Ooo / i1IIi * IiII
  if 50 - 50: I11i
  if 9 - 9: iII111i . OoOoOO00 * iII111i
  if 54 - 54: i11iIiiIii * I1IiiI / IiII - OoO0O00 % i1IIi
 I111IoOo0oOOO0o = lisp_eid_record ( )
 I111IoOo0oOOO0o . rloc_count = OOOoo0ooooo0
 I111IoOo0oOOO0o . authoritative = True
 I111IoOo0oOOO0o . action = action
 I111IoOo0oOOO0o . ddt_incomplete = O0oOo00O
 I111IoOo0oOOO0o . eid = eid_prefix
 I111IoOo0oOOO0o . group = group_prefix
 I111IoOo0oOOO0o . record_ttl = iiI
 if 2 - 2: II111iiii - OoOoOO00
 iI1IIII1ii1 += I111IoOo0oOOO0o . encode ( )
 I111IoOo0oOOO0o . print_record ( "  " , True )
 if 81 - 81: IiII / OOooOOo / OoooooooOO + II111iiii - OOooOOo . i11iIiiIii
 if 33 - 33: o0oOOo0O0Ooo - OoooooooOO
 if 30 - 30: i1IIi + II111iiii + OoOoOO00 + I1ii11iIi11i % ooOoO0o % OOooOOo
 if 40 - 40: I1IiiI % I1IiiI - i11iIiiIii % OoOoOO00
 if ( OOOoo0ooooo0 != 0 ) :
  for ooOiiI1Ii11 in I11 . delegation_set :
   i1iIiII = lisp_rloc_record ( )
   i1iIiII . rloc = ooOiiI1Ii11 . delegate_address
   i1iIiII . priority = ooOiiI1Ii11 . priority
   i1iIiII . weight = ooOiiI1Ii11 . weight
   i1iIiII . mpriority = 255
   i1iIiII . mweight = 0
   i1iIiII . reach_bit = True
   iI1IIII1ii1 += i1iIiII . encode ( )
   i1iIiII . print_record ( "    " )
   if 17 - 17: ooOoO0o - i1IIi
   if 73 - 73: iIii1I11I1II1 - I1Ii111 % Oo0Ooo . O0
   if 16 - 16: OoO0O00 / Oo0Ooo / IiII . Oo0Ooo - OoooooooOO
   if 5 - 5: OoOoOO00 . I11i
   if 28 - 28: I11i % OOooOOo + Oo0Ooo / OoO0O00 % o0oOOo0O0Ooo + OoO0O00
   if 20 - 20: ooOoO0o . iII111i % OOooOOo + i11iIiiIii
   if 64 - 64: i1IIi . o0oOOo0O0Ooo * I1Ii111 - O0
 if ( map_request . nonce != 0 ) : port = LISP_CTRL_PORT
 lisp_send_map_referral ( lisp_sockets , iI1IIII1ii1 , ecm_source , port )
 return
 if 76 - 76: I1IiiI % Ii1I + OoO0O00 + I1ii11iIi11i * II111iiii + Oo0Ooo
 if 3 - 3: Ii1I - I1IiiI + O0
 if 90 - 90: Ii1I + OoooooooOO . i11iIiiIii / Oo0Ooo % OoOoOO00 / IiII
 if 45 - 45: OoooooooOO / oO0o . I1ii11iIi11i + OOooOOo
 if 54 - 54: Ii1I - o0oOOo0O0Ooo + OoOoOO00 / OoooooooOO
 if 61 - 61: I11i / IiII % OoooooooOO - i11iIiiIii * i1IIi % o0oOOo0O0Ooo
 if 67 - 67: o0oOOo0O0Ooo - Ii1I
 if 29 - 29: OoOoOO00 . I1ii11iIi11i
def lisp_send_negative_map_reply ( sockets , eid , group , nonce , dest , port , ttl ,
 xtr_id , pubsub ) :
 if 24 - 24: OOooOOo + i1IIi . I11i . OoOoOO00 + OoooooooOO
 lprint ( "Build negative Map-Reply EID-prefix {}, nonce 0x{} to ITR {}" . format ( lisp_print_eid_tuple ( eid , group ) , lisp_hex_string ( nonce ) ,
 # I1IiiI + i1IIi * I1IiiI / Oo0Ooo . IiII . OoO0O00
 red ( dest . print_address ( ) , False ) ) )
 if 20 - 20: II111iiii . IiII
 I11IiIi1I = LISP_NATIVE_FORWARD_ACTION if group . is_null ( ) else LISP_DROP_ACTION
 if 10 - 10: IiII / OoooooooOO * IiII
 if 22 - 22: I1ii11iIi11i * OoooooooOO
 if 22 - 22: II111iiii . Ii1I + iIii1I11I1II1
 if 91 - 91: II111iiii / iIii1I11I1II1 / OoOoOO00 . II111iiii
 if 58 - 58: OoOoOO00 - II111iiii
 if ( lisp_get_eid_hash ( eid ) != None ) :
  I11IiIi1I = LISP_SEND_MAP_REQUEST_ACTION
  if 77 - 77: I1ii11iIi11i
  if 72 - 72: I1IiiI - i1IIi
 iI1IIII1ii1 = lisp_build_map_reply ( eid , group , [ ] , nonce , I11IiIi1I , ttl , False ,
 None , False , False )
 if 11 - 11: iIii1I11I1II1 . OoO0O00 * Ii1I
 if 65 - 65: Oo0Ooo / OoooooooOO
 if 60 - 60: II111iiii + I1IiiI % oO0o - o0oOOo0O0Ooo
 if 50 - 50: iIii1I11I1II1 - i11iIiiIii / iII111i + ooOoO0o / OOooOOo
 if ( pubsub ) :
  lisp_process_pubsub ( sockets , iI1IIII1ii1 , eid , dest , port , nonce , ttl ,
 xtr_id )
 else :
  lisp_send_map_reply ( sockets , iI1IIII1ii1 , dest , port )
  if 80 - 80: IiII / OoooooooOO
 return
 if 69 - 69: OoOoOO00 + IiII
 if 18 - 18: O0 / I11i
 if 10 - 10: I1Ii111 * i1IIi
 if 48 - 48: Oo0Ooo % i1IIi / iII111i . O0
 if 27 - 27: I11i + iIii1I11I1II1 - i11iIiiIii
 if 81 - 81: I11i + oO0o * iIii1I11I1II1 * IiII
 if 7 - 7: I11i - I1IiiI . iII111i + O0 / iIii1I11I1II1 - I1Ii111
def lisp_retransmit_ddt_map_request ( mr ) :
 iii11i1i1II11 = mr . mr_source . print_address ( )
 OoOoOooOOOOO0 = mr . print_eid_tuple ( )
 iIiIi1i1Iiii = mr . nonce
 if 51 - 51: O0 . O0
 if 9 - 9: Oo0Ooo . i1IIi - i1IIi + I1Ii111 * ooOoO0o . I1ii11iIi11i
 if 17 - 17: I11i * I1ii11iIi11i % I1IiiI + OoO0O00 + IiII
 if 90 - 90: OoooooooOO - I1IiiI / I1ii11iIi11i + oO0o - o0oOOo0O0Ooo
 if 84 - 84: OoOoOO00 + O0 % Oo0Ooo
 if ( mr . last_request_sent_to ) :
  iiii1I1I11 = mr . last_request_sent_to . print_address ( )
  OOO0OoOooO0 = lisp_referral_cache_lookup ( mr . last_cached_prefix [ 0 ] ,
 mr . last_cached_prefix [ 1 ] , True )
  if ( OOO0OoOooO0 and OOO0OoOooO0 . referral_set . has_key ( iiii1I1I11 ) ) :
   OOO0OoOooO0 . referral_set [ iiii1I1I11 ] . no_responses += 1
   if 2 - 2: Ii1I * O0 . II111iiii
   if 39 - 39: iII111i + iIii1I11I1II1 / Ii1I . IiII
   if 35 - 35: ooOoO0o - oO0o
   if 24 - 24: OoooooooOO / i1IIi / Ii1I
   if 77 - 77: iII111i / OoO0O00 % Oo0Ooo % OoOoOO00 % IiII / II111iiii
   if 82 - 82: I1Ii111 + O0 . I1IiiI / I1ii11iIi11i % II111iiii
   if 46 - 46: O0 - I1IiiI + OoooooooOO / OoOoOO00
 if ( mr . retry_count == LISP_MAX_MAP_NOTIFY_RETRIES ) :
  lprint ( "DDT Map-Request retry limit reached for EID {}, nonce 0x{}" . format ( green ( OoOoOooOOOOO0 , False ) , lisp_hex_string ( iIiIi1i1Iiii ) ) )
  if 76 - 76: I1ii11iIi11i - ooOoO0o % OoooooooOO / Oo0Ooo % IiII / ooOoO0o
  mr . dequeue_map_request ( )
  return
  if 57 - 57: O0
  if 23 - 23: OoO0O00 / II111iiii . I1ii11iIi11i . O0
 mr . retry_count += 1
 if 13 - 13: I1ii11iIi11i
 i1I1iIi1IiI = green ( iii11i1i1II11 , False )
 i1i11ii1Ii = green ( OoOoOooOOOOO0 , False )
 lprint ( "Retransmit DDT {} from {}ITR {} EIDs: {} -> {}, nonce 0x{}" . format ( bold ( "Map-Request" , False ) , "P" if mr . from_pitr else "" ,
 # i1IIi * OOooOOo
 red ( mr . itr . print_address ( ) , False ) , i1I1iIi1IiI , i1i11ii1Ii ,
 lisp_hex_string ( iIiIi1i1Iiii ) ) )
 if 35 - 35: I1Ii111 / Oo0Ooo * OoooooooOO / O0 / iIii1I11I1II1
 if 44 - 44: o0oOOo0O0Ooo / iIii1I11I1II1
 if 40 - 40: OoO0O00 / O0
 if 60 - 60: iIii1I11I1II1 / Oo0Ooo / oO0o + iII111i
 lisp_send_ddt_map_request ( mr , False )
 if 66 - 66: iIii1I11I1II1 . O0 * IiII . ooOoO0o + i1IIi
 if 83 - 83: o0oOOo0O0Ooo / II111iiii + I1IiiI - iII111i + OoO0O00
 if 67 - 67: I1Ii111 - OoOoOO00 . i11iIiiIii - I1Ii111 . i11iIiiIii
 if 25 - 25: I11i % I1Ii111 + Ii1I
 mr . retransmit_timer = threading . Timer ( LISP_DDT_MAP_REQUEST_INTERVAL ,
 lisp_retransmit_ddt_map_request , [ mr ] )
 mr . retransmit_timer . start ( )
 return
 if 46 - 46: ooOoO0o + Oo0Ooo + oO0o / II111iiii . iIii1I11I1II1 * I1IiiI
 if 87 - 87: I11i + iIii1I11I1II1
 if 91 - 91: oO0o
 if 58 - 58: i11iIiiIii / Ii1I - OoooooooOO
 if 25 - 25: i1IIi * ooOoO0o % OOooOOo / I1IiiI
 if 75 - 75: i11iIiiIii
 if 38 - 38: iIii1I11I1II1
 if 80 - 80: OoO0O00
def lisp_get_referral_node ( referral , source_eid , dest_eid ) :
 if 72 - 72: I11i * II111iiii
 if 82 - 82: I1Ii111 . OoO0O00 * II111iiii
 if 99 - 99: iIii1I11I1II1 / iII111i % i1IIi - II111iiii / OoO0O00
 if 33 - 33: OoooooooOO / i1IIi . Ii1I
 OOoO = [ ]
 for iI1I111iI1I1I in referral . referral_set . values ( ) :
  if ( iI1I111iI1I1I . updown == False ) : continue
  if ( len ( OOoO ) == 0 or OOoO [ 0 ] . priority == iI1I111iI1I1I . priority ) :
   OOoO . append ( iI1I111iI1I1I )
  elif ( OOoO [ 0 ] . priority > iI1I111iI1I1I . priority ) :
   OOoO = [ ]
   OOoO . append ( iI1I111iI1I1I )
   if 7 - 7: I1IiiI - OOooOOo % II111iiii / I1IiiI / i1IIi
   if 59 - 59: O0
   if 38 - 38: IiII . IiII
 oo00OO = len ( OOoO )
 if ( oo00OO == 0 ) : return ( None )
 if 49 - 49: iIii1I11I1II1 % Oo0Ooo % I11i * Ii1I - OoO0O00
 oO000o0o0oOo0 = dest_eid . hash_address ( source_eid )
 oO000o0o0oOo0 = oO000o0o0oOo0 % oo00OO
 return ( OOoO [ oO000o0o0oOo0 ] )
 if 15 - 15: i11iIiiIii + o0oOOo0O0Ooo . Ii1I . I1IiiI
 if 8 - 8: iII111i % II111iiii + IiII
 if 5 - 5: i1IIi + II111iiii
 if 75 - 75: OOooOOo . IiII . I1IiiI + OoooooooOO
 if 35 - 35: I11i % i1IIi - I1ii11iIi11i . Oo0Ooo
 if 69 - 69: ooOoO0o * OoO0O00 % o0oOOo0O0Ooo * o0oOOo0O0Ooo
 if 35 - 35: I1IiiI . OOooOOo * OoO0O00 . I1ii11iIi11i - I1IiiI
def lisp_send_ddt_map_request ( mr , send_to_root ) :
 iiiII1i1i1iII = mr . lisp_sockets
 iIiIi1i1Iiii = mr . nonce
 iIi1 = mr . itr
 i1IIIii1III1 = mr . mr_source
 oo0ooooO = mr . print_eid_tuple ( )
 if 90 - 90: IiII % I1ii11iIi11i - I1ii11iIi11i - iII111i
 if 63 - 63: O0 % i1IIi + OoOoOO00 + I11i . IiII + ooOoO0o
 if 19 - 19: O0 - i1IIi / I1Ii111
 if 14 - 14: I11i - i11iIiiIii
 if 49 - 49: oO0o . I1ii11iIi11i
 if ( mr . send_count == 8 ) :
  lprint ( "Giving up on map-request-queue entry {}, nonce 0x{}" . format ( green ( oo0ooooO , False ) , lisp_hex_string ( iIiIi1i1Iiii ) ) )
  if 51 - 51: OOooOOo + o0oOOo0O0Ooo . OOooOOo
  mr . dequeue_map_request ( )
  return
  if 23 - 23: iIii1I11I1II1 + OoO0O00 / I1IiiI
  if 48 - 48: OoOoOO00 + I11i + oO0o . I1IiiI
  if 7 - 7: iII111i * i1IIi % OoOoOO00 % Ii1I . I1IiiI
  if 53 - 53: OOooOOo / I11i + OOooOOo / I1IiiI / OoO0O00
  if 12 - 12: i11iIiiIii % ooOoO0o / iII111i . IiII
  if 68 - 68: OOooOOo / iIii1I11I1II1 + I1IiiI . ooOoO0o * IiII
 if ( send_to_root ) :
  oOoOO0oOOoO0o = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  iI1I = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  mr . tried_root = True
  lprint ( "Jumping up to root for EID {}" . format ( green ( oo0ooooO , False ) ) )
 else :
  oOoOO0oOOoO0o = mr . eid
  iI1I = mr . group
  if 28 - 28: i1IIi
  if 69 - 69: OOooOOo % ooOoO0o - i1IIi . Oo0Ooo
  if 35 - 35: iIii1I11I1II1 - I11i / iIii1I11I1II1 % ooOoO0o % I1IiiI
  if 46 - 46: oO0o
  if 5 - 5: i1IIi % o0oOOo0O0Ooo + OoOoOO00 - I11i . Ii1I
 iiIiI1III111 = lisp_referral_cache_lookup ( oOoOO0oOOoO0o , iI1I , False )
 if ( iiIiI1III111 == None ) :
  lprint ( "No referral cache entry found" )
  lisp_send_negative_map_reply ( iiiII1i1i1iII , oOoOO0oOOoO0o , iI1I ,
 iIiIi1i1Iiii , iIi1 , mr . sport , 15 , None , False )
  return
  if 8 - 8: I1ii11iIi11i
  if 45 - 45: i1IIi - OoO0O00 % Oo0Ooo
 i1111I1I = iiIiI1III111 . print_eid_tuple ( )
 lprint ( "Found referral cache entry {}, referral-type: {}" . format ( i1111I1I ,
 iiIiI1III111 . print_referral_type ( ) ) )
 if 66 - 66: iII111i - ooOoO0o * I1ii11iIi11i - Ii1I / OoooooooOO
 iI1I111iI1I1I = lisp_get_referral_node ( iiIiI1III111 , i1IIIii1III1 , mr . eid )
 if ( iI1I111iI1I1I == None ) :
  lprint ( "No reachable referral-nodes found" )
  mr . dequeue_map_request ( )
  lisp_send_negative_map_reply ( iiiII1i1i1iII , iiIiI1III111 . eid ,
 iiIiI1III111 . group , iIiIi1i1Iiii , iIi1 , mr . sport , 1 , None , False )
  return
  if 86 - 86: I1IiiI % iII111i + Oo0Ooo + i1IIi % o0oOOo0O0Ooo
  if 85 - 85: Ii1I + I1Ii111 * I11i
 lprint ( "Send DDT Map-Request to {} {} for EID {}, nonce 0x{}" . format ( iI1I111iI1I1I . referral_address . print_address ( ) ,
 # Oo0Ooo . OoO0O00 + OoooooooOO + I1Ii111
 iiIiI1III111 . print_referral_type ( ) , green ( oo0ooooO , False ) ,
 lisp_hex_string ( iIiIi1i1Iiii ) ) )
 if 57 - 57: Ii1I % Ii1I * Oo0Ooo % i11iIiiIii
 if 12 - 12: oO0o . Oo0Ooo . I1IiiI - i11iIiiIii / o0oOOo0O0Ooo
 if 54 - 54: i11iIiiIii + I1Ii111 . I1Ii111 * I1ii11iIi11i % I1Ii111 - OoooooooOO
 if 76 - 76: IiII + i1IIi + i11iIiiIii . oO0o
 I1IIiII1 = ( iiIiI1III111 . referral_type == LISP_DDT_ACTION_MS_REFERRAL or
 iiIiI1III111 . referral_type == LISP_DDT_ACTION_MS_ACK )
 lisp_send_ecm ( iiiII1i1i1iII , mr . packet , i1IIIii1III1 , mr . sport , mr . eid ,
 iI1I111iI1I1I . referral_address , to_ms = I1IIiII1 , ddt = True )
 if 35 - 35: iII111i / iII111i * OoOoOO00 - i11iIiiIii
 if 27 - 27: i1IIi / I11i + I1Ii111 . II111iiii * OoO0O00
 if 55 - 55: i1IIi % Ii1I - o0oOOo0O0Ooo - o0oOOo0O0Ooo
 if 6 - 6: i1IIi
 mr . last_request_sent_to = iI1I111iI1I1I . referral_address
 mr . last_sent = lisp_get_timestamp ( )
 mr . send_count += 1
 iI1I111iI1I1I . map_requests_sent += 1
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
 i1OO0o = map_request . target_eid
 Oo000o0o0 = map_request . target_group
 OoOoOooOOOOO0 = map_request . print_eid_tuple ( )
 iii11i1i1II11 = mr_source . print_address ( )
 iIiIi1i1Iiii = map_request . nonce
 if 66 - 66: I1IiiI + I11i
 i1I1iIi1IiI = green ( iii11i1i1II11 , False )
 i1i11ii1Ii = green ( OoOoOooOOOOO0 , False )
 lprint ( "Received Map-Request from {}ITR {} EIDs: {} -> {}, nonce 0x{}" . format ( "P" if map_request . pitr_bit else "" ,
 # I1ii11iIi11i . OoooooooOO . oO0o - I11i
 red ( ecm_source . print_address ( ) , False ) , i1I1iIi1IiI , i1i11ii1Ii ,
 lisp_hex_string ( iIiIi1i1Iiii ) ) )
 if 59 - 59: Ii1I / o0oOOo0O0Ooo / OoO0O00 + IiII + i11iIiiIii
 if 64 - 64: o0oOOo0O0Ooo * IiII * IiII * iII111i % i11iIiiIii
 if 22 - 22: I1ii11iIi11i * II111iiii - OOooOOo % i11iIiiIii
 if 10 - 10: OOooOOo / I1ii11iIi11i
 IIiIII1IIi = lisp_ddt_map_request ( lisp_sockets , packet , i1OO0o , Oo000o0o0 , iIiIi1i1Iiii )
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
 O0ooO00OO = packet
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
  packet = O0ooO00OO
  i1OO0o , Oo000o0o0 , iI11IIii1Ii = lisp_ms_process_map_request ( lisp_sockets ,
 O0ooO00OO , O00O0 , mr_source , mr_port , ecm_source )
  if ( ddt_request ) :
   lisp_ms_send_map_referral ( lisp_sockets , O00O0 , ecm_source ,
 ecm_port , iI11IIii1Ii , i1OO0o , Oo000o0o0 )
   if 62 - 62: OoooooooOO * Oo0Ooo * iIii1I11I1II1 % I1IiiI . i11iIiiIii + I11i
  return
  if 78 - 78: Ii1I % Oo0Ooo / OoO0O00 . iIii1I11I1II1 . II111iiii
  if 67 - 67: oO0o % I1Ii111
  if 72 - 72: I1IiiI . i11iIiiIii . OoOoOO00 + I1IiiI - I1Ii111 + iII111i
  if 15 - 15: I1IiiI
  if 88 - 88: IiII / I1ii11iIi11i % I11i + i11iIiiIii * O0 . I1Ii111
 if ( lisp_i_am_mr and not ddt_request ) :
  lisp_mr_process_map_request ( lisp_sockets , O0ooO00OO , O00O0 ,
 ecm_source , mr_port , mr_source )
  if 69 - 69: Oo0Ooo - OOooOOo / I1IiiI . i11iIiiIii * OoO0O00
  if 45 - 45: I1Ii111 + OOooOOo
  if 78 - 78: OoOoOO00 . Oo0Ooo % I11i
  if 7 - 7: I1ii11iIi11i % Ii1I . OoooooooOO - iII111i
  if 18 - 18: O0 * OoooooooOO % IiII - iIii1I11I1II1 % IiII * o0oOOo0O0Ooo
 if ( lisp_i_am_ddt or ddt_request ) :
  packet = O0ooO00OO
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
 OOO0iI1 = lisp_map_reply ( )
 packet = OOO0iI1 . decode ( packet )
 if ( packet == None ) :
  lprint ( "Could not decode Map-Reply packet" )
  return
  if 67 - 67: iII111i - OoO0O00 % I1ii11iIi11i * Oo0Ooo
 OOO0iI1 . print_map_reply ( )
 if 51 - 51: I1IiiI + O0
 if 4 - 4: ooOoO0o / OoO0O00 * iIii1I11I1II1 * iIii1I11I1II1
 if 33 - 33: iII111i . iIii1I11I1II1 - Ii1I
 if 85 - 85: OoOoOO00
 OOOo0OOO = None
 for oO in range ( OOO0iI1 . record_count ) :
  I111IoOo0oOOO0o = lisp_eid_record ( )
  packet = I111IoOo0oOOO0o . decode ( packet )
  if ( packet == None ) :
   lprint ( "Could not decode EID-record in Map-Reply packet" )
   return
   if 64 - 64: I1IiiI % ooOoO0o
  I111IoOo0oOOO0o . print_record ( "  " , False )
  if 78 - 78: I11i / Ii1I . IiII / o0oOOo0O0Ooo / OoO0O00 + OoOoOO00
  if 50 - 50: Ii1I
  if 84 - 84: iII111i % II111iiii
  if 31 - 31: I11i
  if 28 - 28: i11iIiiIii + IiII / I11i . Ii1I / OoO0O00
  if ( I111IoOo0oOOO0o . rloc_count == 0 ) :
   lisp_store_mr_stats ( source , OOO0iI1 . nonce )
   if 100 - 100: o0oOOo0O0Ooo - I11i . o0oOOo0O0Ooo
   if 90 - 90: OoOoOO00 / II111iiii / I11i * I11i - iIii1I11I1II1
  o0OoOO00O0O0 = ( I111IoOo0oOOO0o . group . is_null ( ) == False )
  if 84 - 84: ooOoO0o * OOooOOo / I1Ii111 * I1IiiI * ooOoO0o
  if 75 - 75: oO0o
  if 60 - 60: OoOoOO00 % I1IiiI . i11iIiiIii % OoOoOO00 - I1Ii111
  if 71 - 71: OoooooooOO * Oo0Ooo
  if 80 - 80: iIii1I11I1II1
  if ( lisp_decent_push_configured ) :
   I11IiIi1I = I111IoOo0oOOO0o . action
   if ( o0OoOO00O0O0 and I11IiIi1I == LISP_DROP_ACTION ) :
    if ( I111IoOo0oOOO0o . eid . is_local ( ) ) : continue
    if 91 - 91: OoOoOO00 + OoOoOO00 + ooOoO0o
    if 44 - 44: I1ii11iIi11i * OOooOOo % OoO0O00 . I1IiiI % Ii1I + II111iiii
    if 100 - 100: oO0o - II111iiii . o0oOOo0O0Ooo
    if 63 - 63: OoOoOO00 % IiII . iII111i
    if 44 - 44: I1IiiI
    if 25 - 25: oO0o
    if 100 - 100: I1IiiI / IiII + OoO0O00 . iII111i
  if ( I111IoOo0oOOO0o . eid . is_null ( ) ) : continue
  if 39 - 39: OoooooooOO * OOooOOo - OoO0O00
  if 3 - 3: I11i . i11iIiiIii % Oo0Ooo % II111iiii . I11i
  if 88 - 88: iIii1I11I1II1 . OOooOOo % iII111i
  if 72 - 72: ooOoO0o + i11iIiiIii / i1IIi
  if 64 - 64: OOooOOo - OOooOOo
  if ( o0OoOO00O0O0 ) :
   Iii1 = lisp_map_cache_lookup ( I111IoOo0oOOO0o . eid , I111IoOo0oOOO0o . group )
  else :
   Iii1 = lisp_map_cache . lookup_cache ( I111IoOo0oOOO0o . eid , True )
   if 75 - 75: OOooOOo + IiII + ooOoO0o / I1IiiI . iIii1I11I1II1 / Oo0Ooo
  O0OooOOooo0 = ( Iii1 == None )
  if 67 - 67: ooOoO0o . I1Ii111 . Oo0Ooo . Ii1I + iIii1I11I1II1 / OoooooooOO
  if 93 - 93: ooOoO0o * OoO0O00 - I1Ii111 / I1ii11iIi11i
  if 60 - 60: OoO0O00 / oO0o . I1IiiI + OoOoOO00 + I1ii11iIi11i % Ii1I
  if 70 - 70: i1IIi * II111iiii * I1IiiI
  oOo0oOOOoOoo = [ ]
  for Ii1i1Ii in range ( I111IoOo0oOOO0o . rloc_count ) :
   i1iIiII = lisp_rloc_record ( )
   i1iIiII . keys = OOO0iI1 . keys
   packet = i1iIiII . decode ( packet , OOO0iI1 . nonce )
   if ( packet == None ) :
    lprint ( "Could not decode RLOC-record in Map-Reply packet" )
    return
    if 7 - 7: OoooooooOO + II111iiii / Oo0Ooo % O0 % OOooOOo . I1Ii111
   i1iIiII . print_record ( "    " )
   if 78 - 78: iIii1I11I1II1 % OOooOOo
   I1I1ii1 = None
   if ( Iii1 ) : I1I1ii1 = Iii1 . get_rloc ( i1iIiII . rloc )
   if ( I1I1ii1 ) :
    i1IIIIi1Ii111 = I1I1ii1
   else :
    i1IIIIi1Ii111 = lisp_rloc ( )
    if 17 - 17: I1ii11iIi11i . Ii1I / IiII - i1IIi - Ii1I
    if 95 - 95: IiII % I11i % iIii1I11I1II1 . OoO0O00
    if 11 - 11: i11iIiiIii - IiII . o0oOOo0O0Ooo / IiII - I1IiiI
    if 66 - 66: iIii1I11I1II1 . i1IIi . i11iIiiIii % I1ii11iIi11i * OOooOOo % IiII
    if 34 - 34: I1IiiI % I11i - iII111i - i11iIiiIii - iIii1I11I1II1 / i1IIi
    if 7 - 7: I1IiiI + iIii1I11I1II1 . oO0o
    if 17 - 17: OoO0O00 / OoO0O00 + o0oOOo0O0Ooo / OOooOOo . I1ii11iIi11i % IiII
   OOo0000o0 = i1IIIIi1Ii111 . store_rloc_from_record ( i1iIiII , OOO0iI1 . nonce ,
 source )
   i1IIIIi1Ii111 . echo_nonce_capable = OOO0iI1 . echo_nonce_capable
   if 40 - 40: OoOoOO00
   if ( i1IIIIi1Ii111 . echo_nonce_capable ) :
    OoOOoooO000 = i1IIIIi1Ii111 . rloc . print_address_no_iid ( )
    if ( lisp_get_echo_nonce ( None , OoOOoooO000 ) == None ) :
     lisp_echo_nonce ( OoOOoooO000 )
     if 81 - 81: Ii1I % I1Ii111 / I1ii11iIi11i % iII111i
     if 39 - 39: i1IIi . iII111i . Oo0Ooo % Oo0Ooo * IiII % Ii1I
     if 40 - 40: o0oOOo0O0Ooo * i11iIiiIii . ooOoO0o
     if 63 - 63: I1Ii111 / Ii1I - iIii1I11I1II1 / i11iIiiIii / IiII + I11i
     if 57 - 57: iIii1I11I1II1 % iIii1I11I1II1
     if 23 - 23: II111iiii . ooOoO0o % I1Ii111
     if 39 - 39: OoooooooOO
     if 10 - 10: Oo0Ooo * iII111i
     if 78 - 78: Oo0Ooo / i11iIiiIii - I1IiiI
     if 51 - 51: ooOoO0o / Oo0Ooo - I1Ii111 - iII111i
   if ( OOO0iI1 . rloc_probe and i1iIiII . probe_bit ) :
    if ( i1IIIIi1Ii111 . rloc . afi == source . afi ) :
     lisp_process_rloc_probe_reply ( i1IIIIi1Ii111 . rloc , source , OOo0000o0 ,
 OOO0iI1 . nonce , OOO0iI1 . hop_count , ttl )
     if 68 - 68: I1ii11iIi11i - iIii1I11I1II1 * OoooooooOO
     if 44 - 44: OoooooooOO + I1Ii111 + OoO0O00
     if 15 - 15: iIii1I11I1II1 % i1IIi + iII111i
     if 48 - 48: o0oOOo0O0Ooo / oO0o
     if 61 - 61: I1IiiI + iII111i * Ii1I % I1Ii111 . Ii1I
     if 83 - 83: i11iIiiIii * OoOoOO00 * i11iIiiIii % II111iiii . i11iIiiIii * I11i
   oOo0oOOOoOoo . append ( i1IIIIi1Ii111 )
   if 67 - 67: i1IIi / i1IIi + IiII . oO0o
   if 70 - 70: i1IIi . I11i * o0oOOo0O0Ooo . iII111i
   if 75 - 75: oO0o * OoO0O00 * I11i + oO0o + O0 . I1Ii111
   if 8 - 8: I1ii11iIi11i / i1IIi - I1ii11iIi11i + Ii1I + OoO0O00 - I11i
   if ( lisp_data_plane_security and i1IIIIi1Ii111 . rloc_recent_rekey ( ) ) :
    OOOo0OOO = i1IIIIi1Ii111
    if 79 - 79: OoooooooOO - I1Ii111 * I1IiiI . I1Ii111 - iIii1I11I1II1
    if 27 - 27: OoOoOO00 % OoOoOO00 % II111iiii
    if 45 - 45: iIii1I11I1II1 . o0oOOo0O0Ooo % I1IiiI
    if 10 - 10: I1IiiI / i1IIi * o0oOOo0O0Ooo + Oo0Ooo - OoOoOO00 % iII111i
    if 88 - 88: Ii1I % Ii1I
    if 29 - 29: OOooOOo % I1ii11iIi11i
    if 57 - 57: I1ii11iIi11i - OoOoOO00 + IiII
    if 58 - 58: OOooOOo % I1IiiI / oO0o . ooOoO0o . OoO0O00 / IiII
    if 72 - 72: ooOoO0o + ooOoO0o + o0oOOo0O0Ooo - o0oOOo0O0Ooo % Ii1I
    if 52 - 52: I11i % i1IIi . I1ii11iIi11i
    if 62 - 62: ooOoO0o - I1ii11iIi11i
  if ( OOO0iI1 . rloc_probe == False and lisp_nat_traversal ) :
   iiiI11II1IiIi = [ ]
   oOOoO0oOOO = [ ]
   for i1IIIIi1Ii111 in oOo0oOOOoOoo :
    if 58 - 58: OOooOOo
    if 51 - 51: iII111i + ooOoO0o / IiII * I1ii11iIi11i % I11i
    if 56 - 56: Ii1I % I1ii11iIi11i . i11iIiiIii - i11iIiiIii
    if 75 - 75: OOooOOo % I1ii11iIi11i
    if 40 - 40: I1IiiI / I1IiiI
    if ( i1IIIIi1Ii111 . rloc . is_private_address ( ) ) :
     i1IIIIi1Ii111 . priority = 1
     i1IIIIi1Ii111 . state = LISP_RLOC_UNREACH_STATE
     iiiI11II1IiIi . append ( i1IIIIi1Ii111 )
     oOOoO0oOOO . append ( i1IIIIi1Ii111 . rloc . print_address_no_iid ( ) )
     continue
     if 26 - 26: i11iIiiIii % OoO0O00 % Ii1I - ooOoO0o
     if 2 - 2: II111iiii . o0oOOo0O0Ooo * OoooooooOO + OoooooooOO
     if 18 - 18: II111iiii * OOooOOo * OoO0O00 * iIii1I11I1II1 % o0oOOo0O0Ooo / IiII
     if 95 - 95: I1ii11iIi11i + I1IiiI . OoooooooOO
     if 22 - 22: I1Ii111 / I1Ii111 / OOooOOo + OoOoOO00 % I1Ii111 / Ii1I
     if 14 - 14: o0oOOo0O0Ooo % i11iIiiIii + i11iIiiIii - I1ii11iIi11i % I1ii11iIi11i
    if ( i1IIIIi1Ii111 . priority == 254 and lisp_i_am_rtr == False ) :
     iiiI11II1IiIi . append ( i1IIIIi1Ii111 )
     oOOoO0oOOO . append ( i1IIIIi1Ii111 . rloc . print_address_no_iid ( ) )
     if 26 - 26: oO0o + OoooooooOO % o0oOOo0O0Ooo
    if ( i1IIIIi1Ii111 . priority != 254 and lisp_i_am_rtr ) :
     iiiI11II1IiIi . append ( i1IIIIi1Ii111 )
     oOOoO0oOOO . append ( i1IIIIi1Ii111 . rloc . print_address_no_iid ( ) )
     if 96 - 96: ooOoO0o * OoOoOO00 - II111iiii
     if 40 - 40: oO0o * OOooOOo + Ii1I + I11i * Ii1I + OoooooooOO
     if 77 - 77: OOooOOo + ooOoO0o / O0
   if ( oOOoO0oOOO != [ ] ) :
    oOo0oOOOoOoo = iiiI11II1IiIi
    lprint ( "NAT-traversal optimized RLOC-set: {}" . format ( oOOoO0oOOO ) )
    if 16 - 16: ooOoO0o + Oo0Ooo * Oo0Ooo . I11i - IiII
    if 49 - 49: ooOoO0o . Ii1I
    if 75 - 75: OOooOOo / II111iiii - Oo0Ooo + I1Ii111
    if 42 - 42: OoooooooOO * II111iiii + Ii1I % OoO0O00 / I1Ii111
    if 11 - 11: ooOoO0o / Oo0Ooo + i1IIi / IiII
    if 4 - 4: iII111i - Oo0Ooo
    if 100 - 100: OOooOOo . i1IIi
  iiiI11II1IiIi = [ ]
  for i1IIIIi1Ii111 in oOo0oOOOoOoo :
   if ( i1IIIIi1Ii111 . json != None ) : continue
   iiiI11II1IiIi . append ( i1IIIIi1Ii111 )
   if 15 - 15: O0 % Oo0Ooo % o0oOOo0O0Ooo . ooOoO0o * iII111i % O0
  if ( iiiI11II1IiIi != [ ] ) :
   o0OO0oooo = len ( oOo0oOOOoOoo ) - len ( iiiI11II1IiIi )
   lprint ( "Pruning {} no-address RLOC-records for map-cache" . format ( o0OO0oooo ) )
   if 31 - 31: i1IIi . Ii1I - OoooooooOO * I11i * ooOoO0o % oO0o
   oOo0oOOOoOoo = iiiI11II1IiIi
   if 61 - 61: I1Ii111 . Ii1I * I1ii11iIi11i
   if 59 - 59: OoOoOO00 + Oo0Ooo . I1ii11iIi11i - Ii1I
   if 48 - 48: I1Ii111 % Ii1I + I1IiiI * OoooooooOO % OoOoOO00 % i11iIiiIii
   if 13 - 13: iII111i % i1IIi
   if 13 - 13: iII111i / OoooooooOO + Ii1I / iII111i
   if 29 - 29: OOooOOo + ooOoO0o % o0oOOo0O0Ooo
   if 18 - 18: I11i + OoO0O00 + OoO0O00 . ooOoO0o
   if 37 - 37: i1IIi . IiII + I1IiiI % OoOoOO00
  if ( OOO0iI1 . rloc_probe and Iii1 != None ) : oOo0oOOOoOoo = Iii1 . rloc_set
  if 3 - 3: i11iIiiIii + Ii1I % IiII - I1Ii111 / Oo0Ooo % iIii1I11I1II1
  if 86 - 86: Oo0Ooo + Oo0Ooo * oO0o * I1IiiI
  if 95 - 95: IiII - OoO0O00 + OOooOOo
  if 33 - 33: o0oOOo0O0Ooo . i11iIiiIii . ooOoO0o
  if 100 - 100: i11iIiiIii % I1Ii111 - OoO0O00 + I1Ii111 / i11iIiiIii + OOooOOo
  Ooo0O = O0OooOOooo0
  if ( Iii1 and oOo0oOOOoOoo != Iii1 . rloc_set ) :
   Iii1 . delete_rlocs_from_rloc_probe_list ( )
   Ooo0O = True
   if 69 - 69: iII111i - OoOoOO00 / O0
   if 22 - 22: o0oOOo0O0Ooo % OoooooooOO + oO0o + Oo0Ooo
   if 34 - 34: iII111i / I11i + i1IIi + I1ii11iIi11i * OoooooooOO * IiII
   if 70 - 70: iIii1I11I1II1 / I1IiiI * OoOoOO00 / IiII / II111iiii + I1IiiI
   if 33 - 33: oO0o
  II = Iii1 . uptime if ( Iii1 ) else None
  Iii1 = lisp_mapping ( I111IoOo0oOOO0o . eid , I111IoOo0oOOO0o . group , oOo0oOOOoOoo )
  Iii1 . mapping_source = source
  Iii1 . map_cache_ttl = I111IoOo0oOOO0o . store_ttl ( )
  Iii1 . action = I111IoOo0oOOO0o . action
  Iii1 . add_cache ( Ooo0O )
  if 76 - 76: OoOoOO00
  OoOoOoO0ooOOo0oO = "Add"
  if ( II ) :
   Iii1 . uptime = II
   OoOoOoO0ooOOo0oO = "Replace"
   if 21 - 21: Oo0Ooo - II111iiii + I11i
   if 69 - 69: Oo0Ooo - iIii1I11I1II1 . oO0o
  lprint ( "{} {} map-cache with {} RLOCs" . format ( OoOoOoO0ooOOo0oO ,
 green ( Iii1 . print_eid_tuple ( ) , False ) , len ( oOo0oOOOoOoo ) ) )
  if 54 - 54: Ii1I / Oo0Ooo - i1IIi * OoooooooOO - OoOoOO00 + OoOoOO00
  if 24 - 24: i1IIi . OoOoOO00 / I1Ii111 + O0
  if 86 - 86: Ii1I * OoOoOO00 % I1ii11iIi11i + OOooOOo
  if 85 - 85: iII111i % i11iIiiIii
  if 78 - 78: i11iIiiIii / I11i / Oo0Ooo + II111iiii - I1ii11iIi11i / I1ii11iIi11i
  if ( lisp_ipc_dp_socket and OOOo0OOO != None ) :
   lisp_write_ipc_keys ( OOOo0OOO )
   if 28 - 28: iIii1I11I1II1 / IiII - iIii1I11I1II1 . i1IIi - O0 * ooOoO0o
   if 41 - 41: Ii1I + IiII
   if 37 - 37: I1Ii111 / o0oOOo0O0Ooo - ooOoO0o - OoooooooOO . I1ii11iIi11i % I1Ii111
   if 53 - 53: I1IiiI % OOooOOo + Ii1I - Ii1I
   if 99 - 99: i1IIi * OoOoOO00 - i1IIi
   if 65 - 65: OoO0O00 / i11iIiiIii + I1ii11iIi11i + OoOoOO00
   if 82 - 82: Ii1I * OOooOOo % ooOoO0o / OoO0O00 - Oo0Ooo . I1Ii111
  if ( O0OooOOooo0 ) :
   O00oOoo0OoOOO = bold ( "RLOC-probe" , False )
   for i1IIIIi1Ii111 in Iii1 . best_rloc_set :
    OoOOoooO000 = red ( i1IIIIi1Ii111 . rloc . print_address_no_iid ( ) , False )
    lprint ( "Trigger {} to {}" . format ( O00oOoo0OoOOO , OoOOoooO000 ) )
    lisp_send_map_request ( lisp_sockets , 0 , Iii1 . eid , Iii1 . group , i1IIIIi1Ii111 )
    if 2 - 2: I11i % iIii1I11I1II1 + I1IiiI + I1ii11iIi11i
    if 85 - 85: OoO0O00 * oO0o / I11i - iII111i - OOooOOo - ooOoO0o
    if 68 - 68: I11i + Ii1I
 return
 if 70 - 70: I11i + oO0o + o0oOOo0O0Ooo . I1Ii111 * i11iIiiIii
 if 46 - 46: O0 . i11iIiiIii / OoO0O00 - iIii1I11I1II1 . iIii1I11I1II1
 if 39 - 39: i11iIiiIii + I1Ii111
 if 49 - 49: i1IIi * iII111i - iIii1I11I1II1 % I11i * O0 / OoOoOO00
 if 48 - 48: IiII
 if 69 - 69: o0oOOo0O0Ooo % i11iIiiIii - OOooOOo - o0oOOo0O0Ooo
 if 98 - 98: o0oOOo0O0Ooo * OoO0O00 . OoooooooOO
 if 40 - 40: I1Ii111 + Oo0Ooo + I1Ii111
def lisp_compute_auth ( packet , map_register , password ) :
 if ( map_register . alg_id == LISP_NONE_ALG_ID ) : return ( packet )
 if 57 - 57: I1Ii111 / II111iiii % iII111i
 packet = map_register . zero_auth ( packet )
 oO000o0o0oOo0 = lisp_hash_me ( packet , map_register . alg_id , password , False )
 if 32 - 32: IiII - OOooOOo + i11iIiiIii + I1IiiI . iII111i
 if 75 - 75: o0oOOo0O0Ooo % o0oOOo0O0Ooo . I1IiiI / OoO0O00
 if 22 - 22: Oo0Ooo / iIii1I11I1II1 + o0oOOo0O0Ooo
 if 16 - 16: II111iiii . Ii1I + I1Ii111 % i1IIi / i11iIiiIii + OOooOOo
 map_register . auth_data = oO000o0o0oOo0
 packet = map_register . encode_auth ( packet )
 return ( packet )
 if 43 - 43: I1IiiI . Oo0Ooo + i1IIi + I11i / OoO0O00
 if 66 - 66: i11iIiiIii
 if 83 - 83: I1Ii111 / iIii1I11I1II1 - oO0o
 if 3 - 3: OOooOOo - Oo0Ooo * I1IiiI - OoO0O00 / OOooOOo + IiII
 if 83 - 83: i1IIi * i1IIi - II111iiii / OoooooooOO . Ii1I + I1Ii111
 if 10 - 10: I11i
 if 24 - 24: Ii1I
def lisp_hash_me ( packet , alg_id , password , do_hex ) :
 if ( alg_id == LISP_NONE_ALG_ID ) : return ( True )
 if 30 - 30: II111iiii / Ii1I - I11i - OoO0O00
 if ( alg_id == LISP_SHA_1_96_ALG_ID ) :
  I1ii11i1111 = hashlib . sha1
  if 55 - 55: OoooooooOO + I1IiiI / Oo0Ooo % O0 % I1ii11iIi11i
 if ( alg_id == LISP_SHA_256_128_ALG_ID ) :
  I1ii11i1111 = hashlib . sha256
  if 95 - 95: i11iIiiIii + I1ii11iIi11i
  if 97 - 97: ooOoO0o * iIii1I11I1II1 * i1IIi * II111iiii - OOooOOo - o0oOOo0O0Ooo
 if ( do_hex ) :
  oO000o0o0oOo0 = hmac . new ( password , packet , I1ii11i1111 ) . hexdigest ( )
 else :
  oO000o0o0oOo0 = hmac . new ( password , packet , I1ii11i1111 ) . digest ( )
  if 37 - 37: II111iiii
 return ( oO000o0o0oOo0 )
 if 27 - 27: Oo0Ooo * OoooooooOO / I1IiiI
 if 43 - 43: OoO0O00
 if 51 - 51: OoooooooOO % IiII % Oo0Ooo
 if 50 - 50: I1IiiI - i11iIiiIii / I1ii11iIi11i . Ii1I - iIii1I11I1II1
 if 91 - 91: I1IiiI . I1Ii111 + II111iiii . Oo0Ooo
 if 95 - 95: iII111i
 if 77 - 77: I1IiiI * II111iiii * iIii1I11I1II1
 if 19 - 19: OOooOOo * o0oOOo0O0Ooo
def lisp_verify_auth ( packet , alg_id , auth_data , password ) :
 if ( alg_id == LISP_NONE_ALG_ID ) : return ( True )
 if 64 - 64: I11i % ooOoO0o / OOooOOo / iII111i
 oO000o0o0oOo0 = lisp_hash_me ( packet , alg_id , password , True )
 o0Oo = ( oO000o0o0oOo0 == auth_data )
 if 60 - 60: i11iIiiIii + o0oOOo0O0Ooo / OoooooooOO
 if 25 - 25: OoooooooOO / iII111i * OOooOOo
 if 1 - 1: OOooOOo / II111iiii / II111iiii % OoO0O00 % iIii1I11I1II1
 if 36 - 36: I1IiiI / O0
 if ( o0Oo == False ) :
  lprint ( "Hashed value: {} does not match packet value: {}" . format ( oO000o0o0oOo0 , auth_data ) )
  if 20 - 20: OoooooooOO + o0oOOo0O0Ooo . IiII * O0 + i11iIiiIii
  if 67 - 67: ooOoO0o . Oo0Ooo
 return ( o0Oo )
 if 15 - 15: OoO0O00 . oO0o - o0oOOo0O0Ooo
 if 28 - 28: OOooOOo * OoOoOO00 + OoooooooOO . OOooOOo / oO0o / OoOoOO00
 if 94 - 94: OoO0O00 / i1IIi . OoO0O00 . I1Ii111 + OoO0O00
 if 30 - 30: o0oOOo0O0Ooo + iIii1I11I1II1 - II111iiii - ooOoO0o + OoOoOO00 - II111iiii
 if 69 - 69: oO0o / O0 / I1IiiI + OoooooooOO * I11i * IiII
 if 41 - 41: ooOoO0o % i11iIiiIii
 if 69 - 69: IiII - oO0o
def lisp_retransmit_map_notify ( map_notify ) :
 iiIi1I = map_notify . etr
 OOo0000o0 = map_notify . etr_port
 if 21 - 21: Oo0Ooo / I1Ii111
 if 72 - 72: OoOoOO00 . i11iIiiIii
 if 25 - 25: i1IIi
 if 69 - 69: OOooOOo / Ii1I
 if 67 - 67: i11iIiiIii . II111iiii + OoooooooOO % o0oOOo0O0Ooo + IiII * i1IIi
 if ( map_notify . retry_count == LISP_MAX_MAP_NOTIFY_RETRIES ) :
  lprint ( "Map-Notify with nonce 0x{} retry limit reached for ETR {}" . format ( map_notify . nonce_key , red ( iiIi1I . print_address ( ) , False ) ) )
  if 53 - 53: oO0o * OoooooooOO + II111iiii . IiII * I1ii11iIi11i
  if 55 - 55: OoOoOO00
  i1IIiI1iII = map_notify . nonce_key
  if ( lisp_map_notify_queue . has_key ( i1IIiI1iII ) ) :
   map_notify . retransmit_timer . cancel ( )
   lprint ( "Dequeue Map-Notify from retransmit queue, key is: {}" . format ( i1IIiI1iII ) )
   if 27 - 27: I1IiiI
   try :
    lisp_map_notify_queue . pop ( i1IIiI1iII )
   except :
    lprint ( "Key not found in Map-Notify queue" )
    if 81 - 81: Oo0Ooo
    if 43 - 43: i1IIi * O0 + ooOoO0o + OoO0O00
  return
  if 99 - 99: IiII . OoOoOO00
  if 64 - 64: I1Ii111
 iiiII1i1i1iII = map_notify . lisp_sockets
 map_notify . retry_count += 1
 if 96 - 96: Ii1I
 lprint ( "Retransmit {} with nonce 0x{} to xTR {}, retry {}" . format ( bold ( "Map-Notify" , False ) , map_notify . nonce_key ,
 # ooOoO0o . oO0o + Ii1I * ooOoO0o + O0 . II111iiii
 red ( iiIi1I . print_address ( ) , False ) , map_notify . retry_count ) )
 if 8 - 8: IiII * OOooOOo + I11i + O0 * oO0o - oO0o
 lisp_send_map_notify ( iiiII1i1i1iII , map_notify . packet , iiIi1I , OOo0000o0 )
 if ( map_notify . site ) : map_notify . site . map_notifies_sent += 1
 if 19 - 19: OoO0O00 - ooOoO0o + I1ii11iIi11i / I1ii11iIi11i % I1Ii111 % iIii1I11I1II1
 if 5 - 5: OoooooooOO + ooOoO0o - II111iiii . i11iIiiIii / oO0o - ooOoO0o
 if 3 - 3: iII111i
 if 74 - 74: i11iIiiIii + OoooooooOO . OOooOOo
 map_notify . retransmit_timer = threading . Timer ( LISP_MAP_NOTIFY_INTERVAL ,
 lisp_retransmit_map_notify , [ map_notify ] )
 map_notify . retransmit_timer . start ( )
 return
 if 29 - 29: IiII % OoO0O00
 if 53 - 53: OoooooooOO - OoOoOO00 / IiII - I1Ii111
 if 16 - 16: iIii1I11I1II1 / OOooOOo + I1IiiI * II111iiii . OOooOOo
 if 68 - 68: IiII * IiII + oO0o / o0oOOo0O0Ooo
 if 41 - 41: OoOoOO00 - O0
 if 48 - 48: OoooooooOO % Ii1I * OoO0O00 / I1ii11iIi11i
 if 53 - 53: ooOoO0o + oO0o - II111iiii
def lisp_send_merged_map_notify ( lisp_sockets , parent , map_register ,
 eid_record ) :
 if 92 - 92: Oo0Ooo - I11i . ooOoO0o % oO0o
 if 6 - 6: iIii1I11I1II1 + oO0o
 if 8 - 8: I1ii11iIi11i + o0oOOo0O0Ooo
 if 29 - 29: Ii1I . OOooOOo
 eid_record . rloc_count = len ( parent . registered_rlocs )
 ooOI1ii = eid_record . encode ( )
 eid_record . print_record ( "Merged Map-Notify " , False )
 if 85 - 85: iII111i * OOooOOo + i1IIi
 if 99 - 99: Oo0Ooo . i1IIi * O0 . o0oOOo0O0Ooo . OoooooooOO
 if 11 - 11: O0
 if 45 - 45: I1IiiI - II111iiii * iIii1I11I1II1 + OOooOOo
 for o0Ii11iI11III in parent . registered_rlocs :
  i1iIiII = lisp_rloc_record ( )
  i1iIiII . store_rloc_entry ( o0Ii11iI11III )
  ooOI1ii += i1iIiII . encode ( )
  i1iIiII . print_record ( "  " )
  del ( i1iIiII )
  if 44 - 44: i1IIi / OoooooooOO * OoooooooOO
  if 93 - 93: OoOoOO00 % Oo0Ooo . OoO0O00 / OoooooooOO
  if 59 - 59: OoO0O00 + O0 + i11iIiiIii / OoOoOO00 + iIii1I11I1II1 / OoOoOO00
  if 69 - 69: OoOoOO00 * Ii1I % ooOoO0o . OoOoOO00 / oO0o * I1Ii111
  if 93 - 93: OoO0O00 % IiII % ooOoO0o . I1IiiI
 for o0Ii11iI11III in parent . registered_rlocs :
  iiIi1I = o0Ii11iI11III . rloc
  o0oo0 = lisp_map_notify ( lisp_sockets )
  o0oo0 . record_count = 1
  I1 = map_register . key_id
  o0oo0 . key_id = I1
  o0oo0 . alg_id = map_register . alg_id
  o0oo0 . auth_len = map_register . auth_len
  o0oo0 . nonce = map_register . nonce
  o0oo0 . nonce_key = lisp_hex_string ( o0oo0 . nonce )
  o0oo0 . etr . copy_address ( iiIi1I )
  o0oo0 . etr_port = map_register . sport
  o0oo0 . site = parent . site
  iI1IIII1ii1 = o0oo0 . encode ( ooOI1ii , parent . site . auth_key [ I1 ] )
  o0oo0 . print_notify ( )
  if 32 - 32: OoO0O00 / I1Ii111 / I1Ii111
  if 45 - 45: iII111i + O0 % i11iIiiIii * I1ii11iIi11i + I1Ii111 / OOooOOo
  if 55 - 55: OoooooooOO % iIii1I11I1II1 . ooOoO0o
  if 10 - 10: O0 * iIii1I11I1II1 . OOooOOo
  i1IIiI1iII = o0oo0 . nonce_key
  if ( lisp_map_notify_queue . has_key ( i1IIiI1iII ) ) :
   iii = lisp_map_notify_queue [ i1IIiI1iII ]
   iii . retransmit_timer . cancel ( )
   del ( iii )
   if 10 - 10: oO0o - i11iIiiIii + I1IiiI / Oo0Ooo - II111iiii * i11iIiiIii
  lisp_map_notify_queue [ i1IIiI1iII ] = o0oo0
  if 57 - 57: I1Ii111 * II111iiii * Oo0Ooo . O0
  if 90 - 90: iIii1I11I1II1 % iIii1I11I1II1 / IiII
  if 21 - 21: ooOoO0o / iII111i % II111iiii * I1IiiI * II111iiii
  if 40 - 40: Ii1I / i1IIi . iII111i
  lprint ( "Send merged Map-Notify to ETR {}" . format ( red ( iiIi1I . print_address ( ) , False ) ) )
  if 65 - 65: iIii1I11I1II1 * O0 . II111iiii * o0oOOo0O0Ooo . I1ii11iIi11i * I1IiiI
  lisp_send ( lisp_sockets , iiIi1I , LISP_CTRL_PORT , iI1IIII1ii1 )
  if 63 - 63: II111iiii . Oo0Ooo % iIii1I11I1II1
  parent . site . map_notifies_sent += 1
  if 85 - 85: I1IiiI + i1IIi % I1Ii111
  if 76 - 76: i11iIiiIii % i11iIiiIii
  if 33 - 33: OOooOOo . ooOoO0o / iIii1I11I1II1 * OOooOOo / oO0o
  if 75 - 75: Ii1I - OoOoOO00 . OOooOOo - o0oOOo0O0Ooo - I1ii11iIi11i
  o0oo0 . retransmit_timer = threading . Timer ( LISP_MAP_NOTIFY_INTERVAL ,
 lisp_retransmit_map_notify , [ o0oo0 ] )
  o0oo0 . retransmit_timer . start ( )
  if 69 - 69: O0 % I1ii11iIi11i
 return
 if 77 - 77: iIii1I11I1II1 . OOooOOo
 if 64 - 64: OoOoOO00 - i1IIi * i1IIi / iII111i * OoOoOO00 * OoO0O00
 if 61 - 61: OOooOOo
 if 51 - 51: Oo0Ooo * OOooOOo / iII111i
 if 49 - 49: ooOoO0o . i1IIi % I1Ii111 . I1IiiI . I1ii11iIi11i + OoO0O00
 if 65 - 65: I1ii11iIi11i + Ii1I / i11iIiiIii * I1Ii111 + OoooooooOO
 if 7 - 7: Oo0Ooo % o0oOOo0O0Ooo
def lisp_build_map_notify ( lisp_sockets , eid_records , eid_list , record_count ,
 source , port , nonce , key_id , alg_id , auth_len , site , map_register_ack ) :
 if 40 - 40: oO0o * IiII
 i1IIiI1iII = lisp_hex_string ( nonce ) + source . print_address ( )
 if 29 - 29: O0 - II111iiii + iII111i
 if 73 - 73: I1Ii111 - I11i + IiII - o0oOOo0O0Ooo - I11i - OOooOOo
 if 40 - 40: iIii1I11I1II1 . iII111i * I1ii11iIi11i + IiII - iIii1I11I1II1
 if 83 - 83: i1IIi
 if 9 - 9: iIii1I11I1II1 + i11iIiiIii
 if 70 - 70: I1IiiI - OoO0O00 % OOooOOo + ooOoO0o % II111iiii
 lisp_remove_eid_from_map_notify_queue ( eid_list )
 if ( lisp_map_notify_queue . has_key ( i1IIiI1iII ) ) :
  o0oo0 = lisp_map_notify_queue [ i1IIiI1iII ]
  i1I1iIi1IiI = red ( source . print_address_no_iid ( ) , False )
  lprint ( "Map-Notify with nonce 0x{} pending for xTR {}" . format ( lisp_hex_string ( o0oo0 . nonce ) , i1I1iIi1IiI ) )
  if 19 - 19: I11i + i1IIi / i1IIi - II111iiii + I1Ii111
  return
  if 11 - 11: i11iIiiIii % i11iIiiIii / IiII - Oo0Ooo / O0 - I11i
  if 29 - 29: OOooOOo * iIii1I11I1II1 * ooOoO0o
 o0oo0 = lisp_map_notify ( lisp_sockets )
 o0oo0 . record_count = record_count
 key_id = key_id
 o0oo0 . key_id = key_id
 o0oo0 . alg_id = alg_id
 o0oo0 . auth_len = auth_len
 o0oo0 . nonce = nonce
 o0oo0 . nonce_key = lisp_hex_string ( nonce )
 o0oo0 . etr . copy_address ( source )
 o0oo0 . etr_port = port
 o0oo0 . site = site
 o0oo0 . eid_list = eid_list
 if 80 - 80: oO0o * I1Ii111
 if 87 - 87: iII111i + OoOoOO00 % ooOoO0o - oO0o
 if 40 - 40: i1IIi / OoOoOO00 - I11i / ooOoO0o . Ii1I
 if 8 - 8: I1IiiI . IiII . OOooOOo . O0
 if ( map_register_ack == False ) :
  i1IIiI1iII = o0oo0 . nonce_key
  lisp_map_notify_queue [ i1IIiI1iII ] = o0oo0
  if 3 - 3: Ii1I + i11iIiiIii
  if 87 - 87: ooOoO0o - iII111i % I11i
 if ( map_register_ack ) :
  lprint ( "Send Map-Notify to ack Map-Register" )
 else :
  lprint ( "Send Map-Notify for RLOC-set change" )
  if 88 - 88: I11i . OoooooooOO
  if 86 - 86: Ii1I - I1IiiI - iII111i % Ii1I . I1ii11iIi11i % i1IIi
  if 84 - 84: OoOoOO00
  if 99 - 99: OoO0O00 - OoOoOO00 - i1IIi / OoO0O00 * I1ii11iIi11i * iIii1I11I1II1
  if 65 - 65: iII111i - O0 / i1IIi . I1Ii111
 iI1IIII1ii1 = o0oo0 . encode ( eid_records , site . auth_key [ key_id ] )
 o0oo0 . print_notify ( )
 if 85 - 85: o0oOOo0O0Ooo % Ii1I
 if ( map_register_ack == False ) :
  I111IoOo0oOOO0o = lisp_eid_record ( )
  I111IoOo0oOOO0o . decode ( eid_records )
  I111IoOo0oOOO0o . print_record ( "  " , False )
  if 81 - 81: oO0o / OoO0O00 * i1IIi % iIii1I11I1II1
  if 23 - 23: II111iiii . II111iiii
  if 17 - 17: i11iIiiIii / IiII * I1IiiI . Oo0Ooo / o0oOOo0O0Ooo - iIii1I11I1II1
  if 21 - 21: OOooOOo % Ii1I
  if 3 - 3: OOooOOo / ooOoO0o / I1Ii111 . I11i
 lisp_send_map_notify ( lisp_sockets , iI1IIII1ii1 , o0oo0 . etr , port )
 site . map_notifies_sent += 1
 if 54 - 54: I1ii11iIi11i - I1IiiI . OoOoOO00
 if ( map_register_ack ) : return
 if 36 - 36: OoO0O00 * I1IiiI / iII111i
 if 95 - 95: Ii1I . Oo0Ooo
 if 42 - 42: IiII . i1IIi % O0 * ooOoO0o - OOooOOo % ooOoO0o
 if 99 - 99: i1IIi + OoOoOO00 - iII111i % II111iiii
 if 6 - 6: ooOoO0o - I1Ii111 . OoOoOO00
 if 64 - 64: iII111i + I1ii11iIi11i
 o0oo0 . retransmit_timer = threading . Timer ( LISP_MAP_NOTIFY_INTERVAL ,
 lisp_retransmit_map_notify , [ o0oo0 ] )
 o0oo0 . retransmit_timer . start ( )
 return
 if 88 - 88: I1Ii111 / i11iIiiIii - O0 . II111iiii / II111iiii * II111iiii
 if 56 - 56: Oo0Ooo / I1IiiI % I1Ii111 % I1ii11iIi11i * I1IiiI - IiII
 if 39 - 39: oO0o + iII111i . I1Ii111 * i11iIiiIii % o0oOOo0O0Ooo + OOooOOo
 if 61 - 61: ooOoO0o / I1Ii111 / I1ii11iIi11i - Ii1I % o0oOOo0O0Ooo * iII111i
 if 94 - 94: I1IiiI / I11i
 if 100 - 100: Ii1I % OoO0O00 % OoooooooOO / II111iiii * I1Ii111
 if 64 - 64: I1Ii111 * OOooOOo * Ii1I + I1ii11iIi11i / iIii1I11I1II1 / Oo0Ooo
 if 50 - 50: OOooOOo % i11iIiiIii
def lisp_send_map_notify_ack ( lisp_sockets , eid_records , map_notify , ms ) :
 map_notify . map_notify_ack = True
 if 99 - 99: IiII
 if 87 - 87: IiII
 if 35 - 35: oO0o . O0 . Ii1I / ooOoO0o
 if 36 - 36: i11iIiiIii . II111iiii . I11i . II111iiii
 iI1IIII1ii1 = map_notify . encode ( eid_records , ms . password )
 map_notify . print_notify ( )
 if 36 - 36: Ii1I + ooOoO0o / Oo0Ooo % Oo0Ooo
 if 2 - 2: oO0o - Oo0Ooo * OoO0O00 . ooOoO0o . OOooOOo - oO0o
 if 74 - 74: o0oOOo0O0Ooo
 if 18 - 18: Oo0Ooo % OOooOOo / OOooOOo . I1IiiI + i1IIi . I1IiiI
 iiIi1I = ms . map_server
 lprint ( "Send Map-Notify-Ack to {}" . format (
 red ( iiIi1I . print_address ( ) , False ) ) )
 lisp_send ( lisp_sockets , iiIi1I , LISP_CTRL_PORT , iI1IIII1ii1 )
 return
 if 3 - 3: O0 * O0 + II111iiii + OoOoOO00 * I11i % Oo0Ooo
 if 19 - 19: oO0o % IiII % OoooooooOO % I1ii11iIi11i / OoO0O00
 if 6 - 6: O0 * I1Ii111 - II111iiii
 if 60 - 60: oO0o % oO0o
 if 76 - 76: I1Ii111 / o0oOOo0O0Ooo
 if 19 - 19: O0 . i1IIi % iIii1I11I1II1 + OOooOOo * OoOoOO00 / I11i
 if 82 - 82: I1ii11iIi11i
 if 75 - 75: I11i - II111iiii
def lisp_send_multicast_map_notify ( lisp_sockets , site_eid , eid_list , xtr ) :
 if 84 - 84: I1ii11iIi11i * IiII / I1IiiI - Ii1I + IiII - i1IIi
 o0oo0 = lisp_map_notify ( lisp_sockets )
 o0oo0 . record_count = 1
 o0oo0 . nonce = lisp_get_control_nonce ( )
 o0oo0 . nonce_key = lisp_hex_string ( o0oo0 . nonce )
 o0oo0 . etr . copy_address ( xtr )
 o0oo0 . etr_port = LISP_CTRL_PORT
 o0oo0 . eid_list = eid_list
 i1IIiI1iII = o0oo0 . nonce_key
 if 98 - 98: II111iiii - iII111i % i11iIiiIii + ooOoO0o
 if 76 - 76: OOooOOo - iII111i + IiII
 if 48 - 48: I1IiiI - II111iiii
 if 15 - 15: O0
 if 54 - 54: iIii1I11I1II1
 if 54 - 54: iII111i + OOooOOo + OoO0O00
 lisp_remove_eid_from_map_notify_queue ( o0oo0 . eid_list )
 if ( lisp_map_notify_queue . has_key ( i1IIiI1iII ) ) :
  o0oo0 = lisp_map_notify_queue [ i1IIiI1iII ]
  lprint ( "Map-Notify with nonce 0x{} pending for ITR {}" . format ( o0oo0 . nonce , red ( xtr . print_address_no_iid ( ) , False ) ) )
  if 6 - 6: oO0o - OoooooooOO * iIii1I11I1II1 * I1ii11iIi11i
  return
  if 65 - 65: IiII + OoOoOO00
  if 93 - 93: Ii1I
  if 43 - 43: iIii1I11I1II1 / iII111i - Ii1I + I11i % iII111i - OoO0O00
  if 5 - 5: OoO0O00 / ooOoO0o
  if 92 - 92: Oo0Ooo / iII111i + O0 * ooOoO0o * OOooOOo % Oo0Ooo
 lisp_map_notify_queue [ i1IIiI1iII ] = o0oo0
 if 97 - 97: oO0o / Ii1I
 if 70 - 70: iII111i / Oo0Ooo . OoOoOO00 - II111iiii * II111iiii % I1IiiI
 if 34 - 34: I1Ii111 + OOooOOo * iII111i / ooOoO0o % i11iIiiIii
 if 91 - 91: IiII * Ii1I * OOooOOo
 II11II1 = site_eid . rtrs_in_rloc_set ( )
 if ( II11II1 ) :
  if ( site_eid . is_rtr_in_rloc_set ( xtr ) ) : II11II1 = False
  if 89 - 89: I1ii11iIi11i * iII111i * IiII
  if 74 - 74: OoO0O00 + I1Ii111 / o0oOOo0O0Ooo % Ii1I
  if 19 - 19: I1IiiI % oO0o - Ii1I
  if 97 - 97: OOooOOo / ooOoO0o . Oo0Ooo - Oo0Ooo . OoOoOO00
  if 88 - 88: iIii1I11I1II1 - OoO0O00 + II111iiii
 I111IoOo0oOOO0o = lisp_eid_record ( )
 I111IoOo0oOOO0o . record_ttl = 1440
 I111IoOo0oOOO0o . eid . copy_address ( site_eid . eid )
 I111IoOo0oOOO0o . group . copy_address ( site_eid . group )
 I111IoOo0oOOO0o . rloc_count = 0
 for ii1I1i11 in site_eid . registered_rlocs :
  if ( II11II1 ^ ii1I1i11 . is_rtr ( ) ) : continue
  I111IoOo0oOOO0o . rloc_count += 1
  if 100 - 100: I1Ii111 + I1IiiI + OOooOOo * iII111i
 iI1IIII1ii1 = I111IoOo0oOOO0o . encode ( )
 if 35 - 35: Oo0Ooo . O0
 if 43 - 43: oO0o . O0 . OOooOOo
 if 3 - 3: i1IIi
 if 85 - 85: i11iIiiIii % i1IIi
 o0oo0 . print_notify ( )
 I111IoOo0oOOO0o . print_record ( "  " , False )
 if 78 - 78: ooOoO0o / I1ii11iIi11i
 if 72 - 72: II111iiii / O0 - I1ii11iIi11i + oO0o + iIii1I11I1II1
 if 65 - 65: OoO0O00 * II111iiii
 if 25 - 25: I1ii11iIi11i - I1Ii111 * I1Ii111 / O0 - iIii1I11I1II1 . iII111i
 for ii1I1i11 in site_eid . registered_rlocs :
  if ( II11II1 ^ ii1I1i11 . is_rtr ( ) ) : continue
  i1iIiII = lisp_rloc_record ( )
  i1iIiII . store_rloc_entry ( ii1I1i11 )
  iI1IIII1ii1 += i1iIiII . encode ( )
  i1iIiII . print_record ( "    " )
  if 83 - 83: ooOoO0o * oO0o * OoO0O00 + OoO0O00
  if 58 - 58: I1ii11iIi11i
  if 93 - 93: i1IIi - IiII + IiII % OoooooooOO / o0oOOo0O0Ooo
  if 39 - 39: I1IiiI + Ii1I - O0
  if 25 - 25: IiII % iIii1I11I1II1 + ooOoO0o % iII111i - OoO0O00
 iI1IIII1ii1 = o0oo0 . encode ( iI1IIII1ii1 , "" )
 if ( iI1IIII1ii1 == None ) : return
 if 36 - 36: OoooooooOO / oO0o + IiII . I1IiiI - o0oOOo0O0Ooo % OOooOOo
 if 15 - 15: Ii1I % IiII + IiII % iII111i - O0 * OoooooooOO
 if 53 - 53: OoOoOO00 . Ii1I / Oo0Ooo
 if 62 - 62: i11iIiiIii
 lisp_send_map_notify ( lisp_sockets , iI1IIII1ii1 , xtr , LISP_CTRL_PORT )
 if 38 - 38: I1ii11iIi11i % ooOoO0o * OoooooooOO + iIii1I11I1II1 % i1IIi / OOooOOo
 if 6 - 6: i11iIiiIii
 if 8 - 8: iIii1I11I1II1 + I1ii11iIi11i . i1IIi % OoOoOO00 % OoooooooOO * Oo0Ooo
 if 53 - 53: oO0o
 o0oo0 . retransmit_timer = threading . Timer ( LISP_MAP_NOTIFY_INTERVAL ,
 lisp_retransmit_map_notify , [ o0oo0 ] )
 o0oo0 . retransmit_timer . start ( )
 return
 if 23 - 23: I1ii11iIi11i . I1Ii111 + OOooOOo
 if 4 - 4: I1IiiI
 if 31 - 31: ooOoO0o * i1IIi . O0
 if 5 - 5: OOooOOo . I1ii11iIi11i + ooOoO0o . ooOoO0o + iII111i
 if 100 - 100: I1Ii111
 if 71 - 71: ooOoO0o * i1IIi / OoOoOO00 * i11iIiiIii - iII111i
 if 88 - 88: IiII
def lisp_queue_multicast_map_notify ( lisp_sockets , rle_list ) :
 i11 = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
 if 62 - 62: IiII
 for oOO00oOooOo in rle_list :
  O0OoO = lisp_site_eid_lookup ( oOO00oOooOo [ 0 ] , oOO00oOooOo [ 1 ] , True )
  if ( O0OoO == None ) : continue
  if 27 - 27: OoO0O00 + OOooOOo / ooOoO0o * I1IiiI / I11i
  if 84 - 84: iII111i . i11iIiiIii % ooOoO0o % O0 + I1IiiI
  if 25 - 25: iIii1I11I1II1
  if 95 - 95: ooOoO0o * OoO0O00 % OoooooooOO % OoO0O00
  if 79 - 79: II111iiii % Ii1I * oO0o * iII111i + II111iiii
  if 51 - 51: I1IiiI + iII111i + I1IiiI / Ii1I * IiII + OOooOOo
  if 70 - 70: I11i . IiII + IiII
  oooO0oo0ooO = O0OoO . registered_rlocs
  if ( len ( oooO0oo0ooO ) == 0 ) :
   oooOO0oooo00 = { }
   for iiiI1iI11i1i1 in O0OoO . individual_registrations . values ( ) :
    for ii1I1i11 in iiiI1iI11i1i1 . registered_rlocs :
     if ( ii1I1i11 . is_rtr ( ) == False ) : continue
     oooOO0oooo00 [ ii1I1i11 . rloc . print_address ( ) ] = ii1I1i11
     if 66 - 66: OoO0O00 * oO0o / i11iIiiIii * O0 . OOooOOo % iIii1I11I1II1
     if 15 - 15: ooOoO0o . O0 - i11iIiiIii - I1Ii111 - Oo0Ooo / OoOoOO00
   oooO0oo0ooO = oooOO0oooo00 . values ( )
   if 68 - 68: Ii1I % Oo0Ooo
   if 74 - 74: iIii1I11I1II1 / O0 + Ii1I . O0 + iII111i
   if 46 - 46: I11i . i11iIiiIii * OoOoOO00 + o0oOOo0O0Ooo / ooOoO0o
   if 37 - 37: OoO0O00 - Ii1I + OoO0O00
   if 49 - 49: OoooooooOO - I1ii11iIi11i % I1ii11iIi11i / i1IIi . ooOoO0o
   if 60 - 60: Oo0Ooo
  iIiI11 = [ ]
  I1i1iI111I1I = False
  if ( O0OoO . eid . address == 0 and O0OoO . eid . mask_len == 0 ) :
   Oo0o00oo = [ ]
   iiI1iiII = [ ] if len ( oooO0oo0ooO ) == 0 else oooO0oo0ooO [ 0 ] . rle . rle_nodes
   if 72 - 72: i1IIi + I1Ii111 . oO0o * oO0o * I1IiiI
   for i1ooOoO in iiI1iiII :
    iIiI11 . append ( i1ooOoO . address )
    Oo0o00oo . append ( i1ooOoO . address . print_address_no_iid ( ) )
    if 40 - 40: OoO0O00 % ooOoO0o + iII111i + IiII + I11i * Oo0Ooo
   lprint ( "Notify existing RLE-nodes {}" . format ( Oo0o00oo ) )
  else :
   if 99 - 99: Oo0Ooo
   if 99 - 99: I1Ii111 + oO0o % OoooooooOO
   if 88 - 88: ooOoO0o % Oo0Ooo * II111iiii
   if 62 - 62: iII111i * I1Ii111 % OoOoOO00 * O0
   if 85 - 85: II111iiii - O0 . i11iIiiIii . o0oOOo0O0Ooo + ooOoO0o - ooOoO0o
   for ii1I1i11 in oooO0oo0ooO :
    if ( ii1I1i11 . is_rtr ( ) ) : iIiI11 . append ( ii1I1i11 . rloc )
    if 25 - 25: I1ii11iIi11i % Ii1I * O0 / I1IiiI % OOooOOo
    if 42 - 42: IiII - IiII - I1ii11iIi11i + i1IIi * Oo0Ooo
    if 80 - 80: oO0o + O0
    if 84 - 84: i1IIi - II111iiii
    if 2 - 2: i11iIiiIii - OoO0O00 * Oo0Ooo
   I1i1iI111I1I = ( len ( iIiI11 ) != 0 )
   if ( I1i1iI111I1I == False ) :
    IIII = lisp_site_eid_lookup ( oOO00oOooOo [ 0 ] , i11 , False )
    if ( IIII == None ) : continue
    if 100 - 100: I1Ii111
    for ii1I1i11 in IIII . registered_rlocs :
     if ( ii1I1i11 . rloc . is_null ( ) ) : continue
     iIiI11 . append ( ii1I1i11 . rloc )
     if 5 - 5: IiII % oO0o . I1IiiI * II111iiii + o0oOOo0O0Ooo / Ii1I
     if 55 - 55: Oo0Ooo / o0oOOo0O0Ooo
     if 51 - 51: I1IiiI + i11iIiiIii / ooOoO0o % I1IiiI + Oo0Ooo
     if 6 - 6: OoOoOO00 . O0
     if 44 - 44: ooOoO0o % I11i + ooOoO0o . oO0o
     if 70 - 70: O0 - I11i . iIii1I11I1II1 % I11i . OoOoOO00 % oO0o
   if ( len ( iIiI11 ) == 0 ) :
    lprint ( "No ITRs or RTRs found for {}, Map-Notify suppressed" . format ( green ( O0OoO . print_eid_tuple ( ) , False ) ) )
    if 5 - 5: O0 * OoO0O00
    continue
    if 61 - 61: Ii1I / I11i + Ii1I . IiII - OoO0O00 - o0oOOo0O0Ooo
    if 84 - 84: OoooooooOO - Oo0Ooo
    if 86 - 86: O0 + OoO0O00 + O0 . I1IiiI
    if 82 - 82: OoOoOO00
    if 61 - 61: oO0o . o0oOOo0O0Ooo
    if 82 - 82: Oo0Ooo * OoooooooOO / ooOoO0o / I1IiiI
  for o0Ii11iI11III in iIiI11 :
   lprint ( "Build Map-Notify to {}TR {} for {}" . format ( "R" if I1i1iI111I1I else "x" , red ( o0Ii11iI11III . print_address_no_iid ( ) , False ) ,
   # I1IiiI . I1IiiI % ooOoO0o * ooOoO0o / I1ii11iIi11i
 green ( O0OoO . print_eid_tuple ( ) , False ) ) )
   if 12 - 12: o0oOOo0O0Ooo
   i111i = [ O0OoO . print_eid_tuple ( ) ]
   lisp_send_multicast_map_notify ( lisp_sockets , O0OoO , i111i , o0Ii11iI11III )
   time . sleep ( .001 )
   if 45 - 45: OoO0O00 + ooOoO0o / iIii1I11I1II1 % i11iIiiIii
   if 16 - 16: i1IIi / oO0o - OOooOOo / Ii1I + I1IiiI
 return
 if 62 - 62: i11iIiiIii . Ii1I . iII111i / I1Ii111 * OoO0O00
 if 31 - 31: OoOoOO00
 if 16 - 16: OoooooooOO
 if 32 - 32: ooOoO0o - o0oOOo0O0Ooo / ooOoO0o + o0oOOo0O0Ooo + iII111i
 if 78 - 78: OoooooooOO . I1ii11iIi11i * oO0o . o0oOOo0O0Ooo * OoOoOO00 / oO0o
 if 47 - 47: OOooOOo
 if 40 - 40: I1ii11iIi11i
 if 67 - 67: I1Ii111 - OoO0O00 * ooOoO0o - oO0o / OoO0O00 . I1Ii111
def lisp_find_sig_in_rloc_set ( packet , rloc_count ) :
 for oO in range ( rloc_count ) :
  i1iIiII = lisp_rloc_record ( )
  packet = i1iIiII . decode ( packet , None )
  i11I1i1Ii1i = i1iIiII . json
  if ( i11I1i1Ii1i == None ) : continue
  if 18 - 18: o0oOOo0O0Ooo + o0oOOo0O0Ooo . OoO0O00 . oO0o . iIii1I11I1II1
  try :
   i11I1i1Ii1i = json . loads ( i11I1i1Ii1i . json_string )
  except :
   lprint ( "Found corrupted JSON signature" )
   continue
   if 62 - 62: OoO0O00 * i11iIiiIii / i1IIi . i11iIiiIii - o0oOOo0O0Ooo
   if 86 - 86: I1Ii111 / I1ii11iIi11i * iII111i . IiII * OoooooooOO - OoO0O00
  if ( i11I1i1Ii1i . has_key ( "signature" ) == False ) : continue
  return ( i1iIiII )
  if 80 - 80: OoOoOO00 * iIii1I11I1II1 % O0 . O0
 return ( None )
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
 if 50 - 50: iII111i % OoO0O00 - oO0o + Oo0Ooo . O0 . iII111i
 if 42 - 42: iII111i + I1ii11iIi11i
 if 44 - 44: I1ii11iIi11i % IiII
def lisp_get_eid_hash ( eid ) :
 III1i11 = None
 for iIiII11O00 in lisp_eid_hashes :
  if 32 - 32: OOooOOo . o0oOOo0O0Ooo - OOooOOo * O0 % Ii1I
  if 20 - 20: ooOoO0o
  if 38 - 38: IiII + OoO0O00 . OOooOOo - I1Ii111 + IiII
  if 82 - 82: OOooOOo
  IIiI1i = iIiII11O00 . instance_id
  if ( IIiI1i == - 1 ) : iIiII11O00 . instance_id = eid . instance_id
  if 26 - 26: ooOoO0o + OoooooooOO + ooOoO0o * I1Ii111
  ii1I111i = eid . is_more_specific ( iIiII11O00 )
  iIiII11O00 . instance_id = IIiI1i
  if ( ii1I111i ) :
   III1i11 = 128 - iIiII11O00 . mask_len
   break
   if 32 - 32: OoOoOO00 + iII111i
   if 8 - 8: o0oOOo0O0Ooo . IiII % iII111i / o0oOOo0O0Ooo * I1IiiI % I1ii11iIi11i
 if ( III1i11 == None ) : return ( None )
 if 91 - 91: I1Ii111 / II111iiii / O0
 oOOOOO0Ooooo = eid . address
 i111ii1i1ii1i = ""
 for oO in range ( 0 , III1i11 / 16 ) :
  I1Iii1I = oOOOOO0Ooooo & 0xffff
  I1Iii1I = hex ( I1Iii1I ) [ 2 : - 1 ]
  i111ii1i1ii1i = I1Iii1I . zfill ( 4 ) + ":" + i111ii1i1ii1i
  oOOOOO0Ooooo >>= 16
  if 97 - 97: ooOoO0o
 if ( III1i11 % 16 != 0 ) :
  I1Iii1I = oOOOOO0Ooooo & 0xff
  I1Iii1I = hex ( I1Iii1I ) [ 2 : - 1 ]
  i111ii1i1ii1i = I1Iii1I . zfill ( 2 ) + ":" + i111ii1i1ii1i
  if 46 - 46: II111iiii - i1IIi
 return ( i111ii1i1ii1i [ 0 : - 1 ] )
 if 72 - 72: I11i
 if 35 - 35: I1Ii111 + oO0o + II111iiii
 if 71 - 71: OoOoOO00 * OoOoOO00
 if 27 - 27: II111iiii + OoooooooOO - I11i * o0oOOo0O0Ooo
 if 67 - 67: i11iIiiIii - OoOoOO00
 if 90 - 90: i11iIiiIii . I1ii11iIi11i - OoooooooOO / o0oOOo0O0Ooo
 if 58 - 58: II111iiii + iIii1I11I1II1
 if 51 - 51: ooOoO0o - Ii1I + ooOoO0o
 if 87 - 87: O0 - I1IiiI
 if 37 - 37: Oo0Ooo - o0oOOo0O0Ooo * II111iiii / ooOoO0o
 if 90 - 90: iIii1I11I1II1 . II111iiii % I1Ii111
def lisp_lookup_public_key ( eid ) :
 IIiI1i = eid . instance_id
 if 28 - 28: i11iIiiIii + OoO0O00 % O0 - I1ii11iIi11i % oO0o
 if 30 - 30: I11i + OOooOOo
 if 27 - 27: OoOoOO00 . ooOoO0o
 if 73 - 73: o0oOOo0O0Ooo
 if 8 - 8: O0
 IIiIIiI1ii1II11I = lisp_get_eid_hash ( eid )
 if ( IIiIIiI1ii1II11I == None ) : return ( [ None , None , False ] )
 if 94 - 94: OoO0O00 / II111iiii / OOooOOo
 IIiIIiI1ii1II11I = "hash-" + IIiIIiI1ii1II11I
 o0OoO = lisp_address ( LISP_AFI_NAME , IIiIIiI1ii1II11I , len ( IIiIIiI1ii1II11I ) , IIiI1i )
 Oo000o0o0 = lisp_address ( LISP_AFI_NONE , "" , 0 , IIiI1i )
 if 77 - 77: I1IiiI . ooOoO0o . o0oOOo0O0Ooo + OoOoOO00 / oO0o + Ii1I
 if 85 - 85: o0oOOo0O0Ooo - OoOoOO00
 if 33 - 33: oO0o - iII111i - I1ii11iIi11i / o0oOOo0O0Ooo . Oo0Ooo
 if 27 - 27: o0oOOo0O0Ooo % o0oOOo0O0Ooo / ooOoO0o + OoooooooOO * iII111i . I11i
 IIII = lisp_site_eid_lookup ( o0OoO , Oo000o0o0 , True )
 if ( IIII == None ) : return ( [ o0OoO , None , False ] )
 if 2 - 2: iIii1I11I1II1 * I1ii11iIi11i - OoooooooOO
 if 93 - 93: iII111i % ooOoO0o * Oo0Ooo
 if 34 - 34: O0 * oO0o
 if 58 - 58: OOooOOo . iII111i - Oo0Ooo / iII111i . I11i
 iI11i = None
 for i1IIIIi1Ii111 in IIII . registered_rlocs :
  oo000oOoO = i1IIIIi1Ii111 . json
  if ( oo000oOoO == None ) : continue
  try :
   oo000oOoO = json . loads ( oo000oOoO . json_string )
  except :
   lprint ( "Registered RLOC JSON format is invalid for {}" . format ( IIiIIiI1ii1II11I ) )
   if 57 - 57: OOooOOo % IiII % i11iIiiIii . iIii1I11I1II1 . o0oOOo0O0Ooo / OOooOOo
   return ( [ o0OoO , None , False ] )
   if 88 - 88: oO0o / I1Ii111 . iII111i * I1ii11iIi11i + OoooooooOO
  if ( oo000oOoO . has_key ( "public-key" ) == False ) : continue
  iI11i = oo000oOoO [ "public-key" ]
  break
  if 56 - 56: OOooOOo * I1Ii111 % OOooOOo + Ii1I
 return ( [ o0OoO , iI11i , True ] )
 if 78 - 78: OOooOOo * OoOoOO00
 if 20 - 20: IiII
 if 17 - 17: o0oOOo0O0Ooo % iIii1I11I1II1
 if 66 - 66: OoooooooOO + IiII . II111iiii
 if 66 - 66: iIii1I11I1II1 % I11i
 if 38 - 38: I1ii11iIi11i * ooOoO0o
 if 77 - 77: OOooOOo - i11iIiiIii - I1ii11iIi11i
 if 94 - 94: OoO0O00 % iII111i - I1Ii111 + OoO0O00 - I1IiiI
def lisp_verify_cga_sig ( eid , rloc_record ) :
 if 65 - 65: OOooOOo
 if 90 - 90: O0
 if 91 - 91: O0 * OoOoOO00 - OoOoOO00 * II111iiii - iII111i
 if 38 - 38: oO0o * I11i % OOooOOo
 if 80 - 80: O0 % II111iiii / O0 . Oo0Ooo * OoOoOO00 + OOooOOo
 oOO0 = json . loads ( rloc_record . json . json_string )
 if 47 - 47: Ii1I - Oo0Ooo * OoOoOO00
 if ( lisp_get_eid_hash ( eid ) ) :
  IIIi11iiIIi = eid
 elif ( oOO0 . has_key ( "signature-eid" ) ) :
  iIi1IIii1 = oOO0 [ "signature-eid" ]
  IIIi11iiIIi = lisp_address ( LISP_AFI_IPV6 , iIi1IIii1 , 0 , 0 )
 else :
  lprint ( "  No signature-eid found in RLOC-record" )
  return ( False )
  if 73 - 73: Ii1I . IiII
  if 43 - 43: I11i . IiII - iII111i * I1IiiI * iII111i
  if 90 - 90: i11iIiiIii * i1IIi
  if 88 - 88: i11iIiiIii - OoOoOO00
  if 53 - 53: iIii1I11I1II1 % I1Ii111 / Oo0Ooo % Oo0Ooo
 o0OoO , iI11i , iIiIi1IiiiI1 = lisp_lookup_public_key ( IIIi11iiIIi )
 if ( o0OoO == None ) :
  oo0ooooO = green ( IIIi11iiIIi . print_address ( ) , False )
  lprint ( "  Could not parse hash in EID {}" . format ( oo0ooooO ) )
  return ( False )
  if 64 - 64: OoO0O00 + I1ii11iIi11i / OoO0O00 * I1Ii111 . Oo0Ooo
  if 5 - 5: iII111i - iIii1I11I1II1 * IiII
 oOO0OOOOoo = "found" if iIiIi1IiiiI1 else bold ( "not found" , False )
 oo0ooooO = green ( o0OoO . print_address ( ) , False )
 lprint ( "  Lookup for crypto-hashed EID {} {}" . format ( oo0ooooO , oOO0OOOOoo ) )
 if ( iIiIi1IiiiI1 == False ) : return ( False )
 if 35 - 35: Oo0Ooo - ooOoO0o % OoO0O00
 if ( iI11i == None ) :
  lprint ( "  RLOC-record with public-key not found" )
  return ( False )
  if 26 - 26: i1IIi * I1Ii111 * OoO0O00 - IiII
  if 26 - 26: Oo0Ooo - ooOoO0o . iII111i * OoOoOO00 / OoooooooOO
 oO00o = iI11i [ 0 : 8 ] + "..." + iI11i [ - 8 : : ]
 lprint ( "  RLOC-record with public-key '{}' found" . format ( oO00o ) )
 if 54 - 54: II111iiii / I1IiiI % iII111i - iII111i % OoO0O00 - OoO0O00
 if 33 - 33: OoooooooOO % i1IIi % I1Ii111 . OoO0O00
 if 24 - 24: i1IIi . iII111i * iIii1I11I1II1 . I11i % I1ii11iIi11i + i11iIiiIii
 if 28 - 28: OoO0O00 . I1ii11iIi11i / O0
 if 35 - 35: O0 . oO0o % OoOoOO00 * O0 - IiII
 oo0OoO0O0O0O0 = oOO0 [ "signature" ]
 if 84 - 84: IiII . OoO0O00
 try :
  oOO0 = binascii . a2b_base64 ( oo0OoO0O0O0O0 )
 except :
  lprint ( "  Incorrect padding in signature string" )
  return ( False )
  if 73 - 73: OoOoOO00
  if 47 - 47: oO0o
 iIIi11Ii1iII = len ( oOO0 )
 if ( iIIi11Ii1iII & 1 ) :
  lprint ( "  Signature length is odd, length {}" . format ( iIIi11Ii1iII ) )
  return ( False )
  if 72 - 72: I11i % ooOoO0o / O0 . O0
  if 7 - 7: O0 * I1ii11iIi11i + Ii1I + oO0o % oO0o
  if 47 - 47: oO0o * I1ii11iIi11i
  if 85 - 85: OoooooooOO * I1ii11iIi11i + i11iIiiIii . iII111i * II111iiii / oO0o
  if 14 - 14: I1Ii111
 ooOOoOO000 = IIIi11iiIIi . print_address ( )
 if 49 - 49: I1IiiI . OOooOOo / OoooooooOO + I11i - I11i
 if 27 - 27: Ii1I / o0oOOo0O0Ooo . iIii1I11I1II1 . I1IiiI - OoO0O00
 if 28 - 28: ooOoO0o
 if 88 - 88: oO0o
 iI11i = binascii . a2b_base64 ( iI11i )
 try :
  i1IIiI1iII = ecdsa . VerifyingKey . from_pem ( iI11i )
 except :
  o0o0Oo = bold ( "Bad public-key" , False )
  lprint ( "  {}, not in PEM format" . format ( o0o0Oo ) )
  return ( False )
  if 76 - 76: OoOoOO00 / iII111i * ooOoO0o . i1IIi
  if 28 - 28: I11i . I1ii11iIi11i
  if 80 - 80: OoO0O00 - OoooooooOO * i11iIiiIii
  if 20 - 20: OoO0O00 . II111iiii
  if 70 - 70: i11iIiiIii % Ii1I * IiII / IiII . o0oOOo0O0Ooo
  if 52 - 52: o0oOOo0O0Ooo % I11i
  if 58 - 58: i11iIiiIii % Ii1I + Oo0Ooo - OoOoOO00 - i11iIiiIii / O0
  if 36 - 36: OOooOOo
  if 42 - 42: OOooOOo * ooOoO0o * i11iIiiIii + OoooooooOO . iIii1I11I1II1
  if 95 - 95: i1IIi * O0 / II111iiii * OoOoOO00 * I1IiiI
  if 38 - 38: OOooOOo - OoOoOO00 / OoO0O00 / o0oOOo0O0Ooo - i11iIiiIii
 try :
  O0o0O00O0 = i1IIiI1iII . verify ( oOO0 , ooOOoOO000 , hashfunc = hashlib . sha256 )
 except :
  lprint ( "  Signature library failed for signature data '{}'" . format ( ooOOoOO000 ) )
  if 4 - 4: I1IiiI * o0oOOo0O0Ooo - I11i - OoooooooOO . OoooooooOO
  lprint ( "  Signature used '{}'" . format ( oo0OoO0O0O0O0 ) )
  return ( False )
  if 79 - 79: oO0o - iII111i
 return ( O0o0O00O0 )
 if 34 - 34: OoooooooOO + Ii1I - iII111i + OoooooooOO / I1IiiI
 if 39 - 39: o0oOOo0O0Ooo . i1IIi * OoO0O00 / II111iiii / I1ii11iIi11i * OOooOOo
 if 39 - 39: O0 . OOooOOo
 if 95 - 95: I11i
 if 58 - 58: I1ii11iIi11i / i11iIiiIii + iII111i + I11i / oO0o
 if 8 - 8: I1ii11iIi11i
 if 100 - 100: OoooooooOO / I11i - Ii1I
 if 11 - 11: OoO0O00
 if 20 - 20: Oo0Ooo
 if 34 - 34: I1Ii111 % i11iIiiIii / oO0o - i1IIi . o0oOOo0O0Ooo / oO0o
def lisp_remove_eid_from_map_notify_queue ( eid_list ) :
 if 68 - 68: I1Ii111 % Ii1I * Oo0Ooo - O0 . IiII
 if 1 - 1: I1ii11iIi11i
 if 18 - 18: i11iIiiIii % OoO0O00 % OOooOOo . OOooOOo * Ii1I / II111iiii
 if 81 - 81: iII111i % IiII / I11i
 if 50 - 50: IiII + i1IIi % I1Ii111
 oooOoo00OO0O0 = [ ]
 for i1iOOO00oo in eid_list :
  for oooo0ooOO0 in lisp_map_notify_queue :
   o0oo0 = lisp_map_notify_queue [ oooo0ooOO0 ]
   if ( i1iOOO00oo not in o0oo0 . eid_list ) : continue
   if 31 - 31: OoOoOO00 * o0oOOo0O0Ooo / O0 . iII111i / i11iIiiIii
   oooOoo00OO0O0 . append ( oooo0ooOO0 )
   II1 = o0oo0 . retransmit_timer
   if ( II1 ) : II1 . cancel ( )
   if 17 - 17: I1ii11iIi11i - I1IiiI . O0
   lprint ( "Remove from Map-Notify queue nonce 0x{} for EID {}" . format ( o0oo0 . nonce_key , green ( i1iOOO00oo , False ) ) )
   if 5 - 5: OoOoOO00 % OoooooooOO - i1IIi / OoooooooOO * OOooOOo / O0
   if 67 - 67: IiII / I1ii11iIi11i - iII111i * O0 / II111iiii * oO0o
   if 9 - 9: i11iIiiIii % iIii1I11I1II1 + i11iIiiIii + Oo0Ooo % OOooOOo
   if 58 - 58: iII111i + OOooOOo / i1IIi * ooOoO0o
   if 37 - 37: OoO0O00
   if 19 - 19: ooOoO0o
   if 4 - 4: Oo0Ooo - i1IIi . Oo0Ooo * I11i . i1IIi + OOooOOo
 for oooo0ooOO0 in oooOoo00OO0O0 : lisp_map_notify_queue . pop ( oooo0ooOO0 )
 return
 if 3 - 3: IiII / iII111i * iII111i
 if 15 - 15: O0 + I1IiiI * OoO0O00 - i1IIi + Ii1I . i1IIi
 if 99 - 99: II111iiii + iIii1I11I1II1 / o0oOOo0O0Ooo / i11iIiiIii % iIii1I11I1II1 - iIii1I11I1II1
 if 38 - 38: I1IiiI . oO0o - II111iiii
 if 37 - 37: i1IIi % oO0o / IiII * I11i + ooOoO0o % Oo0Ooo
 if 75 - 75: o0oOOo0O0Ooo . I1Ii111 % i1IIi . i11iIiiIii
 if 38 - 38: o0oOOo0O0Ooo - OoO0O00 - i11iIiiIii
 if 60 - 60: i11iIiiIii % iIii1I11I1II1 * I1ii11iIi11i * iII111i . oO0o + iII111i
def lisp_decrypt_map_register ( packet ) :
 if 29 - 29: Oo0Ooo
 if 16 - 16: oO0o
 if 52 - 52: I11i * I1IiiI % I11i - iII111i - Ii1I - OoooooooOO
 if 15 - 15: iII111i
 if 95 - 95: i11iIiiIii . Ii1I / II111iiii + II111iiii + Ii1I / I11i
 IIiiIiIIiI1 = socket . ntohl ( struct . unpack ( "I" , packet [ 0 : 4 ] ) [ 0 ] )
 O00 = ( IIiiIiIIiI1 >> 13 ) & 0x1
 if ( O00 == 0 ) : return ( packet )
 if 94 - 94: II111iiii . Oo0Ooo - ooOoO0o
 o000OO0O0 = ( IIiiIiIIiI1 >> 14 ) & 0x7
 if 14 - 14: II111iiii . O0 + ooOoO0o
 if 62 - 62: II111iiii * o0oOOo0O0Ooo . OoO0O00 / II111iiii
 if 5 - 5: OoO0O00 + O0 . OoooooooOO + I1IiiI + i1IIi * OOooOOo
 if 19 - 19: OoooooooOO + i11iIiiIii / II111iiii - Oo0Ooo . OOooOOo
 try :
  iIIIIIIIi11I1 = lisp_ms_encryption_keys [ o000OO0O0 ]
  iIIIIIIIi11I1 = iIIIIIIIi11I1 . zfill ( 32 )
  Ooo = "0" * 8
 except :
  lprint ( "Cannot decrypt Map-Register with key-id {}" . format ( o000OO0O0 ) )
  return ( None )
  if 3 - 3: ooOoO0o % I1ii11iIi11i . ooOoO0o - iIii1I11I1II1 + Ii1I % I1Ii111
  if 29 - 29: I1Ii111 + OoOoOO00
 i1i11ii1Ii = bold ( "Decrypt" , False )
 lprint ( "{} Map-Register with key-id {}" . format ( i1i11ii1Ii , o000OO0O0 ) )
 if 26 - 26: OoooooooOO + I1ii11iIi11i * O0 * OOooOOo
 O0oo0ooo0 = chacha . ChaCha ( iIIIIIIIi11I1 , Ooo ) . decrypt ( packet [ 4 : : ] )
 return ( packet [ 0 : 4 ] + O0oo0ooo0 )
 if 65 - 65: i1IIi * ooOoO0o * OoooooooOO - i11iIiiIii + IiII - o0oOOo0O0Ooo
 if 12 - 12: I1IiiI
 if 34 - 34: o0oOOo0O0Ooo / I1IiiI * i11iIiiIii + I1Ii111 / IiII
 if 55 - 55: iIii1I11I1II1 % iIii1I11I1II1 % iII111i
 if 80 - 80: OoooooooOO % iII111i * IiII % IiII
 if 34 - 34: OoO0O00
 if 22 - 22: OOooOOo
def lisp_process_map_register ( lisp_sockets , packet , source , sport ) :
 global lisp_registered_count
 if 23 - 23: I1ii11iIi11i
 if 53 - 53: I11i
 if 64 - 64: iIii1I11I1II1 + O0 % IiII
 if 13 - 13: i11iIiiIii
 if 49 - 49: OoOoOO00
 if 61 - 61: I1Ii111 / I1Ii111 / iII111i / ooOoO0o - I1IiiI . o0oOOo0O0Ooo
 packet = lisp_decrypt_map_register ( packet )
 if ( packet == None ) : return
 if 80 - 80: I1IiiI - OOooOOo . oO0o
 oOOOoO0 = lisp_map_register ( )
 O0ooO00OO , packet = oOOOoO0 . decode ( packet )
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
 iIII = oOOOoO0 . record_count
 for oO in range ( iIII ) :
  I111IoOo0oOOO0o = lisp_eid_record ( )
  i1iIiII = lisp_rloc_record ( )
  packet = I111IoOo0oOOO0o . decode ( packet )
  if ( packet == None ) :
   lprint ( "Could not decode EID-record in Map-Register packet" )
   return
   if 32 - 32: o0oOOo0O0Ooo + OoooooooOO + I1ii11iIi11i + OoooooooOO . OOooOOo * o0oOOo0O0Ooo
  I111IoOo0oOOO0o . print_record ( "  " , False )
  if 8 - 8: I1ii11iIi11i . o0oOOo0O0Ooo + OoooooooOO
  if 52 - 52: i1IIi - oO0o
  if 33 - 33: Ii1I / I1ii11iIi11i . ooOoO0o . OoooooooOO
  if 45 - 45: OoO0O00 . I1ii11iIi11i + Ii1I / I11i - ooOoO0o / OoooooooOO
  IIII = lisp_site_eid_lookup ( I111IoOo0oOOO0o . eid , I111IoOo0oOOO0o . group ,
 False )
  if 44 - 44: OoO0O00 % O0 * IiII + iII111i
  o0OOoOOoo0oo0 = IIII . print_eid_tuple ( ) if IIII else None
  if 1 - 1: ooOoO0o . IiII
  if 4 - 4: iIii1I11I1II1 % I1IiiI - OoooooooOO / iII111i
  if 55 - 55: O0 + iII111i * OoOoOO00 . i11iIiiIii * Ii1I + oO0o
  if 66 - 66: i1IIi . I1ii11iIi11i
  if 86 - 86: Oo0Ooo
  if 48 - 48: OoO0O00
  if 55 - 55: OoO0O00 * i1IIi * I11i / iII111i
  if ( IIII and IIII . accept_more_specifics == False ) :
   if ( IIII . eid_record_matches ( I111IoOo0oOOO0o ) == False ) :
    iiiIIIII1iIi = IIII . parent_for_more_specifics
    if ( iiiIIIII1iIi ) : IIII = iiiIIIII1iIi
    if 8 - 8: o0oOOo0O0Ooo * OoO0O00 % IiII / OoooooooOO * ooOoO0o - i11iIiiIii
    if 14 - 14: Oo0Ooo . iII111i
    if 50 - 50: iIii1I11I1II1
    if 48 - 48: Ii1I - o0oOOo0O0Ooo - Oo0Ooo . iIii1I11I1II1
    if 1 - 1: i1IIi % OoooooooOO
    if 30 - 30: ooOoO0o % I11i
    if 4 - 4: oO0o / OoO0O00
    if 90 - 90: I11i . IiII / OoO0O00 . IiII
  OoO0OOoooooOO = ( IIII and IIII . accept_more_specifics )
  if ( OoO0OOoooooOO ) :
   i1iIIiii = lisp_site_eid ( IIII . site )
   i1iIIiii . dynamic = True
   i1iIIiii . eid . copy_address ( I111IoOo0oOOO0o . eid )
   i1iIIiii . group . copy_address ( I111IoOo0oOOO0o . group )
   i1iIIiii . parent_for_more_specifics = IIII
   i1iIIiii . add_cache ( )
   i1iIIiii . inherit_from_ams_parent ( )
   IIII . more_specific_registrations . append ( i1iIIiii )
   IIII = i1iIIiii
  else :
   IIII = lisp_site_eid_lookup ( I111IoOo0oOOO0o . eid , I111IoOo0oOOO0o . group ,
 True )
   if 2 - 2: I11i + I1IiiI . IiII . OoOoOO00 * oO0o - ooOoO0o
   if 29 - 29: OoO0O00
  oo0ooooO = I111IoOo0oOOO0o . print_eid_tuple ( )
  if 78 - 78: iII111i * ooOoO0o + O0 % ooOoO0o + OoO0O00
  if ( IIII == None ) :
   oOo00 = bold ( "Site not found" , False )
   lprint ( "  {} for EID {}{}" . format ( oOo00 , green ( oo0ooooO , False ) ,
 ", matched non-ams {}" . format ( green ( o0OOoOOoo0oo0 , False ) if o0OOoOOoo0oo0 else "" ) ) )
   if 41 - 41: II111iiii . oO0o + O0 % i1IIi . Ii1I
   if 90 - 90: ooOoO0o * I1IiiI / II111iiii % Oo0Ooo % OoooooooOO
   if 78 - 78: OoooooooOO . IiII
   if 55 - 55: I11i / I1ii11iIi11i * O0 + IiII % I11i
   if 69 - 69: o0oOOo0O0Ooo % iIii1I11I1II1 . OoooooooOO - ooOoO0o
   packet = i1iIiII . end_of_rlocs ( packet , I111IoOo0oOOO0o . rloc_count )
   if ( packet == None ) :
    lprint ( "  Could not decode RLOC-record in Map-Register packet" )
    return
    if 94 - 94: iIii1I11I1II1 / Oo0Ooo % IiII * IiII
   continue
   if 62 - 62: I11i . IiII - OOooOOo - I1Ii111 / OoooooooOO . Ii1I
   if 28 - 28: iII111i / I1ii11iIi11i - OoOoOO00 * Oo0Ooo + Ii1I * OoOoOO00
  I1ii1I = IIII . site
  if 94 - 94: oO0o
  if ( OoO0OOoooooOO ) :
   I1i11II = IIII . parent_for_more_specifics . print_eid_tuple ( )
   lprint ( "  Found ams {} for site '{}' for registering prefix {}" . format ( green ( I1i11II , False ) , I1ii1I . site_name , green ( oo0ooooO , False ) ) )
   if 95 - 95: ooOoO0o * O0 + OOooOOo
  else :
   I1i11II = green ( IIII . print_eid_tuple ( ) , False )
   lprint ( "  Found {} for site '{}' for registering prefix {}" . format ( I1i11II , I1ii1I . site_name , green ( oo0ooooO , False ) ) )
   if 11 - 11: i1IIi / OoOoOO00 + OoOoOO00 + I1ii11iIi11i + OOooOOo
   if 21 - 21: ooOoO0o
   if 28 - 28: OoOoOO00 + OoOoOO00 - OoOoOO00 / ooOoO0o
   if 81 - 81: oO0o
   if 34 - 34: o0oOOo0O0Ooo * OOooOOo - i1IIi * o0oOOo0O0Ooo * Oo0Ooo
   if 59 - 59: iIii1I11I1II1 / Oo0Ooo % II111iiii
  if ( I1ii1I . shutdown ) :
   lprint ( ( "  Rejecting registration for site '{}', configured in " +
 "admin-shutdown state" ) . format ( I1ii1I . site_name ) )
   packet = i1iIiII . end_of_rlocs ( packet , I111IoOo0oOOO0o . rloc_count )
   continue
   if 55 - 55: ooOoO0o - IiII + o0oOOo0O0Ooo
   if 48 - 48: O0 - iIii1I11I1II1 * OOooOOo
   if 33 - 33: I11i
   if 63 - 63: Ii1I % II111iiii / OoOoOO00 + Oo0Ooo
   if 28 - 28: OoO0O00 + I1IiiI . oO0o + II111iiii - O0
   if 32 - 32: oO0o
   if 62 - 62: i11iIiiIii + OoooooooOO + IiII - OoO0O00 / oO0o * iIii1I11I1II1
   if 91 - 91: o0oOOo0O0Ooo - i11iIiiIii + Oo0Ooo % iIii1I11I1II1
  I1 = oOOOoO0 . key_id
  if ( I1ii1I . auth_key . has_key ( I1 ) == False ) : I1 = 0
  O0O0 = I1ii1I . auth_key [ I1 ]
  if 40 - 40: I1Ii111 * OoOoOO00 * Ii1I % iII111i % ooOoO0o . Ii1I
  i111II = lisp_verify_auth ( O0ooO00OO , oOOOoO0 . alg_id ,
 oOOOoO0 . auth_data , O0O0 )
  iiIi1i1i = "dynamic " if IIII . dynamic else ""
  if 69 - 69: i11iIiiIii + Oo0Ooo / II111iiii % OoOoOO00
  o0OOo0o0 = bold ( "passed" if i111II else "failed" , False )
  I1 = "key-id {}" . format ( I1 ) if I1 == oOOOoO0 . key_id else "bad key-id {}" . format ( oOOOoO0 . key_id )
  if 4 - 4: II111iiii + ooOoO0o
  lprint ( "  Authentication {} for {}EID-prefix {}, {}" . format ( o0OOo0o0 , iiIi1i1i , green ( oo0ooooO , False ) , I1 ) )
  if 25 - 25: I1IiiI - iIii1I11I1II1
  if 11 - 11: I1Ii111 / iII111i - I11i
  if 87 - 87: I1Ii111 * i11iIiiIii . OOooOOo . OoooooooOO
  if 2 - 2: i11iIiiIii + oO0o
  if 40 - 40: i11iIiiIii + oO0o * IiII
  if 19 - 19: iII111i / II111iiii . I1Ii111 * I1IiiI - OOooOOo
  oO0OoO0 = True
  O0o0O0oooo0O = ( lisp_get_eid_hash ( I111IoOo0oOOO0o . eid ) != None )
  if ( O0o0O0oooo0O or IIII . require_signature ) :
   o000000oOooO = "Required " if IIII . require_signature else ""
   oo0ooooO = green ( oo0ooooO , False )
   i1IIIIi1Ii111 = lisp_find_sig_in_rloc_set ( packet , I111IoOo0oOOO0o . rloc_count )
   if ( i1IIIIi1Ii111 == None ) :
    oO0OoO0 = False
    lprint ( ( "  {}EID-crypto-hash signature verification {} " + "for EID-prefix {}, no signature found" ) . format ( o000000oOooO ,
    # OOooOOo
 bold ( "failed" , False ) , oo0ooooO ) )
   else :
    oO0OoO0 = lisp_verify_cga_sig ( I111IoOo0oOOO0o . eid , i1IIIIi1Ii111 )
    o0OOo0o0 = bold ( "passed" if oO0OoO0 else "failed" , False )
    lprint ( ( "  {}EID-crypto-hash signature verification {} " + "for EID-prefix {}" ) . format ( o000000oOooO , o0OOo0o0 , oo0ooooO ) )
    if 88 - 88: OoooooooOO / iII111i + i1IIi
    if 64 - 64: IiII % I11i / iIii1I11I1II1
    if 66 - 66: Ii1I
    if 55 - 55: OOooOOo + I1IiiI + IiII . Ii1I * oO0o
  if ( i111II == False or oO0OoO0 == False ) :
   packet = i1iIiII . end_of_rlocs ( packet , I111IoOo0oOOO0o . rloc_count )
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
   iiiIIIII1iIi = IIII
   iiiIIIII1iIi . inconsistent_registration = False
   if 22 - 22: Ii1I / I1IiiI / II111iiii
   if 31 - 31: II111iiii - Ii1I * OOooOOo - i11iIiiIii / OoooooooOO - I1Ii111
   if 76 - 76: Oo0Ooo
   if 93 - 93: i1IIi - I1IiiI * i11iIiiIii / Ii1I . Ii1I - i1IIi
   if 19 - 19: iIii1I11I1II1 * OOooOOo * Oo0Ooo % I1IiiI
   if ( IIII . group . is_null ( ) ) :
    if ( iiiIIIII1iIi . site_id != oOOOoO0 . site_id ) :
     iiiIIIII1iIi . site_id = oOOOoO0 . site_id
     iiiIIIII1iIi . registered = False
     iiiIIIII1iIi . individual_registrations = { }
     iiiIIIII1iIi . registered_rlocs = [ ]
     lisp_registered_count -= 1
     if 93 - 93: IiII % OoOoOO00 / I1IiiI + o0oOOo0O0Ooo * ooOoO0o / i1IIi
     if 25 - 25: O0 / Oo0Ooo - o0oOOo0O0Ooo * Oo0Ooo
     if 45 - 45: Ii1I * IiII - OOooOOo
   i1IIiI1iII = source . address + oOOOoO0 . xtr_id
   if ( IIII . individual_registrations . has_key ( i1IIiI1iII ) ) :
    IIII = IIII . individual_registrations [ i1IIiI1iII ]
   else :
    IIII = lisp_site_eid ( I1ii1I )
    IIII . eid . copy_address ( iiiIIIII1iIi . eid )
    IIII . group . copy_address ( iiiIIIII1iIi . group )
    iiiIIIII1iIi . individual_registrations [ i1IIiI1iII ] = IIII
    if 57 - 57: iII111i % OoO0O00 / OoooooooOO
  else :
   IIII . inconsistent_registration = IIII . merge_register_requested
   if 69 - 69: oO0o
   if 44 - 44: IiII - II111iiii % Ii1I
   if 64 - 64: Ii1I % OoO0O00 + OOooOOo % OoOoOO00 + IiII
  IIII . map_registers_received += 1
  if 92 - 92: iII111i * Oo0Ooo - OoOoOO00
  if 33 - 33: i11iIiiIii - OoOoOO00 . OOooOOo * II111iiii . Ii1I
  if 59 - 59: OoOoOO00
  if 29 - 29: iII111i - II111iiii * OoooooooOO * OoooooooOO
  if 15 - 15: IiII / OOooOOo / iIii1I11I1II1 / OoOoOO00
  o0o0Oo = ( IIII . is_rloc_in_rloc_set ( source ) == False )
  if ( I111IoOo0oOOO0o . record_ttl == 0 and o0o0Oo ) :
   lprint ( "  Ignore deregistration request from {}" . format ( red ( source . print_address_no_iid ( ) , False ) ) )
   if 91 - 91: i11iIiiIii % O0 . Oo0Ooo / I1Ii111
   continue
   if 62 - 62: Oo0Ooo . II111iiii % OoO0O00 . Ii1I * OOooOOo + II111iiii
   if 7 - 7: OOooOOo
   if 22 - 22: Oo0Ooo + ooOoO0o
   if 71 - 71: OOooOOo . Ii1I * i11iIiiIii . I11i
   if 9 - 9: O0 / I1ii11iIi11i . iII111i . O0 + IiII % I11i
   if 27 - 27: i11iIiiIii - I1ii11iIi11i / O0 - i1IIi + I1IiiI * iII111i
  iI1iIIIIiiii = IIII . registered_rlocs
  IIII . registered_rlocs = [ ]
  if 17 - 17: II111iiii - I1Ii111 - i11iIiiIii - iIii1I11I1II1
  if 10 - 10: I1IiiI
  if 40 - 40: OoO0O00 * oO0o / OoOoOO00
  if 37 - 37: iII111i * oO0o / I1IiiI * I1ii11iIi11i
  oOo0000 = packet
  for Ii1i1Ii in range ( I111IoOo0oOOO0o . rloc_count ) :
   i1iIiII = lisp_rloc_record ( )
   packet = i1iIiII . decode ( packet , None )
   if ( packet == None ) :
    lprint ( "  Could not decode RLOC-record in Map-Register packet" )
    return
    if 59 - 59: I1Ii111 % o0oOOo0O0Ooo - I1IiiI * i1IIi
   i1iIiII . print_record ( "    " )
   if 5 - 5: I1IiiI
   if 22 - 22: II111iiii / iII111i
   if 18 - 18: i11iIiiIii * ooOoO0o . I1IiiI + i1IIi + I11i
   if 62 - 62: O0 % o0oOOo0O0Ooo + iIii1I11I1II1 + iIii1I11I1II1 * ooOoO0o
   if ( len ( I1ii1I . allowed_rlocs ) > 0 ) :
    OoOOoooO000 = i1iIiII . rloc . print_address ( )
    if ( I1ii1I . allowed_rlocs . has_key ( OoOOoooO000 ) == False ) :
     lprint ( ( "  Reject registration, RLOC {} not " + "configured in allowed RLOC-set" ) . format ( red ( OoOOoooO000 , False ) ) )
     if 21 - 21: o0oOOo0O0Ooo % O0
     if 81 - 81: i1IIi + i1IIi
     IIII . registered = False
     packet = i1iIiII . end_of_rlocs ( packet ,
 I111IoOo0oOOO0o . rloc_count - Ii1i1Ii - 1 )
     break
     if 3 - 3: I1Ii111 . I1ii11iIi11i * iII111i * i11iIiiIii * IiII
     if 52 - 52: iIii1I11I1II1 % o0oOOo0O0Ooo % I1IiiI
     if 71 - 71: I1IiiI + iII111i
     if 47 - 47: iIii1I11I1II1 . OoO0O00 . iIii1I11I1II1
     if 57 - 57: IiII * ooOoO0o * ooOoO0o * iIii1I11I1II1 * I1Ii111 + OoOoOO00
     if 83 - 83: OoOoOO00 . Oo0Ooo . OoO0O00
   i1IIIIi1Ii111 = lisp_rloc ( )
   i1IIIIi1Ii111 . store_rloc_from_record ( i1iIiII , None , source )
   if 65 - 65: iII111i * iIii1I11I1II1
   if 48 - 48: iII111i * OoO0O00
   if 57 - 57: ooOoO0o + I1IiiI
   if 32 - 32: I1ii11iIi11i + OOooOOo - I11i
   if 82 - 82: Oo0Ooo % Oo0Ooo
   if 91 - 91: I11i
   if ( source . is_exact_match ( i1IIIIi1Ii111 . rloc ) ) :
    i1IIIIi1Ii111 . map_notify_requested = oOOOoO0 . map_notify_requested
    if 98 - 98: I11i - II111iiii . IiII % Oo0Ooo
    if 65 - 65: OoO0O00
    if 65 - 65: oO0o
    if 77 - 77: I11i * i1IIi - OOooOOo / OoOoOO00
    if 50 - 50: O0 - oO0o . oO0o
   IIII . registered_rlocs . append ( i1IIIIi1Ii111 )
   if 98 - 98: IiII % Ii1I / Ii1I
   if 10 - 10: Ii1I
  O0oo0Oo0Oo00o = ( IIII . do_rloc_sets_match ( iI1iIIIIiiii ) == False )
  if 94 - 94: O0 + II111iiii - iII111i / i1IIi
  if 25 - 25: ooOoO0o . OoO0O00 - oO0o
  if 76 - 76: iIii1I11I1II1 / II111iiii * OoOoOO00 % iII111i . II111iiii + i11iIiiIii
  if 41 - 41: oO0o . o0oOOo0O0Ooo . I11i
  if 53 - 53: I11i
  if 64 - 64: OoO0O00 + I11i / I1IiiI . II111iiii
  if ( oOOOoO0 . map_register_refresh and O0oo0Oo0Oo00o and
 IIII . registered ) :
   lprint ( "  Reject registration, refreshes cannot change RLOC-set" )
   IIII . registered_rlocs = iI1iIIIIiiii
   continue
   if 79 - 79: I1Ii111 + IiII / OoooooooOO
   if 53 - 53: Ii1I
   if 85 - 85: OoO0O00 + II111iiii / OoO0O00 . II111iiii * OoOoOO00 * I1IiiI
   if 19 - 19: iII111i / Ii1I + iIii1I11I1II1 * O0 - Oo0Ooo
   if 47 - 47: iIii1I11I1II1 % I1ii11iIi11i
   if 33 - 33: oO0o . oO0o / IiII + II111iiii
  if ( IIII . registered == False ) :
   IIII . first_registered = lisp_get_timestamp ( )
   lisp_registered_count += 1
   if 34 - 34: OoO0O00 . OoOoOO00 / i1IIi / OOooOOo
  IIII . last_registered = lisp_get_timestamp ( )
  IIII . registered = ( I111IoOo0oOOO0o . record_ttl != 0 )
  IIII . last_registerer = source
  if 12 - 12: o0oOOo0O0Ooo . Oo0Ooo / II111iiii
  if 18 - 18: I1Ii111 % II111iiii + Ii1I * Oo0Ooo - OoooooooOO . Oo0Ooo
  if 25 - 25: OoO0O00
  if 83 - 83: II111iiii . iIii1I11I1II1
  IIII . auth_sha1_or_sha2 = Iiii
  IIII . proxy_reply_requested = oOOOoO0 . proxy_reply_requested
  IIII . lisp_sec_present = oOOOoO0 . lisp_sec_present
  IIII . map_notify_requested = oOOOoO0 . map_notify_requested
  IIII . mobile_node_requested = oOOOoO0 . mobile_node
  IIII . merge_register_requested = oOOOoO0 . merge_register_requested
  if 77 - 77: O0 . OoOoOO00 % oO0o / OOooOOo
  IIII . use_register_ttl_requested = oOOOoO0 . use_ttl_for_timeout
  if ( IIII . use_register_ttl_requested ) :
   IIII . register_ttl = I111IoOo0oOOO0o . store_ttl ( )
  else :
   IIII . register_ttl = LISP_SITE_TIMEOUT_CHECK_INTERVAL * 3
   if 8 - 8: iII111i - i1IIi
  IIII . xtr_id_present = oOOOoO0 . xtr_id_present
  if ( IIII . xtr_id_present ) :
   IIII . xtr_id = oOOOoO0 . xtr_id
   IIII . site_id = oOOOoO0 . site_id
   if 81 - 81: ooOoO0o / OOooOOo % OoOoOO00 . iIii1I11I1II1
   if 45 - 45: I1IiiI . ooOoO0o - OoooooooOO
   if 84 - 84: I1ii11iIi11i
   if 69 - 69: I1Ii111 + II111iiii
   if 92 - 92: OoooooooOO
  if ( oOOOoO0 . merge_register_requested ) :
   if ( iiiIIIII1iIi . merge_in_site_eid ( IIII ) ) :
    o00OO00o00 . append ( [ I111IoOo0oOOO0o . eid , I111IoOo0oOOO0o . group ] )
    if 80 - 80: I1ii11iIi11i % I1ii11iIi11i . OoO0O00 . oO0o % I1IiiI % I11i
   if ( oOOOoO0 . map_notify_requested ) :
    lisp_send_merged_map_notify ( lisp_sockets , iiiIIIII1iIi , oOOOoO0 ,
 I111IoOo0oOOO0o )
    if 4 - 4: OoO0O00 / iII111i / I1ii11iIi11i - o0oOOo0O0Ooo * I1Ii111
    if 24 - 24: OoooooooOO / ooOoO0o + Oo0Ooo - OOooOOo - o0oOOo0O0Ooo . I1ii11iIi11i
    if 2 - 2: I1IiiI . o0oOOo0O0Ooo / Oo0Ooo - OoOoOO00 - OoooooooOO
  if ( O0oo0Oo0Oo00o == False ) : continue
  if ( len ( o00OO00o00 ) != 0 ) : continue
  if 73 - 73: I1Ii111 . i11iIiiIii * ooOoO0o . IiII - I11i + I1Ii111
  IiiiIIIi . append ( IIII . print_eid_tuple ( ) )
  if 21 - 21: I1Ii111 + iIii1I11I1II1 + I1IiiI / O0 * I1ii11iIi11i
  if 57 - 57: OOooOOo * I11i . oO0o
  if 17 - 17: iII111i - OOooOOo * I1IiiI + i1IIi % I1ii11iIi11i
  if 71 - 71: Ii1I - o0oOOo0O0Ooo - oO0o
  if 27 - 27: O0 - iIii1I11I1II1
  if 78 - 78: Oo0Ooo / o0oOOo0O0Ooo
  if 35 - 35: o0oOOo0O0Ooo . OoO0O00 / o0oOOo0O0Ooo / IiII - I1ii11iIi11i . Oo0Ooo
  I111IoOo0oOOO0o = I111IoOo0oOOO0o . encode ( )
  I111IoOo0oOOO0o += oOo0000
  i111i = [ IIII . print_eid_tuple ( ) ]
  lprint ( "    Changed RLOC-set, Map-Notifying old RLOC-set" )
  if 97 - 97: i11iIiiIii + I1ii11iIi11i - I11i . oO0o
  for i1IIIIi1Ii111 in iI1iIIIIiiii :
   if ( i1IIIIi1Ii111 . map_notify_requested == False ) : continue
   if ( i1IIIIi1Ii111 . rloc . is_exact_match ( source ) ) : continue
   lisp_build_map_notify ( lisp_sockets , I111IoOo0oOOO0o , i111i , 1 , i1IIIIi1Ii111 . rloc ,
 LISP_CTRL_PORT , oOOOoO0 . nonce , oOOOoO0 . key_id ,
 oOOOoO0 . alg_id , oOOOoO0 . auth_len , I1ii1I , False )
   if 76 - 76: IiII * II111iiii * I1ii11iIi11i + OoooooooOO - OoOoOO00 . Ii1I
   if 51 - 51: II111iiii % I1Ii111 * O0 . ooOoO0o * OoOoOO00
   if 17 - 17: I1IiiI % I11i
   if 28 - 28: I1ii11iIi11i * OoooooooOO
   if 19 - 19: Oo0Ooo - iII111i % OoOoOO00 * i11iIiiIii / oO0o . i11iIiiIii
  lisp_notify_subscribers ( lisp_sockets , I111IoOo0oOOO0o , IIII . eid , I1ii1I )
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
 o0oo0 = lisp_map_notify ( "" )
 packet = o0oo0 . decode ( packet )
 if ( packet == None ) :
  lprint ( "Could not decode Map-Notify packet" )
  return
  if 30 - 30: oO0o
  if 64 - 64: O0
 o0oo0 . print_notify ( )
 if ( o0oo0 . record_count == 0 ) : return
 if 70 - 70: oO0o % I1IiiI . iIii1I11I1II1 - Oo0Ooo + OoOoOO00 % O0
 O00OO0OO = o0oo0 . eid_records
 if 38 - 38: OoooooooOO . i1IIi - i1IIi + iIii1I11I1II1 * OOooOOo - I1IiiI
 for oO in range ( o0oo0 . record_count ) :
  I111IoOo0oOOO0o = lisp_eid_record ( )
  O00OO0OO = I111IoOo0oOOO0o . decode ( O00OO0OO )
  if ( packet == None ) : return
  I111IoOo0oOOO0o . print_record ( "  " , False )
  if 92 - 92: I11i
  if 77 - 77: I11i / iII111i / O0 % II111iiii % OoOoOO00 / I1Ii111
  if 77 - 77: OoOoOO00 % I1IiiI % II111iiii * iII111i . OoOoOO00 / O0
  if 21 - 21: ooOoO0o - I11i . i11iIiiIii
  Iii1 = lisp_map_cache_lookup ( I111IoOo0oOOO0o . eid , I111IoOo0oOOO0o . group )
  if ( Iii1 == None ) :
   Iii1 = lisp_mapping ( I111IoOo0oOOO0o . eid , I111IoOo0oOOO0o . group , [ ] )
   Iii1 . add_cache ( )
   if 39 - 39: Oo0Ooo * II111iiii % OOooOOo / oO0o . ooOoO0o
   if 75 - 75: I11i / O0 + OoooooooOO + OOooOOo % iII111i + I1IiiI
  Iii1 . mapping_source = None if source == "lisp-etr" else source
  Iii1 . map_cache_ttl = I111IoOo0oOOO0o . store_ttl ( )
  if 10 - 10: II111iiii * I11i - IiII * iIii1I11I1II1 . OoooooooOO
  if 39 - 39: I11i . I1IiiI % Oo0Ooo + oO0o
  if 76 - 76: I1IiiI * OoooooooOO - i11iIiiIii / I11i / Oo0Ooo
  if 82 - 82: IiII % ooOoO0o
  if 100 - 100: Oo0Ooo . oO0o - iII111i + OoooooooOO
  if ( len ( Iii1 . rloc_set ) != 0 and I111IoOo0oOOO0o . rloc_count == 0 ) :
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
  for Ii1i1Ii in range ( I111IoOo0oOOO0o . rloc_count ) :
   i1iIiII = lisp_rloc_record ( )
   O00OO0OO = i1iIiII . decode ( O00OO0OO , None )
   i1iIiII . print_record ( "    " )
   if ( I111IoOo0oOOO0o . group . is_null ( ) ) : continue
   if ( i1iIiII . rle == None ) : continue
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
   i1IIIIi1Ii111 = lisp_rloc ( )
   i1IIIIi1Ii111 . store_rloc_from_record ( i1iIiII , None , Iii1 . mapping_source )
   if ( oO000O0oooOo != None ) : i1IIIIi1Ii111 . stats = copy . deepcopy ( oO000O0oooOo )
   if 20 - 20: OoO0O00 . OoooooooOO - I1Ii111 * IiII
   if ( I11iI1iIi1i and i1IIIIi1Ii111 . is_rtr ( ) == False ) : continue
   if 20 - 20: o0oOOo0O0Ooo . OoooooooOO * I1IiiI . Oo0Ooo * OoOoOO00
   Iii1 . rloc_set = [ i1IIIIi1Ii111 ]
   Iii1 . build_best_rloc_set ( )
   lisp_write_ipc_map_cache ( True , Iii1 )
   if 3 - 3: I1Ii111 % i11iIiiIii % O0 % II111iiii
   lprint ( "Update {} map-cache entry with RLE {}" . format ( green ( Iii1 . print_eid_tuple ( ) , False ) , i1IIIIi1Ii111 . rle . print_rle ( False ) ) )
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
 o0oo0 = lisp_map_notify ( "" )
 iI1IIII1ii1 = o0oo0 . decode ( orig_packet )
 if ( iI1IIII1ii1 == None ) :
  lprint ( "Could not decode Map-Notify packet" )
  return
  if 81 - 81: oO0o / I11i % Ii1I . I11i + OoooooooOO
  if 31 - 31: OoO0O00
 o0oo0 . print_notify ( )
 if 41 - 41: i11iIiiIii - I1ii11iIi11i - II111iiii
 if 5 - 5: OoOoOO00 + i1IIi
 if 43 - 43: iII111i * I1IiiI
 if 20 - 20: I1IiiI . I11i * OoO0O00 . ooOoO0o . II111iiii
 if 6 - 6: Ii1I * OoOoOO00 % IiII + I11i
 i1I1iIi1IiI = source . print_address ( )
 if ( o0oo0 . alg_id != 0 or o0oo0 . auth_len != 0 ) :
  ii1I111i = None
  for i1IIiI1iII in lisp_map_servers_list :
   if ( i1IIiI1iII . find ( i1I1iIi1IiI ) == - 1 ) : continue
   ii1I111i = lisp_map_servers_list [ i1IIiI1iII ]
   if 20 - 20: oO0o
  if ( ii1I111i == None ) :
   lprint ( ( "  Could not find Map-Server {} to authenticate " + "Map-Notify" ) . format ( i1I1iIi1IiI ) )
   if 34 - 34: i1IIi + oO0o * Oo0Ooo * I1Ii111 % OoooooooOO % ooOoO0o
   return
   if 17 - 17: I1ii11iIi11i + o0oOOo0O0Ooo / OoO0O00 . Oo0Ooo - o0oOOo0O0Ooo / oO0o
   if 87 - 87: ooOoO0o
  ii1I111i . map_notifies_received += 1
  if 74 - 74: i11iIiiIii . i11iIiiIii . iIii1I11I1II1
  i111II = lisp_verify_auth ( iI1IIII1ii1 , o0oo0 . alg_id ,
 o0oo0 . auth_data , ii1I111i . password )
  if 100 - 100: i11iIiiIii - oO0o + iIii1I11I1II1 * OoOoOO00 % OOooOOo % i11iIiiIii
  lprint ( "  Authentication {} for Map-Notify" . format ( "succeeded" if i111II else "failed" ) )
  if 26 - 26: O0
  if ( i111II == False ) : return
 else :
  ii1I111i = lisp_ms ( i1I1iIi1IiI , None , "" , 0 , "" , False , False , False , False , 0 , 0 , 0 ,
 None )
  if 97 - 97: OOooOOo + I11i % I1Ii111 % i11iIiiIii / I1ii11iIi11i
  if 21 - 21: O0 + iIii1I11I1II1 / i11iIiiIii . OOooOOo * i1IIi
  if 3 - 3: i1IIi % o0oOOo0O0Ooo + OoOoOO00
  if 32 - 32: OoO0O00 . Oo0Ooo * iIii1I11I1II1
  if 12 - 12: O0 + I1ii11iIi11i + I11i . I1Ii111
  if 48 - 48: Ii1I . iIii1I11I1II1 - iIii1I11I1II1 * I11i . OoooooooOO
 O00OO0OO = o0oo0 . eid_records
 if ( o0oo0 . record_count == 0 ) :
  lisp_send_map_notify_ack ( lisp_sockets , O00OO0OO , o0oo0 , ii1I111i )
  return
  if 73 - 73: Ii1I / II111iiii - iIii1I11I1II1 . ooOoO0o * II111iiii . OOooOOo
  if 50 - 50: iIii1I11I1II1 + OoOoOO00 % O0 + OoO0O00 . i11iIiiIii / oO0o
  if 31 - 31: I1IiiI % o0oOOo0O0Ooo . i11iIiiIii % OOooOOo - iIii1I11I1II1
  if 77 - 77: i11iIiiIii / OOooOOo
  if 93 - 93: I1ii11iIi11i - iII111i % O0 - Ii1I
  if 84 - 84: I1ii11iIi11i . iIii1I11I1II1 % IiII * I11i + ooOoO0o
  if 59 - 59: oO0o * OoO0O00 - I11i * I1IiiI
  if 60 - 60: iII111i - OoooooooOO / iII111i % OoO0O00 . OoOoOO00 - o0oOOo0O0Ooo
 I111IoOo0oOOO0o = lisp_eid_record ( )
 iI1IIII1ii1 = I111IoOo0oOOO0o . decode ( O00OO0OO )
 if ( iI1IIII1ii1 == None ) : return
 if 71 - 71: iII111i * o0oOOo0O0Ooo * i11iIiiIii * O0
 I111IoOo0oOOO0o . print_record ( "  " , False )
 if 77 - 77: OOooOOo % iII111i + I11i / OoOoOO00
 for Ii1i1Ii in range ( I111IoOo0oOOO0o . rloc_count ) :
  i1iIiII = lisp_rloc_record ( )
  iI1IIII1ii1 = i1iIiII . decode ( iI1IIII1ii1 , None )
  if ( iI1IIII1ii1 == None ) :
   lprint ( "  Could not decode RLOC-record in Map-Notify packet" )
   return
   if 50 - 50: OoOoOO00 - i11iIiiIii - OOooOOo . iIii1I11I1II1
  i1iIiII . print_record ( "    " )
  if 97 - 97: oO0o % OOooOOo . OoooooooOO * Ii1I
  if 100 - 100: I1ii11iIi11i / Ii1I % Oo0Ooo
  if 83 - 83: O0 . I1Ii111 % I1ii11iIi11i
  if 97 - 97: Oo0Ooo % OoO0O00 * I1ii11iIi11i * ooOoO0o * OoO0O00
  if 12 - 12: ooOoO0o
 if ( I111IoOo0oOOO0o . group . is_null ( ) == False ) :
  if 56 - 56: i1IIi
  if 3 - 3: OOooOOo - Oo0Ooo * Ii1I + i11iIiiIii
  if 53 - 53: i1IIi % I1ii11iIi11i
  if 65 - 65: I11i + OoOoOO00 - i11iIiiIii
  if 72 - 72: i11iIiiIii - iII111i . i11iIiiIii
  lprint ( "Send {} Map-Notify IPC message to ITR process" . format ( green ( I111IoOo0oOOO0o . print_eid_tuple ( ) , False ) ) )
  if 61 - 61: oO0o . i11iIiiIii / Ii1I % iII111i
  if 36 - 36: OoO0O00 + Ii1I / I11i - iII111i % OoO0O00 / Oo0Ooo
  Oooo000 = lisp_control_packet_ipc ( orig_packet , i1I1iIi1IiI , "lisp-itr" , 0 )
  lisp_ipc ( Oooo000 , lisp_sockets [ 2 ] , "lisp-core-pkt" )
  if 38 - 38: Ii1I - ooOoO0o - O0 + oO0o . iIii1I11I1II1
  if 90 - 90: i1IIi * OoOoOO00
  if 27 - 27: iIii1I11I1II1
  if 95 - 95: iII111i / ooOoO0o % Ii1I
  if 44 - 44: OOooOOo . OOooOOo
 lisp_send_map_notify_ack ( lisp_sockets , O00OO0OO , o0oo0 , ii1I111i )
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
 o0oo0 = lisp_map_notify ( "" )
 packet = o0oo0 . decode ( packet )
 if ( packet == None ) :
  lprint ( "Could not decode Map-Notify-Ack packet" )
  return
  if 11 - 11: o0oOOo0O0Ooo
  if 77 - 77: o0oOOo0O0Ooo / iIii1I11I1II1 * iIii1I11I1II1 / o0oOOo0O0Ooo * iII111i
 o0oo0 . print_notify ( )
 if 26 - 26: Ii1I
 if 1 - 1: OoOoOO00 . o0oOOo0O0Ooo + Oo0Ooo % Oo0Ooo * I1ii11iIi11i
 if 50 - 50: IiII / i1IIi . I1ii11iIi11i
 if 75 - 75: I11i * oO0o + OoooooooOO . iII111i + OoO0O00
 if 44 - 44: II111iiii
 if ( o0oo0 . record_count < 1 ) :
  lprint ( "No EID-prefix found, cannot authenticate Map-Notify-Ack" )
  return
  if 65 - 65: I11i . iII111i . I1IiiI - Oo0Ooo % iIii1I11I1II1 / O0
  if 54 - 54: iII111i - I1Ii111
 I111IoOo0oOOO0o = lisp_eid_record ( )
 if 88 - 88: iII111i * OoO0O00 % OoooooooOO / oO0o
 if ( I111IoOo0oOOO0o . decode ( o0oo0 . eid_records ) == None ) :
  lprint ( "Could not decode EID-record, cannot authenticate " +
 "Map-Notify-Ack" )
  return
  if 7 - 7: i1IIi
 I111IoOo0oOOO0o . print_record ( "  " , False )
 if 30 - 30: oO0o . i1IIi / I11i
 oo0ooooO = I111IoOo0oOOO0o . print_eid_tuple ( )
 if 23 - 23: i1IIi + oO0o % iII111i - OoO0O00 - i1IIi
 if 74 - 74: Ii1I + I11i . OoooooooOO - I1ii11iIi11i
 if 2 - 2: oO0o - o0oOOo0O0Ooo
 if 80 - 80: i1IIi
 if ( o0oo0 . alg_id != LISP_NONE_ALG_ID and o0oo0 . auth_len != 0 ) :
  IIII = lisp_sites_by_eid . lookup_cache ( I111IoOo0oOOO0o . eid , True )
  if ( IIII == None ) :
   oOo00 = bold ( "Site not found" , False )
   lprint ( ( "{} for EID {}, cannot authenticate Map-Notify-Ack" ) . format ( oOo00 , green ( oo0ooooO , False ) ) )
   if 40 - 40: O0 . ooOoO0o * iII111i . I11i + I1Ii111 % OoO0O00
   return
   if 9 - 9: IiII * oO0o - o0oOOo0O0Ooo
  I1ii1I = IIII . site
  if 17 - 17: iII111i % Oo0Ooo
  if 14 - 14: I1IiiI - I1Ii111 % I1IiiI - II111iiii
  if 34 - 34: I1ii11iIi11i * IiII / II111iiii / ooOoO0o * oO0o
  if 3 - 3: II111iiii
  I1ii1I . map_notify_acks_received += 1
  if 61 - 61: oO0o . I1IiiI + i1IIi
  I1 = o0oo0 . key_id
  if ( I1ii1I . auth_key . has_key ( I1 ) == False ) : I1 = 0
  O0O0 = I1ii1I . auth_key [ I1 ]
  if 69 - 69: O0 / i1IIi - OoOoOO00 + ooOoO0o - oO0o
  i111II = lisp_verify_auth ( packet , o0oo0 . alg_id ,
 o0oo0 . auth_data , O0O0 )
  if 80 - 80: o0oOOo0O0Ooo % O0 * I11i . i1IIi - ooOoO0o
  I1 = "key-id {}" . format ( I1 ) if I1 == o0oo0 . key_id else "bad key-id {}" . format ( o0oo0 . key_id )
  if 93 - 93: OoooooooOO / o0oOOo0O0Ooo
  if 61 - 61: II111iiii / i1IIi . I1ii11iIi11i % iIii1I11I1II1
  lprint ( "  Authentication {} for Map-Notify-Ack, {}" . format ( "succeeded" if i111II else "failed" , I1 ) )
  if 66 - 66: iIii1I11I1II1 % OoOoOO00 + i1IIi * i11iIiiIii * OoooooooOO
  if ( i111II == False ) : return
  if 36 - 36: iII111i - OoO0O00 + I1IiiI + Ii1I . OoooooooOO
  if 75 - 75: oO0o * Oo0Ooo * O0
  if 22 - 22: ooOoO0o / OoooooooOO . II111iiii / Ii1I * OoO0O00 . i1IIi
  if 62 - 62: oO0o % Ii1I - Ii1I
  if 16 - 16: OoO0O00 - O0 - OOooOOo - I11i % OoOoOO00
 if ( o0oo0 . retransmit_timer ) : o0oo0 . retransmit_timer . cancel ( )
 if 7 - 7: I1Ii111 / OoOoOO00 . II111iiii
 II11iiI1I1I = source . print_address ( )
 i1IIiI1iII = o0oo0 . nonce_key
 if 9 - 9: I11i . I11i . OoooooooOO
 if ( lisp_map_notify_queue . has_key ( i1IIiI1iII ) ) :
  o0oo0 = lisp_map_notify_queue . pop ( i1IIiI1iII )
  if ( o0oo0 . retransmit_timer ) : o0oo0 . retransmit_timer . cancel ( )
  lprint ( "Dequeue Map-Notify from retransmit queue, key is: {}" . format ( i1IIiI1iII ) )
  if 42 - 42: iII111i / oO0o / iII111i * OoO0O00
 else :
  lprint ( "Map-Notify with nonce 0x{} queue entry not found for {}" . format ( o0oo0 . nonce_key , red ( II11iiI1I1I , False ) ) )
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
 i1o0000oOO00 = False
 if ( group . is_null ( ) == False ) :
  i1o0000oOO00 = mr . last_cached_prefix [ 1 ] . is_more_specific ( group )
  if 3 - 3: O0 / iIii1I11I1II1 % IiII + I11i
 if ( i1o0000oOO00 == False ) :
  i1o0000oOO00 = mr . last_cached_prefix [ 0 ] . is_more_specific ( eid )
  if 43 - 43: Oo0Ooo % I11i
  if 53 - 53: OoOoOO00 % OoooooooOO * o0oOOo0O0Ooo % OoooooooOO
 if ( i1o0000oOO00 ) :
  Oo0OooI11IIIiiiI = lisp_print_eid_tuple ( eid , group )
  IiII1II1I = lisp_print_eid_tuple ( mr . last_cached_prefix [ 0 ] ,
 mr . last_cached_prefix [ 1 ] )
  if 40 - 40: o0oOOo0O0Ooo - OoOoOO00 - iIii1I11I1II1
  lprint ( ( "Map-Referral prefix {} from {} is not more-specific " + "than cached prefix {}" ) . format ( green ( Oo0OooI11IIIiiiI , False ) , s ,
  # OoooooooOO + ooOoO0o * I1ii11iIi11i
 IiII1II1I ) )
  if 6 - 6: OoooooooOO % i1IIi % II111iiii + ooOoO0o / IiII + Ii1I
 return ( i1o0000oOO00 )
 if 97 - 97: ooOoO0o / I1Ii111 * I1ii11iIi11i
 if 83 - 83: Ii1I + ooOoO0o
 if 46 - 46: OoOoOO00
 if 66 - 66: iII111i - O0 . I1Ii111 * i1IIi / OoO0O00 / II111iiii
 if 35 - 35: ooOoO0o * OOooOOo / I11i % I11i / OoooooooOO . I1Ii111
 if 70 - 70: I1ii11iIi11i % I1ii11iIi11i / oO0o
 if 85 - 85: OoOoOO00 % I11i / Oo0Ooo + I11i - Oo0Ooo
def lisp_process_map_referral ( lisp_sockets , packet , source ) :
 if 20 - 20: IiII
 Oo0oo = lisp_map_referral ( )
 packet = Oo0oo . decode ( packet )
 if ( packet == None ) :
  lprint ( "Could not decode Map-Referral packet" )
  return
  if 81 - 81: Oo0Ooo / I1Ii111
 Oo0oo . print_map_referral ( )
 if 20 - 20: o0oOOo0O0Ooo + ooOoO0o % i1IIi
 i1I1iIi1IiI = source . print_address ( )
 iIiIi1i1Iiii = Oo0oo . nonce
 if 51 - 51: iII111i - ooOoO0o
 if 32 - 32: IiII - i11iIiiIii
 if 41 - 41: Ii1I % Ii1I * oO0o - I11i + iIii1I11I1II1 . ooOoO0o
 if 30 - 30: Ii1I * iII111i . II111iiii / i1IIi
 for oO in range ( Oo0oo . record_count ) :
  I111IoOo0oOOO0o = lisp_eid_record ( )
  packet = I111IoOo0oOOO0o . decode ( packet )
  if ( packet == None ) :
   lprint ( "Could not decode EID-record in Map-Referral packet" )
   return
   if 77 - 77: oO0o . IiII + I1ii11iIi11i . i1IIi
  I111IoOo0oOOO0o . print_record ( "  " , True )
  if 49 - 49: I1Ii111 . OoooooooOO / o0oOOo0O0Ooo - iII111i - iII111i - i11iIiiIii
  if 37 - 37: OOooOOo
  if 79 - 79: I1Ii111 - OoO0O00 + ooOoO0o + oO0o . i11iIiiIii + i1IIi
  if 32 - 32: IiII . ooOoO0o / OoO0O00 / iII111i . iIii1I11I1II1 % IiII
  i1IIiI1iII = str ( iIiIi1i1Iiii )
  if ( i1IIiI1iII not in lisp_ddt_map_requestQ ) :
   lprint ( ( "Map-Referral nonce 0x{} from {} not found in " + "Map-Request queue, EID-record ignored" ) . format ( lisp_hex_string ( iIiIi1i1Iiii ) , i1I1iIi1IiI ) )
   if 28 - 28: I1Ii111 + OoooooooOO + IiII . ooOoO0o . I1IiiI / oO0o
   if 66 - 66: Ii1I - I11i + Oo0Ooo . ooOoO0o
   continue
   if 89 - 89: IiII . II111iiii / OoO0O00 + I1ii11iIi11i * i11iIiiIii
  IIiIII1IIi = lisp_ddt_map_requestQ [ i1IIiI1iII ]
  if ( IIiIII1IIi == None ) :
   lprint ( ( "No Map-Request queue entry found for Map-Referral " +
 "nonce 0x{} from {}, EID-record ignored" ) . format ( lisp_hex_string ( iIiIi1i1Iiii ) , i1I1iIi1IiI ) )
   if 85 - 85: o0oOOo0O0Ooo - Oo0Ooo / I1Ii111
   continue
   if 100 - 100: OoO0O00 * iIii1I11I1II1 - IiII . i1IIi % i11iIiiIii % Oo0Ooo
   if 22 - 22: ooOoO0o - OOooOOo
   if 90 - 90: i11iIiiIii . i11iIiiIii - iIii1I11I1II1
   if 20 - 20: ooOoO0o - i11iIiiIii
   if 23 - 23: OoO0O00 + I1IiiI / I1ii11iIi11i * I1ii11iIi11i % ooOoO0o
   if 83 - 83: I1IiiI * i11iIiiIii - I1ii11iIi11i + I11i
  if ( lisp_map_referral_loop ( IIiIII1IIi , I111IoOo0oOOO0o . eid , I111IoOo0oOOO0o . group ,
 I111IoOo0oOOO0o . action , i1I1iIi1IiI ) ) :
   IIiIII1IIi . dequeue_map_request ( )
   continue
   if 33 - 33: OoO0O00 . OoooooooOO % iII111i / oO0o * Ii1I + ooOoO0o
   if 29 - 29: oO0o
  IIiIII1IIi . last_cached_prefix [ 0 ] = I111IoOo0oOOO0o . eid
  IIiIII1IIi . last_cached_prefix [ 1 ] = I111IoOo0oOOO0o . group
  if 21 - 21: i11iIiiIii . o0oOOo0O0Ooo
  if 78 - 78: Oo0Ooo
  if 77 - 77: oO0o % Oo0Ooo % O0
  if 51 - 51: IiII % IiII + OOooOOo . II111iiii / I1ii11iIi11i
  OoOoOoO0ooOOo0oO = False
  iiIiI1III111 = lisp_referral_cache_lookup ( I111IoOo0oOOO0o . eid , I111IoOo0oOOO0o . group ,
 True )
  if ( iiIiI1III111 == None ) :
   OoOoOoO0ooOOo0oO = True
   iiIiI1III111 = lisp_referral ( )
   iiIiI1III111 . eid = I111IoOo0oOOO0o . eid
   iiIiI1III111 . group = I111IoOo0oOOO0o . group
   if ( I111IoOo0oOOO0o . ddt_incomplete == False ) : iiIiI1III111 . add_cache ( )
  elif ( iiIiI1III111 . referral_source . not_set ( ) ) :
   lprint ( "Do not replace static referral entry {}" . format ( green ( iiIiI1III111 . print_eid_tuple ( ) , False ) ) )
   if 4 - 4: o0oOOo0O0Ooo % I1IiiI * o0oOOo0O0Ooo * OoOoOO00 - Ii1I
   IIiIII1IIi . dequeue_map_request ( )
   continue
   if 61 - 61: OoooooooOO - OoOoOO00 . O0 / ooOoO0o . Ii1I
   if 41 - 41: Oo0Ooo / OoOoOO00 % I1Ii111 - O0
  I11IiIi1I = I111IoOo0oOOO0o . action
  iiIiI1III111 . referral_source = source
  iiIiI1III111 . referral_type = I11IiIi1I
  iiI = I111IoOo0oOOO0o . store_ttl ( )
  iiIiI1III111 . referral_ttl = iiI
  iiIiI1III111 . expires = lisp_set_timestamp ( iiI )
  if 19 - 19: I1IiiI % I1Ii111 - O0 . iIii1I11I1II1 . I11i % O0
  if 88 - 88: ooOoO0o
  if 52 - 52: iIii1I11I1II1 % ooOoO0o * iIii1I11I1II1
  if 20 - 20: i11iIiiIii * I11i
  i11Ii = iiIiI1III111 . is_referral_negative ( )
  if ( iiIiI1III111 . referral_set . has_key ( i1I1iIi1IiI ) ) :
   iI1I111iI1I1I = iiIiI1III111 . referral_set [ i1I1iIi1IiI ]
   if 37 - 37: II111iiii
   if ( iI1I111iI1I1I . updown == False and i11Ii == False ) :
    iI1I111iI1I1I . updown = True
    lprint ( "Change up/down status for referral-node {} to up" . format ( i1I1iIi1IiI ) )
    if 94 - 94: OOooOOo % I1ii11iIi11i % O0 + iII111i
   elif ( iI1I111iI1I1I . updown == True and i11Ii == True ) :
    iI1I111iI1I1I . updown = False
    lprint ( ( "Change up/down status for referral-node {} " + "to down, received negative referral" ) . format ( i1I1iIi1IiI ) )
    if 62 - 62: iIii1I11I1II1 . OoOoOO00 / iIii1I11I1II1 + IiII
    if 31 - 31: Ii1I . OoO0O00 . Ii1I + OoO0O00 * iIii1I11I1II1 . iII111i
    if 42 - 42: O0 / oO0o % O0 . i1IIi % OOooOOo
    if 13 - 13: I1IiiI % ooOoO0o + OOooOOo
    if 91 - 91: oO0o - ooOoO0o
    if 20 - 20: i1IIi . IiII / o0oOOo0O0Ooo / I11i
    if 27 - 27: ooOoO0o . ooOoO0o - Ii1I % i11iIiiIii
    if 74 - 74: I1Ii111 - II111iiii % o0oOOo0O0Ooo
  IiIiiI = { }
  for i1IIiI1iII in iiIiI1III111 . referral_set : IiIiiI [ i1IIiI1iII ] = None
  if 19 - 19: ooOoO0o * iII111i
  if 38 - 38: ooOoO0o
  if 35 - 35: o0oOOo0O0Ooo * IiII * Oo0Ooo
  if 34 - 34: I11i - OoooooooOO % i1IIi + I1IiiI
  for oO in range ( I111IoOo0oOOO0o . rloc_count ) :
   i1iIiII = lisp_rloc_record ( )
   packet = i1iIiII . decode ( packet , None )
   if ( packet == None ) :
    lprint ( "Could not decode RLOC-record in Map-Referral packet" )
    return
    if 14 - 14: I1IiiI . o0oOOo0O0Ooo / I1Ii111
   i1iIiII . print_record ( "    " )
   if 67 - 67: OoooooooOO . oO0o * OoOoOO00 - OoooooooOO
   if 32 - 32: oO0o
   if 72 - 72: I1IiiI
   if 34 - 34: ooOoO0o % II111iiii / ooOoO0o
   OoOOoooO000 = i1iIiII . rloc . print_address ( )
   if ( iiIiI1III111 . referral_set . has_key ( OoOOoooO000 ) == False ) :
    iI1I111iI1I1I = lisp_referral_node ( )
    iI1I111iI1I1I . referral_address . copy_address ( i1iIiII . rloc )
    iiIiI1III111 . referral_set [ OoOOoooO000 ] = iI1I111iI1I1I
    if ( i1I1iIi1IiI == OoOOoooO000 and i11Ii ) : iI1I111iI1I1I . updown = False
   else :
    iI1I111iI1I1I = iiIiI1III111 . referral_set [ OoOOoooO000 ]
    if ( IiIiiI . has_key ( OoOOoooO000 ) ) : IiIiiI . pop ( OoOOoooO000 )
    if 87 - 87: Oo0Ooo
   iI1I111iI1I1I . priority = i1iIiII . priority
   iI1I111iI1I1I . weight = i1iIiII . weight
   if 7 - 7: iIii1I11I1II1
   if 85 - 85: iIii1I11I1II1 . O0
   if 43 - 43: II111iiii / OoOoOO00 + OOooOOo % Oo0Ooo * OOooOOo
   if 62 - 62: ooOoO0o * OOooOOo . I11i + Oo0Ooo - I1Ii111
   if 48 - 48: I1Ii111 * Oo0Ooo % OoO0O00 % Ii1I
  for i1IIiI1iII in IiIiiI : iiIiI1III111 . referral_set . pop ( i1IIiI1iII )
  if 8 - 8: OoO0O00 . OoO0O00
  oo0ooooO = iiIiI1III111 . print_eid_tuple ( )
  if 29 - 29: I11i + OoooooooOO % o0oOOo0O0Ooo - I1Ii111
  if ( OoOoOoO0ooOOo0oO ) :
   if ( I111IoOo0oOOO0o . ddt_incomplete ) :
    lprint ( "Suppress add {} to referral-cache" . format ( green ( oo0ooooO , False ) ) )
    if 45 - 45: II111iiii - OOooOOo / oO0o % O0 . iII111i . iII111i
   else :
    lprint ( "Add {}, referral-count {} to referral-cache" . format ( green ( oo0ooooO , False ) , I111IoOo0oOOO0o . rloc_count ) )
    if 82 - 82: iIii1I11I1II1 % Oo0Ooo * i1IIi - I1Ii111 - I1ii11iIi11i / iII111i
    if 24 - 24: IiII
  else :
   lprint ( "Replace {}, referral-count: {} in referral-cache" . format ( green ( oo0ooooO , False ) , I111IoOo0oOOO0o . rloc_count ) )
   if 95 - 95: IiII + OoOoOO00 * OOooOOo
   if 92 - 92: OoOoOO00 + ooOoO0o . iII111i
   if 59 - 59: iIii1I11I1II1 % I1Ii111 + I1ii11iIi11i . OoOoOO00 * Oo0Ooo / I1Ii111
   if 41 - 41: i1IIi / IiII
   if 73 - 73: o0oOOo0O0Ooo % ooOoO0o
   if 72 - 72: OoO0O00 * OoOoOO00 % I1IiiI - OOooOOo . Oo0Ooo
  if ( I11IiIi1I == LISP_DDT_ACTION_DELEGATION_HOLE ) :
   lisp_send_negative_map_reply ( IIiIII1IIi . lisp_sockets , iiIiI1III111 . eid ,
 iiIiI1III111 . group , IIiIII1IIi . nonce , IIiIII1IIi . itr , IIiIII1IIi . sport , 15 , None , False )
   IIiIII1IIi . dequeue_map_request ( )
   if 70 - 70: ooOoO0o . o0oOOo0O0Ooo * II111iiii - O0
   if 74 - 74: oO0o % I1IiiI / oO0o / Oo0Ooo / ooOoO0o
  if ( I11IiIi1I == LISP_DDT_ACTION_NOT_AUTH ) :
   if ( IIiIII1IIi . tried_root ) :
    lisp_send_negative_map_reply ( IIiIII1IIi . lisp_sockets , iiIiI1III111 . eid ,
 iiIiI1III111 . group , IIiIII1IIi . nonce , IIiIII1IIi . itr , IIiIII1IIi . sport , 0 , None , False )
    IIiIII1IIi . dequeue_map_request ( )
   else :
    lisp_send_ddt_map_request ( IIiIII1IIi , True )
    if 29 - 29: ooOoO0o + iIii1I11I1II1 + OoO0O00 - o0oOOo0O0Ooo
    if 74 - 74: II111iiii - II111iiii + ooOoO0o + Oo0Ooo % iIii1I11I1II1
    if 90 - 90: oO0o / o0oOOo0O0Ooo . o0oOOo0O0Ooo % OoOoOO00 / IiII
  if ( I11IiIi1I == LISP_DDT_ACTION_MS_NOT_REG ) :
   if ( iiIiI1III111 . referral_set . has_key ( i1I1iIi1IiI ) ) :
    iI1I111iI1I1I = iiIiI1III111 . referral_set [ i1I1iIi1IiI ]
    iI1I111iI1I1I . updown = False
    if 13 - 13: oO0o + IiII
   if ( len ( iiIiI1III111 . referral_set ) == 0 ) :
    IIiIII1IIi . dequeue_map_request ( )
   else :
    lisp_send_ddt_map_request ( IIiIII1IIi , False )
    if 36 - 36: oO0o - OoOoOO00 . O0 % IiII
    if 65 - 65: Oo0Ooo - i11iIiiIii * OoOoOO00 . I1Ii111 . iIii1I11I1II1
    if 48 - 48: iIii1I11I1II1 - oO0o / OoO0O00 + O0 . Ii1I + I1Ii111
  if ( I11IiIi1I in ( LISP_DDT_ACTION_NODE_REFERRAL ,
 LISP_DDT_ACTION_MS_REFERRAL ) ) :
   if ( IIiIII1IIi . eid . is_exact_match ( I111IoOo0oOOO0o . eid ) ) :
    if ( not IIiIII1IIi . tried_root ) :
     lisp_send_ddt_map_request ( IIiIII1IIi , True )
    else :
     lisp_send_negative_map_reply ( IIiIII1IIi . lisp_sockets ,
 iiIiI1III111 . eid , iiIiI1III111 . group , IIiIII1IIi . nonce , IIiIII1IIi . itr ,
 IIiIII1IIi . sport , 15 , None , False )
     IIiIII1IIi . dequeue_map_request ( )
     if 17 - 17: OoOoOO00 . Oo0Ooo - I1Ii111 / I1Ii111 + I11i % i1IIi
   else :
    lisp_send_ddt_map_request ( IIiIII1IIi , False )
    if 31 - 31: OoooooooOO . O0 / OoO0O00 . I1Ii111
    if 41 - 41: OoooooooOO + iII111i . OOooOOo
    if 73 - 73: oO0o + i1IIi + i11iIiiIii / I1ii11iIi11i
  if ( I11IiIi1I == LISP_DDT_ACTION_MS_ACK ) : IIiIII1IIi . dequeue_map_request ( )
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
 oOo000oOo = lisp_ecm ( 0 )
 packet = oOo000oOo . decode ( packet )
 if ( packet == None ) :
  lprint ( "Could not decode ECM packet" )
  return
  if 95 - 95: ooOoO0o + OoOoOO00 . II111iiii + Ii1I
  if 81 - 81: OoooooooOO / OOooOOo / Oo0Ooo
 oOo000oOo . print_ecm ( )
 if 26 - 26: iII111i
 IIiiIiIIiI1 = lisp_control_header ( )
 if ( IIiiIiIIiI1 . decode ( packet ) == None ) :
  lprint ( "Could not decode control header" )
  return
  if 93 - 93: Oo0Ooo + I1IiiI % OoOoOO00 / OOooOOo / I1ii11iIi11i
  if 6 - 6: IiII
 o00o0o = IIiiIiIIiI1 . type
 del ( IIiiIiIIiI1 )
 if 15 - 15: Ii1I + Oo0Ooo - I1ii11iIi11i / i11iIiiIii
 if ( o00o0o != LISP_MAP_REQUEST ) :
  lprint ( "Received ECM without Map-Request inside" )
  return
  if 80 - 80: i11iIiiIii + oO0o
  if 42 - 42: i11iIiiIii . Ii1I / i1IIi % OoooooooOO + Oo0Ooo % II111iiii
  if 33 - 33: II111iiii + IiII % O0 * I1Ii111 - Oo0Ooo / i1IIi
  if 87 - 87: O0 + iII111i . iIii1I11I1II1 - I11i + OOooOOo
  if 18 - 18: I1ii11iIi11i . Ii1I * iII111i . I1IiiI . O0 - OoO0O00
 ooO0o00000O0o = oOo000oOo . udp_sport
 lisp_process_map_request ( lisp_sockets , packet , source , ecm_port ,
 oOo000oOo . source , ooO0o00000O0o , oOo000oOo . ddt , - 1 )
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
 iiIi1I = ms . map_server
 if ( lisp_decent_push_configured and iiIi1I . is_multicast_address ( ) and
 ( ms . map_registers_multicast_sent == 1 or ms . map_registers_sent == 1 ) ) :
  iiIi1I = copy . deepcopy ( iiIi1I )
  iiIi1I . address = 0x7f000001
  iI = bold ( "Bootstrap" , False )
  i1iII1iii = ms . map_server . print_address_no_iid ( )
  lprint ( "{} mapping system for peer-group {}" . format ( iI , i1iII1iii ) )
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
  iIIIIIIIi11I1 = ms . ekey . zfill ( 32 )
  Ooo = "0" * 8
  Ii = chacha . ChaCha ( iIIIIIIIi11I1 , Ooo ) . encrypt ( packet [ 4 : : ] )
  packet = packet [ 0 : 4 ] + Ii
  I1i11II = bold ( "Encrypt" , False )
  lprint ( "{} Map-Register with key-id {}" . format ( I1i11II , ms . ekey_id ) )
  if 19 - 19: OoooooooOO
  if 31 - 31: I11i . OoOoOO00 - O0 * iII111i % I1Ii111 - II111iiii
 iII = ""
 if ( lisp_decent_pull_xtr_configured ( ) ) :
  iII = ", decent-index {}" . format ( bold ( ms . dns_name , False ) )
  if 37 - 37: i11iIiiIii - I11i
  if 24 - 24: I1IiiI . I1IiiI % ooOoO0o
 lprint ( "Send Map-Register to map-server {}{}{}" . format ( iiIi1I . print_address ( ) , ", ms-name '{}'" . format ( ms . ms_name ) , iII ) )
 if 32 - 32: OOooOOo / i1IIi / OOooOOo
 lisp_send ( lisp_sockets , iiIi1I , LISP_CTRL_PORT , packet )
 return
 if 97 - 97: ooOoO0o * Oo0Ooo * OoooooooOO * I1IiiI
 if 45 - 45: Oo0Ooo
 if 27 - 27: oO0o / IiII - iIii1I11I1II1 / o0oOOo0O0Ooo % OOooOOo * iIii1I11I1II1
 if 40 - 40: oO0o - II111iiii * OOooOOo % OoooooooOO
 if 52 - 52: OOooOOo + OoO0O00
 if 96 - 96: OOooOOo % O0 - Oo0Ooo % oO0o / I1IiiI . i1IIi
 if 42 - 42: i1IIi
 if 52 - 52: OoO0O00 % iII111i % O0
def lisp_send_ipc_to_core ( lisp_socket , packet , dest , port ) :
 IIi1IiIii = lisp_socket . getsockname ( )
 dest = dest . print_address_no_iid ( )
 if 11 - 11: i1IIi / i11iIiiIii + Ii1I % Oo0Ooo % O0
 lprint ( "Send IPC {} bytes to {} {}, control-packet: {}" . format ( len ( packet ) , dest , port , lisp_format_packet ( packet ) ) )
 if 50 - 50: oO0o . I1Ii111
 if 38 - 38: iIii1I11I1II1 . Ii1I
 packet = lisp_control_packet_ipc ( packet , IIi1IiIii , dest , port )
 lisp_ipc ( packet , lisp_socket , "lisp-core-pkt" )
 return
 if 82 - 82: OOooOOo * Ii1I + I1ii11iIi11i . OoO0O00
 if 15 - 15: O0
 if 44 - 44: Ii1I . Oo0Ooo . I1Ii111 + oO0o
 if 32 - 32: OOooOOo - II111iiii + IiII * iIii1I11I1II1 - Oo0Ooo
 if 25 - 25: ooOoO0o
 if 33 - 33: Oo0Ooo
 if 11 - 11: I11i
 if 55 - 55: i11iIiiIii * OoOoOO00 - OoOoOO00 * OoO0O00 / iII111i
def lisp_send_map_reply ( lisp_sockets , packet , dest , port ) :
 lprint ( "Send Map-Reply to {}" . format ( dest . print_address_no_iid ( ) ) )
 lisp_send_ipc_to_core ( lisp_sockets [ 2 ] , packet , dest , port )
 return
 if 64 - 64: iIii1I11I1II1 . Ii1I * Oo0Ooo - OoO0O00
 if 74 - 74: I1IiiI / o0oOOo0O0Ooo
 if 53 - 53: iIii1I11I1II1 * oO0o
 if 43 - 43: IiII * Oo0Ooo / OOooOOo % oO0o
 if 11 - 11: OoOoOO00 * Oo0Ooo / I11i * OOooOOo
 if 15 - 15: ooOoO0o - OOooOOo / OoooooooOO
 if 41 - 41: OoOoOO00 . iII111i . i1IIi + oO0o
 if 60 - 60: oO0o * I1Ii111
def lisp_send_map_referral ( lisp_sockets , packet , dest , port ) :
 lprint ( "Send Map-Referral to {}" . format ( dest . print_address ( ) ) )
 lisp_send_ipc_to_core ( lisp_sockets [ 2 ] , packet , dest , port )
 return
 if 81 - 81: oO0o - OOooOOo - oO0o
 if 54 - 54: oO0o % I11i
 if 71 - 71: oO0o / I1ii11iIi11i . Ii1I % II111iiii
 if 22 - 22: iIii1I11I1II1 - OoooooooOO
 if 8 - 8: ooOoO0o % i11iIiiIii
 if 41 - 41: I1Ii111 . ooOoO0o - i11iIiiIii + Ii1I . OOooOOo . OoOoOO00
 if 70 - 70: i1IIi % OoOoOO00 / iII111i + i11iIiiIii % ooOoO0o + IiII
 if 58 - 58: OOooOOo / i11iIiiIii . Oo0Ooo % iII111i
def lisp_send_map_notify ( lisp_sockets , packet , dest , port ) :
 lprint ( "Send Map-Notify to xTR {}" . format ( dest . print_address ( ) ) )
 lisp_send_ipc_to_core ( lisp_sockets [ 2 ] , packet , dest , port )
 return
 if 92 - 92: OoOoOO00 / ooOoO0o % iII111i / iIii1I11I1II1
 if 73 - 73: O0 % i11iIiiIii
 if 16 - 16: O0
 if 15 - 15: i1IIi % i11iIiiIii
 if 18 - 18: Ii1I . OoO0O00 . iII111i * oO0o + O0
 if 35 - 35: OoOoOO00 . oO0o / II111iiii
 if 97 - 97: Ii1I + I1Ii111 / II111iiii
def lisp_send_ecm ( lisp_sockets , packet , inner_source , inner_sport , inner_dest ,
 outer_dest , to_etr = False , to_ms = False , ddt = False ) :
 if 14 - 14: iII111i / IiII / oO0o
 if ( inner_source == None or inner_source . is_null ( ) ) :
  inner_source = inner_dest
  if 55 - 55: OoO0O00 % O0
  if 92 - 92: OoooooooOO / O0
  if 14 - 14: i11iIiiIii
  if 43 - 43: OOooOOo
  if 79 - 79: iII111i % Oo0Ooo . i1IIi % ooOoO0o
  if 93 - 93: OoOoOO00
 if ( lisp_nat_traversal ) :
  o0OO0OO000OO = lisp_get_any_translated_port ( )
  if ( o0OO0OO000OO != None ) : inner_sport = o0OO0OO000OO
  if 49 - 49: i1IIi * OOooOOo % I11i * Ii1I . I1Ii111 * iIii1I11I1II1
 oOo000oOo = lisp_ecm ( inner_sport )
 if 72 - 72: ooOoO0o
 oOo000oOo . to_etr = to_etr if lisp_is_running ( "lisp-etr" ) else False
 oOo000oOo . to_ms = to_ms if lisp_is_running ( "lisp-ms" ) else False
 oOo000oOo . ddt = ddt
 OOoiiI = oOo000oOo . encode ( packet , inner_source , inner_dest )
 if ( OOoiiI == None ) :
  lprint ( "Could not encode ECM message" )
  return
  if 38 - 38: iIii1I11I1II1 - iII111i . iII111i . OoooooooOO * I1Ii111 * I1ii11iIi11i
 oOo000oOo . print_ecm ( )
 if 89 - 89: I1Ii111 % iIii1I11I1II1 % Ii1I * IiII + Oo0Ooo / I1IiiI
 packet = OOoiiI + packet
 if 66 - 66: OOooOOo - I1Ii111 + OoooooooOO + I1ii11iIi11i + Oo0Ooo - I1IiiI
 OoOOoooO000 = outer_dest . print_address_no_iid ( )
 lprint ( "Send Encapsulated-Control-Message to {}" . format ( OoOOoooO000 ) )
 iiIi1I = lisp_convert_4to6 ( OoOOoooO000 )
 lisp_send ( lisp_sockets , iiIi1I , LISP_CTRL_PORT , packet )
 return
 if 2 - 2: o0oOOo0O0Ooo
 if 27 - 27: O0 . oO0o - i11iIiiIii / i11iIiiIii
 if 65 - 65: Oo0Ooo - o0oOOo0O0Ooo + i1IIi + I1IiiI
 if 58 - 58: iII111i * IiII . i1IIi + I1Ii111
 if 19 - 19: iII111i * II111iiii * OOooOOo
 if 86 - 86: Oo0Ooo - I11i - I1ii11iIi11i / I11i - I11i
 if 3 - 3: I1Ii111
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
if 99 - 99: I1Ii111 * OOooOOo % I1IiiI / OoOoOO00 * iIii1I11I1II1
LISP_RLOC_UNKNOWN_STATE = 0
LISP_RLOC_UP_STATE = 1
LISP_RLOC_DOWN_STATE = 2
LISP_RLOC_UNREACH_STATE = 3
LISP_RLOC_NO_ECHOED_NONCE_STATE = 4
LISP_RLOC_ADMIN_DOWN_STATE = 5
if 45 - 45: iIii1I11I1II1
LISP_AUTH_NONE = 0
LISP_AUTH_MD5 = 1
LISP_AUTH_SHA1 = 2
LISP_AUTH_SHA2 = 3
if 73 - 73: OoOoOO00 * OOooOOo * I11i / I1IiiI + oO0o
if 14 - 14: oO0o % o0oOOo0O0Ooo * i11iIiiIii - OoooooooOO * OOooOOo
if 11 - 11: oO0o
if 14 - 14: OoooooooOO . I1ii11iIi11i % I1IiiI / I1IiiI % Oo0Ooo
if 97 - 97: i1IIi
if 6 - 6: Ii1I
if 43 - 43: i1IIi - Ii1I % iIii1I11I1II1 . OoO0O00 + oO0o - iIii1I11I1II1
LISP_IPV4_HOST_MASK_LEN = 32
LISP_IPV6_HOST_MASK_LEN = 128
LISP_MAC_HOST_MASK_LEN = 48
LISP_E164_HOST_MASK_LEN = 60
if 17 - 17: IiII . i1IIi
if 37 - 37: OoooooooOO + Oo0Ooo - Oo0Ooo + I1ii11iIi11i . I1Ii111 / I1IiiI
if 60 - 60: I1IiiI % Ii1I / I1Ii111 + Ii1I
if 43 - 43: I1ii11iIi11i + I11i
if 83 - 83: II111iiii + o0oOOo0O0Ooo - I1Ii111
if 100 - 100: IiII - OoOoOO00 / I11i
def byte_swap_64 ( address ) :
 I1Iii1I = ( ( address & 0x00000000000000ff ) << 56 ) | ( ( address & 0x000000000000ff00 ) << 40 ) | ( ( address & 0x0000000000ff0000 ) << 24 ) | ( ( address & 0x00000000ff000000 ) << 8 ) | ( ( address & 0x000000ff00000000 ) >> 8 ) | ( ( address & 0x0000ff0000000000 ) >> 24 ) | ( ( address & 0x00ff000000000000 ) >> 40 ) | ( ( address & 0xff00000000000000 ) >> 56 )
 if 33 - 33: I1Ii111 * OoOoOO00 . I1ii11iIi11i % I1Ii111
 if 87 - 87: Oo0Ooo
 if 65 - 65: ooOoO0o . I1IiiI
 if 51 - 51: IiII
 if 43 - 43: oO0o - I11i . i11iIiiIii
 if 78 - 78: i11iIiiIii + Oo0Ooo * Ii1I - o0oOOo0O0Ooo % i11iIiiIii
 if 30 - 30: I1IiiI % oO0o * OoooooooOO
 if 64 - 64: I1IiiI
 return ( I1Iii1I )
 if 11 - 11: I1ii11iIi11i % iII111i / II111iiii % ooOoO0o % IiII
 if 14 - 14: ooOoO0o / IiII . o0oOOo0O0Ooo
 if 27 - 27: I1IiiI - OOooOOo . II111iiii * I1ii11iIi11i % ooOoO0o / I1IiiI
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
class lisp_cache_entries ( ) :
 def __init__ ( self ) :
  self . entries = { }
  self . entries_sorted = [ ]
  if 41 - 41: II111iiii + Oo0Ooo / iII111i . IiII / iII111i / I1IiiI
  if 78 - 78: o0oOOo0O0Ooo % OoOoOO00 . O0
  if 41 - 41: iIii1I11I1II1 . OOooOOo - Oo0Ooo % OOooOOo
class lisp_cache ( ) :
 def __init__ ( self ) :
  self . cache = { }
  self . cache_sorted = [ ]
  self . cache_count = 0
  if 90 - 90: i11iIiiIii + OoooooooOO - i11iIiiIii + OoooooooOO
  if 23 - 23: i11iIiiIii - IiII - I1ii11iIi11i + I1ii11iIi11i % I1IiiI
 def cache_size ( self ) :
  return ( self . cache_count )
  if 79 - 79: II111iiii / OoooooooOO
  if 35 - 35: i1IIi + IiII + II111iiii % OOooOOo
 def build_key ( self , prefix ) :
  if ( prefix . afi == LISP_AFI_ULTIMATE_ROOT ) :
   ii11i1 = 0
  elif ( prefix . afi == LISP_AFI_IID_RANGE ) :
   ii11i1 = prefix . mask_len
  else :
   ii11i1 = prefix . mask_len + 48
   if 25 - 25: I11i + i11iIiiIii + O0 - Ii1I
   if 69 - 69: I11i . OoOoOO00 / OOooOOo / i1IIi . II111iiii
  IIiI1i = lisp_hex_string ( prefix . instance_id ) . zfill ( 8 )
  ooOooOooOOO = lisp_hex_string ( prefix . afi ) . zfill ( 4 )
  if 17 - 17: I1Ii111
  if ( prefix . afi > 0 ) :
   if ( prefix . is_binary ( ) ) :
    I1I1 = prefix . addr_length ( ) * 2
    I1Iii1I = lisp_hex_string ( prefix . address ) . zfill ( I1I1 )
   else :
    I1Iii1I = prefix . address
    if 2 - 2: O0 % OoOoOO00 + oO0o
  elif ( prefix . afi == LISP_AFI_GEO_COORD ) :
   ooOooOooOOO = "8003"
   I1Iii1I = prefix . address . print_geo ( )
  else :
   ooOooOooOOO = ""
   I1Iii1I = ""
   if 24 - 24: iII111i + iII111i - OoooooooOO % OoooooooOO * O0
   if 51 - 51: IiII
  i1IIiI1iII = IIiI1i + ooOooOooOOO + I1Iii1I
  return ( [ ii11i1 , i1IIiI1iII ] )
  if 31 - 31: I11i - iIii1I11I1II1 * Ii1I + Ii1I
  if 10 - 10: OoOoOO00 - i11iIiiIii % iIii1I11I1II1 / ooOoO0o * i11iIiiIii - Ii1I
 def add_cache ( self , prefix , entry ) :
  if ( prefix . is_binary ( ) ) : prefix . zero_host_bits ( )
  ii11i1 , i1IIiI1iII = self . build_key ( prefix )
  if ( self . cache . has_key ( ii11i1 ) == False ) :
   self . cache [ ii11i1 ] = lisp_cache_entries ( )
   self . cache [ ii11i1 ] . entries = { }
   self . cache [ ii11i1 ] . entries_sorted = [ ]
   self . cache_sorted = sorted ( self . cache )
   if 64 - 64: II111iiii . i11iIiiIii . iII111i . OOooOOo
  if ( self . cache [ ii11i1 ] . entries . has_key ( i1IIiI1iII ) == False ) :
   self . cache_count += 1
   if 95 - 95: O0 - OoOoOO00
  self . cache [ ii11i1 ] . entries [ i1IIiI1iII ] = entry
  self . cache [ ii11i1 ] . entries_sorted = sorted ( self . cache [ ii11i1 ] . entries )
  if 68 - 68: ooOoO0o . I1Ii111
  if 84 - 84: OoooooooOO + oO0o % i1IIi + o0oOOo0O0Ooo * i1IIi
 def lookup_cache ( self , prefix , exact ) :
  OOi1II1IiIIIIii , i1IIiI1iII = self . build_key ( prefix )
  if ( exact ) :
   if ( self . cache . has_key ( OOi1II1IiIIIIii ) == False ) : return ( None )
   if ( self . cache [ OOi1II1IiIIIIii ] . entries . has_key ( i1IIiI1iII ) == False ) : return ( None )
   return ( self . cache [ OOi1II1IiIIIIii ] . entries [ i1IIiI1iII ] )
   if 11 - 11: i11iIiiIii
   if 84 - 84: I11i + OOooOOo - OoooooooOO / I1ii11iIi11i
  oOO0OOOOoo = None
  for ii11i1 in self . cache_sorted :
   if ( OOi1II1IiIIIIii < ii11i1 ) : return ( oOO0OOOOoo )
   for IiIiiiII111i in self . cache [ ii11i1 ] . entries_sorted :
    O0Iii1I1IIIi1iI = self . cache [ ii11i1 ] . entries
    if ( IiIiiiII111i in O0Iii1I1IIIi1iI ) :
     o0Iiii = O0Iii1I1IIIi1iI [ IiIiiiII111i ]
     if ( o0Iiii == None ) : continue
     if ( prefix . is_more_specific ( o0Iiii . eid ) ) : oOO0OOOOoo = o0Iiii
     if 79 - 79: iIii1I11I1II1 . iII111i
     if 42 - 42: I1Ii111 - I1IiiI % I1IiiI * I1IiiI
     if 70 - 70: O0 / I1IiiI / I1IiiI
  return ( oOO0OOOOoo )
  if 71 - 71: OOooOOo - Oo0Ooo + IiII * oO0o
  if 90 - 90: OoOoOO00 * I1ii11iIi11i
 def delete_cache ( self , prefix ) :
  ii11i1 , i1IIiI1iII = self . build_key ( prefix )
  if ( self . cache . has_key ( ii11i1 ) == False ) : return
  if ( self . cache [ ii11i1 ] . entries . has_key ( i1IIiI1iII ) == False ) : return
  self . cache [ ii11i1 ] . entries . pop ( i1IIiI1iII )
  self . cache [ ii11i1 ] . entries_sorted . remove ( i1IIiI1iII )
  self . cache_count -= 1
  if 16 - 16: i1IIi - OoO0O00
  if 61 - 61: o0oOOo0O0Ooo + OoOoOO00 - ooOoO0o + ooOoO0o % ooOoO0o % II111iiii
 def walk_cache ( self , function , parms ) :
  for ii11i1 in self . cache_sorted :
   for i1IIiI1iII in self . cache [ ii11i1 ] . entries_sorted :
    o0Iiii = self . cache [ ii11i1 ] . entries [ i1IIiI1iII ]
    ii1 , parms = function ( o0Iiii , parms )
    if ( ii1 == False ) : return ( parms )
    if 80 - 80: OOooOOo * O0 / iIii1I11I1II1 / IiII / OoOoOO00
    if 15 - 15: I1ii11iIi11i * iII111i + i11iIiiIii
  return ( parms )
  if 68 - 68: i1IIi / oO0o * I1ii11iIi11i - OoOoOO00 + Oo0Ooo / O0
  if 1 - 1: ooOoO0o - Oo0Ooo + I1Ii111
 def print_cache ( self ) :
  lprint ( "Printing contents of {}: " . format ( self ) )
  if ( self . cache_size ( ) == 0 ) :
   lprint ( "  Cache is empty" )
   return
   if 90 - 90: I1Ii111 * O0 . iII111i - Oo0Ooo % iIii1I11I1II1
  for ii11i1 in self . cache_sorted :
   for i1IIiI1iII in self . cache [ ii11i1 ] . entries_sorted :
    o0Iiii = self . cache [ ii11i1 ] . entries [ i1IIiI1iII ]
    lprint ( "  Mask-length: {}, key: {}, entry: {}" . format ( ii11i1 , i1IIiI1iII ,
 o0Iiii ) )
    if 7 - 7: I1ii11iIi11i % o0oOOo0O0Ooo % O0 % iIii1I11I1II1
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
  oo0ooooO = source . print_sg ( dest ) if o0OoOO00O0O0 else dest . print_address ( )
  oo0ooooO = green ( oo0ooooO , False )
  dprint ( "Lookup for EID {} not found in map-cache" . format ( oo0ooooO ) )
  return ( None )
  if 81 - 81: I11i % Oo0Ooo / iII111i
  if 44 - 44: Oo0Ooo
  if 90 - 90: Oo0Ooo . ooOoO0o / IiII * I1Ii111 . ooOoO0o + II111iiii
  if 43 - 43: iIii1I11I1II1 % OOooOOo + OoOoOO00 + I1ii11iIi11i - Oo0Ooo / Ii1I
  if 94 - 94: Ii1I / Oo0Ooo % II111iiii % Oo0Ooo * oO0o
 if ( o0OoOO00O0O0 == False ) :
  O00oooO0 = green ( Iii1 . eid . print_prefix ( ) , False )
  dprint ( "Lookup for EID {} found map-cache entry {}" . format ( green ( dest . print_address ( ) , False ) , O00oooO0 ) )
  if 54 - 54: O0 / ooOoO0o * I1Ii111
  return ( Iii1 )
  if 5 - 5: Ii1I / OoOoOO00 - O0 * OoO0O00
  if 13 - 13: IiII + Oo0Ooo - I1Ii111
  if 10 - 10: OOooOOo % OoooooooOO / I1IiiI . II111iiii % iII111i
  if 47 - 47: o0oOOo0O0Ooo . i11iIiiIii * i1IIi % I11i - ooOoO0o * oO0o
  if 95 - 95: oO0o / Ii1I + OoO0O00
 Iii1 = Iii1 . lookup_source_cache ( source , False )
 if ( Iii1 == None ) :
  oo0ooooO = source . print_sg ( dest )
  dprint ( "Lookup for EID {} not found in map-cache" . format ( oo0ooooO ) )
  return ( None )
  if 57 - 57: iIii1I11I1II1 + I1Ii111 % oO0o - Ii1I . I1IiiI
  if 39 - 39: OoO0O00 + II111iiii
  if 98 - 98: O0 - I1Ii111 % oO0o - iII111i + Ii1I * i1IIi
  if 76 - 76: o0oOOo0O0Ooo
  if 55 - 55: OOooOOo + I1ii11iIi11i * Oo0Ooo
 O00oooO0 = green ( Iii1 . print_eid_tuple ( ) , False )
 dprint ( "Lookup for EID {} found map-cache entry {}" . format ( green ( source . print_sg ( dest ) , False ) , O00oooO0 ) )
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
  OOO0OoOooO0 = lisp_referral_cache . lookup_cache ( eid , exact )
  return ( OOO0OoOooO0 )
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
 OOO0OoOooO0 = lisp_referral_cache . lookup_cache ( group , exact )
 if ( OOO0OoOooO0 == None ) : return ( None )
 if 45 - 45: IiII
 Ii1Oooo0 = OOO0OoOooO0 . lookup_source_cache ( eid , exact )
 if ( Ii1Oooo0 ) : return ( Ii1Oooo0 )
 if 91 - 91: o0oOOo0O0Ooo
 if ( exact ) : OOO0OoOooO0 = None
 return ( OOO0OoOooO0 )
 if 97 - 97: I1IiiI
 if 80 - 80: OOooOOo . oO0o * i11iIiiIii * IiII
 if 30 - 30: iIii1I11I1II1 - ooOoO0o / iIii1I11I1II1 / I1IiiI + OoOoOO00 - iIii1I11I1II1
 if 69 - 69: i11iIiiIii . O0
 if 21 - 21: i1IIi . OoO0O00 % I11i + II111iiii % o0oOOo0O0Ooo
 if 17 - 17: i11iIiiIii + oO0o * iII111i . II111iiii
 if 44 - 44: I1ii11iIi11i
def lisp_ddt_cache_lookup ( eid , group , exact ) :
 if ( group . is_null ( ) ) :
  OOOoooooo0oO = lisp_ddt_cache . lookup_cache ( eid , exact )
  return ( OOOoooooo0oO )
  if 39 - 39: iII111i + Oo0Ooo / oO0o
  if 95 - 95: I1Ii111 * oO0o / ooOoO0o . Ii1I . OoOoOO00
  if 99 - 99: I1IiiI * II111iiii
  if 84 - 84: II111iiii - I1IiiI
  if 41 - 41: iIii1I11I1II1 % I1Ii111 % OoOoOO00
 if ( eid . is_null ( ) ) : return ( None )
 if 35 - 35: I11i + i1IIi
 if 85 - 85: Ii1I * Ii1I . OoOoOO00 / Oo0Ooo
 if 97 - 97: oO0o % iIii1I11I1II1
 if 87 - 87: II111iiii % I1IiiI + oO0o - I11i / I11i
 if 16 - 16: I1IiiI
 if 39 - 39: ooOoO0o * II111iiii
 OOOoooooo0oO = lisp_ddt_cache . lookup_cache ( group , exact )
 if ( OOOoooooo0oO == None ) : return ( None )
 if 90 - 90: OoooooooOO * ooOoO0o
 iiiII111I11 = OOOoooooo0oO . lookup_source_cache ( eid , exact )
 if ( iiiII111I11 ) : return ( iiiII111I11 )
 if 82 - 82: I1IiiI % iIii1I11I1II1 * Ii1I . OOooOOo / o0oOOo0O0Ooo
 if ( exact ) : OOOoooooo0oO = None
 return ( OOOoooooo0oO )
 if 12 - 12: oO0o - O0
 if 62 - 62: OoOoOO00 % I1Ii111 . iIii1I11I1II1 * I11i . oO0o - iII111i
 if 22 - 22: OoooooooOO - Oo0Ooo . OoOoOO00
 if 73 - 73: Ii1I . IiII + OoO0O00
 if 64 - 64: IiII
 if 83 - 83: iIii1I11I1II1 % Oo0Ooo * I1Ii111 . I1ii11iIi11i
 if 10 - 10: I1ii11iIi11i
def lisp_site_eid_lookup ( eid , group , exact ) :
 if 27 - 27: OoOoOO00 . i1IIi
 if ( group . is_null ( ) ) :
  IIII = lisp_sites_by_eid . lookup_cache ( eid , exact )
  return ( IIII )
  if 76 - 76: I1ii11iIi11i + oO0o . I1ii11iIi11i - o0oOOo0O0Ooo * Oo0Ooo
  if 20 - 20: Oo0Ooo
  if 45 - 45: iIii1I11I1II1 % O0 / I1IiiI . o0oOOo0O0Ooo * IiII
  if 87 - 87: II111iiii / OoooooooOO * II111iiii % i11iIiiIii - ooOoO0o + II111iiii
  if 39 - 39: I1Ii111
 if ( eid . is_null ( ) ) : return ( None )
 if 51 - 51: o0oOOo0O0Ooo * I11i
 if 42 - 42: OOooOOo % I11i
 if 84 - 84: Oo0Ooo * OoOoOO00 / Ii1I / IiII / o0oOOo0O0Ooo . I1ii11iIi11i
 if 81 - 81: I1IiiI
 if 82 - 82: I1Ii111 - OoooooooOO - Ii1I
 if 34 - 34: OOooOOo . iIii1I11I1II1 / I1IiiI . Oo0Ooo - iIii1I11I1II1
 IIII = lisp_sites_by_eid . lookup_cache ( group , exact )
 if ( IIII == None ) : return ( None )
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
 if 64 - 64: i11iIiiIii / iII111i + i11iIiiIii . I11i
 if 66 - 66: i1IIi
 if 98 - 98: Oo0Ooo / iIii1I11I1II1
 I1IIiiII = IIII . lookup_source_cache ( eid , exact )
 if ( I1IIiiII ) : return ( I1IIiiII )
 if 33 - 33: O0 - iII111i
 if ( exact ) :
  IIII = None
 else :
  iiiIIIII1iIi = IIII . parent_for_more_specifics
  if ( iiiIIIII1iIi and iiiIIIII1iIi . accept_more_specifics ) :
   if ( group . is_more_specific ( iiiIIIII1iIi . group ) ) : IIII = iiiIIIII1iIi
   if 40 - 40: iII111i * I11i
   if 25 - 25: O0 * o0oOOo0O0Ooo % ooOoO0o % I1IiiI
 return ( IIII )
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
 if 34 - 34: i11iIiiIii / OoOoOO00
 if 100 - 100: o0oOOo0O0Ooo - I1IiiI / I11i
 if 43 - 43: o0oOOo0O0Ooo % iIii1I11I1II1
class lisp_address ( ) :
 def __init__ ( self , afi , addr_str , mask_len , iid ) :
  self . afi = afi
  self . mask_len = mask_len
  self . instance_id = iid
  self . iid_list = [ ]
  self . address = 0
  if ( addr_str != "" ) : self . store_address ( addr_str )
  if 85 - 85: oO0o + OoooooooOO - IiII % o0oOOo0O0Ooo * ooOoO0o * II111iiii
  if 4 - 4: Ii1I . i1IIi + Oo0Ooo % I11i . OoO0O00
 def copy_address ( self , addr ) :
  if ( addr == None ) : return
  self . afi = addr . afi
  self . address = addr . address
  self . mask_len = addr . mask_len
  self . instance_id = addr . instance_id
  self . iid_list = addr . iid_list
  if 70 - 70: OOooOOo * OoOoOO00 / OoOoOO00 / OoOoOO00
  if 23 - 23: I1IiiI
 def make_default_route ( self , addr ) :
  self . afi = addr . afi
  self . instance_id = addr . instance_id
  self . mask_len = 0
  self . address = 0
  if 24 - 24: I1Ii111 * i1IIi % O0 * Ii1I + iII111i
  if 14 - 14: oO0o * iII111i + Ii1I + Ii1I * IiII
 def make_default_multicast_route ( self , addr ) :
  self . afi = addr . afi
  self . instance_id = addr . instance_id
  if ( self . afi == LISP_AFI_IPV4 ) :
   self . address = 0xe0000000
   self . mask_len = 4
   if 82 - 82: IiII * ooOoO0o / OOooOOo + OoOoOO00
  if ( self . afi == LISP_AFI_IPV6 ) :
   self . address = 0xff << 120
   self . mask_len = 8
   if 32 - 32: IiII
  if ( self . afi == LISP_AFI_MAC ) :
   self . address = 0xffffffffffff
   self . mask_len = 48
   if 90 - 90: I1ii11iIi11i / I11i * o0oOOo0O0Ooo % O0 * i11iIiiIii
   if 68 - 68: I11i . Ii1I + I11i / IiII . I11i / iIii1I11I1II1
   if 96 - 96: O0
 def not_set ( self ) :
  return ( self . afi == LISP_AFI_NONE )
  if 2 - 2: OoO0O00 / iII111i + o0oOOo0O0Ooo
  if 27 - 27: I11i - OoOoOO00 - ooOoO0o - I1IiiI
 def is_private_address ( self ) :
  if ( self . is_ipv4 ( ) == False ) : return ( False )
  I1Iii1I = self . address
  if ( ( ( I1Iii1I & 0xff000000 ) >> 24 ) == 10 ) : return ( True )
  if ( ( ( I1Iii1I & 0xff000000 ) >> 24 ) == 172 ) :
   O0O0Oo0 = ( I1Iii1I & 0x00ff0000 ) >> 16
   if ( O0O0Oo0 >= 16 and O0O0Oo0 <= 31 ) : return ( True )
   if 9 - 9: II111iiii - IiII . Oo0Ooo . I1Ii111 % oO0o % I1ii11iIi11i
  if ( ( ( I1Iii1I & 0xffff0000 ) >> 16 ) == 0xc0a8 ) : return ( True )
  return ( False )
  if 36 - 36: IiII
  if 97 - 97: i1IIi % OoOoOO00 . Oo0Ooo - OoO0O00 - ooOoO0o
 def is_multicast_address ( self ) :
  if ( self . is_ipv4 ( ) ) : return ( self . is_ipv4_multicast ( ) )
  if ( self . is_ipv6 ( ) ) : return ( self . is_ipv6_multicast ( ) )
  if ( self . is_mac ( ) ) : return ( self . is_mac_multicast ( ) )
  return ( False )
  if 99 - 99: i11iIiiIii / I1Ii111 / I1IiiI * oO0o
  if 100 - 100: II111iiii * Ii1I . OoO0O00 . iII111i + i1IIi * I1IiiI
 def host_mask_len ( self ) :
  if ( self . afi == LISP_AFI_IPV4 ) : return ( LISP_IPV4_HOST_MASK_LEN )
  if ( self . afi == LISP_AFI_IPV6 ) : return ( LISP_IPV6_HOST_MASK_LEN )
  if ( self . afi == LISP_AFI_MAC ) : return ( LISP_MAC_HOST_MASK_LEN )
  if ( self . afi == LISP_AFI_E164 ) : return ( LISP_E164_HOST_MASK_LEN )
  if ( self . afi == LISP_AFI_NAME ) : return ( len ( self . address ) * 8 )
  if ( self . afi == LISP_AFI_GEO_COORD ) :
   return ( len ( self . address . print_geo ( ) ) * 8 )
   if 84 - 84: OoO0O00 + i1IIi
  return ( 0 )
  if 99 - 99: OOooOOo + o0oOOo0O0Ooo * I1Ii111 % OoooooooOO % I11i
  if 48 - 48: o0oOOo0O0Ooo / OoO0O00
 def is_iana_eid ( self ) :
  if ( self . is_ipv6 ( ) == False ) : return ( False )
  I1Iii1I = self . address >> 96
  return ( I1Iii1I == 0x20010005 )
  if 45 - 45: OOooOOo
  if 57 - 57: iIii1I11I1II1 + IiII - I1IiiI
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
   if 64 - 64: II111iiii . IiII / I1IiiI
  return ( 0 )
  if 20 - 20: OoooooooOO - I1ii11iIi11i * I1ii11iIi11i * I1ii11iIi11i
  if 87 - 87: OoooooooOO * ooOoO0o
 def afi_to_version ( self ) :
  if ( self . afi == LISP_AFI_IPV4 ) : return ( 4 )
  if ( self . afi == LISP_AFI_IPV6 ) : return ( 6 )
  return ( 0 )
  if 6 - 6: I1Ii111 / ooOoO0o / OoooooooOO . iIii1I11I1II1
  if 68 - 68: OoO0O00
 def packet_format ( self ) :
  if 26 - 26: I11i % i1IIi / iIii1I11I1II1 % IiII . iII111i + I1ii11iIi11i
  if 49 - 49: O0 . IiII + I1Ii111 - I11i % II111iiii
  if 15 - 15: O0 - OoOoOO00 % II111iiii + O0 % O0 + OoOoOO00
  if 34 - 34: I1Ii111
  if 69 - 69: iIii1I11I1II1 . OOooOOo % I11i
  if ( self . afi == LISP_AFI_IPV4 ) : return ( "I" )
  if ( self . afi == LISP_AFI_IPV6 ) : return ( "QQ" )
  if ( self . afi == LISP_AFI_MAC ) : return ( "HHH" )
  if ( self . afi == LISP_AFI_E164 ) : return ( "II" )
  if ( self . afi == LISP_AFI_LCAF ) : return ( "I" )
  return ( "" )
  if 28 - 28: I1Ii111 . ooOoO0o % I1IiiI
  if 62 - 62: II111iiii + ooOoO0o + I1IiiI
 def pack_address ( self ) :
  oOO0OOOoO0ooo = self . packet_format ( )
  iI1IIII1ii1 = ""
  if ( self . is_ipv4 ( ) ) :
   iI1IIII1ii1 = struct . pack ( oOO0OOOoO0ooo , socket . htonl ( self . address ) )
  elif ( self . is_ipv6 ( ) ) :
   I1I11Iiii111 = byte_swap_64 ( self . address >> 64 )
   iI1 = byte_swap_64 ( self . address & 0xffffffffffffffff )
   iI1IIII1ii1 = struct . pack ( oOO0OOOoO0ooo , I1I11Iiii111 , iI1 )
  elif ( self . is_mac ( ) ) :
   I1Iii1I = self . address
   I1I11Iiii111 = ( I1Iii1I >> 32 ) & 0xffff
   iI1 = ( I1Iii1I >> 16 ) & 0xffff
   OOo00OO = I1Iii1I & 0xffff
   iI1IIII1ii1 = struct . pack ( oOO0OOOoO0ooo , I1I11Iiii111 , iI1 , OOo00OO )
  elif ( self . is_e164 ( ) ) :
   I1Iii1I = self . address
   I1I11Iiii111 = ( I1Iii1I >> 32 ) & 0xffffffff
   iI1 = ( I1Iii1I & 0xffffffff )
   iI1IIII1ii1 = struct . pack ( oOO0OOOoO0ooo , I1I11Iiii111 , iI1 )
  elif ( self . is_dist_name ( ) ) :
   iI1IIII1ii1 += self . address + "\0"
   if 76 - 76: ooOoO0o % O0 . I1ii11iIi11i
  return ( iI1IIII1ii1 )
  if 97 - 97: oO0o - Oo0Ooo . i11iIiiIii % ooOoO0o * i11iIiiIii - OoooooooOO
  if 44 - 44: I11i % OoooooooOO / iII111i - i11iIiiIii * i1IIi * o0oOOo0O0Ooo
 def unpack_address ( self , packet ) :
  oOO0OOOoO0ooo = self . packet_format ( )
  I1111ii1i = struct . calcsize ( oOO0OOOoO0ooo )
  if ( len ( packet ) < I1111ii1i ) : return ( None )
  if 51 - 51: Ii1I + IiII / I1ii11iIi11i + O0 % Ii1I
  I1Iii1I = struct . unpack ( oOO0OOOoO0ooo , packet [ : I1111ii1i ] )
  if 55 - 55: iII111i % o0oOOo0O0Ooo - oO0o % OoooooooOO
  if ( self . is_ipv4 ( ) ) :
   self . address = socket . ntohl ( I1Iii1I [ 0 ] )
   if 18 - 18: OoooooooOO - I1ii11iIi11i
  elif ( self . is_ipv6 ( ) ) :
   if 94 - 94: OOooOOo . Oo0Ooo + Ii1I * o0oOOo0O0Ooo
   if 79 - 79: OOooOOo + Oo0Ooo
   if 33 - 33: iIii1I11I1II1
   if 75 - 75: I1Ii111 / iIii1I11I1II1 . OoooooooOO
   if 98 - 98: iIii1I11I1II1 / I1IiiI + i1IIi
   if 80 - 80: II111iiii . Oo0Ooo * oO0o % II111iiii / I1ii11iIi11i
   if 66 - 66: iII111i / OoO0O00 / i11iIiiIii
   if 99 - 99: OOooOOo
   if ( I1Iii1I [ 0 ] <= 0xffff and ( I1Iii1I [ 0 ] & 0xff ) == 0 ) :
    ooII1iIIiIIIi1 = ( I1Iii1I [ 0 ] << 48 ) << 64
   else :
    ooII1iIIiIIIi1 = byte_swap_64 ( I1Iii1I [ 0 ] ) << 64
    if 79 - 79: oO0o % o0oOOo0O0Ooo / o0oOOo0O0Ooo % iII111i
   oOOOOoOO00 = byte_swap_64 ( I1Iii1I [ 1 ] )
   self . address = ooII1iIIiIIIi1 | oOOOOoOO00
   if 11 - 11: I11i + i11iIiiIii / oO0o % oO0o * o0oOOo0O0Ooo / OoOoOO00
  elif ( self . is_mac ( ) ) :
   oOo = I1Iii1I [ 0 ]
   oO000o000oOo = I1Iii1I [ 1 ]
   ooooOO00O = I1Iii1I [ 2 ]
   self . address = ( oOo << 32 ) + ( oO000o000oOo << 16 ) + ooooOO00O
   if 42 - 42: I11i % o0oOOo0O0Ooo + O0
  elif ( self . is_e164 ( ) ) :
   self . address = ( I1Iii1I [ 0 ] << 32 ) + I1Iii1I [ 1 ]
   if 61 - 61: II111iiii - I1Ii111 + I1ii11iIi11i
  elif ( self . is_dist_name ( ) ) :
   packet , self . address = lisp_decode_dist_name ( packet )
   self . mask_len = len ( self . address ) * 8
   I1111ii1i = 0
   if 57 - 57: OOooOOo + II111iiii
  packet = packet [ I1111ii1i : : ]
  return ( packet )
  if 67 - 67: II111iiii
  if 39 - 39: i1IIi
 def is_ipv4 ( self ) :
  return ( True if ( self . afi == LISP_AFI_IPV4 ) else False )
  if 16 - 16: OoOoOO00 % iIii1I11I1II1 + Ii1I - o0oOOo0O0Ooo . Oo0Ooo + i1IIi
  if 59 - 59: i1IIi
 def is_ipv4_link_local ( self ) :
  if ( self . is_ipv4 ( ) == False ) : return ( False )
  return ( ( ( self . address >> 16 ) & 0xffff ) == 0xa9fe )
  if 37 - 37: OoO0O00 / I1ii11iIi11i / OoOoOO00
  if 15 - 15: I1IiiI % iIii1I11I1II1 . I1Ii111
 def is_ipv4_loopback ( self ) :
  if ( self . is_ipv4 ( ) == False ) : return ( False )
  return ( self . address == 0x7f000001 )
  if 71 - 71: I11i - Ii1I + i11iIiiIii % I1ii11iIi11i - OoO0O00 - OOooOOo
  if 71 - 71: OOooOOo
 def is_ipv4_multicast ( self ) :
  if ( self . is_ipv4 ( ) == False ) : return ( False )
  return ( ( ( self . address >> 24 ) & 0xf0 ) == 0xe0 )
  if 27 - 27: OOooOOo * O0 * i11iIiiIii / OoOoOO00 - i1IIi
  if 73 - 73: iII111i / I1IiiI * ooOoO0o
 def is_ipv4_string ( self , addr_str ) :
  return ( addr_str . find ( "." ) != - 1 )
  if 85 - 85: I11i + I11i + oO0o - OoOoOO00
  if 15 - 15: OoO0O00
 def is_ipv6 ( self ) :
  return ( True if ( self . afi == LISP_AFI_IPV6 ) else False )
  if 88 - 88: Ii1I % i1IIi / I1Ii111
  if 2 - 2: Ii1I . IiII % OoOoOO00
 def is_ipv6_link_local ( self ) :
  if ( self . is_ipv6 ( ) == False ) : return ( False )
  return ( ( ( self . address >> 112 ) & 0xffff ) == 0xfe80 )
  if 42 - 42: OoOoOO00 * OoO0O00 * IiII - IiII % Oo0Ooo . IiII
  if 38 - 38: I1Ii111 . IiII - ooOoO0o . i11iIiiIii
 def is_ipv6_string_link_local ( self , addr_str ) :
  return ( addr_str . find ( "fe80::" ) != - 1 )
  if 35 - 35: i11iIiiIii
  if 62 - 62: O0 - o0oOOo0O0Ooo + I1Ii111 * I1ii11iIi11i / OOooOOo
 def is_ipv6_loopback ( self ) :
  if ( self . is_ipv6 ( ) == False ) : return ( False )
  return ( self . address == 1 )
  if 87 - 87: Oo0Ooo / OoooooooOO + O0 / o0oOOo0O0Ooo % II111iiii - O0
  if 63 - 63: OOooOOo - OoO0O00 * i1IIi - I1ii11iIi11i . I1IiiI
 def is_ipv6_multicast ( self ) :
  if ( self . is_ipv6 ( ) == False ) : return ( False )
  return ( ( ( self . address >> 120 ) & 0xff ) == 0xff )
  if 59 - 59: i11iIiiIii . OOooOOo % Oo0Ooo + O0
  if 84 - 84: I1Ii111 / O0 - IiII . I11i / o0oOOo0O0Ooo
 def is_ipv6_string ( self , addr_str ) :
  return ( addr_str . find ( ":" ) != - 1 )
  if 12 - 12: i11iIiiIii / Ii1I + i1IIi
  if 54 - 54: I1IiiI
 def is_mac ( self ) :
  return ( True if ( self . afi == LISP_AFI_MAC ) else False )
  if 55 - 55: I1ii11iIi11i % IiII % o0oOOo0O0Ooo + i1IIi * OoooooooOO % II111iiii
  if 37 - 37: Oo0Ooo
 def is_mac_multicast ( self ) :
  if ( self . is_mac ( ) == False ) : return ( False )
  return ( ( self . address & 0x010000000000 ) != 0 )
  if 33 - 33: OoooooooOO - O0 . O0 - o0oOOo0O0Ooo % o0oOOo0O0Ooo % OoO0O00
  if 27 - 27: ooOoO0o . i11iIiiIii / o0oOOo0O0Ooo * OoO0O00 * OoOoOO00 * oO0o
 def is_mac_broadcast ( self ) :
  if ( self . is_mac ( ) == False ) : return ( False )
  return ( self . address == 0xffffffffffff )
  if 19 - 19: O0 * II111iiii * OoOoOO00
  if 53 - 53: Oo0Ooo
 def is_mac_string ( self , addr_str ) :
  return ( len ( addr_str ) == 15 and addr_str . find ( "-" ) != - 1 )
  if 16 - 16: Ii1I
  if 73 - 73: i11iIiiIii + I1IiiI - IiII - IiII + IiII . Ii1I
 def is_link_local_multicast ( self ) :
  if ( self . is_ipv4 ( ) ) :
   return ( ( 0xe0ffff00 & self . address ) == 0xe0000000 )
   if 78 - 78: OoO0O00 + oO0o
  if ( self . is_ipv6 ( ) ) :
   return ( ( self . address >> 112 ) & 0xffff == 0xff02 )
   if 86 - 86: ooOoO0o . ooOoO0o + oO0o
  return ( False )
  if 84 - 84: OOooOOo - OoOoOO00 + i1IIi * I1ii11iIi11i % I1ii11iIi11i * I1Ii111
  if 31 - 31: IiII + iII111i
 def is_null ( self ) :
  return ( True if ( self . afi == LISP_AFI_NONE ) else False )
  if 5 - 5: O0 * Ii1I
  if 78 - 78: iII111i * iIii1I11I1II1 . OoO0O00 . OoOoOO00 % I1Ii111
 def is_ultimate_root ( self ) :
  return ( True if self . afi == LISP_AFI_ULTIMATE_ROOT else False )
  if 77 - 77: OOooOOo / OoooooooOO
  if 11 - 11: iIii1I11I1II1 - Ii1I - OoOoOO00 . oO0o / I1ii11iIi11i
 def is_iid_range ( self ) :
  return ( True if self . afi == LISP_AFI_IID_RANGE else False )
  if 79 - 79: i11iIiiIii % o0oOOo0O0Ooo * II111iiii . i1IIi * Ii1I - i11iIiiIii
  if 31 - 31: IiII / o0oOOo0O0Ooo
 def is_e164 ( self ) :
  return ( True if ( self . afi == LISP_AFI_E164 ) else False )
  if 27 - 27: Oo0Ooo
  if 32 - 32: Oo0Ooo * i11iIiiIii % I1IiiI - i11iIiiIii - I1Ii111 % I1ii11iIi11i
 def is_dist_name ( self ) :
  return ( True if ( self . afi == LISP_AFI_NAME ) else False )
  if 35 - 35: o0oOOo0O0Ooo % iII111i / O0 * I1IiiI . o0oOOo0O0Ooo / OOooOOo
  if 81 - 81: I1ii11iIi11i - i11iIiiIii
 def is_geo_prefix ( self ) :
  return ( True if ( self . afi == LISP_AFI_GEO_COORD ) else False )
  if 49 - 49: iII111i * I11i - II111iiii . o0oOOo0O0Ooo
  if 52 - 52: Ii1I + Ii1I - II111iiii . O0 + I1ii11iIi11i
 def is_binary ( self ) :
  if ( self . is_dist_name ( ) ) : return ( False )
  if ( self . is_geo_prefix ( ) ) : return ( False )
  return ( True )
  if 60 - 60: i11iIiiIii + IiII
  if 41 - 41: I1Ii111 * o0oOOo0O0Ooo + Oo0Ooo
 def store_address ( self , addr_str ) :
  if ( self . afi == LISP_AFI_NONE ) : self . string_to_afi ( addr_str )
  if 86 - 86: Ii1I / oO0o
  if 40 - 40: OoO0O00 % oO0o + Oo0Ooo
  if 60 - 60: II111iiii / Ii1I
  if 14 - 14: iII111i - Oo0Ooo / o0oOOo0O0Ooo * oO0o / Oo0Ooo - I1IiiI
  oO = addr_str . find ( "[" )
  Ii1i1Ii = addr_str . find ( "]" )
  if ( oO != - 1 and Ii1i1Ii != - 1 ) :
   self . instance_id = int ( addr_str [ oO + 1 : Ii1i1Ii ] )
   addr_str = addr_str [ Ii1i1Ii + 1 : : ]
   if ( self . is_dist_name ( ) == False ) :
    addr_str = addr_str . replace ( " " , "" )
    if 89 - 89: i1IIi / I1Ii111 + Ii1I - i1IIi
    if 66 - 66: OoooooooOO
    if 68 - 68: iII111i + I1Ii111
    if 90 - 90: o0oOOo0O0Ooo
    if 48 - 48: iII111i + Ii1I
    if 45 - 45: oO0o / iIii1I11I1II1 % O0 % IiII % I1ii11iIi11i
  if ( self . is_ipv4 ( ) ) :
   oOO00OoO = addr_str . split ( "." )
   oOOO = int ( oOO00OoO [ 0 ] ) << 24
   oOOO += int ( oOO00OoO [ 1 ] ) << 16
   oOOO += int ( oOO00OoO [ 2 ] ) << 8
   oOOO += int ( oOO00OoO [ 3 ] )
   self . address = oOOO
  elif ( self . is_ipv6 ( ) ) :
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
   if 66 - 66: o0oOOo0O0Ooo % IiII
   if 39 - 39: IiII
   if 18 - 18: iII111i % o0oOOo0O0Ooo - i1IIi
   OOO000 = ( addr_str [ 2 : 4 ] == "::" )
   try :
    addr_str = socket . inet_pton ( socket . AF_INET6 , addr_str )
   except :
    addr_str = socket . inet_pton ( socket . AF_INET6 , "0::0" )
    if 66 - 66: I1ii11iIi11i
   addr_str = binascii . hexlify ( addr_str )
   if 4 - 4: I11i % II111iiii + i11iIiiIii . OOooOOo . I11i / iIii1I11I1II1
   if ( OOO000 ) :
    addr_str = addr_str [ 2 : 4 ] + addr_str [ 0 : 2 ] + addr_str [ 4 : : ]
    if 62 - 62: O0
   self . address = int ( addr_str , 16 )
   if 52 - 52: OoooooooOO . oO0o
  elif ( self . is_geo_prefix ( ) ) :
   oOo0o0oOoo0Oo = lisp_geo ( None )
   oOo0o0oOoo0Oo . name = "geo-prefix-{}" . format ( oOo0o0oOoo0Oo )
   oOo0o0oOoo0Oo . parse_geo_string ( addr_str )
   self . address = oOo0o0oOoo0Oo
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
   if 38 - 38: ooOoO0o . i1IIi / iII111i + I1IiiI - II111iiii
  self . mask_len = self . host_mask_len ( )
  if 21 - 21: i11iIiiIii + II111iiii - i1IIi / OoooooooOO * OOooOOo % Oo0Ooo
  if 59 - 59: Ii1I
 def store_prefix ( self , prefix_str ) :
  if ( self . is_geo_string ( prefix_str ) ) :
   OOOoO000 = prefix_str . find ( "]" )
   ooooOo00OO0o = len ( prefix_str [ OOOoO000 + 1 : : ] ) * 8
  elif ( prefix_str . find ( "/" ) != - 1 ) :
   prefix_str , ooooOo00OO0o = prefix_str . split ( "/" )
  else :
   II11 = prefix_str . find ( "'" )
   if ( II11 == - 1 ) : return
   oOoOOOo = prefix_str . find ( "'" , II11 + 1 )
   if ( oOoOOOo == - 1 ) : return
   ooooOo00OO0o = len ( prefix_str [ II11 + 1 : oOoOOOo ] ) * 8
   if 77 - 77: I1ii11iIi11i * Ii1I * O0 * I1IiiI % OoO0O00 - iIii1I11I1II1
   if 6 - 6: i11iIiiIii . I11i - OoooooooOO
  self . string_to_afi ( prefix_str )
  self . store_address ( prefix_str )
  self . mask_len = int ( ooooOo00OO0o )
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
  OOOoO000 = addr_str . find ( "]" )
  if ( OOOoO000 != - 1 ) : addr_str = addr_str [ OOOoO000 + 1 : : ]
  if 22 - 22: iIii1I11I1II1 . i1IIi . OOooOOo % Oo0Ooo - i1IIi
  oOo0o0oOoo0Oo = addr_str . split ( "/" )
  if ( len ( oOo0o0oOoo0Oo ) == 2 ) :
   if ( oOo0o0oOoo0Oo [ 1 ] . isdigit ( ) == False ) : return ( False )
   if 78 - 78: I1IiiI / i1IIi % II111iiii % I1IiiI % Ii1I
  oOo0o0oOoo0Oo = oOo0o0oOoo0Oo [ 0 ]
  oOo0o0oOoo0Oo = oOo0o0oOoo0Oo . split ( "-" )
  IiIIi1IIii = len ( oOo0o0oOoo0Oo )
  if ( IiIIi1IIii < 8 or IiIIi1IIii > 9 ) : return ( False )
  if 86 - 86: I1Ii111 % ooOoO0o + OoOoOO00 + II111iiii % I1Ii111 + i11iIiiIii
  for OO00o0O0Oo in range ( 0 , IiIIi1IIii ) :
   if ( OO00o0O0Oo == 3 ) :
    if ( oOo0o0oOoo0Oo [ OO00o0O0Oo ] in [ "N" , "S" ] ) : continue
    return ( False )
    if 90 - 90: i11iIiiIii
   if ( OO00o0O0Oo == 7 ) :
    if ( oOo0o0oOoo0Oo [ OO00o0O0Oo ] in [ "W" , "E" ] ) : continue
    return ( False )
    if 92 - 92: i1IIi
   if ( oOo0o0oOoo0Oo [ OO00o0O0Oo ] . isdigit ( ) == False ) : return ( False )
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
  I1Iii1I = self . print_address_no_iid ( )
  IIiI1i = "[" + str ( self . instance_id )
  for oO in self . iid_list : IIiI1i += "," + str ( oO )
  IIiI1i += "]"
  I1Iii1I = "{}{}" . format ( IIiI1i , I1Iii1I )
  return ( I1Iii1I )
  if 45 - 45: Ii1I % OOooOOo * Ii1I - iIii1I11I1II1
  if 18 - 18: I1Ii111 / Oo0Ooo % Ii1I + OoO0O00
 def print_address_no_iid ( self ) :
  if ( self . is_ipv4 ( ) ) :
   I1Iii1I = self . address
   o0Ooo0OoOo = I1Iii1I >> 24
   oOO0O = ( I1Iii1I >> 16 ) & 0xff
   II1o0OoO = ( I1Iii1I >> 8 ) & 0xff
   oo0o0O00O = I1Iii1I & 0xff
   return ( "{}.{}.{}.{}" . format ( o0Ooo0OoOo , oOO0O , II1o0OoO , oo0o0O00O ) )
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
  I1Iii1I = self . print_address ( )
  if ( self . is_dist_name ( ) ) : return ( I1Iii1I )
  if ( self . is_geo_prefix ( ) ) : return ( I1Iii1I )
  if 82 - 82: O0 / I1Ii111 + OOooOOo . IiII + Ii1I
  OOOoO000 = I1Iii1I . find ( "no-address" )
  if ( OOOoO000 == - 1 ) :
   I1Iii1I = "{}/{}" . format ( I1Iii1I , str ( self . mask_len ) )
  else :
   I1Iii1I = I1Iii1I [ 0 : OOOoO000 ]
   if 31 - 31: i1IIi * OoO0O00 - Ii1I + I11i
  return ( I1Iii1I )
  if 8 - 8: O0 + i1IIi . O0
  if 67 - 67: I1IiiI
 def print_prefix_no_iid ( self ) :
  I1Iii1I = self . print_address_no_iid ( )
  if ( self . is_dist_name ( ) ) : return ( I1Iii1I )
  if ( self . is_geo_prefix ( ) ) : return ( I1Iii1I )
  return ( "{}/{}" . format ( I1Iii1I , str ( self . mask_len ) ) )
  if 42 - 42: ooOoO0o - o0oOOo0O0Ooo % oO0o - ooOoO0o
  if 87 - 87: OoooooooOO / O0
 def print_prefix_url ( self ) :
  if ( self . is_ultimate_root ( ) ) : return ( "0--0" )
  I1Iii1I = self . print_address ( )
  OOOoO000 = I1Iii1I . find ( "]" )
  if ( OOOoO000 != - 1 ) : I1Iii1I = I1Iii1I [ OOOoO000 + 1 : : ]
  if ( self . is_geo_prefix ( ) ) :
   I1Iii1I = I1Iii1I . replace ( "/" , "-" )
   return ( "{}-{}" . format ( self . instance_id , I1Iii1I ) )
   if 57 - 57: iIii1I11I1II1 / IiII + OoO0O00 * oO0o + Ii1I
  return ( "{}-{}-{}" . format ( self . instance_id , I1Iii1I , self . mask_len ) )
  if 76 - 76: i11iIiiIii . OOooOOo / I11i * oO0o % iIii1I11I1II1 . ooOoO0o
  if 75 - 75: O0 + I1IiiI
 def print_sg ( self , g ) :
  i1I1iIi1IiI = self . print_prefix ( )
  OOooOOoOoo = i1I1iIi1IiI . find ( "]" ) + 1
  g = g . print_prefix ( )
  o00 = g . find ( "]" ) + 1
  I1I1I11Ii = "[{}]({}, {})" . format ( self . instance_id , i1I1iIi1IiI [ OOooOOoOoo : : ] , g [ o00 : : ] )
  return ( I1I1I11Ii )
  if 70 - 70: I1IiiI / I11i - II111iiii . o0oOOo0O0Ooo / O0
  if 29 - 29: OOooOOo . OOooOOo * iII111i % OoO0O00
 def hash_address ( self , addr ) :
  I1I11Iiii111 = self . address
  iI1 = addr . address
  if 66 - 66: Ii1I / OoO0O00 * i11iIiiIii * oO0o . iIii1I11I1II1
  if ( self . is_geo_prefix ( ) ) : I1I11Iiii111 = self . address . print_geo ( )
  if ( addr . is_geo_prefix ( ) ) : iI1 = addr . address . print_geo ( )
  if 16 - 16: Oo0Ooo % IiII * o0oOOo0O0Ooo % OoOoOO00 - OoooooooOO
  if ( type ( I1I11Iiii111 ) == str ) :
   I1I11Iiii111 = int ( binascii . hexlify ( I1I11Iiii111 [ 0 : 1 ] ) )
   if 61 - 61: i11iIiiIii - i1IIi + iIii1I11I1II1 * I1IiiI % OoOoOO00 . oO0o
  if ( type ( iI1 ) == str ) :
   iI1 = int ( binascii . hexlify ( iI1 [ 0 : 1 ] ) )
   if 24 - 24: iII111i . i1IIi * I1ii11iIi11i
  return ( I1I11Iiii111 ^ iI1 )
  if 1 - 1: oO0o / OoOoOO00 + I1IiiI
  if 47 - 47: O0 / OOooOOo . i1IIi / OoooooooOO . IiII
  if 34 - 34: OoO0O00 * II111iiii + I1Ii111
  if 20 - 20: iIii1I11I1II1 . OoO0O00 . II111iiii / Ii1I - iIii1I11I1II1 / OOooOOo
  if 20 - 20: i11iIiiIii * oO0o * ooOoO0o
  if 65 - 65: I1ii11iIi11i / Oo0Ooo / I1IiiI + IiII
 def is_more_specific ( self , prefix ) :
  if ( prefix . afi == LISP_AFI_ULTIMATE_ROOT ) : return ( True )
  if 71 - 71: OoO0O00 . I1Ii111 + OoooooooOO
  ooooOo00OO0o = prefix . mask_len
  if ( prefix . afi == LISP_AFI_IID_RANGE ) :
   Ii1ii = 2 ** ( 32 - ooooOo00OO0o )
   iI11I = prefix . instance_id
   IIi1Iii1 = iI11I + Ii1ii
   return ( self . instance_id in range ( iI11I , IIi1Iii1 ) )
   if 77 - 77: I1ii11iIi11i % ooOoO0o + o0oOOo0O0Ooo + ooOoO0o
   if 23 - 23: OoOoOO00 % ooOoO0o
  if ( self . instance_id != prefix . instance_id ) : return ( False )
  if ( self . afi != prefix . afi ) :
   if ( prefix . afi != LISP_AFI_NONE ) : return ( False )
   if 39 - 39: OoO0O00
   if 9 - 9: Ii1I % oO0o
   if 33 - 33: I1IiiI
   if 98 - 98: I1Ii111 . i11iIiiIii * iIii1I11I1II1 + oO0o
   if 96 - 96: II111iiii - OOooOOo * I1Ii111 . oO0o
  if ( self . is_binary ( ) == False ) :
   if ( prefix . afi == LISP_AFI_NONE ) : return ( True )
   if ( type ( self . address ) != type ( prefix . address ) ) : return ( False )
   I1Iii1I = self . address
   Ii11i11iiiIII = prefix . address
   if ( self . is_geo_prefix ( ) ) :
    I1Iii1I = self . address . print_geo ( )
    Ii11i11iiiIII = prefix . address . print_geo ( )
    if 77 - 77: OOooOOo + oO0o + Oo0Ooo * o0oOOo0O0Ooo
   if ( len ( I1Iii1I ) < len ( Ii11i11iiiIII ) ) : return ( False )
   return ( I1Iii1I . find ( Ii11i11iiiIII ) == 0 )
   if 71 - 71: Ii1I
   if 70 - 70: oO0o . I1ii11iIi11i
   if 81 - 81: iII111i * i11iIiiIii % OoO0O00 - iIii1I11I1II1 * I1ii11iIi11i
   if 8 - 8: O0 / iIii1I11I1II1 - Oo0Ooo % ooOoO0o * Ii1I % o0oOOo0O0Ooo
   if 59 - 59: Oo0Ooo % iII111i
  if ( self . mask_len < ooooOo00OO0o ) : return ( False )
  if 52 - 52: o0oOOo0O0Ooo . I1ii11iIi11i
  iiIiII1IiiI1 = ( prefix . addr_length ( ) * 8 ) - ooooOo00OO0o
  OoOo0Ooo0Oooo = ( 2 ** ooooOo00OO0o - 1 ) << iiIiII1IiiI1
  return ( ( self . address & OoOo0Ooo0Oooo ) == prefix . address )
  if 72 - 72: Ii1I
  if 76 - 76: O0 + oO0o * OoooooooOO - I11i
 def mask_address ( self , mask_len ) :
  iiIiII1IiiI1 = ( self . addr_length ( ) * 8 ) - mask_len
  OoOo0Ooo0Oooo = ( 2 ** mask_len - 1 ) << iiIiII1IiiI1
  self . address &= OoOo0Ooo0Oooo
  if 96 - 96: I1Ii111 - Ii1I - i11iIiiIii
  if 57 - 57: IiII % i1IIi
 def is_exact_match ( self , prefix ) :
  if ( self . instance_id != prefix . instance_id ) : return ( False )
  O000ooOo0o = self . print_prefix ( )
  IIIi1i1Ii1I = prefix . print_prefix ( ) if prefix else ""
  return ( O000ooOo0o == IIIi1i1Ii1I )
  if 15 - 15: i1IIi
  if 38 - 38: I1ii11iIi11i / Oo0Ooo - iIii1I11I1II1 . i1IIi
 def is_local ( self ) :
  if ( self . is_ipv4 ( ) ) :
   O00o0Oo = lisp_myrlocs [ 0 ]
   if ( O00o0Oo == None ) : return ( False )
   O00o0Oo = O00o0Oo . print_address_no_iid ( )
   return ( self . print_address_no_iid ( ) == O00o0Oo )
   if 56 - 56: I1Ii111 * i1IIi % i11iIiiIii
  if ( self . is_ipv6 ( ) ) :
   O00o0Oo = lisp_myrlocs [ 1 ]
   if ( O00o0Oo == None ) : return ( False )
   O00o0Oo = O00o0Oo . print_address_no_iid ( )
   return ( self . print_address_no_iid ( ) == O00o0Oo )
   if 56 - 56: Ii1I . iII111i
  return ( False )
  if 76 - 76: I1IiiI / Ii1I % OoOoOO00 + IiII / i11iIiiIii . o0oOOo0O0Ooo
  if 31 - 31: oO0o * oO0o % o0oOOo0O0Ooo . O0 + iII111i
 def store_iid_range ( self , iid , mask_len ) :
  if ( self . afi == LISP_AFI_NONE ) :
   if ( iid is 0 and mask_len is 0 ) : self . afi = LISP_AFI_ULTIMATE_ROOT
   else : self . afi = LISP_AFI_IID_RANGE
   if 52 - 52: i11iIiiIii
  self . instance_id = iid
  self . mask_len = mask_len
  if 1 - 1: i1IIi * iIii1I11I1II1
  if 29 - 29: I11i
 def lcaf_length ( self , lcaf_type ) :
  I1I1 = self . addr_length ( ) + 2
  if ( lcaf_type == LISP_LCAF_AFI_LIST_TYPE ) : I1I1 += 4
  if ( lcaf_type == LISP_LCAF_INSTANCE_ID_TYPE ) : I1I1 += 4
  if ( lcaf_type == LISP_LCAF_ASN_TYPE ) : I1I1 += 4
  if ( lcaf_type == LISP_LCAF_APP_DATA_TYPE ) : I1I1 += 8
  if ( lcaf_type == LISP_LCAF_GEO_COORD_TYPE ) : I1I1 += 12
  if ( lcaf_type == LISP_LCAF_OPAQUE_TYPE ) : I1I1 += 0
  if ( lcaf_type == LISP_LCAF_NAT_TYPE ) : I1I1 += 4
  if ( lcaf_type == LISP_LCAF_NONCE_LOC_TYPE ) : I1I1 += 4
  if ( lcaf_type == LISP_LCAF_MCAST_INFO_TYPE ) : I1I1 = I1I1 * 2 + 8
  if ( lcaf_type == LISP_LCAF_ELP_TYPE ) : I1I1 += 0
  if ( lcaf_type == LISP_LCAF_SECURITY_TYPE ) : I1I1 += 6
  if ( lcaf_type == LISP_LCAF_SOURCE_DEST_TYPE ) : I1I1 += 4
  if ( lcaf_type == LISP_LCAF_RLE_TYPE ) : I1I1 += 4
  return ( I1I1 )
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
  if 77 - 77: ooOoO0o + I1ii11iIi11i * o0oOOo0O0Ooo / i1IIi * I11i
 def lcaf_encode_iid ( self ) :
  O00OO0oOOO = LISP_LCAF_INSTANCE_ID_TYPE
  o000OO00OoO00 = socket . htons ( self . lcaf_length ( O00OO0oOOO ) )
  IIiI1i = self . instance_id
  ooOooOooOOO = self . afi
  ii11i1 = 0
  if ( ooOooOooOOO < 0 ) :
   if ( self . afi == LISP_AFI_GEO_COORD ) :
    ooOooOooOOO = LISP_AFI_LCAF
    ii11i1 = 0
   else :
    ooOooOooOOO = 0
    ii11i1 = self . mask_len
    if 70 - 70: oO0o / iII111i * i1IIi / II111iiii / OoOoOO00 + oO0o
    if 30 - 30: i1IIi - iII111i - i11iIiiIii . OoOoOO00 . o0oOOo0O0Ooo
    if 74 - 74: i11iIiiIii / II111iiii
  oOoiII1I1 = struct . pack ( "BBBBH" , 0 , 0 , O00OO0oOOO , ii11i1 , o000OO00OoO00 )
  oOoiII1I1 += struct . pack ( "IH" , socket . htonl ( IIiI1i ) , socket . htons ( ooOooOooOOO ) )
  if ( ooOooOooOOO == 0 ) : return ( oOoiII1I1 )
  if 56 - 56: Ii1I + o0oOOo0O0Ooo
  if ( self . afi == LISP_AFI_GEO_COORD ) :
   oOoiII1I1 = oOoiII1I1 [ 0 : - 2 ]
   oOoiII1I1 += self . address . encode_geo ( )
   return ( oOoiII1I1 )
   if 92 - 92: I1Ii111 * iIii1I11I1II1 - o0oOOo0O0Ooo / O0 % iIii1I11I1II1
   if 39 - 39: Ii1I . II111iiii / I1IiiI
  oOoiII1I1 += self . pack_address ( )
  return ( oOoiII1I1 )
  if 44 - 44: Ii1I / Ii1I / OoO0O00 % ooOoO0o / I11i . I1ii11iIi11i
  if 41 - 41: I1ii11iIi11i * ooOoO0o * I11i + O0 * O0 - O0
 def lcaf_decode_iid ( self , packet ) :
  oOO0OOOoO0ooo = "BBBBH"
  I1111ii1i = struct . calcsize ( oOO0OOOoO0ooo )
  if ( len ( packet ) < I1111ii1i ) : return ( None )
  if 81 - 81: I1Ii111 % OoO0O00 / O0
  oOOooOOO , OOo00o000oOO0 , O00OO0oOOO , ooO000O0 , I1I1 = struct . unpack ( oOO0OOOoO0ooo ,
 packet [ : I1111ii1i ] )
  packet = packet [ I1111ii1i : : ]
  if 31 - 31: IiII
  if ( O00OO0oOOO != LISP_LCAF_INSTANCE_ID_TYPE ) : return ( None )
  if 37 - 37: iII111i % I1IiiI % ooOoO0o
  oOO0OOOoO0ooo = "IH"
  I1111ii1i = struct . calcsize ( oOO0OOOoO0ooo )
  if ( len ( packet ) < I1111ii1i ) : return ( None )
  if 39 - 39: OOooOOo / Oo0Ooo / I1IiiI + I1Ii111 % iII111i * iIii1I11I1II1
  IIiI1i , ooOooOooOOO = struct . unpack ( oOO0OOOoO0ooo , packet [ : I1111ii1i ] )
  packet = packet [ I1111ii1i : : ]
  if 94 - 94: o0oOOo0O0Ooo
  I1I1 = socket . ntohs ( I1I1 )
  self . instance_id = socket . ntohl ( IIiI1i )
  ooOooOooOOO = socket . ntohs ( ooOooOooOOO )
  self . afi = ooOooOooOOO
  if ( ooO000O0 != 0 and ooOooOooOOO == 0 ) : self . mask_len = ooO000O0
  if ( ooOooOooOOO == 0 ) :
   self . afi = LISP_AFI_IID_RANGE if ooO000O0 else LISP_AFI_ULTIMATE_ROOT
   if 66 - 66: Ii1I - Oo0Ooo / oO0o + iII111i % IiII
   if 19 - 19: I1IiiI + I1IiiI + I1Ii111 % i1IIi * I1IiiI
   if 83 - 83: II111iiii - o0oOOo0O0Ooo . OoO0O00 . OOooOOo % o0oOOo0O0Ooo
   if 96 - 96: i1IIi % OoooooooOO * OOooOOo - Oo0Ooo + iIii1I11I1II1
   if 87 - 87: I11i . I1ii11iIi11i / i1IIi - II111iiii - i11iIiiIii
  if ( ooOooOooOOO == 0 ) : return ( packet )
  if 49 - 49: I1ii11iIi11i + I1Ii111 * OOooOOo - IiII . i11iIiiIii
  if 34 - 34: iII111i . OoOoOO00
  if 49 - 49: I1ii11iIi11i % oO0o - I1Ii111 . I1ii11iIi11i % II111iiii
  if 20 - 20: I1ii11iIi11i . iIii1I11I1II1 - Ii1I % OoO0O00
  if ( self . is_dist_name ( ) ) :
   packet , self . address = lisp_decode_dist_name ( packet )
   self . mask_len = len ( self . address ) * 8
   return ( packet )
   if 27 - 27: iIii1I11I1II1 / I1Ii111 - I11i . OoO0O00 + ooOoO0o
   if 89 - 89: I1IiiI % I11i - OOooOOo
   if 71 - 71: OOooOOo % Oo0Ooo - o0oOOo0O0Ooo / I1Ii111 - O0 - oO0o
   if 10 - 10: I1IiiI
   if 17 - 17: i11iIiiIii % o0oOOo0O0Ooo . ooOoO0o
  if ( ooOooOooOOO == LISP_AFI_LCAF ) :
   oOO0OOOoO0ooo = "BBBBH"
   I1111ii1i = struct . calcsize ( oOO0OOOoO0ooo )
   if ( len ( packet ) < I1111ii1i ) : return ( None )
   if 34 - 34: OoooooooOO / iII111i / O0
   OOII1iI , Ooooo0OO , O00OO0oOOO , o0o0OO0OO , ii111 = struct . unpack ( oOO0OOOoO0ooo , packet [ : I1111ii1i ] )
   if 75 - 75: I11i % OOooOOo - OoO0O00 * I11i * IiII
   if 11 - 11: I1ii11iIi11i . O0 - iII111i * IiII . i1IIi . iII111i
   if ( O00OO0oOOO != LISP_LCAF_GEO_COORD_TYPE ) : return ( None )
   if 82 - 82: i1IIi * I11i * Ii1I - IiII . i11iIiiIii
   ii111 = socket . ntohs ( ii111 )
   packet = packet [ I1111ii1i : : ]
   if ( ii111 > len ( packet ) ) : return ( None )
   if 40 - 40: OOooOOo - OoooooooOO
   oOo0o0oOoo0Oo = lisp_geo ( "" )
   self . afi = LISP_AFI_GEO_COORD
   self . address = oOo0o0oOoo0Oo
   packet = oOo0o0oOoo0Oo . decode_geo ( packet , ii111 , o0o0OO0OO )
   self . mask_len = self . host_mask_len ( )
   return ( packet )
   if 36 - 36: i1IIi % OoOoOO00 - i1IIi
   if 5 - 5: I1IiiI . I1IiiI % II111iiii - I1Ii111
  o000OO00OoO00 = self . addr_length ( )
  if ( len ( packet ) < o000OO00OoO00 ) : return ( None )
  if 97 - 97: I11i . ooOoO0o
  packet = self . unpack_address ( packet )
  return ( packet )
  if 87 - 87: oO0o / iIii1I11I1II1 - I11i + OoooooooOO
  if 79 - 79: I1ii11iIi11i * IiII . I1ii11iIi11i
  if 65 - 65: iII111i - Ii1I - II111iiii * O0 + I1ii11iIi11i . iIii1I11I1II1
  if 76 - 76: OoO0O00 * ooOoO0o
  if 32 - 32: O0 . oO0o * o0oOOo0O0Ooo . Ii1I + IiII
  if 98 - 98: iII111i . II111iiii % O0
  if 43 - 43: OOooOOo % I1Ii111 . IiII % OoO0O00 + I1Ii111 % OoooooooOO
  if 17 - 17: OoooooooOO - i1IIi * I11i
  if 33 - 33: i1IIi . Oo0Ooo + I11i
  if 97 - 97: OOooOOo / IiII / ooOoO0o / OoooooooOO
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
 def lcaf_encode_sg ( self , group ) :
  O00OO0oOOO = LISP_LCAF_MCAST_INFO_TYPE
  IIiI1i = socket . htonl ( self . instance_id )
  o000OO00OoO00 = socket . htons ( self . lcaf_length ( O00OO0oOOO ) )
  oOoiII1I1 = struct . pack ( "BBBBHIHBB" , 0 , 0 , O00OO0oOOO , 0 , o000OO00OoO00 , IIiI1i ,
 0 , self . mask_len , group . mask_len )
  if 18 - 18: OoO0O00 - OoO0O00 . o0oOOo0O0Ooo
  oOoiII1I1 += struct . pack ( "H" , socket . htons ( self . afi ) )
  oOoiII1I1 += self . pack_address ( )
  oOoiII1I1 += struct . pack ( "H" , socket . htons ( group . afi ) )
  oOoiII1I1 += group . pack_address ( )
  return ( oOoiII1I1 )
  if 80 - 80: I11i + I1Ii111 / I1IiiI * OOooOOo % iII111i
  if 48 - 48: iIii1I11I1II1 + i1IIi . I1IiiI % OoO0O00 - iIii1I11I1II1 / i1IIi
 def lcaf_decode_sg ( self , packet ) :
  oOO0OOOoO0ooo = "BBBBHIHBB"
  I1111ii1i = struct . calcsize ( oOO0OOOoO0ooo )
  if ( len ( packet ) < I1111ii1i ) : return ( [ None , None ] )
  if 14 - 14: IiII . I11i
  oOOooOOO , OOo00o000oOO0 , O00OO0oOOO , oOoo , I1I1 , IIiI1i , IIi11II11 , I1ii1IiIi11 , IIiIIiI1III111iI = struct . unpack ( oOO0OOOoO0ooo , packet [ : I1111ii1i ] )
  if 14 - 14: Ii1I / iIii1I11I1II1 + O0 / iIii1I11I1II1 . oO0o % O0
  packet = packet [ I1111ii1i : : ]
  if 72 - 72: ooOoO0o / IiII / OOooOOo + OOooOOo / I1ii11iIi11i / i1IIi
  if ( O00OO0oOOO != LISP_LCAF_MCAST_INFO_TYPE ) : return ( [ None , None ] )
  if 61 - 61: I11i * O0
  self . instance_id = socket . ntohl ( IIiI1i )
  I1I1 = socket . ntohs ( I1I1 ) - 8
  if 80 - 80: I1ii11iIi11i + II111iiii % Oo0Ooo - o0oOOo0O0Ooo
  if 1 - 1: iII111i - OoOoOO00
  if 14 - 14: I1IiiI + I1IiiI / iIii1I11I1II1 . OoOoOO00 - II111iiii - II111iiii
  if 85 - 85: o0oOOo0O0Ooo + i11iIiiIii - Oo0Ooo . iII111i
  if 58 - 58: O0 / I1Ii111 + OoO0O00
  oOO0OOOoO0ooo = "H"
  I1111ii1i = struct . calcsize ( oOO0OOOoO0ooo )
  if ( len ( packet ) < I1111ii1i ) : return ( [ None , None ] )
  if ( I1I1 < I1111ii1i ) : return ( [ None , None ] )
  if 41 - 41: o0oOOo0O0Ooo - I1ii11iIi11i - II111iiii / Oo0Ooo % i1IIi * iIii1I11I1II1
  ooOooOooOOO = struct . unpack ( oOO0OOOoO0ooo , packet [ : I1111ii1i ] ) [ 0 ]
  packet = packet [ I1111ii1i : : ]
  I1I1 -= I1111ii1i
  self . afi = socket . ntohs ( ooOooOooOOO )
  self . mask_len = I1ii1IiIi11
  o000OO00OoO00 = self . addr_length ( )
  if ( I1I1 < o000OO00OoO00 ) : return ( [ None , None ] )
  if 53 - 53: I1Ii111 . I1ii11iIi11i
  packet = self . unpack_address ( packet )
  if ( packet == None ) : return ( [ None , None ] )
  if 18 - 18: I1ii11iIi11i / i11iIiiIii
  I1I1 -= o000OO00OoO00
  if 52 - 52: i11iIiiIii . O0 * ooOoO0o - o0oOOo0O0Ooo - O0
  if 39 - 39: iII111i / I11i
  if 67 - 67: i1IIi
  if 1 - 1: OoOoOO00 * O0 + i11iIiiIii . ooOoO0o / OoO0O00
  if 48 - 48: o0oOOo0O0Ooo * II111iiii
  oOO0OOOoO0ooo = "H"
  I1111ii1i = struct . calcsize ( oOO0OOOoO0ooo )
  if ( len ( packet ) < I1111ii1i ) : return ( [ None , None ] )
  if ( I1I1 < I1111ii1i ) : return ( [ None , None ] )
  if 17 - 17: o0oOOo0O0Ooo / ooOoO0o + i1IIi
  ooOooOooOOO = struct . unpack ( oOO0OOOoO0ooo , packet [ : I1111ii1i ] ) [ 0 ]
  packet = packet [ I1111ii1i : : ]
  I1I1 -= I1111ii1i
  Oo000o0o0 = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  Oo000o0o0 . afi = socket . ntohs ( ooOooOooOOO )
  Oo000o0o0 . mask_len = IIiIIiI1III111iI
  Oo000o0o0 . instance_id = self . instance_id
  o000OO00OoO00 = self . addr_length ( )
  if ( I1I1 < o000OO00OoO00 ) : return ( [ None , None ] )
  if 78 - 78: iIii1I11I1II1 * o0oOOo0O0Ooo * Oo0Ooo - OoO0O00 / OoO0O00
  packet = Oo000o0o0 . unpack_address ( packet )
  if ( packet == None ) : return ( [ None , None ] )
  if 89 - 89: o0oOOo0O0Ooo % o0oOOo0O0Ooo
  return ( [ packet , Oo000o0o0 ] )
  if 8 - 8: Ii1I % oO0o - o0oOOo0O0Ooo
  if 14 - 14: OOooOOo * IiII
 def lcaf_decode_eid ( self , packet ) :
  oOO0OOOoO0ooo = "BBB"
  I1111ii1i = struct . calcsize ( oOO0OOOoO0ooo )
  if ( len ( packet ) < I1111ii1i ) : return ( [ None , None ] )
  if 15 - 15: o0oOOo0O0Ooo + OoooooooOO - OOooOOo - o0oOOo0O0Ooo . iIii1I11I1II1 / Ii1I
  if 33 - 33: OoO0O00
  if 91 - 91: I11i % I11i % iII111i
  if 19 - 19: I11i / I11i + I1IiiI * OoO0O00 - iII111i . Oo0Ooo
  if 76 - 76: iII111i % OOooOOo / OoooooooOO . I1IiiI % OoO0O00 % i1IIi
  oOoo , Ooooo0OO , O00OO0oOOO = struct . unpack ( oOO0OOOoO0ooo ,
 packet [ : I1111ii1i ] )
  if 95 - 95: Oo0Ooo - O0 / I1ii11iIi11i . I1IiiI / o0oOOo0O0Ooo % OoOoOO00
  if ( O00OO0oOOO == LISP_LCAF_INSTANCE_ID_TYPE ) :
   return ( [ self . lcaf_decode_iid ( packet ) , None ] )
  elif ( O00OO0oOOO == LISP_LCAF_MCAST_INFO_TYPE ) :
   packet , Oo000o0o0 = self . lcaf_decode_sg ( packet )
   return ( [ packet , Oo000o0o0 ] )
  elif ( O00OO0oOOO == LISP_LCAF_GEO_COORD_TYPE ) :
   oOO0OOOoO0ooo = "BBBBH"
   I1111ii1i = struct . calcsize ( oOO0OOOoO0ooo )
   if ( len ( packet ) < I1111ii1i ) : return ( None )
   if 38 - 38: OoOoOO00 % OoooooooOO . oO0o - OoooooooOO + I11i
   OOII1iI , Ooooo0OO , O00OO0oOOO , o0o0OO0OO , ii111 = struct . unpack ( oOO0OOOoO0ooo , packet [ : I1111ii1i ] )
   if 18 - 18: OoooooooOO + ooOoO0o * OoOoOO00 - OoO0O00
   if 42 - 42: oO0o % OoOoOO00 - oO0o + I11i / i11iIiiIii
   if ( O00OO0oOOO != LISP_LCAF_GEO_COORD_TYPE ) : return ( None )
   if 74 - 74: OoO0O00 - II111iiii - ooOoO0o % i1IIi
   ii111 = socket . ntohs ( ii111 )
   packet = packet [ I1111ii1i : : ]
   if ( ii111 > len ( packet ) ) : return ( None )
   if 42 - 42: i11iIiiIii / O0
   oOo0o0oOoo0Oo = lisp_geo ( "" )
   self . instance_id = 0
   self . afi = LISP_AFI_GEO_COORD
   self . address = oOo0o0oOoo0Oo
   packet = oOo0o0oOoo0Oo . decode_geo ( packet , ii111 , o0o0OO0OO )
   self . mask_len = self . host_mask_len ( )
   if 8 - 8: I1Ii111
  return ( [ packet , None ] )
  if 51 - 51: i11iIiiIii
  if 1 - 1: iIii1I11I1II1 . i1IIi . i11iIiiIii % I1ii11iIi11i
  if 58 - 58: i11iIiiIii * i11iIiiIii - OoO0O00
  if 8 - 8: i11iIiiIii * OoOoOO00 . o0oOOo0O0Ooo
  if 27 - 27: I1ii11iIi11i + Ii1I % I1Ii111
  if 20 - 20: Oo0Ooo
class lisp_elp_node ( ) :
 def __init__ ( self ) :
  self . address = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . probe = False
  self . strict = False
  self . eid = False
  self . we_are_last = False
  if 33 - 33: oO0o - OoOoOO00 - i11iIiiIii + I1Ii111 + iIii1I11I1II1
  if 2 - 2: OoooooooOO + IiII / iII111i . iIii1I11I1II1 * OoOoOO00
 def copy_elp_node ( self ) :
  IIi1i1111i = lisp_elp_node ( )
  IIi1i1111i . copy_address ( self . address )
  IIi1i1111i . probe = self . probe
  IIi1i1111i . strict = self . strict
  IIi1i1111i . eid = self . eid
  IIi1i1111i . we_are_last = self . we_are_last
  return ( IIi1i1111i )
  if 84 - 84: OOooOOo
  if 68 - 68: I1Ii111
  if 92 - 92: oO0o * Ii1I / OoO0O00 % II111iiii
class lisp_elp ( ) :
 def __init__ ( self , name ) :
  self . elp_name = name
  self . elp_nodes = [ ]
  self . use_elp_node = None
  self . we_are_last = False
  if 54 - 54: oO0o + I11i - OoO0O00
  if 86 - 86: OoooooooOO
 def copy_elp ( self ) :
  o00oOO0 = lisp_elp ( self . elp_name )
  o00oOO0 . use_elp_node = self . use_elp_node
  o00oOO0 . we_are_last = self . we_are_last
  for IIi1i1111i in self . elp_nodes :
   o00oOO0 . elp_nodes . append ( IIi1i1111i . copy_elp_node ( ) )
   if 51 - 51: i11iIiiIii
  return ( o00oOO0 )
  if 91 - 91: OOooOOo
  if 22 - 22: OoooooooOO + OoOoOO00 - Ii1I . iII111i / OoooooooOO / I1IiiI
 def print_elp ( self , want_marker ) :
  Oo0OooO00O = ""
  for IIi1i1111i in self . elp_nodes :
   OoO00Oo0 = ""
   if ( want_marker ) :
    if ( IIi1i1111i == self . use_elp_node ) :
     OoO00Oo0 = "*"
    elif ( IIi1i1111i . we_are_last ) :
     OoO00Oo0 = "x"
     if 73 - 73: I1IiiI . iIii1I11I1II1
     if 50 - 50: OoO0O00 - O0 % OOooOOo
   Oo0OooO00O += "{}{}({}{}{}), " . format ( OoO00Oo0 ,
 IIi1i1111i . address . print_address_no_iid ( ) ,
 "r" if IIi1i1111i . eid else "R" , "P" if IIi1i1111i . probe else "p" ,
 "S" if IIi1i1111i . strict else "s" )
   if 6 - 6: Oo0Ooo
  return ( Oo0OooO00O [ 0 : - 2 ] if Oo0OooO00O != "" else "" )
  if 9 - 9: Oo0Ooo - II111iiii - i1IIi - ooOoO0o / o0oOOo0O0Ooo * I1ii11iIi11i
  if 29 - 29: ooOoO0o
 def select_elp_node ( self ) :
  oo00OOOOOO0Oo , oo0ooo0ooOOo0 , Ooooo = lisp_myrlocs
  OOOoO000 = None
  if 64 - 64: o0oOOo0O0Ooo
  for IIi1i1111i in self . elp_nodes :
   if ( oo00OOOOOO0Oo and IIi1i1111i . address . is_exact_match ( oo00OOOOOO0Oo ) ) :
    OOOoO000 = self . elp_nodes . index ( IIi1i1111i )
    break
    if 72 - 72: iIii1I11I1II1 / OoooooooOO * ooOoO0o / ooOoO0o % O0 + IiII
   if ( oo0ooo0ooOOo0 and IIi1i1111i . address . is_exact_match ( oo0ooo0ooOOo0 ) ) :
    OOOoO000 = self . elp_nodes . index ( IIi1i1111i )
    break
    if 96 - 96: iII111i / i11iIiiIii + Oo0Ooo . I1IiiI + iII111i % OoOoOO00
    if 19 - 19: i11iIiiIii . Oo0Ooo . OoOoOO00 - I1IiiI
    if 85 - 85: I11i - OoO0O00 % iIii1I11I1II1 . iII111i + ooOoO0o . Oo0Ooo
    if 87 - 87: iII111i
    if 86 - 86: IiII - I11i
    if 99 - 99: i1IIi + I1ii11iIi11i
    if 24 - 24: ooOoO0o / OoooooooOO % I1ii11iIi11i * ooOoO0o
  if ( OOOoO000 == None ) :
   self . use_elp_node = self . elp_nodes [ 0 ]
   IIi1i1111i . we_are_last = False
   return
   if 14 - 14: I1ii11iIi11i + OoO0O00 - I1IiiI - Oo0Ooo
   if 44 - 44: II111iiii / I1ii11iIi11i
   if 39 - 39: OoooooooOO % OoO0O00
   if 83 - 83: OOooOOo % I1IiiI + O0 % OoooooooOO
   if 84 - 84: I11i - Oo0Ooo % ooOoO0o - II111iiii
   if 29 - 29: IiII
  if ( self . elp_nodes [ - 1 ] == self . elp_nodes [ OOOoO000 ] ) :
   self . use_elp_node = None
   IIi1i1111i . we_are_last = True
   return
   if 4 - 4: II111iiii * o0oOOo0O0Ooo - IiII * iII111i
   if 91 - 91: I1Ii111 * iII111i * OoO0O00
   if 79 - 79: iII111i + oO0o
   if 19 - 19: I1Ii111 - OOooOOo . ooOoO0o . O0 + II111iiii . OoooooooOO
   if 97 - 97: O0 / OoOoOO00 / ooOoO0o
  self . use_elp_node = self . elp_nodes [ OOOoO000 + 1 ]
  return
  if 11 - 11: II111iiii . i11iIiiIii - Ii1I . IiII
  if 10 - 10: OOooOOo * OoooooooOO
  if 12 - 12: II111iiii - O0 . i1IIi % oO0o % OoooooooOO
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
  if 36 - 36: IiII * OoOoOO00 - iIii1I11I1II1 + II111iiii
  if 65 - 65: I1IiiI * I11i . I1Ii111 % I1ii11iIi11i + O0
 def copy_geo ( self ) :
  oOo0o0oOoo0Oo = lisp_geo ( self . geo_name )
  oOo0o0oOoo0Oo . latitude = self . latitude
  oOo0o0oOoo0Oo . lat_mins = self . lat_mins
  oOo0o0oOoo0Oo . lat_secs = self . lat_secs
  oOo0o0oOoo0Oo . longitude = self . longitude
  oOo0o0oOoo0Oo . long_mins = self . long_mins
  oOo0o0oOoo0Oo . long_secs = self . long_secs
  oOo0o0oOoo0Oo . altitude = self . altitude
  oOo0o0oOoo0Oo . radius = self . radius
  return ( oOo0o0oOoo0Oo )
  if 91 - 91: OoooooooOO % I1Ii111 * OoO0O00 - OoOoOO00
  if 5 - 5: iIii1I11I1II1 * I11i - oO0o % oO0o % o0oOOo0O0Ooo . i1IIi
 def no_geo_altitude ( self ) :
  return ( self . altitude == - 1 )
  if 95 - 95: Oo0Ooo * I1ii11iIi11i + iII111i - o0oOOo0O0Ooo - Oo0Ooo . OoO0O00
  if 62 - 62: I11i
 def parse_geo_string ( self , geo_str ) :
  OOOoO000 = geo_str . find ( "]" )
  if ( OOOoO000 != - 1 ) : geo_str = geo_str [ OOOoO000 + 1 : : ]
  if 58 - 58: I11i . OoOoOO00 + iII111i . iII111i
  if 43 - 43: I1Ii111 + I1Ii111 % Oo0Ooo % OoO0O00 - ooOoO0o
  if 61 - 61: OoOoOO00 + Ii1I % i11iIiiIii - I1IiiI * OoO0O00 % iIii1I11I1II1
  if 66 - 66: iII111i + i1IIi
  if 24 - 24: O0 / OoooooooOO - OoOoOO00
  if ( geo_str . find ( "/" ) != - 1 ) :
   geo_str , OOOO0oO = geo_str . split ( "/" )
   self . radius = int ( OOOO0oO )
   if 75 - 75: ooOoO0o . I1Ii111 * i1IIi . I1IiiI . Ii1I
   if 69 - 69: o0oOOo0O0Ooo % ooOoO0o * Ii1I * I1Ii111
  geo_str = geo_str . split ( "-" )
  if ( len ( geo_str ) < 8 ) : return ( False )
  if 59 - 59: Ii1I + Oo0Ooo % O0 % i1IIi - iII111i
  Ii1I1IiI = geo_str [ 0 : 4 ]
  IiIIII1i1Ii = geo_str [ 4 : 8 ]
  if 44 - 44: o0oOOo0O0Ooo / I1ii11iIi11i / i1IIi / Ii1I + I11i
  if 5 - 5: I1Ii111 . Ii1I - ooOoO0o % OoooooooOO
  if 2 - 2: OOooOOo . IiII . iII111i / Oo0Ooo
  if 86 - 86: OOooOOo . o0oOOo0O0Ooo - iIii1I11I1II1
  if ( len ( geo_str ) > 8 ) : self . altitude = int ( geo_str [ 8 ] )
  if 12 - 12: oO0o + iII111i
  if 16 - 16: O0 + oO0o - ooOoO0o * O0 . I1ii11iIi11i . oO0o
  if 4 - 4: I1Ii111
  if 39 - 39: OoOoOO00 - I1Ii111 / I11i + II111iiii * I1IiiI * I1IiiI
  self . latitude = int ( Ii1I1IiI [ 0 ] )
  self . lat_mins = int ( Ii1I1IiI [ 1 ] )
  self . lat_secs = int ( Ii1I1IiI [ 2 ] )
  if ( Ii1I1IiI [ 3 ] == "N" ) : self . latitude = - self . latitude
  if 9 - 9: IiII * I1IiiI * OoO0O00 - I1IiiI * I1IiiI - OoO0O00
  if 20 - 20: i1IIi + I1IiiI + i11iIiiIii + II111iiii + i1IIi
  if 18 - 18: i11iIiiIii * O0 * Oo0Ooo + iII111i + OOooOOo
  if 62 - 62: OOooOOo - oO0o + i1IIi % Ii1I . I1Ii111 . II111iiii
  self . longitude = int ( IiIIII1i1Ii [ 0 ] )
  self . long_mins = int ( IiIIII1i1Ii [ 1 ] )
  self . long_secs = int ( IiIIII1i1Ii [ 2 ] )
  if ( IiIIII1i1Ii [ 3 ] == "E" ) : self . longitude = - self . longitude
  return ( True )
  if 94 - 94: OOooOOo - I1IiiI
  if 35 - 35: i11iIiiIii
 def print_geo ( self ) :
  IiIi11IIi1 = "N" if self . latitude < 0 else "S"
  I1ii = "E" if self . longitude < 0 else "W"
  if 62 - 62: OoO0O00 * I1Ii111 * Ii1I / ooOoO0o
  i1i = "{}-{}-{}-{}-{}-{}-{}-{}" . format ( abs ( self . latitude ) ,
 self . lat_mins , self . lat_secs , IiIi11IIi1 , abs ( self . longitude ) ,
 self . long_mins , self . long_secs , I1ii )
  if 27 - 27: oO0o . iII111i . oO0o
  if ( self . no_geo_altitude ( ) == False ) :
   i1i += "-" + str ( self . altitude )
   if 37 - 37: Oo0Ooo . I1ii11iIi11i / OoooooooOO % ooOoO0o / I1IiiI + ooOoO0o
   if 14 - 14: I11i + ooOoO0o . oO0o * I11i
   if 98 - 98: Ii1I . i1IIi * OoO0O00 * Ii1I * iIii1I11I1II1
   if 22 - 22: OoooooooOO - OoO0O00 + OoOoOO00 - OOooOOo + i11iIiiIii - oO0o
   if 9 - 9: I1Ii111 - i1IIi . ooOoO0o
  if ( self . radius != 0 ) : i1i += "/{}" . format ( self . radius )
  return ( i1i )
  if 33 - 33: I11i
  if 37 - 37: Oo0Ooo
 def geo_url ( self ) :
  i11111I1111 = os . getenv ( "LISP_GEO_ZOOM_LEVEL" )
  i11111I1111 = "10" if ( i11111I1111 == "" or i11111I1111 . isdigit ( ) == False ) else i11111I1111
  oOo0OOOoOoo , OooiII11II = self . dms_to_decimal ( )
  oooooOO00O = ( "http://maps.googleapis.com/maps/api/staticmap?center={},{}" + "&markers=color:blue%7Clabel:lisp%7C{},{}" + "&zoom={}&size=1024x1024&sensor=false" ) . format ( oOo0OOOoOoo , OooiII11II , oOo0OOOoOoo , OooiII11II ,
  # II111iiii . ooOoO0o / Ii1I * o0oOOo0O0Ooo * OoOoOO00
  # OoOoOO00 / OoO0O00 % II111iiii / O0
 i11111I1111 )
  return ( oooooOO00O )
  if 35 - 35: i11iIiiIii % OoooooooOO % OoooooooOO + i1IIi
  if 13 - 13: o0oOOo0O0Ooo / i1IIi
 def print_geo_url ( self ) :
  oOo0o0oOoo0Oo = self . print_geo ( )
  if ( self . radius == 0 ) :
   oooooOO00O = self . geo_url ( )
   oo0OooO = "<a href='{}'>{}</a>" . format ( oooooOO00O , oOo0o0oOoo0Oo )
  else :
   oooooOO00O = oOo0o0oOoo0Oo . replace ( "/" , "-" )
   oo0OooO = "<a href='/lisp/geo-map/{}'>{}</a>" . format ( oooooOO00O , oOo0o0oOoo0Oo )
   if 73 - 73: ooOoO0o
  return ( oo0OooO )
  if 37 - 37: OOooOOo % OoOoOO00 - II111iiii * o0oOOo0O0Ooo . I1IiiI . OoOoOO00
  if 92 - 92: I11i + OoO0O00 . OoooooooOO
 def dms_to_decimal ( self ) :
  iIiIi1iIIii , I1iiIii11Ii , IIo0 = self . latitude , self . lat_mins , self . lat_secs
  I1OOoO = float ( abs ( iIiIi1iIIii ) )
  I1OOoO += float ( I1iiIii11Ii * 60 + IIo0 ) / 3600
  if ( iIiIi1iIIii > 0 ) : I1OOoO = - I1OOoO
  I1i1Iii = I1OOoO
  if 2 - 2: OoOoOO00 / Ii1I - iII111i * Ii1I - iII111i
  iIiIi1iIIii , I1iiIii11Ii , IIo0 = self . longitude , self . long_mins , self . long_secs
  I1OOoO = float ( abs ( iIiIi1iIIii ) )
  I1OOoO += float ( I1iiIii11Ii * 60 + IIo0 ) / 3600
  if ( iIiIi1iIIii > 0 ) : I1OOoO = - I1OOoO
  o00ooOooooo = I1OOoO
  return ( ( I1i1Iii , o00ooOooooo ) )
  if 65 - 65: i1IIi . iIii1I11I1II1 % iIii1I11I1II1
  if 35 - 35: iIii1I11I1II1 - o0oOOo0O0Ooo + I1ii11iIi11i * iII111i - OOooOOo . o0oOOo0O0Ooo
 def get_distance ( self , geo_point ) :
  ii1IIi1I11i = self . dms_to_decimal ( )
  ii11ii11iiI = geo_point . dms_to_decimal ( )
  OoIIi11111 = vincenty ( ii1IIi1I11i , ii11ii11iiI )
  return ( OoIIi11111 . km )
  if 55 - 55: O0 - I1Ii111 / OoooooooOO - iII111i
  if 83 - 83: OOooOOo * I1ii11iIi11i * iII111i * I1ii11iIi11i . OoO0O00
 def point_in_circle ( self , geo_point ) :
  o0o0oOo00Oo = self . get_distance ( geo_point )
  return ( o0o0oOo00Oo <= self . radius )
  if 94 - 94: ooOoO0o / Ii1I
  if 9 - 9: I1Ii111 * oO0o
 def encode_geo ( self ) :
  O0OOOOO0O = socket . htons ( LISP_AFI_LCAF )
  IiIIi1IIii = socket . htons ( 20 + 2 )
  Ooooo0OO = 0
  if 44 - 44: ooOoO0o * oO0o
  oOo0OOOoOoo = abs ( self . latitude )
  Ooii111IIi1ii1 = ( ( self . lat_mins * 60 ) + self . lat_secs ) * 1000
  if ( self . latitude < 0 ) : Ooooo0OO |= 0x40
  if 33 - 33: i1IIi . Oo0Ooo + iIii1I11I1II1 / i1IIi
  OooiII11II = abs ( self . longitude )
  i111I = ( ( self . long_mins * 60 ) + self . long_secs ) * 1000
  if ( self . longitude < 0 ) : Ooooo0OO |= 0x20
  if 6 - 6: iIii1I11I1II1
  oooi11iI = 0
  if ( self . no_geo_altitude ( ) == False ) :
   oooi11iI = socket . htonl ( self . altitude )
   Ooooo0OO |= 0x10
   if 61 - 61: I1ii11iIi11i . OOooOOo - O0 * OoOoOO00
  OOOO0oO = socket . htons ( self . radius )
  if ( OOOO0oO != 0 ) : Ooooo0OO |= 0x06
  if 12 - 12: I1ii11iIi11i / I1Ii111
  II1I = struct . pack ( "HBBBBH" , O0OOOOO0O , 0 , 0 , LISP_LCAF_GEO_COORD_TYPE ,
 0 , IiIIi1IIii )
  II1I += struct . pack ( "BBHBBHBBHIHHH" , Ooooo0OO , 0 , 0 , oOo0OOOoOoo , Ooii111IIi1ii1 >> 16 ,
 socket . htons ( Ooii111IIi1ii1 & 0x0ffff ) , OooiII11II , i111I >> 16 ,
 socket . htons ( i111I & 0xffff ) , oooi11iI , OOOO0oO , 0 , 0 )
  if 60 - 60: ooOoO0o
  return ( II1I )
  if 62 - 62: i11iIiiIii
  if 88 - 88: i11iIiiIii
 def decode_geo ( self , packet , lcaf_len , radius_hi ) :
  oOO0OOOoO0ooo = "BBHBBHBBHIHHH"
  I1111ii1i = struct . calcsize ( oOO0OOOoO0ooo )
  if ( lcaf_len < I1111ii1i ) : return ( None )
  if 59 - 59: oO0o - OoooooooOO % ooOoO0o
  Ooooo0OO , o0o0o00 , iI1III , oOo0OOOoOoo , iiIIIi , Ooii111IIi1ii1 , OooiII11II , O0oOoOOOO , i111I , oooi11iI , OOOO0oO , OO0 , ooOooOooOOO = struct . unpack ( oOO0OOOoO0ooo ,
  # I1IiiI % ooOoO0o * II111iiii
 packet [ : I1111ii1i ] )
  if 47 - 47: Ii1I % o0oOOo0O0Ooo + i11iIiiIii % oO0o
  if 80 - 80: ooOoO0o * OOooOOo % O0 / oO0o + i1IIi
  if 50 - 50: I11i . ooOoO0o . I1IiiI / iIii1I11I1II1 - oO0o
  if 72 - 72: I11i . O0 + O0 + i11iIiiIii
  ooOooOooOOO = socket . ntohs ( ooOooOooOOO )
  if ( ooOooOooOOO == LISP_AFI_LCAF ) : return ( None )
  if 100 - 100: II111iiii / Ii1I + i11iIiiIii % OOooOOo / ooOoO0o . oO0o
  if ( Ooooo0OO & 0x40 ) : oOo0OOOoOoo = - oOo0OOOoOoo
  self . latitude = oOo0OOOoOoo
  oOoiI1IIiI1i11Ii = ( ( iiIIIi << 16 ) | socket . ntohs ( Ooii111IIi1ii1 ) ) / 1000
  self . lat_mins = oOoiI1IIiI1i11Ii / 60
  self . lat_secs = oOoiI1IIiI1i11Ii % 60
  if 70 - 70: I1IiiI . I1IiiI - OoooooooOO - I11i
  if ( Ooooo0OO & 0x20 ) : OooiII11II = - OooiII11II
  self . longitude = OooiII11II
  Ii1I111 = ( ( O0oOoOOOO << 16 ) | socket . ntohs ( i111I ) ) / 1000
  self . long_mins = Ii1I111 / 60
  self . long_secs = Ii1I111 % 60
  if 80 - 80: OOooOOo % OoO0O00 + OoOoOO00 % iII111i % OoooooooOO - ooOoO0o
  self . altitude = socket . ntohl ( oooi11iI ) if ( Ooooo0OO & 0x10 ) else - 1
  OOOO0oO = socket . ntohs ( OOOO0oO )
  self . radius = OOOO0oO if ( Ooooo0OO & 0x02 ) else OOOO0oO * 1000
  if 25 - 25: OoOoOO00 % i11iIiiIii - I1IiiI * iIii1I11I1II1 - Oo0Ooo . O0
  self . geo_name = None
  packet = packet [ I1111ii1i : : ]
  if 48 - 48: I1IiiI + oO0o % i11iIiiIii % iIii1I11I1II1
  if ( ooOooOooOOO != 0 ) :
   self . rloc . afi = ooOooOooOOO
   packet = self . rloc . unpack_address ( packet )
   self . rloc . mask_len = self . rloc . host_mask_len ( )
   if 14 - 14: iIii1I11I1II1
  return ( packet )
  if 78 - 78: I1Ii111 / Oo0Ooo - I1Ii111
  if 1 - 1: OoO0O00 - I1IiiI * o0oOOo0O0Ooo
  if 84 - 84: OoO0O00 % OoooooooOO
  if 66 - 66: OoOoOO00 . iII111i
  if 1 - 1: iII111i * i1IIi . iIii1I11I1II1 % O0 - OoooooooOO
  if 87 - 87: iII111i . Oo0Ooo * i11iIiiIii % o0oOOo0O0Ooo + Ii1I
class lisp_rle_node ( ) :
 def __init__ ( self ) :
  self . address = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . level = 0
  self . translated_port = 0
  self . rloc_name = None
  if 72 - 72: Ii1I / II111iiii + o0oOOo0O0Ooo
  if 33 - 33: I1Ii111 * OoOoOO00 - OoooooooOO
 def copy_rle_node ( self ) :
  i1ooOoO = lisp_rle_node ( )
  i1ooOoO . address . copy_address ( self . address )
  i1ooOoO . level = self . level
  i1ooOoO . translated_port = self . translated_port
  i1ooOoO . rloc_name = self . rloc_name
  return ( i1ooOoO )
  if 11 - 11: I1Ii111 - Oo0Ooo / iIii1I11I1II1 - OoooooooOO
  if 71 - 71: Oo0Ooo + Ii1I - OoooooooOO + I11i - iIii1I11I1II1 / O0
 def store_translated_rloc ( self , rloc , port ) :
  self . address . copy_address ( rloc )
  self . translated_port = port
  if 76 - 76: i11iIiiIii % o0oOOo0O0Ooo . O0 * I11i
  if 90 - 90: II111iiii + OOooOOo % I1Ii111 * iIii1I11I1II1 % iIii1I11I1II1
 def get_encap_keys ( self ) :
  OOo0000o0 = "4341" if self . translated_port == 0 else str ( self . translated_port )
  if 55 - 55: II111iiii % O0 * O0 - II111iiii * I1IiiI % Oo0Ooo
  OoOOoooO000 = self . address . print_address_no_iid ( ) + ":" + OOo0000o0
  if 48 - 48: I1ii11iIi11i + OoooooooOO % i1IIi
  try :
   II1i = lisp_crypto_keys_by_rloc_encap [ OoOOoooO000 ]
   if ( II1i [ 1 ] ) : return ( II1i [ 1 ] . encrypt_key , II1i [ 1 ] . icv_key )
   return ( None , None )
  except :
   return ( None , None )
   if 46 - 46: OoOoOO00
   if 75 - 75: I1IiiI
   if 37 - 37: iIii1I11I1II1 % OoO0O00 * ooOoO0o + I11i % ooOoO0o / i11iIiiIii
   if 14 - 14: i1IIi / ooOoO0o
class lisp_rle ( ) :
 def __init__ ( self , name ) :
  self . rle_name = name
  self . rle_nodes = [ ]
  self . rle_forwarding_list = [ ]
  if 10 - 10: ooOoO0o / OoooooooOO - ooOoO0o % O0 + oO0o - oO0o
  if 16 - 16: O0
 def copy_rle ( self ) :
  O0OOOO0000O = lisp_rle ( self . rle_name )
  for i1ooOoO in self . rle_nodes :
   O0OOOO0000O . rle_nodes . append ( i1ooOoO . copy_rle_node ( ) )
   if 14 - 14: Ii1I . Ii1I . OOooOOo - O0 / OoO0O00 % II111iiii
  O0OOOO0000O . build_forwarding_list ( )
  return ( O0OOOO0000O )
  if 5 - 5: iIii1I11I1II1 % OoOoOO00 % OOooOOo % O0 * oO0o . iIii1I11I1II1
  if 96 - 96: i11iIiiIii + oO0o / I1ii11iIi11i . IiII % o0oOOo0O0Ooo
 def print_rle ( self , html ) :
  IiIiII = ""
  for i1ooOoO in self . rle_nodes :
   OOo0000o0 = i1ooOoO . translated_port
   iIooO0O000oO = blue ( i1ooOoO . rloc_name , html ) if i1ooOoO . rloc_name != None else ""
   if 22 - 22: o0oOOo0O0Ooo - I1Ii111
   OoOOoooO000 = i1ooOoO . address . print_address_no_iid ( )
   if ( i1ooOoO . address . is_local ( ) ) : OoOOoooO000 = red ( OoOOoooO000 , html )
   IiIiII += "{}{}(L{}){}, " . format ( OoOOoooO000 , "" if OOo0000o0 == 0 else "-" + str ( OOo0000o0 ) , i1ooOoO . level ,
   # I1ii11iIi11i * OoO0O00 % OoOoOO00
 "" if i1ooOoO . rloc_name == None else iIooO0O000oO )
   if 80 - 80: Oo0Ooo / I1ii11iIi11i
  return ( IiIiII [ 0 : - 2 ] if IiIiII != "" else "" )
  if 17 - 17: i1IIi / IiII . I1IiiI % i1IIi
  if 46 - 46: IiII % O0 . o0oOOo0O0Ooo . OOooOOo
 def build_forwarding_list ( self ) :
  II1II = - 1
  for i1ooOoO in self . rle_nodes :
   if ( II1II == - 1 ) :
    if ( i1ooOoO . address . is_local ( ) ) : II1II = i1ooOoO . level
   else :
    if ( i1ooOoO . level > II1II ) : break
    if 47 - 47: OoooooooOO . oO0o . II111iiii / II111iiii - OoOoOO00
    if 81 - 81: o0oOOo0O0Ooo - Oo0Ooo % IiII - ooOoO0o / O0
  II1II = 0 if II1II == - 1 else i1ooOoO . level
  if 27 - 27: Oo0Ooo
  self . rle_forwarding_list = [ ]
  for i1ooOoO in self . rle_nodes :
   if ( i1ooOoO . level == II1II or ( II1II == 0 and
 i1ooOoO . level == 128 ) ) :
    if ( lisp_i_am_rtr == False and i1ooOoO . address . is_local ( ) ) :
     OoOOoooO000 = i1ooOoO . address . print_address_no_iid ( )
     lprint ( "Exclude local RLE RLOC {}" . format ( OoOOoooO000 ) )
     continue
     if 15 - 15: iIii1I11I1II1 . OoOoOO00 % Ii1I / i1IIi . o0oOOo0O0Ooo
    self . rle_forwarding_list . append ( i1ooOoO )
    if 45 - 45: iIii1I11I1II1 - i1IIi % I1IiiI - I1Ii111 + oO0o
    if 15 - 15: iIii1I11I1II1 - OoooooooOO / ooOoO0o
    if 83 - 83: IiII + I1Ii111 / OoOoOO00 * IiII . oO0o
    if 22 - 22: O0 + ooOoO0o + I1Ii111
    if 57 - 57: OOooOOo . ooOoO0o - OoooooooOO - I1ii11iIi11i * O0
class lisp_json ( ) :
 def __init__ ( self , name , string ) :
  self . json_name = name
  self . json_string = string
  if 85 - 85: I1IiiI * OoO0O00
  if 63 - 63: I1IiiI - i11iIiiIii
 def add ( self ) :
  self . delete ( )
  lisp_json_list [ self . json_name ] = self
  if 4 - 4: OOooOOo + iIii1I11I1II1 / I1IiiI * Ii1I
  if 64 - 64: OoOoOO00
 def delete ( self ) :
  if ( lisp_json_list . has_key ( self . json_name ) ) :
   del ( lisp_json_list [ self . json_name ] )
   lisp_json_list [ self . json_name ] = None
   if 94 - 94: OOooOOo * OoooooooOO * o0oOOo0O0Ooo / I1Ii111 . II111iiii
   if 37 - 37: O0 * II111iiii * I1IiiI - O0 - I11i / i1IIi
   if 27 - 27: i11iIiiIii + iIii1I11I1II1
 def print_json ( self , html ) :
  i1I1iii11 = self . json_string
  o0o0Oo = "***"
  if ( html ) : o0o0Oo = red ( o0o0Oo , html )
  oO0oOo0o = o0o0Oo + self . json_string + o0o0Oo
  if ( self . valid_json ( ) ) : return ( i1I1iii11 )
  return ( oO0oOo0o )
  if 4 - 4: IiII * OoO0O00 % I1ii11iIi11i * Ii1I . iII111i
  if 41 - 41: OoooooooOO % I11i . O0 + I1Ii111
 def valid_json ( self ) :
  try :
   json . loads ( self . json_string )
  except :
   return ( False )
   if 67 - 67: OoOoOO00 * OOooOOo / OOooOOo / OoooooooOO
  return ( True )
  if 67 - 67: I11i - i1IIi . OoooooooOO / iIii1I11I1II1
  if 34 - 34: OoO0O00 * II111iiii
  if 43 - 43: OoOoOO00 . I1IiiI
  if 44 - 44: O0 / o0oOOo0O0Ooo
  if 19 - 19: I11i
  if 91 - 91: OOooOOo * OoooooooOO
class lisp_stats ( ) :
 def __init__ ( self ) :
  self . packet_count = 0
  self . byte_count = 0
  self . last_rate_check = 0
  self . last_packet_count = 0
  self . last_byte_count = 0
  self . last_increment = None
  if 89 - 89: i1IIi / iII111i . I1Ii111
  if 74 - 74: I1ii11iIi11i % iII111i / OoooooooOO / I1ii11iIi11i % i11iIiiIii % ooOoO0o
 def increment ( self , octets ) :
  self . packet_count += 1
  self . byte_count += octets
  self . last_increment = lisp_get_timestamp ( )
  if 82 - 82: OoooooooOO . o0oOOo0O0Ooo * I1ii11iIi11i % I1ii11iIi11i * Ii1I
  if 83 - 83: I11i - Oo0Ooo + i11iIiiIii - i11iIiiIii
 def recent_packet_sec ( self ) :
  if ( self . last_increment == None ) : return ( False )
  ooooOoO0O = time . time ( ) - self . last_increment
  return ( ooooOoO0O <= 1 )
  if 64 - 64: IiII % I1IiiI / ooOoO0o
  if 74 - 74: OoooooooOO
 def recent_packet_min ( self ) :
  if ( self . last_increment == None ) : return ( False )
  ooooOoO0O = time . time ( ) - self . last_increment
  return ( ooooOoO0O <= 60 )
  if 22 - 22: II111iiii . O0 * I1Ii111 % OoO0O00 / OoooooooOO + I1Ii111
  if 71 - 71: ooOoO0o . oO0o * OoooooooOO + iII111i - I1Ii111 . I1ii11iIi11i
 def stat_colors ( self , c1 , c2 , html ) :
  if ( self . recent_packet_sec ( ) ) :
   return ( green_last_sec ( c1 ) , green_last_sec ( c2 ) )
   if 100 - 100: I11i + O0 - o0oOOo0O0Ooo * I1ii11iIi11i
  if ( self . recent_packet_min ( ) ) :
   return ( green_last_min ( c1 ) , green_last_min ( c2 ) )
   if 94 - 94: Oo0Ooo . IiII / Ii1I / oO0o - I1IiiI
  return ( c1 , c2 )
  if 77 - 77: i11iIiiIii . Ii1I - Ii1I
  if 47 - 47: iII111i % OOooOOo . I1ii11iIi11i + I1ii11iIi11i . I1Ii111
 def normalize ( self , count ) :
  count = str ( count )
  IIII1iII = len ( count )
  if ( IIII1iII > 12 ) :
   count = count [ 0 : - 10 ] + "." + count [ - 10 : - 7 ] + "T"
   return ( count )
   if 24 - 24: oO0o
  if ( IIII1iII > 9 ) :
   count = count [ 0 : - 9 ] + "." + count [ - 9 : - 7 ] + "B"
   return ( count )
   if 98 - 98: oO0o + iIii1I11I1II1 . ooOoO0o / I1ii11iIi11i
  if ( IIII1iII > 6 ) :
   count = count [ 0 : - 6 ] + "." + count [ - 6 ] + "M"
   return ( count )
   if 77 - 77: OoOoOO00 / Oo0Ooo * OoOoOO00 % I1IiiI . II111iiii % OoO0O00
  return ( count )
  if 38 - 38: iII111i - OoO0O00 / i1IIi + ooOoO0o . ooOoO0o . iII111i
  if 37 - 37: iIii1I11I1II1 * OoOoOO00 . OoOoOO00 + OoooooooOO + OoO0O00
 def get_stats ( self , summary , html ) :
  Iii1IIiii1iii1i = self . last_rate_check
  iiI11 = self . last_packet_count
  o00oOooo0 = self . last_byte_count
  self . last_rate_check = lisp_get_timestamp ( )
  self . last_packet_count = self . packet_count
  self . last_byte_count = self . byte_count
  if 54 - 54: I11i % o0oOOo0O0Ooo
  iIIIii1ii = self . last_rate_check - Iii1IIiii1iii1i
  if ( iIIIii1ii == 0 ) :
   Ooo0oOO = 0
   I1Ii111Oo00o0o = 0
  else :
   Ooo0oOO = int ( ( self . packet_count - iiI11 ) / iIIIii1ii )
   I1Ii111Oo00o0o = ( self . byte_count - o00oOooo0 ) / iIIIii1ii
   I1Ii111Oo00o0o = ( I1Ii111Oo00o0o * 8 ) / 1000000
   I1Ii111Oo00o0o = round ( I1Ii111Oo00o0o , 2 )
   if 74 - 74: I1Ii111 - i11iIiiIii * OoooooooOO
   if 90 - 90: i1IIi
   if 52 - 52: IiII + ooOoO0o - II111iiii - OoooooooOO * OoO0O00 - iIii1I11I1II1
   if 38 - 38: II111iiii % iIii1I11I1II1 * IiII * OoOoOO00 % II111iiii . I1IiiI
   if 35 - 35: OoooooooOO - i11iIiiIii * i11iIiiIii % Ii1I - OOooOOo . iIii1I11I1II1
  ooOoO0OOOO = self . normalize ( self . packet_count )
  I1i = self . normalize ( self . byte_count )
  if 52 - 52: oO0o
  if 21 - 21: iII111i % I1Ii111 % iIii1I11I1II1 % iIii1I11I1II1 . iIii1I11I1II1 / O0
  if 77 - 77: i1IIi . oO0o - O0
  if 76 - 76: o0oOOo0O0Ooo - ooOoO0o % OOooOOo . OoooooooOO
  if 18 - 18: Ii1I / iIii1I11I1II1 * OoO0O00 - I11i . OoO0O00 % iIii1I11I1II1
  if ( summary ) :
   oO0o00ooO = "<br>" if html else ""
   ooOoO0OOOO , I1i = self . stat_colors ( ooOoO0OOOO , I1i , html )
   oO0 = "packet-count: {}{}byte-count: {}" . format ( ooOoO0OOOO , oO0o00ooO , I1i )
   oO000O0oooOo = "packet-rate: {} pps\nbit-rate: {} Mbps" . format ( Ooo0oOO , I1Ii111Oo00o0o )
   if 88 - 88: I1Ii111 * ooOoO0o - Ii1I % OoooooooOO . OOooOOo + OoOoOO00
   if ( html != "" ) : oO000O0oooOo = lisp_span ( oO0 , oO000O0oooOo )
  else :
   i1II1Iii = str ( Ooo0oOO )
   O0OoOOo0O00O = str ( I1Ii111Oo00o0o )
   if ( html ) :
    ooOoO0OOOO = lisp_print_cour ( ooOoO0OOOO )
    i1II1Iii = lisp_print_cour ( i1II1Iii )
    I1i = lisp_print_cour ( I1i )
    O0OoOOo0O00O = lisp_print_cour ( O0OoOOo0O00O )
    if 77 - 77: o0oOOo0O0Ooo + ooOoO0o * I1Ii111 % iII111i / I1IiiI / i1IIi
   oO0o00ooO = "<br>" if html else ", "
   if 22 - 22: i11iIiiIii - I11i / I1ii11iIi11i * Ii1I * O0
   oO000O0oooOo = ( "packet-count: {}{}packet-rate: {} pps{}byte-count: " + "{}{}bit-rate: {} mbps" ) . format ( ooOoO0OOOO , oO0o00ooO , i1II1Iii , oO0o00ooO , I1i , oO0o00ooO ,
   # OOooOOo % Ii1I + ooOoO0o
 O0OoOOo0O00O )
   if 17 - 17: iIii1I11I1II1 * I1Ii111 % oO0o + o0oOOo0O0Ooo . Ii1I * Oo0Ooo
  return ( oO000O0oooOo )
  if 16 - 16: I1IiiI % OoO0O00 . ooOoO0o / OoooooooOO
  if 8 - 8: I1Ii111 % OoO0O00 . I1IiiI - OoOoOO00 + i1IIi / iIii1I11I1II1
  if 89 - 89: II111iiii / Ii1I % Ii1I
  if 57 - 57: I11i
  if 95 - 95: OoOoOO00 + I11i * i1IIi - ooOoO0o % ooOoO0o
  if 58 - 58: OOooOOo
  if 74 - 74: i1IIi . IiII / ooOoO0o + I11i % i11iIiiIii % iII111i
  if 62 - 62: i1IIi % I1Ii111
lisp_decap_stats = {
 "good-packets" : lisp_stats ( ) , "ICV-error" : lisp_stats ( ) ,
 "checksum-error" : lisp_stats ( ) , "lisp-header-error" : lisp_stats ( ) ,
 "no-decrypt-key" : lisp_stats ( ) , "bad-inner-version" : lisp_stats ( ) ,
 "outer-header-error" : lisp_stats ( )
 }
if 94 - 94: i1IIi + iII111i
if 25 - 25: I1Ii111 . Ii1I - Ii1I . o0oOOo0O0Ooo - IiII
if 91 - 91: o0oOOo0O0Ooo % I1ii11iIi11i % OoOoOO00 * iIii1I11I1II1
if 18 - 18: OoOoOO00 * I1ii11iIi11i . i1IIi * iII111i
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
  if 67 - 67: IiII + i11iIiiIii . II111iiii / OoOoOO00 + OoooooooOO + i11iIiiIii
  if ( recurse == False ) : return
  if 23 - 23: Oo0Ooo
  if 7 - 7: Oo0Ooo / oO0o . I1Ii111 % I11i
  if 85 - 85: II111iiii / o0oOOo0O0Ooo . iIii1I11I1II1 . OoooooooOO / Ii1I
  if 18 - 18: i11iIiiIii + o0oOOo0O0Ooo . i11iIiiIii
  if 50 - 50: IiII / OoooooooOO . I11i
  if 93 - 93: OOooOOo / OoooooooOO % iII111i % Ii1I / I1Ii111 % OOooOOo
  IiiI1iiI11 = lisp_get_default_route_next_hops ( )
  if ( IiiI1iiI11 == [ ] or len ( IiiI1iiI11 ) == 1 ) : return
  if 44 - 44: OOooOOo + II111iiii - i11iIiiIii
  self . rloc_next_hop = IiiI1iiI11 [ 0 ]
  O0oo00o000 = self
  for I1i1i1iIIiI11 in IiiI1iiI11 [ 1 : : ] :
   oo00OO0 = lisp_rloc ( False )
   oo00OO0 = copy . deepcopy ( self )
   oo00OO0 . rloc_next_hop = I1i1i1iIIiI11
   O0oo00o000 . next_rloc = oo00OO0
   O0oo00o000 = oo00OO0
   if 49 - 49: I1IiiI % Ii1I
   if 60 - 60: I1Ii111 * i11iIiiIii . iII111i . i1IIi + ooOoO0o * o0oOOo0O0Ooo
   if 99 - 99: oO0o / o0oOOo0O0Ooo . i11iIiiIii % OoooooooOO * O0
 def up_state ( self ) :
  return ( self . state == LISP_RLOC_UP_STATE )
  if 52 - 52: OOooOOo / ooOoO0o . II111iiii / Oo0Ooo
  if 66 - 66: Ii1I * I1Ii111 * OoO0O00
 def unreach_state ( self ) :
  return ( self . state == LISP_RLOC_UNREACH_STATE )
  if 92 - 92: II111iiii * iII111i % OoOoOO00 % OoOoOO00 % i11iIiiIii
  if 93 - 93: Ii1I + iIii1I11I1II1 % Ii1I . iIii1I11I1II1
 def no_echoed_nonce_state ( self ) :
  return ( self . state == LISP_RLOC_NO_ECHOED_NONCE_STATE )
  if 48 - 48: OoooooooOO - O0 + I1IiiI - I11i
  if 86 - 86: i11iIiiIii / IiII + i11iIiiIii + o0oOOo0O0Ooo . I1Ii111 . I1Ii111
 def down_state ( self ) :
  return ( self . state in [ LISP_RLOC_DOWN_STATE , LISP_RLOC_ADMIN_DOWN_STATE ] )
  if 90 - 90: ooOoO0o % Ii1I
  if 12 - 12: OoooooooOO . OoooooooOO * I11i
  if 76 - 76: OoooooooOO - Ii1I + IiII % OoOoOO00 / OoooooooOO
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
  if 55 - 55: i11iIiiIii - IiII * OOooOOo + II111iiii . I1ii11iIi11i / O0
  if 16 - 16: II111iiii . Oo0Ooo * I1Ii111 + o0oOOo0O0Ooo - i11iIiiIii
 def print_rloc ( self , indent ) :
  III11I1 = lisp_print_elapsed ( self . uptime )
  lprint ( "{}rloc {}, uptime {}, {}, parms {}/{}/{}/{}" . format ( indent ,
 red ( self . rloc . print_address ( ) , False ) , III11I1 , self . print_state ( ) ,
 self . priority , self . weight , self . mpriority , self . mweight ) )
  if 98 - 98: II111iiii - i1IIi - ooOoO0o
  if 36 - 36: IiII + o0oOOo0O0Ooo
 def print_rloc_name ( self , cour = False ) :
  if ( self . rloc_name == None ) : return ( "" )
  O0O00O = self . rloc_name
  if ( cour ) : O0O00O = lisp_print_cour ( O0O00O )
  return ( 'rloc-name: {}' . format ( blue ( O0O00O , cour ) ) )
  if 81 - 81: OOooOOo / I11i % oO0o + ooOoO0o
  if 10 - 10: oO0o / i11iIiiIii
 def store_rloc_from_record ( self , rloc_record , nonce , source ) :
  OOo0000o0 = LISP_DATA_PORT
  self . rloc . copy_address ( rloc_record . rloc )
  self . rloc_name = rloc_record . rloc_name
  if 73 - 73: OoO0O00 - i1IIi
  if 52 - 52: I1ii11iIi11i
  if 4 - 4: Ii1I - iII111i + i1IIi - I1Ii111 / iII111i . Oo0Ooo
  if 18 - 18: oO0o % iIii1I11I1II1 + ooOoO0o
  i1IIIIi1Ii111 = self . rloc
  if ( i1IIIIi1Ii111 . is_null ( ) == False ) :
   IiiiI11I1 = lisp_get_nat_info ( i1IIIIi1Ii111 , self . rloc_name )
   if ( IiiiI11I1 ) :
    OOo0000o0 = IiiiI11I1 . port
    i11IIi = lisp_nat_state_info [ self . rloc_name ] [ 0 ]
    OoOOoooO000 = i1IIIIi1Ii111 . print_address_no_iid ( )
    I111I = red ( OoOOoooO000 , False )
    IiiiI1i = "" if self . rloc_name == None else blue ( self . rloc_name , False )
    if 62 - 62: OoooooooOO + OoO0O00 . IiII
    if 41 - 41: OoooooooOO + oO0o % oO0o / I1ii11iIi11i
    if 86 - 86: i1IIi
    if 73 - 73: iIii1I11I1II1 * Oo0Ooo
    if 54 - 54: oO0o . Ii1I
    if 31 - 31: I11i
    if ( IiiiI11I1 . timed_out ( ) ) :
     lprint ( ( "    Matched stored NAT state timed out for " + "RLOC {}:{}, {}" ) . format ( I111I , OOo0000o0 , IiiiI1i ) )
     if 60 - 60: Oo0Ooo - iII111i . II111iiii % ooOoO0o / OoooooooOO / iIii1I11I1II1
     if 23 - 23: I11i + iIii1I11I1II1
     IiiiI11I1 = None if ( IiiiI11I1 == i11IIi ) else i11IIi
     if ( IiiiI11I1 and IiiiI11I1 . timed_out ( ) ) :
      OOo0000o0 = IiiiI11I1 . port
      I111I = red ( IiiiI11I1 . address , False )
      lprint ( ( "    Youngest stored NAT state timed out " + " for RLOC {}:{}, {}" ) . format ( I111I , OOo0000o0 ,
      # I1Ii111 * OoOoOO00 . I1Ii111 / o0oOOo0O0Ooo
 IiiiI1i ) )
      IiiiI11I1 = None
      if 41 - 41: o0oOOo0O0Ooo / o0oOOo0O0Ooo . Oo0Ooo
      if 4 - 4: I1Ii111
      if 85 - 85: iIii1I11I1II1 % Oo0Ooo
      if 20 - 20: IiII + i11iIiiIii * OOooOOo
      if 27 - 27: O0 * OoO0O00 * I1ii11iIi11i
      if 40 - 40: O0 + oO0o - ooOoO0o + I1IiiI - IiII
      if 60 - 60: I1Ii111 * OoO0O00 * oO0o + oO0o
    if ( IiiiI11I1 ) :
     if ( IiiiI11I1 . address != OoOOoooO000 ) :
      lprint ( "RLOC conflict, RLOC-record {}, NAT state {}" . format ( I111I , red ( IiiiI11I1 . address , False ) ) )
      if 34 - 34: o0oOOo0O0Ooo
      self . rloc . store_address ( IiiiI11I1 . address )
      if 76 - 76: oO0o + OoooooooOO % OoOoOO00 / OoOoOO00
     I111I = red ( IiiiI11I1 . address , False )
     OOo0000o0 = IiiiI11I1 . port
     lprint ( "    Use NAT translated RLOC {}:{} for {}" . format ( I111I , OOo0000o0 , IiiiI1i ) )
     if 51 - 51: II111iiii / OoOoOO00
     self . store_translated_rloc ( i1IIIIi1Ii111 , OOo0000o0 )
     if 69 - 69: i11iIiiIii
     if 77 - 77: I1ii11iIi11i % OoooooooOO - Oo0Ooo - Ii1I + I11i
     if 93 - 93: I1IiiI % O0 * OoO0O00 % OoOoOO00 . I1Ii111 * I1IiiI
     if 95 - 95: IiII + o0oOOo0O0Ooo - o0oOOo0O0Ooo
  self . geo = rloc_record . geo
  self . elp = rloc_record . elp
  self . json = rloc_record . json
  if 83 - 83: ooOoO0o
  if 59 - 59: I1ii11iIi11i
  if 26 - 26: I11i . Ii1I
  if 94 - 94: ooOoO0o . I1IiiI + IiII % I1IiiI / o0oOOo0O0Ooo % o0oOOo0O0Ooo
  self . rle = rloc_record . rle
  if ( self . rle ) :
   for i1ooOoO in self . rle . rle_nodes :
    O0O00O = i1ooOoO . rloc_name
    IiiiI11I1 = lisp_get_nat_info ( i1ooOoO . address , O0O00O )
    if ( IiiiI11I1 == None ) : continue
    if 21 - 21: O0 / OOooOOo - II111iiii + I1ii11iIi11i / OoooooooOO
    OOo0000o0 = IiiiI11I1 . port
    Ooo000oo0OO0 = O0O00O
    if ( Ooo000oo0OO0 ) : Ooo000oo0OO0 = blue ( O0O00O , False )
    if 81 - 81: i11iIiiIii / Oo0Ooo * i1IIi + OoO0O00 + O0 % I1ii11iIi11i
    lprint ( ( "      Store translated encap-port {} for RLE-" + "node {}, rloc-name '{}'" ) . format ( OOo0000o0 ,
    # iII111i
 i1ooOoO . address . print_address_no_iid ( ) , Ooo000oo0OO0 ) )
    i1ooOoO . translated_port = OOo0000o0
    if 94 - 94: i11iIiiIii
    if 90 - 90: iII111i + i11iIiiIii + iII111i % I1IiiI % oO0o
    if 71 - 71: ooOoO0o + OOooOOo * I1IiiI % I11i . I1Ii111 % OoooooooOO
  self . priority = rloc_record . priority
  self . mpriority = rloc_record . mpriority
  self . weight = rloc_record . weight
  self . mweight = rloc_record . mweight
  if ( rloc_record . reach_bit and rloc_record . local_bit and
 rloc_record . probe_bit == False ) : self . state = LISP_RLOC_UP_STATE
  if 7 - 7: iIii1I11I1II1
  if 88 - 88: ooOoO0o
  if 37 - 37: ooOoO0o * OoOoOO00 . ooOoO0o
  if 47 - 47: iIii1I11I1II1 + iIii1I11I1II1 / Ii1I
  I11II1iiIIIIiI = source . is_exact_match ( rloc_record . rloc ) if source != None else None
  if 76 - 76: iIii1I11I1II1 . iIii1I11I1II1 / OOooOOo / OoOoOO00 / iII111i / II111iiii
  if ( rloc_record . keys != None and I11II1iiIIIIiI ) :
   i1IIiI1iII = rloc_record . keys [ 1 ]
   if ( i1IIiI1iII != None ) :
    OoOOoooO000 = rloc_record . rloc . print_address_no_iid ( ) + ":" + str ( OOo0000o0 )
    if 64 - 64: i1IIi * II111iiii + I1ii11iIi11i + OOooOOo % I1ii11iIi11i - OoooooooOO
    i1IIiI1iII . add_key_by_rloc ( OoOOoooO000 , True )
    lprint ( "    Store encap-keys for nonce 0x{}, RLOC {}" . format ( lisp_hex_string ( nonce ) , red ( OoOOoooO000 , False ) ) )
    if 96 - 96: IiII + oO0o / Oo0Ooo + OoooooooOO
    if 53 - 53: Ii1I * IiII + Oo0Ooo + i11iIiiIii - iIii1I11I1II1
    if 66 - 66: O0 - I1ii11iIi11i * iIii1I11I1II1 - I1Ii111 / I1ii11iIi11i
  return ( OOo0000o0 )
  if 24 - 24: Ii1I
  if 39 - 39: O0 % Ii1I
 def store_translated_rloc ( self , rloc , port ) :
  self . rloc . copy_address ( rloc )
  self . translated_rloc . copy_address ( rloc )
  self . translated_port = port
  if 63 - 63: OOooOOo / I1ii11iIi11i
  if 11 - 11: O0 % iIii1I11I1II1
 def is_rloc_translated ( self ) :
  return ( self . translated_rloc . is_null ( ) == False )
  if 64 - 64: OoOoOO00 - oO0o
  if 8 - 8: i11iIiiIii - iIii1I11I1II1 / I1Ii111 . i11iIiiIii % o0oOOo0O0Ooo / oO0o
 def rloc_exists ( self ) :
  if ( self . rloc . is_null ( ) == False ) : return ( True )
  if ( self . rle_name or self . geo_name or self . elp_name or self . json_name ) :
   return ( False )
   if 36 - 36: IiII
  return ( True )
  if 53 - 53: OoooooooOO / I1IiiI % I11i + Oo0Ooo
  if 15 - 15: O0
 def is_rtr ( self ) :
  return ( ( self . priority == 254 and self . mpriority == 255 and self . weight == 0 and self . mweight == 0 ) )
  if 75 - 75: iII111i / OoOoOO00
  if 2 - 2: i1IIi + oO0o % iII111i % I1ii11iIi11i + ooOoO0o . iII111i
  if 26 - 26: I11i + o0oOOo0O0Ooo + Ii1I % I11i
 def print_state_change ( self , new_state ) :
  O00o0OoO = self . print_state ( )
  oo0OooO = "{} -> {}" . format ( O00o0OoO , new_state )
  if ( new_state == "up" and self . unreach_state ( ) ) :
   oo0OooO = bold ( oo0OooO , False )
   if 3 - 3: i11iIiiIii / I1Ii111
  return ( oo0OooO )
  if 40 - 40: OoooooooOO / o0oOOo0O0Ooo + OoOoOO00
  if 73 - 73: OOooOOo / Oo0Ooo
 def print_rloc_probe_rtt ( self ) :
  if ( self . rloc_probe_rtt == - 1 ) : return ( "none" )
  return ( self . rloc_probe_rtt )
  if 80 - 80: OoO0O00 + I1IiiI % i1IIi / I11i % i1IIi * i11iIiiIii
  if 27 - 27: OoOoOO00 / I1Ii111 * O0 / I1IiiI - IiII / o0oOOo0O0Ooo
 def print_recent_rloc_probe_rtts ( self ) :
  ooo00o0oo = str ( self . recent_rloc_probe_rtts )
  ooo00o0oo = ooo00o0oo . replace ( "-1" , "?" )
  return ( ooo00o0oo )
  if 77 - 77: I1ii11iIi11i . i1IIi * OOooOOo / iII111i
  if 70 - 70: o0oOOo0O0Ooo
 def compute_rloc_probe_rtt ( self ) :
  O0oo00o000 = self . rloc_probe_rtt
  self . rloc_probe_rtt = - 1
  if ( self . last_rloc_probe_reply == None ) : return
  if ( self . last_rloc_probe == None ) : return
  self . rloc_probe_rtt = self . last_rloc_probe_reply - self . last_rloc_probe
  self . rloc_probe_rtt = round ( self . rloc_probe_rtt , 3 )
  I1Ii1iI1 = self . recent_rloc_probe_rtts
  self . recent_rloc_probe_rtts = [ O0oo00o000 ] + I1Ii1iI1 [ 0 : - 1 ]
  if 44 - 44: Oo0Ooo + Ii1I + ooOoO0o / I1ii11iIi11i
  if 50 - 50: i1IIi . iIii1I11I1II1 % OoO0O00
 def print_rloc_probe_hops ( self ) :
  return ( self . rloc_probe_hops )
  if 45 - 45: OoooooooOO . O0 * oO0o + IiII
  if 18 - 18: II111iiii . O0 - I11i / I11i
 def print_recent_rloc_probe_hops ( self ) :
  OOOoooo = str ( self . recent_rloc_probe_hops )
  return ( OOOoooo )
  if 39 - 39: Ii1I + I1Ii111 * Oo0Ooo + OoOoOO00 / I1Ii111 - ooOoO0o
  if 66 - 66: I11i * OoO0O00
 def store_rloc_probe_hops ( self , to_hops , from_ttl ) :
  if ( to_hops == 0 ) :
   to_hops = "?"
  elif ( to_hops < LISP_RLOC_PROBE_TTL / 2 ) :
   to_hops = "!"
  else :
   to_hops = str ( LISP_RLOC_PROBE_TTL - to_hops )
   if 98 - 98: IiII . Oo0Ooo + I1Ii111
  if ( from_ttl < LISP_RLOC_PROBE_TTL / 2 ) :
   oO0OOOOOO0000 = "!"
  else :
   oO0OOOOOO0000 = str ( LISP_RLOC_PROBE_TTL - from_ttl )
   if 94 - 94: OOooOOo % I1IiiI * I1Ii111 * I11i - OoOoOO00 + iIii1I11I1II1
   if 3 - 3: O0 / I1Ii111
  O0oo00o000 = self . rloc_probe_hops
  self . rloc_probe_hops = to_hops + "/" + oO0OOOOOO0000
  I1Ii1iI1 = self . recent_rloc_probe_hops
  self . recent_rloc_probe_hops = [ O0oo00o000 ] + I1Ii1iI1 [ 0 : - 1 ]
  if 35 - 35: O0 + II111iiii + o0oOOo0O0Ooo - OoO0O00 - Ii1I
  if 88 - 88: I1ii11iIi11i . O0 - o0oOOo0O0Ooo . I1ii11iIi11i * iII111i * I11i
 def process_rloc_probe_reply ( self , nonce , eid , group , hop_count , ttl ) :
  i1IIIIi1Ii111 = self
  while ( True ) :
   if ( i1IIIIi1Ii111 . last_rloc_probe_nonce == nonce ) : break
   i1IIIIi1Ii111 = i1IIIIi1Ii111 . next_rloc
   if ( i1IIIIi1Ii111 == None ) :
    lprint ( "    No matching nonce state found for nonce 0x{}" . format ( lisp_hex_string ( nonce ) ) )
    if 89 - 89: Oo0Ooo - oO0o + O0 / i11iIiiIii
    return
    if 64 - 64: OoO0O00 % OoOoOO00 % I1IiiI - Ii1I / IiII * Ii1I
    if 74 - 74: IiII - O0 % OOooOOo % OoooooooOO - I11i
    if 4 - 4: i1IIi + OoOoOO00 + iIii1I11I1II1 - i1IIi * i11iIiiIii
  i1IIIIi1Ii111 . last_rloc_probe_reply = lisp_get_timestamp ( )
  i1IIIIi1Ii111 . compute_rloc_probe_rtt ( )
  OO0oOo00 = i1IIIIi1Ii111 . print_state_change ( "up" )
  if ( i1IIIIi1Ii111 . state != LISP_RLOC_UP_STATE ) :
   lisp_update_rtr_updown ( i1IIIIi1Ii111 . rloc , True )
   i1IIIIi1Ii111 . state = LISP_RLOC_UP_STATE
   i1IIIIi1Ii111 . last_state_change = lisp_get_timestamp ( )
   Iii1 = lisp_map_cache . lookup_cache ( eid , True )
   if ( Iii1 ) : lisp_write_ipc_map_cache ( True , Iii1 )
   if 88 - 88: O0 % OOooOOo . iII111i
   if 40 - 40: O0 . Ii1I % IiII % I1ii11iIi11i - OoOoOO00
  i1IIIIi1Ii111 . store_rloc_probe_hops ( hop_count , ttl )
  if 94 - 94: I1IiiI . I1Ii111
  O00oOoo0OoOOO = bold ( "RLOC-probe reply" , False )
  OoOOoooO000 = i1IIIIi1Ii111 . rloc . print_address_no_iid ( )
  iiiI1i1I = bold ( str ( i1IIIIi1Ii111 . print_rloc_probe_rtt ( ) ) , False )
  o0O0o = ":{}" . format ( self . translated_port ) if self . translated_port != 0 else ""
  if 20 - 20: OOooOOo / I1Ii111 % i11iIiiIii / OoO0O00 * Ii1I
  I1i1i1iIIiI11 = ""
  if ( i1IIIIi1Ii111 . rloc_next_hop != None ) :
   i1i11ii1Ii , IIiIiIii1111 = i1IIIIi1Ii111 . rloc_next_hop
   I1i1i1iIIiI11 = ", nh {}({})" . format ( IIiIiIii1111 , i1i11ii1Ii )
   if 29 - 29: iII111i % iII111i % o0oOOo0O0Ooo + II111iiii
   if 89 - 89: I1IiiI - OoooooooOO / I11i . ooOoO0o
  I1i11II = green ( lisp_print_eid_tuple ( eid , group ) , False )
  lprint ( ( "    Received {} from {}{} for {}, {}, rtt {}{}, " + "to-ttl/from-ttl {}" ) . format ( O00oOoo0OoOOO , red ( OoOOoooO000 , False ) , o0O0o , I1i11II ,
  # I1ii11iIi11i . Ii1I . iIii1I11I1II1 * I1ii11iIi11i / Ii1I
 OO0oOo00 , iiiI1i1I , I1i1i1iIIiI11 , str ( hop_count ) + "/" + str ( ttl ) ) )
  if 74 - 74: Oo0Ooo * I1Ii111
  if ( i1IIIIi1Ii111 . rloc_next_hop == None ) : return
  if 72 - 72: OoOoOO00 + O0 - IiII * ooOoO0o
  if 20 - 20: II111iiii % OoOoOO00 * i11iIiiIii
  if 68 - 68: IiII / ooOoO0o
  if 100 - 100: ooOoO0o / I1IiiI
  i1IIIIi1Ii111 = None
  O00OOO0 = None
  while ( True ) :
   i1IIIIi1Ii111 = self if i1IIIIi1Ii111 == None else i1IIIIi1Ii111 . next_rloc
   if ( i1IIIIi1Ii111 == None ) : break
   if ( i1IIIIi1Ii111 . up_state ( ) == False ) : continue
   if ( i1IIIIi1Ii111 . rloc_probe_rtt == - 1 ) : continue
   if 66 - 66: OoooooooOO / iII111i / I1IiiI % ooOoO0o / OoO0O00 + OOooOOo
   if ( O00OOO0 == None ) : O00OOO0 = i1IIIIi1Ii111
   if ( i1IIIIi1Ii111 . rloc_probe_rtt < O00OOO0 . rloc_probe_rtt ) : O00OOO0 = i1IIIIi1Ii111
   if 64 - 64: i1IIi
   if 26 - 26: OoOoOO00 / o0oOOo0O0Ooo . OOooOOo + I1IiiI + Ii1I . iII111i
  if ( O00OOO0 != None ) :
   i1i11ii1Ii , IIiIiIii1111 = O00OOO0 . rloc_next_hop
   I1i1i1iIIiI11 = bold ( "nh {}({})" . format ( IIiIiIii1111 , i1i11ii1Ii ) , False )
   lprint ( "    Install host-route via best {}" . format ( I1i1i1iIIiI11 ) )
   lisp_install_host_route ( OoOOoooO000 , None , False )
   lisp_install_host_route ( OoOOoooO000 , IIiIiIii1111 , True )
   if 89 - 89: I1Ii111 * I1IiiI . i1IIi - iIii1I11I1II1 * I1Ii111
   if 5 - 5: OoOoOO00 % i1IIi
   if 31 - 31: Oo0Ooo * O0 . OOooOOo . o0oOOo0O0Ooo + OoO0O00 + II111iiii
 def add_to_rloc_probe_list ( self , eid , group ) :
  OoOOoooO000 = self . rloc . print_address_no_iid ( )
  OOo0000o0 = self . translated_port
  if ( OOo0000o0 != 0 ) : OoOOoooO000 += ":" + str ( OOo0000o0 )
  if 76 - 76: Oo0Ooo + I1IiiI - O0
  if ( lisp_rloc_probe_list . has_key ( OoOOoooO000 ) == False ) :
   lisp_rloc_probe_list [ OoOOoooO000 ] = [ ]
   if 58 - 58: IiII * i1IIi . I1IiiI - iII111i
   if 73 - 73: Oo0Ooo . OoOoOO00
  if ( group . is_null ( ) ) : group . instance_id = 0
  for iIOoo000 , I1i11II , i1iII1iii in lisp_rloc_probe_list [ OoOOoooO000 ] :
   if ( I1i11II . is_exact_match ( eid ) and i1iII1iii . is_exact_match ( group ) ) :
    if ( iIOoo000 == self ) :
     if ( lisp_rloc_probe_list [ OoOOoooO000 ] == [ ] ) :
      lisp_rloc_probe_list . pop ( OoOOoooO000 )
      if 50 - 50: IiII / o0oOOo0O0Ooo
     return
     if 9 - 9: Oo0Ooo - OoO0O00 + iII111i / OoooooooOO
    lisp_rloc_probe_list [ OoOOoooO000 ] . remove ( [ iIOoo000 , I1i11II , i1iII1iii ] )
    break
    if 52 - 52: O0
    if 34 - 34: OoooooooOO + OoOoOO00 - Oo0Ooo . OOooOOo * iIii1I11I1II1
  lisp_rloc_probe_list [ OoOOoooO000 ] . append ( [ self , eid , group ] )
  if 93 - 93: i11iIiiIii / Oo0Ooo * OoOoOO00 / ooOoO0o + OoO0O00 * OOooOOo
  if 81 - 81: IiII * iII111i + i1IIi + I1Ii111 / OoO0O00
  if 83 - 83: oO0o / OoO0O00
  if 34 - 34: OoooooooOO - i1IIi * O0
  if 83 - 83: I1IiiI + OoO0O00
  i1IIIIi1Ii111 = lisp_rloc_probe_list [ OoOOoooO000 ] [ 0 ] [ 0 ]
  if ( i1IIIIi1Ii111 . state == LISP_RLOC_UNREACH_STATE ) :
   self . state = LISP_RLOC_UNREACH_STATE
   self . last_state_change = lisp_get_timestamp ( )
   if 41 - 41: Ii1I + II111iiii . OOooOOo * I1Ii111 / II111iiii
   if 32 - 32: Oo0Ooo - Ii1I % o0oOOo0O0Ooo
   if 15 - 15: iIii1I11I1II1 * I1ii11iIi11i / ooOoO0o * oO0o % OOooOOo
 def delete_from_rloc_probe_list ( self , eid , group ) :
  OoOOoooO000 = self . rloc . print_address_no_iid ( )
  OOo0000o0 = self . translated_port
  if ( OOo0000o0 != 0 ) : OoOOoooO000 += ":" + str ( OOo0000o0 )
  if ( lisp_rloc_probe_list . has_key ( OoOOoooO000 ) == False ) : return
  if 62 - 62: Ii1I / Oo0Ooo . OoO0O00 - OOooOOo
  oOOOOoOO0Oo = [ ]
  for o0Iiii in lisp_rloc_probe_list [ OoOOoooO000 ] :
   if ( o0Iiii [ 0 ] != self ) : continue
   if ( o0Iiii [ 1 ] . is_exact_match ( eid ) == False ) : continue
   if ( o0Iiii [ 2 ] . is_exact_match ( group ) == False ) : continue
   oOOOOoOO0Oo = o0Iiii
   break
   if 84 - 84: Oo0Ooo * I1Ii111 - o0oOOo0O0Ooo % Ii1I
  if ( oOOOOoOO0Oo == [ ] ) : return
  if 69 - 69: I11i + OoOoOO00 - i11iIiiIii * O0 % O0
  try :
   lisp_rloc_probe_list [ OoOOoooO000 ] . remove ( oOOOOoOO0Oo )
   if ( lisp_rloc_probe_list [ OoOOoooO000 ] == [ ] ) :
    lisp_rloc_probe_list . pop ( OoOOoooO000 )
    if 81 - 81: I11i - o0oOOo0O0Ooo % Ii1I / I1Ii111 * II111iiii
  except :
   return
   if 40 - 40: OoO0O00 . i11iIiiIii
   if 36 - 36: o0oOOo0O0Ooo * iII111i / I1ii11iIi11i % i1IIi % I1ii11iIi11i + i11iIiiIii
   if 24 - 24: I1Ii111 / ooOoO0o - i11iIiiIii
 def print_rloc_probe_state ( self , trailing_linefeed ) :
  ooO000O = ""
  i1IIIIi1Ii111 = self
  while ( True ) :
   Iii111II1I11I = i1IIIIi1Ii111 . last_rloc_probe
   if ( Iii111II1I11I == None ) : Iii111II1I11I = 0
   IIii = i1IIIIi1Ii111 . last_rloc_probe_reply
   if ( IIii == None ) : IIii = 0
   iiiI1i1I = i1IIIIi1Ii111 . print_rloc_probe_rtt ( )
   i1I1iIi1IiI = space ( 4 )
   if 56 - 56: II111iiii * iIii1I11I1II1 % I1ii11iIi11i
   if ( i1IIIIi1Ii111 . rloc_next_hop == None ) :
    ooO000O += "RLOC-Probing:\n"
   else :
    i1i11ii1Ii , IIiIiIii1111 = i1IIIIi1Ii111 . rloc_next_hop
    ooO000O += "RLOC-Probing for nh {}({}):\n" . format ( IIiIiIii1111 , i1i11ii1Ii )
    if 83 - 83: i1IIi . i11iIiiIii / iII111i
    if 28 - 28: i1IIi - iII111i + o0oOOo0O0Ooo / Oo0Ooo * oO0o
   ooO000O += ( "{}RLOC-probe request sent: {}\n{}RLOC-probe reply " + "received: {}, rtt {}" ) . format ( i1I1iIi1IiI , lisp_print_elapsed ( Iii111II1I11I ) ,
   # I11i
 i1I1iIi1IiI , lisp_print_elapsed ( IIii ) , iiiI1i1I )
   if 42 - 42: OOooOOo * ooOoO0o / i1IIi . i11iIiiIii - oO0o - Ii1I
   if ( trailing_linefeed ) : ooO000O += "\n"
   if 5 - 5: i1IIi + II111iiii . ooOoO0o
   i1IIIIi1Ii111 = i1IIIIi1Ii111 . next_rloc
   if ( i1IIIIi1Ii111 == None ) : break
   ooO000O += "\n"
   if 21 - 21: i1IIi
  return ( ooO000O )
  if 96 - 96: OoOoOO00 * OoOoOO00 % OoO0O00 * iII111i
  if 51 - 51: I1IiiI + i11iIiiIii + iII111i
 def get_encap_keys ( self ) :
  OOo0000o0 = "4341" if self . translated_port == 0 else str ( self . translated_port )
  if 57 - 57: Oo0Ooo . oO0o
  OoOOoooO000 = self . rloc . print_address_no_iid ( ) + ":" + OOo0000o0
  if 52 - 52: IiII % OoO0O00 - OoO0O00 . I1IiiI + OoO0O00 * ooOoO0o
  try :
   II1i = lisp_crypto_keys_by_rloc_encap [ OoOOoooO000 ]
   if ( II1i [ 1 ] ) : return ( II1i [ 1 ] . encrypt_key , II1i [ 1 ] . icv_key )
   return ( None , None )
  except :
   return ( None , None )
   if 44 - 44: iIii1I11I1II1 / Ii1I - oO0o % i11iIiiIii
   if 65 - 65: I1ii11iIi11i * Oo0Ooo / Ii1I . OOooOOo * iIii1I11I1II1 + Oo0Ooo
   if 44 - 44: ooOoO0o * iII111i * IiII % o0oOOo0O0Ooo
 def rloc_recent_rekey ( self ) :
  OOo0000o0 = "4341" if self . translated_port == 0 else str ( self . translated_port )
  if 45 - 45: OoOoOO00 % o0oOOo0O0Ooo + IiII / i11iIiiIii
  OoOOoooO000 = self . rloc . print_address_no_iid ( ) + ":" + OOo0000o0
  if 29 - 29: iIii1I11I1II1 . OoO0O00 / I1IiiI
  try :
   i1IIiI1iII = lisp_crypto_keys_by_rloc_encap [ OoOOoooO000 ] [ 1 ]
   if ( i1IIiI1iII == None ) : return ( False )
   if ( i1IIiI1iII . last_rekey == None ) : return ( True )
   return ( time . time ( ) - i1IIiI1iII . last_rekey < 1 )
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
  if 71 - 71: I11i % I11i - i11iIiiIii + iIii1I11I1II1 / iII111i
  if 63 - 63: O0 * i11iIiiIii / IiII / IiII
 def print_mapping ( self , eid_indent , rloc_indent ) :
  III11I1 = lisp_print_elapsed ( self . uptime )
  Oo000o0o0 = "" if self . group . is_null ( ) else ", group {}" . format ( self . group . print_prefix ( ) )
  if 72 - 72: i11iIiiIii * OoOoOO00 % oO0o / I1Ii111
  lprint ( "{}eid {}{}, uptime {}, {} rlocs:" . format ( eid_indent ,
 green ( self . eid . print_prefix ( ) , False ) , Oo000o0o0 , III11I1 ,
 len ( self . rloc_set ) ) )
  for i1IIIIi1Ii111 in self . rloc_set : i1IIIIi1Ii111 . print_rloc ( rloc_indent )
  if 9 - 9: iIii1I11I1II1 . IiII
  if 42 - 42: i1IIi / Ii1I * I1ii11iIi11i
 def print_eid_tuple ( self ) :
  return ( lisp_print_eid_tuple ( self . eid , self . group ) )
  if 9 - 9: I11i % i1IIi / i1IIi / OoO0O00
  if 46 - 46: I1Ii111 * II111iiii + II111iiii * O0 % II111iiii
 def print_ttl ( self ) :
  iiI = self . map_cache_ttl
  if ( iiI == None ) : return ( "forever" )
  if 37 - 37: OOooOOo . iIii1I11I1II1 / O0 . ooOoO0o + OOooOOo - OoooooooOO
  if ( iiI >= 3600 ) :
   if ( ( iiI % 3600 ) == 0 ) :
    iiI = str ( iiI / 3600 ) + " hours"
   else :
    iiI = str ( iiI * 60 ) + " mins"
    if 96 - 96: I1Ii111 / oO0o . I1ii11iIi11i % I1IiiI * OOooOOo
  elif ( iiI >= 60 ) :
   if ( ( iiI % 60 ) == 0 ) :
    iiI = str ( iiI / 60 ) + " mins"
   else :
    iiI = str ( iiI ) + " secs"
    if 99 - 99: i11iIiiIii - I1Ii111
  else :
   iiI = str ( iiI ) + " secs"
   if 4 - 4: o0oOOo0O0Ooo - i11iIiiIii . iIii1I11I1II1 . OOooOOo % IiII
  return ( iiI )
  if 68 - 68: I11i / iII111i - IiII . iIii1I11I1II1 / o0oOOo0O0Ooo
  if 54 - 54: II111iiii * I1IiiI
 def has_ttl_elapsed ( self ) :
  if ( self . map_cache_ttl == None ) : return ( False )
  ooooOoO0O = time . time ( ) - self . last_refresh_time
  return ( ooooOoO0O >= self . map_cache_ttl )
  if 49 - 49: I1ii11iIi11i
  if 31 - 31: o0oOOo0O0Ooo - OoOoOO00 + I1ii11iIi11i . oO0o - O0
 def is_active ( self ) :
  if ( self . stats . last_increment == None ) : return ( False )
  ooooOoO0O = time . time ( ) - self . stats . last_increment
  return ( ooooOoO0O <= 60 )
  if 61 - 61: I1ii11iIi11i * II111iiii . i1IIi
  if 60 - 60: OoooooooOO % ooOoO0o * i11iIiiIii * OoooooooOO % IiII
 def match_eid_tuple ( self , db ) :
  if ( self . eid . is_exact_match ( db . eid ) == False ) : return ( False )
  if ( self . group . is_exact_match ( db . group ) == False ) : return ( False )
  return ( True )
  if 15 - 15: oO0o
  if 40 - 40: I1Ii111
 def sort_rloc_set ( self ) :
  self . rloc_set . sort ( key = operator . attrgetter ( 'rloc.address' ) )
  if 77 - 77: II111iiii - o0oOOo0O0Ooo . Ii1I
  if 47 - 47: o0oOOo0O0Ooo % OOooOOo + I1Ii111
 def delete_rlocs_from_rloc_probe_list ( self ) :
  for i1IIIIi1Ii111 in self . best_rloc_set :
   i1IIIIi1Ii111 . delete_from_rloc_probe_list ( self . eid , self . group )
   if 64 - 64: ooOoO0o / IiII . I1IiiI
   if 77 - 77: o0oOOo0O0Ooo % I1Ii111 . OOooOOo
   if 90 - 90: I11i
 def build_best_rloc_set ( self ) :
  OOooOo = self . best_rloc_set
  self . best_rloc_set = [ ]
  if ( self . rloc_set == None ) : return
  if 42 - 42: iII111i
  if 90 - 90: Ii1I . o0oOOo0O0Ooo
  if 3 - 3: oO0o
  if 42 - 42: Oo0Ooo
  iIIII1I11iii = 256
  for i1IIIIi1Ii111 in self . rloc_set :
   if ( i1IIIIi1Ii111 . up_state ( ) ) : iIIII1I11iii = min ( i1IIIIi1Ii111 . priority , iIIII1I11iii )
   if 22 - 22: o0oOOo0O0Ooo
   if 45 - 45: I1Ii111 + OoooooooOO + o0oOOo0O0Ooo * II111iiii
   if 12 - 12: I1ii11iIi11i / O0
   if 18 - 18: OoOoOO00 . i11iIiiIii + i1IIi / OoooooooOO - IiII % OoO0O00
   if 47 - 47: iII111i % IiII + I1Ii111 * o0oOOo0O0Ooo * OoooooooOO
   if 100 - 100: Oo0Ooo / I1IiiI / iII111i / I1Ii111 / oO0o % o0oOOo0O0Ooo
   if 16 - 16: I1IiiI + I11i
   if 66 - 66: OoooooooOO % II111iiii / I1Ii111 . i11iIiiIii
   if 67 - 67: Ii1I + Oo0Ooo - I1IiiI - IiII + oO0o + Oo0Ooo
   if 84 - 84: I1ii11iIi11i % oO0o - OOooOOo * Ii1I
  for i1IIIIi1Ii111 in self . rloc_set :
   if ( i1IIIIi1Ii111 . priority <= iIIII1I11iii ) :
    if ( i1IIIIi1Ii111 . unreach_state ( ) and i1IIIIi1Ii111 . last_rloc_probe == None ) :
     i1IIIIi1Ii111 . last_rloc_probe = lisp_get_timestamp ( )
     if 78 - 78: i1IIi / ooOoO0o / oO0o
    self . best_rloc_set . append ( i1IIIIi1Ii111 )
    if 21 - 21: IiII % Ii1I + OOooOOo + IiII
    if 90 - 90: o0oOOo0O0Ooo
    if 38 - 38: OoOoOO00 / OOooOOo % OoooooooOO * I1ii11iIi11i
    if 7 - 7: I11i * O0 + Oo0Ooo / O0 * oO0o + i11iIiiIii
    if 74 - 74: OoOoOO00
    if 91 - 91: i11iIiiIii / Ii1I % OOooOOo % O0 - I11i . I11i
    if 78 - 78: i1IIi + I11i % OoooooooOO + i1IIi + iII111i % Ii1I
    if 87 - 87: ooOoO0o . iIii1I11I1II1
  for i1IIIIi1Ii111 in OOooOo :
   if ( i1IIIIi1Ii111 . priority < iIIII1I11iii ) : continue
   i1IIIIi1Ii111 . delete_from_rloc_probe_list ( self . eid , self . group )
   if 99 - 99: Ii1I + OoooooooOO * IiII * i11iIiiIii - iIii1I11I1II1
  for i1IIIIi1Ii111 in self . best_rloc_set :
   if ( i1IIIIi1Ii111 . rloc . is_null ( ) ) : continue
   i1IIIIi1Ii111 . add_to_rloc_probe_list ( self . eid , self . group )
   if 58 - 58: IiII % i1IIi . i11iIiiIii
   if 5 - 5: OoOoOO00
   if 75 - 75: OOooOOo
 def select_rloc ( self , lisp_packet , ipc_socket ) :
  iI1IIII1ii1 = lisp_packet . packet
  o0OooooO0 = lisp_packet . inner_version
  I1I1 = len ( self . best_rloc_set )
  if ( I1I1 is 0 ) :
   self . stats . increment ( len ( iI1IIII1ii1 ) )
   return ( [ None , None , None , self . action , None , None ] )
   if 71 - 71: OoO0O00
   if 19 - 19: IiII - II111iiii % i1IIi + IiII
  iIiII11OoO0000O000o = 4 if lisp_load_split_pings else 0
  oO000o0o0oOo0 = lisp_packet . hash_ports ( )
  if ( o0OooooO0 == 4 ) :
   for oO in range ( 8 + iIiII11OoO0000O000o ) :
    oO000o0o0oOo0 = oO000o0o0oOo0 ^ struct . unpack ( "B" , iI1IIII1ii1 [ oO + 12 ] ) [ 0 ]
    if 74 - 74: i1IIi
  elif ( o0OooooO0 == 6 ) :
   for oO in range ( 0 , 32 + iIiII11OoO0000O000o , 4 ) :
    oO000o0o0oOo0 = oO000o0o0oOo0 ^ struct . unpack ( "I" , iI1IIII1ii1 [ oO + 8 : oO + 12 ] ) [ 0 ]
    if 63 - 63: I1ii11iIi11i + iII111i * o0oOOo0O0Ooo % II111iiii
   oO000o0o0oOo0 = ( oO000o0o0oOo0 >> 16 ) + ( oO000o0o0oOo0 & 0xffff )
   oO000o0o0oOo0 = ( oO000o0o0oOo0 >> 8 ) + ( oO000o0o0oOo0 & 0xff )
  else :
   for oO in range ( 0 , 12 + iIiII11OoO0000O000o , 4 ) :
    oO000o0o0oOo0 = oO000o0o0oOo0 ^ struct . unpack ( "I" , iI1IIII1ii1 [ oO : oO + 4 ] ) [ 0 ]
    if 23 - 23: i1IIi * oO0o * oO0o . i11iIiiIii / o0oOOo0O0Ooo
    if 80 - 80: O0 / II111iiii . Oo0Ooo + o0oOOo0O0Ooo - OoO0O00
    if 8 - 8: o0oOOo0O0Ooo / I1Ii111 % i1IIi
  if ( lisp_data_plane_logging ) :
   i1IIII1iiiII1 = [ ]
   for iIOoo000 in self . best_rloc_set :
    if ( iIOoo000 . rloc . is_null ( ) ) : continue
    i1IIII1iiiII1 . append ( [ iIOoo000 . rloc . print_address_no_iid ( ) , iIOoo000 . print_state ( ) ] )
    if 9 - 9: I1ii11iIi11i - o0oOOo0O0Ooo / i11iIiiIii * iII111i / OoOoOO00 . I1IiiI
   dprint ( "Packet hash {}, index {}, best-rloc-list: {}" . format ( hex ( oO000o0o0oOo0 ) , oO000o0o0oOo0 % I1I1 , red ( str ( i1IIII1iiiII1 ) , False ) ) )
   if 23 - 23: I1IiiI . iII111i % i1IIi
   if 92 - 92: o0oOOo0O0Ooo % i1IIi / OoooooooOO * OoooooooOO / iIii1I11I1II1
   if 7 - 7: IiII / OOooOOo + Oo0Ooo . I1IiiI
   if 33 - 33: I1Ii111 + OoooooooOO
   if 73 - 73: O0 . Oo0Ooo
   if 28 - 28: I1IiiI . O0 % o0oOOo0O0Ooo / I11i
  i1IIIIi1Ii111 = self . best_rloc_set [ oO000o0o0oOo0 % I1I1 ]
  if 48 - 48: II111iiii % I1ii11iIi11i - II111iiii
  if 29 - 29: I1Ii111 - I1Ii111 - I11i * iIii1I11I1II1 % OoO0O00 % IiII
  if 73 - 73: i1IIi . OoooooooOO / OoOoOO00 % Ii1I / Ii1I / Ii1I
  if 40 - 40: I1Ii111 - iIii1I11I1II1
  if 88 - 88: OOooOOo * O0 * OoOoOO00
  i11iiIi = lisp_get_echo_nonce ( i1IIIIi1Ii111 . rloc , None )
  if ( i11iiIi ) :
   i11iiIi . change_state ( i1IIIIi1Ii111 )
   if ( i1IIIIi1Ii111 . no_echoed_nonce_state ( ) ) :
    i11iiIi . request_nonce_sent = None
    if 26 - 26: Ii1I
    if 65 - 65: iII111i / iIii1I11I1II1 + I11i - iIii1I11I1II1 - Ii1I . I1Ii111
    if 77 - 77: OoOoOO00 / I1IiiI + IiII
    if 66 - 66: i11iIiiIii * OoooooooOO + iII111i / Ii1I
    if 42 - 42: Ii1I / iIii1I11I1II1 / Oo0Ooo . O0 . oO0o * I1IiiI
    if 21 - 21: OoooooooOO
  if ( i1IIIIi1Ii111 . up_state ( ) == False ) :
   OoooO00OO0OO = oO000o0o0oOo0 % I1I1
   OOOoO000 = ( OoooO00OO0OO + 1 ) % I1I1
   while ( OOOoO000 != OoooO00OO0OO ) :
    i1IIIIi1Ii111 = self . best_rloc_set [ OOOoO000 ]
    if ( i1IIIIi1Ii111 . up_state ( ) ) : break
    OOOoO000 = ( OOOoO000 + 1 ) % I1I1
    if 50 - 50: OoO0O00 . o0oOOo0O0Ooo
   if ( OOOoO000 == OoooO00OO0OO ) :
    self . build_best_rloc_set ( )
    return ( [ None , None , None , None , None , None ] )
    if 30 - 30: I1ii11iIi11i % iII111i
    if 79 - 79: OOooOOo % I1Ii111 / IiII - Oo0Ooo
    if 48 - 48: Oo0Ooo * iII111i - Oo0Ooo + I11i % II111iiii
    if 71 - 71: OoOoOO00 % o0oOOo0O0Ooo . oO0o
    if 65 - 65: OoO0O00
    if 48 - 48: OoO0O00
  i1IIIIi1Ii111 . stats . increment ( len ( iI1IIII1ii1 ) )
  if 59 - 59: OoooooooOO + I11i . oO0o
  if 65 - 65: I1ii11iIi11i * II111iiii % I11i + II111iiii . i1IIi / ooOoO0o
  if 74 - 74: OoOoOO00 % OoO0O00 . OoOoOO00
  if 16 - 16: OoO0O00 / Ii1I * i11iIiiIii / o0oOOo0O0Ooo + I1Ii111
  if ( i1IIIIi1Ii111 . rle_name and i1IIIIi1Ii111 . rle == None ) :
   if ( lisp_rle_list . has_key ( i1IIIIi1Ii111 . rle_name ) ) :
    i1IIIIi1Ii111 . rle = lisp_rle_list [ i1IIIIi1Ii111 . rle_name ]
    if 21 - 21: I11i % I1ii11iIi11i
    if 8 - 8: OOooOOo % OoO0O00 + O0 - o0oOOo0O0Ooo
  if ( i1IIIIi1Ii111 . rle ) : return ( [ None , None , None , None , i1IIIIi1Ii111 . rle , None ] )
  if 46 - 46: Oo0Ooo . ooOoO0o + OoOoOO00 - I11i / i11iIiiIii . iII111i
  if 80 - 80: II111iiii + OoO0O00 % ooOoO0o + i11iIiiIii
  if 30 - 30: Ii1I / I1ii11iIi11i % IiII - Oo0Ooo
  if 100 - 100: IiII . I1Ii111 * oO0o % OoO0O00 . iIii1I11I1II1 * Oo0Ooo
  if ( i1IIIIi1Ii111 . elp and i1IIIIi1Ii111 . elp . use_elp_node ) :
   return ( [ i1IIIIi1Ii111 . elp . use_elp_node . address , None , None , None , None ,
 None ] )
   if 100 - 100: IiII - OoOoOO00 % iII111i
   if 24 - 24: Oo0Ooo / OoO0O00 + i11iIiiIii
   if 81 - 81: i11iIiiIii . iIii1I11I1II1 - OoooooooOO
   if 52 - 52: O0 - I1Ii111 + oO0o % ooOoO0o . oO0o
   if 60 - 60: oO0o + o0oOOo0O0Ooo - OOooOOo % o0oOOo0O0Ooo . I11i + OoO0O00
  Ii1Ii1ii = None if ( i1IIIIi1Ii111 . rloc . is_null ( ) ) else i1IIIIi1Ii111 . rloc
  OOo0000o0 = i1IIIIi1Ii111 . translated_port
  I11IiIi1I = self . action if ( Ii1Ii1ii == None ) else None
  if 85 - 85: OoO0O00 * OOooOOo . Oo0Ooo
  if 44 - 44: OoO0O00 / iII111i * II111iiii
  if 22 - 22: Ii1I / ooOoO0o / o0oOOo0O0Ooo % I1ii11iIi11i . iIii1I11I1II1
  if 78 - 78: OoO0O00 . I1ii11iIi11i / ooOoO0o + OoO0O00 / I1ii11iIi11i * ooOoO0o
  if 96 - 96: IiII % iII111i . OoOoOO00 / oO0o . OoO0O00
  iIiIi1i1Iiii = None
  if ( i11iiIi and i11iiIi . request_nonce_timeout ( ) == False ) :
   iIiIi1i1Iiii = i11iiIi . get_request_or_echo_nonce ( ipc_socket , Ii1Ii1ii )
   if 85 - 85: iIii1I11I1II1 / OoOoOO00 * I1ii11iIi11i
   if 26 - 26: iII111i - OoO0O00 . o0oOOo0O0Ooo
   if 50 - 50: I1Ii111 . O0 . OoOoOO00 + I1Ii111 + OoooooooOO . i11iIiiIii
   if 65 - 65: I1IiiI % iIii1I11I1II1
   if 52 - 52: I1IiiI
  return ( [ Ii1Ii1ii , OOo0000o0 , iIiIi1i1Iiii , I11IiIi1I , None , i1IIIIi1Ii111 ] )
  if 19 - 19: I1IiiI
  if 17 - 17: I11i + OoooooooOO
 def do_rloc_sets_match ( self , rloc_address_set ) :
  if ( len ( self . rloc_set ) != len ( rloc_address_set ) ) : return ( False )
  if 63 - 63: IiII
  if 3 - 3: oO0o * II111iiii . O0
  if 19 - 19: I1IiiI / I1IiiI / Oo0Ooo + oO0o + i1IIi
  if 31 - 31: iII111i / OoooooooOO - I1Ii111 . iII111i
  if 38 - 38: ooOoO0o . OoooooooOO - II111iiii * i11iIiiIii / i1IIi . OoooooooOO
  for ii1I1i11 in self . rloc_set :
   for i1IIIIi1Ii111 in rloc_address_set :
    if ( i1IIIIi1Ii111 . is_exact_match ( ii1I1i11 . rloc ) == False ) : continue
    i1IIIIi1Ii111 = None
    break
    if 51 - 51: oO0o - I1ii11iIi11i + I1ii11iIi11i
   if ( i1IIIIi1Ii111 == rloc_address_set [ - 1 ] ) : return ( False )
   if 100 - 100: I11i - I1ii11iIi11i . i1IIi
  return ( True )
  if 85 - 85: II111iiii
  if 58 - 58: i1IIi - OoO0O00 + ooOoO0o
 def get_rloc ( self , rloc ) :
  for ii1I1i11 in self . rloc_set :
   iIOoo000 = ii1I1i11 . rloc
   if ( rloc . is_exact_match ( iIOoo000 ) ) : return ( ii1I1i11 )
   if 6 - 6: IiII % I1IiiI + OoooooooOO * oO0o . iII111i + oO0o
  return ( None )
  if 4 - 4: I11i % I1IiiI
  if 72 - 72: I1IiiI % II111iiii % iII111i / OoOoOO00
 def get_rloc_by_interface ( self , interface ) :
  for ii1I1i11 in self . rloc_set :
   if ( ii1I1i11 . interface == interface ) : return ( ii1I1i11 )
   if 96 - 96: OoOoOO00 % Ii1I
  return ( None )
  if 50 - 50: IiII - II111iiii
  if 10 - 10: OoooooooOO % Ii1I * OOooOOo + IiII * oO0o
 def add_db ( self ) :
  if ( self . group . is_null ( ) ) :
   lisp_db_for_lookups . add_cache ( self . eid , self )
  else :
   o0Oo00OOOo00 = lisp_db_for_lookups . lookup_cache ( self . group , True )
   if ( o0Oo00OOOo00 == None ) :
    o0Oo00OOOo00 = lisp_mapping ( self . group , self . group , [ ] )
    lisp_db_for_lookups . add_cache ( self . group , o0Oo00OOOo00 )
    if 13 - 13: II111iiii
   o0Oo00OOOo00 . add_source_entry ( self )
   if 14 - 14: i11iIiiIii . IiII
   if 70 - 70: Oo0Ooo * OOooOOo + I1Ii111 % OoOoOO00 / O0
   if 23 - 23: O0 * oO0o / I1IiiI + i1IIi * O0 % oO0o
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
    if 11 - 11: I1Ii111 . OoooooooOO * iIii1I11I1II1 / I1ii11iIi11i - ooOoO0o . iII111i
   if ( self . eid . is_null ( ) ) : self . eid . make_default_route ( Iii1 . group )
   Iii1 . add_source_entry ( self )
   if 71 - 71: i11iIiiIii + I11i / i11iIiiIii % Oo0Ooo / iIii1I11I1II1 * OoO0O00
  if ( do_ipc ) : lisp_write_ipc_map_cache ( True , self )
  if 49 - 49: iII111i + OoOoOO00
  if 33 - 33: ooOoO0o
 def delete_cache ( self ) :
  self . delete_rlocs_from_rloc_probe_list ( )
  lisp_write_ipc_map_cache ( False , self )
  if 19 - 19: I1Ii111 % IiII
  if ( self . group . is_null ( ) ) :
   lisp_map_cache . delete_cache ( self . eid )
   if ( lisp_program_hardware ) :
    O00OOOoOoooo = self . eid . print_prefix_no_iid ( )
    os . system ( "ip route delete {}" . format ( O00OOOoOoooo ) )
    if 88 - 88: OOooOOo
  else :
   Iii1 = lisp_map_cache . lookup_cache ( self . group , True )
   if ( Iii1 == None ) : return
   if 79 - 79: oO0o
   OOoOOoo = Iii1 . lookup_source_cache ( self . eid , True )
   if ( OOoOOoo == None ) : return
   if 13 - 13: oO0o % ooOoO0o % I1IiiI - o0oOOo0O0Ooo
   Iii1 . source_cache . delete_cache ( self . eid )
   if ( Iii1 . source_cache . cache_size ( ) == 0 ) :
    lisp_map_cache . delete_cache ( self . group )
    if 50 - 50: I1Ii111 . I1Ii111 . OoO0O00 + I11i * o0oOOo0O0Ooo
    if 45 - 45: I11i * I11i * iIii1I11I1II1
    if 85 - 85: oO0o * I1Ii111 * OoooooooOO % i11iIiiIii . Ii1I % i1IIi
    if 40 - 40: Oo0Ooo
 def add_source_entry ( self , source_mc ) :
  if ( self . source_cache == None ) : self . source_cache = lisp_cache ( )
  self . source_cache . add_cache ( source_mc . eid , source_mc )
  if 40 - 40: oO0o % i1IIi % ooOoO0o . oO0o % oO0o
  if 69 - 69: OoooooooOO . oO0o / OoooooooOO / OoOoOO00
 def lookup_source_cache ( self , source , exact ) :
  if ( self . source_cache == None ) : return ( None )
  return ( self . source_cache . lookup_cache ( source , exact ) )
  if 41 - 41: ooOoO0o + o0oOOo0O0Ooo . o0oOOo0O0Ooo / oO0o * IiII
  if 96 - 96: IiII % O0 + Ii1I / o0oOOo0O0Ooo + I1ii11iIi11i * II111iiii
 def dynamic_eid_configured ( self ) :
  return ( self . dynamic_eids != None )
  if 65 - 65: Ii1I * Oo0Ooo * Oo0Ooo . Ii1I
  if 4 - 4: i11iIiiIii - iIii1I11I1II1 % o0oOOo0O0Ooo * oO0o
 def star_secondary_iid ( self , prefix ) :
  if ( self . secondary_iid == None ) : return ( prefix )
  IIiI1i = "," + str ( self . secondary_iid )
  return ( prefix . replace ( IIiI1i , IIiI1i + "*" ) )
  if 19 - 19: Ii1I
  if 47 - 47: IiII - IiII
 def increment_decap_stats ( self , packet ) :
  OOo0000o0 = packet . udp_dport
  if ( OOo0000o0 == LISP_DATA_PORT ) :
   i1IIIIi1Ii111 = self . get_rloc ( packet . outer_dest )
  else :
   if 33 - 33: ooOoO0o
   if 23 - 23: I1Ii111 + OoO0O00
   if 35 - 35: Oo0Ooo - iIii1I11I1II1 - I1Ii111 % OOooOOo
   if 59 - 59: i1IIi
   for i1IIIIi1Ii111 in self . rloc_set :
    if ( i1IIIIi1Ii111 . translated_port != 0 ) : break
    if 38 - 38: Oo0Ooo . o0oOOo0O0Ooo % oO0o / i11iIiiIii * OoO0O00 % OoOoOO00
    if 18 - 18: OOooOOo
  if ( i1IIIIi1Ii111 != None ) : i1IIIIi1Ii111 . stats . increment ( len ( packet . packet ) )
  self . stats . increment ( len ( packet . packet ) )
  if 12 - 12: I1Ii111 % II111iiii / o0oOOo0O0Ooo - iIii1I11I1II1 + II111iiii
  if 41 - 41: OOooOOo
 def rtrs_in_rloc_set ( self ) :
  for i1IIIIi1Ii111 in self . rloc_set :
   if ( i1IIIIi1Ii111 . is_rtr ( ) ) : return ( True )
   if 8 - 8: i11iIiiIii . IiII . I1ii11iIi11i + i1IIi % I1Ii111
  return ( False )
  if 64 - 64: I1IiiI . Oo0Ooo * OoO0O00
  if 87 - 87: i1IIi / OoooooooOO
  if 68 - 68: I1Ii111 / iIii1I11I1II1
class lisp_dynamic_eid ( ) :
 def __init__ ( self ) :
  self . dynamic_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . uptime = lisp_get_timestamp ( )
  self . interface = None
  self . last_packet = None
  self . timeout = LISP_DEFAULT_DYN_EID_TIMEOUT
  if 8 - 8: ooOoO0o * IiII * OOooOOo / I1IiiI
  if 40 - 40: i11iIiiIii + OoooooooOO
 def get_timeout ( self , interface ) :
  try :
   iII1IIIII1I1 = lisp_myinterfaces [ interface ]
   self . timeout = iII1IIIII1I1 . dynamic_eid_timeout
  except :
   self . timeout = LISP_DEFAULT_DYN_EID_TIMEOUT
   if 39 - 39: i11iIiiIii * II111iiii
   if 75 - 75: OoooooooOO * IiII * OOooOOo
   if 1 - 1: iII111i * I1IiiI . o0oOOo0O0Ooo . IiII
   if 6 - 6: OOooOOo . oO0o / Oo0Ooo / o0oOOo0O0Ooo
class lisp_group_mapping ( ) :
 def __init__ ( self , group_name , ms_name , group_prefix , sources , rle_addr ) :
  self . group_name = group_name
  self . group_prefix = group_prefix
  self . use_ms_name = ms_name
  self . sources = sources
  self . rle_address = rle_addr
  if 24 - 24: Oo0Ooo % OoooooooOO
  if 78 - 78: OoooooooOO - II111iiii . OoO0O00 / I1ii11iIi11i
 def add_group ( self ) :
  lisp_group_mapping_list [ self . group_name ] = self
  if 86 - 86: OOooOOo * OoOoOO00 % i1IIi * IiII . I1ii11iIi11i
  if 72 - 72: i1IIi - I1Ii111 . O0 * OoO0O00
  if 62 - 62: Oo0Ooo . iII111i
lisp_site_flags = {
 "P" : "ETR is {}Requesting Map-Server to Proxy Map-Reply" ,
 "S" : "ETR is {}LISP-SEC capable" ,
 "I" : "xTR-ID and site-ID are {}included in Map-Register" ,
 "T" : "Use Map-Register TTL field to timeout registration is {}set" ,
 "R" : "Merging registrations are {}requested" ,
 "M" : "ETR is {}a LISP Mobile-Node" ,
 "N" : "ETR is {}requesting Map-Notify messages from Map-Server"
 }
if 15 - 15: i11iIiiIii * I11i + oO0o
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
  if 67 - 67: IiII . OoO0O00
  if 59 - 59: oO0o * o0oOOo0O0Ooo
  if 76 - 76: I1IiiI
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
  if 94 - 94: OoooooooOO * I1ii11iIi11i
  if 28 - 28: II111iiii / II111iiii / II111iiii
 def print_eid_tuple ( self ) :
  return ( lisp_print_eid_tuple ( self . eid , self . group ) )
  if 70 - 70: OoO0O00 + O0 * OoO0O00
  if 25 - 25: OoooooooOO . Oo0Ooo + OOooOOo + Oo0Ooo * O0 % i1IIi
 def print_flags ( self , html ) :
  if ( html == False ) :
   ooO000O = "{}-{}-{}-{}-{}-{}-{}" . format ( "P" if self . proxy_reply_requested else "p" ,
   # i1IIi % Oo0Ooo / oO0o % OoOoOO00 / OoOoOO00
 "S" if self . lisp_sec_present else "s" ,
 "I" if self . xtr_id_present else "i" ,
 "T" if self . use_register_ttl_requested else "t" ,
 "R" if self . merge_register_requested else "r" ,
 "M" if self . mobile_node_requested else "m" ,
 "N" if self . map_notify_requested else "n" )
  else :
   Ii11i1IiII = self . print_flags ( False )
   Ii11i1IiII = Ii11i1IiII . split ( "-" )
   ooO000O = ""
   for o0oO0o00O0 in Ii11i1IiII :
    oOOoo0O0OOO = lisp_site_flags [ o0oO0o00O0 . upper ( ) ]
    oOOoo0O0OOO = oOOoo0O0OOO . format ( "" if o0oO0o00O0 . isupper ( ) else "not " )
    ooO000O += lisp_span ( o0oO0o00O0 , oOOoo0O0OOO )
    if ( o0oO0o00O0 . lower ( ) != "n" ) : ooO000O += "-"
    if 29 - 29: O0 * IiII / I1ii11iIi11i + OoOoOO00 / O0 + i11iIiiIii
    if 92 - 92: ooOoO0o + Ii1I . o0oOOo0O0Ooo * II111iiii
  return ( ooO000O )
  if 8 - 8: OoOoOO00 . Oo0Ooo * I1Ii111
  if 62 - 62: Ii1I % OoO0O00 - I1Ii111 / i11iIiiIii
 def copy_state_to_parent ( self , child ) :
  self . xtr_id = child . xtr_id
  self . site_id = child . site_id
  self . first_registered = child . first_registered
  self . last_registered = child . last_registered
  self . last_registerer = child . last_registerer
  self . register_ttl = child . register_ttl
  if ( self . registered == False ) :
   self . first_registered = lisp_get_timestamp ( )
   if 27 - 27: i11iIiiIii . OoO0O00 + Ii1I
  self . auth_sha1_or_sha2 = child . auth_sha1_or_sha2
  self . registered = child . registered
  self . proxy_reply_requested = child . proxy_reply_requested
  self . lisp_sec_present = child . lisp_sec_present
  self . xtr_id_present = child . xtr_id_present
  self . use_register_ttl_requested = child . use_register_ttl_requested
  self . merge_register_requested = child . merge_register_requested
  self . mobile_node_requested = child . mobile_node_requested
  self . map_notify_requested = child . map_notify_requested
  if 47 - 47: I1Ii111 . iIii1I11I1II1 + i11iIiiIii
  if 75 - 75: iIii1I11I1II1 / OoO0O00 * OOooOOo % O0
 def build_sort_key ( self ) :
  OOooo = lisp_cache ( )
  ii11i1 , i1IIiI1iII = OOooo . build_key ( self . eid )
  IIi1iI11i1i1i = ""
  if ( self . group . is_null ( ) == False ) :
   IIiIIiI1III111iI , IIi1iI11i1i1i = OOooo . build_key ( self . group )
   IIi1iI11i1i1i = "-" + IIi1iI11i1i1i [ 0 : 12 ] + "-" + str ( IIiIIiI1III111iI ) + "-" + IIi1iI11i1i1i [ 12 : : ]
   if 83 - 83: I1Ii111 % oO0o % i11iIiiIii % i11iIiiIii - I1IiiI
  i1IIiI1iII = i1IIiI1iII [ 0 : 12 ] + "-" + str ( ii11i1 ) + "-" + i1IIiI1iII [ 12 : : ] + IIi1iI11i1i1i
  del ( OOooo )
  return ( i1IIiI1iII )
  if 16 - 16: ooOoO0o - o0oOOo0O0Ooo
  if 34 - 34: OoooooooOO - iII111i * iIii1I11I1II1 . OoO0O00
 def merge_in_site_eid ( self , child ) :
  oo0O0o0oO = False
  if ( self . group . is_null ( ) ) :
   self . merge_rlocs_in_site_eid ( )
  else :
   oo0O0o0oO = self . merge_rles_in_site_eid ( )
   if 61 - 61: IiII * IiII - OoOoOO00 % Ii1I . Oo0Ooo * II111iiii
   if 76 - 76: iII111i * O0 % i1IIi / Oo0Ooo * oO0o
   if 78 - 78: OoOoOO00 / II111iiii
   if 6 - 6: I1Ii111 . OoOoOO00
   if 75 - 75: Oo0Ooo + I11i
   if 87 - 87: I1IiiI
  if ( child != None ) :
   self . copy_state_to_parent ( child )
   self . map_registers_received += 1
   if 36 - 36: OoO0O00 . ooOoO0o . O0 / OoO0O00
  return ( oo0O0o0oO )
  if 50 - 50: Ii1I . OoOoOO00 * o0oOOo0O0Ooo
  if 68 - 68: IiII * oO0o / OoOoOO00 / I1Ii111
 def copy_rloc_records ( self ) :
  o0000ooOO = [ ]
  for ii1I1i11 in self . registered_rlocs :
   o0000ooOO . append ( copy . deepcopy ( ii1I1i11 ) )
   if 63 - 63: iII111i / iII111i % II111iiii . Oo0Ooo + I1Ii111 - o0oOOo0O0Ooo
  return ( o0000ooOO )
  if 27 - 27: II111iiii + i1IIi / OOooOOo - II111iiii * iII111i
  if 38 - 38: I1IiiI + IiII % OoOoOO00 % O0 - I11i - I1ii11iIi11i
 def merge_rlocs_in_site_eid ( self ) :
  self . registered_rlocs = [ ]
  for IIII in self . individual_registrations . values ( ) :
   if ( self . site_id != IIII . site_id ) : continue
   if ( IIII . registered == False ) : continue
   self . registered_rlocs += IIII . copy_rloc_records ( )
   if 60 - 60: O0 . O0 * oO0o
   if 13 - 13: OoooooooOO / ooOoO0o + IiII / oO0o + oO0o
   if 78 - 78: iII111i * o0oOOo0O0Ooo + OOooOOo
   if 39 - 39: ooOoO0o + o0oOOo0O0Ooo + OOooOOo * OoOoOO00
   if 98 - 98: iIii1I11I1II1 - oO0o
   if 91 - 91: iII111i % iII111i . ooOoO0o / iII111i
  o0000ooOO = [ ]
  for ii1I1i11 in self . registered_rlocs :
   if ( ii1I1i11 . rloc . is_null ( ) or len ( o0000ooOO ) == 0 ) :
    o0000ooOO . append ( ii1I1i11 )
    continue
    if 29 - 29: OoooooooOO + i11iIiiIii
   for iiIIII1I111 in o0000ooOO :
    if ( iiIIII1I111 . rloc . is_null ( ) ) : continue
    if ( ii1I1i11 . rloc . is_exact_match ( iiIIII1I111 . rloc ) ) : break
    if 24 - 24: Oo0Ooo % i1IIi
   if ( iiIIII1I111 == o0000ooOO [ - 1 ] ) : o0000ooOO . append ( ii1I1i11 )
   if 50 - 50: OoO0O00
  self . registered_rlocs = o0000ooOO
  if 52 - 52: o0oOOo0O0Ooo + O0
  if 13 - 13: OoO0O00
  if 56 - 56: OoOoOO00 . ooOoO0o * oO0o - I11i
  if 47 - 47: oO0o . i1IIi * I1ii11iIi11i % OOooOOo % IiII / Oo0Ooo
  if ( len ( self . registered_rlocs ) == 0 ) : self . registered = False
  return
  if 39 - 39: i11iIiiIii . OOooOOo + Oo0Ooo
  if 92 - 92: O0 * Oo0Ooo / o0oOOo0O0Ooo % OoO0O00
 def merge_rles_in_site_eid ( self ) :
  if 87 - 87: OoooooooOO / I11i . O0
  if 77 - 77: OOooOOo + oO0o * iIii1I11I1II1 / oO0o / OOooOOo . i11iIiiIii
  if 92 - 92: Oo0Ooo . o0oOOo0O0Ooo % OoooooooOO * i11iIiiIii * OoO0O00 * o0oOOo0O0Ooo
  if 48 - 48: iII111i * I1ii11iIi11i * oO0o % O0 . OoO0O00
  i1I1I = { }
  for ii1I1i11 in self . registered_rlocs :
   if ( ii1I1i11 . rle == None ) : continue
   for i1ooOoO in ii1I1i11 . rle . rle_nodes :
    I1Iii1I = i1ooOoO . address . print_address_no_iid ( )
    i1I1I [ I1Iii1I ] = i1ooOoO . address
    if 37 - 37: I11i . O0 - Oo0Ooo % iII111i
   break
   if 11 - 11: I11i % OoooooooOO
   if 96 - 96: i11iIiiIii * O0 + iIii1I11I1II1 . I11i * IiII + I1Ii111
   if 84 - 84: I1ii11iIi11i / o0oOOo0O0Ooo * II111iiii . i11iIiiIii
   if 68 - 68: OOooOOo . ooOoO0o / OOooOOo + i1IIi / I1IiiI
   if 80 - 80: Oo0Ooo + Oo0Ooo + oO0o % i1IIi / ooOoO0o
  self . merge_rlocs_in_site_eid ( )
  if 24 - 24: i11iIiiIii - ooOoO0o * iII111i - Ii1I . iIii1I11I1II1 . I1IiiI
  if 81 - 81: OoOoOO00 * OoOoOO00 + OOooOOo . I11i - oO0o
  if 85 - 85: O0 * I1IiiI . Oo0Ooo - IiII
  if 84 - 84: I1Ii111 . iIii1I11I1II1 . O0 * I1ii11iIi11i
  if 59 - 59: i1IIi . o0oOOo0O0Ooo . Oo0Ooo * I1Ii111 + OoooooooOO
  if 11 - 11: I11i * ooOoO0o % iIii1I11I1II1 - O0
  if 68 - 68: ooOoO0o * OoooooooOO - OoooooooOO
  if 59 - 59: Ii1I / I11i / I1Ii111 + IiII * I1ii11iIi11i
  iIOOoo0 = [ ]
  for ii1I1i11 in self . registered_rlocs :
   if ( self . registered_rlocs . index ( ii1I1i11 ) == 0 ) :
    iIOOoo0 . append ( ii1I1i11 )
    continue
    if 17 - 17: I1ii11iIi11i + OoooooooOO / iIii1I11I1II1 . II111iiii + Oo0Ooo
   if ( ii1I1i11 . rle == None ) : iIOOoo0 . append ( ii1I1i11 )
   if 7 - 7: O0 - I1ii11iIi11i - iIii1I11I1II1
  self . registered_rlocs = iIOOoo0
  if 96 - 96: OoOoOO00 . I1IiiI . I11i * OoooooooOO + OoooooooOO * O0
  if 90 - 90: I11i + I1ii11iIi11i + OoooooooOO + OoOoOO00 + IiII / iII111i
  if 75 - 75: i11iIiiIii
  if 27 - 27: I11i - IiII - I1Ii111
  if 90 - 90: OoO0O00 . oO0o * O0 / I11i % O0 + I1Ii111
  if 48 - 48: iIii1I11I1II1 . i11iIiiIii / OoooooooOO . i1IIi . o0oOOo0O0Ooo
  if 84 - 84: Ii1I
  O0OOOO0000O = lisp_rle ( "" )
  oO0o00000o = { }
  O0O00O = None
  for IIII in self . individual_registrations . values ( ) :
   if ( IIII . registered == False ) : continue
   iIiIiiIII1I1 = IIII . registered_rlocs [ 0 ] . rle
   if ( iIiIiiIII1I1 == None ) : continue
   if 8 - 8: i11iIiiIii * i1IIi . Oo0Ooo + I11i * I11i . OoOoOO00
   O0O00O = IIII . registered_rlocs [ 0 ] . rloc_name
   for ooOOo0O in iIiIiiIII1I1 . rle_nodes :
    I1Iii1I = ooOOo0O . address . print_address_no_iid ( )
    if ( oO0o00000o . has_key ( I1Iii1I ) ) : break
    if 37 - 37: Ii1I * O0 - I1Ii111
    i1ooOoO = lisp_rle_node ( )
    i1ooOoO . address . copy_address ( ooOOo0O . address )
    i1ooOoO . level = ooOOo0O . level
    i1ooOoO . rloc_name = O0O00O
    O0OOOO0000O . rle_nodes . append ( i1ooOoO )
    oO0o00000o [ I1Iii1I ] = ooOOo0O . address
    if 33 - 33: iIii1I11I1II1 . I11i
    if 63 - 63: oO0o - iII111i
    if 13 - 13: I1Ii111 / i1IIi % OoooooooOO / I11i
    if 66 - 66: I1Ii111 % o0oOOo0O0Ooo . iII111i . ooOoO0o + OOooOOo * II111iiii
    if 33 - 33: oO0o
    if 64 - 64: OoO0O00 % Oo0Ooo % I11i . iII111i % I1IiiI
  if ( len ( O0OOOO0000O . rle_nodes ) == 0 ) : O0OOOO0000O = None
  if ( len ( self . registered_rlocs ) != 0 ) :
   self . registered_rlocs [ 0 ] . rle = O0OOOO0000O
   if ( O0O00O ) : self . registered_rlocs [ 0 ] . rloc_name = None
   if 50 - 50: i1IIi + ooOoO0o - iIii1I11I1II1
   if 45 - 45: OoooooooOO / o0oOOo0O0Ooo / iII111i
   if 72 - 72: I1Ii111
   if 94 - 94: ooOoO0o . IiII - Ii1I + I1ii11iIi11i / ooOoO0o
   if 10 - 10: ooOoO0o . OOooOOo * O0 % II111iiii
  if ( i1I1I . keys ( ) == oO0o00000o . keys ( ) ) : return ( False )
  if 12 - 12: oO0o + I1IiiI * Oo0Ooo - iII111i
  lprint ( "{} {} from {} to {}" . format ( green ( self . print_eid_tuple ( ) , False ) , bold ( "RLE change" , False ) ,
  # i11iIiiIii / OoO0O00 % I1Ii111 * OoOoOO00 . o0oOOo0O0Ooo / ooOoO0o
 i1I1I . keys ( ) , oO0o00000o . keys ( ) ) )
  if 100 - 100: I1IiiI
  return ( True )
  if 27 - 27: OoOoOO00 * O0 - I11i
  if 98 - 98: OoOoOO00 % I1ii11iIi11i / OoOoOO00 % o0oOOo0O0Ooo / I1ii11iIi11i
 def add_cache ( self ) :
  if ( self . group . is_null ( ) ) :
   lisp_sites_by_eid . add_cache ( self . eid , self )
  else :
   iiiI1iI11i1i1 = lisp_sites_by_eid . lookup_cache ( self . group , True )
   if ( iiiI1iI11i1i1 == None ) :
    iiiI1iI11i1i1 = lisp_site_eid ( self . site )
    iiiI1iI11i1i1 . eid . copy_address ( self . group )
    iiiI1iI11i1i1 . group . copy_address ( self . group )
    lisp_sites_by_eid . add_cache ( self . group , iiiI1iI11i1i1 )
    if 21 - 21: I1IiiI * IiII - Oo0Ooo % ooOoO0o * i1IIi
    if 23 - 23: I11i * II111iiii + OoooooooOO . i1IIi + OoO0O00 + OoOoOO00
    if 52 - 52: iII111i * OoOoOO00
    if 80 - 80: I1Ii111 / IiII * o0oOOo0O0Ooo - OoOoOO00 / iIii1I11I1II1
    if 38 - 38: II111iiii / I11i + IiII % OoooooooOO
    iiiI1iI11i1i1 . parent_for_more_specifics = self . parent_for_more_specifics
    if 27 - 27: OoOoOO00 * OoO0O00 * OOooOOo % I1IiiI * o0oOOo0O0Ooo + I1ii11iIi11i
   if ( self . eid . is_null ( ) ) : self . eid . make_default_route ( iiiI1iI11i1i1 . group )
   iiiI1iI11i1i1 . add_source_entry ( self )
   if 73 - 73: i1IIi
   if 52 - 52: IiII / i11iIiiIii * O0
   if 67 - 67: OOooOOo / I11i - I1Ii111 % i11iIiiIii
 def delete_cache ( self ) :
  if ( self . group . is_null ( ) ) :
   lisp_sites_by_eid . delete_cache ( self . eid )
  else :
   iiiI1iI11i1i1 = lisp_sites_by_eid . lookup_cache ( self . group , True )
   if ( iiiI1iI11i1i1 == None ) : return
   if 3 - 3: oO0o + iII111i + OOooOOo
   IIII = iiiI1iI11i1i1 . lookup_source_cache ( self . eid , True )
   if ( IIII == None ) : return
   if 54 - 54: i11iIiiIii + OoO0O00 - IiII - iII111i / I11i
   if ( iiiI1iI11i1i1 . source_cache == None ) : return
   if 85 - 85: OOooOOo * OOooOOo * I1Ii111 - ooOoO0o . O0 % iII111i
   iiiI1iI11i1i1 . source_cache . delete_cache ( self . eid )
   if ( iiiI1iI11i1i1 . source_cache . cache_size ( ) == 0 ) :
    lisp_sites_by_eid . delete_cache ( self . group )
    if 5 - 5: i1IIi * iII111i . o0oOOo0O0Ooo - I1ii11iIi11i
    if 84 - 84: i1IIi
    if 17 - 17: IiII + iII111i * OoO0O00 / iII111i
    if 67 - 67: i1IIi * IiII . OoOoOO00 % iIii1I11I1II1 - iIii1I11I1II1 * I1ii11iIi11i
 def add_source_entry ( self , source_se ) :
  if ( self . source_cache == None ) : self . source_cache = lisp_cache ( )
  self . source_cache . add_cache ( source_se . eid , source_se )
  if 96 - 96: iII111i / i11iIiiIii / oO0o + Oo0Ooo
  if 65 - 65: OoOoOO00
 def lookup_source_cache ( self , source , exact ) :
  if ( self . source_cache == None ) : return ( None )
  return ( self . source_cache . lookup_cache ( source , exact ) )
  if 87 - 87: I11i % i1IIi + i11iIiiIii * II111iiii
  if 58 - 58: OoO0O00 * I1IiiI - II111iiii / Ii1I - I1IiiI % OoooooooOO
 def is_star_g ( self ) :
  if ( self . group . is_null ( ) ) : return ( False )
  return ( self . eid . is_exact_match ( self . group ) )
  if 33 - 33: IiII / i1IIi + I1Ii111
  if 5 - 5: O0 / iII111i % II111iiii . Oo0Ooo - I11i
 def eid_record_matches ( self , eid_record ) :
  if ( self . eid . is_exact_match ( eid_record . eid ) == False ) : return ( False )
  if ( eid_record . group . is_null ( ) ) : return ( True )
  return ( eid_record . group . is_exact_match ( self . group ) )
  if 84 - 84: oO0o * iII111i % i11iIiiIii - O0 . iIii1I11I1II1 - OoOoOO00
  if 73 - 73: OoOoOO00
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
  if 66 - 66: Oo0Ooo
  if 42 - 42: i11iIiiIii / II111iiii . OOooOOo
 def rtrs_in_rloc_set ( self ) :
  for ii1I1i11 in self . registered_rlocs :
   if ( ii1I1i11 . is_rtr ( ) ) : return ( True )
   if 65 - 65: OoOoOO00 % II111iiii + Oo0Ooo
  return ( False )
  if 24 - 24: OoO0O00 % OoooooooOO
  if 16 - 16: OoOoOO00 % Oo0Ooo * OoOoOO00 . Ii1I
 def is_rtr_in_rloc_set ( self , rtr_rloc ) :
  for ii1I1i11 in self . registered_rlocs :
   if ( ii1I1i11 . rloc . is_exact_match ( rtr_rloc ) == False ) : continue
   if ( ii1I1i11 . is_rtr ( ) ) : return ( True )
   if 91 - 91: I1Ii111 - OoooooooOO . i1IIi . I1ii11iIi11i
  return ( False )
  if 37 - 37: IiII - oO0o
  if 92 - 92: I1IiiI
 def is_rloc_in_rloc_set ( self , rloc ) :
  for ii1I1i11 in self . registered_rlocs :
   if ( ii1I1i11 . rle ) :
    for O0OOOO0000O in ii1I1i11 . rle . rle_nodes :
     if ( O0OOOO0000O . address . is_exact_match ( rloc ) ) : return ( True )
     if 51 - 51: OoO0O00 + Oo0Ooo - OOooOOo + I1ii11iIi11i
     if 32 - 32: I1ii11iIi11i % OoOoOO00 + Oo0Ooo
   if ( ii1I1i11 . rloc . is_exact_match ( rloc ) ) : return ( True )
   if 92 - 92: II111iiii . O0 . iIii1I11I1II1 % IiII - i11iIiiIii
  return ( False )
  if 9 - 9: OoO0O00
  if 60 - 60: O0 / OoOoOO00 % i11iIiiIii % II111iiii / OoooooooOO
 def do_rloc_sets_match ( self , prev_rloc_set ) :
  if ( len ( self . registered_rlocs ) != len ( prev_rloc_set ) ) : return ( False )
  if 52 - 52: ooOoO0o
  for ii1I1i11 in prev_rloc_set :
   I1I1ii1 = ii1I1i11 . rloc
   if ( self . is_rloc_in_rloc_set ( I1I1ii1 ) == False ) : return ( False )
   if 100 - 100: Oo0Ooo - o0oOOo0O0Ooo + iIii1I11I1II1 / ooOoO0o % iIii1I11I1II1
  return ( True )
  if 4 - 4: OoOoOO00 / Oo0Ooo - OoO0O00 . OoOoOO00 / I1Ii111
  if 60 - 60: OOooOOo * I1Ii111
  if 17 - 17: iII111i * I11i / iIii1I11I1II1 - II111iiii
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
   if 97 - 97: II111iiii * o0oOOo0O0Ooo
  self . last_used = 0
  self . last_reply = 0
  self . last_nonce = 0
  self . map_requests_sent = 0
  self . neg_map_replies_received = 0
  self . total_rtt = 0
  if 13 - 13: o0oOOo0O0Ooo . II111iiii
  if 76 - 76: II111iiii + I1Ii111 . OoooooooOO / IiII % i11iIiiIii
 def resolve_dns_name ( self ) :
  if ( self . dns_name == None ) : return
  if ( self . last_dns_resolve and
 time . time ( ) - self . last_dns_resolve < 30 ) : return
  if 87 - 87: Ii1I / OoOoOO00 / OOooOOo
  try :
   II111 = socket . gethostbyname_ex ( self . dns_name )
   self . last_dns_resolve = lisp_get_timestamp ( )
   IIiIIIiII1Ii1 = II111 [ 2 ]
  except :
   return
   if 39 - 39: IiII . II111iiii
   if 42 - 42: I1ii11iIi11i . Oo0Ooo * I1IiiI / Oo0Ooo
   if 83 - 83: i11iIiiIii / OoOoOO00
   if 37 - 37: iIii1I11I1II1 % IiII / i11iIiiIii - oO0o
   if 43 - 43: II111iiii - OoooooooOO
   if 11 - 11: I1IiiI
  if ( len ( IIiIIIiII1Ii1 ) <= self . a_record_index ) :
   self . delete_mr ( )
   return
   if 76 - 76: iII111i - II111iiii % Oo0Ooo . I1Ii111
   if 64 - 64: OoO0O00 - OoO0O00
  I1Iii1I = IIiIIIiII1Ii1 [ self . a_record_index ]
  if ( I1Iii1I != self . map_resolver . print_address_no_iid ( ) ) :
   self . delete_mr ( )
   self . map_resolver . store_address ( I1Iii1I )
   self . insert_mr ( )
   if 93 - 93: Oo0Ooo . O0
   if 75 - 75: iII111i * II111iiii - I1IiiI
   if 30 - 30: i1IIi / ooOoO0o . ooOoO0o
   if 22 - 22: I11i % iIii1I11I1II1 - i11iIiiIii * OoOoOO00 - I1Ii111
   if 97 - 97: i11iIiiIii . OoOoOO00 + oO0o * O0 % OoO0O00 - Ii1I
   if 46 - 46: I1Ii111
  if ( lisp_is_decent_dns_suffix ( self . dns_name ) == False ) : return
  if ( self . a_record_index != 0 ) : return
  if 87 - 87: o0oOOo0O0Ooo - iII111i * OoO0O00 * o0oOOo0O0Ooo . o0oOOo0O0Ooo / OOooOOo
  for I1Iii1I in IIiIIIiII1Ii1 [ 1 : : ] :
   OOOO0o = lisp_address ( LISP_AFI_NONE , I1Iii1I , 0 , 0 )
   IIiIII1IIi = lisp_get_map_resolver ( OOOO0o , None )
   if ( IIiIII1IIi != None and IIiIII1IIi . a_record_index == IIiIIIiII1Ii1 . index ( I1Iii1I ) ) :
    continue
    if 50 - 50: i11iIiiIii - II111iiii * OoooooooOO + II111iiii - ooOoO0o
   IIiIII1IIi = lisp_mr ( I1Iii1I , None , None )
   IIiIII1IIi . a_record_index = IIiIIIiII1Ii1 . index ( I1Iii1I )
   IIiIII1IIi . dns_name = self . dns_name
   IIiIII1IIi . last_dns_resolve = lisp_get_timestamp ( )
   if 52 - 52: i1IIi + i1IIi * i1IIi / OoOoOO00
   if 98 - 98: iII111i . i1IIi + o0oOOo0O0Ooo * OoooooooOO - i11iIiiIii
   if 21 - 21: i11iIiiIii . oO0o * o0oOOo0O0Ooo + Oo0Ooo * OoOoOO00 * o0oOOo0O0Ooo
   if 33 - 33: I1IiiI + O0 - I11i
   if 90 - 90: I1Ii111 * OoooooooOO . iIii1I11I1II1 % OoO0O00 / I11i + iII111i
  OOoOoo0OO = [ ]
  for IIiIII1IIi in lisp_map_resolvers_list . values ( ) :
   if ( self . dns_name != IIiIII1IIi . dns_name ) : continue
   OOOO0o = IIiIII1IIi . map_resolver . print_address_no_iid ( )
   if ( OOOO0o in IIiIIIiII1Ii1 ) : continue
   OOoOoo0OO . append ( IIiIII1IIi )
   if 85 - 85: I1Ii111 - Oo0Ooo / I11i + OoOoOO00 . O0 - Oo0Ooo
  for IIiIII1IIi in OOoOoo0OO : IIiIII1IIi . delete_mr ( )
  if 24 - 24: I1IiiI + i1IIi
  if 21 - 21: iII111i / o0oOOo0O0Ooo
 def insert_mr ( self ) :
  i1IIiI1iII = self . mr_name + self . map_resolver . print_address ( )
  lisp_map_resolvers_list [ i1IIiI1iII ] = self
  if 61 - 61: iII111i . I1Ii111 % OoooooooOO / I1Ii111
  if 8 - 8: OoOoOO00
 def delete_mr ( self ) :
  i1IIiI1iII = self . mr_name + self . map_resolver . print_address ( )
  if ( lisp_map_resolvers_list . has_key ( i1IIiI1iII ) == False ) : return
  lisp_map_resolvers_list . pop ( i1IIiI1iII )
  if 80 - 80: IiII + I1ii11iIi11i + ooOoO0o
  if 48 - 48: O0 / I1IiiI % II111iiii
  if 10 - 10: Ii1I / I1Ii111 / O0 - II111iiii % IiII - ooOoO0o
class lisp_ddt_root ( ) :
 def __init__ ( self ) :
  self . root_address = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . public_key = ""
  self . priority = 0
  self . weight = 0
  if 48 - 48: OOooOOo * OoOoOO00 / oO0o + II111iiii - I1ii11iIi11i
  if 85 - 85: I1ii11iIi11i * OoooooooOO . OOooOOo * OOooOOo
  if 13 - 13: I1IiiI / Ii1I - OoOoOO00 . i1IIi * oO0o * o0oOOo0O0Ooo
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
  if 5 - 5: I11i - I1Ii111 * I11i - II111iiii + OOooOOo + II111iiii
  if 91 - 91: i1IIi + Oo0Ooo - I1ii11iIi11i + I1ii11iIi11i * O0 / O0
 def print_referral ( self , eid_indent , referral_indent ) :
  oo0oOOoo00OOOO = lisp_print_elapsed ( self . uptime )
  iiiI1i1I1IiiI = lisp_print_future ( self . expires )
  lprint ( "{}Referral EID {}, uptime/expires {}/{}, {} referrals:" . format ( eid_indent , green ( self . eid . print_prefix ( ) , False ) , oo0oOOoo00OOOO ,
  # iII111i . Ii1I . OoooooooOO / OoOoOO00
 iiiI1i1I1IiiI , len ( self . referral_set ) ) )
  if 85 - 85: II111iiii - II111iiii
  for iI1I111iI1I1I in self . referral_set . values ( ) :
   iI1I111iI1I1I . print_ref_node ( referral_indent )
   if 95 - 95: II111iiii + II111iiii + iII111i
   if 38 - 38: OoO0O00 * Ii1I * O0 / I1IiiI
   if 99 - 99: Oo0Ooo + ooOoO0o - I1ii11iIi11i + I1Ii111 + Ii1I * I1IiiI
 def print_referral_type ( self ) :
  if ( self . eid . afi == LISP_AFI_ULTIMATE_ROOT ) : return ( "root" )
  if ( self . referral_type == LISP_DDT_ACTION_NULL ) :
   return ( "null-referral" )
   if 68 - 68: OoO0O00
  if ( self . referral_type == LISP_DDT_ACTION_SITE_NOT_FOUND ) :
   return ( "no-site-action" )
   if 79 - 79: Ii1I . IiII + OoOoOO00
  if ( self . referral_type > LISP_DDT_ACTION_MAX ) :
   return ( "invalid-action" )
   if 10 - 10: OoooooooOO * iII111i * ooOoO0o . Ii1I % I1Ii111 / I1ii11iIi11i
  return ( lisp_map_referral_action_string [ self . referral_type ] )
  if 71 - 71: Ii1I + IiII
  if 10 - 10: II111iiii % o0oOOo0O0Ooo . o0oOOo0O0Ooo % iII111i
 def print_eid_tuple ( self ) :
  return ( lisp_print_eid_tuple ( self . eid , self . group ) )
  if 2 - 2: OoooooooOO / IiII % Oo0Ooo % iIii1I11I1II1
  if 62 - 62: oO0o
 def print_ttl ( self ) :
  iiI = self . referral_ttl
  if ( iiI < 60 ) : return ( str ( iiI ) + " secs" )
  if 47 - 47: I1IiiI - O0 - I1ii11iIi11i . OoOoOO00
  if ( ( iiI % 60 ) == 0 ) :
   iiI = str ( iiI / 60 ) + " mins"
  else :
   iiI = str ( iiI ) + " secs"
   if 98 - 98: o0oOOo0O0Ooo - OoO0O00 . I1ii11iIi11i / OOooOOo
  return ( iiI )
  if 43 - 43: I1IiiI + OOooOOo + o0oOOo0O0Ooo
  if 44 - 44: o0oOOo0O0Ooo % OoO0O00 . OoooooooOO
 def is_referral_negative ( self ) :
  return ( self . referral_type in ( LISP_DDT_ACTION_MS_NOT_REG , LISP_DDT_ACTION_DELEGATION_HOLE ,
  # I1Ii111 - Oo0Ooo
 LISP_DDT_ACTION_NOT_AUTH ) )
  if 66 - 66: iII111i - IiII . I1Ii111
  if 29 - 29: I1Ii111 - Ii1I + O0 - oO0o - O0
 def add_cache ( self ) :
  if ( self . group . is_null ( ) ) :
   lisp_referral_cache . add_cache ( self . eid , self )
  else :
   OOO0OoOooO0 = lisp_referral_cache . lookup_cache ( self . group , True )
   if ( OOO0OoOooO0 == None ) :
    OOO0OoOooO0 = lisp_referral ( )
    OOO0OoOooO0 . eid . copy_address ( self . group )
    OOO0OoOooO0 . group . copy_address ( self . group )
    lisp_referral_cache . add_cache ( self . group , OOO0OoOooO0 )
    if 68 - 68: iII111i + II111iiii + I1ii11iIi11i * OOooOOo / oO0o
   if ( self . eid . is_null ( ) ) : self . eid . make_default_route ( OOO0OoOooO0 . group )
   OOO0OoOooO0 . add_source_entry ( self )
   if 41 - 41: OOooOOo + Oo0Ooo % I1IiiI
   if 3 - 3: ooOoO0o * Ii1I
   if 29 - 29: OoooooooOO + OOooOOo
 def delete_cache ( self ) :
  if ( self . group . is_null ( ) ) :
   lisp_referral_cache . delete_cache ( self . eid )
  else :
   OOO0OoOooO0 = lisp_referral_cache . lookup_cache ( self . group , True )
   if ( OOO0OoOooO0 == None ) : return
   if 68 - 68: O0 + IiII / iII111i - OoOoOO00
   Ii1Oooo0 = OOO0OoOooO0 . lookup_source_cache ( self . eid , True )
   if ( Ii1Oooo0 == None ) : return
   if 5 - 5: I1IiiI * OoooooooOO - II111iiii
   OOO0OoOooO0 . source_cache . delete_cache ( self . eid )
   if ( OOO0OoOooO0 . source_cache . cache_size ( ) == 0 ) :
    lisp_referral_cache . delete_cache ( self . group )
    if 64 - 64: i1IIi
    if 77 - 77: OOooOOo - i1IIi / II111iiii . I1Ii111 + O0
    if 1 - 1: OoooooooOO % iIii1I11I1II1 * I1ii11iIi11i
    if 17 - 17: Ii1I * i1IIi % OoO0O00
 def add_source_entry ( self , source_ref ) :
  if ( self . source_cache == None ) : self . source_cache = lisp_cache ( )
  self . source_cache . add_cache ( source_ref . eid , source_ref )
  if 12 - 12: I1ii11iIi11i
  if 86 - 86: iIii1I11I1II1 % iII111i
 def lookup_source_cache ( self , source , exact ) :
  if ( self . source_cache == None ) : return ( None )
  return ( self . source_cache . lookup_cache ( source , exact ) )
  if 80 - 80: Oo0Ooo
  if 37 - 37: i11iIiiIii - I1Ii111
  if 50 - 50: I1IiiI / Ii1I / Ii1I + O0 % I11i - i1IIi
class lisp_referral_node ( ) :
 def __init__ ( self ) :
  self . referral_address = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . priority = 0
  self . weight = 0
  self . updown = True
  self . map_requests_sent = 0
  self . no_responses = 0
  self . uptime = lisp_get_timestamp ( )
  if 72 - 72: II111iiii . OoO0O00 . II111iiii * I1ii11iIi11i
  if 42 - 42: II111iiii
 def print_ref_node ( self , indent ) :
  III11I1 = lisp_print_elapsed ( self . uptime )
  lprint ( "{}referral {}, uptime {}, {}, priority/weight: {}/{}" . format ( indent , red ( self . referral_address . print_address ( ) , False ) , III11I1 ,
  # O0 - O0 - I1Ii111
 "up" if self . updown else "down" , self . priority , self . weight ) )
  if 88 - 88: o0oOOo0O0Ooo % I1Ii111
  if 4 - 4: i11iIiiIii + o0oOOo0O0Ooo % I11i - I1ii11iIi11i * I1ii11iIi11i
  if 87 - 87: I1Ii111 % i11iIiiIii + O0
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
   if 67 - 67: OoooooooOO / i1IIi / ooOoO0o . i1IIi - i11iIiiIii . i1IIi
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
   if 41 - 41: i11iIiiIii / ooOoO0o - Ii1I + I11i
   if 15 - 15: I1ii11iIi11i
   if 22 - 22: iIii1I11I1II1 - i1IIi - i11iIiiIii / I1IiiI + o0oOOo0O0Ooo
 def resolve_dns_name ( self ) :
  if ( self . dns_name == None ) : return
  if ( self . last_dns_resolve and
 time . time ( ) - self . last_dns_resolve < 30 ) : return
  if 56 - 56: I1IiiI . ooOoO0o
  try :
   II111 = socket . gethostbyname_ex ( self . dns_name )
   self . last_dns_resolve = lisp_get_timestamp ( )
   IIiIIIiII1Ii1 = II111 [ 2 ]
  except :
   return
   if 35 - 35: iIii1I11I1II1 % Oo0Ooo + o0oOOo0O0Ooo * o0oOOo0O0Ooo % ooOoO0o
   if 10 - 10: I1ii11iIi11i / II111iiii % II111iiii - OoooooooOO * o0oOOo0O0Ooo / ooOoO0o
   if 26 - 26: OoO0O00 . O0 * iII111i % OoOoOO00 % iIii1I11I1II1
   if 37 - 37: iII111i - ooOoO0o * Ii1I + II111iiii * i11iIiiIii
   if 8 - 8: OoooooooOO % I11i - iII111i * OOooOOo . O0
   if 40 - 40: I1Ii111 . oO0o + OoO0O00 % Oo0Ooo / II111iiii
  if ( len ( IIiIIIiII1Ii1 ) <= self . a_record_index ) :
   self . delete_ms ( )
   return
   if 19 - 19: i11iIiiIii
   if 20 - 20: i11iIiiIii . II111iiii - I1ii11iIi11i / ooOoO0o % i11iIiiIii
  I1Iii1I = IIiIIIiII1Ii1 [ self . a_record_index ]
  if ( I1Iii1I != self . map_server . print_address_no_iid ( ) ) :
   self . delete_ms ( )
   self . map_server . store_address ( I1Iii1I )
   self . insert_ms ( )
   if 35 - 35: Oo0Ooo - I1ii11iIi11i . Oo0Ooo
   if 13 - 13: II111iiii / OoOoOO00 * iII111i % O0 % I1ii11iIi11i * i11iIiiIii
   if 92 - 92: i11iIiiIii + OoO0O00
   if 94 - 94: I1ii11iIi11i + OoO0O00 . II111iiii + oO0o . II111iiii
   if 96 - 96: i11iIiiIii
   if 66 - 66: ooOoO0o * iII111i - iII111i - O0 . o0oOOo0O0Ooo
  if ( lisp_is_decent_dns_suffix ( self . dns_name ) == False ) : return
  if ( self . a_record_index != 0 ) : return
  if 23 - 23: iIii1I11I1II1 / I11i % OoOoOO00 . OoO0O00
  for I1Iii1I in IIiIIIiII1Ii1 [ 1 : : ] :
   OOOO0o = lisp_address ( LISP_AFI_NONE , I1Iii1I , 0 , 0 )
   ii1I111i = lisp_get_map_server ( OOOO0o )
   if ( ii1I111i != None and ii1I111i . a_record_index == IIiIIIiII1Ii1 . index ( I1Iii1I ) ) :
    continue
    if 90 - 90: iIii1I11I1II1 - OOooOOo . Ii1I % OoO0O00
   ii1I111i = copy . deepcopy ( self )
   ii1I111i . map_server . store_address ( I1Iii1I )
   ii1I111i . a_record_index = IIiIIIiII1Ii1 . index ( I1Iii1I )
   ii1I111i . last_dns_resolve = lisp_get_timestamp ( )
   ii1I111i . insert_ms ( )
   if 89 - 89: i11iIiiIii
   if 86 - 86: Oo0Ooo % iIii1I11I1II1 . II111iiii / I11i % OoO0O00 % OoO0O00
   if 40 - 40: o0oOOo0O0Ooo . iIii1I11I1II1 * Oo0Ooo * i1IIi
   if 94 - 94: oO0o - II111iiii + OoOoOO00
   if 90 - 90: Oo0Ooo + Oo0Ooo + I1Ii111
  OOoOoo0OO = [ ]
  for ii1I111i in lisp_map_servers_list . values ( ) :
   if ( self . dns_name != ii1I111i . dns_name ) : continue
   OOOO0o = ii1I111i . map_server . print_address_no_iid ( )
   if ( OOOO0o in IIiIIIiII1Ii1 ) : continue
   OOoOoo0OO . append ( ii1I111i )
   if 81 - 81: i1IIi % iIii1I11I1II1 % Ii1I * ooOoO0o % i1IIi * I1IiiI
  for ii1I111i in OOoOoo0OO : ii1I111i . delete_ms ( )
  if 15 - 15: ooOoO0o
  if 26 - 26: IiII % ooOoO0o / OOooOOo
 def insert_ms ( self ) :
  i1IIiI1iII = self . ms_name + self . map_server . print_address ( )
  lisp_map_servers_list [ i1IIiI1iII ] = self
  if 14 - 14: i11iIiiIii . I1ii11iIi11i
  if 20 - 20: O0 . iIii1I11I1II1 * I1ii11iIi11i - O0 + I1ii11iIi11i / I1IiiI
 def delete_ms ( self ) :
  i1IIiI1iII = self . ms_name + self . map_server . print_address ( )
  if ( lisp_map_servers_list . has_key ( i1IIiI1iII ) == False ) : return
  lisp_map_servers_list . pop ( i1IIiI1iII )
  if 67 - 67: OoO0O00 / OoOoOO00 / i11iIiiIii % OoOoOO00
  if 54 - 54: o0oOOo0O0Ooo . i11iIiiIii + I1IiiI * ooOoO0o - ooOoO0o
  if 28 - 28: I1Ii111 . i11iIiiIii * oO0o % ooOoO0o / iII111i . OOooOOo
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
  if 57 - 57: OoooooooOO . iIii1I11I1II1 % iII111i % Oo0Ooo
  if 92 - 92: I1Ii111 - Ii1I + I1Ii111
 def add_interface ( self ) :
  lisp_myinterfaces [ self . device ] = self
  if 8 - 8: Oo0Ooo . iII111i / i11iIiiIii + iIii1I11I1II1 - OoOoOO00
  if 1 - 1: i11iIiiIii
 def get_instance_id ( self ) :
  return ( self . instance_id )
  if 25 - 25: OoooooooOO / II111iiii . OOooOOo * OoOoOO00 - OoooooooOO
  if 8 - 8: iII111i . iIii1I11I1II1 * O0
 def get_socket ( self ) :
  return ( self . raw_socket )
  if 87 - 87: OoO0O00 * OoooooooOO + OoOoOO00 . OoooooooOO + o0oOOo0O0Ooo + Ii1I
  if 26 - 26: i1IIi
 def get_bridge_socket ( self ) :
  return ( self . bridge_socket )
  if 33 - 33: OoOoOO00 + OOooOOo . i1IIi . IiII
  if 78 - 78: OoooooooOO * I11i / OOooOOo + oO0o . I1Ii111 * iII111i
 def does_dynamic_eid_match ( self , eid ) :
  if ( self . dynamic_eid . is_null ( ) ) : return ( False )
  return ( eid . is_more_specific ( self . dynamic_eid ) )
  if 98 - 98: i1IIi
  if 28 - 28: Oo0Ooo . I1Ii111 . iIii1I11I1II1 + I1IiiI . II111iiii * I1ii11iIi11i
 def set_socket ( self , device ) :
  i1I1iIi1IiI = socket . socket ( socket . AF_INET , socket . SOCK_RAW , socket . IPPROTO_RAW )
  i1I1iIi1IiI . setsockopt ( socket . SOL_IP , socket . IP_HDRINCL , 1 )
  try :
   i1I1iIi1IiI . setsockopt ( socket . SOL_SOCKET , socket . SO_BINDTODEVICE , device )
  except :
   i1I1iIi1IiI . close ( )
   i1I1iIi1IiI = None
   if 26 - 26: i1IIi / i11iIiiIii * II111iiii
  self . raw_socket = i1I1iIi1IiI
  if 11 - 11: Oo0Ooo % i1IIi
  if 70 - 70: II111iiii * Oo0Ooo * OOooOOo - I1IiiI + iIii1I11I1II1 + ooOoO0o
 def set_bridge_socket ( self , device ) :
  i1I1iIi1IiI = socket . socket ( socket . PF_PACKET , socket . SOCK_RAW )
  try :
   i1I1iIi1IiI = i1I1iIi1IiI . bind ( ( device , 0 ) )
   self . bridge_socket = i1I1iIi1IiI
  except :
   return
   if 27 - 27: I1ii11iIi11i - I1Ii111 * O0 % ooOoO0o / I1IiiI
   if 53 - 53: i11iIiiIii * i11iIiiIii % O0 % IiII
   if 57 - 57: I1IiiI % i1IIi * OoO0O00 + I1Ii111 . I11i % I11i
   if 69 - 69: I1ii11iIi11i / OoOoOO00 + iIii1I11I1II1
class lisp_datetime ( ) :
 def __init__ ( self , datetime_str ) :
  self . datetime_name = datetime_str
  self . datetime = None
  self . parse_datetime ( )
  if 8 - 8: OoooooooOO
  if 72 - 72: OoooooooOO % I1ii11iIi11i - OoO0O00 . OoooooooOO
 def valid_datetime ( self ) :
  OOO00OO0ooOO = self . datetime_name
  if ( OOO00OO0ooOO . find ( ":" ) == - 1 ) : return ( False )
  if ( OOO00OO0ooOO . find ( "-" ) == - 1 ) : return ( False )
  iii1i11i1 , ooOo0 , I11IIiIIi , time = OOO00OO0ooOO [ 0 : 4 ] , OOO00OO0ooOO [ 5 : 7 ] , OOO00OO0ooOO [ 8 : 10 ] , OOO00OO0ooOO [ 11 : : ]
  if 63 - 63: OoOoOO00 - o0oOOo0O0Ooo % II111iiii - Ii1I
  if ( ( iii1i11i1 + ooOo0 + I11IIiIIi ) . isdigit ( ) == False ) : return ( False )
  if ( ooOo0 < "01" and ooOo0 > "12" ) : return ( False )
  if ( I11IIiIIi < "01" and I11IIiIIi > "31" ) : return ( False )
  if 81 - 81: iII111i % OOooOOo * oO0o
  O0OoOOoO , oo0o00Oo0 , iIIi1IiIi = time . split ( ":" )
  if 10 - 10: IiII * Ii1I . OoO0O00 % OOooOOo
  if ( ( O0OoOOoO + oo0o00Oo0 + iIIi1IiIi ) . isdigit ( ) == False ) : return ( False )
  if ( O0OoOOoO < "00" and O0OoOOoO > "23" ) : return ( False )
  if ( oo0o00Oo0 < "00" and oo0o00Oo0 > "59" ) : return ( False )
  if ( iIIi1IiIi < "00" and iIIi1IiIi > "59" ) : return ( False )
  return ( True )
  if 56 - 56: I1ii11iIi11i . OoOoOO00 + o0oOOo0O0Ooo . OOooOOo - OOooOOo - I1Ii111
  if 18 - 18: iII111i . II111iiii * I1IiiI
 def parse_datetime ( self ) :
  O0OOoO0Oo0000 = self . datetime_name
  O0OOoO0Oo0000 = O0OOoO0Oo0000 . replace ( "-" , "" )
  O0OOoO0Oo0000 = O0OOoO0Oo0000 . replace ( ":" , "" )
  self . datetime = int ( O0OOoO0Oo0000 )
  if 96 - 96: Oo0Ooo % o0oOOo0O0Ooo . OoOoOO00 % i11iIiiIii / OoooooooOO
  if 87 - 87: OoooooooOO - Ii1I . I11i / I1Ii111 . i1IIi
 def now ( self ) :
  III11I1 = datetime . datetime . now ( ) . strftime ( "%Y-%m-%d-%H:%M:%S" )
  III11I1 = lisp_datetime ( III11I1 )
  return ( III11I1 )
  if 86 - 86: i1IIi . oO0o % OOooOOo
  if 99 - 99: oO0o / I1Ii111 * oO0o * I11i
 def print_datetime ( self ) :
  return ( self . datetime_name )
  if 38 - 38: o0oOOo0O0Ooo + OoOoOO00
  if 24 - 24: Ii1I - OOooOOo - o0oOOo0O0Ooo - I1Ii111 / OoooooooOO
 def future ( self ) :
  return ( self . datetime > self . now ( ) . datetime )
  if 17 - 17: OoO0O00
  if 79 - 79: Ii1I - II111iiii
 def past ( self ) :
  return ( self . future ( ) == False )
  if 57 - 57: II111iiii / OoooooooOO
  if 4 - 4: I11i * OoOoOO00
 def now_in_range ( self , upper ) :
  return ( self . past ( ) and upper . future ( ) )
  if 18 - 18: iIii1I11I1II1 % OOooOOo - I1ii11iIi11i * i1IIi + Oo0Ooo
  if 87 - 87: oO0o . I11i
 def this_year ( self ) :
  iII1I11II = str ( self . now ( ) . datetime ) [ 0 : 4 ]
  III11I1 = str ( self . datetime ) [ 0 : 4 ]
  return ( III11I1 == iII1I11II )
  if 14 - 14: iIii1I11I1II1 - iIii1I11I1II1 * OOooOOo * iII111i - I1ii11iIi11i / Oo0Ooo
  if 50 - 50: oO0o . Oo0Ooo / o0oOOo0O0Ooo * O0 % Oo0Ooo
 def this_month ( self ) :
  iII1I11II = str ( self . now ( ) . datetime ) [ 0 : 6 ]
  III11I1 = str ( self . datetime ) [ 0 : 6 ]
  return ( III11I1 == iII1I11II )
  if 52 - 52: I1IiiI % I1Ii111 - i1IIi . o0oOOo0O0Ooo % I1ii11iIi11i
  if 34 - 34: o0oOOo0O0Ooo / OoOoOO00
 def today ( self ) :
  iII1I11II = str ( self . now ( ) . datetime ) [ 0 : 8 ]
  III11I1 = str ( self . datetime ) [ 0 : 8 ]
  return ( III11I1 == iII1I11II )
  if 74 - 74: IiII + i1IIi . II111iiii
  if 1 - 1: Ii1I - o0oOOo0O0Ooo / i11iIiiIii
  if 24 - 24: O0
  if 59 - 59: OoO0O00 % iII111i + oO0o * II111iiii . OOooOOo
  if 26 - 26: OOooOOo % OoooooooOO . Ii1I / iIii1I11I1II1 * I1IiiI
  if 85 - 85: IiII / Ii1I - I1ii11iIi11i * OOooOOo
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
  if 19 - 19: I1ii11iIi11i
  if 12 - 12: ooOoO0o * I1ii11iIi11i * O0 / oO0o + iII111i - iIii1I11I1II1
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
  if 81 - 81: Ii1I
  if 87 - 87: O0 % iII111i
 def match_policy_map_request ( self , mr , srloc ) :
  for O00oooO0 in self . match_clauses :
   o0O0o = O00oooO0 . source_eid
   I1iIIiiiiIII = mr . source_eid
   if ( o0O0o and I1iIIiiiiIII and I1iIIiiiiIII . is_more_specific ( o0O0o ) == False ) : continue
   if 57 - 57: Ii1I
   o0O0o = O00oooO0 . dest_eid
   I1iIIiiiiIII = mr . target_eid
   if ( o0O0o and I1iIIiiiiIII and I1iIIiiiiIII . is_more_specific ( o0O0o ) == False ) : continue
   if 49 - 49: I11i
   o0O0o = O00oooO0 . source_rloc
   I1iIIiiiiIII = srloc
   if ( o0O0o and I1iIIiiiiIII and I1iIIiiiiIII . is_more_specific ( o0O0o ) == False ) : continue
   ooO = O00oooO0 . datetime_lower
   IIIIIi1I11i = O00oooO0 . datetime_upper
   if ( ooO and IIIIIi1I11i and ooO . now_in_range ( IIIIIi1I11i ) == False ) : continue
   return ( True )
   if 42 - 42: O0
  return ( False )
  if 55 - 55: i11iIiiIii % OOooOOo
  if 10 - 10: OoOoOO00 / i11iIiiIii
 def set_policy_map_reply ( self ) :
  I1iiI11I = ( self . set_rloc_address == None and
 self . set_rloc_record_name == None and self . set_geo_name == None and
 self . set_elp_name == None and self . set_rle_name == None )
  if ( I1iiI11I ) : return ( None )
  if 36 - 36: II111iiii . O0 % O0 * iII111i * iIii1I11I1II1
  i1IIIIi1Ii111 = lisp_rloc ( )
  if ( self . set_rloc_address ) :
   i1IIIIi1Ii111 . rloc . copy_address ( self . set_rloc_address )
   I1Iii1I = i1IIIIi1Ii111 . rloc . print_address_no_iid ( )
   lprint ( "Policy set-rloc-address to {}" . format ( I1Iii1I ) )
   if 42 - 42: iII111i . OOooOOo + oO0o / OoOoOO00
  if ( self . set_rloc_record_name ) :
   i1IIIIi1Ii111 . rloc_name = self . set_rloc_record_name
   iI11i1Ii = blue ( i1IIIIi1Ii111 . rloc_name , False )
   lprint ( "Policy set-rloc-record-name to {}" . format ( iI11i1Ii ) )
   if 54 - 54: ooOoO0o % o0oOOo0O0Ooo + i11iIiiIii / ooOoO0o * II111iiii * Ii1I
  if ( self . set_geo_name ) :
   i1IIIIi1Ii111 . geo_name = self . set_geo_name
   iI11i1Ii = i1IIIIi1Ii111 . geo_name
   O000OOO = "" if lisp_geo_list . has_key ( iI11i1Ii ) else "(not configured)"
   if 43 - 43: oO0o / II111iiii - iII111i / oO0o
   lprint ( "Policy set-geo-name '{}' {}" . format ( iI11i1Ii , O000OOO ) )
   if 98 - 98: OoOoOO00 / OOooOOo
  if ( self . set_elp_name ) :
   i1IIIIi1Ii111 . elp_name = self . set_elp_name
   iI11i1Ii = i1IIIIi1Ii111 . elp_name
   O000OOO = "" if lisp_elp_list . has_key ( iI11i1Ii ) else "(not configured)"
   if 31 - 31: II111iiii % I11i - I11i
   lprint ( "Policy set-elp-name '{}' {}" . format ( iI11i1Ii , O000OOO ) )
   if 17 - 17: iII111i . IiII + OOooOOo % I1Ii111 % i11iIiiIii
  if ( self . set_rle_name ) :
   i1IIIIi1Ii111 . rle_name = self . set_rle_name
   iI11i1Ii = i1IIIIi1Ii111 . rle_name
   O000OOO = "" if lisp_rle_list . has_key ( iI11i1Ii ) else "(not configured)"
   if 100 - 100: i11iIiiIii - O0 . OoO0O00 / O0 - Ii1I - IiII
   lprint ( "Policy set-rle-name '{}' {}" . format ( iI11i1Ii , O000OOO ) )
   if 72 - 72: Ii1I % O0 + II111iiii . i11iIiiIii
  if ( self . set_json_name ) :
   i1IIIIi1Ii111 . json_name = self . set_json_name
   iI11i1Ii = i1IIIIi1Ii111 . json_name
   O000OOO = "" if lisp_json_list . has_key ( iI11i1Ii ) else "(not configured)"
   if 66 - 66: II111iiii % I1IiiI
   lprint ( "Policy set-json-name '{}' {}" . format ( iI11i1Ii , O000OOO ) )
   if 88 - 88: iIii1I11I1II1 * iIii1I11I1II1 + I1Ii111 * OOooOOo . I1IiiI
  return ( i1IIIIi1Ii111 )
  if 96 - 96: I1ii11iIi11i
  if 37 - 37: OoO0O00 % o0oOOo0O0Ooo * O0 * O0 + iII111i
 def save_policy ( self ) :
  lisp_policies [ self . policy_name ] = self
  if 18 - 18: i11iIiiIii . o0oOOo0O0Ooo - OOooOOo % oO0o * Ii1I / I1IiiI
  if 46 - 46: o0oOOo0O0Ooo . ooOoO0o / Ii1I
  if 97 - 97: Ii1I . Oo0Ooo - O0 - I1Ii111 . i1IIi
class lisp_pubsub ( ) :
 def __init__ ( self , itr , port , nonce , ttl , xtr_id ) :
  self . itr = itr
  self . port = port
  self . nonce = nonce
  self . uptime = lisp_get_timestamp ( )
  self . ttl = ttl
  self . xtr_id = xtr_id
  self . map_notify_count = 0
  if 47 - 47: IiII * ooOoO0o - i1IIi % OoOoOO00 * i11iIiiIii . OoooooooOO
  if 84 - 84: OoOoOO00 / IiII - i1IIi - I1IiiI * OOooOOo
 def add ( self , eid_prefix ) :
  iiI = self . ttl
  i1OO0o = eid_prefix . print_prefix ( )
  if ( lisp_pubsub_cache . has_key ( i1OO0o ) == False ) :
   lisp_pubsub_cache [ i1OO0o ] = { }
   if 35 - 35: II111iiii
  oO0000o00OO = lisp_pubsub_cache [ i1OO0o ]
  if 28 - 28: I1Ii111 + IiII + I1ii11iIi11i . Ii1I
  O0o0o00o = "Add"
  if ( oO0000o00OO . has_key ( self . xtr_id ) ) :
   O0o0o00o = "Replace"
   del ( oO0000o00OO [ self . xtr_id ] )
   if 38 - 38: I1IiiI % I1ii11iIi11i * I1IiiI + OOooOOo - OoOoOO00
  oO0000o00OO [ self . xtr_id ] = self
  if 78 - 78: OOooOOo + I1Ii111
  i1OO0o = green ( i1OO0o , False )
  iIi1 = red ( self . itr . print_address_no_iid ( ) , False )
  IIIIiiii = "0x" + lisp_hex_string ( self . xtr_id )
  lprint ( "{} pubsub state {} for {}, xtr-id: {}, ttl {}" . format ( O0o0o00o , i1OO0o ,
 iIi1 , IIIIiiii , iiI ) )
  if 41 - 41: I11i + Oo0Ooo . Oo0Ooo / iII111i . OoOoOO00
  if 1 - 1: ooOoO0o + iII111i % i11iIiiIii / OoOoOO00
 def delete ( self , eid_prefix ) :
  i1OO0o = eid_prefix . print_prefix ( )
  iIi1 = red ( self . itr . print_address_no_iid ( ) , False )
  IIIIiiii = "0x" + lisp_hex_string ( self . xtr_id )
  if ( lisp_pubsub_cache . has_key ( i1OO0o ) ) :
   oO0000o00OO = lisp_pubsub_cache [ i1OO0o ]
   if ( oO0000o00OO . has_key ( self . xtr_id ) ) :
    oO0000o00OO . pop ( self . xtr_id )
    lprint ( "Remove pubsub state {} for {}, xtr-id: {}" . format ( i1OO0o ,
 iIi1 , IIIIiiii ) )
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
    if 51 - 51: iII111i % i11iIiiIii . OoO0O00 . IiII - OoOoOO00 * i1IIi
    if 14 - 14: I1ii11iIi11i . OoO0O00
    if 26 - 26: iII111i / ooOoO0o / Oo0Ooo / Oo0Ooo . I1ii11iIi11i * OOooOOo
class lisp_trace ( ) :
 def __init__ ( self ) :
  self . nonce = lisp_get_control_nonce ( )
  self . packet_json = [ ]
  self . local_rloc = None
  self . local_port = None
  self . lisp_socket = None
  if 25 - 25: IiII % I1IiiI / O0 % OOooOOo - OoooooooOO
  if 29 - 29: O0 + iII111i
 def print_trace ( self ) :
  I1I111iI1IIi = self . packet_json
  lprint ( "LISP-Trace JSON: '{}'" . format ( I1I111iI1IIi ) )
  if 100 - 100: II111iiii % O0 . OoOoOO00 . O0 + OoOoOO00 / Ii1I
  if 21 - 21: O0 / OOooOOo . Oo0Ooo % O0
 def encode ( self ) :
  O0ooOo0Oooo = socket . htonl ( 0x90000000 )
  iI1IIII1ii1 = struct . pack ( "II" , O0ooOo0Oooo , 0 )
  iI1IIII1ii1 += struct . pack ( "Q" , self . nonce )
  iI1IIII1ii1 += json . dumps ( self . packet_json )
  return ( iI1IIII1ii1 )
  if 95 - 95: O0 - I1IiiI / O0 % O0
  if 66 - 66: iII111i / i1IIi - Oo0Ooo . Ii1I
 def decode ( self , packet ) :
  oOO0OOOoO0ooo = "I"
  I1111ii1i = struct . calcsize ( oOO0OOOoO0ooo )
  if ( len ( packet ) < I1111ii1i ) : return ( False )
  O0ooOo0Oooo = struct . unpack ( oOO0OOOoO0ooo , packet [ : I1111ii1i ] ) [ 0 ]
  packet = packet [ I1111ii1i : : ]
  O0ooOo0Oooo = socket . ntohl ( O0ooOo0Oooo )
  if ( ( O0ooOo0Oooo & 0xff000000 ) != 0x90000000 ) : return ( False )
  if 65 - 65: I1ii11iIi11i % ooOoO0o - OoOoOO00 + ooOoO0o + Oo0Ooo
  if ( len ( packet ) < I1111ii1i ) : return ( False )
  I1Iii1I = struct . unpack ( oOO0OOOoO0ooo , packet [ : I1111ii1i ] ) [ 0 ]
  packet = packet [ I1111ii1i : : ]
  if 95 - 95: I1Ii111 * i11iIiiIii - I1IiiI - OoOoOO00 . ooOoO0o
  I1Iii1I = socket . ntohl ( I1Iii1I )
  IiII1iiiI1 = I1Iii1I >> 24
  O0oOo0 = ( I1Iii1I >> 16 ) & 0xff
  OO0oiiIi11 = ( I1Iii1I >> 8 ) & 0xff
  oo00OOOOOO0Oo = I1Iii1I & 0xff
  self . local_rloc = "{}.{}.{}.{}" . format ( IiII1iiiI1 , O0oOo0 , OO0oiiIi11 , oo00OOOOOO0Oo )
  self . local_port = str ( O0ooOo0Oooo & 0xffff )
  if 24 - 24: i1IIi * O0 + I1Ii111 * iIii1I11I1II1 . OOooOOo
  oOO0OOOoO0ooo = "Q"
  I1111ii1i = struct . calcsize ( oOO0OOOoO0ooo )
  if ( len ( packet ) < I1111ii1i ) : return ( False )
  self . nonce = struct . unpack ( oOO0OOOoO0ooo , packet [ : I1111ii1i ] ) [ 0 ]
  packet = packet [ I1111ii1i : : ]
  if ( len ( packet ) == 0 ) : return ( True )
  if 25 - 25: i1IIi
  try :
   self . packet_json = json . loads ( packet )
  except :
   return ( False )
   if 99 - 99: OOooOOo + OoooooooOO . I1Ii111 * Oo0Ooo % oO0o
  return ( True )
  if 75 - 75: iII111i
  if 8 - 8: I1ii11iIi11i . I11i / I1ii11iIi11i - i1IIi
 def myeid ( self , eid ) :
  return ( lisp_is_myeid ( eid ) )
  if 22 - 22: OOooOOo
  if 7 - 7: O0 - I1ii11iIi11i - OoO0O00 * I1Ii111
 def return_to_sender ( self , lisp_socket , rts_rloc , packet ) :
  i1IIIIi1Ii111 , OOo0000o0 = self . rtr_cache_nat_trace_find ( rts_rloc )
  if ( i1IIIIi1Ii111 == None ) :
   i1IIIIi1Ii111 , OOo0000o0 = rts_rloc . split ( ":" )
   OOo0000o0 = int ( OOo0000o0 )
   lprint ( "Send LISP-Trace to address {}:{}" . format ( i1IIIIi1Ii111 , OOo0000o0 ) )
  else :
   lprint ( "Send LISP-Trace to translated address {}:{}" . format ( i1IIIIi1Ii111 ,
 OOo0000o0 ) )
   if 17 - 17: o0oOOo0O0Ooo % OoO0O00 - I11i * o0oOOo0O0Ooo - i1IIi / I1IiiI
   if 100 - 100: OoO0O00 * i1IIi * o0oOOo0O0Ooo * Oo0Ooo - o0oOOo0O0Ooo
  if ( lisp_socket == None ) :
   i1I1iIi1IiI = socket . socket ( socket . AF_INET , socket . SOCK_DGRAM )
   i1I1iIi1IiI . bind ( ( "0.0.0.0" , LISP_TRACE_PORT ) )
   i1I1iIi1IiI . sendto ( packet , ( i1IIIIi1Ii111 , OOo0000o0 ) )
   i1I1iIi1IiI . close ( )
  else :
   lisp_socket . sendto ( packet , ( i1IIIIi1Ii111 , OOo0000o0 ) )
   if 100 - 100: iII111i - i11iIiiIii + OoO0O00
   if 50 - 50: II111iiii
   if 42 - 42: OOooOOo * I1Ii111
 def packet_length ( self ) :
  IIi1ii1 = 8 ; Ooo00O0O0O = 4 + 4 + 8
  return ( IIi1ii1 + Ooo00O0O0O + len ( json . dumps ( self . packet_json ) ) )
  if 81 - 81: iIii1I11I1II1 / OoooooooOO % II111iiii * i11iIiiIii - Oo0Ooo / I1ii11iIi11i
  if 78 - 78: OoooooooOO % Ii1I % oO0o + o0oOOo0O0Ooo + OoO0O00
 def rtr_cache_nat_trace ( self , translated_rloc , translated_port ) :
  i1IIiI1iII = self . local_rloc + ":" + self . local_port
  oOOO = ( translated_rloc , translated_port )
  lisp_rtr_nat_trace_cache [ i1IIiI1iII ] = oOOO
  lprint ( "Cache NAT Trace addresses {} -> {}" . format ( i1IIiI1iII , oOOO ) )
  if 53 - 53: Ii1I / o0oOOo0O0Ooo * I1IiiI / i1IIi / iII111i + iII111i
  if 66 - 66: i1IIi + I1IiiI
 def rtr_cache_nat_trace_find ( self , local_rloc_and_port ) :
  i1IIiI1iII = local_rloc_and_port
  try : oOOO = lisp_rtr_nat_trace_cache [ i1IIiI1iII ]
  except : oOOO = ( None , None )
  return ( oOOO )
  if 45 - 45: I1Ii111 . iII111i + OoO0O00 - O0
  if 71 - 71: Oo0Ooo + OOooOOo
  if 94 - 94: OOooOOo
  if 81 - 81: i11iIiiIii + iIii1I11I1II1 . i11iIiiIii / OOooOOo / iII111i
  if 34 - 34: i11iIiiIii - o0oOOo0O0Ooo * OoooooooOO * I1ii11iIi11i * Oo0Ooo % I1ii11iIi11i
  if 31 - 31: I11i . o0oOOo0O0Ooo
  if 82 - 82: I11i - Oo0Ooo
  if 77 - 77: I1IiiI + OoO0O00 % iIii1I11I1II1 - OOooOOo
  if 80 - 80: oO0o % I1ii11iIi11i * I1Ii111 + i1IIi
  if 79 - 79: oO0o + IiII
  if 4 - 4: iII111i + OoooooooOO / I1Ii111
def lisp_get_map_server ( address ) :
 for ii1I111i in lisp_map_servers_list . values ( ) :
  if ( ii1I111i . map_server . is_exact_match ( address ) ) : return ( ii1I111i )
  if 57 - 57: I1IiiI . iIii1I11I1II1 % iII111i * iII111i / I1Ii111
 return ( None )
 if 30 - 30: O0 / I11i % OoOoOO00 * I1Ii111 / O0 % ooOoO0o
 if 36 - 36: iIii1I11I1II1 . iII111i * I1IiiI . I1IiiI - IiII
 if 39 - 39: O0 / ooOoO0o + I11i - OoOoOO00 * o0oOOo0O0Ooo - OoO0O00
 if 97 - 97: i11iIiiIii / O0 % OoO0O00
 if 88 - 88: i1IIi . I1IiiI
 if 8 - 8: I1ii11iIi11i . OoO0O00 % o0oOOo0O0Ooo / O0
 if 51 - 51: oO0o + Ii1I * Ii1I * I1ii11iIi11i % I11i - I1ii11iIi11i
def lisp_get_any_map_server ( ) :
 for ii1I111i in lisp_map_servers_list . values ( ) : return ( ii1I111i )
 return ( None )
 if 15 - 15: i1IIi / OoO0O00 - Oo0Ooo
 if 74 - 74: o0oOOo0O0Ooo % Ii1I - II111iiii / ooOoO0o
 if 84 - 84: I1IiiI + OOooOOo
 if 80 - 80: OOooOOo / OoOoOO00
 if 93 - 93: OOooOOo
 if 82 - 82: iIii1I11I1II1 + OoO0O00 / iIii1I11I1II1 . iIii1I11I1II1
 if 36 - 36: iII111i % I1ii11iIi11i + OoOoOO00 - i11iIiiIii % II111iiii % I11i
 if 92 - 92: O0 * OoooooooOO + I1ii11iIi11i / IiII
 if 97 - 97: o0oOOo0O0Ooo . Ii1I + I1Ii111
 if 72 - 72: i11iIiiIii . iII111i . Ii1I * I1ii11iIi11i
def lisp_get_map_resolver ( address , eid ) :
 if ( address != None ) :
  I1Iii1I = address . print_address ( )
  IIiIII1IIi = None
  for i1IIiI1iII in lisp_map_resolvers_list :
   if ( i1IIiI1iII . find ( I1Iii1I ) == - 1 ) : continue
   IIiIII1IIi = lisp_map_resolvers_list [ i1IIiI1iII ]
   if 49 - 49: OoOoOO00 - O0 % I11i - ooOoO0o * OOooOOo
  return ( IIiIII1IIi )
  if 58 - 58: OoooooooOO - OOooOOo * oO0o / Ii1I . IiII
  if 50 - 50: IiII . OOooOOo + I1ii11iIi11i - OoooooooOO
  if 2 - 2: o0oOOo0O0Ooo % ooOoO0o / O0 / i11iIiiIii
  if 91 - 91: II111iiii * o0oOOo0O0Ooo
  if 20 - 20: iIii1I11I1II1 % Oo0Ooo * OoOoOO00 % IiII
  if 93 - 93: I11i * iIii1I11I1II1 * oO0o
  if 74 - 74: I1IiiI
 if ( eid == "" ) :
  I1i11111Iiii = ""
 elif ( eid == None ) :
  I1i11111Iiii = "all"
 else :
  o0Oo00OOOo00 = lisp_db_for_lookups . lookup_cache ( eid , False )
  I1i11111Iiii = "all" if o0Oo00OOOo00 == None else o0Oo00OOOo00 . use_mr_name
  if 13 - 13: i1IIi % i1IIi % ooOoO0o + IiII * II111iiii * OOooOOo
  if 66 - 66: iIii1I11I1II1
 oOOO0000O0oo0 = None
 for IIiIII1IIi in lisp_map_resolvers_list . values ( ) :
  if ( I1i11111Iiii == "" ) : return ( IIiIII1IIi )
  if ( IIiIII1IIi . mr_name != I1i11111Iiii ) : continue
  if ( oOOO0000O0oo0 == None or IIiIII1IIi . last_used < oOOO0000O0oo0 . last_used ) : oOOO0000O0oo0 = IIiIII1IIi
  if 34 - 34: I1Ii111 / OoooooooOO / O0 + IiII
 return ( oOOO0000O0oo0 )
 if 80 - 80: i11iIiiIii - OoooooooOO + II111iiii / i1IIi - oO0o
 if 100 - 100: Ii1I
 if 73 - 73: IiII - O0
 if 54 - 54: OOooOOo
 if 28 - 28: i1IIi - Oo0Ooo * OoO0O00 + OoooooooOO - Ii1I * i11iIiiIii
 if 71 - 71: iII111i - OOooOOo / iIii1I11I1II1 % i11iIiiIii
 if 39 - 39: o0oOOo0O0Ooo
 if 32 - 32: iIii1I11I1II1 . II111iiii / IiII % O0 / iII111i
def lisp_get_decent_map_resolver ( eid ) :
 OOOoO000 = lisp_get_decent_index ( eid )
 oooOOoooo000o = str ( OOOoO000 ) + "." + lisp_decent_dns_suffix
 if 57 - 57: I11i . IiII / iIii1I11I1II1 - ooOoO0o
 lprint ( "Use LISP-Decent map-resolver {} for EID {}" . format ( bold ( oooOOoooo000o , False ) , eid . print_prefix ( ) ) )
 if 50 - 50: O0 / II111iiii
 if 94 - 94: O0 + O0 % I1ii11iIi11i % i1IIi
 oOOO0000O0oo0 = None
 for IIiIII1IIi in lisp_map_resolvers_list . values ( ) :
  if ( oooOOoooo000o != IIiIII1IIi . dns_name ) : continue
  if ( oOOO0000O0oo0 == None or IIiIII1IIi . last_used < oOOO0000O0oo0 . last_used ) : oOOO0000O0oo0 = IIiIII1IIi
  if 15 - 15: I1IiiI
 return ( oOOO0000O0oo0 )
 if 48 - 48: Ii1I * IiII % O0 - II111iiii
 if 66 - 66: iIii1I11I1II1 / OOooOOo
 if 65 - 65: IiII . oO0o + O0 - i11iIiiIii + iIii1I11I1II1
 if 82 - 82: iIii1I11I1II1 * iII111i + iIii1I11I1II1 / OoO0O00 + O0
 if 67 - 67: I1Ii111
 if 94 - 94: I1Ii111 % iIii1I11I1II1 - II111iiii . ooOoO0o + i11iIiiIii - i11iIiiIii
 if 55 - 55: OoooooooOO % iIii1I11I1II1 % I1ii11iIi11i % i1IIi
def lisp_ipv4_input ( packet ) :
 if 46 - 46: I11i - ooOoO0o . I1IiiI
 if 36 - 36: I11i + OoO0O00 * O0 * OoOoOO00 * iII111i
 if 90 - 90: i11iIiiIii / i1IIi
 if 35 - 35: Ii1I . I11i / oO0o / OoOoOO00
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
   if 5 - 5: I1ii11iIi11i . o0oOOo0O0Ooo * iII111i * I1ii11iIi11i % I1Ii111
   if 83 - 83: iIii1I11I1II1 * o0oOOo0O0Ooo % i11iIiiIii + OoO0O00 . O0
   if 87 - 87: II111iiii - iIii1I11I1II1 % I11i % I1IiiI . o0oOOo0O0Ooo
   if 52 - 52: i11iIiiIii . oO0o / OoooooooOO - OoO0O00
   if 7 - 7: I1IiiI * I1IiiI % OOooOOo % iIii1I11I1II1 * OoO0O00 . o0oOOo0O0Ooo
   if 32 - 32: ooOoO0o / i1IIi
   if 55 - 55: oO0o . OoOoOO00 + OoooooooOO - ooOoO0o . OoooooooOO
 iiI = struct . unpack ( "B" , packet [ 8 : 9 ] ) [ 0 ]
 if ( iiI == 0 ) :
  dprint ( "IPv4 packet arrived with ttl 0, packet discarded" )
  return ( None )
 elif ( iiI == 1 ) :
  dprint ( "IPv4 packet {}, packet discarded" . format ( bold ( "ttl expiry" , False ) ) )
  if 77 - 77: I1IiiI
  return ( None )
  if 16 - 16: I1IiiI + ooOoO0o - O0 / o0oOOo0O0Ooo
  if 36 - 36: Oo0Ooo - OoOoOO00 - II111iiii
 iiI -= 1
 packet = packet [ 0 : 8 ] + struct . pack ( "B" , iiI ) + packet [ 9 : : ]
 packet = packet [ 0 : 10 ] + struct . pack ( "H" , 0 ) + packet [ 12 : : ]
 packet = lisp_ip_checksum ( packet )
 return ( packet )
 if 25 - 25: i11iIiiIii + II111iiii * OOooOOo % OOooOOo
 if 87 - 87: I11i % Ii1I % Oo0Ooo . II111iiii / oO0o
 if 19 - 19: O0 . OOooOOo + I1Ii111 * I1ii11iIi11i
 if 91 - 91: o0oOOo0O0Ooo / oO0o . o0oOOo0O0Ooo + IiII + ooOoO0o . I1Ii111
 if 90 - 90: i1IIi + oO0o * oO0o / ooOoO0o . IiII
 if 98 - 98: I11i % OoO0O00 . iII111i - o0oOOo0O0Ooo
 if 92 - 92: I11i
def lisp_ipv6_input ( packet ) :
 iiIi1I = packet . inner_dest
 packet = packet . packet
 if 34 - 34: I1IiiI % iIii1I11I1II1 . I1ii11iIi11i * Oo0Ooo * iIii1I11I1II1 / O0
 if 98 - 98: iII111i % IiII + OoO0O00
 if 23 - 23: OOooOOo
 if 83 - 83: I1ii11iIi11i / O0 * II111iiii + IiII + Oo0Ooo
 if 99 - 99: II111iiii + O0
 iiI = struct . unpack ( "B" , packet [ 7 : 8 ] ) [ 0 ]
 if ( iiI == 0 ) :
  dprint ( "IPv6 packet arrived with hop-limit 0, packet discarded" )
  return ( None )
 elif ( iiI == 1 ) :
  dprint ( "IPv6 packet {}, packet discarded" . format ( bold ( "ttl expiry" , False ) ) )
  if 94 - 94: ooOoO0o * ooOoO0o + o0oOOo0O0Ooo . iII111i % iIii1I11I1II1 + Ii1I
  return ( None )
  if 88 - 88: Oo0Ooo . iII111i
  if 89 - 89: OOooOOo + I1Ii111 % i11iIiiIii + Oo0Ooo / Oo0Ooo + OoO0O00
  if 9 - 9: OoOoOO00 % i1IIi + IiII
  if 19 - 19: I1Ii111 - II111iiii / I1Ii111 + I1IiiI - OoooooooOO + o0oOOo0O0Ooo
  if 100 - 100: OoO0O00 / OoOoOO00 / OOooOOo / OoO0O00
 if ( iiIi1I . is_ipv6_link_local ( ) ) :
  dprint ( "Do not encapsulate IPv6 link-local packets" )
  return ( None )
  if 95 - 95: ooOoO0o
  if 95 - 95: Ii1I + i1IIi . I1IiiI % I1Ii111 / Ii1I * O0
 iiI -= 1
 packet = packet [ 0 : 7 ] + struct . pack ( "B" , iiI ) + packet [ 8 : : ]
 return ( packet )
 if 68 - 68: I1Ii111 - IiII - oO0o - Oo0Ooo - o0oOOo0O0Ooo
 if 32 - 32: OoOoOO00 % i11iIiiIii
 if 53 - 53: I1Ii111 * Ii1I / IiII . i1IIi * II111iiii / o0oOOo0O0Ooo
 if 44 - 44: I1Ii111 + ooOoO0o
 if 15 - 15: I11i + OoO0O00 + OoOoOO00
 if 100 - 100: I1Ii111
 if 78 - 78: OoOoOO00
 if 16 - 16: I1Ii111 % OoO0O00 - OoO0O00 % OoOoOO00 * OoO0O00
def lisp_mac_input ( packet ) :
 return ( packet )
 if 36 - 36: OoOoOO00 * II111iiii . OoooooooOO * I11i . I11i
 if 13 - 13: I1ii11iIi11i * II111iiii
 if 93 - 93: OOooOOo / O0 - o0oOOo0O0Ooo + OoO0O00 * I1IiiI
 if 53 - 53: I1ii11iIi11i
 if 91 - 91: o0oOOo0O0Ooo - I1ii11iIi11i . i1IIi
 if 64 - 64: ooOoO0o
 if 23 - 23: Oo0Ooo . OoO0O00
 if 49 - 49: oO0o % i11iIiiIii * Ii1I
 if 9 - 9: Oo0Ooo - OoO0O00 + ooOoO0o / o0oOOo0O0Ooo
def lisp_rate_limit_map_request ( source , dest ) :
 if ( lisp_last_map_request_sent == None ) : return ( False )
 iII1I11II = lisp_get_timestamp ( )
 ooooOoO0O = iII1I11II - lisp_last_map_request_sent
 oo0oO0OO = ( ooooOoO0O < LISP_MAP_REQUEST_RATE_LIMIT )
 if 39 - 39: i11iIiiIii - iII111i / O0 % Oo0Ooo
 if ( oo0oO0OO ) :
  if ( source != None ) : source = source . print_address ( )
  dest = dest . print_address ( )
  dprint ( "Rate-limiting Map-Request for {} -> {}" . format ( source , dest ) )
  if 40 - 40: O0 * Oo0Ooo % o0oOOo0O0Ooo / OoooooooOO
 return ( oo0oO0OO )
 if 94 - 94: iII111i
 if 79 - 79: o0oOOo0O0Ooo / I1ii11iIi11i . iII111i . II111iiii + I1ii11iIi11i * I11i
 if 49 - 49: Ii1I * OoooooooOO * i1IIi % OoOoOO00
 if 83 - 83: iIii1I11I1II1 - i1IIi - Ii1I % iII111i
 if 69 - 69: I1Ii111 * oO0o * I1IiiI
 if 74 - 74: O0 / I11i . Oo0Ooo / I11i % OoO0O00 % o0oOOo0O0Ooo
 if 83 - 83: OoO0O00 - i11iIiiIii + iIii1I11I1II1
def lisp_send_map_request ( lisp_sockets , lisp_ephem_port , seid , deid , rloc ) :
 global lisp_last_map_request_sent
 if 52 - 52: OoooooooOO
 if 44 - 44: O0 / OoooooooOO + ooOoO0o * I1ii11iIi11i
 if 36 - 36: I1ii11iIi11i / OoO0O00 - oO0o % O0
 if 12 - 12: i1IIi * ooOoO0o / oO0o + I1IiiI / OoooooooOO
 if 86 - 86: Oo0Ooo / OoO0O00
 if 78 - 78: I1IiiI * I1IiiI
 iIIiI11II = i1i111 = None
 if ( rloc ) :
  iIIiI11II = rloc . rloc
  i1i111 = rloc . translated_port if lisp_i_am_rtr else LISP_DATA_PORT
  if 6 - 6: O0 - Ii1I . OOooOOo
  if 39 - 39: I1IiiI + I1Ii111 / I1ii11iIi11i * i1IIi
  if 37 - 37: O0 + iIii1I11I1II1 % IiII * oO0o
  if 43 - 43: OOooOOo . O0
  if 76 - 76: OOooOOo * OoooooooOO / IiII . OoO0O00 + II111iiii
 II1ii1ii , I11ii1i1i , Ooooo = lisp_myrlocs
 if ( II1ii1ii == None ) :
  lprint ( "Suppress sending Map-Request, IPv4 RLOC not found" )
  return
  if 8 - 8: I11i % O0 - O0
 if ( I11ii1i1i == None and iIIiI11II != None and iIIiI11II . is_ipv6 ( ) ) :
  lprint ( "Suppress sending Map-Request, IPv6 RLOC not found" )
  return
  if 32 - 32: I1ii11iIi11i + o0oOOo0O0Ooo
  if 24 - 24: ooOoO0o % I1Ii111 + OoO0O00 * o0oOOo0O0Ooo % O0 - i11iIiiIii
 O00O0 = lisp_map_request ( )
 O00O0 . record_count = 1
 O00O0 . nonce = lisp_get_control_nonce ( )
 O00O0 . rloc_probe = ( iIIiI11II != None )
 if 49 - 49: o0oOOo0O0Ooo / OoOoOO00 + iII111i
 if 85 - 85: I1IiiI - o0oOOo0O0Ooo
 if 86 - 86: II111iiii + Ii1I * Ii1I
 if 26 - 26: o0oOOo0O0Ooo + oO0o * i11iIiiIii / II111iiii
 if 86 - 86: Ii1I
 if 69 - 69: oO0o % o0oOOo0O0Ooo / o0oOOo0O0Ooo
 if 1 - 1: Ii1I
 if ( rloc ) : rloc . last_rloc_probe_nonce = O00O0 . nonce
 if 43 - 43: o0oOOo0O0Ooo
 oOO00oOooOo = deid . is_multicast_address ( )
 if ( oOO00oOooOo ) :
  O00O0 . target_eid = seid
  O00O0 . target_group = deid
 else :
  O00O0 . target_eid = deid
  if 78 - 78: I1Ii111 % i1IIi * I11i
  if 59 - 59: OoOoOO00 % OoO0O00 % i11iIiiIii . II111iiii % I1ii11iIi11i + i1IIi
  if 99 - 99: I11i + IiII * I1Ii111 - OOooOOo - i1IIi
  if 77 - 77: I11i . IiII / OoO0O00 / I1Ii111
  if 8 - 8: o0oOOo0O0Ooo + iII111i / OoO0O00 * ooOoO0o - oO0o . iII111i
  if 32 - 32: OoooooooOO . I1Ii111 - I1ii11iIi11i
  if 29 - 29: OoO0O00
  if 33 - 33: I1ii11iIi11i - O0
  if 72 - 72: Oo0Ooo * iII111i - I11i
 if ( O00O0 . rloc_probe == False ) :
  o0Oo00OOOo00 = lisp_get_signature_eid ( )
  if ( o0Oo00OOOo00 ) :
   O00O0 . signature_eid . copy_address ( o0Oo00OOOo00 . eid )
   O00O0 . privkey_filename = "./lisp-sig.pem"
   if 81 - 81: I1Ii111
   if 85 - 85: O0 % OoOoOO00 . I1ii11iIi11i
   if 46 - 46: OOooOOo * iIii1I11I1II1
   if 33 - 33: OoO0O00 * II111iiii / i1IIi
   if 93 - 93: I1Ii111 % I11i
   if 64 - 64: I1IiiI % OoOoOO00 / Oo0Ooo
 if ( seid == None or oOO00oOooOo ) :
  O00O0 . source_eid . afi = LISP_AFI_NONE
 else :
  O00O0 . source_eid = seid
  if 40 - 40: Ii1I + iIii1I11I1II1 / oO0o . II111iiii % O0 - IiII
  if 49 - 49: IiII - OOooOOo * OOooOOo . O0
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
 if ( iIIiI11II != None and lisp_nat_traversal and lisp_i_am_rtr == False ) :
  if ( iIIiI11II . is_private_address ( ) == False ) :
   II1ii1ii = lisp_get_any_translated_rloc ( )
   if 75 - 75: OoooooooOO
  if ( II1ii1ii == None ) :
   lprint ( "Suppress sending Map-Request, translated RLOC not found" )
   return
   if 24 - 24: I1Ii111 % i11iIiiIii % oO0o . OOooOOo % IiII
   if 23 - 23: o0oOOo0O0Ooo * II111iiii - Oo0Ooo - I1IiiI
   if 86 - 86: I1IiiI - II111iiii * II111iiii * oO0o % OoooooooOO * OoOoOO00
   if 93 - 93: I1IiiI + OoO0O00 % O0 - ooOoO0o * i1IIi
   if 60 - 60: I1IiiI
   if 9 - 9: I11i % i1IIi / ooOoO0o % iII111i - oO0o - II111iiii
   if 29 - 29: ooOoO0o . II111iiii . i1IIi % oO0o
   if 11 - 11: OoOoOO00 . OoO0O00 % I11i * iII111i % I1Ii111 . O0
 if ( iIIiI11II == None or iIIiI11II . is_ipv4 ( ) ) :
  if ( lisp_nat_traversal and iIIiI11II == None ) :
   I1Iii = lisp_get_any_translated_rloc ( )
   if ( I1Iii != None ) : II1ii1ii = I1Iii
   if 5 - 5: II111iiii
  O00O0 . itr_rlocs . append ( II1ii1ii )
  if 100 - 100: O0 * iIii1I11I1II1 - OoooooooOO
 if ( iIIiI11II == None or iIIiI11II . is_ipv6 ( ) ) :
  if ( I11ii1i1i == None or I11ii1i1i . is_ipv6_link_local ( ) ) :
   I11ii1i1i = None
  else :
   O00O0 . itr_rloc_count = 1 if ( iIIiI11II == None ) else 0
   O00O0 . itr_rlocs . append ( I11ii1i1i )
   if 41 - 41: OoO0O00 / OoooooooOO
   if 61 - 61: ooOoO0o
   if 4 - 4: Oo0Ooo + oO0o + oO0o
   if 79 - 79: OoooooooOO
   if 98 - 98: O0 . ooOoO0o * I1Ii111
   if 98 - 98: ooOoO0o + o0oOOo0O0Ooo / I11i - Ii1I * II111iiii + i1IIi
   if 10 - 10: oO0o
   if 8 - 8: I1ii11iIi11i * OOooOOo * iIii1I11I1II1 + I11i . iII111i
   if 55 - 55: I1IiiI + Ii1I % I1ii11iIi11i + iIii1I11I1II1
 if ( iIIiI11II != None and O00O0 . itr_rlocs != [ ] ) :
  I1i11111i = O00O0 . itr_rlocs [ 0 ]
 else :
  if ( deid . is_ipv4 ( ) ) :
   I1i11111i = II1ii1ii
  elif ( deid . is_ipv6 ( ) ) :
   I1i11111i = I11ii1i1i
  else :
   I1i11111i = II1ii1ii
   if 64 - 64: i1IIi / O0 - oO0o
   if 7 - 7: IiII . IiII * Ii1I
   if 1 - 1: i11iIiiIii
   if 91 - 91: I1ii11iIi11i . OoO0O00 / OoO0O00 / I1ii11iIi11i + iII111i
   if 20 - 20: o0oOOo0O0Ooo . I1Ii111 + O0
   if 99 - 99: O0 / IiII . oO0o
 iI1IIII1ii1 = O00O0 . encode ( iIIiI11II , i1i111 )
 O00O0 . print_map_request ( )
 if 18 - 18: OoooooooOO * OoO0O00 * I1Ii111
 if 12 - 12: i11iIiiIii / iIii1I11I1II1 . I11i % I1Ii111 * ooOoO0o % ooOoO0o
 if 13 - 13: i1IIi . ooOoO0o . ooOoO0o
 if 24 - 24: iIii1I11I1II1
 if 72 - 72: i11iIiiIii + o0oOOo0O0Ooo % ooOoO0o * I1ii11iIi11i . i1IIi
 if 59 - 59: OoooooooOO - OoooooooOO - o0oOOo0O0Ooo + i1IIi % I1Ii111
 if ( iIIiI11II != None ) :
  if ( rloc . is_rloc_translated ( ) ) :
   IiiiI11I1 = lisp_get_nat_info ( iIIiI11II , rloc . rloc_name )
   if ( IiiiI11I1 and len ( lisp_sockets ) == 4 ) :
    lisp_encapsulate_rloc_probe ( lisp_sockets , iIIiI11II ,
 IiiiI11I1 , iI1IIII1ii1 )
    return
    if 74 - 74: IiII * iIii1I11I1II1 - I1IiiI
    if 62 - 62: o0oOOo0O0Ooo
    if 54 - 54: iIii1I11I1II1 / OoooooooOO + o0oOOo0O0Ooo . i1IIi - OoooooooOO
  OoOOoooO000 = iIIiI11II . print_address_no_iid ( )
  iiIi1I = lisp_convert_4to6 ( OoOOoooO000 )
  lisp_send ( lisp_sockets , iiIi1I , LISP_CTRL_PORT , iI1IIII1ii1 )
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
 if ( seid == None ) : seid = I1i11111i
 lisp_send_ecm ( lisp_sockets , iI1IIII1ii1 , seid , lisp_ephem_port , deid ,
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
 i1ii = lisp_info ( )
 i1ii . nonce = lisp_get_control_nonce ( )
 if ( device_name ) : i1ii . hostname += "-" + device_name
 if 7 - 7: oO0o
 OoOOoooO000 = dest . print_address_no_iid ( )
 if 89 - 89: i11iIiiIii / o0oOOo0O0Ooo / I1ii11iIi11i % iII111i . OoooooooOO - iIii1I11I1II1
 if 63 - 63: Ii1I % I1Ii111 + O0 * OoO0O00 . oO0o
 if 34 - 34: I1IiiI . I1ii11iIi11i . O0 - OoOoOO00 - i11iIiiIii / iII111i
 if 63 - 63: OOooOOo
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
 iiIi1iIi1i = False
 if ( device_name ) :
  i1i1 = lisp_get_host_route_next_hop ( OoOOoooO000 )
  if 53 - 53: IiII / II111iiii / oO0o % O0 / I1Ii111
  if 91 - 91: oO0o * OoOoOO00 + O0 % Oo0Ooo
  if 62 - 62: iIii1I11I1II1 - i11iIiiIii % iIii1I11I1II1 . ooOoO0o / OOooOOo * OoOoOO00
  if 45 - 45: OOooOOo - OOooOOo % iII111i - IiII . O0
  if 6 - 6: iIii1I11I1II1 * II111iiii / O0 % IiII - I1Ii111
  if 64 - 64: ooOoO0o
  if 28 - 28: i11iIiiIii - IiII * I1ii11iIi11i + IiII * iII111i
  if 75 - 75: o0oOOo0O0Ooo * OoOoOO00 % I1ii11iIi11i + OOooOOo . II111iiii
  if 12 - 12: ooOoO0o
  if ( port == LISP_CTRL_PORT and i1i1 != None ) :
   while ( True ) :
    time . sleep ( .01 )
    i1i1 = lisp_get_host_route_next_hop ( OoOOoooO000 )
    if ( i1i1 == None ) : break
    if 83 - 83: I1Ii111 % ooOoO0o + OoooooooOO
    if 50 - 50: i11iIiiIii % I1IiiI * iII111i / Ii1I
    if 12 - 12: iII111i / OoO0O00 - II111iiii + Oo0Ooo
  ooO0oO00O = lisp_get_default_route_next_hops ( )
  for Ooooo , I1i1i1iIIiI11 in ooO0oO00O :
   if ( Ooooo != device_name ) : continue
   if 22 - 22: I11i / i11iIiiIii * II111iiii
   if 52 - 52: o0oOOo0O0Ooo . O0 % I11i . iIii1I11I1II1 % iIii1I11I1II1 / I1Ii111
   if 18 - 18: Ii1I * I1ii11iIi11i % I11i
   if 50 - 50: Ii1I . I1ii11iIi11i + iIii1I11I1II1 * i11iIiiIii . iII111i
   if 47 - 47: o0oOOo0O0Ooo * oO0o % I1ii11iIi11i
   if 59 - 59: IiII
   if ( i1i1 != I1i1i1iIIiI11 ) :
    if ( i1i1 != None ) :
     lisp_install_host_route ( OoOOoooO000 , i1i1 , False )
     if 22 - 22: i11iIiiIii . oO0o * OoOoOO00 . OoooooooOO
    lisp_install_host_route ( OoOOoooO000 , I1i1i1iIIiI11 , True )
    iiIi1iIi1i = True
    if 100 - 100: I1Ii111 + O0
   break
   if 69 - 69: I11i + OoO0O00 + o0oOOo0O0Ooo - o0oOOo0O0Ooo - Ii1I
   if 24 - 24: i11iIiiIii + I11i . O0
   if 96 - 96: OoOoOO00 . I1ii11iIi11i - oO0o
   if 81 - 81: iII111i - II111iiii * O0
   if 55 - 55: II111iiii * i1IIi
   if 7 - 7: OOooOOo - I1ii11iIi11i * O0 * iIii1I11I1II1 + OoO0O00 / I11i
 iI1IIII1ii1 = i1ii . encode ( )
 i1ii . print_info ( )
 if 25 - 25: OoooooooOO . O0 % OoO0O00
 if 52 - 52: i11iIiiIii
 if 97 - 97: Oo0Ooo % IiII
 if 24 - 24: iIii1I11I1II1
 OOOoo0O00 = "(for control)" if port == LISP_CTRL_PORT else "(for data)"
 OOOoo0O00 = bold ( OOOoo0O00 , False )
 o0O0o = bold ( "{}" . format ( port ) , False )
 OOOO0o = red ( OoOOoooO000 , False )
 ooo0O = "RTR " if port == LISP_DATA_PORT else "MS "
 lprint ( "Send Info-Request to {}{}, port {} {}" . format ( ooo0O , OOOO0o , o0O0o , OOOoo0O00 ) )
 if 22 - 22: oO0o + O0 + I11i . OoO0O00 - II111iiii
 if 20 - 20: Ii1I * I1Ii111 . I1IiiI % OoOoOO00 / OoO0O00 % II111iiii
 if 43 - 43: IiII + II111iiii + oO0o / I1ii11iIi11i % i1IIi - OoO0O00
 if 59 - 59: Oo0Ooo + O0 + iII111i
 if 71 - 71: IiII - OoO0O00
 if 90 - 90: Oo0Ooo
 if ( port == LISP_CTRL_PORT ) :
  lisp_send ( lisp_sockets , dest , LISP_CTRL_PORT , iI1IIII1ii1 )
 else :
  IIiiIiIIiI1 = lisp_data_header ( )
  IIiiIiIIiI1 . instance_id ( 0xffffff )
  IIiiIiIIiI1 = IIiiIiIIiI1 . encode ( )
  if ( IIiiIiIIiI1 ) :
   iI1IIII1ii1 = IIiiIiIIiI1 + iI1IIII1ii1
   if 83 - 83: iIii1I11I1II1 % ooOoO0o % OOooOOo * i1IIi - o0oOOo0O0Ooo * i1IIi
   if 60 - 60: Ii1I . I1ii11iIi11i - I11i + i11iIiiIii / iII111i
   if 9 - 9: I1Ii111 . oO0o . OoO0O00 / IiII - oO0o / oO0o
   if 50 - 50: II111iiii + OoOoOO00
   if 17 - 17: ooOoO0o + I1ii11iIi11i
   if 34 - 34: Ii1I / II111iiii + OoOoOO00 . II111iiii + OoooooooOO * o0oOOo0O0Ooo
   if 48 - 48: O0
   if 99 - 99: II111iiii * oO0o / I1ii11iIi11i - i1IIi
   if 84 - 84: i11iIiiIii . OoooooooOO
   lisp_send ( lisp_sockets , dest , LISP_DATA_PORT , iI1IIII1ii1 )
   if 69 - 69: I1Ii111 * II111iiii % I1Ii111 * i11iIiiIii . ooOoO0o / Oo0Ooo
   if 5 - 5: Ii1I
   if 19 - 19: oO0o
   if 61 - 61: OoOoOO00 + iIii1I11I1II1 / I1ii11iIi11i - i1IIi
   if 11 - 11: oO0o * o0oOOo0O0Ooo . I1IiiI
   if 12 - 12: I1IiiI % OoO0O00 / I1Ii111 / O0 % o0oOOo0O0Ooo
   if 1 - 1: OoOoOO00 / I11i
 if ( iiIi1iIi1i ) :
  lisp_install_host_route ( OoOOoooO000 , None , False )
  if ( i1i1 != None ) : lisp_install_host_route ( OoOOoooO000 , i1i1 , True )
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
 i1ii = lisp_info ( )
 packet = i1ii . decode ( packet )
 if ( packet == None ) : return
 i1ii . print_info ( )
 if 18 - 18: I1Ii111
 if 29 - 29: i1IIi - I1IiiI / i1IIi
 if 64 - 64: IiII
 if 69 - 69: OOooOOo . I1IiiI
 if 11 - 11: I1Ii111 * I1IiiI - I1Ii111 / iII111i
 i1ii . info_reply = True
 i1ii . global_etr_rloc . store_address ( addr_str )
 i1ii . etr_port = sport
 if 22 - 22: iII111i % I11i % O0 - I11i
 if 71 - 71: I1Ii111 / II111iiii - OoooooooOO % i1IIi + OoOoOO00 % OoooooooOO
 if 52 - 52: Ii1I . OoOoOO00 / o0oOOo0O0Ooo / iII111i
 if 83 - 83: OoO0O00 - Oo0Ooo + I1Ii111 . I1IiiI
 if 78 - 78: I11i / ooOoO0o . OoOoOO00 * i1IIi
 i1ii . private_etr_rloc . afi = LISP_AFI_NAME
 i1ii . private_etr_rloc . store_address ( i1ii . hostname )
 if 15 - 15: i1IIi . II111iiii * OoOoOO00 / Oo0Ooo
 if ( rtr_list != None ) : i1ii . rtr_list = rtr_list
 packet = i1ii . encode ( )
 i1ii . print_info ( )
 if 99 - 99: iII111i - o0oOOo0O0Ooo / O0
 if 97 - 97: iIii1I11I1II1 * I1Ii111
 if 39 - 39: I1Ii111 . II111iiii
 if 94 - 94: OoO0O00 - OoO0O00 + iIii1I11I1II1 + O0 * oO0o
 if 9 - 9: Ii1I * Oo0Ooo / oO0o / Ii1I
 lprint ( "Send Info-Reply to {}" . format ( red ( addr_str , False ) ) )
 iiIi1I = lisp_convert_4to6 ( addr_str )
 lisp_send ( lisp_sockets , iiIi1I , sport , packet )
 if 34 - 34: I1IiiI
 if 56 - 56: Ii1I
 if 71 - 71: O0 / i1IIi
 if 20 - 20: OOooOOo . iIii1I11I1II1 - I1Ii111 . i1IIi
 if 82 - 82: oO0o * i11iIiiIii % o0oOOo0O0Ooo % IiII - I11i - OoO0O00
 IIiIiII1iI1II1I = lisp_info_source ( i1ii . hostname , addr_str , sport )
 IIiIiII1iI1II1I . cache_address_for_info_source ( )
 return
 if 97 - 97: i11iIiiIii
 if 62 - 62: i1IIi - I1IiiI * i1IIi % I1Ii111
 if 37 - 37: I11i
 if 61 - 61: OoooooooOO % iIii1I11I1II1 % O0 % I1Ii111 / Oo0Ooo . I1IiiI
 if 20 - 20: ooOoO0o - I1Ii111
 if 97 - 97: O0
 if 56 - 56: Ii1I * I1IiiI * ooOoO0o
 if 39 - 39: iII111i % Ii1I * iIii1I11I1II1 - Ii1I - I1Ii111
def lisp_get_signature_eid ( ) :
 for o0Oo00OOOo00 in lisp_db_list :
  if ( o0Oo00OOOo00 . signature_eid ) : return ( o0Oo00OOOo00 )
  if 60 - 60: i11iIiiIii + i11iIiiIii - OoooooooOO + OoooooooOO
 return ( None )
 if 5 - 5: o0oOOo0O0Ooo
 if 78 - 78: OOooOOo * O0 * II111iiii % OoOoOO00
 if 12 - 12: Oo0Ooo . o0oOOo0O0Ooo - i1IIi - oO0o % IiII . I11i
 if 17 - 17: i1IIi % OoO0O00 + i11iIiiIii % I1Ii111 * ooOoO0o . I1ii11iIi11i
 if 64 - 64: O0 - iII111i
 if 82 - 82: O0
 if 37 - 37: I1Ii111
 if 98 - 98: iII111i - OoOoOO00 / I1Ii111 . OOooOOo - OOooOOo - ooOoO0o
def lisp_get_any_translated_port ( ) :
 for o0Oo00OOOo00 in lisp_db_list :
  for ii1I1i11 in o0Oo00OOOo00 . rloc_set :
   if ( ii1I1i11 . translated_rloc . is_null ( ) ) : continue
   return ( ii1I1i11 . translated_port )
   if 84 - 84: OOooOOo * ooOoO0o / O0
   if 96 - 96: I11i . I11i % II111iiii
 return ( None )
 if 14 - 14: iII111i / OoooooooOO
 if 8 - 8: OOooOOo + I1IiiI - Oo0Ooo + i1IIi . Ii1I . I1Ii111
 if 38 - 38: I1IiiI / II111iiii * OoOoOO00 / I1Ii111
 if 80 - 80: I1ii11iIi11i / ooOoO0o * ooOoO0o . Oo0Ooo
 if 44 - 44: Ii1I * i1IIi % OoOoOO00 . OoOoOO00
 if 16 - 16: Oo0Ooo / i1IIi / iIii1I11I1II1 / iIii1I11I1II1 % o0oOOo0O0Ooo / I1ii11iIi11i
 if 11 - 11: I1IiiI
 if 45 - 45: OOooOOo / i1IIi * IiII * I1Ii111
 if 34 - 34: ooOoO0o / iIii1I11I1II1 . iII111i
def lisp_get_any_translated_rloc ( ) :
 for o0Oo00OOOo00 in lisp_db_list :
  for ii1I1i11 in o0Oo00OOOo00 . rloc_set :
   if ( ii1I1i11 . translated_rloc . is_null ( ) ) : continue
   return ( ii1I1i11 . translated_rloc )
   if 91 - 91: OoO0O00
   if 8 - 8: oO0o
 return ( None )
 if 96 - 96: IiII
 if 37 - 37: Ii1I % i11iIiiIii + iIii1I11I1II1 % Oo0Ooo - iIii1I11I1II1
 if 26 - 26: o0oOOo0O0Ooo . i1IIi
 if 62 - 62: IiII * I1ii11iIi11i % iIii1I11I1II1 / II111iiii - OoO0O00
 if 52 - 52: iII111i . I11i - I11i + oO0o + iIii1I11I1II1
 if 83 - 83: I11i * iIii1I11I1II1 + OoOoOO00
 if 81 - 81: ooOoO0o * OOooOOo / OoO0O00 + I1ii11iIi11i % I1Ii111
def lisp_get_all_translated_rlocs ( ) :
 IiIi1IiI1 = [ ]
 for o0Oo00OOOo00 in lisp_db_list :
  for ii1I1i11 in o0Oo00OOOo00 . rloc_set :
   if ( ii1I1i11 . is_rloc_translated ( ) == False ) : continue
   I1Iii1I = ii1I1i11 . translated_rloc . print_address_no_iid ( )
   IiIi1IiI1 . append ( I1Iii1I )
   if 100 - 100: II111iiii / Oo0Ooo / iII111i / OOooOOo
   if 100 - 100: iIii1I11I1II1
 return ( IiIi1IiI1 )
 if 50 - 50: I1Ii111 / ooOoO0o * I11i
 if 53 - 53: II111iiii . IiII
 if 5 - 5: i1IIi % IiII
 if 16 - 16: ooOoO0o - iII111i % Ii1I . OoOoOO00
 if 56 - 56: i11iIiiIii % i11iIiiIii % OoooooooOO . Ii1I . iII111i + I11i
 if 64 - 64: O0
 if 37 - 37: o0oOOo0O0Ooo / O0
 if 58 - 58: I1Ii111 + OoooooooOO + iIii1I11I1II1
def lisp_update_default_routes ( map_resolver , iid , rtr_list ) :
 I1ii1iiiiIIIi = ( os . getenv ( "LISP_RTR_BEHIND_NAT" ) != None )
 if 13 - 13: o0oOOo0O0Ooo . I11i / O0
 I1II11 = { }
 for i1IIIIi1Ii111 in rtr_list :
  if ( i1IIIIi1Ii111 == None ) : continue
  I1Iii1I = rtr_list [ i1IIIIi1Ii111 ]
  if ( I1ii1iiiiIIIi and I1Iii1I . is_private_address ( ) ) : continue
  I1II11 [ i1IIIIi1Ii111 ] = I1Iii1I
  if 67 - 67: I1IiiI % O0 + I1IiiI * I1Ii111 * OoOoOO00 * II111iiii
 rtr_list = I1II11
 if 79 - 79: I1IiiI
 i11IiiI = [ ]
 for ooOooOooOOO in [ LISP_AFI_IPV4 , LISP_AFI_IPV6 , LISP_AFI_MAC ] :
  if ( ooOooOooOOO == LISP_AFI_MAC and lisp_l2_overlay == False ) : break
  if 35 - 35: oO0o . I1IiiI / i1IIi + IiII / OoooooooOO . I1IiiI
  if 30 - 30: I1Ii111 / i11iIiiIii / i11iIiiIii + OoOoOO00
  if 42 - 42: iII111i
  if 63 - 63: i1IIi
  if 24 - 24: i11iIiiIii % iII111i . oO0o
  O00OOOoOoooo = lisp_address ( ooOooOooOOO , "" , 0 , iid )
  O00OOOoOoooo . make_default_route ( O00OOOoOoooo )
  Iii1 = lisp_map_cache . lookup_cache ( O00OOOoOoooo , True )
  if ( Iii1 ) :
   if ( Iii1 . checkpoint_entry ) :
    lprint ( "Updating checkpoint entry for {}" . format ( green ( Iii1 . print_eid_tuple ( ) , False ) ) )
    if 44 - 44: II111iiii - OoO0O00 + i11iIiiIii
   elif ( Iii1 . do_rloc_sets_match ( rtr_list . values ( ) ) ) :
    continue
    if 34 - 34: I1ii11iIi11i % ooOoO0o / II111iiii * O0 % OOooOOo
   Iii1 . delete_cache ( )
   if 9 - 9: I1ii11iIi11i / I1ii11iIi11i - OOooOOo . iIii1I11I1II1
   if 33 - 33: I1IiiI + oO0o % I1IiiI / iII111i - ooOoO0o - i11iIiiIii
  i11IiiI . append ( [ O00OOOoOoooo , "" ] )
  if 39 - 39: i11iIiiIii / oO0o
  if 71 - 71: I1Ii111 * iIii1I11I1II1 - I1Ii111
  if 87 - 87: I1IiiI / Ii1I
  if 54 - 54: OoooooooOO / Ii1I
  Oo000o0o0 = lisp_address ( ooOooOooOOO , "" , 0 , iid )
  Oo000o0o0 . make_default_multicast_route ( Oo000o0o0 )
  iIIIi1 = lisp_map_cache . lookup_cache ( Oo000o0o0 , True )
  if ( iIIIi1 ) : iIIIi1 = iIIIi1 . source_cache . lookup_cache ( O00OOOoOoooo , True )
  if ( iIIIi1 ) : iIIIi1 . delete_cache ( )
  if 80 - 80: OoO0O00 - ooOoO0o . Oo0Ooo - OOooOOo + OoOoOO00 . iII111i
  i11IiiI . append ( [ O00OOOoOoooo , Oo000o0o0 ] )
  if 26 - 26: OOooOOo
 if ( len ( i11IiiI ) == 0 ) : return
 if 89 - 89: i11iIiiIii . o0oOOo0O0Ooo % iIii1I11I1II1 * O0 + OOooOOo . o0oOOo0O0Ooo
 if 17 - 17: I1Ii111
 if 59 - 59: OoOoOO00 . OoOoOO00 * iII111i - Ii1I . i11iIiiIii
 if 68 - 68: iII111i
 oOo0oOOOoOoo = [ ]
 for ooo0O in rtr_list :
  O00O0OO0O = rtr_list [ ooo0O ]
  ii1I1i11 = lisp_rloc ( )
  ii1I1i11 . rloc . copy_address ( O00O0OO0O )
  ii1I1i11 . priority = 254
  ii1I1i11 . mpriority = 255
  ii1I1i11 . rloc_name = "RTR"
  oOo0oOOOoOoo . append ( ii1I1i11 )
  if 3 - 3: iIii1I11I1II1 + iIii1I11I1II1 + OoO0O00
  if 59 - 59: iII111i
 for O00OOOoOoooo in i11IiiI :
  Iii1 = lisp_mapping ( O00OOOoOoooo [ 0 ] , O00OOOoOoooo [ 1 ] , oOo0oOOOoOoo )
  Iii1 . mapping_source = map_resolver
  Iii1 . map_cache_ttl = LISP_MR_TTL * 60
  Iii1 . add_cache ( )
  lprint ( "Add {} to map-cache with RTR RLOC-set: {}" . format ( green ( Iii1 . print_eid_tuple ( ) , False ) , rtr_list . keys ( ) ) )
  if 7 - 7: o0oOOo0O0Ooo * OoooooooOO - Ii1I * II111iiii % I1Ii111
  oOo0oOOOoOoo = copy . deepcopy ( oOo0oOOOoOoo )
  if 82 - 82: OoOoOO00 - OoOoOO00 + iIii1I11I1II1 + o0oOOo0O0Ooo + IiII - o0oOOo0O0Ooo
 return
 if 65 - 65: I1Ii111 + OOooOOo
 if 97 - 97: oO0o % OoOoOO00 * oO0o % II111iiii + iIii1I11I1II1
 if 11 - 11: ooOoO0o . o0oOOo0O0Ooo
 if 94 - 94: ooOoO0o . oO0o * OoooooooOO % oO0o
 if 77 - 77: ooOoO0o % I1IiiI
 if 26 - 26: o0oOOo0O0Ooo
 if 72 - 72: I1IiiI
 if 90 - 90: ooOoO0o
 if 67 - 67: iIii1I11I1II1 + i1IIi * I1IiiI * OoooooooOO
 if 23 - 23: IiII
def lisp_process_info_reply ( source , packet , store ) :
 if 32 - 32: OoOoOO00 - iII111i % oO0o / I1ii11iIi11i - o0oOOo0O0Ooo
 if 52 - 52: Ii1I / OoooooooOO % i11iIiiIii + iII111i
 if 59 - 59: Ii1I / o0oOOo0O0Ooo / oO0o + iII111i * I1ii11iIi11i - o0oOOo0O0Ooo
 if 70 - 70: O0 / I1ii11iIi11i + ooOoO0o . OoO0O00 - OoO0O00 / i11iIiiIii
 i1ii = lisp_info ( )
 packet = i1ii . decode ( packet )
 if ( packet == None ) : return ( [ None , None , False ] )
 if 1 - 1: iIii1I11I1II1 % I1ii11iIi11i
 i1ii . print_info ( )
 if 49 - 49: iII111i + o0oOOo0O0Ooo % I1ii11iIi11i . O0 % OoooooooOO . o0oOOo0O0Ooo
 if 3 - 3: i11iIiiIii - i1IIi * o0oOOo0O0Ooo / OoOoOO00 % Oo0Ooo
 if 65 - 65: OoooooooOO + iII111i - i11iIiiIii - IiII + oO0o
 if 67 - 67: i1IIi * I1Ii111 * O0
 III1IiI = False
 for ooo0O in i1ii . rtr_list :
  OoOOoooO000 = ooo0O . print_address_no_iid ( )
  if ( lisp_rtr_list . has_key ( OoOOoooO000 ) ) :
   if ( lisp_register_all_rtrs == False ) : continue
   if ( lisp_rtr_list [ OoOOoooO000 ] != None ) : continue
   if 57 - 57: OOooOOo * OOooOOo
  III1IiI = True
  lisp_rtr_list [ OoOOoooO000 ] = ooo0O
  if 63 - 63: o0oOOo0O0Ooo * iIii1I11I1II1 - II111iiii
  if 72 - 72: o0oOOo0O0Ooo * I1ii11iIi11i
  if 57 - 57: IiII * OOooOOo
  if 28 - 28: I1Ii111
  if 27 - 27: OoOoOO00 - OoO0O00 - iIii1I11I1II1 + OoOoOO00 - I11i
 if ( lisp_i_am_itr and III1IiI ) :
  if ( lisp_iid_to_interface == { } ) :
   lisp_update_default_routes ( source , lisp_default_iid , lisp_rtr_list )
  else :
   for IIiI1i in lisp_iid_to_interface . keys ( ) :
    lisp_update_default_routes ( source , int ( IIiI1i ) , lisp_rtr_list )
    if 10 - 10: I1ii11iIi11i
    if 6 - 6: OoO0O00 + OoO0O00 * OOooOOo / IiII % ooOoO0o - I1IiiI
    if 17 - 17: II111iiii
    if 66 - 66: O0 % OoOoOO00 + IiII % I1Ii111
    if 94 - 94: OoOoOO00 / OoooooooOO % Ii1I * i11iIiiIii
    if 95 - 95: iIii1I11I1II1 % OOooOOo % O0
    if 93 - 93: I1ii11iIi11i
 if ( store == False ) :
  return ( [ i1ii . global_etr_rloc , i1ii . etr_port , III1IiI ] )
  if 61 - 61: o0oOOo0O0Ooo * ooOoO0o
  if 82 - 82: O0 * O0 % I1IiiI / o0oOOo0O0Ooo
  if 46 - 46: IiII . O0 . I11i % I1ii11iIi11i * oO0o - oO0o
  if 92 - 92: I1IiiI - I1IiiI
  if 28 - 28: oO0o * iII111i + IiII
  if 73 - 73: OoooooooOO
 for o0Oo00OOOo00 in lisp_db_list :
  for ii1I1i11 in o0Oo00OOOo00 . rloc_set :
   i1IIIIi1Ii111 = ii1I1i11 . rloc
   iIiiiIiIi = ii1I1i11 . interface
   if ( iIiiiIiIi == None ) :
    if ( i1IIIIi1Ii111 . is_null ( ) ) : continue
    if ( i1IIIIi1Ii111 . is_local ( ) == False ) : continue
    if ( i1ii . private_etr_rloc . is_null ( ) == False and
 i1IIIIi1Ii111 . is_exact_match ( i1ii . private_etr_rloc ) == False ) :
     continue
     if 45 - 45: IiII + I1IiiI * I1Ii111
   elif ( i1ii . private_etr_rloc . is_dist_name ( ) ) :
    O0O00O = i1ii . private_etr_rloc . address
    if ( O0O00O != ii1I1i11 . rloc_name ) : continue
    if 82 - 82: OOooOOo / I11i % Ii1I * OoOoOO00
    if 88 - 88: o0oOOo0O0Ooo % OoO0O00
   oo0ooooO = green ( o0Oo00OOOo00 . eid . print_prefix ( ) , False )
   I111I = red ( i1IIIIi1Ii111 . print_address_no_iid ( ) , False )
   if 30 - 30: II111iiii / Oo0Ooo % Oo0Ooo + O0 / iIii1I11I1II1 . OoO0O00
   Ii1IIiI1iI = i1ii . global_etr_rloc . is_exact_match ( i1IIIIi1Ii111 )
   if ( ii1I1i11 . translated_port == 0 and Ii1IIiI1iI ) :
    lprint ( "No NAT for {} ({}), EID-prefix {}" . format ( I111I ,
 iIiiiIiIi , oo0ooooO ) )
    continue
    if 14 - 14: OoO0O00
    if 21 - 21: II111iiii + i11iIiiIii + I11i % I1IiiI
    if 65 - 65: IiII + I1ii11iIi11i / iII111i / I1IiiI + Ii1I
    if 88 - 88: IiII % iIii1I11I1II1
    if 3 - 3: ooOoO0o / I1Ii111 % iIii1I11I1II1 % I11i * oO0o / iIii1I11I1II1
   ooOoO0OoOo = i1ii . global_etr_rloc
   iI1I1iiIii = ii1I1i11 . translated_rloc
   if ( iI1I1iiIii . is_exact_match ( ooOoO0OoOo ) and
 i1ii . etr_port == ii1I1i11 . translated_port ) : continue
   if 72 - 72: OoOoOO00 * OoooooooOO % O0 / I1ii11iIi11i % Ii1I - I11i
   lprint ( "Store translation {}:{} for {} ({}), EID-prefix {}" . format ( red ( i1ii . global_etr_rloc . print_address_no_iid ( ) , False ) ,
   # OoOoOO00 % ooOoO0o . I1Ii111 / OoO0O00
 i1ii . etr_port , I111I , iIiiiIiIi , oo0ooooO ) )
   if 21 - 21: IiII
   ii1I1i11 . store_translated_rloc ( i1ii . global_etr_rloc ,
 i1ii . etr_port )
   if 15 - 15: OoOoOO00 % O0 - OOooOOo - oO0o . iII111i . OoO0O00
   if 52 - 52: II111iiii * o0oOOo0O0Ooo
 return ( [ i1ii . global_etr_rloc , i1ii . etr_port , III1IiI ] )
 if 95 - 95: I1Ii111 - OoooooooOO
 if 99 - 99: OoooooooOO % IiII . I11i + OoooooooOO
 if 57 - 57: Ii1I / I1IiiI * i1IIi
 if 21 - 21: I11i . O0 * OoooooooOO + ooOoO0o * oO0o % i11iIiiIii
 if 30 - 30: ooOoO0o * I1Ii111 + OoO0O00
 if 30 - 30: Ii1I / iII111i * Ii1I
 if 11 - 11: OoOoOO00 - OoOoOO00 % oO0o
 if 3 - 3: I1IiiI - OoooooooOO % iIii1I11I1II1 + I1Ii111 + OoOoOO00
def lisp_test_mr ( lisp_sockets , port ) :
 return
 lprint ( "Test Map-Resolvers" )
 if 71 - 71: i1IIi % O0 % ooOoO0o
 i1OO0o = lisp_address ( LISP_AFI_IPV4 , "" , 0 , 0 )
 i1iiI = lisp_address ( LISP_AFI_IPV6 , "" , 0 , 0 )
 if 65 - 65: I11i - iII111i * oO0o + Ii1I * i1IIi % OoOoOO00
 if 100 - 100: Ii1I % OoOoOO00 % iIii1I11I1II1
 if 44 - 44: ooOoO0o + O0 + Oo0Ooo / II111iiii . o0oOOo0O0Ooo + OoO0O00
 if 69 - 69: OoO0O00 . ooOoO0o * ooOoO0o * iIii1I11I1II1
 i1OO0o . store_address ( "10.0.0.1" )
 lisp_send_map_request ( lisp_sockets , port , None , i1OO0o , None )
 i1OO0o . store_address ( "192.168.0.1" )
 lisp_send_map_request ( lisp_sockets , port , None , i1OO0o , None )
 if 8 - 8: iII111i . oO0o . OOooOOo + iII111i . Ii1I
 if 46 - 46: OoO0O00
 if 21 - 21: iIii1I11I1II1 - iII111i
 if 15 - 15: O0 + iII111i + i11iIiiIii
 i1iiI . store_address ( "0100::1" )
 lisp_send_map_request ( lisp_sockets , port , None , i1iiI , None )
 i1iiI . store_address ( "8000::1" )
 lisp_send_map_request ( lisp_sockets , port , None , i1iiI , None )
 if 31 - 31: iIii1I11I1II1 * iIii1I11I1II1 . I11i
 if 52 - 52: i11iIiiIii / oO0o / IiII
 if 84 - 84: I11i . oO0o + ooOoO0o
 if 75 - 75: I1Ii111
 o0oOOo00oO0 = threading . Timer ( LISP_TEST_MR_INTERVAL , lisp_test_mr ,
 [ lisp_sockets , port ] )
 o0oOOo00oO0 . start ( )
 return
 if 58 - 58: iII111i + I1IiiI . O0
 if 73 - 73: ooOoO0o + O0 - I11i . I1IiiI + OOooOOo
 if 36 - 36: I11i % OoO0O00 * OoOoOO00 - I1Ii111
 if 16 - 16: ooOoO0o % OOooOOo . OoO0O00 % II111iiii . iIii1I11I1II1
 if 21 - 21: oO0o + II111iiii / OoOoOO00 * I11i
 if 90 - 90: OoOoOO00 % OoOoOO00 + I11i
 if 70 - 70: I1IiiI . ooOoO0o / I11i / OoO0O00
 if 40 - 40: oO0o % iIii1I11I1II1 * iIii1I11I1II1 / Oo0Ooo * OoO0O00
 if 61 - 61: OOooOOo
 if 80 - 80: I1ii11iIi11i
 if 6 - 6: I1ii11iIi11i + OOooOOo % ooOoO0o
 if 65 - 65: iIii1I11I1II1 % i1IIi / I1IiiI / oO0o % ooOoO0o / I11i
 if 2 - 2: I1ii11iIi11i
def lisp_update_local_rloc ( rloc ) :
 if ( rloc . interface == None ) : return
 if 90 - 90: II111iiii * I1Ii111 . ooOoO0o - I1ii11iIi11i % I11i * o0oOOo0O0Ooo
 I1Iii1I = lisp_get_interface_address ( rloc . interface )
 if ( I1Iii1I == None ) : return
 if 85 - 85: iIii1I11I1II1
 oooo0O0oOOo = rloc . rloc . print_address_no_iid ( )
 IIi1i1iI11I11 = I1Iii1I . print_address_no_iid ( )
 if 14 - 14: OoOoOO00 - O0 / OOooOOo % Oo0Ooo * IiII
 if ( oooo0O0oOOo == IIi1i1iI11I11 ) : return
 if 46 - 46: I1IiiI + i1IIi + Ii1I
 lprint ( "Local interface address changed on {} from {} to {}" . format ( rloc . interface , oooo0O0oOOo , IIi1i1iI11I11 ) )
 if 19 - 19: I1ii11iIi11i % I1IiiI
 if 85 - 85: II111iiii . Oo0Ooo / O0 % I11i * iII111i
 rloc . rloc . copy_address ( I1Iii1I )
 lisp_myrlocs [ 0 ] = I1Iii1I
 return
 if 6 - 6: OoooooooOO % ooOoO0o % OoO0O00 * IiII
 if 62 - 62: i1IIi . I11i / I11i
 if 90 - 90: O0 * OOooOOo / oO0o . Oo0Ooo * I11i
 if 93 - 93: oO0o / ooOoO0o - I1Ii111
 if 70 - 70: OOooOOo / Ii1I - ooOoO0o + OoooooooOO / OoO0O00 - i11iIiiIii
 if 26 - 26: O0 + Oo0Ooo
 if 30 - 30: IiII
 if 6 - 6: O0
def lisp_update_encap_port ( mc ) :
 for i1IIIIi1Ii111 in mc . rloc_set :
  IiiiI11I1 = lisp_get_nat_info ( i1IIIIi1Ii111 . rloc , i1IIIIi1Ii111 . rloc_name )
  if ( IiiiI11I1 == None ) : continue
  if ( i1IIIIi1Ii111 . translated_port == IiiiI11I1 . port ) : continue
  if 92 - 92: I11i
  lprint ( ( "Encap-port changed from {} to {} for RLOC {}, " + "EID-prefix {}" ) . format ( i1IIIIi1Ii111 . translated_port , IiiiI11I1 . port ,
  # I1IiiI % oO0o % OoooooooOO . i1IIi . O0
 red ( i1IIIIi1Ii111 . rloc . print_address_no_iid ( ) , False ) ,
 green ( mc . print_eid_tuple ( ) , False ) ) )
  if 9 - 9: OoooooooOO % Ii1I
  i1IIIIi1Ii111 . store_translated_rloc ( i1IIIIi1Ii111 . rloc , IiiiI11I1 . port )
  if 59 - 59: i1IIi * ooOoO0o . iIii1I11I1II1
 return
 if 87 - 87: ooOoO0o % I1ii11iIi11i . I1IiiI
 if 42 - 42: iII111i % i11iIiiIii % o0oOOo0O0Ooo . O0 % iII111i
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
def lisp_timeout_map_cache_entry ( mc , delete_list ) :
 if ( mc . map_cache_ttl == None ) :
  lisp_update_encap_port ( mc )
  return ( [ True , delete_list ] )
  if 33 - 33: I1Ii111
  if 1 - 1: IiII - iIii1I11I1II1 % OoooooooOO
  if 1 - 1: o0oOOo0O0Ooo - i11iIiiIii + I11i
  if 47 - 47: O0 + IiII + ooOoO0o + OOooOOo / OoOoOO00
  if 31 - 31: oO0o * iII111i % OoOoOO00
 if ( mc . action == LISP_NO_ACTION ) :
  iII1I11II = lisp_get_timestamp ( )
  if ( mc . last_refresh_time + mc . map_cache_ttl > iII1I11II ) :
   lisp_update_encap_port ( mc )
   return ( [ True , delete_list ] )
   if 80 - 80: ooOoO0o % I1ii11iIi11i % I11i . I1Ii111
   if 3 - 3: ooOoO0o - Oo0Ooo
   if 2 - 2: iII111i . iII111i
   if 77 - 77: OOooOOo
   if 74 - 74: O0
   if 86 - 86: OoOoOO00
 ooooOoO0O = lisp_print_elapsed ( mc . last_refresh_time )
 Oo0OooI11IIIiiiI = mc . print_eid_tuple ( )
 lprint ( "Map-cache entry for EID-prefix {} has {}, had uptime of {}" . format ( green ( Oo0OooI11IIIiiiI , False ) , bold ( "timed out" , False ) , ooooOoO0O ) )
 if 4 - 4: OoooooooOO * OoO0O00
 if 93 - 93: OoO0O00 - I1Ii111 - OoO0O00
 if 1 - 1: o0oOOo0O0Ooo . oO0o * i11iIiiIii * IiII - OoO0O00 - OoooooooOO
 if 29 - 29: iIii1I11I1II1 + OoO0O00 * II111iiii * Ii1I * iII111i . O0
 if 6 - 6: I1IiiI - OoOoOO00
 delete_list . append ( mc )
 return ( [ True , delete_list ] )
 if 63 - 63: OOooOOo - oO0o * I1IiiI
 if 60 - 60: II111iiii - Oo0Ooo
 if 43 - 43: I1IiiI - IiII - OOooOOo
 if 19 - 19: I1Ii111 / I1Ii111 - i1IIi
 if 99 - 99: O0
 if 37 - 37: iIii1I11I1II1 / I1Ii111 + OoO0O00
 if 85 - 85: ooOoO0o / I1IiiI
 if 7 - 7: Oo0Ooo - iIii1I11I1II1 / I1ii11iIi11i * I1IiiI + Ii1I
def lisp_timeout_map_cache_walk ( mc , parms ) :
 OOoOoo0OO = parms [ 0 ]
 ooOO0o0oO = parms [ 1 ]
 if 12 - 12: I1Ii111 / I11i / Ii1I
 if 95 - 95: iIii1I11I1II1 . Ii1I % oO0o - I11i % IiII
 if 42 - 42: OoOoOO00 + oO0o * i1IIi + i11iIiiIii
 if 25 - 25: Ii1I - Ii1I - I1ii11iIi11i / i1IIi . OoOoOO00 % Oo0Ooo
 if ( mc . group . is_null ( ) ) :
  ii1 , OOoOoo0OO = lisp_timeout_map_cache_entry ( mc , OOoOoo0OO )
  if ( OOoOoo0OO == [ ] or mc != OOoOoo0OO [ - 1 ] ) :
   ooOO0o0oO = lisp_write_checkpoint_entry ( ooOO0o0oO , mc )
   if 76 - 76: I1Ii111 / OoOoOO00
  return ( [ ii1 , parms ] )
  if 61 - 61: Oo0Ooo . i1IIi
  if 78 - 78: i11iIiiIii
 if ( mc . source_cache == None ) : return ( [ True , parms ] )
 if 20 - 20: Ii1I
 if 100 - 100: OoooooooOO . I1Ii111
 if 32 - 32: iIii1I11I1II1 . iIii1I11I1II1 % II111iiii / Oo0Ooo . iIii1I11I1II1 . O0
 if 63 - 63: I1IiiI . iIii1I11I1II1 . Oo0Ooo % OOooOOo - iII111i + ooOoO0o
 if 64 - 64: o0oOOo0O0Ooo / Ii1I % I1Ii111 % iII111i + OOooOOo * IiII
 parms = mc . source_cache . walk_cache ( lisp_timeout_map_cache_entry , parms )
 return ( [ True , parms ] )
 if 87 - 87: I1ii11iIi11i . i1IIi - I11i + OoOoOO00 . O0
 if 37 - 37: IiII
 if 65 - 65: ooOoO0o * Ii1I / I1IiiI . i1IIi % ooOoO0o . OoooooooOO
 if 17 - 17: ooOoO0o / OoO0O00 / I1IiiI / OOooOOo % IiII
 if 88 - 88: i1IIi - OoOoOO00
 if 66 - 66: OoooooooOO - OoooooooOO * I11i / II111iiii + oO0o / Ii1I
 if 7 - 7: Ii1I / iIii1I11I1II1
def lisp_timeout_map_cache ( lisp_map_cache ) :
 oOOOOOo = [ [ ] , [ ] ]
 oOOOOOo = lisp_map_cache . walk_cache ( lisp_timeout_map_cache_walk , oOOOOOo )
 if 36 - 36: iIii1I11I1II1 % i11iIiiIii
 if 35 - 35: Oo0Ooo + I1IiiI - O0 - I1Ii111
 if 64 - 64: i1IIi * OoOoOO00 / II111iiii * oO0o
 if 35 - 35: i1IIi - Ii1I - Ii1I . O0 % iII111i * iII111i
 if 15 - 15: OoooooooOO . Ii1I * I1Ii111 . ooOoO0o % OoO0O00 * Oo0Ooo
 OOoOoo0OO = oOOOOOo [ 0 ]
 for Iii1 in OOoOoo0OO : Iii1 . delete_cache ( )
 if 10 - 10: iII111i + i11iIiiIii . OOooOOo % iII111i - i1IIi
 if 10 - 10: iIii1I11I1II1 * i11iIiiIii - O0
 if 45 - 45: oO0o % OOooOOo - IiII + o0oOOo0O0Ooo + i11iIiiIii
 if 79 - 79: IiII % I1Ii111 . I1IiiI + O0 * oO0o * ooOoO0o
 ooOO0o0oO = oOOOOOo [ 1 ]
 lisp_checkpoint ( ooOO0o0oO )
 return
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
 if 16 - 16: Oo0Ooo
def lisp_store_nat_info ( hostname , rloc , port ) :
 OoOOoooO000 = rloc . print_address_no_iid ( )
 iIiiIIiII1iII11 = "{} NAT state for {}, RLOC {}, port {}" . format ( "{}" ,
 blue ( hostname , False ) , red ( OoOOoooO000 , False ) , port )
 if 75 - 75: i11iIiiIii / II111iiii - Ii1I % O0
 OoO0Oo = lisp_nat_info ( OoOOoooO000 , hostname , port )
 if 19 - 19: iIii1I11I1II1 + I1Ii111 / OoooooooOO % OOooOOo - i1IIi + I11i
 if ( lisp_nat_state_info . has_key ( hostname ) == False ) :
  lisp_nat_state_info [ hostname ] = [ OoO0Oo ]
  lprint ( iIiiIIiII1iII11 . format ( "Store initial" ) )
  return ( True )
  if 87 - 87: OoooooooOO
  if 97 - 97: ooOoO0o * IiII / iIii1I11I1II1
  if 65 - 65: i1IIi - i11iIiiIii + oO0o % I1IiiI - OoO0O00 % ooOoO0o
  if 23 - 23: o0oOOo0O0Ooo . o0oOOo0O0Ooo - iIii1I11I1II1 / o0oOOo0O0Ooo
  if 65 - 65: I1Ii111 + I1Ii111 . I1ii11iIi11i . OoOoOO00 % o0oOOo0O0Ooo * o0oOOo0O0Ooo
  if 2 - 2: oO0o % iII111i + I1ii11iIi11i / II111iiii * I1ii11iIi11i
 IiiiI11I1 = lisp_nat_state_info [ hostname ] [ 0 ]
 if ( IiiiI11I1 . address == OoOOoooO000 and IiiiI11I1 . port == port ) :
  IiiiI11I1 . uptime = lisp_get_timestamp ( )
  lprint ( iIiiIIiII1iII11 . format ( "Refresh existing" ) )
  return ( False )
  if 45 - 45: II111iiii . iII111i
  if 55 - 55: ooOoO0o / iII111i / O0
  if 98 - 98: O0 % iII111i + II111iiii
  if 13 - 13: I1IiiI * oO0o - o0oOOo0O0Ooo
  if 23 - 23: iIii1I11I1II1 + oO0o . oO0o / o0oOOo0O0Ooo
  if 77 - 77: i1IIi * o0oOOo0O0Ooo * IiII
  if 24 - 24: i11iIiiIii / iIii1I11I1II1 / iII111i
 iIoOoooO0oo = None
 for IiiiI11I1 in lisp_nat_state_info [ hostname ] :
  if ( IiiiI11I1 . address == OoOOoooO000 and IiiiI11I1 . port == port ) :
   iIoOoooO0oo = IiiiI11I1
   break
   if 36 - 36: ooOoO0o - oO0o * IiII * OOooOOo / OoooooooOO % i1IIi
   if 73 - 73: OoOoOO00 / i1IIi * iII111i + II111iiii + II111iiii % I11i
   if 11 - 11: iII111i + o0oOOo0O0Ooo - iII111i - OoooooooOO
 if ( iIoOoooO0oo == None ) :
  lprint ( iIiiIIiII1iII11 . format ( "Store new" ) )
 else :
  lisp_nat_state_info [ hostname ] . remove ( iIoOoooO0oo )
  lprint ( iIiiIIiII1iII11 . format ( "Use previous" ) )
  if 19 - 19: ooOoO0o % O0 % oO0o % OOooOOo % OoO0O00
  if 90 - 90: O0
 OO0000oOOO = lisp_nat_state_info [ hostname ]
 lisp_nat_state_info [ hostname ] = [ OoO0Oo ] + OO0000oOOO
 return ( True )
 if 49 - 49: OOooOOo / i1IIi - II111iiii . iIii1I11I1II1 + I11i . OOooOOo
 if 9 - 9: iIii1I11I1II1 + Ii1I + I11i
 if 96 - 96: OoO0O00 + i11iIiiIii + OoO0O00
 if 7 - 7: i1IIi . I1IiiI
 if 68 - 68: OoooooooOO
 if 91 - 91: IiII . ooOoO0o * I11i
 if 39 - 39: o0oOOo0O0Ooo + i11iIiiIii
 if 69 - 69: iIii1I11I1II1 . II111iiii
def lisp_get_nat_info ( rloc , hostname ) :
 if ( lisp_nat_state_info . has_key ( hostname ) == False ) : return ( None )
 if 36 - 36: I1IiiI * i1IIi + OoOoOO00
 OoOOoooO000 = rloc . print_address_no_iid ( )
 for IiiiI11I1 in lisp_nat_state_info [ hostname ] :
  if ( IiiiI11I1 . address == OoOOoooO000 ) : return ( IiiiI11I1 )
  if 63 - 63: OoOoOO00 - iII111i
 return ( None )
 if 83 - 83: i1IIi / iII111i % ooOoO0o % i11iIiiIii + I1ii11iIi11i
 if 82 - 82: iIii1I11I1II1 / OOooOOo
 if 7 - 7: OoooooooOO
 if 71 - 71: OOooOOo * Oo0Ooo . Oo0Ooo % iIii1I11I1II1
 if 56 - 56: IiII * iIii1I11I1II1 - iIii1I11I1II1 . O0
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
def lisp_build_info_requests ( lisp_sockets , dest , port ) :
 if ( lisp_nat_traversal == False ) : return
 if 16 - 16: I11i * OoO0O00 % o0oOOo0O0Ooo - O0 % II111iiii - I1IiiI
 if 72 - 72: OoooooooOO * OoOoOO00 . OOooOOo + Ii1I . OOooOOo / II111iiii
 if 8 - 8: i1IIi
 if 1 - 1: OoOoOO00 . OoO0O00 . OoO0O00 * O0
 if 97 - 97: OoooooooOO % ooOoO0o . I1Ii111 / iII111i
 if 59 - 59: II111iiii + O0 . I1ii11iIi11i . Oo0Ooo * OoO0O00
 II11I = [ ]
 o0o = [ ]
 if ( dest == None ) :
  for IIiIII1IIi in lisp_map_resolvers_list . values ( ) :
   o0o . append ( IIiIII1IIi . map_resolver )
   if 88 - 88: I1IiiI / i11iIiiIii * OOooOOo
  II11I = o0o
  if ( II11I == [ ] ) :
   for ii1I111i in lisp_map_servers_list . values ( ) :
    II11I . append ( ii1I111i . map_server )
    if 3 - 3: oO0o / o0oOOo0O0Ooo - OOooOOo . OoOoOO00 * I1Ii111
    if 61 - 61: OOooOOo + OoooooooOO
  if ( II11I == [ ] ) : return
 else :
  II11I . append ( dest )
  if 17 - 17: I1Ii111 / OOooOOo . i11iIiiIii - I11i
  if 7 - 7: I1Ii111 + ooOoO0o % o0oOOo0O0Ooo
  if 53 - 53: i1IIi / iII111i % Ii1I % OoooooooOO
  if 63 - 63: OOooOOo + I1ii11iIi11i . i1IIi . Ii1I - I1ii11iIi11i * o0oOOo0O0Ooo
  if 79 - 79: ooOoO0o - O0
 IiIi1IiI1 = { }
 for o0Oo00OOOo00 in lisp_db_list :
  for ii1I1i11 in o0Oo00OOOo00 . rloc_set :
   lisp_update_local_rloc ( ii1I1i11 )
   if ( ii1I1i11 . rloc . is_null ( ) ) : continue
   if ( ii1I1i11 . interface == None ) : continue
   if 20 - 20: OOooOOo
   I1Iii1I = ii1I1i11 . rloc . print_address_no_iid ( )
   if ( I1Iii1I in IiIi1IiI1 ) : continue
   IiIi1IiI1 [ I1Iii1I ] = ii1I1i11 . interface
   if 22 - 22: iIii1I11I1II1 / I1Ii111
   if 6 - 6: iII111i . i11iIiiIii / Oo0Ooo
 if ( IiIi1IiI1 == { } ) :
  lprint ( 'Suppress Info-Request, no "interface = <device>" RLOC ' + "found in any database-mappings" )
  if 86 - 86: I11i % I1Ii111 % oO0o - ooOoO0o / i1IIi
  return
  if 68 - 68: i1IIi % O0 % iII111i
  if 55 - 55: I1ii11iIi11i % OOooOOo - o0oOOo0O0Ooo - II111iiii
  if 52 - 52: I1Ii111
  if 34 - 34: II111iiii + iII111i / IiII
  if 47 - 47: OoO0O00
  if 40 - 40: o0oOOo0O0Ooo / iII111i . o0oOOo0O0Ooo
 for I1Iii1I in IiIi1IiI1 :
  iIiiiIiIi = IiIi1IiI1 [ I1Iii1I ]
  OOOO0o = red ( I1Iii1I , False )
  lprint ( "Build Info-Request for private address {} ({})" . format ( OOOO0o ,
 iIiiiIiIi ) )
  Ooooo = iIiiiIiIi if len ( IiIi1IiI1 ) > 1 else None
  for dest in II11I :
   lisp_send_info_request ( lisp_sockets , dest , port , Ooooo )
   if 63 - 63: o0oOOo0O0Ooo * iIii1I11I1II1 * II111iiii . OoO0O00 - oO0o / OoOoOO00
   if 78 - 78: i11iIiiIii / OoO0O00 / i1IIi . i11iIiiIii
   if 100 - 100: II111iiii . IiII . I11i
   if 60 - 60: OoOoOO00 % OOooOOo * i1IIi
   if 3 - 3: OoooooooOO
   if 75 - 75: OoooooooOO * I1Ii111 * o0oOOo0O0Ooo + I1ii11iIi11i . iIii1I11I1II1 / O0
 if ( o0o != [ ] ) :
  for IIiIII1IIi in lisp_map_resolvers_list . values ( ) :
   IIiIII1IIi . resolve_dns_name ( )
   if 23 - 23: oO0o - O0 * IiII + i11iIiiIii * Ii1I
   if 8 - 8: ooOoO0o / II111iiii . I1ii11iIi11i * ooOoO0o % oO0o
 return
 if 36 - 36: I1ii11iIi11i % OOooOOo - ooOoO0o - I11i + I1IiiI
 if 37 - 37: I1ii11iIi11i * IiII
 if 65 - 65: OOooOOo / O0 . I1ii11iIi11i % i1IIi % Oo0Ooo
 if 36 - 36: i11iIiiIii - OOooOOo + iII111i + iII111i * I11i * oO0o
 if 14 - 14: O0 - iII111i * I1Ii111 - I1IiiI + IiII
 if 46 - 46: OoooooooOO * OoO0O00 . I1Ii111
 if 95 - 95: ooOoO0o . I1ii11iIi11i . ooOoO0o / I1IiiI * OoOoOO00 . O0
 if 78 - 78: oO0o
def lisp_valid_address_format ( kw , value ) :
 if ( kw != "address" ) : return ( True )
 if 33 - 33: oO0o + i1IIi
 if 32 - 32: iIii1I11I1II1
 if 71 - 71: Ii1I * I1IiiI
 if 62 - 62: II111iiii / I1IiiI . I1ii11iIi11i
 if 49 - 49: IiII / OoOoOO00 / O0 * i11iIiiIii
 if ( value [ 0 ] == "'" and value [ - 1 ] == "'" ) : return ( True )
 if 47 - 47: i11iIiiIii + iII111i + i11iIiiIii
 if 66 - 66: o0oOOo0O0Ooo . I1IiiI + OoooooooOO . iII111i / OoooooooOO - IiII
 if 47 - 47: o0oOOo0O0Ooo / II111iiii * i11iIiiIii * OoO0O00 . iIii1I11I1II1
 if 34 - 34: I11i / o0oOOo0O0Ooo * OOooOOo * OOooOOo
 if ( value . find ( "." ) != - 1 ) :
  I1Iii1I = value . split ( "." )
  if ( len ( I1Iii1I ) != 4 ) : return ( False )
  if 89 - 89: I1ii11iIi11i . OoooooooOO
  for oooO00 in I1Iii1I :
   if ( oooO00 . isdigit ( ) == False ) : return ( False )
   if ( int ( oooO00 ) > 255 ) : return ( False )
   if 3 - 3: I1Ii111 - Oo0Ooo / iIii1I11I1II1
  return ( True )
  if 71 - 71: o0oOOo0O0Ooo + i11iIiiIii + OoooooooOO % OoOoOO00 - I1ii11iIi11i / OoooooooOO
  if 26 - 26: II111iiii
  if 41 - 41: Oo0Ooo . OoOoOO00 . iII111i / i11iIiiIii
  if 65 - 65: iII111i * o0oOOo0O0Ooo * OoooooooOO + I11i + oO0o % OoO0O00
  if 1 - 1: I1ii11iIi11i . ooOoO0o
 if ( value . find ( "-" ) != - 1 ) :
  I1Iii1I = value . split ( "-" )
  for oO in [ "N" , "S" , "W" , "E" ] :
   if ( oO in I1Iii1I ) :
    if ( len ( I1Iii1I ) < 8 ) : return ( False )
    return ( True )
    if 54 - 54: OoOoOO00 % I1IiiI . ooOoO0o + IiII / i11iIiiIii / o0oOOo0O0Ooo
    if 51 - 51: OoOoOO00 / Ii1I . I1IiiI / Ii1I . II111iiii - iIii1I11I1II1
    if 78 - 78: I11i
    if 42 - 42: Ii1I
    if 50 - 50: iIii1I11I1II1 / Ii1I . ooOoO0o / ooOoO0o * OoOoOO00 * iII111i
    if 15 - 15: o0oOOo0O0Ooo % II111iiii + I1IiiI
    if 21 - 21: I1ii11iIi11i - ooOoO0o
 if ( value . find ( "-" ) != - 1 ) :
  I1Iii1I = value . split ( "-" )
  if ( len ( I1Iii1I ) != 3 ) : return ( False )
  if 81 - 81: iII111i / i11iIiiIii / I1Ii111
  for oOo0 in I1Iii1I :
   try : int ( oOo0 , 16 )
   except : return ( False )
   if 64 - 64: iIii1I11I1II1 / OoOoOO00
  return ( True )
  if 14 - 14: Ii1I / OoooooooOO . i1IIi % IiII % i11iIiiIii
  if 23 - 23: iIii1I11I1II1 - o0oOOo0O0Ooo - Ii1I % OOooOOo
  if 100 - 100: oO0o . OoO0O00 . i11iIiiIii % II111iiii * IiII
  if 81 - 81: OOooOOo - OOooOOo + OoOoOO00
  if 19 - 19: o0oOOo0O0Ooo
 if ( value . find ( ":" ) != - 1 ) :
  I1Iii1I = value . split ( ":" )
  if ( len ( I1Iii1I ) < 2 ) : return ( False )
  if 20 - 20: I1Ii111 + iIii1I11I1II1 % I1IiiI + ooOoO0o
  oOOo00oOO00o = False
  o0OO0oooo = 0
  for oOo0 in I1Iii1I :
   o0OO0oooo += 1
   if ( oOo0 == "" ) :
    if ( oOOo00oOO00o ) :
     if ( len ( I1Iii1I ) == o0OO0oooo ) : break
     if ( o0OO0oooo > 2 ) : return ( False )
     if 22 - 22: oO0o % IiII + O0 - IiII . OoOoOO00 . I1IiiI
    oOOo00oOO00o = True
    continue
    if 71 - 71: oO0o % i11iIiiIii + I1Ii111 . OoooooooOO * i1IIi
   try : int ( oOo0 , 16 )
   except : return ( False )
   if 85 - 85: II111iiii - Oo0Ooo . OoOoOO00 - i1IIi - I1ii11iIi11i
  return ( True )
  if 24 - 24: ooOoO0o % ooOoO0o - I1ii11iIi11i - OoO0O00 % I1IiiI
  if 8 - 8: iIii1I11I1II1 - O0 - i11iIiiIii . O0
  if 35 - 35: Ii1I . II111iiii % OoOoOO00
  if 3 - 3: OOooOOo - OoOoOO00
  if 49 - 49: IiII / i11iIiiIii
 if ( value [ 0 ] == "+" ) :
  I1Iii1I = value [ 1 : : ]
  for ooOo in I1Iii1I :
   if ( ooOo . isdigit ( ) == False ) : return ( False )
   if 49 - 49: OOooOOo / OoO0O00 % I1Ii111
  return ( True )
  if 80 - 80: iII111i
 return ( False )
 if 17 - 17: oO0o % o0oOOo0O0Ooo . o0oOOo0O0Ooo + ooOoO0o + I1Ii111 - OoO0O00
 if 37 - 37: i1IIi * OOooOOo / OoooooooOO + II111iiii
 if 73 - 73: I1Ii111 - II111iiii / Ii1I + Ii1I
 if 41 - 41: II111iiii / II111iiii / iII111i * I1IiiI * I1Ii111 * oO0o
 if 2 - 2: OoOoOO00 - I1ii11iIi11i * I1IiiI * Ii1I
 if 41 - 41: OoOoOO00 . OOooOOo / OoOoOO00 % iIii1I11I1II1
 if 47 - 47: ooOoO0o . i11iIiiIii / OoO0O00
 if 48 - 48: O0
 if 89 - 89: i11iIiiIii % OoO0O00 . OoOoOO00 + Oo0Ooo + OoOoOO00
 if 53 - 53: Ii1I / OoOoOO00 % iII111i * OoooooooOO + Oo0Ooo
 if 70 - 70: OoO0O00 % OoO0O00 * OoooooooOO
 if 96 - 96: ooOoO0o * Ii1I + I11i + II111iiii * I1IiiI / iII111i
def lisp_process_api ( process , lisp_socket , data_structure ) :
 Ii11IIiII , oOOOOOo = data_structure . split ( "%" )
 if 35 - 35: oO0o * OOooOOo . OoooooooOO . OOooOOo . i11iIiiIii
 lprint ( "Process API request '{}', parameters: '{}'" . format ( Ii11IIiII ,
 oOOOOOo ) )
 if 71 - 71: oO0o + I1ii11iIi11i * I1ii11iIi11i
 O0OooO0oo = [ ]
 if ( Ii11IIiII == "map-cache" ) :
  if ( oOOOOOo == "" ) :
   O0OooO0oo = lisp_map_cache . walk_cache ( lisp_process_api_map_cache , O0OooO0oo )
  else :
   O0OooO0oo = lisp_process_api_map_cache_entry ( json . loads ( oOOOOOo ) )
   if 79 - 79: oO0o
   if 47 - 47: OoooooooOO - i1IIi * OOooOOo
 if ( Ii11IIiII == "site-cache" ) :
  if ( oOOOOOo == "" ) :
   O0OooO0oo = lisp_sites_by_eid . walk_cache ( lisp_process_api_site_cache ,
 O0OooO0oo )
  else :
   O0OooO0oo = lisp_process_api_site_cache_entry ( json . loads ( oOOOOOo ) )
   if 11 - 11: I11i / OOooOOo . o0oOOo0O0Ooo - O0 * OoooooooOO % iII111i
   if 7 - 7: OoOoOO00 . IiII + OoooooooOO - I1Ii111 / oO0o
 if ( Ii11IIiII == "map-server" ) :
  oOOOOOo = { } if ( oOOOOOo == "" ) else json . loads ( oOOOOOo )
  O0OooO0oo = lisp_process_api_ms_or_mr ( True , oOOOOOo )
  if 32 - 32: iIii1I11I1II1 + I11i + OOooOOo - OoooooooOO + i11iIiiIii * o0oOOo0O0Ooo
 if ( Ii11IIiII == "map-resolver" ) :
  oOOOOOo = { } if ( oOOOOOo == "" ) else json . loads ( oOOOOOo )
  O0OooO0oo = lisp_process_api_ms_or_mr ( False , oOOOOOo )
  if 8 - 8: iII111i
 if ( Ii11IIiII == "database-mapping" ) :
  O0OooO0oo = lisp_process_api_database_mapping ( )
  if 10 - 10: OoOoOO00 % I11i
  if 49 - 49: oO0o % ooOoO0o + II111iiii
  if 21 - 21: i1IIi + OoO0O00 . I1IiiI - Oo0Ooo
  if 99 - 99: OoOoOO00
  if 46 - 46: I1ii11iIi11i / II111iiii / OoooooooOO / Ii1I
 O0OooO0oo = json . dumps ( O0OooO0oo )
 Oooo000 = lisp_api_ipc ( process , O0OooO0oo )
 lisp_ipc ( Oooo000 , lisp_socket , "lisp-core" )
 return
 if 37 - 37: I1ii11iIi11i - Ii1I / oO0o . I1IiiI % I1Ii111
 if 8 - 8: oO0o
 if 46 - 46: I1Ii111 + IiII + II111iiii . o0oOOo0O0Ooo + i11iIiiIii
 if 97 - 97: o0oOOo0O0Ooo % OoOoOO00 * O0 / iIii1I11I1II1 * OoO0O00 / i11iIiiIii
 if 1 - 1: OoooooooOO . Ii1I
 if 68 - 68: Ii1I
 if 98 - 98: iII111i
def lisp_process_api_map_cache ( mc , data ) :
 if 33 - 33: OoO0O00 - ooOoO0o % O0 % iIii1I11I1II1 * iII111i - iII111i
 if 27 - 27: i11iIiiIii + I1ii11iIi11i + i1IIi
 if 67 - 67: o0oOOo0O0Ooo
 if 58 - 58: IiII % o0oOOo0O0Ooo + i1IIi
 if ( mc . group . is_null ( ) ) : return ( lisp_gather_map_cache_data ( mc , data ) )
 if 33 - 33: II111iiii
 if ( mc . source_cache == None ) : return ( [ True , data ] )
 if 61 - 61: I1Ii111
 if 56 - 56: I1ii11iIi11i - OoooooooOO
 if 52 - 52: Oo0Ooo - I11i - IiII - OoOoOO00
 if 21 - 21: oO0o % o0oOOo0O0Ooo + I1Ii111 . OOooOOo / OOooOOo
 if 41 - 41: Oo0Ooo . ooOoO0o * oO0o
 data = mc . source_cache . walk_cache ( lisp_gather_map_cache_data , data )
 return ( [ True , data ] )
 if 31 - 31: Oo0Ooo * IiII / IiII
 if 3 - 3: I1Ii111
 if 65 - 65: iIii1I11I1II1 % Oo0Ooo % I11i / OoooooooOO
 if 82 - 82: o0oOOo0O0Ooo
 if 33 - 33: OoOoOO00 / i11iIiiIii - I1IiiI - OoooooooOO + i1IIi * I1Ii111
 if 92 - 92: iII111i + OoO0O00
 if 70 - 70: iIii1I11I1II1
def lisp_gather_map_cache_data ( mc , data ) :
 o0Iiii = { }
 o0Iiii [ "instance-id" ] = str ( mc . eid . instance_id )
 o0Iiii [ "eid-prefix" ] = mc . eid . print_prefix_no_iid ( )
 if ( mc . group . is_null ( ) == False ) :
  o0Iiii [ "group-prefix" ] = mc . group . print_prefix_no_iid ( )
  if 100 - 100: OOooOOo . oO0o % ooOoO0o * ooOoO0o . I1Ii111 - oO0o
 o0Iiii [ "uptime" ] = lisp_print_elapsed ( mc . uptime )
 o0Iiii [ "expires" ] = lisp_print_elapsed ( mc . uptime )
 o0Iiii [ "action" ] = lisp_map_reply_action_string [ mc . action ]
 o0Iiii [ "ttl" ] = "--" if mc . map_cache_ttl == None else str ( mc . map_cache_ttl / 60 )
 if 33 - 33: Oo0Ooo . i1IIi - OoooooooOO
 if 14 - 14: I1Ii111 + Oo0Ooo
 if 35 - 35: i11iIiiIii * Ii1I
 if 100 - 100: O0 . iII111i / iIii1I11I1II1
 if 47 - 47: ooOoO0o + OoOoOO00
 oOo0oOOOoOoo = [ ]
 for i1IIIIi1Ii111 in mc . rloc_set :
  iIOoo000 = { }
  if ( i1IIIIi1Ii111 . rloc_exists ( ) ) :
   iIOoo000 [ "address" ] = i1IIIIi1Ii111 . rloc . print_address_no_iid ( )
   if 67 - 67: IiII - I1ii11iIi11i * i1IIi - ooOoO0o
   if 91 - 91: I11i
  if ( i1IIIIi1Ii111 . translated_port != 0 ) :
   iIOoo000 [ "encap-port" ] = str ( i1IIIIi1Ii111 . translated_port )
   if 54 - 54: I1ii11iIi11i / i1IIi
  iIOoo000 [ "state" ] = i1IIIIi1Ii111 . print_state ( )
  if ( i1IIIIi1Ii111 . geo ) : iIOoo000 [ "geo" ] = i1IIIIi1Ii111 . geo . print_geo ( )
  if ( i1IIIIi1Ii111 . elp ) : iIOoo000 [ "elp" ] = i1IIIIi1Ii111 . elp . print_elp ( False )
  if ( i1IIIIi1Ii111 . rle ) : iIOoo000 [ "rle" ] = i1IIIIi1Ii111 . rle . print_rle ( False )
  if ( i1IIIIi1Ii111 . json ) : iIOoo000 [ "json" ] = i1IIIIi1Ii111 . json . print_json ( False )
  if ( i1IIIIi1Ii111 . rloc_name ) : iIOoo000 [ "rloc-name" ] = i1IIIIi1Ii111 . rloc_name
  oO000O0oooOo = i1IIIIi1Ii111 . stats . get_stats ( False , False )
  if ( oO000O0oooOo ) : iIOoo000 [ "stats" ] = oO000O0oooOo
  iIOoo000 [ "uptime" ] = lisp_print_elapsed ( i1IIIIi1Ii111 . uptime )
  iIOoo000 [ "upriority" ] = str ( i1IIIIi1Ii111 . priority )
  iIOoo000 [ "uweight" ] = str ( i1IIIIi1Ii111 . weight )
  iIOoo000 [ "mpriority" ] = str ( i1IIIIi1Ii111 . mpriority )
  iIOoo000 [ "mweight" ] = str ( i1IIIIi1Ii111 . mweight )
  Iii111111I1I = i1IIIIi1Ii111 . last_rloc_probe_reply
  if ( Iii111111I1I ) :
   iIOoo000 [ "last-rloc-probe-reply" ] = lisp_print_elapsed ( Iii111111I1I )
   iIOoo000 [ "rloc-probe-rtt" ] = str ( i1IIIIi1Ii111 . rloc_probe_rtt )
   if 14 - 14: o0oOOo0O0Ooo / O0 - iIii1I11I1II1
  iIOoo000 [ "rloc-hop-count" ] = i1IIIIi1Ii111 . rloc_probe_hops
  iIOoo000 [ "recent-rloc-hop-counts" ] = i1IIIIi1Ii111 . recent_rloc_probe_hops
  if 88 - 88: OoooooooOO
  i111i111i = [ ]
  for iiiI1i1I in i1IIIIi1Ii111 . recent_rloc_probe_rtts : i111i111i . append ( str ( iiiI1i1I ) )
  iIOoo000 [ "recent-rloc-probe-rtts" ] = i111i111i
  if 29 - 29: IiII / OoooooooOO + I1ii11iIi11i
  oOo0oOOOoOoo . append ( iIOoo000 )
  if 21 - 21: I1ii11iIi11i
 o0Iiii [ "rloc-set" ] = oOo0oOOOoOoo
 if 35 - 35: IiII % Oo0Ooo * Ii1I . IiII
 data . append ( o0Iiii )
 return ( [ True , data ] )
 if 16 - 16: I1ii11iIi11i % I1IiiI + Ii1I * I11i + i1IIi
 if 14 - 14: iII111i / ooOoO0o % IiII - I1IiiI . Oo0Ooo
 if 30 - 30: O0 . OOooOOo
 if 23 - 23: i1IIi + OoooooooOO * OOooOOo . Oo0Ooo
 if 83 - 83: OoooooooOO
 if 53 - 53: o0oOOo0O0Ooo - Oo0Ooo / IiII + O0
 if 88 - 88: Oo0Ooo % I1Ii111 * O0 - i1IIi * OoO0O00
def lisp_process_api_map_cache_entry ( parms ) :
 IIiI1i = parms [ "instance-id" ]
 IIiI1i = 0 if ( IIiI1i == "" ) else int ( IIiI1i )
 if 74 - 74: Oo0Ooo % iIii1I11I1II1 + OOooOOo
 if 50 - 50: OoO0O00 . OoooooooOO
 if 31 - 31: OoO0O00
 if 55 - 55: OoOoOO00 + I1Ii111 * o0oOOo0O0Ooo - I1ii11iIi11i + OoOoOO00
 i1OO0o = lisp_address ( LISP_AFI_NONE , "" , 0 , IIiI1i )
 i1OO0o . store_prefix ( parms [ "eid-prefix" ] )
 iiIi1I = i1OO0o
 IIi1IiIii = i1OO0o
 if 6 - 6: II111iiii % iIii1I11I1II1 * I1Ii111
 if 2 - 2: IiII - I1Ii111 . iIii1I11I1II1 - Ii1I * I11i
 if 58 - 58: i1IIi % iIii1I11I1II1 % i11iIiiIii - o0oOOo0O0Ooo + ooOoO0o
 if 23 - 23: Oo0Ooo % Oo0Ooo / IiII
 if 63 - 63: I11i % Oo0Ooo * I1Ii111 - Oo0Ooo % i11iIiiIii . II111iiii
 Oo000o0o0 = lisp_address ( LISP_AFI_NONE , "" , 0 , IIiI1i )
 if ( parms . has_key ( "group-prefix" ) ) :
  Oo000o0o0 . store_prefix ( parms [ "group-prefix" ] )
  iiIi1I = Oo000o0o0
  if 44 - 44: I11i . I1Ii111 . I1ii11iIi11i . oO0o
  if 1 - 1: I11i % II111iiii / OoO0O00 + OoO0O00
 O0OooO0oo = [ ]
 Iii1 = lisp_map_cache_lookup ( IIi1IiIii , iiIi1I )
 if ( Iii1 ) : ii1 , O0OooO0oo = lisp_process_api_map_cache ( Iii1 , O0OooO0oo )
 return ( O0OooO0oo )
 if 46 - 46: Oo0Ooo * Ii1I / IiII % O0 * iII111i
 if 74 - 74: OoooooooOO + Ii1I
 if 100 - 100: I1IiiI
 if 59 - 59: I1IiiI - OoOoOO00 * ooOoO0o / O0
 if 54 - 54: Oo0Ooo % iIii1I11I1II1 * Oo0Ooo
 if 80 - 80: I1ii11iIi11i - I1ii11iIi11i
 if 26 - 26: I1ii11iIi11i - I1IiiI * I1Ii111 % iIii1I11I1II1
def lisp_process_api_site_cache ( se , data ) :
 if 77 - 77: o0oOOo0O0Ooo + I1Ii111 . OOooOOo . i1IIi . I1IiiI
 if 100 - 100: ooOoO0o . i11iIiiIii + Ii1I - OOooOOo - i11iIiiIii - OoooooooOO
 if 42 - 42: OoOoOO00 . I1IiiI / OoOoOO00 / I1ii11iIi11i . OoO0O00
 if 67 - 67: Ii1I - O0 . OoooooooOO . I1Ii111 . o0oOOo0O0Ooo
 if ( se . group . is_null ( ) ) : return ( lisp_gather_site_cache_data ( se , data ) )
 if 73 - 73: I11i - oO0o . I1Ii111 + oO0o
 if ( se . source_cache == None ) : return ( [ True , data ] )
 if 48 - 48: IiII . IiII * o0oOOo0O0Ooo * II111iiii % ooOoO0o
 if 40 - 40: I1ii11iIi11i
 if 76 - 76: Oo0Ooo - I11i
 if 82 - 82: OoO0O00 % oO0o . I11i / O0 - I1Ii111
 if 39 - 39: I1IiiI
 data = se . source_cache . walk_cache ( lisp_gather_site_cache_data , data )
 return ( [ True , data ] )
 if 8 - 8: IiII * i1IIi * i1IIi * O0
 if 69 - 69: Oo0Ooo
 if 48 - 48: iII111i
 if 11 - 11: i11iIiiIii * OoOoOO00 . OoO0O00
 if 47 - 47: Oo0Ooo % I1Ii111 + ooOoO0o
 if 89 - 89: iII111i
 if 29 - 29: I1ii11iIi11i . ooOoO0o * II111iiii / iII111i . OoooooooOO - OoOoOO00
def lisp_process_api_ms_or_mr ( ms_or_mr , data ) :
 oOOOOO0Ooooo = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
 oooOOoooo000o = data [ "dns-name" ] if data . has_key ( "dns-name" ) else None
 if ( data . has_key ( "address" ) ) :
  oOOOOO0Ooooo . store_address ( data [ "address" ] )
  if 99 - 99: IiII % O0 - I1Ii111 * OoO0O00
  if 77 - 77: OoooooooOO - I11i / I1IiiI % OoOoOO00 - OOooOOo
 oOOO = { }
 if ( ms_or_mr ) :
  for ii1I111i in lisp_map_servers_list . values ( ) :
   if ( oooOOoooo000o ) :
    if ( oooOOoooo000o != ii1I111i . dns_name ) : continue
   else :
    if ( oOOOOO0Ooooo . is_exact_match ( ii1I111i . map_server ) == False ) : continue
    if 37 - 37: ooOoO0o
    if 22 - 22: I1ii11iIi11i + II111iiii / OoooooooOO % o0oOOo0O0Ooo * OoOoOO00 . Oo0Ooo
   oOOO [ "dns-name" ] = ii1I111i . dns_name
   oOOO [ "address" ] = ii1I111i . map_server . print_address_no_iid ( )
   oOOO [ "ms-name" ] = "" if ii1I111i . ms_name == None else ii1I111i . ms_name
   return ( [ oOOO ] )
   if 26 - 26: OoO0O00 % oO0o * Ii1I % OoooooooOO - oO0o
 else :
  for IIiIII1IIi in lisp_map_resolvers_list . values ( ) :
   if ( oooOOoooo000o ) :
    if ( oooOOoooo000o != IIiIII1IIi . dns_name ) : continue
   else :
    if ( oOOOOO0Ooooo . is_exact_match ( IIiIII1IIi . map_resolver ) == False ) : continue
    if 46 - 46: I1IiiI + OoO0O00 - O0 * O0
    if 75 - 75: OOooOOo + iIii1I11I1II1 * OOooOOo
   oOOO [ "dns-name" ] = IIiIII1IIi . dns_name
   oOOO [ "address" ] = IIiIII1IIi . map_resolver . print_address_no_iid ( )
   oOOO [ "mr-name" ] = "" if IIiIII1IIi . mr_name == None else IIiIII1IIi . mr_name
   return ( [ oOOO ] )
   if 82 - 82: iII111i - I1Ii111 - OoOoOO00
   if 96 - 96: Oo0Ooo . Oo0Ooo % o0oOOo0O0Ooo - I1IiiI * iIii1I11I1II1
 return ( [ ] )
 if 29 - 29: i1IIi / Ii1I / oO0o * iII111i
 if 44 - 44: O0
 if 95 - 95: OOooOOo + OOooOOo - OoOoOO00
 if 83 - 83: II111iiii * ooOoO0o - O0 - i11iIiiIii
 if 62 - 62: I1IiiI + II111iiii * iIii1I11I1II1 % iII111i + IiII / ooOoO0o
 if 14 - 14: iIii1I11I1II1 * I1ii11iIi11i + OOooOOo + O0
 if 79 - 79: II111iiii - iII111i
 if 89 - 89: O0 - OoO0O00
def lisp_process_api_database_mapping ( ) :
 O0OooO0oo = [ ]
 if 8 - 8: I1ii11iIi11i / oO0o - OoooooooOO + ooOoO0o + o0oOOo0O0Ooo % i11iIiiIii
 for o0Oo00OOOo00 in lisp_db_list :
  o0Iiii = { }
  o0Iiii [ "eid-prefix" ] = o0Oo00OOOo00 . eid . print_prefix ( )
  if ( o0Oo00OOOo00 . group . is_null ( ) == False ) :
   o0Iiii [ "group-prefix" ] = o0Oo00OOOo00 . group . print_prefix ( )
   if 32 - 32: O0 + IiII
   if 93 - 93: OoOoOO00 - I11i / iII111i - iIii1I11I1II1 + I11i % oO0o
  Ii1II1 = [ ]
  for iIOoo000 in o0Oo00OOOo00 . rloc_set :
   i1IIIIi1Ii111 = { }
   if ( iIOoo000 . rloc . is_null ( ) == False ) :
    i1IIIIi1Ii111 [ "rloc" ] = iIOoo000 . rloc . print_address_no_iid ( )
    if 24 - 24: Ii1I / iIii1I11I1II1 + o0oOOo0O0Ooo
   if ( iIOoo000 . rloc_name != None ) : i1IIIIi1Ii111 [ "rloc-name" ] = iIOoo000 . rloc_name
   if ( iIOoo000 . interface != None ) : i1IIIIi1Ii111 [ "interface" ] = iIOoo000 . interface
   i1Ii11iiI = iIOoo000 . translated_rloc
   if ( i1Ii11iiI . is_null ( ) == False ) :
    i1IIIIi1Ii111 [ "translated-rloc" ] = i1Ii11iiI . print_address_no_iid ( )
    if 76 - 76: ooOoO0o / OoO0O00 / Ii1I
   if ( i1IIIIi1Ii111 != { } ) : Ii1II1 . append ( i1IIIIi1Ii111 )
   if 26 - 26: I11i * ooOoO0o * OoO0O00 * I1Ii111 - OoooooooOO / o0oOOo0O0Ooo
   if 14 - 14: Ii1I / II111iiii % IiII
   if 81 - 81: oO0o + oO0o
   if 27 - 27: OoOoOO00 % OoOoOO00 / o0oOOo0O0Ooo
   if 9 - 9: Oo0Ooo
  o0Iiii [ "rlocs" ] = Ii1II1
  if 84 - 84: iII111i - oO0o * OoO0O00 / i11iIiiIii / oO0o
  if 64 - 64: I1Ii111 - I11i + oO0o . oO0o
  if 22 - 22: Oo0Ooo / OOooOOo - iIii1I11I1II1 / ooOoO0o
  if 7 - 7: ooOoO0o . OoooooooOO . iII111i * II111iiii . II111iiii / OOooOOo
  O0OooO0oo . append ( o0Iiii )
  if 46 - 46: Ii1I - Oo0Ooo / i1IIi % IiII - I1ii11iIi11i + OOooOOo
 return ( O0OooO0oo )
 if 42 - 42: i1IIi - IiII % OOooOOo % iIii1I11I1II1
 if 71 - 71: OoO0O00
 if 72 - 72: II111iiii + o0oOOo0O0Ooo / i1IIi * Oo0Ooo / i1IIi
 if 52 - 52: I1Ii111 % OoO0O00 . I1Ii111 * I1ii11iIi11i * OoOoOO00 + i1IIi
 if 54 - 54: Ii1I / I1IiiI
 if 7 - 7: iIii1I11I1II1 . O0 + OOooOOo . Ii1I * Oo0Ooo
 if 25 - 25: I1Ii111 . Oo0Ooo % II111iiii . IiII - O0
def lisp_gather_site_cache_data ( se , data ) :
 o0Iiii = { }
 o0Iiii [ "site-name" ] = se . site . site_name
 o0Iiii [ "instance-id" ] = str ( se . eid . instance_id )
 o0Iiii [ "eid-prefix" ] = se . eid . print_prefix_no_iid ( )
 if ( se . group . is_null ( ) == False ) :
  o0Iiii [ "group-prefix" ] = se . group . print_prefix_no_iid ( )
  if 18 - 18: oO0o * OOooOOo
 o0Iiii [ "registered" ] = "yes" if se . registered else "no"
 o0Iiii [ "first-registered" ] = lisp_print_elapsed ( se . first_registered )
 o0Iiii [ "last-registered" ] = lisp_print_elapsed ( se . last_registered )
 if 19 - 19: iIii1I11I1II1 / I1ii11iIi11i - I1ii11iIi11i / iIii1I11I1II1
 I1Iii1I = se . last_registerer
 I1Iii1I = "none" if I1Iii1I . is_null ( ) else I1Iii1I . print_address ( )
 o0Iiii [ "last-registerer" ] = I1Iii1I
 o0Iiii [ "ams" ] = "yes" if ( se . accept_more_specifics ) else "no"
 o0Iiii [ "dynamic" ] = "yes" if ( se . dynamic ) else "no"
 o0Iiii [ "site-id" ] = str ( se . site_id )
 if ( se . xtr_id_present ) :
  o0Iiii [ "xtr-id" ] = "0x" + lisp_hex_string ( se . xtr_id )
  if 42 - 42: iIii1I11I1II1 / OOooOOo - O0 * OoooooooOO / i1IIi
  if 33 - 33: OOooOOo . o0oOOo0O0Ooo % OoO0O00 - I1Ii111 . OoooooooOO
  if 96 - 96: II111iiii % I11i / Ii1I - i11iIiiIii
  if 63 - 63: I1IiiI
  if 15 - 15: iIii1I11I1II1 - I1ii11iIi11i % OoO0O00 * II111iiii / I11i + I11i
 oOo0oOOOoOoo = [ ]
 for i1IIIIi1Ii111 in se . registered_rlocs :
  iIOoo000 = { }
  iIOoo000 [ "address" ] = i1IIIIi1Ii111 . rloc . print_address_no_iid ( ) if i1IIIIi1Ii111 . rloc_exists ( ) else "none"
  if 23 - 23: I1IiiI
  if 51 - 51: i11iIiiIii / ooOoO0o - OoooooooOO + OoOoOO00 + oO0o
  if ( i1IIIIi1Ii111 . geo ) : iIOoo000 [ "geo" ] = i1IIIIi1Ii111 . geo . print_geo ( )
  if ( i1IIIIi1Ii111 . elp ) : iIOoo000 [ "elp" ] = i1IIIIi1Ii111 . elp . print_elp ( False )
  if ( i1IIIIi1Ii111 . rle ) : iIOoo000 [ "rle" ] = i1IIIIi1Ii111 . rle . print_rle ( False )
  if ( i1IIIIi1Ii111 . json ) : iIOoo000 [ "json" ] = i1IIIIi1Ii111 . json . print_json ( False )
  if ( i1IIIIi1Ii111 . rloc_name ) : iIOoo000 [ "rloc-name" ] = i1IIIIi1Ii111 . rloc_name
  iIOoo000 [ "uptime" ] = lisp_print_elapsed ( i1IIIIi1Ii111 . uptime )
  iIOoo000 [ "upriority" ] = str ( i1IIIIi1Ii111 . priority )
  iIOoo000 [ "uweight" ] = str ( i1IIIIi1Ii111 . weight )
  iIOoo000 [ "mpriority" ] = str ( i1IIIIi1Ii111 . mpriority )
  iIOoo000 [ "mweight" ] = str ( i1IIIIi1Ii111 . mweight )
  if 57 - 57: iIii1I11I1II1
  oOo0oOOOoOoo . append ( iIOoo000 )
  if 19 - 19: Ii1I / o0oOOo0O0Ooo + O0 / iIii1I11I1II1 + II111iiii
 o0Iiii [ "registered-rlocs" ] = oOo0oOOOoOoo
 if 3 - 3: oO0o % OoO0O00 % OOooOOo
 data . append ( o0Iiii )
 return ( [ True , data ] )
 if 64 - 64: o0oOOo0O0Ooo . II111iiii * IiII % Oo0Ooo + I11i - OoooooooOO
 if 58 - 58: ooOoO0o
 if 15 - 15: O0 * OOooOOo * I11i + Ii1I * OoooooooOO + OOooOOo
 if 77 - 77: O0
 if 98 - 98: iII111i - iII111i % i1IIi - I1Ii111 . I1IiiI % o0oOOo0O0Ooo
 if 38 - 38: IiII % OoOoOO00 . OOooOOo . I1ii11iIi11i
 if 34 - 34: iII111i . i11iIiiIii + OoO0O00 + o0oOOo0O0Ooo / ooOoO0o - i11iIiiIii
def lisp_process_api_site_cache_entry ( parms ) :
 IIiI1i = parms [ "instance-id" ]
 IIiI1i = 0 if ( IIiI1i == "" ) else int ( IIiI1i )
 if 63 - 63: ooOoO0o % OoO0O00 % ooOoO0o
 if 28 - 28: IiII * I1Ii111 * o0oOOo0O0Ooo + ooOoO0o - IiII / IiII
 if 73 - 73: iIii1I11I1II1 . I1ii11iIi11i + OOooOOo
 if 51 - 51: I11i % Oo0Ooo * OOooOOo % OoooooooOO - OoOoOO00 % Ii1I
 i1OO0o = lisp_address ( LISP_AFI_NONE , "" , 0 , IIiI1i )
 i1OO0o . store_prefix ( parms [ "eid-prefix" ] )
 if 60 - 60: OoOoOO00 - IiII + OoO0O00
 if 77 - 77: iIii1I11I1II1
 if 92 - 92: IiII
 if 68 - 68: OOooOOo . IiII / iIii1I11I1II1 % i11iIiiIii
 if 74 - 74: iII111i + i11iIiiIii
 Oo000o0o0 = lisp_address ( LISP_AFI_NONE , "" , 0 , IIiI1i )
 if ( parms . has_key ( "group-prefix" ) ) :
  Oo000o0o0 . store_prefix ( parms [ "group-prefix" ] )
  if 95 - 95: Ii1I
  if 49 - 49: I1ii11iIi11i . i1IIi + OoO0O00 % O0 + OoO0O00
 O0OooO0oo = [ ]
 iiiI1iI11i1i1 = lisp_site_eid_lookup ( i1OO0o , Oo000o0o0 , False )
 if ( iiiI1iI11i1i1 ) : lisp_gather_site_cache_data ( iiiI1iI11i1i1 , O0OooO0oo )
 return ( O0OooO0oo )
 if 21 - 21: ooOoO0o * oO0o / OoooooooOO % ooOoO0o / O0
 if 24 - 24: OoO0O00 - i11iIiiIii / i11iIiiIii * I1Ii111
 if 20 - 20: IiII % iIii1I11I1II1 . iII111i + iIii1I11I1II1 + O0
 if 96 - 96: I1ii11iIi11i - IiII % OoooooooOO . iII111i
 if 30 - 30: Oo0Ooo . OoooooooOO / Oo0Ooo / oO0o
 if 44 - 44: I1ii11iIi11i % o0oOOo0O0Ooo / iIii1I11I1II1 - o0oOOo0O0Ooo / I11i * I1Ii111
 if 49 - 49: iII111i / iII111i - OoOoOO00
def lisp_get_interface_instance_id ( device , source_eid ) :
 iIiiiIiIi = None
 if ( lisp_myinterfaces . has_key ( device ) ) :
  iIiiiIiIi = lisp_myinterfaces [ device ]
  if 89 - 89: ooOoO0o
  if 16 - 16: oO0o + oO0o + i1IIi + iIii1I11I1II1
  if 93 - 93: I1IiiI - i11iIiiIii * I1Ii111 - O0 + iII111i
  if 11 - 11: iII111i
  if 100 - 100: OoooooooOO / ooOoO0o . OoO0O00
  if 89 - 89: I11i % II111iiii
 if ( iIiiiIiIi == None or iIiiiIiIi . instance_id == None ) :
  return ( lisp_default_iid )
  if 35 - 35: oO0o
  if 65 - 65: II111iiii
  if 87 - 87: oO0o / OoO0O00 - oO0o
  if 69 - 69: i11iIiiIii
  if 29 - 29: IiII . ooOoO0o / iII111i - OOooOOo / OOooOOo % Oo0Ooo
  if 42 - 42: OoO0O00 . I1Ii111 . I1IiiI + Oo0Ooo * O0
  if 35 - 35: Oo0Ooo / iII111i - O0 - OOooOOo * Oo0Ooo . i11iIiiIii
  if 43 - 43: OoOoOO00 % oO0o % OoO0O00 / Ii1I . I11i
  if 86 - 86: I1Ii111 * i1IIi + IiII - OoOoOO00
 IIiI1i = iIiiiIiIi . get_instance_id ( )
 if ( source_eid == None ) : return ( IIiI1i )
 if 14 - 14: I1ii11iIi11i / i11iIiiIii * I11i % o0oOOo0O0Ooo + IiII / I1ii11iIi11i
 oOoOooO = source_eid . instance_id
 i1IIII1iiiII1 = None
 for iIiiiIiIi in lisp_multi_tenant_interfaces :
  if ( iIiiiIiIi . device != device ) : continue
  O00OOOoOoooo = iIiiiIiIi . multi_tenant_eid
  source_eid . instance_id = O00OOOoOoooo . instance_id
  if ( source_eid . is_more_specific ( O00OOOoOoooo ) == False ) : continue
  if ( i1IIII1iiiII1 == None or i1IIII1iiiII1 . multi_tenant_eid . mask_len < O00OOOoOoooo . mask_len ) :
   i1IIII1iiiII1 = iIiiiIiIi
   if 11 - 11: OOooOOo + i11iIiiIii
   if 21 - 21: OoOoOO00 * OoooooooOO . I11i . I1Ii111
 source_eid . instance_id = oOoOooO
 if 95 - 95: iIii1I11I1II1 - I1Ii111 - I1ii11iIi11i
 if ( i1IIII1iiiII1 == None ) : return ( IIiI1i )
 return ( i1IIII1iiiII1 . get_instance_id ( ) )
 if 91 - 91: I1IiiI
 if 19 - 19: i1IIi / OOooOOo + i1IIi * OoooooooOO
 if 61 - 61: oO0o / OoooooooOO . Ii1I / o0oOOo0O0Ooo . oO0o
 if 21 - 21: oO0o / iIii1I11I1II1 / OoO0O00 + IiII - iII111i
 if 68 - 68: II111iiii - IiII * i11iIiiIii
 if 64 - 64: i11iIiiIii . I1Ii111 % i11iIiiIii % I11i
 if 56 - 56: o0oOOo0O0Ooo + ooOoO0o + OoooooooOO
 if 64 - 64: OOooOOo / OoOoOO00
 if 30 - 30: OOooOOo % I1Ii111 - i11iIiiIii
def lisp_allow_dynamic_eid ( device , eid ) :
 if ( lisp_myinterfaces . has_key ( device ) == False ) : return ( None )
 if 20 - 20: i1IIi * I11i / OoO0O00 / i1IIi / I1Ii111 * O0
 iIiiiIiIi = lisp_myinterfaces [ device ]
 O000O0 = device if iIiiiIiIi . dynamic_eid_device == None else iIiiiIiIi . dynamic_eid_device
 if 29 - 29: OoOoOO00 % OoO0O00 * Oo0Ooo * i11iIiiIii * OOooOOo / iII111i
 if 79 - 79: OoO0O00
 if ( iIiiiIiIi . does_dynamic_eid_match ( eid ) ) : return ( O000O0 )
 return ( None )
 if 24 - 24: oO0o + IiII . o0oOOo0O0Ooo . OoooooooOO . i11iIiiIii / I1ii11iIi11i
 if 49 - 49: IiII
 if 1 - 1: oO0o / I11i
 if 99 - 99: OoO0O00 % IiII + I1Ii111 - oO0o
 if 28 - 28: OOooOOo - O0 - O0 % i11iIiiIii * OoooooooOO
 if 60 - 60: OoooooooOO / i1IIi / i1IIi / Ii1I . IiII
 if 24 - 24: O0
def lisp_start_rloc_probe_timer ( interval , lisp_sockets ) :
 global lisp_rloc_probe_timer
 if 6 - 6: I1IiiI . i11iIiiIii . OoooooooOO . I1IiiI . o0oOOo0O0Ooo
 if ( lisp_rloc_probe_timer != None ) : lisp_rloc_probe_timer . cancel ( )
 if 65 - 65: i11iIiiIii
 i1iIII = lisp_process_rloc_probe_timer
 II1 = threading . Timer ( interval , i1iIII , [ lisp_sockets ] )
 lisp_rloc_probe_timer = II1
 II1 . start ( )
 return
 if 17 - 17: II111iiii % II111iiii - IiII / i1IIi . Oo0Ooo
 if 42 - 42: i11iIiiIii + ooOoO0o % Ii1I + oO0o * OoOoOO00 / i1IIi
 if 44 - 44: II111iiii * i1IIi - I1ii11iIi11i
 if 28 - 28: OoOoOO00 / oO0o % Ii1I / iII111i / i1IIi . o0oOOo0O0Ooo
 if 48 - 48: oO0o . Ii1I / OoOoOO00 % o0oOOo0O0Ooo
 if 59 - 59: o0oOOo0O0Ooo % Ii1I / o0oOOo0O0Ooo % IiII % OOooOOo + o0oOOo0O0Ooo
 if 19 - 19: O0 + i11iIiiIii % O0 / II111iiii
def lisp_show_rloc_probe_list ( ) :
 lprint ( bold ( "----- RLOC-probe-list -----" , False ) )
 for i1IIiI1iII in lisp_rloc_probe_list :
  Oo0O0o = lisp_rloc_probe_list [ i1IIiI1iII ]
  lprint ( "RLOC {}:" . format ( i1IIiI1iII ) )
  for iIOoo000 , I1i11II , i1iII1iii in Oo0O0o :
   lprint ( "  [{}, {}, {}, {}]" . format ( hex ( id ( iIOoo000 ) ) , I1i11II . print_prefix ( ) ,
 i1iII1iii . print_prefix ( ) , iIOoo000 . translated_port ) )
   if 92 - 92: iII111i / o0oOOo0O0Ooo * oO0o . I11i % o0oOOo0O0Ooo
   if 87 - 87: Ii1I / Oo0Ooo % iIii1I11I1II1 / iII111i
 lprint ( bold ( "---------------------------" , False ) )
 return
 if 42 - 42: OoO0O00 . I1IiiI . OOooOOo + ooOoO0o
 if 87 - 87: OOooOOo
 if 44 - 44: Oo0Ooo + iIii1I11I1II1
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
 i1IIIIi1Ii111 , I1i11II , i1iII1iii = eid_list [ 0 ]
 iII1II = [ lisp_print_eid_tuple ( I1i11II , i1iII1iii ) ]
 if 43 - 43: I1ii11iIi11i % I1ii11iIi11i % i1IIi
 for i1IIIIi1Ii111 , I1i11II , i1iII1iii in eid_list [ 1 : : ] :
  i1IIIIi1Ii111 . state = LISP_RLOC_UNREACH_STATE
  i1IIIIi1Ii111 . last_state_change = lisp_get_timestamp ( )
  iII1II . append ( lisp_print_eid_tuple ( I1i11II , i1iII1iii ) )
  if 56 - 56: I1IiiI - OoO0O00 - iII111i . o0oOOo0O0Ooo . I1Ii111
  if 70 - 70: iIii1I11I1II1 - I11i
 iI1i = bold ( "unreachable" , False )
 I111I = red ( i1IIIIi1Ii111 . rloc . print_address_no_iid ( ) , False )
 if 45 - 45: OoO0O00 % iII111i / iIii1I11I1II1 % I1IiiI + OOooOOo
 for i1OO0o in iII1II :
  I1i11II = green ( i1OO0o , False )
  lprint ( "RLOC {} went {} for EID {}" . format ( I111I , iI1i , I1i11II ) )
  if 62 - 62: OOooOOo . OOooOOo . oO0o
  if 18 - 18: iII111i . I1IiiI . ooOoO0o * oO0o / OoooooooOO
  if 85 - 85: i1IIi
  if 79 - 79: I11i - I11i
  if 25 - 25: OOooOOo / O0 / iIii1I11I1II1 + II111iiii * Ii1I
  if 74 - 74: i1IIi . I1Ii111 / O0 + Oo0Ooo * OOooOOo
 for i1IIIIi1Ii111 , I1i11II , i1iII1iii in eid_list :
  Iii1 = lisp_map_cache . lookup_cache ( I1i11II , True )
  if ( Iii1 ) : lisp_write_ipc_map_cache ( True , Iii1 )
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
 o0OO0oooo = 0
 O00oOoo0OoOOO = bold ( "RLOC-probe" , False )
 for OOOo0O in lisp_rloc_probe_list . values ( ) :
  if 51 - 51: OOooOOo
  if 60 - 60: ooOoO0o % iIii1I11I1II1 / iIii1I11I1II1
  if 61 - 61: oO0o
  if 12 - 12: iIii1I11I1II1 - I1ii11iIi11i % I1ii11iIi11i * I1Ii111
  if 98 - 98: oO0o / iII111i - Oo0Ooo / I1Ii111 * oO0o - OoO0O00
  I1oo0O0oOOoOo = None
  for oOoI1IiII11II11 , i1OO0o , Oo000o0o0 in OOOo0O :
   OoOOoooO000 = oOoI1IiII11II11 . rloc . print_address_no_iid ( )
   if 55 - 55: OoooooooOO + oO0o . o0oOOo0O0Ooo % iIii1I11I1II1 - I1Ii111
   if 40 - 40: I1IiiI . o0oOOo0O0Ooo - Oo0Ooo
   if 44 - 44: Ii1I % OoO0O00 * oO0o * OoO0O00
   if 7 - 7: I1Ii111 % i1IIi . I11i . O0 / i1IIi
   if 56 - 56: Oo0Ooo
   if 21 - 21: i11iIiiIii * o0oOOo0O0Ooo + Oo0Ooo
   if ( oOoI1IiII11II11 . down_state ( ) ) : continue
   if 20 - 20: IiII / OoooooooOO / O0 / I1Ii111 * ooOoO0o
   if 45 - 45: ooOoO0o / Oo0Ooo % o0oOOo0O0Ooo . ooOoO0o
   if 19 - 19: o0oOOo0O0Ooo % I11i . I1ii11iIi11i
   if 70 - 70: Oo0Ooo - I11i / I1ii11iIi11i % OoO0O00 % II111iiii
   if 72 - 72: i11iIiiIii * I11i
   if 69 - 69: I1Ii111 . Ii1I * I1ii11iIi11i % I11i - o0oOOo0O0Ooo
   if 30 - 30: ooOoO0o / Oo0Ooo * iII111i % OoooooooOO / I1ii11iIi11i
   if 64 - 64: OoooooooOO
   if 41 - 41: Ii1I . I11i / oO0o * OoooooooOO
   if 98 - 98: I1ii11iIi11i - O0 + i11iIiiIii
   if 71 - 71: O0 - OoooooooOO
   if ( I1oo0O0oOOoOo ) :
    oOoI1IiII11II11 . last_rloc_probe_nonce = I1oo0O0oOOoOo . last_rloc_probe_nonce
    if 82 - 82: i11iIiiIii * II111iiii % IiII
    if ( I1oo0O0oOOoOo . translated_port == oOoI1IiII11II11 . translated_port and I1oo0O0oOOoOo . rloc_name == oOoI1IiII11II11 . rloc_name ) :
     if 80 - 80: Ii1I . i11iIiiIii % oO0o * o0oOOo0O0Ooo
     I1i11II = green ( lisp_print_eid_tuple ( i1OO0o , Oo000o0o0 ) , False )
     lprint ( "Suppress probe to duplicate RLOC {} for {}" . format ( red ( OoOOoooO000 , False ) , I1i11II ) )
     if 56 - 56: I1Ii111 % iII111i / II111iiii - Oo0Ooo - Oo0Ooo - iIii1I11I1II1
     continue
     if 67 - 67: iII111i
     if 80 - 80: Ii1I . iII111i * I1IiiI * Ii1I
     if 82 - 82: OoO0O00 % OoOoOO00 * i11iIiiIii . OoO0O00 . I1ii11iIi11i + Ii1I
   I1i1i1iIIiI11 = None
   i1IIIIi1Ii111 = None
   while ( True ) :
    i1IIIIi1Ii111 = oOoI1IiII11II11 if i1IIIIi1Ii111 == None else i1IIIIi1Ii111 . next_rloc
    if ( i1IIIIi1Ii111 == None ) : break
    if 60 - 60: i1IIi / iII111i
    if 10 - 10: I1Ii111 / OoOoOO00 * Ii1I % o0oOOo0O0Ooo . OoOoOO00 / I1ii11iIi11i
    if 2 - 2: iIii1I11I1II1
    if 85 - 85: O0 - ooOoO0o
    if 35 - 35: o0oOOo0O0Ooo - I1IiiI
    if ( i1IIIIi1Ii111 . rloc_next_hop != None ) :
     if ( i1IIIIi1Ii111 . rloc_next_hop not in I1i1 ) :
      if ( i1IIIIi1Ii111 . up_state ( ) ) :
       i1i11ii1Ii , IIiIiIii1111 = i1IIIIi1Ii111 . rloc_next_hop
       i1IIIIi1Ii111 . state = LISP_RLOC_UNREACH_STATE
       i1IIIIi1Ii111 . last_state_change = lisp_get_timestamp ( )
       lisp_update_rtr_updown ( i1IIIIi1Ii111 . rloc , False )
       if 47 - 47: i11iIiiIii * iII111i . OoOoOO00 * I1Ii111 % i11iIiiIii + Ii1I
      iI1i = bold ( "unreachable" , False )
      lprint ( "Next-hop {}({}) for RLOC {} is {}" . format ( IIiIiIii1111 , i1i11ii1Ii ,
 red ( OoOOoooO000 , False ) , iI1i ) )
      continue
      if 65 - 65: Ii1I % i11iIiiIii
      if 98 - 98: iII111i * o0oOOo0O0Ooo % Oo0Ooo
      if 7 - 7: oO0o * OoooooooOO % o0oOOo0O0Ooo . I1Ii111 + O0
      if 14 - 14: I11i * II111iiii % o0oOOo0O0Ooo / iII111i . OoooooooOO % iII111i
      if 88 - 88: iII111i
      if 94 - 94: OoooooooOO
    O0oo00o000 = i1IIIIi1Ii111 . last_rloc_probe
    iiI11Ii1I = 0 if O0oo00o000 == None else time . time ( ) - O0oo00o000
    if ( i1IIIIi1Ii111 . unreach_state ( ) and iiI11Ii1I < LISP_RLOC_PROBE_INTERVAL ) :
     lprint ( "Waiting for probe-reply from RLOC {}" . format ( red ( OoOOoooO000 , False ) ) )
     if 71 - 71: ooOoO0o
     continue
     if 19 - 19: i11iIiiIii * I1Ii111
     if 82 - 82: OOooOOo . iII111i
     if 65 - 65: oO0o
     if 18 - 18: i1IIi % I11i * OoOoOO00 - I11i + OoO0O00 - O0
     if 36 - 36: iIii1I11I1II1 * iII111i / IiII % i1IIi
     if 8 - 8: I11i
    i11iiIi = lisp_get_echo_nonce ( None , OoOOoooO000 )
    if ( i11iiIi and i11iiIi . request_nonce_timeout ( ) ) :
     i1IIIIi1Ii111 . state = LISP_RLOC_NO_ECHOED_NONCE_STATE
     i1IIIIi1Ii111 . last_state_change = lisp_get_timestamp ( )
     iI1i = bold ( "unreachable" , False )
     lprint ( "RLOC {} went {}, nonce-echo failed" . format ( red ( OoOOoooO000 , False ) , iI1i ) )
     if 33 - 33: I1Ii111 . I11i . Ii1I - iIii1I11I1II1
     lisp_update_rtr_updown ( i1IIIIi1Ii111 . rloc , False )
     continue
     if 96 - 96: II111iiii % oO0o . i1IIi + II111iiii . iII111i
     if 67 - 67: i1IIi - i11iIiiIii / ooOoO0o * oO0o
     if 64 - 64: oO0o / IiII
     if 86 - 86: I11i
     if 36 - 36: o0oOOo0O0Ooo / OoO0O00
     if 6 - 6: I11i % I1IiiI + iII111i * OoooooooOO . O0
    if ( i11iiIi and i11iiIi . recently_echoed ( ) ) :
     lprint ( ( "Suppress RLOC-probe to {}, nonce-echo " + "received" ) . format ( red ( OoOOoooO000 , False ) ) )
     if 87 - 87: ooOoO0o / Ii1I % O0 . OoO0O00
     continue
     if 55 - 55: i1IIi . o0oOOo0O0Ooo % OoooooooOO + II111iiii . OoOoOO00
     if 32 - 32: IiII * I1Ii111 * Oo0Ooo . i1IIi * OoooooooOO
     if 12 - 12: I1IiiI . OOooOOo % Oo0Ooo
     if 86 - 86: i11iIiiIii
     if 57 - 57: iII111i - OoooooooOO - ooOoO0o % II111iiii
     if 62 - 62: i11iIiiIii . Oo0Ooo / Oo0Ooo . IiII . OoooooooOO
    if ( i1IIIIi1Ii111 . last_rloc_probe != None ) :
     O0oo00o000 = i1IIIIi1Ii111 . last_rloc_probe_reply
     if ( O0oo00o000 == None ) : O0oo00o000 = 0
     iiI11Ii1I = time . time ( ) - O0oo00o000
     if ( i1IIIIi1Ii111 . up_state ( ) and iiI11Ii1I >= LISP_RLOC_PROBE_REPLY_WAIT ) :
      if 86 - 86: I1ii11iIi11i * OoOoOO00 + iII111i
      i1IIIIi1Ii111 . state = LISP_RLOC_UNREACH_STATE
      i1IIIIi1Ii111 . last_state_change = lisp_get_timestamp ( )
      lisp_update_rtr_updown ( i1IIIIi1Ii111 . rloc , False )
      iI1i = bold ( "unreachable" , False )
      lprint ( "RLOC {} went {}, probe it" . format ( red ( OoOOoooO000 , False ) , iI1i ) )
      if 79 - 79: I11i - II111iiii
      if 27 - 27: I1IiiI + o0oOOo0O0Ooo * oO0o % I1IiiI
      lisp_mark_rlocs_for_other_eids ( OOOo0O )
      if 66 - 66: OoO0O00 + IiII . o0oOOo0O0Ooo . IiII
      if 88 - 88: oO0o + oO0o % OoO0O00 . OoooooooOO - OoooooooOO . Oo0Ooo
      if 44 - 44: I1IiiI * IiII . OoooooooOO
    i1IIIIi1Ii111 . last_rloc_probe = lisp_get_timestamp ( )
    if 62 - 62: I11i - Ii1I / i11iIiiIii * I1IiiI + ooOoO0o + o0oOOo0O0Ooo
    iiII11 = "" if i1IIIIi1Ii111 . unreach_state ( ) == False else " unreachable"
    if 69 - 69: iIii1I11I1II1 * o0oOOo0O0Ooo * II111iiii + OoooooooOO . Ii1I
    if 99 - 99: Ii1I % iIii1I11I1II1 . I1Ii111 / iIii1I11I1II1 / oO0o
    if 76 - 76: I1Ii111
    if 27 - 27: I1ii11iIi11i
    if 72 - 72: OoooooooOO - IiII
    if 8 - 8: i11iIiiIii + I11i . II111iiii . O0
    if 21 - 21: i1IIi * Oo0Ooo / iII111i . iIii1I11I1II1 % OOooOOo % i1IIi
    II1Iii1Iiii = ""
    IIiIiIii1111 = None
    if ( i1IIIIi1Ii111 . rloc_next_hop != None ) :
     i1i11ii1Ii , IIiIiIii1111 = i1IIIIi1Ii111 . rloc_next_hop
     lisp_install_host_route ( OoOOoooO000 , IIiIiIii1111 , True )
     II1Iii1Iiii = ", send on nh {}({})" . format ( IIiIiIii1111 , i1i11ii1Ii )
     if 10 - 10: O0 . Ii1I . i1IIi
     if 44 - 44: OoooooooOO % I1Ii111 / Oo0Ooo . Ii1I
     if 36 - 36: iII111i
     if 67 - 67: I1Ii111 / iII111i / iII111i . IiII
     if 17 - 17: ooOoO0o . I1ii11iIi11i % OoOoOO00 . I1ii11iIi11i . OoooooooOO % OoOoOO00
    iiiI1i1I = i1IIIIi1Ii111 . print_rloc_probe_rtt ( )
    OOOoOOO = OoOOoooO000
    if ( i1IIIIi1Ii111 . translated_port != 0 ) :
     OOOoOOO += ":{}" . format ( i1IIIIi1Ii111 . translated_port )
     if 13 - 13: OoOoOO00
    OOOoOOO = red ( OOOoOOO , False )
    if ( i1IIIIi1Ii111 . rloc_name != None ) :
     OOOoOOO += " (" + blue ( i1IIIIi1Ii111 . rloc_name , False ) + ")"
     if 72 - 72: II111iiii * iII111i . II111iiii + iII111i * IiII
    lprint ( "Send {}{} {}, last rtt: {}{}" . format ( O00oOoo0OoOOO , iiII11 ,
 OOOoOOO , iiiI1i1I , II1Iii1Iiii ) )
    if 90 - 90: oO0o * I1Ii111 / O0
    if 15 - 15: o0oOOo0O0Ooo * O0 . OOooOOo / Oo0Ooo
    if 28 - 28: OoooooooOO + OoooooooOO
    if 27 - 27: I11i . oO0o / OoooooooOO - OoO0O00 . I11i
    if 15 - 15: II111iiii * OoO0O00
    if 33 - 33: OoooooooOO . o0oOOo0O0Ooo . I1IiiI / I1ii11iIi11i . OoOoOO00
    if 58 - 58: Ii1I
    if 20 - 20: OOooOOo
    if ( i1IIIIi1Ii111 . rloc_next_hop != None ) :
     I1i1i1iIIiI11 = lisp_get_host_route_next_hop ( OoOOoooO000 )
     if ( I1i1i1iIIiI11 ) : lisp_install_host_route ( OoOOoooO000 , I1i1i1iIIiI11 , False )
     if 93 - 93: i1IIi . IiII % O0 * iII111i
     if 84 - 84: I11i
     if 99 - 99: I1ii11iIi11i
     if 78 - 78: I1Ii111 . IiII - OOooOOo
     if 93 - 93: iIii1I11I1II1
     if 33 - 33: OOooOOo . i1IIi
    if ( i1IIIIi1Ii111 . rloc . is_null ( ) ) :
     i1IIIIi1Ii111 . rloc . copy_address ( oOoI1IiII11II11 . rloc )
     if 63 - 63: II111iiii . oO0o * IiII
     if 73 - 73: iII111i . i1IIi + oO0o + OOooOOo + ooOoO0o - iIii1I11I1II1
     if 47 - 47: I11i
     if 88 - 88: OoO0O00 - OoooooooOO
     if 93 - 93: Oo0Ooo * I1IiiI
    I1IIiiII = None if ( Oo000o0o0 . is_null ( ) ) else i1OO0o
    o0000OO = i1OO0o if ( Oo000o0o0 . is_null ( ) ) else Oo000o0o0
    lisp_send_map_request ( lisp_sockets , 0 , I1IIiiII , o0000OO , i1IIIIi1Ii111 )
    I1oo0O0oOOoOo = oOoI1IiII11II11
    if 46 - 46: oO0o . O0 % iIii1I11I1II1 - iIii1I11I1II1 . O0
    if 91 - 91: I1IiiI + IiII / OOooOOo - i1IIi % i11iIiiIii / iIii1I11I1II1
    if 73 - 73: i11iIiiIii . I1ii11iIi11i * OoOoOO00
    if 95 - 95: i1IIi + iIii1I11I1II1 . I1Ii111 / I1Ii111
    if ( IIiIiIii1111 ) : lisp_install_host_route ( OoOOoooO000 , IIiIiIii1111 , False )
    if 84 - 84: Oo0Ooo . OoO0O00 * IiII
    if 95 - 95: OoO0O00
    if 100 - 100: II111iiii
    if 34 - 34: I11i % OOooOOo - iII111i % II111iiii
    if 14 - 14: I11i * o0oOOo0O0Ooo % II111iiii
   if ( I1i1i1iIIiI11 ) : lisp_install_host_route ( OoOOoooO000 , I1i1i1iIIiI11 , True )
   if 36 - 36: ooOoO0o - iIii1I11I1II1 / IiII + OoOoOO00
   if 42 - 42: ooOoO0o + I1IiiI * iII111i / OoOoOO00 . i1IIi - OoooooooOO
   if 8 - 8: iIii1I11I1II1 - Oo0Ooo + iII111i
   if 40 - 40: o0oOOo0O0Ooo * I1IiiI
   o0OO0oooo += 1
   if ( ( o0OO0oooo % 10 ) == 0 ) : time . sleep ( 0.020 )
   if 75 - 75: O0 * OOooOOo / ooOoO0o + I11i
   if 56 - 56: I1IiiI % OoooooooOO % Oo0Ooo
   if 19 - 19: i11iIiiIii - iIii1I11I1II1 . i1IIi . I1Ii111 / I1IiiI * I1Ii111
 lprint ( "---------- End RLOC Probing ----------" )
 return
 if 41 - 41: oO0o . o0oOOo0O0Ooo . I11i * OoOoOO00
 if 16 - 16: oO0o
 if 32 - 32: OoooooooOO
 if 77 - 77: Oo0Ooo . i1IIi - I11i
 if 98 - 98: O0
 if 87 - 87: OoO0O00 % I1Ii111 - OOooOOo - II111iiii + iII111i
 if 54 - 54: i1IIi % iII111i
 if 16 - 16: II111iiii - Oo0Ooo
def lisp_update_rtr_updown ( rtr , updown ) :
 global lisp_ipc_socket
 if 44 - 44: OOooOOo / Oo0Ooo - I1ii11iIi11i + I11i . oO0o
 if 85 - 85: iIii1I11I1II1 / Ii1I
 if 43 - 43: I1IiiI % I1Ii111 - oO0o . II111iiii / iIii1I11I1II1
 if 97 - 97: I1Ii111 + I1ii11iIi11i
 if ( lisp_i_am_itr == False ) : return
 if 21 - 21: O0 + o0oOOo0O0Ooo * OoooooooOO % IiII % I1ii11iIi11i
 if 80 - 80: I11i
 if 28 - 28: OoOoOO00 * OoooooooOO * i11iIiiIii
 if 88 - 88: ooOoO0o + ooOoO0o / I1Ii111
 if 69 - 69: O0 * o0oOOo0O0Ooo + i1IIi * ooOoO0o . o0oOOo0O0Ooo
 if ( lisp_register_all_rtrs ) : return
 if 46 - 46: Oo0Ooo / Oo0Ooo * IiII
 OoOO00OoOOo00 = rtr . print_address_no_iid ( )
 if 66 - 66: iII111i
 if 37 - 37: i1IIi % iIii1I11I1II1 / OoOoOO00 * o0oOOo0O0Ooo - ooOoO0o . I1Ii111
 if 91 - 91: OoOoOO00
 if 89 - 89: Ii1I . I1Ii111 * OOooOOo + I1ii11iIi11i
 if 24 - 24: oO0o % iII111i
 if ( lisp_rtr_list . has_key ( OoOO00OoOOo00 ) == False ) : return
 if 70 - 70: IiII * I1Ii111 - II111iiii / Oo0Ooo / OOooOOo
 updown = "up" if updown else "down"
 lprint ( "Send ETR IPC message, RTR {} has done {}" . format (
 red ( OoOO00OoOOo00 , False ) , bold ( updown , False ) ) )
 if 6 - 6: O0 + i11iIiiIii
 if 59 - 59: ooOoO0o . iII111i - II111iiii
 if 30 - 30: o0oOOo0O0Ooo % iII111i - i11iIiiIii
 if 25 - 25: i11iIiiIii + OoOoOO00 + oO0o / Ii1I * Oo0Ooo + Oo0Ooo
 Oooo000 = "rtr%{}%{}" . format ( OoOO00OoOOo00 , updown )
 Oooo000 = lisp_command_ipc ( Oooo000 , "lisp-itr" )
 lisp_ipc ( Oooo000 , lisp_ipc_socket , "lisp-etr" )
 return
 if 26 - 26: I1IiiI % I1ii11iIi11i + o0oOOo0O0Ooo / I1ii11iIi11i - I1IiiI
 if 55 - 55: OoooooooOO
 if 2 - 2: Oo0Ooo + I11i / OOooOOo + OOooOOo
 if 62 - 62: OOooOOo . iIii1I11I1II1 + I1IiiI / OOooOOo
 if 90 - 90: OOooOOo
 if 29 - 29: OoOoOO00 - I1IiiI / oO0o + Oo0Ooo + I1Ii111 + O0
 if 65 - 65: oO0o
def lisp_process_rloc_probe_reply ( rloc_addr , source , port , nonce , hop_count ,
 ttl ) :
 O00oOoo0OoOOO = bold ( "RLOC-probe reply" , False )
 IiI1Iiiii1Iii = rloc_addr . print_address_no_iid ( )
 iiiII1 = source . print_address_no_iid ( )
 oOOo0oO0 = lisp_rloc_probe_list
 if 62 - 62: O0 + I1ii11iIi11i + Ii1I / i1IIi
 if 77 - 77: O0
 if 49 - 49: o0oOOo0O0Ooo / i11iIiiIii
 if 36 - 36: II111iiii
 if 78 - 78: OoO0O00 + iIii1I11I1II1 * i1IIi
 if 7 - 7: i11iIiiIii
 I1Iii1I = IiI1Iiiii1Iii
 if ( oOOo0oO0 . has_key ( I1Iii1I ) == False ) :
  I1Iii1I += ":" + str ( port )
  if ( oOOo0oO0 . has_key ( I1Iii1I ) == False ) :
   I1Iii1I = iiiII1
   if ( oOOo0oO0 . has_key ( I1Iii1I ) == False ) :
    I1Iii1I += ":" + str ( port )
    lprint ( "    Received unsolicited {} from {}/{}" . format ( O00oOoo0OoOOO ,
 red ( IiI1Iiiii1Iii , False ) , red ( iiiII1 , False ) ) )
    return
    if 49 - 49: I1IiiI - oO0o % OOooOOo / O0 / II111iiii
    if 41 - 41: IiII % II111iiii
    if 99 - 99: IiII - O0
    if 59 - 59: iII111i % O0 + OOooOOo * ooOoO0o
    if 27 - 27: I1Ii111 % i11iIiiIii * I1IiiI
    if 19 - 19: OoOoOO00 / o0oOOo0O0Ooo - iII111i / OoO0O00
    if 12 - 12: I1ii11iIi11i - I11i * O0 % I1IiiI + O0 - II111iiii
    if 13 - 13: iII111i / OOooOOo * i11iIiiIii / oO0o / OoooooooOO
 for i1IIIIi1Ii111 , i1OO0o , Oo000o0o0 in lisp_rloc_probe_list [ I1Iii1I ] :
  if ( lisp_i_am_rtr and i1IIIIi1Ii111 . translated_port != 0 and
 i1IIIIi1Ii111 . translated_port != port ) : continue
  if 89 - 89: Ii1I * Oo0Ooo / I1Ii111 * I1ii11iIi11i + O0 * Oo0Ooo
  i1IIIIi1Ii111 . process_rloc_probe_reply ( nonce , i1OO0o , Oo000o0o0 , hop_count , ttl )
  if 74 - 74: I11i . I11i
 return
 if 74 - 74: OoOoOO00 * ooOoO0o * I1Ii111
 if 56 - 56: iIii1I11I1II1 * OoO0O00 - oO0o * Ii1I
 if 62 - 62: i1IIi + I11i / OOooOOo - OoooooooOO % i1IIi . I1IiiI
 if 13 - 13: O0 * iII111i
 if 26 - 26: i1IIi - I1Ii111 - ooOoO0o
 if 73 - 73: o0oOOo0O0Ooo . OoooooooOO
 if 96 - 96: i1IIi - OOooOOo / I11i % OoOoOO00 - i11iIiiIii % II111iiii
 if 47 - 47: I1Ii111 * iII111i
def lisp_db_list_length ( ) :
 o0OO0oooo = 0
 for o0Oo00OOOo00 in lisp_db_list :
  o0OO0oooo += len ( o0Oo00OOOo00 . dynamic_eids ) if o0Oo00OOOo00 . dynamic_eid_configured ( ) else 1
  o0OO0oooo += len ( o0Oo00OOOo00 . eid . iid_list )
  if 90 - 90: i1IIi * Ii1I . OoO0O00 % I11i * ooOoO0o . OOooOOo
 return ( o0OO0oooo )
 if 76 - 76: iIii1I11I1II1 . i11iIiiIii * II111iiii - iII111i
 if 51 - 51: I1IiiI
 if 52 - 52: I1Ii111
 if 82 - 82: iII111i + II111iiii
 if 29 - 29: O0 % Ii1I * ooOoO0o % O0
 if 83 - 83: oO0o
 if 95 - 95: Oo0Ooo * O0 % i1IIi / iII111i + oO0o
 if 85 - 85: iIii1I11I1II1 / I11i
def lisp_is_myeid ( eid ) :
 for o0Oo00OOOo00 in lisp_db_list :
  if ( eid . is_more_specific ( o0Oo00OOOo00 . eid ) ) : return ( True )
  if 65 - 65: I11i / i1IIi * OoOoOO00 * Ii1I * OoO0O00
 return ( False )
 if 74 - 74: I1ii11iIi11i . I1ii11iIi11i % IiII + OOooOOo . OoO0O00 * I11i
 if 20 - 20: OOooOOo % i1IIi * Ii1I / i11iIiiIii
 if 89 - 89: ooOoO0o
 if 83 - 83: I11i . I11i * OOooOOo - OOooOOo
 if 46 - 46: iIii1I11I1II1 . I1Ii111 % I1IiiI
 if 22 - 22: i1IIi * I11i + II111iiii + II111iiii
 if 20 - 20: I11i
 if 37 - 37: I1Ii111
 if 19 - 19: I1ii11iIi11i / OOooOOo . I1IiiI / ooOoO0o + OoO0O00 + i11iIiiIii
def lisp_format_macs ( sa , da ) :
 sa = sa [ 0 : 4 ] + "-" + sa [ 4 : 8 ] + "-" + sa [ 8 : 12 ]
 da = da [ 0 : 4 ] + "-" + da [ 4 : 8 ] + "-" + da [ 8 : 12 ]
 return ( "{} -> {}" . format ( sa , da ) )
 if 80 - 80: OoO0O00 . O0 / Ii1I % I1Ii111 / iII111i * I1IiiI
 if 41 - 41: O0 / OoooooooOO - i1IIi
 if 6 - 6: i1IIi - I1ii11iIi11i % I1Ii111 - II111iiii / ooOoO0o / i11iIiiIii
 if 32 - 32: oO0o / IiII - I11i . ooOoO0o
 if 69 - 69: i11iIiiIii * i11iIiiIii
 if 100 - 100: I1ii11iIi11i * I1ii11iIi11i + i1IIi
 if 96 - 96: I1Ii111 / I1IiiI + ooOoO0o
def lisp_get_echo_nonce ( rloc , rloc_str ) :
 if ( lisp_nonce_echoing == False ) : return ( None )
 if 16 - 16: I1ii11iIi11i % o0oOOo0O0Ooo % OOooOOo % OoOoOO00 + ooOoO0o % I1ii11iIi11i
 if ( rloc ) : rloc_str = rloc . print_address_no_iid ( )
 i11iiIi = None
 if ( lisp_nonce_echo_list . has_key ( rloc_str ) ) :
  i11iiIi = lisp_nonce_echo_list [ rloc_str ]
  if 85 - 85: oO0o * OoooooooOO * iIii1I11I1II1 + iII111i
 return ( i11iiIi )
 if 67 - 67: Ii1I / i11iIiiIii % OoOoOO00 % O0 / OoOoOO00
 if 54 - 54: I11i . OoOoOO00 / II111iiii . i1IIi + OOooOOo % II111iiii
 if 82 - 82: i11iIiiIii . OoooooooOO % OoOoOO00 * O0 - I1Ii111
 if 78 - 78: OoOoOO00 % Ii1I % OOooOOo % Oo0Ooo % I11i . Ii1I
 if 73 - 73: OoooooooOO / i1IIi . iIii1I11I1II1
 if 89 - 89: I1Ii111
 if 29 - 29: I11i * ooOoO0o - OoooooooOO
 if 92 - 92: O0 % i1IIi / OOooOOo - oO0o
def lisp_decode_dist_name ( packet ) :
 o0OO0oooo = 0
 OOooOOo00OOo = ""
 if 30 - 30: Oo0Ooo . oO0o / i11iIiiIii % i1IIi . OoO0O00
 while ( packet [ 0 : 1 ] != "\0" ) :
  if ( o0OO0oooo == 255 ) : return ( [ None , None ] )
  OOooOOo00OOo += packet [ 0 : 1 ]
  packet = packet [ 1 : : ]
  o0OO0oooo += 1
  if 12 - 12: II111iiii . I1Ii111
  if 81 - 81: II111iiii + OoOoOO00 * II111iiii / iIii1I11I1II1 - Oo0Ooo % oO0o
 packet = packet [ 1 : : ]
 return ( packet , OOooOOo00OOo )
 if 66 - 66: ooOoO0o % O0 + iIii1I11I1II1 * I1Ii111 - I1Ii111
 if 61 - 61: I1ii11iIi11i
 if 12 - 12: OoO0O00
 if 97 - 97: OOooOOo . Oo0Ooo . oO0o * i1IIi
 if 7 - 7: Oo0Ooo
 if 38 - 38: Oo0Ooo - I1ii11iIi11i
 if 19 - 19: Ii1I * OoO0O00 / OoO0O00 . II111iiii % iIii1I11I1II1
 if 61 - 61: I1ii11iIi11i * oO0o % iII111i + IiII + i11iIiiIii * I11i
def lisp_write_flow_log ( flow_log ) :
 Oo0OO0o0oOO0 = open ( "./logs/lisp-flow.log" , "a" )
 if 3 - 3: Ii1I
 o0OO0oooo = 0
 for I11ii1i in flow_log :
  iI1IIII1ii1 = I11ii1i [ 3 ]
  OoI1i1 = iI1IIII1ii1 . print_flow ( I11ii1i [ 0 ] , I11ii1i [ 1 ] , I11ii1i [ 2 ] )
  Oo0OO0o0oOO0 . write ( OoI1i1 )
  o0OO0oooo += 1
  if 73 - 73: OoO0O00 / iII111i
 Oo0OO0o0oOO0 . close ( )
 del ( flow_log )
 if 40 - 40: I11i + IiII * Oo0Ooo . OoooooooOO * I1IiiI
 o0OO0oooo = bold ( str ( o0OO0oooo ) , False )
 lprint ( "Wrote {} flow entries to ./logs/lisp-flow.log" . format ( o0OO0oooo ) )
 return
 if 91 - 91: ooOoO0o / oO0o * OOooOOo . II111iiii - I11i - I11i
 if 5 - 5: O0 + OoooooooOO + i11iIiiIii * Oo0Ooo * OoOoOO00 . oO0o
 if 6 - 6: OoO0O00 % Oo0Ooo % I1IiiI % o0oOOo0O0Ooo % O0 % Oo0Ooo
 if 94 - 94: I11i . i1IIi / II111iiii + OOooOOo
 if 64 - 64: I1IiiI % ooOoO0o
 if 72 - 72: O0 * II111iiii % OoO0O00 - I1IiiI * OOooOOo
 if 80 - 80: OOooOOo * I11i / OOooOOo - oO0o
def lisp_policy_command ( kv_pair ) :
 o0O0o = lisp_policy ( "" )
 IiIIIIi1I = None
 if 73 - 73: I1IiiI . OoO0O00
 IiiiOOo = [ ]
 for oO in range ( len ( kv_pair [ "datetime-range" ] ) ) :
  IiiiOOo . append ( lisp_policy_match ( ) )
  if 34 - 34: OoooooooOO
  if 40 - 40: O0 * OoooooooOO - oO0o + iIii1I11I1II1 * OOooOOo + I1ii11iIi11i
 for iIi in kv_pair . keys ( ) :
  oOOO = kv_pair [ iIi ]
  if 36 - 36: I11i
  if 28 - 28: ooOoO0o
  if 1 - 1: IiII / OoO0O00 * oO0o - I1Ii111 . OoOoOO00
  if 85 - 85: i11iIiiIii + OoOoOO00
  if ( iIi == "instance-id" ) :
   for oO in range ( len ( IiiiOOo ) ) :
    II1i1III = oOOO [ oO ]
    if ( II1i1III == "" ) : continue
    i1iIiii1iI = IiiiOOo [ oO ]
    if ( i1iIiii1iI . source_eid == None ) :
     i1iIiii1iI . source_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
     if 93 - 93: Ii1I - iII111i - O0 * OoO0O00
    if ( i1iIiii1iI . dest_eid == None ) :
     i1iIiii1iI . dest_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
     if 14 - 14: i1IIi - II111iiii * I11i
    i1iIiii1iI . source_eid . instance_id = int ( II1i1III )
    i1iIiii1iI . dest_eid . instance_id = int ( II1i1III )
    if 89 - 89: II111iiii * oO0o . OoooooooOO / IiII / IiII + iII111i
    if 15 - 15: OoOoOO00 . IiII / iIii1I11I1II1 . OoooooooOO
  if ( iIi == "source-eid" ) :
   for oO in range ( len ( IiiiOOo ) ) :
    II1i1III = oOOO [ oO ]
    if ( II1i1III == "" ) : continue
    i1iIiii1iI = IiiiOOo [ oO ]
    if ( i1iIiii1iI . source_eid == None ) :
     i1iIiii1iI . source_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
     if 14 - 14: IiII * OoooooooOO - iIii1I11I1II1
    IIiI1i = i1iIiii1iI . source_eid . instance_id
    i1iIiii1iI . source_eid . store_prefix ( II1i1III )
    i1iIiii1iI . source_eid . instance_id = IIiI1i
    if 11 - 11: I1IiiI + Oo0Ooo % I1Ii111 * Ii1I - iIii1I11I1II1 % I1ii11iIi11i
    if 43 - 43: o0oOOo0O0Ooo * o0oOOo0O0Ooo . iII111i / Oo0Ooo - i11iIiiIii
  if ( iIi == "destination-eid" ) :
   for oO in range ( len ( IiiiOOo ) ) :
    II1i1III = oOOO [ oO ]
    if ( II1i1III == "" ) : continue
    i1iIiii1iI = IiiiOOo [ oO ]
    if ( i1iIiii1iI . dest_eid == None ) :
     i1iIiii1iI . dest_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
     if 66 - 66: I1IiiI / i1IIi + o0oOOo0O0Ooo % IiII - OoOoOO00 / Oo0Ooo
    IIiI1i = i1iIiii1iI . dest_eid . instance_id
    i1iIiii1iI . dest_eid . store_prefix ( II1i1III )
    i1iIiii1iI . dest_eid . instance_id = IIiI1i
    if 22 - 22: oO0o % I1Ii111 - I1Ii111 / I1Ii111
    if 25 - 25: OoooooooOO / oO0o / ooOoO0o / I1IiiI * I1ii11iIi11i . o0oOOo0O0Ooo
  if ( iIi == "source-rloc" ) :
   for oO in range ( len ( IiiiOOo ) ) :
    II1i1III = oOOO [ oO ]
    if ( II1i1III == "" ) : continue
    i1iIiii1iI = IiiiOOo [ oO ]
    i1iIiii1iI . source_rloc = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
    i1iIiii1iI . source_rloc . store_prefix ( II1i1III )
    if 30 - 30: o0oOOo0O0Ooo / i11iIiiIii
    if 33 - 33: OOooOOo % OoooooooOO
  if ( iIi == "destination-rloc" ) :
   for oO in range ( len ( IiiiOOo ) ) :
    II1i1III = oOOO [ oO ]
    if ( II1i1III == "" ) : continue
    i1iIiii1iI = IiiiOOo [ oO ]
    i1iIiii1iI . dest_rloc = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
    i1iIiii1iI . dest_rloc . store_prefix ( II1i1III )
    if 98 - 98: Ii1I
    if 38 - 38: ooOoO0o - iII111i * OOooOOo % I1ii11iIi11i + Oo0Ooo
  if ( iIi == "rloc-record-name" ) :
   for oO in range ( len ( IiiiOOo ) ) :
    II1i1III = oOOO [ oO ]
    if ( II1i1III == "" ) : continue
    i1iIiii1iI = IiiiOOo [ oO ]
    i1iIiii1iI . rloc_record_name = II1i1III
    if 95 - 95: iIii1I11I1II1 / O0 % O0
    if 53 - 53: ooOoO0o . ooOoO0o
  if ( iIi == "geo-name" ) :
   for oO in range ( len ( IiiiOOo ) ) :
    II1i1III = oOOO [ oO ]
    if ( II1i1III == "" ) : continue
    i1iIiii1iI = IiiiOOo [ oO ]
    i1iIiii1iI . geo_name = II1i1III
    if 80 - 80: i11iIiiIii % I1Ii111 % I1IiiI / I1IiiI + oO0o + iII111i
    if 18 - 18: OoO0O00 * ooOoO0o
  if ( iIi == "elp-name" ) :
   for oO in range ( len ( IiiiOOo ) ) :
    II1i1III = oOOO [ oO ]
    if ( II1i1III == "" ) : continue
    i1iIiii1iI = IiiiOOo [ oO ]
    i1iIiii1iI . elp_name = II1i1III
    if 32 - 32: oO0o . OoooooooOO - o0oOOo0O0Ooo + II111iiii
    if 4 - 4: OOooOOo * I1IiiI - I11i - I11i
  if ( iIi == "rle-name" ) :
   for oO in range ( len ( IiiiOOo ) ) :
    II1i1III = oOOO [ oO ]
    if ( II1i1III == "" ) : continue
    i1iIiii1iI = IiiiOOo [ oO ]
    i1iIiii1iI . rle_name = II1i1III
    if 67 - 67: I1IiiI
    if 32 - 32: oO0o * i11iIiiIii - I11i % Oo0Ooo * I1ii11iIi11i
  if ( iIi == "json-name" ) :
   for oO in range ( len ( IiiiOOo ) ) :
    II1i1III = oOOO [ oO ]
    if ( II1i1III == "" ) : continue
    i1iIiii1iI = IiiiOOo [ oO ]
    i1iIiii1iI . json_name = II1i1III
    if 79 - 79: II111iiii / Oo0Ooo / I1ii11iIi11i
    if 30 - 30: I11i . o0oOOo0O0Ooo / II111iiii
  if ( iIi == "datetime-range" ) :
   for oO in range ( len ( IiiiOOo ) ) :
    II1i1III = oOOO [ oO ]
    i1iIiii1iI = IiiiOOo [ oO ]
    if ( II1i1III == "" ) : continue
    ooO = lisp_datetime ( II1i1III [ 0 : 19 ] )
    IIIIIi1I11i = lisp_datetime ( II1i1III [ 19 : : ] )
    if ( ooO . valid_datetime ( ) and IIIIIi1I11i . valid_datetime ( ) ) :
     i1iIiii1iI . datetime_lower = ooO
     i1iIiii1iI . datetime_upper = IIIIIi1I11i
     if 59 - 59: i11iIiiIii
     if 5 - 5: i11iIiiIii + o0oOOo0O0Ooo . OoO0O00 % OoOoOO00 + I11i
     if 59 - 59: I1ii11iIi11i
     if 47 - 47: I1IiiI + Oo0Ooo
     if 78 - 78: i1IIi / I1ii11iIi11i % ooOoO0o * OoO0O00
     if 10 - 10: i1IIi % ooOoO0o / iII111i
     if 98 - 98: IiII / o0oOOo0O0Ooo - i1IIi - OOooOOo
  if ( iIi == "set-action" ) :
   o0O0o . set_action = oOOO
   if 65 - 65: Ii1I + OoOoOO00 * Oo0Ooo . O0 . IiII
  if ( iIi == "set-record-ttl" ) :
   o0O0o . set_record_ttl = int ( oOOO )
   if 33 - 33: i11iIiiIii . i1IIi . I1Ii111 - OoOoOO00 + OOooOOo
  if ( iIi == "set-instance-id" ) :
   if ( o0O0o . set_source_eid == None ) :
    o0O0o . set_source_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
    if 34 - 34: I1ii11iIi11i . i1IIi * O0 / OoooooooOO
   if ( o0O0o . set_dest_eid == None ) :
    o0O0o . set_dest_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
    if 22 - 22: OOooOOo % o0oOOo0O0Ooo - i11iIiiIii
   IiIIIIi1I = int ( oOOO )
   o0O0o . set_source_eid . instance_id = IiIIIIi1I
   o0O0o . set_dest_eid . instance_id = IiIIIIi1I
   if 58 - 58: IiII . Ii1I + II111iiii
  if ( iIi == "set-source-eid" ) :
   if ( o0O0o . set_source_eid == None ) :
    o0O0o . set_source_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
    if 31 - 31: i11iIiiIii + i11iIiiIii + I11i * Oo0Ooo . I11i
   o0O0o . set_source_eid . store_prefix ( oOOO )
   if ( IiIIIIi1I != None ) : o0O0o . set_source_eid . instance_id = IiIIIIi1I
   if 28 - 28: OOooOOo * iIii1I11I1II1 * OoOoOO00
  if ( iIi == "set-destination-eid" ) :
   if ( o0O0o . set_dest_eid == None ) :
    o0O0o . set_dest_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
    if 75 - 75: Oo0Ooo % IiII + II111iiii + oO0o
   o0O0o . set_dest_eid . store_prefix ( oOOO )
   if ( IiIIIIi1I != None ) : o0O0o . set_dest_eid . instance_id = IiIIIIi1I
   if 35 - 35: I1ii11iIi11i - oO0o - O0 / iII111i % IiII
  if ( iIi == "set-rloc-address" ) :
   o0O0o . set_rloc_address = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
   o0O0o . set_rloc_address . store_address ( oOOO )
   if 10 - 10: OOooOOo + oO0o - I1Ii111 . I1IiiI
  if ( iIi == "set-rloc-record-name" ) :
   o0O0o . set_rloc_record_name = oOOO
   if 11 - 11: I1ii11iIi11i . I1Ii111 / o0oOOo0O0Ooo + IiII
  if ( iIi == "set-elp-name" ) :
   o0O0o . set_elp_name = oOOO
   if 73 - 73: OoO0O00 . i11iIiiIii * OoO0O00 * i1IIi + I11i
  if ( iIi == "set-geo-name" ) :
   o0O0o . set_geo_name = oOOO
   if 27 - 27: i11iIiiIii / OoOoOO00 % O0 / II111iiii . I11i - ooOoO0o
  if ( iIi == "set-rle-name" ) :
   o0O0o . set_rle_name = oOOO
   if 54 - 54: oO0o * II111iiii
  if ( iIi == "set-json-name" ) :
   o0O0o . set_json_name = oOOO
   if 79 - 79: o0oOOo0O0Ooo . ooOoO0o . Oo0Ooo * OoooooooOO
  if ( iIi == "policy-name" ) :
   o0O0o . policy_name = oOOO
   if 98 - 98: ooOoO0o
   if 73 - 73: I1Ii111
   if 97 - 97: OoO0O00 * Ii1I + Oo0Ooo
   if 83 - 83: II111iiii - Oo0Ooo % II111iiii * o0oOOo0O0Ooo
   if 51 - 51: iII111i * iIii1I11I1II1 % Ii1I * Ii1I + i11iIiiIii . OoooooooOO
   if 54 - 54: i11iIiiIii . iIii1I11I1II1 * iIii1I11I1II1 + Ii1I % I11i - OoO0O00
 o0O0o . match_clauses = IiiiOOo
 o0O0o . save_policy ( )
 return
 if 16 - 16: IiII % iIii1I11I1II1 * i11iIiiIii + O0
 if 76 - 76: iII111i * OOooOOo
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
if 7 - 7: ooOoO0o + o0oOOo0O0Ooo + o0oOOo0O0Ooo
if 73 - 73: IiII % I11i % i11iIiiIii + ooOoO0o
if 83 - 83: Ii1I * I1Ii111 * i11iIiiIii / iIii1I11I1II1 % I1ii11iIi11i
if 40 - 40: iII111i
if 21 - 21: I1Ii111 / iII111i + Oo0Ooo / I1ii11iIi11i / I1Ii111
if 33 - 33: OoooooooOO
if 59 - 59: i11iIiiIii - OoooooooOO . ooOoO0o / i11iIiiIii % iIii1I11I1II1 * I1ii11iIi11i
def lisp_send_to_arista ( command , interface ) :
 interface = "" if ( interface == None ) else "interface " + interface
 if 45 - 45: I1ii11iIi11i * I1ii11iIi11i
 IIiI1111I = command
 if ( interface != "" ) : IIiI1111I = interface + ": " + IIiI1111I
 lprint ( "Send CLI command '{}' to hardware" . format ( IIiI1111I ) )
 if 82 - 82: II111iiii . Oo0Ooo . Ii1I * o0oOOo0O0Ooo
 commands = '''
        enable
        configure
        {}
        {}
    ''' . format ( interface , command )
 if 17 - 17: II111iiii
 os . system ( "FastCli -c '{}'" . format ( commands ) )
 return
 if 91 - 91: oO0o - oO0o % Ii1I % iIii1I11I1II1 / OoOoOO00
 if 60 - 60: I1IiiI / iIii1I11I1II1 - o0oOOo0O0Ooo / OoooooooOO * OoooooooOO
 if 22 - 22: I1ii11iIi11i . Oo0Ooo - o0oOOo0O0Ooo * Oo0Ooo . i1IIi * OoO0O00
 if 7 - 7: O0 / I1IiiI + OoO0O00 . i1IIi - ooOoO0o + ooOoO0o
 if 93 - 93: oO0o - I1IiiI / I1ii11iIi11i % o0oOOo0O0Ooo / OoooooooOO + II111iiii
 if 10 - 10: o0oOOo0O0Ooo - iII111i . O0 + OoO0O00 - Oo0Ooo - i11iIiiIii
 if 37 - 37: iIii1I11I1II1
def lisp_arista_is_alive ( prefix ) :
 i1i1i1I = "enable\nsh plat trident l3 software routes {}\n" . format ( prefix )
 ooO000O = commands . getoutput ( "FastCli -c '{}'" . format ( i1i1i1I ) )
 if 37 - 37: II111iiii % OoOoOO00 . IiII * ooOoO0o . I1IiiI
 if 25 - 25: OoooooooOO % i1IIi . I1Ii111 / OoOoOO00 - I1ii11iIi11i
 if 15 - 15: iIii1I11I1II1
 if 72 - 72: OoO0O00 . IiII * Ii1I - I1IiiI
 ooO000O = ooO000O . split ( "\n" ) [ 1 ]
 OOOoO00000oOoO = ooO000O . split ( " " )
 OOOoO00000oOoO = OOOoO00000oOoO [ - 1 ] . replace ( "\r" , "" )
 if 84 - 84: OoO0O00 + Oo0Ooo . I1IiiI
 if 65 - 65: OoO0O00
 if 34 - 34: IiII * IiII
 if 76 - 76: OOooOOo
 return ( OOOoO00000oOoO == "Y" )
 if 54 - 54: O0 * II111iiii * OOooOOo
 if 44 - 44: I1IiiI
 if 66 - 66: o0oOOo0O0Ooo
 if 40 - 40: OOooOOo * Ii1I
 if 38 - 38: ooOoO0o
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
def lisp_program_vxlan_hardware ( mc ) :
 if 93 - 93: iIii1I11I1II1 . II111iiii * OOooOOo - iIii1I11I1II1 . oO0o % Oo0Ooo
 if 92 - 92: OoO0O00
 if 42 - 42: I1ii11iIi11i - iIii1I11I1II1 % ooOoO0o
 if 7 - 7: Oo0Ooo / ooOoO0o + o0oOOo0O0Ooo
 if 38 - 38: o0oOOo0O0Ooo . O0 - OoO0O00 % I11i
 if 80 - 80: o0oOOo0O0Ooo
 if ( os . path . exists ( "/persist/local/lispers.net" ) == False ) : return
 if 100 - 100: iIii1I11I1II1 . OoOoOO00 . OoooooooOO / I1ii11iIi11i - I1IiiI * I11i
 if 5 - 5: i1IIi * o0oOOo0O0Ooo - I1Ii111 + I1IiiI - II111iiii
 if 15 - 15: I1Ii111
 if 38 - 38: O0
 if ( len ( mc . best_rloc_set ) == 0 ) : return
 if 50 - 50: i11iIiiIii * OoO0O00 + iII111i / O0 * oO0o % ooOoO0o
 if 6 - 6: OoO0O00 . o0oOOo0O0Ooo / Ii1I + Ii1I
 if 59 - 59: II111iiii - o0oOOo0O0Ooo * OoooooooOO
 if 83 - 83: oO0o . iIii1I11I1II1 . iII111i % Oo0Ooo
 iIiII11O00 = mc . eid . print_prefix_no_iid ( )
 i1IIIIi1Ii111 = mc . best_rloc_set [ 0 ] . rloc . print_address_no_iid ( )
 if 48 - 48: oO0o % OoO0O00 - OoooooooOO . IiII
 if 11 - 11: I1Ii111 % o0oOOo0O0Ooo - o0oOOo0O0Ooo % OoooooooOO . o0oOOo0O0Ooo - I1ii11iIi11i
 if 33 - 33: OoO0O00 + II111iiii . Oo0Ooo * I1Ii111
 if 63 - 63: OoooooooOO + OoOoOO00 - OoooooooOO
 OO0oOo = commands . getoutput ( "ip route get {} | egrep vlan4094" . format ( iIiII11O00 ) )
 if 44 - 44: i1IIi - ooOoO0o / I1ii11iIi11i
 if ( OO0oOo != "" ) :
  lprint ( "Route {} already in hardware: '{}'" . format ( green ( iIiII11O00 , False ) , OO0oOo ) )
  if 60 - 60: o0oOOo0O0Ooo . i1IIi * IiII
  return
  if 100 - 100: I1IiiI / I1Ii111 - Oo0Ooo % iII111i - I1ii11iIi11i % OoO0O00
  if 11 - 11: II111iiii
  if 37 - 37: IiII
  if 43 - 43: OoO0O00 / IiII % iIii1I11I1II1
  if 89 - 89: I11i + iII111i / i11iIiiIii
  if 46 - 46: ooOoO0o + ooOoO0o / IiII
  if 57 - 57: OOooOOo + I1ii11iIi11i
 ooIi1iiI11I = commands . getoutput ( "ifconfig | egrep 'vxlan|vlan4094'" )
 if ( ooIi1iiI11I . find ( "vxlan" ) == - 1 ) :
  lprint ( "No VXLAN interface found, cannot program hardware" )
  return
  if 24 - 24: o0oOOo0O0Ooo * I11i . I1IiiI
 if ( ooIi1iiI11I . find ( "vlan4094" ) == - 1 ) :
  lprint ( "No vlan4094 interface found, cannot program hardware" )
  return
  if 52 - 52: OoooooooOO * I1Ii111 % II111iiii
 I1i1iiI11ii = commands . getoutput ( "ip addr | egrep vlan4094 | egrep inet" )
 if ( I1i1iiI11ii == "" ) :
  lprint ( "No IP address found on vlan4094, cannot program hardware" )
  return
  if 51 - 51: OoO0O00 - Oo0Ooo . I11i / oO0o . II111iiii * I1Ii111
 I1i1iiI11ii = I1i1iiI11ii . split ( "inet " ) [ 1 ]
 I1i1iiI11ii = I1i1iiI11ii . split ( "/" ) [ 0 ]
 if 40 - 40: I1Ii111
 if 88 - 88: i11iIiiIii * O0 . i11iIiiIii . o0oOOo0O0Ooo . OoooooooOO
 if 94 - 94: ooOoO0o / oO0o . iII111i % IiII - I11i
 if 61 - 61: OoooooooOO % OoO0O00 . OoO0O00 - I11i
 if 35 - 35: oO0o . Ii1I
 if 71 - 71: iIii1I11I1II1 / I1ii11iIi11i + OoooooooOO . ooOoO0o
 if 63 - 63: i11iIiiIii % I1Ii111 % IiII * i1IIi + I1Ii111 + I1Ii111
 O0o0 = [ ]
 IiI1i = commands . getoutput ( "arp -i vlan4094" ) . split ( "\n" )
 for i11ii in IiI1i :
  if ( i11ii . find ( "vlan4094" ) == - 1 ) : continue
  if ( i11ii . find ( "(incomplete)" ) == - 1 ) : continue
  I1i1i1iIIiI11 = i11ii . split ( " " ) [ 0 ]
  O0o0 . append ( I1i1i1iIIiI11 )
  if 29 - 29: I1IiiI - OOooOOo
  if 83 - 83: OoOoOO00 * oO0o . OOooOOo - OoO0O00
 I1i1i1iIIiI11 = None
 O00o0Oo = I1i1iiI11ii
 I1i1iiI11ii = I1i1iiI11ii . split ( "." )
 for oO in range ( 1 , 255 ) :
  I1i1iiI11ii [ 3 ] = str ( oO )
  I1Iii1I = "." . join ( I1i1iiI11ii )
  if ( I1Iii1I in O0o0 ) : continue
  if ( I1Iii1I == O00o0Oo ) : continue
  I1i1i1iIIiI11 = I1Iii1I
  break
  if 73 - 73: I1ii11iIi11i / iII111i / Oo0Ooo
 if ( I1i1i1iIIiI11 == None ) :
  lprint ( "Address allocation failed for vlan4094, cannot program " + "hardware" )
  if 85 - 85: Ii1I
  return
  if 67 - 67: i11iIiiIii / II111iiii . i11iIiiIii * i11iIiiIii / ooOoO0o . oO0o
  if 46 - 46: oO0o . OoO0O00 - iIii1I11I1II1 . IiII
  if 52 - 52: i11iIiiIii / O0 + oO0o . I11i
  if 73 - 73: OoooooooOO / I1IiiI % Oo0Ooo . oO0o + OoooooooOO
  if 84 - 84: I1ii11iIi11i - OOooOOo * II111iiii
  if 28 - 28: I1ii11iIi11i . oO0o / o0oOOo0O0Ooo - iII111i
  if 65 - 65: I1ii11iIi11i * OOooOOo * ooOoO0o + oO0o - OOooOOo
 ooOOo0Oo000 = i1IIIIi1Ii111 . split ( "." )
 i1iiiIIiI = lisp_hex_string ( ooOOo0Oo000 [ 1 ] ) . zfill ( 2 )
 i1iIiII1 = lisp_hex_string ( ooOOo0Oo000 [ 2 ] ) . zfill ( 2 )
 OO000oOooO00 = lisp_hex_string ( ooOOo0Oo000 [ 3 ] ) . zfill ( 2 )
 o0O0oO0 = "00:00:00:{}:{}:{}" . format ( i1iiiIIiI , i1iIiII1 , OO000oOooO00 )
 IIi1iii = "0000.00{}.{}{}" . format ( i1iiiIIiI , i1iIiII1 , OO000oOooO00 )
 oo0O0oOOo0O = "arp -i vlan4094 -s {} {}" . format ( I1i1i1iIIiI11 , o0O0oO0 )
 os . system ( oo0O0oOOo0O )
 if 16 - 16: II111iiii % oO0o
 if 59 - 59: iII111i
 if 26 - 26: I11i + o0oOOo0O0Ooo / OoO0O00
 if 55 - 55: i11iIiiIii
 iiIIi1Iii1 = ( "mac address-table static {} vlan 4094 " + "interface vxlan 1 vtep {}" ) . format ( IIi1iii , i1IIIIi1Ii111 )
 if 25 - 25: OoOoOO00 * OoOoOO00 * Oo0Ooo / iIii1I11I1II1
 lisp_send_to_arista ( iiIIi1Iii1 , None )
 if 63 - 63: IiII - ooOoO0o % OoO0O00 * i11iIiiIii % OOooOOo
 if 90 - 90: oO0o / Oo0Ooo + iII111i - O0
 if 76 - 76: ooOoO0o + IiII / I1ii11iIi11i . iIii1I11I1II1
 if 52 - 52: iIii1I11I1II1 * OOooOOo % i1IIi
 if 1 - 1: o0oOOo0O0Ooo + Ii1I - o0oOOo0O0Ooo % I1ii11iIi11i
 o0oOIIiIi11I = "ip route add {} via {}" . format ( iIiII11O00 , I1i1i1iIIiI11 )
 os . system ( o0oOIIiIi11I )
 if 22 - 22: ooOoO0o . ooOoO0o % i1IIi * II111iiii * IiII
 lprint ( "Hardware programmed with commands:" )
 o0oOIIiIi11I = o0oOIIiIi11I . replace ( iIiII11O00 , green ( iIiII11O00 , False ) )
 lprint ( "  " + o0oOIIiIi11I )
 lprint ( "  " + oo0O0oOOo0O )
 iiIIi1Iii1 = iiIIi1Iii1 . replace ( i1IIIIi1Ii111 , red ( i1IIIIi1Ii111 , False ) )
 lprint ( "  " + iiIIi1Iii1 )
 return
 if 6 - 6: II111iiii . iII111i % I1ii11iIi11i + IiII / I11i
 if 35 - 35: iII111i * Oo0Ooo
 if 61 - 61: I1Ii111 - I1IiiI - I11i * OoO0O00 - O0 + iII111i
 if 9 - 9: IiII - OOooOOo / O0 + i1IIi . O0 % oO0o
 if 57 - 57: i1IIi . OOooOOo
 if 72 - 72: ooOoO0o / I1IiiI - ooOoO0o * OoO0O00 . OOooOOo
 if 1 - 1: o0oOOo0O0Ooo + I1Ii111 + OoO0O00 * OOooOOo / I1Ii111 % i11iIiiIii
def lisp_clear_hardware_walk ( mc , parms ) :
 O00OOOoOoooo = mc . eid . print_prefix_no_iid ( )
 os . system ( "ip route delete {}" . format ( O00OOOoOoooo ) )
 return ( [ True , None ] )
 if 49 - 49: OOooOOo - oO0o
 if 73 - 73: o0oOOo0O0Ooo . I1IiiI - I11i . ooOoO0o % II111iiii . OoooooooOO
 if 8 - 8: OoooooooOO
 if 92 - 92: ooOoO0o + IiII * II111iiii
 if 41 - 41: I1IiiI + OoOoOO00 . OOooOOo
 if 57 - 57: II111iiii . iIii1I11I1II1
 if 32 - 32: o0oOOo0O0Ooo
 if 75 - 75: I1IiiI . II111iiii - iII111i % IiII * OoO0O00 % ooOoO0o
def lisp_clear_map_cache ( ) :
 global lisp_map_cache , lisp_rloc_probe_list
 global lisp_crypto_keys_by_rloc_encap , lisp_crypto_keys_by_rloc_decap
 global lisp_rtr_list
 if 38 - 38: I1IiiI / OoooooooOO
 IiiI11iI1I = bold ( "User cleared" , False )
 o0OO0oooo = lisp_map_cache . cache_count
 lprint ( "{} map-cache with {} entries" . format ( IiiI11iI1I , o0OO0oooo ) )
 if 43 - 43: OoO0O00 - I1Ii111 % OoooooooOO % I1ii11iIi11i . OoOoOO00
 if ( lisp_program_hardware ) :
  lisp_map_cache . walk_cache ( lisp_clear_hardware_walk , None )
  if 87 - 87: OOooOOo
 lisp_map_cache = lisp_cache ( )
 if 60 - 60: ooOoO0o * o0oOOo0O0Ooo . OoO0O00 * iII111i * oO0o * i1IIi
 if 100 - 100: iII111i . o0oOOo0O0Ooo - I1Ii111 % oO0o
 if 11 - 11: o0oOOo0O0Ooo . OoooooooOO - i1IIi
 if 71 - 71: I1IiiI . OOooOOo . I1ii11iIi11i
 if 90 - 90: i11iIiiIii + I1Ii111 % II111iiii
 lisp_rloc_probe_list = { }
 if 67 - 67: OoOoOO00 / iII111i * OoO0O00 % i11iIiiIii
 if 76 - 76: OoO0O00
 if 92 - 92: iIii1I11I1II1 * O0 % I11i
 if 92 - 92: OoOoOO00 + oO0o
 lisp_crypto_keys_by_rloc_encap = { }
 lisp_crypto_keys_by_rloc_decap = { }
 if 89 - 89: IiII % iII111i / iIii1I11I1II1 . Ii1I . Oo0Ooo + ooOoO0o
 if 28 - 28: I1IiiI . iIii1I11I1II1
 if 12 - 12: I1Ii111 * OOooOOo
 if 11 - 11: II111iiii % O0 % O0 % o0oOOo0O0Ooo
 if 45 - 45: OoooooooOO * oO0o
 lisp_rtr_list = { }
 if 74 - 74: ooOoO0o * I11i / oO0o - IiII + OoOoOO00
 if 16 - 16: Oo0Ooo
 if 29 - 29: Oo0Ooo . I1ii11iIi11i / II111iiii / oO0o / o0oOOo0O0Ooo + I11i
 if 4 - 4: OoooooooOO % I1ii11iIi11i . OoO0O00 * o0oOOo0O0Ooo + I1ii11iIi11i * IiII
 lisp_process_data_plane_restart ( True )
 return
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
def lisp_encapsulate_rloc_probe ( lisp_sockets , rloc , nat_info , packet ) :
 if ( len ( lisp_sockets ) != 4 ) : return
 if 18 - 18: iIii1I11I1II1 . ooOoO0o
 oO0oOO00 = lisp_myrlocs [ 0 ]
 if 33 - 33: OoO0O00 / OOooOOo % Oo0Ooo . o0oOOo0O0Ooo % II111iiii
 if 62 - 62: iII111i . OoooooooOO - i1IIi
 if 59 - 59: OoOoOO00 + i1IIi * OoooooooOO . oO0o
 if 38 - 38: I1ii11iIi11i / o0oOOo0O0Ooo
 if 95 - 95: iIii1I11I1II1 / OoOoOO00 % I1Ii111
 I1I1 = len ( packet ) + 28
 oOo00Ooo0o0 = struct . pack ( "BBHIBBHII" , 0x45 , 0 , socket . htons ( I1I1 ) , 0 , 64 ,
 17 , 0 , socket . htonl ( oO0oOO00 . address ) , socket . htonl ( rloc . address ) )
 oOo00Ooo0o0 = lisp_ip_checksum ( oOo00Ooo0o0 )
 if 54 - 54: OoooooooOO % Ii1I
 IIi1ii1 = struct . pack ( "HHHH" , 0 , socket . htons ( LISP_CTRL_PORT ) ,
 socket . htons ( I1I1 - 20 ) , 0 )
 if 100 - 100: OOooOOo - I11i . O0 * i1IIi % OoooooooOO - ooOoO0o
 if 54 - 54: O0 + I11i
 if 71 - 71: OoOoOO00
 if 29 - 29: O0 . i11iIiiIii
 packet = lisp_packet ( oOo00Ooo0o0 + IIi1ii1 + packet )
 if 51 - 51: IiII
 if 53 - 53: O0
 if 19 - 19: o0oOOo0O0Ooo / iII111i % OoOoOO00
 if 65 - 65: o0oOOo0O0Ooo
 packet . inner_dest . copy_address ( rloc )
 packet . inner_dest . instance_id = 0xffffff
 packet . inner_source . copy_address ( oO0oOO00 )
 packet . inner_ttl = 64
 packet . outer_dest . copy_address ( rloc )
 packet . outer_source . copy_address ( oO0oOO00 )
 packet . outer_version = packet . outer_dest . afi_to_version ( )
 packet . outer_ttl = 64
 packet . encap_port = nat_info . port if nat_info else LISP_DATA_PORT
 if 89 - 89: iIii1I11I1II1 + OoooooooOO + i1IIi + OoooooooOO % IiII * OoO0O00
 I111I = red ( rloc . print_address_no_iid ( ) , False )
 if ( nat_info ) :
  iI111III = " {}" . format ( blue ( nat_info . hostname , False ) )
  O00oOoo0OoOOO = bold ( "RLOC-probe request" , False )
 else :
  iI111III = ""
  O00oOoo0OoOOO = bold ( "RLOC-probe reply" , False )
  if 53 - 53: OOooOOo . IiII % I11i - OoO0O00 - Oo0Ooo
  if 58 - 58: I1Ii111 / OoooooooOO . I11i % I1Ii111
 lprint ( ( "Data encapsulate {} to {}{} port {} for " + "NAT-traversal" ) . format ( O00oOoo0OoOOO , I111I , iI111III , packet . encap_port ) )
 if 8 - 8: Oo0Ooo % ooOoO0o / i11iIiiIii
 if 54 - 54: IiII
 if 85 - 85: OOooOOo - i1IIi
 if 10 - 10: I1ii11iIi11i
 if 3 - 3: ooOoO0o * O0 / o0oOOo0O0Ooo
 if ( packet . encode ( None ) == None ) : return
 packet . print_packet ( "Send" , True )
 if 22 - 22: OoOoOO00 + OOooOOo . iII111i % iIii1I11I1II1 - I11i
 iI1iI1Iiii1i1 = lisp_sockets [ 3 ]
 packet . send_packet ( iI1iI1Iiii1i1 , packet . outer_dest )
 del ( packet )
 return
 if 67 - 67: OoO0O00 - ooOoO0o . OoO0O00 - ooOoO0o / o0oOOo0O0Ooo / II111iiii
 if 77 - 77: Oo0Ooo
 if 53 - 53: ooOoO0o * iIii1I11I1II1 . oO0o * Oo0Ooo . Oo0Ooo % iIii1I11I1II1
 if 7 - 7: ooOoO0o + Ii1I
 if 25 - 25: OoO0O00 * oO0o
 if 29 - 29: OOooOOo - I1Ii111 - i11iIiiIii % i1IIi
 if 2 - 2: i11iIiiIii % iIii1I11I1II1 * OOooOOo
 if 45 - 45: oO0o + i1IIi + iII111i + o0oOOo0O0Ooo * OOooOOo + ooOoO0o
def lisp_get_default_route_next_hops ( ) :
 if 83 - 83: OoO0O00 - ooOoO0o / OoooooooOO % iIii1I11I1II1 - II111iiii
 if 73 - 73: Oo0Ooo + II111iiii - IiII
 if 60 - 60: i1IIi . i11iIiiIii / i1IIi . I11i % OOooOOo
 if 47 - 47: oO0o + IiII * I1Ii111 % o0oOOo0O0Ooo - O0 % IiII
 if ( lisp_is_macos ( ) ) :
  i1i1i1I = "route -n get default"
  Oooo0O0ooOooO = commands . getoutput ( i1i1i1I ) . split ( "\n" )
  I1iI11iII11 = iIiiiIiIi = None
  for Oo0OO0o0oOO0 in Oooo0O0ooOooO :
   if ( Oo0OO0o0oOO0 . find ( "gateway: " ) != - 1 ) : I1iI11iII11 = Oo0OO0o0oOO0 . split ( ": " ) [ 1 ]
   if ( Oo0OO0o0oOO0 . find ( "interface: " ) != - 1 ) : iIiiiIiIi = Oo0OO0o0oOO0 . split ( ": " ) [ 1 ]
   if 56 - 56: Ii1I + i1IIi / II111iiii
  return ( [ [ iIiiiIiIi , I1iI11iII11 ] ] )
  if 54 - 54: O0 * IiII + i11iIiiIii - oO0o - ooOoO0o + i11iIiiIii
  if 87 - 87: I1ii11iIi11i * iIii1I11I1II1 / I1Ii111
  if 5 - 5: i1IIi * IiII / iIii1I11I1II1 * OoooooooOO . O0
  if 57 - 57: i11iIiiIii
  if 89 - 89: o0oOOo0O0Ooo . I1Ii111 * I11i + oO0o - OoooooooOO + OoO0O00
 i1i1i1I = "ip route | egrep 'default via'"
 ooO0oO00O = commands . getoutput ( i1i1i1I ) . split ( "\n" )
 if 25 - 25: i1IIi * I1Ii111 * iII111i . OoooooooOO
 IiiI1iiI11 = [ ]
 for OO0oOo in ooO0oO00O :
  if ( OO0oOo . find ( " metric " ) != - 1 ) : continue
  iIOoo000 = OO0oOo . split ( " " )
  try :
   ooOiiIiI1I = iIOoo000 . index ( "via" ) + 1
   if ( ooOiiIiI1I >= len ( iIOoo000 ) ) : continue
   O0OO0 = iIOoo000 . index ( "dev" ) + 1
   if ( O0OO0 >= len ( iIOoo000 ) ) : continue
  except :
   continue
   if 60 - 60: OoO0O00 / I1ii11iIi11i % iII111i % i11iIiiIii * OoooooooOO * iII111i
   if 92 - 92: I11i % iIii1I11I1II1 * iII111i - OoooooooOO - I11i
  IiiI1iiI11 . append ( [ iIOoo000 [ O0OO0 ] , iIOoo000 [ ooOiiIiI1I ] ] )
  if 34 - 34: I1Ii111 / i1IIi / O0 / OoooooooOO
 return ( IiiI1iiI11 )
 if 55 - 55: I1Ii111 . I1IiiI * iIii1I11I1II1 / Ii1I . I1IiiI
 if 63 - 63: ooOoO0o . Ii1I - I1Ii111 - oO0o * I1Ii111 + ooOoO0o
 if 85 - 85: II111iiii + I1ii11iIi11i
 if 33 - 33: iII111i
 if 14 - 14: O0 * Oo0Ooo / i1IIi
 if 95 - 95: O0 % i1IIi % ooOoO0o % oO0o - I1IiiI
 if 78 - 78: II111iiii % OOooOOo
def lisp_get_host_route_next_hop ( rloc ) :
 i1i1i1I = "ip route | egrep '{} via'" . format ( rloc )
 OO0oOo = commands . getoutput ( i1i1i1I ) . split ( " " )
 if 6 - 6: OOooOOo
 try : OOOoO000 = OO0oOo . index ( "via" ) + 1
 except : return ( None )
 if 21 - 21: I1Ii111 - Ii1I - i1IIi % oO0o
 if ( OOOoO000 >= len ( OO0oOo ) ) : return ( None )
 return ( OO0oOo [ OOOoO000 ] )
 if 55 - 55: OOooOOo + oO0o - II111iiii
 if 5 - 5: iII111i * OoooooooOO . OoO0O00 % ooOoO0o + Ii1I
 if 59 - 59: OoOoOO00
 if 96 - 96: I1IiiI
 if 3 - 3: OoooooooOO
 if 3 - 3: IiII / O0 * i11iIiiIii . iII111i - iIii1I11I1II1
 if 56 - 56: ooOoO0o
def lisp_install_host_route ( dest , nh , install ) :
 install = "add" if install else "delete"
 II1Iii1Iiii = "none" if nh == None else nh
 if 82 - 82: ooOoO0o . IiII . I1Ii111 - iIii1I11I1II1 + II111iiii . OoOoOO00
 lprint ( "{} host-route {}, nh {}" . format ( install . title ( ) , dest , II1Iii1Iiii ) )
 if 59 - 59: Oo0Ooo
 if ( nh == None ) :
  O0o0o00o = "ip route {} {}/32" . format ( install , dest )
 else :
  O0o0o00o = "ip route {} {}/32 via {}" . format ( install , dest , nh )
  if 98 - 98: I1Ii111 * II111iiii / Oo0Ooo . Oo0Ooo % I1Ii111
 os . system ( O0o0o00o )
 return
 if 52 - 52: OoOoOO00
 if 59 - 59: ooOoO0o / OoooooooOO
 if 71 - 71: OOooOOo + I11i * O0 / o0oOOo0O0Ooo + I1IiiI + Ii1I
 if 41 - 41: ooOoO0o * I1Ii111
 if 40 - 40: OoOoOO00
 if 60 - 60: IiII . i11iIiiIii * II111iiii . Ii1I
 if 10 - 10: O0
 if 65 - 65: I11i % i11iIiiIii + i11iIiiIii % II111iiii
def lisp_checkpoint ( checkpoint_list ) :
 if ( lisp_checkpoint_map_cache == False ) : return
 if 95 - 95: I1Ii111 - I11i . II111iiii . i1IIi / II111iiii + Oo0Ooo
 Oo0OO0o0oOO0 = open ( lisp_checkpoint_filename , "w" )
 for o0Iiii in checkpoint_list :
  Oo0OO0o0oOO0 . write ( o0Iiii + "\n" )
  if 96 - 96: iIii1I11I1II1 * iII111i / OOooOOo * iIii1I11I1II1 - O0
 Oo0OO0o0oOO0 . close ( )
 lprint ( "{} {} entries to file '{}'" . format ( bold ( "Checkpoint" , False ) ,
 len ( checkpoint_list ) , lisp_checkpoint_filename ) )
 return
 if 28 - 28: I11i / I1IiiI - I1Ii111 + I1ii11iIi11i % iIii1I11I1II1
 if 35 - 35: iIii1I11I1II1 % Oo0Ooo % iII111i / iIii1I11I1II1 - I1ii11iIi11i . Oo0Ooo
 if 81 - 81: II111iiii + oO0o
 if 67 - 67: ooOoO0o + I11i - I1ii11iIi11i - OoooooooOO
 if 37 - 37: I11i % I1IiiI
 if 32 - 32: OOooOOo + OoooooooOO . IiII . Oo0Ooo * iII111i
 if 86 - 86: I1ii11iIi11i . iII111i + Ii1I - IiII / i11iIiiIii + OoOoOO00
 if 50 - 50: o0oOOo0O0Ooo - IiII + OoOoOO00 - II111iiii
def lisp_load_checkpoint ( ) :
 if ( lisp_checkpoint_map_cache == False ) : return
 if ( os . path . exists ( lisp_checkpoint_filename ) == False ) : return
 if 24 - 24: I1Ii111 - IiII % I1IiiI - OoooooooOO % Ii1I
 Oo0OO0o0oOO0 = open ( lisp_checkpoint_filename , "r" )
 if 56 - 56: I1ii11iIi11i
 o0OO0oooo = 0
 for o0Iiii in Oo0OO0o0oOO0 :
  o0OO0oooo += 1
  I1i11II = o0Iiii . split ( " rloc " )
  Ii1II1 = [ ] if ( I1i11II [ 1 ] in [ "native-forward\n" , "\n" ] ) else I1i11II [ 1 ] . split ( ", " )
  if 40 - 40: OoooooooOO
  if 100 - 100: IiII - I11i
  oOo0oOOOoOoo = [ ]
  for i1IIIIi1Ii111 in Ii1II1 :
   ii1I1i11 = lisp_rloc ( False )
   iIOoo000 = i1IIIIi1Ii111 . split ( " " )
   ii1I1i11 . rloc . store_address ( iIOoo000 [ 0 ] )
   ii1I1i11 . priority = int ( iIOoo000 [ 1 ] )
   ii1I1i11 . weight = int ( iIOoo000 [ 2 ] )
   oOo0oOOOoOoo . append ( ii1I1i11 )
   if 79 - 79: iII111i % O0
   if 73 - 73: Oo0Ooo
  Iii1 = lisp_mapping ( "" , "" , oOo0oOOOoOoo )
  if ( Iii1 != None ) :
   Iii1 . eid . store_prefix ( I1i11II [ 0 ] )
   Iii1 . checkpoint_entry = True
   Iii1 . map_cache_ttl = LISP_NMR_TTL * 60
   if ( oOo0oOOOoOoo == [ ] ) : Iii1 . action = LISP_NATIVE_FORWARD_ACTION
   Iii1 . add_cache ( )
   continue
   if 13 - 13: OOooOOo - ooOoO0o
   if 8 - 8: I1Ii111 % oO0o
  o0OO0oooo -= 1
  if 19 - 19: O0 + OoO0O00 - i1IIi % OoOoOO00 / Oo0Ooo + OoooooooOO
  if 93 - 93: i11iIiiIii % OOooOOo . I11i * ooOoO0o
 Oo0OO0o0oOO0 . close ( )
 lprint ( "{} {} map-cache entries from file '{}'" . format (
 bold ( "Loaded" , False ) , o0OO0oooo , lisp_checkpoint_filename ) )
 return
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
 if 34 - 34: I1Ii111 % Ii1I / Oo0Ooo % ooOoO0o / i11iIiiIii * I1IiiI
 if 36 - 36: i11iIiiIii * i1IIi % iII111i . Oo0Ooo
 if 54 - 54: o0oOOo0O0Ooo % i1IIi % I1ii11iIi11i . o0oOOo0O0Ooo / OoOoOO00
 if 55 - 55: O0 / OoooooooOO % Ii1I * O0 + iIii1I11I1II1 . iIii1I11I1II1
def lisp_write_checkpoint_entry ( checkpoint_list , mc ) :
 if ( lisp_checkpoint_map_cache == False ) : return
 if 55 - 55: Ii1I . OoooooooOO % Ii1I . IiII
 o0Iiii = "{} rloc " . format ( mc . eid . print_prefix ( ) )
 if 67 - 67: oO0o
 for ii1I1i11 in mc . rloc_set :
  if ( ii1I1i11 . rloc . is_null ( ) ) : continue
  o0Iiii += "{} {} {}, " . format ( ii1I1i11 . rloc . print_address_no_iid ( ) ,
 ii1I1i11 . priority , ii1I1i11 . weight )
  if 12 - 12: I1IiiI + OoooooooOO
  if 25 - 25: iIii1I11I1II1 - I1IiiI . i11iIiiIii + ooOoO0o
 if ( mc . rloc_set != [ ] ) :
  o0Iiii = o0Iiii [ 0 : - 2 ]
 elif ( mc . action == LISP_NATIVE_FORWARD_ACTION ) :
  o0Iiii += "native-forward"
  if 19 - 19: OoooooooOO / IiII
  if 40 - 40: OoOoOO00 / OoooooooOO * iIii1I11I1II1 / i1IIi . OoooooooOO
 checkpoint_list . append ( o0Iiii )
 return
 if 88 - 88: I1IiiI % I1IiiI / II111iiii - IiII
 if 72 - 72: OoO0O00 - I1ii11iIi11i . Oo0Ooo / OoO0O00
 if 86 - 86: i11iIiiIii - oO0o . i11iIiiIii
 if 51 - 51: OoO0O00 - OoO0O00 * IiII
 if 24 - 24: OoooooooOO . II111iiii
 if 97 - 97: II111iiii . O0
 if 18 - 18: iII111i
def lisp_check_dp_socket ( ) :
 I1iioo0oOo0 = lisp_ipc_dp_socket_name
 if ( os . path . exists ( I1iioo0oOo0 ) == False ) :
  OOoooOOoooOO0 = bold ( "does not exist" , False )
  lprint ( "Socket '{}' {}" . format ( I1iioo0oOo0 , OOoooOOoooOO0 ) )
  return ( False )
  if 61 - 61: i11iIiiIii + OOooOOo - i1IIi
 return ( True )
 if 2 - 2: I1ii11iIi11i / I1Ii111 / I1ii11iIi11i / iII111i * i11iIiiIii % iII111i
 if 48 - 48: O0 + o0oOOo0O0Ooo . oO0o - IiII * OoooooooOO . OoO0O00
 if 63 - 63: oO0o * OoO0O00 * oO0o
 if 31 - 31: Oo0Ooo
 if 90 - 90: I11i . IiII * iIii1I11I1II1 . I11i + i1IIi
 if 67 - 67: I1Ii111 . I1ii11iIi11i
 if 2 - 2: O0 + I1Ii111
def lisp_write_to_dp_socket ( entry ) :
 try :
  o00oo = json . dumps ( entry )
  IIIIIii1IiI = bold ( "Write IPC" , False )
  lprint ( "{} record to named socket: '{}'" . format ( IIIIIii1IiI , o00oo ) )
  lisp_ipc_dp_socket . sendto ( o00oo , lisp_ipc_dp_socket_name )
 except :
  lprint ( "Failed to write IPC record to named socket: '{}'" . format ( o00oo ) )
  if 36 - 36: Ii1I * ooOoO0o * OoooooooOO + OoOoOO00
 return
 if 43 - 43: I1Ii111 - Oo0Ooo % i1IIi . II111iiii
 if 80 - 80: IiII . iII111i + I1Ii111 + iII111i % Oo0Ooo
 if 98 - 98: i11iIiiIii . II111iiii + OoOoOO00
 if 25 - 25: I1IiiI + i11iIiiIii . I1Ii111 - I1ii11iIi11i
 if 67 - 67: OOooOOo - OOooOOo * I1IiiI - II111iiii . i1IIi + Oo0Ooo
 if 97 - 97: O0 / i11iIiiIii - o0oOOo0O0Ooo - OoOoOO00 . oO0o
 if 77 - 77: oO0o * oO0o . OoOoOO00 . i1IIi
 if 90 - 90: OOooOOo . Ii1I . II111iiii + Ii1I
 if 2 - 2: I1Ii111 * OOooOOo + II111iiii - OoOoOO00
def lisp_write_ipc_keys ( rloc ) :
 OoOOoooO000 = rloc . rloc . print_address_no_iid ( )
 OOo0000o0 = rloc . translated_port
 if ( OOo0000o0 != 0 ) : OoOOoooO000 += ":" + str ( OOo0000o0 )
 if ( lisp_rloc_probe_list . has_key ( OoOOoooO000 ) == False ) : return
 if 94 - 94: Ii1I - iII111i . I1ii11iIi11i - Oo0Ooo % o0oOOo0O0Ooo + I1Ii111
 for iIOoo000 , I1i11II , i1iII1iii in lisp_rloc_probe_list [ OoOOoooO000 ] :
  Iii1 = lisp_map_cache . lookup_cache ( I1i11II , True )
  if ( Iii1 == None ) : continue
  lisp_write_ipc_map_cache ( True , Iii1 )
  if 58 - 58: oO0o . ooOoO0o . I1IiiI . Oo0Ooo * iIii1I11I1II1 - iII111i
 return
 if 96 - 96: OOooOOo % o0oOOo0O0Ooo / iIii1I11I1II1
 if 60 - 60: i1IIi / iIii1I11I1II1 + I11i % iII111i
 if 64 - 64: I11i . i11iIiiIii / iIii1I11I1II1 . I11i
 if 73 - 73: OoO0O00 % iIii1I11I1II1 + IiII * I1Ii111 % II111iiii
 if 20 - 20: I11i % I1ii11iIi11i . OoO0O00 % OoOoOO00
 if 84 - 84: OoooooooOO / i11iIiiIii . IiII / I1IiiI
 if 62 - 62: iII111i - I1IiiI + OoooooooOO
def lisp_write_ipc_map_cache ( add_or_delete , mc , dont_send = False ) :
 if ( lisp_i_am_etr ) : return
 if ( lisp_ipc_dp_socket == None ) : return
 if ( lisp_check_dp_socket ( ) == False ) : return
 if 59 - 59: iIii1I11I1II1 + i11iIiiIii * oO0o . Oo0Ooo . I1Ii111
 if 49 - 49: II111iiii
 if 99 - 99: Oo0Ooo . OOooOOo
 if 85 - 85: OoOoOO00 . IiII + oO0o - II111iiii
 I1Ii = "add" if add_or_delete else "delete"
 o0Iiii = { "type" : "map-cache" , "opcode" : I1Ii }
 if 70 - 70: O0 % I1Ii111
 o0OoOO00O0O0 = ( mc . group . is_null ( ) == False )
 if ( o0OoOO00O0O0 ) :
  o0Iiii [ "eid-prefix" ] = mc . group . print_prefix_no_iid ( )
  o0Iiii [ "rles" ] = [ ]
 else :
  o0Iiii [ "eid-prefix" ] = mc . eid . print_prefix_no_iid ( )
  o0Iiii [ "rlocs" ] = [ ]
  if 13 - 13: I1ii11iIi11i % OoO0O00 / Ii1I * IiII
 o0Iiii [ "instance-id" ] = str ( mc . eid . instance_id )
 if 82 - 82: ooOoO0o % Oo0Ooo
 if ( o0OoOO00O0O0 ) :
  if ( len ( mc . rloc_set ) >= 1 and mc . rloc_set [ 0 ] . rle ) :
   for i1ooOoO in mc . rloc_set [ 0 ] . rle . rle_forwarding_list :
    I1Iii1I = i1ooOoO . address . print_address_no_iid ( )
    OOo0000o0 = str ( 4341 ) if i1ooOoO . translated_port == 0 else str ( i1ooOoO . translated_port )
    if 26 - 26: OoO0O00 + i11iIiiIii % I11i . I1ii11iIi11i
    iIOoo000 = { "rle" : I1Iii1I , "port" : OOo0000o0 }
    iIIIIIIIi11I1 , OoO0OOo = i1ooOoO . get_encap_keys ( )
    iIOoo000 = lisp_build_json_keys ( iIOoo000 , iIIIIIIIi11I1 , OoO0OOo , "encrypt-key" )
    o0Iiii [ "rles" ] . append ( iIOoo000 )
    if 48 - 48: I1ii11iIi11i
    if 69 - 69: oO0o + I11i * Ii1I
 else :
  for i1IIIIi1Ii111 in mc . rloc_set :
   if ( i1IIIIi1Ii111 . rloc . is_ipv4 ( ) == False and i1IIIIi1Ii111 . rloc . is_ipv6 ( ) == False ) :
    continue
    if 13 - 13: I1ii11iIi11i / Oo0Ooo - I1Ii111 * OoOoOO00
   if ( i1IIIIi1Ii111 . up_state ( ) == False ) : continue
   if 47 - 47: IiII
   OOo0000o0 = str ( 4341 ) if i1IIIIi1Ii111 . translated_port == 0 else str ( i1IIIIi1Ii111 . translated_port )
   if 76 - 76: iII111i / II111iiii / I11i
   iIOoo000 = { "rloc" : i1IIIIi1Ii111 . rloc . print_address_no_iid ( ) , "priority" :
 str ( i1IIIIi1Ii111 . priority ) , "weight" : str ( i1IIIIi1Ii111 . weight ) , "port" :
 OOo0000o0 }
   iIIIIIIIi11I1 , OoO0OOo = i1IIIIi1Ii111 . get_encap_keys ( )
   iIOoo000 = lisp_build_json_keys ( iIOoo000 , iIIIIIIIi11I1 , OoO0OOo , "encrypt-key" )
   o0Iiii [ "rlocs" ] . append ( iIOoo000 )
   if 62 - 62: I1ii11iIi11i
   if 100 - 100: iII111i / ooOoO0o / IiII % II111iiii
   if 6 - 6: OoooooooOO - I1IiiI + OoooooooOO
 if ( dont_send == False ) : lisp_write_to_dp_socket ( o0Iiii )
 return ( o0Iiii )
 if 89 - 89: oO0o % Oo0Ooo . O0 . ooOoO0o
 if 46 - 46: IiII * I11i - OoO0O00 - Ii1I
 if 93 - 93: iIii1I11I1II1 / o0oOOo0O0Ooo - I11i - OOooOOo % ooOoO0o
 if 16 - 16: ooOoO0o * o0oOOo0O0Ooo - IiII + I1ii11iIi11i / o0oOOo0O0Ooo - O0
 if 71 - 71: i1IIi
 if 79 - 79: iII111i * O0 / Ii1I / O0 % i1IIi
 if 52 - 52: OoooooooOO % oO0o - I11i % OoOoOO00 . II111iiii
def lisp_write_ipc_decap_key ( rloc_addr , keys ) :
 if ( lisp_i_am_itr ) : return
 if ( lisp_ipc_dp_socket == None ) : return
 if ( lisp_check_dp_socket ( ) == False ) : return
 if 62 - 62: Ii1I . I1ii11iIi11i . iII111i + I11i * o0oOOo0O0Ooo
 if 56 - 56: oO0o * iIii1I11I1II1 . II111iiii - II111iiii + II111iiii - i11iIiiIii
 if 79 - 79: iII111i
 if 29 - 29: Ii1I * I1Ii111 / OoO0O00 - O0 - i11iIiiIii * I1IiiI
 if ( keys == None or len ( keys ) == 0 or keys [ 1 ] == None ) : return
 if 2 - 2: OoOoOO00 . I1ii11iIi11i * I1ii11iIi11i
 iIIIIIIIi11I1 = keys [ 1 ] . encrypt_key
 OoO0OOo = keys [ 1 ] . icv_key
 if 42 - 42: OoO0O00 . OoO0O00 + II111iiii - IiII - OOooOOo * Oo0Ooo
 if 47 - 47: oO0o - OoooooooOO + iII111i
 if 69 - 69: I1ii11iIi11i - I1IiiI % oO0o + OOooOOo - I1Ii111
 if 5 - 5: ooOoO0o . OoO0O00
 i1ii1iI1iII = rloc_addr . split ( ":" )
 if ( len ( i1ii1iI1iII ) == 1 ) :
  o0Iiii = { "type" : "decap-keys" , "rloc" : i1ii1iI1iII [ 0 ] }
 else :
  o0Iiii = { "type" : "decap-keys" , "rloc" : i1ii1iI1iII [ 0 ] , "port" : i1ii1iI1iII [ 1 ] }
  if 95 - 95: O0 / OoO0O00 + IiII * OOooOOo . OOooOOo . I11i
 o0Iiii = lisp_build_json_keys ( o0Iiii , iIIIIIIIi11I1 , OoO0OOo , "decrypt-key" )
 if 63 - 63: I1ii11iIi11i * iIii1I11I1II1 + OoooooooOO . i1IIi * O0 * i1IIi
 lisp_write_to_dp_socket ( o0Iiii )
 return
 if 29 - 29: i11iIiiIii
 if 34 - 34: OoOoOO00
 if 17 - 17: oO0o * OoOoOO00 % OoO0O00 % I1IiiI * I11i
 if 78 - 78: OoooooooOO . I1Ii111 + Ii1I - II111iiii - IiII / iIii1I11I1II1
 if 92 - 92: Ii1I
 if 34 - 34: OOooOOo * OoooooooOO / I1ii11iIi11i
 if 41 - 41: i1IIi
 if 75 - 75: o0oOOo0O0Ooo . I1Ii111 - I1Ii111 % Ii1I * OoooooooOO
def lisp_build_json_keys ( entry , ekey , ikey , key_type ) :
 if ( ekey == None ) : return ( entry )
 if 99 - 99: OOooOOo + o0oOOo0O0Ooo - OOooOOo . i1IIi
 entry [ "keys" ] = [ ]
 i1IIiI1iII = { "key-id" : "1" , key_type : ekey , "icv-key" : ikey }
 entry [ "keys" ] . append ( i1IIiI1iII )
 return ( entry )
 if 86 - 86: Ii1I % oO0o - i11iIiiIii - O0 + IiII + iII111i
 if 100 - 100: OoO0O00 . Oo0Ooo
 if 29 - 29: OoO0O00
 if 34 - 34: O0 - o0oOOo0O0Ooo % OOooOOo . OoO0O00 % IiII
 if 63 - 63: O0 % iIii1I11I1II1 . o0oOOo0O0Ooo . I1IiiI * Ii1I % i1IIi
 if 47 - 47: II111iiii * I1ii11iIi11i
 if 70 - 70: I1ii11iIi11i - o0oOOo0O0Ooo
def lisp_write_ipc_database_mappings ( ephem_port ) :
 if ( lisp_i_am_etr == False ) : return
 if ( lisp_ipc_dp_socket == None ) : return
 if ( lisp_check_dp_socket ( ) == False ) : return
 if 71 - 71: I1ii11iIi11i * i1IIi
 if 67 - 67: I1ii11iIi11i % OoOoOO00 . iII111i / Ii1I . I1IiiI
 if 48 - 48: IiII + II111iiii . I1IiiI % o0oOOo0O0Ooo
 if 57 - 57: OOooOOo . I11i % OoOoOO00
 o0Iiii = { "type" : "database-mappings" , "database-mappings" : [ ] }
 if 68 - 68: iIii1I11I1II1 % I1ii11iIi11i % II111iiii / O0 + iII111i
 if 78 - 78: iII111i - OOooOOo / I1Ii111
 if 38 - 38: I11i % i1IIi + o0oOOo0O0Ooo + I1ii11iIi11i + I1IiiI
 if 1 - 1: II111iiii * o0oOOo0O0Ooo . O0 - Ii1I / oO0o
 for o0Oo00OOOo00 in lisp_db_list :
  if ( o0Oo00OOOo00 . eid . is_ipv4 ( ) == False and o0Oo00OOOo00 . eid . is_ipv6 ( ) == False ) : continue
  IiIiII1II1 = { "instance-id" : str ( o0Oo00OOOo00 . eid . instance_id ) ,
 "eid-prefix" : o0Oo00OOOo00 . eid . print_prefix_no_iid ( ) }
  o0Iiii [ "database-mappings" ] . append ( IiIiII1II1 )
  if 72 - 72: OoO0O00 + I11i / iII111i % OOooOOo
 lisp_write_to_dp_socket ( o0Iiii )
 if 5 - 5: oO0o % OOooOOo
 if 95 - 95: OoOoOO00 + OoooooooOO - O0 + o0oOOo0O0Ooo
 if 88 - 88: i11iIiiIii . iIii1I11I1II1
 if 57 - 57: Ii1I * iIii1I11I1II1
 if 92 - 92: Ii1I % Ii1I . I11i / i1IIi % Oo0Ooo
 o0Iiii = { "type" : "etr-nat-port" , "port" : ephem_port }
 lisp_write_to_dp_socket ( o0Iiii )
 return
 if 25 - 25: o0oOOo0O0Ooo - OoO0O00 - OoOoOO00 - ooOoO0o
 if 28 - 28: OOooOOo * ooOoO0o * OoooooooOO % IiII
 if 9 - 9: OoooooooOO
 if 92 - 92: I1Ii111 + O0 + OoO0O00 % IiII
 if 31 - 31: Ii1I / Oo0Ooo - I1IiiI - I11i - i11iIiiIii
 if 45 - 45: ooOoO0o - IiII / OoO0O00 / IiII
 if 63 - 63: ooOoO0o . i11iIiiIii + iII111i . OoO0O00 / ooOoO0o % iII111i
def lisp_write_ipc_interfaces ( ) :
 if ( lisp_i_am_etr ) : return
 if ( lisp_ipc_dp_socket == None ) : return
 if ( lisp_check_dp_socket ( ) == False ) : return
 if 23 - 23: iIii1I11I1II1 - ooOoO0o / I11i * I11i
 if 62 - 62: OOooOOo - I1IiiI * oO0o + O0 / ooOoO0o * iIii1I11I1II1
 if 25 - 25: I1Ii111 % Oo0Ooo + OoO0O00 % OOooOOo
 if 85 - 85: I1IiiI . i11iIiiIii - ooOoO0o * I11i * OoOoOO00 * I11i
 o0Iiii = { "type" : "interfaces" , "interfaces" : [ ] }
 if 29 - 29: I1Ii111 * I1Ii111 . iII111i + o0oOOo0O0Ooo
 for iIiiiIiIi in lisp_myinterfaces . values ( ) :
  if ( iIiiiIiIi . instance_id == None ) : continue
  IiIiII1II1 = { "interface" : iIiiiIiIi . device ,
 "instance-id" : str ( iIiiiIiIi . instance_id ) }
  o0Iiii [ "interfaces" ] . append ( IiIiII1II1 )
  if 57 - 57: I1Ii111 - IiII
  if 89 - 89: oO0o + iII111i
 lisp_write_to_dp_socket ( o0Iiii )
 return
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
 if 6 - 6: iII111i / iII111i . i11iIiiIii
 if 12 - 12: I11i - OoO0O00
 if 68 - 68: IiII - OoOoOO00
def lisp_parse_auth_key ( value ) :
 OOOo0O = value . split ( "[" )
 ii1i1iIi1Ii1I1 = { }
 if ( len ( OOOo0O ) == 1 ) :
  ii1i1iIi1Ii1I1 [ 0 ] = value
  return ( ii1i1iIi1Ii1I1 )
  if 100 - 100: I11i % i1IIi / OoooooooOO
  if 12 - 12: Ii1I . Ii1I
 for II1i1III in OOOo0O :
  if ( II1i1III == "" ) : continue
  OOOoO000 = II1i1III . find ( "]" )
  I1 = II1i1III [ 0 : OOOoO000 ]
  try : I1 = int ( I1 )
  except : return
  if 13 - 13: oO0o - i1IIi / i1IIi + OoooooooOO
  ii1i1iIi1Ii1I1 [ I1 ] = II1i1III [ OOOoO000 + 1 : : ]
  if 57 - 57: OoooooooOO / O0 + I1ii11iIi11i % I11i * oO0o / Ii1I
 return ( ii1i1iIi1Ii1I1 )
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
 if 41 - 41: II111iiii . o0oOOo0O0Ooo
 if 92 - 92: Ii1I - O0 - i11iIiiIii + IiII % I1Ii111 + II111iiii
 if 71 - 71: ooOoO0o * I1Ii111 + i11iIiiIii + i1IIi . I1IiiI
 if 15 - 15: OoO0O00
 if 37 - 37: OoO0O00 . OoooooooOO - OOooOOo
 if 34 - 34: o0oOOo0O0Ooo + iIii1I11I1II1 / o0oOOo0O0Ooo / ooOoO0o
def lisp_reassemble ( packet ) :
 O0OOo = socket . ntohs ( struct . unpack ( "H" , packet [ 6 : 8 ] ) [ 0 ] )
 if 53 - 53: II111iiii / iIii1I11I1II1
 if 25 - 25: I1Ii111
 if 58 - 58: OoOoOO00 * i1IIi
 if 20 - 20: IiII
 if ( O0OOo == 0 or O0OOo == 0x4000 ) : return ( packet )
 if 81 - 81: I1Ii111 . i1IIi / o0oOOo0O0Ooo
 if 30 - 30: i11iIiiIii . I1IiiI
 if 5 - 5: Ii1I / O0 + iIii1I11I1II1
 if 22 - 22: ooOoO0o . ooOoO0o * OOooOOo % OoOoOO00
 i1iIii = socket . ntohs ( struct . unpack ( "H" , packet [ 4 : 6 ] ) [ 0 ] )
 oOO = socket . ntohs ( struct . unpack ( "H" , packet [ 2 : 4 ] ) [ 0 ] )
 if 61 - 61: O0 % I11i % o0oOOo0O0Ooo
 iIIIOoOoo0oo0Oo = ( O0OOo & 0x2000 == 0 and ( O0OOo & 0x1fff ) != 0 )
 o0Iiii = [ ( O0OOo & 0x1fff ) * 8 , oOO - 20 , packet , iIIIOoOoo0oo0Oo ]
 if 49 - 49: O0 . i11iIiiIii / I11i + OOooOOo * OOooOOo + II111iiii
 if 55 - 55: I11i / I1ii11iIi11i . I1ii11iIi11i - Oo0Ooo
 if 4 - 4: I1IiiI
 if 40 - 40: Oo0Ooo % oO0o
 if 40 - 40: IiII * o0oOOo0O0Ooo . I1Ii111 - O0 % OoooooooOO + I1Ii111
 if 1 - 1: I1Ii111 % OoooooooOO + OoooooooOO - I1IiiI % I1IiiI
 if 51 - 51: iIii1I11I1II1 / I1IiiI
 if 27 - 27: O0 . o0oOOo0O0Ooo / ooOoO0o / OoooooooOO % Ii1I
 if ( O0OOo == 0x2000 ) :
  o0OO0OO000OO , O00o0000OO = struct . unpack ( "HH" , packet [ 20 : 24 ] )
  o0OO0OO000OO = socket . ntohs ( o0OO0OO000OO )
  O00o0000OO = socket . ntohs ( O00o0000OO )
  if ( O00o0000OO not in [ 4341 , 8472 , 4789 ] and o0OO0OO000OO != 4341 ) :
   lisp_reassembly_queue [ i1iIii ] = [ ]
   o0Iiii [ 2 ] = None
   if 27 - 27: ooOoO0o / IiII + OoO0O00 + Ii1I % I1Ii111
   if 86 - 86: O0 % i11iIiiIii - Ii1I * oO0o % OOooOOo * i1IIi
   if 87 - 87: II111iiii
   if 53 - 53: OoOoOO00 * i11iIiiIii / I1Ii111
   if 100 - 100: ooOoO0o + I1IiiI * oO0o + ooOoO0o
   if 24 - 24: i11iIiiIii + ooOoO0o
 if ( lisp_reassembly_queue . has_key ( i1iIii ) == False ) :
  lisp_reassembly_queue [ i1iIii ] = [ ]
  if 80 - 80: IiII % I11i % oO0o
  if 97 - 97: i1IIi * i11iIiiIii / Ii1I - I1IiiI % IiII
  if 70 - 70: iIii1I11I1II1
  if 2 - 2: IiII - i1IIi * IiII % O0 / Ii1I
  if 64 - 64: iII111i - Oo0Ooo
 oo00O0000o00 = lisp_reassembly_queue [ i1iIii ]
 if 56 - 56: O0 / OoooooooOO / OoOoOO00
 if 19 - 19: o0oOOo0O0Ooo / i11iIiiIii . i1IIi / Oo0Ooo / I1Ii111
 if 83 - 83: iII111i % o0oOOo0O0Ooo * OoOoOO00
 if 49 - 49: II111iiii / OoO0O00
 if 69 - 69: Ii1I * II111iiii
 if ( len ( oo00O0000o00 ) == 1 and oo00O0000o00 [ 0 ] [ 2 ] == None ) :
  dprint ( "Drop non-LISP encapsulated fragment 0x{}" . format ( lisp_hex_string ( i1iIii ) . zfill ( 4 ) ) )
  if 24 - 24: I1Ii111 * I1ii11iIi11i . OOooOOo . I1IiiI - I1ii11iIi11i
  return ( None )
  if 56 - 56: I1IiiI * Oo0Ooo + OoO0O00 - oO0o * I1Ii111
  if 68 - 68: ooOoO0o * i11iIiiIii * OOooOOo % iII111i
  if 10 - 10: Ii1I / Oo0Ooo - i1IIi
  if 11 - 11: I11i * iII111i
  if 28 - 28: II111iiii + IiII / Oo0Ooo * I1IiiI - OOooOOo
 oo00O0000o00 . append ( o0Iiii )
 oo00O0000o00 = sorted ( oo00O0000o00 )
 if 2 - 2: oO0o + I11i / I1Ii111 . I11i
 if 59 - 59: Ii1I
 if 47 - 47: iII111i % iII111i
 if 81 - 81: oO0o / I1ii11iIi11i . OoooooooOO % II111iiii / oO0o
 I1Iii1I = lisp_address ( LISP_AFI_IPV4 , "" , 32 , 0 )
 I1Iii1I . address = socket . ntohl ( struct . unpack ( "I" , packet [ 12 : 16 ] ) [ 0 ] )
 I1IIiI = I1Iii1I . print_address_no_iid ( )
 I1Iii1I . address = socket . ntohl ( struct . unpack ( "I" , packet [ 16 : 20 ] ) [ 0 ] )
 Iii1i1 = I1Iii1I . print_address_no_iid ( )
 I1Iii1I = red ( "{} -> {}" . format ( I1IIiI , Iii1i1 ) , False )
 if 74 - 74: OoO0O00 - O0 + I1IiiI + i11iIiiIii
 dprint ( "{}{} fragment, RLOCs: {}, packet 0x{}, frag-offset: 0x{}" . format ( bold ( "Received" , False ) , " non-LISP encapsulated" if o0Iiii [ 2 ] == None else "" , I1Iii1I , lisp_hex_string ( i1iIii ) . zfill ( 4 ) ,
 # iIii1I11I1II1 - iII111i - oO0o + Oo0Ooo . Ii1I / i11iIiiIii
 # ooOoO0o - I1Ii111
 lisp_hex_string ( O0OOo ) . zfill ( 4 ) ) )
 if 97 - 97: OOooOOo
 if 87 - 87: iII111i
 if 73 - 73: II111iiii
 if 2 - 2: i1IIi % iII111i . oO0o / II111iiii * I1IiiI
 if 17 - 17: O0 + iII111i + oO0o / iIii1I11I1II1 % oO0o
 if ( oo00O0000o00 [ 0 ] [ 0 ] != 0 or oo00O0000o00 [ - 1 ] [ 3 ] == False ) : return ( None )
 O00oooooOo0OO = oo00O0000o00 [ 0 ]
 for iiii1 in oo00O0000o00 [ 1 : : ] :
  O0OOo = iiii1 [ 0 ]
  o00oO0O0O0 , IiI1IIiIiI1I = O00oooooOo0OO [ 0 ] , O00oooooOo0OO [ 1 ]
  if ( o00oO0O0O0 + IiI1IIiIiI1I != O0OOo ) : return ( None )
  O00oooooOo0OO = iiii1
  if 78 - 78: oO0o - II111iiii . II111iiii * I1Ii111 % O0 - iII111i
 lisp_reassembly_queue . pop ( i1iIii )
 if 59 - 59: Oo0Ooo - IiII
 if 6 - 6: OOooOOo - I1IiiI . IiII
 if 40 - 40: II111iiii
 if 13 - 13: OoOoOO00
 if 23 - 23: Oo0Ooo / II111iiii % OOooOOo % iII111i - Oo0Ooo / OoO0O00
 packet = oo00O0000o00 [ 0 ] [ 2 ]
 for iiii1 in oo00O0000o00 [ 1 : : ] : packet += iiii1 [ 2 ] [ 20 : : ]
 if 7 - 7: Ii1I / I11i / II111iiii % I11i * I11i + iIii1I11I1II1
 dprint ( "{} fragments arrived for packet 0x{}, length {}" . format ( bold ( "All" , False ) , lisp_hex_string ( i1iIii ) . zfill ( 4 ) , len ( packet ) ) )
 if 6 - 6: iIii1I11I1II1 * oO0o - iIii1I11I1II1 . O0 . O0
 if 96 - 96: I1Ii111 * II111iiii % i11iIiiIii - oO0o
 if 32 - 32: i11iIiiIii * o0oOOo0O0Ooo . OoooooooOO / O0
 if 14 - 14: i11iIiiIii . I1Ii111 % I1ii11iIi11i . I1ii11iIi11i % IiII
 if 93 - 93: iIii1I11I1II1 / IiII
 I1I1 = socket . htons ( len ( packet ) )
 IIiiIiIIiI1 = packet [ 0 : 2 ] + struct . pack ( "H" , I1I1 ) + packet [ 4 : 6 ] + struct . pack ( "H" , 0 ) + packet [ 8 : 10 ] + struct . pack ( "H" , 0 ) + packet [ 12 : 20 ]
 if 91 - 91: i11iIiiIii % ooOoO0o - iII111i * I1Ii111 . i11iIiiIii
 if 1 - 1: IiII + iIii1I11I1II1 * I1ii11iIi11i - IiII - i1IIi
 IIiiIiIIiI1 = lisp_ip_checksum ( IIiiIiIIiI1 )
 return ( IIiiIiIIiI1 + packet [ 20 : : ] )
 if 75 - 75: II111iiii * o0oOOo0O0Ooo / I1ii11iIi11i
 if 46 - 46: OOooOOo
 if 67 - 67: OoO0O00 . I11i % OOooOOo + Oo0Ooo
 if 40 - 40: OoO0O00 / I11i % iIii1I11I1II1 - ooOoO0o
 if 51 - 51: Oo0Ooo % iIii1I11I1II1 % oO0o + o0oOOo0O0Ooo
 if 32 - 32: I1Ii111 * I1IiiI + Ii1I
 if 30 - 30: OoooooooOO / I1IiiI . iIii1I11I1II1 / ooOoO0o
 if 20 - 20: OoooooooOO * OOooOOo
def lisp_get_crypto_decap_lookup_key ( addr , port ) :
 OoOOoooO000 = addr . print_address_no_iid ( ) + ":" + str ( port )
 if ( lisp_crypto_keys_by_rloc_decap . has_key ( OoOOoooO000 ) ) : return ( OoOOoooO000 )
 if 77 - 77: Ii1I - OoooooooOO . OoOoOO00
 OoOOoooO000 = addr . print_address_no_iid ( )
 if ( lisp_crypto_keys_by_rloc_decap . has_key ( OoOOoooO000 ) ) : return ( OoOOoooO000 )
 if 93 - 93: OoooooooOO / I1Ii111
 if 91 - 91: I1Ii111
 if 18 - 18: ooOoO0o * I11i
 if 53 - 53: I11i . i11iIiiIii - iIii1I11I1II1 / I1Ii111
 if 86 - 86: i1IIi % OoO0O00 - OoooooooOO
 for OO0Ii1iii1iIIII in lisp_crypto_keys_by_rloc_decap :
  OOOO0o = OO0Ii1iii1iIIII . split ( ":" )
  if ( len ( OOOO0o ) == 1 ) : continue
  OOOO0o = OOOO0o [ 0 ] if len ( OOOO0o ) == 2 else ":" . join ( OOOO0o [ 0 : - 1 ] )
  if ( OOOO0o == OoOOoooO000 ) :
   II1i = lisp_crypto_keys_by_rloc_decap [ OO0Ii1iii1iIIII ]
   lisp_crypto_keys_by_rloc_decap [ OoOOoooO000 ] = II1i
   return ( OoOOoooO000 )
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
  for IiiiI11I1 in lisp_nat_state_info . values ( ) :
   for oOo0o0ooO0OOO in IiiiI11I1 :
    if ( addr == oOo0o0ooO0OOO . address ) : return ( o0oo000o )
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
 IIi1ii1 = ( struct . unpack ( "B" , packet [ 9 ] ) [ 0 ] == 17 )
 if ( IIi1ii1 == False ) : return ( [ packet , None , None , None ] )
 if 16 - 16: OoOoOO00 * I1Ii111 - I1IiiI / I1Ii111
 if ( rr == 0 ) :
  O00oOoo0OoOOO = lisp_is_rloc_probe_request ( packet [ 28 ] )
  if ( O00oOoo0OoOOO == False ) : return ( [ packet , None , None , None ] )
 elif ( rr == 1 ) :
  O00oOoo0OoOOO = lisp_is_rloc_probe_reply ( packet [ 28 ] )
  if ( O00oOoo0OoOOO == False ) : return ( [ packet , None , None , None ] )
 elif ( rr == - 1 ) :
  O00oOoo0OoOOO = lisp_is_rloc_probe_request ( packet [ 28 ] )
  if ( O00oOoo0OoOOO == False ) :
   O00oOoo0OoOOO = lisp_is_rloc_probe_reply ( packet [ 28 ] )
   if ( O00oOoo0OoOOO == False ) : return ( [ packet , None , None , None ] )
   if 64 - 64: I1ii11iIi11i . i1IIi % II111iiii % Oo0Ooo + oO0o - I1IiiI
   if 24 - 24: IiII . II111iiii . II111iiii . OoOoOO00 . i11iIiiIii
   if 11 - 11: Ii1I
   if 82 - 82: I11i - i1IIi . Oo0Ooo * I1Ii111
   if 44 - 44: iII111i
   if 56 - 56: II111iiii / Oo0Ooo % IiII * II111iiii - iIii1I11I1II1 + ooOoO0o
 IIi1IiIii = lisp_address ( LISP_AFI_IPV4 , "" , 32 , 0 )
 IIi1IiIii . address = socket . ntohl ( struct . unpack ( "I" , packet [ 12 : 16 ] ) [ 0 ] )
 if 33 - 33: o0oOOo0O0Ooo . I11i / I1IiiI
 if 29 - 29: o0oOOo0O0Ooo - ooOoO0o
 if 59 - 59: I11i / IiII * OoO0O00 / IiII . I1Ii111
 if 82 - 82: OOooOOo . iIii1I11I1II1 + I1Ii111
 if ( IIi1IiIii . is_local ( ) ) : return ( [ None , None , None , None ] )
 if 14 - 14: IiII . i11iIiiIii
 if 17 - 17: ooOoO0o % ooOoO0o * oO0o
 if 8 - 8: ooOoO0o + OoO0O00 . II111iiii / iIii1I11I1II1 - OOooOOo
 if 87 - 87: iIii1I11I1II1 . IiII % I1IiiI . OoO0O00 - I1Ii111
 IIi1IiIii = IIi1IiIii . print_address_no_iid ( )
 OOo0000o0 = socket . ntohs ( struct . unpack ( "H" , packet [ 20 : 22 ] ) [ 0 ] )
 iiI = struct . unpack ( "B" , packet [ 8 ] ) [ 0 ] - 1
 packet = packet [ 28 : : ]
 if 53 - 53: I1Ii111 % i11iIiiIii
 iIOoo000 = bold ( "Receive(pcap)" , False )
 Oo0OO0o0oOO0 = bold ( "from " + IIi1IiIii , False )
 o0O0o = lisp_format_packet ( packet )
 lprint ( "{} {} bytes {} {}, packet: {}" . format ( iIOoo000 , len ( packet ) , Oo0OO0o0oOO0 , OOo0000o0 , o0O0o ) )
 if 99 - 99: I1IiiI - i1IIi * i11iIiiIii + OoO0O00
 return ( [ packet , IIi1IiIii , OOo0000o0 , iiI ] )
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
def lisp_ipc_write_xtr_parameters ( cp , dp ) :
 if ( lisp_ipc_dp_socket == None ) : return
 if 7 - 7: OoOoOO00 - OoO0O00 % OoOoOO00 . I1ii11iIi11i % Oo0Ooo * iII111i
 Oooo000 = { "type" : "xtr-parameters" , "control-plane-logging" : cp ,
 "data-plane-logging" : dp , "rtr" : lisp_i_am_rtr }
 if 90 - 90: IiII - OOooOOo + iIii1I11I1II1
 lisp_write_to_dp_socket ( Oooo000 )
 return
 if 88 - 88: ooOoO0o . o0oOOo0O0Ooo . OOooOOo - I11i
 if 76 - 76: IiII % I1IiiI . iII111i
 if 5 - 5: ooOoO0o . oO0o - OoOoOO00 - OoooooooOO
 if 2 - 2: OOooOOo
 if 37 - 37: IiII - iIii1I11I1II1 * i11iIiiIii . ooOoO0o
 if 78 - 78: OOooOOo - I1ii11iIi11i + iII111i % OoOoOO00
 if 28 - 28: I11i + i1IIi / i11iIiiIii * OOooOOo * II111iiii
 if 78 - 78: OoO0O00 - i1IIi % I1Ii111
def lisp_external_data_plane ( ) :
 i1i1i1I = 'egrep "ipc-data-plane = yes" ./lisp.config'
 if ( commands . getoutput ( i1i1i1I ) != "" ) : return ( True )
 if 87 - 87: I11i
 if ( os . getenv ( "LISP_RUN_LISP_XTR" ) != None ) : return ( True )
 return ( False )
 if 37 - 37: iII111i . I1Ii111 - iII111i - I11i - iIii1I11I1II1 - II111iiii
 if 80 - 80: I1Ii111 % O0 - IiII / II111iiii + i1IIi
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
def lisp_process_data_plane_restart ( do_clear = False ) :
 os . system ( "touch ./lisp.config" )
 if 35 - 35: i11iIiiIii / o0oOOo0O0Ooo / oO0o / I11i . O0
 oO0oiII = { "type" : "entire-map-cache" , "entries" : [ ] }
 if 65 - 65: IiII % I1IiiI % ooOoO0o / oO0o
 if ( do_clear == False ) :
  O0Iii1I1IIIi1iI = oO0oiII [ "entries" ]
  lisp_map_cache . walk_cache ( lisp_ipc_walk_map_cache , O0Iii1I1IIIi1iI )
  if 48 - 48: II111iiii % OoO0O00 % o0oOOo0O0Ooo * O0 - O0 / ooOoO0o
  if 60 - 60: ooOoO0o / I1ii11iIi11i * i1IIi - IiII . II111iiii
 lisp_write_to_dp_socket ( oO0oiII )
 return
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
def lisp_process_data_plane_stats ( msg , lisp_sockets , lisp_port ) :
 if ( msg . has_key ( "entries" ) == False ) :
  lprint ( "No 'entries' in stats IPC message" )
  return
  if 73 - 73: OoOoOO00 + OOooOOo * II111iiii . OOooOOo % I1Ii111 % oO0o
 if ( type ( msg [ "entries" ] ) != list ) :
  lprint ( "'entries' in stats IPC message must be an array" )
  return
  if 79 - 79: I1ii11iIi11i % I11i
  if 78 - 78: i11iIiiIii % I1Ii111 + iIii1I11I1II1 + iII111i
 for msg in msg [ "entries" ] :
  if ( msg . has_key ( "eid-prefix" ) == False ) :
   lprint ( "No 'eid-prefix' in stats IPC message" )
   continue
   if 66 - 66: I1IiiI - o0oOOo0O0Ooo
  oo0ooooO = msg [ "eid-prefix" ]
  if 67 - 67: oO0o . iII111i * Ii1I - OOooOOo / oO0o
  if ( msg . has_key ( "instance-id" ) == False ) :
   lprint ( "No 'instance-id' in stats IPC message" )
   continue
   if 98 - 98: OoOoOO00 * OoO0O00 . Oo0Ooo
  IIiI1i = int ( msg [ "instance-id" ] )
  if 6 - 6: I11i % iIii1I11I1II1 + I1Ii111
  if 48 - 48: II111iiii . OOooOOo . ooOoO0o - iII111i
  if 90 - 90: OOooOOo
  if 43 - 43: IiII + ooOoO0o
  i1OO0o = lisp_address ( LISP_AFI_NONE , "" , 0 , IIiI1i )
  i1OO0o . store_prefix ( oo0ooooO )
  Iii1 = lisp_map_cache_lookup ( None , i1OO0o )
  if ( Iii1 == None ) :
   lprint ( "Map-cache entry for {} not found for stats update" . format ( oo0ooooO ) )
   if 4 - 4: i1IIi
   continue
   if 89 - 89: Oo0Ooo / iIii1I11I1II1 . OoOoOO00
   if 6 - 6: Ii1I / iII111i
  if ( msg . has_key ( "rlocs" ) == False ) :
   lprint ( "No 'rlocs' in stats IPC message for {}" . format ( oo0ooooO ) )
   if 69 - 69: iIii1I11I1II1 % I1Ii111 % OOooOOo + O0 - OoOoOO00 % oO0o
   continue
   if 70 - 70: oO0o - I1IiiI + Ii1I
  if ( type ( msg [ "rlocs" ] ) != list ) :
   lprint ( "'rlocs' in stats IPC message must be an array" )
   continue
   if 54 - 54: OoOoOO00 / ooOoO0o - I1IiiI
  iIIi1iiI = msg [ "rlocs" ]
  if 21 - 21: OoooooooOO % IiII / I11i . I11i . I11i + I11i
  if 75 - 75: ooOoO0o / i1IIi
  if 28 - 28: OoO0O00 / I1Ii111
  if 51 - 51: i1IIi - oO0o / I11i + Ii1I + ooOoO0o
  for iIIOO0OO in iIIi1iiI :
   if ( iIIOO0OO . has_key ( "rloc" ) == False ) : continue
   if 67 - 67: OoO0O00 . II111iiii * O0
   I111I = iIIOO0OO [ "rloc" ]
   if ( I111I == "no-address" ) : continue
   if 1 - 1: o0oOOo0O0Ooo + Oo0Ooo
   i1IIIIi1Ii111 = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
   i1IIIIi1Ii111 . store_address ( I111I )
   if 20 - 20: O0
   ii1I1i11 = Iii1 . get_rloc ( i1IIIIi1Ii111 )
   if ( ii1I1i11 == None ) : continue
   if 77 - 77: I1ii11iIi11i + OoooooooOO * OoO0O00 * iIii1I11I1II1 % I1Ii111
   if 22 - 22: i1IIi
   if 61 - 61: IiII
   if 3 - 3: ooOoO0o . Oo0Ooo . ooOoO0o / OoO0O00 / o0oOOo0O0Ooo . I1Ii111
   i1Iii1i = 0 if iIIOO0OO . has_key ( "packet-count" ) == False else iIIOO0OO [ "packet-count" ]
   if 18 - 18: OOooOOo * O0 % ooOoO0o - ooOoO0o
   I1i = 0 if iIIOO0OO . has_key ( "byte-count" ) == False else iIIOO0OO [ "byte-count" ]
   if 46 - 46: o0oOOo0O0Ooo * oO0o / oO0o . oO0o + I11i * OOooOOo
   III11I1 = 0 if iIIOO0OO . has_key ( "seconds-last-packet" ) == False else iIIOO0OO [ "seconds-last-packet" ]
   if 48 - 48: iII111i + Ii1I
   if 10 - 10: I1IiiI + o0oOOo0O0Ooo
   ii1I1i11 . stats . packet_count += i1Iii1i
   ii1I1i11 . stats . byte_count += I1i
   ii1I1i11 . stats . last_increment = lisp_get_timestamp ( ) - III11I1
   if 75 - 75: Oo0Ooo
   lprint ( "Update stats {}/{}/{}s for {} RLOC {}" . format ( i1Iii1i , I1i ,
 III11I1 , oo0ooooO , I111I ) )
   if 100 - 100: i1IIi / Oo0Ooo / II111iiii + iII111i . II111iiii * oO0o
   if 36 - 36: Oo0Ooo + iII111i / OOooOOo + OOooOOo % i11iIiiIii / I1IiiI
   if 59 - 59: ooOoO0o / I11i
   if 32 - 32: iIii1I11I1II1 % oO0o / I1Ii111
   if 42 - 42: I11i / I1ii11iIi11i - I1IiiI * iII111i / I1IiiI / i11iIiiIii
  if ( Iii1 . group . is_null ( ) and Iii1 . has_ttl_elapsed ( ) ) :
   oo0ooooO = green ( Iii1 . print_eid_tuple ( ) , False )
   lprint ( "Refresh map-cache entry {}" . format ( oo0ooooO ) )
   lisp_send_map_request ( lisp_sockets , lisp_port , None , Iii1 . eid , None )
   if 75 - 75: Oo0Ooo + IiII / I11i % I11i % IiII / I1Ii111
   if 95 - 95: OoOoOO00
 return
 if 78 - 78: I11i
 if 62 - 62: iIii1I11I1II1 . o0oOOo0O0Ooo . ooOoO0o % oO0o % O0 % oO0o
 if 51 - 51: Oo0Ooo / IiII - Oo0Ooo
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
 if 20 - 20: I1IiiI + iII111i + O0 * O0
 if 18 - 18: I11i - I11i . OoOoOO00 . ooOoO0o
 if 31 - 31: ooOoO0o
def lisp_process_data_plane_decap_stats ( msg , lisp_ipc_socket ) :
 if 87 - 87: OoooooooOO + OOooOOo - I1ii11iIi11i / I1IiiI + ooOoO0o - Oo0Ooo
 if 19 - 19: ooOoO0o + I1ii11iIi11i - ooOoO0o
 if 17 - 17: I11i * i1IIi + iIii1I11I1II1 % I1IiiI
 if 44 - 44: IiII + I1IiiI . Ii1I % Oo0Ooo
 if 97 - 97: O0
 if ( lisp_i_am_itr ) :
  lprint ( "Send decap-stats IPC message to lisp-etr process" )
  Oooo000 = "stats%{}" . format ( json . dumps ( msg ) )
  Oooo000 = lisp_command_ipc ( Oooo000 , "lisp-itr" )
  lisp_ipc ( Oooo000 , lisp_ipc_socket , "lisp-etr" )
  return
  if 95 - 95: OoO0O00 % iII111i / I1IiiI * OoooooooOO
  if 31 - 31: iIii1I11I1II1
  if 62 - 62: o0oOOo0O0Ooo - iII111i / II111iiii . o0oOOo0O0Ooo
  if 20 - 20: iIii1I11I1II1 % OOooOOo
  if 91 - 91: ooOoO0o
  if 96 - 96: I1IiiI . OOooOOo
  if 94 - 94: OoooooooOO + II111iiii % ooOoO0o - II111iiii / O0
  if 34 - 34: IiII % oO0o
 Oooo000 = bold ( "IPC" , False )
 lprint ( "Process decap-stats {} message: '{}'" . format ( Oooo000 , msg ) )
 if 54 - 54: I1IiiI
 if ( lisp_i_am_etr ) : msg = json . loads ( msg )
 if 80 - 80: OoOoOO00 . I1IiiI / I1ii11iIi11i . iII111i
 i1Iii11iiiII1 = [ "good-packets" , "ICV-error" , "checksum-error" ,
 "lisp-header-error" , "no-decrypt-key" , "bad-inner-version" ,
 "outer-header-error" ]
 if 78 - 78: i11iIiiIii . o0oOOo0O0Ooo
 for OOOo0oOOOO0 in i1Iii11iiiII1 :
  i1Iii1i = 0 if msg . has_key ( OOOo0oOOOO0 ) == False else msg [ OOOo0oOOOO0 ] [ "packet-count" ]
  if 23 - 23: I1IiiI - O0 - iII111i . II111iiii / oO0o
  lisp_decap_stats [ OOOo0oOOOO0 ] . packet_count += i1Iii1i
  if 1 - 1: I11i . OOooOOo / oO0o % I11i * Oo0Ooo + Oo0Ooo
  I1i = 0 if msg . has_key ( OOOo0oOOOO0 ) == False else msg [ OOOo0oOOOO0 ] [ "byte-count" ]
  if 23 - 23: Ii1I % i1IIi - I1Ii111
  lisp_decap_stats [ OOOo0oOOOO0 ] . byte_count += I1i
  if 95 - 95: OoOoOO00 - ooOoO0o . i1IIi . OoooooooOO
  III11I1 = 0 if msg . has_key ( OOOo0oOOOO0 ) == False else msg [ OOOo0oOOOO0 ] [ "seconds-last-packet" ]
  if 38 - 38: I1IiiI + I1ii11iIi11i - Oo0Ooo . i11iIiiIii - i1IIi
  lisp_decap_stats [ OOOo0oOOOO0 ] . last_increment = lisp_get_timestamp ( ) - III11I1
  if 11 - 11: IiII / I1IiiI . I1IiiI
 return
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
def lisp_process_punt ( punt_socket , lisp_send_sockets , lisp_ephem_port ) :
 I1I , IIi1IiIii = punt_socket . recvfrom ( 4000 )
 if 40 - 40: OOooOOo - i11iIiiIii - I11i . i1IIi * o0oOOo0O0Ooo
 iIiiIIiII1iII11 = json . loads ( I1I )
 if ( type ( iIiiIIiII1iII11 ) != dict ) :
  lprint ( "Invalid punt message from {}, not in JSON format" . format ( IIi1IiIii ) )
  if 2 - 2: I1ii11iIi11i * IiII
  return
  if 64 - 64: OoooooooOO % OoooooooOO
 III111ii1ii = bold ( "Punt" , False )
 lprint ( "{} message from '{}': '{}'" . format ( III111ii1ii , IIi1IiIii , iIiiIIiII1iII11 ) )
 if 16 - 16: OOooOOo - iII111i
 if ( iIiiIIiII1iII11 . has_key ( "type" ) == False ) :
  lprint ( "Punt IPC message has no 'type' key" )
  return
  if 5 - 5: o0oOOo0O0Ooo % ooOoO0o % O0 % I1ii11iIi11i + Oo0Ooo
  if 82 - 82: oO0o / iIii1I11I1II1 % ooOoO0o . Ii1I / i1IIi - I1Ii111
  if 15 - 15: I11i - OOooOOo . II111iiii . iIii1I11I1II1
  if 93 - 93: I11i + o0oOOo0O0Ooo / OOooOOo + Ii1I % Oo0Ooo % I1ii11iIi11i
  if 72 - 72: IiII / II111iiii
 if ( iIiiIIiII1iII11 [ "type" ] == "statistics" ) :
  lisp_process_data_plane_stats ( iIiiIIiII1iII11 , lisp_send_sockets , lisp_ephem_port )
  return
  if 25 - 25: i1IIi + OoOoOO00 + oO0o + OoooooooOO
 if ( iIiiIIiII1iII11 [ "type" ] == "decap-statistics" ) :
  lisp_process_data_plane_decap_stats ( iIiiIIiII1iII11 , punt_socket )
  return
  if 21 - 21: I1ii11iIi11i
  if 60 - 60: i1IIi / OoO0O00 . Ii1I
  if 16 - 16: i11iIiiIii + OoOoOO00 % Oo0Ooo + I1ii11iIi11i * Ii1I / I1Ii111
  if 26 - 26: iII111i
  if 31 - 31: iII111i
 if ( iIiiIIiII1iII11 [ "type" ] == "restart" ) :
  lisp_process_data_plane_restart ( )
  return
  if 45 - 45: OoO0O00
  if 55 - 55: iIii1I11I1II1 % iIii1I11I1II1 + I11i - ooOoO0o + I1IiiI * O0
  if 47 - 47: ooOoO0o + iIii1I11I1II1 * OOooOOo . I1IiiI . o0oOOo0O0Ooo
  if 49 - 49: Oo0Ooo . OoOoOO00 * OOooOOo
  if 86 - 86: IiII * OOooOOo + Ii1I
 if ( iIiiIIiII1iII11 [ "type" ] != "discovery" ) :
  lprint ( "Punt IPC message has wrong format" )
  return
  if 62 - 62: I11i
 if ( iIiiIIiII1iII11 . has_key ( "interface" ) == False ) :
  lprint ( "Invalid punt message from {}, required keys missing" . format ( IIi1IiIii ) )
  if 86 - 86: Oo0Ooo % II111iiii + I1Ii111 / I1ii11iIi11i
  return
  if 15 - 15: I1IiiI / I1Ii111 % iII111i
  if 57 - 57: I1Ii111 . iIii1I11I1II1 / Oo0Ooo / IiII / iII111i * OoOoOO00
  if 35 - 35: i1IIi + I1Ii111 - ooOoO0o . I1ii11iIi11i + Oo0Ooo
  if 43 - 43: oO0o . OoO0O00 * i1IIi
  if 1 - 1: ooOoO0o / i1IIi
 Ooooo = iIiiIIiII1iII11 [ "interface" ]
 if ( Ooooo == "" ) :
  IIiI1i = int ( iIiiIIiII1iII11 [ "instance-id" ] )
  if ( IIiI1i == - 1 ) : return
 else :
  IIiI1i = lisp_get_interface_instance_id ( Ooooo , None )
  if 42 - 42: I1ii11iIi11i * ooOoO0o + OoOoOO00 % I1ii11iIi11i . IiII
  if 75 - 75: OoO0O00 * i1IIi - OOooOOo % II111iiii % OoO0O00 - OoOoOO00
  if 75 - 75: I11i * IiII * ooOoO0o
  if 31 - 31: Ii1I
  if 72 - 72: OOooOOo * Ii1I % OoO0O00
 I1IIiiII = None
 if ( iIiiIIiII1iII11 . has_key ( "source-eid" ) ) :
  oOo000O00O = iIiiIIiII1iII11 [ "source-eid" ]
  I1IIiiII = lisp_address ( LISP_AFI_NONE , oOo000O00O , 0 , IIiI1i )
  if ( I1IIiiII . is_null ( ) ) :
   lprint ( "Invalid source-EID format '{}'" . format ( oOo000O00O ) )
   return
   if 72 - 72: OoOoOO00 + o0oOOo0O0Ooo - i1IIi - OoO0O00 % OoOoOO00
   if 42 - 42: oO0o / i1IIi . IiII
 o0000OO = None
 if ( iIiiIIiII1iII11 . has_key ( "dest-eid" ) ) :
  iiOoo0o00o0ooO = iIiiIIiII1iII11 [ "dest-eid" ]
  o0000OO = lisp_address ( LISP_AFI_NONE , iiOoo0o00o0ooO , 0 , IIiI1i )
  if ( o0000OO . is_null ( ) ) :
   lprint ( "Invalid dest-EID format '{}'" . format ( iiOoo0o00o0ooO ) )
   return
   if 88 - 88: OoooooooOO . I1IiiI
   if 6 - 6: I1Ii111 - i11iIiiIii - oO0o
   if 7 - 7: i1IIi
   if 6 - 6: OoooooooOO - Oo0Ooo - I1ii11iIi11i
   if 34 - 34: iII111i + i11iIiiIii . IiII
   if 54 - 54: Oo0Ooo + I11i - iII111i * ooOoO0o % i11iIiiIii . IiII
   if 29 - 29: II111iiii % i11iIiiIii % O0
   if 38 - 38: o0oOOo0O0Ooo * IiII
 if ( I1IIiiII ) :
  I1i11II = green ( I1IIiiII . print_address ( ) , False )
  o0Oo00OOOo00 = lisp_db_for_lookups . lookup_cache ( I1IIiiII , False )
  if ( o0Oo00OOOo00 != None ) :
   if 51 - 51: OoooooooOO . Ii1I % OoooooooOO - I1IiiI + I1Ii111 % oO0o
   if 28 - 28: i11iIiiIii - I1IiiI * OoO0O00
   if 19 - 19: OoooooooOO
   if 34 - 34: OoOoOO00 . oO0o
   if 53 - 53: oO0o + OoooooooOO * ooOoO0o
   if ( o0Oo00OOOo00 . dynamic_eid_configured ( ) ) :
    iIiiiIiIi = lisp_allow_dynamic_eid ( Ooooo , I1IIiiII )
    if ( iIiiiIiIi != None and lisp_i_am_itr ) :
     lisp_itr_discover_eid ( o0Oo00OOOo00 , I1IIiiII , Ooooo , iIiiiIiIi )
    else :
     lprint ( ( "Disallow dynamic source-EID {} " + "on interface {}" ) . format ( I1i11II , Ooooo ) )
     if 85 - 85: I1ii11iIi11i - o0oOOo0O0Ooo % o0oOOo0O0Ooo % iII111i * OoOoOO00
     if 50 - 50: I1Ii111 + I1Ii111 + I11i - OoOoOO00
     if 65 - 65: oO0o / I11i + iII111i - I1ii11iIi11i
  else :
   lprint ( "Punt from non-EID source {}" . format ( I1i11II ) )
   if 80 - 80: II111iiii . i11iIiiIii
   if 66 - 66: ooOoO0o * iII111i * OOooOOo % OoO0O00 / I1ii11iIi11i
   if 33 - 33: iIii1I11I1II1
   if 52 - 52: iIii1I11I1II1 + O0
   if 84 - 84: OOooOOo / iII111i . I1IiiI / O0 % OOooOOo . iII111i
   if 32 - 32: OoO0O00 + OoO0O00 % o0oOOo0O0Ooo / O0
 if ( o0000OO ) :
  Iii1 = lisp_map_cache_lookup ( I1IIiiII , o0000OO )
  if ( Iii1 == None or Iii1 . action == LISP_SEND_MAP_REQUEST_ACTION ) :
   if 29 - 29: iII111i % I1Ii111
   if 95 - 95: OOooOOo - ooOoO0o % i1IIi / O0 % I11i . IiII
   if 63 - 63: ooOoO0o
   if 22 - 22: OOooOOo . i11iIiiIii + II111iiii - Oo0Ooo % i1IIi / o0oOOo0O0Ooo
   if 90 - 90: IiII
   if ( lisp_rate_limit_map_request ( I1IIiiII , o0000OO ) ) : return
   lisp_send_map_request ( lisp_send_sockets , lisp_ephem_port ,
 I1IIiiII , o0000OO , None )
  else :
   I1i11II = green ( o0000OO . print_address ( ) , False )
   lprint ( "Map-cache entry for {} already exists" . format ( I1i11II ) )
   if 38 - 38: i1IIi / ooOoO0o / I11i * I1ii11iIi11i / II111iiii . iIii1I11I1II1
   if 52 - 52: I1ii11iIi11i % ooOoO0o * Ii1I * IiII + IiII / i11iIiiIii
 return
 if 51 - 51: iIii1I11I1II1 * o0oOOo0O0Ooo % o0oOOo0O0Ooo . Ii1I / OoooooooOO
 if 23 - 23: oO0o * I1IiiI - oO0o - ooOoO0o . IiII / i11iIiiIii
 if 53 - 53: Ii1I * Ii1I . OoOoOO00 . OOooOOo / I1ii11iIi11i % O0
 if 98 - 98: OOooOOo
 if 11 - 11: OOooOOo * iIii1I11I1II1 % IiII - I1IiiI . I11i
 if 29 - 29: OOooOOo % I11i - OOooOOo - OOooOOo * I11i . oO0o
 if 75 - 75: II111iiii . O0 . I1Ii111 * O0 / OoooooooOO
def lisp_ipc_map_cache_entry ( mc , jdata ) :
 o0Iiii = lisp_write_ipc_map_cache ( True , mc , dont_send = True )
 jdata . append ( o0Iiii )
 return ( [ True , jdata ] )
 if 60 - 60: OOooOOo - Oo0Ooo * OOooOOo / OoO0O00
 if 55 - 55: I1ii11iIi11i * II111iiii * iIii1I11I1II1
 if 38 - 38: iIii1I11I1II1 % I1ii11iIi11i . Ii1I + I1IiiI % i11iIiiIii - i11iIiiIii
 if 62 - 62: I1Ii111 + I1IiiI
 if 9 - 9: iIii1I11I1II1 / iIii1I11I1II1
 if 24 - 24: OOooOOo . I1IiiI % i11iIiiIii
 if 43 - 43: OoooooooOO . o0oOOo0O0Ooo - I1ii11iIi11i + OoO0O00 . I1Ii111 . iII111i
 if 1 - 1: iII111i / OoO0O00 / OoOoOO00 * Oo0Ooo * OoooooooOO
def lisp_ipc_walk_map_cache ( mc , jdata ) :
 if 59 - 59: iII111i
 if 14 - 14: oO0o . IiII + iIii1I11I1II1 - i1IIi
 if 46 - 46: i11iIiiIii * II111iiii / i11iIiiIii % i11iIiiIii * II111iiii + i11iIiiIii
 if 87 - 87: Oo0Ooo + OoO0O00 / II111iiii * OoooooooOO
 if ( mc . group . is_null ( ) ) : return ( lisp_ipc_map_cache_entry ( mc , jdata ) )
 if 95 - 95: I1Ii111 * o0oOOo0O0Ooo + OoO0O00 % OoOoOO00 - ooOoO0o / OoOoOO00
 if ( mc . source_cache == None ) : return ( [ True , jdata ] )
 if 45 - 45: OoooooooOO / oO0o / o0oOOo0O0Ooo + Ii1I + O0 . iII111i
 if 34 - 34: iIii1I11I1II1 . o0oOOo0O0Ooo + ooOoO0o
 if 96 - 96: O0 / ooOoO0o
 if 82 - 82: OoO0O00 * OOooOOo * I11i * I1Ii111 % iIii1I11I1II1
 if 50 - 50: Ii1I * Ii1I % I11i / iIii1I11I1II1 / ooOoO0o / iII111i
 jdata = mc . source_cache . walk_cache ( lisp_ipc_map_cache_entry , jdata )
 return ( [ True , jdata ] )
 if 91 - 91: Ii1I - O0 . I11i - OoooooooOO * IiII . II111iiii
 if 38 - 38: I1IiiI + OoO0O00
 if 11 - 11: iIii1I11I1II1 + i1IIi * IiII - Oo0Ooo
 if 66 - 66: I1Ii111 . Ii1I / I1ii11iIi11i / iIii1I11I1II1 + O0 / i1IIi
 if 72 - 72: ooOoO0o . II111iiii
 if 32 - 32: I1Ii111 - oO0o + OoooooooOO . OoOoOO00 + i11iIiiIii / i1IIi
 if 26 - 26: I1IiiI + OoooooooOO % OoOoOO00 . IiII - II111iiii . OoOoOO00
def lisp_itr_discover_eid ( db , eid , input_interface , routed_interface ,
 lisp_ipc_listen_socket ) :
 oo0ooooO = eid . print_address ( )
 if ( db . dynamic_eids . has_key ( oo0ooooO ) ) :
  db . dynamic_eids [ oo0ooooO ] . last_packet = lisp_get_timestamp ( )
  return
  if 37 - 37: OoO0O00 % O0 + OoOoOO00 * I11i . Ii1I * OoO0O00
  if 18 - 18: o0oOOo0O0Ooo / OOooOOo
  if 28 - 28: O0 / Ii1I - oO0o % I1ii11iIi11i % O0 . OoO0O00
  if 100 - 100: O0
  if 19 - 19: Ii1I * iIii1I11I1II1 * Oo0Ooo - i11iIiiIii * i11iIiiIii - OOooOOo
 oOiiI1i11I = lisp_dynamic_eid ( )
 oOiiI1i11I . dynamic_eid . copy_address ( eid )
 oOiiI1i11I . interface = routed_interface
 oOiiI1i11I . last_packet = lisp_get_timestamp ( )
 oOiiI1i11I . get_timeout ( routed_interface )
 db . dynamic_eids [ oo0ooooO ] = oOiiI1i11I
 if 88 - 88: O0 . iIii1I11I1II1 . I1ii11iIi11i
 oO0oo = ""
 if ( input_interface != routed_interface ) :
  oO0oo = ", routed-interface " + routed_interface
  if 38 - 38: Ii1I
  if 20 - 20: iIii1I11I1II1 + Oo0Ooo - Ii1I / i11iIiiIii . OoO0O00
 Ooo0o0OoO = green ( oo0ooooO , False ) + bold ( " discovered" , False )
 lprint ( "Dynamic-EID {} on interface {}{}, timeout {}" . format ( Ooo0o0OoO , input_interface , oO0oo , oOiiI1i11I . timeout ) )
 if 56 - 56: I1ii11iIi11i + I1Ii111 - OoO0O00 . I1ii11iIi11i * O0 - I11i
 if 58 - 58: oO0o - iIii1I11I1II1 * i11iIiiIii / i11iIiiIii % I11i
 if 69 - 69: iII111i * i1IIi
 if 100 - 100: Oo0Ooo + Oo0Ooo - II111iiii
 if 4 - 4: iII111i / OoO0O00 . i11iIiiIii * II111iiii - Ii1I * IiII
 Oooo000 = "learn%{}%{}" . format ( oo0ooooO , routed_interface )
 Oooo000 = lisp_command_ipc ( Oooo000 , "lisp-itr" )
 lisp_ipc ( Oooo000 , lisp_ipc_listen_socket , "lisp-etr" )
 return
 if 45 - 45: OoO0O00
 if 15 - 15: iII111i * o0oOOo0O0Ooo * Ii1I % IiII
 if 31 - 31: ooOoO0o . IiII + I1ii11iIi11i * II111iiii * iII111i + Oo0Ooo
 if 35 - 35: oO0o + I1ii11iIi11i / o0oOOo0O0Ooo
 if 78 - 78: i11iIiiIii
 if 21 - 21: iII111i / ooOoO0o - i11iIiiIii % iII111i
 if 94 - 94: OoooooooOO / iII111i * ooOoO0o / i1IIi * i11iIiiIii * II111iiii
 if 98 - 98: Ii1I * Ii1I / IiII
 if 1 - 1: OOooOOo
 if 47 - 47: i11iIiiIii - I11i
 if 38 - 38: Oo0Ooo % OoooooooOO + iII111i
 if 31 - 31: OoO0O00 + I1Ii111 / iIii1I11I1II1
 if 11 - 11: ooOoO0o - OoOoOO00
def lisp_retry_decap_keys ( addr_str , packet , iv , packet_icv ) :
 if ( lisp_search_decap_keys == False ) : return
 if 19 - 19: O0 . OoOoOO00 - i1IIi . oO0o
 if 96 - 96: o0oOOo0O0Ooo % o0oOOo0O0Ooo - OoO0O00 * iIii1I11I1II1 + ooOoO0o - ooOoO0o
 if 4 - 4: OoO0O00 - OOooOOo
 if 21 - 21: I1Ii111 * i11iIiiIii
 if ( addr_str . find ( ":" ) != - 1 ) : return
 if 63 - 63: oO0o + OoOoOO00
 iiiIIIII1iIi = lisp_crypto_keys_by_rloc_decap [ addr_str ]
 if 50 - 50: o0oOOo0O0Ooo / Oo0Ooo * ooOoO0o * Ii1I
 for i1IIiI1iII in lisp_crypto_keys_by_rloc_decap :
  if 97 - 97: I1IiiI / oO0o + I1Ii111 + I1Ii111
  if 86 - 86: o0oOOo0O0Ooo % ooOoO0o + OoOoOO00 * ooOoO0o
  if 20 - 20: Ii1I * iII111i / ooOoO0o
  if 18 - 18: Oo0Ooo * Ii1I / i11iIiiIii . OoO0O00 + OoooooooOO
  if ( i1IIiI1iII . find ( addr_str ) == - 1 ) : continue
  if 23 - 23: I1IiiI - I1ii11iIi11i . O0 . OoOoOO00 . OoO0O00
  if 81 - 81: IiII * I11i - iIii1I11I1II1
  if 41 - 41: oO0o * I11i + I1IiiI - OoO0O00
  if 63 - 63: Oo0Ooo * Ii1I - Ii1I
  if ( i1IIiI1iII == addr_str ) : continue
  if 76 - 76: OoO0O00 . IiII % iIii1I11I1II1 / I1IiiI + iIii1I11I1II1 . I1IiiI
  if 57 - 57: IiII - i1IIi * ooOoO0o
  if 5 - 5: oO0o . O0 * IiII / Ii1I + OoO0O00
  if 75 - 75: OOooOOo * OoOoOO00
  o0Iiii = lisp_crypto_keys_by_rloc_decap [ i1IIiI1iII ]
  if ( o0Iiii == iiiIIIII1iIi ) : continue
  if 82 - 82: Ii1I
  if 83 - 83: I1IiiI
  if 22 - 22: IiII / Ii1I + I1Ii111 % iIii1I11I1II1
  if 75 - 75: OoOoOO00 % OoOoOO00 % o0oOOo0O0Ooo % I1ii11iIi11i + IiII
  i1iiiI1i = o0Iiii [ 1 ]
  if ( packet_icv != i1iiiI1i . do_icv ( packet , iv ) ) :
   lprint ( "Test ICV with key {} failed" . format ( red ( i1IIiI1iII , False ) ) )
   continue
   if 48 - 48: OoooooooOO + OoO0O00 % i11iIiiIii * OoooooooOO
   if 64 - 64: I1ii11iIi11i . I1Ii111
  lprint ( "Changing decap crypto key to {}" . format ( red ( i1IIiI1iII , False ) ) )
  lisp_crypto_keys_by_rloc_decap [ addr_str ] = o0Iiii
  if 81 - 81: IiII . ooOoO0o + O0 . ooOoO0o + iIii1I11I1II1
 return
 if 68 - 68: i11iIiiIii . iII111i + OoooooooOO + II111iiii + iIii1I11I1II1 % I11i
 if 7 - 7: i1IIi - o0oOOo0O0Ooo - I1IiiI
 if 62 - 62: OoOoOO00 * oO0o - I1IiiI / Ii1I
 if 48 - 48: o0oOOo0O0Ooo % o0oOOo0O0Ooo - OoOoOO00
 if 13 - 13: OoO0O00 - Ii1I . ooOoO0o / O0 * OoOoOO00
 if 57 - 57: O0 + OoooooooOO % o0oOOo0O0Ooo / I1Ii111 / OOooOOo - OoOoOO00
 if 48 - 48: o0oOOo0O0Ooo - II111iiii + OoOoOO00
 if 54 - 54: II111iiii - OoO0O00 - o0oOOo0O0Ooo - O0 % I1Ii111
def lisp_decent_pull_xtr_configured ( ) :
 return ( lisp_decent_modulus != 0 and lisp_decent_dns_suffix != None )
 if 9 - 9: i1IIi % iII111i / Ii1I
 if 83 - 83: oO0o
 if 1 - 1: oO0o * iIii1I11I1II1 % iIii1I11I1II1 % iIii1I11I1II1 / oO0o + IiII
 if 29 - 29: OoooooooOO
 if 55 - 55: O0 - o0oOOo0O0Ooo % I1ii11iIi11i * I11i * oO0o
 if 83 - 83: iIii1I11I1II1
 if 92 - 92: OoO0O00 - iII111i
 if 97 - 97: ooOoO0o / I11i . IiII + I1Ii111 . iIii1I11I1II1
def lisp_is_decent_dns_suffix ( dns_name ) :
 if ( lisp_decent_dns_suffix == None ) : return ( False )
 iI11i1Ii = dns_name . split ( "." )
 iI11i1Ii = "." . join ( iI11i1Ii [ 1 : : ] )
 return ( iI11i1Ii == lisp_decent_dns_suffix )
 if 24 - 24: ooOoO0o - oO0o % OoOoOO00 * Oo0Ooo
 if 54 - 54: Ii1I - OoooooooOO % I1IiiI + oO0o
 if 70 - 70: I1Ii111 % iIii1I11I1II1
 if 74 - 74: i1IIi % i11iIiiIii + oO0o
 if 94 - 94: OoO0O00 * I1IiiI / O0 + I1Ii111 / i11iIiiIii
 if 34 - 34: Oo0Ooo . i1IIi
 if 97 - 97: I11i
def lisp_get_decent_index ( eid ) :
 oo0ooooO = eid . print_prefix ( )
 o0oOOoo0OO0 = hashlib . sha256 ( oo0ooooO ) . hexdigest ( )
 OOOoO000 = int ( o0oOOoo0OO0 , 16 ) % lisp_decent_modulus
 return ( OOOoO000 )
 if 52 - 52: iII111i - II111iiii % i1IIi / iII111i
 if 14 - 14: oO0o / I1Ii111 / IiII - i1IIi * Ii1I
 if 90 - 90: ooOoO0o
 if 100 - 100: iII111i * i1IIi . iII111i / O0 / OoO0O00 - oO0o
 if 65 - 65: OoOoOO00 + ooOoO0o * OoO0O00 % OoooooooOO + OoooooooOO * OoooooooOO
 if 49 - 49: o0oOOo0O0Ooo + i1IIi / iII111i
 if 43 - 43: i1IIi . OoO0O00 + I1ii11iIi11i
def lisp_get_decent_dns_name ( eid ) :
 OOOoO000 = lisp_get_decent_index ( eid )
 return ( str ( OOOoO000 ) + "." + lisp_decent_dns_suffix )
 if 88 - 88: OoooooooOO / I11i % II111iiii % OOooOOo - I11i
 if 55 - 55: Oo0Ooo - OOooOOo - O0
 if 40 - 40: OoOoOO00 - OOooOOo
 if 3 - 3: IiII % I11i * I1Ii111 + iIii1I11I1II1 . oO0o
 if 35 - 35: II111iiii
 if 15 - 15: I11i * iIii1I11I1II1 + OOooOOo % IiII . o0oOOo0O0Ooo % Oo0Ooo
 if 96 - 96: O0
 if 15 - 15: i1IIi . iIii1I11I1II1
def lisp_get_decent_dns_name_from_str ( iid , eid_str ) :
 i1OO0o = lisp_address ( LISP_AFI_NONE , eid_str , 0 , iid )
 OOOoO000 = lisp_get_decent_index ( i1OO0o )
 return ( str ( OOOoO000 ) + "." + lisp_decent_dns_suffix )
 if 3 - 3: II111iiii * i11iIiiIii * i1IIi - i1IIi
 if 11 - 11: I1IiiI % Ii1I * i11iIiiIii % OOooOOo + II111iiii
 if 61 - 61: I1Ii111 + I11i + I1IiiI
 if 48 - 48: I11i
 if 67 - 67: o0oOOo0O0Ooo
 if 36 - 36: IiII - I11i - Ii1I / OoOoOO00 % OoO0O00 * iIii1I11I1II1
 if 61 - 61: i11iIiiIii / Ii1I - OOooOOo . I1ii11iIi11i
 if 89 - 89: ooOoO0o % i11iIiiIii
 if 57 - 57: Oo0Ooo / ooOoO0o - O0 . ooOoO0o
 if 61 - 61: o0oOOo0O0Ooo / OoooooooOO . I1ii11iIi11i + Oo0Ooo
def lisp_trace_append ( packet , reason = None , ed = "encap" , lisp_socket = None ,
 rloc_entry = None ) :
 if 75 - 75: Ii1I
 oOO0OO0O = 28 if packet . inner_version == 4 else 48
 OoOOo0 = packet . packet [ oOO0OO0O : : ]
 Ooo00O0O0O = lisp_trace ( )
 if ( Ooo00O0O0O . decode ( OoOOo0 ) == False ) :
  lprint ( "Could not decode JSON portion of a LISP-Trace packet" )
  return ( False )
  if 32 - 32: ooOoO0o * OoO0O00 - I11i - OoooooooOO % i1IIi
  if 81 - 81: OOooOOo * O0 + II111iiii . Oo0Ooo
 oo0oo0000o = "?" if packet . outer_dest . is_null ( ) else packet . outer_dest . print_address_no_iid ( )
 if 5 - 5: iIii1I11I1II1
 if 32 - 32: IiII - iII111i . I1Ii111 + Oo0Ooo
 if 45 - 45: OoooooooOO . i11iIiiIii + I1Ii111 . OoO0O00 * ooOoO0o % OoO0O00
 if 14 - 14: I1IiiI % OoOoOO00 + iII111i - iIii1I11I1II1
 if 30 - 30: OoooooooOO * i1IIi % o0oOOo0O0Ooo . Ii1I
 if 85 - 85: I1ii11iIi11i % OoOoOO00 . OoO0O00
 if ( oo0oo0000o != "?" and packet . encap_port != LISP_DATA_PORT ) :
  if ( ed == "encap" ) : oo0oo0000o += ":{}" . format ( packet . encap_port )
  if 38 - 38: Oo0Ooo / iIii1I11I1II1 + iIii1I11I1II1 % iII111i . ooOoO0o * OoooooooOO
  if 83 - 83: OOooOOo
  if 53 - 53: Ii1I
  if 63 - 63: I11i % OoOoOO00
  if 46 - 46: iIii1I11I1II1 . II111iiii / OoooooooOO - ooOoO0o * iII111i
 o0Iiii = { }
 o0Iiii [ "node" ] = "ITR" if lisp_i_am_itr else "ETR" if lisp_i_am_etr else "RTR" if lisp_i_am_rtr else "?"
 if 52 - 52: I11i + iII111i
 IIii11IIIii = packet . outer_source
 if ( IIii11IIIii . is_null ( ) ) : IIii11IIIii = lisp_myrlocs [ 0 ]
 o0Iiii [ "srloc" ] = IIii11IIIii . print_address_no_iid ( )
 if 43 - 43: OoooooooOO * O0
 if 62 - 62: IiII . O0
 if 87 - 87: I1ii11iIi11i / oO0o / IiII . OOooOOo
 if 91 - 91: OOooOOo % oO0o . OoOoOO00 . I1IiiI - OoOoOO00
 if 18 - 18: O0 - I1IiiI + i1IIi % i11iIiiIii
 if ( o0Iiii [ "node" ] == "ITR" and packet . inner_sport != LISP_TRACE_PORT ) :
  o0Iiii [ "srloc" ] += ":{}" . format ( packet . inner_sport )
  if 97 - 97: iII111i * OoooooooOO + I1Ii111 + ooOoO0o - ooOoO0o
  if 63 - 63: o0oOOo0O0Ooo * OOooOOo + iIii1I11I1II1 + Oo0Ooo
 o0Iiii [ "hn" ] = lisp_hostname
 i1IIiI1iII = ed + "-ts"
 o0Iiii [ i1IIiI1iII ] = lisp_get_timestamp ( )
 if 25 - 25: oO0o + IiII % o0oOOo0O0Ooo
 if 24 - 24: OoOoOO00
 if 87 - 87: I1ii11iIi11i / ooOoO0o * i1IIi
 if 71 - 71: OoOoOO00 - I11i
 if 83 - 83: oO0o + oO0o - Oo0Ooo . Oo0Ooo - iII111i . OOooOOo
 if 56 - 56: OoOoOO00 * IiII + i1IIi
 if ( oo0oo0000o == "?" and o0Iiii [ "node" ] == "ETR" ) :
  o0Oo00OOOo00 = lisp_db_for_lookups . lookup_cache ( packet . inner_dest , False )
  if ( o0Oo00OOOo00 != None and len ( o0Oo00OOOo00 . rloc_set ) >= 1 ) :
   oo0oo0000o = o0Oo00OOOo00 . rloc_set [ 0 ] . rloc . print_address_no_iid ( )
   if 40 - 40: I1ii11iIi11i / O0
   if 87 - 87: ooOoO0o
 o0Iiii [ "drloc" ] = oo0oo0000o
 if 100 - 100: iII111i + II111iiii * Oo0Ooo * OOooOOo
 if 6 - 6: IiII % OOooOOo
 if 3 - 3: OoOoOO00 / OoOoOO00 - II111iiii
 if 41 - 41: oO0o
 if ( oo0oo0000o == "?" and reason != None ) :
  o0Iiii [ "drloc" ] += " ({})" . format ( reason )
  if 12 - 12: I1IiiI + I1Ii111
  if 66 - 66: I1Ii111 + OOooOOo + I1Ii111 . OoooooooOO * oO0o / OoO0O00
  if 74 - 74: O0 % OOooOOo * OoOoOO00 / oO0o - Oo0Ooo
  if 79 - 79: Ii1I + IiII
  if 21 - 21: o0oOOo0O0Ooo * iII111i * o0oOOo0O0Ooo * o0oOOo0O0Ooo . Oo0Ooo
 if ( rloc_entry != None ) :
  o0Iiii [ "rtts" ] = rloc_entry . recent_rloc_probe_rtts
  o0Iiii [ "hops" ] = rloc_entry . recent_rloc_probe_hops
  if 98 - 98: I1ii11iIi11i
  if 58 - 58: IiII / i11iIiiIii % I11i
  if 74 - 74: OoooooooOO - I1ii11iIi11i + OOooOOo % IiII . o0oOOo0O0Ooo
  if 21 - 21: Ii1I
  if 72 - 72: I1Ii111 . OoooooooOO / I1Ii111 - Ii1I / I1ii11iIi11i * I1ii11iIi11i
  if 72 - 72: IiII . Ii1I + OoooooooOO * OoOoOO00 + Oo0Ooo . iII111i
 I1IIiiII = packet . inner_source . print_address ( )
 o0000OO = packet . inner_dest . print_address ( )
 if ( Ooo00O0O0O . packet_json == [ ] ) :
  o00oo = { }
  o00oo [ "seid" ] = I1IIiiII
  o00oo [ "deid" ] = o0000OO
  o00oo [ "paths" ] = [ ]
  Ooo00O0O0O . packet_json . append ( o00oo )
  if 92 - 92: O0 * Ii1I - I1ii11iIi11i - IiII . OoO0O00 + I1IiiI
  if 59 - 59: i1IIi * OOooOOo % Oo0Ooo
  if 44 - 44: iIii1I11I1II1 . OOooOOo
  if 57 - 57: II111iiii + I1Ii111
  if 42 - 42: OoOoOO00 % O0
  if 70 - 70: iIii1I11I1II1 * Oo0Ooo - I1IiiI / OoO0O00 + OoOoOO00
 for o00oo in Ooo00O0O0O . packet_json :
  if ( o00oo [ "deid" ] != o0000OO ) : continue
  o00oo [ "paths" ] . append ( o0Iiii )
  break
  if 94 - 94: OoooooooOO + O0 * iIii1I11I1II1 * II111iiii
  if 90 - 90: I11i + O0 / I1IiiI . oO0o / O0
  if 46 - 46: O0 . O0 - oO0o . II111iiii * I1IiiI * Ii1I
  if 10 - 10: i1IIi + i1IIi . i1IIi - I1IiiI - I1IiiI
  if 26 - 26: Ii1I * I11i / I11i
  if 79 - 79: ooOoO0o / oO0o - oO0o / OoooooooOO
  if 91 - 91: iIii1I11I1II1 - O0 * o0oOOo0O0Ooo * o0oOOo0O0Ooo . II111iiii
  if 69 - 69: II111iiii - Oo0Ooo + i1IIi . II111iiii + o0oOOo0O0Ooo
 Ii1I11iII = False
 if ( len ( Ooo00O0O0O . packet_json ) == 1 and Ooo00O0O0O . myeid ( packet . inner_dest ) ) :
  o00oo = { }
  o00oo [ "seid" ] = o0000OO
  o00oo [ "deid" ] = I1IIiiII
  o00oo [ "paths" ] = [ ]
  Ooo00O0O0O . packet_json . append ( o00oo )
  Ii1I11iII = True
  if 64 - 64: O0 + iII111i / I11i * OoOoOO00 + o0oOOo0O0Ooo + I1Ii111
  if 16 - 16: I11i
  if 9 - 9: Ii1I / IiII * I11i - i11iIiiIii * I1ii11iIi11i / iII111i
  if 61 - 61: O0 % iII111i
  if 41 - 41: I1Ii111 * OoooooooOO
  if 76 - 76: OoooooooOO * II111iiii . II111iiii / o0oOOo0O0Ooo - iII111i
 Ooo00O0O0O . print_trace ( )
 OoOOo0 = Ooo00O0O0O . encode ( )
 if 49 - 49: O0 . I1ii11iIi11i . OoOoOO00 . I1Ii111 % O0 . iIii1I11I1II1
 if 19 - 19: iIii1I11I1II1
 if 97 - 97: Ii1I . I11i / ooOoO0o + Oo0Ooo
 if 100 - 100: iII111i / I1Ii111 % OoOoOO00 . O0 / OoOoOO00
 if 81 - 81: OoO0O00 % i11iIiiIii / OoO0O00 + ooOoO0o
 if 100 - 100: O0 . Oo0Ooo % Oo0Ooo % O0 / i11iIiiIii
 if 56 - 56: IiII - OOooOOo - OoOoOO00 - I11i
 if 57 - 57: i1IIi
 i11ii11ii = Ooo00O0O0O . packet_json [ 0 ] [ "paths" ] [ 0 ] [ "srloc" ]
 if ( oo0oo0000o == "?" ) :
  lprint ( "LISP-Trace return to sender RLOC {}" . format ( i11ii11ii ) )
  Ooo00O0O0O . return_to_sender ( lisp_socket , i11ii11ii , OoOOo0 )
  return ( False )
  if 45 - 45: iII111i - I1Ii111 % OOooOOo . I1IiiI + Ii1I
  if 59 - 59: O0 * o0oOOo0O0Ooo + I1IiiI / oO0o
  if 44 - 44: OoOoOO00 / OoOoOO00 . I11i - Ii1I
  if 82 - 82: I1IiiI + OoOoOO00 . II111iiii / OoOoOO00 % OoOoOO00 . I1ii11iIi11i
  if 19 - 19: iIii1I11I1II1 . iIii1I11I1II1 + OOooOOo - I1ii11iIi11i
  if 59 - 59: i11iIiiIii / oO0o * IiII . o0oOOo0O0Ooo % Ii1I
 i1 = Ooo00O0O0O . packet_length ( )
 if 95 - 95: OoooooooOO - I1IiiI * I1ii11iIi11i
 if 52 - 52: oO0o % iII111i - I1IiiI - o0oOOo0O0Ooo
 if 66 - 66: o0oOOo0O0Ooo - Oo0Ooo - OoooooooOO * o0oOOo0O0Ooo + I1Ii111
 if 82 - 82: I11i * i1IIi / Ii1I + O0
 if 85 - 85: O0 + oO0o / I1Ii111
 if 65 - 65: o0oOOo0O0Ooo . Oo0Ooo . i1IIi / IiII . I11i . O0
 oOo0O0OO = packet . packet [ 0 : oOO0OO0O ]
 o0O0o = struct . pack ( "HH" , socket . htons ( i1 ) , 0 )
 oOo0O0OO = oOo0O0OO [ 0 : oOO0OO0O - 4 ] + o0O0o
 if ( packet . inner_version == 6 and o0Iiii [ "node" ] == "ETR" and
 len ( Ooo00O0O0O . packet_json ) == 2 ) :
  IIi1ii1 = oOo0O0OO [ oOO0OO0O - 8 : : ] + OoOOo0
  IIi1ii1 = lisp_udp_checksum ( I1IIiiII , o0000OO , IIi1ii1 )
  oOo0O0OO = oOo0O0OO [ 0 : oOO0OO0O - 8 ] + IIi1ii1 [ 0 : 8 ]
  if 66 - 66: I1ii11iIi11i + iII111i / Ii1I / I1IiiI * i11iIiiIii
  if 41 - 41: Ii1I / Oo0Ooo . OoO0O00 . iIii1I11I1II1 % IiII . I11i
  if 59 - 59: O0 + II111iiii + IiII % Oo0Ooo
  if 71 - 71: oO0o
  if 75 - 75: Oo0Ooo * oO0o + iIii1I11I1II1 / Oo0Ooo
  if 51 - 51: Ii1I * Ii1I + iII111i * oO0o / OOooOOo - ooOoO0o
 if ( Ii1I11iII ) :
  if ( packet . inner_version == 4 ) :
   oOo0O0OO = oOo0O0OO [ 0 : 12 ] + oOo0O0OO [ 16 : 20 ] + oOo0O0OO [ 12 : 16 ] + oOo0O0OO [ 22 : 24 ] + oOo0O0OO [ 20 : 22 ] + oOo0O0OO [ 24 : : ]
   if 16 - 16: I1Ii111 + O0 - O0 * iIii1I11I1II1 / iII111i
  else :
   oOo0O0OO = oOo0O0OO [ 0 : 8 ] + oOo0O0OO [ 24 : 40 ] + oOo0O0OO [ 8 : 24 ] + oOo0O0OO [ 42 : 44 ] + oOo0O0OO [ 40 : 42 ] + oOo0O0OO [ 44 : : ]
   if 4 - 4: iII111i
   if 75 - 75: I1IiiI * IiII % OoO0O00 - ooOoO0o * iII111i
  i1i11ii1Ii = packet . inner_dest
  packet . inner_dest = packet . inner_source
  packet . inner_source = i1i11ii1Ii
  if 32 - 32: iII111i
  if 59 - 59: OoOoOO00 - I1Ii111
  if 34 - 34: ooOoO0o . OoooooooOO / ooOoO0o + OoooooooOO
  if 24 - 24: OoooooooOO * I1ii11iIi11i / O0 / Oo0Ooo * I1IiiI / ooOoO0o
  if 33 - 33: Ii1I
 oOO0OO0O = 2 if packet . inner_version == 4 else 4
 i111i1 = 20 + i1 if packet . inner_version == 4 else i1
 oO0o00ooO = struct . pack ( "H" , socket . htons ( i111i1 ) )
 oOo0O0OO = oOo0O0OO [ 0 : oOO0OO0O ] + oO0o00ooO + oOo0O0OO [ oOO0OO0O + 2 : : ]
 if 58 - 58: i11iIiiIii / OoOoOO00
 if 18 - 18: ooOoO0o + O0 - OOooOOo + iIii1I11I1II1 . OOooOOo * iIii1I11I1II1
 if 83 - 83: OoO0O00 - Oo0Ooo * I1IiiI % Oo0Ooo % oO0o
 if 64 - 64: OoOoOO00 + oO0o / OoooooooOO . i11iIiiIii / II111iiii
 if ( packet . inner_version == 4 ) :
  OoOOooOOoo = struct . pack ( "H" , 0 )
  oOo0O0OO = oOo0O0OO [ 0 : 10 ] + OoOOooOOoo + oOo0O0OO [ 12 : : ]
  oO0o00ooO = lisp_ip_checksum ( oOo0O0OO [ 0 : 20 ] )
  oOo0O0OO = oO0o00ooO + oOo0O0OO [ 20 : : ]
  if 55 - 55: ooOoO0o . i11iIiiIii . o0oOOo0O0Ooo
  if 52 - 52: IiII . oO0o + i11iIiiIii % IiII
  if 45 - 45: i1IIi - I1IiiI / IiII - I1IiiI
  if 21 - 21: IiII
  if 43 - 43: IiII
 packet . packet = oOo0O0OO + OoOOo0
 return ( True )
 if 9 - 9: OOooOOo * ooOoO0o + ooOoO0o . I1Ii111
 if 8 - 8: IiII * iIii1I11I1II1
 if 7 - 7: I1Ii111 / OoooooooOO % O0 - I1ii11iIi11i
# dd678faae9ac167bc83abf78e5cb2f3f0688d3a3
