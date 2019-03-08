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
LISP_DATA_PORT = 4341
LISP_CTRL_PORT = 4342
LISP_L2_DATA_PORT = 8472
LISP_VXLAN_DATA_PORT = 4789
LISP_VXLAN_GPE_PORT = 4790
LISP_TRACE_PORT = 2434
if 78 - 78: I1ii11iIi11i + OOooOOo - I1Ii111
if 38 - 38: o0oOOo0O0Ooo - oO0o + iIii1I11I1II1 / OoOoOO00 % Oo0Ooo
if 57 - 57: OoO0O00 / ooOoO0o
if 29 - 29: iIii1I11I1II1 + OoOoOO00 * OoO0O00 * OOooOOo . I1IiiI * I1IiiI
LISP_MAP_REQUEST = 1
LISP_MAP_REPLY = 2
LISP_MAP_REGISTER = 3
LISP_MAP_NOTIFY = 4
LISP_MAP_NOTIFY_ACK = 5
LISP_MAP_REFERRAL = 6
LISP_NAT_INFO = 7
LISP_ECM = 8
LISP_TRACE = 9
if 7 - 7: IiII * I1Ii111 % Ii1I - o0oOOo0O0Ooo
if 13 - 13: Ii1I . i11iIiiIii
if 56 - 56: I1ii11iIi11i % O0 - I1IiiI
if 100 - 100: Ii1I - O0 % oO0o * OOooOOo + I1IiiI
LISP_NO_ACTION = 0
LISP_NATIVE_FORWARD_ACTION = 1
LISP_SEND_MAP_REQUEST_ACTION = 2
LISP_DROP_ACTION = 3
LISP_POLICY_DENIED_ACTION = 4
LISP_AUTH_FAILURE_ACTION = 5
if 88 - 88: OoooooooOO - OoO0O00 * O0 * OoooooooOO . OoooooooOO
lisp_map_reply_action_string = [ "no-action" , "native-forward" ,
 "send-map-request" , "drop-action" , "policy-denied" , "auth-failure" ]
if 33 - 33: I1Ii111 + iII111i * oO0o / iIii1I11I1II1 - I1IiiI
if 54 - 54: I1Ii111 / OOooOOo . oO0o % iII111i
if 57 - 57: i11iIiiIii . I1ii11iIi11i - Ii1I - oO0o + OoOoOO00
if 63 - 63: OoOoOO00 * iII111i
LISP_NONE_ALG_ID = 0
LISP_SHA_1_96_ALG_ID = 1
LISP_SHA_256_128_ALG_ID = 2
LISP_MD5_AUTH_DATA_LEN = 16
LISP_SHA1_160_AUTH_DATA_LEN = 20
LISP_SHA2_256_AUTH_DATA_LEN = 32
if 69 - 69: O0 . OoO0O00
if 49 - 49: I1IiiI - I11i
if 74 - 74: iIii1I11I1II1 * I1ii11iIi11i + OoOoOO00 / i1IIi / II111iiii . Oo0Ooo
if 62 - 62: OoooooooOO * I1IiiI
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
if 58 - 58: OoOoOO00 % o0oOOo0O0Ooo
if 50 - 50: I1Ii111 . o0oOOo0O0Ooo
if 97 - 97: O0 + OoOoOO00
if 89 - 89: o0oOOo0O0Ooo + OoO0O00 * I11i * Ii1I
LISP_MR_TTL = ( 24 * 60 )
LISP_REGISTER_TTL = 3
LISP_SHORT_TTL = 1
LISP_NMR_TTL = 15
if 37 - 37: OoooooooOO - O0 - o0oOOo0O0Ooo
LISP_SITE_TIMEOUT_CHECK_INTERVAL = 60
LISP_PUBSUB_TIMEOUT_CHECK_INTERVAL = 60
LISP_REFERRAL_TIMEOUT_CHECK_INTERVAL = 60
LISP_TEST_MR_INTERVAL = 60
LISP_MAP_NOTIFY_INTERVAL = 2
LISP_DDT_MAP_REQUEST_INTERVAL = 2
LISP_MAX_MAP_NOTIFY_RETRIES = 3
LISP_INFO_INTERVAL = 15
LISP_MAP_REQUEST_RATE_LIMIT = 5
if 77 - 77: OOooOOo * iIii1I11I1II1
LISP_RLOC_PROBE_TTL = 64
LISP_RLOC_PROBE_INTERVAL = 10
LISP_RLOC_PROBE_REPLY_WAIT = 15
if 98 - 98: I1IiiI % Ii1I * OoooooooOO
LISP_DEFAULT_DYN_EID_TIMEOUT = 15
LISP_NONCE_ECHO_INTERVAL = 10
if 51 - 51: iIii1I11I1II1 . OoOoOO00 / oO0o + o0oOOo0O0Ooo
if 33 - 33: ooOoO0o . II111iiii % iII111i + o0oOOo0O0Ooo
if 71 - 71: Oo0Ooo % OOooOOo
if 98 - 98: I11i % i11iIiiIii % ooOoO0o + Ii1I
if 78 - 78: I1ii11iIi11i % oO0o / iII111i - iIii1I11I1II1
if 69 - 69: I1Ii111
if 11 - 11: I1IiiI
if 16 - 16: Ii1I + IiII * O0 % i1IIi . I1IiiI
if 67 - 67: OoooooooOO / I1IiiI * Ii1I + I11i
if 65 - 65: OoooooooOO - I1ii11iIi11i / ooOoO0o / II111iiii / i1IIi
if 71 - 71: I1Ii111 + Ii1I
if 28 - 28: OOooOOo
if 38 - 38: ooOoO0o % II111iiii % I11i / OoO0O00 + OoOoOO00 / i1IIi
if 54 - 54: iIii1I11I1II1 % I1ii11iIi11i - OOooOOo / oO0o - OoO0O00 . I11i
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
LISP_CS_1024 = 0
LISP_CS_1024_G = 2
LISP_CS_1024_P = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF
if 10 - 10: iII111i + Oo0Ooo * I1ii11iIi11i + iIii1I11I1II1 / I1Ii111 / I1ii11iIi11i
LISP_CS_2048_CBC = 1
LISP_CS_2048_CBC_G = 2
LISP_CS_2048_CBC_P = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF
if 42 - 42: I1IiiI
LISP_CS_25519_CBC = 2
LISP_CS_2048_GCM = 3
if 38 - 38: OOooOOo + II111iiii % ooOoO0o % OoOoOO00 - Ii1I / OoooooooOO
LISP_CS_3072 = 4
LISP_CS_3072_G = 2
LISP_CS_3072_P = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF
if 73 - 73: o0oOOo0O0Ooo * O0 - i11iIiiIii
LISP_CS_25519_GCM = 5
LISP_CS_25519_CHACHA = 6
if 85 - 85: Ii1I % iII111i + I11i / o0oOOo0O0Ooo . oO0o + OOooOOo
LISP_4_32_MASK = 0xFFFFFFFF
LISP_8_64_MASK = 0xFFFFFFFFFFFFFFFF
LISP_16_128_MASK = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
if 62 - 62: i11iIiiIii + i11iIiiIii - o0oOOo0O0Ooo
if 28 - 28: iII111i . iII111i % iIii1I11I1II1 * iIii1I11I1II1 . o0oOOo0O0Ooo / iII111i
if 27 - 27: OoO0O00 + ooOoO0o - i1IIi
if 69 - 69: IiII - O0 % I1ii11iIi11i + i11iIiiIii . OoOoOO00 / OoO0O00
if 79 - 79: O0 * i11iIiiIii - IiII / IiII
if 48 - 48: O0
if 93 - 93: i11iIiiIii - I1IiiI * I1ii11iIi11i * I11i % O0 + OoooooooOO
if 25 - 25: IiII + Ii1I / ooOoO0o . o0oOOo0O0Ooo % O0 * OoO0O00
def lisp_record_traceback ( * args ) :
 o0O0oo0OO0O = datetime . datetime . now ( ) . strftime ( "%m/%d/%y %H:%M:%S.%f" ) [ : - 3 ]
 OO0 = open ( "./logs/lisp-traceback.log" , "a" )
 OO0 . write ( "---------- Exception occurred: {} ----------\n" . format ( o0O0oo0OO0O ) )
 try :
  traceback . print_last ( file = OO0 )
 except :
  OO0 . write ( "traceback.print_last(file=fd) failed" )
  if 72 - 72: OoooooooOO
 try :
  traceback . print_last ( )
 except :
  print ( "traceback.print_last() failed" )
  if 72 - 72: I1IiiI % i11iIiiIii . Oo0Ooo / II111iiii
 OO0 . close ( )
 return
 if 14 - 14: I1ii11iIi11i + OoO0O00
 if 3 - 3: I1ii11iIi11i . Oo0Ooo / II111iiii
 if 39 - 39: I1Ii111
 if 91 - 91: OoooooooOO - iIii1I11I1II1 + OoOoOO00 / OoO0O00 . OoOoOO00 + O0
 if 26 - 26: I1ii11iIi11i - OoooooooOO
 if 11 - 11: I1IiiI * oO0o
 if 81 - 81: iII111i + IiII
def lisp_set_exception ( ) :
 sys . excepthook = lisp_record_traceback
 return
 if 98 - 98: I1IiiI
 if 95 - 95: ooOoO0o / ooOoO0o
 if 30 - 30: I1ii11iIi11i + Oo0Ooo / Oo0Ooo % I1ii11iIi11i . I1ii11iIi11i
 if 55 - 55: ooOoO0o - I11i + II111iiii + iII111i % Ii1I
 if 41 - 41: i1IIi - I11i - Ii1I
 if 8 - 8: OoO0O00 + I1Ii111 - o0oOOo0O0Ooo % Oo0Ooo % o0oOOo0O0Ooo * oO0o
 if 9 - 9: Oo0Ooo - i11iIiiIii - OOooOOo * Ii1I + ooOoO0o
def lisp_is_raspbian ( ) :
 if ( platform . dist ( ) [ 0 ] != "debian" ) : return ( False )
 return ( platform . machine ( ) in [ "armv6l" , "armv7l" ] )
 if 44 - 44: II111iiii
 if 52 - 52: I1ii11iIi11i - Oo0Ooo + I1ii11iIi11i % o0oOOo0O0Ooo
 if 35 - 35: iIii1I11I1II1
 if 42 - 42: I1Ii111 . I1IiiI . i1IIi + OoOoOO00 + OOooOOo + I1IiiI
 if 31 - 31: iII111i . OOooOOo - ooOoO0o . OoooooooOO / OoooooooOO
 if 56 - 56: OoO0O00 / oO0o / i11iIiiIii + OoooooooOO - Oo0Ooo - I11i
 if 21 - 21: O0 % IiII . I1IiiI / II111iiii + IiII
def lisp_is_ubuntu ( ) :
 return ( platform . dist ( ) [ 0 ] == "Ubuntu" )
 if 53 - 53: oO0o - I1IiiI - oO0o * iII111i
 if 71 - 71: O0 - iIii1I11I1II1
 if 12 - 12: OOooOOo / o0oOOo0O0Ooo
 if 42 - 42: Oo0Ooo
 if 19 - 19: oO0o % I1ii11iIi11i * iIii1I11I1II1 + I1IiiI
 if 46 - 46: Oo0Ooo
 if 1 - 1: iII111i
def lisp_is_fedora ( ) :
 return ( platform . dist ( ) [ 0 ] == "fedora" )
 if 97 - 97: OOooOOo + iII111i + O0 + i11iIiiIii
 if 77 - 77: o0oOOo0O0Ooo / OoooooooOO
 if 46 - 46: o0oOOo0O0Ooo % iIii1I11I1II1 . iII111i % iII111i + i11iIiiIii
 if 72 - 72: iIii1I11I1II1 * Ii1I % ooOoO0o / OoO0O00
 if 35 - 35: ooOoO0o + i1IIi % I1ii11iIi11i % I11i + oO0o
 if 17 - 17: i1IIi
 if 21 - 21: Oo0Ooo
def lisp_is_centos ( ) :
 return ( platform . dist ( ) [ 0 ] == "centos" )
 if 29 - 29: I11i / II111iiii / ooOoO0o * OOooOOo
 if 10 - 10: I1Ii111 % IiII * IiII . I11i / Ii1I % OOooOOo
 if 49 - 49: OoO0O00 / oO0o + O0 * o0oOOo0O0Ooo
 if 28 - 28: ooOoO0o + i11iIiiIii / I11i % OoOoOO00 % Oo0Ooo - O0
 if 54 - 54: i1IIi + II111iiii
 if 83 - 83: I1ii11iIi11i - I1IiiI + OOooOOo
 if 5 - 5: Ii1I
def lisp_is_debian ( ) :
 return ( platform . dist ( ) [ 0 ] == "debian" )
 if 46 - 46: IiII
 if 45 - 45: ooOoO0o
 if 21 - 21: oO0o . I1Ii111 . OOooOOo / Oo0Ooo / I1Ii111
 if 17 - 17: OOooOOo / OOooOOo / I11i
 if 1 - 1: i1IIi . i11iIiiIii % OOooOOo
 if 82 - 82: iIii1I11I1II1 + Oo0Ooo . iIii1I11I1II1 % IiII / Ii1I . Ii1I
 if 14 - 14: o0oOOo0O0Ooo . OOooOOo . I11i + OoooooooOO - OOooOOo + IiII
def lisp_is_debian_kali ( ) :
 return ( platform . dist ( ) [ 0 ] == "Kali" )
 if 9 - 9: Ii1I
 if 59 - 59: I1IiiI * II111iiii . O0
 if 56 - 56: Ii1I - iII111i % I1IiiI - o0oOOo0O0Ooo
 if 51 - 51: O0 / ooOoO0o * iIii1I11I1II1 + I1ii11iIi11i + o0oOOo0O0Ooo
 if 98 - 98: iIii1I11I1II1 * I1ii11iIi11i * OOooOOo + ooOoO0o % i11iIiiIii % O0
 if 27 - 27: O0
 if 79 - 79: o0oOOo0O0Ooo - I11i + o0oOOo0O0Ooo . oO0o
def lisp_is_macos ( ) :
 return ( platform . uname ( ) [ 0 ] == "Darwin" )
 if 28 - 28: i1IIi - iII111i
 if 54 - 54: iII111i - O0 % OOooOOo
 if 73 - 73: O0 . OoOoOO00 + I1IiiI - I11i % I11i . I11i
 if 17 - 17: Ii1I - OoooooooOO % Ii1I . IiII / i11iIiiIii % iII111i
 if 28 - 28: I11i
 if 58 - 58: OoOoOO00
 if 37 - 37: Oo0Ooo - iIii1I11I1II1 / I1ii11iIi11i
def lisp_is_alpine ( ) :
 return ( os . path . exists ( "/etc/alpine-release" ) )
 if 73 - 73: i11iIiiIii - IiII
 if 25 - 25: OoooooooOO + IiII * I1ii11iIi11i
 if 92 - 92: I1IiiI + I11i + O0 / o0oOOo0O0Ooo + I1Ii111
 if 18 - 18: ooOoO0o * OoOoOO00 . iII111i / I1ii11iIi11i / i11iIiiIii
 if 21 - 21: oO0o / I1ii11iIi11i + Ii1I + OoooooooOO
 if 91 - 91: i11iIiiIii / i1IIi + iII111i + ooOoO0o * i11iIiiIii
 if 66 - 66: iIii1I11I1II1 % i1IIi - O0 + I11i * I1Ii111 . IiII
def lisp_is_x86 ( ) :
 O0ooo0 = platform . machine ( )
 return ( O0ooo0 in ( "x86" , "i686" , "x86_64" ) )
 if 8 - 8: ooOoO0o + II111iiii / iII111i / I11i
 if 74 - 74: O0 / i1IIi
 if 78 - 78: OoooooooOO . OoO0O00 + ooOoO0o - i1IIi
 if 31 - 31: OoooooooOO . OOooOOo
 if 83 - 83: iII111i . O0 / Oo0Ooo / OOooOOo - II111iiii
 if 100 - 100: OoO0O00
 if 46 - 46: OoOoOO00 / iIii1I11I1II1 % iII111i . iIii1I11I1II1 * iII111i
def lisp_is_linux ( ) :
 return ( platform . uname ( ) [ 0 ] == "Linux" )
 if 38 - 38: I1ii11iIi11i - iII111i / O0 . I1Ii111
 if 45 - 45: I1Ii111
 if 83 - 83: OoOoOO00 . OoooooooOO
 if 58 - 58: i11iIiiIii + OoooooooOO % OoooooooOO / IiII / i11iIiiIii
 if 62 - 62: OoO0O00 / I1ii11iIi11i
 if 7 - 7: OoooooooOO . IiII
 if 53 - 53: Ii1I % Ii1I * o0oOOo0O0Ooo + OoOoOO00
 if 92 - 92: OoooooooOO + i1IIi / Ii1I * O0
def lisp_process_logfile ( ) :
 O00oOo00o0o = "./logs/lisp-{}.log" . format ( lisp_log_id )
 if ( os . path . exists ( O00oOo00o0o ) ) : return
 if 85 - 85: iII111i + OoooooooOO * iII111i - I1Ii111 % i11iIiiIii
 sys . stdout . close ( )
 sys . stdout = open ( O00oOo00o0o , "a" )
 if 71 - 71: I1ii11iIi11i - ooOoO0o / OoOoOO00 * OoOoOO00 / i1IIi . i1IIi
 lisp_print_banner ( bold ( "logfile rotation" , False ) )
 return
 if 53 - 53: I1Ii111
 if 21 - 21: I11i
 if 92 - 92: i11iIiiIii / I1Ii111 - iII111i % ooOoO0o * I1Ii111 + Oo0Ooo
 if 11 - 11: OoooooooOO . I1Ii111
 if 80 - 80: OoooooooOO - OOooOOo * Ii1I * I1ii11iIi11i / I1IiiI / OOooOOo
 if 13 - 13: I1Ii111 * ooOoO0o + i11iIiiIii * I1Ii111 - ooOoO0o
 if 23 - 23: iIii1I11I1II1 * i1IIi % OoooooooOO * IiII
 if 9 - 9: IiII - II111iiii + O0 / iIii1I11I1II1 / i11iIiiIii
def lisp_i_am ( name ) :
 global lisp_log_id , lisp_i_am_itr , lisp_i_am_etr , lisp_i_am_rtr
 global lisp_i_am_mr , lisp_i_am_ms , lisp_i_am_ddt , lisp_i_am_core
 global lisp_hostname
 if 39 - 39: IiII * Oo0Ooo + iIii1I11I1II1 - IiII + OOooOOo
 lisp_log_id = name
 if ( name == "itr" ) : lisp_i_am_itr = True
 if ( name == "etr" ) : lisp_i_am_etr = True
 if ( name == "rtr" ) : lisp_i_am_rtr = True
 if ( name == "mr" ) : lisp_i_am_mr = True
 if ( name == "ms" ) : lisp_i_am_ms = True
 if ( name == "ddt" ) : lisp_i_am_ddt = True
 if ( name == "core" ) : lisp_i_am_core = True
 if 69 - 69: O0
 if 85 - 85: ooOoO0o / O0
 if 18 - 18: o0oOOo0O0Ooo % O0 * I1ii11iIi11i
 if 62 - 62: I1Ii111 . IiII . OoooooooOO
 if 11 - 11: OOooOOo / I11i
 lisp_hostname = socket . gethostname ( )
 oooO0 = lisp_hostname . find ( "." )
 if ( oooO0 != - 1 ) : lisp_hostname = lisp_hostname [ 0 : oooO0 ]
 return
 if 16 - 16: II111iiii + oO0o - OoooooooOO
 if 3 - 3: O0 / iII111i
 if 31 - 31: OOooOOo + o0oOOo0O0Ooo . OoooooooOO
 if 89 - 89: II111iiii + i1IIi + II111iiii
 if 7 - 7: O0 % o0oOOo0O0Ooo + I1ii11iIi11i * iII111i - iII111i
 if 42 - 42: OoOoOO00 * OoOoOO00 * I1Ii111 . I11i
 if 51 - 51: OOooOOo % iIii1I11I1II1 - OoooooooOO % ooOoO0o * iIii1I11I1II1 % OoO0O00
def lprint ( * args ) :
 if ( lisp_debug_logging == False ) : return
 if 99 - 99: oO0o * II111iiii * I1Ii111
 lisp_process_logfile ( )
 o0O0oo0OO0O = datetime . datetime . now ( ) . strftime ( "%m/%d/%y %H:%M:%S.%f" )
 o0O0oo0OO0O = o0O0oo0OO0O [ : - 3 ]
 print "{}: {}:" . format ( o0O0oo0OO0O , lisp_log_id ) ,
 for oOooO0 in args : print oOooO0 ,
 print ""
 try : sys . stdout . flush ( )
 except : pass
 return
 if 79 - 79: OoO0O00 - iIii1I11I1II1 + Ii1I - I1Ii111
 if 93 - 93: II111iiii . I1IiiI - Oo0Ooo + OoOoOO00
 if 61 - 61: II111iiii
 if 15 - 15: i11iIiiIii % I1IiiI * I11i / I1Ii111
 if 90 - 90: iII111i
 if 31 - 31: OOooOOo + O0
 if 87 - 87: ooOoO0o
 if 45 - 45: OoO0O00 / OoooooooOO - iII111i / Ii1I % IiII
def dprint ( * args ) :
 if ( lisp_data_plane_logging ) : lprint ( * args )
 return
 if 83 - 83: I1IiiI . iIii1I11I1II1 - IiII * i11iIiiIii
 if 20 - 20: i1IIi * I1Ii111 + II111iiii % o0oOOo0O0Ooo % oO0o
 if 13 - 13: Oo0Ooo
 if 60 - 60: I1ii11iIi11i * I1IiiI
 if 17 - 17: OOooOOo % Oo0Ooo / I1ii11iIi11i . IiII * OOooOOo - II111iiii
 if 41 - 41: Ii1I
 if 77 - 77: I1Ii111
 if 65 - 65: II111iiii . I1IiiI % oO0o * OoO0O00
def debug ( * args ) :
 lisp_process_logfile ( )
 if 38 - 38: OoOoOO00 / iII111i % Oo0Ooo
 o0O0oo0OO0O = datetime . datetime . now ( ) . strftime ( "%m/%d/%y %H:%M:%S.%f" )
 o0O0oo0OO0O = o0O0oo0OO0O [ : - 3 ]
 if 11 - 11: iII111i - oO0o + II111iiii - iIii1I11I1II1
 print red ( ">>>" , False ) ,
 print "{}:" . format ( o0O0oo0OO0O ) ,
 for oOooO0 in args : print oOooO0 ,
 print red ( "<<<\n" , False )
 try : sys . stdout . flush ( )
 except : pass
 return
 if 7 - 7: IiII - I11i / II111iiii * Ii1I . iII111i * iII111i
 if 61 - 61: I11i % ooOoO0o - OoO0O00 / Oo0Ooo
 if 4 - 4: OoooooooOO - i1IIi % Ii1I - OOooOOo * o0oOOo0O0Ooo
 if 85 - 85: OoooooooOO * iIii1I11I1II1 . iII111i / OoooooooOO % I1IiiI % O0
 if 36 - 36: Ii1I / II111iiii / IiII / IiII + I1ii11iIi11i
 if 95 - 95: IiII
 if 51 - 51: II111iiii + IiII . i1IIi . I1ii11iIi11i + OoOoOO00 * I1IiiI
def lisp_print_banner ( string ) :
 global lisp_version , lisp_hostname
 if 72 - 72: oO0o + oO0o / II111iiii . OoooooooOO % Ii1I
 if ( lisp_version == "" ) :
  lisp_version = commands . getoutput ( "cat lisp-version.txt" )
  if 49 - 49: oO0o . OoO0O00 - Oo0Ooo * OoooooooOO . Oo0Ooo
 ii1Ii1IiIIi = bold ( lisp_hostname , False )
 lprint ( "lispers.net LISP {} {}, version {}, hostname {}" . format ( string ,
 datetime . datetime . now ( ) , lisp_version , ii1Ii1IiIIi ) )
 return
 if 83 - 83: I11i / I1ii11iIi11i
 if 34 - 34: I1IiiI * Oo0Ooo * I1Ii111 / OoO0O00 * I11i / iIii1I11I1II1
 if 74 - 74: Oo0Ooo / i11iIiiIii - II111iiii * o0oOOo0O0Ooo
 if 5 - 5: OOooOOo - OOooOOo . Oo0Ooo + OoOoOO00 - OOooOOo . oO0o
 if 31 - 31: II111iiii - iIii1I11I1II1 - iIii1I11I1II1 % I11i
 if 12 - 12: iIii1I11I1II1
 if 20 - 20: o0oOOo0O0Ooo / i1IIi
def green ( string , html ) :
 if ( html ) : return ( '<font color="green"><b>{}</b></font>' . format ( string ) )
 return ( bold ( "\033[92m" + string + "\033[0m" , html ) )
 if 71 - 71: OoOoOO00 . i1IIi
 if 94 - 94: OOooOOo . I1Ii111
 if 84 - 84: O0 . I11i - II111iiii . ooOoO0o / II111iiii
 if 47 - 47: OoooooooOO
 if 4 - 4: I1IiiI % I11i
 if 10 - 10: IiII . OoooooooOO - OoO0O00 + IiII - O0
 if 82 - 82: ooOoO0o + II111iiii
def green_last_sec ( string ) :
 return ( green ( string , True ) )
 if 39 - 39: oO0o % iIii1I11I1II1 % O0 % OoooooooOO * I1ii11iIi11i + iII111i
 if 68 - 68: Oo0Ooo + i11iIiiIii
 if 69 - 69: iIii1I11I1II1 * iIii1I11I1II1 * i11iIiiIii + I1IiiI / OOooOOo % Ii1I
 if 58 - 58: OOooOOo * o0oOOo0O0Ooo + O0 % OOooOOo
 if 25 - 25: Oo0Ooo % I1ii11iIi11i * ooOoO0o
 if 6 - 6: iII111i . IiII * OoOoOO00 . i1IIi
 if 98 - 98: i1IIi
def green_last_min ( string ) :
 return ( '<font color="#58D68D"><b>{}</b></font>' . format ( string ) )
 if 65 - 65: OoOoOO00 / OoO0O00 % IiII
 if 45 - 45: OoOoOO00
 if 66 - 66: OoO0O00
 if 56 - 56: O0
 if 61 - 61: o0oOOo0O0Ooo / OOooOOo / Oo0Ooo * O0
 if 23 - 23: oO0o - OOooOOo + I11i
 if 12 - 12: I1IiiI / ooOoO0o % o0oOOo0O0Ooo / i11iIiiIii % OoooooooOO
def red ( string , html ) :
 if ( html ) : return ( '<font color="red"><b>{}</b></font>' . format ( string ) )
 return ( bold ( "\033[91m" + string + "\033[0m" , html ) )
 if 15 - 15: iIii1I11I1II1 % OoooooooOO - Oo0Ooo * Ii1I + I11i
 if 11 - 11: iII111i * Ii1I - OoOoOO00
 if 66 - 66: OoOoOO00 . i11iIiiIii - iII111i * o0oOOo0O0Ooo + OoooooooOO * I1ii11iIi11i
 if 74 - 74: Oo0Ooo
 if 61 - 61: Oo0Ooo - I1Ii111 * II111iiii % ooOoO0o * iIii1I11I1II1 + OoO0O00
 if 71 - 71: I11i / I11i * oO0o * oO0o / II111iiii
 if 35 - 35: OOooOOo * o0oOOo0O0Ooo * I1IiiI % Oo0Ooo . OoOoOO00
def blue ( string , html ) :
 if ( html ) : return ( '<font color="blue"><b>{}</b></font>' . format ( string ) )
 return ( bold ( "\033[94m" + string + "\033[0m" , html ) )
 if 58 - 58: I11i + II111iiii * iII111i * i11iIiiIii - iIii1I11I1II1
 if 68 - 68: OoooooooOO % II111iiii
 if 26 - 26: II111iiii % i11iIiiIii % iIii1I11I1II1 % I11i * I11i * I1ii11iIi11i
 if 24 - 24: II111iiii % I1Ii111 - ooOoO0o + I1IiiI * I1ii11iIi11i
 if 2 - 2: Ii1I - IiII
 if 83 - 83: oO0o % o0oOOo0O0Ooo % Ii1I - II111iiii * OOooOOo / OoooooooOO
 if 18 - 18: OoO0O00 + iIii1I11I1II1 - II111iiii - I1IiiI
def bold ( string , html ) :
 if ( html ) : return ( "<b>{}</b>" . format ( string ) )
 return ( "\033[1m" + string + "\033[0m" )
 if 71 - 71: OoooooooOO
 if 33 - 33: I1Ii111
 if 62 - 62: I1ii11iIi11i + Ii1I + i1IIi / OoooooooOO
 if 7 - 7: o0oOOo0O0Ooo + i1IIi . I1IiiI / Oo0Ooo
 if 22 - 22: ooOoO0o - ooOoO0o % OOooOOo . I1Ii111 + oO0o
 if 63 - 63: I1IiiI % I1Ii111 * o0oOOo0O0Ooo + I1Ii111 / Oo0Ooo % iII111i
 if 45 - 45: IiII
def convert_font ( string ) :
 Ii1Iii111IiI1 = [ [ "[91m" , red ] , [ "[92m" , green ] , [ "[94m" , blue ] , [ "[1m" , bold ] ]
 O00oOooo0 = "[0m"
 if 56 - 56: II111iiii / oO0o + i11iIiiIii + OOooOOo
 for O0O0o0o0o in Ii1Iii111IiI1 :
  IIIIIiI = O0O0o0o0o [ 0 ]
  Oo0000O0OOooO = O0O0o0o0o [ 1 ]
  O00OO = len ( IIIIIiI )
  oooO0 = string . find ( IIIIIiI )
  if ( oooO0 != - 1 ) : break
  if 65 - 65: i1IIi . OoooooooOO * Ii1I / IiII
  if 86 - 86: OoOoOO00 * II111iiii - O0 . OoOoOO00 % iIii1I11I1II1 / OOooOOo
 while ( oooO0 != - 1 ) :
  IiIIiIIIiIii = string [ oooO0 : : ] . find ( O00oOooo0 )
  I1i11II = string [ oooO0 + O00OO : oooO0 + IiIIiIIIiIii ]
  string = string [ : oooO0 ] + Oo0000O0OOooO ( I1i11II , True ) + string [ oooO0 + IiIIiIIIiIii + O00OO : : ]
  if 31 - 31: oO0o / IiII * o0oOOo0O0Ooo . II111iiii
  oooO0 = string . find ( IIIIIiI )
  if 89 - 89: O0
  if 2 - 2: I1ii11iIi11i . I1ii11iIi11i + I1ii11iIi11i * o0oOOo0O0Ooo
  if 100 - 100: Oo0Ooo % Ii1I / I11i
  if 30 - 30: Oo0Ooo - OOooOOo - iII111i
  if 81 - 81: o0oOOo0O0Ooo . OoooooooOO + OOooOOo * ooOoO0o
 if ( string . find ( "[1m" ) != - 1 ) : string = convert_font ( string )
 return ( string )
 if 74 - 74: i1IIi + O0 + Oo0Ooo
 if 5 - 5: Oo0Ooo * OoOoOO00
 if 46 - 46: ooOoO0o
 if 33 - 33: iII111i - II111iiii * OoooooooOO - Oo0Ooo - OOooOOo
 if 84 - 84: I1Ii111 + Oo0Ooo - OoOoOO00 * OoOoOO00
 if 61 - 61: OoooooooOO . oO0o . OoooooooOO / Oo0Ooo
 if 72 - 72: i1IIi
def lisp_space ( num ) :
 OOoo0oo = ""
 for ooOooo0OO in range ( num ) : OOoo0oo += "&#160;"
 return ( OOoo0oo )
 if 2 - 2: II111iiii - OoO0O00 . IiII * iII111i / oO0o
 if 80 - 80: OOooOOo / I11i / OoOoOO00 + i1IIi - Oo0Ooo
 if 11 - 11: o0oOOo0O0Ooo * OoO0O00
 if 15 - 15: OoOoOO00
 if 62 - 62: Ii1I
 if 51 - 51: OoOoOO00
 if 14 - 14: IiII % oO0o % Oo0Ooo - i11iIiiIii
def lisp_button ( string , url ) :
 o0OO000ooOo = '<button style="background-color:transparent;border-radius:10px; ' + 'type="button">'
 if 86 - 86: OoO0O00 * OoooooooOO
 if 71 - 71: iIii1I11I1II1 - OOooOOo . I1IiiI % OoooooooOO + OOooOOo
 if ( url == None ) :
  IIi11I1 = o0OO000ooOo + string + "</button>"
 else :
  iiiI111I = '<a href="{}">' . format ( url )
  oooOOO00o0 = lisp_space ( 2 )
  IIi11I1 = oooOOO00o0 + iiiI111I + o0OO000ooOo + string + "</button></a>" + oooOOO00o0
  if 1 - 1: iIii1I11I1II1
 return ( IIi11I1 )
 if 93 - 93: i1IIi . i11iIiiIii . Oo0Ooo
 if 99 - 99: I11i - I1Ii111 - oO0o % OoO0O00
 if 21 - 21: II111iiii % I1ii11iIi11i . i1IIi - OoooooooOO
 if 4 - 4: OoooooooOO . ooOoO0o
 if 78 - 78: I1ii11iIi11i + I11i - O0
 if 10 - 10: I1Ii111 % I1IiiI
 if 97 - 97: OoooooooOO - I1Ii111
def lisp_print_cour ( string ) :
 OOoo0oo = '<font face="Courier New">{}</font>' . format ( string )
 return ( OOoo0oo )
 if 58 - 58: iIii1I11I1II1 + O0
 if 30 - 30: ooOoO0o % iII111i * OOooOOo - I1ii11iIi11i * Ii1I % ooOoO0o
 if 46 - 46: i11iIiiIii - O0 . oO0o
 if 100 - 100: I1IiiI / o0oOOo0O0Ooo * iII111i . O0 / OOooOOo
 if 83 - 83: I1Ii111
 if 48 - 48: II111iiii * OOooOOo * I1Ii111
 if 50 - 50: IiII % i1IIi
def lisp_print_sans ( string ) :
 OOoo0oo = '<font face="Sans-Serif">{}</font>' . format ( string )
 return ( OOoo0oo )
 if 21 - 21: OoooooooOO - iIii1I11I1II1
 if 93 - 93: oO0o - o0oOOo0O0Ooo % OoOoOO00 . OoOoOO00 - ooOoO0o
 if 90 - 90: ooOoO0o + II111iiii * I1ii11iIi11i / Ii1I . o0oOOo0O0Ooo + o0oOOo0O0Ooo
 if 40 - 40: ooOoO0o / OoOoOO00 % i11iIiiIii % I1ii11iIi11i / I1IiiI
 if 62 - 62: i1IIi - OoOoOO00
 if 62 - 62: i1IIi + Oo0Ooo % IiII
 if 28 - 28: I1ii11iIi11i . i1IIi
def lisp_span ( string , hover_string ) :
 OOoo0oo = '<span title="{}">{}</span>' . format ( hover_string , string )
 return ( OOoo0oo )
 if 10 - 10: OoO0O00 / Oo0Ooo
 if 15 - 15: iII111i . OoOoOO00 / iII111i * I11i - I1IiiI % I1ii11iIi11i
 if 57 - 57: O0 % OoOoOO00 % oO0o
 if 45 - 45: I1ii11iIi11i + II111iiii * i11iIiiIii
 if 13 - 13: OoooooooOO * oO0o - Ii1I / OOooOOo + I11i + IiII
 if 39 - 39: iIii1I11I1II1 - OoooooooOO
 if 81 - 81: I1ii11iIi11i - O0 * OoooooooOO
def lisp_eid_help_hover ( output ) :
 iiIiI = '''Unicast EID format:
  For longest match lookups: 
    <address> or [<iid>]<address>
  For exact match lookups: 
    <prefix> or [<iid>]<prefix>
Multicast EID format:
  For longest match lookups:
    <address>-><group> or
    [<iid>]<address>->[<iid>]<group>'''
 if 87 - 87: ooOoO0o - OoooooooOO + i11iIiiIii
 if 73 - 73: I11i * OoooooooOO . O0 . IiII
 o0oooO = lisp_span ( output , iiIiI )
 return ( o0oooO )
 if 89 - 89: II111iiii / oO0o
 if 14 - 14: OOooOOo . I1IiiI * ooOoO0o + II111iiii - ooOoO0o + OOooOOo
 if 18 - 18: oO0o - o0oOOo0O0Ooo - I1IiiI - I1IiiI
 if 54 - 54: Oo0Ooo + I1IiiI / iII111i . I1IiiI * OoOoOO00
 if 1 - 1: OoOoOO00 * OoO0O00 . i1IIi / Oo0Ooo . I1ii11iIi11i + Oo0Ooo
 if 17 - 17: Oo0Ooo + OoO0O00 / Ii1I / iII111i * OOooOOo
 if 29 - 29: OoO0O00 % OoooooooOO * oO0o / II111iiii - oO0o
def lisp_geo_help_hover ( output ) :
 iiIiI = '''EID format:
    <address> or [<iid>]<address>
    '<name>' or [<iid>]'<name>'
Geo-Point format:
    d-m-s-<N|S>-d-m-s-<W|E> or 
    [<iid>]d-m-s-<N|S>-d-m-s-<W|E>
Geo-Prefix format:
    d-m-s-<N|S>-d-m-s-<W|E>/<km> or
    [<iid>]d-m-s-<N|S>-d-m-s-<W|E>/<km>'''
 if 19 - 19: i11iIiiIii
 if 54 - 54: II111iiii . I11i
 o0oooO = lisp_span ( output , iiIiI )
 return ( o0oooO )
 if 73 - 73: OoOoOO00 . I1IiiI
 if 32 - 32: OoOoOO00 * I1IiiI % ooOoO0o * Ii1I . O0
 if 48 - 48: iII111i * iII111i
 if 13 - 13: Ii1I / I11i + OoOoOO00 . o0oOOo0O0Ooo % ooOoO0o
 if 48 - 48: I1IiiI / i11iIiiIii - o0oOOo0O0Ooo * oO0o / OoooooooOO
 if 89 - 89: iIii1I11I1II1 / I1IiiI - II111iiii / Ii1I . i11iIiiIii . Ii1I
 if 48 - 48: O0 + O0 . I1Ii111 - ooOoO0o
def space ( num ) :
 OOoo0oo = ""
 for ooOooo0OO in range ( num ) : OOoo0oo += "&#160;"
 return ( OOoo0oo )
 if 63 - 63: oO0o
 if 71 - 71: i1IIi . Ii1I * iII111i % OoooooooOO + OOooOOo
 if 36 - 36: IiII
 if 49 - 49: OOooOOo / OoooooooOO / I1IiiI
 if 74 - 74: I1Ii111 % I1ii11iIi11i
 if 7 - 7: II111iiii
 if 27 - 27: oO0o . OoooooooOO + i11iIiiIii
 if 86 - 86: I11i / o0oOOo0O0Ooo - o0oOOo0O0Ooo + I1ii11iIi11i + oO0o
def lisp_get_ephemeral_port ( ) :
 return ( random . randrange ( 32768 , 65535 ) )
 if 33 - 33: o0oOOo0O0Ooo . iII111i . IiII . i1IIi
 if 49 - 49: I1ii11iIi11i
 if 84 - 84: I11i - Oo0Ooo / O0 - I1Ii111
 if 21 - 21: O0 * O0 % I1ii11iIi11i
 if 94 - 94: I11i + II111iiii % i11iIiiIii
 if 8 - 8: ooOoO0o * O0
 if 73 - 73: o0oOOo0O0Ooo / oO0o / I11i / OoO0O00
def lisp_get_data_nonce ( ) :
 return ( random . randint ( 0 , 0xffffff ) )
 if 11 - 11: OoOoOO00 + IiII - OoooooooOO / OoO0O00
 if 34 - 34: ooOoO0o
 if 45 - 45: ooOoO0o / Oo0Ooo / Ii1I
 if 44 - 44: I1ii11iIi11i - Ii1I / II111iiii * OoO0O00 * Oo0Ooo
 if 73 - 73: o0oOOo0O0Ooo - I1IiiI * i1IIi / i11iIiiIii * OOooOOo % II111iiii
 if 56 - 56: OoooooooOO * Oo0Ooo . Oo0Ooo . I1ii11iIi11i
 if 24 - 24: Oo0Ooo . I11i * Ii1I % iII111i / OOooOOo
def lisp_get_control_nonce ( ) :
 return ( random . randint ( 0 , ( 2 ** 64 ) - 1 ) )
 if 58 - 58: I1IiiI - I1ii11iIi11i % O0 . I1IiiI % OoO0O00 % IiII
 if 87 - 87: oO0o - i11iIiiIii
 if 78 - 78: i11iIiiIii / iIii1I11I1II1 - o0oOOo0O0Ooo
 if 23 - 23: I11i
 if 40 - 40: o0oOOo0O0Ooo - II111iiii / Oo0Ooo
 if 14 - 14: I1ii11iIi11i
 if 5 - 5: o0oOOo0O0Ooo . iIii1I11I1II1 % iIii1I11I1II1
 if 56 - 56: OoooooooOO - I11i - i1IIi
 if 8 - 8: I1Ii111 / OOooOOo . I1IiiI + I1ii11iIi11i / i11iIiiIii
def lisp_hex_string ( integer_value ) :
 I1Iii1iI1 = hex ( integer_value ) [ 2 : : ]
 if ( I1Iii1iI1 [ - 1 ] == "L" ) : I1Iii1iI1 = I1Iii1iI1 [ 0 : - 1 ]
 return ( I1Iii1iI1 )
 if 86 - 86: O0
 if 95 - 95: iII111i * OOooOOo . OoOoOO00 . i1IIi . i1IIi - o0oOOo0O0Ooo
 if 26 - 26: iIii1I11I1II1 % i11iIiiIii % I1ii11iIi11i
 if 67 - 67: OoooooooOO
 if 29 - 29: O0 - i11iIiiIii - II111iiii + OOooOOo * IiII
 if 2 - 2: i1IIi - ooOoO0o + I1IiiI . o0oOOo0O0Ooo * o0oOOo0O0Ooo / OoOoOO00
 if 93 - 93: i1IIi
def lisp_get_timestamp ( ) :
 return ( time . time ( ) )
 if 53 - 53: OoooooooOO + Oo0Ooo + oO0o
 if 24 - 24: iII111i - IiII - iII111i * I1ii11iIi11i . OoooooooOO / IiII
 if 66 - 66: Oo0Ooo
 if 97 - 97: i1IIi - OoooooooOO / I1Ii111 * I1IiiI
 if 55 - 55: o0oOOo0O0Ooo . iII111i
 if 87 - 87: o0oOOo0O0Ooo % iIii1I11I1II1
 if 100 - 100: I1Ii111 . I1IiiI * I1Ii111 - I1IiiI . I11i * Ii1I
def lisp_set_timestamp ( seconds ) :
 return ( time . time ( ) + seconds )
 if 89 - 89: OoO0O00 + IiII * I1Ii111
 if 28 - 28: OoooooooOO . oO0o % I1ii11iIi11i / i1IIi / OOooOOo
 if 36 - 36: o0oOOo0O0Ooo + I11i - IiII + iIii1I11I1II1 + OoooooooOO
 if 4 - 4: II111iiii . I11i + Ii1I * I1Ii111 . ooOoO0o
 if 87 - 87: OoOoOO00 / OoO0O00 / i11iIiiIii
 if 74 - 74: oO0o / I1ii11iIi11i % o0oOOo0O0Ooo
 if 88 - 88: OoOoOO00 - i11iIiiIii % o0oOOo0O0Ooo * I11i + I1ii11iIi11i
def lisp_print_elapsed ( ts ) :
 if ( ts == 0 or ts == None ) : return ( "never" )
 Oo = time . time ( ) - ts
 Oo = round ( Oo , 0 )
 return ( str ( datetime . timedelta ( seconds = Oo ) ) )
 if 40 - 40: OoOoOO00 % OoO0O00
 if 62 - 62: o0oOOo0O0Ooo
 if 15 - 15: I11i + Ii1I . OOooOOo * OoO0O00 . OoOoOO00
 if 18 - 18: i1IIi % II111iiii + I1Ii111 % Ii1I
 if 72 - 72: iIii1I11I1II1
 if 45 - 45: Oo0Ooo - o0oOOo0O0Ooo % I1Ii111
 if 38 - 38: I1Ii111 % OOooOOo - OoooooooOO
def lisp_print_future ( ts ) :
 if ( ts == 0 ) : return ( "never" )
 oOo0OOoooO = ts - time . time ( )
 if ( oOo0OOoooO < 0 ) : return ( "expired" )
 oOo0OOoooO = round ( oOo0OOoooO , 0 )
 return ( str ( datetime . timedelta ( seconds = oOo0OOoooO ) ) )
 if 26 - 26: o0oOOo0O0Ooo * IiII . i1IIi
 if 59 - 59: O0 + i1IIi - o0oOOo0O0Ooo
 if 62 - 62: i11iIiiIii % OOooOOo . IiII . OOooOOo
 if 84 - 84: i11iIiiIii * OoO0O00
 if 18 - 18: OOooOOo - Ii1I - OoOoOO00 / I1Ii111 - O0
 if 30 - 30: O0 + I1ii11iIi11i + II111iiii
 if 14 - 14: o0oOOo0O0Ooo / OOooOOo - iIii1I11I1II1 - oO0o % ooOoO0o
 if 49 - 49: ooOoO0o * oO0o / o0oOOo0O0Ooo / Oo0Ooo * iIii1I11I1II1
 if 57 - 57: OoOoOO00 - oO0o / ooOoO0o % i11iIiiIii
 if 3 - 3: iII111i . ooOoO0o % I1IiiI + I1ii11iIi11i
 if 64 - 64: i1IIi
 if 29 - 29: o0oOOo0O0Ooo / i11iIiiIii / I1IiiI % oO0o % i11iIiiIii
 if 18 - 18: OOooOOo + I1Ii111
def lisp_print_eid_tuple ( eid , group ) :
 OO0OO0O = eid . print_prefix ( )
 if ( group . is_null ( ) ) : return ( OO0OO0O )
 if 75 - 75: I11i / o0oOOo0O0Ooo / OOooOOo / IiII % ooOoO0o + II111iiii
 I1III111i = group . print_prefix ( )
 iiI1iii = group . instance_id
 if 79 - 79: OoO0O00 * OoOoOO00 . OoooooooOO - I11i * o0oOOo0O0Ooo
 if ( eid . is_null ( ) or eid . is_exact_match ( group ) ) :
  oooO0 = I1III111i . find ( "]" ) + 1
  return ( "[{}](*, {})" . format ( iiI1iii , I1III111i [ oooO0 : : ] ) )
  if 78 - 78: IiII
  if 83 - 83: iIii1I11I1II1 % OoOoOO00 % o0oOOo0O0Ooo % I1Ii111 . I1ii11iIi11i % O0
 iIiIi1ii = eid . print_sg ( group )
 return ( iIiIi1ii )
 if 28 - 28: iIii1I11I1II1 + iIii1I11I1II1
 if 28 - 28: oO0o
 if 52 - 52: I1IiiI + iIii1I11I1II1
 if 71 - 71: O0 / oO0o
 if 34 - 34: OoOoOO00 . iIii1I11I1II1 % O0
 if 43 - 43: I1ii11iIi11i - iII111i
 if 70 - 70: iII111i / OOooOOo % ooOoO0o - Ii1I
 if 47 - 47: iII111i
def lisp_convert_6to4 ( addr_str ) :
 if ( addr_str . find ( "::ffff:" ) == - 1 ) : return ( addr_str )
 o00Ooo0 = addr_str . split ( ":" )
 return ( o00Ooo0 [ - 1 ] )
 if 62 - 62: OOooOOo + Ii1I - OoOoOO00 * OoOoOO00 . OoOoOO00 + OoooooooOO
 if 77 - 77: iIii1I11I1II1 . Ii1I % oO0o / Ii1I
 if 54 - 54: oO0o + ooOoO0o - Oo0Ooo
 if 35 - 35: Ii1I - Ii1I + i1IIi - O0 - I1Ii111
 if 58 - 58: OoOoOO00 - iII111i - OoooooooOO
 if 96 - 96: iIii1I11I1II1
 if 82 - 82: OoOoOO00 + O0 - IiII % oO0o * i11iIiiIii
 if 15 - 15: o0oOOo0O0Ooo
 if 39 - 39: OOooOOo / I1ii11iIi11i / I1IiiI * I1Ii111
 if 44 - 44: O0 + ooOoO0o . iIii1I11I1II1 + Oo0Ooo / O0 - I11i
 if 83 - 83: IiII * I11i / Oo0Ooo
def lisp_convert_4to6 ( addr_str ) :
 o00Ooo0 = lisp_address ( LISP_AFI_IPV6 , "" , 128 , 0 )
 if ( o00Ooo0 . is_ipv4_string ( addr_str ) ) : addr_str = "::ffff:" + addr_str
 o00Ooo0 . store_address ( addr_str )
 return ( o00Ooo0 )
 if 32 - 32: o0oOOo0O0Ooo + OoOoOO00 - OoooooooOO
 if 39 - 39: OoooooooOO * OOooOOo * O0 . I11i . OoO0O00 + ooOoO0o
 if 9 - 9: OoOoOO00 + oO0o % OoooooooOO + o0oOOo0O0Ooo
 if 56 - 56: OoooooooOO + I1ii11iIi11i - iII111i
 if 24 - 24: o0oOOo0O0Ooo + ooOoO0o + I11i - iIii1I11I1II1
 if 49 - 49: I11i . ooOoO0o * OoOoOO00 % IiII . O0
 if 48 - 48: O0 * Ii1I - O0 / Ii1I + OoOoOO00
 if 52 - 52: OoO0O00 % Ii1I * II111iiii
 if 4 - 4: I11i % O0 - OoooooooOO + ooOoO0o . oO0o % II111iiii
def lisp_gethostbyname ( string ) :
 Iiii1iiiIiI1 = string . split ( "." )
 I11Iii1 = string . split ( ":" )
 i1iIIi1II1iiI = string . split ( "-" )
 if 31 - 31: o0oOOo0O0Ooo % I11i + iIii1I11I1II1 + i11iIiiIii * I1Ii111
 if ( len ( Iiii1iiiIiI1 ) > 1 ) :
  if ( Iiii1iiiIiI1 [ 0 ] . isdigit ( ) ) : return ( string )
  if 45 - 45: OOooOOo * I1Ii111 . ooOoO0o - I1Ii111 + IiII
 if ( len ( I11Iii1 ) > 1 ) :
  try :
   int ( I11Iii1 [ 0 ] , 16 )
   return ( string )
  except :
   pass
   if 34 - 34: OOooOOo . Oo0Ooo
   if 78 - 78: I1ii11iIi11i % I1IiiI / OoooooooOO % OOooOOo - iII111i
   if 2 - 2: iIii1I11I1II1
   if 45 - 45: OoooooooOO / i11iIiiIii
   if 10 - 10: iII111i - oO0o * iIii1I11I1II1 % iIii1I11I1II1 * IiII - I1ii11iIi11i
   if 97 - 97: II111iiii % I1Ii111 + I1Ii111 - OoO0O00 / Ii1I * I1IiiI
   if 17 - 17: Ii1I
 if ( len ( i1iIIi1II1iiI ) == 3 ) :
  for ooOooo0OO in range ( 3 ) :
   try : int ( i1iIIi1II1iiI [ ooOooo0OO ] , 16 )
   except : break
   if 39 - 39: ooOoO0o . II111iiii
   if 45 - 45: oO0o * OoOoOO00 / iIii1I11I1II1
   if 77 - 77: I1Ii111 - I11i
 try :
  o00Ooo0 = socket . gethostbyname ( string )
  return ( o00Ooo0 )
 except :
  if ( lisp_is_alpine ( ) == False ) : return ( "" )
  if 11 - 11: I1ii11iIi11i
  if 26 - 26: iIii1I11I1II1 * I1Ii111 - OOooOOo
  if 27 - 27: I1ii11iIi11i * I1Ii111 - OoO0O00 + Ii1I * Ii1I
  if 55 - 55: ooOoO0o
  if 82 - 82: I1Ii111 - OOooOOo + OoO0O00
 try :
  o00Ooo0 = socket . getaddrinfo ( string , 0 ) [ 0 ]
  if ( o00Ooo0 [ 3 ] != string ) : return ( "" )
  o00Ooo0 = o00Ooo0 [ 4 ] [ 0 ]
 except :
  o00Ooo0 = ""
  if 64 - 64: o0oOOo0O0Ooo . O0 * Ii1I + OoooooooOO - Oo0Ooo . OoooooooOO
 return ( o00Ooo0 )
 if 70 - 70: Oo0Ooo - oO0o . iIii1I11I1II1 % I11i / OoOoOO00 - O0
 if 55 - 55: iII111i - OoO0O00
 if 100 - 100: O0
 if 79 - 79: iIii1I11I1II1
 if 81 - 81: OOooOOo + iIii1I11I1II1 * I1Ii111 - iIii1I11I1II1 . OOooOOo
 if 48 - 48: I11i . OoooooooOO . I1IiiI . OoOoOO00 % I1ii11iIi11i / iII111i
 if 11 - 11: i1IIi % OoO0O00 % iII111i
 if 99 - 99: ooOoO0o / iIii1I11I1II1 - Ii1I * I1ii11iIi11i % I1IiiI
def lisp_ip_checksum ( data ) :
 if ( len ( data ) < 20 ) :
  lprint ( "IPv4 packet too short, length {}" . format ( len ( data ) ) )
  return ( data )
  if 13 - 13: OoO0O00
  if 70 - 70: I1Ii111 + O0 . oO0o * Ii1I
 ii = binascii . hexlify ( data )
 if 9 - 9: OoO0O00 * Ii1I % i1IIi % oO0o
 if 53 - 53: oO0o * OoooooooOO . OoOoOO00
 if 96 - 96: I1IiiI % i1IIi . o0oOOo0O0Ooo . O0
 if 37 - 37: i1IIi - OOooOOo % OoooooooOO / OOooOOo % ooOoO0o
 iiIiII11i1 = 0
 for ooOooo0OO in range ( 0 , 40 , 4 ) :
  iiIiII11i1 += int ( ii [ ooOooo0OO : ooOooo0OO + 4 ] , 16 )
  if 93 - 93: OoOoOO00 % iIii1I11I1II1
  if 90 - 90: I1IiiI - OOooOOo / Ii1I / O0 / I11i
  if 87 - 87: OoOoOO00 / IiII + iIii1I11I1II1
  if 93 - 93: iIii1I11I1II1 + oO0o % ooOoO0o
  if 21 - 21: OOooOOo
 iiIiII11i1 = ( iiIiII11i1 >> 16 ) + ( iiIiII11i1 & 0xffff )
 iiIiII11i1 += iiIiII11i1 >> 16
 iiIiII11i1 = socket . htons ( ~ iiIiII11i1 & 0xffff )
 if 6 - 6: IiII
 if 46 - 46: IiII + oO0o
 if 79 - 79: OoooooooOO - IiII * IiII . OoOoOO00
 if 100 - 100: II111iiii * I11i % I1IiiI / I1ii11iIi11i
 iiIiII11i1 = struct . pack ( "H" , iiIiII11i1 )
 ii = data [ 0 : 10 ] + iiIiII11i1 + data [ 12 : : ]
 return ( ii )
 if 90 - 90: I1ii11iIi11i . ooOoO0o . OoOoOO00 . Ii1I
 if 4 - 4: Ii1I + OoOoOO00 % I1ii11iIi11i / i11iIiiIii
 if 74 - 74: II111iiii . O0 - I1IiiI + IiII % i11iIiiIii % OoOoOO00
 if 78 - 78: Ii1I + OoOoOO00 + IiII - IiII . i11iIiiIii / OoO0O00
 if 27 - 27: Ii1I - O0 % I11i * I1Ii111 . IiII % iIii1I11I1II1
 if 37 - 37: OoooooooOO + O0 - i1IIi % ooOoO0o
 if 24 - 24: OoOoOO00
def lisp_get_interface_address ( device ) :
 if 94 - 94: i1IIi * i1IIi % II111iiii + OOooOOo
 if 28 - 28: I1IiiI
 if 49 - 49: I11i . o0oOOo0O0Ooo % oO0o / Ii1I
 if 95 - 95: O0 * OoOoOO00 * IiII . ooOoO0o / iIii1I11I1II1
 if ( device not in netifaces . interfaces ( ) ) : return ( None )
 if 28 - 28: IiII + oO0o - ooOoO0o / iIii1I11I1II1 - I1IiiI
 if 45 - 45: O0 / i1IIi * oO0o * OoO0O00
 if 35 - 35: I1ii11iIi11i / iII111i % I1IiiI + iIii1I11I1II1
 if 79 - 79: OoOoOO00 / ooOoO0o
 oOo00o = netifaces . ifaddresses ( device )
 if ( oOo00o . has_key ( netifaces . AF_INET ) == False ) : return ( None )
 if 98 - 98: OOooOOo % i1IIi . I1IiiI . II111iiii . I1ii11iIi11i / i11iIiiIii
 if 32 - 32: o0oOOo0O0Ooo + I1IiiI . I1Ii111
 if 41 - 41: OoOoOO00 . i11iIiiIii / I11i
 if 98 - 98: OoOoOO00 % II111iiii
 OoO0O000 = lisp_address ( LISP_AFI_IPV4 , "" , 32 , 0 )
 if 14 - 14: OoO0O00 / OoO0O00 * O0 . oO0o
 for o00Ooo0 in oOo00o [ netifaces . AF_INET ] :
  oooOO0oOooO00 = o00Ooo0 [ "addr" ]
  OoO0O000 . store_address ( oooOO0oOooO00 )
  return ( OoO0O000 )
  if 37 - 37: IiII
 return ( None )
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
 for o00Ooo0 in netifaces . ifaddresses ( "lo" ) [ netifaces . AF_INET ] :
  if ( o00Ooo0 [ "peer" ] == "127.0.0.1" ) : continue
  return ( o00Ooo0 [ "peer" ] )
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
  i1iIIi1II1iiI = o00O [ netifaces . AF_LINK ] [ 0 ] [ "addr" ]
  i1iIIi1II1iiI = i1iIIi1II1iiI . replace ( ":" , "" )
  if 88 - 88: OOooOOo % Oo0Ooo - iII111i - OoOoOO00 % i11iIiiIii
  if 6 - 6: Ii1I - OoO0O00 . I1IiiI - O0
  if 16 - 16: iII111i * iII111i % Ii1I % I1IiiI
  if 48 - 48: OOooOOo / Ii1I % OoO0O00 / IiII / I1Ii111
  if 89 - 89: I1Ii111 * oO0o
  if ( len ( i1iIIi1II1iiI ) < 12 ) : continue
  if 63 - 63: OoooooooOO * OoooooooOO % OoO0O00 + O0 / I1Ii111 + iIii1I11I1II1
  if ( lisp_mymacs . has_key ( i1iIIi1II1iiI ) == False ) : lisp_mymacs [ i1iIIi1II1iiI ] = [ ]
  lisp_mymacs [ i1iIIi1II1iiI ] . append ( oOOOo0o )
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
 o00Ooo0 = ""
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
 o00Ooo0 = ""
 Oo0O0oo0o00o0 = Oo0O0oo0o00o0 . split ( "\n" )
 if 91 - 91: II111iiii - O0 . iIii1I11I1II1 . O0 + I1ii11iIi11i - II111iiii
 for iiIiiIi1 in Oo0O0oo0o00o0 :
  iiiI111I = iiIiiIi1 . split ( ) [ 1 ]
  if ( o0OO00oo0O == False ) : iiiI111I = iiiI111I . split ( "/" ) [ 0 ]
  I1Ii11i = lisp_address ( LISP_AFI_IPV4 , iiiI111I , 32 , 0 )
  return ( I1Ii11i )
  if 19 - 19: IiII - o0oOOo0O0Ooo . iIii1I11I1II1 . OoOoOO00 / OOooOOo
 return ( lisp_address ( LISP_AFI_IPV4 , o00Ooo0 , 32 , 0 ) )
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
 oooO0 = 1
 Ii11iiI1 = os . getenv ( "LISP_ADDR_SELECT" )
 if ( Ii11iiI1 != None and Ii11iiI1 != "" ) :
  Ii11iiI1 = Ii11iiI1 . split ( ":" )
  if ( len ( Ii11iiI1 ) == 2 ) :
   II1iI1IIi = Ii11iiI1 [ 0 ]
   oooO0 = Ii11iiI1 [ 1 ]
  else :
   if ( Ii11iiI1 [ 0 ] . isdigit ( ) ) :
    oooO0 = Ii11iiI1 [ 0 ]
   else :
    II1iI1IIi = Ii11iiI1 [ 0 ]
    if 71 - 71: o0oOOo0O0Ooo / OOooOOo % OOooOOo
    if 89 - 89: OoooooooOO + i11iIiiIii / I11i + iIii1I11I1II1 % ooOoO0o
  oooO0 = 1 if ( oooO0 == "" ) else int ( oooO0 )
  if 29 - 29: I1ii11iIi11i
  if 53 - 53: i11iIiiIii . I1ii11iIi11i % Ii1I / ooOoO0o % iIii1I11I1II1
 iIiIii1I1 = [ None , None , None ]
 O0OOOOo0 = lisp_address ( LISP_AFI_IPV4 , "" , 32 , 0 )
 OOooO0Oo00 = lisp_address ( LISP_AFI_IPV6 , "" , 128 , 0 )
 iIIIIIIIiIII = None
 if 94 - 94: iII111i * iIii1I11I1II1 . I11i
 for oOOOo0o in netifaces . interfaces ( ) :
  if ( II1iI1IIi != None and II1iI1IIi != oOOOo0o ) : continue
  oOo00o = netifaces . ifaddresses ( oOOOo0o )
  if ( oOo00o == { } ) : continue
  if 13 - 13: iIii1I11I1II1 * OoOoOO00 / I1Ii111 % ooOoO0o + oO0o
  if 41 - 41: I1ii11iIi11i
  if 5 - 5: Oo0Ooo
  if 100 - 100: Ii1I + iIii1I11I1II1
  iIIIIIIIiIII = lisp_get_interface_instance_id ( oOOOo0o , None )
  if 59 - 59: IiII
  if 89 - 89: OoOoOO00 % iIii1I11I1II1
  if 35 - 35: I1ii11iIi11i + I1Ii111 - OoOoOO00 % oO0o % o0oOOo0O0Ooo % OoOoOO00
  if 45 - 45: I1IiiI * OOooOOo % OoO0O00
  if ( oOo00o . has_key ( netifaces . AF_INET ) ) :
   Iiii1iiiIiI1 = oOo00o [ netifaces . AF_INET ]
   i111I11I = 0
   for o00Ooo0 in Iiii1iiiIiI1 :
    O0OOOOo0 . store_address ( o00Ooo0 [ "addr" ] )
    if ( O0OOOOo0 . is_ipv4_loopback ( ) ) : continue
    if ( O0OOOOo0 . is_ipv4_link_local ( ) ) : continue
    if ( O0OOOOo0 . address == 0 ) : continue
    i111I11I += 1
    O0OOOOo0 . instance_id = iIIIIIIIiIII
    if ( II1iI1IIi == None and
 lisp_db_for_lookups . lookup_cache ( O0OOOOo0 , False ) ) : continue
    iIiIii1I1 [ 0 ] = O0OOOOo0
    if ( i111I11I == oooO0 ) : break
    if 80 - 80: iIii1I11I1II1 - OoooooooOO - I1ii11iIi11i - I1ii11iIi11i . OoooooooOO
    if 48 - 48: I1Ii111 . i11iIiiIii / i1IIi % IiII % iII111i + oO0o
  if ( oOo00o . has_key ( netifaces . AF_INET6 ) ) :
   I11Iii1 = oOo00o [ netifaces . AF_INET6 ]
   i111I11I = 0
   for o00Ooo0 in I11Iii1 :
    oooOO0oOooO00 = o00Ooo0 [ "addr" ]
    OOooO0Oo00 . store_address ( oooOO0oOooO00 )
    if ( OOooO0Oo00 . is_ipv6_string_link_local ( oooOO0oOooO00 ) ) : continue
    if ( OOooO0Oo00 . is_ipv6_loopback ( ) ) : continue
    i111I11I += 1
    OOooO0Oo00 . instance_id = iIIIIIIIiIII
    if ( II1iI1IIi == None and
 lisp_db_for_lookups . lookup_cache ( OOooO0Oo00 , False ) ) : continue
    iIiIii1I1 [ 1 ] = OOooO0Oo00
    if ( i111I11I == oooO0 ) : break
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
   for o00Ooo0 in oo [ netifaces . AF_INET ] :
    iiiI111I = o00Ooo0 [ "addr" ]
    if ( iiiI111I . find ( "127.0.0.1" ) != - 1 ) : continue
    I1 . append ( iiiI111I )
    if 81 - 81: I1IiiI - iIii1I11I1II1 / I1IiiI / O0
    if 34 - 34: Ii1I * Ii1I - I1ii11iIi11i - O0 . i11iIiiIii
  if ( oo . has_key ( netifaces . AF_INET6 ) ) :
   for o00Ooo0 in oo [ netifaces . AF_INET6 ] :
    iiiI111I = o00Ooo0 [ "addr" ]
    if ( iiiI111I == "::1" ) : continue
    if ( iiiI111I [ 0 : 5 ] == "fe80:" ) : continue
    I1 . append ( iiiI111I )
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
  oO = iiIiiIi1 . split ( "rle-address = " ) [ 1 ]
  Iii11111iiI = int ( oO . split ( "." ) [ 0 ] )
  if ( Iii11111iiI >= 224 and Iii11111iiI < 240 ) : Ooi1IIii11i1I1 . append ( oO )
  if 67 - 67: o0oOOo0O0Ooo
 return ( Ooi1IIii11i1I1 )
 if 76 - 76: OoOoOO00 - I1IiiI + OOooOOo + I11i
 if 50 - 50: I1Ii111 + I1ii11iIi11i
 if 4 - 4: IiII / Oo0Ooo
 if 31 - 31: I1Ii111 - I1ii11iIi11i + O0 . Oo0Ooo + OoOoOO00 - oO0o
 if 43 - 43: iII111i + Oo0Ooo / OoooooooOO
 if 24 - 24: O0 + o0oOOo0O0Ooo * Ii1I - I1Ii111
 if 10 - 10: i11iIiiIii
 if 21 - 21: I1IiiI / iII111i
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
  self . inner_dport = 0
  self . lisp_header = lisp_data_header ( )
  self . packet = packet
  self . inner_version = 0
  self . outer_version = 0
  self . encap_port = LISP_DATA_PORT
  self . inner_is_fragment = False
  self . packet_error = ""
  if 69 - 69: ooOoO0o % ooOoO0o
  if 76 - 76: i11iIiiIii * iII111i / OoO0O00 % I1ii11iIi11i + OOooOOo
 def encode ( self , nonce ) :
  if 48 - 48: iIii1I11I1II1 % i1IIi + OoOoOO00 % o0oOOo0O0Ooo
  if 79 - 79: OoOoOO00 % I1IiiI % Ii1I / i1IIi % OoO0O00
  if 56 - 56: iIii1I11I1II1 - i11iIiiIii * iII111i
  if 84 - 84: OOooOOo + Ii1I + o0oOOo0O0Ooo
  if 33 - 33: Ii1I
  if ( self . outer_source . is_null ( ) ) : return ( None )
  if 93 - 93: ooOoO0o
  if 34 - 34: oO0o - ooOoO0o * Oo0Ooo / o0oOOo0O0Ooo
  if 19 - 19: I1ii11iIi11i
  if 46 - 46: iIii1I11I1II1 . i11iIiiIii - OoOoOO00 % O0 / II111iiii * i1IIi
  if 66 - 66: O0
  if 52 - 52: OoO0O00 * OoooooooOO
  if ( nonce == None ) :
   self . lisp_header . nonce ( lisp_get_data_nonce ( ) )
  elif ( self . lisp_header . is_request_nonce ( nonce ) ) :
   self . lisp_header . request_nonce ( nonce )
  else :
   self . lisp_header . nonce ( nonce )
   if 12 - 12: O0 + IiII * i1IIi . OoO0O00
  self . lisp_header . instance_id ( self . inner_dest . instance_id )
  if 71 - 71: I1Ii111 - o0oOOo0O0Ooo - OOooOOo
  if 28 - 28: iIii1I11I1II1
  if 7 - 7: o0oOOo0O0Ooo % IiII * OoOoOO00
  if 58 - 58: IiII / I11i + II111iiii % iII111i - OoooooooOO
  if 25 - 25: OoOoOO00 % OoooooooOO * Oo0Ooo - i1IIi * II111iiii * oO0o
  if 30 - 30: I11i % OoOoOO00 / I1ii11iIi11i * O0 * Ii1I . I1IiiI
  self . lisp_header . key_id ( 0 )
  iIi11I11 = ( self . lisp_header . get_instance_id ( ) == 0xffffff )
  if ( lisp_data_plane_security and iIi11I11 == False ) :
   oooOO0oOooO00 = self . outer_dest . print_address_no_iid ( ) + ":" + str ( self . encap_port )
   if 40 - 40: iIii1I11I1II1
   if ( lisp_crypto_keys_by_rloc_encap . has_key ( oooOO0oOooO00 ) ) :
    oOoOo0o00o = lisp_crypto_keys_by_rloc_encap [ oooOO0oOooO00 ]
    if ( oOoOo0o00o [ 1 ] ) :
     oOoOo0o00o [ 1 ] . use_count += 1
     iIIi1 , ooo0o0 = self . encrypt ( oOoOo0o00o [ 1 ] , oooOO0oOooO00 )
     if ( ooo0o0 ) : self . packet = iIIi1
     if 84 - 84: I11i - Oo0Ooo * O0 / Ii1I . Ii1I
     if 93 - 93: O0 / ooOoO0o + I1IiiI
     if 20 - 20: IiII / iII111i % OoooooooOO / iIii1I11I1II1 + I1IiiI
     if 57 - 57: o0oOOo0O0Ooo / I1Ii111
     if 13 - 13: OoooooooOO + OoO0O00
     if 32 - 32: O0 + oO0o % Oo0Ooo
     if 7 - 7: I1ii11iIi11i / ooOoO0o
     if 11 - 11: IiII * ooOoO0o / ooOoO0o - OOooOOo
  self . udp_checksum = 0
  if ( self . encap_port == LISP_DATA_PORT ) :
   if ( lisp_crypto_ephem_port == None ) :
    self . hash_packet ( )
   else :
    self . udp_sport = lisp_crypto_ephem_port
    if 68 - 68: I1IiiI % IiII - IiII / I1IiiI + I1ii11iIi11i - Oo0Ooo
  else :
   self . udp_sport = LISP_DATA_PORT
   if 65 - 65: ooOoO0o - i1IIi
  self . udp_dport = self . encap_port
  self . udp_length = len ( self . packet ) + 16
  if 62 - 62: I11i / oO0o % Oo0Ooo . OoooooooOO / i11iIiiIii / I1Ii111
  if 60 - 60: I1IiiI % oO0o / o0oOOo0O0Ooo % oO0o * i11iIiiIii / iII111i
  if 34 - 34: I1Ii111 - OOooOOo
  if 25 - 25: oO0o % I1IiiI + i11iIiiIii + O0 * OoooooooOO
  if ( self . outer_version == 4 ) :
   ooO0 = socket . htons ( self . udp_sport )
   o0 = socket . htons ( self . udp_dport )
  else :
   ooO0 = self . udp_sport
   o0 = self . udp_dport
   if 32 - 32: OoooooooOO / II111iiii / oO0o + Ii1I / O0
   if 98 - 98: OoO0O00 / I11i - Ii1I
  o0 = socket . htons ( self . udp_dport ) if self . outer_version == 4 else self . udp_dport
  if 82 - 82: Oo0Ooo . Ii1I * I1ii11iIi11i * I11i . II111iiii
  if 47 - 47: oO0o + iIii1I11I1II1 . OoOoOO00
  iI = struct . pack ( "HHHH" , ooO0 , o0 , socket . htons ( self . udp_length ) ,
 self . udp_checksum )
  if 73 - 73: I1Ii111 * Oo0Ooo * OoOoOO00
  if 65 - 65: i11iIiiIii + Oo0Ooo * OoooooooOO - OoO0O00
  if 26 - 26: o0oOOo0O0Ooo % OOooOOo + OOooOOo % I11i * i11iIiiIii / iII111i
  if 64 - 64: oO0o % OoOoOO00 / II111iiii % ooOoO0o - iII111i
  I1II1IiI1 = self . lisp_header . encode ( )
  if 26 - 26: OOooOOo * Oo0Ooo
  if 31 - 31: I11i * oO0o . Ii1I
  if 35 - 35: I11i
  if 94 - 94: ooOoO0o / i11iIiiIii % O0
  if 70 - 70: I11i - Oo0Ooo / OoooooooOO % OoooooooOO
  if ( self . outer_version == 4 ) :
   oooo0o0OOO0 = socket . htons ( self . udp_length + 20 )
   iiIII1 = socket . htons ( 0x4000 )
   iiI1iIiI111 = struct . pack ( "BBHHHBBH" , 0x45 , self . outer_tos , oooo0o0OOO0 , 0xdfdf ,
 iiIII1 , self . outer_ttl , 17 , 0 )
   iiI1iIiI111 += self . outer_source . pack_address ( )
   iiI1iIiI111 += self . outer_dest . pack_address ( )
   iiI1iIiI111 = lisp_ip_checksum ( iiI1iIiI111 )
  elif ( self . outer_version == 6 ) :
   iiI1iIiI111 = ""
   if 48 - 48: Oo0Ooo + ooOoO0o * iII111i
   if 95 - 95: O0 + I1IiiI + OoOoOO00 . OOooOOo
   if 73 - 73: oO0o . II111iiii * iII111i % oO0o + OoOoOO00 - OoO0O00
   if 19 - 19: iII111i * Oo0Ooo . iII111i . OoO0O00 / OoO0O00 - oO0o
   if 9 - 9: I1Ii111 * IiII * I1Ii111
   if 74 - 74: iIii1I11I1II1 / o0oOOo0O0Ooo
   if 58 - 58: iIii1I11I1II1 - I1IiiI % o0oOOo0O0Ooo % OoooooooOO * iIii1I11I1II1 + OOooOOo
  else :
   return ( None )
   if 25 - 25: OOooOOo % O0
   if 44 - 44: I1Ii111 . Ii1I * II111iiii / IiII + iIii1I11I1II1
  self . packet = iiI1iIiI111 + iI + I1II1IiI1 + self . packet
  return ( self )
  if 14 - 14: O0 % IiII % Ii1I * oO0o
  if 65 - 65: I11i % oO0o + I1ii11iIi11i
 def cipher_pad ( self , packet ) :
  Oooo = len ( packet )
  if ( ( Oooo % 16 ) != 0 ) :
   OoO00OooO0 = ( ( Oooo / 16 ) + 1 ) * 16
   packet = packet . ljust ( OoO00OooO0 )
   if 98 - 98: OOooOOo + Ii1I
  return ( packet )
  if 52 - 52: Oo0Ooo / OoOoOO00 - I1Ii111 . iII111i
  if 50 - 50: iIii1I11I1II1 - iII111i - I11i
 def encrypt ( self , key , addr_str ) :
  if ( key == None or key . shared_key == None ) :
   return ( [ self . packet , False ] )
   if 60 - 60: iIii1I11I1II1 * ooOoO0o
   if 71 - 71: OoOoOO00 % Oo0Ooo % ooOoO0o
   if 34 - 34: I11i / I11i % IiII . OoOoOO00 / Oo0Ooo
   if 99 - 99: ooOoO0o * I1IiiI - ooOoO0o % Ii1I
   if 40 - 40: OOooOOo / IiII / iIii1I11I1II1 + Ii1I
  iIIi1 = self . cipher_pad ( self . packet )
  O0Ooo0ooo00o = key . get_iv ( )
  if 73 - 73: ooOoO0o % ooOoO0o . iII111i + I1Ii111
  o0O0oo0OO0O = lisp_get_timestamp ( )
  Ii1IOOooO00OO = None
  if ( key . cipher_suite == LISP_CS_25519_CHACHA ) :
   O00OoOOoo = chacha . ChaCha ( key . encrypt_key , O0Ooo0ooo00o ) . encrypt
  elif ( key . cipher_suite == LISP_CS_25519_GCM ) :
   IiIIi11i = binascii . unhexlify ( key . encrypt_key )
   try :
    IIii11i = AES . new ( IiIIi11i , AES . MODE_GCM , O0Ooo0ooo00o )
    O00OoOOoo = IIii11i . encrypt
    Ii1IOOooO00OO = IIii11i . digest
   except :
    lprint ( "You need AES-GCM, do a 'pip install pycryptodome'" )
    return ( [ self . packet , False ] )
    if 82 - 82: I1ii11iIi11i
  else :
   IiIIi11i = binascii . unhexlify ( key . encrypt_key )
   O00OoOOoo = AES . new ( IiIIi11i , AES . MODE_CBC , O0Ooo0ooo00o ) . encrypt
   if 54 - 54: o0oOOo0O0Ooo + I11i - iIii1I11I1II1 % ooOoO0o % IiII
   if 19 - 19: I1ii11iIi11i / iIii1I11I1II1 % i1IIi . OoooooooOO
  O0oO0oo0O0 = O00OoOOoo ( iIIi1 )
  if 66 - 66: OOooOOo - ooOoO0o - Oo0Ooo
  if ( O0oO0oo0O0 == None ) : return ( [ self . packet , False ] )
  o0O0oo0OO0O = int ( str ( time . time ( ) - o0O0oo0OO0O ) . split ( "." ) [ 1 ] [ 0 : 6 ] )
  if 54 - 54: iII111i . i1IIi
  if 19 - 19: ooOoO0o % oO0o
  if 22 - 22: oO0o . II111iiii . Oo0Ooo
  if 91 - 91: II111iiii . OOooOOo + o0oOOo0O0Ooo
  if 8 - 8: OOooOOo * Oo0Ooo / iII111i - OoO0O00 - OoooooooOO
  if 100 - 100: oO0o . iIii1I11I1II1 . iIii1I11I1II1
  if ( Ii1IOOooO00OO != None ) : O0oO0oo0O0 += Ii1IOOooO00OO ( )
  if 55 - 55: oO0o
  if 37 - 37: IiII / i11iIiiIii / Oo0Ooo
  if 97 - 97: I1Ii111 . I11i / I1IiiI
  if 83 - 83: I11i - I1ii11iIi11i * oO0o
  if 90 - 90: Oo0Ooo * I1IiiI
  self . lisp_header . key_id ( key . key_id )
  I1II1IiI1 = self . lisp_header . encode ( )
  if 75 - 75: I1ii11iIi11i - OoOoOO00 * i11iIiiIii . OoooooooOO - Oo0Ooo . I11i
  I1iI1i11IiI11 = key . do_icv ( I1II1IiI1 + O0Ooo0ooo00o + O0oO0oo0O0 , O0Ooo0ooo00o )
  if 82 - 82: I1Ii111 * OoO0O00
  i1 = 4 if ( key . do_poly ) else 8
  if 95 - 95: O0
  O00OO0O = bold ( "Encrypt" , False )
  O0OO00000o00 = bold ( key . cipher_suite_string , False )
  addr_str = "RLOC: " + red ( addr_str , False )
  OOO000Oo = "poly" if key . do_poly else "sha256"
  OOO000Oo = bold ( OOO000Oo , False )
  I1IIIi1i = "ICV({}): 0x{}...{}" . format ( OOO000Oo , I1iI1i11IiI11 [ 0 : i1 ] , I1iI1i11IiI11 [ - i1 : : ] )
  dprint ( "{} for key-id: {}, {}, {}, {}-time: {} usec" . format ( O00OO0O , key . key_id , addr_str , I1IIIi1i , O0OO00000o00 , o0O0oo0OO0O ) )
  if 54 - 54: II111iiii . i1IIi / I1ii11iIi11i % I1IiiI / I1Ii111
  if 65 - 65: OoOoOO00 . OoOoOO00 - oO0o + Oo0Ooo / i11iIiiIii
  I1iI1i11IiI11 = int ( I1iI1i11IiI11 , 16 )
  if ( key . do_poly ) :
   ooOoOo = byte_swap_64 ( ( I1iI1i11IiI11 >> 64 ) & LISP_8_64_MASK )
   iIi = byte_swap_64 ( I1iI1i11IiI11 & LISP_8_64_MASK )
   I1iI1i11IiI11 = struct . pack ( "QQ" , ooOoOo , iIi )
  else :
   ooOoOo = byte_swap_64 ( ( I1iI1i11IiI11 >> 96 ) & LISP_8_64_MASK )
   iIi = byte_swap_64 ( ( I1iI1i11IiI11 >> 32 ) & LISP_8_64_MASK )
   ii1iI1i = socket . htonl ( I1iI1i11IiI11 & 0xffffffff )
   I1iI1i11IiI11 = struct . pack ( "QQI" , ooOoOo , iIi , ii1iI1i )
   if 36 - 36: IiII + OoooooooOO / i11iIiiIii
   if 40 - 40: OoooooooOO * OoOoOO00 / II111iiii - I1ii11iIi11i + Ii1I
  return ( [ O0Ooo0ooo00o + O0oO0oo0O0 + I1iI1i11IiI11 , True ] )
  if 72 - 72: IiII % o0oOOo0O0Ooo
  if 93 - 93: iIii1I11I1II1 + i11iIiiIii . o0oOOo0O0Ooo . i1IIi % I1IiiI % ooOoO0o
 def decrypt ( self , packet , header_length , key , addr_str ) :
  if 74 - 74: OoOoOO00 / i1IIi % OoooooooOO
  if 52 - 52: IiII % ooOoO0o
  if 25 - 25: I11i / I11i % OoooooooOO - I1ii11iIi11i * oO0o
  if 23 - 23: i11iIiiIii
  if 100 - 100: oO0o + O0 . I1IiiI + i1IIi - OoOoOO00 + o0oOOo0O0Ooo
  if 65 - 65: II111iiii / Oo0Ooo
  if ( key . do_poly ) :
   ooOoOo , iIi = struct . unpack ( "QQ" , packet [ - 16 : : ] )
   iiII1i = byte_swap_64 ( ooOoOo ) << 64
   iiII1i |= byte_swap_64 ( iIi )
   iiII1i = lisp_hex_string ( iiII1i ) . zfill ( 32 )
   packet = packet [ 0 : - 16 ]
   i1 = 4
   IiiiI1 = bold ( "poly" , False )
  else :
   ooOoOo , iIi , ii1iI1i = struct . unpack ( "QQI" , packet [ - 20 : : ] )
   iiII1i = byte_swap_64 ( ooOoOo ) << 96
   iiII1i |= byte_swap_64 ( iIi ) << 32
   iiII1i |= socket . htonl ( ii1iI1i )
   iiII1i = lisp_hex_string ( iiII1i ) . zfill ( 40 )
   packet = packet [ 0 : - 20 ]
   i1 = 8
   IiiiI1 = bold ( "sha" , False )
   if 34 - 34: Ii1I + Oo0Ooo - i1IIi - IiII + iIii1I11I1II1
  I1II1IiI1 = self . lisp_header . encode ( )
  if 75 - 75: I1ii11iIi11i
  if 92 - 92: I11i / O0 * I1IiiI - I11i
  if 99 - 99: i11iIiiIii % OoooooooOO
  if 56 - 56: IiII * I1Ii111
  if ( key . cipher_suite == LISP_CS_25519_CHACHA ) :
   O00oO0O = 8
   O0OO00000o00 = bold ( "chacha" , False )
  elif ( key . cipher_suite == LISP_CS_25519_GCM ) :
   O00oO0O = 12
   O0OO00000o00 = bold ( "aes-gcm" , False )
  else :
   O00oO0O = 16
   O0OO00000o00 = bold ( "aes-cbc" , False )
   if 3 - 3: iIii1I11I1II1 % I1ii11iIi11i . OOooOOo % I11i
  O0Ooo0ooo00o = packet [ 0 : O00oO0O ]
  if 40 - 40: ooOoO0o * Ii1I . Ii1I + II111iiii + OoooooooOO
  if 17 - 17: IiII % Ii1I
  if 46 - 46: I1IiiI - I11i / OoooooooOO - i1IIi . i11iIiiIii
  if 15 - 15: II111iiii * oO0o % iII111i / i11iIiiIii - oO0o + Oo0Ooo
  I1IIii11 = key . do_icv ( I1II1IiI1 + packet , O0Ooo0ooo00o )
  if 22 - 22: ooOoO0o / ooOoO0o - Ii1I % I11i . OOooOOo + IiII
  OooO00oo0O0 = "0x{}...{}" . format ( iiII1i [ 0 : i1 ] , iiII1i [ - i1 : : ] )
  i1iI = "0x{}...{}" . format ( I1IIii11 [ 0 : i1 ] , I1IIii11 [ - i1 : : ] )
  if 73 - 73: OoooooooOO . Oo0Ooo / O0 - O0
  if ( I1IIii11 != iiII1i ) :
   self . packet_error = "ICV-error"
   IiI11IIi11Iii = O0OO00000o00 + "/" + IiiiI1
   ii11i1I1i = bold ( "ICV failed ({})" . format ( IiI11IIi11Iii ) , False )
   I1IIIi1i = "packet-ICV {} != computed-ICV {}" . format ( OooO00oo0O0 , i1iI )
   dprint ( ( "{} from RLOC {}, receive-port: {}, key-id: {}, " + "packet dropped, {}" ) . format ( ii11i1I1i , red ( addr_str , False ) ,
   # OoO0O00 - I1IiiI . OoooooooOO
 self . udp_sport , key . key_id , I1IIIi1i ) )
   dprint ( "{}" . format ( key . print_keys ( ) ) )
   if 6 - 6: iIii1I11I1II1 - iIii1I11I1II1 % o0oOOo0O0Ooo / iIii1I11I1II1 * I1Ii111
   if 3 - 3: OOooOOo . IiII / Oo0Ooo
   if 89 - 89: OoooooooOO . iIii1I11I1II1 . Oo0Ooo * iIii1I11I1II1 - I1Ii111
   if 92 - 92: OoooooooOO - I1ii11iIi11i - OoooooooOO % I1IiiI % I1IiiI % iIii1I11I1II1
   if 92 - 92: iII111i * O0 % I1Ii111 . iIii1I11I1II1
   if 66 - 66: I11i + Ii1I
   lisp_retry_decap_keys ( addr_str , I1II1IiI1 + packet , O0Ooo0ooo00o , iiII1i )
   return ( [ None , False ] )
   if 48 - 48: I1ii11iIi11i
   if 96 - 96: ooOoO0o . OoooooooOO
   if 39 - 39: OOooOOo + OoO0O00
   if 80 - 80: OOooOOo % OoO0O00 / OoOoOO00
   if 54 - 54: Oo0Ooo % OoO0O00 - OOooOOo - I11i
  packet = packet [ O00oO0O : : ]
  if 71 - 71: ooOoO0o . i11iIiiIii
  if 56 - 56: O0 * iII111i + iII111i * iIii1I11I1II1 / ooOoO0o * I1Ii111
  if 25 - 25: iIii1I11I1II1 . I11i * i11iIiiIii + Oo0Ooo * I11i
  if 67 - 67: iII111i
  o0O0oo0OO0O = lisp_get_timestamp ( )
  if ( key . cipher_suite == LISP_CS_25519_CHACHA ) :
   oooO0o = chacha . ChaCha ( key . encrypt_key , O0Ooo0ooo00o ) . decrypt
  elif ( key . cipher_suite == LISP_CS_25519_GCM ) :
   IiIIi11i = binascii . unhexlify ( key . encrypt_key )
   try :
    oooO0o = AES . new ( IiIIi11i , AES . MODE_GCM , O0Ooo0ooo00o ) . decrypt
   except :
    self . packet_error = "no-decrypt-key"
    lprint ( "You need AES-GCM, do a 'pip install pycryptodome'" )
    return ( [ None , False ] )
    if 19 - 19: OOooOOo % OoO0O00 / Ii1I + II111iiii % OoooooooOO
  else :
   if ( ( len ( packet ) % 16 ) != 0 ) :
    dprint ( "Ciphertext not multiple of 16 bytes, packet dropped" )
    return ( [ None , False ] )
    if 89 - 89: Ii1I
   IiIIi11i = binascii . unhexlify ( key . encrypt_key )
   oooO0o = AES . new ( IiIIi11i , AES . MODE_CBC , O0Ooo0ooo00o ) . decrypt
   if 51 - 51: iII111i
   if 68 - 68: iII111i - o0oOOo0O0Ooo * OoO0O00 % ooOoO0o . ooOoO0o - iIii1I11I1II1
  Ii1IOoO0o0O = oooO0o ( packet )
  o0O0oo0OO0O = int ( str ( time . time ( ) - o0O0oo0OO0O ) . split ( "." ) [ 1 ] [ 0 : 6 ] )
  if 20 - 20: O0
  if 61 - 61: II111iiii . O0 - Ii1I - I1ii11iIi11i / i11iIiiIii - II111iiii
  if 98 - 98: Ii1I - I1IiiI . i11iIiiIii * Oo0Ooo
  if 29 - 29: Ii1I / ooOoO0o % I11i
  O00OO0O = bold ( "Decrypt" , False )
  addr_str = "RLOC: " + red ( addr_str , False )
  OOO000Oo = "poly" if key . do_poly else "sha256"
  OOO000Oo = bold ( OOO000Oo , False )
  I1IIIi1i = "ICV({}): {}" . format ( OOO000Oo , OooO00oo0O0 )
  dprint ( "{} for key-id: {}, {}, {} (good), {}-time: {} usec" . format ( O00OO0O , key . key_id , addr_str , I1IIIi1i , O0OO00000o00 , o0O0oo0OO0O ) )
  if 10 - 10: iIii1I11I1II1 % OoooooooOO % I1ii11iIi11i
  if 39 - 39: II111iiii * OoOoOO00 . O0 * I11i
  if 89 - 89: Ii1I - ooOoO0o . I11i - I1Ii111 - I1IiiI
  if 79 - 79: IiII + IiII + Ii1I
  if 39 - 39: O0 - OoooooooOO
  if 63 - 63: iIii1I11I1II1 % o0oOOo0O0Ooo * ooOoO0o
  if 79 - 79: O0
  self . packet = self . packet [ 0 : header_length ]
  return ( [ Ii1IOoO0o0O , True ] )
  if 32 - 32: II111iiii . O0 + Ii1I / OoOoOO00 / IiII / OOooOOo
  if 15 - 15: I1ii11iIi11i
 def fragment_outer ( self , outer_hdr , inner_packet ) :
  I11iI1 = 1000
  if 96 - 96: o0oOOo0O0Ooo % IiII / OOooOOo
  if 63 - 63: i1IIi % i11iIiiIii % II111iiii * OoooooooOO
  if 40 - 40: Oo0Ooo
  if 47 - 47: OoOoOO00
  if 65 - 65: O0 + I1Ii111 % Ii1I * I1IiiI / ooOoO0o / OoOoOO00
  oooOO = [ ]
  O00OO = 0
  Oooo = len ( inner_packet )
  while ( O00OO < Oooo ) :
   iiIII1 = inner_packet [ O00OO : : ]
   if ( len ( iiIII1 ) > I11iI1 ) : iiIII1 = iiIII1 [ 0 : I11iI1 ]
   oooOO . append ( iiIII1 )
   O00OO += len ( iiIII1 )
   if 33 - 33: oO0o
   if 39 - 39: OoO0O00 + O0 + ooOoO0o * II111iiii % O0 - O0
   if 41 - 41: IiII % o0oOOo0O0Ooo
   if 67 - 67: O0 % I1Ii111
   if 35 - 35: I1IiiI . OoOoOO00 + OoooooooOO % Oo0Ooo % OOooOOo
   if 39 - 39: Ii1I
  oOo0000ooO = [ ]
  O00OO = 0
  for iiIII1 in oooOO :
   if 15 - 15: ooOoO0o . o0oOOo0O0Ooo + OoOoOO00 . iIii1I11I1II1 % ooOoO0o + O0
   if 22 - 22: o0oOOo0O0Ooo + Oo0Ooo . ooOoO0o + I1ii11iIi11i * iII111i . i11iIiiIii
   if 90 - 90: OOooOOo * OoOoOO00 - Oo0Ooo + o0oOOo0O0Ooo
   if 53 - 53: OoooooooOO . OoooooooOO + o0oOOo0O0Ooo - iII111i + OOooOOo
   i1111iIII = O00OO if ( iiIII1 == oooOO [ - 1 ] ) else 0x2000 + O00OO
   i1111iIII = socket . htons ( i1111iIII )
   outer_hdr = outer_hdr [ 0 : 6 ] + struct . pack ( "H" , i1111iIII ) + outer_hdr [ 8 : : ]
   if 50 - 50: O0 * I1ii11iIi11i + II111iiii . i1IIi + OoOoOO00
   if 39 - 39: iIii1I11I1II1 + ooOoO0o
   if 92 - 92: I11i % i11iIiiIii % Oo0Ooo
   if 23 - 23: II111iiii * iII111i
   o0Oo = socket . htons ( len ( iiIII1 ) + 20 )
   outer_hdr = outer_hdr [ 0 : 2 ] + struct . pack ( "H" , o0Oo ) + outer_hdr [ 4 : : ]
   outer_hdr = lisp_ip_checksum ( outer_hdr )
   oOo0000ooO . append ( outer_hdr + iiIII1 )
   O00OO += len ( iiIII1 ) / 8
   if 16 - 16: iII111i % I1IiiI - ooOoO0o
  return ( oOo0000ooO )
  if 100 - 100: OoooooooOO * oO0o
  if 83 - 83: iIii1I11I1II1 - ooOoO0o - I1Ii111 / OoO0O00 - O0
 def fragment ( self ) :
  iIIi1 = self . fix_outer_header ( self . packet )
  if 81 - 81: Ii1I - oO0o * I1ii11iIi11i / I1Ii111
  if 21 - 21: OoO0O00
  if 63 - 63: I11i . O0 * I11i + iIii1I11I1II1
  if 46 - 46: i1IIi + II111iiii * i1IIi - Ii1I
  if 79 - 79: II111iiii - oO0o * I1ii11iIi11i - OoOoOO00 . I1ii11iIi11i
  if 11 - 11: O0 * OoOoOO00
  Oooo = len ( iIIi1 )
  if ( Oooo <= 1500 ) : return ( [ iIIi1 ] , "Fragment-None" )
  if 37 - 37: OoOoOO00 + O0 . O0 * Oo0Ooo % I1Ii111 / iII111i
  iIIi1 = self . packet
  if 18 - 18: OoooooooOO
  if 57 - 57: ooOoO0o . OoOoOO00 * o0oOOo0O0Ooo - OoooooooOO
  if 75 - 75: i11iIiiIii / o0oOOo0O0Ooo . IiII . i1IIi . i1IIi / I11i
  if 94 - 94: ooOoO0o + I1IiiI
  if 56 - 56: OoOoOO00 % o0oOOo0O0Ooo
  if ( self . inner_version != 4 ) :
   i11i = random . randint ( 0 , 0xffff )
   Ii11I1I11II = iIIi1 [ 0 : 4 ] + struct . pack ( "H" , i11i ) + iIIi1 [ 6 : 20 ]
   IIiiiI = iIIi1 [ 20 : : ]
   oOo0000ooO = self . fragment_outer ( Ii11I1I11II , IIiiiI )
   return ( oOo0000ooO , "Fragment-Outer" )
   if 59 - 59: oO0o % ooOoO0o
   if 36 - 36: OoooooooOO
   if 33 - 33: O0 + Oo0Ooo - iIii1I11I1II1 % i11iIiiIii / I1IiiI
   if 47 - 47: I1ii11iIi11i * oO0o + iIii1I11I1II1 - oO0o / IiII
   if 86 - 86: IiII
  Iii1I = 56 if ( self . outer_version == 6 ) else 36
  Ii11I1I11II = iIIi1 [ 0 : Iii1I ]
  ooo = iIIi1 [ Iii1I : Iii1I + 20 ]
  IIiiiI = iIIi1 [ Iii1I + 20 : : ]
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
  O00OO = 0
  Oooo = len ( IIiiiI )
  oOo0000ooO = [ ]
  while ( O00OO < Oooo ) :
   oOo0000ooO . append ( IIiiiI [ O00OO : O00OO + 1400 ] )
   O00OO += 1400
   if 33 - 33: II111iiii / O0 / IiII - I11i - i1IIi
   if 8 - 8: i11iIiiIii . iII111i / iIii1I11I1II1 / I1ii11iIi11i / IiII - Ii1I
   if 32 - 32: o0oOOo0O0Ooo . i1IIi * Oo0Ooo
   if 98 - 98: Ii1I - II111iiii / I1IiiI . oO0o * IiII . I11i
   if 25 - 25: i11iIiiIii / OoOoOO00 - I1Ii111 / OoO0O00 . o0oOOo0O0Ooo . o0oOOo0O0Ooo
  oooOO = oOo0000ooO
  oOo0000ooO = [ ]
  iI1 = True if i1Iii & 0x2000 else False
  i1Iii = ( i1Iii & 0x1fff ) * 8
  for iiIII1 in oooOO :
   if 43 - 43: I1ii11iIi11i + o0oOOo0O0Ooo
   if 50 - 50: oO0o % i1IIi * O0
   if 4 - 4: iIii1I11I1II1 . i1IIi
   if 63 - 63: iIii1I11I1II1 + IiII % i1IIi / I1IiiI % II111iiii
   OO0iiiii1iiIIii = i1Iii / 8
   if ( iI1 ) :
    OO0iiiii1iiIIii |= 0x2000
   elif ( iiIII1 != oooOO [ - 1 ] ) :
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
   Oooo = len ( iiIII1 )
   i1Iii += Oooo
   o0Oo = socket . htons ( Oooo + 20 )
   ooo = ooo [ 0 : 2 ] + struct . pack ( "H" , o0Oo ) + ooo [ 4 : 10 ] + struct . pack ( "H" , 0 ) + ooo [ 12 : : ]
   if 62 - 62: ooOoO0o + II111iiii % ooOoO0o
   ooo = lisp_ip_checksum ( ooo )
   Ii1IIii = ooo + iiIII1
   if 80 - 80: i11iIiiIii
   if 29 - 29: I1IiiI . OOooOOo + II111iiii . Oo0Ooo
   if 29 - 29: Ii1I - O0 . ooOoO0o / I1ii11iIi11i / i1IIi . OoOoOO00
   if 36 - 36: OoO0O00 - O0 * I1IiiI / I1ii11iIi11i / OOooOOo
   if 33 - 33: OoooooooOO % I1ii11iIi11i . O0 / I1ii11iIi11i
   Oooo = len ( Ii1IIii )
   if ( self . outer_version == 4 ) :
    o0Oo = Oooo + Iii1I
    Oooo += 16
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
   o0Oo = socket . htons ( Oooo )
   Ii1IIii = Ii1IIii [ 0 : Oooo0Oo00o ] + struct . pack ( "H" , o0Oo ) + Ii1IIii [ Oooo0Oo00o + 2 : : ]
   if 32 - 32: OoOoOO00 . iIii1I11I1II1 % oO0o . O0 . OoOoOO00 / iII111i
   oOo0000ooO . append ( Ii1IIii )
   if 45 - 45: iIii1I11I1II1
  return ( oOo0000ooO , "Fragment-Inner" )
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
  oOo0000ooO , ooO = self . fragment ( )
  if 34 - 34: I1Ii111 * II111iiii
  for Ii1IIii in oOo0000ooO :
   if ( len ( oOo0000ooO ) != 1 ) :
    self . packet = Ii1IIii
    self . print_packet ( ooO , True )
    if 71 - 71: IiII
    if 97 - 97: I1ii11iIi11i
   try : lisp_raw_socket . sendto ( Ii1IIii , ( dest , 0 ) )
   except socket . error , O0O0o0o0o :
    lprint ( "socket.sendto() failed: {}" . format ( O0O0o0o0o ) )
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
  iIIi1 = mac_header + self . packet
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
  l2_socket . write ( iIIi1 )
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
  except socket . error , O0O0o0o0o :
   lprint ( "bridge_l2_packet(): socket.send() failed: {}" . format ( O0O0o0o0o ) )
   if 13 - 13: II111iiii / OoOoOO00 / OoOoOO00 + ooOoO0o
   if 49 - 49: O0 / II111iiii * I1IiiI - OoooooooOO . II111iiii % IiII
   if 13 - 13: oO0o . iIii1I11I1II1 . OOooOOo . IiII
 def decode ( self , is_lisp_packet , lisp_ipc_socket , stats ) :
  self . packet_error = ""
  iIIi1 = self . packet
  oo0oo00O0O = len ( iIIi1 )
  iIiiI1I = Oo0 = True
  if 34 - 34: OoOoOO00 - oO0o * OoooooooOO
  if 5 - 5: i11iIiiIii * iII111i - Ii1I - I1ii11iIi11i - i1IIi + iII111i
  if 4 - 4: ooOoO0o + O0 . i1IIi * I1ii11iIi11i - o0oOOo0O0Ooo
  if 42 - 42: o0oOOo0O0Ooo * OoOoOO00 . OoO0O00 - iII111i / II111iiii
  iII1ii11III = 0
  iiI1iii = self . lisp_header . get_instance_id ( )
  if ( is_lisp_packet ) :
   OOOO0oO0O = struct . unpack ( "B" , iIIi1 [ 0 : 1 ] ) [ 0 ]
   self . outer_version = OOOO0oO0O >> 4
   if ( self . outer_version == 4 ) :
    if 59 - 59: II111iiii
    if 29 - 29: OoO0O00 . ooOoO0o
    if 58 - 58: IiII % i11iIiiIii * II111iiii . I1ii11iIi11i
    if 94 - 94: i11iIiiIii . OOooOOo + iIii1I11I1II1 * I1Ii111 * I1Ii111
    if 36 - 36: I11i - IiII . IiII
    Oo0OOOO0oOoo0 = struct . unpack ( "H" , iIIi1 [ 10 : 12 ] ) [ 0 ]
    iIIi1 = lisp_ip_checksum ( iIIi1 )
    iiIiII11i1 = struct . unpack ( "H" , iIIi1 [ 10 : 12 ] ) [ 0 ]
    if ( iiIiII11i1 != 0 ) :
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
    O00OO = 12
    self . outer_tos = struct . unpack ( "B" , iIIi1 [ 1 : 2 ] ) [ 0 ]
    self . outer_ttl = struct . unpack ( "B" , iIIi1 [ 8 : 9 ] ) [ 0 ]
    iII1ii11III = 20
   elif ( self . outer_version == 6 ) :
    ooo0O0O0oo0 = LISP_AFI_IPV6
    O00OO = 8
    oo000oO = struct . unpack ( "H" , iIIi1 [ 0 : 2 ] ) [ 0 ]
    self . outer_tos = ( socket . ntohs ( oo000oO ) >> 4 ) & 0xff
    self . outer_ttl = struct . unpack ( "B" , iIIi1 [ 7 : 8 ] ) [ 0 ]
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
   self . outer_source . unpack_address ( iIIi1 [ O00OO : O00OO + oooO00oo0 ] )
   O00OO += oooO00oo0
   self . outer_dest . unpack_address ( iIIi1 [ O00OO : O00OO + oooO00oo0 ] )
   iIIi1 = iIIi1 [ iII1ii11III : : ]
   self . outer_source . mask_len = self . outer_source . host_mask_len ( )
   self . outer_dest . mask_len = self . outer_dest . host_mask_len ( )
   if 86 - 86: O0 . i1IIi - OoO0O00 / Oo0Ooo / I1ii11iIi11i
   if 64 - 64: OoooooooOO - i1IIi / II111iiii
   if 49 - 49: Oo0Ooo + O0 + IiII . II111iiii % ooOoO0o
   if 33 - 33: OoOoOO00 . iIii1I11I1II1 / I11i % Ii1I
   IIiiI11 = struct . unpack ( "H" , iIIi1 [ 0 : 2 ] ) [ 0 ]
   self . udp_sport = socket . ntohs ( IIiiI11 )
   IIiiI11 = struct . unpack ( "H" , iIIi1 [ 2 : 4 ] ) [ 0 ]
   self . udp_dport = socket . ntohs ( IIiiI11 )
   IIiiI11 = struct . unpack ( "H" , iIIi1 [ 4 : 6 ] ) [ 0 ]
   self . udp_length = socket . ntohs ( IIiiI11 )
   IIiiI11 = struct . unpack ( "H" , iIIi1 [ 6 : 8 ] ) [ 0 ]
   self . udp_checksum = socket . ntohs ( IIiiI11 )
   iIIi1 = iIIi1 [ 8 : : ]
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
   if ( self . lisp_header . decode ( iIIi1 ) == False ) :
    self . packet_error = "lisp-header-error"
    if ( stats ) : stats [ self . packet_error ] . increment ( oo0oo00O0O )
    if 61 - 61: o0oOOo0O0Ooo / i11iIiiIii
    if ( lisp_flow_logging ) : self . log_flow ( False )
    lprint ( "Cannot decode LISP header" )
    return ( None )
    if 28 - 28: OOooOOo / OoOoOO00
   iIIi1 = iIIi1 [ 8 : : ]
   iiI1iii = self . lisp_header . get_instance_id ( )
   iII1ii11III += 16
   if 30 - 30: ooOoO0o
  if ( iiI1iii == 0xffffff ) : iiI1iii = 0
  if 57 - 57: o0oOOo0O0Ooo * i11iIiiIii / OoOoOO00
  if 40 - 40: iIii1I11I1II1 - ooOoO0o / Oo0Ooo
  if 24 - 24: oO0o - iII111i / ooOoO0o
  if 10 - 10: OoOoOO00 * i1IIi
  I1Ii1ii = False
  iIIi1OoOo0O00 = self . lisp_header . k_bits
  if ( iIIi1OoOo0O00 ) :
   oooOO0oOooO00 = lisp_get_crypto_decap_lookup_key ( self . outer_source ,
 self . udp_sport )
   if ( oooOO0oOooO00 == None ) :
    self . packet_error = "no-decrypt-key"
    if ( stats ) : stats [ self . packet_error ] . increment ( oo0oo00O0O )
    if 9 - 9: OOooOOo
    self . print_packet ( "Receive" , is_lisp_packet )
    I1i = bold ( "No key available" , False )
    dprint ( "{} for key-id {} to decrypt packet" . format ( I1i , iIIi1OoOo0O00 ) )
    if ( lisp_flow_logging ) : self . log_flow ( False )
    return ( None )
    if 44 - 44: OoO0O00 . iII111i / I11i + Oo0Ooo - OoO0O00 / II111iiii
    if 93 - 93: oO0o - OOooOOo + o0oOOo0O0Ooo . oO0o / I11i
   o0000oO = lisp_crypto_keys_by_rloc_decap [ oooOO0oOooO00 ] [ iIIi1OoOo0O00 ]
   if ( o0000oO == None ) :
    self . packet_error = "no-decrypt-key"
    if ( stats ) : stats [ self . packet_error ] . increment ( oo0oo00O0O )
    if 83 - 83: OoO0O00
    self . print_packet ( "Receive" , is_lisp_packet )
    I1i = bold ( "No key available" , False )
    dprint ( "{} to decrypt packet from RLOC {}" . format ( I1i ,
 red ( oooOO0oOooO00 , False ) ) )
    if ( lisp_flow_logging ) : self . log_flow ( False )
    return ( None )
    if 16 - 16: ooOoO0o
    if 32 - 32: o0oOOo0O0Ooo % I1IiiI
    if 7 - 7: Oo0Ooo . i1IIi - oO0o
    if 93 - 93: IiII % I1ii11iIi11i
    if 31 - 31: II111iiii + OOooOOo - OoooooooOO . I11i
   o0000oO . use_count += 1
   iIIi1 , I1Ii1ii = self . decrypt ( iIIi1 , iII1ii11III , o0000oO ,
 oooOO0oOooO00 )
   if ( I1Ii1ii == False ) :
    if ( stats ) : stats [ self . packet_error ] . increment ( oo0oo00O0O )
    if ( lisp_flow_logging ) : self . log_flow ( False )
    return ( None )
    if 28 - 28: Ii1I . I1ii11iIi11i
    if 77 - 77: I1ii11iIi11i % II111iiii
    if 81 - 81: OoOoOO00 % Ii1I / O0 * iIii1I11I1II1 % IiII . I1IiiI
    if 90 - 90: o0oOOo0O0Ooo
    if 44 - 44: o0oOOo0O0Ooo / I1ii11iIi11i . Oo0Ooo + OoOoOO00
    if 32 - 32: IiII - ooOoO0o * iII111i * I11i
  OOOO0oO0O = struct . unpack ( "B" , iIIi1 [ 0 : 1 ] ) [ 0 ]
  self . inner_version = OOOO0oO0O >> 4
  if ( iIiiI1I and self . inner_version == 4 and OOOO0oO0O >= 0x45 ) :
   O00OOOo = socket . ntohs ( struct . unpack ( "H" , iIIi1 [ 2 : 4 ] ) [ 0 ] )
   self . inner_tos = struct . unpack ( "B" , iIIi1 [ 1 : 2 ] ) [ 0 ]
   self . inner_ttl = struct . unpack ( "B" , iIIi1 [ 8 : 9 ] ) [ 0 ]
   self . inner_protocol = struct . unpack ( "B" , iIIi1 [ 9 : 10 ] ) [ 0 ]
   self . inner_source . afi = LISP_AFI_IPV4
   self . inner_dest . afi = LISP_AFI_IPV4
   self . inner_source . unpack_address ( iIIi1 [ 12 : 16 ] )
   self . inner_dest . unpack_address ( iIIi1 [ 16 : 20 ] )
   i1Iii = socket . ntohs ( struct . unpack ( "H" , iIIi1 [ 6 : 8 ] ) [ 0 ] )
   self . inner_is_fragment = ( i1Iii & 0x2000 or i1Iii != 0 )
   if ( self . inner_protocol == LISP_UDP_PROTOCOL ) :
    self . inner_dport = struct . unpack ( "H" , iIIi1 [ 22 : 24 ] ) [ 0 ]
    self . inner_dport = socket . ntohs ( self . inner_dport )
    if 37 - 37: I11i % I1ii11iIi11i / ooOoO0o
  elif ( iIiiI1I and self . inner_version == 6 and OOOO0oO0O >= 0x60 ) :
   O00OOOo = socket . ntohs ( struct . unpack ( "H" , iIIi1 [ 4 : 6 ] ) [ 0 ] ) + 40
   oo000oO = struct . unpack ( "H" , iIIi1 [ 0 : 2 ] ) [ 0 ]
   self . inner_tos = ( socket . ntohs ( oo000oO ) >> 4 ) & 0xff
   self . inner_ttl = struct . unpack ( "B" , iIIi1 [ 7 : 8 ] ) [ 0 ]
   self . inner_protocol = struct . unpack ( "B" , iIIi1 [ 6 : 7 ] ) [ 0 ]
   self . inner_source . afi = LISP_AFI_IPV6
   self . inner_dest . afi = LISP_AFI_IPV6
   self . inner_source . unpack_address ( iIIi1 [ 8 : 24 ] )
   self . inner_dest . unpack_address ( iIIi1 [ 24 : 40 ] )
   if ( self . inner_protocol == LISP_UDP_PROTOCOL ) :
    self . inner_dport = struct . unpack ( "H" , iIIi1 [ 42 : 44 ] ) [ 0 ]
    self . inner_dport = socket . ntohs ( self . inner_dport )
    if 94 - 94: I11i / OoO0O00 . o0oOOo0O0Ooo
  elif ( Oo0 ) :
   O00OOOo = len ( iIIi1 )
   self . inner_tos = 0
   self . inner_ttl = 0
   self . inner_protocol = 0
   self . inner_source . afi = LISP_AFI_MAC
   self . inner_dest . afi = LISP_AFI_MAC
   self . inner_dest . unpack_address ( self . swap_mac ( iIIi1 [ 0 : 6 ] ) )
   self . inner_source . unpack_address ( self . swap_mac ( iIIi1 [ 6 : 12 ] ) )
  elif ( self . lisp_header . get_instance_id ( ) == 0xffffff ) :
   if ( lisp_flow_logging ) : self . log_flow ( False )
   return ( self )
  else :
   self . packet_error = "bad-inner-version"
   if ( stats ) : stats [ self . packet_error ] . increment ( oo0oo00O0O )
   if 1 - 1: Oo0Ooo . II111iiii
   lprint ( "Cannot decode encapsulation, header version {}" . format ( hex ( OOOO0oO0O ) ) )
   if 93 - 93: II111iiii . i11iIiiIii + II111iiii % oO0o
   iIIi1 = lisp_format_packet ( iIIi1 [ 0 : 20 ] )
   lprint ( "Packet header: {}" . format ( iIIi1 ) )
   if ( lisp_flow_logging and is_lisp_packet ) : self . log_flow ( False )
   return ( None )
   if 98 - 98: I1Ii111 * oO0o * OoOoOO00 + Ii1I * iII111i
  self . inner_source . mask_len = self . inner_source . host_mask_len ( )
  self . inner_dest . mask_len = self . inner_dest . host_mask_len ( )
  self . inner_source . instance_id = iiI1iii
  self . inner_dest . instance_id = iiI1iii
  if 4 - 4: IiII
  if 16 - 16: iIii1I11I1II1 * iII111i + oO0o . O0 . o0oOOo0O0Ooo
  if 99 - 99: i11iIiiIii - iII111i
  if 85 - 85: I1Ii111 % I1ii11iIi11i
  if 95 - 95: OoO0O00 * OOooOOo * iII111i . o0oOOo0O0Ooo
  if ( lisp_nonce_echoing and is_lisp_packet ) :
   oooOo00 = lisp_get_echo_nonce ( self . outer_source , None )
   if ( oooOo00 == None ) :
    iII1II = self . outer_source . print_address_no_iid ( )
    oooOo00 = lisp_echo_nonce ( iII1II )
    if 12 - 12: I11i
   I11iIi1i1I1i1 = self . lisp_header . get_nonce ( )
   if ( self . lisp_header . is_e_bit_set ( ) ) :
    oooOo00 . receive_request ( lisp_ipc_socket , I11iIi1i1I1i1 )
   elif ( oooOo00 . request_nonce_sent ) :
    oooOo00 . receive_echo ( lisp_ipc_socket , I11iIi1i1I1i1 )
    if 14 - 14: I11i
    if 18 - 18: I1IiiI
    if 23 - 23: OoooooooOO * II111iiii
    if 70 - 70: I1ii11iIi11i + I1IiiI
    if 65 - 65: iII111i - iII111i . Oo0Ooo
    if 54 - 54: I1IiiI % iII111i
    if 80 - 80: o0oOOo0O0Ooo % iII111i
  if ( I1Ii1ii ) : self . packet += iIIi1 [ : O00OOOo ]
  if 80 - 80: Ii1I
  if 26 - 26: iIii1I11I1II1 . OoooooooOO - iIii1I11I1II1
  if 59 - 59: I1ii11iIi11i + I11i . oO0o
  if 87 - 87: OoO0O00
  if ( lisp_flow_logging and is_lisp_packet ) : self . log_flow ( False )
  return ( self )
  if 34 - 34: I1Ii111 . OoOoOO00 / i11iIiiIii / iII111i
  if 46 - 46: Oo0Ooo + II111iiii * I1IiiI + OOooOOo
 def swap_mac ( self , mac ) :
  return ( mac [ 1 ] + mac [ 0 ] + mac [ 3 ] + mac [ 2 ] + mac [ 5 ] + mac [ 4 ] )
  if 31 - 31: Ii1I * o0oOOo0O0Ooo * Ii1I + OoO0O00 * o0oOOo0O0Ooo . I1Ii111
  if 89 - 89: OoooooooOO * Ii1I * I1IiiI . ooOoO0o * Ii1I / iII111i
 def strip_outer_headers ( self ) :
  O00OO = 16
  O00OO += 20 if ( self . outer_version == 4 ) else 40
  self . packet = self . packet [ O00OO : : ]
  return ( self )
  if 46 - 46: i11iIiiIii
  if 15 - 15: O0 / i1IIi / i1IIi . iII111i % OoOoOO00 + I1IiiI
 def hash_ports ( self ) :
  iIIi1 = self . packet
  OOOO0oO0O = self . inner_version
  I11111ii1i = 0
  if ( OOOO0oO0O == 4 ) :
   O0OOoO0OoO0 = struct . unpack ( "B" , iIIi1 [ 9 ] ) [ 0 ]
   if ( self . inner_is_fragment ) : return ( O0OOoO0OoO0 )
   if ( O0OOoO0OoO0 in [ 6 , 17 ] ) :
    I11111ii1i = O0OOoO0OoO0
    I11111ii1i += struct . unpack ( "I" , iIIi1 [ 20 : 24 ] ) [ 0 ]
    I11111ii1i = ( I11111ii1i >> 16 ) ^ ( I11111ii1i & 0xffff )
    if 37 - 37: oO0o % I1Ii111 % oO0o
    if 14 - 14: OoO0O00 / I1IiiI
  if ( OOOO0oO0O == 6 ) :
   O0OOoO0OoO0 = struct . unpack ( "B" , iIIi1 [ 6 ] ) [ 0 ]
   if ( O0OOoO0OoO0 in [ 6 , 17 ] ) :
    I11111ii1i = O0OOoO0OoO0
    I11111ii1i += struct . unpack ( "I" , iIIi1 [ 40 : 44 ] ) [ 0 ]
    I11111ii1i = ( I11111ii1i >> 16 ) ^ ( I11111ii1i & 0xffff )
    if 66 - 66: Oo0Ooo / i11iIiiIii % ooOoO0o
    if 43 - 43: OOooOOo
  return ( I11111ii1i )
  if 84 - 84: OOooOOo . IiII . iII111i
  if 2 - 2: Oo0Ooo - OoOoOO00
 def hash_packet ( self ) :
  I11111ii1i = self . inner_source . address ^ self . inner_dest . address
  I11111ii1i += self . hash_ports ( )
  if ( self . inner_version == 4 ) :
   I11111ii1i = ( I11111ii1i >> 16 ) ^ ( I11111ii1i & 0xffff )
  elif ( self . inner_version == 6 ) :
   I11111ii1i = ( I11111ii1i >> 64 ) ^ ( I11111ii1i & 0xffffffffffffffff )
   I11111ii1i = ( I11111ii1i >> 32 ) ^ ( I11111ii1i & 0xffffffff )
   I11111ii1i = ( I11111ii1i >> 16 ) ^ ( I11111ii1i & 0xffff )
   if 49 - 49: Ii1I + II111iiii / oO0o - OoOoOO00 % OoOoOO00 + I1IiiI
  self . udp_sport = 0xf000 | ( I11111ii1i & 0xfff )
  if 54 - 54: ooOoO0o % Oo0Ooo - OOooOOo
  if 16 - 16: I1ii11iIi11i * iII111i / I11i
 def print_packet ( self , s_or_r , is_lisp_packet ) :
  if ( is_lisp_packet == False ) :
   iiII1 = "{} -> {}" . format ( self . inner_source . print_address ( ) ,
 self . inner_dest . print_address ( ) )
   dprint ( ( "{} {}, tos/ttl: {}/{}, length: {}, packet: {} ..." ) . format ( bold ( s_or_r , False ) ,
   # I1IiiI / iII111i / OoooooooOO - i11iIiiIii + I1IiiI
 green ( iiII1 , False ) , self . inner_tos ,
 self . inner_ttl , len ( self . packet ) ,
 lisp_format_packet ( self . packet [ 0 : 60 ] ) ) )
   return
   if 64 - 64: i11iIiiIii + i1IIi % O0 . I11i
   if 64 - 64: ooOoO0o / i1IIi % iII111i
  if ( s_or_r . find ( "Receive" ) != - 1 ) :
   OOoOo0O0 = "decap"
   OOoOo0O0 += "-vxlan" if self . udp_dport == LISP_VXLAN_DATA_PORT else ""
  else :
   OOoOo0O0 = s_or_r
   if ( OOoOo0O0 in [ "Send" , "Replicate" ] or OOoOo0O0 . find ( "Fragment" ) != - 1 ) :
    OOoOo0O0 = "encap"
    if 39 - 39: I1Ii111 . OoO0O00 % ooOoO0o . OOooOOo / iII111i * OoO0O00
    if 12 - 12: I1IiiI / o0oOOo0O0Ooo
  oOO0O00o0O0 = "{} -> {}" . format ( self . outer_source . print_address_no_iid ( ) ,
 self . outer_dest . print_address_no_iid ( ) )
  if 68 - 68: i11iIiiIii + OoO0O00
  if 13 - 13: ooOoO0o - I1IiiI
  if 23 - 23: I1IiiI
  if 7 - 7: iII111i % I1ii11iIi11i
  if 64 - 64: I1Ii111 + i11iIiiIii
  if ( self . lisp_header . get_instance_id ( ) == 0xffffff ) :
   iiIiiIi1 = ( "{} LISP packet, outer RLOCs: {}, outer tos/ttl: " + "{}/{}, outer UDP: {} -> {}, " )
   if 35 - 35: OoOoOO00 + i1IIi % OOooOOo
   iiIiiIi1 += bold ( "control-packet" , False ) + ": {} ..."
   if 68 - 68: IiII . ooOoO0o
   dprint ( iiIiiIi1 . format ( bold ( s_or_r , False ) , red ( oOO0O00o0O0 , False ) ,
 self . outer_tos , self . outer_ttl , self . udp_sport ,
 self . udp_dport , lisp_format_packet ( self . packet [ 0 : 56 ] ) ) )
   return
  else :
   iiIiiIi1 = ( "{} LISP packet, outer RLOCs: {}, outer tos/ttl: " + "{}/{}, outer UDP: {} -> {}, inner EIDs: {}, " + "inner tos/ttl: {}/{}, length: {}, {}, packet: {} ..." )
   if 64 - 64: i1IIi + Oo0Ooo * I1IiiI / OOooOOo
   if 3 - 3: Oo0Ooo / ooOoO0o + ooOoO0o . I1ii11iIi11i
   if 50 - 50: iIii1I11I1II1 * oO0o
   if 85 - 85: i1IIi
  if ( self . lisp_header . k_bits ) :
   if ( OOoOo0O0 == "encap" ) : OOoOo0O0 = "encrypt/encap"
   if ( OOoOo0O0 == "decap" ) : OOoOo0O0 = "decap/decrypt"
   if 100 - 100: OoooooooOO / I11i % OoO0O00 + Ii1I
   if 42 - 42: Oo0Ooo / IiII . Ii1I * I1IiiI
  iiII1 = "{} -> {}" . format ( self . inner_source . print_address ( ) ,
 self . inner_dest . print_address ( ) )
  if 54 - 54: OoOoOO00 * iII111i + OoO0O00
  dprint ( iiIiiIi1 . format ( bold ( s_or_r , False ) , red ( oOO0O00o0O0 , False ) ,
 self . outer_tos , self . outer_ttl , self . udp_sport , self . udp_dport ,
 green ( iiII1 , False ) , self . inner_tos , self . inner_ttl ,
 len ( self . packet ) , self . lisp_header . print_header ( OOoOo0O0 ) ,
 lisp_format_packet ( self . packet [ 0 : 56 ] ) ) )
  if 93 - 93: o0oOOo0O0Ooo / I1IiiI
  if 47 - 47: Oo0Ooo * OOooOOo
 def print_eid_tuple ( self ) :
  return ( lisp_print_eid_tuple ( self . inner_source , self . inner_dest ) )
  if 98 - 98: oO0o - oO0o . ooOoO0o
  if 60 - 60: I1IiiI * I1ii11iIi11i / O0 + I11i + IiII
 def get_raw_socket ( self ) :
  iiI1iii = str ( self . lisp_header . get_instance_id ( ) )
  if ( iiI1iii == "0" ) : return ( None )
  if ( lisp_iid_to_interface . has_key ( iiI1iii ) == False ) : return ( None )
  if 66 - 66: IiII * Oo0Ooo . OoooooooOO * I1Ii111
  iiiii11I1 = lisp_iid_to_interface [ iiI1iii ]
  oooOOO00o0 = iiiii11I1 . get_socket ( )
  if ( oooOOO00o0 == None ) :
   O00OO0O = bold ( "SO_BINDTODEVICE" , False )
   o0oOo = ( os . getenv ( "LISP_ENFORCE_BINDTODEVICE" ) != None )
   lprint ( "{} required for multi-tenancy support, {} packet" . format ( O00OO0O , "drop" if o0oOo else "forward" ) )
   if 61 - 61: ooOoO0o % iIii1I11I1II1 - I1IiiI - OoooooooOO * ooOoO0o + i11iIiiIii
   if ( o0oOo ) : return ( None )
   if 4 - 4: ooOoO0o * O0 * II111iiii + iIii1I11I1II1 % Ii1I
   if 65 - 65: OoOoOO00 . II111iiii % iII111i + Ii1I
  iiI1iii = bold ( iiI1iii , False )
  O0o0oo0oOO0oO = bold ( iiiii11I1 . device , False )
  dprint ( "Send packet on instance-id {} interface {}" . format ( iiI1iii , O0o0oo0oOO0oO ) )
  return ( oooOOO00o0 )
  if 37 - 37: oO0o - iIii1I11I1II1 + II111iiii . Ii1I % iIii1I11I1II1
  if 17 - 17: I1Ii111 + i1IIi % O0
 def log_flow ( self , encap ) :
  global lisp_flow_log
  if 65 - 65: IiII
  iiI11 = os . path . exists ( "./log-flows" )
  if ( len ( lisp_flow_log ) == LISP_FLOW_LOG_SIZE or iiI11 ) :
   OoooOOo0oOO = [ lisp_flow_log ]
   lisp_flow_log = [ ]
   threading . Thread ( target = lisp_write_flow_log , args = OoooOOo0oOO ) . start ( )
   if ( iiI11 ) : os . system ( "rm ./log-flows" )
   return
   if 44 - 44: OOooOOo % iIii1I11I1II1
   if 30 - 30: i11iIiiIii - I1IiiI / I1ii11iIi11i
  o0O0oo0OO0O = datetime . datetime . now ( )
  lisp_flow_log . append ( [ o0O0oo0OO0O , encap , self . packet , self ] )
  if 26 - 26: ooOoO0o % oO0o + I1IiiI / IiII . I1IiiI
  if 38 - 38: OoooooooOO + OoooooooOO - i11iIiiIii * I1IiiI * i1IIi / II111iiii
 def print_flow ( self , ts , encap , packet ) :
  ts = ts . strftime ( "%m/%d/%y %H:%M:%S.%f" ) [ : - 3 ]
  OOO00000O = "{}: {}" . format ( ts , "encap" if encap else "decap" )
  if 23 - 23: Oo0Ooo - O0
  iI111iIi = red ( self . outer_source . print_address_no_iid ( ) , False )
  IIi1IiIIii = red ( self . outer_dest . print_address_no_iid ( ) , False )
  oOooOOOO0oOo = green ( self . inner_source . print_address ( ) , False )
  iIiI = green ( self . inner_dest . print_address ( ) , False )
  if 57 - 57: iIii1I11I1II1 * Ii1I * iII111i / oO0o
  if ( self . lisp_header . get_instance_id ( ) == 0xffffff ) :
   OOO00000O += " {}:{} -> {}:{}, LISP control message type {}\n"
   OOO00000O = OOO00000O . format ( iI111iIi , self . udp_sport , IIi1IiIIii , self . udp_dport ,
 self . inner_version )
   return ( OOO00000O )
   if 46 - 46: Ii1I
   if 61 - 61: o0oOOo0O0Ooo / ooOoO0o - II111iiii
  if ( self . outer_dest . is_null ( ) == False ) :
   OOO00000O += " {}:{} -> {}:{}, len/tos/ttl {}/{}/{}"
   OOO00000O = OOO00000O . format ( iI111iIi , self . udp_sport , IIi1IiIIii , self . udp_dport ,
 len ( packet ) , self . outer_tos , self . outer_ttl )
   if 87 - 87: I1ii11iIi11i / I1IiiI
   if 45 - 45: OoOoOO00 * ooOoO0o / OoooooooOO + OoO0O00 . I1Ii111 / OoO0O00
   if 64 - 64: Ii1I / i1IIi % I1IiiI - o0oOOo0O0Ooo
   if 11 - 11: I1ii11iIi11i - OoooooooOO
   if 16 - 16: IiII % OoooooooOO - ooOoO0o * Ii1I - Ii1I
  if ( self . lisp_header . k_bits != 0 ) :
   I1iiII1 = "\n"
   if ( self . packet_error != "" ) :
    I1iiII1 = " ({})" . format ( self . packet_error ) + I1iiII1
    if 45 - 45: OoO0O00 + OoO0O00 % ooOoO0o
   OOO00000O += ", encrypted" + I1iiII1
   return ( OOO00000O )
   if 36 - 36: Ii1I * I11i . I11i / Oo0Ooo / I1IiiI
   if 80 - 80: OoooooooOO - i1IIi
   if 51 - 51: i1IIi . OoOoOO00 / OoOoOO00 % i11iIiiIii * OOooOOo - I1Ii111
   if 49 - 49: Oo0Ooo - iIii1I11I1II1
   if 64 - 64: I1Ii111 + iIii1I11I1II1
  if ( self . outer_dest . is_null ( ) == False ) :
   packet = packet [ 36 : : ] if self . outer_version == 4 else packet [ 56 : : ]
   if 14 - 14: Ii1I / OoooooooOO + II111iiii . O0 / i1IIi
   if 58 - 58: o0oOOo0O0Ooo / i11iIiiIii / O0 % I11i % I1IiiI
  O0OOoO0OoO0 = packet [ 9 ] if self . inner_version == 4 else packet [ 6 ]
  O0OOoO0OoO0 = struct . unpack ( "B" , O0OOoO0OoO0 ) [ 0 ]
  if 86 - 86: IiII + OoOoOO00 / I1IiiI + I11i % I11i / i11iIiiIii
  OOO00000O += " {} -> {}, len/tos/ttl/prot {}/{}/{}/{}"
  OOO00000O = OOO00000O . format ( oOooOOOO0oOo , iIiI , len ( packet ) , self . inner_tos ,
 self . inner_ttl , O0OOoO0OoO0 )
  if 12 - 12: OoOoOO00 + o0oOOo0O0Ooo . I1Ii111
  if 52 - 52: OoO0O00
  if 4 - 4: Ii1I % I1ii11iIi11i + I11i - I1ii11iIi11i
  if 98 - 98: Ii1I - O0 * oO0o * Ii1I * Ii1I
  if ( O0OOoO0OoO0 in [ 6 , 17 ] ) :
   i11IiII = packet [ 20 : 24 ] if self . inner_version == 4 else packet [ 40 : 44 ]
   if ( len ( i11IiII ) == 4 ) :
    i11IiII = socket . ntohl ( struct . unpack ( "I" , i11IiII ) [ 0 ] )
    OOO00000O += ", ports {} -> {}" . format ( i11IiII >> 16 , i11IiII & 0xffff )
    if 53 - 53: OoO0O00 % I1ii11iIi11i . iII111i . i1IIi . OoO0O00
  elif ( O0OOoO0OoO0 == 1 ) :
   iiII1II11i = packet [ 26 : 28 ] if self . inner_version == 4 else packet [ 46 : 48 ]
   if ( len ( iiII1II11i ) == 2 ) :
    iiII1II11i = socket . ntohs ( struct . unpack ( "H" , iiII1II11i ) [ 0 ] )
    OOO00000O += ", icmp-seq {}" . format ( iiII1II11i )
    if 78 - 78: i11iIiiIii / oO0o
    if 85 - 85: ooOoO0o - I1IiiI / i1IIi / OoO0O00 / II111iiii
  if ( self . packet_error != "" ) :
   OOO00000O += " ({})" . format ( self . packet_error )
   if 94 - 94: iIii1I11I1II1 + IiII
  OOO00000O += "\n"
  return ( OOO00000O )
  if 44 - 44: OoO0O00 + I11i % OoO0O00 + i1IIi + iII111i + O0
  if 18 - 18: iIii1I11I1II1 % iIii1I11I1II1 % oO0o + I1IiiI % ooOoO0o / Ii1I
 def is_trace ( self ) :
  return ( self . inner_protocol == LISP_UDP_PROTOCOL and
 self . inner_dport == LISP_TRACE_PORT )
  if 36 - 36: OoOoOO00 . i11iIiiIii
  if 81 - 81: Oo0Ooo * iII111i * OoO0O00
  if 85 - 85: O0 * oO0o
  if 39 - 39: II111iiii * I1IiiI - iIii1I11I1II1
  if 25 - 25: OoooooooOO . Ii1I % iII111i . IiII
  if 67 - 67: OoooooooOO + I1Ii111 / ooOoO0o
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
LISP_N_BIT = 0x80000000
LISP_L_BIT = 0x40000000
LISP_E_BIT = 0x20000000
LISP_V_BIT = 0x10000000
LISP_I_BIT = 0x08000000
LISP_P_BIT = 0x04000000
LISP_K_BITS = 0x03000000
if 19 - 19: i11iIiiIii
class lisp_data_header ( ) :
 def __init__ ( self ) :
  self . first_long = 0
  self . second_long = 0
  self . k_bits = 0
  if 80 - 80: I1IiiI
  if 58 - 58: oO0o + I1ii11iIi11i % OoOoOO00
 def print_header ( self , e_or_d ) :
  Iii11I1i = lisp_hex_string ( self . first_long & 0xffffff )
  oO0OOoOO = lisp_hex_string ( self . second_long ) . zfill ( 8 )
  if 97 - 97: i1IIi
  iiIiiIi1 = ( "{} LISP-header -> flags: {}{}{}{}{}{}{}{}, nonce: {}, " + "iid/lsb: {}" )
  if 46 - 46: I1ii11iIi11i
  return ( iiIiiIi1 . format ( bold ( e_or_d , False ) ,
 "N" if ( self . first_long & LISP_N_BIT ) else "n" ,
 "L" if ( self . first_long & LISP_L_BIT ) else "l" ,
 "E" if ( self . first_long & LISP_E_BIT ) else "e" ,
 "V" if ( self . first_long & LISP_V_BIT ) else "v" ,
 "I" if ( self . first_long & LISP_I_BIT ) else "i" ,
 "P" if ( self . first_long & LISP_P_BIT ) else "p" ,
 "K" if ( self . k_bits in [ 2 , 3 ] ) else "k" ,
 "K" if ( self . k_bits in [ 1 , 3 ] ) else "k" ,
 Iii11I1i , oO0OOoOO ) )
  if 30 - 30: OoO0O00 / O0 * o0oOOo0O0Ooo * I1Ii111 + OoooooooOO * iII111i
  if 23 - 23: I11i
 def encode ( self ) :
  I1I = "II"
  Iii11I1i = socket . htonl ( self . first_long )
  oO0OOoOO = socket . htonl ( self . second_long )
  if 81 - 81: I1Ii111 / Oo0Ooo - iIii1I11I1II1
  I11i1I1i1 = struct . pack ( I1I , Iii11I1i , oO0OOoOO )
  return ( I11i1I1i1 )
  if 95 - 95: ooOoO0o * IiII
  if 47 - 47: I1Ii111
 def decode ( self , packet ) :
  I1I = "II"
  ii1I1iIi = struct . calcsize ( I1I )
  if ( len ( packet ) < ii1I1iIi ) : return ( False )
  if 83 - 83: ooOoO0o % Ii1I / Oo0Ooo - iII111i / O0
  Iii11I1i , oO0OOoOO = struct . unpack ( I1I , packet [ : ii1I1iIi ] )
  if 97 - 97: iIii1I11I1II1 * I11i
  if 95 - 95: OoO0O00
  self . first_long = socket . ntohl ( Iii11I1i )
  self . second_long = socket . ntohl ( oO0OOoOO )
  self . k_bits = ( self . first_long & LISP_K_BITS ) >> 24
  return ( True )
  if 68 - 68: iIii1I11I1II1 . iIii1I11I1II1 / OoOoOO00 - II111iiii - iIii1I11I1II1
  if 75 - 75: ooOoO0o . I1IiiI * II111iiii
 def key_id ( self , key_id ) :
  self . first_long &= ~ ( 0x3 << 24 )
  self . first_long |= ( ( key_id & 0x3 ) << 24 )
  self . k_bits = key_id
  if 99 - 99: iIii1I11I1II1 * I1ii11iIi11i + IiII
  if 70 - 70: i1IIi % ooOoO0o . I1ii11iIi11i - IiII + OOooOOo
 def nonce ( self , nonce ) :
  self . first_long |= LISP_N_BIT
  self . first_long |= nonce
  if 84 - 84: oO0o + II111iiii * II111iiii % o0oOOo0O0Ooo / iII111i + ooOoO0o
  if 9 - 9: iII111i
 def map_version ( self , version ) :
  self . first_long |= LISP_V_BIT
  self . first_long |= version
  if 25 - 25: OOooOOo - Ii1I . I11i
  if 57 - 57: o0oOOo0O0Ooo + Oo0Ooo * I1ii11iIi11i - ooOoO0o % iIii1I11I1II1 - Ii1I
 def instance_id ( self , iid ) :
  if ( iid == 0 ) : return
  self . first_long |= LISP_I_BIT
  self . second_long &= 0xff
  self . second_long |= ( iid << 8 )
  if 37 - 37: OoO0O00 * I11i + Ii1I + I1ii11iIi11i * o0oOOo0O0Ooo
  if 95 - 95: Ii1I - i11iIiiIii % i11iIiiIii - O0 * I1Ii111
 def get_instance_id ( self ) :
  return ( ( self . second_long >> 8 ) & 0xffffff )
  if 81 - 81: II111iiii * I1IiiI % i1IIi * i11iIiiIii + OoOoOO00
  if 100 - 100: i1IIi % Ii1I
 def locator_status_bits ( self , lsbs ) :
  self . first_long |= LISP_L_BIT
  self . second_long &= 0xffffff00
  self . second_long |= ( lsbs & 0xff )
  if 55 - 55: I1IiiI + iII111i
  if 85 - 85: oO0o + iII111i % iII111i / I11i . I1IiiI - OoOoOO00
 def is_request_nonce ( self , nonce ) :
  return ( nonce & 0x80000000 )
  if 19 - 19: I11i / iII111i + IiII
  if 76 - 76: iIii1I11I1II1 / I1Ii111 - I1ii11iIi11i % o0oOOo0O0Ooo % OOooOOo + OoooooooOO
 def request_nonce ( self , nonce ) :
  self . first_long |= LISP_E_BIT
  self . first_long |= LISP_N_BIT
  self . first_long |= ( nonce & 0xffffff )
  if 10 - 10: OoO0O00 * I11i / Oo0Ooo - I1Ii111
  if 11 - 11: IiII % I1ii11iIi11i / ooOoO0o . i11iIiiIii + OOooOOo - II111iiii
 def is_e_bit_set ( self ) :
  return ( self . first_long & LISP_E_BIT )
  if 50 - 50: i1IIi * oO0o / i11iIiiIii / i11iIiiIii / oO0o
  if 84 - 84: I1ii11iIi11i - iII111i + I1ii11iIi11i
 def get_nonce ( self ) :
  return ( self . first_long & 0xffffff )
  if 63 - 63: I11i * ooOoO0o % II111iiii % I1Ii111 + I1IiiI * Oo0Ooo
  if 96 - 96: IiII
  if 99 - 99: iIii1I11I1II1 - ooOoO0o
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
  if 79 - 79: I1IiiI + oO0o % I11i % oO0o
  if 56 - 56: I1ii11iIi11i + oO0o . OoO0O00 + OoooooooOO * I1ii11iIi11i - O0
 def send_ipc ( self , ipc_socket , ipc ) :
  I1iO00O000oOO0oO = "lisp-itr" if lisp_i_am_itr else "lisp-etr"
  OO0i1Ii1II11 = "lisp-etr" if lisp_i_am_itr else "lisp-itr"
  ipc = lisp_command_ipc ( ipc , I1iO00O000oOO0oO )
  lisp_ipc ( ipc , ipc_socket , OO0i1Ii1II11 )
  if 25 - 25: OoooooooOO % oO0o / iIii1I11I1II1 + O0
  if 95 - 95: Oo0Ooo * OOooOOo + I1IiiI . O0
 def send_request_ipc ( self , ipc_socket , nonce ) :
  nonce = lisp_hex_string ( nonce )
  IIiIi1II1IiI = "nonce%R%{}%{}" . format ( self . rloc_str , nonce )
  self . send_ipc ( ipc_socket , IIiIi1II1IiI )
  if 99 - 99: Oo0Ooo
  if 17 - 17: i11iIiiIii - i11iIiiIii + I1ii11iIi11i * ooOoO0o * oO0o / OoooooooOO
 def send_echo_ipc ( self , ipc_socket , nonce ) :
  nonce = lisp_hex_string ( nonce )
  IIiIi1II1IiI = "nonce%E%{}%{}" . format ( self . rloc_str , nonce )
  self . send_ipc ( ipc_socket , IIiIi1II1IiI )
  if 22 - 22: I1Ii111 * I1ii11iIi11i - IiII
  if 71 - 71: iIii1I11I1II1 / i11iIiiIii % o0oOOo0O0Ooo . I1Ii111 * I1IiiI % II111iiii
 def receive_request ( self , ipc_socket , nonce ) :
  i1II1111 = self . request_nonce_rcvd
  self . request_nonce_rcvd = nonce
  self . last_request_nonce_rcvd = lisp_get_timestamp ( )
  if ( lisp_i_am_rtr ) : return
  if ( i1II1111 != nonce ) : self . send_request_ipc ( ipc_socket , nonce )
  if 55 - 55: iIii1I11I1II1 + I1IiiI - Oo0Ooo
  if 24 - 24: OoO0O00 / I1Ii111 + iII111i * I11i * iII111i
 def receive_echo ( self , ipc_socket , nonce ) :
  if ( self . request_nonce_sent != nonce ) : return
  self . last_echo_nonce_rcvd = lisp_get_timestamp ( )
  if ( self . echo_nonce_rcvd == nonce ) : return
  if 10 - 10: I1IiiI - I1ii11iIi11i - Oo0Ooo - o0oOOo0O0Ooo
  self . echo_nonce_rcvd = nonce
  if ( lisp_i_am_rtr ) : return
  self . send_echo_ipc ( ipc_socket , nonce )
  if 21 - 21: OoooooooOO + I1Ii111
  if 43 - 43: i11iIiiIii . I1ii11iIi11i . oO0o
 def get_request_or_echo_nonce ( self , ipc_socket , remote_rloc ) :
  if 31 - 31: Ii1I % o0oOOo0O0Ooo % I1Ii111 . I1ii11iIi11i / o0oOOo0O0Ooo * oO0o
  if 74 - 74: I1IiiI . ooOoO0o / iII111i . IiII
  if 74 - 74: Oo0Ooo / I1Ii111 % I1Ii111 . IiII
  if 72 - 72: i1IIi
  if 21 - 21: I1Ii111 . OOooOOo / i11iIiiIii * i1IIi
  if ( self . request_nonce_sent and self . echo_nonce_sent and remote_rloc ) :
   O00O0ooo00OO0 = lisp_myrlocs [ 0 ] if remote_rloc . is_ipv4 ( ) else lisp_myrlocs [ 1 ]
   if 63 - 63: I11i * II111iiii
   if 70 - 70: II111iiii + iII111i * OoOoOO00
   if ( remote_rloc . address > O00O0ooo00OO0 . address ) :
    iiiI111I = "exit"
    self . request_nonce_sent = None
   else :
    iiiI111I = "stay in"
    self . echo_nonce_sent = None
    if 61 - 61: OOooOOo + OOooOOo + oO0o / iIii1I11I1II1
    if 91 - 91: I1IiiI / II111iiii * OOooOOo
   ooOoo000 = bold ( "collision" , False )
   o0Oo = red ( O00O0ooo00OO0 . print_address_no_iid ( ) , False )
   o0O = red ( remote_rloc . print_address_no_iid ( ) , False )
   lprint ( "Echo nonce {}, {} -> {}, {} request-nonce mode" . format ( ooOoo000 ,
 o0Oo , o0O , iiiI111I ) )
   if 11 - 11: OoooooooOO % Ii1I
   if 81 - 81: OoO0O00 - iIii1I11I1II1
   if 60 - 60: I1Ii111
   if 77 - 77: I1IiiI / I1ii11iIi11i
   if 95 - 95: I1Ii111 * i1IIi + oO0o
  if ( self . echo_nonce_sent != None ) :
   I11iIi1i1I1i1 = self . echo_nonce_sent
   O0O0o0o0o = bold ( "Echoing" , False )
   lprint ( "{} nonce 0x{} to {}" . format ( O0O0o0o0o ,
 lisp_hex_string ( I11iIi1i1I1i1 ) , red ( self . rloc_str , False ) ) )
   self . last_echo_nonce_sent = lisp_get_timestamp ( )
   self . echo_nonce_sent = None
   return ( I11iIi1i1I1i1 )
   if 40 - 40: II111iiii
   if 7 - 7: OOooOOo / OoO0O00
   if 88 - 88: i1IIi
   if 53 - 53: ooOoO0o . OOooOOo . o0oOOo0O0Ooo + oO0o
   if 17 - 17: iIii1I11I1II1 + i1IIi . I1ii11iIi11i + Ii1I % i1IIi . oO0o
   if 57 - 57: oO0o
   if 92 - 92: II111iiii - OoO0O00 - OOooOOo % I1IiiI - OoOoOO00 * I1Ii111
  I11iIi1i1I1i1 = self . request_nonce_sent
  IiIi11 = self . last_request_nonce_sent
  if ( I11iIi1i1I1i1 and IiIi11 != None ) :
   if ( time . time ( ) - IiIi11 >= LISP_NONCE_ECHO_INTERVAL ) :
    self . request_nonce_sent = None
    lprint ( "Stop request-nonce mode for {}, nonce 0x{}" . format ( red ( self . rloc_str , False ) , lisp_hex_string ( I11iIi1i1I1i1 ) ) )
    if 89 - 89: iII111i . OoOoOO00 . I11i
    return ( None )
    if 55 - 55: iII111i + Oo0Ooo
    if 95 - 95: I11i + Oo0Ooo + Oo0Ooo
    if 33 - 33: i1IIi % OoooooooOO / OoooooooOO
    if 88 - 88: I1Ii111 - Ii1I - oO0o + i1IIi
    if 15 - 15: OOooOOo
    if 31 - 31: oO0o % i1IIi . OoooooooOO - o0oOOo0O0Ooo + OoooooooOO
    if 45 - 45: OOooOOo + I11i / OoooooooOO - Ii1I + OoooooooOO
    if 42 - 42: iIii1I11I1II1 * I1IiiI * I1Ii111
    if 62 - 62: OOooOOo * O0 % IiII . IiII . I1IiiI
  if ( I11iIi1i1I1i1 == None ) :
   I11iIi1i1I1i1 = lisp_get_data_nonce ( )
   if ( self . recently_requested ( ) ) : return ( I11iIi1i1I1i1 )
   if 91 - 91: i1IIi . iII111i
   self . request_nonce_sent = I11iIi1i1I1i1
   lprint ( "Start request-nonce mode for {}, nonce 0x{}" . format ( red ( self . rloc_str , False ) , lisp_hex_string ( I11iIi1i1I1i1 ) ) )
   if 37 - 37: iII111i - I11i + iIii1I11I1II1 / I1Ii111 - OoO0O00 . o0oOOo0O0Ooo
   self . last_new_request_nonce_sent = lisp_get_timestamp ( )
   if 62 - 62: I1ii11iIi11i
   if 47 - 47: I1Ii111 % OOooOOo * OoO0O00 . iIii1I11I1II1 % Oo0Ooo + OoooooooOO
   if 2 - 2: I1Ii111 % OoooooooOO - ooOoO0o * I1ii11iIi11i * IiII
   if 99 - 99: iIii1I11I1II1 . Oo0Ooo / ooOoO0o . OOooOOo % I1IiiI * I11i
   if 95 - 95: oO0o
   if ( lisp_i_am_itr == False ) : return ( I11iIi1i1I1i1 | 0x80000000 )
   self . send_request_ipc ( ipc_socket , I11iIi1i1I1i1 )
  else :
   lprint ( "Continue request-nonce mode for {}, nonce 0x{}" . format ( red ( self . rloc_str , False ) , lisp_hex_string ( I11iIi1i1I1i1 ) ) )
   if 80 - 80: IiII
   if 42 - 42: OoooooooOO * II111iiii
   if 53 - 53: I1Ii111 + i1IIi . OoO0O00 / i11iIiiIii + Ii1I % OoOoOO00
   if 9 - 9: ooOoO0o . I11i - Oo0Ooo . I1Ii111
   if 39 - 39: OOooOOo
   if 70 - 70: IiII % OoO0O00 % I1IiiI
   if 95 - 95: OoOoOO00 - I1Ii111 / O0 * I1IiiI - o0oOOo0O0Ooo
  self . last_request_nonce_sent = lisp_get_timestamp ( )
  return ( I11iIi1i1I1i1 | 0x80000000 )
  if 12 - 12: iIii1I11I1II1 % Oo0Ooo . iII111i . IiII % i11iIiiIii
  if 2 - 2: oO0o * oO0o . OoOoOO00 * Ii1I * iIii1I11I1II1
 def request_nonce_timeout ( self ) :
  if ( self . request_nonce_sent == None ) : return ( False )
  if ( self . request_nonce_sent == self . echo_nonce_rcvd ) : return ( False )
  if 13 - 13: I11i / O0 . i11iIiiIii * i1IIi % i11iIiiIii
  Oo = time . time ( ) - self . last_request_nonce_sent
  iIi1Iii1 = self . last_echo_nonce_rcvd
  return ( Oo >= LISP_NONCE_ECHO_INTERVAL and iIi1Iii1 == None )
  if 87 - 87: OoooooooOO
  if 1 - 1: iIii1I11I1II1 / o0oOOo0O0Ooo
 def recently_requested ( self ) :
  iIi1Iii1 = self . last_request_nonce_sent
  if ( iIi1Iii1 == None ) : return ( False )
  if 98 - 98: O0 % I1IiiI / OoooooooOO * I1ii11iIi11i - oO0o
  Oo = time . time ( ) - iIi1Iii1
  return ( Oo <= LISP_NONCE_ECHO_INTERVAL )
  if 51 - 51: iII111i + I11i
  if 54 - 54: II111iiii * O0 % I1IiiI . I11i
 def recently_echoed ( self ) :
  if ( self . request_nonce_sent == None ) : return ( True )
  if 62 - 62: Ii1I . i11iIiiIii % O0 % I1Ii111 - Oo0Ooo
  if 69 - 69: II111iiii . OoOoOO00 * OoOoOO00 % Ii1I + I1IiiI
  if 100 - 100: i11iIiiIii - Oo0Ooo
  if 47 - 47: iII111i * OoOoOO00 * IiII
  iIi1Iii1 = self . last_good_echo_nonce_rcvd
  if ( iIi1Iii1 == None ) : iIi1Iii1 = 0
  Oo = time . time ( ) - iIi1Iii1
  if ( Oo <= LISP_NONCE_ECHO_INTERVAL ) : return ( True )
  if 46 - 46: Ii1I
  if 42 - 42: iIii1I11I1II1
  if 32 - 32: Oo0Ooo - Ii1I . OoooooooOO - OoooooooOO - Oo0Ooo . iIii1I11I1II1
  if 34 - 34: Oo0Ooo
  if 31 - 31: i1IIi - I11i + I1Ii111 + ooOoO0o . ooOoO0o . O0
  if 33 - 33: i1IIi / iII111i * OoO0O00
  iIi1Iii1 = self . last_new_request_nonce_sent
  if ( iIi1Iii1 == None ) : iIi1Iii1 = 0
  Oo = time . time ( ) - iIi1Iii1
  return ( Oo <= LISP_NONCE_ECHO_INTERVAL )
  if 2 - 2: oO0o . OOooOOo
  if 43 - 43: iIii1I11I1II1
 def change_state ( self , rloc ) :
  if ( rloc . up_state ( ) and self . recently_echoed ( ) == False ) :
   I1I1iIIiii1 = bold ( "down" , False )
   I1IIiiiiI1iIi = lisp_print_elapsed ( self . last_good_echo_nonce_rcvd )
   lprint ( "Take {} {}, last good echo: {}" . format ( red ( self . rloc_str , False ) , I1I1iIIiii1 , I1IIiiiiI1iIi ) )
   if 82 - 82: i11iIiiIii + O0 - Ii1I
   rloc . state = LISP_RLOC_NO_ECHOED_NONCE_STATE
   rloc . last_state_change = lisp_get_timestamp ( )
   return
   if 63 - 63: OoOoOO00
   if 61 - 61: II111iiii * Ii1I + II111iiii % iII111i . i1IIi . oO0o
  if ( rloc . no_echoed_nonce_state ( ) == False ) : return
  if 33 - 33: iIii1I11I1II1 + I1IiiI / oO0o * iII111i - oO0o
  if ( self . recently_requested ( ) == False ) :
   O00 = bold ( "up" , False )
   lprint ( "Bring {} {}, retry request-nonce mode" . format ( red ( self . rloc_str , False ) , O00 ) )
   if 20 - 20: Ii1I / iII111i + II111iiii . i11iIiiIii . OOooOOo
   rloc . state = LISP_RLOC_UP_STATE
   rloc . last_state_change = lisp_get_timestamp ( )
   if 77 - 77: OoOoOO00
   if 91 - 91: oO0o
   if 56 - 56: iIii1I11I1II1 % II111iiii / OoOoOO00 % OoooooooOO
 def print_echo_nonce ( self ) :
  I1IiIIIIi1iiI = lisp_print_elapsed ( self . last_request_nonce_sent )
  O0ii = lisp_print_elapsed ( self . last_good_echo_nonce_rcvd )
  if 53 - 53: Ii1I / I1IiiI * Ii1I + o0oOOo0O0Ooo + oO0o - Oo0Ooo
  IIi1iiIIi1i = lisp_print_elapsed ( self . last_echo_nonce_sent )
  ii1I = lisp_print_elapsed ( self . last_request_nonce_rcvd )
  oooOOO00o0 = space ( 4 )
  if 33 - 33: i11iIiiIii % OoOoOO00 % OOooOOo % i11iIiiIii - I1ii11iIi11i
  OOoo0oo = "Nonce-Echoing:\n"
  OOoo0oo += ( "{}Last request-nonce sent: {}\n{}Last echo-nonce " + "received: {}\n" ) . format ( oooOOO00o0 , I1IiIIIIi1iiI , oooOOO00o0 , O0ii )
  if 21 - 21: I11i . Oo0Ooo - OoooooooOO * i1IIi
  OOoo0oo += ( "{}Last request-nonce received: {}\n{}Last echo-nonce " + "sent: {}" ) . format ( oooOOO00o0 , ii1I , oooOOO00o0 , IIi1iiIIi1i )
  if 54 - 54: II111iiii % o0oOOo0O0Ooo - i1IIi . I1IiiI - II111iiii / iIii1I11I1II1
  if 29 - 29: oO0o
  return ( OOoo0oo )
  if 66 - 66: OoooooooOO + iII111i . IiII % i1IIi
  if 58 - 58: OOooOOo % iII111i * O0 + I1ii11iIi11i - IiII
  if 26 - 26: i1IIi / I1IiiI / I11i + I11i
  if 46 - 46: I1Ii111 % I1ii11iIi11i + Ii1I
  if 67 - 67: iIii1I11I1II1 . i11iIiiIii . i11iIiiIii . i11iIiiIii / I11i + ooOoO0o
  if 10 - 10: ooOoO0o - Oo0Ooo % II111iiii
  if 66 - 66: iIii1I11I1II1 . iIii1I11I1II1
  if 46 - 46: I1Ii111 * oO0o . Ii1I * I1Ii111 * iIii1I11I1II1 / I11i
  if 46 - 46: II111iiii % I1ii11iIi11i . OOooOOo . Oo0Ooo / i11iIiiIii + OoO0O00
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
    if 47 - 47: IiII . OOooOOo
   self . local_private_key = random . randint ( 0 , 2 ** 128 - 1 )
   o0000oO = lisp_hex_string ( self . local_private_key ) . zfill ( 32 )
   self . curve25519 = curve25519 . Private ( o0000oO )
  else :
   self . local_private_key = random . randint ( 0 , 0x1fff )
   if 96 - 96: I11i % II111iiii / ooOoO0o % OOooOOo / ooOoO0o % i11iIiiIii
  self . local_public_key = self . compute_public_key ( )
  self . remote_public_key = None
  self . shared_key = None
  self . encrypt_key = None
  self . icv_key = None
  self . icv = poly1305 if do_poly else hashlib . sha256
  self . iv = None
  self . get_iv ( )
  self . do_poly = do_poly
  if 57 - 57: I11i - I11i % II111iiii % Oo0Ooo . o0oOOo0O0Ooo % Oo0Ooo
  if 91 - 91: I1IiiI - OoO0O00 - Oo0Ooo - Ii1I * iIii1I11I1II1
 def copy_keypair ( self , key ) :
  self . local_private_key = key . local_private_key
  self . local_public_key = key . local_public_key
  self . curve25519 = key . curve25519
  if 68 - 68: OoO0O00 % O0 * iIii1I11I1II1 / oO0o * o0oOOo0O0Ooo + OOooOOo
  if 89 - 89: ooOoO0o * I1IiiI . oO0o
 def get_iv ( self ) :
  if ( self . iv == None ) :
   self . iv = random . randint ( 0 , LISP_16_128_MASK )
  else :
   self . iv += 1
   if 75 - 75: ooOoO0o - iII111i % iII111i + ooOoO0o * o0oOOo0O0Ooo - I1ii11iIi11i
  O0Ooo0ooo00o = self . iv
  if ( self . cipher_suite == LISP_CS_25519_CHACHA ) :
   O0Ooo0ooo00o = struct . pack ( "Q" , O0Ooo0ooo00o & LISP_8_64_MASK )
  elif ( self . cipher_suite == LISP_CS_25519_GCM ) :
   I111Ii1I1I1iI = struct . pack ( "I" , ( O0Ooo0ooo00o >> 64 ) & LISP_4_32_MASK )
   III = struct . pack ( "Q" , O0Ooo0ooo00o & LISP_8_64_MASK )
   O0Ooo0ooo00o = I111Ii1I1I1iI + III
  else :
   O0Ooo0ooo00o = struct . pack ( "QQ" , O0Ooo0ooo00o >> 64 , O0Ooo0ooo00o & LISP_8_64_MASK )
  return ( O0Ooo0ooo00o )
  if 84 - 84: i11iIiiIii / o0oOOo0O0Ooo % iIii1I11I1II1 . ooOoO0o . OoO0O00 / iII111i
  if 55 - 55: iII111i
 def key_length ( self , key ) :
  if ( type ( key ) != str ) : key = self . normalize_pub_key ( key )
  return ( len ( key ) / 2 )
  if 3 - 3: iIii1I11I1II1
  if 19 - 19: II111iiii . OoO0O00 * OoO0O00 + I1IiiI % Oo0Ooo
 def print_key ( self , key ) :
  IiIIi11i = self . normalize_pub_key ( key )
  return ( "0x{}...{}({})" . format ( IiIIi11i [ 0 : 4 ] , IiIIi11i [ - 4 : : ] , self . key_length ( IiIIi11i ) ) )
  if 21 - 21: OoOoOO00 - i11iIiiIii - OoOoOO00
  if 4 - 4: I11i . IiII
 def normalize_pub_key ( self , key ) :
  if ( type ( key ) == str ) :
   if ( self . curve25519 ) : return ( binascii . hexlify ( key ) )
   return ( key )
   if 39 - 39: OOooOOo . Oo0Ooo - OoOoOO00 * i11iIiiIii
  key = lisp_hex_string ( key ) . zfill ( 256 )
  return ( key )
  if 4 - 4: OoOoOO00 * O0 - I11i
  if 72 - 72: I11i + ooOoO0o / I1IiiI . IiII % OoO0O00 / i11iIiiIii
 def print_keys ( self , do_bold = True ) :
  o0Oo = bold ( "local-key: " , False ) if do_bold else "local-key: "
  if ( self . local_public_key == None ) :
   o0Oo += "none"
  else :
   o0Oo += self . print_key ( self . local_public_key )
   if 13 - 13: I1Ii111 % o0oOOo0O0Ooo + OOooOOo + I1Ii111 + i11iIiiIii - I1ii11iIi11i
  o0O = bold ( "remote-key: " , False ) if do_bold else "remote-key: "
  if ( self . remote_public_key == None ) :
   o0O += "none"
  else :
   o0O += self . print_key ( self . remote_public_key )
   if 70 - 70: II111iiii * II111iiii . I1IiiI
  iiIi1111iiI1 = "ECDH" if ( self . curve25519 ) else "DH"
  o00oo00 = self . cipher_suite
  return ( "{} cipher-suite: {}, {}, {}" . format ( iiIi1111iiI1 , o00oo00 , o0Oo , o0O ) )
  if 57 - 57: OOooOOo + o0oOOo0O0Ooo . OOooOOo
  if 64 - 64: OoOoOO00
 def compare_keys ( self , keys ) :
  if ( self . dh_g_value != keys . dh_g_value ) : return ( False )
  if ( self . dh_p_value != keys . dh_p_value ) : return ( False )
  if ( self . remote_public_key != keys . remote_public_key ) : return ( False )
  return ( True )
  if 28 - 28: O0 + I1Ii111 / OoO0O00 + I1Ii111
  if 91 - 91: OoooooooOO . OOooOOo - ooOoO0o + II111iiii + Ii1I . OoooooooOO
 def compute_public_key ( self ) :
  if ( self . curve25519 ) : return ( self . curve25519 . get_public ( ) . public )
  if 42 - 42: iIii1I11I1II1 / I11i . O0 . Ii1I
  o0000oO = self . local_private_key
  Ii1i111iI = self . dh_g_value
  iII1ii = self . dh_p_value
  return ( int ( ( Ii1i111iI ** o0000oO ) % iII1ii ) )
  if 51 - 51: o0oOOo0O0Ooo . I1ii11iIi11i * Ii1I / Oo0Ooo * II111iiii / O0
  if 44 - 44: i11iIiiIii % I1Ii111 % oO0o + I11i * oO0o . Ii1I
 def compute_shared_key ( self , ed , print_shared = False ) :
  o0000oO = self . local_private_key
  OoOo0Oooo0o = self . remote_public_key
  if 65 - 65: OoOoOO00 + I1Ii111 % I1IiiI
  o0OO0 = bold ( "Compute {} shared-key" . format ( ed ) , False )
  lprint ( "{}, key-material: {}" . format ( o0OO0 , self . print_keys ( ) ) )
  if 69 - 69: oO0o * I1ii11iIi11i - O0 + I1IiiI + o0oOOo0O0Ooo
  if ( self . curve25519 ) :
   oooOo = curve25519 . Public ( OoOo0Oooo0o )
   self . shared_key = self . curve25519 . get_shared_key ( oooOo )
  else :
   iII1ii = self . dh_p_value
   self . shared_key = ( OoOo0Oooo0o ** o0000oO ) % iII1ii
   if 91 - 91: I1IiiI - iII111i / OoO0O00 - OoO0O00 / Ii1I - IiII
   if 14 - 14: OOooOOo / o0oOOo0O0Ooo + Ii1I / OoooooooOO - I11i
   if 88 - 88: Ii1I / OoooooooOO % OoOoOO00 - i1IIi
   if 49 - 49: o0oOOo0O0Ooo - iIii1I11I1II1
   if 61 - 61: iII111i * ooOoO0o
   if 1 - 1: I1Ii111 * OoOoOO00
   if 100 - 100: I1ii11iIi11i / O0 / ooOoO0o + I1ii11iIi11i
  if ( print_shared ) :
   IiIIi11i = self . print_key ( self . shared_key )
   lprint ( "Computed shared-key: {}" . format ( IiIIi11i ) )
   if 48 - 48: OoooooooOO . iII111i + O0
   if 85 - 85: II111iiii - Ii1I
   if 93 - 93: IiII / i11iIiiIii - oO0o + OoO0O00 / i1IIi
   if 62 - 62: I1ii11iIi11i / OoooooooOO * I1IiiI - i1IIi
   if 81 - 81: oO0o / O0 * ooOoO0o % OoOoOO00 / O0
  self . compute_encrypt_icv_keys ( )
  if 85 - 85: OoooooooOO + OoooooooOO
  if 23 - 23: i1IIi
  if 31 - 31: Oo0Ooo - iIii1I11I1II1 / I11i . OoO0O00
  if 74 - 74: Oo0Ooo - II111iiii - IiII
  self . rekey_count += 1
  self . last_rekey = lisp_get_timestamp ( )
  if 50 - 50: I1IiiI - oO0o + oO0o * I11i + oO0o
  if 70 - 70: i1IIi % OoO0O00 / i1IIi
 def compute_encrypt_icv_keys ( self ) :
  iIi1i1I1I = hashlib . sha256
  if ( self . curve25519 ) :
   i11iiiI = self . shared_key
  else :
   i11iiiI = lisp_hex_string ( self . shared_key )
   if 100 - 100: IiII / I1ii11iIi11i - iII111i
   if 85 - 85: Ii1I + I1Ii111 . OOooOOo . O0 . OoOoOO00 * II111iiii
   if 86 - 86: i1IIi * I1IiiI
   if 53 - 53: O0 . OOooOOo
   if 79 - 79: OoooooooOO * I1Ii111 - i1IIi * OoooooooOO % O0 % iIii1I11I1II1
  o0Oo = self . local_public_key
  if ( type ( o0Oo ) != long ) : o0Oo = int ( binascii . hexlify ( o0Oo ) , 16 )
  o0O = self . remote_public_key
  if ( type ( o0O ) != long ) : o0O = int ( binascii . hexlify ( o0O ) , 16 )
  oO0 = "0001" + "lisp-crypto" + lisp_hex_string ( o0Oo ^ o0O ) + "0100"
  if 73 - 73: I1Ii111
  i1IiIiiiii11 = hmac . new ( oO0 , i11iiiI , iIi1i1I1I ) . hexdigest ( )
  i1IiIiiiii11 = int ( i1IiIiiiii11 , 16 )
  if 58 - 58: OoooooooOO / iIii1I11I1II1
  if 25 - 25: O0 % i11iIiiIii + Ii1I + OOooOOo
  if 40 - 40: o0oOOo0O0Ooo + I1Ii111 * oO0o + I11i
  if 75 - 75: OoO0O00 - OoOoOO00 - i1IIi % Oo0Ooo - II111iiii
  oOoooO = ( i1IiIiiiii11 >> 128 ) & LISP_16_128_MASK
  o00OooooOOOO = i1IiIiiiii11 & LISP_16_128_MASK
  self . encrypt_key = lisp_hex_string ( oOoooO ) . zfill ( 32 )
  oo000o = 32 if self . do_poly else 40
  self . icv_key = lisp_hex_string ( o00OooooOOOO ) . zfill ( oo000o )
  if 6 - 6: OOooOOo + I1ii11iIi11i + Oo0Ooo
  if 52 - 52: IiII * Oo0Ooo + OoooooooOO
 def do_icv ( self , packet , nonce ) :
  if ( self . icv_key == None ) : return ( "" )
  if ( self . do_poly ) :
   oo0oooOoO0OOo = self . icv . poly1305aes
   IIIo0Oo00OOO0o = self . icv . binascii . hexlify
   nonce = IIIo0Oo00OOO0o ( nonce )
   IIIiiII1iIi1ii1i = oo0oooOoO0OOo ( self . encrypt_key , self . icv_key , nonce , packet )
   IIIiiII1iIi1ii1i = IIIo0Oo00OOO0o ( IIIiiII1iIi1ii1i )
  else :
   o0000oO = binascii . unhexlify ( self . icv_key )
   IIIiiII1iIi1ii1i = hmac . new ( o0000oO , packet , self . icv ) . hexdigest ( )
   IIIiiII1iIi1ii1i = IIIiiII1iIi1ii1i [ 0 : 40 ]
   if 49 - 49: OoOoOO00
  return ( IIIiiII1iIi1ii1i )
  if 99 - 99: O0 + IiII + ooOoO0o - ooOoO0o * I1ii11iIi11i / IiII
  if 82 - 82: o0oOOo0O0Ooo - OOooOOo
 def add_key_by_nonce ( self , nonce ) :
  if ( lisp_crypto_keys_by_nonce . has_key ( nonce ) == False ) :
   lisp_crypto_keys_by_nonce [ nonce ] = [ None , None , None , None ]
   if 84 - 84: iII111i % i1IIi % OoO0O00 % II111iiii
  lisp_crypto_keys_by_nonce [ nonce ] [ self . key_id ] = self
  if 94 - 94: ooOoO0o * O0
  if 60 - 60: iII111i / iII111i - ooOoO0o / OoooooooOO + O0
 def delete_key_by_nonce ( self , nonce ) :
  if ( lisp_crypto_keys_by_nonce . has_key ( nonce ) == False ) : return
  lisp_crypto_keys_by_nonce . pop ( nonce )
  if 55 - 55: OoO0O00 % O0 / OoooooooOO
  if 49 - 49: I1IiiI . OoO0O00 * OoooooooOO % i11iIiiIii + iIii1I11I1II1 * i1IIi
 def add_key_by_rloc ( self , addr_str , encap ) :
  oOO0oOoooOoo0 = lisp_crypto_keys_by_rloc_encap if encap else lisp_crypto_keys_by_rloc_decap
  if 1 - 1: O0 + iII111i * ooOoO0o - i11iIiiIii
  if 18 - 18: ooOoO0o
  if ( oOO0oOoooOoo0 . has_key ( addr_str ) == False ) :
   oOO0oOoooOoo0 [ addr_str ] = [ None , None , None , None ]
   if 37 - 37: Oo0Ooo % i11iIiiIii - I1IiiI * I1ii11iIi11i . ooOoO0o
  oOO0oOoooOoo0 [ addr_str ] [ self . key_id ] = self
  if 62 - 62: OoooooooOO / ooOoO0o + I1ii11iIi11i . o0oOOo0O0Ooo - iII111i
  if 29 - 29: oO0o
  if 26 - 26: O0 % OOooOOo - IiII . OOooOOo
  if 70 - 70: o0oOOo0O0Ooo + I11i / iII111i + ooOoO0o / I1IiiI
  if 33 - 33: OoooooooOO . O0
  if ( encap == False ) :
   lisp_write_ipc_decap_key ( addr_str , oOO0oOoooOoo0 [ addr_str ] )
   if 59 - 59: iIii1I11I1II1
   if 45 - 45: O0
   if 78 - 78: I11i - iIii1I11I1II1 + I1Ii111 - I1ii11iIi11i - I1Ii111
 def encode_lcaf ( self , rloc_addr ) :
  iii1 = self . normalize_pub_key ( self . local_public_key )
  iII1iii = self . key_length ( iii1 )
  o0O0o = ( 6 + iII1iii + 2 )
  if ( rloc_addr != None ) : o0O0o += rloc_addr . addr_length ( )
  if 79 - 79: OoOoOO00 + iIii1I11I1II1 * i1IIi * ooOoO0o - I11i * OoO0O00
  iIIi1 = struct . pack ( "HBBBBHBB" , socket . htons ( LISP_AFI_LCAF ) , 0 , 0 ,
 LISP_LCAF_SECURITY_TYPE , 0 , socket . htons ( o0O0o ) , 1 , 0 )
  if 78 - 78: iII111i % i11iIiiIii + iII111i + o0oOOo0O0Ooo
  if 22 - 22: I11i - o0oOOo0O0Ooo
  if 54 - 54: oO0o * OoO0O00 - iII111i * I11i + o0oOOo0O0Ooo - Ii1I
  if 5 - 5: oO0o + Ii1I
  if 48 - 48: I1Ii111 * i1IIi - I1ii11iIi11i / I1IiiI + i11iIiiIii - i1IIi
  if 91 - 91: o0oOOo0O0Ooo / i11iIiiIii
  o00oo00 = self . cipher_suite
  iIIi1 += struct . pack ( "BBH" , o00oo00 , 0 , socket . htons ( iII1iii ) )
  if 96 - 96: OoO0O00 + iII111i * II111iiii
  if 82 - 82: o0oOOo0O0Ooo + Ii1I * I1IiiI - oO0o
  if 6 - 6: OOooOOo / iIii1I11I1II1 / ooOoO0o / I1IiiI - i1IIi - OOooOOo
  if 8 - 8: i11iIiiIii * I11i . OOooOOo / OOooOOo
  for ooOooo0OO in range ( 0 , iII1iii * 2 , 16 ) :
   o0000oO = int ( iii1 [ ooOooo0OO : ooOooo0OO + 16 ] , 16 )
   iIIi1 += struct . pack ( "Q" , byte_swap_64 ( o0000oO ) )
   if 42 - 42: OoooooooOO / I1Ii111 . o0oOOo0O0Ooo / O0 - IiII * IiII
   if 1 - 1: Ii1I % I1Ii111
   if 97 - 97: OoOoOO00
   if 13 - 13: OoOoOO00 % OOooOOo . O0 / Oo0Ooo % Oo0Ooo
   if 19 - 19: I1Ii111 % ooOoO0o - ooOoO0o % I1IiiI . OOooOOo - OoooooooOO
  if ( rloc_addr ) :
   iIIi1 += struct . pack ( "H" , socket . htons ( rloc_addr . afi ) )
   iIIi1 += rloc_addr . pack_address ( )
   if 100 - 100: I1IiiI + Ii1I + o0oOOo0O0Ooo . i1IIi % OoooooooOO
  return ( iIIi1 )
  if 64 - 64: O0 % i1IIi * I1Ii111 - Ii1I + Oo0Ooo
  if 65 - 65: OoOoOO00 . i11iIiiIii
 def decode_lcaf ( self , packet , lcaf_len ) :
  if 36 - 36: oO0o * iII111i + IiII * iII111i . I1ii11iIi11i - iIii1I11I1II1
  if 14 - 14: I11i * oO0o + i11iIiiIii
  if 84 - 84: iII111i / II111iiii
  if 86 - 86: I1IiiI
  if ( lcaf_len == 0 ) :
   I1I = "HHBBH"
   ii1I1iIi = struct . calcsize ( I1I )
   if ( len ( packet ) < ii1I1iIi ) : return ( None )
   if 97 - 97: II111iiii
   ooo0O0O0oo0 , iIiIii , ii111I1IiiI1i , iIiIii , lcaf_len = struct . unpack ( I1I , packet [ : ii1I1iIi ] )
   if 22 - 22: II111iiii / I1ii11iIi11i * IiII - o0oOOo0O0Ooo % I1ii11iIi11i
   if 70 - 70: II111iiii - IiII
   if ( ii111I1IiiI1i != LISP_LCAF_SECURITY_TYPE ) :
    packet = packet [ lcaf_len + 6 : : ]
    return ( packet )
    if 76 - 76: I1Ii111
   lcaf_len = socket . ntohs ( lcaf_len )
   packet = packet [ ii1I1iIi : : ]
   if 43 - 43: O0 / I1Ii111 . iIii1I11I1II1 - OoOoOO00
   if 47 - 47: II111iiii - I1ii11iIi11i - Ii1I
   if 9 - 9: I1ii11iIi11i - IiII
   if 64 - 64: i1IIi
   if 71 - 71: IiII * o0oOOo0O0Ooo
   if 99 - 99: o0oOOo0O0Ooo
  ii111I1IiiI1i = LISP_LCAF_SECURITY_TYPE
  I1I = "BBBBH"
  ii1I1iIi = struct . calcsize ( I1I )
  if ( len ( packet ) < ii1I1iIi ) : return ( None )
  if 28 - 28: OoooooooOO % O0 - OOooOOo / o0oOOo0O0Ooo / I1IiiI
  Iii1iIII1Iii , iIiIii , o00oo00 , iIiIii , iII1iii = struct . unpack ( I1I ,
 packet [ : ii1I1iIi ] )
  if 13 - 13: iIii1I11I1II1 - OOooOOo
  if 14 - 14: ooOoO0o
  if 75 - 75: iIii1I11I1II1 % ooOoO0o / OOooOOo - iII111i % i11iIiiIii
  if 11 - 11: I11i . Ii1I
  if 87 - 87: OOooOOo + OOooOOo
  if 45 - 45: i1IIi - Oo0Ooo
  packet = packet [ ii1I1iIi : : ]
  iII1iii = socket . ntohs ( iII1iii )
  if ( len ( packet ) < iII1iii ) : return ( None )
  if 87 - 87: OoOoOO00 - OoO0O00 * OoO0O00 / Ii1I . I11i * o0oOOo0O0Ooo
  if 21 - 21: II111iiii
  if 29 - 29: OoOoOO00 % Ii1I
  if 7 - 7: i1IIi / IiII / iII111i
  oOo0OO0 = [ LISP_CS_25519_CBC , LISP_CS_25519_GCM , LISP_CS_25519_CHACHA ,
 LISP_CS_1024 ]
  if ( o00oo00 not in oOo0OO0 ) :
   lprint ( "Cipher-suites {} supported, received {}" . format ( oOo0OO0 ,
 o00oo00 ) )
   packet = packet [ iII1iii : : ]
   return ( packet )
   if 56 - 56: II111iiii . II111iiii + IiII . o0oOOo0O0Ooo
   if 32 - 32: ooOoO0o . IiII . II111iiii
  self . cipher_suite = o00oo00
  if 25 - 25: IiII * I1Ii111 - oO0o * i11iIiiIii * I1IiiI * OOooOOo
  if 56 - 56: OoooooooOO . I1IiiI . II111iiii % iII111i
  if 59 - 59: ooOoO0o % Oo0Ooo - oO0o + IiII
  if 33 - 33: Ii1I + OoOoOO00 - I1ii11iIi11i + iIii1I11I1II1 % i1IIi * IiII
  if 21 - 21: O0 * ooOoO0o % OoO0O00
  iii1 = 0
  for ooOooo0OO in range ( 0 , iII1iii , 8 ) :
   o0000oO = byte_swap_64 ( struct . unpack ( "Q" , packet [ ooOooo0OO : ooOooo0OO + 8 ] ) [ 0 ] )
   iii1 <<= 64
   iii1 |= o0000oO
   if 14 - 14: O0 / I1Ii111 / ooOoO0o + IiII - IiII
  self . remote_public_key = iii1
  if 10 - 10: O0 - I1ii11iIi11i / I1Ii111 % OoOoOO00 / OoooooooOO / Ii1I
  if 73 - 73: ooOoO0o + IiII % o0oOOo0O0Ooo . I1ii11iIi11i / OOooOOo . I1Ii111
  if 76 - 76: I11i . I1ii11iIi11i * OoooooooOO % iII111i
  if 24 - 24: OoooooooOO
  if 83 - 83: O0 / OoO0O00
  if ( self . curve25519 ) :
   o0000oO = lisp_hex_string ( self . remote_public_key )
   o0000oO = o0000oO . zfill ( 64 )
   o0O000O00o = ""
   for ooOooo0OO in range ( 0 , len ( o0000oO ) , 2 ) :
    o0O000O00o += chr ( int ( o0000oO [ ooOooo0OO : ooOooo0OO + 2 ] , 16 ) )
    if 38 - 38: OoooooooOO . iII111i
   self . remote_public_key = o0O000O00o
   if 43 - 43: OoooooooOO
   if 8 - 8: OOooOOo + I11i . I11i
  packet = packet [ iII1iii : : ]
  return ( packet )
  if 89 - 89: I1ii11iIi11i * I1ii11iIi11i * OoOoOO00 / iII111i
  if 60 - 60: OoO0O00 / iII111i / I1IiiI + oO0o
  if 93 - 93: OoooooooOO * Ii1I / O0 + Ii1I - iIii1I11I1II1
  if 6 - 6: IiII - Oo0Ooo - I11i - O0 % OoooooooOO
  if 88 - 88: O0 / o0oOOo0O0Ooo * o0oOOo0O0Ooo . o0oOOo0O0Ooo . O0
  if 27 - 27: i11iIiiIii % iII111i + Ii1I . OOooOOo
  if 9 - 9: OoO0O00
  if 43 - 43: Ii1I . OOooOOo + I1IiiI * i11iIiiIii
class lisp_thread ( ) :
 def __init__ ( self , name ) :
  self . thread_name = name
  self . thread_number = - 1
  self . number_of_pcap_threads = 0
  self . number_of_worker_threads = 0
  self . input_queue = Queue . Queue ( )
  self . input_stats = lisp_stats ( )
  self . lisp_packet = lisp_packet ( None )
  if 2 - 2: OOooOOo
  if 3 - 3: I1IiiI . iII111i % O0 - ooOoO0o / O0
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
  if 28 - 28: iII111i - o0oOOo0O0Ooo
  if 92 - 92: Oo0Ooo % o0oOOo0O0Ooo - ooOoO0o / ooOoO0o / OoOoOO00
 def decode ( self , packet ) :
  I1I = "BBBBQ"
  ii1I1iIi = struct . calcsize ( I1I )
  if ( len ( packet ) < ii1I1iIi ) : return ( False )
  if 84 - 84: OOooOOo
  I1I1I1 , iIiiiiII11 , OOOo , self . record_count , self . nonce = struct . unpack ( I1I , packet [ : ii1I1iIi ] )
  if 22 - 22: i1IIi / IiII * I11i
  if 96 - 96: o0oOOo0O0Ooo - I1IiiI % OoOoOO00 + OoO0O00 - IiII - IiII
  self . type = I1I1I1 >> 4
  if ( self . type == LISP_MAP_REQUEST ) :
   self . smr_bit = True if ( I1I1I1 & 0x01 ) else False
   self . rloc_probe = True if ( I1I1I1 & 0x02 ) else False
   self . smr_invoked_bit = True if ( iIiiiiII11 & 0x40 ) else False
   if 2 - 2: ooOoO0o % i11iIiiIii
  if ( self . type == LISP_ECM ) :
   self . ddt_bit = True if ( I1I1I1 & 0x04 ) else False
   self . to_etr = True if ( I1I1I1 & 0x02 ) else False
   self . to_ms = True if ( I1I1I1 & 0x01 ) else False
   if 11 - 11: iIii1I11I1II1 . I1Ii111 - Oo0Ooo / I11i + II111iiii
  if ( self . type == LISP_NAT_INFO ) :
   self . info_reply = True if ( I1I1I1 & 0x08 ) else False
   if 29 - 29: I11i . i11iIiiIii + i1IIi - Ii1I + O0 . I1IiiI
  return ( True )
  if 8 - 8: o0oOOo0O0Ooo
  if 78 - 78: i1IIi - Oo0Ooo
 def is_info_request ( self ) :
  return ( ( self . type == LISP_NAT_INFO and self . is_info_reply ( ) == False ) )
  if 48 - 48: Ii1I - OoooooooOO + I1Ii111 % o0oOOo0O0Ooo - OoOoOO00 . I1IiiI
  if 42 - 42: I1Ii111
 def is_info_reply ( self ) :
  return ( True if self . info_reply else False )
  if 70 - 70: o0oOOo0O0Ooo / I11i + oO0o % I1IiiI % Oo0Ooo + OoO0O00
  if 80 - 80: OOooOOo
 def is_rloc_probe ( self ) :
  return ( True if self . rloc_probe else False )
  if 12 - 12: Ii1I
  if 2 - 2: OoooooooOO
 def is_smr ( self ) :
  return ( True if self . smr_bit else False )
  if 100 - 100: Oo0Ooo / O0 * i11iIiiIii * OoooooooOO
  if 46 - 46: O0 % OoooooooOO
 def is_smr_invoked ( self ) :
  return ( True if self . smr_invoked_bit else False )
  if 22 - 22: iII111i + OoooooooOO - OoOoOO00 - OoO0O00 * I1Ii111 - oO0o
  if 99 - 99: ooOoO0o / I1IiiI . Ii1I - Ii1I * I1IiiI
 def is_ddt ( self ) :
  return ( True if self . ddt_bit else False )
  if 24 - 24: I11i * OoO0O00 - oO0o / iIii1I11I1II1 - Oo0Ooo . OOooOOo
  if 2 - 2: ooOoO0o - O0 - I1ii11iIi11i / I11i * OoOoOO00
 def is_to_etr ( self ) :
  return ( True if self . to_etr else False )
  if 26 - 26: I1ii11iIi11i + I1Ii111 - oO0o + IiII % OOooOOo
  if 84 - 84: I11i % Ii1I % O0 * o0oOOo0O0Ooo
 def is_to_ms ( self ) :
  return ( True if self . to_ms else False )
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
  if 40 - 40: iII111i
  if 62 - 62: ooOoO0o / OOooOOo
 def print_map_register ( self ) :
  O0o0O0OoOo0 = lisp_hex_string ( self . xtr_id )
  if 92 - 92: I11i % I1Ii111
  iiIiiIi1 = ( "{} -> flags: {}{}{}{}{}{}{}{}{}, record-count: " +
 "{}, nonce: 0x{}, key/alg-id: {}/{}{}, auth-len: {}, xtr-id: " +
 "0x{}, site-id: {}" )
  if 18 - 18: ooOoO0o + I1Ii111 / OOooOOo / oO0o + iIii1I11I1II1 % IiII
  lprint ( iiIiiIi1 . format ( bold ( "Map-Register" , False ) , "P" if self . proxy_reply_requested else "p" ,
  # I11i . i11iIiiIii + o0oOOo0O0Ooo - I1Ii111 * i11iIiiIii - I1IiiI
 "S" if self . lisp_sec_present else "s" ,
 "I" if self . xtr_id_present else "i" ,
 "T" if self . use_ttl_for_timeout else "t" ,
 "R" if self . merge_register_requested else "r" ,
 "M" if self . mobile_node else "m" ,
 "N" if self . map_notify_requested else "n" ,
 "F" if self . map_register_refresh else "f" ,
 "E" if self . encrypt_bit else "e" ,
 self . record_count , lisp_hex_string ( self . nonce ) , self . key_id ,
 self . alg_id , " (sha1)" if ( self . key_id == LISP_SHA_1_96_ALG_ID ) else ( " (sha2)" if ( self . key_id == LISP_SHA_256_128_ALG_ID ) else "" ) , self . auth_len , O0o0O0OoOo0 , self . site_id ) )
  if 49 - 49: i1IIi % oO0o / OOooOOo . I1ii11iIi11i - I1Ii111
  if 12 - 12: i11iIiiIii + I11i - I1ii11iIi11i
  if 27 - 27: iII111i
  if 22 - 22: OoOoOO00 / I1IiiI
 def encode ( self ) :
  Iii11I1i = ( LISP_MAP_REGISTER << 28 ) | self . record_count
  if ( self . proxy_reply_requested ) : Iii11I1i |= 0x08000000
  if ( self . lisp_sec_present ) : Iii11I1i |= 0x04000000
  if ( self . xtr_id_present ) : Iii11I1i |= 0x02000000
  if ( self . map_register_refresh ) : Iii11I1i |= 0x1000
  if ( self . use_ttl_for_timeout ) : Iii11I1i |= 0x800
  if ( self . merge_register_requested ) : Iii11I1i |= 0x400
  if ( self . mobile_node ) : Iii11I1i |= 0x200
  if ( self . map_notify_requested ) : Iii11I1i |= 0x100
  if ( self . encryption_key_id != None ) :
   Iii11I1i |= 0x2000
   Iii11I1i |= self . encryption_key_id << 14
   if 33 - 33: I11i
   if 37 - 37: OoOoOO00 % o0oOOo0O0Ooo * OoO0O00 / i11iIiiIii * II111iiii * iII111i
   if 70 - 70: ooOoO0o . i11iIiiIii % OoOoOO00 + oO0o
   if 95 - 95: I1ii11iIi11i
   if 48 - 48: I11i
  if ( self . alg_id == LISP_NONE_ALG_ID ) :
   self . auth_len = 0
  else :
   if ( self . alg_id == LISP_SHA_1_96_ALG_ID ) :
    self . auth_len = LISP_SHA1_160_AUTH_DATA_LEN
    if 14 - 14: iIii1I11I1II1 / o0oOOo0O0Ooo * IiII
   if ( self . alg_id == LISP_SHA_256_128_ALG_ID ) :
    self . auth_len = LISP_SHA2_256_AUTH_DATA_LEN
    if 35 - 35: iIii1I11I1II1
    if 34 - 34: OoO0O00 % I1IiiI . o0oOOo0O0Ooo % OoO0O00 % OoO0O00
    if 30 - 30: I1IiiI + I1IiiI
  iIIi1 = struct . pack ( "I" , socket . htonl ( Iii11I1i ) )
  iIIi1 += struct . pack ( "QBBH" , self . nonce , self . key_id , self . alg_id ,
 socket . htons ( self . auth_len ) )
  if 75 - 75: I1IiiI - ooOoO0o - I1IiiI % oO0o % OoooooooOO
  iIIi1 = self . zero_auth ( iIIi1 )
  return ( iIIi1 )
  if 13 - 13: ooOoO0o * OoO0O00 % iIii1I11I1II1 / IiII * iII111i . Oo0Ooo
  if 23 - 23: ooOoO0o / IiII . iII111i * Ii1I
 def zero_auth ( self , packet ) :
  O00OO = struct . calcsize ( "I" ) + struct . calcsize ( "QHH" )
  oOiIiii1III = ""
  o00oOOO = 0
  if ( self . alg_id == LISP_NONE_ALG_ID ) : return ( packet )
  if ( self . alg_id == LISP_SHA_1_96_ALG_ID ) :
   oOiIiii1III = struct . pack ( "QQI" , 0 , 0 , 0 )
   o00oOOO = struct . calcsize ( "QQI" )
   if 95 - 95: i11iIiiIii . o0oOOo0O0Ooo + OoooooooOO % Oo0Ooo
  if ( self . alg_id == LISP_SHA_256_128_ALG_ID ) :
   oOiIiii1III = struct . pack ( "QQQQ" , 0 , 0 , 0 , 0 )
   o00oOOO = struct . calcsize ( "QQQQ" )
   if 21 - 21: iII111i - o0oOOo0O0Ooo / I11i % O0 / iIii1I11I1II1 / iII111i
  packet = packet [ 0 : O00OO ] + oOiIiii1III + packet [ O00OO + o00oOOO : : ]
  return ( packet )
  if 1 - 1: Oo0Ooo . i11iIiiIii
  if 9 - 9: OoooooooOO / I11i
 def encode_auth ( self , packet ) :
  O00OO = struct . calcsize ( "I" ) + struct . calcsize ( "QHH" )
  o00oOOO = self . auth_len
  oOiIiii1III = self . auth_data
  packet = packet [ 0 : O00OO ] + oOiIiii1III + packet [ O00OO + o00oOOO : : ]
  return ( packet )
  if 47 - 47: OoooooooOO
  if 48 - 48: OoOoOO00 . IiII % I1IiiI + I11i
 def decode ( self , packet ) :
  II11iII = packet
  I1I = "I"
  ii1I1iIi = struct . calcsize ( I1I )
  if ( len ( packet ) < ii1I1iIi ) : return ( [ None , None ] )
  if 78 - 78: IiII + I11i - o0oOOo0O0Ooo + OoO0O00 / iIii1I11I1II1
  Iii11I1i = struct . unpack ( I1I , packet [ : ii1I1iIi ] )
  Iii11I1i = socket . ntohl ( Iii11I1i [ 0 ] )
  packet = packet [ ii1I1iIi : : ]
  if 47 - 47: OOooOOo
  I1I = "QBBH"
  ii1I1iIi = struct . calcsize ( I1I )
  if ( len ( packet ) < ii1I1iIi ) : return ( [ None , None ] )
  if 20 - 20: I1Ii111 % ooOoO0o - I1Ii111 * OoooooooOO / I1ii11iIi11i
  self . nonce , self . key_id , self . alg_id , self . auth_len = struct . unpack ( I1I , packet [ : ii1I1iIi ] )
  if 57 - 57: IiII % I11i * OOooOOo % I1ii11iIi11i
  if 65 - 65: i1IIi - OoooooooOO
  self . auth_len = socket . ntohs ( self . auth_len )
  self . proxy_reply_requested = True if ( Iii11I1i & 0x08000000 ) else False
  if 66 - 66: I1ii11iIi11i / i1IIi * I1IiiI - OoOoOO00 + oO0o
  self . lisp_sec_present = True if ( Iii11I1i & 0x04000000 ) else False
  self . xtr_id_present = True if ( Iii11I1i & 0x02000000 ) else False
  self . use_ttl_for_timeout = True if ( Iii11I1i & 0x800 ) else False
  self . map_register_refresh = True if ( Iii11I1i & 0x1000 ) else False
  self . merge_register_requested = True if ( Iii11I1i & 0x400 ) else False
  self . mobile_node = True if ( Iii11I1i & 0x200 ) else False
  self . map_notify_requested = True if ( Iii11I1i & 0x100 ) else False
  self . record_count = Iii11I1i & 0xff
  if 74 - 74: iII111i / I1Ii111 / II111iiii - iII111i / oO0o % I11i
  if 19 - 19: IiII % OoooooooOO + OoooooooOO
  if 7 - 7: i1IIi
  if 91 - 91: OoOoOO00 - OoOoOO00 . IiII
  self . encrypt_bit = True if Iii11I1i & 0x2000 else False
  if ( self . encrypt_bit ) :
   self . encryption_key_id = ( Iii11I1i >> 14 ) & 0x7
   if 33 - 33: I1Ii111 - iIii1I11I1II1 / Ii1I % O0
   if 80 - 80: IiII % OoooooooOO - IiII
   if 27 - 27: I1Ii111 - o0oOOo0O0Ooo * I1ii11iIi11i - I1IiiI
   if 22 - 22: Oo0Ooo % OoooooooOO - Oo0Ooo - iII111i . Ii1I
   if 100 - 100: II111iiii / I1Ii111 / iII111i - I1ii11iIi11i * iIii1I11I1II1
  if ( self . xtr_id_present ) :
   if ( self . decode_xtr_id ( II11iII ) == False ) : return ( [ None , None ] )
   if 7 - 7: i1IIi . IiII % i11iIiiIii * I1ii11iIi11i . I11i % I1ii11iIi11i
   if 35 - 35: I1IiiI
  packet = packet [ ii1I1iIi : : ]
  if 48 - 48: OoooooooOO % OoooooooOO - OoO0O00 . OoOoOO00
  if 22 - 22: ooOoO0o . i11iIiiIii . OoooooooOO . i1IIi
  if 12 - 12: OoOoOO00 % OOooOOo + oO0o . O0 % iIii1I11I1II1
  if 41 - 41: OoooooooOO
  if ( self . auth_len != 0 ) :
   if ( len ( packet ) < self . auth_len ) : return ( [ None , None ] )
   if 13 - 13: I11i + I1Ii111 - I1Ii111 % oO0o / I11i
   if ( self . alg_id not in ( LISP_NONE_ALG_ID , LISP_SHA_1_96_ALG_ID ,
 LISP_SHA_256_128_ALG_ID ) ) :
    lprint ( "Invalid authentication alg-id: {}" . format ( self . alg_id ) )
    return ( [ None , None ] )
    if 4 - 4: I1IiiI + OOooOOo - IiII + iII111i
    if 78 - 78: Ii1I
   o00oOOO = self . auth_len
   if ( self . alg_id == LISP_SHA_1_96_ALG_ID ) :
    ii1I1iIi = struct . calcsize ( "QQI" )
    if ( o00oOOO < ii1I1iIi ) :
     lprint ( "Invalid sha1-96 authentication length" )
     return ( [ None , None ] )
     if 29 - 29: II111iiii
    OoOoO0ooo , OO000o0O0o , O0O = struct . unpack ( "QQI" , packet [ : o00oOOO ] )
    iiiIIiIi1ii11 = ""
   elif ( self . alg_id == LISP_SHA_256_128_ALG_ID ) :
    ii1I1iIi = struct . calcsize ( "QQQQ" )
    if ( o00oOOO < ii1I1iIi ) :
     lprint ( "Invalid sha2-256 authentication length" )
     return ( [ None , None ] )
     if 78 - 78: ooOoO0o
    OoOoO0ooo , OO000o0O0o , O0O , iiiIIiIi1ii11 = struct . unpack ( "QQQQ" ,
 packet [ : o00oOOO ] )
   else :
    lprint ( "Unsupported authentication alg-id value {}" . format ( self . alg_id ) )
    if 94 - 94: OoooooooOO + OoOoOO00 / O0
    return ( [ None , None ] )
    if 60 - 60: I11i
   self . auth_data = lisp_concat_auth_data ( self . alg_id , OoOoO0ooo , OO000o0O0o ,
 O0O , iiiIIiIi1ii11 )
   II11iII = self . zero_auth ( II11iII )
   packet = packet [ self . auth_len : : ]
   if 97 - 97: i11iIiiIii * iIii1I11I1II1 / II111iiii
  return ( [ II11iII , packet ] )
  if 66 - 66: II111iiii + iII111i * oO0o % I11i / i1IIi / iIii1I11I1II1
  if 62 - 62: OoOoOO00 + oO0o * IiII + O0 / OOooOOo + ooOoO0o
 def encode_xtr_id ( self , packet ) :
  iiIi = self . xtr_id >> 64
  ooO00Oo = self . xtr_id & 0xffffffffffffffff
  iiIi = byte_swap_64 ( iiIi )
  ooO00Oo = byte_swap_64 ( ooO00Oo )
  IIiI1iiIII1 = byte_swap_64 ( self . site_id )
  packet += struct . pack ( "QQQ" , iiIi , ooO00Oo , IIiI1iiIII1 )
  return ( packet )
  if 68 - 68: i11iIiiIii . ooOoO0o % I11i
  if 47 - 47: OoOoOO00 . i1IIi
 def decode_xtr_id ( self , packet ) :
  ii1I1iIi = struct . calcsize ( "QQQ" )
  if ( len ( packet ) < ii1I1iIi ) : return ( [ None , None ] )
  packet = packet [ len ( packet ) - ii1I1iIi : : ]
  iiIi , ooO00Oo , IIiI1iiIII1 = struct . unpack ( "QQQ" ,
 packet [ : ii1I1iIi ] )
  iiIi = byte_swap_64 ( iiIi )
  ooO00Oo = byte_swap_64 ( ooO00Oo )
  self . xtr_id = ( iiIi << 64 ) | ooO00Oo
  self . site_id = byte_swap_64 ( IIiI1iiIII1 )
  return ( True )
  if 47 - 47: i11iIiiIii . IiII
  if 37 - 37: I1IiiI / OoooooooOO % i11iIiiIii % I1ii11iIi11i
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
  if 76 - 76: Ii1I + iII111i - IiII * iIii1I11I1II1 % i1IIi
  if 72 - 72: ooOoO0o + II111iiii . O0 - iII111i / OoooooooOO . I1Ii111
 def print_notify ( self ) :
  oOiIiii1III = binascii . hexlify ( self . auth_data )
  if ( self . alg_id == LISP_SHA_1_96_ALG_ID and len ( oOiIiii1III ) != 40 ) :
   oOiIiii1III = self . auth_data
  elif ( self . alg_id == LISP_SHA_256_128_ALG_ID and len ( oOiIiii1III ) != 64 ) :
   oOiIiii1III = self . auth_data
   if 28 - 28: iIii1I11I1II1 . O0
  iiIiiIi1 = ( "{} -> record-count: {}, nonce: 0x{}, key/alg-id: " +
 "{}{}{}, auth-len: {}, auth-data: {}" )
  lprint ( iiIiiIi1 . format ( bold ( "Map-Notify-Ack" , False ) if self . map_notify_ack else bold ( "Map-Notify" , False ) ,
  # OoooooooOO . II111iiii
 self . record_count , lisp_hex_string ( self . nonce ) , self . key_id ,
 self . alg_id , " (sha1)" if ( self . key_id == LISP_SHA_1_96_ALG_ID ) else ( " (sha2)" if ( self . key_id == LISP_SHA_256_128_ALG_ID ) else "" ) , self . auth_len , oOiIiii1III ) )
  if 3 - 3: O0 + OoOoOO00 % I11i * Ii1I
  if 13 - 13: Ii1I - oO0o
  if 55 - 55: IiII % I1ii11iIi11i + O0 . o0oOOo0O0Ooo / Ii1I * iII111i
  if 63 - 63: I1Ii111 - oO0o - iII111i - ooOoO0o / oO0o + OoO0O00
 def zero_auth ( self , packet ) :
  if ( self . alg_id == LISP_NONE_ALG_ID ) : return ( packet )
  if ( self . alg_id == LISP_SHA_1_96_ALG_ID ) :
   oOiIiii1III = struct . pack ( "QQI" , 0 , 0 , 0 )
   if 94 - 94: IiII / I1IiiI . II111iiii
  if ( self . alg_id == LISP_SHA_256_128_ALG_ID ) :
   oOiIiii1III = struct . pack ( "QQQQ" , 0 , 0 , 0 , 0 )
   if 32 - 32: oO0o . OOooOOo % OOooOOo . OoOoOO00
  packet += oOiIiii1III
  return ( packet )
  if 37 - 37: OOooOOo + O0 + OOooOOo . iII111i . o0oOOo0O0Ooo
  if 78 - 78: I1IiiI / I11i + o0oOOo0O0Ooo . Oo0Ooo / O0
 def encode ( self , eid_records , password ) :
  if ( self . map_notify_ack ) :
   Iii11I1i = ( LISP_MAP_NOTIFY_ACK << 28 ) | self . record_count
  else :
   Iii11I1i = ( LISP_MAP_NOTIFY << 28 ) | self . record_count
   if 49 - 49: I1ii11iIi11i
  iIIi1 = struct . pack ( "I" , socket . htonl ( Iii11I1i ) )
  iIIi1 += struct . pack ( "QBBH" , self . nonce , self . key_id , self . alg_id ,
 socket . htons ( self . auth_len ) )
  if 66 - 66: o0oOOo0O0Ooo . I1ii11iIi11i
  if ( self . alg_id == LISP_NONE_ALG_ID ) :
   self . packet = iIIi1 + eid_records
   return ( self . packet )
   if 18 - 18: Oo0Ooo + IiII
   if 79 - 79: OoO0O00 - O0 + II111iiii % Ii1I . I1IiiI
   if 43 - 43: I1IiiI % I1ii11iIi11i * Ii1I
   if 31 - 31: Ii1I / iII111i
   if 3 - 3: IiII
  iIIi1 = self . zero_auth ( iIIi1 )
  iIIi1 += eid_records
  if 37 - 37: Ii1I * OoooooooOO * I11i + Oo0Ooo . I1IiiI
  I11111ii1i = lisp_hash_me ( iIIi1 , self . alg_id , password , False )
  if 61 - 61: OOooOOo . OOooOOo
  O00OO = struct . calcsize ( "I" ) + struct . calcsize ( "QHH" )
  o00oOOO = self . auth_len
  self . auth_data = I11111ii1i
  iIIi1 = iIIi1 [ 0 : O00OO ] + I11111ii1i + iIIi1 [ O00OO + o00oOOO : : ]
  self . packet = iIIi1
  return ( iIIi1 )
  if 17 - 17: II111iiii / ooOoO0o
  if 80 - 80: OOooOOo * OoO0O00 + Ii1I
 def decode ( self , packet ) :
  II11iII = packet
  I1I = "I"
  ii1I1iIi = struct . calcsize ( I1I )
  if ( len ( packet ) < ii1I1iIi ) : return ( None )
  if 62 - 62: OoooooooOO . O0 % Oo0Ooo
  Iii11I1i = struct . unpack ( I1I , packet [ : ii1I1iIi ] )
  Iii11I1i = socket . ntohl ( Iii11I1i [ 0 ] )
  self . map_notify_ack = ( ( Iii11I1i >> 28 ) == LISP_MAP_NOTIFY_ACK )
  self . record_count = Iii11I1i & 0xff
  packet = packet [ ii1I1iIi : : ]
  if 98 - 98: o0oOOo0O0Ooo * Oo0Ooo - Ii1I . ooOoO0o
  I1I = "QBBH"
  ii1I1iIi = struct . calcsize ( I1I )
  if ( len ( packet ) < ii1I1iIi ) : return ( None )
  if 2 - 2: Oo0Ooo - ooOoO0o % iIii1I11I1II1
  self . nonce , self . key_id , self . alg_id , self . auth_len = struct . unpack ( I1I , packet [ : ii1I1iIi ] )
  if 88 - 88: I1Ii111 - OoO0O00
  self . nonce_key = lisp_hex_string ( self . nonce )
  self . auth_len = socket . ntohs ( self . auth_len )
  packet = packet [ ii1I1iIi : : ]
  self . eid_records = packet [ self . auth_len : : ]
  if 79 - 79: iII111i
  if ( self . auth_len == 0 ) : return ( self . eid_records )
  if 45 - 45: II111iiii + iII111i . I11i . O0 * i1IIi - Ii1I
  if 48 - 48: I1ii11iIi11i + Oo0Ooo
  if 76 - 76: I1ii11iIi11i
  if 98 - 98: II111iiii + I1IiiI - I1ii11iIi11i . Ii1I
  if ( len ( packet ) < self . auth_len ) : return ( None )
  if 51 - 51: Ii1I + i11iIiiIii * OoO0O00 % Oo0Ooo / I1IiiI - iIii1I11I1II1
  o00oOOO = self . auth_len
  if ( self . alg_id == LISP_SHA_1_96_ALG_ID ) :
   OoOoO0ooo , OO000o0O0o , O0O = struct . unpack ( "QQI" , packet [ : o00oOOO ] )
   iiiIIiIi1ii11 = ""
   if 20 - 20: I1Ii111 . I11i . Ii1I + I11i - OOooOOo * oO0o
  if ( self . alg_id == LISP_SHA_256_128_ALG_ID ) :
   OoOoO0ooo , OO000o0O0o , O0O , iiiIIiIi1ii11 = struct . unpack ( "QQQQ" ,
 packet [ : o00oOOO ] )
   if 82 - 82: OoO0O00
  self . auth_data = lisp_concat_auth_data ( self . alg_id , OoOoO0ooo , OO000o0O0o ,
 O0O , iiiIIiIi1ii11 )
  if 78 - 78: II111iiii / I11i - i11iIiiIii + I1ii11iIi11i * Oo0Ooo
  ii1I1iIi = struct . calcsize ( "I" ) + struct . calcsize ( "QHH" )
  packet = self . zero_auth ( II11iII [ : ii1I1iIi ] )
  ii1I1iIi += o00oOOO
  packet += II11iII [ ii1I1iIi : : ]
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
  O0o0O0OoOo0 = ""
  if ( self . xtr_id != None and self . subscribe_bit ) :
   O0o0O0OoOo0 = "subscribe, xtr-id: 0x{}, " . format ( lisp_hex_string ( self . xtr_id ) )
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
 self . target_eid . afi , green ( self . print_prefix ( ) , False ) , O0o0O0OoOo0 ) )
  if 99 - 99: I1IiiI
  oOoOo0o00o = self . keys
  for Ii1ii1Ii11 in self . itr_rlocs :
   lprint ( "  itr-rloc: afi {} {}{}" . format ( Ii1ii1Ii11 . afi ,
 red ( Ii1ii1Ii11 . print_address_no_iid ( ) , False ) ,
 "" if ( oOoOo0o00o == None ) else ", " + oOoOo0o00o [ 1 ] . print_keys ( ) ) )
   oOoOo0o00o = None
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
   o0000oO = ecdsa . VerifyingKey . from_pem ( pubkey )
  except :
   lprint ( "Invalid public-key in mapping system for sig-eid {}" . format ( self . signature_eid . print_address_no_iid ( ) ) )
   if 19 - 19: o0oOOo0O0Ooo
   oOo0 = False
   if 19 - 19: OoooooooOO
   if 95 - 95: Ii1I . IiII / I11i . i11iIiiIii . IiII
  if ( oOo0 ) :
   try :
    oOo0 = o0000oO . verify ( self . map_request_signature , oOoO00OO00 )
   except :
    oOo0 = False
    if 43 - 43: i11iIiiIii + o0oOOo0O0Ooo % o0oOOo0O0Ooo * OoooooooOO / I1Ii111
    if 9 - 9: iIii1I11I1II1 / II111iiii * OOooOOo
    if 96 - 96: Ii1I + I1ii11iIi11i * OoOoOO00 * IiII * I1ii11iIi11i . I1ii11iIi11i
  i1I11iIIiIIiIi = bold ( "passed" if oOo0 else "failed" , False )
  lprint ( "Signature verification {} for EID {}" . format ( i1I11iIIiIIiIi , OOOO00oO ) )
  return ( oOo0 )
  if 45 - 45: I1IiiI
  if 17 - 17: OoooooooOO - ooOoO0o + Ii1I . OoooooooOO % Oo0Ooo
 def encode ( self , probe_dest , probe_port ) :
  Iii11I1i = ( LISP_MAP_REQUEST << 28 ) | self . record_count
  Iii11I1i = Iii11I1i | ( self . itr_rloc_count << 8 )
  if ( self . auth_bit ) : Iii11I1i |= 0x08000000
  if ( self . map_data_present ) : Iii11I1i |= 0x04000000
  if ( self . rloc_probe ) : Iii11I1i |= 0x02000000
  if ( self . smr_bit ) : Iii11I1i |= 0x01000000
  if ( self . pitr_bit ) : Iii11I1i |= 0x00800000
  if ( self . smr_invoked_bit ) : Iii11I1i |= 0x00400000
  if ( self . mobile_node ) : Iii11I1i |= 0x00200000
  if ( self . xtr_id_present ) : Iii11I1i |= 0x00100000
  if ( self . local_xtr ) : Iii11I1i |= 0x00004000
  if ( self . dont_reply_bit ) : Iii11I1i |= 0x00002000
  if 92 - 92: I1Ii111 - OOooOOo % OoO0O00 - o0oOOo0O0Ooo % i1IIi
  iIIi1 = struct . pack ( "I" , socket . htonl ( Iii11I1i ) )
  iIIi1 += struct . pack ( "Q" , self . nonce )
  if 38 - 38: I1ii11iIi11i . I11i / OoOoOO00 % I11i
  if 10 - 10: O0 . I1IiiI * o0oOOo0O0Ooo / iII111i
  if 61 - 61: Oo0Ooo - I1Ii111
  if 51 - 51: iII111i * ooOoO0o / O0 / O0
  if 52 - 52: OoooooooOO % O0
  if 56 - 56: oO0o - i1IIi * OoooooooOO - II111iiii
  iii1I = False
  iIIiiiIiiii11 = self . privkey_filename
  if ( iIIiiiIiiii11 != None and os . path . exists ( iIIiiiIiiii11 ) ) :
   iI1i1i1i1i = open ( iIIiiiIiiii11 , "r" ) ; o0000oO = iI1i1i1i1i . read ( ) ; iI1i1i1i1i . close ( )
   try :
    o0000oO = ecdsa . SigningKey . from_pem ( o0000oO )
   except :
    return ( None )
    if 10 - 10: II111iiii . OOooOOo / iII111i
   I1II = self . sign_map_request ( o0000oO )
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
   ii111I1IiiI1i = LISP_LCAF_JSON_TYPE
   iio00OOO0o0Oo0 = socket . htons ( LISP_AFI_LCAF )
   I1iIiI1iiI = socket . htons ( len ( I1II ) + 2 )
   oO000O00 = socket . htons ( len ( I1II ) )
   iIIi1 += struct . pack ( "HBBBBHH" , iio00OOO0o0Oo0 , 0 , 0 , ii111I1IiiI1i , 0 ,
 I1iIiI1iiI , oO000O00 )
   iIIi1 += I1II
   iIIi1 += struct . pack ( "H" , 0 )
  else :
   if ( self . source_eid . instance_id != 0 ) :
    iIIi1 += struct . pack ( "H" , socket . htons ( LISP_AFI_LCAF ) )
    iIIi1 += self . source_eid . lcaf_encode_iid ( )
   else :
    iIIi1 += struct . pack ( "H" , socket . htons ( self . source_eid . afi ) )
    iIIi1 += self . source_eid . pack_address ( )
    if 39 - 39: O0 * Oo0Ooo - I1IiiI + Ii1I / II111iiii
    if 66 - 66: ooOoO0o + oO0o % OoooooooOO
    if 23 - 23: oO0o . OoOoOO00 + iIii1I11I1II1
    if 17 - 17: IiII
    if 12 - 12: i1IIi . OoO0O00
    if 14 - 14: OOooOOo + II111iiii % OOooOOo . oO0o * ooOoO0o
    if 54 - 54: ooOoO0o * I11i - I1Ii111
  if ( probe_dest ) :
   if ( probe_port == 0 ) : probe_port = LISP_DATA_PORT
   oooOO0oOooO00 = probe_dest . print_address_no_iid ( ) + ":" + str ( probe_port )
   if 15 - 15: iII111i / O0
   if ( lisp_crypto_keys_by_rloc_encap . has_key ( oooOO0oOooO00 ) ) :
    self . keys = lisp_crypto_keys_by_rloc_encap [ oooOO0oOooO00 ]
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
     oOoOo0o00o = lisp_keys ( 1 )
     self . keys = [ None , oOoOo0o00o , None , None ]
     if 37 - 37: I1ii11iIi11i * I1Ii111 * I1IiiI * O0
    oOoOo0o00o = self . keys [ 1 ]
    oOoOo0o00o . add_key_by_nonce ( self . nonce )
    iIIi1 += oOoOo0o00o . encode_lcaf ( Ii1ii1Ii11 )
   else :
    iIIi1 += struct . pack ( "H" , socket . htons ( Ii1ii1Ii11 . afi ) )
    iIIi1 += Ii1ii1Ii11 . pack_address ( )
    if 35 - 35: I1IiiI - I1ii11iIi11i * iII111i + IiII / i1IIi
    if 46 - 46: Oo0Ooo . ooOoO0o % Oo0Ooo / II111iiii * ooOoO0o * OOooOOo
    if 59 - 59: I1Ii111 * iII111i
  i1iIi = 0 if self . target_eid . is_binary ( ) == False else self . target_eid . mask_len
  if 78 - 78: OOooOOo * i11iIiiIii
  if 54 - 54: I1Ii111 . I1Ii111 % iIii1I11I1II1 . o0oOOo0O0Ooo + O0
  oO0I11i1I1 = 0
  if ( self . subscribe_bit ) :
   oO0I11i1I1 = 0x80
   self . xtr_id_present = True
   if ( self . xtr_id == None ) :
    self . xtr_id = random . randint ( 0 , ( 2 ** 128 ) - 1 )
    if 5 - 5: OoooooooOO - iII111i - i11iIiiIii
    if 53 - 53: iII111i * OoO0O00 / I1ii11iIi11i + I1IiiI + OoooooooOO
    if 47 - 47: I1Ii111
  I1I = "BB"
  iIIi1 += struct . pack ( I1I , oO0I11i1I1 , i1iIi )
  if 65 - 65: Ii1I
  if ( self . target_group . is_null ( ) == False ) :
   iIIi1 += struct . pack ( "H" , socket . htons ( LISP_AFI_LCAF ) )
   iIIi1 += self . target_eid . lcaf_encode_sg ( self . target_group )
  elif ( self . target_eid . instance_id != 0 or
 self . target_eid . is_geo_prefix ( ) ) :
   iIIi1 += struct . pack ( "H" , socket . htons ( LISP_AFI_LCAF ) )
   iIIi1 += self . target_eid . lcaf_encode_iid ( )
  else :
   iIIi1 += struct . pack ( "H" , socket . htons ( self . target_eid . afi ) )
   iIIi1 += self . target_eid . pack_address ( )
   if 71 - 71: I1Ii111 % I1Ii111 . oO0o + i11iIiiIii - i11iIiiIii
   if 16 - 16: iIii1I11I1II1 / I1IiiI / I1Ii111 - i11iIiiIii . ooOoO0o / OOooOOo
   if 13 - 13: o0oOOo0O0Ooo % O0 - I1Ii111 * OoooooooOO / Oo0Ooo - OoooooooOO
   if 78 - 78: oO0o % OoooooooOO
   if 73 - 73: I1IiiI % ooOoO0o % IiII + i1IIi - OoooooooOO / oO0o
  if ( self . subscribe_bit ) : iIIi1 = self . encode_xtr_id ( iIIi1 )
  return ( iIIi1 )
  if 78 - 78: OoooooooOO % oO0o - i11iIiiIii
  if 37 - 37: IiII % Ii1I % i1IIi
 def lcaf_decode_json ( self , packet ) :
  I1I = "BBBBHH"
  ii1I1iIi = struct . calcsize ( I1I )
  if ( len ( packet ) < ii1I1iIi ) : return ( None )
  if 23 - 23: ooOoO0o - O0 + i11iIiiIii
  oO0ooOoOooO00o00 , o0Ooo00Oo0oo0 , ii111I1IiiI1i , I11 , I1iIiI1iiI , oO000O00 = struct . unpack ( I1I , packet [ : ii1I1iIi ] )
  if 51 - 51: II111iiii % I1IiiI * IiII * I1ii11iIi11i
  if 72 - 72: IiII % ooOoO0o / Oo0Ooo + iII111i
  if ( ii111I1IiiI1i != LISP_LCAF_JSON_TYPE ) : return ( packet )
  if 62 - 62: OOooOOo / i1IIi * Ii1I * Ii1I + oO0o . o0oOOo0O0Ooo
  if 28 - 28: iIii1I11I1II1 + OoOoOO00 / IiII / Ii1I * OOooOOo
  if 33 - 33: OOooOOo
  if 22 - 22: O0 + OOooOOo % i1IIi
  I1iIiI1iiI = socket . ntohs ( I1iIiI1iiI )
  oO000O00 = socket . ntohs ( oO000O00 )
  packet = packet [ ii1I1iIi : : ]
  if ( len ( packet ) < I1iIiI1iiI ) : return ( None )
  if ( I1iIiI1iiI != oO000O00 + 2 ) : return ( None )
  if 83 - 83: O0 + Ii1I % i11iIiiIii
  if 32 - 32: I1Ii111 % Oo0Ooo - I11i + O0
  if 57 - 57: OoO0O00 + I1Ii111 . I11i . i1IIi - o0oOOo0O0Ooo / Oo0Ooo
  if 19 - 19: iIii1I11I1II1 . OoO0O00 / OoooooooOO
  try :
   I1II = json . loads ( packet [ 0 : oO000O00 ] )
  except :
   return ( None )
   if 2 - 2: O0 - O0 % I1Ii111 / I1ii11iIi11i
  packet = packet [ oO000O00 : : ]
  if 76 - 76: OoO0O00 * oO0o - OoO0O00
  if 57 - 57: OoooooooOO / OoOoOO00 + oO0o . Ii1I
  if 14 - 14: i11iIiiIii % OOooOOo * o0oOOo0O0Ooo * OoOoOO00
  if 55 - 55: I1Ii111 * OOooOOo * I1Ii111
  I1I = "H"
  ii1I1iIi = struct . calcsize ( I1I )
  ooo0O0O0oo0 = struct . unpack ( I1I , packet [ : ii1I1iIi ] ) [ 0 ]
  packet = packet [ ii1I1iIi : : ]
  if ( ooo0O0O0oo0 != 0 ) : return ( packet )
  if 70 - 70: O0 . Ii1I
  if 33 - 33: OOooOOo * Ii1I
  if 64 - 64: i11iIiiIii . iIii1I11I1II1
  if 7 - 7: OoOoOO00 % ooOoO0o + OoOoOO00 - OoOoOO00 * i11iIiiIii % OoO0O00
  if ( I1II . has_key ( "source-eid" ) == False ) : return ( packet )
  oOOOO = I1II [ "source-eid" ]
  ooo0O0O0oo0 = LISP_AFI_IPV4 if oOOOO . count ( "." ) == 3 else LISP_AFI_IPV6 if oOOOO . count ( ":" ) == 7 else None
  if 60 - 60: O0 * Oo0Ooo % OOooOOo + IiII . OoO0O00 . Oo0Ooo
  if ( ooo0O0O0oo0 == None ) :
   lprint ( "Bad JSON 'source-eid' value: {}" . format ( oOOOO ) )
   return ( None )
   if 70 - 70: I11i . I1ii11iIi11i * oO0o
   if 97 - 97: oO0o . iIii1I11I1II1 - OOooOOo
  self . source_eid . afi = ooo0O0O0oo0
  self . source_eid . store_address ( oOOOO )
  if 23 - 23: I1ii11iIi11i % I11i
  if ( I1II . has_key ( "signature-eid" ) == False ) : return ( packet )
  oOOOO = I1II [ "signature-eid" ]
  if ( oOOOO . count ( ":" ) != 7 ) :
   lprint ( "Bad JSON 'signature-eid' value: {}" . format ( oOOOO ) )
   return ( None )
   if 18 - 18: OoooooooOO . i1IIi + II111iiii
   if 99 - 99: I1Ii111 - I1ii11iIi11i - I1IiiI - I1Ii111 + OoO0O00 + II111iiii
  self . signature_eid . afi = LISP_AFI_IPV6
  self . signature_eid . store_address ( oOOOO )
  if 34 - 34: I1Ii111 * I11i
  if ( I1II . has_key ( "signature" ) == False ) : return ( packet )
  I111II11I = binascii . a2b_base64 ( I1II [ "signature" ] )
  self . map_request_signature = I111II11I
  return ( packet )
  if 31 - 31: IiII . oO0o
  if 40 - 40: Ii1I - I11i / II111iiii * i1IIi + IiII * II111iiii
 def decode ( self , packet , source , port ) :
  I1I = "I"
  ii1I1iIi = struct . calcsize ( I1I )
  if ( len ( packet ) < ii1I1iIi ) : return ( None )
  if 53 - 53: I1ii11iIi11i - i11iIiiIii . OoO0O00 / OoOoOO00 - I1Ii111
  Iii11I1i = struct . unpack ( I1I , packet [ : ii1I1iIi ] )
  Iii11I1i = Iii11I1i [ 0 ]
  packet = packet [ ii1I1iIi : : ]
  if 99 - 99: Ii1I - IiII - i1IIi / i11iIiiIii . IiII
  I1I = "Q"
  ii1I1iIi = struct . calcsize ( I1I )
  if ( len ( packet ) < ii1I1iIi ) : return ( None )
  if 58 - 58: OOooOOo
  I11iIi1i1I1i1 = struct . unpack ( I1I , packet [ : ii1I1iIi ] )
  packet = packet [ ii1I1iIi : : ]
  if 12 - 12: I1IiiI . o0oOOo0O0Ooo * OoooooooOO
  Iii11I1i = socket . ntohl ( Iii11I1i )
  self . auth_bit = True if ( Iii11I1i & 0x08000000 ) else False
  self . map_data_present = True if ( Iii11I1i & 0x04000000 ) else False
  self . rloc_probe = True if ( Iii11I1i & 0x02000000 ) else False
  self . smr_bit = True if ( Iii11I1i & 0x01000000 ) else False
  self . pitr_bit = True if ( Iii11I1i & 0x00800000 ) else False
  self . smr_invoked_bit = True if ( Iii11I1i & 0x00400000 ) else False
  self . mobile_node = True if ( Iii11I1i & 0x00200000 ) else False
  self . xtr_id_present = True if ( Iii11I1i & 0x00100000 ) else False
  self . local_xtr = True if ( Iii11I1i & 0x00004000 ) else False
  self . dont_reply_bit = True if ( Iii11I1i & 0x00002000 ) else False
  self . itr_rloc_count = ( ( Iii11I1i >> 8 ) & 0x1f ) + 1
  self . record_count = Iii11I1i & 0xff
  self . nonce = I11iIi1i1I1i1 [ 0 ]
  if 64 - 64: OoOoOO00 + IiII - i1IIi . II111iiii . OoO0O00
  if 31 - 31: oO0o . iII111i - I11i . iIii1I11I1II1 + I11i . OoOoOO00
  if 86 - 86: I1ii11iIi11i - I1ii11iIi11i / iII111i - I1ii11iIi11i * iII111i + I1Ii111
  if 61 - 61: Oo0Ooo / II111iiii / Oo0Ooo / i1IIi . Oo0Ooo - IiII
  if ( self . xtr_id_present ) :
   if ( self . decode_xtr_id ( packet ) == False ) : return ( None )
   if 30 - 30: OoooooooOO % OOooOOo
   if 14 - 14: OoOoOO00 / OoO0O00 / i11iIiiIii - OoOoOO00 / o0oOOo0O0Ooo - OOooOOo
  ii1I1iIi = struct . calcsize ( "H" )
  if ( len ( packet ) < ii1I1iIi ) : return ( None )
  if 81 - 81: iII111i % Ii1I . ooOoO0o
  ooo0O0O0oo0 = struct . unpack ( "H" , packet [ : ii1I1iIi ] )
  self . source_eid . afi = socket . ntohs ( ooo0O0O0oo0 [ 0 ] )
  packet = packet [ ii1I1iIi : : ]
  if 66 - 66: I1ii11iIi11i * Ii1I / OoooooooOO * O0 % OOooOOo
  if ( self . source_eid . afi == LISP_AFI_LCAF ) :
   Ii = packet
   packet = self . source_eid . lcaf_decode_iid ( packet )
   if ( packet == None ) :
    packet = self . lcaf_decode_json ( Ii )
    if ( packet == None ) : return ( None )
    if 100 - 100: O0 * i1IIi
  elif ( self . source_eid . afi != LISP_AFI_NONE ) :
   packet = self . source_eid . unpack_address ( packet )
   if ( packet == None ) : return ( None )
   if 80 - 80: OoooooooOO * oO0o % Oo0Ooo / Ii1I / Ii1I % Ii1I
  self . source_eid . mask_len = self . source_eid . host_mask_len ( )
  if 20 - 20: ooOoO0o
  ooOooooOo00OO0o = ( os . getenv ( "LISP_NO_CRYPTO" ) != None )
  self . itr_rlocs = [ ]
  while ( self . itr_rloc_count != 0 ) :
   ii1I1iIi = struct . calcsize ( "H" )
   if ( len ( packet ) < ii1I1iIi ) : return ( None )
   if 86 - 86: OoOoOO00
   ooo0O0O0oo0 = struct . unpack ( "H" , packet [ : ii1I1iIi ] ) [ 0 ]
   if 61 - 61: IiII / II111iiii . O0 + OoooooooOO * i1IIi
   Ii1ii1Ii11 = lisp_address ( LISP_AFI_NONE , "" , 32 , 0 )
   Ii1ii1Ii11 . afi = socket . ntohs ( ooo0O0O0oo0 )
   if 59 - 59: OoooooooOO % II111iiii . Ii1I * o0oOOo0O0Ooo . OoOoOO00
   if 95 - 95: Ii1I % i11iIiiIii * OoooooooOO + Ii1I . II111iiii
   if 89 - 89: iII111i
   if 73 - 73: IiII / Ii1I + I1Ii111 . OOooOOo - II111iiii / iIii1I11I1II1
   if 79 - 79: I1Ii111 * Oo0Ooo . o0oOOo0O0Ooo - I1Ii111
   if ( Ii1ii1Ii11 . afi != LISP_AFI_LCAF ) :
    if ( len ( packet ) < Ii1ii1Ii11 . addr_length ( ) ) : return ( None )
    packet = Ii1ii1Ii11 . unpack_address ( packet [ ii1I1iIi : : ] )
    if ( packet == None ) : return ( None )
    if 16 - 16: I1IiiI - O0 * I1ii11iIi11i . I1ii11iIi11i % OOooOOo
    if ( ooOooooOo00OO0o ) :
     self . itr_rlocs . append ( Ii1ii1Ii11 )
     self . itr_rloc_count -= 1
     continue
     if 39 - 39: II111iiii / I11i - OoOoOO00 * OoOoOO00 - Ii1I
     if 8 - 8: O0 . i11iIiiIii
    oooOO0oOooO00 = lisp_build_crypto_decap_lookup_key ( Ii1ii1Ii11 , port )
    if 54 - 54: OOooOOo . I1ii11iIi11i * I11i % I1Ii111 . O0 * IiII
    if 87 - 87: Ii1I % I1ii11iIi11i * Oo0Ooo
    if 59 - 59: Oo0Ooo / I11i - iIii1I11I1II1 * iIii1I11I1II1
    if 18 - 18: I11i * I1ii11iIi11i / i11iIiiIii / iIii1I11I1II1 * OoooooooOO . OOooOOo
    if 69 - 69: Oo0Ooo * ooOoO0o
    if ( lisp_nat_traversal and Ii1ii1Ii11 . is_private_address ( ) and source ) : Ii1ii1Ii11 = source
    if 91 - 91: o0oOOo0O0Ooo . ooOoO0o / OoO0O00 / i11iIiiIii * o0oOOo0O0Ooo
    Ooooo0OO = lisp_crypto_keys_by_rloc_decap
    if ( Ooooo0OO . has_key ( oooOO0oOooO00 ) ) : Ooooo0OO . pop ( oooOO0oOooO00 )
    if 51 - 51: IiII - OOooOOo / OoOoOO00
    if 63 - 63: oO0o + I1Ii111 / I1IiiI - OoooooooOO / OoOoOO00 * Ii1I
    if 17 - 17: OoO0O00 . I1IiiI * O0
    if 81 - 81: OOooOOo
    if 58 - 58: II111iiii . I1Ii111 . Ii1I * OoooooooOO / Ii1I / I11i
    if 41 - 41: I11i + OoO0O00 . iII111i
    lisp_write_ipc_decap_key ( oooOO0oOooO00 , None )
   else :
    II11iII = packet
    OoOOoOOOoooO0 = lisp_keys ( 1 )
    packet = OoOOoOOOoooO0 . decode_lcaf ( II11iII , 0 )
    if ( packet == None ) : return ( None )
    if 5 - 5: IiII - I11i
    if 16 - 16: IiII . iII111i . Oo0Ooo % OOooOOo / IiII
    if 72 - 72: o0oOOo0O0Ooo * ooOoO0o - i11iIiiIii / Ii1I
    if 11 - 11: O0 - I1IiiI
    oOo0OO0 = [ LISP_CS_25519_CBC , LISP_CS_25519_GCM ,
 LISP_CS_25519_CHACHA ]
    if ( OoOOoOOOoooO0 . cipher_suite in oOo0OO0 ) :
     if ( OoOOoOOOoooO0 . cipher_suite == LISP_CS_25519_CBC or
 OoOOoOOOoooO0 . cipher_suite == LISP_CS_25519_GCM ) :
      o0000oO = lisp_keys ( 1 , do_poly = False , do_chacha = False )
      if 31 - 31: iII111i
     if ( OoOOoOOOoooO0 . cipher_suite == LISP_CS_25519_CHACHA ) :
      o0000oO = lisp_keys ( 1 , do_poly = True , do_chacha = True )
      if 1 - 1: I1Ii111 / OoOoOO00 * OoOoOO00 - o0oOOo0O0Ooo % Ii1I
    else :
     o0000oO = lisp_keys ( 1 , do_poly = False , do_curve = False ,
 do_chacha = False )
     if 96 - 96: IiII / Ii1I % OoO0O00 . iIii1I11I1II1
    packet = o0000oO . decode_lcaf ( II11iII , 0 )
    if ( packet == None ) : return ( None )
    if 30 - 30: I11i - OoO0O00
    if ( len ( packet ) < ii1I1iIi ) : return ( None )
    ooo0O0O0oo0 = struct . unpack ( "H" , packet [ : ii1I1iIi ] ) [ 0 ]
    Ii1ii1Ii11 . afi = socket . ntohs ( ooo0O0O0oo0 )
    if ( len ( packet ) < Ii1ii1Ii11 . addr_length ( ) ) : return ( None )
    if 15 - 15: OoooooooOO
    packet = Ii1ii1Ii11 . unpack_address ( packet [ ii1I1iIi : : ] )
    if ( packet == None ) : return ( None )
    if 31 - 31: II111iiii
    if ( ooOooooOo00OO0o ) :
     self . itr_rlocs . append ( Ii1ii1Ii11 )
     self . itr_rloc_count -= 1
     continue
     if 62 - 62: iIii1I11I1II1 % I1Ii111 % I1ii11iIi11i * IiII
     if 87 - 87: IiII
    oooOO0oOooO00 = lisp_build_crypto_decap_lookup_key ( Ii1ii1Ii11 , port )
    if 45 - 45: oO0o + II111iiii * O0 % OOooOOo . iIii1I11I1II1
    oOo0ooo00OoO = None
    if ( lisp_nat_traversal and Ii1ii1Ii11 . is_private_address ( ) and source ) : Ii1ii1Ii11 = source
    if 88 - 88: oO0o
    if 33 - 33: o0oOOo0O0Ooo / i1IIi
    if ( lisp_crypto_keys_by_rloc_decap . has_key ( oooOO0oOooO00 ) ) :
     oOoOo0o00o = lisp_crypto_keys_by_rloc_decap [ oooOO0oOooO00 ]
     oOo0ooo00OoO = oOoOo0o00o [ 1 ] if oOoOo0o00o and oOoOo0o00o [ 1 ] else None
     if 71 - 71: OoooooooOO - iII111i + Ii1I / O0 % o0oOOo0O0Ooo + OoO0O00
     if 83 - 83: IiII * I1ii11iIi11i / IiII * IiII - OOooOOo
    oO0OO00000o = True
    if ( oOo0ooo00OoO ) :
     if ( oOo0ooo00OoO . compare_keys ( o0000oO ) ) :
      self . keys = [ None , oOo0ooo00OoO , None , None ]
      lprint ( "Maintain stored decap-keys for RLOC {}" . format ( red ( oooOO0oOooO00 , False ) ) )
      if 46 - 46: ooOoO0o - iIii1I11I1II1
     else :
      oO0OO00000o = False
      o0ooOoOO0 = bold ( "Remote decap-rekeying" , False )
      lprint ( "{} for RLOC {}" . format ( o0ooOoOO0 , red ( oooOO0oOooO00 ,
 False ) ) )
      o0000oO . copy_keypair ( oOo0ooo00OoO )
      o0000oO . uptime = oOo0ooo00OoO . uptime
      oOo0ooo00OoO = None
      if 35 - 35: I11i % O0
      if 48 - 48: I1Ii111 % ooOoO0o . Oo0Ooo + OoO0O00 - oO0o
      if 38 - 38: IiII . iIii1I11I1II1 - II111iiii - Ii1I
    if ( oOo0ooo00OoO == None ) :
     self . keys = [ None , o0000oO , None , None ]
     if ( lisp_i_am_etr == False and lisp_i_am_rtr == False ) :
      o0000oO . local_public_key = None
      lprint ( "{} for {}" . format ( bold ( "Ignoring decap-keys" ,
 False ) , red ( oooOO0oOooO00 , False ) ) )
     elif ( o0000oO . remote_public_key != None ) :
      if ( oO0OO00000o ) :
       lprint ( "{} for RLOC {}" . format ( bold ( "New decap-keying" , False ) ,
       # OoO0O00 + OoOoOO00 + iIii1I11I1II1 - ooOoO0o
 red ( oooOO0oOooO00 , False ) ) )
       if 42 - 42: o0oOOo0O0Ooo - OOooOOo / OOooOOo / iII111i * Oo0Ooo . Oo0Ooo
      o0000oO . compute_shared_key ( "decap" )
      o0000oO . add_key_by_rloc ( oooOO0oOooO00 , False )
      if 96 - 96: OoooooooOO + I1ii11iIi11i * O0
      if 33 - 33: I1ii11iIi11i - IiII
      if 17 - 17: OOooOOo - oO0o
      if 1 - 1: iIii1I11I1II1 / i11iIiiIii * II111iiii
   self . itr_rlocs . append ( Ii1ii1Ii11 )
   self . itr_rloc_count -= 1
   if 48 - 48: I1ii11iIi11i + O0 * oO0o + I1ii11iIi11i + I1ii11iIi11i
   if 60 - 60: II111iiii % Oo0Ooo
  ii1I1iIi = struct . calcsize ( "BBH" )
  if ( len ( packet ) < ii1I1iIi ) : return ( None )
  if 62 - 62: O0 + iII111i - iII111i % iIii1I11I1II1
  oO0I11i1I1 , i1iIi , ooo0O0O0oo0 = struct . unpack ( "BBH" , packet [ : ii1I1iIi ] )
  self . subscribe_bit = ( oO0I11i1I1 & 0x80 )
  self . target_eid . afi = socket . ntohs ( ooo0O0O0oo0 )
  packet = packet [ ii1I1iIi : : ]
  if 47 - 47: I1Ii111 + I1IiiI
  self . target_eid . mask_len = i1iIi
  if ( self . target_eid . afi == LISP_AFI_LCAF ) :
   packet , IiI1Iii1iI1 = self . target_eid . lcaf_decode_eid ( packet )
   if ( packet == None ) : return ( None )
   if ( IiI1Iii1iI1 ) : self . target_group = IiI1Iii1iI1
  else :
   packet = self . target_eid . unpack_address ( packet )
   if ( packet == None ) : return ( None )
   packet = packet [ ii1I1iIi : : ]
   if 88 - 88: iII111i / ooOoO0o
  return ( packet )
  if 17 - 17: OoOoOO00
  if 40 - 40: O0 - iII111i
 def print_eid_tuple ( self ) :
  return ( lisp_print_eid_tuple ( self . target_eid , self . target_group ) )
  if 18 - 18: o0oOOo0O0Ooo / i11iIiiIii % I1ii11iIi11i * OoooooooOO
  if 67 - 67: OoOoOO00
 def encode_xtr_id ( self , packet ) :
  iiIi = self . xtr_id >> 64
  ooO00Oo = self . xtr_id & 0xffffffffffffffff
  iiIi = byte_swap_64 ( iiIi )
  ooO00Oo = byte_swap_64 ( ooO00Oo )
  packet += struct . pack ( "QQ" , iiIi , ooO00Oo )
  return ( packet )
  if 67 - 67: I1ii11iIi11i / iII111i + iIii1I11I1II1 % I1IiiI
  if 99 - 99: ooOoO0o . Ii1I
 def decode_xtr_id ( self , packet ) :
  ii1I1iIi = struct . calcsize ( "QQ" )
  if ( len ( packet ) < ii1I1iIi ) : return ( None )
  packet = packet [ len ( packet ) - ii1I1iIi : : ]
  iiIi , ooO00Oo = struct . unpack ( "QQ" , packet [ : ii1I1iIi ] )
  iiIi = byte_swap_64 ( iiIi )
  ooO00Oo = byte_swap_64 ( ooO00Oo )
  self . xtr_id = ( iiIi << 64 ) | ooO00Oo
  return ( True )
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
  if 30 - 30: OOooOOo * I1ii11iIi11i % I1ii11iIi11i + iII111i * IiII
class lisp_map_reply ( ) :
 def __init__ ( self ) :
  self . rloc_probe = False
  self . echo_nonce_capable = False
  self . security = False
  self . record_count = 0
  self . hop_count = 0
  self . nonce = 0
  self . keys = None
  if 33 - 33: o0oOOo0O0Ooo + I11i * O0 * OoO0O00 . I1ii11iIi11i
  if 74 - 74: iII111i * iII111i * o0oOOo0O0Ooo / oO0o
 def print_map_reply ( self ) :
  iiIiiIi1 = "{} -> flags: {}{}{}, hop-count: {}, record-count: {}, " + "nonce: 0x{}"
  if 91 - 91: i11iIiiIii . I1ii11iIi11i / II111iiii
  lprint ( iiIiiIi1 . format ( bold ( "Map-Reply" , False ) , "R" if self . rloc_probe else "r" ,
  # iII111i * Ii1I % OoOoOO00 / o0oOOo0O0Ooo * o0oOOo0O0Ooo + O0
 "E" if self . echo_nonce_capable else "e" ,
 "S" if self . security else "s" , self . hop_count , self . record_count ,
 lisp_hex_string ( self . nonce ) ) )
  if 73 - 73: o0oOOo0O0Ooo / iII111i % O0 . i1IIi
  if 99 - 99: II111iiii - I1ii11iIi11i * IiII
 def encode ( self ) :
  Iii11I1i = ( LISP_MAP_REPLY << 28 ) | self . record_count
  Iii11I1i |= self . hop_count << 8
  if ( self . rloc_probe ) : Iii11I1i |= 0x08000000
  if ( self . echo_nonce_capable ) : Iii11I1i |= 0x04000000
  if ( self . security ) : Iii11I1i |= 0x02000000
  if 3 - 3: IiII - I1ii11iIi11i * iII111i * I1ii11iIi11i + Oo0Ooo
  iIIi1 = struct . pack ( "I" , socket . htonl ( Iii11I1i ) )
  iIIi1 += struct . pack ( "Q" , self . nonce )
  return ( iIIi1 )
  if 15 - 15: I1ii11iIi11i * Ii1I / iII111i . o0oOOo0O0Ooo / Ii1I % OoOoOO00
  if 75 - 75: OoooooooOO % i11iIiiIii % iIii1I11I1II1 % I1ii11iIi11i / i11iIiiIii
 def decode ( self , packet ) :
  I1I = "I"
  ii1I1iIi = struct . calcsize ( I1I )
  if ( len ( packet ) < ii1I1iIi ) : return ( None )
  if 96 - 96: ooOoO0o * oO0o / iIii1I11I1II1 / I11i
  Iii11I1i = struct . unpack ( I1I , packet [ : ii1I1iIi ] )
  Iii11I1i = Iii11I1i [ 0 ]
  packet = packet [ ii1I1iIi : : ]
  if 5 - 5: o0oOOo0O0Ooo
  I1I = "Q"
  ii1I1iIi = struct . calcsize ( I1I )
  if ( len ( packet ) < ii1I1iIi ) : return ( None )
  if 83 - 83: I11i * I1IiiI . II111iiii * i1IIi % O0
  I11iIi1i1I1i1 = struct . unpack ( I1I , packet [ : ii1I1iIi ] )
  packet = packet [ ii1I1iIi : : ]
  if 35 - 35: OoOoOO00 % OoO0O00 + O0 * o0oOOo0O0Ooo % I1ii11iIi11i
  Iii11I1i = socket . ntohl ( Iii11I1i )
  self . rloc_probe = True if ( Iii11I1i & 0x08000000 ) else False
  self . echo_nonce_capable = True if ( Iii11I1i & 0x04000000 ) else False
  self . security = True if ( Iii11I1i & 0x02000000 ) else False
  self . hop_count = ( Iii11I1i >> 8 ) & 0xff
  self . record_count = Iii11I1i & 0xff
  self . nonce = I11iIi1i1I1i1 [ 0 ]
  if 57 - 57: oO0o / I11i
  if ( lisp_crypto_keys_by_nonce . has_key ( self . nonce ) ) :
   self . keys = lisp_crypto_keys_by_nonce [ self . nonce ]
   self . keys [ 1 ] . delete_key_by_nonce ( self . nonce )
   if 63 - 63: ooOoO0o * OoO0O00 * ooOoO0o + OoOoOO00
  return ( packet )
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
  if 47 - 47: O0 . I1IiiI / ooOoO0o % i11iIiiIii
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
  if 47 - 47: Ii1I . OoOoOO00 . iIii1I11I1II1 . o0oOOo0O0Ooo
  if 39 - 39: o0oOOo0O0Ooo
 def print_prefix ( self ) :
  if ( self . group . is_null ( ) ) :
   return ( green ( self . eid . print_prefix ( ) , False ) )
   if 89 - 89: OoooooooOO + iII111i . I1Ii111 / Ii1I
  return ( green ( self . eid . print_sg ( self . group ) , False ) )
  if 75 - 75: iIii1I11I1II1 * iII111i / OoOoOO00 * II111iiii . i1IIi
  if 6 - 6: Ii1I % Ii1I / OoooooooOO * oO0o . I1IiiI . i1IIi
 def print_ttl ( self ) :
  O00O00Oo = self . record_ttl
  if ( self . record_ttl & 0x80000000 ) :
   O00O00Oo = str ( self . record_ttl & 0x7fffffff ) + " secs"
  elif ( ( O00O00Oo % 60 ) == 0 ) :
   O00O00Oo = str ( O00O00Oo / 60 ) + " hours"
  else :
   O00O00Oo = str ( O00O00Oo ) + " mins"
   if 62 - 62: oO0o / Oo0Ooo
  return ( O00O00Oo )
  if 10 - 10: O0 + iII111i + i11iIiiIii % iIii1I11I1II1 * iII111i * Oo0Ooo
  if 55 - 55: i11iIiiIii
 def store_ttl ( self ) :
  O00O00Oo = self . record_ttl * 60
  if ( self . record_ttl & 0x80000000 ) : O00O00Oo = self . record_ttl & 0x7fffffff
  return ( O00O00Oo )
  if 11 - 11: ooOoO0o . I1Ii111 - iII111i . o0oOOo0O0Ooo
  if 41 - 41: oO0o / OoO0O00 - OoO0O00 + ooOoO0o * OOooOOo
 def print_record ( self , indent , ddt ) :
  i1IiIi1II11ii = ""
  IIi = ""
  I111iI1iiii = bold ( "invalid-action" , False )
  if ( ddt ) :
   if ( self . action < len ( lisp_map_referral_action_string ) ) :
    I111iI1iiii = lisp_map_referral_action_string [ self . action ]
    I111iI1iiii = bold ( I111iI1iiii , False )
    i1IiIi1II11ii = ( ", " + bold ( "ddt-incomplete" , False ) ) if self . ddt_incomplete else ""
    if 55 - 55: I1Ii111 / OoooooooOO . ooOoO0o / OoO0O00
    IIi = ( ", sig-count: " + str ( self . signature_count ) ) if ( self . signature_count != 0 ) else ""
    if 28 - 28: i11iIiiIii % O0
    if 17 - 17: I1Ii111 + i11iIiiIii . i11iIiiIii * i1IIi / O0
  else :
   if ( self . action < len ( lisp_map_reply_action_string ) ) :
    I111iI1iiii = lisp_map_reply_action_string [ self . action ]
    if ( self . action != LISP_NO_ACTION ) :
     I111iI1iiii = bold ( I111iI1iiii , False )
     if 2 - 2: II111iiii / OoO0O00 % iIii1I11I1II1 / i11iIiiIii
     if 52 - 52: ooOoO0o % iIii1I11I1II1 . i11iIiiIii % ooOoO0o
     if 86 - 86: oO0o % iIii1I11I1II1 % OoOoOO00
     if 94 - 94: o0oOOo0O0Ooo - I11i % oO0o % o0oOOo0O0Ooo + I11i
  ooo0O0O0oo0 = LISP_AFI_LCAF if ( self . eid . afi < 0 ) else self . eid . afi
  iiIiiIi1 = ( "{}EID-record -> record-ttl: {}, rloc-count: {}, action: " +
 "{}, {}{}{}, map-version: {}, afi: {}, [iid]eid/ml: {}" )
  if 31 - 31: I1Ii111 * o0oOOo0O0Ooo * II111iiii + O0 / iII111i * ooOoO0o
  lprint ( iiIiiIi1 . format ( indent , self . print_ttl ( ) , self . rloc_count ,
 I111iI1iiii , "auth" if ( self . authoritative is True ) else "non-auth" ,
 i1IiIi1II11ii , IIi , self . map_version , ooo0O0O0oo0 ,
 green ( self . print_prefix ( ) , False ) ) )
  if 52 - 52: iIii1I11I1II1 / iII111i . O0 * IiII . I1IiiI
  if 67 - 67: II111iiii + Ii1I - I1IiiI * ooOoO0o
 def encode ( self ) :
  iiIiiIii1IiI = self . action << 13
  if ( self . authoritative ) : iiIiiIii1IiI |= 0x1000
  if ( self . ddt_incomplete ) : iiIiiIii1IiI |= 0x800
  if 71 - 71: iIii1I11I1II1 + O0 . IiII . iII111i % o0oOOo0O0Ooo % O0
  if 51 - 51: o0oOOo0O0Ooo - Ii1I - iIii1I11I1II1 * iIii1I11I1II1 * o0oOOo0O0Ooo - O0
  if 27 - 27: i1IIi . I1Ii111
  if 64 - 64: ooOoO0o / i1IIi
  ooo0O0O0oo0 = self . eid . afi if ( self . eid . instance_id == 0 ) else LISP_AFI_LCAF
  if ( ooo0O0O0oo0 < 0 ) : ooo0O0O0oo0 = LISP_AFI_LCAF
  ooo00 = ( self . group . is_null ( ) == False )
  if ( ooo00 ) : ooo0O0O0oo0 = LISP_AFI_LCAF
  if 56 - 56: OOooOOo - I1Ii111
  OOoO0ooOooOoo = ( self . signature_count << 12 ) | self . map_version
  i1iIi = 0 if self . eid . is_binary ( ) == False else self . eid . mask_len
  if 57 - 57: i11iIiiIii + I11i % ooOoO0o / iIii1I11I1II1
  iIIi1 = struct . pack ( "IBBHHH" , socket . htonl ( self . record_ttl ) ,
 self . rloc_count , i1iIi , socket . htons ( iiIiiIii1IiI ) ,
 socket . htons ( OOoO0ooOooOoo ) , socket . htons ( ooo0O0O0oo0 ) )
  if 74 - 74: Oo0Ooo + OOooOOo . o0oOOo0O0Ooo / OoOoOO00 + Ii1I + i1IIi
  if 82 - 82: Ii1I * I11i / I1IiiI * iIii1I11I1II1 / ooOoO0o + IiII
  if 30 - 30: oO0o . i11iIiiIii / I11i + i1IIi - I11i
  if 50 - 50: i1IIi
  if ( ooo00 ) :
   iIIi1 += self . eid . lcaf_encode_sg ( self . group )
   return ( iIIi1 )
   if 56 - 56: OoO0O00 + I1Ii111 / Ii1I
   if 75 - 75: OoOoOO00
   if 96 - 96: o0oOOo0O0Ooo * I11i * Oo0Ooo
   if 36 - 36: OoooooooOO + ooOoO0o . oO0o * ooOoO0o + IiII
   if 45 - 45: oO0o / iII111i + I1ii11iIi11i - Oo0Ooo - ooOoO0o . iIii1I11I1II1
  if ( self . eid . afi == LISP_AFI_GEO_COORD and self . eid . instance_id == 0 ) :
   iIIi1 = iIIi1 [ 0 : - 2 ]
   iIIi1 += self . eid . address . encode_geo ( )
   return ( iIIi1 )
   if 52 - 52: I1IiiI + i1IIi . iII111i * I1IiiI
   if 31 - 31: Oo0Ooo % iIii1I11I1II1 . O0
   if 80 - 80: I11i / Oo0Ooo + I1ii11iIi11i
   if 18 - 18: II111iiii - iII111i / iIii1I11I1II1 % OoOoOO00 % I1ii11iIi11i / o0oOOo0O0Ooo
   if 47 - 47: OOooOOo
  if ( ooo0O0O0oo0 == LISP_AFI_LCAF ) :
   iIIi1 += self . eid . lcaf_encode_iid ( )
   return ( iIIi1 )
   if 24 - 24: Ii1I % o0oOOo0O0Ooo
   if 87 - 87: o0oOOo0O0Ooo % iII111i / ooOoO0o - IiII + i11iIiiIii
   if 85 - 85: OoooooooOO * IiII . OOooOOo / iII111i / OoooooooOO
   if 87 - 87: OoO0O00
   if 32 - 32: i11iIiiIii - OoOoOO00 * I11i . Oo0Ooo * ooOoO0o
  iIIi1 += self . eid . pack_address ( )
  return ( iIIi1 )
  if 21 - 21: OOooOOo
  if 11 - 11: oO0o % i11iIiiIii * O0
 def decode ( self , packet ) :
  I1I = "IBBHHH"
  ii1I1iIi = struct . calcsize ( I1I )
  if ( len ( packet ) < ii1I1iIi ) : return ( None )
  if 28 - 28: I1Ii111 / iIii1I11I1II1 + OOooOOo . I1ii11iIi11i % OOooOOo + OoO0O00
  self . record_ttl , self . rloc_count , self . eid . mask_len , iiIiiIii1IiI , self . map_version , self . eid . afi = struct . unpack ( I1I , packet [ : ii1I1iIi ] )
  if 79 - 79: oO0o
  if 39 - 39: I1Ii111 % oO0o % O0 % O0 - iII111i - oO0o
  if 83 - 83: i11iIiiIii + iIii1I11I1II1
  self . record_ttl = socket . ntohl ( self . record_ttl )
  iiIiiIii1IiI = socket . ntohs ( iiIiiIii1IiI )
  self . action = ( iiIiiIii1IiI >> 13 ) & 0x7
  self . authoritative = True if ( ( iiIiiIii1IiI >> 12 ) & 1 ) else False
  self . ddt_incomplete = True if ( ( iiIiiIii1IiI >> 11 ) & 1 ) else False
  self . map_version = socket . ntohs ( self . map_version )
  self . signature_count = self . map_version >> 12
  self . map_version = self . map_version & 0xfff
  self . eid . afi = socket . ntohs ( self . eid . afi )
  self . eid . instance_id = 0
  packet = packet [ ii1I1iIi : : ]
  if 21 - 21: o0oOOo0O0Ooo / i11iIiiIii % I1Ii111
  if 56 - 56: o0oOOo0O0Ooo * iIii1I11I1II1 . Ii1I + OoOoOO00 % I1Ii111
  if 11 - 11: OOooOOo
  if 12 - 12: OoooooooOO * OOooOOo * I1ii11iIi11i * ooOoO0o
  if ( self . eid . afi == LISP_AFI_LCAF ) :
   packet , iiI = self . eid . lcaf_decode_eid ( packet )
   if ( iiI ) : self . group = iiI
   self . group . instance_id = self . eid . instance_id
   return ( packet )
   if 23 - 23: IiII + i11iIiiIii * Ii1I
   if 55 - 55: Oo0Ooo % IiII + i11iIiiIii - OOooOOo - II111iiii
  packet = self . eid . unpack_address ( packet )
  return ( packet )
  if 80 - 80: IiII
  if 97 - 97: iII111i
 def print_eid_tuple ( self ) :
  return ( lisp_print_eid_tuple ( self . eid , self . group ) )
  if 40 - 40: ooOoO0o
  if 61 - 61: iII111i - OOooOOo / iII111i . Oo0Ooo % OoO0O00
  if 70 - 70: I1Ii111 * Oo0Ooo
  if 75 - 75: I1IiiI . iII111i % iII111i * i11iIiiIii + i1IIi * Oo0Ooo
  if 98 - 98: Ii1I - OoooooooOO * I11i * oO0o % I1ii11iIi11i * II111iiii
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
  if 1 - 1: I1IiiI - OoOoOO00
  if 74 - 74: OoOoOO00 * II111iiii + O0 + I11i
  if 3 - 3: iIii1I11I1II1 - i1IIi / iII111i + i1IIi + O0
  if 18 - 18: iIii1I11I1II1 . iII111i % OOooOOo % oO0o + iIii1I11I1II1 * OoooooooOO
  if 78 - 78: IiII
LISP_UDP_PROTOCOL = 17
LISP_DEFAULT_ECM_TTL = 128
if 38 - 38: OoO0O00 * I1ii11iIi11i
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
  if 4 - 4: OoO0O00 . I1ii11iIi11i
  if 21 - 21: i11iIiiIii / OoO0O00 / I1ii11iIi11i * O0 - II111iiii * OOooOOo
 def print_ecm ( self ) :
  iiIiiIi1 = ( "{} -> flags: {}{}{}{}, " + "inner IP: {} -> {}, inner UDP: {} -> {}" )
  if 27 - 27: o0oOOo0O0Ooo . OoOoOO00 * Ii1I * iII111i * O0
  lprint ( iiIiiIi1 . format ( bold ( "ECM" , False ) , "S" if self . security else "s" ,
 "D" if self . ddt else "d" , "E" if self . to_etr else "e" ,
 "M" if self . to_ms else "m" ,
 green ( self . source . print_address ( ) , False ) ,
 green ( self . dest . print_address ( ) , False ) , self . udp_sport ,
 self . udp_dport ) )
  if 93 - 93: IiII % I1Ii111 % II111iiii
 def encode ( self , packet , inner_source , inner_dest ) :
  self . udp_length = len ( packet ) + 8
  self . source = inner_source
  self . dest = inner_dest
  if ( inner_dest . is_ipv4 ( ) ) :
   self . afi = LISP_AFI_IPV4
   self . length = self . udp_length + 20
   if 20 - 20: OoooooooOO * I1Ii111
  if ( inner_dest . is_ipv6 ( ) ) :
   self . afi = LISP_AFI_IPV6
   self . length = self . udp_length
   if 38 - 38: iII111i . OoooooooOO
   if 28 - 28: I1Ii111 * i1IIi . I1ii11iIi11i
   if 75 - 75: O0 / oO0o * ooOoO0o - OOooOOo / i1IIi
   if 61 - 61: I11i
   if 100 - 100: O0 - iIii1I11I1II1 * Oo0Ooo
   if 35 - 35: ooOoO0o
  Iii11I1i = ( LISP_ECM << 28 )
  if ( self . security ) : Iii11I1i |= 0x08000000
  if ( self . ddt ) : Iii11I1i |= 0x04000000
  if ( self . to_etr ) : Iii11I1i |= 0x02000000
  if ( self . to_ms ) : Iii11I1i |= 0x01000000
  if 57 - 57: OoO0O00 . Oo0Ooo + I1IiiI
  Ii1Ii1Ii = struct . pack ( "I" , socket . htonl ( Iii11I1i ) )
  if 73 - 73: I1IiiI - I11i . Ii1I * iII111i
  ii = ""
  if ( self . afi == LISP_AFI_IPV4 ) :
   ii = struct . pack ( "BBHHHBBH" , 0x45 , 0 , socket . htons ( self . length ) ,
 0 , 0 , self . ttl , self . protocol , socket . htons ( self . ip_checksum ) )
   ii += self . source . pack_address ( )
   ii += self . dest . pack_address ( )
   ii = lisp_ip_checksum ( ii )
   if 3 - 3: i11iIiiIii
  if ( self . afi == LISP_AFI_IPV6 ) :
   ii = struct . pack ( "BBHHBB" , 0x60 , 0 , 0 , socket . htons ( self . length ) ,
 self . protocol , self . ttl )
   ii += self . source . pack_address ( )
   ii += self . dest . pack_address ( )
   if 72 - 72: ooOoO0o
   if 85 - 85: Ii1I . Ii1I * IiII * i1IIi
  oooOOO00o0 = socket . htons ( self . udp_sport )
  O0o0oo0oOO0oO = socket . htons ( self . udp_dport )
  o0Oo = socket . htons ( self . udp_length )
  ooOoo000 = socket . htons ( self . udp_checksum )
  iI = struct . pack ( "HHHH" , oooOOO00o0 , O0o0oo0oOO0oO , o0Oo , ooOoo000 )
  return ( Ii1Ii1Ii + ii + iI )
  if 4 - 4: i11iIiiIii - i1IIi
  if 90 - 90: i1IIi / OoooooooOO . Oo0Ooo
 def decode ( self , packet ) :
  if 5 - 5: iII111i * ooOoO0o + IiII . I1IiiI / I1IiiI
  if 72 - 72: OoO0O00 / I1ii11iIi11i - OOooOOo - OoooooooOO / OoooooooOO % OoooooooOO
  if 85 - 85: OoO0O00 . o0oOOo0O0Ooo . I1IiiI
  if 75 - 75: iIii1I11I1II1 - Ii1I % O0 % IiII
  I1I = "I"
  ii1I1iIi = struct . calcsize ( I1I )
  if ( len ( packet ) < ii1I1iIi ) : return ( None )
  if 6 - 6: Oo0Ooo % oO0o * ooOoO0o - i1IIi . OoOoOO00
  Iii11I1i = struct . unpack ( I1I , packet [ : ii1I1iIi ] )
  if 20 - 20: Oo0Ooo / I1Ii111 . Oo0Ooo
  Iii11I1i = socket . ntohl ( Iii11I1i [ 0 ] )
  self . security = True if ( Iii11I1i & 0x08000000 ) else False
  self . ddt = True if ( Iii11I1i & 0x04000000 ) else False
  self . to_etr = True if ( Iii11I1i & 0x02000000 ) else False
  self . to_ms = True if ( Iii11I1i & 0x01000000 ) else False
  packet = packet [ ii1I1iIi : : ]
  if 60 - 60: I1ii11iIi11i - I1IiiI * O0 * Oo0Ooo . i1IIi . OoOoOO00
  if 24 - 24: IiII * I1IiiI / OOooOOo
  if 51 - 51: iIii1I11I1II1 / I11i * OoO0O00 * Ii1I + I1ii11iIi11i . OoooooooOO
  if 75 - 75: IiII / OoooooooOO / O0 % OOooOOo
  if ( len ( packet ) < 1 ) : return ( None )
  OOOO0oO0O = struct . unpack ( "B" , packet [ 0 : 1 ] ) [ 0 ]
  OOOO0oO0O = OOOO0oO0O >> 4
  if 87 - 87: II111iiii / iIii1I11I1II1 % I1ii11iIi11i
  if ( OOOO0oO0O == 4 ) :
   ii1I1iIi = struct . calcsize ( "HHIBBH" )
   if ( len ( packet ) < ii1I1iIi ) : return ( None )
   if 11 - 11: o0oOOo0O0Ooo * OoO0O00
   oO0IiiI1i1i11I1 , o0Oo , oO0IiiI1i1i11I1 , oOOO0ooo , iII1ii , ooOoo000 = struct . unpack ( "HHIBBH" , packet [ : ii1I1iIi ] )
   self . length = socket . ntohs ( o0Oo )
   self . ttl = oOOO0ooo
   self . protocol = iII1ii
   self . ip_checksum = socket . ntohs ( ooOoo000 )
   self . source . afi = self . dest . afi = LISP_AFI_IPV4
   if 18 - 18: Oo0Ooo - oO0o + I1IiiI . I11i
   if 67 - 67: IiII / o0oOOo0O0Ooo + I11i % iII111i - ooOoO0o - I1IiiI
   if 44 - 44: Ii1I . o0oOOo0O0Ooo . iIii1I11I1II1 + OoooooooOO - I1IiiI
   if 22 - 22: I11i * I1ii11iIi11i . OoooooooOO / Oo0Ooo / Ii1I
   iII1ii = struct . pack ( "H" , 0 )
   o0O00OOo00O = struct . calcsize ( "HHIBB" )
   IiiiII1III1 = struct . calcsize ( "H" )
   packet = packet [ : o0O00OOo00O ] + iII1ii + packet [ o0O00OOo00O + IiiiII1III1 : ]
   if 45 - 45: Oo0Ooo
   packet = packet [ ii1I1iIi : : ]
   packet = self . source . unpack_address ( packet )
   if ( packet == None ) : return ( None )
   packet = self . dest . unpack_address ( packet )
   if ( packet == None ) : return ( None )
   if 27 - 27: iII111i + Oo0Ooo * O0 / oO0o * i11iIiiIii
   if 24 - 24: I11i
  if ( OOOO0oO0O == 6 ) :
   ii1I1iIi = struct . calcsize ( "IHBB" )
   if ( len ( packet ) < ii1I1iIi ) : return ( None )
   if 9 - 9: i1IIi + oO0o
   oO0IiiI1i1i11I1 , o0Oo , iII1ii , oOOO0ooo = struct . unpack ( "IHBB" , packet [ : ii1I1iIi ] )
   self . length = socket . ntohs ( o0Oo )
   self . protocol = iII1ii
   self . ttl = oOOO0ooo
   self . source . afi = self . dest . afi = LISP_AFI_IPV6
   if 14 - 14: O0 + I1ii11iIi11i
   packet = packet [ ii1I1iIi : : ]
   packet = self . source . unpack_address ( packet )
   if ( packet == None ) : return ( None )
   packet = self . dest . unpack_address ( packet )
   if ( packet == None ) : return ( None )
   if 39 - 39: i11iIiiIii
   if 97 - 97: OoOoOO00 . Oo0Ooo . I1Ii111 + iII111i % ooOoO0o . IiII
  self . source . mask_len = self . source . host_mask_len ( )
  self . dest . mask_len = self . dest . host_mask_len ( )
  if 40 - 40: I1Ii111 - i11iIiiIii
  ii1I1iIi = struct . calcsize ( "HHHH" )
  if ( len ( packet ) < ii1I1iIi ) : return ( None )
  if 58 - 58: II111iiii / O0
  oooOOO00o0 , O0o0oo0oOO0oO , o0Oo , ooOoo000 = struct . unpack ( "HHHH" , packet [ : ii1I1iIi ] )
  self . udp_sport = socket . ntohs ( oooOOO00o0 )
  self . udp_dport = socket . ntohs ( O0o0oo0oOO0oO )
  self . udp_length = socket . ntohs ( o0Oo )
  self . udp_checksum = socket . ntohs ( ooOoo000 )
  packet = packet [ ii1I1iIi : : ]
  return ( packet )
  if 83 - 83: OOooOOo * IiII / OoO0O00 / i11iIiiIii
  if 94 - 94: O0 / iIii1I11I1II1 + O0 / I1IiiI
  if 90 - 90: OoooooooOO * OoooooooOO
  if 47 - 47: OoOoOO00 - I1Ii111 + IiII . II111iiii / oO0o / i11iIiiIii
  if 28 - 28: I1IiiI . o0oOOo0O0Ooo + OoO0O00
  if 100 - 100: oO0o + II111iiii / IiII / i1IIi / Ii1I / O0
  if 50 - 50: Ii1I + Ii1I
  if 51 - 51: I1ii11iIi11i / OoooooooOO * IiII
  if 78 - 78: iII111i / I1ii11iIi11i . i11iIiiIii
  if 69 - 69: I11i - II111iiii
  if 66 - 66: I1IiiI . I1IiiI - OoOoOO00 * OoooooooOO * II111iiii + I1IiiI
  if 59 - 59: Ii1I
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
  if 13 - 13: i1IIi . I1IiiI
  if 45 - 45: ooOoO0o % I11i
 def print_rloc_name ( self , cour = False ) :
  if ( self . rloc_name == None ) : return ( "" )
  i11Ii1i1iII = self . rloc_name
  if ( cour ) : i11Ii1i1iII = lisp_print_cour ( i11Ii1i1iII )
  return ( 'rloc-name: {}' . format ( blue ( i11Ii1i1iII , cour ) ) )
  if 58 - 58: I1Ii111 * OoO0O00 * i1IIi
  if 34 - 34: OoooooooOO - oO0o / OOooOOo / o0oOOo0O0Ooo + OOooOOo . i11iIiiIii
 def print_record ( self , indent ) :
  iII1II = self . print_rloc_name ( )
  if ( iII1II != "" ) : iII1II = ", " + iII1II
  iII1IiiIIi = ""
  if ( self . geo ) :
   oo00 = ""
   if ( self . geo . geo_name ) : oo00 = "'{}' " . format ( self . geo . geo_name )
   iII1IiiIIi = ", geo: {}{}" . format ( oo00 , self . geo . print_geo ( ) )
   if 61 - 61: iIii1I11I1II1 % IiII - II111iiii
  Ii1111IIIiiIi = ""
  if ( self . elp ) :
   oo00 = ""
   if ( self . elp . elp_name ) : oo00 = "'{}' " . format ( self . elp . elp_name )
   Ii1111IIIiiIi = ", elp: {}{}" . format ( oo00 , self . elp . print_elp ( True ) )
   if 94 - 94: I11i
  OoI1iIi = ""
  if ( self . rle ) :
   oo00 = ""
   if ( self . rle . rle_name ) : oo00 = "'{}' " . format ( self . rle . rle_name )
   OoI1iIi = ", rle: {}{}" . format ( oo00 , self . rle . print_rle ( False ) )
   if 80 - 80: i1IIi / OOooOOo / o0oOOo0O0Ooo - IiII
  Iii11 = ""
  if ( self . json ) :
   oo00 = ""
   if ( self . json . json_name ) :
    oo00 = "'{}' " . format ( self . json . json_name )
    if 13 - 13: OoO0O00 * OOooOOo + oO0o
   Iii11 = ", json: {}" . format ( self . json . print_json ( False ) )
   if 21 - 21: i11iIiiIii . Ii1I % i1IIi * Ii1I . oO0o + Ii1I
   if 92 - 92: i1IIi + OoO0O00 * I11i
  o00o0o = ""
  if ( self . rloc . is_null ( ) == False and self . keys and self . keys [ 1 ] ) :
   o00o0o = ", " + self . keys [ 1 ] . print_keys ( )
   if 56 - 56: Oo0Ooo
   if 4 - 4: o0oOOo0O0Ooo / oO0o / iII111i . oO0o
  iiIiiIi1 = ( "{}RLOC-record -> flags: {}, {}/{}/{}/{}, afi: {}, rloc: "
 + "{}{}{}{}{}{}{}" )
  lprint ( iiIiiIi1 . format ( indent , self . print_flags ( ) , self . priority ,
 self . weight , self . mpriority , self . mweight , self . rloc . afi ,
 red ( self . rloc . print_address_no_iid ( ) , False ) , iII1II , iII1IiiIIi ,
 Ii1111IIIiiIi , OoI1iIi , Iii11 , o00o0o ) )
  if 80 - 80: IiII . II111iiii
  if 68 - 68: Ii1I + OoO0O00 - Oo0Ooo + iII111i * OoooooooOO + iII111i
 def print_flags ( self ) :
  return ( "{}{}{}" . format ( "L" if self . local_bit else "l" , "P" if self . probe_bit else "p" , "R" if self . reach_bit else "r" ) )
  if 25 - 25: OOooOOo % iII111i + iII111i
  if 41 - 41: OoO0O00 / I1ii11iIi11i . I1ii11iIi11i / i1IIi - i1IIi - I1ii11iIi11i
  if 78 - 78: iII111i % iII111i % O0 - I11i - OoO0O00
 def store_rloc_entry ( self , rloc_entry ) :
  Oo0O0 = rloc_entry . rloc if ( rloc_entry . translated_rloc . is_null ( ) ) else rloc_entry . translated_rloc
  if 21 - 21: OoO0O00 % iIii1I11I1II1 / I1ii11iIi11i / iIii1I11I1II1 * iIii1I11I1II1
  self . rloc . copy_address ( Oo0O0 )
  if 72 - 72: o0oOOo0O0Ooo * OOooOOo - I1IiiI * II111iiii
  if ( rloc_entry . rloc_name ) :
   self . rloc_name = rloc_entry . rloc_name
   if 94 - 94: OOooOOo . OoooooooOO
   if 46 - 46: IiII * OoooooooOO . o0oOOo0O0Ooo - I1Ii111 * I1IiiI
  if ( rloc_entry . geo ) :
   self . geo = rloc_entry . geo
  else :
   oo00 = rloc_entry . geo_name
   if ( oo00 and lisp_geo_list . has_key ( oo00 ) ) :
    self . geo = lisp_geo_list [ oo00 ]
    if 83 - 83: Oo0Ooo . o0oOOo0O0Ooo + iII111i + o0oOOo0O0Ooo % iIii1I11I1II1 * OoOoOO00
    if 65 - 65: OOooOOo . II111iiii * i11iIiiIii + OOooOOo
  if ( rloc_entry . elp ) :
   self . elp = rloc_entry . elp
  else :
   oo00 = rloc_entry . elp_name
   if ( oo00 and lisp_elp_list . has_key ( oo00 ) ) :
    self . elp = lisp_elp_list [ oo00 ]
    if 99 - 99: I1ii11iIi11i % Oo0Ooo
    if 31 - 31: o0oOOo0O0Ooo - II111iiii * OOooOOo . OOooOOo - oO0o
  if ( rloc_entry . rle ) :
   self . rle = rloc_entry . rle
  else :
   oo00 = rloc_entry . rle_name
   if ( oo00 and lisp_rle_list . has_key ( oo00 ) ) :
    self . rle = lisp_rle_list [ oo00 ]
    if 57 - 57: OOooOOo / i11iIiiIii / I1Ii111 - Oo0Ooo . iIii1I11I1II1
    if 84 - 84: IiII
  if ( rloc_entry . json ) :
   self . json = rloc_entry . json
  else :
   oo00 = rloc_entry . json_name
   if ( oo00 and lisp_json_list . has_key ( oo00 ) ) :
    self . json = lisp_json_list [ oo00 ]
    if 42 - 42: O0 . I1Ii111 / I11i
    if 69 - 69: OoOoOO00 / I1Ii111 * I1IiiI
  self . priority = rloc_entry . priority
  self . weight = rloc_entry . weight
  self . mpriority = rloc_entry . mpriority
  self . mweight = rloc_entry . mweight
  if 76 - 76: O0 + II111iiii * OoO0O00
  if 1 - 1: o0oOOo0O0Ooo
 def encode_lcaf ( self ) :
  iio00OOO0o0Oo0 = socket . htons ( LISP_AFI_LCAF )
  IIi1II = ""
  if ( self . geo ) :
   IIi1II = self . geo . encode_geo ( )
   if 36 - 36: IiII . IiII
   if 27 - 27: OoOoOO00 - iIii1I11I1II1 / i1IIi * I1Ii111 - ooOoO0o
  I111I1IiI1i1 = ""
  if ( self . elp ) :
   o0oo = ""
   for OO in self . elp . elp_nodes :
    ooo0O0O0oo0 = socket . htons ( OO . address . afi )
    o0Ooo00Oo0oo0 = 0
    if ( OO . eid ) : o0Ooo00Oo0oo0 |= 0x4
    if ( OO . probe ) : o0Ooo00Oo0oo0 |= 0x2
    if ( OO . strict ) : o0Ooo00Oo0oo0 |= 0x1
    o0Ooo00Oo0oo0 = socket . htons ( o0Ooo00Oo0oo0 )
    o0oo += struct . pack ( "HH" , o0Ooo00Oo0oo0 , ooo0O0O0oo0 )
    o0oo += OO . address . pack_address ( )
    if 88 - 88: OOooOOo / Ii1I . iII111i - OoOoOO00 + iII111i
    if 83 - 83: iII111i + OoooooooOO + i1IIi / Oo0Ooo
   iii1Io0OOOooo = socket . htons ( len ( o0oo ) )
   I111I1IiI1i1 = struct . pack ( "HBBBBH" , iio00OOO0o0Oo0 , 0 , 0 , LISP_LCAF_ELP_TYPE ,
 0 , iii1Io0OOOooo )
   I111I1IiI1i1 += o0oo
   if 34 - 34: i11iIiiIii % OoO0O00 - oO0o / OOooOOo / iII111i
   if 5 - 5: I1Ii111 . oO0o
  o0ooo = ""
  if ( self . rle ) :
   iIIIII1iiI = ""
   for iIiiI11iI111 in self . rle . rle_nodes :
    ooo0O0O0oo0 = socket . htons ( iIiiI11iI111 . address . afi )
    iIIIII1iiI += struct . pack ( "HBBH" , 0 , 0 , iIiiI11iI111 . level , ooo0O0O0oo0 )
    iIIIII1iiI += iIiiI11iI111 . address . pack_address ( )
    if ( iIiiI11iI111 . rloc_name ) :
     iIIIII1iiI += struct . pack ( "H" , socket . htons ( LISP_AFI_NAME ) )
     iIIIII1iiI += iIiiI11iI111 . rloc_name + "\0"
     if 28 - 28: oO0o . ooOoO0o / I11i + Oo0Ooo
     if 55 - 55: OoooooooOO % OoOoOO00 + i1IIi * OoO0O00 * OOooOOo
     if 39 - 39: OOooOOo - oO0o
   oO00OOooOOOoO = socket . htons ( len ( iIIIII1iiI ) )
   o0ooo = struct . pack ( "HBBBBH" , iio00OOO0o0Oo0 , 0 , 0 , LISP_LCAF_RLE_TYPE ,
 0 , oO00OOooOOOoO )
   o0ooo += iIIIII1iiI
   if 60 - 60: OoO0O00
   if 16 - 16: I11i
  iII11i1 = ""
  if ( self . json ) :
   I1iIiI1iiI = socket . htons ( len ( self . json . json_string ) + 2 )
   oO000O00 = socket . htons ( len ( self . json . json_string ) )
   iII11i1 = struct . pack ( "HBBBBHH" , iio00OOO0o0Oo0 , 0 , 0 , LISP_LCAF_JSON_TYPE ,
 0 , I1iIiI1iiI , oO000O00 )
   iII11i1 += self . json . json_string
   iII11i1 += struct . pack ( "H" , 0 )
   if 58 - 58: iII111i
   if 77 - 77: IiII % oO0o % OoO0O00
  O0O0o0OooO0 = ""
  if ( self . rloc . is_null ( ) == False and self . keys and self . keys [ 1 ] ) :
   O0O0o0OooO0 = self . keys [ 1 ] . encode_lcaf ( self . rloc )
   if 88 - 88: i11iIiiIii - i1IIi + Oo0Ooo - O0
   if 50 - 50: I1ii11iIi11i
  IIi1iiIII11 = ""
  if ( self . rloc_name ) :
   IIi1iiIII11 += struct . pack ( "H" , socket . htons ( LISP_AFI_NAME ) )
   IIi1iiIII11 += self . rloc_name + "\0"
   if 69 - 69: I1ii11iIi11i . OoooooooOO % I1Ii111
   if 79 - 79: I1IiiI - IiII . OoooooooOO - I1ii11iIi11i
  OO0Oo0 = len ( IIi1II ) + len ( I111I1IiI1i1 ) + len ( o0ooo ) + len ( O0O0o0OooO0 ) + 2 + len ( iII11i1 ) + self . rloc . addr_length ( ) + len ( IIi1iiIII11 )
  if 65 - 65: Oo0Ooo * ooOoO0o % i11iIiiIii
  OO0Oo0 = socket . htons ( OO0Oo0 )
  iIiooo0O0OOO = struct . pack ( "HBBBBHH" , iio00OOO0o0Oo0 , 0 , 0 , LISP_LCAF_AFI_LIST_TYPE ,
 0 , OO0Oo0 , socket . htons ( self . rloc . afi ) )
  iIiooo0O0OOO += self . rloc . pack_address ( )
  return ( iIiooo0O0OOO + IIi1iiIII11 + IIi1II + I111I1IiI1i1 + o0ooo + O0O0o0OooO0 + iII11i1 )
  if 5 - 5: OoOoOO00 . oO0o + Ii1I * ooOoO0o * OoooooooOO
  if 36 - 36: OoO0O00 % Ii1I % iII111i
 def encode ( self ) :
  o0Ooo00Oo0oo0 = 0
  if ( self . local_bit ) : o0Ooo00Oo0oo0 |= 0x0004
  if ( self . probe_bit ) : o0Ooo00Oo0oo0 |= 0x0002
  if ( self . reach_bit ) : o0Ooo00Oo0oo0 |= 0x0001
  if 66 - 66: I1IiiI . OOooOOo - OoO0O00 % Oo0Ooo * o0oOOo0O0Ooo - oO0o
  iIIi1 = struct . pack ( "BBBBHH" , self . priority , self . weight ,
 self . mpriority , self . mweight , socket . htons ( o0Ooo00Oo0oo0 ) ,
 socket . htons ( self . rloc . afi ) )
  if 68 - 68: I11i - i11iIiiIii / o0oOOo0O0Ooo + ooOoO0o / I1IiiI
  if ( self . geo or self . elp or self . rle or self . keys or self . rloc_name or self . json ) :
   if 31 - 31: I1Ii111 . OoooooooOO . i1IIi
   iIIi1 = iIIi1 [ 0 : - 2 ] + self . encode_lcaf ( )
  else :
   iIIi1 += self . rloc . pack_address ( )
   if 65 - 65: OoO0O00 . ooOoO0o
  return ( iIIi1 )
  if 12 - 12: I1Ii111 + O0 - oO0o . IiII
  if 46 - 46: IiII . ooOoO0o / iII111i
 def decode_lcaf ( self , packet , nonce ) :
  I1I = "HBBBBH"
  ii1I1iIi = struct . calcsize ( I1I )
  if ( len ( packet ) < ii1I1iIi ) : return ( None )
  if 63 - 63: II111iiii - I1ii11iIi11i * II111iiii
  ooo0O0O0oo0 , oO0ooOoOooO00o00 , o0Ooo00Oo0oo0 , ii111I1IiiI1i , I11 , I1iIiI1iiI = struct . unpack ( I1I , packet [ : ii1I1iIi ] )
  if 92 - 92: OoO0O00 % ooOoO0o * O0 % iIii1I11I1II1 / i1IIi / OoOoOO00
  if 67 - 67: I1Ii111 + I11i + I1Ii111 . OOooOOo % o0oOOo0O0Ooo / ooOoO0o
  I1iIiI1iiI = socket . ntohs ( I1iIiI1iiI )
  packet = packet [ ii1I1iIi : : ]
  if ( I1iIiI1iiI > len ( packet ) ) : return ( None )
  if 78 - 78: I1ii11iIi11i . O0
  if 56 - 56: oO0o - i1IIi * O0 / I11i * I1IiiI . I11i
  if 54 - 54: i11iIiiIii % i1IIi + Oo0Ooo / OoOoOO00
  if 26 - 26: I11i . I1ii11iIi11i
  if ( ii111I1IiiI1i == LISP_LCAF_AFI_LIST_TYPE ) :
   while ( I1iIiI1iiI > 0 ) :
    I1I = "H"
    ii1I1iIi = struct . calcsize ( I1I )
    if ( I1iIiI1iiI < ii1I1iIi ) : return ( None )
    if 55 - 55: OoOoOO00 * I1Ii111 % OoO0O00 - OoO0O00
    O00OOOo = len ( packet )
    ooo0O0O0oo0 = struct . unpack ( I1I , packet [ : ii1I1iIi ] ) [ 0 ]
    ooo0O0O0oo0 = socket . ntohs ( ooo0O0O0oo0 )
    if 34 - 34: O0 * OoO0O00 - oO0o - IiII * Ii1I . II111iiii
    if ( ooo0O0O0oo0 == LISP_AFI_LCAF ) :
     packet = self . decode_lcaf ( packet , nonce )
     if ( packet == None ) : return ( None )
    else :
     packet = packet [ ii1I1iIi : : ]
     self . rloc_name = None
     if ( ooo0O0O0oo0 == LISP_AFI_NAME ) :
      packet , i11Ii1i1iII = lisp_decode_dist_name ( packet )
      self . rloc_name = i11Ii1i1iII
     else :
      self . rloc . afi = ooo0O0O0oo0
      packet = self . rloc . unpack_address ( packet )
      if ( packet == None ) : return ( None )
      self . rloc . mask_len = self . rloc . host_mask_len ( )
      if 28 - 28: O0 % iII111i - i1IIi
      if 49 - 49: ooOoO0o . I11i - iIii1I11I1II1
      if 41 - 41: ooOoO0o * i11iIiiIii % ooOoO0o . oO0o
    I1iIiI1iiI -= O00OOOo - len ( packet )
    if 97 - 97: oO0o - iII111i + IiII . OoOoOO00 + iIii1I11I1II1
    if 75 - 75: ooOoO0o + ooOoO0o . I1Ii111 % iII111i / iIii1I11I1II1 * iII111i
  elif ( ii111I1IiiI1i == LISP_LCAF_GEO_COORD_TYPE ) :
   if 13 - 13: II111iiii * i11iIiiIii - i1IIi * OoO0O00 + i1IIi
   if 43 - 43: O0 % oO0o * I1IiiI
   if 64 - 64: II111iiii + i11iIiiIii
   if 17 - 17: O0 * I1IiiI
   ii11iIIiiI1I = lisp_geo ( "" )
   packet = ii11iIIiiI1I . decode_geo ( packet , I1iIiI1iiI , I11 )
   if ( packet == None ) : return ( None )
   self . geo = ii11iIIiiI1I
   if 91 - 91: I1IiiI - OoooooooOO - OoooooooOO
  elif ( ii111I1IiiI1i == LISP_LCAF_JSON_TYPE ) :
   if 69 - 69: iII111i * i11iIiiIii / i1IIi
   if 86 - 86: I1IiiI % I11i * O0 + i1IIi % I1Ii111
   if 97 - 97: II111iiii * OoOoOO00 - I1Ii111 / i11iIiiIii / OoOoOO00
   if 25 - 25: Oo0Ooo / Oo0Ooo
   I1I = "H"
   ii1I1iIi = struct . calcsize ( I1I )
   if ( I1iIiI1iiI < ii1I1iIi ) : return ( None )
   if 74 - 74: OOooOOo
   oO000O00 = struct . unpack ( I1I , packet [ : ii1I1iIi ] ) [ 0 ]
   oO000O00 = socket . ntohs ( oO000O00 )
   if ( I1iIiI1iiI < ii1I1iIi + oO000O00 ) : return ( None )
   if 30 - 30: O0 . Ii1I / o0oOOo0O0Ooo + I1IiiI - O0
   packet = packet [ ii1I1iIi : : ]
   self . json = lisp_json ( "" , packet [ 0 : oO000O00 ] )
   packet = packet [ oO000O00 : : ]
   if 88 - 88: i11iIiiIii
  elif ( ii111I1IiiI1i == LISP_LCAF_ELP_TYPE ) :
   if 33 - 33: OoO0O00 + O0
   if 20 - 20: o0oOOo0O0Ooo % I11i . ooOoO0o - i1IIi . O0
   if 10 - 10: i1IIi
   if 49 - 49: I1Ii111 - Ii1I . O0
   iIiiiIiIIi = lisp_elp ( None )
   iIiiiIiIIi . elp_nodes = [ ]
   while ( I1iIiI1iiI > 0 ) :
    o0Ooo00Oo0oo0 , ooo0O0O0oo0 = struct . unpack ( "HH" , packet [ : 4 ] )
    if 87 - 87: i1IIi - O0 % OoooooooOO * i11iIiiIii % i11iIiiIii
    ooo0O0O0oo0 = socket . ntohs ( ooo0O0O0oo0 )
    if ( ooo0O0O0oo0 == LISP_AFI_LCAF ) : return ( None )
    if 19 - 19: ooOoO0o
    OO = lisp_elp_node ( )
    iIiiiIiIIi . elp_nodes . append ( OO )
    if 44 - 44: I1Ii111 - i11iIiiIii * I1IiiI
    o0Ooo00Oo0oo0 = socket . ntohs ( o0Ooo00Oo0oo0 )
    OO . eid = ( o0Ooo00Oo0oo0 & 0x4 )
    OO . probe = ( o0Ooo00Oo0oo0 & 0x2 )
    OO . strict = ( o0Ooo00Oo0oo0 & 0x1 )
    OO . address . afi = ooo0O0O0oo0
    OO . address . mask_len = OO . address . host_mask_len ( )
    packet = OO . address . unpack_address ( packet [ 4 : : ] )
    I1iIiI1iiI -= OO . address . addr_length ( ) + 4
    if 84 - 84: O0 % Ii1I
   iIiiiIiIIi . select_elp_node ( )
   self . elp = iIiiiIiIIi
   if 3 - 3: I1IiiI . I11i / I1ii11iIi11i
  elif ( ii111I1IiiI1i == LISP_LCAF_RLE_TYPE ) :
   if 2 - 2: IiII + I11i / iIii1I11I1II1 . i11iIiiIii . i1IIi * ooOoO0o
   if 14 - 14: Oo0Ooo . O0 - oO0o - i11iIiiIii
   if 8 - 8: I1IiiI / iIii1I11I1II1 / OoooooooOO / Oo0Ooo / ooOoO0o
   if 80 - 80: I11i
   oO = lisp_rle ( None )
   oO . rle_nodes = [ ]
   while ( I1iIiI1iiI > 0 ) :
    oO0IiiI1i1i11I1 , IiiiIi , OooOOo0 , ooo0O0O0oo0 = struct . unpack ( "HBBH" , packet [ : 6 ] )
    if 73 - 73: OoO0O00 + OOooOOo + IiII - i1IIi
    ooo0O0O0oo0 = socket . ntohs ( ooo0O0O0oo0 )
    if ( ooo0O0O0oo0 == LISP_AFI_LCAF ) : return ( None )
    if 67 - 67: OoooooooOO - i1IIi + Ii1I + I1IiiI
    iIiiI11iI111 = lisp_rle_node ( )
    oO . rle_nodes . append ( iIiiI11iI111 )
    if 18 - 18: Oo0Ooo * iII111i / II111iiii
    iIiiI11iI111 . level = OooOOo0
    iIiiI11iI111 . address . afi = ooo0O0O0oo0
    iIiiI11iI111 . address . mask_len = iIiiI11iI111 . address . host_mask_len ( )
    packet = iIiiI11iI111 . address . unpack_address ( packet [ 6 : : ] )
    if 77 - 77: Ii1I . o0oOOo0O0Ooo * oO0o
    I1iIiI1iiI -= iIiiI11iI111 . address . addr_length ( ) + 6
    if ( I1iIiI1iiI >= 2 ) :
     ooo0O0O0oo0 = struct . unpack ( "H" , packet [ : 2 ] ) [ 0 ]
     if ( socket . ntohs ( ooo0O0O0oo0 ) == LISP_AFI_NAME ) :
      packet = packet [ 2 : : ]
      packet , iIiiI11iI111 . rloc_name = lisp_decode_dist_name ( packet )
      if 42 - 42: Ii1I / Oo0Ooo
      if ( packet == None ) : return ( None )
      I1iIiI1iiI -= len ( iIiiI11iI111 . rloc_name ) + 1 + 2
      if 25 - 25: OoooooooOO % Ii1I * I1Ii111 * I11i + I1IiiI % I1ii11iIi11i
      if 70 - 70: Ii1I + I1ii11iIi11i * I11i * i1IIi . I1Ii111
      if 76 - 76: OoooooooOO * OoOoOO00 . OoooooooOO
   self . rle = oO
   self . rle . build_forwarding_list ( )
   if 46 - 46: ooOoO0o * o0oOOo0O0Ooo % II111iiii / I1Ii111
  elif ( ii111I1IiiI1i == LISP_LCAF_SECURITY_TYPE ) :
   if 29 - 29: OoO0O00 - i11iIiiIii % Oo0Ooo % o0oOOo0O0Ooo
   if 30 - 30: oO0o - Ii1I % Ii1I
   if 8 - 8: IiII
   if 68 - 68: IiII . OoooooooOO - i11iIiiIii + i11iIiiIii
   if 81 - 81: OoOoOO00 + iII111i . i11iIiiIii
   II11iII = packet
   OoOOoOOOoooO0 = lisp_keys ( 1 )
   packet = OoOOoOOOoooO0 . decode_lcaf ( II11iII , I1iIiI1iiI )
   if ( packet == None ) : return ( None )
   if 10 - 10: OoOoOO00 + I11i - iIii1I11I1II1 - I11i
   if 58 - 58: ooOoO0o
   if 98 - 98: Ii1I / OoO0O00 % OoooooooOO
   if 65 - 65: ooOoO0o % Oo0Ooo - I1IiiI % I1Ii111 + iIii1I11I1II1 / iIii1I11I1II1
   oOo0OO0 = [ LISP_CS_25519_CBC , LISP_CS_25519_CHACHA ]
   if ( OoOOoOOOoooO0 . cipher_suite in oOo0OO0 ) :
    if ( OoOOoOOOoooO0 . cipher_suite == LISP_CS_25519_CBC ) :
     o0000oO = lisp_keys ( 1 , do_poly = False , do_chacha = False )
     if 94 - 94: IiII - Oo0Ooo . o0oOOo0O0Ooo - ooOoO0o - oO0o . I11i
    if ( OoOOoOOOoooO0 . cipher_suite == LISP_CS_25519_CHACHA ) :
     o0000oO = lisp_keys ( 1 , do_poly = True , do_chacha = True )
     if 39 - 39: oO0o + OoOoOO00
   else :
    o0000oO = lisp_keys ( 1 , do_poly = False , do_chacha = False )
    if 68 - 68: i1IIi * oO0o / i11iIiiIii
   packet = o0000oO . decode_lcaf ( II11iII , I1iIiI1iiI )
   if ( packet == None ) : return ( None )
   if 96 - 96: I1IiiI
   if ( len ( packet ) < 2 ) : return ( None )
   ooo0O0O0oo0 = struct . unpack ( "H" , packet [ : 2 ] ) [ 0 ]
   self . rloc . afi = socket . ntohs ( ooo0O0O0oo0 )
   if ( len ( packet ) < self . rloc . addr_length ( ) ) : return ( None )
   packet = self . rloc . unpack_address ( packet [ 2 : : ] )
   if ( packet == None ) : return ( None )
   self . rloc . mask_len = self . rloc . host_mask_len ( )
   if 78 - 78: OoO0O00
   if 72 - 72: I1ii11iIi11i / O0 % II111iiii / II111iiii
   if 48 - 48: OOooOOo % OOooOOo / iIii1I11I1II1 - i11iIiiIii
   if 57 - 57: I11i / IiII * i1IIi + II111iiii . o0oOOo0O0Ooo
   if 11 - 11: II111iiii
   if 66 - 66: Ii1I - I1IiiI . OoooooooOO * I1Ii111
   if ( self . rloc . is_null ( ) ) : return ( packet )
   if 16 - 16: IiII * OoO0O00 * i11iIiiIii - ooOoO0o
   Oo00 = self . rloc_name
   if ( Oo00 ) : Oo00 = blue ( self . rloc_name , False )
   if 26 - 26: I1IiiI * OoooooooOO / I1IiiI . O0 . ooOoO0o + O0
   if 84 - 84: I1Ii111 . O0 + O0 % O0 % i1IIi + iIii1I11I1II1
   if 71 - 71: iII111i / iIii1I11I1II1 . OOooOOo * i11iIiiIii
   if 98 - 98: O0 % iIii1I11I1II1 . IiII - II111iiii
   if 14 - 14: Ii1I % ooOoO0o - OoOoOO00
   if 52 - 52: OoO0O00 / i1IIi - Ii1I
   oOo0ooo00OoO = self . keys [ 1 ] if self . keys else None
   if ( oOo0ooo00OoO == None ) :
    if ( o0000oO . remote_public_key == None ) :
     O00OO0O = bold ( "No remote encap-public-key supplied" , False )
     lprint ( "    {} for {}" . format ( O00OO0O , Oo00 ) )
     o0000oO = None
    else :
     O00OO0O = bold ( "New encap-keying with new state" , False )
     lprint ( "    {} for {}" . format ( O00OO0O , Oo00 ) )
     o0000oO . compute_shared_key ( "encap" )
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
   if ( oOo0ooo00OoO ) :
    if ( o0000oO . remote_public_key == None ) :
     o0000oO = None
     o0ooOoOO0 = bold ( "Remote encap-unkeying occurred" , False )
     lprint ( "    {} for {}" . format ( o0ooOoOO0 , Oo00 ) )
    elif ( oOo0ooo00OoO . compare_keys ( o0000oO ) ) :
     o0000oO = oOo0ooo00OoO
     lprint ( "    Maintain stored encap-keys for {}" . format ( Oo00 ) )
     if 45 - 45: i11iIiiIii * iII111i - I1ii11iIi11i + ooOoO0o % iII111i
    else :
     if ( oOo0ooo00OoO . remote_public_key == None ) :
      O00OO0O = "New encap-keying for existing state"
     else :
      O00OO0O = "Remote encap-rekeying"
      if 11 - 11: iIii1I11I1II1
     lprint ( "    {} for {}" . format ( bold ( O00OO0O , False ) ,
 Oo00 ) )
     oOo0ooo00OoO . remote_public_key = o0000oO . remote_public_key
     oOo0ooo00OoO . compute_shared_key ( "encap" )
     o0000oO = oOo0ooo00OoO
     if 48 - 48: iIii1I11I1II1 - Oo0Ooo
     if 80 - 80: i1IIi
   self . keys = [ None , o0000oO , None , None ]
   if 56 - 56: II111iiii - o0oOOo0O0Ooo
  else :
   if 48 - 48: Oo0Ooo - I1ii11iIi11i - II111iiii . Ii1I . oO0o / iIii1I11I1II1
   if 38 - 38: I1Ii111 % i11iIiiIii + Ii1I * ooOoO0o / I1Ii111
   if 93 - 93: oO0o
   if 60 - 60: I1Ii111 . oO0o / Oo0Ooo * ooOoO0o + OoOoOO00 - i1IIi
   packet = packet [ I1iIiI1iiI : : ]
   if 13 - 13: i11iIiiIii * oO0o / I11i * I1IiiI
  return ( packet )
  if 31 - 31: iIii1I11I1II1 * Ii1I % OOooOOo . II111iiii
  if 56 - 56: IiII / i11iIiiIii . o0oOOo0O0Ooo . oO0o - i11iIiiIii
 def decode ( self , packet , nonce ) :
  I1I = "BBBBHH"
  ii1I1iIi = struct . calcsize ( I1I )
  if ( len ( packet ) < ii1I1iIi ) : return ( None )
  if 23 - 23: I1ii11iIi11i * i11iIiiIii % ooOoO0o
  self . priority , self . weight , self . mpriority , self . mweight , o0Ooo00Oo0oo0 , ooo0O0O0oo0 = struct . unpack ( I1I , packet [ : ii1I1iIi ] )
  if 47 - 47: iIii1I11I1II1 . OOooOOo / I11i % II111iiii
  if 92 - 92: I1ii11iIi11i % i11iIiiIii
  o0Ooo00Oo0oo0 = socket . ntohs ( o0Ooo00Oo0oo0 )
  ooo0O0O0oo0 = socket . ntohs ( ooo0O0O0oo0 )
  self . local_bit = True if ( o0Ooo00Oo0oo0 & 0x0004 ) else False
  self . probe_bit = True if ( o0Ooo00Oo0oo0 & 0x0002 ) else False
  self . reach_bit = True if ( o0Ooo00Oo0oo0 & 0x0001 ) else False
  if 82 - 82: I1Ii111 * I1ii11iIi11i % Ii1I / o0oOOo0O0Ooo
  if ( ooo0O0O0oo0 == LISP_AFI_LCAF ) :
   packet = packet [ ii1I1iIi - 2 : : ]
   packet = self . decode_lcaf ( packet , nonce )
  else :
   self . rloc . afi = ooo0O0O0oo0
   packet = packet [ ii1I1iIi : : ]
   packet = self . rloc . unpack_address ( packet )
   if 28 - 28: iII111i % OoO0O00 - OOooOOo - Oo0Ooo
  self . rloc . mask_len = self . rloc . host_mask_len ( )
  return ( packet )
  if 16 - 16: i11iIiiIii - i11iIiiIii . OoOoOO00 / i1IIi
  if 76 - 76: O0 * OoO0O00 / O0
 def end_of_rlocs ( self , packet , rloc_count ) :
  for ooOooo0OO in range ( rloc_count ) :
   packet = self . decode ( packet , None )
   if ( packet == None ) : return ( None )
   if 23 - 23: I1ii11iIi11i . iIii1I11I1II1 - i11iIiiIii / II111iiii
  return ( packet )
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
  if 46 - 46: I1ii11iIi11i * I1Ii111 - iIii1I11I1II1
class lisp_map_referral ( ) :
 def __init__ ( self ) :
  self . record_count = 0
  self . nonce = 0
  if 25 - 25: II111iiii / OOooOOo + Oo0Ooo - iIii1I11I1II1 - OoOoOO00
  if 97 - 97: OOooOOo . OOooOOo / I1ii11iIi11i + I1IiiI * i1IIi
 def print_map_referral ( self ) :
  lprint ( "{} -> record-count: {}, nonce: 0x{}" . format ( bold ( "Map-Referral" , False ) , self . record_count ,
  # O0 . IiII / iII111i % OoooooooOO
 lisp_hex_string ( self . nonce ) ) )
  if 43 - 43: IiII + IiII
  if 88 - 88: OoOoOO00 % I1IiiI * I1IiiI
 def encode ( self ) :
  Iii11I1i = ( LISP_MAP_REFERRAL << 28 ) | self . record_count
  iIIi1 = struct . pack ( "I" , socket . htonl ( Iii11I1i ) )
  iIIi1 += struct . pack ( "Q" , self . nonce )
  return ( iIIi1 )
  if 97 - 97: iII111i + I1IiiI % oO0o % II111iiii * II111iiii + OoO0O00
  if 17 - 17: I11i - i11iIiiIii % iIii1I11I1II1 + OoO0O00 . iIii1I11I1II1
 def decode ( self , packet ) :
  I1I = "I"
  ii1I1iIi = struct . calcsize ( I1I )
  if ( len ( packet ) < ii1I1iIi ) : return ( None )
  if 57 - 57: I1IiiI - iIii1I11I1II1
  Iii11I1i = struct . unpack ( I1I , packet [ : ii1I1iIi ] )
  Iii11I1i = socket . ntohl ( Iii11I1i [ 0 ] )
  self . record_count = Iii11I1i & 0xff
  packet = packet [ ii1I1iIi : : ]
  if 82 - 82: OoO0O00
  I1I = "Q"
  ii1I1iIi = struct . calcsize ( I1I )
  if ( len ( packet ) < ii1I1iIi ) : return ( None )
  if 13 - 13: OoOoOO00 + i1IIi - I1IiiI
  self . nonce = struct . unpack ( I1I , packet [ : ii1I1iIi ] ) [ 0 ]
  packet = packet [ ii1I1iIi : : ]
  return ( packet )
  if 3 - 3: II111iiii % IiII * O0
  if 58 - 58: OOooOOo * I1Ii111
  if 19 - 19: OoOoOO00 / IiII - OOooOOo * i11iIiiIii % I1Ii111
  if 98 - 98: IiII + IiII + OOooOOo / i1IIi + oO0o
  if 53 - 53: OoOoOO00
  if 69 - 69: iIii1I11I1II1 * OoO0O00 / OoooooooOO % I1ii11iIi11i . I1IiiI % I11i
  if 40 - 40: i11iIiiIii % oO0o / OOooOOo
  if 85 - 85: OoO0O00 % O0 . Ii1I . iII111i . iII111i
class lisp_ddt_entry ( ) :
 def __init__ ( self ) :
  self . eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . group = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . uptime = lisp_get_timestamp ( )
  self . delegation_set = [ ]
  self . source_cache = None
  self . map_referrals_sent = 0
  if 90 - 90: o0oOOo0O0Ooo - Oo0Ooo / ooOoO0o / i1IIi - Ii1I
  if 43 - 43: i11iIiiIii - OoooooooOO % ooOoO0o
 def is_auth_prefix ( self ) :
  if ( len ( self . delegation_set ) != 0 ) : return ( False )
  if ( self . is_star_g ( ) ) : return ( False )
  return ( True )
  if 55 - 55: oO0o % Oo0Ooo % IiII
  if 65 - 65: IiII * IiII
 def is_ms_peer_entry ( self ) :
  if ( len ( self . delegation_set ) == 0 ) : return ( False )
  return ( self . delegation_set [ 0 ] . is_ms_peer ( ) )
  if 60 - 60: ooOoO0o
  if 92 - 92: O0 % IiII
 def print_referral_type ( self ) :
  if ( len ( self . delegation_set ) == 0 ) : return ( "unknown" )
  IiIiiI1iiiI = self . delegation_set [ 0 ]
  return ( IiIiiI1iiiI . print_node_type ( ) )
  if 48 - 48: OOooOOo - O0 % i1IIi * o0oOOo0O0Ooo - oO0o
  if 73 - 73: II111iiii
 def print_eid_tuple ( self ) :
  return ( lisp_print_eid_tuple ( self . eid , self . group ) )
  if 7 - 7: O0 / OoO0O00
  if 90 - 90: iII111i % oO0o / iIii1I11I1II1
 def add_cache ( self ) :
  if ( self . group . is_null ( ) ) :
   lisp_ddt_cache . add_cache ( self . eid , self )
  else :
   ooOoO = lisp_ddt_cache . lookup_cache ( self . group , True )
   if ( ooOoO == None ) :
    ooOoO = lisp_ddt_entry ( )
    ooOoO . eid . copy_address ( self . group )
    ooOoO . group . copy_address ( self . group )
    lisp_ddt_cache . add_cache ( self . group , ooOoO )
    if 2 - 2: I1IiiI - iIii1I11I1II1 / OoOoOO00 * O0 / i11iIiiIii * IiII
   if ( self . eid . is_null ( ) ) : self . eid . make_default_route ( ooOoO . group )
   ooOoO . add_source_entry ( self )
   if 80 - 80: oO0o + oO0o % I11i / OoO0O00
   if 11 - 11: ooOoO0o + OoO0O00 - I1ii11iIi11i . iII111i
   if 39 - 39: o0oOOo0O0Ooo % OoooooooOO - O0
 def add_source_entry ( self , source_ddt ) :
  if ( self . source_cache == None ) : self . source_cache = lisp_cache ( )
  self . source_cache . add_cache ( source_ddt . eid , source_ddt )
  if 87 - 87: I1IiiI * i1IIi * Oo0Ooo / I1ii11iIi11i - OoO0O00
  if 44 - 44: Oo0Ooo
 def lookup_source_cache ( self , source , exact ) :
  if ( self . source_cache == None ) : return ( None )
  return ( self . source_cache . lookup_cache ( source , exact ) )
  if 37 - 37: OOooOOo / Ii1I
  if 51 - 51: OOooOOo + O0
 def is_star_g ( self ) :
  if ( self . group . is_null ( ) ) : return ( False )
  return ( self . eid . is_exact_match ( self . group ) )
  if 91 - 91: i11iIiiIii + o0oOOo0O0Ooo % OoO0O00 / oO0o - i1IIi
  if 82 - 82: Ii1I . OoooooooOO + OoooooooOO % OoO0O00 % I1ii11iIi11i
  if 65 - 65: Oo0Ooo . I11i
class lisp_ddt_node ( ) :
 def __init__ ( self ) :
  self . delegate_address = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . public_key = ""
  self . map_server_peer = False
  self . map_server_child = False
  self . priority = 0
  self . weight = 0
  if 7 - 7: Oo0Ooo * II111iiii
  if 11 - 11: OoOoOO00 % OoooooooOO
 def print_node_type ( self ) :
  if ( self . is_ddt_child ( ) ) : return ( "ddt-child" )
  if ( self . is_ms_child ( ) ) : return ( "map-server-child" )
  if ( self . is_ms_peer ( ) ) : return ( "map-server-peer" )
  if 92 - 92: OoOoOO00 - iII111i * Ii1I - i1IIi
  if 87 - 87: Ii1I * I1Ii111 + iIii1I11I1II1 * o0oOOo0O0Ooo * iIii1I11I1II1 . I11i
 def is_ddt_child ( self ) :
  if ( self . map_server_child ) : return ( False )
  if ( self . map_server_peer ) : return ( False )
  return ( True )
  if 66 - 66: Ii1I / OoO0O00 . O0 . I11i % OoooooooOO / OOooOOo
  if 49 - 49: I1IiiI * iII111i - OoO0O00 % Ii1I + Ii1I * I1Ii111
 def is_ms_child ( self ) :
  return ( self . map_server_child )
  if 94 - 94: OoOoOO00 - I11i + Ii1I + OoOoOO00 + II111iiii
  if 61 - 61: IiII + Ii1I / oO0o . OoooooooOO + iII111i
 def is_ms_peer ( self ) :
  return ( self . map_server_peer )
  if 29 - 29: OOooOOo
  if 69 - 69: oO0o % OoooooooOO * iII111i
  if 58 - 58: oO0o / i11iIiiIii . OoOoOO00 % O0 / iIii1I11I1II1
  if 50 - 50: I1Ii111 . I11i / O0 . I11i
  if 91 - 91: i11iIiiIii . I1ii11iIi11i + I11i
  if 67 - 67: I1ii11iIi11i * I1Ii111 * I1IiiI / I11i - IiII + oO0o
  if 11 - 11: O0 + i1IIi / o0oOOo0O0Ooo * OoO0O00
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
  if 64 - 64: i1IIi % IiII . ooOoO0o . iIii1I11I1II1 + OoO0O00 - iIii1I11I1II1
  if 52 - 52: II111iiii - IiII
 def print_ddt_map_request ( self ) :
  lprint ( "Queued Map-Request from {}ITR {}->{}, nonce 0x{}" . format ( "P" if self . from_pitr else "" ,
  # OoOoOO00 * i11iIiiIii . OOooOOo % OOooOOo % Oo0Ooo . i11iIiiIii
 red ( self . itr . print_address ( ) , False ) ,
 green ( self . eid . print_address ( ) , False ) , self . nonce ) )
  if 31 - 31: I1IiiI % I1ii11iIi11i - i1IIi + IiII . OoO0O00
  if 66 - 66: OOooOOo * i1IIi / iII111i * Oo0Ooo * I11i
 def queue_map_request ( self ) :
  self . retransmit_timer = threading . Timer ( LISP_DDT_MAP_REQUEST_INTERVAL ,
 lisp_retransmit_ddt_map_request , [ self ] )
  self . retransmit_timer . start ( )
  lisp_ddt_map_requestQ [ str ( self . nonce ) ] = self
  if 84 - 84: I1Ii111 . O0
  if 4 - 4: iII111i
 def dequeue_map_request ( self ) :
  self . retransmit_timer . cancel ( )
  if ( lisp_ddt_map_requestQ . has_key ( str ( self . nonce ) ) ) :
   lisp_ddt_map_requestQ . pop ( str ( self . nonce ) )
   if 59 - 59: OoO0O00
   if 12 - 12: I1Ii111
   if 86 - 86: o0oOOo0O0Ooo . i1IIi * II111iiii % I1IiiI
 def print_eid_tuple ( self ) :
  return ( lisp_print_eid_tuple ( self . eid , self . group ) )
  if 89 - 89: OOooOOo / i1IIi - I11i * oO0o
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
LISP_DDT_ACTION_SITE_NOT_FOUND = - 2
LISP_DDT_ACTION_NULL = - 1
LISP_DDT_ACTION_NODE_REFERRAL = 0
LISP_DDT_ACTION_MS_REFERRAL = 1
LISP_DDT_ACTION_MS_ACK = 2
LISP_DDT_ACTION_MS_NOT_REG = 3
LISP_DDT_ACTION_DELEGATION_HOLE = 4
LISP_DDT_ACTION_NOT_AUTH = 5
LISP_DDT_ACTION_MAX = LISP_DDT_ACTION_NOT_AUTH
if 7 - 7: i11iIiiIii * I1ii11iIi11i / OoO0O00 * oO0o
lisp_map_referral_action_string = [
 "node-referral" , "ms-referral" , "ms-ack" , "ms-not-registered" ,
 "delegation-hole" , "not-authoritative" ]
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
  if 31 - 31: i11iIiiIii + iIii1I11I1II1 . II111iiii
  if 72 - 72: I1Ii111 * OoO0O00 + Oo0Ooo / Ii1I % OOooOOo
 def print_info ( self ) :
  if ( self . info_reply ) :
   oOOo = "Info-Reply"
   Oo0O0 = ( ", ms-port: {}, etr-port: {}, global-rloc: {}, " + "ms-rloc: {}, private-rloc: {}, RTR-list: " ) . format ( self . ms_port , self . etr_port ,
   # Ii1I
   # Ii1I - II111iiii / oO0o + Oo0Ooo . I1IiiI
 red ( self . global_etr_rloc . print_address_no_iid ( ) , False ) ,
 red ( self . global_ms_rloc . print_address_no_iid ( ) , False ) ,
 red ( self . private_etr_rloc . print_address_no_iid ( ) , False ) )
   if ( len ( self . rtr_list ) == 0 ) : Oo0O0 += "empty, "
   for OOoO0o0 in self . rtr_list :
    Oo0O0 += red ( OOoO0o0 . print_address_no_iid ( ) , False ) + ", "
    if 51 - 51: OoO0O00 . OoO0O00 - iIii1I11I1II1
   Oo0O0 = Oo0O0 [ 0 : - 2 ]
  else :
   oOOo = "Info-Request"
   IIiiIiiI1Ii1i = "<none>" if self . hostname == None else self . hostname
   Oo0O0 = ", hostname: {}" . format ( blue ( IIiiIiiI1Ii1i , False ) )
   if 14 - 14: Ii1I * Oo0Ooo / II111iiii . Oo0Ooo + OoOoOO00
  lprint ( "{} -> nonce: 0x{}{}" . format ( bold ( oOOo , False ) ,
 lisp_hex_string ( self . nonce ) , Oo0O0 ) )
  if 21 - 21: OOooOOo / O0
  if 46 - 46: OoooooooOO % Oo0Ooo % i1IIi / ooOoO0o - I11i
 def encode ( self ) :
  Iii11I1i = ( LISP_NAT_INFO << 28 )
  if ( self . info_reply ) : Iii11I1i |= ( 1 << 27 )
  if 21 - 21: i11iIiiIii / I1IiiI / I1ii11iIi11i - I1Ii111 - i1IIi * I1ii11iIi11i
  if 78 - 78: o0oOOo0O0Ooo . OoOoOO00
  if 61 - 61: i1IIi + Ii1I * OoooooooOO - ooOoO0o
  if 78 - 78: iIii1I11I1II1 * OoOoOO00 - I1IiiI . O0 / I1Ii111
  if 5 - 5: I1ii11iIi11i % OoOoOO00 . OoooooooOO . o0oOOo0O0Ooo + i11iIiiIii
  iIIi1 = struct . pack ( "I" , socket . htonl ( Iii11I1i ) )
  iIIi1 += struct . pack ( "Q" , self . nonce )
  iIIi1 += struct . pack ( "III" , 0 , 0 , 0 )
  if 54 - 54: ooOoO0o - O0 + iII111i
  if 34 - 34: Ii1I - OOooOOo % iII111i
  if 48 - 48: oO0o - O0
  if 17 - 17: iIii1I11I1II1 . IiII / ooOoO0o % I11i + o0oOOo0O0Ooo - iIii1I11I1II1
  if ( self . info_reply == False ) :
   if ( self . hostname == None ) :
    iIIi1 += struct . pack ( "H" , 0 )
   else :
    iIIi1 += struct . pack ( "H" , socket . htons ( LISP_AFI_NAME ) )
    iIIi1 += self . hostname + "\0"
    if 95 - 95: OoOoOO00 + OOooOOo - I11i * i1IIi + i1IIi * O0
   return ( iIIi1 )
   if 60 - 60: Oo0Ooo + I11i % iIii1I11I1II1 % oO0o - I1Ii111 / o0oOOo0O0Ooo
   if 9 - 9: IiII / oO0o % O0 * I1Ii111 - iIii1I11I1II1 % i1IIi
   if 83 - 83: OoOoOO00 + OOooOOo / OoooooooOO
   if 39 - 39: OoO0O00 % iII111i . oO0o . II111iiii - i11iIiiIii
   if 85 - 85: O0 - OoOoOO00
  ooo0O0O0oo0 = socket . htons ( LISP_AFI_LCAF )
  ii111I1IiiI1i = LISP_LCAF_NAT_TYPE
  I1iIiI1iiI = socket . htons ( 16 )
  iIii1 = socket . htons ( self . ms_port )
  OOO0 = socket . htons ( self . etr_port )
  iIIi1 += struct . pack ( "HHBBHHHH" , ooo0O0O0oo0 , 0 , ii111I1IiiI1i , 0 , I1iIiI1iiI ,
 iIii1 , OOO0 , socket . htons ( self . global_etr_rloc . afi ) )
  iIIi1 += self . global_etr_rloc . pack_address ( )
  iIIi1 += struct . pack ( "HH" , 0 , socket . htons ( self . private_etr_rloc . afi ) )
  iIIi1 += self . private_etr_rloc . pack_address ( )
  if ( len ( self . rtr_list ) == 0 ) : iIIi1 += struct . pack ( "H" , 0 )
  if 13 - 13: I11i / OoooooooOO - I1Ii111
  if 78 - 78: iII111i . oO0o . I1IiiI % O0 * ooOoO0o % I1Ii111
  if 26 - 26: OoooooooOO + iII111i * ooOoO0o
  if 71 - 71: OOooOOo . I1ii11iIi11i + II111iiii
  for OOoO0o0 in self . rtr_list :
   iIIi1 += struct . pack ( "H" , socket . htons ( OOoO0o0 . afi ) )
   iIIi1 += OOoO0o0 . pack_address ( )
   if 26 - 26: I1ii11iIi11i % O0 / Ii1I + i11iIiiIii - Ii1I
  return ( iIIi1 )
  if 48 - 48: I1IiiI - i11iIiiIii * I1ii11iIi11i
  if 70 - 70: I1ii11iIi11i * OoOoOO00
 def decode ( self , packet ) :
  II11iII = packet
  I1I = "I"
  ii1I1iIi = struct . calcsize ( I1I )
  if ( len ( packet ) < ii1I1iIi ) : return ( None )
  if 63 - 63: ooOoO0o . IiII - OoOoOO00 % IiII - I1Ii111 / I1Ii111
  Iii11I1i = struct . unpack ( I1I , packet [ : ii1I1iIi ] )
  Iii11I1i = Iii11I1i [ 0 ]
  packet = packet [ ii1I1iIi : : ]
  if 42 - 42: i1IIi . OoOoOO00 * OoOoOO00 * OoOoOO00
  I1I = "Q"
  ii1I1iIi = struct . calcsize ( I1I )
  if ( len ( packet ) < ii1I1iIi ) : return ( None )
  if 14 - 14: II111iiii / I1Ii111 . I1IiiI
  I11iIi1i1I1i1 = struct . unpack ( I1I , packet [ : ii1I1iIi ] )
  if 66 - 66: I1Ii111 % oO0o . iII111i * i1IIi
  Iii11I1i = socket . ntohl ( Iii11I1i )
  self . nonce = I11iIi1i1I1i1 [ 0 ]
  self . info_reply = Iii11I1i & 0x08000000
  self . hostname = None
  packet = packet [ ii1I1iIi : : ]
  if 81 - 81: OoooooooOO * I1IiiI / I1Ii111
  if 10 - 10: I1IiiI - II111iiii / IiII * II111iiii
  if 67 - 67: II111iiii . Ii1I % oO0o . Oo0Ooo + IiII
  if 10 - 10: OOooOOo - OoO0O00 * oO0o / iIii1I11I1II1 - OoOoOO00
  if 20 - 20: IiII % I1IiiI + iIii1I11I1II1 % iII111i
  I1I = "HH"
  ii1I1iIi = struct . calcsize ( I1I )
  if ( len ( packet ) < ii1I1iIi ) : return ( None )
  if 100 - 100: o0oOOo0O0Ooo - Oo0Ooo % I1Ii111 . i11iIiiIii % OoooooooOO
  if 39 - 39: I1ii11iIi11i / i11iIiiIii * i1IIi * Oo0Ooo
  if 39 - 39: OoO0O00 * OoooooooOO / i1IIi + Oo0Ooo
  if 57 - 57: O0
  if 83 - 83: OOooOOo / Ii1I * I1IiiI % oO0o / iIii1I11I1II1
  iIIi1OoOo0O00 , o00oOOO = struct . unpack ( I1I , packet [ : ii1I1iIi ] )
  if ( o00oOOO != 0 ) : return ( None )
  if 1 - 1: I11i / OoooooooOO / iII111i
  packet = packet [ ii1I1iIi : : ]
  I1I = "IBBH"
  ii1I1iIi = struct . calcsize ( I1I )
  if ( len ( packet ) < ii1I1iIi ) : return ( None )
  if 68 - 68: i1IIi / Oo0Ooo / I11i * Oo0Ooo
  O00O00Oo , iIiIii , oOOoOO , oooO0o0O000O0000oO = struct . unpack ( I1I ,
 packet [ : ii1I1iIi ] )
  if 91 - 91: I1IiiI + O0 / OoO0O00 * OoOoOO00 . o0oOOo0O0Ooo % i11iIiiIii
  if ( oooO0o0O000O0000oO != 0 ) : return ( None )
  packet = packet [ ii1I1iIi : : ]
  if 77 - 77: iIii1I11I1II1 + OoOoOO00 - ooOoO0o * oO0o % OoO0O00
  if 38 - 38: I1ii11iIi11i + II111iiii - I11i . IiII + IiII - IiII
  if 44 - 44: iII111i
  if 63 - 63: ooOoO0o . o0oOOo0O0Ooo / ooOoO0o % OoO0O00 * OoOoOO00 + Oo0Ooo
  if ( self . info_reply == False ) :
   I1I = "H"
   ii1I1iIi = struct . calcsize ( I1I )
   if ( len ( packet ) >= ii1I1iIi ) :
    ooo0O0O0oo0 = struct . unpack ( I1I , packet [ : ii1I1iIi ] ) [ 0 ]
    if ( socket . ntohs ( ooo0O0O0oo0 ) == LISP_AFI_NAME ) :
     packet = packet [ ii1I1iIi : : ]
     packet , self . hostname = lisp_decode_dist_name ( packet )
     if 44 - 44: O0 - I11i
     if 43 - 43: O0
   return ( II11iII )
   if 50 - 50: I11i - OoooooooOO
   if 29 - 29: oO0o * oO0o
   if 44 - 44: ooOoO0o . I1IiiI * oO0o * Ii1I
   if 41 - 41: i1IIi % i11iIiiIii + I11i % OoooooooOO / I1ii11iIi11i
   if 8 - 8: OoooooooOO - OoO0O00 / i11iIiiIii / O0 . IiII
  I1I = "HHBBHHH"
  ii1I1iIi = struct . calcsize ( I1I )
  if ( len ( packet ) < ii1I1iIi ) : return ( None )
  if 86 - 86: ooOoO0o * OoooooooOO + iII111i + o0oOOo0O0Ooo
  ooo0O0O0oo0 , oO0IiiI1i1i11I1 , ii111I1IiiI1i , iIiIii , I1iIiI1iiI , iIii1 , OOO0 = struct . unpack ( I1I , packet [ : ii1I1iIi ] )
  if 79 - 79: i1IIi % I1ii11iIi11i - OoO0O00 % I1ii11iIi11i
  if 6 - 6: Oo0Ooo / iII111i . i11iIiiIii
  if ( socket . ntohs ( ooo0O0O0oo0 ) != LISP_AFI_LCAF ) : return ( None )
  if 8 - 8: I1ii11iIi11i + O0 - oO0o % II111iiii . I1Ii111
  self . ms_port = socket . ntohs ( iIii1 )
  self . etr_port = socket . ntohs ( OOO0 )
  packet = packet [ ii1I1iIi : : ]
  if 86 - 86: IiII
  if 71 - 71: Ii1I - i1IIi . I1IiiI
  if 15 - 15: i1IIi % II111iiii / II111iiii - I1ii11iIi11i - I11i % i1IIi
  if 54 - 54: i1IIi . OoO0O00 + iII111i + OoO0O00 * i1IIi
  I1I = "H"
  ii1I1iIi = struct . calcsize ( I1I )
  if ( len ( packet ) < ii1I1iIi ) : return ( None )
  if 13 - 13: Oo0Ooo / OoO0O00 + OOooOOo
  if 90 - 90: OoO0O00 * i11iIiiIii / oO0o
  if 91 - 91: iII111i - OoOoOO00 / Oo0Ooo % II111iiii / II111iiii / o0oOOo0O0Ooo
  if 34 - 34: OoO0O00 * II111iiii + i11iIiiIii % Ii1I
  ooo0O0O0oo0 = struct . unpack ( I1I , packet [ : ii1I1iIi ] ) [ 0 ]
  packet = packet [ ii1I1iIi : : ]
  if ( ooo0O0O0oo0 != 0 ) :
   self . global_etr_rloc . afi = socket . ntohs ( ooo0O0O0oo0 )
   packet = self . global_etr_rloc . unpack_address ( packet )
   if ( packet == None ) : return ( None )
   self . global_etr_rloc . mask_len = self . global_etr_rloc . host_mask_len ( )
   if 25 - 25: OoOoOO00 + IiII . i11iIiiIii
   if 87 - 87: I1IiiI + OoooooooOO + O0
   if 32 - 32: Ii1I / I1ii11iIi11i . Ii1I
   if 65 - 65: IiII
   if 74 - 74: Oo0Ooo + i1IIi - II111iiii / ooOoO0o / iII111i
   if 66 - 66: ooOoO0o / IiII * iIii1I11I1II1
  if ( len ( packet ) < ii1I1iIi ) : return ( II11iII )
  if 42 - 42: I1Ii111 - i11iIiiIii % II111iiii * ooOoO0o . O0 % I11i
  ooo0O0O0oo0 = struct . unpack ( I1I , packet [ : ii1I1iIi ] ) [ 0 ]
  packet = packet [ ii1I1iIi : : ]
  if ( ooo0O0O0oo0 != 0 ) :
   self . global_ms_rloc . afi = socket . ntohs ( ooo0O0O0oo0 )
   packet = self . global_ms_rloc . unpack_address ( packet )
   if ( packet == None ) : return ( II11iII )
   self . global_ms_rloc . mask_len = self . global_ms_rloc . host_mask_len ( )
   if 82 - 82: Oo0Ooo % O0 + I1ii11iIi11i % I1ii11iIi11i
   if 74 - 74: O0 * IiII . I11i - I1Ii111 + O0 + I11i
   if 48 - 48: oO0o . o0oOOo0O0Ooo - OOooOOo
   if 29 - 29: Oo0Ooo - Ii1I - Oo0Ooo
   if 89 - 89: Oo0Ooo . OoO0O00 . I1ii11iIi11i * oO0o . O0
  if ( len ( packet ) < ii1I1iIi ) : return ( II11iII )
  if 72 - 72: i11iIiiIii % I11i / I1Ii111 + I1IiiI * iII111i
  ooo0O0O0oo0 = struct . unpack ( I1I , packet [ : ii1I1iIi ] ) [ 0 ]
  packet = packet [ ii1I1iIi : : ]
  if ( ooo0O0O0oo0 != 0 ) :
   self . private_etr_rloc . afi = socket . ntohs ( ooo0O0O0oo0 )
   packet = self . private_etr_rloc . unpack_address ( packet )
   if ( packet == None ) : return ( II11iII )
   self . private_etr_rloc . mask_len = self . private_etr_rloc . host_mask_len ( )
   if 69 - 69: I1Ii111 + O0 . IiII . o0oOOo0O0Ooo
   if 38 - 38: IiII / i1IIi
   if 60 - 60: OoOoOO00
   if 75 - 75: II111iiii / iIii1I11I1II1 / OoooooooOO
   if 61 - 61: IiII . IiII
   if 17 - 17: OoOoOO00 % Oo0Ooo / I1Ii111 . Ii1I % OoO0O00
  while ( len ( packet ) >= ii1I1iIi ) :
   ooo0O0O0oo0 = struct . unpack ( I1I , packet [ : ii1I1iIi ] ) [ 0 ]
   packet = packet [ ii1I1iIi : : ]
   if ( ooo0O0O0oo0 == 0 ) : continue
   OOoO0o0 = lisp_address ( socket . ntohs ( ooo0O0O0oo0 ) , "" , 0 , 0 )
   packet = OOoO0o0 . unpack_address ( packet )
   if ( packet == None ) : return ( II11iII )
   OOoO0o0 . mask_len = OOoO0o0 . host_mask_len ( )
   self . rtr_list . append ( OOoO0o0 )
   if 32 - 32: I1IiiI + ooOoO0o / O0 * i11iIiiIii % Oo0Ooo + II111iiii
  return ( II11iII )
  if 95 - 95: iII111i / ooOoO0o + I1Ii111
  if 78 - 78: iIii1I11I1II1 / I1IiiI - IiII
  if 81 - 81: I1ii11iIi11i
class lisp_nat_info ( ) :
 def __init__ ( self , addr_str , hostname , port ) :
  self . address = addr_str
  self . hostname = hostname
  self . port = port
  self . uptime = lisp_get_timestamp ( )
  if 31 - 31: O0 % ooOoO0o / I1IiiI * iII111i % iIii1I11I1II1 * OoOoOO00
  if 76 - 76: I1Ii111 - O0
 def timed_out ( self ) :
  Oo = time . time ( ) - self . uptime
  return ( Oo >= ( LISP_INFO_INTERVAL * 2 ) )
  if 23 - 23: O0 * Ii1I * ooOoO0o % ooOoO0o
  if 7 - 7: II111iiii + I11i
  if 99 - 99: iIii1I11I1II1 * oO0o
class lisp_info_source ( ) :
 def __init__ ( self , hostname , addr_str , port ) :
  self . address = lisp_address ( LISP_AFI_IPV4 , addr_str , 32 , 0 )
  self . port = port
  self . uptime = lisp_get_timestamp ( )
  self . nonce = None
  self . hostname = hostname
  self . no_timeout = False
  if 37 - 37: ooOoO0o * iII111i * I11i
  if 11 - 11: I1IiiI
 def cache_address_for_info_source ( self ) :
  o0000oO = self . address . print_address_no_iid ( ) + self . hostname
  lisp_info_sources_by_address [ o0000oO ] = self
  if 48 - 48: O0 . I11i
  if 9 - 9: oO0o / Oo0Ooo
 def cache_nonce_for_info_source ( self , nonce ) :
  self . nonce = nonce
  lisp_info_sources_by_nonce [ nonce ] = self
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
def lisp_concat_auth_data ( alg_id , auth1 , auth2 , auth3 , auth4 ) :
 if 30 - 30: i11iIiiIii % OOooOOo
 if ( lisp_is_x86 ( ) ) :
  if ( auth1 != "" ) : auth1 = byte_swap_64 ( auth1 )
  if ( auth2 != "" ) : auth2 = byte_swap_64 ( auth2 )
  if ( auth3 != "" ) :
   if ( alg_id == LISP_SHA_1_96_ALG_ID ) : auth3 = socket . ntohl ( auth3 )
   else : auth3 = byte_swap_64 ( auth3 )
   if 52 - 52: I11i - oO0o . i11iIiiIii - II111iiii + Ii1I . iII111i
  if ( auth4 != "" ) : auth4 = byte_swap_64 ( auth4 )
  if 27 - 27: I1IiiI + OoOoOO00 + iII111i
  if 70 - 70: I11i + IiII . ooOoO0o - I1ii11iIi11i
 if ( alg_id == LISP_SHA_1_96_ALG_ID ) :
  auth1 = lisp_hex_string ( auth1 )
  auth1 = auth1 . zfill ( 16 )
  auth2 = lisp_hex_string ( auth2 )
  auth2 = auth2 . zfill ( 16 )
  auth3 = lisp_hex_string ( auth3 )
  auth3 = auth3 . zfill ( 8 )
  oOiIiii1III = auth1 + auth2 + auth3
  if 34 - 34: i1IIi % Oo0Ooo . oO0o
 if ( alg_id == LISP_SHA_256_128_ALG_ID ) :
  auth1 = lisp_hex_string ( auth1 )
  auth1 = auth1 . zfill ( 16 )
  auth2 = lisp_hex_string ( auth2 )
  auth2 = auth2 . zfill ( 16 )
  auth3 = lisp_hex_string ( auth3 )
  auth3 = auth3 . zfill ( 16 )
  auth4 = lisp_hex_string ( auth4 )
  auth4 = auth4 . zfill ( 16 )
  oOiIiii1III = auth1 + auth2 + auth3 + auth4
  if 36 - 36: I1ii11iIi11i / I1Ii111 - IiII + OOooOOo + I1Ii111
 return ( oOiIiii1III )
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
def lisp_open_listen_socket ( local_addr , port ) :
 if ( port . isdigit ( ) ) :
  if ( local_addr . find ( "." ) != - 1 ) :
   iIiiiIIi = socket . socket ( socket . AF_INET , socket . SOCK_DGRAM )
   if 36 - 36: I1IiiI * I1IiiI
  if ( local_addr . find ( ":" ) != - 1 ) :
   if ( lisp_is_raspbian ( ) ) : return ( None )
   iIiiiIIi = socket . socket ( socket . AF_INET6 , socket . SOCK_DGRAM )
   if 79 - 79: I1Ii111 - I11i
  iIiiiIIi . bind ( ( local_addr , int ( port ) ) )
 else :
  oo00 = port
  if ( os . path . exists ( oo00 ) ) :
   os . system ( "rm " + oo00 )
   time . sleep ( 1 )
   if 49 - 49: II111iiii + O0 * ooOoO0o - Oo0Ooo
  iIiiiIIi = socket . socket ( socket . AF_UNIX , socket . SOCK_DGRAM )
  iIiiiIIi . bind ( oo00 )
  if 89 - 89: I1IiiI + I11i . oO0o . II111iiii + oO0o / Oo0Ooo
 return ( iIiiiIIi )
 if 32 - 32: OoO0O00 % oO0o * I1ii11iIi11i + I11i / I1Ii111
 if 5 - 5: o0oOOo0O0Ooo + iII111i / OoooooooOO + Ii1I . OoOoOO00 / oO0o
 if 18 - 18: II111iiii . o0oOOo0O0Ooo
 if 75 - 75: OoooooooOO - Oo0Ooo
 if 56 - 56: II111iiii - i11iIiiIii - oO0o . o0oOOo0O0Ooo
 if 4 - 4: i1IIi
 if 91 - 91: IiII . OoO0O00 * Ii1I / o0oOOo0O0Ooo
def lisp_open_send_socket ( internal_name , afi ) :
 if ( internal_name == "" ) :
  if ( afi == LISP_AFI_IPV4 ) :
   iIiiiIIi = socket . socket ( socket . AF_INET , socket . SOCK_DGRAM )
   if 41 - 41: I1IiiI . OoO0O00 / i1IIi . Oo0Ooo . oO0o
  if ( afi == LISP_AFI_IPV6 ) :
   if ( lisp_is_raspbian ( ) ) : return ( None )
   iIiiiIIi = socket . socket ( socket . AF_INET6 , socket . SOCK_DGRAM )
   if 44 - 44: iII111i * I11i + i11iIiiIii + i1IIi / IiII * II111iiii
 else :
  if ( os . path . exists ( internal_name ) ) : os . system ( "rm " + internal_name )
  iIiiiIIi = socket . socket ( socket . AF_UNIX , socket . SOCK_DGRAM )
  iIiiiIIi . bind ( internal_name )
  if 58 - 58: OOooOOo
 return ( iIiiiIIi )
 if 72 - 72: OoO0O00 + OOooOOo - Oo0Ooo % ooOoO0o . IiII
 if 95 - 95: iII111i % OOooOOo - IiII - OoOoOO00 % o0oOOo0O0Ooo * O0
 if 16 - 16: I1Ii111 / Oo0Ooo
 if 48 - 48: Oo0Ooo / oO0o + iII111i % iII111i
 if 9 - 9: I1ii11iIi11i - o0oOOo0O0Ooo . Oo0Ooo + I1ii11iIi11i . OOooOOo
 if 30 - 30: OoooooooOO - iIii1I11I1II1 / oO0o * Ii1I / Ii1I
 if 52 - 52: OoOoOO00 - OoO0O00 + I1IiiI + IiII
def lisp_close_socket ( sock , internal_name ) :
 sock . close ( )
 if ( os . path . exists ( internal_name ) ) : os . system ( "rm " + internal_name )
 return
 if 49 - 49: oO0o / I11i - oO0o
 if 31 - 31: OoOoOO00 + I1IiiI + I1ii11iIi11i + I11i * II111iiii % oO0o
 if 90 - 90: OOooOOo * iIii1I11I1II1 / i1IIi
 if 60 - 60: OOooOOo * I1Ii111 . oO0o
 if 47 - 47: oO0o % OOooOOo / OOooOOo % OoOoOO00 % I1Ii111 / OoOoOO00
 if 51 - 51: I1IiiI . I11i - OoOoOO00
 if 10 - 10: Oo0Ooo * OOooOOo / IiII . o0oOOo0O0Ooo
 if 97 - 97: Ii1I . Ii1I % iII111i
def lisp_is_running ( node ) :
 return ( True if ( os . path . exists ( node ) ) else False )
 if 49 - 49: Oo0Ooo % OOooOOo - OoooooooOO + IiII
 if 54 - 54: iIii1I11I1II1 - OoooooooOO / I11i / oO0o % I1IiiI + OoOoOO00
 if 26 - 26: OoO0O00 * II111iiii % OOooOOo * iII111i + iII111i
 if 25 - 25: I11i - I1ii11iIi11i
 if 100 - 100: I1Ii111 / Ii1I + OoOoOO00 . OoooooooOO
 if 83 - 83: O0
 if 35 - 35: i11iIiiIii - I11i . OoOoOO00 * II111iiii % i11iIiiIii
 if 55 - 55: o0oOOo0O0Ooo / O0 / OoooooooOO * Oo0Ooo % iII111i
 if 24 - 24: I1ii11iIi11i % OOooOOo + OoooooooOO + OoO0O00
def lisp_packet_ipc ( packet , source , sport ) :
 return ( ( "packet@" + str ( len ( packet ) ) + "@" + source + "@" + str ( sport ) + "@" + packet ) )
 if 100 - 100: Oo0Ooo % OoO0O00 - OoOoOO00
 if 46 - 46: o0oOOo0O0Ooo
 if 28 - 28: i1IIi
 if 81 - 81: oO0o % OoooooooOO . I1Ii111 - OoOoOO00 / I1IiiI
 if 62 - 62: I1Ii111 * I11i / I11i
 if 42 - 42: ooOoO0o * ooOoO0o / Ii1I / OOooOOo * OOooOOo
 if 92 - 92: Oo0Ooo / iII111i - OoooooooOO - o0oOOo0O0Ooo % ooOoO0o
 if 35 - 35: i1IIi % iII111i % I11i * iIii1I11I1II1 % Ii1I - Oo0Ooo
 if 94 - 94: iII111i
def lisp_control_packet_ipc ( packet , source , dest , dport ) :
 return ( "control-packet@" + dest + "@" + str ( dport ) + "@" + packet )
 if 68 - 68: OoooooooOO % OOooOOo / OoooooooOO / I1Ii111 + Ii1I - o0oOOo0O0Ooo
 if 81 - 81: I1IiiI
 if 62 - 62: Ii1I * OoOoOO00
 if 27 - 27: Oo0Ooo + Oo0Ooo / II111iiii % I1Ii111
 if 11 - 11: Ii1I
 if 54 - 54: I1IiiI * I1Ii111 / ooOoO0o / iIii1I11I1II1 % iII111i / oO0o
 if 11 - 11: ooOoO0o + I1IiiI + Ii1I . II111iiii
def lisp_data_packet_ipc ( packet , source ) :
 return ( "data-packet@" + str ( len ( packet ) ) + "@" + source + "@@" + packet )
 if 50 - 50: Oo0Ooo
 if 14 - 14: O0
 if 67 - 67: II111iiii / O0
 if 10 - 10: i1IIi / Oo0Ooo
 if 20 - 20: Oo0Ooo * I1Ii111 / I1ii11iIi11i . ooOoO0o
 if 67 - 67: o0oOOo0O0Ooo . Oo0Ooo % I11i
 if 38 - 38: OOooOOo - OoO0O00 . ooOoO0o
 if 50 - 50: o0oOOo0O0Ooo
 if 85 - 85: II111iiii . iII111i - i1IIi
def lisp_command_ipc ( packet , source ) :
 return ( "command@" + str ( len ( packet ) ) + "@" + source + "@@" + packet )
 if 23 - 23: iII111i . Ii1I - OoO0O00 / I1ii11iIi11i / O0
 if 4 - 4: i1IIi % Oo0Ooo % Ii1I * ooOoO0o - I11i
 if 76 - 76: iIii1I11I1II1 / ooOoO0o % I1ii11iIi11i % OOooOOo
 if 13 - 13: IiII
 if 56 - 56: Oo0Ooo
 if 55 - 55: i11iIiiIii + iIii1I11I1II1 / i1IIi / I1ii11iIi11i
 if 64 - 64: IiII . OoO0O00 * i11iIiiIii
 if 18 - 18: Ii1I % o0oOOo0O0Ooo - Oo0Ooo
 if 28 - 28: IiII
def lisp_api_ipc ( source , data ) :
 return ( "api@" + str ( len ( data ) ) + "@" + source + "@@" + data )
 if 93 - 93: Oo0Ooo % i1IIi
 if 51 - 51: oO0o % O0
 if 41 - 41: I1IiiI * I1IiiI . I1Ii111
 if 38 - 38: I1IiiI % i11iIiiIii
 if 17 - 17: i11iIiiIii
 if 81 - 81: I1Ii111
 if 25 - 25: I1IiiI
 if 52 - 52: I1ii11iIi11i % i1IIi . IiII % OoOoOO00
 if 50 - 50: OOooOOo * I1IiiI / o0oOOo0O0Ooo
def lisp_ipc ( packet , send_socket , node ) :
 if 91 - 91: iIii1I11I1II1 / OOooOOo * O0 . o0oOOo0O0Ooo + oO0o / I1ii11iIi11i
 if 33 - 33: II111iiii + Ii1I
 if 46 - 46: IiII + O0 + i1IIi + ooOoO0o / iII111i
 if 94 - 94: oO0o + iII111i * OoOoOO00 - i1IIi / OoooooooOO
 if ( lisp_is_running ( node ) == False ) :
  lprint ( "Suppress sending IPC to {}" . format ( node ) )
  return
  if 59 - 59: I11i % Ii1I / OoOoOO00
  if 99 - 99: Ii1I + II111iiii / i11iIiiIii - IiII / iII111i + iII111i
 O00ooO = 1500 if ( packet . find ( "control-packet" ) == - 1 ) else 9000
 if 85 - 85: I1ii11iIi11i + iII111i * iIii1I11I1II1 + OoOoOO00 . OoOoOO00 * I1IiiI
 O00OO = 0
 Oooo = len ( packet )
 iIII1iIIiI = 0
 OOOo0OOO0OO = .001
 while ( Oooo > 0 ) :
  O0OooOOo0OOOO = min ( Oooo , O00ooO )
  II1i = packet [ O00OO : O0OooOOo0OOOO + O00OO ]
  if 23 - 23: I11i / OoO0O00 % OOooOOo
  try :
   send_socket . sendto ( II1i , node )
   lprint ( "Send IPC {}-out-of-{} byte to {} succeeded" . format ( len ( II1i ) , len ( packet ) , node ) )
   if 9 - 9: ooOoO0o % I1ii11iIi11i . OoooooooOO + OoO0O00 % OOooOOo * OoooooooOO
   iIII1iIIiI = 0
   OOOo0OOO0OO = .001
   if 21 - 21: Ii1I % O0
  except socket . error , O0O0o0o0o :
   if ( iIII1iIIiI == 12 ) :
    lprint ( "Giving up on {}, consider it down" . format ( node ) )
    break
    if 15 - 15: II111iiii * Ii1I + IiII % iII111i
    if 96 - 96: II111iiii * I1Ii111 / Oo0Ooo
   lprint ( "Send IPC {}-out-of-{} byte to {} failed: {}" . format ( len ( II1i ) , len ( packet ) , node , O0O0o0o0o ) )
   if 35 - 35: I1IiiI
   if 54 - 54: I1ii11iIi11i % o0oOOo0O0Ooo . i1IIi
   iIII1iIIiI += 1
   time . sleep ( OOOo0OOO0OO )
   if 72 - 72: Ii1I
   lprint ( "Retrying after {} ms ..." . format ( OOOo0OOO0OO * 1000 ) )
   OOOo0OOO0OO *= 2
   continue
   if 87 - 87: iII111i - I1IiiI
   if 54 - 54: iIii1I11I1II1 + oO0o * o0oOOo0O0Ooo % OoooooooOO . Oo0Ooo
  O00OO += O0OooOOo0OOOO
  Oooo -= O0OooOOo0OOOO
  if 32 - 32: iII111i
 return
 if 33 - 33: ooOoO0o + Oo0Ooo * OoOoOO00 % ooOoO0o * oO0o - OoO0O00
 if 40 - 40: I11i . OoooooooOO * O0 / I1Ii111 + O0
 if 97 - 97: ooOoO0o - ooOoO0o * OOooOOo % OoOoOO00 - OoOoOO00 - I1Ii111
 if 52 - 52: O0 % iII111i
 if 81 - 81: OoooooooOO % OoOoOO00 % Oo0Ooo - I1IiiI
 if 43 - 43: o0oOOo0O0Ooo % o0oOOo0O0Ooo
 if 48 - 48: O0
def lisp_format_packet ( packet ) :
 packet = binascii . hexlify ( packet )
 O00OO = 0
 oO0OO00000o = ""
 Oooo = len ( packet ) * 2
 while ( O00OO < Oooo ) :
  oO0OO00000o += packet [ O00OO : O00OO + 8 ] + " "
  O00OO += 8
  Oooo -= 4
  if 5 - 5: OOooOOo / i11iIiiIii . I11i % OOooOOo
 return ( oO0OO00000o )
 if 1 - 1: II111iiii + O0 * OoOoOO00 / IiII . O0
 if 87 - 87: IiII + I1IiiI
 if 74 - 74: OoO0O00 + OoO0O00 % iII111i / I11i / O0
 if 54 - 54: o0oOOo0O0Ooo / OoooooooOO * ooOoO0o . OoOoOO00 - I1Ii111
 if 69 - 69: oO0o - OoO0O00
 if 80 - 80: ooOoO0o + iIii1I11I1II1 . II111iiii + I1IiiI - oO0o % OoOoOO00
 if 10 - 10: iIii1I11I1II1
def lisp_send ( lisp_sockets , dest , port , packet ) :
 IIiIIIi1i1Ii = lisp_sockets [ 0 ] if dest . is_ipv4 ( ) else lisp_sockets [ 1 ]
 if 71 - 71: i11iIiiIii + oO0o / OoOoOO00 / OoooooooOO + I1IiiI * ooOoO0o
 if 64 - 64: iIii1I11I1II1 / i1IIi + oO0o
 if 45 - 45: i11iIiiIii . Ii1I
 if 34 - 34: IiII / ooOoO0o * II111iiii * iII111i % OoooooooOO - iIii1I11I1II1
 if 61 - 61: OOooOOo - OOooOOo / ooOoO0o * I1Ii111
 if 73 - 73: OoO0O00 * Ii1I
 if 49 - 49: OoooooooOO / oO0o / I1IiiI + o0oOOo0O0Ooo * ooOoO0o . Oo0Ooo
 if 48 - 48: I11i + IiII / IiII
 if 65 - 65: I1ii11iIi11i - i1IIi % oO0o * iIii1I11I1II1 - IiII + ooOoO0o
 if 63 - 63: i11iIiiIii - OOooOOo . OoOoOO00 + IiII . OoO0O00
 if 70 - 70: iIii1I11I1II1 % OoooooooOO / OoO0O00 . O0 - I11i % II111iiii
 if 84 - 84: OOooOOo * i1IIi . iIii1I11I1II1 * iII111i + I1Ii111 + II111iiii
 I1Ii11i = dest . print_address_no_iid ( )
 if ( I1Ii11i . find ( "::ffff:" ) != - 1 and I1Ii11i . count ( "." ) == 3 ) :
  if ( lisp_i_am_rtr ) : IIiIIIi1i1Ii = lisp_sockets [ 0 ]
  if ( IIiIIIi1i1Ii == None ) :
   IIiIIIi1i1Ii = lisp_sockets [ 0 ]
   I1Ii11i = I1Ii11i . split ( "::ffff:" ) [ - 1 ]
   if 97 - 97: Ii1I - IiII
   if 64 - 64: oO0o . ooOoO0o / ooOoO0o - II111iiii
   if 81 - 81: I1ii11iIi11i
 lprint ( "{} {} bytes {} {}, packet: {}" . format ( bold ( "Send" , False ) ,
 len ( packet ) , bold ( "to " + I1Ii11i , False ) , port ,
 lisp_format_packet ( packet ) ) )
 if 64 - 64: oO0o * OoO0O00 / OOooOOo + Ii1I % Oo0Ooo . IiII
 if 2 - 2: I1Ii111 + I11i
 if 47 - 47: i11iIiiIii + iIii1I11I1II1 % I1ii11iIi11i - oO0o % OoO0O00
 if 85 - 85: oO0o * OoOoOO00 / OoOoOO00
 OOo0o = ( LISP_RLOC_PROBE_TTL == 255 )
 if ( OOo0o ) :
  ii1iI11 = struct . unpack ( "B" , packet [ 0 ] ) [ 0 ]
  OOo0o = ( ii1iI11 in [ 0x12 , 0x28 ] )
  if ( OOo0o ) : lisp_set_ttl ( IIiIIIi1i1Ii , LISP_RLOC_PROBE_TTL )
  if 27 - 27: I1IiiI - I1ii11iIi11i / II111iiii - IiII
  if 74 - 74: Ii1I * OoooooooOO % OOooOOo + OoooooooOO + iII111i
 try : IIiIIIi1i1Ii . sendto ( packet , ( I1Ii11i , port ) )
 except socket . error , O0O0o0o0o :
  lprint ( "socket.sendto() failed: {}" . format ( O0O0o0o0o ) )
  if 83 - 83: i1IIi
  if 2 - 2: i1IIi / OOooOOo * O0
  if 99 - 99: OoooooooOO . OoOoOO00 / II111iiii
  if 64 - 64: iII111i / i1IIi . I1IiiI + O0
  if 5 - 5: O0 . i11iIiiIii
 if ( OOo0o ) : lisp_set_ttl ( IIiIIIi1i1Ii , 64 )
 return
 if 71 - 71: o0oOOo0O0Ooo + iII111i + ooOoO0o
 if 27 - 27: OoooooooOO . iII111i * I1Ii111 % O0 + OoooooooOO - iII111i
 if 86 - 86: i1IIi
 if 81 - 81: OoOoOO00
 if 52 - 52: iII111i * IiII % I1IiiI * I11i
 if 73 - 73: I1Ii111 * ooOoO0o
 if 62 - 62: OOooOOo . I1IiiI * iIii1I11I1II1 + OoO0O00 * ooOoO0o / oO0o
 if 14 - 14: iII111i / OoO0O00
def lisp_receive_segments ( lisp_socket , packet , source , total_length ) :
 if 75 - 75: IiII
 if 68 - 68: IiII - i1IIi % IiII . OoO0O00 . i11iIiiIii . OoooooooOO
 if 32 - 32: iII111i + OoO0O00 % IiII + I1IiiI
 if 69 - 69: I1Ii111 + I11i - iIii1I11I1II1 - II111iiii . Ii1I
 if 74 - 74: I1ii11iIi11i % o0oOOo0O0Ooo + O0 - i11iIiiIii - IiII % OOooOOo
 O0OooOOo0OOOO = total_length - len ( packet )
 if ( O0OooOOo0OOOO == 0 ) : return ( [ True , packet ] )
 if 39 - 39: OoO0O00 - o0oOOo0O0Ooo
 lprint ( "Received {}-out-of-{} byte segment from {}" . format ( len ( packet ) ,
 total_length , source ) )
 if 71 - 71: iII111i . OoO0O00 + ooOoO0o - OOooOOo - Oo0Ooo
 if 100 - 100: OoooooooOO - o0oOOo0O0Ooo + I1Ii111 . OoooooooOO % i11iIiiIii
 if 64 - 64: I1Ii111 % OoooooooOO / i1IIi / OoO0O00
 if 2 - 2: I11i % o0oOOo0O0Ooo . OoO0O00 . OoO0O00
 if 89 - 89: ooOoO0o - oO0o + II111iiii + OoO0O00 - IiII
 Oooo = O0OooOOo0OOOO
 while ( Oooo > 0 ) :
  try : II1i = lisp_socket . recvfrom ( 9000 )
  except : return ( [ False , None ] )
  if 27 - 27: I1Ii111 - o0oOOo0O0Ooo + OoO0O00
  II1i = II1i [ 0 ]
  if 38 - 38: OoOoOO00 + OoO0O00 . i11iIiiIii + Ii1I % i1IIi % I1IiiI
  if 93 - 93: i11iIiiIii
  if 63 - 63: iIii1I11I1II1 - iIii1I11I1II1 % o0oOOo0O0Ooo
  if 97 - 97: i1IIi % I11i % OoOoOO00
  if 25 - 25: OoOoOO00 . iIii1I11I1II1 - iII111i % II111iiii . OoOoOO00
  if ( II1i . find ( "packet@" ) == 0 ) :
   IIiIiiIIi = II1i . split ( "@" )
   lprint ( "Received new message ({}-out-of-{}) while receiving " + "fragments, old message discarded" , len ( II1i ) ,
   # OOooOOo % I1ii11iIi11i - iII111i / OoOoOO00 + OoOoOO00 - I1IiiI
 IIiIiiIIi [ 1 ] if len ( IIiIiiIIi ) > 2 else "?" )
   return ( [ False , II1i ] )
   if 10 - 10: Ii1I / II111iiii
   if 53 - 53: i11iIiiIii . i1IIi . I1IiiI . ooOoO0o * OoOoOO00
  Oooo -= len ( II1i )
  packet += II1i
  if 98 - 98: I1ii11iIi11i + ooOoO0o
  lprint ( "Received {}-out-of-{} byte segment from {}" . format ( len ( II1i ) , total_length , source ) )
  if 42 - 42: Oo0Ooo + OoOoOO00 - O0 / Oo0Ooo - OoooooooOO . Ii1I
  if 64 - 64: OoooooooOO
 return ( [ True , packet ] )
 if 25 - 25: IiII
 if 29 - 29: OoOoOO00 % ooOoO0o * OoooooooOO
 if 8 - 8: i11iIiiIii - I1Ii111 / IiII
 if 17 - 17: i11iIiiIii * OoO0O00 . o0oOOo0O0Ooo . OoooooooOO . OoOoOO00 - I1ii11iIi11i
 if 78 - 78: I1ii11iIi11i - OoooooooOO + O0
 if 15 - 15: I1ii11iIi11i / IiII % I1IiiI
 if 16 - 16: Ii1I
 if 26 - 26: o0oOOo0O0Ooo / I11i + OoOoOO00 / OoOoOO00
def lisp_bit_stuff ( payload ) :
 lprint ( "Bit-stuffing, found {} segments" . format ( len ( payload ) ) )
 iIIi1 = ""
 for II1i in payload : iIIi1 += II1i + "\x40"
 return ( iIIi1 [ : - 1 ] )
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
 if 7 - 7: OoOoOO00 . i1IIi * i11iIiiIii % i11iIiiIii
 if 54 - 54: OoO0O00 / I1IiiI . Oo0Ooo
 if 39 - 39: OoO0O00 . ooOoO0o
 if 41 - 41: Oo0Ooo * I1ii11iIi11i - II111iiii - II111iiii
 if 7 - 7: oO0o
 if 41 - 41: ooOoO0o
 if 93 - 93: Ii1I + I1Ii111 + Ii1I
def lisp_receive ( lisp_socket , internal ) :
 while ( True ) :
  if 23 - 23: I1IiiI - i1IIi / ooOoO0o
  if 4 - 4: IiII . I1ii11iIi11i + iII111i % ooOoO0o
  if 28 - 28: I1Ii111
  if 27 - 27: iII111i * I1IiiI
  try : ooOo = lisp_socket . recvfrom ( 9000 )
  except : return ( [ "" , "" , "" , "" ] )
  if 57 - 57: I1IiiI % i1IIi * ooOoO0o
  if 49 - 49: I11i % I1Ii111 + Ii1I * OOooOOo / I1ii11iIi11i
  if 19 - 19: i1IIi * iIii1I11I1II1 + OoOoOO00 % iII111i
  if 24 - 24: I1ii11iIi11i / OoO0O00 / II111iiii * I11i + OoooooooOO * I11i
  if 57 - 57: IiII - i1IIi * oO0o
  if 87 - 87: OoOoOO00 + I11i . ooOoO0o * II111iiii
  if ( internal == False ) :
   iIIi1 = ooOo [ 0 ]
   I1iO00O000oOO0oO = lisp_convert_6to4 ( ooOo [ 1 ] [ 0 ] )
   i1I1IIIi11I = ooOo [ 1 ] [ 1 ]
   if 13 - 13: iIii1I11I1II1 . OOooOOo . oO0o - Oo0Ooo * I1IiiI / i1IIi
   if ( i1I1IIIi11I == LISP_DATA_PORT ) :
    Ooo0OOo = lisp_data_plane_logging
    OOO0I1IiiI = lisp_format_packet ( iIIi1 [ 0 : 60 ] ) + " ..."
   else :
    Ooo0OOo = True
    OOO0I1IiiI = lisp_format_packet ( iIIi1 )
    if 86 - 86: i11iIiiIii
    if 93 - 93: i11iIiiIii . ooOoO0o . iII111i
   if ( Ooo0OOo ) :
    lprint ( "{} {} bytes {} {}, packet: {}" . format ( bold ( "Receive" ,
 False ) , len ( iIIi1 ) , bold ( "from " + I1iO00O000oOO0oO , False ) , i1I1IIIi11I ,
 OOO0I1IiiI ) )
    if 67 - 67: I1IiiI . O0 . OoooooooOO - II111iiii / Ii1I
   return ( [ "packet" , I1iO00O000oOO0oO , i1I1IIIi11I , iIIi1 ] )
   if 63 - 63: O0 . i11iIiiIii / o0oOOo0O0Ooo % OOooOOo
   if 20 - 20: Oo0Ooo - O0 - ooOoO0o % iII111i * OoOoOO00 * OoooooooOO
   if 94 - 94: II111iiii
   if 27 - 27: OOooOOo
   if 95 - 95: oO0o - I1Ii111 + Oo0Ooo
   if 32 - 32: iIii1I11I1II1 - ooOoO0o . o0oOOo0O0Ooo
  oo0O = False
  i11iiiI = ooOo [ 0 ]
  iIoo = False
  if 27 - 27: oO0o
  while ( oo0O == False ) :
   i11iiiI = i11iiiI . split ( "@" )
   if 61 - 61: I1Ii111 / O0 - iII111i
   if ( len ( i11iiiI ) < 4 ) :
    lprint ( "Possible fragment (length {}), from old message, " + "discarding" , len ( i11iiiI [ 0 ] ) )
    if 44 - 44: i1IIi
    iIoo = True
    break
    if 23 - 23: I1ii11iIi11i . OoooooooOO / Ii1I + o0oOOo0O0Ooo
    if 89 - 89: OoOoOO00 + Oo0Ooo . OoOoOO00 - II111iiii
   OoooO0o0o000 = i11iiiI [ 0 ]
   try :
    II11i1ii = int ( i11iiiI [ 1 ] )
   except :
    IiIiI1II = bold ( "Internal packet reassembly error" , False )
    lprint ( "{}: {}" . format ( IiIiI1II , ooOo ) )
    iIoo = True
    break
    if 70 - 70: OOooOOo * OoOoOO00 / oO0o + Oo0Ooo / O0
   I1iO00O000oOO0oO = i11iiiI [ 2 ]
   i1I1IIIi11I = i11iiiI [ 3 ]
   if 16 - 16: Oo0Ooo / OoooooooOO / IiII + Oo0Ooo * i11iIiiIii
   if 15 - 15: o0oOOo0O0Ooo / i11iIiiIii
   if 63 - 63: I1ii11iIi11i - Ii1I + I11i
   if 98 - 98: iII111i / IiII * I1IiiI / oO0o - iIii1I11I1II1
   if 72 - 72: O0 . OOooOOo
   if 99 - 99: i1IIi + iIii1I11I1II1 - ooOoO0o + OoO0O00 + Oo0Ooo . I1ii11iIi11i
   if 74 - 74: i1IIi
   if 80 - 80: ooOoO0o + I1Ii111 . I1ii11iIi11i % OoooooooOO
   if ( len ( i11iiiI ) > 5 ) :
    iIIi1 = lisp_bit_stuff ( i11iiiI [ 4 : : ] )
   else :
    iIIi1 = i11iiiI [ 4 ]
    if 26 - 26: OoOoOO00 . iII111i * iIii1I11I1II1 / IiII
    if 69 - 69: OoooooooOO / I11i + Ii1I * II111iiii
    if 35 - 35: i11iIiiIii + oO0o
    if 85 - 85: OoOoOO00 . O0 % OoooooooOO % oO0o
    if 43 - 43: I1IiiI - I11i . I1IiiI / i11iIiiIii % IiII * i11iIiiIii
    if 12 - 12: II111iiii - iIii1I11I1II1
   oo0O , iIIi1 = lisp_receive_segments ( lisp_socket , iIIi1 ,
 I1iO00O000oOO0oO , II11i1ii )
   if ( iIIi1 == None ) : return ( [ "" , "" , "" , "" ] )
   if 43 - 43: i11iIiiIii % OoO0O00
   if 100 - 100: i1IIi
   if 4 - 4: i11iIiiIii - OOooOOo * IiII % OoooooooOO - OoOoOO00
   if 81 - 81: Ii1I * ooOoO0o . oO0o . IiII
   if 71 - 71: IiII + OoO0O00
   if ( oo0O == False ) :
    i11iiiI = iIIi1
    continue
    if 39 - 39: I1IiiI % IiII / II111iiii / II111iiii
    if 95 - 95: II111iiii + i11iIiiIii + o0oOOo0O0Ooo
   if ( i1I1IIIi11I == "" ) : i1I1IIIi11I = "no-port"
   if ( OoooO0o0o000 == "command" and lisp_i_am_core == False ) :
    oooO0 = iIIi1 . find ( " {" )
    Ii1iIi11 = iIIi1 if oooO0 == - 1 else iIIi1 [ : oooO0 ]
    Ii1iIi11 = ": '" + Ii1iIi11 + "'"
   else :
    Ii1iIi11 = ""
    if 17 - 17: iIii1I11I1II1
    if 10 - 10: i11iIiiIii / iII111i - oO0o
   lprint ( "{} {} bytes {} {}, {}{}" . format ( bold ( "Receive" , False ) ,
 len ( iIIi1 ) , bold ( "from " + I1iO00O000oOO0oO , False ) , i1I1IIIi11I , OoooO0o0o000 ,
 Ii1iIi11 if ( OoooO0o0o000 in [ "command" , "api" ] ) else ": ... " if ( OoooO0o0o000 == "data-packet" ) else ": " + lisp_format_packet ( iIIi1 ) ) )
   if 98 - 98: Ii1I % iII111i . I11i
   if 38 - 38: iIii1I11I1II1 % I1ii11iIi11i % o0oOOo0O0Ooo . ooOoO0o - oO0o
   if 64 - 64: I11i * ooOoO0o
   if 86 - 86: OoooooooOO * I1IiiI
   if 88 - 88: Ii1I + O0
  if ( iIoo ) : continue
  return ( [ OoooO0o0o000 , I1iO00O000oOO0oO , i1I1IIIi11I , iIIi1 ] )
  if 92 - 92: I1IiiI % iII111i % I11i + OoooooooOO - i11iIiiIii
  if 9 - 9: i11iIiiIii - II111iiii / ooOoO0o
  if 81 - 81: i11iIiiIii % OoOoOO00 % OoO0O00 * Ii1I
  if 85 - 85: OoooooooOO * ooOoO0o
  if 23 - 23: OOooOOo / I11i / OoooooooOO - Ii1I / OoO0O00 - OoO0O00
  if 60 - 60: OOooOOo . ooOoO0o % i1IIi % Ii1I % ooOoO0o + OoO0O00
  if 26 - 26: O0 % o0oOOo0O0Ooo + iII111i * I1ii11iIi11i * I1Ii111
  if 4 - 4: OOooOOo * OoooooooOO * i1IIi % I1ii11iIi11i % Oo0Ooo
def lisp_parse_packet ( lisp_sockets , packet , source , udp_sport , ttl = - 1 ) :
 II1iI = False
 if 58 - 58: i1IIi - I1Ii111 % I1Ii111 / I11i
 I11i1I1i1 = lisp_control_header ( )
 if ( I11i1I1i1 . decode ( packet ) == None ) :
  lprint ( "Could not decode control header" )
  return ( II1iI )
  if 75 - 75: Ii1I - IiII + iIii1I11I1II1 * I1Ii111 . I1IiiI
  if 40 - 40: Ii1I
  if 85 - 85: I11i % IiII
  if 68 - 68: Oo0Ooo . I1Ii111 - o0oOOo0O0Ooo * iIii1I11I1II1 - II111iiii % i1IIi
  if 58 - 58: I11i / i11iIiiIii * i11iIiiIii
 I111IiiI1 = source
 if ( source . find ( "lisp" ) == - 1 ) :
  oooOOO00o0 = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  oooOOO00o0 . string_to_afi ( source )
  oooOOO00o0 . store_address ( source )
  source = oooOOO00o0
  if 66 - 66: iIii1I11I1II1 / OoOoOO00 * iII111i - iIii1I11I1II1 % I1Ii111 - II111iiii
  if 24 - 24: ooOoO0o % Oo0Ooo . I11i * I1ii11iIi11i / I1Ii111
 if ( I11i1I1i1 . type == LISP_MAP_REQUEST ) :
  lisp_process_map_request ( lisp_sockets , packet , None , 0 , source ,
 udp_sport , False , ttl )
  if 21 - 21: oO0o / I1ii11iIi11i % iII111i . I11i
 elif ( I11i1I1i1 . type == LISP_MAP_REPLY ) :
  lisp_process_map_reply ( lisp_sockets , packet , source , ttl )
  if 58 - 58: I1IiiI - i1IIi - OOooOOo
 elif ( I11i1I1i1 . type == LISP_MAP_REGISTER ) :
  lisp_process_map_register ( lisp_sockets , packet , source , udp_sport )
  if 33 - 33: O0 % I1IiiI + ooOoO0o % OOooOOo
 elif ( I11i1I1i1 . type == LISP_MAP_NOTIFY ) :
  if ( I111IiiI1 == "lisp-etr" ) :
   lisp_process_multicast_map_notify ( packet , source )
  else :
   if ( lisp_is_running ( "lisp-rtr" ) ) :
    lisp_process_multicast_map_notify ( packet , source )
    if 49 - 49: ooOoO0o / O0 - OoOoOO00 % O0 * oO0o * OoooooooOO
   lisp_process_map_notify ( lisp_sockets , packet , source )
   if 66 - 66: o0oOOo0O0Ooo . I1ii11iIi11i / OoooooooOO . I11i
   if 33 - 33: I1Ii111
 elif ( I11i1I1i1 . type == LISP_MAP_NOTIFY_ACK ) :
  lisp_process_map_notify_ack ( packet , source )
  if 41 - 41: ooOoO0o + Ii1I / i1IIi % Ii1I
 elif ( I11i1I1i1 . type == LISP_MAP_REFERRAL ) :
  lisp_process_map_referral ( lisp_sockets , packet , source )
  if 97 - 97: Oo0Ooo % OoOoOO00 / OOooOOo / iIii1I11I1II1 / OoooooooOO - I1ii11iIi11i
 elif ( I11i1I1i1 . type == LISP_NAT_INFO and I11i1I1i1 . is_info_reply ( ) ) :
  oO0IiiI1i1i11I1 , IiiiIi , II1iI = lisp_process_info_reply ( source , packet , True )
  if 6 - 6: iIii1I11I1II1
 elif ( I11i1I1i1 . type == LISP_NAT_INFO and I11i1I1i1 . is_info_reply ( ) == False ) :
  oooOO0oOooO00 = source . print_address_no_iid ( )
  lisp_process_info_request ( lisp_sockets , packet , oooOO0oOooO00 , udp_sport ,
 None )
  if 27 - 27: Ii1I / i11iIiiIii / i1IIi
 elif ( I11i1I1i1 . type == LISP_ECM ) :
  lisp_process_ecm ( lisp_sockets , packet , source , udp_sport )
  if 36 - 36: ooOoO0o % ooOoO0o . i11iIiiIii
 else :
  lprint ( "Invalid LISP control packet type {}" . format ( I11i1I1i1 . type ) )
  if 42 - 42: OoO0O00 . I1Ii111 / Ii1I
 return ( II1iI )
 if 57 - 57: iIii1I11I1II1 % I1ii11iIi11i . OOooOOo / oO0o . OoOoOO00
 if 74 - 74: I1IiiI * OoO0O00 + OoooooooOO * ooOoO0o . oO0o
 if 66 - 66: II111iiii + OOooOOo + i11iIiiIii / II111iiii
 if 37 - 37: I1IiiI + OoO0O00 . OoO0O00 % OoOoOO00 + o0oOOo0O0Ooo
 if 81 - 81: i1IIi % iIii1I11I1II1
 if 41 - 41: oO0o - iII111i / o0oOOo0O0Ooo . iII111i % Oo0Ooo + OOooOOo
 if 82 - 82: ooOoO0o
def lisp_process_rloc_probe_request ( lisp_sockets , map_request , source , port ,
 ttl ) :
 if 89 - 89: OOooOOo / I1ii11iIi11i . I1IiiI + i11iIiiIii
 iII1ii = bold ( "RLOC-probe" , False )
 if 11 - 11: oO0o . i11iIiiIii * ooOoO0o % OoooooooOO % O0
 if ( lisp_i_am_etr ) :
  lprint ( "Received {} Map-Request, send RLOC-probe Map-Reply" . format ( iII1ii ) )
  lisp_etr_process_map_request ( lisp_sockets , map_request , source , port ,
 ttl )
  return
  if 59 - 59: i11iIiiIii / OoO0O00
  if 48 - 48: iIii1I11I1II1
 if ( lisp_i_am_rtr ) :
  lprint ( "Received {} Map-Request, send RLOC-probe Map-Reply" . format ( iII1ii ) )
  lisp_rtr_process_map_request ( lisp_sockets , map_request , source , port ,
 ttl )
  return
  if 19 - 19: oO0o
  if 69 - 69: I1ii11iIi11i % iII111i - OoooooooOO % Ii1I * oO0o
 lprint ( "Ignoring received {} Map-Request, not an ETR or RTR" . format ( iII1ii ) )
 return
 if 12 - 12: OoOoOO00 / I1Ii111 . O0 . IiII - OOooOOo - OoO0O00
 if 28 - 28: II111iiii . OoOoOO00 - o0oOOo0O0Ooo
 if 89 - 89: I1Ii111 * OoooooooOO . OOooOOo . I11i % i11iIiiIii
 if 8 - 8: I1ii11iIi11i + II111iiii . OoO0O00 + I1IiiI - II111iiii % OoO0O00
 if 85 - 85: i11iIiiIii % iII111i + II111iiii
def lisp_process_smr ( map_request ) :
 lprint ( "Received SMR-based Map-Request" )
 return
 if 16 - 16: ooOoO0o * OoOoOO00 / OoOoOO00 + II111iiii
 if 50 - 50: OoO0O00 / OOooOOo % I1IiiI / Ii1I + OoO0O00 . iIii1I11I1II1
 if 62 - 62: I1Ii111 + OoooooooOO - Ii1I - iIii1I11I1II1
 if 80 - 80: OoO0O00
 if 72 - 72: II111iiii % i11iIiiIii + OoOoOO00 / I1Ii111 - i11iIiiIii
def lisp_process_smr_invoked_request ( map_request ) :
 lprint ( "Received SMR-invoked Map-Request" )
 return
 if 39 - 39: i11iIiiIii - OOooOOo / OoO0O00 * OoOoOO00 / IiII
 if 84 - 84: I1ii11iIi11i . iIii1I11I1II1 / Ii1I / II111iiii
 if 56 - 56: OOooOOo * iII111i / Ii1I
 if 9 - 9: I1ii11iIi11i * i11iIiiIii / I1Ii111 + iIii1I11I1II1
 if 1 - 1: OoO0O00 % iIii1I11I1II1 * OoOoOO00 / oO0o
 if 73 - 73: iII111i
 if 6 - 6: o0oOOo0O0Ooo + Oo0Ooo
def lisp_build_map_reply ( eid , group , rloc_set , nonce , action , ttl , rloc_probe ,
 keys , enc , auth , mr_ttl = - 1 ) :
 iIiii1i1Ii = lisp_map_reply ( )
 iIiii1i1Ii . rloc_probe = rloc_probe
 iIiii1i1Ii . echo_nonce_capable = enc
 iIiii1i1Ii . hop_count = 0 if ( mr_ttl == - 1 ) else mr_ttl
 iIiii1i1Ii . record_count = 1
 iIiii1i1Ii . nonce = nonce
 iIIi1 = iIiii1i1Ii . encode ( )
 iIiii1i1Ii . print_map_reply ( )
 if 68 - 68: iIii1I11I1II1
 oooOoO00o0 = lisp_eid_record ( )
 oooOoO00o0 . rloc_count = len ( rloc_set )
 oooOoO00o0 . authoritative = auth
 oooOoO00o0 . record_ttl = ttl
 oooOoO00o0 . action = action
 oooOoO00o0 . eid = eid
 oooOoO00o0 . group = group
 if 18 - 18: ooOoO0o
 iIIi1 += oooOoO00o0 . encode ( )
 oooOoO00o0 . print_record ( "  " , False )
 if 18 - 18: I1Ii111 + OoOoOO00 % OOooOOo - IiII - i1IIi + I1ii11iIi11i
 I1i1II1I11iiI = lisp_get_all_addresses ( ) + lisp_get_all_translated_rlocs ( )
 if 12 - 12: II111iiii / Ii1I * O0 * OoooooooOO * OoOoOO00
 for OOO0OOO000oOO0 in rloc_set :
  ooOo0OooO = lisp_rloc_record ( )
  oooOO0oOooO00 = OOO0OOO000oOO0 . rloc . print_address_no_iid ( )
  if ( oooOO0oOooO00 in I1i1II1I11iiI ) :
   ooOo0OooO . local_bit = True
   ooOo0OooO . probe_bit = rloc_probe
   ooOo0OooO . keys = keys
   if ( OOO0OOO000oOO0 . priority == 254 and lisp_i_am_rtr ) :
    ooOo0OooO . rloc_name = "RTR"
    if 52 - 52: I1IiiI % OoO0O00
    if 29 - 29: Oo0Ooo
  ooOo0OooO . store_rloc_entry ( OOO0OOO000oOO0 )
  ooOo0OooO . reach_bit = True
  ooOo0OooO . print_record ( "    " )
  iIIi1 += ooOo0OooO . encode ( )
  if 26 - 26: I1ii11iIi11i - OoO0O00
 return ( iIIi1 )
 if 19 - 19: iIii1I11I1II1 / I1ii11iIi11i + O0
 if 12 - 12: I11i . OOooOOo + o0oOOo0O0Ooo . OoO0O00 + o0oOOo0O0Ooo
 if 56 - 56: i1IIi / i1IIi . OoO0O00 % i1IIi - OoOoOO00 % OOooOOo
 if 66 - 66: i11iIiiIii * IiII % IiII . I1IiiI / ooOoO0o
 if 50 - 50: IiII . iII111i / o0oOOo0O0Ooo % OoOoOO00 * IiII % I11i
 if 15 - 15: Ii1I
 if 29 - 29: I11i / I1IiiI / OoooooooOO . OoOoOO00 / I11i . I1Ii111
def lisp_build_map_referral ( eid , group , ddt_entry , action , ttl , nonce ) :
 OoOOOO0Oo0oO = lisp_map_referral ( )
 OoOOOO0Oo0oO . record_count = 1
 OoOOOO0Oo0oO . nonce = nonce
 iIIi1 = OoOOOO0Oo0oO . encode ( )
 OoOOOO0Oo0oO . print_map_referral ( )
 if 95 - 95: o0oOOo0O0Ooo * I1ii11iIi11i - o0oOOo0O0Ooo
 oooOoO00o0 = lisp_eid_record ( )
 if 47 - 47: I1IiiI / OoOoOO00 / II111iiii
 iI1Oo0000O0o0 = 0
 if ( ddt_entry == None ) :
  oooOoO00o0 . eid = eid
  oooOoO00o0 . group = group
 else :
  iI1Oo0000O0o0 = len ( ddt_entry . delegation_set )
  oooOoO00o0 . eid = ddt_entry . eid
  oooOoO00o0 . group = ddt_entry . group
  ddt_entry . map_referrals_sent += 1
  if 99 - 99: IiII / i11iIiiIii - II111iiii . ooOoO0o
 oooOoO00o0 . rloc_count = iI1Oo0000O0o0
 oooOoO00o0 . authoritative = True
 if 29 - 29: OoO0O00 - Ii1I
 if 35 - 35: IiII
 if 99 - 99: iIii1I11I1II1 % I1Ii111 . IiII
 if 7 - 7: OOooOOo + II111iiii + I1IiiI . Oo0Ooo / iIii1I11I1II1 . oO0o
 if 30 - 30: OoO0O00 / OOooOOo
 i1IiIi1II11ii = False
 if ( action == LISP_DDT_ACTION_NULL ) :
  if ( iI1Oo0000O0o0 == 0 ) :
   action = LISP_DDT_ACTION_NODE_REFERRAL
  else :
   IiIiiI1iiiI = ddt_entry . delegation_set [ 0 ]
   if ( IiIiiI1iiiI . is_ddt_child ( ) ) :
    action = LISP_DDT_ACTION_NODE_REFERRAL
    if 81 - 81: I1Ii111 % OoO0O00 . II111iiii - IiII + IiII + Ii1I
   if ( IiIiiI1iiiI . is_ms_child ( ) ) :
    action = LISP_DDT_ACTION_MS_REFERRAL
    if 11 - 11: OOooOOo / iII111i + OoOoOO00 - Ii1I
    if 5 - 5: OOooOOo . oO0o / o0oOOo0O0Ooo
    if 52 - 52: I1IiiI + O0 * I1Ii111
    if 17 - 17: OoooooooOO % I1Ii111 . o0oOOo0O0Ooo * OoO0O00 - I1Ii111 . iII111i
    if 62 - 62: oO0o * OoooooooOO % o0oOOo0O0Ooo
    if 16 - 16: II111iiii - I1IiiI * O0 . OOooOOo / iII111i
    if 55 - 55: Ii1I + OoooooooOO % I1Ii111 % OoO0O00 / OoO0O00 + II111iiii
 if ( action == LISP_DDT_ACTION_NOT_AUTH ) : i1IiIi1II11ii = True
 if ( action in ( LISP_DDT_ACTION_MS_REFERRAL , LISP_DDT_ACTION_MS_ACK ) ) :
  i1IiIi1II11ii = ( lisp_i_am_ms and IiIiiI1iiiI . is_ms_peer ( ) == False )
  if 79 - 79: o0oOOo0O0Ooo % I1Ii111 . Ii1I % iIii1I11I1II1 / Oo0Ooo + i11iIiiIii
  if 25 - 25: ooOoO0o
 oooOoO00o0 . action = action
 oooOoO00o0 . ddt_incomplete = i1IiIi1II11ii
 oooOoO00o0 . record_ttl = ttl
 if 49 - 49: OoO0O00 % I11i . OOooOOo + i1IIi
 iIIi1 += oooOoO00o0 . encode ( )
 oooOoO00o0 . print_record ( "  " , True )
 if 23 - 23: IiII + ooOoO0o % OoOoOO00 % I1IiiI
 if ( iI1Oo0000O0o0 == 0 ) : return ( iIIi1 )
 if 43 - 43: IiII - IiII
 for IiIiiI1iiiI in ddt_entry . delegation_set :
  ooOo0OooO = lisp_rloc_record ( )
  ooOo0OooO . rloc = IiIiiI1iiiI . delegate_address
  ooOo0OooO . priority = IiIiiI1iiiI . priority
  ooOo0OooO . weight = IiIiiI1iiiI . weight
  ooOo0OooO . mpriority = 255
  ooOo0OooO . mweight = 0
  ooOo0OooO . reach_bit = True
  iIIi1 += ooOo0OooO . encode ( )
  ooOo0OooO . print_record ( "    " )
  if 46 - 46: O0 % I1IiiI / I1ii11iIi11i + i1IIi
 return ( iIIi1 )
 if 95 - 95: oO0o / OoooooooOO % I1Ii111 + I1Ii111 + I1IiiI
 if 17 - 17: ooOoO0o % I1IiiI
 if 34 - 34: I11i - i1IIi % OoO0O00 - OoOoOO00 * iIii1I11I1II1 . OoO0O00
 if 98 - 98: Oo0Ooo * oO0o - Oo0Ooo * oO0o
 if 24 - 24: IiII % i11iIiiIii + ooOoO0o
 if 28 - 28: I11i * I11i + I11i / O0 - OOooOOo
 if 29 - 29: OoOoOO00 + i11iIiiIii % OoO0O00 - OoooooooOO
def lisp_etr_process_map_request ( lisp_sockets , map_request , source , sport ,
 ttl ) :
 if 68 - 68: iII111i / OOooOOo
 if ( map_request . target_group . is_null ( ) ) :
  iIiIi = lisp_db_for_lookups . lookup_cache ( map_request . target_eid , False )
 else :
  iIiIi = lisp_db_for_lookups . lookup_cache ( map_request . target_group , False )
  if ( iIiIi ) : iIiIi = iIiIi . lookup_source_cache ( map_request . target_eid , False )
  if 6 - 6: I11i
 OO0OO0O = map_request . print_prefix ( )
 if 23 - 23: i11iIiiIii - I11i . O0 - iIii1I11I1II1 % Oo0Ooo / o0oOOo0O0Ooo
 if ( iIiIi == None ) :
  lprint ( "Database-mapping entry not found for requested EID {}" . format ( green ( OO0OO0O , False ) ) )
  if 6 - 6: ooOoO0o - OOooOOo . Oo0Ooo * OoOoOO00 / OoooooooOO * OoO0O00
  return
  if 3 - 3: OoooooooOO + O0 % Oo0Ooo / oO0o
  if 67 - 67: I1ii11iIi11i % Oo0Ooo * OoOoOO00
 OO0oO0 = iIiIi . print_eid_tuple ( )
 if 39 - 39: OoO0O00 - Oo0Ooo / iII111i * IiII
 lprint ( "Found database-mapping EID-prefix {} for requested EID {}" . format ( green ( OO0oO0 , False ) , green ( OO0OO0O , False ) ) )
 if 56 - 56: OOooOOo * IiII . iIii1I11I1II1 * I1Ii111
 if 95 - 95: oO0o % Ii1I - OOooOOo . O0 . OoooooooOO - II111iiii
 if 91 - 91: I1IiiI % i1IIi . Ii1I
 if 67 - 67: oO0o + i1IIi / o0oOOo0O0Ooo
 if 78 - 78: ooOoO0o
 Ii1ii11i1i = map_request . itr_rlocs [ 0 ]
 if ( Ii1ii11i1i . is_private_address ( ) and lisp_nat_traversal ) :
  Ii1ii11i1i = source
  if 21 - 21: oO0o / i11iIiiIii % OoooooooOO / iII111i % I1Ii111
  if 37 - 37: OoOoOO00 . I1ii11iIi11i / II111iiii % oO0o % II111iiii
 I11iIi1i1I1i1 = map_request . nonce
 Iiii = lisp_nonce_echoing
 oOoOo0o00o = map_request . keys
 if 56 - 56: Ii1I * I1IiiI / ooOoO0o * II111iiii
 iIiIi . map_replies_sent += 1
 if 51 - 51: i1IIi . oO0o % OOooOOo
 iIIi1 = lisp_build_map_reply ( iIiIi . eid , iIiIi . group , iIiIi . rloc_set , I11iIi1i1I1i1 ,
 LISP_NO_ACTION , 1440 , map_request . rloc_probe , oOoOo0o00o , Iiii , True , ttl )
 if 90 - 90: OoooooooOO + iII111i / iIii1I11I1II1
 if 12 - 12: OoooooooOO
 if 9 - 9: O0 / O0 / I1IiiI - oO0o . ooOoO0o
 if 6 - 6: O0 - OoO0O00 + OoooooooOO % iIii1I11I1II1
 if 58 - 58: i11iIiiIii * OOooOOo . Oo0Ooo / iII111i - i1IIi
 if 45 - 45: Ii1I
 if 89 - 89: ooOoO0o + I11i * O0 % OoOoOO00
 if 2 - 2: I1Ii111 % iIii1I11I1II1 . Ii1I - II111iiii
 if 33 - 33: I11i . i11iIiiIii % i1IIi * II111iiii * i11iIiiIii + OoOoOO00
 if 26 - 26: I1IiiI % OoOoOO00 % I11i + Oo0Ooo
 if ( map_request . rloc_probe and len ( lisp_sockets ) == 4 ) :
  oooOo = ( Ii1ii11i1i . is_private_address ( ) == False )
  OOoO0o0 = Ii1ii11i1i . print_address_no_iid ( )
  if ( oooOo and lisp_rtr_list . has_key ( OOoO0o0 ) ) :
   lisp_encapsulate_rloc_probe ( lisp_sockets , Ii1ii11i1i , None , iIIi1 )
   return
   if 86 - 86: iII111i / i1IIi % Oo0Ooo
   if 84 - 84: o0oOOo0O0Ooo * OOooOOo . I11i * Ii1I
   if 32 - 32: ooOoO0o % ooOoO0o * I1ii11iIi11i % Ii1I + Oo0Ooo . OoOoOO00
   if 2 - 2: I1Ii111 / ooOoO0o * oO0o + IiII
   if 14 - 14: OoOoOO00 / iIii1I11I1II1 . o0oOOo0O0Ooo % i11iIiiIii . OoOoOO00
   if 92 - 92: OoO0O00 . i1IIi
 lisp_send_map_reply ( lisp_sockets , iIIi1 , Ii1ii11i1i , sport )
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
 Ii1ii11i1i = map_request . itr_rlocs [ 0 ]
 if ( Ii1ii11i1i . is_private_address ( ) ) : Ii1ii11i1i = source
 I11iIi1i1I1i1 = map_request . nonce
 if 8 - 8: I1IiiI . IiII * O0 * o0oOOo0O0Ooo
 oOOOO = map_request . target_eid
 iiI = map_request . target_group
 if 17 - 17: I1IiiI . oO0o + Oo0Ooo + I11i / o0oOOo0O0Ooo
 I111i = [ ]
 for Ii11Ii11III in [ lisp_myrlocs [ 0 ] , lisp_myrlocs [ 1 ] ] :
  if ( Ii11Ii11III == None ) : continue
  Oo0O0 = lisp_rloc ( )
  Oo0O0 . rloc . copy_address ( Ii11Ii11III )
  Oo0O0 . priority = 254
  I111i . append ( Oo0O0 )
  if 1 - 1: O0 * oO0o * OoOoOO00 . i1IIi . Ii1I - OoOoOO00
  if 27 - 27: O0
 Iiii = lisp_nonce_echoing
 oOoOo0o00o = map_request . keys
 if 86 - 86: IiII + Ii1I / Oo0Ooo / O0 % iII111i - oO0o
 iIIi1 = lisp_build_map_reply ( oOOOO , iiI , I111i , I11iIi1i1I1i1 , LISP_NO_ACTION ,
 1440 , True , oOoOo0o00o , Iiii , True , ttl )
 lisp_send_map_reply ( lisp_sockets , iIIi1 , Ii1ii11i1i , sport )
 return
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
def lisp_get_private_rloc_set ( target_site_eid , seid , group ) :
 I111i = target_site_eid . registered_rlocs
 if 94 - 94: OOooOOo / IiII
 I1i11111i = lisp_site_eid_lookup ( seid , group , False )
 if ( I1i11111i == None ) : return ( I111i )
 if 22 - 22: OoOoOO00 - Oo0Ooo
 if 41 - 41: iIii1I11I1II1 * I1Ii111 / OoO0O00
 if 33 - 33: I11i + O0
 if 9 - 9: I11i . iII111i * ooOoO0o * ooOoO0o
 Oo0o0o0oo = None
 iiiIIiIIi1 = [ ]
 for OOO0OOO000oOO0 in I111i :
  if ( OOO0OOO000oOO0 . is_rtr ( ) ) : continue
  if ( OOO0OOO000oOO0 . rloc . is_private_address ( ) ) :
   I11I = copy . deepcopy ( OOO0OOO000oOO0 )
   iiiIIiIIi1 . append ( I11I )
   continue
   if 55 - 55: I11i + ooOoO0o / ooOoO0o % I1ii11iIi11i
  Oo0o0o0oo = OOO0OOO000oOO0
  break
  if 84 - 84: O0 + IiII - I1IiiI - I1Ii111 / OoooooooOO
 if ( Oo0o0o0oo == None ) : return ( I111i )
 Oo0o0o0oo = Oo0o0o0oo . rloc . print_address_no_iid ( )
 if 76 - 76: i11iIiiIii - Ii1I * I1ii11iIi11i + oO0o - OOooOOo
 if 42 - 42: o0oOOo0O0Ooo
 if 37 - 37: ooOoO0o / oO0o % O0 + Ii1I / OOooOOo
 if 14 - 14: I11i
 oO000oooOoO0O = None
 for OOO0OOO000oOO0 in I1i11111i . registered_rlocs :
  if ( OOO0OOO000oOO0 . is_rtr ( ) ) : continue
  if ( OOO0OOO000oOO0 . rloc . is_private_address ( ) ) : continue
  oO000oooOoO0O = OOO0OOO000oOO0
  break
  if 72 - 72: I1Ii111 % i11iIiiIii / Ii1I % I1ii11iIi11i % IiII
 if ( oO000oooOoO0O == None ) : return ( I111i )
 oO000oooOoO0O = oO000oooOoO0O . rloc . print_address_no_iid ( )
 if 52 - 52: OoooooooOO / OOooOOo
 if 44 - 44: IiII - OoooooooOO * O0 + II111iiii + IiII
 if 82 - 82: OoO0O00 + OOooOOo + O0
 if 60 - 60: iIii1I11I1II1
 IIiI1iiIII1 = target_site_eid . site_id
 if ( IIiI1iiIII1 == 0 ) :
  if ( oO000oooOoO0O == Oo0o0o0oo ) :
   lprint ( "Return private RLOCs for sites behind {}" . format ( Oo0o0o0oo ) )
   if 100 - 100: Oo0Ooo + IiII
   return ( iiiIIiIIi1 )
   if 81 - 81: iIii1I11I1II1 + iIii1I11I1II1
  return ( I111i )
  if 19 - 19: ooOoO0o + i1IIi / Oo0Ooo * II111iiii * I1Ii111 / ooOoO0o
  if 23 - 23: I1Ii111
  if 76 - 76: Ii1I + Ii1I / i1IIi % o0oOOo0O0Ooo . iIii1I11I1II1 . OoOoOO00
  if 75 - 75: I11i . Ii1I / I1ii11iIi11i
  if 99 - 99: Ii1I
  if 85 - 85: I1Ii111 + I1Ii111 + OoOoOO00 / ooOoO0o / o0oOOo0O0Ooo . Oo0Ooo
  if 41 - 41: i1IIi % Ii1I . i1IIi * OoooooooOO % Ii1I
 if ( IIiI1iiIII1 == I1i11111i . site_id ) :
  lprint ( "Return private RLOCs for sites in site-id {}" . format ( IIiI1iiIII1 ) )
  return ( iiiIIiIIi1 )
  if 21 - 21: iII111i
 return ( I111i )
 if 72 - 72: I11i % o0oOOo0O0Ooo . iIii1I11I1II1 - I1Ii111 / i11iIiiIii
 if 75 - 75: OoooooooOO
 if 24 - 24: oO0o % iII111i - II111iiii / Ii1I + O0
 if 37 - 37: I1Ii111 - i1IIi / iIii1I11I1II1
 if 53 - 53: Ii1I - iIii1I11I1II1 % I1ii11iIi11i * i11iIiiIii + ooOoO0o
 if 63 - 63: Oo0Ooo * I1IiiI
 if 84 - 84: Oo0Ooo
 if 67 - 67: oO0o / II111iiii . I11i / oO0o
 if 46 - 46: oO0o * Oo0Ooo - I11i / iIii1I11I1II1
def lisp_get_partial_rloc_set ( registered_rloc_set , mr_source , multicast ) :
 ooOOO00Ooo0 = [ ]
 I111i = [ ]
 if 3 - 3: I1ii11iIi11i
 if 38 - 38: ooOoO0o % Ii1I % I11i % iIii1I11I1II1
 if 2 - 2: I11i * oO0o - Ii1I
 if 41 - 41: OoOoOO00 * IiII + iII111i
 if 58 - 58: I1ii11iIi11i / oO0o + i11iIiiIii * o0oOOo0O0Ooo
 if 19 - 19: OoOoOO00
 i1i1iI = False
 oO0ooOo0O = False
 for OOO0OOO000oOO0 in registered_rloc_set :
  if ( OOO0OOO000oOO0 . priority != 254 ) : continue
  oO0ooOo0O |= True
  if ( OOO0OOO000oOO0 . rloc . is_exact_match ( mr_source ) == False ) : continue
  i1i1iI = True
  break
  if 44 - 44: O0 + OoOoOO00 . iIii1I11I1II1 . IiII
  if 2 - 2: iII111i
  if 47 - 47: i1IIi % I11i
  if 17 - 17: OoOoOO00 - iII111i % I11i / o0oOOo0O0Ooo / II111iiii
  if 22 - 22: Oo0Ooo + I1ii11iIi11i % i11iIiiIii . OoO0O00 - I11i % I11i
  if 21 - 21: I1IiiI . OoO0O00 * IiII % OoooooooOO - Oo0Ooo + Oo0Ooo
  if 94 - 94: ooOoO0o
 if ( oO0ooOo0O == False ) : return ( registered_rloc_set )
 if 80 - 80: i11iIiiIii - O0 / I1Ii111 + OOooOOo % Oo0Ooo
 if 95 - 95: II111iiii
 if 76 - 76: OoO0O00 % iII111i * OoOoOO00 / ooOoO0o / i1IIi
 if 45 - 45: Ii1I . I11i * I1Ii111 . i11iIiiIii
 if 34 - 34: O0 * o0oOOo0O0Ooo / IiII
 if 75 - 75: I1Ii111 - i1IIi - OoO0O00
 if 25 - 25: iII111i . o0oOOo0O0Ooo
 if 62 - 62: I11i + i1IIi . I1ii11iIi11i - I1ii11iIi11i
 if 68 - 68: ooOoO0o % OoooooooOO
 if 94 - 94: Oo0Ooo * o0oOOo0O0Ooo
 o00 = ( os . getenv ( "LISP_RTR_BEHIND_NAT" ) != None )
 if 39 - 39: O0 - i11iIiiIii - I1IiiI / Oo0Ooo - i11iIiiIii
 if 30 - 30: OoO0O00 / OoOoOO00 + I1ii11iIi11i % IiII - OoO0O00
 if 19 - 19: I1IiiI
 if 99 - 99: OOooOOo - OOooOOo
 if 98 - 98: o0oOOo0O0Ooo + O0 * oO0o - i11iIiiIii
 for OOO0OOO000oOO0 in registered_rloc_set :
  if ( o00 and OOO0OOO000oOO0 . rloc . is_private_address ( ) ) : continue
  if ( multicast == False and OOO0OOO000oOO0 . priority == 255 ) : continue
  if ( multicast and OOO0OOO000oOO0 . mpriority == 255 ) : continue
  if ( OOO0OOO000oOO0 . priority == 254 ) :
   ooOOO00Ooo0 . append ( OOO0OOO000oOO0 )
  else :
   I111i . append ( OOO0OOO000oOO0 )
   if 83 - 83: o0oOOo0O0Ooo
   if 23 - 23: o0oOOo0O0Ooo . I11i
   if 67 - 67: iII111i
   if 52 - 52: IiII . OoooooooOO
   if 34 - 34: o0oOOo0O0Ooo / IiII . OoooooooOO . Oo0Ooo / ooOoO0o + O0
   if 38 - 38: I11i
 if ( i1i1iI ) : return ( I111i )
 if 66 - 66: II111iiii
 if 57 - 57: OoO0O00 / Oo0Ooo % I1IiiI * I1ii11iIi11i
 if 68 - 68: iII111i - o0oOOo0O0Ooo - OoO0O00 . O0 - i11iIiiIii
 if 2 - 2: I1ii11iIi11i * i1IIi
 if 17 - 17: I1ii11iIi11i * Ii1I % Oo0Ooo * I1Ii111 + OoO0O00 . OoooooooOO
 if 60 - 60: Ii1I . II111iiii
 if 36 - 36: IiII . iII111i * O0 . i1IIi * O0 * I1Ii111
 if 50 - 50: OoooooooOO + o0oOOo0O0Ooo + iIii1I11I1II1 + OOooOOo
 if 90 - 90: Ii1I * I11i % I1Ii111 - I1ii11iIi11i * I1Ii111 % OoO0O00
 if 50 - 50: iIii1I11I1II1
 I111i = [ ]
 for OOO0OOO000oOO0 in registered_rloc_set :
  if ( OOO0OOO000oOO0 . rloc . is_private_address ( ) ) : I111i . append ( OOO0OOO000oOO0 )
  if 56 - 56: oO0o
 I111i += ooOOO00Ooo0
 return ( I111i )
 if 55 - 55: iIii1I11I1II1 % oO0o % OOooOOo / I1Ii111 * OoooooooOO / Oo0Ooo
 if 88 - 88: I11i + OoO0O00 . iIii1I11I1II1 . II111iiii
 if 67 - 67: OOooOOo - ooOoO0o % iII111i % IiII
 if 71 - 71: OoO0O00 - ooOoO0o - I1IiiI + O0
 if 15 - 15: i1IIi
 if 43 - 43: II111iiii + OOooOOo . i11iIiiIii - II111iiii
 if 80 - 80: o0oOOo0O0Ooo . oO0o . I1Ii111
 if 26 - 26: i1IIi - I1IiiI + IiII / OoO0O00 . I1ii11iIi11i
 if 82 - 82: I1Ii111 % iII111i . OoOoOO00 % OoO0O00 + I1ii11iIi11i
 if 69 - 69: I1IiiI * OoOoOO00 - ooOoO0o . O0
def lisp_store_pubsub_state ( reply_eid , itr_rloc , mr_sport , nonce , ttl , xtr_id ) :
 II = lisp_pubsub ( itr_rloc , mr_sport , nonce , ttl , xtr_id )
 II . add ( reply_eid )
 return
 if 46 - 46: I1Ii111 - iII111i / oO0o % OoO0O00 / O0 + oO0o
 if 35 - 35: Oo0Ooo
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
 if 74 - 74: O0 / I11i
def lisp_convert_reply_to_notify ( packet ) :
 if 52 - 52: I1IiiI + oO0o * II111iiii
 if 15 - 15: I11i
 if 72 - 72: O0
 if 15 - 15: II111iiii / I11i % II111iiii % Ii1I % i11iIiiIii / I1Ii111
 o00o = struct . unpack ( "I" , packet [ 0 : 4 ] ) [ 0 ]
 o00o = socket . ntohl ( o00o ) & 0xff
 I11iIi1i1I1i1 = packet [ 4 : 12 ]
 packet = packet [ 12 : : ]
 if 85 - 85: I1ii11iIi11i * OOooOOo - I1IiiI
 if 76 - 76: iIii1I11I1II1
 if 94 - 94: O0
 if 50 - 50: I1Ii111 * o0oOOo0O0Ooo - ooOoO0o - I1ii11iIi11i % I1IiiI . ooOoO0o
 Iii11I1i = ( LISP_MAP_NOTIFY << 28 ) | o00o
 I11i1I1i1 = struct . pack ( "I" , socket . htonl ( Iii11I1i ) )
 OOO000Oo = struct . pack ( "I" , 0 )
 if 35 - 35: Ii1I % i1IIi + I1IiiI
 if 51 - 51: I1Ii111 / iIii1I11I1II1 + i1IIi
 if 71 - 71: iIii1I11I1II1 * ooOoO0o % iIii1I11I1II1 % I1IiiI
 if 75 - 75: I1IiiI
 packet = I11i1I1i1 + I11iIi1i1I1i1 + OOO000Oo + packet
 return ( packet )
 if 33 - 33: OoOoOO00
 if 53 - 53: i11iIiiIii / i1IIi . i1IIi + I11i
 if 19 - 19: ooOoO0o . OoOoOO00 + Oo0Ooo + iIii1I11I1II1 . OoOoOO00 - I1IiiI
 if 70 - 70: OOooOOo . OoOoOO00 . OOooOOo / iII111i
 if 72 - 72: OoooooooOO + Ii1I + iIii1I11I1II1
 if 13 - 13: iII111i . I1Ii111 % ooOoO0o / i1IIi
 if 64 - 64: iII111i
 if 9 - 9: I1ii11iIi11i + Oo0Ooo * I11i / I1Ii111 / I1ii11iIi11i / oO0o
def lisp_notify_subscribers ( lisp_sockets , eid_record , eid , site ) :
 OO0OO0O = eid . print_prefix ( )
 if ( lisp_pubsub_cache . has_key ( OO0OO0O ) == False ) : return
 if 48 - 48: Oo0Ooo % i1IIi / I1ii11iIi11i / oO0o + iII111i
 for II in lisp_pubsub_cache [ OO0OO0O ] . values ( ) :
  Ii1ii1Ii11 = II . itr
  i1I1IIIi11I = II . port
  i11iiII1III = red ( Ii1ii1Ii11 . print_address_no_iid ( ) , False )
  iI1II111 = bold ( "subscriber" , False )
  O0o0O0OoOo0 = "0x" + lisp_hex_string ( II . xtr_id )
  I11iIi1i1I1i1 = "0x" + lisp_hex_string ( II . nonce )
  if 14 - 14: OoOoOO00 - OoOoOO00 / ooOoO0o
  lprint ( "    Notify {} {}:{} xtr-id {} for {}, nonce {}" . format ( iI1II111 , i11iiII1III , i1I1IIIi11I , O0o0O0OoOo0 , green ( OO0OO0O , False ) , I11iIi1i1I1i1 ) )
  if 22 - 22: I1Ii111
  if 59 - 59: I1Ii111
  lisp_build_map_notify ( lisp_sockets , eid_record , [ OO0OO0O ] , 1 , Ii1ii1Ii11 ,
 i1I1IIIi11I , II . nonce , 0 , 0 , 0 , site , False )
  II . map_notify_count += 1
  if 22 - 22: OoooooooOO
 return
 if 88 - 88: I1Ii111 - OoO0O00
 if 29 - 29: I1IiiI . I1Ii111
 if 74 - 74: Oo0Ooo / OoOoOO00 + OoOoOO00 % i11iIiiIii . OoO0O00 + ooOoO0o
 if 77 - 77: ooOoO0o . I11i + OoooooooOO
 if 100 - 100: ooOoO0o . oO0o % I1ii11iIi11i . IiII * IiII - o0oOOo0O0Ooo
 if 49 - 49: iIii1I11I1II1 % Ii1I / OoooooooOO - II111iiii . Ii1I
 if 65 - 65: OoooooooOO + I1Ii111 % ooOoO0o + II111iiii . i1IIi + OoooooooOO
def lisp_process_pubsub ( lisp_sockets , packet , reply_eid , itr_rloc , port , nonce ,
 ttl , xtr_id ) :
 if 26 - 26: I1IiiI / II111iiii % I1ii11iIi11i * o0oOOo0O0Ooo . IiII / OoO0O00
 if 10 - 10: i11iIiiIii / i1IIi + O0 - i11iIiiIii % I11i - i1IIi
 if 38 - 38: O0 - I1IiiI + Oo0Ooo + ooOoO0o
 if 56 - 56: I1Ii111 + oO0o / Ii1I + I1Ii111
 lisp_store_pubsub_state ( reply_eid , itr_rloc , port , nonce , ttl , xtr_id )
 if 21 - 21: OOooOOo / OoOoOO00 + OoOoOO00 + OoOoOO00 - i1IIi + Ii1I
 oOOOO = green ( reply_eid . print_prefix ( ) , False )
 Ii1ii1Ii11 = red ( itr_rloc . print_address_no_iid ( ) , False )
 iiiIIi1I1I1 = bold ( "Map-Notify" , False )
 xtr_id = "0x" + lisp_hex_string ( xtr_id )
 lprint ( "{} pubsub request for {} to ack ITR {} xtr-id: {}" . format ( iiiIIi1I1I1 ,
 oOOOO , Ii1ii1Ii11 , xtr_id ) )
 if 18 - 18: OoooooooOO * i11iIiiIii - iII111i % IiII . i11iIiiIii
 if 8 - 8: I1IiiI . ooOoO0o
 if 31 - 31: ooOoO0o / OoOoOO00
 if 16 - 16: ooOoO0o
 packet = lisp_convert_reply_to_notify ( packet )
 lisp_send_map_notify ( lisp_sockets , packet , itr_rloc , port )
 return
 if 61 - 61: IiII
 if 53 - 53: Oo0Ooo % iII111i % iII111i
 if 71 - 71: iII111i
 if 99 - 99: O0 - OoOoOO00 * I1Ii111 - Oo0Ooo
 if 62 - 62: i1IIi + ooOoO0o + Oo0Ooo - i11iIiiIii
 if 19 - 19: I1IiiI / OOooOOo
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
 oOOOO = map_request . target_eid
 iiI = map_request . target_group
 OO0OO0O = lisp_print_eid_tuple ( oOOOO , iiI )
 Ii1ii11i1i = map_request . itr_rlocs [ 0 ]
 O0o0O0OoOo0 = map_request . xtr_id
 I11iIi1i1I1i1 = map_request . nonce
 iiIiiIii1IiI = LISP_NO_ACTION
 II = map_request . subscribe_bit
 if 59 - 59: O0 + Oo0Ooo
 if 63 - 63: OoO0O00 / I1IiiI / oO0o . Ii1I / i1IIi
 if 50 - 50: I11i . I11i % I1IiiI - i1IIi
 if 63 - 63: OoO0O00 . iII111i
 if 28 - 28: ooOoO0o . Oo0Ooo - OoooooooOO - I1Ii111 - OoooooooOO - oO0o
 I1i11 = True
 i11iI111 = ( lisp_get_eid_hash ( oOOOO ) != None )
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
 if ( II and I1i11 == False ) :
  II = False
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
 O0ooo0OOo0o = Ii1ii11i1i if ( Ii1ii11i1i . afi == ecm_source . afi ) else ecm_source
 if 3 - 3: O0
 o0O0oOo = lisp_site_eid_lookup ( oOOOO , iiI , False )
 if 97 - 97: o0oOOo0O0Ooo + i1IIi % OoO0O00 - oO0o % I1ii11iIi11i * o0oOOo0O0Ooo
 if ( o0O0oOo == None or o0O0oOo . is_star_g ( ) ) :
  oOoOo0OO0o = bold ( "Site not found" , False )
  lprint ( "{} for requested EID {}" . format ( oOoOo0OO0o ,
 green ( OO0OO0O , False ) ) )
  if 52 - 52: I1Ii111
  if 86 - 86: O0 * IiII + OoOoOO00 + OoO0O00
  if 53 - 53: I1IiiI % i11iIiiIii + o0oOOo0O0Ooo . I1ii11iIi11i
  if 73 - 73: iII111i - o0oOOo0O0Ooo / OOooOOo + iII111i + o0oOOo0O0Ooo % II111iiii
  lisp_send_negative_map_reply ( lisp_sockets , oOOOO , iiI , I11iIi1i1I1i1 , Ii1ii11i1i ,
 mr_sport , 15 , O0o0O0OoOo0 , II )
  if 74 - 74: I11i * iIii1I11I1II1 - OoO0O00 / i1IIi / OoO0O00 / IiII
  return ( [ oOOOO , iiI , LISP_DDT_ACTION_SITE_NOT_FOUND ] )
  if 60 - 60: oO0o % I1Ii111 % Oo0Ooo
  if 34 - 34: o0oOOo0O0Ooo * OOooOOo % Ii1I + I1IiiI
 OO0oO0 = o0O0oOo . print_eid_tuple ( )
 oOO0O0o = o0O0oOo . site . site_name
 if 22 - 22: I11i * i1IIi % I1ii11iIi11i
 if 62 - 62: O0
 if 29 - 29: ooOoO0o + o0oOOo0O0Ooo
 if 32 - 32: IiII + iII111i * OoO0O00 . I1ii11iIi11i / Ii1I
 if 66 - 66: Oo0Ooo . I1Ii111 / I1Ii111
 if ( i11iI111 == False and o0O0oOo . require_signature ) :
  I111II11I = map_request . map_request_signature
  i11iii1 = map_request . signature_eid
  if ( I111II11I == None or i11iii1 . is_null ( ) ) :
   lprint ( "Signature required for site {}" . format ( oOO0O0o ) )
   I1i11 = False
  else :
   i11iii1 = map_request . signature_eid
   iIII , iiI111 , I1i11 = lisp_lookup_public_key ( i11iii1 )
   if ( I1i11 ) :
    I1i11 = map_request . verify_map_request_sig ( iiI111 )
   else :
    lprint ( "Public-key lookup failed for sig-eid {}, hash-eid {}" . format ( i11iii1 . print_address ( ) , iIII . print_address ( ) ) )
    if 78 - 78: I11i / I1IiiI . Ii1I
    if 92 - 92: OOooOOo + OoooooooOO + II111iiii . iIii1I11I1II1 + II111iiii - OoOoOO00
   ooOI1i = bold ( "passed" , False ) if I1i11 else bold ( "failed" , False )
   lprint ( "Required signature verification {}" . format ( ooOI1i ) )
   if 93 - 93: II111iiii . I1ii11iIi11i + Oo0Ooo % I1IiiI - iII111i
   if 93 - 93: OoO0O00 * ooOoO0o - Oo0Ooo / OOooOOo * OOooOOo
   if 87 - 87: I1ii11iIi11i - Oo0Ooo % i11iIiiIii
   if 99 - 99: o0oOOo0O0Ooo . O0 % OoOoOO00 / I1IiiI + OoOoOO00
   if 33 - 33: oO0o
   if 58 - 58: I1ii11iIi11i / Ii1I * ooOoO0o - IiII
 if ( I1i11 and o0O0oOo . registered == False ) :
  lprint ( "Site '{}' with EID-prefix {} is not registered for EID {}" . format ( oOO0O0o , green ( OO0oO0 , False ) , green ( OO0OO0O , False ) ) )
  if 67 - 67: ooOoO0o - ooOoO0o * o0oOOo0O0Ooo
  if 65 - 65: O0
  if 37 - 37: I1ii11iIi11i - Oo0Ooo . i11iIiiIii / i11iIiiIii + oO0o
  if 19 - 19: i1IIi / i1IIi - OoooooooOO - OOooOOo . i1IIi
  if 57 - 57: OOooOOo / I1ii11iIi11i * oO0o
  if 53 - 53: o0oOOo0O0Ooo * Ii1I
  if ( o0O0oOo . accept_more_specifics == False ) :
   oOOOO = o0O0oOo . eid
   iiI = o0O0oOo . group
   if 42 - 42: I11i + iII111i / iIii1I11I1II1
   if 1 - 1: O0 - II111iiii
   if 75 - 75: II111iiii / OoO0O00 % II111iiii
   if 3 - 3: Ii1I - Ii1I % I1ii11iIi11i
   if 44 - 44: OOooOOo - o0oOOo0O0Ooo
  O00O00Oo = 1
  if ( o0O0oOo . force_ttl != None ) :
   O00O00Oo = o0O0oOo . force_ttl | 0x80000000
   if 69 - 69: IiII + I1ii11iIi11i / o0oOOo0O0Ooo / OOooOOo
   if 31 - 31: oO0o + I1ii11iIi11i * i1IIi % I1IiiI % I1IiiI + iIii1I11I1II1
   if 62 - 62: OoooooooOO
   if 38 - 38: iII111i % iII111i * ooOoO0o / OoO0O00 + ooOoO0o
   if 52 - 52: ooOoO0o . iIii1I11I1II1 / iIii1I11I1II1 % oO0o - oO0o * II111iiii
  lisp_send_negative_map_reply ( lisp_sockets , oOOOO , iiI , I11iIi1i1I1i1 , Ii1ii11i1i ,
 mr_sport , O00O00Oo , O0o0O0OoOo0 , II )
  if 57 - 57: I1Ii111
  return ( [ oOOOO , iiI , LISP_DDT_ACTION_MS_NOT_REG ] )
  if 23 - 23: I1ii11iIi11i + II111iiii
  if 99 - 99: o0oOOo0O0Ooo . I1IiiI + o0oOOo0O0Ooo * o0oOOo0O0Ooo / O0
  if 27 - 27: OOooOOo - I1Ii111
  if 33 - 33: OOooOOo - Ii1I - iII111i + I1ii11iIi11i - i11iIiiIii
  if 89 - 89: iIii1I11I1II1 * I11i + OOooOOo
 iiIiIIi1I = False
 Ooo0 = ""
 ooOooOo = False
 if ( o0O0oOo . force_nat_proxy_reply ) :
  Ooo0 = ", nat-forced"
  iiIiIIi1I = True
  ooOooOo = True
 elif ( o0O0oOo . force_proxy_reply ) :
  Ooo0 = ", forced"
  ooOooOo = True
 elif ( o0O0oOo . proxy_reply_requested ) :
  Ooo0 = ", requested"
  ooOooOo = True
 elif ( map_request . pitr_bit and o0O0oOo . pitr_proxy_reply_drop ) :
  Ooo0 = ", drop-to-pitr"
  iiIiiIii1IiI = LISP_DROP_ACTION
 elif ( o0O0oOo . proxy_reply_action != "" ) :
  iiIiiIii1IiI = o0O0oOo . proxy_reply_action
  Ooo0 = ", forced, action {}" . format ( iiIiiIii1IiI )
  iiIiiIii1IiI = LISP_DROP_ACTION if ( iiIiiIii1IiI == "drop" ) else LISP_NATIVE_FORWARD_ACTION
  if 98 - 98: i11iIiiIii * Oo0Ooo + iIii1I11I1II1
  if 23 - 23: i11iIiiIii - II111iiii . OoooooooOO / I1ii11iIi11i / OoOoOO00 * OoO0O00
  if 72 - 72: OOooOOo * OOooOOo
  if 5 - 5: o0oOOo0O0Ooo / i11iIiiIii
  if 5 - 5: oO0o % iII111i . Oo0Ooo . O0 . OoOoOO00 / iII111i
  if 78 - 78: Ii1I - I1ii11iIi11i + iIii1I11I1II1 + OoooooooOO . OoO0O00 - ooOoO0o
  if 81 - 81: o0oOOo0O0Ooo * OoooooooOO
 II11iiiIi = False
 oOo0oO = None
 if ( ooOooOo and lisp_policies . has_key ( o0O0oOo . policy ) ) :
  iII1ii = lisp_policies [ o0O0oOo . policy ]
  if ( iII1ii . match_policy_map_request ( map_request , mr_source ) ) : oOo0oO = iII1ii
  if 29 - 29: OoooooooOO * O0 / iIii1I11I1II1
  if ( oOo0oO ) :
   i1 = bold ( "matched" , False )
   lprint ( "Map-Request {} policy '{}', set-action '{}'" . format ( i1 ,
 iII1ii . policy_name , iII1ii . set_action ) )
  else :
   i1 = bold ( "no match" , False )
   lprint ( "Map-Request {} for policy '{}', implied drop" . format ( i1 ,
 iII1ii . policy_name ) )
   II11iiiIi = True
   if 29 - 29: OoO0O00 / IiII + i1IIi / OoO0O00 . Oo0Ooo
   if 52 - 52: OoOoOO00 . iIii1I11I1II1 / OoOoOO00
   if 14 - 14: i1IIi
 if ( Ooo0 != "" ) :
  lprint ( "Proxy-replying for EID {}, found site '{}' EID-prefix {}{}" . format ( green ( OO0OO0O , False ) , oOO0O0o , green ( OO0oO0 , False ) ,
  # O0 + I1IiiI + IiII . Oo0Ooo
 Ooo0 ) )
  if 75 - 75: OoO0O00 % OoO0O00 + OoOoOO00 . O0 . OOooOOo / O0
  I111i = o0O0oOo . registered_rlocs
  O00O00Oo = 1440
  if ( iiIiIIi1I ) :
   if ( o0O0oOo . site_id != 0 ) :
    I11I1Ii1i = map_request . source_eid
    I111i = lisp_get_private_rloc_set ( o0O0oOo , I11I1Ii1i , iiI )
    if 63 - 63: I11i - ooOoO0o % IiII
   if ( I111i == o0O0oOo . registered_rlocs ) :
    iIiIii11I1 = ( o0O0oOo . group . is_null ( ) == False )
    iiiIIiIIi1 = lisp_get_partial_rloc_set ( I111i , O0ooo0OOo0o , iIiIii11I1 )
    if ( iiiIIiIIi1 != I111i ) :
     O00O00Oo = 15
     I111i = iiiIIiIIi1
     if 74 - 74: i11iIiiIii . Ii1I . I1IiiI * I1IiiI
     if 51 - 51: oO0o . Oo0Ooo / i1IIi + i1IIi * i1IIi
     if 32 - 32: I1IiiI + IiII + iII111i . iIii1I11I1II1 * Ii1I
     if 27 - 27: oO0o + Ii1I . i11iIiiIii
     if 97 - 97: iII111i . I1IiiI
     if 71 - 71: OOooOOo - IiII % oO0o * I1ii11iIi11i
     if 48 - 48: o0oOOo0O0Ooo * iIii1I11I1II1 + Oo0Ooo
     if 45 - 45: oO0o
  if ( o0O0oOo . force_ttl != None ) :
   O00O00Oo = o0O0oOo . force_ttl | 0x80000000
   if 50 - 50: Ii1I * Ii1I / O0 . Oo0Ooo + iII111i
   if 9 - 9: OoooooooOO % O0 % I1ii11iIi11i
   if 100 - 100: i11iIiiIii - iII111i - I11i
   if 5 - 5: oO0o % IiII * iII111i
   if 98 - 98: iII111i / OOooOOo + IiII
   if 100 - 100: II111iiii . i11iIiiIii / oO0o - OOooOOo + OoOoOO00 % I1ii11iIi11i
  if ( oOo0oO ) :
   if ( oOo0oO . set_record_ttl ) :
    O00O00Oo = oOo0oO . set_record_ttl
    lprint ( "Policy set-record-ttl to {}" . format ( O00O00Oo ) )
    if 82 - 82: ooOoO0o % OOooOOo % Ii1I
   if ( oOo0oO . set_action == "drop" ) :
    lprint ( "Policy set-action drop, send negative Map-Reply" )
    iiIiiIii1IiI = LISP_POLICY_DENIED_ACTION
    I111i = [ ]
   else :
    Oo0O0 = oOo0oO . set_policy_map_reply ( )
    if ( Oo0O0 ) : I111i = [ Oo0O0 ]
    if 82 - 82: I1ii11iIi11i
    if 52 - 52: i11iIiiIii % I1Ii111 - iII111i / O0 - I1ii11iIi11i / iII111i
    if 7 - 7: OoooooooOO . OOooOOo . OOooOOo
  if ( II11iiiIi ) :
   lprint ( "Implied drop action, send negative Map-Reply" )
   iiIiiIii1IiI = LISP_POLICY_DENIED_ACTION
   I111i = [ ]
   if 53 - 53: OOooOOo * OoOoOO00 % iII111i
   if 86 - 86: OOooOOo . OOooOOo + IiII - I1ii11iIi11i . OoO0O00
  Iiii = o0O0oOo . echo_nonce_capable
  if 66 - 66: I1IiiI * OoOoOO00 . I1IiiI / Oo0Ooo - Ii1I
  if 69 - 69: iIii1I11I1II1 % iII111i + ooOoO0o * i1IIi + iII111i * I1Ii111
  if 67 - 67: Ii1I % Oo0Ooo - Oo0Ooo . I11i + IiII
  if 73 - 73: Oo0Ooo + iIii1I11I1II1 . iIii1I11I1II1
  if ( I1i11 ) :
   o0OOO00 = o0O0oOo . eid
   OoOOOO0oo = o0O0oOo . group
  else :
   o0OOO00 = oOOOO
   OoOOOO0oo = iiI
   iiIiiIii1IiI = LISP_AUTH_FAILURE_ACTION
   I111i = [ ]
   if 4 - 4: i1IIi
   if 70 - 70: I1ii11iIi11i + iII111i . O0 . I1ii11iIi11i + Oo0Ooo / OOooOOo
   if 22 - 22: Ii1I
   if 48 - 48: Oo0Ooo / iIii1I11I1II1
   if 80 - 80: i1IIi + I1IiiI / OoooooooOO + OOooOOo . Ii1I
   if 96 - 96: iIii1I11I1II1 - I1ii11iIi11i
  packet = lisp_build_map_reply ( o0OOO00 , OoOOOO0oo , I111i ,
 I11iIi1i1I1i1 , iiIiiIii1IiI , O00O00Oo , False , None , Iiii , False )
  if 41 - 41: II111iiii - OoOoOO00 + OoooooooOO - I1ii11iIi11i . oO0o . o0oOOo0O0Ooo
  if ( II ) :
   lisp_process_pubsub ( lisp_sockets , packet , o0OOO00 , Ii1ii11i1i ,
 mr_sport , I11iIi1i1I1i1 , O00O00Oo , O0o0O0OoOo0 )
  else :
   lisp_send_map_reply ( lisp_sockets , packet , Ii1ii11i1i , mr_sport )
   if 34 - 34: I1ii11iIi11i % I11i / Oo0Ooo * oO0o % ooOoO0o / OOooOOo
   if 50 - 50: O0 * O0 / iIii1I11I1II1
  return ( [ o0O0oOo . eid , o0O0oOo . group , LISP_DDT_ACTION_MS_ACK ] )
  if 31 - 31: I1IiiI / o0oOOo0O0Ooo
  if 70 - 70: I1IiiI
  if 36 - 36: ooOoO0o . oO0o . I11i - I1ii11iIi11i / OoOoOO00 * Oo0Ooo
  if 42 - 42: OoooooooOO / o0oOOo0O0Ooo . Ii1I * iII111i * I1IiiI - Oo0Ooo
  if 76 - 76: oO0o * II111iiii
 iI1Oo0000O0o0 = len ( o0O0oOo . registered_rlocs )
 if ( iI1Oo0000O0o0 == 0 ) :
  lprint ( "Requested EID {} found site '{}' with EID-prefix {} with " + "no registered RLOCs" . format ( green ( OO0OO0O , False ) , oOO0O0o ,
  # I11i . iIii1I11I1II1 . I11i + oO0o + I1IiiI
 green ( OO0oO0 , False ) ) )
  return ( [ o0O0oOo . eid , o0O0oOo . group , LISP_DDT_ACTION_MS_ACK ] )
  if 85 - 85: I1Ii111
  if 1 - 1: o0oOOo0O0Ooo % oO0o * I1Ii111 - i1IIi - iII111i . oO0o
  if 25 - 25: i1IIi * o0oOOo0O0Ooo / oO0o
  if 11 - 11: IiII + II111iiii
  if 37 - 37: O0
 o0oo0OoOo000 = map_request . target_eid if map_request . source_eid . is_null ( ) else map_request . source_eid
 if 35 - 35: I11i + OoooooooOO
 I11111ii1i = map_request . target_eid . hash_address ( o0oo0OoOo000 )
 I11111ii1i %= iI1Oo0000O0o0
 O0iiI11111i = o0O0oOo . registered_rlocs [ I11111ii1i ]
 if 69 - 69: O0 . I1Ii111 % ooOoO0o - I1ii11iIi11i . Ii1I
 if ( O0iiI11111i . rloc . is_null ( ) ) :
  lprint ( ( "Suppress forwarding Map-Request for EID {} at site '{}' " + "EID-prefix {}, no RLOC address" ) . format ( green ( OO0OO0O , False ) ,
  # OoooooooOO
 oOO0O0o , green ( OO0oO0 , False ) ) )
 else :
  lprint ( ( "Forwarding Map-Request for EID {} to ETR {} at site '{}' " + "EID-prefix {}" ) . format ( green ( OO0OO0O , False ) ,
  # II111iiii
 red ( O0iiI11111i . rloc . print_address ( ) , False ) , oOO0O0o ,
 green ( OO0oO0 , False ) ) )
  if 77 - 77: OoooooooOO
  if 92 - 92: oO0o
  if 49 - 49: i11iIiiIii + OoO0O00 - OOooOOo
  if 9 - 9: II111iiii * OOooOOo / Oo0Ooo + iIii1I11I1II1 % I1IiiI
  lisp_send_ecm ( lisp_sockets , packet , map_request . source_eid , mr_sport ,
 map_request . target_eid , O0iiI11111i . rloc , to_etr = True )
  if 95 - 95: I1Ii111 . IiII % OoO0O00 - OOooOOo - I11i
 return ( [ o0O0oOo . eid , o0O0oOo . group , LISP_DDT_ACTION_MS_ACK ] )
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
 oOOOO = map_request . target_eid
 iiI = map_request . target_group
 OO0OO0O = lisp_print_eid_tuple ( oOOOO , iiI )
 I11iIi1i1I1i1 = map_request . nonce
 iiIiiIii1IiI = LISP_DDT_ACTION_NULL
 if 93 - 93: OoOoOO00 * i1IIi . Ii1I
 if 2 - 2: i1IIi
 if 84 - 84: i1IIi / Ii1I + OoOoOO00 % Ii1I . oO0o
 if 74 - 74: OOooOOo - o0oOOo0O0Ooo - I1Ii111 - OoO0O00
 if 40 - 40: o0oOOo0O0Ooo . IiII * OoOoOO00
 iii1i111I = None
 if ( lisp_i_am_ms ) :
  o0O0oOo = lisp_site_eid_lookup ( oOOOO , iiI , False )
  if ( o0O0oOo == None ) : return
  if 8 - 8: Ii1I % OoOoOO00 % II111iiii * ooOoO0o + I1IiiI
  if ( o0O0oOo . registered ) :
   iiIiiIii1IiI = LISP_DDT_ACTION_MS_ACK
   O00O00Oo = 1440
  else :
   oOOOO , iiI , iiIiiIii1IiI = lisp_ms_compute_neg_prefix ( oOOOO , iiI )
   iiIiiIii1IiI = LISP_DDT_ACTION_MS_NOT_REG
   O00O00Oo = 1
   if 19 - 19: OoO0O00 * ooOoO0o % I1ii11iIi11i
 else :
  iii1i111I = lisp_ddt_cache_lookup ( oOOOO , iiI , False )
  if ( iii1i111I == None ) :
   iiIiiIii1IiI = LISP_DDT_ACTION_NOT_AUTH
   O00O00Oo = 0
   lprint ( "DDT delegation entry not found for EID {}" . format ( green ( OO0OO0O , False ) ) )
   if 21 - 21: OoO0O00 * I11i
  elif ( iii1i111I . is_auth_prefix ( ) ) :
   if 76 - 76: I1IiiI - I1ii11iIi11i / I1ii11iIi11i . o0oOOo0O0Ooo % OoooooooOO
   if 39 - 39: OoooooooOO % iII111i
   if 55 - 55: IiII . i11iIiiIii % OoooooooOO
   if 88 - 88: Ii1I * o0oOOo0O0Ooo / oO0o
   iiIiiIii1IiI = LISP_DDT_ACTION_DELEGATION_HOLE
   O00O00Oo = 15
   oOoo = iii1i111I . print_eid_tuple ( )
   lprint ( ( "DDT delegation entry not found but auth-prefix {} " + "found for EID {}" ) . format ( oOoo ,
   # I11i % I1IiiI
 green ( OO0OO0O , False ) ) )
   if 82 - 82: i11iIiiIii * i11iIiiIii + I1Ii111 - I1ii11iIi11i * oO0o - Ii1I
   if ( iiI . is_null ( ) ) :
    oOOOO = lisp_ddt_compute_neg_prefix ( oOOOO , iii1i111I ,
 lisp_ddt_cache )
   else :
    iiI = lisp_ddt_compute_neg_prefix ( iiI , iii1i111I ,
 lisp_ddt_cache )
    oOOOO = lisp_ddt_compute_neg_prefix ( oOOOO , iii1i111I ,
 iii1i111I . source_cache )
    if 40 - 40: o0oOOo0O0Ooo + OoO0O00 % i1IIi % iII111i * I1Ii111
   iii1i111I = None
  else :
   oOoo = iii1i111I . print_eid_tuple ( )
   lprint ( "DDT delegation entry {} found for EID {}" . format ( oOoo , green ( OO0OO0O , False ) ) )
   if 36 - 36: I1ii11iIi11i % II111iiii % I1Ii111 / I1ii11iIi11i
   O00O00Oo = 1440
   if 34 - 34: OoooooooOO * i11iIiiIii
   if 33 - 33: II111iiii
   if 59 - 59: iIii1I11I1II1 % I11i
   if 93 - 93: I1ii11iIi11i
   if 50 - 50: ooOoO0o % OoO0O00 % OoO0O00
   if 36 - 36: I1IiiI * O0 . IiII / I1Ii111
 iIIi1 = lisp_build_map_referral ( oOOOO , iiI , iii1i111I , iiIiiIii1IiI , O00O00Oo , I11iIi1i1I1i1 )
 I11iIi1i1I1i1 = map_request . nonce >> 32
 if ( map_request . nonce != 0 and I11iIi1i1I1i1 != 0xdfdf0e1d ) : port = LISP_CTRL_PORT
 lisp_send_map_referral ( lisp_sockets , iIIi1 , ecm_source , port )
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
 i1iIi = 0
 if 48 - 48: O0 + OoOoOO00 - O0
 if 79 - 79: ooOoO0o . OoOoOO00 / OoooooooOO - II111iiii
 if 48 - 48: Oo0Ooo
 if 59 - 59: OoO0O00 % o0oOOo0O0Ooo
 for i1iIi in range ( I1I11I111I ) :
  O0ooO0O0O00 = 1 << ( I1I11I111I - i1iIi - 1 )
  if ( I11ii1I11ii & O0ooO0O0O00 ) : break
  if 5 - 5: I1IiiI % I1IiiI + OoooooooOO / I1ii11iIi11i
  if 77 - 77: OOooOOo / i11iIiiIii % iII111i * oO0o
 if ( i1iIi > neg_prefix . mask_len ) : neg_prefix . mask_len = i1iIi
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
 oOOOO , ii1ii , iI11Ii1 = parms
 if 68 - 68: O0 - i1IIi % iII111i * I1ii11iIi11i + I11i
 if ( ii1ii == None ) :
  if ( entry . eid . instance_id != oOOOO . instance_id ) :
   return ( [ True , parms ] )
   if 94 - 94: iII111i / OoOoOO00 . o0oOOo0O0Ooo / iIii1I11I1II1
  if ( entry . eid . afi != oOOOO . afi ) : return ( [ True , parms ] )
 else :
  if ( entry . eid . is_more_specific ( ii1ii ) == False ) :
   return ( [ True , parms ] )
   if 94 - 94: OoO0O00 . ooOoO0o
   if 25 - 25: I1Ii111 % OOooOOo
   if 82 - 82: Ii1I
   if 17 - 17: iII111i . i1IIi . i1IIi
   if 76 - 76: OoooooooOO % IiII
   if 81 - 81: iII111i . OOooOOo * i1IIi
 lisp_find_negative_mask_len ( oOOOO , entry . eid , iI11Ii1 )
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
 i1iiIi1 = lisp_address ( group . afi , "" , 0 , 0 )
 i1iiIi1 . copy_address ( group )
 i1iiIi1 . mask_len = 0
 ii1ii = None
 if 53 - 53: Ii1I - I1Ii111 * IiII + I1Ii111 . iIii1I11I1II1 + i11iIiiIii
 if 19 - 19: O0 - i11iIiiIii + ooOoO0o % O0
 if 63 - 63: iII111i + iIii1I11I1II1 * OoOoOO00 . I1Ii111 / I11i * o0oOOo0O0Ooo
 if 6 - 6: OOooOOo . ooOoO0o % iII111i - o0oOOo0O0Ooo % I11i + i11iIiiIii
 if 6 - 6: i11iIiiIii
 if ( group . is_null ( ) ) :
  iii1i111I = lisp_ddt_cache . lookup_cache ( eid , False )
  if ( iii1i111I == None ) :
   iI11Ii1 . mask_len = iI11Ii1 . host_mask_len ( )
   i1iiIi1 . mask_len = i1iiIi1 . host_mask_len ( )
   return ( [ iI11Ii1 , i1iiIi1 , LISP_DDT_ACTION_NOT_AUTH ] )
   if 66 - 66: I1Ii111 * I1ii11iIi11i . Ii1I
  iIiIiiiiI = lisp_sites_by_eid
  if ( iii1i111I . is_auth_prefix ( ) ) : ii1ii = iii1i111I . eid
 else :
  iii1i111I = lisp_ddt_cache . lookup_cache ( group , False )
  if ( iii1i111I == None ) :
   iI11Ii1 . mask_len = iI11Ii1 . host_mask_len ( )
   i1iiIi1 . mask_len = i1iiIi1 . host_mask_len ( )
   return ( [ iI11Ii1 , i1iiIi1 , LISP_DDT_ACTION_NOT_AUTH ] )
   if 78 - 78: I1Ii111 % Oo0Ooo . i11iIiiIii % OoooooooOO
  if ( iii1i111I . is_auth_prefix ( ) ) : ii1ii = iii1i111I . group
  if 2 - 2: O0 - i11iIiiIii + I1Ii111 - i11iIiiIii + I11i * iIii1I11I1II1
  group , ii1ii , i1iiIi1 = lisp_sites_by_eid . walk_cache ( lisp_neg_prefix_walk , ( group , ii1ii , i1iiIi1 ) )
  if 23 - 23: OoO0O00
  if 63 - 63: o0oOOo0O0Ooo - I1IiiI % OOooOOo
  i1iiIi1 . mask_address ( i1iiIi1 . mask_len )
  if 34 - 34: I1ii11iIi11i - I1IiiI . iII111i / I1Ii111 + oO0o + OOooOOo
  lprint ( ( "Least specific prefix computed from site-cache for " + "group EID {} using auth-prefix {} is {}" ) . format ( group . print_address ( ) , ii1ii . print_prefix ( ) if ( ii1ii != None ) else "'not found'" ,
  # OoooooooOO
  # o0oOOo0O0Ooo + Ii1I . iIii1I11I1II1
  # i1IIi * I1ii11iIi11i
 i1iiIi1 . print_prefix ( ) ) )
  if 77 - 77: ooOoO0o . II111iiii
  iIiIiiiiI = iii1i111I . source_cache
  if 41 - 41: IiII
  if 27 - 27: IiII / IiII
  if 91 - 91: Ii1I
  if 93 - 93: OoO0O00 * OoO0O00 * I1ii11iIi11i * OoO0O00 * o0oOOo0O0Ooo
  if 84 - 84: I1Ii111 * OoO0O00 - ooOoO0o - Oo0Ooo . OoO0O00 % oO0o
 iiIiiIii1IiI = LISP_DDT_ACTION_DELEGATION_HOLE if ( ii1ii != None ) else LISP_DDT_ACTION_NOT_AUTH
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
 return ( [ iI11Ii1 , i1iiIi1 , iiIiiIii1IiI ] )
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
 oOOOO = map_request . target_eid
 iiI = map_request . target_group
 I11iIi1i1I1i1 = map_request . nonce
 if 82 - 82: I11i % IiII + Oo0Ooo + iIii1I11I1II1 - I11i - I1IiiI
 if ( action == LISP_DDT_ACTION_MS_ACK ) : O00O00Oo = 1440
 if 65 - 65: IiII / O0 * II111iiii + oO0o
 if 52 - 52: o0oOOo0O0Ooo - OoOoOO00 * II111iiii / OoooooooOO
 if 44 - 44: OOooOOo - oO0o + o0oOOo0O0Ooo - i1IIi % o0oOOo0O0Ooo
 if 79 - 79: iII111i . iIii1I11I1II1
 OoOOOO0Oo0oO = lisp_map_referral ( )
 OoOOOO0Oo0oO . record_count = 1
 OoOOOO0Oo0oO . nonce = I11iIi1i1I1i1
 iIIi1 = OoOOOO0Oo0oO . encode ( )
 OoOOOO0Oo0oO . print_map_referral ( )
 if 42 - 42: i11iIiiIii / IiII . O0 / OOooOOo . iII111i * i1IIi
 i1IiIi1II11ii = False
 if 83 - 83: iIii1I11I1II1 . II111iiii * Oo0Ooo . I1IiiI - I1IiiI - iIii1I11I1II1
 if 29 - 29: Oo0Ooo
 if 35 - 35: OoOoOO00 + II111iiii
 if 46 - 46: O0 / I1ii11iIi11i + OOooOOo - I1Ii111 + I1IiiI - ooOoO0o
 if 96 - 96: IiII + i1IIi - I11i * I11i - OoO0O00 % II111iiii
 if 47 - 47: I1Ii111 . i11iIiiIii + oO0o . I1ii11iIi11i
 if ( action == LISP_DDT_ACTION_SITE_NOT_FOUND ) :
  eid_prefix , group_prefix , action = lisp_ms_compute_neg_prefix ( oOOOO ,
 iiI )
  O00O00Oo = 15
  if 12 - 12: iIii1I11I1II1 % I1Ii111 * OoOoOO00 / OoooooooOO % OoooooooOO
 if ( action == LISP_DDT_ACTION_MS_NOT_REG ) : O00O00Oo = 1
 if ( action == LISP_DDT_ACTION_MS_ACK ) : O00O00Oo = 1440
 if ( action == LISP_DDT_ACTION_DELEGATION_HOLE ) : O00O00Oo = 15
 if ( action == LISP_DDT_ACTION_NOT_AUTH ) : O00O00Oo = 0
 if 81 - 81: iIii1I11I1II1 - Oo0Ooo - ooOoO0o . OoO0O00 + I1ii11iIi11i
 O0I11Ii1I1111i1 = False
 iI1Oo0000O0o0 = 0
 iii1i111I = lisp_ddt_cache_lookup ( oOOOO , iiI , False )
 if ( iii1i111I != None ) :
  iI1Oo0000O0o0 = len ( iii1i111I . delegation_set )
  O0I11Ii1I1111i1 = iii1i111I . is_ms_peer_entry ( )
  iii1i111I . map_referrals_sent += 1
  if 46 - 46: iIii1I11I1II1
  if 78 - 78: I1ii11iIi11i - IiII - Oo0Ooo % iII111i % I11i
  if 42 - 42: Oo0Ooo . OoO0O00
  if 22 - 22: ooOoO0o - o0oOOo0O0Ooo + I11i / I1IiiI + OOooOOo
  if 10 - 10: oO0o / I1IiiI
 if ( action == LISP_DDT_ACTION_NOT_AUTH ) : i1IiIi1II11ii = True
 if ( action in ( LISP_DDT_ACTION_MS_REFERRAL , LISP_DDT_ACTION_MS_ACK ) ) :
  i1IiIi1II11ii = ( O0I11Ii1I1111i1 == False )
  if 95 - 95: II111iiii - IiII % IiII . o0oOOo0O0Ooo
  if 19 - 19: II111iiii . ooOoO0o . I11i - OoooooooOO / I1ii11iIi11i . I1Ii111
  if 57 - 57: II111iiii . I1Ii111 . i11iIiiIii / OoOoOO00 - O0
  if 56 - 56: OOooOOo / I1Ii111
  if 13 - 13: oO0o + Oo0Ooo + Oo0Ooo / OoO0O00 + i1IIi + I1IiiI
 oooOoO00o0 = lisp_eid_record ( )
 oooOoO00o0 . rloc_count = iI1Oo0000O0o0
 oooOoO00o0 . authoritative = True
 oooOoO00o0 . action = action
 oooOoO00o0 . ddt_incomplete = i1IiIi1II11ii
 oooOoO00o0 . eid = eid_prefix
 oooOoO00o0 . group = group_prefix
 oooOoO00o0 . record_ttl = O00O00Oo
 if 56 - 56: OoOoOO00
 iIIi1 += oooOoO00o0 . encode ( )
 oooOoO00o0 . print_record ( "  " , True )
 if 10 - 10: iIii1I11I1II1 + i1IIi * Ii1I / iIii1I11I1II1 % OoOoOO00 / O0
 if 14 - 14: O0
 if 65 - 65: IiII / oO0o
 if 57 - 57: IiII + oO0o - IiII
 if ( iI1Oo0000O0o0 != 0 ) :
  for IiIiiI1iiiI in iii1i111I . delegation_set :
   ooOo0OooO = lisp_rloc_record ( )
   ooOo0OooO . rloc = IiIiiI1iiiI . delegate_address
   ooOo0OooO . priority = IiIiiI1iiiI . priority
   ooOo0OooO . weight = IiIiiI1iiiI . weight
   ooOo0OooO . mpriority = 255
   ooOo0OooO . mweight = 0
   ooOo0OooO . reach_bit = True
   iIIi1 += ooOo0OooO . encode ( )
   ooOo0OooO . print_record ( "    " )
   if 51 - 51: OoOoOO00 % IiII / iII111i - oO0o - OoO0O00 . iIii1I11I1II1
   if 61 - 61: OoO0O00
   if 60 - 60: I1IiiI % O0 % OoooooooOO / Ii1I
   if 9 - 9: OoooooooOO / I11i % I11i * O0 / II111iiii . II111iiii
   if 40 - 40: II111iiii + OoooooooOO / iII111i % O0 + OOooOOo . ooOoO0o
   if 71 - 71: OoooooooOO + ooOoO0o * o0oOOo0O0Ooo + I1IiiI
   if 47 - 47: oO0o
 if ( map_request . nonce != 0 ) : port = LISP_CTRL_PORT
 lisp_send_map_referral ( lisp_sockets , iIIi1 , ecm_source , port )
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
 iiIiiIii1IiI = LISP_NATIVE_FORWARD_ACTION if group . is_null ( ) else LISP_DROP_ACTION
 if 23 - 23: O0 . OoO0O00 . i1IIi
 if 19 - 19: O0 . OoooooooOO % iIii1I11I1II1 - Ii1I . Ii1I + I1IiiI
 if 98 - 98: oO0o . Oo0Ooo
 if 9 - 9: I1Ii111 % IiII - i11iIiiIii - OOooOOo % iII111i % OoooooooOO
 if 6 - 6: i1IIi - II111iiii * OoOoOO00 + oO0o
 if ( lisp_get_eid_hash ( eid ) != None ) :
  iiIiiIii1IiI = LISP_SEND_MAP_REQUEST_ACTION
  if 6 - 6: I1IiiI - ooOoO0o + I1IiiI + OoO0O00 - i11iIiiIii % ooOoO0o
  if 64 - 64: OoooooooOO + OOooOOo
 iIIi1 = lisp_build_map_reply ( eid , group , [ ] , nonce , iiIiiIii1IiI , ttl , False ,
 None , False , False )
 if 36 - 36: I1IiiI - Ii1I / I1ii11iIi11i + Oo0Ooo % I1ii11iIi11i
 if 86 - 86: iIii1I11I1II1 * OoO0O00
 if 82 - 82: I1IiiI - OoO0O00 % o0oOOo0O0Ooo
 if 72 - 72: O0 + OoOoOO00 % OOooOOo / oO0o / IiII
 if ( pubsub ) :
  lisp_process_pubsub ( sockets , iIIi1 , eid , dest , port , nonce , ttl ,
 xtr_id )
 else :
  lisp_send_map_reply ( sockets , iIIi1 , dest , port )
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
 IiiI = mr . mr_source . print_address ( )
 ii1I11iiIiIii = mr . print_eid_tuple ( )
 I11iIi1i1I1i1 = mr . nonce
 if 60 - 60: iII111i / I1IiiI / i11iIiiIii
 if 85 - 85: OoOoOO00 - oO0o
 if 40 - 40: i11iIiiIii % iIii1I11I1II1 . ooOoO0o - I11i
 if 96 - 96: ooOoO0o + Ii1I / I1Ii111
 if 85 - 85: i1IIi / I1Ii111 * Oo0Ooo + O0
 if ( mr . last_request_sent_to ) :
  iiII11I = mr . last_request_sent_to . print_address ( )
  i11iII1I1I1i1 = lisp_referral_cache_lookup ( mr . last_cached_prefix [ 0 ] ,
 mr . last_cached_prefix [ 1 ] , True )
  if ( i11iII1I1I1i1 and i11iII1I1I1i1 . referral_set . has_key ( iiII11I ) ) :
   i11iII1I1I1i1 . referral_set [ iiII11I ] . no_responses += 1
   if 65 - 65: iIii1I11I1II1 / OOooOOo
   if 2 - 2: I11i - OOooOOo / o0oOOo0O0Ooo
   if 14 - 14: I11i + Oo0Ooo + i11iIiiIii - i1IIi . O0
   if 47 - 47: o0oOOo0O0Ooo / i1IIi * IiII
   if 50 - 50: I11i
   if 9 - 9: iII111i . OoOoOO00 * iII111i
   if 54 - 54: i11iIiiIii * I1IiiI / IiII - OoO0O00 % i1IIi
 if ( mr . retry_count == LISP_MAX_MAP_NOTIFY_RETRIES ) :
  lprint ( "DDT Map-Request retry limit reached for EID {}, nonce 0x{}" . format ( green ( ii1I11iiIiIii , False ) , lisp_hex_string ( I11iIi1i1I1i1 ) ) )
  if 2 - 2: II111iiii - OoOoOO00
  mr . dequeue_map_request ( )
  return
  if 81 - 81: IiII / OOooOOo / OoooooooOO + II111iiii - OOooOOo . i11iIiiIii
  if 33 - 33: o0oOOo0O0Ooo - OoooooooOO
 mr . retry_count += 1
 if 30 - 30: i1IIi + II111iiii + OoOoOO00 + I1ii11iIi11i % ooOoO0o % OOooOOo
 oooOOO00o0 = green ( IiiI , False )
 O0o0oo0oOO0oO = green ( ii1I11iiIiIii , False )
 lprint ( "Retransmit DDT {} from {}ITR {} EIDs: {} -> {}, nonce 0x{}" . format ( bold ( "Map-Request" , False ) , "P" if mr . from_pitr else "" ,
 # iII111i - o0oOOo0O0Ooo + I1IiiI
 red ( mr . itr . print_address ( ) , False ) , oooOOO00o0 , O0o0oo0oOO0oO ,
 lisp_hex_string ( I11iIi1i1I1i1 ) ) )
 if 72 - 72: OoOoOO00
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
 I11111ii1i = dest_eid . hash_address ( source_eid )
 I11111ii1i = I11111ii1i % oOoOO
 return ( Ii1ii1IiiIiiI [ I11111ii1i ] )
 if 63 - 63: Ii1I + iIii1I11I1II1 - i11iIiiIii / OoOoOO00
 if 81 - 81: OOooOOo * Ii1I
 if 23 - 23: OoooooooOO * OOooOOo
 if 24 - 24: IiII + I1IiiI / OoooooooOO
 if 8 - 8: II111iiii . I1Ii111 * OoOoOO00 / iII111i - Oo0Ooo
 if 17 - 17: iII111i . O0
 if 27 - 27: I11i + iIii1I11I1II1 - i11iIiiIii
def lisp_send_ddt_map_request ( mr , send_to_root ) :
 O00O0o = mr . lisp_sockets
 I11iIi1i1I1i1 = mr . nonce
 Ii1ii1Ii11 = mr . itr
 oO0oOO0ooOo0 = mr . mr_source
 OO0OO0O = mr . print_eid_tuple ( )
 if 32 - 32: ooOoO0o
 if 9 - 9: I1Ii111
 if 77 - 77: OoooooooOO * I1Ii111
 if 63 - 63: IiII * oO0o * iIii1I11I1II1
 if 18 - 18: II111iiii * o0oOOo0O0Ooo % i11iIiiIii . OoOoOO00
 if ( mr . send_count == 8 ) :
  lprint ( "Giving up on map-request-queue entry {}, nonce 0x{}" . format ( green ( OO0OO0O , False ) , lisp_hex_string ( I11iIi1i1I1i1 ) ) )
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
  lprint ( "Jumping up to root for EID {}" . format ( green ( OO0OO0O , False ) ) )
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
 I11iIi1i1I1i1 , Ii1ii1Ii11 , mr . sport , 15 , None , False )
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
 I11I1 . group , I11iIi1i1I1i1 , Ii1ii1Ii11 , mr . sport , 1 , None , False )
  return
  if 9 - 9: iIii1I11I1II1
  if 57 - 57: i1IIi * OOooOOo
 lprint ( "Send DDT Map-Request to {} {} for EID {}, nonce 0x{}" . format ( oOoooooOoOoO . referral_address . print_address ( ) ,
 # i1IIi % IiII * Oo0Ooo
 I11I1 . print_referral_type ( ) , green ( OO0OO0O , False ) ,
 lisp_hex_string ( I11iIi1i1I1i1 ) ) )
 if 25 - 25: II111iiii
 if 8 - 8: OoO0O00
 if 17 - 17: iIii1I11I1II1 - Oo0Ooo
 if 25 - 25: O0 + I1ii11iIi11i
 ooOII1ii1ii1I1 = ( I11I1 . referral_type == LISP_DDT_ACTION_MS_REFERRAL or
 I11I1 . referral_type == LISP_DDT_ACTION_MS_ACK )
 lisp_send_ecm ( O00O0o , mr . packet , oO0oOO0ooOo0 , mr . sport , mr . eid ,
 oOoooooOoOoO . referral_address , to_ms = ooOII1ii1ii1I1 , ddt = True )
 if 21 - 21: i1IIi % Oo0Ooo - o0oOOo0O0Ooo / OoO0O00 / iII111i
 if 43 - 43: oO0o % O0 * I1ii11iIi11i + i11iIiiIii
 if 16 - 16: i1IIi . I11i + OoO0O00 % Ii1I * IiII + I1IiiI
 if 96 - 96: II111iiii + O0 - II111iiii
 mr . last_request_sent_to = oOoooooOoOoO . referral_address
 mr . last_sent = lisp_get_timestamp ( )
 mr . send_count += 1
 oOoooooOoOoO . map_requests_sent += 1
 return
 if 97 - 97: I1IiiI
 if 87 - 87: I11i + iIii1I11I1II1
 if 91 - 91: oO0o
 if 58 - 58: i11iIiiIii / Ii1I - OoooooooOO
 if 25 - 25: i1IIi * ooOoO0o % OOooOOo / I1IiiI
 if 75 - 75: i11iIiiIii
 if 38 - 38: iIii1I11I1II1
 if 80 - 80: OoO0O00
def lisp_mr_process_map_request ( lisp_sockets , packet , map_request , ecm_source ,
 sport , mr_source ) :
 if 72 - 72: I11i * II111iiii
 oOOOO = map_request . target_eid
 iiI = map_request . target_group
 ii1I11iiIiIii = map_request . print_eid_tuple ( )
 IiiI = mr_source . print_address ( )
 I11iIi1i1I1i1 = map_request . nonce
 if 82 - 82: I1Ii111 . OoO0O00 * II111iiii
 oooOOO00o0 = green ( IiiI , False )
 O0o0oo0oOO0oO = green ( ii1I11iiIiIii , False )
 lprint ( "Received Map-Request from {}ITR {} EIDs: {} -> {}, nonce 0x{}" . format ( "P" if map_request . pitr_bit else "" ,
 # II111iiii % OOooOOo . I1ii11iIi11i * OoooooooOO / OoO0O00 / I1IiiI
 red ( ecm_source . print_address ( ) , False ) , oooOOO00o0 , O0o0oo0oOO0oO ,
 lisp_hex_string ( I11iIi1i1I1i1 ) ) )
 if 48 - 48: i11iIiiIii / i1IIi
 if 80 - 80: i1IIi - iIii1I11I1II1 + OoooooooOO + ooOoO0o / IiII - I1ii11iIi11i
 if 90 - 90: I1IiiI * ooOoO0o - I11i + O0 - I11i
 if 59 - 59: OOooOOo % II111iiii
 iiIii = lisp_ddt_map_request ( lisp_sockets , packet , oOOOO , iiI , I11iIi1i1I1i1 )
 iiIii . packet = packet
 iiIii . itr = ecm_source
 iiIii . mr_source = mr_source
 iiIii . sport = sport
 iiIii . from_pitr = map_request . pitr_bit
 iiIii . queue_map_request ( )
 if 38 - 38: IiII . IiII
 lisp_send_ddt_map_request ( iiIii , False )
 return
 if 53 - 53: II111iiii + Ii1I * o0oOOo0O0Ooo
 if 47 - 47: Ii1I % OOooOOo . Oo0Ooo
 if 94 - 94: Ii1I - iIii1I11I1II1 + I1IiiI - iIii1I11I1II1 . o0oOOo0O0Ooo
 if 3 - 3: O0 / I11i + OoOoOO00 % IiII / i11iIiiIii
 if 25 - 25: II111iiii / I1ii11iIi11i % iIii1I11I1II1
 if 69 - 69: IiII
 if 36 - 36: I1IiiI / oO0o
def lisp_process_map_request ( lisp_sockets , packet , ecm_source , ecm_port ,
 mr_source , mr_port , ddt_request , ttl ) :
 if 72 - 72: i1IIi - I1ii11iIi11i . OOooOOo + I1Ii111 - ooOoO0o
 II11iII = packet
 oOOO0oo00oOO = lisp_map_request ( )
 packet = oOOO0oo00oOO . decode ( packet , mr_source , mr_port )
 if ( packet == None ) :
  lprint ( "Could not decode Map-Request packet" )
  return
  if 59 - 59: i1IIi . I1Ii111
  if 24 - 24: I1IiiI - IiII
 oOOO0oo00oOO . print_map_request ( )
 if 32 - 32: I1Ii111 . I1ii11iIi11i / OoooooooOO + I1Ii111 . I1Ii111
 if 52 - 52: O0 - I1Ii111 . oO0o
 if 43 - 43: IiII * Ii1I - I1ii11iIi11i * I1ii11iIi11i
 if 53 - 53: oO0o % I11i * OoO0O00 . i1IIi
 if ( oOOO0oo00oOO . rloc_probe ) :
  lisp_process_rloc_probe_request ( lisp_sockets , oOOO0oo00oOO ,
 mr_source , mr_port , ttl )
  return
  if 35 - 35: I11i . IiII + ooOoO0o
  if 19 - 19: O0 - i1IIi / I1Ii111
  if 14 - 14: I11i - i11iIiiIii
  if 49 - 49: oO0o . I1ii11iIi11i
  if 51 - 51: OOooOOo + o0oOOo0O0Ooo . OOooOOo
 if ( oOOO0oo00oOO . smr_bit ) :
  lisp_process_smr ( oOOO0oo00oOO )
  if 23 - 23: iIii1I11I1II1 + OoO0O00 / I1IiiI
  if 48 - 48: OoOoOO00 + I11i + oO0o . I1IiiI
  if 7 - 7: iII111i * i1IIi % OoOoOO00 % Ii1I . I1IiiI
  if 53 - 53: OOooOOo / I11i + OOooOOo / I1IiiI / OoO0O00
  if 12 - 12: i11iIiiIii % ooOoO0o / iII111i . IiII
 if ( oOOO0oo00oOO . smr_invoked_bit ) :
  lisp_process_smr_invoked_request ( oOOO0oo00oOO )
  if 68 - 68: OOooOOo / iIii1I11I1II1 + I1IiiI . ooOoO0o * IiII
  if 72 - 72: I1Ii111
  if 51 - 51: OoOoOO00
  if 61 - 61: Oo0Ooo / i1IIi + I1Ii111 - OoooooooOO / O0
  if 25 - 25: I1ii11iIi11i * i11iIiiIii / i1IIi
 if ( lisp_i_am_etr ) :
  lisp_etr_process_map_request ( lisp_sockets , oOOO0oo00oOO , mr_source ,
 mr_port , ttl )
  if 69 - 69: OOooOOo % ooOoO0o - i1IIi . Oo0Ooo
  if 35 - 35: iIii1I11I1II1 - I11i / iIii1I11I1II1 % ooOoO0o % I1IiiI
  if 46 - 46: oO0o
  if 5 - 5: i1IIi % o0oOOo0O0Ooo + OoOoOO00 - I11i . Ii1I
  if 33 - 33: II111iiii * o0oOOo0O0Ooo
 if ( lisp_i_am_ms ) :
  packet = II11iII
  oOOOO , iiI , iIII111iiII = lisp_ms_process_map_request ( lisp_sockets ,
 II11iII , oOOO0oo00oOO , mr_source , mr_port , ecm_source )
  if ( ddt_request ) :
   lisp_ms_send_map_referral ( lisp_sockets , oOOO0oo00oOO , ecm_source ,
 ecm_port , iIII111iiII , oOOOO , iiI )
   if 42 - 42: I11i / Oo0Ooo + I1IiiI + o0oOOo0O0Ooo
  return
  if 100 - 100: iII111i % iII111i + OOooOOo - I1ii11iIi11i % IiII % ooOoO0o
  if 57 - 57: Ii1I / IiII / I11i % I1IiiI
  if 49 - 49: Oo0Ooo + i1IIi % iII111i - I1IiiI + Ii1I
  if 96 - 96: I1ii11iIi11i % Oo0Ooo . OoO0O00 + OoooooooOO + I1ii11iIi11i * OOooOOo
  if 75 - 75: Ii1I * Oo0Ooo % iIii1I11I1II1 . O0 % oO0o
 if ( lisp_i_am_mr and not ddt_request ) :
  lisp_mr_process_map_request ( lisp_sockets , II11iII , oOOO0oo00oOO ,
 ecm_source , mr_port , mr_source )
  if 4 - 4: I1IiiI - i11iIiiIii / o0oOOo0O0Ooo
  if 54 - 54: i11iIiiIii + I1Ii111 . I1Ii111 * I1ii11iIi11i % I1Ii111 - OoooooooOO
  if 76 - 76: IiII + i1IIi + i11iIiiIii . oO0o
  if 23 - 23: ooOoO0o - OoO0O00 + oO0o . OOooOOo - I1IiiI
  if 66 - 66: iII111i % iII111i
 if ( lisp_i_am_ddt or ddt_request ) :
  packet = II11iII
  lisp_ddt_process_map_request ( lisp_sockets , oOOO0oo00oOO , ecm_source ,
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
 iiIii = lisp_get_map_resolver ( source , None )
 if ( iiIii == None ) : return
 if 95 - 95: i1IIi . ooOoO0o . Oo0Ooo
 if 13 - 13: OOooOOo - Oo0Ooo % O0 . I1Ii111
 if 66 - 66: I1IiiI + I11i
 if 58 - 58: I1ii11iIi11i
 iiIii . neg_map_replies_received += 1
 iiIii . last_reply = lisp_get_timestamp ( )
 if 7 - 7: oO0o - I11i
 if 59 - 59: Ii1I / o0oOOo0O0Ooo / OoO0O00 + IiII + i11iIiiIii
 if 64 - 64: o0oOOo0O0Ooo * IiII * IiII * iII111i % i11iIiiIii
 if 22 - 22: I1ii11iIi11i * II111iiii - OOooOOo % i11iIiiIii
 if ( ( iiIii . neg_map_replies_received % 100 ) == 0 ) : iiIii . total_rtt = 0
 if 10 - 10: OOooOOo / I1ii11iIi11i
 if 21 - 21: OoO0O00 % Oo0Ooo . o0oOOo0O0Ooo + IiII
 if 48 - 48: O0 / i1IIi / iII111i
 if 11 - 11: O0 - OoO0O00 + OoOoOO00 * ooOoO0o - Ii1I
 if ( iiIii . last_nonce == nonce ) :
  iiIii . total_rtt += ( time . time ( ) - iiIii . last_used )
  iiIii . last_nonce = 0
  if 82 - 82: Ii1I - O0 * ooOoO0o . ooOoO0o
 if ( ( iiIii . neg_map_replies_received % 10 ) == 0 ) : iiIii . last_nonce = 0
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
 iIiii1i1Ii = lisp_map_reply ( )
 packet = iIiii1i1Ii . decode ( packet )
 if ( packet == None ) :
  lprint ( "Could not decode Map-Reply packet" )
  return
  if 46 - 46: ooOoO0o + oO0o
 iIiii1i1Ii . print_map_reply ( )
 if 7 - 7: ooOoO0o * oO0o . i1IIi
 if 74 - 74: i1IIi * I11i + OoOoOO00 / OoO0O00 - oO0o / I11i
 if 90 - 90: IiII % I1ii11iIi11i % i1IIi
 if 63 - 63: Ii1I . I1IiiI + IiII / OoOoOO00 + ooOoO0o - iIii1I11I1II1
 Iiii11iiiI1 = None
 for ooOooo0OO in range ( iIiii1i1Ii . record_count ) :
  oooOoO00o0 = lisp_eid_record ( )
  packet = oooOoO00o0 . decode ( packet )
  if ( packet == None ) :
   lprint ( "Could not decode EID-record in Map-Reply packet" )
   return
   if 78 - 78: I1Ii111 % I1Ii111 + II111iiii * iII111i + ooOoO0o
  oooOoO00o0 . print_record ( "  " , False )
  if 100 - 100: OOooOOo . ooOoO0o + Ii1I + Ii1I
  if 70 - 70: ooOoO0o . iIii1I11I1II1 / oO0o
  if 18 - 18: Ii1I / OoooooooOO % i1IIi * o0oOOo0O0Ooo
  if 70 - 70: IiII % i1IIi / IiII - o0oOOo0O0Ooo . Oo0Ooo / O0
  if 54 - 54: o0oOOo0O0Ooo
  if ( oooOoO00o0 . rloc_count == 0 ) :
   lisp_store_mr_stats ( source , iIiii1i1Ii . nonce )
   if 53 - 53: II111iiii / IiII . i1IIi + I1Ii111 / OoO0O00 - OoooooooOO
   if 67 - 67: ooOoO0o . Ii1I - Oo0Ooo * iII111i . I11i - OOooOOo
  iIIiI1iiIi = ( oooOoO00o0 . group . is_null ( ) == False )
  if 39 - 39: IiII - i1IIi - IiII - OoooooooOO - I1ii11iIi11i
  if 66 - 66: IiII + i1IIi
  if 21 - 21: IiII / i11iIiiIii / OoOoOO00
  if 75 - 75: Ii1I . i1IIi / I1IiiI * iII111i . IiII / OoOoOO00
  if 58 - 58: ooOoO0o + OOooOOo / ooOoO0o / i11iIiiIii
  if ( lisp_decent_push_configured ) :
   iiIiiIii1IiI = oooOoO00o0 . action
   if ( iIIiI1iiIi and iiIiiIii1IiI == LISP_DROP_ACTION ) :
    if ( oooOoO00o0 . eid . is_local ( ) ) : continue
    if 95 - 95: ooOoO0o
    if 10 - 10: OoO0O00 % ooOoO0o * o0oOOo0O0Ooo
    if 37 - 37: Ii1I . o0oOOo0O0Ooo
    if 34 - 34: ooOoO0o * IiII . Ii1I + iIii1I11I1II1
    if 1 - 1: i11iIiiIii + I11i
    if 78 - 78: Ii1I % Oo0Ooo / OoO0O00 . iIii1I11I1II1 . II111iiii
    if 67 - 67: oO0o % I1Ii111
  if ( oooOoO00o0 . eid . is_null ( ) ) : continue
  if 72 - 72: I1IiiI . i11iIiiIii . OoOoOO00 + I1IiiI - I1Ii111 + iII111i
  if 15 - 15: I1IiiI
  if 88 - 88: IiII / I1ii11iIi11i % I11i + i11iIiiIii * O0 . I1Ii111
  if 69 - 69: Oo0Ooo - OOooOOo / I1IiiI . i11iIiiIii * OoO0O00
  if 45 - 45: I1Ii111 + OOooOOo
  if ( iIIiI1iiIi ) :
   oOooO0Oo0Oo0 = lisp_map_cache_lookup ( oooOoO00o0 . eid , oooOoO00o0 . group )
  else :
   oOooO0Oo0Oo0 = lisp_map_cache . lookup_cache ( oooOoO00o0 . eid , True )
   if 18 - 18: O0 * OoooooooOO % IiII - iIii1I11I1II1 % IiII * o0oOOo0O0Ooo
  IIIiii1 = ( oOooO0Oo0Oo0 == None )
  if 99 - 99: I11i
  if 61 - 61: i1IIi - i1IIi
  if 97 - 97: I11i + II111iiii / OoooooooOO + I1ii11iIi11i * o0oOOo0O0Ooo
  if 29 - 29: I1Ii111
  I111i = [ ]
  for OOOoOOo000oo in range ( oooOoO00o0 . rloc_count ) :
   ooOo0OooO = lisp_rloc_record ( )
   ooOo0OooO . keys = iIiii1i1Ii . keys
   packet = ooOo0OooO . decode ( packet , iIiii1i1Ii . nonce )
   if ( packet == None ) :
    lprint ( "Could not decode RLOC-record in Map-Reply packet" )
    return
    if 3 - 3: O0 / OOooOOo - iII111i
   ooOo0OooO . print_record ( "    " )
   if 60 - 60: I1IiiI
   Ii11IIiiI1I = None
   if ( oOooO0Oo0Oo0 ) : Ii11IIiiI1I = oOooO0Oo0Oo0 . get_rloc ( ooOo0OooO . rloc )
   if ( Ii11IIiiI1I ) :
    Oo0O0 = Ii11IIiiI1I
   else :
    Oo0O0 = lisp_rloc ( )
    if 18 - 18: O0
    if 26 - 26: i1IIi - iIii1I11I1II1
    if 8 - 8: I1Ii111
    if 86 - 86: i1IIi
    if 26 - 26: o0oOOo0O0Ooo % I1Ii111 / Oo0Ooo
    if 68 - 68: II111iiii / Oo0Ooo / Oo0Ooo
    if 1 - 1: Oo0Ooo
   i1I1IIIi11I = Oo0O0 . store_rloc_from_record ( ooOo0OooO , iIiii1i1Ii . nonce ,
 source )
   Oo0O0 . echo_nonce_capable = iIiii1i1Ii . echo_nonce_capable
   if 73 - 73: Ii1I * iIii1I11I1II1 / o0oOOo0O0Ooo - o0oOOo0O0Ooo / i1IIi
   if ( Oo0O0 . echo_nonce_capable ) :
    oooOO0oOooO00 = Oo0O0 . rloc . print_address_no_iid ( )
    if ( lisp_get_echo_nonce ( None , oooOO0oOooO00 ) == None ) :
     lisp_echo_nonce ( oooOO0oOooO00 )
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
   if ( iIiii1i1Ii . rloc_probe and ooOo0OooO . probe_bit ) :
    if ( Oo0O0 . rloc . afi == source . afi ) :
     lisp_process_rloc_probe_reply ( Oo0O0 . rloc , source , i1I1IIIi11I ,
 iIiii1i1Ii . nonce , iIiii1i1Ii . hop_count , ttl )
     if 54 - 54: Ii1I + I1IiiI * OoOoOO00 + oO0o
     if 10 - 10: Ii1I - I1IiiI / IiII / iII111i - I1Ii111 - o0oOOo0O0Ooo
     if 75 - 75: OOooOOo . ooOoO0o
     if 32 - 32: i1IIi / I11i + iIii1I11I1II1 . OOooOOo
     if 67 - 67: iII111i - OoO0O00 % I1ii11iIi11i * Oo0Ooo
     if 51 - 51: I1IiiI + O0
   I111i . append ( Oo0O0 )
   if 4 - 4: ooOoO0o / OoO0O00 * iIii1I11I1II1 * iIii1I11I1II1
   if 33 - 33: iII111i . iIii1I11I1II1 - Ii1I
   if 85 - 85: OoOoOO00
   if 57 - 57: Oo0Ooo - II111iiii - I1ii11iIi11i * oO0o
   if ( lisp_data_plane_security and Oo0O0 . rloc_recent_rekey ( ) ) :
    Iiii11iiiI1 = Oo0O0
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
  if ( iIiii1i1Ii . rloc_probe == False and lisp_nat_traversal ) :
   iiiIIiIIi1 = [ ]
   o0o0oO0oo0OOO = [ ]
   for Oo0O0 in I111i :
    if 36 - 36: OoO0O00 * IiII * I1ii11iIi11i
    if 71 - 71: OoO0O00 . I1IiiI % Ii1I + ooOoO0o / OoOoOO00
    if 57 - 57: II111iiii . oO0o - I11i + OoOoOO00
    if 14 - 14: OoO0O00 * I1IiiI . O0 / ooOoO0o - I1IiiI - I1IiiI
    if 43 - 43: OoO0O00 . Oo0Ooo % IiII + OOooOOo . OoO0O00 % i11iIiiIii
    if ( Oo0O0 . rloc . is_private_address ( ) ) :
     Oo0O0 . priority = 1
     Oo0O0 . state = LISP_RLOC_UNREACH_STATE
     iiiIIiIIi1 . append ( Oo0O0 )
     o0o0oO0oo0OOO . append ( Oo0O0 . rloc . print_address_no_iid ( ) )
     continue
     if 70 - 70: I11i
     if 71 - 71: iII111i
     if 40 - 40: II111iiii
     if 71 - 71: O0 + Ii1I . iII111i % Oo0Ooo % ooOoO0o + II111iiii
     if 1 - 1: II111iiii - oO0o
     if 66 - 66: I1ii11iIi11i + i1IIi / ooOoO0o . I1Ii111 % OoOoOO00
    if ( Oo0O0 . priority == 254 and lisp_i_am_rtr == False ) :
     iiiIIiIIi1 . append ( Oo0O0 )
     o0o0oO0oo0OOO . append ( Oo0O0 . rloc . print_address_no_iid ( ) )
     if 67 - 67: i1IIi * i11iIiiIii * I1IiiI
    if ( Oo0O0 . priority != 254 and lisp_i_am_rtr ) :
     iiiIIiIIi1 . append ( Oo0O0 )
     o0o0oO0oo0OOO . append ( Oo0O0 . rloc . print_address_no_iid ( ) )
     if 23 - 23: Oo0Ooo
     if 81 - 81: I1Ii111 % II111iiii - Oo0Ooo / I1IiiI + i11iIiiIii . I11i
     if 67 - 67: ooOoO0o . I1Ii111 . Oo0Ooo . Ii1I + iIii1I11I1II1 / OoooooooOO
   if ( o0o0oO0oo0OOO != [ ] ) :
    I111i = iiiIIiIIi1
    lprint ( "NAT-traversal optimized RLOC-set: {}" . format ( o0o0oO0oo0OOO ) )
    if 93 - 93: ooOoO0o * OoO0O00 - I1Ii111 / I1ii11iIi11i
    if 60 - 60: OoO0O00 / oO0o . I1IiiI + OoOoOO00 + I1ii11iIi11i % Ii1I
    if 70 - 70: i1IIi * II111iiii * I1IiiI
    if 7 - 7: OoooooooOO + II111iiii % o0oOOo0O0Ooo * O0 . OoO0O00 * OoooooooOO
    if 20 - 20: Oo0Ooo % OOooOOo
    if 8 - 8: OOooOOo
    if 92 - 92: iII111i / OOooOOo . IiII / I11i + o0oOOo0O0Ooo
  iiiIIiIIi1 = [ ]
  for Oo0O0 in I111i :
   if ( Oo0O0 . json != None ) : continue
   iiiIIiIIi1 . append ( Oo0O0 )
   if 99 - 99: II111iiii
  if ( iiiIIiIIi1 != [ ] ) :
   i111I11I = len ( I111i ) - len ( iiiIIiIIi1 )
   lprint ( "Pruning {} no-address RLOC-records for map-cache" . format ( i111I11I ) )
   if 70 - 70: O0 % I1ii11iIi11i
   I111i = iiiIIiIIi1
   if 28 - 28: IiII - i1IIi - I1Ii111 % Ii1I - IiII
   if 73 - 73: iIii1I11I1II1 . iIii1I11I1II1 + oO0o % i11iIiiIii . IiII
   if 33 - 33: IiII - OOooOOo / i11iIiiIii * iIii1I11I1II1
   if 2 - 2: i11iIiiIii % ooOoO0o
   if 56 - 56: IiII % ooOoO0o + I1IiiI % I11i - OOooOOo
   if 82 - 82: OoooooooOO . i1IIi . OoO0O00 . OoO0O00
   if 31 - 31: iIii1I11I1II1
   if 64 - 64: ooOoO0o
  if ( iIiii1i1Ii . rloc_probe and oOooO0Oo0Oo0 != None ) : I111i = oOooO0Oo0Oo0 . rloc_set
  if 30 - 30: OoO0O00 + o0oOOo0O0Ooo / iIii1I11I1II1
  if 69 - 69: IiII - OoooooooOO + iII111i + iII111i - Ii1I
  if 27 - 27: I1ii11iIi11i % Oo0Ooo * iIii1I11I1II1 * O0 / I11i * Oo0Ooo
  if 97 - 97: IiII % Oo0Ooo % OoOoOO00
  if 87 - 87: i11iIiiIii . oO0o * I1IiiI * I1Ii111
  OoooO = IIIiii1
  if ( oOooO0Oo0Oo0 and I111i != oOooO0Oo0Oo0 . rloc_set ) :
   oOooO0Oo0Oo0 . delete_rlocs_from_rloc_probe_list ( )
   OoooO = True
   if 88 - 88: I1IiiI - iIii1I11I1II1 % i1IIi . iIii1I11I1II1 + II111iiii
   if 73 - 73: Oo0Ooo * OoooooooOO . i1IIi . Oo0Ooo * Ii1I * OoOoOO00
   if 33 - 33: i11iIiiIii - o0oOOo0O0Ooo / I1ii11iIi11i
   if 32 - 32: Oo0Ooo - I1Ii111 - OOooOOo * o0oOOo0O0Ooo + I1Ii111 - iIii1I11I1II1
   if 18 - 18: Oo0Ooo + Oo0Ooo / I1Ii111
  i1iIi1I = oOooO0Oo0Oo0 . uptime if ( oOooO0Oo0Oo0 ) else None
  oOooO0Oo0Oo0 = lisp_mapping ( oooOoO00o0 . eid , oooOoO00o0 . group , I111i )
  oOooO0Oo0Oo0 . mapping_source = source
  oOooO0Oo0Oo0 . map_cache_ttl = oooOoO00o0 . store_ttl ( )
  oOooO0Oo0Oo0 . action = oooOoO00o0 . action
  oOooO0Oo0Oo0 . add_cache ( OoooO )
  if 24 - 24: oO0o - oO0o
  o0000o = "Add"
  if ( i1iIi1I ) :
   oOooO0Oo0Oo0 . uptime = i1iIi1I
   o0000o = "Replace"
   if 91 - 91: iII111i % i11iIiiIii * OoOoOO00 * i11iIiiIii % iIii1I11I1II1
   if 30 - 30: I11i . I1ii11iIi11i - i1IIi / i1IIi + IiII . oO0o
  lprint ( "{} {} map-cache with {} RLOCs" . format ( o0000o ,
 green ( oOooO0Oo0Oo0 . print_eid_tuple ( ) , False ) , len ( I111i ) ) )
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
   for Oo0O0 in oOooO0Oo0Oo0 . best_rloc_set :
    oooOO0oOooO00 = red ( Oo0O0 . rloc . print_address_no_iid ( ) , False )
    lprint ( "Trigger {} to {}" . format ( o0ooOOoO0O , oooOO0oOooO00 ) )
    lisp_send_map_request ( lisp_sockets , 0 , oOooO0Oo0Oo0 . eid , oOooO0Oo0Oo0 . group , Oo0O0 )
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
 I11111ii1i = lisp_hash_me ( packet , map_register . alg_id , password , False )
 if 77 - 77: i11iIiiIii + i11iIiiIii - I1ii11iIi11i % I1ii11iIi11i
 if 26 - 26: oO0o + OoooooooOO % o0oOOo0O0Ooo
 if 96 - 96: ooOoO0o * OoOoOO00 - II111iiii
 if 40 - 40: oO0o * OOooOOo + Ii1I + I11i * Ii1I + OoooooooOO
 map_register . auth_data = I11111ii1i
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
  I11111ii1i = hmac . new ( password , packet , Ii1IiI1111i ) . hexdigest ( )
 else :
  I11111ii1i = hmac . new ( password , packet , Ii1IiI1111i ) . digest ( )
  if 48 - 48: I1Ii111 % Ii1I + I1IiiI * OoooooooOO % OoOoOO00 % i11iIiiIii
 return ( I11111ii1i )
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
 I11111ii1i = lisp_hash_me ( packet , alg_id , password , True )
 OoO0OOo0Oo = ( I11111ii1i == auth_data )
 if 68 - 68: I1IiiI - i11iIiiIii . I1ii11iIi11i * OOooOOo
 if 43 - 43: II111iiii % O0 + o0oOOo0O0Ooo / Ii1I
 if 55 - 55: Oo0Ooo / Oo0Ooo - I1IiiI
 if 94 - 94: OoO0O00 % I11i
 if ( OoO0OOo0Oo == False ) :
  lprint ( "Hashed value: {} does not match packet value: {}" . format ( I11111ii1i , auth_data ) )
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
 OO0i1Ii1II11 = map_notify . etr
 i1I1IIIi11I = map_notify . etr_port
 if 24 - 24: i1IIi . OoOoOO00 / I1Ii111 + O0
 if 86 - 86: Ii1I * OoOoOO00 % I1ii11iIi11i + OOooOOo
 if 85 - 85: iII111i % i11iIiiIii
 if 78 - 78: i11iIiiIii / I11i / Oo0Ooo + II111iiii - I1ii11iIi11i / I1ii11iIi11i
 if 28 - 28: iIii1I11I1II1 / IiII - iIii1I11I1II1 . i1IIi - O0 * ooOoO0o
 if ( map_notify . retry_count == LISP_MAX_MAP_NOTIFY_RETRIES ) :
  lprint ( "Map-Notify with nonce 0x{} retry limit reached for ETR {}" . format ( map_notify . nonce_key , red ( OO0i1Ii1II11 . print_address ( ) , False ) ) )
  if 41 - 41: Ii1I + IiII
  if 37 - 37: I1Ii111 / o0oOOo0O0Ooo - ooOoO0o - OoooooooOO . I1ii11iIi11i % I1Ii111
  o0000oO = map_notify . nonce_key
  if ( lisp_map_notify_queue . has_key ( o0000oO ) ) :
   map_notify . retransmit_timer . cancel ( )
   lprint ( "Dequeue Map-Notify from retransmit queue, key is: {}" . format ( o0000oO ) )
   if 53 - 53: I1IiiI % OOooOOo + Ii1I - Ii1I
   try :
    lisp_map_notify_queue . pop ( o0000oO )
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
 red ( OO0i1Ii1II11 . print_address ( ) , False ) , map_notify . retry_count ) )
 if 32 - 32: ooOoO0o * OoO0O00 * oO0o / I1ii11iIi11i
 lisp_send_map_notify ( O00O0o , map_notify . packet , OO0i1Ii1II11 , i1I1IIIi11I )
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
  ooOo0OooO = lisp_rloc_record ( )
  ooOo0OooO . store_rloc_entry ( O0oOoooooO00o )
  IiI1iiIi1I1i += ooOo0OooO . encode ( )
  ooOo0OooO . print_record ( "  " )
  del ( ooOo0OooO )
  if 4 - 4: O0 / II111iiii % OoooooooOO - oO0o / Ii1I
  if 64 - 64: i1IIi + Ii1I - II111iiii % I1Ii111 / I11i
  if 2 - 2: I11i * o0oOOo0O0Ooo * OoOoOO00 % I1IiiI . I1IiiI
  if 69 - 69: O0 % I1Ii111 - i1IIi
  if 50 - 50: I1ii11iIi11i
 for O0oOoooooO00o in parent . registered_rlocs :
  OO0i1Ii1II11 = O0oOoooooO00o . rloc
  O00o0oOoO0OOo = lisp_map_notify ( lisp_sockets )
  O00o0oOoO0OOo . record_count = 1
  iIIi1OoOo0O00 = map_register . key_id
  O00o0oOoO0OOo . key_id = iIIi1OoOo0O00
  O00o0oOoO0OOo . alg_id = map_register . alg_id
  O00o0oOoO0OOo . auth_len = map_register . auth_len
  O00o0oOoO0OOo . nonce = map_register . nonce
  O00o0oOoO0OOo . nonce_key = lisp_hex_string ( O00o0oOoO0OOo . nonce )
  O00o0oOoO0OOo . etr . copy_address ( OO0i1Ii1II11 )
  O00o0oOoO0OOo . etr_port = map_register . sport
  O00o0oOoO0OOo . site = parent . site
  iIIi1 = O00o0oOoO0OOo . encode ( IiI1iiIi1I1i , parent . site . auth_key [ iIIi1OoOo0O00 ] )
  O00o0oOoO0OOo . print_notify ( )
  if 26 - 26: ooOoO0o + Oo0Ooo
  if 24 - 24: I1IiiI
  if 43 - 43: OoO0O00
  if 51 - 51: OoooooooOO % IiII % Oo0Ooo
  o0000oO = O00o0oOoO0OOo . nonce_key
  if ( lisp_map_notify_queue . has_key ( o0000oO ) ) :
   IiiiiII1i = lisp_map_notify_queue [ o0000oO ]
   IiiiiII1i . retransmit_timer . cancel ( )
   del ( IiiiiII1i )
   if 91 - 91: I1IiiI . I1Ii111 + II111iiii . Oo0Ooo
  lisp_map_notify_queue [ o0000oO ] = O00o0oOoO0OOo
  if 95 - 95: iII111i
  if 77 - 77: I1IiiI * II111iiii * iIii1I11I1II1
  if 19 - 19: OOooOOo * o0oOOo0O0Ooo
  if 64 - 64: I11i % ooOoO0o / OOooOOo / iII111i
  lprint ( "Send merged Map-Notify to ETR {}" . format ( red ( OO0i1Ii1II11 . print_address ( ) , False ) ) )
  if 80 - 80: i1IIi
  lisp_send ( lisp_sockets , OO0i1Ii1II11 , LISP_CTRL_PORT , iIIi1 )
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
 o0000oO = lisp_hex_string ( nonce ) + source . print_address ( )
 if 73 - 73: II111iiii + ooOoO0o % OOooOOo . oO0o / oO0o * i1IIi
 if 19 - 19: I1Ii111 + I11i
 if 21 - 21: OoOoOO00
 if 2 - 2: i1IIi . OOooOOo
 if 23 - 23: Ii1I - OOooOOo
 if 89 - 89: i11iIiiIii
 lisp_remove_eid_from_map_notify_queue ( eid_list )
 if ( lisp_map_notify_queue . has_key ( o0000oO ) ) :
  O00o0oOoO0OOo = lisp_map_notify_queue [ o0000oO ]
  oooOOO00o0 = red ( source . print_address_no_iid ( ) , False )
  lprint ( "Map-Notify with nonce 0x{} pending for xTR {}" . format ( lisp_hex_string ( O00o0oOoO0OOo . nonce ) , oooOOO00o0 ) )
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
  o0000oO = O00o0oOoO0OOo . nonce_key
  lisp_map_notify_queue [ o0000oO ] = O00o0oOoO0OOo
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
 iIIi1 = O00o0oOoO0OOo . encode ( eid_records , site . auth_key [ key_id ] )
 O00o0oOoO0OOo . print_notify ( )
 if 16 - 16: iIii1I11I1II1 / OOooOOo + I1IiiI * II111iiii . OOooOOo
 if ( map_register_ack == False ) :
  oooOoO00o0 = lisp_eid_record ( )
  oooOoO00o0 . decode ( eid_records )
  oooOoO00o0 . print_record ( "  " , False )
  if 68 - 68: IiII * IiII + oO0o / o0oOOo0O0Ooo
  if 41 - 41: OoOoOO00 - O0
  if 48 - 48: OoooooooOO % Ii1I * OoO0O00 / I1ii11iIi11i
  if 53 - 53: ooOoO0o + oO0o - II111iiii
  if 92 - 92: Oo0Ooo - I11i . ooOoO0o % oO0o
 lisp_send_map_notify ( lisp_sockets , iIIi1 , O00o0oOoO0OOo . etr , port )
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
 iIIi1 = map_notify . encode ( eid_records , ms . password )
 map_notify . print_notify ( )
 if 22 - 22: OoO0O00 * OoOoOO00 * I11i * IiII . OoO0O00 . I1ii11iIi11i
 if 32 - 32: o0oOOo0O0Ooo - iII111i + i11iIiiIii / ooOoO0o . OoOoOO00 . IiII
 if 9 - 9: iIii1I11I1II1
 if 66 - 66: iIii1I11I1II1
 OO0i1Ii1II11 = ms . map_server
 lprint ( "Send Map-Notify-Ack to {}" . format (
 red ( OO0i1Ii1II11 . print_address ( ) , False ) ) )
 lisp_send ( lisp_sockets , OO0i1Ii1II11 , LISP_CTRL_PORT , iIIi1 )
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
 o0000oO = O00o0oOoO0OOo . nonce_key
 if 76 - 76: i11iIiiIii % i11iIiiIii
 if 33 - 33: OOooOOo . ooOoO0o / iIii1I11I1II1 * OOooOOo / oO0o
 if 75 - 75: Ii1I - OoOoOO00 . OOooOOo - o0oOOo0O0Ooo - I1ii11iIi11i
 if 69 - 69: O0 % I1ii11iIi11i
 if 77 - 77: iIii1I11I1II1 . OOooOOo
 if 64 - 64: OoOoOO00 - i1IIi * i1IIi / iII111i * OoOoOO00 * OoO0O00
 lisp_remove_eid_from_map_notify_queue ( O00o0oOoO0OOo . eid_list )
 if ( lisp_map_notify_queue . has_key ( o0000oO ) ) :
  O00o0oOoO0OOo = lisp_map_notify_queue [ o0000oO ]
  lprint ( "Map-Notify with nonce 0x{} pending for ITR {}" . format ( O00o0oOoO0OOo . nonce , red ( xtr . print_address_no_iid ( ) , False ) ) )
  if 61 - 61: OOooOOo
  return
  if 51 - 51: Oo0Ooo * OOooOOo / iII111i
  if 49 - 49: ooOoO0o . i1IIi % I1Ii111 . I1IiiI . I1ii11iIi11i + OoO0O00
  if 65 - 65: I1ii11iIi11i + Ii1I / i11iIiiIii * I1Ii111 + OoooooooOO
  if 7 - 7: Oo0Ooo % o0oOOo0O0Ooo
  if 40 - 40: oO0o * IiII
 lisp_map_notify_queue [ o0000oO ] = O00o0oOoO0OOo
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
 oooOoO00o0 = lisp_eid_record ( )
 oooOoO00o0 . record_ttl = 1440
 oooOoO00o0 . eid . copy_address ( site_eid . eid )
 oooOoO00o0 . group . copy_address ( site_eid . group )
 oooOoO00o0 . rloc_count = 0
 for OOO0OOO000oOO0 in site_eid . registered_rlocs :
  if ( iii11II ^ OOO0OOO000oOO0 . is_rtr ( ) ) : continue
  oooOoO00o0 . rloc_count += 1
  if 87 - 87: iII111i + OoOoOO00 % ooOoO0o - oO0o
 iIIi1 = oooOoO00o0 . encode ( )
 if 40 - 40: i1IIi / OoOoOO00 - I11i / ooOoO0o . Ii1I
 if 8 - 8: I1IiiI . IiII . OOooOOo . O0
 if 3 - 3: Ii1I + i11iIiiIii
 if 87 - 87: ooOoO0o - iII111i % I11i
 O00o0oOoO0OOo . print_notify ( )
 oooOoO00o0 . print_record ( "  " , False )
 if 88 - 88: I11i . OoooooooOO
 if 86 - 86: Ii1I - I1IiiI - iII111i % Ii1I . I1ii11iIi11i % i1IIi
 if 84 - 84: OoOoOO00
 if 99 - 99: OoO0O00 - OoOoOO00 - i1IIi / OoO0O00 * I1ii11iIi11i * iIii1I11I1II1
 for OOO0OOO000oOO0 in site_eid . registered_rlocs :
  if ( iii11II ^ OOO0OOO000oOO0 . is_rtr ( ) ) : continue
  ooOo0OooO = lisp_rloc_record ( )
  ooOo0OooO . store_rloc_entry ( OOO0OOO000oOO0 )
  iIIi1 += ooOo0OooO . encode ( )
  ooOo0OooO . print_record ( "    " )
  if 65 - 65: iII111i - O0 / i1IIi . I1Ii111
  if 85 - 85: o0oOOo0O0Ooo % Ii1I
  if 81 - 81: oO0o / OoO0O00 * i1IIi % iIii1I11I1II1
  if 23 - 23: II111iiii . II111iiii
  if 17 - 17: i11iIiiIii / IiII * I1IiiI . Oo0Ooo / o0oOOo0O0Ooo - iIii1I11I1II1
 iIIi1 = O00o0oOoO0OOo . encode ( iIIi1 , "" )
 if ( iIIi1 == None ) : return
 if 21 - 21: OOooOOo % Ii1I
 if 3 - 3: OOooOOo / ooOoO0o / I1Ii111 . I11i
 if 54 - 54: I1ii11iIi11i - I1IiiI . OoOoOO00
 if 36 - 36: OoO0O00 * I1IiiI / iII111i
 lisp_send_map_notify ( lisp_sockets , iIIi1 , xtr , LISP_CTRL_PORT )
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
 for ooo00 in rle_list :
  IiIIIiiiii1iIII = lisp_site_eid_lookup ( ooo00 [ 0 ] , ooo00 [ 1 ] , True )
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
    for OOO0OOO000oOO0 in oo00oO0 . registered_rlocs :
     if ( OOO0OOO000oOO0 . is_rtr ( ) == False ) : continue
     O0oo [ OOO0OOO000oOO0 . rloc . print_address ( ) ] = OOO0OOO000oOO0
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
   iI111 = [ ] if len ( iiI1iIi1II1ii ) == 0 else iiI1iIi1II1ii [ 0 ] . rle . rle_nodes
   if 28 - 28: iII111i + O0 * ooOoO0o
   for iIiiI11iI111 in iI111 :
    o0O0OoO . append ( iIiiI11iI111 . address )
    oooO0O000O0O . append ( iIiiI11iI111 . address . print_address_no_iid ( ) )
    if 100 - 100: Oo0Ooo % II111iiii * oO0o / OOooOOo % IiII
   lprint ( "Notify existing RLE-nodes {}" . format ( oooO0O000O0O ) )
  else :
   if 33 - 33: Oo0Ooo . OoOoOO00 - II111iiii * II111iiii % I1IiiI
   if 34 - 34: I1Ii111 + OOooOOo * iII111i / ooOoO0o % i11iIiiIii
   if 91 - 91: IiII * Ii1I * OOooOOo
   if 17 - 17: o0oOOo0O0Ooo + Ii1I % I1ii11iIi11i + IiII % I1Ii111 + I1ii11iIi11i
   if 100 - 100: I11i * OoO0O00 - i1IIi + iII111i * Ii1I - OoooooooOO
   for OOO0OOO000oOO0 in iiI1iIi1II1ii :
    if ( OOO0OOO000oOO0 . is_rtr ( ) ) : o0O0OoO . append ( OOO0OOO000oOO0 . rloc )
    if 47 - 47: o0oOOo0O0Ooo / Ii1I - iII111i * OOooOOo / i11iIiiIii
    if 97 - 97: iIii1I11I1II1 + OoOoOO00 + OoOoOO00 * o0oOOo0O0Ooo
    if 14 - 14: II111iiii + I1ii11iIi11i * Oo0Ooo
    if 95 - 95: IiII + iII111i % I1IiiI
    if 18 - 18: Oo0Ooo
   Oo0oOOoO0O0o = ( len ( o0O0OoO ) != 0 )
   if ( Oo0oOOoO0O0o == False ) :
    o0O0oOo = lisp_site_eid_lookup ( ooo00 [ 0 ] , O00OO0oOooOOo , False )
    if ( o0O0oOo == None ) : continue
    if 8 - 8: O0 + iIii1I11I1II1 - O0
    for OOO0OOO000oOO0 in o0O0oOo . registered_rlocs :
     if ( OOO0OOO000oOO0 . rloc . is_null ( ) ) : continue
     o0O0OoO . append ( OOO0OOO000oOO0 . rloc )
     if 67 - 67: O0
     if 22 - 22: I11i / i1IIi . II111iiii % ooOoO0o / I11i - Ii1I
     if 28 - 28: O0 - Oo0Ooo
     if 58 - 58: iIii1I11I1II1 - OoooooooOO - iII111i
     if 43 - 43: ooOoO0o / o0oOOo0O0Ooo
     if 56 - 56: II111iiii * I1ii11iIi11i * O0 . iII111i . I1ii11iIi11i % I1Ii111
   if ( len ( o0O0OoO ) == 0 ) :
    lprint ( "No ITRs or RTRs found for {}, Map-Notify suppressed" . format ( green ( IiIIIiiiii1iIII . print_eid_tuple ( ) , False ) ) )
    if 99 - 99: Oo0Ooo - OoO0O00 + OoooooooOO - I1Ii111 - I1ii11iIi11i % i1IIi
    continue
    if 49 - 49: IiII % OoooooooOO / Oo0Ooo - OoOoOO00 + o0oOOo0O0Ooo / Ii1I
    if 6 - 6: I11i % IiII
    if 48 - 48: Ii1I
    if 100 - 100: OoO0O00 % I1Ii111 + OoooooooOO / OoO0O00
    if 62 - 62: IiII
    if 66 - 66: o0oOOo0O0Ooo % OOooOOo
  for O0oOoooooO00o in o0O0OoO :
   lprint ( "Build Map-Notify to {}TR {} for {}" . format ( "R" if Oo0oOOoO0O0o else "x" , red ( O0oOoooooO00o . print_address_no_iid ( ) , False ) ,
   # ooOoO0o
 green ( IiIIIiiiii1iIII . print_eid_tuple ( ) , False ) ) )
   if 72 - 72: IiII + IiII % iII111i - O0 * OoooooooOO
   oOo = [ IiIIIiiiii1iIII . print_eid_tuple ( ) ]
   lisp_send_multicast_map_notify ( lisp_sockets , IiIIIiiiii1iIII , oOo , O0oOoooooO00o )
   time . sleep ( .001 )
   if 79 - 79: O0 - Oo0Ooo . IiII
   if 79 - 79: ooOoO0o * OoooooooOO + iIii1I11I1II1 % I1IiiI
 return
 if 23 - 23: i11iIiiIii . O0 . OoOoOO00 * iIii1I11I1II1
 if 7 - 7: i1IIi % OoOoOO00 % OoooooooOO * Oo0Ooo
 if 53 - 53: oO0o
 if 23 - 23: I1ii11iIi11i . I1Ii111 + OOooOOo
 if 4 - 4: I1IiiI
 if 31 - 31: ooOoO0o * i1IIi . O0
 if 5 - 5: OOooOOo . I1ii11iIi11i + ooOoO0o . ooOoO0o + iII111i
 if 100 - 100: I1Ii111
def lisp_find_sig_in_rloc_set ( packet , rloc_count ) :
 for ooOooo0OO in range ( rloc_count ) :
  ooOo0OooO = lisp_rloc_record ( )
  packet = ooOo0OooO . decode ( packet , None )
  O0oo0OOo00o0o = ooOo0OooO . json
  if ( O0oo0OOo00o0o == None ) : continue
  if 18 - 18: iII111i
  try :
   O0oo0OOo00o0o = json . loads ( O0oo0OOo00o0o . json_string )
  except :
   lprint ( "Found corrupted JSON signature" )
   continue
   if 98 - 98: IiII . OOooOOo * ooOoO0o / OoO0O00
   if 21 - 21: OOooOOo / OoO0O00 + OoooooooOO
  if ( O0oo0OOo00o0o . has_key ( "signature" ) == False ) : continue
  return ( ooOo0OooO )
  if 66 - 66: II111iiii * I11i + iII111i * iII111i . i11iIiiIii % Ii1I
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
  iiI1iii = i1IIIII1 . instance_id
  if ( iiI1iii == - 1 ) : i1IIIII1 . instance_id = eid . instance_id
  if 63 - 63: iII111i - o0oOOo0O0Ooo * OOooOOo . Ii1I . Ii1I
  iiIiiiII11Iii1 = eid . is_more_specific ( i1IIIII1 )
  i1IIIII1 . instance_id = iiI1iii
  if ( iiIiiiII11Iii1 ) :
   iIi1I1i11iI = 128 - i1IIIII1 . mask_len
   break
   if 93 - 93: oO0o * Oo0Ooo / Ii1I * OoO0O00
   if 42 - 42: iII111i + IiII + I11i * ooOoO0o + Oo0Ooo . ooOoO0o
 if ( iIi1I1i11iI == None ) : return ( None )
 if 38 - 38: iII111i * OoooooooOO - IiII
 I1Ii11i = eid . address
 I1IiII11111Ii = ""
 for ooOooo0OO in range ( 0 , iIi1I1i11iI / 16 ) :
  o00Ooo0 = I1Ii11i & 0xffff
  o00Ooo0 = hex ( o00Ooo0 ) [ 2 : - 1 ]
  I1IiII11111Ii = o00Ooo0 . zfill ( 4 ) + ":" + I1IiII11111Ii
  I1Ii11i >>= 16
  if 85 - 85: II111iiii - O0 . i11iIiiIii . o0oOOo0O0Ooo + ooOoO0o - ooOoO0o
 if ( iIi1I1i11iI % 16 != 0 ) :
  o00Ooo0 = I1Ii11i & 0xff
  o00Ooo0 = hex ( o00Ooo0 ) [ 2 : - 1 ]
  I1IiII11111Ii = o00Ooo0 . zfill ( 2 ) + ":" + I1IiII11111Ii
  if 25 - 25: I1ii11iIi11i % Ii1I * O0 / I1IiiI % OOooOOo
 return ( I1IiII11111Ii [ 0 : - 1 ] )
 if 42 - 42: IiII - IiII - I1ii11iIi11i + i1IIi * Oo0Ooo
 if 80 - 80: oO0o + O0
 if 84 - 84: i1IIi - II111iiii
 if 2 - 2: i11iIiiIii - OoO0O00 * Oo0Ooo
 if 100 - 100: I1Ii111
 if 5 - 5: IiII % oO0o . I1IiiI * II111iiii + o0oOOo0O0Ooo / Ii1I
 if 55 - 55: Oo0Ooo / o0oOOo0O0Ooo
 if 51 - 51: I1IiiI + i11iIiiIii / ooOoO0o % I1IiiI + Oo0Ooo
 if 6 - 6: OoOoOO00 . O0
 if 44 - 44: ooOoO0o % I11i + ooOoO0o . oO0o
 if 70 - 70: O0 - I11i . iIii1I11I1II1 % I11i . OoOoOO00 % oO0o
def lisp_lookup_public_key ( eid ) :
 iiI1iii = eid . instance_id
 if 5 - 5: O0 * OoO0O00
 if 61 - 61: Ii1I / I11i + Ii1I . IiII - OoO0O00 - o0oOOo0O0Ooo
 if 84 - 84: OoooooooOO - Oo0Ooo
 if 86 - 86: O0 + OoO0O00 + O0 . I1IiiI
 if 82 - 82: OoOoOO00
 oOO = lisp_get_eid_hash ( eid )
 if ( oOO == None ) : return ( [ None , None , False ] )
 if 82 - 82: Oo0Ooo * OoooooooOO / ooOoO0o / I1IiiI
 oOO = "hash-" + oOO
 iIII = lisp_address ( LISP_AFI_NAME , oOO , len ( oOO ) , iiI1iii )
 iiI = lisp_address ( LISP_AFI_NONE , "" , 0 , iiI1iii )
 if 70 - 70: I1IiiI
 if 74 - 74: ooOoO0o * II111iiii
 if 96 - 96: i11iIiiIii . I1IiiI - II111iiii . I11i
 if 79 - 79: OoO0O00 . OoOoOO00 - i1IIi + Ii1I * i11iIiiIii . OoooooooOO
 o0O0oOo = lisp_site_eid_lookup ( iIII , iiI , True )
 if ( o0O0oOo == None ) : return ( [ iIII , None , False ] )
 if 83 - 83: o0oOOo0O0Ooo / oO0o
 if 24 - 24: Ii1I + oO0o / OoooooooOO % i11iIiiIii
 if 1 - 1: iII111i / I1Ii111 * I1IiiI + OoOoOO00 . OoooooooOO
 if 5 - 5: I1IiiI
 iiI111 = None
 for Oo0O0 in o0O0oOo . registered_rlocs :
  OoOO0OO000oo0 = Oo0O0 . json
  if ( OoOO0OO000oo0 == None ) : continue
  try :
   OoOO0OO000oo0 = json . loads ( OoOO0OO000oo0 . json_string )
  except :
   lprint ( "Registered RLOC JSON format is invalid for {}" . format ( oOO ) )
   if 57 - 57: oO0o
   return ( [ iIII , None , False ] )
   if 100 - 100: OoOoOO00 / OoOoOO00 - OOooOOo . Oo0Ooo
  if ( OoOO0OO000oo0 . has_key ( "public-key" ) == False ) : continue
  iiI111 = OoOO0OO000oo0 [ "public-key" ]
  break
  if 11 - 11: IiII - I1Ii111 - OoO0O00 * o0oOOo0O0Ooo
 return ( [ iIII , iiI111 , True ] )
 if 99 - 99: O0 - OoO0O00
 if 95 - 95: Ii1I . IiII * o0oOOo0O0Ooo
 if 91 - 91: I1Ii111
 if 49 - 49: I11i
 if 17 - 17: Oo0Ooo % o0oOOo0O0Ooo
 if 3 - 3: OoO0O00 . oO0o . oO0o . Ii1I
 if 100 - 100: i11iIiiIii / i1IIi . I1ii11iIi11i
 if 1 - 1: IiII * I1Ii111 / I1ii11iIi11i * i11iIiiIii
def lisp_verify_cga_sig ( eid , rloc_record ) :
 if 82 - 82: o0oOOo0O0Ooo * OoO0O00 / o0oOOo0O0Ooo % OoOoOO00 * iIii1I11I1II1 % O0
 if 10 - 10: ooOoO0o
 if 69 - 69: I11i + I1IiiI / oO0o
 if 89 - 89: i1IIi % OoOoOO00 . I1ii11iIi11i
 if 85 - 85: I1Ii111 - oO0o
 I111II11I = json . loads ( rloc_record . json . json_string )
 if 34 - 34: iIii1I11I1II1 / IiII + OoOoOO00 - IiII / ooOoO0o + OoOoOO00
 if ( lisp_get_eid_hash ( eid ) ) :
  i11iii1 = eid
 elif ( I111II11I . has_key ( "signature-eid" ) ) :
  oO0oo000O = I111II11I [ "signature-eid" ]
  i11iii1 = lisp_address ( LISP_AFI_IPV6 , oO0oo000O , 0 , 0 )
 else :
  lprint ( "  No signature-eid found in RLOC-record" )
  return ( False )
  if 14 - 14: ooOoO0o - OoooooooOO / iIii1I11I1II1
  if 98 - 98: i1IIi
  if 81 - 81: OoOoOO00 * i11iIiiIii + I1IiiI
  if 2 - 2: I11i - IiII + I1IiiI % OoO0O00 + iIii1I11I1II1 + oO0o
  if 49 - 49: I1IiiI * I1Ii111 . I1IiiI - II111iiii
 iIII , iiI111 , oOOoOo0 = lisp_lookup_public_key ( i11iii1 )
 if ( iIII == None ) :
  OO0OO0O = green ( i11iii1 . print_address ( ) , False )
  lprint ( "  Could not parse hash in EID {}" . format ( OO0OO0O ) )
  return ( False )
  if 48 - 48: i11iIiiIii + I1IiiI
  if 78 - 78: o0oOOo0O0Ooo
 IIIi = "found" if oOOoOo0 else bold ( "not found" , False )
 OO0OO0O = green ( iIII . print_address ( ) , False )
 lprint ( "  Lookup for crypto-hashed EID {} {}" . format ( OO0OO0O , IIIi ) )
 if ( oOOoOo0 == False ) : return ( False )
 if 24 - 24: i1IIi
 if ( iiI111 == None ) :
  lprint ( "  RLOC-record with public-key not found" )
  return ( False )
  if 54 - 54: iIii1I11I1II1 - IiII + o0oOOo0O0Ooo + I1ii11iIi11i + IiII
  if 99 - 99: Oo0Ooo
 iIiI111I = iiI111 [ 0 : 8 ] + "..." + iiI111 [ - 8 : : ]
 lprint ( "  RLOC-record with public-key '{}' found" . format ( iIiI111I ) )
 if 42 - 42: i11iIiiIii - O0 + O0
 if 83 - 83: Oo0Ooo / I1ii11iIi11i % OoO0O00
 if 29 - 29: IiII - I1ii11iIi11i . Oo0Ooo + IiII - I1IiiI
 if 95 - 95: O0 / o0oOOo0O0Ooo + OoO0O00 / IiII - IiII % OOooOOo
 if 16 - 16: I1IiiI * iIii1I11I1II1 % o0oOOo0O0Ooo - IiII - OOooOOo
 ooo0O0O0oOO = I111II11I [ "signature" ]
 if 68 - 68: IiII * O0 % OOooOOo
 try :
  I111II11I = binascii . a2b_base64 ( ooo0O0O0oOO )
 except :
  lprint ( "  Incorrect padding in signature string" )
  return ( False )
  if 26 - 26: ooOoO0o + OoooooooOO + ooOoO0o * I1Ii111
  if 26 - 26: I1IiiI - OOooOOo
 I1iiiII1i1 = len ( I111II11I )
 if ( I1iiiII1i1 & 1 ) :
  lprint ( "  Signature length is odd, length {}" . format ( I1iiiII1i1 ) )
  return ( False )
  if 2 - 2: IiII % iII111i / o0oOOo0O0Ooo * I11i
  if 35 - 35: OoOoOO00 * I1Ii111 / II111iiii / O0
  if 35 - 35: ooOoO0o * I11i
  if 85 - 85: i1IIi
  if 81 - 81: I1Ii111
 oOoO00OO00 = i11iii1 . print_address ( )
 if 28 - 28: i1IIi * ooOoO0o
 if 14 - 14: II111iiii + II111iiii - I11i / I11i . OoOoOO00 + OoO0O00
 if 92 - 92: II111iiii - II111iiii % IiII
 if 48 - 48: oO0o / II111iiii + oO0o
 iiI111 = binascii . a2b_base64 ( iiI111 )
 try :
  o0000oO = ecdsa . VerifyingKey . from_pem ( iiI111 )
 except :
  IIIiIiI1Ii = bold ( "Bad public-key" , False )
  lprint ( "  {}, not in PEM format" . format ( IIIiIiI1Ii ) )
  return ( False )
  if 4 - 4: II111iiii - o0oOOo0O0Ooo / i1IIi - Oo0Ooo
  if 26 - 26: o0oOOo0O0Ooo
  if 43 - 43: OoOoOO00 * ooOoO0o % OoooooooOO * o0oOOo0O0Ooo
  if 8 - 8: I1ii11iIi11i + Oo0Ooo - iII111i
  if 53 - 53: ooOoO0o / IiII
  if 36 - 36: iIii1I11I1II1
  if 78 - 78: II111iiii * I11i
  if 47 - 47: Ii1I
  if 42 - 42: I11i . oO0o - I1IiiI / OoO0O00
  if 75 - 75: I1IiiI / OoOoOO00 . I11i * iIii1I11I1II1
  if 53 - 53: iIii1I11I1II1
 try :
  oOo0 = o0000oO . verify ( I111II11I , oOoO00OO00 , hashfunc = hashlib . sha256 )
 except :
  lprint ( "  Signature library failed for signature data '{}'" . format ( oOoO00OO00 ) )
  if 8 - 8: O0 - O0 - II111iiii
  lprint ( "  Signature used '{}'" . format ( ooo0O0O0oOO ) )
  return ( False )
  if 77 - 77: i1IIi - ooOoO0o + O0 . OoO0O00 * I1Ii111 - I11i
 return ( oOo0 )
 if 64 - 64: i1IIi + OoooooooOO + OOooOOo / ooOoO0o % I1IiiI . OoooooooOO
 if 96 - 96: II111iiii - OoOoOO00 + oO0o
 if 80 - 80: oO0o / OoOoOO00 - I11i / oO0o - iII111i - OoooooooOO
 if 57 - 57: o0oOOo0O0Ooo
 if 37 - 37: iII111i * o0oOOo0O0Ooo
 if 23 - 23: ooOoO0o + OoooooooOO * iII111i . I11i
 if 2 - 2: iIii1I11I1II1 * I1ii11iIi11i - OoooooooOO
 if 93 - 93: iII111i % ooOoO0o * Oo0Ooo
 if 34 - 34: O0 * oO0o
 if 58 - 58: OOooOOo . iII111i - Oo0Ooo / iII111i . I11i
def lisp_remove_eid_from_map_notify_queue ( eid_list ) :
 if 86 - 86: iIii1I11I1II1 - iII111i % Ii1I
 if 18 - 18: oO0o / IiII - OOooOOo % Ii1I
 if 88 - 88: i11iIiiIii
 if 13 - 13: I1IiiI
 if 52 - 52: Ii1I * oO0o / I1Ii111 . IiII
 ooOO0000O = [ ]
 for Oo00Ooo0oo0 in eid_list :
  for oOOoo0oOo in lisp_map_notify_queue :
   O00o0oOoO0OOo = lisp_map_notify_queue [ oOOoo0oOo ]
   if ( Oo00Ooo0oo0 not in O00o0oOoO0OOo . eid_list ) : continue
   if 79 - 79: I11i
   ooOO0000O . append ( oOOoo0oOo )
   iI11II1IiI111 = O00o0oOoO0OOo . retransmit_timer
   if ( iI11II1IiI111 ) : iI11II1IiI111 . cancel ( )
   if 45 - 45: OoOoOO00 * OOooOOo * I1IiiI + oO0o
   lprint ( "Remove from Map-Notify queue nonce 0x{} for EID {}" . format ( O00o0oOoO0OOo . nonce_key , green ( Oo00Ooo0oo0 , False ) ) )
   if 6 - 6: OoooooooOO * I1Ii111 . I1Ii111 % o0oOOo0O0Ooo . OoOoOO00
   if 100 - 100: II111iiii - Oo0Ooo % OoO0O00
   if 92 - 92: I11i % Ii1I % I11i * O0
   if 28 - 28: O0 . ooOoO0o
   if 40 - 40: OOooOOo + OoO0O00 + oO0o
   if 77 - 77: OoOoOO00 + iIii1I11I1II1 / OoOoOO00 - Ii1I / OoO0O00 + I1IiiI
   if 3 - 3: i1IIi % Ii1I . OoO0O00 * iIii1I11I1II1 % I11i
 for oOOoo0oOo in ooOO0000O : lisp_map_notify_queue . pop ( oOOoo0oOo )
 return
 if 64 - 64: iII111i * I1IiiI * IiII * iII111i / i1IIi . IiII
 if 30 - 30: OoOoOO00 . oO0o - iIii1I11I1II1 % i1IIi
 if 94 - 94: Oo0Ooo + iIii1I11I1II1 . OoO0O00 * oO0o . i1IIi
 if 85 - 85: O0 / OoOoOO00 . iII111i
 if 64 - 64: OoO0O00 + I1ii11iIi11i / OoO0O00 * I1Ii111 . Oo0Ooo
 if 5 - 5: iII111i - iIii1I11I1II1 * IiII
 if 52 - 52: OOooOOo
 if 50 - 50: OoOoOO00 % o0oOOo0O0Ooo - II111iiii - i1IIi
def lisp_decrypt_map_register ( packet ) :
 if 35 - 35: Oo0Ooo - ooOoO0o % OoO0O00
 if 26 - 26: i1IIi * I1Ii111 * OoO0O00 - IiII
 if 26 - 26: Oo0Ooo - ooOoO0o . iII111i * OoOoOO00 / OoooooooOO
 if 66 - 66: I1IiiI
 if 45 - 45: II111iiii * I1Ii111 - II111iiii / I1IiiI % oO0o
 I11i1I1i1 = socket . ntohl ( struct . unpack ( "I" , packet [ 0 : 4 ] ) [ 0 ] )
 OOOOoO0o0oo = ( I11i1I1i1 >> 13 ) & 0x1
 if ( OOOOoO0o0oo == 0 ) : return ( packet )
 if 91 - 91: ooOoO0o / i1IIi . IiII
 o00Ii = ( I11i1I1i1 >> 14 ) & 0x7
 if 45 - 45: OoO0O00
 if 31 - 31: I1IiiI . O0 % Ii1I . oO0o
 if 91 - 91: O0 - oO0o * O0
 if 98 - 98: Ii1I
 try :
  o0O0O0O00 = lisp_ms_encryption_keys [ o00Ii ]
  o0O0O0O00 = o0O0O0O00 . zfill ( 32 )
  O0Ooo0ooo00o = "0" * 8
 except :
  lprint ( "Cannot decrypt Map-Register with key-id {}" . format ( o00Ii ) )
  return ( None )
  if 31 - 31: IiII
  if 43 - 43: OoOoOO00 . OoooooooOO + OoooooooOO - IiII . OoOoOO00
 O0o0oo0oOO0oO = bold ( "Decrypt" , False )
 lprint ( "{} Map-Register with key-id {}" . format ( O0o0oo0oOO0oO , o00Ii ) )
 if 56 - 56: I11i
 Ii1IOoO0o0O = chacha . ChaCha ( o0O0O0O00 , O0Ooo0ooo00o ) . decrypt ( packet [ 4 : : ] )
 return ( packet [ 0 : 4 ] + Ii1IOoO0o0O )
 if 75 - 75: ooOoO0o . oO0o . OoOoOO00
 if 72 - 72: I11i % ooOoO0o / O0 . O0
 if 7 - 7: O0 * I1ii11iIi11i + Ii1I + oO0o % oO0o
 if 47 - 47: oO0o * I1ii11iIi11i
 if 85 - 85: OoooooooOO * I1ii11iIi11i + i11iIiiIii . iII111i * II111iiii / oO0o
 if 14 - 14: I1Ii111
 if 49 - 49: I1IiiI . OOooOOo / OoooooooOO + I11i - I11i
def lisp_process_map_register ( lisp_sockets , packet , source , sport ) :
 global lisp_registered_count
 if 27 - 27: Ii1I / o0oOOo0O0Ooo . iIii1I11I1II1 . I1IiiI - OoO0O00
 if 28 - 28: ooOoO0o
 if 88 - 88: oO0o
 if 77 - 77: ooOoO0o + I1Ii111 . OoOoOO00
 if 2 - 2: i1IIi - IiII + iIii1I11I1II1 % i1IIi * II111iiii
 if 26 - 26: I11i
 packet = lisp_decrypt_map_register ( packet )
 if ( packet == None ) : return
 if 57 - 57: I1ii11iIi11i + I1Ii111 + i11iIiiIii . i1IIi / i11iIiiIii
 i11i11i1i1 = lisp_map_register ( )
 II11iII , packet = i11i11i1i1 . decode ( packet )
 if ( packet == None ) :
  lprint ( "Could not decode Map-Register packet" )
  return
  if 55 - 55: I11i / I11i - IiII - I11i
 i11i11i1i1 . sport = sport
 if 3 - 3: oO0o % o0oOOo0O0Ooo + OoOoOO00
 i11i11i1i1 . print_map_register ( )
 if 22 - 22: O0
 if 36 - 36: OOooOOo
 if 42 - 42: OOooOOo * ooOoO0o * i11iIiiIii + OoooooooOO . iIii1I11I1II1
 if 95 - 95: i1IIi * O0 / II111iiii * OoOoOO00 * I1IiiI
 I1iIiIII = True
 if ( i11i11i1i1 . auth_len == LISP_SHA1_160_AUTH_DATA_LEN ) :
  I1iIiIII = True
  if 1 - 1: iII111i
 if ( i11i11i1i1 . alg_id == LISP_SHA_256_128_ALG_ID ) :
  I1iIiIII = False
  if 98 - 98: o0oOOo0O0Ooo - I1ii11iIi11i
  if 74 - 74: OoooooooOO
  if 16 - 16: OOooOOo / iII111i - OOooOOo / OoooooooOO + oO0o
  if 80 - 80: I1IiiI % I1IiiI . Oo0Ooo
  if 94 - 94: o0oOOo0O0Ooo
 oOoo0 = [ ]
 if 59 - 59: i1IIi + O0 . I1Ii111 % I11i . I1ii11iIi11i
 if 80 - 80: I1IiiI - i11iIiiIii
 if 39 - 39: I11i / O0 - I1ii11iIi11i . Oo0Ooo * OoooooooOO / o0oOOo0O0Ooo
 if 71 - 71: O0 . OoooooooOO + Oo0Ooo . ooOoO0o / Ii1I
 oOooOO = None
 O000OOoo0o = packet
 I11ioO = [ ]
 o00o = i11i11i1i1 . record_count
 for ooOooo0OO in range ( o00o ) :
  oooOoO00o0 = lisp_eid_record ( )
  ooOo0OooO = lisp_rloc_record ( )
  packet = oooOoO00o0 . decode ( packet )
  if ( packet == None ) :
   lprint ( "Could not decode EID-record in Map-Register packet" )
   return
   if 99 - 99: Ii1I / iII111i / Ii1I + iII111i
  oooOoO00o0 . print_record ( "  " , False )
  if 18 - 18: OoOoOO00 % OoO0O00 + Ii1I * I1Ii111 / O0 % I1Ii111
  if 6 - 6: II111iiii - i1IIi
  if 78 - 78: OoOoOO00 - Oo0Ooo * II111iiii % iIii1I11I1II1 . i11iIiiIii % iII111i
  if 85 - 85: I1ii11iIi11i + OOooOOo % i1IIi
  o0O0oOo = lisp_site_eid_lookup ( oooOoO00o0 . eid , oooOoO00o0 . group ,
 False )
  if 13 - 13: OOooOOo + i11iIiiIii / OOooOOo . O0 . OoO0O00 - Ii1I
  IIiIiii1ii1i = o0O0oOo . print_eid_tuple ( ) if o0O0oOo else None
  if 35 - 35: Oo0Ooo / I1ii11iIi11i - I1IiiI . i11iIiiIii . iII111i * OoOoOO00
  if 66 - 66: i1IIi / IiII
  if 17 - 17: O0 - OOooOOo
  if 96 - 96: OOooOOo * I1ii11iIi11i
  if 85 - 85: O0 / II111iiii * O0 - iII111i % i11iIiiIii
  if 47 - 47: OoOoOO00
  if 4 - 4: OOooOOo + I1ii11iIi11i - iII111i + OOooOOo / IiII
  if ( o0O0oOo and o0O0oOo . accept_more_specifics == False ) :
   if ( o0O0oOo . eid_record_matches ( oooOoO00o0 ) == False ) :
    IiIii1 = o0O0oOo . parent_for_more_specifics
    if ( IiIii1 ) : o0O0oOo = IiIii1
    if 4 - 4: Oo0Ooo - i1IIi . Oo0Ooo * I11i . i1IIi + OOooOOo
    if 3 - 3: IiII / iII111i * iII111i
    if 15 - 15: O0 + I1IiiI * OoO0O00 - i1IIi + Ii1I . i1IIi
    if 99 - 99: II111iiii + iIii1I11I1II1 / o0oOOo0O0Ooo / i11iIiiIii % iIii1I11I1II1 - iIii1I11I1II1
    if 38 - 38: I1IiiI . oO0o - II111iiii
    if 37 - 37: i1IIi % oO0o / IiII * I11i + ooOoO0o % Oo0Ooo
    if 75 - 75: o0oOOo0O0Ooo . I1Ii111 % i1IIi . i11iIiiIii
    if 38 - 38: o0oOOo0O0Ooo - OoO0O00 - i11iIiiIii
  Oo0o0Oo0OO0 = ( o0O0oOo and o0O0oOo . accept_more_specifics )
  if ( Oo0o0Oo0OO0 ) :
   iiiII1 = lisp_site_eid ( o0O0oOo . site )
   iiiII1 . dynamic = True
   iiiII1 . eid . copy_address ( oooOoO00o0 . eid )
   iiiII1 . group . copy_address ( oooOoO00o0 . group )
   iiiII1 . parent_for_more_specifics = o0O0oOo
   iiiII1 . add_cache ( )
   iiiII1 . inherit_from_ams_parent ( )
   o0O0oOo . more_specific_registrations . append ( iiiII1 )
   o0O0oOo = iiiII1
  else :
   o0O0oOo = lisp_site_eid_lookup ( oooOoO00o0 . eid , oooOoO00o0 . group ,
 True )
   if 100 - 100: I1IiiI % I11i - iII111i - Ii1I - OoooooooOO
   if 15 - 15: iII111i
  OO0OO0O = oooOoO00o0 . print_eid_tuple ( )
  if 95 - 95: i11iIiiIii . Ii1I / II111iiii + II111iiii + Ii1I / I11i
  if ( o0O0oOo == None ) :
   oOoOo0OO0o = bold ( "Site not found" , False )
   lprint ( "  {} for EID {}{}" . format ( oOoOo0OO0o , green ( OO0OO0O , False ) ,
 ", matched non-ams {}" . format ( green ( IIiIiii1ii1i , False ) if IIiIiii1ii1i else "" ) ) )
   if 72 - 72: I1Ii111 . I1Ii111 * O0 + I1ii11iIi11i / Oo0Ooo
   if 96 - 96: oO0o . ooOoO0o * Oo0Ooo % ooOoO0o + I1Ii111 + iIii1I11I1II1
   if 45 - 45: II111iiii
   if 42 - 42: ooOoO0o
   if 62 - 62: II111iiii * o0oOOo0O0Ooo . OoO0O00 / II111iiii
   packet = ooOo0OooO . end_of_rlocs ( packet , oooOoO00o0 . rloc_count )
   if ( packet == None ) :
    lprint ( "  Could not decode RLOC-record in Map-Register packet" )
    return
    if 5 - 5: OoO0O00 + O0 . OoooooooOO + I1IiiI + i1IIi * OOooOOo
   continue
   if 19 - 19: OoooooooOO + i11iIiiIii / II111iiii - Oo0Ooo . OOooOOo
   if 10 - 10: oO0o * Oo0Ooo
  oOooOO = o0O0oOo . site
  if 55 - 55: OoO0O00 - i1IIi - I11i * oO0o
  if ( Oo0o0Oo0OO0 ) :
   O0O0o0o0o = o0O0oOo . parent_for_more_specifics . print_eid_tuple ( )
   lprint ( "  Found ams {} for site '{}' for registering prefix {}" . format ( green ( O0O0o0o0o , False ) , oOooOO . site_name , green ( OO0OO0O , False ) ) )
   if 91 - 91: I1Ii111
  else :
   O0O0o0o0o = green ( o0O0oOo . print_eid_tuple ( ) , False )
   lprint ( "  Found {} for site '{}' for registering prefix {}" . format ( O0O0o0o0o , oOooOO . site_name , green ( OO0OO0O , False ) ) )
   if 77 - 77: I1ii11iIi11i . ooOoO0o - iIii1I11I1II1 + Ii1I % II111iiii * II111iiii
   if 41 - 41: II111iiii + Oo0Ooo - IiII / I1Ii111 - OOooOOo . oO0o
   if 100 - 100: ooOoO0o / I1ii11iIi11i * OoOoOO00 . I1ii11iIi11i . o0oOOo0O0Ooo * iIii1I11I1II1
   if 15 - 15: iII111i + o0oOOo0O0Ooo / IiII
   if 33 - 33: OoooooooOO . IiII * o0oOOo0O0Ooo
   if 41 - 41: Ii1I . iII111i . o0oOOo0O0Ooo % OoooooooOO % IiII
  if ( oOooOO . shutdown ) :
   lprint ( ( "  Rejecting registration for site '{}', configured in " +
 "admin-shutdown state" ) . format ( oOooOO . site_name ) )
   packet = ooOo0OooO . end_of_rlocs ( packet , oooOoO00o0 . rloc_count )
   continue
   if 81 - 81: IiII * i11iIiiIii + i1IIi + OOooOOo . i1IIi
   if 6 - 6: i11iIiiIii - oO0o % OoO0O00 + iIii1I11I1II1
   if 69 - 69: IiII
   if 13 - 13: i11iIiiIii
   if 49 - 49: OoOoOO00
   if 61 - 61: I1Ii111 / I1Ii111 / iII111i / ooOoO0o - I1IiiI . o0oOOo0O0Ooo
   if 80 - 80: I1IiiI - OOooOOo . oO0o
   if 75 - 75: oO0o + OoOoOO00 - OoooooooOO
  iIIi1OoOo0O00 = i11i11i1i1 . key_id
  if ( oOooOO . auth_key . has_key ( iIIi1OoOo0O00 ) == False ) : iIIi1OoOo0O00 = 0
  I1i1 = oOooOO . auth_key [ iIIi1OoOo0O00 ]
  if 95 - 95: OOooOOo . O0 - OOooOOo
  i111i1iiII1 = lisp_verify_auth ( II11iII , i11i11i1i1 . alg_id ,
 i11i11i1i1 . auth_data , I1i1 )
  II1iII11 = "dynamic " if o0O0oOo . dynamic else ""
  if 63 - 63: i11iIiiIii + OoooooooOO % I11i / OoO0O00
  i1I11iIIiIIiIi = bold ( "passed" if i111i1iiII1 else "failed" , False )
  iIIi1OoOo0O00 = "key-id {}" . format ( iIIi1OoOo0O00 ) if iIIi1OoOo0O00 == i11i11i1i1 . key_id else "bad key-id {}" . format ( i11i11i1i1 . key_id )
  if 73 - 73: i11iIiiIii / i1IIi
  lprint ( "  Authentication {} for {}EID-prefix {}, {}" . format ( i1I11iIIiIIiIi , II1iII11 , green ( OO0OO0O , False ) , iIIi1OoOo0O00 ) )
  if 8 - 8: O0 / OOooOOo + iII111i % iIii1I11I1II1 % iIii1I11I1II1 . ooOoO0o
  if 47 - 47: OoO0O00 / o0oOOo0O0Ooo / Ii1I * I1IiiI % ooOoO0o / I1Ii111
  if 80 - 80: I1Ii111 / O0 * O0
  if 40 - 40: OoO0O00 - oO0o / o0oOOo0O0Ooo . oO0o
  if 89 - 89: i11iIiiIii - II111iiii
  if 67 - 67: IiII % I1Ii111 + i11iIiiIii
  o00OO00o00 = True
  Iii1 = ( lisp_get_eid_hash ( oooOoO00o0 . eid ) != None )
  if ( Iii1 or o0O0oOo . require_signature ) :
   Ii11iI1I = "Required " if o0O0oOo . require_signature else ""
   OO0OO0O = green ( OO0OO0O , False )
   Oo0O0 = lisp_find_sig_in_rloc_set ( packet , oooOoO00o0 . rloc_count )
   if ( Oo0O0 == None ) :
    o00OO00o00 = False
    lprint ( ( "  {}EID-crypto-hash signature verification {} " + "for EID-prefix {}, no signature found" ) . format ( Ii11iI1I ,
    # Ii1I * I1ii11iIi11i
 bold ( "failed" , False ) , OO0OO0O ) )
   else :
    o00OO00o00 = lisp_verify_cga_sig ( oooOoO00o0 . eid , Oo0O0 )
    i1I11iIIiIIiIi = bold ( "passed" if o00OO00o00 else "failed" , False )
    lprint ( ( "  {}EID-crypto-hash signature verification {} " + "for EID-prefix {}" ) . format ( Ii11iI1I , i1I11iIIiIIiIi , OO0OO0O ) )
    if 21 - 21: I1IiiI . i11iIiiIii - o0oOOo0O0Ooo * II111iiii % iIii1I11I1II1
    if 9 - 9: I1ii11iIi11i + I11i
    if 20 - 20: iII111i + i1IIi / oO0o % OoooooooOO * OoOoOO00
    if 70 - 70: Oo0Ooo - OOooOOo * OOooOOo / o0oOOo0O0Ooo
  if ( i111i1iiII1 == False or o00OO00o00 == False ) :
   packet = ooOo0OooO . end_of_rlocs ( packet , oooOoO00o0 . rloc_count )
   if ( packet == None ) :
    lprint ( "  Could not decode RLOC-record in Map-Register packet" )
    return
    if 4 - 4: OoOoOO00 / OoO0O00
   continue
   if 66 - 66: I1Ii111 / OoOoOO00
   if 53 - 53: OoOoOO00 . i11iIiiIii - OoooooooOO
   if 92 - 92: O0 - i11iIiiIii + OoO0O00 - OoooooooOO - o0oOOo0O0Ooo
   if 25 - 25: oO0o / oO0o / Ii1I / O0
   if 56 - 56: ooOoO0o
   if 19 - 19: O0 * I1IiiI + I1ii11iIi11i
  if ( i11i11i1i1 . merge_register_requested ) :
   IiIii1 = o0O0oOo
   IiIii1 . inconsistent_registration = False
   if 25 - 25: I11i - ooOoO0o / OoO0O00 / iII111i - OoO0O00
   if 86 - 86: OoO0O00
   if 89 - 89: OoooooooOO % iII111i * I1ii11iIi11i + I1ii11iIi11i . Oo0Ooo
   if 4 - 4: I11i
   if 8 - 8: IiII
   if ( o0O0oOo . group . is_null ( ) ) :
    if ( IiIii1 . site_id != i11i11i1i1 . site_id ) :
     IiIii1 . site_id = i11i11i1i1 . site_id
     IiIii1 . registered = False
     IiIii1 . individual_registrations = { }
     IiIii1 . registered_rlocs = [ ]
     lisp_registered_count -= 1
     if 1 - 1: ooOoO0o . IiII
     if 4 - 4: iIii1I11I1II1 % I1IiiI - OoooooooOO / iII111i
     if 55 - 55: O0 + iII111i * OoOoOO00 . i11iIiiIii * Ii1I + oO0o
   o0000oO = source . address + i11i11i1i1 . xtr_id
   if ( o0O0oOo . individual_registrations . has_key ( o0000oO ) ) :
    o0O0oOo = o0O0oOo . individual_registrations [ o0000oO ]
   else :
    o0O0oOo = lisp_site_eid ( oOooOO )
    o0O0oOo . eid . copy_address ( IiIii1 . eid )
    o0O0oOo . group . copy_address ( IiIii1 . group )
    IiIii1 . individual_registrations [ o0000oO ] = o0O0oOo
    if 66 - 66: i1IIi . I1ii11iIi11i
  else :
   o0O0oOo . inconsistent_registration = o0O0oOo . merge_register_requested
   if 86 - 86: Oo0Ooo
   if 48 - 48: OoO0O00
   if 55 - 55: OoO0O00 * i1IIi * I11i / iII111i
  o0O0oOo . map_registers_received += 1
  if 42 - 42: IiII
  if 28 - 28: OoOoOO00 + OoOoOO00
  if 53 - 53: II111iiii % i1IIi + ooOoO0o . I1Ii111
  if 52 - 52: I1IiiI + I1Ii111 * oO0o / i11iIiiIii * iIii1I11I1II1
  if 27 - 27: Oo0Ooo
  IIIiIiI1Ii = ( o0O0oOo . is_rloc_in_rloc_set ( source ) == False )
  if ( oooOoO00o0 . record_ttl == 0 and IIIiIiI1Ii ) :
   lprint ( "  Ignore deregistration request from {}" . format ( red ( source . print_address_no_iid ( ) , False ) ) )
   if 85 - 85: iIii1I11I1II1 . o0oOOo0O0Ooo + oO0o
   continue
   if 79 - 79: O0 - iIii1I11I1II1 + i1IIi . I11i
   if 21 - 21: II111iiii
   if 23 - 23: I11i * i1IIi . oO0o / IiII + o0oOOo0O0Ooo
   if 1 - 1: IiII / OoO0O00 . oO0o * I1Ii111 - i11iIiiIii
   if 50 - 50: oO0o - O0 / I1IiiI . OoOoOO00 . Oo0Ooo
   if 30 - 30: IiII . OoO0O00 + Oo0Ooo
  IiiiooOo00OOO0 = o0O0oOo . registered_rlocs
  o0O0oOo . registered_rlocs = [ ]
  if 29 - 29: OoO0O00
  if 78 - 78: iII111i * ooOoO0o + O0 % ooOoO0o + OoO0O00
  if 41 - 41: II111iiii . oO0o + O0 % i1IIi . Ii1I
  if 90 - 90: ooOoO0o * I1IiiI / II111iiii % Oo0Ooo % OoooooooOO
  ooOo00OOo0000 = packet
  for OOOoOOo000oo in range ( oooOoO00o0 . rloc_count ) :
   ooOo0OooO = lisp_rloc_record ( )
   packet = ooOo0OooO . decode ( packet , None )
   if ( packet == None ) :
    lprint ( "  Could not decode RLOC-record in Map-Register packet" )
    return
    if 52 - 52: i11iIiiIii - oO0o . ooOoO0o / o0oOOo0O0Ooo * II111iiii
   ooOo0OooO . print_record ( "    " )
   if 11 - 11: I1Ii111 + IiII * IiII - I11i . oO0o
   if 88 - 88: II111iiii % O0 * Ii1I . II111iiii
   if 85 - 85: oO0o % I1ii11iIi11i
   if 92 - 92: Oo0Ooo + Ii1I * OoOoOO00
   if ( len ( oOooOO . allowed_rlocs ) > 0 ) :
    oooOO0oOooO00 = ooOo0OooO . rloc . print_address ( )
    if ( oOooOO . allowed_rlocs . has_key ( oooOO0oOooO00 ) == False ) :
     lprint ( ( "  Reject registration, RLOC {} not " + "configured in allowed RLOC-set" ) . format ( red ( oooOO0oOooO00 , False ) ) )
     if 94 - 94: oO0o
     if 95 - 95: ooOoO0o * O0 + OOooOOo
     o0O0oOo . registered = False
     packet = ooOo0OooO . end_of_rlocs ( packet ,
 oooOoO00o0 . rloc_count - OOOoOOo000oo - 1 )
     break
     if 11 - 11: i1IIi / OoOoOO00 + OoOoOO00 + I1ii11iIi11i + OOooOOo
     if 21 - 21: ooOoO0o
     if 28 - 28: OoOoOO00 + OoOoOO00 - OoOoOO00 / ooOoO0o
     if 81 - 81: oO0o
     if 34 - 34: o0oOOo0O0Ooo * OOooOOo - i1IIi * o0oOOo0O0Ooo * Oo0Ooo
     if 59 - 59: iIii1I11I1II1 / Oo0Ooo % II111iiii
   Oo0O0 = lisp_rloc ( )
   Oo0O0 . store_rloc_from_record ( ooOo0OooO , None , source )
   if 55 - 55: ooOoO0o - IiII + o0oOOo0O0Ooo
   if 48 - 48: O0 - iIii1I11I1II1 * OOooOOo
   if 33 - 33: I11i
   if 63 - 63: Ii1I % II111iiii / OoOoOO00 + Oo0Ooo
   if 28 - 28: OoO0O00 + I1IiiI . oO0o + II111iiii - O0
   if 32 - 32: oO0o
   if ( source . is_exact_match ( Oo0O0 . rloc ) ) :
    Oo0O0 . map_notify_requested = i11i11i1i1 . map_notify_requested
    if 62 - 62: i11iIiiIii + OoooooooOO + IiII - OoO0O00 / oO0o * iIii1I11I1II1
    if 91 - 91: o0oOOo0O0Ooo - i11iIiiIii + Oo0Ooo % iIii1I11I1II1
    if 58 - 58: iII111i / ooOoO0o - I1Ii111 + I1Ii111 * ooOoO0o
    if 48 - 48: iII111i % O0 % Ii1I * OoO0O00 . OoO0O00
    if 74 - 74: OoO0O00 * i1IIi + I1ii11iIi11i / o0oOOo0O0Ooo / i1IIi
   o0O0oOo . registered_rlocs . append ( Oo0O0 )
   if 94 - 94: Ii1I
   if 13 - 13: OoO0O00 - II111iiii . iII111i + OoOoOO00 / i11iIiiIii
  i1iiI = ( o0O0oOo . do_rloc_sets_match ( IiiiooOo00OOO0 ) == False )
  if 34 - 34: iIii1I11I1II1
  if 47 - 47: OOooOOo * iII111i
  if 71 - 71: IiII - OoooooooOO * i11iIiiIii . OoooooooOO % i1IIi . Oo0Ooo
  if 3 - 3: OoO0O00 + i11iIiiIii + oO0o * IiII
  if 19 - 19: iII111i / II111iiii . I1Ii111 * I1IiiI - OOooOOo
  if 70 - 70: OoO0O00
  if ( i11i11i1i1 . map_register_refresh and i1iiI and
 o0O0oOo . registered ) :
   lprint ( "  Reject registration, refreshes cannot change RLOC-set" )
   o0O0oOo . registered_rlocs = IiiiooOo00OOO0
   continue
   if 42 - 42: OoooooooOO - I1Ii111 + I1ii11iIi11i * iII111i * iII111i / OoO0O00
   if 85 - 85: O0 . II111iiii
   if 80 - 80: O0 * I11i * I1Ii111
   if 89 - 89: Ii1I * OoO0O00 . i1IIi . O0 - IiII - OoOoOO00
   if 25 - 25: iII111i + i1IIi
   if 64 - 64: IiII % I11i / iIii1I11I1II1
  if ( o0O0oOo . registered == False ) :
   o0O0oOo . first_registered = lisp_get_timestamp ( )
   lisp_registered_count += 1
   if 66 - 66: Ii1I
  o0O0oOo . last_registered = lisp_get_timestamp ( )
  o0O0oOo . registered = ( oooOoO00o0 . record_ttl != 0 )
  o0O0oOo . last_registerer = source
  if 55 - 55: OOooOOo + I1IiiI + IiII . Ii1I * oO0o
  if 71 - 71: IiII - iII111i % I1IiiI * iII111i
  if 27 - 27: ooOoO0o - OoO0O00
  if 83 - 83: iII111i * OoOoOO00 - O0 * Ii1I
  o0O0oOo . auth_sha1_or_sha2 = I1iIiIII
  o0O0oOo . proxy_reply_requested = i11i11i1i1 . proxy_reply_requested
  o0O0oOo . lisp_sec_present = i11i11i1i1 . lisp_sec_present
  o0O0oOo . map_notify_requested = i11i11i1i1 . map_notify_requested
  o0O0oOo . mobile_node_requested = i11i11i1i1 . mobile_node
  o0O0oOo . merge_register_requested = i11i11i1i1 . merge_register_requested
  if 79 - 79: I11i / iII111i % Ii1I / OoOoOO00 % O0 / IiII
  o0O0oOo . use_register_ttl_requested = i11i11i1i1 . use_ttl_for_timeout
  if ( o0O0oOo . use_register_ttl_requested ) :
   o0O0oOo . register_ttl = oooOoO00o0 . store_ttl ( )
  else :
   o0O0oOo . register_ttl = LISP_SITE_TIMEOUT_CHECK_INTERVAL * 3
   if 32 - 32: IiII * II111iiii . Ii1I
  o0O0oOo . xtr_id_present = i11i11i1i1 . xtr_id_present
  if ( o0O0oOo . xtr_id_present ) :
   o0O0oOo . xtr_id = i11i11i1i1 . xtr_id
   o0O0oOo . site_id = i11i11i1i1 . site_id
   if 68 - 68: I11i / O0
   if 6 - 6: oO0o - oO0o . I1IiiI % I1ii11iIi11i
   if 22 - 22: Ii1I / I1IiiI / II111iiii
   if 31 - 31: II111iiii - Ii1I * OOooOOo - i11iIiiIii / OoooooooOO - I1Ii111
   if 76 - 76: Oo0Ooo
  if ( i11i11i1i1 . merge_register_requested ) :
   if ( IiIii1 . merge_in_site_eid ( o0O0oOo ) ) :
    oOoo0 . append ( [ oooOoO00o0 . eid , oooOoO00o0 . group ] )
    if 93 - 93: i1IIi - I1IiiI * i11iIiiIii / Ii1I . Ii1I - i1IIi
   if ( i11i11i1i1 . map_notify_requested ) :
    lisp_send_merged_map_notify ( lisp_sockets , IiIii1 , i11i11i1i1 ,
 oooOoO00o0 )
    if 19 - 19: iIii1I11I1II1 * OOooOOo * Oo0Ooo % I1IiiI
    if 93 - 93: IiII % OoOoOO00 / I1IiiI + o0oOOo0O0Ooo * ooOoO0o / i1IIi
    if 25 - 25: O0 / Oo0Ooo - o0oOOo0O0Ooo * Oo0Ooo
  if ( i1iiI == False ) : continue
  if ( len ( oOoo0 ) != 0 ) : continue
  if 45 - 45: Ii1I * IiII - OOooOOo
  I11ioO . append ( o0O0oOo . print_eid_tuple ( ) )
  if 57 - 57: iII111i % OoO0O00 / OoooooooOO
  if 69 - 69: oO0o
  if 44 - 44: IiII - II111iiii % Ii1I
  if 64 - 64: Ii1I % OoO0O00 + OOooOOo % OoOoOO00 + IiII
  if 92 - 92: iII111i * Oo0Ooo - OoOoOO00
  if 33 - 33: i11iIiiIii - OoOoOO00 . OOooOOo * II111iiii . Ii1I
  if 59 - 59: OoOoOO00
  oooOoO00o0 = oooOoO00o0 . encode ( )
  oooOoO00o0 += ooOo00OOo0000
  oOo = [ o0O0oOo . print_eid_tuple ( ) ]
  lprint ( "    Changed RLOC-set, Map-Notifying old RLOC-set" )
  if 29 - 29: iII111i - II111iiii * OoooooooOO * OoooooooOO
  for Oo0O0 in IiiiooOo00OOO0 :
   if ( Oo0O0 . map_notify_requested == False ) : continue
   if ( Oo0O0 . rloc . is_exact_match ( source ) ) : continue
   lisp_build_map_notify ( lisp_sockets , oooOoO00o0 , oOo , 1 , Oo0O0 . rloc ,
 LISP_CTRL_PORT , i11i11i1i1 . nonce , i11i11i1i1 . key_id ,
 i11i11i1i1 . alg_id , i11i11i1i1 . auth_len , oOooOO , False )
   if 15 - 15: IiII / OOooOOo / iIii1I11I1II1 / OoOoOO00
   if 91 - 91: i11iIiiIii % O0 . Oo0Ooo / I1Ii111
   if 62 - 62: Oo0Ooo . II111iiii % OoO0O00 . Ii1I * OOooOOo + II111iiii
   if 7 - 7: OOooOOo
   if 22 - 22: Oo0Ooo + ooOoO0o
  lisp_notify_subscribers ( lisp_sockets , oooOoO00o0 , o0O0oOo . eid , oOooOO )
  if 71 - 71: OOooOOo . Ii1I * i11iIiiIii . I11i
  if 9 - 9: O0 / I1ii11iIi11i . iII111i . O0 + IiII % I11i
  if 27 - 27: i11iIiiIii - I1ii11iIi11i / O0 - i1IIi + I1IiiI * iII111i
  if 26 - 26: Oo0Ooo . Ii1I
  if 7 - 7: OoOoOO00 - o0oOOo0O0Ooo + oO0o
 if ( len ( oOoo0 ) != 0 ) :
  lisp_queue_multicast_map_notify ( lisp_sockets , oOoo0 )
  if 8 - 8: iIii1I11I1II1
  if 6 - 6: oO0o
  if 51 - 51: I1Ii111 - o0oOOo0O0Ooo
  if 5 - 5: O0
  if 7 - 7: OoOoOO00 + OoO0O00 * I1IiiI
  if 63 - 63: I1ii11iIi11i + iII111i * i1IIi
 if ( i11i11i1i1 . merge_register_requested ) : return
 if 63 - 63: I1ii11iIi11i / II111iiii % oO0o + ooOoO0o . Ii1I % I11i
 if 59 - 59: I1Ii111 % o0oOOo0O0Ooo - I1IiiI * i1IIi
 if 5 - 5: I1IiiI
 if 22 - 22: II111iiii / iII111i
 if 18 - 18: i11iIiiIii * ooOoO0o . I1IiiI + i1IIi + I11i
 if ( i11i11i1i1 . map_notify_requested and oOooOO != None ) :
  lisp_build_map_notify ( lisp_sockets , O000OOoo0o , I11ioO ,
 i11i11i1i1 . record_count , source , sport , i11i11i1i1 . nonce ,
 i11i11i1i1 . key_id , i11i11i1i1 . alg_id , i11i11i1i1 . auth_len ,
 oOooOO , True )
  if 62 - 62: O0 % o0oOOo0O0Ooo + iIii1I11I1II1 + iIii1I11I1II1 * ooOoO0o
 return
 if 21 - 21: o0oOOo0O0Ooo % O0
 if 81 - 81: i1IIi + i1IIi
 if 3 - 3: I1Ii111 . I1ii11iIi11i * iII111i * i11iIiiIii * IiII
 if 52 - 52: iIii1I11I1II1 % o0oOOo0O0Ooo % I1IiiI
 if 71 - 71: I1IiiI + iII111i
 if 47 - 47: iIii1I11I1II1 . OoO0O00 . iIii1I11I1II1
 if 57 - 57: IiII * ooOoO0o * ooOoO0o * iIii1I11I1II1 * I1Ii111 + OoOoOO00
 if 83 - 83: OoOoOO00 . Oo0Ooo . OoO0O00
 if 65 - 65: iII111i * iIii1I11I1II1
 if 48 - 48: iII111i * OoO0O00
def lisp_process_multicast_map_notify ( packet , source ) :
 O00o0oOoO0OOo = lisp_map_notify ( "" )
 packet = O00o0oOoO0OOo . decode ( packet )
 if ( packet == None ) :
  lprint ( "Could not decode Map-Notify packet" )
  return
  if 57 - 57: ooOoO0o + I1IiiI
  if 32 - 32: I1ii11iIi11i + OOooOOo - I11i
 O00o0oOoO0OOo . print_notify ( )
 if ( O00o0oOoO0OOo . record_count == 0 ) : return
 if 82 - 82: Oo0Ooo % Oo0Ooo
 o0OO0oo00O = O00o0oOoO0OOo . eid_records
 if 65 - 65: OoO0O00
 for ooOooo0OO in range ( O00o0oOoO0OOo . record_count ) :
  oooOoO00o0 = lisp_eid_record ( )
  o0OO0oo00O = oooOoO00o0 . decode ( o0OO0oo00O )
  if ( packet == None ) : return
  oooOoO00o0 . print_record ( "  " , False )
  if 65 - 65: oO0o
  if 77 - 77: I11i * i1IIi - OOooOOo / OoOoOO00
  if 50 - 50: O0 - oO0o . oO0o
  if 98 - 98: IiII % Ii1I / Ii1I
  oOooO0Oo0Oo0 = lisp_map_cache_lookup ( oooOoO00o0 . eid , oooOoO00o0 . group )
  if ( oOooO0Oo0Oo0 == None ) :
   oOooO0Oo0Oo0 = lisp_mapping ( oooOoO00o0 . eid , oooOoO00o0 . group , [ ] )
   oOooO0Oo0Oo0 . add_cache ( )
   if 10 - 10: Ii1I
   if 69 - 69: I1Ii111 * OoooooooOO . o0oOOo0O0Ooo % I1IiiI
  oOooO0Oo0Oo0 . mapping_source = None if source == "lisp-etr" else source
  oOooO0Oo0Oo0 . map_cache_ttl = oooOoO00o0 . store_ttl ( )
  if 70 - 70: iII111i . i11iIiiIii * I1Ii111
  if 54 - 54: o0oOOo0O0Ooo . i1IIi / iII111i
  if 21 - 21: O0 + ooOoO0o
  if 53 - 53: Ii1I - II111iiii * iIii1I11I1II1
  if 91 - 91: OoOoOO00 % iIii1I11I1II1
  if ( len ( oOooO0Oo0Oo0 . rloc_set ) != 0 and oooOoO00o0 . rloc_count == 0 ) :
   oOooO0Oo0Oo0 . rloc_set = [ ]
   oOooO0Oo0Oo0 . build_best_rloc_set ( )
   lisp_write_ipc_map_cache ( True , oOooO0Oo0Oo0 )
   lprint ( "Update {} map-cache entry with no RLOC-set" . format ( green ( oOooO0Oo0Oo0 . print_eid_tuple ( ) , False ) ) )
   if 81 - 81: i11iIiiIii / OoOoOO00 + iIii1I11I1II1
   continue
   if 65 - 65: o0oOOo0O0Ooo
   if 73 - 73: I11i . I1ii11iIi11i - OoO0O00 + OoooooooOO
  oo0OO = oOooO0Oo0Oo0 . rtrs_in_rloc_set ( )
  if 91 - 91: OoooooooOO * o0oOOo0O0Ooo
  if 14 - 14: I1Ii111 * OoO0O00 + II111iiii / OoO0O00 . IiII
  if 26 - 26: I1IiiI + Ii1I / iII111i / Ii1I + iIii1I11I1II1 * I1ii11iIi11i
  if 7 - 7: i1IIi + iIii1I11I1II1 % I1ii11iIi11i
  if 33 - 33: oO0o . oO0o / IiII + II111iiii
  for OOOoOOo000oo in range ( oooOoO00o0 . rloc_count ) :
   ooOo0OooO = lisp_rloc_record ( )
   o0OO0oo00O = ooOo0OooO . decode ( o0OO0oo00O , None )
   ooOo0OooO . print_record ( "    " )
   if ( oooOoO00o0 . group . is_null ( ) ) : continue
   if ( ooOo0OooO . rle == None ) : continue
   if 34 - 34: OoO0O00 . OoOoOO00 / i1IIi / OOooOOo
   if 12 - 12: o0oOOo0O0Ooo . Oo0Ooo / II111iiii
   if 18 - 18: I1Ii111 % II111iiii + Ii1I * Oo0Ooo - OoooooooOO . Oo0Ooo
   if 25 - 25: OoO0O00
   if 83 - 83: II111iiii . iIii1I11I1II1
   OooO0o = oOooO0Oo0Oo0 . rloc_set [ 0 ] . stats if len ( oOooO0Oo0Oo0 . rloc_set ) != 0 else None
   if 17 - 17: i1IIi % o0oOOo0O0Ooo % ooOoO0o / I11i
   if 68 - 68: OoOoOO00
   if 14 - 14: iIii1I11I1II1 + oO0o / ooOoO0o
   if 20 - 20: I1ii11iIi11i . II111iiii % I1Ii111 + I1Ii111 / OoooooooOO . Ii1I
   Oo0O0 = lisp_rloc ( )
   Oo0O0 . store_rloc_from_record ( ooOo0OooO , None , oOooO0Oo0Oo0 . mapping_source )
   if ( OooO0o != None ) : Oo0O0 . stats = copy . deepcopy ( OooO0o )
   if 98 - 98: OoooooooOO - i11iIiiIii - iII111i + Ii1I - I1IiiI
   if ( oo0OO and Oo0O0 . is_rtr ( ) == False ) : continue
   if 75 - 75: OOooOOo
   oOooO0Oo0Oo0 . rloc_set = [ Oo0O0 ]
   oOooO0Oo0Oo0 . build_best_rloc_set ( )
   lisp_write_ipc_map_cache ( True , oOooO0Oo0Oo0 )
   if 25 - 25: iII111i / I1ii11iIi11i - ooOoO0o
   lprint ( "Update {} map-cache entry with RLE {}" . format ( green ( oOooO0Oo0Oo0 . print_eid_tuple ( ) , False ) , Oo0O0 . rle . print_rle ( False ) ) )
   if 53 - 53: IiII / OoooooooOO / ooOoO0o + Oo0Ooo - OOooOOo - iIii1I11I1II1
   if 53 - 53: OOooOOo . I1IiiI . o0oOOo0O0Ooo / o0oOOo0O0Ooo
   if 40 - 40: OoooooooOO + iII111i % I1Ii111 . ooOoO0o
 return
 if 2 - 2: ooOoO0o
 if 55 - 55: I11i + i1IIi * OoOoOO00 % Oo0Ooo * II111iiii . I1IiiI
 if 98 - 98: I1ii11iIi11i
 if 57 - 57: OOooOOo * I11i . oO0o
 if 17 - 17: iII111i - OOooOOo * I1IiiI + i1IIi % I1ii11iIi11i
 if 71 - 71: Ii1I - o0oOOo0O0Ooo - oO0o
 if 27 - 27: O0 - iIii1I11I1II1
 if 78 - 78: Oo0Ooo / o0oOOo0O0Ooo
def lisp_process_map_notify ( lisp_sockets , orig_packet , source ) :
 O00o0oOoO0OOo = lisp_map_notify ( "" )
 iIIi1 = O00o0oOoO0OOo . decode ( orig_packet )
 if ( iIIi1 == None ) :
  lprint ( "Could not decode Map-Notify packet" )
  return
  if 35 - 35: o0oOOo0O0Ooo . OoO0O00 / o0oOOo0O0Ooo / IiII - I1ii11iIi11i . Oo0Ooo
  if 97 - 97: i11iIiiIii + I1ii11iIi11i - I11i . oO0o
 O00o0oOoO0OOo . print_notify ( )
 if 76 - 76: IiII * II111iiii * I1ii11iIi11i + OoooooooOO - OoOoOO00 . Ii1I
 if 51 - 51: II111iiii % I1Ii111 * O0 . ooOoO0o * OoOoOO00
 if 17 - 17: I1IiiI % I11i
 if 28 - 28: I1ii11iIi11i * OoooooooOO
 if 19 - 19: Oo0Ooo - iII111i % OoOoOO00 * i11iIiiIii / oO0o . i11iIiiIii
 oooOOO00o0 = source . print_address ( )
 if ( O00o0oOoO0OOo . alg_id != 0 or O00o0oOoO0OOo . auth_len != 0 ) :
  iiIiiiII11Iii1 = None
  for o0000oO in lisp_map_servers_list :
   if ( o0000oO . find ( oooOOO00o0 ) == - 1 ) : continue
   iiIiiiII11Iii1 = lisp_map_servers_list [ o0000oO ]
   if 46 - 46: I1ii11iIi11i
  if ( iiIiiiII11Iii1 == None ) :
   lprint ( ( "  Could not find Map-Server {} to authenticate " + "Map-Notify" ) . format ( oooOOO00o0 ) )
   if 50 - 50: OOooOOo * OoO0O00 * OOooOOo % I1IiiI - I1Ii111 * Ii1I
   return
   if 88 - 88: OOooOOo . iII111i / I11i
   if 1 - 1: iIii1I11I1II1 - Oo0Ooo % OoooooooOO
  iiIiiiII11Iii1 . map_notifies_received += 1
  if 71 - 71: OOooOOo - Ii1I
  i111i1iiII1 = lisp_verify_auth ( iIIi1 , O00o0oOoO0OOo . alg_id ,
 O00o0oOoO0OOo . auth_data , iiIiiiII11Iii1 . password )
  if 68 - 68: ooOoO0o
  lprint ( "  Authentication {} for Map-Notify" . format ( "succeeded" if i111i1iiII1 else "failed" ) )
  if 35 - 35: IiII . iIii1I11I1II1 + Ii1I % O0
  if ( i111i1iiII1 == False ) : return
 else :
  iiIiiiII11Iii1 = lisp_ms ( oooOOO00o0 , None , "" , 0 , "" , False , False , False , False , 0 , 0 , 0 ,
 None )
  if 94 - 94: OoOoOO00 + II111iiii . II111iiii + ooOoO0o + ooOoO0o
  if 95 - 95: iIii1I11I1II1 / i11iIiiIii - IiII - OOooOOo
  if 4 - 4: II111iiii + oO0o + o0oOOo0O0Ooo % IiII % iIii1I11I1II1
  if 68 - 68: i11iIiiIii
  if 79 - 79: OoOoOO00 * Ii1I / I1ii11iIi11i + OOooOOo
  if 19 - 19: I1IiiI + I11i + I1IiiI + OoO0O00
 o0OO0oo00O = O00o0oOoO0OOo . eid_records
 if ( O00o0oOoO0OOo . record_count == 0 ) :
  lisp_send_map_notify_ack ( lisp_sockets , o0OO0oo00O , O00o0oOoO0OOo , iiIiiiII11Iii1 )
  return
  if 33 - 33: i11iIiiIii - Ii1I * II111iiii
  if 97 - 97: OoO0O00 / o0oOOo0O0Ooo * iIii1I11I1II1
  if 5 - 5: I1IiiI
  if 27 - 27: i1IIi + oO0o / I1ii11iIi11i + oO0o
  if 98 - 98: II111iiii + iIii1I11I1II1
  if 70 - 70: I11i / OoooooooOO / i11iIiiIii
  if 61 - 61: O0 . Oo0Ooo . iIii1I11I1II1
  if 54 - 54: OOooOOo * I1ii11iIi11i + OoooooooOO
 oooOoO00o0 = lisp_eid_record ( )
 iIIi1 = oooOoO00o0 . decode ( o0OO0oo00O )
 if ( iIIi1 == None ) : return
 if 58 - 58: i1IIi - OoooooooOO * OOooOOo . ooOoO0o + O0 + o0oOOo0O0Ooo
 oooOoO00o0 . print_record ( "  " , False )
 if 87 - 87: OOooOOo + I1Ii111 + O0 / oO0o / i11iIiiIii
 for OOOoOOo000oo in range ( oooOoO00o0 . rloc_count ) :
  ooOo0OooO = lisp_rloc_record ( )
  iIIi1 = ooOo0OooO . decode ( iIIi1 , None )
  if ( iIIi1 == None ) :
   lprint ( "  Could not decode RLOC-record in Map-Notify packet" )
   return
   if 60 - 60: O0 . II111iiii
  ooOo0OooO . print_record ( "    " )
  if 69 - 69: II111iiii / ooOoO0o - OoOoOO00 / OOooOOo
  if 52 - 52: OoO0O00 % I11i + o0oOOo0O0Ooo % OoOoOO00
  if 46 - 46: o0oOOo0O0Ooo % O0
  if 30 - 30: oO0o
  if 64 - 64: O0
 if ( oooOoO00o0 . group . is_null ( ) == False ) :
  if 70 - 70: oO0o % I1IiiI . iIii1I11I1II1 - Oo0Ooo + OoOoOO00 % O0
  if 91 - 91: I1Ii111 - oO0o * ooOoO0o - I1ii11iIi11i + IiII + O0
  if 18 - 18: OoOoOO00 / IiII / o0oOOo0O0Ooo . OOooOOo
  if 35 - 35: I11i . ooOoO0o % I11i / iII111i / O0 % I11i
  if 29 - 29: I1Ii111 + Ii1I
  lprint ( "Send {} Map-Notify IPC message to ITR process" . format ( green ( oooOoO00o0 . print_eid_tuple ( ) , False ) ) )
  if 100 - 100: Ii1I + I1Ii111 / iIii1I11I1II1 / i1IIi % OoOoOO00
  if 6 - 6: oO0o + ooOoO0o
  IIiIi1II1IiI = lisp_control_packet_ipc ( orig_packet , oooOOO00o0 , "lisp-itr" , 0 )
  lisp_ipc ( IIiIi1II1IiI , lisp_sockets [ 2 ] , "lisp-core-pkt" )
  if 13 - 13: Oo0Ooo . IiII % iII111i + i1IIi / OOooOOo
  if 1 - 1: I11i * i1IIi * Oo0Ooo % O0
  if 41 - 41: OOooOOo % OoOoOO00
  if 82 - 82: I11i . IiII
  if 27 - 27: I1Ii111 % O0 * OoooooooOO . Oo0Ooo
 lisp_send_map_notify_ack ( lisp_sockets , o0OO0oo00O , O00o0oOoO0OOo , iiIiiiII11Iii1 )
 return
 if 51 - 51: I11i
 if 80 - 80: Oo0Ooo + oO0o
 if 76 - 76: I1IiiI * OoooooooOO - i11iIiiIii / I11i / Oo0Ooo
 if 82 - 82: IiII % ooOoO0o
 if 100 - 100: Oo0Ooo . oO0o - iII111i + OoooooooOO
 if 27 - 27: Oo0Ooo . I1Ii111 - i1IIi * I1IiiI
 if 96 - 96: I1ii11iIi11i - Ii1I . I1ii11iIi11i
 if 89 - 89: II111iiii % I1ii11iIi11i % IiII . I11i
def lisp_process_map_notify_ack ( packet , source ) :
 O00o0oOoO0OOo = lisp_map_notify ( "" )
 packet = O00o0oOoO0OOo . decode ( packet )
 if ( packet == None ) :
  lprint ( "Could not decode Map-Notify-Ack packet" )
  return
  if 49 - 49: iII111i % i11iIiiIii * I11i - oO0o . OOooOOo . i11iIiiIii
  if 26 - 26: iIii1I11I1II1 + i11iIiiIii % iII111i + I1IiiI + oO0o - ooOoO0o
 O00o0oOoO0OOo . print_notify ( )
 if 4 - 4: Oo0Ooo - IiII - I11i
 if 72 - 72: OoooooooOO
 if 19 - 19: Oo0Ooo . OOooOOo
 if 58 - 58: IiII % iII111i + i1IIi % I1IiiI % OOooOOo . iII111i
 if 85 - 85: i11iIiiIii . o0oOOo0O0Ooo * iII111i . I1ii11iIi11i / I1Ii111 % Ii1I
 if ( O00o0oOoO0OOo . record_count < 1 ) :
  lprint ( "No EID-prefix found, cannot authenticate Map-Notify-Ack" )
  return
  if 27 - 27: II111iiii . iIii1I11I1II1 / I1ii11iIi11i / i1IIi / iIii1I11I1II1
  if 70 - 70: i11iIiiIii . OoO0O00 / OoooooooOO * OoooooooOO - OOooOOo
 oooOoO00o0 = lisp_eid_record ( )
 if 34 - 34: I1ii11iIi11i * i1IIi % OoooooooOO / I1IiiI
 if ( oooOoO00o0 . decode ( O00o0oOoO0OOo . eid_records ) == None ) :
  lprint ( "Could not decode EID-record, cannot authenticate " +
 "Map-Notify-Ack" )
  return
  if 39 - 39: OoO0O00 + IiII - II111iiii % I11i
 oooOoO00o0 . print_record ( "  " , False )
 if 80 - 80: o0oOOo0O0Ooo * ooOoO0o
 OO0OO0O = oooOoO00o0 . print_eid_tuple ( )
 if 87 - 87: I1Ii111 + O0 / I1ii11iIi11i / OoOoOO00 . Oo0Ooo - IiII
 if 24 - 24: OoOoOO00
 if 19 - 19: ooOoO0o
 if 43 - 43: O0 . I1Ii111 % OoooooooOO / I1IiiI . o0oOOo0O0Ooo - OoOoOO00
 if ( O00o0oOoO0OOo . alg_id != LISP_NONE_ALG_ID and O00o0oOoO0OOo . auth_len != 0 ) :
  o0O0oOo = lisp_sites_by_eid . lookup_cache ( oooOoO00o0 . eid , True )
  if ( o0O0oOo == None ) :
   oOoOo0OO0o = bold ( "Site not found" , False )
   lprint ( ( "{} for EID {}, cannot authenticate Map-Notify-Ack" ) . format ( oOoOo0OO0o , green ( OO0OO0O , False ) ) )
   if 46 - 46: I11i - OoooooooOO % o0oOOo0O0Ooo
   return
   if 7 - 7: OoooooooOO - I1Ii111 * IiII
  oOooOO = o0O0oOo . site
  if 20 - 20: o0oOOo0O0Ooo . OoooooooOO * I1IiiI . Oo0Ooo * OoOoOO00
  if 3 - 3: I1Ii111 % i11iIiiIii % O0 % II111iiii
  if 8 - 8: OoooooooOO * ooOoO0o
  if 26 - 26: i11iIiiIii + oO0o - i1IIi
  oOooOO . map_notify_acks_received += 1
  if 71 - 71: I1IiiI % I1Ii111 / oO0o % oO0o / iIii1I11I1II1 + I1Ii111
  iIIi1OoOo0O00 = O00o0oOoO0OOo . key_id
  if ( oOooOO . auth_key . has_key ( iIIi1OoOo0O00 ) == False ) : iIIi1OoOo0O00 = 0
  I1i1 = oOooOO . auth_key [ iIIi1OoOo0O00 ]
  if 86 - 86: IiII % i1IIi * o0oOOo0O0Ooo - I1Ii111
  i111i1iiII1 = lisp_verify_auth ( packet , O00o0oOoO0OOo . alg_id ,
 O00o0oOoO0OOo . auth_data , I1i1 )
  if 37 - 37: iII111i % I1IiiI - I1ii11iIi11i % I11i
  iIIi1OoOo0O00 = "key-id {}" . format ( iIIi1OoOo0O00 ) if iIIi1OoOo0O00 == O00o0oOoO0OOo . key_id else "bad key-id {}" . format ( O00o0oOoO0OOo . key_id )
  if 35 - 35: O0 - OoooooooOO % iII111i
  if 48 - 48: OOooOOo % i11iIiiIii
  lprint ( "  Authentication {} for Map-Notify-Ack, {}" . format ( "succeeded" if i111i1iiII1 else "failed" , iIIi1OoOo0O00 ) )
  if 49 - 49: O0 * iII111i + II111iiii - OOooOOo
  if ( i111i1iiII1 == False ) : return
  if 29 - 29: OoooooooOO % II111iiii - Oo0Ooo / IiII - i11iIiiIii
  if 64 - 64: iII111i . I1Ii111 + I1Ii111
  if 1 - 1: OOooOOo % Oo0Ooo
  if 81 - 81: oO0o / I11i % Ii1I . I11i + OoooooooOO
  if 31 - 31: OoO0O00
 if ( O00o0oOoO0OOo . retransmit_timer ) : O00o0oOoO0OOo . retransmit_timer . cancel ( )
 if 41 - 41: i11iIiiIii - I1ii11iIi11i - II111iiii
 O0iiI11111i = source . print_address ( )
 o0000oO = O00o0oOoO0OOo . nonce_key
 if 5 - 5: OoOoOO00 + i1IIi
 if ( lisp_map_notify_queue . has_key ( o0000oO ) ) :
  O00o0oOoO0OOo = lisp_map_notify_queue . pop ( o0000oO )
  if ( O00o0oOoO0OOo . retransmit_timer ) : O00o0oOoO0OOo . retransmit_timer . cancel ( )
  lprint ( "Dequeue Map-Notify from retransmit queue, key is: {}" . format ( o0000oO ) )
  if 43 - 43: iII111i * I1IiiI
 else :
  lprint ( "Map-Notify with nonce 0x{} queue entry not found for {}" . format ( O00o0oOoO0OOo . nonce_key , red ( O0iiI11111i , False ) ) )
  if 20 - 20: I1IiiI . I11i * OoO0O00 . ooOoO0o . II111iiii
  if 6 - 6: Ii1I * OoOoOO00 % IiII + I11i
 return
 if 20 - 20: oO0o
 if 34 - 34: i1IIi + oO0o * Oo0Ooo * I1Ii111 % OoooooooOO % ooOoO0o
 if 17 - 17: I1ii11iIi11i + o0oOOo0O0Ooo / OoO0O00 . Oo0Ooo - o0oOOo0O0Ooo / oO0o
 if 87 - 87: ooOoO0o
 if 74 - 74: i11iIiiIii . i11iIiiIii . iIii1I11I1II1
 if 100 - 100: i11iIiiIii - oO0o + iIii1I11I1II1 * OoOoOO00 % OOooOOo % i11iIiiIii
 if 26 - 26: O0
 if 97 - 97: OOooOOo + I11i % I1Ii111 % i11iIiiIii / I1ii11iIi11i
def lisp_map_referral_loop ( mr , eid , group , action , s ) :
 if ( action not in ( LISP_DDT_ACTION_NODE_REFERRAL ,
 LISP_DDT_ACTION_MS_REFERRAL ) ) : return ( False )
 if 21 - 21: O0 + iIii1I11I1II1 / i11iIiiIii . OOooOOo * i1IIi
 if ( mr . last_cached_prefix [ 0 ] == None ) : return ( False )
 if 3 - 3: i1IIi % o0oOOo0O0Ooo + OoOoOO00
 if 32 - 32: OoO0O00 . Oo0Ooo * iIii1I11I1II1
 if 12 - 12: O0 + I1ii11iIi11i + I11i . I1Ii111
 if 48 - 48: Ii1I . iIii1I11I1II1 - iIii1I11I1II1 * I11i . OoooooooOO
 iIoo = False
 if ( group . is_null ( ) == False ) :
  iIoo = mr . last_cached_prefix [ 1 ] . is_more_specific ( group )
  if 73 - 73: Ii1I / II111iiii - iIii1I11I1II1 . ooOoO0o * II111iiii . OOooOOo
 if ( iIoo == False ) :
  iIoo = mr . last_cached_prefix [ 0 ] . is_more_specific ( eid )
  if 50 - 50: iIii1I11I1II1 + OoOoOO00 % O0 + OoO0O00 . i11iIiiIii / oO0o
  if 31 - 31: I1IiiI % o0oOOo0O0Ooo . i11iIiiIii % OOooOOo - iIii1I11I1II1
 if ( iIoo ) :
  OO0oO0 = lisp_print_eid_tuple ( eid , group )
  oo00O00Oo000 = lisp_print_eid_tuple ( mr . last_cached_prefix [ 0 ] ,
 mr . last_cached_prefix [ 1 ] )
  if 3 - 3: iIii1I11I1II1 % IiII * I11i + ooOoO0o
  lprint ( ( "Map-Referral prefix {} from {} is not more-specific " + "than cached prefix {}" ) . format ( green ( OO0oO0 , False ) , s ,
  # iII111i - o0oOOo0O0Ooo - IiII + I11i
 oo00O00Oo000 ) )
  if 34 - 34: oO0o * II111iiii % I11i / iII111i
 return ( iIoo )
 if 15 - 15: OoOoOO00 - I11i - oO0o
 if 86 - 86: o0oOOo0O0Ooo * i11iIiiIii * Ii1I . I11i - OoOoOO00 % iII111i
 if 19 - 19: OoOoOO00 + OOooOOo - o0oOOo0O0Ooo + i11iIiiIii . OOooOOo
 if 14 - 14: Ii1I - O0 - IiII % Ii1I / OoOoOO00 * OoooooooOO
 if 57 - 57: Oo0Ooo % Oo0Ooo % O0 . I1Ii111 % I1ii11iIi11i
 if 97 - 97: Oo0Ooo % OoO0O00 * I1ii11iIi11i * ooOoO0o * OoO0O00
 if 12 - 12: ooOoO0o
def lisp_process_map_referral ( lisp_sockets , packet , source ) :
 if 56 - 56: i1IIi
 OoOOOO0Oo0oO = lisp_map_referral ( )
 packet = OoOOOO0Oo0oO . decode ( packet )
 if ( packet == None ) :
  lprint ( "Could not decode Map-Referral packet" )
  return
  if 3 - 3: OOooOOo - Oo0Ooo * Ii1I + i11iIiiIii
 OoOOOO0Oo0oO . print_map_referral ( )
 if 53 - 53: i1IIi % I1ii11iIi11i
 oooOOO00o0 = source . print_address ( )
 I11iIi1i1I1i1 = OoOOOO0Oo0oO . nonce
 if 65 - 65: I11i + OoOoOO00 - i11iIiiIii
 if 72 - 72: i11iIiiIii - iII111i . i11iIiiIii
 if 61 - 61: oO0o . i11iIiiIii / Ii1I % iII111i
 if 36 - 36: OoO0O00 + Ii1I / I11i - iII111i % OoO0O00 / Oo0Ooo
 for ooOooo0OO in range ( OoOOOO0Oo0oO . record_count ) :
  oooOoO00o0 = lisp_eid_record ( )
  packet = oooOoO00o0 . decode ( packet )
  if ( packet == None ) :
   lprint ( "Could not decode EID-record in Map-Referral packet" )
   return
   if 38 - 38: Ii1I - ooOoO0o - O0 + oO0o . iIii1I11I1II1
  oooOoO00o0 . print_record ( "  " , True )
  if 90 - 90: i1IIi * OoOoOO00
  if 27 - 27: iIii1I11I1II1
  if 95 - 95: iII111i / ooOoO0o % Ii1I
  if 44 - 44: OOooOOo . OOooOOo
  o0000oO = str ( I11iIi1i1I1i1 )
  if ( o0000oO not in lisp_ddt_map_requestQ ) :
   lprint ( ( "Map-Referral nonce 0x{} from {} not found in " + "Map-Request queue, EID-record ignored" ) . format ( lisp_hex_string ( I11iIi1i1I1i1 ) , oooOOO00o0 ) )
   if 5 - 5: oO0o + OoooooooOO
   if 88 - 88: oO0o + OOooOOo
   continue
   if 14 - 14: I11i / i1IIi
  iiIii = lisp_ddt_map_requestQ [ o0000oO ]
  if ( iiIii == None ) :
   lprint ( ( "No Map-Request queue entry found for Map-Referral " +
 "nonce 0x{} from {}, EID-record ignored" ) . format ( lisp_hex_string ( I11iIi1i1I1i1 ) , oooOOO00o0 ) )
   if 56 - 56: OoooooooOO
   continue
   if 59 - 59: I1ii11iIi11i + OoO0O00
   if 37 - 37: IiII * I1IiiI % O0
   if 32 - 32: ooOoO0o % II111iiii
   if 60 - 60: i11iIiiIii
   if 11 - 11: o0oOOo0O0Ooo
   if 77 - 77: o0oOOo0O0Ooo / iIii1I11I1II1 * iIii1I11I1II1 / o0oOOo0O0Ooo * iII111i
  if ( lisp_map_referral_loop ( iiIii , oooOoO00o0 . eid , oooOoO00o0 . group ,
 oooOoO00o0 . action , oooOOO00o0 ) ) :
   iiIii . dequeue_map_request ( )
   continue
   if 26 - 26: Ii1I
   if 1 - 1: OoOoOO00 . o0oOOo0O0Ooo + Oo0Ooo % Oo0Ooo * I1ii11iIi11i
  iiIii . last_cached_prefix [ 0 ] = oooOoO00o0 . eid
  iiIii . last_cached_prefix [ 1 ] = oooOoO00o0 . group
  if 50 - 50: IiII / i1IIi . I1ii11iIi11i
  if 75 - 75: I11i * oO0o + OoooooooOO . iII111i + OoO0O00
  if 44 - 44: II111iiii
  if 65 - 65: I11i . iII111i . I1IiiI - Oo0Ooo % iIii1I11I1II1 / O0
  o0000o = False
  I11I1 = lisp_referral_cache_lookup ( oooOoO00o0 . eid , oooOoO00o0 . group ,
 True )
  if ( I11I1 == None ) :
   o0000o = True
   I11I1 = lisp_referral ( )
   I11I1 . eid = oooOoO00o0 . eid
   I11I1 . group = oooOoO00o0 . group
   if ( oooOoO00o0 . ddt_incomplete == False ) : I11I1 . add_cache ( )
  elif ( I11I1 . referral_source . not_set ( ) ) :
   lprint ( "Do not replace static referral entry {}" . format ( green ( I11I1 . print_eid_tuple ( ) , False ) ) )
   if 54 - 54: iII111i - I1Ii111
   iiIii . dequeue_map_request ( )
   continue
   if 88 - 88: iII111i * OoO0O00 % OoooooooOO / oO0o
   if 7 - 7: i1IIi
  iiIiiIii1IiI = oooOoO00o0 . action
  I11I1 . referral_source = source
  I11I1 . referral_type = iiIiiIii1IiI
  O00O00Oo = oooOoO00o0 . store_ttl ( )
  I11I1 . referral_ttl = O00O00Oo
  I11I1 . expires = lisp_set_timestamp ( O00O00Oo )
  if 30 - 30: oO0o . i1IIi / I11i
  if 23 - 23: i1IIi + oO0o % iII111i - OoO0O00 - i1IIi
  if 74 - 74: Ii1I + I11i . OoooooooOO - I1ii11iIi11i
  if 2 - 2: oO0o - o0oOOo0O0Ooo
  oO0oIi1I111IiI11I = I11I1 . is_referral_negative ( )
  if ( I11I1 . referral_set . has_key ( oooOOO00o0 ) ) :
   oOoooooOoOoO = I11I1 . referral_set [ oooOOO00o0 ]
   if 63 - 63: I1IiiI . iII111i % iIii1I11I1II1 + I1ii11iIi11i
   if ( oOoooooOoOoO . updown == False and oO0oIi1I111IiI11I == False ) :
    oOoooooOoOoO . updown = True
    lprint ( "Change up/down status for referral-node {} to up" . format ( oooOOO00o0 ) )
    if 56 - 56: I1Ii111 % oO0o
   elif ( oOoooooOoOoO . updown == True and oO0oIi1I111IiI11I == True ) :
    oOoooooOoOoO . updown = False
    lprint ( ( "Change up/down status for referral-node {} " + "to down, received negative referral" ) . format ( oooOOO00o0 ) )
    if 31 - 31: OOooOOo + IiII
    if 56 - 56: OoooooooOO * II111iiii
    if 99 - 99: i11iIiiIii - II111iiii . Oo0Ooo - oO0o . I1IiiI + i1IIi
    if 69 - 69: O0 / i1IIi - OoOoOO00 + ooOoO0o - oO0o
    if 80 - 80: o0oOOo0O0Ooo % O0 * I11i . i1IIi - ooOoO0o
    if 93 - 93: OoooooooOO / o0oOOo0O0Ooo
    if 61 - 61: II111iiii / i1IIi . I1ii11iIi11i % iIii1I11I1II1
    if 66 - 66: iIii1I11I1II1 % OoOoOO00 + i1IIi * i11iIiiIii * OoooooooOO
  I1IIIii1i = { }
  for o0000oO in I11I1 . referral_set : I1IIIii1i [ o0000oO ] = None
  if 75 - 75: oO0o * Oo0Ooo * O0
  if 22 - 22: ooOoO0o / OoooooooOO . II111iiii / Ii1I * OoO0O00 . i1IIi
  if 62 - 62: oO0o % Ii1I - Ii1I
  if 16 - 16: OoO0O00 - O0 - OOooOOo - I11i % OoOoOO00
  for ooOooo0OO in range ( oooOoO00o0 . rloc_count ) :
   ooOo0OooO = lisp_rloc_record ( )
   packet = ooOo0OooO . decode ( packet , None )
   if ( packet == None ) :
    lprint ( "Could not decode RLOC-record in Map-Referral packet" )
    return
    if 7 - 7: I1Ii111 / OoOoOO00 . II111iiii
   ooOo0OooO . print_record ( "    " )
   if 9 - 9: I11i . I11i . OoooooooOO
   if 42 - 42: iII111i / oO0o / iII111i * OoO0O00
   if 25 - 25: OoOoOO00 - II111iiii + II111iiii . Ii1I * II111iiii
   if 12 - 12: IiII / Ii1I
   oooOO0oOooO00 = ooOo0OooO . rloc . print_address ( )
   if ( I11I1 . referral_set . has_key ( oooOO0oOooO00 ) == False ) :
    oOoooooOoOoO = lisp_referral_node ( )
    oOoooooOoOoO . referral_address . copy_address ( ooOo0OooO . rloc )
    I11I1 . referral_set [ oooOO0oOooO00 ] = oOoooooOoOoO
    if ( oooOOO00o0 == oooOO0oOooO00 and oO0oIi1I111IiI11I ) : oOoooooOoOoO . updown = False
   else :
    oOoooooOoOoO = I11I1 . referral_set [ oooOO0oOooO00 ]
    if ( I1IIIii1i . has_key ( oooOO0oOooO00 ) ) : I1IIIii1i . pop ( oooOO0oOooO00 )
    if 54 - 54: Oo0Ooo + Ii1I % OoooooooOO * OOooOOo / OoOoOO00
   oOoooooOoOoO . priority = ooOo0OooO . priority
   oOoooooOoOoO . weight = ooOo0OooO . weight
   if 39 - 39: I1IiiI % i11iIiiIii % Ii1I
   if 59 - 59: ooOoO0o % OoO0O00 / I1IiiI - II111iiii + OoooooooOO * i11iIiiIii
   if 58 - 58: IiII / Oo0Ooo + o0oOOo0O0Ooo
   if 71 - 71: Ii1I - IiII
   if 2 - 2: OoOoOO00 % IiII % OoO0O00 . i1IIi / I1Ii111 - iIii1I11I1II1
  for o0000oO in I1IIIii1i : I11I1 . referral_set . pop ( o0000oO )
  if 88 - 88: Oo0Ooo * i1IIi % OOooOOo
  OO0OO0O = I11I1 . print_eid_tuple ( )
  if 65 - 65: iII111i . oO0o
  if ( o0000o ) :
   if ( oooOoO00o0 . ddt_incomplete ) :
    lprint ( "Suppress add {} to referral-cache" . format ( green ( OO0OO0O , False ) ) )
    if 67 - 67: I1IiiI / iII111i / O0 % ooOoO0o - IiII / Ii1I
   else :
    lprint ( "Add {}, referral-count {} to referral-cache" . format ( green ( OO0OO0O , False ) , oooOoO00o0 . rloc_count ) )
    if 31 - 31: I11i - oO0o * ooOoO0o
    if 64 - 64: I11i
  else :
   lprint ( "Replace {}, referral-count: {} in referral-cache" . format ( green ( OO0OO0O , False ) , oooOoO00o0 . rloc_count ) )
   if 41 - 41: I1Ii111 * OoooooooOO / OoOoOO00 + OoO0O00 . OoOoOO00 + I1Ii111
   if 9 - 9: IiII . I11i . I1Ii111 / i1IIi * OoOoOO00 - O0
   if 3 - 3: O0 / iIii1I11I1II1 % IiII + I11i
   if 43 - 43: Oo0Ooo % I11i
   if 53 - 53: OoOoOO00 % OoooooooOO * o0oOOo0O0Ooo % OoooooooOO
   if 47 - 47: iIii1I11I1II1 - OOooOOo + I1ii11iIi11i * ooOoO0o + Oo0Ooo + OoO0O00
  if ( iiIiiIii1IiI == LISP_DDT_ACTION_DELEGATION_HOLE ) :
   lisp_send_negative_map_reply ( iiIii . lisp_sockets , I11I1 . eid ,
 I11I1 . group , iiIii . nonce , iiIii . itr , iiIii . sport , 15 , None , False )
   iiIii . dequeue_map_request ( )
   if 64 - 64: OoOoOO00 - OoOoOO00 . OoooooooOO + ooOoO0o
   if 100 - 100: ooOoO0o . OoooooooOO % i1IIi % OoO0O00
  if ( iiIiiIii1IiI == LISP_DDT_ACTION_NOT_AUTH ) :
   if ( iiIii . tried_root ) :
    lisp_send_negative_map_reply ( iiIii . lisp_sockets , I11I1 . eid ,
 I11I1 . group , iiIii . nonce , iiIii . itr , iiIii . sport , 0 , None , False )
    iiIii . dequeue_map_request ( )
   else :
    lisp_send_ddt_map_request ( iiIii , True )
    if 26 - 26: OoOoOO00 * IiII
    if 76 - 76: I1IiiI + IiII * I1ii11iIi11i * I1IiiI % Ii1I + ooOoO0o
    if 46 - 46: OoOoOO00
  if ( iiIiiIii1IiI == LISP_DDT_ACTION_MS_NOT_REG ) :
   if ( I11I1 . referral_set . has_key ( oooOOO00o0 ) ) :
    oOoooooOoOoO = I11I1 . referral_set [ oooOOO00o0 ]
    oOoooooOoOoO . updown = False
    if 66 - 66: iII111i - O0 . I1Ii111 * i1IIi / OoO0O00 / II111iiii
   if ( len ( I11I1 . referral_set ) == 0 ) :
    iiIii . dequeue_map_request ( )
   else :
    lisp_send_ddt_map_request ( iiIii , False )
    if 35 - 35: ooOoO0o * OOooOOo / I11i % I11i / OoooooooOO . I1Ii111
    if 70 - 70: I1ii11iIi11i % I1ii11iIi11i / oO0o
    if 85 - 85: OoOoOO00 % I11i / Oo0Ooo + I11i - Oo0Ooo
  if ( iiIiiIii1IiI in ( LISP_DDT_ACTION_NODE_REFERRAL ,
 LISP_DDT_ACTION_MS_REFERRAL ) ) :
   if ( iiIii . eid . is_exact_match ( oooOoO00o0 . eid ) ) :
    if ( not iiIii . tried_root ) :
     lisp_send_ddt_map_request ( iiIii , True )
    else :
     lisp_send_negative_map_reply ( iiIii . lisp_sockets ,
 I11I1 . eid , I11I1 . group , iiIii . nonce , iiIii . itr ,
 iiIii . sport , 15 , None , False )
     iiIii . dequeue_map_request ( )
     if 20 - 20: IiII
   else :
    lisp_send_ddt_map_request ( iiIii , False )
    if 81 - 81: Oo0Ooo / I1Ii111
    if 20 - 20: o0oOOo0O0Ooo + ooOoO0o % i1IIi
    if 51 - 51: iII111i - ooOoO0o
  if ( iiIiiIii1IiI == LISP_DDT_ACTION_MS_ACK ) : iiIii . dequeue_map_request ( )
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
 Ii1Ii1Ii = lisp_ecm ( 0 )
 packet = Ii1Ii1Ii . decode ( packet )
 if ( packet == None ) :
  lprint ( "Could not decode ECM packet" )
  return
  if 66 - 66: Ii1I - I11i + Oo0Ooo . ooOoO0o
  if 89 - 89: IiII . II111iiii / OoO0O00 + I1ii11iIi11i * i11iIiiIii
 Ii1Ii1Ii . print_ecm ( )
 if 85 - 85: o0oOOo0O0Ooo - Oo0Ooo / I1Ii111
 I11i1I1i1 = lisp_control_header ( )
 if ( I11i1I1i1 . decode ( packet ) == None ) :
  lprint ( "Could not decode control header" )
  return
  if 100 - 100: OoO0O00 * iIii1I11I1II1 - IiII . i1IIi % i11iIiiIii % Oo0Ooo
  if 22 - 22: ooOoO0o - OOooOOo
 ooOiiI1 = I11i1I1i1 . type
 del ( I11i1I1i1 )
 if 3 - 3: I1IiiI % OoO0O00
 if ( ooOiiI1 != LISP_MAP_REQUEST ) :
  lprint ( "Received ECM without Map-Request inside" )
  return
  if 18 - 18: I1ii11iIi11i * I11i
  if 57 - 57: o0oOOo0O0Ooo % I1IiiI * i11iIiiIii - I1ii11iIi11i + I1IiiI % ooOoO0o
  if 10 - 10: OoooooooOO % iII111i / IiII
  if 64 - 64: ooOoO0o % O0 / oO0o
  if 21 - 21: i11iIiiIii . o0oOOo0O0Ooo
 o0O0O0 = Ii1Ii1Ii . udp_sport
 lisp_process_map_request ( lisp_sockets , packet , source , ecm_port ,
 Ii1Ii1Ii . source , o0O0O0 , Ii1Ii1Ii . ddt , - 1 )
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
 OO0i1Ii1II11 = ms . map_server
 if ( lisp_decent_push_configured and OO0i1Ii1II11 . is_multicast_address ( ) and
 ( ms . map_registers_multicast_sent == 1 or ms . map_registers_sent == 1 ) ) :
  OO0i1Ii1II11 = copy . deepcopy ( OO0i1Ii1II11 )
  OO0i1Ii1II11 . address = 0x7f000001
  o0OO000ooOo = bold ( "Bootstrap" , False )
  Ii1i111iI = ms . map_server . print_address_no_iid ( )
  lprint ( "{} mapping system for peer-group {}" . format ( o0OO000ooOo , Ii1i111iI ) )
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
  o0O0O0O00 = ms . ekey . zfill ( 32 )
  O0Ooo0ooo00o = "0" * 8
  O0oO0oo0O0 = chacha . ChaCha ( o0O0O0O00 , O0Ooo0ooo00o ) . encrypt ( packet [ 4 : : ] )
  packet = packet [ 0 : 4 ] + O0oO0oo0O0
  O0O0o0o0o = bold ( "Encrypt" , False )
  lprint ( "{} Map-Register with key-id {}" . format ( O0O0o0o0o , ms . ekey_id ) )
  if 87 - 87: Oo0Ooo
  if 7 - 7: iIii1I11I1II1
 ooiiiII111III = ""
 if ( lisp_decent_pull_xtr_configured ( ) ) :
  ooiiiII111III = ", decent-index {}" . format ( bold ( ms . dns_name , False ) )
  if 74 - 74: i11iIiiIii * OoO0O00 - I1ii11iIi11i % I1Ii111 + I1ii11iIi11i + ooOoO0o
  if 94 - 94: OOooOOo + Ii1I + i1IIi . OoO0O00 . OoO0O00
 lprint ( "Send Map-Register to map-server {}{}{}" . format ( OO0i1Ii1II11 . print_address ( ) , ", ms-name '{}'" . format ( ms . ms_name ) , ooiiiII111III ) )
 if 29 - 29: I11i + OoooooooOO % o0oOOo0O0Ooo - I1Ii111
 lisp_send ( lisp_sockets , OO0i1Ii1II11 , LISP_CTRL_PORT , packet )
 return
 if 45 - 45: II111iiii - OOooOOo / oO0o % O0 . iII111i . iII111i
 if 82 - 82: iIii1I11I1II1 % Oo0Ooo * i1IIi - I1Ii111 - I1ii11iIi11i / iII111i
 if 24 - 24: IiII
 if 95 - 95: IiII + OoOoOO00 * OOooOOo
 if 92 - 92: OoOoOO00 + ooOoO0o . iII111i
 if 59 - 59: iIii1I11I1II1 % I1Ii111 + I1ii11iIi11i . OoOoOO00 * Oo0Ooo / I1Ii111
 if 41 - 41: i1IIi / IiII
 if 73 - 73: o0oOOo0O0Ooo % ooOoO0o
def lisp_send_ipc_to_core ( lisp_socket , packet , dest , port ) :
 I1iO00O000oOO0oO = lisp_socket . getsockname ( )
 dest = dest . print_address_no_iid ( )
 if 72 - 72: OoO0O00 * OoOoOO00 % I1IiiI - OOooOOo . Oo0Ooo
 lprint ( "Send IPC {} bytes to {} {}, control-packet: {}" . format ( len ( packet ) , dest , port , lisp_format_packet ( packet ) ) )
 if 70 - 70: ooOoO0o . o0oOOo0O0Ooo * II111iiii - O0
 if 74 - 74: oO0o % I1IiiI / oO0o / Oo0Ooo / ooOoO0o
 packet = lisp_control_packet_ipc ( packet , I1iO00O000oOO0oO , dest , port )
 lisp_ipc ( packet , lisp_socket , "lisp-core-pkt" )
 return
 if 29 - 29: ooOoO0o + iIii1I11I1II1 + OoO0O00 - o0oOOo0O0Ooo
 if 74 - 74: II111iiii - II111iiii + ooOoO0o + Oo0Ooo % iIii1I11I1II1
 if 90 - 90: oO0o / o0oOOo0O0Ooo . o0oOOo0O0Ooo % OoOoOO00 / IiII
 if 13 - 13: oO0o + IiII
 if 36 - 36: oO0o - OoOoOO00 . O0 % IiII
 if 65 - 65: Oo0Ooo - i11iIiiIii * OoOoOO00 . I1Ii111 . iIii1I11I1II1
 if 48 - 48: iIii1I11I1II1 - oO0o / OoO0O00 + O0 . Ii1I + I1Ii111
 if 17 - 17: OoOoOO00 . Oo0Ooo - I1Ii111 / I1Ii111 + I11i % i1IIi
def lisp_send_map_reply ( lisp_sockets , packet , dest , port ) :
 lprint ( "Send Map-Reply to {}" . format ( dest . print_address_no_iid ( ) ) )
 lisp_send_ipc_to_core ( lisp_sockets [ 2 ] , packet , dest , port )
 return
 if 31 - 31: OoooooooOO . O0 / OoO0O00 . I1Ii111
 if 41 - 41: OoooooooOO + iII111i . OOooOOo
 if 73 - 73: oO0o + i1IIi + i11iIiiIii / I1ii11iIi11i
 if 100 - 100: I1IiiI % ooOoO0o % OoooooooOO / i11iIiiIii + i11iIiiIii % IiII
 if 39 - 39: Ii1I % o0oOOo0O0Ooo + OOooOOo / iIii1I11I1II1
 if 40 - 40: iIii1I11I1II1 / iII111i % OOooOOo % i11iIiiIii
 if 57 - 57: II111iiii % OoO0O00 * i1IIi
 if 19 - 19: ooOoO0o . iIii1I11I1II1 + I1ii11iIi11i + I1ii11iIi11i / o0oOOo0O0Ooo . Oo0Ooo
def lisp_send_map_referral ( lisp_sockets , packet , dest , port ) :
 lprint ( "Send Map-Referral to {}" . format ( dest . print_address ( ) ) )
 lisp_send_ipc_to_core ( lisp_sockets [ 2 ] , packet , dest , port )
 return
 if 9 - 9: II111iiii % OoooooooOO
 if 4 - 4: i1IIi * i11iIiiIii % OoooooooOO + OoOoOO00 . oO0o
 if 95 - 95: I1ii11iIi11i * OoOoOO00 % o0oOOo0O0Ooo / O0 + ooOoO0o % OOooOOo
 if 48 - 48: i1IIi + IiII - iIii1I11I1II1 . i11iIiiIii % OOooOOo + I1ii11iIi11i
 if 95 - 95: ooOoO0o + OoOoOO00 . II111iiii + Ii1I
 if 81 - 81: OoooooooOO / OOooOOo / Oo0Ooo
 if 26 - 26: iII111i
 if 93 - 93: Oo0Ooo + I1IiiI % OoOoOO00 / OOooOOo / I1ii11iIi11i
def lisp_send_map_notify ( lisp_sockets , packet , dest , port ) :
 lprint ( "Send Map-Notify to xTR {}" . format ( dest . print_address ( ) ) )
 lisp_send_ipc_to_core ( lisp_sockets [ 2 ] , packet , dest , port )
 return
 if 6 - 6: IiII
 if 68 - 68: Oo0Ooo
 if 83 - 83: OOooOOo / iIii1I11I1II1 . OoO0O00 - oO0o % Oo0Ooo
 if 30 - 30: Ii1I . OoOoOO00 / oO0o . OoO0O00
 if 93 - 93: i11iIiiIii
 if 33 - 33: i1IIi % OoooooooOO + Oo0Ooo % I1IiiI / ooOoO0o
 if 40 - 40: IiII % IiII
def lisp_send_ecm ( lisp_sockets , packet , inner_source , inner_sport , inner_dest ,
 outer_dest , to_etr = False , to_ms = False , ddt = False ) :
 if 9 - 9: I1IiiI * i1IIi + OOooOOo * OoOoOO00
 if ( inner_source == None or inner_source . is_null ( ) ) :
  inner_source = inner_dest
  if 8 - 8: iII111i
  if 51 - 51: I1IiiI
  if 72 - 72: ooOoO0o / I1ii11iIi11i . Ii1I * iII111i . iIii1I11I1II1
  if 35 - 35: OoO0O00 . OoOoOO00 % O0 * OoO0O00
  if 68 - 68: OOooOOo
  if 87 - 87: IiII * IiII - OoO0O00 / I1ii11iIi11i + OOooOOo / i11iIiiIii
 if ( lisp_nat_traversal ) :
  ooO0 = lisp_get_any_translated_port ( )
  if ( ooO0 != None ) : inner_sport = ooO0
  if 21 - 21: o0oOOo0O0Ooo / oO0o + oO0o + Oo0Ooo / o0oOOo0O0Ooo
 Ii1Ii1Ii = lisp_ecm ( inner_sport )
 if 39 - 39: i11iIiiIii - OoO0O00 - i11iIiiIii / OoooooooOO
 Ii1Ii1Ii . to_etr = to_etr if lisp_is_running ( "lisp-etr" ) else False
 Ii1Ii1Ii . to_ms = to_ms if lisp_is_running ( "lisp-ms" ) else False
 Ii1Ii1Ii . ddt = ddt
 IiI1IIi = Ii1Ii1Ii . encode ( packet , inner_source , inner_dest )
 if ( IiI1IIi == None ) :
  lprint ( "Could not encode ECM message" )
  return
  if 23 - 23: OOooOOo / OoOoOO00 / OoooooooOO + i1IIi % OoooooooOO
 Ii1Ii1Ii . print_ecm ( )
 if 15 - 15: o0oOOo0O0Ooo % I1ii11iIi11i / II111iiii
 packet = IiI1IIi + packet
 if 50 - 50: oO0o * Ii1I % I1Ii111
 oooOO0oOooO00 = outer_dest . print_address_no_iid ( )
 lprint ( "Send Encapsulated-Control-Message to {}" . format ( oooOO0oOooO00 ) )
 OO0i1Ii1II11 = lisp_convert_4to6 ( oooOO0oOooO00 )
 lisp_send ( lisp_sockets , OO0i1Ii1II11 , LISP_CTRL_PORT , packet )
 return
 if 74 - 74: iIii1I11I1II1 - OOooOOo / I1Ii111 / ooOoO0o . oO0o % iIii1I11I1II1
 if 91 - 91: o0oOOo0O0Ooo . o0oOOo0O0Ooo - Ii1I
 if 60 - 60: i11iIiiIii . Oo0Ooo / iIii1I11I1II1 / II111iiii
 if 31 - 31: Oo0Ooo / Oo0Ooo / iIii1I11I1II1 / I11i % OoooooooOO
 if 90 - 90: I1IiiI
 if 35 - 35: O0
 if 10 - 10: Ii1I - I1Ii111 / Oo0Ooo + O0
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
if 67 - 67: Ii1I % i11iIiiIii . Oo0Ooo
LISP_RLOC_UNKNOWN_STATE = 0
LISP_RLOC_UP_STATE = 1
LISP_RLOC_DOWN_STATE = 2
LISP_RLOC_UNREACH_STATE = 3
LISP_RLOC_NO_ECHOED_NONCE_STATE = 4
LISP_RLOC_ADMIN_DOWN_STATE = 5
if 78 - 78: I1IiiI - iIii1I11I1II1
LISP_AUTH_NONE = 0
LISP_AUTH_MD5 = 1
LISP_AUTH_SHA1 = 2
LISP_AUTH_SHA2 = 3
if 20 - 20: i11iIiiIii % I1IiiI % OoOoOO00
if 85 - 85: I11i + OoOoOO00 * O0 * O0
if 92 - 92: i11iIiiIii
if 16 - 16: I11i . ooOoO0o - Oo0Ooo / OoO0O00 . i1IIi
if 59 - 59: ooOoO0o - ooOoO0o % I11i + OoO0O00
if 88 - 88: Ii1I - ooOoO0o . Oo0Ooo
if 83 - 83: I11i + Oo0Ooo . I1ii11iIi11i * I1ii11iIi11i
LISP_IPV4_HOST_MASK_LEN = 32
LISP_IPV6_HOST_MASK_LEN = 128
LISP_MAC_HOST_MASK_LEN = 48
LISP_E164_HOST_MASK_LEN = 60
if 80 - 80: i1IIi * I11i - OOooOOo / II111iiii * iIii1I11I1II1
if 42 - 42: OoOoOO00 . I11i % II111iiii
if 19 - 19: OoooooooOO
if 31 - 31: I11i . OoOoOO00 - O0 * iII111i % I1Ii111 - II111iiii
if 21 - 21: OOooOOo . Oo0Ooo - i1IIi
if 56 - 56: I11i
def byte_swap_64 ( address ) :
 o00Ooo0 = ( ( address & 0x00000000000000ff ) << 56 ) | ( ( address & 0x000000000000ff00 ) << 40 ) | ( ( address & 0x0000000000ff0000 ) << 24 ) | ( ( address & 0x00000000ff000000 ) << 8 ) | ( ( address & 0x000000ff00000000 ) >> 8 ) | ( ( address & 0x0000ff0000000000 ) >> 24 ) | ( ( address & 0x00ff000000000000 ) >> 40 ) | ( ( address & 0xff00000000000000 ) >> 56 )
 if 24 - 24: I1IiiI . I1IiiI % ooOoO0o
 if 32 - 32: OOooOOo / i1IIi / OOooOOo
 if 97 - 97: ooOoO0o * Oo0Ooo * OoooooooOO * I1IiiI
 if 45 - 45: Oo0Ooo
 if 27 - 27: oO0o / IiII - iIii1I11I1II1 / o0oOOo0O0Ooo % OOooOOo * iIii1I11I1II1
 if 40 - 40: oO0o - II111iiii * OOooOOo % OoooooooOO
 if 52 - 52: OOooOOo + OoO0O00
 if 96 - 96: OOooOOo % O0 - Oo0Ooo % oO0o / I1IiiI . i1IIi
 return ( o00Ooo0 )
 if 42 - 42: i1IIi
 if 52 - 52: OoO0O00 % iII111i % O0
 if 11 - 11: i1IIi / i11iIiiIii + Ii1I % Oo0Ooo % O0
 if 50 - 50: oO0o . I1Ii111
 if 38 - 38: iIii1I11I1II1 . Ii1I
 if 82 - 82: OOooOOo * Ii1I + I1ii11iIi11i . OoO0O00
 if 15 - 15: O0
 if 44 - 44: Ii1I . Oo0Ooo . I1Ii111 + oO0o
 if 32 - 32: OOooOOo - II111iiii + IiII * iIii1I11I1II1 - Oo0Ooo
 if 25 - 25: ooOoO0o
 if 33 - 33: Oo0Ooo
 if 11 - 11: I11i
 if 55 - 55: i11iIiiIii * OoOoOO00 - OoOoOO00 * OoO0O00 / iII111i
 if 64 - 64: iIii1I11I1II1 . Ii1I * Oo0Ooo - OoO0O00
 if 74 - 74: I1IiiI / o0oOOo0O0Ooo
class lisp_cache_entries ( ) :
 def __init__ ( self ) :
  self . entries = { }
  self . entries_sorted = [ ]
  if 53 - 53: iIii1I11I1II1 * oO0o
  if 43 - 43: IiII * Oo0Ooo / OOooOOo % oO0o
  if 11 - 11: OoOoOO00 * Oo0Ooo / I11i * OOooOOo
class lisp_cache ( ) :
 def __init__ ( self ) :
  self . cache = { }
  self . cache_sorted = [ ]
  self . cache_count = 0
  if 15 - 15: ooOoO0o - OOooOOo / OoooooooOO
  if 41 - 41: OoOoOO00 . iII111i . i1IIi + oO0o
 def cache_size ( self ) :
  return ( self . cache_count )
  if 60 - 60: oO0o * I1Ii111
  if 81 - 81: oO0o - OOooOOo - oO0o
 def build_key ( self , prefix ) :
  if ( prefix . afi == LISP_AFI_ULTIMATE_ROOT ) :
   oOOoOO = 0
  elif ( prefix . afi == LISP_AFI_IID_RANGE ) :
   oOOoOO = prefix . mask_len
  else :
   oOOoOO = prefix . mask_len + 48
   if 54 - 54: oO0o % I11i
   if 71 - 71: oO0o / I1ii11iIi11i . Ii1I % II111iiii
  iiI1iii = lisp_hex_string ( prefix . instance_id ) . zfill ( 8 )
  ooo0O0O0oo0 = lisp_hex_string ( prefix . afi ) . zfill ( 4 )
  if 22 - 22: iIii1I11I1II1 - OoooooooOO
  if ( prefix . afi > 0 ) :
   if ( prefix . is_binary ( ) ) :
    Oooo = prefix . addr_length ( ) * 2
    o00Ooo0 = lisp_hex_string ( prefix . address ) . zfill ( Oooo )
   else :
    o00Ooo0 = prefix . address
    if 8 - 8: ooOoO0o % i11iIiiIii
  elif ( prefix . afi == LISP_AFI_GEO_COORD ) :
   ooo0O0O0oo0 = "8003"
   o00Ooo0 = prefix . address . print_geo ( )
  else :
   ooo0O0O0oo0 = ""
   o00Ooo0 = ""
   if 41 - 41: I1Ii111 . ooOoO0o - i11iIiiIii + Ii1I . OOooOOo . OoOoOO00
   if 70 - 70: i1IIi % OoOoOO00 / iII111i + i11iIiiIii % ooOoO0o + IiII
  o0000oO = iiI1iii + ooo0O0O0oo0 + o00Ooo0
  return ( [ oOOoOO , o0000oO ] )
  if 58 - 58: OOooOOo / i11iIiiIii . Oo0Ooo % iII111i
  if 92 - 92: OoOoOO00 / ooOoO0o % iII111i / iIii1I11I1II1
 def add_cache ( self , prefix , entry ) :
  if ( prefix . is_binary ( ) ) : prefix . zero_host_bits ( )
  oOOoOO , o0000oO = self . build_key ( prefix )
  if ( self . cache . has_key ( oOOoOO ) == False ) :
   self . cache [ oOOoOO ] = lisp_cache_entries ( )
   self . cache [ oOOoOO ] . entries = { }
   self . cache [ oOOoOO ] . entries_sorted = [ ]
   self . cache_sorted = sorted ( self . cache )
   if 73 - 73: O0 % i11iIiiIii
  if ( self . cache [ oOOoOO ] . entries . has_key ( o0000oO ) == False ) :
   self . cache_count += 1
   if 16 - 16: O0
  self . cache [ oOOoOO ] . entries [ o0000oO ] = entry
  self . cache [ oOOoOO ] . entries_sorted = sorted ( self . cache [ oOOoOO ] . entries )
  if 15 - 15: i1IIi % i11iIiiIii
  if 18 - 18: Ii1I . OoO0O00 . iII111i * oO0o + O0
 def lookup_cache ( self , prefix , exact ) :
  iIioOO0o0ooOo0o0 , o0000oO = self . build_key ( prefix )
  if ( exact ) :
   if ( self . cache . has_key ( iIioOO0o0ooOo0o0 ) == False ) : return ( None )
   if ( self . cache [ iIioOO0o0ooOo0o0 ] . entries . has_key ( o0000oO ) == False ) : return ( None )
   return ( self . cache [ iIioOO0o0ooOo0o0 ] . entries [ o0000oO ] )
   if 64 - 64: I11i / O0 + i1IIi * II111iiii
   if 20 - 20: iIii1I11I1II1
  IIIi = None
  for oOOoOO in self . cache_sorted :
   if ( iIioOO0o0ooOo0o0 < oOOoOO ) : return ( IIIi )
   for iiI1I11 in self . cache [ oOOoOO ] . entries_sorted :
    ii11iII11i = self . cache [ oOOoOO ] . entries
    if ( iiI1I11 in ii11iII11i ) :
     oo = ii11iII11i [ iiI1I11 ]
     if ( oo == None ) : continue
     if ( prefix . is_more_specific ( oo . eid ) ) : IIIi = oo
     if 72 - 72: I11i * Ii1I . I1Ii111 * iIii1I11I1II1
     if 72 - 72: ooOoO0o
     if 63 - 63: Oo0Ooo . OoO0O00 . OoooooooOO / i1IIi
  return ( IIIi )
  if 53 - 53: OOooOOo * O0 . iII111i
  if 3 - 3: OoooooooOO * I1Ii111 * IiII - OOooOOo * I1Ii111
 def delete_cache ( self , prefix ) :
  oOOoOO , o0000oO = self . build_key ( prefix )
  if ( self . cache . has_key ( oOOoOO ) == False ) : return
  if ( self . cache [ oOOoOO ] . entries . has_key ( o0000oO ) == False ) : return
  self . cache [ oOOoOO ] . entries . pop ( o0000oO )
  self . cache [ oOOoOO ] . entries_sorted . remove ( o0000oO )
  self . cache_count -= 1
  if 78 - 78: iII111i
  if 80 - 80: i1IIi * I1IiiI + OOooOOo
 def walk_cache ( self , function , parms ) :
  for oOOoOO in self . cache_sorted :
   for o0000oO in self . cache [ oOOoOO ] . entries_sorted :
    oo = self . cache [ oOOoOO ] . entries [ o0000oO ]
    OO0OoOOOOo , parms = function ( oo , parms )
    if ( OO0OoOOOOo == False ) : return ( parms )
    if 2 - 2: o0oOOo0O0Ooo
    if 27 - 27: O0 . oO0o - i11iIiiIii / i11iIiiIii
  return ( parms )
  if 65 - 65: Oo0Ooo - o0oOOo0O0Ooo + i1IIi + I1IiiI
  if 58 - 58: iII111i * IiII . i1IIi + I1Ii111
 def print_cache ( self ) :
  lprint ( "Printing contents of {}: " . format ( self ) )
  if ( self . cache_size ( ) == 0 ) :
   lprint ( "  Cache is empty" )
   return
   if 19 - 19: iII111i * II111iiii * OOooOOo
  for oOOoOO in self . cache_sorted :
   for o0000oO in self . cache [ oOOoOO ] . entries_sorted :
    oo = self . cache [ oOOoOO ] . entries [ o0000oO ]
    lprint ( "  Mask-length: {}, key: {}, entry: {}" . format ( oOOoOO , o0000oO ,
 oo ) )
    if 86 - 86: Oo0Ooo - I11i - I1ii11iIi11i / I11i - I11i
    if 3 - 3: I1Ii111
    if 99 - 99: I1Ii111 * OOooOOo % I1IiiI / OoOoOO00 * iIii1I11I1II1
    if 45 - 45: iIii1I11I1II1
    if 73 - 73: OoOoOO00 * OOooOOo * I11i / I1IiiI + oO0o
    if 14 - 14: oO0o % o0oOOo0O0Ooo * i11iIiiIii - OoooooooOO * OOooOOo
    if 11 - 11: oO0o
    if 14 - 14: OoooooooOO . I1ii11iIi11i % I1IiiI / I1IiiI % Oo0Ooo
lisp_referral_cache = lisp_cache ( )
lisp_ddt_cache = lisp_cache ( )
lisp_sites_by_eid = lisp_cache ( )
lisp_map_cache = lisp_cache ( )
lisp_db_for_lookups = lisp_cache ( )
if 97 - 97: i1IIi
if 6 - 6: Ii1I
if 43 - 43: i1IIi - Ii1I % iIii1I11I1II1 . OoO0O00 + oO0o - iIii1I11I1II1
if 17 - 17: IiII . i1IIi
if 37 - 37: OoooooooOO + Oo0Ooo - Oo0Ooo + I1ii11iIi11i . I1Ii111 / I1IiiI
if 60 - 60: I1IiiI % Ii1I / I1Ii111 + Ii1I
if 43 - 43: I1ii11iIi11i + I11i
def lisp_map_cache_lookup ( source , dest ) :
 if 83 - 83: II111iiii + o0oOOo0O0Ooo - I1Ii111
 iIIiI1iiIi = dest . is_multicast_address ( )
 if 100 - 100: IiII - OoOoOO00 / I11i
 if 33 - 33: I1Ii111 * OoOoOO00 . I1ii11iIi11i % I1Ii111
 if 87 - 87: Oo0Ooo
 if 65 - 65: ooOoO0o . I1IiiI
 oOooO0Oo0Oo0 = lisp_map_cache . lookup_cache ( dest , False )
 if ( oOooO0Oo0Oo0 == None ) :
  OO0OO0O = source . print_sg ( dest ) if iIIiI1iiIi else dest . print_address ( )
  OO0OO0O = green ( OO0OO0O , False )
  dprint ( "Lookup for EID {} not found in map-cache" . format ( OO0OO0O ) )
  return ( None )
  if 51 - 51: IiII
  if 43 - 43: oO0o - I11i . i11iIiiIii
  if 78 - 78: i11iIiiIii + Oo0Ooo * Ii1I - o0oOOo0O0Ooo % i11iIiiIii
  if 30 - 30: I1IiiI % oO0o * OoooooooOO
  if 64 - 64: I1IiiI
 if ( iIIiI1iiIi == False ) :
  iIiIii11I1 = green ( oOooO0Oo0Oo0 . eid . print_prefix ( ) , False )
  dprint ( "Lookup for EID {} found map-cache entry {}" . format ( green ( dest . print_address ( ) , False ) , iIiIii11I1 ) )
  if 11 - 11: I1ii11iIi11i % iII111i / II111iiii % ooOoO0o % IiII
  return ( oOooO0Oo0Oo0 )
  if 14 - 14: ooOoO0o / IiII . o0oOOo0O0Ooo
  if 27 - 27: I1IiiI - OOooOOo . II111iiii * I1ii11iIi11i % ooOoO0o / I1IiiI
  if 90 - 90: o0oOOo0O0Ooo / I1ii11iIi11i - oO0o - Ii1I - I1IiiI + I1Ii111
  if 93 - 93: I1IiiI - I11i . I1IiiI - iIii1I11I1II1
  if 1 - 1: O0 . Ii1I % Ii1I + II111iiii . oO0o
 oOooO0Oo0Oo0 = oOooO0Oo0Oo0 . lookup_source_cache ( source , False )
 if ( oOooO0Oo0Oo0 == None ) :
  OO0OO0O = source . print_sg ( dest )
  dprint ( "Lookup for EID {} not found in map-cache" . format ( OO0OO0O ) )
  return ( None )
  if 24 - 24: o0oOOo0O0Ooo . I1Ii111 % O0
  if 67 - 67: I1IiiI * Ii1I
  if 64 - 64: OOooOOo
  if 90 - 90: iII111i . OoOoOO00 + i1IIi % ooOoO0o * I11i + OoooooooOO
  if 2 - 2: o0oOOo0O0Ooo . II111iiii
 iIiIii11I1 = green ( oOooO0Oo0Oo0 . print_eid_tuple ( ) , False )
 dprint ( "Lookup for EID {} found map-cache entry {}" . format ( green ( source . print_sg ( dest ) , False ) , iIiIii11I1 ) )
 if 9 - 9: I1Ii111 - II111iiii + OoOoOO00 . OoO0O00
 return ( oOooO0Oo0Oo0 )
 if 33 - 33: Oo0Ooo
 if 12 - 12: i11iIiiIii . Oo0Ooo / OoOoOO00 + iII111i . Ii1I + ooOoO0o
 if 66 - 66: IiII
 if 41 - 41: II111iiii + Oo0Ooo / iII111i . IiII / iII111i / I1IiiI
 if 78 - 78: o0oOOo0O0Ooo % OoOoOO00 . O0
 if 41 - 41: iIii1I11I1II1 . OOooOOo - Oo0Ooo % OOooOOo
 if 90 - 90: i11iIiiIii + OoooooooOO - i11iIiiIii + OoooooooOO
def lisp_referral_cache_lookup ( eid , group , exact ) :
 if ( group and group . is_null ( ) ) :
  i11iII1I1I1i1 = lisp_referral_cache . lookup_cache ( eid , exact )
  return ( i11iII1I1I1i1 )
  if 23 - 23: i11iIiiIii - IiII - I1ii11iIi11i + I1ii11iIi11i % I1IiiI
  if 79 - 79: II111iiii / OoooooooOO
  if 35 - 35: i1IIi + IiII + II111iiii % OOooOOo
  if 25 - 25: I11i + i11iIiiIii + O0 - Ii1I
  if 69 - 69: I11i . OoOoOO00 / OOooOOo / i1IIi . II111iiii
 if ( eid == None or eid . is_null ( ) ) : return ( None )
 if 17 - 17: I1Ii111
 if 2 - 2: O0 % OoOoOO00 + oO0o
 if 24 - 24: iII111i + iII111i - OoooooooOO % OoooooooOO * O0
 if 51 - 51: IiII
 if 31 - 31: I11i - iIii1I11I1II1 * Ii1I + Ii1I
 if 10 - 10: OoOoOO00 - i11iIiiIii % iIii1I11I1II1 / ooOoO0o * i11iIiiIii - Ii1I
 i11iII1I1I1i1 = lisp_referral_cache . lookup_cache ( group , exact )
 if ( i11iII1I1I1i1 == None ) : return ( None )
 if 64 - 64: II111iiii . i11iIiiIii . iII111i . OOooOOo
 ooO0oo000 = i11iII1I1I1i1 . lookup_source_cache ( eid , exact )
 if ( ooO0oo000 ) : return ( ooO0oo000 )
 if 74 - 74: I11i / OoOoOO00 - i1IIi
 if ( exact ) : i11iII1I1I1i1 = None
 return ( i11iII1I1I1i1 )
 if 93 - 93: o0oOOo0O0Ooo / i11iIiiIii % I1IiiI - OoooooooOO
 if 96 - 96: I1ii11iIi11i - OoO0O00 * Oo0Ooo . oO0o + OoO0O00
 if 5 - 5: iIii1I11I1II1
 if 14 - 14: iII111i
 if 66 - 66: oO0o % i1IIi % OoooooooOO
 if 58 - 58: OOooOOo
 if 89 - 89: iIii1I11I1II1 - i1IIi
def lisp_ddt_cache_lookup ( eid , group , exact ) :
 if ( group . is_null ( ) ) :
  ooOoO = lisp_ddt_cache . lookup_cache ( eid , exact )
  return ( ooOoO )
  if 26 - 26: OOooOOo - iII111i * I1ii11iIi11i / iII111i
  if 9 - 9: I1Ii111 / II111iiii * I1Ii111 / I11i - OoO0O00
  if 36 - 36: IiII . OoOoOO00 . Ii1I
  if 31 - 31: iIii1I11I1II1
  if 84 - 84: I1ii11iIi11i - iII111i * I1IiiI
 if ( eid . is_null ( ) ) : return ( None )
 if 88 - 88: OOooOOo / Oo0Ooo
 if 31 - 31: II111iiii
 if 32 - 32: o0oOOo0O0Ooo % o0oOOo0O0Ooo
 if 67 - 67: IiII + oO0o * IiII
 if 26 - 26: I1ii11iIi11i + i1IIi . i1IIi - oO0o + I1IiiI * o0oOOo0O0Ooo
 if 62 - 62: ooOoO0o + ooOoO0o % I11i
 ooOoO = lisp_ddt_cache . lookup_cache ( group , exact )
 if ( ooOoO == None ) : return ( None )
 if 100 - 100: II111iiii . OoooooooOO
 I111iiiii1I = ooOoO . lookup_source_cache ( eid , exact )
 if ( I111iiiii1I ) : return ( I111iiiii1I )
 if 15 - 15: I1ii11iIi11i * iII111i + i11iIiiIii
 if ( exact ) : ooOoO = None
 return ( ooOoO )
 if 68 - 68: i1IIi / oO0o * I1ii11iIi11i - OoOoOO00 + Oo0Ooo / O0
 if 1 - 1: ooOoO0o - Oo0Ooo + I1Ii111
 if 90 - 90: I1Ii111 * O0 . iII111i - Oo0Ooo % iIii1I11I1II1
 if 7 - 7: I1ii11iIi11i % o0oOOo0O0Ooo % O0 % iIii1I11I1II1
 if 10 - 10: OoooooooOO - iII111i . i1IIi % oO0o . OoooooooOO + OOooOOo
 if 59 - 59: I1IiiI * OoooooooOO % OOooOOo / I11i
 if 77 - 77: II111iiii - IiII % OOooOOo
def lisp_site_eid_lookup ( eid , group , exact ) :
 if 22 - 22: OoooooooOO / oO0o
 if ( group . is_null ( ) ) :
  o0O0oOo = lisp_sites_by_eid . lookup_cache ( eid , exact )
  return ( o0O0oOo )
  if 78 - 78: oO0o * I11i . i1IIi % i1IIi + i1IIi / OOooOOo
  if 66 - 66: OoooooooOO % o0oOOo0O0Ooo / I11i * I1Ii111
  if 12 - 12: I1Ii111
  if 17 - 17: I1Ii111 % oO0o + O0
  if 15 - 15: o0oOOo0O0Ooo - OoooooooOO % ooOoO0o % oO0o / i11iIiiIii / Oo0Ooo
 if ( eid . is_null ( ) ) : return ( None )
 if 59 - 59: iII111i + O0 - I1ii11iIi11i * I1ii11iIi11i + iIii1I11I1II1
 if 41 - 41: iIii1I11I1II1 . O0 - ooOoO0o / OoOoOO00 % iIii1I11I1II1 + IiII
 if 23 - 23: OoOoOO00 + ooOoO0o . i11iIiiIii
 if 39 - 39: OoOoOO00 - I1ii11iIi11i / I1Ii111
 if 48 - 48: IiII - oO0o + I11i % o0oOOo0O0Ooo
 if 81 - 81: Oo0Ooo . I1Ii111 * iIii1I11I1II1
 o0O0oOo = lisp_sites_by_eid . lookup_cache ( group , exact )
 if ( o0O0oOo == None ) : return ( None )
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
 if 98 - 98: O0 - I1Ii111 % oO0o - iII111i + Ii1I * i1IIi
 I11I1Ii1i = o0O0oOo . lookup_source_cache ( eid , exact )
 if ( I11I1Ii1i ) : return ( I11I1Ii1i )
 if 76 - 76: o0oOOo0O0Ooo
 if ( exact ) :
  o0O0oOo = None
 else :
  IiIii1 = o0O0oOo . parent_for_more_specifics
  if ( IiIii1 and IiIii1 . accept_more_specifics ) :
   if ( group . is_more_specific ( IiIii1 . group ) ) : o0O0oOo = IiIii1
   if 55 - 55: OOooOOo + I1ii11iIi11i * Oo0Ooo
   if 11 - 11: i1IIi - OoooooooOO * OoOoOO00 / oO0o - OoooooooOO - I1IiiI
 return ( o0O0oOo )
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
 if 17 - 17: i11iIiiIii + oO0o * iII111i . II111iiii
class lisp_address ( ) :
 def __init__ ( self , afi , addr_str , mask_len , iid ) :
  self . afi = afi
  self . mask_len = mask_len
  self . instance_id = iid
  self . iid_list = [ ]
  self . address = 0
  if ( addr_str != "" ) : self . store_address ( addr_str )
  if 44 - 44: I1ii11iIi11i
  if 39 - 39: iII111i + Oo0Ooo / oO0o
 def copy_address ( self , addr ) :
  if ( addr == None ) : return
  self . afi = addr . afi
  self . address = addr . address
  self . mask_len = addr . mask_len
  self . instance_id = addr . instance_id
  self . iid_list = addr . iid_list
  if 95 - 95: I1Ii111 * oO0o / ooOoO0o . Ii1I . OoOoOO00
  if 99 - 99: I1IiiI * II111iiii
 def make_default_route ( self , addr ) :
  self . afi = addr . afi
  self . instance_id = addr . instance_id
  self . mask_len = 0
  self . address = 0
  if 84 - 84: II111iiii - I1IiiI
  if 41 - 41: iIii1I11I1II1 % I1Ii111 % OoOoOO00
 def make_default_multicast_route ( self , addr ) :
  self . afi = addr . afi
  self . instance_id = addr . instance_id
  if ( self . afi == LISP_AFI_IPV4 ) :
   self . address = 0xe0000000
   self . mask_len = 4
   if 35 - 35: I11i + i1IIi
  if ( self . afi == LISP_AFI_IPV6 ) :
   self . address = 0xff << 120
   self . mask_len = 8
   if 85 - 85: Ii1I * Ii1I . OoOoOO00 / Oo0Ooo
  if ( self . afi == LISP_AFI_MAC ) :
   self . address = 0xffffffffffff
   self . mask_len = 48
   if 97 - 97: oO0o % iIii1I11I1II1
   if 87 - 87: II111iiii % I1IiiI + oO0o - I11i / I11i
   if 16 - 16: I1IiiI
 def not_set ( self ) :
  return ( self . afi == LISP_AFI_NONE )
  if 39 - 39: ooOoO0o * II111iiii
  if 90 - 90: OoooooooOO * ooOoO0o
 def is_private_address ( self ) :
  if ( self . is_ipv4 ( ) == False ) : return ( False )
  o00Ooo0 = self . address
  if ( ( ( o00Ooo0 & 0xff000000 ) >> 24 ) == 10 ) : return ( True )
  if ( ( ( o00Ooo0 & 0xff000000 ) >> 24 ) == 172 ) :
   iiiII111I11 = ( o00Ooo0 & 0x00ff0000 ) >> 16
   if ( iiiII111I11 >= 16 and iiiII111I11 <= 31 ) : return ( True )
   if 82 - 82: I1IiiI % iIii1I11I1II1 * Ii1I . OOooOOo / o0oOOo0O0Ooo
  if ( ( ( o00Ooo0 & 0xffff0000 ) >> 16 ) == 0xc0a8 ) : return ( True )
  return ( False )
  if 12 - 12: oO0o - O0
  if 62 - 62: OoOoOO00 % I1Ii111 . iIii1I11I1II1 * I11i . oO0o - iII111i
 def is_multicast_address ( self ) :
  if ( self . is_ipv4 ( ) ) : return ( self . is_ipv4_multicast ( ) )
  if ( self . is_ipv6 ( ) ) : return ( self . is_ipv6_multicast ( ) )
  if ( self . is_mac ( ) ) : return ( self . is_mac_multicast ( ) )
  return ( False )
  if 22 - 22: OoooooooOO - Oo0Ooo . OoOoOO00
  if 73 - 73: Ii1I . IiII + OoO0O00
 def host_mask_len ( self ) :
  if ( self . afi == LISP_AFI_IPV4 ) : return ( LISP_IPV4_HOST_MASK_LEN )
  if ( self . afi == LISP_AFI_IPV6 ) : return ( LISP_IPV6_HOST_MASK_LEN )
  if ( self . afi == LISP_AFI_MAC ) : return ( LISP_MAC_HOST_MASK_LEN )
  if ( self . afi == LISP_AFI_E164 ) : return ( LISP_E164_HOST_MASK_LEN )
  if ( self . afi == LISP_AFI_NAME ) : return ( len ( self . address ) * 8 )
  if ( self . afi == LISP_AFI_GEO_COORD ) :
   return ( len ( self . address . print_geo ( ) ) * 8 )
   if 64 - 64: IiII
  return ( 0 )
  if 83 - 83: iIii1I11I1II1 % Oo0Ooo * I1Ii111 . I1ii11iIi11i
  if 10 - 10: I1ii11iIi11i
 def is_iana_eid ( self ) :
  if ( self . is_ipv6 ( ) == False ) : return ( False )
  o00Ooo0 = self . address >> 96
  return ( o00Ooo0 == 0x20010005 )
  if 27 - 27: OoOoOO00 . i1IIi
  if 76 - 76: I1ii11iIi11i + oO0o . I1ii11iIi11i - o0oOOo0O0Ooo * Oo0Ooo
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
   if 20 - 20: Oo0Ooo
  return ( 0 )
  if 45 - 45: iIii1I11I1II1 % O0 / I1IiiI . o0oOOo0O0Ooo * IiII
  if 87 - 87: II111iiii / OoooooooOO * II111iiii % i11iIiiIii - ooOoO0o + II111iiii
 def afi_to_version ( self ) :
  if ( self . afi == LISP_AFI_IPV4 ) : return ( 4 )
  if ( self . afi == LISP_AFI_IPV6 ) : return ( 6 )
  return ( 0 )
  if 39 - 39: I1Ii111
  if 51 - 51: o0oOOo0O0Ooo * I11i
 def packet_format ( self ) :
  if 42 - 42: OOooOOo % I11i
  if 84 - 84: Oo0Ooo * OoOoOO00 / Ii1I / IiII / o0oOOo0O0Ooo . I1ii11iIi11i
  if 81 - 81: I1IiiI
  if 82 - 82: I1Ii111 - OoooooooOO - Ii1I
  if 34 - 34: OOooOOo . iIii1I11I1II1 / I1IiiI . Oo0Ooo - iIii1I11I1II1
  if ( self . afi == LISP_AFI_IPV4 ) : return ( "I" )
  if ( self . afi == LISP_AFI_IPV6 ) : return ( "QQ" )
  if ( self . afi == LISP_AFI_MAC ) : return ( "HHH" )
  if ( self . afi == LISP_AFI_E164 ) : return ( "II" )
  if ( self . afi == LISP_AFI_LCAF ) : return ( "I" )
  return ( "" )
  if 83 - 83: iII111i - I1ii11iIi11i + iII111i
  if 4 - 4: o0oOOo0O0Ooo % iIii1I11I1II1 + I11i
 def pack_address ( self ) :
  I1I = self . packet_format ( )
  iIIi1 = ""
  if ( self . is_ipv4 ( ) ) :
   iIIi1 = struct . pack ( I1I , socket . htonl ( self . address ) )
  elif ( self . is_ipv6 ( ) ) :
   III1IiI1i1i = byte_swap_64 ( self . address >> 64 )
   o0OOOOOo0 = byte_swap_64 ( self . address & 0xffffffffffffffff )
   iIIi1 = struct . pack ( I1I , III1IiI1i1i , o0OOOOOo0 )
  elif ( self . is_mac ( ) ) :
   o00Ooo0 = self . address
   III1IiI1i1i = ( o00Ooo0 >> 32 ) & 0xffff
   o0OOOOOo0 = ( o00Ooo0 >> 16 ) & 0xffff
   OO00 = o00Ooo0 & 0xffff
   iIIi1 = struct . pack ( I1I , III1IiI1i1i , o0OOOOOo0 , OO00 )
  elif ( self . is_e164 ( ) ) :
   o00Ooo0 = self . address
   III1IiI1i1i = ( o00Ooo0 >> 32 ) & 0xffffffff
   o0OOOOOo0 = ( o00Ooo0 & 0xffffffff )
   iIIi1 = struct . pack ( I1I , III1IiI1i1i , o0OOOOOo0 )
  elif ( self . is_dist_name ( ) ) :
   iIIi1 += self . address + "\0"
   if 74 - 74: I11i
  return ( iIIi1 )
  if 63 - 63: I1IiiI
  if 36 - 36: OOooOOo + IiII
 def unpack_address ( self , packet ) :
  I1I = self . packet_format ( )
  ii1I1iIi = struct . calcsize ( I1I )
  if ( len ( packet ) < ii1I1iIi ) : return ( None )
  if 37 - 37: iII111i + i1IIi % Oo0Ooo / o0oOOo0O0Ooo / iII111i
  o00Ooo0 = struct . unpack ( I1I , packet [ : ii1I1iIi ] )
  if 81 - 81: ooOoO0o
  if ( self . is_ipv4 ( ) ) :
   self . address = socket . ntohl ( o00Ooo0 [ 0 ] )
   if 74 - 74: OoO0O00
  elif ( self . is_ipv6 ( ) ) :
   if 13 - 13: I1ii11iIi11i / OoO0O00
   if 90 - 90: iIii1I11I1II1 - OoO0O00 . i1IIi / o0oOOo0O0Ooo + O0
   if 94 - 94: IiII * i1IIi
   if 90 - 90: O0 % I1IiiI . o0oOOo0O0Ooo % ooOoO0o % I1IiiI
   if 16 - 16: OoO0O00 / OOooOOo / iIii1I11I1II1 / OoooooooOO . oO0o - I1Ii111
   if 43 - 43: OoOoOO00 % OOooOOo / I1IiiI + I1IiiI
   if 40 - 40: OOooOOo . I1Ii111 + I1Ii111
   if 4 - 4: iIii1I11I1II1 - iIii1I11I1II1 * I11i
   if ( o00Ooo0 [ 0 ] <= 0xffff and ( o00Ooo0 [ 0 ] & 0xff ) == 0 ) :
    Ii1iI1 = ( o00Ooo0 [ 0 ] << 48 ) << 64
   else :
    Ii1iI1 = byte_swap_64 ( o00Ooo0 [ 0 ] ) << 64
    if 24 - 24: I1Ii111
   iIiiI1ii1 = byte_swap_64 ( o00Ooo0 [ 1 ] )
   self . address = Ii1iI1 | iIiiI1ii1
   if 66 - 66: i1IIi
  elif ( self . is_mac ( ) ) :
   oOooI1I = o00Ooo0 [ 0 ]
   I1iI1i1I11i1 = o00Ooo0 [ 1 ]
   iI11I = o00Ooo0 [ 2 ]
   self . address = ( oOooI1I << 32 ) + ( I1iI1i1I11i1 << 16 ) + iI11I
   if 49 - 49: IiII . iII111i * Ii1I % o0oOOo0O0Ooo * i1IIi . Ii1I
  elif ( self . is_e164 ( ) ) :
   self . address = ( o00Ooo0 [ 0 ] << 32 ) + o00Ooo0 [ 1 ]
   if 89 - 89: IiII % I11i
  elif ( self . is_dist_name ( ) ) :
   packet , self . address = lisp_decode_dist_name ( packet )
   self . mask_len = len ( self . address ) * 8
   ii1I1iIi = 0
   if 20 - 20: OoOoOO00 % o0oOOo0O0Ooo
  packet = packet [ ii1I1iIi : : ]
  return ( packet )
  if 38 - 38: O0 + IiII % I11i . OoO0O00 + I1ii11iIi11i * OOooOOo
  if 2 - 2: OoO0O00 % OoO0O00 * Oo0Ooo - I11i * Ii1I . II111iiii
 def is_ipv4 ( self ) :
  return ( True if ( self . afi == LISP_AFI_IPV4 ) else False )
  if 28 - 28: I11i
  if 7 - 7: Ii1I . I1ii11iIi11i / o0oOOo0O0Ooo - I1ii11iIi11i / Ii1I
 def is_ipv4_link_local ( self ) :
  if ( self . is_ipv4 ( ) == False ) : return ( False )
  return ( ( ( self . address >> 16 ) & 0xffff ) == 0xa9fe )
  if 6 - 6: O0
  if 67 - 67: I1Ii111
 def is_ipv4_loopback ( self ) :
  if ( self . is_ipv4 ( ) == False ) : return ( False )
  return ( self . address == 0x7f000001 )
  if 49 - 49: IiII / i1IIi . OOooOOo
  if 64 - 64: O0
 def is_ipv4_multicast ( self ) :
  if ( self . is_ipv4 ( ) == False ) : return ( False )
  return ( ( ( self . address >> 24 ) & 0xf0 ) == 0xe0 )
  if 10 - 10: I1ii11iIi11i % ooOoO0o * IiII - iIii1I11I1II1
  if 42 - 42: iII111i
 def is_ipv4_string ( self , addr_str ) :
  return ( addr_str . find ( "." ) != - 1 )
  if 96 - 96: OoO0O00 + o0oOOo0O0Ooo . ooOoO0o
  if 44 - 44: I11i * iIii1I11I1II1 . I1ii11iIi11i
 def is_ipv6 ( self ) :
  return ( True if ( self . afi == LISP_AFI_IPV6 ) else False )
  if 9 - 9: o0oOOo0O0Ooo
  if 23 - 23: ooOoO0o * OoO0O00 + O0 % I1Ii111
 def is_ipv6_link_local ( self ) :
  if ( self . is_ipv6 ( ) == False ) : return ( False )
  return ( ( ( self . address >> 112 ) & 0xffff ) == 0xfe80 )
  if 21 - 21: Ii1I * OoOoOO00
  if 29 - 29: iIii1I11I1II1 / ooOoO0o
 def is_ipv6_string_link_local ( self , addr_str ) :
  return ( addr_str . find ( "fe80::" ) != - 1 )
  if 75 - 75: OoooooooOO + I1IiiI % OoOoOO00 / O0 - IiII
  if 88 - 88: OoO0O00 % Ii1I
 def is_ipv6_loopback ( self ) :
  if ( self . is_ipv6 ( ) == False ) : return ( False )
  return ( self . address == 1 )
  if 12 - 12: OoooooooOO . O0
  if 33 - 33: OoooooooOO / I11i . II111iiii * i1IIi
 def is_ipv6_multicast ( self ) :
  if ( self . is_ipv6 ( ) == False ) : return ( False )
  return ( ( ( self . address >> 120 ) & 0xff ) == 0xff )
  if 34 - 34: i11iIiiIii / OoOoOO00
  if 100 - 100: o0oOOo0O0Ooo - I1IiiI / I11i
 def is_ipv6_string ( self , addr_str ) :
  return ( addr_str . find ( ":" ) != - 1 )
  if 43 - 43: o0oOOo0O0Ooo % iIii1I11I1II1
  if 85 - 85: oO0o + OoooooooOO - IiII % o0oOOo0O0Ooo * ooOoO0o * II111iiii
 def is_mac ( self ) :
  return ( True if ( self . afi == LISP_AFI_MAC ) else False )
  if 4 - 4: Ii1I . i1IIi + Oo0Ooo % I11i . OoO0O00
  if 70 - 70: OOooOOo * OoOoOO00 / OoOoOO00 / OoOoOO00
 def is_mac_multicast ( self ) :
  if ( self . is_mac ( ) == False ) : return ( False )
  return ( ( self . address & 0x010000000000 ) != 0 )
  if 23 - 23: I1IiiI
  if 24 - 24: I1Ii111 * i1IIi % O0 * Ii1I + iII111i
 def is_mac_broadcast ( self ) :
  if ( self . is_mac ( ) == False ) : return ( False )
  return ( self . address == 0xffffffffffff )
  if 14 - 14: oO0o * iII111i + Ii1I + Ii1I * IiII
  if 82 - 82: IiII * ooOoO0o / OOooOOo + OoOoOO00
 def is_mac_string ( self , addr_str ) :
  return ( len ( addr_str ) == 15 and addr_str . find ( "-" ) != - 1 )
  if 32 - 32: IiII
  if 90 - 90: I1ii11iIi11i / I11i * o0oOOo0O0Ooo % O0 * i11iIiiIii
 def is_link_local_multicast ( self ) :
  if ( self . is_ipv4 ( ) ) :
   return ( ( 0xe0ffff00 & self . address ) == 0xe0000000 )
   if 68 - 68: I11i . Ii1I + I11i / IiII . I11i / iIii1I11I1II1
  if ( self . is_ipv6 ( ) ) :
   return ( ( self . address >> 112 ) & 0xffff == 0xff02 )
   if 96 - 96: O0
  return ( False )
  if 2 - 2: OoO0O00 / iII111i + o0oOOo0O0Ooo
  if 27 - 27: I11i - OoOoOO00 - ooOoO0o - I1IiiI
 def is_null ( self ) :
  return ( True if ( self . afi == LISP_AFI_NONE ) else False )
  if 51 - 51: I11i + I11i + O0 + O0 * I1Ii111
  if 61 - 61: IiII . O0
 def is_ultimate_root ( self ) :
  return ( True if self . afi == LISP_AFI_ULTIMATE_ROOT else False )
  if 38 - 38: Ii1I * I1ii11iIi11i - i11iIiiIii + ooOoO0o * I11i
  if 74 - 74: OoOoOO00 . o0oOOo0O0Ooo
 def is_iid_range ( self ) :
  return ( True if self . afi == LISP_AFI_IID_RANGE else False )
  if 40 - 40: ooOoO0o + I1ii11iIi11i * i11iIiiIii / i1IIi
  if 95 - 95: oO0o / IiII * II111iiii * Ii1I . OoO0O00 . OoO0O00
 def is_e164 ( self ) :
  return ( True if ( self . afi == LISP_AFI_E164 ) else False )
  if 85 - 85: I1IiiI / II111iiii * OoO0O00 + ooOoO0o / OoO0O00 % OOooOOo
  if 100 - 100: I1Ii111 % OoooooooOO % OoOoOO00 % I1IiiI
 def is_dist_name ( self ) :
  return ( True if ( self . afi == LISP_AFI_NAME ) else False )
  if 32 - 32: OoO0O00 + OOooOOo . OoO0O00 - Oo0Ooo
  if 12 - 12: I1IiiI * OoO0O00 - II111iiii . i1IIi
 def is_geo_prefix ( self ) :
  return ( True if ( self . afi == LISP_AFI_GEO_COORD ) else False )
  if 86 - 86: OOooOOo / OoooooooOO - IiII
  if 56 - 56: I1ii11iIi11i - i1IIi * OoooooooOO * O0 * I1IiiI - I1Ii111
 def is_binary ( self ) :
  if ( self . is_dist_name ( ) ) : return ( False )
  if ( self . is_geo_prefix ( ) ) : return ( False )
  return ( True )
  if 32 - 32: OoooooooOO . OOooOOo . OoO0O00 . IiII / I11i % i1IIi
  if 21 - 21: O0 . OoO0O00 * I1ii11iIi11i % iII111i + OoooooooOO
 def store_address ( self , addr_str ) :
  if ( self . afi == LISP_AFI_NONE ) : self . string_to_afi ( addr_str )
  if 8 - 8: oO0o * iII111i * I11i
  if 30 - 30: I1Ii111
  if 61 - 61: iII111i
  if 50 - 50: Ii1I / I1IiiI . O0
  ooOooo0OO = addr_str . find ( "[" )
  OOOoOOo000oo = addr_str . find ( "]" )
  if ( ooOooo0OO != - 1 and OOOoOOo000oo != - 1 ) :
   self . instance_id = int ( addr_str [ ooOooo0OO + 1 : OOOoOOo000oo ] )
   addr_str = addr_str [ OOOoOOo000oo + 1 : : ]
   if ( self . is_dist_name ( ) == False ) :
    addr_str = addr_str . replace ( " " , "" )
    if 49 - 49: I1Ii111 . OoO0O00 % O0
    if 15 - 15: I11i - Oo0Ooo / I1Ii111 . ooOoO0o % I1IiiI
    if 62 - 62: II111iiii + ooOoO0o + I1IiiI
    if 70 - 70: o0oOOo0O0Ooo + Ii1I . OoO0O00 * Ii1I + OOooOOo + ooOoO0o
    if 13 - 13: I1ii11iIi11i
    if 97 - 97: oO0o - Oo0Ooo . i11iIiiIii % ooOoO0o * i11iIiiIii - OoooooooOO
  if ( self . is_ipv4 ( ) ) :
   I1iiI11i1iI = addr_str . split ( "." )
   I1Iii1iI1 = int ( I1iiI11i1iI [ 0 ] ) << 24
   I1Iii1iI1 += int ( I1iiI11i1iI [ 1 ] ) << 16
   I1Iii1iI1 += int ( I1iiI11i1iI [ 2 ] ) << 8
   I1Iii1iI1 += int ( I1iiI11i1iI [ 3 ] )
   self . address = I1Iii1iI1
  elif ( self . is_ipv6 ( ) ) :
   if 51 - 51: Ii1I + IiII / I1ii11iIi11i + O0 % Ii1I
   if 55 - 55: iII111i % o0oOOo0O0Ooo - oO0o % OoooooooOO
   if 18 - 18: OoooooooOO - I1ii11iIi11i
   if 94 - 94: OOooOOo . Oo0Ooo + Ii1I * o0oOOo0O0Ooo
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
   oOooO000o000oOo = ( addr_str [ 2 : 4 ] == "::" )
   try :
    addr_str = socket . inet_pton ( socket . AF_INET6 , addr_str )
   except :
    addr_str = socket . inet_pton ( socket . AF_INET6 , "0::0" )
    if 72 - 72: OoooooooOO - O0 . OoO0O00
   addr_str = binascii . hexlify ( addr_str )
   if 46 - 46: o0oOOo0O0Ooo % OoO0O00 + I11i % o0oOOo0O0Ooo + oO0o . Oo0Ooo
   if ( oOooO000o000oOo ) :
    addr_str = addr_str [ 2 : 4 ] + addr_str [ 0 : 2 ] + addr_str [ 4 : : ]
    if 58 - 58: I1Ii111 + I1ii11iIi11i
   self . address = int ( addr_str , 16 )
   if 57 - 57: OOooOOo + II111iiii
  elif ( self . is_geo_prefix ( ) ) :
   ii11iIIiiI1I = lisp_geo ( None )
   ii11iIIiiI1I . name = "geo-prefix-{}" . format ( ii11iIIiiI1I )
   ii11iIIiiI1I . parse_geo_string ( addr_str )
   self . address = ii11iIIiiI1I
  elif ( self . is_mac ( ) ) :
   addr_str = addr_str . replace ( "-" , "" )
   I1Iii1iI1 = int ( addr_str , 16 )
   self . address = I1Iii1iI1
  elif ( self . is_e164 ( ) ) :
   addr_str = addr_str [ 1 : : ]
   I1Iii1iI1 = int ( addr_str , 16 )
   self . address = I1Iii1iI1 << 4
  elif ( self . is_dist_name ( ) ) :
   self . address = addr_str . replace ( "'" , "" )
   if 67 - 67: II111iiii
  self . mask_len = self . host_mask_len ( )
  if 39 - 39: i1IIi
  if 16 - 16: OoOoOO00 % iIii1I11I1II1 + Ii1I - o0oOOo0O0Ooo . Oo0Ooo + i1IIi
 def store_prefix ( self , prefix_str ) :
  if ( self . is_geo_string ( prefix_str ) ) :
   oooO0 = prefix_str . find ( "]" )
   i1iIi = len ( prefix_str [ oooO0 + 1 : : ] ) * 8
  elif ( prefix_str . find ( "/" ) != - 1 ) :
   prefix_str , i1iIi = prefix_str . split ( "/" )
  else :
   IIIIIiI = prefix_str . find ( "'" )
   if ( IIIIIiI == - 1 ) : return
   O00oOooo0 = prefix_str . find ( "'" , IIIIIiI + 1 )
   if ( O00oOooo0 == - 1 ) : return
   i1iIi = len ( prefix_str [ IIIIIiI + 1 : O00oOooo0 ] ) * 8
   if 59 - 59: i1IIi
   if 37 - 37: OoO0O00 / I1ii11iIi11i / OoOoOO00
  self . string_to_afi ( prefix_str )
  self . store_address ( prefix_str )
  self . mask_len = int ( i1iIi )
  if 15 - 15: I1IiiI % iIii1I11I1II1 . I1Ii111
  if 71 - 71: I11i - Ii1I + i11iIiiIii % I1ii11iIi11i - OoO0O00 - OOooOOo
 def zero_host_bits ( self ) :
  oo0000oooO = ( 2 ** self . mask_len ) - 1
  iIi11i11II = self . addr_length ( ) * 8 - self . mask_len
  oo0000oooO <<= iIi11i11II
  self . address &= oo0000oooO
  if 72 - 72: I1ii11iIi11i % OoOoOO00 - iIii1I11I1II1
  if 15 - 15: Oo0Ooo * Ii1I % I1IiiI
 def is_geo_string ( self , addr_str ) :
  oooO0 = addr_str . find ( "]" )
  if ( oooO0 != - 1 ) : addr_str = addr_str [ oooO0 + 1 : : ]
  if 25 - 25: OoOoOO00 . Ii1I . IiII % OoO0O00 + ooOoO0o * OoOoOO00
  ii11iIIiiI1I = addr_str . split ( "/" )
  if ( len ( ii11iIIiiI1I ) == 2 ) :
   if ( ii11iIIiiI1I [ 1 ] . isdigit ( ) == False ) : return ( False )
   if 90 - 90: IiII - IiII % iIii1I11I1II1
  ii11iIIiiI1I = ii11iIIiiI1I [ 0 ]
  ii11iIIiiI1I = ii11iIIiiI1I . split ( "-" )
  IIi1I1 = len ( ii11iIIiiI1I )
  if ( IIi1I1 < 8 or IIi1I1 > 9 ) : return ( False )
  if 16 - 16: I1IiiI . i11iIiiIii . Ii1I - O0 - o0oOOo0O0Ooo + I1Ii111
  for oO00oOOoo in range ( 0 , IIi1I1 ) :
   if ( oO00oOOoo == 3 ) :
    if ( ii11iIIiiI1I [ oO00oOOoo ] in [ "N" , "S" ] ) : continue
    return ( False )
    if 10 - 10: oO0o - O0 / Ii1I - OOooOOo - I1Ii111
   if ( oO00oOOoo == 7 ) :
    if ( ii11iIIiiI1I [ oO00oOOoo ] in [ "W" , "E" ] ) : continue
    return ( False )
    if 41 - 41: O0 / I1IiiI - I1ii11iIi11i - i11iIiiIii
   if ( ii11iIIiiI1I [ oO00oOOoo ] . isdigit ( ) == False ) : return ( False )
   if 2 - 2: OoO0O00 % O0 + iII111i * I1Ii111 / OOooOOo
  return ( True )
  if 7 - 7: IiII
  if 30 - 30: iIii1I11I1II1 - OoooooooOO + Oo0Ooo . i1IIi % o0oOOo0O0Ooo
 def string_to_afi ( self , addr_str ) :
  if ( addr_str . count ( "'" ) == 2 ) :
   self . afi = LISP_AFI_NAME
   return
   if 7 - 7: IiII - iII111i
  if ( addr_str . find ( ":" ) != - 1 ) : self . afi = LISP_AFI_IPV6
  elif ( addr_str . find ( "." ) != - 1 ) : self . afi = LISP_AFI_IPV4
  elif ( addr_str . find ( "+" ) != - 1 ) : self . afi = LISP_AFI_E164
  elif ( self . is_geo_string ( addr_str ) ) : self . afi = LISP_AFI_GEO_COORD
  elif ( addr_str . find ( "-" ) != - 1 ) : self . afi = LISP_AFI_MAC
  else : self . afi = LISP_AFI_NONE
  if 59 - 59: Oo0Ooo * ooOoO0o - Ii1I / II111iiii / Oo0Ooo
  if 8 - 8: IiII / OoooooooOO - iIii1I11I1II1
 def print_address ( self ) :
  o00Ooo0 = self . print_address_no_iid ( )
  iiI1iii = "[" + str ( self . instance_id )
  for ooOooo0OO in self . iid_list : iiI1iii += "," + str ( ooOooo0OO )
  iiI1iii += "]"
  o00Ooo0 = "{}{}" . format ( iiI1iii , o00Ooo0 )
  return ( o00Ooo0 )
  if 10 - 10: I11i . I11i - OoO0O00 - II111iiii
  if 94 - 94: ooOoO0o
 def print_address_no_iid ( self ) :
  if ( self . is_ipv4 ( ) ) :
   o00Ooo0 = self . address
   iI1I1IIiI1i1 = o00Ooo0 >> 24
   iiIii111 = ( o00Ooo0 >> 16 ) & 0xff
   iiI1I1i11 = ( o00Ooo0 >> 8 ) & 0xff
   oOO0Oo = o00Ooo0 & 0xff
   return ( "{}.{}.{}.{}" . format ( iI1I1IIiI1i1 , iiIii111 , iiI1I1i11 , oOO0Oo ) )
  elif ( self . is_ipv6 ( ) ) :
   oooOO0oOooO00 = lisp_hex_string ( self . address ) . zfill ( 32 )
   oooOO0oOooO00 = binascii . unhexlify ( oooOO0oOooO00 )
   oooOO0oOooO00 = socket . inet_ntop ( socket . AF_INET6 , oooOO0oOooO00 )
   if 99 - 99: oO0o * IiII * oO0o
   if 70 - 70: IiII + iII111i / I1ii11iIi11i
   if 97 - 97: I1IiiI * OoOoOO00 / iII111i * i11iIiiIii
   if 20 - 20: Ii1I . I11i % iII111i * iIii1I11I1II1 . OoO0O00 . Ii1I
   if ( oooOO0oOooO00 [ 2 : 6 ] == "00::" ) :
    oooOO0oOooO00 = oooOO0oOooO00 [ 0 : 2 ] + oooOO0oOooO00 [ 4 : : ]
    if 50 - 50: I1IiiI % OOooOOo / iIii1I11I1II1 / I1ii11iIi11i % oO0o . Ii1I
   return ( "{}" . format ( oooOO0oOooO00 ) )
  elif ( self . is_geo_prefix ( ) ) :
   return ( "{}" . format ( self . address . print_geo ( ) ) )
  elif ( self . is_mac ( ) ) :
   oooOO0oOooO00 = lisp_hex_string ( self . address ) . zfill ( 12 )
   oooOO0oOooO00 = "{}-{}-{}" . format ( oooOO0oOooO00 [ 0 : 4 ] , oooOO0oOooO00 [ 4 : 8 ] ,
 oooOO0oOooO00 [ 8 : 12 ] )
   return ( "{}" . format ( oooOO0oOooO00 ) )
  elif ( self . is_e164 ( ) ) :
   oooOO0oOooO00 = lisp_hex_string ( self . address ) . zfill ( 15 )
   return ( "+{}" . format ( oooOO0oOooO00 ) )
  elif ( self . is_dist_name ( ) ) :
   return ( "'{}'" . format ( self . address ) )
  elif ( self . is_null ( ) ) :
   return ( "no-address" )
   if 14 - 14: oO0o / Ii1I - I1Ii111
  return ( "unknown-afi:{}" . format ( self . afi ) )
  if 79 - 79: I1Ii111
  if 54 - 54: II111iiii
 def print_prefix ( self ) :
  if ( self . is_ultimate_root ( ) ) : return ( "[*]" )
  if ( self . is_iid_range ( ) ) :
   if ( self . mask_len == 32 ) : return ( "[{}]" . format ( self . instance_id ) )
   o0oooo0O = self . instance_id + ( 2 ** ( 32 - self . mask_len ) - 1 )
   return ( "[{}-{}]" . format ( self . instance_id , o0oooo0O ) )
   if 27 - 27: Oo0Ooo
  o00Ooo0 = self . print_address ( )
  if ( self . is_dist_name ( ) ) : return ( o00Ooo0 )
  if ( self . is_geo_prefix ( ) ) : return ( o00Ooo0 )
  if 32 - 32: Oo0Ooo * i11iIiiIii % I1IiiI - i11iIiiIii - I1Ii111 % I1ii11iIi11i
  oooO0 = o00Ooo0 . find ( "no-address" )
  if ( oooO0 == - 1 ) :
   o00Ooo0 = "{}/{}" . format ( o00Ooo0 , str ( self . mask_len ) )
  else :
   o00Ooo0 = o00Ooo0 [ 0 : oooO0 ]
   if 35 - 35: o0oOOo0O0Ooo % iII111i / O0 * I1IiiI . o0oOOo0O0Ooo / OOooOOo
  return ( o00Ooo0 )
  if 81 - 81: I1ii11iIi11i - i11iIiiIii
  if 49 - 49: iII111i * I11i - II111iiii . o0oOOo0O0Ooo
 def print_prefix_no_iid ( self ) :
  o00Ooo0 = self . print_address_no_iid ( )
  if ( self . is_dist_name ( ) ) : return ( o00Ooo0 )
  if ( self . is_geo_prefix ( ) ) : return ( o00Ooo0 )
  return ( "{}/{}" . format ( o00Ooo0 , str ( self . mask_len ) ) )
  if 52 - 52: Ii1I + Ii1I - II111iiii . O0 + I1ii11iIi11i
  if 60 - 60: i11iIiiIii + IiII
 def print_prefix_url ( self ) :
  if ( self . is_ultimate_root ( ) ) : return ( "0--0" )
  o00Ooo0 = self . print_address ( )
  oooO0 = o00Ooo0 . find ( "]" )
  if ( oooO0 != - 1 ) : o00Ooo0 = o00Ooo0 [ oooO0 + 1 : : ]
  if ( self . is_geo_prefix ( ) ) :
   o00Ooo0 = o00Ooo0 . replace ( "/" , "-" )
   return ( "{}-{}" . format ( self . instance_id , o00Ooo0 ) )
   if 41 - 41: I1Ii111 * o0oOOo0O0Ooo + Oo0Ooo
  return ( "{}-{}-{}" . format ( self . instance_id , o00Ooo0 , self . mask_len ) )
  if 86 - 86: Ii1I / oO0o
  if 40 - 40: OoO0O00 % oO0o + Oo0Ooo
 def print_sg ( self , g ) :
  oooOOO00o0 = self . print_prefix ( )
  oo0o = oooOOO00o0 . find ( "]" ) + 1
  g = g . print_prefix ( )
  OoO0OoOOOo0O = g . find ( "]" ) + 1
  iIiIi1ii = "[{}]({}, {})" . format ( self . instance_id , oooOOO00o0 [ oo0o : : ] , g [ OoO0OoOOOo0O : : ] )
  return ( iIiIi1ii )
  if 24 - 24: I1Ii111 + OOooOOo
  if 76 - 76: O0 - OoooooooOO
 def hash_address ( self , addr ) :
  III1IiI1i1i = self . address
  o0OOOOOo0 = addr . address
  if 68 - 68: iII111i + I1Ii111
  if ( self . is_geo_prefix ( ) ) : III1IiI1i1i = self . address . print_geo ( )
  if ( addr . is_geo_prefix ( ) ) : o0OOOOOo0 = addr . address . print_geo ( )
  if 90 - 90: o0oOOo0O0Ooo
  if ( type ( III1IiI1i1i ) == str ) :
   III1IiI1i1i = int ( binascii . hexlify ( III1IiI1i1i [ 0 : 1 ] ) )
   if 48 - 48: iII111i + Ii1I
  if ( type ( o0OOOOOo0 ) == str ) :
   o0OOOOOo0 = int ( binascii . hexlify ( o0OOOOOo0 [ 0 : 1 ] ) )
   if 45 - 45: oO0o / iIii1I11I1II1 % O0 % IiII % I1ii11iIi11i
  return ( III1IiI1i1i ^ o0OOOOOo0 )
  if 89 - 89: OOooOOo - I1Ii111 - iII111i
  if 67 - 67: oO0o
  if 76 - 76: I1IiiI % I1IiiI - IiII / OoOoOO00 / I1ii11iIi11i
  if 42 - 42: I1IiiI + I1ii11iIi11i + Oo0Ooo * i1IIi - II111iiii
  if 15 - 15: o0oOOo0O0Ooo
  if 60 - 60: I1ii11iIi11i / I1Ii111
 def is_more_specific ( self , prefix ) :
  if ( prefix . afi == LISP_AFI_ULTIMATE_ROOT ) : return ( True )
  if 13 - 13: I1Ii111
  i1iIi = prefix . mask_len
  if ( prefix . afi == LISP_AFI_IID_RANGE ) :
   oooO0o0o0oo0O00o = 2 ** ( 32 - i1iIi )
   oO0IIIiI1i1iiIIi = prefix . instance_id
   o0oooo0O = oO0IIIiI1i1iiIIi + oooO0o0o0oo0O00o
   return ( self . instance_id in range ( oO0IIIiI1i1iiIIi , o0oooo0O ) )
   if 1 - 1: Oo0Ooo
   if 65 - 65: I1IiiI / Oo0Ooo / IiII / OOooOOo
  if ( self . instance_id != prefix . instance_id ) : return ( False )
  if ( self . afi != prefix . afi ) :
   if ( prefix . afi != LISP_AFI_NONE ) : return ( False )
   if 33 - 33: IiII - i11iIiiIii + OoooooooOO * I11i + iII111i
   if 52 - 52: o0oOOo0O0Ooo / Oo0Ooo * o0oOOo0O0Ooo - IiII
   if 72 - 72: i11iIiiIii - i11iIiiIii - Ii1I * Oo0Ooo % i11iIiiIii / i11iIiiIii
   if 1 - 1: I11i / oO0o . O0 . i1IIi - O0
   if 18 - 18: I11i + ooOoO0o . i1IIi / OoOoOO00
  if ( self . is_binary ( ) == False ) :
   if ( prefix . afi == LISP_AFI_NONE ) : return ( True )
   if ( type ( self . address ) != type ( prefix . address ) ) : return ( False )
   o00Ooo0 = self . address
   Ooo0O = prefix . address
   if ( self . is_geo_prefix ( ) ) :
    o00Ooo0 = self . address . print_geo ( )
    Ooo0O = prefix . address . print_geo ( )
    if 5 - 5: i1IIi / iII111i / Ii1I . OOooOOo
   if ( len ( o00Ooo0 ) < len ( Ooo0O ) ) : return ( False )
   return ( o00Ooo0 . find ( Ooo0O ) == 0 )
   if 37 - 37: Ii1I . IiII % I1ii11iIi11i * IiII
   if 77 - 77: OOooOOo . oO0o + iIii1I11I1II1 + Oo0Ooo . i11iIiiIii . I1ii11iIi11i
   if 71 - 71: II111iiii
   if 2 - 2: OOooOOo / iIii1I11I1II1
   if 86 - 86: oO0o % IiII
  if ( self . mask_len < i1iIi ) : return ( False )
  if 71 - 71: I11i + ooOoO0o * OoooooooOO
  iIi11i11II = ( prefix . addr_length ( ) * 8 ) - i1iIi
  oo0000oooO = ( 2 ** i1iIi - 1 ) << iIi11i11II
  return ( ( self . address & oo0000oooO ) == prefix . address )
  if 37 - 37: OoO0O00 % i11iIiiIii
  if 13 - 13: OoooooooOO - II111iiii / OoOoOO00 + OoooooooOO * oO0o
 def mask_address ( self , mask_len ) :
  iIi11i11II = ( self . addr_length ( ) * 8 ) - mask_len
  oo0000oooO = ( 2 ** mask_len - 1 ) << iIi11i11II
  self . address &= oo0000oooO
  if 32 - 32: I1Ii111 + OoooooooOO - OoOoOO00 . IiII
  if 33 - 33: OoOoOO00 - I1IiiI + iII111i . iII111i
 def is_exact_match ( self , prefix ) :
  if ( self . instance_id != prefix . instance_id ) : return ( False )
  OOOOO = self . print_prefix ( )
  i1ii = prefix . print_prefix ( ) if prefix else ""
  return ( OOOOO == i1ii )
  if 8 - 8: OOooOOo % o0oOOo0O0Ooo
  if 36 - 36: Ii1I % OoooooooOO
 def is_local ( self ) :
  if ( self . is_ipv4 ( ) ) :
   I1i1II1iI = lisp_myrlocs [ 0 ]
   if ( I1i1II1iI == None ) : return ( False )
   I1i1II1iI = I1i1II1iI . print_address_no_iid ( )
   return ( self . print_address_no_iid ( ) == I1i1II1iI )
   if 53 - 53: Oo0Ooo % Oo0Ooo
  if ( self . is_ipv6 ( ) ) :
   I1i1II1iI = lisp_myrlocs [ 1 ]
   if ( I1i1II1iI == None ) : return ( False )
   I1i1II1iI = I1i1II1iI . print_address_no_iid ( )
   return ( self . print_address_no_iid ( ) == I1i1II1iI )
   if 29 - 29: IiII
  return ( False )
  if 94 - 94: I1IiiI * Oo0Ooo * OOooOOo + Oo0Ooo / I1Ii111
  if 3 - 3: I11i * iII111i - OoooooooOO % OoOoOO00 % ooOoO0o
 def store_iid_range ( self , iid , mask_len ) :
  if ( self . afi == LISP_AFI_NONE ) :
   if ( iid is 0 and mask_len is 0 ) : self . afi = LISP_AFI_ULTIMATE_ROOT
   else : self . afi = LISP_AFI_IID_RANGE
   if 48 - 48: i11iIiiIii * i11iIiiIii
  self . instance_id = iid
  self . mask_len = mask_len
  if 92 - 92: i1IIi
  if 3 - 3: iIii1I11I1II1 . I1ii11iIi11i
 def lcaf_length ( self , lcaf_type ) :
  Oooo = self . addr_length ( ) + 2
  if ( lcaf_type == LISP_LCAF_AFI_LIST_TYPE ) : Oooo += 4
  if ( lcaf_type == LISP_LCAF_INSTANCE_ID_TYPE ) : Oooo += 4
  if ( lcaf_type == LISP_LCAF_ASN_TYPE ) : Oooo += 4
  if ( lcaf_type == LISP_LCAF_APP_DATA_TYPE ) : Oooo += 8
  if ( lcaf_type == LISP_LCAF_GEO_COORD_TYPE ) : Oooo += 12
  if ( lcaf_type == LISP_LCAF_OPAQUE_TYPE ) : Oooo += 0
  if ( lcaf_type == LISP_LCAF_NAT_TYPE ) : Oooo += 4
  if ( lcaf_type == LISP_LCAF_NONCE_LOC_TYPE ) : Oooo += 4
  if ( lcaf_type == LISP_LCAF_MCAST_INFO_TYPE ) : Oooo = Oooo * 2 + 8
  if ( lcaf_type == LISP_LCAF_ELP_TYPE ) : Oooo += 0
  if ( lcaf_type == LISP_LCAF_SECURITY_TYPE ) : Oooo += 6
  if ( lcaf_type == LISP_LCAF_SOURCE_DEST_TYPE ) : Oooo += 4
  if ( lcaf_type == LISP_LCAF_RLE_TYPE ) : Oooo += 4
  return ( Oooo )
  if 97 - 97: O0
  if 82 - 82: OoooooooOO / I1Ii111 - ooOoO0o . I1Ii111
  if 41 - 41: I11i . I11i
  if 12 - 12: OoOoOO00 / I1IiiI
  if 4 - 4: Oo0Ooo * o0oOOo0O0Ooo
  if 45 - 45: Ii1I % OOooOOo * Ii1I - iIii1I11I1II1
  if 18 - 18: I1Ii111 / Oo0Ooo % Ii1I + OoO0O00
  if 69 - 69: iII111i % I1ii11iIi11i
  if 19 - 19: IiII
  if 35 - 35: OoOoOO00
  if 18 - 18: II111iiii . OoOoOO00 + I1ii11iIi11i * oO0o + OoooooooOO
  if 39 - 39: I1IiiI * ooOoO0o / i11iIiiIii - oO0o - oO0o + O0
  if 73 - 73: OOooOOo
  if 44 - 44: I1ii11iIi11i * i1IIi - iIii1I11I1II1 - oO0o - oO0o * II111iiii
  if 98 - 98: Oo0Ooo + ooOoO0o / OOooOOo . iIii1I11I1II1 . I1IiiI . OoOoOO00
  if 92 - 92: i1IIi + OoOoOO00 * i1IIi / IiII
  if 4 - 4: oO0o % OoO0O00 + IiII + o0oOOo0O0Ooo
 def lcaf_encode_iid ( self ) :
  ii111I1IiiI1i = LISP_LCAF_INSTANCE_ID_TYPE
  oooO00oo0 = socket . htons ( self . lcaf_length ( ii111I1IiiI1i ) )
  iiI1iii = self . instance_id
  ooo0O0O0oo0 = self . afi
  oOOoOO = 0
  if ( ooo0O0O0oo0 < 0 ) :
   if ( self . afi == LISP_AFI_GEO_COORD ) :
    ooo0O0O0oo0 = LISP_AFI_LCAF
    oOOoOO = 0
   else :
    ooo0O0O0oo0 = 0
    oOOoOO = self . mask_len
    if 82 - 82: O0 / I1Ii111 + OOooOOo . IiII + Ii1I
    if 31 - 31: i1IIi * OoO0O00 - Ii1I + I11i
    if 8 - 8: O0 + i1IIi . O0
  oOOO0 = struct . pack ( "BBBBH" , 0 , 0 , ii111I1IiiI1i , oOOoOO , oooO00oo0 )
  oOOO0 += struct . pack ( "IH" , socket . htonl ( iiI1iii ) , socket . htons ( ooo0O0O0oo0 ) )
  if ( ooo0O0O0oo0 == 0 ) : return ( oOOO0 )
  if 77 - 77: oO0o - IiII * II111iiii / OoooooooOO
  if ( self . afi == LISP_AFI_GEO_COORD ) :
   oOOO0 = oOOO0 [ 0 : - 2 ]
   oOOO0 += self . address . encode_geo ( )
   return ( oOOO0 )
   if 10 - 10: OoooooooOO % I1IiiI . I1Ii111 * OoO0O00
   if 43 - 43: Ii1I % iIii1I11I1II1 * II111iiii . OOooOOo
  oOOO0 += self . pack_address ( )
  return ( oOOO0 )
  if 88 - 88: oO0o % iIii1I11I1II1 . I11i * Oo0Ooo / O0
  if 35 - 35: OOooOOo % II111iiii + oO0o . OoO0O00
 def lcaf_decode_iid ( self , packet ) :
  I1I = "BBBBH"
  ii1I1iIi = struct . calcsize ( I1I )
  if ( len ( packet ) < ii1I1iIi ) : return ( None )
  if 22 - 22: OoooooooOO . I1IiiI % iIii1I11I1II1
  oO0IiiI1i1i11I1 , IiiiIi , ii111I1IiiI1i , O0oOO0oooO , Oooo = struct . unpack ( I1I ,
 packet [ : ii1I1iIi ] )
  packet = packet [ ii1I1iIi : : ]
  if 9 - 9: iIii1I11I1II1 - OOooOOo
  if ( ii111I1IiiI1i != LISP_LCAF_INSTANCE_ID_TYPE ) : return ( None )
  if 93 - 93: iII111i % OOooOOo + OoooooooOO % I1Ii111 % OoO0O00
  I1I = "IH"
  ii1I1iIi = struct . calcsize ( I1I )
  if ( len ( packet ) < ii1I1iIi ) : return ( None )
  if 86 - 86: O0
  iiI1iii , ooo0O0O0oo0 = struct . unpack ( I1I , packet [ : ii1I1iIi ] )
  packet = packet [ ii1I1iIi : : ]
  if 65 - 65: OoooooooOO
  Oooo = socket . ntohs ( Oooo )
  self . instance_id = socket . ntohl ( iiI1iii )
  ooo0O0O0oo0 = socket . ntohs ( ooo0O0O0oo0 )
  self . afi = ooo0O0O0oo0
  if ( O0oOO0oooO != 0 and ooo0O0O0oo0 == 0 ) : self . mask_len = O0oOO0oooO
  if ( ooo0O0O0oo0 == 0 ) :
   self . afi = LISP_AFI_IID_RANGE if O0oOO0oooO else LISP_AFI_ULTIMATE_ROOT
   if 79 - 79: I1Ii111 + Ii1I * oO0o - OoooooooOO + oO0o
   if 85 - 85: OoO0O00 . IiII / iII111i . I1IiiI
   if 8 - 8: i1IIi - iIii1I11I1II1 + iII111i
   if 90 - 90: i11iIiiIii - Oo0Ooo
   if 31 - 31: OoOoOO00 + OoOoOO00 + OoooooooOO % O0
  if ( ooo0O0O0oo0 == 0 ) : return ( packet )
  if 14 - 14: i1IIi / OoooooooOO . I1IiiI * I1Ii111 + OoO0O00
  if 45 - 45: OoooooooOO * I1Ii111
  if 7 - 7: O0
  if 42 - 42: o0oOOo0O0Ooo / Ii1I
  if ( self . is_dist_name ( ) ) :
   packet , self . address = lisp_decode_dist_name ( packet )
   self . mask_len = len ( self . address ) * 8
   return ( packet )
   if 31 - 31: OOooOOo
   if 20 - 20: i11iIiiIii * oO0o * ooOoO0o
   if 65 - 65: I1ii11iIi11i / Oo0Ooo / I1IiiI + IiII
   if 71 - 71: OoO0O00 . I1Ii111 + OoooooooOO
   if 9 - 9: OoooooooOO / iIii1I11I1II1 % I1IiiI . I1IiiI / I11i - iII111i
  if ( ooo0O0O0oo0 == LISP_AFI_LCAF ) :
   I1I = "BBBBH"
   ii1I1iIi = struct . calcsize ( I1I )
   if ( len ( packet ) < ii1I1iIi ) : return ( None )
   if 60 - 60: I11i - OoO0O00 - OoOoOO00 * ooOoO0o - i1IIi
   oO0ooOoOooO00o00 , o0Ooo00Oo0oo0 , ii111I1IiiI1i , I11 , I1iIiI1iiI = struct . unpack ( I1I , packet [ : ii1I1iIi ] )
   if 18 - 18: ooOoO0o + i11iIiiIii + O0 + OOooOOo / Ii1I
   if 65 - 65: I1IiiI . ooOoO0o
   if ( ii111I1IiiI1i != LISP_LCAF_GEO_COORD_TYPE ) : return ( None )
   if 51 - 51: I1Ii111
   I1iIiI1iiI = socket . ntohs ( I1iIiI1iiI )
   packet = packet [ ii1I1iIi : : ]
   if ( I1iIiI1iiI > len ( packet ) ) : return ( None )
   if 89 - 89: Oo0Ooo
   ii11iIIiiI1I = lisp_geo ( "" )
   self . afi = LISP_AFI_GEO_COORD
   self . address = ii11iIIiiI1I
   packet = ii11iIIiiI1I . decode_geo ( packet , I1iIiI1iiI , I11 )
   self . mask_len = self . host_mask_len ( )
   return ( packet )
   if 15 - 15: OOooOOo * II111iiii - OOooOOo * iIii1I11I1II1
   if 95 - 95: I1Ii111 / OoooooooOO * I11i * OoooooooOO
  oooO00oo0 = self . addr_length ( )
  if ( len ( packet ) < oooO00oo0 ) : return ( None )
  if 88 - 88: I1IiiI / Oo0Ooo / oO0o + oO0o % OOooOOo + Oo0Ooo
  packet = self . unpack_address ( packet )
  return ( packet )
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
  if 77 - 77: I11i + i1IIi * OoOoOO00 % OoooooooOO
  if 56 - 56: I1Ii111 * i1IIi % i11iIiiIii
  if 56 - 56: Ii1I . iII111i
  if 76 - 76: I1IiiI / Ii1I % OoOoOO00 + IiII / i11iIiiIii . o0oOOo0O0Ooo
  if 31 - 31: oO0o * oO0o % o0oOOo0O0Ooo . O0 + iII111i
  if 52 - 52: i11iIiiIii
  if 1 - 1: i1IIi * iIii1I11I1II1
  if 29 - 29: I11i
 def lcaf_encode_sg ( self , group ) :
  ii111I1IiiI1i = LISP_LCAF_MCAST_INFO_TYPE
  iiI1iii = socket . htonl ( self . instance_id )
  oooO00oo0 = socket . htons ( self . lcaf_length ( ii111I1IiiI1i ) )
  oOOO0 = struct . pack ( "BBBBHIHBB" , 0 , 0 , ii111I1IiiI1i , 0 , oooO00oo0 , iiI1iii ,
 0 , self . mask_len , group . mask_len )
  if 12 - 12: oO0o % i1IIi - oO0o / ooOoO0o * II111iiii % ooOoO0o
  oOOO0 += struct . pack ( "H" , socket . htons ( self . afi ) )
  oOOO0 += self . pack_address ( )
  oOOO0 += struct . pack ( "H" , socket . htons ( group . afi ) )
  oOOO0 += group . pack_address ( )
  return ( oOOO0 )
  if 6 - 6: IiII / OoO0O00
  if 83 - 83: IiII - iIii1I11I1II1 * ooOoO0o - oO0o
 def lcaf_decode_sg ( self , packet ) :
  I1I = "BBBBHIHBB"
  ii1I1iIi = struct . calcsize ( I1I )
  if ( len ( packet ) < ii1I1iIi ) : return ( [ None , None ] )
  if 77 - 77: Ii1I
  oO0IiiI1i1i11I1 , IiiiIi , ii111I1IiiI1i , iIiIii , Oooo , iiI1iii , i1Ii , Oo00OOoO , ii1iiI1i1Ii1 = struct . unpack ( I1I , packet [ : ii1I1iIi ] )
  if 13 - 13: i1IIi % iII111i + OoOoOO00 / Ii1I . Ii1I + II111iiii
  packet = packet [ ii1I1iIi : : ]
  if 44 - 44: OoOoOO00 / OoooooooOO % O0 * Ii1I * IiII
  if ( ii111I1IiiI1i != LISP_LCAF_MCAST_INFO_TYPE ) : return ( [ None , None ] )
  if 84 - 84: o0oOOo0O0Ooo * IiII * OOooOOo * iII111i
  self . instance_id = socket . ntohl ( iiI1iii )
  Oooo = socket . ntohs ( Oooo ) - 8
  if 56 - 56: iII111i * II111iiii . OoooooooOO . I11i
  if 25 - 25: ooOoO0o % o0oOOo0O0Ooo - i11iIiiIii
  if 79 - 79: iII111i - I1IiiI % O0 / Oo0Ooo + OoOoOO00 . Oo0Ooo
  if 59 - 59: I1ii11iIi11i * OoOoOO00 / Ii1I
  if 80 - 80: IiII - ooOoO0o / OoOoOO00 / I11i * O0 + oO0o
  I1I = "H"
  ii1I1iIi = struct . calcsize ( I1I )
  if ( len ( packet ) < ii1I1iIi ) : return ( [ None , None ] )
  if ( Oooo < ii1I1iIi ) : return ( [ None , None ] )
  if 77 - 77: ooOoO0o + I1ii11iIi11i * o0oOOo0O0Ooo / i1IIi * I11i
  ooo0O0O0oo0 = struct . unpack ( I1I , packet [ : ii1I1iIi ] ) [ 0 ]
  packet = packet [ ii1I1iIi : : ]
  Oooo -= ii1I1iIi
  self . afi = socket . ntohs ( ooo0O0O0oo0 )
  self . mask_len = Oo00OOoO
  oooO00oo0 = self . addr_length ( )
  if ( Oooo < oooO00oo0 ) : return ( [ None , None ] )
  if 70 - 70: oO0o / iII111i * i1IIi / II111iiii / OoOoOO00 + oO0o
  packet = self . unpack_address ( packet )
  if ( packet == None ) : return ( [ None , None ] )
  if 30 - 30: i1IIi - iII111i - i11iIiiIii . OoOoOO00 . o0oOOo0O0Ooo
  Oooo -= oooO00oo0
  if 74 - 74: i11iIiiIii / II111iiii
  if 62 - 62: O0
  if 63 - 63: Oo0Ooo + Oo0Ooo
  if 48 - 48: Oo0Ooo * I1ii11iIi11i % II111iiii
  if 42 - 42: I1Ii111 - ooOoO0o % o0oOOo0O0Ooo * I1IiiI . o0oOOo0O0Ooo
  I1I = "H"
  ii1I1iIi = struct . calcsize ( I1I )
  if ( len ( packet ) < ii1I1iIi ) : return ( [ None , None ] )
  if ( Oooo < ii1I1iIi ) : return ( [ None , None ] )
  if 84 - 84: iIii1I11I1II1
  ooo0O0O0oo0 = struct . unpack ( I1I , packet [ : ii1I1iIi ] ) [ 0 ]
  packet = packet [ ii1I1iIi : : ]
  Oooo -= ii1I1iIi
  iiI = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  iiI . afi = socket . ntohs ( ooo0O0O0oo0 )
  iiI . mask_len = ii1iiI1i1Ii1
  iiI . instance_id = self . instance_id
  oooO00oo0 = self . addr_length ( )
  if ( Oooo < oooO00oo0 ) : return ( [ None , None ] )
  if 39 - 39: Ii1I . II111iiii / I1IiiI
  packet = iiI . unpack_address ( packet )
  if ( packet == None ) : return ( [ None , None ] )
  if 44 - 44: Ii1I / Ii1I / OoO0O00 % ooOoO0o / I11i . I1ii11iIi11i
  return ( [ packet , iiI ] )
  if 41 - 41: I1ii11iIi11i * ooOoO0o * I11i + O0 * O0 - O0
  if 81 - 81: I1Ii111 % OoO0O00 / O0
 def lcaf_decode_eid ( self , packet ) :
  I1I = "BBB"
  ii1I1iIi = struct . calcsize ( I1I )
  if ( len ( packet ) < ii1I1iIi ) : return ( [ None , None ] )
  if 55 - 55: i1IIi - I1Ii111 + I11i
  if 93 - 93: I1IiiI % IiII . OoOoOO00 + iII111i
  if 81 - 81: ooOoO0o / I1Ii111 + OOooOOo / Oo0Ooo / OoOoOO00
  if 34 - 34: ooOoO0o * iIii1I11I1II1 % i11iIiiIii * OOooOOo - OOooOOo
  if 63 - 63: Oo0Ooo / oO0o + iII111i % OoooooooOO * I11i
  iIiIii , o0Ooo00Oo0oo0 , ii111I1IiiI1i = struct . unpack ( I1I ,
 packet [ : ii1I1iIi ] )
  if 34 - 34: I1IiiI + I1Ii111 % ooOoO0o
  if ( ii111I1IiiI1i == LISP_LCAF_INSTANCE_ID_TYPE ) :
   return ( [ self . lcaf_decode_iid ( packet ) , None ] )
  elif ( ii111I1IiiI1i == LISP_LCAF_MCAST_INFO_TYPE ) :
   packet , iiI = self . lcaf_decode_sg ( packet )
   return ( [ packet , iiI ] )
  elif ( ii111I1IiiI1i == LISP_LCAF_GEO_COORD_TYPE ) :
   I1I = "BBBBH"
   ii1I1iIi = struct . calcsize ( I1I )
   if ( len ( packet ) < ii1I1iIi ) : return ( None )
   if 24 - 24: Ii1I % II111iiii - i11iIiiIii
   oO0ooOoOooO00o00 , o0Ooo00Oo0oo0 , ii111I1IiiI1i , I11 , I1iIiI1iiI = struct . unpack ( I1I , packet [ : ii1I1iIi ] )
   if 52 - 52: OoO0O00
   if 76 - 76: ooOoO0o - iII111i % ooOoO0o / oO0o . OOooOOo
   if ( ii111I1IiiI1i != LISP_LCAF_GEO_COORD_TYPE ) : return ( None )
   if 50 - 50: IiII . i11iIiiIii % I11i
   I1iIiI1iiI = socket . ntohs ( I1iIiI1iiI )
   packet = packet [ ii1I1iIi : : ]
   if ( I1iIiI1iiI > len ( packet ) ) : return ( None )
   if 22 - 22: i1IIi - II111iiii - OoOoOO00 . iII111i
   ii11iIIiiI1I = lisp_geo ( "" )
   self . instance_id = 0
   self . afi = LISP_AFI_GEO_COORD
   self . address = ii11iIIiiI1I
   packet = ii11iIIiiI1I . decode_geo ( packet , I1iIiI1iiI , I11 )
   self . mask_len = self . host_mask_len ( )
   if 43 - 43: I1Ii111 * OOooOOo - IiII . i11iIiiIii
  return ( [ packet , None ] )
  if 34 - 34: iII111i . OoOoOO00
  if 49 - 49: I1ii11iIi11i % oO0o - I1Ii111 . I1ii11iIi11i % II111iiii
  if 20 - 20: I1ii11iIi11i . iIii1I11I1II1 - Ii1I % OoO0O00
  if 27 - 27: iIii1I11I1II1 / I1Ii111 - I11i . OoO0O00 + ooOoO0o
  if 89 - 89: I1IiiI % I11i - OOooOOo
  if 71 - 71: OOooOOo % Oo0Ooo - o0oOOo0O0Ooo / I1Ii111 - O0 - oO0o
class lisp_elp_node ( ) :
 def __init__ ( self ) :
  self . address = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . probe = False
  self . strict = False
  self . eid = False
  self . we_are_last = False
  if 10 - 10: I1IiiI
  if 17 - 17: i11iIiiIii % o0oOOo0O0Ooo . ooOoO0o
 def copy_elp_node ( self ) :
  OO = lisp_elp_node ( )
  OO . copy_address ( self . address )
  OO . probe = self . probe
  OO . strict = self . strict
  OO . eid = self . eid
  OO . we_are_last = self . we_are_last
  return ( OO )
  if 34 - 34: OoooooooOO / iII111i / O0
  if 75 - 75: I11i % OOooOOo - OoO0O00 * I11i * IiII
  if 11 - 11: I1ii11iIi11i . O0 - iII111i * IiII . i1IIi . iII111i
class lisp_elp ( ) :
 def __init__ ( self , name ) :
  self . elp_name = name
  self . elp_nodes = [ ]
  self . use_elp_node = None
  self . we_are_last = False
  if 82 - 82: i1IIi * I11i * Ii1I - IiII . i11iIiiIii
  if 40 - 40: OOooOOo - OoooooooOO
 def copy_elp ( self ) :
  iIiiiIiIIi = lisp_elp ( self . elp_name )
  iIiiiIiIIi . use_elp_node = self . use_elp_node
  iIiiiIiIIi . we_are_last = self . we_are_last
  for OO in self . elp_nodes :
   iIiiiIiIIi . elp_nodes . append ( OO . copy_elp_node ( ) )
   if 36 - 36: i1IIi % OoOoOO00 - i1IIi
  return ( iIiiiIiIIi )
  if 5 - 5: I1IiiI . I1IiiI % II111iiii - I1Ii111
  if 97 - 97: I11i . ooOoO0o
 def print_elp ( self , want_marker ) :
  Ii1111IIIiiIi = ""
  for OO in self . elp_nodes :
   OOOoO = ""
   if ( want_marker ) :
    if ( OO == self . use_elp_node ) :
     OOOoO = "*"
    elif ( OO . we_are_last ) :
     OOOoO = "x"
     if 72 - 72: OoOoOO00 % I1Ii111
     if 58 - 58: IiII
   Ii1111IIIiiIi += "{}{}({}{}{}), " . format ( OOOoO ,
 OO . address . print_address_no_iid ( ) ,
 "r" if OO . eid else "R" , "P" if OO . probe else "p" ,
 "S" if OO . strict else "s" )
   if 58 - 58: OOooOOo * o0oOOo0O0Ooo * I1Ii111 % II111iiii
  return ( Ii1111IIIiiIi [ 0 : - 2 ] if Ii1111IIIiiIi != "" else "" )
  if 45 - 45: i11iIiiIii
  if 58 - 58: Ii1I
 def select_elp_node ( self ) :
  I1i1ii , OOI1Ii11iiI111 , oOOOo0o = lisp_myrlocs
  oooO0 = None
  if 5 - 5: IiII % OoO0O00 + I1Ii111 % OoooooooOO / o0oOOo0O0Ooo + OoooooooOO
  for OO in self . elp_nodes :
   if ( I1i1ii and OO . address . is_exact_match ( I1i1ii ) ) :
    oooO0 = self . elp_nodes . index ( OO )
    break
    if 93 - 93: I1IiiI % OoOoOO00
   if ( OOI1Ii11iiI111 and OO . address . is_exact_match ( OOI1Ii11iiI111 ) ) :
    oooO0 = self . elp_nodes . index ( OO )
    break
    if 12 - 12: Oo0Ooo + I11i
    if 97 - 97: OOooOOo / IiII / ooOoO0o / OoooooooOO
    if 78 - 78: I1Ii111 + I1Ii111
    if 43 - 43: I1Ii111 * o0oOOo0O0Ooo + i1IIi
    if 19 - 19: Ii1I
    if 51 - 51: oO0o
    if 57 - 57: i11iIiiIii - Oo0Ooo + I1Ii111 * OoO0O00
  if ( oooO0 == None ) :
   self . use_elp_node = self . elp_nodes [ 0 ]
   OO . we_are_last = False
   return
   if 35 - 35: o0oOOo0O0Ooo % II111iiii + O0
   if 70 - 70: I1ii11iIi11i . II111iiii
   if 54 - 54: OOooOOo
   if 67 - 67: I1IiiI . o0oOOo0O0Ooo / i1IIi * I1ii11iIi11i . Oo0Ooo + II111iiii
   if 63 - 63: OoOoOO00 - OoOoOO00
   if 31 - 31: I1ii11iIi11i % O0 - i11iIiiIii * o0oOOo0O0Ooo . ooOoO0o * ooOoO0o
  if ( self . elp_nodes [ - 1 ] == self . elp_nodes [ oooO0 ] ) :
   self . use_elp_node = None
   OO . we_are_last = True
   return
   if 18 - 18: OoO0O00 - OoO0O00 . o0oOOo0O0Ooo
   if 80 - 80: I11i + I1Ii111 / I1IiiI * OOooOOo % iII111i
   if 48 - 48: iIii1I11I1II1 + i1IIi . I1IiiI % OoO0O00 - iIii1I11I1II1 / i1IIi
   if 14 - 14: IiII . I11i
   if 13 - 13: OoOoOO00 - I11i . OOooOOo % OoO0O00
  self . use_elp_node = self . elp_nodes [ oooO0 + 1 ]
  return
  if 79 - 79: iII111i / Ii1I % i11iIiiIii . I1IiiI % OoO0O00 / i11iIiiIii
  if 100 - 100: OOooOOo + Oo0Ooo . iIii1I11I1II1 . ooOoO0o * Oo0Ooo
  if 16 - 16: Oo0Ooo % OoOoOO00 + I1Ii111 % I1Ii111
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
  if 12 - 12: I1Ii111 . Ii1I / iIii1I11I1II1 + i1IIi
  if 9 - 9: iIii1I11I1II1
 def copy_geo ( self ) :
  ii11iIIiiI1I = lisp_geo ( self . geo_name )
  ii11iIIiiI1I . latitude = self . latitude
  ii11iIIiiI1I . lat_mins = self . lat_mins
  ii11iIIiiI1I . lat_secs = self . lat_secs
  ii11iIIiiI1I . longitude = self . longitude
  ii11iIIiiI1I . long_mins = self . long_mins
  ii11iIIiiI1I . long_secs = self . long_secs
  ii11iIIiiI1I . altitude = self . altitude
  ii11iIIiiI1I . radius = self . radius
  return ( ii11iIIiiI1I )
  if 75 - 75: I11i . II111iiii * I1IiiI * IiII
  if 36 - 36: OOooOOo / I1ii11iIi11i / oO0o / ooOoO0o / I11i
 def no_geo_altitude ( self ) :
  return ( self . altitude == - 1 )
  if 7 - 7: OoO0O00 - I11i - o0oOOo0O0Ooo / o0oOOo0O0Ooo + i11iIiiIii
  if 28 - 28: OoOoOO00 % ooOoO0o . I1IiiI + II111iiii
 def parse_geo_string ( self , geo_str ) :
  oooO0 = geo_str . find ( "]" )
  if ( oooO0 != - 1 ) : geo_str = geo_str [ oooO0 + 1 : : ]
  if 34 - 34: iIii1I11I1II1
  if 65 - 65: II111iiii - iII111i / o0oOOo0O0Ooo
  if 35 - 35: i11iIiiIii - Oo0Ooo . I1ii11iIi11i % OoOoOO00
  if 20 - 20: OoO0O00
  if 93 - 93: ooOoO0o + o0oOOo0O0Ooo - I1ii11iIi11i
  if ( geo_str . find ( "/" ) != - 1 ) :
   geo_str , o0O0oIi1Ii = geo_str . split ( "/" )
   self . radius = int ( o0O0oIi1Ii )
   if 31 - 31: i11iIiiIii - o0oOOo0O0Ooo
   if 69 - 69: i11iIiiIii
  geo_str = geo_str . split ( "-" )
  if ( len ( geo_str ) < 8 ) : return ( False )
  if 96 - 96: OOooOOo
  OoOoo000 = geo_str [ 0 : 4 ]
  i1ooooo0O = geo_str [ 4 : 8 ]
  if 48 - 48: o0oOOo0O0Ooo * II111iiii
  if 17 - 17: o0oOOo0O0Ooo / ooOoO0o + i1IIi
  if 78 - 78: iIii1I11I1II1 * o0oOOo0O0Ooo * Oo0Ooo - OoO0O00 / OoO0O00
  if 89 - 89: o0oOOo0O0Ooo % o0oOOo0O0Ooo
  if ( len ( geo_str ) > 8 ) : self . altitude = int ( geo_str [ 8 ] )
  if 8 - 8: Ii1I % oO0o - o0oOOo0O0Ooo
  if 14 - 14: OOooOOo * IiII
  if 15 - 15: o0oOOo0O0Ooo + OoooooooOO - OOooOOo - o0oOOo0O0Ooo . iIii1I11I1II1 / Ii1I
  if 33 - 33: OoO0O00
  self . latitude = int ( OoOoo000 [ 0 ] )
  self . lat_mins = int ( OoOoo000 [ 1 ] )
  self . lat_secs = int ( OoOoo000 [ 2 ] )
  if ( OoOoo000 [ 3 ] == "N" ) : self . latitude = - self . latitude
  if 91 - 91: I11i % I11i % iII111i
  if 19 - 19: I11i / I11i + I1IiiI * OoO0O00 - iII111i . Oo0Ooo
  if 76 - 76: iII111i % OOooOOo / OoooooooOO . I1IiiI % OoO0O00 % i1IIi
  if 95 - 95: Oo0Ooo - O0 / I1ii11iIi11i . I1IiiI / o0oOOo0O0Ooo % OoOoOO00
  self . longitude = int ( i1ooooo0O [ 0 ] )
  self . long_mins = int ( i1ooooo0O [ 1 ] )
  self . long_secs = int ( i1ooooo0O [ 2 ] )
  if ( i1ooooo0O [ 3 ] == "E" ) : self . longitude = - self . longitude
  return ( True )
  if 38 - 38: OoOoOO00 % OoooooooOO . oO0o - OoooooooOO + I11i
  if 18 - 18: OoooooooOO + ooOoO0o * OoOoOO00 - OoO0O00
 def print_geo ( self ) :
  IIIIIIi1i1I = "N" if self . latitude < 0 else "S"
  oo00oOooo = "E" if self . longitude < 0 else "W"
  if 8 - 8: iIii1I11I1II1
  iII1IiiIIi = "{}-{}-{}-{}-{}-{}-{}-{}" . format ( abs ( self . latitude ) ,
 self . lat_mins , self . lat_secs , IIIIIIi1i1I , abs ( self . longitude ) ,
 self . long_mins , self . long_secs , oo00oOooo )
  if 94 - 94: i11iIiiIii . o0oOOo0O0Ooo . iIii1I11I1II1 . O0
  if ( self . no_geo_altitude ( ) == False ) :
   iII1IiiIIi += "-" + str ( self . altitude )
   if 24 - 24: I1ii11iIi11i . Oo0Ooo - i11iIiiIii * i11iIiiIii - OoO0O00
   if 8 - 8: i11iIiiIii * OoOoOO00 . o0oOOo0O0Ooo
   if 27 - 27: I1ii11iIi11i + Ii1I % I1Ii111
   if 20 - 20: Oo0Ooo
   if 33 - 33: oO0o - OoOoOO00 - i11iIiiIii + I1Ii111 + iIii1I11I1II1
  if ( self . radius != 0 ) : iII1IiiIIi += "/{}" . format ( self . radius )
  return ( iII1IiiIIi )
  if 2 - 2: OoooooooOO + IiII / iII111i . iIii1I11I1II1 * OoOoOO00
  if 84 - 84: OOooOOo
 def geo_url ( self ) :
  o0O0Oo00OoOO = os . getenv ( "LISP_GEO_ZOOM_LEVEL" )
  o0O0Oo00OoOO = "10" if ( o0O0Oo00OoOO == "" or o0O0Oo00OoOO . isdigit ( ) == False ) else o0O0Oo00OoOO
  I1I1iiIii , oo0OoOOo0o = self . dms_to_decimal ( )
  oo0Oo00Oo00 = ( "http://maps.googleapis.com/maps/api/staticmap?center={},{}" + "&markers=color:blue%7Clabel:lisp%7C{},{}" + "&zoom={}&size=1024x1024&sensor=false" ) . format ( I1I1iiIii , oo0OoOOo0o , I1I1iiIii , oo0OoOOo0o ,
  # I1IiiI . iIii1I11I1II1
  # o0oOOo0O0Ooo + iII111i + O0
 o0O0Oo00OoOO )
  return ( oo0Oo00Oo00 )
  if 70 - 70: i11iIiiIii
  if 36 - 36: ooOoO0o
 def print_geo_url ( self ) :
  ii11iIIiiI1I = self . print_geo ( )
  if ( self . radius == 0 ) :
   oo0Oo00Oo00 = self . geo_url ( )
   O00OO0O = "<a href='{}'>{}</a>" . format ( oo0Oo00Oo00 , ii11iIIiiI1I )
  else :
   oo0Oo00Oo00 = ii11iIIiiI1I . replace ( "/" , "-" )
   O00OO0O = "<a href='/lisp/geo-map/{}'>{}</a>" . format ( oo0Oo00Oo00 , ii11iIIiiI1I )
   if 53 - 53: II111iiii - i1IIi - i1IIi
  return ( O00OO0O )
  if 96 - 96: I1ii11iIi11i - iIii1I11I1II1 / oO0o * I1Ii111 + ooOoO0o / ooOoO0o
  if 35 - 35: oO0o - Oo0Ooo - Ii1I
 def dms_to_decimal ( self ) :
  ii1i1iii1i , Ii1IiI11i , Ii11 = self . latitude , self . lat_mins , self . lat_secs
  o0O0Oo = float ( abs ( ii1i1iii1i ) )
  o0O0Oo += float ( Ii1IiI11i * 60 + Ii11 ) / 3600
  if ( ii1i1iii1i > 0 ) : o0O0Oo = - o0O0Oo
  iI11Ii = o0O0Oo
  if 58 - 58: i11iIiiIii
  ii1i1iii1i , Ii1IiI11i , Ii11 = self . longitude , self . long_mins , self . long_secs
  o0O0Oo = float ( abs ( ii1i1iii1i ) )
  o0O0Oo += float ( Ii1IiI11i * 60 + Ii11 ) / 3600
  if ( ii1i1iii1i > 0 ) : o0O0Oo = - o0O0Oo
  iIi11I11I = o0O0Oo
  return ( ( iI11Ii , iIi11I11I ) )
  if 3 - 3: OoO0O00
  if 83 - 83: ooOoO0o
 def get_distance ( self , geo_point ) :
  I11I11iIiIiIi11 = self . dms_to_decimal ( )
  I1iIIIII = geo_point . dms_to_decimal ( )
  oOoooOiiI1I1III1 = vincenty ( I11I11iIiIiIi11 , I1iIIIII )
  return ( oOoooOiiI1I1III1 . km )
  if 6 - 6: o0oOOo0O0Ooo % OOooOOo
  if 71 - 71: oO0o + II111iiii * O0 / i11iIiiIii * o0oOOo0O0Ooo
 def point_in_circle ( self , geo_point ) :
  oO0000O0 = self . get_distance ( geo_point )
  return ( oO0000O0 <= self . radius )
  if 94 - 94: OoO0O00 % II111iiii % iII111i + OoooooooOO - o0oOOo0O0Ooo * I1Ii111
  if 9 - 9: ooOoO0o . O0 + II111iiii . OoooooooOO
 def encode_geo ( self ) :
  iio00OOO0o0Oo0 = socket . htons ( LISP_AFI_LCAF )
  IIi1I1 = socket . htons ( 20 + 2 )
  o0Ooo00Oo0oo0 = 0
  if 97 - 97: O0 / OoOoOO00 / ooOoO0o
  I1I1iiIii = abs ( self . latitude )
  Iio0 = ( ( self . lat_mins * 60 ) + self . lat_secs ) * 1000
  if ( self . latitude < 0 ) : o0Ooo00Oo0oo0 |= 0x40
  if 88 - 88: i1IIi
  oo0OoOOo0o = abs ( self . longitude )
  Oo0O = ( ( self . long_mins * 60 ) + self . long_secs ) * 1000
  if ( self . longitude < 0 ) : o0Ooo00Oo0oo0 |= 0x20
  if 26 - 26: O0
  oOoOO00OOOo = 0
  if ( self . no_geo_altitude ( ) == False ) :
   oOoOO00OOOo = socket . htonl ( self . altitude )
   o0Ooo00Oo0oo0 |= 0x10
   if 29 - 29: ooOoO0o % O0 / I11i % I1Ii111
  o0O0oIi1Ii = socket . htons ( self . radius )
  if ( o0O0oIi1Ii != 0 ) : o0Ooo00Oo0oo0 |= 0x06
  if 43 - 43: I1Ii111 . I11i - I1Ii111 / I1Ii111
  oo00oO0OOoOo000OO = struct . pack ( "HBBBBH" , iio00OOO0o0Oo0 , 0 , 0 , LISP_LCAF_GEO_COORD_TYPE ,
 0 , IIi1I1 )
  oo00oO0OOoOo000OO += struct . pack ( "BBHBBHBBHIHHH" , o0Ooo00Oo0oo0 , 0 , 0 , I1I1iiIii , Iio0 >> 16 ,
 socket . htons ( Iio0 & 0x0ffff ) , oo0OoOOo0o , Oo0O >> 16 ,
 socket . htons ( Oo0O & 0xffff ) , oOoOO00OOOo , o0O0oIi1Ii , 0 , 0 )
  if 57 - 57: I1ii11iIi11i % O0 - OoO0O00 + oO0o
  return ( oo00oO0OOoOo000OO )
  if 12 - 12: I1ii11iIi11i - I11i . OoOoOO00 + iII111i . iII111i
  if 43 - 43: I1Ii111 + I1Ii111 % Oo0Ooo % OoO0O00 - ooOoO0o
 def decode_geo ( self , packet , lcaf_len , radius_hi ) :
  I1I = "BBHBBHBBHIHHH"
  ii1I1iIi = struct . calcsize ( I1I )
  if ( lcaf_len < ii1I1iIi ) : return ( None )
  if 61 - 61: OoOoOO00 + Ii1I % i11iIiiIii - I1IiiI * OoO0O00 % iIii1I11I1II1
  o0Ooo00Oo0oo0 , o0ooOoo , oO0OOOO , I1I1iiIii , o00o00 , Iio0 , oo0OoOOo0o , ooo0 , Oo0O , oOoOO00OOOo , o0O0oIi1Ii , OO00000O0O0 , ooo0O0O0oo0 = struct . unpack ( I1I ,
  # Ii1I + o0oOOo0O0Ooo . iII111i / I1ii11iIi11i . I1ii11iIi11i
 packet [ : ii1I1iIi ] )
  if 7 - 7: I11i - OoooooooOO + O0 - i1IIi % I1IiiI
  if 63 - 63: IiII + oO0o + II111iiii * I11i
  if 49 - 49: OoO0O00
  if 78 - 78: I1IiiI - I1ii11iIi11i
  ooo0O0O0oo0 = socket . ntohs ( ooo0O0O0oo0 )
  if ( ooo0O0O0oo0 == LISP_AFI_LCAF ) : return ( None )
  if 24 - 24: Ii1I + I11i
  if ( o0Ooo00Oo0oo0 & 0x40 ) : I1I1iiIii = - I1I1iiIii
  self . latitude = I1I1iiIii
  I1IOooOoOo0o0O0O = ( ( o00o00 << 16 ) | socket . ntohs ( Iio0 ) ) / 1000
  self . lat_mins = I1IOooOoOo0o0O0O / 60
  self . lat_secs = I1IOooOoOo0o0O0O % 60
  if 7 - 7: o0oOOo0O0Ooo - iIii1I11I1II1 . I1IiiI / iII111i - OoooooooOO
  if ( o0Ooo00Oo0oo0 & 0x20 ) : oo0OoOOo0o = - oo0OoOOo0o
  self . longitude = oo0OoOOo0o
  oOOoooOOoo0O0OO = ( ( ooo0 << 16 ) | socket . ntohs ( Oo0O ) ) / 1000
  self . long_mins = oOOoooOOoo0O0OO / 60
  self . long_secs = oOOoooOOoo0O0OO % 60
  if 30 - 30: I11i + II111iiii * I1IiiI * O0 / ooOoO0o * IiII
  self . altitude = socket . ntohl ( oOoOO00OOOo ) if ( o0Ooo00Oo0oo0 & 0x10 ) else - 1
  o0O0oIi1Ii = socket . ntohs ( o0O0oIi1Ii )
  self . radius = o0O0oIi1Ii if ( o0Ooo00Oo0oo0 & 0x02 ) else o0O0oIi1Ii * 1000
  if 94 - 94: OoO0O00 - I1IiiI * oO0o
  self . geo_name = None
  packet = packet [ ii1I1iIi : : ]
  if 35 - 35: OOooOOo / i1IIi + OoO0O00
  if ( ooo0O0O0oo0 != 0 ) :
   self . rloc . afi = ooo0O0O0oo0
   packet = self . rloc . unpack_address ( packet )
   self . rloc . mask_len = self . rloc . host_mask_len ( )
   if 31 - 31: OoO0O00 . i1IIi / OoooooooOO
  return ( packet )
  if 81 - 81: ooOoO0o . Oo0Ooo . OoOoOO00 + OOooOOo % iII111i - oO0o
  if 68 - 68: iII111i - O0 / Ii1I
  if 15 - 15: I1Ii111 / I1ii11iIi11i / I1IiiI % i11iIiiIii + II111iiii . ooOoO0o
  if 74 - 74: o0oOOo0O0Ooo
  if 4 - 4: I1ii11iIi11i * II111iiii - Oo0Ooo % i1IIi % O0 * i11iIiiIii
  if 62 - 62: OoO0O00 * I1Ii111 * Ii1I / ooOoO0o
class lisp_rle_node ( ) :
 def __init__ ( self ) :
  self . address = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . level = 0
  self . translated_port = 0
  self . rloc_name = None
  if 27 - 27: oO0o . iII111i . oO0o
  if 37 - 37: Oo0Ooo . I1ii11iIi11i / OoooooooOO % ooOoO0o / I1IiiI + ooOoO0o
 def copy_rle_node ( self ) :
  iIiiI11iI111 = lisp_rle_node ( )
  iIiiI11iI111 . address . copy_address ( self . address )
  iIiiI11iI111 . level = self . level
  iIiiI11iI111 . translated_port = self . translated_port
  iIiiI11iI111 . rloc_name = self . rloc_name
  return ( iIiiI11iI111 )
  if 14 - 14: I11i + ooOoO0o . oO0o * I11i
  if 98 - 98: Ii1I . i1IIi * OoO0O00 * Ii1I * iIii1I11I1II1
 def store_translated_rloc ( self , rloc , port ) :
  self . address . copy_address ( rloc )
  self . translated_port = port
  if 22 - 22: OoooooooOO - OoO0O00 + OoOoOO00 - OOooOOo + i11iIiiIii - oO0o
  if 9 - 9: I1Ii111 - i1IIi . ooOoO0o
 def get_encap_keys ( self ) :
  i1I1IIIi11I = "4341" if self . translated_port == 0 else str ( self . translated_port )
  if 33 - 33: I11i
  oooOO0oOooO00 = self . address . print_address_no_iid ( ) + ":" + i1I1IIIi11I
  if 37 - 37: Oo0Ooo
  try :
   oOoOo0o00o = lisp_crypto_keys_by_rloc_encap [ oooOO0oOooO00 ]
   if ( oOoOo0o00o [ 1 ] ) : return ( oOoOo0o00o [ 1 ] . encrypt_key , oOoOo0o00o [ 1 ] . icv_key )
   return ( None , None )
  except :
   return ( None , None )
   if 36 - 36: IiII % I11i
   if 72 - 72: oO0o % I11i % OOooOOo * iIii1I11I1II1 - OOooOOo % O0
   if 84 - 84: oO0o - o0oOOo0O0Ooo / II111iiii . o0oOOo0O0Ooo
   if 82 - 82: OoooooooOO
class lisp_rle ( ) :
 def __init__ ( self , name ) :
  self . rle_name = name
  self . rle_nodes = [ ]
  self . rle_forwarding_list = [ ]
  if 14 - 14: OoO0O00 / oO0o - OOooOOo
  if 100 - 100: IiII - I11i . iIii1I11I1II1 / iIii1I11I1II1
 def copy_rle ( self ) :
  oO = lisp_rle ( self . rle_name )
  for iIiiI11iI111 in self . rle_nodes :
   oO . rle_nodes . append ( iIiiI11iI111 . copy_rle_node ( ) )
   if 16 - 16: IiII + Oo0Ooo % I11i
  oO . build_forwarding_list ( )
  return ( oO )
  if 16 - 16: ooOoO0o / I1Ii111
  if 78 - 78: OoOoOO00 - II111iiii - OOooOOo + I1IiiI + O0 / I1IiiI
 def print_rle ( self , html ) :
  OoI1iIi = ""
  for iIiiI11iI111 in self . rle_nodes :
   i1I1IIIi11I = iIiiI11iI111 . translated_port
   O0iiii = blue ( iIiiI11iI111 . rloc_name , html ) if iIiiI11iI111 . rloc_name != None else ""
   if 27 - 27: I11i / ooOoO0o . I1Ii111 + Ii1I
   oooOO0oOooO00 = iIiiI11iI111 . address . print_address_no_iid ( )
   if ( iIiiI11iI111 . address . is_local ( ) ) : oooOO0oOooO00 = red ( oooOO0oOooO00 , html )
   OoI1iIi += "{}{}(L{}){}, " . format ( oooOO0oOooO00 , "" if i1I1IIIi11I == 0 else "-" + str ( i1I1IIIi11I ) , iIiiI11iI111 . level ,
   # OoOoOO00 - II111iiii * o0oOOo0O0Ooo . iIii1I11I1II1
 "" if iIiiI11iI111 . rloc_name == None else O0iiii )
   if 33 - 33: OoO0O00 * I11i + iIii1I11I1II1
  return ( OoI1iIi [ 0 : - 2 ] if OoI1iIi != "" else "" )
  if 43 - 43: OoooooooOO . iII111i
  if 45 - 45: oO0o
 def build_forwarding_list ( self ) :
  OooOOo0 = - 1
  for iIiiI11iI111 in self . rle_nodes :
   if ( OooOOo0 == - 1 ) :
    if ( iIiiI11iI111 . address . is_local ( ) ) : OooOOo0 = iIiiI11iI111 . level
   else :
    if ( iIiiI11iI111 . level > OooOOo0 ) : break
    if 29 - 29: o0oOOo0O0Ooo . iIii1I11I1II1 - OoooooooOO . Ii1I - i1IIi * I1IiiI
    if 43 - 43: O0
  OooOOo0 = 0 if OooOOo0 == - 1 else iIiiI11iI111 . level
  if 99 - 99: i11iIiiIii - o0oOOo0O0Ooo + o0oOOo0O0Ooo . OoooooooOO * iII111i . Oo0Ooo
  self . rle_forwarding_list = [ ]
  for iIiiI11iI111 in self . rle_nodes :
   if ( iIiiI11iI111 . level == OooOOo0 or ( OooOOo0 == 0 and
 iIiiI11iI111 . level == 128 ) ) :
    if ( lisp_i_am_rtr == False and iIiiI11iI111 . address . is_local ( ) ) :
     oooOO0oOooO00 = iIiiI11iI111 . address . print_address_no_iid ( )
     lprint ( "Exclude local RLE RLOC {}" . format ( oooOO0oOooO00 ) )
     continue
     if 63 - 63: I11i
    self . rle_forwarding_list . append ( iIiiI11iI111 )
    if 60 - 60: I1IiiI / I1ii11iIi11i / I11i / Ii1I + iIii1I11I1II1
    if 85 - 85: O0 / OOooOOo . OoOoOO00 / I1ii11iIi11i
    if 80 - 80: I1ii11iIi11i * iII111i % i1IIi * OOooOOo % II111iiii % i1IIi
    if 44 - 44: OoooooooOO
    if 18 - 18: i11iIiiIii
class lisp_json ( ) :
 def __init__ ( self , name , string ) :
  self . json_name = name
  self . json_string = string
  if 65 - 65: i1IIi . iIii1I11I1II1 % iIii1I11I1II1
  if 35 - 35: iIii1I11I1II1 - o0oOOo0O0Ooo + I1ii11iIi11i * iII111i - OOooOOo . o0oOOo0O0Ooo
 def add ( self ) :
  self . delete ( )
  lisp_json_list [ self . json_name ] = self
  if 12 - 12: iIii1I11I1II1 % OoO0O00 * Oo0Ooo
  if 5 - 5: I11i - II111iiii * iIii1I11I1II1 / iIii1I11I1II1 % IiII * i1IIi
 def delete ( self ) :
  if ( lisp_json_list . has_key ( self . json_name ) ) :
   del ( lisp_json_list [ self . json_name ] )
   lisp_json_list [ self . json_name ] = None
   if 30 - 30: i1IIi % I1IiiI . OOooOOo % iIii1I11I1II1 . I1ii11iIi11i / o0oOOo0O0Ooo
   if 53 - 53: OOooOOo % ooOoO0o
   if 94 - 94: OOooOOo - O0 - I1Ii111 / OoooooooOO - iII111i
 def print_json ( self , html ) :
  O00O00oOO0Oo = self . json_string
  IIIiIiI1Ii = "***"
  if ( html ) : IIIiIiI1Ii = red ( IIIiIiI1Ii , html )
  OO0i11I = IIIiIiI1Ii + self . json_string + IIIiIiI1Ii
  if ( self . valid_json ( ) ) : return ( O00O00oOO0Oo )
  return ( OO0i11I )
  if 12 - 12: II111iiii / Ii1I * I1IiiI . I1Ii111 * OoO0O00 - i1IIi
  if 93 - 93: OOooOOo - O0 - I1IiiI . I1Ii111 . iII111i . OOooOOo
 def valid_json ( self ) :
  try :
   json . loads ( self . json_string )
  except :
   return ( False )
   if 76 - 76: II111iiii + iIii1I11I1II1 % I11i . I1IiiI
  return ( True )
  if 59 - 59: i1IIi
  if 40 - 40: iIii1I11I1II1 / i1IIi / OoOoOO00
  if 27 - 27: OOooOOo % O0 - iIii1I11I1II1 . i1IIi * II111iiii . II111iiii
  if 16 - 16: I1Ii111 / I1IiiI % OOooOOo
  if 61 - 61: I1ii11iIi11i . OOooOOo - O0 * OoOoOO00
  if 12 - 12: I1ii11iIi11i / I1Ii111
class lisp_stats ( ) :
 def __init__ ( self ) :
  self . packet_count = 0
  self . byte_count = 0
  self . last_rate_check = 0
  self . last_packet_count = 0
  self . last_byte_count = 0
  self . last_increment = None
  if 5 - 5: Oo0Ooo / o0oOOo0O0Ooo % i11iIiiIii - ooOoO0o
  if 62 - 62: i11iIiiIii
 def increment ( self , octets ) :
  self . packet_count += 1
  self . byte_count += octets
  self . last_increment = lisp_get_timestamp ( )
  if 88 - 88: i11iIiiIii
  if 59 - 59: oO0o - OoooooooOO % ooOoO0o
 def recent_packet_sec ( self ) :
  if ( self . last_increment == None ) : return ( False )
  Oo = time . time ( ) - self . last_increment
  return ( Oo <= 1 )
  if 90 - 90: OoOoOO00
  if 96 - 96: II111iiii % Ii1I
 def recent_packet_min ( self ) :
  if ( self . last_increment == None ) : return ( False )
  Oo = time . time ( ) - self . last_increment
  return ( Oo <= 60 )
  if 84 - 84: I1IiiI . I1IiiI
  if 82 - 82: OoO0O00 - iIii1I11I1II1 . iIii1I11I1II1 + I1ii11iIi11i
 def stat_colors ( self , c1 , c2 , html ) :
  if ( self . recent_packet_sec ( ) ) :
   return ( green_last_sec ( c1 ) , green_last_sec ( c2 ) )
   if 45 - 45: iII111i . oO0o * iII111i
  if ( self . recent_packet_min ( ) ) :
   return ( green_last_min ( c1 ) , green_last_min ( c2 ) )
   if 3 - 3: OoOoOO00 / Oo0Ooo - Oo0Ooo
  return ( c1 , c2 )
  if 54 - 54: Oo0Ooo . OoO0O00 * I1IiiI % IiII
  if 97 - 97: o0oOOo0O0Ooo + Ii1I
 def normalize ( self , count ) :
  count = str ( count )
  o0oO0000 = len ( count )
  if ( o0oO0000 > 12 ) :
   count = count [ 0 : - 10 ] + "." + count [ - 10 : - 7 ] + "T"
   return ( count )
   if 71 - 71: O0 / oO0o + OoOoOO00 / iIii1I11I1II1 % I11i
  if ( o0oO0000 > 9 ) :
   count = count [ 0 : - 9 ] + "." + count [ - 9 : - 7 ] + "B"
   return ( count )
   if 13 - 13: I1IiiI / iIii1I11I1II1 - I11i - iIii1I11I1II1 - OoOoOO00 % O0
  if ( o0oO0000 > 6 ) :
   count = count [ 0 : - 6 ] + "." + count [ - 6 ] + "M"
   return ( count )
   if 37 - 37: i11iIiiIii
  return ( count )
  if 100 - 100: II111iiii / Ii1I + i11iIiiIii % OOooOOo / ooOoO0o . oO0o
  if 89 - 89: I1IiiI . II111iiii
 def get_stats ( self , summary , html ) :
  iI1IIiI1i11Ii = self . last_rate_check
  Oooo0O0Oo0 = self . last_packet_count
  O00000OO0O00O = self . last_byte_count
  self . last_rate_check = lisp_get_timestamp ( )
  self . last_packet_count = self . packet_count
  self . last_byte_count = self . byte_count
  if 19 - 19: iII111i / OoOoOO00 % i11iIiiIii - I1IiiI * iIii1I11I1II1 - iIii1I11I1II1
  iIIi1I1 = self . last_rate_check - iI1IIiI1i11Ii
  if ( iIIi1I1 == 0 ) :
   iii = 0
   o0OO = 0
  else :
   iii = int ( ( self . packet_count - Oooo0O0Oo0 ) / iIIi1I1 )
   o0OO = ( self . byte_count - O00000OO0O00O ) / iIIi1I1
   o0OO = ( o0OO * 8 ) / 1000000
   o0OO = round ( o0OO , 2 )
   if 91 - 91: OoOoOO00
   if 63 - 63: I1IiiI * iII111i - i1IIi
   if 80 - 80: OOooOOo / iIii1I11I1II1 / OoOoOO00
   if 85 - 85: OOooOOo
   if 99 - 99: i1IIi . iIii1I11I1II1 % O0 - IiII . i11iIiiIii % iII111i
  ooOO00Oo0O = self . normalize ( self . packet_count )
  II11I = self . normalize ( self . byte_count )
  if 47 - 47: o0oOOo0O0Ooo . o0oOOo0O0Ooo
  if 94 - 94: I1ii11iIi11i + iIii1I11I1II1
  if 16 - 16: OoO0O00 * o0oOOo0O0Ooo + Oo0Ooo % oO0o / I11i
  if 21 - 21: O0
  if 76 - 76: i11iIiiIii % o0oOOo0O0Ooo . O0 * I11i
  if ( summary ) :
   Oo0000 = "<br>" if html else ""
   ooOO00Oo0O , II11I = self . stat_colors ( ooOO00Oo0O , II11I , html )
   oO0ooOo0o0OOOOO = "packet-count: {}{}byte-count: {}" . format ( ooOO00Oo0O , Oo0000 , II11I )
   OooO0o = "packet-rate: {} pps\nbit-rate: {} Mbps" . format ( iii , o0OO )
   if 59 - 59: i1IIi . iIii1I11I1II1 + I11i + I1IiiI . Oo0Ooo
   if ( html != "" ) : OooO0o = lisp_span ( oO0ooOo0o0OOOOO , OooO0o )
  else :
   O0OI1i1iiiii1i = str ( iii )
   oOo00OoOOOooo = str ( o0OO )
   if ( html ) :
    ooOO00Oo0O = lisp_print_cour ( ooOO00Oo0O )
    O0OI1i1iiiii1i = lisp_print_cour ( O0OI1i1iiiii1i )
    II11I = lisp_print_cour ( II11I )
    oOo00OoOOOooo = lisp_print_cour ( oOo00OoOOOooo )
    if 14 - 14: Ii1I . Ii1I . OOooOOo - O0 / OoO0O00 % II111iiii
   Oo0000 = "<br>" if html else ", "
   if 5 - 5: iIii1I11I1II1 % OoOoOO00 % OOooOOo % O0 * oO0o . iIii1I11I1II1
   OooO0o = ( "packet-count: {}{}packet-rate: {} pps{}byte-count: " + "{}{}bit-rate: {} mbps" ) . format ( ooOO00Oo0O , Oo0000 , O0OI1i1iiiii1i , Oo0000 , II11I , Oo0000 ,
   # Oo0Ooo % I1IiiI . i11iIiiIii - iII111i - o0oOOo0O0Ooo * OoO0O00
 oOo00OoOOOooo )
   if 35 - 35: o0oOOo0O0Ooo
  return ( OooO0o )
  if 60 - 60: OoooooooOO % OoOoOO00
  if 71 - 71: I1Ii111 % i11iIiiIii % i1IIi + I1IiiI
  if 53 - 53: OoOoOO00 * I1ii11iIi11i * OoO0O00 % OoOoOO00
  if 80 - 80: Oo0Ooo / I1ii11iIi11i
  if 17 - 17: i1IIi / IiII . I1IiiI % i1IIi
  if 46 - 46: IiII % O0 . o0oOOo0O0Ooo . OOooOOo
  if 47 - 47: OoooooooOO . oO0o . II111iiii / II111iiii - OoOoOO00
  if 81 - 81: o0oOOo0O0Ooo - Oo0Ooo % IiII - ooOoO0o / O0
lisp_decap_stats = {
 "good-packets" : lisp_stats ( ) , "ICV-error" : lisp_stats ( ) ,
 "checksum-error" : lisp_stats ( ) , "lisp-header-error" : lisp_stats ( ) ,
 "no-decrypt-key" : lisp_stats ( ) , "bad-inner-version" : lisp_stats ( ) ,
 "outer-header-error" : lisp_stats ( )
 }
if 27 - 27: Oo0Ooo
if 15 - 15: iIii1I11I1II1 . OoOoOO00 % Ii1I / i1IIi . o0oOOo0O0Ooo
if 45 - 45: iIii1I11I1II1 - i1IIi % I1IiiI - I1Ii111 + oO0o
if 15 - 15: iIii1I11I1II1 - OoooooooOO / ooOoO0o
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
  if 83 - 83: IiII + I1Ii111 / OoOoOO00 * IiII . oO0o
  if ( recurse == False ) : return
  if 22 - 22: O0 + ooOoO0o + I1Ii111
  if 57 - 57: OOooOOo . ooOoO0o - OoooooooOO - I1ii11iIi11i * O0
  if 85 - 85: I1IiiI * OoO0O00
  if 63 - 63: I1IiiI - i11iIiiIii
  if 4 - 4: OOooOOo + iIii1I11I1II1 / I1IiiI * Ii1I
  if 64 - 64: OoOoOO00
  O00ooOo0oO00o = lisp_get_default_route_next_hops ( )
  if ( O00ooOo0oO00o == [ ] or len ( O00ooOo0oO00o ) == 1 ) : return
  if 85 - 85: I1IiiI - OOooOOo
  self . rloc_next_hop = O00ooOo0oO00o [ 0 ]
  IiIi11 = self
  for iiiiIiiiiI in O00ooOo0oO00o [ 1 : : ] :
   Oooo000oOO0oO = lisp_rloc ( False )
   Oooo000oOO0oO = copy . deepcopy ( self )
   Oooo000oOO0oO . rloc_next_hop = iiiiIiiiiI
   IiIi11 . next_rloc = Oooo000oOO0oO
   IiIi11 = Oooo000oOO0oO
   if 16 - 16: i11iIiiIii . I1Ii111 % iII111i * I1Ii111 + i11iIiiIii - Ii1I
   if 82 - 82: OOooOOo - OoooooooOO . I11i
   if 45 - 45: I1Ii111
 def up_state ( self ) :
  return ( self . state == LISP_RLOC_UP_STATE )
  if 67 - 67: OoOoOO00 * OOooOOo / OOooOOo / OoooooooOO
  if 67 - 67: I11i - i1IIi . OoooooooOO / iIii1I11I1II1
 def unreach_state ( self ) :
  return ( self . state == LISP_RLOC_UNREACH_STATE )
  if 34 - 34: OoO0O00 * II111iiii
  if 43 - 43: OoOoOO00 . I1IiiI
 def no_echoed_nonce_state ( self ) :
  return ( self . state == LISP_RLOC_NO_ECHOED_NONCE_STATE )
  if 44 - 44: O0 / o0oOOo0O0Ooo
  if 19 - 19: I11i
 def down_state ( self ) :
  return ( self . state in [ LISP_RLOC_DOWN_STATE , LISP_RLOC_ADMIN_DOWN_STATE ] )
  if 91 - 91: OOooOOo * OoooooooOO
  if 89 - 89: i1IIi / iII111i . I1Ii111
  if 74 - 74: I1ii11iIi11i % iII111i / OoooooooOO / I1ii11iIi11i % i11iIiiIii % ooOoO0o
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
  if 82 - 82: OoooooooOO . o0oOOo0O0Ooo * I1ii11iIi11i % I1ii11iIi11i * Ii1I
  if 83 - 83: I11i - Oo0Ooo + i11iIiiIii - i11iIiiIii
 def print_rloc ( self , indent ) :
  o0O0oo0OO0O = lisp_print_elapsed ( self . uptime )
  lprint ( "{}rloc {}, uptime {}, {}, parms {}/{}/{}/{}" . format ( indent ,
 red ( self . rloc . print_address ( ) , False ) , o0O0oo0OO0O , self . print_state ( ) ,
 self . priority , self . weight , self . mpriority , self . mweight ) )
  if 64 - 64: IiII % I1IiiI / ooOoO0o
  if 74 - 74: OoooooooOO
 def print_rloc_name ( self , cour = False ) :
  if ( self . rloc_name == None ) : return ( "" )
  i11Ii1i1iII = self . rloc_name
  if ( cour ) : i11Ii1i1iII = lisp_print_cour ( i11Ii1i1iII )
  return ( 'rloc-name: {}' . format ( blue ( i11Ii1i1iII , cour ) ) )
  if 22 - 22: II111iiii . O0 * I1Ii111 % OoO0O00 / OoooooooOO + I1Ii111
  if 71 - 71: ooOoO0o . oO0o * OoooooooOO + iII111i - I1Ii111 . I1ii11iIi11i
 def store_rloc_from_record ( self , rloc_record , nonce , source ) :
  i1I1IIIi11I = LISP_DATA_PORT
  self . rloc . copy_address ( rloc_record . rloc )
  self . rloc_name = rloc_record . rloc_name
  if 100 - 100: I11i + O0 - o0oOOo0O0Ooo * I1ii11iIi11i
  if 94 - 94: Oo0Ooo . IiII / Ii1I / oO0o - I1IiiI
  if 77 - 77: i11iIiiIii . Ii1I - Ii1I
  if 47 - 47: iII111i % OOooOOo . I1ii11iIi11i + I1ii11iIi11i . I1Ii111
  Oo0O0 = self . rloc
  if ( Oo0O0 . is_null ( ) == False ) :
   IIII1iII = lisp_get_nat_info ( Oo0O0 , self . rloc_name )
   if ( IIII1iII ) :
    i1I1IIIi11I = IIII1iII . port
    i1IIIiii1 = lisp_nat_state_info [ self . rloc_name ] [ 0 ]
    oooOO0oOooO00 = Oo0O0 . print_address_no_iid ( )
    iII1II = red ( oooOO0oOooO00 , False )
    OoO0O0OoO0oO = "" if self . rloc_name == None else blue ( self . rloc_name , False )
    if 38 - 38: iII111i - OoO0O00 / i1IIi + ooOoO0o . ooOoO0o . iII111i
    if 37 - 37: iIii1I11I1II1 * OoOoOO00 . OoOoOO00 + OoooooooOO + OoO0O00
    if 25 - 25: I1IiiI / IiII . OOooOOo . I1ii11iIi11i % i1IIi
    if 12 - 12: O0 % O0
    if 9 - 9: O0 . I1IiiI + I1ii11iIi11i / OOooOOo * I1ii11iIi11i
    if 10 - 10: IiII % o0oOOo0O0Ooo / O0 / II111iiii
    if ( IIII1iII . timed_out ( ) ) :
     lprint ( ( "    Matched stored NAT state timed out for " + "RLOC {}:{}, {}" ) . format ( iII1II , i1I1IIIi11I , OoO0O0OoO0oO ) )
     if 81 - 81: Ii1I / o0oOOo0O0Ooo % OoOoOO00 . I1ii11iIi11i
     if 47 - 47: II111iiii + OOooOOo / II111iiii . OOooOOo
     IIII1iII = None if ( IIII1iII == i1IIIiii1 ) else i1IIIiii1
     if ( IIII1iII and IIII1iII . timed_out ( ) ) :
      i1I1IIIi11I = IIII1iII . port
      iII1II = red ( IIII1iII . address , False )
      lprint ( ( "    Youngest stored NAT state timed out " + " for RLOC {}:{}, {}" ) . format ( iII1II , i1I1IIIi11I ,
      # OoooooooOO . iIii1I11I1II1 - Ii1I / OoO0O00 / oO0o
 OoO0O0OoO0oO ) )
      IIII1iII = None
      if 14 - 14: OOooOOo + iIii1I11I1II1 - Ii1I % I11i % OoO0O00 - i11iIiiIii
      if 88 - 88: iII111i / I11i / I1ii11iIi11i + IiII * OoooooooOO . IiII
      if 3 - 3: ooOoO0o - Oo0Ooo
      if 86 - 86: I1ii11iIi11i * I1Ii111 / o0oOOo0O0Ooo . OoO0O00
      if 14 - 14: I11i * IiII / iIii1I11I1II1
      if 88 - 88: OoOoOO00 % II111iiii . I1IiiI / oO0o * IiII / i11iIiiIii
      if 76 - 76: o0oOOo0O0Ooo
    if ( IIII1iII ) :
     if ( IIII1iII . address != oooOO0oOooO00 ) :
      lprint ( "RLOC conflict, RLOC-record {}, NAT state {}" . format ( iII1II , red ( IIII1iII . address , False ) ) )
      if 80 - 80: OOooOOo
      self . rloc . store_address ( IIII1iII . address )
      if 15 - 15: OOooOOo . OoOoOO00 / oO0o . I1ii11iIi11i % OoO0O00 - oO0o
     iII1II = red ( IIII1iII . address , False )
     i1I1IIIi11I = IIII1iII . port
     lprint ( "    Use NAT translated RLOC {}:{} for {}" . format ( iII1II , i1I1IIIi11I , OoO0O0OoO0oO ) )
     if 21 - 21: ooOoO0o . o0oOOo0O0Ooo . oO0o . i1IIi
     self . store_translated_rloc ( Oo0O0 , i1I1IIIi11I )
     if 96 - 96: Ii1I % I11i * OoooooooOO . I1IiiI . iIii1I11I1II1
     if 8 - 8: O0 + o0oOOo0O0Ooo / O0 - I1ii11iIi11i % I1ii11iIi11i
     if 55 - 55: OoooooooOO * OoooooooOO % I1Ii111 / Ii1I / ooOoO0o
     if 12 - 12: i11iIiiIii + Ii1I % iIii1I11I1II1 + I1Ii111
  self . geo = rloc_record . geo
  self . elp = rloc_record . elp
  self . json = rloc_record . json
  if 12 - 12: Ii1I + I1Ii111 / O0 * II111iiii
  if 67 - 67: iIii1I11I1II1 / I11i + ooOoO0o * I1Ii111 * oO0o
  if 100 - 100: OoooooooOO % I1IiiI / OoOoOO00 % OoOoOO00 . o0oOOo0O0Ooo
  if 81 - 81: Ii1I - II111iiii + I11i / Ii1I
  self . rle = rloc_record . rle
  if ( self . rle ) :
   for iIiiI11iI111 in self . rle . rle_nodes :
    i11Ii1i1iII = iIiiI11iI111 . rloc_name
    IIII1iII = lisp_get_nat_info ( iIiiI11iI111 . address , i11Ii1i1iII )
    if ( IIII1iII == None ) : continue
    if 89 - 89: i11iIiiIii + I1ii11iIi11i - ooOoO0o . ooOoO0o + Oo0Ooo % Ii1I
    i1I1IIIi11I = IIII1iII . port
    Oo00 = i11Ii1i1iII
    if ( Oo00 ) : Oo00 = blue ( i11Ii1i1iII , False )
    if 96 - 96: I1Ii111 - I11i * I1Ii111
    lprint ( ( "      Store translated encap-port {} for RLE-" + "node {}, rloc-name '{}'" ) . format ( i1I1IIIi11I ,
    # i1IIi * I1IiiI
 iIiiI11iI111 . address . print_address_no_iid ( ) , Oo00 ) )
    iIiiI11iI111 . translated_port = i1I1IIIi11I
    if 23 - 23: I1ii11iIi11i % i11iIiiIii
    if 25 - 25: I1ii11iIi11i * Ii1I * OoO0O00 . OOooOOo % OoOoOO00
    if 77 - 77: I1Ii111 / iIii1I11I1II1 * I1Ii111 % oO0o + o0oOOo0O0Ooo . IiII
  self . priority = rloc_record . priority
  self . mpriority = rloc_record . mpriority
  self . weight = rloc_record . weight
  self . mweight = rloc_record . mweight
  if ( rloc_record . reach_bit and rloc_record . local_bit and
 rloc_record . probe_bit == False ) : self . state = LISP_RLOC_UP_STATE
  if 80 - 80: OOooOOo . I1IiiI % iIii1I11I1II1
  if 45 - 45: OoooooooOO * O0
  if 86 - 86: O0 * oO0o + Oo0Ooo / II111iiii + i1IIi
  if 12 - 12: I1IiiI + OOooOOo / Ii1I % i11iIiiIii - I1Ii111 % I11i
  i1Ii111Ii111 = source . is_exact_match ( rloc_record . rloc ) if source != None else None
  if 1 - 1: IiII / OoOoOO00
  if ( rloc_record . keys != None and i1Ii111Ii111 ) :
   o0000oO = rloc_record . keys [ 1 ]
   if ( o0000oO != None ) :
    oooOO0oOooO00 = rloc_record . rloc . print_address_no_iid ( ) + ":" + str ( i1I1IIIi11I )
    if 98 - 98: Ii1I % iII111i . OoooooooOO - i1IIi % I1Ii111
    o0000oO . add_key_by_rloc ( oooOO0oOooO00 , True )
    lprint ( "    Store encap-keys for nonce 0x{}, RLOC {}" . format ( lisp_hex_string ( nonce ) , red ( oooOO0oOooO00 , False ) ) )
    if 94 - 94: i1IIi + iII111i
    if 25 - 25: I1Ii111 . Ii1I - Ii1I . o0oOOo0O0Ooo - IiII
    if 91 - 91: o0oOOo0O0Ooo % I1ii11iIi11i % OoOoOO00 * iIii1I11I1II1
  return ( i1I1IIIi11I )
  if 18 - 18: OoOoOO00 * I1ii11iIi11i . i1IIi * iII111i
  if 67 - 67: IiII + i11iIiiIii . II111iiii / OoOoOO00 + OoooooooOO + i11iIiiIii
 def store_translated_rloc ( self , rloc , port ) :
  self . rloc . copy_address ( rloc )
  self . translated_rloc . copy_address ( rloc )
  self . translated_port = port
  if 23 - 23: Oo0Ooo
  if 7 - 7: Oo0Ooo / oO0o . I1Ii111 % I11i
 def is_rloc_translated ( self ) :
  return ( self . translated_rloc . is_null ( ) == False )
  if 85 - 85: II111iiii / o0oOOo0O0Ooo . iIii1I11I1II1 . OoooooooOO / Ii1I
  if 18 - 18: i11iIiiIii + o0oOOo0O0Ooo . i11iIiiIii
 def rloc_exists ( self ) :
  if ( self . rloc . is_null ( ) == False ) : return ( True )
  if ( self . rle_name or self . geo_name or self . elp_name or self . json_name ) :
   return ( False )
   if 50 - 50: IiII / OoooooooOO . I11i
  return ( True )
  if 93 - 93: OOooOOo / OoooooooOO % iII111i % Ii1I / I1Ii111 % OOooOOo
  if 25 - 25: i1IIi % Oo0Ooo . i1IIi * OoOoOO00 . Ii1I % OoO0O00
 def is_rtr ( self ) :
  return ( ( self . priority == 254 and self . mpriority == 255 and self . weight == 0 and self . mweight == 0 ) )
  if 47 - 47: o0oOOo0O0Ooo - i11iIiiIii / OoooooooOO
  if 93 - 93: I1IiiI * II111iiii * O0 % o0oOOo0O0Ooo + oO0o / ooOoO0o
  if 79 - 79: OoO0O00 + ooOoO0o / oO0o % I1ii11iIi11i
 def print_state_change ( self , new_state ) :
  o0o0 = self . print_state ( )
  O00OO0O = "{} -> {}" . format ( o0o0 , new_state )
  if ( new_state == "up" and self . unreach_state ( ) ) :
   O00OO0O = bold ( O00OO0O , False )
   if 60 - 60: I1Ii111 * i11iIiiIii . iII111i . i1IIi + ooOoO0o * o0oOOo0O0Ooo
  return ( O00OO0O )
  if 99 - 99: oO0o / o0oOOo0O0Ooo . i11iIiiIii % OoooooooOO * O0
  if 52 - 52: OOooOOo / ooOoO0o . II111iiii / Oo0Ooo
 def print_rloc_probe_rtt ( self ) :
  if ( self . rloc_probe_rtt == - 1 ) : return ( "none" )
  return ( self . rloc_probe_rtt )
  if 66 - 66: Ii1I * I1Ii111 * OoO0O00
  if 92 - 92: II111iiii * iII111i % OoOoOO00 % OoOoOO00 % i11iIiiIii
 def print_recent_rloc_probe_rtts ( self ) :
  O00oo0o = str ( self . recent_rloc_probe_rtts )
  O00oo0o = O00oo0o . replace ( "-1" , "?" )
  return ( O00oo0o )
  if 48 - 48: OoooooooOO - O0 + I1IiiI - I11i
  if 86 - 86: i11iIiiIii / IiII + i11iIiiIii + o0oOOo0O0Ooo . I1Ii111 . I1Ii111
 def compute_rloc_probe_rtt ( self ) :
  IiIi11 = self . rloc_probe_rtt
  self . rloc_probe_rtt = - 1
  if ( self . last_rloc_probe_reply == None ) : return
  if ( self . last_rloc_probe == None ) : return
  self . rloc_probe_rtt = self . last_rloc_probe_reply - self . last_rloc_probe
  self . rloc_probe_rtt = round ( self . rloc_probe_rtt , 3 )
  o00oOoo0o00 = self . recent_rloc_probe_rtts
  self . recent_rloc_probe_rtts = [ IiIi11 ] + o00oOoo0o00 [ 0 : - 1 ]
  if 74 - 74: OoO0O00 / Ii1I % II111iiii * OoOoOO00
  if 19 - 19: o0oOOo0O0Ooo * IiII . Oo0Ooo * OOooOOo
 def print_rloc_probe_hops ( self ) :
  return ( self . rloc_probe_hops )
  if 6 - 6: I1ii11iIi11i / O0
  if 16 - 16: II111iiii . Oo0Ooo * I1Ii111 + o0oOOo0O0Ooo - i11iIiiIii
 def print_recent_rloc_probe_hops ( self ) :
  ooOo0OoO0 = str ( self . recent_rloc_probe_hops )
  return ( ooOo0OoO0 )
  if 54 - 54: I1IiiI - I11i - OoOoOO00 % ooOoO0o - O0
  if 30 - 30: i11iIiiIii - I11i
 def store_rloc_probe_hops ( self , to_hops , from_ttl ) :
  if ( to_hops == 0 ) :
   to_hops = "?"
  elif ( to_hops < LISP_RLOC_PROBE_TTL / 2 ) :
   to_hops = "!"
  else :
   to_hops = str ( LISP_RLOC_PROBE_TTL - to_hops )
   if 28 - 28: i1IIi + O0 - i11iIiiIii - I1Ii111
  if ( from_ttl < LISP_RLOC_PROBE_TTL / 2 ) :
   O0Ooo0 = "!"
  else :
   O0Ooo0 = str ( LISP_RLOC_PROBE_TTL - from_ttl )
   if 10 - 10: OoooooooOO + iII111i + OoOoOO00 - ooOoO0o . Ii1I + OOooOOo
   if 33 - 33: OoooooooOO
  IiIi11 = self . rloc_probe_hops
  self . rloc_probe_hops = to_hops + "/" + O0Ooo0
  o00oOoo0o00 = self . recent_rloc_probe_hops
  self . recent_rloc_probe_hops = [ IiIi11 ] + o00oOoo0o00 [ 0 : - 1 ]
  if 62 - 62: OOooOOo % OoooooooOO * Oo0Ooo + OOooOOo * Oo0Ooo - I1IiiI
  if 2 - 2: I1IiiI + II111iiii . ooOoO0o + oO0o . OoO0O00
 def process_rloc_probe_reply ( self , nonce , eid , group , hop_count , ttl ) :
  Oo0O0 = self
  while ( True ) :
   if ( Oo0O0 . last_rloc_probe_nonce == nonce ) : break
   Oo0O0 = Oo0O0 . next_rloc
   if ( Oo0O0 == None ) :
    lprint ( "    No matching nonce state found for nonce 0x{}" . format ( lisp_hex_string ( nonce ) ) )
    if 49 - 49: OoO0O00 . IiII
    return
    if 41 - 41: OoooooooOO + oO0o % oO0o / I1ii11iIi11i
    if 86 - 86: i1IIi
    if 73 - 73: iIii1I11I1II1 * Oo0Ooo
  Oo0O0 . last_rloc_probe_reply = lisp_get_timestamp ( )
  Oo0O0 . compute_rloc_probe_rtt ( )
  oOo0OOo00oo0o = Oo0O0 . print_state_change ( "up" )
  if ( Oo0O0 . state != LISP_RLOC_UP_STATE ) :
   lisp_update_rtr_updown ( Oo0O0 . rloc , True )
   Oo0O0 . state = LISP_RLOC_UP_STATE
   Oo0O0 . last_state_change = lisp_get_timestamp ( )
   oOooO0Oo0Oo0 = lisp_map_cache . lookup_cache ( eid , True )
   if ( oOooO0Oo0Oo0 ) : lisp_write_ipc_map_cache ( True , oOooO0Oo0Oo0 )
   if 18 - 18: i1IIi
   if 33 - 33: iIii1I11I1II1 % ooOoO0o - I1Ii111
  Oo0O0 . store_rloc_probe_hops ( hop_count , ttl )
  if 9 - 9: I1Ii111 / OoO0O00 - OoO0O00
  o0ooOOoO0O = bold ( "RLOC-probe reply" , False )
  oooOO0oOooO00 = Oo0O0 . rloc . print_address_no_iid ( )
  IIi1 = bold ( str ( Oo0O0 . print_rloc_probe_rtt ( ) ) , False )
  iII1ii = ":{}" . format ( self . translated_port ) if self . translated_port != 0 else ""
  if 85 - 85: iIii1I11I1II1 % Oo0Ooo
  iiiiIiiiiI = ""
  if ( Oo0O0 . rloc_next_hop != None ) :
   O0o0oo0oOO0oO , i11i1iI = Oo0O0 . rloc_next_hop
   iiiiIiiiiI = ", nh {}({})" . format ( i11i1iI , O0o0oo0oOO0oO )
   if 93 - 93: IiII
   if 45 - 45: Ii1I + O0 + oO0o - OoOoOO00
  O0O0o0o0o = green ( lisp_print_eid_tuple ( eid , group ) , False )
  lprint ( ( "    Received {} from {}{} for {}, {}, rtt {}{}, " + "to-ttl/from-ttl {}" ) . format ( o0ooOOoO0O , red ( oooOO0oOooO00 , False ) , iII1ii , O0O0o0o0o ,
  # I1IiiI - I1ii11iIi11i * ooOoO0o - iII111i * OoO0O00 + oO0o
 oOo0OOo00oo0o , IIi1 , iiiiIiiiiI , str ( hop_count ) + "/" + str ( ttl ) ) )
  if 63 - 63: o0oOOo0O0Ooo . Ii1I
  if ( Oo0O0 . rloc_next_hop == None ) : return
  if 51 - 51: I11i - OoooooooOO / OoOoOO00
  if 46 - 46: I1IiiI / OoOoOO00 / i11iIiiIii % i11iIiiIii
  if 77 - 77: I1ii11iIi11i % OoooooooOO - Oo0Ooo - Ii1I + I11i
  if 93 - 93: I1IiiI % O0 * OoO0O00 % OoOoOO00 . I1Ii111 * I1IiiI
  Oo0O0 = None
  o0OOO0 = None
  while ( True ) :
   Oo0O0 = self if Oo0O0 == None else Oo0O0 . next_rloc
   if ( Oo0O0 == None ) : break
   if ( Oo0O0 . up_state ( ) == False ) : continue
   if ( Oo0O0 . rloc_probe_rtt == - 1 ) : continue
   if 13 - 13: i11iIiiIii - II111iiii - iIii1I11I1II1 / Ii1I % I1Ii111 * i11iIiiIii
   if ( o0OOO0 == None ) : o0OOO0 = Oo0O0
   if ( Oo0O0 . rloc_probe_rtt < o0OOO0 . rloc_probe_rtt ) : o0OOO0 = Oo0O0
   if 98 - 98: Ii1I / i1IIi * I1IiiI
   if 70 - 70: i1IIi - i1IIi % I1ii11iIi11i . OOooOOo
  if ( o0OOO0 != None ) :
   O0o0oo0oOO0oO , i11i1iI = o0OOO0 . rloc_next_hop
   iiiiIiiiiI = bold ( "nh {}({})" . format ( i11i1iI , O0o0oo0oOO0oO ) , False )
   lprint ( "    Install host-route via best {}" . format ( iiiiIiiiiI ) )
   lisp_install_host_route ( oooOO0oOooO00 , None , False )
   lisp_install_host_route ( oooOO0oOooO00 , i11i1iI , True )
   if 36 - 36: I1ii11iIi11i / OoooooooOO
   if 81 - 81: i11iIiiIii / Oo0Ooo * i1IIi + OoO0O00 + O0 % I1ii11iIi11i
   if 3 - 3: i11iIiiIii * IiII . Oo0Ooo % OoOoOO00 * I11i . iII111i
 def add_to_rloc_probe_list ( self , eid , group ) :
  oooOO0oOooO00 = self . rloc . print_address_no_iid ( )
  i1I1IIIi11I = self . translated_port
  if ( i1I1IIIi11I != 0 ) : oooOO0oOooO00 += ":" + str ( i1I1IIIi11I )
  if 80 - 80: I11i - IiII
  if ( lisp_rloc_probe_list . has_key ( oooOO0oOooO00 ) == False ) :
   lisp_rloc_probe_list [ oooOO0oOooO00 ] = [ ]
   if 40 - 40: OOooOOo * I1IiiI % I11i . I1Ii111 % O0 . O0
   if 14 - 14: ooOoO0o . OoOoOO00 + ooOoO0o * OoOoOO00 . OoOoOO00 * Oo0Ooo
  if ( group . is_null ( ) ) : group . instance_id = 0
  for o0O , O0O0o0o0o , Ii1i111iI in lisp_rloc_probe_list [ oooOO0oOooO00 ] :
   if ( O0O0o0o0o . is_exact_match ( eid ) and Ii1i111iI . is_exact_match ( group ) ) :
    if ( o0O == self ) :
     if ( lisp_rloc_probe_list [ oooOO0oOooO00 ] == [ ] ) :
      lisp_rloc_probe_list . pop ( oooOO0oOooO00 )
      if 40 - 40: OoooooooOO
     return
     if 14 - 14: o0oOOo0O0Ooo / OOooOOo . OoOoOO00 % iIii1I11I1II1 % OoOoOO00
    lisp_rloc_probe_list [ oooOO0oOooO00 ] . remove ( [ o0O , O0O0o0o0o , Ii1i111iI ] )
    break
    if 92 - 92: o0oOOo0O0Ooo + II111iiii
    if 56 - 56: OoOoOO00 - OoOoOO00 / Ii1I
  lisp_rloc_probe_list [ oooOO0oOooO00 ] . append ( [ self , eid , group ] )
  if 92 - 92: iIii1I11I1II1
  if 21 - 21: I1IiiI
  if 69 - 69: OoooooooOO + iII111i
  if 29 - 29: ooOoO0o * I1IiiI / Oo0Ooo / I1ii11iIi11i
  if 74 - 74: I1ii11iIi11i - ooOoO0o / OoOoOO00 - OoooooooOO * oO0o
  Oo0O0 = lisp_rloc_probe_list [ oooOO0oOooO00 ] [ 0 ] [ 0 ]
  if ( Oo0O0 . state == LISP_RLOC_UNREACH_STATE ) :
   self . state = LISP_RLOC_UNREACH_STATE
   self . last_state_change = lisp_get_timestamp ( )
   if 45 - 45: o0oOOo0O0Ooo . I1Ii111 % Ii1I
   if 42 - 42: Oo0Ooo + i11iIiiIii - OOooOOo . I1ii11iIi11i % I1Ii111 . I1ii11iIi11i
   if 59 - 59: OoooooooOO
 def delete_from_rloc_probe_list ( self , eid , group ) :
  oooOO0oOooO00 = self . rloc . print_address_no_iid ( )
  i1I1IIIi11I = self . translated_port
  if ( i1I1IIIi11I != 0 ) : oooOO0oOooO00 += ":" + str ( i1I1IIIi11I )
  if ( lisp_rloc_probe_list . has_key ( oooOO0oOooO00 ) == False ) : return
  if 91 - 91: i11iIiiIii / Oo0Ooo % I11i / O0
  Oo0Oo = [ ]
  for oo in lisp_rloc_probe_list [ oooOO0oOooO00 ] :
   if ( oo [ 0 ] != self ) : continue
   if ( oo [ 1 ] . is_exact_match ( eid ) == False ) : continue
   if ( oo [ 2 ] . is_exact_match ( group ) == False ) : continue
   Oo0Oo = oo
   break
   if 32 - 32: iIii1I11I1II1 . i1IIi - OoOoOO00 - O0 - iII111i
  if ( Oo0Oo == [ ] ) : return
  if 64 - 64: II111iiii
  try :
   lisp_rloc_probe_list [ oooOO0oOooO00 ] . remove ( Oo0Oo )
   if ( lisp_rloc_probe_list [ oooOO0oOooO00 ] == [ ] ) :
    lisp_rloc_probe_list . pop ( oooOO0oOooO00 )
    if 14 - 14: I1Ii111
  except :
   return
   if 81 - 81: II111iiii
   if 55 - 55: O0 + o0oOOo0O0Ooo * I1IiiI - OoooooooOO
   if 68 - 68: I11i + Oo0Ooo
 def print_rloc_probe_state ( self , trailing_linefeed ) :
  OOoo0oo = ""
  Oo0O0 = self
  while ( True ) :
   i1iIi1Ii1I11I = Oo0O0 . last_rloc_probe
   if ( i1iIi1Ii1I11I == None ) : i1iIi1Ii1I11I = 0
   o0oOO0OO0000O = Oo0O0 . last_rloc_probe_reply
   if ( o0oOO0OO0000O == None ) : o0oOO0OO0000O = 0
   IIi1 = Oo0O0 . print_rloc_probe_rtt ( )
   oooOOO00o0 = space ( 4 )
   if 58 - 58: O0 * oO0o * OoOoOO00 . I1IiiI . i11iIiiIii / I1Ii111
   if ( Oo0O0 . rloc_next_hop == None ) :
    OOoo0oo += "RLOC-Probing:\n"
   else :
    O0o0oo0oOO0oO , i11i1iI = Oo0O0 . rloc_next_hop
    OOoo0oo += "RLOC-Probing for nh {}({}):\n" . format ( i11i1iI , O0o0oo0oOO0oO )
    if 40 - 40: OoooooooOO / o0oOOo0O0Ooo + OoOoOO00
    if 73 - 73: OOooOOo / Oo0Ooo
   OOoo0oo += ( "{}RLOC-probe request sent: {}\n{}RLOC-probe reply " + "received: {}, rtt {}" ) . format ( oooOOO00o0 , lisp_print_elapsed ( i1iIi1Ii1I11I ) ,
   # I1IiiI * Ii1I + i1IIi / I11i / I11i
 oooOOO00o0 , lisp_print_elapsed ( o0oOO0OO0000O ) , IIi1 )
   if 90 - 90: II111iiii . I1Ii111
   if ( trailing_linefeed ) : OOoo0oo += "\n"
   if 26 - 26: I1Ii111 * O0 / oO0o
   Oo0O0 = Oo0O0 . next_rloc
   if ( Oo0O0 == None ) : break
   OOoo0oo += "\n"
   if 33 - 33: o0oOOo0O0Ooo * OOooOOo
  return ( OOoo0oo )
  if 7 - 7: i11iIiiIii . OOooOOo * Ii1I . i1IIi
  if 4 - 4: O0 - IiII - II111iiii / iII111i - OOooOOo
 def get_encap_keys ( self ) :
  i1I1IIIi11I = "4341" if self . translated_port == 0 else str ( self . translated_port )
  if 6 - 6: ooOoO0o + OOooOOo - I1IiiI + OOooOOo
  oooOO0oOooO00 = self . rloc . print_address_no_iid ( ) + ":" + i1I1IIIi11I
  if 16 - 16: OoO0O00 * OoOoOO00 - Oo0Ooo
  try :
   oOoOo0o00o = lisp_crypto_keys_by_rloc_encap [ oooOO0oOooO00 ]
   if ( oOoOo0o00o [ 1 ] ) : return ( oOoOo0o00o [ 1 ] . encrypt_key , oOoOo0o00o [ 1 ] . icv_key )
   return ( None , None )
  except :
   return ( None , None )
   if 44 - 44: ooOoO0o / OoOoOO00 - O0 + iII111i / iIii1I11I1II1
   if 41 - 41: iIii1I11I1II1 - iII111i / O0
   if 39 - 39: OoooooooOO * iIii1I11I1II1 - o0oOOo0O0Ooo / O0
 def rloc_recent_rekey ( self ) :
  i1I1IIIi11I = "4341" if self . translated_port == 0 else str ( self . translated_port )
  if 29 - 29: I11i % OoOoOO00 - oO0o + II111iiii . II111iiii
  oooOO0oOooO00 = self . rloc . print_address_no_iid ( ) + ":" + i1I1IIIi11I
  if 25 - 25: Oo0Ooo * ooOoO0o % I1Ii111
  try :
   o0000oO = lisp_crypto_keys_by_rloc_encap [ oooOO0oOooO00 ] [ 1 ]
   if ( o0000oO == None ) : return ( False )
   if ( o0000oO . last_rekey == None ) : return ( True )
   return ( time . time ( ) - o0000oO . last_rekey < 1 )
  except :
   return ( False )
   if 34 - 34: OoOoOO00 / I1Ii111 - ooOoO0o
   if 66 - 66: I11i * OoO0O00
   if 98 - 98: IiII . Oo0Ooo + I1Ii111
   if 63 - 63: oO0o * I1IiiI * oO0o
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
  if 56 - 56: oO0o - Ii1I % I1Ii111
  if 100 - 100: OOooOOo * IiII % IiII / o0oOOo0O0Ooo * OoO0O00 % OoOoOO00
 def print_mapping ( self , eid_indent , rloc_indent ) :
  o0O0oo0OO0O = lisp_print_elapsed ( self . uptime )
  iiI = "" if self . group . is_null ( ) else ", group {}" . format ( self . group . print_prefix ( ) )
  if 12 - 12: I1IiiI
  lprint ( "{}eid {}{}, uptime {}, {} rlocs:" . format ( eid_indent ,
 green ( self . eid . print_prefix ( ) , False ) , iiI , o0O0oo0OO0O ,
 len ( self . rloc_set ) ) )
  for Oo0O0 in self . rloc_set : Oo0O0 . print_rloc ( rloc_indent )
  if 32 - 32: I1Ii111
  if 35 - 35: O0 + II111iiii + o0oOOo0O0Ooo - OoO0O00 - Ii1I
 def print_eid_tuple ( self ) :
  return ( lisp_print_eid_tuple ( self . eid , self . group ) )
  if 88 - 88: I1ii11iIi11i . O0 - o0oOOo0O0Ooo . I1ii11iIi11i * iII111i * I11i
  if 89 - 89: Oo0Ooo - oO0o + O0 / i11iIiiIii
 def print_ttl ( self ) :
  O00O00Oo = self . map_cache_ttl
  if ( O00O00Oo == None ) : return ( "forever" )
  if 64 - 64: OoO0O00 % OoOoOO00 % I1IiiI - Ii1I / IiII * Ii1I
  if ( O00O00Oo >= 3600 ) :
   if ( ( O00O00Oo % 3600 ) == 0 ) :
    O00O00Oo = str ( O00O00Oo / 3600 ) + " hours"
   else :
    O00O00Oo = str ( O00O00Oo * 60 ) + " mins"
    if 74 - 74: IiII - O0 % OOooOOo % OoooooooOO - I11i
  elif ( O00O00Oo >= 60 ) :
   if ( ( O00O00Oo % 60 ) == 0 ) :
    O00O00Oo = str ( O00O00Oo / 60 ) + " mins"
   else :
    O00O00Oo = str ( O00O00Oo ) + " secs"
    if 4 - 4: i1IIi + OoOoOO00 + iIii1I11I1II1 - i1IIi * i11iIiiIii
  else :
   O00O00Oo = str ( O00O00Oo ) + " secs"
   if 99 - 99: I1ii11iIi11i - O0 % II111iiii + ooOoO0o % OoO0O00 * Ii1I
  return ( O00O00Oo )
  if 8 - 8: OOooOOo
  if 85 - 85: O0 % OOooOOo . Ii1I
 def has_ttl_elapsed ( self ) :
  if ( self . map_cache_ttl == None ) : return ( False )
  Oo = time . time ( ) - self . last_refresh_time
  return ( Oo >= self . map_cache_ttl )
  if 74 - 74: I1ii11iIi11i - I1Ii111 + i11iIiiIii / I1Ii111 / OoooooooOO + o0oOOo0O0Ooo
  if 23 - 23: Oo0Ooo
 def is_active ( self ) :
  if ( self . stats . last_increment == None ) : return ( False )
  Oo = time . time ( ) - self . stats . last_increment
  return ( Oo <= 60 )
  if 91 - 91: I1Ii111
  if 59 - 59: i1IIi % OOooOOo
 def match_eid_tuple ( self , db ) :
  if ( self . eid . is_exact_match ( db . eid ) == False ) : return ( False )
  if ( self . group . is_exact_match ( db . group ) == False ) : return ( False )
  return ( True )
  if 81 - 81: i11iIiiIii / OoO0O00 * OoOoOO00 % iII111i - iIii1I11I1II1 + I1ii11iIi11i
  if 20 - 20: O0 . I1Ii111 * Ii1I * II111iiii
 def sort_rloc_set ( self ) :
  self . rloc_set . sort ( key = operator . attrgetter ( 'rloc.address' ) )
  if 66 - 66: Ii1I % OoO0O00 % II111iiii - OOooOOo * o0oOOo0O0Ooo
  if 33 - 33: OoooooooOO / I11i
 def delete_rlocs_from_rloc_probe_list ( self ) :
  for Oo0O0 in self . best_rloc_set :
   Oo0O0 . delete_from_rloc_probe_list ( self . eid , self . group )
   if 98 - 98: I1ii11iIi11i . Ii1I . iIii1I11I1II1 * I1ii11iIi11i / Ii1I
   if 74 - 74: Oo0Ooo * I1Ii111
   if 72 - 72: OoOoOO00 + O0 - IiII * ooOoO0o
 def build_best_rloc_set ( self ) :
  ii1Ii1ii11 = self . best_rloc_set
  self . best_rloc_set = [ ]
  if ( self . rloc_set == None ) : return
  if 100 - 100: ooOoO0o / I1IiiI
  if 69 - 69: ooOoO0o + OoO0O00 * o0oOOo0O0Ooo - ooOoO0o
  if 66 - 66: OoooooooOO / iII111i / I1IiiI % ooOoO0o / OoO0O00 + OOooOOo
  if 64 - 64: i1IIi
  IIiI = 256
  for Oo0O0 in self . rloc_set :
   if ( Oo0O0 . up_state ( ) ) : IIiI = min ( Oo0O0 . priority , IIiI )
   if 50 - 50: I1IiiI + Ii1I . IiII * ooOoO0o % I1Ii111
   if 4 - 4: i1IIi - ooOoO0o
   if 14 - 14: i1IIi . OoOoOO00 % I1IiiI / iII111i * i11iIiiIii + O0
   if 10 - 10: o0oOOo0O0Ooo + OoO0O00 + Ii1I / OoO0O00
   if 34 - 34: I1IiiI - I1ii11iIi11i . o0oOOo0O0Ooo
   if 88 - 88: i1IIi . I1IiiI - I11i % OoooooooOO / OoOoOO00 + OoOoOO00
   if 32 - 32: o0oOOo0O0Ooo * O0
   if 65 - 65: Oo0Ooo + i1IIi + OoooooooOO % o0oOOo0O0Ooo
   if 4 - 4: I1IiiI
   if 74 - 74: oO0o / i11iIiiIii + Oo0Ooo
  for Oo0O0 in self . rloc_set :
   if ( Oo0O0 . priority <= IIiI ) :
    if ( Oo0O0 . unreach_state ( ) and Oo0O0 . last_rloc_probe == None ) :
     Oo0O0 . last_rloc_probe = lisp_get_timestamp ( )
     if 99 - 99: I1Ii111 . II111iiii * IiII . II111iiii + OoOoOO00
    self . best_rloc_set . append ( Oo0O0 )
    if 36 - 36: OoO0O00 * iII111i % ooOoO0o % OoOoOO00 * I1IiiI % i1IIi
    if 25 - 25: iII111i + I1IiiI / OoO0O00 - I1IiiI / OoooooooOO - ooOoO0o
    if 22 - 22: iII111i
    if 30 - 30: OoO0O00 + I11i + Oo0Ooo
    if 77 - 77: II111iiii
    if 92 - 92: I1Ii111 / I1IiiI / I1ii11iIi11i + I11i + Ii1I
    if 51 - 51: OOooOOo
    if 85 - 85: II111iiii
  for Oo0O0 in ii1Ii1ii11 :
   if ( Oo0O0 . priority < IIiI ) : continue
   Oo0O0 . delete_from_rloc_probe_list ( self . eid , self . group )
   if 60 - 60: Ii1I * OOooOOo - o0oOOo0O0Ooo - Ii1I / Oo0Ooo . OOooOOo
  for Oo0O0 in self . best_rloc_set :
   if ( Oo0O0 . rloc . is_null ( ) ) : continue
   Oo0O0 . add_to_rloc_probe_list ( self . eid , self . group )
   if 43 - 43: II111iiii * o0oOOo0O0Ooo % o0oOOo0O0Ooo + iIii1I11I1II1 + OoOoOO00
   if 54 - 54: II111iiii + OOooOOo * Oo0Ooo * I1Ii111 - o0oOOo0O0Ooo % Ii1I
   if 69 - 69: I11i + OoOoOO00 - i11iIiiIii * O0 % O0
 def select_rloc ( self , lisp_packet , ipc_socket ) :
  iIIi1 = lisp_packet . packet
  O00Oo000 = lisp_packet . inner_version
  Oooo = len ( self . best_rloc_set )
  if ( Oooo is 0 ) :
   self . stats . increment ( len ( iIIi1 ) )
   return ( [ None , None , None , self . action , None ] )
   if 29 - 29: iIii1I11I1II1 / i11iIiiIii + Oo0Ooo
   if 99 - 99: I1IiiI - iII111i * Ii1I - OoOoOO00 / i11iIiiIii - i1IIi
  iI1ii11ii111 = 4 if lisp_load_split_pings else 0
  I11111ii1i = lisp_packet . hash_ports ( )
  if ( O00Oo000 == 4 ) :
   for ooOooo0OO in range ( 8 + iI1ii11ii111 ) :
    I11111ii1i = I11111ii1i ^ struct . unpack ( "B" , iIIi1 [ ooOooo0OO + 12 ] ) [ 0 ]
    if 55 - 55: I1ii11iIi11i % ooOoO0o % OoOoOO00
  elif ( O00Oo000 == 6 ) :
   for ooOooo0OO in range ( 0 , 32 + iI1ii11ii111 , 4 ) :
    I11111ii1i = I11111ii1i ^ struct . unpack ( "I" , iIIi1 [ ooOooo0OO + 8 : ooOooo0OO + 12 ] ) [ 0 ]
    if 18 - 18: OOooOOo / O0 . OoO0O00 - II111iiii * OOooOOo
   I11111ii1i = ( I11111ii1i >> 16 ) + ( I11111ii1i & 0xffff )
   I11111ii1i = ( I11111ii1i >> 8 ) + ( I11111ii1i & 0xff )
  else :
   for ooOooo0OO in range ( 0 , 12 + iI1ii11ii111 , 4 ) :
    I11111ii1i = I11111ii1i ^ struct . unpack ( "I" , iIIi1 [ ooOooo0OO : ooOooo0OO + 4 ] ) [ 0 ]
    if 13 - 13: OoO0O00 % i1IIi . i11iIiiIii / iII111i
    if 28 - 28: i1IIi - iII111i + o0oOOo0O0Ooo / Oo0Ooo * oO0o
    if 8 - 8: ooOoO0o + OOooOOo * ooOoO0o / i1IIi . I1ii11iIi11i
  if ( lisp_data_plane_logging ) :
   I1iIIiii1 = [ ]
   for o0O in self . best_rloc_set :
    if ( o0O . rloc . is_null ( ) ) : continue
    I1iIIiii1 . append ( [ o0O . rloc . print_address_no_iid ( ) , o0O . print_state ( ) ] )
    if 21 - 21: i1IIi
   dprint ( "Packet hash {}, index {}, best-rloc-list: {}" . format ( hex ( I11111ii1i ) , I11111ii1i % Oooo , red ( str ( I1iIIiii1 ) , False ) ) )
   if 96 - 96: OoOoOO00 * OoOoOO00 % OoO0O00 * iII111i
   if 51 - 51: I1IiiI + i11iIiiIii + iII111i
   if 57 - 57: Oo0Ooo . oO0o
   if 52 - 52: IiII % OoO0O00 - OoO0O00 . I1IiiI + OoO0O00 * ooOoO0o
   if 44 - 44: iIii1I11I1II1 / Ii1I - oO0o % i11iIiiIii
   if 65 - 65: I1ii11iIi11i * Oo0Ooo / Ii1I . OOooOOo * iIii1I11I1II1 + Oo0Ooo
  Oo0O0 = self . best_rloc_set [ I11111ii1i % Oooo ]
  if 44 - 44: ooOoO0o * iII111i * IiII % o0oOOo0O0Ooo
  if 45 - 45: OoOoOO00 % o0oOOo0O0Ooo + IiII / i11iIiiIii
  if 29 - 29: iIii1I11I1II1 . OoO0O00 / I1IiiI
  if 38 - 38: Oo0Ooo / Oo0Ooo % ooOoO0o
  if 56 - 56: oO0o / iII111i % i1IIi * II111iiii . Ii1I
  oooOo00 = lisp_get_echo_nonce ( Oo0O0 . rloc , None )
  if ( oooOo00 ) :
   oooOo00 . change_state ( Oo0O0 )
   if ( Oo0O0 . no_echoed_nonce_state ( ) ) :
    oooOo00 . request_nonce_sent = None
    if 10 - 10: ooOoO0o - I1ii11iIi11i
    if 82 - 82: o0oOOo0O0Ooo / I11i - I11i / O0 * I1IiiI / OoO0O00
    if 71 - 71: I11i % I11i - i11iIiiIii + iIii1I11I1II1 / iII111i
    if 63 - 63: O0 * i11iIiiIii / IiII / IiII
    if 72 - 72: i11iIiiIii * OoOoOO00 % oO0o / I1Ii111
    if 9 - 9: iIii1I11I1II1 . IiII
  if ( Oo0O0 . up_state ( ) == False ) :
   ii11I = I11111ii1i % Oooo
   oooO0 = ( ii11I + 1 ) % Oooo
   while ( oooO0 != ii11I ) :
    Oo0O0 = self . best_rloc_set [ oooO0 ]
    if ( Oo0O0 . up_state ( ) ) : break
    oooO0 = ( oooO0 + 1 ) % Oooo
    if 9 - 9: I11i % i1IIi / i1IIi / OoO0O00
   if ( oooO0 == ii11I ) :
    self . build_best_rloc_set ( )
    return ( [ None , None , None , None , None ] )
    if 46 - 46: I1Ii111 * II111iiii + II111iiii * O0 % II111iiii
    if 37 - 37: OOooOOo . iIii1I11I1II1 / O0 . ooOoO0o + OOooOOo - OoooooooOO
    if 96 - 96: I1Ii111 / oO0o . I1ii11iIi11i % I1IiiI * OOooOOo
    if 99 - 99: i11iIiiIii - I1Ii111
    if 4 - 4: o0oOOo0O0Ooo - i11iIiiIii . iIii1I11I1II1 . OOooOOo % IiII
    if 68 - 68: I11i / iII111i - IiII . iIii1I11I1II1 / o0oOOo0O0Ooo
  Oo0O0 . stats . increment ( len ( iIIi1 ) )
  if 54 - 54: II111iiii * I1IiiI
  if 49 - 49: I1ii11iIi11i
  if 31 - 31: o0oOOo0O0Ooo - OoOoOO00 + I1ii11iIi11i . oO0o - O0
  if 61 - 61: I1ii11iIi11i * II111iiii . i1IIi
  if ( Oo0O0 . rle_name and Oo0O0 . rle == None ) :
   if ( lisp_rle_list . has_key ( Oo0O0 . rle_name ) ) :
    Oo0O0 . rle = lisp_rle_list [ Oo0O0 . rle_name ]
    if 60 - 60: OoooooooOO % ooOoO0o * i11iIiiIii * OoooooooOO % IiII
    if 15 - 15: oO0o
  if ( Oo0O0 . rle ) : return ( [ None , None , None , None , Oo0O0 . rle ] )
  if 40 - 40: I1Ii111
  if 77 - 77: II111iiii - o0oOOo0O0Ooo . Ii1I
  if 47 - 47: o0oOOo0O0Ooo % OOooOOo + I1Ii111
  if 64 - 64: ooOoO0o / IiII . I1IiiI
  if ( Oo0O0 . elp and Oo0O0 . elp . use_elp_node ) :
   return ( [ Oo0O0 . elp . use_elp_node . address , None , None , None , None ] )
   if 77 - 77: o0oOOo0O0Ooo % I1Ii111 . OOooOOo
   if 90 - 90: I11i
   if 53 - 53: I1ii11iIi11i + i11iIiiIii / iIii1I11I1II1 + OoooooooOO + IiII * I1IiiI
   if 16 - 16: i11iIiiIii - oO0o . i11iIiiIii + OoO0O00 + i11iIiiIii
   if 85 - 85: I1ii11iIi11i - ooOoO0o + I1Ii111 + I1Ii111
  iiiII = None if ( Oo0O0 . rloc . is_null ( ) ) else Oo0O0 . rloc
  i1I1IIIi11I = Oo0O0 . translated_port
  iiIiiIii1IiI = self . action if ( iiiII == None ) else None
  if 55 - 55: Oo0Ooo * IiII . o0oOOo0O0Ooo
  if 26 - 26: i1IIi
  if 20 - 20: OoooooooOO . O0 * OoOoOO00 + i11iIiiIii
  if 24 - 24: OoooooooOO - iII111i
  if 87 - 87: OOooOOo + iII111i % Oo0Ooo
  I11iIi1i1I1i1 = None
  if ( oooOo00 and oooOo00 . request_nonce_timeout ( ) == False ) :
   I11iIi1i1I1i1 = oooOo00 . get_request_or_echo_nonce ( ipc_socket , iiiII )
   if 90 - 90: IiII * OoooooooOO - IiII * Oo0Ooo / I1IiiI / II111iiii
   if 81 - 81: I11i * oO0o
   if 51 - 51: I1IiiI
   if 35 - 35: OOooOOo % oO0o
   if 73 - 73: II111iiii / i11iIiiIii
  return ( [ iiiII , i1I1IIIi11I , I11iIi1i1I1i1 , iiIiiIii1IiI , None ] )
  if 91 - 91: OOooOOo
  if 92 - 92: o0oOOo0O0Ooo % o0oOOo0O0Ooo + I1IiiI
 def do_rloc_sets_match ( self , rloc_address_set ) :
  if ( len ( self . rloc_set ) != len ( rloc_address_set ) ) : return ( False )
  if 35 - 35: oO0o + iII111i + I11i - I1ii11iIi11i - ooOoO0o - OOooOOo
  if 77 - 77: OoooooooOO + OoooooooOO / oO0o * o0oOOo0O0Ooo / I11i
  if 86 - 86: I1IiiI % IiII - IiII
  if 1 - 1: o0oOOo0O0Ooo + OoOoOO00 / OOooOOo % IiII
  if 16 - 16: IiII . I11i * O0 + OoooooooOO
  for OOO0OOO000oOO0 in self . rloc_set :
   for Oo0O0 in rloc_address_set :
    if ( Oo0O0 . is_exact_match ( OOO0OOO000oOO0 . rloc ) == False ) : continue
    Oo0O0 = None
    break
    if 37 - 37: OoO0O00 . i11iIiiIii - i11iIiiIii % I1Ii111 + II111iiii * i11iIiiIii
   if ( Oo0O0 == rloc_address_set [ - 1 ] ) : return ( False )
   if 83 - 83: OOooOOo % O0 - I11i . Ii1I % IiII
  return ( True )
  if 45 - 45: I11i % OoO0O00
  if 18 - 18: Ii1I / Ii1I * IiII
 def get_rloc ( self , rloc ) :
  for OOO0OOO000oOO0 in self . rloc_set :
   o0O = OOO0OOO000oOO0 . rloc
   if ( rloc . is_exact_match ( o0O ) ) : return ( OOO0OOO000oOO0 )
   if 33 - 33: ooOoO0o
  return ( None )
  if 14 - 14: Oo0Ooo % I1Ii111 % ooOoO0o . oO0o * iIii1I11I1II1 . I1ii11iIi11i
  if 50 - 50: O0 * i11iIiiIii / iIii1I11I1II1 . I11i + i11iIiiIii
 def get_rloc_by_interface ( self , interface ) :
  for OOO0OOO000oOO0 in self . rloc_set :
   if ( OOO0OOO000oOO0 . interface == interface ) : return ( OOO0OOO000oOO0 )
   if 68 - 68: oO0o + o0oOOo0O0Ooo * iIii1I11I1II1 / i1IIi
  return ( None )
  if 9 - 9: I11i % OoO0O00 . oO0o / I1ii11iIi11i
  if 88 - 88: Oo0Ooo / IiII / II111iiii / I1ii11iIi11i + OoooooooOO
 def add_db ( self ) :
  if ( self . group . is_null ( ) ) :
   lisp_db_for_lookups . add_cache ( self . eid , self )
  else :
   iIiIi = lisp_db_for_lookups . lookup_cache ( self . group , True )
   if ( iIiIi == None ) :
    iIiIi = lisp_mapping ( self . group , self . group , [ ] )
    lisp_db_for_lookups . add_cache ( self . group , iIiIi )
    if 65 - 65: iII111i % oO0o * IiII
   iIiIi . add_source_entry ( self )
   if 16 - 16: iII111i % I11i % OoOoOO00
   if 80 - 80: OoooooooOO * i11iIiiIii % oO0o / Oo0Ooo - I1ii11iIi11i
   if 92 - 92: o0oOOo0O0Ooo % i1IIi / I1Ii111 % ooOoO0o / oO0o
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
    if 2 - 2: i11iIiiIii / Ii1I - i1IIi % O0
   if ( self . eid . is_null ( ) ) : self . eid . make_default_route ( oOooO0Oo0Oo0 . group )
   oOooO0Oo0Oo0 . add_source_entry ( self )
   if 12 - 12: Oo0Ooo + I1ii11iIi11i
  if ( do_ipc ) : lisp_write_ipc_map_cache ( True , self )
  if 54 - 54: OoO0O00 . o0oOOo0O0Ooo / I11i
  if 95 - 95: i1IIi . I1Ii111
 def delete_cache ( self ) :
  self . delete_rlocs_from_rloc_probe_list ( )
  lisp_write_ipc_map_cache ( False , self )
  if 94 - 94: I1IiiI + Ii1I + i1IIi . iIii1I11I1II1
  if ( self . group . is_null ( ) ) :
   lisp_map_cache . delete_cache ( self . eid )
   if ( lisp_program_hardware ) :
    Oo0OOoO0oo0oO = self . eid . print_prefix_no_iid ( )
    os . system ( "ip route delete {}" . format ( Oo0OOoO0oo0oO ) )
    if 31 - 31: iIii1I11I1II1 + I1IiiI
  else :
   oOooO0Oo0Oo0 = lisp_map_cache . lookup_cache ( self . group , True )
   if ( oOooO0Oo0Oo0 == None ) : return
   if 82 - 82: I1Ii111 / Ii1I % OoooooooOO - IiII / OoooooooOO
   iiII1iIIii = oOooO0Oo0Oo0 . lookup_source_cache ( self . eid , True )
   if ( iiII1iIIii == None ) : return
   if 37 - 37: I11i . i11iIiiIii / Oo0Ooo . o0oOOo0O0Ooo / I1IiiI . OOooOOo
   oOooO0Oo0Oo0 . source_cache . delete_cache ( self . eid )
   if ( oOooO0Oo0Oo0 . source_cache . cache_size ( ) == 0 ) :
    lisp_map_cache . delete_cache ( self . group )
    if 10 - 10: I11i - OoOoOO00
    if 49 - 49: I1ii11iIi11i / II111iiii - ooOoO0o / I1Ii111 - oO0o
    if 91 - 91: iII111i % Ii1I . IiII + ooOoO0o % i1IIi . II111iiii
    if 19 - 19: OoooooooOO + I1IiiI % Ii1I % II111iiii + o0oOOo0O0Ooo
 def add_source_entry ( self , source_mc ) :
  if ( self . source_cache == None ) : self . source_cache = lisp_cache ( )
  self . source_cache . add_cache ( source_mc . eid , source_mc )
  if 91 - 91: IiII
  if 36 - 36: ooOoO0o - OoOoOO00 . iIii1I11I1II1 / oO0o % OoooooooOO * iII111i
 def lookup_source_cache ( self , source , exact ) :
  if ( self . source_cache == None ) : return ( None )
  return ( self . source_cache . lookup_cache ( source , exact ) )
  if 42 - 42: oO0o
  if 71 - 71: i11iIiiIii . I1Ii111 % OoO0O00 % I1IiiI
 def dynamic_eid_configured ( self ) :
  return ( self . dynamic_eids != None )
  if 46 - 46: IiII + oO0o - ooOoO0o
  if 2 - 2: i1IIi / Ii1I % OoO0O00
 def star_secondary_iid ( self , prefix ) :
  if ( self . secondary_iid == None ) : return ( prefix )
  iiI1iii = "," + str ( self . secondary_iid )
  return ( prefix . replace ( iiI1iii , iiI1iii + "*" ) )
  if 85 - 85: i1IIi % iIii1I11I1II1
  if 10 - 10: O0 . oO0o * I1IiiI
 def increment_decap_stats ( self , packet ) :
  i1I1IIIi11I = packet . udp_dport
  if ( i1I1IIIi11I == LISP_DATA_PORT ) :
   Oo0O0 = self . get_rloc ( packet . outer_dest )
  else :
   if 21 - 21: OoooooooOO
   if 76 - 76: i1IIi * i11iIiiIii / OOooOOo + I1Ii111
   if 50 - 50: oO0o % OoOoOO00 + I1IiiI
   if 15 - 15: II111iiii - iII111i / I1ii11iIi11i
   for Oo0O0 in self . rloc_set :
    if ( Oo0O0 . translated_port != 0 ) : break
    if 81 - 81: Ii1I - i1IIi % oO0o * Oo0Ooo * OoOoOO00
    if 79 - 79: oO0o + I1IiiI % iII111i + II111iiii % OoO0O00 % iII111i
  if ( Oo0O0 != None ) : Oo0O0 . stats . increment ( len ( packet . packet ) )
  self . stats . increment ( len ( packet . packet ) )
  if 46 - 46: o0oOOo0O0Ooo
  if 61 - 61: OoO0O00 . O0 + I1ii11iIi11i + OoO0O00
 def rtrs_in_rloc_set ( self ) :
  for Oo0O0 in self . rloc_set :
   if ( Oo0O0 . is_rtr ( ) ) : return ( True )
   if 44 - 44: I11i . oO0o
  return ( False )
  if 65 - 65: I1ii11iIi11i * II111iiii % I11i + II111iiii . i1IIi / ooOoO0o
  if 74 - 74: OoOoOO00 % OoO0O00 . OoOoOO00
  if 16 - 16: OoO0O00 / Ii1I * i11iIiiIii / o0oOOo0O0Ooo + I1Ii111
class lisp_dynamic_eid ( ) :
 def __init__ ( self ) :
  self . dynamic_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . uptime = lisp_get_timestamp ( )
  self . interface = None
  self . last_packet = None
  self . timeout = LISP_DEFAULT_DYN_EID_TIMEOUT
  if 21 - 21: I11i % I1ii11iIi11i
  if 8 - 8: OOooOOo % OoO0O00 + O0 - o0oOOo0O0Ooo
 def get_timeout ( self , interface ) :
  try :
   IIIOo0oo00 = lisp_myinterfaces [ interface ]
   self . timeout = IIIOo0oo00 . dynamic_eid_timeout
  except :
   self . timeout = LISP_DEFAULT_DYN_EID_TIMEOUT
   if 64 - 64: Ii1I / I1IiiI + ooOoO0o
   if 4 - 4: II111iiii - Ii1I
   if 77 - 77: IiII - ooOoO0o + O0 * IiII
   if 87 - 87: oO0o % OoO0O00 . iIii1I11I1II1 * ooOoO0o + oO0o + IiII
class lisp_group_mapping ( ) :
 def __init__ ( self , group_name , ms_name , group_prefix , sources , rle_addr ) :
  self . group_name = group_name
  self . group_prefix = group_prefix
  self . use_ms_name = ms_name
  self . sources = sources
  self . rle_address = rle_addr
  if 74 - 74: i1IIi % i1IIi + Oo0Ooo
  if 48 - 48: iII111i . i11iIiiIii + i11iIiiIii
 def add_group ( self ) :
  lisp_group_mapping_list [ self . group_name ] = self
  if 56 - 56: OoooooooOO
  if 52 - 52: O0 - I1Ii111 + oO0o % ooOoO0o . oO0o
  if 60 - 60: oO0o + o0oOOo0O0Ooo - OOooOOo % o0oOOo0O0Ooo . I11i + OoO0O00
lisp_site_flags = {
 "P" : "ETR is {}Requesting Map-Server to Proxy Map-Reply" ,
 "S" : "ETR is {}LISP-SEC capable" ,
 "I" : "xTR-ID and site-ID are {}included in Map-Register" ,
 "T" : "Use Map-Register TTL field to timeout registration is {}set" ,
 "R" : "Merging registrations are {}requested" ,
 "M" : "ETR is {}a LISP Mobile-Node" ,
 "N" : "ETR is {}requesting Map-Notify messages from Map-Server"
 }
if 27 - 27: i11iIiiIii - I1ii11iIi11i * I1Ii111 . I1IiiI / OoO0O00 * ooOoO0o
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
  if 42 - 42: OOooOOo
  if 36 - 36: OoooooooOO + ooOoO0o + iII111i
  if 30 - 30: i1IIi % Ii1I
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
  if 18 - 18: o0oOOo0O0Ooo % I1ii11iIi11i . Ii1I . O0 * II111iiii + I1ii11iIi11i
  if 45 - 45: OoO0O00 / I1ii11iIi11i * ooOoO0o * OOooOOo % i11iIiiIii * iII111i
 def print_eid_tuple ( self ) :
  return ( lisp_print_eid_tuple ( self . eid , self . group ) )
  if 33 - 33: oO0o . iII111i + Oo0Ooo
  if 33 - 33: ooOoO0o
 def print_flags ( self , html ) :
  if ( html == False ) :
   OOoo0oo = "{}-{}-{}-{}-{}-{}-{}" . format ( "P" if self . proxy_reply_requested else "p" ,
   # II111iiii - o0oOOo0O0Ooo + iII111i
 "S" if self . lisp_sec_present else "s" ,
 "I" if self . xtr_id_present else "i" ,
 "T" if self . use_register_ttl_requested else "t" ,
 "R" if self . merge_register_requested else "r" ,
 "M" if self . mobile_node_requested else "m" ,
 "N" if self . map_notify_requested else "n" )
  else :
   iIiiiiII11 = self . print_flags ( False )
   iIiiiiII11 = iIiiiiII11 . split ( "-" )
   OOoo0oo = ""
   for iI1i1iiI in iIiiiiII11 :
    iiiiIi1iiIiIi = lisp_site_flags [ iI1i1iiI . upper ( ) ]
    iiiiIi1iiIiIi = iiiiIi1iiIiIi . format ( "" if iI1i1iiI . isupper ( ) else "not " )
    OOoo0oo += lisp_span ( iI1i1iiI , iiiiIi1iiIiIi )
    if ( iI1i1iiI . lower ( ) != "n" ) : OOoo0oo += "-"
    if 3 - 3: II111iiii . I1IiiI
    if 71 - 71: iIii1I11I1II1 - IiII
  return ( OOoo0oo )
  if 3 - 3: oO0o * II111iiii . O0
  if 19 - 19: I1IiiI / I1IiiI / Oo0Ooo + oO0o + i1IIi
 def copy_state_to_parent ( self , child ) :
  self . xtr_id = child . xtr_id
  self . site_id = child . site_id
  self . first_registered = child . first_registered
  self . last_registered = child . last_registered
  self . last_registerer = child . last_registerer
  self . register_ttl = child . register_ttl
  if ( self . registered == False ) :
   self . first_registered = lisp_get_timestamp ( )
   if 31 - 31: iII111i / OoooooooOO - I1Ii111 . iII111i
  self . auth_sha1_or_sha2 = child . auth_sha1_or_sha2
  self . registered = child . registered
  self . proxy_reply_requested = child . proxy_reply_requested
  self . lisp_sec_present = child . lisp_sec_present
  self . xtr_id_present = child . xtr_id_present
  self . use_register_ttl_requested = child . use_register_ttl_requested
  self . merge_register_requested = child . merge_register_requested
  self . mobile_node_requested = child . mobile_node_requested
  self . map_notify_requested = child . map_notify_requested
  if 38 - 38: ooOoO0o . OoooooooOO - II111iiii * i11iIiiIii / i1IIi . OoooooooOO
  if 51 - 51: oO0o - I1ii11iIi11i + I1ii11iIi11i
 def build_sort_key ( self ) :
  o0oOo0oo = lisp_cache ( )
  oOOoOO , o0000oO = o0oOo0oo . build_key ( self . eid )
  ooOO0o000 = ""
  if ( self . group . is_null ( ) == False ) :
   ii1iiI1i1Ii1 , ooOO0o000 = o0oOo0oo . build_key ( self . group )
   ooOO0o000 = "-" + ooOO0o000 [ 0 : 12 ] + "-" + str ( ii1iiI1i1Ii1 ) + "-" + ooOO0o000 [ 12 : : ]
   if 47 - 47: OoooooooOO * iIii1I11I1II1
  o0000oO = o0000oO [ 0 : 12 ] + "-" + str ( oOOoOO ) + "-" + o0000oO [ 12 : : ] + ooOO0o000
  del ( o0oOo0oo )
  return ( o0000oO )
  if 65 - 65: oO0o * OoooooooOO . OOooOOo
  if 75 - 75: o0oOOo0O0Ooo % iII111i
 def merge_in_site_eid ( self , child ) :
  Ii1I1 = False
  if ( self . group . is_null ( ) ) :
   self . merge_rlocs_in_site_eid ( )
  else :
   Ii1I1 = self . merge_rles_in_site_eid ( )
   if 23 - 23: Ii1I + i1IIi + IiII - O0 / OOooOOo
   if 82 - 82: I1Ii111
   if 78 - 78: I1Ii111 % oO0o * iIii1I11I1II1
   if 1 - 1: i1IIi . iIii1I11I1II1
   if 2 - 2: OOooOOo % Oo0Ooo * OOooOOo + I1Ii111 % OoOoOO00 / O0
   if 23 - 23: O0 * oO0o / I1IiiI + i1IIi * O0 % oO0o
  if ( child != None ) :
   self . copy_state_to_parent ( child )
   self . map_registers_received += 1
   if 11 - 11: I1Ii111 . OoooooooOO * iIii1I11I1II1 / I1ii11iIi11i - ooOoO0o . iII111i
  return ( Ii1I1 )
  if 71 - 71: i11iIiiIii + I11i / i11iIiiIii % Oo0Ooo / iIii1I11I1II1 * OoO0O00
  if 49 - 49: iII111i + OoOoOO00
 def copy_rloc_records ( self ) :
  iii11111111II = [ ]
  for OOO0OOO000oOO0 in self . registered_rlocs :
   iii11111111II . append ( copy . deepcopy ( OOO0OOO000oOO0 ) )
   if 58 - 58: o0oOOo0O0Ooo
  return ( iii11111111II )
  if 5 - 5: O0
  if 23 - 23: OOooOOo . i11iIiiIii % o0oOOo0O0Ooo - OoOoOO00 * OoooooooOO - OoO0O00
 def merge_rlocs_in_site_eid ( self ) :
  self . registered_rlocs = [ ]
  for o0O0oOo in self . individual_registrations . values ( ) :
   if ( self . site_id != o0O0oOo . site_id ) : continue
   if ( o0O0oOo . registered == False ) : continue
   self . registered_rlocs += o0O0oOo . copy_rloc_records ( )
   if 51 - 51: iIii1I11I1II1 / I1ii11iIi11i
   if 83 - 83: ooOoO0o % I1IiiI - OoOoOO00 - I11i
   if 12 - 12: I1Ii111 . OoO0O00 + I11i * OoO0O00 - IiII + I11i
   if 98 - 98: iII111i . I1Ii111 * IiII - Ii1I * OoooooooOO
   if 13 - 13: iII111i
   if 76 - 76: iIii1I11I1II1 + Oo0Ooo
  iii11111111II = [ ]
  for OOO0OOO000oOO0 in self . registered_rlocs :
   if ( OOO0OOO000oOO0 . rloc . is_null ( ) or len ( iii11111111II ) == 0 ) :
    iii11111111II . append ( OOO0OOO000oOO0 )
    continue
    if 40 - 40: oO0o % i1IIi % ooOoO0o . oO0o % oO0o
   for OoIiII1 in iii11111111II :
    if ( OoIiII1 . rloc . is_null ( ) ) : continue
    if ( OOO0OOO000oOO0 . rloc . is_exact_match ( OoIiII1 . rloc ) ) : break
    if 36 - 36: o0oOOo0O0Ooo . o0oOOo0O0Ooo / oO0o * ooOoO0o * Ii1I * IiII
   if ( OoIiII1 == iii11111111II [ - 1 ] ) : iii11111111II . append ( OOO0OOO000oOO0 )
   if 39 - 39: i1IIi
  self . registered_rlocs = iii11111111II
  if 79 - 79: ooOoO0o - II111iiii - oO0o
  if 55 - 55: iII111i % iIii1I11I1II1 + Ii1I + oO0o . i11iIiiIii - OOooOOo
  if 14 - 14: oO0o - i11iIiiIii / OoOoOO00 % o0oOOo0O0Ooo / IiII * I1IiiI
  if 2 - 2: i1IIi / I1Ii111 + I1IiiI + I1ii11iIi11i - o0oOOo0O0Ooo + iIii1I11I1II1
  if ( len ( self . registered_rlocs ) == 0 ) : self . registered = False
  return
  if 78 - 78: I1ii11iIi11i % i1IIi . I1Ii111 + Oo0Ooo . o0oOOo0O0Ooo % II111iiii
  if 65 - 65: Ii1I . OoOoOO00 + O0 / iIii1I11I1II1 % Ii1I % I1Ii111
 def merge_rles_in_site_eid ( self ) :
  if 31 - 31: o0oOOo0O0Ooo - Oo0Ooo
  if 15 - 15: O0 + OOooOOo
  if 8 - 8: i11iIiiIii . IiII . I1ii11iIi11i + i1IIi % I1Ii111
  if 64 - 64: I1IiiI . Oo0Ooo * OoO0O00
  ooo0o = { }
  for OOO0OOO000oOO0 in self . registered_rlocs :
   if ( OOO0OOO000oOO0 . rle == None ) : continue
   for iIiiI11iI111 in OOO0OOO000oOO0 . rle . rle_nodes :
    o00Ooo0 = iIiiI11iI111 . address . print_address_no_iid ( )
    ooo0o [ o00Ooo0 ] = iIiiI11iI111 . address
    if 29 - 29: O0 . ooOoO0o - ooOoO0o * i1IIi * I1IiiI - Oo0Ooo
   break
   if 28 - 28: OoooooooOO . i1IIi . I1Ii111
   if 53 - 53: OoO0O00 * Oo0Ooo + Oo0Ooo
   if 62 - 62: OOooOOo - i1IIi + i11iIiiIii * I11i / OoO0O00
   if 84 - 84: IiII * OOooOOo
   if 1 - 1: iII111i * I1IiiI . o0oOOo0O0Ooo . IiII
  self . merge_rlocs_in_site_eid ( )
  if 6 - 6: OOooOOo . oO0o / Oo0Ooo / o0oOOo0O0Ooo
  if 24 - 24: Oo0Ooo % OoooooooOO
  if 78 - 78: OoooooooOO - II111iiii . OoO0O00 / I1ii11iIi11i
  if 86 - 86: OOooOOo * OoOoOO00 % i1IIi * IiII . I1ii11iIi11i
  if 72 - 72: i1IIi - I1Ii111 . O0 * OoO0O00
  if 62 - 62: Oo0Ooo . iII111i
  if 15 - 15: i11iIiiIii * I11i + oO0o
  if 67 - 67: IiII . OoO0O00
  oOO0oO0o0oOoO = [ ]
  for OOO0OOO000oOO0 in self . registered_rlocs :
   if ( self . registered_rlocs . index ( OOO0OOO000oOO0 ) == 0 ) :
    oOO0oO0o0oOoO . append ( OOO0OOO000oOO0 )
    continue
    if 30 - 30: II111iiii / II111iiii
   if ( OOO0OOO000oOO0 . rle == None ) : oOO0oO0o0oOoO . append ( OOO0OOO000oOO0 )
   if 70 - 70: OoO0O00 + O0 * OoO0O00
  self . registered_rlocs = oOO0oO0o0oOoO
  if 25 - 25: OoooooooOO . Oo0Ooo + OOooOOo + Oo0Ooo * O0 % i1IIi
  if 71 - 71: II111iiii / Ii1I + i1IIi - OoOoOO00 + Ii1I
  if 31 - 31: OoooooooOO * Ii1I - iII111i . oO0o % Ii1I
  if 97 - 97: Ii1I
  if 51 - 51: II111iiii . oO0o % iII111i
  if 47 - 47: II111iiii - iII111i * I1IiiI . IiII
  if 41 - 41: OoOoOO00 / O0 + I1Ii111 . I1ii11iIi11i
  oO = lisp_rle ( "" )
  I11oO = { }
  i11Ii1i1iII = None
  for o0O0oOo in self . individual_registrations . values ( ) :
   if ( o0O0oOo . registered == False ) : continue
   iI1II11IIi1ii = o0O0oOo . registered_rlocs [ 0 ] . rle
   if ( iI1II11IIi1ii == None ) : continue
   if 36 - 36: i11iIiiIii
   i11Ii1i1iII = o0O0oOo . registered_rlocs [ 0 ] . rloc_name
   for iIIi1Iii1Ii in iI1II11IIi1ii . rle_nodes :
    o00Ooo0 = iIIi1Iii1Ii . address . print_address_no_iid ( )
    if ( I11oO . has_key ( o00Ooo0 ) ) : break
    if 13 - 13: Ii1I + O0 % o0oOOo0O0Ooo % Oo0Ooo / i1IIi . II111iiii
    iIiiI11iI111 = lisp_rle_node ( )
    iIiiI11iI111 . address . copy_address ( iIIi1Iii1Ii . address )
    iIiiI11iI111 . level = iIIi1Iii1Ii . level
    iIiiI11iI111 . rloc_name = i11Ii1i1iII
    oO . rle_nodes . append ( iIiiI11iI111 )
    I11oO [ o00Ooo0 ] = iIIi1Iii1Ii . address
    if 23 - 23: I1ii11iIi11i . Oo0Ooo . iII111i % i1IIi
    if 56 - 56: iIii1I11I1II1 * i11iIiiIii % O0 * Ii1I % I1Ii111 % I11i
    if 65 - 65: I1ii11iIi11i . I1IiiI . II111iiii . ooOoO0o - o0oOOo0O0Ooo
    if 34 - 34: OoooooooOO - iII111i * iIii1I11I1II1 . OoO0O00
    if 75 - 75: i11iIiiIii - oO0o % I1Ii111
    if 19 - 19: oO0o . I1Ii111 - IiII * IiII - OoOoOO00 % iIii1I11I1II1
  if ( len ( oO . rle_nodes ) == 0 ) : oO = None
  if ( len ( self . registered_rlocs ) != 0 ) :
   self . registered_rlocs [ 0 ] . rle = oO
   if ( i11Ii1i1iII ) : self . registered_rlocs [ 0 ] . rloc_name = None
   if 77 - 77: II111iiii + OOooOOo % iII111i * O0 % i1IIi / I1Ii111
   if 39 - 39: II111iiii % OoOoOO00 / O0 / II111iiii
   if 15 - 15: I11i + I1IiiI / I11i + iIii1I11I1II1 * Oo0Ooo / I1ii11iIi11i
   if 8 - 8: ooOoO0o . O0 / OoO0O00
   if 50 - 50: Ii1I . OoOoOO00 * o0oOOo0O0Ooo
  if ( ooo0o . keys ( ) == I11oO . keys ( ) ) : return ( False )
  if 68 - 68: IiII * oO0o / OoOoOO00 / I1Ii111
  lprint ( "{} {} from {} to {}" . format ( green ( self . print_eid_tuple ( ) , False ) , bold ( "RLE change" , False ) ,
  # I1ii11iIi11i . OOooOOo % I1Ii111 * iIii1I11I1II1 / I1ii11iIi11i
 ooo0o . keys ( ) , I11oO . keys ( ) ) )
  if 62 - 62: I1IiiI * Ii1I * iIii1I11I1II1 % II111iiii
  return ( True )
  if 38 - 38: I1Ii111 - II111iiii - iII111i
  if 43 - 43: i1IIi / I1ii11iIi11i
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
    if 67 - 67: iII111i / IiII + I1IiiI + IiII % OoOoOO00 % I1ii11iIi11i
    if 7 - 7: I1ii11iIi11i % OoOoOO00 - O0 . I1Ii111
    if 9 - 9: Ii1I . OoooooooOO / ooOoO0o + i1IIi
    if 90 - 90: oO0o - OoOoOO00 % ooOoO0o
    if 83 - 83: OOooOOo - I1ii11iIi11i + OoO0O00
    oo00oO0 . parent_for_more_specifics = self . parent_for_more_specifics
    if 99 - 99: iII111i - OoOoOO00 % ooOoO0o
   if ( self . eid . is_null ( ) ) : self . eid . make_default_route ( oo00oO0 . group )
   oo00oO0 . add_source_entry ( self )
   if 27 - 27: oO0o . oO0o * iII111i % iIii1I11I1II1
   if 81 - 81: iII111i * II111iiii
   if 28 - 28: i11iIiiIii . Oo0Ooo . Ii1I
 def delete_cache ( self ) :
  if ( self . group . is_null ( ) ) :
   lisp_sites_by_eid . delete_cache ( self . eid )
  else :
   oo00oO0 = lisp_sites_by_eid . lookup_cache ( self . group , True )
   if ( oo00oO0 == None ) : return
   if 19 - 19: OoO0O00 - Ii1I + ooOoO0o + OOooOOo
   o0O0oOo = oo00oO0 . lookup_source_cache ( self . eid , True )
   if ( o0O0oOo == None ) : return
   if 84 - 84: iII111i / Oo0Ooo
   if ( oo00oO0 . source_cache == None ) : return
   if 21 - 21: OoO0O00 . I1IiiI - OoO0O00
   oo00oO0 . source_cache . delete_cache ( self . eid )
   if ( oo00oO0 . source_cache . cache_size ( ) == 0 ) :
    lisp_sites_by_eid . delete_cache ( self . group )
    if 51 - 51: iIii1I11I1II1
    if 5 - 5: oO0o - OoOoOO00 . ooOoO0o
    if 97 - 97: I11i - ooOoO0o + oO0o . I1Ii111
    if 22 - 22: Ii1I - II111iiii % Oo0Ooo * OoOoOO00 + iIii1I11I1II1
 def add_source_entry ( self , source_se ) :
  if ( self . source_cache == None ) : self . source_cache = lisp_cache ( )
  self . source_cache . add_cache ( source_se . eid , source_se )
  if 5 - 5: Oo0Ooo % o0oOOo0O0Ooo * I1Ii111
  if 6 - 6: OOooOOo + o0oOOo0O0Ooo
 def lookup_source_cache ( self , source , exact ) :
  if ( self . source_cache == None ) : return ( None )
  return ( self . source_cache . lookup_cache ( source , exact ) )
  if 41 - 41: OoooooooOO + iIii1I11I1II1 . O0 % I1Ii111 % OOooOOo + I1Ii111
  if 65 - 65: II111iiii . oO0o
 def is_star_g ( self ) :
  if ( self . group . is_null ( ) ) : return ( False )
  return ( self . eid . is_exact_match ( self . group ) )
  if 9 - 9: I1Ii111 . i11iIiiIii * I11i + o0oOOo0O0Ooo
  if 85 - 85: i11iIiiIii * iII111i
 def eid_record_matches ( self , eid_record ) :
  if ( self . eid . is_exact_match ( eid_record . eid ) == False ) : return ( False )
  if ( eid_record . group . is_null ( ) ) : return ( True )
  return ( eid_record . group . is_exact_match ( self . group ) )
  if 43 - 43: Ii1I + iII111i * I1ii11iIi11i * Ii1I
  if 62 - 62: O0
 def inherit_from_ams_parent ( self ) :
  IiIii1 = self . parent_for_more_specifics
  if ( IiIii1 == None ) : return
  self . force_proxy_reply = IiIii1 . force_proxy_reply
  self . force_nat_proxy_reply = IiIii1 . force_nat_proxy_reply
  self . force_ttl = IiIii1 . force_ttl
  self . pitr_proxy_reply_drop = IiIii1 . pitr_proxy_reply_drop
  self . proxy_reply_action = IiIii1 . proxy_reply_action
  self . echo_nonce_capable = IiIii1 . echo_nonce_capable
  self . policy = IiIii1 . policy
  self . require_signature = IiIii1 . require_signature
  if 44 - 44: i1IIi
  if 27 - 27: ooOoO0o - Oo0Ooo + i11iIiiIii - oO0o % O0
 def rtrs_in_rloc_set ( self ) :
  for OOO0OOO000oOO0 in self . registered_rlocs :
   if ( OOO0OOO000oOO0 . is_rtr ( ) ) : return ( True )
   if 68 - 68: iIii1I11I1II1 % Ii1I / I11i
  return ( False )
  if 17 - 17: IiII * Oo0Ooo . i11iIiiIii . IiII . Oo0Ooo % IiII
  if 93 - 93: II111iiii - IiII - O0 - i11iIiiIii / OOooOOo
 def is_rtr_in_rloc_set ( self , rtr_rloc ) :
  for OOO0OOO000oOO0 in self . registered_rlocs :
   if ( OOO0OOO000oOO0 . rloc . is_exact_match ( rtr_rloc ) == False ) : continue
   if ( OOO0OOO000oOO0 . is_rtr ( ) ) : return ( True )
   if 76 - 76: OOooOOo
  return ( False )
  if 31 - 31: OOooOOo + i1IIi / Ii1I / OoOoOO00 % OoO0O00 + Oo0Ooo
  if 84 - 84: i1IIi / i1IIi * oO0o * i11iIiiIii
 def is_rloc_in_rloc_set ( self , rloc ) :
  for OOO0OOO000oOO0 in self . registered_rlocs :
   if ( OOO0OOO000oOO0 . rle ) :
    for oO in OOO0OOO000oOO0 . rle . rle_nodes :
     if ( oO . address . is_exact_match ( rloc ) ) : return ( True )
     if 92 - 92: iII111i - Ii1I . iIii1I11I1II1 . iII111i + ooOoO0o % OoOoOO00
     if 38 - 38: OOooOOo . I11i - oO0o
   if ( OOO0OOO000oOO0 . rloc . is_exact_match ( rloc ) ) : return ( True )
   if 85 - 85: O0 * I1IiiI . Oo0Ooo - IiII
  return ( False )
  if 84 - 84: I1Ii111 . iIii1I11I1II1 . O0 * I1ii11iIi11i
  if 59 - 59: i1IIi . o0oOOo0O0Ooo . Oo0Ooo * I1Ii111 + OoooooooOO
 def do_rloc_sets_match ( self , prev_rloc_set ) :
  if ( len ( self . registered_rlocs ) != len ( prev_rloc_set ) ) : return ( False )
  if 11 - 11: I11i * ooOoO0o % iIii1I11I1II1 - O0
  for OOO0OOO000oOO0 in prev_rloc_set :
   Ii11IIiiI1I = OOO0OOO000oOO0 . rloc
   if ( self . is_rloc_in_rloc_set ( Ii11IIiiI1I ) == False ) : return ( False )
   if 68 - 68: ooOoO0o * OoooooooOO - OoooooooOO
  return ( True )
  if 59 - 59: Ii1I / I11i / I1Ii111 + IiII * I1ii11iIi11i
  if 18 - 18: O0
  if 60 - 60: II111iiii % O0 - I1Ii111 / iII111i / I1IiiI
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
   if 59 - 59: O0 / iIii1I11I1II1
  self . last_used = 0
  self . last_reply = 0
  self . last_nonce = 0
  self . map_requests_sent = 0
  self . neg_map_replies_received = 0
  self . total_rtt = 0
  if 49 - 49: O0 + I1IiiI
  if 52 - 52: oO0o
 def resolve_dns_name ( self ) :
  if ( self . dns_name == None ) : return
  if ( self . last_dns_resolve and
 time . time ( ) - self . last_dns_resolve < 30 ) : return
  if 56 - 56: ooOoO0o
  try :
   oOo00o = socket . gethostbyname_ex ( self . dns_name )
   self . last_dns_resolve = lisp_get_timestamp ( )
   ooO00Ooo0 = oOo00o [ 2 ]
  except :
   return
   if 100 - 100: OoO0O00 % Oo0Ooo - OoooooooOO
   if 48 - 48: IiII / I11i * OoooooooOO
   if 1 - 1: I1ii11iIi11i + I11i
   if 54 - 54: IiII * O0 * I1Ii111 + i1IIi - I11i . I11i
   if 39 - 39: I1Ii111
   if 48 - 48: iIii1I11I1II1 . i11iIiiIii / OoooooooOO . i1IIi . o0oOOo0O0Ooo
  if ( len ( ooO00Ooo0 ) <= self . a_record_index ) :
   self . delete_mr ( )
   return
   if 84 - 84: Ii1I
   if 92 - 92: I11i
  o00Ooo0 = ooO00Ooo0 [ self . a_record_index ]
  if ( o00Ooo0 != self . map_resolver . print_address_no_iid ( ) ) :
   self . delete_mr ( )
   self . map_resolver . store_address ( o00Ooo0 )
   self . insert_mr ( )
   if 64 - 64: iII111i / iII111i * iII111i % O0 / IiII . I1ii11iIi11i
   if 23 - 23: i1IIi / I1ii11iIi11i + o0oOOo0O0Ooo
   if 82 - 82: O0 * ooOoO0o * iIii1I11I1II1 . i1IIi
   if 47 - 47: I11i * I11i . OoOoOO00
   if 68 - 68: OoooooooOO + OoOoOO00 + i11iIiiIii
   if 89 - 89: Oo0Ooo + Ii1I * O0 - I1Ii111
  if ( lisp_is_decent_dns_suffix ( self . dns_name ) == False ) : return
  if ( self . a_record_index != 0 ) : return
  if 33 - 33: iIii1I11I1II1 . I11i
  for o00Ooo0 in ooO00Ooo0 [ 1 : : ] :
   iiiI111I = lisp_address ( LISP_AFI_NONE , o00Ooo0 , 0 , 0 )
   iiIii = lisp_get_map_resolver ( iiiI111I , None )
   if ( iiIii != None and iiIii . a_record_index == ooO00Ooo0 . index ( o00Ooo0 ) ) :
    continue
    if 63 - 63: oO0o - iII111i
   iiIii = lisp_mr ( o00Ooo0 , None , None )
   iiIii . a_record_index = ooO00Ooo0 . index ( o00Ooo0 )
   iiIii . dns_name = self . dns_name
   iiIii . last_dns_resolve = lisp_get_timestamp ( )
   if 13 - 13: I1Ii111 / i1IIi % OoooooooOO / I11i
   if 66 - 66: I1Ii111 % o0oOOo0O0Ooo . iII111i . ooOoO0o + OOooOOo * II111iiii
   if 33 - 33: oO0o
   if 64 - 64: OoO0O00 % Oo0Ooo % I11i . iII111i % I1IiiI
   if 50 - 50: i1IIi + ooOoO0o - iIii1I11I1II1
  iiiI = [ ]
  for iiIii in lisp_map_resolvers_list . values ( ) :
   if ( self . dns_name != iiIii . dns_name ) : continue
   iiiI111I = iiIii . map_resolver . print_address_no_iid ( )
   if ( iiiI111I in ooO00Ooo0 ) : continue
   iiiI . append ( iiIii )
   if 81 - 81: I1Ii111 . Ii1I * ooOoO0o . IiII - OoOoOO00
  for iiIii in iiiI : iiIii . delete_mr ( )
  if 79 - 79: ooOoO0o - O0
  if 56 - 56: ooOoO0o
 def insert_mr ( self ) :
  o0000oO = self . mr_name + self . map_resolver . print_address ( )
  lisp_map_resolvers_list [ o0000oO ] = self
  if 89 - 89: O0 % iIii1I11I1II1 / OoOoOO00 - I1Ii111 - I1IiiI
  if 60 - 60: IiII % i11iIiiIii / OOooOOo
 def delete_mr ( self ) :
  o0000oO = self . mr_name + self . map_resolver . print_address ( )
  if ( lisp_map_resolvers_list . has_key ( o0000oO ) == False ) : return
  lisp_map_resolvers_list . pop ( o0000oO )
  if 43 - 43: i11iIiiIii * II111iiii + ooOoO0o - OoooooooOO * II111iiii / OoO0O00
  if 92 - 92: O0 - ooOoO0o % iII111i
  if 83 - 83: I1ii11iIi11i / OoOoOO00 % OoooooooOO
class lisp_ddt_root ( ) :
 def __init__ ( self ) :
  self . root_address = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . public_key = ""
  self . priority = 0
  self . weight = 0
  if 54 - 54: I11i / I1IiiI * IiII - iII111i
  if 37 - 37: i1IIi * I1Ii111 / I11i * II111iiii + OoooooooOO . OoO0O00
  if 22 - 22: OoOoOO00 + OoooooooOO - I1Ii111
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
  if 82 - 82: Ii1I % I1Ii111 / ooOoO0o
  if 86 - 86: II111iiii - iIii1I11I1II1 + oO0o + I1IiiI
 def print_referral ( self , eid_indent , referral_indent ) :
  i11ii11I1I = lisp_print_elapsed ( self . uptime )
  OoOOO0ooOOo00 = lisp_print_future ( self . expires )
  lprint ( "{}Referral EID {}, uptime/expires {}/{}, {} referrals:" . format ( eid_indent , green ( self . eid . print_prefix ( ) , False ) , i11ii11I1I ,
  # O0
 OoOOO0ooOOo00 , len ( self . referral_set ) ) )
  if 67 - 67: OOooOOo / I11i - I1Ii111 % i11iIiiIii
  for oOoooooOoOoO in self . referral_set . values ( ) :
   oOoooooOoOoO . print_ref_node ( referral_indent )
   if 3 - 3: oO0o + iII111i + OOooOOo
   if 54 - 54: i11iIiiIii + OoO0O00 - IiII - iII111i / I11i
   if 85 - 85: OOooOOo * OOooOOo * I1Ii111 - ooOoO0o . O0 % iII111i
 def print_referral_type ( self ) :
  if ( self . eid . afi == LISP_AFI_ULTIMATE_ROOT ) : return ( "root" )
  if ( self . referral_type == LISP_DDT_ACTION_NULL ) :
   return ( "null-referral" )
   if 5 - 5: i1IIi * iII111i . o0oOOo0O0Ooo - I1ii11iIi11i
  if ( self . referral_type == LISP_DDT_ACTION_SITE_NOT_FOUND ) :
   return ( "no-site-action" )
   if 84 - 84: i1IIi
  if ( self . referral_type > LISP_DDT_ACTION_MAX ) :
   return ( "invalid-action" )
   if 17 - 17: IiII + iII111i * OoO0O00 / iII111i
  return ( lisp_map_referral_action_string [ self . referral_type ] )
  if 67 - 67: i1IIi * IiII . OoOoOO00 % iIii1I11I1II1 - iIii1I11I1II1 * I1ii11iIi11i
  if 96 - 96: iII111i / i11iIiiIii / oO0o + Oo0Ooo
 def print_eid_tuple ( self ) :
  return ( lisp_print_eid_tuple ( self . eid , self . group ) )
  if 65 - 65: OoOoOO00
  if 87 - 87: I11i % i1IIi + i11iIiiIii * II111iiii
 def print_ttl ( self ) :
  O00O00Oo = self . referral_ttl
  if ( O00O00Oo < 60 ) : return ( str ( O00O00Oo ) + " secs" )
  if 58 - 58: OoO0O00 * I1IiiI - II111iiii / Ii1I - I1IiiI % OoooooooOO
  if ( ( O00O00Oo % 60 ) == 0 ) :
   O00O00Oo = str ( O00O00Oo / 60 ) + " mins"
  else :
   O00O00Oo = str ( O00O00Oo ) + " secs"
   if 33 - 33: IiII / i1IIi + I1Ii111
  return ( O00O00Oo )
  if 5 - 5: O0 / iII111i % II111iiii . Oo0Ooo - I11i
  if 84 - 84: oO0o * iII111i % i11iIiiIii - O0 . iIii1I11I1II1 - OoOoOO00
 def is_referral_negative ( self ) :
  return ( self . referral_type in ( LISP_DDT_ACTION_MS_NOT_REG , LISP_DDT_ACTION_DELEGATION_HOLE ,
  # OoOoOO00 . O0 - OoO0O00 + i1IIi + i11iIiiIii
 LISP_DDT_ACTION_NOT_AUTH ) )
  if 4 - 4: oO0o % OoOoOO00
  if 77 - 77: II111iiii + i1IIi + I1IiiI
 def add_cache ( self ) :
  if ( self . group . is_null ( ) ) :
   lisp_referral_cache . add_cache ( self . eid , self )
  else :
   i11iII1I1I1i1 = lisp_referral_cache . lookup_cache ( self . group , True )
   if ( i11iII1I1I1i1 == None ) :
    i11iII1I1I1i1 = lisp_referral ( )
    i11iII1I1I1i1 . eid . copy_address ( self . group )
    i11iII1I1I1i1 . group . copy_address ( self . group )
    lisp_referral_cache . add_cache ( self . group , i11iII1I1I1i1 )
    if 75 - 75: OoooooooOO . I11i - OoOoOO00
   if ( self . eid . is_null ( ) ) : self . eid . make_default_route ( i11iII1I1I1i1 . group )
   i11iII1I1I1i1 . add_source_entry ( self )
   if 93 - 93: OoOoOO00 . I1Ii111 % I1ii11iIi11i
   if 58 - 58: OoooooooOO . i1IIi . Oo0Ooo - o0oOOo0O0Ooo / oO0o * I1Ii111
   if 6 - 6: oO0o - OoO0O00
 def delete_cache ( self ) :
  if ( self . group . is_null ( ) ) :
   lisp_referral_cache . delete_cache ( self . eid )
  else :
   i11iII1I1I1i1 = lisp_referral_cache . lookup_cache ( self . group , True )
   if ( i11iII1I1I1i1 == None ) : return
   if 44 - 44: Oo0Ooo + I1ii11iIi11i % Oo0Ooo / I11i
   ooO0oo000 = i11iII1I1I1i1 . lookup_source_cache ( self . eid , True )
   if ( ooO0oo000 == None ) : return
   if 57 - 57: Oo0Ooo + Ii1I * OoooooooOO
   i11iII1I1I1i1 . source_cache . delete_cache ( self . eid )
   if ( i11iII1I1I1i1 . source_cache . cache_size ( ) == 0 ) :
    lisp_referral_cache . delete_cache ( self . group )
    if 30 - 30: O0
    if 70 - 70: oO0o
    if 89 - 89: O0
    if 3 - 3: iII111i - O0 / I11i
 def add_source_entry ( self , source_ref ) :
  if ( self . source_cache == None ) : self . source_cache = lisp_cache ( )
  self . source_cache . add_cache ( source_ref . eid , source_ref )
  if 46 - 46: I1IiiI . OoooooooOO / iIii1I11I1II1 - ooOoO0o * OOooOOo
  if 55 - 55: o0oOOo0O0Ooo + iIii1I11I1II1 / I11i
 def lookup_source_cache ( self , source , exact ) :
  if ( self . source_cache == None ) : return ( None )
  return ( self . source_cache . lookup_cache ( source , exact ) )
  if 97 - 97: i11iIiiIii
  if 71 - 71: oO0o + Oo0Ooo
  if 7 - 7: OoOoOO00 / I1ii11iIi11i * i1IIi
class lisp_referral_node ( ) :
 def __init__ ( self ) :
  self . referral_address = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . priority = 0
  self . weight = 0
  self . updown = True
  self . map_requests_sent = 0
  self . no_responses = 0
  self . uptime = lisp_get_timestamp ( )
  if 87 - 87: OoooooooOO * IiII - I1IiiI % I1ii11iIi11i % iIii1I11I1II1
  if 28 - 28: I1Ii111 / o0oOOo0O0Ooo / II111iiii . o0oOOo0O0Ooo . Ii1I / I11i
 def print_ref_node ( self , indent ) :
  o0O0oo0OO0O = lisp_print_elapsed ( self . uptime )
  lprint ( "{}referral {}, uptime {}, {}, priority/weight: {}/{}" . format ( indent , red ( self . referral_address . print_address ( ) , False ) , o0O0oo0OO0O ,
  # iIii1I11I1II1 / I1IiiI * OoooooooOO
 "up" if self . updown else "down" , self . priority , self . weight ) )
  if 75 - 75: IiII . OoooooooOO + I1IiiI % OOooOOo + ooOoO0o . ooOoO0o
  if 53 - 53: OoO0O00
  if 58 - 58: I1IiiI / IiII - OoooooooOO - I1Ii111
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
   if 39 - 39: IiII . II111iiii
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
   if 42 - 42: I1ii11iIi11i . Oo0Ooo * I1IiiI / Oo0Ooo
   if 83 - 83: i11iIiiIii / OoOoOO00
   if 37 - 37: iIii1I11I1II1 % IiII / i11iIiiIii - oO0o
 def resolve_dns_name ( self ) :
  if ( self . dns_name == None ) : return
  if ( self . last_dns_resolve and
 time . time ( ) - self . last_dns_resolve < 30 ) : return
  if 43 - 43: II111iiii - OoooooooOO
  try :
   oOo00o = socket . gethostbyname_ex ( self . dns_name )
   self . last_dns_resolve = lisp_get_timestamp ( )
   ooO00Ooo0 = oOo00o [ 2 ]
  except :
   return
   if 11 - 11: I1IiiI
   if 76 - 76: iII111i - II111iiii % Oo0Ooo . I1Ii111
   if 64 - 64: OoO0O00 - OoO0O00
   if 93 - 93: Oo0Ooo . O0
   if 75 - 75: iII111i * II111iiii - I1IiiI
   if 30 - 30: i1IIi / ooOoO0o . ooOoO0o
  if ( len ( ooO00Ooo0 ) <= self . a_record_index ) :
   self . delete_ms ( )
   return
   if 22 - 22: I11i % iIii1I11I1II1 - i11iIiiIii * OoOoOO00 - I1Ii111
   if 97 - 97: i11iIiiIii . OoOoOO00 + oO0o * O0 % OoO0O00 - Ii1I
  o00Ooo0 = ooO00Ooo0 [ self . a_record_index ]
  if ( o00Ooo0 != self . map_server . print_address_no_iid ( ) ) :
   self . delete_ms ( )
   self . map_server . store_address ( o00Ooo0 )
   self . insert_ms ( )
   if 46 - 46: I1Ii111
   if 87 - 87: o0oOOo0O0Ooo - iII111i * OoO0O00 * o0oOOo0O0Ooo . o0oOOo0O0Ooo / OOooOOo
   if 50 - 50: i11iIiiIii - II111iiii * OoooooooOO + II111iiii - ooOoO0o
   if 52 - 52: i1IIi + i1IIi * i1IIi / OoOoOO00
   if 98 - 98: iII111i . i1IIi + o0oOOo0O0Ooo * OoooooooOO - i11iIiiIii
   if 21 - 21: i11iIiiIii . oO0o * o0oOOo0O0Ooo + Oo0Ooo * OoOoOO00 * o0oOOo0O0Ooo
  if ( lisp_is_decent_dns_suffix ( self . dns_name ) == False ) : return
  if ( self . a_record_index != 0 ) : return
  if 33 - 33: I1IiiI + O0 - I11i
  for o00Ooo0 in ooO00Ooo0 [ 1 : : ] :
   iiiI111I = lisp_address ( LISP_AFI_NONE , o00Ooo0 , 0 , 0 )
   iiIiiiII11Iii1 = lisp_get_map_server ( iiiI111I )
   if ( iiIiiiII11Iii1 != None and iiIiiiII11Iii1 . a_record_index == ooO00Ooo0 . index ( o00Ooo0 ) ) :
    continue
    if 90 - 90: I1Ii111 * OoooooooOO . iIii1I11I1II1 % OoO0O00 / I11i + iII111i
   iiIiiiII11Iii1 = copy . deepcopy ( self )
   iiIiiiII11Iii1 . map_server . store_address ( o00Ooo0 )
   iiIiiiII11Iii1 . a_record_index = ooO00Ooo0 . index ( o00Ooo0 )
   iiIiiiII11Iii1 . last_dns_resolve = lisp_get_timestamp ( )
   iiIiiiII11Iii1 . insert_ms ( )
   if 63 - 63: o0oOOo0O0Ooo . IiII . Oo0Ooo - iIii1I11I1II1 / I1Ii111
   if 66 - 66: ooOoO0o * I1Ii111 - II111iiii
   if 38 - 38: O0 % I1ii11iIi11i + O0
   if 37 - 37: Oo0Ooo / I1IiiI
   if 23 - 23: II111iiii / iII111i
  iiiI = [ ]
  for iiIiiiII11Iii1 in lisp_map_servers_list . values ( ) :
   if ( self . dns_name != iiIiiiII11Iii1 . dns_name ) : continue
   iiiI111I = iiIiiiII11Iii1 . map_server . print_address_no_iid ( )
   if ( iiiI111I in ooO00Ooo0 ) : continue
   iiiI . append ( iiIiiiII11Iii1 )
   if 55 - 55: i11iIiiIii - Ii1I % OoooooooOO * OoooooooOO
  for iiIiiiII11Iii1 in iiiI : iiIiiiII11Iii1 . delete_ms ( )
  if 92 - 92: iIii1I11I1II1
  if 47 - 47: Oo0Ooo + Oo0Ooo * ooOoO0o - OoOoOO00 + II111iiii
 def insert_ms ( self ) :
  o0000oO = self . ms_name + self . map_server . print_address ( )
  lisp_map_servers_list [ o0000oO ] = self
  if 10 - 10: II111iiii / ooOoO0o . Ii1I / I1Ii111 / oO0o
  if 8 - 8: OOooOOo / ooOoO0o * I11i + OOooOOo * i1IIi
 def delete_ms ( self ) :
  o0000oO = self . ms_name + self . map_server . print_address ( )
  if ( lisp_map_servers_list . has_key ( o0000oO ) == False ) : return
  lisp_map_servers_list . pop ( o0000oO )
  if 48 - 48: o0oOOo0O0Ooo - I1ii11iIi11i / iII111i
  if 63 - 63: O0 - IiII . OOooOOo % IiII . I1IiiI / oO0o
  if 79 - 79: OoOoOO00
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
  if 88 - 88: oO0o * o0oOOo0O0Ooo
  if 5 - 5: I11i - I1Ii111 * I11i - II111iiii + OOooOOo + II111iiii
 def add_interface ( self ) :
  lisp_myinterfaces [ self . device ] = self
  if 91 - 91: i1IIi + Oo0Ooo - I1ii11iIi11i + I1ii11iIi11i * O0 / O0
  if 78 - 78: OoooooooOO
 def get_instance_id ( self ) :
  return ( self . instance_id )
  if 8 - 8: Oo0Ooo - Oo0Ooo % O0 - Ii1I / o0oOOo0O0Ooo % Oo0Ooo
  if 51 - 51: iIii1I11I1II1 / iIii1I11I1II1 * I1ii11iIi11i / I11i
 def get_socket ( self ) :
  return ( self . raw_socket )
  if 18 - 18: Ii1I - i11iIiiIii + OoO0O00 . O0 - iII111i
  if 9 - 9: OoooooooOO / iII111i + o0oOOo0O0Ooo / II111iiii / I1Ii111
 def get_bridge_socket ( self ) :
  return ( self . bridge_socket )
  if 44 - 44: I1IiiI / iII111i / Oo0Ooo
  if 66 - 66: I1Ii111 + OoooooooOO % I1IiiI . iII111i * Oo0Ooo + o0oOOo0O0Ooo
 def does_dynamic_eid_match ( self , eid ) :
  return ( eid . is_more_specific ( self . dynamic_eid ) )
  if 96 - 96: OoO0O00 - ooOoO0o * Ii1I
  if 34 - 34: OoO0O00 . Oo0Ooo % Ii1I . IiII + OoOoOO00
 def set_socket ( self , device ) :
  oooOOO00o0 = socket . socket ( socket . AF_INET , socket . SOCK_RAW , socket . IPPROTO_RAW )
  oooOOO00o0 . setsockopt ( socket . SOL_IP , socket . IP_HDRINCL , 1 )
  try :
   oooOOO00o0 . setsockopt ( socket . SOL_SOCKET , socket . SO_BINDTODEVICE , device )
  except :
   oooOOO00o0 . close ( )
   oooOOO00o0 = None
   if 10 - 10: OoooooooOO * iII111i * ooOoO0o . Ii1I % I1Ii111 / I1ii11iIi11i
  self . raw_socket = oooOOO00o0
  if 71 - 71: Ii1I + IiII
  if 10 - 10: II111iiii % o0oOOo0O0Ooo . o0oOOo0O0Ooo % iII111i
 def set_bridge_socket ( self , device ) :
  oooOOO00o0 = socket . socket ( socket . PF_PACKET , socket . SOCK_RAW )
  try :
   oooOOO00o0 = oooOOO00o0 . bind ( ( device , 0 ) )
   self . bridge_socket = oooOOO00o0
  except :
   return
   if 2 - 2: OoooooooOO / IiII % Oo0Ooo % iIii1I11I1II1
   if 62 - 62: oO0o
   if 47 - 47: I1IiiI - O0 - I1ii11iIi11i . OoOoOO00
   if 98 - 98: o0oOOo0O0Ooo - OoO0O00 . I1ii11iIi11i / OOooOOo
class lisp_datetime ( ) :
 def __init__ ( self , datetime_str ) :
  self . datetime_name = datetime_str
  self . datetime = None
  self . parse_datetime ( )
  if 43 - 43: I1IiiI + OOooOOo + o0oOOo0O0Ooo
  if 44 - 44: o0oOOo0O0Ooo % OoO0O00 . OoooooooOO
 def valid_datetime ( self ) :
  IIIII1i11i1I1 = self . datetime_name
  if ( IIIII1i11i1I1 . find ( ":" ) == - 1 ) : return ( False )
  if ( IIIII1i11i1I1 . find ( "-" ) == - 1 ) : return ( False )
  IiIIi11I , o0Oo0 , oOO0Ooi11iiIiI1IIii , time = IIIII1i11i1I1 [ 0 : 4 ] , IIIII1i11i1I1 [ 5 : 7 ] , IIIII1i11i1I1 [ 8 : 10 ] , IIIII1i11i1I1 [ 11 : : ]
  if 90 - 90: OoOoOO00 % OoO0O00 . I1IiiI * oO0o
  if ( ( IiIIi11I + o0Oo0 + oOO0Ooi11iiIiI1IIii ) . isdigit ( ) == False ) : return ( False )
  if ( o0Oo0 < "01" and o0Oo0 > "12" ) : return ( False )
  if ( oOO0Ooi11iiIiI1IIii < "01" and oOO0Ooi11iiIiI1IIii > "31" ) : return ( False )
  if 17 - 17: O0 - i1IIi
  O0ooooO0 , i1i1iIi11iIiiI1i1i1 , oOoOo0 = time . split ( ":" )
  if 50 - 50: I1IiiI / Ii1I / Ii1I + O0 % I11i - i1IIi
  if ( ( O0ooooO0 + i1i1iIi11iIiiI1i1i1 + oOoOo0 ) . isdigit ( ) == False ) : return ( False )
  if ( O0ooooO0 < "00" and O0ooooO0 > "23" ) : return ( False )
  if ( i1i1iIi11iIiiI1i1i1 < "00" and i1i1iIi11iIiiI1i1i1 > "59" ) : return ( False )
  if ( oOoOo0 < "00" and oOoOo0 > "59" ) : return ( False )
  return ( True )
  if 72 - 72: II111iiii . OoO0O00 . II111iiii * I1ii11iIi11i
  if 42 - 42: II111iiii
 def parse_datetime ( self ) :
  IIiO0O0 = self . datetime_name
  IIiO0O0 = IIiO0O0 . replace ( "-" , "" )
  IIiO0O0 = IIiO0O0 . replace ( ":" , "" )
  self . datetime = int ( IIiO0O0 )
  if 4 - 4: i11iIiiIii + o0oOOo0O0Ooo % I11i - I1ii11iIi11i * I1ii11iIi11i
  if 87 - 87: I1Ii111 % i11iIiiIii + O0
 def now ( self ) :
  o0O0oo0OO0O = datetime . datetime . now ( ) . strftime ( "%Y-%m-%d-%H:%M:%S" )
  o0O0oo0OO0O = lisp_datetime ( o0O0oo0OO0O )
  return ( o0O0oo0OO0O )
  if 67 - 67: OoooooooOO / i1IIi / ooOoO0o . i1IIi - i11iIiiIii . i1IIi
  if 41 - 41: i11iIiiIii / ooOoO0o - Ii1I + I11i
 def print_datetime ( self ) :
  return ( self . datetime_name )
  if 15 - 15: I1ii11iIi11i
  if 22 - 22: iIii1I11I1II1 - i1IIi - i11iIiiIii / I1IiiI + o0oOOo0O0Ooo
 def future ( self ) :
  return ( self . datetime > self . now ( ) . datetime )
  if 56 - 56: I1IiiI . ooOoO0o
  if 35 - 35: iIii1I11I1II1 % Oo0Ooo + o0oOOo0O0Ooo * o0oOOo0O0Ooo % ooOoO0o
 def past ( self ) :
  return ( self . future ( ) == False )
  if 10 - 10: I1ii11iIi11i / II111iiii % II111iiii - OoooooooOO * o0oOOo0O0Ooo / ooOoO0o
  if 26 - 26: OoO0O00 . O0 * iII111i % OoOoOO00 % iIii1I11I1II1
 def now_in_range ( self , upper ) :
  return ( self . past ( ) and upper . future ( ) )
  if 37 - 37: iII111i - ooOoO0o * Ii1I + II111iiii * i11iIiiIii
  if 8 - 8: OoooooooOO % I11i - iII111i * OOooOOo . O0
 def this_year ( self ) :
  I1IIiIiiiii1 = str ( self . now ( ) . datetime ) [ 0 : 4 ]
  o0O0oo0OO0O = str ( self . datetime ) [ 0 : 4 ]
  return ( o0O0oo0OO0O == I1IIiIiiiii1 )
  if 7 - 7: I1ii11iIi11i
  if 29 - 29: I11i - ooOoO0o
 def this_month ( self ) :
  I1IIiIiiiii1 = str ( self . now ( ) . datetime ) [ 0 : 6 ]
  o0O0oo0OO0O = str ( self . datetime ) [ 0 : 6 ]
  return ( o0O0oo0OO0O == I1IIiIiiiii1 )
  if 1 - 1: o0oOOo0O0Ooo + iIii1I11I1II1 + I1ii11iIi11i
  if 40 - 40: I1Ii111
 def today ( self ) :
  I1IIiIiiiii1 = str ( self . now ( ) . datetime ) [ 0 : 8 ]
  o0O0oo0OO0O = str ( self . datetime ) [ 0 : 8 ]
  return ( o0O0oo0OO0O == I1IIiIiiiii1 )
  if 18 - 18: OoOoOO00 * Ii1I
  if 81 - 81: IiII . i11iIiiIii - I1IiiI * i11iIiiIii + OoO0O00
  if 94 - 94: I1ii11iIi11i + OoO0O00 . II111iiii + oO0o . II111iiii
  if 96 - 96: i11iIiiIii
  if 66 - 66: ooOoO0o * iII111i - iII111i - O0 . o0oOOo0O0Ooo
  if 23 - 23: iIii1I11I1II1 / I11i % OoOoOO00 . OoO0O00
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
  if 90 - 90: iIii1I11I1II1 - OOooOOo . Ii1I % OoO0O00
  if 89 - 89: i11iIiiIii
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
  if 86 - 86: Oo0Ooo % iIii1I11I1II1 . II111iiii / I11i % OoO0O00 % OoO0O00
  if 40 - 40: o0oOOo0O0Ooo . iIii1I11I1II1 * Oo0Ooo * i1IIi
 def match_policy_map_request ( self , mr , srloc ) :
  for iIiIii11I1 in self . match_clauses :
   iII1ii = iIiIii11I1 . source_eid
   oOOO0ooo = mr . source_eid
   if ( iII1ii and oOOO0ooo and oOOO0ooo . is_more_specific ( iII1ii ) == False ) : continue
   if 94 - 94: oO0o - II111iiii + OoOoOO00
   iII1ii = iIiIii11I1 . dest_eid
   oOOO0ooo = mr . target_eid
   if ( iII1ii and oOOO0ooo and oOOO0ooo . is_more_specific ( iII1ii ) == False ) : continue
   if 90 - 90: Oo0Ooo + Oo0Ooo + I1Ii111
   iII1ii = iIiIii11I1 . source_rloc
   oOOO0ooo = srloc
   if ( iII1ii and oOOO0ooo and oOOO0ooo . is_more_specific ( iII1ii ) == False ) : continue
   o0Oo = iIiIii11I1 . datetime_lower
   Oo0o00000o = iIiIii11I1 . datetime_upper
   if ( o0Oo and Oo0o00000o and o0Oo . now_in_range ( Oo0o00000o ) == False ) : continue
   return ( True )
   if 31 - 31: iIii1I11I1II1
  return ( False )
  if 100 - 100: I11i + IiII
  if 29 - 29: iIii1I11I1II1 % O0 / I1ii11iIi11i . I1Ii111 / O0 . iII111i
 def set_policy_map_reply ( self ) :
  IIiiIiII = ( self . set_rloc_address == None and
 self . set_rloc_record_name == None and self . set_geo_name == None and
 self . set_elp_name == None and self . set_rle_name == None )
  if ( IIiiIiII ) : return ( None )
  if 23 - 23: OoOoOO00 / i11iIiiIii % OoOoOO00
  Oo0O0 = lisp_rloc ( )
  if ( self . set_rloc_address ) :
   Oo0O0 . rloc . copy_address ( self . set_rloc_address )
   o00Ooo0 = Oo0O0 . rloc . print_address_no_iid ( )
   lprint ( "Policy set-rloc-address to {}" . format ( o00Ooo0 ) )
   if 54 - 54: o0oOOo0O0Ooo . i11iIiiIii + I1IiiI * ooOoO0o - ooOoO0o
  if ( self . set_rloc_record_name ) :
   Oo0O0 . rloc_name = self . set_rloc_record_name
   oo00 = blue ( Oo0O0 . rloc_name , False )
   lprint ( "Policy set-rloc-record-name to {}" . format ( oo00 ) )
   if 28 - 28: I1Ii111 . i11iIiiIii * oO0o % ooOoO0o / iII111i . OOooOOo
  if ( self . set_geo_name ) :
   Oo0O0 . geo_name = self . set_geo_name
   oo00 = Oo0O0 . geo_name
   Ooo0O0OO0O00o = "" if lisp_geo_list . has_key ( oo00 ) else "(not configured)"
   if 70 - 70: Oo0Ooo
   lprint ( "Policy set-geo-name '{}' {}" . format ( oo00 , Ooo0O0OO0O00o ) )
   if 33 - 33: i11iIiiIii + iIii1I11I1II1 - i11iIiiIii + i11iIiiIii . i1IIi
  if ( self . set_elp_name ) :
   Oo0O0 . elp_name = self . set_elp_name
   oo00 = Oo0O0 . elp_name
   Ooo0O0OO0O00o = "" if lisp_elp_list . has_key ( oo00 ) else "(not configured)"
   if 70 - 70: O0 / II111iiii
   lprint ( "Policy set-elp-name '{}' {}" . format ( oo00 , Ooo0O0OO0O00o ) )
   if 98 - 98: OoOoOO00 - O0 . O0 + ooOoO0o * iIii1I11I1II1
  if ( self . set_rle_name ) :
   Oo0O0 . rle_name = self . set_rle_name
   oo00 = Oo0O0 . rle_name
   Ooo0O0OO0O00o = "" if lisp_rle_list . has_key ( oo00 ) else "(not configured)"
   if 7 - 7: IiII * OoOoOO00 + iIii1I11I1II1 / OoOoOO00 + Oo0Ooo / o0oOOo0O0Ooo
   lprint ( "Policy set-rle-name '{}' {}" . format ( oo00 , Ooo0O0OO0O00o ) )
   if 77 - 77: i1IIi . I1IiiI
  if ( self . set_json_name ) :
   Oo0O0 . json_name = self . set_json_name
   oo00 = Oo0O0 . json_name
   Ooo0O0OO0O00o = "" if lisp_json_list . has_key ( oo00 ) else "(not configured)"
   if 59 - 59: O0 + OoooooooOO - i1IIi
   lprint ( "Policy set-json-name '{}' {}" . format ( oo00 , Ooo0O0OO0O00o ) )
   if 87 - 87: IiII * OoooooooOO / Oo0Ooo % iIii1I11I1II1 % oO0o
  return ( Oo0O0 )
  if 97 - 97: ooOoO0o % i1IIi . IiII / Oo0Ooo . I1Ii111 . OoO0O00
  if 12 - 12: I1IiiI
 def save_policy ( self ) :
  lisp_policies [ self . policy_name ] = self
  if 99 - 99: II111iiii - OoOoOO00
  if 22 - 22: i11iIiiIii * II111iiii
  if 11 - 11: Oo0Ooo % i1IIi
class lisp_pubsub ( ) :
 def __init__ ( self , itr , port , nonce , ttl , xtr_id ) :
  self . itr = itr
  self . port = port
  self . nonce = nonce
  self . uptime = lisp_get_timestamp ( )
  self . ttl = ttl
  self . xtr_id = xtr_id
  self . map_notify_count = 0
  if 70 - 70: II111iiii * Oo0Ooo * OOooOOo - I1IiiI + iIii1I11I1II1 + ooOoO0o
  if 27 - 27: I1ii11iIi11i - I1Ii111 * O0 % ooOoO0o / I1IiiI
 def add ( self , eid_prefix ) :
  O00O00Oo = self . ttl
  oOOOO = eid_prefix . print_prefix ( )
  if ( lisp_pubsub_cache . has_key ( oOOOO ) == False ) :
   lisp_pubsub_cache [ oOOOO ] = { }
   if 53 - 53: i11iIiiIii * i11iIiiIii % O0 % IiII
  II = lisp_pubsub_cache [ oOOOO ]
  if 57 - 57: I1IiiI % i1IIi * OoO0O00 + I1Ii111 . I11i % I11i
  oOOO = "Add"
  if ( II . has_key ( self . xtr_id ) ) :
   oOOO = "Replace"
   del ( II [ self . xtr_id ] )
   if 12 - 12: O0
  II [ self . xtr_id ] = self
  if 20 - 20: Ii1I - oO0o / OoooooooOO - OoooooooOO + iII111i
  oOOOO = green ( oOOOO , False )
  Ii1ii1Ii11 = red ( self . itr . print_address_no_iid ( ) , False )
  O0o0O0OoOo0 = "0x" + lisp_hex_string ( self . xtr_id )
  lprint ( "{} pubsub state {} for {}, xtr-id: {}, ttl {}" . format ( oOOO , oOOOO ,
 Ii1ii1Ii11 , O0o0O0OoOo0 , O00O00Oo ) )
  if 78 - 78: o0oOOo0O0Ooo - IiII % oO0o + i11iIiiIii % I1ii11iIi11i . OoOoOO00
  if 31 - 31: II111iiii . i1IIi . OoOoOO00
 def delete ( self , eid_prefix ) :
  oOOOO = eid_prefix . print_prefix ( )
  Ii1ii1Ii11 = red ( self . itr . print_address_no_iid ( ) , False )
  O0o0O0OoOo0 = "0x" + lisp_hex_string ( self . xtr_id )
  if ( lisp_pubsub_cache . has_key ( oOOOO ) ) :
   II = lisp_pubsub_cache [ oOOOO ]
   if ( II . has_key ( self . xtr_id ) ) :
    II . pop ( self . xtr_id )
    lprint ( "Remove pubsub state {} for {}, xtr-id: {}" . format ( oOOOO ,
 Ii1ii1Ii11 , O0o0O0OoOo0 ) )
    if 98 - 98: iII111i
    if 80 - 80: I1Ii111 % i1IIi
    if 33 - 33: o0oOOo0O0Ooo
    if 32 - 32: Ii1I / iII111i - Oo0Ooo % iIii1I11I1II1 + OoO0O00
    if 55 - 55: oO0o
    if 60 - 60: OOooOOo + OOooOOo - Ii1I / iII111i
    if 42 - 42: IiII % oO0o - o0oOOo0O0Ooo * iII111i - Oo0Ooo
    if 19 - 19: I1IiiI - iII111i - oO0o / II111iiii
    if 98 - 98: IiII * OoOoOO00
    if 13 - 13: O0 + oO0o - iIii1I11I1II1 - Oo0Ooo % I1IiiI
    if 45 - 45: O0
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
class lisp_trace ( ) :
 def __init__ ( self ) :
  self . nonce = lisp_get_control_nonce ( )
  self . packet_json = [ ]
  if 17 - 17: OoO0O00
  if 79 - 79: Ii1I - II111iiii
 def print_trace ( self ) :
  ooooo = self . packet_json
  lprint ( "LISP-Trace JSON: '{}'" . format ( ooooo ) )
  if 98 - 98: OoooooooOO + Ii1I % oO0o . IiII - I1ii11iIi11i
  if 45 - 45: IiII + i1IIi
 def encode ( self ) :
  Iii11I1i = socket . htonl ( 0x90000000 )
  iIIi1 = struct . pack ( "I" , Iii11I1i )
  iIIi1 += struct . pack ( "Q" , self . nonce )
  iIIi1 += json . dumps ( self . packet_json )
  return ( iIIi1 )
  if 3 - 3: iIii1I11I1II1 % oO0o . oO0o + IiII
  if 36 - 36: OoOoOO00 * iIii1I11I1II1 + oO0o * IiII . IiII . OOooOOo
 def decode ( self , packet ) :
  I1I = "I"
  ii1I1iIi = struct . calcsize ( I1I )
  if ( len ( packet ) < ii1I1iIi ) : return ( False )
  Iii11I1i = struct . unpack ( I1I , packet [ : ii1I1iIi ] ) [ 0 ]
  packet = packet [ ii1I1iIi : : ]
  if ( socket . ntohl ( Iii11I1i ) != 0x90000000 ) : return ( False )
  if 64 - 64: I1ii11iIi11i / OoOoOO00 + O0 % i1IIi - ooOoO0o + o0oOOo0O0Ooo
  I1I = "Q"
  ii1I1iIi = struct . calcsize ( I1I )
  if ( len ( packet ) < ii1I1iIi ) : return ( False )
  self . nonce = struct . unpack ( I1I , packet [ : ii1I1iIi ] ) [ 0 ]
  packet = packet [ ii1I1iIi : : ]
  if ( len ( packet ) == 0 ) : return ( True )
  if 67 - 67: Oo0Ooo
  try :
   self . packet_json = json . loads ( packet )
  except :
   return ( False )
   if 52 - 52: I1IiiI % I1Ii111 - i1IIi . o0oOOo0O0Ooo % I1ii11iIi11i
  return ( True )
  if 34 - 34: o0oOOo0O0Ooo / OoOoOO00
  if 74 - 74: IiII + i1IIi . II111iiii
 def myeid ( self , eid ) :
  return ( lisp_is_myeid ( eid ) )
  if 1 - 1: Ii1I - o0oOOo0O0Ooo / i11iIiiIii
  if 24 - 24: O0
 def return_to_sender ( self , rts_rloc , packet ) :
  oooOOO00o0 = socket . socket ( socket . AF_INET , socket . SOCK_DGRAM )
  oooOOO00o0 . sendto ( packet , ( rts_rloc , LISP_TRACE_PORT ) )
  oooOOO00o0 . close ( )
  if 59 - 59: OoO0O00 % iII111i + oO0o * II111iiii . OOooOOo
  if 26 - 26: OOooOOo % OoooooooOO . Ii1I / iIii1I11I1II1 * I1IiiI
 def packet_length ( self ) :
  iI = 8 ; O0O0 = 4 + 8
  return ( iI + O0O0 + len ( json . dumps ( self . packet_json ) ) )
  if 95 - 95: OoooooooOO % I1ii11iIi11i . I1Ii111 . IiII
  if 98 - 98: OoooooooOO - OoO0O00 . oO0o - iIii1I11I1II1 * iIii1I11I1II1 % Ii1I
  if 87 - 87: O0 % iII111i
  if 57 - 57: Ii1I
  if 49 - 49: I11i
  if 22 - 22: Oo0Ooo % OOooOOo + O0 - OoO0O00 % I11i * O0
  if 42 - 42: O0
  if 55 - 55: i11iIiiIii % OOooOOo
  if 10 - 10: OoOoOO00 / i11iIiiIii
  if 21 - 21: Ii1I - i1IIi / I11i + IiII
  if 44 - 44: OoooooooOO % I11i / O0
  if 94 - 94: IiII
def lisp_get_map_server ( address ) :
 for iiIiiiII11Iii1 in lisp_map_servers_list . values ( ) :
  if ( iiIiiiII11Iii1 . map_server . is_exact_match ( address ) ) : return ( iiIiiiII11Iii1 )
  if 83 - 83: OoO0O00
 return ( None )
 if 55 - 55: iII111i
 if 37 - 37: oO0o / o0oOOo0O0Ooo + I11i * OoO0O00 * o0oOOo0O0Ooo
 if 33 - 33: I1Ii111
 if 97 - 97: Ii1I / iII111i - ooOoO0o + IiII * OoOoOO00 - OOooOOo
 if 43 - 43: oO0o / II111iiii - iII111i / oO0o
 if 98 - 98: OoOoOO00 / OOooOOo
 if 31 - 31: II111iiii % I11i - I11i
def lisp_get_any_map_server ( ) :
 for iiIiiiII11Iii1 in lisp_map_servers_list . values ( ) : return ( iiIiiiII11Iii1 )
 return ( None )
 if 17 - 17: iII111i . IiII + OOooOOo % I1Ii111 % i11iIiiIii
 if 100 - 100: i11iIiiIii - O0 . OoO0O00 / O0 - Ii1I - IiII
 if 72 - 72: Ii1I % O0 + II111iiii . i11iIiiIii
 if 66 - 66: II111iiii % I1IiiI
 if 88 - 88: iIii1I11I1II1 * iIii1I11I1II1 + I1Ii111 * OOooOOo . I1IiiI
 if 96 - 96: I1ii11iIi11i
 if 37 - 37: OoO0O00 % o0oOOo0O0Ooo * O0 * O0 + iII111i
 if 18 - 18: i11iIiiIii . o0oOOo0O0Ooo - OOooOOo % oO0o * Ii1I / I1IiiI
 if 46 - 46: o0oOOo0O0Ooo . ooOoO0o / Ii1I
 if 97 - 97: Ii1I . Oo0Ooo - O0 - I1Ii111 . i1IIi
def lisp_get_map_resolver ( address , eid ) :
 if ( address != None ) :
  o00Ooo0 = address . print_address ( )
  iiIii = None
  for o0000oO in lisp_map_resolvers_list :
   if ( o0000oO . find ( o00Ooo0 ) == - 1 ) : continue
   iiIii = lisp_map_resolvers_list [ o0000oO ]
   if 47 - 47: IiII * ooOoO0o - i1IIi % OoOoOO00 * i11iIiiIii . OoooooooOO
  return ( iiIii )
  if 84 - 84: OoOoOO00 / IiII - i1IIi - I1IiiI * OOooOOo
  if 35 - 35: II111iiii
  if 28 - 28: I1Ii111 + IiII + I1ii11iIi11i . Ii1I
  if 82 - 82: ooOoO0o - ooOoO0o . Ii1I . i11iIiiIii % Ii1I + OOooOOo
  if 33 - 33: Oo0Ooo - OOooOOo / OoOoOO00 % II111iiii % OOooOOo + I1Ii111
  if 41 - 41: I11i + Oo0Ooo . Oo0Ooo / iII111i . OoOoOO00
  if 1 - 1: ooOoO0o + iII111i % i11iIiiIii / OoOoOO00
 if ( eid == "" ) :
  o000oO0O0ooo = ""
 elif ( eid == None ) :
  o000oO0O0ooo = "all"
 else :
  iIiIi = lisp_db_for_lookups . lookup_cache ( eid , False )
  o000oO0O0ooo = "all" if iIiIi == None else iIiIi . use_mr_name
  if 57 - 57: iII111i
  if 18 - 18: II111iiii % i11iIiiIii + I11i - OOooOOo
 OOO0o = None
 for iiIii in lisp_map_resolvers_list . values ( ) :
  if ( o000oO0O0ooo == "" ) : return ( iiIii )
  if ( iiIii . mr_name != o000oO0O0ooo ) : continue
  if ( OOO0o == None or iiIii . last_used < OOO0o . last_used ) : OOO0o = iiIii
  if 15 - 15: iII111i % I11i / II111iiii * O0
 return ( OOO0o )
 if 61 - 61: OOooOOo / OoO0O00 % I11i * OoO0O00 / IiII / I1IiiI
 if 77 - 77: IiII / i1IIi + OOooOOo + Oo0Ooo % iII111i % OoOoOO00
 if 6 - 6: i11iIiiIii + ooOoO0o
 if 89 - 89: iIii1I11I1II1 . I1Ii111
 if 43 - 43: Oo0Ooo + o0oOOo0O0Ooo % o0oOOo0O0Ooo % I1ii11iIi11i / iIii1I11I1II1 . I1ii11iIi11i
 if 59 - 59: IiII . OoO0O00 - OoooooooOO . O0
 if 33 - 33: Ii1I
 if 95 - 95: OoooooooOO + OoO0O00 * ooOoO0o
def lisp_get_decent_map_resolver ( eid ) :
 oooO0 = lisp_get_decent_index ( eid )
 ii111 = str ( oooO0 ) + "." + lisp_decent_dns_suffix
 if 98 - 98: I1IiiI
 lprint ( "Use LISP-Decent map-resolver {} for EID {}" . format ( bold ( ii111 , False ) , eid . print_prefix ( ) ) )
 if 4 - 4: I1IiiI % O0 / Oo0Ooo / O0
 if 90 - 90: ooOoO0o - O0 . IiII - O0 . iIii1I11I1II1
 OOO0o = None
 for iiIii in lisp_map_resolvers_list . values ( ) :
  if ( ii111 != iiIii . dns_name ) : continue
  if ( OOO0o == None or iiIii . last_used < OOO0o . last_used ) : OOO0o = iiIii
  if 42 - 42: I1ii11iIi11i
 return ( OOO0o )
 if 51 - 51: iII111i % i11iIiiIii . OoO0O00 . IiII - OoOoOO00 * i1IIi
 if 14 - 14: I1ii11iIi11i . OoO0O00
 if 26 - 26: iII111i / ooOoO0o / Oo0Ooo / Oo0Ooo . I1ii11iIi11i * OOooOOo
 if 25 - 25: IiII % I1IiiI / O0 % OOooOOo - OoooooooOO
 if 29 - 29: O0 + iII111i
 if 4 - 4: I11i * I11i - Ii1I * oO0o . I1ii11iIi11i % o0oOOo0O0Ooo
 if 33 - 33: Ii1I * i11iIiiIii / O0 . Oo0Ooo + i1IIi . OoOoOO00
def lisp_ipv4_input ( packet ) :
 if 76 - 76: OoooooooOO - O0
 if 17 - 17: Oo0Ooo % I1Ii111 . oO0o - O0
 if 32 - 32: O0 % O0
 if 66 - 66: iII111i / i1IIi - Oo0Ooo . Ii1I
 iiIiII11i1 = struct . unpack ( "H" , packet [ 10 : 12 ] ) [ 0 ]
 if ( iiIiII11i1 == 0 ) :
  dprint ( "Packet arrived with checksum of 0!" )
 else :
  packet = lisp_ip_checksum ( packet )
  iiIiII11i1 = struct . unpack ( "H" , packet [ 10 : 12 ] ) [ 0 ]
  if ( iiIiII11i1 != 0 ) :
   dprint ( "IPv4 header checksum failed for inner header" )
   packet = lisp_format_packet ( packet [ 0 : 20 ] )
   dprint ( "Packet header: {}" . format ( packet ) )
   return ( None )
   if 65 - 65: I1ii11iIi11i % ooOoO0o - OoOoOO00 + ooOoO0o + Oo0Ooo
   if 95 - 95: I1Ii111 * i11iIiiIii - I1IiiI - OoOoOO00 . ooOoO0o
   if 34 - 34: OoooooooOO % I1ii11iIi11i + OoooooooOO % i11iIiiIii / IiII - ooOoO0o
   if 74 - 74: iIii1I11I1II1 % II111iiii + IiII
   if 71 - 71: I1IiiI / O0 * i1IIi . i1IIi + Oo0Ooo
   if 32 - 32: i1IIi * I1Ii111 % I1IiiI / IiII . I1Ii111
   if 11 - 11: OOooOOo
 O00O00Oo = struct . unpack ( "B" , packet [ 8 : 9 ] ) [ 0 ]
 if ( O00O00Oo == 0 ) :
  dprint ( "IPv4 packet arrived with ttl 0, packet discarded" )
  return ( None )
 elif ( O00O00Oo == 1 ) :
  dprint ( "IPv4 packet {}, packet discarded" . format ( bold ( "ttl expiry" , False ) ) )
  if 25 - 25: i1IIi
  return ( None )
  if 99 - 99: OOooOOo + OoooooooOO . I1Ii111 * Oo0Ooo % oO0o
  if 75 - 75: iII111i
 O00O00Oo -= 1
 packet = packet [ 0 : 8 ] + struct . pack ( "B" , O00O00Oo ) + packet [ 9 : : ]
 packet = packet [ 0 : 10 ] + struct . pack ( "H" , 0 ) + packet [ 12 : : ]
 packet = lisp_ip_checksum ( packet )
 return ( packet )
 if 8 - 8: I1ii11iIi11i . I11i / I1ii11iIi11i - i1IIi
 if 22 - 22: OOooOOo
 if 7 - 7: O0 - I1ii11iIi11i - OoO0O00 * I1Ii111
 if 17 - 17: o0oOOo0O0Ooo % OoO0O00 - I11i * o0oOOo0O0Ooo - i1IIi / I1IiiI
 if 100 - 100: OoO0O00 * i1IIi * o0oOOo0O0Ooo * Oo0Ooo - o0oOOo0O0Ooo
 if 100 - 100: iII111i - i11iIiiIii + OoO0O00
 if 50 - 50: II111iiii
def lisp_ipv6_input ( packet ) :
 OO0i1Ii1II11 = packet . inner_dest
 packet = packet . packet
 if 42 - 42: OOooOOo * I1Ii111
 if 53 - 53: II111iiii % OOooOOo / I1ii11iIi11i * OoOoOO00 % I1ii11iIi11i * iII111i
 if 91 - 91: iII111i . OoooooooOO
 if 90 - 90: i11iIiiIii - I1IiiI
 if 39 - 39: iII111i % OoooooooOO % Ii1I % I1IiiI
 O00O00Oo = struct . unpack ( "B" , packet [ 7 : 8 ] ) [ 0 ]
 if ( O00O00Oo == 0 ) :
  dprint ( "IPv6 packet arrived with hop-limit 0, packet discarded" )
  return ( None )
 elif ( O00O00Oo == 1 ) :
  dprint ( "IPv6 packet {}, packet discarded" . format ( bold ( "ttl expiry" , False ) ) )
  if 63 - 63: OoO0O00 - I1Ii111 - II111iiii
  return ( None )
  if 79 - 79: II111iiii - II111iiii + OoOoOO00 / iII111i % OoooooooOO - OoO0O00
  if 22 - 22: o0oOOo0O0Ooo + I1Ii111 . Oo0Ooo
  if 84 - 84: O0 + I1IiiI % Oo0Ooo + OOooOOo
  if 94 - 94: OOooOOo
  if 81 - 81: i11iIiiIii + iIii1I11I1II1 . i11iIiiIii / OOooOOo / iII111i
 if ( OO0i1Ii1II11 . is_ipv6_link_local ( ) ) :
  dprint ( "Do not encapsulate IPv6 link-local packets" )
  return ( None )
  if 34 - 34: i11iIiiIii - o0oOOo0O0Ooo * OoooooooOO * I1ii11iIi11i * Oo0Ooo % I1ii11iIi11i
  if 31 - 31: I11i . o0oOOo0O0Ooo
 O00O00Oo -= 1
 packet = packet [ 0 : 7 ] + struct . pack ( "B" , O00O00Oo ) + packet [ 8 : : ]
 return ( packet )
 if 82 - 82: I11i - Oo0Ooo
 if 77 - 77: I1IiiI + OoO0O00 % iIii1I11I1II1 - OOooOOo
 if 80 - 80: oO0o % I1ii11iIi11i * I1Ii111 + i1IIi
 if 79 - 79: oO0o + IiII
 if 4 - 4: iII111i + OoooooooOO / I1Ii111
 if 57 - 57: I1IiiI . iIii1I11I1II1 % iII111i * iII111i / I1Ii111
 if 30 - 30: O0 / I11i % OoOoOO00 * I1Ii111 / O0 % ooOoO0o
 if 36 - 36: iIii1I11I1II1 . iII111i * I1IiiI . I1IiiI - IiII
def lisp_mac_input ( packet ) :
 return ( packet )
 if 39 - 39: O0 / ooOoO0o + I11i - OoOoOO00 * o0oOOo0O0Ooo - OoO0O00
 if 97 - 97: i11iIiiIii / O0 % OoO0O00
 if 88 - 88: i1IIi . I1IiiI
 if 8 - 8: I1ii11iIi11i . OoO0O00 % o0oOOo0O0Ooo / O0
 if 51 - 51: oO0o + Ii1I * Ii1I * I1ii11iIi11i % I11i - I1ii11iIi11i
 if 15 - 15: i1IIi / OoO0O00 - Oo0Ooo
 if 74 - 74: o0oOOo0O0Ooo % Ii1I - II111iiii / ooOoO0o
 if 84 - 84: I1IiiI + OOooOOo
 if 80 - 80: OOooOOo / OoOoOO00
def lisp_rate_limit_map_request ( source , dest ) :
 if ( lisp_last_map_request_sent == None ) : return ( False )
 I1IIiIiiiii1 = lisp_get_timestamp ( )
 Oo = I1IIiIiiiii1 - lisp_last_map_request_sent
 o0OOooOooo = ( Oo < LISP_MAP_REQUEST_RATE_LIMIT )
 if 36 - 36: iII111i % I1ii11iIi11i + OoOoOO00 - i11iIiiIii % II111iiii % I11i
 if ( o0OOooOooo ) :
  if ( source != None ) : source = source . print_address ( )
  dest = dest . print_address ( )
  dprint ( "Rate-limiting Map-Request for {} -> {}" . format ( source , dest ) )
  if 92 - 92: O0 * OoooooooOO + I1ii11iIi11i / IiII
 return ( o0OOooOooo )
 if 97 - 97: o0oOOo0O0Ooo . Ii1I + I1Ii111
 if 72 - 72: i11iIiiIii . iII111i . Ii1I * I1ii11iIi11i
 if 49 - 49: OoOoOO00 - O0 % I11i - ooOoO0o * OOooOOo
 if 58 - 58: OoooooooOO - OOooOOo * oO0o / Ii1I . IiII
 if 50 - 50: IiII . OOooOOo + I1ii11iIi11i - OoooooooOO
 if 2 - 2: o0oOOo0O0Ooo % ooOoO0o / O0 / i11iIiiIii
 if 91 - 91: II111iiii * o0oOOo0O0Ooo
def lisp_send_map_request ( lisp_sockets , lisp_ephem_port , seid , deid , rloc ) :
 global lisp_last_map_request_sent
 if 20 - 20: iIii1I11I1II1 % Oo0Ooo * OoOoOO00 % IiII
 if 93 - 93: I11i * iIii1I11I1II1 * oO0o
 if 74 - 74: I1IiiI
 if 39 - 39: iII111i * IiII / iII111i * IiII % I1ii11iIi11i
 if 27 - 27: iIii1I11I1II1 . ooOoO0o
 if 74 - 74: i1IIi % OoOoOO00
 O0o0Ooo0O0OO = O00O0oo0OOo = None
 if ( rloc ) :
  O0o0Ooo0O0OO = rloc . rloc
  O00O0oo0OOo = rloc . translated_port if lisp_i_am_rtr else LISP_DATA_PORT
  if 94 - 94: OoOoOO00 . O0
  if 86 - 86: oO0o % Oo0Ooo . OoooooooOO / OOooOOo / i1IIi
  if 65 - 65: Ii1I . OoooooooOO % IiII - o0oOOo0O0Ooo . OOooOOo . II111iiii
  if 100 - 100: ooOoO0o / Oo0Ooo + I1ii11iIi11i + OoooooooOO
  if 100 - 100: I11i . OOooOOo - II111iiii % I11i % iIii1I11I1II1
 iIiooo , Oo00o , oOOOo0o = lisp_myrlocs
 if ( iIiooo == None ) :
  lprint ( "Suppress sending Map-Request, IPv4 RLOC not found" )
  return
  if 14 - 14: OOooOOo . IiII
 if ( Oo00o == None and O0o0Ooo0O0OO != None and O0o0Ooo0O0OO . is_ipv6 ( ) ) :
  lprint ( "Suppress sending Map-Request, IPv6 RLOC not found" )
  return
  if 75 - 75: i11iIiiIii . OoooooooOO / I11i % Ii1I
  if 13 - 13: iIii1I11I1II1 - I1IiiI % o0oOOo0O0Ooo * iIii1I11I1II1
 oOOO0oo00oOO = lisp_map_request ( )
 oOOO0oo00oOO . record_count = 1
 oOOO0oo00oOO . nonce = lisp_get_control_nonce ( )
 oOOO0oo00oOO . rloc_probe = ( O0o0Ooo0O0OO != None )
 if 99 - 99: OoooooooOO / II111iiii . I1Ii111
 if 62 - 62: OOooOOo . iII111i . I1ii11iIi11i
 if 23 - 23: O0
 if 33 - 33: ooOoO0o - iII111i % IiII
 if 67 - 67: II111iiii
 if 66 - 66: iIii1I11I1II1 / OOooOOo
 if 65 - 65: IiII . oO0o + O0 - i11iIiiIii + iIii1I11I1II1
 if ( rloc ) : rloc . last_rloc_probe_nonce = oOOO0oo00oOO . nonce
 if 82 - 82: iIii1I11I1II1 * iII111i + iIii1I11I1II1 / OoO0O00 + O0
 ooo00 = deid . is_multicast_address ( )
 if ( ooo00 ) :
  oOOO0oo00oOO . target_eid = seid
  oOOO0oo00oOO . target_group = deid
 else :
  oOOO0oo00oOO . target_eid = deid
  if 67 - 67: I1Ii111
  if 94 - 94: I1Ii111 % iIii1I11I1II1 - II111iiii . ooOoO0o + i11iIiiIii - i11iIiiIii
  if 55 - 55: OoooooooOO % iIii1I11I1II1 % I1ii11iIi11i % i1IIi
  if 46 - 46: I11i - ooOoO0o . I1IiiI
  if 36 - 36: I11i + OoO0O00 * O0 * OoOoOO00 * iII111i
  if 90 - 90: i11iIiiIii / i1IIi
  if 35 - 35: Ii1I . I11i / oO0o / OoOoOO00
  if 5 - 5: I1ii11iIi11i . o0oOOo0O0Ooo * iII111i * I1ii11iIi11i % I1Ii111
  if 83 - 83: iIii1I11I1II1 * o0oOOo0O0Ooo % i11iIiiIii + OoO0O00 . O0
 if ( oOOO0oo00oOO . rloc_probe == False ) :
  iIiIi = lisp_get_signature_eid ( )
  if ( iIiIi ) :
   oOOO0oo00oOO . signature_eid . copy_address ( iIiIi . eid )
   oOOO0oo00oOO . privkey_filename = "./lisp-sig.pem"
   if 87 - 87: II111iiii - iIii1I11I1II1 % I11i % I1IiiI . o0oOOo0O0Ooo
   if 52 - 52: i11iIiiIii . oO0o / OoooooooOO - OoO0O00
   if 7 - 7: I1IiiI * I1IiiI % OOooOOo % iIii1I11I1II1 * OoO0O00 . o0oOOo0O0Ooo
   if 32 - 32: ooOoO0o / i1IIi
   if 55 - 55: oO0o . OoOoOO00 + OoooooooOO - ooOoO0o . OoooooooOO
   if 77 - 77: I1IiiI
 if ( seid == None or ooo00 ) :
  oOOO0oo00oOO . source_eid . afi = LISP_AFI_NONE
 else :
  oOOO0oo00oOO . source_eid = seid
  if 16 - 16: I1IiiI + ooOoO0o - O0 / o0oOOo0O0Ooo
  if 36 - 36: Oo0Ooo - OoOoOO00 - II111iiii
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
 if ( O0o0Ooo0O0OO != None and lisp_nat_traversal and lisp_i_am_rtr == False ) :
  if ( O0o0Ooo0O0OO . is_private_address ( ) == False ) :
   iIiooo = lisp_get_any_translated_rloc ( )
   if 83 - 83: I1ii11iIi11i / O0 * II111iiii + IiII + Oo0Ooo
  if ( iIiooo == None ) :
   lprint ( "Suppress sending Map-Request, translated RLOC not found" )
   return
   if 99 - 99: II111iiii + O0
   if 94 - 94: ooOoO0o * ooOoO0o + o0oOOo0O0Ooo . iII111i % iIii1I11I1II1 + Ii1I
   if 88 - 88: Oo0Ooo . iII111i
   if 89 - 89: OOooOOo + I1Ii111 % i11iIiiIii + Oo0Ooo / Oo0Ooo + OoO0O00
   if 9 - 9: OoOoOO00 % i1IIi + IiII
   if 19 - 19: I1Ii111 - II111iiii / I1Ii111 + I1IiiI - OoooooooOO + o0oOOo0O0Ooo
   if 100 - 100: OoO0O00 / OoOoOO00 / OOooOOo / OoO0O00
   if 95 - 95: ooOoO0o
 if ( O0o0Ooo0O0OO == None or O0o0Ooo0O0OO . is_ipv4 ( ) ) :
  if ( lisp_nat_traversal and O0o0Ooo0O0OO == None ) :
   O0oo0Oo = lisp_get_any_translated_rloc ( )
   if ( O0oo0Oo != None ) : iIiooo = O0oo0Oo
   if 94 - 94: O0 % iII111i % I1Ii111 - IiII - oO0o - oO0o
  oOOO0oo00oOO . itr_rlocs . append ( iIiooo )
  if 40 - 40: I1IiiI / OoOoOO00 % o0oOOo0O0Ooo . ooOoO0o
 if ( O0o0Ooo0O0OO == None or O0o0Ooo0O0OO . is_ipv6 ( ) ) :
  if ( Oo00o == None or Oo00o . is_ipv6_link_local ( ) ) :
   Oo00o = None
  else :
   oOOO0oo00oOO . itr_rloc_count = 1 if ( O0o0Ooo0O0OO == None ) else 0
   oOOO0oo00oOO . itr_rlocs . append ( Oo00o )
   if 86 - 86: Ii1I / IiII . i1IIi * II111iiii / OoO0O00 - OoooooooOO
   if 50 - 50: iIii1I11I1II1 * OoO0O00 + I1IiiI % OoOoOO00 + O0 * I1Ii111
   if 78 - 78: OoOoOO00
   if 16 - 16: I1Ii111 % OoO0O00 - OoO0O00 % OoOoOO00 * OoO0O00
   if 36 - 36: OoOoOO00 * II111iiii . OoooooooOO * I11i . I11i
   if 13 - 13: I1ii11iIi11i * II111iiii
   if 93 - 93: OOooOOo / O0 - o0oOOo0O0Ooo + OoO0O00 * I1IiiI
   if 53 - 53: I1ii11iIi11i
   if 91 - 91: o0oOOo0O0Ooo - I1ii11iIi11i . i1IIi
 if ( O0o0Ooo0O0OO != None and oOOO0oo00oOO . itr_rlocs != [ ] ) :
  Ii1ii11i1i = oOOO0oo00oOO . itr_rlocs [ 0 ]
 else :
  if ( deid . is_ipv4 ( ) ) :
   Ii1ii11i1i = iIiooo
  elif ( deid . is_ipv6 ( ) ) :
   Ii1ii11i1i = Oo00o
  else :
   Ii1ii11i1i = iIiooo
   if 64 - 64: ooOoO0o
   if 23 - 23: Oo0Ooo . OoO0O00
   if 49 - 49: oO0o % i11iIiiIii * Ii1I
   if 9 - 9: Oo0Ooo - OoO0O00 + ooOoO0o / o0oOOo0O0Ooo
   if 61 - 61: O0 - i11iIiiIii * o0oOOo0O0Ooo
   if 92 - 92: Oo0Ooo + OOooOOo - i11iIiiIii
 iIIi1 = oOOO0oo00oOO . encode ( O0o0Ooo0O0OO , O00O0oo0OOo )
 oOOO0oo00oOO . print_map_request ( )
 if 26 - 26: O0 % Oo0Ooo + ooOoO0o - Ii1I . Oo0Ooo
 if 33 - 33: I1Ii111 / iII111i . I1Ii111 % II111iiii
 if 52 - 52: I1ii11iIi11i
 if 1 - 1: II111iiii + I1ii11iIi11i * OoOoOO00 % ooOoO0o - iII111i % OoooooooOO
 if 77 - 77: iII111i + o0oOOo0O0Ooo
 if 60 - 60: I1ii11iIi11i
 if ( O0o0Ooo0O0OO != None ) :
  if ( rloc . is_rloc_translated ( ) ) :
   IIII1iII = lisp_get_nat_info ( O0o0Ooo0O0OO , rloc . rloc_name )
   if ( IIII1iII and len ( lisp_sockets ) == 4 ) :
    lisp_encapsulate_rloc_probe ( lisp_sockets , O0o0Ooo0O0OO ,
 IIII1iII , iIIi1 )
    return
    if 23 - 23: iII111i % I1IiiI % I1Ii111 * oO0o * I1IiiI
    if 74 - 74: O0 / I11i . Oo0Ooo / I11i % OoO0O00 % o0oOOo0O0Ooo
    if 83 - 83: OoO0O00 - i11iIiiIii + iIii1I11I1II1
  oooOO0oOooO00 = O0o0Ooo0O0OO . print_address_no_iid ( )
  OO0i1Ii1II11 = lisp_convert_4to6 ( oooOO0oOooO00 )
  lisp_send ( lisp_sockets , OO0i1Ii1II11 , LISP_CTRL_PORT , iIIi1 )
  return
  if 52 - 52: OoooooooOO
  if 44 - 44: O0 / OoooooooOO + ooOoO0o * I1ii11iIi11i
  if 36 - 36: I1ii11iIi11i / OoO0O00 - oO0o % O0
  if 12 - 12: i1IIi * ooOoO0o / oO0o + I1IiiI / OoooooooOO
  if 86 - 86: Oo0Ooo / OoO0O00
  if 78 - 78: I1IiiI * I1IiiI
 iIIiI11II = None if lisp_i_am_rtr else seid
 if ( lisp_decent_pull_xtr_configured ( ) ) :
  iiIii = lisp_get_decent_map_resolver ( deid )
 else :
  iiIii = lisp_get_map_resolver ( None , iIIiI11II )
  if 15 - 15: Ii1I + I1IiiI
 if ( iiIii == None ) :
  lprint ( "Cannot find Map-Resolver for source-EID {}" . format ( green ( seid . print_address ( ) , False ) ) )
  if 77 - 77: O0 % I1ii11iIi11i + i11iIiiIii . OOooOOo % o0oOOo0O0Ooo + OoO0O00
  return
  if 31 - 31: ooOoO0o * I1ii11iIi11i
 iiIii . last_used = lisp_get_timestamp ( )
 iiIii . map_requests_sent += 1
 if ( iiIii . last_nonce == 0 ) : iiIii . last_nonce = oOOO0oo00oOO . nonce
 if 23 - 23: OoOoOO00 - I11i . iIii1I11I1II1
 if 87 - 87: OoO0O00 - i11iIiiIii / O0 % OOooOOo % OOooOOo * i1IIi
 if 18 - 18: IiII
 if 50 - 50: i1IIi / o0oOOo0O0Ooo * OoO0O00
 if ( seid == None ) : seid = Ii1ii11i1i
 lisp_send_ecm ( lisp_sockets , iIIi1 , seid , lisp_ephem_port , deid ,
 iiIii . map_resolver )
 if 98 - 98: I11i . II111iiii
 if 13 - 13: oO0o - I11i % II111iiii
 if 30 - 30: ooOoO0o / O0 . I11i + I1ii11iIi11i % O0 . I1IiiI
 if 25 - 25: o0oOOo0O0Ooo - ooOoO0o / I11i
 lisp_last_map_request_sent = lisp_get_timestamp ( )
 if 98 - 98: ooOoO0o * I11i + o0oOOo0O0Ooo
 if 62 - 62: i11iIiiIii
 if 49 - 49: o0oOOo0O0Ooo / OoOoOO00 + iII111i
 if 85 - 85: I1IiiI - o0oOOo0O0Ooo
 iiIii . resolve_dns_name ( )
 return
 if 86 - 86: II111iiii + Ii1I * Ii1I
 if 26 - 26: o0oOOo0O0Ooo + oO0o * i11iIiiIii / II111iiii
 if 86 - 86: Ii1I
 if 69 - 69: oO0o % o0oOOo0O0Ooo / o0oOOo0O0Ooo
 if 1 - 1: Ii1I
 if 43 - 43: o0oOOo0O0Ooo
 if 78 - 78: I1Ii111 % i1IIi * I11i
 if 59 - 59: OoOoOO00 % OoO0O00 % i11iIiiIii . II111iiii % I1ii11iIi11i + i1IIi
def lisp_send_info_request ( lisp_sockets , dest , port , device_name ) :
 if 99 - 99: I11i + IiII * I1Ii111 - OOooOOo - i1IIi
 if 77 - 77: I11i . IiII / OoO0O00 / I1Ii111
 if 8 - 8: o0oOOo0O0Ooo + iII111i / OoO0O00 * ooOoO0o - oO0o . iII111i
 if 32 - 32: OoooooooOO . I1Ii111 - I1ii11iIi11i
 iiiIIi1 = lisp_info ( )
 iiiIIi1 . nonce = lisp_get_control_nonce ( )
 if ( device_name ) : iiiIIi1 . hostname += "-" + device_name
 if 35 - 35: o0oOOo0O0Ooo + I11i % O0 % iII111i * I11i + O0
 oooOO0oOooO00 = dest . print_address_no_iid ( )
 if 11 - 11: OoOoOO00 - I1Ii111 / OOooOOo
 if 12 - 12: IiII + OoO0O00
 if 18 - 18: I1Ii111 / OoooooooOO
 if 77 - 77: oO0o % I11i + i1IIi + Oo0Ooo + I1Ii111 + OoO0O00
 if 78 - 78: O0 . oO0o
 if 72 - 72: O0 - IiII
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
 OO0OO0 = False
 if ( device_name ) :
  IiI11iiI111iI = lisp_get_host_route_next_hop ( oooOO0oOooO00 )
  if 90 - 90: II111iiii - Oo0Ooo - IiII / I1Ii111
  if 51 - 51: II111iiii * iII111i
  if 30 - 30: I1Ii111 - OoOoOO00 / OOooOOo * I1IiiI + Ii1I
  if 41 - 41: ooOoO0o . i1IIi * iIii1I11I1II1 - I1IiiI
  if 9 - 9: I11i % i1IIi / ooOoO0o % iII111i - oO0o - II111iiii
  if 29 - 29: ooOoO0o . II111iiii . i1IIi % oO0o
  if 11 - 11: OoOoOO00 . OoO0O00 % I11i * iII111i % I1Ii111 . O0
  if 17 - 17: OOooOOo / i11iIiiIii - i11iIiiIii . II111iiii . ooOoO0o
  if 38 - 38: OOooOOo . OoooooooOO . II111iiii + OoO0O00 / oO0o . OoooooooOO
  if ( port == LISP_CTRL_PORT and IiI11iiI111iI != None ) :
   while ( True ) :
    time . sleep ( .01 )
    IiI11iiI111iI = lisp_get_host_route_next_hop ( oooOO0oOooO00 )
    if ( IiI11iiI111iI == None ) : break
    if 100 - 100: OoO0O00
    if 36 - 36: oO0o + Ii1I - O0
    if 19 - 19: O0 + I1Ii111 . I1Ii111 * IiII * ooOoO0o + i1IIi
  O00OooooOo = lisp_get_default_route_next_hops ( )
  for oOOOo0o , iiiiIiiiiI in O00OooooOo :
   if ( oOOOo0o != device_name ) : continue
   if 68 - 68: IiII - OoO0O00 % O0 . iII111i % o0oOOo0O0Ooo - OoOoOO00
   if 33 - 33: Oo0Ooo % iIii1I11I1II1 - OoO0O00 - i1IIi / o0oOOo0O0Ooo
   if 6 - 6: Oo0Ooo . IiII . IiII * Ii1I
   if 1 - 1: i11iIiiIii
   if 91 - 91: I1ii11iIi11i . OoO0O00 / OoO0O00 / I1ii11iIi11i + iII111i
   if 20 - 20: o0oOOo0O0Ooo . I1Ii111 + O0
   if ( IiI11iiI111iI != iiiiIiiiiI ) :
    if ( IiI11iiI111iI != None ) :
     lisp_install_host_route ( oooOO0oOooO00 , IiI11iiI111iI , False )
     if 99 - 99: O0 / IiII . oO0o
    lisp_install_host_route ( oooOO0oOooO00 , iiiiIiiiiI , True )
    OO0OO0 = True
    if 18 - 18: OoooooooOO * OoO0O00 * I1Ii111
   break
   if 12 - 12: i11iIiiIii / iIii1I11I1II1 . I11i % I1Ii111 * ooOoO0o % ooOoO0o
   if 13 - 13: i1IIi . ooOoO0o . ooOoO0o
   if 24 - 24: iIii1I11I1II1
   if 72 - 72: i11iIiiIii + o0oOOo0O0Ooo % ooOoO0o * I1ii11iIi11i . i1IIi
   if 59 - 59: OoooooooOO - OoooooooOO - o0oOOo0O0Ooo + i1IIi % I1Ii111
   if 74 - 74: IiII * iIii1I11I1II1 - I1IiiI
 iIIi1 = iiiIIi1 . encode ( )
 iiiIIi1 . print_info ( )
 if 62 - 62: o0oOOo0O0Ooo
 if 54 - 54: iIii1I11I1II1 / OoooooooOO + o0oOOo0O0Ooo . i1IIi - OoooooooOO
 if 70 - 70: Ii1I / OoOoOO00 * Oo0Ooo
 if 32 - 32: I1Ii111 . OoOoOO00 % OoooooooOO + I1Ii111 * OoO0O00
 o0oOO0o = "(for control)" if port == LISP_CTRL_PORT else "(for data)"
 o0oOO0o = bold ( o0oOO0o , False )
 iII1ii = bold ( "{}" . format ( port ) , False )
 iiiI111I = red ( oooOO0oOooO00 , False )
 OOoO0o0 = "RTR " if port == LISP_DATA_PORT else "MS "
 lprint ( "Send Info-Request to {}{}, port {} {}" . format ( OOoO0o0 , iiiI111I , iII1ii , o0oOO0o ) )
 if 11 - 11: OoOoOO00 * o0oOOo0O0Ooo - Ii1I + OOooOOo % I1Ii111
 if 1 - 1: Ii1I * OoOoOO00 / OoOoOO00 / OoOoOO00 + OoooooooOO + Oo0Ooo
 if 91 - 91: OoOoOO00 + II111iiii / I11i * iIii1I11I1II1
 if 92 - 92: I1Ii111 - IiII / IiII
 if 42 - 42: IiII
 if 7 - 7: iIii1I11I1II1
 if ( port == LISP_CTRL_PORT ) :
  lisp_send ( lisp_sockets , dest , LISP_CTRL_PORT , iIIi1 )
 else :
  I11i1I1i1 = lisp_data_header ( )
  I11i1I1i1 . instance_id ( 0xffffff )
  I11i1I1i1 = I11i1I1i1 . encode ( )
  if ( I11i1I1i1 ) :
   iIIi1 = I11i1I1i1 + iIIi1
   if 35 - 35: IiII + O0 % I1Ii111 - I1ii11iIi11i - i1IIi
   if 100 - 100: I1Ii111 + i11iIiiIii - IiII / I1ii11iIi11i / iII111i
   if 56 - 56: iII111i
   if 91 - 91: Oo0Ooo . I11i . I1ii11iIi11i
   if 60 - 60: i11iIiiIii - OOooOOo
   if 78 - 78: I1IiiI * ooOoO0o % iIii1I11I1II1 / I1ii11iIi11i
   if 61 - 61: I1Ii111 . Ii1I + OoooooooOO
   if 98 - 98: OOooOOo . ooOoO0o . OoOoOO00 - I1Ii111 . i1IIi - iIii1I11I1II1
   if 89 - 89: II111iiii * I1ii11iIi11i - I1IiiI
   lisp_send ( lisp_sockets , dest , LISP_DATA_PORT , iIIi1 )
   if 58 - 58: Ii1I / Oo0Ooo % IiII
   if 33 - 33: II111iiii . OOooOOo % iIii1I11I1II1 - Oo0Ooo - OoOoOO00 % i11iIiiIii
   if 60 - 60: iII111i . o0oOOo0O0Ooo
   if 56 - 56: I1ii11iIi11i
   if 89 - 89: Oo0Ooo + I1ii11iIi11i * o0oOOo0O0Ooo * oO0o % O0 % OoO0O00
   if 70 - 70: o0oOOo0O0Ooo + O0 % I1IiiI
   if 56 - 56: Ii1I
 if ( OO0OO0 ) :
  lisp_install_host_route ( oooOO0oOooO00 , None , False )
  if ( IiI11iiI111iI != None ) : lisp_install_host_route ( oooOO0oOooO00 , IiI11iiI111iI , True )
  if 84 - 84: iII111i
 return
 if 21 - 21: i11iIiiIii
 if 30 - 30: OoO0O00 + OoooooooOO
 if 98 - 98: I1ii11iIi11i % I1IiiI
 if 9 - 9: o0oOOo0O0Ooo / I1Ii111 % i1IIi - OOooOOo % I1IiiI / I1ii11iIi11i
 if 66 - 66: IiII
 if 56 - 56: oO0o + OoooooooOO
 if 75 - 75: O0 % Ii1I
def lisp_process_info_request ( lisp_sockets , packet , addr_str , sport , rtr_list ) :
 if 47 - 47: OoooooooOO - OoooooooOO + OoO0O00 / iIii1I11I1II1
 if 23 - 23: iII111i / iIii1I11I1II1
 if 5 - 5: O0
 if 64 - 64: i1IIi * i1IIi . iII111i - O0 - oO0o % OoooooooOO
 iiiIIi1 = lisp_info ( )
 packet = iiiIIi1 . decode ( packet )
 if ( packet == None ) : return
 iiiIIi1 . print_info ( )
 if 14 - 14: Ii1I % OoO0O00 % I1Ii111 * O0
 if 8 - 8: I1IiiI - i11iIiiIii * I1IiiI
 if 6 - 6: O0 - OoOoOO00 - i11iIiiIii / iII111i
 if 63 - 63: OOooOOo
 if 84 - 84: i11iIiiIii * iIii1I11I1II1 % I11i % iII111i + OoooooooOO . o0oOOo0O0Ooo
 iiiIIi1 . info_reply = True
 iiiIIi1 . global_etr_rloc . store_address ( addr_str )
 iiiIIi1 . etr_port = sport
 if 78 - 78: o0oOOo0O0Ooo . iII111i + O0 / I1ii11iIi11i + I1ii11iIi11i + II111iiii
 if 96 - 96: iIii1I11I1II1 * II111iiii . iIii1I11I1II1
 if 13 - 13: Ii1I - OoOoOO00 . Ii1I
 if 7 - 7: Ii1I - I11i / I1ii11iIi11i + iII111i
 if 47 - 47: I11i * IiII / oO0o - OoooooooOO . OoooooooOO / I11i
 iiiIIi1 . private_etr_rloc . afi = LISP_AFI_NAME
 iiiIIi1 . private_etr_rloc . store_address ( iiiIIi1 . hostname )
 if 73 - 73: Ii1I . IiII % IiII
 if ( rtr_list != None ) : iiiIIi1 . rtr_list = rtr_list
 packet = iiiIIi1 . encode ( )
 iiiIIi1 . print_info ( )
 if 56 - 56: I1Ii111 + iII111i + iII111i
 if 99 - 99: o0oOOo0O0Ooo % I1ii11iIi11i / Oo0Ooo . O0 + OoO0O00 * OoOoOO00
 if 48 - 48: iIii1I11I1II1 + O0 * I11i * i11iIiiIii . Ii1I / i1IIi
 if 48 - 48: i1IIi % iIii1I11I1II1 + I1IiiI - OoOoOO00 % I11i . I1Ii111
 if 66 - 66: I1Ii111 * i11iIiiIii + I1IiiI % II111iiii
 lprint ( "Send Info-Reply to {}" . format ( red ( addr_str , False ) ) )
 OO0i1Ii1II11 = lisp_convert_4to6 ( addr_str )
 lisp_send ( lisp_sockets , OO0i1Ii1II11 , sport , packet )
 if 47 - 47: II111iiii % o0oOOo0O0Ooo
 if 26 - 26: I1ii11iIi11i / I11i / Oo0Ooo / i1IIi + O0 * ooOoO0o
 if 53 - 53: IiII / II111iiii / oO0o % O0 / I1Ii111
 if 91 - 91: oO0o * OoOoOO00 + O0 % Oo0Ooo
 if 62 - 62: iIii1I11I1II1 - i11iIiiIii % iIii1I11I1II1 . ooOoO0o / OOooOOo * OoOoOO00
 II1II1i1 = lisp_info_source ( iiiIIi1 . hostname , addr_str , sport )
 II1II1i1 . cache_address_for_info_source ( )
 return
 if 6 - 6: Ii1I
 if 96 - 96: I1IiiI
 if 30 - 30: oO0o . I1Ii111 * i11iIiiIii - II111iiii * I11i
 if 67 - 67: IiII
 if 87 - 87: I1Ii111 - iII111i * I11i
 if 74 - 74: Ii1I - OoOoOO00 + i11iIiiIii - II111iiii - i11iIiiIii . ooOoO0o
 if 83 - 83: I1Ii111 % ooOoO0o + OoooooooOO
 if 50 - 50: i11iIiiIii % I1IiiI * iII111i / Ii1I
def lisp_get_signature_eid ( ) :
 for iIiIi in lisp_db_list :
  if ( iIiIi . signature_eid ) : return ( iIiIi )
  if 12 - 12: iII111i / OoO0O00 - II111iiii + Oo0Ooo
 return ( None )
 if 78 - 78: i1IIi
 if 25 - 25: Ii1I * II111iiii / OoOoOO00
 if 86 - 86: i1IIi + I1IiiI + I1Ii111 % II111iiii . IiII - iIii1I11I1II1
 if 54 - 54: i11iIiiIii . Ii1I % I1IiiI . I1Ii111 . OoooooooOO
 if 49 - 49: OOooOOo % I11i - OOooOOo + Ii1I . I1ii11iIi11i + ooOoO0o
 if 15 - 15: i11iIiiIii
 if 85 - 85: I1Ii111 + iII111i - oO0o
 if 59 - 59: IiII . oO0o / i11iIiiIii . I1Ii111
def lisp_get_any_translated_port ( ) :
 for iIiIi in lisp_db_list :
  for OOO0OOO000oOO0 in iIiIi . rloc_set :
   if ( OOO0OOO000oOO0 . translated_rloc . is_null ( ) ) : continue
   return ( OOO0OOO000oOO0 . translated_port )
   if 64 - 64: OoOoOO00
   if 20 - 20: OoOoOO00 / O0 * OOooOOo % I11i + OoO0O00 + o0oOOo0O0Ooo
 return ( None )
 if 51 - 51: Ii1I - OoOoOO00 / i11iIiiIii + O0
 if 71 - 71: ooOoO0o
 if 35 - 35: OoOoOO00
 if 55 - 55: iII111i - o0oOOo0O0Ooo + IiII * II111iiii
 if 6 - 6: I1Ii111 / i1IIi / IiII . o0oOOo0O0Ooo
 if 69 - 69: ooOoO0o - OoOoOO00 . I1IiiI . I11i + OoOoOO00 / i11iIiiIii
 if 20 - 20: OoO0O00 . OoooooooOO - ooOoO0o . I11i / Oo0Ooo
 if 89 - 89: iIii1I11I1II1 . ooOoO0o
 if 82 - 82: OoOoOO00 - II111iiii . OoO0O00 * ooOoO0o
def lisp_get_any_translated_rloc ( ) :
 for iIiIi in lisp_db_list :
  for OOO0OOO000oOO0 in iIiIi . rloc_set :
   if ( OOO0OOO000oOO0 . translated_rloc . is_null ( ) ) : continue
   return ( OOO0OOO000oOO0 . translated_rloc )
   if 78 - 78: OoOoOO00 % oO0o
   if 39 - 39: iIii1I11I1II1
 return ( None )
 if 72 - 72: II111iiii + I1Ii111 / Ii1I * iIii1I11I1II1
 if 95 - 95: OoooooooOO + OOooOOo + II111iiii + IiII + OoO0O00
 if 86 - 86: II111iiii / iII111i - I1ii11iIi11i
 if 65 - 65: I1ii11iIi11i + OoOoOO00
 if 43 - 43: O0 + I11i % II111iiii
 if 56 - 56: IiII + Oo0Ooo . IiII % iIii1I11I1II1 % ooOoO0o % ooOoO0o
 if 70 - 70: ooOoO0o / i1IIi - I11i - i11iIiiIii
def lisp_get_all_translated_rlocs ( ) :
 OO0oo0o0 = [ ]
 for iIiIi in lisp_db_list :
  for OOO0OOO000oOO0 in iIiIi . rloc_set :
   if ( OOO0OOO000oOO0 . is_rloc_translated ( ) == False ) : continue
   o00Ooo0 = OOO0OOO000oOO0 . translated_rloc . print_address_no_iid ( )
   OO0oo0o0 . append ( o00Ooo0 )
   if 8 - 8: oO0o . OoO0O00 / IiII - oO0o / OoOoOO00 - i1IIi
   if 48 - 48: OoooooooOO + II111iiii
 return ( OO0oo0o0 )
 if 46 - 46: I1IiiI - II111iiii * OoO0O00 % OoooooooOO / OoO0O00 + II111iiii
 if 92 - 92: OoOoOO00 - iIii1I11I1II1
 if 10 - 10: iII111i - I1IiiI / I1ii11iIi11i - i1IIi - II111iiii % i11iIiiIii
 if 2 - 2: ooOoO0o % ooOoO0o
 if 94 - 94: ooOoO0o / OoooooooOO * i1IIi . Oo0Ooo * i11iIiiIii
 if 5 - 5: iIii1I11I1II1 / oO0o - Oo0Ooo - I1IiiI + iIii1I11I1II1
 if 63 - 63: iIii1I11I1II1 / ooOoO0o + O0 - o0oOOo0O0Ooo
 if 31 - 31: Ii1I
def lisp_update_default_routes ( map_resolver , iid , rtr_list ) :
 o00 = ( os . getenv ( "LISP_RTR_BEHIND_NAT" ) != None )
 if 76 - 76: OoO0O00 / II111iiii
 OOiI1I1 = { }
 for Oo0O0 in rtr_list :
  if ( Oo0O0 == None ) : continue
  o00Ooo0 = rtr_list [ Oo0O0 ]
  if ( o00 and o00Ooo0 . is_private_address ( ) ) : continue
  OOiI1I1 [ Oo0O0 ] = o00Ooo0
  if 61 - 61: i1IIi / Ii1I . OoOoOO00 + i11iIiiIii
 rtr_list = OOiI1I1
 if 69 - 69: i11iIiiIii - iIii1I11I1II1
 iIII1 = [ ]
 for ooo0O0O0oo0 in [ LISP_AFI_IPV4 , LISP_AFI_IPV6 , LISP_AFI_MAC ] :
  if ( ooo0O0O0oo0 == LISP_AFI_MAC and lisp_l2_overlay == False ) : break
  if 100 - 100: OoOoOO00 % iII111i * ooOoO0o . O0
  if 37 - 37: I1ii11iIi11i
  if 24 - 24: O0 . I1Ii111 * i11iIiiIii
  if 84 - 84: ooOoO0o / I1ii11iIi11i - o0oOOo0O0Ooo . OoooooooOO * iIii1I11I1II1
  if 16 - 16: I11i % O0
  Oo0OOoO0oo0oO = lisp_address ( ooo0O0O0oo0 , "" , 0 , iid )
  Oo0OOoO0oo0oO . make_default_route ( Oo0OOoO0oo0oO )
  oOooO0Oo0Oo0 = lisp_map_cache . lookup_cache ( Oo0OOoO0oo0oO , True )
  if ( oOooO0Oo0Oo0 ) :
   if ( oOooO0Oo0Oo0 . checkpoint_entry ) :
    lprint ( "Updating checkpoint entry for {}" . format ( green ( oOooO0Oo0Oo0 . print_eid_tuple ( ) , False ) ) )
    if 56 - 56: Ii1I * OoOoOO00 . i1IIi
   elif ( oOooO0Oo0Oo0 . do_rloc_sets_match ( rtr_list . values ( ) ) ) :
    continue
    if 15 - 15: I1Ii111
   oOooO0Oo0Oo0 . delete_cache ( )
   if 64 - 64: OOooOOo * Oo0Ooo
   if 96 - 96: Oo0Ooo / I1ii11iIi11i * iIii1I11I1II1 / iII111i
  iIII1 . append ( [ Oo0OOoO0oo0oO , "" ] )
  if 18 - 18: I1Ii111
  if 29 - 29: i1IIi - I1IiiI / i1IIi
  if 64 - 64: IiII
  if 69 - 69: OOooOOo . I1IiiI
  iiI = lisp_address ( ooo0O0O0oo0 , "" , 0 , iid )
  iiI . make_default_multicast_route ( iiI )
  I1Iii11iI1111 = lisp_map_cache . lookup_cache ( iiI , True )
  if ( I1Iii11iI1111 ) : I1Iii11iI1111 = I1Iii11iI1111 . source_cache . lookup_cache ( Oo0OOoO0oo0oO , True )
  if ( I1Iii11iI1111 ) : I1Iii11iI1111 . delete_cache ( )
  if 52 - 52: I11i
  iIII1 . append ( [ Oo0OOoO0oo0oO , iiI ] )
  if 71 - 71: I1Ii111 / II111iiii - OoooooooOO % i1IIi + OoOoOO00 % OoooooooOO
 if ( len ( iIII1 ) == 0 ) : return
 if 52 - 52: Ii1I . OoOoOO00 / o0oOOo0O0Ooo / iII111i
 if 83 - 83: OoO0O00 - Oo0Ooo + I1Ii111 . I1IiiI
 if 78 - 78: I11i / ooOoO0o . OoOoOO00 * i1IIi
 if 15 - 15: i1IIi . II111iiii * OoOoOO00 / Oo0Ooo
 I111i = [ ]
 for OOoO0o0 in rtr_list :
  o0oOo0o0o = rtr_list [ OOoO0o0 ]
  OOO0OOO000oOO0 = lisp_rloc ( )
  OOO0OOO000oOO0 . rloc . copy_address ( o0oOo0o0o )
  OOO0OOO000oOO0 . priority = 254
  OOO0OOO000oOO0 . mpriority = 255
  OOO0OOO000oOO0 . rloc_name = "RTR"
  I111i . append ( OOO0OOO000oOO0 )
  if 91 - 91: iIii1I11I1II1 / II111iiii * I1Ii111
  if 70 - 70: Oo0Ooo + Oo0Ooo + IiII . O0
 for Oo0OOoO0oo0oO in iIII1 :
  oOooO0Oo0Oo0 = lisp_mapping ( Oo0OOoO0oo0oO [ 0 ] , Oo0OOoO0oo0oO [ 1 ] , I111i )
  oOooO0Oo0Oo0 . mapping_source = map_resolver
  oOooO0Oo0Oo0 . map_cache_ttl = LISP_MR_TTL * 60
  oOooO0Oo0Oo0 . add_cache ( )
  lprint ( "Add {} to map-cache with RTR RLOC-set: {}" . format ( green ( oOooO0Oo0Oo0 . print_eid_tuple ( ) , False ) , rtr_list . keys ( ) ) )
  if 63 - 63: o0oOOo0O0Ooo
  I111i = copy . deepcopy ( I111i )
  if 91 - 91: Oo0Ooo / oO0o / I1IiiI % I1IiiI . I1ii11iIi11i
 return
 if 12 - 12: i1IIi % O0 / OoooooooOO / i11iIiiIii - OOooOOo
 if 66 - 66: O0
 if 95 - 95: ooOoO0o % IiII
 if 64 - 64: Ii1I . oO0o - I1ii11iIi11i * OoO0O00 % i1IIi
 if 76 - 76: oO0o
 if 42 - 42: OoO0O00 * i1IIi
 if 60 - 60: I1IiiI * I1Ii111 + oO0o - Ii1I
 if 58 - 58: i11iIiiIii . o0oOOo0O0Ooo - i1IIi - I1IiiI * i1IIi % I1Ii111
 if 37 - 37: I11i
 if 61 - 61: OoooooooOO % iIii1I11I1II1 % O0 % I1Ii111 / Oo0Ooo . I1IiiI
def lisp_process_info_reply ( source , packet , store ) :
 if 20 - 20: ooOoO0o - I1Ii111
 if 97 - 97: O0
 if 56 - 56: Ii1I * I1IiiI * ooOoO0o
 if 39 - 39: iII111i % Ii1I * iIii1I11I1II1 - Ii1I - I1Ii111
 iiiIIi1 = lisp_info ( )
 packet = iiiIIi1 . decode ( packet )
 if ( packet == None ) : return ( [ None , None , False ] )
 if 60 - 60: i11iIiiIii + i11iIiiIii - OoooooooOO + OoooooooOO
 iiiIIi1 . print_info ( )
 if 5 - 5: o0oOOo0O0Ooo
 if 78 - 78: OOooOOo * O0 * II111iiii % OoOoOO00
 if 12 - 12: Oo0Ooo . o0oOOo0O0Ooo - i1IIi - oO0o % IiII . I11i
 if 17 - 17: i1IIi % OoO0O00 + i11iIiiIii % I1Ii111 * ooOoO0o . I1ii11iIi11i
 oo00ooOo = False
 for OOoO0o0 in iiiIIi1 . rtr_list :
  oooOO0oOooO00 = OOoO0o0 . print_address_no_iid ( )
  if ( lisp_rtr_list . has_key ( oooOO0oOooO00 ) ) :
   if ( lisp_register_all_rtrs == False ) : continue
   if ( lisp_rtr_list [ oooOO0oOooO00 ] != None ) : continue
   if 92 - 92: I1ii11iIi11i * I1IiiI % i11iIiiIii + oO0o * I1ii11iIi11i % OOooOOo
  oo00ooOo = True
  lisp_rtr_list [ oooOO0oOooO00 ] = OOoO0o0
  if 96 - 96: I1Ii111 + i1IIi % O0 * I1IiiI * I11i . Ii1I
  if 71 - 71: i1IIi . I1IiiI
  if 81 - 81: O0
  if 89 - 89: oO0o % OoOoOO00 + Oo0Ooo
  if 16 - 16: Ii1I . I1Ii111
 if ( lisp_i_am_itr and oo00ooOo ) :
  if ( lisp_iid_to_interface == { } ) :
   lisp_update_default_routes ( source , lisp_default_iid , lisp_rtr_list )
  else :
   for iiI1iii in lisp_iid_to_interface . keys ( ) :
    lisp_update_default_routes ( source , int ( iiI1iii ) , lisp_rtr_list )
    if 38 - 38: I1IiiI / II111iiii * OoOoOO00 / I1Ii111
    if 80 - 80: I1ii11iIi11i / ooOoO0o * ooOoO0o . Oo0Ooo
    if 44 - 44: Ii1I * i1IIi % OoOoOO00 . OoOoOO00
    if 16 - 16: Oo0Ooo / i1IIi / iIii1I11I1II1 / iIii1I11I1II1 % o0oOOo0O0Ooo / I1ii11iIi11i
    if 11 - 11: I1IiiI
    if 45 - 45: OOooOOo / i1IIi * IiII * I1Ii111
    if 34 - 34: ooOoO0o / iIii1I11I1II1 . iII111i
 if ( store == False ) :
  return ( [ iiiIIi1 . global_etr_rloc , iiiIIi1 . etr_port , oo00ooOo ] )
  if 91 - 91: OoO0O00
  if 8 - 8: oO0o
  if 96 - 96: IiII
  if 37 - 37: Ii1I % i11iIiiIii + iIii1I11I1II1 % Oo0Ooo - iIii1I11I1II1
  if 26 - 26: o0oOOo0O0Ooo . i1IIi
  if 62 - 62: IiII * I1ii11iIi11i % iIii1I11I1II1 / II111iiii - OoO0O00
 for iIiIi in lisp_db_list :
  for OOO0OOO000oOO0 in iIiIi . rloc_set :
   Oo0O0 = OOO0OOO000oOO0 . rloc
   iiiii11I1 = OOO0OOO000oOO0 . interface
   if ( iiiii11I1 == None ) :
    if ( Oo0O0 . is_null ( ) ) : continue
    if ( Oo0O0 . is_local ( ) == False ) : continue
    if ( iiiIIi1 . private_etr_rloc . is_null ( ) == False and
 Oo0O0 . is_exact_match ( iiiIIi1 . private_etr_rloc ) == False ) :
     continue
     if 52 - 52: iII111i . I11i - I11i + oO0o + iIii1I11I1II1
   elif ( iiiIIi1 . private_etr_rloc . is_dist_name ( ) ) :
    i11Ii1i1iII = iiiIIi1 . private_etr_rloc . address
    if ( i11Ii1i1iII != OOO0OOO000oOO0 . rloc_name ) : continue
    if 83 - 83: I11i * iIii1I11I1II1 + OoOoOO00
    if 81 - 81: ooOoO0o * OOooOOo / OoO0O00 + I1ii11iIi11i % I1Ii111
   OO0OO0O = green ( iIiIi . eid . print_prefix ( ) , False )
   iII1II = red ( Oo0O0 . print_address_no_iid ( ) , False )
   if 37 - 37: i11iIiiIii - OoooooooOO - OoOoOO00 * oO0o / Ii1I
   OooOo = iiiIIi1 . global_etr_rloc . is_exact_match ( Oo0O0 )
   if ( OOO0OOO000oOO0 . translated_port == 0 and OooOo ) :
    lprint ( "No NAT for {} ({}), EID-prefix {}" . format ( iII1II ,
 iiiii11I1 , OO0OO0O ) )
    continue
    if 82 - 82: i11iIiiIii * OoOoOO00 . i1IIi + IiII * ooOoO0o
    if 75 - 75: iIii1I11I1II1 / IiII / II111iiii . I11i
    if 23 - 23: OOooOOo . ooOoO0o - iII111i % Ii1I . I1ii11iIi11i + IiII
    if 81 - 81: I11i
    if 5 - 5: OoooooooOO
   I11IiiI = iiiIIi1 . global_etr_rloc
   iiIII1Ii = OOO0OOO000oOO0 . translated_rloc
   if ( iiIII1Ii . is_exact_match ( I11IiiI ) and
 iiiIIi1 . etr_port == OOO0OOO000oOO0 . translated_port ) : continue
   if 13 - 13: Oo0Ooo
   lprint ( "Store translation {}:{} for {} ({}), EID-prefix {}" . format ( red ( iiiIIi1 . global_etr_rloc . print_address_no_iid ( ) , False ) ,
   # o0oOOo0O0Ooo
 iiiIIi1 . etr_port , iII1II , iiiii11I1 , OO0OO0O ) )
   if 29 - 29: Oo0Ooo . Oo0Ooo * OoO0O00 % Ii1I - ooOoO0o
   OOO0OOO000oOO0 . store_translated_rloc ( iiiIIi1 . global_etr_rloc ,
 iiiIIi1 . etr_port )
   if 67 - 67: I1IiiI % O0 + I1IiiI * I1Ii111 * OoOoOO00 * II111iiii
   if 79 - 79: I1IiiI
 return ( [ iiiIIi1 . global_etr_rloc , iiiIIi1 . etr_port , oo00ooOo ] )
 if 37 - 37: I1Ii111 + Ii1I
 if 50 - 50: i11iIiiIii
 if 57 - 57: O0 * i1IIi - I1IiiI
 if 48 - 48: IiII / iIii1I11I1II1
 if 20 - 20: oO0o / OoooooooOO
 if 95 - 95: Oo0Ooo . i11iIiiIii
 if 50 - 50: iII111i . i11iIiiIii - i1IIi
 if 24 - 24: i11iIiiIii % iII111i . oO0o
def lisp_test_mr ( lisp_sockets , port ) :
 return
 lprint ( "Test Map-Resolvers" )
 if 44 - 44: II111iiii - OoO0O00 + i11iIiiIii
 oOOOO = lisp_address ( LISP_AFI_IPV4 , "" , 0 , 0 )
 IIi11i1iIi = lisp_address ( LISP_AFI_IPV6 , "" , 0 , 0 )
 if 62 - 62: oO0o - I1ii11iIi11i
 if 16 - 16: I1IiiI . OoO0O00 * Ii1I / oO0o
 if 27 - 27: iII111i - ooOoO0o - i11iIiiIii
 if 39 - 39: i11iIiiIii / oO0o
 oOOOO . store_address ( "10.0.0.1" )
 lisp_send_map_request ( lisp_sockets , port , None , oOOOO , None )
 oOOOO . store_address ( "192.168.0.1" )
 lisp_send_map_request ( lisp_sockets , port , None , oOOOO , None )
 if 71 - 71: I1Ii111 * iIii1I11I1II1 - I1Ii111
 if 87 - 87: I1IiiI / Ii1I
 if 54 - 54: OoooooooOO / Ii1I
 if 26 - 26: o0oOOo0O0Ooo + OoO0O00
 IIi11i1iIi . store_address ( "0100::1" )
 lisp_send_map_request ( lisp_sockets , port , None , IIi11i1iIi , None )
 IIi11i1iIi . store_address ( "8000::1" )
 lisp_send_map_request ( lisp_sockets , port , None , IIi11i1iIi , None )
 if 59 - 59: Ii1I * IiII
 if 64 - 64: ooOoO0o . Oo0Ooo - OoOoOO00
 if 66 - 66: OoOoOO00
 if 83 - 83: OOooOOo . IiII
 o0OOo = threading . Timer ( LISP_TEST_MR_INTERVAL , lisp_test_mr ,
 [ lisp_sockets , port ] )
 o0OOo . start ( )
 return
 if 4 - 4: OoooooooOO - I1Ii111 . I11i - OoOoOO00 . ooOoO0o
 if 49 - 49: i11iIiiIii % i11iIiiIii % i11iIiiIii % iII111i
 if 68 - 68: I1Ii111 - OoO0O00 % OoO0O00 % OOooOOo - OoO0O00
 if 3 - 3: iIii1I11I1II1 + iIii1I11I1II1 + OoO0O00
 if 59 - 59: iII111i
 if 7 - 7: o0oOOo0O0Ooo * OoooooooOO - Ii1I * II111iiii % I1Ii111
 if 82 - 82: OoOoOO00 - OoOoOO00 + iIii1I11I1II1 + o0oOOo0O0Ooo + IiII - o0oOOo0O0Ooo
 if 65 - 65: I1Ii111 + OOooOOo
 if 97 - 97: oO0o % OoOoOO00 * oO0o % II111iiii + iIii1I11I1II1
 if 11 - 11: ooOoO0o . o0oOOo0O0Ooo
 if 94 - 94: ooOoO0o . oO0o * OoooooooOO % oO0o
 if 77 - 77: ooOoO0o % I1IiiI
 if 26 - 26: o0oOOo0O0Ooo
def lisp_update_local_rloc ( rloc ) :
 if ( rloc . interface == None ) : return
 if 72 - 72: I1IiiI
 o00Ooo0 = lisp_get_interface_address ( rloc . interface )
 if ( o00Ooo0 == None ) : return
 if 90 - 90: ooOoO0o
 Oo0o0o = rloc . rloc . print_address_no_iid ( )
 oO0OO00000o = o00Ooo0 . print_address_no_iid ( )
 if 19 - 19: IiII . I1IiiI
 if ( Oo0o0o == oO0OO00000o ) : return
 if 82 - 82: I11i + II111iiii % oO0o - I1ii11iIi11i
 lprint ( "Local interface address changed on {} from {} to {}" . format ( rloc . interface , Oo0o0o , oO0OO00000o ) )
 if 54 - 54: i1IIi - I11i % Oo0Ooo / i11iIiiIii
 if 83 - 83: I1IiiI * OoooooooOO % I1IiiI - oO0o
 rloc . rloc . copy_address ( o00Ooo0 )
 lisp_myrlocs [ 0 ] = o00Ooo0
 return
 if 93 - 93: I1ii11iIi11i - OOooOOo - II111iiii * OoO0O00 . O0 - ooOoO0o
 if 53 - 53: OoO0O00 / i11iIiiIii . OoooooooOO
 if 84 - 84: I1ii11iIi11i
 if 49 - 49: iII111i + o0oOOo0O0Ooo % I1ii11iIi11i . O0 % OoooooooOO . o0oOOo0O0Ooo
 if 3 - 3: i11iIiiIii - i1IIi * o0oOOo0O0Ooo / OoOoOO00 % Oo0Ooo
 if 65 - 65: OoooooooOO + iII111i - i11iIiiIii - IiII + oO0o
 if 67 - 67: i1IIi * I1Ii111 * O0
 if 16 - 16: OoO0O00 + iII111i + i1IIi + I1ii11iIi11i - I1IiiI
def lisp_update_encap_port ( mc ) :
 for Oo0O0 in mc . rloc_set :
  IIII1iII = lisp_get_nat_info ( Oo0O0 . rloc , Oo0O0 . rloc_name )
  if ( IIII1iII == None ) : continue
  if ( Oo0O0 . translated_port == IIII1iII . port ) : continue
  if 88 - 88: oO0o % iII111i + I1ii11iIi11i - II111iiii . I11i
  lprint ( ( "Encap-port changed from {} to {} for RLOC {}, " + "EID-prefix {}" ) . format ( Oo0O0 . translated_port , IIII1iII . port ,
  # o0oOOo0O0Ooo * I1ii11iIi11i
 red ( Oo0O0 . rloc . print_address_no_iid ( ) , False ) ,
 green ( mc . print_eid_tuple ( ) , False ) ) )
  if 57 - 57: IiII * OOooOOo
  Oo0O0 . store_translated_rloc ( Oo0O0 . rloc , IIII1iII . port )
  if 28 - 28: I1Ii111
 return
 if 27 - 27: OoOoOO00 - OoO0O00 - iIii1I11I1II1 + OoOoOO00 - I11i
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
def lisp_timeout_map_cache_entry ( mc , delete_list ) :
 if ( mc . map_cache_ttl == None ) :
  lisp_update_encap_port ( mc )
  return ( [ True , delete_list ] )
  if 28 - 28: oO0o * iII111i + IiII
  if 73 - 73: OoooooooOO
  if 45 - 45: IiII + I1IiiI * I1Ii111
  if 82 - 82: OOooOOo / I11i % Ii1I * OoOoOO00
  if 88 - 88: o0oOOo0O0Ooo % OoO0O00
 if ( mc . action == LISP_NO_ACTION ) :
  I1IIiIiiiii1 = lisp_get_timestamp ( )
  if ( mc . last_refresh_time + mc . map_cache_ttl > I1IIiIiiiii1 ) :
   lisp_update_encap_port ( mc )
   return ( [ True , delete_list ] )
   if 30 - 30: II111iiii / Oo0Ooo % Oo0Ooo + O0 / iIii1I11I1II1 . OoO0O00
   if 43 - 43: I1IiiI % OoOoOO00 * O0 + o0oOOo0O0Ooo
   if 97 - 97: iIii1I11I1II1 + O0
   if 41 - 41: OoOoOO00 - II111iiii
   if 46 - 46: OOooOOo
   if 73 - 73: iII111i - IiII + II111iiii
 Oo = lisp_print_elapsed ( mc . last_refresh_time )
 OO0oO0 = mc . print_eid_tuple ( )
 lprint ( "Map-cache entry for EID-prefix {} has {}, had uptime of {}" . format ( green ( OO0oO0 , False ) , bold ( "timed out" , False ) , Oo ) )
 if 58 - 58: Oo0Ooo % I1IiiI
 if 78 - 78: iII111i / iIii1I11I1II1 * IiII . ooOoO0o / I1Ii111 % I11i
 if 14 - 14: II111iiii % iIii1I11I1II1 - I1IiiI % i11iIiiIii . OOooOOo * I1ii11iIi11i
 if 12 - 12: I1ii11iIi11i % I1ii11iIi11i . OoO0O00 . OoOoOO00
 if 73 - 73: I1ii11iIi11i * i1IIi * Oo0Ooo / O0
 delete_list . append ( mc )
 return ( [ True , delete_list ] )
 if 1 - 1: iII111i * OOooOOo + II111iiii / Ii1I . I1ii11iIi11i
 if 61 - 61: oO0o % OoOoOO00 % ooOoO0o . I1Ii111 / OoO0O00
 if 21 - 21: IiII
 if 15 - 15: OoOoOO00 % O0 - OOooOOo - oO0o . iII111i . OoO0O00
 if 52 - 52: II111iiii * o0oOOo0O0Ooo
 if 95 - 95: I1Ii111 - OoooooooOO
 if 99 - 99: OoooooooOO % IiII . I11i + OoooooooOO
 if 57 - 57: Ii1I / I1IiiI * i1IIi
def lisp_timeout_map_cache_walk ( mc , parms ) :
 iiiI = parms [ 0 ]
 I11i111 = parms [ 1 ]
 if 63 - 63: II111iiii
 if 44 - 44: Oo0Ooo * OoO0O00 * OoOoOO00 / Ii1I / iII111i * Ii1I
 if 11 - 11: OoOoOO00 - OoOoOO00 % oO0o
 if 3 - 3: I1IiiI - OoooooooOO % iIii1I11I1II1 + I1Ii111 + OoOoOO00
 if ( mc . group . is_null ( ) ) :
  OO0OoOOOOo , iiiI = lisp_timeout_map_cache_entry ( mc , iiiI )
  if ( iiiI == [ ] or mc != iiiI [ - 1 ] ) :
   I11i111 = lisp_write_checkpoint_entry ( I11i111 , mc )
   if 71 - 71: i1IIi % O0 % ooOoO0o
  return ( [ OO0OoOOOOo , parms ] )
  if 24 - 24: O0
  if 88 - 88: OoooooooOO / Oo0Ooo / oO0o
 if ( mc . source_cache == None ) : return ( [ True , parms ] )
 if 99 - 99: I1Ii111 % OoOoOO00 % IiII - Ii1I
 if 79 - 79: ooOoO0o + Oo0Ooo
 if 80 - 80: OoOoOO00 % OoO0O00 . OoO0O00 * OoO0O00 * O0
 if 18 - 18: II111iiii . o0oOOo0O0Ooo + OoO0O00
 if 69 - 69: OoO0O00 . ooOoO0o * ooOoO0o * iIii1I11I1II1
 parms = mc . source_cache . walk_cache ( lisp_timeout_map_cache_entry , parms )
 return ( [ True , parms ] )
 if 8 - 8: iII111i . oO0o . OOooOOo + iII111i . Ii1I
 if 46 - 46: OoO0O00
 if 21 - 21: iIii1I11I1II1 - iII111i
 if 15 - 15: O0 + iII111i + i11iIiiIii
 if 31 - 31: iIii1I11I1II1 * iIii1I11I1II1 . I11i
 if 52 - 52: i11iIiiIii / oO0o / IiII
 if 84 - 84: I11i . oO0o + ooOoO0o
def lisp_timeout_map_cache ( lisp_map_cache ) :
 o00O = [ [ ] , [ ] ]
 o00O = lisp_map_cache . walk_cache ( lisp_timeout_map_cache_walk , o00O )
 if 75 - 75: I1Ii111
 if 97 - 97: ooOoO0o % Oo0Ooo . o0oOOo0O0Ooo
 if 22 - 22: O0 % I11i + OoO0O00 - iII111i + I1IiiI . O0
 if 73 - 73: ooOoO0o + O0 - I11i . I1IiiI + OOooOOo
 if 36 - 36: I11i % OoO0O00 * OoOoOO00 - I1Ii111
 iiiI = o00O [ 0 ]
 for oOooO0Oo0Oo0 in iiiI : oOooO0Oo0Oo0 . delete_cache ( )
 if 16 - 16: ooOoO0o % OOooOOo . OoO0O00 % II111iiii . iIii1I11I1II1
 if 21 - 21: oO0o + II111iiii / OoOoOO00 * I11i
 if 90 - 90: OoOoOO00 % OoOoOO00 + I11i
 if 70 - 70: I1IiiI . ooOoO0o / I11i / OoO0O00
 I11i111 = o00O [ 1 ]
 lisp_checkpoint ( I11i111 )
 return
 if 40 - 40: oO0o % iIii1I11I1II1 * iIii1I11I1II1 / Oo0Ooo * OoO0O00
 if 61 - 61: OOooOOo
 if 80 - 80: I1ii11iIi11i
 if 6 - 6: I1ii11iIi11i + OOooOOo % ooOoO0o
 if 65 - 65: iIii1I11I1II1 % i1IIi / I1IiiI / oO0o % ooOoO0o / I11i
 if 2 - 2: I1ii11iIi11i
 if 90 - 90: II111iiii * I1Ii111 . ooOoO0o - I1ii11iIi11i % I11i * o0oOOo0O0Ooo
 if 85 - 85: iIii1I11I1II1
 if 76 - 76: i11iIiiIii % I1IiiI / I11i
 if 42 - 42: o0oOOo0O0Ooo . I1IiiI + I11i . OoOoOO00 - O0 / Ii1I
 if 66 - 66: IiII + OoOoOO00 + I1IiiI + i1IIi + OoooooooOO % I1IiiI
 if 80 - 80: iII111i / O0 % OoooooooOO / Oo0Ooo
 if 75 - 75: ooOoO0o
 if 72 - 72: oO0o . OoooooooOO % ooOoO0o % OoO0O00 * oO0o * OoO0O00
 if 14 - 14: I11i / I11i
 if 90 - 90: O0 * OOooOOo / oO0o . Oo0Ooo * I11i
def lisp_store_nat_info ( hostname , rloc , port ) :
 oooOO0oOooO00 = rloc . print_address_no_iid ( )
 oOO00 = "{} NAT state for {}, RLOC {}, port {}" . format ( "{}" ,
 blue ( hostname , False ) , red ( oooOO0oOooO00 , False ) , port )
 if 70 - 70: OOooOOo / Ii1I - ooOoO0o + OoooooooOO / OoO0O00 - i11iIiiIii
 iiIii1i = lisp_nat_info ( oooOO0oOooO00 , hostname , port )
 if 4 - 4: I1Ii111
 if ( lisp_nat_state_info . has_key ( hostname ) == False ) :
  lisp_nat_state_info [ hostname ] = [ iiIii1i ]
  lprint ( oOO00 . format ( "Store initial" ) )
  return ( True )
  if 15 - 15: I11i % I11i / iIii1I11I1II1 - i11iIiiIii / i1IIi
  if 9 - 9: OoooooooOO
  if 71 - 71: Ii1I
  if 59 - 59: i1IIi * ooOoO0o . iIii1I11I1II1
  if 87 - 87: ooOoO0o % I1ii11iIi11i . I1IiiI
  if 42 - 42: iII111i % i11iIiiIii % o0oOOo0O0Ooo . O0 % iII111i
 IIII1iII = lisp_nat_state_info [ hostname ] [ 0 ]
 if ( IIII1iII . address == oooOO0oOooO00 and IIII1iII . port == port ) :
  IIII1iII . uptime = lisp_get_timestamp ( )
  lprint ( oOO00 . format ( "Refresh existing" ) )
  return ( False )
  if 72 - 72: Oo0Ooo . Oo0Ooo . IiII . Oo0Ooo
  if 80 - 80: I1Ii111 + IiII + O0 - I1Ii111 . iIii1I11I1II1
  if 53 - 53: OoO0O00 / i11iIiiIii * I1Ii111
  if 62 - 62: oO0o / Oo0Ooo / IiII + I11i * ooOoO0o
  if 84 - 84: ooOoO0o + OoOoOO00 * I1ii11iIi11i % OoooooooOO . O0
  if 27 - 27: OoO0O00 * OoooooooOO - II111iiii / o0oOOo0O0Ooo
  if 76 - 76: I11i % I1Ii111 % iII111i + IiII * iII111i + OoOoOO00
 o0o = None
 for IIII1iII in lisp_nat_state_info [ hostname ] :
  if ( IIII1iII . address == oooOO0oOooO00 and IIII1iII . port == port ) :
   o0o = IIII1iII
   break
   if 96 - 96: oO0o % I1Ii111 . I11i - I11i + OoO0O00 - oO0o
   if 25 - 25: IiII % O0 - I1IiiI + I1Ii111 . i11iIiiIii
   if 50 - 50: OOooOOo * OoooooooOO . OoO0O00 . oO0o
 if ( o0o == None ) :
  lprint ( oOO00 . format ( "Store new" ) )
 else :
  lisp_nat_state_info [ hostname ] . remove ( o0o )
  lprint ( oOO00 . format ( "Use previous" ) )
  if 52 - 52: I11i . OOooOOo + OoO0O00
  if 10 - 10: Oo0Ooo * OoooooooOO * OOooOOo
 i1I11I = lisp_nat_state_info [ hostname ]
 lisp_nat_state_info [ hostname ] = [ iiIii1i ] + i1I11I
 return ( True )
 if 80 - 80: ooOoO0o % I1ii11iIi11i % I11i . I1Ii111
 if 3 - 3: ooOoO0o - Oo0Ooo
 if 2 - 2: iII111i . iII111i
 if 77 - 77: OOooOOo
 if 74 - 74: O0
 if 86 - 86: OoOoOO00
 if 4 - 4: OoooooooOO * OoO0O00
 if 93 - 93: OoO0O00 - I1Ii111 - OoO0O00
def lisp_get_nat_info ( rloc , hostname ) :
 if ( lisp_nat_state_info . has_key ( hostname ) == False ) : return ( None )
 if 1 - 1: o0oOOo0O0Ooo . oO0o * i11iIiiIii * IiII - OoO0O00 - OoooooooOO
 oooOO0oOooO00 = rloc . print_address_no_iid ( )
 for IIII1iII in lisp_nat_state_info [ hostname ] :
  if ( IIII1iII . address == oooOO0oOooO00 ) : return ( IIII1iII )
  if 29 - 29: iIii1I11I1II1 + OoO0O00 * II111iiii * Ii1I * iII111i . O0
 return ( None )
 if 6 - 6: I1IiiI - OoOoOO00
 if 63 - 63: OOooOOo - oO0o * I1IiiI
 if 60 - 60: II111iiii - Oo0Ooo
 if 43 - 43: I1IiiI - IiII - OOooOOo
 if 19 - 19: I1Ii111 / I1Ii111 - i1IIi
 if 99 - 99: O0
 if 37 - 37: iIii1I11I1II1 / I1Ii111 + OoO0O00
 if 85 - 85: ooOoO0o / I1IiiI
 if 7 - 7: Oo0Ooo - iIii1I11I1II1 / I1ii11iIi11i * I1IiiI + Ii1I
 if 99 - 99: i11iIiiIii - I1ii11iIi11i
 if 64 - 64: IiII . OoOoOO00 . Oo0Ooo . I1Ii111 / I11i / Ii1I
 if 95 - 95: iIii1I11I1II1 . Ii1I % oO0o - I11i % IiII
 if 42 - 42: OoOoOO00 + oO0o * i1IIi + i11iIiiIii
 if 25 - 25: Ii1I - Ii1I - I1ii11iIi11i / i1IIi . OoOoOO00 % Oo0Ooo
 if 76 - 76: I1Ii111 / OoOoOO00
 if 61 - 61: Oo0Ooo . i1IIi
 if 78 - 78: i11iIiiIii
 if 20 - 20: Ii1I
 if 100 - 100: OoooooooOO . I1Ii111
 if 32 - 32: iIii1I11I1II1 . iIii1I11I1II1 % II111iiii / Oo0Ooo . iIii1I11I1II1 . O0
def lisp_build_info_requests ( lisp_sockets , dest , port ) :
 if ( lisp_nat_traversal == False ) : return
 if 63 - 63: I1IiiI . iIii1I11I1II1 . Oo0Ooo % OOooOOo - iII111i + ooOoO0o
 if 64 - 64: o0oOOo0O0Ooo / Ii1I % I1Ii111 % iII111i + OOooOOo * IiII
 if 87 - 87: I1ii11iIi11i . i1IIi - I11i + OoOoOO00 . O0
 if 37 - 37: IiII
 if 65 - 65: ooOoO0o * Ii1I / I1IiiI . i1IIi % ooOoO0o . OoooooooOO
 if 17 - 17: ooOoO0o / OoO0O00 / I1IiiI / OOooOOo % IiII
 ooOO0Oo0 = [ ]
 iIiiI1iii1 = [ ]
 if ( dest == None ) :
  for iiIii in lisp_map_resolvers_list . values ( ) :
   iIiiI1iii1 . append ( iiIii . map_resolver )
   if 13 - 13: OOooOOo / i11iIiiIii . I1IiiI
  ooOO0Oo0 = iIiiI1iii1
  if ( ooOO0Oo0 == [ ] ) :
   for iiIiiiII11Iii1 in lisp_map_servers_list . values ( ) :
    ooOO0Oo0 . append ( iiIiiiII11Iii1 . map_server )
    if 51 - 51: o0oOOo0O0Ooo + I1ii11iIi11i + O0
    if 91 - 91: I1Ii111 - II111iiii / I1Ii111 + II111iiii
  if ( ooOO0Oo0 == [ ] ) : return
 else :
  ooOO0Oo0 . append ( dest )
  if 62 - 62: I1ii11iIi11i * oO0o / Ii1I
  if 11 - 11: O0 % iII111i * iIii1I11I1II1 % O0 * OoooooooOO
  if 86 - 86: I1Ii111 . ooOoO0o % OoO0O00 * O0 + Ii1I
  if 46 - 46: i11iIiiIii . OOooOOo % iII111i - O0 / I1Ii111 + iIii1I11I1II1
  if 51 - 51: O0
 OO0oo0o0 = { }
 for iIiIi in lisp_db_list :
  for OOO0OOO000oOO0 in iIiIi . rloc_set :
   lisp_update_local_rloc ( OOO0OOO000oOO0 )
   if ( OOO0OOO000oOO0 . rloc . is_null ( ) ) : continue
   if ( OOO0OOO000oOO0 . interface == None ) : continue
   if 45 - 45: oO0o % OOooOOo - IiII + o0oOOo0O0Ooo + i11iIiiIii
   o00Ooo0 = OOO0OOO000oOO0 . rloc . print_address_no_iid ( )
   if ( o00Ooo0 in OO0oo0o0 ) : continue
   OO0oo0o0 [ o00Ooo0 ] = OOO0OOO000oOO0 . interface
   if 79 - 79: IiII % I1Ii111 . I1IiiI + O0 * oO0o * ooOoO0o
   if 38 - 38: IiII
 if ( OO0oo0o0 == { } ) :
  lprint ( 'Suppress Info-Request, no "interface = <device>" RLOC ' + "found in any database-mappings" )
  if 78 - 78: Oo0Ooo * I1ii11iIi11i % OOooOOo / Oo0Ooo + I1ii11iIi11i * IiII
  return
  if 2 - 2: Oo0Ooo - OoOoOO00
  if 22 - 22: OoO0O00 - oO0o - O0
  if 49 - 49: iIii1I11I1II1 + I1Ii111 / i11iIiiIii
  if 62 - 62: ooOoO0o . I1IiiI * i11iIiiIii
  if 2 - 2: i11iIiiIii
  if 86 - 86: I1Ii111 + o0oOOo0O0Ooo
 for o00Ooo0 in OO0oo0o0 :
  iiiii11I1 = OO0oo0o0 [ o00Ooo0 ]
  iiiI111I = red ( o00Ooo0 , False )
  lprint ( "Build Info-Request for private address {} ({})" . format ( iiiI111I ,
 iiiii11I1 ) )
  oOOOo0o = iiiii11I1 if len ( OO0oo0o0 ) > 1 else None
  for dest in ooOO0Oo0 :
   lisp_send_info_request ( lisp_sockets , dest , port , oOOOo0o )
   if 17 - 17: iIii1I11I1II1
   if 32 - 32: IiII - OoOoOO00
   if 88 - 88: OOooOOo - II111iiii + i1IIi * Oo0Ooo
   if 48 - 48: I1Ii111 + IiII % iII111i * iII111i + I1Ii111
   if 83 - 83: OoO0O00 . I11i * I1ii11iIi11i - II111iiii
   if 41 - 41: OoooooooOO . OoOoOO00 * iIii1I11I1II1
 if ( iIiiI1iii1 != [ ] ) :
  for iiIii in lisp_map_resolvers_list . values ( ) :
   iiIii . resolve_dns_name ( )
   if 18 - 18: IiII / I1Ii111 % i1IIi * i11iIiiIii
   if 16 - 16: Oo0Ooo
 return
 if 24 - 24: o0oOOo0O0Ooo . OoOoOO00
 if 50 - 50: I1ii11iIi11i / iIii1I11I1II1 - Oo0Ooo - i11iIiiIii % o0oOOo0O0Ooo - ooOoO0o
 if 92 - 92: OoooooooOO - I1ii11iIi11i . I11i / O0 % iII111i
 if 96 - 96: I1IiiI . oO0o % O0
 if 19 - 19: iIii1I11I1II1 + I1Ii111 / OoooooooOO % OOooOOo - i1IIi + I11i
 if 87 - 87: OoooooooOO
 if 97 - 97: ooOoO0o * IiII / iIii1I11I1II1
 if 65 - 65: i1IIi - i11iIiiIii + oO0o % I1IiiI - OoO0O00 % ooOoO0o
def lisp_valid_address_format ( kw , value ) :
 if ( kw != "address" ) : return ( True )
 if 23 - 23: o0oOOo0O0Ooo . o0oOOo0O0Ooo - iIii1I11I1II1 / o0oOOo0O0Ooo
 if 65 - 65: I1Ii111 + I1Ii111 . I1ii11iIi11i . OoOoOO00 % o0oOOo0O0Ooo * o0oOOo0O0Ooo
 if 2 - 2: oO0o % iII111i + I1ii11iIi11i / II111iiii * I1ii11iIi11i
 if 45 - 45: II111iiii . iII111i
 if 55 - 55: ooOoO0o / iII111i / O0
 if ( value [ 0 ] == "'" and value [ - 1 ] == "'" ) : return ( True )
 if 98 - 98: O0 % iII111i + II111iiii
 if 13 - 13: I1IiiI * oO0o - o0oOOo0O0Ooo
 if 23 - 23: iIii1I11I1II1 + oO0o . oO0o / o0oOOo0O0Ooo
 if 77 - 77: i1IIi * o0oOOo0O0Ooo * IiII
 if ( value . find ( "." ) != - 1 ) :
  o00Ooo0 = value . split ( "." )
  if ( len ( o00Ooo0 ) != 4 ) : return ( False )
  if 24 - 24: i11iIiiIii / iIii1I11I1II1 / iII111i
  for iIoOoooO0oo in o00Ooo0 :
   if ( iIoOoooO0oo . isdigit ( ) == False ) : return ( False )
   if ( int ( iIoOoooO0oo ) > 255 ) : return ( False )
   if 36 - 36: ooOoO0o - oO0o * IiII * OOooOOo / OoooooooOO % i1IIi
  return ( True )
  if 73 - 73: OoOoOO00 / i1IIi * iII111i + II111iiii + II111iiii % I11i
  if 11 - 11: iII111i + o0oOOo0O0Ooo - iII111i - OoooooooOO
  if 19 - 19: ooOoO0o % O0 % oO0o % OOooOOo % OoO0O00
  if 90 - 90: O0
  if 91 - 91: I1IiiI % ooOoO0o * iII111i % OoOoOO00 . OoOoOO00 + OoOoOO00
 if ( value . find ( "-" ) != - 1 ) :
  o00Ooo0 = value . split ( "-" )
  for ooOooo0OO in [ "N" , "S" , "W" , "E" ] :
   if ( ooOooo0OO in o00Ooo0 ) :
    if ( len ( o00Ooo0 ) < 8 ) : return ( False )
    return ( True )
    if 95 - 95: o0oOOo0O0Ooo % i1IIi
    if 14 - 14: iIii1I11I1II1 + iIii1I11I1II1
    if 74 - 74: OoOoOO00 . iIii1I11I1II1 + Ii1I + ooOoO0o % OoOoOO00
    if 37 - 37: i11iIiiIii + O0 + II111iiii
    if 13 - 13: OOooOOo / O0
    if 19 - 19: iIii1I11I1II1 + IiII * I11i * II111iiii + o0oOOo0O0Ooo + i11iIiiIii
    if 69 - 69: iIii1I11I1II1 . II111iiii
 if ( value . find ( "-" ) != - 1 ) :
  o00Ooo0 = value . split ( "-" )
  if ( len ( o00Ooo0 ) != 3 ) : return ( False )
  if 36 - 36: I1IiiI * i1IIi + OoOoOO00
  for oO000oo0 in o00Ooo0 :
   try : int ( oO000oo0 , 16 )
   except : return ( False )
   if 84 - 84: OoO0O00 * I1ii11iIi11i . i1IIi % iIii1I11I1II1 / OOooOOo
  return ( True )
  if 7 - 7: OoooooooOO
  if 71 - 71: OOooOOo * Oo0Ooo . Oo0Ooo % iIii1I11I1II1
  if 56 - 56: IiII * iIii1I11I1II1 - iIii1I11I1II1 . O0
  if 56 - 56: I1Ii111 / iIii1I11I1II1 % IiII * iIii1I11I1II1 . I1ii11iIi11i . OOooOOo
  if 1 - 1: Ii1I . Ii1I % II111iiii + I11i + OoOoOO00
 if ( value . find ( ":" ) != - 1 ) :
  o00Ooo0 = value . split ( ":" )
  if ( len ( o00Ooo0 ) < 2 ) : return ( False )
  if 52 - 52: OoooooooOO - OoO0O00
  I1IIII1IIiIi = False
  i111I11I = 0
  for oO000oo0 in o00Ooo0 :
   i111I11I += 1
   if ( oO000oo0 == "" ) :
    if ( I1IIII1IIiIi ) :
     if ( len ( o00Ooo0 ) == i111I11I ) : break
     if ( i111I11I > 2 ) : return ( False )
     if 58 - 58: OoooooooOO / Oo0Ooo / Oo0Ooo
    I1IIII1IIiIi = True
    continue
    if 11 - 11: I1IiiI - oO0o - oO0o . I11i
   try : int ( oO000oo0 , 16 )
   except : return ( False )
   if 65 - 65: i1IIi
  return ( True )
  if 20 - 20: i11iIiiIii + iIii1I11I1II1 / iII111i . I1IiiI
  if 8 - 8: O0 - iII111i - i1IIi * oO0o / II111iiii
  if 48 - 48: I1ii11iIi11i . IiII * oO0o
  if 92 - 92: OoOoOO00 + oO0o % Ii1I / Ii1I - iII111i
  if 11 - 11: Oo0Ooo % II111iiii * Ii1I + II111iiii
 if ( value [ 0 ] == "+" ) :
  o00Ooo0 = value [ 1 : : ]
  for i1IIiI1111II1 in o00Ooo0 :
   if ( i1IIiI1111II1 . isdigit ( ) == False ) : return ( False )
   if 82 - 82: I1IiiI . II111iiii % OoooooooOO
  return ( True )
  if 67 - 67: i11iIiiIii - I11i * OoOoOO00 + iII111i * IiII . IiII
 return ( False )
 if 73 - 73: o0oOOo0O0Ooo + Ii1I - I1ii11iIi11i . I1IiiI / I11i
 if 95 - 95: iIii1I11I1II1 / OoO0O00 + OoooooooOO % II111iiii % II111iiii - O0
 if 7 - 7: oO0o . iIii1I11I1II1
 if 50 - 50: OoO0O00
 if 90 - 90: ooOoO0o . Ii1I - OoooooooOO
 if 13 - 13: I1Ii111 / I1ii11iIi11i % OoO0O00 % i11iIiiIii / iIii1I11I1II1 . I1ii11iIi11i
 if 90 - 90: I1IiiI + I1IiiI % oO0o
 if 95 - 95: OOooOOo + OoooooooOO . i11iIiiIii * OoO0O00 * I1IiiI / I1Ii111
 if 5 - 5: Ii1I . oO0o / o0oOOo0O0Ooo - OoooooooOO
 if 67 - 67: I1Ii111 + i1IIi - OOooOOo + OoooooooOO / II111iiii - I1Ii111
 if 13 - 13: i11iIiiIii - O0 % OoOoOO00 + OOooOOo * ooOoO0o
 if 55 - 55: i1IIi - OOooOOo / I11i * Ii1I
def lisp_process_api ( process , lisp_socket , data_structure ) :
 II1iIiiI11II1 , o00O = data_structure . split ( "%" )
 if 26 - 26: O0 * iIii1I11I1II1 / i1IIi - i1IIi
 lprint ( "Process API request '{}', parameters: '{}'" . format ( II1iIiiI11II1 ,
 o00O ) )
 if 20 - 20: I1Ii111
 i11iiiI = [ ]
 if ( II1iIiiI11II1 == "map-cache" ) :
  if ( o00O == "" ) :
   i11iiiI = lisp_map_cache . walk_cache ( lisp_process_api_map_cache , i11iiiI )
  else :
   i11iiiI = lisp_process_api_map_cache_entry ( json . loads ( o00O ) )
   if 6 - 6: iII111i . i11iIiiIii / Oo0Ooo
   if 86 - 86: I11i % I1Ii111 % oO0o - ooOoO0o / i1IIi
 if ( II1iIiiI11II1 == "site-cache" ) :
  if ( o00O == "" ) :
   i11iiiI = lisp_sites_by_eid . walk_cache ( lisp_process_api_site_cache ,
 i11iiiI )
  else :
   i11iiiI = lisp_process_api_site_cache_entry ( json . loads ( o00O ) )
   if 68 - 68: i1IIi % O0 % iII111i
   if 55 - 55: I1ii11iIi11i % OOooOOo - o0oOOo0O0Ooo - II111iiii
 if ( II1iIiiI11II1 == "map-server" ) :
  o00O = { } if ( o00O == "" ) else json . loads ( o00O )
  i11iiiI = lisp_process_api_ms_or_mr ( True , o00O )
  if 52 - 52: I1Ii111
 if ( II1iIiiI11II1 == "map-resolver" ) :
  o00O = { } if ( o00O == "" ) else json . loads ( o00O )
  i11iiiI = lisp_process_api_ms_or_mr ( False , o00O )
  if 34 - 34: II111iiii + iII111i / IiII
 if ( II1iIiiI11II1 == "database-mapping" ) :
  i11iiiI = lisp_process_api_database_mapping ( )
  if 47 - 47: OoO0O00
  if 40 - 40: o0oOOo0O0Ooo / iII111i . o0oOOo0O0Ooo
  if 63 - 63: o0oOOo0O0Ooo * iIii1I11I1II1 * II111iiii . OoO0O00 - oO0o / OoOoOO00
  if 78 - 78: i11iIiiIii / OoO0O00 / i1IIi . i11iIiiIii
  if 100 - 100: II111iiii . IiII . I11i
 i11iiiI = json . dumps ( i11iiiI )
 IIiIi1II1IiI = lisp_api_ipc ( process , i11iiiI )
 lisp_ipc ( IIiIi1II1IiI , lisp_socket , "lisp-core" )
 return
 if 60 - 60: OoOoOO00 % OOooOOo * i1IIi
 if 3 - 3: OoooooooOO
 if 75 - 75: OoooooooOO * I1Ii111 * o0oOOo0O0Ooo + I1ii11iIi11i . iIii1I11I1II1 / O0
 if 23 - 23: oO0o - O0 * IiII + i11iIiiIii * Ii1I
 if 8 - 8: ooOoO0o / II111iiii . I1ii11iIi11i * ooOoO0o % oO0o
 if 36 - 36: I1ii11iIi11i % OOooOOo - ooOoO0o - I11i + I1IiiI
 if 37 - 37: I1ii11iIi11i * IiII
def lisp_process_api_map_cache ( mc , data ) :
 if 65 - 65: OOooOOo / O0 . I1ii11iIi11i % i1IIi % Oo0Ooo
 if 36 - 36: i11iIiiIii - OOooOOo + iII111i + iII111i * I11i * oO0o
 if 14 - 14: O0 - iII111i * I1Ii111 - I1IiiI + IiII
 if 46 - 46: OoooooooOO * OoO0O00 . I1Ii111
 if ( mc . group . is_null ( ) ) : return ( lisp_gather_map_cache_data ( mc , data ) )
 if 95 - 95: ooOoO0o . I1ii11iIi11i . ooOoO0o / I1IiiI * OoOoOO00 . O0
 if ( mc . source_cache == None ) : return ( [ True , data ] )
 if 78 - 78: oO0o
 if 33 - 33: oO0o + i1IIi
 if 32 - 32: iIii1I11I1II1
 if 71 - 71: Ii1I * I1IiiI
 if 62 - 62: II111iiii / I1IiiI . I1ii11iIi11i
 data = mc . source_cache . walk_cache ( lisp_gather_map_cache_data , data )
 return ( [ True , data ] )
 if 49 - 49: IiII / OoOoOO00 / O0 * i11iIiiIii
 if 47 - 47: i11iIiiIii + iII111i + i11iIiiIii
 if 66 - 66: o0oOOo0O0Ooo . I1IiiI + OoooooooOO . iII111i / OoooooooOO - IiII
 if 47 - 47: o0oOOo0O0Ooo / II111iiii * i11iIiiIii * OoO0O00 . iIii1I11I1II1
 if 34 - 34: I11i / o0oOOo0O0Ooo * OOooOOo * OOooOOo
 if 89 - 89: I1ii11iIi11i . OoooooooOO
 if 61 - 61: i1IIi + i11iIiiIii
def lisp_gather_map_cache_data ( mc , data ) :
 oo = { }
 oo [ "instance-id" ] = str ( mc . eid . instance_id )
 oo [ "eid-prefix" ] = mc . eid . print_prefix_no_iid ( )
 if ( mc . group . is_null ( ) == False ) :
  oo [ "group-prefix" ] = mc . group . print_prefix_no_iid ( )
  if 59 - 59: i11iIiiIii * OOooOOo + i1IIi * iIii1I11I1II1 + I11i
 oo [ "uptime" ] = lisp_print_elapsed ( mc . uptime )
 oo [ "expires" ] = lisp_print_elapsed ( mc . uptime )
 oo [ "action" ] = lisp_map_reply_action_string [ mc . action ]
 oo [ "ttl" ] = "--" if mc . map_cache_ttl == None else str ( mc . map_cache_ttl / 60 )
 if 97 - 97: OoO0O00 - I11i . OoooooooOO
 if 58 - 58: I1ii11iIi11i / II111iiii / i11iIiiIii
 if 27 - 27: iIii1I11I1II1 - O0 + OoOoOO00
 if 28 - 28: oO0o . IiII * iII111i % Oo0Ooo - OoO0O00 / I11i
 if 67 - 67: i11iIiiIii + i11iIiiIii / ooOoO0o - o0oOOo0O0Ooo
 I111i = [ ]
 for Oo0O0 in mc . rloc_set :
  o0O = { }
  if ( Oo0O0 . rloc_exists ( ) ) :
   o0O [ "address" ] = Oo0O0 . rloc . print_address_no_iid ( )
   if 94 - 94: O0 + OoO0O00 / I1IiiI * II111iiii * i11iIiiIii
   if 55 - 55: OoooooooOO * O0 + i1IIi % I1IiiI
  if ( Oo0O0 . translated_port != 0 ) :
   o0O [ "encap-port" ] = str ( Oo0O0 . translated_port )
   if 10 - 10: II111iiii - Ii1I . I11i . O0 + Ii1I
  o0O [ "state" ] = Oo0O0 . print_state ( )
  if ( Oo0O0 . geo ) : o0O [ "geo" ] = Oo0O0 . geo . print_geo ( )
  if ( Oo0O0 . elp ) : o0O [ "elp" ] = Oo0O0 . elp . print_elp ( False )
  if ( Oo0O0 . rle ) : o0O [ "rle" ] = Oo0O0 . rle . print_rle ( False )
  if ( Oo0O0 . json ) : o0O [ "json" ] = Oo0O0 . json . print_json ( False )
  if ( Oo0O0 . rloc_name ) : o0O [ "rloc-name" ] = Oo0O0 . rloc_name
  OooO0o = Oo0O0 . stats . get_stats ( False , False )
  if ( OooO0o ) : o0O [ "stats" ] = OooO0o
  o0O [ "uptime" ] = lisp_print_elapsed ( Oo0O0 . uptime )
  o0O [ "upriority" ] = str ( Oo0O0 . priority )
  o0O [ "uweight" ] = str ( Oo0O0 . weight )
  o0O [ "mpriority" ] = str ( Oo0O0 . mpriority )
  o0O [ "mweight" ] = str ( Oo0O0 . mweight )
  Iii1i = Oo0O0 . last_rloc_probe_reply
  if ( Iii1i ) :
   o0O [ "last-rloc-probe-reply" ] = lisp_print_elapsed ( Iii1i )
   o0O [ "rloc-probe-rtt" ] = str ( Oo0O0 . rloc_probe_rtt )
   if 98 - 98: IiII * iII111i + Oo0Ooo . o0oOOo0O0Ooo % II111iiii + I1IiiI
  o0O [ "rloc-hop-count" ] = Oo0O0 . rloc_probe_hops
  o0O [ "recent-rloc-hop-counts" ] = Oo0O0 . recent_rloc_probe_hops
  if 21 - 21: I1ii11iIi11i - ooOoO0o
  o0ooOoOo0 = [ ]
  for IIi1 in Oo0O0 . recent_rloc_probe_rtts : o0ooOoOo0 . append ( str ( IIi1 ) )
  o0O [ "recent-rloc-probe-rtts" ] = o0ooOoOo0
  if 64 - 64: iIii1I11I1II1 / OoOoOO00
  I111i . append ( o0O )
  if 14 - 14: Ii1I / OoooooooOO . i1IIi % IiII % i11iIiiIii
 oo [ "rloc-set" ] = I111i
 if 23 - 23: iIii1I11I1II1 - o0oOOo0O0Ooo - Ii1I % OOooOOo
 data . append ( oo )
 return ( [ True , data ] )
 if 100 - 100: oO0o . OoO0O00 . i11iIiiIii % II111iiii * IiII
 if 81 - 81: OOooOOo - OOooOOo + OoOoOO00
 if 19 - 19: o0oOOo0O0Ooo
 if 20 - 20: I1Ii111 + iIii1I11I1II1 % I1IiiI + ooOoO0o
 if 86 - 86: o0oOOo0O0Ooo * i11iIiiIii - I11i
 if 71 - 71: OoO0O00 - I11i
 if 96 - 96: I1Ii111 / Ii1I
def lisp_process_api_map_cache_entry ( parms ) :
 iiI1iii = parms [ "instance-id" ]
 iiI1iii = 0 if ( iiI1iii == "" ) else int ( iiI1iii )
 if 65 - 65: I1ii11iIi11i * O0 . IiII
 if 11 - 11: I11i / Ii1I % oO0o
 if 50 - 50: i11iIiiIii
 if 93 - 93: i1IIi / Ii1I * II111iiii - Oo0Ooo . OoOoOO00 - OOooOOo
 oOOOO = lisp_address ( LISP_AFI_NONE , "" , 0 , iiI1iii )
 oOOOO . store_prefix ( parms [ "eid-prefix" ] )
 OO0i1Ii1II11 = oOOOO
 I1iO00O000oOO0oO = oOOOO
 if 25 - 25: I11i / ooOoO0o % ooOoO0o - OOooOOo
 if 59 - 59: I1IiiI + o0oOOo0O0Ooo . iIii1I11I1II1 - O0 - i11iIiiIii
 if 4 - 4: I1IiiI
 if 36 - 36: Ii1I
 if 76 - 76: i11iIiiIii + i1IIi
 iiI = lisp_address ( LISP_AFI_NONE , "" , 0 , iiI1iii )
 if ( parms . has_key ( "group-prefix" ) ) :
  iiI . store_prefix ( parms [ "group-prefix" ] )
  OO0i1Ii1II11 = iiI
  if 56 - 56: OoOoOO00 + II111iiii / i11iIiiIii * OoOoOO00 * OoooooooOO
  if 15 - 15: OoOoOO00 / OoooooooOO + OOooOOo
 i11iiiI = [ ]
 oOooO0Oo0Oo0 = lisp_map_cache_lookup ( I1iO00O000oOO0oO , OO0i1Ii1II11 )
 if ( oOooO0Oo0Oo0 ) : OO0OoOOOOo , i11iiiI = lisp_process_api_map_cache ( oOooO0Oo0Oo0 , i11iiiI )
 return ( i11iiiI )
 if 76 - 76: Ii1I * iII111i . OoooooooOO
 if 92 - 92: iIii1I11I1II1 - Oo0Ooo - I1IiiI - OOooOOo * I1Ii111
 if 44 - 44: I1Ii111 - II111iiii / OOooOOo
 if 50 - 50: I11i / I1ii11iIi11i
 if 60 - 60: II111iiii / Ii1I + OoO0O00 % I1IiiI * i1IIi / II111iiii
 if 91 - 91: I1IiiI * I1Ii111 * i11iIiiIii - oO0o - IiII + I1ii11iIi11i
 if 99 - 99: OoO0O00 % o0oOOo0O0Ooo
def lisp_process_api_site_cache ( se , data ) :
 if 3 - 3: OOooOOo / OoOoOO00 % iIii1I11I1II1
 if 47 - 47: ooOoO0o . i11iIiiIii / OoO0O00
 if 48 - 48: O0
 if 89 - 89: i11iIiiIii % OoO0O00 . OoOoOO00 + Oo0Ooo + OoOoOO00
 if ( se . group . is_null ( ) ) : return ( lisp_gather_site_cache_data ( se , data ) )
 if 53 - 53: Ii1I / OoOoOO00 % iII111i * OoooooooOO + Oo0Ooo
 if ( se . source_cache == None ) : return ( [ True , data ] )
 if 70 - 70: OoO0O00 % OoO0O00 * OoooooooOO
 if 96 - 96: ooOoO0o * Ii1I + I11i + II111iiii * I1IiiI / iII111i
 if 40 - 40: OoooooooOO - I11i % OOooOOo - I1IiiI . I1IiiI + Ii1I
 if 97 - 97: OOooOOo . OoooooooOO . OOooOOo . i11iIiiIii
 if 71 - 71: oO0o + I1ii11iIi11i * I1ii11iIi11i
 data = se . source_cache . walk_cache ( lisp_gather_site_cache_data , data )
 return ( [ True , data ] )
 if 79 - 79: oO0o
 if 47 - 47: OoooooooOO - i1IIi * OOooOOo
 if 11 - 11: I11i / OOooOOo . o0oOOo0O0Ooo - O0 * OoooooooOO % iII111i
 if 7 - 7: OoOoOO00 . IiII + OoooooooOO - I1Ii111 / oO0o
 if 32 - 32: iIii1I11I1II1 + I11i + OOooOOo - OoooooooOO + i11iIiiIii * o0oOOo0O0Ooo
 if 8 - 8: iII111i
 if 10 - 10: OoOoOO00 % I11i
def lisp_process_api_ms_or_mr ( ms_or_mr , data ) :
 I1Ii11i = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
 ii111 = data [ "dns-name" ] if data . has_key ( "dns-name" ) else None
 if ( data . has_key ( "address" ) ) :
  I1Ii11i . store_address ( data [ "address" ] )
  if 49 - 49: oO0o % ooOoO0o + II111iiii
  if 21 - 21: i1IIi + OoO0O00 . I1IiiI - Oo0Ooo
 I1Iii1iI1 = { }
 if ( ms_or_mr ) :
  for iiIiiiII11Iii1 in lisp_map_servers_list . values ( ) :
   if ( ii111 ) :
    if ( ii111 != iiIiiiII11Iii1 . dns_name ) : continue
   else :
    if ( I1Ii11i . is_exact_match ( iiIiiiII11Iii1 . map_server ) == False ) : continue
    if 99 - 99: OoOoOO00
    if 46 - 46: I1ii11iIi11i / II111iiii / OoooooooOO / Ii1I
   I1Iii1iI1 [ "dns-name" ] = iiIiiiII11Iii1 . dns_name
   I1Iii1iI1 [ "address" ] = iiIiiiII11Iii1 . map_server . print_address_no_iid ( )
   I1Iii1iI1 [ "ms-name" ] = "" if iiIiiiII11Iii1 . ms_name == None else iiIiiiII11Iii1 . ms_name
   return ( [ I1Iii1iI1 ] )
   if 37 - 37: I1ii11iIi11i - Ii1I / oO0o . I1IiiI % I1Ii111
 else :
  for iiIii in lisp_map_resolvers_list . values ( ) :
   if ( ii111 ) :
    if ( ii111 != iiIii . dns_name ) : continue
   else :
    if ( I1Ii11i . is_exact_match ( iiIii . map_resolver ) == False ) : continue
    if 8 - 8: oO0o
    if 46 - 46: I1Ii111 + IiII + II111iiii . o0oOOo0O0Ooo + i11iIiiIii
   I1Iii1iI1 [ "dns-name" ] = iiIii . dns_name
   I1Iii1iI1 [ "address" ] = iiIii . map_resolver . print_address_no_iid ( )
   I1Iii1iI1 [ "mr-name" ] = "" if iiIii . mr_name == None else iiIii . mr_name
   return ( [ I1Iii1iI1 ] )
   if 97 - 97: o0oOOo0O0Ooo % OoOoOO00 * O0 / iIii1I11I1II1 * OoO0O00 / i11iIiiIii
   if 1 - 1: OoooooooOO . Ii1I
 return ( [ ] )
 if 68 - 68: Ii1I
 if 98 - 98: iII111i
 if 33 - 33: OoO0O00 - ooOoO0o % O0 % iIii1I11I1II1 * iII111i - iII111i
 if 27 - 27: i11iIiiIii + I1ii11iIi11i + i1IIi
 if 67 - 67: o0oOOo0O0Ooo
 if 58 - 58: IiII % o0oOOo0O0Ooo + i1IIi
 if 33 - 33: II111iiii
 if 61 - 61: I1Ii111
def lisp_process_api_database_mapping ( ) :
 i11iiiI = [ ]
 if 56 - 56: I1ii11iIi11i - OoooooooOO
 for iIiIi in lisp_db_list :
  oo = { }
  oo [ "eid-prefix" ] = iIiIi . eid . print_prefix ( )
  if ( iIiIi . group . is_null ( ) == False ) :
   oo [ "group-prefix" ] = iIiIi . group . print_prefix ( )
   if 52 - 52: Oo0Ooo - I11i - IiII - OoOoOO00
   if 21 - 21: oO0o % o0oOOo0O0Ooo + I1Ii111 . OOooOOo / OOooOOo
  iIiIii1I1 = [ ]
  for o0O in iIiIi . rloc_set :
   Oo0O0 = { }
   if ( o0O . rloc . is_null ( ) == False ) :
    Oo0O0 [ "rloc" ] = o0O . rloc . print_address_no_iid ( )
    if 41 - 41: Oo0Ooo . ooOoO0o * oO0o
   if ( o0O . rloc_name != None ) : Oo0O0 [ "rloc-name" ] = o0O . rloc_name
   if ( o0O . interface != None ) : Oo0O0 [ "interface" ] = o0O . interface
   iIi11ii1II1i1 = o0O . translated_rloc
   if ( iIi11ii1II1i1 . is_null ( ) == False ) :
    Oo0O0 [ "translated-rloc" ] = iIi11ii1II1i1 . print_address_no_iid ( )
    if 38 - 38: OoooooooOO % iII111i
   if ( Oo0O0 != { } ) : iIiIii1I1 . append ( Oo0O0 )
   if 6 - 6: iII111i / OoOoOO00 / i11iIiiIii - o0oOOo0O0Ooo
   if 35 - 35: ooOoO0o / I1Ii111 / I1Ii111
   if 19 - 19: OoO0O00 % i11iIiiIii % iIii1I11I1II1
   if 100 - 100: OOooOOo . oO0o % ooOoO0o * ooOoO0o . I1Ii111 - oO0o
   if 33 - 33: Oo0Ooo . i1IIi - OoooooooOO
  oo [ "rlocs" ] = iIiIii1I1
  if 14 - 14: I1Ii111 + Oo0Ooo
  if 35 - 35: i11iIiiIii * Ii1I
  if 100 - 100: O0 . iII111i / iIii1I11I1II1
  if 47 - 47: ooOoO0o + OoOoOO00
  i11iiiI . append ( oo )
  if 67 - 67: IiII - I1ii11iIi11i * i1IIi - ooOoO0o
 return ( i11iiiI )
 if 91 - 91: I11i
 if 54 - 54: I1ii11iIi11i / i1IIi
 if 14 - 14: iIii1I11I1II1 * I11i . I11i * ooOoO0o * iII111i
 if 60 - 60: iIii1I11I1II1 + i1IIi + oO0o - iIii1I11I1II1 . i11iIiiIii * OoooooooOO
 if 23 - 23: iII111i - IiII % i11iIiiIii
 if 81 - 81: OoooooooOO % OoOoOO00 / IiII / OoooooooOO + i1IIi - O0
 if 60 - 60: OOooOOo - I1Ii111 * Oo0Ooo
def lisp_gather_site_cache_data ( se , data ) :
 oo = { }
 oo [ "site-name" ] = se . site . site_name
 oo [ "instance-id" ] = str ( se . eid . instance_id )
 oo [ "eid-prefix" ] = se . eid . print_prefix_no_iid ( )
 if ( se . group . is_null ( ) == False ) :
  oo [ "group-prefix" ] = se . group . print_prefix_no_iid ( )
  if 9 - 9: OoooooooOO * OOooOOo % OoO0O00 - ooOoO0o + Ii1I
 oo [ "registered" ] = "yes" if se . registered else "no"
 oo [ "first-registered" ] = lisp_print_elapsed ( se . first_registered )
 oo [ "last-registered" ] = lisp_print_elapsed ( se . last_registered )
 if 39 - 39: iIii1I11I1II1 / i1IIi % I11i % I1ii11iIi11i * IiII
 o00Ooo0 = se . last_registerer
 o00Ooo0 = "none" if o00Ooo0 . is_null ( ) else o00Ooo0 . print_address ( )
 oo [ "last-registerer" ] = o00Ooo0
 oo [ "ams" ] = "yes" if ( se . accept_more_specifics ) else "no"
 oo [ "dynamic" ] = "yes" if ( se . dynamic ) else "no"
 oo [ "site-id" ] = str ( se . site_id )
 if ( se . xtr_id_present ) :
  oo [ "xtr-id" ] = "0x" + lisp_hex_string ( se . xtr_id )
  if 11 - 11: II111iiii + i1IIi
  if 1 - 1: OOooOOo
  if 23 - 23: i1IIi + OoooooooOO * OOooOOo . Oo0Ooo
  if 83 - 83: OoooooooOO
  if 53 - 53: o0oOOo0O0Ooo - Oo0Ooo / IiII + O0
 I111i = [ ]
 for Oo0O0 in se . registered_rlocs :
  o0O = { }
  o0O [ "address" ] = Oo0O0 . rloc . print_address_no_iid ( ) if Oo0O0 . rloc_exists ( ) else "none"
  if 88 - 88: Oo0Ooo % I1Ii111 * O0 - i1IIi * OoO0O00
  if 74 - 74: Oo0Ooo % iIii1I11I1II1 + OOooOOo
  if ( Oo0O0 . geo ) : o0O [ "geo" ] = Oo0O0 . geo . print_geo ( )
  if ( Oo0O0 . elp ) : o0O [ "elp" ] = Oo0O0 . elp . print_elp ( False )
  if ( Oo0O0 . rle ) : o0O [ "rle" ] = Oo0O0 . rle . print_rle ( False )
  if ( Oo0O0 . json ) : o0O [ "json" ] = Oo0O0 . json . print_json ( False )
  if ( Oo0O0 . rloc_name ) : o0O [ "rloc-name" ] = Oo0O0 . rloc_name
  o0O [ "uptime" ] = lisp_print_elapsed ( Oo0O0 . uptime )
  o0O [ "upriority" ] = str ( Oo0O0 . priority )
  o0O [ "uweight" ] = str ( Oo0O0 . weight )
  o0O [ "mpriority" ] = str ( Oo0O0 . mpriority )
  o0O [ "mweight" ] = str ( Oo0O0 . mweight )
  if 50 - 50: OoO0O00 . OoooooooOO
  I111i . append ( o0O )
  if 31 - 31: OoO0O00
 oo [ "registered-rlocs" ] = I111i
 if 55 - 55: OoOoOO00 + I1Ii111 * o0oOOo0O0Ooo - I1ii11iIi11i + OoOoOO00
 data . append ( oo )
 return ( [ True , data ] )
 if 6 - 6: II111iiii % iIii1I11I1II1 * I1Ii111
 if 2 - 2: IiII - I1Ii111 . iIii1I11I1II1 - Ii1I * I11i
 if 58 - 58: i1IIi % iIii1I11I1II1 % i11iIiiIii - o0oOOo0O0Ooo + ooOoO0o
 if 23 - 23: Oo0Ooo % Oo0Ooo / IiII
 if 63 - 63: I11i % Oo0Ooo * I1Ii111 - Oo0Ooo % i11iIiiIii . II111iiii
 if 44 - 44: I11i . I1Ii111 . I1ii11iIi11i . oO0o
 if 1 - 1: I11i % II111iiii / OoO0O00 + OoO0O00
def lisp_process_api_site_cache_entry ( parms ) :
 iiI1iii = parms [ "instance-id" ]
 iiI1iii = 0 if ( iiI1iii == "" ) else int ( iiI1iii )
 if 46 - 46: Oo0Ooo * Ii1I / IiII % O0 * iII111i
 if 74 - 74: OoooooooOO + Ii1I
 if 100 - 100: I1IiiI
 if 59 - 59: I1IiiI - OoOoOO00 * ooOoO0o / O0
 oOOOO = lisp_address ( LISP_AFI_NONE , "" , 0 , iiI1iii )
 oOOOO . store_prefix ( parms [ "eid-prefix" ] )
 if 54 - 54: Oo0Ooo % iIii1I11I1II1 * Oo0Ooo
 if 80 - 80: I1ii11iIi11i - I1ii11iIi11i
 if 26 - 26: I1ii11iIi11i - I1IiiI * I1Ii111 % iIii1I11I1II1
 if 77 - 77: o0oOOo0O0Ooo + I1Ii111 . OOooOOo . i1IIi . I1IiiI
 if 100 - 100: ooOoO0o . i11iIiiIii + Ii1I - OOooOOo - i11iIiiIii - OoooooooOO
 iiI = lisp_address ( LISP_AFI_NONE , "" , 0 , iiI1iii )
 if ( parms . has_key ( "group-prefix" ) ) :
  iiI . store_prefix ( parms [ "group-prefix" ] )
  if 42 - 42: OoOoOO00 . I1IiiI / OoOoOO00 / I1ii11iIi11i . OoO0O00
  if 67 - 67: Ii1I - O0 . OoooooooOO . I1Ii111 . o0oOOo0O0Ooo
 i11iiiI = [ ]
 oo00oO0 = lisp_site_eid_lookup ( oOOOO , iiI , False )
 if ( oo00oO0 ) : lisp_gather_site_cache_data ( oo00oO0 , i11iiiI )
 return ( i11iiiI )
 if 73 - 73: I11i - oO0o . I1Ii111 + oO0o
 if 48 - 48: IiII . IiII * o0oOOo0O0Ooo * II111iiii % ooOoO0o
 if 40 - 40: I1ii11iIi11i
 if 76 - 76: Oo0Ooo - I11i
 if 82 - 82: OoO0O00 % oO0o . I11i / O0 - I1Ii111
 if 39 - 39: I1IiiI
 if 8 - 8: IiII * i1IIi * i1IIi * O0
def lisp_get_interface_instance_id ( device , source_eid ) :
 iiiii11I1 = None
 if ( lisp_myinterfaces . has_key ( device ) ) :
  iiiii11I1 = lisp_myinterfaces [ device ]
  if 69 - 69: Oo0Ooo
  if 48 - 48: iII111i
  if 11 - 11: i11iIiiIii * OoOoOO00 . OoO0O00
  if 47 - 47: Oo0Ooo % I1Ii111 + ooOoO0o
  if 89 - 89: iII111i
  if 29 - 29: I1ii11iIi11i . ooOoO0o * II111iiii / iII111i . OoooooooOO - OoOoOO00
 if ( iiiii11I1 == None or iiiii11I1 . instance_id == None ) :
  return ( lisp_default_iid )
  if 99 - 99: IiII % O0 - I1Ii111 * OoO0O00
  if 77 - 77: OoooooooOO - I11i / I1IiiI % OoOoOO00 - OOooOOo
  if 37 - 37: ooOoO0o
  if 22 - 22: I1ii11iIi11i + II111iiii / OoooooooOO % o0oOOo0O0Ooo * OoOoOO00 . Oo0Ooo
  if 26 - 26: OoO0O00 % oO0o * Ii1I % OoooooooOO - oO0o
  if 46 - 46: I1IiiI + OoO0O00 - O0 * O0
  if 75 - 75: OOooOOo + iIii1I11I1II1 * OOooOOo
  if 82 - 82: iII111i - I1Ii111 - OoOoOO00
  if 96 - 96: Oo0Ooo . Oo0Ooo % o0oOOo0O0Ooo - I1IiiI * iIii1I11I1II1
 iiI1iii = iiiii11I1 . get_instance_id ( )
 if ( source_eid == None ) : return ( iiI1iii )
 if 29 - 29: i1IIi / Ii1I / oO0o * iII111i
 i1iI1I1I1iI1 = source_eid . instance_id
 I1iIIiii1 = None
 for iiiii11I1 in lisp_multi_tenant_interfaces :
  if ( iiiii11I1 . device != device ) : continue
  Oo0OOoO0oo0oO = iiiii11I1 . multi_tenant_eid
  source_eid . instance_id = Oo0OOoO0oo0oO . instance_id
  if ( source_eid . is_more_specific ( Oo0OOoO0oo0oO ) == False ) : continue
  if ( I1iIIiii1 == None or I1iIIiii1 . multi_tenant_eid . mask_len < Oo0OOoO0oo0oO . mask_len ) :
   I1iIIiii1 = iiiii11I1
   if 62 - 62: i11iIiiIii
   if 62 - 62: I1IiiI + II111iiii * iIii1I11I1II1 % iII111i + IiII / ooOoO0o
 source_eid . instance_id = i1iI1I1I1iI1
 if 14 - 14: iIii1I11I1II1 * I1ii11iIi11i + OOooOOo + O0
 if ( I1iIIiii1 == None ) : return ( iiI1iii )
 return ( I1iIIiii1 . get_instance_id ( ) )
 if 79 - 79: II111iiii - iII111i
 if 89 - 89: O0 - OoO0O00
 if 8 - 8: I1ii11iIi11i / oO0o - OoooooooOO + ooOoO0o + o0oOOo0O0Ooo % i11iIiiIii
 if 32 - 32: O0 + IiII
 if 93 - 93: OoOoOO00 - I11i / iII111i - iIii1I11I1II1 + I11i % oO0o
 if 24 - 24: Ii1I / iIii1I11I1II1 + o0oOOo0O0Ooo
 if 17 - 17: OOooOOo
 if 75 - 75: Ii1I / i1IIi % I1ii11iIi11i . Ii1I
 if 46 - 46: II111iiii * OoO0O00
def lisp_allow_dynamic_eid ( device , eid ) :
 if ( lisp_myinterfaces . has_key ( device ) == False ) : return ( None )
 if 77 - 77: ooOoO0o * I11i
 iiiii11I1 = lisp_myinterfaces [ device ]
 OOO0ooOoOo00 = device if iiiii11I1 . dynamic_eid_device == None else iiiii11I1 . dynamic_eid_device
 if 30 - 30: OoooooooOO % oO0o + II111iiii - OOooOOo + II111iiii + OoOoOO00
 if 51 - 51: i11iIiiIii
 if ( iiiii11I1 . does_dynamic_eid_match ( eid ) ) : return ( OOO0ooOoOo00 )
 return ( None )
 if 39 - 39: o0oOOo0O0Ooo % I1Ii111 % i1IIi - II111iiii + i11iIiiIii
 if 62 - 62: I1ii11iIi11i - I1IiiI * i11iIiiIii % oO0o
 if 63 - 63: II111iiii - Oo0Ooo
 if 55 - 55: iIii1I11I1II1 / O0 * O0 * i11iIiiIii * OoooooooOO
 if 94 - 94: II111iiii . II111iiii / OoOoOO00 % oO0o * i1IIi % Oo0Ooo
 if 78 - 78: IiII - I1IiiI
 if 59 - 59: oO0o + i1IIi - IiII % OOooOOo % iIii1I11I1II1
def lisp_start_rloc_probe_timer ( interval , lisp_sockets ) :
 global lisp_rloc_probe_timer
 if 71 - 71: OoO0O00
 if ( lisp_rloc_probe_timer != None ) : lisp_rloc_probe_timer . cancel ( )
 if 72 - 72: II111iiii + o0oOOo0O0Ooo / i1IIi * Oo0Ooo / i1IIi
 O0oO000OOOo = lisp_process_rloc_probe_timer
 iI11II1IiI111 = threading . Timer ( interval , O0oO000OOOo , [ lisp_sockets ] )
 lisp_rloc_probe_timer = iI11II1IiI111
 iI11II1IiI111 . start ( )
 return
 if 54 - 54: Ii1I / I1IiiI
 if 7 - 7: iIii1I11I1II1 . O0 + OOooOOo . Ii1I * Oo0Ooo
 if 25 - 25: I1Ii111 . Oo0Ooo % II111iiii . IiII - O0
 if 18 - 18: oO0o * OOooOOo
 if 19 - 19: iIii1I11I1II1 / I1ii11iIi11i - I1ii11iIi11i / iIii1I11I1II1
 if 42 - 42: iIii1I11I1II1 / OOooOOo - O0 * OoooooooOO / i1IIi
 if 33 - 33: OOooOOo . o0oOOo0O0Ooo % OoO0O00 - I1Ii111 . OoooooooOO
def lisp_show_rloc_probe_list ( ) :
 lprint ( bold ( "----- RLOC-probe-list -----" , False ) )
 for o0000oO in lisp_rloc_probe_list :
  Ooo0O0oOooo = lisp_rloc_probe_list [ o0000oO ]
  lprint ( "RLOC {}:" . format ( o0000oO ) )
  for o0O , O0O0o0o0o , Ii1i111iI in Ooo0O0oOooo :
   lprint ( "  [{}, {}, {}, {}]" . format ( hex ( id ( o0O ) ) , O0O0o0o0o . print_prefix ( ) ,
 Ii1i111iI . print_prefix ( ) , o0O . translated_port ) )
   if 89 - 89: OOooOOo . IiII - OoooooooOO + II111iiii
   if 35 - 35: i1IIi % I1IiiI . Ii1I - i11iIiiIii / oO0o
 lprint ( bold ( "---------------------------" , False ) )
 return
 if 98 - 98: OoOoOO00 . oO0o + I1ii11iIi11i
 if 14 - 14: OoooooooOO
 if 73 - 73: OoOoOO00 % o0oOOo0O0Ooo
 if 28 - 28: OoO0O00
 if 15 - 15: OoO0O00 . I11i
 if 64 - 64: OOooOOo + I1Ii111 - o0oOOo0O0Ooo . II111iiii * Ii1I
 if 88 - 88: I1ii11iIi11i + OoooooooOO % I1ii11iIi11i
 if 3 - 3: I1Ii111 . O0 * OOooOOo * I11i + Ii1I * I1IiiI
 if 18 - 18: iIii1I11I1II1 % ooOoO0o . o0oOOo0O0Ooo * iII111i % iII111i
def lisp_mark_rlocs_for_other_eids ( eid_list ) :
 if 64 - 64: I1Ii111 . I11i
 if 32 - 32: I1ii11iIi11i + IiII % OoOoOO00 . O0
 if 70 - 70: IiII + iII111i . i11iIiiIii + OoO0O00
 if 45 - 45: o0oOOo0O0Ooo - ooOoO0o
 Oo0O0 , O0O0o0o0o , Ii1i111iI = eid_list [ 0 ]
 I111I1 = [ lisp_print_eid_tuple ( O0O0o0o0o , Ii1i111iI ) ]
 if 28 - 28: IiII * I1Ii111 * o0oOOo0O0Ooo + ooOoO0o - IiII / IiII
 for Oo0O0 , O0O0o0o0o , Ii1i111iI in eid_list [ 1 : : ] :
  Oo0O0 . state = LISP_RLOC_UNREACH_STATE
  Oo0O0 . last_state_change = lisp_get_timestamp ( )
  I111I1 . append ( lisp_print_eid_tuple ( O0O0o0o0o , Ii1i111iI ) )
  if 73 - 73: iIii1I11I1II1 . I1ii11iIi11i + OOooOOo
  if 51 - 51: I11i % Oo0Ooo * OOooOOo % OoooooooOO - OoOoOO00 % Ii1I
 oOO0O0oo = bold ( "unreachable" , False )
 iII1II = red ( Oo0O0 . rloc . print_address_no_iid ( ) , False )
 if 92 - 92: IiII
 for oOOOO in I111I1 :
  O0O0o0o0o = green ( oOOOO , False )
  lprint ( "RLOC {} went {} for EID {}" . format ( iII1II , oOO0O0oo , O0O0o0o0o ) )
  if 68 - 68: OOooOOo . IiII / iIii1I11I1II1 % i11iIiiIii
  if 74 - 74: iII111i + i11iIiiIii
  if 95 - 95: Ii1I
  if 49 - 49: I1ii11iIi11i . i1IIi + OoO0O00 % O0 + OoO0O00
  if 21 - 21: ooOoO0o * oO0o / OoooooooOO % ooOoO0o / O0
  if 24 - 24: OoO0O00 - i11iIiiIii / i11iIiiIii * I1Ii111
 for Oo0O0 , O0O0o0o0o , Ii1i111iI in eid_list :
  oOooO0Oo0Oo0 = lisp_map_cache . lookup_cache ( O0O0o0o0o , True )
  if ( oOooO0Oo0Oo0 ) : lisp_write_ipc_map_cache ( True , oOooO0Oo0Oo0 )
  if 20 - 20: IiII % iIii1I11I1II1 . iII111i + iIii1I11I1II1 + O0
 return
 if 96 - 96: I1ii11iIi11i - IiII % OoooooooOO . iII111i
 if 30 - 30: Oo0Ooo . OoooooooOO / Oo0Ooo / oO0o
 if 44 - 44: I1ii11iIi11i % o0oOOo0O0Ooo / iIii1I11I1II1 - o0oOOo0O0Ooo / I11i * I1Ii111
 if 49 - 49: iII111i / iII111i - OoOoOO00
 if 89 - 89: ooOoO0o
 if 16 - 16: oO0o + oO0o + i1IIi + iIii1I11I1II1
 if 93 - 93: I1IiiI - i11iIiiIii * I1Ii111 - O0 + iII111i
 if 11 - 11: iII111i
 if 100 - 100: OoooooooOO / ooOoO0o . OoO0O00
 if 89 - 89: I11i % II111iiii
def lisp_process_rloc_probe_timer ( lisp_sockets ) :
 lisp_set_exception ( )
 if 35 - 35: oO0o
 lisp_start_rloc_probe_timer ( LISP_RLOC_PROBE_INTERVAL , lisp_sockets )
 if ( lisp_rloc_probing == False ) : return
 if 65 - 65: II111iiii
 if 87 - 87: oO0o / OoO0O00 - oO0o
 if 69 - 69: i11iIiiIii
 if 29 - 29: IiII . ooOoO0o / iII111i - OOooOOo / OOooOOo % Oo0Ooo
 if ( lisp_print_rloc_probe_list ) : lisp_show_rloc_probe_list ( )
 if 42 - 42: OoO0O00 . I1Ii111 . I1IiiI + Oo0Ooo * O0
 if 35 - 35: Oo0Ooo / iII111i - O0 - OOooOOo * Oo0Ooo . i11iIiiIii
 if 43 - 43: OoOoOO00 % oO0o % OoO0O00 / Ii1I . I11i
 if 86 - 86: I1Ii111 * i1IIi + IiII - OoOoOO00
 II1iOOo0O0o = lisp_get_default_route_next_hops ( )
 if 1 - 1: iIii1I11I1II1 - OoO0O00 / II111iiii . OoOoOO00
 lprint ( "---------- Start RLOC Probing for {} entries ----------" . format ( len ( lisp_rloc_probe_list ) ) )
 if 11 - 11: OOooOOo + i11iIiiIii
 if 21 - 21: OoOoOO00 * OoooooooOO . I11i . I1Ii111
 if 95 - 95: iIii1I11I1II1 - I1Ii111 - I1ii11iIi11i
 if 91 - 91: I1IiiI
 if 19 - 19: i1IIi / OOooOOo + i1IIi * OoooooooOO
 i111I11I = 0
 o0ooOOoO0O = bold ( "RLOC-probe" , False )
 for OOoo in lisp_rloc_probe_list . values ( ) :
  if 31 - 31: o0oOOo0O0Ooo . i1IIi - i1IIi % i1IIi - iIii1I11I1II1
  if 50 - 50: IiII - OOooOOo % OoOoOO00
  if 66 - 66: IiII * i11iIiiIii
  if 64 - 64: i11iIiiIii . I1Ii111 % i11iIiiIii % I11i
  if 56 - 56: o0oOOo0O0Ooo + ooOoO0o + OoooooooOO
  o0OoII1ii11ii1 = None
  for ii11i , oOOOO , iiI in OOoo :
   oooOO0oOooO00 = ii11i . rloc . print_address_no_iid ( )
   if 95 - 95: Ii1I + Ii1I % IiII - IiII / OOooOOo
   if 46 - 46: IiII + iII111i + II111iiii . iII111i - i11iIiiIii % OoO0O00
   if 24 - 24: oO0o + IiII . o0oOOo0O0Ooo . OoooooooOO . i11iIiiIii / I1ii11iIi11i
   if 49 - 49: IiII
   if 1 - 1: oO0o / I11i
   if 99 - 99: OoO0O00 % IiII + I1Ii111 - oO0o
   if ( ii11i . down_state ( ) ) : continue
   if 28 - 28: OOooOOo - O0 - O0 % i11iIiiIii * OoooooooOO
   if 60 - 60: OoooooooOO / i1IIi / i1IIi / Ii1I . IiII
   if 24 - 24: O0
   if 6 - 6: I1IiiI . i11iIiiIii . OoooooooOO . I1IiiI . o0oOOo0O0Ooo
   if 65 - 65: i11iIiiIii
   if 46 - 46: i11iIiiIii
   if 70 - 70: i1IIi + o0oOOo0O0Ooo
   if 44 - 44: iII111i . II111iiii % o0oOOo0O0Ooo
   if 29 - 29: i11iIiiIii * i1IIi
   if 36 - 36: OoO0O00 * I11i . ooOoO0o
   if 50 - 50: oO0o * OoOoOO00 / OoO0O00 / ooOoO0o + II111iiii
   if ( o0OoII1ii11ii1 ) :
    ii11i . last_rloc_probe_nonce = o0OoII1ii11ii1 . last_rloc_probe_nonce
    if 55 - 55: II111iiii - IiII
    if ( o0OoII1ii11ii1 . translated_port == ii11i . translated_port and o0OoII1ii11ii1 . rloc_name == ii11i . rloc_name ) :
     if 24 - 24: oO0o % Ii1I / i1IIi
     O0O0o0o0o = green ( lisp_print_eid_tuple ( oOOOO , iiI ) , False )
     lprint ( "Suppress probe to duplicate RLOC {} for {}" . format ( red ( oooOO0oOooO00 , False ) , O0O0o0o0o ) )
     if 84 - 84: i1IIi
     continue
     if 53 - 53: OoooooooOO - i1IIi - Ii1I
     if 73 - 73: I1ii11iIi11i - Ii1I * o0oOOo0O0Ooo
     if 29 - 29: o0oOOo0O0Ooo % IiII % OOooOOo + OoooooooOO - o0oOOo0O0Ooo
   iiiiIiiiiI = None
   Oo0O0 = None
   while ( True ) :
    Oo0O0 = ii11i if Oo0O0 == None else Oo0O0 . next_rloc
    if ( Oo0O0 == None ) : break
    if 34 - 34: Ii1I
    if 5 - 5: II111iiii . I1ii11iIi11i
    if 85 - 85: I1Ii111 . IiII + II111iiii
    if 92 - 92: iII111i / o0oOOo0O0Ooo * oO0o . I11i % o0oOOo0O0Ooo
    if 87 - 87: Ii1I / Oo0Ooo % iIii1I11I1II1 / iII111i
    if ( Oo0O0 . rloc_next_hop != None ) :
     if ( Oo0O0 . rloc_next_hop not in II1iOOo0O0o ) :
      if ( Oo0O0 . up_state ( ) ) :
       O0o0oo0oOO0oO , i11i1iI = Oo0O0 . rloc_next_hop
       Oo0O0 . state = LISP_RLOC_UNREACH_STATE
       Oo0O0 . last_state_change = lisp_get_timestamp ( )
       lisp_update_rtr_updown ( Oo0O0 . rloc , False )
       if 42 - 42: OoO0O00 . I1IiiI . OOooOOo + ooOoO0o
      oOO0O0oo = bold ( "unreachable" , False )
      lprint ( "Next-hop {}({}) for RLOC {} is {}" . format ( i11i1iI , O0o0oo0oOO0oO ,
 red ( oooOO0oOooO00 , False ) , oOO0O0oo ) )
      continue
      if 87 - 87: OOooOOo
      if 44 - 44: Oo0Ooo + iIii1I11I1II1
      if 67 - 67: iII111i . OOooOOo / ooOoO0o * iIii1I11I1II1
      if 29 - 29: I1Ii111 / OoOoOO00 % I1ii11iIi11i * IiII / II111iiii
      if 10 - 10: O0 / I11i
      if 29 - 29: i11iIiiIii % I11i
    IiIi11 = Oo0O0 . last_rloc_probe
    i1IiI1i111 = 0 if IiIi11 == None else time . time ( ) - IiIi11
    if ( Oo0O0 . unreach_state ( ) and i1IiI1i111 < LISP_RLOC_PROBE_INTERVAL ) :
     lprint ( "Waiting for probe-reply from RLOC {}" . format ( red ( oooOO0oOooO00 , False ) ) )
     if 11 - 11: O0 / Ii1I % iIii1I11I1II1
     continue
     if 36 - 36: oO0o + o0oOOo0O0Ooo - Ii1I . iII111i - O0
     if 53 - 53: Oo0Ooo - I1IiiI * O0 . II111iiii
     if 72 - 72: ooOoO0o - Ii1I . Ii1I . I11i / OoooooooOO + Ii1I
     if 32 - 32: O0
     if 42 - 42: i1IIi * I1ii11iIi11i * OoOoOO00
     if 43 - 43: I1ii11iIi11i % I1ii11iIi11i % i1IIi
    oooOo00 = lisp_get_echo_nonce ( None , oooOO0oOooO00 )
    if ( oooOo00 and oooOo00 . request_nonce_timeout ( ) ) :
     Oo0O0 . state = LISP_RLOC_NO_ECHOED_NONCE_STATE
     Oo0O0 . last_state_change = lisp_get_timestamp ( )
     oOO0O0oo = bold ( "unreachable" , False )
     lprint ( "RLOC {} went {}, nonce-echo failed" . format ( red ( oooOO0oOooO00 , False ) , oOO0O0oo ) )
     if 56 - 56: I1IiiI - OoO0O00 - iII111i . o0oOOo0O0Ooo . I1Ii111
     lisp_update_rtr_updown ( Oo0O0 . rloc , False )
     continue
     if 70 - 70: iIii1I11I1II1 - I11i
     if 2 - 2: oO0o / II111iiii * OoO0O00
     if 71 - 71: i1IIi + I11i * OoO0O00 . OOooOOo + oO0o
     if 40 - 40: OOooOOo
     if 14 - 14: OoooooooOO - OoooooooOO % i11iIiiIii % ooOoO0o / ooOoO0o
     if 33 - 33: iII111i / i1IIi . II111iiii % I1ii11iIi11i
    if ( oooOo00 and oooOo00 . recently_echoed ( ) ) :
     lprint ( ( "Suppress RLOC-probe to {}, nonce-echo " + "received" ) . format ( red ( oooOO0oOooO00 , False ) ) )
     if 74 - 74: iII111i / OOooOOo / O0 / iIii1I11I1II1 + IiII
     continue
     if 26 - 26: OOooOOo % i1IIi . I1Ii111 / O0 + I1Ii111
     if 39 - 39: I1ii11iIi11i * I1IiiI * II111iiii . Oo0Ooo % I1IiiI
     if 100 - 100: iIii1I11I1II1 - OoooooooOO * OoooooooOO - iII111i / ooOoO0o
     if 98 - 98: OoO0O00 + oO0o - II111iiii
     if 84 - 84: Oo0Ooo . OoOoOO00 - iII111i
     if 5 - 5: OoooooooOO . O0 / OOooOOo + I11i - Ii1I
    if ( Oo0O0 . last_rloc_probe != None ) :
     IiIi11 = Oo0O0 . last_rloc_probe_reply
     if ( IiIi11 == None ) : IiIi11 = 0
     i1IiI1i111 = time . time ( ) - IiIi11
     if ( Oo0O0 . up_state ( ) and i1IiI1i111 >= LISP_RLOC_PROBE_REPLY_WAIT ) :
      if 77 - 77: iIii1I11I1II1 * Oo0Ooo . IiII / oO0o + O0
      Oo0O0 . state = LISP_RLOC_UNREACH_STATE
      Oo0O0 . last_state_change = lisp_get_timestamp ( )
      lisp_update_rtr_updown ( Oo0O0 . rloc , False )
      oOO0O0oo = bold ( "unreachable" , False )
      lprint ( "RLOC {} went {}, probe it" . format ( red ( oooOO0oOooO00 , False ) , oOO0O0oo ) )
      if 76 - 76: iII111i + o0oOOo0O0Ooo - OoooooooOO * oO0o % OoooooooOO - O0
      if 18 - 18: Ii1I
      lisp_mark_rlocs_for_other_eids ( OOoo )
      if 82 - 82: OoOoOO00 + OoO0O00 - IiII / ooOoO0o
      if 70 - 70: OoO0O00
      if 43 - 43: ooOoO0o + OOooOOo + II111iiii - I1IiiI
    Oo0O0 . last_rloc_probe = lisp_get_timestamp ( )
    if 58 - 58: I11i
    oO0O00 = "" if Oo0O0 . unreach_state ( ) == False else " unreachable"
    if 61 - 61: o0oOOo0O0Ooo % OoOoOO00 * Ii1I . iII111i
    if 21 - 21: Ii1I / iIii1I11I1II1 / iIii1I11I1II1 / OOooOOo % OoOoOO00
    if 6 - 6: I1IiiI / o0oOOo0O0Ooo * IiII * OOooOOo - iII111i
    if 28 - 28: O0 - I11i / OoOoOO00 / oO0o
    if 41 - 41: i11iIiiIii + Oo0Ooo - OoO0O00 . i11iIiiIii / i11iIiiIii / Ii1I
    if 49 - 49: O0 % Oo0Ooo * I11i
    if 40 - 40: II111iiii
    oo0OOooo0o000 = ""
    i11i1iI = None
    if ( Oo0O0 . rloc_next_hop != None ) :
     O0o0oo0oOO0oO , i11i1iI = Oo0O0 . rloc_next_hop
     lisp_install_host_route ( oooOO0oOooO00 , i11i1iI , True )
     oo0OOooo0o000 = ", send on nh {}({})" . format ( i11i1iI , O0o0oo0oOO0oO )
     if 32 - 32: Ii1I % iIii1I11I1II1 + i1IIi / o0oOOo0O0Ooo
     if 6 - 6: OoOoOO00 % o0oOOo0O0Ooo - IiII . OOooOOo / i11iIiiIii * i1IIi
     if 1 - 1: iII111i - OoOoOO00 + II111iiii + o0oOOo0O0Ooo % iIii1I11I1II1 - OOooOOo
     if 60 - 60: ooOoO0o % iIii1I11I1II1 / iIii1I11I1II1
     if 61 - 61: oO0o
    IIi1 = Oo0O0 . print_rloc_probe_rtt ( )
    Ii1I1I11 = oooOO0oOooO00
    if ( Oo0O0 . translated_port != 0 ) :
     Ii1I1I11 += ":{}" . format ( Oo0O0 . translated_port )
     if 85 - 85: oO0o - iII111i
    Ii1I1I11 = red ( Ii1I1I11 , False )
    if ( Oo0O0 . rloc_name != None ) :
     Ii1I1I11 += " (" + blue ( Oo0O0 . rloc_name , False ) + ")"
     if 22 - 22: I1Ii111 * oO0o - OoO0O00
    lprint ( "Send {}{} {}, last rtt: {}{}" . format ( o0ooOOoO0O , oO0O00 ,
 Ii1I1I11 , IIi1 , oo0OOooo0o000 ) )
    if 12 - 12: IiII . OoooooooOO - iIii1I11I1II1 % iII111i
    if 56 - 56: Oo0Ooo / I1IiiI + iIii1I11I1II1 + I1IiiI % iIii1I11I1II1
    if 64 - 64: O0
    if 55 - 55: OoO0O00 * oO0o . Ii1I + OoOoOO00 % I11i + IiII
    if 55 - 55: OoooooooOO + oO0o . o0oOOo0O0Ooo % iIii1I11I1II1 - I1Ii111
    if 40 - 40: I1IiiI . o0oOOo0O0Ooo - Oo0Ooo
    if 44 - 44: Ii1I % OoO0O00 * oO0o * OoO0O00
    if 7 - 7: I1Ii111 % i1IIi . I11i . O0 / i1IIi
    if ( Oo0O0 . rloc_next_hop != None ) :
     iiiiIiiiiI = lisp_get_host_route_next_hop ( oooOO0oOooO00 )
     if ( iiiiIiiiiI ) : lisp_install_host_route ( oooOO0oOooO00 , iiiiIiiiiI , False )
     if 56 - 56: Oo0Ooo
     if 21 - 21: i11iIiiIii * o0oOOo0O0Ooo + Oo0Ooo
     if 20 - 20: IiII / OoooooooOO / O0 / I1Ii111 * ooOoO0o
     if 45 - 45: ooOoO0o / Oo0Ooo % o0oOOo0O0Ooo . ooOoO0o
     if 19 - 19: o0oOOo0O0Ooo % I11i . I1ii11iIi11i
     if 70 - 70: Oo0Ooo - I11i / I1ii11iIi11i % OoO0O00 % II111iiii
    if ( Oo0O0 . rloc . is_null ( ) ) :
     Oo0O0 . rloc . copy_address ( ii11i . rloc )
     if 72 - 72: i11iIiiIii * I11i
     if 69 - 69: I1Ii111 . Ii1I * I1ii11iIi11i % I11i - o0oOOo0O0Ooo
     if 30 - 30: ooOoO0o / Oo0Ooo * iII111i % OoooooooOO / I1ii11iIi11i
     if 64 - 64: OoooooooOO
     if 41 - 41: Ii1I . I11i / oO0o * OoooooooOO
    I11I1Ii1i = None if ( iiI . is_null ( ) ) else oOOOO
    oOOoo0oO = oOOOO if ( iiI . is_null ( ) ) else iiI
    lisp_send_map_request ( lisp_sockets , 0 , I11I1Ii1i , oOOoo0oO , Oo0O0 )
    o0OoII1ii11ii1 = ii11i
    if 8 - 8: Oo0Ooo % IiII
    if 3 - 3: IiII / o0oOOo0O0Ooo % Ii1I . i11iIiiIii % IiII
    if 62 - 62: IiII - I1Ii111 % iII111i / oO0o
    if 27 - 27: o0oOOo0O0Ooo + iIii1I11I1II1 + OoooooooOO - iII111i
    if ( i11i1iI ) : lisp_install_host_route ( oooOO0oOooO00 , i11i1iI , False )
    if 80 - 80: Ii1I . iII111i * I1IiiI * Ii1I
    if 82 - 82: OoO0O00 % OoOoOO00 * i11iIiiIii . OoO0O00 . I1ii11iIi11i + Ii1I
    if 60 - 60: i1IIi / iII111i
    if 10 - 10: I1Ii111 / OoOoOO00 * Ii1I % o0oOOo0O0Ooo . OoOoOO00 / I1ii11iIi11i
    if 2 - 2: iIii1I11I1II1
   if ( iiiiIiiiiI ) : lisp_install_host_route ( oooOO0oOooO00 , iiiiIiiiiI , True )
   if 85 - 85: O0 - ooOoO0o
   if 35 - 35: o0oOOo0O0Ooo - I1IiiI
   if 47 - 47: i11iIiiIii * iII111i . OoOoOO00 * I1Ii111 % i11iIiiIii + Ii1I
   if 65 - 65: Ii1I % i11iIiiIii
   i111I11I += 1
   if ( ( i111I11I % 10 ) == 0 ) : time . sleep ( 0.020 )
   if 98 - 98: iII111i * o0oOOo0O0Ooo % Oo0Ooo
   if 7 - 7: oO0o * OoooooooOO % o0oOOo0O0Ooo . I1Ii111 + O0
   if 14 - 14: I11i * II111iiii % o0oOOo0O0Ooo / iII111i . OoooooooOO % iII111i
 lprint ( "---------- End RLOC Probing ----------" )
 return
 if 88 - 88: iII111i
 if 94 - 94: OoooooooOO
 if 32 - 32: I1ii11iIi11i
 if 8 - 8: I11i * i11iIiiIii - ooOoO0o
 if 47 - 47: ooOoO0o . I1IiiI / i11iIiiIii * iII111i * I1IiiI
 if 8 - 8: oO0o % oO0o . iII111i / i1IIi % IiII
 if 71 - 71: OoOoOO00 + oO0o % O0 + Oo0Ooo
 if 62 - 62: i1IIi . Ii1I * i1IIi * O0 . I1IiiI % o0oOOo0O0Ooo
def lisp_update_rtr_updown ( rtr , updown ) :
 global lisp_ipc_socket
 if 16 - 16: I11i . Ii1I - ooOoO0o . OOooOOo % O0 / oO0o
 if 42 - 42: II111iiii . iII111i
 if 67 - 67: i1IIi - i11iIiiIii / ooOoO0o * oO0o
 if 64 - 64: oO0o / IiII
 if ( lisp_i_am_itr == False ) : return
 if 86 - 86: I11i
 if 36 - 36: o0oOOo0O0Ooo / OoO0O00
 if 6 - 6: I11i % I1IiiI + iII111i * OoooooooOO . O0
 if 87 - 87: ooOoO0o / Ii1I % O0 . OoO0O00
 if 55 - 55: i1IIi . o0oOOo0O0Ooo % OoooooooOO + II111iiii . OoOoOO00
 if ( lisp_register_all_rtrs ) : return
 if 32 - 32: IiII * I1Ii111 * Oo0Ooo . i1IIi * OoooooooOO
 iiO0ooOO = rtr . print_address_no_iid ( )
 if 63 - 63: OoooooooOO - ooOoO0o % oO0o / i11iIiiIii % i11iIiiIii
 if 30 - 30: Oo0Ooo . IiII . OoooooooOO
 if 86 - 86: I1ii11iIi11i * OoOoOO00 + iII111i
 if 79 - 79: I11i - II111iiii
 if 27 - 27: I1IiiI + o0oOOo0O0Ooo * oO0o % I1IiiI
 if ( lisp_rtr_list . has_key ( iiO0ooOO ) == False ) : return
 if 66 - 66: OoO0O00 + IiII . o0oOOo0O0Ooo . IiII
 updown = "up" if updown else "down"
 lprint ( "Send ETR IPC message, RTR {} has done {}" . format (
 red ( iiO0ooOO , False ) , bold ( updown , False ) ) )
 if 88 - 88: oO0o + oO0o % OoO0O00 . OoooooooOO - OoooooooOO . Oo0Ooo
 if 44 - 44: I1IiiI * IiII . OoooooooOO
 if 62 - 62: I11i - Ii1I / i11iIiiIii * I1IiiI + ooOoO0o + o0oOOo0O0Ooo
 if 10 - 10: i1IIi + o0oOOo0O0Ooo
 IIiIi1II1IiI = "rtr%{}%{}" . format ( iiO0ooOO , updown )
 IIiIi1II1IiI = lisp_command_ipc ( IIiIi1II1IiI , "lisp-itr" )
 lisp_ipc ( IIiIi1II1IiI , lisp_ipc_socket , "lisp-etr" )
 return
 if 47 - 47: OOooOOo * IiII % I1Ii111 . OoOoOO00 - OoooooooOO / OoooooooOO
 if 79 - 79: I11i % i11iIiiIii % I1IiiI . OoooooooOO * oO0o . Ii1I
 if 14 - 14: iIii1I11I1II1 / I11i - o0oOOo0O0Ooo / IiII / o0oOOo0O0Ooo . OoO0O00
 if 2 - 2: I11i
 if 12 - 12: i1IIi . I1Ii111
 if 99 - 99: Oo0Ooo / i11iIiiIii
 if 81 - 81: Ii1I . i1IIi % iII111i . OoO0O00 % IiII
def lisp_process_rloc_probe_reply ( rloc_addr , source , port , nonce , hop_count ,
 ttl ) :
 o0ooOOoO0O = bold ( "RLOC-probe reply" , False )
 i1IiiIi = rloc_addr . print_address_no_iid ( )
 iiII1ii1iI1 = source . print_address_no_iid ( )
 iIIi1i1i11i1 = lisp_rloc_probe_list
 if 1 - 1: I1ii11iIi11i % OoOoOO00 . I1ii11iIi11i . OoooooooOO % oO0o + Ii1I
 if 46 - 46: I1IiiI + OoO0O00 - Oo0Ooo
 if 13 - 13: OoOoOO00
 if 72 - 72: II111iiii * iII111i . II111iiii + iII111i * IiII
 if 90 - 90: oO0o * I1Ii111 / O0
 if 15 - 15: o0oOOo0O0Ooo * O0 . OOooOOo / Oo0Ooo
 o00Ooo0 = i1IiiIi
 if ( iIIi1i1i11i1 . has_key ( o00Ooo0 ) == False ) :
  o00Ooo0 += ":" + str ( port )
  if ( iIIi1i1i11i1 . has_key ( o00Ooo0 ) == False ) :
   o00Ooo0 = iiII1ii1iI1
   if ( iIIi1i1i11i1 . has_key ( o00Ooo0 ) == False ) :
    o00Ooo0 += ":" + str ( port )
    lprint ( "    Received unsolicited {} from {}/{}" . format ( o0ooOOoO0O ,
 red ( i1IiiIi , False ) , red ( iiII1ii1iI1 , False ) ) )
    return
    if 28 - 28: OoooooooOO + OoooooooOO
    if 27 - 27: I11i . oO0o / OoooooooOO - OoO0O00 . I11i
    if 15 - 15: II111iiii * OoO0O00
    if 33 - 33: OoooooooOO . o0oOOo0O0Ooo . I1IiiI / I1ii11iIi11i . OoOoOO00
    if 58 - 58: Ii1I
    if 20 - 20: OOooOOo
    if 93 - 93: i1IIi . IiII % O0 * iII111i
    if 84 - 84: I11i
 for Oo0O0 , oOOOO , iiI in lisp_rloc_probe_list [ o00Ooo0 ] :
  if ( lisp_i_am_rtr and Oo0O0 . translated_port != 0 and
 Oo0O0 . translated_port != port ) : continue
  if 99 - 99: I1ii11iIi11i
  Oo0O0 . process_rloc_probe_reply ( nonce , oOOOO , iiI , hop_count , ttl )
  if 78 - 78: I1Ii111 . IiII - OOooOOo
 return
 if 93 - 93: iIii1I11I1II1
 if 33 - 33: OOooOOo . i1IIi
 if 63 - 63: II111iiii . oO0o * IiII
 if 73 - 73: iII111i . i1IIi + oO0o + OOooOOo + ooOoO0o - iIii1I11I1II1
 if 47 - 47: I11i
 if 88 - 88: OoO0O00 - OoooooooOO
 if 93 - 93: Oo0Ooo * I1IiiI
 if 60 - 60: I1Ii111 + OOooOOo % iII111i
def lisp_db_list_length ( ) :
 i111I11I = 0
 for iIiIi in lisp_db_list :
  i111I11I += len ( iIiIi . dynamic_eids ) if iIiIi . dynamic_eid_configured ( ) else 1
  i111I11I += len ( iIiIi . eid . iid_list )
  if 40 - 40: I11i + oO0o . O0 % oO0o
 return ( i111I11I )
 if 12 - 12: iIii1I11I1II1
 if 9 - 9: OoOoOO00 * II111iiii / o0oOOo0O0Ooo * iII111i - II111iiii / i11iIiiIii
 if 14 - 14: i11iIiiIii + I1Ii111 . OoOoOO00 - oO0o * OoO0O00
 if 23 - 23: iIii1I11I1II1
 if 32 - 32: iII111i * iIii1I11I1II1 + I1Ii111 + IiII + O0 * OoO0O00
 if 100 - 100: II111iiii
 if 34 - 34: I11i % OOooOOo - iII111i % II111iiii
def lisp_is_myeid ( eid ) :
 for iIiIi in lisp_db_list :
  if ( iIiIi . eid . is_exact_match ( eid ) ) : return ( True )
  if 14 - 14: I11i * o0oOOo0O0Ooo % II111iiii
 return ( False )
 if 36 - 36: ooOoO0o - iIii1I11I1II1 / IiII + OoOoOO00
 if 42 - 42: ooOoO0o + I1IiiI * iII111i / OoOoOO00 . i1IIi - OoooooooOO
 if 8 - 8: iIii1I11I1II1 - Oo0Ooo + iII111i
 if 40 - 40: o0oOOo0O0Ooo * I1IiiI
 if 75 - 75: O0 * OOooOOo / ooOoO0o + I11i
 if 56 - 56: I1IiiI % OoooooooOO % Oo0Ooo
 if 19 - 19: i11iIiiIii - iIii1I11I1II1 . i1IIi . I1Ii111 / I1IiiI * I1Ii111
 if 41 - 41: oO0o . o0oOOo0O0Ooo . I11i * OoOoOO00
 if 16 - 16: oO0o
def lisp_format_macs ( sa , da ) :
 sa = sa [ 0 : 4 ] + "-" + sa [ 4 : 8 ] + "-" + sa [ 8 : 12 ]
 da = da [ 0 : 4 ] + "-" + da [ 4 : 8 ] + "-" + da [ 8 : 12 ]
 return ( "{} -> {}" . format ( sa , da ) )
 if 32 - 32: OoooooooOO
 if 77 - 77: Oo0Ooo . i1IIi - I11i
 if 98 - 98: O0
 if 87 - 87: OoO0O00 % I1Ii111 - OOooOOo - II111iiii + iII111i
 if 54 - 54: i1IIi % iII111i
 if 16 - 16: II111iiii - Oo0Ooo
 if 44 - 44: OOooOOo / Oo0Ooo - I1ii11iIi11i + I11i . oO0o
def lisp_get_echo_nonce ( rloc , rloc_str ) :
 if ( lisp_nonce_echoing == False ) : return ( None )
 if 85 - 85: iIii1I11I1II1 / Ii1I
 if ( rloc ) : rloc_str = rloc . print_address_no_iid ( )
 oooOo00 = None
 if ( lisp_nonce_echo_list . has_key ( rloc_str ) ) :
  oooOo00 = lisp_nonce_echo_list [ rloc_str ]
  if 43 - 43: I1IiiI % I1Ii111 - oO0o . II111iiii / iIii1I11I1II1
 return ( oooOo00 )
 if 97 - 97: I1Ii111 + I1ii11iIi11i
 if 21 - 21: O0 + o0oOOo0O0Ooo * OoooooooOO % IiII % I1ii11iIi11i
 if 80 - 80: I11i
 if 28 - 28: OoOoOO00 * OoooooooOO * i11iIiiIii
 if 88 - 88: ooOoO0o + ooOoO0o / I1Ii111
 if 69 - 69: O0 * o0oOOo0O0Ooo + i1IIi * ooOoO0o . o0oOOo0O0Ooo
 if 46 - 46: Oo0Ooo / Oo0Ooo * IiII
 if 65 - 65: iIii1I11I1II1 * o0oOOo0O0Ooo - iII111i % II111iiii - I1ii11iIi11i
def lisp_decode_dist_name ( packet ) :
 i111I11I = 0
 o0Oo0O00oo = ""
 if 11 - 11: I1ii11iIi11i + iIii1I11I1II1 - I1Ii111 * iIii1I11I1II1 * IiII + oO0o
 while ( packet [ 0 : 1 ] != "\0" ) :
  if ( i111I11I == 255 ) : return ( [ None , None ] )
  o0Oo0O00oo += packet [ 0 : 1 ]
  packet = packet [ 1 : : ]
  i111I11I += 1
  if 6 - 6: I1Ii111 * OOooOOo + i1IIi - Ii1I / oO0o
  if 81 - 81: I1Ii111 % oO0o * i1IIi * OoooooooOO / Oo0Ooo
 packet = packet [ 1 : : ]
 return ( packet , o0Oo0O00oo )
 if 70 - 70: I1IiiI
 if 35 - 35: i11iIiiIii
 if 59 - 59: ooOoO0o . iII111i - II111iiii
 if 30 - 30: o0oOOo0O0Ooo % iII111i - i11iIiiIii
 if 25 - 25: i11iIiiIii + OoOoOO00 + oO0o / Ii1I * Oo0Ooo + Oo0Ooo
 if 26 - 26: I1IiiI % I1ii11iIi11i + o0oOOo0O0Ooo / I1ii11iIi11i - I1IiiI
 if 55 - 55: OoooooooOO
 if 2 - 2: Oo0Ooo + I11i / OOooOOo + OOooOOo
def lisp_write_flow_log ( flow_log ) :
 iI1i1i1i1i = open ( "./logs/lisp-flow.log" , "a" )
 if 62 - 62: OOooOOo . iIii1I11I1II1 + I1IiiI / OOooOOo
 i111I11I = 0
 for OOO00000O in flow_log :
  iIIi1 = OOO00000O [ 3 ]
  oo0OOoOOOO = iIIi1 . print_flow ( OOO00000O [ 0 ] , OOO00000O [ 1 ] , OOO00000O [ 2 ] )
  iI1i1i1i1i . write ( oo0OOoOOOO )
  i111I11I += 1
  if 38 - 38: O0 * iIii1I11I1II1 - oO0o
 iI1i1i1i1i . close ( )
 del ( flow_log )
 if 38 - 38: iIii1I11I1II1 / I1Ii111 + ooOoO0o . II111iiii - iIii1I11I1II1
 i111I11I = bold ( str ( i111I11I ) , False )
 lprint ( "Wrote {} flow entries to ./logs/lisp-flow.log" . format ( i111I11I ) )
 return
 if 13 - 13: Ii1I
 if 34 - 34: I1IiiI / iIii1I11I1II1
 if 35 - 35: oO0o / oO0o
 if 86 - 86: o0oOOo0O0Ooo . Oo0Ooo - Ii1I / i11iIiiIii
 if 63 - 63: oO0o - O0 + I1ii11iIi11i + Ii1I / i1IIi
 if 77 - 77: O0
 if 49 - 49: o0oOOo0O0Ooo / i11iIiiIii
def lisp_policy_command ( kv_pair ) :
 iII1ii = lisp_policy ( "" )
 i1III = None
 if 97 - 97: i1IIi
 iIO0Oo0 = [ ]
 for ooOooo0OO in range ( len ( kv_pair [ "datetime-range" ] ) ) :
  iIO0Oo0 . append ( lisp_policy_match ( ) )
  if 21 - 21: II111iiii
  if 41 - 41: IiII % II111iiii
 for o0oOO00O in kv_pair . keys ( ) :
  I1Iii1iI1 = kv_pair [ o0oOO00O ]
  if 6 - 6: ooOoO0o % Oo0Ooo / I1Ii111 % i11iIiiIii * OoooooooOO + I1ii11iIi11i
  if 21 - 21: o0oOOo0O0Ooo - iII111i / OoO0O00
  if 12 - 12: I1ii11iIi11i - I11i * O0 % I1IiiI + O0 - II111iiii
  if 13 - 13: iII111i / OOooOOo * i11iIiiIii / oO0o / OoooooooOO
  if ( o0oOO00O == "instance-id" ) :
   for ooOooo0OO in range ( len ( iIO0Oo0 ) ) :
    O0oO00OO0oO0 = I1Iii1iI1 [ ooOooo0OO ]
    if ( O0oO00OO0oO0 == "" ) : continue
    i11I1I111I = iIO0Oo0 [ ooOooo0OO ]
    if ( i11I1I111I . source_eid == None ) :
     i11I1I111I . source_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
     if 51 - 51: o0oOOo0O0Ooo . IiII + Ii1I - IiII - i1IIi + I1IiiI
    if ( i11I1I111I . dest_eid == None ) :
     i11I1I111I . dest_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
     if 75 - 75: iII111i - iIii1I11I1II1 / I1IiiI / iIii1I11I1II1
    i11I1I111I . source_eid . instance_id = int ( O0oO00OO0oO0 )
    i11I1I111I . dest_eid . instance_id = int ( O0oO00OO0oO0 )
    if 31 - 31: iII111i . OoO0O00 / i1IIi - I1Ii111 - I11i * i1IIi
    if 8 - 8: ooOoO0o / I1ii11iIi11i * I1IiiI / OOooOOo
  if ( o0oOO00O == "source-eid" ) :
   for ooOooo0OO in range ( len ( iIO0Oo0 ) ) :
    O0oO00OO0oO0 = I1Iii1iI1 [ ooOooo0OO ]
    if ( O0oO00OO0oO0 == "" ) : continue
    i11I1I111I = iIO0Oo0 [ ooOooo0OO ]
    if ( i11I1I111I . source_eid == None ) :
     i11I1I111I . source_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
     if 77 - 77: OoOoOO00 - i11iIiiIii % OoOoOO00 / I1Ii111 / I1Ii111
    iiI1iii = i11I1I111I . source_eid . instance_id
    i11I1I111I . source_eid . store_prefix ( O0oO00OO0oO0 )
    i11I1I111I . source_eid . instance_id = iiI1iii
    if 84 - 84: IiII * i11iIiiIii / iII111i % iII111i + i11iIiiIii % ooOoO0o
    if 70 - 70: iIii1I11I1II1 - I1Ii111 . oO0o . iII111i / o0oOOo0O0Ooo
  if ( o0oOO00O == "destination-eid" ) :
   for ooOooo0OO in range ( len ( iIO0Oo0 ) ) :
    O0oO00OO0oO0 = I1Iii1iI1 [ ooOooo0OO ]
    if ( O0oO00OO0oO0 == "" ) : continue
    i11I1I111I = iIO0Oo0 [ ooOooo0OO ]
    if ( i11I1I111I . dest_eid == None ) :
     i11I1I111I . dest_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
     if 8 - 8: O0 - I1Ii111
    iiI1iii = i11I1I111I . dest_eid . instance_id
    i11I1I111I . dest_eid . store_prefix ( O0oO00OO0oO0 )
    i11I1I111I . dest_eid . instance_id = iiI1iii
    if 82 - 82: iII111i + II111iiii
    if 29 - 29: O0 % Ii1I * ooOoO0o % O0
  if ( o0oOO00O == "source-rloc" ) :
   for ooOooo0OO in range ( len ( iIO0Oo0 ) ) :
    O0oO00OO0oO0 = I1Iii1iI1 [ ooOooo0OO ]
    if ( O0oO00OO0oO0 == "" ) : continue
    i11I1I111I = iIO0Oo0 [ ooOooo0OO ]
    i11I1I111I . source_rloc = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
    i11I1I111I . source_rloc . store_prefix ( O0oO00OO0oO0 )
    if 83 - 83: oO0o
    if 95 - 95: Oo0Ooo * O0 % i1IIi / iII111i + oO0o
  if ( o0oOO00O == "destination-rloc" ) :
   for ooOooo0OO in range ( len ( iIO0Oo0 ) ) :
    O0oO00OO0oO0 = I1Iii1iI1 [ ooOooo0OO ]
    if ( O0oO00OO0oO0 == "" ) : continue
    i11I1I111I = iIO0Oo0 [ ooOooo0OO ]
    i11I1I111I . dest_rloc = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
    i11I1I111I . dest_rloc . store_prefix ( O0oO00OO0oO0 )
    if 85 - 85: iIii1I11I1II1 / I11i
    if 65 - 65: I11i / i1IIi * OoOoOO00 * Ii1I * OoO0O00
  if ( o0oOO00O == "rloc-record-name" ) :
   for ooOooo0OO in range ( len ( iIO0Oo0 ) ) :
    O0oO00OO0oO0 = I1Iii1iI1 [ ooOooo0OO ]
    if ( O0oO00OO0oO0 == "" ) : continue
    i11I1I111I = iIO0Oo0 [ ooOooo0OO ]
    i11I1I111I . rloc_record_name = O0oO00OO0oO0
    if 74 - 74: I1ii11iIi11i . I1ii11iIi11i % IiII + OOooOOo . OoO0O00 * I11i
    if 20 - 20: OOooOOo % i1IIi * Ii1I / i11iIiiIii
  if ( o0oOO00O == "geo-name" ) :
   for ooOooo0OO in range ( len ( iIO0Oo0 ) ) :
    O0oO00OO0oO0 = I1Iii1iI1 [ ooOooo0OO ]
    if ( O0oO00OO0oO0 == "" ) : continue
    i11I1I111I = iIO0Oo0 [ ooOooo0OO ]
    i11I1I111I . geo_name = O0oO00OO0oO0
    if 89 - 89: ooOoO0o
    if 83 - 83: I11i . I11i * OOooOOo - OOooOOo
  if ( o0oOO00O == "elp-name" ) :
   for ooOooo0OO in range ( len ( iIO0Oo0 ) ) :
    O0oO00OO0oO0 = I1Iii1iI1 [ ooOooo0OO ]
    if ( O0oO00OO0oO0 == "" ) : continue
    i11I1I111I = iIO0Oo0 [ ooOooo0OO ]
    i11I1I111I . elp_name = O0oO00OO0oO0
    if 46 - 46: iIii1I11I1II1 . I1Ii111 % I1IiiI
    if 22 - 22: i1IIi * I11i + II111iiii + II111iiii
  if ( o0oOO00O == "rle-name" ) :
   for ooOooo0OO in range ( len ( iIO0Oo0 ) ) :
    O0oO00OO0oO0 = I1Iii1iI1 [ ooOooo0OO ]
    if ( O0oO00OO0oO0 == "" ) : continue
    i11I1I111I = iIO0Oo0 [ ooOooo0OO ]
    i11I1I111I . rle_name = O0oO00OO0oO0
    if 20 - 20: I11i
    if 37 - 37: I1Ii111
  if ( o0oOO00O == "json-name" ) :
   for ooOooo0OO in range ( len ( iIO0Oo0 ) ) :
    O0oO00OO0oO0 = I1Iii1iI1 [ ooOooo0OO ]
    if ( O0oO00OO0oO0 == "" ) : continue
    i11I1I111I = iIO0Oo0 [ ooOooo0OO ]
    i11I1I111I . json_name = O0oO00OO0oO0
    if 19 - 19: I1ii11iIi11i / OOooOOo . I1IiiI / ooOoO0o + OoO0O00 + i11iIiiIii
    if 80 - 80: OoO0O00 . O0 / Ii1I % I1Ii111 / iII111i * I1IiiI
  if ( o0oOO00O == "datetime-range" ) :
   for ooOooo0OO in range ( len ( iIO0Oo0 ) ) :
    O0oO00OO0oO0 = I1Iii1iI1 [ ooOooo0OO ]
    i11I1I111I = iIO0Oo0 [ ooOooo0OO ]
    if ( O0oO00OO0oO0 == "" ) : continue
    o0Oo = lisp_datetime ( O0oO00OO0oO0 [ 0 : 19 ] )
    Oo0o00000o = lisp_datetime ( O0oO00OO0oO0 [ 19 : : ] )
    if ( o0Oo . valid_datetime ( ) and Oo0o00000o . valid_datetime ( ) ) :
     i11I1I111I . datetime_lower = o0Oo
     i11I1I111I . datetime_upper = Oo0o00000o
     if 41 - 41: O0 / OoooooooOO - i1IIi
     if 6 - 6: i1IIi - I1ii11iIi11i % I1Ii111 - II111iiii / ooOoO0o / i11iIiiIii
     if 32 - 32: oO0o / IiII - I11i . ooOoO0o
     if 69 - 69: i11iIiiIii * i11iIiiIii
     if 100 - 100: I1ii11iIi11i * I1ii11iIi11i + i1IIi
     if 96 - 96: I1Ii111 / I1IiiI + ooOoO0o
     if 16 - 16: I1ii11iIi11i % o0oOOo0O0Ooo % OOooOOo % OoOoOO00 + ooOoO0o % I1ii11iIi11i
  if ( o0oOO00O == "set-action" ) :
   iII1ii . set_action = I1Iii1iI1
   if 85 - 85: oO0o * OoooooooOO * iIii1I11I1II1 + iII111i
  if ( o0oOO00O == "set-record-ttl" ) :
   iII1ii . set_record_ttl = int ( I1Iii1iI1 )
   if 67 - 67: Ii1I / i11iIiiIii % OoOoOO00 % O0 / OoOoOO00
  if ( o0oOO00O == "set-instance-id" ) :
   if ( iII1ii . set_source_eid == None ) :
    iII1ii . set_source_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
    if 54 - 54: I11i . OoOoOO00 / II111iiii . i1IIi + OOooOOo % II111iiii
   if ( iII1ii . set_dest_eid == None ) :
    iII1ii . set_dest_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
    if 82 - 82: i11iIiiIii . OoooooooOO % OoOoOO00 * O0 - I1Ii111
   i1III = int ( I1Iii1iI1 )
   iII1ii . set_source_eid . instance_id = i1III
   iII1ii . set_dest_eid . instance_id = i1III
   if 78 - 78: OoOoOO00 % Ii1I % OOooOOo % Oo0Ooo % I11i . Ii1I
  if ( o0oOO00O == "set-source-eid" ) :
   if ( iII1ii . set_source_eid == None ) :
    iII1ii . set_source_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
    if 73 - 73: OoooooooOO / i1IIi . iIii1I11I1II1
   iII1ii . set_source_eid . store_prefix ( I1Iii1iI1 )
   if ( i1III != None ) : iII1ii . set_source_eid . instance_id = i1III
   if 89 - 89: I1Ii111
  if ( o0oOO00O == "set-destination-eid" ) :
   if ( iII1ii . set_dest_eid == None ) :
    iII1ii . set_dest_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
    if 29 - 29: I11i * ooOoO0o - OoooooooOO
   iII1ii . set_dest_eid . store_prefix ( I1Iii1iI1 )
   if ( i1III != None ) : iII1ii . set_dest_eid . instance_id = i1III
   if 92 - 92: O0 % i1IIi / OOooOOo - oO0o
  if ( o0oOO00O == "set-rloc-address" ) :
   iII1ii . set_rloc_address = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
   iII1ii . set_rloc_address . store_address ( I1Iii1iI1 )
   if 83 - 83: o0oOOo0O0Ooo . OoO0O00 % iIii1I11I1II1 % OoOoOO00 - i11iIiiIii
  if ( o0oOO00O == "set-rloc-record-name" ) :
   iII1ii . set_rloc_record_name = I1Iii1iI1
   if 71 - 71: I1ii11iIi11i - II111iiii / O0 % i1IIi + oO0o
  if ( o0oOO00O == "set-elp-name" ) :
   iII1ii . set_elp_name = I1Iii1iI1
   if 73 - 73: OoooooooOO
  if ( o0oOO00O == "set-geo-name" ) :
   iII1ii . set_geo_name = I1Iii1iI1
   if 25 - 25: i1IIi . II111iiii . I1Ii111
  if ( o0oOO00O == "set-rle-name" ) :
   iII1ii . set_rle_name = I1Iii1iI1
   if 81 - 81: II111iiii + OoOoOO00 * II111iiii / iIii1I11I1II1 - Oo0Ooo % oO0o
  if ( o0oOO00O == "set-json-name" ) :
   iII1ii . set_json_name = I1Iii1iI1
   if 66 - 66: ooOoO0o % O0 + iIii1I11I1II1 * I1Ii111 - I1Ii111
  if ( o0oOO00O == "policy-name" ) :
   iII1ii . policy_name = I1Iii1iI1
   if 61 - 61: I1ii11iIi11i
   if 12 - 12: OoO0O00
   if 97 - 97: OOooOOo . Oo0Ooo . oO0o * i1IIi
   if 7 - 7: Oo0Ooo
   if 38 - 38: Oo0Ooo - I1ii11iIi11i
   if 19 - 19: Ii1I * OoO0O00 / OoO0O00 . II111iiii % iIii1I11I1II1
 iII1ii . match_clauses = iIO0Oo0
 iII1ii . save_policy ( )
 return
 if 61 - 61: I1ii11iIi11i * oO0o % iII111i + IiII + i11iIiiIii * I11i
 if 3 - 3: Ii1I
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
if 71 - 71: iIii1I11I1II1 . OOooOOo / I11i / i1IIi
if 69 - 69: i1IIi / iII111i + Ii1I + I11i + IiII
if 86 - 86: Oo0Ooo
if 97 - 97: I1IiiI
if 91 - 91: ooOoO0o / oO0o * OOooOOo . II111iiii - I11i - I11i
if 5 - 5: O0 + OoooooooOO + i11iIiiIii * Oo0Ooo * OoOoOO00 . oO0o
if 6 - 6: OoO0O00 % Oo0Ooo % I1IiiI % o0oOOo0O0Ooo % O0 % Oo0Ooo
def lisp_send_to_arista ( command , interface ) :
 interface = "" if ( interface == None ) else "interface " + interface
 if 94 - 94: I11i . i1IIi / II111iiii + OOooOOo
 oo0000o0oO = command
 if ( interface != "" ) : oo0000o0oO = interface + ": " + oo0000o0oO
 lprint ( "Send CLI command '{}' to hardware" . format ( oo0000o0oO ) )
 if 41 - 41: OOooOOo / I1ii11iIi11i % OOooOOo * I11i / OOooOOo - oO0o
 commands = '''
        enable
        configure
        {}
        {}
    ''' . format ( interface , command )
 if 18 - 18: i1IIi - OOooOOo - o0oOOo0O0Ooo - iIii1I11I1II1
 os . system ( "FastCli -c '{}'" . format ( commands ) )
 return
 if 72 - 72: OoooooooOO % I1IiiI . OoO0O00
 if 28 - 28: II111iiii / iIii1I11I1II1 / iII111i - o0oOOo0O0Ooo . I1IiiI / O0
 if 16 - 16: ooOoO0o * oO0o . OoooooooOO
 if 44 - 44: iIii1I11I1II1 * OOooOOo + OoO0O00 - OoooooooOO
 if 13 - 13: Oo0Ooo . I11i . II111iiii
 if 6 - 6: OOooOOo . IiII / OoO0O00 * oO0o - I1Ii111 . OoOoOO00
 if 85 - 85: i11iIiiIii + OoOoOO00
def lisp_arista_is_alive ( prefix ) :
 Ii1I1i111 = "enable\nsh plat trident l3 software routes {}\n" . format ( prefix )
 OOoo0oo = commands . getoutput ( "FastCli -c '{}'" . format ( Ii1I1i111 ) )
 if 4 - 4: OOooOOo . OoO0O00 * II111iiii + OoO0O00 % Oo0Ooo
 if 60 - 60: OOooOOo . Ii1I
 if 13 - 13: i1IIi . iII111i / OoOoOO00 . I1Ii111
 if 65 - 65: oO0o % I1Ii111 % OoO0O00 . iIii1I11I1II1
 OOoo0oo = OOoo0oo . split ( "\n" ) [ 1 ]
 I1i1OooOooo0O00o = OOoo0oo . split ( " " )
 I1i1OooOooo0O00o = I1i1OooOooo0O00o [ - 1 ] . replace ( "\r" , "" )
 if 65 - 65: OoOoOO00
 if 31 - 31: iIii1I11I1II1 . iIii1I11I1II1 / IiII + I1ii11iIi11i * iIii1I11I1II1 / iIii1I11I1II1
 if 100 - 100: Ii1I / I1Ii111 + I1Ii111
 if 52 - 52: iIii1I11I1II1 % OoO0O00 - IiII % i11iIiiIii - o0oOOo0O0Ooo
 return ( I1i1OooOooo0O00o == "Y" )
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
def lisp_program_vxlan_hardware ( mc ) :
 if 51 - 51: iII111i * iIii1I11I1II1 % Ii1I * Ii1I + i11iIiiIii . OoooooooOO
 if 54 - 54: i11iIiiIii . iIii1I11I1II1 * iIii1I11I1II1 + Ii1I % I11i - OoO0O00
 if 16 - 16: IiII % iIii1I11I1II1 * i11iIiiIii + O0
 if 76 - 76: iII111i * OOooOOo
 if 7 - 7: ooOoO0o + o0oOOo0O0Ooo + o0oOOo0O0Ooo
 if 73 - 73: IiII % I11i % i11iIiiIii + ooOoO0o
 if ( os . path . exists ( "/persist/local/lispers.net" ) == False ) : return
 if 83 - 83: Ii1I * I1Ii111 * i11iIiiIii / iIii1I11I1II1 % I1ii11iIi11i
 if 40 - 40: iII111i
 if 21 - 21: I1Ii111 / iII111i + Oo0Ooo / I1ii11iIi11i / I1Ii111
 if 33 - 33: OoooooooOO
 if ( len ( mc . best_rloc_set ) == 0 ) : return
 if 59 - 59: i11iIiiIii - OoooooooOO . ooOoO0o / i11iIiiIii % iIii1I11I1II1 * I1ii11iIi11i
 if 45 - 45: I1ii11iIi11i * I1ii11iIi11i
 if 31 - 31: OoO0O00 - OOooOOo . iII111i * I1Ii111 * iII111i + I1ii11iIi11i
 if 5 - 5: Oo0Ooo . I1Ii111
 i1IIIII1 = mc . eid . print_prefix_no_iid ( )
 Oo0O0 = mc . best_rloc_set [ 0 ] . rloc . print_address_no_iid ( )
 if 77 - 77: i11iIiiIii / I1Ii111 / I1ii11iIi11i % oO0o
 if 83 - 83: Ii1I % iIii1I11I1II1 / I1ii11iIi11i + I11i
 if 23 - 23: iIii1I11I1II1 - I1IiiI
 if 51 - 51: OoooooooOO / IiII / I1ii11iIi11i . Oo0Ooo - o0oOOo0O0Ooo * OoooooooOO
 IIi1iiiIIiI = commands . getoutput ( "ip route get {} | egrep vlan4094" . format ( i1IIIII1 ) )
 if 97 - 97: I1Ii111 * oO0o - I1IiiI / I1ii11iIi11i % o0oOOo0O0Ooo / I1IiiI
 if ( IIi1iiiIIiI != "" ) :
  lprint ( "Route {} already in hardware: '{}'" . format ( green ( i1IIIII1 , False ) , IIi1iiiIIiI ) )
  if 20 - 20: I1Ii111 . I1ii11iIi11i
  return
  if 53 - 53: iII111i
  if 46 - 46: o0oOOo0O0Ooo
  if 44 - 44: i11iIiiIii + i11iIiiIii + Oo0Ooo . I11i
  if 79 - 79: OoOoOO00 . iII111i
  if 86 - 86: ooOoO0o
  if 32 - 32: iII111i % OoooooooOO
  if 11 - 11: I1Ii111 / I1ii11iIi11i
 Iii = commands . getoutput ( "ifconfig | egrep 'vxlan|vlan4094'" )
 if ( Iii . find ( "vxlan" ) == - 1 ) :
  lprint ( "No VXLAN interface found, cannot program hardware" )
  return
  if 72 - 72: OoO0O00 . IiII * Ii1I - I1IiiI
 if ( Iii . find ( "vlan4094" ) == - 1 ) :
  lprint ( "No vlan4094 interface found, cannot program hardware" )
  return
  if 81 - 81: oO0o . OOooOOo - Ii1I . OoOoOO00
 O00oOoO0OOOo = commands . getoutput ( "ip addr | egrep vlan4094 | egrep inet" )
 if ( O00oOoO0OOOo == "" ) :
  lprint ( "No IP address found on vlan4094, cannot program hardware" )
  return
  if 40 - 40: O0 - OoO0O00
 O00oOoO0OOOo = O00oOoO0OOOo . split ( "inet " ) [ 1 ]
 O00oOoO0OOOo = O00oOoO0OOOo . split ( "/" ) [ 0 ]
 if 34 - 34: IiII * IiII
 if 76 - 76: OOooOOo
 if 54 - 54: O0 * II111iiii * OOooOOo
 if 44 - 44: I1IiiI
 if 66 - 66: o0oOOo0O0Ooo
 if 40 - 40: OOooOOo * Ii1I
 if 38 - 38: ooOoO0o
 iiI111I = [ ]
 IiI1IiiI = commands . getoutput ( "arp -i vlan4094" ) . split ( "\n" )
 for iiIiiIi1 in IiI1IiiI :
  if ( iiIiiIi1 . find ( "vlan4094" ) == - 1 ) : continue
  if ( iiIiiIi1 . find ( "(incomplete)" ) == - 1 ) : continue
  iiiiIiiiiI = iiIiiIi1 . split ( " " ) [ 0 ]
  iiI111I . append ( iiiiIiiiiI )
  if 37 - 37: O0 . II111iiii
  if 70 - 70: o0oOOo0O0Ooo / iII111i + i1IIi + I11i % iIii1I11I1II1 % Oo0Ooo
 iiiiIiiiiI = None
 I1i1II1iI = O00oOoO0OOOo
 O00oOoO0OOOo = O00oOoO0OOOo . split ( "." )
 for ooOooo0OO in range ( 1 , 255 ) :
  O00oOoO0OOOo [ 3 ] = str ( ooOooo0OO )
  o00Ooo0 = "." . join ( O00oOoO0OOOo )
  if ( o00Ooo0 in iiI111I ) : continue
  if ( o00Ooo0 == I1i1II1iI ) : continue
  iiiiIiiiiI = o00Ooo0
  break
  if 1 - 1: O0 + OoO0O00 . i11iIiiIii + I1Ii111 - OoO0O00 - IiII
 if ( iiiiIiiiiI == None ) :
  lprint ( "Address allocation failed for vlan4094, cannot program " + "hardware" )
  if 1 - 1: I1ii11iIi11i / i1IIi . I1IiiI / Ii1I
  return
  if 19 - 19: iIii1I11I1II1 / Oo0Ooo . O0 - Oo0Ooo
  if 74 - 74: I1ii11iIi11i * OoooooooOO . iII111i
  if 45 - 45: I1IiiI - IiII % ooOoO0o - IiII . Oo0Ooo - o0oOOo0O0Ooo
  if 27 - 27: iII111i
  if 64 - 64: iIii1I11I1II1 - OOooOOo . iII111i % o0oOOo0O0Ooo / II111iiii % OoooooooOO
  if 87 - 87: OoooooooOO
  if 70 - 70: o0oOOo0O0Ooo % OoooooooOO % I1IiiI . OoOoOO00 * I1IiiI - ooOoO0o
 oo0 = Oo0O0 . split ( "." )
 O0o0 = lisp_hex_string ( oo0 [ 1 ] ) . zfill ( 2 )
 oOOo00O0Oo000 = lisp_hex_string ( oo0 [ 2 ] ) . zfill ( 2 )
 Ii1iII1 = lisp_hex_string ( oo0 [ 3 ] ) . zfill ( 2 )
 i1iIIi1II1iiI = "00:00:00:{}:{}:{}" . format ( O0o0 , oOOo00O0Oo000 , Ii1iII1 )
 ii1iiI = "0000.00{}.{}{}" . format ( O0o0 , oOOo00O0Oo000 , Ii1iII1 )
 OoOoooo = "arp -i vlan4094 -s {} {}" . format ( iiiiIiiiiI , i1iIIi1II1iiI )
 os . system ( OoOoooo )
 if 49 - 49: OoOoOO00 . I1IiiI . IiII / OoooooooOO . i11iIiiIii
 if 42 - 42: oO0o / I1ii11iIi11i - iIii1I11I1II1 + i1IIi * iIii1I11I1II1 * Ii1I
 if 37 - 37: I1Ii111 + i1IIi * o0oOOo0O0Ooo - i11iIiiIii
 if 92 - 92: I1Ii111 - I1IiiI + Ii1I / iII111i % OOooOOo
 IiI = ( "mac address-table static {} vlan 4094 " + "interface vxlan 1 vtep {}" ) . format ( ii1iiI , Oo0O0 )
 if 83 - 83: I11i % oO0o % oO0o / o0oOOo0O0Ooo + I1Ii111
 lisp_send_to_arista ( IiI , None )
 if 16 - 16: OoooooooOO
 if 9 - 9: i11iIiiIii . iII111i - o0oOOo0O0Ooo % i11iIiiIii + Oo0Ooo + Ii1I
 if 85 - 85: I11i % i11iIiiIii * I11i
 if 31 - 31: IiII * Oo0Ooo % OoO0O00
 if 60 - 60: I1IiiI + i11iIiiIii + oO0o + OoooooooOO % II111iiii
 oOO0OOoOo = "ip route add {} via {}" . format ( i1IIIII1 , iiiiIiiiiI )
 os . system ( oOO0OOoOo )
 if 70 - 70: i11iIiiIii - IiII
 lprint ( "Hardware programmed with commands:" )
 oOO0OOoOo = oOO0OOoOo . replace ( i1IIIII1 , green ( i1IIIII1 , False ) )
 lprint ( "  " + oOO0OOoOo )
 lprint ( "  " + OoOoooo )
 IiI = IiI . replace ( Oo0O0 , red ( Oo0O0 , False ) )
 lprint ( "  " + IiI )
 return
 if 35 - 35: Ii1I + Ii1I + iIii1I11I1II1 + I1Ii111 * OoO0O00 % o0oOOo0O0Ooo
 if 64 - 64: I1IiiI / OoOoOO00
 if 89 - 89: o0oOOo0O0Ooo - OOooOOo * I1Ii111 . i1IIi % I1IiiI . I11i
 if 99 - 99: I1Ii111 * ooOoO0o
 if 9 - 9: I1Ii111
 if 26 - 26: iIii1I11I1II1 - I11i . Oo0Ooo - I1Ii111
 if 3 - 3: I1IiiI + I1ii11iIi11i - I11i
def lisp_clear_hardware_walk ( mc , parms ) :
 Oo0OOoO0oo0oO = mc . eid . print_prefix_no_iid ( )
 os . system ( "ip route delete {}" . format ( Oo0OOoO0oo0oO ) )
 return ( [ True , None ] )
 if 15 - 15: OoOoOO00 . Oo0Ooo / ooOoO0o + Oo0Ooo - OoooooooOO - o0oOOo0O0Ooo
 if 64 - 64: OOooOOo
 if 44 - 44: O0 % ooOoO0o - iIii1I11I1II1 * i11iIiiIii . OoOoOO00
 if 32 - 32: I1ii11iIi11i - iII111i
 if 34 - 34: OOooOOo . i1IIi * o0oOOo0O0Ooo - I1Ii111 + I1ii11iIi11i
 if 32 - 32: i11iIiiIii . I1Ii111
 if 38 - 38: O0
 if 50 - 50: i11iIiiIii * OoO0O00 + iII111i / O0 * oO0o % ooOoO0o
def lisp_clear_map_cache ( ) :
 global lisp_map_cache , lisp_rloc_probe_list
 global lisp_crypto_keys_by_rloc_encap , lisp_crypto_keys_by_rloc_decap
 global lisp_rtr_list
 if 6 - 6: OoO0O00 . o0oOOo0O0Ooo / Ii1I + Ii1I
 oo0Oo0Oo = bold ( "User cleared" , False )
 i111I11I = lisp_map_cache . cache_count
 lprint ( "{} map-cache with {} entries" . format ( oo0Oo0Oo , i111I11I ) )
 if 61 - 61: iIii1I11I1II1
 if ( lisp_program_hardware ) :
  lisp_map_cache . walk_cache ( lisp_clear_hardware_walk , None )
  if 79 - 79: OoOoOO00 + Ii1I - oO0o - iIii1I11I1II1 + OoooooooOO
 lisp_map_cache = lisp_cache ( )
 if 87 - 87: ooOoO0o
 if 74 - 74: o0oOOo0O0Ooo - o0oOOo0O0Ooo % OoooooooOO . o0oOOo0O0Ooo - I1IiiI - I1ii11iIi11i
 if 40 - 40: II111iiii . Oo0Ooo * I1Ii111
 if 63 - 63: OoooooooOO + OoOoOO00 - OoooooooOO
 if 54 - 54: OoO0O00 + I1IiiI % O0 + OoO0O00
 lisp_rloc_probe_list = { }
 if 37 - 37: II111iiii / I1ii11iIi11i * I1IiiI - OoooooooOO
 if 55 - 55: IiII / ooOoO0o * I1IiiI / I1Ii111 - Oo0Ooo % o0oOOo0O0Ooo
 if 82 - 82: OoO0O00 - iIii1I11I1II1 . Oo0Ooo / IiII . OoO0O00
 if 47 - 47: OOooOOo + IiII
 lisp_crypto_keys_by_rloc_encap = { }
 lisp_crypto_keys_by_rloc_decap = { }
 if 11 - 11: Oo0Ooo + I1IiiI % i11iIiiIii % Oo0Ooo + ooOoO0o + i1IIi
 if 100 - 100: II111iiii - OOooOOo + iII111i - i11iIiiIii . O0 / iII111i
 if 64 - 64: Ii1I
 if 4 - 4: OoOoOO00
 if 78 - 78: i1IIi - iII111i + O0 - I1IiiI % o0oOOo0O0Ooo
 lisp_rtr_list = { }
 if 48 - 48: iII111i / II111iiii * I1Ii111 + I11i / ooOoO0o . OoOoOO00
 if 45 - 45: OOooOOo / Ii1I % O0
 if 7 - 7: oO0o * i11iIiiIii + OoooooooOO + I11i
 if 9 - 9: II111iiii * Oo0Ooo * I1Ii111 . IiII
 lisp_process_data_plane_restart ( True )
 return
 if 80 - 80: i11iIiiIii . i11iIiiIii . i11iIiiIii . OoooooooOO - OOooOOo * OoooooooOO
 if 96 - 96: oO0o
 if 80 - 80: IiII - oO0o % Ii1I - iIii1I11I1II1 . OoO0O00
 if 64 - 64: I1IiiI % i11iIiiIii / oO0o
 if 78 - 78: II111iiii - Oo0Ooo . iIii1I11I1II1 - ooOoO0o . oO0o
 if 84 - 84: iII111i . ooOoO0o * I1IiiI * Oo0Ooo / I1Ii111
 if 93 - 93: i1IIi * i11iIiiIii % OoOoOO00 % iII111i
 if 31 - 31: OoO0O00
 if 89 - 89: II111iiii
 if 33 - 33: OOooOOo / oO0o % OoOoOO00 * O0
 if 65 - 65: OoO0O00 % OoOoOO00 % I1ii11iIi11i / OoooooooOO
def lisp_encapsulate_rloc_probe ( lisp_sockets , rloc , nat_info , packet ) :
 if ( len ( lisp_sockets ) != 4 ) : return
 if 85 - 85: O0 * OOooOOo % I1Ii111
 ii1 = lisp_myrlocs [ 0 ]
 if 2 - 2: O0 . ooOoO0o
 if 65 - 65: O0 - o0oOOo0O0Ooo - OoO0O00
 if 8 - 8: IiII
 if 52 - 52: i11iIiiIii / O0 + oO0o . I11i
 if 73 - 73: OoooooooOO / I1IiiI % Oo0Ooo . oO0o + OoooooooOO
 Oooo = len ( packet ) + 28
 ii = struct . pack ( "BBHIBBHII" , 0x45 , 0 , socket . htons ( Oooo ) , 0 , 64 ,
 17 , 0 , socket . htonl ( ii1 . address ) , socket . htonl ( rloc . address ) )
 ii = lisp_ip_checksum ( ii )
 if 84 - 84: I1ii11iIi11i - OOooOOo * II111iiii
 iI = struct . pack ( "HHHH" , 0 , socket . htons ( LISP_CTRL_PORT ) ,
 socket . htons ( Oooo - 20 ) , 0 )
 if 28 - 28: I1ii11iIi11i . oO0o / o0oOOo0O0Ooo - iII111i
 if 65 - 65: I1ii11iIi11i * OOooOOo * ooOoO0o + oO0o - OOooOOo
 if 100 - 100: iII111i
 if 12 - 12: OoooooooOO - I1ii11iIi11i * iII111i / ooOoO0o
 packet = lisp_packet ( ii + iI + packet )
 if 99 - 99: I1ii11iIi11i + I11i
 if 29 - 29: I1ii11iIi11i / oO0o
 if 2 - 2: Oo0Ooo / IiII - OoooooooOO
 if 65 - 65: OoO0O00 - Ii1I
 packet . inner_dest . copy_address ( rloc )
 packet . inner_dest . instance_id = 0xffffff
 packet . inner_source . copy_address ( ii1 )
 packet . inner_ttl = 64
 packet . outer_dest . copy_address ( rloc )
 packet . outer_source . copy_address ( ii1 )
 packet . outer_version = packet . outer_dest . afi_to_version ( )
 packet . outer_ttl = 64
 packet . encap_port = nat_info . port if nat_info else LISP_DATA_PORT
 if 98 - 98: OoOoOO00 * I1Ii111 * iIii1I11I1II1 * OoOoOO00
 iII1II = red ( rloc . print_address_no_iid ( ) , False )
 if ( nat_info ) :
  IIiiIiiI1Ii1i = " {}" . format ( blue ( nat_info . hostname , False ) )
  o0ooOOoO0O = bold ( "RLOC-probe request" , False )
 else :
  IIiiIiiI1Ii1i = ""
  o0ooOOoO0O = bold ( "RLOC-probe reply" , False )
  if 15 - 15: Oo0Ooo
  if 100 - 100: IiII + I1ii11iIi11i + iII111i . i1IIi . I1ii11iIi11i / OoooooooOO
 lprint ( ( "Data encapsulate {} to {}{} port {} for " + "NAT-traversal" ) . format ( o0ooOOoO0O , iII1II , IIiiIiiI1Ii1i , packet . encap_port ) )
 if 84 - 84: o0oOOo0O0Ooo * I11i
 if 22 - 22: i1IIi + OOooOOo % OoooooooOO
 if 34 - 34: oO0o / O0 - II111iiii % Oo0Ooo + I11i
 if 23 - 23: o0oOOo0O0Ooo + i11iIiiIii . I1IiiI + iIii1I11I1II1
 if 18 - 18: o0oOOo0O0Ooo . O0 + I1Ii111
 if ( packet . encode ( None ) == None ) : return
 packet . print_packet ( "Send" , True )
 if 66 - 66: OoooooooOO
 o0O0OoOoO = lisp_sockets [ 3 ]
 packet . send_packet ( o0O0OoOoO , packet . outer_dest )
 del ( packet )
 return
 if 80 - 80: OOooOOo * IiII * Ii1I + i11iIiiIii
 if 68 - 68: I1IiiI - Oo0Ooo - o0oOOo0O0Ooo + O0 % oO0o % OoOoOO00
 if 97 - 97: i11iIiiIii * I1ii11iIi11i
 if 12 - 12: ooOoO0o + OOooOOo . i1IIi % i11iIiiIii
 if 61 - 61: o0oOOo0O0Ooo - Ii1I % o0oOOo0O0Ooo
 if 59 - 59: OoooooooOO . iIii1I11I1II1 * OoooooooOO + ooOoO0o
 if 56 - 56: OoOoOO00 . iII111i / OOooOOo
 if 39 - 39: iIii1I11I1II1 % ooOoO0o
def lisp_get_default_route_next_hops ( ) :
 if 75 - 75: i1IIi * II111iiii * O0 * i11iIiiIii % iII111i / iII111i
 if 36 - 36: IiII / I1IiiI % iII111i / iII111i
 if 38 - 38: OOooOOo * I1ii11iIi11i * I1Ii111 + I11i
 if 65 - 65: O0 + O0 * I1Ii111
 if ( lisp_is_macos ( ) ) :
  Ii1I1i111 = "route -n get default"
  O0Oo = commands . getoutput ( Ii1I1i111 ) . split ( "\n" )
  iiIIiii111i = iiiii11I1 = None
  for iI1i1i1i1i in O0Oo :
   if ( iI1i1i1i1i . find ( "gateway: " ) != - 1 ) : iiIIiii111i = iI1i1i1i1i . split ( ": " ) [ 1 ]
   if ( iI1i1i1i1i . find ( "interface: " ) != - 1 ) : iiiii11I1 = iI1i1i1i1i . split ( ": " ) [ 1 ]
   if 97 - 97: I1Ii111 / iIii1I11I1II1 * OOooOOo + i11iIiiIii
  return ( [ [ iiiii11I1 , iiIIiii111i ] ] )
  if 86 - 86: OoO0O00 - I1Ii111 * OoO0O00
  if 29 - 29: I1Ii111 % OoOoOO00 . oO0o / oO0o % I11i
  if 91 - 91: o0oOOo0O0Ooo
  if 59 - 59: I11i . I11i
  if 98 - 98: II111iiii
 Ii1I1i111 = "ip route | egrep 'default via'"
 O00OooooOo = commands . getoutput ( Ii1I1i111 ) . split ( "\n" )
 if 20 - 20: iIii1I11I1II1
 O00ooOo0oO00o = [ ]
 for IIi1iiiIIiI in O00OooooOo :
  if ( IIi1iiiIIiI . find ( " metric " ) != - 1 ) : continue
  o0O = IIi1iiiIIiI . split ( " " )
  try :
   II111i = o0O . index ( "via" ) + 1
   if ( II111i >= len ( o0O ) ) : continue
   iiiIII = o0O . index ( "dev" ) + 1
   if ( iiiIII >= len ( o0O ) ) : continue
  except :
   continue
   if 24 - 24: II111iiii
   if 15 - 15: o0oOOo0O0Ooo . I11i
  O00ooOo0oO00o . append ( [ o0O [ iiiIII ] , o0O [ II111i ] ] )
  if 100 - 100: I1IiiI
 return ( O00ooOo0oO00o )
 if 58 - 58: iII111i % IiII
 if 90 - 90: ooOoO0o + II111iiii + I1IiiI / OoooooooOO . o0oOOo0O0Ooo
 if 3 - 3: i11iIiiIii . I1ii11iIi11i
 if 65 - 65: II111iiii * iII111i - OoO0O00 + oO0o % OoO0O00
 if 83 - 83: OoooooooOO % I1ii11iIi11i . IiII + OOooOOo . iII111i - ooOoO0o
 if 100 - 100: o0oOOo0O0Ooo
 if 95 - 95: iII111i * oO0o * i1IIi
def lisp_get_host_route_next_hop ( rloc ) :
 Ii1I1i111 = "ip route | egrep '{} via'" . format ( rloc )
 IIi1iiiIIiI = commands . getoutput ( Ii1I1i111 ) . split ( " " )
 if 100 - 100: iII111i . o0oOOo0O0Ooo - I1Ii111 % oO0o
 try : oooO0 = IIi1iiiIIiI . index ( "via" ) + 1
 except : return ( None )
 if 11 - 11: o0oOOo0O0Ooo . OoooooooOO - i1IIi
 if ( oooO0 >= len ( IIi1iiiIIiI ) ) : return ( None )
 return ( IIi1iiiIIiI [ oooO0 ] )
 if 71 - 71: I1IiiI . OOooOOo . I1ii11iIi11i
 if 90 - 90: i11iIiiIii + I1Ii111 % II111iiii
 if 67 - 67: OoOoOO00 / iII111i * OoO0O00 % i11iIiiIii
 if 76 - 76: OoO0O00
 if 92 - 92: iIii1I11I1II1 * O0 % I11i
 if 92 - 92: OoOoOO00 + oO0o
 if 89 - 89: IiII % iII111i / iIii1I11I1II1 . Ii1I . Oo0Ooo + ooOoO0o
def lisp_install_host_route ( dest , nh , install ) :
 install = "add" if install else "delete"
 oo0OOooo0o000 = "none" if nh == None else nh
 if 28 - 28: I1IiiI . iIii1I11I1II1
 lprint ( "{} host-route {}, nh {}" . format ( install . title ( ) , dest , oo0OOooo0o000 ) )
 if 12 - 12: I1Ii111 * OOooOOo
 if ( nh == None ) :
  oOOO = "ip route {} {}/32" . format ( install , dest )
 else :
  oOOO = "ip route {} {}/32 via {}" . format ( install , dest , nh )
  if 11 - 11: II111iiii % O0 % O0 % o0oOOo0O0Ooo
 os . system ( oOOO )
 return
 if 45 - 45: OoooooooOO * oO0o
 if 74 - 74: ooOoO0o * I11i / oO0o - IiII + OoOoOO00
 if 16 - 16: Oo0Ooo
 if 29 - 29: Oo0Ooo . I1ii11iIi11i / II111iiii / oO0o / o0oOOo0O0Ooo + I11i
 if 4 - 4: OoooooooOO % I1ii11iIi11i . OoO0O00 * o0oOOo0O0Ooo + I1ii11iIi11i * IiII
 if 67 - 67: I1IiiI
 if 93 - 93: ooOoO0o . Ii1I + IiII / Oo0Ooo % I11i
 if 40 - 40: Oo0Ooo % OoOoOO00 . IiII / I1IiiI % OoooooooOO
def lisp_checkpoint ( checkpoint_list ) :
 if ( lisp_checkpoint_map_cache == False ) : return
 if 33 - 33: OOooOOo - OoooooooOO . iII111i
 iI1i1i1i1i = open ( lisp_checkpoint_filename , "w" )
 for oo in checkpoint_list :
  iI1i1i1i1i . write ( oo + "\n" )
  if 2 - 2: I11i + i1IIi
 iI1i1i1i1i . close ( )
 lprint ( "{} {} entries to file '{}'" . format ( bold ( "Checkpoint" , False ) ,
 len ( checkpoint_list ) , lisp_checkpoint_filename ) )
 return
 if 52 - 52: I11i - OoO0O00 % I1Ii111 . OOooOOo
 if 90 - 90: O0 - Oo0Ooo / i1IIi * iIii1I11I1II1 % o0oOOo0O0Ooo / oO0o
 if 73 - 73: iII111i % iIii1I11I1II1 + o0oOOo0O0Ooo % Ii1I . II111iiii + IiII
 if 55 - 55: OoOoOO00 * II111iiii / iII111i + OOooOOo / OoooooooOO
 if 12 - 12: II111iiii * O0 - Oo0Ooo + o0oOOo0O0Ooo . Oo0Ooo + iIii1I11I1II1
 if 4 - 4: I1Ii111 - I1Ii111 / I1ii11iIi11i . i1IIi + I1ii11iIi11i / oO0o
 if 18 - 18: iIii1I11I1II1 . ooOoO0o
 if 68 - 68: o0oOOo0O0Ooo
def lisp_load_checkpoint ( ) :
 if ( lisp_checkpoint_map_cache == False ) : return
 if ( os . path . exists ( lisp_checkpoint_filename ) == False ) : return
 if 36 - 36: Oo0Ooo . I11i + I1IiiI * i1IIi % Ii1I + OOooOOo
 iI1i1i1i1i = open ( lisp_checkpoint_filename , "r" )
 if 5 - 5: o0oOOo0O0Ooo % oO0o / OoO0O00
 i111I11I = 0
 for oo in iI1i1i1i1i :
  i111I11I += 1
  O0O0o0o0o = oo . split ( " rloc " )
  iIiIii1I1 = [ ] if ( O0O0o0o0o [ 1 ] in [ "native-forward\n" , "\n" ] ) else O0O0o0o0o [ 1 ] . split ( ", " )
  if 17 - 17: OoooooooOO - I1ii11iIi11i / OoO0O00 - I1Ii111 + i1IIi
  if 6 - 6: Oo0Ooo - II111iiii
  I111i = [ ]
  for Oo0O0 in iIiIii1I1 :
   OOO0OOO000oOO0 = lisp_rloc ( False )
   o0O = Oo0O0 . split ( " " )
   OOO0OOO000oOO0 . rloc . store_address ( o0O [ 0 ] )
   OOO0OOO000oOO0 . priority = int ( o0O [ 1 ] )
   OOO0OOO000oOO0 . weight = int ( o0O [ 2 ] )
   I111i . append ( OOO0OOO000oOO0 )
   if 33 - 33: I1Ii111 - I1IiiI + iII111i . OoOoOO00
   if 91 - 91: OOooOOo / Ii1I / IiII * OOooOOo
  oOooO0Oo0Oo0 = lisp_mapping ( "" , "" , I111i )
  if ( oOooO0Oo0Oo0 != None ) :
   oOooO0Oo0Oo0 . eid . store_prefix ( O0O0o0o0o [ 0 ] )
   oOooO0Oo0Oo0 . checkpoint_entry = True
   oOooO0Oo0Oo0 . map_cache_ttl = LISP_NMR_TTL * 60
   if ( I111i == [ ] ) : oOooO0Oo0Oo0 . action = LISP_NATIVE_FORWARD_ACTION
   oOooO0Oo0Oo0 . add_cache ( )
   continue
   if 68 - 68: I11i
   if 91 - 91: I11i
  i111I11I -= 1
  if 24 - 24: ooOoO0o . i1IIi - O0 + I11i
  if 71 - 71: OoOoOO00
 iI1i1i1i1i . close ( )
 lprint ( "{} {} map-cache entries from file '{}'" . format (
 bold ( "Loaded" , False ) , i111I11I , lisp_checkpoint_filename ) )
 return
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
def lisp_write_checkpoint_entry ( checkpoint_list , mc ) :
 if ( lisp_checkpoint_map_cache == False ) : return
 if 23 - 23: OoOoOO00 * I1Ii111
 oo = "{} rloc " . format ( mc . eid . print_prefix ( ) )
 if 18 - 18: o0oOOo0O0Ooo % i11iIiiIii . Ii1I . O0
 for OOO0OOO000oOO0 in mc . rloc_set :
  if ( OOO0OOO000oOO0 . rloc . is_null ( ) ) : continue
  oo += "{} {} {}, " . format ( OOO0OOO000oOO0 . rloc . print_address_no_iid ( ) ,
 OOO0OOO000oOO0 . priority , OOO0OOO000oOO0 . weight )
  if 85 - 85: I1ii11iIi11i * iIii1I11I1II1 + o0oOOo0O0Ooo * OoO0O00
  if 25 - 25: o0oOOo0O0Ooo / Ii1I / Oo0Ooo . ooOoO0o - ooOoO0o * O0
 if ( mc . rloc_set != [ ] ) :
  oo = oo [ 0 : - 2 ]
 elif ( mc . action == LISP_NATIVE_FORWARD_ACTION ) :
  oo += "native-forward"
  if 14 - 14: O0 - Ii1I + iIii1I11I1II1 + II111iiii . ooOoO0o + Ii1I
  if 25 - 25: OoO0O00 * oO0o
 checkpoint_list . append ( oo )
 return
 if 29 - 29: OOooOOo - I1Ii111 - i11iIiiIii % i1IIi
 if 2 - 2: i11iIiiIii % iIii1I11I1II1 * OOooOOo
 if 45 - 45: oO0o + i1IIi + iII111i + o0oOOo0O0Ooo * OOooOOo + ooOoO0o
 if 83 - 83: OoO0O00 - ooOoO0o / OoooooooOO % iIii1I11I1II1 - II111iiii
 if 73 - 73: Oo0Ooo + II111iiii - IiII
 if 60 - 60: i1IIi . i11iIiiIii / i1IIi . I11i % OOooOOo
 if 47 - 47: oO0o + IiII * I1Ii111 % o0oOOo0O0Ooo - O0 % IiII
def lisp_check_dp_socket ( ) :
 Oooo0O0ooOooO = lisp_ipc_dp_socket_name
 if ( os . path . exists ( Oooo0O0ooOooO ) == False ) :
  I1iI11iII11 = bold ( "does not exist" , False )
  lprint ( "Socket '{}' {}" . format ( Oooo0O0ooOooO , I1iI11iII11 ) )
  return ( False )
  if 56 - 56: Ii1I + i1IIi / II111iiii
 return ( True )
 if 54 - 54: O0 * IiII + i11iIiiIii - oO0o - ooOoO0o + i11iIiiIii
 if 87 - 87: I1ii11iIi11i * iIii1I11I1II1 / I1Ii111
 if 5 - 5: i1IIi * IiII / iIii1I11I1II1 * OoooooooOO . O0
 if 57 - 57: i11iIiiIii
 if 89 - 89: o0oOOo0O0Ooo . I1Ii111 * I11i + oO0o - OoooooooOO + OoO0O00
 if 25 - 25: i1IIi * I1Ii111 * iII111i . OoooooooOO
 if 70 - 70: iIii1I11I1II1
def lisp_write_to_dp_socket ( entry ) :
 try :
  iiIII = json . dumps ( entry )
  O0o0OO0O = bold ( "Write IPC" , False )
  lprint ( "{} record to named socket: '{}'" . format ( O0o0OO0O , iiIII ) )
  lisp_ipc_dp_socket . sendto ( iiIII , lisp_ipc_dp_socket_name )
 except :
  lprint ( "Failed to write IPC record to named socket: '{}'" . format ( iiIII ) )
  if 87 - 87: I11i + I1ii11iIi11i
 return
 if 83 - 83: i11iIiiIii * OoooooooOO * I1Ii111 * Ii1I % I11i
 if 100 - 100: I1ii11iIi11i
 if 83 - 83: I11i . I1ii11iIi11i / I1Ii111 / II111iiii
 if 23 - 23: OoooooooOO . o0oOOo0O0Ooo
 if 76 - 76: I1Ii111
 if 91 - 91: iIii1I11I1II1 / Ii1I . I1IiiI
 if 63 - 63: ooOoO0o . Ii1I - I1Ii111 - oO0o * I1Ii111 + ooOoO0o
 if 85 - 85: II111iiii + I1ii11iIi11i
 if 33 - 33: iII111i
def lisp_write_ipc_keys ( rloc ) :
 oooOO0oOooO00 = rloc . rloc . print_address_no_iid ( )
 i1I1IIIi11I = rloc . translated_port
 if ( i1I1IIIi11I != 0 ) : oooOO0oOooO00 += ":" + str ( i1I1IIIi11I )
 if ( lisp_rloc_probe_list . has_key ( oooOO0oOooO00 ) == False ) : return
 if 14 - 14: O0 * Oo0Ooo / i1IIi
 for o0O , O0O0o0o0o , Ii1i111iI in lisp_rloc_probe_list [ oooOO0oOooO00 ] :
  oOooO0Oo0Oo0 = lisp_map_cache . lookup_cache ( O0O0o0o0o , True )
  if ( oOooO0Oo0Oo0 == None ) : continue
  lisp_write_ipc_map_cache ( True , oOooO0Oo0Oo0 )
  if 95 - 95: O0 % i1IIi % ooOoO0o % oO0o - I1IiiI
 return
 if 78 - 78: II111iiii % OOooOOo
 if 6 - 6: OOooOOo
 if 21 - 21: I1Ii111 - Ii1I - i1IIi % oO0o
 if 55 - 55: OOooOOo + oO0o - II111iiii
 if 5 - 5: iII111i * OoooooooOO . OoO0O00 % ooOoO0o + Ii1I
 if 59 - 59: OoOoOO00
 if 96 - 96: I1IiiI
def lisp_write_ipc_map_cache ( add_or_delete , mc , dont_send = False ) :
 if ( lisp_i_am_etr ) : return
 if ( lisp_ipc_dp_socket == None ) : return
 if ( lisp_check_dp_socket ( ) == False ) : return
 if 3 - 3: OoooooooOO
 if 3 - 3: IiII / O0 * i11iIiiIii . iII111i - iIii1I11I1II1
 if 56 - 56: ooOoO0o
 if 82 - 82: ooOoO0o . IiII . I1Ii111 - iIii1I11I1II1 + II111iiii . OoOoOO00
 o0000oi1I1Ii = "add" if add_or_delete else "delete"
 oo = { "type" : "map-cache" , "opcode" : o0000oi1I1Ii }
 if 48 - 48: I1IiiI / OoooooooOO * IiII % Oo0Ooo
 iIIiI1iiIi = ( mc . group . is_null ( ) == False )
 if ( iIIiI1iiIi ) :
  oo [ "eid-prefix" ] = mc . group . print_prefix_no_iid ( )
  oo [ "rles" ] = [ ]
 else :
  oo [ "eid-prefix" ] = mc . eid . print_prefix_no_iid ( )
  oo [ "rlocs" ] = [ ]
  if 67 - 67: i1IIi % Oo0Ooo . OoOoOO00 - Ii1I / OoooooooOO + iII111i
 oo [ "instance-id" ] = str ( mc . eid . instance_id )
 if 100 - 100: O0 + I1ii11iIi11i + OoooooooOO - iII111i * iIii1I11I1II1 . II111iiii
 if ( iIIiI1iiIi ) :
  if ( len ( mc . rloc_set ) >= 1 and mc . rloc_set [ 0 ] . rle ) :
   for iIiiI11iI111 in mc . rloc_set [ 0 ] . rle . rle_forwarding_list :
    o00Ooo0 = iIiiI11iI111 . address . print_address_no_iid ( )
    i1I1IIIi11I = str ( 4341 ) if iIiiI11iI111 . translated_port == 0 else str ( iIiiI11iI111 . translated_port )
    if 79 - 79: i11iIiiIii
    o0O = { "rle" : o00Ooo0 , "port" : i1I1IIIi11I }
    o0O0O0O00 , I11Ii1ii1 = iIiiI11iI111 . get_encap_keys ( )
    o0O = lisp_build_json_keys ( o0O , o0O0O0O00 , I11Ii1ii1 , "encrypt-key" )
    oo [ "rles" ] . append ( o0O )
    if 91 - 91: i11iIiiIii * i11iIiiIii % OoooooooOO / i1IIi
    if 35 - 35: ooOoO0o + Ii1I
 else :
  for Oo0O0 in mc . rloc_set :
   if ( Oo0O0 . rloc . is_ipv4 ( ) == False and Oo0O0 . rloc . is_ipv6 ( ) == False ) :
    continue
    if 98 - 98: i1IIi
   if ( Oo0O0 . up_state ( ) == False ) : continue
   if 83 - 83: oO0o % O0 . I11i / I11i / I1IiiI - OoOoOO00
   i1I1IIIi11I = str ( 4341 ) if Oo0O0 . translated_port == 0 else str ( Oo0O0 . translated_port )
   if 91 - 91: iIii1I11I1II1 - IiII + iIii1I11I1II1 % Oo0Ooo % I1IiiI
   o0O = { "rloc" : Oo0O0 . rloc . print_address_no_iid ( ) , "priority" :
 str ( Oo0O0 . priority ) , "weight" : str ( Oo0O0 . weight ) , "port" :
 i1I1IIIi11I }
   o0O0O0O00 , I11Ii1ii1 = Oo0O0 . get_encap_keys ( )
   o0O = lisp_build_json_keys ( o0O , o0O0O0O00 , I11Ii1ii1 , "encrypt-key" )
   oo [ "rlocs" ] . append ( o0O )
   if 84 - 84: iIii1I11I1II1 . Oo0Ooo - OoooooooOO % Oo0Ooo
   if 27 - 27: I1ii11iIi11i - ooOoO0o + I11i - I1ii11iIi11i
   if 57 - 57: Oo0Ooo
 if ( dont_send == False ) : lisp_write_to_dp_socket ( oo )
 return ( oo )
 if 31 - 31: I1IiiI % Ii1I / OOooOOo + OoooooooOO . i11iIiiIii
 if 87 - 87: iII111i + IiII * I1ii11iIi11i . iII111i + Ii1I - II111iiii
 if 87 - 87: OoOoOO00 . o0oOOo0O0Ooo + I1ii11iIi11i
 if 53 - 53: o0oOOo0O0Ooo * II111iiii + i1IIi
 if 83 - 83: I11i * o0oOOo0O0Ooo * Ii1I + OoooooooOO
 if 76 - 76: I1ii11iIi11i . OoooooooOO + ooOoO0o / I1IiiI
 if 56 - 56: Ii1I % I11i / O0 % O0 % iIii1I11I1II1 + I1IiiI
def lisp_write_ipc_decap_key ( rloc_addr , keys ) :
 if ( lisp_i_am_itr ) : return
 if ( lisp_ipc_dp_socket == None ) : return
 if ( lisp_check_dp_socket ( ) == False ) : return
 if 51 - 51: O0 * Ii1I / oO0o * OoooooooOO
 if 93 - 93: I1ii11iIi11i . OOooOOo + i1IIi
 if 30 - 30: Oo0Ooo + I1Ii111 / OOooOOo
 if 74 - 74: iIii1I11I1II1
 if ( keys == None or len ( keys ) == 0 or keys [ 1 ] == None ) : return
 if 69 - 69: ooOoO0o % iIii1I11I1II1 * o0oOOo0O0Ooo + OoOoOO00 % I1Ii111 % Oo0Ooo
 o0O0O0O00 = keys [ 1 ] . encrypt_key
 I11Ii1ii1 = keys [ 1 ] . icv_key
 if 64 - 64: iIii1I11I1II1 * Ii1I * ooOoO0o * i11iIiiIii
 if 54 - 54: IiII . Ii1I
 if 54 - 54: iII111i
 if 2 - 2: OoOoOO00 + I1IiiI . ooOoO0o - oO0o . iIii1I11I1II1
 ooo00ooOOO0 = rloc_addr . split ( ":" )
 if ( len ( ooo00ooOOO0 ) == 1 ) :
  oo = { "type" : "decap-keys" , "rloc" : ooo00ooOOO0 [ 0 ] }
 else :
  oo = { "type" : "decap-keys" , "rloc" : ooo00ooOOO0 [ 0 ] , "port" : ooo00ooOOO0 [ 1 ] }
  if 44 - 44: I11i
 oo = lisp_build_json_keys ( oo , o0O0O0O00 , I11Ii1ii1 , "decrypt-key" )
 if 48 - 48: Oo0Ooo . IiII / ooOoO0o + I11i
 lisp_write_to_dp_socket ( oo )
 return
 if 40 - 40: I1IiiI + I1ii11iIi11i * I1IiiI % Ii1I
 if 27 - 27: O0 / Oo0Ooo . oO0o
 if 34 - 34: I1Ii111 % Ii1I / Oo0Ooo % ooOoO0o / i11iIiiIii * I1IiiI
 if 36 - 36: i11iIiiIii * i1IIi % iII111i . Oo0Ooo
 if 54 - 54: o0oOOo0O0Ooo % i1IIi % I1ii11iIi11i . o0oOOo0O0Ooo / OoOoOO00
 if 55 - 55: O0 / OoooooooOO % Ii1I * O0 + iIii1I11I1II1 . iIii1I11I1II1
 if 55 - 55: Ii1I . OoooooooOO % Ii1I . IiII
 if 67 - 67: oO0o
def lisp_build_json_keys ( entry , ekey , ikey , key_type ) :
 if ( ekey == None ) : return ( entry )
 if 12 - 12: I1IiiI + OoooooooOO
 entry [ "keys" ] = [ ]
 o0000oO = { "key-id" : "1" , key_type : ekey , "icv-key" : ikey }
 entry [ "keys" ] . append ( o0000oO )
 return ( entry )
 if 25 - 25: iIii1I11I1II1 - I1IiiI . i11iIiiIii + ooOoO0o
 if 19 - 19: OoooooooOO / IiII
 if 40 - 40: OoOoOO00 / OoooooooOO * iIii1I11I1II1 / i1IIi . OoooooooOO
 if 88 - 88: I1IiiI % I1IiiI / II111iiii - IiII
 if 72 - 72: OoO0O00 - I1ii11iIi11i . Oo0Ooo / OoO0O00
 if 86 - 86: i11iIiiIii - oO0o . i11iIiiIii
 if 51 - 51: OoO0O00 - OoO0O00 * IiII
def lisp_write_ipc_database_mappings ( ephem_port ) :
 if ( lisp_i_am_etr == False ) : return
 if ( lisp_ipc_dp_socket == None ) : return
 if ( lisp_check_dp_socket ( ) == False ) : return
 if 24 - 24: OoooooooOO . II111iiii
 if 97 - 97: II111iiii . O0
 if 18 - 18: iII111i
 if 35 - 35: ooOoO0o / O0 / iIii1I11I1II1 - iIii1I11I1II1 + I11i
 oo = { "type" : "database-mappings" , "database-mappings" : [ ] }
 if 8 - 8: I1Ii111 . oO0o % Oo0Ooo * OoooooooOO
 if 25 - 25: OoO0O00
 if 54 - 54: O0
 if 20 - 20: ooOoO0o + Oo0Ooo - Oo0Ooo
 for iIiIi in lisp_db_list :
  if ( iIiIi . eid . is_ipv4 ( ) == False and iIiIi . eid . is_ipv6 ( ) == False ) : continue
  Iii1iIi1i = { "instance-id" : str ( iIiIi . eid . instance_id ) ,
 "eid-prefix" : iIiIi . eid . print_prefix_no_iid ( ) }
  oo [ "database-mappings" ] . append ( Iii1iIi1i )
  if 60 - 60: OOooOOo * iII111i . ooOoO0o + O0 + o0oOOo0O0Ooo . o0oOOo0O0Ooo
 lisp_write_to_dp_socket ( oo )
 if 62 - 62: O0 * OoO0O00 / Oo0Ooo - oO0o * OoO0O00 * oO0o
 if 31 - 31: Oo0Ooo
 if 90 - 90: I11i . IiII * iIii1I11I1II1 . I11i + i1IIi
 if 67 - 67: I1Ii111 . I1ii11iIi11i
 if 2 - 2: O0 + I1Ii111
 oo = { "type" : "etr-nat-port" , "port" : ephem_port }
 lisp_write_to_dp_socket ( oo )
 return
 if 82 - 82: Ii1I / iII111i
 if 13 - 13: I11i + iII111i
 if 54 - 54: I1ii11iIi11i - I1IiiI . Ii1I
 if 59 - 59: Oo0Ooo + I1ii11iIi11i
 if 87 - 87: ooOoO0o * OoooooooOO + OoO0O00 + oO0o - I1Ii111
 if 70 - 70: i1IIi . Ii1I / Ii1I
 if 9 - 9: iII111i + I1Ii111 + iII111i % ooOoO0o + i11iIiiIii + i11iIiiIii
def lisp_write_ipc_interfaces ( ) :
 if ( lisp_i_am_etr ) : return
 if ( lisp_ipc_dp_socket == None ) : return
 if ( lisp_check_dp_socket ( ) == False ) : return
 if 45 - 45: i1IIi + I1ii11iIi11i
 if 49 - 49: i11iIiiIii . I1ii11iIi11i
 if 91 - 91: ooOoO0o - OOooOOo - OOooOOo * o0oOOo0O0Ooo
 if 33 - 33: II111iiii
 oo = { "type" : "interfaces" , "interfaces" : [ ] }
 if 39 - 39: ooOoO0o + I11i
 for iiiii11I1 in lisp_myinterfaces . values ( ) :
  if ( iiiii11I1 . instance_id == None ) : continue
  Iii1iIi1i = { "interface" : iiiii11I1 . device ,
 "instance-id" : str ( iiiii11I1 . instance_id ) }
  oo [ "interfaces" ] . append ( Iii1iIi1i )
  if 24 - 24: o0oOOo0O0Ooo
  if 5 - 5: i11iIiiIii - oO0o + o0oOOo0O0Ooo % ooOoO0o
 lisp_write_to_dp_socket ( oo )
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
 if 73 - 73: OoO0O00 % iIii1I11I1II1 + IiII * I1Ii111 % II111iiii
 if 20 - 20: I11i % I1ii11iIi11i . OoO0O00 % OoOoOO00
 if 84 - 84: OoooooooOO / i11iIiiIii . IiII / I1IiiI
 if 62 - 62: iII111i - I1IiiI + OoooooooOO
 if 59 - 59: iIii1I11I1II1 + i11iIiiIii * oO0o . Oo0Ooo . I1Ii111
def lisp_parse_auth_key ( value ) :
 OOoo = value . split ( "[" )
 i1iiIOoOO0OOo0 = { }
 if ( len ( OOoo ) == 1 ) :
  i1iiIOoOO0OOo0 [ 0 ] = value
  return ( i1iiIOoOO0OOo0 )
  if 28 - 28: I1Ii111 . o0oOOo0O0Ooo . I1ii11iIi11i % OoO0O00 / IiII
  if 77 - 77: i1IIi % ooOoO0o % II111iiii + OoO0O00 - I11i + i11iIiiIii
 for O0oO00OO0oO0 in OOoo :
  if ( O0oO00OO0oO0 == "" ) : continue
  oooO0 = O0oO00OO0oO0 . find ( "]" )
  iIIi1OoOo0O00 = O0oO00OO0oO0 [ 0 : oooO0 ]
  try : iIIi1OoOo0O00 = int ( iIIi1OoOo0O00 )
  except : return
  if 17 - 17: Ii1I - OoOoOO00 * I1ii11iIi11i / I1IiiI * Oo0Ooo
  i1iiIOoOO0OOo0 [ iIIi1OoOo0O00 ] = O0oO00OO0oO0 [ oooO0 + 1 : : ]
  if 28 - 28: I1ii11iIi11i . OoOoOO00 % OoOoOO00
 return ( i1iiIOoOO0OOo0 )
 if 61 - 61: Ii1I % I1ii11iIi11i . I1ii11iIi11i / Oo0Ooo - I1Ii111 * OoOoOO00
 if 47 - 47: IiII
 if 76 - 76: iII111i / II111iiii / I11i
 if 62 - 62: I1ii11iIi11i
 if 100 - 100: iII111i / ooOoO0o / IiII % II111iiii
 if 6 - 6: OoooooooOO - I1IiiI + OoooooooOO
 if 89 - 89: oO0o % Oo0Ooo . O0 . ooOoO0o
 if 46 - 46: IiII * I11i - OoO0O00 - Ii1I
 if 93 - 93: iIii1I11I1II1 / o0oOOo0O0Ooo - I11i - OOooOOo % ooOoO0o
 if 16 - 16: ooOoO0o * o0oOOo0O0Ooo - IiII + I1ii11iIi11i / o0oOOo0O0Ooo - O0
 if 71 - 71: i1IIi
 if 79 - 79: iII111i * O0 / Ii1I / O0 % i1IIi
 if 52 - 52: OoooooooOO % oO0o - I11i % OoOoOO00 . II111iiii
 if 62 - 62: Ii1I . I1ii11iIi11i . iII111i + I11i * o0oOOo0O0Ooo
 if 56 - 56: oO0o * iIii1I11I1II1 . II111iiii - II111iiii + II111iiii - i11iIiiIii
 if 79 - 79: iII111i
def lisp_reassemble ( packet ) :
 i1111iIII = socket . ntohs ( struct . unpack ( "H" , packet [ 6 : 8 ] ) [ 0 ] )
 if 29 - 29: Ii1I * I1Ii111 / OoO0O00 - O0 - i11iIiiIii * I1IiiI
 if 2 - 2: OoOoOO00 . I1ii11iIi11i * I1ii11iIi11i
 if 42 - 42: OoO0O00 . OoO0O00 + II111iiii - IiII - OOooOOo * Oo0Ooo
 if 47 - 47: oO0o - OoooooooOO + iII111i
 if ( i1111iIII == 0 or i1111iIII == 0x4000 ) : return ( packet )
 if 69 - 69: I1ii11iIi11i - I1IiiI % oO0o + OOooOOo - I1Ii111
 if 5 - 5: ooOoO0o . OoO0O00
 if 40 - 40: iII111i
 if 87 - 87: IiII / II111iiii
 i11i = socket . ntohs ( struct . unpack ( "H" , packet [ 4 : 6 ] ) [ 0 ] )
 IIOooOO00o0o00O = socket . ntohs ( struct . unpack ( "H" , packet [ 2 : 4 ] ) [ 0 ] )
 if 93 - 93: Oo0Ooo - i11iIiiIii . iII111i . iII111i / i1IIi . II111iiii
 iiIi11 = ( i1111iIII & 0x2000 == 0 and ( i1111iIII & 0x1fff ) != 0 )
 oo = [ ( i1111iIII & 0x1fff ) * 8 , IIOooOO00o0o00O - 20 , packet , iiIi11 ]
 if 65 - 65: Ii1I + IiII + I11i / I1Ii111 % iIii1I11I1II1
 if 17 - 17: I1ii11iIi11i * OOooOOo % II111iiii
 if 30 - 30: I1Ii111 . Ii1I . Oo0Ooo / OOooOOo * OoooooooOO / I1ii11iIi11i
 if 41 - 41: i1IIi
 if 75 - 75: o0oOOo0O0Ooo . I1Ii111 - I1Ii111 % Ii1I * OoooooooOO
 if 99 - 99: OOooOOo + o0oOOo0O0Ooo - OOooOOo . i1IIi
 if 86 - 86: Ii1I % oO0o - i11iIiiIii - O0 + IiII + iII111i
 if 100 - 100: OoO0O00 . Oo0Ooo
 if ( i1111iIII == 0x2000 ) :
  ooO0 , o0 = struct . unpack ( "HH" , packet [ 20 : 24 ] )
  ooO0 = socket . ntohs ( ooO0 )
  o0 = socket . ntohs ( o0 )
  if ( o0 not in [ 4341 , 8472 , 4789 ] and ooO0 != 4341 ) :
   lisp_reassembly_queue [ i11i ] = [ ]
   oo [ 2 ] = None
   if 29 - 29: OoO0O00
   if 34 - 34: O0 - o0oOOo0O0Ooo % OOooOOo . OoO0O00 % IiII
   if 63 - 63: O0 % iIii1I11I1II1 . o0oOOo0O0Ooo . I1IiiI * Ii1I % i1IIi
   if 47 - 47: II111iiii * I1ii11iIi11i
   if 70 - 70: I1ii11iIi11i - o0oOOo0O0Ooo
   if 71 - 71: I1ii11iIi11i * i1IIi
 if ( lisp_reassembly_queue . has_key ( i11i ) == False ) :
  lisp_reassembly_queue [ i11i ] = [ ]
  if 67 - 67: I1ii11iIi11i % OoOoOO00 . iII111i / Ii1I . I1IiiI
  if 48 - 48: IiII + II111iiii . I1IiiI % o0oOOo0O0Ooo
  if 57 - 57: OOooOOo . I11i % OoOoOO00
  if 68 - 68: iIii1I11I1II1 % I1ii11iIi11i % II111iiii / O0 + iII111i
  if 78 - 78: iII111i - OOooOOo / I1Ii111
 I1IiIIIIii1 = lisp_reassembly_queue [ i11i ]
 if 99 - 99: o0oOOo0O0Ooo . oO0o
 if 9 - 9: oO0o % OoooooooOO
 if 62 - 62: OoO0O00 / OoOoOO00 / I1Ii111 + Oo0Ooo - Ii1I
 if 72 - 72: OoO0O00 + I11i / iII111i % OOooOOo
 if 5 - 5: oO0o % OOooOOo
 if ( len ( I1IiIIIIii1 ) == 1 and I1IiIIIIii1 [ 0 ] [ 2 ] == None ) :
  dprint ( "Drop non-LISP encapsulated fragment 0x{}" . format ( lisp_hex_string ( i11i ) . zfill ( 4 ) ) )
  if 95 - 95: OoOoOO00 + OoooooooOO - O0 + o0oOOo0O0Ooo
  return ( None )
  if 88 - 88: i11iIiiIii . iIii1I11I1II1
  if 57 - 57: Ii1I * iIii1I11I1II1
  if 92 - 92: Ii1I % Ii1I . I11i / i1IIi % Oo0Ooo
  if 25 - 25: o0oOOo0O0Ooo - OoO0O00 - OoOoOO00 - ooOoO0o
  if 28 - 28: OOooOOo * ooOoO0o * OoooooooOO % IiII
 I1IiIIIIii1 . append ( oo )
 I1IiIIIIii1 = sorted ( I1IiIIIIii1 )
 if 9 - 9: OoooooooOO
 if 92 - 92: I1Ii111 + O0 + OoO0O00 % IiII
 if 31 - 31: Ii1I / Oo0Ooo - I1IiiI - I11i - i11iIiiIii
 if 45 - 45: ooOoO0o - IiII / OoO0O00 / IiII
 o00Ooo0 = lisp_address ( LISP_AFI_IPV4 , "" , 32 , 0 )
 o00Ooo0 . address = socket . ntohl ( struct . unpack ( "I" , packet [ 12 : 16 ] ) [ 0 ] )
 O0OiiI111iIIii = o00Ooo0 . print_address_no_iid ( )
 o00Ooo0 . address = socket . ntohl ( struct . unpack ( "I" , packet [ 16 : 20 ] ) [ 0 ] )
 O0O0O00OOO = o00Ooo0 . print_address_no_iid ( )
 o00Ooo0 = red ( "{} -> {}" . format ( O0OiiI111iIIii , O0O0O00OOO ) , False )
 if 33 - 33: I1Ii111
 dprint ( "{}{} fragment, RLOCs: {}, packet 0x{}, frag-offset: 0x{}" . format ( bold ( "Received" , False ) , " non-LISP encapsulated" if oo [ 2 ] == None else "" , o00Ooo0 , lisp_hex_string ( i11i ) . zfill ( 4 ) ,
 # i1IIi . I11i - OoO0O00 * Ii1I + OOooOOo + iII111i
 # I1IiiI . i11iIiiIii - ooOoO0o * I11i * OoOoOO00 * I11i
 lisp_hex_string ( i1111iIII ) . zfill ( 4 ) ) )
 if 29 - 29: I1Ii111 * I1Ii111 . iII111i + o0oOOo0O0Ooo
 if 57 - 57: I1Ii111 - IiII
 if 89 - 89: oO0o + iII111i
 if 52 - 52: OOooOOo % O0 * I1ii11iIi11i . I1ii11iIi11i / IiII
 if 7 - 7: II111iiii
 if ( I1IiIIIIii1 [ 0 ] [ 0 ] != 0 or I1IiIIIIii1 [ - 1 ] [ 3 ] == False ) : return ( None )
 Iii11iIiIi11 = I1IiIIIIii1 [ 0 ]
 for iiIII1 in I1IiIIIIii1 [ 1 : : ] :
  i1111iIII = iiIII1 [ 0 ]
  I1I1 , i1iIi1IOO = Iii11iIiIi11 [ 0 ] , Iii11iIiIi11 [ 1 ]
  if ( I1I1 + i1iIi1IOO != i1111iIII ) : return ( None )
  Iii11iIiIi11 = iiIII1
  if 13 - 13: iII111i . iII111i % O0 % o0oOOo0O0Ooo
 lisp_reassembly_queue . pop ( i11i )
 if 99 - 99: OoO0O00 - OoOoOO00 + OoO0O00
 if 67 - 67: I1Ii111
 if 31 - 31: OoO0O00 * Oo0Ooo % O0 * II111iiii + ooOoO0o * I1IiiI
 if 77 - 77: ooOoO0o
 if 98 - 98: I1Ii111 + I1ii11iIi11i % OoO0O00 * Ii1I + iII111i
 packet = I1IiIIIIii1 [ 0 ] [ 2 ]
 for iiIII1 in I1IiIIIIii1 [ 1 : : ] : packet += iiIII1 [ 2 ] [ 20 : : ]
 if 6 - 6: iII111i / iII111i . i11iIiiIii
 dprint ( "{} fragments arrived for packet 0x{}, length {}" . format ( bold ( "All" , False ) , lisp_hex_string ( i11i ) . zfill ( 4 ) , len ( packet ) ) )
 if 12 - 12: I11i - OoO0O00
 if 68 - 68: IiII - OoOoOO00
 if 22 - 22: i1IIi . IiII
 if 8 - 8: IiII % o0oOOo0O0Ooo . i11iIiiIii
 if 69 - 69: I1Ii111 / Ii1I - ooOoO0o
 Oooo = socket . htons ( len ( packet ) )
 I11i1I1i1 = packet [ 0 : 2 ] + struct . pack ( "H" , Oooo ) + packet [ 4 : 6 ] + struct . pack ( "H" , 0 ) + packet [ 8 : 10 ] + struct . pack ( "H" , 0 ) + packet [ 12 : 20 ]
 if 38 - 38: II111iiii % OoooooooOO / OoooooooOO . Ii1I . Ii1I
 if 13 - 13: oO0o - i1IIi / i1IIi + OoooooooOO
 I11i1I1i1 = lisp_ip_checksum ( I11i1I1i1 )
 return ( I11i1I1i1 + packet [ 20 : : ] )
 if 57 - 57: OoooooooOO / O0 + I1ii11iIi11i % I11i * oO0o / Ii1I
 if 49 - 49: I1IiiI * ooOoO0o * OOooOOo + OoO0O00 + ooOoO0o
 if 42 - 42: i1IIi . OoO0O00 % iII111i
 if 57 - 57: I1ii11iIi11i / I1IiiI
 if 69 - 69: iII111i - iII111i . OoO0O00 / oO0o - OoO0O00 + I1Ii111
 if 98 - 98: iII111i . oO0o - O0 % I1IiiI . I1ii11iIi11i / i1IIi
 if 72 - 72: I1IiiI / Oo0Ooo % IiII - O0 / O0 * O0
 if 83 - 83: O0 / I1Ii111 - OoooooooOO
def lisp_get_crypto_decap_lookup_key ( addr , port ) :
 oooOO0oOooO00 = addr . print_address_no_iid ( ) + ":" + str ( port )
 if ( lisp_crypto_keys_by_rloc_decap . has_key ( oooOO0oOooO00 ) ) : return ( oooOO0oOooO00 )
 if 42 - 42: Ii1I / i1IIi - IiII / I1Ii111
 oooOO0oOooO00 = addr . print_address_no_iid ( )
 if ( lisp_crypto_keys_by_rloc_decap . has_key ( oooOO0oOooO00 ) ) : return ( oooOO0oOooO00 )
 if 39 - 39: OoooooooOO
 if 4 - 4: iIii1I11I1II1 - Oo0Ooo / OOooOOo % OoooooooOO . Oo0Ooo - Oo0Ooo
 if 41 - 41: II111iiii . o0oOOo0O0Ooo
 if 92 - 92: Ii1I - O0 - i11iIiiIii + IiII % I1Ii111 + II111iiii
 if 71 - 71: ooOoO0o * I1Ii111 + i11iIiiIii + i1IIi . I1IiiI
 for iIIiIIi in lisp_crypto_keys_by_rloc_decap :
  iiiI111I = iIIiIIi . split ( ":" )
  if ( len ( iiiI111I ) == 1 ) : continue
  iiiI111I = iiiI111I [ 0 ] if len ( iiiI111I ) == 2 else ":" . join ( iiiI111I [ 0 : - 1 ] )
  if ( iiiI111I == oooOO0oOooO00 ) :
   oOoOo0o00o = lisp_crypto_keys_by_rloc_decap [ iIIiIIi ]
   lisp_crypto_keys_by_rloc_decap [ oooOO0oOooO00 ] = oOoOo0o00o
   return ( oooOO0oOooO00 )
   if 69 - 69: Oo0Ooo - o0oOOo0O0Ooo
   if 18 - 18: OoooooooOO
 return ( None )
 if 52 - 52: i1IIi - II111iiii / i1IIi . I1Ii111 . OoooooooOO - IiII
 if 47 - 47: iIii1I11I1II1 / IiII
 if 81 - 81: I1Ii111 . i1IIi / o0oOOo0O0Ooo
 if 30 - 30: i11iIiiIii . I1IiiI
 if 5 - 5: Ii1I / O0 + iIii1I11I1II1
 if 22 - 22: ooOoO0o . ooOoO0o * OOooOOo % OoOoOO00
 if 51 - 51: OoOoOO00 . oO0o - OoOoOO00
 if 79 - 79: iII111i
 if 71 - 71: i1IIi / OoO0O00 / OOooOOo + I1Ii111
 if 80 - 80: Oo0Ooo . iIii1I11I1II1 . OoooooooOO % iII111i . oO0o
 if 10 - 10: i11iIiiIii * OoooooooOO . i11iIiiIii
def lisp_build_crypto_decap_lookup_key ( addr , port ) :
 addr = addr . print_address_no_iid ( )
 I1IIiIIi1iII = addr + ":" + str ( port )
 if 56 - 56: iIii1I11I1II1 . Oo0Ooo / II111iiii
 if ( lisp_i_am_rtr ) :
  if ( lisp_rloc_probe_list . has_key ( addr ) ) : return ( addr )
  if 75 - 75: Oo0Ooo - I1Ii111 * IiII
  if 2 - 2: I1Ii111 - O0 % OoooooooOO + I1Ii111
  if 1 - 1: I1Ii111 % OoooooooOO + OoooooooOO - I1IiiI % I1IiiI
  if 51 - 51: iIii1I11I1II1 / I1IiiI
  if 27 - 27: O0 . o0oOOo0O0Ooo / ooOoO0o / OoooooooOO % Ii1I
  if 27 - 27: ooOoO0o / IiII + OoO0O00 + Ii1I % I1Ii111
  for IIII1iII in lisp_nat_state_info . values ( ) :
   for iiIiIIi1I in IIII1iII :
    if ( addr == iiIiIIi1I . address ) : return ( I1IIiIIi1iII )
    if 86 - 86: O0 % i11iIiiIii - Ii1I * oO0o % OOooOOo * i1IIi
    if 87 - 87: II111iiii
  return ( addr )
  if 53 - 53: OoOoOO00 * i11iIiiIii / I1Ii111
 return ( I1IIiIIi1iII )
 if 100 - 100: ooOoO0o + I1IiiI * oO0o + ooOoO0o
 if 24 - 24: i11iIiiIii + ooOoO0o
 if 80 - 80: IiII % I11i % oO0o
 if 97 - 97: i1IIi * i11iIiiIii / Ii1I - I1IiiI % IiII
 if 70 - 70: iIii1I11I1II1
 if 2 - 2: IiII - i1IIi * IiII % O0 / Ii1I
 if 64 - 64: iII111i - Oo0Ooo
def lisp_set_ttl ( lisp_socket , ttl ) :
 try :
  lisp_socket . setsockopt ( socket . SOL_IP , socket . IP_TTL , ttl )
 except :
  lprint ( "socket.setsockopt(IP_TTL) not supported" )
  pass
  if 73 - 73: iIii1I11I1II1 * I1Ii111 * OoO0O00
 return
 if 68 - 68: ooOoO0o * Ii1I / I1ii11iIi11i * OoooooooOO + OoooooooOO . OoooooooOO
 if 50 - 50: I1IiiI % o0oOOo0O0Ooo
 if 1 - 1: II111iiii
 if 22 - 22: I1Ii111 + iII111i
 if 50 - 50: iII111i % OoOoOO00 - II111iiii + II111iiii / OoO0O00
 if 69 - 69: Ii1I * II111iiii
 if 24 - 24: I1Ii111 * I1ii11iIi11i . OOooOOo . I1IiiI - I1ii11iIi11i
def lisp_is_rloc_probe_request ( lisp_type ) :
 lisp_type = struct . unpack ( "B" , lisp_type ) [ 0 ]
 return ( lisp_type == 0x12 )
 if 56 - 56: I1IiiI * Oo0Ooo + OoO0O00 - oO0o * I1Ii111
 if 68 - 68: ooOoO0o * i11iIiiIii * OOooOOo % iII111i
 if 10 - 10: Ii1I / Oo0Ooo - i1IIi
 if 11 - 11: I11i * iII111i
 if 28 - 28: II111iiii + IiII / Oo0Ooo * I1IiiI - OOooOOo
 if 2 - 2: oO0o + I11i / I1Ii111 . I11i
 if 59 - 59: Ii1I
def lisp_is_rloc_probe_reply ( lisp_type ) :
 lisp_type = struct . unpack ( "B" , lisp_type ) [ 0 ]
 return ( lisp_type == 0x28 )
 if 47 - 47: iII111i % iII111i
 if 81 - 81: oO0o / I1ii11iIi11i . OoooooooOO % II111iiii / oO0o
 if 23 - 23: IiII + oO0o + o0oOOo0O0Ooo . I1ii11iIi11i / i11iIiiIii + iIii1I11I1II1
 if 74 - 74: I11i % OOooOOo
 if 57 - 57: O0 + I1IiiI + i11iIiiIii
 if 90 - 90: I1ii11iIi11i . OoO0O00 * iIii1I11I1II1 - Oo0Ooo
 if 28 - 28: I1IiiI . ooOoO0o - ooOoO0o * OOooOOo . IiII
 if 16 - 16: iIii1I11I1II1 % i11iIiiIii / Ii1I % iIii1I11I1II1 / iII111i
 if 27 - 27: II111iiii * OoooooooOO / Oo0Ooo % O0
 if 41 - 41: oO0o / iIii1I11I1II1 % iII111i - I1Ii111 % I11i * i11iIiiIii
 if 21 - 21: O0
 if 14 - 14: IiII / I1ii11iIi11i + Ii1I
 if 48 - 48: I1Ii111 * oO0o / o0oOOo0O0Ooo * OoOoOO00 * ooOoO0o
 if 38 - 38: I1IiiI * Ii1I + Oo0Ooo - OoooooooOO
 if 63 - 63: I1ii11iIi11i
 if 99 - 99: I1Ii111 % oO0o - II111iiii . ooOoO0o
 if 26 - 26: I1ii11iIi11i * iII111i . OoooooooOO - Oo0Ooo - IiII
 if 6 - 6: OOooOOo - I1IiiI . IiII
 if 40 - 40: II111iiii
def lisp_is_rloc_probe ( packet , rr ) :
 iI = ( struct . unpack ( "B" , packet [ 9 ] ) [ 0 ] == 17 )
 if ( iI == False ) : return ( [ packet , None , None , None ] )
 if 13 - 13: OoOoOO00
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
   if 23 - 23: Oo0Ooo / II111iiii % OOooOOo % iII111i - Oo0Ooo / OoO0O00
   if 7 - 7: Ii1I / I11i / II111iiii % I11i * I11i + iIii1I11I1II1
   if 6 - 6: iIii1I11I1II1 * oO0o - iIii1I11I1II1 . O0 . O0
   if 96 - 96: I1Ii111 * II111iiii % i11iIiiIii - oO0o
   if 32 - 32: i11iIiiIii * o0oOOo0O0Ooo . OoooooooOO / O0
   if 14 - 14: i11iIiiIii . I1Ii111 % I1ii11iIi11i . I1ii11iIi11i % IiII
 I1iO00O000oOO0oO = lisp_address ( LISP_AFI_IPV4 , "" , 32 , 0 )
 I1iO00O000oOO0oO . address = socket . ntohl ( struct . unpack ( "I" , packet [ 12 : 16 ] ) [ 0 ] )
 if 93 - 93: iIii1I11I1II1 / IiII
 if 91 - 91: i11iIiiIii % ooOoO0o - iII111i * I1Ii111 . i11iIiiIii
 if 1 - 1: IiII + iIii1I11I1II1 * I1ii11iIi11i - IiII - i1IIi
 if 75 - 75: II111iiii * o0oOOo0O0Ooo / I1ii11iIi11i
 if ( I1iO00O000oOO0oO . is_local ( ) ) : return ( [ None , None , None , None ] )
 if 46 - 46: OOooOOo
 if 67 - 67: OoO0O00 . I11i % OOooOOo + Oo0Ooo
 if 40 - 40: OoO0O00 / I11i % iIii1I11I1II1 - ooOoO0o
 if 51 - 51: Oo0Ooo % iIii1I11I1II1 % oO0o + o0oOOo0O0Ooo
 I1iO00O000oOO0oO = I1iO00O000oOO0oO . print_address_no_iid ( )
 i1I1IIIi11I = socket . ntohs ( struct . unpack ( "H" , packet [ 20 : 22 ] ) [ 0 ] )
 O00O00Oo = struct . unpack ( "B" , packet [ 8 ] ) [ 0 ] - 1
 packet = packet [ 28 : : ]
 if 32 - 32: I1Ii111 * I1IiiI + Ii1I
 o0O = bold ( "Receive(pcap)" , False )
 iI1i1i1i1i = bold ( "from " + I1iO00O000oOO0oO , False )
 iII1ii = lisp_format_packet ( packet )
 lprint ( "{} {} bytes {} {}, packet: {}" . format ( o0O , len ( packet ) , iI1i1i1i1i , i1I1IIIi11I , iII1ii ) )
 if 30 - 30: OoooooooOO / I1IiiI . iIii1I11I1II1 / ooOoO0o
 return ( [ packet , I1iO00O000oOO0oO , i1I1IIIi11I , O00O00Oo ] )
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
def lisp_ipc_write_xtr_parameters ( cp , dp ) :
 if ( lisp_ipc_dp_socket == None ) : return
 if 38 - 38: OoOoOO00 . OoooooooOO % I1ii11iIi11i . oO0o % oO0o
 IIiIi1II1IiI = { "type" : "xtr-parameters" , "control-plane-logging" : cp ,
 "data-plane-logging" : dp , "rtr" : lisp_i_am_rtr }
 if 80 - 80: i11iIiiIii / OoOoOO00 . OOooOOo . iIii1I11I1II1
 lisp_write_to_dp_socket ( IIiIi1II1IiI )
 return
 if 81 - 81: I1ii11iIi11i * OoO0O00 . o0oOOo0O0Ooo . OoooooooOO
 if 64 - 64: Oo0Ooo . I1ii11iIi11i / ooOoO0o % oO0o . iIii1I11I1II1
 if 84 - 84: II111iiii . oO0o * O0 / iII111i + OoooooooOO
 if 99 - 99: I1ii11iIi11i . oO0o + Oo0Ooo + I1ii11iIi11i / I1Ii111 . I1ii11iIi11i
 if 95 - 95: OoOoOO00 * iIii1I11I1II1 / OoooooooOO % i1IIi
 if 91 - 91: OOooOOo - OoOoOO00
 if 58 - 58: II111iiii . OOooOOo % II111iiii * oO0o % OoO0O00 % I11i
 if 71 - 71: Ii1I * II111iiii * I1IiiI
def lisp_external_data_plane ( ) :
 Ii1I1i111 = 'egrep "ipc-data-plane = yes" ./lisp.config'
 if ( commands . getoutput ( Ii1I1i111 ) != "" ) : return ( True )
 if 22 - 22: oO0o
 if ( os . getenv ( "LISP_RUN_LISP_XTR" ) != None ) : return ( True )
 return ( False )
 if 96 - 96: ooOoO0o * iII111i . IiII
 if 77 - 77: OOooOOo - I11i % o0oOOo0O0Ooo
 if 46 - 46: I1IiiI % oO0o . OoooooooOO . IiII / I11i - i1IIi
 if 43 - 43: OoOoOO00 - o0oOOo0O0Ooo
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
def lisp_process_data_plane_restart ( do_clear = False ) :
 os . system ( "touch ./lisp.config" )
 if 25 - 25: iII111i / oO0o
 Ooo = { "type" : "entire-map-cache" , "entries" : [ ] }
 if 77 - 77: oO0o % o0oOOo0O0Ooo % iII111i
 if ( do_clear == False ) :
  ii11iII11i = Ooo [ "entries" ]
  lisp_map_cache . walk_cache ( lisp_ipc_walk_map_cache , ii11iII11i )
  if 28 - 28: OoOoOO00 . O0 - II111iiii - I1IiiI / OOooOOo % O0
  if 49 - 49: ooOoO0o % Ii1I
 lisp_write_to_dp_socket ( Ooo )
 return
 if 86 - 86: o0oOOo0O0Ooo - I1IiiI . II111iiii . I1Ii111
 if 22 - 22: IiII
 if 63 - 63: I1IiiI . OOooOOo . O0
 if 32 - 32: Ii1I / OOooOOo * i1IIi / i1IIi + I1IiiI % o0oOOo0O0Ooo
 if 61 - 61: o0oOOo0O0Ooo
 if 39 - 39: I1ii11iIi11i / o0oOOo0O0Ooo / Oo0Ooo * II111iiii - OoO0O00
 if 66 - 66: OoO0O00 / oO0o / I1ii11iIi11i - oO0o
 if 9 - 9: ooOoO0o * iIii1I11I1II1 * OoooooooOO
 if 13 - 13: iII111i . i11iIiiIii * o0oOOo0O0Ooo . iII111i
 if 96 - 96: Ii1I
 if 90 - 90: II111iiii
 if 93 - 93: i11iIiiIii / Ii1I * Oo0Ooo . iII111i % iII111i / IiII
 if 15 - 15: OoOoOO00 % I1Ii111 - iIii1I11I1II1
 if 52 - 52: i11iIiiIii * ooOoO0o
def lisp_process_data_plane_stats ( msg , lisp_sockets , lisp_port ) :
 if ( msg . has_key ( "entries" ) == False ) :
  lprint ( "No 'entries' in stats IPC message" )
  return
  if 15 - 15: OoooooooOO . oO0o . i11iIiiIii / o0oOOo0O0Ooo
 if ( type ( msg [ "entries" ] ) != list ) :
  lprint ( "'entries' in stats IPC message must be an array" )
  return
  if 91 - 91: ooOoO0o
  if 47 - 47: II111iiii + I11i + ooOoO0o % Oo0Ooo / iII111i
 for msg in msg [ "entries" ] :
  if ( msg . has_key ( "eid-prefix" ) == False ) :
   lprint ( "No 'eid-prefix' in stats IPC message" )
   continue
   if 9 - 9: O0 + IiII
  OO0OO0O = msg [ "eid-prefix" ]
  if 69 - 69: I1IiiI
  if ( msg . has_key ( "instance-id" ) == False ) :
   lprint ( "No 'instance-id' in stats IPC message" )
   continue
   if 11 - 11: I11i % I1Ii111 + O0 . Ii1I . I1ii11iIi11i % I1Ii111
  iiI1iii = int ( msg [ "instance-id" ] )
  if 28 - 28: IiII . o0oOOo0O0Ooo + iII111i - OoOoOO00 / OOooOOo
  if 86 - 86: ooOoO0o * OoOoOO00 + oO0o / II111iiii % OOooOOo
  if 89 - 89: O0 * Ii1I / OoO0O00 / OoOoOO00 % iII111i * iIii1I11I1II1
  if 72 - 72: iIii1I11I1II1 / iIii1I11I1II1 * I11i
  oOOOO = lisp_address ( LISP_AFI_NONE , "" , 0 , iiI1iii )
  oOOOO . store_prefix ( OO0OO0O )
  oOooO0Oo0Oo0 = lisp_map_cache_lookup ( None , oOOOO )
  if ( oOooO0Oo0Oo0 == None ) :
   lprint ( "Map-cache entry for {} not found for stats update" . format ( OO0OO0O ) )
   if 19 - 19: I1ii11iIi11i
   continue
   if 42 - 42: OoOoOO00 / IiII
   if 65 - 65: ooOoO0o - ooOoO0o * OoO0O00
  if ( msg . has_key ( "rlocs" ) == False ) :
   lprint ( "No 'rlocs' in stats IPC message for {}" . format ( OO0OO0O ) )
   if 99 - 99: I11i % ooOoO0o . I1Ii111
   continue
   if 34 - 34: ooOoO0o + oO0o + II111iiii . I1Ii111 . i1IIi
  if ( type ( msg [ "rlocs" ] ) != list ) :
   lprint ( "'rlocs' in stats IPC message must be an array" )
   continue
   if 14 - 14: OoO0O00 . ooOoO0o - i1IIi * I1IiiI
  ii1i = msg [ "rlocs" ]
  if 56 - 56: I1ii11iIi11i + i1IIi * I1Ii111 / ooOoO0o - I1ii11iIi11i . I11i
  if 25 - 25: Oo0Ooo / o0oOOo0O0Ooo + I1IiiI - I11i / i11iIiiIii
  if 89 - 89: II111iiii
  if 2 - 2: OoOoOO00 . i11iIiiIii
  for i1II1ii1I1I in ii1i :
   if ( i1II1ii1I1I . has_key ( "rloc" ) == False ) : continue
   if 2 - 2: IiII - II111iiii / Oo0Ooo % IiII * I1ii11iIi11i
   iII1II = i1II1ii1I1I [ "rloc" ]
   if ( iII1II == "no-address" ) : continue
   if 26 - 26: ooOoO0o . OoOoOO00 / iIii1I11I1II1
   Oo0O0 = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
   Oo0O0 . store_address ( iII1II )
   if 54 - 54: I1IiiI % II111iiii
   OOO0OOO000oOO0 = oOooO0Oo0Oo0 . get_rloc ( Oo0O0 )
   if ( OOO0OOO000oOO0 == None ) : continue
   if 29 - 29: ooOoO0o - OOooOOo - I11i / I1Ii111
   if 88 - 88: O0 + IiII
   if 91 - 91: OoooooooOO + OoO0O00 % I1Ii111 . I1IiiI . iIii1I11I1II1
   if 88 - 88: OoooooooOO
   I11Ii1I1iIiiI = 0 if i1II1ii1I1I . has_key ( "packet-count" ) == False else i1II1ii1I1I [ "packet-count" ]
   if 11 - 11: Ii1I * iIii1I11I1II1 . IiII % O0
   II11I = 0 if i1II1ii1I1I . has_key ( "byte-count" ) == False else i1II1ii1I1I [ "byte-count" ]
   if 32 - 32: I1Ii111 + i1IIi - I1Ii111 % i11iIiiIii
   o0O0oo0OO0O = 0 if i1II1ii1I1I . has_key ( "seconds-last-packet" ) == False else i1II1ii1I1I [ "seconds-last-packet" ]
   if 99 - 99: I1IiiI - i1IIi * i11iIiiIii + OoO0O00
   if 80 - 80: o0oOOo0O0Ooo . I11i % iIii1I11I1II1 + OoOoOO00
   OOO0OOO000oOO0 . stats . packet_count += I11Ii1I1iIiiI
   OOO0OOO000oOO0 . stats . byte_count += II11I
   OOO0OOO000oOO0 . stats . last_increment = lisp_get_timestamp ( ) - o0O0oo0OO0O
   if 87 - 87: I1Ii111 + II111iiii / I1ii11iIi11i + OoOoOO00
   lprint ( "Update stats {}/{}/{}s for {} RLOC {}" . format ( I11Ii1I1iIiiI , II11I ,
 o0O0oo0OO0O , OO0OO0O , iII1II ) )
   if 71 - 71: I1IiiI + iIii1I11I1II1 + O0 * iII111i % IiII
   if 42 - 42: OOooOOo - I1ii11iIi11i
   if 93 - 93: I1Ii111 + OOooOOo % ooOoO0o / I1Ii111 % OOooOOo . IiII
   if 37 - 37: iII111i * oO0o / oO0o / Ii1I % I11i
   if 12 - 12: i11iIiiIii
  if ( oOooO0Oo0Oo0 . group . is_null ( ) and oOooO0Oo0Oo0 . has_ttl_elapsed ( ) ) :
   OO0OO0O = green ( oOooO0Oo0Oo0 . print_eid_tuple ( ) , False )
   lprint ( "Refresh map-cache entry {}" . format ( OO0OO0O ) )
   lisp_send_map_request ( lisp_sockets , lisp_port , None , oOooO0Oo0Oo0 . eid , None )
   if 62 - 62: oO0o + OOooOOo + oO0o + I1IiiI
   if 10 - 10: IiII - Oo0Ooo % ooOoO0o
 return
 if 38 - 38: oO0o * o0oOOo0O0Ooo . I11i % II111iiii / I11i % Ii1I
 if 19 - 19: II111iiii / i11iIiiIii * II111iiii + OoOoOO00 - OoOoOO00
 if 7 - 7: OoOoOO00 - OoO0O00 % OoOoOO00 . I1ii11iIi11i % Oo0Ooo * iII111i
 if 90 - 90: IiII - OOooOOo + iIii1I11I1II1
 if 88 - 88: ooOoO0o . o0oOOo0O0Ooo . OOooOOo - I11i
 if 76 - 76: IiII % I1IiiI . iII111i
 if 5 - 5: ooOoO0o . oO0o - OoOoOO00 - OoooooooOO
 if 2 - 2: OOooOOo
 if 37 - 37: IiII - iIii1I11I1II1 * i11iIiiIii . ooOoO0o
 if 78 - 78: OOooOOo - I1ii11iIi11i + iII111i % OoOoOO00
 if 28 - 28: I11i + i1IIi / i11iIiiIii * OOooOOo * II111iiii
 if 78 - 78: OoO0O00 - i1IIi % I1Ii111
 if 87 - 87: I11i
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
def lisp_process_data_plane_decap_stats ( msg , lisp_ipc_socket ) :
 if 15 - 15: iIii1I11I1II1 * Oo0Ooo . iIii1I11I1II1 . Ii1I % iII111i - i11iIiiIii
 if 77 - 77: ooOoO0o - o0oOOo0O0Ooo * OoOoOO00 % oO0o
 if 4 - 4: i11iIiiIii + OoOoOO00
 if 45 - 45: ooOoO0o / OoooooooOO . Oo0Ooo
 if 35 - 35: i11iIiiIii / o0oOOo0O0Ooo / oO0o / I11i . O0
 if ( lisp_i_am_itr ) :
  lprint ( "Send decap-stats IPC message to lisp-etr process" )
  IIiIi1II1IiI = "stats%{}" . format ( json . dumps ( msg ) )
  IIiIi1II1IiI = lisp_command_ipc ( IIiIi1II1IiI , "lisp-itr" )
  lisp_ipc ( IIiIi1II1IiI , lisp_ipc_socket , "lisp-etr" )
  return
  if 53 - 53: i1IIi
  if 51 - 51: OoOoOO00 / iIii1I11I1II1 . oO0o - I1ii11iIi11i - OOooOOo
  if 90 - 90: i1IIi / oO0o * I1Ii111 + II111iiii % I11i
  if 41 - 41: o0oOOo0O0Ooo - II111iiii . ooOoO0o . iII111i - ooOoO0o / iII111i
  if 59 - 59: O0 / II111iiii * II111iiii - ooOoO0o
  if 63 - 63: I1ii11iIi11i * IiII % OoO0O00 . OoOoOO00 - II111iiii % IiII
  if 8 - 8: iIii1I11I1II1
  if 71 - 71: oO0o / o0oOOo0O0Ooo % iIii1I11I1II1 * iIii1I11I1II1
 IIiIi1II1IiI = bold ( "IPC" , False )
 lprint ( "Process decap-stats {} message: '{}'" . format ( IIiIi1II1IiI , msg ) )
 if 29 - 29: ooOoO0o - OoOoOO00 - o0oOOo0O0Ooo
 if ( lisp_i_am_etr ) : msg = json . loads ( msg )
 if 54 - 54: Ii1I + i11iIiiIii + i1IIi - OoooooooOO
 oO0Iii1ii = [ "good-packets" , "ICV-error" , "checksum-error" ,
 "lisp-header-error" , "no-decrypt-key" , "bad-inner-version" ,
 "outer-header-error" ]
 if 72 - 72: iIii1I11I1II1 - I1IiiI * OoO0O00 * o0oOOo0O0Ooo - I1IiiI . I1ii11iIi11i
 for iiiII1I1I1IiiI in oO0Iii1ii :
  I11Ii1I1iIiiI = 0 if msg . has_key ( iiiII1I1I1IiiI ) == False else msg [ iiiII1I1I1IiiI ] [ "packet-count" ]
  if 73 - 73: OoOoOO00 + OOooOOo * II111iiii . OOooOOo % I1Ii111 % oO0o
  lisp_decap_stats [ iiiII1I1I1IiiI ] . packet_count += I11Ii1I1iIiiI
  if 79 - 79: I1ii11iIi11i % I11i
  II11I = 0 if msg . has_key ( iiiII1I1I1IiiI ) == False else msg [ iiiII1I1I1IiiI ] [ "byte-count" ]
  if 78 - 78: i11iIiiIii % I1Ii111 + iIii1I11I1II1 + iII111i
  lisp_decap_stats [ iiiII1I1I1IiiI ] . byte_count += II11I
  if 66 - 66: I1IiiI - o0oOOo0O0Ooo
  o0O0oo0OO0O = 0 if msg . has_key ( iiiII1I1I1IiiI ) == False else msg [ iiiII1I1I1IiiI ] [ "seconds-last-packet" ]
  if 67 - 67: oO0o . iII111i * Ii1I - OOooOOo / oO0o
  lisp_decap_stats [ iiiII1I1I1IiiI ] . last_increment = lisp_get_timestamp ( ) - o0O0oo0OO0O
  if 98 - 98: OoOoOO00 * OoO0O00 . Oo0Ooo
 return
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
 if 72 - 72: I11i
 if 35 - 35: I11i % OoooooooOO / i1IIi * i1IIi / I1IiiI
 if 42 - 42: I11i - i1IIi - oO0o / I11i + Ii1I + ooOoO0o
 if 23 - 23: OoOoOO00 . oO0o - iII111i
def lisp_process_punt ( punt_socket , lisp_send_sockets , lisp_ephem_port ) :
 iIIIIiI1iiii , I1iO00O000oOO0oO = punt_socket . recvfrom ( 4000 )
 if 37 - 37: OoooooooOO + O0 . I11i % OoOoOO00
 oOO00 = json . loads ( iIIIIiI1iiii )
 if ( type ( oOO00 ) != dict ) :
  lprint ( "Invalid punt message from {}, not in JSON format" . format ( I1iO00O000oOO0oO ) )
  if 57 - 57: I1Ii111 . OOooOOo + I1Ii111 . iIii1I11I1II1 / oO0o / O0
  return
  if 88 - 88: I1Ii111
 IIIIiI = bold ( "Punt" , False )
 lprint ( "{} message from '{}': '{}'" . format ( IIIIiI , I1iO00O000oOO0oO , oOO00 ) )
 if 93 - 93: OoOoOO00 + iII111i
 if ( oOO00 . has_key ( "type" ) == False ) :
  lprint ( "Punt IPC message has no 'type' key" )
  return
  if 49 - 49: I11i . i11iIiiIii
  if 18 - 18: OOooOOo * O0 % ooOoO0o - ooOoO0o
  if 46 - 46: o0oOOo0O0Ooo * oO0o / oO0o . oO0o + I11i * OOooOOo
  if 48 - 48: iII111i + Ii1I
  if 10 - 10: I1IiiI + o0oOOo0O0Ooo
 if ( oOO00 [ "type" ] == "statistics" ) :
  lisp_process_data_plane_stats ( oOO00 , lisp_send_sockets , lisp_ephem_port )
  return
  if 75 - 75: Oo0Ooo
 if ( oOO00 [ "type" ] == "decap-statistics" ) :
  lisp_process_data_plane_decap_stats ( oOO00 , punt_socket )
  return
  if 100 - 100: i1IIi / Oo0Ooo / II111iiii + iII111i . II111iiii * oO0o
  if 36 - 36: Oo0Ooo + iII111i / OOooOOo + OOooOOo % i11iIiiIii / I1IiiI
  if 59 - 59: ooOoO0o / I11i
  if 32 - 32: iIii1I11I1II1 % oO0o / I1Ii111
  if 42 - 42: I11i / I1ii11iIi11i - I1IiiI * iII111i / I1IiiI / i11iIiiIii
 if ( oOO00 [ "type" ] == "restart" ) :
  lisp_process_data_plane_restart ( )
  return
  if 75 - 75: Oo0Ooo + IiII / I11i % I11i % IiII / I1Ii111
  if 95 - 95: OoOoOO00
  if 78 - 78: I11i
  if 62 - 62: iIii1I11I1II1 . o0oOOo0O0Ooo . ooOoO0o % oO0o % O0 % oO0o
  if 51 - 51: Oo0Ooo / IiII - Oo0Ooo
 if ( oOO00 [ "type" ] != "discovery" ) :
  lprint ( "Punt IPC message has wrong format" )
  return
  if 71 - 71: I11i * I1ii11iIi11i * OOooOOo * o0oOOo0O0Ooo
 if ( oOO00 . has_key ( "interface" ) == False ) :
  lprint ( "Invalid punt message from {}, required keys missing" . format ( I1iO00O000oOO0oO ) )
  if 53 - 53: I1IiiI % I1IiiI
  return
  if 80 - 80: OoO0O00 - i11iIiiIii / iII111i * I1ii11iIi11i / I1IiiI - I1Ii111
  if 85 - 85: IiII
  if 72 - 72: iII111i * OoOoOO00
  if 65 - 65: iIii1I11I1II1 / iIii1I11I1II1 % O0 / II111iiii . OOooOOo . O0
  if 65 - 65: I11i
 oOOOo0o = oOO00 [ "interface" ]
 if ( oOOOo0o == "" ) :
  iiI1iii = int ( oOO00 [ "instance-id" ] )
  if ( iiI1iii == - 1 ) : return
 else :
  iiI1iii = lisp_get_interface_instance_id ( oOOOo0o , None )
  if 35 - 35: o0oOOo0O0Ooo - i11iIiiIii
  if 78 - 78: ooOoO0o - II111iiii - i1IIi
  if 18 - 18: OoooooooOO % OoOoOO00 - IiII / oO0o . OOooOOo . I1IiiI
  if 77 - 77: I1ii11iIi11i . OoO0O00 / OoOoOO00 / O0
  if 67 - 67: ooOoO0o % I11i % oO0o
 I11I1Ii1i = None
 if ( oOO00 . has_key ( "source-eid" ) ) :
  II1iIIii1I111 = oOO00 [ "source-eid" ]
  I11I1Ii1i = lisp_address ( LISP_AFI_NONE , II1iIIii1I111 , 0 , iiI1iii )
  if ( I11I1Ii1i . is_null ( ) ) :
   lprint ( "Invalid source-EID format '{}'" . format ( II1iIIii1I111 ) )
   return
   if 74 - 74: II111iiii
   if 44 - 44: Oo0Ooo + OoO0O00 + OoOoOO00 - I1IiiI
 oOOoo0oO = None
 if ( oOO00 . has_key ( "dest-eid" ) ) :
  Ooo0ii = oOO00 [ "dest-eid" ]
  oOOoo0oO = lisp_address ( LISP_AFI_NONE , Ooo0ii , 0 , iiI1iii )
  if ( oOOoo0oO . is_null ( ) ) :
   lprint ( "Invalid dest-EID format '{}'" . format ( Ooo0ii ) )
   return
   if 75 - 75: I1ii11iIi11i - IiII . II111iiii / i1IIi
   if 76 - 76: II111iiii * O0 - Oo0Ooo + OoooooooOO
   if 37 - 37: OoooooooOO + i11iIiiIii
   if 20 - 20: I1IiiI + iII111i + O0 * O0
   if 18 - 18: I11i - I11i . OoOoOO00 . ooOoO0o
   if 31 - 31: ooOoO0o
   if 87 - 87: OoooooooOO + OOooOOo - I1ii11iIi11i / I1IiiI + ooOoO0o - Oo0Ooo
   if 19 - 19: ooOoO0o + I1ii11iIi11i - ooOoO0o
 if ( I11I1Ii1i ) :
  O0O0o0o0o = green ( I11I1Ii1i . print_address ( ) , False )
  iIiIi = lisp_db_for_lookups . lookup_cache ( I11I1Ii1i , False )
  if ( iIiIi != None ) :
   if 17 - 17: I11i * i1IIi + iIii1I11I1II1 % I1IiiI
   if 44 - 44: IiII + I1IiiI . Ii1I % Oo0Ooo
   if 97 - 97: O0
   if 95 - 95: OoO0O00 % iII111i / I1IiiI * OoooooooOO
   if 31 - 31: iIii1I11I1II1
   if ( iIiIi . dynamic_eid_configured ( ) ) :
    iiiii11I1 = lisp_allow_dynamic_eid ( oOOOo0o , I11I1Ii1i )
    if ( iiiii11I1 != None and lisp_i_am_itr ) :
     lisp_itr_discover_eid ( iIiIi , I11I1Ii1i , oOOOo0o , iiiii11I1 )
    else :
     lprint ( ( "Disallow dynamic source-EID {} " + "on interface {}" ) . format ( O0O0o0o0o , oOOOo0o ) )
     if 62 - 62: o0oOOo0O0Ooo - iII111i / II111iiii . o0oOOo0O0Ooo
     if 20 - 20: iIii1I11I1II1 % OOooOOo
     if 91 - 91: ooOoO0o
  else :
   lprint ( "Punt from non-EID source {}" . format ( O0O0o0o0o ) )
   if 96 - 96: I1IiiI . OOooOOo
   if 94 - 94: OoooooooOO + II111iiii % ooOoO0o - II111iiii / O0
   if 34 - 34: IiII % oO0o
   if 54 - 54: I1IiiI
   if 80 - 80: OoOoOO00 . I1IiiI / I1ii11iIi11i . iII111i
   if 31 - 31: I11i * o0oOOo0O0Ooo
 if ( oOOoo0oO ) :
  oOooO0Oo0Oo0 = lisp_map_cache_lookup ( I11I1Ii1i , oOOoo0oO )
  if ( oOooO0Oo0Oo0 == None or oOooO0Oo0Oo0 . action == LISP_SEND_MAP_REQUEST_ACTION ) :
   if 17 - 17: Ii1I * iIii1I11I1II1
   if 9 - 9: o0oOOo0O0Ooo - IiII
   if 78 - 78: i11iIiiIii . o0oOOo0O0Ooo
   if 72 - 72: Oo0Ooo % II111iiii + O0 * OoOoOO00 - OOooOOo + I1Ii111
   if 23 - 23: I1IiiI - O0 - iII111i . II111iiii / oO0o
   if ( lisp_rate_limit_map_request ( I11I1Ii1i , oOOoo0oO ) ) : return
   lisp_send_map_request ( lisp_send_sockets , lisp_ephem_port ,
 I11I1Ii1i , oOOoo0oO , None )
  else :
   O0O0o0o0o = green ( oOOoo0oO . print_address ( ) , False )
   lprint ( "Map-cache entry for {} already exists" . format ( O0O0o0o0o ) )
   if 1 - 1: I11i . OOooOOo / oO0o % I11i * Oo0Ooo + Oo0Ooo
   if 23 - 23: Ii1I % i1IIi - I1Ii111
 return
 if 95 - 95: OoOoOO00 - ooOoO0o . i1IIi . OoooooooOO
 if 38 - 38: I1IiiI + I1ii11iIi11i - Oo0Ooo . i11iIiiIii - i1IIi
 if 11 - 11: IiII / I1IiiI . I1IiiI
 if 87 - 87: OoooooooOO * OoO0O00 * iIii1I11I1II1
 if 16 - 16: o0oOOo0O0Ooo * I11i + OoooooooOO + O0 / iIii1I11I1II1
 if 60 - 60: Ii1I % IiII * OoooooooOO * ooOoO0o * Ii1I
 if 8 - 8: I1Ii111 - o0oOOo0O0Ooo
def lisp_ipc_map_cache_entry ( mc , jdata ) :
 oo = lisp_write_ipc_map_cache ( True , mc , dont_send = True )
 jdata . append ( oo )
 return ( [ True , jdata ] )
 if 52 - 52: OoOoOO00 % O0 + I1ii11iIi11i . i11iIiiIii
 if 59 - 59: Ii1I - I1Ii111 . ooOoO0o - OoOoOO00 + oO0o . OoO0O00
 if 88 - 88: OOooOOo - ooOoO0o * o0oOOo0O0Ooo . OoooooooOO
 if 3 - 3: I1Ii111
 if 24 - 24: Ii1I + i11iIiiIii * I1Ii111 - OoOoOO00 / Ii1I - OoOoOO00
 if 69 - 69: I11i - I1IiiI . oO0o - OoooooooOO
 if 33 - 33: o0oOOo0O0Ooo - o0oOOo0O0Ooo
 if 55 - 55: OoooooooOO / IiII + i1IIi
def lisp_ipc_walk_map_cache ( mc , jdata ) :
 if 54 - 54: ooOoO0o * Ii1I / Ii1I
 if 15 - 15: oO0o * I1Ii111
 if 11 - 11: Ii1I + o0oOOo0O0Ooo * OoooooooOO % iIii1I11I1II1
 if 87 - 87: OoO0O00 + o0oOOo0O0Ooo
 if ( mc . group . is_null ( ) ) : return ( lisp_ipc_map_cache_entry ( mc , jdata ) )
 if 46 - 46: oO0o + OoOoOO00
 if ( mc . source_cache == None ) : return ( [ True , jdata ] )
 if 17 - 17: Ii1I . Oo0Ooo - oO0o % OOooOOo
 if 59 - 59: O0
 if 75 - 75: o0oOOo0O0Ooo / OoooooooOO . I1ii11iIi11i * oO0o * I11i / OoooooooOO
 if 17 - 17: Ii1I % I1ii11iIi11i + I11i
 if 80 - 80: i1IIi . OoooooooOO % OoooooooOO . oO0o / OOooOOo
 jdata = mc . source_cache . walk_cache ( lisp_ipc_map_cache_entry , jdata )
 return ( [ True , jdata ] )
 if 85 - 85: OOooOOo
 if 80 - 80: ooOoO0o % O0 % I1ii11iIi11i + Oo0Ooo
 if 82 - 82: oO0o / iIii1I11I1II1 % ooOoO0o . Ii1I / i1IIi - I1Ii111
 if 15 - 15: I11i - OOooOOo . II111iiii . iIii1I11I1II1
 if 93 - 93: I11i + o0oOOo0O0Ooo / OOooOOo + Ii1I % Oo0Ooo % I1ii11iIi11i
 if 72 - 72: IiII / II111iiii
 if 25 - 25: i1IIi + OoOoOO00 + oO0o + OoooooooOO
def lisp_itr_discover_eid ( db , eid , input_interface , routed_interface ,
 lisp_ipc_listen_socket ) :
 OO0OO0O = eid . print_address ( )
 if ( db . dynamic_eids . has_key ( OO0OO0O ) ) :
  db . dynamic_eids [ OO0OO0O ] . last_packet = lisp_get_timestamp ( )
  return
  if 21 - 21: I1ii11iIi11i
  if 60 - 60: i1IIi / OoO0O00 . Ii1I
  if 16 - 16: i11iIiiIii + OoOoOO00 % Oo0Ooo + I1ii11iIi11i * Ii1I / I1Ii111
  if 26 - 26: iII111i
  if 31 - 31: iII111i
 O0OOOOoO00oo = lisp_dynamic_eid ( )
 O0OOOOoO00oo . dynamic_eid . copy_address ( eid )
 O0OOOOoO00oo . interface = routed_interface
 O0OOOOoO00oo . last_packet = lisp_get_timestamp ( )
 O0OOOOoO00oo . get_timeout ( routed_interface )
 db . dynamic_eids [ OO0OO0O ] = O0OOOOoO00oo
 if 45 - 45: OoO0O00
 OoOoO0O00o = ""
 if ( input_interface != routed_interface ) :
  OoOoO0O00o = ", routed-interface " + routed_interface
  if 8 - 8: OoOoOO00 % I1Ii111 * iIii1I11I1II1
  if 12 - 12: I1IiiI . OoOoOO00 - O0 + IiII + OoOoOO00
 O00OO0OII1IIii1IiIi = green ( OO0OO0O , False ) + bold ( " discovered" , False )
 lprint ( "Dynamic-EID {} on interface {}{}, timeout {}" . format ( O00OO0OII1IIii1IiIi , input_interface , OoOoO0O00o , O0OOOOoO00oo . timeout ) )
 if 34 - 34: iII111i * ooOoO0o - I1Ii111 . iIii1I11I1II1 / II111iiii
 if 37 - 37: IiII * iII111i
 if 49 - 49: Oo0Ooo % I1ii11iIi11i / I1Ii111
 if 16 - 16: I1ii11iIi11i + OoO0O00 + iIii1I11I1II1 + ooOoO0o - i1IIi + i11iIiiIii
 if 33 - 33: i1IIi * OoO0O00
 IIiIi1II1IiI = "learn%{}%{}" . format ( OO0OO0O , routed_interface )
 IIiIi1II1IiI = lisp_command_ipc ( IIiIi1II1IiI , "lisp-itr" )
 lisp_ipc ( IIiIi1II1IiI , lisp_ipc_listen_socket , "lisp-etr" )
 return
 if 76 - 76: OoOoOO00 - Ii1I * i11iIiiIii + IiII - I1Ii111 % ooOoO0o
 if 43 - 43: Ii1I / I11i % I1ii11iIi11i / OoO0O00
 if 49 - 49: iII111i + iII111i % ooOoO0o * i11iIiiIii / Ii1I
 if 72 - 72: OOooOOo * Ii1I % OoO0O00
 if 72 - 72: OoOoOO00 + o0oOOo0O0Ooo - i1IIi - OoO0O00 % OoOoOO00
 if 42 - 42: oO0o / i1IIi . IiII
 if 12 - 12: i11iIiiIii . ooOoO0o
 if 80 - 80: O0 / iIii1I11I1II1 % iII111i * ooOoO0o / i11iIiiIii . OoOoOO00
 if 88 - 88: OoooooooOO . I1IiiI
 if 6 - 6: I1Ii111 - i11iIiiIii - oO0o
 if 7 - 7: i1IIi
 if 6 - 6: OoooooooOO - Oo0Ooo - I1ii11iIi11i
 if 34 - 34: iII111i + i11iIiiIii . IiII
def lisp_retry_decap_keys ( addr_str , packet , iv , packet_icv ) :
 if ( lisp_search_decap_keys == False ) : return
 if 54 - 54: Oo0Ooo + I11i - iII111i * ooOoO0o % i11iIiiIii . IiII
 if 29 - 29: II111iiii % i11iIiiIii % O0
 if 38 - 38: o0oOOo0O0Ooo * IiII
 if 51 - 51: OoooooooOO . Ii1I % OoooooooOO - I1IiiI + I1Ii111 % oO0o
 if ( addr_str . find ( ":" ) != - 1 ) : return
 if 28 - 28: i11iIiiIii - I1IiiI * OoO0O00
 IiIii1 = lisp_crypto_keys_by_rloc_decap [ addr_str ]
 if 19 - 19: OoooooooOO
 for o0000oO in lisp_crypto_keys_by_rloc_decap :
  if 34 - 34: OoOoOO00 . oO0o
  if 53 - 53: oO0o + OoooooooOO * ooOoO0o
  if 85 - 85: I1ii11iIi11i - o0oOOo0O0Ooo % o0oOOo0O0Ooo % iII111i * OoOoOO00
  if 50 - 50: I1Ii111 + I1Ii111 + I11i - OoOoOO00
  if ( o0000oO . find ( addr_str ) == - 1 ) : continue
  if 65 - 65: oO0o / I11i + iII111i - I1ii11iIi11i
  if 80 - 80: II111iiii . i11iIiiIii
  if 66 - 66: ooOoO0o * iII111i * OOooOOo % OoO0O00 / I1ii11iIi11i
  if 33 - 33: iIii1I11I1II1
  if ( o0000oO == addr_str ) : continue
  if 52 - 52: iIii1I11I1II1 + O0
  if 84 - 84: OOooOOo / iII111i . I1IiiI / O0 % OOooOOo . iII111i
  if 32 - 32: OoO0O00 + OoO0O00 % o0oOOo0O0Ooo / O0
  if 29 - 29: iII111i % I1Ii111
  oo = lisp_crypto_keys_by_rloc_decap [ o0000oO ]
  if ( oo == IiIii1 ) : continue
  if 95 - 95: OOooOOo - ooOoO0o % i1IIi / O0 % I11i . IiII
  if 63 - 63: ooOoO0o
  if 22 - 22: OOooOOo . i11iIiiIii + II111iiii - Oo0Ooo % i1IIi / o0oOOo0O0Ooo
  if 90 - 90: IiII
  Iii11ooooO00O0 = oo [ 1 ]
  if ( packet_icv != Iii11ooooO00O0 . do_icv ( packet , iv ) ) :
   lprint ( "Test ICV with key {} failed" . format ( red ( o0000oO , False ) ) )
   continue
   if 96 - 96: OoO0O00 % II111iiii * i11iIiiIii * I11i - iIii1I11I1II1 * iII111i
   if 55 - 55: o0oOOo0O0Ooo
  lprint ( "Changing decap crypto key to {}" . format ( red ( o0000oO , False ) ) )
  lisp_crypto_keys_by_rloc_decap [ addr_str ] = oo
  if 30 - 30: i1IIi / I1Ii111 * oO0o - oO0o / oO0o
 return
 if 9 - 9: IiII / o0oOOo0O0Ooo . IiII * O0 % i11iIiiIii % OoOoOO00
 if 29 - 29: I1ii11iIi11i % ooOoO0o . OOooOOo . Ii1I . IiII
 if 69 - 69: o0oOOo0O0Ooo . i11iIiiIii * I11i + IiII / I11i
 if 66 - 66: I1ii11iIi11i % I1Ii111 - i11iIiiIii % I11i
 if 62 - 62: i11iIiiIii % iIii1I11I1II1 / IiII . I1IiiI * O0
 if 17 - 17: I1ii11iIi11i - I1Ii111 % II111iiii + OOooOOo
 if 45 - 45: I1Ii111 + iII111i - iIii1I11I1II1 / Oo0Ooo
 if 92 - 92: iIii1I11I1II1 . OoO0O00 - I11i % I1ii11iIi11i / i11iIiiIii
def lisp_decent_pull_xtr_configured ( ) :
 return ( lisp_decent_modulus != 0 and lisp_decent_dns_suffix != None )
 if 4 - 4: Oo0Ooo / I1IiiI * i1IIi . II111iiii
 if 13 - 13: i1IIi
 if 39 - 39: OOooOOo
 if 73 - 73: OoO0O00 . ooOoO0o
 if 13 - 13: o0oOOo0O0Ooo - OoOoOO00
 if 60 - 60: OoO0O00
 if 17 - 17: i11iIiiIii % i1IIi % I1IiiI % ooOoO0o + I1Ii111 + Oo0Ooo
 if 16 - 16: iII111i . I1ii11iIi11i . oO0o . OoO0O00
def lisp_is_decent_dns_suffix ( dns_name ) :
 if ( lisp_decent_dns_suffix == None ) : return ( False )
 oo00 = dns_name . split ( "." )
 oo00 = "." . join ( oo00 [ 1 : : ] )
 return ( oo00 == lisp_decent_dns_suffix )
 if 90 - 90: i1IIi . ooOoO0o + i11iIiiIii * OoooooooOO
 if 30 - 30: iII111i . OoO0O00 . i11iIiiIii / I1ii11iIi11i * Oo0Ooo
 if 38 - 38: IiII + II111iiii
 if 20 - 20: iII111i * I1IiiI * iII111i - o0oOOo0O0Ooo + i1IIi + ooOoO0o
 if 49 - 49: II111iiii * I1IiiI / oO0o
 if 50 - 50: Ii1I + O0 . I1IiiI * Oo0Ooo
 if 15 - 15: Oo0Ooo
def lisp_get_decent_index ( eid ) :
 OO0OO0O = eid . print_prefix ( )
 Oooo0000O0O00 = hashlib . sha256 ( OO0OO0O ) . hexdigest ( )
 oooO0 = int ( Oooo0000O0O00 , 16 ) % lisp_decent_modulus
 return ( oooO0 )
 if 79 - 79: OoOoOO00 . IiII * iII111i % OoooooooOO % i1IIi % iIii1I11I1II1
 if 20 - 20: I1Ii111 % oO0o * iIii1I11I1II1 % oO0o . IiII % OoooooooOO
 if 11 - 11: Oo0Ooo / Oo0Ooo / OoO0O00 / oO0o . iIii1I11I1II1 + I1Ii111
 if 23 - 23: Oo0Ooo * IiII - I1Ii111 . OoooooooOO
 if 78 - 78: OoOoOO00 - iIii1I11I1II1
 if 20 - 20: i1IIi
 if 72 - 72: ooOoO0o . II111iiii
def lisp_get_decent_dns_name ( eid ) :
 oooO0 = lisp_get_decent_index ( eid )
 return ( str ( oooO0 ) + "." + lisp_decent_dns_suffix )
 if 32 - 32: I1Ii111 - oO0o + OoooooooOO . OoOoOO00 + i11iIiiIii / i1IIi
 if 26 - 26: I1IiiI + OoooooooOO % OoOoOO00 . IiII - II111iiii . OoOoOO00
 if 37 - 37: OoO0O00 % O0 + OoOoOO00 * I11i . Ii1I * OoO0O00
 if 18 - 18: o0oOOo0O0Ooo / OOooOOo
 if 28 - 28: O0 / Ii1I - oO0o % I1ii11iIi11i % O0 . OoO0O00
 if 100 - 100: O0
 if 19 - 19: Ii1I * iIii1I11I1II1 * Oo0Ooo - i11iIiiIii * i11iIiiIii - OOooOOo
 if 88 - 88: O0 . iIii1I11I1II1 . I1ii11iIi11i
def lisp_get_decent_dns_name_from_str ( iid , eid_str ) :
 oOOOO = lisp_address ( LISP_AFI_NONE , eid_str , 0 , iid )
 oooO0 = lisp_get_decent_index ( oOOOO )
 return ( str ( oooO0 ) + "." + lisp_decent_dns_suffix )
 if 80 - 80: oO0o / i1IIi * iIii1I11I1II1
 if 38 - 38: Ii1I
 if 20 - 20: iIii1I11I1II1 + Oo0Ooo - Ii1I / i11iIiiIii . OoO0O00
 if 66 - 66: OoooooooOO - Ii1I / iII111i . I1IiiI + I1ii11iIi11i - I1Ii111
 if 36 - 36: I1Ii111 - OoO0O00 . I1ii11iIi11i * I1ii11iIi11i
 if 9 - 9: OOooOOo - oO0o - iIii1I11I1II1 * i11iIiiIii / I11i
 if 2 - 2: i1IIi % iII111i * ooOoO0o / OoOoOO00 + Oo0Ooo
 if 59 - 59: i11iIiiIii / I1IiiI * iII111i
 if 16 - 16: i11iIiiIii * II111iiii - ooOoO0o
 if 80 - 80: iIii1I11I1II1 + iIii1I11I1II1 + I1Ii111 - IiII * iII111i - Ii1I
def lisp_trace_append ( packet , ed = "encap" ) :
 O00OO = 28 if packet . inner_version == 4 else 48
 oo0O00O0oO0OO = packet . packet [ O00OO : : ]
 O0O0 = lisp_trace ( )
 if ( O0O0 . decode ( oo0O00O0oO0OO ) == False ) :
  lprint ( "Could not decode JSON portion of a LISP-Trace packet" )
  return ( False )
  if 36 - 36: II111iiii - o0oOOo0O0Ooo - Ii1I
  if 2 - 2: i1IIi
 oO00o000oo0 = "?" if packet . outer_dest . is_null ( ) else packet . outer_dest . print_address_no_iid ( )
 if 81 - 81: I1Ii111 * i1IIi
 if 94 - 94: II111iiii
 if 98 - 98: Ii1I * Ii1I / IiII
 if 1 - 1: OOooOOo
 if 47 - 47: i11iIiiIii - I11i
 oo = { }
 oo [ "node" ] = "ITR" if lisp_i_am_itr else "ETR" if lisp_i_am_etr else "RTR" if lisp_i_am_rtr else "?"
 if 38 - 38: Oo0Ooo % OoooooooOO + iII111i
 iIi1iii = packet . outer_source
 if ( iIi1iii . is_null ( ) ) : iIi1iii = lisp_myrlocs [ 0 ]
 oo [ "srloc" ] = iIi1iii . print_address_no_iid ( )
 oo [ "drloc" ] = oO00o000oo0
 oo [ "hostname" ] = lisp_hostname
 o0000oO = ed + "-timestamp"
 oo [ o0000oO ] = lisp_get_timestamp ( )
 if 60 - 60: OoooooooOO + i11iIiiIii - o0oOOo0O0Ooo . OoooooooOO + oO0o / ooOoO0o
 if 93 - 93: I1ii11iIi11i - ooOoO0o - Oo0Ooo + o0oOOo0O0Ooo . ooOoO0o
 if 98 - 98: II111iiii
 if 56 - 56: i1IIi % IiII / I1Ii111
 if 1 - 1: I1IiiI / OoOoOO00 - oO0o + OoooooooOO
 I11I1Ii1i = packet . inner_source . print_address ( )
 oOOoo0oO = packet . inner_dest . print_address ( )
 if ( O0O0 . packet_json == [ ] ) :
  iiIII = { }
  iiIII [ "seid" ] = I11I1Ii1i
  iiIII [ "deid" ] = oOOoo0oO
  iiIII [ "paths" ] = [ ]
  O0O0 . packet_json . append ( iiIII )
  if 51 - 51: ooOoO0o + Ii1I * o0oOOo0O0Ooo * I1IiiI / oO0o + OoO0O00
  if 92 - 92: oO0o * o0oOOo0O0Ooo % ooOoO0o + OoOoOO00 * OoooooooOO * Oo0Ooo
  if 86 - 86: iII111i / OoooooooOO * I1Ii111 % I1IiiI + Ii1I
  if 16 - 16: OoO0O00
  if 41 - 41: i1IIi
  if 72 - 72: OoooooooOO / i11iIiiIii - O0 . OoOoOO00
 for iiIII in O0O0 . packet_json :
  if ( iiIII [ "deid" ] != oOOoo0oO ) : continue
  iiIII [ "paths" ] . append ( oo )
  break
  if 41 - 41: IiII + oO0o * iIii1I11I1II1 % oO0o + IiII
  if 64 - 64: I1ii11iIi11i % OoO0O00 + oO0o
  if 47 - 47: I1ii11iIi11i + Ii1I % I1Ii111 % OoO0O00 . IiII % i1IIi
  if 14 - 14: O0 / I1IiiI . I1ii11iIi11i
  if 47 - 47: I1Ii111 * ooOoO0o / iII111i . O0
  if 61 - 61: II111iiii . OoO0O00 * OoO0O00 % II111iiii % OOooOOo * OoOoOO00
  if 82 - 82: Ii1I
  if 83 - 83: I1IiiI
 I1I1O00 = False
 if ( len ( O0O0 . packet_json ) == 1 and O0O0 . myeid ( packet . inner_dest ) ) :
  iiIII = { }
  iiIII [ "seid" ] = oOOoo0oO
  iiIII [ "deid" ] = I11I1Ii1i
  iiIII [ "paths" ] = [ ]
  O0O0 . packet_json . append ( iiIII )
  I1I1O00 = True
  if 72 - 72: OoOoOO00 % o0oOOo0O0Ooo % Oo0Ooo
  if 58 - 58: i1IIi + I11i - OoooooooOO . OoOoOO00 . iIii1I11I1II1 % OoOoOO00
  if 59 - 59: Ii1I / I1Ii111 + i11iIiiIii
  if 20 - 20: O0 / I1Ii111 - OOooOOo % iIii1I11I1II1
  if 89 - 89: O0 * OoOoOO00 . ooOoO0o
  if 11 - 11: iIii1I11I1II1 * OoO0O00 . I1IiiI * OoOoOO00 / II111iiii
 O0O0 . print_trace ( )
 oo0O00O0oO0OO = O0O0 . encode ( )
 if 72 - 72: I11i
 if 7 - 7: i1IIi - o0oOOo0O0Ooo - I1IiiI
 if 62 - 62: OoOoOO00 * oO0o - I1IiiI / Ii1I
 if 48 - 48: o0oOOo0O0Ooo % o0oOOo0O0Ooo - OoOoOO00
 if 13 - 13: OoO0O00 - Ii1I . ooOoO0o / O0 * OoOoOO00
 if 57 - 57: O0 + OoooooooOO % o0oOOo0O0Ooo / I1Ii111 / OOooOOo - OoOoOO00
 if 48 - 48: o0oOOo0O0Ooo - II111iiii + OoOoOO00
 if 54 - 54: II111iiii - OoO0O00 - o0oOOo0O0Ooo - O0 % I1Ii111
 iii111iIi1 = O0O0 . packet_json [ 0 ] [ "paths" ] [ 0 ] [ "srloc" ]
 if ( oO00o000oo0 == "?" ) :
  lprint ( "LISP-Trace return to sender RLOC {}" . format ( iii111iIi1 ) )
  O0O0 . return_to_sender ( iii111iIi1 , oo0O00O0oO0OO )
  return ( False )
  if 100 - 100: iIii1I11I1II1 % iIii1I11I1II1 % iIii1I11I1II1 / Oo0Ooo
  if 61 - 61: O0 / o0oOOo0O0Ooo . I1ii11iIi11i % Ii1I . IiII - I1ii11iIi11i
  if 85 - 85: iII111i - iIii1I11I1II1 . I1IiiI * OoO0O00 - iII111i
  if 97 - 97: ooOoO0o / I11i . IiII + I1Ii111 . iIii1I11I1II1
  if 24 - 24: ooOoO0o - oO0o % OoOoOO00 * Oo0Ooo
  if 54 - 54: Ii1I - OoooooooOO % I1IiiI + oO0o
 o0o0O0oOoO = O0O0 . packet_length ( )
 if 94 - 94: OoO0O00 * I1IiiI / O0 + I1Ii111 / i11iIiiIii
 if 34 - 34: Oo0Ooo . i1IIi
 if 97 - 97: I11i
 if 89 - 89: iII111i % OoOoOO00 . Oo0Ooo
 iII1III11ii = packet . packet [ 0 : O00OO ]
 iII1ii = struct . pack ( "HH" , socket . htons ( o0o0O0oOoO ) , 0 )
 iII1III11ii = iII1III11ii [ 0 : O00OO - 4 ] + iII1ii
 if 24 - 24: OOooOOo . oO0o / I1Ii111 / IiII - iII111i
 if 23 - 23: iIii1I11I1II1 * ooOoO0o * iII111i * i11iIiiIii * i1IIi
 if 25 - 25: O0 / OoO0O00 - oO0o - I1IiiI * OoOoOO00
 if 98 - 98: OoO0O00 % OoooooooOO + OoooooooOO * OoOoOO00 / OoO0O00 + o0oOOo0O0Ooo
 if 25 - 25: OoO0O00 % OoOoOO00
 if ( I1I1O00 ) :
  iII1III11ii = iII1III11ii [ 0 : 12 ] + iII1III11ii [ 16 : 20 ] + iII1III11ii [ 12 : 16 ] + iII1III11ii [ 20 : : ]
  if 15 - 15: OoO0O00 + I1ii11iIi11i
  O0o0oo0oOO0oO = packet . inner_dest
  packet . inner_dest = packet . inner_source
  packet . inner_source = O0o0oo0oOO0oO
  if 88 - 88: OoooooooOO / I11i % II111iiii % OOooOOo - I11i
  if 55 - 55: Oo0Ooo - OOooOOo - O0
  if 40 - 40: OoOoOO00 - OOooOOo
  if 3 - 3: IiII % I11i * I1Ii111 + iIii1I11I1II1 . oO0o
  if 35 - 35: II111iiii
 O00OO = 2 if packet . inner_version == 4 else 4
 I1Ii11i11II1 = 20 + o0o0O0oOoO if packet . inner_version == 4 else 40 + o0o0O0oOoO
 Oo0000 = struct . pack ( "H" , socket . htons ( I1Ii11i11II1 ) )
 iII1III11ii = iII1III11ii [ 0 : O00OO ] + Oo0000 + iII1III11ii [ O00OO + 2 : : ]
 if 14 - 14: iIii1I11I1II1
 if 29 - 29: i1IIi
 if 12 - 12: OOooOOo
 if 84 - 84: i11iIiiIii * o0oOOo0O0Ooo
 if ( packet . inner_version == 4 ) :
  ooOoo000 = struct . pack ( "H" , 0 )
  iII1III11ii = iII1III11ii [ 0 : 10 ] + ooOoo000 + iII1III11ii [ 12 : : ]
  Oo0000 = lisp_ip_checksum ( iII1III11ii [ 0 : 20 ] )
  iII1III11ii = Oo0000 + iII1III11ii [ 20 : : ]
  if 24 - 24: Ii1I . OOooOOo
  if 34 - 34: I11i % Oo0Ooo . II111iiii - OoO0O00 - I1Ii111 + Oo0Ooo
  if 71 - 71: O0 + OOooOOo % OoooooooOO
  if 51 - 51: I1ii11iIi11i * o0oOOo0O0Ooo * I11i
  if 27 - 27: OoOoOO00 % OoO0O00 * oO0o . II111iiii - i11iIiiIii
 packet . packet = iII1III11ii + oo0O00O0oO0OO
 return ( True )
 if 56 - 56: OOooOOo . IiII - OOooOOo / i11iIiiIii * I1ii11iIi11i
 if 66 - 66: oO0o + ooOoO0o
 if 1 - 1: ooOoO0o
# dd678faae9ac167bc83abf78e5cb2f3f0688d3a3
