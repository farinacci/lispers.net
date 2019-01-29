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
lisp_decent_configured = False
if 95 - 95: I1IiiI + i11iIiiIii
if 6 - 6: ooOoO0o / i11iIiiIii + iII111i * oO0o
if 80 - 80: II111iiii
if 83 - 83: I11i . i11iIiiIii + II111iiii . o0oOOo0O0Ooo * I11i
if 53 - 53: II111iiii
if 31 - 31: OoO0O00
lisp_ipc_socket = None
if 80 - 80: I1Ii111 . i11iIiiIii - o0oOOo0O0Ooo
if 25 - 25: OoO0O00
if 62 - 62: OOooOOo + O0
if 98 - 98: o0oOOo0O0Ooo
lisp_ms_encryption_keys = { }
if 51 - 51: Oo0Ooo - oO0o + II111iiii * Ii1I . I11i + oO0o
if 78 - 78: i11iIiiIii / iII111i - Ii1I / OOooOOo + oO0o
if 82 - 82: Ii1I
if 46 - 46: OoooooooOO . i11iIiiIii
if 94 - 94: o0oOOo0O0Ooo * Ii1I / Oo0Ooo / Ii1I
if 87 - 87: Oo0Ooo . IiII
LISP_DATA_PORT = 4341
LISP_CTRL_PORT = 4342
LISP_L2_DATA_PORT = 8472
LISP_VXLAN_DATA_PORT = 4789
LISP_VXLAN_GPE_PORT = 4790
if 75 - 75: ooOoO0o + OoOoOO00 + o0oOOo0O0Ooo * I11i % oO0o . iII111i
if 55 - 55: OOooOOo . I1IiiI
if 61 - 61: Oo0Ooo % IiII . Oo0Ooo
if 100 - 100: I1Ii111 * O0
LISP_MAP_REQUEST = 1
LISP_MAP_REPLY = 2
LISP_MAP_REGISTER = 3
LISP_MAP_NOTIFY = 4
LISP_MAP_NOTIFY_ACK = 5
LISP_MAP_REFERRAL = 6
LISP_NAT_INFO = 7
LISP_ECM = 8
if 64 - 64: OOooOOo % iIii1I11I1II1 * oO0o
if 79 - 79: O0
if 78 - 78: I1ii11iIi11i + OOooOOo - I1Ii111
if 38 - 38: o0oOOo0O0Ooo - oO0o + iIii1I11I1II1 / OoOoOO00 % Oo0Ooo
LISP_NO_ACTION = 0
LISP_NATIVE_FORWARD_ACTION = 1
LISP_SEND_MAP_REQUEST_ACTION = 2
LISP_DROP_ACTION = 3
LISP_POLICY_DENIED_ACTION = 4
LISP_AUTH_FAILURE_ACTION = 5
if 57 - 57: OoO0O00 / ooOoO0o
lisp_map_reply_action_string = [ "no-action" , "native-forward" ,
 "send-map-request" , "drop-action" , "policy-denied" , "auth-failure" ]
if 29 - 29: iIii1I11I1II1 + OoOoOO00 * OoO0O00 * OOooOOo . I1IiiI * I1IiiI
if 7 - 7: IiII * I1Ii111 % Ii1I - o0oOOo0O0Ooo
if 13 - 13: Ii1I . i11iIiiIii
if 56 - 56: I1ii11iIi11i % O0 - I1IiiI
LISP_NONE_ALG_ID = 0
LISP_SHA_1_96_ALG_ID = 1
LISP_SHA_256_128_ALG_ID = 2
LISP_MD5_AUTH_DATA_LEN = 16
LISP_SHA1_160_AUTH_DATA_LEN = 20
LISP_SHA2_256_AUTH_DATA_LEN = 32
if 100 - 100: Ii1I - O0 % oO0o * OOooOOo + I1IiiI
if 88 - 88: OoooooooOO - OoO0O00 * O0 * OoooooooOO . OoooooooOO
if 33 - 33: I1Ii111 + iII111i * oO0o / iIii1I11I1II1 - I1IiiI
if 54 - 54: I1Ii111 / OOooOOo . oO0o % iII111i
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
if 57 - 57: i11iIiiIii . I1ii11iIi11i - Ii1I - oO0o + OoOoOO00
if 63 - 63: OoOoOO00 * iII111i
if 69 - 69: O0 . OoO0O00
if 49 - 49: I1IiiI - I11i
LISP_MR_TTL = ( 24 * 60 )
LISP_REGISTER_TTL = 3
LISP_SHORT_TTL = 1
LISP_NMR_TTL = 15
if 74 - 74: iIii1I11I1II1 * I1ii11iIi11i + OoOoOO00 / i1IIi / II111iiii . Oo0Ooo
LISP_SITE_TIMEOUT_CHECK_INTERVAL = 60
LISP_PUBSUB_TIMEOUT_CHECK_INTERVAL = 60
LISP_REFERRAL_TIMEOUT_CHECK_INTERVAL = 60
LISP_TEST_MR_INTERVAL = 60
LISP_MAP_NOTIFY_INTERVAL = 2
LISP_DDT_MAP_REQUEST_INTERVAL = 2
LISP_MAX_MAP_NOTIFY_RETRIES = 3
LISP_INFO_INTERVAL = 15
LISP_MAP_REQUEST_RATE_LIMIT = 5
if 62 - 62: OoooooooOO * I1IiiI
LISP_RLOC_PROBE_TTL = 64
LISP_RLOC_PROBE_INTERVAL = 10
LISP_RLOC_PROBE_REPLY_WAIT = 15
if 58 - 58: OoOoOO00 % o0oOOo0O0Ooo
LISP_DEFAULT_DYN_EID_TIMEOUT = 15
LISP_NONCE_ECHO_INTERVAL = 10
if 50 - 50: I1Ii111 . o0oOOo0O0Ooo
if 97 - 97: O0 + OoOoOO00
if 89 - 89: o0oOOo0O0Ooo + OoO0O00 * I11i * Ii1I
if 37 - 37: OoooooooOO - O0 - o0oOOo0O0Ooo
if 77 - 77: OOooOOo * iIii1I11I1II1
if 98 - 98: I1IiiI % Ii1I * OoooooooOO
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
LISP_CS_1024 = 0
LISP_CS_1024_G = 2
LISP_CS_1024_P = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF
if 42 - 42: Oo0Ooo
LISP_CS_2048_CBC = 1
LISP_CS_2048_CBC_G = 2
LISP_CS_2048_CBC_P = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF
if 76 - 76: I1IiiI * iII111i % I1Ii111
LISP_CS_25519_CBC = 2
LISP_CS_2048_GCM = 3
if 57 - 57: iIii1I11I1II1 - i1IIi / I1Ii111 - O0 * OoooooooOO % II111iiii
LISP_CS_3072 = 4
LISP_CS_3072_G = 2
LISP_CS_3072_P = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF
if 68 - 68: OoooooooOO * I11i % OoOoOO00 - IiII
LISP_CS_25519_GCM = 5
LISP_CS_25519_CHACHA = 6
if 34 - 34: I1Ii111 . iIii1I11I1II1 * OoOoOO00 * oO0o / I1Ii111 / I1ii11iIi11i
LISP_4_32_MASK = 0xFFFFFFFF
LISP_8_64_MASK = 0xFFFFFFFFFFFFFFFF
LISP_16_128_MASK = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
if 78 - 78: Oo0Ooo - o0oOOo0O0Ooo / OoOoOO00
if 10 - 10: iII111i + Oo0Ooo * I1ii11iIi11i + iIii1I11I1II1 / I1Ii111 / I1ii11iIi11i
if 42 - 42: I1IiiI
if 38 - 38: OOooOOo + II111iiii % ooOoO0o % OoOoOO00 - Ii1I / OoooooooOO
if 73 - 73: o0oOOo0O0Ooo * O0 - i11iIiiIii
if 85 - 85: Ii1I % iII111i + I11i / o0oOOo0O0Ooo . oO0o + OOooOOo
if 62 - 62: i11iIiiIii + i11iIiiIii - o0oOOo0O0Ooo
if 28 - 28: iII111i . iII111i % iIii1I11I1II1 * iIii1I11I1II1 . o0oOOo0O0Ooo / iII111i
def lisp_record_traceback ( * args ) :
 iII1i1 = datetime . datetime . now ( ) . strftime ( "%m/%d/%y %H:%M:%S.%f" ) [ : - 3 ]
 O0oOOoooOO0O = open ( "./logs/lisp-traceback.log" , "a" )
 O0oOOoooOO0O . write ( "---------- Exception occurred: {} ----------\n" . format ( iII1i1 ) )
 try :
  traceback . print_last ( file = O0oOOoooOO0O )
 except :
  O0oOOoooOO0O . write ( "traceback.print_last(file=fd) failed" )
  if 86 - 86: o0oOOo0O0Ooo
 try :
  traceback . print_last ( )
 except :
  print ( "traceback.print_last() failed" )
  if 5 - 5: IiII * OoOoOO00
 O0oOOoooOO0O . close ( )
 return
 if 5 - 5: I1Ii111
 if 90 - 90: I1Ii111 . ooOoO0o / Ii1I - I11i
 if 40 - 40: OoooooooOO
 if 25 - 25: IiII + Ii1I / ooOoO0o . o0oOOo0O0Ooo % O0 * OoO0O00
 if 84 - 84: ooOoO0o % Ii1I + i11iIiiIii
 if 28 - 28: Oo0Ooo + OoO0O00 * OOooOOo % oO0o . I11i % O0
 if 16 - 16: I11i - iIii1I11I1II1 / I1IiiI . II111iiii + iIii1I11I1II1
def lisp_set_exception ( ) :
 sys . excepthook = lisp_record_traceback
 return
 if 19 - 19: OoO0O00 - Oo0Ooo . O0
 if 60 - 60: II111iiii + Oo0Ooo
 if 9 - 9: ooOoO0o * OoooooooOO - iIii1I11I1II1 + OoOoOO00 / OoO0O00 . OoO0O00
 if 49 - 49: II111iiii
 if 25 - 25: OoooooooOO - I1IiiI . I1IiiI * oO0o
 if 81 - 81: iII111i + IiII
 if 98 - 98: I1IiiI
def lisp_is_raspbian ( ) :
 if ( platform . dist ( ) [ 0 ] != "debian" ) : return ( False )
 return ( platform . machine ( ) in [ "armv6l" , "armv7l" ] )
 if 95 - 95: ooOoO0o / ooOoO0o
 if 30 - 30: I1ii11iIi11i + Oo0Ooo / Oo0Ooo % I1ii11iIi11i . I1ii11iIi11i
 if 55 - 55: ooOoO0o - I11i + II111iiii + iII111i % Ii1I
 if 41 - 41: i1IIi - I11i - Ii1I
 if 8 - 8: OoO0O00 + I1Ii111 - o0oOOo0O0Ooo % Oo0Ooo % o0oOOo0O0Ooo * oO0o
 if 9 - 9: Oo0Ooo - i11iIiiIii - OOooOOo * Ii1I + ooOoO0o
 if 44 - 44: II111iiii
def lisp_is_ubuntu ( ) :
 return ( platform . dist ( ) [ 0 ] == "Ubuntu" )
 if 52 - 52: I1ii11iIi11i - Oo0Ooo + I1ii11iIi11i % o0oOOo0O0Ooo
 if 35 - 35: iIii1I11I1II1
 if 42 - 42: I1Ii111 . I1IiiI . i1IIi + OoOoOO00 + OOooOOo + I1IiiI
 if 31 - 31: iII111i . OOooOOo - ooOoO0o . OoooooooOO / OoooooooOO
 if 56 - 56: OoO0O00 / oO0o / i11iIiiIii + OoooooooOO - Oo0Ooo - I11i
 if 21 - 21: O0 % IiII . I1IiiI / II111iiii + IiII
 if 53 - 53: oO0o - I1IiiI - oO0o * iII111i
def lisp_is_fedora ( ) :
 return ( platform . dist ( ) [ 0 ] == "fedora" )
 if 71 - 71: O0 - iIii1I11I1II1
 if 12 - 12: OOooOOo / o0oOOo0O0Ooo
 if 42 - 42: Oo0Ooo
 if 19 - 19: oO0o % I1ii11iIi11i * iIii1I11I1II1 + I1IiiI
 if 46 - 46: Oo0Ooo
 if 1 - 1: iII111i
 if 97 - 97: OOooOOo + iII111i + O0 + i11iIiiIii
def lisp_is_centos ( ) :
 return ( platform . dist ( ) [ 0 ] == "centos" )
 if 77 - 77: o0oOOo0O0Ooo / OoooooooOO
 if 46 - 46: o0oOOo0O0Ooo % iIii1I11I1II1 . iII111i % iII111i + i11iIiiIii
 if 72 - 72: iIii1I11I1II1 * Ii1I % ooOoO0o / OoO0O00
 if 35 - 35: ooOoO0o + i1IIi % I1ii11iIi11i % I11i + oO0o
 if 17 - 17: i1IIi
 if 21 - 21: Oo0Ooo
 if 29 - 29: I11i / II111iiii / ooOoO0o * OOooOOo
def lisp_is_debian ( ) :
 return ( platform . dist ( ) [ 0 ] == "debian" )
 if 10 - 10: I1Ii111 % IiII * IiII . I11i / Ii1I % OOooOOo
 if 49 - 49: OoO0O00 / oO0o + O0 * o0oOOo0O0Ooo
 if 28 - 28: ooOoO0o + i11iIiiIii / I11i % OoOoOO00 % Oo0Ooo - O0
 if 54 - 54: i1IIi + II111iiii
 if 83 - 83: I1ii11iIi11i - I1IiiI + OOooOOo
 if 5 - 5: Ii1I
 if 46 - 46: IiII
def lisp_is_debian_kali ( ) :
 return ( platform . dist ( ) [ 0 ] == "Kali" )
 if 45 - 45: ooOoO0o
 if 21 - 21: oO0o . I1Ii111 . OOooOOo / Oo0Ooo / I1Ii111
 if 17 - 17: OOooOOo / OOooOOo / I11i
 if 1 - 1: i1IIi . i11iIiiIii % OOooOOo
 if 82 - 82: iIii1I11I1II1 + Oo0Ooo . iIii1I11I1II1 % IiII / Ii1I . Ii1I
 if 14 - 14: o0oOOo0O0Ooo . OOooOOo . I11i + OoooooooOO - OOooOOo + IiII
 if 9 - 9: Ii1I
def lisp_is_macos ( ) :
 return ( platform . uname ( ) [ 0 ] == "Darwin" )
 if 59 - 59: I1IiiI * II111iiii . O0
 if 56 - 56: Ii1I - iII111i % I1IiiI - o0oOOo0O0Ooo
 if 51 - 51: O0 / ooOoO0o * iIii1I11I1II1 + I1ii11iIi11i + o0oOOo0O0Ooo
 if 98 - 98: iIii1I11I1II1 * I1ii11iIi11i * OOooOOo + ooOoO0o % i11iIiiIii % O0
 if 27 - 27: O0
 if 79 - 79: o0oOOo0O0Ooo - I11i + o0oOOo0O0Ooo . oO0o
 if 28 - 28: i1IIi - iII111i
def lisp_is_alpine ( ) :
 return ( os . path . exists ( "/etc/alpine-release" ) )
 if 54 - 54: iII111i - O0 % OOooOOo
 if 73 - 73: O0 . OoOoOO00 + I1IiiI - I11i % I11i . I11i
 if 17 - 17: Ii1I - OoooooooOO % Ii1I . IiII / i11iIiiIii % iII111i
 if 28 - 28: I11i
 if 58 - 58: OoOoOO00
 if 37 - 37: Oo0Ooo - iIii1I11I1II1 / I1ii11iIi11i
 if 73 - 73: i11iIiiIii - IiII
def lisp_is_x86 ( ) :
 ii11I1 = platform . machine ( )
 return ( ii11I1 in ( "x86" , "i686" , "x86_64" ) )
 if 75 - 75: OoO0O00 / II111iiii % O0
 if 38 - 38: OoooooooOO * ooOoO0o % O0 * OoOoOO00
 if 29 - 29: I1ii11iIi11i / i1IIi . I1IiiI - OoOoOO00 - OoOoOO00 - Ii1I
 if 20 - 20: i1IIi % OoO0O00 . I1IiiI / IiII * i11iIiiIii * OOooOOo
 if 85 - 85: o0oOOo0O0Ooo . OoOoOO00 / ooOoO0o . O0 % I1Ii111
 if 90 - 90: Oo0Ooo % O0 * iIii1I11I1II1 . iII111i
 if 8 - 8: ooOoO0o + II111iiii / iII111i / I11i
def lisp_is_linux ( ) :
 return ( platform . uname ( ) [ 0 ] == "Linux" )
 if 74 - 74: O0 / i1IIi
 if 78 - 78: OoooooooOO . OoO0O00 + ooOoO0o - i1IIi
 if 31 - 31: OoooooooOO . OOooOOo
 if 83 - 83: iII111i . O0 / Oo0Ooo / OOooOOo - II111iiii
 if 100 - 100: OoO0O00
 if 46 - 46: OoOoOO00 / iIii1I11I1II1 % iII111i . iIii1I11I1II1 * iII111i
 if 38 - 38: I1ii11iIi11i - iII111i / O0 . I1Ii111
 if 45 - 45: I1Ii111
def lisp_process_logfile ( ) :
 oO = "./logs/lisp-{}.log" . format ( lisp_log_id )
 if ( os . path . exists ( oO ) ) : return
 if 17 - 17: Oo0Ooo % OOooOOo . i1IIi / OoooooooOO
 sys . stdout . close ( )
 sys . stdout = open ( oO , "a" )
 if 28 - 28: oO0o . II111iiii / I1ii11iIi11i + II111iiii . OoooooooOO . IiII
 lisp_print_banner ( bold ( "logfile rotation" , False ) )
 return
 if 53 - 53: Ii1I % Ii1I * o0oOOo0O0Ooo + OoOoOO00
 if 92 - 92: OoooooooOO + i1IIi / Ii1I * O0
 if 100 - 100: ooOoO0o % iIii1I11I1II1 * II111iiii - iII111i
 if 92 - 92: ooOoO0o
 if 22 - 22: Oo0Ooo % iII111i * I1ii11iIi11i / OOooOOo % i11iIiiIii * I11i
 if 95 - 95: OoooooooOO - IiII * I1IiiI + OoOoOO00
 if 10 - 10: o0oOOo0O0Ooo / i11iIiiIii
 if 92 - 92: I11i . I1Ii111
def lisp_i_am ( name ) :
 global lisp_log_id , lisp_i_am_itr , lisp_i_am_etr , lisp_i_am_rtr
 global lisp_i_am_mr , lisp_i_am_ms , lisp_i_am_ddt , lisp_i_am_core
 global lisp_hostname
 if 85 - 85: I1ii11iIi11i . I1Ii111
 lisp_log_id = name
 if ( name == "itr" ) : lisp_i_am_itr = True
 if ( name == "etr" ) : lisp_i_am_etr = True
 if ( name == "rtr" ) : lisp_i_am_rtr = True
 if ( name == "mr" ) : lisp_i_am_mr = True
 if ( name == "ms" ) : lisp_i_am_ms = True
 if ( name == "ddt" ) : lisp_i_am_ddt = True
 if ( name == "core" ) : lisp_i_am_core = True
 if 78 - 78: ooOoO0o * I1Ii111 + iIii1I11I1II1 + iIii1I11I1II1 / I1Ii111 . Ii1I
 if 97 - 97: ooOoO0o / I1Ii111 % i1IIi % I1ii11iIi11i
 if 18 - 18: iIii1I11I1II1 % I11i
 if 95 - 95: ooOoO0o + i11iIiiIii * I1Ii111 - i1IIi * I1Ii111 - iIii1I11I1II1
 if 75 - 75: OoooooooOO * IiII
 lisp_hostname = socket . gethostname ( )
 I1Iiiiiii = lisp_hostname . find ( "." )
 if ( I1Iiiiiii != - 1 ) : lisp_hostname = lisp_hostname [ 0 : I1Iiiiiii ]
 return
 if 39 - 39: IiII * Oo0Ooo + iIii1I11I1II1 - IiII + OOooOOo
 if 69 - 69: O0
 if 85 - 85: ooOoO0o / O0
 if 18 - 18: o0oOOo0O0Ooo % O0 * I1ii11iIi11i
 if 62 - 62: I1Ii111 . IiII . OoooooooOO
 if 11 - 11: OOooOOo / I11i
 if 73 - 73: i1IIi / i11iIiiIii
def lprint ( * args ) :
 if ( lisp_debug_logging == False ) : return
 if 58 - 58: Oo0Ooo . II111iiii + oO0o - i11iIiiIii / II111iiii / O0
 lisp_process_logfile ( )
 iII1i1 = datetime . datetime . now ( ) . strftime ( "%m/%d/%y %H:%M:%S.%f" )
 iII1i1 = iII1i1 [ : - 3 ]
 print "{}: {}:" . format ( iII1i1 , lisp_log_id ) ,
 for oOOoOo in args : print oOOoOo ,
 print ""
 try : sys . stdout . flush ( )
 except : pass
 return
 if 89 - 89: II111iiii + i1IIi + II111iiii
 if 7 - 7: O0 % o0oOOo0O0Ooo + I1ii11iIi11i * iII111i - iII111i
 if 42 - 42: OoOoOO00 * OoOoOO00 * I1Ii111 . I11i
 if 51 - 51: OOooOOo % iIii1I11I1II1 - OoooooooOO % ooOoO0o * iIii1I11I1II1 % OoO0O00
 if 99 - 99: oO0o * II111iiii * I1Ii111
 if 92 - 92: Oo0Ooo
 if 40 - 40: OoOoOO00 / IiII
 if 79 - 79: OoO0O00 - iIii1I11I1II1 + Ii1I - I1Ii111
def dprint ( * args ) :
 if ( lisp_data_plane_logging ) : lprint ( * args )
 return
 if 93 - 93: II111iiii . I1IiiI - Oo0Ooo + OoOoOO00
 if 61 - 61: II111iiii
 if 15 - 15: i11iIiiIii % I1IiiI * I11i / I1Ii111
 if 90 - 90: iII111i
 if 31 - 31: OOooOOo + O0
 if 87 - 87: ooOoO0o
 if 45 - 45: OoO0O00 / OoooooooOO - iII111i / Ii1I % IiII
 if 83 - 83: I1IiiI . iIii1I11I1II1 - IiII * i11iIiiIii
def debug ( * args ) :
 lisp_process_logfile ( )
 if 20 - 20: i1IIi * I1Ii111 + II111iiii % o0oOOo0O0Ooo % oO0o
 iII1i1 = datetime . datetime . now ( ) . strftime ( "%m/%d/%y %H:%M:%S.%f" )
 iII1i1 = iII1i1 [ : - 3 ]
 if 13 - 13: Oo0Ooo
 print red ( ">>>" , False ) ,
 print "{}:" . format ( iII1i1 ) ,
 for oOOoOo in args : print oOOoOo ,
 print red ( "<<<\n" , False )
 try : sys . stdout . flush ( )
 except : pass
 return
 if 60 - 60: I1ii11iIi11i * I1IiiI
 if 17 - 17: OOooOOo % Oo0Ooo / I1ii11iIi11i . IiII * OOooOOo - II111iiii
 if 41 - 41: Ii1I
 if 77 - 77: I1Ii111
 if 65 - 65: II111iiii . I1IiiI % oO0o * OoO0O00
 if 38 - 38: OoOoOO00 / iII111i % Oo0Ooo
 if 11 - 11: iII111i - oO0o + II111iiii - iIii1I11I1II1
def lisp_print_banner ( string ) :
 global lisp_version , lisp_hostname
 if 7 - 7: IiII - I11i / II111iiii * Ii1I . iII111i * iII111i
 if ( lisp_version == "" ) :
  lisp_version = commands . getoutput ( "cat lisp-version.txt" )
  if 61 - 61: I11i % ooOoO0o - OoO0O00 / Oo0Ooo
 Ii1iI111 = bold ( lisp_hostname , False )
 lprint ( "lispers.net LISP {} {}, version {}, hostname {}" . format ( string ,
 datetime . datetime . now ( ) , lisp_version , Ii1iI111 ) )
 return
 if 51 - 51: IiII * O0 / II111iiii . Ii1I % OOooOOo / I1IiiI
 if 9 - 9: I1IiiI % I1IiiI % II111iiii
 if 30 - 30: IiII + I1Ii111 - IiII . IiII - II111iiii + O0
 if 86 - 86: i1IIi
 if 41 - 41: OoOoOO00 * I11i / OoOoOO00 % oO0o
 if 18 - 18: II111iiii . OoooooooOO % OoOoOO00 % Ii1I
 if 9 - 9: OoO0O00 - Oo0Ooo * OoooooooOO . Oo0Ooo
def green ( string , html ) :
 if ( html ) : return ( '<font color="green"><b>{}</b></font>' . format ( string ) )
 return ( bold ( "\033[92m" + string + "\033[0m" , html ) )
 if 2 - 2: OoooooooOO % OOooOOo
 if 63 - 63: I1IiiI % iIii1I11I1II1
 if 39 - 39: iII111i / II111iiii / I1ii11iIi11i % I1IiiI
 if 89 - 89: I1Ii111 + OoooooooOO + I1Ii111 * i1IIi + iIii1I11I1II1 % I11i
 if 59 - 59: OOooOOo + i11iIiiIii
 if 88 - 88: i11iIiiIii - ooOoO0o
 if 67 - 67: OOooOOo . Oo0Ooo + OoOoOO00 - OoooooooOO
def green_last_sec ( string ) :
 return ( green ( string , True ) )
 if 70 - 70: OOooOOo / II111iiii - iIii1I11I1II1 - iII111i
 if 11 - 11: iIii1I11I1II1 . OoooooooOO . II111iiii / i1IIi - I11i
 if 30 - 30: OoOoOO00
 if 21 - 21: i11iIiiIii / I1Ii111 % OOooOOo * O0 . I11i - iIii1I11I1II1
 if 26 - 26: II111iiii * OoOoOO00
 if 10 - 10: II111iiii . iII111i
 if 32 - 32: Ii1I . IiII . OoooooooOO - OoO0O00 + oO0o
def green_last_min ( string ) :
 return ( '<font color="#58D68D"><b>{}</b></font>' . format ( string ) )
 if 88 - 88: iII111i
 if 19 - 19: II111iiii * IiII + Ii1I
 if 65 - 65: OOooOOo . I1Ii111 . OoO0O00 . iII111i - OOooOOo
 if 19 - 19: i11iIiiIii + iII111i % ooOoO0o
 if 14 - 14: OoO0O00 . II111iiii . I11i / Ii1I % I1ii11iIi11i - ooOoO0o
 if 67 - 67: I11i - OOooOOo . i1IIi
 if 35 - 35: iII111i + ooOoO0o - oO0o . iII111i . IiII
def red ( string , html ) :
 if ( html ) : return ( '<font color="red"><b>{}</b></font>' . format ( string ) )
 return ( bold ( "\033[91m" + string + "\033[0m" , html ) )
 if 87 - 87: OoOoOO00
 if 25 - 25: i1IIi . OoO0O00 - OoOoOO00 / OoO0O00 % OoO0O00 * iIii1I11I1II1
 if 50 - 50: OoO0O00 . i11iIiiIii - oO0o . oO0o
 if 31 - 31: OOooOOo / Oo0Ooo * i1IIi . OoOoOO00
 if 57 - 57: OOooOOo + iIii1I11I1II1 % i1IIi % I1IiiI
 if 83 - 83: o0oOOo0O0Ooo / i11iIiiIii % iIii1I11I1II1 . I11i % oO0o . OoooooooOO
 if 94 - 94: Ii1I + iIii1I11I1II1 % OoO0O00
def blue ( string , html ) :
 if ( html ) : return ( '<font color="blue"><b>{}</b></font>' . format ( string ) )
 return ( bold ( "\033[94m" + string + "\033[0m" , html ) )
 if 93 - 93: Ii1I - OOooOOo + iIii1I11I1II1 * o0oOOo0O0Ooo + I1Ii111 . iII111i
 if 49 - 49: OoooooooOO * I11i - Oo0Ooo . oO0o
 if 89 - 89: ooOoO0o + Ii1I * ooOoO0o / ooOoO0o
 if 46 - 46: OoO0O00
 if 71 - 71: I11i / I11i * oO0o * oO0o / II111iiii
 if 35 - 35: OOooOOo * o0oOOo0O0Ooo * I1IiiI % Oo0Ooo . OoOoOO00
 if 58 - 58: I11i + II111iiii * iII111i * i11iIiiIii - iIii1I11I1II1
def bold ( string , html ) :
 if ( html ) : return ( "<b>{}</b>" . format ( string ) )
 return ( "\033[1m" + string + "\033[0m" )
 if 68 - 68: OoooooooOO % II111iiii
 if 26 - 26: II111iiii % i11iIiiIii % iIii1I11I1II1 % I11i * I11i * I1ii11iIi11i
 if 24 - 24: II111iiii % I1Ii111 - ooOoO0o + I1IiiI * I1ii11iIi11i
 if 2 - 2: Ii1I - IiII
 if 83 - 83: oO0o % o0oOOo0O0Ooo % Ii1I - II111iiii * OOooOOo / OoooooooOO
 if 18 - 18: OoO0O00 + iIii1I11I1II1 - II111iiii - I1IiiI
 if 71 - 71: OoooooooOO
def convert_font ( string ) :
 iIIIII1iiiiII = [ [ "[91m" , red ] , [ "[92m" , green ] , [ "[94m" , blue ] , [ "[1m" , bold ] ]
 oooO = "[0m"
 if 22 - 22: ooOoO0o - ooOoO0o % OOooOOo . I1Ii111 + oO0o
 for Oo00OOo00O in iIIIII1iiiiII :
  o0 = Oo00OOo00O [ 0 ]
  Ii1Iii111IiI1 = Oo00OOo00O [ 1 ]
  O00oOooo0 = len ( o0 )
  I1Iiiiiii = string . find ( o0 )
  if ( I1Iiiiiii != - 1 ) : break
  if 56 - 56: II111iiii / oO0o + i11iIiiIii + OOooOOo
  if 54 - 54: Ii1I - I11i - I1Ii111 . iIii1I11I1II1
 while ( I1Iiiiiii != - 1 ) :
  o0O = string [ I1Iiiiiii : : ] . find ( oooO )
  IIiI1I1 = string [ I1Iiiiiii + O00oOooo0 : I1Iiiiiii + o0O ]
  string = string [ : I1Iiiiiii ] + Ii1Iii111IiI1 ( IIiI1I1 , True ) + string [ I1Iiiiiii + o0O + O00oOooo0 : : ]
  if 15 - 15: Ii1I * Oo0Ooo % I1ii11iIi11i * iIii1I11I1II1 - i11iIiiIii
  I1Iiiiiii = string . find ( o0 )
  if 60 - 60: I1IiiI * I1Ii111 % OoO0O00 + oO0o
  if 52 - 52: i1IIi
  if 84 - 84: Ii1I / IiII
  if 86 - 86: OoOoOO00 * II111iiii - O0 . OoOoOO00 % iIii1I11I1II1 / OOooOOo
  if 11 - 11: I1IiiI * oO0o + I1ii11iIi11i / I1ii11iIi11i
 if ( string . find ( "[1m" ) != - 1 ) : string = convert_font ( string )
 return ( string )
 if 37 - 37: i11iIiiIii + i1IIi
 if 23 - 23: iII111i + I11i . OoOoOO00 * I1IiiI + I1ii11iIi11i
 if 18 - 18: IiII * o0oOOo0O0Ooo . IiII / O0
 if 8 - 8: o0oOOo0O0Ooo
 if 4 - 4: I1ii11iIi11i + I1ii11iIi11i * ooOoO0o - OoOoOO00
 if 78 - 78: Ii1I / II111iiii % OoOoOO00
 if 52 - 52: OOooOOo - iII111i * oO0o
def lisp_space ( num ) :
 Ii1I11I = ""
 for iiIii1I in range ( num ) : Ii1I11I += "&#160;"
 return ( Ii1I11I )
 if 47 - 47: ooOoO0o . I11i / o0oOOo0O0Ooo
 if 83 - 83: o0oOOo0O0Ooo / OOooOOo / OOooOOo + o0oOOo0O0Ooo * I1Ii111 + o0oOOo0O0Ooo
 if 36 - 36: OoOoOO00 + o0oOOo0O0Ooo - OoooooooOO . oO0o . OoooooooOO / Oo0Ooo
 if 72 - 72: i1IIi
 if 82 - 82: OoOoOO00 + OoooooooOO / i11iIiiIii * I1ii11iIi11i . OoooooooOO
 if 63 - 63: I1ii11iIi11i
 if 6 - 6: ooOoO0o / I1ii11iIi11i
def lisp_button ( string , url ) :
 oOooO00o0O = '<button style="background-color:transparent;border-radius:10px; ' + 'type="button">'
 if 80 - 80: OOooOOo / I11i / OoOoOO00 + i1IIi - Oo0Ooo
 if 11 - 11: o0oOOo0O0Ooo * OoO0O00
 if ( url == None ) :
  iIi1IiI = oOooO00o0O + string + "</button>"
 else :
  I11IIIiIi11 = '<a href="{}">' . format ( url )
  I11iiIi1i1 = lisp_space ( 2 )
  iIi1IiI = I11iiIi1i1 + I11IIIiIi11 + oOooO00o0O + string + "</button></a>" + I11iiIi1i1
  if 41 - 41: Ii1I % I1ii11iIi11i
 return ( iIi1IiI )
 if 12 - 12: OOooOOo
 if 69 - 69: OoooooooOO + OOooOOo
 if 26 - 26: Oo0Ooo + OOooOOo / OoO0O00 % OoOoOO00 % I1ii11iIi11i + II111iiii
 if 31 - 31: I11i % OOooOOo * I11i
 if 45 - 45: i1IIi . I1IiiI + OOooOOo - OoooooooOO % ooOoO0o
 if 1 - 1: iIii1I11I1II1
 if 93 - 93: i1IIi . i11iIiiIii . Oo0Ooo
def lisp_print_cour ( string ) :
 Ii1I11I = '<font face="Courier New">{}</font>' . format ( string )
 return ( Ii1I11I )
 if 99 - 99: I11i - I1Ii111 - oO0o % OoO0O00
 if 21 - 21: II111iiii % I1ii11iIi11i . i1IIi - OoooooooOO
 if 4 - 4: OoooooooOO . ooOoO0o
 if 78 - 78: I1ii11iIi11i + I11i - O0
 if 10 - 10: I1Ii111 % I1IiiI
 if 97 - 97: OoooooooOO - I1Ii111
 if 58 - 58: iIii1I11I1II1 + O0
def lisp_print_sans ( string ) :
 Ii1I11I = '<font face="Sans-Serif">{}</font>' . format ( string )
 return ( Ii1I11I )
 if 30 - 30: ooOoO0o % iII111i * OOooOOo - I1ii11iIi11i * Ii1I % ooOoO0o
 if 46 - 46: i11iIiiIii - O0 . oO0o
 if 100 - 100: I1IiiI / o0oOOo0O0Ooo * iII111i . O0 / OOooOOo
 if 83 - 83: I1Ii111
 if 48 - 48: II111iiii * OOooOOo * I1Ii111
 if 50 - 50: IiII % i1IIi
 if 21 - 21: OoooooooOO - iIii1I11I1II1
def lisp_span ( string , hover_string ) :
 Ii1I11I = '<span title="{}">{}</span>' . format ( hover_string , string )
 return ( Ii1I11I )
 if 93 - 93: oO0o - o0oOOo0O0Ooo % OoOoOO00 . OoOoOO00 - ooOoO0o
 if 90 - 90: ooOoO0o + II111iiii * I1ii11iIi11i / Ii1I . o0oOOo0O0Ooo + o0oOOo0O0Ooo
 if 40 - 40: ooOoO0o / OoOoOO00 % i11iIiiIii % I1ii11iIi11i / I1IiiI
 if 62 - 62: i1IIi - OoOoOO00
 if 62 - 62: i1IIi + Oo0Ooo % IiII
 if 28 - 28: I1ii11iIi11i . i1IIi
 if 10 - 10: OoO0O00 / Oo0Ooo
def lisp_eid_help_hover ( output ) :
 I1i = '''Unicast EID format:
  For longest match lookups: 
    <address> or [<iid>]<address>
  For exact match lookups: 
    <prefix> or [<iid>]<prefix>
Multicast EID format:
  For longest match lookups:
    <address>-><group> or
    [<iid>]<address>->[<iid>]<group>'''
 if 50 - 50: o0oOOo0O0Ooo * Ii1I % I1ii11iIi11i / Oo0Ooo - O0 % iII111i
 if 48 - 48: I1IiiI + I1ii11iIi11i + II111iiii * i11iIiiIii
 IiIIi1I1I11Ii = lisp_span ( output , I1i )
 return ( IiIIi1I1I11Ii )
 if 64 - 64: OoooooooOO
 if 81 - 81: I1ii11iIi11i - O0 * OoooooooOO
 if 23 - 23: II111iiii / oO0o
 if 28 - 28: Oo0Ooo * ooOoO0o - OoO0O00
 if 19 - 19: I11i
 if 67 - 67: O0 % iIii1I11I1II1 / IiII . i11iIiiIii - Ii1I + O0
 if 27 - 27: OOooOOo
def lisp_geo_help_hover ( output ) :
 I1i = '''EID format:
    <address> or [<iid>]<address>
    '<name>' or [<iid>]'<name>'
Geo-Point format:
    d-m-s-<N|S>-d-m-s-<W|E> or 
    [<iid>]d-m-s-<N|S>-d-m-s-<W|E>
Geo-Prefix format:
    d-m-s-<N|S>-d-m-s-<W|E>/<km> or
    [<iid>]d-m-s-<N|S>-d-m-s-<W|E>/<km>'''
 if 89 - 89: II111iiii / oO0o
 if 14 - 14: OOooOOo . I1IiiI * ooOoO0o + II111iiii - ooOoO0o + OOooOOo
 IiIIi1I1I11Ii = lisp_span ( output , I1i )
 return ( IiIIi1I1I11Ii )
 if 18 - 18: oO0o - o0oOOo0O0Ooo - I1IiiI - I1IiiI
 if 54 - 54: Oo0Ooo + I1IiiI / iII111i . I1IiiI * OoOoOO00
 if 1 - 1: OoOoOO00 * OoO0O00 . i1IIi / Oo0Ooo . I1ii11iIi11i + Oo0Ooo
 if 17 - 17: Oo0Ooo + OoO0O00 / Ii1I / iII111i * OOooOOo
 if 29 - 29: OoO0O00 % OoooooooOO * oO0o / II111iiii - oO0o
 if 19 - 19: i11iIiiIii
 if 54 - 54: II111iiii . I11i
def space ( num ) :
 Ii1I11I = ""
 for iiIii1I in range ( num ) : Ii1I11I += "&#160;"
 return ( Ii1I11I )
 if 73 - 73: OoOoOO00 . I1IiiI
 if 32 - 32: OoOoOO00 * I1IiiI % ooOoO0o * Ii1I . O0
 if 48 - 48: iII111i * iII111i
 if 13 - 13: Ii1I / I11i + OoOoOO00 . o0oOOo0O0Ooo % ooOoO0o
 if 48 - 48: I1IiiI / i11iIiiIii - o0oOOo0O0Ooo * oO0o / OoooooooOO
 if 89 - 89: iIii1I11I1II1 / I1IiiI - II111iiii / Ii1I . i11iIiiIii . Ii1I
 if 48 - 48: O0 + O0 . I1Ii111 - ooOoO0o
 if 63 - 63: oO0o
def lisp_get_ephemeral_port ( ) :
 return ( random . randrange ( 32768 , 65535 ) )
 if 71 - 71: i1IIi . Ii1I * iII111i % OoooooooOO + OOooOOo
 if 36 - 36: IiII
 if 49 - 49: OOooOOo / OoooooooOO / I1IiiI
 if 74 - 74: I1Ii111 % I1ii11iIi11i
 if 7 - 7: II111iiii
 if 27 - 27: oO0o . OoooooooOO + i11iIiiIii
 if 86 - 86: I11i / o0oOOo0O0Ooo - o0oOOo0O0Ooo + I1ii11iIi11i + oO0o
def lisp_get_data_nonce ( ) :
 return ( random . randint ( 0 , 0xffffff ) )
 if 33 - 33: o0oOOo0O0Ooo . iII111i . IiII . i1IIi
 if 49 - 49: I1ii11iIi11i
 if 84 - 84: I11i - Oo0Ooo / O0 - I1Ii111
 if 21 - 21: O0 * O0 % I1ii11iIi11i
 if 94 - 94: I11i + II111iiii % i11iIiiIii
 if 8 - 8: ooOoO0o * O0
 if 73 - 73: o0oOOo0O0Ooo / oO0o / I11i / OoO0O00
def lisp_get_control_nonce ( ) :
 return ( random . randint ( 0 , ( 2 ** 64 ) - 1 ) )
 if 11 - 11: OoOoOO00 + IiII - OoooooooOO / OoO0O00
 if 34 - 34: ooOoO0o
 if 45 - 45: ooOoO0o / Oo0Ooo / Ii1I
 if 44 - 44: I1ii11iIi11i - Ii1I / II111iiii * OoO0O00 * Oo0Ooo
 if 73 - 73: o0oOOo0O0Ooo - I1IiiI * i1IIi / i11iIiiIii * OOooOOo % II111iiii
 if 56 - 56: OoooooooOO * Oo0Ooo . Oo0Ooo . I1ii11iIi11i
 if 24 - 24: Oo0Ooo . I11i * Ii1I % iII111i / OOooOOo
 if 58 - 58: I1IiiI - I1ii11iIi11i % O0 . I1IiiI % OoO0O00 % IiII
 if 87 - 87: oO0o - i11iIiiIii
def lisp_hex_string ( integer_value ) :
 ooOoO = hex ( integer_value ) [ 2 : : ]
 if ( ooOoO [ - 1 ] == "L" ) : ooOoO = ooOoO [ 0 : - 1 ]
 return ( ooOoO )
 if 23 - 23: I11i
 if 40 - 40: o0oOOo0O0Ooo - II111iiii / Oo0Ooo
 if 14 - 14: I1ii11iIi11i
 if 5 - 5: o0oOOo0O0Ooo . iIii1I11I1II1 % iIii1I11I1II1
 if 56 - 56: OoooooooOO - I11i - i1IIi
 if 8 - 8: I1Ii111 / OOooOOo . I1IiiI + I1ii11iIi11i / i11iIiiIii
 if 31 - 31: ooOoO0o - iIii1I11I1II1 + iII111i . Oo0Ooo / IiII % iIii1I11I1II1
def lisp_get_timestamp ( ) :
 return ( time . time ( ) )
 if 6 - 6: IiII * i11iIiiIii % iIii1I11I1II1 % i11iIiiIii + o0oOOo0O0Ooo / i1IIi
 if 53 - 53: I11i + iIii1I11I1II1
 if 70 - 70: I1ii11iIi11i
 if 67 - 67: OoooooooOO
 if 29 - 29: O0 - i11iIiiIii - II111iiii + OOooOOo * IiII
 if 2 - 2: i1IIi - ooOoO0o + I1IiiI . o0oOOo0O0Ooo * o0oOOo0O0Ooo / OoOoOO00
 if 93 - 93: i1IIi
def lisp_set_timestamp ( seconds ) :
 return ( time . time ( ) + seconds )
 if 53 - 53: OoooooooOO + Oo0Ooo + oO0o
 if 24 - 24: iII111i - IiII - iII111i * I1ii11iIi11i . OoooooooOO / IiII
 if 66 - 66: Oo0Ooo
 if 97 - 97: i1IIi - OoooooooOO / I1Ii111 * I1IiiI
 if 55 - 55: o0oOOo0O0Ooo . iII111i
 if 87 - 87: o0oOOo0O0Ooo % iIii1I11I1II1
 if 100 - 100: I1Ii111 . I1IiiI * I1Ii111 - I1IiiI . I11i * Ii1I
def lisp_print_elapsed ( ts ) :
 if ( ts == 0 or ts == None ) : return ( "never" )
 oO000o = time . time ( ) - ts
 oO000o = round ( oO000o , 0 )
 return ( str ( datetime . timedelta ( seconds = oO000o ) ) )
 if 78 - 78: OoooooooOO
 if 77 - 77: I1ii11iIi11i / i1IIi / Oo0Ooo % OOooOOo
 if 48 - 48: I11i - IiII + iIii1I11I1II1 + OoooooooOO
 if 4 - 4: II111iiii . I11i + Ii1I * I1Ii111 . ooOoO0o
 if 87 - 87: OoOoOO00 / OoO0O00 / i11iIiiIii
 if 74 - 74: oO0o / I1ii11iIi11i % o0oOOo0O0Ooo
 if 88 - 88: OoOoOO00 - i11iIiiIii % o0oOOo0O0Ooo * I11i + I1ii11iIi11i
def lisp_print_future ( ts ) :
 if ( ts == 0 ) : return ( "never" )
 Oo = ts - time . time ( )
 if ( Oo < 0 ) : return ( "expired" )
 Oo = round ( Oo , 0 )
 return ( str ( datetime . timedelta ( seconds = Oo ) ) )
 if 40 - 40: OoOoOO00 % OoO0O00
 if 62 - 62: o0oOOo0O0Ooo
 if 15 - 15: I11i + Ii1I . OOooOOo * OoO0O00 . OoOoOO00
 if 18 - 18: i1IIi % II111iiii + I1Ii111 % Ii1I
 if 72 - 72: iIii1I11I1II1
 if 45 - 45: Oo0Ooo - o0oOOo0O0Ooo % I1Ii111
 if 38 - 38: I1Ii111 % OOooOOo - OoooooooOO
 if 87 - 87: OoO0O00 % I1IiiI
 if 77 - 77: iIii1I11I1II1 - i1IIi . oO0o
 if 26 - 26: o0oOOo0O0Ooo * IiII . i1IIi
 if 59 - 59: O0 + i1IIi - o0oOOo0O0Ooo
 if 62 - 62: i11iIiiIii % OOooOOo . IiII . OOooOOo
 if 84 - 84: i11iIiiIii * OoO0O00
def lisp_print_eid_tuple ( eid , group ) :
 I1I1iII1i = eid . print_prefix ( )
 if ( group . is_null ( ) ) : return ( I1I1iII1i )
 if 30 - 30: O0 + I1ii11iIi11i + II111iiii
 III1I = group . print_prefix ( )
 I1I111iIi = group . instance_id
 if 53 - 53: iIii1I11I1II1 + o0oOOo0O0Ooo - OoOoOO00 - oO0o / ooOoO0o % i11iIiiIii
 if ( eid . is_null ( ) or eid . is_exact_match ( group ) ) :
  I1Iiiiiii = III1I . find ( "]" ) + 1
  return ( "[{}](*, {})" . format ( I1I111iIi , III1I [ I1Iiiiiii : : ] ) )
  if 3 - 3: iII111i . ooOoO0o % I1IiiI + I1ii11iIi11i
  if 64 - 64: i1IIi
 IIii1 = eid . print_sg ( group )
 return ( IIii1 )
 if 35 - 35: i11iIiiIii - I1IiiI / OOooOOo + Ii1I * oO0o
 if 49 - 49: o0oOOo0O0Ooo * Ii1I + I11i + iII111i
 if 30 - 30: o0oOOo0O0Ooo / OOooOOo / IiII % ooOoO0o + II111iiii
 if 4 - 4: iII111i - Oo0Ooo - IiII - I11i % i11iIiiIii / OoO0O00
 if 50 - 50: ooOoO0o + i1IIi
 if 31 - 31: Ii1I
 if 78 - 78: i11iIiiIii + o0oOOo0O0Ooo + I1Ii111 / o0oOOo0O0Ooo % iIii1I11I1II1 % IiII
 if 83 - 83: iIii1I11I1II1 % OoOoOO00 % o0oOOo0O0Ooo % I1Ii111 . I1ii11iIi11i % O0
def lisp_convert_6to4 ( addr_str ) :
 if ( addr_str . find ( "::ffff:" ) == - 1 ) : return ( addr_str )
 iIiIi1ii = addr_str . split ( ":" )
 return ( iIiIi1ii [ - 1 ] )
 if 28 - 28: iIii1I11I1II1 + iIii1I11I1II1
 if 28 - 28: oO0o
 if 52 - 52: I1IiiI + iIii1I11I1II1
 if 71 - 71: O0 / oO0o
 if 34 - 34: OoOoOO00 . iIii1I11I1II1 % O0
 if 43 - 43: I1ii11iIi11i - iII111i
 if 70 - 70: iII111i / OOooOOo % ooOoO0o - Ii1I
 if 47 - 47: iII111i
 if 92 - 92: OOooOOo + OoOoOO00 % i1IIi
 if 23 - 23: I1Ii111 - OOooOOo + Ii1I - OoOoOO00 * OoOoOO00 . Oo0Ooo
 if 47 - 47: oO0o % iIii1I11I1II1
def lisp_convert_4to6 ( addr_str ) :
 iIiIi1ii = lisp_address ( LISP_AFI_IPV6 , "" , 128 , 0 )
 if ( iIiIi1ii . is_ipv4_string ( addr_str ) ) : addr_str = "::ffff:" + addr_str
 iIiIi1ii . store_address ( addr_str )
 return ( iIiIi1ii )
 if 11 - 11: I1IiiI % Ii1I - OoO0O00 - oO0o + o0oOOo0O0Ooo
 if 98 - 98: iII111i + Ii1I - OoO0O00
 if 79 - 79: OOooOOo / I1Ii111 . OoOoOO00 - I1ii11iIi11i
 if 47 - 47: OoooooooOO % O0 * iII111i . Ii1I
 if 38 - 38: O0 - IiII % I1Ii111
 if 64 - 64: iIii1I11I1II1
 if 15 - 15: I1ii11iIi11i + OOooOOo / I1ii11iIi11i / I1Ii111
 if 31 - 31: ooOoO0o + O0 + ooOoO0o . iIii1I11I1II1 + Oo0Ooo / o0oOOo0O0Ooo
 if 6 - 6: Oo0Ooo % IiII * I11i / I1IiiI + Oo0Ooo
def lisp_gethostbyname ( string ) :
 IIiI11i11 = string . split ( "." )
 i1 = string . split ( ":" )
 iiIII1IIiIIII = string . split ( "-" )
 if 19 - 19: iII111i - o0oOOo0O0Ooo / o0oOOo0O0Ooo + Oo0Ooo
 if ( len ( IIiI11i11 ) > 1 ) :
  if ( IIiI11i11 [ 0 ] . isdigit ( ) ) : return ( string )
  if 98 - 98: iIii1I11I1II1 % OOooOOo + I11i . ooOoO0o
 if ( len ( i1 ) > 1 ) :
  try :
   int ( i1 [ 0 ] , 16 )
   return ( string )
  except :
   pass
   if 99 - 99: O0 + O0 * I11i + O0 * oO0o
   if 80 - 80: I1IiiI . Ii1I
   if 47 - 47: I11i + ooOoO0o + II111iiii % i11iIiiIii
   if 93 - 93: I1ii11iIi11i % OoOoOO00 . O0 / iII111i * oO0o
   if 29 - 29: o0oOOo0O0Ooo
   if 86 - 86: II111iiii . IiII
   if 2 - 2: OoooooooOO
 if ( len ( iiIII1IIiIIII ) == 3 ) :
  for iiIii1I in range ( 3 ) :
   try : int ( iiIII1IIiIIII [ iiIii1I ] , 16 )
   except : break
   if 60 - 60: OoO0O00
   if 81 - 81: OoOoOO00 % Ii1I
   if 87 - 87: iIii1I11I1II1 . OoooooooOO * OoOoOO00
 try :
  iIiIi1ii = socket . gethostbyname ( string )
  return ( iIiIi1ii )
 except :
  if ( lisp_is_alpine ( ) == False ) : return ( "" )
  if 100 - 100: OoO0O00 / i1IIi - I1IiiI % Ii1I - iIii1I11I1II1
  if 17 - 17: I11i / o0oOOo0O0Ooo % Oo0Ooo
  if 71 - 71: IiII . I1Ii111 . OoO0O00
  if 68 - 68: i11iIiiIii % oO0o * OoO0O00 * IiII * II111iiii + O0
  if 66 - 66: I11i % I1ii11iIi11i % OoooooooOO
 try :
  iIiIi1ii = socket . getaddrinfo ( string , 0 ) [ 0 ]
  if ( iIiIi1ii [ 3 ] != string ) : return ( "" )
  iIiIi1ii = iIiIi1ii [ 4 ] [ 0 ]
 except :
  iIiIi1ii = ""
  if 34 - 34: o0oOOo0O0Ooo / iII111i % O0 . OoO0O00 . i1IIi
 return ( iIiIi1ii )
 if 29 - 29: O0 . I1Ii111
 if 66 - 66: oO0o * iIii1I11I1II1 % iIii1I11I1II1 * IiII - ooOoO0o - IiII
 if 70 - 70: I1Ii111 + oO0o
 if 93 - 93: I1Ii111 + Ii1I
 if 33 - 33: O0
 if 78 - 78: O0 / II111iiii * OoO0O00
 if 50 - 50: OoooooooOO - iIii1I11I1II1 + i1IIi % I1Ii111 - iIii1I11I1II1 % O0
 if 58 - 58: IiII + iIii1I11I1II1
def lisp_ip_checksum ( data ) :
 if ( len ( data ) < 20 ) :
  lprint ( "IPv4 packet too short, length {}" . format ( len ( data ) ) )
  return ( data )
  if 65 - 65: II111iiii - I1Ii111 % o0oOOo0O0Ooo - OoOoOO00 * iII111i + Ii1I
  if 79 - 79: ooOoO0o . OoOoOO00 % I1Ii111 - Oo0Ooo
 o0oO0oO0O = binascii . hexlify ( data )
 if 18 - 18: Oo0Ooo
 if 20 - 20: oO0o * O0 + I11i - OoooooooOO . I11i
 if 60 - 60: o0oOOo0O0Ooo . o0oOOo0O0Ooo / iII111i
 if 45 - 45: O0 . i11iIiiIii % iII111i . OoOoOO00 % IiII % iIii1I11I1II1
 Oooo0oooo0OoO0o = 0
 for iiIii1I in range ( 0 , 40 , 4 ) :
  Oooo0oooo0OoO0o += int ( o0oO0oO0O [ iiIii1I : iiIii1I + 4 ] , 16 )
  if 50 - 50: iII111i / iII111i + OOooOOo * ooOoO0o / I1ii11iIi11i
  if 14 - 14: Ii1I % I1IiiI - iIii1I11I1II1 . OOooOOo + OoO0O00 - I1Ii111
  if 5 - 5: iII111i
  if 62 - 62: OoOoOO00 . OoooooooOO . OOooOOo . OoO0O00 * iII111i
  if 78 - 78: oO0o / OoO0O00 - oO0o * OoooooooOO . OoOoOO00
 Oooo0oooo0OoO0o = ( Oooo0oooo0OoO0o >> 16 ) + ( Oooo0oooo0OoO0o & 0xffff )
 Oooo0oooo0OoO0o += Oooo0oooo0OoO0o >> 16
 Oooo0oooo0OoO0o = socket . htons ( ~ Oooo0oooo0OoO0o & 0xffff )
 if 96 - 96: I1IiiI % i1IIi . o0oOOo0O0Ooo . O0
 if 37 - 37: i1IIi - OOooOOo % OoooooooOO / OOooOOo % ooOoO0o
 if 48 - 48: i11iIiiIii % oO0o
 if 29 - 29: iII111i + i11iIiiIii % I11i
 Oooo0oooo0OoO0o = struct . pack ( "H" , Oooo0oooo0OoO0o )
 o0oO0oO0O = data [ 0 : 10 ] + Oooo0oooo0OoO0o + data [ 12 : : ]
 return ( o0oO0oO0O )
 if 93 - 93: OoOoOO00 % iIii1I11I1II1
 if 90 - 90: I1IiiI - OOooOOo / Ii1I / O0 / I11i
 if 87 - 87: OoOoOO00 / IiII + iIii1I11I1II1
 if 93 - 93: iIii1I11I1II1 + oO0o % ooOoO0o
 if 21 - 21: OOooOOo
 if 6 - 6: IiII
 if 46 - 46: IiII + oO0o
def lisp_get_interface_address ( device ) :
 if 79 - 79: OoooooooOO - IiII * IiII . OoOoOO00
 if 100 - 100: II111iiii * I11i % I1IiiI / I1ii11iIi11i
 if 90 - 90: I1ii11iIi11i . ooOoO0o . OoOoOO00 . Ii1I
 if 4 - 4: Ii1I + OoOoOO00 % I1ii11iIi11i / i11iIiiIii
 if ( device not in netifaces . interfaces ( ) ) : return ( None )
 if 74 - 74: II111iiii . O0 - I1IiiI + IiII % i11iIiiIii % OoOoOO00
 if 78 - 78: Ii1I + OoOoOO00 + IiII - IiII . i11iIiiIii / OoO0O00
 if 27 - 27: Ii1I - O0 % I11i * I1Ii111 . IiII % iIii1I11I1II1
 if 37 - 37: OoooooooOO + O0 - i1IIi % ooOoO0o
 i1I1i1i = netifaces . ifaddresses ( device )
 if ( i1I1i1i . has_key ( netifaces . AF_INET ) == False ) : return ( None )
 if 36 - 36: II111iiii % O0
 if 35 - 35: iIii1I11I1II1 - OOooOOo % o0oOOo0O0Ooo
 if 30 - 30: I1Ii111 % I1Ii111 % IiII . OoOoOO00
 if 9 - 9: ooOoO0o / II111iiii . OoOoOO00 % o0oOOo0O0Ooo * II111iiii - ooOoO0o
 oOOoo0 = lisp_address ( LISP_AFI_IPV4 , "" , 32 , 0 )
 if 24 - 24: OoO0O00 - oO0o + I1ii11iIi11i / iII111i % I1IiiI + iIii1I11I1II1
 for iIiIi1ii in i1I1i1i [ netifaces . AF_INET ] :
  oO00o = iIiIi1ii [ "addr" ]
  oOOoo0 . store_address ( oO00o )
  return ( oOOoo0 )
  if 36 - 36: I1Ii111 . II111iiii % ooOoO0o
 return ( None )
 if 84 - 84: OoooooooOO - i11iIiiIii / iIii1I11I1II1 / OoooooooOO / I1ii11iIi11i
 if 4 - 4: Oo0Ooo + o0oOOo0O0Ooo
 if 17 - 17: OoO0O00 * OoOoOO00
 if 15 - 15: i11iIiiIii / ooOoO0o % I1IiiI
 if 71 - 71: I1Ii111 / I1ii11iIi11i * iIii1I11I1II1
 if 57 - 57: OOooOOo + I1Ii111 % I1ii11iIi11i . OoO0O00 / OoO0O00 * O0
 if 6 - 6: i1IIi - II111iiii * o0oOOo0O0Ooo . OoO0O00
 if 68 - 68: o0oOOo0O0Ooo
 if 20 - 20: I1Ii111 - I1Ii111
 if 37 - 37: IiII
 if 37 - 37: Oo0Ooo / IiII * O0
 if 73 - 73: iII111i * iII111i / ooOoO0o
def lisp_get_input_interface ( packet ) :
 IIi = lisp_format_packet ( packet [ 0 : 12 ] ) . replace ( " " , "" )
 i1i11iI1II11 = IIi [ 0 : 12 ]
 iIi11i = IIi [ 12 : : ]
 if 56 - 56: i11iIiiIii . ooOoO0o / iII111i
 try : III1iii1i1II = lisp_mymacs . has_key ( iIi11i )
 except : III1iii1i1II = False
 if 87 - 87: OOooOOo + o0oOOo0O0Ooo . iII111i - OoooooooOO
 if ( lisp_mymacs . has_key ( i1i11iI1II11 ) ) : return ( lisp_mymacs [ i1i11iI1II11 ] , iIi11i , i1i11iI1II11 , III1iii1i1II )
 if ( III1iii1i1II ) : return ( lisp_mymacs [ iIi11i ] , iIi11i , i1i11iI1II11 , III1iii1i1II )
 return ( [ "?" ] , iIi11i , i1i11iI1II11 , III1iii1i1II )
 if 6 - 6: iIii1I11I1II1 * OoooooooOO
 if 28 - 28: Oo0Ooo * o0oOOo0O0Ooo / I1Ii111
 if 52 - 52: O0 / o0oOOo0O0Ooo % iII111i * I1IiiI % OOooOOo
 if 69 - 69: I1ii11iIi11i
 if 83 - 83: o0oOOo0O0Ooo
 if 38 - 38: I1Ii111 + OoooooooOO . i1IIi
 if 19 - 19: iII111i - o0oOOo0O0Ooo - Ii1I - OoOoOO00 . iII111i . I1Ii111
 if 48 - 48: iII111i + IiII
def lisp_get_local_interfaces ( ) :
 for O0o0o0 in netifaces . interfaces ( ) :
  iii = lisp_interface ( O0o0o0 )
  iii . add_interface ( )
  if 70 - 70: Ii1I . i11iIiiIii % Ii1I . O0 - iIii1I11I1II1
 return
 if 26 - 26: OOooOOo
 if 76 - 76: i1IIi * OoooooooOO * O0 + I1Ii111 * I1Ii111
 if 35 - 35: o0oOOo0O0Ooo
 if 73 - 73: O0 - I1ii11iIi11i
 if 2 - 2: II111iiii / I1Ii111
 if 54 - 54: i1IIi . I11i - I1ii11iIi11i + ooOoO0o + Oo0Ooo / Oo0Ooo
 if 22 - 22: ooOoO0o . iIii1I11I1II1
def lisp_get_loopback_address ( ) :
 for iIiIi1ii in netifaces . ifaddresses ( "lo" ) [ netifaces . AF_INET ] :
  if ( iIiIi1ii [ "peer" ] == "127.0.0.1" ) : continue
  return ( iIiIi1ii [ "peer" ] )
  if 12 - 12: Ii1I
 return ( None )
 if 71 - 71: I1IiiI . II111iiii . I1IiiI - ooOoO0o
 if 45 - 45: IiII / O0 / OoOoOO00 * OOooOOo
 if 18 - 18: iIii1I11I1II1 + OOooOOo + iIii1I11I1II1 . I1ii11iIi11i + I1Ii111 . ooOoO0o
 if 7 - 7: I1ii11iIi11i + iIii1I11I1II1 * I11i * I11i / II111iiii - Ii1I
 if 65 - 65: oO0o + OoOoOO00 + II111iiii
 if 77 - 77: II111iiii
 if 50 - 50: O0 . O0 . ooOoO0o % Oo0Ooo
 if 68 - 68: oO0o
def lisp_get_local_macs ( ) :
 for O0o0o0 in netifaces . interfaces ( ) :
  if 10 - 10: Ii1I
  if 77 - 77: OOooOOo / II111iiii + IiII + ooOoO0o - i11iIiiIii
  if 44 - 44: I1IiiI + OoOoOO00 + I1ii11iIi11i . I1IiiI * OoOoOO00 % iIii1I11I1II1
  if 72 - 72: OOooOOo . OOooOOo - I1ii11iIi11i
  if 48 - 48: Oo0Ooo - ooOoO0o + Oo0Ooo - I1IiiI * i11iIiiIii . iII111i
  I1 = O0o0o0 . replace ( ":" , "" )
  I1 = O0o0o0 . replace ( "-" , "" )
  if ( I1 . isalnum ( ) == False ) : continue
  if 35 - 35: I1IiiI
  if 36 - 36: i1IIi - I1ii11iIi11i - I1Ii111
  if 7 - 7: i11iIiiIii + I1IiiI
  if 47 - 47: I1Ii111 - OOooOOo / ooOoO0o - Oo0Ooo + iII111i - iIii1I11I1II1
  if 68 - 68: Ii1I - oO0o + Oo0Ooo
  try :
   i11Iii1Ii1i1 = netifaces . ifaddresses ( O0o0o0 )
  except :
   continue
   if 10 - 10: iII111i . i1IIi + Ii1I
  if ( i11Iii1Ii1i1 . has_key ( netifaces . AF_LINK ) == False ) : continue
  iiIII1IIiIIII = i11Iii1Ii1i1 [ netifaces . AF_LINK ] [ 0 ] [ "addr" ]
  iiIII1IIiIIII = iiIII1IIiIIII . replace ( ":" , "" )
  if 66 - 66: OoO0O00 % o0oOOo0O0Ooo
  if 21 - 21: OoOoOO00 - OoooooooOO % i11iIiiIii
  if 71 - 71: i1IIi - I11i * I1Ii111 + oO0o - OoO0O00 % I1ii11iIi11i
  if 63 - 63: iIii1I11I1II1 + OOooOOo . OoO0O00 / I1IiiI
  if 84 - 84: i1IIi
  if ( len ( iiIII1IIiIIII ) < 12 ) : continue
  if 42 - 42: II111iiii - OoO0O00 - OoooooooOO . iII111i / OoOoOO00
  if ( lisp_mymacs . has_key ( iiIII1IIiIIII ) == False ) : lisp_mymacs [ iiIII1IIiIIII ] = [ ]
  lisp_mymacs [ iiIII1IIiIIII ] . append ( O0o0o0 )
  if 56 - 56: i11iIiiIii - iIii1I11I1II1 . II111iiii
  if 81 - 81: IiII / OoOoOO00 * IiII . O0
 lprint ( "Local MACs are: {}" . format ( lisp_mymacs ) )
 return
 if 61 - 61: OoO0O00 * OOooOOo + I1Ii111 . iIii1I11I1II1 % I11i . I1Ii111
 if 53 - 53: I1Ii111 * IiII / iIii1I11I1II1 / I1IiiI % I1ii11iIi11i
 if 39 - 39: OoO0O00 / OoooooooOO . OoO0O00 * I1ii11iIi11i / OoOoOO00
 if 38 - 38: OoO0O00 / ooOoO0o % I1Ii111 * I11i + i11iIiiIii % ooOoO0o
 if 61 - 61: I1Ii111 - Ii1I % I1ii11iIi11i / ooOoO0o / iII111i + iIii1I11I1II1
 if 87 - 87: I1Ii111 + ooOoO0o + O0 / i1IIi % IiII / I1Ii111
 if 64 - 64: OoO0O00 % IiII . I1Ii111 % OoO0O00 + I11i * IiII
 if 83 - 83: o0oOOo0O0Ooo % oO0o + I11i % i11iIiiIii + O0
def lisp_get_local_rloc ( ) :
 OoOOoooO000 = commands . getoutput ( "netstat -rn | egrep 'default|0.0.0.0'" )
 if ( OoOOoooO000 == "" ) : return ( lisp_address ( LISP_AFI_IPV4 , "" , 32 , 0 ) )
 if 85 - 85: I1IiiI % I11i + OOooOOo / Ii1I % OoooooooOO
 if 42 - 42: I1Ii111 * IiII
 if 23 - 23: oO0o * I1Ii111 - OoooooooOO * OoooooooOO % OoO0O00 + II111iiii
 if 9 - 9: iIii1I11I1II1 * OoO0O00 % I1Ii111
 OoOOoooO000 = OoOOoooO000 . split ( "\n" ) [ 0 ]
 O0o0o0 = OoOOoooO000 . split ( ) [ - 1 ]
 if 46 - 46: I11i . IiII / II111iiii % iIii1I11I1II1 + IiII
 iIiIi1ii = ""
 O0OOo = lisp_is_macos ( )
 if ( O0OOo ) :
  OoOOoooO000 = commands . getoutput ( "ifconfig {} | egrep 'inet '" . format ( O0o0o0 ) )
  if ( OoOOoooO000 == "" ) : return ( lisp_address ( LISP_AFI_IPV4 , "" , 32 , 0 ) )
 else :
  i1I1Iiii1 = 'ip addr show | egrep "inet " | egrep "{}"' . format ( O0o0o0 )
  OoOOoooO000 = commands . getoutput ( i1I1Iiii1 )
  if ( OoOOoooO000 == "" ) :
   i1I1Iiii1 = 'ip addr show | egrep "inet " | egrep "global lo"'
   OoOOoooO000 = commands . getoutput ( i1I1Iiii1 )
   if 69 - 69: I11i % O0 / I1IiiI . I1Ii111 / ooOoO0o
  if ( OoOOoooO000 == "" ) : return ( lisp_address ( LISP_AFI_IPV4 , "" , 32 , 0 ) )
  if 94 - 94: I11i - II111iiii . I1IiiI - Oo0Ooo + I1ii11iIi11i * I1ii11iIi11i
  if 27 - 27: IiII * I1IiiI . iIii1I11I1II1 - iIii1I11I1II1
  if 5 - 5: IiII
  if 84 - 84: II111iiii * oO0o * II111iiii % IiII / I1IiiI
  if 100 - 100: IiII . Ii1I - iIii1I11I1II1 . i11iIiiIii / II111iiii
  if 71 - 71: I1Ii111 * Oo0Ooo . I11i
 iIiIi1ii = ""
 OoOOoooO000 = OoOOoooO000 . split ( "\n" )
 if 49 - 49: IiII * O0 . IiII
 for ii1II1II in OoOOoooO000 :
  I11IIIiIi11 = ii1II1II . split ( ) [ 1 ]
  if ( O0OOo == False ) : I11IIIiIi11 = I11IIIiIi11 . split ( "/" ) [ 0 ]
  i11i11II11i = lisp_address ( LISP_AFI_IPV4 , I11IIIiIi11 , 32 , 0 )
  return ( i11i11II11i )
  if 9 - 9: OoOoOO00 - I1ii11iIi11i * ooOoO0o . ooOoO0o - I1IiiI
 return ( lisp_address ( LISP_AFI_IPV4 , iIiIi1ii , 32 , 0 ) )
 if 74 - 74: I1ii11iIi11i * i11iIiiIii / I1IiiI - O0 . ooOoO0o
 if 39 - 39: ooOoO0o / O0 * IiII
 if 17 - 17: Ii1I / iIii1I11I1II1 - OoO0O00 + I1IiiI % OOooOOo
 if 14 - 14: o0oOOo0O0Ooo % IiII + I1ii11iIi11i + OoO0O00
 if 76 - 76: OoO0O00 - i11iIiiIii + OoOoOO00 + OOooOOo / OoooooooOO
 if 50 - 50: II111iiii - I1Ii111 + iIii1I11I1II1 + iIii1I11I1II1
 if 91 - 91: II111iiii - O0 . iIii1I11I1II1 . O0 + I1ii11iIi11i - II111iiii
 if 26 - 26: o0oOOo0O0Ooo
 if 12 - 12: OoooooooOO / O0 + II111iiii * I1ii11iIi11i
 if 46 - 46: II111iiii - IiII * OoooooooOO / oO0o % IiII
 if 11 - 11: iIii1I11I1II1 . OoOoOO00 / IiII % ooOoO0o
def lisp_get_local_addresses ( ) :
 global lisp_myrlocs
 if 61 - 61: ooOoO0o - OOooOOo + OOooOOo
 if 40 - 40: i11iIiiIii . iIii1I11I1II1
 if 2 - 2: i1IIi * oO0o - oO0o + OoooooooOO % OoOoOO00 / OoOoOO00
 if 3 - 3: OoooooooOO
 if 71 - 71: IiII + i1IIi - iII111i - i11iIiiIii . I11i - ooOoO0o
 if 85 - 85: I1ii11iIi11i - OoOoOO00 / I1ii11iIi11i + OOooOOo - iII111i
 if 49 - 49: OoO0O00 - O0 / OoO0O00 * OoOoOO00 + I1Ii111
 if 35 - 35: II111iiii . I1IiiI / i1IIi / I1IiiI * oO0o
 if 85 - 85: II111iiii . ooOoO0o % OOooOOo % I11i
 if 80 - 80: oO0o * I11i / iIii1I11I1II1 % oO0o / iIii1I11I1II1
 Iiii1 = None
 I1Iiiiiii = 1
 i1iiIIiiiII = os . getenv ( "LISP_ADDR_SELECT" )
 if ( i1iiIIiiiII != None and i1iiIIiiiII != "" ) :
  i1iiIIiiiII = i1iiIIiiiII . split ( ":" )
  if ( len ( i1iiIIiiiII ) == 2 ) :
   Iiii1 = i1iiIIiiiII [ 0 ]
   I1Iiiiiii = i1iiIIiiiII [ 1 ]
  else :
   if ( i1iiIIiiiII [ 0 ] . isdigit ( ) ) :
    I1Iiiiiii = i1iiIIiiiII [ 0 ]
   else :
    Iiii1 = i1iiIIiiiII [ 0 ]
    if 5 - 5: OoooooooOO / o0oOOo0O0Ooo % I11i % OoO0O00 * iII111i + iIii1I11I1II1
    if 11 - 11: I1Ii111 % i11iIiiIii % oO0o . IiII
  I1Iiiiiii = 1 if ( I1Iiiiiii == "" ) else int ( I1Iiiiiii )
  if 92 - 92: II111iiii
  if 45 - 45: O0 % I1IiiI - iII111i . OoO0O00
 I1II = [ None , None , None ]
 iIIi1Ii1III = lisp_address ( LISP_AFI_IPV4 , "" , 32 , 0 )
 Oooo00 = lisp_address ( LISP_AFI_IPV6 , "" , 128 , 0 )
 iii1II1iI1IIi = None
 if 41 - 41: I1IiiI - I1Ii111 % II111iiii . I1Ii111 - I11i
 for O0o0o0 in netifaces . interfaces ( ) :
  if ( Iiii1 != None and Iiii1 != O0o0o0 ) : continue
  i1I1i1i = netifaces . ifaddresses ( O0o0o0 )
  if ( i1I1i1i == { } ) : continue
  if 45 - 45: Ii1I - OOooOOo
  if 70 - 70: OoO0O00 % I1IiiI / I1IiiI . I11i % ooOoO0o . II111iiii
  if 10 - 10: Ii1I - i11iIiiIii . I1ii11iIi11i % i1IIi
  if 78 - 78: iIii1I11I1II1 * Oo0Ooo . Oo0Ooo - OOooOOo . iIii1I11I1II1
  iii1II1iI1IIi = lisp_get_interface_instance_id ( O0o0o0 , None )
  if 30 - 30: ooOoO0o + ooOoO0o % IiII - o0oOOo0O0Ooo - I1ii11iIi11i
  if 36 - 36: I11i % OOooOOo
  if 72 - 72: I1IiiI / iII111i - O0 + I11i
  if 83 - 83: O0
  if ( i1I1i1i . has_key ( netifaces . AF_INET ) ) :
   IIiI11i11 = i1I1i1i [ netifaces . AF_INET ]
   oOOOOOo = 0
   for iIiIi1ii in IIiI11i11 :
    iIIi1Ii1III . store_address ( iIiIi1ii [ "addr" ] )
    if ( iIIi1Ii1III . is_ipv4_loopback ( ) ) : continue
    if ( iIIi1Ii1III . is_ipv4_link_local ( ) ) : continue
    if ( iIIi1Ii1III . address == 0 ) : continue
    oOOOOOo += 1
    iIIi1Ii1III . instance_id = iii1II1iI1IIi
    if ( Iiii1 == None and
 lisp_db_for_lookups . lookup_cache ( iIIi1Ii1III , False ) ) : continue
    I1II [ 0 ] = iIIi1Ii1III
    if ( oOOOOOo == I1Iiiiiii ) : break
    if 50 - 50: I1Ii111 + ooOoO0o + iII111i
    if 15 - 15: I11i
  if ( i1I1i1i . has_key ( netifaces . AF_INET6 ) ) :
   i1 = i1I1i1i [ netifaces . AF_INET6 ]
   oOOOOOo = 0
   for iIiIi1ii in i1 :
    oO00o = iIiIi1ii [ "addr" ]
    Oooo00 . store_address ( oO00o )
    if ( Oooo00 . is_ipv6_string_link_local ( oO00o ) ) : continue
    if ( Oooo00 . is_ipv6_loopback ( ) ) : continue
    oOOOOOo += 1
    Oooo00 . instance_id = iii1II1iI1IIi
    if ( Iiii1 == None and
 lisp_db_for_lookups . lookup_cache ( Oooo00 , False ) ) : continue
    I1II [ 1 ] = Oooo00
    if ( oOOOOOo == I1Iiiiiii ) : break
    if 13 - 13: iIii1I11I1II1 * OoOoOO00 / I1Ii111 % ooOoO0o + oO0o
    if 41 - 41: I1ii11iIi11i
    if 5 - 5: Oo0Ooo
    if 100 - 100: Ii1I + iIii1I11I1II1
    if 59 - 59: IiII
    if 89 - 89: OoOoOO00 % iIii1I11I1II1
  if ( I1II [ 0 ] == None ) : continue
  if 35 - 35: I1ii11iIi11i + I1Ii111 - OoOoOO00 % oO0o % o0oOOo0O0Ooo % OoOoOO00
  I1II [ 2 ] = O0o0o0
  break
  if 45 - 45: I1IiiI * OOooOOo % OoO0O00
  if 24 - 24: ooOoO0o - I11i * oO0o
 O00OoOoO = I1II [ 0 ] . print_address_no_iid ( ) if I1II [ 0 ] else "none"
 ooO0o0oo = I1II [ 1 ] . print_address_no_iid ( ) if I1II [ 1 ] else "none"
 O0o0o0 = I1II [ 2 ] if I1II [ 2 ] else "none"
 if 79 - 79: IiII % OoO0O00
 Iiii1 = " (user selected)" if Iiii1 != None else ""
 if 81 - 81: i11iIiiIii + i11iIiiIii * OoO0O00 + IiII
 O00OoOoO = red ( O00OoOoO , False )
 ooO0o0oo = red ( ooO0o0oo , False )
 O0o0o0 = bold ( O0o0o0 , False )
 lprint ( "Local addresses are IPv4: {}, IPv6: {} from device {}{}, iid {}" . format ( O00OoOoO , ooO0o0oo , O0o0o0 , Iiii1 , iii1II1iI1IIi ) )
 if 32 - 32: O0 . OoooooooOO
 if 15 - 15: I1IiiI . OoO0O00
 lisp_myrlocs = I1II
 return ( ( I1II [ 0 ] != None ) )
 if 17 - 17: i11iIiiIii / Oo0Ooo . OoO0O00 / I1IiiI
 if 38 - 38: i1IIi . I1ii11iIi11i % Ii1I + iIii1I11I1II1 + O0
 if 47 - 47: OoO0O00 + IiII / II111iiii
 if 97 - 97: I1ii11iIi11i / I1IiiI % O0 + i1IIi - ooOoO0o
 if 38 - 38: o0oOOo0O0Ooo % I1Ii111 + i11iIiiIii + iII111i + ooOoO0o / i11iIiiIii
 if 94 - 94: iII111i - Oo0Ooo + oO0o
 if 59 - 59: I11i . I1IiiI - iIii1I11I1II1 + iIii1I11I1II1
 if 56 - 56: oO0o + ooOoO0o
 if 32 - 32: II111iiii + OoOoOO00 % ooOoO0o / OoOoOO00 + I1ii11iIi11i
def lisp_get_all_addresses ( ) :
 IiI11I111 = [ ]
 for iii in netifaces . interfaces ( ) :
  try : Ooo000O00 = netifaces . ifaddresses ( iii )
  except : continue
  if 36 - 36: OOooOOo % i11iIiiIii
  if ( Ooo000O00 . has_key ( netifaces . AF_INET ) ) :
   for iIiIi1ii in Ooo000O00 [ netifaces . AF_INET ] :
    I11IIIiIi11 = iIiIi1ii [ "addr" ]
    if ( I11IIIiIi11 . find ( "127.0.0.1" ) != - 1 ) : continue
    IiI11I111 . append ( I11IIIiIi11 )
    if 47 - 47: i1IIi + II111iiii . Oo0Ooo * oO0o . I11i / i1IIi
    if 50 - 50: I1Ii111 / i1IIi % OoooooooOO
  if ( Ooo000O00 . has_key ( netifaces . AF_INET6 ) ) :
   for iIiIi1ii in Ooo000O00 [ netifaces . AF_INET6 ] :
    I11IIIiIi11 = iIiIi1ii [ "addr" ]
    if ( I11IIIiIi11 == "::1" ) : continue
    if ( I11IIIiIi11 [ 0 : 5 ] == "fe80:" ) : continue
    IiI11I111 . append ( I11IIIiIi11 )
    if 83 - 83: I1ii11iIi11i * I1ii11iIi11i + OOooOOo
    if 57 - 57: O0 - O0 . I1ii11iIi11i / o0oOOo0O0Ooo / Ii1I
    if 20 - 20: OOooOOo * II111iiii - OoOoOO00 - oO0o * I1Ii111
 return ( IiI11I111 )
 if 6 - 6: ooOoO0o + OOooOOo / Oo0Ooo + IiII % II111iiii / OoO0O00
 if 45 - 45: OoooooooOO
 if 9 - 9: I11i . OoO0O00 * i1IIi . OoooooooOO
 if 32 - 32: OoOoOO00 . I1ii11iIi11i % I1IiiI - II111iiii
 if 11 - 11: O0 + I1IiiI
 if 80 - 80: oO0o % oO0o % O0 - i11iIiiIii . iII111i / O0
 if 13 - 13: I1IiiI + O0 - I1ii11iIi11i % Oo0Ooo / Ii1I . i1IIi
 if 60 - 60: Oo0Ooo . IiII % I1IiiI - I1Ii111
def lisp_get_all_multicast_rles ( ) :
 oooOo = [ ]
 OoOOoooO000 = commands . getoutput ( 'egrep "rle-address =" ./lisp.config' )
 if ( OoOOoooO000 == "" ) : return ( oooOo )
 if 79 - 79: oO0o - II111iiii
 Ii1iiI1 = OoOOoooO000 . split ( "\n" )
 for ii1II1II in Ii1iiI1 :
  if ( ii1II1II [ 0 ] == "#" ) : continue
  o0ooOOoO0oO0 = ii1II1II . split ( "rle-address = " ) [ 1 ]
  oo00 = int ( o0ooOOoO0oO0 . split ( "." ) [ 0 ] )
  if ( oo00 >= 224 and oo00 < 240 ) : oooOo . append ( o0ooOOoO0oO0 )
  if 35 - 35: ooOoO0o % I1IiiI - ooOoO0o - OoO0O00 - OoooooooOO
 return ( oooOo )
 if 46 - 46: i1IIi . i1IIi . oO0o / I11i / ooOoO0o
 if 34 - 34: OoooooooOO / Oo0Ooo * i11iIiiIii . II111iiii . OoooooooOO
 if 59 - 59: i11iIiiIii . OoooooooOO / I11i * I1ii11iIi11i + OoooooooOO
 if 3 - 3: i11iIiiIii * Oo0Ooo % iIii1I11I1II1 % I1IiiI * iII111i / OOooOOo
 if 95 - 95: IiII * O0 * I1Ii111 . OoooooooOO % Oo0Ooo + I1ii11iIi11i
 if 98 - 98: oO0o . OoooooooOO
 if 54 - 54: O0 / IiII % ooOoO0o * i1IIi * O0
 if 48 - 48: o0oOOo0O0Ooo . oO0o % OoOoOO00 - OoOoOO00
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
  self . lisp_header = lisp_data_header ( )
  self . packet = packet
  self . inner_version = 0
  self . outer_version = 0
  self . encap_port = LISP_DATA_PORT
  self . inner_is_fragment = False
  self . packet_error = ""
  if 33 - 33: I11i % II111iiii + OoO0O00
  if 93 - 93: i1IIi . IiII / I1IiiI + IiII
 def encode ( self , nonce ) :
  if 58 - 58: I1ii11iIi11i + O0 . Oo0Ooo + OoOoOO00 - OoO0O00 - OoOoOO00
  if 41 - 41: Oo0Ooo / i1IIi / Oo0Ooo - iII111i . o0oOOo0O0Ooo
  if 65 - 65: O0 * i11iIiiIii . OoooooooOO / I1IiiI / iII111i
  if 69 - 69: ooOoO0o % ooOoO0o
  if 76 - 76: i11iIiiIii * iII111i / OoO0O00 % I1ii11iIi11i + OOooOOo
  if ( self . outer_source . is_null ( ) ) : return ( None )
  if 48 - 48: iIii1I11I1II1 % i1IIi + OoOoOO00 % o0oOOo0O0Ooo
  if 79 - 79: OoOoOO00 % I1IiiI % Ii1I / i1IIi % OoO0O00
  if 56 - 56: iIii1I11I1II1 - i11iIiiIii * iII111i
  if 84 - 84: OOooOOo + Ii1I + o0oOOo0O0Ooo
  if 33 - 33: Ii1I
  if 93 - 93: ooOoO0o
  if ( nonce == None ) :
   self . lisp_header . nonce ( lisp_get_data_nonce ( ) )
  elif ( self . lisp_header . is_request_nonce ( nonce ) ) :
   self . lisp_header . request_nonce ( nonce )
  else :
   self . lisp_header . nonce ( nonce )
   if 34 - 34: oO0o - ooOoO0o * Oo0Ooo / o0oOOo0O0Ooo
  self . lisp_header . instance_id ( self . inner_dest . instance_id )
  if 19 - 19: I1ii11iIi11i
  if 46 - 46: iIii1I11I1II1 . i11iIiiIii - OoOoOO00 % O0 / II111iiii * i1IIi
  if 66 - 66: O0
  if 52 - 52: OoO0O00 * OoooooooOO
  if 12 - 12: O0 + IiII * i1IIi . OoO0O00
  if 71 - 71: I1Ii111 - o0oOOo0O0Ooo - OOooOOo
  self . lisp_header . key_id ( 0 )
  iiI = ( self . lisp_header . get_instance_id ( ) == 0xffffff )
  if ( lisp_data_plane_security and iiI == False ) :
   oO00o = self . outer_dest . print_address_no_iid ( ) + ":" + str ( self . encap_port )
   if 81 - 81: IiII * I1ii11iIi11i + II111iiii % IiII
   if ( lisp_crypto_keys_by_rloc_encap . has_key ( oO00o ) ) :
    IiI1ii11I1 = lisp_crypto_keys_by_rloc_encap [ oO00o ]
    if ( IiI1ii11I1 [ 1 ] ) :
     IiI1ii11I1 [ 1 ] . use_count += 1
     I1i1iI , I1iI1I1ii1 = self . encrypt ( IiI1ii11I1 [ 1 ] , oO00o )
     if ( I1iI1I1ii1 ) : self . packet = I1i1iI
     if 33 - 33: o0oOOo0O0Ooo / O0 + OOooOOo
     if 75 - 75: IiII % i11iIiiIii + iIii1I11I1II1
     if 92 - 92: OoOoOO00 % O0
     if 55 - 55: iIii1I11I1II1 * iII111i
     if 85 - 85: iIii1I11I1II1 . II111iiii
     if 54 - 54: Ii1I . OoooooooOO % Oo0Ooo
     if 22 - 22: OOooOOo
     if 22 - 22: iII111i * I11i - Oo0Ooo * O0 / i11iIiiIii
  self . udp_checksum = 0
  if ( self . encap_port == LISP_DATA_PORT ) :
   if ( lisp_crypto_ephem_port == None ) :
    self . hash_packet ( )
   else :
    self . udp_sport = lisp_crypto_ephem_port
    if 78 - 78: Oo0Ooo * O0 / ooOoO0o + OoooooooOO + OOooOOo
  else :
   self . udp_sport = LISP_DATA_PORT
   if 23 - 23: iII111i % OoooooooOO / iIii1I11I1II1 + I1ii11iIi11i / i1IIi / o0oOOo0O0Ooo
  self . udp_dport = self . encap_port
  self . udp_length = len ( self . packet ) + 16
  if 94 - 94: i1IIi
  if 36 - 36: I1IiiI + Oo0Ooo
  if 46 - 46: iII111i
  if 65 - 65: i1IIi . I1ii11iIi11i / ooOoO0o
  if ( self . outer_version == 4 ) :
   I1i1I11111iI1 = socket . htons ( self . udp_sport )
   IIIIIIi = socket . htons ( self . udp_dport )
  else :
   I1i1I11111iI1 = self . udp_sport
   IIIIIIi = self . udp_dport
   if 59 - 59: oO0o / I1IiiI * Ii1I % O0 - II111iiii + OoooooooOO
   if 21 - 21: I1Ii111
  IIIIIIi = socket . htons ( self . udp_dport ) if self . outer_version == 4 else self . udp_dport
  if 60 - 60: I1IiiI % oO0o / o0oOOo0O0Ooo % oO0o * i11iIiiIii / iII111i
  if 34 - 34: I1Ii111 - OOooOOo
  IIIiIi1iiI = struct . pack ( "HHHH" , I1i1I11111iI1 , IIIIIIi , socket . htons ( self . udp_length ) ,
 self . udp_checksum )
  if 15 - 15: I1ii11iIi11i . iII111i
  if 94 - 94: I11i . I1IiiI
  if 73 - 73: i1IIi / II111iiii
  if 45 - 45: Ii1I / ooOoO0o . OoooooooOO + OoO0O00
  O00oO000Oo0 = self . lisp_header . encode ( )
  if 26 - 26: Oo0Ooo + O0 - iIii1I11I1II1
  if 47 - 47: OoooooooOO
  if 2 - 2: OoOoOO00 % I1Ii111 * Oo0Ooo * OoOoOO00
  if 65 - 65: i11iIiiIii + Oo0Ooo * OoooooooOO - OoO0O00
  if 26 - 26: o0oOOo0O0Ooo % OOooOOo + OOooOOo % I11i * i11iIiiIii / iII111i
  if ( self . outer_version == 4 ) :
   OOoO0oO00o = socket . htons ( self . udp_length + 20 )
   OOO0OoO0oo0OO = socket . htons ( 0x4000 )
   i1iI1Ii11Ii1 = struct . pack ( "BBHHHBBH" , 0x45 , self . outer_tos , OOoO0oO00o , 0xdfdf ,
 OOO0OoO0oo0OO , self . outer_ttl , 17 , 0 )
   i1iI1Ii11Ii1 += self . outer_source . pack_address ( )
   i1iI1Ii11Ii1 += self . outer_dest . pack_address ( )
   i1iI1Ii11Ii1 = lisp_ip_checksum ( i1iI1Ii11Ii1 )
  elif ( self . outer_version == 6 ) :
   i1iI1Ii11Ii1 = ""
   if 82 - 82: O0
   if 70 - 70: I11i - Oo0Ooo / OoooooooOO % OoooooooOO
   if 95 - 95: OoooooooOO % OoooooooOO . Ii1I
   if 26 - 26: oO0o + IiII - II111iiii . II111iiii + I1ii11iIi11i + OoOoOO00
   if 68 - 68: O0
   if 76 - 76: I1ii11iIi11i
   if 99 - 99: o0oOOo0O0Ooo
  else :
   return ( None )
   if 1 - 1: Ii1I * OoOoOO00 * OoO0O00 + Oo0Ooo
   if 90 - 90: I1Ii111 % Oo0Ooo - Oo0Ooo . iIii1I11I1II1 / OOooOOo + I11i
  self . packet = i1iI1Ii11Ii1 + IIIiIi1iiI + O00oO000Oo0 + self . packet
  return ( self )
  if 89 - 89: oO0o
  if 87 - 87: iII111i % Oo0Ooo
 def cipher_pad ( self , packet ) :
  OOo000o = len ( packet )
  if ( ( OOo000o % 16 ) != 0 ) :
   iiIIIIiI111 = ( ( OOo000o / 16 ) + 1 ) * 16
   packet = packet . ljust ( iiIIIIiI111 )
   if 86 - 86: II111iiii % iIii1I11I1II1 / I1ii11iIi11i - o0oOOo0O0Ooo * Ii1I . I1IiiI
  return ( packet )
  if 68 - 68: OoooooooOO * iIii1I11I1II1 + i1IIi - i1IIi
  if 76 - 76: OoO0O00 . OoooooooOO % I1Ii111 * Ii1I
 def encrypt ( self , key , addr_str ) :
  if ( key == None or key . shared_key == None ) :
   return ( [ self . packet , False ] )
   if 23 - 23: IiII + iIii1I11I1II1
   if 14 - 14: O0 % IiII % Ii1I * oO0o
   if 65 - 65: I11i % oO0o + I1ii11iIi11i
   if 86 - 86: iIii1I11I1II1 / O0 . I1Ii111 % iIii1I11I1II1 % Oo0Ooo
   if 86 - 86: i11iIiiIii - o0oOOo0O0Ooo . ooOoO0o * Oo0Ooo / Ii1I % o0oOOo0O0Ooo
  I1i1iI = self . cipher_pad ( self . packet )
  oOOo00 = key . get_iv ( )
  if 50 - 50: iIii1I11I1II1 - iII111i - I11i
  iII1i1 = lisp_get_timestamp ( )
  oo00O0O0O0o0o = None
  if ( key . cipher_suite == LISP_CS_25519_CHACHA ) :
   Oo0oOO0O00 = chacha . ChaCha ( key . encrypt_key , oOOo00 ) . encrypt
  elif ( key . cipher_suite == LISP_CS_25519_GCM ) :
   o00OOo0o0O = binascii . unhexlify ( key . encrypt_key )
   try :
    I111Iii1 = AES . new ( o00OOo0o0O , AES . MODE_GCM , oOOo00 )
    Oo0oOO0O00 = I111Iii1 . encrypt
    oo00O0O0O0o0o = I111Iii1 . digest
   except :
    lprint ( "You need AES-GCM, do a 'pip install pycryptodome'" )
    return ( [ self . packet , False ] )
    if 30 - 30: i1IIi
  else :
   o00OOo0o0O = binascii . unhexlify ( key . encrypt_key )
   Oo0oOO0O00 = AES . new ( o00OOo0o0O , AES . MODE_CBC , oOOo00 ) . encrypt
   if 75 - 75: I11i . OOooOOo - iIii1I11I1II1 * OoO0O00 * iII111i
   if 93 - 93: ooOoO0o
  iII1IIiiI11II = Oo0oOO0O00 ( I1i1iI )
  if 70 - 70: Ii1I - OOooOOo * OOooOOo / iIii1I11I1II1 + O0
  if ( iII1IIiiI11II == None ) : return ( [ self . packet , False ] )
  iII1i1 = int ( str ( time . time ( ) - iII1i1 ) . split ( "." ) [ 1 ] [ 0 : 6 ] )
  if 49 - 49: i11iIiiIii - I1ii11iIi11i - I11i / OoooooooOO % OoOoOO00
  if 65 - 65: O0 - I1Ii111 . Ii1I
  if 19 - 19: I1ii11iIi11i . iII111i - o0oOOo0O0Ooo + I11i - Ii1I
  if 13 - 13: IiII * I1ii11iIi11i / I1ii11iIi11i / iIii1I11I1II1 % iIii1I11I1II1
  if 21 - 21: I1ii11iIi11i
  if 86 - 86: ooOoO0o
  if ( oo00O0O0O0o0o != None ) : iII1IIiiI11II += oo00O0O0O0o0o ( )
  if 51 - 51: OoO0O00 - i11iIiiIii * I1IiiI
  if 95 - 95: OOooOOo % I1ii11iIi11i + o0oOOo0O0Ooo % ooOoO0o
  if 36 - 36: O0 / i1IIi % II111iiii / iII111i
  if 96 - 96: Oo0Ooo / oO0o . II111iiii . Oo0Ooo
  if 91 - 91: II111iiii . OOooOOo + o0oOOo0O0Ooo
  self . lisp_header . key_id ( key . key_id )
  O00oO000Oo0 = self . lisp_header . encode ( )
  if 8 - 8: OOooOOo * Oo0Ooo / iII111i - OoO0O00 - OoooooooOO
  oOiIi = key . do_icv ( O00oO000Oo0 + oOOo00 + iII1IIiiI11II , oOOo00 )
  if 65 - 65: II111iiii + i1IIi * i11iIiiIii
  Ii1i1i = 4 if ( key . do_poly ) else 8
  if 83 - 83: I11i - I1ii11iIi11i * oO0o
  oOO00OO0OooOo = bold ( "Encrypt" , False )
  ii111iI1i1 = bold ( key . cipher_suite_string , False )
  addr_str = "RLOC: " + red ( addr_str , False )
  OO000 = "poly" if key . do_poly else "sha256"
  OO000 = bold ( OO000 , False )
  IIiii11ii1II1 = "ICV({}): 0x{}...{}" . format ( OO000 , oOiIi [ 0 : Ii1i1i ] , oOiIi [ - Ii1i1i : : ] )
  dprint ( "{} for key-id: {}, {}, {}, {}-time: {} usec" . format ( oOO00OO0OooOo , key . key_id , addr_str , IIiii11ii1II1 , ii111iI1i1 , iII1i1 ) )
  if 97 - 97: I11i - o0oOOo0O0Ooo + ooOoO0o
  if 89 - 89: oO0o + I11i * I11i % i1IIi % I11i
  oOiIi = int ( oOiIi , 16 )
  if ( key . do_poly ) :
   OOOO000Ooo0O = byte_swap_64 ( ( oOiIi >> 64 ) & LISP_8_64_MASK )
   oOo0oO = byte_swap_64 ( oOiIi & LISP_8_64_MASK )
   oOiIi = struct . pack ( "QQ" , OOOO000Ooo0O , oOo0oO )
  else :
   OOOO000Ooo0O = byte_swap_64 ( ( oOiIi >> 96 ) & LISP_8_64_MASK )
   oOo0oO = byte_swap_64 ( ( oOiIi >> 32 ) & LISP_8_64_MASK )
   ooo0O = socket . htonl ( oOiIi & 0xffffffff )
   oOiIi = struct . pack ( "QQI" , OOOO000Ooo0O , oOo0oO , ooo0O )
   if 22 - 22: oO0o * iII111i
   if 4 - 4: OoOoOO00 - oO0o + I1IiiI
  return ( [ oOOo00 + iII1IIiiI11II + oOiIi , True ] )
  if 36 - 36: IiII
  if 19 - 19: OoOoOO00 . o0oOOo0O0Ooo . OoooooooOO
 def decrypt ( self , packet , header_length , key , addr_str ) :
  if 13 - 13: OOooOOo . Oo0Ooo / II111iiii
  if 43 - 43: iIii1I11I1II1 % OoO0O00
  if 84 - 84: Oo0Ooo
  if 44 - 44: OoooooooOO * i11iIiiIii / Oo0Ooo
  if 75 - 75: OoooooooOO . OOooOOo + OoO0O00 / Ii1I - I1IiiI % Ii1I
  if 89 - 89: iII111i * iIii1I11I1II1 + i11iIiiIii . OoooooooOO
  if ( key . do_poly ) :
   OOOO000Ooo0O , oOo0oO = struct . unpack ( "QQ" , packet [ - 16 : : ] )
   O0O0 = byte_swap_64 ( OOOO000Ooo0O ) << 64
   O0O0 |= byte_swap_64 ( oOo0oO )
   O0O0 = lisp_hex_string ( O0O0 ) . zfill ( 32 )
   packet = packet [ 0 : - 16 ]
   Ii1i1i = 4
   oO0oo = bold ( "poly" , False )
  else :
   OOOO000Ooo0O , oOo0oO , ooo0O = struct . unpack ( "QQI" , packet [ - 20 : : ] )
   O0O0 = byte_swap_64 ( OOOO000Ooo0O ) << 96
   O0O0 |= byte_swap_64 ( oOo0oO ) << 32
   O0O0 |= socket . htonl ( ooo0O )
   O0O0 = lisp_hex_string ( O0O0 ) . zfill ( 40 )
   packet = packet [ 0 : - 20 ]
   Ii1i1i = 8
   oO0oo = bold ( "sha" , False )
   if 52 - 52: IiII % ooOoO0o
  O00oO000Oo0 = self . lisp_header . encode ( )
  if 25 - 25: I11i / I11i % OoooooooOO - I1ii11iIi11i * oO0o
  if 23 - 23: i11iIiiIii
  if 100 - 100: oO0o + O0 . I1IiiI + i1IIi - OoOoOO00 + o0oOOo0O0Ooo
  if 65 - 65: II111iiii / Oo0Ooo
  if ( key . cipher_suite == LISP_CS_25519_CHACHA ) :
   ii = 8
   ii111iI1i1 = bold ( "chacha" , False )
  elif ( key . cipher_suite == LISP_CS_25519_GCM ) :
   ii = 12
   ii111iI1i1 = bold ( "aes-gcm" , False )
  else :
   ii = 16
   ii111iI1i1 = bold ( "aes-cbc" , False )
   if 6 - 6: OoOoOO00 / iIii1I11I1II1 * I1Ii111 / I1IiiI + O0
  oOOo00 = packet [ 0 : ii ]
  if 2 - 2: I1IiiI * Oo0Ooo % o0oOOo0O0Ooo % Oo0Ooo
  if 66 - 66: IiII + iIii1I11I1II1
  if 75 - 75: I1ii11iIi11i
  if 92 - 92: I11i / O0 * I1IiiI - I11i
  oooOo00000 = key . do_icv ( O00oO000Oo0 + packet , oOOo00 )
  if 45 - 45: O0 * I1Ii111 + i11iIiiIii - OOooOOo - iIii1I11I1II1
  I11I111i1I1 = "0x{}...{}" . format ( O0O0 [ 0 : Ii1i1i ] , O0O0 [ - Ii1i1i : : ] )
  iii1 = "0x{}...{}" . format ( oooOo00000 [ 0 : Ii1i1i ] , oooOo00000 [ - Ii1i1i : : ] )
  if 88 - 88: I11i + I1IiiI - I11i / OoooooooOO - i11iIiiIii
  if ( oooOo00000 != O0O0 ) :
   self . packet_error = "ICV-error"
   i11 = ii111iI1i1 + "/" + oO0oo
   Ii1IiIIIi = bold ( "ICV failed ({})" . format ( i11 ) , False )
   IIiii11ii1II1 = "packet-ICV {} != computed-ICV {}" . format ( I11I111i1I1 , iii1 )
   dprint ( ( "{} from RLOC {}, receive-port: {}, key-id: {}, " + "packet dropped, {}" ) . format ( Ii1IiIIIi , red ( addr_str , False ) ,
   # I11i - oO0o + O0 / iII111i % i1IIi
 self . udp_sport , key . key_id , IIiii11ii1II1 ) )
   dprint ( "{}" . format ( key . print_keys ( ) ) )
   if 97 - 97: o0oOOo0O0Ooo * ooOoO0o
   if 78 - 78: I11i . OOooOOo + oO0o * iII111i - i1IIi
   if 27 - 27: Ii1I % i1IIi . Oo0Ooo % I1Ii111
   if 10 - 10: IiII / OoooooooOO
   if 50 - 50: i11iIiiIii - OoooooooOO . oO0o + O0 . i1IIi
   if 91 - 91: o0oOOo0O0Ooo . iII111i % Oo0Ooo - iII111i . oO0o % i11iIiiIii
   lisp_retry_decap_keys ( addr_str , O00oO000Oo0 + packet , oOOo00 , O0O0 )
   return ( [ None , False ] )
   if 25 - 25: iIii1I11I1II1
   if 63 - 63: ooOoO0o
   if 96 - 96: I11i
   if 34 - 34: OoOoOO00 / OoO0O00 - I1IiiI . O0 . OOooOOo
   if 63 - 63: iII111i
  packet = packet [ ii : : ]
  if 11 - 11: iII111i - iIii1I11I1II1
  if 92 - 92: OoO0O00
  if 15 - 15: IiII / IiII + iIii1I11I1II1 % OoooooooOO
  if 12 - 12: ooOoO0o
  iII1i1 = lisp_get_timestamp ( )
  if ( key . cipher_suite == LISP_CS_25519_CHACHA ) :
   I11 = chacha . ChaCha ( key . encrypt_key , oOOo00 ) . decrypt
  elif ( key . cipher_suite == LISP_CS_25519_GCM ) :
   o00OOo0o0O = binascii . unhexlify ( key . encrypt_key )
   try :
    I11 = AES . new ( o00OOo0o0O , AES . MODE_GCM , oOOo00 ) . decrypt
   except :
    self . packet_error = "no-decrypt-key"
    lprint ( "You need AES-GCM, do a 'pip install pycryptodome'" )
    return ( [ None , False ] )
    if 90 - 90: o0oOOo0O0Ooo / OOooOOo - OOooOOo . I1IiiI
  else :
   if ( ( len ( packet ) % 16 ) != 0 ) :
    dprint ( "Ciphertext not multiple of 16 bytes, packet dropped" )
    return ( [ None , False ] )
    if 82 - 82: I1Ii111 . I1Ii111 - iII111i
   o00OOo0o0O = binascii . unhexlify ( key . encrypt_key )
   I11 = AES . new ( o00OOo0o0O , AES . MODE_CBC , oOOo00 ) . decrypt
   if 72 - 72: i11iIiiIii
   if 94 - 94: OOooOOo
  i1IiI1ii1i = I11 ( packet )
  iII1i1 = int ( str ( time . time ( ) - iII1i1 ) . split ( "." ) [ 1 ] [ 0 : 6 ] )
  if 39 - 39: OOooOOo + OoO0O00
  if 80 - 80: OOooOOo % OoO0O00 / OoOoOO00
  if 54 - 54: Oo0Ooo % OoO0O00 - OOooOOo - I11i
  if 71 - 71: ooOoO0o . i11iIiiIii
  oOO00OO0OooOo = bold ( "Decrypt" , False )
  addr_str = "RLOC: " + red ( addr_str , False )
  OO000 = "poly" if key . do_poly else "sha256"
  OO000 = bold ( OO000 , False )
  IIiii11ii1II1 = "ICV({}): {}" . format ( OO000 , I11I111i1I1 )
  dprint ( "{} for key-id: {}, {}, {} (good), {}-time: {} usec" . format ( oOO00OO0OooOo , key . key_id , addr_str , IIiii11ii1II1 , ii111iI1i1 , iII1i1 ) )
  if 56 - 56: O0 * iII111i + iII111i * iIii1I11I1II1 / ooOoO0o * I1Ii111
  if 25 - 25: iIii1I11I1II1 . I11i * i11iIiiIii + Oo0Ooo * I11i
  if 67 - 67: iII111i
  if 88 - 88: Oo0Ooo
  if 8 - 8: I1ii11iIi11i
  if 82 - 82: OoooooooOO
  if 75 - 75: II111iiii % I1IiiI + OOooOOo % OoooooooOO / IiII
  self . packet = self . packet [ 0 : header_length ]
  return ( [ i1IiI1ii1i , True ] )
  if 4 - 4: i11iIiiIii - OOooOOo % I1ii11iIi11i * I1Ii111 % o0oOOo0O0Ooo
  if 71 - 71: ooOoO0o . ooOoO0o - iIii1I11I1II1
 def fragment_outer ( self , outer_hdr , inner_packet ) :
  Ii1IOoO0o0O = 1000
  if 20 - 20: O0
  if 61 - 61: II111iiii . O0 - Ii1I - I1ii11iIi11i / i11iIiiIii - II111iiii
  if 98 - 98: Ii1I - I1IiiI . i11iIiiIii * Oo0Ooo
  if 29 - 29: Ii1I / ooOoO0o % I11i
  if 10 - 10: iIii1I11I1II1 % OoooooooOO % I1ii11iIi11i
  IiiI1i111I1i = [ ]
  O00oOooo0 = 0
  OOo000o = len ( inner_packet )
  while ( O00oOooo0 < OOo000o ) :
   OOO0OoO0oo0OO = inner_packet [ O00oOooo0 : : ]
   if ( len ( OOO0OoO0oo0OO ) > Ii1IOoO0o0O ) : OOO0OoO0oo0OO = OOO0OoO0oo0OO [ 0 : Ii1IOoO0o0O ]
   IiiI1i111I1i . append ( OOO0OoO0oo0OO )
   O00oOooo0 += len ( OOO0OoO0oo0OO )
   if 97 - 97: OOooOOo % I1IiiI * I1IiiI % Oo0Ooo
   if 86 - 86: Ii1I * i1IIi + oO0o
   if 8 - 8: oO0o
   if 50 - 50: IiII . ooOoO0o - O0 % I1IiiI . I1Ii111
   if 17 - 17: O0 + OoooooooOO
   if 78 - 78: II111iiii + IiII
  oOo = [ ]
  O00oOooo0 = 0
  for OOO0OoO0oo0OO in IiiI1i111I1i :
   if 86 - 86: I1Ii111 * Oo0Ooo . iII111i
   if 96 - 96: o0oOOo0O0Ooo % IiII / OOooOOo
   if 63 - 63: i1IIi % i11iIiiIii % II111iiii * OoooooooOO
   if 40 - 40: Oo0Ooo
   iI1Ii11 = O00oOooo0 if ( OOO0OoO0oo0OO == IiiI1i111I1i [ - 1 ] ) else 0x2000 + O00oOooo0
   iI1Ii11 = socket . htons ( iI1Ii11 )
   outer_hdr = outer_hdr [ 0 : 6 ] + struct . pack ( "H" , iI1Ii11 ) + outer_hdr [ 8 : : ]
   if 93 - 93: I1IiiI / ooOoO0o / I11i + II111iiii + i11iIiiIii
   if 16 - 16: I1IiiI - oO0o . Oo0Ooo
   if 94 - 94: OoOoOO00 + IiII . ooOoO0o
   if 69 - 69: O0 - O0
   i1I1i1i1I1 = socket . htons ( len ( OOO0OoO0oo0OO ) + 20 )
   outer_hdr = outer_hdr [ 0 : 2 ] + struct . pack ( "H" , i1I1i1i1I1 ) + outer_hdr [ 4 : : ]
   outer_hdr = lisp_ip_checksum ( outer_hdr )
   oOo . append ( outer_hdr + OOO0OoO0oo0OO )
   O00oOooo0 += len ( OOO0OoO0oo0OO ) / 8
   if 17 - 17: OoOoOO00 + OoooooooOO % OOooOOo
  return ( oOo )
  if 36 - 36: i11iIiiIii + I1ii11iIi11i % OOooOOo . I1IiiI - ooOoO0o
  if 94 - 94: I1IiiI % OoOoOO00 . IiII . ooOoO0o . OoO0O00
 def fragment ( self ) :
  I1i1iI = self . fix_outer_header ( self . packet )
  if 53 - 53: OoOoOO00
  if 84 - 84: OoO0O00
  if 97 - 97: i1IIi
  if 98 - 98: OoooooooOO - I1IiiI + ooOoO0o
  if 98 - 98: iII111i . IiII . IiII - OOooOOo
  if 65 - 65: Oo0Ooo + o0oOOo0O0Ooo - Ii1I
  OOo000o = len ( I1i1iI )
  if ( OOo000o <= 1500 ) : return ( [ I1i1iI ] , "Fragment-None" )
  if 12 - 12: OoooooooOO + I1ii11iIi11i
  I1i1iI = self . packet
  if 55 - 55: OOooOOo * II111iiii + oO0o
  if 93 - 93: iII111i * oO0o . OoO0O00 - Ii1I + O0 * OoO0O00
  if 59 - 59: II111iiii
  if 43 - 43: Oo0Ooo + OoooooooOO
  if 47 - 47: ooOoO0o
  if ( self . inner_version != 4 ) :
   o00oOoo0o00 = random . randint ( 0 , 0xffff )
   iIiiI11II11i = I1i1iI [ 0 : 4 ] + struct . pack ( "H" , o00oOoo0o00 ) + I1i1iI [ 6 : 20 ]
   o00OoO0o0 = I1i1iI [ 20 : : ]
   oOo = self . fragment_outer ( iIiiI11II11i , o00OoO0o0 )
   return ( oOo , "Fragment-Outer" )
   if 52 - 52: iII111i . oO0o - Ii1I
   if 85 - 85: I1ii11iIi11i / i1IIi * OoO0O00 . oO0o
   if 60 - 60: I11i
   if 93 - 93: Oo0Ooo
   if 75 - 75: OoOoOO00
  o0oO = 56 if ( self . outer_version == 6 ) else 36
  iIiiI11II11i = I1i1iI [ 0 : o0oO ]
  I1Ii1IIIiII = I1i1iI [ o0oO : o0oO + 20 ]
  o00OoO0o0 = I1i1iI [ o0oO + 20 : : ]
  if 11 - 11: O0 * OoOoOO00
  if 37 - 37: OoOoOO00 + O0 . O0 * Oo0Ooo % I1Ii111 / iII111i
  if 18 - 18: OoooooooOO
  if 57 - 57: ooOoO0o . OoOoOO00 * o0oOOo0O0Ooo - OoooooooOO
  OooO = struct . unpack ( "H" , I1Ii1IIIiII [ 6 : 8 ] ) [ 0 ]
  OooO = socket . ntohs ( OooO )
  if ( OooO & 0x4000 ) :
   Iii = bold ( "DF-bit set" , False )
   dprint ( "{} in inner header, packet discarded" . format ( Iii ) )
   return ( [ ] , "Fragment-None-DF-bit" )
   if 22 - 22: II111iiii * ooOoO0o + I1ii11iIi11i + I11i / OoOoOO00
   if 52 - 52: OoooooooOO / IiII % II111iiii
  O00oOooo0 = 0
  OOo000o = len ( o00OoO0o0 )
  oOo = [ ]
  while ( O00oOooo0 < OOo000o ) :
   oOo . append ( o00OoO0o0 [ O00oOooo0 : O00oOooo0 + 1400 ] )
   O00oOooo0 += 1400
   if 40 - 40: I1IiiI % ooOoO0o % IiII + OoO0O00
   if 75 - 75: oO0o - I1ii11iIi11i + oO0o + OoooooooOO . i11iIiiIii
   if 52 - 52: iII111i / ooOoO0o - i11iIiiIii + OoooooooOO
   if 33 - 33: O0 + Oo0Ooo - iIii1I11I1II1 % i11iIiiIii / I1IiiI
   if 47 - 47: I1ii11iIi11i * oO0o + iIii1I11I1II1 - oO0o / IiII
  IiiI1i111I1i = oOo
  oOo = [ ]
  oO0ooo0O0Ooo = True if OooO & 0x2000 else False
  OooO = ( OooO & 0x1fff ) * 8
  for OOO0OoO0oo0OO in IiiI1i111I1i :
   if 33 - 33: II111iiii - IiII - ooOoO0o
   if 92 - 92: OoO0O00 * IiII
   if 92 - 92: oO0o
   if 7 - 7: iII111i
   oOOoOO0O00o = OooO / 8
   if ( oO0ooo0O0Ooo ) :
    oOOoOO0O00o |= 0x2000
   elif ( OOO0OoO0oo0OO != IiiI1i111I1i [ - 1 ] ) :
    oOOoOO0O00o |= 0x2000
    if 38 - 38: i11iIiiIii . iIii1I11I1II1 . OOooOOo / OoO0O00
   oOOoOO0O00o = socket . htons ( oOOoOO0O00o )
   I1Ii1IIIiII = I1Ii1IIIiII [ 0 : 6 ] + struct . pack ( "H" , oOOoOO0O00o ) + I1Ii1IIIiII [ 8 : : ]
   if 18 - 18: Oo0Ooo * I1Ii111
   if 99 - 99: II111iiii * iIii1I11I1II1 % O0 * oO0o / II111iiii % OoooooooOO
   if 14 - 14: IiII . IiII % ooOoO0o
   if 42 - 42: o0oOOo0O0Ooo . OOooOOo - ooOoO0o
   if 33 - 33: II111iiii / O0 / IiII - I11i - i1IIi
   if 8 - 8: i11iIiiIii . iII111i / iIii1I11I1II1 / I1ii11iIi11i / IiII - Ii1I
   OOo000o = len ( OOO0OoO0oo0OO )
   OooO += OOo000o
   i1I1i1i1I1 = socket . htons ( OOo000o + 20 )
   I1Ii1IIIiII = I1Ii1IIIiII [ 0 : 2 ] + struct . pack ( "H" , i1I1i1i1I1 ) + I1Ii1IIIiII [ 4 : 10 ] + struct . pack ( "H" , 0 ) + I1Ii1IIIiII [ 12 : : ]
   if 32 - 32: o0oOOo0O0Ooo . i1IIi * Oo0Ooo
   I1Ii1IIIiII = lisp_ip_checksum ( I1Ii1IIIiII )
   O0oooo0O = I1Ii1IIIiII + OOO0OoO0oo0OO
   if 15 - 15: i1IIi % OoooooooOO * OOooOOo . II111iiii + O0 * OoO0O00
   if 16 - 16: O0 - O0 / I11i - OoO0O00
   if 30 - 30: o0oOOo0O0Ooo - OoO0O00 + OOooOOo
   if 65 - 65: O0 / II111iiii . iIii1I11I1II1 . oO0o / Oo0Ooo % iIii1I11I1II1
   if 74 - 74: i1IIi / I1IiiI % I1ii11iIi11i / O0 % I11i - OoOoOO00
   OOo000o = len ( O0oooo0O )
   if ( self . outer_version == 4 ) :
    i1I1i1i1I1 = OOo000o + o0oO
    OOo000o += 16
    iIiiI11II11i = iIiiI11II11i [ 0 : 2 ] + struct . pack ( "H" , i1I1i1i1I1 ) + iIiiI11II11i [ 4 : : ]
    if 31 - 31: I1IiiI / OoooooooOO . iIii1I11I1II1 * OoOoOO00 . OoooooooOO + II111iiii
    iIiiI11II11i = lisp_ip_checksum ( iIiiI11II11i )
    O0oooo0O = iIiiI11II11i + O0oooo0O
    O0oooo0O = self . fix_outer_header ( O0oooo0O )
    if 8 - 8: I1ii11iIi11i * I1ii11iIi11i * i1IIi + iII111i . I1ii11iIi11i
    if 100 - 100: OoooooooOO - O0 . I11i / I11i + II111iiii * OoOoOO00
    if 37 - 37: Oo0Ooo
    if 72 - 72: IiII % I1ii11iIi11i * OOooOOo . i11iIiiIii % IiII * OOooOOo
    if 15 - 15: I11i / Oo0Ooo * I11i
   I1111I1Ii = o0oO - 12
   i1I1i1i1I1 = socket . htons ( OOo000o )
   O0oooo0O = O0oooo0O [ 0 : I1111I1Ii ] + struct . pack ( "H" , i1I1i1i1I1 ) + O0oooo0O [ I1111I1Ii + 2 : : ]
   if 68 - 68: OoO0O00 + I1IiiI * o0oOOo0O0Ooo . oO0o + OoOoOO00 + ooOoO0o
   oOo . append ( O0oooo0O )
   if 80 - 80: OoOoOO00 * OOooOOo
  return ( oOo , "Fragment-Inner" )
  if 47 - 47: ooOoO0o
  if 63 - 63: II111iiii / i11iIiiIii % II111iiii . I1ii11iIi11i
 def fix_outer_header ( self , packet ) :
  if 6 - 6: OOooOOo + i11iIiiIii
  if 26 - 26: IiII / Ii1I - OoooooooOO
  if 9 - 9: OoooooooOO * I1ii11iIi11i
  if 9 - 9: Oo0Ooo + iII111i
  if 64 - 64: O0 * I1IiiI / I1IiiI
  if 57 - 57: I1ii11iIi11i / OoooooooOO % I1ii11iIi11i . O0 / I1ii11iIi11i
  if 63 - 63: IiII + iIii1I11I1II1 + I1IiiI + I1Ii111
  if 72 - 72: OoO0O00 + i11iIiiIii + I1ii11iIi11i
  if ( self . outer_version == 4 or self . inner_version == 4 ) :
   if ( lisp_is_macos ( ) ) :
    packet = packet [ 0 : 2 ] + packet [ 3 ] + packet [ 2 ] + packet [ 4 : 6 ] + packet [ 7 ] + packet [ 6 ] + packet [ 8 : : ]
    if 96 - 96: oO0o % i1IIi / o0oOOo0O0Ooo
   else :
    packet = packet [ 0 : 2 ] + packet [ 3 ] + packet [ 2 ] + packet [ 4 : : ]
    if 13 - 13: II111iiii - Oo0Ooo % i11iIiiIii + iII111i
    if 88 - 88: O0 . oO0o % I1IiiI
  return ( packet )
  if 10 - 10: I1IiiI + O0
  if 75 - 75: O0 % iIii1I11I1II1 / OoOoOO00 % OOooOOo / IiII
 def send_packet ( self , lisp_raw_socket , dest ) :
  if ( lisp_flow_logging and dest != self . inner_dest ) : self . log_flow ( True )
  if 31 - 31: i11iIiiIii * OoOoOO00
  dest = dest . print_address_no_iid ( )
  oOo , oOiI1I = self . fragment ( )
  if 6 - 6: OoO0O00
  for O0oooo0O in oOo :
   if ( len ( oOo ) != 1 ) :
    self . packet = O0oooo0O
    self . print_packet ( oOiI1I , True )
    if 99 - 99: o0oOOo0O0Ooo * OOooOOo % oO0o * oO0o + OoooooooOO
    if 82 - 82: I11i / OoOoOO00 - OOooOOo / ooOoO0o
   try : lisp_raw_socket . sendto ( O0oooo0O , ( dest , 0 ) )
   except socket . error , Oo00OOo00O :
    lprint ( "socket.sendto() failed: {}" . format ( Oo00OOo00O ) )
    if 50 - 50: OOooOOo + OoO0O00 . i11iIiiIii + I1ii11iIi11i + i11iIiiIii
    if 31 - 31: oO0o * I1Ii111 . OoOoOO00 * I11i
    if 28 - 28: IiII + I1IiiI - Oo0Ooo % OOooOOo . I11i + I1IiiI
    if 72 - 72: Ii1I / Oo0Ooo / oO0o * OoOoOO00 + OOooOOo
 def send_l2_packet ( self , l2_socket , mac_header ) :
  if ( l2_socket == None ) :
   lprint ( "No layer-2 socket, drop IPv6 packet" )
   return
   if 58 - 58: o0oOOo0O0Ooo % I1IiiI . I1IiiI * OoO0O00 - IiII . OoooooooOO
  if ( mac_header == None ) :
   lprint ( "Could not build MAC header, drop IPv6 packet" )
   return
   if 10 - 10: I1Ii111
   if 48 - 48: iII111i * i1IIi % OoooooooOO * Ii1I * OoO0O00
  I1i1iI = mac_header + self . packet
  if 7 - 7: iII111i . Ii1I . iII111i - I1Ii111
  if 33 - 33: ooOoO0o + OoooooooOO - OoO0O00 / i1IIi / OoooooooOO
  if 82 - 82: I1ii11iIi11i / OOooOOo - iII111i / Oo0Ooo * OoO0O00
  if 55 - 55: OoooooooOO
  if 73 - 73: OoOoOO00 - I1ii11iIi11i % Oo0Ooo + I1ii11iIi11i - O0 . OoO0O00
  if 38 - 38: O0
  if 79 - 79: i1IIi . oO0o
  if 34 - 34: I1Ii111 * II111iiii
  if 71 - 71: IiII
  if 97 - 97: I1ii11iIi11i
  if 86 - 86: Oo0Ooo - OOooOOo . OoOoOO00 . II111iiii * I1IiiI . II111iiii
  l2_socket . write ( I1i1iI )
  return
  if 34 - 34: o0oOOo0O0Ooo . I1Ii111 % IiII - O0 / I1Ii111
  if 91 - 91: i11iIiiIii % I1Ii111 * oO0o - I1ii11iIi11i . I1Ii111
 def bridge_l2_packet ( self , eid , db ) :
  try : iI = db . dynamic_eids [ eid . print_address_no_iid ( ) ]
  except : return
  try : iii = lisp_myinterfaces [ iI . interface ]
  except : return
  try :
   socket = iii . get_bridge_socket ( )
   if ( socket == None ) : return
  except : return
  if 66 - 66: iII111i / i11iIiiIii * O0
  try : socket . send ( self . packet )
  except socket . error , Oo00OOo00O :
   lprint ( "bridge_l2_packet(): socket.send() failed: {}" . format ( Oo00OOo00O ) )
   if 78 - 78: IiII - I11i % O0 - OOooOOo % OoO0O00
   if 43 - 43: OoO0O00
   if 90 - 90: OoooooooOO + O0 + I1ii11iIi11i / I11i / Ii1I * I1ii11iIi11i
 def decode ( self , is_lisp_packet , lisp_ipc_socket , stats ) :
  self . packet_error = ""
  I1i1iI = self . packet
  o0ooooOOoo = len ( I1i1iI )
  ooo = oO0o000oOO = True
  if 27 - 27: O0 - I11i * II111iiii - iIii1I11I1II1 / ooOoO0o
  if 24 - 24: Oo0Ooo / iIii1I11I1II1 % OOooOOo * OoOoOO00 - iIii1I11I1II1
  if 50 - 50: II111iiii
  if 39 - 39: II111iiii . OoOoOO00 - Oo0Ooo * i1IIi . OoooooooOO
  iIIiI = 0
  I1I111iIi = self . lisp_header . get_instance_id ( )
  if ( is_lisp_packet ) :
   O0O0O0OO00oo = struct . unpack ( "B" , I1i1iI [ 0 : 1 ] ) [ 0 ]
   self . outer_version = O0O0O0OO00oo >> 4
   if ( self . outer_version == 4 ) :
    if 39 - 39: IiII % OoOoOO00 * I1ii11iIi11i - OoooooooOO - Oo0Ooo
    if 75 - 75: i11iIiiIii . ooOoO0o % i1IIi . I1IiiI - oO0o + Oo0Ooo
    if 66 - 66: oO0o % I1ii11iIi11i . II111iiii / OoOoOO00 / OoO0O00
    if 47 - 47: iII111i + O0 / II111iiii * I1IiiI - OoooooooOO . Ii1I
    if 28 - 28: oO0o . oO0o . iIii1I11I1II1 . OOooOOo . I1ii11iIi11i * i11iIiiIii
    ooo00O0OOo = struct . unpack ( "H" , I1i1iI [ 10 : 12 ] ) [ 0 ]
    I1i1iI = lisp_ip_checksum ( I1i1iI )
    Oooo0oooo0OoO0o = struct . unpack ( "H" , I1i1iI [ 10 : 12 ] ) [ 0 ]
    if ( Oooo0oooo0OoO0o != 0 ) :
     if ( ooo00O0OOo != 0 or lisp_is_macos ( ) == False ) :
      self . packet_error = "checksum-error"
      if ( stats ) :
       stats [ self . packet_error ] . increment ( o0ooooOOoo )
       if 45 - 45: I1IiiI / iII111i + oO0o + IiII
       if 15 - 15: I1IiiI % OoO0O00
      lprint ( "IPv4 header checksum failed for outer header" )
      if ( lisp_flow_logging ) : self . log_flow ( False )
      return ( None )
      if 66 - 66: oO0o * i11iIiiIii . I1Ii111
      if 92 - 92: oO0o
      if 81 - 81: o0oOOo0O0Ooo % I1IiiI - iII111i / i11iIiiIii
    ooo0oOOOO00Oo = LISP_AFI_IPV4
    O00oOooo0 = 12
    self . outer_tos = struct . unpack ( "B" , I1i1iI [ 1 : 2 ] ) [ 0 ]
    self . outer_ttl = struct . unpack ( "B" , I1i1iI [ 8 : 9 ] ) [ 0 ]
    iIIiI = 20
   elif ( self . outer_version == 6 ) :
    ooo0oOOOO00Oo = LISP_AFI_IPV6
    O00oOooo0 = 8
    Ii1iii1 = struct . unpack ( "H" , I1i1iI [ 0 : 2 ] ) [ 0 ]
    self . outer_tos = ( socket . ntohs ( Ii1iii1 ) >> 4 ) & 0xff
    self . outer_ttl = struct . unpack ( "B" , I1i1iI [ 7 : 8 ] ) [ 0 ]
    iIIiI = 40
   else :
    self . packet_error = "outer-header-error"
    if ( stats ) : stats [ self . packet_error ] . increment ( o0ooooOOoo )
    lprint ( "Cannot decode outer header" )
    return ( None )
    if 37 - 37: iIii1I11I1II1 % I11i / IiII
    if 37 - 37: I1Ii111 - oO0o - OoO0O00
   self . outer_source . afi = ooo0oOOOO00Oo
   self . outer_dest . afi = ooo0oOOOO00Oo
   IiI1IIiiiii = self . outer_source . addr_length ( )
   if 43 - 43: oO0o - IiII % i11iIiiIii * II111iiii . I1Ii111 - I11i
   self . outer_source . unpack_address ( I1i1iI [ O00oOooo0 : O00oOooo0 + IiI1IIiiiii ] )
   O00oOooo0 += IiI1IIiiiii
   self . outer_dest . unpack_address ( I1i1iI [ O00oOooo0 : O00oOooo0 + IiI1IIiiiii ] )
   I1i1iI = I1i1iI [ iIIiI : : ]
   self . outer_source . mask_len = self . outer_source . host_mask_len ( )
   self . outer_dest . mask_len = self . outer_dest . host_mask_len ( )
   if 13 - 13: OoO0O00
   if 70 - 70: IiII . I1Ii111 * OoO0O00 + I11i - IiII . IiII
   if 60 - 60: i11iIiiIii * Oo0Ooo % OoO0O00 + OoO0O00
   if 84 - 84: iIii1I11I1II1 + OoooooooOO
   Oo0OOOOOOO0oo = struct . unpack ( "H" , I1i1iI [ 0 : 2 ] ) [ 0 ]
   self . udp_sport = socket . ntohs ( Oo0OOOOOOO0oo )
   Oo0OOOOOOO0oo = struct . unpack ( "H" , I1i1iI [ 2 : 4 ] ) [ 0 ]
   self . udp_dport = socket . ntohs ( Oo0OOOOOOO0oo )
   Oo0OOOOOOO0oo = struct . unpack ( "H" , I1i1iI [ 4 : 6 ] ) [ 0 ]
   self . udp_length = socket . ntohs ( Oo0OOOOOOO0oo )
   Oo0OOOOOOO0oo = struct . unpack ( "H" , I1i1iI [ 6 : 8 ] ) [ 0 ]
   self . udp_checksum = socket . ntohs ( Oo0OOOOOOO0oo )
   I1i1iI = I1i1iI [ 8 : : ]
   if 35 - 35: I1ii11iIi11i * OoO0O00 * I1IiiI / OoooooooOO
   if 15 - 15: ooOoO0o % o0oOOo0O0Ooo / oO0o - II111iiii . iIii1I11I1II1
   if 28 - 28: II111iiii * ooOoO0o * Ii1I
   if 93 - 93: i1IIi . Ii1I * I1Ii111 . ooOoO0o
   ooo = ( self . udp_dport == LISP_DATA_PORT or
 self . udp_sport == LISP_DATA_PORT )
   oO0o000oOO = ( self . udp_dport in ( LISP_L2_DATA_PORT , LISP_VXLAN_DATA_PORT ) )
   if 54 - 54: iII111i . i1IIi . I1ii11iIi11i * o0oOOo0O0Ooo % iII111i
   if 30 - 30: I11i
   if 85 - 85: II111iiii + ooOoO0o * I11i
   if 12 - 12: Ii1I . I1IiiI % o0oOOo0O0Ooo
   if ( self . lisp_header . decode ( I1i1iI ) == False ) :
    self . packet_error = "lisp-header-error"
    if ( stats ) : stats [ self . packet_error ] . increment ( o0ooooOOoo )
    if 28 - 28: Ii1I - I1IiiI % OoO0O00 * I1Ii111
    if ( lisp_flow_logging ) : self . log_flow ( False )
    lprint ( "Cannot decode LISP header" )
    return ( None )
    if 80 - 80: OOooOOo * IiII
   I1i1iI = I1i1iI [ 8 : : ]
   I1I111iIi = self . lisp_header . get_instance_id ( )
   iIIiI += 16
   if 4 - 4: iIii1I11I1II1 . I1Ii111 + II111iiii % OoooooooOO
  if ( I1I111iIi == 0xffffff ) : I1I111iIi = 0
  if 82 - 82: OoooooooOO / ooOoO0o * I11i * O0 . I1ii11iIi11i
  if 21 - 21: II111iiii + Oo0Ooo
  if 59 - 59: OOooOOo + I1IiiI / II111iiii / OoOoOO00
  if 80 - 80: OoOoOO00 + iIii1I11I1II1 . IiII
  ooOoOoo000O0O = False
  iI11i = self . lisp_header . k_bits
  if ( iI11i ) :
   oO00o = lisp_get_crypto_decap_lookup_key ( self . outer_source ,
 self . udp_sport )
   if ( oO00o == None ) :
    self . packet_error = "no-decrypt-key"
    if ( stats ) : stats [ self . packet_error ] . increment ( o0ooooOOoo )
    if 78 - 78: Oo0Ooo / OoO0O00
    self . print_packet ( "Receive" , is_lisp_packet )
    I1I1i = bold ( "No key available" , False )
    dprint ( "{} for key-id {} to decrypt packet" . format ( I1I1i , iI11i ) )
    if ( lisp_flow_logging ) : self . log_flow ( False )
    return ( None )
    if 41 - 41: i1IIi . I1Ii111 - I1IiiI - oO0o
    if 2 - 2: O0 % I1Ii111 % I1ii11iIi11i % o0oOOo0O0Ooo - Oo0Ooo
   i1i11ii1 = lisp_crypto_keys_by_rloc_decap [ oO00o ] [ iI11i ]
   if ( i1i11ii1 == None ) :
    self . packet_error = "no-decrypt-key"
    if ( stats ) : stats [ self . packet_error ] . increment ( o0ooooOOoo )
    if 95 - 95: i11iIiiIii
    self . print_packet ( "Receive" , is_lisp_packet )
    I1I1i = bold ( "No key available" , False )
    dprint ( "{} to decrypt packet from RLOC {}" . format ( I1I1i ,
 red ( oO00o , False ) ) )
    if ( lisp_flow_logging ) : self . log_flow ( False )
    return ( None )
    if 95 - 95: Oo0Ooo
    if 49 - 49: I1IiiI
    if 24 - 24: II111iiii / Ii1I . iIii1I11I1II1 - II111iiii % O0
    if 8 - 8: OoO0O00 % iII111i . OoooooooOO - Ii1I % OoooooooOO
    if 61 - 61: o0oOOo0O0Ooo / i11iIiiIii
   i1i11ii1 . use_count += 1
   I1i1iI , ooOoOoo000O0O = self . decrypt ( I1i1iI , iIIiI , i1i11ii1 ,
 oO00o )
   if ( ooOoOoo000O0O == False ) :
    if ( stats ) : stats [ self . packet_error ] . increment ( o0ooooOOoo )
    if ( lisp_flow_logging ) : self . log_flow ( False )
    return ( None )
    if 28 - 28: OOooOOo / OoOoOO00
    if 30 - 30: ooOoO0o
    if 57 - 57: o0oOOo0O0Ooo * i11iIiiIii / OoOoOO00
    if 40 - 40: iIii1I11I1II1 - ooOoO0o / Oo0Ooo
    if 24 - 24: oO0o - iII111i / ooOoO0o
    if 10 - 10: OoOoOO00 * i1IIi
  O0O0O0OO00oo = struct . unpack ( "B" , I1i1iI [ 0 : 1 ] ) [ 0 ]
  self . inner_version = O0O0O0OO00oo >> 4
  if ( ooo and self . inner_version == 4 and O0O0O0OO00oo >= 0x45 ) :
   I1Ii1ii = socket . ntohs ( struct . unpack ( "H" , I1i1iI [ 2 : 4 ] ) [ 0 ] )
   self . inner_tos = struct . unpack ( "B" , I1i1iI [ 1 : 2 ] ) [ 0 ]
   self . inner_ttl = struct . unpack ( "B" , I1i1iI [ 8 : 9 ] ) [ 0 ]
   self . inner_source . afi = LISP_AFI_IPV4
   self . inner_dest . afi = LISP_AFI_IPV4
   self . inner_source . unpack_address ( I1i1iI [ 12 : 16 ] )
   self . inner_dest . unpack_address ( I1i1iI [ 16 : 20 ] )
   OooO = socket . ntohs ( struct . unpack ( "H" , I1i1iI [ 6 : 8 ] ) [ 0 ] )
   self . inner_is_fragment = ( OooO & 0x2000 or OooO != 0 )
  elif ( ooo and self . inner_version == 6 and O0O0O0OO00oo >= 0x60 ) :
   I1Ii1ii = socket . ntohs ( struct . unpack ( "H" , I1i1iI [ 4 : 6 ] ) [ 0 ] ) + 40
   Ii1iii1 = struct . unpack ( "H" , I1i1iI [ 0 : 2 ] ) [ 0 ]
   self . inner_tos = ( socket . ntohs ( Ii1iii1 ) >> 4 ) & 0xff
   self . inner_ttl = struct . unpack ( "B" , I1i1iI [ 7 : 8 ] ) [ 0 ]
   self . inner_source . afi = LISP_AFI_IPV6
   self . inner_dest . afi = LISP_AFI_IPV6
   self . inner_source . unpack_address ( I1i1iI [ 8 : 24 ] )
   self . inner_dest . unpack_address ( I1i1iI [ 24 : 40 ] )
  elif ( oO0o000oOO ) :
   I1Ii1ii = len ( I1i1iI )
   self . inner_tos = 0
   self . inner_ttl = 0
   self . inner_source . afi = LISP_AFI_MAC
   self . inner_dest . afi = LISP_AFI_MAC
   self . inner_dest . unpack_address ( self . swap_mac ( I1i1iI [ 0 : 6 ] ) )
   self . inner_source . unpack_address ( self . swap_mac ( I1i1iI [ 6 : 12 ] ) )
  elif ( self . lisp_header . get_instance_id ( ) == 0xffffff ) :
   if ( lisp_flow_logging ) : self . log_flow ( False )
   return ( self )
  else :
   self . packet_error = "bad-inner-version"
   if ( stats ) : stats [ self . packet_error ] . increment ( o0ooooOOoo )
   if 34 - 34: I1IiiI
   lprint ( "Cannot decode encapsulation, header version {}" . format ( hex ( O0O0O0OO00oo ) ) )
   if 57 - 57: OOooOOo . Ii1I % o0oOOo0O0Ooo
   I1i1iI = lisp_format_packet ( I1i1iI [ 0 : 20 ] )
   lprint ( "Packet header: {}" . format ( I1i1iI ) )
   if ( lisp_flow_logging and is_lisp_packet ) : self . log_flow ( False )
   return ( None )
   if 32 - 32: I11i / IiII - O0 * iIii1I11I1II1
  self . inner_source . mask_len = self . inner_source . host_mask_len ( )
  self . inner_dest . mask_len = self . inner_dest . host_mask_len ( )
  self . inner_source . instance_id = I1I111iIi
  self . inner_dest . instance_id = I1I111iIi
  if 70 - 70: OoooooooOO % OoooooooOO % OoO0O00
  if 98 - 98: OoO0O00
  if 18 - 18: I11i + Oo0Ooo - OoO0O00 / I1Ii111 / OOooOOo
  if 53 - 53: OOooOOo + o0oOOo0O0Ooo . oO0o / I11i
  if 52 - 52: I1Ii111 + I1Ii111
  if ( lisp_nonce_echoing and is_lisp_packet ) :
   OO0 = lisp_get_echo_nonce ( self . outer_source , None )
   if ( OO0 == None ) :
    ii1 = self . outer_source . print_address_no_iid ( )
    OO0 = lisp_echo_nonce ( ii1 )
    if 32 - 32: o0oOOo0O0Ooo % I1IiiI
   iII = self . lisp_header . get_nonce ( )
   if ( self . lisp_header . is_e_bit_set ( ) ) :
    OO0 . receive_request ( lisp_ipc_socket , iII )
   elif ( OO0 . request_nonce_sent ) :
    OO0 . receive_echo ( lisp_ipc_socket , iII )
    if 23 - 23: II111iiii * IiII % I1IiiI - oO0o
    if 41 - 41: OOooOOo - O0
    if 16 - 16: II111iiii / Ii1I . Ii1I - Ii1I / I1ii11iIi11i
    if 28 - 28: OOooOOo * OoooooooOO + ooOoO0o % iII111i . iIii1I11I1II1
    if 17 - 17: IiII / o0oOOo0O0Ooo . OOooOOo + o0oOOo0O0Ooo / I1ii11iIi11i . Oo0Ooo
    if 39 - 39: o0oOOo0O0Ooo / IiII - iII111i
    if 96 - 96: I11i * I1ii11iIi11i * Ii1I + I1ii11iIi11i % I1IiiI + i11iIiiIii
  if ( ooOoOoo000O0O ) : self . packet += I1i1iI [ : I1Ii1ii ]
  if 37 - 37: I11i % I1ii11iIi11i / ooOoO0o
  if 94 - 94: I11i / OoO0O00 . o0oOOo0O0Ooo
  if 1 - 1: Oo0Ooo . II111iiii
  if 93 - 93: II111iiii . i11iIiiIii + II111iiii % oO0o
  if ( lisp_flow_logging and is_lisp_packet ) : self . log_flow ( False )
  return ( self )
  if 98 - 98: I1Ii111 * oO0o * OoOoOO00 + Ii1I * iII111i
  if 4 - 4: IiII
 def swap_mac ( self , mac ) :
  return ( mac [ 1 ] + mac [ 0 ] + mac [ 3 ] + mac [ 2 ] + mac [ 5 ] + mac [ 4 ] )
  if 16 - 16: iIii1I11I1II1 * iII111i + oO0o . O0 . o0oOOo0O0Ooo
  if 99 - 99: i11iIiiIii - iII111i
 def strip_outer_headers ( self ) :
  O00oOooo0 = 16
  O00oOooo0 += 20 if ( self . outer_version == 4 ) else 40
  self . packet = self . packet [ O00oOooo0 : : ]
  return ( self )
  if 85 - 85: I1Ii111 % I1ii11iIi11i
  if 95 - 95: OoO0O00 * OOooOOo * iII111i . o0oOOo0O0Ooo
 def hash_ports ( self ) :
  I1i1iI = self . packet
  O0O0O0OO00oo = self . inner_version
  oooOo00 = 0
  if ( O0O0O0OO00oo == 4 ) :
   iII1II = struct . unpack ( "B" , I1i1iI [ 9 ] ) [ 0 ]
   if ( self . inner_is_fragment ) : return ( iII1II )
   if ( iII1II in [ 6 , 17 ] ) :
    oooOo00 = iII1II
    oooOo00 += struct . unpack ( "I" , I1i1iI [ 20 : 24 ] ) [ 0 ]
    oooOo00 = ( oooOo00 >> 16 ) ^ ( oooOo00 & 0xffff )
    if 12 - 12: I11i
    if 19 - 19: Ii1I * i1IIi % O0 + I11i
  if ( O0O0O0OO00oo == 6 ) :
   iII1II = struct . unpack ( "B" , I1i1iI [ 6 ] ) [ 0 ]
   if ( iII1II in [ 6 , 17 ] ) :
    oooOo00 = iII1II
    oooOo00 += struct . unpack ( "I" , I1i1iI [ 40 : 44 ] ) [ 0 ]
    oooOo00 = ( oooOo00 >> 16 ) ^ ( oooOo00 & 0xffff )
    if 25 - 25: I1Ii111 - Ii1I / O0 . OoooooooOO % I1IiiI . i1IIi
    if 19 - 19: II111iiii / II111iiii % I1ii11iIi11i + oO0o + oO0o + iII111i
  return ( oooOo00 )
  if 4 - 4: o0oOOo0O0Ooo + I11i / iII111i + i1IIi % o0oOOo0O0Ooo % iII111i
  if 80 - 80: Ii1I
 def hash_packet ( self ) :
  oooOo00 = self . inner_source . address ^ self . inner_dest . address
  oooOo00 += self . hash_ports ( )
  if ( self . inner_version == 4 ) :
   oooOo00 = ( oooOo00 >> 16 ) ^ ( oooOo00 & 0xffff )
  elif ( self . inner_version == 6 ) :
   oooOo00 = ( oooOo00 >> 64 ) ^ ( oooOo00 & 0xffffffffffffffff )
   oooOo00 = ( oooOo00 >> 32 ) ^ ( oooOo00 & 0xffffffff )
   oooOo00 = ( oooOo00 >> 16 ) ^ ( oooOo00 & 0xffff )
   if 26 - 26: iIii1I11I1II1 . OoooooooOO - iIii1I11I1II1
  self . udp_sport = 0xf000 | ( oooOo00 & 0xfff )
  if 59 - 59: I1ii11iIi11i + I11i . oO0o
  if 87 - 87: OoO0O00
 def print_packet ( self , s_or_r , is_lisp_packet ) :
  if ( is_lisp_packet == False ) :
   I1ii1 = "{} -> {}" . format ( self . inner_source . print_address ( ) ,
 self . inner_dest . print_address ( ) )
   dprint ( ( "{} {}, tos/ttl: {}/{}, length: {}, packet: {} ..." ) . format ( bold ( s_or_r , False ) ,
   # OoO0O00 - iII111i + II111iiii
 green ( I1ii1 , False ) , self . inner_tos ,
 self . inner_ttl , len ( self . packet ) ,
 lisp_format_packet ( self . packet [ 0 : 60 ] ) ) )
   return
   if 38 - 38: I1IiiI % IiII * Ii1I
   if 91 - 91: Ii1I + OoO0O00 * o0oOOo0O0Ooo . I1Ii111
  if ( s_or_r . find ( "Receive" ) != - 1 ) :
   Oo00oo00o00Oo = "decap"
   Oo00oo00o00Oo += "-vxlan" if self . udp_dport == LISP_VXLAN_DATA_PORT else ""
  else :
   Oo00oo00o00Oo = s_or_r
   if ( Oo00oo00o00Oo in [ "Send" , "Replicate" ] or Oo00oo00o00Oo . find ( "Fragment" ) != - 1 ) :
    Oo00oo00o00Oo = "encap"
    if 1 - 1: IiII
    if 31 - 31: i1IIi
  i11I = "{} -> {}" . format ( self . outer_source . print_address_no_iid ( ) ,
 self . outer_dest . print_address_no_iid ( ) )
  if 48 - 48: OOooOOo + I1Ii111 % OOooOOo
  if 84 - 84: O0 % Ii1I . Ii1I . iII111i * I11i
  if 43 - 43: OoOoOO00 . I1ii11iIi11i % i1IIi
  if 61 - 61: I1IiiI + oO0o % I1Ii111 % iIii1I11I1II1 - OoooooooOO
  if 22 - 22: OOooOOo + II111iiii + Oo0Ooo
  if ( self . lisp_header . get_instance_id ( ) == 0xffffff ) :
   ii1II1II = ( "{} LISP packet, outer RLOCs: {}, outer tos/ttl: " + "{}/{}, outer UDP: {} -> {}, " )
   if 83 - 83: ooOoO0o
   ii1II1II += bold ( "control-packet" , False ) + ": {} ..."
   if 43 - 43: OOooOOo
   dprint ( ii1II1II . format ( bold ( s_or_r , False ) , red ( i11I , False ) ,
 self . outer_tos , self . outer_ttl , self . udp_sport ,
 self . udp_dport , lisp_format_packet ( self . packet [ 0 : 56 ] ) ) )
   return
  else :
   ii1II1II = ( "{} LISP packet, outer RLOCs: {}, outer tos/ttl: " + "{}/{}, outer UDP: {} -> {}, inner EIDs: {}, " + "inner tos/ttl: {}/{}, length: {}, {}, packet: {} ..." )
   if 84 - 84: OOooOOo . IiII . iII111i
   if 2 - 2: Oo0Ooo - OoOoOO00
   if 49 - 49: Ii1I + II111iiii / oO0o - OoOoOO00 % OoOoOO00 + I1IiiI
   if 54 - 54: ooOoO0o % Oo0Ooo - OOooOOo
  if ( self . lisp_header . k_bits ) :
   if ( Oo00oo00o00Oo == "encap" ) : Oo00oo00o00Oo = "encrypt/encap"
   if ( Oo00oo00o00Oo == "decap" ) : Oo00oo00o00Oo = "decap/decrypt"
   if 16 - 16: I1ii11iIi11i * iII111i / I11i
   if 46 - 46: II111iiii
  I1ii1 = "{} -> {}" . format ( self . inner_source . print_address ( ) ,
 self . inner_dest . print_address ( ) )
  if 13 - 13: IiII + II111iiii % I1IiiI
  dprint ( ii1II1II . format ( bold ( s_or_r , False ) , red ( i11I , False ) ,
 self . outer_tos , self . outer_ttl , self . udp_sport , self . udp_dport ,
 green ( I1ii1 , False ) , self . inner_tos , self . inner_ttl ,
 len ( self . packet ) , self . lisp_header . print_header ( Oo00oo00o00Oo ) ,
 lisp_format_packet ( self . packet [ 0 : 56 ] ) ) )
  if 30 - 30: OoooooooOO - i11iIiiIii + oO0o / Oo0Ooo - i11iIiiIii
  if 74 - 74: O0 . I11i
 def print_eid_tuple ( self ) :
  return ( lisp_print_eid_tuple ( self . inner_source , self . inner_dest ) )
  if 64 - 64: ooOoO0o / i1IIi % iII111i
  if 84 - 84: OoOoOO00 - Oo0Ooo . ooOoO0o . IiII - Oo0Ooo
 def get_raw_socket ( self ) :
  I1I111iIi = str ( self . lisp_header . get_instance_id ( ) )
  if ( I1I111iIi == "0" ) : return ( None )
  if ( lisp_iid_to_interface . has_key ( I1I111iIi ) == False ) : return ( None )
  if 99 - 99: I1Ii111
  iii = lisp_iid_to_interface [ I1I111iIi ]
  I11iiIi1i1 = iii . get_socket ( )
  if ( I11iiIi1i1 == None ) :
   oOO00OO0OooOo = bold ( "SO_BINDTODEVICE" , False )
   o0I1IiiiiI1i1I = ( os . getenv ( "LISP_ENFORCE_BINDTODEVICE" ) != None )
   lprint ( "{} required for multi-tenancy support, {} packet" . format ( oOO00OO0OooOo , "drop" if o0I1IiiiiI1i1I else "forward" ) )
   if 48 - 48: I11i + II111iiii % oO0o % OOooOOo * II111iiii
   if ( o0I1IiiiiI1i1I ) : return ( None )
   if 41 - 41: OoO0O00
   if 13 - 13: ooOoO0o - I1IiiI
  I1I111iIi = bold ( I1I111iIi , False )
  I1 = bold ( iii . device , False )
  dprint ( "Send packet on instance-id {} interface {}" . format ( I1I111iIi , I1 ) )
  return ( I11iiIi1i1 )
  if 23 - 23: I1IiiI
  if 7 - 7: iII111i % I1ii11iIi11i
 def log_flow ( self , encap ) :
  global lisp_flow_log
  if 64 - 64: I1Ii111 + i11iIiiIii
  iI1i11i = os . path . exists ( "./log-flows" )
  if ( len ( lisp_flow_log ) == LISP_FLOW_LOG_SIZE or iI1i11i ) :
   IIIIi1Iii1iIi = [ lisp_flow_log ]
   lisp_flow_log = [ ]
   threading . Thread ( target = lisp_write_flow_log , args = IIIIi1Iii1iIi ) . start ( )
   if ( iI1i11i ) : os . system ( "rm ./log-flows" )
   return
   if 36 - 36: i11iIiiIii * I1ii11iIi11i * OoOoOO00
   if 24 - 24: oO0o . O0 * ooOoO0o / OoooooooOO - Ii1I . I11i
  iII1i1 = datetime . datetime . now ( )
  lisp_flow_log . append ( [ iII1i1 , encap , self . packet , self ] )
  if 41 - 41: OoO0O00 % I1IiiI - Oo0Ooo
  if 11 - 11: Ii1I * o0oOOo0O0Ooo / IiII + OoOoOO00 + OoO0O00 % I1Ii111
 def print_flow ( self , ts , encap , packet ) :
  ts = ts . strftime ( "%m/%d/%y %H:%M:%S.%f" ) [ : - 3 ]
  iIIi1II1 = "{}: {}" . format ( ts , "encap" if encap else "decap" )
  if 42 - 42: iIii1I11I1II1 - ooOoO0o - I11i - I1Ii111
  iIiI11II = red ( self . outer_source . print_address_no_iid ( ) , False )
  OO0Iii1iIiI111Ii = red ( self . outer_dest . print_address_no_iid ( ) , False )
  ooO0oo0000oOo = green ( self . inner_source . print_address ( ) , False )
  oOOoO0oO00O = green ( self . inner_dest . print_address ( ) , False )
  if 72 - 72: OoO0O00 - iIii1I11I1II1 . iII111i / Ii1I
  if ( self . lisp_header . get_instance_id ( ) == 0xffffff ) :
   iIIi1II1 += " {}:{} -> {}:{}, LISP control message type {}\n"
   iIIi1II1 = iIIi1II1 . format ( iIiI11II , self . udp_sport , OO0Iii1iIiI111Ii , self . udp_dport ,
 self . inner_version )
   return ( iIIi1II1 )
   if 12 - 12: I1IiiI + I1Ii111
   if 80 - 80: oO0o . O0
  if ( self . outer_dest . is_null ( ) == False ) :
   iIIi1II1 += " {}:{} -> {}:{}, len/tos/ttl {}/{}/{}"
   iIIi1II1 = iIIi1II1 . format ( iIiI11II , self . udp_sport , OO0Iii1iIiI111Ii , self . udp_dport ,
 len ( packet ) , self . outer_tos , self . outer_ttl )
   if 90 - 90: II111iiii / OoO0O00 / Ii1I
   if 70 - 70: Ii1I - II111iiii . Oo0Ooo / Oo0Ooo
   if 30 - 30: oO0o . OoO0O00 + I11i / iIii1I11I1II1 % Oo0Ooo / oO0o
   if 3 - 3: I1ii11iIi11i / II111iiii
   if 73 - 73: OoO0O00 * OoooooooOO - OoooooooOO + I1IiiI * Oo0Ooo
  if ( self . lisp_header . k_bits != 0 ) :
   oOo0 = "\n"
   if ( self . packet_error != "" ) :
    oOo0 = " ({})" . format ( self . packet_error ) + oOo0
    if 2 - 2: I1IiiI + II111iiii / Ii1I % Oo0Ooo - I1Ii111 + I1Ii111
   iIIi1II1 += ", encrypted" + oOo0
   return ( iIIi1II1 )
   if 84 - 84: o0oOOo0O0Ooo % i1IIi / Oo0Ooo - I1IiiI . I1ii11iIi11i . o0oOOo0O0Ooo
   if 75 - 75: O0 * i1IIi - I11i / OOooOOo % OOooOOo / OoOoOO00
   if 5 - 5: O0 - iII111i / I1Ii111 . o0oOOo0O0Ooo
   if 7 - 7: I1ii11iIi11i - OoOoOO00
   if 54 - 54: oO0o / iIii1I11I1II1 / OoooooooOO . i1IIi - OoOoOO00
  if ( self . outer_dest . is_null ( ) == False ) :
   packet = packet [ 36 : : ] if self . outer_version == 4 else packet [ 56 : : ]
   if 57 - 57: iIii1I11I1II1 * Ii1I * iII111i / oO0o
   if 46 - 46: Ii1I
  iII1II = packet [ 9 ] if self . inner_version == 4 else packet [ 6 ]
  iII1II = struct . unpack ( "B" , iII1II ) [ 0 ]
  if 61 - 61: o0oOOo0O0Ooo / ooOoO0o - II111iiii
  iIIi1II1 += " {} -> {}, len/tos/ttl/prot {}/{}/{}/{}"
  iIIi1II1 = iIIi1II1 . format ( ooO0oo0000oOo , oOOoO0oO00O , len ( packet ) , self . inner_tos ,
 self . inner_ttl , iII1II )
  if 87 - 87: I1ii11iIi11i / I1IiiI
  if 45 - 45: OoOoOO00 * ooOoO0o / OoooooooOO + OoO0O00 . I1Ii111 / OoO0O00
  if 64 - 64: Ii1I / i1IIi % I1IiiI - o0oOOo0O0Ooo
  if 11 - 11: I1ii11iIi11i - OoooooooOO
  if ( iII1II in [ 6 , 17 ] ) :
   I1Ii11I11i1 = packet [ 20 : 24 ] if self . inner_version == 4 else packet [ 40 : 44 ]
   if ( len ( I1Ii11I11i1 ) == 4 ) :
    I1Ii11I11i1 = socket . ntohl ( struct . unpack ( "I" , I1Ii11I11i1 ) [ 0 ] )
    iIIi1II1 += ", ports {} -> {}" . format ( I1Ii11I11i1 >> 16 , I1Ii11I11i1 & 0xffff )
    if 48 - 48: iIii1I11I1II1 / Oo0Ooo + OoO0O00 % Oo0Ooo + Ii1I + OoO0O00
  elif ( iII1II == 1 ) :
   o00o0o0oOo0 = packet [ 26 : 28 ] if self . inner_version == 4 else packet [ 46 : 48 ]
   if ( len ( o00o0o0oOo0 ) == 2 ) :
    o00o0o0oOo0 = socket . ntohs ( struct . unpack ( "H" , o00o0o0oOo0 ) [ 0 ] )
    iIIi1II1 += ", icmp-seq {}" . format ( o00o0o0oOo0 )
    if 33 - 33: i1IIi / IiII - i1IIi . I1IiiI
    if 48 - 48: ooOoO0o + OOooOOo . I1Ii111 % II111iiii + oO0o
  if ( self . packet_error != "" ) :
   iIIi1II1 += " ({})" . format ( self . packet_error )
   if 38 - 38: oO0o
  iIIi1II1 += "\n"
  return ( iIIi1II1 )
  if 28 - 28: iIii1I11I1II1 * I11i . I1IiiI
  if 78 - 78: OoooooooOO . OoooooooOO / O0
  if 25 - 25: II111iiii % II111iiii - Ii1I . O0
  if 79 - 79: IiII / OoO0O00 * OoooooooOO * OoOoOO00 + I1IiiI
  if 68 - 68: I11i / iIii1I11I1II1 . Oo0Ooo + i11iIiiIii + o0oOOo0O0Ooo
  if 92 - 92: OoO0O00 . o0oOOo0O0Ooo . Ii1I % OoOoOO00
  if 58 - 58: I1ii11iIi11i % Ii1I * Ii1I - iII111i
  if 9 - 9: ooOoO0o - Ii1I % II111iiii + IiII + OOooOOo % O0
  if 65 - 65: OOooOOo - OoO0O00 % i11iIiiIii
  if 58 - 58: iII111i
  if 2 - 2: II111iiii + i1IIi
  if 68 - 68: OOooOOo + Ii1I
  if 58 - 58: IiII * Ii1I . i1IIi
  if 19 - 19: oO0o
  if 85 - 85: ooOoO0o - I1IiiI / i1IIi / OoO0O00 / II111iiii
  if 94 - 94: iIii1I11I1II1 + IiII
LISP_N_BIT = 0x80000000
LISP_L_BIT = 0x40000000
LISP_E_BIT = 0x20000000
LISP_V_BIT = 0x10000000
LISP_I_BIT = 0x08000000
LISP_P_BIT = 0x04000000
LISP_K_BITS = 0x03000000
if 44 - 44: OoO0O00 + I11i % OoO0O00 + i1IIi + iII111i + O0
class lisp_data_header ( ) :
 def __init__ ( self ) :
  self . first_long = 0
  self . second_long = 0
  self . k_bits = 0
  if 18 - 18: iIii1I11I1II1 % iIii1I11I1II1 % oO0o + I1IiiI % ooOoO0o / Ii1I
  if 36 - 36: OoOoOO00 . i11iIiiIii
 def print_header ( self , e_or_d ) :
  oO00O0o0oOOO = lisp_hex_string ( self . first_long & 0xffffff )
  ooooOoo00 = lisp_hex_string ( self . second_long ) . zfill ( 8 )
  if 7 - 7: OOooOOo * OoO0O00 + OoooooooOO . ooOoO0o * I11i
  ii1II1II = ( "{} LISP-header -> flags: {}{}{}{}{}{}{}{}, nonce: {}, " + "iid/lsb: {}" )
  if 82 - 82: iIii1I11I1II1 * OoooooooOO
  return ( ii1II1II . format ( bold ( e_or_d , False ) ,
 "N" if ( self . first_long & LISP_N_BIT ) else "n" ,
 "L" if ( self . first_long & LISP_L_BIT ) else "l" ,
 "E" if ( self . first_long & LISP_E_BIT ) else "e" ,
 "V" if ( self . first_long & LISP_V_BIT ) else "v" ,
 "I" if ( self . first_long & LISP_I_BIT ) else "i" ,
 "P" if ( self . first_long & LISP_P_BIT ) else "p" ,
 "K" if ( self . k_bits in [ 2 , 3 ] ) else "k" ,
 "K" if ( self . k_bits in [ 1 , 3 ] ) else "k" ,
 oO00O0o0oOOO , ooooOoo00 ) )
  if 50 - 50: I1Ii111 - II111iiii
  if 33 - 33: IiII / IiII . i11iIiiIii * I1ii11iIi11i + o0oOOo0O0Ooo
 def encode ( self ) :
  ii1iI11IiIIi = "II"
  oO00O0o0oOOO = socket . htonl ( self . first_long )
  ooooOoo00 = socket . htonl ( self . second_long )
  if 47 - 47: OOooOOo . oO0o + OoOoOO00 % IiII % i1IIi / iIii1I11I1II1
  oo = struct . pack ( ii1iI11IiIIi , oO00O0o0oOOO , ooooOoo00 )
  return ( oo )
  if 41 - 41: i1IIi . OOooOOo / ooOoO0o / o0oOOo0O0Ooo % IiII - Ii1I
  if 14 - 14: I1ii11iIi11i - i11iIiiIii * I1Ii111
 def decode ( self , packet ) :
  ii1iI11IiIIi = "II"
  iiii = struct . calcsize ( ii1iI11IiIIi )
  if ( len ( packet ) < iiii ) : return ( False )
  if 80 - 80: I1IiiI
  oO00O0o0oOOO , ooooOoo00 = struct . unpack ( ii1iI11IiIIi , packet [ : iiii ] )
  if 58 - 58: oO0o + I1ii11iIi11i % OoOoOO00
  if 22 - 22: iIii1I11I1II1 - Ii1I / I1IiiI * IiII
  self . first_long = socket . ntohl ( oO00O0o0oOOO )
  self . second_long = socket . ntohl ( ooooOoo00 )
  self . k_bits = ( self . first_long & LISP_K_BITS ) >> 24
  return ( True )
  if 26 - 26: o0oOOo0O0Ooo + OOooOOo - o0oOOo0O0Ooo + Oo0Ooo . oO0o
  if 97 - 97: i1IIi
 def key_id ( self , key_id ) :
  self . first_long &= ~ ( 0x3 << 24 )
  self . first_long |= ( ( key_id & 0x3 ) << 24 )
  self . k_bits = key_id
  if 46 - 46: I1ii11iIi11i
  if 30 - 30: OoO0O00 / O0 * o0oOOo0O0Ooo * I1Ii111 + OoooooooOO * iII111i
 def nonce ( self , nonce ) :
  self . first_long |= LISP_N_BIT
  self . first_long |= nonce
  if 23 - 23: I11i
  if 36 - 36: IiII . iII111i - i1IIi + I1Ii111
 def map_version ( self , version ) :
  self . first_long |= LISP_V_BIT
  self . first_long |= version
  if 54 - 54: OoooooooOO . oO0o - iII111i
  if 76 - 76: I1Ii111
 def instance_id ( self , iid ) :
  if ( iid == 0 ) : return
  self . first_long |= LISP_I_BIT
  self . second_long &= 0xff
  self . second_long |= ( iid << 8 )
  if 61 - 61: ooOoO0o / II111iiii * ooOoO0o * OoOoOO00 * I1Ii111 . i11iIiiIii
  if 26 - 26: I1Ii111 / ooOoO0o - OoO0O00 . iIii1I11I1II1
 def get_instance_id ( self ) :
  return ( ( self . second_long >> 8 ) & 0xffffff )
  if 83 - 83: ooOoO0o % Ii1I / Oo0Ooo - iII111i / O0
  if 97 - 97: iIii1I11I1II1 * I11i
 def locator_status_bits ( self , lsbs ) :
  self . first_long |= LISP_L_BIT
  self . second_long &= 0xffffff00
  self . second_long |= ( lsbs & 0xff )
  if 95 - 95: OoO0O00
  if 68 - 68: iIii1I11I1II1 . iIii1I11I1II1 / OoOoOO00 - II111iiii - iIii1I11I1II1
 def is_request_nonce ( self , nonce ) :
  return ( nonce & 0x80000000 )
  if 75 - 75: ooOoO0o . I1IiiI * II111iiii
  if 99 - 99: iIii1I11I1II1 * I1ii11iIi11i + IiII
 def request_nonce ( self , nonce ) :
  self . first_long |= LISP_E_BIT
  self . first_long |= LISP_N_BIT
  self . first_long |= ( nonce & 0xffffff )
  if 70 - 70: i1IIi % ooOoO0o . I1ii11iIi11i - IiII + OOooOOo
  if 84 - 84: oO0o + II111iiii * II111iiii % o0oOOo0O0Ooo / iII111i + ooOoO0o
 def is_e_bit_set ( self ) :
  return ( self . first_long & LISP_E_BIT )
  if 9 - 9: iII111i
  if 25 - 25: OOooOOo - Ii1I . I11i
 def get_nonce ( self ) :
  return ( self . first_long & 0xffffff )
  if 57 - 57: o0oOOo0O0Ooo + Oo0Ooo * I1ii11iIi11i - ooOoO0o % iIii1I11I1II1 - Ii1I
  if 37 - 37: OoO0O00 * I11i + Ii1I + I1ii11iIi11i * o0oOOo0O0Ooo
  if 95 - 95: Ii1I - i11iIiiIii % i11iIiiIii - O0 * I1Ii111
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
  if 81 - 81: II111iiii * I1IiiI % i1IIi * i11iIiiIii + OoOoOO00
  if 100 - 100: i1IIi % Ii1I
 def send_ipc ( self , ipc_socket , ipc ) :
  oO000O = "lisp-itr" if lisp_i_am_itr else "lisp-etr"
  Oo0o0OoOoOo0 = "lisp-etr" if lisp_i_am_itr else "lisp-itr"
  ipc = lisp_command_ipc ( ipc , oO000O )
  lisp_ipc ( ipc , ipc_socket , Oo0o0OoOoOo0 )
  if 36 - 36: Ii1I * I1IiiI * I1ii11iIi11i . I11i * I1ii11iIi11i
  if 76 - 76: OOooOOo + O0 / IiII - OoO0O00
 def send_request_ipc ( self , ipc_socket , nonce ) :
  nonce = lisp_hex_string ( nonce )
  II1i111i = "nonce%R%{}%{}" . format ( self . rloc_str , nonce )
  self . send_ipc ( ipc_socket , II1i111i )
  if 58 - 58: ooOoO0o
  if 45 - 45: o0oOOo0O0Ooo
 def send_echo_ipc ( self , ipc_socket , nonce ) :
  nonce = lisp_hex_string ( nonce )
  II1i111i = "nonce%E%{}%{}" . format ( self . rloc_str , nonce )
  self . send_ipc ( ipc_socket , II1i111i )
  if 67 - 67: iII111i + ooOoO0o
  if 25 - 25: i1IIi - i11iIiiIii
 def receive_request ( self , ipc_socket , nonce ) :
  i1IIII1II = self . request_nonce_rcvd
  self . request_nonce_rcvd = nonce
  self . last_request_nonce_rcvd = lisp_get_timestamp ( )
  if ( lisp_i_am_rtr ) : return
  if ( i1IIII1II != nonce ) : self . send_request_ipc ( ipc_socket , nonce )
  if 89 - 89: I11i % iII111i * Oo0Ooo / I1Ii111 * Oo0Ooo / ooOoO0o
  if 14 - 14: i1IIi * iIii1I11I1II1 - Ii1I * OoOoOO00 - iII111i / oO0o
 def receive_echo ( self , ipc_socket , nonce ) :
  if ( self . request_nonce_sent != nonce ) : return
  self . last_echo_nonce_rcvd = lisp_get_timestamp ( )
  if ( self . echo_nonce_rcvd == nonce ) : return
  if 73 - 73: I1ii11iIi11i - OoOoOO00 * O0 - OoOoOO00 - OoO0O00
  self . echo_nonce_rcvd = nonce
  if ( lisp_i_am_rtr ) : return
  self . send_echo_ipc ( ipc_socket , nonce )
  if 96 - 96: I1ii11iIi11i - O0
  if 35 - 35: OOooOOo . I11i . I1Ii111 - I11i % I11i + I1Ii111
 def get_request_or_echo_nonce ( self , ipc_socket , remote_rloc ) :
  if 99 - 99: o0oOOo0O0Ooo + OOooOOo
  if 34 - 34: I1Ii111 * o0oOOo0O0Ooo . I1IiiI % i11iIiiIii
  if 61 - 61: iIii1I11I1II1 + oO0o * I11i - i1IIi % oO0o
  if 76 - 76: oO0o / OoOoOO00
  if 12 - 12: I1Ii111
  if ( self . request_nonce_sent and self . echo_nonce_sent and remote_rloc ) :
   OO0oOo = lisp_myrlocs [ 0 ] if remote_rloc . is_ipv4 ( ) else lisp_myrlocs [ 1 ]
   if 36 - 36: OoOoOO00 * OoO0O00 / ooOoO0o / I1IiiI - Ii1I
   if 53 - 53: oO0o
   if ( remote_rloc . address > OO0oOo . address ) :
    I11IIIiIi11 = "exit"
    self . request_nonce_sent = None
   else :
    I11IIIiIi11 = "stay in"
    self . echo_nonce_sent = None
    if 99 - 99: Oo0Ooo
    if 17 - 17: i11iIiiIii - i11iIiiIii + I1ii11iIi11i * ooOoO0o * oO0o / OoooooooOO
   i1II111ii1ii = bold ( "collision" , False )
   i1I1i1i1I1 = red ( OO0oOo . print_address_no_iid ( ) , False )
   O0ooOoO0OO000 = red ( remote_rloc . print_address_no_iid ( ) , False )
   lprint ( "Echo nonce {}, {} -> {}, {} request-nonce mode" . format ( i1II111ii1ii ,
 i1I1i1i1I1 , O0ooOoO0OO000 , I11IIIiIi11 ) )
   if 93 - 93: OoO0O00 + I1ii11iIi11i . Oo0Ooo + i1IIi
   if 82 - 82: Oo0Ooo + I1Ii111
   if 93 - 93: I11i * O0 * OOooOOo - o0oOOo0O0Ooo / I1ii11iIi11i
   if 54 - 54: i1IIi - OoO0O00 / OoooooooOO
   if 95 - 95: O0 + iIii1I11I1II1 . I1ii11iIi11i
  if ( self . echo_nonce_sent != None ) :
   iII = self . echo_nonce_sent
   Oo00OOo00O = bold ( "Echoing" , False )
   lprint ( "{} nonce 0x{} to {}" . format ( Oo00OOo00O ,
 lisp_hex_string ( iII ) , red ( self . rloc_str , False ) ) )
   self . last_echo_nonce_sent = lisp_get_timestamp ( )
   self . echo_nonce_sent = None
   return ( iII )
   if 61 - 61: Ii1I * Ii1I
   if 70 - 70: I1Ii111 . I1ii11iIi11i / o0oOOo0O0Ooo * oO0o
   if 74 - 74: I1IiiI . ooOoO0o / iII111i . IiII
   if 74 - 74: Oo0Ooo / I1Ii111 % I1Ii111 . IiII
   if 72 - 72: i1IIi
   if 21 - 21: I1Ii111 . OOooOOo / i11iIiiIii * i1IIi
   if 82 - 82: ooOoO0o * Oo0Ooo % i11iIiiIii * i1IIi . OOooOOo
  iII = self . request_nonce_sent
  o0Oo00o0 = self . last_request_nonce_sent
  if ( iII and o0Oo00o0 != None ) :
   if ( time . time ( ) - o0Oo00o0 >= LISP_NONCE_ECHO_INTERVAL ) :
    self . request_nonce_sent = None
    lprint ( "Stop request-nonce mode for {}, nonce 0x{}" . format ( red ( self . rloc_str , False ) , lisp_hex_string ( iII ) ) )
    if 42 - 42: I1Ii111 / OoOoOO00 % oO0o
    return ( None )
    if 63 - 63: OoO0O00 % i1IIi - oO0o
    if 12 - 12: OoooooooOO + I1Ii111 / OOooOOo / Oo0Ooo * II111iiii - I1ii11iIi11i
    if 11 - 11: iII111i
    if 89 - 89: OoOoOO00 - ooOoO0o . iIii1I11I1II1 + iII111i / Ii1I / iII111i
    if 25 - 25: iIii1I11I1II1 + i11iIiiIii - Ii1I * OoooooooOO
    if 22 - 22: I1Ii111 - I1IiiI
    if 96 - 96: i1IIi + Oo0Ooo - II111iiii . OoooooooOO . OOooOOo / OoO0O00
    if 88 - 88: i1IIi
    if 53 - 53: ooOoO0o . OOooOOo . o0oOOo0O0Ooo + oO0o
  if ( iII == None ) :
   iII = lisp_get_data_nonce ( )
   if ( self . recently_requested ( ) ) : return ( iII )
   if 17 - 17: iIii1I11I1II1 + i1IIi . I1ii11iIi11i + Ii1I % i1IIi . oO0o
   self . request_nonce_sent = iII
   lprint ( "Start request-nonce mode for {}, nonce 0x{}" . format ( red ( self . rloc_str , False ) , lisp_hex_string ( iII ) ) )
   if 57 - 57: oO0o
   self . last_new_request_nonce_sent = lisp_get_timestamp ( )
   if 92 - 92: II111iiii - OoO0O00 - OOooOOo % I1IiiI - OoOoOO00 * I1Ii111
   if 16 - 16: iIii1I11I1II1 + OoooooooOO - ooOoO0o * IiII
   if 37 - 37: iII111i
   if 15 - 15: o0oOOo0O0Ooo % OoO0O00 / iII111i
   if 36 - 36: OoO0O00 + OoO0O00 % Oo0Ooo + Oo0Ooo / i1IIi % i1IIi
   if ( lisp_i_am_itr == False ) : return ( iII | 0x80000000 )
   self . send_request_ipc ( ipc_socket , iII )
  else :
   lprint ( "Continue request-nonce mode for {}, nonce 0x{}" . format ( red ( self . rloc_str , False ) , lisp_hex_string ( iII ) ) )
   if 20 - 20: OOooOOo * oO0o
   if 91 - 91: OoO0O00 % i1IIi - iIii1I11I1II1 . OOooOOo
   if 31 - 31: oO0o % i1IIi . OoooooooOO - o0oOOo0O0Ooo + OoooooooOO
   if 45 - 45: OOooOOo + I11i / OoooooooOO - Ii1I + OoooooooOO
   if 42 - 42: iIii1I11I1II1 * I1IiiI * I1Ii111
   if 62 - 62: OOooOOo * O0 % IiII . IiII . I1IiiI
   if 91 - 91: i1IIi . iII111i
  self . last_request_nonce_sent = lisp_get_timestamp ( )
  return ( iII | 0x80000000 )
  if 37 - 37: iII111i - I11i + iIii1I11I1II1 / I1Ii111 - OoO0O00 . o0oOOo0O0Ooo
  if 62 - 62: I1ii11iIi11i
 def request_nonce_timeout ( self ) :
  if ( self . request_nonce_sent == None ) : return ( False )
  if ( self . request_nonce_sent == self . echo_nonce_rcvd ) : return ( False )
  if 47 - 47: I1Ii111 % OOooOOo * OoO0O00 . iIii1I11I1II1 % Oo0Ooo + OoooooooOO
  oO000o = time . time ( ) - self . last_request_nonce_sent
  I1Ii111I111 = self . last_echo_nonce_rcvd
  return ( oO000o >= LISP_NONCE_ECHO_INTERVAL and I1Ii111I111 == None )
  if 7 - 7: I1IiiI
  if 40 - 40: ooOoO0o
 def recently_requested ( self ) :
  I1Ii111I111 = self . last_request_nonce_sent
  if ( I1Ii111I111 == None ) : return ( False )
  if 80 - 80: I1IiiI * I1Ii111 % oO0o . i11iIiiIii % IiII
  oO000o = time . time ( ) - I1Ii111I111
  return ( oO000o <= LISP_NONCE_ECHO_INTERVAL )
  if 42 - 42: OoooooooOO * II111iiii
  if 53 - 53: I1Ii111 + i1IIi . OoO0O00 / i11iIiiIii + Ii1I % OoOoOO00
 def recently_echoed ( self ) :
  if ( self . request_nonce_sent == None ) : return ( True )
  if 9 - 9: ooOoO0o . I11i - Oo0Ooo . I1Ii111
  if 39 - 39: OOooOOo
  if 70 - 70: IiII % OoO0O00 % I1IiiI
  if 95 - 95: OoOoOO00 - I1Ii111 / O0 * I1IiiI - o0oOOo0O0Ooo
  I1Ii111I111 = self . last_good_echo_nonce_rcvd
  if ( I1Ii111I111 == None ) : I1Ii111I111 = 0
  oO000o = time . time ( ) - I1Ii111I111
  if ( oO000o <= LISP_NONCE_ECHO_INTERVAL ) : return ( True )
  if 12 - 12: iIii1I11I1II1 % Oo0Ooo . iII111i . IiII % i11iIiiIii
  if 2 - 2: oO0o * oO0o . OoOoOO00 * Ii1I * iIii1I11I1II1
  if 13 - 13: I11i / O0 . i11iIiiIii * i1IIi % i11iIiiIii
  if 8 - 8: OoOoOO00 - OoooooooOO
  if 99 - 99: II111iiii / IiII % OoooooooOO . i11iIiiIii
  if 18 - 18: o0oOOo0O0Ooo . ooOoO0o
  I1Ii111I111 = self . last_new_request_nonce_sent
  if ( I1Ii111I111 == None ) : I1Ii111I111 = 0
  oO000o = time . time ( ) - I1Ii111I111
  return ( oO000o <= LISP_NONCE_ECHO_INTERVAL )
  if 70 - 70: OoooooooOO . ooOoO0o / oO0o . oO0o - o0oOOo0O0Ooo
  if 29 - 29: I11i % OOooOOo - ooOoO0o
 def change_state ( self , rloc ) :
  if ( rloc . up_state ( ) and self . recently_echoed ( ) == False ) :
   Ii = bold ( "down" , False )
   I1i11i1iI = lisp_print_elapsed ( self . last_good_echo_nonce_rcvd )
   lprint ( "Take {} {}, last good echo: {}" . format ( red ( self . rloc_str , False ) , Ii , I1i11i1iI ) )
   if 92 - 92: OOooOOo % II111iiii . iII111i
   rloc . state = LISP_RLOC_NO_ECHOED_NONCE_STATE
   rloc . last_state_change = lisp_get_timestamp ( )
   return
   if 46 - 46: OoOoOO00 + I1IiiI % OoooooooOO * i11iIiiIii - Oo0Ooo
   if 47 - 47: iII111i * OoOoOO00 * IiII
  if ( rloc . no_echoed_nonce_state ( ) == False ) : return
  if 46 - 46: Ii1I
  if ( self . recently_requested ( ) == False ) :
   ii1o0 = bold ( "up" , False )
   lprint ( "Bring {} {}, retry request-nonce mode" . format ( red ( self . rloc_str , False ) , ii1o0 ) )
   if 67 - 67: OoooooooOO - O0
   rloc . state = LISP_RLOC_UP_STATE
   rloc . last_state_change = lisp_get_timestamp ( )
   if 40 - 40: I1IiiI
   if 3 - 3: ooOoO0o / i1IIi - OoOoOO00
   if 73 - 73: OoooooooOO * O0 * ooOoO0o
 def print_echo_nonce ( self ) :
  iii11Ii = lisp_print_elapsed ( self . last_request_nonce_sent )
  i1Iiii111 = lisp_print_elapsed ( self . last_good_echo_nonce_rcvd )
  if 37 - 37: OoO0O00 . i1IIi + i1IIi / I1IiiI * ooOoO0o * Ii1I
  OoooO = lisp_print_elapsed ( self . last_echo_nonce_sent )
  oo0OOoOo0 = lisp_print_elapsed ( self . last_request_nonce_rcvd )
  I11iiIi1i1 = space ( 4 )
  if 63 - 63: OoOoOO00
  Ii1I11I = "Nonce-Echoing:\n"
  Ii1I11I += ( "{}Last request-nonce sent: {}\n{}Last echo-nonce " + "received: {}\n" ) . format ( I11iiIi1i1 , iii11Ii , I11iiIi1i1 , i1Iiii111 )
  if 61 - 61: II111iiii * Ii1I + II111iiii % iII111i . i1IIi . oO0o
  Ii1I11I += ( "{}Last request-nonce received: {}\n{}Last echo-nonce " + "sent: {}" ) . format ( I11iiIi1i1 , oo0OOoOo0 , I11iiIi1i1 , OoooO )
  if 33 - 33: iIii1I11I1II1 + I1IiiI / oO0o * iII111i - oO0o
  if 96 - 96: I11i . OoooooooOO % II111iiii % Ii1I
  return ( Ii1I11I )
  if 43 - 43: II111iiii . i11iIiiIii . Ii1I - OoOoOO00 . I1Ii111
  if 15 - 15: I1ii11iIi11i - iIii1I11I1II1 % II111iiii / I11i
  if 46 - 46: iIii1I11I1II1
  if 96 - 96: IiII
  if 56 - 56: I11i / oO0o - oO0o
  if 40 - 40: i11iIiiIii * II111iiii
  if 57 - 57: O0 * iIii1I11I1II1 % O0 . OoooooooOO
  if 53 - 53: Ii1I / I1IiiI * Ii1I + o0oOOo0O0Ooo + oO0o - Oo0Ooo
  if 16 - 16: OoO0O00 % I1Ii111 . i1IIi / I1ii11iIi11i - O0
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
    if 85 - 85: i1IIi . i1IIi
   self . local_private_key = random . randint ( 0 , 2 ** 128 - 1 )
   i1i11ii1 = lisp_hex_string ( self . local_private_key ) . zfill ( 32 )
   self . curve25519 = curve25519 . Private ( i1i11ii1 )
  else :
   self . local_private_key = random . randint ( 0 , 0x1fff )
   if 16 - 16: I1IiiI - OOooOOo % Ii1I . OOooOOo + I1ii11iIi11i % i11iIiiIii
  self . local_public_key = self . compute_public_key ( )
  self . remote_public_key = None
  self . shared_key = None
  self . encrypt_key = None
  self . icv_key = None
  self . icv = poly1305 if do_poly else hashlib . sha256
  self . iv = None
  self . get_iv ( )
  self . do_poly = do_poly
  if 59 - 59: i11iIiiIii - I11i
  if 59 - 59: OoooooooOO * o0oOOo0O0Ooo / I1Ii111
 def copy_keypair ( self , key ) :
  self . local_private_key = key . local_private_key
  self . local_public_key = key . local_public_key
  self . curve25519 = key . curve25519
  if 75 - 75: o0oOOo0O0Ooo - OoooooooOO
  if 21 - 21: I1IiiI + iIii1I11I1II1 / i11iIiiIii / oO0o
 def get_iv ( self ) :
  if ( self . iv == None ) :
   self . iv = random . randint ( 0 , LISP_16_128_MASK )
  else :
   self . iv += 1
   if 66 - 66: OoooooooOO + iII111i . IiII % i1IIi
  oOOo00 = self . iv
  if ( self . cipher_suite == LISP_CS_25519_CHACHA ) :
   oOOo00 = struct . pack ( "Q" , oOOo00 & LISP_8_64_MASK )
  elif ( self . cipher_suite == LISP_CS_25519_GCM ) :
   O000OoOO0oO = struct . pack ( "I" , ( oOOo00 >> 64 ) & LISP_4_32_MASK )
   iII1 = struct . pack ( "Q" , oOOo00 & LISP_8_64_MASK )
   oOOo00 = O000OoOO0oO + iII1
  else :
   oOOo00 = struct . pack ( "QQ" , oOOo00 >> 64 , oOOo00 & LISP_8_64_MASK )
  return ( oOOo00 )
  if 72 - 72: Ii1I + OoOoOO00 * I1ii11iIi11i
  if 80 - 80: O0 * i11iIiiIii . O0 . II111iiii . i11iIiiIii
 def key_length ( self , key ) :
  if ( type ( key ) != str ) : key = self . normalize_pub_key ( key )
  return ( len ( key ) / 2 )
  if 45 - 45: O0 * oO0o + I11i * II111iiii + OOooOOo
  if 30 - 30: iIii1I11I1II1
 def print_key ( self , key ) :
  o00OOo0o0O = self . normalize_pub_key ( key )
  return ( "0x{}...{}({})" . format ( o00OOo0o0O [ 0 : 4 ] , o00OOo0o0O [ - 4 : : ] , self . key_length ( o00OOo0o0O ) ) )
  if 15 - 15: ooOoO0o * iIii1I11I1II1 * oO0o
  if 96 - 96: I1Ii111 * iIii1I11I1II1 / OoOoOO00 % OOooOOo * II111iiii
 def normalize_pub_key ( self , key ) :
  if ( type ( key ) == str ) :
   if ( self . curve25519 ) : return ( binascii . hexlify ( key ) )
   return ( key )
   if 3 - 3: OOooOOo . Oo0Ooo / i11iIiiIii + OoO0O00
  key = lisp_hex_string ( key ) . zfill ( 256 )
  return ( key )
  if 47 - 47: IiII . OOooOOo
  if 96 - 96: I11i % II111iiii / ooOoO0o % OOooOOo / ooOoO0o % i11iIiiIii
 def print_keys ( self , do_bold = True ) :
  i1I1i1i1I1 = bold ( "local-key: " , False ) if do_bold else "local-key: "
  if ( self . local_public_key == None ) :
   i1I1i1i1I1 += "none"
  else :
   i1I1i1i1I1 += self . print_key ( self . local_public_key )
   if 57 - 57: I11i - I11i % II111iiii % Oo0Ooo . o0oOOo0O0Ooo % Oo0Ooo
  O0ooOoO0OO000 = bold ( "remote-key: " , False ) if do_bold else "remote-key: "
  if ( self . remote_public_key == None ) :
   O0ooOoO0OO000 += "none"
  else :
   O0ooOoO0OO000 += self . print_key ( self . remote_public_key )
   if 91 - 91: I1IiiI - OoO0O00 - Oo0Ooo - Ii1I * iIii1I11I1II1
  OO0ooo0OOO = "ECDH" if ( self . curve25519 ) else "DH"
  O00oOO = self . cipher_suite
  return ( "{} cipher-suite: {}, {}, {}" . format ( OO0ooo0OOO , O00oOO , i1I1i1i1I1 , O0ooOoO0OO000 ) )
  if 75 - 75: ooOoO0o - iII111i % iII111i + ooOoO0o * o0oOOo0O0Ooo - I1ii11iIi11i
  if 26 - 26: I11i * Ii1I % I1IiiI + iII111i
 def compare_keys ( self , keys ) :
  if ( self . dh_g_value != keys . dh_g_value ) : return ( False )
  if ( self . dh_p_value != keys . dh_p_value ) : return ( False )
  if ( self . remote_public_key != keys . remote_public_key ) : return ( False )
  return ( True )
  if 38 - 38: iII111i - Oo0Ooo / Ii1I + oO0o . iII111i + IiII
  if 19 - 19: Ii1I
 def compute_public_key ( self ) :
  if ( self . curve25519 ) : return ( self . curve25519 . get_public ( ) . public )
  if 51 - 51: iIii1I11I1II1
  i1i11ii1 = self . local_private_key
  II1I = self . dh_g_value
  Iiiii1III1iIi = self . dh_p_value
  return ( int ( ( II1I ** i1i11ii1 ) % Iiiii1III1iIi ) )
  if 43 - 43: oO0o + OoOoOO00 . I1IiiI . i11iIiiIii
  if 71 - 71: o0oOOo0O0Ooo + OOooOOo . Oo0Ooo - OoOoOO00 * i11iIiiIii . OoOoOO00
 def compute_shared_key ( self , ed , print_shared = False ) :
  i1i11ii1 = self . local_private_key
  oo000O0o = self . remote_public_key
  if 99 - 99: I1IiiI
  OOoo = bold ( "Compute {} shared-key" . format ( ed ) , False )
  lprint ( "{}, key-material: {}" . format ( OOoo , self . print_keys ( ) ) )
  if 87 - 87: OoO0O00 * OoOoOO00 - Oo0Ooo % OOooOOo * i11iIiiIii
  if ( self . curve25519 ) :
   O0ooooo = curve25519 . Public ( oo000O0o )
   self . shared_key = self . curve25519 . get_shared_key ( O0ooooo )
  else :
   Iiiii1III1iIi = self . dh_p_value
   self . shared_key = ( oo000O0o ** i1i11ii1 ) % Iiiii1III1iIi
   if 16 - 16: OoOoOO00 / Ii1I . I1Ii111 % i11iIiiIii % I1IiiI / OOooOOo
   if 85 - 85: I11i + I1Ii111
   if 11 - 11: I11i
   if 95 - 95: Oo0Ooo + i11iIiiIii % OOooOOo - oO0o
   if 11 - 11: I1ii11iIi11i / O0 + II111iiii
   if 95 - 95: I1Ii111 + IiII * iIii1I11I1II1
   if 17 - 17: OoO0O00 - Oo0Ooo * O0 / Ii1I
  if ( print_shared ) :
   o00OOo0o0O = self . print_key ( self . shared_key )
   lprint ( "Computed shared-key: {}" . format ( o00OOo0o0O ) )
   if 19 - 19: i1IIi - iIii1I11I1II1 . I11i
   if 2 - 2: Ii1I
   if 12 - 12: i11iIiiIii - iIii1I11I1II1 * IiII * iII111i
   if 19 - 19: O0 + oO0o + o0oOOo0O0Ooo
   if 81 - 81: iIii1I11I1II1
  self . compute_encrypt_icv_keys ( )
  if 51 - 51: o0oOOo0O0Ooo . I1ii11iIi11i * Ii1I / Oo0Ooo * II111iiii / O0
  if 44 - 44: i11iIiiIii % I1Ii111 % oO0o + I11i * oO0o . Ii1I
  if 89 - 89: OoooooooOO % II111iiii - OoO0O00 % i11iIiiIii
  if 7 - 7: IiII
  self . rekey_count += 1
  self . last_rekey = lisp_get_timestamp ( )
  if 15 - 15: Oo0Ooo + iII111i + I1IiiI * o0oOOo0O0Ooo
  if 33 - 33: o0oOOo0O0Ooo * Oo0Ooo
 def compute_encrypt_icv_keys ( self ) :
  O0OOOOoOOO = hashlib . sha256
  if ( self . curve25519 ) :
   oooOoOOo0OOoO = self . shared_key
  else :
   oooOoOOo0OOoO = lisp_hex_string ( self . shared_key )
   if 66 - 66: iIii1I11I1II1 * II111iiii % Oo0Ooo % I1IiiI - Ii1I
   if 59 - 59: IiII % oO0o
   if 21 - 21: OoooooooOO % OoOoOO00 - OoOoOO00 / I1ii11iIi11i / o0oOOo0O0Ooo
   if 15 - 15: ooOoO0o / ooOoO0o % OoooooooOO . I1Ii111
   if 93 - 93: I1ii11iIi11i * I1ii11iIi11i / OoooooooOO
  i1I1i1i1I1 = self . local_public_key
  if ( type ( i1I1i1i1I1 ) != long ) : i1I1i1i1I1 = int ( binascii . hexlify ( i1I1i1i1I1 ) , 16 )
  O0ooOoO0OO000 = self . remote_public_key
  if ( type ( O0ooOoO0OO000 ) != long ) : O0ooOoO0OO000 = int ( binascii . hexlify ( O0ooOoO0OO000 ) , 16 )
  iIIIiiI1i1iIi = "0001" + "lisp-crypto" + lisp_hex_string ( i1I1i1i1I1 ^ O0ooOoO0OO000 ) + "0100"
  if 79 - 79: i1IIi % I1ii11iIi11i * I1IiiI . II111iiii - i1IIi + oO0o
  o0oOoo00 = hmac . new ( iIIIiiI1i1iIi , oooOoOOo0OOoO , O0OOOOoOOO ) . hexdigest ( )
  o0oOoo00 = int ( o0oOoo00 , 16 )
  if 21 - 21: O0 * ooOoO0o % OoOoOO00 / O0
  if 85 - 85: OoooooooOO + OoooooooOO
  if 23 - 23: i1IIi
  if 31 - 31: Oo0Ooo - iIii1I11I1II1 / I11i . OoO0O00
  oOOo0O0Oo = ( o0oOoo00 >> 128 ) & LISP_16_128_MASK
  III1I1I1iiIi = o0oOoo00 & LISP_16_128_MASK
  self . encrypt_key = lisp_hex_string ( oOOo0O0Oo ) . zfill ( 32 )
  iIi1i1I1I = 32 if self . do_poly else 40
  self . icv_key = lisp_hex_string ( III1I1I1iiIi ) . zfill ( iIi1i1I1I )
  if 35 - 35: I11i + O0 * II111iiii
  if 23 - 23: OoOoOO00 * IiII / oO0o
 def do_icv ( self , packet , nonce ) :
  if ( self . icv_key == None ) : return ( "" )
  if ( self . do_poly ) :
   O0O0o0o0oo0O = self . icv . poly1305aes
   I1iiI = self . icv . binascii . hexlify
   nonce = I1iiI ( nonce )
   iIOoO00o0o0oo0o = O0O0o0o0oo0O ( self . encrypt_key , self . icv_key , nonce , packet )
   iIOoO00o0o0oo0o = I1iiI ( iIOoO00o0o0oo0o )
  else :
   i1i11ii1 = binascii . unhexlify ( self . icv_key )
   iIOoO00o0o0oo0o = hmac . new ( i1i11ii1 , packet , self . icv ) . hexdigest ( )
   iIOoO00o0o0oo0o = iIOoO00o0o0oo0o [ 0 : 40 ]
   if 13 - 13: I11i % I1Ii111 . i1IIi
  return ( iIOoO00o0o0oo0o )
  if 1 - 1: o0oOOo0O0Ooo % o0oOOo0O0Ooo . iIii1I11I1II1 . OoooooooOO . IiII . iII111i
  if 58 - 58: OoooooooOO / iIii1I11I1II1
 def add_key_by_nonce ( self , nonce ) :
  if ( lisp_crypto_keys_by_nonce . has_key ( nonce ) == False ) :
   lisp_crypto_keys_by_nonce [ nonce ] = [ None , None , None , None ]
   if 25 - 25: O0 % i11iIiiIii + Ii1I + OOooOOo
  lisp_crypto_keys_by_nonce [ nonce ] [ self . key_id ] = self
  if 40 - 40: o0oOOo0O0Ooo + I1Ii111 * oO0o + I11i
  if 75 - 75: OoO0O00 - OoOoOO00 - i1IIi % Oo0Ooo - II111iiii
 def delete_key_by_nonce ( self , nonce ) :
  if ( lisp_crypto_keys_by_nonce . has_key ( nonce ) == False ) : return
  lisp_crypto_keys_by_nonce . pop ( nonce )
  if 61 - 61: Oo0Ooo + OoooooooOO / i11iIiiIii
  if 44 - 44: IiII . I11i % I1IiiI - i1IIi
 def add_key_by_rloc ( self , addr_str , encap ) :
  iIII1II = lisp_crypto_keys_by_rloc_encap if encap else lisp_crypto_keys_by_rloc_decap
  if 6 - 6: I1Ii111 * O0 / Oo0Ooo + OoO0O00 - Oo0Ooo - o0oOOo0O0Ooo
  if 48 - 48: OoOoOO00 * OoooooooOO + OoooooooOO * iIii1I11I1II1 * II111iiii % i11iIiiIii
  if ( iIII1II . has_key ( addr_str ) == False ) :
   iIII1II [ addr_str ] = [ None , None , None , None ]
   if 22 - 22: OoO0O00 . OoOoOO00 % II111iiii - O0
  iIII1II [ addr_str ] [ self . key_id ] = self
  if 52 - 52: OoO0O00
  if 49 - 49: Ii1I . I1ii11iIi11i % ooOoO0o . Oo0Ooo * OOooOOo
  if 44 - 44: iIii1I11I1II1 / O0 * Oo0Ooo + I1IiiI . ooOoO0o
  if 20 - 20: iII111i + o0oOOo0O0Ooo . I1Ii111 / i11iIiiIii
  if 7 - 7: OoOoOO00 / OoOoOO00 . I1Ii111 * O0 + IiII + oO0o
  if ( encap == False ) :
   lisp_write_ipc_decap_key ( addr_str , iIII1II [ addr_str ] )
   if 98 - 98: II111iiii * IiII - I1IiiI % o0oOOo0O0Ooo - iII111i % I1ii11iIi11i
   if 69 - 69: i1IIi % OoO0O00 % I1Ii111 / ooOoO0o / ooOoO0o
   if 6 - 6: II111iiii % I1ii11iIi11i % i1IIi * ooOoO0o
 def encode_lcaf ( self , rloc_addr ) :
  iIIoooO0 = self . normalize_pub_key ( self . local_public_key )
  iI1iIi1ii1I1 = self . key_length ( iIIoooO0 )
  ooOoooOoo0oO = ( 6 + iI1iIi1ii1I1 + 2 )
  if ( rloc_addr != None ) : ooOoooOoo0oO += rloc_addr . addr_length ( )
  if 50 - 50: ooOoO0o
  I1i1iI = struct . pack ( "HBBBBHBB" , socket . htons ( LISP_AFI_LCAF ) , 0 , 0 ,
 LISP_LCAF_SECURITY_TYPE , 0 , socket . htons ( ooOoooOoo0oO ) , 1 , 0 )
  if 81 - 81: i11iIiiIii * iIii1I11I1II1 / Oo0Ooo * OOooOOo
  if 83 - 83: i11iIiiIii - I1IiiI * i11iIiiIii
  if 59 - 59: iII111i - OoooooooOO / ooOoO0o + I1ii11iIi11i . o0oOOo0O0Ooo - iII111i
  if 29 - 29: oO0o
  if 26 - 26: O0 % OOooOOo - IiII . OOooOOo
  if 70 - 70: o0oOOo0O0Ooo + I11i / iII111i + ooOoO0o / I1IiiI
  O00oOO = self . cipher_suite
  I1i1iI += struct . pack ( "BBH" , O00oOO , 0 , socket . htons ( iI1iIi1ii1I1 ) )
  if 33 - 33: OoooooooOO . O0
  if 59 - 59: iIii1I11I1II1
  if 45 - 45: O0
  if 78 - 78: I11i - iIii1I11I1II1 + I1Ii111 - I1ii11iIi11i - I1Ii111
  for iiIii1I in range ( 0 , iI1iIi1ii1I1 * 2 , 16 ) :
   i1i11ii1 = int ( iIIoooO0 [ iiIii1I : iiIii1I + 16 ] , 16 )
   I1i1iI += struct . pack ( "Q" , byte_swap_64 ( i1i11ii1 ) )
   if 21 - 21: OoooooooOO . O0 / i11iIiiIii
   if 86 - 86: OoOoOO00 / OOooOOo
   if 40 - 40: iIii1I11I1II1 / ooOoO0o / I1IiiI + I1ii11iIi11i * OOooOOo
   if 1 - 1: OoO0O00 * ooOoO0o + IiII . oO0o / ooOoO0o
   if 91 - 91: Ii1I + I11i - Oo0Ooo % OoOoOO00 . iII111i
  if ( rloc_addr ) :
   I1i1iI += struct . pack ( "H" , socket . htons ( rloc_addr . afi ) )
   I1i1iI += rloc_addr . pack_address ( )
   if 51 - 51: OOooOOo / I11i
  return ( I1i1iI )
  if 51 - 51: ooOoO0o * oO0o - I1Ii111 + iII111i
  if 46 - 46: o0oOOo0O0Ooo - i11iIiiIii % OoO0O00 / Ii1I - OoOoOO00
 def decode_lcaf ( self , packet , lcaf_len ) :
  if 88 - 88: oO0o * I1IiiI / OoO0O00 - OOooOOo / i1IIi . I1Ii111
  if 26 - 26: i11iIiiIii - ooOoO0o
  if 45 - 45: ooOoO0o + II111iiii % iII111i
  if 55 - 55: ooOoO0o - oO0o % I1IiiI
  if ( lcaf_len == 0 ) :
   ii1iI11IiIIi = "HHBBH"
   iiii = struct . calcsize ( ii1iI11IiIIi )
   if ( len ( packet ) < iiii ) : return ( None )
   if 61 - 61: ooOoO0o
   ooo0oOOOO00Oo , Iii1I , I1iI , Iii1I , lcaf_len = struct . unpack ( ii1iI11IiIIi , packet [ : iiii ] )
   if 95 - 95: iIii1I11I1II1
   if 75 - 75: OOooOOo - OoO0O00
   if ( I1iI != LISP_LCAF_SECURITY_TYPE ) :
    packet = packet [ lcaf_len + 6 : : ]
    return ( packet )
    if 91 - 91: O0 . I1Ii111
   lcaf_len = socket . ntohs ( lcaf_len )
   packet = packet [ iiii : : ]
   if 31 - 31: O0 - IiII * i11iIiiIii * i1IIi
   if 78 - 78: ooOoO0o * OoOoOO00 . Ii1I . OoOoOO00 % iIii1I11I1II1
   if 67 - 67: Ii1I . Oo0Ooo
   if 39 - 39: I11i * I1Ii111
   if 63 - 63: ooOoO0o % I1IiiI . OOooOOo - ooOoO0o / Oo0Ooo % I1IiiI
   if 39 - 39: o0oOOo0O0Ooo . i1IIi % oO0o / I11i % O0
  I1iI = LISP_LCAF_SECURITY_TYPE
  ii1iI11IiIIi = "BBBBH"
  iiii = struct . calcsize ( ii1iI11IiIIi )
  if ( len ( packet ) < iiii ) : return ( None )
  if 100 - 100: I1Ii111 - OoOoOO00
  oooOoO00O , Iii1I , O00oOO , Iii1I , iI1iIi1ii1I1 = struct . unpack ( ii1iI11IiIIi ,
 packet [ : iiii ] )
  if 42 - 42: IiII * iII111i . I1ii11iIi11i - iIii1I11I1II1 . ooOoO0o + I11i
  if 35 - 35: iII111i . I1IiiI / II111iiii % IiII
  if 6 - 6: iIii1I11I1II1 * II111iiii
  if 38 - 38: I1IiiI
  if 42 - 42: o0oOOo0O0Ooo
  if 8 - 8: i11iIiiIii / ooOoO0o
  packet = packet [ iiii : : ]
  iI1iIi1ii1I1 = socket . ntohs ( iI1iIi1ii1I1 )
  if ( len ( packet ) < iI1iIi1ii1I1 ) : return ( None )
  if 33 - 33: I1Ii111 * IiII - O0 + I1IiiI / IiII
  if 19 - 19: i1IIi % II111iiii
  if 85 - 85: IiII - o0oOOo0O0Ooo % OOooOOo - II111iiii
  if 56 - 56: Ii1I * i11iIiiIii
  oooo0OoOO = [ LISP_CS_25519_CBC , LISP_CS_25519_GCM , LISP_CS_25519_CHACHA ,
 LISP_CS_1024 ]
  if ( O00oOO not in oooo0OoOO ) :
   lprint ( "Cipher-suites {} supported, received {}" . format ( oooo0OoOO ,
 O00oOO ) )
   packet = packet [ iI1iIi1ii1I1 : : ]
   return ( packet )
   if 37 - 37: I1ii11iIi11i / Ii1I - OoooooooOO . oO0o
   if 57 - 57: i11iIiiIii - I11i / ooOoO0o / o0oOOo0O0Ooo * i11iIiiIii * o0oOOo0O0Ooo
  self . cipher_suite = O00oOO
  if 28 - 28: OoooooooOO % O0 - OOooOOo / o0oOOo0O0Ooo / I1IiiI
  if 41 - 41: II111iiii * IiII / OoO0O00 . oO0o
  if 50 - 50: OoooooooOO + iIii1I11I1II1 / oO0o / OOooOOo . i11iIiiIii . ooOoO0o
  if 75 - 75: iIii1I11I1II1 % ooOoO0o / OOooOOo - iII111i % i11iIiiIii
  if 11 - 11: I11i . Ii1I
  iIIoooO0 = 0
  for iiIii1I in range ( 0 , iI1iIi1ii1I1 , 8 ) :
   i1i11ii1 = byte_swap_64 ( struct . unpack ( "Q" , packet [ iiIii1I : iiIii1I + 8 ] ) [ 0 ] )
   iIIoooO0 <<= 64
   iIIoooO0 |= i1i11ii1
   if 87 - 87: OOooOOo + OOooOOo
  self . remote_public_key = iIIoooO0
  if 45 - 45: i1IIi - Oo0Ooo
  if 87 - 87: OoOoOO00 - OoO0O00 * OoO0O00 / Ii1I . I11i * o0oOOo0O0Ooo
  if 21 - 21: II111iiii
  if 29 - 29: OoOoOO00 % Ii1I
  if 7 - 7: i1IIi / IiII / iII111i
  if ( self . curve25519 ) :
   i1i11ii1 = lisp_hex_string ( self . remote_public_key )
   i1i11ii1 = i1i11ii1 . zfill ( 64 )
   oOo0OO0 = ""
   for iiIii1I in range ( 0 , len ( i1i11ii1 ) , 2 ) :
    oOo0OO0 += chr ( int ( i1i11ii1 [ iiIii1I : iiIii1I + 2 ] , 16 ) )
    if 56 - 56: II111iiii . II111iiii + IiII . o0oOOo0O0Ooo
   self . remote_public_key = oOo0OO0
   if 32 - 32: ooOoO0o . IiII . II111iiii
   if 25 - 25: IiII * I1Ii111 - oO0o * i11iIiiIii * I1IiiI * OOooOOo
  packet = packet [ iI1iIi1ii1I1 : : ]
  return ( packet )
  if 56 - 56: OoooooooOO . I1IiiI . II111iiii % iII111i
  if 59 - 59: ooOoO0o % Oo0Ooo - oO0o + IiII
  if 33 - 33: Ii1I + OoOoOO00 - I1ii11iIi11i + iIii1I11I1II1 % i1IIi * IiII
  if 21 - 21: O0 * ooOoO0o % OoO0O00
  if 14 - 14: O0 / I1Ii111 / ooOoO0o + IiII - IiII
  if 10 - 10: O0 - I1ii11iIi11i / I1Ii111 % OoOoOO00 / OoooooooOO / Ii1I
  if 73 - 73: ooOoO0o + IiII % o0oOOo0O0Ooo . I1ii11iIi11i / OOooOOo . I1Ii111
  if 76 - 76: I11i . I1ii11iIi11i * OoooooooOO % iII111i
class lisp_thread ( ) :
 def __init__ ( self , name ) :
  self . thread_name = name
  self . thread_number = - 1
  self . number_of_pcap_threads = 0
  self . number_of_worker_threads = 0
  self . input_queue = Queue . Queue ( )
  self . input_stats = lisp_stats ( )
  self . lisp_packet = lisp_packet ( None )
  if 24 - 24: OoooooooOO
  if 83 - 83: O0 / OoO0O00
  if 62 - 62: I11i
  if 73 - 73: Ii1I % OoO0O00 * OOooOOo
  if 84 - 84: Oo0Ooo
  if 18 - 18: OoooooooOO
  if 85 - 85: OoooooooOO . OoO0O00 . OoO0O00
  if 70 - 70: I11i
  if 72 - 72: I1Ii111 - ooOoO0o - I1IiiI - iII111i + OOooOOo - i1IIi
  if 45 - 45: OoO0O00 * I1IiiI
  if 61 - 61: iII111i % II111iiii / OoOoOO00 % I1ii11iIi11i . iIii1I11I1II1 % O0
  if 74 - 74: I1ii11iIi11i * oO0o + iII111i % O0
  if 18 - 18: i1IIi % IiII . O0 - O0 - O0 - II111iiii
  if 55 - 55: OoOoOO00 . iIii1I11I1II1 * OOooOOo % iIii1I11I1II1 . OoO0O00
  if 43 - 43: Ii1I . OOooOOo + I1IiiI * i11iIiiIii
  if 2 - 2: OOooOOo
  if 3 - 3: I1IiiI . iII111i % O0 - ooOoO0o / O0
  if 79 - 79: Ii1I + oO0o % ooOoO0o % I1IiiI
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
  if 68 - 68: II111iiii - OoooooooOO / iIii1I11I1II1 - o0oOOo0O0Ooo % II111iiii
  if 53 - 53: iII111i . oO0o / Oo0Ooo . OoO0O00 . i11iIiiIii
 def decode ( self , packet ) :
  ii1iI11IiIIi = "BBBBQ"
  iiii = struct . calcsize ( ii1iI11IiIIi )
  if ( len ( packet ) < iiii ) : return ( False )
  if 60 - 60: II111iiii
  iIIIII , iiiII , Oo0OooII1iII11 , self . record_count , self . nonce = struct . unpack ( ii1iI11IiIIi , packet [ : iiii ] )
  if 19 - 19: II111iiii
  if 5 - 5: Oo0Ooo
  self . type = iIIIII >> 4
  if ( self . type == LISP_MAP_REQUEST ) :
   self . smr_bit = True if ( iIIIII & 0x01 ) else False
   self . rloc_probe = True if ( iIIIII & 0x02 ) else False
   self . smr_invoked_bit = True if ( iiiII & 0x40 ) else False
   if 84 - 84: I1ii11iIi11i
  if ( self . type == LISP_ECM ) :
   self . ddt_bit = True if ( iIIIII & 0x04 ) else False
   self . to_etr = True if ( iIIIII & 0x02 ) else False
   self . to_ms = True if ( iIIIII & 0x01 ) else False
   if 53 - 53: oO0o
  if ( self . type == LISP_NAT_INFO ) :
   self . info_reply = True if ( iIIIII & 0x08 ) else False
   if 26 - 26: I1Ii111 / I1Ii111 + Oo0Ooo - o0oOOo0O0Ooo % II111iiii . OoooooooOO
  return ( True )
  if 7 - 7: II111iiii - I1ii11iIi11i / I11i % OoooooooOO + i1IIi
  if 42 - 42: I11i + i1IIi - Ii1I / IiII . iII111i
 def is_info_request ( self ) :
  return ( ( self . type == LISP_NAT_INFO and self . is_info_reply ( ) == False ) )
  if 30 - 30: Oo0Ooo + Ii1I % i11iIiiIii * i1IIi + I1IiiI % OOooOOo
  if 30 - 30: i11iIiiIii * Oo0Ooo . II111iiii + I1ii11iIi11i / o0oOOo0O0Ooo % I1Ii111
 def is_info_reply ( self ) :
  return ( True if self . info_reply else False )
  if 78 - 78: I1ii11iIi11i + OoooooooOO - I1IiiI * OoOoOO00 * iII111i
  if 7 - 7: OOooOOo . IiII . I1Ii111 / Ii1I / Oo0Ooo
 def is_rloc_probe ( self ) :
  return ( True if self . rloc_probe else False )
  if 83 - 83: I11i / Oo0Ooo
  if 23 - 23: iIii1I11I1II1
 def is_smr ( self ) :
  return ( True if self . smr_bit else False )
  if 10 - 10: I11i - o0oOOo0O0Ooo % OoooooooOO - I1ii11iIi11i
  if 64 - 64: OoO0O00 / I1IiiI
 def is_smr_invoked ( self ) :
  return ( True if self . smr_invoked_bit else False )
  if 23 - 23: I11i * I1Ii111 * o0oOOo0O0Ooo - I1IiiI % OoOoOO00 + o0oOOo0O0Ooo
  if 41 - 41: IiII * OoooooooOO . ooOoO0o % i11iIiiIii
 def is_ddt ( self ) :
  return ( True if self . ddt_bit else False )
  if 11 - 11: iIii1I11I1II1 . I1Ii111 - Oo0Ooo / I11i + II111iiii
  if 29 - 29: I11i . i11iIiiIii + i1IIi - Ii1I + O0 . I1IiiI
 def is_to_etr ( self ) :
  return ( True if self . to_etr else False )
  if 8 - 8: o0oOOo0O0Ooo
  if 78 - 78: i1IIi - Oo0Ooo
 def is_to_ms ( self ) :
  return ( True if self . to_ms else False )
  if 48 - 48: Ii1I - OoooooooOO + I1Ii111 % o0oOOo0O0Ooo - OoOoOO00 . I1IiiI
  if 42 - 42: I1Ii111
  if 70 - 70: o0oOOo0O0Ooo / I11i + oO0o % I1IiiI % Oo0Ooo + OoO0O00
  if 80 - 80: OOooOOo
  if 12 - 12: Ii1I
  if 2 - 2: OoooooooOO
  if 100 - 100: Oo0Ooo / O0 * i11iIiiIii * OoooooooOO
  if 46 - 46: O0 % OoooooooOO
  if 22 - 22: iII111i + OoooooooOO - OoOoOO00 - OoO0O00 * I1Ii111 - oO0o
  if 99 - 99: ooOoO0o / I1IiiI . Ii1I - Ii1I * I1IiiI
  if 24 - 24: I11i * OoO0O00 - oO0o / iIii1I11I1II1 - Oo0Ooo . OOooOOo
  if 2 - 2: ooOoO0o - O0 - I1ii11iIi11i / I11i * OoOoOO00
  if 26 - 26: I1ii11iIi11i + I1Ii111 - oO0o + IiII % OOooOOo
  if 84 - 84: I11i % Ii1I % O0 * o0oOOo0O0Ooo
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
  if 78 - 78: oO0o + II111iiii
  if 55 - 55: OoooooooOO
 def print_map_register ( self ) :
  ooO0O = lisp_hex_string ( self . xtr_id )
  if 55 - 55: OOooOOo - II111iiii - IiII . I11i + oO0o - oO0o
  ii1II1II = ( "{} -> flags: {}{}{}{}{}{}{}{}{}, record-count: " +
 "{}, nonce: 0x{}, key/alg-id: {}/{}{}, auth-len: {}, xtr-id: " +
 "0x{}, site-id: {}" )
  if 29 - 29: OoOoOO00 - I1Ii111 % OOooOOo
  lprint ( ii1II1II . format ( bold ( "Map-Register" , False ) , "P" if self . proxy_reply_requested else "p" ,
  # OoooooooOO + OoO0O00 * Oo0Ooo
 "S" if self . lisp_sec_present else "s" ,
 "I" if self . xtr_id_present else "i" ,
 "T" if self . use_ttl_for_timeout else "t" ,
 "R" if self . merge_register_requested else "r" ,
 "M" if self . mobile_node else "m" ,
 "N" if self . map_notify_requested else "n" ,
 "F" if self . map_register_refresh else "f" ,
 "E" if self . encrypt_bit else "e" ,
 self . record_count , lisp_hex_string ( self . nonce ) , self . key_id ,
 self . alg_id , " (sha1)" if ( self . key_id == LISP_SHA_1_96_ALG_ID ) else ( " (sha2)" if ( self . key_id == LISP_SHA_256_128_ALG_ID ) else "" ) , self . auth_len , ooO0O , self . site_id ) )
  if 20 - 20: i11iIiiIii - II111iiii - ooOoO0o % oO0o . ooOoO0o
  if 50 - 50: iIii1I11I1II1 + I1Ii111 - I11i - OoooooooOO
  if 84 - 84: OoOoOO00 - I11i
  if 80 - 80: i11iIiiIii % OOooOOo - Oo0Ooo % OOooOOo
 def encode ( self ) :
  oO00O0o0oOOO = ( LISP_MAP_REGISTER << 28 ) | self . record_count
  if ( self . proxy_reply_requested ) : oO00O0o0oOOO |= 0x08000000
  if ( self . lisp_sec_present ) : oO00O0o0oOOO |= 0x04000000
  if ( self . xtr_id_present ) : oO00O0o0oOOO |= 0x02000000
  if ( self . map_register_refresh ) : oO00O0o0oOOO |= 0x1000
  if ( self . use_ttl_for_timeout ) : oO00O0o0oOOO |= 0x800
  if ( self . merge_register_requested ) : oO00O0o0oOOO |= 0x400
  if ( self . mobile_node ) : oO00O0o0oOOO |= 0x200
  if ( self . map_notify_requested ) : oO00O0o0oOOO |= 0x100
  if ( self . encryption_key_id != None ) :
   oO00O0o0oOOO |= 0x2000
   oO00O0o0oOOO |= self . encryption_key_id << 14
   if 89 - 89: Ii1I * I11i + OoOoOO00 / i11iIiiIii
   if 68 - 68: OoooooooOO * I11i
   if 86 - 86: o0oOOo0O0Ooo / OoOoOO00
   if 40 - 40: iII111i
   if 62 - 62: ooOoO0o / OOooOOo
  if ( self . alg_id == LISP_NONE_ALG_ID ) :
   self . auth_len = 0
  else :
   if ( self . alg_id == LISP_SHA_1_96_ALG_ID ) :
    self . auth_len = LISP_SHA1_160_AUTH_DATA_LEN
    if 74 - 74: iII111i % I1Ii111 / I1Ii111 - iIii1I11I1II1 - II111iiii + OOooOOo
   if ( self . alg_id == LISP_SHA_256_128_ALG_ID ) :
    self . auth_len = LISP_SHA2_256_AUTH_DATA_LEN
    if 92 - 92: I11i % I1Ii111
    if 18 - 18: ooOoO0o + I1Ii111 / OOooOOo / oO0o + iIii1I11I1II1 % IiII
    if 94 - 94: I11i
  I1i1iI = struct . pack ( "I" , socket . htonl ( oO00O0o0oOOO ) )
  I1i1iI += struct . pack ( "QBBH" , self . nonce , self . key_id , self . alg_id ,
 socket . htons ( self . auth_len ) )
  if 37 - 37: oO0o
  I1i1iI = self . zero_auth ( I1i1iI )
  return ( I1i1iI )
  if 52 - 52: I1ii11iIi11i * I1IiiI . OOooOOo + i1IIi % oO0o / iIii1I11I1II1
  if 68 - 68: I1Ii111 - OoOoOO00 . i11iIiiIii + o0oOOo0O0Ooo
 def zero_auth ( self , packet ) :
  O00oOooo0 = struct . calcsize ( "I" ) + struct . calcsize ( "QHH" )
  Oo0oo = ""
  iii1I = 0
  if ( self . alg_id == LISP_NONE_ALG_ID ) : return ( packet )
  if ( self . alg_id == LISP_SHA_1_96_ALG_ID ) :
   Oo0oo = struct . pack ( "QQI" , 0 , 0 , 0 )
   iii1I = struct . calcsize ( "QQI" )
   if 89 - 89: iII111i + i1IIi - IiII + ooOoO0o . II111iiii
  if ( self . alg_id == LISP_SHA_256_128_ALG_ID ) :
   Oo0oo = struct . pack ( "QQQQ" , 0 , 0 , 0 , 0 )
   iii1I = struct . calcsize ( "QQQQ" )
   if 85 - 85: iIii1I11I1II1 - Ii1I * Oo0Ooo . oO0o + I1Ii111
  packet = packet [ 0 : O00oOooo0 ] + Oo0oo + packet [ O00oOooo0 + iii1I : : ]
  return ( packet )
  if 13 - 13: O0 + iIii1I11I1II1 % II111iiii + iIii1I11I1II1
  if 85 - 85: I1IiiI * iIii1I11I1II1 . iII111i / iII111i
 def encode_auth ( self , packet ) :
  O00oOooo0 = struct . calcsize ( "I" ) + struct . calcsize ( "QHH" )
  iii1I = self . auth_len
  Oo0oo = self . auth_data
  packet = packet [ 0 : O00oOooo0 ] + Oo0oo + packet [ O00oOooo0 + iii1I : : ]
  return ( packet )
  if 43 - 43: I1IiiI
  if 78 - 78: OoO0O00 % II111iiii + OoOoOO00 / I1IiiI
 def decode ( self , packet ) :
  IIII11i1Ii = packet
  ii1iI11IiIIi = "I"
  iiii = struct . calcsize ( ii1iI11IiIIi )
  if ( len ( packet ) < iiii ) : return ( [ None , None ] )
  if 13 - 13: ooOoO0o * OoO0O00 % iIii1I11I1II1 / IiII * iII111i . Oo0Ooo
  oO00O0o0oOOO = struct . unpack ( ii1iI11IiIIi , packet [ : iiii ] )
  oO00O0o0oOOO = socket . ntohl ( oO00O0o0oOOO [ 0 ] )
  packet = packet [ iiii : : ]
  if 23 - 23: ooOoO0o / IiII . iII111i * Ii1I
  ii1iI11IiIIi = "QBBH"
  iiii = struct . calcsize ( ii1iI11IiIIi )
  if ( len ( packet ) < iiii ) : return ( [ None , None ] )
  if 87 - 87: i11iIiiIii
  self . nonce , self . key_id , self . alg_id , self . auth_len = struct . unpack ( ii1iI11IiIIi , packet [ : iiii ] )
  if 34 - 34: i1IIi
  if 64 - 64: iIii1I11I1II1 / IiII / Oo0Ooo - I1ii11iIi11i
  self . auth_len = socket . ntohs ( self . auth_len )
  self . proxy_reply_requested = True if ( oO00O0o0oOOO & 0x08000000 ) else False
  if 100 - 100: IiII + i1IIi * OoO0O00
  self . lisp_sec_present = True if ( oO00O0o0oOOO & 0x04000000 ) else False
  self . xtr_id_present = True if ( oO00O0o0oOOO & 0x02000000 ) else False
  self . use_ttl_for_timeout = True if ( oO00O0o0oOOO & 0x800 ) else False
  self . map_register_refresh = True if ( oO00O0o0oOOO & 0x1000 ) else False
  self . merge_register_requested = True if ( oO00O0o0oOOO & 0x400 ) else False
  self . mobile_node = True if ( oO00O0o0oOOO & 0x200 ) else False
  self . map_notify_requested = True if ( oO00O0o0oOOO & 0x100 ) else False
  self . record_count = oO00O0o0oOOO & 0xff
  if 64 - 64: oO0o * i11iIiiIii . Oo0Ooo
  if 52 - 52: Oo0Ooo / ooOoO0o / iII111i - o0oOOo0O0Ooo / iII111i
  if 74 - 74: i1IIi . iIii1I11I1II1
  if 85 - 85: I1IiiI
  self . encrypt_bit = True if oO00O0o0oOOO & 0x2000 else False
  if ( self . encrypt_bit ) :
   self . encryption_key_id = ( oO00O0o0oOOO >> 14 ) & 0x7
   if 10 - 10: O0 . II111iiii / OoooooooOO
   if 72 - 72: OoooooooOO . o0oOOo0O0Ooo + O0
   if 46 - 46: OoOoOO00 * I11i / oO0o + Oo0Ooo + IiII
   if 95 - 95: o0oOOo0O0Ooo - Ii1I
   if 67 - 67: I1ii11iIi11i * Oo0Ooo % o0oOOo0O0Ooo
  if ( self . xtr_id_present ) :
   if ( self . decode_xtr_id ( IIII11i1Ii ) == False ) : return ( [ None , None ] )
   if 19 - 19: OoOoOO00 . OOooOOo . OoooooooOO
   if 79 - 79: OOooOOo * ooOoO0o * I1IiiI * I1ii11iIi11i / I1ii11iIi11i
  packet = packet [ iiii : : ]
  if 62 - 62: ooOoO0o * Ii1I % I1ii11iIi11i - i1IIi - I1ii11iIi11i
  if 24 - 24: OOooOOo
  if 71 - 71: IiII - i1IIi
  if 56 - 56: OoOoOO00 + oO0o
  if ( self . auth_len != 0 ) :
   if ( len ( packet ) < self . auth_len ) : return ( [ None , None ] )
   if 74 - 74: iII111i / I1Ii111 / II111iiii - iII111i / oO0o % I11i
   if ( self . alg_id not in ( LISP_NONE_ALG_ID , LISP_SHA_1_96_ALG_ID ,
 LISP_SHA_256_128_ALG_ID ) ) :
    lprint ( "Invalid authentication alg-id: {}" . format ( self . alg_id ) )
    return ( [ None , None ] )
    if 19 - 19: IiII % OoooooooOO + OoooooooOO
    if 7 - 7: i1IIi
   iii1I = self . auth_len
   if ( self . alg_id == LISP_SHA_1_96_ALG_ID ) :
    iiii = struct . calcsize ( "QQI" )
    if ( iii1I < iiii ) :
     lprint ( "Invalid sha1-96 authentication length" )
     return ( [ None , None ] )
     if 91 - 91: OoOoOO00 - OoOoOO00 . IiII
    I1ii11i1 , IIi1iII11III , i1IIiIIi11 = struct . unpack ( "QQI" , packet [ : iii1I ] )
    Ooo0 = ""
   elif ( self . alg_id == LISP_SHA_256_128_ALG_ID ) :
    iiii = struct . calcsize ( "QQQQ" )
    if ( iii1I < iiii ) :
     lprint ( "Invalid sha2-256 authentication length" )
     return ( [ None , None ] )
     if 65 - 65: I1ii11iIi11i * O0 . OoooooooOO * I11i / IiII
    I1ii11i1 , IIi1iII11III , i1IIiIIi11 , Ooo0 = struct . unpack ( "QQQQ" ,
 packet [ : iii1I ] )
   else :
    lprint ( "Unsupported authentication alg-id value {}" . format ( self . alg_id ) )
    if 87 - 87: iIii1I11I1II1
    return ( [ None , None ] )
    if 58 - 58: I1ii11iIi11i % i11iIiiIii + OoOoOO00 / I11i - OoooooooOO
   self . auth_data = lisp_concat_auth_data ( self . alg_id , I1ii11i1 , IIi1iII11III ,
 i1IIiIIi11 , Ooo0 )
   IIII11i1Ii = self . zero_auth ( IIII11i1Ii )
   packet = packet [ self . auth_len : : ]
   if 62 - 62: OoO0O00 . OoOoOO00
  return ( [ IIII11i1Ii , packet ] )
  if 22 - 22: ooOoO0o . i11iIiiIii . OoooooooOO . i1IIi
  if 12 - 12: OoOoOO00 % OOooOOo + oO0o . O0 % iIii1I11I1II1
 def encode_xtr_id ( self , packet ) :
  ii1I = self . xtr_id >> 64
  O00oO0oOOOOOO = self . xtr_id & 0xffffffffffffffff
  ii1I = byte_swap_64 ( ii1I )
  O00oO0oOOOOOO = byte_swap_64 ( O00oO0oOOOOOO )
  Oo0ooo00OoO = byte_swap_64 ( self . site_id )
  packet += struct . pack ( "QQQ" , ii1I , O00oO0oOOOOOO , Oo0ooo00OoO )
  return ( packet )
  if 1 - 1: OoooooooOO * iIii1I11I1II1 / I1ii11iIi11i * I11i
  if 37 - 37: iII111i % I11i . iII111i - OOooOOo / iIii1I11I1II1 - OOooOOo
 def decode_xtr_id ( self , packet ) :
  iiii = struct . calcsize ( "QQQ" )
  if ( len ( packet ) < iiii ) : return ( [ None , None ] )
  packet = packet [ len ( packet ) - iiii : : ]
  ii1I , O00oO0oOOOOOO , Oo0ooo00OoO = struct . unpack ( "QQQ" ,
 packet [ : iiii ] )
  ii1I = byte_swap_64 ( ii1I )
  O00oO0oOOOOOO = byte_swap_64 ( O00oO0oOOOOOO )
  self . xtr_id = ( ii1I << 64 ) | O00oO0oOOOOOO
  self . site_id = byte_swap_64 ( Oo0ooo00OoO )
  return ( True )
  if 50 - 50: O0
  if 97 - 97: II111iiii
  if 43 - 43: Oo0Ooo / I1Ii111 / i1IIi
  if 3 - 3: Ii1I * ooOoO0o . OoO0O00 * OoooooooOO + OoOoOO00 / O0
  if 60 - 60: I11i
  if 97 - 97: i11iIiiIii * iIii1I11I1II1 / II111iiii
  if 66 - 66: II111iiii + iII111i * oO0o % I11i / i1IIi / iIii1I11I1II1
  if 62 - 62: OoOoOO00 + oO0o * IiII + O0 / OOooOOo + ooOoO0o
  if 38 - 38: i1IIi / iIii1I11I1II1 + iII111i
  if 26 - 26: I1ii11iIi11i . Ii1I % o0oOOo0O0Ooo
  if 4 - 4: I1Ii111
  if 80 - 80: Oo0Ooo . O0 % o0oOOo0O0Ooo . o0oOOo0O0Ooo
  if 52 - 52: OoO0O00 % i11iIiiIii . ooOoO0o % OoOoOO00 % OoooooooOO
  if 5 - 5: OoOoOO00 / O0 / i11iIiiIii
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
  if 74 - 74: ooOoO0o - o0oOOo0O0Ooo * IiII % ooOoO0o
  if 93 - 93: iIii1I11I1II1 / OoOoOO00 % Oo0Ooo * I1Ii111 - OoO0O00 - o0oOOo0O0Ooo
 def print_notify ( self ) :
  Oo0oo = binascii . hexlify ( self . auth_data )
  if ( self . alg_id == LISP_SHA_1_96_ALG_ID and len ( Oo0oo ) != 40 ) :
   Oo0oo = self . auth_data
  elif ( self . alg_id == LISP_SHA_256_128_ALG_ID and len ( Oo0oo ) != 64 ) :
   Oo0oo = self . auth_data
   if 44 - 44: OoooooooOO
  ii1II1II = ( "{} -> record-count: {}, nonce: 0x{}, key/alg-id: " +
 "{}{}{}, auth-len: {}, auth-data: {}" )
  lprint ( ii1II1II . format ( bold ( "Map-Notify-Ack" , False ) if self . map_notify_ack else bold ( "Map-Notify" , False ) ,
  # i11iIiiIii / OoOoOO00 + iII111i . Oo0Ooo * O0
 self . record_count , lisp_hex_string ( self . nonce ) , self . key_id ,
 self . alg_id , " (sha1)" if ( self . key_id == LISP_SHA_1_96_ALG_ID ) else ( " (sha2)" if ( self . key_id == LISP_SHA_256_128_ALG_ID ) else "" ) , self . auth_len , Oo0oo ) )
  if 60 - 60: oO0o
  if 9 - 9: IiII
  if 68 - 68: I1ii11iIi11i % I1Ii111 + I11i . Oo0Ooo
  if 95 - 95: OOooOOo * i11iIiiIii . I11i + Ii1I / Ii1I
 def zero_auth ( self , packet ) :
  if ( self . alg_id == LISP_NONE_ALG_ID ) : return ( packet )
  if ( self . alg_id == LISP_SHA_1_96_ALG_ID ) :
   Oo0oo = struct . pack ( "QQI" , 0 , 0 , 0 )
   if 43 - 43: IiII . OoooooooOO - II111iiii
  if ( self . alg_id == LISP_SHA_256_128_ALG_ID ) :
   Oo0oo = struct . pack ( "QQQQ" , 0 , 0 , 0 , 0 )
   if 90 - 90: I1IiiI - iIii1I11I1II1 + I1ii11iIi11i * OOooOOo * oO0o
  packet += Oo0oo
  return ( packet )
  if 19 - 19: I1Ii111 * II111iiii % Oo0Ooo - i1IIi
  if 27 - 27: OoOoOO00 . O0 / I1ii11iIi11i . iIii1I11I1II1
 def encode ( self , eid_records , password ) :
  if ( self . map_notify_ack ) :
   oO00O0o0oOOO = ( LISP_MAP_NOTIFY_ACK << 28 ) | self . record_count
  else :
   oO00O0o0oOOO = ( LISP_MAP_NOTIFY << 28 ) | self . record_count
   if 15 - 15: Ii1I + OoO0O00 % iIii1I11I1II1 - I1ii11iIi11i - i1IIi % o0oOOo0O0Ooo
  I1i1iI = struct . pack ( "I" , socket . htonl ( oO00O0o0oOOO ) )
  I1i1iI += struct . pack ( "QBBH" , self . nonce , self . key_id , self . alg_id ,
 socket . htons ( self . auth_len ) )
  if 54 - 54: IiII - II111iiii . ooOoO0o + Ii1I
  if ( self . alg_id == LISP_NONE_ALG_ID ) :
   self . packet = I1i1iI + eid_records
   return ( self . packet )
   if 45 - 45: oO0o + II111iiii . iII111i / I1ii11iIi11i
   if 76 - 76: Ii1I + iII111i - IiII * iIii1I11I1II1 % i1IIi
   if 72 - 72: ooOoO0o + II111iiii . O0 - iII111i / OoooooooOO . I1Ii111
   if 28 - 28: iIii1I11I1II1 . O0
   if 32 - 32: OoooooooOO
  I1i1iI = self . zero_auth ( I1i1iI )
  I1i1iI += eid_records
  if 29 - 29: I1ii11iIi11i
  oooOo00 = lisp_hash_me ( I1i1iI , self . alg_id , password , False )
  if 41 - 41: Ii1I
  O00oOooo0 = struct . calcsize ( "I" ) + struct . calcsize ( "QHH" )
  iii1I = self . auth_len
  self . auth_data = oooOo00
  I1i1iI = I1i1iI [ 0 : O00oOooo0 ] + oooOo00 + I1i1iI [ O00oOooo0 + iii1I : : ]
  self . packet = I1i1iI
  return ( I1i1iI )
  if 49 - 49: Ii1I % II111iiii . Ii1I - o0oOOo0O0Ooo - I11i * IiII
  if 47 - 47: O0 . o0oOOo0O0Ooo / Ii1I * iII111i
 def decode ( self , packet ) :
  IIII11i1Ii = packet
  ii1iI11IiIIi = "I"
  iiii = struct . calcsize ( ii1iI11IiIIi )
  if ( len ( packet ) < iiii ) : return ( None )
  if 63 - 63: I1Ii111 - oO0o - iII111i - ooOoO0o / oO0o + OoO0O00
  oO00O0o0oOOO = struct . unpack ( ii1iI11IiIIi , packet [ : iiii ] )
  oO00O0o0oOOO = socket . ntohl ( oO00O0o0oOOO [ 0 ] )
  self . map_notify_ack = ( ( oO00O0o0oOOO >> 28 ) == LISP_MAP_NOTIFY_ACK )
  self . record_count = oO00O0o0oOOO & 0xff
  packet = packet [ iiii : : ]
  if 94 - 94: IiII / I1IiiI . II111iiii
  ii1iI11IiIIi = "QBBH"
  iiii = struct . calcsize ( ii1iI11IiIIi )
  if ( len ( packet ) < iiii ) : return ( None )
  if 32 - 32: oO0o . OOooOOo % OOooOOo . OoOoOO00
  self . nonce , self . key_id , self . alg_id , self . auth_len = struct . unpack ( ii1iI11IiIIi , packet [ : iiii ] )
  if 37 - 37: OOooOOo + O0 + OOooOOo . iII111i . o0oOOo0O0Ooo
  self . nonce_key = lisp_hex_string ( self . nonce )
  self . auth_len = socket . ntohs ( self . auth_len )
  packet = packet [ iiii : : ]
  self . eid_records = packet [ self . auth_len : : ]
  if 78 - 78: I1IiiI / I11i + o0oOOo0O0Ooo . Oo0Ooo / O0
  if ( self . auth_len == 0 ) : return ( self . eid_records )
  if 49 - 49: I1ii11iIi11i
  if 66 - 66: o0oOOo0O0Ooo . I1ii11iIi11i
  if 18 - 18: Oo0Ooo + IiII
  if 79 - 79: OoO0O00 - O0 + II111iiii % Ii1I . I1IiiI
  if ( len ( packet ) < self . auth_len ) : return ( None )
  if 43 - 43: I1IiiI % I1ii11iIi11i * Ii1I
  iii1I = self . auth_len
  if ( self . alg_id == LISP_SHA_1_96_ALG_ID ) :
   I1ii11i1 , IIi1iII11III , i1IIiIIi11 = struct . unpack ( "QQI" , packet [ : iii1I ] )
   Ooo0 = ""
   if 31 - 31: Ii1I / iII111i
  if ( self . alg_id == LISP_SHA_256_128_ALG_ID ) :
   I1ii11i1 , IIi1iII11III , i1IIiIIi11 , Ooo0 = struct . unpack ( "QQQQ" ,
 packet [ : iii1I ] )
   if 3 - 3: IiII
  self . auth_data = lisp_concat_auth_data ( self . alg_id , I1ii11i1 , IIi1iII11III ,
 i1IIiIIi11 , Ooo0 )
  if 37 - 37: Ii1I * OoooooooOO * I11i + Oo0Ooo . I1IiiI
  iiii = struct . calcsize ( "I" ) + struct . calcsize ( "QHH" )
  packet = self . zero_auth ( IIII11i1Ii [ : iiii ] )
  iiii += iii1I
  packet += IIII11i1Ii [ iiii : : ]
  return ( packet )
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
  if 68 - 68: II111iiii - I1ii11iIi11i - OoO0O00 * iIii1I11I1II1 / I1IiiI * I1ii11iIi11i
  if 45 - 45: I1Ii111 * I11i / iIii1I11I1II1 / I1IiiI % II111iiii
 def print_prefix ( self ) :
  if ( self . target_group . is_null ( ) ) :
   return ( green ( self . target_eid . print_prefix ( ) , False ) )
   if 49 - 49: Ii1I / iII111i . iII111i . iII111i + i11iIiiIii % I11i
  return ( green ( self . target_eid . print_sg ( self . target_group ) , False ) )
  if 7 - 7: IiII * ooOoO0o + OoOoOO00
  if 22 - 22: iII111i
 def print_map_request ( self ) :
  ooO0O = ""
  if ( self . xtr_id != None and self . subscribe_bit ) :
   ooO0O = "subscribe, xtr-id: 0x{}, " . format ( lisp_hex_string ( self . xtr_id ) )
   if 48 - 48: I1ii11iIi11i . I1IiiI
   if 73 - 73: O0 . I1Ii111 - OoooooooOO % I11i % i1IIi
   if 14 - 14: I1Ii111 + Ii1I * Oo0Ooo
  ii1II1II = ( "{} -> flags: {}{}{}{}{}{}{}{}{}{}, itr-rloc-" +
 "count: {} (+1), record-count: {}, nonce: 0x{}, source-eid: " +
 "afi {}, {}{}, target-eid: afi {}, {}, {}ITR-RLOCs:" )
  if 49 - 49: Oo0Ooo
  lprint ( ii1II1II . format ( bold ( "Map-Request" , False ) , "A" if self . auth_bit else "a" ,
  # I1Ii111 % I1ii11iIi11i . oO0o * iII111i
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
 self . target_eid . afi , green ( self . print_prefix ( ) , False ) , ooO0O ) )
  if 89 - 89: iII111i
  IiI1ii11I1 = self . keys
  for i1o0oOoooOoo0 in self . itr_rlocs :
   lprint ( "  itr-rloc: afi {} {}{}" . format ( i1o0oOoooOoo0 . afi ,
 red ( i1o0oOoooOoo0 . print_address_no_iid ( ) , False ) ,
 "" if ( IiI1ii11I1 == None ) else ", " + IiI1ii11I1 [ 1 ] . print_keys ( ) ) )
   IiI1ii11I1 = None
   if 26 - 26: O0 * Ii1I - I1IiiI - iII111i / iIii1I11I1II1
   if 57 - 57: I1ii11iIi11i - OoO0O00 * iIii1I11I1II1
   if 26 - 26: OoO0O00 % ooOoO0o % o0oOOo0O0Ooo % OoOoOO00 . iII111i % O0
 def sign_map_request ( self , privkey ) :
  OoiIiiIi11 = self . signature_eid . print_address ( )
  o0o0oOOo = self . source_eid . print_address ( )
  ooO0000 = self . target_eid . print_address ( )
  Ooo00O0OooOOO = lisp_hex_string ( self . nonce ) + o0o0oOOo + ooO0000
  self . map_request_signature = privkey . sign ( Ooo00O0OooOOO )
  iIIIIi = binascii . b2a_base64 ( self . map_request_signature )
  iIIIIi = { "source-eid" : o0o0oOOo , "signature-eid" : OoiIiiIi11 ,
 "signature" : iIIIIi }
  return ( json . dumps ( iIIIIi ) )
  if 19 - 19: o0oOOo0O0Ooo - Ii1I / OoOoOO00 . I11i % OOooOOo
  if 61 - 61: O0 . Ii1I . O0 * i11iIiiIii * II111iiii / I1Ii111
 def verify_map_request_sig ( self , pubkey ) :
  ooo0Oo000o = green ( self . signature_eid . print_address ( ) , False )
  if ( pubkey == None ) :
   lprint ( "Public-key not found for signature-EID {}" . format ( ooo0Oo000o ) )
   return ( False )
   if 18 - 18: O0
   if 14 - 14: Ii1I / IiII - O0
  o0o0oOOo = self . source_eid . print_address ( )
  ooO0000 = self . target_eid . print_address ( )
  Ooo00O0OooOOO = lisp_hex_string ( self . nonce ) + o0o0oOOo + ooO0000
  pubkey = binascii . a2b_base64 ( pubkey )
  if 16 - 16: I1Ii111 % iIii1I11I1II1 . i1IIi
  o0O0oOOoo0O0 = True
  try :
   i1i11ii1 = ecdsa . VerifyingKey . from_pem ( pubkey )
  except :
   lprint ( "Invalid public-key in mapping system for sig-eid {}" . format ( self . signature_eid . print_address_no_iid ( ) ) )
   if 71 - 71: I1ii11iIi11i + I11i * Oo0Ooo - i1IIi . O0 % i11iIiiIii
   o0O0oOOoo0O0 = False
   if 40 - 40: ooOoO0o - i11iIiiIii % I1ii11iIi11i % I1IiiI . IiII * OoO0O00
   if 51 - 51: O0 % oO0o - ooOoO0o * I1IiiI * oO0o
  if ( o0O0oOOoo0O0 ) :
   try :
    o0O0oOOoo0O0 = i1i11ii1 . verify ( self . map_request_signature , Ooo00O0OooOOO )
   except :
    o0O0oOOoo0O0 = False
    if 90 - 90: Ii1I + Oo0Ooo / iIii1I11I1II1 - O0 + ooOoO0o . I1ii11iIi11i
    if 58 - 58: OoO0O00 + iII111i * o0oOOo0O0Ooo . I11i
    if 48 - 48: OOooOOo
  i111I = bold ( "passed" if o0O0oOOoo0O0 else "failed" , False )
  lprint ( "Signature verification {} for EID {}" . format ( i111I , ooo0Oo000o ) )
  return ( o0O0oOOoo0O0 )
  if 58 - 58: ooOoO0o - Oo0Ooo
  if 23 - 23: OoOoOO00
 def encode ( self , probe_dest , probe_port ) :
  oO00O0o0oOOO = ( LISP_MAP_REQUEST << 28 ) | self . record_count
  oO00O0o0oOOO = oO00O0o0oOOO | ( self . itr_rloc_count << 8 )
  if ( self . auth_bit ) : oO00O0o0oOOO |= 0x08000000
  if ( self . map_data_present ) : oO00O0o0oOOO |= 0x04000000
  if ( self . rloc_probe ) : oO00O0o0oOOO |= 0x02000000
  if ( self . smr_bit ) : oO00O0o0oOOO |= 0x01000000
  if ( self . pitr_bit ) : oO00O0o0oOOO |= 0x00800000
  if ( self . smr_invoked_bit ) : oO00O0o0oOOO |= 0x00400000
  if ( self . mobile_node ) : oO00O0o0oOOO |= 0x00200000
  if ( self . xtr_id_present ) : oO00O0o0oOOO |= 0x00100000
  if ( self . local_xtr ) : oO00O0o0oOOO |= 0x00004000
  if ( self . dont_reply_bit ) : oO00O0o0oOOO |= 0x00002000
  if 38 - 38: I1IiiI . oO0o / O0 % Oo0Ooo / IiII / OoooooooOO
  I1i1iI = struct . pack ( "I" , socket . htonl ( oO00O0o0oOOO ) )
  I1i1iI += struct . pack ( "Q" , self . nonce )
  if 11 - 11: O0 / I1Ii111 / iIii1I11I1II1 % Ii1I
  if 31 - 31: I11i . i11iIiiIii . OoO0O00 * Oo0Ooo % Ii1I . o0oOOo0O0Ooo
  if 92 - 92: OoooooooOO / O0 * i1IIi + iIii1I11I1II1
  if 93 - 93: ooOoO0o % I1Ii111
  if 46 - 46: I1ii11iIi11i * OoOoOO00 * IiII * I1ii11iIi11i . I1ii11iIi11i
  if 43 - 43: ooOoO0o . i1IIi
  O0oOOoOOoOo = False
  ii1IiI = self . privkey_filename
  if ( ii1IiI != None and os . path . exists ( ii1IiI ) ) :
   o0oO00O000O = open ( ii1IiI , "r" ) ; i1i11ii1 = o0oO00O000O . read ( ) ; o0oO00O000O . close ( )
   try :
    i1i11ii1 = ecdsa . SigningKey . from_pem ( i1i11ii1 )
   except :
    return ( None )
    if 44 - 44: i1IIi - I1ii11iIi11i + I1ii11iIi11i . I11i / OOooOOo
   IIiIiI1Ii = self . sign_map_request ( i1i11ii1 )
   O0oOOoOOoOo = True
  elif ( self . map_request_signature != None ) :
   iIIIIi = binascii . b2a_base64 ( self . map_request_signature )
   IIiIiI1Ii = { "source-eid" : self . source_eid . print_address ( ) ,
 "signature-eid" : self . signature_eid . print_address ( ) ,
 "signature" : iIIIIi }
   IIiIiI1Ii = json . dumps ( IIiIiI1Ii )
   O0oOOoOOoOo = True
   if 55 - 55: o0oOOo0O0Ooo * IiII - iII111i
  if ( O0oOOoOOoOo ) :
   I1iI = LISP_LCAF_JSON_TYPE
   IiiIi = socket . htons ( LISP_AFI_LCAF )
   oOO0oOoooOo = socket . htons ( len ( IIiIiI1Ii ) + 2 )
   iIiI1IIiii = socket . htons ( len ( IIiIiI1Ii ) )
   I1i1iI += struct . pack ( "HBBBBHH" , IiiIi , 0 , 0 , I1iI , 0 ,
 oOO0oOoooOo , iIiI1IIiii )
   I1i1iI += IIiIiI1Ii
   I1i1iI += struct . pack ( "H" , 0 )
  else :
   if ( self . source_eid . instance_id != 0 ) :
    I1i1iI += struct . pack ( "H" , socket . htons ( LISP_AFI_LCAF ) )
    I1i1iI += self . source_eid . lcaf_encode_iid ( )
   else :
    I1i1iI += struct . pack ( "H" , socket . htons ( self . source_eid . afi ) )
    I1i1iI += self . source_eid . pack_address ( )
    if 63 - 63: i11iIiiIii
    if 21 - 21: I1Ii111
    if 70 - 70: I11i . OoOoOO00
    if 86 - 86: IiII
    if 25 - 25: Ii1I . O0 . i11iIiiIii + OoooooooOO / OOooOOo
    if 83 - 83: i1IIi % OoOoOO00 % Oo0Ooo
    if 91 - 91: o0oOOo0O0Ooo
  if ( probe_dest ) :
   if ( probe_port == 0 ) : probe_port = LISP_DATA_PORT
   oO00o = probe_dest . print_address_no_iid ( ) + ":" + str ( probe_port )
   if 14 - 14: i11iIiiIii
   if ( lisp_crypto_keys_by_rloc_encap . has_key ( oO00o ) ) :
    self . keys = lisp_crypto_keys_by_rloc_encap [ oO00o ]
    if 17 - 17: IiII + I11i % Oo0Ooo + oO0o
    if 87 - 87: I11i
    if 54 - 54: Ii1I
    if 27 - 27: iII111i % Oo0Ooo . I1ii11iIi11i . i1IIi % OoOoOO00 . o0oOOo0O0Ooo
    if 37 - 37: iII111i + I1Ii111 * Ii1I + IiII
    if 39 - 39: O0 * Oo0Ooo - I1IiiI + Ii1I / II111iiii
    if 66 - 66: ooOoO0o + oO0o % OoooooooOO
  for i1o0oOoooOoo0 in self . itr_rlocs :
   if ( lisp_data_plane_security and self . itr_rlocs . index ( i1o0oOoooOoo0 ) == 0 ) :
    if ( self . keys == None or self . keys [ 1 ] == None ) :
     IiI1ii11I1 = lisp_keys ( 1 )
     self . keys = [ None , IiI1ii11I1 , None , None ]
     if 23 - 23: oO0o . OoOoOO00 + iIii1I11I1II1
    IiI1ii11I1 = self . keys [ 1 ]
    IiI1ii11I1 . add_key_by_nonce ( self . nonce )
    I1i1iI += IiI1ii11I1 . encode_lcaf ( i1o0oOoooOoo0 )
   else :
    I1i1iI += struct . pack ( "H" , socket . htons ( i1o0oOoooOoo0 . afi ) )
    I1i1iI += i1o0oOoooOoo0 . pack_address ( )
    if 17 - 17: IiII
    if 12 - 12: i1IIi . OoO0O00
    if 14 - 14: OOooOOo + II111iiii % OOooOOo . oO0o * ooOoO0o
  o0O00ooo0oO0o = 0 if self . target_eid . is_binary ( ) == False else self . target_eid . mask_len
  if 21 - 21: iIii1I11I1II1 / ooOoO0o * I1Ii111
  if 98 - 98: O0 + o0oOOo0O0Ooo
  i11i = 0
  if ( self . subscribe_bit ) :
   i11i = 0x80
   self . xtr_id_present = True
   if ( self . xtr_id == None ) :
    self . xtr_id = random . randint ( 0 , ( 2 ** 128 ) - 1 )
    if 8 - 8: o0oOOo0O0Ooo * Oo0Ooo + Oo0Ooo % I11i + I1ii11iIi11i * II111iiii
    if 34 - 34: IiII - II111iiii % Ii1I
    if 91 - 91: Oo0Ooo * Oo0Ooo / IiII + Oo0Ooo
  ii1iI11IiIIi = "BB"
  I1i1iI += struct . pack ( ii1iI11IiIIi , i11i , o0O00ooo0oO0o )
  if 94 - 94: ooOoO0o - i1IIi . O0 / I1IiiI
  if ( self . target_group . is_null ( ) == False ) :
   I1i1iI += struct . pack ( "H" , socket . htons ( LISP_AFI_LCAF ) )
   I1i1iI += self . target_eid . lcaf_encode_sg ( self . target_group )
  elif ( self . target_eid . instance_id != 0 or
 self . target_eid . is_geo_prefix ( ) ) :
   I1i1iI += struct . pack ( "H" , socket . htons ( LISP_AFI_LCAF ) )
   I1i1iI += self . target_eid . lcaf_encode_iid ( )
  else :
   I1i1iI += struct . pack ( "H" , socket . htons ( self . target_eid . afi ) )
   I1i1iI += self . target_eid . pack_address ( )
   if 37 - 37: I1ii11iIi11i * I1Ii111 * I1IiiI * O0
   if 35 - 35: I1IiiI - I1ii11iIi11i * iII111i + IiII / i1IIi
   if 46 - 46: Oo0Ooo . ooOoO0o % Oo0Ooo / II111iiii * ooOoO0o * OOooOOo
   if 59 - 59: I1Ii111 * iII111i
   if 31 - 31: I11i / O0
  if ( self . subscribe_bit ) : I1i1iI = self . encode_xtr_id ( I1i1iI )
  return ( I1i1iI )
  if 57 - 57: i1IIi % ooOoO0o
  if 69 - 69: o0oOOo0O0Ooo
 def lcaf_decode_json ( self , packet ) :
  ii1iI11IiIIi = "BBBBHH"
  iiii = struct . calcsize ( ii1iI11IiIIi )
  if ( len ( packet ) < iiii ) : return ( None )
  if 69 - 69: I1Ii111
  OoO , oooO0o0O00o0O , I1iI , oOoO0oO , oOO0oOoooOo , iIiI1IIiii = struct . unpack ( ii1iI11IiIIi , packet [ : iiii ] )
  if 80 - 80: i1IIi % OoOoOO00 + OoO0O00 - OoooooooOO / iIii1I11I1II1 + I1Ii111
  if 65 - 65: Ii1I
  if ( I1iI != LISP_LCAF_JSON_TYPE ) : return ( packet )
  if 71 - 71: I1Ii111 % I1Ii111 . oO0o + i11iIiiIii - i11iIiiIii
  if 16 - 16: iIii1I11I1II1 / I1IiiI / I1Ii111 - i11iIiiIii . ooOoO0o / OOooOOo
  if 13 - 13: o0oOOo0O0Ooo % O0 - I1Ii111 * OoooooooOO / Oo0Ooo - OoooooooOO
  if 78 - 78: oO0o % OoooooooOO
  oOO0oOoooOo = socket . ntohs ( oOO0oOoooOo )
  iIiI1IIiii = socket . ntohs ( iIiI1IIiii )
  packet = packet [ iiii : : ]
  if ( len ( packet ) < oOO0oOoooOo ) : return ( None )
  if ( oOO0oOoooOo != iIiI1IIiii + 2 ) : return ( None )
  if 73 - 73: I1IiiI % ooOoO0o % IiII + i1IIi - OoooooooOO / oO0o
  if 78 - 78: OoooooooOO % oO0o - i11iIiiIii
  if 37 - 37: IiII % Ii1I % i1IIi
  if 23 - 23: ooOoO0o - O0 + i11iIiiIii
  try :
   IIiIiI1Ii = json . loads ( packet [ 0 : iIiI1IIiii ] )
  except :
   return ( None )
   if 98 - 98: OoooooooOO
  packet = packet [ iIiI1IIiii : : ]
  if 61 - 61: o0oOOo0O0Ooo . IiII . O0 + OoooooooOO + O0
  if 65 - 65: i1IIi * OOooOOo * OoooooooOO - IiII . iII111i - OoO0O00
  if 71 - 71: Ii1I * OoOoOO00
  if 33 - 33: i1IIi . i1IIi * OoooooooOO % I1Ii111 * o0oOOo0O0Ooo
  ii1iI11IiIIi = "H"
  iiii = struct . calcsize ( ii1iI11IiIIi )
  ooo0oOOOO00Oo = struct . unpack ( ii1iI11IiIIi , packet [ : iiii ] ) [ 0 ]
  packet = packet [ iiii : : ]
  if ( ooo0oOOOO00Oo != 0 ) : return ( packet )
  if 64 - 64: ooOoO0o / ooOoO0o + I1ii11iIi11i * OOooOOo % OOooOOo
  if 87 - 87: OoO0O00 * Oo0Ooo
  if 83 - 83: i1IIi * I1Ii111 - IiII / Ii1I
  if 48 - 48: oO0o . II111iiii - OoOoOO00 % i1IIi . OoOoOO00
  if ( IIiIiI1Ii . has_key ( "source-eid" ) == False ) : return ( packet )
  I1IiiIiIIi1Ii = IIiIiI1Ii [ "source-eid" ]
  ooo0oOOOO00Oo = LISP_AFI_IPV4 if I1IiiIiIIi1Ii . count ( "." ) == 3 else LISP_AFI_IPV6 if I1IiiIiIIi1Ii . count ( ":" ) == 7 else None
  if 83 - 83: O0 + Ii1I % i11iIiiIii
  if ( ooo0oOOOO00Oo == None ) :
   lprint ( "Bad JSON 'source-eid' value: {}" . format ( I1IiiIiIIi1Ii ) )
   return ( None )
   if 32 - 32: I1Ii111 % Oo0Ooo - I11i + O0
   if 57 - 57: OoO0O00 + I1Ii111 . I11i . i1IIi - o0oOOo0O0Ooo / Oo0Ooo
  self . source_eid . afi = ooo0oOOOO00Oo
  self . source_eid . store_address ( I1IiiIiIIi1Ii )
  if 19 - 19: iIii1I11I1II1 . OoO0O00 / OoooooooOO
  if ( IIiIiI1Ii . has_key ( "signature-eid" ) == False ) : return ( packet )
  I1IiiIiIIi1Ii = IIiIiI1Ii [ "signature-eid" ]
  if ( I1IiiIiIIi1Ii . count ( ":" ) != 7 ) :
   lprint ( "Bad JSON 'signature-eid' value: {}" . format ( I1IiiIiIIi1Ii ) )
   return ( None )
   if 2 - 2: O0 - O0 % I1Ii111 / I1ii11iIi11i
   if 76 - 76: OoO0O00 * oO0o - OoO0O00
  self . signature_eid . afi = LISP_AFI_IPV6
  self . signature_eid . store_address ( I1IiiIiIIi1Ii )
  if 57 - 57: OoooooooOO / OoOoOO00 + oO0o . Ii1I
  if ( IIiIiI1Ii . has_key ( "signature" ) == False ) : return ( packet )
  iIIIIi = binascii . a2b_base64 ( IIiIiI1Ii [ "signature" ] )
  self . map_request_signature = iIIIIi
  return ( packet )
  if 14 - 14: i11iIiiIii % OOooOOo * o0oOOo0O0Ooo * OoOoOO00
  if 55 - 55: I1Ii111 * OOooOOo * I1Ii111
 def decode ( self , packet , source , port ) :
  ii1iI11IiIIi = "I"
  iiii = struct . calcsize ( ii1iI11IiIIi )
  if ( len ( packet ) < iiii ) : return ( None )
  if 70 - 70: O0 . Ii1I
  oO00O0o0oOOO = struct . unpack ( ii1iI11IiIIi , packet [ : iiii ] )
  oO00O0o0oOOO = oO00O0o0oOOO [ 0 ]
  packet = packet [ iiii : : ]
  if 33 - 33: OOooOOo * Ii1I
  ii1iI11IiIIi = "Q"
  iiii = struct . calcsize ( ii1iI11IiIIi )
  if ( len ( packet ) < iiii ) : return ( None )
  if 64 - 64: i11iIiiIii . iIii1I11I1II1
  iII = struct . unpack ( ii1iI11IiIIi , packet [ : iiii ] )
  packet = packet [ iiii : : ]
  if 7 - 7: OoOoOO00 % ooOoO0o + OoOoOO00 - OoOoOO00 * i11iIiiIii % OoO0O00
  oO00O0o0oOOO = socket . ntohl ( oO00O0o0oOOO )
  self . auth_bit = True if ( oO00O0o0oOOO & 0x08000000 ) else False
  self . map_data_present = True if ( oO00O0o0oOOO & 0x04000000 ) else False
  self . rloc_probe = True if ( oO00O0o0oOOO & 0x02000000 ) else False
  self . smr_bit = True if ( oO00O0o0oOOO & 0x01000000 ) else False
  self . pitr_bit = True if ( oO00O0o0oOOO & 0x00800000 ) else False
  self . smr_invoked_bit = True if ( oO00O0o0oOOO & 0x00400000 ) else False
  self . mobile_node = True if ( oO00O0o0oOOO & 0x00200000 ) else False
  self . xtr_id_present = True if ( oO00O0o0oOOO & 0x00100000 ) else False
  self . local_xtr = True if ( oO00O0o0oOOO & 0x00004000 ) else False
  self . dont_reply_bit = True if ( oO00O0o0oOOO & 0x00002000 ) else False
  self . itr_rloc_count = ( ( oO00O0o0oOOO >> 8 ) & 0x1f ) + 1
  self . record_count = oO00O0o0oOOO & 0xff
  self . nonce = iII [ 0 ]
  if 57 - 57: OOooOOo / OoO0O00 + I1ii11iIi11i
  if 60 - 60: O0 * Oo0Ooo % OOooOOo + IiII . OoO0O00 . Oo0Ooo
  if 70 - 70: I11i . I1ii11iIi11i * oO0o
  if 97 - 97: oO0o . iIii1I11I1II1 - OOooOOo
  if ( self . xtr_id_present ) :
   if ( self . decode_xtr_id ( packet ) == False ) : return ( None )
   if 23 - 23: I1ii11iIi11i % I11i
   if 18 - 18: OoooooooOO . i1IIi + II111iiii
  iiii = struct . calcsize ( "H" )
  if ( len ( packet ) < iiii ) : return ( None )
  if 99 - 99: I1Ii111 - I1ii11iIi11i - I1IiiI - I1Ii111 + OoO0O00 + II111iiii
  ooo0oOOOO00Oo = struct . unpack ( "H" , packet [ : iiii ] )
  self . source_eid . afi = socket . ntohs ( ooo0oOOOO00Oo [ 0 ] )
  packet = packet [ iiii : : ]
  if 34 - 34: I1Ii111 * I11i
  if ( self . source_eid . afi == LISP_AFI_LCAF ) :
   i1oO0o00oOo00oO = packet
   packet = self . source_eid . lcaf_decode_iid ( packet )
   if ( packet == None ) :
    packet = self . lcaf_decode_json ( i1oO0o00oOo00oO )
    if ( packet == None ) : return ( None )
    if 68 - 68: iIii1I11I1II1 - I1IiiI . oO0o + OoOoOO00
  elif ( self . source_eid . afi != LISP_AFI_NONE ) :
   packet = self . source_eid . unpack_address ( packet )
   if ( packet == None ) : return ( None )
   if 94 - 94: o0oOOo0O0Ooo % o0oOOo0O0Ooo % II111iiii * iIii1I11I1II1 / IiII . I1ii11iIi11i
  self . source_eid . mask_len = self . source_eid . host_mask_len ( )
  if 13 - 13: OoOoOO00 . I1IiiI . o0oOOo0O0Ooo * oO0o / Ii1I
  i1iiiiIi1 = ( os . getenv ( "LISP_NO_CRYPTO" ) != None )
  self . itr_rlocs = [ ]
  while ( self . itr_rloc_count != 0 ) :
   iiii = struct . calcsize ( "H" )
   if ( len ( packet ) < iiii ) : return ( None )
   if 15 - 15: iII111i - I11i . iIii1I11I1II1 + iIii1I11I1II1
   ooo0oOOOO00Oo = struct . unpack ( "H" , packet [ : iiii ] ) [ 0 ]
   if 74 - 74: IiII * I1ii11iIi11i - OoooooooOO
   i1o0oOoooOoo0 = lisp_address ( LISP_AFI_NONE , "" , 32 , 0 )
   i1o0oOoooOoo0 . afi = socket . ntohs ( ooo0oOOOO00Oo )
   if 59 - 59: ooOoO0o * OoO0O00 - I1Ii111 % oO0o
   if 95 - 95: II111iiii + II111iiii
   if 33 - 33: i1IIi . Oo0Ooo - IiII
   if 30 - 30: OoooooooOO % OOooOOo
   if 14 - 14: OoOoOO00 / OoO0O00 / i11iIiiIii - OoOoOO00 / o0oOOo0O0Ooo - OOooOOo
   if ( i1o0oOoooOoo0 . afi != LISP_AFI_LCAF ) :
    if ( len ( packet ) < i1o0oOoooOoo0 . addr_length ( ) ) : return ( None )
    packet = i1o0oOoooOoo0 . unpack_address ( packet [ iiii : : ] )
    if ( packet == None ) : return ( None )
    if 81 - 81: iII111i % Ii1I . ooOoO0o
    if ( i1iiiiIi1 ) :
     self . itr_rlocs . append ( i1o0oOoooOoo0 )
     self . itr_rloc_count -= 1
     continue
     if 66 - 66: I1ii11iIi11i * Ii1I / OoooooooOO * O0 % OOooOOo
     if 49 - 49: II111iiii . I1IiiI * O0 * Ii1I / I1Ii111 * OoooooooOO
    oO00o = lisp_build_crypto_decap_lookup_key ( i1o0oOoooOoo0 , port )
    if 82 - 82: Oo0Ooo / Ii1I / Ii1I % Ii1I
    if 20 - 20: ooOoO0o
    if 63 - 63: iIii1I11I1II1 . OoO0O00
    if 100 - 100: i1IIi * i1IIi
    if 26 - 26: OOooOOo . OoO0O00 % OoOoOO00
    if ( lisp_nat_traversal and i1o0oOoooOoo0 . is_private_address ( ) and source ) : i1o0oOoooOoo0 = source
    if 94 - 94: IiII
    i1i1iiIi1 = lisp_crypto_keys_by_rloc_decap
    if ( i1i1iiIi1 . has_key ( oO00o ) ) : i1i1iiIi1 . pop ( oO00o )
    if 18 - 18: Ii1I - iII111i
    if 18 - 18: II111iiii
    if 92 - 92: o0oOOo0O0Ooo . I1Ii111 + iII111i % I1Ii111 % i11iIiiIii
    if 46 - 46: OoooooooOO
    if 80 - 80: O0 * iII111i
    if 73 - 73: IiII / Ii1I + I1Ii111 . OOooOOo - II111iiii / iIii1I11I1II1
    lisp_write_ipc_decap_key ( oO00o , None )
   else :
    IIII11i1Ii = packet
    O0oOOO0o0OO0 = lisp_keys ( 1 )
    packet = O0oOOO0o0OO0 . decode_lcaf ( IIII11i1Ii , 0 )
    if ( packet == None ) : return ( None )
    if 7 - 7: I1ii11iIi11i
    if 81 - 81: Oo0Ooo % II111iiii % o0oOOo0O0Ooo / I11i
    if 95 - 95: OoOoOO00 - O0 % OoooooooOO
    if 13 - 13: i11iIiiIii
    oooo0OoOO = [ LISP_CS_25519_CBC , LISP_CS_25519_GCM ,
 LISP_CS_25519_CHACHA ]
    if ( O0oOOO0o0OO0 . cipher_suite in oooo0OoOO ) :
     if ( O0oOOO0o0OO0 . cipher_suite == LISP_CS_25519_CBC or
 O0oOOO0o0OO0 . cipher_suite == LISP_CS_25519_GCM ) :
      i1i11ii1 = lisp_keys ( 1 , do_poly = False , do_chacha = False )
      if 54 - 54: OOooOOo . I1ii11iIi11i * I11i % I1Ii111 . O0 * IiII
     if ( O0oOOO0o0OO0 . cipher_suite == LISP_CS_25519_CHACHA ) :
      i1i11ii1 = lisp_keys ( 1 , do_poly = True , do_chacha = True )
      if 87 - 87: Ii1I % I1ii11iIi11i * Oo0Ooo
    else :
     i1i11ii1 = lisp_keys ( 1 , do_poly = False , do_curve = False ,
 do_chacha = False )
     if 59 - 59: Oo0Ooo / I11i - iIii1I11I1II1 * iIii1I11I1II1
    packet = i1i11ii1 . decode_lcaf ( IIII11i1Ii , 0 )
    if ( packet == None ) : return ( None )
    if 18 - 18: I11i * I1ii11iIi11i / i11iIiiIii / iIii1I11I1II1 * OoooooooOO . OOooOOo
    if ( len ( packet ) < iiii ) : return ( None )
    ooo0oOOOO00Oo = struct . unpack ( "H" , packet [ : iiii ] ) [ 0 ]
    i1o0oOoooOoo0 . afi = socket . ntohs ( ooo0oOOOO00Oo )
    if ( len ( packet ) < i1o0oOoooOoo0 . addr_length ( ) ) : return ( None )
    if 69 - 69: Oo0Ooo * ooOoO0o
    packet = i1o0oOoooOoo0 . unpack_address ( packet [ iiii : : ] )
    if ( packet == None ) : return ( None )
    if 91 - 91: o0oOOo0O0Ooo . ooOoO0o / OoO0O00 / i11iIiiIii * o0oOOo0O0Ooo
    if ( i1iiiiIi1 ) :
     self . itr_rlocs . append ( i1o0oOoooOoo0 )
     self . itr_rloc_count -= 1
     continue
     if 52 - 52: I1IiiI - i11iIiiIii / IiII . oO0o
     if 38 - 38: oO0o + OoooooooOO * OoOoOO00 % oO0o
    oO00o = lisp_build_crypto_decap_lookup_key ( i1o0oOoooOoo0 , port )
    if 91 - 91: i1IIi - I1ii11iIi11i * I1IiiI
    iI1iIiI1Ii1iI = None
    if ( lisp_nat_traversal and i1o0oOoooOoo0 . is_private_address ( ) and source ) : i1o0oOoooOoo0 = source
    if 58 - 58: II111iiii . I1Ii111 . Ii1I * OoooooooOO / Ii1I / I11i
    if 41 - 41: I11i + OoO0O00 . iII111i
    if ( lisp_crypto_keys_by_rloc_decap . has_key ( oO00o ) ) :
     IiI1ii11I1 = lisp_crypto_keys_by_rloc_decap [ oO00o ]
     iI1iIiI1Ii1iI = IiI1ii11I1 [ 1 ] if IiI1ii11I1 and IiI1ii11I1 [ 1 ] else None
     if 73 - 73: i11iIiiIii * I1IiiI + o0oOOo0O0Ooo / oO0o
     if 56 - 56: i1IIi
    IiiI11i1i1i = True
    if ( iI1iIiI1Ii1iI ) :
     if ( iI1iIiI1Ii1iI . compare_keys ( i1i11ii1 ) ) :
      self . keys = [ None , iI1iIiI1Ii1iI , None , None ]
      lprint ( "Maintain stored decap-keys for RLOC {}" . format ( red ( oO00o , False ) ) )
      if 83 - 83: II111iiii + IiII - o0oOOo0O0Ooo % o0oOOo0O0Ooo * o0oOOo0O0Ooo
     else :
      IiiI11i1i1i = False
      o0iiiii1i1 = bold ( "Remote decap-rekeying" , False )
      lprint ( "{} for RLOC {}" . format ( o0iiiii1i1 , red ( oO00o ,
 False ) ) )
      i1i11ii1 . copy_keypair ( iI1iIiI1Ii1iI )
      i1i11ii1 . uptime = iI1iIiI1Ii1iI . uptime
      iI1iIiI1Ii1iI = None
      if 18 - 18: OoOoOO00 * OoOoOO00 - o0oOOo0O0Ooo % ooOoO0o % II111iiii - IiII
      if 75 - 75: OoO0O00 . II111iiii . oO0o / OoO0O00 % iIii1I11I1II1
      if 8 - 8: O0 / II111iiii
    if ( iI1iIiI1Ii1iI == None ) :
     self . keys = [ None , i1i11ii1 , None , None ]
     if ( lisp_i_am_etr == False and lisp_i_am_rtr == False ) :
      i1i11ii1 . local_public_key = None
      lprint ( "{} for {}" . format ( bold ( "Ignoring decap-keys" ,
 False ) , red ( oO00o , False ) ) )
     elif ( i1i11ii1 . remote_public_key != None ) :
      if ( IiiI11i1i1i ) :
       lprint ( "{} for RLOC {}" . format ( bold ( "New decap-keying" , False ) ,
       # Ii1I - I11i . I1Ii111 * I1ii11iIi11i
 red ( oO00o , False ) ) )
       if 87 - 87: IiII . iII111i + oO0o + II111iiii * O0 % OoooooooOO
      i1i11ii1 . compute_shared_key ( "decap" )
      i1i11ii1 . add_key_by_rloc ( oO00o , False )
      if 70 - 70: o0oOOo0O0Ooo
      if 6 - 6: i11iIiiIii + OoooooooOO % i11iIiiIii . I11i * OoooooooOO - Oo0Ooo
      if 88 - 88: oO0o
      if 33 - 33: o0oOOo0O0Ooo / i1IIi
   self . itr_rlocs . append ( i1o0oOoooOoo0 )
   self . itr_rloc_count -= 1
   if 71 - 71: OoooooooOO - iII111i + Ii1I / O0 % o0oOOo0O0Ooo + OoO0O00
   if 83 - 83: IiII * I1ii11iIi11i / IiII * IiII - OOooOOo
  iiii = struct . calcsize ( "BBH" )
  if ( len ( packet ) < iiii ) : return ( None )
  if 89 - 89: OoO0O00 % I11i
  i11i , o0O00ooo0oO0o , ooo0oOOOO00Oo = struct . unpack ( "BBH" , packet [ : iiii ] )
  self . subscribe_bit = ( i11i & 0x80 )
  self . target_eid . afi = socket . ntohs ( ooo0oOOOO00Oo )
  packet = packet [ iiii : : ]
  if 51 - 51: ooOoO0o * Ii1I * OoooooooOO % OoOoOO00
  self . target_eid . mask_len = o0O00ooo0oO0o
  if ( self . target_eid . afi == LISP_AFI_LCAF ) :
   packet , Ii1iI1iiIiII1 = self . target_eid . lcaf_decode_eid ( packet )
   if ( packet == None ) : return ( None )
   if ( Ii1iI1iiIiII1 ) : self . target_group = Ii1iI1iiIiII1
  else :
   packet = self . target_eid . unpack_address ( packet )
   if ( packet == None ) : return ( None )
   packet = packet [ iiii : : ]
   if 35 - 35: I11i % O0
  return ( packet )
  if 48 - 48: I1Ii111 % ooOoO0o . Oo0Ooo + OoO0O00 - oO0o
  if 38 - 38: IiII . iIii1I11I1II1 - II111iiii - Ii1I
 def print_eid_tuple ( self ) :
  return ( lisp_print_eid_tuple ( self . target_eid , self . target_group ) )
  if 63 - 63: OoO0O00 + o0oOOo0O0Ooo + iIii1I11I1II1
  if 97 - 97: oO0o * II111iiii - OOooOOo
 def encode_xtr_id ( self , packet ) :
  ii1I = self . xtr_id >> 64
  O00oO0oOOOOOO = self . xtr_id & 0xffffffffffffffff
  ii1I = byte_swap_64 ( ii1I )
  O00oO0oOOOOOO = byte_swap_64 ( O00oO0oOOOOOO )
  packet += struct . pack ( "QQ" , ii1I , O00oO0oOOOOOO )
  return ( packet )
  if 18 - 18: iII111i * Oo0Ooo . ooOoO0o + Oo0Ooo + OoooooooOO
  if 87 - 87: I1IiiI . oO0o / IiII - OoooooooOO
 def decode_xtr_id ( self , packet ) :
  iiii = struct . calcsize ( "QQ" )
  if ( len ( packet ) < iiii ) : return ( None )
  packet = packet [ len ( packet ) - iiii : : ]
  ii1I , O00oO0oOOOOOO = struct . unpack ( "QQ" , packet [ : iiii ] )
  ii1I = byte_swap_64 ( ii1I )
  O00oO0oOOOOOO = byte_swap_64 ( O00oO0oOOOOOO )
  self . xtr_id = ( ii1I << 64 ) | O00oO0oOOOOOO
  return ( True )
  if 33 - 33: oO0o % OoO0O00 . iIii1I11I1II1 / IiII
  if 3 - 3: Ii1I + OoO0O00
  if 60 - 60: OoO0O00 . OoOoOO00 - I1ii11iIi11i - I1IiiI - II111iiii % Oo0Ooo
  if 62 - 62: O0 + iII111i - iII111i % iIii1I11I1II1
  if 47 - 47: I1Ii111 + I1IiiI
  if 40 - 40: iIii1I11I1II1 % Ii1I + II111iiii - I1IiiI
  if 80 - 80: oO0o
  if 81 - 81: OoooooooOO / ooOoO0o * iIii1I11I1II1 . Oo0Ooo + oO0o / O0
  if 84 - 84: II111iiii - o0oOOo0O0Ooo
  if 78 - 78: IiII
  if 58 - 58: i11iIiiIii - OoOoOO00
  if 67 - 67: I1ii11iIi11i / iII111i + iIii1I11I1II1 % I1IiiI
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
class lisp_map_reply ( ) :
 def __init__ ( self ) :
  self . rloc_probe = False
  self . echo_nonce_capable = False
  self . security = False
  self . record_count = 0
  self . hop_count = 0
  self . nonce = 0
  self . keys = None
  if 47 - 47: iII111i / OoooooooOO - II111iiii
  if 91 - 91: OoOoOO00 + o0oOOo0O0Ooo
 def print_map_reply ( self ) :
  ii1II1II = "{} -> flags: {}{}{}, hop-count: {}, record-count: {}, " + "nonce: 0x{}"
  if 23 - 23: i1IIi
  lprint ( ii1II1II . format ( bold ( "Map-Reply" , False ) , "R" if self . rloc_probe else "r" ,
  # Ii1I
 "E" if self . echo_nonce_capable else "e" ,
 "S" if self . security else "s" , self . hop_count , self . record_count ,
 lisp_hex_string ( self . nonce ) ) )
  if 69 - 69: I1Ii111 - ooOoO0o
  if 43 - 43: OoOoOO00
 def encode ( self ) :
  oO00O0o0oOOO = ( LISP_MAP_REPLY << 28 ) | self . record_count
  oO00O0o0oOOO |= self . hop_count << 8
  if ( self . rloc_probe ) : oO00O0o0oOOO |= 0x08000000
  if ( self . echo_nonce_capable ) : oO00O0o0oOOO |= 0x04000000
  if ( self . security ) : oO00O0o0oOOO |= 0x02000000
  if 54 - 54: O0 * Ii1I
  I1i1iI = struct . pack ( "I" , socket . htonl ( oO00O0o0oOOO ) )
  I1i1iI += struct . pack ( "Q" , self . nonce )
  return ( I1i1iI )
  if 48 - 48: iII111i . I1IiiI + O0
  if 19 - 19: I1IiiI / I1Ii111 - I11i
 def decode ( self , packet ) :
  ii1iI11IiIIi = "I"
  iiii = struct . calcsize ( ii1iI11IiIIi )
  if ( len ( packet ) < iiii ) : return ( None )
  if 49 - 49: iIii1I11I1II1 - iIii1I11I1II1 - OoOoOO00 + IiII / OoOoOO00
  oO00O0o0oOOO = struct . unpack ( ii1iI11IiIIi , packet [ : iiii ] )
  oO00O0o0oOOO = oO00O0o0oOOO [ 0 ]
  packet = packet [ iiii : : ]
  if 74 - 74: OoooooooOO + I1ii11iIi11i % O0
  ii1iI11IiIIi = "Q"
  iiii = struct . calcsize ( ii1iI11IiIIi )
  if ( len ( packet ) < iiii ) : return ( None )
  if 32 - 32: I1ii11iIi11i + I1ii11iIi11i
  iII = struct . unpack ( ii1iI11IiIIi , packet [ : iiii ] )
  packet = packet [ iiii : : ]
  if 89 - 89: ooOoO0o + oO0o + Ii1I - OOooOOo
  oO00O0o0oOOO = socket . ntohl ( oO00O0o0oOOO )
  self . rloc_probe = True if ( oO00O0o0oOOO & 0x08000000 ) else False
  self . echo_nonce_capable = True if ( oO00O0o0oOOO & 0x04000000 ) else False
  self . security = True if ( oO00O0o0oOOO & 0x02000000 ) else False
  self . hop_count = ( oO00O0o0oOOO >> 8 ) & 0xff
  self . record_count = oO00O0o0oOOO & 0xff
  self . nonce = iII [ 0 ]
  if 12 - 12: OoOoOO00 - o0oOOo0O0Ooo - I1Ii111 / I11i
  if ( lisp_crypto_keys_by_nonce . has_key ( self . nonce ) ) :
   self . keys = lisp_crypto_keys_by_nonce [ self . nonce ]
   self . keys [ 1 ] . delete_key_by_nonce ( self . nonce )
   if 17 - 17: OoO0O00 - I1Ii111 - II111iiii / I1Ii111 / Ii1I
  return ( packet )
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
  if 84 - 84: IiII - OoOoOO00 . IiII + ooOoO0o . iII111i
  if 96 - 96: Ii1I % iII111i * Ii1I % I1IiiI . o0oOOo0O0Ooo / o0oOOo0O0Ooo
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
  if 7 - 7: OoO0O00 - ooOoO0o % i1IIi
  if 24 - 24: OoO0O00 % O0 % I11i
 def print_prefix ( self ) :
  if ( self . group . is_null ( ) ) :
   return ( green ( self . eid . print_prefix ( ) , False ) )
   if 61 - 61: ooOoO0o . iII111i / ooOoO0o * OoooooooOO
  return ( green ( self . eid . print_sg ( self . group ) , False ) )
  if 13 - 13: II111iiii
  if 17 - 17: II111iiii
 def print_ttl ( self ) :
  o0O0OOo0oo00 = self . record_ttl
  if ( self . record_ttl & 0x80000000 ) :
   o0O0OOo0oo00 = str ( self . record_ttl & 0x7fffffff ) + " secs"
  elif ( ( o0O0OOo0oo00 % 60 ) == 0 ) :
   o0O0OOo0oo00 = str ( o0O0OOo0oo00 / 60 ) + " hours"
  else :
   o0O0OOo0oo00 = str ( o0O0OOo0oo00 ) + " mins"
   if 84 - 84: OoooooooOO - Oo0Ooo
  return ( o0O0OOo0oo00 )
  if 79 - 79: O0 - oO0o + oO0o . Ii1I . OoOoOO00 - I1ii11iIi11i
  if 74 - 74: ooOoO0o % I1ii11iIi11i * i1IIi
 def store_ttl ( self ) :
  o0O0OOo0oo00 = self . record_ttl * 60
  if ( self . record_ttl & 0x80000000 ) : o0O0OOo0oo00 = self . record_ttl & 0x7fffffff
  return ( o0O0OOo0oo00 )
  if 18 - 18: OoOoOO00
  if 30 - 30: II111iiii
 def print_record ( self , indent , ddt ) :
  IiIi1iiII = ""
  ooO0o0o = ""
  Ii1IiIi1IiI = bold ( "invalid-action" , False )
  if ( ddt ) :
   if ( self . action < len ( lisp_map_referral_action_string ) ) :
    Ii1IiIi1IiI = lisp_map_referral_action_string [ self . action ]
    Ii1IiIi1IiI = bold ( Ii1IiIi1IiI , False )
    IiIi1iiII = ( ", " + bold ( "ddt-incomplete" , False ) ) if self . ddt_incomplete else ""
    if 61 - 61: O0
    ooO0o0o = ( ", sig-count: " + str ( self . signature_count ) ) if ( self . signature_count != 0 ) else ""
    if 25 - 25: ooOoO0o % OoOoOO00 . oO0o
    if 9 - 9: OoOoOO00 . iIii1I11I1II1 . Oo0Ooo - o0oOOo0O0Ooo . IiII
  else :
   if ( self . action < len ( lisp_map_reply_action_string ) ) :
    Ii1IiIi1IiI = lisp_map_reply_action_string [ self . action ]
    if ( self . action != LISP_NO_ACTION ) :
     Ii1IiIi1IiI = bold ( Ii1IiIi1IiI , False )
     if 66 - 66: i11iIiiIii / I1IiiI % I1Ii111
     if 78 - 78: ooOoO0o % OoooooooOO . ooOoO0o % i11iIiiIii + II111iiii
     if 25 - 25: ooOoO0o
     if 83 - 83: Ii1I / OoooooooOO * oO0o . I1IiiI . i1IIi
  ooo0oOOOO00Oo = LISP_AFI_LCAF if ( self . eid . afi < 0 ) else self . eid . afi
  ii1II1II = ( "{}EID-record -> record-ttl: {}, rloc-count: {}, action: " +
 "{}, {}{}{}, map-version: {}, afi: {}, [iid]eid/ml: {}" )
  if 59 - 59: I11i . I11i * I1IiiI - Ii1I % OoOoOO00
  lprint ( ii1II1II . format ( indent , self . print_ttl ( ) , self . rloc_count ,
 Ii1IiIi1IiI , "auth" if ( self . authoritative is True ) else "non-auth" ,
 IiIi1iiII , ooO0o0o , self . map_version , ooo0oOOOO00Oo ,
 green ( self . print_prefix ( ) , False ) ) )
  if 19 - 19: OoooooooOO / Oo0Ooo - I1Ii111 . OoOoOO00
  if 8 - 8: I11i % ooOoO0o . iIii1I11I1II1
 def encode ( self ) :
  OOoooO = self . action << 13
  if ( self . authoritative ) : OOoooO |= 0x1000
  if ( self . ddt_incomplete ) : OOoooO |= 0x800
  if 12 - 12: I1Ii111 - iII111i . OoO0O00 - II111iiii % o0oOOo0O0Ooo - OoO0O00
  if 48 - 48: ooOoO0o * iIii1I11I1II1 % OoOoOO00
  if 100 - 100: II111iiii - i11iIiiIii + OoO0O00 % ooOoO0o - iIii1I11I1II1 * i11iIiiIii
  if 30 - 30: OoO0O00 . OoO0O00 . Ii1I % Ii1I * i1IIi * oO0o
  ooo0oOOOO00Oo = self . eid . afi if ( self . eid . instance_id == 0 ) else LISP_AFI_LCAF
  if ( ooo0oOOOO00Oo < 0 ) : ooo0oOOOO00Oo = LISP_AFI_LCAF
  oooOoooo0Ooo0ooo0 = ( self . group . is_null ( ) == False )
  if ( oooOoooo0Ooo0ooo0 ) : ooo0oOOOO00Oo = LISP_AFI_LCAF
  if 50 - 50: i11iIiiIii . i11iIiiIii * i1IIi / i11iIiiIii . i1IIi - II111iiii
  oooOOoo0o00O0O0oO = ( self . signature_count << 12 ) | self . map_version
  o0O00ooo0oO0o = 0 if self . eid . is_binary ( ) == False else self . eid . mask_len
  if 94 - 94: o0oOOo0O0Ooo - I11i % oO0o % o0oOOo0O0Ooo + I11i
  I1i1iI = struct . pack ( "IBBHHH" , socket . htonl ( self . record_ttl ) ,
 self . rloc_count , o0O00ooo0oO0o , socket . htons ( OOoooO ) ,
 socket . htons ( oooOOoo0o00O0O0oO ) , socket . htons ( ooo0oOOOO00Oo ) )
  if 31 - 31: I1Ii111 * o0oOOo0O0Ooo * II111iiii + O0 / iII111i * ooOoO0o
  if 52 - 52: iIii1I11I1II1 / iII111i . O0 * IiII . I1IiiI
  if 67 - 67: II111iiii + Ii1I - I1IiiI * ooOoO0o
  if 19 - 19: i11iIiiIii * Oo0Ooo
  if ( oooOoooo0Ooo0ooo0 ) :
   I1i1iI += self . eid . lcaf_encode_sg ( self . group )
   return ( I1i1iI )
   if 33 - 33: i11iIiiIii + I1IiiI
   if 95 - 95: I1ii11iIi11i / IiII % iIii1I11I1II1 + O0
   if 6 - 6: IiII
   if 73 - 73: o0oOOo0O0Ooo % o0oOOo0O0Ooo . OOooOOo * I1ii11iIi11i - Ii1I
   if 97 - 97: IiII
  if ( self . eid . afi == LISP_AFI_GEO_COORD and self . eid . instance_id == 0 ) :
   I1i1iI = I1i1iI [ 0 : - 2 ]
   I1i1iI += self . eid . address . encode_geo ( )
   return ( I1i1iI )
   if 15 - 15: O0 - I1IiiI / i1IIi . I1Ii111
   if 64 - 64: ooOoO0o / i1IIi
   if 100 - 100: II111iiii
   if 16 - 16: Ii1I
   if 96 - 96: o0oOOo0O0Ooo / I1Ii111 % Ii1I - ooOoO0o
  if ( ooo0oOOOO00Oo == LISP_AFI_LCAF ) :
   I1i1iI += self . eid . lcaf_encode_iid ( )
   return ( I1i1iI )
   if 35 - 35: OOooOOo
   if 90 - 90: i11iIiiIii
   if 47 - 47: OoO0O00 . i11iIiiIii
   if 9 - 9: OoOoOO00 - I11i . OoooooooOO % ooOoO0o
   if 13 - 13: OoO0O00 * iIii1I11I1II1 + II111iiii - Oo0Ooo - OoOoOO00
  I1i1iI += self . eid . pack_address ( )
  return ( I1i1iI )
  if 43 - 43: iII111i / I1Ii111 * I1IiiI % ooOoO0o % I1IiiI
  if 18 - 18: OoO0O00
 def decode ( self , packet ) :
  ii1iI11IiIIi = "IBBHHH"
  iiii = struct . calcsize ( ii1iI11IiIIi )
  if ( len ( packet ) < iiii ) : return ( None )
  if 99 - 99: iII111i / oO0o . i11iIiiIii / I11i + i1IIi - I11i
  self . record_ttl , self . rloc_count , self . eid . mask_len , OOoooO , self . map_version , self . eid . afi = struct . unpack ( ii1iI11IiIIi , packet [ : iiii ] )
  if 50 - 50: i1IIi
  if 56 - 56: OoO0O00 + I1Ii111 / Ii1I
  if 75 - 75: OoOoOO00
  self . record_ttl = socket . ntohl ( self . record_ttl )
  OOoooO = socket . ntohs ( OOoooO )
  self . action = ( OOoooO >> 13 ) & 0x7
  self . authoritative = True if ( ( OOoooO >> 12 ) & 1 ) else False
  self . ddt_incomplete = True if ( ( OOoooO >> 11 ) & 1 ) else False
  self . map_version = socket . ntohs ( self . map_version )
  self . signature_count = self . map_version >> 12
  self . map_version = self . map_version & 0xfff
  self . eid . afi = socket . ntohs ( self . eid . afi )
  self . eid . instance_id = 0
  packet = packet [ iiii : : ]
  if 96 - 96: o0oOOo0O0Ooo * I11i * Oo0Ooo
  if 36 - 36: OoooooooOO + ooOoO0o . oO0o * ooOoO0o + IiII
  if 45 - 45: oO0o / iII111i + I1ii11iIi11i - Oo0Ooo - ooOoO0o . iIii1I11I1II1
  if 52 - 52: I1IiiI + i1IIi . iII111i * I1IiiI
  if ( self . eid . afi == LISP_AFI_LCAF ) :
   packet , iIiii1Ii1I = self . eid . lcaf_decode_eid ( packet )
   if ( iIiii1Ii1I ) : self . group = iIiii1Ii1I
   self . group . instance_id = self . eid . instance_id
   return ( packet )
   if 36 - 36: ooOoO0o / II111iiii - iII111i / Ii1I
   if 11 - 11: OoooooooOO + o0oOOo0O0Ooo - i11iIiiIii + i1IIi % i1IIi
  packet = self . eid . unpack_address ( packet )
  return ( packet )
  if 68 - 68: IiII - I11i % II111iiii - o0oOOo0O0Ooo % ooOoO0o
  if 41 - 41: iII111i . ooOoO0o % OoooooooOO / I1IiiI * II111iiii - iII111i
 def print_eid_tuple ( self ) :
  return ( lisp_print_eid_tuple ( self . eid , self . group ) )
  if 19 - 19: OoO0O00 . I11i / i11iIiiIii - OoOoOO00 * I11i . IiII
  if 39 - 39: O0 / iIii1I11I1II1 % iII111i + I1Ii111 - O0 . II111iiii
  if 94 - 94: OoOoOO00 * iIii1I11I1II1
  if 11 - 11: I1ii11iIi11i % OOooOOo + Ii1I + oO0o . Oo0Ooo
  if 93 - 93: OOooOOo * Ii1I - o0oOOo0O0Ooo . oO0o . iII111i
  if 64 - 64: Oo0Ooo / iIii1I11I1II1 . OoO0O00 / o0oOOo0O0Ooo / I11i
  if 3 - 3: OOooOOo - o0oOOo0O0Ooo * iIii1I11I1II1 . Ii1I + OoOoOO00 % I1Ii111
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
LISP_UDP_PROTOCOL = 17
LISP_DEFAULT_ECM_TTL = 128
if 90 - 90: I1IiiI - i11iIiiIii
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
  if 42 - 42: OOooOOo . Oo0Ooo
  if 21 - 21: iII111i . I1IiiI / I11i
 def print_ecm ( self ) :
  ii1II1II = ( "{} -> flags: {}{}{}{}, " + "inner IP: {} -> {}, inner UDP: {} -> {}" )
  if 97 - 97: iIii1I11I1II1 + i1IIi - o0oOOo0O0Ooo
  lprint ( ii1II1II . format ( bold ( "ECM" , False ) , "S" if self . security else "s" ,
 "D" if self . ddt else "d" , "E" if self . to_etr else "e" ,
 "M" if self . to_ms else "m" ,
 green ( self . source . print_address ( ) , False ) ,
 green ( self . dest . print_address ( ) , False ) , self . udp_sport ,
 self . udp_dport ) )
  if 73 - 73: OoO0O00 - i11iIiiIii % I1Ii111 / Oo0Ooo - OoooooooOO % OOooOOo
 def encode ( self , packet , inner_source , inner_dest ) :
  self . udp_length = len ( packet ) + 8
  self . source = inner_source
  self . dest = inner_dest
  if ( inner_dest . is_ipv4 ( ) ) :
   self . afi = LISP_AFI_IPV4
   self . length = self . udp_length + 20
   if 79 - 79: I1IiiI / o0oOOo0O0Ooo . Ii1I * I1ii11iIi11i + I11i
  if ( inner_dest . is_ipv6 ( ) ) :
   self . afi = LISP_AFI_IPV6
   self . length = self . udp_length
   if 96 - 96: OoO0O00 * II111iiii
   if 1 - 1: I1IiiI - OoOoOO00
   if 74 - 74: OoOoOO00 * II111iiii + O0 + I11i
   if 3 - 3: iIii1I11I1II1 - i1IIi / iII111i + i1IIi + O0
   if 18 - 18: iIii1I11I1II1 . iII111i % OOooOOo % oO0o + iIii1I11I1II1 * OoooooooOO
   if 78 - 78: IiII
  oO00O0o0oOOO = ( LISP_ECM << 28 )
  if ( self . security ) : oO00O0o0oOOO |= 0x08000000
  if ( self . ddt ) : oO00O0o0oOOO |= 0x04000000
  if ( self . to_etr ) : oO00O0o0oOOO |= 0x02000000
  if ( self . to_ms ) : oO00O0o0oOOO |= 0x01000000
  if 38 - 38: OoO0O00 * I1ii11iIi11i
  iIIIiiI = struct . pack ( "I" , socket . htonl ( oO00O0o0oOOO ) )
  if 97 - 97: O0 - II111iiii * II111iiii % iII111i
  o0oO0oO0O = ""
  if ( self . afi == LISP_AFI_IPV4 ) :
   o0oO0oO0O = struct . pack ( "BBHHHBBH" , 0x45 , 0 , socket . htons ( self . length ) ,
 0 , 0 , self . ttl , self . protocol , socket . htons ( self . ip_checksum ) )
   o0oO0oO0O += self . source . pack_address ( )
   o0oO0oO0O += self . dest . pack_address ( )
   o0oO0oO0O = lisp_ip_checksum ( o0oO0oO0O )
   if 7 - 7: OoOoOO00 * Ii1I * iII111i * O0
  if ( self . afi == LISP_AFI_IPV6 ) :
   o0oO0oO0O = struct . pack ( "BBHHBB" , 0x60 , 0 , 0 , socket . htons ( self . length ) ,
 self . protocol , self . ttl )
   o0oO0oO0O += self . source . pack_address ( )
   o0oO0oO0O += self . dest . pack_address ( )
   if 93 - 93: IiII % I1Ii111 % II111iiii
   if 20 - 20: OoooooooOO * I1Ii111
  I11iiIi1i1 = socket . htons ( self . udp_sport )
  I1 = socket . htons ( self . udp_dport )
  i1I1i1i1I1 = socket . htons ( self . udp_length )
  i1II111ii1ii = socket . htons ( self . udp_checksum )
  IIIiIi1iiI = struct . pack ( "HHHH" , I11iiIi1i1 , I1 , i1I1i1i1I1 , i1II111ii1ii )
  return ( iIIIiiI + o0oO0oO0O + IIIiIi1iiI )
  if 38 - 38: iII111i . OoooooooOO
  if 28 - 28: I1Ii111 * i1IIi . I1ii11iIi11i
 def decode ( self , packet ) :
  if 75 - 75: O0 / oO0o * ooOoO0o - OOooOOo / i1IIi
  if 61 - 61: I11i
  if 100 - 100: O0 - iIii1I11I1II1 * Oo0Ooo
  if 35 - 35: ooOoO0o
  ii1iI11IiIIi = "I"
  iiii = struct . calcsize ( ii1iI11IiIIi )
  if ( len ( packet ) < iiii ) : return ( None )
  if 57 - 57: OoO0O00 . Oo0Ooo + I1IiiI
  oO00O0o0oOOO = struct . unpack ( ii1iI11IiIIi , packet [ : iiii ] )
  if 18 - 18: I1IiiI - I1ii11iIi11i * I11i / i11iIiiIii - o0oOOo0O0Ooo % o0oOOo0O0Ooo
  oO00O0o0oOOO = socket . ntohl ( oO00O0o0oOOO [ 0 ] )
  self . security = True if ( oO00O0o0oOOO & 0x08000000 ) else False
  self . ddt = True if ( oO00O0o0oOOO & 0x04000000 ) else False
  self . to_etr = True if ( oO00O0o0oOOO & 0x02000000 ) else False
  self . to_ms = True if ( oO00O0o0oOOO & 0x01000000 ) else False
  packet = packet [ iiii : : ]
  if 31 - 31: I11i
  if 100 - 100: i11iIiiIii * i11iIiiIii . iIii1I11I1II1 % iII111i * I1ii11iIi11i
  if 17 - 17: Ii1I * IiII * i11iIiiIii / I1ii11iIi11i / i11iIiiIii
  if 23 - 23: OoooooooOO + i11iIiiIii / Oo0Ooo / iII111i . iII111i * I1IiiI
  if ( len ( packet ) < 1 ) : return ( None )
  O0O0O0OO00oo = struct . unpack ( "B" , packet [ 0 : 1 ] ) [ 0 ]
  O0O0O0OO00oo = O0O0O0OO00oo >> 4
  if 98 - 98: IiII
  if ( O0O0O0OO00oo == 4 ) :
   iiii = struct . calcsize ( "HHIBBH" )
   if ( len ( packet ) < iiii ) : return ( None )
   if 23 - 23: I11i / i1IIi * OoO0O00
   O0oo0oo0 , i1I1i1i1I1 , O0oo0oo0 , iiII1II , Iiiii1III1iIi , i1II111ii1ii = struct . unpack ( "HHIBBH" , packet [ : iiii ] )
   self . length = socket . ntohs ( i1I1i1i1I1 )
   self . ttl = iiII1II
   self . protocol = Iiiii1III1iIi
   self . ip_checksum = socket . ntohs ( i1II111ii1ii )
   self . source . afi = self . dest . afi = LISP_AFI_IPV4
   if 13 - 13: Ii1I % IiII . Ii1I . Oo0Ooo % I1Ii111
   if 62 - 62: iIii1I11I1II1 * OoOoOO00 / OoOoOO00 / I1IiiI
   if 38 - 38: I1Ii111
   if 39 - 39: oO0o * I1Ii111 - ooOoO0o + O0
   Iiiii1III1iIi = struct . pack ( "H" , 0 )
   iii11ii1 = struct . calcsize ( "HHIBB" )
   Oo000 = struct . calcsize ( "H" )
   packet = packet [ : iii11ii1 ] + Iiiii1III1iIi + packet [ iii11ii1 + Oo000 : ]
   if 43 - 43: i11iIiiIii % OoooooooOO - I11i
   packet = packet [ iiii : : ]
   packet = self . source . unpack_address ( packet )
   if ( packet == None ) : return ( None )
   packet = self . dest . unpack_address ( packet )
   if ( packet == None ) : return ( None )
   if 54 - 54: II111iiii * OoooooooOO
   if 71 - 71: OOooOOo
  if ( O0O0O0OO00oo == 6 ) :
   iiii = struct . calcsize ( "IHBB" )
   if ( len ( packet ) < iiii ) : return ( None )
   if 87 - 87: II111iiii / iIii1I11I1II1 % I1ii11iIi11i
   O0oo0oo0 , i1I1i1i1I1 , Iiiii1III1iIi , iiII1II = struct . unpack ( "IHBB" , packet [ : iiii ] )
   self . length = socket . ntohs ( i1I1i1i1I1 )
   self . protocol = Iiiii1III1iIi
   self . ttl = iiII1II
   self . source . afi = self . dest . afi = LISP_AFI_IPV6
   if 11 - 11: o0oOOo0O0Ooo * OoO0O00
   packet = packet [ iiii : : ]
   packet = self . source . unpack_address ( packet )
   if ( packet == None ) : return ( None )
   packet = self . dest . unpack_address ( packet )
   if ( packet == None ) : return ( None )
   if 92 - 92: OoOoOO00 . Oo0Ooo * I11i
   if 86 - 86: O0
  self . source . mask_len = self . source . host_mask_len ( )
  self . dest . mask_len = self . dest . host_mask_len ( )
  if 55 - 55: Ii1I / I1Ii111 / I1ii11iIi11i % ooOoO0o % I1IiiI
  iiii = struct . calcsize ( "HHHH" )
  if ( len ( packet ) < iiii ) : return ( None )
  if 55 - 55: oO0o + OoooooooOO % i1IIi
  I11iiIi1i1 , I1 , i1I1i1i1I1 , i1II111ii1ii = struct . unpack ( "HHHH" , packet [ : iiii ] )
  self . udp_sport = socket . ntohs ( I11iiIi1i1 )
  self . udp_dport = socket . ntohs ( I1 )
  self . udp_length = socket . ntohs ( i1I1i1i1I1 )
  self . udp_checksum = socket . ntohs ( i1II111ii1ii )
  packet = packet [ iiii : : ]
  return ( packet )
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
  if 60 - 60: oO0o . OoooooooOO
  if 40 - 40: I11i
 def print_rloc_name ( self , cour = False ) :
  if ( self . rloc_name == None ) : return ( "" )
  iI1Iii11Iii11 = self . rloc_name
  if ( cour ) : iI1Iii11Iii11 = lisp_print_cour ( iI1Iii11Iii11 )
  return ( 'rloc-name: {}' . format ( blue ( iI1Iii11Iii11 , cour ) ) )
  if 29 - 29: o0oOOo0O0Ooo / iIii1I11I1II1
  if 2 - 2: I1ii11iIi11i % Oo0Ooo + IiII / iII111i
 def print_record ( self , indent ) :
  ii1 = self . print_rloc_name ( )
  if ( ii1 != "" ) : ii1 = ", " + ii1
  o0O0oO = ""
  if ( self . geo ) :
   ii1I11 = ""
   if ( self . geo . geo_name ) : ii1I11 = "'{}' " . format ( self . geo . geo_name )
   o0O0oO = ", geo: {}{}" . format ( ii1I11 , self . geo . print_geo ( ) )
   if 31 - 31: II111iiii + OoooooooOO * OoO0O00
  o0oOiiI1 = ""
  if ( self . elp ) :
   ii1I11 = ""
   if ( self . elp . elp_name ) : ii1I11 = "'{}' " . format ( self . elp . elp_name )
   o0oOiiI1 = ", elp: {}{}" . format ( ii1I11 , self . elp . print_elp ( True ) )
   if 64 - 64: OoOoOO00
  iIiiii = ""
  if ( self . rle ) :
   ii1I11 = ""
   if ( self . rle . rle_name ) : ii1I11 = "'{}' " . format ( self . rle . rle_name )
   iIiiii = ", rle: {}{}" . format ( ii1I11 , self . rle . print_rle ( False ) )
   if 25 - 25: II111iiii + I11i
  Oo000O = ""
  if ( self . json ) :
   ii1I11 = ""
   if ( self . json . json_name ) :
    ii1I11 = "'{}' " . format ( self . json . json_name )
    if 6 - 6: I1Ii111 . oO0o . I1ii11iIi11i - ooOoO0o + I1Ii111
   Oo000O = ", json: {}" . format ( self . json . print_json ( False ) )
   if 85 - 85: I1IiiI / I1ii11iIi11i * OoooooooOO
   if 33 - 33: OOooOOo / o0oOOo0O0Ooo + OOooOOo . i11iIiiIii
  iII1IiiIIi = ""
  if ( self . rloc . is_null ( ) == False and self . keys and self . keys [ 1 ] ) :
   iII1IiiIIi = ", " + self . keys [ 1 ] . print_keys ( )
   if 61 - 61: OoooooooOO / OOooOOo % oO0o
   if 48 - 48: I1ii11iIi11i . II111iiii * IiII . I1IiiI * Ii1I
  ii1II1II = ( "{}RLOC-record -> flags: {}, {}/{}/{}/{}, afi: {}, rloc: "
 + "{}{}{}{}{}{}{}" )
  lprint ( ii1II1II . format ( indent , self . print_flags ( ) , self . priority ,
 self . weight , self . mpriority , self . mweight , self . rloc . afi ,
 red ( self . rloc . print_address_no_iid ( ) , False ) , ii1 , o0O0oO ,
 o0oOiiI1 , iIiiii , Oo000O , iII1IiiIIi ) )
  if 82 - 82: OoOoOO00 * I1ii11iIi11i - OoooooooOO / i1IIi + OoooooooOO * I11i
  if 87 - 87: i1IIi . I1ii11iIi11i / ooOoO0o / O0
 def print_flags ( self ) :
  return ( "{}{}{}" . format ( "L" if self . local_bit else "l" , "P" if self . probe_bit else "p" , "R" if self . reach_bit else "r" ) )
  if 62 - 62: o0oOOo0O0Ooo % II111iiii
  if 22 - 22: oO0o - o0oOOo0O0Ooo
  if 89 - 89: OOooOOo
 def store_rloc_entry ( self , rloc_entry ) :
  i11iII1Ii1ii111 = rloc_entry . rloc if ( rloc_entry . translated_rloc . is_null ( ) ) else rloc_entry . translated_rloc
  if 22 - 22: Ii1I
  self . rloc . copy_address ( i11iII1Ii1ii111 )
  if 44 - 44: I1Ii111 % OoOoOO00 + I1Ii111 / OoO0O00
  if ( rloc_entry . rloc_name ) :
   self . rloc_name = rloc_entry . rloc_name
   if 73 - 73: Oo0Ooo . I11i * iII111i . I1ii11iIi11i . O0
   if 38 - 38: oO0o
  if ( rloc_entry . geo ) :
   self . geo = rloc_entry . geo
  else :
   ii1I11 = rloc_entry . geo_name
   if ( ii1I11 and lisp_geo_list . has_key ( ii1I11 ) ) :
    self . geo = lisp_geo_list [ ii1I11 ]
    if 17 - 17: oO0o / iII111i . Ii1I - II111iiii
    if 6 - 6: OOooOOo / OoOoOO00 * o0oOOo0O0Ooo % OoO0O00 + I1Ii111 + iII111i
  if ( rloc_entry . elp ) :
   self . elp = rloc_entry . elp
  else :
   ii1I11 = rloc_entry . elp_name
   if ( ii1I11 and lisp_elp_list . has_key ( ii1I11 ) ) :
    self . elp = lisp_elp_list [ ii1I11 ]
    if 43 - 43: iII111i
    if 25 - 25: OOooOOo % iII111i + iII111i
  if ( rloc_entry . rle ) :
   self . rle = rloc_entry . rle
  else :
   ii1I11 = rloc_entry . rle_name
   if ( ii1I11 and lisp_rle_list . has_key ( ii1I11 ) ) :
    self . rle = lisp_rle_list [ ii1I11 ]
    if 41 - 41: OoO0O00 / I1ii11iIi11i . I1ii11iIi11i / i1IIi - i1IIi - I1ii11iIi11i
    if 78 - 78: iII111i % iII111i % O0 - I11i - OoO0O00
  if ( rloc_entry . json ) :
   self . json = rloc_entry . json
  else :
   ii1I11 = rloc_entry . json_name
   if ( ii1I11 and lisp_json_list . has_key ( ii1I11 ) ) :
    self . json = lisp_json_list [ ii1I11 ]
    if 59 - 59: I1IiiI / I1ii11iIi11i * i1IIi % iII111i
    if 78 - 78: iIii1I11I1II1 / I1ii11iIi11i / IiII
  self . priority = rloc_entry . priority
  self . weight = rloc_entry . weight
  self . mpriority = rloc_entry . mpriority
  self . mweight = rloc_entry . mweight
  if 11 - 11: I11i
  if 59 - 59: OOooOOo - I1Ii111 - II111iiii / i1IIi * OOooOOo . OoooooooOO
 def encode_lcaf ( self ) :
  IiiIi = socket . htons ( LISP_AFI_LCAF )
  I1iiII11i11iI = ""
  if ( self . geo ) :
   I1iiII11i11iI = self . geo . encode_geo ( )
   if 47 - 47: iII111i + o0oOOo0O0Ooo % iIii1I11I1II1 * OoOoOO00
   if 65 - 65: OOooOOo . II111iiii * i11iIiiIii + OOooOOo
  oOOo0OO0oo = ""
  if ( self . elp ) :
   OOO0o0ooO0 = ""
   for i1i in self . elp . elp_nodes :
    ooo0oOOOO00Oo = socket . htons ( i1i . address . afi )
    oooO0o0O00o0O = 0
    if ( i1i . eid ) : oooO0o0O00o0O |= 0x4
    if ( i1i . probe ) : oooO0o0O00o0O |= 0x2
    if ( i1i . strict ) : oooO0o0O00o0O |= 0x1
    oooO0o0O00o0O = socket . htons ( oooO0o0O00o0O )
    OOO0o0ooO0 += struct . pack ( "HH" , oooO0o0O00o0O , ooo0oOOOO00Oo )
    OOO0o0ooO0 += i1i . address . pack_address ( )
    if 89 - 89: iIii1I11I1II1 + I1IiiI . I1Ii111
    if 74 - 74: II111iiii + I1Ii111 + I1IiiI * Oo0Ooo % OoOoOO00
   IIiiI = socket . htons ( len ( OOO0o0ooO0 ) )
   oOOo0OO0oo = struct . pack ( "HBBBBH" , IiiIi , 0 , 0 , LISP_LCAF_ELP_TYPE ,
 0 , IIiiI )
   oOOo0OO0oo += OOO0o0ooO0
   if 34 - 34: o0oOOo0O0Ooo + OOooOOo . OoO0O00 + I1IiiI + OoooooooOO
   if 90 - 90: Ii1I / OoOoOO00 - iIii1I11I1II1 / i1IIi * I1Ii111 - ooOoO0o
  I111I1IiI1i1 = ""
  if ( self . rle ) :
   o0oo = ""
   for OO in self . rle . rle_nodes :
    ooo0oOOOO00Oo = socket . htons ( OO . address . afi )
    o0oo += struct . pack ( "HBBH" , 0 , 0 , OO . level , ooo0oOOOO00Oo )
    o0oo += OO . address . pack_address ( )
    if ( OO . rloc_name ) :
     o0oo += struct . pack ( "H" , socket . htons ( LISP_AFI_NAME ) )
     o0oo += OO . rloc_name + "\0"
     if 88 - 88: OOooOOo / Ii1I . iII111i - OoOoOO00 + iII111i
     if 83 - 83: iII111i + OoooooooOO + i1IIi / Oo0Ooo
     if 28 - 28: I1IiiI
   iI1iI1IIIii = socket . htons ( len ( o0oo ) )
   I111I1IiI1i1 = struct . pack ( "HBBBBH" , IiiIi , 0 , 0 , LISP_LCAF_RLE_TYPE ,
 0 , iI1iI1IIIii )
   I111I1IiI1i1 += o0oo
   if 2 - 2: Ii1I % OOooOOo . OoO0O00
   if 17 - 17: OOooOOo / i11iIiiIii % O0 / I1Ii111
  Oo0ooi1I = ""
  if ( self . json ) :
   oOO0oOoooOo = socket . htons ( len ( self . json . json_string ) + 2 )
   iIiI1IIiii = socket . htons ( len ( self . json . json_string ) )
   Oo0ooi1I = struct . pack ( "HBBBBHH" , IiiIi , 0 , 0 , LISP_LCAF_JSON_TYPE ,
 0 , oOO0oOoooOo , iIiI1IIiii )
   Oo0ooi1I += self . json . json_string
   Oo0ooi1I += struct . pack ( "H" , 0 )
   if 48 - 48: oO0o + iIii1I11I1II1 * o0oOOo0O0Ooo / OoO0O00
   if 27 - 27: OoooooooOO - o0oOOo0O0Ooo . iII111i % oO0o / OOooOOo * iII111i
  IIioOO00oOO0o = ""
  if ( self . rloc . is_null ( ) == False and self . keys and self . keys [ 1 ] ) :
   IIioOO00oOO0o = self . keys [ 1 ] . encode_lcaf ( self . rloc )
   if 85 - 85: Oo0Ooo % I1ii11iIi11i / OOooOOo
   if 65 - 65: ooOoO0o + IiII - OoOoOO00 % II111iiii - iIii1I11I1II1
  iiIIiI = ""
  if ( self . rloc_name ) :
   iiIIiI += struct . pack ( "H" , socket . htons ( LISP_AFI_NAME ) )
   iiIIiI += self . rloc_name + "\0"
   if 16 - 16: I11i
   if 23 - 23: o0oOOo0O0Ooo + ooOoO0o - IiII
  Ii11I111 = len ( I1iiII11i11iI ) + len ( oOOo0OO0oo ) + len ( I111I1IiI1i1 ) + len ( IIioOO00oOO0o ) + 2 + len ( Oo0ooi1I ) + self . rloc . addr_length ( ) + len ( iiIIiI )
  if 63 - 63: I1ii11iIi11i % ooOoO0o % I1ii11iIi11i
  Ii11I111 = socket . htons ( Ii11I111 )
  oOooO00OOoO = struct . pack ( "HBBBBHH" , IiiIi , 0 , 0 , LISP_LCAF_AFI_LIST_TYPE ,
 0 , Ii11I111 , socket . htons ( self . rloc . afi ) )
  oOooO00OOoO += self . rloc . pack_address ( )
  return ( oOooO00OOoO + iiIIiI + I1iiII11i11iI + oOOo0OO0oo + I111I1IiI1i1 + IIioOO00oOO0o + Oo0ooi1I )
  if 22 - 22: O0 + O0 + Oo0Ooo - ooOoO0o
  if 77 - 77: iII111i / II111iiii / OoO0O00 - o0oOOo0O0Ooo
 def encode ( self ) :
  oooO0o0O00o0O = 0
  if ( self . local_bit ) : oooO0o0O00o0O |= 0x0004
  if ( self . probe_bit ) : oooO0o0O00o0O |= 0x0002
  if ( self . reach_bit ) : oooO0o0O00o0O |= 0x0001
  if 87 - 87: Oo0Ooo % I1ii11iIi11i . OoooooooOO % Ii1I * oO0o - I1IiiI
  I1i1iI = struct . pack ( "BBBBHH" , self . priority , self . weight ,
 self . mpriority , self . mweight , socket . htons ( oooO0o0O00o0O ) ,
 socket . htons ( self . rloc . afi ) )
  if 9 - 9: OoooooooOO - Ii1I - Oo0Ooo - Ii1I - iIii1I11I1II1 - iII111i
  if ( self . geo or self . elp or self . rle or self . keys or self . rloc_name or self . json ) :
   if 65 - 65: Oo0Ooo * ooOoO0o % i11iIiiIii
   I1i1iI = I1i1iI [ 0 : - 2 ] + self . encode_lcaf ( )
  else :
   I1i1iI += self . rloc . pack_address ( )
   if 12 - 12: OoOoOO00 . I1ii11iIi11i . Oo0Ooo
  return ( I1i1iI )
  if 61 - 61: I11i / OOooOOo
  if 85 - 85: OoOoOO00 - I11i . OoOoOO00 . OoOoOO00
 def decode_lcaf ( self , packet , nonce ) :
  ii1iI11IiIIi = "HBBBBH"
  iiii = struct . calcsize ( ii1iI11IiIIi )
  if ( len ( packet ) < iiii ) : return ( None )
  if 62 - 62: IiII % OoooooooOO * OoO0O00 + OoO0O00 % Ii1I % iII111i
  ooo0oOOOO00Oo , OoO , oooO0o0O00o0O , I1iI , oOoO0oO , oOO0oOoooOo = struct . unpack ( ii1iI11IiIIi , packet [ : iiii ] )
  if 66 - 66: I1IiiI . OOooOOo - OoO0O00 % Oo0Ooo * o0oOOo0O0Ooo - oO0o
  if 68 - 68: I11i - i11iIiiIii / o0oOOo0O0Ooo + ooOoO0o / I1IiiI
  oOO0oOoooOo = socket . ntohs ( oOO0oOoooOo )
  packet = packet [ iiii : : ]
  if ( oOO0oOoooOo > len ( packet ) ) : return ( None )
  if 31 - 31: I1Ii111 . OoooooooOO . i1IIi
  if 65 - 65: OoO0O00 . ooOoO0o
  if 12 - 12: I1Ii111 + O0 - oO0o . IiII
  if 46 - 46: IiII . ooOoO0o / iII111i
  if ( I1iI == LISP_LCAF_AFI_LIST_TYPE ) :
   while ( oOO0oOoooOo > 0 ) :
    ii1iI11IiIIi = "H"
    iiii = struct . calcsize ( ii1iI11IiIIi )
    if ( oOO0oOoooOo < iiii ) : return ( None )
    if 63 - 63: II111iiii - I1ii11iIi11i * II111iiii
    I1Ii1ii = len ( packet )
    ooo0oOOOO00Oo = struct . unpack ( ii1iI11IiIIi , packet [ : iiii ] ) [ 0 ]
    ooo0oOOOO00Oo = socket . ntohs ( ooo0oOOOO00Oo )
    if 92 - 92: OoO0O00 % ooOoO0o * O0 % iIii1I11I1II1 / i1IIi / OoOoOO00
    if ( ooo0oOOOO00Oo == LISP_AFI_LCAF ) :
     packet = self . decode_lcaf ( packet , nonce )
     if ( packet == None ) : return ( None )
    else :
     packet = packet [ iiii : : ]
     self . rloc_name = None
     if ( ooo0oOOOO00Oo == LISP_AFI_NAME ) :
      packet , iI1Iii11Iii11 = lisp_decode_dist_name ( packet )
      self . rloc_name = iI1Iii11Iii11
     else :
      self . rloc . afi = ooo0oOOOO00Oo
      packet = self . rloc . unpack_address ( packet )
      if ( packet == None ) : return ( None )
      self . rloc . mask_len = self . rloc . host_mask_len ( )
      if 67 - 67: I1Ii111 + I11i + I1Ii111 . OOooOOo % o0oOOo0O0Ooo / ooOoO0o
      if 78 - 78: I1ii11iIi11i . O0
      if 56 - 56: oO0o - i1IIi * O0 / I11i * I1IiiI . I11i
    oOO0oOoooOo -= I1Ii1ii - len ( packet )
    if 54 - 54: i11iIiiIii % i1IIi + Oo0Ooo / OoOoOO00
    if 26 - 26: I11i . I1ii11iIi11i
  elif ( I1iI == LISP_LCAF_GEO_COORD_TYPE ) :
   if 55 - 55: OoOoOO00 * I1Ii111 % OoO0O00 - OoO0O00
   if 34 - 34: O0 * OoO0O00 - oO0o - IiII * Ii1I . II111iiii
   if 28 - 28: O0 % iII111i - i1IIi
   if 49 - 49: ooOoO0o . I11i - iIii1I11I1II1
   I11ii1I11III1 = lisp_geo ( "" )
   packet = I11ii1I11III1 . decode_geo ( packet , oOO0oOoooOo , oOoO0oO )
   if ( packet == None ) : return ( None )
   self . geo = I11ii1I11III1
   if 12 - 12: OoOoOO00 + I11i . OoO0O00 * i11iIiiIii * I11i * I1Ii111
  elif ( I1iI == LISP_LCAF_JSON_TYPE ) :
   if 28 - 28: iIii1I11I1II1 * iIii1I11I1II1 * ooOoO0o % I1ii11iIi11i / i11iIiiIii
   if 90 - 90: OoO0O00 + i1IIi
   if 43 - 43: O0 % oO0o * I1IiiI
   if 64 - 64: II111iiii + i11iIiiIii
   ii1iI11IiIIi = "H"
   iiii = struct . calcsize ( ii1iI11IiIIi )
   if ( oOO0oOoooOo < iiii ) : return ( None )
   if 17 - 17: O0 * I1IiiI
   iIiI1IIiii = struct . unpack ( ii1iI11IiIIi , packet [ : iiii ] ) [ 0 ]
   iIiI1IIiii = socket . ntohs ( iIiI1IIiii )
   if ( oOO0oOoooOo < iiii + iIiI1IIiii ) : return ( None )
   if 40 - 40: iIii1I11I1II1 * iII111i % iIii1I11I1II1
   packet = packet [ iiii : : ]
   self . json = lisp_json ( "" , packet [ 0 : iIiI1IIiii ] )
   packet = packet [ iIiI1IIiii : : ]
   if 39 - 39: i1IIi . Ii1I - Oo0Ooo
  elif ( I1iI == LISP_LCAF_ELP_TYPE ) :
   if 91 - 91: I1IiiI - OoooooooOO - OoooooooOO
   if 69 - 69: iII111i * i11iIiiIii / i1IIi
   if 86 - 86: I1IiiI % I11i * O0 + i1IIi % I1Ii111
   if 97 - 97: II111iiii * OoOoOO00 - I1Ii111 / i11iIiiIii / OoOoOO00
   iII1i = lisp_elp ( None )
   iII1i . elp_nodes = [ ]
   while ( oOO0oOoooOo > 0 ) :
    oooO0o0O00o0O , ooo0oOOOO00Oo = struct . unpack ( "HH" , packet [ : 4 ] )
    if 69 - 69: iIii1I11I1II1 % O0
    ooo0oOOOO00Oo = socket . ntohs ( ooo0oOOOO00Oo )
    if ( ooo0oOOOO00Oo == LISP_AFI_LCAF ) : return ( None )
    if 27 - 27: o0oOOo0O0Ooo + I1IiiI - IiII . i11iIiiIii . I1IiiI
    i1i = lisp_elp_node ( )
    iII1i . elp_nodes . append ( i1i )
    if 25 - 25: O0 + OOooOOo / iII111i
    oooO0o0O00o0O = socket . ntohs ( oooO0o0O00o0O )
    i1i . eid = ( oooO0o0O00o0O & 0x4 )
    i1i . probe = ( oooO0o0O00o0O & 0x2 )
    i1i . strict = ( oooO0o0O00o0O & 0x1 )
    i1i . address . afi = ooo0oOOOO00Oo
    i1i . address . mask_len = i1i . address . host_mask_len ( )
    packet = i1i . address . unpack_address ( packet [ 4 : : ] )
    oOO0oOoooOo -= i1i . address . addr_length ( ) + 4
    if 51 - 51: I11i
   iII1i . select_elp_node ( )
   self . elp = iII1i
   if 54 - 54: i1IIi . O0 . i1IIi . OoO0O00 + I1Ii111 - i11iIiiIii
  elif ( I1iI == LISP_LCAF_RLE_TYPE ) :
   if 80 - 80: OoOoOO00
   if 5 - 5: I1IiiI - I1IiiI / O0 + OOooOOo - i11iIiiIii
   if 87 - 87: i1IIi - O0 % OoooooooOO * i11iIiiIii % i11iIiiIii
   if 19 - 19: ooOoO0o
   o0ooOOoO0oO0 = lisp_rle ( None )
   o0ooOOoO0oO0 . rle_nodes = [ ]
   while ( oOO0oOoooOo > 0 ) :
    O0oo0oo0 , i11ii1i1i , oooo0O , ooo0oOOOO00Oo = struct . unpack ( "HBBH" , packet [ : 6 ] )
    if 2 - 2: IiII + I11i / iIii1I11I1II1 . i11iIiiIii . i1IIi * ooOoO0o
    ooo0oOOOO00Oo = socket . ntohs ( ooo0oOOOO00Oo )
    if ( ooo0oOOOO00Oo == LISP_AFI_LCAF ) : return ( None )
    if 14 - 14: Oo0Ooo . O0 - oO0o - i11iIiiIii
    OO = lisp_rle_node ( )
    o0ooOOoO0oO0 . rle_nodes . append ( OO )
    if 8 - 8: I1IiiI / iIii1I11I1II1 / OoooooooOO / Oo0Ooo / ooOoO0o
    OO . level = oooo0O
    OO . address . afi = ooo0oOOOO00Oo
    OO . address . mask_len = OO . address . host_mask_len ( )
    packet = OO . address . unpack_address ( packet [ 6 : : ] )
    if 80 - 80: I11i
    oOO0oOoooOo -= OO . address . addr_length ( ) + 6
    if ( oOO0oOoooOo >= 2 ) :
     ooo0oOOOO00Oo = struct . unpack ( "H" , packet [ : 2 ] ) [ 0 ]
     if ( socket . ntohs ( ooo0oOOOO00Oo ) == LISP_AFI_NAME ) :
      packet = packet [ 2 : : ]
      packet , OO . rloc_name = lisp_decode_dist_name ( packet )
      if 26 - 26: II111iiii + I1IiiI . II111iiii - oO0o % OoO0O00
      if ( packet == None ) : return ( None )
      oOO0oOoooOo -= len ( OO . rloc_name ) + 1 + 2
      if 1 - 1: OoO0O00 - II111iiii
      if 75 - 75: Oo0Ooo - OoOoOO00 + oO0o % i1IIi * OOooOOo
      if 56 - 56: OoOoOO00 / OoO0O00 / I1IiiI % OoooooooOO
   self . rle = o0ooOOoO0oO0
   self . rle . build_forwarding_list ( )
   if 39 - 39: I1IiiI + II111iiii * Oo0Ooo % Ii1I . o0oOOo0O0Ooo * oO0o
  elif ( I1iI == LISP_LCAF_SECURITY_TYPE ) :
   if 42 - 42: Ii1I / Oo0Ooo
   if 25 - 25: OoooooooOO % Ii1I * I1Ii111 * I11i + I1IiiI % I1ii11iIi11i
   if 70 - 70: Ii1I + I1ii11iIi11i * I11i * i1IIi . I1Ii111
   if 76 - 76: OoooooooOO * OoOoOO00 . OoooooooOO
   if 46 - 46: ooOoO0o * o0oOOo0O0Ooo % II111iiii / I1Ii111
   IIII11i1Ii = packet
   O0oOOO0o0OO0 = lisp_keys ( 1 )
   packet = O0oOOO0o0OO0 . decode_lcaf ( IIII11i1Ii , oOO0oOoooOo )
   if ( packet == None ) : return ( None )
   if 29 - 29: OoO0O00 - i11iIiiIii % Oo0Ooo % o0oOOo0O0Ooo
   if 30 - 30: oO0o - Ii1I % Ii1I
   if 8 - 8: IiII
   if 68 - 68: IiII . OoooooooOO - i11iIiiIii + i11iIiiIii
   oooo0OoOO = [ LISP_CS_25519_CBC , LISP_CS_25519_CHACHA ]
   if ( O0oOOO0o0OO0 . cipher_suite in oooo0OoOO ) :
    if ( O0oOOO0o0OO0 . cipher_suite == LISP_CS_25519_CBC ) :
     i1i11ii1 = lisp_keys ( 1 , do_poly = False , do_chacha = False )
     if 81 - 81: OoOoOO00 + iII111i . i11iIiiIii
    if ( O0oOOO0o0OO0 . cipher_suite == LISP_CS_25519_CHACHA ) :
     i1i11ii1 = lisp_keys ( 1 , do_poly = True , do_chacha = True )
     if 10 - 10: OoOoOO00 + I11i - iIii1I11I1II1 - I11i
   else :
    i1i11ii1 = lisp_keys ( 1 , do_poly = False , do_chacha = False )
    if 58 - 58: ooOoO0o
   packet = i1i11ii1 . decode_lcaf ( IIII11i1Ii , oOO0oOoooOo )
   if ( packet == None ) : return ( None )
   if 98 - 98: Ii1I / OoO0O00 % OoooooooOO
   if ( len ( packet ) < 2 ) : return ( None )
   ooo0oOOOO00Oo = struct . unpack ( "H" , packet [ : 2 ] ) [ 0 ]
   self . rloc . afi = socket . ntohs ( ooo0oOOOO00Oo )
   if ( len ( packet ) < self . rloc . addr_length ( ) ) : return ( None )
   packet = self . rloc . unpack_address ( packet [ 2 : : ] )
   if ( packet == None ) : return ( None )
   self . rloc . mask_len = self . rloc . host_mask_len ( )
   if 65 - 65: ooOoO0o % Oo0Ooo - I1IiiI % I1Ii111 + iIii1I11I1II1 / iIii1I11I1II1
   if 94 - 94: IiII - Oo0Ooo . o0oOOo0O0Ooo - ooOoO0o - oO0o . I11i
   if 39 - 39: oO0o + OoOoOO00
   if 68 - 68: i1IIi * oO0o / i11iIiiIii
   if 96 - 96: I1IiiI
   if 78 - 78: OoO0O00
   if ( self . rloc . is_null ( ) ) : return ( packet )
   if 72 - 72: I1ii11iIi11i / O0 % II111iiii / II111iiii
   IIi1IiiI1i1 = self . rloc_name
   if ( IIi1IiiI1i1 ) : IIi1IiiI1i1 = blue ( self . rloc_name , False )
   if 96 - 96: i1IIi + II111iiii . iIii1I11I1II1 - II111iiii . I1ii11iIi11i - OOooOOo
   if 78 - 78: I1IiiI
   if 90 - 90: I1Ii111
   if 16 - 16: IiII * OoO0O00 * i11iIiiIii - ooOoO0o
   if 88 - 88: iIii1I11I1II1 / Ii1I * IiII / I1Ii111
   if 31 - 31: O0 . I1IiiI
   iI1iIiI1Ii1iI = self . keys [ 1 ] if self . keys else None
   if ( iI1iIiI1Ii1iI == None ) :
    if ( i1i11ii1 . remote_public_key == None ) :
     oOO00OO0OooOo = bold ( "No remote encap-public-key supplied" , False )
     lprint ( "    {} for {}" . format ( oOO00OO0OooOo , IIi1IiiI1i1 ) )
     i1i11ii1 = None
    else :
     oOO00OO0OooOo = bold ( "New encap-keying with new state" , False )
     lprint ( "    {} for {}" . format ( oOO00OO0OooOo , IIi1IiiI1i1 ) )
     i1i11ii1 . compute_shared_key ( "encap" )
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
   if ( iI1iIiI1Ii1iI ) :
    if ( i1i11ii1 . remote_public_key == None ) :
     i1i11ii1 = None
     o0iiiii1i1 = bold ( "Remote encap-unkeying occurred" , False )
     lprint ( "    {} for {}" . format ( o0iiiii1i1 , IIi1IiiI1i1 ) )
    elif ( iI1iIiI1Ii1iI . compare_keys ( i1i11ii1 ) ) :
     i1i11ii1 = iI1iIiI1Ii1iI
     lprint ( "    Maintain stored encap-keys for {}" . format ( IIi1IiiI1i1 ) )
     if 60 - 60: Oo0Ooo - II111iiii + I1IiiI
    else :
     if ( iI1iIiI1Ii1iI . remote_public_key == None ) :
      oOO00OO0OooOo = "New encap-keying for existing state"
     else :
      oOO00OO0OooOo = "Remote encap-rekeying"
      if 17 - 17: OoOoOO00 % I1IiiI
     lprint ( "    {} for {}" . format ( bold ( oOO00OO0OooOo , False ) ,
 IIi1IiiI1i1 ) )
     iI1iIiI1Ii1iI . remote_public_key = i1i11ii1 . remote_public_key
     iI1iIiI1Ii1iI . compute_shared_key ( "encap" )
     i1i11ii1 = iI1iIiI1Ii1iI
     if 8 - 8: Oo0Ooo
     if 49 - 49: OoOoOO00 * I11i - o0oOOo0O0Ooo / OoO0O00 * oO0o
   self . keys = [ None , i1i11ii1 , None , None ]
   if 51 - 51: ooOoO0o - iIii1I11I1II1 . I11i * OoOoOO00 + I1Ii111 * i1IIi
  else :
   if 37 - 37: IiII * oO0o / OoooooooOO . OoO0O00
   if 77 - 77: II111iiii + OoOoOO00 * OOooOOo
   if 9 - 9: II111iiii - i11iIiiIii * o0oOOo0O0Ooo % OoO0O00 * i11iIiiIii / I11i
   if 45 - 45: i11iIiiIii * iII111i - I1ii11iIi11i + ooOoO0o % iII111i
   packet = packet [ oOO0oOoooOo : : ]
   if 11 - 11: iIii1I11I1II1
  return ( packet )
  if 48 - 48: iIii1I11I1II1 - Oo0Ooo
  if 80 - 80: i1IIi
 def decode ( self , packet , nonce ) :
  ii1iI11IiIIi = "BBBBHH"
  iiii = struct . calcsize ( ii1iI11IiIIi )
  if ( len ( packet ) < iiii ) : return ( None )
  if 56 - 56: II111iiii - o0oOOo0O0Ooo
  self . priority , self . weight , self . mpriority , self . mweight , oooO0o0O00o0O , ooo0oOOOO00Oo = struct . unpack ( ii1iI11IiIIi , packet [ : iiii ] )
  if 48 - 48: Oo0Ooo - I1ii11iIi11i - II111iiii . Ii1I . oO0o / iIii1I11I1II1
  if 38 - 38: I1Ii111 % i11iIiiIii + Ii1I * ooOoO0o / I1Ii111
  oooO0o0O00o0O = socket . ntohs ( oooO0o0O00o0O )
  ooo0oOOOO00Oo = socket . ntohs ( ooo0oOOOO00Oo )
  self . local_bit = True if ( oooO0o0O00o0O & 0x0004 ) else False
  self . probe_bit = True if ( oooO0o0O00o0O & 0x0002 ) else False
  self . reach_bit = True if ( oooO0o0O00o0O & 0x0001 ) else False
  if 93 - 93: oO0o
  if ( ooo0oOOOO00Oo == LISP_AFI_LCAF ) :
   packet = packet [ iiii - 2 : : ]
   packet = self . decode_lcaf ( packet , nonce )
  else :
   self . rloc . afi = ooo0oOOOO00Oo
   packet = packet [ iiii : : ]
   packet = self . rloc . unpack_address ( packet )
   if 60 - 60: I1Ii111 . oO0o / Oo0Ooo * ooOoO0o + OoOoOO00 - i1IIi
  self . rloc . mask_len = self . rloc . host_mask_len ( )
  return ( packet )
  if 13 - 13: i11iIiiIii * oO0o / I11i * I1IiiI
  if 31 - 31: iIii1I11I1II1 * Ii1I % OOooOOo . II111iiii
 def end_of_rlocs ( self , packet , rloc_count ) :
  for iiIii1I in range ( rloc_count ) :
   packet = self . decode ( packet , None )
   if ( packet == None ) : return ( None )
   if 56 - 56: IiII / i11iIiiIii . o0oOOo0O0Ooo . oO0o - i11iIiiIii
  return ( packet )
  if 23 - 23: I1ii11iIi11i * i11iIiiIii % ooOoO0o
  if 47 - 47: iIii1I11I1II1 . OOooOOo / I11i % II111iiii
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
class lisp_map_referral ( ) :
 def __init__ ( self ) :
  self . record_count = 0
  self . nonce = 0
  if 79 - 79: O0
  if 71 - 71: OoO0O00 - O0
 def print_map_referral ( self ) :
  lprint ( "{} -> record-count: {}, nonce: 0x{}" . format ( bold ( "Map-Referral" , False ) , self . record_count ,
  # iIii1I11I1II1 . iIii1I11I1II1 . o0oOOo0O0Ooo + i11iIiiIii * oO0o
 lisp_hex_string ( self . nonce ) ) )
  if 48 - 48: iIii1I11I1II1 + OoOoOO00 / o0oOOo0O0Ooo
  if 59 - 59: iIii1I11I1II1
 def encode ( self ) :
  oO00O0o0oOOO = ( LISP_MAP_REFERRAL << 28 ) | self . record_count
  I1i1iI = struct . pack ( "I" , socket . htonl ( oO00O0o0oOOO ) )
  I1i1iI += struct . pack ( "Q" , self . nonce )
  return ( I1i1iI )
  if 82 - 82: o0oOOo0O0Ooo / I1Ii111 + II111iiii . OoooooooOO
  if 32 - 32: i11iIiiIii
 def decode ( self , packet ) :
  ii1iI11IiIIi = "I"
  iiii = struct . calcsize ( ii1iI11IiIIi )
  if ( len ( packet ) < iiii ) : return ( None )
  if 75 - 75: I1Ii111 + o0oOOo0O0Ooo - I1Ii111
  oO00O0o0oOOO = struct . unpack ( ii1iI11IiIIi , packet [ : iiii ] )
  oO00O0o0oOOO = socket . ntohl ( oO00O0o0oOOO [ 0 ] )
  self . record_count = oO00O0o0oOOO & 0xff
  packet = packet [ iiii : : ]
  if 15 - 15: i1IIi % II111iiii
  ii1iI11IiIIi = "Q"
  iiii = struct . calcsize ( ii1iI11IiIIi )
  if ( len ( packet ) < iiii ) : return ( None )
  if 35 - 35: Oo0Ooo - iIii1I11I1II1 - ooOoO0o + I11i
  self . nonce = struct . unpack ( ii1iI11IiIIi , packet [ : iiii ] ) [ 0 ]
  packet = packet [ iiii : : ]
  return ( packet )
  if 11 - 11: OOooOOo / I1ii11iIi11i + I1IiiI * i1IIi
  if 53 - 53: O0
  if 28 - 28: iII111i % OoO0O00 . OoO0O00 / IiII * Oo0Ooo * iII111i
  if 49 - 49: I1IiiI / I1Ii111 * iII111i + I1IiiI % oO0o % ooOoO0o
  if 27 - 27: OoO0O00 / iII111i . I1ii11iIi11i
  if 71 - 71: OoO0O00 . i11iIiiIii . iIii1I11I1II1 + I1IiiI - o0oOOo0O0Ooo
  if 34 - 34: iII111i
  if 6 - 6: OoO0O00 . OoOoOO00 + I1ii11iIi11i
class lisp_ddt_entry ( ) :
 def __init__ ( self ) :
  self . eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . group = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . uptime = lisp_get_timestamp ( )
  self . delegation_set = [ ]
  self . source_cache = None
  self . map_referrals_sent = 0
  if 24 - 24: OoO0O00 . Ii1I
  if 26 - 26: O0 * I1IiiI - OOooOOo * OoooooooOO * II111iiii % OoOoOO00
 def is_auth_prefix ( self ) :
  if ( len ( self . delegation_set ) != 0 ) : return ( False )
  if ( self . is_star_g ( ) ) : return ( False )
  return ( True )
  if 56 - 56: OOooOOo * i11iIiiIii % ooOoO0o * OoOoOO00 % Oo0Ooo * IiII
  if 30 - 30: i1IIi + o0oOOo0O0Ooo - OoOoOO00 . OOooOOo
 def is_ms_peer_entry ( self ) :
  if ( len ( self . delegation_set ) == 0 ) : return ( False )
  return ( self . delegation_set [ 0 ] . is_ms_peer ( ) )
  if 95 - 95: i1IIi . I11i + O0 . I11i - I11i / Oo0Ooo
  if 41 - 41: OoooooooOO . OOooOOo - Ii1I * OoO0O00 % i11iIiiIii
 def print_referral_type ( self ) :
  if ( len ( self . delegation_set ) == 0 ) : return ( "unknown" )
  ii1111IIiIi = self . delegation_set [ 0 ]
  return ( ii1111IIiIi . print_node_type ( ) )
  if 97 - 97: Ii1I / OoOoOO00 + i11iIiiIii - Ii1I
  if 17 - 17: OoO0O00 - oO0o % Oo0Ooo % oO0o * I1Ii111 / IiII
 def print_eid_tuple ( self ) :
  return ( lisp_print_eid_tuple ( self . eid , self . group ) )
  if 88 - 88: ooOoO0o . II111iiii * O0 % IiII
  if 15 - 15: O0 % i1IIi - OOooOOo . IiII
 def add_cache ( self ) :
  if ( self . group . is_null ( ) ) :
   lisp_ddt_cache . add_cache ( self . eid , self )
  else :
   iII1I = lisp_ddt_cache . lookup_cache ( self . group , True )
   if ( iII1I == None ) :
    iII1I = lisp_ddt_entry ( )
    iII1I . eid . copy_address ( self . group )
    iII1I . group . copy_address ( self . group )
    lisp_ddt_cache . add_cache ( self . group , iII1I )
    if 70 - 70: IiII . o0oOOo0O0Ooo / oO0o - i11iIiiIii % II111iiii
   if ( self . eid . is_null ( ) ) : self . eid . make_default_route ( iII1I . group )
   iII1I . add_source_entry ( self )
   if 7 - 7: O0 / OoO0O00
   if 90 - 90: iII111i % oO0o / iIii1I11I1II1
   if 52 - 52: I1IiiI / o0oOOo0O0Ooo
 def add_source_entry ( self , source_ddt ) :
  if ( self . source_cache == None ) : self . source_cache = lisp_cache ( )
  self . source_cache . add_cache ( source_ddt . eid , source_ddt )
  if 20 - 20: I1Ii111 . I1IiiI - iIii1I11I1II1 / iII111i
  if 46 - 46: I1Ii111 . i11iIiiIii
 def lookup_source_cache ( self , source , exact ) :
  if ( self . source_cache == None ) : return ( None )
  return ( self . source_cache . lookup_cache ( source , exact ) )
  if 89 - 89: OoO0O00 - OOooOOo - i1IIi - OoO0O00 % iIii1I11I1II1
  if 52 - 52: o0oOOo0O0Ooo * O0 + I1ii11iIi11i
 def is_star_g ( self ) :
  if ( self . group . is_null ( ) ) : return ( False )
  return ( self . eid . is_exact_match ( self . group ) )
  if 83 - 83: I11i + OOooOOo - OoooooooOO
  if 7 - 7: IiII % ooOoO0o / OoooooooOO / o0oOOo0O0Ooo + OoO0O00 - OoO0O00
  if 15 - 15: i1IIi + OOooOOo / Ii1I
class lisp_ddt_node ( ) :
 def __init__ ( self ) :
  self . delegate_address = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . public_key = ""
  self . map_server_peer = False
  self . map_server_child = False
  self . priority = 0
  self . weight = 0
  if 51 - 51: OOooOOo + O0
  if 91 - 91: i11iIiiIii + o0oOOo0O0Ooo % OoO0O00 / oO0o - i1IIi
 def print_node_type ( self ) :
  if ( self . is_ddt_child ( ) ) : return ( "ddt-child" )
  if ( self . is_ms_child ( ) ) : return ( "map-server-child" )
  if ( self . is_ms_peer ( ) ) : return ( "map-server-peer" )
  if 82 - 82: Ii1I . OoooooooOO + OoooooooOO % OoO0O00 % I1ii11iIi11i
  if 65 - 65: Oo0Ooo . I11i
 def is_ddt_child ( self ) :
  if ( self . map_server_child ) : return ( False )
  if ( self . map_server_peer ) : return ( False )
  return ( True )
  if 7 - 7: Oo0Ooo * II111iiii
  if 11 - 11: OoOoOO00 % OoooooooOO
 def is_ms_child ( self ) :
  return ( self . map_server_child )
  if 92 - 92: OoOoOO00 - iII111i * Ii1I - i1IIi
  if 87 - 87: Ii1I * I1Ii111 + iIii1I11I1II1 * o0oOOo0O0Ooo * iIii1I11I1II1 . I11i
 def is_ms_peer ( self ) :
  return ( self . map_server_peer )
  if 66 - 66: Ii1I / OoO0O00 . O0 . I11i % OoooooooOO / OOooOOo
  if 49 - 49: I1IiiI * iII111i - OoO0O00 % Ii1I + Ii1I * I1Ii111
  if 94 - 94: OoOoOO00 - I11i + Ii1I + OoOoOO00 + II111iiii
  if 61 - 61: IiII + Ii1I / oO0o . OoooooooOO + iII111i
  if 29 - 29: OOooOOo
  if 69 - 69: oO0o % OoooooooOO * iII111i
  if 58 - 58: oO0o / i11iIiiIii . OoOoOO00 % O0 / iIii1I11I1II1
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
  if 50 - 50: I1Ii111 . I11i / O0 . I11i
  if 91 - 91: i11iIiiIii . I1ii11iIi11i + I11i
 def print_ddt_map_request ( self ) :
  lprint ( "Queued Map-Request from {}ITR {}->{}, nonce 0x{}" . format ( "P" if self . from_pitr else "" ,
  # I1Ii111 * IiII - i1IIi * o0oOOo0O0Ooo / I11i
 red ( self . itr . print_address ( ) , False ) ,
 green ( self . eid . print_address ( ) , False ) , self . nonce ) )
  if 36 - 36: iIii1I11I1II1 - OoOoOO00 - II111iiii . IiII / OoO0O00 - oO0o
  if 86 - 86: OoooooooOO / O0 * OoOoOO00 * OOooOOo . OoO0O00
 def queue_map_request ( self ) :
  self . retransmit_timer = threading . Timer ( LISP_DDT_MAP_REQUEST_INTERVAL ,
 lisp_retransmit_ddt_map_request , [ self ] )
  self . retransmit_timer . start ( )
  lisp_ddt_map_requestQ [ str ( self . nonce ) ] = self
  if 15 - 15: o0oOOo0O0Ooo / IiII / ooOoO0o * OoOoOO00
  if 13 - 13: iII111i
 def dequeue_map_request ( self ) :
  self . retransmit_timer . cancel ( )
  if ( lisp_ddt_map_requestQ . has_key ( str ( self . nonce ) ) ) :
   lisp_ddt_map_requestQ . pop ( str ( self . nonce ) )
   if 69 - 69: i11iIiiIii - i11iIiiIii + I11i / I1IiiI % I1ii11iIi11i
   if 56 - 56: iIii1I11I1II1 / OoO0O00 * OOooOOo
   if 73 - 73: OoooooooOO % IiII / I1Ii111 * I11i + i1IIi % i11iIiiIii
 def print_eid_tuple ( self ) :
  return ( lisp_print_eid_tuple ( self . eid , self . group ) )
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
  if 65 - 65: ooOoO0o % II111iiii . iII111i - iIii1I11I1II1 - I1IiiI
  if 63 - 63: I1IiiI . OoOoOO00 - II111iiii
  if 55 - 55: ooOoO0o - o0oOOo0O0Ooo
  if 32 - 32: I1Ii111 * Ii1I / I1Ii111 . OoOoOO00 + I1ii11iIi11i - ooOoO0o
LISP_DDT_ACTION_SITE_NOT_FOUND = - 2
LISP_DDT_ACTION_NULL = - 1
LISP_DDT_ACTION_NODE_REFERRAL = 0
LISP_DDT_ACTION_MS_REFERRAL = 1
LISP_DDT_ACTION_MS_ACK = 2
LISP_DDT_ACTION_MS_NOT_REG = 3
LISP_DDT_ACTION_DELEGATION_HOLE = 4
LISP_DDT_ACTION_NOT_AUTH = 5
LISP_DDT_ACTION_MAX = LISP_DDT_ACTION_NOT_AUTH
if 14 - 14: IiII * O0 + O0 - ooOoO0o . i11iIiiIii - IiII
lisp_map_referral_action_string = [
 "node-referral" , "ms-referral" , "ms-ack" , "ms-not-registered" ,
 "delegation-hole" , "not-authoritative" ]
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
  if 15 - 15: o0oOOo0O0Ooo
  if 55 - 55: i11iIiiIii / OoooooooOO - I11i
 def print_info ( self ) :
  if ( self . info_reply ) :
   O0Oo0oO0 = "Info-Reply"
   i11iII1Ii1ii111 = ( ", ms-port: {}, etr-port: {}, global-rloc: {}, " + "ms-rloc: {}, private-rloc: {}, RTR-list: " ) . format ( self . ms_port , self . etr_port ,
   # I1Ii111
   # Oo0Ooo / I11i . I1ii11iIi11i
 red ( self . global_etr_rloc . print_address_no_iid ( ) , False ) ,
 red ( self . global_ms_rloc . print_address_no_iid ( ) , False ) ,
 red ( self . private_etr_rloc . print_address_no_iid ( ) , False ) )
   if ( len ( self . rtr_list ) == 0 ) : i11iII1Ii1ii111 += "empty, "
   for iiiii11 in self . rtr_list :
    i11iII1Ii1ii111 += red ( iiiii11 . print_address_no_iid ( ) , False ) + ", "
    if 97 - 97: OoO0O00 + Oo0Ooo / Ii1I % iII111i % OoooooooOO / OoOoOO00
   i11iII1Ii1ii111 = i11iII1Ii1ii111 [ 0 : - 2 ]
  else :
   O0Oo0oO0 = "Info-Request"
   o00 = "<none>" if self . hostname == None else self . hostname
   i11iII1Ii1ii111 = ", hostname: {}" . format ( blue ( o00 , False ) )
   if 63 - 63: II111iiii / oO0o + Oo0Ooo . iII111i + oO0o
  lprint ( "{} -> nonce: 0x{}{}" . format ( bold ( O0Oo0oO0 , False ) ,
 lisp_hex_string ( self . nonce ) , i11iII1Ii1ii111 ) )
  if 46 - 46: OoO0O00 / iIii1I11I1II1 % Ii1I
  if 51 - 51: OoO0O00 . OoO0O00 - iIii1I11I1II1
 def encode ( self ) :
  oO00O0o0oOOO = ( LISP_NAT_INFO << 28 )
  if ( self . info_reply ) : oO00O0o0oOOO |= ( 1 << 27 )
  if 41 - 41: OoO0O00 * i11iIiiIii / i1IIi + o0oOOo0O0Ooo . IiII
  if 48 - 48: OoooooooOO * iIii1I11I1II1
  if 69 - 69: II111iiii % O0 + Oo0Ooo / OoOoOO00 + i1IIi / II111iiii
  if 68 - 68: OoOoOO00
  if 78 - 78: OOooOOo / II111iiii + oO0o / I11i * i1IIi
  I1i1iI = struct . pack ( "I" , socket . htonl ( oO00O0o0oOOO ) )
  I1i1iI += struct . pack ( "Q" , self . nonce )
  I1i1iI += struct . pack ( "III" , 0 , 0 , 0 )
  if 93 - 93: II111iiii . I1IiiI
  if 54 - 54: I1Ii111 - i1IIi * Ii1I - i1IIi
  if 3 - 3: oO0o + OoO0O00 - iII111i / Ii1I
  if 58 - 58: Ii1I * I11i
  if ( self . info_reply == False ) :
   if ( self . hostname == None ) :
    I1i1iI += struct . pack ( "H" , 0 )
   else :
    I1i1iI += struct . pack ( "H" , socket . htons ( LISP_AFI_NAME ) )
    I1i1iI += self . hostname + "\0"
    if 95 - 95: oO0o
   return ( I1i1iI )
   if 49 - 49: I1IiiI
   if 23 - 23: I1Ii111
   if 5 - 5: I1ii11iIi11i % OoOoOO00 . OoooooooOO . o0oOOo0O0Ooo + i11iIiiIii
   if 54 - 54: ooOoO0o - O0 + iII111i
   if 34 - 34: Ii1I - OOooOOo % iII111i
  ooo0oOOOO00Oo = socket . htons ( LISP_AFI_LCAF )
  I1iI = LISP_LCAF_NAT_TYPE
  oOO0oOoooOo = socket . htons ( 16 )
  iIii1iii1 = socket . htons ( self . ms_port )
  O0OOo0 = socket . htons ( self . etr_port )
  I1i1iI += struct . pack ( "HHBBHHHH" , ooo0oOOOO00Oo , 0 , I1iI , 0 , oOO0oOoooOo ,
 iIii1iii1 , O0OOo0 , socket . htons ( self . global_etr_rloc . afi ) )
  I1i1iI += self . global_etr_rloc . pack_address ( )
  I1i1iI += struct . pack ( "HH" , 0 , socket . htons ( self . private_etr_rloc . afi ) )
  I1i1iI += self . private_etr_rloc . pack_address ( )
  if ( len ( self . rtr_list ) == 0 ) : I1i1iI += struct . pack ( "H" , 0 )
  if 97 - 97: oO0o + ooOoO0o % I11i
  if 41 - 41: i1IIi * O0
  if 60 - 60: Oo0Ooo + I11i % iIii1I11I1II1 % oO0o - I1Ii111 / o0oOOo0O0Ooo
  if 9 - 9: IiII / oO0o % O0 * I1Ii111 - iIii1I11I1II1 % i1IIi
  for iiiii11 in self . rtr_list :
   I1i1iI += struct . pack ( "H" , socket . htons ( iiiii11 . afi ) )
   I1i1iI += iiiii11 . pack_address ( )
   if 83 - 83: OoOoOO00 + OOooOOo / OoooooooOO
  return ( I1i1iI )
  if 39 - 39: OoO0O00 % iII111i . oO0o . II111iiii - i11iIiiIii
  if 85 - 85: O0 - OoOoOO00
 def decode ( self , packet ) :
  IIII11i1Ii = packet
  ii1iI11IiIIi = "I"
  iiii = struct . calcsize ( ii1iI11IiIIi )
  if ( len ( packet ) < iiii ) : return ( None )
  if 17 - 17: o0oOOo0O0Ooo / i1IIi / OOooOOo
  oO00O0o0oOOO = struct . unpack ( ii1iI11IiIIi , packet [ : iiii ] )
  oO00O0o0oOOO = oO00O0o0oOOO [ 0 ]
  packet = packet [ iiii : : ]
  if 91 - 91: I1ii11iIi11i / Ii1I - OoOoOO00 . I11i / oO0o
  ii1iI11IiIIi = "Q"
  iiii = struct . calcsize ( ii1iI11IiIIi )
  if ( len ( packet ) < iiii ) : return ( None )
  if 16 - 16: IiII % iII111i . oO0o . I1IiiI % O0 * I11i
  iII = struct . unpack ( ii1iI11IiIIi , packet [ : iiii ] )
  if 99 - 99: OoOoOO00 / OoooooooOO + iII111i * I11i * i11iIiiIii + OOooOOo
  oO00O0o0oOOO = socket . ntohl ( oO00O0o0oOOO )
  self . nonce = iII [ 0 ]
  self . info_reply = oO00O0o0oOOO & 0x08000000
  self . hostname = None
  packet = packet [ iiii : : ]
  if 40 - 40: II111iiii / I11i % I1IiiI - O0
  if 39 - 39: i11iIiiIii - OoOoOO00 % OOooOOo + ooOoO0o + i11iIiiIii
  if 59 - 59: IiII / OoOoOO00 - I1Ii111 - ooOoO0o . oO0o
  if 87 - 87: oO0o + I1IiiI * I1Ii111 * o0oOOo0O0Ooo + O0
  if 21 - 21: I1Ii111 + OoOoOO00 + OoOoOO00 . II111iiii / I1Ii111 . I1IiiI
  ii1iI11IiIIi = "HH"
  iiii = struct . calcsize ( ii1iI11IiIIi )
  if ( len ( packet ) < iiii ) : return ( None )
  if 66 - 66: I1Ii111 % oO0o . iII111i * i1IIi
  if 81 - 81: OoooooooOO * I1IiiI / I1Ii111
  if 10 - 10: I1IiiI - II111iiii / IiII * II111iiii
  if 67 - 67: II111iiii . Ii1I % oO0o . Oo0Ooo + IiII
  if 10 - 10: OOooOOo - OoO0O00 * oO0o / iIii1I11I1II1 - OoOoOO00
  iI11i , iii1I = struct . unpack ( ii1iI11IiIIi , packet [ : iiii ] )
  if ( iii1I != 0 ) : return ( None )
  if 20 - 20: IiII % I1IiiI + iIii1I11I1II1 % iII111i
  packet = packet [ iiii : : ]
  ii1iI11IiIIi = "IBBH"
  iiii = struct . calcsize ( ii1iI11IiIIi )
  if ( len ( packet ) < iiii ) : return ( None )
  if 100 - 100: o0oOOo0O0Ooo - Oo0Ooo % I1Ii111 . i11iIiiIii % OoooooooOO
  o0O0OOo0oo00 , Iii1I , II1i , oOO0Oo = struct . unpack ( ii1iI11IiIIi ,
 packet [ : iiii ] )
  if 17 - 17: Oo0Ooo / O0 - O0
  if ( oOO0Oo != 0 ) : return ( None )
  packet = packet [ iiii : : ]
  if 83 - 83: OOooOOo / Ii1I * I1IiiI % oO0o / iIii1I11I1II1
  if 1 - 1: I11i / OoooooooOO / iII111i
  if 68 - 68: i1IIi / Oo0Ooo / I11i * Oo0Ooo
  if 91 - 91: OoO0O00 . iII111i
  if ( self . info_reply == False ) :
   ii1iI11IiIIi = "H"
   iiii = struct . calcsize ( ii1iI11IiIIi )
   if ( len ( packet ) >= iiii ) :
    ooo0oOOOO00Oo = struct . unpack ( ii1iI11IiIIi , packet [ : iiii ] ) [ 0 ]
    if ( socket . ntohs ( ooo0oOOOO00Oo ) == LISP_AFI_NAME ) :
     packet = packet [ iiii : : ]
     packet , self . hostname = lisp_decode_dist_name ( packet )
     if 82 - 82: I1ii11iIi11i / Oo0Ooo
     if 63 - 63: I1IiiI
   return ( IIII11i1Ii )
   if 3 - 3: iII111i + I1ii11iIi11i
   if 35 - 35: oO0o * iII111i * oO0o * I1Ii111 * IiII * i1IIi
   if 43 - 43: OoO0O00 * I1IiiI / IiII . i11iIiiIii + iII111i + o0oOOo0O0Ooo
   if 1 - 1: I1IiiI % o0oOOo0O0Ooo . I1Ii111 + I11i * oO0o
   if 41 - 41: OoO0O00 * oO0o - II111iiii
  ii1iI11IiIIi = "HHBBHHH"
  iiii = struct . calcsize ( ii1iI11IiIIi )
  if ( len ( packet ) < iiii ) : return ( None )
  if 2 - 2: IiII + IiII - OoO0O00 * iII111i . oO0o
  ooo0oOOOO00Oo , O0oo0oo0 , I1iI , Iii1I , oOO0oOoooOo , iIii1iii1 , O0OOo0 = struct . unpack ( ii1iI11IiIIi , packet [ : iiii ] )
  if 91 - 91: ooOoO0o
  if 22 - 22: ooOoO0o % OoO0O00 * OoOoOO00 + Oo0Ooo
  if ( socket . ntohs ( ooo0oOOOO00Oo ) != LISP_AFI_LCAF ) : return ( None )
  if 44 - 44: O0 - I11i
  self . ms_port = socket . ntohs ( iIii1iii1 )
  self . etr_port = socket . ntohs ( O0OOo0 )
  packet = packet [ iiii : : ]
  if 43 - 43: O0
  if 50 - 50: I11i - OoooooooOO
  if 29 - 29: oO0o * oO0o
  if 44 - 44: ooOoO0o . I1IiiI * oO0o * Ii1I
  ii1iI11IiIIi = "H"
  iiii = struct . calcsize ( ii1iI11IiIIi )
  if ( len ( packet ) < iiii ) : return ( None )
  if 41 - 41: i1IIi % i11iIiiIii + I11i % OoooooooOO / I1ii11iIi11i
  if 8 - 8: OoooooooOO - OoO0O00 / i11iIiiIii / O0 . IiII
  if 86 - 86: ooOoO0o * OoooooooOO + iII111i + o0oOOo0O0Ooo
  if 79 - 79: i1IIi % I1ii11iIi11i - OoO0O00 % I1ii11iIi11i
  ooo0oOOOO00Oo = struct . unpack ( ii1iI11IiIIi , packet [ : iiii ] ) [ 0 ]
  packet = packet [ iiii : : ]
  if ( ooo0oOOOO00Oo != 0 ) :
   self . global_etr_rloc . afi = socket . ntohs ( ooo0oOOOO00Oo )
   packet = self . global_etr_rloc . unpack_address ( packet )
   if ( packet == None ) : return ( None )
   self . global_etr_rloc . mask_len = self . global_etr_rloc . host_mask_len ( )
   if 6 - 6: Oo0Ooo / iII111i . i11iIiiIii
   if 8 - 8: I1ii11iIi11i + O0 - oO0o % II111iiii . I1Ii111
   if 86 - 86: IiII
   if 71 - 71: Ii1I - i1IIi . I1IiiI
   if 15 - 15: i1IIi % II111iiii / II111iiii - I1ii11iIi11i - I11i % i1IIi
   if 54 - 54: i1IIi . OoO0O00 + iII111i + OoO0O00 * i1IIi
  if ( len ( packet ) < iiii ) : return ( IIII11i1Ii )
  if 13 - 13: Oo0Ooo / OoO0O00 + OOooOOo
  ooo0oOOOO00Oo = struct . unpack ( ii1iI11IiIIi , packet [ : iiii ] ) [ 0 ]
  packet = packet [ iiii : : ]
  if ( ooo0oOOOO00Oo != 0 ) :
   self . global_ms_rloc . afi = socket . ntohs ( ooo0oOOOO00Oo )
   packet = self . global_ms_rloc . unpack_address ( packet )
   if ( packet == None ) : return ( IIII11i1Ii )
   self . global_ms_rloc . mask_len = self . global_ms_rloc . host_mask_len ( )
   if 90 - 90: OoO0O00 * i11iIiiIii / oO0o
   if 91 - 91: iII111i - OoOoOO00 / Oo0Ooo % II111iiii / II111iiii / o0oOOo0O0Ooo
   if 34 - 34: OoO0O00 * II111iiii + i11iIiiIii % Ii1I
   if 25 - 25: OoOoOO00 + IiII . i11iIiiIii
   if 87 - 87: I1IiiI + OoooooooOO + O0
  if ( len ( packet ) < iiii ) : return ( IIII11i1Ii )
  if 32 - 32: Ii1I / I1ii11iIi11i . Ii1I
  ooo0oOOOO00Oo = struct . unpack ( ii1iI11IiIIi , packet [ : iiii ] ) [ 0 ]
  packet = packet [ iiii : : ]
  if ( ooo0oOOOO00Oo != 0 ) :
   self . private_etr_rloc . afi = socket . ntohs ( ooo0oOOOO00Oo )
   packet = self . private_etr_rloc . unpack_address ( packet )
   if ( packet == None ) : return ( IIII11i1Ii )
   self . private_etr_rloc . mask_len = self . private_etr_rloc . host_mask_len ( )
   if 65 - 65: IiII
   if 74 - 74: Oo0Ooo + i1IIi - II111iiii / ooOoO0o / iII111i
   if 66 - 66: ooOoO0o / IiII * iIii1I11I1II1
   if 42 - 42: I1Ii111 - i11iIiiIii % II111iiii * ooOoO0o . O0 % I11i
   if 82 - 82: Oo0Ooo % O0 + I1ii11iIi11i % I1ii11iIi11i
   if 74 - 74: O0 * IiII . I11i - I1Ii111 + O0 + I11i
  while ( len ( packet ) >= iiii ) :
   ooo0oOOOO00Oo = struct . unpack ( ii1iI11IiIIi , packet [ : iiii ] ) [ 0 ]
   packet = packet [ iiii : : ]
   if ( ooo0oOOOO00Oo == 0 ) : continue
   iiiii11 = lisp_address ( socket . ntohs ( ooo0oOOOO00Oo ) , "" , 0 , 0 )
   packet = iiiii11 . unpack_address ( packet )
   if ( packet == None ) : return ( IIII11i1Ii )
   iiiii11 . mask_len = iiiii11 . host_mask_len ( )
   self . rtr_list . append ( iiiii11 )
   if 48 - 48: oO0o . o0oOOo0O0Ooo - OOooOOo
  return ( IIII11i1Ii )
  if 29 - 29: Oo0Ooo - Ii1I - Oo0Ooo
  if 89 - 89: Oo0Ooo . OoO0O00 . I1ii11iIi11i * oO0o . O0
  if 72 - 72: i11iIiiIii % I11i / I1Ii111 + I1IiiI * iII111i
class lisp_nat_info ( ) :
 def __init__ ( self , addr_str , hostname , port ) :
  self . address = addr_str
  self . hostname = hostname
  self . port = port
  self . uptime = lisp_get_timestamp ( )
  if 69 - 69: I1Ii111 + O0 . IiII . o0oOOo0O0Ooo
  if 38 - 38: IiII / i1IIi
 def timed_out ( self ) :
  oO000o = time . time ( ) - self . uptime
  return ( oO000o >= ( LISP_INFO_INTERVAL * 2 ) )
  if 60 - 60: OoOoOO00
  if 75 - 75: II111iiii / iIii1I11I1II1 / OoooooooOO
  if 61 - 61: IiII . IiII
class lisp_info_source ( ) :
 def __init__ ( self , hostname , addr_str , port ) :
  self . address = lisp_address ( LISP_AFI_IPV4 , addr_str , 32 , 0 )
  self . port = port
  self . uptime = lisp_get_timestamp ( )
  self . nonce = None
  self . hostname = hostname
  self . no_timeout = False
  if 17 - 17: OoOoOO00 % Oo0Ooo / I1Ii111 . Ii1I % OoO0O00
  if 32 - 32: I1IiiI + ooOoO0o / O0 * i11iIiiIii % Oo0Ooo + II111iiii
 def cache_address_for_info_source ( self ) :
  i1i11ii1 = self . address . print_address_no_iid ( ) + self . hostname
  lisp_info_sources_by_address [ i1i11ii1 ] = self
  if 95 - 95: iII111i / ooOoO0o + I1Ii111
  if 78 - 78: iIii1I11I1II1 / I1IiiI - IiII
 def cache_nonce_for_info_source ( self , nonce ) :
  self . nonce = nonce
  lisp_info_sources_by_nonce [ nonce ] = self
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
def lisp_concat_auth_data ( alg_id , auth1 , auth2 , auth3 , auth4 ) :
 if 41 - 41: Ii1I / OoO0O00 / OoO0O00 * I11i
 if ( lisp_is_x86 ( ) ) :
  if ( auth1 != "" ) : auth1 = byte_swap_64 ( auth1 )
  if ( auth2 != "" ) : auth2 = byte_swap_64 ( auth2 )
  if ( auth3 != "" ) :
   if ( alg_id == LISP_SHA_1_96_ALG_ID ) : auth3 = socket . ntohl ( auth3 )
   else : auth3 = byte_swap_64 ( auth3 )
   if 31 - 31: Ii1I / OoooooooOO % iIii1I11I1II1 - IiII * I1IiiI - O0
  if ( auth4 != "" ) : auth4 = byte_swap_64 ( auth4 )
  if 31 - 31: oO0o
  if 74 - 74: OoO0O00
 if ( alg_id == LISP_SHA_1_96_ALG_ID ) :
  auth1 = lisp_hex_string ( auth1 )
  auth1 = auth1 . zfill ( 16 )
  auth2 = lisp_hex_string ( auth2 )
  auth2 = auth2 . zfill ( 16 )
  auth3 = lisp_hex_string ( auth3 )
  auth3 = auth3 . zfill ( 8 )
  Oo0oo = auth1 + auth2 + auth3
  if 11 - 11: oO0o + O0 % Ii1I . I11i * o0oOOo0O0Ooo
 if ( alg_id == LISP_SHA_256_128_ALG_ID ) :
  auth1 = lisp_hex_string ( auth1 )
  auth1 = auth1 . zfill ( 16 )
  auth2 = lisp_hex_string ( auth2 )
  auth2 = auth2 . zfill ( 16 )
  auth3 = lisp_hex_string ( auth3 )
  auth3 = auth3 . zfill ( 16 )
  auth4 = lisp_hex_string ( auth4 )
  auth4 = auth4 . zfill ( 16 )
  Oo0oo = auth1 + auth2 + auth3 + auth4
  if 14 - 14: I11i . iIii1I11I1II1 + I1Ii111 % OoooooooOO
 return ( Oo0oo )
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
def lisp_open_listen_socket ( local_addr , port ) :
 if ( port . isdigit ( ) ) :
  if ( local_addr . find ( "." ) != - 1 ) :
   OOo00 = socket . socket ( socket . AF_INET , socket . SOCK_DGRAM )
   if 3 - 3: O0
  if ( local_addr . find ( ":" ) != - 1 ) :
   if ( lisp_is_raspbian ( ) ) : return ( None )
   OOo00 = socket . socket ( socket . AF_INET6 , socket . SOCK_DGRAM )
   if 73 - 73: I1Ii111 + OoOoOO00
  OOo00 . bind ( ( local_addr , int ( port ) ) )
 else :
  ii1I11 = port
  if ( os . path . exists ( ii1I11 ) ) :
   os . system ( "rm " + ii1I11 )
   time . sleep ( 1 )
   if 59 - 59: IiII + oO0o % i11iIiiIii / I1IiiI
  OOo00 = socket . socket ( socket . AF_UNIX , socket . SOCK_DGRAM )
  OOo00 . bind ( ii1I11 )
  if 76 - 76: o0oOOo0O0Ooo * Ii1I % I1ii11iIi11i % I1ii11iIi11i * I1IiiI
 return ( OOo00 )
 if 59 - 59: iII111i / ooOoO0o % OoO0O00 / I1ii11iIi11i - IiII
 if 96 - 96: O0 / I11i - iIii1I11I1II1
 if 74 - 74: II111iiii % o0oOOo0O0Ooo - iII111i
 if 53 - 53: I1IiiI * iIii1I11I1II1 % Oo0Ooo * OOooOOo - OOooOOo
 if 88 - 88: I1Ii111
 if 72 - 72: iIii1I11I1II1 % i1IIi / OoO0O00 / I1IiiI - II111iiii - I1Ii111
 if 43 - 43: o0oOOo0O0Ooo - Oo0Ooo - I1ii11iIi11i / II111iiii + I1IiiI / I1ii11iIi11i
def lisp_open_send_socket ( internal_name , afi ) :
 if ( internal_name == "" ) :
  if ( afi == LISP_AFI_IPV4 ) :
   OOo00 = socket . socket ( socket . AF_INET , socket . SOCK_DGRAM )
   if 34 - 34: Oo0Ooo
  if ( afi == LISP_AFI_IPV6 ) :
   if ( lisp_is_raspbian ( ) ) : return ( None )
   OOo00 = socket . socket ( socket . AF_INET6 , socket . SOCK_DGRAM )
   if 21 - 21: I1IiiI / I1IiiI % I1Ii111 - OoOoOO00 % OoOoOO00 - II111iiii
 else :
  if ( os . path . exists ( internal_name ) ) : os . system ( "rm " + internal_name )
  OOo00 = socket . socket ( socket . AF_UNIX , socket . SOCK_DGRAM )
  OOo00 . bind ( internal_name )
  if 97 - 97: oO0o
 return ( OOo00 )
 if 98 - 98: I1Ii111 * I1IiiI + iIii1I11I1II1
 if 75 - 75: oO0o
 if 50 - 50: oO0o / Oo0Ooo
 if 32 - 32: OoO0O00 % oO0o * I1ii11iIi11i + I11i / I1Ii111
 if 5 - 5: o0oOOo0O0Ooo + iII111i / OoooooooOO + Ii1I . OoOoOO00 / oO0o
 if 18 - 18: II111iiii . o0oOOo0O0Ooo
 if 75 - 75: OoooooooOO - Oo0Ooo
def lisp_close_socket ( sock , internal_name ) :
 sock . close ( )
 if ( os . path . exists ( internal_name ) ) : os . system ( "rm " + internal_name )
 return
 if 56 - 56: II111iiii - i11iIiiIii - oO0o . o0oOOo0O0Ooo
 if 4 - 4: i1IIi
 if 91 - 91: IiII . OoO0O00 * Ii1I / o0oOOo0O0Ooo
 if 41 - 41: I1IiiI . OoO0O00 / i1IIi . Oo0Ooo . oO0o
 if 44 - 44: iII111i * I11i + i11iIiiIii + i1IIi / IiII * II111iiii
 if 58 - 58: OOooOOo
 if 72 - 72: OoO0O00 + OOooOOo - Oo0Ooo % ooOoO0o . IiII
 if 95 - 95: iII111i % OOooOOo - IiII - OoOoOO00 % o0oOOo0O0Ooo * O0
def lisp_is_running ( node ) :
 return ( True if ( os . path . exists ( node ) ) else False )
 if 16 - 16: I1Ii111 / Oo0Ooo
 if 48 - 48: Oo0Ooo / oO0o + iII111i % iII111i
 if 9 - 9: I1ii11iIi11i - o0oOOo0O0Ooo . Oo0Ooo + I1ii11iIi11i . OOooOOo
 if 30 - 30: OoooooooOO - iIii1I11I1II1 / oO0o * Ii1I / Ii1I
 if 52 - 52: OoOoOO00 - OoO0O00 + I1IiiI + IiII
 if 49 - 49: oO0o / I11i - oO0o
 if 31 - 31: OoOoOO00 + I1IiiI + I1ii11iIi11i + I11i * II111iiii % oO0o
 if 90 - 90: OOooOOo * iIii1I11I1II1 / i1IIi
 if 60 - 60: OOooOOo * I1Ii111 . oO0o
def lisp_packet_ipc ( packet , source , sport ) :
 return ( ( "packet@" + str ( len ( packet ) ) + "@" + source + "@" + str ( sport ) + "@" + packet ) )
 if 47 - 47: oO0o % OOooOOo / OOooOOo % OoOoOO00 % I1Ii111 / OoOoOO00
 if 51 - 51: I1IiiI . I11i - OoOoOO00
 if 10 - 10: Oo0Ooo * OOooOOo / IiII . o0oOOo0O0Ooo
 if 97 - 97: Ii1I . Ii1I % iII111i
 if 49 - 49: Oo0Ooo % OOooOOo - OoooooooOO + IiII
 if 54 - 54: iIii1I11I1II1 - OoooooooOO / I11i / oO0o % I1IiiI + OoOoOO00
 if 26 - 26: OoO0O00 * II111iiii % OOooOOo * iII111i + iII111i
 if 25 - 25: I11i - I1ii11iIi11i
 if 100 - 100: I1Ii111 / Ii1I + OoOoOO00 . OoooooooOO
def lisp_control_packet_ipc ( packet , source , dest , dport ) :
 return ( "control-packet@" + dest + "@" + str ( dport ) + "@" + packet )
 if 83 - 83: O0
 if 35 - 35: i11iIiiIii - I11i . OoOoOO00 * II111iiii % i11iIiiIii
 if 55 - 55: o0oOOo0O0Ooo / O0 / OoooooooOO * Oo0Ooo % iII111i
 if 24 - 24: I1ii11iIi11i % OOooOOo + OoooooooOO + OoO0O00
 if 100 - 100: Oo0Ooo % OoO0O00 - OoOoOO00
 if 46 - 46: o0oOOo0O0Ooo
 if 28 - 28: i1IIi
def lisp_data_packet_ipc ( packet , source ) :
 return ( "data-packet@" + str ( len ( packet ) ) + "@" + source + "@@" + packet )
 if 81 - 81: oO0o % OoooooooOO . I1Ii111 - OoOoOO00 / I1IiiI
 if 62 - 62: I1Ii111 * I11i / I11i
 if 42 - 42: ooOoO0o * ooOoO0o / Ii1I / OOooOOo * OOooOOo
 if 92 - 92: Oo0Ooo / iII111i - OoooooooOO - o0oOOo0O0Ooo % ooOoO0o
 if 35 - 35: i1IIi % iII111i % I11i * iIii1I11I1II1 % Ii1I - Oo0Ooo
 if 94 - 94: iII111i
 if 68 - 68: OoooooooOO % OOooOOo / OoooooooOO / I1Ii111 + Ii1I - o0oOOo0O0Ooo
 if 81 - 81: I1IiiI
 if 62 - 62: Ii1I * OoOoOO00
def lisp_command_ipc ( packet , source ) :
 return ( "command@" + str ( len ( packet ) ) + "@" + source + "@@" + packet )
 if 27 - 27: Oo0Ooo + Oo0Ooo / II111iiii % I1Ii111
 if 11 - 11: Ii1I
 if 54 - 54: I1IiiI * I1Ii111 / ooOoO0o / iIii1I11I1II1 % iII111i / oO0o
 if 11 - 11: ooOoO0o + I1IiiI + Ii1I . II111iiii
 if 50 - 50: Oo0Ooo
 if 14 - 14: O0
 if 67 - 67: II111iiii / O0
 if 10 - 10: i1IIi / Oo0Ooo
 if 20 - 20: Oo0Ooo * I1Ii111 / I1ii11iIi11i . ooOoO0o
def lisp_api_ipc ( source , data ) :
 return ( "api@" + str ( len ( data ) ) + "@" + source + "@@" + data )
 if 67 - 67: o0oOOo0O0Ooo . Oo0Ooo % I11i
 if 38 - 38: OOooOOo - OoO0O00 . ooOoO0o
 if 50 - 50: o0oOOo0O0Ooo
 if 85 - 85: II111iiii . iII111i - i1IIi
 if 23 - 23: iII111i . Ii1I - OoO0O00 / I1ii11iIi11i / O0
 if 4 - 4: i1IIi % Oo0Ooo % Ii1I * ooOoO0o - I11i
 if 76 - 76: iIii1I11I1II1 / ooOoO0o % I1ii11iIi11i % OOooOOo
 if 13 - 13: IiII
 if 56 - 56: Oo0Ooo
def lisp_ipc ( packet , send_socket , node ) :
 if 55 - 55: i11iIiiIii + iIii1I11I1II1 / i1IIi / I1ii11iIi11i
 if 64 - 64: IiII . OoO0O00 * i11iIiiIii
 if 18 - 18: Ii1I % o0oOOo0O0Ooo - Oo0Ooo
 if 28 - 28: IiII
 if ( lisp_is_running ( node ) == False ) :
  lprint ( "Suppress sending IPC to {}" . format ( node ) )
  return
  if 93 - 93: Oo0Ooo % i1IIi
  if 51 - 51: oO0o % O0
 iiii1Ii1Iiii = 1500 if ( packet . find ( "control-packet" ) == - 1 ) else 9000
 if 5 - 5: I1Ii111 . O0 / o0oOOo0O0Ooo / I11i - I1ii11iIi11i
 O00oOooo0 = 0
 OOo000o = len ( packet )
 i1III11iII1 = 0
 o00iIiIIi = .001
 while ( OOo000o > 0 ) :
  i1I1I = min ( OOo000o , iiii1Ii1Iiii )
  oOi111II11IIiii = packet [ O00oOooo0 : i1I1I + O00oOooo0 ]
  if 59 - 59: I11i % Ii1I / OoOoOO00
  try :
   send_socket . sendto ( oOi111II11IIiii , node )
   lprint ( "Send IPC {}-out-of-{} byte to {} succeeded" . format ( len ( oOi111II11IIiii ) , len ( packet ) , node ) )
   if 99 - 99: Ii1I + II111iiii / i11iIiiIii - IiII / iII111i + iII111i
   i1III11iII1 = 0
   o00iIiIIi = .001
   if 55 - 55: IiII + OoooooooOO * I1ii11iIi11i . IiII * I1ii11iIi11i + IiII
  except socket . error , Oo00OOo00O :
   if ( i1III11iII1 == 12 ) :
    lprint ( "Giving up on {}, consider it down" . format ( node ) )
    break
    if 81 - 81: iIii1I11I1II1 . ooOoO0o + OoOoOO00
    if 31 - 31: I11i / OoOoOO00 + o0oOOo0O0Ooo
   lprint ( "Send IPC {}-out-of-{} byte to {} failed: {}" . format ( len ( oOi111II11IIiii ) , len ( packet ) , node , Oo00OOo00O ) )
   if 80 - 80: Oo0Ooo
   if 58 - 58: I1Ii111 + OOooOOo
   i1III11iII1 += 1
   time . sleep ( o00iIiIIi )
   if 76 - 76: II111iiii - o0oOOo0O0Ooo % OoO0O00 + iII111i
   lprint ( "Retrying after {} ms ..." . format ( o00iIiIIi * 1000 ) )
   o00iIiIIi *= 2
   continue
   if 38 - 38: I1Ii111 - I11i * i1IIi + iIii1I11I1II1
   if 41 - 41: Ii1I . OoO0O00 + I1ii11iIi11i + OoOoOO00
  O00oOooo0 += i1I1I
  OOo000o -= i1I1I
  if 76 - 76: iII111i - iIii1I11I1II1
 return
 if 23 - 23: I11i / OoO0O00 % OOooOOo
 if 9 - 9: ooOoO0o % I1ii11iIi11i . OoooooooOO + OoO0O00 % OOooOOo * OoooooooOO
 if 21 - 21: Ii1I % O0
 if 15 - 15: II111iiii * Ii1I + IiII % iII111i
 if 96 - 96: II111iiii * I1Ii111 / Oo0Ooo
 if 35 - 35: I1IiiI
 if 54 - 54: I1ii11iIi11i % o0oOOo0O0Ooo . i1IIi
def lisp_format_packet ( packet ) :
 packet = binascii . hexlify ( packet )
 O00oOooo0 = 0
 IiiI11i1i1i = ""
 OOo000o = len ( packet ) * 2
 while ( O00oOooo0 < OOo000o ) :
  IiiI11i1i1i += packet [ O00oOooo0 : O00oOooo0 + 8 ] + " "
  O00oOooo0 += 8
  OOo000o -= 4
  if 72 - 72: Ii1I
 return ( IiiI11i1i1i )
 if 87 - 87: iII111i - I1IiiI
 if 54 - 54: iIii1I11I1II1 + oO0o * o0oOOo0O0Ooo % OoooooooOO . Oo0Ooo
 if 32 - 32: iII111i
 if 33 - 33: ooOoO0o + Oo0Ooo * OoOoOO00 % ooOoO0o * oO0o - OoO0O00
 if 40 - 40: I11i . OoooooooOO * O0 / I1Ii111 + O0
 if 97 - 97: ooOoO0o - ooOoO0o * OOooOOo % OoOoOO00 - OoOoOO00 - I1Ii111
 if 52 - 52: O0 % iII111i
def lisp_send ( lisp_sockets , dest , port , packet ) :
 Oo0OOOoOo0O = lisp_sockets [ 0 ] if dest . is_ipv4 ( ) else lisp_sockets [ 1 ]
 if 51 - 51: O0 . o0oOOo0O0Ooo . I1IiiI
 if 69 - 69: i11iIiiIii
 if 69 - 69: i11iIiiIii - OoOoOO00 % I1Ii111 / II111iiii . OoOoOO00
 if 14 - 14: IiII . OoO0O00 / I1IiiI * Ii1I % OoO0O00 + OOooOOo
 if 45 - 45: i1IIi % I11i
 if 6 - 6: II111iiii % I1Ii111 - i11iIiiIii / ooOoO0o
 if 51 - 51: OOooOOo * o0oOOo0O0Ooo / oO0o
 if 43 - 43: I1IiiI * OoooooooOO * OoOoOO00 . OOooOOo / I1IiiI
 if 71 - 71: O0 + iIii1I11I1II1 . oO0o + iII111i
 if 49 - 49: oO0o
 if 36 - 36: iII111i . I11i . i1IIi + I11i
 if 97 - 97: II111iiii . OoooooooOO - OoOoOO00
 i11i11II11i = dest . print_address_no_iid ( )
 if ( i11i11II11i . find ( "::ffff:" ) != - 1 and i11i11II11i . count ( "." ) == 3 ) :
  if ( lisp_i_am_rtr ) : Oo0OOOoOo0O = lisp_sockets [ 0 ]
  if ( Oo0OOOoOo0O == None ) :
   Oo0OOOoOo0O = lisp_sockets [ 0 ]
   i11i11II11i = i11i11II11i . split ( "::ffff:" ) [ - 1 ]
   if 35 - 35: I1Ii111
   if 35 - 35: Oo0Ooo - iIii1I11I1II1 / i1IIi + OoO0O00 - OoooooooOO / i11iIiiIii
   if 79 - 79: I1IiiI * ooOoO0o * ooOoO0o
 lprint ( "{} {} bytes {} {}, packet: {}" . format ( bold ( "Send" , False ) ,
 len ( packet ) , bold ( "to " + i11i11II11i , False ) , port ,
 lisp_format_packet ( packet ) ) )
 if 92 - 92: iII111i % I1ii11iIi11i
 if 16 - 16: oO0o
 if 52 - 52: OoooooooOO % ooOoO0o - I1Ii111 * I11i
 if 24 - 24: Ii1I + IiII + OoooooooOO / oO0o / I1IiiI + IiII
 oOOOO0o00O0OO = ( LISP_RLOC_PROBE_TTL == 255 )
 if ( oOOOO0o00O0OO ) :
  oOOoO00O0Ooo0 = struct . unpack ( "B" , packet [ 0 ] ) [ 0 ]
  oOOOO0o00O0OO = ( oOOoO00O0Ooo0 in [ 0x12 , 0x28 ] )
  if ( oOOOO0o00O0OO ) : lisp_set_ttl ( Oo0OOOoOo0O , LISP_RLOC_PROBE_TTL )
  if 49 - 49: IiII . OOooOOo + ooOoO0o
  if 84 - 84: II111iiii
 try : Oo0OOOoOo0O . sendto ( packet , ( i11i11II11i , port ) )
 except socket . error , Oo00OOo00O :
  lprint ( "socket.sendto() failed: {}" . format ( Oo00OOo00O ) )
  if 16 - 16: OoO0O00
  if 60 - 60: Ii1I
  if 72 - 72: ooOoO0o % I1Ii111
  if 68 - 68: i1IIi
  if 95 - 95: OoOoOO00
 if ( oOOOO0o00O0OO ) : lisp_set_ttl ( Oo0OOOoOo0O , 64 )
 return
 if 82 - 82: II111iiii * I1IiiI * I1ii11iIi11i
 if 79 - 79: o0oOOo0O0Ooo - oO0o . ooOoO0o / ooOoO0o - iII111i / OoooooooOO
 if 58 - 58: ooOoO0o * I1IiiI - OoO0O00 + OOooOOo
 if 79 - 79: Oo0Ooo . i11iIiiIii * OoO0O00 / I11i * OoOoOO00
 if 78 - 78: I11i . I1ii11iIi11i . I1ii11iIi11i
 if 71 - 71: iII111i + IiII + I1IiiI - OoOoOO00
 if 49 - 49: I1IiiI % O0 - OoooooooOO * OoO0O00 / iIii1I11I1II1 + I11i
 if 7 - 7: iII111i * I1ii11iIi11i / oO0o
def lisp_receive_segments ( lisp_socket , packet , source , total_length ) :
 if 31 - 31: I1ii11iIi11i - II111iiii
 if 86 - 86: IiII % OOooOOo % OoOoOO00 / I1IiiI % OoooooooOO
 if 83 - 83: i1IIi . OoOoOO00 . i1IIi / OOooOOo * O0
 if 99 - 99: OoooooooOO . OoOoOO00 / II111iiii
 if 64 - 64: iII111i / i1IIi . I1IiiI + O0
 i1I1I = total_length - len ( packet )
 if ( i1I1I == 0 ) : return ( [ True , packet ] )
 if 5 - 5: O0 . i11iIiiIii
 lprint ( "Received {}-out-of-{} byte segment from {}" . format ( len ( packet ) ,
 total_length , source ) )
 if 71 - 71: o0oOOo0O0Ooo + iII111i + ooOoO0o
 if 27 - 27: OoooooooOO . iII111i * I1Ii111 % O0 + OoooooooOO - iII111i
 if 86 - 86: i1IIi
 if 81 - 81: OoOoOO00
 if 52 - 52: iII111i * IiII % I1IiiI * I11i
 OOo000o = i1I1I
 while ( OOo000o > 0 ) :
  try : oOi111II11IIiii = lisp_socket . recvfrom ( 9000 )
  except : return ( [ False , None ] )
  if 73 - 73: I1Ii111 * ooOoO0o
  oOi111II11IIiii = oOi111II11IIiii [ 0 ]
  if 62 - 62: OOooOOo . I1IiiI * iIii1I11I1II1 + OoO0O00 * ooOoO0o / oO0o
  if 14 - 14: iII111i / OoO0O00
  if 75 - 75: IiII
  if 68 - 68: IiII - i1IIi % IiII . OoO0O00 . i11iIiiIii . OoooooooOO
  if 32 - 32: iII111i + OoO0O00 % IiII + I1IiiI
  if ( oOi111II11IIiii . find ( "packet@" ) == 0 ) :
   O0O0Ooo = oOi111II11IIiii . split ( "@" )
   lprint ( "Received new message ({}-out-of-{}) while receiving " + "fragments, old message discarded" , len ( oOi111II11IIiii ) ,
   # I11i % iII111i
 O0O0Ooo [ 1 ] if len ( O0O0Ooo ) > 2 else "?" )
   return ( [ False , oOi111II11IIiii ] )
   if 74 - 74: o0oOOo0O0Ooo + O0 - i11iIiiIii - Ii1I
   if 90 - 90: i1IIi + OoO0O00 - I11i - I11i
  OOo000o -= len ( oOi111II11IIiii )
  packet += oOi111II11IIiii
  if 9 - 9: OoO0O00 + ooOoO0o - OOooOOo - ooOoO0o + Ii1I
  lprint ( "Received {}-out-of-{} byte segment from {}" . format ( len ( oOi111II11IIiii ) , total_length , source ) )
  if 54 - 54: OoOoOO00
  if 53 - 53: I1Ii111
 return ( [ True , packet ] )
 if 72 - 72: i11iIiiIii
 if 64 - 64: I1Ii111 % OoooooooOO / i1IIi / OoO0O00
 if 2 - 2: I11i % o0oOOo0O0Ooo . OoO0O00 . OoO0O00
 if 89 - 89: ooOoO0o - oO0o + II111iiii + OoO0O00 - IiII
 if 27 - 27: I1Ii111 - o0oOOo0O0Ooo + OoO0O00
 if 38 - 38: OoOoOO00 + OoO0O00 . i11iIiiIii + Ii1I % i1IIi % I1IiiI
 if 93 - 93: i11iIiiIii
 if 63 - 63: iIii1I11I1II1 - iIii1I11I1II1 % o0oOOo0O0Ooo
def lisp_bit_stuff ( payload ) :
 lprint ( "Bit-stuffing, found {} segments" . format ( len ( payload ) ) )
 I1i1iI = ""
 for oOi111II11IIiii in payload : I1i1iI += oOi111II11IIiii + "\x40"
 return ( I1i1iI [ : - 1 ] )
 if 97 - 97: i1IIi % I11i % OoOoOO00
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
 if 29 - 29: OoOoOO00 % ooOoO0o * OoooooooOO
 if 8 - 8: i11iIiiIii - I1Ii111 / IiII
 if 17 - 17: i11iIiiIii * OoO0O00 . o0oOOo0O0Ooo . OoooooooOO . OoOoOO00 - I1ii11iIi11i
 if 78 - 78: I1ii11iIi11i - OoooooooOO + O0
 if 15 - 15: I1ii11iIi11i / IiII % I1IiiI
 if 16 - 16: Ii1I
 if 26 - 26: o0oOOo0O0Ooo / I11i + OoOoOO00 / OoOoOO00
 if 31 - 31: I1Ii111
 if 84 - 84: i11iIiiIii * OOooOOo . iII111i - Ii1I * i1IIi - I1ii11iIi11i
def lisp_receive ( lisp_socket , internal ) :
 while ( True ) :
  if 1 - 1: II111iiii
  if 94 - 94: I1ii11iIi11i * iII111i % iII111i % I11i - iII111i
  if 38 - 38: IiII - OoO0O00 % Ii1I - II111iiii
  if 97 - 97: O0 . Ii1I
  try : o0Oo0Oo0oOOO = lisp_socket . recvfrom ( 9000 )
  except : return ( [ "" , "" , "" , "" ] )
  if 1 - 1: Oo0Ooo . i11iIiiIii
  if 75 - 75: I1Ii111 % II111iiii + OoOoOO00 % i11iIiiIii / iIii1I11I1II1
  if 81 - 81: II111iiii * I1Ii111 + OoooooooOO
  if 33 - 33: Ii1I - II111iiii + IiII / II111iiii * I1ii11iIi11i - I1Ii111
  if 53 - 53: I1Ii111
  if 25 - 25: i1IIi
  if ( internal == False ) :
   I1i1iI = o0Oo0Oo0oOOO [ 0 ]
   oO000O = lisp_convert_6to4 ( o0Oo0Oo0oOOO [ 1 ] [ 0 ] )
   OoO0o = o0Oo0Oo0oOOO [ 1 ] [ 1 ]
   if 84 - 84: OoooooooOO
   if ( OoO0o == LISP_DATA_PORT ) :
    ooOo = lisp_data_plane_logging
    I1ii = lisp_format_packet ( I1i1iI [ 0 : 60 ] ) + " ..."
   else :
    ooOo = True
    I1ii = lisp_format_packet ( I1i1iI )
    if 54 - 54: OoO0O00 / I1IiiI . Oo0Ooo
    if 39 - 39: OoO0O00 . ooOoO0o
   if ( ooOo ) :
    lprint ( "{} {} bytes {} {}, packet: {}" . format ( bold ( "Receive" ,
 False ) , len ( I1i1iI ) , bold ( "from " + oO000O , False ) , OoO0o ,
 I1ii ) )
    if 41 - 41: Oo0Ooo * I1ii11iIi11i - II111iiii - II111iiii
   return ( [ "packet" , oO000O , OoO0o , I1i1iI ] )
   if 7 - 7: oO0o
   if 41 - 41: ooOoO0o
   if 93 - 93: Ii1I + I1Ii111 + Ii1I
   if 23 - 23: I1IiiI - i1IIi / ooOoO0o
   if 4 - 4: IiII . I1ii11iIi11i + iII111i % ooOoO0o
   if 28 - 28: I1Ii111
  i1IIIiiIiII1I = False
  oooOoOOo0OOoO = o0Oo0Oo0oOOO [ 0 ]
  oO000O000o0Oo = False
  if 63 - 63: Oo0Ooo / I11i . iII111i + ooOoO0o / I1ii11iIi11i / I1IiiI
  while ( i1IIIiiIiII1I == False ) :
   oooOoOOo0OOoO = oooOoOOo0OOoO . split ( "@" )
   if 43 - 43: OoOoOO00 / I1Ii111 % I11i / I1IiiI - IiII - ooOoO0o
   if ( len ( oooOoOOo0OOoO ) < 4 ) :
    lprint ( "Possible fragment (length {}), from old message, " + "discarding" , len ( oooOoOOo0OOoO [ 0 ] ) )
    if 25 - 25: OOooOOo * OoOoOO00 + I11i . ooOoO0o
    oO000O000o0Oo = True
    break
    if 96 - 96: iIii1I11I1II1 / Ii1I
    if 92 - 92: OoO0O00 * I1ii11iIi11i + iIii1I11I1II1
   Oo0ooo0 = oooOoOOo0OOoO [ 0 ]
   try :
    OOoooO0Ooo0OO = int ( oooOoOOo0OOoO [ 1 ] )
   except :
    IiII1iII1 = bold ( "Internal packet reassembly error" , False )
    lprint ( "{}: {}" . format ( IiII1iII1 , o0Oo0Oo0oOOO ) )
    oO000O000o0Oo = True
    break
    if 59 - 59: I1IiiI
   oO000O = oooOoOOo0OOoO [ 2 ]
   OoO0o = oooOoOOo0OOoO [ 3 ]
   if 61 - 61: i11iIiiIii . Oo0Ooo * i11iIiiIii . ooOoO0o . OOooOOo % I11i
   if 9 - 9: O0 . I1ii11iIi11i
   if 20 - 20: Ii1I / oO0o
   if 52 - 52: O0
   if 24 - 24: I11i
   if 52 - 52: IiII / Oo0Ooo - O0 - OOooOOo
   if 96 - 96: IiII % OoooooooOO + O0 * II111iiii / OOooOOo . I1Ii111
   if 47 - 47: OoO0O00 - Oo0Ooo * OoO0O00 / oO0o
   if ( len ( oooOoOOo0OOoO ) > 5 ) :
    I1i1iI = lisp_bit_stuff ( oooOoOOo0OOoO [ 4 : : ] )
   else :
    I1i1iI = oooOoOOo0OOoO [ 4 ]
    if 13 - 13: ooOoO0o
    if 55 - 55: i1IIi . I11i . II111iiii + O0 + ooOoO0o - i1IIi
    if 3 - 3: iIii1I11I1II1 / oO0o
    if 61 - 61: I1Ii111 / O0 - iII111i
    if 44 - 44: i1IIi
    if 23 - 23: I1ii11iIi11i . OoooooooOO / Ii1I + o0oOOo0O0Ooo
   i1IIIiiIiII1I , I1i1iI = lisp_receive_segments ( lisp_socket , I1i1iI ,
 oO000O , OOoooO0Ooo0OO )
   if ( I1i1iI == None ) : return ( [ "" , "" , "" , "" ] )
   if 89 - 89: OoOoOO00 + Oo0Ooo . OoOoOO00 - II111iiii
   if 85 - 85: OoooooooOO * OoooooooOO / Ii1I - II111iiii
   if 69 - 69: iII111i * I11i
   if 43 - 43: o0oOOo0O0Ooo - IiII * Ii1I . i11iIiiIii / II111iiii
   if 61 - 61: OoOoOO00 / I1IiiI . I1ii11iIi11i % OOooOOo
   if ( i1IIIiiIiII1I == False ) :
    oooOoOOo0OOoO = I1i1iI
    continue
    if 70 - 70: OOooOOo * OoOoOO00 / oO0o + Oo0Ooo / O0
    if 16 - 16: Oo0Ooo / OoooooooOO / IiII + Oo0Ooo * i11iIiiIii
   if ( OoO0o == "" ) : OoO0o = "no-port"
   if ( Oo0ooo0 == "command" and lisp_i_am_core == False ) :
    I1Iiiiiii = I1i1iI . find ( " {" )
    iIiII = I1i1iI if I1Iiiiiii == - 1 else I1i1iI [ : I1Iiiiiii ]
    iIiII = ": '" + iIiII + "'"
   else :
    iIiII = ""
    if 62 - 62: Ii1I + ooOoO0o % OoooooooOO % iII111i
    if 98 - 98: I1IiiI / oO0o - I11i . O0 / OOooOOo . ooOoO0o
   lprint ( "{} {} bytes {} {}, {}{}" . format ( bold ( "Receive" , False ) ,
 len ( I1i1iI ) , bold ( "from " + oO000O , False ) , OoO0o , Oo0ooo0 ,
 iIiII if ( Oo0ooo0 in [ "command" , "api" ] ) else ": ... " if ( Oo0ooo0 == "data-packet" ) else ": " + lisp_format_packet ( I1i1iI ) ) )
   if 97 - 97: o0oOOo0O0Ooo / Oo0Ooo . ooOoO0o
   if 47 - 47: Oo0Ooo . I11i - OoooooooOO
   if 21 - 21: Oo0Ooo - i11iIiiIii * OOooOOo * OoooooooOO - II111iiii
   if 64 - 64: OoOoOO00
   if 97 - 97: iIii1I11I1II1 / OOooOOo * i1IIi - OoO0O00 / ooOoO0o % Ii1I
  if ( oO000O000o0Oo ) : continue
  return ( [ Oo0ooo0 , oO000O , OoO0o , I1i1iI ] )
  if 30 - 30: OoOoOO00 / oO0o . iII111i
  if 56 - 56: OoOoOO00
  if 83 - 83: OOooOOo
  if 17 - 17: IiII + I1IiiI - I11i . I1IiiI
  if 34 - 34: ooOoO0o . i11iIiiIii * I1IiiI . II111iiii - iIii1I11I1II1
  if 43 - 43: i11iIiiIii % OoO0O00
  if 100 - 100: i1IIi
  if 4 - 4: i11iIiiIii - OOooOOo * IiII % OoooooooOO - OoOoOO00
def lisp_parse_packet ( lisp_sockets , packet , source , udp_sport , ttl = - 1 ) :
 O0o0oO00oO0OO = False
 if 56 - 56: i1IIi / II111iiii * II111iiii / Oo0Ooo * OoO0O00
 oo = lisp_control_header ( )
 if ( oo . decode ( packet ) == None ) :
  lprint ( "Could not decode control header" )
  return ( O0o0oO00oO0OO )
  if 27 - 27: o0oOOo0O0Ooo . I11i / I1ii11iIi11i
  if 10 - 10: OoO0O00 . I1Ii111 . OoooooooOO % iIii1I11I1II1 . O0
  if 36 - 36: oO0o . iII111i
  if 62 - 62: I11i + iIii1I11I1II1 % I11i * OOooOOo + iIii1I11I1II1 % Ii1I
  if 56 - 56: o0oOOo0O0Ooo
 OOo0000o0 = source
 if ( source . find ( "lisp" ) == - 1 ) :
  I11iiIi1i1 = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  I11iiIi1i1 . string_to_afi ( source )
  I11iiIi1i1 . store_address ( source )
  source = I11iiIi1i1
  if 18 - 18: OoooooooOO * Ii1I + O0
  if 92 - 92: I1IiiI % iII111i % I11i + OoooooooOO - i11iIiiIii
 if ( oo . type == LISP_MAP_REQUEST ) :
  lisp_process_map_request ( lisp_sockets , packet , None , 0 , source ,
 udp_sport , False , ttl )
  if 9 - 9: i11iIiiIii - II111iiii / ooOoO0o
 elif ( oo . type == LISP_MAP_REPLY ) :
  lisp_process_map_reply ( lisp_sockets , packet , source , ttl )
  if 81 - 81: i11iIiiIii % OoOoOO00 % OoO0O00 * Ii1I
 elif ( oo . type == LISP_MAP_REGISTER ) :
  lisp_process_map_register ( lisp_sockets , packet , source , udp_sport )
  if 85 - 85: OoooooooOO * ooOoO0o
 elif ( oo . type == LISP_MAP_NOTIFY ) :
  if ( OOo0000o0 == "lisp-etr" ) :
   lisp_process_multicast_map_notify ( packet , source )
  else :
   if ( lisp_is_running ( "lisp-rtr" ) ) :
    lisp_process_multicast_map_notify ( packet , source )
    if 23 - 23: OOooOOo / I11i / OoooooooOO - Ii1I / OoO0O00 - OoO0O00
   lisp_process_map_notify ( lisp_sockets , packet , source )
   if 60 - 60: OOooOOo . ooOoO0o % i1IIi % Ii1I % ooOoO0o + OoO0O00
   if 26 - 26: O0 % o0oOOo0O0Ooo + iII111i * I1ii11iIi11i * I1Ii111
 elif ( oo . type == LISP_MAP_NOTIFY_ACK ) :
  lisp_process_map_notify_ack ( packet , source )
  if 4 - 4: OOooOOo * OoooooooOO * i1IIi % I1ii11iIi11i % Oo0Ooo
 elif ( oo . type == LISP_MAP_REFERRAL ) :
  lisp_process_map_referral ( lisp_sockets , packet , source )
  if 1 - 1: OoO0O00 / iIii1I11I1II1 % I1ii11iIi11i - o0oOOo0O0Ooo
 elif ( oo . type == LISP_NAT_INFO and oo . is_info_reply ( ) ) :
  O0oo0oo0 , i11ii1i1i , O0o0oO00oO0OO = lisp_process_info_reply ( source , packet , True )
  if 62 - 62: I1Ii111 % II111iiii
 elif ( oo . type == LISP_NAT_INFO and oo . is_info_reply ( ) == False ) :
  oO00o = source . print_address_no_iid ( )
  lisp_process_info_request ( lisp_sockets , packet , oO00o , udp_sport ,
 None )
  if 91 - 91: I11i % Ii1I - IiII + iIii1I11I1II1 * iIii1I11I1II1
 elif ( oo . type == LISP_ECM ) :
  lisp_process_ecm ( lisp_sockets , packet , source , udp_sport )
  if 91 - 91: i11iIiiIii + Ii1I
 else :
  lprint ( "Invalid LISP control packet type {}" . format ( oo . type ) )
  if 85 - 85: I11i % IiII
 return ( O0o0oO00oO0OO )
 if 68 - 68: Oo0Ooo . I1Ii111 - o0oOOo0O0Ooo * iIii1I11I1II1 - II111iiii % i1IIi
 if 58 - 58: I11i / i11iIiiIii * i11iIiiIii
 if 24 - 24: ooOoO0o - I1Ii111 * II111iiii - II111iiii
 if 47 - 47: IiII - iIii1I11I1II1 / OoOoOO00 * iII111i - iIii1I11I1II1 % oO0o
 if 93 - 93: Ii1I / iII111i
 if 100 - 100: Oo0Ooo
 if 94 - 94: I1ii11iIi11i / i1IIi * I1IiiI - I11i - I1ii11iIi11i
def lisp_process_rloc_probe_request ( lisp_sockets , map_request , source , port ,
 ttl ) :
 if 6 - 6: I1ii11iIi11i % o0oOOo0O0Ooo + o0oOOo0O0Ooo / OOooOOo / I1IiiI
 Iiiii1III1iIi = bold ( "RLOC-probe" , False )
 if 67 - 67: OoOoOO00 . iII111i / OOooOOo * ooOoO0o + i1IIi
 if ( lisp_i_am_etr ) :
  lprint ( "Received {} Map-Request, send RLOC-probe Map-Reply" . format ( Iiiii1III1iIi ) )
  lisp_etr_process_map_request ( lisp_sockets , map_request , source , port ,
 ttl )
  return
  if 100 - 100: OOooOOo . ooOoO0o + I1Ii111 . oO0o
  if 20 - 20: i11iIiiIii - i1IIi - iIii1I11I1II1 - OoooooooOO
 if ( lisp_i_am_rtr ) :
  lprint ( "Received {} Map-Request, send RLOC-probe Map-Reply" . format ( Iiiii1III1iIi ) )
  lisp_rtr_process_map_request ( lisp_sockets , map_request , source , port ,
 ttl )
  return
  if 72 - 72: I1Ii111 . OoO0O00
  if 59 - 59: I1IiiI * I11i % i1IIi
 lprint ( "Ignoring received {} Map-Request, not an ETR or RTR" . format ( Iiiii1III1iIi ) )
 return
 if 77 - 77: OOooOOo * OoooooooOO + I1IiiI + I1IiiI % oO0o . OoooooooOO
 if 60 - 60: iIii1I11I1II1
 if 13 - 13: II111iiii + Ii1I
 if 33 - 33: i1IIi
 if 36 - 36: ooOoO0o % ooOoO0o . i11iIiiIii
def lisp_process_smr ( map_request ) :
 lprint ( "Received SMR-based Map-Request" )
 return
 if 42 - 42: OoO0O00 . I1Ii111 / Ii1I
 if 57 - 57: iIii1I11I1II1 % I1ii11iIi11i . OOooOOo / oO0o . OoOoOO00
 if 74 - 74: I1IiiI * OoO0O00 + OoooooooOO * ooOoO0o . oO0o
 if 66 - 66: II111iiii + OOooOOo + i11iIiiIii / II111iiii
 if 37 - 37: I1IiiI + OoO0O00 . OoO0O00 % OoOoOO00 + o0oOOo0O0Ooo
def lisp_process_smr_invoked_request ( map_request ) :
 lprint ( "Received SMR-invoked Map-Request" )
 return
 if 81 - 81: i1IIi % iIii1I11I1II1
 if 41 - 41: oO0o - iII111i / o0oOOo0O0Ooo . iII111i % Oo0Ooo + OOooOOo
 if 82 - 82: ooOoO0o
 if 89 - 89: OOooOOo / I1ii11iIi11i . I1IiiI + i11iIiiIii
 if 11 - 11: oO0o . i11iIiiIii * ooOoO0o % OoooooooOO % O0
 if 59 - 59: i11iIiiIii / OoO0O00
 if 48 - 48: iIii1I11I1II1
def lisp_build_map_reply ( eid , group , rloc_set , nonce , action , ttl , rloc_probe ,
 keys , enc , auth , mr_ttl = - 1 ) :
 i111II11i = lisp_map_reply ( )
 i111II11i . rloc_probe = rloc_probe
 i111II11i . echo_nonce_capable = enc
 i111II11i . hop_count = 0 if ( mr_ttl == - 1 ) else mr_ttl
 i111II11i . record_count = 1
 i111II11i . nonce = nonce
 I1i1iI = i111II11i . encode ( )
 i111II11i . print_map_reply ( )
 if 92 - 92: iIii1I11I1II1 - i1IIi * OoooooooOO + i11iIiiIii * O0
 OOOoOooO = lisp_eid_record ( )
 OOOoOooO . rloc_count = len ( rloc_set )
 OOOoOooO . authoritative = auth
 OOOoOooO . record_ttl = ttl
 OOOoOooO . action = action
 OOOoOooO . eid = eid
 OOOoOooO . group = group
 if 50 - 50: Ii1I * I1Ii111 * OoooooooOO . OoooooooOO
 I1i1iI += OOOoOooO . encode ( )
 OOOoOooO . print_record ( "  " , False )
 if 67 - 67: i11iIiiIii % ooOoO0o . I1ii11iIi11i + II111iiii . OoO0O00
 I1iI1 = lisp_get_all_addresses ( ) + lisp_get_all_translated_rlocs ( )
 if 42 - 42: OoO0O00 . II111iiii % oO0o . ooOoO0o * OoooooooOO
 for iiI1iI1 in rloc_set :
  oO0oO = lisp_rloc_record ( )
  oO00o = iiI1iI1 . rloc . print_address_no_iid ( )
  if ( oO00o in I1iI1 ) :
   oO0oO . local_bit = True
   oO0oO . probe_bit = rloc_probe
   oO0oO . keys = keys
   if ( iiI1iI1 . priority == 254 and lisp_i_am_rtr ) :
    oO0oO . rloc_name = "RTR"
    if 15 - 15: OoOoOO00 - o0oOOo0O0Ooo * o0oOOo0O0Ooo . Ii1I
    if 14 - 14: OoO0O00 . I11i % II111iiii % i11iIiiIii + OoooooooOO
  oO0oO . store_rloc_entry ( iiI1iI1 )
  oO0oO . reach_bit = True
  oO0oO . print_record ( "    " )
  I1i1iI += oO0oO . encode ( )
  if 50 - 50: i11iIiiIii * I11i + i11iIiiIii - i1IIi
 return ( I1i1iI )
 if 69 - 69: I1IiiI + IiII + oO0o * I1ii11iIi11i . iIii1I11I1II1 / OoooooooOO
 if 77 - 77: Oo0Ooo - ooOoO0o
 if 68 - 68: Ii1I * O0
 if 61 - 61: II111iiii - OoO0O00 . iIii1I11I1II1 * o0oOOo0O0Ooo . OoO0O00 % IiII
 if 11 - 11: oO0o + I11i
 if 6 - 6: i1IIi . o0oOOo0O0Ooo + OoO0O00 + OOooOOo + oO0o
 if 30 - 30: O0
def lisp_build_map_referral ( eid , group , ddt_entry , action , ttl , nonce ) :
 oOo0ooOO0ooOo = lisp_map_referral ( )
 oOo0ooOO0ooOo . record_count = 1
 oOo0ooOO0ooOo . nonce = nonce
 I1i1iI = oOo0ooOO0ooOo . encode ( )
 oOo0ooOO0ooOo . print_map_referral ( )
 if 48 - 48: i1IIi * OoooooooOO % ooOoO0o . I1Ii111 / OoOoOO00
 OOOoOooO = lisp_eid_record ( )
 if 91 - 91: oO0o + OOooOOo % I1IiiI * I1ii11iIi11i / I1IiiI
 Oo0OO0O00o = 0
 if ( ddt_entry == None ) :
  OOOoOooO . eid = eid
  OOOoOooO . group = group
 else :
  Oo0OO0O00o = len ( ddt_entry . delegation_set )
  OOOoOooO . eid = ddt_entry . eid
  OOOoOooO . group = ddt_entry . group
  ddt_entry . map_referrals_sent += 1
  if 29 - 29: Ii1I . II111iiii / I1Ii111
 OOOoOooO . rloc_count = Oo0OO0O00o
 OOOoOooO . authoritative = True
 if 79 - 79: IiII . OoOoOO00 / oO0o % OoO0O00 / Ii1I + I11i
 if 78 - 78: o0oOOo0O0Ooo + I1Ii111 % i11iIiiIii % I1IiiI - Ii1I
 if 81 - 81: i11iIiiIii - II111iiii + I11i
 if 52 - 52: II111iiii
 if 62 - 62: iII111i / OoO0O00 + i11iIiiIii / Oo0Ooo
 IiIi1iiII = False
 if ( action == LISP_DDT_ACTION_NULL ) :
  if ( Oo0OO0O00o == 0 ) :
   action = LISP_DDT_ACTION_NODE_REFERRAL
  else :
   ii1111IIiIi = ddt_entry . delegation_set [ 0 ]
   if ( ii1111IIiIi . is_ddt_child ( ) ) :
    action = LISP_DDT_ACTION_NODE_REFERRAL
    if 26 - 26: I1ii11iIi11i - OoO0O00
   if ( ii1111IIiIi . is_ms_child ( ) ) :
    action = LISP_DDT_ACTION_MS_REFERRAL
    if 19 - 19: iIii1I11I1II1 / I1ii11iIi11i + O0
    if 12 - 12: I11i . OOooOOo + o0oOOo0O0Ooo . OoO0O00 + o0oOOo0O0Ooo
    if 56 - 56: i1IIi / i1IIi . OoO0O00 % i1IIi - OoOoOO00 % OOooOOo
    if 66 - 66: i11iIiiIii * IiII % IiII . I1IiiI / ooOoO0o
    if 50 - 50: IiII . iII111i / o0oOOo0O0Ooo % OoOoOO00 * IiII % I11i
    if 15 - 15: Ii1I
    if 29 - 29: I11i / I1IiiI / OoooooooOO . OoOoOO00 / I11i . I1Ii111
 if ( action == LISP_DDT_ACTION_NOT_AUTH ) : IiIi1iiII = True
 if ( action in ( LISP_DDT_ACTION_MS_REFERRAL , LISP_DDT_ACTION_MS_ACK ) ) :
  IiIi1iiII = ( lisp_i_am_ms and ii1111IIiIi . is_ms_peer ( ) == False )
  if 69 - 69: O0 * OoOoOO00 + o0oOOo0O0Ooo + I1IiiI % iII111i . OoooooooOO
  if 45 - 45: I1Ii111 + oO0o - o0oOOo0O0Ooo - OoOoOO00 + I1IiiI / II111iiii
 OOOoOooO . action = action
 OOOoOooO . ddt_incomplete = IiIi1iiII
 OOOoOooO . record_ttl = ttl
 if 46 - 46: II111iiii . iIii1I11I1II1
 I1i1iI += OOOoOooO . encode ( )
 OOOoOooO . print_record ( "  " , True )
 if 62 - 62: I1ii11iIi11i % i1IIi % I1Ii111 * ooOoO0o % OOooOOo + I1IiiI
 if ( Oo0OO0O00o == 0 ) : return ( I1i1iI )
 if 100 - 100: II111iiii - o0oOOo0O0Ooo * OoooooooOO . ooOoO0o / II111iiii / oO0o
 for ii1111IIiIi in ddt_entry . delegation_set :
  oO0oO = lisp_rloc_record ( )
  oO0oO . rloc = ii1111IIiIi . delegate_address
  oO0oO . priority = ii1111IIiIi . priority
  oO0oO . weight = ii1111IIiIi . weight
  oO0oO . mpriority = 255
  oO0oO . mweight = 0
  oO0oO . reach_bit = True
  I1i1iI += oO0oO . encode ( )
  oO0oO . print_record ( "    " )
  if 43 - 43: iIii1I11I1II1 + ooOoO0o * iII111i + iIii1I11I1II1 . I1Ii111
 return ( I1i1iI )
 if 87 - 87: I1Ii111
 if 47 - 47: II111iiii + I1IiiI . Oo0Ooo / iIii1I11I1II1
 if 14 - 14: i1IIi / OoO0O00 / iII111i % I1Ii111
 if 72 - 72: OoO0O00 . II111iiii - IiII + IiII + iIii1I11I1II1 % oO0o
 if 21 - 21: iII111i + OoOoOO00 - i11iIiiIii % O0 + OOooOOo
 if 30 - 30: o0oOOo0O0Ooo - Oo0Ooo + iII111i / O0
 if 94 - 94: IiII
def lisp_etr_process_map_request ( lisp_sockets , map_request , source , sport ,
 ttl ) :
 if 69 - 69: I1Ii111 . I1Ii111
 if ( map_request . target_group . is_null ( ) ) :
  Oo00OO0 = lisp_db_for_lookups . lookup_cache ( map_request . target_eid , False )
 else :
  Oo00OO0 = lisp_db_for_lookups . lookup_cache ( map_request . target_group , False )
  if ( Oo00OO0 ) : Oo00OO0 = Oo00OO0 . lookup_source_cache ( map_request . target_eid , False )
  if 61 - 61: o0oOOo0O0Ooo / OOooOOo . II111iiii - I1IiiI * i11iIiiIii
 I1I1iII1i = map_request . print_prefix ( )
 if 8 - 8: iII111i % o0oOOo0O0Ooo
 if ( Oo00OO0 == None ) :
  lprint ( "Database-mapping entry not found for requested EID {}" . format ( green ( I1I1iII1i , False ) ) )
  if 87 - 87: Ii1I % I11i / I1Ii111
  return
  if 21 - 21: OoO0O00 + Ii1I / I1Ii111
  if 75 - 75: I1Ii111 . Ii1I % iIii1I11I1II1 / OoOoOO00
 ii1IOo0OOoo = Oo00OO0 . print_eid_tuple ( )
 if 64 - 64: Ii1I * I11i * OoOoOO00
 lprint ( "Found database-mapping EID-prefix {} for requested EID {}" . format ( green ( ii1IOo0OOoo , False ) , green ( I1I1iII1i , False ) ) )
 if 35 - 35: OOooOOo / IiII * OoOoOO00
 if 65 - 65: I1IiiI . Oo0Ooo + i1IIi - Ii1I * i1IIi
 if 64 - 64: I1IiiI / OoO0O00 * I1IiiI * II111iiii . Ii1I
 if 98 - 98: I1Ii111 + o0oOOo0O0Ooo
 if 73 - 73: I1ii11iIi11i / I1Ii111 + i11iIiiIii + OoO0O00 . ooOoO0o
 OOO0OO = map_request . itr_rlocs [ 0 ]
 if ( OOO0OO . is_private_address ( ) and lisp_nat_traversal ) :
  OOO0OO = source
  if 24 - 24: IiII % i11iIiiIii + ooOoO0o
  if 28 - 28: I11i * I11i + I11i / O0 - OOooOOo
 iII = map_request . nonce
 II1iII = lisp_nonce_echoing
 IiI1ii11I1 = map_request . keys
 if 17 - 17: I1IiiI / OOooOOo * OoooooooOO / OoOoOO00 / i11iIiiIii
 Oo00OO0 . map_replies_sent += 1
 if 56 - 56: iIii1I11I1II1 . I11i
 I1i1iI = lisp_build_map_reply ( Oo00OO0 . eid , Oo00OO0 . group , Oo00OO0 . rloc_set , iII ,
 LISP_NO_ACTION , 1440 , map_request . rloc_probe , IiI1ii11I1 , II1iII , True , ttl )
 if 23 - 23: i11iIiiIii - I11i . O0 - iIii1I11I1II1 % Oo0Ooo / o0oOOo0O0Ooo
 if 6 - 6: ooOoO0o - OOooOOo . Oo0Ooo * OoOoOO00 / OoooooooOO * OoO0O00
 if 3 - 3: OoooooooOO + O0 % Oo0Ooo / oO0o
 if 67 - 67: I1ii11iIi11i % Oo0Ooo * OoOoOO00
 if 57 - 57: Oo0Ooo + I1IiiI * OOooOOo - Oo0Ooo
 if 57 - 57: I1IiiI + IiII + IiII * I1ii11iIi11i
 if 63 - 63: iIii1I11I1II1 % IiII * I1Ii111 . IiII * oO0o % o0oOOo0O0Ooo
 if 78 - 78: OOooOOo
 if 10 - 10: oO0o
 if 19 - 19: OoOoOO00 * I11i
 if ( map_request . rloc_probe and len ( lisp_sockets ) == 4 ) :
  O0ooooo = ( OOO0OO . is_private_address ( ) == False )
  iiiii11 = OOO0OO . print_address_no_iid ( )
  if ( O0ooooo and lisp_rtr_list . has_key ( iiiii11 ) ) :
   lisp_encapsulate_rloc_probe ( lisp_sockets , OOO0OO , None , I1i1iI )
   return
   if 32 - 32: i1IIi
   if 79 - 79: Oo0Ooo + II111iiii - o0oOOo0O0Ooo / Ii1I
   if 15 - 15: I11i / i1IIi % O0 % ooOoO0o / II111iiii * I11i
   if 18 - 18: i1IIi % oO0o
   if 80 - 80: II111iiii
   if 18 - 18: I1Ii111 % iII111i + OoOoOO00 . I1ii11iIi11i / I11i
 lisp_send_map_reply ( lisp_sockets , I1i1iI , OOO0OO , sport )
 return
 if 29 - 29: II111iiii - I1Ii111 . OoooooooOO / i11iIiiIii / I1ii11iIi11i
 if 60 - 60: i1IIi % ooOoO0o / II111iiii * Oo0Ooo - i1IIi . Ii1I
 if 63 - 63: OoO0O00 * OoooooooOO + iII111i / iIii1I11I1II1 . i11iIiiIii
 if 17 - 17: OOooOOo
 if 21 - 21: i1IIi
 if 10 - 10: i11iIiiIii / ooOoO0o - o0oOOo0O0Ooo . o0oOOo0O0Ooo
 if 8 - 8: iII111i + iIii1I11I1II1 . I1ii11iIi11i
def lisp_rtr_process_map_request ( lisp_sockets , map_request , source , sport ,
 ttl ) :
 if 68 - 68: OoooooooOO . OoooooooOO % I1ii11iIi11i + i1IIi % OoooooooOO + Ii1I
 if 89 - 89: ooOoO0o + I11i * O0 % OoOoOO00
 if 2 - 2: I1Ii111 % iIii1I11I1II1 . Ii1I - II111iiii
 if 33 - 33: I11i . i11iIiiIii % i1IIi * II111iiii * i11iIiiIii + OoOoOO00
 OOO0OO = map_request . itr_rlocs [ 0 ]
 if ( OOO0OO . is_private_address ( ) ) : OOO0OO = source
 iII = map_request . nonce
 if 26 - 26: I1IiiI % OoOoOO00 % I11i + Oo0Ooo
 I1IiiIiIIi1Ii = map_request . target_eid
 iIiii1Ii1I = map_request . target_group
 if 86 - 86: iII111i / i1IIi % Oo0Ooo
 OOoO000o00000 = [ ]
 for O0oOOo in [ lisp_myrlocs [ 0 ] , lisp_myrlocs [ 1 ] ] :
  if ( O0oOOo == None ) : continue
  i11iII1Ii1ii111 = lisp_rloc ( )
  i11iII1Ii1ii111 . rloc . copy_address ( O0oOOo )
  i11iII1Ii1ii111 . priority = 254
  OOoO000o00000 . append ( i11iII1Ii1ii111 )
  if 60 - 60: IiII * ooOoO0o
  if 40 - 40: iIii1I11I1II1 * i1IIi % i11iIiiIii + iIii1I11I1II1
 II1iII = lisp_nonce_echoing
 IiI1ii11I1 = map_request . keys
 if 69 - 69: i11iIiiIii . I1Ii111 + i11iIiiIii / OoO0O00
 I1i1iI = lisp_build_map_reply ( I1IiiIiIIi1Ii , iIiii1Ii1I , OOoO000o00000 , iII , LISP_NO_ACTION ,
 1440 , True , IiI1ii11I1 , II1iII , True , ttl )
 lisp_send_map_reply ( lisp_sockets , I1i1iI , OOO0OO , sport )
 return
 if 25 - 25: i11iIiiIii / Ii1I
 if 34 - 34: II111iiii + OOooOOo % oO0o - OOooOOo
 if 25 - 25: iII111i % iIii1I11I1II1 + IiII
 if 33 - 33: OOooOOo % I1IiiI - I1IiiI / IiII
 if 22 - 22: ooOoO0o * ooOoO0o % o0oOOo0O0Ooo * Ii1I . OoO0O00
 if 55 - 55: OoOoOO00 - I1ii11iIi11i + iIii1I11I1II1 - i11iIiiIii / i1IIi / II111iiii
 if 37 - 37: Ii1I + o0oOOo0O0Ooo
 if 74 - 74: Oo0Ooo / O0 + i1IIi . I1IiiI + OoO0O00 / Oo0Ooo
 if 13 - 13: o0oOOo0O0Ooo / Ii1I . II111iiii
 if 8 - 8: I11i - I11i % IiII
def lisp_get_private_rloc_set ( target_site_eid , seid , group ) :
 OOoO000o00000 = target_site_eid . registered_rlocs
 if 8 - 8: I1IiiI . IiII * O0 * o0oOOo0O0Ooo
 IiIIi1Ii = lisp_site_eid_lookup ( seid , group , False )
 if ( IiIIi1Ii == None ) : return ( OOoO000o00000 )
 if 51 - 51: Ii1I * iII111i
 if 24 - 24: iII111i * IiII / OOooOOo
 if 64 - 64: iII111i * Oo0Ooo
 if 42 - 42: ooOoO0o . O0 * ooOoO0o
 oooO0Oo = None
 i1I1i1iI1iI1 = [ ]
 for iiI1iI1 in OOoO000o00000 :
  if ( iiI1iI1 . is_rtr ( ) ) : continue
  if ( iiI1iI1 . rloc . is_private_address ( ) ) :
   ooo0OO0OOoO = copy . deepcopy ( iiI1iI1 )
   i1I1i1iI1iI1 . append ( ooo0OO0OOoO )
   continue
   if 70 - 70: Ii1I * i11iIiiIii
  oooO0Oo = iiI1iI1
  break
  if 28 - 28: II111iiii / ooOoO0o * i11iIiiIii % OOooOOo
 if ( oooO0Oo == None ) : return ( OOoO000o00000 )
 oooO0Oo = oooO0Oo . rloc . print_address_no_iid ( )
 if 18 - 18: I11i - IiII - iIii1I11I1II1
 if 82 - 82: II111iiii + OoO0O00 % iIii1I11I1II1 / O0
 if 75 - 75: OOooOOo * OoO0O00 + OoooooooOO + i11iIiiIii . OoO0O00
 if 94 - 94: I11i * ooOoO0o . I1IiiI / Ii1I - I1IiiI % OoooooooOO
 iiiii1 = None
 for iiI1iI1 in IiIIi1Ii . registered_rlocs :
  if ( iiI1iI1 . is_rtr ( ) ) : continue
  if ( iiI1iI1 . rloc . is_private_address ( ) ) : continue
  iiiii1 = iiI1iI1
  break
  if 61 - 61: OOooOOo % O0 . I1ii11iIi11i . iIii1I11I1II1 * I11i
 if ( iiiii1 == None ) : return ( OOoO000o00000 )
 iiiii1 = iiiii1 . rloc . print_address_no_iid ( )
 if 29 - 29: ooOoO0o + i1IIi % IiII * Ii1I
 if 94 - 94: OOooOOo / IiII
 if 18 - 18: IiII - I11i / Ii1I % IiII * i1IIi
 if 22 - 22: OoOoOO00 - Oo0Ooo
 Oo0ooo00OoO = target_site_eid . site_id
 if ( Oo0ooo00OoO == 0 ) :
  if ( iiiii1 == oooO0Oo ) :
   lprint ( "Return private RLOCs for sites behind {}" . format ( oooO0Oo ) )
   if 41 - 41: iIii1I11I1II1 * I1Ii111 / OoO0O00
   return ( i1I1i1iI1iI1 )
   if 33 - 33: I11i + O0
  return ( OOoO000o00000 )
  if 9 - 9: I11i . iII111i * ooOoO0o * ooOoO0o
  if 68 - 68: O0 - i11iIiiIii % iIii1I11I1II1 % ooOoO0o
  if 12 - 12: II111iiii + I11i
  if 9 - 9: I1ii11iIi11i
  if 51 - 51: I1ii11iIi11i
  if 37 - 37: I1IiiI % I1Ii111
  if 22 - 22: o0oOOo0O0Ooo % OOooOOo - I11i + ooOoO0o / OOooOOo
 if ( Oo0ooo00OoO == IiIIi1Ii . site_id ) :
  lprint ( "Return private RLOCs for sites in site-id {}" . format ( Oo0ooo00OoO ) )
  return ( i1I1i1iI1iI1 )
  if 98 - 98: I11i * O0 + IiII - oO0o
 return ( OOoO000o00000 )
 if 35 - 35: OoooooooOO * Ii1I
 if 73 - 73: ooOoO0o . OoO0O00 % I1ii11iIi11i - oO0o
 if 67 - 67: o0oOOo0O0Ooo . I11i + i1IIi
 if 100 - 100: Oo0Ooo - I1IiiI . OOooOOo % iIii1I11I1II1 . I11i
 if 83 - 83: OoOoOO00 * iII111i
 if 75 - 75: i11iIiiIii . o0oOOo0O0Ooo / oO0o . OoO0O00 % Ii1I % Ii1I
 if 94 - 94: iII111i . Ii1I
 if 71 - 71: o0oOOo0O0Ooo * II111iiii / OOooOOo . OoO0O00
 if 73 - 73: I1Ii111 * OoO0O00 / OoOoOO00 . II111iiii
def lisp_get_partial_rloc_set ( registered_rloc_set , mr_source , multicast ) :
 OOOO0o = [ ]
 OOoO000o00000 = [ ]
 if 60 - 60: iIii1I11I1II1
 if 100 - 100: Oo0Ooo + IiII
 if 81 - 81: iIii1I11I1II1 + iIii1I11I1II1
 if 19 - 19: ooOoO0o + i1IIi / Oo0Ooo * II111iiii * I1Ii111 / ooOoO0o
 if 23 - 23: I1Ii111
 if 76 - 76: Ii1I + Ii1I / i1IIi % o0oOOo0O0Ooo . iIii1I11I1II1 . OoOoOO00
 o0o = False
 Oo000O0O0oOo0 = False
 for iiI1iI1 in registered_rloc_set :
  if ( iiI1iI1 . priority != 254 ) : continue
  Oo000O0O0oOo0 |= True
  if ( iiI1iI1 . rloc . is_exact_match ( mr_source ) == False ) : continue
  o0o = True
  break
  if 13 - 13: OoO0O00 + Ii1I % iIii1I11I1II1 / Ii1I
  if 86 - 86: OoooooooOO % Ii1I
  if 21 - 21: iII111i
  if 72 - 72: I11i % o0oOOo0O0Ooo . iIii1I11I1II1 - I1Ii111 / i11iIiiIii
  if 75 - 75: OoooooooOO
  if 24 - 24: oO0o % iII111i - II111iiii / Ii1I + O0
  if 37 - 37: I1Ii111 - i1IIi / iIii1I11I1II1
 if ( Oo000O0O0oOo0 == False ) : return ( registered_rloc_set )
 if 53 - 53: Ii1I - iIii1I11I1II1 % I1ii11iIi11i * i11iIiiIii + ooOoO0o
 if 63 - 63: Oo0Ooo * I1IiiI
 if 84 - 84: Oo0Ooo
 if 67 - 67: oO0o / II111iiii . I11i / oO0o
 if 46 - 46: oO0o * Oo0Ooo - I11i / iIii1I11I1II1
 if 100 - 100: i11iIiiIii % oO0o
 if 62 - 62: OOooOOo * i1IIi - OOooOOo / i11iIiiIii
 if 17 - 17: I1ii11iIi11i + ooOoO0o % Ii1I % OOooOOo
 if 73 - 73: i11iIiiIii
 if 44 - 44: o0oOOo0O0Ooo % Ii1I - OoOoOO00 + OoOoOO00 * IiII + iII111i
 OOOO = ( os . getenv ( "LISP_RTR_BEHIND_NAT" ) != None )
 if 90 - 90: o0oOOo0O0Ooo
 if 19 - 19: OoOoOO00
 if 17 - 17: Oo0Ooo
 if 76 - 76: II111iiii % I1ii11iIi11i
 if 99 - 99: oO0o - I1Ii111
 for iiI1iI1 in registered_rloc_set :
  if ( OOOO and iiI1iI1 . rloc . is_private_address ( ) ) : continue
  if ( multicast == False and iiI1iI1 . priority == 255 ) : continue
  if ( multicast and iiI1iI1 . mpriority == 255 ) : continue
  if ( iiI1iI1 . priority == 254 ) :
   OOOO0o . append ( iiI1iI1 )
  else :
   OOoO000o00000 . append ( iiI1iI1 )
   if 29 - 29: I1IiiI - I11i
   if 42 - 42: Oo0Ooo - O0 . OoOoOO00
   if 4 - 4: IiII
   if 2 - 2: iII111i
   if 47 - 47: i1IIi % I11i
   if 17 - 17: OoOoOO00 - iII111i % I11i / o0oOOo0O0Ooo / II111iiii
 if ( o0o ) : return ( OOoO000o00000 )
 if 22 - 22: Oo0Ooo + I1ii11iIi11i % i11iIiiIii . OoO0O00 - I11i % I11i
 if 21 - 21: I1IiiI . OoO0O00 * IiII % OoooooooOO - Oo0Ooo + Oo0Ooo
 if 94 - 94: ooOoO0o
 if 80 - 80: i11iIiiIii - O0 / I1Ii111 + OOooOOo % Oo0Ooo
 if 95 - 95: II111iiii
 if 76 - 76: OoO0O00 % iII111i * OoOoOO00 / ooOoO0o / i1IIi
 if 45 - 45: Ii1I . I11i * I1Ii111 . i11iIiiIii
 if 34 - 34: O0 * o0oOOo0O0Ooo / IiII
 if 75 - 75: I1Ii111 - i1IIi - OoO0O00
 if 25 - 25: iII111i . o0oOOo0O0Ooo
 OOoO000o00000 = [ ]
 for iiI1iI1 in registered_rloc_set :
  if ( iiI1iI1 . rloc . is_private_address ( ) ) : OOoO000o00000 . append ( iiI1iI1 )
  if 62 - 62: I11i + i1IIi . I1ii11iIi11i - I1ii11iIi11i
 OOoO000o00000 += OOOO0o
 return ( OOoO000o00000 )
 if 68 - 68: ooOoO0o % OoooooooOO
 if 94 - 94: Oo0Ooo * o0oOOo0O0Ooo
 if 60 - 60: iII111i . OOooOOo
 if 39 - 39: O0 - i11iIiiIii - I1IiiI / Oo0Ooo - i11iIiiIii
 if 30 - 30: OoO0O00 / OoOoOO00 + I1ii11iIi11i % IiII - OoO0O00
 if 19 - 19: I1IiiI
 if 99 - 99: OOooOOo - OOooOOo
 if 98 - 98: o0oOOo0O0Ooo + O0 * oO0o - i11iIiiIii
 if 83 - 83: o0oOOo0O0Ooo
 if 23 - 23: o0oOOo0O0Ooo . I11i
def lisp_store_pubsub_state ( reply_eid , itr_rloc , mr_sport , nonce , ttl , xtr_id ) :
 oOoo0oO0oOo = lisp_pubsub ( itr_rloc , mr_sport , nonce , ttl , xtr_id )
 oOoo0oO0oOo . add ( reply_eid )
 return
 if 88 - 88: OoooooooOO
 if 30 - 30: ooOoO0o + Oo0Ooo . O0
 if 75 - 75: II111iiii . I1ii11iIi11i - OoO0O00 / Ii1I
 if 38 - 38: I1ii11iIi11i + I11i % iII111i - o0oOOo0O0Ooo - OoO0O00 . OOooOOo
 if 8 - 8: i11iIiiIii
 if 32 - 32: i1IIi - iII111i . I1ii11iIi11i * Ii1I % Oo0Ooo * OoOoOO00
 if 92 - 92: OoO0O00
 if 16 - 16: iIii1I11I1II1 / II111iiii % ooOoO0o + i11iIiiIii
 if 88 - 88: i11iIiiIii % ooOoO0o . IiII / I1Ii111 . o0oOOo0O0Ooo + I1IiiI
 if 16 - 16: Oo0Ooo - OOooOOo . IiII
 if 99 - 99: I11i % oO0o % ooOoO0o * iII111i - OoO0O00 * OoOoOO00
 if 10 - 10: I1ii11iIi11i
 if 5 - 5: IiII - iIii1I11I1II1 % oO0o % i1IIi
 if 68 - 68: OoooooooOO * Oo0Ooo / o0oOOo0O0Ooo * I11i + OoO0O00 . OoooooooOO
 if 12 - 12: oO0o - I1ii11iIi11i
def lisp_convert_reply_to_notify ( packet ) :
 if 69 - 69: iII111i * IiII * oO0o % OoO0O00 - o0oOOo0O0Ooo
 if 97 - 97: O0 + i11iIiiIii . i1IIi
 if 43 - 43: II111iiii + OOooOOo . i11iIiiIii - II111iiii
 if 80 - 80: o0oOOo0O0Ooo . oO0o . I1Ii111
 IiIii1iI = struct . unpack ( "I" , packet [ 0 : 4 ] ) [ 0 ]
 IiIii1iI = socket . ntohl ( IiIii1iI ) & 0xff
 iII = packet [ 4 : 12 ]
 packet = packet [ 12 : : ]
 if 60 - 60: iII111i % i11iIiiIii * OOooOOo % I1IiiI + OoO0O00
 if 56 - 56: I1Ii111 - OOooOOo + iIii1I11I1II1 + O0 * iIii1I11I1II1
 if 62 - 62: oO0o
 if 46 - 46: I1Ii111 - iII111i / oO0o % OoO0O00 / O0 + oO0o
 oO00O0o0oOOO = ( LISP_MAP_NOTIFY << 28 ) | IiIii1iI
 oo = struct . pack ( "I" , socket . htonl ( oO00O0o0oOOO ) )
 OO000 = struct . pack ( "I" , 0 )
 if 35 - 35: Oo0Ooo
 if 86 - 86: ooOoO0o . OoO0O00
 if 47 - 47: IiII % I1IiiI
 if 91 - 91: Ii1I
 packet = oo + iII + OO000 + packet
 return ( packet )
 if 69 - 69: iII111i
 if 96 - 96: Ii1I
 if 39 - 39: OoO0O00 - I1IiiI % II111iiii - IiII * I1ii11iIi11i
 if 64 - 64: OOooOOo + Oo0Ooo . OoOoOO00 . OOooOOo + i11iIiiIii
 if 7 - 7: ooOoO0o * I11i / iIii1I11I1II1
 if 15 - 15: OoooooooOO / iII111i
 if 40 - 40: o0oOOo0O0Ooo
 if 75 - 75: oO0o - OoOoOO00 * ooOoO0o . O0
def lisp_notify_subscribers ( lisp_sockets , eid_record , eid , site ) :
 I1I1iII1i = eid . print_prefix ( )
 if ( lisp_pubsub_cache . has_key ( I1I1iII1i ) == False ) : return
 if 78 - 78: Oo0Ooo
 for oOoo0oO0oOo in lisp_pubsub_cache [ I1I1iII1i ] . values ( ) :
  i1o0oOoooOoo0 = oOoo0oO0oOo . itr
  OoO0o = oOoo0oO0oOo . port
  oo0O = red ( i1o0oOoooOoo0 . print_address_no_iid ( ) , False )
  i1Iii = bold ( "subscriber" , False )
  ooO0O = "0x" + lisp_hex_string ( oOoo0oO0oOo . xtr_id )
  iII = "0x" + lisp_hex_string ( oOoo0oO0oOo . nonce )
  if 15 - 15: i11iIiiIii % iIii1I11I1II1 . II111iiii * I11i / I11i
  lprint ( "    Notify {} {}:{} xtr-id {} for {}, nonce {}" . format ( i1Iii , oo0O , OoO0o , ooO0O , green ( I1I1iII1i , False ) , iII ) )
  if 80 - 80: Ii1I % II111iiii
  if 4 - 4: OoOoOO00 * OOooOOo / OoooooooOO % OoOoOO00 * I1ii11iIi11i * o0oOOo0O0Ooo
  lisp_build_map_notify ( lisp_sockets , eid_record , [ I1I1iII1i ] , 1 , i1o0oOoooOoo0 ,
 OoO0o , oOoo0oO0oOo . nonce , 0 , 0 , 0 , site , False )
  oOoo0oO0oOo . map_notify_count += 1
  if 69 - 69: O0 % iIii1I11I1II1
 return
 if 94 - 94: O0
 if 50 - 50: I1Ii111 * o0oOOo0O0Ooo - ooOoO0o - I1ii11iIi11i % I1IiiI . ooOoO0o
 if 35 - 35: Ii1I % i1IIi + I1IiiI
 if 51 - 51: I1Ii111 / iIii1I11I1II1 + i1IIi
 if 71 - 71: iIii1I11I1II1 * ooOoO0o % iIii1I11I1II1 % I1IiiI
 if 75 - 75: I1IiiI
 if 33 - 33: OoOoOO00
def lisp_process_pubsub ( lisp_sockets , packet , reply_eid , itr_rloc , port , nonce ,
 ttl , xtr_id ) :
 if 53 - 53: i11iIiiIii / i1IIi . i1IIi + I11i
 if 19 - 19: ooOoO0o . OoOoOO00 + Oo0Ooo + iIii1I11I1II1 . OoOoOO00 - I1IiiI
 if 70 - 70: OOooOOo . OoOoOO00 . OOooOOo / iII111i
 if 72 - 72: OoooooooOO + Ii1I + iIii1I11I1II1
 lisp_store_pubsub_state ( reply_eid , itr_rloc , port , nonce , ttl , xtr_id )
 if 13 - 13: iII111i . I1Ii111 % ooOoO0o / i1IIi
 I1IiiIiIIi1Ii = green ( reply_eid . print_prefix ( ) , False )
 i1o0oOoooOoo0 = red ( itr_rloc . print_address_no_iid ( ) , False )
 oo0OO0Oo0o0 = bold ( "Map-Notify" , False )
 xtr_id = "0x" + lisp_hex_string ( xtr_id )
 lprint ( "{} pubsub request for {} to ack ITR {} xtr-id: {}" . format ( oo0OO0Oo0o0 ,
 I1IiiIiIIi1Ii , i1o0oOoooOoo0 , xtr_id ) )
 if 22 - 22: OoOoOO00 - OOooOOo % i1IIi + i1IIi
 if 28 - 28: oO0o + OoOoOO00 * Ii1I . I11i
 if 80 - 80: I1ii11iIi11i / OoOoOO00
 if 74 - 74: I1ii11iIi11i + O0 + o0oOOo0O0Ooo - iII111i
 packet = lisp_convert_reply_to_notify ( packet )
 lisp_send_map_notify ( lisp_sockets , packet , itr_rloc , port )
 return
 if 48 - 48: ooOoO0o * iIii1I11I1II1 % Oo0Ooo
 if 60 - 60: OoOoOO00 / i1IIi * iIii1I11I1II1
 if 91 - 91: I1Ii111 . OoooooooOO / IiII / I1IiiI
 if 56 - 56: II111iiii + iIii1I11I1II1 / I1Ii111 / I1Ii111 % Oo0Ooo / OoOoOO00
 if 46 - 46: i11iIiiIii + OoO0O00 . ooOoO0o + OoO0O00 % i11iIiiIii
 if 97 - 97: OoooooooOO % IiII * iIii1I11I1II1
 if 97 - 97: iIii1I11I1II1 - I1Ii111 - o0oOOo0O0Ooo * o0oOOo0O0Ooo * OoOoOO00
 if 80 - 80: II111iiii . I1ii11iIi11i % i11iIiiIii / Ii1I / oO0o
def lisp_ms_process_map_request ( lisp_sockets , packet , map_request , mr_source ,
 mr_sport , ecm_source ) :
 if 100 - 100: Ii1I . OoO0O00 * ooOoO0o
 if 4 - 4: i1IIi + OoooooooOO
 if 26 - 26: I1IiiI / II111iiii % I1ii11iIi11i * o0oOOo0O0Ooo . IiII / OoO0O00
 if 10 - 10: i11iIiiIii / i1IIi + O0 - i11iIiiIii % I11i - i1IIi
 if 38 - 38: O0 - I1IiiI + Oo0Ooo + ooOoO0o
 if 56 - 56: I1Ii111 + oO0o / Ii1I + I1Ii111
 I1IiiIiIIi1Ii = map_request . target_eid
 iIiii1Ii1I = map_request . target_group
 I1I1iII1i = lisp_print_eid_tuple ( I1IiiIiIIi1Ii , iIiii1Ii1I )
 OOO0OO = map_request . itr_rlocs [ 0 ]
 ooO0O = map_request . xtr_id
 iII = map_request . nonce
 OOoooO = LISP_NO_ACTION
 oOoo0oO0oOo = map_request . subscribe_bit
 if 21 - 21: OOooOOo / OoOoOO00 + OoOoOO00 + OoOoOO00 - i1IIi + Ii1I
 if 43 - 43: O0 % II111iiii
 if 60 - 60: iII111i / ooOoO0o - Ii1I - OoooooooOO
 if 79 - 79: oO0o / iII111i . iIii1I11I1II1 * i11iIiiIii * i1IIi . iIii1I11I1II1
 if 31 - 31: OoooooooOO / ooOoO0o / OoooooooOO + ooOoO0o . O0 - IiII
 oO0000o00OO = True
 II1IIII = ( lisp_get_eid_hash ( I1IiiIiIIi1Ii ) != None )
 if ( II1IIII ) :
  iIIIIi = map_request . map_request_signature
  if ( iIIIIi == None ) :
   oO0000o00OO = False
   lprint ( ( "EID-crypto-hash signature verification {}, " + "no signature found" ) . format ( bold ( "failed" , False ) ) )
   if 24 - 24: I1ii11iIi11i * i11iIiiIii + OoooooooOO
  else :
   OoiIiiIi11 = map_request . signature_eid
   i1iII , O0OOO0O0Oo0O , oO0000o00OO = lisp_lookup_public_key ( OoiIiiIi11 )
   if ( oO0000o00OO ) :
    oO0000o00OO = map_request . verify_map_request_sig ( O0OOO0O0Oo0O )
   else :
    lprint ( "Public-key lookup failed for sig-eid {}, hash-eid {}" . format ( OoiIiiIi11 . print_address ( ) , i1iII . print_address ( ) ) )
    if 1 - 1: I1IiiI
    if 68 - 68: ooOoO0o
   o00o0OOO000 = bold ( "passed" , False ) if oO0000o00OO else bold ( "failed" , False )
   lprint ( "EID-crypto-hash signature verification {}" . format ( o00o0OOO000 ) )
   if 43 - 43: I1Ii111
   if 53 - 53: I1Ii111 + ooOoO0o - iII111i + I1ii11iIi11i * iII111i
   if 95 - 95: OoO0O00 * OoOoOO00 / i1IIi / iII111i + IiII - Ii1I
 if ( oOoo0oO0oOo and oO0000o00OO == False ) :
  oOoo0oO0oOo = False
  lprint ( "Suppress creating pubsub state due to signature failure" )
  if 36 - 36: II111iiii * OoO0O00 + I11i
  if 39 - 39: II111iiii - OoO0O00
  if 8 - 8: I11i - OoO0O00 / II111iiii
  if 32 - 32: oO0o
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
 ii1iI1i1IIi = OOO0OO if ( OOO0OO . afi == ecm_source . afi ) else ecm_source
 if 20 - 20: OoO0O00 * II111iiii
 iI1II1i1I1Ii = lisp_site_eid_lookup ( I1IiiIiIIi1Ii , iIiii1Ii1I , False )
 if 4 - 4: OoO0O00 . I1IiiI - O0 % iII111i . OOooOOo
 if ( iI1II1i1I1Ii == None or iI1II1i1I1Ii . is_star_g ( ) ) :
  oo0 = bold ( "Site not found" , False )
  lprint ( "{} for requested EID {}" . format ( oo0 ,
 green ( I1I1iII1i , False ) ) )
  if 40 - 40: i1IIi
  if 11 - 11: Oo0Ooo + oO0o
  if 53 - 53: OOooOOo % ooOoO0o
  if 91 - 91: o0oOOo0O0Ooo + i11iIiiIii
  lisp_send_negative_map_reply ( lisp_sockets , I1IiiIiIIi1Ii , iIiii1Ii1I , iII , OOO0OO ,
 mr_sport , 15 , ooO0O , oOoo0oO0oOo )
  if 92 - 92: OoOoOO00 * i11iIiiIii . OoO0O00 % oO0o
  return ( [ I1IiiIiIIi1Ii , iIiii1Ii1I , LISP_DDT_ACTION_SITE_NOT_FOUND ] )
  if 12 - 12: OoO0O00
  if 5 - 5: OoOoOO00
 ii1IOo0OOoo = iI1II1i1I1Ii . print_eid_tuple ( )
 II1Iiii1I = iI1II1i1I1Ii . site . site_name
 if 22 - 22: II111iiii / IiII % oO0o * o0oOOo0O0Ooo + OoooooooOO - IiII
 if 56 - 56: OOooOOo / ooOoO0o + I1Ii111 / I11i + I1IiiI
 if 63 - 63: ooOoO0o * I1ii11iIi11i * I1Ii111 - I1ii11iIi11i * i11iIiiIii
 if 100 - 100: oO0o . i11iIiiIii + I1IiiI % oO0o + I11i . OoooooooOO
 if 84 - 84: oO0o * oO0o - i1IIi + ooOoO0o
 if ( II1IIII == False and iI1II1i1I1Ii . require_signature ) :
  iIIIIi = map_request . map_request_signature
  OoiIiiIi11 = map_request . signature_eid
  if ( iIIIIi == None or OoiIiiIi11 . is_null ( ) ) :
   lprint ( "Signature required for site {}" . format ( II1Iiii1I ) )
   oO0000o00OO = False
  else :
   OoiIiiIi11 = map_request . signature_eid
   i1iII , O0OOO0O0Oo0O , oO0000o00OO = lisp_lookup_public_key ( OoiIiiIi11 )
   if ( oO0000o00OO ) :
    oO0000o00OO = map_request . verify_map_request_sig ( O0OOO0O0Oo0O )
   else :
    lprint ( "Public-key lookup failed for sig-eid {}, hash-eid {}" . format ( OoiIiiIi11 . print_address ( ) , i1iII . print_address ( ) ) )
    if 83 - 83: i1IIi
    if 85 - 85: i11iIiiIii / OoO0O00 / oO0o
   o00o0OOO000 = bold ( "passed" , False ) if oO0000o00OO else bold ( "failed" , False )
   lprint ( "Required signature verification {}" . format ( o00o0OOO000 ) )
   if 12 - 12: iII111i % OOooOOo % i1IIi
   if 17 - 17: IiII
   if 63 - 63: ooOoO0o . i11iIiiIii / iIii1I11I1II1
   if 8 - 8: i11iIiiIii . IiII * iIii1I11I1II1 * I1IiiI * Ii1I * i11iIiiIii
   if 24 - 24: I1IiiI * I11i - o0oOOo0O0Ooo / iII111i + IiII - I1ii11iIi11i
   if 53 - 53: I11i / I1IiiI - iIii1I11I1II1 - o0oOOo0O0Ooo * OoOoOO00
 if ( oO0000o00OO and iI1II1i1I1Ii . registered == False ) :
  lprint ( "Site '{}' with EID-prefix {} is not registered for EID {}" . format ( II1Iiii1I , green ( ii1IOo0OOoo , False ) , green ( I1I1iII1i , False ) ) )
  if 86 - 86: iIii1I11I1II1 - I1Ii111
  if 86 - 86: O0 * IiII + OoOoOO00 + OoO0O00
  if 53 - 53: I1IiiI % i11iIiiIii + o0oOOo0O0Ooo . I1ii11iIi11i
  if 73 - 73: iII111i - o0oOOo0O0Ooo / OOooOOo + iII111i + o0oOOo0O0Ooo % II111iiii
  if 74 - 74: I11i * iIii1I11I1II1 - OoO0O00 / i1IIi / OoO0O00 / IiII
  if 60 - 60: oO0o % I1Ii111 % Oo0Ooo
  if ( iI1II1i1I1Ii . accept_more_specifics == False ) :
   I1IiiIiIIi1Ii = iI1II1i1I1Ii . eid
   iIiii1Ii1I = iI1II1i1I1Ii . group
   if 34 - 34: o0oOOo0O0Ooo * OOooOOo % Ii1I + I1IiiI
   if 77 - 77: OoOoOO00 + IiII + Oo0Ooo
   if 88 - 88: i1IIi
   if 45 - 45: iII111i % I1ii11iIi11i / i11iIiiIii - II111iiii . Oo0Ooo / ooOoO0o
   if 55 - 55: OoO0O00 % IiII
  o0O0OOo0oo00 = 1
  if ( iI1II1i1I1Ii . force_ttl != None ) :
   o0O0OOo0oo00 = iI1II1i1I1Ii . force_ttl | 0x80000000
   if 93 - 93: OoO0O00 . I1ii11iIi11i / OOooOOo % OoooooooOO + i1IIi + I1Ii111
   if 94 - 94: II111iiii + i11iIiiIii % Ii1I / ooOoO0o * OoOoOO00
   if 68 - 68: O0 / Oo0Ooo / iIii1I11I1II1
   if 63 - 63: I1Ii111 + iII111i
   if 6 - 6: I1ii11iIi11i + Ii1I
  lisp_send_negative_map_reply ( lisp_sockets , I1IiiIiIIi1Ii , iIiii1Ii1I , iII , OOO0OO ,
 mr_sport , o0O0OOo0oo00 , ooO0O , oOoo0oO0oOo )
  if 36 - 36: iII111i + iII111i * OoO0O00 * I1ii11iIi11i
  return ( [ I1IiiIiIIi1Ii , iIiii1Ii1I , LISP_DDT_ACTION_MS_NOT_REG ] )
  if 97 - 97: ooOoO0o + OOooOOo
  if 70 - 70: o0oOOo0O0Ooo + Ii1I - i11iIiiIii + I11i * o0oOOo0O0Ooo . Ii1I
  if 6 - 6: Oo0Ooo + I1IiiI
  if 48 - 48: oO0o . I1ii11iIi11i
  if 59 - 59: IiII - Ii1I
 O0OO000OOooO = False
 OoOooOoOo = ""
 oOoO = False
 if ( iI1II1i1I1Ii . force_nat_proxy_reply ) :
  OoOooOoOo = ", nat-forced"
  O0OO000OOooO = True
  oOoO = True
 elif ( iI1II1i1I1Ii . force_proxy_reply ) :
  OoOooOoOo = ", forced"
  oOoO = True
 elif ( iI1II1i1I1Ii . proxy_reply_requested ) :
  OoOooOoOo = ", requested"
  oOoO = True
 elif ( map_request . pitr_bit and iI1II1i1I1Ii . pitr_proxy_reply_drop ) :
  OoOooOoOo = ", drop-to-pitr"
  OOoooO = LISP_DROP_ACTION
 elif ( iI1II1i1I1Ii . proxy_reply_action != "" ) :
  OOoooO = iI1II1i1I1Ii . proxy_reply_action
  OoOooOoOo = ", forced, action {}" . format ( OOoooO )
  OOoooO = LISP_DROP_ACTION if ( OOoooO == "drop" ) else LISP_NATIVE_FORWARD_ACTION
  if 19 - 19: OOooOOo
  if 24 - 24: OoooooooOO + ooOoO0o - oO0o - o0oOOo0O0Ooo
  if 29 - 29: Ii1I - OoOoOO00 + I11i + iII111i / i11iIiiIii . i1IIi
  if 52 - 52: II111iiii
  if 75 - 75: II111iiii / OoO0O00 % II111iiii
  if 3 - 3: Ii1I - Ii1I % I1ii11iIi11i
  if 44 - 44: OOooOOo - o0oOOo0O0Ooo
 O0oOoOO = False
 II1I1i = None
 if ( oOoO and lisp_policies . has_key ( iI1II1i1I1Ii . policy ) ) :
  Iiiii1III1iIi = lisp_policies [ iI1II1i1I1Ii . policy ]
  if ( Iiiii1III1iIi . match_policy_map_request ( map_request , mr_source ) ) : II1I1i = Iiiii1III1iIi
  if 82 - 82: I1IiiI + iIii1I11I1II1
  if ( II1I1i ) :
   Ii1i1i = bold ( "matched" , False )
   lprint ( "Map-Request {} policy '{}', set-action '{}'" . format ( Ii1i1i ,
 Iiiii1III1iIi . policy_name , Iiiii1III1iIi . set_action ) )
  else :
   Ii1i1i = bold ( "no match" , False )
   lprint ( "Map-Request {} for policy '{}', implied drop" . format ( Ii1i1i ,
 Iiiii1III1iIi . policy_name ) )
   O0oOoOO = True
   if 62 - 62: OoooooooOO
   if 38 - 38: iII111i % iII111i * ooOoO0o / OoO0O00 + ooOoO0o
   if 52 - 52: ooOoO0o . iIii1I11I1II1 / iIii1I11I1II1 % oO0o - oO0o * II111iiii
 if ( OoOooOoOo != "" ) :
  lprint ( "Proxy-replying for EID {}, found site '{}' EID-prefix {}{}" . format ( green ( I1I1iII1i , False ) , II1Iiii1I , green ( ii1IOo0OOoo , False ) ,
  # I1Ii111 . i1IIi / I1ii11iIi11i + II111iiii
 OoOooOoOo ) )
  if 99 - 99: o0oOOo0O0Ooo . I1IiiI + o0oOOo0O0Ooo * o0oOOo0O0Ooo / O0
  OOoO000o00000 = iI1II1i1I1Ii . registered_rlocs
  o0O0OOo0oo00 = 1440
  if ( O0OO000OOooO ) :
   if ( iI1II1i1I1Ii . site_id != 0 ) :
    i11i1III1 = map_request . source_eid
    OOoO000o00000 = lisp_get_private_rloc_set ( iI1II1i1I1Ii , i11i1III1 , iIiii1Ii1I )
    if 38 - 38: I1ii11iIi11i - IiII . iII111i + Oo0Ooo . I11i
   if ( OOoO000o00000 == iI1II1i1I1Ii . registered_rlocs ) :
    oOoOo = ( iI1II1i1I1Ii . group . is_null ( ) == False )
    i1I1i1iI1iI1 = lisp_get_partial_rloc_set ( OOoO000o00000 , ii1iI1i1IIi , oOoOo )
    if ( i1I1i1iI1iI1 != OOoO000o00000 ) :
     o0O0OOo0oo00 = 15
     OOoO000o00000 = i1I1i1iI1iI1
     if 47 - 47: ooOoO0o . IiII + Ii1I
     if 18 - 18: OoooooooOO
     if 99 - 99: OoOoOO00 + Oo0Ooo . I1IiiI . oO0o
     if 10 - 10: I1Ii111 + I1IiiI . iIii1I11I1II1 + IiII / i11iIiiIii - O0
     if 27 - 27: OoooooooOO / I1ii11iIi11i
     if 87 - 87: I11i + IiII / OOooOOo
     if 70 - 70: II111iiii
     if 21 - 21: i11iIiiIii . iII111i * O0 - iII111i
  if ( iI1II1i1I1Ii . force_ttl != None ) :
   o0O0OOo0oo00 = iI1II1i1I1Ii . force_ttl | 0x80000000
   if 5 - 5: O0 . OoOoOO00 / iII111i
   if 78 - 78: Ii1I - I1ii11iIi11i + iIii1I11I1II1 + OoooooooOO . OoO0O00 - ooOoO0o
   if 81 - 81: o0oOOo0O0Ooo * OoooooooOO
   if 32 - 32: OoOoOO00 - I11i * i11iIiiIii . I1ii11iIi11i . IiII . iIii1I11I1II1
   if 41 - 41: iII111i / OoOoOO00 / OoO0O00 / ooOoO0o
   if 16 - 16: iIii1I11I1II1 . II111iiii
  if ( II1I1i ) :
   if ( II1I1i . set_record_ttl ) :
    o0O0OOo0oo00 = II1I1i . set_record_ttl
    lprint ( "Policy set-record-ttl to {}" . format ( o0O0OOo0oo00 ) )
    if 80 - 80: Oo0Ooo + IiII
   if ( II1I1i . set_action == "drop" ) :
    lprint ( "Policy set-action drop, send negative Map-Reply" )
    OOoooO = LISP_POLICY_DENIED_ACTION
    OOoO000o00000 = [ ]
   else :
    i11iII1Ii1ii111 = II1I1i . set_policy_map_reply ( )
    if ( i11iII1Ii1ii111 ) : OOoO000o00000 = [ i11iII1Ii1ii111 ]
    if 18 - 18: OoO0O00 . Oo0Ooo
    if 52 - 52: OoOoOO00 . iIii1I11I1II1 / OoOoOO00
    if 14 - 14: i1IIi
  if ( O0oOoOO ) :
   lprint ( "Implied drop action, send negative Map-Reply" )
   OOoooO = LISP_POLICY_DENIED_ACTION
   OOoO000o00000 = [ ]
   if 63 - 63: OoOoOO00 . i11iIiiIii / IiII
   if 36 - 36: OOooOOo * OoOoOO00 + i11iIiiIii + O0 + O0
  II1iII = iI1II1i1I1Ii . echo_nonce_capable
  if 18 - 18: Oo0Ooo . I1ii11iIi11i * ooOoO0o % Ii1I + I1ii11iIi11i
  if 23 - 23: oO0o / o0oOOo0O0Ooo + I11i % IiII * OoO0O00
  if 48 - 48: OoO0O00
  if 30 - 30: iIii1I11I1II1
  if ( oO0000o00OO ) :
   oOo00 = iI1II1i1I1Ii . eid
   OOooo00ooO = iI1II1i1I1Ii . group
  else :
   oOo00 = I1IiiIiIIi1Ii
   OOooo00ooO = iIiii1Ii1I
   OOoooO = LISP_AUTH_FAILURE_ACTION
   OOoO000o00000 = [ ]
   if 78 - 78: oO0o
   if 20 - 20: i1IIi + i1IIi * i1IIi
   if 32 - 32: I1IiiI + IiII + iII111i . iIii1I11I1II1 * Ii1I
   if 27 - 27: oO0o + Ii1I . i11iIiiIii
   if 97 - 97: iII111i . I1IiiI
   if 71 - 71: OOooOOo - IiII % oO0o * I1ii11iIi11i
  packet = lisp_build_map_reply ( oOo00 , OOooo00ooO , OOoO000o00000 ,
 iII , OOoooO , o0O0OOo0oo00 , False , None , II1iII , False )
  if 48 - 48: o0oOOo0O0Ooo * iIii1I11I1II1 + Oo0Ooo
  if ( oOoo0oO0oOo ) :
   lisp_process_pubsub ( lisp_sockets , packet , oOo00 , OOO0OO ,
 mr_sport , iII , o0O0OOo0oo00 , ooO0O )
  else :
   lisp_send_map_reply ( lisp_sockets , packet , OOO0OO , mr_sport )
   if 45 - 45: oO0o
   if 50 - 50: Ii1I * Ii1I / O0 . Oo0Ooo + iII111i
  return ( [ iI1II1i1I1Ii . eid , iI1II1i1I1Ii . group , LISP_DDT_ACTION_MS_ACK ] )
  if 9 - 9: OoooooooOO % O0 % I1ii11iIi11i
  if 100 - 100: i11iIiiIii - iII111i - I11i
  if 5 - 5: oO0o % IiII * iII111i
  if 98 - 98: iII111i / OOooOOo + IiII
  if 100 - 100: II111iiii . i11iIiiIii / oO0o - OOooOOo + OoOoOO00 % I1ii11iIi11i
 Oo0OO0O00o = len ( iI1II1i1I1Ii . registered_rlocs )
 if ( Oo0OO0O00o == 0 ) :
  lprint ( "Requested EID {} found site '{}' with EID-prefix {} with " + "no registered RLOCs" . format ( green ( I1I1iII1i , False ) , II1Iiii1I ,
  # Ii1I + iII111i * Ii1I - O0 % I1ii11iIi11i
 green ( ii1IOo0OOoo , False ) ) )
  return ( [ iI1II1i1I1Ii . eid , iI1II1i1I1Ii . group , LISP_DDT_ACTION_MS_ACK ] )
  if 52 - 52: i11iIiiIii % I1Ii111 - iII111i / O0 - I1ii11iIi11i / iII111i
  if 7 - 7: OoooooooOO . OOooOOo . OOooOOo
  if 53 - 53: OOooOOo * OoOoOO00 % iII111i
  if 86 - 86: OOooOOo . OOooOOo + IiII - I1ii11iIi11i . OoO0O00
  if 66 - 66: I1IiiI * OoOoOO00 . I1IiiI / Oo0Ooo - Ii1I
 OoO000Oo000 = map_request . target_eid if map_request . source_eid . is_null ( ) else map_request . source_eid
 if 67 - 67: Ii1I % Oo0Ooo - Oo0Ooo . I11i + IiII
 oooOo00 = map_request . target_eid . hash_address ( OoO000Oo000 )
 oooOo00 %= Oo0OO0O00o
 oOooo0o = iI1II1i1I1Ii . registered_rlocs [ oooOo00 ]
 if 45 - 45: oO0o + ooOoO0o + OOooOOo * OOooOOo * o0oOOo0O0Ooo / Oo0Ooo
 if ( oOooo0o . rloc . is_null ( ) ) :
  lprint ( ( "Suppress forwarding Map-Request for EID {} at site '{}' " + "EID-prefix {}, no RLOC address" ) . format ( green ( I1I1iII1i , False ) ,
  # Ii1I - iIii1I11I1II1 / O0 . i1IIi
 II1Iiii1I , green ( ii1IOo0OOoo , False ) ) )
 else :
  lprint ( ( "Forwarding Map-Request for EID {} to ETR {} at site '{}' " + "EID-prefix {}" ) . format ( green ( I1I1iII1i , False ) ,
  # OoO0O00 * iIii1I11I1II1 - iIii1I11I1II1 % OoO0O00 . I1ii11iIi11i
 red ( oOooo0o . rloc . print_address ( ) , False ) , II1Iiii1I ,
 green ( ii1IOo0OOoo , False ) ) )
  if 19 - 19: i1IIi % Ii1I . OoOoOO00
  if 22 - 22: iIii1I11I1II1 + Ii1I
  if 73 - 73: I1IiiI / OoO0O00 / OoooooooOO
  if 14 - 14: ooOoO0o % o0oOOo0O0Ooo / I1ii11iIi11i . IiII + I1ii11iIi11i
  lisp_send_ecm ( lisp_sockets , packet , map_request . source_eid , mr_sport ,
 map_request . target_eid , oOooo0o . rloc , to_etr = True )
  if 30 - 30: I1ii11iIi11i + iIii1I11I1II1 . I1ii11iIi11i
 return ( [ iI1II1i1I1Ii . eid , iI1II1i1I1Ii . group , LISP_DDT_ACTION_MS_ACK ] )
 if 9 - 9: I1IiiI - Ii1I * II111iiii - I11i
 if 85 - 85: oO0o % ooOoO0o / OOooOOo
 if 50 - 50: O0 * O0 / iIii1I11I1II1
 if 31 - 31: I1IiiI / o0oOOo0O0Ooo
 if 70 - 70: I1IiiI
 if 36 - 36: ooOoO0o . oO0o . I11i - I1ii11iIi11i / OoOoOO00 * Oo0Ooo
 if 42 - 42: OoooooooOO / o0oOOo0O0Ooo . Ii1I * iII111i * I1IiiI - Oo0Ooo
def lisp_ddt_process_map_request ( lisp_sockets , map_request , ecm_source , port ) :
 if 76 - 76: oO0o * II111iiii
 if 81 - 81: I11i
 if 2 - 2: OoOoOO00
 if 75 - 75: I1IiiI - OoooooooOO * I1Ii111
 I1IiiIiIIi1Ii = map_request . target_eid
 iIiii1Ii1I = map_request . target_group
 I1I1iII1i = lisp_print_eid_tuple ( I1IiiIiIIi1Ii , iIiii1Ii1I )
 iII = map_request . nonce
 OOoooO = LISP_DDT_ACTION_NULL
 if 1 - 1: o0oOOo0O0Ooo % oO0o * I1Ii111 - i1IIi - iII111i . oO0o
 if 25 - 25: i1IIi * o0oOOo0O0Ooo / oO0o
 if 11 - 11: IiII + II111iiii
 if 37 - 37: O0
 if 98 - 98: IiII * OoooooooOO . iII111i
 ii111I = None
 if ( lisp_i_am_ms ) :
  iI1II1i1I1Ii = lisp_site_eid_lookup ( I1IiiIiIIi1Ii , iIiii1Ii1I , False )
  if ( iI1II1i1I1Ii == None ) : return
  if 26 - 26: OoooooooOO % I1ii11iIi11i - i11iIiiIii
  if ( iI1II1i1I1Ii . registered ) :
   OOoooO = LISP_DDT_ACTION_MS_ACK
   o0O0OOo0oo00 = 1440
  else :
   I1IiiIiIIi1Ii , iIiii1Ii1I , OOoooO = lisp_ms_compute_neg_prefix ( I1IiiIiIIi1Ii , iIiii1Ii1I )
   OOoooO = LISP_DDT_ACTION_MS_NOT_REG
   o0O0OOo0oo00 = 1
   if 84 - 84: OoO0O00
 else :
  ii111I = lisp_ddt_cache_lookup ( I1IiiIiIIi1Ii , iIiii1Ii1I , False )
  if ( ii111I == None ) :
   OOoooO = LISP_DDT_ACTION_NOT_AUTH
   o0O0OOo0oo00 = 0
   lprint ( "DDT delegation entry not found for EID {}" . format ( green ( I1I1iII1i , False ) ) )
   if 67 - 67: I1Ii111 + I1Ii111
  elif ( ii111I . is_auth_prefix ( ) ) :
   if 81 - 81: II111iiii % I11i % O0 . I1Ii111 % ooOoO0o - O0
   if 58 - 58: OoooooooOO . II111iiii . O0 % I1Ii111 / OoooooooOO
   if 64 - 64: Oo0Ooo + oO0o . OoO0O00
   if 67 - 67: I11i
   OOoooO = LISP_DDT_ACTION_DELEGATION_HOLE
   o0O0OOo0oo00 = 15
   o0OO = ii111I . print_eid_tuple ( )
   lprint ( ( "DDT delegation entry not found but auth-prefix {} " + "found for EID {}" ) . format ( o0OO ,
   # I1IiiI . iII111i * I1Ii111 . IiII % I1ii11iIi11i
 green ( I1I1iII1i , False ) ) )
   if 44 - 44: I11i % I1ii11iIi11i - OoooooooOO % iII111i
   if ( iIiii1Ii1I . is_null ( ) ) :
    I1IiiIiIIi1Ii = lisp_ddt_compute_neg_prefix ( I1IiiIiIIi1Ii , ii111I ,
 lisp_ddt_cache )
   else :
    iIiii1Ii1I = lisp_ddt_compute_neg_prefix ( iIiii1Ii1I , ii111I ,
 lisp_ddt_cache )
    I1IiiIiIIi1Ii = lisp_ddt_compute_neg_prefix ( I1IiiIiIIi1Ii , ii111I ,
 ii111I . source_cache )
    if 60 - 60: IiII % oO0o
   ii111I = None
  else :
   o0OO = ii111I . print_eid_tuple ( )
   lprint ( "DDT delegation entry {} found for EID {}" . format ( o0OO , green ( I1I1iII1i , False ) ) )
   if 11 - 11: I1Ii111 - II111iiii
   o0O0OOo0oo00 = 1440
   if 12 - 12: i11iIiiIii
   if 9 - 9: OOooOOo * I1ii11iIi11i + iIii1I11I1II1 / OoO0O00 * OoooooooOO
   if 91 - 91: i11iIiiIii % IiII + oO0o . I1IiiI - I1IiiI
   if 62 - 62: Oo0Ooo * II111iiii + o0oOOo0O0Ooo . OoOoOO00
   if 94 - 94: Oo0Ooo / I1IiiI * iIii1I11I1II1 - OoO0O00
   if 96 - 96: ooOoO0o - OoooooooOO * iIii1I11I1II1 . IiII - O0
 I1i1iI = lisp_build_map_referral ( I1IiiIiIIi1Ii , iIiii1Ii1I , ii111I , OOoooO , o0O0OOo0oo00 , iII )
 iII = map_request . nonce >> 32
 if ( map_request . nonce != 0 and iII != 0xdfdf0e1d ) : port = LISP_CTRL_PORT
 lisp_send_map_referral ( lisp_sockets , I1i1iI , ecm_source , port )
 return
 if 7 - 7: iIii1I11I1II1 . OoO0O00
 if 88 - 88: i1IIi * II111iiii / i11iIiiIii % IiII . IiII
 if 93 - 93: OoOoOO00 * i1IIi . Ii1I
 if 2 - 2: i1IIi
 if 84 - 84: i1IIi / Ii1I + OoOoOO00 % Ii1I . oO0o
 if 74 - 74: OOooOOo - o0oOOo0O0Ooo - I1Ii111 - OoO0O00
 if 40 - 40: o0oOOo0O0Ooo . IiII * OoOoOO00
 if 14 - 14: OOooOOo
 if 18 - 18: i11iIiiIii % iII111i
 if 70 - 70: O0 + iII111i % I11i % I1Ii111 + OoOoOO00 / ooOoO0o
 if 35 - 35: IiII + OoO0O00
 if 82 - 82: i1IIi - ooOoO0o / I11i + I11i % I1IiiI - OoooooooOO
 if 56 - 56: I1ii11iIi11i
def lisp_find_negative_mask_len ( eid , entry_prefix , neg_prefix ) :
 OOo0 = eid . hash_address ( entry_prefix )
 IIi11ii1 = eid . addr_length ( ) * 8
 o0O00ooo0oO0o = 0
 if 36 - 36: i1IIi % oO0o - O0 - OoO0O00 . OoooooooOO - O0
 if 20 - 20: I11i % I1IiiI
 if 82 - 82: i11iIiiIii * i11iIiiIii + I1Ii111 - I1ii11iIi11i * oO0o - Ii1I
 if 40 - 40: o0oOOo0O0Ooo + OoO0O00 % i1IIi % iII111i * I1Ii111
 for o0O00ooo0oO0o in range ( IIi11ii1 ) :
  II1ii1IIi1i = 1 << ( IIi11ii1 - o0O00ooo0oO0o - 1 )
  if ( OOo0 & II1ii1IIi1i ) : break
  if 4 - 4: II111iiii . I1ii11iIi11i
  if 21 - 21: I11i . O0 * OoOoOO00 - OOooOOo + ooOoO0o
 if ( o0O00ooo0oO0o > neg_prefix . mask_len ) : neg_prefix . mask_len = o0O00ooo0oO0o
 return
 if 81 - 81: Oo0Ooo + I1Ii111 - I1IiiI
 if 4 - 4: i1IIi
 if 89 - 89: II111iiii . I11i + Ii1I * ooOoO0o + I11i . IiII
 if 83 - 83: o0oOOo0O0Ooo - iIii1I11I1II1
 if 9 - 9: Ii1I
 if 53 - 53: Ii1I % IiII + I11i % IiII
 if 33 - 33: iII111i
 if 8 - 8: I11i
 if 95 - 95: OoOoOO00 % O0 % I1IiiI
 if 85 - 85: iIii1I11I1II1 * i11iIiiIii
def lisp_neg_prefix_walk ( entry , parms ) :
 I1IiiIiIIi1Ii , ooO00Oo0o0OOo , o000oOo0oooO0 = parms
 if 7 - 7: OoO0O00 + OoooooooOO % II111iiii % oO0o
 if ( ooO00Oo0o0OOo == None ) :
  if ( entry . eid . instance_id != I1IiiIiIIi1Ii . instance_id ) :
   return ( [ True , parms ] )
   if 48 - 48: OOooOOo . II111iiii * OOooOOo - I11i / iIii1I11I1II1 / i11iIiiIii
  if ( entry . eid . afi != I1IiiIiIIi1Ii . afi ) : return ( [ True , parms ] )
 else :
  if ( entry . eid . is_more_specific ( ooO00Oo0o0OOo ) == False ) :
   return ( [ True , parms ] )
   if 37 - 37: II111iiii % O0 + iIii1I11I1II1 - I1IiiI . I11i + I1ii11iIi11i
   if 14 - 14: ooOoO0o % iIii1I11I1II1 % ooOoO0o / IiII + OOooOOo
   if 14 - 14: Oo0Ooo
   if 79 - 79: I1ii11iIi11i % I1Ii111 % I11i - iII111i * OoOoOO00
   if 48 - 48: O0 + OoOoOO00 - O0
   if 79 - 79: ooOoO0o . OoOoOO00 / OoooooooOO - II111iiii
 lisp_find_negative_mask_len ( I1IiiIiIIi1Ii , entry . eid , o000oOo0oooO0 )
 return ( [ True , parms ] )
 if 48 - 48: Oo0Ooo
 if 59 - 59: OoO0O00 % o0oOOo0O0Ooo
 if 83 - 83: iII111i % iIii1I11I1II1 / OOooOOo - OoOoOO00
 if 98 - 98: I11i % oO0o . I1IiiI % OoOoOO00
 if 32 - 32: I1ii11iIi11i / Ii1I
 if 54 - 54: I11i - i11iIiiIii
 if 91 - 91: Ii1I - OoO0O00 - I1IiiI % OoO0O00 . o0oOOo0O0Ooo
 if 85 - 85: ooOoO0o . ooOoO0o % Oo0Ooo . OOooOOo + OOooOOo / I1IiiI
def lisp_ddt_compute_neg_prefix ( eid , ddt_entry , cache ) :
 if 69 - 69: i1IIi + II111iiii / Ii1I
 if 4 - 4: I11i * OoOoOO00 % o0oOOo0O0Ooo % ooOoO0o - I1ii11iIi11i
 if 88 - 88: iIii1I11I1II1 * iIii1I11I1II1 * I11i * OoOoOO00
 if 14 - 14: i11iIiiIii * I1IiiI % O0 % iIii1I11I1II1
 if ( eid . is_binary ( ) == False ) : return ( eid )
 if 18 - 18: Oo0Ooo % OOooOOo + IiII
 o000oOo0oooO0 = lisp_address ( eid . afi , "" , 0 , 0 )
 o000oOo0oooO0 . copy_address ( eid )
 o000oOo0oooO0 . mask_len = 0
 if 28 - 28: OOooOOo . OoO0O00 / o0oOOo0O0Ooo + II111iiii / iIii1I11I1II1 * II111iiii
 Ooooo = ddt_entry . print_eid_tuple ( )
 ooO00Oo0o0OOo = ddt_entry . eid
 if 47 - 47: OoooooooOO / i11iIiiIii + II111iiii / i11iIiiIii % i1IIi
 if 31 - 31: o0oOOo0O0Ooo + IiII * OOooOOo
 if 26 - 26: Ii1I % O0 - i1IIi % iII111i * OoO0O00
 if 60 - 60: I1ii11iIi11i * iII111i / OoOoOO00 . o0oOOo0O0Ooo / iIii1I11I1II1
 if 94 - 94: OoO0O00 . ooOoO0o
 eid , ooO00Oo0o0OOo , o000oOo0oooO0 = cache . walk_cache ( lisp_neg_prefix_walk ,
 ( eid , ooO00Oo0o0OOo , o000oOo0oooO0 ) )
 if 25 - 25: I1Ii111 % OOooOOo
 if 82 - 82: Ii1I
 if 17 - 17: iII111i . i1IIi . i1IIi
 if 76 - 76: OoooooooOO % IiII
 o000oOo0oooO0 . mask_address ( o000oOo0oooO0 . mask_len )
 if 81 - 81: iII111i . OOooOOo * i1IIi
 lprint ( ( "Least specific prefix computed from ddt-cache for EID {} " + "using auth-prefix {} is {}" ) . format ( green ( eid . print_address ( ) , False ) ,
 # O0
 Ooooo , o000oOo0oooO0 . print_prefix ( ) ) )
 return ( o000oOo0oooO0 )
 if 65 - 65: iIii1I11I1II1
 if 83 - 83: iIii1I11I1II1 - iII111i
 if 91 - 91: i11iIiiIii . I11i . i1IIi - Ii1I
 if 37 - 37: O0
 if 68 - 68: OoO0O00 - I1Ii111
 if 66 - 66: Oo0Ooo % II111iiii / Ii1I . iII111i . OOooOOo . OOooOOo
 if 63 - 63: I11i / I11i + IiII - i1IIi / Ii1I
 if 100 - 100: OoO0O00 * iIii1I11I1II1
def lisp_ms_compute_neg_prefix ( eid , group ) :
 o000oOo0oooO0 = lisp_address ( eid . afi , "" , 0 , 0 )
 o000oOo0oooO0 . copy_address ( eid )
 o000oOo0oooO0 . mask_len = 0
 ooO0O0oo = lisp_address ( group . afi , "" , 0 , 0 )
 ooO0O0oo . copy_address ( group )
 ooO0O0oo . mask_len = 0
 ooO00Oo0o0OOo = None
 if 20 - 20: iII111i - OOooOOo - I11i * oO0o
 if 88 - 88: I1IiiI - I1Ii111
 if 50 - 50: OoOoOO00
 if 67 - 67: OOooOOo
 if 90 - 90: Oo0Ooo % iII111i % Oo0Ooo * I11i / OoOoOO00
 if ( group . is_null ( ) ) :
  ii111I = lisp_ddt_cache . lookup_cache ( eid , False )
  if ( ii111I == None ) :
   o000oOo0oooO0 . mask_len = o000oOo0oooO0 . host_mask_len ( )
   ooO0O0oo . mask_len = ooO0O0oo . host_mask_len ( )
   return ( [ o000oOo0oooO0 , ooO0O0oo , LISP_DDT_ACTION_NOT_AUTH ] )
   if 49 - 49: I1ii11iIi11i * II111iiii
  o0ooO00 = lisp_sites_by_eid
  if ( ii111I . is_auth_prefix ( ) ) : ooO00Oo0o0OOo = ii111I . eid
 else :
  ii111I = lisp_ddt_cache . lookup_cache ( group , False )
  if ( ii111I == None ) :
   o000oOo0oooO0 . mask_len = o000oOo0oooO0 . host_mask_len ( )
   ooO0O0oo . mask_len = ooO0O0oo . host_mask_len ( )
   return ( [ o000oOo0oooO0 , ooO0O0oo , LISP_DDT_ACTION_NOT_AUTH ] )
   if 40 - 40: I11i . iII111i + OoOoOO00 % I1ii11iIi11i
  if ( ii111I . is_auth_prefix ( ) ) : ooO00Oo0o0OOo = ii111I . group
  if 79 - 79: I1Ii111 - OOooOOo * I1ii11iIi11i + i11iIiiIii . iII111i
  group , ooO00Oo0o0OOo , ooO0O0oo = lisp_sites_by_eid . walk_cache ( lisp_neg_prefix_walk , ( group , ooO00Oo0o0OOo , ooO0O0oo ) )
  if 3 - 3: Oo0Ooo
  if 81 - 81: OoO0O00 / OoO0O00 . I1ii11iIi11i
  ooO0O0oo . mask_address ( ooO0O0oo . mask_len )
  if 100 - 100: iIii1I11I1II1 % II111iiii - I1ii11iIi11i . iIii1I11I1II1 + IiII % iIii1I11I1II1
  lprint ( ( "Least specific prefix computed from site-cache for " + "group EID {} using auth-prefix {} is {}" ) . format ( group . print_address ( ) , ooO00Oo0o0OOo . print_prefix ( ) if ( ooO00Oo0o0OOo != None ) else "'not found'" ,
  # OOooOOo / i1IIi % Oo0Ooo
  # OOooOOo / I1ii11iIi11i % oO0o / o0oOOo0O0Ooo
  # I1Ii111 * I1ii11iIi11i + I1Ii111 . OoO0O00
 ooO0O0oo . print_prefix ( ) ) )
  if 79 - 79: I1ii11iIi11i * I1IiiI % Ii1I
  o0ooO00 = ii111I . source_cache
  if 61 - 61: oO0o + I11i * OoooooooOO * I11i % OoOoOO00
  if 88 - 88: iII111i * iIii1I11I1II1 + IiII / II111iiii * i11iIiiIii
  if 22 - 22: OOooOOo + Oo0Ooo . I1Ii111 + i11iIiiIii / ooOoO0o - II111iiii
  if 93 - 93: O0 + i1IIi - O0
  if 13 - 13: i11iIiiIii
 OOoooO = LISP_DDT_ACTION_DELEGATION_HOLE if ( ooO00Oo0o0OOo != None ) else LISP_DDT_ACTION_NOT_AUTH
 if 14 - 14: I11i . OoOoOO00 . OOooOOo - Oo0Ooo + I1Ii111 % ooOoO0o
 if 95 - 95: OoO0O00 * II111iiii + i1IIi
 if 22 - 22: Ii1I / ooOoO0o % I11i + OoO0O00 . ooOoO0o
 if 61 - 61: O0 - iIii1I11I1II1 * Oo0Ooo . Ii1I + O0
 if 20 - 20: ooOoO0o / ooOoO0o - Ii1I - ooOoO0o
 if 93 - 93: O0 * OoOoOO00 * iIii1I11I1II1
 eid , ooO00Oo0o0OOo , o000oOo0oooO0 = o0ooO00 . walk_cache ( lisp_neg_prefix_walk ,
 ( eid , ooO00Oo0o0OOo , o000oOo0oooO0 ) )
 if 3 - 3: I1ii11iIi11i - O0
 if 46 - 46: iII111i
 if 99 - 99: oO0o
 if 85 - 85: I1Ii111 * iIii1I11I1II1 . OoOoOO00
 o000oOo0oooO0 . mask_address ( o000oOo0oooO0 . mask_len )
 if 20 - 20: I11i * O0 - OoooooooOO * OOooOOo % oO0o * iII111i
 lprint ( ( "Least specific prefix computed from site-cache for EID {} " + "using auth-prefix {} is {}" ) . format ( green ( eid . print_address ( ) , False ) ,
 # OoO0O00 - i11iIiiIii % OoooooooOO . OOooOOo . OoOoOO00
 # iIii1I11I1II1 * Ii1I - OoooooooOO / oO0o - OoO0O00 / i11iIiiIii
 ooO00Oo0o0OOo . print_prefix ( ) if ( ooO00Oo0o0OOo != None ) else "'not found'" , o000oOo0oooO0 . print_prefix ( ) ) )
 if 24 - 24: I1IiiI
 if 63 - 63: I11i - iIii1I11I1II1 * Ii1I + OoooooooOO . i11iIiiIii
 return ( [ o000oOo0oooO0 , ooO0O0oo , OOoooO ] )
 if 94 - 94: OoO0O00 . oO0o . OoOoOO00 * i11iIiiIii
 if 96 - 96: i1IIi . OoO0O00 . OoO0O00 - o0oOOo0O0Ooo - Ii1I
 if 33 - 33: ooOoO0o + I1ii11iIi11i - I1IiiI . iII111i / OoO0O00
 if 91 - 91: OOooOOo - OoooooooOO . OoO0O00
 if 34 - 34: Ii1I . I1IiiI . i1IIi * I1ii11iIi11i
 if 77 - 77: ooOoO0o . II111iiii
 if 41 - 41: IiII
 if 27 - 27: IiII / IiII
def lisp_ms_send_map_referral ( lisp_sockets , map_request , ecm_source , port ,
 action , eid_prefix , group_prefix ) :
 if 91 - 91: Ii1I
 I1IiiIiIIi1Ii = map_request . target_eid
 iIiii1Ii1I = map_request . target_group
 iII = map_request . nonce
 if 93 - 93: OoO0O00 * OoO0O00 * I1ii11iIi11i * OoO0O00 * o0oOOo0O0Ooo
 if ( action == LISP_DDT_ACTION_MS_ACK ) : o0O0OOo0oo00 = 1440
 if 84 - 84: I1Ii111 * OoO0O00 - ooOoO0o - Oo0Ooo . OoO0O00 % oO0o
 if 98 - 98: OoO0O00 . i1IIi
 if 58 - 58: i1IIi * O0 + I1ii11iIi11i . IiII
 if 11 - 11: OOooOOo + iIii1I11I1II1 - ooOoO0o * OoO0O00 * i11iIiiIii
 oOo0ooOO0ooOo = lisp_map_referral ( )
 oOo0ooOO0ooOo . record_count = 1
 oOo0ooOO0ooOo . nonce = iII
 I1i1iI = oOo0ooOO0ooOo . encode ( )
 oOo0ooOO0ooOo . print_map_referral ( )
 if 45 - 45: I1ii11iIi11i + Oo0Ooo
 IiIi1iiII = False
 if 7 - 7: Oo0Ooo + ooOoO0o - I1Ii111 * iIii1I11I1II1
 if 6 - 6: ooOoO0o % I1Ii111 % ooOoO0o . Ii1I * Oo0Ooo . IiII
 if 100 - 100: i1IIi . Ii1I . o0oOOo0O0Ooo + Ii1I - i1IIi . I11i
 if 19 - 19: i11iIiiIii + I11i - IiII . iII111i * i1IIi
 if 66 - 66: ooOoO0o
 if 4 - 4: iII111i / iII111i * OOooOOo + o0oOOo0O0Ooo . I1Ii111 + II111iiii
 if ( action == LISP_DDT_ACTION_SITE_NOT_FOUND ) :
  eid_prefix , group_prefix , action = lisp_ms_compute_neg_prefix ( I1IiiIiIIi1Ii ,
 iIiii1Ii1I )
  o0O0OOo0oo00 = 15
  if 90 - 90: IiII * iII111i % OoOoOO00 . i11iIiiIii
 if ( action == LISP_DDT_ACTION_MS_NOT_REG ) : o0O0OOo0oo00 = 1
 if ( action == LISP_DDT_ACTION_MS_ACK ) : o0O0OOo0oo00 = 1440
 if ( action == LISP_DDT_ACTION_DELEGATION_HOLE ) : o0O0OOo0oo00 = 15
 if ( action == LISP_DDT_ACTION_NOT_AUTH ) : o0O0OOo0oo00 = 0
 if 5 - 5: O0 * i1IIi / IiII
 iI1I1 = False
 Oo0OO0O00o = 0
 ii111I = lisp_ddt_cache_lookup ( I1IiiIiIIi1Ii , iIiii1Ii1I , False )
 if ( ii111I != None ) :
  Oo0OO0O00o = len ( ii111I . delegation_set )
  iI1I1 = ii111I . is_ms_peer_entry ( )
  ii111I . map_referrals_sent += 1
  if 90 - 90: OoO0O00 + OOooOOo
  if 64 - 64: o0oOOo0O0Ooo + OoO0O00 % I1Ii111 * I11i * iII111i % I11i
  if 26 - 26: OoO0O00 - II111iiii - o0oOOo0O0Ooo
  if 50 - 50: OoooooooOO
  if 51 - 51: II111iiii - oO0o % OoooooooOO - II111iiii / O0 - OoooooooOO
 if ( action == LISP_DDT_ACTION_NOT_AUTH ) : IiIi1iiII = True
 if ( action in ( LISP_DDT_ACTION_MS_REFERRAL , LISP_DDT_ACTION_MS_ACK ) ) :
  IiIi1iiII = ( iI1I1 == False )
  if 21 - 21: iII111i * o0oOOo0O0Ooo
  if 85 - 85: I1ii11iIi11i . OoOoOO00 . i1IIi % OOooOOo * I11i . I1Ii111
  if 26 - 26: I1Ii111 + Oo0Ooo + II111iiii % OoOoOO00 % OOooOOo
  if 40 - 40: I1ii11iIi11i + i1IIi
  if 9 - 9: OOooOOo
 OOOoOooO = lisp_eid_record ( )
 OOOoOooO . rloc_count = Oo0OO0O00o
 OOOoOooO . authoritative = True
 OOOoOooO . action = action
 OOOoOooO . ddt_incomplete = IiIi1iiII
 OOOoOooO . eid = eid_prefix
 OOOoOooO . group = group_prefix
 OOOoOooO . record_ttl = o0O0OOo0oo00
 if 74 - 74: OoOoOO00 - OOooOOo % OoOoOO00
 I1i1iI += OOOoOooO . encode ( )
 OOOoOooO . print_record ( "  " , True )
 if 82 - 82: I11i % IiII + Oo0Ooo + iIii1I11I1II1 - I11i - I1IiiI
 if 65 - 65: IiII / O0 * II111iiii + oO0o
 if 52 - 52: o0oOOo0O0Ooo - OoOoOO00 * II111iiii / OoooooooOO
 if 44 - 44: OOooOOo - oO0o + o0oOOo0O0Ooo - i1IIi % o0oOOo0O0Ooo
 if ( Oo0OO0O00o != 0 ) :
  for ii1111IIiIi in ii111I . delegation_set :
   oO0oO = lisp_rloc_record ( )
   oO0oO . rloc = ii1111IIiIi . delegate_address
   oO0oO . priority = ii1111IIiIi . priority
   oO0oO . weight = ii1111IIiIi . weight
   oO0oO . mpriority = 255
   oO0oO . mweight = 0
   oO0oO . reach_bit = True
   I1i1iI += oO0oO . encode ( )
   oO0oO . print_record ( "    " )
   if 79 - 79: iII111i . iIii1I11I1II1
   if 42 - 42: i11iIiiIii / IiII . O0 / OOooOOo . iII111i * i1IIi
   if 83 - 83: iIii1I11I1II1 . II111iiii * Oo0Ooo . I1IiiI - I1IiiI - iIii1I11I1II1
   if 29 - 29: Oo0Ooo
   if 35 - 35: OoOoOO00 + II111iiii
   if 46 - 46: O0 / I1ii11iIi11i + OOooOOo - I1Ii111 + I1IiiI - ooOoO0o
   if 96 - 96: IiII + i1IIi - I11i * I11i - OoO0O00 % II111iiii
 if ( map_request . nonce != 0 ) : port = LISP_CTRL_PORT
 lisp_send_map_referral ( lisp_sockets , I1i1iI , ecm_source , port )
 return
 if 47 - 47: I1Ii111 . i11iIiiIii + oO0o . I1ii11iIi11i
 if 12 - 12: iIii1I11I1II1 % I1Ii111 * OoOoOO00 / OoooooooOO % OoooooooOO
 if 81 - 81: iIii1I11I1II1 - Oo0Ooo - ooOoO0o . OoO0O00 + I1ii11iIi11i
 if 84 - 84: iII111i . OOooOOo . iII111i * oO0o % Ii1I . oO0o
 if 86 - 86: iII111i * ooOoO0o / iIii1I11I1II1 + Ii1I . iII111i
 if 64 - 64: IiII - Oo0Ooo % iII111i % I11i
 if 42 - 42: Oo0Ooo . OoO0O00
 if 22 - 22: ooOoO0o - o0oOOo0O0Ooo + I11i / I1IiiI + OOooOOo
def lisp_send_negative_map_reply ( sockets , eid , group , nonce , dest , port , ttl ,
 xtr_id , pubsub ) :
 if 10 - 10: oO0o / I1IiiI
 lprint ( "Build negative Map-Reply EID-prefix {}, nonce 0x{} to ITR {}" . format ( lisp_print_eid_tuple ( eid , group ) , lisp_hex_string ( nonce ) ,
 # o0oOOo0O0Ooo - OOooOOo / O0 * o0oOOo0O0Ooo * I1Ii111 / i11iIiiIii
 red ( dest . print_address ( ) , False ) ) )
 if 29 - 29: ooOoO0o
 OOoooO = LISP_NATIVE_FORWARD_ACTION if group . is_null ( ) else LISP_DROP_ACTION
 if 61 - 61: OoooooooOO / I1ii11iIi11i . I1ii11iIi11i * i11iIiiIii % II111iiii
 if 1 - 1: i11iIiiIii / OoOoOO00 - I1ii11iIi11i . I1IiiI / I1Ii111 % iIii1I11I1II1
 if 87 - 87: OoOoOO00 - II111iiii + Oo0Ooo
 if 44 - 44: i1IIi + I1ii11iIi11i / iIii1I11I1II1
 if 47 - 47: I1Ii111
 if ( lisp_get_eid_hash ( eid ) != None ) :
  OOoooO = LISP_SEND_MAP_REQUEST_ACTION
  if 41 - 41: IiII
  if 25 - 25: I11i % iIii1I11I1II1
 I1i1iI = lisp_build_map_reply ( eid , group , [ ] , nonce , OOoooO , ttl , False ,
 None , False , False )
 if 27 - 27: iIii1I11I1II1 . O0 . oO0o
 if 21 - 21: oO0o * I1ii11iIi11i
 if 44 - 44: o0oOOo0O0Ooo * IiII - o0oOOo0O0Ooo
 if 90 - 90: i1IIi + I1ii11iIi11i * oO0o % i11iIiiIii - OoO0O00
 if ( pubsub ) :
  lisp_process_pubsub ( sockets , I1i1iI , eid , dest , port , nonce , ttl ,
 xtr_id )
 else :
  lisp_send_map_reply ( sockets , I1i1iI , dest , port )
  if 12 - 12: OoO0O00 . I1ii11iIi11i - I1IiiI % OOooOOo
 return
 if 9 - 9: Ii1I / O0
 if 95 - 95: iII111i / I11i
 if 86 - 86: O0 / II111iiii . Oo0Ooo / Oo0Ooo * II111iiii
 if 22 - 22: Ii1I
 if 81 - 81: iIii1I11I1II1 . ooOoO0o % I11i
 if 64 - 64: I1Ii111 . Oo0Ooo * o0oOOo0O0Ooo
 if 32 - 32: oO0o . I1Ii111 * I1Ii111
def lisp_retransmit_ddt_map_request ( mr ) :
 i1IiI1 = mr . mr_source . print_address ( )
 oO0O000oOOOOo = mr . print_eid_tuple ( )
 iII = mr . nonce
 if 47 - 47: II111iiii
 if 81 - 81: I11i / Oo0Ooo % Ii1I % OoO0O00
 if 87 - 87: O0 % II111iiii
 if 42 - 42: I1IiiI . i1IIi
 if 98 - 98: o0oOOo0O0Ooo % I11i . Oo0Ooo * Oo0Ooo % iII111i
 if ( mr . last_request_sent_to ) :
  IIi11 = mr . last_request_sent_to . print_address ( )
  o0oOiiii1 = lisp_referral_cache_lookup ( mr . last_cached_prefix [ 0 ] ,
 mr . last_cached_prefix [ 1 ] , True )
  if ( o0oOiiii1 and o0oOiiii1 . referral_set . has_key ( IIi11 ) ) :
   o0oOiiii1 . referral_set [ IIi11 ] . no_responses += 1
   if 13 - 13: II111iiii
   if 36 - 36: iII111i - oO0o / Oo0Ooo / O0 . OoO0O00 . i1IIi
   if 19 - 19: O0 . OoooooooOO % iIii1I11I1II1 - Ii1I . Ii1I + I1IiiI
   if 98 - 98: oO0o . Oo0Ooo
   if 9 - 9: I1Ii111 % IiII - i11iIiiIii - OOooOOo % iII111i % OoooooooOO
   if 6 - 6: i1IIi - II111iiii * OoOoOO00 + oO0o
   if 6 - 6: I1IiiI - ooOoO0o + I1IiiI + OoO0O00 - i11iIiiIii % ooOoO0o
 if ( mr . retry_count == LISP_MAX_MAP_NOTIFY_RETRIES ) :
  lprint ( "DDT Map-Request retry limit reached for EID {}, nonce 0x{}" . format ( green ( oO0O000oOOOOo , False ) , lisp_hex_string ( iII ) ) )
  if 64 - 64: OoooooooOO + OOooOOo
  mr . dequeue_map_request ( )
  return
  if 36 - 36: I1IiiI - Ii1I / I1ii11iIi11i + Oo0Ooo % I1ii11iIi11i
  if 86 - 86: iIii1I11I1II1 * OoO0O00
 mr . retry_count += 1
 if 82 - 82: I1IiiI - OoO0O00 % o0oOOo0O0Ooo
 I11iiIi1i1 = green ( i1IiI1 , False )
 I1 = green ( oO0O000oOOOOo , False )
 lprint ( "Retransmit DDT {} from {}ITR {} EIDs: {} -> {}, nonce 0x{}" . format ( bold ( "Map-Request" , False ) , "P" if mr . from_pitr else "" ,
 # OoOoOO00 % OOooOOo . OoooooooOO + i1IIi % oO0o
 red ( mr . itr . print_address ( ) , False ) , I11iiIi1i1 , I1 ,
 lisp_hex_string ( iII ) ) )
 if 88 - 88: iIii1I11I1II1 + I1Ii111 + I11i / o0oOOo0O0Ooo + IiII * Oo0Ooo
 if 51 - 51: I11i % ooOoO0o % oO0o * OoooooooOO
 if 98 - 98: IiII * OOooOOo % OOooOOo % I1Ii111
 if 37 - 37: I11i + O0 + II111iiii % IiII
 lisp_send_ddt_map_request ( mr , False )
 if 98 - 98: IiII - o0oOOo0O0Ooo
 if 55 - 55: I1ii11iIi11i
 if 20 - 20: iII111i - Ii1I - i1IIi
 if 97 - 97: oO0o % iII111i - OOooOOo . OoooooooOO
 mr . retransmit_timer = threading . Timer ( LISP_DDT_MAP_REQUEST_INTERVAL ,
 lisp_retransmit_ddt_map_request , [ mr ] )
 mr . retransmit_timer . start ( )
 return
 if 94 - 94: Oo0Ooo
 if 10 - 10: i11iIiiIii / I1ii11iIi11i . i1IIi + i1IIi * iII111i
 if 64 - 64: II111iiii % I1ii11iIi11i . OoOoOO00 . iIii1I11I1II1 / I1ii11iIi11i
 if 43 - 43: OoooooooOO * I1IiiI
 if 2 - 2: OOooOOo / oO0o + I1ii11iIi11i + i11iIiiIii % iIii1I11I1II1 . I1ii11iIi11i
 if 100 - 100: Oo0Ooo * ooOoO0o + Ii1I / iII111i * o0oOOo0O0Ooo
 if 26 - 26: I1Ii111 * OoOoOO00
 if 38 - 38: II111iiii
def lisp_get_referral_node ( referral , source_eid , dest_eid ) :
 if 50 - 50: OoOoOO00 . IiII - OOooOOo
 if 46 - 46: iIii1I11I1II1
 if 97 - 97: O0 * OOooOOo - o0oOOo0O0Ooo % o0oOOo0O0Ooo * II111iiii % I11i
 if 65 - 65: iIii1I11I1II1 / OOooOOo
 i1i1Ii1I1 = [ ]
 for iiiiiIIiI in referral . referral_set . values ( ) :
  if ( iiiiiIIiI . updown == False ) : continue
  if ( len ( i1i1Ii1I1 ) == 0 or i1i1Ii1I1 [ 0 ] . priority == iiiiiIIiI . priority ) :
   i1i1Ii1I1 . append ( iiiiiIIiI )
  elif ( i1i1Ii1I1 [ 0 ] . priority > iiiiiIIiI . priority ) :
   i1i1Ii1I1 = [ ]
   i1i1Ii1I1 . append ( iiiiiIIiI )
   if 91 - 91: OoOoOO00 * i11iIiiIii
   if 75 - 75: OoO0O00
   if 12 - 12: OoOoOO00 * o0oOOo0O0Ooo % ooOoO0o % I1IiiI . I1IiiI
 OOoooOoO00o = len ( i1i1Ii1I1 )
 if ( OOoooOoO00o == 0 ) : return ( None )
 if 86 - 86: Oo0Ooo % OoooooooOO
 oooOo00 = dest_eid . hash_address ( source_eid )
 oooOo00 = oooOo00 % OOoooOoO00o
 return ( i1i1Ii1I1 [ oooOo00 ] )
 if 61 - 61: OOooOOo . i11iIiiIii
 if 33 - 33: o0oOOo0O0Ooo - OoooooooOO
 if 30 - 30: i1IIi + II111iiii + OoOoOO00 + I1ii11iIi11i % ooOoO0o % OOooOOo
 if 40 - 40: I1IiiI % I1IiiI - i11iIiiIii % OoOoOO00
 if 17 - 17: ooOoO0o - i1IIi
 if 73 - 73: iIii1I11I1II1 - I1Ii111 % Oo0Ooo . O0
 if 16 - 16: OoO0O00 / Oo0Ooo / IiII . Oo0Ooo - OoooooooOO
def lisp_send_ddt_map_request ( mr , send_to_root ) :
 iIo00O0oO0OOOOo = mr . lisp_sockets
 iII = mr . nonce
 i1o0oOoooOoo0 = mr . itr
 o00OOoOOoo0OO = mr . mr_source
 I1I1iII1i = mr . print_eid_tuple ( )
 if 92 - 92: Ii1I
 if 85 - 85: OoO0O00 + OoO0O00 % I1Ii111 + I1IiiI - II111iiii
 if 40 - 40: OoOoOO00
 if 57 - 57: I1IiiI + IiII . OoOoOO00 * iIii1I11I1II1 % OoooooooOO
 if 21 - 21: I11i
 if ( mr . send_count == 8 ) :
  lprint ( "Giving up on map-request-queue entry {}, nonce 0x{}" . format ( green ( I1I1iII1i , False ) , lisp_hex_string ( iII ) ) )
  if 36 - 36: IiII + OoO0O00
  mr . dequeue_map_request ( )
  return
  if 66 - 66: iIii1I11I1II1 / oO0o
  if 36 - 36: o0oOOo0O0Ooo % I1ii11iIi11i - Oo0Ooo % o0oOOo0O0Ooo
  if 18 - 18: oO0o / i1IIi * I11i
  if 71 - 71: OoooooooOO - i11iIiiIii * i1IIi % OOooOOo - oO0o / o0oOOo0O0Ooo
  if 77 - 77: iIii1I11I1II1 / OoOoOO00
  if 59 - 59: Oo0Ooo % OOooOOo
 if ( send_to_root ) :
  i1i1I = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  Iiii = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  mr . tried_root = True
  lprint ( "Jumping up to root for EID {}" . format ( green ( I1I1iII1i , False ) ) )
 else :
  i1i1I = mr . eid
  Iiii = mr . group
  if 40 - 40: IiII
  if 42 - 42: O0 / II111iiii
  if 88 - 88: Oo0Ooo
  if 20 - 20: OoooooooOO * i1IIi * IiII / OoooooooOO - Oo0Ooo / i11iIiiIii
  if 28 - 28: iIii1I11I1II1 % OOooOOo * I1IiiI
 iiIIIIi1 = lisp_referral_cache_lookup ( i1i1I , Iiii , False )
 if ( iiIIIIi1 == None ) :
  lprint ( "No referral cache entry found" )
  lisp_send_negative_map_reply ( iIo00O0oO0OOOOo , i1i1I , Iiii ,
 iII , i1o0oOoooOoo0 , mr . sport , 15 , None , False )
  return
  if 9 - 9: OoooooooOO % I1IiiI - iIii1I11I1II1 / Oo0Ooo
  if 17 - 17: ooOoO0o
 IiiIiIIIi = iiIIIIi1 . print_eid_tuple ( )
 lprint ( "Found referral cache entry {}, referral-type: {}" . format ( IiiIiIIIi ,
 iiIIIIi1 . print_referral_type ( ) ) )
 if 73 - 73: oO0o - o0oOOo0O0Ooo
 iiiiiIIiI = lisp_get_referral_node ( iiIIIIi1 , o00OOoOOoo0OO , mr . eid )
 if ( iiiiiIIiI == None ) :
  lprint ( "No reachable referral-nodes found" )
  mr . dequeue_map_request ( )
  lisp_send_negative_map_reply ( iIo00O0oO0OOOOo , iiIIIIi1 . eid ,
 iiIIIIi1 . group , iII , i1o0oOoooOoo0 , mr . sport , 1 , None , False )
  return
  if 50 - 50: iIii1I11I1II1 - i11iIiiIii / iII111i + ooOoO0o / OOooOOo
  if 80 - 80: IiII / OoooooooOO
 lprint ( "Send DDT Map-Request to {} {} for EID {}, nonce 0x{}" . format ( iiiiiIIiI . referral_address . print_address ( ) ,
 # I1IiiI / IiII + I1IiiI / O0 / I11i
 iiIIIIi1 . print_referral_type ( ) , green ( I1I1iII1i , False ) ,
 lisp_hex_string ( iII ) ) )
 if 10 - 10: I1Ii111 * i1IIi
 if 48 - 48: Oo0Ooo % i1IIi / iII111i . O0
 if 27 - 27: I11i + iIii1I11I1II1 - i11iIiiIii
 if 81 - 81: I11i + oO0o * iIii1I11I1II1 * IiII
 I1iII1iiI = ( iiIIIIi1 . referral_type == LISP_DDT_ACTION_MS_REFERRAL or
 iiIIIIi1 . referral_type == LISP_DDT_ACTION_MS_ACK )
 lisp_send_ecm ( iIo00O0oO0OOOOo , mr . packet , o00OOoOOoo0OO , mr . sport , mr . eid ,
 iiiiiIIiI . referral_address , to_ms = I1iII1iiI , ddt = True )
 if 11 - 11: iIii1I11I1II1 / O0 * I1Ii111 . OoooooooOO % OoooooooOO * I1Ii111
 if 63 - 63: IiII * oO0o * iIii1I11I1II1
 if 18 - 18: II111iiii * o0oOOo0O0Ooo % i11iIiiIii . OoOoOO00
 if 40 - 40: oO0o - o0oOOo0O0Ooo * II111iiii
 mr . last_request_sent_to = iiiiiIIiI . referral_address
 mr . last_sent = lisp_get_timestamp ( )
 mr . send_count += 1
 iiiiiIIiI . map_requests_sent += 1
 return
 if 4 - 4: O0
 if 9 - 9: Oo0Ooo . i1IIi - i1IIi + I1Ii111 * ooOoO0o . I1ii11iIi11i
 if 17 - 17: I11i * I1ii11iIi11i % I1IiiI + OoO0O00 + IiII
 if 90 - 90: OoooooooOO - I1IiiI / I1ii11iIi11i + oO0o - o0oOOo0O0Ooo
 if 84 - 84: OoOoOO00 + O0 % Oo0Ooo
 if 22 - 22: iIii1I11I1II1 % i11iIiiIii
 if 29 - 29: ooOoO0o - iII111i + IiII % Ii1I - oO0o - ooOoO0o
 if 43 - 43: oO0o
def lisp_mr_process_map_request ( lisp_sockets , packet , map_request , ecm_source ,
 sport , mr_source ) :
 if 22 - 22: I1Ii111 + i11iIiiIii
 I1IiiIiIIi1Ii = map_request . target_eid
 iIiii1Ii1I = map_request . target_group
 oO0O000oOOOOo = map_request . print_eid_tuple ( )
 i1IiI1 = mr_source . print_address ( )
 iII = map_request . nonce
 if 49 - 49: O0 % II111iiii . OOooOOo + iII111i + iIii1I11I1II1 / i11iIiiIii
 I11iiIi1i1 = green ( i1IiI1 , False )
 I1 = green ( oO0O000oOOOOo , False )
 lprint ( "Received Map-Request from {}ITR {} EIDs: {} -> {}, nonce 0x{}" . format ( "P" if map_request . pitr_bit else "" ,
 # I1IiiI * o0oOOo0O0Ooo / oO0o * OoO0O00 / i1IIi
 red ( ecm_source . print_address ( ) , False ) , I11iiIi1i1 , I1 ,
 lisp_hex_string ( iII ) ) )
 if 16 - 16: Ii1I / Ii1I
 if 95 - 95: I11i % OoO0O00
 if 69 - 69: OoOoOO00 % IiII / II111iiii
 if 82 - 82: I1Ii111 + O0 . I1IiiI / I1ii11iIi11i % II111iiii
 IiIiiiI11 = lisp_ddt_map_request ( lisp_sockets , packet , I1IiiIiIIi1Ii , iIiii1Ii1I , iII )
 IiIiiiI11 . packet = packet
 IiIiiiI11 . itr = ecm_source
 IiIiiiI11 . mr_source = mr_source
 IiIiiiI11 . sport = sport
 IiIiiiI11 . from_pitr = map_request . pitr_bit
 IiIiiiI11 . queue_map_request ( )
 if 63 - 63: ooOoO0o % OoooooooOO / Oo0Ooo % II111iiii
 lisp_send_ddt_map_request ( IiIiiiI11 , False )
 return
 if 88 - 88: O0 - i1IIi . II111iiii - O0 + O0 / I1ii11iIi11i
 if 9 - 9: iIii1I11I1II1
 if 57 - 57: i1IIi * OOooOOo
 if 35 - 35: I1Ii111 / Oo0Ooo * OoooooooOO / O0 / iIii1I11I1II1
 if 44 - 44: o0oOOo0O0Ooo / iIii1I11I1II1
 if 40 - 40: OoO0O00 / O0
 if 60 - 60: iIii1I11I1II1 / Oo0Ooo / oO0o + iII111i
def lisp_process_map_request ( lisp_sockets , packet , ecm_source , ecm_port ,
 mr_source , mr_port , ddt_request , ttl ) :
 if 66 - 66: iIii1I11I1II1 . O0 * IiII . ooOoO0o + i1IIi
 IIII11i1Ii = packet
 OOOo = lisp_map_request ( )
 packet = OOOo . decode ( packet , mr_source , mr_port )
 if ( packet == None ) :
  lprint ( "Could not decode Map-Request packet" )
  return
  if 53 - 53: iII111i + OoO0O00
  if 67 - 67: I1Ii111 - OoOoOO00 . i11iIiiIii - I1Ii111 . i11iIiiIii
 OOOo . print_map_request ( )
 if 25 - 25: I11i % I1Ii111 + Ii1I
 if 46 - 46: ooOoO0o + Oo0Ooo + oO0o / II111iiii . iIii1I11I1II1 * I1IiiI
 if 87 - 87: I11i + iIii1I11I1II1
 if 91 - 91: oO0o
 if ( OOOo . rloc_probe ) :
  lisp_process_rloc_probe_request ( lisp_sockets , OOOo ,
 mr_source , mr_port , ttl )
  return
  if 58 - 58: i11iIiiIii / Ii1I - OoooooooOO
  if 25 - 25: i1IIi * ooOoO0o % OOooOOo / I1IiiI
  if 75 - 75: i11iIiiIii
  if 38 - 38: iIii1I11I1II1
  if 80 - 80: OoO0O00
 if ( OOOo . smr_bit ) :
  lisp_process_smr ( OOOo )
  if 72 - 72: I11i * II111iiii
  if 82 - 82: I1Ii111 . OoO0O00 * II111iiii
  if 99 - 99: iIii1I11I1II1 / iII111i % i1IIi - II111iiii / OoO0O00
  if 33 - 33: OoooooooOO / i1IIi . Ii1I
  if 96 - 96: OoOoOO00 / Oo0Ooo . II111iiii / ooOoO0o
 if ( OOOo . smr_invoked_bit ) :
  lisp_process_smr_invoked_request ( OOOo )
  if 56 - 56: IiII - ooOoO0o % oO0o / Oo0Ooo * oO0o % O0
  if 71 - 71: iII111i / II111iiii - II111iiii / I1IiiI
  if 24 - 24: O0 . I1IiiI + IiII . IiII
  if 53 - 53: II111iiii + Ii1I * o0oOOo0O0Ooo
  if 47 - 47: Ii1I % OOooOOo . Oo0Ooo
 if ( lisp_i_am_etr ) :
  lisp_etr_process_map_request ( lisp_sockets , OOOo , mr_source ,
 mr_port , ttl )
  if 94 - 94: Ii1I - iIii1I11I1II1 + I1IiiI - iIii1I11I1II1 . o0oOOo0O0Ooo
  if 3 - 3: O0 / I11i + OoOoOO00 % IiII / i11iIiiIii
  if 25 - 25: II111iiii / I1ii11iIi11i % iIii1I11I1II1
  if 69 - 69: IiII
  if 36 - 36: I1IiiI / oO0o
 if ( lisp_i_am_ms ) :
  packet = IIII11i1Ii
  I1IiiIiIIi1Ii , iIiii1Ii1I , OooOO0O00 = lisp_ms_process_map_request ( lisp_sockets ,
 IIII11i1Ii , OOOo , mr_source , mr_port , ecm_source )
  if ( ddt_request ) :
   lisp_ms_send_map_referral ( lisp_sockets , OOOo , ecm_source ,
 ecm_port , OooOO0O00 , I1IiiIiIIi1Ii , iIiii1Ii1I )
   if 69 - 69: o0oOOo0O0Ooo * I1IiiI - I11i
  return
  if 11 - 11: OOooOOo * O0
  if 43 - 43: I1IiiI - i1IIi . i1IIi * II111iiii
  if 64 - 64: I1IiiI * iIii1I11I1II1 % I1Ii111
  if 22 - 22: OoooooooOO + I1Ii111 . o0oOOo0O0Ooo * Oo0Ooo
  if 61 - 61: iIii1I11I1II1
 if ( lisp_i_am_mr and not ddt_request ) :
  lisp_mr_process_map_request ( lisp_sockets , IIII11i1Ii , OOOo ,
 ecm_source , mr_port , mr_source )
  if 95 - 95: I1ii11iIi11i + IiII * Ii1I - IiII
  if 58 - 58: I1ii11iIi11i - oO0o % I11i * O0
  if 43 - 43: OoOoOO00 + O0
  if 71 - 71: ooOoO0o * I1IiiI / I1ii11iIi11i
  if 8 - 8: I1Ii111 / iIii1I11I1II1
 if ( lisp_i_am_ddt or ddt_request ) :
  packet = IIII11i1Ii
  lisp_ddt_process_map_request ( lisp_sockets , OOOo , ecm_source ,
 ecm_port )
  if 29 - 29: i11iIiiIii % i1IIi + oO0o . I1ii11iIi11i
 return
 if 51 - 51: OOooOOo + o0oOOo0O0Ooo . OOooOOo
 if 23 - 23: iIii1I11I1II1 + OoO0O00 / I1IiiI
 if 48 - 48: OoOoOO00 + I11i + oO0o . I1IiiI
 if 7 - 7: iII111i * i1IIi % OoOoOO00 % Ii1I . I1IiiI
 if 53 - 53: OOooOOo / I11i + OOooOOo / I1IiiI / OoO0O00
 if 12 - 12: i11iIiiIii % ooOoO0o / iII111i . IiII
 if 68 - 68: OOooOOo / iIii1I11I1II1 + I1IiiI . ooOoO0o * IiII
 if 72 - 72: I1Ii111
def lisp_store_mr_stats ( source , nonce ) :
 IiIiiiI11 = lisp_get_map_resolver ( source , None )
 if ( IiIiiiI11 == None ) : return
 if 51 - 51: OoOoOO00
 if 61 - 61: Oo0Ooo / i1IIi + I1Ii111 - OoooooooOO / O0
 if 25 - 25: I1ii11iIi11i * i11iIiiIii / i1IIi
 if 69 - 69: OOooOOo % ooOoO0o - i1IIi . Oo0Ooo
 IiIiiiI11 . neg_map_replies_received += 1
 IiIiiiI11 . last_reply = lisp_get_timestamp ( )
 if 35 - 35: iIii1I11I1II1 - I11i / iIii1I11I1II1 % ooOoO0o % I1IiiI
 if 46 - 46: oO0o
 if 5 - 5: i1IIi % o0oOOo0O0Ooo + OoOoOO00 - I11i . Ii1I
 if 33 - 33: II111iiii * o0oOOo0O0Ooo
 if ( ( IiIiiiI11 . neg_map_replies_received % 100 ) == 0 ) : IiIiiiI11 . total_rtt = 0
 if 8 - 8: I1ii11iIi11i % o0oOOo0O0Ooo - IiII
 if 91 - 91: iIii1I11I1II1 . OoO0O00 - I1ii11iIi11i + I11i / Oo0Ooo + OoO0O00
 if 35 - 35: ooOoO0o * iII111i % iII111i + OOooOOo
 if 66 - 66: iII111i - ooOoO0o * I1ii11iIi11i - Ii1I / OoooooooOO
 if ( IiIiiiI11 . last_nonce == nonce ) :
  IiIiiiI11 . total_rtt += ( time . time ( ) - IiIiiiI11 . last_used )
  IiIiiiI11 . last_nonce = 0
  if 86 - 86: I1IiiI % iII111i + Oo0Ooo + i1IIi % o0oOOo0O0Ooo
 if ( ( IiIiiiI11 . neg_map_replies_received % 10 ) == 0 ) : IiIiiiI11 . last_nonce = 0
 return
 if 85 - 85: Ii1I + I1Ii111 * I11i
 if 59 - 59: Oo0Ooo
 if 35 - 35: OoooooooOO + I1ii11iIi11i * OOooOOo
 if 75 - 75: Ii1I * Oo0Ooo % iIii1I11I1II1 . O0 % oO0o
 if 4 - 4: I1IiiI - i11iIiiIii / o0oOOo0O0Ooo
 if 54 - 54: i11iIiiIii + I1Ii111 . I1Ii111 * I1ii11iIi11i % I1Ii111 - OoooooooOO
 if 76 - 76: IiII + i1IIi + i11iIiiIii . oO0o
def lisp_process_map_reply ( lisp_sockets , packet , source , ttl ) :
 global lisp_map_cache
 if 23 - 23: ooOoO0o - OoO0O00 + oO0o . OOooOOo - I1IiiI
 i111II11i = lisp_map_reply ( )
 packet = i111II11i . decode ( packet )
 if ( packet == None ) :
  lprint ( "Could not decode Map-Reply packet" )
  return
  if 66 - 66: iII111i % iII111i
 i111II11i . print_map_reply ( )
 if 59 - 59: II111iiii . i1IIi % i1IIi
 if 40 - 40: I1Ii111 . II111iiii * o0oOOo0O0Ooo + I11i - i1IIi
 if 67 - 67: o0oOOo0O0Ooo - O0 - i1IIi . ooOoO0o . iII111i
 if 43 - 43: II111iiii . o0oOOo0O0Ooo + i11iIiiIii . O0 / O0 . II111iiii
 i1ii1111II1 = None
 for iiIii1I in range ( i111II11i . record_count ) :
  OOOoOooO = lisp_eid_record ( )
  packet = OOOoOooO . decode ( packet )
  if ( packet == None ) :
   lprint ( "Could not decode EID-record in Map-Reply packet" )
   return
   if 26 - 26: i1IIi % OoOoOO00 / i1IIi
  OOOoOooO . print_record ( "  " , False )
  if 41 - 41: oO0o % oO0o . iIii1I11I1II1 . o0oOOo0O0Ooo
  if 95 - 95: i1IIi . ooOoO0o . Oo0Ooo
  if 13 - 13: OOooOOo - Oo0Ooo % O0 . I1Ii111
  if 66 - 66: I1IiiI + I11i
  if 58 - 58: I1ii11iIi11i
  if ( OOOoOooO . rloc_count == 0 ) :
   lisp_store_mr_stats ( source , i111II11i . nonce )
   if 7 - 7: oO0o - I11i
   if 59 - 59: Ii1I / o0oOOo0O0Ooo / OoO0O00 + IiII + i11iIiiIii
  OO000000ooO0 = ( OOOoOooO . group . is_null ( ) == False )
  if 56 - 56: OOooOOo / i11iIiiIii - OoooooooOO . i1IIi
  if 70 - 70: oO0o / OoO0O00 % Oo0Ooo . Oo0Ooo
  if 51 - 51: I1IiiI + O0 / i1IIi / iIii1I11I1II1 % o0oOOo0O0Ooo % O0
  if 44 - 44: OoOoOO00 * ooOoO0o - Ii1I
  if 82 - 82: Ii1I - O0 * ooOoO0o . ooOoO0o
  if ( lisp_decent_configured ) :
   OOoooO = OOOoOooO . action
   if ( OO000000ooO0 and OOoooO == LISP_DROP_ACTION ) :
    if ( OOOoOooO . eid . is_local ( ) ) : continue
    if 32 - 32: o0oOOo0O0Ooo . OoooooooOO % OOooOOo
    if 2 - 2: OoOoOO00 + I1ii11iIi11i + oO0o
    if 27 - 27: OoooooooOO - Ii1I / OoooooooOO + OoO0O00
    if 58 - 58: OOooOOo * I11i . I1IiiI
    if 46 - 46: I11i + II111iiii * iII111i % ooOoO0o - I1IiiI
    if 73 - 73: I1ii11iIi11i * iIii1I11I1II1 . I1Ii111 - Ii1I
    if 11 - 11: I11i
  if ( OOOoOooO . eid . is_null ( ) ) : continue
  if 48 - 48: IiII / O0
  if 46 - 46: ooOoO0o + oO0o
  if 7 - 7: ooOoO0o * oO0o . i1IIi
  if 74 - 74: i1IIi * I11i + OoOoOO00 / OoO0O00 - oO0o / I11i
  if 90 - 90: IiII % I1ii11iIi11i % i1IIi
  if ( OO000000ooO0 ) :
   O0O = lisp_map_cache_lookup ( OOOoOooO . eid , OOOoOooO . group )
  else :
   O0O = lisp_map_cache . lookup_cache ( OOOoOooO . eid , True )
   if 34 - 34: I1IiiI * OoOoOO00
  OoOoo0 = ( O0O == None )
  if 88 - 88: O0
  if 12 - 12: Ii1I % OOooOOo % Oo0Ooo * I1Ii111
  if 96 - 96: iII111i + ooOoO0o
  if 100 - 100: OOooOOo . ooOoO0o + Ii1I + Ii1I
  OOoO000o00000 = [ ]
  for o0oIIi1 in range ( OOOoOooO . rloc_count ) :
   oO0oO = lisp_rloc_record ( )
   oO0oO . keys = i111II11i . keys
   packet = oO0oO . decode ( packet , i111II11i . nonce )
   if ( packet == None ) :
    lprint ( "Could not decode RLOC-record in Map-Reply packet" )
    return
    if 72 - 72: i1IIi * o0oOOo0O0Ooo
   oO0oO . print_record ( "    " )
   if 70 - 70: IiII % i1IIi / IiII - o0oOOo0O0Ooo . Oo0Ooo / O0
   oO0ooo0O = None
   if ( O0O ) : oO0ooo0O = O0O . get_rloc ( oO0oO . rloc )
   if ( oO0ooo0O ) :
    i11iII1Ii1ii111 = oO0ooo0O
   else :
    i11iII1Ii1ii111 = lisp_rloc ( )
    if 23 - 23: o0oOOo0O0Ooo * OoO0O00
    if 20 - 20: i11iIiiIii * I1ii11iIi11i * ooOoO0o % iIii1I11I1II1 + iII111i
    if 51 - 51: O0 - I11i . o0oOOo0O0Ooo + o0oOOo0O0Ooo / I1Ii111
    if 32 - 32: II111iiii - Oo0Ooo
    if 69 - 69: o0oOOo0O0Ooo * I1ii11iIi11i / o0oOOo0O0Ooo * OoooooooOO
    if 60 - 60: OoOoOO00 / i1IIi * Oo0Ooo / i1IIi
    if 86 - 86: OoOoOO00 . I11i
   OoO0o = i11iII1Ii1ii111 . store_rloc_from_record ( oO0oO , i111II11i . nonce ,
 source )
   i11iII1Ii1ii111 . echo_nonce_capable = i111II11i . echo_nonce_capable
   if 97 - 97: Ii1I
   if ( i11iII1Ii1ii111 . echo_nonce_capable ) :
    oO00o = i11iII1Ii1ii111 . rloc . print_address_no_iid ( )
    if ( lisp_get_echo_nonce ( None , oO00o ) == None ) :
     lisp_echo_nonce ( oO00o )
     if 24 - 24: I1IiiI * i11iIiiIii
     if 83 - 83: OoOoOO00 * I1ii11iIi11i
     if 64 - 64: II111iiii * i1IIi - ooOoO0o
     if 4 - 4: ooOoO0o . OoO0O00 . OoO0O00 % ooOoO0o * Oo0Ooo - I1IiiI
     if 8 - 8: I1IiiI - I1Ii111 - OoooooooOO * Oo0Ooo * Ii1I
     if 11 - 11: I1IiiI
     if 43 - 43: I11i
     if 78 - 78: Ii1I % Oo0Ooo / OoO0O00 . iIii1I11I1II1 . II111iiii
     if 67 - 67: oO0o % I1Ii111
     if 72 - 72: I1IiiI . i11iIiiIii . OoOoOO00 + I1IiiI - I1Ii111 + iII111i
   if ( i111II11i . rloc_probe and oO0oO . probe_bit ) :
    if ( i11iII1Ii1ii111 . rloc . afi == source . afi ) :
     lisp_process_rloc_probe_reply ( i11iII1Ii1ii111 . rloc , source , OoO0o ,
 i111II11i . nonce , i111II11i . hop_count , ttl )
     if 15 - 15: I1IiiI
     if 88 - 88: IiII / I1ii11iIi11i % I11i + i11iIiiIii * O0 . I1Ii111
     if 69 - 69: Oo0Ooo - OOooOOo / I1IiiI . i11iIiiIii * OoO0O00
     if 45 - 45: I1Ii111 + OOooOOo
     if 78 - 78: OoOoOO00 . Oo0Ooo % I11i
     if 7 - 7: I1ii11iIi11i % Ii1I . OoooooooOO - iII111i
   OOoO000o00000 . append ( i11iII1Ii1ii111 )
   if 18 - 18: O0 * OoooooooOO % IiII - iIii1I11I1II1 % IiII * o0oOOo0O0Ooo
   if 13 - 13: OoO0O00 + i11iIiiIii + O0 / ooOoO0o % iIii1I11I1II1
   if 75 - 75: oO0o / i1IIi / Ii1I * Oo0Ooo
   if 75 - 75: Oo0Ooo / OoooooooOO
   if ( lisp_data_plane_security and i11iII1Ii1ii111 . rloc_recent_rekey ( ) ) :
    i1ii1111II1 = i11iII1Ii1ii111
    if 98 - 98: II111iiii - I1Ii111 . ooOoO0o * iII111i
    if 49 - 49: I1ii11iIi11i / OoooooooOO - I11i
    if 76 - 76: i1IIi . OoO0O00 . O0 / OOooOOo - iII111i
    if 60 - 60: I1IiiI
    if 3 - 3: II111iiii % IiII % I1IiiI - I1IiiI . I1Ii111 - OoOoOO00
    if 18 - 18: O0
    if 26 - 26: i1IIi - iIii1I11I1II1
    if 8 - 8: I1Ii111
    if 86 - 86: i1IIi
    if 26 - 26: o0oOOo0O0Ooo % I1Ii111 / Oo0Ooo
    if 68 - 68: II111iiii / Oo0Ooo / Oo0Ooo
  if ( i111II11i . rloc_probe == False and lisp_nat_traversal ) :
   i1I1i1iI1iI1 = [ ]
   i1111i = [ ]
   for i11iII1Ii1ii111 in OOoO000o00000 :
    if 15 - 15: OoooooooOO - i1IIi - Oo0Ooo - IiII
    if 80 - 80: II111iiii - I1ii11iIi11i / iIii1I11I1II1 % Oo0Ooo . Ii1I
    if 33 - 33: OOooOOo + I1ii11iIi11i + I1Ii111 * I11i / OoO0O00 + o0oOOo0O0Ooo
    if 46 - 46: iII111i
    if 56 - 56: Oo0Ooo / II111iiii
    if ( i11iII1Ii1ii111 . rloc . is_private_address ( ) ) :
     i11iII1Ii1ii111 . priority = 1
     i11iII1Ii1ii111 . state = LISP_RLOC_UNREACH_STATE
     i1I1i1iI1iI1 . append ( i11iII1Ii1ii111 )
     i1111i . append ( i11iII1Ii1ii111 . rloc . print_address_no_iid ( ) )
     continue
     if 61 - 61: Ii1I - i1IIi / ooOoO0o - Oo0Ooo / IiII % Oo0Ooo
     if 53 - 53: OoooooooOO + iII111i % II111iiii * IiII
     if 10 - 10: OoOoOO00 % I11i
     if 46 - 46: i1IIi % IiII
     if 45 - 45: I1ii11iIi11i / I1ii11iIi11i - OoO0O00
     if 54 - 54: Ii1I + I1IiiI * OoOoOO00 + oO0o
    if ( i11iII1Ii1ii111 . priority == 254 and lisp_i_am_rtr == False ) :
     i1I1i1iI1iI1 . append ( i11iII1Ii1ii111 )
     i1111i . append ( i11iII1Ii1ii111 . rloc . print_address_no_iid ( ) )
     if 10 - 10: Ii1I - I1IiiI / IiII / iII111i - I1Ii111 - o0oOOo0O0Ooo
    if ( i11iII1Ii1ii111 . priority != 254 and lisp_i_am_rtr ) :
     i1I1i1iI1iI1 . append ( i11iII1Ii1ii111 )
     i1111i . append ( i11iII1Ii1ii111 . rloc . print_address_no_iid ( ) )
     if 75 - 75: OOooOOo . ooOoO0o
     if 32 - 32: i1IIi / I11i + iIii1I11I1II1 . OOooOOo
     if 67 - 67: iII111i - OoO0O00 % I1ii11iIi11i * Oo0Ooo
   if ( i1111i != [ ] ) :
    OOoO000o00000 = i1I1i1iI1iI1
    lprint ( "NAT-traversal optimized RLOC-set: {}" . format ( i1111i ) )
    if 51 - 51: I1IiiI + O0
    if 4 - 4: ooOoO0o / OoO0O00 * iIii1I11I1II1 * iIii1I11I1II1
    if 33 - 33: iII111i . iIii1I11I1II1 - Ii1I
    if 85 - 85: OoOoOO00
    if 57 - 57: Oo0Ooo - II111iiii - I1ii11iIi11i * oO0o
    if 41 - 41: I11i / ooOoO0o + IiII % OoooooooOO
    if 72 - 72: Ii1I
  i1I1i1iI1iI1 = [ ]
  for i11iII1Ii1ii111 in OOoO000o00000 :
   if ( i11iII1Ii1ii111 . json != None ) : continue
   i1I1i1iI1iI1 . append ( i11iII1Ii1ii111 )
   if 22 - 22: o0oOOo0O0Ooo / OoO0O00 + OoOoOO00 + Ii1I . II111iiii * I11i
  if ( i1I1i1iI1iI1 != [ ] ) :
   oOOOOOo = len ( OOoO000o00000 ) - len ( i1I1i1iI1iI1 )
   lprint ( "Pruning {} no-address RLOC-records for map-cache" . format ( oOOOOOo ) )
   if 85 - 85: i11iIiiIii / I11i
   OOoO000o00000 = i1I1i1iI1iI1
   if 28 - 28: i11iIiiIii + IiII / I11i . Ii1I / OoO0O00
   if 100 - 100: o0oOOo0O0Ooo - I11i . o0oOOo0O0Ooo
   if 90 - 90: OoOoOO00 / II111iiii / I11i * I11i - iIii1I11I1II1
   if 87 - 87: IiII
   if 92 - 92: OoO0O00 / IiII - ooOoO0o
   if 45 - 45: iII111i - I11i * ooOoO0o * OOooOOo / I1Ii111 * iII111i
   if 33 - 33: iIii1I11I1II1 % I1ii11iIi11i - OOooOOo % iIii1I11I1II1 + I11i / i11iIiiIii
   if 64 - 64: I11i * ooOoO0o / OoooooooOO
  if ( i111II11i . rloc_probe and O0O != None ) : OOoO000o00000 = O0O . rloc_set
  if 38 - 38: iIii1I11I1II1 . OoO0O00 * OoOoOO00 + OoOoOO00 + ooOoO0o
  if 44 - 44: I1ii11iIi11i * OOooOOo % OoO0O00 . I1IiiI % Ii1I + II111iiii
  if 100 - 100: oO0o - II111iiii . o0oOOo0O0Ooo
  if 63 - 63: OoOoOO00 % IiII . iII111i
  if 44 - 44: I1IiiI
  i1IiiI1iI = OoOoo0
  if ( O0O and OOoO000o00000 != O0O . rloc_set ) :
   O0O . delete_rlocs_from_rloc_probe_list ( )
   i1IiiI1iI = True
   if 83 - 83: IiII + OOooOOo . OOooOOo
   if 44 - 44: OOooOOo
   if 11 - 11: i11iIiiIii % Oo0Ooo % II111iiii . IiII % OoOoOO00
   if 10 - 10: Ii1I
   if 68 - 68: Oo0Ooo % ooOoO0o + i11iIiiIii / oO0o / II111iiii
  OOOooo000O = O0O . uptime if ( O0O ) else None
  O0O = lisp_mapping ( OOOoOooO . eid , OOOoOooO . group , OOoO000o00000 )
  O0O . mapping_source = source
  O0O . map_cache_ttl = OOOoOooO . store_ttl ( )
  O0O . action = OOOoOooO . action
  O0O . add_cache ( i1IiiI1iI )
  if 67 - 67: i1IIi * i11iIiiIii * I1IiiI
  i1111I = "Add"
  if ( OOOooo000O ) :
   O0O . uptime = OOOooo000O
   i1111I = "Replace"
   if 30 - 30: OoO0O00 + I1IiiI
   if 4 - 4: I11i
  lprint ( "{} {} map-cache with {} RLOCs" . format ( i1111I ,
 green ( O0O . print_eid_tuple ( ) , False ) , len ( OOoO000o00000 ) ) )
  if 67 - 67: ooOoO0o . I1Ii111 . Oo0Ooo . Ii1I + iIii1I11I1II1 / OoooooooOO
  if 93 - 93: ooOoO0o * OoO0O00 - I1Ii111 / I1ii11iIi11i
  if 60 - 60: OoO0O00 / oO0o . I1IiiI + OoOoOO00 + I1ii11iIi11i % Ii1I
  if 70 - 70: i1IIi * II111iiii * I1IiiI
  if 7 - 7: OoooooooOO + II111iiii % o0oOOo0O0Ooo * O0 . OoO0O00 * OoooooooOO
  if ( lisp_ipc_dp_socket and i1ii1111II1 != None ) :
   lisp_write_ipc_keys ( i1ii1111II1 )
   if 20 - 20: Oo0Ooo % OOooOOo
   if 8 - 8: OOooOOo
   if 92 - 92: iII111i / OOooOOo . IiII / I11i + o0oOOo0O0Ooo
   if 99 - 99: II111iiii
   if 70 - 70: O0 % I1ii11iIi11i
   if 28 - 28: IiII - i1IIi - I1Ii111 % Ii1I - IiII
   if 73 - 73: iIii1I11I1II1 . iIii1I11I1II1 + oO0o % i11iIiiIii . IiII
  if ( OoOoo0 ) :
   I1iI1iiii = bold ( "RLOC-probe" , False )
   for i11iII1Ii1ii111 in O0O . best_rloc_set :
    oO00o = red ( i11iII1Ii1ii111 . rloc . print_address_no_iid ( ) , False )
    lprint ( "Trigger {} to {}" . format ( I1iI1iiii , oO00o ) )
    lisp_send_map_request ( lisp_sockets , 0 , O0O . eid , O0O . group , i11iII1Ii1ii111 )
    if 72 - 72: ooOoO0o
    if 56 - 56: IiII % ooOoO0o + I1IiiI % I11i - OOooOOo
    if 82 - 82: OoooooooOO . i1IIi . OoO0O00 . OoO0O00
 return
 if 31 - 31: iIii1I11I1II1
 if 64 - 64: ooOoO0o
 if 30 - 30: OoO0O00 + o0oOOo0O0Ooo / iIii1I11I1II1
 if 69 - 69: IiII - OoooooooOO + iII111i + iII111i - Ii1I
 if 27 - 27: I1ii11iIi11i % Oo0Ooo * iIii1I11I1II1 * O0 / I11i * Oo0Ooo
 if 97 - 97: IiII % Oo0Ooo % OoOoOO00
 if 87 - 87: i11iIiiIii . oO0o * I1IiiI * I1Ii111
 if 57 - 57: iIii1I11I1II1 / i11iIiiIii / IiII + I1ii11iIi11i % I1IiiI
def lisp_compute_auth ( packet , map_register , password ) :
 if ( map_register . alg_id == LISP_NONE_ALG_ID ) : return ( packet )
 if 80 - 80: iIii1I11I1II1
 packet = map_register . zero_auth ( packet )
 oooOo00 = lisp_hash_me ( packet , map_register . alg_id , password , False )
 if 23 - 23: II111iiii . ooOoO0o % I1Ii111
 if 39 - 39: OoooooooOO
 if 10 - 10: Oo0Ooo * iII111i
 if 78 - 78: Oo0Ooo / i11iIiiIii - I1IiiI
 map_register . auth_data = oooOo00
 packet = map_register . encode_auth ( packet )
 return ( packet )
 if 51 - 51: ooOoO0o / Oo0Ooo - I1Ii111 - iII111i
 if 68 - 68: I1ii11iIi11i - iIii1I11I1II1 * OoooooooOO
 if 44 - 44: OoooooooOO + I1Ii111 + OoO0O00
 if 15 - 15: iIii1I11I1II1 % i1IIi + iII111i
 if 48 - 48: o0oOOo0O0Ooo / oO0o
 if 61 - 61: I1IiiI + iII111i * Ii1I % I1Ii111 . Ii1I
 if 83 - 83: i11iIiiIii * OoOoOO00 * i11iIiiIii % II111iiii . i11iIiiIii * I11i
def lisp_hash_me ( packet , alg_id , password , do_hex ) :
 if ( alg_id == LISP_NONE_ALG_ID ) : return ( True )
 if 67 - 67: i1IIi / i1IIi + IiII . oO0o
 if ( alg_id == LISP_SHA_1_96_ALG_ID ) :
  OoOO0 = hashlib . sha1
  if 75 - 75: oO0o * OoO0O00 * I11i + oO0o + O0 . I1Ii111
 if ( alg_id == LISP_SHA_256_128_ALG_ID ) :
  OoOO0 = hashlib . sha256
  if 8 - 8: I1ii11iIi11i / i1IIi - I1ii11iIi11i + Ii1I + OoO0O00 - I11i
  if 79 - 79: OoooooooOO - I1Ii111 * I1IiiI . I1Ii111 - iIii1I11I1II1
 if ( do_hex ) :
  oooOo00 = hmac . new ( password , packet , OoOO0 ) . hexdigest ( )
 else :
  oooOo00 = hmac . new ( password , packet , OoOO0 ) . digest ( )
  if 27 - 27: OoOoOO00 % OoOoOO00 % II111iiii
 return ( oooOo00 )
 if 45 - 45: iIii1I11I1II1 . o0oOOo0O0Ooo % I1IiiI
 if 10 - 10: I1IiiI / i1IIi * o0oOOo0O0Ooo + Oo0Ooo - OoOoOO00 % iII111i
 if 88 - 88: Ii1I % Ii1I
 if 29 - 29: OOooOOo % I1ii11iIi11i
 if 57 - 57: I1ii11iIi11i - OoOoOO00 + IiII
 if 58 - 58: OOooOOo % I1IiiI / oO0o . ooOoO0o . OoO0O00 / IiII
 if 72 - 72: ooOoO0o + ooOoO0o + o0oOOo0O0Ooo - o0oOOo0O0Ooo % Ii1I
 if 52 - 52: I11i % i1IIi . I1ii11iIi11i
def lisp_verify_auth ( packet , alg_id , auth_data , password ) :
 if ( alg_id == LISP_NONE_ALG_ID ) : return ( True )
 if 62 - 62: ooOoO0o - I1ii11iIi11i
 oooOo00 = lisp_hash_me ( packet , alg_id , password , True )
 oOOoO0oOOO = ( oooOo00 == auth_data )
 if 58 - 58: OOooOOo
 if 51 - 51: iII111i + ooOoO0o / IiII * I1ii11iIi11i % I11i
 if 56 - 56: Ii1I % I1ii11iIi11i . i11iIiiIii - i11iIiiIii
 if 75 - 75: OOooOOo % I1ii11iIi11i
 if ( oOOoO0oOOO == False ) :
  lprint ( "Hashed value: {} does not match packet value: {}" . format ( oooOo00 , auth_data ) )
  if 40 - 40: I1IiiI / I1IiiI
  if 26 - 26: i11iIiiIii % OoO0O00 % Ii1I - ooOoO0o
 return ( oOOoO0oOOO )
 if 2 - 2: II111iiii . o0oOOo0O0Ooo * OoooooooOO + OoooooooOO
 if 18 - 18: II111iiii * OOooOOo * OoO0O00 * iIii1I11I1II1 % o0oOOo0O0Ooo / IiII
 if 95 - 95: I1ii11iIi11i + I1IiiI . OoooooooOO
 if 22 - 22: I1Ii111 / I1Ii111 / OOooOOo + OoOoOO00 % I1Ii111 / Ii1I
 if 14 - 14: o0oOOo0O0Ooo % i11iIiiIii + i11iIiiIii - I1ii11iIi11i % I1ii11iIi11i
 if 26 - 26: oO0o + OoooooooOO % o0oOOo0O0Ooo
 if 96 - 96: ooOoO0o * OoOoOO00 - II111iiii
def lisp_retransmit_map_notify ( map_notify ) :
 Oo0o0OoOoOo0 = map_notify . etr
 OoO0o = map_notify . etr_port
 if 40 - 40: oO0o * OOooOOo + Ii1I + I11i * Ii1I + OoooooooOO
 if 77 - 77: OOooOOo + ooOoO0o / O0
 if 16 - 16: ooOoO0o + Oo0Ooo * Oo0Ooo . I11i - IiII
 if 49 - 49: ooOoO0o . Ii1I
 if 75 - 75: OOooOOo / II111iiii - Oo0Ooo + I1Ii111
 if ( map_notify . retry_count == LISP_MAX_MAP_NOTIFY_RETRIES ) :
  lprint ( "Map-Notify with nonce 0x{} retry limit reached for ETR {}" . format ( map_notify . nonce_key , red ( Oo0o0OoOoOo0 . print_address ( ) , False ) ) )
  if 42 - 42: OoooooooOO * II111iiii + Ii1I % OoO0O00 / I1Ii111
  if 11 - 11: ooOoO0o / Oo0Ooo + i1IIi / IiII
  i1i11ii1 = map_notify . nonce_key
  if ( lisp_map_notify_queue . has_key ( i1i11ii1 ) ) :
   map_notify . retransmit_timer . cancel ( )
   lprint ( "Dequeue Map-Notify from retransmit queue, key is: {}" . format ( i1i11ii1 ) )
   if 4 - 4: iII111i - Oo0Ooo
   try :
    lisp_map_notify_queue . pop ( i1i11ii1 )
   except :
    lprint ( "Key not found in Map-Notify queue" )
    if 100 - 100: OOooOOo . i1IIi
    if 15 - 15: O0 % Oo0Ooo % o0oOOo0O0Ooo . ooOoO0o * iII111i % O0
  return
  if 31 - 31: i1IIi . Ii1I - OoooooooOO * I11i * ooOoO0o % oO0o
  if 61 - 61: I1Ii111 . Ii1I * I1ii11iIi11i
 iIo00O0oO0OOOOo = map_notify . lisp_sockets
 map_notify . retry_count += 1
 if 59 - 59: OoOoOO00 + Oo0Ooo . I1ii11iIi11i - Ii1I
 lprint ( "Retransmit {} with nonce 0x{} to xTR {}, retry {}" . format ( bold ( "Map-Notify" , False ) , map_notify . nonce_key ,
 # OOooOOo * Oo0Ooo * Ii1I
 red ( Oo0o0OoOoOo0 . print_address ( ) , False ) , map_notify . retry_count ) )
 if 94 - 94: OoooooooOO % iII111i
 lisp_send_map_notify ( iIo00O0oO0OOOOo , map_notify . packet , Oo0o0OoOoOo0 , OoO0o )
 if ( map_notify . site ) : map_notify . site . map_notifies_sent += 1
 if 48 - 48: iIii1I11I1II1
 if 25 - 25: i1IIi % o0oOOo0O0Ooo . iII111i / OoooooooOO + i1IIi
 if 76 - 76: Oo0Ooo / OOooOOo + ooOoO0o % OoooooooOO - Oo0Ooo - I11i
 if 36 - 36: OoO0O00 . Oo0Ooo * I1ii11iIi11i
 map_notify . retransmit_timer = threading . Timer ( LISP_MAP_NOTIFY_INTERVAL ,
 lisp_retransmit_map_notify , [ map_notify ] )
 map_notify . retransmit_timer . start ( )
 return
 if 16 - 16: IiII + OOooOOo
 if 33 - 33: ooOoO0o . i11iIiiIii + OOooOOo
 if 77 - 77: OoooooooOO * Ii1I * iIii1I11I1II1 + IiII
 if 53 - 53: IiII + I1Ii111 + oO0o
 if 31 - 31: OOooOOo + OoOoOO00 * OOooOOo + OoOoOO00 / o0oOOo0O0Ooo . iIii1I11I1II1
 if 1 - 1: I1Ii111 * i11iIiiIii % I1Ii111 - OoO0O00 + I1Ii111 / Oo0Ooo
 if 3 - 3: OOooOOo - i11iIiiIii / I1Ii111 . OOooOOo - OoO0O00
def lisp_send_merged_map_notify ( lisp_sockets , parent , map_register ,
 eid_record ) :
 if 60 - 60: OoOoOO00 / i1IIi . Ii1I - OoO0O00 - OoooooooOO
 if 39 - 39: I1IiiI + i1IIi * OoO0O00 % I11i
 if 41 - 41: I1ii11iIi11i * IiII
 if 16 - 16: I1Ii111 % iIii1I11I1II1 / I1IiiI * OoOoOO00 / IiII / OoOoOO00
 eid_record . rloc_count = len ( parent . registered_rlocs )
 iiIi1 = eid_record . encode ( )
 eid_record . print_record ( "Merged Map-Notify " , False )
 if 1 - 1: i11iIiiIii % I1Ii111 + I1ii11iIi11i
 if 17 - 17: Oo0Ooo
 if 59 - 59: OoO0O00 * o0oOOo0O0Ooo . I11i
 if 32 - 32: I1ii11iIi11i
 for iiIiIIIIi11II in parent . registered_rlocs :
  oO0oO = lisp_rloc_record ( )
  oO0oO . store_rloc_entry ( iiIiIIIIi11II )
  iiIi1 += oO0oO . encode ( )
  oO0oO . print_record ( "  " )
  del ( oO0oO )
  if 37 - 37: iIii1I11I1II1
  if 64 - 64: II111iiii * oO0o % I1Ii111 + i1IIi
  if 57 - 57: OoOoOO00 + OoOoOO00
  if 24 - 24: i1IIi . OoOoOO00 / I1Ii111 + O0
  if 86 - 86: Ii1I * OoOoOO00 % I1ii11iIi11i + OOooOOo
 for iiIiIIIIi11II in parent . registered_rlocs :
  Oo0o0OoOoOo0 = iiIiIIIIi11II . rloc
  o0o00ooo0O = lisp_map_notify ( lisp_sockets )
  o0o00ooo0O . record_count = 1
  iI11i = map_register . key_id
  o0o00ooo0O . key_id = iI11i
  o0o00ooo0O . alg_id = map_register . alg_id
  o0o00ooo0O . auth_len = map_register . auth_len
  o0o00ooo0O . nonce = map_register . nonce
  o0o00ooo0O . nonce_key = lisp_hex_string ( o0o00ooo0O . nonce )
  o0o00ooo0O . etr . copy_address ( Oo0o0OoOoOo0 )
  o0o00ooo0O . etr_port = map_register . sport
  o0o00ooo0O . site = parent . site
  I1i1iI = o0o00ooo0O . encode ( iiIi1 , parent . site . auth_key [ iI11i ] )
  o0o00ooo0O . print_notify ( )
  if 38 - 38: I1IiiI / I1ii11iIi11i - I1Ii111 / II111iiii
  if 13 - 13: iIii1I11I1II1 * oO0o . IiII / O0
  if 98 - 98: Oo0Ooo / IiII % Oo0Ooo
  if 95 - 95: I1ii11iIi11i * o0oOOo0O0Ooo
  i1i11ii1 = o0o00ooo0O . nonce_key
  if ( lisp_map_notify_queue . has_key ( i1i11ii1 ) ) :
   Oo0 = lisp_map_notify_queue [ i1i11ii1 ]
   Oo0 . retransmit_timer . cancel ( )
   del ( Oo0 )
   if 60 - 60: I1ii11iIi11i - I1IiiI % OOooOOo + Ii1I - ooOoO0o % OoOoOO00
  lisp_map_notify_queue [ i1i11ii1 ] = o0o00ooo0O
  if 94 - 94: OoOoOO00 - i1IIi
  if 65 - 65: OoO0O00 / i11iIiiIii + I1ii11iIi11i + OoOoOO00
  if 82 - 82: Ii1I * OOooOOo % ooOoO0o / OoO0O00 - Oo0Ooo . I1Ii111
  if 90 - 90: I11i * i11iIiiIii % i1IIi + I1Ii111 / OoO0O00
  lprint ( "Send merged Map-Notify to ETR {}" . format ( red ( Oo0o0OoOoOo0 . print_address ( ) , False ) ) )
  if 15 - 15: Oo0Ooo + oO0o . I11i % OoO0O00
  lisp_send ( lisp_sockets , Oo0o0OoOoOo0 , LISP_CTRL_PORT , I1i1iI )
  if 13 - 13: I1ii11iIi11i / ooOoO0o * I1Ii111
  parent . site . map_notifies_sent += 1
  if 45 - 45: I1ii11iIi11i - I11i
  if 60 - 60: OOooOOo - OOooOOo * OoOoOO00 / Ii1I % iII111i % Oo0Ooo
  if 75 - 75: iIii1I11I1II1 - IiII - I1Ii111
  if 4 - 4: i11iIiiIii % OoooooooOO . i11iIiiIii
  o0o00ooo0O . retransmit_timer = threading . Timer ( LISP_MAP_NOTIFY_INTERVAL ,
 lisp_retransmit_map_notify , [ o0o00ooo0O ] )
  o0o00ooo0O . retransmit_timer . start ( )
  if 61 - 61: iIii1I11I1II1 . Oo0Ooo . i1IIi
 return
 if 45 - 45: I1Ii111
 if 49 - 49: i1IIi * iII111i - iIii1I11I1II1 % I11i * O0 / OoOoOO00
 if 48 - 48: IiII
 if 69 - 69: o0oOOo0O0Ooo % i11iIiiIii - OOooOOo - o0oOOo0O0Ooo
 if 98 - 98: o0oOOo0O0Ooo * OoO0O00 . OoooooooOO
 if 40 - 40: I1Ii111 + Oo0Ooo + I1Ii111
 if 57 - 57: I1Ii111 / II111iiii % iII111i
def lisp_build_map_notify ( lisp_sockets , eid_records , eid_list , record_count ,
 source , port , nonce , key_id , alg_id , auth_len , site , map_register_ack ) :
 if 32 - 32: IiII - OOooOOo + i11iIiiIii + I1IiiI . iII111i
 i1i11ii1 = lisp_hex_string ( nonce ) + source . print_address ( )
 if 75 - 75: o0oOOo0O0Ooo % o0oOOo0O0Ooo . I1IiiI / OoO0O00
 if 22 - 22: Oo0Ooo / iIii1I11I1II1 + o0oOOo0O0Ooo
 if 16 - 16: II111iiii . Ii1I + I1Ii111 % i1IIi / i11iIiiIii + OOooOOo
 if 43 - 43: I1IiiI . Oo0Ooo + i1IIi + I11i / OoO0O00
 if 66 - 66: i11iIiiIii
 if 83 - 83: I1Ii111 / iIii1I11I1II1 - oO0o
 lisp_remove_eid_from_map_notify_queue ( eid_list )
 if ( lisp_map_notify_queue . has_key ( i1i11ii1 ) ) :
  o0o00ooo0O = lisp_map_notify_queue [ i1i11ii1 ]
  I11iiIi1i1 = red ( source . print_address_no_iid ( ) , False )
  lprint ( "Map-Notify with nonce 0x{} pending for xTR {}" . format ( lisp_hex_string ( o0o00ooo0O . nonce ) , I11iiIi1i1 ) )
  if 3 - 3: OOooOOo - Oo0Ooo * I1IiiI - OoO0O00 / OOooOOo + IiII
  return
  if 83 - 83: i1IIi * i1IIi - II111iiii / OoooooooOO . Ii1I + I1Ii111
  if 10 - 10: I11i
 o0o00ooo0O = lisp_map_notify ( lisp_sockets )
 o0o00ooo0O . record_count = record_count
 key_id = key_id
 o0o00ooo0O . key_id = key_id
 o0o00ooo0O . alg_id = alg_id
 o0o00ooo0O . auth_len = auth_len
 o0o00ooo0O . nonce = nonce
 o0o00ooo0O . nonce_key = lisp_hex_string ( nonce )
 o0o00ooo0O . etr . copy_address ( source )
 o0o00ooo0O . etr_port = port
 o0o00ooo0O . site = site
 o0o00ooo0O . eid_list = eid_list
 if 24 - 24: Ii1I
 if 30 - 30: II111iiii / Ii1I - I11i - OoO0O00
 if 25 - 25: I11i % i1IIi / I11i * i11iIiiIii
 if 71 - 71: IiII % I11i - OoooooooOO + I1IiiI / Oo0Ooo % I11i
 if ( map_register_ack == False ) :
  i1i11ii1 = o0o00ooo0O . nonce_key
  lisp_map_notify_queue [ i1i11ii1 ] = o0o00ooo0O
  if 6 - 6: i1IIi * i11iIiiIii + ooOoO0o - IiII
  if 97 - 97: iIii1I11I1II1 * i1IIi * II111iiii - OOooOOo - Oo0Ooo - iIii1I11I1II1
 if ( map_register_ack ) :
  lprint ( "Send Map-Notify to ack Map-Register" )
 else :
  lprint ( "Send Map-Notify for RLOC-set change" )
  if 26 - 26: ooOoO0o + Oo0Ooo
  if 24 - 24: I1IiiI
  if 43 - 43: OoO0O00
  if 51 - 51: OoooooooOO % IiII % Oo0Ooo
  if 50 - 50: I1IiiI - i11iIiiIii / I1ii11iIi11i . Ii1I - iIii1I11I1II1
 I1i1iI = o0o00ooo0O . encode ( eid_records , site . auth_key [ key_id ] )
 o0o00ooo0O . print_notify ( )
 if 91 - 91: I1IiiI . I1Ii111 + II111iiii . Oo0Ooo
 if ( map_register_ack == False ) :
  OOOoOooO = lisp_eid_record ( )
  OOOoOooO . decode ( eid_records )
  OOOoOooO . print_record ( "  " , False )
  if 95 - 95: iII111i
  if 77 - 77: I1IiiI * II111iiii * iIii1I11I1II1
  if 19 - 19: OOooOOo * o0oOOo0O0Ooo
  if 64 - 64: I11i % ooOoO0o / OOooOOo / iII111i
  if 80 - 80: i1IIi
 lisp_send_map_notify ( lisp_sockets , I1i1iI , o0o00ooo0O . etr , port )
 site . map_notifies_sent += 1
 if 74 - 74: I1ii11iIi11i . OoO0O00 + i11iIiiIii
 if ( map_register_ack ) : return
 if 19 - 19: i1IIi / I1IiiI + IiII . iII111i
 if 68 - 68: iII111i
 if 29 - 29: II111iiii / II111iiii % OoO0O00 % Oo0Ooo . II111iiii
 if 33 - 33: OoooooooOO . OoO0O00 % OoooooooOO
 if 9 - 9: IiII * O0 + OOooOOo . II111iiii
 if 14 - 14: iIii1I11I1II1 + i11iIiiIii + o0oOOo0O0Ooo + o0oOOo0O0Ooo - IiII / I1Ii111
 o0o00ooo0O . retransmit_timer = threading . Timer ( LISP_MAP_NOTIFY_INTERVAL ,
 lisp_retransmit_map_notify , [ o0o00ooo0O ] )
 o0o00ooo0O . retransmit_timer . start ( )
 return
 if 70 - 70: OoooooooOO + I1IiiI / OOooOOo
 if 19 - 19: I1Ii111 + i1IIi % OoooooooOO + i1IIi
 if 16 - 16: I1Ii111 + II111iiii + IiII
 if 34 - 34: iIii1I11I1II1 - II111iiii - ooOoO0o + oO0o
 if 46 - 46: ooOoO0o % II111iiii
 if 61 - 61: OoO0O00 . I1IiiI
 if 89 - 89: IiII
 if 73 - 73: II111iiii + ooOoO0o % OOooOOo . oO0o / oO0o * i1IIi
def lisp_send_map_notify_ack ( lisp_sockets , eid_records , map_notify , ms ) :
 map_notify . map_notify_ack = True
 if 19 - 19: I1Ii111 + I11i
 if 21 - 21: OoOoOO00
 if 2 - 2: i1IIi . OOooOOo
 if 23 - 23: Ii1I - OOooOOo
 I1i1iI = map_notify . encode ( eid_records , ms . password )
 map_notify . print_notify ( )
 if 89 - 89: i11iIiiIii
 if 40 - 40: OoooooooOO % OoO0O00
 if 54 - 54: i1IIi * OOooOOo - oO0o * OoooooooOO + II111iiii . IiII
 if 90 - 90: O0 - II111iiii + I1IiiI . iII111i
 Oo0o0OoOoOo0 = ms . map_server
 lprint ( "Send Map-Notify-Ack to {}" . format (
 red ( Oo0o0OoOoOo0 . print_address ( ) , False ) ) )
 lisp_send ( lisp_sockets , Oo0o0OoOoOo0 , LISP_CTRL_PORT , I1i1iI )
 return
 if 3 - 3: o0oOOo0O0Ooo + i1IIi * Oo0Ooo
 if 6 - 6: OoO0O00 * OoooooooOO * iIii1I11I1II1
 if 87 - 87: iIii1I11I1II1 - ooOoO0o * iIii1I11I1II1
 if 79 - 79: ooOoO0o . oO0o + Ii1I * ooOoO0o + O0 . II111iiii
 if 8 - 8: IiII * OOooOOo + I11i + O0 * oO0o - oO0o
 if 19 - 19: OoO0O00 - ooOoO0o + I1ii11iIi11i / I1ii11iIi11i % I1Ii111 % iIii1I11I1II1
 if 5 - 5: OoooooooOO + ooOoO0o - II111iiii . i11iIiiIii / oO0o - ooOoO0o
 if 3 - 3: iII111i
def lisp_send_multicast_map_notify ( lisp_sockets , site_eid , eid_list , xtr ) :
 if 74 - 74: i11iIiiIii + OoooooooOO . OOooOOo
 o0o00ooo0O = lisp_map_notify ( lisp_sockets )
 o0o00ooo0O . record_count = 1
 o0o00ooo0O . nonce = lisp_get_control_nonce ( )
 o0o00ooo0O . nonce_key = lisp_hex_string ( o0o00ooo0O . nonce )
 o0o00ooo0O . etr . copy_address ( xtr )
 o0o00ooo0O . etr_port = LISP_CTRL_PORT
 o0o00ooo0O . eid_list = eid_list
 i1i11ii1 = o0o00ooo0O . nonce_key
 if 29 - 29: IiII % OoO0O00
 if 53 - 53: OoooooooOO - OoOoOO00 / IiII - I1Ii111
 if 16 - 16: iIii1I11I1II1 / OOooOOo + I1IiiI * II111iiii . OOooOOo
 if 68 - 68: IiII * IiII + oO0o / o0oOOo0O0Ooo
 if 41 - 41: OoOoOO00 - O0
 if 48 - 48: OoooooooOO % Ii1I * OoO0O00 / I1ii11iIi11i
 lisp_remove_eid_from_map_notify_queue ( o0o00ooo0O . eid_list )
 if ( lisp_map_notify_queue . has_key ( i1i11ii1 ) ) :
  o0o00ooo0O = lisp_map_notify_queue [ i1i11ii1 ]
  lprint ( "Map-Notify with nonce 0x{} pending for ITR {}" . format ( o0o00ooo0O . nonce , red ( xtr . print_address_no_iid ( ) , False ) ) )
  if 53 - 53: ooOoO0o + oO0o - II111iiii
  return
  if 92 - 92: Oo0Ooo - I11i . ooOoO0o % oO0o
  if 6 - 6: iIii1I11I1II1 + oO0o
  if 8 - 8: I1ii11iIi11i + o0oOOo0O0Ooo
  if 29 - 29: Ii1I . OOooOOo
  if 59 - 59: O0 . OoO0O00
 lisp_map_notify_queue [ i1i11ii1 ] = o0o00ooo0O
 if 10 - 10: I1Ii111 / OoooooooOO / OoO0O00 * ooOoO0o
 if 81 - 81: i1IIi % I11i * iIii1I11I1II1
 if 39 - 39: iIii1I11I1II1 / O0 . OoooooooOO - O0 . OoO0O00 . oO0o
 if 59 - 59: II111iiii * I1IiiI
 Iii1i11i = site_eid . rtrs_in_rloc_set ( )
 if ( Iii1i11i ) :
  if ( site_eid . is_rtr_in_rloc_set ( xtr ) ) : Iii1i11i = False
  if 78 - 78: Oo0Ooo / ooOoO0o % Oo0Ooo + OoO0O00 + Oo0Ooo
  if 27 - 27: OoooooooOO * OoooooooOO
  if 93 - 93: OoOoOO00 % Oo0Ooo . OoO0O00 / OoooooooOO
  if 59 - 59: OoO0O00 + O0 + i11iIiiIii / OoOoOO00 + iIii1I11I1II1 / OoOoOO00
  if 69 - 69: OoOoOO00 * Ii1I % ooOoO0o . OoOoOO00 / oO0o * I1Ii111
 OOOoOooO = lisp_eid_record ( )
 OOOoOooO . record_ttl = 1440
 OOOoOooO . eid . copy_address ( site_eid . eid )
 OOOoOooO . group . copy_address ( site_eid . group )
 OOOoOooO . rloc_count = 0
 for iiI1iI1 in site_eid . registered_rlocs :
  if ( Iii1i11i ^ iiI1iI1 . is_rtr ( ) ) : continue
  OOOoOooO . rloc_count += 1
  if 93 - 93: OoO0O00 % IiII % ooOoO0o . I1IiiI
 I1i1iI = OOOoOooO . encode ( )
 if 96 - 96: II111iiii
 if 73 - 73: II111iiii
 if 81 - 81: I1IiiI + OoO0O00
 if 22 - 22: OoO0O00 * OoOoOO00 * I11i * IiII . OoO0O00 . I1ii11iIi11i
 o0o00ooo0O . print_notify ( )
 OOOoOooO . print_record ( "  " , False )
 if 32 - 32: o0oOOo0O0Ooo - iII111i + i11iIiiIii / ooOoO0o . OoOoOO00 . IiII
 if 9 - 9: iIii1I11I1II1
 if 66 - 66: iIii1I11I1II1
 if 13 - 13: O0 / ooOoO0o
 for iiI1iI1 in site_eid . registered_rlocs :
  if ( Iii1i11i ^ iiI1iI1 . is_rtr ( ) ) : continue
  oO0oO = lisp_rloc_record ( )
  oO0oO . store_rloc_entry ( iiI1iI1 )
  I1i1iI += oO0oO . encode ( )
  oO0oO . print_record ( "    " )
  if 64 - 64: i11iIiiIii + I1IiiI / Oo0Ooo - iII111i
  if 26 - 26: I1ii11iIi11i
  if 67 - 67: I1Ii111 * iIii1I11I1II1 / O0 + OoO0O00 * iIii1I11I1II1 % II111iiii
  if 13 - 13: Ii1I / ooOoO0o / iII111i % II111iiii * I1IiiI * II111iiii
  if 40 - 40: Ii1I / i1IIi . iII111i
 I1i1iI = o0o00ooo0O . encode ( I1i1iI , "" )
 if ( I1i1iI == None ) : return
 if 65 - 65: iIii1I11I1II1 * O0 . II111iiii * o0oOOo0O0Ooo . I1ii11iIi11i * I1IiiI
 if 63 - 63: II111iiii . Oo0Ooo % iIii1I11I1II1
 if 85 - 85: I1IiiI + i1IIi % I1Ii111
 if 76 - 76: i11iIiiIii % i11iIiiIii
 lisp_send_map_notify ( lisp_sockets , I1i1iI , xtr , LISP_CTRL_PORT )
 if 33 - 33: OOooOOo . ooOoO0o / iIii1I11I1II1 * OOooOOo / oO0o
 if 75 - 75: Ii1I - OoOoOO00 . OOooOOo - o0oOOo0O0Ooo - I1ii11iIi11i
 if 69 - 69: O0 % I1ii11iIi11i
 if 77 - 77: iIii1I11I1II1 . OOooOOo
 o0o00ooo0O . retransmit_timer = threading . Timer ( LISP_MAP_NOTIFY_INTERVAL ,
 lisp_retransmit_map_notify , [ o0o00ooo0O ] )
 o0o00ooo0O . retransmit_timer . start ( )
 return
 if 64 - 64: OoOoOO00 - i1IIi * i1IIi / iII111i * OoOoOO00 * OoO0O00
 if 61 - 61: OOooOOo
 if 51 - 51: Oo0Ooo * OOooOOo / iII111i
 if 49 - 49: ooOoO0o . i1IIi % I1Ii111 . I1IiiI . I1ii11iIi11i + OoO0O00
 if 65 - 65: I1ii11iIi11i + Ii1I / i11iIiiIii * I1Ii111 + OoooooooOO
 if 7 - 7: Oo0Ooo % o0oOOo0O0Ooo
 if 40 - 40: oO0o * IiII
def lisp_queue_multicast_map_notify ( lisp_sockets , rle_list ) :
 iiIi111I1 = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
 if 39 - 39: IiII - o0oOOo0O0Ooo - I11i - Oo0Ooo - Ii1I
 for oooOoooo0Ooo0ooo0 in rle_list :
  i1III1i1iiiiI = lisp_site_eid_lookup ( oooOoooo0Ooo0ooo0 [ 0 ] , oooOoooo0Ooo0ooo0 [ 1 ] , True )
  if ( i1III1i1iiiiI == None ) : continue
  if 14 - 14: OOooOOo
  if 84 - 84: Ii1I + OoO0O00 + OOooOOo % ooOoO0o
  if 27 - 27: OoOoOO00 % I11i
  if 19 - 19: i1IIi - OoOoOO00
  if 26 - 26: IiII . i11iIiiIii % i11iIiiIii / IiII - Oo0Ooo / o0oOOo0O0Ooo
  if 7 - 7: I1IiiI / OOooOOo * iIii1I11I1II1 * Ii1I * i1IIi
  if 87 - 87: IiII * Oo0Ooo - OOooOOo * OoOoOO00
  OO0ooOOo0 = i1III1i1iiiiI . registered_rlocs
  if ( len ( OO0ooOOo0 ) == 0 ) :
   IiIiii1iIii = { }
   for ii1II11111i in i1III1i1iiiiI . individual_registrations . values ( ) :
    for iiI1iI1 in ii1II11111i . registered_rlocs :
     if ( iiI1iI1 . is_rtr ( ) == False ) : continue
     IiIiii1iIii [ iiI1iI1 . rloc . print_address ( ) ] = iiI1iI1
     if 14 - 14: IiII / I1ii11iIi11i * o0oOOo0O0Ooo % I11i / iII111i
     if 6 - 6: I1ii11iIi11i % iII111i / OoOoOO00 . ooOoO0o * I1ii11iIi11i
   OO0ooOOo0 = IiIiii1iIii . values ( )
   if 44 - 44: OoooooooOO + ooOoO0o / I1Ii111 + I1ii11iIi11i
   if 15 - 15: oO0o - i1IIi % iIii1I11I1II1 . i1IIi
   if 93 - 93: I11i / Ii1I - o0oOOo0O0Ooo % oO0o / OoO0O00 * I11i
   if 24 - 24: i1IIi
   if 21 - 21: II111iiii
   if 27 - 27: I1IiiI * i11iIiiIii
  OoiIiii111i = [ ]
  oo0o00OOO = False
  if ( i1III1i1iiiiI . eid . address == 0 and i1III1i1iiiiI . eid . mask_len == 0 ) :
   oOOO0O = [ ]
   i1ii1II1i11i = [ ] if len ( OO0ooOOo0 ) == 0 else OO0ooOOo0 [ 0 ] . rle . rle_nodes
   if 91 - 91: I1ii11iIi11i
   for OO in i1ii1II1i11i :
    OoiIiii111i . append ( OO . address )
    oOOO0O . append ( OO . address . print_address_no_iid ( ) )
    if 99 - 99: ooOoO0o % I1ii11iIi11i * i1IIi + OoOoOO00 - I11i
   lprint ( "Notify existing RLE-nodes {}" . format ( oOOO0O ) )
  else :
   if 85 - 85: OoOoOO00 . oO0o
   if 98 - 98: I1Ii111
   if 49 - 49: OoO0O00 / I1ii11iIi11i % IiII * II111iiii
   if 92 - 92: iIii1I11I1II1 . OoooooooOO . ooOoO0o / II111iiii
   if 30 - 30: i1IIi * Ii1I + Ii1I / I1Ii111
   for iiI1iI1 in OO0ooOOo0 :
    if ( iiI1iI1 . is_rtr ( ) ) : OoiIiii111i . append ( iiI1iI1 . rloc )
    if 84 - 84: I1IiiI - Oo0Ooo * OoO0O00 * oO0o
    if 13 - 13: I1Ii111 * i11iIiiIii % o0oOOo0O0Ooo + oO0o - iII111i
    if 32 - 32: I1Ii111 / I1ii11iIi11i - Ii1I % o0oOOo0O0Ooo * I1Ii111 % II111iiii
    if 33 - 33: ooOoO0o % I11i
    if 72 - 72: OoO0O00 % OoooooooOO / II111iiii * oO0o * I1Ii111
   oo0o00OOO = ( len ( OoiIiii111i ) != 0 )
   if ( oo0o00OOO == False ) :
    iI1II1i1I1Ii = lisp_site_eid_lookup ( oooOoooo0Ooo0ooo0 [ 0 ] , iiIi111I1 , False )
    if ( iI1II1i1I1Ii == None ) : continue
    if 98 - 98: OOooOOo * Ii1I + I1ii11iIi11i / iIii1I11I1II1 / OoOoOO00 + I1IiiI
    for iiI1iI1 in iI1II1i1I1Ii . registered_rlocs :
     if ( iiI1iI1 . rloc . is_null ( ) ) : continue
     OoiIiii111i . append ( iiI1iI1 . rloc )
     if 74 - 74: ooOoO0o . IiII . O0 * I1IiiI * oO0o
     if 6 - 6: O0 . Ii1I / Oo0Ooo * o0oOOo0O0Ooo
     if 1 - 1: i11iIiiIii
     if 30 - 30: I11i
     if 26 - 26: Oo0Ooo - II111iiii % ooOoO0o
     if 81 - 81: i11iIiiIii + I1ii11iIi11i * oO0o
   if ( len ( OoiIiii111i ) == 0 ) :
    lprint ( "No ITRs or RTRs found for {}, Map-Notify suppressed" . format ( green ( i1III1i1iiiiI . print_eid_tuple ( ) , False ) ) )
    if 86 - 86: OoO0O00 . ooOoO0o . o0oOOo0O0Ooo
    continue
    if 70 - 70: O0 % OoooooooOO - Ii1I * Oo0Ooo
    if 18 - 18: OOooOOo . I1IiiI + i1IIi . I1IiiI
    if 3 - 3: O0 * O0 + II111iiii + OoOoOO00 * I11i % Oo0Ooo
    if 19 - 19: oO0o % IiII % OoooooooOO % I1ii11iIi11i / OoO0O00
    if 6 - 6: O0 * I1Ii111 - II111iiii
    if 60 - 60: oO0o % oO0o
  for iiIiIIIIi11II in OoiIiii111i :
   lprint ( "Build Map-Notify to {}TR {} for {}" . format ( "R" if oo0o00OOO else "x" , red ( iiIiIIIIi11II . print_address_no_iid ( ) , False ) ,
   # I1IiiI / o0oOOo0O0Ooo * IiII / O0 . Ii1I
 green ( i1III1i1iiiiI . print_eid_tuple ( ) , False ) ) )
   if 25 - 25: I1Ii111 . II111iiii % OoOoOO00
   OO0Ii111Ii1Ii = [ i1III1i1iiiiI . print_eid_tuple ( ) ]
   lisp_send_multicast_map_notify ( lisp_sockets , i1III1i1iiiiI , OO0Ii111Ii1Ii , iiIiIIIIi11II )
   time . sleep ( .001 )
   if 34 - 34: IiII - ooOoO0o / oO0o - I11i / iII111i
   if 50 - 50: ooOoO0o
 return
 if 76 - 76: OOooOOo - iII111i + IiII
 if 48 - 48: I1IiiI - II111iiii
 if 15 - 15: O0
 if 54 - 54: iIii1I11I1II1
 if 54 - 54: iII111i + OOooOOo + OoO0O00
 if 6 - 6: oO0o - OoooooooOO * iIii1I11I1II1 * I1ii11iIi11i
 if 65 - 65: IiII + OoOoOO00
 if 93 - 93: Ii1I
def lisp_find_sig_in_rloc_set ( packet , rloc_count ) :
 for iiIii1I in range ( rloc_count ) :
  oO0oO = lisp_rloc_record ( )
  packet = oO0oO . decode ( packet , None )
  IiI1I = oO0oO . json
  if ( IiI1I == None ) : continue
  if 79 - 79: OOooOOo % OoO0O00 % I1IiiI . OoO0O00 / ooOoO0o
  try :
   IiI1I = json . loads ( IiI1I . json_string )
  except :
   lprint ( "Found corrupted JSON signature" )
   continue
   if 92 - 92: Oo0Ooo / iII111i + O0 * ooOoO0o * OOooOOo % Oo0Ooo
   if 97 - 97: oO0o / Ii1I
  if ( IiI1I . has_key ( "signature" ) == False ) : continue
  return ( oO0oO )
  if 70 - 70: iII111i / Oo0Ooo . OoOoOO00 - II111iiii * II111iiii % I1IiiI
 return ( None )
 if 34 - 34: I1Ii111 + OOooOOo * iII111i / ooOoO0o % i11iIiiIii
 if 91 - 91: IiII * Ii1I * OOooOOo
 if 17 - 17: o0oOOo0O0Ooo + Ii1I % I1ii11iIi11i + IiII % I1Ii111 + I1ii11iIi11i
 if 100 - 100: I11i * OoO0O00 - i1IIi + iII111i * Ii1I - OoooooooOO
 if 47 - 47: o0oOOo0O0Ooo / Ii1I - iII111i * OOooOOo / i11iIiiIii
 if 97 - 97: iIii1I11I1II1 + OoOoOO00 + OoOoOO00 * o0oOOo0O0Ooo
 if 14 - 14: II111iiii + I1ii11iIi11i * Oo0Ooo
 if 95 - 95: IiII + iII111i % I1IiiI
 if 18 - 18: Oo0Ooo
 if 8 - 8: O0 + iIii1I11I1II1 - O0
 if 67 - 67: O0
 if 22 - 22: I11i / i1IIi . II111iiii % ooOoO0o / I11i - Ii1I
 if 28 - 28: O0 - Oo0Ooo
 if 58 - 58: iIii1I11I1II1 - OoooooooOO - iII111i
 if 43 - 43: ooOoO0o / o0oOOo0O0Ooo
 if 56 - 56: II111iiii * I1ii11iIi11i * O0 . iII111i . I1ii11iIi11i % I1Ii111
 if 99 - 99: Oo0Ooo - OoO0O00 + OoooooooOO - I1Ii111 - I1ii11iIi11i % i1IIi
 if 49 - 49: IiII % OoooooooOO / Oo0Ooo - OoOoOO00 + o0oOOo0O0Ooo / Ii1I
 if 6 - 6: I11i % IiII
def lisp_get_eid_hash ( eid ) :
 i1I1II1iiII = None
 for Ii1I1i111 in lisp_eid_hashes :
  if 49 - 49: IiII % iII111i - O0 * o0oOOo0O0Ooo / OoooooooOO + OoOoOO00
  if 26 - 26: oO0o + i11iIiiIii . IiII + I1ii11iIi11i % IiII
  if 96 - 96: I11i / I1IiiI . i1IIi
  if 67 - 67: i11iIiiIii
  I1I111iIi = Ii1I1i111 . instance_id
  if ( I1I111iIi == - 1 ) : Ii1I1i111 . instance_id = eid . instance_id
  if 3 - 3: IiII
  iIoO0oOOoOoO = eid . is_more_specific ( Ii1I1i111 )
  Ii1I1i111 . instance_id = I1I111iIi
  if ( iIoO0oOOoOoO ) :
   i1I1II1iiII = 128 - Ii1I1i111 . mask_len
   break
   if 3 - 3: I1Ii111 + i11iIiiIii - I1IiiI . I1IiiI
   if 40 - 40: O0 * O0 / OOooOOo . OOooOOo . I1ii11iIi11i + O0
 if ( i1I1II1iiII == None ) : return ( None )
 if 96 - 96: iII111i * i11iIiiIii * I1Ii111
 i11i11II11i = eid . address
 O0oo0OOo00o0o = ""
 for iiIii1I in range ( 0 , i1I1II1iiII / 16 ) :
  iIiIi1ii = i11i11II11i & 0xffff
  iIiIi1ii = hex ( iIiIi1ii ) [ 2 : - 1 ]
  O0oo0OOo00o0o = iIiIi1ii . zfill ( 4 ) + ":" + O0oo0OOo00o0o
  i11i11II11i >>= 16
  if 18 - 18: iII111i
 if ( i1I1II1iiII % 16 != 0 ) :
  iIiIi1ii = i11i11II11i & 0xff
  iIiIi1ii = hex ( iIiIi1ii ) [ 2 : - 1 ]
  O0oo0OOo00o0o = iIiIi1ii . zfill ( 2 ) + ":" + O0oo0OOo00o0o
  if 98 - 98: IiII . OOooOOo * ooOoO0o / OoO0O00
 return ( O0oo0OOo00o0o [ 0 : - 1 ] )
 if 21 - 21: OOooOOo / OoO0O00 + OoooooooOO
 if 66 - 66: II111iiii * I11i + iII111i * iII111i . i11iIiiIii % Ii1I
 if 96 - 96: I1IiiI . O0 / iIii1I11I1II1
 if 95 - 95: ooOoO0o * OoO0O00 % OoooooooOO % OoO0O00
 if 79 - 79: II111iiii % Ii1I * oO0o * iII111i + II111iiii
 if 51 - 51: I1IiiI + iII111i + I1IiiI / Ii1I * IiII + OOooOOo
 if 70 - 70: I11i . IiII + IiII
 if 74 - 74: Ii1I
 if 11 - 11: I1ii11iIi11i
 if 83 - 83: O0
 if 97 - 97: O0
def lisp_lookup_public_key ( eid ) :
 I1I111iIi = eid . instance_id
 if 50 - 50: I1Ii111 / OoooooooOO . o0oOOo0O0Ooo + I1IiiI * i11iIiiIii
 if 28 - 28: I1Ii111 * II111iiii
 if 14 - 14: iIii1I11I1II1 / Ii1I + o0oOOo0O0Ooo . iII111i % iII111i . i1IIi
 if 67 - 67: IiII * II111iiii + ooOoO0o - i11iIiiIii
 if 15 - 15: I11i
 o0oOO = lisp_get_eid_hash ( eid )
 if ( o0oOO == None ) : return ( [ None , None , False ] )
 if 5 - 5: i1IIi * OoOoOO00 + i1IIi % I11i
 o0oOO = "hash-" + o0oOO
 i1iII = lisp_address ( LISP_AFI_NAME , o0oOO , len ( o0oOO ) , I1I111iIi )
 iIiii1Ii1I = lisp_address ( LISP_AFI_NONE , "" , 0 , I1I111iIi )
 if 79 - 79: OOooOOo % iIii1I11I1II1 / OoOoOO00
 if 9 - 9: Ii1I
 if 44 - 44: iII111i
 if 46 - 46: I11i . i11iIiiIii * OoOoOO00 + o0oOOo0O0Ooo / ooOoO0o
 iI1II1i1I1Ii = lisp_site_eid_lookup ( i1iII , iIiii1Ii1I , True )
 if ( iI1II1i1I1Ii == None ) : return ( [ i1iII , None , False ] )
 if 37 - 37: OoO0O00 - Ii1I + OoO0O00
 if 49 - 49: OoooooooOO - I1ii11iIi11i % I1ii11iIi11i / i1IIi . ooOoO0o
 if 60 - 60: Oo0Ooo
 if 46 - 46: OoOoOO00 + i1IIi
 O0OOO0O0Oo0O = None
 for i11iII1Ii1ii111 in iI1II1i1I1Ii . registered_rlocs :
  Ii111i1iI111 = i11iII1Ii1ii111 . json
  if ( Ii111i1iI111 == None ) : continue
  try :
   Ii111i1iI111 = json . loads ( Ii111i1iI111 . json_string )
  except :
   lprint ( "Registered RLOC JSON format is invalid for {}" . format ( o0oOO ) )
   if 63 - 63: iII111i - o0oOOo0O0Ooo * OOooOOo . Ii1I . Ii1I
   return ( [ i1iII , None , False ] )
   if 7 - 7: i11iIiiIii . I1ii11iIi11i
  if ( Ii111i1iI111 . has_key ( "public-key" ) == False ) : continue
  O0OOO0O0Oo0O = Ii111i1iI111 [ "public-key" ]
  break
  if 4 - 4: i11iIiiIii % OoO0O00 . oO0o
 return ( [ i1iII , O0OOO0O0Oo0O , True ] )
 if 72 - 72: i1IIi + I1Ii111 . oO0o * oO0o * I1IiiI
 if 40 - 40: OoO0O00 % ooOoO0o + iII111i + IiII + I11i * Oo0Ooo
 if 99 - 99: Oo0Ooo
 if 99 - 99: I1Ii111 + oO0o % OoooooooOO
 if 88 - 88: ooOoO0o % Oo0Ooo * II111iiii
 if 62 - 62: iII111i * I1Ii111 % OoOoOO00 * O0
 if 85 - 85: II111iiii - O0 . i11iIiiIii . o0oOOo0O0Ooo + ooOoO0o - ooOoO0o
 if 25 - 25: I1ii11iIi11i % Ii1I * O0 / I1IiiI % OOooOOo
def lisp_verify_cga_sig ( eid , rloc_record ) :
 if 42 - 42: IiII - IiII - I1ii11iIi11i + i1IIi * Oo0Ooo
 if 80 - 80: oO0o + O0
 if 84 - 84: i1IIi - II111iiii
 if 2 - 2: i11iIiiIii - OoO0O00 * Oo0Ooo
 if 100 - 100: I1Ii111
 iIIIIi = json . loads ( rloc_record . json . json_string )
 if 5 - 5: IiII % oO0o . I1IiiI * II111iiii + o0oOOo0O0Ooo / Ii1I
 if ( lisp_get_eid_hash ( eid ) ) :
  OoiIiiIi11 = eid
 elif ( iIIIIi . has_key ( "signature-eid" ) ) :
  oOOO0 = iIIIIi [ "signature-eid" ]
  OoiIiiIi11 = lisp_address ( LISP_AFI_IPV6 , oOOO0 , 0 , 0 )
 else :
  lprint ( "  No signature-eid found in RLOC-record" )
  return ( False )
  if 45 - 45: i11iIiiIii / ooOoO0o % Oo0Ooo
  if 32 - 32: OoooooooOO . OoOoOO00 . O0
  if 44 - 44: ooOoO0o % I11i + ooOoO0o . oO0o
  if 70 - 70: O0 - I11i . iIii1I11I1II1 % I11i . OoOoOO00 % oO0o
  if 5 - 5: O0 * OoO0O00
 i1iII , O0OOO0O0Oo0O , O0O0I1III1iI = lisp_lookup_public_key ( OoiIiiIi11 )
 if ( i1iII == None ) :
  I1I1iII1i = green ( OoiIiiIi11 . print_address ( ) , False )
  lprint ( "  Could not parse hash in EID {}" . format ( I1I1iII1i ) )
  return ( False )
  if 16 - 16: oO0o * O0 + OoO0O00
  if 42 - 42: O0
 III = "found" if O0O0I1III1iI else bold ( "not found" , False )
 I1I1iII1i = green ( i1iII . print_address ( ) , False )
 lprint ( "  Lookup for crypto-hashed EID {} {}" . format ( I1I1iII1i , III ) )
 if ( O0O0I1III1iI == False ) : return ( False )
 if 30 - 30: oO0o
 if ( O0OOO0O0Oo0O == None ) :
  lprint ( "  RLOC-record with public-key not found" )
  return ( False )
  if 54 - 54: IiII - II111iiii + II111iiii / I1IiiI * OOooOOo
  if 9 - 9: I1IiiI % ooOoO0o
 oOooOooo000oO = O0OOO0O0Oo0O [ 0 : 8 ] + "..." + O0OOO0O0Oo0O [ - 8 : : ]
 lprint ( "  RLOC-record with public-key '{}' found" . format ( oOooOooo000oO ) )
 if 56 - 56: i1IIi + Ii1I * iIii1I11I1II1
 if 1 - 1: iII111i
 if 25 - 25: oO0o - i1IIi
 if 67 - 67: I1IiiI % I11i - OoooooooOO
 if 2 - 2: Ii1I
 I1IiiIiiii1I1 = iIIIIi [ "signature" ]
 if 21 - 21: ooOoO0o + o0oOOo0O0Ooo + Ii1I * ooOoO0o
 try :
  iIIIIi = binascii . a2b_base64 ( I1IiiIiiii1I1 )
 except :
  lprint ( "  Incorrect padding in signature string" )
  return ( False )
  if 15 - 15: I1ii11iIi11i * i11iIiiIii
  if 61 - 61: II111iiii - oO0o + O0 + Oo0Ooo % I1ii11iIi11i . OOooOOo
 O0OO0oOoO0Oo = len ( iIIIIi )
 if ( O0OO0oOoO0Oo & 1 ) :
  lprint ( "  Signature length is odd, length {}" . format ( O0OO0oOoO0Oo ) )
  return ( False )
  if 78 - 78: o0oOOo0O0Ooo * O0 * OoOoOO00 * I11i . OoooooooOO . OOooOOo
  if 38 - 38: o0oOOo0O0Ooo . OoO0O00 . oO0o . iIii1I11I1II1
  if 62 - 62: OoO0O00 * i11iIiiIii / i1IIi . i11iIiiIii - o0oOOo0O0Ooo
  if 86 - 86: I1Ii111 / I1ii11iIi11i * iII111i . IiII * OoooooooOO - OoO0O00
  if 80 - 80: OoOoOO00 * iIii1I11I1II1 % O0 . O0
 Ooo00O0OooOOO = OoiIiiIi11 . print_address ( )
 if 100 - 100: OoO0O00 + II111iiii % oO0o / OoOoOO00 * OOooOOo
 if 23 - 23: OoOoOO00
 if 56 - 56: o0oOOo0O0Ooo / oO0o * I1Ii111 + iIii1I11I1II1 / IiII + o0oOOo0O0Ooo
 if 50 - 50: I1IiiI * ooOoO0o
 O0OOO0O0Oo0O = binascii . a2b_base64 ( O0OOO0O0Oo0O )
 try :
  i1i11ii1 = ecdsa . VerifyingKey . from_pem ( O0OOO0O0Oo0O )
 except :
  IIIo000 = bold ( "Bad public-key" , False )
  lprint ( "  {}, not in PEM format" . format ( IIIo000 ) )
  return ( False )
  if 39 - 39: OoOoOO00
  if 61 - 61: OoooooooOO / ooOoO0o . i1IIi . Oo0Ooo % OoOoOO00 * OoO0O00
  if 4 - 4: I1Ii111 . o0oOOo0O0Ooo
  if 72 - 72: Ii1I * OoO0O00 / OoO0O00
  if 39 - 39: oO0o
  if 49 - 49: I1IiiI * I1Ii111 . I1IiiI - II111iiii
  if 57 - 57: oO0o + O0 - OoOoOO00
  if 14 - 14: II111iiii + i11iIiiIii + Ii1I / o0oOOo0O0Ooo . OoO0O00
  if 93 - 93: o0oOOo0O0Ooo + i1IIi
  if 24 - 24: i1IIi
  if 54 - 54: iIii1I11I1II1 - IiII + o0oOOo0O0Ooo + I1ii11iIi11i + IiII
 try :
  o0O0oOOoo0O0 = i1i11ii1 . verify ( iIIIIi , Ooo00O0OooOOO , hashfunc = hashlib . sha256 )
 except :
  lprint ( "  Signature library failed for signature data '{}'" . format ( Ooo00O0OooOOO ) )
  if 99 - 99: Oo0Ooo
  lprint ( "  Signature used '{}'" . format ( I1IiiIiiii1I1 ) )
  return ( False )
  if 38 - 38: I1ii11iIi11i - I1IiiI
 return ( o0O0oOOoo0O0 )
 if 50 - 50: iII111i % OoO0O00 - oO0o + Oo0Ooo . O0 . iII111i
 if 42 - 42: iII111i + I1ii11iIi11i
 if 44 - 44: I1ii11iIi11i % IiII
 if 1 - 1: Oo0Ooo + IiII - I1Ii111 / I1Ii111
 if 25 - 25: OoOoOO00
 if 52 - 52: OOooOOo + IiII
 if 73 - 73: OoooooooOO - I1Ii111 % iII111i / OOooOOo . o0oOOo0O0Ooo - IiII
 if 69 - 69: Ii1I . iIii1I11I1II1 / Oo0Ooo * Oo0Ooo % IiII
 if 5 - 5: OOooOOo - I1Ii111 + IiII
 if 82 - 82: OOooOOo
def lisp_remove_eid_from_map_notify_queue ( eid_list ) :
 if 26 - 26: ooOoO0o + OoooooooOO + ooOoO0o * I1Ii111
 if 26 - 26: I1IiiI - OOooOOo
 if 34 - 34: I1Ii111 % I1IiiI . OoOoOO00 / iII111i + ooOoO0o . i11iIiiIii
 if 51 - 51: OoooooooOO * I1Ii111 * I11i - I1ii11iIi11i + I1Ii111
 if 50 - 50: OoooooooOO * II111iiii
 i1111 = [ ]
 for ii1ii1i1i1I in eid_list :
  for Ii1i1 in lisp_map_notify_queue :
   o0o00ooo0O = lisp_map_notify_queue [ Ii1i1 ]
   if ( ii1ii1i1i1I not in o0o00ooo0O . eid_list ) : continue
   if 35 - 35: I1Ii111 + oO0o + II111iiii
   i1111 . append ( Ii1i1 )
   oOOoOOoOo00O = o0o00ooo0O . retransmit_timer
   if ( oOOoOOoOo00O ) : oOOoOOoOo00O . cancel ( )
   if 67 - 67: i11iIiiIii - OoOoOO00
   lprint ( "Remove from Map-Notify queue nonce 0x{} for EID {}" . format ( o0o00ooo0O . nonce_key , green ( ii1ii1i1i1I , False ) ) )
   if 90 - 90: i11iIiiIii . I1ii11iIi11i - OoooooooOO / o0oOOo0O0Ooo
   if 58 - 58: II111iiii + iIii1I11I1II1
   if 51 - 51: ooOoO0o - Ii1I + ooOoO0o
   if 87 - 87: O0 - I1IiiI
   if 37 - 37: Oo0Ooo - o0oOOo0O0Ooo * II111iiii / ooOoO0o
   if 90 - 90: iIii1I11I1II1 . II111iiii % I1Ii111
   if 28 - 28: i11iIiiIii + OoO0O00 % O0 - I1ii11iIi11i % oO0o
 for Ii1i1 in i1111 : lisp_map_notify_queue . pop ( Ii1i1 )
 return
 if 30 - 30: I11i + OOooOOo
 if 27 - 27: OoOoOO00 . ooOoO0o
 if 73 - 73: o0oOOo0O0Ooo
 if 8 - 8: O0
 if 40 - 40: OOooOOo . II111iiii . ooOoO0o % o0oOOo0O0Ooo
 if 22 - 22: O0 * IiII . OoO0O00
 if 63 - 63: oO0o % Oo0Ooo * OoO0O00 / II111iiii / Ii1I - ooOoO0o
 if 14 - 14: ooOoO0o . o0oOOo0O0Ooo + II111iiii
def lisp_decrypt_map_register ( packet ) :
 if 50 - 50: Ii1I - i1IIi * oO0o
 if 52 - 52: I11i / oO0o - oO0o
 if 84 - 84: iIii1I11I1II1 - o0oOOo0O0Ooo
 if 37 - 37: iII111i * o0oOOo0O0Ooo
 if 23 - 23: ooOoO0o + OoooooooOO * iII111i . I11i
 oo = socket . ntohl ( struct . unpack ( "I" , packet [ 0 : 4 ] ) [ 0 ] )
 iiIIi1I1111Ii = ( oo >> 13 ) & 0x1
 if ( iiIIi1I1111Ii == 0 ) : return ( packet )
 if 23 - 23: oO0o . Ii1I - OOooOOo . iII111i - Oo0Ooo / O0
 OOOo000oOoOO = ( oo >> 14 ) & 0x7
 if 89 - 89: Ii1I % O0 * iIii1I11I1II1 . I1IiiI . o0oOOo0O0Ooo
 if 66 - 66: OoooooooOO % i11iIiiIii - IiII * Oo0Ooo * OoooooooOO - I1ii11iIi11i
 if 64 - 64: I11i % OoOoOO00 * Ii1I % OoooooooOO % OOooOOo * OoOoOO00
 if 20 - 20: IiII
 try :
  iIiIIIii1iI = lisp_ms_encryption_keys [ OOOo000oOoOO ]
  iIiIIIii1iI = iIiIIIii1iI . zfill ( 32 )
  oOOo00 = "0" * 8
 except :
  lprint ( "Cannot decrypt Map-Register with key-id {}" . format ( OOOo000oOoOO ) )
  return ( None )
  if 27 - 27: I11i . II111iiii + I1ii11iIi11i * Ii1I * Oo0Ooo
  if 64 - 64: i11iIiiIii - I1Ii111 - Ii1I % OOooOOo + iII111i
 I1 = bold ( "Decrypt" , False )
 lprint ( "{} Map-Register with key-id {}" . format ( I1 , OOOo000oOoOO ) )
 if 46 - 46: OoO0O00 - oO0o / OOooOOo . OoooooooOO * I1Ii111 . Ii1I
 i1IiI1ii1i = chacha . ChaCha ( iIiIIIii1iI , oOOo00 ) . decrypt ( packet [ 4 : : ] )
 return ( packet [ 0 : 4 ] + i1IiI1ii1i )
 if 94 - 94: o0oOOo0O0Ooo
 if 46 - 46: I1ii11iIi11i + iII111i / OoO0O00 + oO0o * I11i % OOooOOo
 if 80 - 80: O0 % II111iiii / O0 . Oo0Ooo * OoOoOO00 + OOooOOo
 if 47 - 47: Ii1I - Oo0Ooo * OoOoOO00
 if 20 - 20: oO0o
 if 48 - 48: I1IiiI % OoO0O00
 if 33 - 33: Ii1I
def lisp_process_map_register ( lisp_sockets , packet , source , sport ) :
 global lisp_registered_count
 if 73 - 73: Ii1I . IiII
 if 43 - 43: I11i . IiII - iII111i * I1IiiI * iII111i
 if 90 - 90: i11iIiiIii * i1IIi
 if 88 - 88: i11iIiiIii - OoOoOO00
 if 53 - 53: iIii1I11I1II1 % I1Ii111 / Oo0Ooo % Oo0Ooo
 if 6 - 6: iII111i
 packet = lisp_decrypt_map_register ( packet )
 if ( packet == None ) : return
 if 44 - 44: oO0o
 IiiiI1I = lisp_map_register ( )
 IIII11i1Ii , packet = IiiiI1I . decode ( packet )
 if ( packet == None ) :
  lprint ( "Could not decode Map-Register packet" )
  return
  if 69 - 69: i1IIi + ooOoO0o - OoO0O00
 IiiiI1I . sport = sport
 if 4 - 4: i11iIiiIii + oO0o + IiII % IiII . i11iIiiIii - OOooOOo
 IiiiI1I . print_map_register ( )
 if 50 - 50: OoOoOO00 % o0oOOo0O0Ooo - II111iiii - i1IIi
 if 35 - 35: Oo0Ooo - ooOoO0o % OoO0O00
 if 26 - 26: i1IIi * I1Ii111 * OoO0O00 - IiII
 if 26 - 26: Oo0Ooo - ooOoO0o . iII111i * OoOoOO00 / OoooooooOO
 oO00oOo0o = True
 if ( IiiiI1I . auth_len == LISP_SHA1_160_AUTH_DATA_LEN ) :
  oO00oOo0o = True
  if 61 - 61: iII111i % OoO0O00 - I1IiiI + OOooOOo - OoooooooOO
 if ( IiiiI1I . alg_id == LISP_SHA_256_128_ALG_ID ) :
  oO00oOo0o = False
  if 82 - 82: I1Ii111 . OoO0O00
  if 24 - 24: i1IIi . iII111i * iIii1I11I1II1 . I11i % I1ii11iIi11i + i11iIiiIii
  if 28 - 28: OoO0O00 . I1ii11iIi11i / O0
  if 35 - 35: O0 . oO0o % OoOoOO00 * O0 - IiII
  if 63 - 63: ooOoO0o
 IiI1I1I1 = [ ]
 if 53 - 53: I1IiiI % IiII . I11i + OoOoOO00 . OoooooooOO + oO0o
 if 17 - 17: IiII
 if 47 - 47: I11i . I1IiiI % ooOoO0o . i11iIiiIii
 if 63 - 63: I1ii11iIi11i % I11i % OoooooooOO
 ooIiIII11IIIi1 = None
 O00oOOoo00oo = packet
 o0Ooo0Oo = [ ]
 IiIii1iI = IiiiI1I . record_count
 for iiIii1I in range ( IiIii1iI ) :
  OOOoOooO = lisp_eid_record ( )
  oO0oO = lisp_rloc_record ( )
  packet = OOOoOooO . decode ( packet )
  if ( packet == None ) :
   lprint ( "Could not decode EID-record in Map-Register packet" )
   return
   if 62 - 62: II111iiii % II111iiii % O0 % i11iIiiIii - iIii1I11I1II1
  OOOoOooO . print_record ( "  " , False )
  if 65 - 65: II111iiii + ooOoO0o . IiII
  if 11 - 11: Oo0Ooo % ooOoO0o + I1Ii111 . OoOoOO00
  if 2 - 2: i1IIi - IiII + iIii1I11I1II1 % i1IIi * II111iiii
  if 26 - 26: I11i
  iI1II1i1I1Ii = lisp_site_eid_lookup ( OOOoOooO . eid , OOOoOooO . group ,
 False )
  if 57 - 57: I1ii11iIi11i + I1Ii111 + i11iIiiIii . i1IIi / i11iIiiIii
  i11i11i1i1 = iI1II1i1I1Ii . print_eid_tuple ( ) if iI1II1i1I1Ii else None
  if 55 - 55: I11i / I11i - IiII - I11i
  if 3 - 3: oO0o % o0oOOo0O0Ooo + OoOoOO00
  if 22 - 22: O0
  if 36 - 36: OOooOOo
  if 42 - 42: OOooOOo * ooOoO0o * i11iIiiIii + OoooooooOO . iIii1I11I1II1
  if 95 - 95: i1IIi * O0 / II111iiii * OoOoOO00 * I1IiiI
  if 38 - 38: OOooOOo - OoOoOO00 / OoO0O00 / o0oOOo0O0Ooo - i11iIiiIii
  if ( iI1II1i1I1Ii and iI1II1i1I1Ii . accept_more_specifics == False ) :
   if ( iI1II1i1I1Ii . eid_record_matches ( OOOoOooO ) == False ) :
    IiIII1iii1iII = iI1II1i1I1Ii . parent_for_more_specifics
    if ( IiIII1iii1iII ) : iI1II1i1I1Ii = IiIII1iii1iII
    if 81 - 81: Oo0Ooo % OoooooooOO
    if 65 - 65: iII111i + OoooooooOO / Oo0Ooo / OoooooooOO * o0oOOo0O0Ooo
    if 88 - 88: OoO0O00 / II111iiii
    if 27 - 27: OOooOOo - i1IIi + O0 . I1Ii111 % I11i . I1ii11iIi11i
    if 80 - 80: I1IiiI - i11iIiiIii
    if 39 - 39: I11i / O0 - I1ii11iIi11i . Oo0Ooo * OoooooooOO / o0oOOo0O0Ooo
    if 71 - 71: O0 . OoooooooOO + Oo0Ooo . ooOoO0o / Ii1I
    if 92 - 92: I1ii11iIi11i . oO0o
  iII1O00OOoo0ooOo0 = ( iI1II1i1I1Ii and iI1II1i1I1Ii . accept_more_specifics )
  if ( iII1O00OOoo0ooOo0 ) :
   oOoO0Oo0o0O = lisp_site_eid ( iI1II1i1I1Ii . site )
   oOoO0Oo0o0O . dynamic = True
   oOoO0Oo0o0O . eid . copy_address ( OOOoOooO . eid )
   oOoO0Oo0o0O . group . copy_address ( OOOoOooO . group )
   oOoO0Oo0o0O . parent_for_more_specifics = iI1II1i1I1Ii
   oOoO0Oo0o0O . add_cache ( )
   oOoO0Oo0o0O . inherit_from_ams_parent ( )
   iI1II1i1I1Ii . more_specific_registrations . append ( oOoO0Oo0o0O )
   iI1II1i1I1Ii = oOoO0Oo0o0O
  else :
   iI1II1i1I1Ii = lisp_site_eid_lookup ( OOOoOooO . eid , OOOoOooO . group ,
 True )
   if 78 - 78: IiII / OoOoOO00 % OoO0O00 + Ii1I * I1Ii111 / I11i
   if 8 - 8: I1IiiI . II111iiii - Ii1I / I1ii11iIi11i * ooOoO0o + Oo0Ooo
  I1I1iII1i = OOOoOooO . print_eid_tuple ( )
  if 72 - 72: iIii1I11I1II1 . Ii1I
  if ( iI1II1i1I1Ii == None ) :
   oo0 = bold ( "Site not found" , False )
   lprint ( "  {} for EID {}{}" . format ( oo0 , green ( I1I1iII1i , False ) ,
 ", matched non-ams {}" . format ( green ( i11i11i1i1 , False ) if i11i11i1i1 else "" ) ) )
   if 4 - 4: OoOoOO00 * I1ii11iIi11i + OOooOOo % iIii1I11I1II1 / ooOoO0o
   if 36 - 36: i11iIiiIii / OOooOOo . O0 . OoO0O00 - Ii1I
   if 31 - 31: OoOoOO00 * o0oOOo0O0Ooo / O0 . iII111i / i11iIiiIii
   if 22 - 22: I1IiiI . OoooooooOO * I1ii11iIi11i + i11iIiiIii - O0 + i11iIiiIii
   if 98 - 98: OOooOOo + I1IiiI / IiII / OoooooooOO / OOooOOo
   packet = oO0oO . end_of_rlocs ( packet , OOOoOooO . rloc_count )
   if ( packet == None ) :
    lprint ( "  Could not decode RLOC-record in Map-Register packet" )
    return
    if 8 - 8: OoooooooOO * OOooOOo * iII111i - iII111i
   continue
   if 32 - 32: I1Ii111
   if 28 - 28: I11i . i11iIiiIii % iIii1I11I1II1 + OoOoOO00
  ooIiIII11IIIi1 = iI1II1i1I1Ii . site
  if 4 - 4: OOooOOo + I1ii11iIi11i - iII111i + OOooOOo / IiII
  if ( iII1O00OOoo0ooOo0 ) :
   Oo00OOo00O = iI1II1i1I1Ii . parent_for_more_specifics . print_eid_tuple ( )
   lprint ( "  Found ams {} for site '{}' for registering prefix {}" . format ( green ( Oo00OOo00O , False ) , ooIiIII11IIIi1 . site_name , green ( I1I1iII1i , False ) ) )
   if 23 - 23: iIii1I11I1II1 + OoooooooOO + ooOoO0o . iII111i . Oo0Ooo - iIii1I11I1II1
  else :
   Oo00OOo00O = green ( iI1II1i1I1Ii . print_eid_tuple ( ) , False )
   lprint ( "  Found {} for site '{}' for registering prefix {}" . format ( Oo00OOo00O , ooIiIII11IIIi1 . site_name , green ( I1I1iII1i , False ) ) )
   if 25 - 25: O0 + I1IiiI % OOooOOo / Oo0Ooo . IiII / I1Ii111
   if 84 - 84: ooOoO0o . O0 + I1IiiI * OoO0O00 - I1IiiI
   if 24 - 24: Ii1I
   if 23 - 23: Oo0Ooo * i1IIi / I1IiiI . I11i - I1ii11iIi11i . iIii1I11I1II1
   if 15 - 15: O0 + o0oOOo0O0Ooo / oO0o
   if 27 - 27: Ii1I * II111iiii / oO0o
  if ( ooIiIII11IIIi1 . shutdown ) :
   lprint ( ( "  Rejecting registration for site '{}', configured in " +
 "admin-shutdown state" ) . format ( ooIiIII11IIIi1 . site_name ) )
   packet = oO0oO . end_of_rlocs ( packet , OOOoOooO . rloc_count )
   continue
   if 99 - 99: I11i + ooOoO0o % I11i + O0 - Ii1I - I1Ii111
   if 3 - 3: Oo0Ooo . I1IiiI
   if 61 - 61: OoO0O00 - I1ii11iIi11i . Ii1I * i11iIiiIii
   if 97 - 97: ooOoO0o
   if 58 - 58: iII111i
   if 47 - 47: II111iiii % Oo0Ooo . iIii1I11I1II1 . oO0o
   if 52 - 52: I11i * I1IiiI % I11i - iII111i - Ii1I - OoooooooOO
   if 15 - 15: iII111i
  iI11i = IiiiI1I . key_id
  if ( ooIiIII11IIIi1 . auth_key . has_key ( iI11i ) == False ) : iI11i = 0
  OoIiIii1 = ooIiIII11IIIi1 . auth_key [ iI11i ]
  if 73 - 73: iIii1I11I1II1 % I1Ii111 * I1IiiI * II111iiii . I1ii11iIi11i
  IiI111II1I1iI = lisp_verify_auth ( IIII11i1Ii , IiiiI1I . alg_id ,
 IiiiI1I . auth_data , OoIiIii1 )
  ii1II1 = "dynamic " if iI1II1i1I1Ii . dynamic else ""
  if 27 - 27: o0oOOo0O0Ooo
  i111I = bold ( "passed" if IiI111II1I1iI else "failed" , False )
  iI11i = "key-id {}" . format ( iI11i ) if iI11i == IiiiI1I . key_id else "bad key-id {}" . format ( IiiiI1I . key_id )
  if 27 - 27: i11iIiiIii / OoO0O00 * OoO0O00
  lprint ( "  Authentication {} for {}EID-prefix {}, {}" . format ( i111I , ii1II1 , green ( I1I1iII1i , False ) , iI11i ) )
  if 12 - 12: OoO0O00
  if 17 - 17: I1Ii111 + OOooOOo / OoooooooOO
  if 75 - 75: OoooooooOO / I1ii11iIi11i . II111iiii
  if 7 - 7: O0 % ooOoO0o / oO0o
  if 36 - 36: I1ii11iIi11i - oO0o + iII111i / I11i
  if 62 - 62: I1Ii111 . ooOoO0o % I1ii11iIi11i . ooOoO0o - iIii1I11I1II1 + iII111i
  OoO0O = True
  Ii1I1i = ( lisp_get_eid_hash ( OOOoOooO . eid ) != None )
  if ( Ii1I1i or iI1II1i1I1Ii . require_signature ) :
   O0o00OoOoO0Oo = "Required " if iI1II1i1I1Ii . require_signature else ""
   I1I1iII1i = green ( I1I1iII1i , False )
   i11iII1Ii1ii111 = lisp_find_sig_in_rloc_set ( packet , OOOoOooO . rloc_count )
   if ( i11iII1Ii1ii111 == None ) :
    OoO0O = False
    lprint ( ( "  {}EID-crypto-hash signature verification {} " + "for EID-prefix {}, no signature found" ) . format ( O0o00OoOoO0Oo ,
    # I1IiiI
 bold ( "failed" , False ) , I1I1iII1i ) )
   else :
    OoO0O = lisp_verify_cga_sig ( OOOoOooO . eid , i11iII1Ii1ii111 )
    i111I = bold ( "passed" if OoO0O else "failed" , False )
    lprint ( ( "  {}EID-crypto-hash signature verification {} " + "for EID-prefix {}" ) . format ( O0o00OoOoO0Oo , i111I , I1I1iII1i ) )
    if 34 - 34: o0oOOo0O0Ooo / I1IiiI * i11iIiiIii + I1Ii111 / IiII
    if 55 - 55: iIii1I11I1II1 % iIii1I11I1II1 % iII111i
    if 80 - 80: OoooooooOO % iII111i * IiII % IiII
    if 34 - 34: OoO0O00
  if ( IiI111II1I1iI == False or OoO0O == False ) :
   packet = oO0oO . end_of_rlocs ( packet , OOOoOooO . rloc_count )
   if ( packet == None ) :
    lprint ( "  Could not decode RLOC-record in Map-Register packet" )
    return
    if 22 - 22: OOooOOo
   continue
   if 23 - 23: I1ii11iIi11i
   if 53 - 53: I11i
   if 64 - 64: iIii1I11I1II1 + O0 % IiII
   if 13 - 13: i11iIiiIii
   if 49 - 49: OoOoOO00
   if 61 - 61: I1Ii111 / I1Ii111 / iII111i / ooOoO0o - I1IiiI . o0oOOo0O0Ooo
  if ( IiiiI1I . merge_register_requested ) :
   IiIII1iii1iII = iI1II1i1I1Ii
   IiIII1iii1iII . inconsistent_registration = False
   if 80 - 80: I1IiiI - OOooOOo . oO0o
   if 75 - 75: oO0o + OoOoOO00 - OoooooooOO
   if 38 - 38: I11i / ooOoO0o / OoOoOO00 * OOooOOo . oO0o
   if 8 - 8: OoO0O00 . OOooOOo % I1Ii111 * OOooOOo / I1IiiI
   if 3 - 3: IiII - I1ii11iIi11i . o0oOOo0O0Ooo
   if ( iI1II1i1I1Ii . group . is_null ( ) ) :
    if ( IiIII1iii1iII . site_id != IiiiI1I . site_id ) :
     IiIII1iii1iII . site_id = IiiiI1I . site_id
     IiIII1iii1iII . registered = False
     IiIII1iii1iII . individual_registrations = { }
     IiIII1iii1iII . registered_rlocs = [ ]
     lisp_registered_count -= 1
     if 39 - 39: oO0o . I1Ii111 + oO0o % OoOoOO00 - i11iIiiIii
     if 69 - 69: I11i / OoO0O00
     if 73 - 73: i11iIiiIii / i1IIi
   i1i11ii1 = source . address + IiiiI1I . xtr_id
   if ( iI1II1i1I1Ii . individual_registrations . has_key ( i1i11ii1 ) ) :
    iI1II1i1I1Ii = iI1II1i1I1Ii . individual_registrations [ i1i11ii1 ]
   else :
    iI1II1i1I1Ii = lisp_site_eid ( ooIiIII11IIIi1 )
    iI1II1i1I1Ii . eid . copy_address ( IiIII1iii1iII . eid )
    iI1II1i1I1Ii . group . copy_address ( IiIII1iii1iII . group )
    IiIII1iii1iII . individual_registrations [ i1i11ii1 ] = iI1II1i1I1Ii
    if 8 - 8: O0 / OOooOOo + iII111i % iIii1I11I1II1 % iIii1I11I1II1 . ooOoO0o
  else :
   iI1II1i1I1Ii . inconsistent_registration = iI1II1i1I1Ii . merge_register_requested
   if 47 - 47: OoO0O00 / o0oOOo0O0Ooo / Ii1I * I1IiiI % ooOoO0o / I1Ii111
   if 80 - 80: I1Ii111 / O0 * O0
   if 40 - 40: OoO0O00 - oO0o / o0oOOo0O0Ooo . oO0o
  iI1II1i1I1Ii . map_registers_received += 1
  if 89 - 89: i11iIiiIii - II111iiii
  if 67 - 67: IiII % I1Ii111 + i11iIiiIii
  if 53 - 53: OOooOOo
  if 95 - 95: oO0o - OOooOOo % I1Ii111 / OoooooooOO % OoooooooOO - O0
  if 21 - 21: I1Ii111 . i1IIi - iII111i % I1ii11iIi11i . OOooOOo
  IIIo000 = ( iI1II1i1I1Ii . is_rloc_in_rloc_set ( source ) == False )
  if ( OOOoOooO . record_ttl == 0 and IIIo000 ) :
   lprint ( "  Ignore deregistration request from {}" . format ( red ( source . print_address_no_iid ( ) , False ) ) )
   if 52 - 52: Ii1I * I1ii11iIi11i
   continue
   if 21 - 21: I1IiiI . i11iIiiIii - o0oOOo0O0Ooo * II111iiii % iIii1I11I1II1
   if 9 - 9: I1ii11iIi11i + I11i
   if 20 - 20: iII111i + i1IIi / oO0o % OoooooooOO * OoOoOO00
   if 70 - 70: Oo0Ooo - OOooOOo * OOooOOo / o0oOOo0O0Ooo
   if 4 - 4: OoOoOO00 / OoO0O00
   if 66 - 66: I1Ii111 / OoOoOO00
  oOO = iI1II1i1I1Ii . registered_rlocs
  iI1II1i1I1Ii . registered_rlocs = [ ]
  if 2 - 2: I1Ii111
  if 69 - 69: I1IiiI . I1ii11iIi11i . o0oOOo0O0Ooo + OoooooooOO
  if 52 - 52: i1IIi - oO0o
  if 33 - 33: Ii1I / I1ii11iIi11i . ooOoO0o . OoooooooOO
  IIIoO0o0oOO0O0 = packet
  for o0oIIi1 in range ( OOOoOooO . rloc_count ) :
   oO0oO = lisp_rloc_record ( )
   packet = oO0oO . decode ( packet , None )
   if ( packet == None ) :
    lprint ( "  Could not decode RLOC-record in Map-Register packet" )
    return
    if 9 - 9: iII111i * OoooooooOO % ooOoO0o
   oO0oO . print_record ( "    " )
   if 82 - 82: O0 - Oo0Ooo - i11iIiiIii
   if 9 - 9: OoooooooOO . i11iIiiIii * iIii1I11I1II1 / IiII * i11iIiiIii
   if 57 - 57: o0oOOo0O0Ooo . I1IiiI / iII111i / ooOoO0o - OoO0O00
   if 8 - 8: iIii1I11I1II1 % ooOoO0o + OoO0O00 . oO0o % I1IiiI - O0
   if ( len ( ooIiIII11IIIi1 . allowed_rlocs ) > 0 ) :
    oO00o = oO0oO . rloc . print_address ( )
    if ( ooIiIII11IIIi1 . allowed_rlocs . has_key ( oO00o ) == False ) :
     lprint ( ( "  Reject registration, RLOC {} not " + "configured in allowed RLOC-set" ) . format ( red ( oO00o , False ) ) )
     if 25 - 25: i11iIiiIii * OoOoOO00 + OoO0O00 . o0oOOo0O0Ooo
     if 65 - 65: I1Ii111 + i1IIi / iII111i % O0 + II111iiii * i1IIi
     iI1II1i1I1Ii . registered = False
     packet = oO0oO . end_of_rlocs ( packet ,
 OOOoOooO . rloc_count - o0oIIi1 - 1 )
     break
     if 49 - 49: o0oOOo0O0Ooo + OOooOOo - II111iiii
     if 34 - 34: ooOoO0o . I1Ii111
     if 52 - 52: I1IiiI + I1Ii111 * oO0o / i11iIiiIii * iIii1I11I1II1
     if 27 - 27: Oo0Ooo
     if 85 - 85: iIii1I11I1II1 . o0oOOo0O0Ooo + oO0o
     if 79 - 79: O0 - iIii1I11I1II1 + i1IIi . I11i
   i11iII1Ii1ii111 = lisp_rloc ( )
   i11iII1Ii1ii111 . store_rloc_from_record ( oO0oO , None , source )
   if 21 - 21: II111iiii
   if 23 - 23: I11i * i1IIi . oO0o / IiII + o0oOOo0O0Ooo
   if 1 - 1: IiII / OoO0O00 . oO0o * I1Ii111 - i11iIiiIii
   if 50 - 50: oO0o - O0 / I1IiiI . OoOoOO00 . Oo0Ooo
   if 30 - 30: IiII . OoO0O00 + Oo0Ooo
   if 48 - 48: iIii1I11I1II1 / i11iIiiIii . OoOoOO00 * I11i
   if ( source . is_exact_match ( i11iII1Ii1ii111 . rloc ) ) :
    i11iII1Ii1ii111 . map_notify_requested = IiiiI1I . map_notify_requested
    if 1 - 1: IiII . OoOoOO00 * o0oOOo0O0Ooo
    if 63 - 63: O0 / Ii1I + I1Ii111 % OoO0O00 % OOooOOo * O0
    if 35 - 35: OoO0O00 + OoooooooOO % Oo0Ooo / I11i - O0 . i1IIi
    if 76 - 76: IiII % I1IiiI * Ii1I / Ii1I / OoooooooOO + Ii1I
    if 19 - 19: OoooooooOO
   iI1II1i1I1Ii . registered_rlocs . append ( i11iII1Ii1ii111 )
   if 88 - 88: I1IiiI % ooOoO0o % Oo0Ooo - O0
   if 71 - 71: OOooOOo % Ii1I - i11iIiiIii - oO0o . ooOoO0o / I1Ii111
  o0OOO0o0O0O0o0o = ( iI1II1i1I1Ii . do_rloc_sets_match ( oOO ) == False )
  if 17 - 17: iII111i / iII111i / I1ii11iIi11i - OoOoOO00 * I1IiiI
  if 39 - 39: OoOoOO00 % O0 * I1Ii111 - IiII + OoO0O00 * O0
  if 69 - 69: Ii1I
  if 29 - 29: OoOoOO00 + Oo0Ooo
  if 49 - 49: OOooOOo - iIii1I11I1II1 / ooOoO0o
  if 28 - 28: OoOoOO00 + OoOoOO00 - OoOoOO00 / ooOoO0o
  if ( IiiiI1I . map_register_refresh and o0OOO0o0O0O0o0o and
 iI1II1i1I1Ii . registered ) :
   lprint ( "  Reject registration, refreshes cannot change RLOC-set" )
   iI1II1i1I1Ii . registered_rlocs = oOO
   continue
   if 81 - 81: oO0o
   if 34 - 34: o0oOOo0O0Ooo * OOooOOo - i1IIi * o0oOOo0O0Ooo * Oo0Ooo
   if 59 - 59: iIii1I11I1II1 / Oo0Ooo % II111iiii
   if 55 - 55: ooOoO0o - IiII + o0oOOo0O0Ooo
   if 48 - 48: O0 - iIii1I11I1II1 * OOooOOo
   if 33 - 33: I11i
  if ( iI1II1i1I1Ii . registered == False ) :
   iI1II1i1I1Ii . first_registered = lisp_get_timestamp ( )
   lisp_registered_count += 1
   if 63 - 63: Ii1I % II111iiii / OoOoOO00 + Oo0Ooo
  iI1II1i1I1Ii . last_registered = lisp_get_timestamp ( )
  iI1II1i1I1Ii . registered = ( OOOoOooO . record_ttl != 0 )
  iI1II1i1I1Ii . last_registerer = source
  if 28 - 28: OoO0O00 + I1IiiI . oO0o + II111iiii - O0
  if 32 - 32: oO0o
  if 62 - 62: i11iIiiIii + OoooooooOO + IiII - OoO0O00 / oO0o * iIii1I11I1II1
  if 91 - 91: o0oOOo0O0Ooo - i11iIiiIii + Oo0Ooo % iIii1I11I1II1
  iI1II1i1I1Ii . auth_sha1_or_sha2 = oO00oOo0o
  iI1II1i1I1Ii . proxy_reply_requested = IiiiI1I . proxy_reply_requested
  iI1II1i1I1Ii . lisp_sec_present = IiiiI1I . lisp_sec_present
  iI1II1i1I1Ii . map_notify_requested = IiiiI1I . map_notify_requested
  iI1II1i1I1Ii . mobile_node_requested = IiiiI1I . mobile_node
  iI1II1i1I1Ii . merge_register_requested = IiiiI1I . merge_register_requested
  if 58 - 58: iII111i / ooOoO0o - I1Ii111 + I1Ii111 * ooOoO0o
  iI1II1i1I1Ii . use_register_ttl_requested = IiiiI1I . use_ttl_for_timeout
  if ( iI1II1i1I1Ii . use_register_ttl_requested ) :
   iI1II1i1I1Ii . register_ttl = OOOoOooO . store_ttl ( )
  else :
   iI1II1i1I1Ii . register_ttl = LISP_SITE_TIMEOUT_CHECK_INTERVAL * 3
   if 48 - 48: iII111i % O0 % Ii1I * OoO0O00 . OoO0O00
  iI1II1i1I1Ii . xtr_id_present = IiiiI1I . xtr_id_present
  if ( iI1II1i1I1Ii . xtr_id_present ) :
   iI1II1i1I1Ii . xtr_id = IiiiI1I . xtr_id
   iI1II1i1I1Ii . site_id = IiiiI1I . site_id
   if 74 - 74: OoO0O00 * i1IIi + I1ii11iIi11i / o0oOOo0O0Ooo / i1IIi
   if 94 - 94: Ii1I
   if 13 - 13: OoO0O00 - II111iiii . iII111i + OoOoOO00 / i11iIiiIii
   if 32 - 32: ooOoO0o / II111iiii / I1ii11iIi11i
   if 34 - 34: iIii1I11I1II1
  if ( IiiiI1I . merge_register_requested ) :
   if ( IiIII1iii1iII . merge_in_site_eid ( iI1II1i1I1Ii ) ) :
    IiI1I1I1 . append ( [ OOOoOooO . eid , OOOoOooO . group ] )
    if 47 - 47: OOooOOo * iII111i
   if ( IiiiI1I . map_notify_requested ) :
    lisp_send_merged_map_notify ( lisp_sockets , IiIII1iii1iII , IiiiI1I ,
 OOOoOooO )
    if 71 - 71: IiII - OoooooooOO * i11iIiiIii . OoooooooOO % i1IIi . Oo0Ooo
    if 3 - 3: OoO0O00 + i11iIiiIii + oO0o * IiII
    if 19 - 19: iII111i / II111iiii . I1Ii111 * I1IiiI - OOooOOo
  if ( o0OOO0o0O0O0o0o == False ) : continue
  if ( len ( IiI1I1I1 ) != 0 ) : continue
  if 70 - 70: OoO0O00
  o0Ooo0Oo . append ( iI1II1i1I1Ii . print_eid_tuple ( ) )
  if 42 - 42: OoooooooOO - I1Ii111 + I1ii11iIi11i * iII111i * iII111i / OoO0O00
  if 85 - 85: O0 . II111iiii
  if 80 - 80: O0 * I11i * I1Ii111
  if 89 - 89: Ii1I * OoO0O00 . i1IIi . O0 - IiII - OoOoOO00
  if 25 - 25: iII111i + i1IIi
  if 64 - 64: IiII % I11i / iIii1I11I1II1
  if 66 - 66: Ii1I
  OOOoOooO = OOOoOooO . encode ( )
  OOOoOooO += IIIoO0o0oOO0O0
  OO0Ii111Ii1Ii = [ iI1II1i1I1Ii . print_eid_tuple ( ) ]
  lprint ( "    Changed RLOC-set, Map-Notifying old RLOC-set" )
  if 55 - 55: OOooOOo + I1IiiI + IiII . Ii1I * oO0o
  for i11iII1Ii1ii111 in oOO :
   if ( i11iII1Ii1ii111 . map_notify_requested == False ) : continue
   if ( i11iII1Ii1ii111 . rloc . is_exact_match ( source ) ) : continue
   lisp_build_map_notify ( lisp_sockets , OOOoOooO , OO0Ii111Ii1Ii , 1 , i11iII1Ii1ii111 . rloc ,
 LISP_CTRL_PORT , IiiiI1I . nonce , IiiiI1I . key_id ,
 IiiiI1I . alg_id , IiiiI1I . auth_len , ooIiIII11IIIi1 , False )
   if 71 - 71: IiII - iII111i % I1IiiI * iII111i
   if 27 - 27: ooOoO0o - OoO0O00
   if 83 - 83: iII111i * OoOoOO00 - O0 * Ii1I
   if 79 - 79: I11i / iII111i % Ii1I / OoOoOO00 % O0 / IiII
   if 32 - 32: IiII * II111iiii . Ii1I
  lisp_notify_subscribers ( lisp_sockets , OOOoOooO , iI1II1i1I1Ii . eid , ooIiIII11IIIi1 )
  if 68 - 68: I11i / O0
  if 6 - 6: oO0o - oO0o . I1IiiI % I1ii11iIi11i
  if 22 - 22: Ii1I / I1IiiI / II111iiii
  if 31 - 31: II111iiii - Ii1I * OOooOOo - i11iIiiIii / OoooooooOO - I1Ii111
  if 76 - 76: Oo0Ooo
 if ( len ( IiI1I1I1 ) != 0 ) :
  lisp_queue_multicast_map_notify ( lisp_sockets , IiI1I1I1 )
  if 93 - 93: i1IIi - I1IiiI * i11iIiiIii / Ii1I . Ii1I - i1IIi
  if 19 - 19: iIii1I11I1II1 * OOooOOo * Oo0Ooo % I1IiiI
  if 93 - 93: IiII % OoOoOO00 / I1IiiI + o0oOOo0O0Ooo * ooOoO0o / i1IIi
  if 25 - 25: O0 / Oo0Ooo - o0oOOo0O0Ooo * Oo0Ooo
  if 45 - 45: Ii1I * IiII - OOooOOo
  if 57 - 57: iII111i % OoO0O00 / OoooooooOO
 if ( IiiiI1I . merge_register_requested ) : return
 if 69 - 69: oO0o
 if 44 - 44: IiII - II111iiii % Ii1I
 if 64 - 64: Ii1I % OoO0O00 + OOooOOo % OoOoOO00 + IiII
 if 92 - 92: iII111i * Oo0Ooo - OoOoOO00
 if 33 - 33: i11iIiiIii - OoOoOO00 . OOooOOo * II111iiii . Ii1I
 if ( IiiiI1I . map_notify_requested and ooIiIII11IIIi1 != None ) :
  lisp_build_map_notify ( lisp_sockets , O00oOOoo00oo , o0Ooo0Oo ,
 IiiiI1I . record_count , source , sport , IiiiI1I . nonce ,
 IiiiI1I . key_id , IiiiI1I . alg_id , IiiiI1I . auth_len ,
 ooIiIII11IIIi1 , True )
  if 59 - 59: OoOoOO00
 return
 if 29 - 29: iII111i - II111iiii * OoooooooOO * OoooooooOO
 if 15 - 15: IiII / OOooOOo / iIii1I11I1II1 / OoOoOO00
 if 91 - 91: i11iIiiIii % O0 . Oo0Ooo / I1Ii111
 if 62 - 62: Oo0Ooo . II111iiii % OoO0O00 . Ii1I * OOooOOo + II111iiii
 if 7 - 7: OOooOOo
 if 22 - 22: Oo0Ooo + ooOoO0o
 if 71 - 71: OOooOOo . Ii1I * i11iIiiIii . I11i
 if 9 - 9: O0 / I1ii11iIi11i . iII111i . O0 + IiII % I11i
 if 27 - 27: i11iIiiIii - I1ii11iIi11i / O0 - i1IIi + I1IiiI * iII111i
 if 26 - 26: Oo0Ooo . Ii1I
def lisp_process_multicast_map_notify ( packet , source ) :
 o0o00ooo0O = lisp_map_notify ( "" )
 packet = o0o00ooo0O . decode ( packet )
 if ( packet == None ) :
  lprint ( "Could not decode Map-Notify packet" )
  return
  if 7 - 7: OoOoOO00 - o0oOOo0O0Ooo + oO0o
  if 8 - 8: iIii1I11I1II1
 o0o00ooo0O . print_notify ( )
 if ( o0o00ooo0O . record_count == 0 ) : return
 if 6 - 6: oO0o
 o0OooooOO = o0o00ooo0O . eid_records
 if 47 - 47: I1IiiI + OoOoOO00 - I1ii11iIi11i + iII111i * oO0o / IiII
 for iiIii1I in range ( o0o00ooo0O . record_count ) :
  OOOoOooO = lisp_eid_record ( )
  o0OooooOO = OOOoOooO . decode ( o0OooooOO )
  if ( packet == None ) : return
  OOOoOooO . print_record ( "  " , False )
  if 33 - 33: II111iiii % oO0o + ooOoO0o . iII111i
  if 77 - 77: oO0o - I1Ii111 % o0oOOo0O0Ooo - I1IiiI * i1IIi
  if 5 - 5: I1IiiI
  if 22 - 22: II111iiii / iII111i
  O0O = lisp_map_cache_lookup ( OOOoOooO . eid , OOOoOooO . group )
  if ( O0O == None ) :
   O0O = lisp_mapping ( OOOoOooO . eid , OOOoOooO . group , [ ] )
   O0O . add_cache ( )
   if 18 - 18: i11iIiiIii * ooOoO0o . I1IiiI + i1IIi + I11i
   if 62 - 62: O0 % o0oOOo0O0Ooo + iIii1I11I1II1 + iIii1I11I1II1 * ooOoO0o
  O0O . mapping_source = None if source == "lisp-etr" else source
  O0O . map_cache_ttl = OOOoOooO . store_ttl ( )
  if 21 - 21: o0oOOo0O0Ooo % O0
  if 81 - 81: i1IIi + i1IIi
  if 3 - 3: I1Ii111 . I1ii11iIi11i * iII111i * i11iIiiIii * IiII
  if 52 - 52: iIii1I11I1II1 % o0oOOo0O0Ooo % I1IiiI
  if 71 - 71: I1IiiI + iII111i
  if ( len ( O0O . rloc_set ) != 0 and OOOoOooO . rloc_count == 0 ) :
   O0O . rloc_set = [ ]
   O0O . build_best_rloc_set ( )
   lisp_write_ipc_map_cache ( True , O0O )
   lprint ( "Update {} map-cache entry with no RLOC-set" . format ( green ( O0O . print_eid_tuple ( ) , False ) ) )
   if 47 - 47: iIii1I11I1II1 . OoO0O00 . iIii1I11I1II1
   continue
   if 57 - 57: IiII * ooOoO0o * ooOoO0o * iIii1I11I1II1 * I1Ii111 + OoOoOO00
   if 83 - 83: OoOoOO00 . Oo0Ooo . OoO0O00
  o0oOo00OOoO0O = O0O . rtrs_in_rloc_set ( )
  if 32 - 32: I1ii11iIi11i + OOooOOo - I11i
  if 82 - 82: Oo0Ooo % Oo0Ooo
  if 91 - 91: I11i
  if 98 - 98: I11i - II111iiii . IiII % Oo0Ooo
  if 65 - 65: OoO0O00
  for o0oIIi1 in range ( OOOoOooO . rloc_count ) :
   oO0oO = lisp_rloc_record ( )
   o0OooooOO = oO0oO . decode ( o0OooooOO , None )
   oO0oO . print_record ( "    " )
   if ( OOOoOooO . group . is_null ( ) ) : continue
   if ( oO0oO . rle == None ) : continue
   if 65 - 65: oO0o
   if 77 - 77: I11i * i1IIi - OOooOOo / OoOoOO00
   if 50 - 50: O0 - oO0o . oO0o
   if 98 - 98: IiII % Ii1I / Ii1I
   if 10 - 10: Ii1I
   O0oo0Oo0Oo00o = O0O . rloc_set [ 0 ] . stats if len ( O0O . rloc_set ) != 0 else None
   if 94 - 94: O0 + II111iiii - iII111i / i1IIi
   if 25 - 25: ooOoO0o . OoO0O00 - oO0o
   if 76 - 76: iIii1I11I1II1 / II111iiii * OoOoOO00 % iII111i . II111iiii + i11iIiiIii
   if 41 - 41: oO0o . o0oOOo0O0Ooo . I11i
   i11iII1Ii1ii111 = lisp_rloc ( )
   i11iII1Ii1ii111 . store_rloc_from_record ( oO0oO , None , O0O . mapping_source )
   if ( O0oo0Oo0Oo00o != None ) : i11iII1Ii1ii111 . stats = copy . deepcopy ( O0oo0Oo0Oo00o )
   if 53 - 53: I11i
   if ( o0oOo00OOoO0O and i11iII1Ii1ii111 . is_rtr ( ) == False ) : continue
   if 64 - 64: OoO0O00 + I11i / I1IiiI . II111iiii
   O0O . rloc_set = [ i11iII1Ii1ii111 ]
   O0O . build_best_rloc_set ( )
   lisp_write_ipc_map_cache ( True , O0O )
   if 79 - 79: I1Ii111 + IiII / OoooooooOO
   lprint ( "Update {} map-cache entry with RLE {}" . format ( green ( O0O . print_eid_tuple ( ) , False ) , i11iII1Ii1ii111 . rle . print_rle ( False ) ) )
   if 53 - 53: Ii1I
   if 85 - 85: OoO0O00 + II111iiii / OoO0O00 . II111iiii * OoOoOO00 * I1IiiI
   if 19 - 19: iII111i / Ii1I + iIii1I11I1II1 * O0 - Oo0Ooo
 return
 if 47 - 47: iIii1I11I1II1 % I1ii11iIi11i
 if 33 - 33: oO0o . oO0o / IiII + II111iiii
 if 34 - 34: OoO0O00 . OoOoOO00 / i1IIi / OOooOOo
 if 12 - 12: o0oOOo0O0Ooo . Oo0Ooo / II111iiii
 if 18 - 18: I1Ii111 % II111iiii + Ii1I * Oo0Ooo - OoooooooOO . Oo0Ooo
 if 25 - 25: OoO0O00
 if 83 - 83: II111iiii . iIii1I11I1II1
 if 77 - 77: O0 . OoOoOO00 % oO0o / OOooOOo
def lisp_process_map_notify ( lisp_sockets , orig_packet , source ) :
 o0o00ooo0O = lisp_map_notify ( "" )
 I1i1iI = o0o00ooo0O . decode ( orig_packet )
 if ( I1i1iI == None ) :
  lprint ( "Could not decode Map-Notify packet" )
  return
  if 8 - 8: iII111i - i1IIi
  if 81 - 81: ooOoO0o / OOooOOo % OoOoOO00 . iIii1I11I1II1
 o0o00ooo0O . print_notify ( )
 if 45 - 45: I1IiiI . ooOoO0o - OoooooooOO
 if 84 - 84: I1ii11iIi11i
 if 69 - 69: I1Ii111 + II111iiii
 if 92 - 92: OoooooooOO
 if 80 - 80: I1ii11iIi11i % I1ii11iIi11i . OoO0O00 . oO0o % I1IiiI % I11i
 I11iiIi1i1 = source . print_address ( )
 if ( o0o00ooo0O . alg_id != 0 or o0o00ooo0O . auth_len != 0 ) :
  iIoO0oOOoOoO = None
  for i1i11ii1 in lisp_map_servers_list :
   if ( i1i11ii1 . find ( I11iiIi1i1 ) == - 1 ) : continue
   iIoO0oOOoOoO = lisp_map_servers_list [ i1i11ii1 ]
   if 4 - 4: OoO0O00 / iII111i / I1ii11iIi11i - o0oOOo0O0Ooo * I1Ii111
  if ( iIoO0oOOoOoO == None ) :
   lprint ( ( "  Could not find Map-Server {} to authenticate " + "Map-Notify" ) . format ( I11iiIi1i1 ) )
   if 24 - 24: OoooooooOO / ooOoO0o + Oo0Ooo - OOooOOo - o0oOOo0O0Ooo . I1ii11iIi11i
   return
   if 2 - 2: I1IiiI . o0oOOo0O0Ooo / Oo0Ooo - OoOoOO00 - OoooooooOO
   if 73 - 73: I1Ii111 . i11iIiiIii * ooOoO0o . IiII - I11i + I1Ii111
  iIoO0oOOoOoO . map_notifies_received += 1
  if 21 - 21: I1Ii111 + iIii1I11I1II1 + I1IiiI / O0 * I1ii11iIi11i
  IiI111II1I1iI = lisp_verify_auth ( I1i1iI , o0o00ooo0O . alg_id ,
 o0o00ooo0O . auth_data , iIoO0oOOoOoO . password )
  if 57 - 57: OOooOOo * I11i . oO0o
  lprint ( "  Authentication {} for Map-Notify" . format ( "succeeded" if IiI111II1I1iI else "failed" ) )
  if 17 - 17: iII111i - OOooOOo * I1IiiI + i1IIi % I1ii11iIi11i
  if ( IiI111II1I1iI == False ) : return
 else :
  iIoO0oOOoOoO = lisp_ms ( I11iiIi1i1 , None , "" , 0 , "" , False , False , False , False , 0 , 0 )
  if 71 - 71: Ii1I - o0oOOo0O0Ooo - oO0o
  if 27 - 27: O0 - iIii1I11I1II1
  if 78 - 78: Oo0Ooo / o0oOOo0O0Ooo
  if 35 - 35: o0oOOo0O0Ooo . OoO0O00 / o0oOOo0O0Ooo / IiII - I1ii11iIi11i . Oo0Ooo
  if 97 - 97: i11iIiiIii + I1ii11iIi11i - I11i . oO0o
  if 76 - 76: IiII * II111iiii * I1ii11iIi11i + OoooooooOO - OoOoOO00 . Ii1I
 o0OooooOO = o0o00ooo0O . eid_records
 if ( o0o00ooo0O . record_count == 0 ) :
  lisp_send_map_notify_ack ( lisp_sockets , o0OooooOO , o0o00ooo0O , iIoO0oOOoOoO )
  return
  if 51 - 51: II111iiii % I1Ii111 * O0 . ooOoO0o * OoOoOO00
  if 17 - 17: I1IiiI % I11i
  if 28 - 28: I1ii11iIi11i * OoooooooOO
  if 19 - 19: Oo0Ooo - iII111i % OoOoOO00 * i11iIiiIii / oO0o . i11iIiiIii
  if 46 - 46: I1ii11iIi11i
  if 50 - 50: OOooOOo * OoO0O00 * OOooOOo % I1IiiI - I1Ii111 * Ii1I
  if 88 - 88: OOooOOo . iII111i / I11i
  if 1 - 1: iIii1I11I1II1 - Oo0Ooo % OoooooooOO
 OOOoOooO = lisp_eid_record ( )
 I1i1iI = OOOoOooO . decode ( o0OooooOO )
 if ( I1i1iI == None ) : return
 if 71 - 71: OOooOOo - Ii1I
 OOOoOooO . print_record ( "  " , False )
 if 68 - 68: ooOoO0o
 for o0oIIi1 in range ( OOOoOooO . rloc_count ) :
  oO0oO = lisp_rloc_record ( )
  I1i1iI = oO0oO . decode ( I1i1iI , None )
  if ( I1i1iI == None ) :
   lprint ( "  Could not decode RLOC-record in Map-Notify packet" )
   return
   if 35 - 35: IiII . iIii1I11I1II1 + Ii1I % O0
  oO0oO . print_record ( "    " )
  if 94 - 94: OoOoOO00 + II111iiii . II111iiii + ooOoO0o + ooOoO0o
  if 95 - 95: iIii1I11I1II1 / i11iIiiIii - IiII - OOooOOo
  if 4 - 4: II111iiii + oO0o + o0oOOo0O0Ooo % IiII % iIii1I11I1II1
  if 68 - 68: i11iIiiIii
  if 79 - 79: OoOoOO00 * Ii1I / I1ii11iIi11i + OOooOOo
 if ( OOOoOooO . group . is_null ( ) == False ) :
  if 19 - 19: I1IiiI + I11i + I1IiiI + OoO0O00
  if 33 - 33: i11iIiiIii - Ii1I * II111iiii
  if 97 - 97: OoO0O00 / o0oOOo0O0Ooo * iIii1I11I1II1
  if 5 - 5: I1IiiI
  if 27 - 27: i1IIi + oO0o / I1ii11iIi11i + oO0o
  lprint ( "Send {} Map-Notify IPC message to ITR process" . format ( green ( OOOoOooO . print_eid_tuple ( ) , False ) ) )
  if 98 - 98: II111iiii + iIii1I11I1II1
  if 70 - 70: I11i / OoooooooOO / i11iIiiIii
  II1i111i = lisp_control_packet_ipc ( orig_packet , I11iiIi1i1 , "lisp-itr" , 0 )
  lisp_ipc ( II1i111i , lisp_sockets [ 2 ] , "lisp-core-pkt" )
  if 61 - 61: O0 . Oo0Ooo . iIii1I11I1II1
  if 54 - 54: OOooOOo * I1ii11iIi11i + OoooooooOO
  if 58 - 58: i1IIi - OoooooooOO * OOooOOo . ooOoO0o + O0 + o0oOOo0O0Ooo
  if 87 - 87: OOooOOo + I1Ii111 + O0 / oO0o / i11iIiiIii
  if 60 - 60: O0 . II111iiii
 lisp_send_map_notify_ack ( lisp_sockets , o0OooooOO , o0o00ooo0O , iIoO0oOOoOoO )
 return
 if 69 - 69: II111iiii / ooOoO0o - OoOoOO00 / OOooOOo
 if 52 - 52: OoO0O00 % I11i + o0oOOo0O0Ooo % OoOoOO00
 if 46 - 46: o0oOOo0O0Ooo % O0
 if 30 - 30: oO0o
 if 64 - 64: O0
 if 70 - 70: oO0o % I1IiiI . iIii1I11I1II1 - Oo0Ooo + OoOoOO00 % O0
 if 91 - 91: I1Ii111 - oO0o * ooOoO0o - I1ii11iIi11i + IiII + O0
 if 18 - 18: OoOoOO00 / IiII / o0oOOo0O0Ooo . OOooOOo
def lisp_process_map_notify_ack ( packet , source ) :
 o0o00ooo0O = lisp_map_notify ( "" )
 packet = o0o00ooo0O . decode ( packet )
 if ( packet == None ) :
  lprint ( "Could not decode Map-Notify-Ack packet" )
  return
  if 35 - 35: I11i . ooOoO0o % I11i / iII111i / O0 % I11i
  if 29 - 29: I1Ii111 + Ii1I
 o0o00ooo0O . print_notify ( )
 if 100 - 100: Ii1I + I1Ii111 / iIii1I11I1II1 / i1IIi % OoOoOO00
 if 6 - 6: oO0o + ooOoO0o
 if 13 - 13: Oo0Ooo . IiII % iII111i + i1IIi / OOooOOo
 if 1 - 1: I11i * i1IIi * Oo0Ooo % O0
 if 41 - 41: OOooOOo % OoOoOO00
 if ( o0o00ooo0O . record_count < 1 ) :
  lprint ( "No EID-prefix found, cannot authenticate Map-Notify-Ack" )
  return
  if 82 - 82: I11i . IiII
  if 27 - 27: I1Ii111 % O0 * OoooooooOO . Oo0Ooo
 OOOoOooO = lisp_eid_record ( )
 if 51 - 51: I11i
 if ( OOOoOooO . decode ( o0o00ooo0O . eid_records ) == None ) :
  lprint ( "Could not decode EID-record, cannot authenticate " +
 "Map-Notify-Ack" )
  return
  if 80 - 80: Oo0Ooo + oO0o
 OOOoOooO . print_record ( "  " , False )
 if 76 - 76: I1IiiI * OoooooooOO - i11iIiiIii / I11i / Oo0Ooo
 I1I1iII1i = OOOoOooO . print_eid_tuple ( )
 if 82 - 82: IiII % ooOoO0o
 if 100 - 100: Oo0Ooo . oO0o - iII111i + OoooooooOO
 if 27 - 27: Oo0Ooo . I1Ii111 - i1IIi * I1IiiI
 if 96 - 96: I1ii11iIi11i - Ii1I . I1ii11iIi11i
 if ( o0o00ooo0O . alg_id != LISP_NONE_ALG_ID and o0o00ooo0O . auth_len != 0 ) :
  iI1II1i1I1Ii = lisp_sites_by_eid . lookup_cache ( OOOoOooO . eid , True )
  if ( iI1II1i1I1Ii == None ) :
   oo0 = bold ( "Site not found" , False )
   lprint ( ( "{} for EID {}, cannot authenticate Map-Notify-Ack" ) . format ( oo0 , green ( I1I1iII1i , False ) ) )
   if 89 - 89: II111iiii % I1ii11iIi11i % IiII . I11i
   return
   if 49 - 49: iII111i % i11iIiiIii * I11i - oO0o . OOooOOo . i11iIiiIii
  ooIiIII11IIIi1 = iI1II1i1I1Ii . site
  if 26 - 26: iIii1I11I1II1 + i11iIiiIii % iII111i + I1IiiI + oO0o - ooOoO0o
  if 4 - 4: Oo0Ooo - IiII - I11i
  if 72 - 72: OoooooooOO
  if 19 - 19: Oo0Ooo . OOooOOo
  ooIiIII11IIIi1 . map_notify_acks_received += 1
  if 58 - 58: IiII % iII111i + i1IIi % I1IiiI % OOooOOo . iII111i
  iI11i = o0o00ooo0O . key_id
  if ( ooIiIII11IIIi1 . auth_key . has_key ( iI11i ) == False ) : iI11i = 0
  OoIiIii1 = ooIiIII11IIIi1 . auth_key [ iI11i ]
  if 85 - 85: i11iIiiIii . o0oOOo0O0Ooo * iII111i . I1ii11iIi11i / I1Ii111 % Ii1I
  IiI111II1I1iI = lisp_verify_auth ( packet , o0o00ooo0O . alg_id ,
 o0o00ooo0O . auth_data , OoIiIii1 )
  if 27 - 27: II111iiii . iIii1I11I1II1 / I1ii11iIi11i / i1IIi / iIii1I11I1II1
  iI11i = "key-id {}" . format ( iI11i ) if iI11i == o0o00ooo0O . key_id else "bad key-id {}" . format ( o0o00ooo0O . key_id )
  if 70 - 70: i11iIiiIii . OoO0O00 / OoooooooOO * OoooooooOO - OOooOOo
  if 34 - 34: I1ii11iIi11i * i1IIi % OoooooooOO / I1IiiI
  lprint ( "  Authentication {} for Map-Notify-Ack, {}" . format ( "succeeded" if IiI111II1I1iI else "failed" , iI11i ) )
  if 39 - 39: OoO0O00 + IiII - II111iiii % I11i
  if ( IiI111II1I1iI == False ) : return
  if 80 - 80: o0oOOo0O0Ooo * ooOoO0o
  if 87 - 87: I1Ii111 + O0 / I1ii11iIi11i / OoOoOO00 . Oo0Ooo - IiII
  if 24 - 24: OoOoOO00
  if 19 - 19: ooOoO0o
  if 43 - 43: O0 . I1Ii111 % OoooooooOO / I1IiiI . o0oOOo0O0Ooo - OoOoOO00
 if ( o0o00ooo0O . retransmit_timer ) : o0o00ooo0O . retransmit_timer . cancel ( )
 if 46 - 46: I11i - OoooooooOO % o0oOOo0O0Ooo
 oOooo0o = source . print_address ( )
 i1i11ii1 = o0o00ooo0O . nonce_key
 if 7 - 7: OoooooooOO - I1Ii111 * IiII
 if ( lisp_map_notify_queue . has_key ( i1i11ii1 ) ) :
  o0o00ooo0O = lisp_map_notify_queue . pop ( i1i11ii1 )
  if ( o0o00ooo0O . retransmit_timer ) : o0o00ooo0O . retransmit_timer . cancel ( )
  lprint ( "Dequeue Map-Notify from retransmit queue, key is: {}" . format ( i1i11ii1 ) )
  if 20 - 20: o0oOOo0O0Ooo . OoooooooOO * I1IiiI . Oo0Ooo * OoOoOO00
 else :
  lprint ( "Map-Notify with nonce 0x{} queue entry not found for {}" . format ( o0o00ooo0O . nonce_key , red ( oOooo0o , False ) ) )
  if 3 - 3: I1Ii111 % i11iIiiIii % O0 % II111iiii
  if 8 - 8: OoooooooOO * ooOoO0o
 return
 if 26 - 26: i11iIiiIii + oO0o - i1IIi
 if 71 - 71: I1IiiI % I1Ii111 / oO0o % oO0o / iIii1I11I1II1 + I1Ii111
 if 86 - 86: IiII % i1IIi * o0oOOo0O0Ooo - I1Ii111
 if 37 - 37: iII111i % I1IiiI - I1ii11iIi11i % I11i
 if 35 - 35: O0 - OoooooooOO % iII111i
 if 48 - 48: OOooOOo % i11iIiiIii
 if 49 - 49: O0 * iII111i + II111iiii - OOooOOo
 if 29 - 29: OoooooooOO % II111iiii - Oo0Ooo / IiII - i11iIiiIii
def lisp_map_referral_loop ( mr , eid , group , action , s ) :
 if ( action not in ( LISP_DDT_ACTION_NODE_REFERRAL ,
 LISP_DDT_ACTION_MS_REFERRAL ) ) : return ( False )
 if 64 - 64: iII111i . I1Ii111 + I1Ii111
 if ( mr . last_cached_prefix [ 0 ] == None ) : return ( False )
 if 1 - 1: OOooOOo % Oo0Ooo
 if 81 - 81: oO0o / I11i % Ii1I . I11i + OoooooooOO
 if 31 - 31: OoO0O00
 if 41 - 41: i11iIiiIii - I1ii11iIi11i - II111iiii
 oO000O000o0Oo = False
 if ( group . is_null ( ) == False ) :
  oO000O000o0Oo = mr . last_cached_prefix [ 1 ] . is_more_specific ( group )
  if 5 - 5: OoOoOO00 + i1IIi
 if ( oO000O000o0Oo == False ) :
  oO000O000o0Oo = mr . last_cached_prefix [ 0 ] . is_more_specific ( eid )
  if 43 - 43: iII111i * I1IiiI
  if 20 - 20: I1IiiI . I11i * OoO0O00 . ooOoO0o . II111iiii
 if ( oO000O000o0Oo ) :
  ii1IOo0OOoo = lisp_print_eid_tuple ( eid , group )
  I11II11iiII1 = lisp_print_eid_tuple ( mr . last_cached_prefix [ 0 ] ,
 mr . last_cached_prefix [ 1 ] )
  if 42 - 42: oO0o * IiII
  lprint ( ( "Map-Referral prefix {} from {} is not more-specific " + "than cached prefix {}" ) . format ( green ( ii1IOo0OOoo , False ) , s ,
  # I1Ii111 % OoooooooOO % ooOoO0o
 I11II11iiII1 ) )
  if 17 - 17: I1ii11iIi11i + o0oOOo0O0Ooo / OoO0O00 . Oo0Ooo - o0oOOo0O0Ooo / oO0o
 return ( oO000O000o0Oo )
 if 87 - 87: ooOoO0o
 if 74 - 74: i11iIiiIii . i11iIiiIii . iIii1I11I1II1
 if 100 - 100: i11iIiiIii - oO0o + iIii1I11I1II1 * OoOoOO00 % OOooOOo % i11iIiiIii
 if 26 - 26: O0
 if 97 - 97: OOooOOo + I11i % I1Ii111 % i11iIiiIii / I1ii11iIi11i
 if 21 - 21: O0 + iIii1I11I1II1 / i11iIiiIii . OOooOOo * i1IIi
 if 3 - 3: i1IIi % o0oOOo0O0Ooo + OoOoOO00
def lisp_process_map_referral ( lisp_sockets , packet , source ) :
 if 32 - 32: OoO0O00 . Oo0Ooo * iIii1I11I1II1
 oOo0ooOO0ooOo = lisp_map_referral ( )
 packet = oOo0ooOO0ooOo . decode ( packet )
 if ( packet == None ) :
  lprint ( "Could not decode Map-Referral packet" )
  return
  if 12 - 12: O0 + I1ii11iIi11i + I11i . I1Ii111
 oOo0ooOO0ooOo . print_map_referral ( )
 if 48 - 48: Ii1I . iIii1I11I1II1 - iIii1I11I1II1 * I11i . OoooooooOO
 I11iiIi1i1 = source . print_address ( )
 iII = oOo0ooOO0ooOo . nonce
 if 73 - 73: Ii1I / II111iiii - iIii1I11I1II1 . ooOoO0o * II111iiii . OOooOOo
 if 50 - 50: iIii1I11I1II1 + OoOoOO00 % O0 + OoO0O00 . i11iIiiIii / oO0o
 if 31 - 31: I1IiiI % o0oOOo0O0Ooo . i11iIiiIii % OOooOOo - iIii1I11I1II1
 if 77 - 77: i11iIiiIii / OOooOOo
 for iiIii1I in range ( oOo0ooOO0ooOo . record_count ) :
  OOOoOooO = lisp_eid_record ( )
  packet = OOOoOooO . decode ( packet )
  if ( packet == None ) :
   lprint ( "Could not decode EID-record in Map-Referral packet" )
   return
   if 93 - 93: I1ii11iIi11i - iII111i % O0 - Ii1I
  OOOoOooO . print_record ( "  " , True )
  if 84 - 84: I1ii11iIi11i . iIii1I11I1II1 % IiII * I11i + ooOoO0o
  if 59 - 59: oO0o * OoO0O00 - I11i * I1IiiI
  if 60 - 60: iII111i - OoooooooOO / iII111i % OoO0O00 . OoOoOO00 - o0oOOo0O0Ooo
  if 71 - 71: iII111i * o0oOOo0O0Ooo * i11iIiiIii * O0
  i1i11ii1 = str ( iII )
  if ( i1i11ii1 not in lisp_ddt_map_requestQ ) :
   lprint ( ( "Map-Referral nonce 0x{} from {} not found in " + "Map-Request queue, EID-record ignored" ) . format ( lisp_hex_string ( iII ) , I11iiIi1i1 ) )
   if 77 - 77: OOooOOo % iII111i + I11i / OoOoOO00
   if 50 - 50: OoOoOO00 - i11iIiiIii - OOooOOo . iIii1I11I1II1
   continue
   if 97 - 97: oO0o % OOooOOo . OoooooooOO * Ii1I
  IiIiiiI11 = lisp_ddt_map_requestQ [ i1i11ii1 ]
  if ( IiIiiiI11 == None ) :
   lprint ( ( "No Map-Request queue entry found for Map-Referral " +
 "nonce 0x{} from {}, EID-record ignored" ) . format ( lisp_hex_string ( iII ) , I11iiIi1i1 ) )
   if 100 - 100: I1ii11iIi11i / Ii1I % Oo0Ooo
   continue
   if 83 - 83: O0 . I1Ii111 % I1ii11iIi11i
   if 97 - 97: Oo0Ooo % OoO0O00 * I1ii11iIi11i * ooOoO0o * OoO0O00
   if 12 - 12: ooOoO0o
   if 56 - 56: i1IIi
   if 3 - 3: OOooOOo - Oo0Ooo * Ii1I + i11iIiiIii
   if 53 - 53: i1IIi % I1ii11iIi11i
  if ( lisp_map_referral_loop ( IiIiiiI11 , OOOoOooO . eid , OOOoOooO . group ,
 OOOoOooO . action , I11iiIi1i1 ) ) :
   IiIiiiI11 . dequeue_map_request ( )
   continue
   if 65 - 65: I11i + OoOoOO00 - i11iIiiIii
   if 72 - 72: i11iIiiIii - iII111i . i11iIiiIii
  IiIiiiI11 . last_cached_prefix [ 0 ] = OOOoOooO . eid
  IiIiiiI11 . last_cached_prefix [ 1 ] = OOOoOooO . group
  if 61 - 61: oO0o . i11iIiiIii / Ii1I % iII111i
  if 36 - 36: OoO0O00 + Ii1I / I11i - iII111i % OoO0O00 / Oo0Ooo
  if 38 - 38: Ii1I - ooOoO0o - O0 + oO0o . iIii1I11I1II1
  if 90 - 90: i1IIi * OoOoOO00
  i1111I = False
  iiIIIIi1 = lisp_referral_cache_lookup ( OOOoOooO . eid , OOOoOooO . group ,
 True )
  if ( iiIIIIi1 == None ) :
   i1111I = True
   iiIIIIi1 = lisp_referral ( )
   iiIIIIi1 . eid = OOOoOooO . eid
   iiIIIIi1 . group = OOOoOooO . group
   if ( OOOoOooO . ddt_incomplete == False ) : iiIIIIi1 . add_cache ( )
  elif ( iiIIIIi1 . referral_source . not_set ( ) ) :
   lprint ( "Do not replace static referral entry {}" . format ( green ( iiIIIIi1 . print_eid_tuple ( ) , False ) ) )
   if 27 - 27: iIii1I11I1II1
   IiIiiiI11 . dequeue_map_request ( )
   continue
   if 95 - 95: iII111i / ooOoO0o % Ii1I
   if 44 - 44: OOooOOo . OOooOOo
  OOoooO = OOOoOooO . action
  iiIIIIi1 . referral_source = source
  iiIIIIi1 . referral_type = OOoooO
  o0O0OOo0oo00 = OOOoOooO . store_ttl ( )
  iiIIIIi1 . referral_ttl = o0O0OOo0oo00
  iiIIIIi1 . expires = lisp_set_timestamp ( o0O0OOo0oo00 )
  if 5 - 5: oO0o + OoooooooOO
  if 88 - 88: oO0o + OOooOOo
  if 14 - 14: I11i / i1IIi
  if 56 - 56: OoooooooOO
  oOOOO00 = iiIIIIi1 . is_referral_negative ( )
  if ( iiIIIIi1 . referral_set . has_key ( I11iiIi1i1 ) ) :
   iiiiiIIiI = iiIIIIi1 . referral_set [ I11iiIi1i1 ]
   if 78 - 78: I1IiiI . II111iiii
   if ( iiiiiIIiI . updown == False and oOOOO00 == False ) :
    iiiiiIIiI . updown = True
    lprint ( "Change up/down status for referral-node {} to up" . format ( I11iiIi1i1 ) )
    if 70 - 70: I1ii11iIi11i / i11iIiiIii . O0 . Ii1I - i1IIi % o0oOOo0O0Ooo
   elif ( iiiiiIIiI . updown == True and oOOOO00 == True ) :
    iiiiiIIiI . updown = False
    lprint ( ( "Change up/down status for referral-node {} " + "to down, received negative referral" ) . format ( I11iiIi1i1 ) )
    if 86 - 86: i1IIi
    if 15 - 15: iII111i - O0 / i11iIiiIii % i11iIiiIii % OoOoOO00 + o0oOOo0O0Ooo
    if 81 - 81: Oo0Ooo * OoOoOO00 - Oo0Ooo
    if 32 - 32: i1IIi . I11i - IiII % OoO0O00 % iIii1I11I1II1 - OoooooooOO
    if 47 - 47: OoO0O00 + II111iiii . IiII - I11i . iII111i . o0oOOo0O0Ooo
    if 31 - 31: I1IiiI + O0 . I1IiiI - iII111i - I1Ii111
    if 88 - 88: iII111i * OoO0O00 % OoooooooOO / oO0o
    if 7 - 7: i1IIi
  iIi = { }
  for i1i11ii1 in iiIIIIi1 . referral_set : iIi [ i1i11ii1 ] = None
  if 23 - 23: OOooOOo / i1IIi + oO0o % iII111i - o0oOOo0O0Ooo
  if 44 - 44: oO0o % OoO0O00
  if 76 - 76: I11i
  if 66 - 66: i11iIiiIii - II111iiii
  for iiIii1I in range ( OOOoOooO . rloc_count ) :
   oO0oO = lisp_rloc_record ( )
   packet = oO0oO . decode ( packet , None )
   if ( packet == None ) :
    lprint ( "Could not decode RLOC-record in Map-Referral packet" )
    return
    if 60 - 60: Ii1I - i1IIi . ooOoO0o + O0
   oO0oO . print_record ( "    " )
   if 7 - 7: iIii1I11I1II1 * OoOoOO00 % iII111i % OoO0O00 * Oo0Ooo . IiII
   if 88 - 88: o0oOOo0O0Ooo - I1IiiI . iII111i % Oo0Ooo
   if 14 - 14: I1IiiI - I1Ii111 % I1IiiI - II111iiii
   if 34 - 34: I1ii11iIi11i * IiII / II111iiii / ooOoO0o * oO0o
   oO00o = oO0oO . rloc . print_address ( )
   if ( iiIIIIi1 . referral_set . has_key ( oO00o ) == False ) :
    iiiiiIIiI = lisp_referral_node ( )
    iiiiiIIiI . referral_address . copy_address ( oO0oO . rloc )
    iiIIIIi1 . referral_set [ oO00o ] = iiiiiIIiI
    if ( I11iiIi1i1 == oO00o and oOOOO00 ) : iiiiiIIiI . updown = False
   else :
    iiiiiIIiI = iiIIIIi1 . referral_set [ oO00o ]
    if ( iIi . has_key ( oO00o ) ) : iIi . pop ( oO00o )
    if 3 - 3: II111iiii
   iiiiiIIiI . priority = oO0oO . priority
   iiiiiIIiI . weight = oO0oO . weight
   if 61 - 61: oO0o . I1IiiI + i1IIi
   if 69 - 69: O0 / i1IIi - OoOoOO00 + ooOoO0o - oO0o
   if 80 - 80: o0oOOo0O0Ooo % O0 * I11i . i1IIi - ooOoO0o
   if 93 - 93: OoooooooOO / o0oOOo0O0Ooo
   if 61 - 61: II111iiii / i1IIi . I1ii11iIi11i % iIii1I11I1II1
  for i1i11ii1 in iIi : iiIIIIi1 . referral_set . pop ( i1i11ii1 )
  if 66 - 66: iIii1I11I1II1 % OoOoOO00 + i1IIi * i11iIiiIii * OoooooooOO
  I1I1iII1i = iiIIIIi1 . print_eid_tuple ( )
  if 36 - 36: iII111i - OoO0O00 + I1IiiI + Ii1I . OoooooooOO
  if ( i1111I ) :
   if ( OOOoOooO . ddt_incomplete ) :
    lprint ( "Suppress add {} to referral-cache" . format ( green ( I1I1iII1i , False ) ) )
    if 75 - 75: oO0o * Oo0Ooo * O0
   else :
    lprint ( "Add {}, referral-count {} to referral-cache" . format ( green ( I1I1iII1i , False ) , OOOoOooO . rloc_count ) )
    if 22 - 22: ooOoO0o / OoooooooOO . II111iiii / Ii1I * OoO0O00 . i1IIi
    if 62 - 62: oO0o % Ii1I - Ii1I
  else :
   lprint ( "Replace {}, referral-count: {} in referral-cache" . format ( green ( I1I1iII1i , False ) , OOOoOooO . rloc_count ) )
   if 16 - 16: OoO0O00 - O0 - OOooOOo - I11i % OoOoOO00
   if 7 - 7: I1Ii111 / OoOoOO00 . II111iiii
   if 9 - 9: I11i . I11i . OoooooooOO
   if 42 - 42: iII111i / oO0o / iII111i * OoO0O00
   if 25 - 25: OoOoOO00 - II111iiii + II111iiii . Ii1I * II111iiii
   if 12 - 12: IiII / Ii1I
  if ( OOoooO == LISP_DDT_ACTION_DELEGATION_HOLE ) :
   lisp_send_negative_map_reply ( IiIiiiI11 . lisp_sockets , iiIIIIi1 . eid ,
 iiIIIIi1 . group , IiIiiiI11 . nonce , IiIiiiI11 . itr , IiIiiiI11 . sport , 15 , None , False )
   IiIiiiI11 . dequeue_map_request ( )
   if 54 - 54: Oo0Ooo + Ii1I % OoooooooOO * OOooOOo / OoOoOO00
   if 39 - 39: I1IiiI % i11iIiiIii % Ii1I
  if ( OOoooO == LISP_DDT_ACTION_NOT_AUTH ) :
   if ( IiIiiiI11 . tried_root ) :
    lisp_send_negative_map_reply ( IiIiiiI11 . lisp_sockets , iiIIIIi1 . eid ,
 iiIIIIi1 . group , IiIiiiI11 . nonce , IiIiiiI11 . itr , IiIiiiI11 . sport , 0 , None , False )
    IiIiiiI11 . dequeue_map_request ( )
   else :
    lisp_send_ddt_map_request ( IiIiiiI11 , True )
    if 59 - 59: ooOoO0o % OoO0O00 / I1IiiI - II111iiii + OoooooooOO * i11iIiiIii
    if 58 - 58: IiII / Oo0Ooo + o0oOOo0O0Ooo
    if 71 - 71: Ii1I - IiII
  if ( OOoooO == LISP_DDT_ACTION_MS_NOT_REG ) :
   if ( iiIIIIi1 . referral_set . has_key ( I11iiIi1i1 ) ) :
    iiiiiIIiI = iiIIIIi1 . referral_set [ I11iiIi1i1 ]
    iiiiiIIiI . updown = False
    if 2 - 2: OoOoOO00 % IiII % OoO0O00 . i1IIi / I1Ii111 - iIii1I11I1II1
   if ( len ( iiIIIIi1 . referral_set ) == 0 ) :
    IiIiiiI11 . dequeue_map_request ( )
   else :
    lisp_send_ddt_map_request ( IiIiiiI11 , False )
    if 88 - 88: Oo0Ooo * i1IIi % OOooOOo
    if 65 - 65: iII111i . oO0o
    if 67 - 67: I1IiiI / iII111i / O0 % ooOoO0o - IiII / Ii1I
  if ( OOoooO in ( LISP_DDT_ACTION_NODE_REFERRAL ,
 LISP_DDT_ACTION_MS_REFERRAL ) ) :
   if ( IiIiiiI11 . eid . is_exact_match ( OOOoOooO . eid ) ) :
    if ( not IiIiiiI11 . tried_root ) :
     lisp_send_ddt_map_request ( IiIiiiI11 , True )
    else :
     lisp_send_negative_map_reply ( IiIiiiI11 . lisp_sockets ,
 iiIIIIi1 . eid , iiIIIIi1 . group , IiIiiiI11 . nonce , IiIiiiI11 . itr ,
 IiIiiiI11 . sport , 15 , None , False )
     IiIiiiI11 . dequeue_map_request ( )
     if 31 - 31: I11i - oO0o * ooOoO0o
   else :
    lisp_send_ddt_map_request ( IiIiiiI11 , False )
    if 64 - 64: I11i
    if 41 - 41: I1Ii111 * OoooooooOO / OoOoOO00 + OoO0O00 . OoOoOO00 + I1Ii111
    if 9 - 9: IiII . I11i . I1Ii111 / i1IIi * OoOoOO00 - O0
  if ( OOoooO == LISP_DDT_ACTION_MS_ACK ) : IiIiiiI11 . dequeue_map_request ( )
  if 3 - 3: O0 / iIii1I11I1II1 % IiII + I11i
 return
 if 43 - 43: Oo0Ooo % I11i
 if 53 - 53: OoOoOO00 % OoooooooOO * o0oOOo0O0Ooo % OoooooooOO
 if 47 - 47: iIii1I11I1II1 - OOooOOo + I1ii11iIi11i * ooOoO0o + Oo0Ooo + OoO0O00
 if 64 - 64: OoOoOO00 - OoOoOO00 . OoooooooOO + ooOoO0o
 if 100 - 100: ooOoO0o . OoooooooOO % i1IIi % OoO0O00
 if 26 - 26: OoOoOO00 * IiII
 if 76 - 76: I1IiiI + IiII * I1ii11iIi11i * I1IiiI % Ii1I + ooOoO0o
 if 46 - 46: OoOoOO00
def lisp_process_ecm ( lisp_sockets , packet , source , ecm_port ) :
 iIIIiiI = lisp_ecm ( 0 )
 packet = iIIIiiI . decode ( packet )
 if ( packet == None ) :
  lprint ( "Could not decode ECM packet" )
  return
  if 66 - 66: iII111i - O0 . I1Ii111 * i1IIi / OoO0O00 / II111iiii
  if 35 - 35: ooOoO0o * OOooOOo / I11i % I11i / OoooooooOO . I1Ii111
 iIIIiiI . print_ecm ( )
 if 70 - 70: I1ii11iIi11i % I1ii11iIi11i / oO0o
 oo = lisp_control_header ( )
 if ( oo . decode ( packet ) == None ) :
  lprint ( "Could not decode control header" )
  return
  if 85 - 85: OoOoOO00 % I11i / Oo0Ooo + I11i - Oo0Ooo
  if 20 - 20: IiII
 oO0oOI1iIiI11ii = oo . type
 del ( oo )
 if 58 - 58: OoO0O00 . Ii1I * IiII % I1ii11iIi11i % Oo0Ooo - I11i
 if ( oO0oOI1iIiI11ii != LISP_MAP_REQUEST ) :
  lprint ( "Received ECM without Map-Request inside" )
  return
  if 3 - 3: ooOoO0o
  if 30 - 30: Ii1I * iII111i . II111iiii / i1IIi
  if 77 - 77: oO0o . IiII + I1ii11iIi11i . i1IIi
  if 49 - 49: I1Ii111 . OoooooooOO / o0oOOo0O0Ooo - iII111i - iII111i - i11iIiiIii
  if 37 - 37: OOooOOo
 O0OOO0oOO = iIIIiiI . udp_sport
 lisp_process_map_request ( lisp_sockets , packet , source , ecm_port ,
 iIIIiiI . source , O0OOO0oOO , iIIIiiI . ddt , - 1 )
 return
 if 4 - 4: ooOoO0o / i11iIiiIii
 if 87 - 87: II111iiii * OoO0O00
 if 2 - 2: iIii1I11I1II1 % II111iiii * OoO0O00 * OoOoOO00 * OoooooooOO
 if 11 - 11: ooOoO0o . I1IiiI / OOooOOo - I1ii11iIi11i - OoOoOO00 % I11i
 if 11 - 11: IiII * i11iIiiIii % IiII
 if 24 - 24: OoO0O00 + ooOoO0o
 if 57 - 57: iII111i
 if 37 - 37: i1IIi - I1Ii111 + IiII * ooOoO0o
 if 43 - 43: O0 . iII111i * I11i / i11iIiiIii
 if 39 - 39: oO0o / ooOoO0o
def lisp_send_map_register ( lisp_sockets , packet , map_register , ms ) :
 if 66 - 66: iIii1I11I1II1 + I1ii11iIi11i . iIii1I11I1II1 . i1IIi / ooOoO0o - i11iIiiIii
 if 23 - 23: OoO0O00 + I1IiiI / I1ii11iIi11i * I1ii11iIi11i % ooOoO0o
 if 83 - 83: I1IiiI * i11iIiiIii - I1ii11iIi11i + I11i
 if 33 - 33: OoO0O00 . OoooooooOO % iII111i / oO0o * Ii1I + ooOoO0o
 if 29 - 29: oO0o
 if 21 - 21: i11iIiiIii . o0oOOo0O0Ooo
 if 78 - 78: Oo0Ooo
 Oo0o0OoOoOo0 = ms . map_server
 if ( lisp_decent_configured and Oo0o0OoOoOo0 . is_multicast_address ( ) and
 ( ms . map_registers_multicast_sent == 1 or ms . map_registers_sent == 1 ) ) :
  Oo0o0OoOoOo0 = copy . deepcopy ( Oo0o0OoOoOo0 )
  Oo0o0OoOoOo0 . address = 0x7f000001
  oOooO00o0O = bold ( "Bootstrap" , False )
  II1I = ms . map_server . print_address_no_iid ( )
  lprint ( "{} mapping system for peer-group {}" . format ( oOooO00o0O , II1I ) )
  if 77 - 77: oO0o % Oo0Ooo % O0
  if 51 - 51: IiII % IiII + OOooOOo . II111iiii / I1ii11iIi11i
  if 4 - 4: o0oOOo0O0Ooo % I1IiiI * o0oOOo0O0Ooo * OoOoOO00 - Ii1I
  if 61 - 61: OoooooooOO - OoOoOO00 . O0 / ooOoO0o . Ii1I
  if 41 - 41: Oo0Ooo / OoOoOO00 % I1Ii111 - O0
  if 19 - 19: I1IiiI % I1Ii111 - O0 . iIii1I11I1II1 . I11i % O0
 packet = lisp_compute_auth ( packet , map_register , ms . password )
 if 88 - 88: ooOoO0o
 if 52 - 52: iIii1I11I1II1 % ooOoO0o * iIii1I11I1II1
 if 20 - 20: i11iIiiIii * I11i
 if 29 - 29: IiII / OOooOOo
 if 39 - 39: O0 + II111iiii
 if ( ms . ekey != None ) :
  iIiIIIii1iI = ms . ekey . zfill ( 32 )
  oOOo00 = "0" * 8
  iII1IIiiI11II = chacha . ChaCha ( iIiIIIii1iI , oOOo00 ) . encrypt ( packet [ 4 : : ] )
  packet = packet [ 0 : 4 ] + iII1IIiiI11II
  Oo00OOo00O = bold ( "Encrypt" , False )
  lprint ( "{} Map-Register with key-id {}" . format ( Oo00OOo00O , ms . ekey_id ) )
  if 94 - 94: OOooOOo % I1ii11iIi11i % O0 + iII111i
  if 62 - 62: iIii1I11I1II1 . OoOoOO00 / iIii1I11I1II1 + IiII
 lprint ( "Send Map-Register to map-server {}{}" . format ( Oo0o0OoOoOo0 . print_address ( ) ,
 ", ms-name '{}'" . format ( ms . ms_name ) ) )
 lisp_send ( lisp_sockets , Oo0o0OoOoOo0 , LISP_CTRL_PORT , packet )
 return
 if 31 - 31: Ii1I . OoO0O00 . Ii1I + OoO0O00 * iIii1I11I1II1 . iII111i
 if 42 - 42: O0 / oO0o % O0 . i1IIi % OOooOOo
 if 13 - 13: I1IiiI % ooOoO0o + OOooOOo
 if 91 - 91: oO0o - ooOoO0o
 if 20 - 20: i1IIi . IiII / o0oOOo0O0Ooo / I11i
 if 27 - 27: ooOoO0o . ooOoO0o - Ii1I % i11iIiiIii
 if 74 - 74: I1Ii111 - II111iiii % o0oOOo0O0Ooo
 if 7 - 7: I1IiiI + OoooooooOO + o0oOOo0O0Ooo . OoooooooOO
def lisp_send_ipc_to_core ( lisp_socket , packet , dest , port ) :
 oO000O = lisp_socket . getsockname ( )
 dest = dest . print_address_no_iid ( )
 if 29 - 29: iII111i * O0 + I1IiiI * IiII + iII111i - IiII
 lprint ( "Send IPC {} bytes to {} {}, control-packet: {}" . format ( len ( packet ) , dest , port , lisp_format_packet ( packet ) ) )
 if 38 - 38: I1ii11iIi11i - Ii1I % OoooooooOO
 if 43 - 43: iIii1I11I1II1 / OoOoOO00
 packet = lisp_control_packet_ipc ( packet , oO000O , dest , port )
 lisp_ipc ( packet , lisp_socket , "lisp-core-pkt" )
 return
 if 13 - 13: o0oOOo0O0Ooo / I1Ii111
 if 67 - 67: OoooooooOO . oO0o * OoOoOO00 - OoooooooOO
 if 32 - 32: oO0o
 if 72 - 72: I1IiiI
 if 34 - 34: ooOoO0o % II111iiii / ooOoO0o
 if 87 - 87: Oo0Ooo
 if 7 - 7: iIii1I11I1II1
 if 85 - 85: iIii1I11I1II1 . O0
def lisp_send_map_reply ( lisp_sockets , packet , dest , port ) :
 lprint ( "Send Map-Reply to {}" . format ( dest . print_address_no_iid ( ) ) )
 lisp_send_ipc_to_core ( lisp_sockets [ 2 ] , packet , dest , port )
 return
 if 43 - 43: II111iiii / OoOoOO00 + OOooOOo % Oo0Ooo * OOooOOo
 if 62 - 62: ooOoO0o * OOooOOo . I11i + Oo0Ooo - I1Ii111
 if 48 - 48: I1Ii111 * Oo0Ooo % OoO0O00 % Ii1I
 if 8 - 8: OoO0O00 . OoO0O00
 if 29 - 29: I11i + OoooooooOO % o0oOOo0O0Ooo - I1Ii111
 if 45 - 45: II111iiii - OOooOOo / oO0o % O0 . iII111i . iII111i
 if 82 - 82: iIii1I11I1II1 % Oo0Ooo * i1IIi - I1Ii111 - I1ii11iIi11i / iII111i
 if 24 - 24: IiII
def lisp_send_map_referral ( lisp_sockets , packet , dest , port ) :
 lprint ( "Send Map-Referral to {}" . format ( dest . print_address ( ) ) )
 lisp_send_ipc_to_core ( lisp_sockets [ 2 ] , packet , dest , port )
 return
 if 95 - 95: IiII + OoOoOO00 * OOooOOo
 if 92 - 92: OoOoOO00 + ooOoO0o . iII111i
 if 59 - 59: iIii1I11I1II1 % I1Ii111 + I1ii11iIi11i . OoOoOO00 * Oo0Ooo / I1Ii111
 if 41 - 41: i1IIi / IiII
 if 73 - 73: o0oOOo0O0Ooo % ooOoO0o
 if 72 - 72: OoO0O00 * OoOoOO00 % I1IiiI - OOooOOo . Oo0Ooo
 if 70 - 70: ooOoO0o . o0oOOo0O0Ooo * II111iiii - O0
 if 74 - 74: oO0o % I1IiiI / oO0o / Oo0Ooo / ooOoO0o
def lisp_send_map_notify ( lisp_sockets , packet , dest , port ) :
 lprint ( "Send Map-Notify to xTR {}" . format ( dest . print_address ( ) ) )
 lisp_send_ipc_to_core ( lisp_sockets [ 2 ] , packet , dest , port )
 return
 if 29 - 29: ooOoO0o + iIii1I11I1II1 + OoO0O00 - o0oOOo0O0Ooo
 if 74 - 74: II111iiii - II111iiii + ooOoO0o + Oo0Ooo % iIii1I11I1II1
 if 90 - 90: oO0o / o0oOOo0O0Ooo . o0oOOo0O0Ooo % OoOoOO00 / IiII
 if 13 - 13: oO0o + IiII
 if 36 - 36: oO0o - OoOoOO00 . O0 % IiII
 if 65 - 65: Oo0Ooo - i11iIiiIii * OoOoOO00 . I1Ii111 . iIii1I11I1II1
 if 48 - 48: iIii1I11I1II1 - oO0o / OoO0O00 + O0 . Ii1I + I1Ii111
def lisp_send_ecm ( lisp_sockets , packet , inner_source , inner_sport , inner_dest ,
 outer_dest , to_etr = False , to_ms = False , ddt = False ) :
 if 17 - 17: OoOoOO00 . Oo0Ooo - I1Ii111 / I1Ii111 + I11i % i1IIi
 if ( inner_source == None or inner_source . is_null ( ) ) :
  inner_source = inner_dest
  if 31 - 31: OoooooooOO . O0 / OoO0O00 . I1Ii111
  if 41 - 41: OoooooooOO + iII111i . OOooOOo
  if 73 - 73: oO0o + i1IIi + i11iIiiIii / I1ii11iIi11i
  if 100 - 100: I1IiiI % ooOoO0o % OoooooooOO / i11iIiiIii + i11iIiiIii % IiII
  if 39 - 39: Ii1I % o0oOOo0O0Ooo + OOooOOo / iIii1I11I1II1
  if 40 - 40: iIii1I11I1II1 / iII111i % OOooOOo % i11iIiiIii
 if ( lisp_nat_traversal ) :
  I1i1I11111iI1 = lisp_get_any_translated_port ( )
  if ( I1i1I11111iI1 != None ) : inner_sport = I1i1I11111iI1
  if 57 - 57: II111iiii % OoO0O00 * i1IIi
 iIIIiiI = lisp_ecm ( inner_sport )
 if 19 - 19: ooOoO0o . iIii1I11I1II1 + I1ii11iIi11i + I1ii11iIi11i / o0oOOo0O0Ooo . Oo0Ooo
 iIIIiiI . to_etr = to_etr if lisp_is_running ( "lisp-etr" ) else False
 iIIIiiI . to_ms = to_ms if lisp_is_running ( "lisp-ms" ) else False
 iIIIiiI . ddt = ddt
 iiii11i1iIi = iIIIiiI . encode ( packet , inner_source , inner_dest )
 if ( iiii11i1iIi == None ) :
  lprint ( "Could not encode ECM message" )
  return
  if 15 - 15: I1Ii111 - I1Ii111 * I1ii11iIi11i
 iIIIiiI . print_ecm ( )
 if 74 - 74: o0oOOo0O0Ooo / O0 + Ii1I
 packet = iiii11i1iIi + packet
 if 99 - 99: IiII + i1IIi + IiII - iIii1I11I1II1 . iII111i
 oO00o = outer_dest . print_address_no_iid ( )
 lprint ( "Send Encapsulated-Control-Message to {}" . format ( oO00o ) )
 Oo0o0OoOoOo0 = lisp_convert_4to6 ( oO00o )
 lisp_send ( lisp_sockets , Oo0o0OoOoOo0 , LISP_CTRL_PORT , packet )
 return
 if 4 - 4: I1ii11iIi11i % o0oOOo0O0Ooo * Oo0Ooo
 if 97 - 97: OoOoOO00
 if 34 - 34: iII111i % Oo0Ooo
 if 25 - 25: OOooOOo / Oo0Ooo
 if 26 - 26: iII111i
 if 93 - 93: Oo0Ooo + I1IiiI % OoOoOO00 / OOooOOo / I1ii11iIi11i
 if 6 - 6: IiII
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
if 68 - 68: Oo0Ooo
LISP_RLOC_UNKNOWN_STATE = 0
LISP_RLOC_UP_STATE = 1
LISP_RLOC_DOWN_STATE = 2
LISP_RLOC_UNREACH_STATE = 3
LISP_RLOC_NO_ECHOED_NONCE_STATE = 4
LISP_RLOC_ADMIN_DOWN_STATE = 5
if 83 - 83: OOooOOo / iIii1I11I1II1 . OoO0O00 - oO0o % Oo0Ooo
LISP_AUTH_NONE = 0
LISP_AUTH_MD5 = 1
LISP_AUTH_SHA1 = 2
LISP_AUTH_SHA2 = 3
if 30 - 30: Ii1I . OoOoOO00 / oO0o . OoO0O00
if 93 - 93: i11iIiiIii
if 33 - 33: i1IIi % OoooooooOO + Oo0Ooo % I1IiiI / ooOoO0o
if 40 - 40: IiII % IiII
if 9 - 9: I1IiiI * i1IIi + OOooOOo * OoOoOO00
if 8 - 8: iII111i
if 51 - 51: I1IiiI
LISP_IPV4_HOST_MASK_LEN = 32
LISP_IPV6_HOST_MASK_LEN = 128
LISP_MAC_HOST_MASK_LEN = 48
LISP_E164_HOST_MASK_LEN = 60
if 72 - 72: ooOoO0o / I1ii11iIi11i . Ii1I * iII111i . iIii1I11I1II1
if 35 - 35: OoO0O00 . OoOoOO00 % O0 * OoO0O00
if 68 - 68: OOooOOo
if 87 - 87: IiII * IiII - OoO0O00 / I1ii11iIi11i + OOooOOo / i11iIiiIii
if 21 - 21: o0oOOo0O0Ooo / oO0o + oO0o + Oo0Ooo / o0oOOo0O0Ooo
if 39 - 39: i11iIiiIii - OoO0O00 - i11iIiiIii / OoooooooOO
def byte_swap_64 ( address ) :
 iIiIi1ii = ( ( address & 0x00000000000000ff ) << 56 ) | ( ( address & 0x000000000000ff00 ) << 40 ) | ( ( address & 0x0000000000ff0000 ) << 24 ) | ( ( address & 0x00000000ff000000 ) << 8 ) | ( ( address & 0x000000ff00000000 ) >> 8 ) | ( ( address & 0x0000ff0000000000 ) >> 24 ) | ( ( address & 0x00ff000000000000 ) >> 40 ) | ( ( address & 0xff00000000000000 ) >> 56 )
 if 15 - 15: i1IIi . iII111i + IiII / I1ii11iIi11i - i1IIi / iII111i
 if 27 - 27: OoOoOO00 / OoooooooOO + i1IIi % iIii1I11I1II1 / OoO0O00
 if 73 - 73: I1ii11iIi11i / OoOoOO00 / IiII + oO0o
 if 73 - 73: I11i * o0oOOo0O0Ooo * I1IiiI . OoooooooOO % I1Ii111
 if 9 - 9: oO0o % I1Ii111 . O0 + I1ii11iIi11i - Ii1I - I1ii11iIi11i
 if 57 - 57: i11iIiiIii
 if 21 - 21: iIii1I11I1II1 / I1IiiI / iII111i
 if 19 - 19: Oo0Ooo / iIii1I11I1II1 / I11i
 return ( iIiIi1ii )
 if 71 - 71: iIii1I11I1II1 * I1IiiI
 if 35 - 35: O0
 if 10 - 10: Ii1I - I1Ii111 / Oo0Ooo + O0
 if 67 - 67: Ii1I % i11iIiiIii . Oo0Ooo
 if 78 - 78: I1IiiI - iIii1I11I1II1
 if 20 - 20: i11iIiiIii % I1IiiI % OoOoOO00
 if 85 - 85: I11i + OoOoOO00 * O0 * O0
 if 92 - 92: i11iIiiIii
 if 16 - 16: I11i . ooOoO0o - Oo0Ooo / OoO0O00 . i1IIi
 if 59 - 59: ooOoO0o - ooOoO0o % I11i + OoO0O00
 if 88 - 88: Ii1I - ooOoO0o . Oo0Ooo
 if 83 - 83: I11i + Oo0Ooo . I1ii11iIi11i * I1ii11iIi11i
 if 80 - 80: i1IIi * I11i - OOooOOo / II111iiii * iIii1I11I1II1
 if 42 - 42: OoOoOO00 . I11i % II111iiii
 if 19 - 19: OoooooooOO
class lisp_cache_entries ( ) :
 def __init__ ( self ) :
  self . entries = { }
  self . entries_sorted = [ ]
  if 31 - 31: I11i . OoOoOO00 - O0 * iII111i % I1Ii111 - II111iiii
  if 21 - 21: OOooOOo . Oo0Ooo - i1IIi
  if 56 - 56: I11i
class lisp_cache ( ) :
 def __init__ ( self ) :
  self . cache = { }
  self . cache_sorted = [ ]
  self . cache_count = 0
  if 24 - 24: I1IiiI . I1IiiI % ooOoO0o
  if 32 - 32: OOooOOo / i1IIi / OOooOOo
 def cache_size ( self ) :
  return ( self . cache_count )
  if 97 - 97: ooOoO0o * Oo0Ooo * OoooooooOO * I1IiiI
  if 45 - 45: Oo0Ooo
 def build_key ( self , prefix ) :
  if ( prefix . afi == LISP_AFI_ULTIMATE_ROOT ) :
   II1i = 0
  elif ( prefix . afi == LISP_AFI_IID_RANGE ) :
   II1i = prefix . mask_len
  else :
   II1i = prefix . mask_len + 48
   if 27 - 27: oO0o / IiII - iIii1I11I1II1 / o0oOOo0O0Ooo % OOooOOo * iIii1I11I1II1
   if 40 - 40: oO0o - II111iiii * OOooOOo % OoooooooOO
  I1I111iIi = lisp_hex_string ( prefix . instance_id ) . zfill ( 8 )
  ooo0oOOOO00Oo = lisp_hex_string ( prefix . afi ) . zfill ( 4 )
  if 52 - 52: OOooOOo + OoO0O00
  if ( prefix . afi > 0 ) :
   if ( prefix . is_binary ( ) ) :
    OOo000o = prefix . addr_length ( ) * 2
    iIiIi1ii = lisp_hex_string ( prefix . address ) . zfill ( OOo000o )
   else :
    iIiIi1ii = prefix . address
    if 96 - 96: OOooOOo % O0 - Oo0Ooo % oO0o / I1IiiI . i1IIi
  elif ( prefix . afi == LISP_AFI_GEO_COORD ) :
   ooo0oOOOO00Oo = "8003"
   iIiIi1ii = prefix . address . print_geo ( )
  else :
   ooo0oOOOO00Oo = ""
   iIiIi1ii = ""
   if 42 - 42: i1IIi
   if 52 - 52: OoO0O00 % iII111i % O0
  i1i11ii1 = I1I111iIi + ooo0oOOOO00Oo + iIiIi1ii
  return ( [ II1i , i1i11ii1 ] )
  if 11 - 11: i1IIi / i11iIiiIii + Ii1I % Oo0Ooo % O0
  if 50 - 50: oO0o . I1Ii111
 def add_cache ( self , prefix , entry ) :
  if ( prefix . is_binary ( ) ) : prefix . zero_host_bits ( )
  II1i , i1i11ii1 = self . build_key ( prefix )
  if ( self . cache . has_key ( II1i ) == False ) :
   self . cache [ II1i ] = lisp_cache_entries ( )
   self . cache [ II1i ] . entries = { }
   self . cache [ II1i ] . entries_sorted = [ ]
   self . cache_sorted = sorted ( self . cache )
   if 38 - 38: iIii1I11I1II1 . Ii1I
  if ( self . cache [ II1i ] . entries . has_key ( i1i11ii1 ) == False ) :
   self . cache_count += 1
   if 82 - 82: OOooOOo * Ii1I + I1ii11iIi11i . OoO0O00
  self . cache [ II1i ] . entries [ i1i11ii1 ] = entry
  self . cache [ II1i ] . entries_sorted = sorted ( self . cache [ II1i ] . entries )
  if 15 - 15: O0
  if 44 - 44: Ii1I . Oo0Ooo . I1Ii111 + oO0o
 def lookup_cache ( self , prefix , exact ) :
  I1Ii11Ii , i1i11ii1 = self . build_key ( prefix )
  if ( exact ) :
   if ( self . cache . has_key ( I1Ii11Ii ) == False ) : return ( None )
   if ( self . cache [ I1Ii11Ii ] . entries . has_key ( i1i11ii1 ) == False ) : return ( None )
   return ( self . cache [ I1Ii11Ii ] . entries [ i1i11ii1 ] )
   if 37 - 37: ooOoO0o . I1IiiI
   if 1 - 1: iIii1I11I1II1 . o0oOOo0O0Ooo % I11i
  III = None
  for II1i in self . cache_sorted :
   if ( I1Ii11Ii < II1i ) : return ( III )
   for oO0OoO0OO in self . cache [ II1i ] . entries_sorted :
    i1III1iiiIIi1 = self . cache [ II1i ] . entries
    if ( oO0OoO0OO in i1III1iiiIIi1 ) :
     Ooo000O00 = i1III1iiiIIi1 [ oO0OoO0OO ]
     if ( Ooo000O00 == None ) : continue
     if ( prefix . is_more_specific ( Ooo000O00 . eid ) ) : III = Ooo000O00
     if 15 - 15: o0oOOo0O0Ooo + IiII * Oo0Ooo / OOooOOo
     if 68 - 68: oO0o . OoOoOO00 * Oo0Ooo / I1Ii111
     if 71 - 71: I1IiiI . ooOoO0o - OOooOOo / OoooooooOO
  return ( III )
  if 41 - 41: OoOoOO00 . iII111i . i1IIi + oO0o
  if 60 - 60: oO0o * I1Ii111
 def delete_cache ( self , prefix ) :
  II1i , i1i11ii1 = self . build_key ( prefix )
  if ( self . cache . has_key ( II1i ) == False ) : return
  if ( self . cache [ II1i ] . entries . has_key ( i1i11ii1 ) == False ) : return
  self . cache [ II1i ] . entries . pop ( i1i11ii1 )
  self . cache [ II1i ] . entries_sorted . remove ( i1i11ii1 )
  self . cache_count -= 1
  if 81 - 81: oO0o - OOooOOo - oO0o
  if 54 - 54: oO0o % I11i
 def walk_cache ( self , function , parms ) :
  for II1i in self . cache_sorted :
   for i1i11ii1 in self . cache [ II1i ] . entries_sorted :
    Ooo000O00 = self . cache [ II1i ] . entries [ i1i11ii1 ]
    OOoO0 , parms = function ( Ooo000O00 , parms )
    if ( OOoO0 == False ) : return ( parms )
    if 77 - 77: I1IiiI / I1ii11iIi11i
    if 12 - 12: O0
  return ( parms )
  if 26 - 26: i11iIiiIii * iII111i + I1Ii111 . ooOoO0o - OoOoOO00
  if 4 - 4: Ii1I
 def print_cache ( self ) :
  lprint ( "Printing contents of {}: " . format ( self ) )
  if ( self . cache_size ( ) == 0 ) :
   lprint ( "  Cache is empty" )
   return
   if 16 - 16: OOooOOo + Ii1I * II111iiii / Oo0Ooo + iII111i
  for II1i in self . cache_sorted :
   for i1i11ii1 in self . cache [ II1i ] . entries_sorted :
    Ooo000O00 = self . cache [ II1i ] . entries [ i1i11ii1 ]
    lprint ( "  Mask-length: {}, key: {}, entry: {}" . format ( II1i , i1i11ii1 ,
 Ooo000O00 ) )
    if 82 - 82: OoOoOO00
    if 97 - 97: oO0o - OOooOOo / i11iIiiIii . Oo0Ooo % I1Ii111 % oO0o
    if 29 - 29: ooOoO0o % iII111i / iIii1I11I1II1
    if 73 - 73: O0 % i11iIiiIii
    if 16 - 16: O0
    if 15 - 15: i1IIi % i11iIiiIii
    if 18 - 18: Ii1I . OoO0O00 . iII111i * oO0o + O0
    if 35 - 35: OoOoOO00 . oO0o / II111iiii
lisp_referral_cache = lisp_cache ( )
lisp_ddt_cache = lisp_cache ( )
lisp_sites_by_eid = lisp_cache ( )
lisp_map_cache = lisp_cache ( )
lisp_db_for_lookups = lisp_cache ( )
if 97 - 97: Ii1I + I1Ii111 / II111iiii
if 14 - 14: iII111i / IiII / oO0o
if 55 - 55: OoO0O00 % O0
if 92 - 92: OoooooooOO / O0
if 14 - 14: i11iIiiIii
if 43 - 43: OOooOOo
if 79 - 79: iII111i % Oo0Ooo . i1IIi % ooOoO0o
def lisp_map_cache_lookup ( source , dest ) :
 if 93 - 93: OoOoOO00
 OO000000ooO0 = dest . is_multicast_address ( )
 if 49 - 49: i1IIi * OOooOOo % I11i * Ii1I . I1Ii111 * iIii1I11I1II1
 if 72 - 72: ooOoO0o
 if 63 - 63: Oo0Ooo . OoO0O00 . OoooooooOO / i1IIi
 if 53 - 53: OOooOOo * O0 . iII111i
 O0O = lisp_map_cache . lookup_cache ( dest , False )
 if ( O0O == None ) :
  I1I1iII1i = source . print_sg ( dest ) if OO000000ooO0 else dest . print_address ( )
  I1I1iII1i = green ( I1I1iII1i , False )
  dprint ( "Lookup for EID {} not found in map-cache" . format ( I1I1iII1i ) )
  return ( None )
  if 3 - 3: OoooooooOO * I1Ii111 * IiII - OOooOOo * I1Ii111
  if 78 - 78: iII111i
  if 80 - 80: i1IIi * I1IiiI + OOooOOo
  if 91 - 91: I1IiiI % OoOoOO00 * Oo0Ooo / I1ii11iIi11i
  if 57 - 57: i11iIiiIii / o0oOOo0O0Ooo . II111iiii
 if ( OO000000ooO0 == False ) :
  oOoOo = green ( O0O . eid . print_prefix ( ) , False )
  dprint ( "Lookup for EID {} found map-cache entry {}" . format ( green ( dest . print_address ( ) , False ) , oOoOo ) )
  if 63 - 63: O0
  return ( O0O )
  if 64 - 64: i11iIiiIii / oO0o . oO0o - Oo0Ooo
  if 48 - 48: i1IIi + I1ii11iIi11i + I1Ii111 - iII111i
  if 3 - 3: i1IIi + OoooooooOO * ooOoO0o + I1Ii111 % OOooOOo / IiII
  if 70 - 70: oO0o + i1IIi % o0oOOo0O0Ooo - I11i
  if 74 - 74: i11iIiiIii
 O0O = O0O . lookup_source_cache ( source , False )
 if ( O0O == None ) :
  I1I1iII1i = source . print_sg ( dest )
  dprint ( "Lookup for EID {} not found in map-cache" . format ( I1I1iII1i ) )
  return ( None )
  if 93 - 93: I1Ii111 % OOooOOo * I1IiiI % iII111i / iIii1I11I1II1 + OoO0O00
  if 6 - 6: I11i
  if 70 - 70: ooOoO0o + OoooooooOO % OoOoOO00 % oO0o / Ii1I . I11i
  if 63 - 63: I1ii11iIi11i - ooOoO0o . OOooOOo / O0 . iIii1I11I1II1 - Ii1I
  if 6 - 6: Ii1I
 oOoOo = green ( O0O . print_eid_tuple ( ) , False )
 dprint ( "Lookup for EID {} found map-cache entry {}" . format ( green ( source . print_sg ( dest ) , False ) , oOoOo ) )
 if 60 - 60: iII111i + I1IiiI
 return ( O0O )
 if 36 - 36: i1IIi . O0 . OoO0O00 % OOooOOo * I11i / Ii1I
 if 16 - 16: Oo0Ooo
 if 44 - 44: iIii1I11I1II1 - II111iiii . IiII . i1IIi
 if 37 - 37: OoooooooOO + Oo0Ooo - Oo0Ooo + I1ii11iIi11i . I1Ii111 / I1IiiI
 if 60 - 60: I1IiiI % Ii1I / I1Ii111 + Ii1I
 if 43 - 43: I1ii11iIi11i + I11i
 if 83 - 83: II111iiii + o0oOOo0O0Ooo - I1Ii111
def lisp_referral_cache_lookup ( eid , group , exact ) :
 if ( group and group . is_null ( ) ) :
  o0oOiiii1 = lisp_referral_cache . lookup_cache ( eid , exact )
  return ( o0oOiiii1 )
  if 100 - 100: IiII - OoOoOO00 / I11i
  if 33 - 33: I1Ii111 * OoOoOO00 . I1ii11iIi11i % I1Ii111
  if 87 - 87: Oo0Ooo
  if 65 - 65: ooOoO0o . I1IiiI
  if 51 - 51: IiII
 if ( eid == None or eid . is_null ( ) ) : return ( None )
 if 43 - 43: oO0o - I11i . i11iIiiIii
 if 78 - 78: i11iIiiIii + Oo0Ooo * Ii1I - o0oOOo0O0Ooo % i11iIiiIii
 if 30 - 30: I1IiiI % oO0o * OoooooooOO
 if 64 - 64: I1IiiI
 if 11 - 11: I1ii11iIi11i % iII111i / II111iiii % ooOoO0o % IiII
 if 14 - 14: ooOoO0o / IiII . o0oOOo0O0Ooo
 o0oOiiii1 = lisp_referral_cache . lookup_cache ( group , exact )
 if ( o0oOiiii1 == None ) : return ( None )
 if 27 - 27: I1IiiI - OOooOOo . II111iiii * I1ii11iIi11i % ooOoO0o / I1IiiI
 OOOOO0OO00OOO = o0oOiiii1 . lookup_source_cache ( eid , exact )
 if ( OOOOO0OO00OOO ) : return ( OOOOO0OO00OOO )
 if 14 - 14: I1IiiI - i11iIiiIii . O0 % OOooOOo . Ii1I
 if ( exact ) : o0oOiiii1 = None
 return ( o0oOiiii1 )
 if 46 - 46: II111iiii . i1IIi - i11iIiiIii + I11i - I1Ii111
 if 6 - 6: ooOoO0o / Ii1I / iIii1I11I1II1 - IiII - ooOoO0o
 if 7 - 7: OoOoOO00 + i1IIi % ooOoO0o * I11i + i11iIiiIii / II111iiii
 if 2 - 2: O0 / o0oOOo0O0Ooo - OoO0O00 * II111iiii
 if 4 - 4: I1IiiI + Oo0Ooo . iIii1I11I1II1
 if 100 - 100: i11iIiiIii
 if 21 - 21: OoOoOO00 + iII111i . OoO0O00
def lisp_ddt_cache_lookup ( eid , group , exact ) :
 if ( group . is_null ( ) ) :
  iII1I = lisp_ddt_cache . lookup_cache ( eid , exact )
  return ( iII1I )
  if 79 - 79: i11iIiiIii - OoO0O00 * OoO0O00 * i1IIi / iIii1I11I1II1 + iII111i
  if 27 - 27: iII111i / Ii1I / iII111i + OoooooooOO - O0 + OoO0O00
  if 62 - 62: iIii1I11I1II1
  if 60 - 60: Oo0Ooo % IiII % OoO0O00 - i11iIiiIii
  if 53 - 53: i11iIiiIii + OoooooooOO
 if ( eid . is_null ( ) ) : return ( None )
 if 23 - 23: i11iIiiIii - IiII - I1ii11iIi11i + I1ii11iIi11i % I1IiiI
 if 79 - 79: II111iiii / OoooooooOO
 if 35 - 35: i1IIi + IiII + II111iiii % OOooOOo
 if 25 - 25: I11i + i11iIiiIii + O0 - Ii1I
 if 69 - 69: I11i . OoOoOO00 / OOooOOo / i1IIi . II111iiii
 if 17 - 17: I1Ii111
 iII1I = lisp_ddt_cache . lookup_cache ( group , exact )
 if ( iII1I == None ) : return ( None )
 if 2 - 2: O0 % OoOoOO00 + oO0o
 I1I11i1 = iII1I . lookup_source_cache ( eid , exact )
 if ( I1I11i1 ) : return ( I1I11i1 )
 if 18 - 18: o0oOOo0O0Ooo
 if ( exact ) : iII1I = None
 return ( iII1I )
 if 15 - 15: o0oOOo0O0Ooo / I11i - iIii1I11I1II1 * Ii1I + O0 % IiII
 if 59 - 59: i11iIiiIii % iIii1I11I1II1 / IiII
 if 100 - 100: Ii1I . o0oOOo0O0Ooo - II111iiii . O0
 if 5 - 5: iII111i
 if 66 - 66: oO0o / OoOoOO00 . i1IIi % ooOoO0o . iII111i * I11i
 if 48 - 48: oO0o % OoOoOO00
 if 23 - 23: i1IIi - Ii1I - oO0o . OoooooooOO + OOooOOo * oO0o
def lisp_site_eid_lookup ( eid , group , exact ) :
 if 56 - 56: O0 + OoOoOO00 + OoO0O00 - iIii1I11I1II1 . iIii1I11I1II1 . i11iIiiIii
 if ( group . is_null ( ) ) :
  iI1II1i1I1Ii = lisp_sites_by_eid . lookup_cache ( eid , exact )
  return ( iI1II1i1I1Ii )
  if 84 - 84: I11i + OOooOOo - OoooooooOO / I1ii11iIi11i
  if 12 - 12: I1IiiI * iIii1I11I1II1 - II111iiii / o0oOOo0O0Ooo - OOooOOo
  if 99 - 99: I1ii11iIi11i / O0 % II111iiii % I1Ii111 * II111iiii
  if 28 - 28: I11i - Oo0Ooo + iIii1I11I1II1 + O0 * Ii1I + I1IiiI
  if 13 - 13: iII111i
 if ( eid . is_null ( ) ) : return ( None )
 if 42 - 42: I1Ii111 - I1IiiI % I1IiiI * I1IiiI
 if 70 - 70: O0 / I1IiiI / I1IiiI
 if 71 - 71: OOooOOo - Oo0Ooo + IiII * oO0o
 if 90 - 90: OoOoOO00 * I1ii11iIi11i
 if 16 - 16: i1IIi - OoO0O00
 if 61 - 61: o0oOOo0O0Ooo + OoOoOO00 - ooOoO0o + ooOoO0o % ooOoO0o % II111iiii
 iI1II1i1I1Ii = lisp_sites_by_eid . lookup_cache ( group , exact )
 if ( iI1II1i1I1Ii == None ) : return ( None )
 if 16 - 16: I1IiiI . Ii1I
 if 80 - 80: OOooOOo * O0 / iIii1I11I1II1 / IiII / OoOoOO00
 if 15 - 15: I1ii11iIi11i * iII111i + i11iIiiIii
 if 68 - 68: i1IIi / oO0o * I1ii11iIi11i - OoOoOO00 + Oo0Ooo / O0
 if 1 - 1: ooOoO0o - Oo0Ooo + I1Ii111
 if 90 - 90: I1Ii111 * O0 . iII111i - Oo0Ooo % iIii1I11I1II1
 if 7 - 7: I1ii11iIi11i % o0oOOo0O0Ooo % O0 % iIii1I11I1II1
 if 10 - 10: OoooooooOO - iII111i . i1IIi % oO0o . OoooooooOO + OOooOOo
 if 59 - 59: I1IiiI * OoooooooOO % OOooOOo / I11i
 if 77 - 77: II111iiii - IiII % OOooOOo
 if 22 - 22: OoooooooOO / oO0o
 if 78 - 78: oO0o * I11i . i1IIi % i1IIi + i1IIi / OOooOOo
 if 66 - 66: OoooooooOO % o0oOOo0O0Ooo / I11i * I1Ii111
 if 12 - 12: I1Ii111
 if 17 - 17: I1Ii111 % oO0o + O0
 if 15 - 15: o0oOOo0O0Ooo - OoooooooOO % ooOoO0o % oO0o / i11iIiiIii / Oo0Ooo
 if 59 - 59: iII111i + O0 - I1ii11iIi11i * I1ii11iIi11i + iIii1I11I1II1
 if 41 - 41: iIii1I11I1II1 . O0 - ooOoO0o / OoOoOO00 % iIii1I11I1II1 + IiII
 i11i1III1 = iI1II1i1I1Ii . lookup_source_cache ( eid , exact )
 if ( i11i1III1 ) : return ( i11i1III1 )
 if 23 - 23: OoOoOO00 + ooOoO0o . i11iIiiIii
 if ( exact ) :
  iI1II1i1I1Ii = None
 else :
  IiIII1iii1iII = iI1II1i1I1Ii . parent_for_more_specifics
  if ( IiIII1iii1iII and IiIII1iii1iII . accept_more_specifics ) :
   if ( group . is_more_specific ( IiIII1iii1iII . group ) ) : iI1II1i1I1Ii = IiIII1iii1iII
   if 39 - 39: OoOoOO00 - I1ii11iIi11i / I1Ii111
   if 48 - 48: IiII - oO0o + I11i % o0oOOo0O0Ooo
 return ( iI1II1i1I1Ii )
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
 if 98 - 98: O0 - I1Ii111 % oO0o - iII111i + Ii1I * i1IIi
 if 76 - 76: o0oOOo0O0Ooo
 if 55 - 55: OOooOOo + I1ii11iIi11i * Oo0Ooo
 if 11 - 11: i1IIi - OoooooooOO * OoOoOO00 / oO0o - OoooooooOO - I1IiiI
 if 22 - 22: i11iIiiIii . Ii1I . Oo0Ooo * Oo0Ooo - iII111i / I1ii11iIi11i
 if 49 - 49: iII111i + I11i . Oo0Ooo
 if 23 - 23: I1IiiI . Ii1I + ooOoO0o . OoooooooOO
 if 57 - 57: OOooOOo / OoOoOO00 / i11iIiiIii - I11i - I11i . Ii1I
class lisp_address ( ) :
 def __init__ ( self , afi , addr_str , mask_len , iid ) :
  self . afi = afi
  self . mask_len = mask_len
  self . instance_id = iid
  self . iid_list = [ ]
  self . address = 0
  if ( addr_str != "" ) : self . store_address ( addr_str )
  if 53 - 53: ooOoO0o . iII111i + Ii1I * I1Ii111
  if 49 - 49: II111iiii . I1ii11iIi11i * OoOoOO00 - OOooOOo
 def copy_address ( self , addr ) :
  if ( addr == None ) : return
  self . afi = addr . afi
  self . address = addr . address
  self . mask_len = addr . mask_len
  self . instance_id = addr . instance_id
  self . iid_list = addr . iid_list
  if 48 - 48: OoO0O00 . iIii1I11I1II1 - OoooooooOO + I1Ii111 / i11iIiiIii . Oo0Ooo
  if 61 - 61: II111iiii + OOooOOo . o0oOOo0O0Ooo . iIii1I11I1II1
 def make_default_route ( self , addr ) :
  self . afi = addr . afi
  self . instance_id = addr . instance_id
  self . mask_len = 0
  self . address = 0
  if 63 - 63: I11i + i11iIiiIii . o0oOOo0O0Ooo . i1IIi + OoOoOO00
  if 1 - 1: i11iIiiIii
 def make_default_multicast_route ( self , addr ) :
  self . afi = addr . afi
  self . instance_id = addr . instance_id
  if ( self . afi == LISP_AFI_IPV4 ) :
   self . address = 0xe0000000
   self . mask_len = 4
   if 1 - 1: iIii1I11I1II1
  if ( self . afi == LISP_AFI_IPV6 ) :
   self . address = 0xff << 120
   self . mask_len = 8
   if 73 - 73: iII111i + IiII
  if ( self . afi == LISP_AFI_MAC ) :
   self . address = 0xffffffffffff
   self . mask_len = 48
   if 95 - 95: O0
   if 75 - 75: ooOoO0o
   if 8 - 8: O0 - OoooooooOO + I1ii11iIi11i / Oo0Ooo . oO0o + I1Ii111
 def not_set ( self ) :
  return ( self . afi == LISP_AFI_NONE )
  if 85 - 85: ooOoO0o
  if 29 - 29: iII111i . Ii1I
 def is_private_address ( self ) :
  if ( self . is_ipv4 ( ) == False ) : return ( False )
  iIiIi1ii = self . address
  if ( ( ( iIiIi1ii & 0xff000000 ) >> 24 ) == 10 ) : return ( True )
  if ( ( ( iIiIi1ii & 0xff000000 ) >> 24 ) == 172 ) :
   I1IIii1I = ( iIiIi1ii & 0x00ff0000 ) >> 16
   if ( I1IIii1I >= 16 and I1IIii1I <= 31 ) : return ( True )
   if 33 - 33: OoO0O00 . IiII . IiII + OoooooooOO
  if ( ( ( iIiIi1ii & 0xffff0000 ) >> 16 ) == 0xc0a8 ) : return ( True )
  return ( False )
  if 33 - 33: I1ii11iIi11i % i11iIiiIii / II111iiii . I1Ii111 % o0oOOo0O0Ooo . ooOoO0o
  if 15 - 15: oO0o % O0
 def is_multicast_address ( self ) :
  if ( self . is_ipv4 ( ) ) : return ( self . is_ipv4_multicast ( ) )
  if ( self . is_ipv6 ( ) ) : return ( self . is_ipv6_multicast ( ) )
  if ( self . is_mac ( ) ) : return ( self . is_mac_multicast ( ) )
  return ( False )
  if 70 - 70: ooOoO0o - IiII . ooOoO0o / iIii1I11I1II1 - ooOoO0o / OoooooooOO
  if 12 - 12: o0oOOo0O0Ooo / iIii1I11I1II1 + OOooOOo
 def host_mask_len ( self ) :
  if ( self . afi == LISP_AFI_IPV4 ) : return ( LISP_IPV4_HOST_MASK_LEN )
  if ( self . afi == LISP_AFI_IPV6 ) : return ( LISP_IPV6_HOST_MASK_LEN )
  if ( self . afi == LISP_AFI_MAC ) : return ( LISP_MAC_HOST_MASK_LEN )
  if ( self . afi == LISP_AFI_E164 ) : return ( LISP_E164_HOST_MASK_LEN )
  if ( self . afi == LISP_AFI_NAME ) : return ( len ( self . address ) * 8 )
  if ( self . afi == LISP_AFI_GEO_COORD ) :
   return ( len ( self . address . print_geo ( ) ) * 8 )
   if 20 - 20: i11iIiiIii
  return ( 0 )
  if 10 - 10: iIii1I11I1II1 % i1IIi
  if 78 - 78: I11i + II111iiii % o0oOOo0O0Ooo
 def is_iana_eid ( self ) :
  if ( self . is_ipv6 ( ) == False ) : return ( False )
  iIiIi1ii = self . address >> 96
  return ( iIiIi1ii == 0x20010005 )
  if 17 - 17: i11iIiiIii + oO0o * iII111i . II111iiii
  if 44 - 44: I1ii11iIi11i
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
   if 39 - 39: iII111i + Oo0Ooo / oO0o
  return ( 0 )
  if 95 - 95: I1Ii111 * oO0o / ooOoO0o . Ii1I . OoOoOO00
  if 99 - 99: I1IiiI * II111iiii
 def afi_to_version ( self ) :
  if ( self . afi == LISP_AFI_IPV4 ) : return ( 4 )
  if ( self . afi == LISP_AFI_IPV6 ) : return ( 6 )
  return ( 0 )
  if 84 - 84: II111iiii - I1IiiI
  if 41 - 41: iIii1I11I1II1 % I1Ii111 % OoOoOO00
 def packet_format ( self ) :
  if 35 - 35: I11i + i1IIi
  if 85 - 85: Ii1I * Ii1I . OoOoOO00 / Oo0Ooo
  if 97 - 97: oO0o % iIii1I11I1II1
  if 87 - 87: II111iiii % I1IiiI + oO0o - I11i / I11i
  if 16 - 16: I1IiiI
  if ( self . afi == LISP_AFI_IPV4 ) : return ( "I" )
  if ( self . afi == LISP_AFI_IPV6 ) : return ( "QQ" )
  if ( self . afi == LISP_AFI_MAC ) : return ( "HHH" )
  if ( self . afi == LISP_AFI_E164 ) : return ( "II" )
  if ( self . afi == LISP_AFI_LCAF ) : return ( "I" )
  return ( "" )
  if 39 - 39: ooOoO0o * II111iiii
  if 90 - 90: OoooooooOO * ooOoO0o
 def pack_address ( self ) :
  ii1iI11IiIIi = self . packet_format ( )
  I1i1iI = ""
  if ( self . is_ipv4 ( ) ) :
   I1i1iI = struct . pack ( ii1iI11IiIIi , socket . htonl ( self . address ) )
  elif ( self . is_ipv6 ( ) ) :
   O00OoOoO = byte_swap_64 ( self . address >> 64 )
   ooO0o0oo = byte_swap_64 ( self . address & 0xffffffffffffffff )
   I1i1iI = struct . pack ( ii1iI11IiIIi , O00OoOoO , ooO0o0oo )
  elif ( self . is_mac ( ) ) :
   iIiIi1ii = self . address
   O00OoOoO = ( iIiIi1ii >> 32 ) & 0xffff
   ooO0o0oo = ( iIiIi1ii >> 16 ) & 0xffff
   iiiII111I11 = iIiIi1ii & 0xffff
   I1i1iI = struct . pack ( ii1iI11IiIIi , O00OoOoO , ooO0o0oo , iiiII111I11 )
  elif ( self . is_e164 ( ) ) :
   iIiIi1ii = self . address
   O00OoOoO = ( iIiIi1ii >> 32 ) & 0xffffffff
   ooO0o0oo = ( iIiIi1ii & 0xffffffff )
   I1i1iI = struct . pack ( ii1iI11IiIIi , O00OoOoO , ooO0o0oo )
  elif ( self . is_dist_name ( ) ) :
   I1i1iI += self . address + "\0"
   if 82 - 82: I1IiiI % iIii1I11I1II1 * Ii1I . OOooOOo / o0oOOo0O0Ooo
  return ( I1i1iI )
  if 12 - 12: oO0o - O0
  if 62 - 62: OoOoOO00 % I1Ii111 . iIii1I11I1II1 * I11i . oO0o - iII111i
 def unpack_address ( self , packet ) :
  ii1iI11IiIIi = self . packet_format ( )
  iiii = struct . calcsize ( ii1iI11IiIIi )
  if ( len ( packet ) < iiii ) : return ( None )
  if 22 - 22: OoooooooOO - Oo0Ooo . OoOoOO00
  iIiIi1ii = struct . unpack ( ii1iI11IiIIi , packet [ : iiii ] )
  if 73 - 73: Ii1I . IiII + OoO0O00
  if ( self . is_ipv4 ( ) ) :
   self . address = socket . ntohl ( iIiIi1ii [ 0 ] )
  elif ( self . is_ipv6 ( ) ) :
   self . address = ( byte_swap_64 ( iIiIi1ii [ 0 ] ) << 64 ) | byte_swap_64 ( iIiIi1ii [ 1 ] )
   if 64 - 64: IiII
  elif ( self . is_mac ( ) ) :
   Oo0Oo0OooOo = iIiIi1ii [ 0 ]
   ii11IIi = iIiIi1ii [ 1 ]
   O0OOooOO = iIiIi1ii [ 2 ]
   self . address = ( Oo0Oo0OooOo << 32 ) + ( ii11IIi << 16 ) + O0OOooOO
  elif ( self . is_e164 ( ) ) :
   self . address = ( iIiIi1ii [ 0 ] << 32 ) + iIiIi1ii [ 1 ]
  elif ( self . is_dist_name ( ) ) :
   packet , self . address = lisp_decode_dist_name ( packet )
   self . mask_len = len ( self . address ) * 8
   iiii = 0
   if 74 - 74: I1IiiI . O0 . IiII + IiII - IiII
  packet = packet [ iiii : : ]
  return ( packet )
  if 100 - 100: ooOoO0o / OoooooooOO
  if 73 - 73: i11iIiiIii - Oo0Ooo
 def is_ipv4 ( self ) :
  return ( True if ( self . afi == LISP_AFI_IPV4 ) else False )
  if 100 - 100: iIii1I11I1II1 + I1Ii111
  if 51 - 51: o0oOOo0O0Ooo * I11i
 def is_ipv4_link_local ( self ) :
  if ( self . is_ipv4 ( ) == False ) : return ( False )
  return ( ( ( self . address >> 16 ) & 0xffff ) == 0xa9fe )
  if 42 - 42: OOooOOo % I11i
  if 84 - 84: Oo0Ooo * OoOoOO00 / Ii1I / IiII / o0oOOo0O0Ooo . I1ii11iIi11i
 def is_ipv4_loopback ( self ) :
  if ( self . is_ipv4 ( ) == False ) : return ( False )
  return ( self . address == 0x7f000001 )
  if 81 - 81: I1IiiI
  if 82 - 82: I1Ii111 - OoooooooOO - Ii1I
 def is_ipv4_multicast ( self ) :
  if ( self . is_ipv4 ( ) == False ) : return ( False )
  return ( ( ( self . address >> 24 ) & 0xf0 ) == 0xe0 )
  if 34 - 34: OOooOOo . iIii1I11I1II1 / I1IiiI . Oo0Ooo - iIii1I11I1II1
  if 83 - 83: iII111i - I1ii11iIi11i + iII111i
 def is_ipv4_string ( self , addr_str ) :
  return ( addr_str . find ( "." ) != - 1 )
  if 4 - 4: o0oOOo0O0Ooo % iIii1I11I1II1 + I11i
  if 60 - 60: I1ii11iIi11i / I1Ii111 % i11iIiiIii % oO0o % I1IiiI . Oo0Ooo
 def is_ipv6 ( self ) :
  return ( True if ( self . afi == LISP_AFI_IPV6 ) else False )
  if 20 - 20: IiII - OOooOOo + OoOoOO00
  if 83 - 83: OoooooooOO / I1IiiI + iII111i - iIii1I11I1II1 % ooOoO0o
 def is_ipv6_link_local ( self ) :
  if ( self . is_ipv6 ( ) == False ) : return ( False )
  return ( ( ( self . address >> 112 ) & 0xffff ) == 0xfe80 )
  if 74 - 74: OoO0O00
  if 13 - 13: I1ii11iIi11i / OoO0O00
 def is_ipv6_string_link_local ( self , addr_str ) :
  return ( addr_str . find ( "fe80::" ) != - 1 )
  if 90 - 90: iIii1I11I1II1 - OoO0O00 . i1IIi / o0oOOo0O0Ooo + O0
  if 94 - 94: IiII * i1IIi
 def is_ipv6_loopback ( self ) :
  if ( self . is_ipv6 ( ) == False ) : return ( False )
  return ( self . address == 1 )
  if 90 - 90: O0 % I1IiiI . o0oOOo0O0Ooo % ooOoO0o % I1IiiI
  if 16 - 16: OoO0O00 / OOooOOo / iIii1I11I1II1 / OoooooooOO . oO0o - I1Ii111
 def is_ipv6_multicast ( self ) :
  if ( self . is_ipv6 ( ) == False ) : return ( False )
  return ( ( ( self . address >> 120 ) & 0xff ) == 0xff )
  if 43 - 43: OoOoOO00 % OOooOOo / I1IiiI + I1IiiI
  if 40 - 40: OOooOOo . I1Ii111 + I1Ii111
 def is_ipv6_string ( self , addr_str ) :
  return ( addr_str . find ( ":" ) != - 1 )
  if 4 - 4: iIii1I11I1II1 - iIii1I11I1II1 * I11i
  if 32 - 32: I1IiiI + II111iiii * iII111i + O0 / O0 * Oo0Ooo
 def is_mac ( self ) :
  return ( True if ( self . afi == LISP_AFI_MAC ) else False )
  if 64 - 64: i11iIiiIii / iII111i + i11iIiiIii . I11i
  if 66 - 66: i1IIi
 def is_mac_multicast ( self ) :
  if ( self . is_mac ( ) == False ) : return ( False )
  return ( ( self . address & 0x010000000000 ) != 0 )
  if 98 - 98: Oo0Ooo / iIii1I11I1II1
  if 33 - 33: O0 - iII111i
 def is_mac_broadcast ( self ) :
  if ( self . is_mac ( ) == False ) : return ( False )
  return ( self . address == 0xffffffffffff )
  if 40 - 40: iII111i * I11i
  if 25 - 25: O0 * o0oOOo0O0Ooo % ooOoO0o % I1IiiI
 def is_mac_string ( self , addr_str ) :
  return ( len ( addr_str ) == 15 and addr_str . find ( "-" ) != - 1 )
  if 87 - 87: OoOoOO00
  if 30 - 30: IiII % OoOoOO00 + I1Ii111
 def is_link_local_multicast ( self ) :
  if ( self . is_ipv4 ( ) ) :
   return ( ( 0xe0ffff00 & self . address ) == 0xe0000000 )
   if 13 - 13: iII111i * Ii1I % o0oOOo0O0Ooo * i1IIi . IiII % i1IIi
  if ( self . is_ipv6 ( ) ) :
   return ( ( self . address >> 112 ) & 0xffff == 0xff02 )
   if 79 - 79: OoooooooOO % I11i / o0oOOo0O0Ooo + IiII + O0 + iII111i
  return ( False )
  if 87 - 87: I11i
  if 39 - 39: I1ii11iIi11i * i11iIiiIii % I1Ii111
 def is_null ( self ) :
  return ( True if ( self . afi == LISP_AFI_NONE ) else False )
  if 72 - 72: OoO0O00 * Oo0Ooo - IiII
  if 74 - 74: Ii1I
 def is_ultimate_root ( self ) :
  return ( True if self . afi == LISP_AFI_ULTIMATE_ROOT else False )
  if 26 - 26: I11i . O0
  if 68 - 68: Ii1I
 def is_iid_range ( self ) :
  return ( True if self . afi == LISP_AFI_IID_RANGE else False )
  if 26 - 26: o0oOOo0O0Ooo - I1ii11iIi11i / O0 % i11iIiiIii
  if 7 - 7: I1Ii111 . Oo0Ooo + IiII / iIii1I11I1II1
 def is_e164 ( self ) :
  return ( True if ( self . afi == LISP_AFI_E164 ) else False )
  if 22 - 22: iIii1I11I1II1 - O0 . iII111i - IiII - ooOoO0o
  if 54 - 54: OoO0O00 . iII111i . OoOoOO00 * OoO0O00 + o0oOOo0O0Ooo . ooOoO0o
 def is_dist_name ( self ) :
  return ( True if ( self . afi == LISP_AFI_NAME ) else False )
  if 44 - 44: I11i * iIii1I11I1II1 . I1ii11iIi11i
  if 9 - 9: o0oOOo0O0Ooo
 def is_geo_prefix ( self ) :
  return ( True if ( self . afi == LISP_AFI_GEO_COORD ) else False )
  if 23 - 23: ooOoO0o * OoO0O00 + O0 % I1Ii111
  if 21 - 21: Ii1I * OoOoOO00
 def is_binary ( self ) :
  if ( self . is_dist_name ( ) ) : return ( False )
  if ( self . is_geo_prefix ( ) ) : return ( False )
  return ( True )
  if 29 - 29: iIii1I11I1II1 / ooOoO0o
  if 75 - 75: OoooooooOO + I1IiiI % OoOoOO00 / O0 - IiII
 def store_address ( self , addr_str ) :
  if ( self . afi == LISP_AFI_NONE ) : self . string_to_afi ( addr_str )
  if 88 - 88: OoO0O00 % Ii1I
  if 12 - 12: OoooooooOO . O0
  if 33 - 33: OoooooooOO / I11i . II111iiii * i1IIi
  if 34 - 34: i11iIiiIii / OoOoOO00
  iiIii1I = addr_str . find ( "[" )
  o0oIIi1 = addr_str . find ( "]" )
  if ( iiIii1I != - 1 and o0oIIi1 != - 1 ) :
   self . instance_id = int ( addr_str [ iiIii1I + 1 : o0oIIi1 ] )
   addr_str = addr_str [ o0oIIi1 + 1 : : ]
   if ( self . is_dist_name ( ) == False ) :
    addr_str = addr_str . replace ( " " , "" )
    if 100 - 100: o0oOOo0O0Ooo - I1IiiI / I11i
    if 43 - 43: o0oOOo0O0Ooo % iIii1I11I1II1
    if 85 - 85: oO0o + OoooooooOO - IiII % o0oOOo0O0Ooo * ooOoO0o * II111iiii
    if 4 - 4: Ii1I . i1IIi + Oo0Ooo % I11i . OoO0O00
    if 70 - 70: OOooOOo * OoOoOO00 / OoOoOO00 / OoOoOO00
    if 23 - 23: I1IiiI
  if ( self . is_ipv4 ( ) ) :
   I11i1iI11i11 = addr_str . split ( "." )
   ooOoO = int ( I11i1iI11i11 [ 0 ] ) << 24
   ooOoO += int ( I11i1iI11i11 [ 1 ] ) << 16
   ooOoO += int ( I11i1iI11i11 [ 2 ] ) << 8
   ooOoO += int ( I11i1iI11i11 [ 3 ] )
   self . address = ooOoO
  elif ( self . is_ipv6 ( ) ) :
   if 63 - 63: Oo0Ooo * I1Ii111 % Ii1I
   if 88 - 88: IiII - i1IIi * OoO0O00 * OoOoOO00 % I1IiiI
   if 10 - 10: OOooOOo * I1ii11iIi11i / I11i * o0oOOo0O0Ooo % O0 * i11iIiiIii
   if 68 - 68: I11i . Ii1I + I11i / IiII . I11i / iIii1I11I1II1
   if 96 - 96: O0
   if 2 - 2: OoO0O00 / iII111i + o0oOOo0O0Ooo
   if 27 - 27: I11i - OoOoOO00 - ooOoO0o - I1IiiI
   if 51 - 51: I11i + I11i + O0 + O0 * I1Ii111
   if 61 - 61: IiII . O0
   if 38 - 38: Ii1I * I1ii11iIi11i - i11iIiiIii + ooOoO0o * I11i
   if 74 - 74: OoOoOO00 . o0oOOo0O0Ooo
   if 40 - 40: ooOoO0o + I1ii11iIi11i * i11iIiiIii / i1IIi
   if 95 - 95: oO0o / IiII * II111iiii * Ii1I . OoO0O00 . OoO0O00
   if 85 - 85: I1IiiI / II111iiii * OoO0O00 + ooOoO0o / OoO0O00 % OOooOOo
   if 100 - 100: I1Ii111 % OoooooooOO % OoOoOO00 % I1IiiI
   if 32 - 32: OoO0O00 + OOooOOo . OoO0O00 - Oo0Ooo
   if 12 - 12: I1IiiI * OoO0O00 - II111iiii . i1IIi
   oOOo = ( addr_str [ 2 : 4 ] == "::" )
   try :
    addr_str = socket . inet_pton ( socket . AF_INET6 , addr_str )
   except :
    addr_str = socket . inet_pton ( socket . AF_INET6 , "0::0" )
    if 88 - 88: I1ii11iIi11i * IiII - I1Ii111 / OoooooooOO
   addr_str = binascii . hexlify ( addr_str )
   if 99 - 99: o0oOOo0O0Ooo
   if ( oOOo ) :
    addr_str = addr_str [ 2 : 4 ] + addr_str [ 0 : 2 ] + addr_str [ 4 : : ]
    if 34 - 34: ooOoO0o / OoooooooOO . OOooOOo . OoO0O00 . IiII / Ii1I
   self . address = int ( addr_str , 16 )
   if 73 - 73: iII111i / iIii1I11I1II1
  elif ( self . is_geo_prefix ( ) ) :
   I11ii1I11III1 = lisp_geo ( None )
   I11ii1I11III1 . name = "geo-prefix-{}" . format ( I11ii1I11III1 )
   I11ii1I11III1 . parse_geo_string ( addr_str )
   self . address = I11ii1I11III1
  elif ( self . is_mac ( ) ) :
   addr_str = addr_str . replace ( "-" , "" )
   ooOoO = int ( addr_str , 16 )
   self . address = ooOoO
  elif ( self . is_e164 ( ) ) :
   addr_str = addr_str [ 1 : : ]
   ooOoO = int ( addr_str , 16 )
   self . address = ooOoO << 4
  elif ( self . is_dist_name ( ) ) :
   self . address = addr_str . replace ( "'" , "" )
   if 7 - 7: iII111i + OoOoOO00 - OoooooooOO % OoOoOO00 . oO0o * I1Ii111
  self . mask_len = self . host_mask_len ( )
  if 82 - 82: iIii1I11I1II1 / oO0o * iII111i . OoOoOO00 + II111iiii
  if 77 - 77: I1IiiI
 def store_prefix ( self , prefix_str ) :
  if ( self . is_geo_string ( prefix_str ) ) :
   I1Iiiiiii = prefix_str . find ( "]" )
   o0O00ooo0oO0o = len ( prefix_str [ I1Iiiiiii + 1 : : ] ) * 8
  elif ( prefix_str . find ( "/" ) != - 1 ) :
   prefix_str , o0O00ooo0oO0o = prefix_str . split ( "/" )
  else :
   o0 = prefix_str . find ( "'" )
   if ( o0 == - 1 ) : return
   oooO = prefix_str . find ( "'" , o0 + 1 )
   if ( oooO == - 1 ) : return
   o0O00ooo0oO0o = len ( prefix_str [ o0 + 1 : oooO ] ) * 8
   if 9 - 9: i11iIiiIii + OOooOOo * OoO0O00
   if 9 - 9: OOooOOo
  self . string_to_afi ( prefix_str )
  self . store_address ( prefix_str )
  self . mask_len = int ( o0O00ooo0oO0o )
  if 67 - 67: Oo0Ooo / I1Ii111 . ooOoO0o % oO0o / Oo0Ooo
  if 49 - 49: ooOoO0o + I1IiiI
 def zero_host_bits ( self ) :
  OOo00OO = ( 2 ** self . mask_len ) - 1
  o0ooO00OOo = self . addr_length ( ) * 8 - self . mask_len
  OOo00OO <<= o0ooO00OOo
  self . address &= OOo00OO
  if 38 - 38: IiII . oO0o * OoooooooOO . IiII + Ii1I
  if 74 - 74: o0oOOo0O0Ooo / iII111i
 def is_geo_string ( self , addr_str ) :
  I1Iiiiiii = addr_str . find ( "]" )
  if ( I1Iiiiiii != - 1 ) : addr_str = addr_str [ I1Iiiiiii + 1 : : ]
  if 95 - 95: ooOoO0o
  I11ii1I11III1 = addr_str . split ( "/" )
  if ( len ( I11ii1I11III1 ) == 2 ) :
   if ( I11ii1I11III1 [ 1 ] . isdigit ( ) == False ) : return ( False )
   if 22 - 22: Ii1I - Ii1I + IiII / I1IiiI
  I11ii1I11III1 = I11ii1I11III1 [ 0 ]
  I11ii1I11III1 = I11ii1I11III1 . split ( "-" )
  O0OOOO0OoooOoO = len ( I11ii1I11III1 )
  if ( O0OOOO0OoooOoO < 8 or O0OOOO0OoooOoO > 9 ) : return ( False )
  if 94 - 94: OOooOOo . Oo0Ooo + Ii1I * o0oOOo0O0Ooo
  for o0Oooo0 in range ( 0 , O0OOOO0OoooOoO ) :
   if ( o0Oooo0 == 3 ) :
    if ( I11ii1I11III1 [ o0Oooo0 ] in [ "N" , "S" ] ) : continue
    return ( False )
    if 42 - 42: iIii1I11I1II1 * iIii1I11I1II1
   if ( o0Oooo0 == 7 ) :
    if ( I11ii1I11III1 [ o0Oooo0 ] in [ "W" , "E" ] ) : continue
    return ( False )
    if 18 - 18: II111iiii + OoO0O00 . i1IIi / I11i % II111iiii . I1Ii111
   if ( I11ii1I11III1 [ o0Oooo0 ] . isdigit ( ) == False ) : return ( False )
   if 37 - 37: i1IIi - I1ii11iIi11i / OoO0O00 - iII111i / II111iiii
  return ( True )
  if 44 - 44: ooOoO0o
  if 16 - 16: OoOoOO00 - i11iIiiIii . o0oOOo0O0Ooo / o0oOOo0O0Ooo * Ii1I
 def string_to_afi ( self , addr_str ) :
  if ( addr_str . count ( "'" ) == 2 ) :
   self . afi = LISP_AFI_NAME
   return
   if 28 - 28: i1IIi - Oo0Ooo - i1IIi + IiII
  if ( addr_str . find ( ":" ) != - 1 ) : self . afi = LISP_AFI_IPV6
  elif ( addr_str . find ( "." ) != - 1 ) : self . afi = LISP_AFI_IPV4
  elif ( addr_str . find ( "+" ) != - 1 ) : self . afi = LISP_AFI_E164
  elif ( self . is_geo_string ( addr_str ) ) : self . afi = LISP_AFI_GEO_COORD
  elif ( addr_str . find ( "-" ) != - 1 ) : self . afi = LISP_AFI_MAC
  else : self . afi = LISP_AFI_NONE
  if 79 - 79: oO0o % o0oOOo0O0Ooo / o0oOOo0O0Ooo % iII111i
  if 56 - 56: Oo0Ooo % I1ii11iIi11i
 def print_address ( self ) :
  iIiIi1ii = self . print_address_no_iid ( )
  I1I111iIi = "[" + str ( self . instance_id )
  for iiIii1I in self . iid_list : I1I111iIi += "," + str ( iiIii1I )
  I1I111iIi += "]"
  iIiIi1ii = "{}{}" . format ( I1I111iIi , iIiIi1ii )
  return ( iIiIi1ii )
  if 53 - 53: OoO0O00 . I11i - ooOoO0o
  if 11 - 11: I11i + i11iIiiIii / oO0o % oO0o * o0oOOo0O0Ooo / OoOoOO00
 def print_address_no_iid ( self ) :
  if ( self . is_ipv4 ( ) ) :
   iIiIi1ii = self . address
   oOooO000o000oOo = iIiIi1ii >> 24
   ooooOO00O = ( iIiIi1ii >> 16 ) & 0xff
   i1IIiIIIiI = ( iIiIi1ii >> 8 ) & 0xff
   OoO0o0oo = iIiIi1ii & 0xff
   return ( "{}.{}.{}.{}" . format ( oOooO000o000oOo , ooooOO00O , i1IIiIIIiI , OoO0o0oo ) )
  elif ( self . is_ipv6 ( ) ) :
   oO00o = lisp_hex_string ( self . address ) . zfill ( 32 )
   oO00o = binascii . unhexlify ( oO00o )
   oO00o = socket . inet_ntop ( socket . AF_INET6 , oO00o )
   if 39 - 39: i1IIi
   if 16 - 16: OoOoOO00 % iIii1I11I1II1 + Ii1I - o0oOOo0O0Ooo . Oo0Ooo + i1IIi
   if 59 - 59: i1IIi
   if 37 - 37: OoO0O00 / I1ii11iIi11i / OoOoOO00
   if ( oO00o [ 2 : 6 ] == "00::" ) :
    oO00o = oO00o [ 0 : 2 ] + oO00o [ 4 : : ]
    if 15 - 15: I1IiiI % iIii1I11I1II1 . I1Ii111
   return ( "{}" . format ( oO00o ) )
  elif ( self . is_geo_prefix ( ) ) :
   return ( "{}" . format ( self . address . print_geo ( ) ) )
  elif ( self . is_mac ( ) ) :
   oO00o = lisp_hex_string ( self . address ) . zfill ( 12 )
   oO00o = "{}-{}-{}" . format ( oO00o [ 0 : 4 ] , oO00o [ 4 : 8 ] ,
 oO00o [ 8 : 12 ] )
   return ( "{}" . format ( oO00o ) )
  elif ( self . is_e164 ( ) ) :
   oO00o = lisp_hex_string ( self . address ) . zfill ( 15 )
   return ( "+{}" . format ( oO00o ) )
  elif ( self . is_dist_name ( ) ) :
   return ( "'{}'" . format ( self . address ) )
  elif ( self . is_null ( ) ) :
   return ( "no-address" )
   if 71 - 71: I11i - Ii1I + i11iIiiIii % I1ii11iIi11i - OoO0O00 - OOooOOo
  return ( "unknown-afi:{}" . format ( self . afi ) )
  if 71 - 71: OOooOOo
  if 27 - 27: OOooOOo * O0 * i11iIiiIii / OoOoOO00 - i1IIi
 def print_prefix ( self ) :
  if ( self . is_ultimate_root ( ) ) : return ( "[*]" )
  if ( self . is_iid_range ( ) ) :
   if ( self . mask_len == 32 ) : return ( "[{}]" . format ( self . instance_id ) )
   o00o0 = self . instance_id + ( 2 ** ( 32 - self . mask_len ) - 1 )
   return ( "[{}-{}]" . format ( self . instance_id , o00o0 ) )
   if 85 - 85: I11i + I11i + oO0o - OoOoOO00
  iIiIi1ii = self . print_address ( )
  if ( self . is_dist_name ( ) ) : return ( iIiIi1ii )
  if ( self . is_geo_prefix ( ) ) : return ( iIiIi1ii )
  if 15 - 15: OoO0O00
  I1Iiiiiii = iIiIi1ii . find ( "no-address" )
  if ( I1Iiiiiii == - 1 ) :
   iIiIi1ii = "{}/{}" . format ( iIiIi1ii , str ( self . mask_len ) )
  else :
   iIiIi1ii = iIiIi1ii [ 0 : I1Iiiiiii ]
   if 88 - 88: Ii1I % i1IIi / I1Ii111
  return ( iIiIi1ii )
  if 2 - 2: Ii1I . IiII % OoOoOO00
  if 42 - 42: OoOoOO00 * OoO0O00 * IiII - IiII % Oo0Ooo . IiII
 def print_prefix_no_iid ( self ) :
  iIiIi1ii = self . print_address_no_iid ( )
  if ( self . is_dist_name ( ) ) : return ( iIiIi1ii )
  if ( self . is_geo_prefix ( ) ) : return ( iIiIi1ii )
  return ( "{}/{}" . format ( iIiIi1ii , str ( self . mask_len ) ) )
  if 38 - 38: I1Ii111 . IiII - ooOoO0o . i11iIiiIii
  if 35 - 35: i11iIiiIii
 def print_prefix_url ( self ) :
  if ( self . is_ultimate_root ( ) ) : return ( "0--0" )
  iIiIi1ii = self . print_address ( )
  I1Iiiiiii = iIiIi1ii . find ( "]" )
  if ( I1Iiiiiii != - 1 ) : iIiIi1ii = iIiIi1ii [ I1Iiiiiii + 1 : : ]
  if ( self . is_geo_prefix ( ) ) :
   iIiIi1ii = iIiIi1ii . replace ( "/" , "-" )
   return ( "{}-{}" . format ( self . instance_id , iIiIi1ii ) )
   if 62 - 62: O0 - o0oOOo0O0Ooo + I1Ii111 * I1ii11iIi11i / OOooOOo
  return ( "{}-{}-{}" . format ( self . instance_id , iIiIi1ii , self . mask_len ) )
  if 87 - 87: Oo0Ooo / OoooooooOO + O0 / o0oOOo0O0Ooo % II111iiii - O0
  if 63 - 63: OOooOOo - OoO0O00 * i1IIi - I1ii11iIi11i . I1IiiI
 def print_sg ( self , g ) :
  I11iiIi1i1 = self . print_prefix ( )
  OoOOo00o0 = I11iiIi1i1 . find ( "]" ) + 1
  g = g . print_prefix ( )
  o0oOOo = g . find ( "]" ) + 1
  IIii1 = "[{}]({}, {})" . format ( self . instance_id , I11iiIi1i1 [ OoOOo00o0 : : ] , g [ o0oOOo : : ] )
  return ( IIii1 )
  if 3 - 3: i1IIi % O0 - I1IiiI
  if 55 - 55: I1ii11iIi11i % IiII % o0oOOo0O0Ooo + i1IIi * OoooooooOO % II111iiii
 def hash_address ( self , addr ) :
  O00OoOoO = self . address
  ooO0o0oo = addr . address
  if 37 - 37: Oo0Ooo
  if ( self . is_geo_prefix ( ) ) : O00OoOoO = self . address . print_geo ( )
  if ( addr . is_geo_prefix ( ) ) : ooO0o0oo = addr . address . print_geo ( )
  if 33 - 33: OoooooooOO - O0 . O0 - o0oOOo0O0Ooo % o0oOOo0O0Ooo % OoO0O00
  if ( type ( O00OoOoO ) == str ) :
   O00OoOoO = int ( binascii . hexlify ( O00OoOoO [ 0 : 1 ] ) )
   if 27 - 27: ooOoO0o . i11iIiiIii / o0oOOo0O0Ooo * OoO0O00 * OoOoOO00 * oO0o
  if ( type ( ooO0o0oo ) == str ) :
   ooO0o0oo = int ( binascii . hexlify ( ooO0o0oo [ 0 : 1 ] ) )
   if 19 - 19: O0 * II111iiii * OoOoOO00
  return ( O00OoOoO ^ ooO0o0oo )
  if 53 - 53: Oo0Ooo
  if 16 - 16: Ii1I
  if 73 - 73: i11iIiiIii + I1IiiI - IiII - IiII + IiII . Ii1I
  if 78 - 78: OoO0O00 + oO0o
  if 86 - 86: ooOoO0o . ooOoO0o + oO0o
  if 84 - 84: OOooOOo - OoOoOO00 + i1IIi * I1ii11iIi11i % I1ii11iIi11i * I1Ii111
 def is_more_specific ( self , prefix ) :
  if ( prefix . afi == LISP_AFI_ULTIMATE_ROOT ) : return ( True )
  if 31 - 31: IiII + iII111i
  o0O00ooo0oO0o = prefix . mask_len
  if ( prefix . afi == LISP_AFI_IID_RANGE ) :
   ii11111iiiI1 = 2 ** ( 32 - o0O00ooo0oO0o )
   IiiIii1IiI1 = prefix . instance_id
   o00o0 = IiiIii1IiI1 + ii11111iiiI1
   return ( self . instance_id in range ( IiiIii1IiI1 , o00o0 ) )
   if 14 - 14: oO0o / Ii1I - I1Ii111
   if 79 - 79: I1Ii111
  if ( self . instance_id != prefix . instance_id ) : return ( False )
  if ( self . afi != prefix . afi ) :
   if ( prefix . afi != LISP_AFI_NONE ) : return ( False )
   if 54 - 54: II111iiii
   if 98 - 98: Ii1I - i11iIiiIii
   if 31 - 31: IiII / o0oOOo0O0Ooo
   if 27 - 27: Oo0Ooo
   if 32 - 32: Oo0Ooo * i11iIiiIii % I1IiiI - i11iIiiIii - I1Ii111 % I1ii11iIi11i
  if ( self . is_binary ( ) == False ) :
   if ( prefix . afi == LISP_AFI_NONE ) : return ( True )
   if ( type ( self . address ) != type ( prefix . address ) ) : return ( False )
   iIiIi1ii = self . address
   IIi11iiiiI1 = prefix . address
   if ( self . is_geo_prefix ( ) ) :
    iIiIi1ii = self . address . print_geo ( )
    IIi11iiiiI1 = prefix . address . print_geo ( )
    if 81 - 81: I1ii11iIi11i - i11iIiiIii
   if ( len ( iIiIi1ii ) < len ( IIi11iiiiI1 ) ) : return ( False )
   return ( iIiIi1ii . find ( IIi11iiiiI1 ) == 0 )
   if 49 - 49: iII111i * I11i - II111iiii . o0oOOo0O0Ooo
   if 52 - 52: Ii1I + Ii1I - II111iiii . O0 + I1ii11iIi11i
   if 60 - 60: i11iIiiIii + IiII
   if 41 - 41: I1Ii111 * o0oOOo0O0Ooo + Oo0Ooo
   if 86 - 86: Ii1I / oO0o
  if ( self . mask_len < o0O00ooo0oO0o ) : return ( False )
  if 40 - 40: OoO0O00 % oO0o + Oo0Ooo
  o0ooO00OOo = ( prefix . addr_length ( ) * 8 ) - o0O00ooo0oO0o
  OOo00OO = ( 2 ** o0O00ooo0oO0o - 1 ) << o0ooO00OOo
  return ( ( self . address & OOo00OO ) == prefix . address )
  if 60 - 60: II111iiii / Ii1I
  if 14 - 14: iII111i - Oo0Ooo / o0oOOo0O0Ooo * oO0o / Oo0Ooo - I1IiiI
 def mask_address ( self , mask_len ) :
  o0ooO00OOo = ( self . addr_length ( ) * 8 ) - mask_len
  OOo00OO = ( 2 ** mask_len - 1 ) << o0ooO00OOo
  self . address &= OOo00OO
  if 89 - 89: i1IIi / I1Ii111 + Ii1I - i1IIi
  if 66 - 66: OoooooooOO
 def is_exact_match ( self , prefix ) :
  if ( self . instance_id != prefix . instance_id ) : return ( False )
  o000oOO = self . print_prefix ( )
  i1I1iI1i1i1 = prefix . print_prefix ( ) if prefix else ""
  return ( o000oOO == i1I1iI1i1i1 )
  if 87 - 87: I1IiiI * OOooOOo - I1Ii111 - iII111i
  if 67 - 67: oO0o
 def is_local ( self ) :
  if ( self . is_ipv4 ( ) ) :
   OoOoo0oOOO = lisp_myrlocs [ 0 ]
   if ( OoOoo0oOOO == None ) : return ( False )
   OoOoo0oOOO = OoOoo0oOOO . print_address_no_iid ( )
   return ( self . print_address_no_iid ( ) == OoOoo0oOOO )
   if 75 - 75: OoOoOO00 + iII111i - Oo0Ooo
  if ( self . is_ipv6 ( ) ) :
   OoOoo0oOOO = lisp_myrlocs [ 1 ]
   if ( OoOoo0oOOO == None ) : return ( False )
   OoOoo0oOOO = OoOoo0oOOO . print_address_no_iid ( )
   return ( self . print_address_no_iid ( ) == OoOoo0oOOO )
   if 51 - 51: iIii1I11I1II1 / iIii1I11I1II1
  return ( False )
  if 51 - 51: I1IiiI / I1Ii111 - iIii1I11I1II1 . I1Ii111
  if 52 - 52: II111iiii / OoO0O00 . Ii1I
 def store_iid_range ( self , iid , mask_len ) :
  if ( self . afi == LISP_AFI_NONE ) :
   if ( iid is 0 and mask_len is 0 ) : self . afi = LISP_AFI_ULTIMATE_ROOT
   else : self . afi = LISP_AFI_IID_RANGE
   if 68 - 68: iII111i
  self . instance_id = iid
  self . mask_len = mask_len
  if 67 - 67: I1IiiI * I1IiiI
  if 100 - 100: iII111i * iII111i . Oo0Ooo
 def lcaf_length ( self , lcaf_type ) :
  OOo000o = self . addr_length ( ) + 2
  if ( lcaf_type == LISP_LCAF_AFI_LIST_TYPE ) : OOo000o += 4
  if ( lcaf_type == LISP_LCAF_INSTANCE_ID_TYPE ) : OOo000o += 4
  if ( lcaf_type == LISP_LCAF_ASN_TYPE ) : OOo000o += 4
  if ( lcaf_type == LISP_LCAF_APP_DATA_TYPE ) : OOo000o += 8
  if ( lcaf_type == LISP_LCAF_GEO_COORD_TYPE ) : OOo000o += 12
  if ( lcaf_type == LISP_LCAF_OPAQUE_TYPE ) : OOo000o += 0
  if ( lcaf_type == LISP_LCAF_NAT_TYPE ) : OOo000o += 4
  if ( lcaf_type == LISP_LCAF_NONCE_LOC_TYPE ) : OOo000o += 4
  if ( lcaf_type == LISP_LCAF_MCAST_INFO_TYPE ) : OOo000o = OOo000o * 2 + 8
  if ( lcaf_type == LISP_LCAF_ELP_TYPE ) : OOo000o += 0
  if ( lcaf_type == LISP_LCAF_SECURITY_TYPE ) : OOo000o += 6
  if ( lcaf_type == LISP_LCAF_SOURCE_DEST_TYPE ) : OOo000o += 4
  if ( lcaf_type == LISP_LCAF_RLE_TYPE ) : OOo000o += 4
  return ( OOo000o )
  if 10 - 10: Oo0Ooo % ooOoO0o * Oo0Ooo
  if 48 - 48: ooOoO0o + II111iiii
  if 73 - 73: II111iiii
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
 def lcaf_encode_iid ( self ) :
  I1iI = LISP_LCAF_INSTANCE_ID_TYPE
  IiI1IIiiiii = socket . htons ( self . lcaf_length ( I1iI ) )
  I1I111iIi = self . instance_id
  ooo0oOOOO00Oo = self . afi
  II1i = 0
  if ( ooo0oOOOO00Oo < 0 ) :
   if ( self . afi == LISP_AFI_GEO_COORD ) :
    ooo0oOOOO00Oo = LISP_AFI_LCAF
    II1i = 0
   else :
    ooo0oOOOO00Oo = 0
    II1i = self . mask_len
    if 26 - 26: I1IiiI
    if 26 - 26: IiII . Ii1I / IiII - OoO0O00 % OoO0O00
    if 72 - 72: OoooooooOO * II111iiii + OoO0O00 % iIii1I11I1II1 . I1ii11iIi11i % OoooooooOO
  iI1iIi = struct . pack ( "BBBBH" , 0 , 0 , I1iI , II1i , IiI1IIiiiii )
  iI1iIi += struct . pack ( "IH" , socket . htonl ( I1I111iIi ) , socket . htons ( ooo0oOOOO00Oo ) )
  if ( ooo0oOOOO00Oo == 0 ) : return ( iI1iIi )
  if 58 - 58: I1ii11iIi11i * O0 . OoOoOO00
  if ( self . afi == LISP_AFI_GEO_COORD ) :
   iI1iIi = iI1iIi [ 0 : - 2 ]
   iI1iIi += self . address . encode_geo ( )
   return ( iI1iIi )
   if 87 - 87: oO0o - OoOoOO00
   if 40 - 40: iII111i . iII111i
  iI1iIi += self . pack_address ( )
  return ( iI1iIi )
  if 68 - 68: OoO0O00 / OoO0O00 - I1IiiI + OoOoOO00
  if 22 - 22: iIii1I11I1II1 . i1IIi . OOooOOo % Oo0Ooo - i1IIi
 def lcaf_decode_iid ( self , packet ) :
  ii1iI11IiIIi = "BBBBH"
  iiii = struct . calcsize ( ii1iI11IiIIi )
  if ( len ( packet ) < iiii ) : return ( None )
  if 78 - 78: I1IiiI / i1IIi % II111iiii % I1IiiI % Ii1I
  O0oo0oo0 , i11ii1i1i , I1iI , IiIIi1IIii , OOo000o = struct . unpack ( ii1iI11IiIIi ,
 packet [ : iiii ] )
  packet = packet [ iiii : : ]
  if 86 - 86: I1Ii111 % ooOoO0o + OoOoOO00 + II111iiii % I1Ii111 + i11iIiiIii
  if ( I1iI != LISP_LCAF_INSTANCE_ID_TYPE ) : return ( None )
  if 79 - 79: oO0o % I11i % I11i . ooOoO0o + I1IiiI + IiII
  ii1iI11IiIIi = "IH"
  iiii = struct . calcsize ( ii1iI11IiIIi )
  if ( len ( packet ) < iiii ) : return ( None )
  if 2 - 2: I1Ii111
  I1I111iIi , ooo0oOOOO00Oo = struct . unpack ( ii1iI11IiIIi , packet [ : iiii ] )
  packet = packet [ iiii : : ]
  if 4 - 4: OoooooooOO . iIii1I11I1II1
  OOo000o = socket . ntohs ( OOo000o )
  self . instance_id = socket . ntohl ( I1I111iIi )
  ooo0oOOOO00Oo = socket . ntohs ( ooo0oOOOO00Oo )
  self . afi = ooo0oOOOO00Oo
  if ( IiIIi1IIii != 0 and ooo0oOOOO00Oo == 0 ) : self . mask_len = IiIIi1IIii
  if ( ooo0oOOOO00Oo == 0 ) :
   self . afi = LISP_AFI_IID_RANGE if IiIIi1IIii else LISP_AFI_ULTIMATE_ROOT
   if 14 - 14: iIii1I11I1II1 * iII111i . i1IIi - OoooooooOO
   if 56 - 56: ooOoO0o . OoO0O00 * iIii1I11I1II1 / I11i % II111iiii . i1IIi
   if 48 - 48: I1IiiI . Oo0Ooo * o0oOOo0O0Ooo
   if 45 - 45: Ii1I % OOooOOo * Ii1I - iIii1I11I1II1
   if 18 - 18: I1Ii111 / Oo0Ooo % Ii1I + OoO0O00
  if ( ooo0oOOOO00Oo == 0 ) : return ( packet )
  if 69 - 69: iII111i % I1ii11iIi11i
  if 19 - 19: IiII
  if 35 - 35: OoOoOO00
  if 18 - 18: II111iiii . OoOoOO00 + I1ii11iIi11i * oO0o + OoooooooOO
  if ( self . is_dist_name ( ) ) :
   packet , self . address = lisp_decode_dist_name ( packet )
   self . mask_len = len ( self . address ) * 8
   return ( packet )
   if 39 - 39: I1IiiI * ooOoO0o / i11iIiiIii - oO0o - oO0o + O0
   if 73 - 73: OOooOOo
   if 44 - 44: I1ii11iIi11i * i1IIi - iIii1I11I1II1 - oO0o - oO0o * II111iiii
   if 98 - 98: Oo0Ooo + ooOoO0o / OOooOOo . iIii1I11I1II1 . I1IiiI . OoOoOO00
   if 92 - 92: i1IIi + OoOoOO00 * i1IIi / IiII
  if ( ooo0oOOOO00Oo == LISP_AFI_LCAF ) :
   ii1iI11IiIIi = "BBBBH"
   iiii = struct . calcsize ( ii1iI11IiIIi )
   if ( len ( packet ) < iiii ) : return ( None )
   if 4 - 4: oO0o % OoO0O00 + IiII + o0oOOo0O0Ooo
   OoO , oooO0o0O00o0O , I1iI , oOoO0oO , oOO0oOoooOo = struct . unpack ( ii1iI11IiIIi , packet [ : iiii ] )
   if 82 - 82: O0 / I1Ii111 + OOooOOo . IiII + Ii1I
   if 31 - 31: i1IIi * OoO0O00 - Ii1I + I11i
   if ( I1iI != LISP_LCAF_GEO_COORD_TYPE ) : return ( None )
   if 8 - 8: O0 + i1IIi . O0
   oOO0oOoooOo = socket . ntohs ( oOO0oOoooOo )
   packet = packet [ iiii : : ]
   if ( oOO0oOoooOo > len ( packet ) ) : return ( None )
   if 67 - 67: I1IiiI
   I11ii1I11III1 = lisp_geo ( "" )
   self . afi = LISP_AFI_GEO_COORD
   self . address = I11ii1I11III1
   packet = I11ii1I11III1 . decode_geo ( packet , oOO0oOoooOo , oOoO0oO )
   self . mask_len = self . host_mask_len ( )
   return ( packet )
   if 42 - 42: ooOoO0o - o0oOOo0O0Ooo % oO0o - ooOoO0o
   if 87 - 87: OoooooooOO / O0
  IiI1IIiiiii = self . addr_length ( )
  if ( len ( packet ) < IiI1IIiiiii ) : return ( None )
  if 57 - 57: iIii1I11I1II1 / IiII + OoO0O00 * oO0o + Ii1I
  packet = self . unpack_address ( packet )
  return ( packet )
  if 76 - 76: i11iIiiIii . OOooOOo / I11i * oO0o % iIii1I11I1II1 . ooOoO0o
  if 75 - 75: O0 + I1IiiI
  if 67 - 67: OoOoOO00 % OoooooooOO / OoO0O00 - OoO0O00 / O0
  if 19 - 19: iIii1I11I1II1 / OOooOOo % I11i % I1IiiI / I1ii11iIi11i
  if 73 - 73: II111iiii
  if 26 - 26: II111iiii . iIii1I11I1II1 - I1Ii111 % OOooOOo
  if 83 - 83: OOooOOo + OoooooooOO % I1Ii111 % IiII + i11iIiiIii
  if 10 - 10: OoooooooOO . Ii1I % I1Ii111 + IiII
  if 78 - 78: OoOoOO00 - oO0o . I1ii11iIi11i * i11iIiiIii
  if 44 - 44: iIii1I11I1II1 * iII111i
  if 32 - 32: OoOoOO00
  if 65 - 65: iIii1I11I1II1 + iII111i
  if 90 - 90: i11iIiiIii - Oo0Ooo
  if 31 - 31: OoOoOO00 + OoOoOO00 + OoooooooOO % O0
  if 14 - 14: i1IIi / OoooooooOO . I1IiiI * I1Ii111 + OoO0O00
  if 45 - 45: OoooooooOO * I1Ii111
  if 7 - 7: O0
  if 42 - 42: o0oOOo0O0Ooo / Ii1I
  if 31 - 31: OOooOOo
  if 20 - 20: i11iIiiIii * oO0o * ooOoO0o
  if 65 - 65: I1ii11iIi11i / Oo0Ooo / I1IiiI + IiII
 def lcaf_encode_sg ( self , group ) :
  I1iI = LISP_LCAF_MCAST_INFO_TYPE
  I1I111iIi = socket . htonl ( self . instance_id )
  IiI1IIiiiii = socket . htons ( self . lcaf_length ( I1iI ) )
  iI1iIi = struct . pack ( "BBBBHIHBB" , 0 , 0 , I1iI , 0 , IiI1IIiiiii , I1I111iIi ,
 0 , self . mask_len , group . mask_len )
  if 71 - 71: OoO0O00 . I1Ii111 + OoooooooOO
  iI1iIi += struct . pack ( "H" , socket . htons ( self . afi ) )
  iI1iIi += self . pack_address ( )
  iI1iIi += struct . pack ( "H" , socket . htons ( group . afi ) )
  iI1iIi += group . pack_address ( )
  return ( iI1iIi )
  if 9 - 9: OoooooooOO / iIii1I11I1II1 % I1IiiI . I1IiiI / I11i - iII111i
  if 60 - 60: I11i - OoO0O00 - OoOoOO00 * ooOoO0o - i1IIi
 def lcaf_decode_sg ( self , packet ) :
  ii1iI11IiIIi = "BBBBHIHBB"
  iiii = struct . calcsize ( ii1iI11IiIIi )
  if ( len ( packet ) < iiii ) : return ( [ None , None ] )
  if 18 - 18: ooOoO0o + i11iIiiIii + O0 + OOooOOo / Ii1I
  O0oo0oo0 , i11ii1i1i , I1iI , Iii1I , OOo000o , I1I111iIi , ooO0 , ooO0OO , Ii1Ii11i11 = struct . unpack ( ii1iI11IiIIi , packet [ : iiii ] )
  if 19 - 19: II111iiii * II111iiii / OoO0O00 + Ii1I - OoO0O00 - OOooOOo
  packet = packet [ iiii : : ]
  if 39 - 39: Oo0Ooo * I11i - Ii1I . OOooOOo
  if ( I1iI != LISP_LCAF_MCAST_INFO_TYPE ) : return ( [ None , None ] )
  if 21 - 21: oO0o
  self . instance_id = socket . ntohl ( I1I111iIi )
  OOo000o = socket . ntohs ( OOo000o ) - 8
  if 57 - 57: I1Ii111 % iII111i % oO0o . IiII + iIii1I11I1II1
  if 57 - 57: IiII
  if 29 - 29: o0oOOo0O0Ooo
  if 12 - 12: ooOoO0o + I11i * o0oOOo0O0Ooo % I1IiiI - OOooOOo
  if 40 - 40: OoooooooOO - o0oOOo0O0Ooo . I11i - Ii1I . Ii1I
  ii1iI11IiIIi = "H"
  iiii = struct . calcsize ( ii1iI11IiIIi )
  if ( len ( packet ) < iiii ) : return ( [ None , None ] )
  if ( OOo000o < iiii ) : return ( [ None , None ] )
  if 57 - 57: I1Ii111 . oO0o - OoooooooOO
  ooo0oOOOO00Oo = struct . unpack ( ii1iI11IiIIi , packet [ : iiii ] ) [ 0 ]
  packet = packet [ iiii : : ]
  OOo000o -= iiii
  self . afi = socket . ntohs ( ooo0oOOOO00Oo )
  self . mask_len = ooO0OO
  IiI1IIiiiii = self . addr_length ( )
  if ( OOo000o < IiI1IIiiiii ) : return ( [ None , None ] )
  if 74 - 74: I1ii11iIi11i + o0oOOo0O0Ooo * i11iIiiIii % OoooooooOO - IiII % i1IIi
  packet = self . unpack_address ( packet )
  if ( packet == None ) : return ( [ None , None ] )
  if 74 - 74: iII111i % I11i * i11iIiiIii . i11iIiiIii + iIii1I11I1II1 * i1IIi
  OOo000o -= IiI1IIiiiii
  if 53 - 53: I1ii11iIi11i + IiII / OOooOOo . OoooooooOO - ooOoO0o
  if 47 - 47: i11iIiiIii
  if 21 - 21: i1IIi - oO0o - Oo0Ooo
  if 11 - 11: i1IIi
  if 77 - 77: I11i + i1IIi * OoOoOO00 % OoooooooOO
  ii1iI11IiIIi = "H"
  iiii = struct . calcsize ( ii1iI11IiIIi )
  if ( len ( packet ) < iiii ) : return ( [ None , None ] )
  if ( OOo000o < iiii ) : return ( [ None , None ] )
  if 56 - 56: I1Ii111 * i1IIi % i11iIiiIii
  ooo0oOOOO00Oo = struct . unpack ( ii1iI11IiIIi , packet [ : iiii ] ) [ 0 ]
  packet = packet [ iiii : : ]
  OOo000o -= iiii
  iIiii1Ii1I = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  iIiii1Ii1I . afi = socket . ntohs ( ooo0oOOOO00Oo )
  iIiii1Ii1I . mask_len = Ii1Ii11i11
  iIiii1Ii1I . instance_id = self . instance_id
  IiI1IIiiiii = self . addr_length ( )
  if ( OOo000o < IiI1IIiiiii ) : return ( [ None , None ] )
  if 56 - 56: Ii1I . iII111i
  packet = iIiii1Ii1I . unpack_address ( packet )
  if ( packet == None ) : return ( [ None , None ] )
  if 76 - 76: I1IiiI / Ii1I % OoOoOO00 + IiII / i11iIiiIii . o0oOOo0O0Ooo
  return ( [ packet , iIiii1Ii1I ] )
  if 31 - 31: oO0o * oO0o % o0oOOo0O0Ooo . O0 + iII111i
  if 52 - 52: i11iIiiIii
 def lcaf_decode_eid ( self , packet ) :
  ii1iI11IiIIi = "BBB"
  iiii = struct . calcsize ( ii1iI11IiIIi )
  if ( len ( packet ) < iiii ) : return ( [ None , None ] )
  if 1 - 1: i1IIi * iIii1I11I1II1
  if 29 - 29: I11i
  if 12 - 12: oO0o % i1IIi - oO0o / ooOoO0o * II111iiii % ooOoO0o
  if 6 - 6: IiII / OoO0O00
  if 83 - 83: IiII - iIii1I11I1II1 * ooOoO0o - oO0o
  Iii1I , oooO0o0O00o0O , I1iI = struct . unpack ( ii1iI11IiIIi ,
 packet [ : iiii ] )
  if 77 - 77: Ii1I
  if ( I1iI == LISP_LCAF_INSTANCE_ID_TYPE ) :
   return ( [ self . lcaf_decode_iid ( packet ) , None ] )
  elif ( I1iI == LISP_LCAF_MCAST_INFO_TYPE ) :
   packet , iIiii1Ii1I = self . lcaf_decode_sg ( packet )
   return ( [ packet , iIiii1Ii1I ] )
  elif ( I1iI == LISP_LCAF_GEO_COORD_TYPE ) :
   ii1iI11IiIIi = "BBBBH"
   iiii = struct . calcsize ( ii1iI11IiIIi )
   if ( len ( packet ) < iiii ) : return ( None )
   if 9 - 9: OOooOOo / OoooooooOO + iII111i
   OoO , oooO0o0O00o0O , I1iI , oOoO0oO , oOO0oOoooOo = struct . unpack ( ii1iI11IiIIi , packet [ : iiii ] )
   if 52 - 52: IiII / OOooOOo * iIii1I11I1II1 + o0oOOo0O0Ooo
   if 20 - 20: I1Ii111
   if ( I1iI != LISP_LCAF_GEO_COORD_TYPE ) : return ( None )
   if 33 - 33: i11iIiiIii / I1Ii111 + IiII / II111iiii + I11i
   oOO0oOoooOo = socket . ntohs ( oOO0oOoooOo )
   packet = packet [ iiii : : ]
   if ( oOO0oOoooOo > len ( packet ) ) : return ( None )
   if 13 - 13: i1IIi % iII111i + OoOoOO00 / Ii1I . Ii1I + II111iiii
   I11ii1I11III1 = lisp_geo ( "" )
   self . instance_id = 0
   self . afi = LISP_AFI_GEO_COORD
   self . address = I11ii1I11III1
   packet = I11ii1I11III1 . decode_geo ( packet , oOO0oOoooOo , oOoO0oO )
   self . mask_len = self . host_mask_len ( )
   if 44 - 44: OoOoOO00 / OoooooooOO % O0 * Ii1I * IiII
  return ( [ packet , None ] )
  if 84 - 84: o0oOOo0O0Ooo * IiII * OOooOOo * iII111i
  if 56 - 56: iII111i * II111iiii . OoooooooOO . I11i
  if 25 - 25: ooOoO0o % o0oOOo0O0Ooo - i11iIiiIii
  if 79 - 79: iII111i - I1IiiI % O0 / Oo0Ooo + OoOoOO00 . Oo0Ooo
  if 59 - 59: I1ii11iIi11i * OoOoOO00 / Ii1I
  if 80 - 80: IiII - ooOoO0o / OoOoOO00 / I11i * O0 + oO0o
class lisp_elp_node ( ) :
 def __init__ ( self ) :
  self . address = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . probe = False
  self . strict = False
  self . eid = False
  self . we_are_last = False
  if 77 - 77: ooOoO0o + I1ii11iIi11i * o0oOOo0O0Ooo / i1IIi * I11i
  if 70 - 70: oO0o / iII111i * i1IIi / II111iiii / OoOoOO00 + oO0o
 def copy_elp_node ( self ) :
  i1i = lisp_elp_node ( )
  i1i . copy_address ( self . address )
  i1i . probe = self . probe
  i1i . strict = self . strict
  i1i . eid = self . eid
  i1i . we_are_last = self . we_are_last
  return ( i1i )
  if 30 - 30: i1IIi - iII111i - i11iIiiIii . OoOoOO00 . o0oOOo0O0Ooo
  if 74 - 74: i11iIiiIii / II111iiii
  if 62 - 62: O0
class lisp_elp ( ) :
 def __init__ ( self , name ) :
  self . elp_name = name
  self . elp_nodes = [ ]
  self . use_elp_node = None
  self . we_are_last = False
  if 63 - 63: Oo0Ooo + Oo0Ooo
  if 48 - 48: Oo0Ooo * I1ii11iIi11i % II111iiii
 def copy_elp ( self ) :
  iII1i = lisp_elp ( self . elp_name )
  iII1i . use_elp_node = self . use_elp_node
  iII1i . we_are_last = self . we_are_last
  for i1i in self . elp_nodes :
   iII1i . elp_nodes . append ( i1i . copy_elp_node ( ) )
   if 42 - 42: I1Ii111 - ooOoO0o % o0oOOo0O0Ooo * I1IiiI . o0oOOo0O0Ooo
  return ( iII1i )
  if 84 - 84: iIii1I11I1II1
  if 39 - 39: Ii1I . II111iiii / I1IiiI
 def print_elp ( self , want_marker ) :
  o0oOiiI1 = ""
  for i1i in self . elp_nodes :
   I1i11 = ""
   if ( want_marker ) :
    if ( i1i == self . use_elp_node ) :
     I1i11 = "*"
    elif ( i1i . we_are_last ) :
     I1i11 = "x"
     if 41 - 41: OoooooooOO * I11i
     if 59 - 59: ooOoO0o * I1Ii111 - ooOoO0o
   o0oOiiI1 += "{}{}({}{}{}), " . format ( I1i11 ,
 i1i . address . print_address_no_iid ( ) ,
 "r" if i1i . eid else "R" , "P" if i1i . probe else "p" ,
 "S" if i1i . strict else "s" )
   if 48 - 48: O0 * O0 - iII111i . iII111i + I1Ii111
  return ( o0oOiiI1 [ 0 : - 2 ] if o0oOiiI1 != "" else "" )
  if 25 - 25: o0oOOo0O0Ooo . I1ii11iIi11i + i1IIi
  if 35 - 35: I1Ii111 % iII111i - i11iIiiIii / Oo0Ooo * iII111i + iII111i
 def select_elp_node ( self ) :
  oO0o0oOOO0000 , II , O0o0o0 = lisp_myrlocs
  I1Iiiiiii = None
  if 66 - 66: Ii1I - Oo0Ooo / oO0o + iII111i % IiII
  for i1i in self . elp_nodes :
   if ( oO0o0oOOO0000 and i1i . address . is_exact_match ( oO0o0oOOO0000 ) ) :
    I1Iiiiiii = self . elp_nodes . index ( i1i )
    break
    if 19 - 19: I1IiiI + I1IiiI + I1Ii111 % i1IIi * I1IiiI
   if ( II and i1i . address . is_exact_match ( II ) ) :
    I1Iiiiiii = self . elp_nodes . index ( i1i )
    break
    if 83 - 83: II111iiii - o0oOOo0O0Ooo . OoO0O00 . OOooOOo % o0oOOo0O0Ooo
    if 96 - 96: i1IIi % OoooooooOO * OOooOOo - Oo0Ooo + iIii1I11I1II1
    if 87 - 87: I11i . I1ii11iIi11i / i1IIi - II111iiii - i11iIiiIii
    if 49 - 49: I1ii11iIi11i + I1Ii111 * OOooOOo - IiII . i11iIiiIii
    if 34 - 34: iII111i . OoOoOO00
    if 49 - 49: I1ii11iIi11i % oO0o - I1Ii111 . I1ii11iIi11i % II111iiii
    if 20 - 20: I1ii11iIi11i . iIii1I11I1II1 - Ii1I % OoO0O00
  if ( I1Iiiiiii == None ) :
   self . use_elp_node = self . elp_nodes [ 0 ]
   i1i . we_are_last = False
   return
   if 27 - 27: iIii1I11I1II1 / I1Ii111 - I11i . OoO0O00 + ooOoO0o
   if 89 - 89: I1IiiI % I11i - OOooOOo
   if 71 - 71: OOooOOo % Oo0Ooo - o0oOOo0O0Ooo / I1Ii111 - O0 - oO0o
   if 10 - 10: I1IiiI
   if 17 - 17: i11iIiiIii % o0oOOo0O0Ooo . ooOoO0o
   if 34 - 34: OoooooooOO / iII111i / O0
  if ( self . elp_nodes [ - 1 ] == self . elp_nodes [ I1Iiiiiii ] ) :
   self . use_elp_node = None
   i1i . we_are_last = True
   return
   if 75 - 75: I11i % OOooOOo - OoO0O00 * I11i * IiII
   if 11 - 11: I1ii11iIi11i . O0 - iII111i * IiII . i1IIi . iII111i
   if 82 - 82: i1IIi * I11i * Ii1I - IiII . i11iIiiIii
   if 40 - 40: OOooOOo - OoooooooOO
   if 36 - 36: i1IIi % OoOoOO00 - i1IIi
  self . use_elp_node = self . elp_nodes [ I1Iiiiiii + 1 ]
  return
  if 5 - 5: I1IiiI . I1IiiI % II111iiii - I1Ii111
  if 97 - 97: I11i . ooOoO0o
  if 87 - 87: oO0o / iIii1I11I1II1 - I11i + OoooooooOO
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
  if 79 - 79: I1ii11iIi11i * IiII . I1ii11iIi11i
  if 65 - 65: iII111i - Ii1I - II111iiii * O0 + I1ii11iIi11i . iIii1I11I1II1
 def copy_geo ( self ) :
  I11ii1I11III1 = lisp_geo ( self . geo_name )
  I11ii1I11III1 . latitude = self . latitude
  I11ii1I11III1 . lat_mins = self . lat_mins
  I11ii1I11III1 . lat_secs = self . lat_secs
  I11ii1I11III1 . longitude = self . longitude
  I11ii1I11III1 . long_mins = self . long_mins
  I11ii1I11III1 . long_secs = self . long_secs
  I11ii1I11III1 . altitude = self . altitude
  I11ii1I11III1 . radius = self . radius
  return ( I11ii1I11III1 )
  if 76 - 76: OoO0O00 * ooOoO0o
  if 32 - 32: O0 . oO0o * o0oOOo0O0Ooo . Ii1I + IiII
 def no_geo_altitude ( self ) :
  return ( self . altitude == - 1 )
  if 98 - 98: iII111i . II111iiii % O0
  if 43 - 43: OOooOOo % I1Ii111 . IiII % OoO0O00 + I1Ii111 % OoooooooOO
 def parse_geo_string ( self , geo_str ) :
  I1Iiiiiii = geo_str . find ( "]" )
  if ( I1Iiiiiii != - 1 ) : geo_str = geo_str [ I1Iiiiiii + 1 : : ]
  if 17 - 17: OoooooooOO - i1IIi * I11i
  if 33 - 33: i1IIi . Oo0Ooo + I11i
  if 97 - 97: OOooOOo / IiII / ooOoO0o / OoooooooOO
  if 78 - 78: I1Ii111 + I1Ii111
  if 43 - 43: I1Ii111 * o0oOOo0O0Ooo + i1IIi
  if ( geo_str . find ( "/" ) != - 1 ) :
   geo_str , iIiIIIIiII1 = geo_str . split ( "/" )
   self . radius = int ( iIiIIIIiII1 )
   if 94 - 94: I1IiiI + o0oOOo0O0Ooo % Oo0Ooo
   if 30 - 30: OOooOOo
  geo_str = geo_str . split ( "-" )
  if ( len ( geo_str ) < 8 ) : return ( False )
  if 18 - 18: I1ii11iIi11i
  II1 = geo_str [ 0 : 4 ]
  ooO0oo = geo_str [ 4 : 8 ]
  if 56 - 56: II111iiii + II111iiii - I1ii11iIi11i
  if 48 - 48: I1Ii111 / I1ii11iIi11i % OOooOOo
  if 8 - 8: O0 . IiII - ooOoO0o * OoOoOO00 / OoO0O00 - O0
  if 41 - 41: OOooOOo % I11i + I1Ii111 / ooOoO0o
  if ( len ( geo_str ) > 8 ) : self . altitude = int ( geo_str [ 8 ] )
  if 34 - 34: iII111i - ooOoO0o + iIii1I11I1II1 + i1IIi . Ii1I
  if 34 - 34: I1IiiI + i1IIi . II111iiii . O0
  if 86 - 86: oO0o . OoOoOO00 - I11i . OOooOOo % OoO0O00
  if 79 - 79: iII111i / Ii1I % i11iIiiIii . I1IiiI % OoO0O00 / i11iIiiIii
  self . latitude = int ( II1 [ 0 ] )
  self . lat_mins = int ( II1 [ 1 ] )
  self . lat_secs = int ( II1 [ 2 ] )
  if ( II1 [ 3 ] == "N" ) : self . latitude = - self . latitude
  if 100 - 100: OOooOOo + Oo0Ooo . iIii1I11I1II1 . ooOoO0o * Oo0Ooo
  if 16 - 16: Oo0Ooo % OoOoOO00 + I1Ii111 % I1Ii111
  if 12 - 12: I1Ii111 . Ii1I / iIii1I11I1II1 + i1IIi
  if 9 - 9: iIii1I11I1II1
  self . longitude = int ( ooO0oo [ 0 ] )
  self . long_mins = int ( ooO0oo [ 1 ] )
  self . long_secs = int ( ooO0oo [ 2 ] )
  if ( ooO0oo [ 3 ] == "E" ) : self . longitude = - self . longitude
  return ( True )
  if 75 - 75: I11i . II111iiii * I1IiiI * IiII
  if 36 - 36: OOooOOo / I1ii11iIi11i / oO0o / ooOoO0o / I11i
 def print_geo ( self ) :
  III1iIIIi = "N" if self . latitude < 0 else "S"
  IIi1IiiIiiI = "E" if self . longitude < 0 else "W"
  if 47 - 47: II111iiii / o0oOOo0O0Ooo * o0oOOo0O0Ooo + oO0o
  o0O0oO = "{}-{}-{}-{}-{}-{}-{}-{}" . format ( abs ( self . latitude ) ,
 self . lat_mins , self . lat_secs , III1iIIIi , abs ( self . longitude ) ,
 self . long_mins , self . long_secs , IIi1IiiIiiI )
  if 3 - 3: Oo0Ooo
  if ( self . no_geo_altitude ( ) == False ) :
   o0O0oO += "-" + str ( self . altitude )
   if 82 - 82: OoooooooOO + OoO0O00 . OoO0O00 * OoO0O00
   if 99 - 99: I1ii11iIi11i - OoooooooOO - Ii1I / Oo0Ooo
   if 96 - 96: o0oOOo0O0Ooo . II111iiii
   if 14 - 14: OoooooooOO - i1IIi / i11iIiiIii - OOooOOo - i11iIiiIii . ooOoO0o
   if 8 - 8: oO0o * O0 - II111iiii + I1IiiI
  if ( self . radius != 0 ) : o0O0oO += "/{}" . format ( self . radius )
  return ( o0O0oO )
  if 85 - 85: OoooooooOO % i11iIiiIii / IiII % OoOoOO00 + O0
  if 6 - 6: OoooooooOO
 def geo_url ( self ) :
  oo0OooO = os . getenv ( "LISP_GEO_ZOOM_LEVEL" )
  oo0OooO = "10" if ( oo0OooO == "" or oo0OooO . isdigit ( ) == False ) else oo0OooO
  I1i111i , OOoOO0o0O = self . dms_to_decimal ( )
  o00OOOo = ( "http://maps.googleapis.com/maps/api/staticmap?center={},{}" + "&markers=color:blue%7Clabel:lisp%7C{},{}" + "&zoom={}&size=1024x1024&sensor=false" ) . format ( I1i111i , OOoOO0o0O , I1i111i , OOoOO0o0O ,
  # OOooOOo * IiII
  # ooOoO0o
 oo0OooO )
  return ( o00OOOo )
  if 37 - 37: OoooooooOO - OOooOOo - o0oOOo0O0Ooo . II111iiii
  if 13 - 13: i11iIiiIii / I1Ii111 + iII111i + I11i % I11i
 def print_geo_url ( self ) :
  I11ii1I11III1 = self . print_geo ( )
  if ( self . radius == 0 ) :
   o00OOOo = self . geo_url ( )
   oOO00OO0OooOo = "<a href='{}'>{}</a>" . format ( o00OOOo , I11ii1I11III1 )
  else :
   o00OOOo = I11ii1I11III1 . replace ( "/" , "-" )
   oOO00OO0OooOo = "<a href='/lisp/geo-map/{}'>{}</a>" . format ( o00OOOo , I11ii1I11III1 )
   if 82 - 82: II111iiii * I11i
  return ( oOO00OO0OooOo )
  if 35 - 35: I1IiiI * OoO0O00 - iII111i . Ii1I + ooOoO0o
  if 81 - 81: OOooOOo / OoooooooOO . I1IiiI % OoO0O00 % I1Ii111 / ooOoO0o
 def dms_to_decimal ( self ) :
  oooOiIII11IiiI , o0oOi1IIII11IIII , oo0OOOOo00 = self . latitude , self . lat_mins , self . lat_secs
  iiiiiIiiiIiiii1iI = float ( abs ( oooOiIII11IiiI ) )
  iiiiiIiiiIiiii1iI += float ( o0oOi1IIII11IIII * 60 + oo0OOOOo00 ) / 3600
  if ( oooOiIII11IiiI > 0 ) : iiiiiIiiiIiiii1iI = - iiiiiIiiiIiiii1iI
  ooOoOoO0ooOOo = iiiiiIiiiIiiii1iI
  if 47 - 47: I11i - I1Ii111 % OoooooooOO
  oooOiIII11IiiI , o0oOi1IIII11IIII , oo0OOOOo00 = self . longitude , self . long_mins , self . long_secs
  iiiiiIiiiIiiii1iI = float ( abs ( oooOiIII11IiiI ) )
  iiiiiIiiiIiiii1iI += float ( o0oOi1IIII11IIII * 60 + oo0OOOOo00 ) / 3600
  if ( oooOiIII11IiiI > 0 ) : iiiiiIiiiIiiii1iI = - iiiiiIiiiIiiii1iI
  i1III = iiiiiIiiiIiiii1iI
  return ( ( ooOoOoO0ooOOo , i1III ) )
  if 47 - 47: OoOoOO00 . iIii1I11I1II1 * i11iIiiIii
  if 83 - 83: I1IiiI . i11iIiiIii * iII111i
 def get_distance ( self , geo_point ) :
  o0o00o0 = self . dms_to_decimal ( )
  OOo00OoOOOOO0 = geo_point . dms_to_decimal ( )
  IiI = vincenty ( o0o00o0 , OOo00OoOOOOO0 )
  return ( IiI . km )
  if 1 - 1: I1Ii111
  if 2 - 2: I1Ii111 / OoooooooOO + OoOoOO00 - Ii1I . i1IIi
 def point_in_circle ( self , geo_point ) :
  oo0Oo00Oo00 = self . get_distance ( geo_point )
  return ( oo0Oo00Oo00 <= self . radius )
  if 27 - 27: I1IiiI
  if 12 - 12: o0oOOo0O0Ooo + iII111i + O0
 def encode_geo ( self ) :
  IiiIi = socket . htons ( LISP_AFI_LCAF )
  O0OOOO0OoooOoO = socket . htons ( 20 + 2 )
  oooO0o0O00o0O = 0
  if 70 - 70: i11iIiiIii
  I1i111i = abs ( self . latitude )
  iIIIiIii11IIi = ( ( self . lat_mins * 60 ) + self . lat_secs ) * 1000
  if ( self . latitude < 0 ) : oooO0o0O00o0O |= 0x40
  if 13 - 13: Oo0Ooo - i1IIi * ooOoO0o * Oo0Ooo + oO0o - o0oOOo0O0Ooo
  OOoOO0o0O = abs ( self . longitude )
  Ii1i1i1 = ( ( self . long_mins * 60 ) + self . long_secs ) * 1000
  if ( self . longitude < 0 ) : oooO0o0O00o0O |= 0x20
  if 14 - 14: I11i . II111iiii
  Ii1IiI11i = 0
  if ( self . no_geo_altitude ( ) == False ) :
   Ii1IiI11i = socket . htonl ( self . altitude )
   oooO0o0O00o0O |= 0x10
   if 11 - 11: i1IIi / I11i * OoOoOO00 * IiII . ooOoO0o * i1IIi
  iIiIIIIiII1 = socket . htons ( self . radius )
  if ( iIiIIIIiII1 != 0 ) : oooO0o0O00o0O |= 0x06
  if 85 - 85: i11iIiiIii . OoO0O00 + I1IiiI
  OoOoooO = struct . pack ( "HBBBBH" , IiiIi , 0 , 0 , LISP_LCAF_GEO_COORD_TYPE ,
 0 , O0OOOO0OoooOoO )
  OoOoooO += struct . pack ( "BBHBBHBBHIHHH" , oooO0o0O00o0O , 0 , 0 , I1i111i , iIIIiIii11IIi >> 16 ,
 socket . htons ( iIIIiIii11IIi & 0x0ffff ) , OOoOO0o0O , Ii1i1i1 >> 16 ,
 socket . htons ( Ii1i1i1 & 0xffff ) , Ii1IiI11i , iIiIIIIiII1 , 0 , 0 )
  if 65 - 65: iII111i / I1ii11iIi11i * I11i
  return ( OoOoooO )
  if 75 - 75: iIii1I11I1II1 . iII111i + i11iIiiIii
  if 97 - 97: iIii1I11I1II1 * IiII % OoooooooOO
 def decode_geo ( self , packet , lcaf_len , radius_hi ) :
  ii1iI11IiIIi = "BBHBBHBBHIHHH"
  iiii = struct . calcsize ( ii1iI11IiIIi )
  if ( lcaf_len < iiii ) : return ( None )
  if 58 - 58: ooOoO0o % OoO0O00 / I1ii11iIi11i / I1ii11iIi11i / ooOoO0o / OOooOOo
  oooO0o0O00o0O , I1iIIIII , oOoooO , I1i111i , iiI1I1III1 , iIIIiIii11IIi , OOoOO0o0O , iII11II1iii , Ii1i1i1 , Ii1IiI11i , iIiIIIIiII1 , o0oOO000 , ooo0oOOOO00Oo = struct . unpack ( ii1iI11IiIIi ,
  # ooOoO0o + iII111i * OoO0O00 % II111iiii % iII111i + oO0o
 packet [ : iiii ] )
  if 19 - 19: I1Ii111 - OOooOOo . ooOoO0o . O0 + II111iiii . OoooooooOO
  if 97 - 97: O0 / OoOoOO00 / ooOoO0o
  if 11 - 11: II111iiii . i11iIiiIii - Ii1I . IiII
  if 10 - 10: OOooOOo * OoooooooOO
  ooo0oOOOO00Oo = socket . ntohs ( ooo0oOOOO00Oo )
  if ( ooo0oOOOO00Oo == LISP_AFI_LCAF ) : return ( None )
  if 12 - 12: II111iiii - O0 . i1IIi % oO0o % OoooooooOO
  if ( oooO0o0O00o0O & 0x40 ) : I1i111i = - I1i111i
  self . latitude = I1i111i
  I1IIIiiI11ii = ( ( iiI1I1III1 << 16 ) | socket . ntohs ( iIIIiIii11IIi ) ) / 1000
  self . lat_mins = I1IIIiiI11ii / 60
  self . lat_secs = I1IIIiiI11ii % 60
  if 74 - 74: OoO0O00 * O0 - oO0o * OoooooooOO % I1Ii111
  if ( oooO0o0O00o0O & 0x20 ) : OOoOO0o0O = - OOoOO0o0O
  self . longitude = OOoOO0o0O
  OOo00oO = ( ( iII11II1iii << 16 ) | socket . ntohs ( Ii1i1i1 ) ) / 1000
  self . long_mins = OOo00oO / 60
  self . long_secs = OOo00oO % 60
  if 75 - 75: OOooOOo - i11iIiiIii - i1IIi - IiII * iII111i
  self . altitude = socket . ntohl ( Ii1IiI11i ) if ( oooO0o0O00o0O & 0x10 ) else - 1
  iIiIIIIiII1 = socket . ntohs ( iIiIIIIiII1 )
  self . radius = iIiIIIIiII1 if ( oooO0o0O00o0O & 0x02 ) else iIiIIIIiII1 * 1000
  if 38 - 38: o0oOOo0O0Ooo - I1ii11iIi11i % o0oOOo0O0Ooo
  self . geo_name = None
  packet = packet [ iiii : : ]
  if 8 - 8: oO0o + I11i . I1ii11iIi11i
  if ( ooo0oOOOO00Oo != 0 ) :
   self . rloc . afi = ooo0oOOOO00Oo
   packet = self . rloc . unpack_address ( packet )
   self . rloc . mask_len = self . rloc . host_mask_len ( )
   if 57 - 57: I11i
  return ( packet )
  if 46 - 46: iII111i . OoO0O00 % Ii1I
  if 36 - 36: I1Ii111 % Oo0Ooo % OoO0O00 - oO0o * OoOoOO00 * OoOoOO00
  if 70 - 70: i11iIiiIii - I1IiiI * OoO0O00 % OOooOOo . i1IIi
  if 48 - 48: i1IIi / II111iiii + OOooOOo . OoOoOO00 / iII111i - OoO0O00
  if 45 - 45: I1Ii111 - OoO0O00 / Ii1I % OoooooooOO
  if 98 - 98: iIii1I11I1II1 * i11iIiiIii / Ii1I / I1ii11iIi11i % o0oOOo0O0Ooo % IiII
class lisp_rle_node ( ) :
 def __init__ ( self ) :
  self . address = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . level = 0
  self . translated_port = 0
  self . rloc_name = None
  if 99 - 99: I1Ii111 % iII111i - Ii1I + Oo0Ooo % O0 % o0oOOo0O0Ooo
  if 22 - 22: I1ii11iIi11i . O0 - oO0o % OoO0O00 % OoooooooOO
 def copy_rle_node ( self ) :
  OO = lisp_rle_node ( )
  OO . address . copy_address ( self . address )
  OO . level = self . level
  OO . translated_port = self . translated_port
  OO . rloc_name = self . rloc_name
  return ( OO )
  if 67 - 67: I11i
  if 23 - 23: I1ii11iIi11i - OoOoOO00
 def store_translated_rloc ( self , rloc , port ) :
  self . address . copy_address ( rloc )
  self . translated_port = port
  if 90 - 90: ooOoO0o - I11i / OoOoOO00
  if 12 - 12: II111iiii % I1IiiI - I1ii11iIi11i
 def get_encap_keys ( self ) :
  OoO0o = "4341" if self . translated_port == 0 else str ( self . translated_port )
  if 24 - 24: Ii1I + I11i
  oO00o = self . address . print_address_no_iid ( ) + ":" + OoO0o
  if 5 - 5: I1Ii111 . Ii1I - ooOoO0o % OoooooooOO
  try :
   IiI1ii11I1 = lisp_crypto_keys_by_rloc_encap [ oO00o ]
   if ( IiI1ii11I1 [ 1 ] ) : return ( IiI1ii11I1 [ 1 ] . encrypt_key , IiI1ii11I1 [ 1 ] . icv_key )
   return ( None , None )
  except :
   return ( None , None )
   if 2 - 2: OOooOOo . IiII . iII111i / Oo0Ooo
   if 86 - 86: OOooOOo . o0oOOo0O0Ooo - iIii1I11I1II1
   if 12 - 12: oO0o + iII111i
   if 16 - 16: O0 + oO0o - ooOoO0o * O0 . I1ii11iIi11i . oO0o
class lisp_rle ( ) :
 def __init__ ( self , name ) :
  self . rle_name = name
  self . rle_nodes = [ ]
  self . rle_forwarding_list = [ ]
  if 4 - 4: I1Ii111
  if 39 - 39: OoOoOO00 - I1Ii111 / I11i + II111iiii * I1IiiI * I1IiiI
 def copy_rle ( self ) :
  o0ooOOoO0oO0 = lisp_rle ( self . rle_name )
  for OO in self . rle_nodes :
   o0ooOOoO0oO0 . rle_nodes . append ( OO . copy_rle_node ( ) )
   if 9 - 9: IiII * I1IiiI * OoO0O00 - I1IiiI * I1IiiI - OoO0O00
  o0ooOOoO0oO0 . build_forwarding_list ( )
  return ( o0ooOOoO0oO0 )
  if 20 - 20: i1IIi + I1IiiI + i11iIiiIii + II111iiii + i1IIi
  if 18 - 18: i11iIiiIii * O0 * Oo0Ooo + iII111i + OOooOOo
 def print_rle ( self , html ) :
  iIiiii = ""
  for OO in self . rle_nodes :
   OoO0o = OO . translated_port
   O0OO0oo0o = blue ( OO . rloc_name , html ) if OO . rloc_name != None else ""
   if 95 - 95: II111iiii * I1ii11iIi11i
   oO00o = OO . address . print_address_no_iid ( )
   if ( OO . address . is_local ( ) ) : oO00o = red ( oO00o , html )
   iIiiii += "{}{}(L{}){}, " . format ( oO00o , "" if OoO0o == 0 else "-" + str ( OoO0o ) , OO . level ,
   # I1IiiI / i11iIiiIii . ooOoO0o / O0 % o0oOOo0O0Ooo
 "" if OO . rloc_name == None else O0OO0oo0o )
   if 4 - 4: I1ii11iIi11i * II111iiii - Oo0Ooo % i1IIi % O0 * i11iIiiIii
  return ( iIiiii [ 0 : - 2 ] if iIiiii != "" else "" )
  if 62 - 62: OoO0O00 * I1Ii111 * Ii1I / ooOoO0o
  if 27 - 27: oO0o . iII111i . oO0o
 def build_forwarding_list ( self ) :
  oooo0O = - 1
  for OO in self . rle_nodes :
   if ( oooo0O == - 1 ) :
    if ( OO . address . is_local ( ) ) : oooo0O = OO . level
   else :
    if ( OO . level > oooo0O ) : break
    if 37 - 37: Oo0Ooo . I1ii11iIi11i / OoooooooOO % ooOoO0o / I1IiiI + ooOoO0o
    if 14 - 14: I11i + ooOoO0o . oO0o * I11i
  oooo0O = 0 if oooo0O == - 1 else OO . level
  if 98 - 98: Ii1I . i1IIi * OoO0O00 * Ii1I * iIii1I11I1II1
  self . rle_forwarding_list = [ ]
  for OO in self . rle_nodes :
   if ( OO . level == oooo0O or ( oooo0O == 0 and
 OO . level == 128 ) ) :
    if ( lisp_i_am_rtr == False and OO . address . is_local ( ) ) :
     oO00o = OO . address . print_address_no_iid ( )
     lprint ( "Exclude local RLE RLOC {}" . format ( oO00o ) )
     continue
     if 22 - 22: OoooooooOO - OoO0O00 + OoOoOO00 - OOooOOo + i11iIiiIii - oO0o
    self . rle_forwarding_list . append ( OO )
    if 9 - 9: I1Ii111 - i1IIi . ooOoO0o
    if 33 - 33: I11i
    if 37 - 37: Oo0Ooo
    if 36 - 36: IiII % I11i
    if 72 - 72: oO0o % I11i % OOooOOo * iIii1I11I1II1 - OOooOOo % O0
class lisp_json ( ) :
 def __init__ ( self , name , string ) :
  self . json_name = name
  self . json_string = string
  if 84 - 84: oO0o - o0oOOo0O0Ooo / II111iiii . o0oOOo0O0Ooo
  if 82 - 82: OoooooooOO
 def add ( self ) :
  self . delete ( )
  lisp_json_list [ self . json_name ] = self
  if 14 - 14: OoO0O00 / oO0o - OOooOOo
  if 100 - 100: IiII - I11i . iIii1I11I1II1 / iIii1I11I1II1
 def delete ( self ) :
  if ( lisp_json_list . has_key ( self . json_name ) ) :
   del ( lisp_json_list [ self . json_name ] )
   lisp_json_list [ self . json_name ] = None
   if 16 - 16: IiII + Oo0Ooo % I11i
   if 16 - 16: ooOoO0o / I1Ii111
   if 78 - 78: OoOoOO00 - II111iiii - OOooOOo + I1IiiI + O0 / I1IiiI
 def print_json ( self , html ) :
  O0iiii = self . json_string
  IIIo000 = "***"
  if ( html ) : IIIo000 = red ( IIIo000 , html )
  I1i1 = IIIo000 + self . json_string + IIIo000
  if ( self . valid_json ( ) ) : return ( O0iiii )
  return ( I1i1 )
  if 37 - 37: OOooOOo % OoOoOO00 - II111iiii * o0oOOo0O0Ooo . I1IiiI . OoOoOO00
  if 92 - 92: I11i + OoO0O00 . OoooooooOO
 def valid_json ( self ) :
  try :
   json . loads ( self . json_string )
  except :
   return ( False )
   if 3 - 3: OoO0O00 % iIii1I11I1II1
  return ( True )
  if 62 - 62: OoooooooOO * o0oOOo0O0Ooo
  if 59 - 59: iIii1I11I1II1
  if 18 - 18: ooOoO0o % I1IiiI / iIii1I11I1II1 + O0
  if 99 - 99: i11iIiiIii - o0oOOo0O0Ooo + o0oOOo0O0Ooo . OoooooooOO * iII111i . Oo0Ooo
  if 63 - 63: I11i
  if 60 - 60: I1IiiI / I1ii11iIi11i / I11i / Ii1I + iIii1I11I1II1
class lisp_stats ( ) :
 def __init__ ( self ) :
  self . packet_count = 0
  self . byte_count = 0
  self . last_rate_check = 0
  self . last_packet_count = 0
  self . last_byte_count = 0
  self . last_increment = None
  if 85 - 85: O0 / OOooOOo . OoOoOO00 / I1ii11iIi11i
  if 80 - 80: I1ii11iIi11i * iII111i % i1IIi * OOooOOo % II111iiii % i1IIi
 def increment ( self , octets ) :
  self . packet_count += 1
  self . byte_count += octets
  self . last_increment = lisp_get_timestamp ( )
  if 44 - 44: OoooooooOO
  if 18 - 18: i11iIiiIii
 def recent_packet_sec ( self ) :
  if ( self . last_increment == None ) : return ( False )
  oO000o = time . time ( ) - self . last_increment
  return ( oO000o <= 1 )
  if 65 - 65: i1IIi . iIii1I11I1II1 % iIii1I11I1II1
  if 35 - 35: iIii1I11I1II1 - o0oOOo0O0Ooo + I1ii11iIi11i * iII111i - OOooOOo . o0oOOo0O0Ooo
 def recent_packet_min ( self ) :
  if ( self . last_increment == None ) : return ( False )
  oO000o = time . time ( ) - self . last_increment
  return ( oO000o <= 60 )
  if 12 - 12: iIii1I11I1II1 % OoO0O00 * Oo0Ooo
  if 5 - 5: I11i - II111iiii * iIii1I11I1II1 / iIii1I11I1II1 % IiII * i1IIi
 def stat_colors ( self , c1 , c2 , html ) :
  if ( self . recent_packet_sec ( ) ) :
   return ( green_last_sec ( c1 ) , green_last_sec ( c2 ) )
   if 30 - 30: i1IIi % I1IiiI . OOooOOo % iIii1I11I1II1 . I1ii11iIi11i / o0oOOo0O0Ooo
  if ( self . recent_packet_min ( ) ) :
   return ( green_last_min ( c1 ) , green_last_min ( c2 ) )
   if 53 - 53: OOooOOo % ooOoO0o
  return ( c1 , c2 )
  if 94 - 94: OOooOOo - O0 - I1Ii111 / OoooooooOO - iII111i
  if 83 - 83: OOooOOo * I1ii11iIi11i * iII111i * I1ii11iIi11i . OoO0O00
 def normalize ( self , count ) :
  count = str ( count )
  o0o0oOo00Oo = len ( count )
  if ( o0o0oOo00Oo > 12 ) :
   count = count [ 0 : - 10 ] + "." + count [ - 10 : - 7 ] + "T"
   return ( count )
   if 94 - 94: ooOoO0o / Ii1I
  if ( o0o0oOo00Oo > 9 ) :
   count = count [ 0 : - 9 ] + "." + count [ - 9 : - 7 ] + "B"
   return ( count )
   if 9 - 9: I1Ii111 * oO0o
  if ( o0o0oOo00Oo > 6 ) :
   count = count [ 0 : - 6 ] + "." + count [ - 6 ] + "M"
   return ( count )
   if 44 - 44: ooOoO0o * oO0o
  return ( count )
  if 67 - 67: iIii1I11I1II1 . iIii1I11I1II1 + iIii1I11I1II1 * iII111i
  if 70 - 70: I1IiiI - I11i / iIii1I11I1II1 . I1IiiI % I1ii11iIi11i
 def get_stats ( self , summary , html ) :
  iIiiiii11Iiii1iiiii = self . last_rate_check
  i1iIIIiIII1iI = self . last_packet_count
  iI1i = self . last_byte_count
  self . last_rate_check = lisp_get_timestamp ( )
  self . last_packet_count = self . packet_count
  self . last_byte_count = self . byte_count
  if 65 - 65: I11i + o0oOOo0O0Ooo
  oOoo0ooOOOO0o = self . last_rate_check - iIiiiii11Iiii1iiiii
  if ( oOoo0ooOOOO0o == 0 ) :
   OO0I11ii = 0
   iIIIiiIiIII = 0
  else :
   OO0I11ii = int ( ( self . packet_count - i1iIIIiIII1iI ) / oOoo0ooOOOO0o )
   iIIIiiIiIII = ( self . byte_count - iI1i ) / oOoo0ooOOOO0o
   iIIIiiIiIII = ( iIIIiiIiIII * 8 ) / 1000000
   iIIIiiIiIII = round ( iIIIiiIiIII , 2 )
   if 10 - 10: oO0o * i11iIiiIii % i1IIi + I1ii11iIi11i + Oo0Ooo
   if 36 - 36: O0 - iII111i + I11i + I1IiiI
   if 89 - 89: OoOoOO00 / Ii1I - OoO0O00 % I11i - oO0o . Ii1I
   if 75 - 75: I11i * OoooooooOO % OoOoOO00 . i1IIi - Ii1I + iIii1I11I1II1
   if 74 - 74: ooOoO0o
  iiI1Ii1I = self . normalize ( self . packet_count )
  ii1oO00o = self . normalize ( self . byte_count )
  if 26 - 26: ooOoO0o . IiII - O0 / I1IiiI
  if 30 - 30: ooOoO0o / ooOoO0o - Oo0Ooo
  if 60 - 60: I1ii11iIi11i
  if 91 - 91: iII111i
  if 99 - 99: OOooOOo / i11iIiiIii - oO0o / I1IiiI
  if ( summary ) :
   oO0Oo0O000 = "<br>" if html else ""
   iiI1Ii1I , ii1oO00o = self . stat_colors ( iiI1Ii1I , ii1oO00o , html )
   O0OO0O00Oo0 = "packet-count: {}{}byte-count: {}" . format ( iiI1Ii1I , oO0Oo0O000 , ii1oO00o )
   O0oo0Oo0Oo00o = "packet-rate: {} pps\nbit-rate: {} Mbps" . format ( OO0I11ii , iIIIiiIiIII )
   if 25 - 25: OoOoOO00 % i11iIiiIii - I1IiiI * iIii1I11I1II1 - Oo0Ooo . O0
   if ( html != "" ) : O0oo0Oo0Oo00o = lisp_span ( O0OO0O00Oo0 , O0oo0Oo0Oo00o )
  else :
   Ii1I1ii = str ( OO0I11ii )
   i1I = str ( iIIIiiIiIII )
   if ( html ) :
    iiI1Ii1I = lisp_print_cour ( iiI1Ii1I )
    Ii1I1ii = lisp_print_cour ( Ii1I1ii )
    ii1oO00o = lisp_print_cour ( ii1oO00o )
    i1I = lisp_print_cour ( i1I )
    if 21 - 21: Oo0Ooo - i11iIiiIii * oO0o + IiII + o0oOOo0O0Ooo + iII111i
   oO0Oo0O000 = "<br>" if html else ", "
   if 21 - 21: OoooooooOO + II111iiii - OoOoOO00 . i11iIiiIii * OOooOOo
   O0oo0Oo0Oo00o = ( "packet-count: {}{}packet-rate: {} pps{}byte-count: " + "{}{}bit-rate: {} mbps" ) . format ( iiI1Ii1I , oO0Oo0O000 , Ii1I1ii , oO0Oo0O000 , ii1oO00o , oO0Oo0O000 ,
   # iIii1I11I1II1 * Ii1I / oO0o . OoooooooOO . OOooOOo * i11iIiiIii
 i1I )
   if 84 - 84: I11i + OoOoOO00 . Ii1I - Oo0Ooo % Ii1I / I1IiiI
  return ( O0oo0Oo0Oo00o )
  if 30 - 30: OoO0O00 / I1Ii111 * OoOoOO00 - OoooooooOO
  if 11 - 11: I1Ii111 - Oo0Ooo / iIii1I11I1II1 - OoooooooOO
  if 71 - 71: Oo0Ooo + Ii1I - OoooooooOO + I11i - iIii1I11I1II1 / O0
  if 76 - 76: i11iIiiIii % o0oOOo0O0Ooo . O0 * I11i
  if 90 - 90: II111iiii + OOooOOo % I1Ii111 * iIii1I11I1II1 % iIii1I11I1II1
  if 55 - 55: II111iiii % O0 * O0 - II111iiii * I1IiiI % Oo0Ooo
  if 48 - 48: I1ii11iIi11i + OoooooooOO % i1IIi
  if 46 - 46: OoOoOO00
lisp_decap_stats = {
 "good-packets" : lisp_stats ( ) , "ICV-error" : lisp_stats ( ) ,
 "checksum-error" : lisp_stats ( ) , "lisp-header-error" : lisp_stats ( ) ,
 "no-decrypt-key" : lisp_stats ( ) , "bad-inner-version" : lisp_stats ( ) ,
 "outer-header-error" : lisp_stats ( )
 }
if 75 - 75: I1IiiI
if 37 - 37: iIii1I11I1II1 % OoO0O00 * ooOoO0o + I11i % ooOoO0o / i11iIiiIii
if 14 - 14: i1IIi / ooOoO0o
if 10 - 10: ooOoO0o / OoooooooOO - ooOoO0o % O0 + oO0o - oO0o
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
  if 16 - 16: O0
  if ( recurse == False ) : return
  if 14 - 14: Ii1I . Ii1I . OOooOOo - O0 / OoO0O00 % II111iiii
  if 5 - 5: iIii1I11I1II1 % OoOoOO00 % OOooOOo % O0 * oO0o . iIii1I11I1II1
  if 96 - 96: i11iIiiIii + oO0o / I1ii11iIi11i . IiII % o0oOOo0O0Ooo
  if 41 - 41: o0oOOo0O0Ooo . i1IIi - OOooOOo
  if 19 - 19: o0oOOo0O0Ooo % I1Ii111 % I11i
  if 1 - 1: I1IiiI / o0oOOo0O0Ooo - I1Ii111
  I1II1iiII = lisp_get_default_route_next_hops ( )
  if ( I1II1iiII == [ ] or len ( I1II1iiII ) == 1 ) : return
  if 17 - 17: i1IIi / IiII . I1IiiI % i1IIi
  self . rloc_next_hop = I1II1iiII [ 0 ]
  o0Oo00o0 = self
  for I1iiiI1I1i in I1II1iiII [ 1 : : ] :
   iiiIiI11I = lisp_rloc ( False )
   iiiIiI11I = copy . deepcopy ( self )
   iiiIiI11I . rloc_next_hop = I1iiiI1I1i
   o0Oo00o0 . next_rloc = iiiIiI11I
   o0Oo00o0 = iiiIiI11I
   if 53 - 53: oO0o + I1IiiI * O0 * iIii1I11I1II1 / Oo0Ooo
   if 15 - 15: iIii1I11I1II1 . OoOoOO00 % Ii1I / i1IIi . o0oOOo0O0Ooo
   if 45 - 45: iIii1I11I1II1 - i1IIi % I1IiiI - I1Ii111 + oO0o
 def up_state ( self ) :
  return ( self . state == LISP_RLOC_UP_STATE )
  if 15 - 15: iIii1I11I1II1 - OoooooooOO / ooOoO0o
  if 83 - 83: IiII + I1Ii111 / OoOoOO00 * IiII . oO0o
 def unreach_state ( self ) :
  return ( self . state == LISP_RLOC_UNREACH_STATE )
  if 22 - 22: O0 + ooOoO0o + I1Ii111
  if 57 - 57: OOooOOo . ooOoO0o - OoooooooOO - I1ii11iIi11i * O0
 def no_echoed_nonce_state ( self ) :
  return ( self . state == LISP_RLOC_NO_ECHOED_NONCE_STATE )
  if 85 - 85: I1IiiI * OoO0O00
  if 63 - 63: I1IiiI - i11iIiiIii
 def down_state ( self ) :
  return ( self . state in [ LISP_RLOC_DOWN_STATE , LISP_RLOC_ADMIN_DOWN_STATE ] )
  if 4 - 4: OOooOOo + iIii1I11I1II1 / I1IiiI * Ii1I
  if 64 - 64: OoOoOO00
  if 94 - 94: OOooOOo * OoooooooOO * o0oOOo0O0Ooo / I1Ii111 . II111iiii
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
  if 37 - 37: O0 * II111iiii * I1IiiI - O0 - I11i / i1IIi
  if 27 - 27: i11iIiiIii + iIii1I11I1II1
 def print_rloc ( self , indent ) :
  iII1i1 = lisp_print_elapsed ( self . uptime )
  lprint ( "{}rloc {}, uptime {}, {}, parms {}/{}/{}/{}" . format ( indent ,
 red ( self . rloc . print_address ( ) , False ) , iII1i1 , self . print_state ( ) ,
 self . priority , self . weight , self . mpriority , self . mweight ) )
  if 15 - 15: oO0o
  if 69 - 69: II111iiii * O0 . ooOoO0o * IiII
 def print_rloc_name ( self , cour = False ) :
  if ( self . rloc_name == None ) : return ( "" )
  iI1Iii11Iii11 = self . rloc_name
  if ( cour ) : iI1Iii11Iii11 = lisp_print_cour ( iI1Iii11Iii11 )
  return ( 'rloc-name: {}' . format ( blue ( iI1Iii11Iii11 , cour ) ) )
  if 25 - 25: I11i - I1ii11iIi11i . I1Ii111 . OoooooooOO
  if 4 - 4: IiII * OoO0O00 % I1ii11iIi11i * Ii1I . iII111i
 def store_rloc_from_record ( self , rloc_record , nonce , source ) :
  OoO0o = LISP_DATA_PORT
  self . rloc . copy_address ( rloc_record . rloc )
  self . rloc_name = rloc_record . rloc_name
  if 41 - 41: OoooooooOO % I11i . O0 + I1Ii111
  if 67 - 67: OoOoOO00 * OOooOOo / OOooOOo / OoooooooOO
  if 67 - 67: I11i - i1IIi . OoooooooOO / iIii1I11I1II1
  if 34 - 34: OoO0O00 * II111iiii
  i11iII1Ii1ii111 = self . rloc
  if ( i11iII1Ii1ii111 . is_null ( ) == False ) :
   iIiiiIi = lisp_get_nat_info ( i11iII1Ii1ii111 , self . rloc_name )
   if ( iIiiiIi ) :
    OoO0o = iIiiiIi . port
    Ii11i1Iiii11 = lisp_nat_state_info [ self . rloc_name ] [ 0 ]
    oO00o = i11iII1Ii1ii111 . print_address_no_iid ( )
    ii1 = red ( oO00o , False )
    OOo0oo0O0o0 = "" if self . rloc_name == None else blue ( self . rloc_name , False )
    if 82 - 82: OoooooooOO . o0oOOo0O0Ooo * I1ii11iIi11i % I1ii11iIi11i * Ii1I
    if 83 - 83: I11i - Oo0Ooo + i11iIiiIii - i11iIiiIii
    if 64 - 64: IiII % I1IiiI / ooOoO0o
    if 74 - 74: OoooooooOO
    if 22 - 22: II111iiii . O0 * I1Ii111 % OoO0O00 / OoooooooOO + I1Ii111
    if 71 - 71: ooOoO0o . oO0o * OoooooooOO + iII111i - I1Ii111 . I1ii11iIi11i
    if ( iIiiiIi . timed_out ( ) ) :
     lprint ( ( "    Matched stored NAT state timed out for " + "RLOC {}:{}, {}" ) . format ( ii1 , OoO0o , OOo0oo0O0o0 ) )
     if 100 - 100: I11i + O0 - o0oOOo0O0Ooo * I1ii11iIi11i
     if 94 - 94: Oo0Ooo . IiII / Ii1I / oO0o - I1IiiI
     iIiiiIi = None if ( iIiiiIi == Ii11i1Iiii11 ) else Ii11i1Iiii11
     if ( iIiiiIi and iIiiiIi . timed_out ( ) ) :
      OoO0o = iIiiiIi . port
      ii1 = red ( iIiiiIi . address , False )
      lprint ( ( "    Youngest stored NAT state timed out " + " for RLOC {}:{}, {}" ) . format ( ii1 , OoO0o ,
      # iIii1I11I1II1 + o0oOOo0O0Ooo . Ii1I % iII111i + Ii1I
 OOo0oo0O0o0 ) )
      iIiiiIi = None
      if 85 - 85: OOooOOo
      if 41 - 41: I1ii11iIi11i . OoooooooOO * I1ii11iIi11i - oO0o
      if 40 - 40: I1IiiI % OoO0O00 + i11iIiiIii / oO0o
      if 98 - 98: oO0o + iIii1I11I1II1 . ooOoO0o / I1ii11iIi11i
      if 77 - 77: OoOoOO00 / Oo0Ooo * OoOoOO00 % I1IiiI . II111iiii % OoO0O00
      if 38 - 38: iII111i - OoO0O00 / i1IIi + ooOoO0o . ooOoO0o . iII111i
      if 37 - 37: iIii1I11I1II1 * OoOoOO00 . OoOoOO00 + OoooooooOO + OoO0O00
    if ( iIiiiIi ) :
     if ( iIiiiIi . address != oO00o ) :
      lprint ( "RLOC conflict, RLOC-record {}, NAT state {}" . format ( ii1 , red ( iIiiiIi . address , False ) ) )
      if 25 - 25: I1IiiI / IiII . OOooOOo . I1ii11iIi11i % i1IIi
      self . rloc . store_address ( iIiiiIi . address )
      if 12 - 12: O0 % O0
     ii1 = red ( iIiiiIi . address , False )
     OoO0o = iIiiiIi . port
     lprint ( "    Use NAT translated RLOC {}:{} for {}" . format ( ii1 , OoO0o , OOo0oo0O0o0 ) )
     if 9 - 9: O0 . I1IiiI + I1ii11iIi11i / OOooOOo * I1ii11iIi11i
     self . store_translated_rloc ( i11iII1Ii1ii111 , OoO0o )
     if 10 - 10: IiII % o0oOOo0O0Ooo / O0 / II111iiii
     if 81 - 81: Ii1I / o0oOOo0O0Ooo % OoOoOO00 . I1ii11iIi11i
     if 47 - 47: II111iiii + OOooOOo / II111iiii . OOooOOo
     if 68 - 68: OoooooooOO
  self . geo = rloc_record . geo
  self . elp = rloc_record . elp
  self . json = rloc_record . json
  if 63 - 63: I1IiiI
  if 80 - 80: oO0o + iIii1I11I1II1
  if 87 - 87: I1ii11iIi11i % Ii1I . Ii1I
  if 71 - 71: OoO0O00 - IiII . i1IIi * I1IiiI % I11i
  self . rle = rloc_record . rle
  if ( self . rle ) :
   for OO in self . rle . rle_nodes :
    iI1Iii11Iii11 = OO . rloc_name
    iIiiiIi = lisp_get_nat_info ( OO . address , iI1Iii11Iii11 )
    if ( iIiiiIi == None ) : continue
    if 36 - 36: IiII * OoooooooOO . i11iIiiIii * i1IIi
    OoO0o = iIiiiIi . port
    IIi1IiiI1i1 = iI1Iii11Iii11
    if ( IIi1IiiI1i1 ) : IIi1IiiI1i1 = blue ( iI1Iii11Iii11 , False )
    if 52 - 52: IiII + ooOoO0o - II111iiii - OoooooooOO * OoO0O00 - iIii1I11I1II1
    lprint ( ( "      Store translated encap-port {} for RLE-" + "node {}, rloc-name '{}'" ) . format ( OoO0o ,
    # I11i * IiII / iIii1I11I1II1
 OO . address . print_address_no_iid ( ) , IIi1IiiI1i1 ) )
    OO . translated_port = OoO0o
    if 88 - 88: OoOoOO00 % II111iiii . I1IiiI / oO0o * IiII / i11iIiiIii
    if 76 - 76: o0oOOo0O0Ooo
    if 80 - 80: OOooOOo
  self . priority = rloc_record . priority
  self . mpriority = rloc_record . mpriority
  self . weight = rloc_record . weight
  self . mweight = rloc_record . mweight
  if ( rloc_record . reach_bit and rloc_record . local_bit and
 rloc_record . probe_bit == False ) : self . state = LISP_RLOC_UP_STATE
  if 15 - 15: OOooOOo . OoOoOO00 / oO0o . I1ii11iIi11i % OoO0O00 - oO0o
  if 21 - 21: ooOoO0o . o0oOOo0O0Ooo . oO0o . i1IIi
  if 96 - 96: Ii1I % I11i * OoooooooOO . I1IiiI . iIii1I11I1II1
  if 8 - 8: O0 + o0oOOo0O0Ooo / O0 - I1ii11iIi11i % I1ii11iIi11i
  Oo0oo0o00oOOo = source . is_exact_match ( rloc_record . rloc ) if source != None else None
  if 71 - 71: iIii1I11I1II1 + iIii1I11I1II1 * OoO0O00 - I1IiiI % I1Ii111
  if ( rloc_record . keys != None and Oo0oo0o00oOOo ) :
   i1i11ii1 = rloc_record . keys [ 1 ]
   if ( i1i11ii1 != None ) :
    oO00o = rloc_record . rloc . print_address_no_iid ( ) + ":" + str ( OoO0o )
    if 86 - 86: II111iiii
    i1i11ii1 . add_key_by_rloc ( oO00o , True )
    lprint ( "    Store encap-keys for nonce 0x{}, RLOC {}" . format ( lisp_hex_string ( nonce ) , red ( oO00o , False ) ) )
    if 67 - 67: iIii1I11I1II1 / I11i + ooOoO0o * I1Ii111 * oO0o
    if 100 - 100: OoooooooOO % I1IiiI / OoOoOO00 % OoOoOO00 . o0oOOo0O0Ooo
    if 81 - 81: Ii1I - II111iiii + I11i / Ii1I
  return ( OoO0o )
  if 89 - 89: i11iIiiIii + I1ii11iIi11i - ooOoO0o . ooOoO0o + Oo0Ooo % Ii1I
  if 96 - 96: I1Ii111 - I11i * I1Ii111
 def store_translated_rloc ( self , rloc , port ) :
  self . rloc . copy_address ( rloc )
  self . translated_rloc . copy_address ( rloc )
  self . translated_port = port
  if 32 - 32: I1IiiI / i1IIi / I1ii11iIi11i % i1IIi . ooOoO0o % I1ii11iIi11i
  if 97 - 97: OoO0O00 . OOooOOo % Ii1I + OoooooooOO * I1Ii111
 def is_rloc_translated ( self ) :
  return ( self . translated_rloc . is_null ( ) == False )
  if 89 - 89: I11i
  if 91 - 91: OoooooooOO - IiII - Ii1I
 def rloc_exists ( self ) :
  if ( self . rloc . is_null ( ) == False ) : return ( True )
  if ( self . rle_name or self . geo_name or self . elp_name or self . json_name ) :
   return ( False )
   if 36 - 36: OOooOOo
  return ( True )
  if 76 - 76: OoO0O00 . i1IIi
  if 98 - 98: O0
 def is_rtr ( self ) :
  return ( ( self . priority == 254 and self . mpriority == 255 and self . weight == 0 and self . mweight == 0 ) )
  if 86 - 86: O0 * oO0o + Oo0Ooo / II111iiii + i1IIi
  if 12 - 12: I1IiiI + OOooOOo / Ii1I % i11iIiiIii - I1Ii111 % I11i
  if 49 - 49: I11i * i1IIi - iII111i
 def print_state_change ( self , new_state ) :
  Oo000ooo = self . print_state ( )
  oOO00OO0OooOo = "{} -> {}" . format ( Oo000ooo , new_state )
  if ( new_state == "up" and self . unreach_state ( ) ) :
   oOO00OO0OooOo = bold ( oOO00OO0OooOo , False )
   if 90 - 90: Ii1I * Ii1I % i11iIiiIii
  return ( oOO00OO0OooOo )
  if 81 - 81: Ii1I / I1Ii111 / OoooooooOO * Oo0Ooo
  if 21 - 21: I11i / I1Ii111 . Ii1I - Ii1I . I1ii11iIi11i
 def print_rloc_probe_rtt ( self ) :
  if ( self . rloc_probe_rtt == - 1 ) : return ( "none" )
  return ( self . rloc_probe_rtt )
  if 52 - 52: o0oOOo0O0Ooo * o0oOOo0O0Ooo % I1ii11iIi11i % OoOoOO00 * OoooooooOO . I1ii11iIi11i
  if 88 - 88: I1ii11iIi11i . i1IIi * iII111i
 def print_recent_rloc_probe_rtts ( self ) :
  O0oooo = str ( self . recent_rloc_probe_rtts )
  O0oooo = O0oooo . replace ( "-1" , "?" )
  return ( O0oooo )
  if 43 - 43: OoooooooOO + i1IIi . O0
  if 39 - 39: I1ii11iIi11i
 def compute_rloc_probe_rtt ( self ) :
  o0Oo00o0 = self . rloc_probe_rtt
  self . rloc_probe_rtt = - 1
  if ( self . last_rloc_probe_reply == None ) : return
  if ( self . last_rloc_probe == None ) : return
  self . rloc_probe_rtt = self . last_rloc_probe_reply - self . last_rloc_probe
  self . rloc_probe_rtt = round ( self . rloc_probe_rtt , 3 )
  iIO00oooOooo = self . recent_rloc_probe_rtts
  self . recent_rloc_probe_rtts = [ o0Oo00o0 ] + iIO00oooOooo [ 0 : - 1 ]
  if 17 - 17: I1IiiI / i11iIiiIii + o0oOOo0O0Ooo . OoOoOO00 . I1IiiI
  if 31 - 31: OoooooooOO . I1Ii111 % OoooooooOO * iII111i % OOooOOo . iII111i
 def print_rloc_probe_hops ( self ) :
  return ( self . rloc_probe_hops )
  if 17 - 17: I1Ii111 % i1IIi % I11i * O0 / Oo0Ooo
  if 96 - 96: OoOoOO00 . Ii1I
 def print_recent_rloc_probe_hops ( self ) :
  oOOOooo = str ( self . recent_rloc_probe_hops )
  return ( oOOOooo )
  if 93 - 93: I1IiiI * II111iiii * O0 % o0oOOo0O0Ooo + oO0o / ooOoO0o
  if 79 - 79: OoO0O00 + ooOoO0o / oO0o % I1ii11iIi11i
 def store_rloc_probe_hops ( self , to_hops , from_ttl ) :
  if ( to_hops == 0 ) :
   to_hops = "?"
  elif ( to_hops < LISP_RLOC_PROBE_TTL / 2 ) :
   to_hops = "!"
  else :
   to_hops = str ( LISP_RLOC_PROBE_TTL - to_hops )
   if 77 - 77: Ii1I / Ii1I / I1ii11iIi11i
  if ( from_ttl < LISP_RLOC_PROBE_TTL / 2 ) :
   Oooo0Oo00O00 = "!"
  else :
   Oooo0Oo00O00 = str ( LISP_RLOC_PROBE_TTL - from_ttl )
   if 21 - 21: o0oOOo0O0Ooo . i11iIiiIii % OoooooooOO * O0
   if 52 - 52: OOooOOo / ooOoO0o . II111iiii / Oo0Ooo
  o0Oo00o0 = self . rloc_probe_hops
  self . rloc_probe_hops = to_hops + "/" + Oooo0Oo00O00
  iIO00oooOooo = self . recent_rloc_probe_hops
  self . recent_rloc_probe_hops = [ o0Oo00o0 ] + iIO00oooOooo [ 0 : - 1 ]
  if 66 - 66: Ii1I * I1Ii111 * OoO0O00
  if 92 - 92: II111iiii * iII111i % OoOoOO00 % OoOoOO00 % i11iIiiIii
 def process_rloc_probe_reply ( self , nonce , eid , group , hop_count , ttl ) :
  i11iII1Ii1ii111 = self
  while ( True ) :
   if ( i11iII1Ii1ii111 . last_rloc_probe_nonce == nonce ) : break
   i11iII1Ii1ii111 = i11iII1Ii1ii111 . next_rloc
   if ( i11iII1Ii1ii111 == None ) :
    lprint ( "    No matching nonce state found for nonce 0x{}" . format ( lisp_hex_string ( nonce ) ) )
    if 93 - 93: Ii1I + iIii1I11I1II1 % Ii1I . iIii1I11I1II1
    return
    if 48 - 48: OoooooooOO - O0 + I1IiiI - I11i
    if 86 - 86: i11iIiiIii / IiII + i11iIiiIii + o0oOOo0O0Ooo . I1Ii111 . I1Ii111
    if 90 - 90: ooOoO0o % Ii1I
  i11iII1Ii1ii111 . last_rloc_probe_reply = lisp_get_timestamp ( )
  i11iII1Ii1ii111 . compute_rloc_probe_rtt ( )
  iio00OoO000o = i11iII1Ii1ii111 . print_state_change ( "up" )
  if ( i11iII1Ii1ii111 . state != LISP_RLOC_UP_STATE ) :
   lisp_update_rtr_updown ( i11iII1Ii1ii111 . rloc , True )
   i11iII1Ii1ii111 . state = LISP_RLOC_UP_STATE
   i11iII1Ii1ii111 . last_state_change = lisp_get_timestamp ( )
   O0O = lisp_map_cache . lookup_cache ( eid , True )
   if ( O0O ) : lisp_write_ipc_map_cache ( True , O0O )
   if 49 - 49: IiII - o0oOOo0O0Ooo
   if 3 - 3: Oo0Ooo * O0 % OoooooooOO / O0 - Ii1I . iIii1I11I1II1
  i11iII1Ii1ii111 . store_rloc_probe_hops ( hop_count , ttl )
  if 30 - 30: OoO0O00 + OOooOOo * i11iIiiIii - OoOoOO00 * II111iiii - oO0o
  I1iI1iiii = bold ( "RLOC-probe reply" , False )
  oO00o = i11iII1Ii1ii111 . rloc . print_address_no_iid ( )
  IiI1I1 = bold ( str ( i11iII1Ii1ii111 . print_rloc_probe_rtt ( ) ) , False )
  Iiiii1III1iIi = ":{}" . format ( self . translated_port ) if self . translated_port != 0 else ""
  if 54 - 54: I11i - I11i
  I1iiiI1I1i = ""
  if ( i11iII1Ii1ii111 . rloc_next_hop != None ) :
   I1 , IiiiIi1iIIiIi = i11iII1Ii1ii111 . rloc_next_hop
   I1iiiI1I1i = ", nh {}({})" . format ( IiiiIi1iIIiIi , I1 )
   if 57 - 57: I1Ii111
   if 54 - 54: iII111i + i1IIi - I1Ii111 / iII111i . Oo0Ooo
  Oo00OOo00O = green ( lisp_print_eid_tuple ( eid , group ) , False )
  lprint ( ( "    Received {} from {}{} for {}, {}, rtt {}{}, " + "to-ttl/from-ttl {}" ) . format ( I1iI1iiii , red ( oO00o , False ) , Iiiii1III1iIi , Oo00OOo00O ,
  # iII111i + oO0o
 iio00OoO000o , IiI1I1 , I1iiiI1I1i , str ( hop_count ) + "/" + str ( ttl ) ) )
  if 48 - 48: ooOoO0o
  if ( i11iII1Ii1ii111 . rloc_next_hop == None ) : return
  if 34 - 34: I1IiiI - OoooooooOO . IiII - OOooOOo % IiII
  if 19 - 19: IiII + I1ii11iIi11i % Oo0Ooo
  if 32 - 32: OOooOOo
  if 46 - 46: II111iiii . OoO0O00
  i11iII1Ii1ii111 = None
  oOOooO0OO = None
  while ( True ) :
   i11iII1Ii1ii111 = self if i11iII1Ii1ii111 == None else i11iII1Ii1ii111 . next_rloc
   if ( i11iII1Ii1ii111 == None ) : break
   if ( i11iII1Ii1ii111 . up_state ( ) == False ) : continue
   if ( i11iII1Ii1ii111 . rloc_probe_rtt == - 1 ) : continue
   if 41 - 41: oO0o % II111iiii
   if ( oOOooO0OO == None ) : oOOooO0OO = i11iII1Ii1ii111
   if ( i11iII1Ii1ii111 . rloc_probe_rtt < oOOooO0OO . rloc_probe_rtt ) : oOOooO0OO = i11iII1Ii1ii111
   if 61 - 61: i11iIiiIii * I11i / ooOoO0o / iIii1I11I1II1
   if 40 - 40: O0 / Ii1I - i11iIiiIii / I11i
  if ( oOOooO0OO != None ) :
   I1 , IiiiIi1iIIiIi = oOOooO0OO . rloc_next_hop
   I1iiiI1I1i = bold ( "nh {}({})" . format ( IiiiIi1iIIiIi , I1 ) , False )
   lprint ( "    Install host-route via best {}" . format ( I1iiiI1I1i ) )
   lisp_install_host_route ( oO00o , None , False )
   lisp_install_host_route ( oO00o , IiiiIi1iIIiIi , True )
   if 60 - 60: Oo0Ooo - iII111i . II111iiii % ooOoO0o / OoooooooOO / iIii1I11I1II1
   if 23 - 23: I11i + iIii1I11I1II1
   if 60 - 60: O0 * I1IiiI + o0oOOo0O0Ooo * OoO0O00 + o0oOOo0O0Ooo / i11iIiiIii
 def add_to_rloc_probe_list ( self , eid , group ) :
  oO00o = self . rloc . print_address_no_iid ( )
  OoO0o = self . translated_port
  if ( OoO0o != 0 ) : oO00o += ":" + str ( OoO0o )
  if 54 - 54: i11iIiiIii . iII111i * i1IIi
  if ( lisp_rloc_probe_list . has_key ( oO00o ) == False ) :
   lisp_rloc_probe_list [ oO00o ] = [ ]
   if 68 - 68: Oo0Ooo
   if 20 - 20: IiII + i11iIiiIii * OOooOOo
  if ( group . is_null ( ) ) : group . instance_id = 0
  for O0ooOoO0OO000 , Oo00OOo00O , II1I in lisp_rloc_probe_list [ oO00o ] :
   if ( Oo00OOo00O . is_exact_match ( eid ) and II1I . is_exact_match ( group ) ) :
    if ( O0ooOoO0OO000 == self ) :
     if ( lisp_rloc_probe_list [ oO00o ] == [ ] ) :
      lisp_rloc_probe_list . pop ( oO00o )
      if 27 - 27: O0 * OoO0O00 * I1ii11iIi11i
     return
     if 40 - 40: O0 + oO0o - ooOoO0o + I1IiiI - IiII
    lisp_rloc_probe_list [ oO00o ] . remove ( [ O0ooOoO0OO000 , Oo00OOo00O , II1I ] )
    break
    if 60 - 60: I1Ii111 * OoO0O00 * oO0o + oO0o
    if 34 - 34: o0oOOo0O0Ooo
  lisp_rloc_probe_list [ oO00o ] . append ( [ self , eid , group ] )
  if 76 - 76: oO0o + OoooooooOO % OoOoOO00 / OoOoOO00
  if 51 - 51: II111iiii / OoOoOO00
  if 69 - 69: i11iIiiIii
  if 77 - 77: I1ii11iIi11i % OoooooooOO - Oo0Ooo - Ii1I + I11i
  if 93 - 93: I1IiiI % O0 * OoO0O00 % OoOoOO00 . I1Ii111 * I1IiiI
  i11iII1Ii1ii111 = lisp_rloc_probe_list [ oO00o ] [ 0 ] [ 0 ]
  if ( i11iII1Ii1ii111 . state == LISP_RLOC_UNREACH_STATE ) :
   self . state = LISP_RLOC_UNREACH_STATE
   self . last_state_change = lisp_get_timestamp ( )
   if 95 - 95: IiII + o0oOOo0O0Ooo - o0oOOo0O0Ooo
   if 83 - 83: ooOoO0o
   if 59 - 59: I1ii11iIi11i
 def delete_from_rloc_probe_list ( self , eid , group ) :
  oO00o = self . rloc . print_address_no_iid ( )
  OoO0o = self . translated_port
  if ( OoO0o != 0 ) : oO00o += ":" + str ( OoO0o )
  if ( lisp_rloc_probe_list . has_key ( oO00o ) == False ) : return
  if 26 - 26: I11i . Ii1I
  O0i1iI1IIi1ii = [ ]
  for Ooo000O00 in lisp_rloc_probe_list [ oO00o ] :
   if ( Ooo000O00 [ 0 ] != self ) : continue
   if ( Ooo000O00 [ 1 ] . is_exact_match ( eid ) == False ) : continue
   if ( Ooo000O00 [ 2 ] . is_exact_match ( group ) == False ) : continue
   O0i1iI1IIi1ii = Ooo000O00
   break
   if 59 - 59: II111iiii + I1ii11iIi11i / iII111i . ooOoO0o
  if ( O0i1iI1IIi1ii == [ ] ) : return
  if 18 - 18: I1Ii111
  try :
   lisp_rloc_probe_list [ oO00o ] . remove ( O0i1iI1IIi1ii )
   if ( lisp_rloc_probe_list [ oO00o ] == [ ] ) :
    lisp_rloc_probe_list . pop ( oO00o )
    if 40 - 40: OoOoOO00 / OOooOOo + O0
  except :
   return
   if 57 - 57: iII111i
   if 94 - 94: i11iIiiIii
   if 90 - 90: iII111i + i11iIiiIii + iII111i % I1IiiI % oO0o
 def print_rloc_probe_state ( self , trailing_linefeed ) :
  Ii1I11I = ""
  i11iII1Ii1ii111 = self
  while ( True ) :
   O0000O = i11iII1Ii1ii111 . last_rloc_probe
   if ( O0000O == None ) : O0000O = 0
   I1iiii1i1II = i11iII1Ii1ii111 . last_rloc_probe_reply
   if ( I1iiii1i1II == None ) : I1iiii1i1II = 0
   IiI1I1 = i11iII1Ii1ii111 . print_rloc_probe_rtt ( )
   I11iiIi1i1 = space ( 4 )
   if 99 - 99: OoOoOO00 . OoOoOO00 * Oo0Ooo + OoooooooOO . Ii1I . OoooooooOO
   if ( i11iII1Ii1ii111 . rloc_next_hop == None ) :
    Ii1I11I += "RLOC-Probing:\n"
   else :
    I1 , IiiiIi1iIIiIi = i11iII1Ii1ii111 . rloc_next_hop
    Ii1I11I += "RLOC-Probing for nh {}({}):\n" . format ( IiiiIi1iIIiIi , I1 )
    if 54 - 54: OOooOOo
    if 77 - 77: iIii1I11I1II1 % I1Ii111 + II111iiii
   Ii1I11I += ( "{}RLOC-probe request sent: {}\n{}RLOC-probe reply " + "received: {}, rtt {}" ) . format ( I11iiIi1i1 , lisp_print_elapsed ( O0000O ) ,
   # II111iiii - Oo0Ooo - I1ii11iIi11i
 I11iiIi1i1 , lisp_print_elapsed ( I1iiii1i1II ) , IiI1I1 )
   if 49 - 49: Ii1I + I1Ii111
   if ( trailing_linefeed ) : Ii1I11I += "\n"
   if 10 - 10: i1IIi
   i11iII1Ii1ii111 = i11iII1Ii1ii111 . next_rloc
   if ( i11iII1Ii1ii111 == None ) : break
   Ii1I11I += "\n"
   if 12 - 12: II111iiii % OoOoOO00
  return ( Ii1I11I )
  if 18 - 18: oO0o / ooOoO0o * I1IiiI / Oo0Ooo / I11i - OOooOOo
  if 53 - 53: ooOoO0o / OoOoOO00 - OoooooooOO * oO0o
 def get_encap_keys ( self ) :
  OoO0o = "4341" if self . translated_port == 0 else str ( self . translated_port )
  if 45 - 45: o0oOOo0O0Ooo . I1Ii111 % Ii1I
  oO00o = self . rloc . print_address_no_iid ( ) + ":" + OoO0o
  if 42 - 42: Oo0Ooo + i11iIiiIii - OOooOOo . I1ii11iIi11i % I1Ii111 . I1ii11iIi11i
  try :
   IiI1ii11I1 = lisp_crypto_keys_by_rloc_encap [ oO00o ]
   if ( IiI1ii11I1 [ 1 ] ) : return ( IiI1ii11I1 [ 1 ] . encrypt_key , IiI1ii11I1 [ 1 ] . icv_key )
   return ( None , None )
  except :
   return ( None , None )
   if 59 - 59: OoooooooOO
   if 91 - 91: i11iIiiIii / Oo0Ooo % I11i / O0
   if 80 - 80: II111iiii / I1ii11iIi11i % I1IiiI . Ii1I
 def rloc_recent_rekey ( self ) :
  OoO0o = "4341" if self . translated_port == 0 else str ( self . translated_port )
  if 8 - 8: oO0o
  oO00o = self . rloc . print_address_no_iid ( ) + ":" + OoO0o
  if 21 - 21: oO0o + iII111i . i11iIiiIii - II111iiii
  try :
   i1i11ii1 = lisp_crypto_keys_by_rloc_encap [ oO00o ] [ 1 ]
   if ( i1i11ii1 == None ) : return ( False )
   if ( i1i11ii1 . last_rekey == None ) : return ( True )
   return ( time . time ( ) - i1i11ii1 . last_rekey < 1 )
  except :
   return ( False )
   if 14 - 14: I1Ii111
   if 81 - 81: II111iiii
   if 55 - 55: O0 + o0oOOo0O0Ooo * I1IiiI - OoooooooOO
   if 68 - 68: I11i + Oo0Ooo
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
  if 15 - 15: O0
  if 75 - 75: iII111i / OoOoOO00
 def print_mapping ( self , eid_indent , rloc_indent ) :
  iII1i1 = lisp_print_elapsed ( self . uptime )
  iIiii1Ii1I = "" if self . group . is_null ( ) else ", group {}" . format ( self . group . print_prefix ( ) )
  if 2 - 2: i1IIi + oO0o % iII111i % I1ii11iIi11i + ooOoO0o . iII111i
  lprint ( "{}eid {}{}, uptime {}, {} rlocs:" . format ( eid_indent ,
 green ( self . eid . print_prefix ( ) , False ) , iIiii1Ii1I , iII1i1 ,
 len ( self . rloc_set ) ) )
  for i11iII1Ii1ii111 in self . rloc_set : i11iII1Ii1ii111 . print_rloc ( rloc_indent )
  if 26 - 26: I11i + o0oOOo0O0Ooo + Ii1I % I11i
  if 95 - 95: IiII - O0 * oO0o * O0
 def print_eid_tuple ( self ) :
  return ( lisp_print_eid_tuple ( self . eid , self . group ) )
  if 47 - 47: I1IiiI
  if 20 - 20: I1Ii111
 def print_ttl ( self ) :
  o0O0OOo0oo00 = self . map_cache_ttl
  if ( o0O0OOo0oo00 == None ) : return ( "forever" )
  if 40 - 40: OoooooooOO / o0oOOo0O0Ooo + OoOoOO00
  if ( o0O0OOo0oo00 >= 3600 ) :
   if ( ( o0O0OOo0oo00 % 3600 ) == 0 ) :
    o0O0OOo0oo00 = str ( o0O0OOo0oo00 / 3600 ) + " hours"
   else :
    o0O0OOo0oo00 = str ( o0O0OOo0oo00 * 60 ) + " mins"
    if 73 - 73: OOooOOo / Oo0Ooo
  elif ( o0O0OOo0oo00 >= 60 ) :
   if ( ( o0O0OOo0oo00 % 60 ) == 0 ) :
    o0O0OOo0oo00 = str ( o0O0OOo0oo00 / 60 ) + " mins"
   else :
    o0O0OOo0oo00 = str ( o0O0OOo0oo00 ) + " secs"
    if 80 - 80: OoO0O00 + I1IiiI % i1IIi / I11i % i1IIi * i11iIiiIii
  else :
   o0O0OOo0oo00 = str ( o0O0OOo0oo00 ) + " secs"
   if 27 - 27: OoOoOO00 / I1Ii111 * O0 / I1IiiI - IiII / o0oOOo0O0Ooo
  return ( o0O0OOo0oo00 )
  if 70 - 70: I1ii11iIi11i
  if 11 - 11: I1Ii111
 def has_ttl_elapsed ( self ) :
  if ( self . map_cache_ttl == None ) : return ( False )
  oO000o = time . time ( ) - self . last_refresh_time
  return ( oO000o >= self . map_cache_ttl )
  if 70 - 70: Ii1I
  if 22 - 22: Ii1I
 def is_active ( self ) :
  if ( self . stats . last_increment == None ) : return ( False )
  oO000o = time . time ( ) - self . stats . last_increment
  return ( oO000o <= 60 )
  if 59 - 59: I1ii11iIi11i
  if 90 - 90: OOooOOo / iII111i
 def match_eid_tuple ( self , db ) :
  if ( self . eid . is_exact_match ( db . eid ) == False ) : return ( False )
  if ( self . group . is_exact_match ( db . group ) == False ) : return ( False )
  return ( True )
  if 70 - 70: o0oOOo0O0Ooo
  if 49 - 49: OOooOOo - I1IiiI + OoooooooOO % iII111i + o0oOOo0O0Ooo + OoOoOO00
 def sort_rloc_set ( self ) :
  self . rloc_set . sort ( key = operator . attrgetter ( 'rloc.address' ) )
  if 37 - 37: II111iiii % I1ii11iIi11i * OoOoOO00
  if 35 - 35: i1IIi
 def delete_rlocs_from_rloc_probe_list ( self ) :
  for i11iII1Ii1ii111 in self . best_rloc_set :
   i11iII1Ii1ii111 . delete_from_rloc_probe_list ( self . eid , self . group )
   if 81 - 81: OoO0O00
   if 45 - 45: OoooooooOO . O0 * oO0o + IiII
   if 18 - 18: II111iiii . O0 - I11i / I11i
 def build_best_rloc_set ( self ) :
  OOOoooo = self . best_rloc_set
  self . best_rloc_set = [ ]
  if ( self . rloc_set == None ) : return
  if 39 - 39: Ii1I + I1Ii111 * Oo0Ooo + OoOoOO00 / I1Ii111 - ooOoO0o
  if 66 - 66: I11i * OoO0O00
  if 98 - 98: IiII . Oo0Ooo + I1Ii111
  if 63 - 63: oO0o * I1IiiI * oO0o
  oO0000000 = 256
  for i11iII1Ii1ii111 in self . rloc_set :
   if ( i11iII1Ii1ii111 . up_state ( ) ) : oO0000000 = min ( i11iII1Ii1ii111 . priority , oO0000000 )
   if 68 - 68: IiII / o0oOOo0O0Ooo * OoO0O00 % iIii1I11I1II1 + I1IiiI . I1IiiI
   if 8 - 8: Ii1I + O0 + II111iiii + o0oOOo0O0Ooo - OoO0O00 - Ii1I
   if 88 - 88: I1ii11iIi11i . O0 - o0oOOo0O0Ooo . I1ii11iIi11i * iII111i * I11i
   if 89 - 89: Oo0Ooo - oO0o + O0 / i11iIiiIii
   if 64 - 64: OoO0O00 % OoOoOO00 % I1IiiI - Ii1I / IiII * Ii1I
   if 74 - 74: IiII - O0 % OOooOOo % OoooooooOO - I11i
   if 4 - 4: i1IIi + OoOoOO00 + iIii1I11I1II1 - i1IIi * i11iIiiIii
   if 99 - 99: I1ii11iIi11i - O0 % II111iiii + ooOoO0o % OoO0O00 * Ii1I
   if 8 - 8: OOooOOo
   if 85 - 85: O0 % OOooOOo . Ii1I
  for i11iII1Ii1ii111 in self . rloc_set :
   if ( i11iII1Ii1ii111 . priority <= oO0000000 ) :
    if ( i11iII1Ii1ii111 . unreach_state ( ) and i11iII1Ii1ii111 . last_rloc_probe == None ) :
     i11iII1Ii1ii111 . last_rloc_probe = lisp_get_timestamp ( )
     if 74 - 74: I1ii11iIi11i - I1Ii111 + i11iIiiIii / I1Ii111 / OoooooooOO + o0oOOo0O0Ooo
    self . best_rloc_set . append ( i11iII1Ii1ii111 )
    if 23 - 23: Oo0Ooo
    if 91 - 91: I1Ii111
    if 59 - 59: i1IIi % OOooOOo
    if 81 - 81: i11iIiiIii / OoO0O00 * OoOoOO00 % iII111i - iIii1I11I1II1 + I1ii11iIi11i
    if 20 - 20: O0 . I1Ii111 * Ii1I * II111iiii
    if 66 - 66: Ii1I % OoO0O00 % II111iiii - OOooOOo * o0oOOo0O0Ooo
    if 33 - 33: OoooooooOO / I11i
    if 98 - 98: I1ii11iIi11i . Ii1I . iIii1I11I1II1 * I1ii11iIi11i / Ii1I
  for i11iII1Ii1ii111 in OOOoooo :
   if ( i11iII1Ii1ii111 . priority < oO0000000 ) : continue
   i11iII1Ii1ii111 . delete_from_rloc_probe_list ( self . eid , self . group )
   if 74 - 74: Oo0Ooo * I1Ii111
  for i11iII1Ii1ii111 in self . best_rloc_set :
   if ( i11iII1Ii1ii111 . rloc . is_null ( ) ) : continue
   i11iII1Ii1ii111 . add_to_rloc_probe_list ( self . eid , self . group )
   if 72 - 72: OoOoOO00 + O0 - IiII * ooOoO0o
   if 20 - 20: II111iiii % OoOoOO00 * i11iIiiIii
   if 68 - 68: IiII / ooOoO0o
 def select_rloc ( self , lisp_packet , ipc_socket ) :
  I1i1iI = lisp_packet . packet
  o0O0 = lisp_packet . inner_version
  OOo000o = len ( self . best_rloc_set )
  if ( OOo000o is 0 ) :
   self . stats . increment ( len ( I1i1iI ) )
   return ( [ None , None , None , self . action , None ] )
   if 57 - 57: ooOoO0o * oO0o + o0oOOo0O0Ooo
   if 97 - 97: OoooooooOO * I1IiiI . Ii1I * I1IiiI
  IIIIiii = 4 if lisp_load_split_pings else 0
  oooOo00 = lisp_packet . hash_ports ( )
  if ( o0O0 == 4 ) :
   for iiIii1I in range ( 8 + IIIIiii ) :
    oooOo00 = oooOo00 ^ struct . unpack ( "B" , I1i1iI [ iiIii1I + 12 ] ) [ 0 ]
    if 88 - 88: i11iIiiIii + o0oOOo0O0Ooo
  elif ( o0O0 == 6 ) :
   for iiIii1I in range ( 0 , 32 + IIIIiii , 4 ) :
    oooOo00 = oooOo00 ^ struct . unpack ( "I" , I1i1iI [ iiIii1I + 8 : iiIii1I + 12 ] ) [ 0 ]
    if 50 - 50: I1IiiI + Ii1I . IiII * ooOoO0o % I1Ii111
   oooOo00 = ( oooOo00 >> 16 ) + ( oooOo00 & 0xffff )
   oooOo00 = ( oooOo00 >> 8 ) + ( oooOo00 & 0xff )
  else :
   for iiIii1I in range ( 0 , 12 + IIIIiii , 4 ) :
    oooOo00 = oooOo00 ^ struct . unpack ( "I" , I1i1iI [ iiIii1I : iiIii1I + 4 ] ) [ 0 ]
    if 4 - 4: i1IIi - ooOoO0o
    if 14 - 14: i1IIi . OoOoOO00 % I1IiiI / iII111i * i11iIiiIii + O0
    if 10 - 10: o0oOOo0O0Ooo + OoO0O00 + Ii1I / OoO0O00
  if ( lisp_data_plane_logging ) :
   iiiII11ii = [ ]
   for O0ooOoO0OO000 in self . best_rloc_set :
    if ( O0ooOoO0OO000 . rloc . is_null ( ) ) : continue
    iiiII11ii . append ( [ O0ooOoO0OO000 . rloc . print_address_no_iid ( ) , O0ooOoO0OO000 . print_state ( ) ] )
    if 65 - 65: I11i % i1IIi
   dprint ( "Packet hash {}, index {}, best-rloc-list: {}" . format ( hex ( oooOo00 ) , oooOo00 % OOo000o , red ( str ( iiiII11ii ) , False ) ) )
   if 17 - 17: OoOoOO00 + I1IiiI / IiII
   if 55 - 55: oO0o
   if 53 - 53: OoO0O00 + iII111i / OoooooooOO
   if 52 - 52: O0
   if 34 - 34: OoooooooOO + OoOoOO00 - Oo0Ooo . OOooOOo * iIii1I11I1II1
   if 93 - 93: i11iIiiIii / Oo0Ooo * OoOoOO00 / ooOoO0o + OoO0O00 * OOooOOo
  i11iII1Ii1ii111 = self . best_rloc_set [ oooOo00 % OOo000o ]
  if 81 - 81: IiII * iII111i + i1IIi + I1Ii111 / OoO0O00
  if 83 - 83: oO0o / OoO0O00
  if 34 - 34: OoooooooOO - i1IIi * O0
  if 83 - 83: I1IiiI + OoO0O00
  if 41 - 41: Ii1I + II111iiii . OOooOOo * I1Ii111 / II111iiii
  OO0 = lisp_get_echo_nonce ( i11iII1Ii1ii111 . rloc , None )
  if ( OO0 ) :
   OO0 . change_state ( i11iII1Ii1ii111 )
   if ( i11iII1Ii1ii111 . no_echoed_nonce_state ( ) ) :
    OO0 . request_nonce_sent = None
    if 32 - 32: Oo0Ooo - Ii1I % o0oOOo0O0Ooo
    if 15 - 15: iIii1I11I1II1 * I1ii11iIi11i / ooOoO0o * oO0o % OOooOOo
    if 62 - 62: Ii1I / Oo0Ooo . OoO0O00 - OOooOOo
    if 89 - 89: o0oOOo0O0Ooo % OoO0O00
    if 53 - 53: OoOoOO00 . ooOoO0o - OoO0O00
    if 26 - 26: ooOoO0o - oO0o + OOooOOo * Ii1I - I11i % I1IiiI
  if ( i11iII1Ii1ii111 . up_state ( ) == False ) :
   O0o0oo0 = oooOo00 % OOo000o
   I1Iiiiiii = ( O0o0oo0 + 1 ) % OOo000o
   while ( I1Iiiiiii != O0o0oo0 ) :
    i11iII1Ii1ii111 = self . best_rloc_set [ I1Iiiiiii ]
    if ( i11iII1Ii1ii111 . up_state ( ) ) : break
    I1Iiiiiii = ( I1Iiiiiii + 1 ) % OOo000o
    if 77 - 77: OOooOOo % I1IiiI - iII111i % I1Ii111
   if ( I1Iiiiiii == O0o0oo0 ) :
    self . build_best_rloc_set ( )
    return ( [ None , None , None , None , None ] )
    if 29 - 29: iIii1I11I1II1 / i11iIiiIii + Oo0Ooo
    if 99 - 99: I1IiiI - iII111i * Ii1I - OoOoOO00 / i11iIiiIii - i1IIi
    if 46 - 46: I1ii11iIi11i * ooOoO0o
    if 4 - 4: I1Ii111 * II111iiii
    if 4 - 4: ooOoO0o * Oo0Ooo - I1ii11iIi11i % ooOoO0o % OoOoOO00
    if 18 - 18: OOooOOo / O0 . OoO0O00 - II111iiii * OOooOOo
  i11iII1Ii1ii111 . stats . increment ( len ( I1i1iI ) )
  if 13 - 13: OoO0O00 % i1IIi . i11iIiiIii / iII111i
  if 28 - 28: i1IIi - iII111i + o0oOOo0O0Ooo / Oo0Ooo * oO0o
  if 8 - 8: ooOoO0o + OOooOOo * ooOoO0o / i1IIi . I1ii11iIi11i
  if 4 - 4: Ii1I - Oo0Ooo . i1IIi + iIii1I11I1II1
  if ( i11iII1Ii1ii111 . rle_name and i11iII1Ii1ii111 . rle == None ) :
   if ( lisp_rle_list . has_key ( i11iII1Ii1ii111 . rle_name ) ) :
    i11iII1Ii1ii111 . rle = lisp_rle_list [ i11iII1Ii1ii111 . rle_name ]
    if 28 - 28: O0 / ooOoO0o / IiII - I11i + IiII + OoO0O00
    if 84 - 84: Oo0Ooo + OoOoOO00 / iII111i . I1ii11iIi11i
  if ( i11iII1Ii1ii111 . rle ) : return ( [ None , None , None , None , i11iII1Ii1ii111 . rle ] )
  if 26 - 26: Oo0Ooo
  if 61 - 61: Ii1I * oO0o * i11iIiiIii + OoO0O00
  if 43 - 43: OoO0O00 * OoO0O00 * oO0o
  if 24 - 24: oO0o
  if ( i11iII1Ii1ii111 . elp and i11iII1Ii1ii111 . elp . use_elp_node ) :
   return ( [ i11iII1Ii1ii111 . elp . use_elp_node . address , None , None , None , None ] )
   if 77 - 77: i11iIiiIii - I1Ii111 - I1ii11iIi11i * Oo0Ooo / i11iIiiIii
   if 79 - 79: Oo0Ooo % Oo0Ooo . oO0o + ooOoO0o * iII111i * I11i
   if 87 - 87: o0oOOo0O0Ooo + OoOoOO00 % o0oOOo0O0Ooo + I1IiiI
   if 89 - 89: II111iiii
   if 41 - 41: iIii1I11I1II1
  iIIiIoO0oO000ooo0o = None if ( i11iII1Ii1ii111 . rloc . is_null ( ) ) else i11iII1Ii1ii111 . rloc
  OoO0o = i11iII1Ii1ii111 . translated_port
  OOoooO = self . action if ( iIIiIoO0oO000ooo0o == None ) else None
  if 24 - 24: I1ii11iIi11i * I1Ii111 % o0oOOo0O0Ooo / I1ii11iIi11i
  if 72 - 72: I1Ii111 % O0
  if 24 - 24: I11i + I11i % I11i
  if 63 - 63: i11iIiiIii + iIii1I11I1II1 / oO0o % IiII - O0
  if 21 - 21: II111iiii
  iII = None
  if ( OO0 and OO0 . request_nonce_timeout ( ) == False ) :
   iII = OO0 . get_request_or_echo_nonce ( ipc_socket , iIIiIoO0oO000ooo0o )
   if 89 - 89: OOooOOo % i11iIiiIii * OoOoOO00 % oO0o / O0 * i1IIi
   if 16 - 16: IiII
   if 42 - 42: i1IIi / Ii1I * I1ii11iIi11i
   if 9 - 9: I11i % i1IIi / i1IIi / OoO0O00
   if 46 - 46: I1Ii111 * II111iiii + II111iiii * O0 % II111iiii
  return ( [ iIIiIoO0oO000ooo0o , OoO0o , iII , OOoooO , None ] )
  if 37 - 37: OOooOOo . iIii1I11I1II1 / O0 . ooOoO0o + OOooOOo - OoooooooOO
  if 96 - 96: I1Ii111 / oO0o . I1ii11iIi11i % I1IiiI * OOooOOo
 def do_rloc_sets_match ( self , rloc_address_set ) :
  if ( len ( self . rloc_set ) != len ( rloc_address_set ) ) : return ( False )
  if 99 - 99: i11iIiiIii - I1Ii111
  if 4 - 4: o0oOOo0O0Ooo - i11iIiiIii . iIii1I11I1II1 . OOooOOo % IiII
  if 68 - 68: I11i / iII111i - IiII . iIii1I11I1II1 / o0oOOo0O0Ooo
  if 54 - 54: II111iiii * I1IiiI
  if 49 - 49: I1ii11iIi11i
  for iiI1iI1 in self . rloc_set :
   for i11iII1Ii1ii111 in rloc_address_set :
    if ( i11iII1Ii1ii111 . is_exact_match ( iiI1iI1 . rloc ) == False ) : continue
    i11iII1Ii1ii111 = None
    break
    if 31 - 31: o0oOOo0O0Ooo - OoOoOO00 + I1ii11iIi11i . oO0o - O0
   if ( i11iII1Ii1ii111 == rloc_address_set [ - 1 ] ) : return ( False )
   if 61 - 61: I1ii11iIi11i * II111iiii . i1IIi
  return ( True )
  if 60 - 60: OoooooooOO % ooOoO0o * i11iIiiIii * OoooooooOO % IiII
  if 15 - 15: oO0o
 def get_rloc ( self , rloc ) :
  for iiI1iI1 in self . rloc_set :
   O0ooOoO0OO000 = iiI1iI1 . rloc
   if ( rloc . is_exact_match ( O0ooOoO0OO000 ) ) : return ( iiI1iI1 )
   if 40 - 40: I1Ii111
  return ( None )
  if 77 - 77: II111iiii - o0oOOo0O0Ooo . Ii1I
  if 47 - 47: o0oOOo0O0Ooo % OOooOOo + I1Ii111
 def get_rloc_by_interface ( self , interface ) :
  for iiI1iI1 in self . rloc_set :
   if ( iiI1iI1 . interface == interface ) : return ( iiI1iI1 )
   if 64 - 64: ooOoO0o / IiII . I1IiiI
  return ( None )
  if 77 - 77: o0oOOo0O0Ooo % I1Ii111 . OOooOOo
  if 90 - 90: I11i
 def add_db ( self ) :
  if ( self . group . is_null ( ) ) :
   lisp_db_for_lookups . add_cache ( self . eid , self )
  else :
   Oo00OO0 = lisp_db_for_lookups . lookup_cache ( self . group , True )
   if ( Oo00OO0 == None ) :
    Oo00OO0 = lisp_mapping ( self . group , self . group , [ ] )
    lisp_db_for_lookups . add_cache ( self . group , Oo00OO0 )
    if 53 - 53: I1ii11iIi11i + i11iIiiIii / iIii1I11I1II1 + OoooooooOO + IiII * I1IiiI
   Oo00OO0 . add_source_entry ( self )
   if 16 - 16: i11iIiiIii - oO0o . i11iIiiIii + OoO0O00 + i11iIiiIii
   if 85 - 85: I1ii11iIi11i - ooOoO0o + I1Ii111 + I1Ii111
   if 13 - 13: II111iiii
 def add_cache ( self , do_ipc = True ) :
  if ( self . group . is_null ( ) ) :
   lisp_map_cache . add_cache ( self . eid , self )
   if ( lisp_program_hardware ) : lisp_program_vxlan_hardware ( self )
  else :
   O0O = lisp_map_cache . lookup_cache ( self . group , True )
   if ( O0O == None ) :
    O0O = lisp_mapping ( self . group , self . group , [ ] )
    O0O . eid . copy_address ( self . group )
    O0O . group . copy_address ( self . group )
    lisp_map_cache . add_cache ( self . group , O0O )
    if 22 - 22: o0oOOo0O0Ooo
   if ( self . eid . is_null ( ) ) : self . eid . make_default_route ( O0O . group )
   O0O . add_source_entry ( self )
   if 45 - 45: I1Ii111 + OoooooooOO + o0oOOo0O0Ooo * II111iiii
  if ( do_ipc ) : lisp_write_ipc_map_cache ( True , self )
  if 12 - 12: I1ii11iIi11i / O0
  if 18 - 18: OoOoOO00 . i11iIiiIii + i1IIi / OoooooooOO - IiII % OoO0O00
 def delete_cache ( self ) :
  self . delete_rlocs_from_rloc_probe_list ( )
  lisp_write_ipc_map_cache ( False , self )
  if 47 - 47: iII111i % IiII + I1Ii111 * o0oOOo0O0Ooo * OoooooooOO
  if ( self . group . is_null ( ) ) :
   lisp_map_cache . delete_cache ( self . eid )
   if ( lisp_program_hardware ) :
    OOoOo = self . eid . print_prefix_no_iid ( )
    os . system ( "ip route delete {}" . format ( OOoOo ) )
    if 81 - 81: I11i * oO0o
  else :
   O0O = lisp_map_cache . lookup_cache ( self . group , True )
   if ( O0O == None ) : return
   if 51 - 51: I1IiiI
   iII1iiii1i = O0O . lookup_source_cache ( self . eid , True )
   if ( iII1iiii1i == None ) : return
   if 67 - 67: Ii1I + Oo0Ooo - I1IiiI - IiII + oO0o + Oo0Ooo
   O0O . source_cache . delete_cache ( self . eid )
   if ( O0O . source_cache . cache_size ( ) == 0 ) :
    lisp_map_cache . delete_cache ( self . group )
    if 84 - 84: I1ii11iIi11i % oO0o - OOooOOo * Ii1I
    if 78 - 78: i1IIi / ooOoO0o / oO0o
    if 21 - 21: IiII % Ii1I + OOooOOo + IiII
    if 90 - 90: o0oOOo0O0Ooo
 def add_source_entry ( self , source_mc ) :
  if ( self . source_cache == None ) : self . source_cache = lisp_cache ( )
  self . source_cache . add_cache ( source_mc . eid , source_mc )
  if 38 - 38: OoOoOO00 / OOooOOo % OoooooooOO * I1ii11iIi11i
  if 7 - 7: I11i * O0 + Oo0Ooo / O0 * oO0o + i11iIiiIii
 def lookup_source_cache ( self , source , exact ) :
  if ( self . source_cache == None ) : return ( None )
  return ( self . source_cache . lookup_cache ( source , exact ) )
  if 74 - 74: OoOoOO00
  if 91 - 91: i11iIiiIii / Ii1I % OOooOOo % O0 - I11i . I11i
 def dynamic_eid_configured ( self ) :
  return ( self . dynamic_eids != None )
  if 78 - 78: i1IIi + I11i % OoooooooOO + i1IIi + iII111i % Ii1I
  if 87 - 87: ooOoO0o . iIii1I11I1II1
 def star_secondary_iid ( self , prefix ) :
  if ( self . secondary_iid == None ) : return ( prefix )
  I1I111iIi = "," + str ( self . secondary_iid )
  return ( prefix . replace ( I1I111iIi , I1I111iIi + "*" ) )
  if 99 - 99: Ii1I + OoooooooOO * IiII * i11iIiiIii - iIii1I11I1II1
  if 58 - 58: IiII % i1IIi . i11iIiiIii
 def increment_decap_stats ( self , packet ) :
  OoO0o = packet . udp_dport
  if ( OoO0o == LISP_DATA_PORT ) :
   i11iII1Ii1ii111 = self . get_rloc ( packet . outer_dest )
  else :
   if 5 - 5: OoOoOO00
   if 75 - 75: OOooOOo
   if 60 - 60: ooOoO0o - II111iiii - iIii1I11I1II1
   if 23 - 23: I1ii11iIi11i
   for i11iII1Ii1ii111 in self . rloc_set :
    if ( i11iII1Ii1ii111 . translated_port != 0 ) : break
    if 68 - 68: OoO0O00 . oO0o / IiII - II111iiii % Oo0Ooo
    if 24 - 24: II111iiii / I1ii11iIi11i + oO0o / Ii1I + IiII % oO0o
  if ( i11iII1Ii1ii111 != None ) : i11iII1Ii1ii111 . stats . increment ( len ( packet . packet ) )
  self . stats . increment ( len ( packet . packet ) )
  if 86 - 86: I1IiiI
  if 83 - 83: I11i % Ii1I + IiII % I11i / i1IIi . oO0o
 def rtrs_in_rloc_set ( self ) :
  for i11iII1Ii1ii111 in self . rloc_set :
   if ( i11iII1Ii1ii111 . is_rtr ( ) ) : return ( True )
   if 56 - 56: I1Ii111 - OOooOOo % o0oOOo0O0Ooo
  return ( False )
  if 30 - 30: I1Ii111 % i1IIi
  if 98 - 98: oO0o . i11iIiiIii / Ii1I - Ii1I
  if 23 - 23: iIii1I11I1II1
class lisp_dynamic_eid ( ) :
 def __init__ ( self ) :
  self . dynamic_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . uptime = lisp_get_timestamp ( )
  self . interface = None
  self . last_packet = None
  self . timeout = LISP_DEFAULT_DYN_EID_TIMEOUT
  if 30 - 30: I1ii11iIi11i + OoO0O00 - O0
  if 42 - 42: I11i - I1Ii111
 def get_timeout ( self , interface ) :
  try :
   i11Ii1iiiI = lisp_myinterfaces [ interface ]
   self . timeout = i11Ii1iiiI . dynamic_eid_timeout
  except :
   self . timeout = LISP_DEFAULT_DYN_EID_TIMEOUT
   if 56 - 56: I1Ii111 . I1ii11iIi11i - o0oOOo0O0Ooo / i11iIiiIii * iII111i / iIii1I11I1II1
   if 49 - 49: I1IiiI / iIii1I11I1II1
   if 31 - 31: i1IIi % I11i * o0oOOo0O0Ooo % i1IIi / IiII
   if 20 - 20: iIii1I11I1II1 . O0
class lisp_group_mapping ( ) :
 def __init__ ( self , group_name , ms_name , group_prefix , sources , rle_addr ) :
  self . group_name = group_name
  self . group_prefix = group_prefix
  self . use_ms_name = ms_name
  self . sources = sources
  self . rle_address = rle_addr
  if 61 - 61: OoOoOO00 * OOooOOo
  if 3 - 3: I1IiiI + Oo0Ooo / I1Ii111
 def add_group ( self ) :
  lisp_group_mapping_list [ self . group_name ] = self
  if 17 - 17: i11iIiiIii / Oo0Ooo . o0oOOo0O0Ooo / I1IiiI . OOooOOo
  if 10 - 10: I11i - OoOoOO00
  if 49 - 49: I1ii11iIi11i / II111iiii - ooOoO0o / I1Ii111 - oO0o
lisp_site_flags = {
 "P" : "ETR is {}Requesting Map-Server to Proxy Map-Reply" ,
 "S" : "ETR is {}LISP-SEC capable" ,
 "I" : "xTR-ID and site-ID are {}included in Map-Register" ,
 "T" : "Use Map-Register TTL field to timeout registration is {}set" ,
 "R" : "Merging registrations are {}requested" ,
 "M" : "ETR is {}a LISP Mobile-Node" ,
 "N" : "ETR is {}requesting Map-Notify messages from Map-Server"
 }
if 91 - 91: iII111i % Ii1I . IiII + ooOoO0o % i1IIi . II111iiii
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
  if 19 - 19: OoooooooOO + I1IiiI % Ii1I % II111iiii + o0oOOo0O0Ooo
  if 91 - 91: IiII
  if 36 - 36: ooOoO0o - OoOoOO00 . iIii1I11I1II1 / oO0o % OoooooooOO * iII111i
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
  if 42 - 42: oO0o
  if 71 - 71: i11iIiiIii . I1Ii111 % OoO0O00 % I1IiiI
 def print_eid_tuple ( self ) :
  return ( lisp_print_eid_tuple ( self . eid , self . group ) )
  if 46 - 46: IiII + oO0o - ooOoO0o
  if 2 - 2: i1IIi / Ii1I % OoO0O00
 def print_flags ( self , html ) :
  if ( html == False ) :
   Ii1I11I = "{}-{}-{}-{}-{}-{}-{}" . format ( "P" if self . proxy_reply_requested else "p" ,
   # Ii1I / iIii1I11I1II1 / Oo0Ooo . O0 . oO0o * I1IiiI
 "S" if self . lisp_sec_present else "s" ,
 "I" if self . xtr_id_present else "i" ,
 "T" if self . use_register_ttl_requested else "t" ,
 "R" if self . merge_register_requested else "r" ,
 "M" if self . mobile_node_requested else "m" ,
 "N" if self . map_notify_requested else "n" )
  else :
   iiiII = self . print_flags ( False )
   iiiII = iiiII . split ( "-" )
   Ii1I11I = ""
   for i1I1 in iiiII :
    iIOO0OOOo = lisp_site_flags [ i1I1 . upper ( ) ]
    iIOO0OOOo = iIOO0OOOo . format ( "" if i1I1 . isupper ( ) else "not " )
    Ii1I11I += lisp_span ( i1I1 , iIOO0OOOo )
    if ( i1I1 . lower ( ) != "n" ) : Ii1I11I += "-"
    if 15 - 15: II111iiii - iII111i / I1ii11iIi11i
    if 81 - 81: Ii1I - i1IIi % oO0o * Oo0Ooo * OoOoOO00
  return ( Ii1I11I )
  if 79 - 79: oO0o + I1IiiI % iII111i + II111iiii % OoO0O00 % iII111i
  if 46 - 46: o0oOOo0O0Ooo
 def copy_state_to_parent ( self , child ) :
  self . xtr_id = child . xtr_id
  self . site_id = child . site_id
  self . first_registered = child . first_registered
  self . last_registered = child . last_registered
  self . last_registerer = child . last_registerer
  self . register_ttl = child . register_ttl
  if ( self . registered == False ) :
   self . first_registered = lisp_get_timestamp ( )
   if 61 - 61: OoO0O00 . O0 + I1ii11iIi11i + OoO0O00
  self . auth_sha1_or_sha2 = child . auth_sha1_or_sha2
  self . registered = child . registered
  self . proxy_reply_requested = child . proxy_reply_requested
  self . lisp_sec_present = child . lisp_sec_present
  self . xtr_id_present = child . xtr_id_present
  self . use_register_ttl_requested = child . use_register_ttl_requested
  self . merge_register_requested = child . merge_register_requested
  self . mobile_node_requested = child . mobile_node_requested
  self . map_notify_requested = child . map_notify_requested
  if 44 - 44: I11i . oO0o
  if 65 - 65: I1ii11iIi11i * II111iiii % I11i + II111iiii . i1IIi / ooOoO0o
 def build_sort_key ( self ) :
  oOoOOo0oO00 = lisp_cache ( )
  II1i , i1i11ii1 = oOoOOo0oO00 . build_key ( self . eid )
  iI1ii11 = ""
  if ( self . group . is_null ( ) == False ) :
   Ii1Ii11i11 , iI1ii11 = oOoOOo0oO00 . build_key ( self . group )
   iI1ii11 = "-" + iI1ii11 [ 0 : 12 ] + "-" + str ( Ii1Ii11i11 ) + "-" + iI1ii11 [ 12 : : ]
   if 59 - 59: o0oOOo0O0Ooo
  i1i11ii1 = i1i11ii1 [ 0 : 12 ] + "-" + str ( II1i ) + "-" + i1i11ii1 [ 12 : : ] + iI1ii11
  del ( oOoOOo0oO00 )
  return ( i1i11ii1 )
  if 76 - 76: OoO0O00 + O0 - OoOoOO00 - IiII
  if 11 - 11: ooOoO0o + OoOoOO00 - i1IIi
 def merge_in_site_eid ( self , child ) :
  o0Oo0OO0o = False
  if ( self . group . is_null ( ) ) :
   self . merge_rlocs_in_site_eid ( )
  else :
   o0Oo0OO0o = self . merge_rles_in_site_eid ( )
   if 30 - 30: Ii1I / I1ii11iIi11i % IiII - Oo0Ooo
   if 100 - 100: IiII . I1Ii111 * oO0o % OoO0O00 . iIii1I11I1II1 * Oo0Ooo
   if 100 - 100: IiII - OoOoOO00 % iII111i
   if 24 - 24: Oo0Ooo / OoO0O00 + i11iIiiIii
   if 81 - 81: i11iIiiIii . iIii1I11I1II1 - OoooooooOO
   if 52 - 52: O0 - I1Ii111 + oO0o % ooOoO0o . oO0o
  if ( child != None ) :
   self . copy_state_to_parent ( child )
   self . map_registers_received += 1
   if 60 - 60: oO0o + o0oOOo0O0Ooo - OOooOOo % o0oOOo0O0Ooo . I11i + OoO0O00
  return ( o0Oo0OO0o )
  if 27 - 27: i11iIiiIii - I1ii11iIi11i * I1Ii111 . I1IiiI / OoO0O00 * ooOoO0o
  if 42 - 42: OOooOOo
 def copy_rloc_records ( self ) :
  iiI11i = [ ]
  for iiI1iI1 in self . registered_rlocs :
   iiI11i . append ( copy . deepcopy ( iiI1iI1 ) )
   if 22 - 22: Ii1I / ooOoO0o / o0oOOo0O0Ooo % I1ii11iIi11i . iIii1I11I1II1
  return ( iiI11i )
  if 78 - 78: OoO0O00 . I1ii11iIi11i / ooOoO0o + OoO0O00 / I1ii11iIi11i * ooOoO0o
  if 96 - 96: IiII % iII111i . OoOoOO00 / oO0o . OoO0O00
 def merge_rlocs_in_site_eid ( self ) :
  self . registered_rlocs = [ ]
  for iI1II1i1I1Ii in self . individual_registrations . values ( ) :
   if ( self . site_id != iI1II1i1I1Ii . site_id ) : continue
   if ( iI1II1i1I1Ii . registered == False ) : continue
   self . registered_rlocs += iI1II1i1I1Ii . copy_rloc_records ( )
   if 85 - 85: iIii1I11I1II1 / OoOoOO00 * I1ii11iIi11i
   if 26 - 26: iII111i - OoO0O00 . o0oOOo0O0Ooo
   if 50 - 50: I1Ii111 . O0 . OoOoOO00 + I1Ii111 + OoooooooOO . i11iIiiIii
   if 65 - 65: I1IiiI % iIii1I11I1II1
   if 52 - 52: I1IiiI
   if 19 - 19: I1IiiI
  iiI11i = [ ]
  for iiI1iI1 in self . registered_rlocs :
   if ( iiI1iI1 . rloc . is_null ( ) or len ( iiI11i ) == 0 ) :
    iiI11i . append ( iiI1iI1 )
    continue
    if 17 - 17: I11i + OoooooooOO
   for ooO0Ooooo0oO in iiI11i :
    if ( ooO0Ooooo0oO . rloc . is_null ( ) ) : continue
    if ( iiI1iI1 . rloc . is_exact_match ( ooO0Ooooo0oO . rloc ) ) : break
    if 33 - 33: Oo0Ooo + OoO0O00
   if ( ooO0Ooooo0oO == iiI11i [ - 1 ] ) : iiI11i . append ( iiI1iI1 )
   if 62 - 62: oO0o / I1IiiI
  self . registered_rlocs = iiI11i
  if 83 - 83: iIii1I11I1II1 / iII111i * ooOoO0o + OoooooooOO
  if 97 - 97: IiII / OoooooooOO / iIii1I11I1II1 . i1IIi
  if 18 - 18: o0oOOo0O0Ooo + OoOoOO00 - I1ii11iIi11i - ooOoO0o
  if 42 - 42: iIii1I11I1II1 % i1IIi - O0 * II111iiii
  if ( len ( self . registered_rlocs ) == 0 ) : self . registered = False
  return
  if 58 - 58: i1IIi - OoO0O00 + ooOoO0o
  if 6 - 6: IiII % I1IiiI + OoooooooOO * oO0o . iII111i + oO0o
 def merge_rles_in_site_eid ( self ) :
  if 4 - 4: I11i % I1IiiI
  if 72 - 72: I1IiiI % II111iiii % iII111i / OoOoOO00
  if 96 - 96: OoOoOO00 % Ii1I
  if 50 - 50: IiII - II111iiii
  Ii11I111Iii = { }
  for iiI1iI1 in self . registered_rlocs :
   if ( iiI1iI1 . rle == None ) : continue
   for OO in iiI1iI1 . rle . rle_nodes :
    iIiIi1ii = OO . address . print_address_no_iid ( )
    Ii11I111Iii [ iIiIi1ii ] = OO . address
    if 27 - 27: i1IIi
   break
   if 15 - 15: IiII
   if 70 - 70: Oo0Ooo * OOooOOo + I1Ii111 % OoOoOO00 / O0
   if 23 - 23: O0 * oO0o / I1IiiI + i1IIi * O0 % oO0o
   if 11 - 11: I1Ii111 . OoooooooOO * iIii1I11I1II1 / I1ii11iIi11i - ooOoO0o . iII111i
   if 71 - 71: i11iIiiIii + I11i / i11iIiiIii % Oo0Ooo / iIii1I11I1II1 * OoO0O00
  self . merge_rlocs_in_site_eid ( )
  if 49 - 49: iII111i + OoOoOO00
  if 33 - 33: ooOoO0o
  if 19 - 19: I1Ii111 % IiII
  if 94 - 94: I1Ii111 * I1ii11iIi11i * I1ii11iIi11i - o0oOOo0O0Ooo . i11iIiiIii
  if 16 - 16: i1IIi
  if 88 - 88: OOooOOo
  if 79 - 79: oO0o
  if 52 - 52: oO0o + OoO0O00 / OoooooooOO - iIii1I11I1II1 / iII111i - oO0o
  OOOO0o0o = [ ]
  for iiI1iI1 in self . registered_rlocs :
   if ( self . registered_rlocs . index ( iiI1iI1 ) == 0 ) :
    OOOO0o0o . append ( iiI1iI1 )
    continue
    if 95 - 95: ooOoO0o + o0oOOo0O0Ooo % OoO0O00
   if ( iiI1iI1 . rle == None ) : OOOO0o0o . append ( iiI1iI1 )
   if 42 - 42: ooOoO0o % iIii1I11I1II1 % ooOoO0o * oO0o * I1Ii111 * Ii1I
  self . registered_rlocs = OOOO0o0o
  if 16 - 16: i11iIiiIii
  if 83 - 83: Oo0Ooo / Oo0Ooo . I11i + oO0o % Ii1I
  if 22 - 22: ooOoO0o
  if 83 - 83: OOooOOo - i11iIiiIii - i1IIi / oO0o
  if 33 - 33: OoO0O00 + OOooOOo
  if 36 - 36: o0oOOo0O0Ooo . o0oOOo0O0Ooo / oO0o * ooOoO0o * Ii1I * IiII
  if 39 - 39: i1IIi
  o0ooOOoO0oO0 = lisp_rle ( "" )
  o0OoOO00 = { }
  iI1Iii11Iii11 = None
  for iI1II1i1I1Ii in self . individual_registrations . values ( ) :
   if ( iI1II1i1I1Ii . registered == False ) : continue
   oO0 = iI1II1i1I1Ii . registered_rlocs [ 0 ] . rle
   if ( oO0 == None ) : continue
   if 4 - 4: i11iIiiIii - iIii1I11I1II1 % o0oOOo0O0Ooo * oO0o
   iI1Iii11Iii11 = iI1II1i1I1Ii . registered_rlocs [ 0 ] . rloc_name
   for iIiI11ii1ii in oO0 . rle_nodes :
    iIiIi1ii = iIiI11ii1ii . address . print_address_no_iid ( )
    if ( o0OoOO00 . has_key ( iIiIi1ii ) ) : break
    if 39 - 39: I1IiiI + I1ii11iIi11i - o0oOOo0O0Ooo + Ii1I . OOooOOo * I1ii11iIi11i
    OO = lisp_rle_node ( )
    OO . address . copy_address ( iIiI11ii1ii . address )
    OO . level = iIiI11ii1ii . level
    OO . rloc_name = iI1Iii11Iii11
    o0ooOOoO0oO0 . rle_nodes . append ( OO )
    o0OoOO00 [ iIiIi1ii ] = iIiI11ii1ii . address
    if 11 - 11: I1Ii111 + iIii1I11I1II1
    if 36 - 36: II111iiii - ooOoO0o - Ii1I . OoOoOO00 + OoooooooOO
    if 10 - 10: I11i . I1Ii111 % II111iiii / o0oOOo0O0Ooo - Oo0Ooo
    if 15 - 15: O0 + OOooOOo
    if 8 - 8: i11iIiiIii . IiII . I1ii11iIi11i + i1IIi % I1Ii111
    if 64 - 64: I1IiiI . Oo0Ooo * OoO0O00
  if ( len ( o0ooOOoO0oO0 . rle_nodes ) == 0 ) : o0ooOOoO0oO0 = None
  if ( len ( self . registered_rlocs ) != 0 ) :
   self . registered_rlocs [ 0 ] . rle = o0ooOOoO0oO0
   if ( iI1Iii11Iii11 ) : self . registered_rlocs [ 0 ] . rloc_name = None
   if 87 - 87: i1IIi / OoooooooOO
   if 68 - 68: I1Ii111 / iIii1I11I1II1
   if 8 - 8: ooOoO0o * IiII * OOooOOo / I1IiiI
   if 40 - 40: i11iIiiIii + OoooooooOO
   if 2 - 2: o0oOOo0O0Ooo * OoO0O00
  if ( Ii11I111Iii . keys ( ) == o0OoOO00 . keys ( ) ) : return ( False )
  if 88 - 88: Oo0Ooo + oO0o + iII111i
  lprint ( "{} {} from {} to {}" . format ( green ( self . print_eid_tuple ( ) , False ) , bold ( "RLE change" , False ) ,
  # Oo0Ooo % ooOoO0o / II111iiii . I11i
 Ii11I111Iii . keys ( ) , o0OoOO00 . keys ( ) ) )
  if 41 - 41: IiII / OOooOOo * o0oOOo0O0Ooo . iII111i * I1IiiI . iIii1I11I1II1
  return ( True )
  if 52 - 52: oO0o . OOooOOo . oO0o / Oo0Ooo / i1IIi - I1IiiI
  if 69 - 69: Ii1I . o0oOOo0O0Ooo - OoooooooOO
 def add_cache ( self ) :
  if ( self . group . is_null ( ) ) :
   lisp_sites_by_eid . add_cache ( self . eid , self )
  else :
   ii1II11111i = lisp_sites_by_eid . lookup_cache ( self . group , True )
   if ( ii1II11111i == None ) :
    ii1II11111i = lisp_site_eid ( self . site )
    ii1II11111i . eid . copy_address ( self . group )
    ii1II11111i . group . copy_address ( self . group )
    lisp_sites_by_eid . add_cache ( self . group , ii1II11111i )
    if 15 - 15: OoO0O00 / I1ii11iIi11i
    if 86 - 86: OOooOOo * OoOoOO00 % i1IIi * IiII . I1ii11iIi11i
    if 72 - 72: i1IIi - I1Ii111 . O0 * OoO0O00
    if 62 - 62: Oo0Ooo . iII111i
    if 15 - 15: i11iIiiIii * I11i + oO0o
    ii1II11111i . parent_for_more_specifics = self . parent_for_more_specifics
    if 67 - 67: IiII . OoO0O00
   if ( self . eid . is_null ( ) ) : self . eid . make_default_route ( ii1II11111i . group )
   ii1II11111i . add_source_entry ( self )
   if 59 - 59: oO0o * o0oOOo0O0Ooo
   if 76 - 76: I1IiiI
   if 94 - 94: OoooooooOO * I1ii11iIi11i
 def delete_cache ( self ) :
  if ( self . group . is_null ( ) ) :
   lisp_sites_by_eid . delete_cache ( self . eid )
  else :
   ii1II11111i = lisp_sites_by_eid . lookup_cache ( self . group , True )
   if ( ii1II11111i == None ) : return
   if 28 - 28: II111iiii / II111iiii / II111iiii
   iI1II1i1I1Ii = ii1II11111i . lookup_source_cache ( self . eid , True )
   if ( iI1II1i1I1Ii == None ) : return
   if 70 - 70: OoO0O00 + O0 * OoO0O00
   if ( ii1II11111i . source_cache == None ) : return
   if 25 - 25: OoooooooOO . Oo0Ooo + OOooOOo + Oo0Ooo * O0 % i1IIi
   ii1II11111i . source_cache . delete_cache ( self . eid )
   if ( ii1II11111i . source_cache . cache_size ( ) == 0 ) :
    lisp_sites_by_eid . delete_cache ( self . group )
    if 71 - 71: II111iiii / Ii1I + i1IIi - OoOoOO00 + Ii1I
    if 31 - 31: OoooooooOO * Ii1I - iII111i . oO0o % Ii1I
    if 97 - 97: Ii1I
    if 51 - 51: II111iiii . oO0o % iII111i
 def add_source_entry ( self , source_se ) :
  if ( self . source_cache == None ) : self . source_cache = lisp_cache ( )
  self . source_cache . add_cache ( source_se . eid , source_se )
  if 47 - 47: II111iiii - iII111i * I1IiiI . IiII
  if 41 - 41: OoOoOO00 / O0 + I1Ii111 . I1ii11iIi11i
 def lookup_source_cache ( self , source , exact ) :
  if ( self . source_cache == None ) : return ( None )
  return ( self . source_cache . lookup_cache ( source , exact ) )
  if 48 - 48: Ii1I . o0oOOo0O0Ooo * O0 / OoooooooOO + I1Ii111 + Oo0Ooo
  if 92 - 92: Ii1I - o0oOOo0O0Ooo % I1IiiI + I1Ii111
 def is_star_g ( self ) :
  if ( self . group . is_null ( ) ) : return ( False )
  return ( self . eid . is_exact_match ( self . group ) )
  if 3 - 3: iIii1I11I1II1 + i11iIiiIii
  if 49 - 49: OoOoOO00 % iIii1I11I1II1 + I1Ii111
 def eid_record_matches ( self , eid_record ) :
  if ( self . eid . is_exact_match ( eid_record . eid ) == False ) : return ( False )
  if ( eid_record . group . is_null ( ) ) : return ( True )
  return ( eid_record . group . is_exact_match ( self . group ) )
  if 38 - 38: i11iIiiIii
  if 75 - 75: iIii1I11I1II1 / OoO0O00 * OOooOOo % O0
 def inherit_from_ams_parent ( self ) :
  IiIII1iii1iII = self . parent_for_more_specifics
  if ( IiIII1iii1iII == None ) : return
  self . force_proxy_reply = IiIII1iii1iII . force_proxy_reply
  self . force_nat_proxy_reply = IiIII1iii1iII . force_nat_proxy_reply
  self . force_ttl = IiIII1iii1iII . force_ttl
  self . pitr_proxy_reply_drop = IiIII1iii1iII . pitr_proxy_reply_drop
  self . proxy_reply_action = IiIII1iii1iII . proxy_reply_action
  self . echo_nonce_capable = IiIII1iii1iII . echo_nonce_capable
  self . policy = IiIII1iii1iII . policy
  self . require_signature = IiIII1iii1iII . require_signature
  if 82 - 82: Oo0Ooo / i1IIi . i1IIi / oO0o
  if 7 - 7: Oo0Ooo . iII111i % I1ii11iIi11i / iII111i
 def rtrs_in_rloc_set ( self ) :
  for iiI1iI1 in self . registered_rlocs :
   if ( iiI1iI1 . is_rtr ( ) ) : return ( True )
   if 93 - 93: iII111i
  return ( False )
  if 5 - 5: iII111i . I11i % I11i * Ii1I - I1ii11iIi11i . i11iIiiIii
  if 32 - 32: II111iiii
 def is_rtr_in_rloc_set ( self , rtr_rloc ) :
  for iiI1iI1 in self . registered_rlocs :
   if ( iiI1iI1 . rloc . is_exact_match ( rtr_rloc ) == False ) : continue
   if ( iiI1iI1 . is_rtr ( ) ) : return ( True )
   if 58 - 58: I1IiiI - o0oOOo0O0Ooo - I1Ii111 . O0 % OoO0O00 . I11i
  return ( False )
  if 41 - 41: iII111i . I1Ii111 - IiII / O0
  if 62 - 62: IiII * I1ii11iIi11i * iII111i * OoOoOO00
 def is_rloc_in_rloc_set ( self , rloc ) :
  for iiI1iI1 in self . registered_rlocs :
   if ( iiI1iI1 . rle ) :
    for o0ooOOoO0oO0 in iiI1iI1 . rle . rle_nodes :
     if ( o0ooOOoO0oO0 . address . is_exact_match ( rloc ) ) : return ( True )
     if 12 - 12: Oo0Ooo * Ii1I / ooOoO0o % I11i % O0
     if 25 - 25: Oo0Ooo * oO0o
   if ( iiI1iI1 . rloc . is_exact_match ( rloc ) ) : return ( True )
   if 78 - 78: OoOoOO00 / II111iiii
  return ( False )
  if 6 - 6: I1Ii111 . OoOoOO00
  if 75 - 75: Oo0Ooo + I11i
 def do_rloc_sets_match ( self , prev_rloc_set ) :
  if ( len ( self . registered_rlocs ) != len ( prev_rloc_set ) ) : return ( False )
  if 87 - 87: I1IiiI
  for iiI1iI1 in prev_rloc_set :
   oO0ooo0O = iiI1iI1 . rloc
   if ( self . is_rloc_in_rloc_set ( oO0ooo0O ) == False ) : return ( False )
   if 36 - 36: OoO0O00 . ooOoO0o . O0 / OoO0O00
  return ( True )
  if 50 - 50: Ii1I . OoOoOO00 * o0oOOo0O0Ooo
  if 68 - 68: IiII * oO0o / OoOoOO00 / I1Ii111
  if 72 - 72: I1ii11iIi11i
class lisp_mr ( ) :
 def __init__ ( self , addr_str , dns_name , mr_name ) :
  self . mr_name = mr_name if ( mr_name != None ) else "all"
  self . dns_name = dns_name
  self . map_resolver = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . last_dns_resolve = None
  if ( addr_str ) :
   self . map_resolver . store_address ( addr_str )
   self . insert_mr ( )
  else :
   self . resolve_dns_name ( )
   if 74 - 74: I1Ii111 * iIii1I11I1II1 / oO0o - IiII - I1IiiI
  self . last_used = 0
  self . last_reply = 0
  self . last_nonce = 0
  self . map_requests_sent = 0
  self . neg_map_replies_received = 0
  self . total_rtt = 0
  if 84 - 84: iIii1I11I1II1 % Oo0Ooo / I1ii11iIi11i + o0oOOo0O0Ooo * II111iiii
  if 81 - 81: I1IiiI / I1ii11iIi11i / OOooOOo
 def resolve_dns_name ( self ) :
  if ( self . dns_name == None ) : return
  if ( self . last_dns_resolve and
 time . time ( ) - self . last_dns_resolve < 30 ) : return
  try :
   self . last_dns_resolve = lisp_get_timestamp ( )
   iIiIi1ii = socket . gethostbyname ( self . dns_name )
   if ( iIiIi1ii != self . map_resolver . print_address_no_iid ( ) ) :
    self . delete_mr ( )
    self . map_resolver . store_address ( iIiIi1ii )
    self . insert_mr ( )
    if 89 - 89: Oo0Ooo % IiII
  except :
   pass
   if 36 - 36: IiII % OoOoOO00 % I1ii11iIi11i
   if 7 - 7: I1ii11iIi11i % OoOoOO00 - O0 . I1Ii111
   if 9 - 9: Ii1I . OoooooooOO / ooOoO0o + i1IIi
 def insert_mr ( self ) :
  i1i11ii1 = self . mr_name + self . map_resolver . print_address ( )
  lisp_map_resolvers_list [ i1i11ii1 ] = self
  if 90 - 90: oO0o - OoOoOO00 % ooOoO0o
  if 83 - 83: OOooOOo - I1ii11iIi11i + OoO0O00
 def delete_mr ( self ) :
  i1i11ii1 = self . mr_name + self . map_resolver . print_address ( )
  if ( lisp_map_resolvers_list . has_key ( i1i11ii1 ) == False ) : return
  lisp_map_resolvers_list . pop ( i1i11ii1 )
  if 99 - 99: iII111i - OoOoOO00 % ooOoO0o
  if 27 - 27: oO0o . oO0o * iII111i % iIii1I11I1II1
  if 81 - 81: iII111i * II111iiii
class lisp_ddt_root ( ) :
 def __init__ ( self ) :
  self . root_address = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . public_key = ""
  self . priority = 0
  self . weight = 0
  if 28 - 28: i11iIiiIii . Oo0Ooo . Ii1I
  if 19 - 19: OoO0O00 - Ii1I + ooOoO0o + OOooOOo
  if 84 - 84: iII111i / Oo0Ooo
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
  if 21 - 21: OoO0O00 . I1IiiI - OoO0O00
  if 51 - 51: iIii1I11I1II1
 def print_referral ( self , eid_indent , referral_indent ) :
  iIiI11IIooO0o0O00o0OO = lisp_print_elapsed ( self . uptime )
  iIoO0ooO0OO0Oo = lisp_print_future ( self . expires )
  lprint ( "{}Referral EID {}, uptime/expires {}/{}, {} referrals:" . format ( eid_indent , green ( self . eid . print_prefix ( ) , False ) , iIiI11IIooO0o0O00o0OO ,
  # iIii1I11I1II1
 iIoO0ooO0OO0Oo , len ( self . referral_set ) ) )
  if 74 - 74: Ii1I
  for iiiiiIIiI in self . referral_set . values ( ) :
   iiiiiIIiI . print_ref_node ( referral_indent )
   if 93 - 93: I1Ii111 % I1IiiI - iIii1I11I1II1
   if 28 - 28: OOooOOo . I1Ii111 . i11iIiiIii * Oo0Ooo
   if 74 - 74: OoooooooOO * i11iIiiIii * OoO0O00 * o0oOOo0O0Ooo
 def print_referral_type ( self ) :
  if ( self . eid . afi == LISP_AFI_ULTIMATE_ROOT ) : return ( "root" )
  if ( self . referral_type == LISP_DDT_ACTION_NULL ) :
   return ( "null-referral" )
   if 48 - 48: iII111i * I1ii11iIi11i * oO0o % O0 . OoO0O00
  if ( self . referral_type == LISP_DDT_ACTION_SITE_NOT_FOUND ) :
   return ( "no-site-action" )
   if 11 - 11: OOooOOo / o0oOOo0O0Ooo
  if ( self . referral_type > LISP_DDT_ACTION_MAX ) :
   return ( "invalid-action" )
   if 98 - 98: oO0o + I11i . oO0o
  return ( lisp_map_referral_action_string [ self . referral_type ] )
  if 10 - 10: iII111i + i1IIi . I11i % ooOoO0o / ooOoO0o
  if 86 - 86: Oo0Ooo
 def print_eid_tuple ( self ) :
  return ( lisp_print_eid_tuple ( self . eid , self . group ) )
  if 7 - 7: iIii1I11I1II1
  if 86 - 86: IiII + iII111i * II111iiii - IiII - o0oOOo0O0Ooo
 def print_ttl ( self ) :
  o0O0OOo0oo00 = self . referral_ttl
  if ( o0O0OOo0oo00 < 60 ) : return ( str ( o0O0OOo0oo00 ) + " secs" )
  if 8 - 8: OOooOOo . Ii1I
  if ( ( o0O0OOo0oo00 % 60 ) == 0 ) :
   o0O0OOo0oo00 = str ( o0O0OOo0oo00 / 60 ) + " mins"
  else :
   o0O0OOo0oo00 = str ( o0O0OOo0oo00 ) + " secs"
   if 15 - 15: ooOoO0o / OOooOOo + i1IIi / Ii1I / OOooOOo
  return ( o0O0OOo0oo00 )
  if 47 - 47: Oo0Ooo + oO0o % OoooooooOO
  if 23 - 23: I1Ii111 / i11iIiiIii - ooOoO0o * iII111i - Ii1I . iIii1I11I1II1
 def is_referral_negative ( self ) :
  return ( self . referral_type in ( LISP_DDT_ACTION_MS_NOT_REG , LISP_DDT_ACTION_DELEGATION_HOLE ,
  # I1IiiI
 LISP_DDT_ACTION_NOT_AUTH ) )
  if 81 - 81: OoOoOO00 * OoOoOO00 + OOooOOo . I11i - oO0o
  if 85 - 85: O0 * I1IiiI . Oo0Ooo - IiII
 def add_cache ( self ) :
  if ( self . group . is_null ( ) ) :
   lisp_referral_cache . add_cache ( self . eid , self )
  else :
   o0oOiiii1 = lisp_referral_cache . lookup_cache ( self . group , True )
   if ( o0oOiiii1 == None ) :
    o0oOiiii1 = lisp_referral ( )
    o0oOiiii1 . eid . copy_address ( self . group )
    o0oOiiii1 . group . copy_address ( self . group )
    lisp_referral_cache . add_cache ( self . group , o0oOiiii1 )
    if 84 - 84: I1Ii111 . iIii1I11I1II1 . O0 * I1ii11iIi11i
   if ( self . eid . is_null ( ) ) : self . eid . make_default_route ( o0oOiiii1 . group )
   o0oOiiii1 . add_source_entry ( self )
   if 59 - 59: i1IIi . o0oOOo0O0Ooo . Oo0Ooo * I1Ii111 + OoooooooOO
   if 11 - 11: I11i * ooOoO0o % iIii1I11I1II1 - O0
   if 68 - 68: ooOoO0o * OoooooooOO - OoooooooOO
 def delete_cache ( self ) :
  if ( self . group . is_null ( ) ) :
   lisp_referral_cache . delete_cache ( self . eid )
  else :
   o0oOiiii1 = lisp_referral_cache . lookup_cache ( self . group , True )
   if ( o0oOiiii1 == None ) : return
   if 59 - 59: Ii1I / I11i / I1Ii111 + IiII * I1ii11iIi11i
   OOOOO0OO00OOO = o0oOiiii1 . lookup_source_cache ( self . eid , True )
   if ( OOOOO0OO00OOO == None ) : return
   if 18 - 18: O0
   o0oOiiii1 . source_cache . delete_cache ( self . eid )
   if ( o0oOiiii1 . source_cache . cache_size ( ) == 0 ) :
    lisp_referral_cache . delete_cache ( self . group )
    if 60 - 60: II111iiii % O0 - I1Ii111 / iII111i / I1IiiI
    if 59 - 59: O0 / iIii1I11I1II1
    if 49 - 49: O0 + I1IiiI
    if 52 - 52: oO0o
 def add_source_entry ( self , source_ref ) :
  if ( self . source_cache == None ) : self . source_cache = lisp_cache ( )
  self . source_cache . add_cache ( source_ref . eid , source_ref )
  if 56 - 56: ooOoO0o
  if 94 - 94: OoOoOO00
 def lookup_source_cache ( self , source , exact ) :
  if ( self . source_cache == None ) : return ( None )
  return ( self . source_cache . lookup_cache ( source , exact ) )
  if 12 - 12: I11i * OoooooooOO + ooOoO0o
  if 16 - 16: IiII
  if 100 - 100: OoO0O00 % Oo0Ooo - OoooooooOO
class lisp_referral_node ( ) :
 def __init__ ( self ) :
  self . referral_address = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . priority = 0
  self . weight = 0
  self . updown = True
  self . map_requests_sent = 0
  self . no_responses = 0
  self . uptime = lisp_get_timestamp ( )
  if 48 - 48: IiII / I11i * OoooooooOO
  if 1 - 1: I1ii11iIi11i + I11i
 def print_ref_node ( self , indent ) :
  iII1i1 = lisp_print_elapsed ( self . uptime )
  lprint ( "{}referral {}, uptime {}, {}, priority/weight: {}/{}" . format ( indent , red ( self . referral_address . print_address ( ) , False ) , iII1i1 ,
  # I1Ii111 * IiII * OoO0O00 . I1Ii111
 "up" if self . updown else "down" , self . priority , self . weight ) )
  if 65 - 65: I11i . I11i
  if 39 - 39: I1Ii111
  if 48 - 48: iIii1I11I1II1 . i11iIiiIii / OoooooooOO . i1IIi . o0oOOo0O0Ooo
class lisp_ms ( ) :
 def __init__ ( self , addr_str , dns_name , ms_name , alg_id , key_id , pw , pr ,
 mr , rr , wmn , site_id , ekey_id , ekey ) :
  self . ms_name = ms_name if ( ms_name != None ) else "all"
  self . dns_name = dns_name
  self . map_server = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . last_dns_resolve = None
  if ( lisp_map_servers_list == { } ) :
   self . xtr_id = lisp_get_control_nonce ( )
  else :
   self . xtr_id = lisp_map_servers_list . values ( ) [ 0 ] . xtr_id
   if 84 - 84: Ii1I
  if ( addr_str ) :
   self . map_server . store_address ( addr_str )
   self . insert_ms ( )
  else :
   self . resolve_dns_name ( )
   if 92 - 92: I11i
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
  if 64 - 64: iII111i / iII111i * iII111i % O0 / IiII . I1ii11iIi11i
  if 23 - 23: i1IIi / I1ii11iIi11i + o0oOOo0O0Ooo
 def resolve_dns_name ( self ) :
  if ( self . dns_name == None ) : return
  if ( self . last_dns_resolve and
 time . time ( ) - self . last_dns_resolve < 30 ) : return
  try :
   self . last_dns_resolve = lisp_get_timestamp ( )
   iIiIi1ii = socket . gethostbyname ( self . dns_name )
   if ( iIiIi1ii != self . map_server . print_address_no_iid ( ) ) :
    self . delete_ms ( )
    self . map_server . store_address ( iIiIi1ii )
    self . insert_ms ( )
    if 82 - 82: O0 * ooOoO0o * iIii1I11I1II1 . i1IIi
  except :
   pass
   if 47 - 47: I11i * I11i . OoOoOO00
   if 68 - 68: OoooooooOO + OoOoOO00 + i11iIiiIii
   if 89 - 89: Oo0Ooo + Ii1I * O0 - I1Ii111
 def insert_ms ( self ) :
  i1i11ii1 = self . ms_name + self . map_server . print_address ( )
  lisp_map_servers_list [ i1i11ii1 ] = self
  if 33 - 33: iIii1I11I1II1 . I11i
  if 63 - 63: oO0o - iII111i
 def delete_ms ( self ) :
  i1i11ii1 = self . ms_name + self . map_server . print_address ( )
  if ( lisp_map_servers_list . has_key ( i1i11ii1 ) == False ) : return
  lisp_map_servers_list . pop ( i1i11ii1 )
  if 13 - 13: I1Ii111 / i1IIi % OoooooooOO / I11i
  if 66 - 66: I1Ii111 % o0oOOo0O0Ooo . iII111i . ooOoO0o + OOooOOo * II111iiii
  if 33 - 33: oO0o
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
  if 64 - 64: OoO0O00 % Oo0Ooo % I11i . iII111i % I1IiiI
  if 50 - 50: i1IIi + ooOoO0o - iIii1I11I1II1
 def add_interface ( self ) :
  lisp_myinterfaces [ self . device ] = self
  if 45 - 45: OoooooooOO / o0oOOo0O0Ooo / iII111i
  if 72 - 72: I1Ii111
 def get_instance_id ( self ) :
  return ( self . instance_id )
  if 94 - 94: ooOoO0o . IiII - Ii1I + I1ii11iIi11i / ooOoO0o
  if 10 - 10: ooOoO0o . OOooOOo * O0 % II111iiii
 def get_socket ( self ) :
  return ( self . raw_socket )
  if 12 - 12: oO0o + I1IiiI * Oo0Ooo - iII111i
  if 88 - 88: OOooOOo . OoO0O00
 def get_bridge_socket ( self ) :
  return ( self . bridge_socket )
  if 86 - 86: OoOoOO00 . o0oOOo0O0Ooo / ooOoO0o * I1IiiI . OoO0O00 / I1Ii111
  if 47 - 47: I11i . iII111i * OoOoOO00 % OoooooooOO
 def does_dynamic_eid_match ( self , eid ) :
  return ( eid . is_more_specific ( self . dynamic_eid ) )
  if 59 - 59: OoooooooOO + I1ii11iIi11i - I11i / I1IiiI * oO0o
  if 90 - 90: I1Ii111 + i1IIi * I1Ii111 / I11i * Oo0Ooo
 def set_socket ( self , device ) :
  I11iiIi1i1 = socket . socket ( socket . AF_INET , socket . SOCK_RAW , socket . IPPROTO_RAW )
  I11iiIi1i1 . setsockopt ( socket . SOL_IP , socket . IP_HDRINCL , 1 )
  try :
   I11iiIi1i1 . setsockopt ( socket . SOL_SOCKET , socket . SO_BINDTODEVICE , device )
  except :
   I11iiIi1i1 . close ( )
   I11iiIi1i1 = None
   if 27 - 27: OoooooooOO
  self . raw_socket = I11iiIi1i1
  if 42 - 42: OoO0O00 + OoOoOO00
  if 52 - 52: iII111i * OoOoOO00
 def set_bridge_socket ( self , device ) :
  I11iiIi1i1 = socket . socket ( socket . PF_PACKET , socket . SOCK_RAW )
  try :
   I11iiIi1i1 = I11iiIi1i1 . bind ( ( device , 0 ) )
   self . bridge_socket = I11iiIi1i1
  except :
   return
   if 80 - 80: I1Ii111 / IiII * o0oOOo0O0Ooo - OoOoOO00 / iIii1I11I1II1
   if 38 - 38: II111iiii / I11i + IiII % OoooooooOO
   if 27 - 27: OoOoOO00 * OoO0O00 * OOooOOo % I1IiiI * o0oOOo0O0Ooo + I1ii11iIi11i
   if 73 - 73: i1IIi
class lisp_datetime ( ) :
 def __init__ ( self , datetime_str ) :
  self . datetime_name = datetime_str
  self . datetime = None
  self . parse_datetime ( )
  if 52 - 52: IiII / i11iIiiIii * O0
  if 67 - 67: OOooOOo / I11i - I1Ii111 % i11iIiiIii
 def valid_datetime ( self ) :
  iII1II1 = self . datetime_name
  if ( iII1II1 . find ( ":" ) == - 1 ) : return ( False )
  if ( iII1II1 . find ( "-" ) == - 1 ) : return ( False )
  iII1i111 , O00O0o00o0 , Iii1III1iiiI , time = iII1II1 [ 0 : 4 ] , iII1II1 [ 5 : 7 ] , iII1II1 [ 8 : 10 ] , iII1II1 [ 11 : : ]
  if 36 - 36: iII111i * OoO0O00 / OOooOOo * IiII * iIii1I11I1II1 / IiII
  if ( ( iII1i111 + O00O0o00o0 + Iii1III1iiiI ) . isdigit ( ) == False ) : return ( False )
  if ( O00O0o00o0 < "01" and O00O0o00o0 > "12" ) : return ( False )
  if ( Iii1III1iiiI < "01" and Iii1III1iiiI > "31" ) : return ( False )
  if 79 - 79: iIii1I11I1II1 - iIii1I11I1II1 * I1ii11iIi11i
  O0oo , IIiI1I , Oo0ooO = time . split ( ":" )
  if 92 - 92: o0oOOo0O0Ooo + II111iiii + oO0o / iII111i % OoooooooOO / I1IiiI
  if ( ( O0oo + IIiI1I + Oo0ooO ) . isdigit ( ) == False ) : return ( False )
  if ( O0oo < "00" and O0oo > "23" ) : return ( False )
  if ( IIiI1I < "00" and IIiI1I > "59" ) : return ( False )
  if ( Oo0ooO < "00" and Oo0ooO > "59" ) : return ( False )
  return ( True )
  if 41 - 41: OoOoOO00 * i1IIi
  if 94 - 94: I11i
 def parse_datetime ( self ) :
  i1iiII1111 = self . datetime_name
  i1iiII1111 = i1iiII1111 . replace ( "-" , "" )
  i1iiII1111 = i1iiII1111 . replace ( ":" , "" )
  self . datetime = int ( i1iiII1111 )
  if 64 - 64: I1ii11iIi11i % i11iIiiIii . I1ii11iIi11i . OoOoOO00 . I11i
  if 11 - 11: O0 - OoO0O00 + OoO0O00
 def now ( self ) :
  iII1i1 = datetime . datetime . now ( ) . strftime ( "%Y-%m-%d-%H:%M:%S" )
  iII1i1 = lisp_datetime ( iII1i1 )
  return ( iII1i1 )
  if 24 - 24: i11iIiiIii
  if 27 - 27: OoOoOO00 - OoOoOO00 % II111iiii + i1IIi + I1IiiI
 def print_datetime ( self ) :
  return ( self . datetime_name )
  if 75 - 75: OoooooooOO . I11i - OoOoOO00
  if 93 - 93: OoOoOO00 . I1Ii111 % I1ii11iIi11i
 def future ( self ) :
  return ( self . datetime > self . now ( ) . datetime )
  if 58 - 58: OoooooooOO . i1IIi . Oo0Ooo - o0oOOo0O0Ooo / oO0o * I1Ii111
  if 6 - 6: oO0o - OoO0O00
 def past ( self ) :
  return ( self . future ( ) == False )
  if 44 - 44: Oo0Ooo + I1ii11iIi11i % Oo0Ooo / I11i
  if 57 - 57: Oo0Ooo + Ii1I * OoooooooOO
 def now_in_range ( self , upper ) :
  return ( self . past ( ) and upper . future ( ) )
  if 30 - 30: O0
  if 70 - 70: oO0o
 def this_year ( self ) :
  ooO = str ( self . now ( ) . datetime ) [ 0 : 4 ]
  iII1i1 = str ( self . datetime ) [ 0 : 4 ]
  return ( iII1i1 == ooO )
  if 60 - 60: O0 / OoOoOO00 % i11iIiiIii % II111iiii / OoooooooOO
  if 52 - 52: ooOoO0o
 def this_month ( self ) :
  ooO = str ( self . now ( ) . datetime ) [ 0 : 6 ]
  iII1i1 = str ( self . datetime ) [ 0 : 6 ]
  return ( iII1i1 == ooO )
  if 100 - 100: Oo0Ooo - o0oOOo0O0Ooo + iIii1I11I1II1 / ooOoO0o % iIii1I11I1II1
  if 4 - 4: OoOoOO00 / Oo0Ooo - OoO0O00 . OoOoOO00 / I1Ii111
 def today ( self ) :
  ooO = str ( self . now ( ) . datetime ) [ 0 : 8 ]
  iII1i1 = str ( self . datetime ) [ 0 : 8 ]
  return ( iII1i1 == ooO )
  if 60 - 60: OOooOOo * I1Ii111
  if 17 - 17: iII111i * I11i / iIii1I11I1II1 - II111iiii
  if 97 - 97: II111iiii * o0oOOo0O0Ooo
  if 13 - 13: o0oOOo0O0Ooo . II111iiii
  if 76 - 76: II111iiii + I1Ii111 . OoooooooOO / IiII % i11iIiiIii
  if 87 - 87: Ii1I / OoOoOO00 / OOooOOo
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
  if 11 - 11: o0oOOo0O0Ooo * OoO0O00 . o0oOOo0O0Ooo - I1IiiI / IiII - OOooOOo
  if 19 - 19: i1IIi + IiII . OoO0O00 / O0 - I1Ii111 - Oo0Ooo
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
  if 24 - 24: iII111i + i1IIi
  if 31 - 31: OoOoOO00
 def match_policy_map_request ( self , mr , srloc ) :
  for oOoOo in self . match_clauses :
   Iiiii1III1iIi = oOoOo . source_eid
   iiII1II = mr . source_eid
   if ( Iiiii1III1iIi and iiII1II and iiII1II . is_more_specific ( Iiiii1III1iIi ) == False ) : continue
   if 37 - 37: iIii1I11I1II1 % IiII / i11iIiiIii - oO0o
   Iiiii1III1iIi = oOoOo . dest_eid
   iiII1II = mr . target_eid
   if ( Iiiii1III1iIi and iiII1II and iiII1II . is_more_specific ( Iiiii1III1iIi ) == False ) : continue
   if 43 - 43: II111iiii - OoooooooOO
   Iiiii1III1iIi = oOoOo . source_rloc
   iiII1II = srloc
   if ( Iiiii1III1iIi and iiII1II and iiII1II . is_more_specific ( Iiiii1III1iIi ) == False ) : continue
   i1I1i1i1I1 = oOoOo . datetime_lower
   i1II11 = oOoOo . datetime_upper
   if ( i1I1i1i1I1 and i1II11 and i1I1i1i1I1 . now_in_range ( i1II11 ) == False ) : continue
   return ( True )
   if 29 - 29: Oo0Ooo
  return ( False )
  if 91 - 91: oO0o / OoO0O00 + I1IiiI * iIii1I11I1II1
  if 38 - 38: I11i
 def set_policy_map_reply ( self ) :
  IIiIiIiii11i = ( self . set_rloc_address == None and
 self . set_rloc_record_name == None and self . set_geo_name == None and
 self . set_elp_name == None and self . set_rle_name == None )
  if ( IIiIiIiii11i ) : return ( None )
  if 70 - 70: I1ii11iIi11i % ooOoO0o . o0oOOo0O0Ooo . I1Ii111 + ooOoO0o
  i11iII1Ii1ii111 = lisp_rloc ( )
  if ( self . set_rloc_address ) :
   i11iII1Ii1ii111 . rloc . copy_address ( self . set_rloc_address )
   iIiIi1ii = i11iII1Ii1ii111 . rloc . print_address_no_iid ( )
   lprint ( "Policy set-rloc-address to {}" . format ( iIiIi1ii ) )
   if 92 - 92: i11iIiiIii
  if ( self . set_rloc_record_name ) :
   i11iII1Ii1ii111 . rloc_name = self . set_rloc_record_name
   ii1I11 = blue ( i11iII1Ii1ii111 . rloc_name , False )
   lprint ( "Policy set-rloc-record-name to {}" . format ( ii1I11 ) )
   if 45 - 45: oO0o * O0 % I1ii11iIi11i
  if ( self . set_geo_name ) :
   i11iII1Ii1ii111 . geo_name = self . set_geo_name
   ii1I11 = i11iII1Ii1ii111 . geo_name
   Ii111II = "" if lisp_geo_list . has_key ( ii1I11 ) else "(not configured)"
   if 94 - 94: OoO0O00 * o0oOOo0O0Ooo . o0oOOo0O0Ooo / OoOoOO00 - Ii1I
   lprint ( "Policy set-geo-name '{}' {}" . format ( ii1I11 , Ii111II ) )
   if 61 - 61: iII111i
  if ( self . set_elp_name ) :
   i11iII1Ii1ii111 . elp_name = self . set_elp_name
   ii1I11 = i11iII1Ii1ii111 . elp_name
   Ii111II = "" if lisp_elp_list . has_key ( ii1I11 ) else "(not configured)"
   if 27 - 27: I1ii11iIi11i / ooOoO0o / o0oOOo0O0Ooo
   lprint ( "Policy set-elp-name '{}' {}" . format ( ii1I11 , Ii111II ) )
   if 53 - 53: IiII / I1IiiI / i1IIi
  if ( self . set_rle_name ) :
   i11iII1Ii1ii111 . rle_name = self . set_rle_name
   ii1I11 = i11iII1Ii1ii111 . rle_name
   Ii111II = "" if lisp_rle_list . has_key ( ii1I11 ) else "(not configured)"
   if 49 - 49: i11iIiiIii % I1IiiI % I1Ii111 / I1ii11iIi11i - i11iIiiIii . i1IIi
   lprint ( "Policy set-rle-name '{}' {}" . format ( ii1I11 , Ii111II ) )
   if 84 - 84: i11iIiiIii
  if ( self . set_json_name ) :
   i11iII1Ii1ii111 . json_name = self . set_json_name
   ii1I11 = i11iII1Ii1ii111 . json_name
   Ii111II = "" if lisp_json_list . has_key ( ii1I11 ) else "(not configured)"
   if 92 - 92: o0oOOo0O0Ooo + Oo0Ooo * OoOoOO00 * o0oOOo0O0Ooo
   lprint ( "Policy set-json-name '{}' {}" . format ( ii1I11 , Ii111II ) )
   if 33 - 33: I1IiiI + O0 - I11i
  return ( i11iII1Ii1ii111 )
  if 90 - 90: I1Ii111 * OoooooooOO . iIii1I11I1II1 % OoO0O00 / I11i + iII111i
  if 63 - 63: o0oOOo0O0Ooo . IiII . Oo0Ooo - iIii1I11I1II1 / I1Ii111
 def save_policy ( self ) :
  lisp_policies [ self . policy_name ] = self
  if 66 - 66: ooOoO0o * I1Ii111 - II111iiii
  if 38 - 38: O0 % I1ii11iIi11i + O0
  if 37 - 37: Oo0Ooo / I1IiiI
class lisp_pubsub ( ) :
 def __init__ ( self , itr , port , nonce , ttl , xtr_id ) :
  self . itr = itr
  self . port = port
  self . nonce = nonce
  self . uptime = lisp_get_timestamp ( )
  self . ttl = ttl
  self . xtr_id = xtr_id
  self . map_notify_count = 0
  if 23 - 23: II111iiii / iII111i
  if 55 - 55: i11iIiiIii - Ii1I % OoooooooOO * OoooooooOO
 def add ( self , eid_prefix ) :
  o0O0OOo0oo00 = self . ttl
  I1IiiIiIIi1Ii = eid_prefix . print_prefix ( )
  if ( lisp_pubsub_cache . has_key ( I1IiiIiIIi1Ii ) == False ) :
   lisp_pubsub_cache [ I1IiiIiIIi1Ii ] = { }
   if 92 - 92: iIii1I11I1II1
  oOoo0oO0oOo = lisp_pubsub_cache [ I1IiiIiIIi1Ii ]
  if 47 - 47: Oo0Ooo + Oo0Ooo * ooOoO0o - OoOoOO00 + II111iiii
  Iii1i = "Add"
  if ( oOoo0oO0oOo . has_key ( self . xtr_id ) ) :
   Iii1i = "Replace"
   del ( oOoo0oO0oOo [ self . xtr_id ] )
   if 79 - 79: oO0o * O0
  oOoo0oO0oOo [ self . xtr_id ] = self
  if 71 - 71: IiII - ooOoO0o
  I1IiiIiIIi1Ii = green ( I1IiiIiIIi1Ii , False )
  i1o0oOoooOoo0 = red ( self . itr . print_address_no_iid ( ) , False )
  ooO0O = "0x" + lisp_hex_string ( self . xtr_id )
  lprint ( "{} pubsub state {} for {}, xtr-id: {}, ttl {}" . format ( Iii1i , I1IiiIiIIi1Ii ,
 i1o0oOoooOoo0 , ooO0O , o0O0OOo0oo00 ) )
  if 48 - 48: OOooOOo * OoOoOO00 / oO0o + II111iiii - I1ii11iIi11i
  if 85 - 85: I1ii11iIi11i * OoooooooOO . OOooOOo * OOooOOo
 def delete ( self , eid_prefix ) :
  I1IiiIiIIi1Ii = eid_prefix . print_prefix ( )
  i1o0oOoooOoo0 = red ( self . itr . print_address_no_iid ( ) , False )
  ooO0O = "0x" + lisp_hex_string ( self . xtr_id )
  if ( lisp_pubsub_cache . has_key ( I1IiiIiIIi1Ii ) ) :
   oOoo0oO0oOo = lisp_pubsub_cache [ I1IiiIiIIi1Ii ]
   if ( oOoo0oO0oOo . has_key ( self . xtr_id ) ) :
    oOoo0oO0oOo . pop ( self . xtr_id )
    lprint ( "Remove pubsub state {} for {}, xtr-id: {}" . format ( I1IiiIiIIi1Ii ,
 i1o0oOoooOoo0 , ooO0O ) )
    if 13 - 13: I1IiiI / Ii1I - OoOoOO00 . i1IIi * oO0o * o0oOOo0O0Ooo
    if 5 - 5: I11i - I1Ii111 * I11i - II111iiii + OOooOOo + II111iiii
    if 91 - 91: i1IIi + Oo0Ooo - I1ii11iIi11i + I1ii11iIi11i * O0 / O0
    if 78 - 78: OoooooooOO
    if 8 - 8: Oo0Ooo - Oo0Ooo % O0 - Ii1I / o0oOOo0O0Ooo % Oo0Ooo
    if 51 - 51: iIii1I11I1II1 / iIii1I11I1II1 * I1ii11iIi11i / I11i
    if 18 - 18: Ii1I - i11iIiiIii + OoO0O00 . O0 - iII111i
    if 9 - 9: OoooooooOO / iII111i + o0oOOo0O0Ooo / II111iiii / I1Ii111
    if 44 - 44: I1IiiI / iII111i / Oo0Ooo
    if 66 - 66: I1Ii111 + OoooooooOO % I1IiiI . iII111i * Oo0Ooo + o0oOOo0O0Ooo
    if 96 - 96: OoO0O00 - ooOoO0o * Ii1I
    if 34 - 34: OoO0O00 . Oo0Ooo % Ii1I . IiII + OoOoOO00
    if 10 - 10: OoooooooOO * iII111i * ooOoO0o . Ii1I % I1Ii111 / I1ii11iIi11i
def lisp_get_any_map_server ( ) :
 for iIoO0oOOoOoO in lisp_map_servers_list . values ( ) : return ( iIoO0oOOoOoO )
 return ( None )
 if 71 - 71: Ii1I + IiII
 if 10 - 10: II111iiii % o0oOOo0O0Ooo . o0oOOo0O0Ooo % iII111i
 if 2 - 2: OoooooooOO / IiII % Oo0Ooo % iIii1I11I1II1
 if 62 - 62: oO0o
 if 47 - 47: I1IiiI - O0 - I1ii11iIi11i . OoOoOO00
 if 98 - 98: o0oOOo0O0Ooo - OoO0O00 . I1ii11iIi11i / OOooOOo
 if 43 - 43: I1IiiI + OOooOOo + o0oOOo0O0Ooo
 if 44 - 44: o0oOOo0O0Ooo % OoO0O00 . OoooooooOO
 if 21 - 21: Oo0Ooo * Oo0Ooo - iII111i - O0
 if 87 - 87: OOooOOo / I1Ii111 - Ii1I + O0 - oO0o - O0
def lisp_get_map_resolver ( address , eid ) :
 if ( address != None ) :
  iIiIi1ii = address . print_address ( )
  IiIiiiI11 = None
  for i1i11ii1 in lisp_map_resolvers_list :
   if ( i1i11ii1 . find ( iIiIi1ii ) == - 1 ) : continue
   IiIiiiI11 = lisp_map_resolvers_list [ i1i11ii1 ]
   if 68 - 68: iII111i + II111iiii + I1ii11iIi11i * OOooOOo / oO0o
  return ( IiIiiiI11 )
  if 41 - 41: OOooOOo + Oo0Ooo % I1IiiI
  if 3 - 3: ooOoO0o * Ii1I
  if 29 - 29: OoooooooOO + OOooOOo
  if 68 - 68: O0 + IiII / iII111i - OoOoOO00
  if 5 - 5: I1IiiI * OoooooooOO - II111iiii
  if 64 - 64: i1IIi
  if 77 - 77: OOooOOo - i1IIi / II111iiii . I1Ii111 + O0
 if ( eid == "" ) :
  ii1iIiI111 = ""
 elif ( eid == None ) :
  ii1iIiI111 = "all"
 else :
  Oo00OO0 = lisp_db_for_lookups . lookup_cache ( eid , False )
  ii1iIiI111 = "all" if Oo00OO0 == None else Oo00OO0 . use_mr_name
  if 21 - 21: i11iIiiIii . IiII - OoooooooOO
  if 72 - 72: iII111i
 oOoOo0 = None
 for IiIiiiI11 in lisp_map_resolvers_list . values ( ) :
  if ( ii1iIiI111 == "" ) : return ( IiIiiiI11 )
  if ( IiIiiiI11 . mr_name != ii1iIiI111 ) : continue
  if ( oOoOo0 == None or IiIiiiI11 . last_used < oOoOo0 . last_used ) : oOoOo0 = IiIiiiI11
  if 50 - 50: I1IiiI / Ii1I / Ii1I + O0 % I11i - i1IIi
 return ( oOoOo0 )
 if 72 - 72: II111iiii . OoO0O00 . II111iiii * I1ii11iIi11i
 if 42 - 42: II111iiii
 if 45 - 45: I1ii11iIi11i . I1Ii111 . i1IIi * OOooOOo
 if 53 - 53: Ii1I . i11iIiiIii + o0oOOo0O0Ooo % I11i - I1ii11iIi11i * I1ii11iIi11i
 if 87 - 87: I1Ii111 % i11iIiiIii + O0
 if 67 - 67: OoooooooOO / i1IIi / ooOoO0o . i1IIi - i11iIiiIii . i1IIi
 if 41 - 41: i11iIiiIii / ooOoO0o - Ii1I + I11i
def lisp_ipv4_input ( packet ) :
 if 15 - 15: I1ii11iIi11i
 if 22 - 22: iIii1I11I1II1 - i1IIi - i11iIiiIii / I1IiiI + o0oOOo0O0Ooo
 if 56 - 56: I1IiiI . ooOoO0o
 if 35 - 35: iIii1I11I1II1 % Oo0Ooo + o0oOOo0O0Ooo * o0oOOo0O0Ooo % ooOoO0o
 Oooo0oooo0OoO0o = struct . unpack ( "H" , packet [ 10 : 12 ] ) [ 0 ]
 if ( Oooo0oooo0OoO0o == 0 ) :
  dprint ( "Packet arrived with checksum of 0!" )
 else :
  packet = lisp_ip_checksum ( packet )
  Oooo0oooo0OoO0o = struct . unpack ( "H" , packet [ 10 : 12 ] ) [ 0 ]
  if ( Oooo0oooo0OoO0o != 0 ) :
   dprint ( "IPv4 header checksum failed for inner header" )
   packet = lisp_format_packet ( packet [ 0 : 20 ] )
   dprint ( "Packet header: {}" . format ( packet ) )
   return ( None )
   if 10 - 10: I1ii11iIi11i / II111iiii % II111iiii - OoooooooOO * o0oOOo0O0Ooo / ooOoO0o
   if 26 - 26: OoO0O00 . O0 * iII111i % OoOoOO00 % iIii1I11I1II1
   if 37 - 37: iII111i - ooOoO0o * Ii1I + II111iiii * i11iIiiIii
   if 8 - 8: OoooooooOO % I11i - iII111i * OOooOOo . O0
   if 40 - 40: I1Ii111 . oO0o + OoO0O00 % Oo0Ooo / II111iiii
   if 19 - 19: i11iIiiIii
   if 20 - 20: i11iIiiIii . II111iiii - I1ii11iIi11i / ooOoO0o % i11iIiiIii
 o0O0OOo0oo00 = struct . unpack ( "B" , packet [ 8 : 9 ] ) [ 0 ]
 if ( o0O0OOo0oo00 == 0 ) :
  dprint ( "IPv4 packet arrived with ttl 0, packet discarded" )
  return ( None )
 elif ( o0O0OOo0oo00 == 1 ) :
  dprint ( "IPv4 packet {}, packet discarded" . format ( bold ( "ttl expiry" , False ) ) )
  if 35 - 35: Oo0Ooo - I1ii11iIi11i . Oo0Ooo
  return ( None )
  if 13 - 13: II111iiii / OoOoOO00 * iII111i % O0 % I1ii11iIi11i * i11iIiiIii
  if 92 - 92: i11iIiiIii + OoO0O00
 o0O0OOo0oo00 -= 1
 packet = packet [ 0 : 8 ] + struct . pack ( "B" , o0O0OOo0oo00 ) + packet [ 9 : : ]
 packet = packet [ 0 : 10 ] + struct . pack ( "H" , 0 ) + packet [ 12 : : ]
 packet = lisp_ip_checksum ( packet )
 return ( packet )
 if 94 - 94: I1ii11iIi11i + OoO0O00 . II111iiii + oO0o . II111iiii
 if 96 - 96: i11iIiiIii
 if 66 - 66: ooOoO0o * iII111i - iII111i - O0 . o0oOOo0O0Ooo
 if 23 - 23: iIii1I11I1II1 / I11i % OoOoOO00 . OoO0O00
 if 90 - 90: iIii1I11I1II1 - OOooOOo . Ii1I % OoO0O00
 if 89 - 89: i11iIiiIii
 if 86 - 86: Oo0Ooo % iIii1I11I1II1 . II111iiii / I11i % OoO0O00 % OoO0O00
def lisp_ipv6_input ( packet ) :
 Oo0o0OoOoOo0 = packet . inner_dest
 packet = packet . packet
 if 40 - 40: o0oOOo0O0Ooo . iIii1I11I1II1 * Oo0Ooo * i1IIi
 if 94 - 94: oO0o - II111iiii + OoOoOO00
 if 90 - 90: Oo0Ooo + Oo0Ooo + I1Ii111
 if 81 - 81: i1IIi % iIii1I11I1II1 % Ii1I * ooOoO0o % i1IIi * I1IiiI
 if 15 - 15: ooOoO0o
 o0O0OOo0oo00 = struct . unpack ( "B" , packet [ 7 : 8 ] ) [ 0 ]
 if ( o0O0OOo0oo00 == 0 ) :
  dprint ( "IPv6 packet arrived with hop-limit 0, packet discarded" )
  return ( None )
 elif ( o0O0OOo0oo00 == 1 ) :
  dprint ( "IPv6 packet {}, packet discarded" . format ( bold ( "ttl expiry" , False ) ) )
  if 26 - 26: IiII % ooOoO0o / OOooOOo
  return ( None )
  if 14 - 14: i11iIiiIii . I1ii11iIi11i
  if 20 - 20: O0 . iIii1I11I1II1 * I1ii11iIi11i - O0 + I1ii11iIi11i / I1IiiI
  if 67 - 67: OoO0O00 / OoOoOO00 / i11iIiiIii % OoOoOO00
  if 54 - 54: o0oOOo0O0Ooo . i11iIiiIii + I1IiiI * ooOoO0o - ooOoO0o
  if 28 - 28: I1Ii111 . i11iIiiIii * oO0o % ooOoO0o / iII111i . OOooOOo
 if ( Oo0o0OoOoOo0 . is_ipv6_link_local ( ) ) :
  dprint ( "Do not encapsulate IPv6 link-local packets" )
  return ( None )
  if 57 - 57: OoooooooOO . iIii1I11I1II1 % iII111i % Oo0Ooo
  if 92 - 92: I1Ii111 - Ii1I + I1Ii111
 o0O0OOo0oo00 -= 1
 packet = packet [ 0 : 7 ] + struct . pack ( "B" , o0O0OOo0oo00 ) + packet [ 8 : : ]
 return ( packet )
 if 8 - 8: Oo0Ooo . iII111i / i11iIiiIii + iIii1I11I1II1 - OoOoOO00
 if 1 - 1: i11iIiiIii
 if 25 - 25: OoooooooOO / II111iiii . OOooOOo * OoOoOO00 - OoooooooOO
 if 8 - 8: iII111i . iIii1I11I1II1 * O0
 if 87 - 87: OoO0O00 * OoooooooOO + OoOoOO00 . OoooooooOO + o0oOOo0O0Ooo + Ii1I
 if 26 - 26: i1IIi
 if 33 - 33: OoOoOO00 + OOooOOo . i1IIi . IiII
 if 78 - 78: OoooooooOO * I11i / OOooOOo + oO0o . I1Ii111 * iII111i
def lisp_mac_input ( packet ) :
 return ( packet )
 if 98 - 98: i1IIi
 if 28 - 28: Oo0Ooo . I1Ii111 . iIii1I11I1II1 + I1IiiI . II111iiii * I1ii11iIi11i
 if 26 - 26: i1IIi / i11iIiiIii * II111iiii
 if 11 - 11: Oo0Ooo % i1IIi
 if 70 - 70: II111iiii * Oo0Ooo * OOooOOo - I1IiiI + iIii1I11I1II1 + ooOoO0o
 if 27 - 27: I1ii11iIi11i - I1Ii111 * O0 % ooOoO0o / I1IiiI
 if 53 - 53: i11iIiiIii * i11iIiiIii % O0 % IiII
 if 57 - 57: I1IiiI % i1IIi * OoO0O00 + I1Ii111 . I11i % I11i
 if 69 - 69: I1ii11iIi11i / OoOoOO00 + iIii1I11I1II1
def lisp_rate_limit_map_request ( source , dest ) :
 if ( lisp_last_map_request_sent == None ) : return ( False )
 ooO = lisp_get_timestamp ( )
 oO000o = ooO - lisp_last_map_request_sent
 i1I1IiIi111I = ( oO000o < LISP_MAP_REQUEST_RATE_LIMIT )
 if 52 - 52: Oo0Ooo * iII111i - O0 . OoOoOO00 - I1IiiI
 if ( i1I1IiIi111I ) :
  if ( source != None ) : source = source . print_address ( )
  dest = dest . print_address ( )
  dprint ( "Rate-limiting Map-Request for {} -> {}" . format ( source , dest ) )
  if 47 - 47: II111iiii
 return ( i1I1IiIi111I )
 if 8 - 8: ooOoO0o + OoooooooOO
 if 85 - 85: I11i / i1IIi * i11iIiiIii / I1IiiI - Ii1I
 if 25 - 25: iII111i - Oo0Ooo % iIii1I11I1II1 + o0oOOo0O0Ooo + iIii1I11I1II1
 if 63 - 63: OoOoOO00 - o0oOOo0O0Ooo % II111iiii - Ii1I
 if 81 - 81: iII111i % OOooOOo * oO0o
 if 84 - 84: iII111i - OoooooooOO + I1ii11iIi11i - I1IiiI
 if 52 - 52: oO0o / ooOoO0o / iII111i / OoOoOO00 * iIii1I11I1II1
def lisp_send_map_request ( lisp_sockets , lisp_ephem_port , seid , deid , rloc ) :
 global lisp_last_map_request_sent
 if 74 - 74: oO0o . I1ii11iIi11i - iIii1I11I1II1
 if 73 - 73: OoO0O00 / O0 . o0oOOo0O0Ooo
 if 100 - 100: Ii1I . OoO0O00 % I1ii11iIi11i % O0 * Oo0Ooo - OoOoOO00
 if 15 - 15: OOooOOo - OOooOOo - OoooooooOO * OoO0O00
 if 12 - 12: II111iiii * I1Ii111 / I1Ii111 * oO0o * Oo0Ooo
 if 17 - 17: OoOoOO00 % I1Ii111 / iII111i * I1Ii111
 OOoO0Oooo0 = Oo0I1i = None
 if ( rloc ) :
  OOoO0Oooo0 = rloc . rloc
  Oo0I1i = rloc . translated_port if lisp_i_am_rtr else LISP_DATA_PORT
  if 86 - 86: i1IIi . oO0o % OOooOOo
  if 99 - 99: oO0o / I1Ii111 * oO0o * I11i
  if 38 - 38: o0oOOo0O0Ooo + OoOoOO00
  if 24 - 24: Ii1I - OOooOOo - o0oOOo0O0Ooo - I1Ii111 / OoooooooOO
  if 17 - 17: OoO0O00
 o0oOooooo , IIi11iII1I , O0o0o0 = lisp_myrlocs
 if ( o0oOooooo == None ) :
  lprint ( "Suppress sending Map-Request, IPv4 RLOC not found" )
  return
  if 45 - 45: IiII + i1IIi
 if ( IIi11iII1I == None and OOoO0Oooo0 != None and OOoO0Oooo0 . is_ipv6 ( ) ) :
  lprint ( "Suppress sending Map-Request, IPv6 RLOC not found" )
  return
  if 3 - 3: iIii1I11I1II1 % oO0o . oO0o + IiII
  if 36 - 36: OoOoOO00 * iIii1I11I1II1 + oO0o * IiII . IiII . OOooOOo
 OOOo = lisp_map_request ( )
 OOOo . record_count = 1
 OOOo . nonce = lisp_get_control_nonce ( )
 OOOo . rloc_probe = ( OOoO0Oooo0 != None )
 if 64 - 64: I1ii11iIi11i / OoOoOO00 + O0 % i1IIi - ooOoO0o + o0oOOo0O0Ooo
 if 67 - 67: Oo0Ooo
 if 52 - 52: I1IiiI % I1Ii111 - i1IIi . o0oOOo0O0Ooo % I1ii11iIi11i
 if 34 - 34: o0oOOo0O0Ooo / OoOoOO00
 if 74 - 74: IiII + i1IIi . II111iiii
 if 1 - 1: Ii1I - o0oOOo0O0Ooo / i11iIiiIii
 if 24 - 24: O0
 if ( rloc ) : rloc . last_rloc_probe_nonce = OOOo . nonce
 if 59 - 59: OoO0O00 % iII111i + oO0o * II111iiii . OOooOOo
 oooOoooo0Ooo0ooo0 = deid . is_multicast_address ( )
 if ( oooOoooo0Ooo0ooo0 ) :
  OOOo . target_eid = seid
  OOOo . target_group = deid
 else :
  OOOo . target_eid = deid
  if 26 - 26: OOooOOo % OoooooooOO . Ii1I / iIii1I11I1II1 * I1IiiI
  if 85 - 85: IiII / Ii1I - I1ii11iIi11i * OOooOOo
  if 19 - 19: I1ii11iIi11i
  if 12 - 12: ooOoO0o * I1ii11iIi11i * O0 / oO0o + iII111i - iIii1I11I1II1
  if 81 - 81: Ii1I
  if 87 - 87: O0 % iII111i
  if 57 - 57: Ii1I
  if 49 - 49: I11i
  if 22 - 22: Oo0Ooo % OOooOOo + O0 - OoO0O00 % I11i * O0
 if ( OOOo . rloc_probe == False ) :
  Oo00OO0 = lisp_get_signature_eid ( )
  if ( Oo00OO0 ) :
   OOOo . signature_eid . copy_address ( Oo00OO0 . eid )
   OOOo . privkey_filename = "./lisp-sig.pem"
   if 42 - 42: O0
   if 55 - 55: i11iIiiIii % OOooOOo
   if 10 - 10: OoOoOO00 / i11iIiiIii
   if 21 - 21: Ii1I - i1IIi / I11i + IiII
   if 44 - 44: OoooooooOO % I11i / O0
   if 94 - 94: IiII
 if ( seid == None or oooOoooo0Ooo0ooo0 ) :
  OOOo . source_eid . afi = LISP_AFI_NONE
 else :
  OOOo . source_eid = seid
  if 83 - 83: OoO0O00
  if 55 - 55: iII111i
  if 37 - 37: oO0o / o0oOOo0O0Ooo + I11i * OoO0O00 * o0oOOo0O0Ooo
  if 33 - 33: I1Ii111
  if 97 - 97: Ii1I / iII111i - ooOoO0o + IiII * OoOoOO00 - OOooOOo
  if 43 - 43: oO0o / II111iiii - iII111i / oO0o
  if 98 - 98: OoOoOO00 / OOooOOo
  if 31 - 31: II111iiii % I11i - I11i
  if 17 - 17: iII111i . IiII + OOooOOo % I1Ii111 % i11iIiiIii
  if 100 - 100: i11iIiiIii - O0 . OoO0O00 / O0 - Ii1I - IiII
  if 72 - 72: Ii1I % O0 + II111iiii . i11iIiiIii
  if 66 - 66: II111iiii % I1IiiI
 if ( OOoO0Oooo0 != None and lisp_nat_traversal and lisp_i_am_rtr == False ) :
  if ( OOoO0Oooo0 . is_private_address ( ) == False ) :
   o0oOooooo = lisp_get_any_translated_rloc ( )
   if 88 - 88: iIii1I11I1II1 * iIii1I11I1II1 + I1Ii111 * OOooOOo . I1IiiI
  if ( o0oOooooo == None ) :
   lprint ( "Suppress sending Map-Request, translated RLOC not found" )
   return
   if 96 - 96: I1ii11iIi11i
   if 37 - 37: OoO0O00 % o0oOOo0O0Ooo * O0 * O0 + iII111i
   if 18 - 18: i11iIiiIii . o0oOOo0O0Ooo - OOooOOo % oO0o * Ii1I / I1IiiI
   if 46 - 46: o0oOOo0O0Ooo . ooOoO0o / Ii1I
   if 97 - 97: Ii1I . Oo0Ooo - O0 - I1Ii111 . i1IIi
   if 47 - 47: IiII * ooOoO0o - i1IIi % OoOoOO00 * i11iIiiIii . OoooooooOO
   if 84 - 84: OoOoOO00 / IiII - i1IIi - I1IiiI * OOooOOo
   if 35 - 35: II111iiii
 if ( OOoO0Oooo0 == None or OOoO0Oooo0 . is_ipv4 ( ) ) :
  if ( lisp_nat_traversal and OOoO0Oooo0 == None ) :
   I1I1iI1 = lisp_get_any_translated_rloc ( )
   if ( I1I1iI1 != None ) : o0oOooooo = I1I1iI1
   if 82 - 82: ooOoO0o - ooOoO0o . Ii1I . i11iIiiIii % Ii1I + OOooOOo
  OOOo . itr_rlocs . append ( o0oOooooo )
  if 33 - 33: Oo0Ooo - OOooOOo / OoOoOO00 % II111iiii % OOooOOo + I1Ii111
 if ( OOoO0Oooo0 == None or OOoO0Oooo0 . is_ipv6 ( ) ) :
  if ( IIi11iII1I == None or IIi11iII1I . is_ipv6_link_local ( ) ) :
   IIi11iII1I = None
  else :
   OOOo . itr_rloc_count = 1 if ( OOoO0Oooo0 == None ) else 0
   OOOo . itr_rlocs . append ( IIi11iII1I )
   if 41 - 41: I11i + Oo0Ooo . Oo0Ooo / iII111i . OoOoOO00
   if 1 - 1: ooOoO0o + iII111i % i11iIiiIii / OoOoOO00
   if 98 - 98: IiII
   if 75 - 75: OoooooooOO % IiII + Ii1I - i1IIi / OoooooooOO
   if 57 - 57: iII111i
   if 18 - 18: II111iiii % i11iIiiIii + I11i - OOooOOo
   if 100 - 100: o0oOOo0O0Ooo / Ii1I - iIii1I11I1II1 / oO0o
   if 68 - 68: I11i / II111iiii * oO0o . II111iiii * OOooOOo
   if 78 - 78: I11i * OoO0O00 / II111iiii
 if ( OOoO0Oooo0 != None and OOOo . itr_rlocs != [ ] ) :
  OOO0OO = OOOo . itr_rlocs [ 0 ]
 else :
  if ( deid . is_ipv4 ( ) ) :
   OOO0OO = o0oOooooo
  elif ( deid . is_ipv6 ( ) ) :
   OOO0OO = IIi11iII1I
  else :
   OOO0OO = o0oOooooo
   if 86 - 86: I1Ii111 % II111iiii
   if 90 - 90: OoO0O00 / I11i - Oo0Ooo
   if 76 - 76: O0 + OoO0O00 / ooOoO0o . II111iiii * iIii1I11I1II1 . I1Ii111
   if 43 - 43: Oo0Ooo + o0oOOo0O0Ooo % o0oOOo0O0Ooo % I1ii11iIi11i / iIii1I11I1II1 . I1ii11iIi11i
   if 59 - 59: IiII . OoO0O00 - OoooooooOO . O0
   if 33 - 33: Ii1I
 I1i1iI = OOOo . encode ( OOoO0Oooo0 , Oo0I1i )
 OOOo . print_map_request ( )
 if 95 - 95: OoooooooOO + OoO0O00 * ooOoO0o
 if 40 - 40: I1IiiI / OOooOOo * Ii1I
 if 98 - 98: I1IiiI
 if 4 - 4: I1IiiI % O0 / Oo0Ooo / O0
 if 90 - 90: ooOoO0o - O0 . IiII - O0 . iIii1I11I1II1
 if 42 - 42: I1ii11iIi11i
 if ( OOoO0Oooo0 != None ) :
  if ( rloc . is_rloc_translated ( ) ) :
   iIiiiIi = lisp_get_nat_info ( OOoO0Oooo0 , rloc . rloc_name )
   if ( iIiiiIi and len ( lisp_sockets ) == 4 ) :
    lisp_encapsulate_rloc_probe ( lisp_sockets , OOoO0Oooo0 ,
 iIiiiIi , I1i1iI )
    return
    if 51 - 51: iII111i % i11iIiiIii . OoO0O00 . IiII - OoOoOO00 * i1IIi
    if 14 - 14: I1ii11iIi11i . OoO0O00
    if 26 - 26: iII111i / ooOoO0o / Oo0Ooo / Oo0Ooo . I1ii11iIi11i * OOooOOo
  oO00o = OOoO0Oooo0 . print_address_no_iid ( )
  Oo0o0OoOoOo0 = lisp_convert_4to6 ( oO00o )
  lisp_send ( lisp_sockets , Oo0o0OoOoOo0 , LISP_CTRL_PORT , I1i1iI )
  return
  if 25 - 25: IiII % I1IiiI / O0 % OOooOOo - OoooooooOO
  if 29 - 29: O0 + iII111i
  if 4 - 4: I11i * I11i - Ii1I * oO0o . I1ii11iIi11i % o0oOOo0O0Ooo
  if 33 - 33: Ii1I * i11iIiiIii / O0 . Oo0Ooo + i1IIi . OoOoOO00
  if 76 - 76: OoooooooOO - O0
  if 17 - 17: Oo0Ooo % I1Ii111 . oO0o - O0
 if ( lisp_i_am_rtr ) :
  IiIiiiI11 = lisp_get_map_resolver ( None , None )
 else :
  IiIiiiI11 = lisp_get_map_resolver ( None , seid )
  if 32 - 32: O0 % O0
 if ( IiIiiiI11 == None ) :
  lprint ( "Cannot find Map-Resolver for source-EID {}" . format ( green ( seid . print_address ( ) , False ) ) )
  if 66 - 66: iII111i / i1IIi - Oo0Ooo . Ii1I
  return
  if 65 - 65: I1ii11iIi11i % ooOoO0o - OoOoOO00 + ooOoO0o + Oo0Ooo
 IiIiiiI11 . last_used = lisp_get_timestamp ( )
 IiIiiiI11 . map_requests_sent += 1
 if ( IiIiiiI11 . last_nonce == 0 ) : IiIiiiI11 . last_nonce = OOOo . nonce
 if 95 - 95: I1Ii111 * i11iIiiIii - I1IiiI - OoOoOO00 . ooOoO0o
 if 34 - 34: OoooooooOO % I1ii11iIi11i + OoooooooOO % i11iIiiIii / IiII - ooOoO0o
 if 74 - 74: iIii1I11I1II1 % II111iiii + IiII
 if 71 - 71: I1IiiI / O0 * i1IIi . i1IIi + Oo0Ooo
 if ( seid == None ) : seid = OOO0OO
 lisp_send_ecm ( lisp_sockets , I1i1iI , seid , lisp_ephem_port , deid ,
 IiIiiiI11 . map_resolver )
 if 32 - 32: i1IIi * I1Ii111 % I1IiiI / IiII . I1Ii111
 if 11 - 11: OOooOOo
 if 25 - 25: i1IIi
 if 99 - 99: OOooOOo + OoooooooOO . I1Ii111 * Oo0Ooo % oO0o
 lisp_last_map_request_sent = lisp_get_timestamp ( )
 if 75 - 75: iII111i
 if 8 - 8: I1ii11iIi11i . I11i / I1ii11iIi11i - i1IIi
 if 22 - 22: OOooOOo
 if 7 - 7: O0 - I1ii11iIi11i - OoO0O00 * I1Ii111
 IiIiiiI11 . resolve_dns_name ( )
 return
 if 17 - 17: o0oOOo0O0Ooo % OoO0O00 - I11i * o0oOOo0O0Ooo - i1IIi / I1IiiI
 if 100 - 100: OoO0O00 * i1IIi * o0oOOo0O0Ooo * Oo0Ooo - o0oOOo0O0Ooo
 if 100 - 100: iII111i - i11iIiiIii + OoO0O00
 if 50 - 50: II111iiii
 if 42 - 42: OOooOOo * I1Ii111
 if 53 - 53: II111iiii % OOooOOo / I1ii11iIi11i * OoOoOO00 % I1ii11iIi11i * iII111i
 if 91 - 91: iII111i . OoooooooOO
 if 90 - 90: i11iIiiIii - I1IiiI
def lisp_send_info_request ( lisp_sockets , dest , port , device_name ) :
 if 39 - 39: iII111i % OoooooooOO % Ii1I % I1IiiI
 if 63 - 63: OoO0O00 - I1Ii111 - II111iiii
 if 79 - 79: II111iiii - II111iiii + OoOoOO00 / iII111i % OoooooooOO - OoO0O00
 if 22 - 22: o0oOOo0O0Ooo + I1Ii111 . Oo0Ooo
 Oo0oOO = lisp_info ( )
 Oo0oOO . nonce = lisp_get_control_nonce ( )
 if ( device_name ) : Oo0oOO . hostname += "-" + device_name
 if 67 - 67: OOooOOo . I11i % i11iIiiIii + iIii1I11I1II1 . i11iIiiIii / OoooooooOO
 oO00o = dest . print_address_no_iid ( )
 if 66 - 66: iII111i + i11iIiiIii - o0oOOo0O0Ooo * OoooooooOO * IiII
 if 59 - 59: I1ii11iIi11i + i1IIi / I11i . iII111i - II111iiii
 if 66 - 66: Ii1I + OoOoOO00 - I11i / o0oOOo0O0Ooo + iIii1I11I1II1
 if 66 - 66: OOooOOo - I1Ii111 - OoOoOO00 - i1IIi * Ii1I
 if 23 - 23: IiII - OoOoOO00 . OoO0O00
 if 81 - 81: I1Ii111 / I1ii11iIi11i
 if 69 - 69: I1IiiI
 if 79 - 79: ooOoO0o
 if 83 - 83: I1Ii111 % II111iiii
 if 89 - 89: Ii1I . I11i
 if 98 - 98: I1Ii111 / O0 % ooOoO0o
 if 36 - 36: iIii1I11I1II1 . iII111i * I1IiiI . I1IiiI - IiII
 if 39 - 39: O0 / ooOoO0o + I11i - OoOoOO00 * o0oOOo0O0Ooo - OoO0O00
 if 97 - 97: i11iIiiIii / O0 % OoO0O00
 if 88 - 88: i1IIi . I1IiiI
 if 8 - 8: I1ii11iIi11i . OoO0O00 % o0oOOo0O0Ooo / O0
 OO00000 = False
 if ( device_name ) :
  OOoOooOOO0 = lisp_get_host_route_next_hop ( oO00o )
  if 54 - 54: oO0o - I1IiiI % ooOoO0o / II111iiii * OoOoOO00
  if 32 - 32: OoooooooOO % OOooOOo / I1Ii111 + OOooOOo . iII111i
  if 54 - 54: OoooooooOO . iIii1I11I1II1 + iIii1I11I1II1
  if 11 - 11: Ii1I * OoO0O00 % I1ii11iIi11i
  if 60 - 60: i11iIiiIii % II111iiii % I11i
  if 92 - 92: O0 * OoooooooOO + I1ii11iIi11i / IiII
  if 97 - 97: o0oOOo0O0Ooo . Ii1I + I1Ii111
  if 72 - 72: i11iIiiIii . iII111i . Ii1I * I1ii11iIi11i
  if 49 - 49: OoOoOO00 - O0 % I11i - ooOoO0o * OOooOOo
  if ( port == LISP_CTRL_PORT and OOoOooOOO0 != None ) :
   while ( True ) :
    time . sleep ( .01 )
    OOoOooOOO0 = lisp_get_host_route_next_hop ( oO00o )
    if ( OOoOooOOO0 == None ) : break
    if 58 - 58: OoooooooOO - OOooOOo * oO0o / Ii1I . IiII
    if 50 - 50: IiII . OOooOOo + I1ii11iIi11i - OoooooooOO
    if 2 - 2: o0oOOo0O0Ooo % ooOoO0o / O0 / i11iIiiIii
  ooOoO0o0O0O0 = lisp_get_default_route_next_hops ( )
  for O0o0o0 , I1iiiI1I1i in ooOoO0o0O0O0 :
   if ( O0o0o0 != device_name ) : continue
   if 93 - 93: I11i * iIii1I11I1II1 * oO0o
   if 74 - 74: I1IiiI
   if 39 - 39: iII111i * IiII / iII111i * IiII % I1ii11iIi11i
   if 27 - 27: iIii1I11I1II1 . ooOoO0o
   if 74 - 74: i1IIi % OoOoOO00
   if 98 - 98: IiII * OOooOOo / O0 - I1Ii111 . I1Ii111 + OOooOOo
   if ( OOoOooOOO0 != I1iiiI1I1i ) :
    if ( OOoOooOOO0 != None ) :
     lisp_install_host_route ( oO00o , OOoOooOOO0 , False )
     if 61 - 61: iII111i * Ii1I % Ii1I + I1IiiI
    lisp_install_host_route ( oO00o , I1iiiI1I1i , True )
    OO00000 = True
    if 23 - 23: oO0o + I1Ii111 / OoooooooOO / O0 + IiII
   break
   if 80 - 80: i11iIiiIii - OoooooooOO + II111iiii / i1IIi - oO0o
   if 100 - 100: Ii1I
   if 73 - 73: IiII - O0
   if 54 - 54: OOooOOo
   if 28 - 28: i1IIi - Oo0Ooo * OoO0O00 + OoooooooOO - Ii1I * i11iIiiIii
   if 71 - 71: iII111i - OOooOOo / iIii1I11I1II1 % i11iIiiIii
 I1i1iI = Oo0oOO . encode ( )
 Oo0oOO . print_info ( )
 if 39 - 39: o0oOOo0O0Ooo
 if 32 - 32: iIii1I11I1II1 . II111iiii / IiII % O0 / iII111i
 if 97 - 97: iIii1I11I1II1
 if 18 - 18: OOooOOo
 Ooooo000 = "(for control)" if port == LISP_CTRL_PORT else "(for data)"
 Ooooo000 = bold ( Ooooo000 , False )
 Iiiii1III1iIi = bold ( "{}" . format ( port ) , False )
 I11IIIiIi11 = red ( oO00o , False )
 iiiii11 = "RTR " if port == LISP_DATA_PORT else "MS "
 lprint ( "Send Info-Request to {}{}, port {} {}" . format ( iiiii11 , I11IIIiIi11 , Iiiii1III1iIi , Ooooo000 ) )
 if 13 - 13: iIii1I11I1II1 - I1IiiI % o0oOOo0O0Ooo * iIii1I11I1II1
 if 99 - 99: OoooooooOO / II111iiii . I1Ii111
 if 62 - 62: OOooOOo . iII111i . I1ii11iIi11i
 if 23 - 23: O0
 if 33 - 33: ooOoO0o - iII111i % IiII
 if 67 - 67: II111iiii
 if ( port == LISP_CTRL_PORT ) :
  lisp_send ( lisp_sockets , dest , LISP_CTRL_PORT , I1i1iI )
 else :
  oo = lisp_data_header ( )
  oo . instance_id ( 0xffffff )
  oo = oo . encode ( )
  if ( oo ) :
   I1i1iI = oo + I1i1iI
   if 66 - 66: iIii1I11I1II1 / OOooOOo
   if 65 - 65: IiII . oO0o + O0 - i11iIiiIii + iIii1I11I1II1
   if 82 - 82: iIii1I11I1II1 * iII111i + iIii1I11I1II1 / OoO0O00 + O0
   if 67 - 67: I1Ii111
   if 94 - 94: I1Ii111 % iIii1I11I1II1 - II111iiii . ooOoO0o + i11iIiiIii - i11iIiiIii
   if 55 - 55: OoooooooOO % iIii1I11I1II1 % I1ii11iIi11i % i1IIi
   if 46 - 46: I11i - ooOoO0o . I1IiiI
   if 36 - 36: I11i + OoO0O00 * O0 * OoOoOO00 * iII111i
   if 90 - 90: i11iIiiIii / i1IIi
   lisp_send ( lisp_sockets , dest , LISP_DATA_PORT , I1i1iI )
   if 35 - 35: Ii1I . I11i / oO0o / OoOoOO00
   if 5 - 5: I1ii11iIi11i . o0oOOo0O0Ooo * iII111i * I1ii11iIi11i % I1Ii111
   if 83 - 83: iIii1I11I1II1 * o0oOOo0O0Ooo % i11iIiiIii + OoO0O00 . O0
   if 87 - 87: II111iiii - iIii1I11I1II1 % I11i % I1IiiI . o0oOOo0O0Ooo
   if 52 - 52: i11iIiiIii . oO0o / OoooooooOO - OoO0O00
   if 7 - 7: I1IiiI * I1IiiI % OOooOOo % iIii1I11I1II1 * OoO0O00 . o0oOOo0O0Ooo
   if 32 - 32: ooOoO0o / i1IIi
 if ( OO00000 ) :
  lisp_install_host_route ( oO00o , None , False )
  if ( OOoOooOOO0 != None ) : lisp_install_host_route ( oO00o , OOoOooOOO0 , True )
  if 55 - 55: oO0o . OoOoOO00 + OoooooooOO - ooOoO0o . OoooooooOO
 return
 if 77 - 77: I1IiiI
 if 16 - 16: I1IiiI + ooOoO0o - O0 / o0oOOo0O0Ooo
 if 36 - 36: Oo0Ooo - OoOoOO00 - II111iiii
 if 25 - 25: i11iIiiIii + II111iiii * OOooOOo % OOooOOo
 if 87 - 87: I11i % Ii1I % Oo0Ooo . II111iiii / oO0o
 if 19 - 19: O0 . OOooOOo + I1Ii111 * I1ii11iIi11i
 if 91 - 91: o0oOOo0O0Ooo / oO0o . o0oOOo0O0Ooo + IiII + ooOoO0o . I1Ii111
def lisp_process_info_request ( lisp_sockets , packet , addr_str , sport , rtr_list ) :
 if 90 - 90: i1IIi + oO0o * oO0o / ooOoO0o . IiII
 if 98 - 98: I11i % OoO0O00 . iII111i - o0oOOo0O0Ooo
 if 92 - 92: I11i
 if 34 - 34: I1IiiI % iIii1I11I1II1 . I1ii11iIi11i * Oo0Ooo * iIii1I11I1II1 / O0
 Oo0oOO = lisp_info ( )
 packet = Oo0oOO . decode ( packet )
 if ( packet == None ) : return
 Oo0oOO . print_info ( )
 if 98 - 98: iII111i % IiII + OoO0O00
 if 23 - 23: OOooOOo
 if 83 - 83: I1ii11iIi11i / O0 * II111iiii + IiII + Oo0Ooo
 if 99 - 99: II111iiii + O0
 if 94 - 94: ooOoO0o * ooOoO0o + o0oOOo0O0Ooo . iII111i % iIii1I11I1II1 + Ii1I
 Oo0oOO . info_reply = True
 Oo0oOO . global_etr_rloc . store_address ( addr_str )
 Oo0oOO . etr_port = sport
 if 88 - 88: Oo0Ooo . iII111i
 if 89 - 89: OOooOOo + I1Ii111 % i11iIiiIii + Oo0Ooo / Oo0Ooo + OoO0O00
 if 9 - 9: OoOoOO00 % i1IIi + IiII
 if 19 - 19: I1Ii111 - II111iiii / I1Ii111 + I1IiiI - OoooooooOO + o0oOOo0O0Ooo
 if 100 - 100: OoO0O00 / OoOoOO00 / OOooOOo / OoO0O00
 Oo0oOO . private_etr_rloc . afi = LISP_AFI_NAME
 Oo0oOO . private_etr_rloc . store_address ( Oo0oOO . hostname )
 if 95 - 95: ooOoO0o
 if ( rtr_list != None ) : Oo0oOO . rtr_list = rtr_list
 packet = Oo0oOO . encode ( )
 Oo0oOO . print_info ( )
 if 95 - 95: Ii1I + i1IIi . I1IiiI % I1Ii111 / Ii1I * O0
 if 68 - 68: I1Ii111 - IiII - oO0o - Oo0Ooo - o0oOOo0O0Ooo
 if 32 - 32: OoOoOO00 % i11iIiiIii
 if 53 - 53: I1Ii111 * Ii1I / IiII . i1IIi * II111iiii / o0oOOo0O0Ooo
 if 44 - 44: I1Ii111 + ooOoO0o
 lprint ( "Send Info-Reply to {}" . format ( red ( addr_str , False ) ) )
 Oo0o0OoOoOo0 = lisp_convert_4to6 ( addr_str )
 lisp_send ( lisp_sockets , Oo0o0OoOoOo0 , sport , packet )
 if 15 - 15: I11i + OoO0O00 + OoOoOO00
 if 100 - 100: I1Ii111
 if 78 - 78: OoOoOO00
 if 16 - 16: I1Ii111 % OoO0O00 - OoO0O00 % OoOoOO00 * OoO0O00
 if 36 - 36: OoOoOO00 * II111iiii . OoooooooOO * I11i . I11i
 iIi11i1IiII1 = lisp_info_source ( Oo0oOO . hostname , addr_str , sport )
 iIi11i1IiII1 . cache_address_for_info_source ( )
 return
 if 43 - 43: O0 - I1ii11iIi11i
 if 91 - 91: o0oOOo0O0Ooo - I1ii11iIi11i . i1IIi
 if 64 - 64: ooOoO0o
 if 23 - 23: Oo0Ooo . OoO0O00
 if 49 - 49: oO0o % i11iIiiIii * Ii1I
 if 9 - 9: Oo0Ooo - OoO0O00 + ooOoO0o / o0oOOo0O0Ooo
 if 61 - 61: O0 - i11iIiiIii * o0oOOo0O0Ooo
 if 92 - 92: Oo0Ooo + OOooOOo - i11iIiiIii
def lisp_get_signature_eid ( ) :
 for Oo00OO0 in lisp_db_list :
  if ( Oo00OO0 . signature_eid ) : return ( Oo00OO0 )
  if 26 - 26: O0 % Oo0Ooo + ooOoO0o - Ii1I . Oo0Ooo
 return ( None )
 if 33 - 33: I1Ii111 / iII111i . I1Ii111 % II111iiii
 if 52 - 52: I1ii11iIi11i
 if 1 - 1: II111iiii + I1ii11iIi11i * OoOoOO00 % ooOoO0o - iII111i % OoooooooOO
 if 77 - 77: iII111i + o0oOOo0O0Ooo
 if 60 - 60: I1ii11iIi11i
 if 23 - 23: iII111i % I1IiiI % I1Ii111 * oO0o * I1IiiI
 if 74 - 74: O0 / I11i . Oo0Ooo / I11i % OoO0O00 % o0oOOo0O0Ooo
 if 83 - 83: OoO0O00 - i11iIiiIii + iIii1I11I1II1
def lisp_get_any_translated_port ( ) :
 for Oo00OO0 in lisp_db_list :
  for iiI1iI1 in Oo00OO0 . rloc_set :
   if ( iiI1iI1 . translated_rloc . is_null ( ) ) : continue
   return ( iiI1iI1 . translated_port )
   if 52 - 52: OoooooooOO
   if 44 - 44: O0 / OoooooooOO + ooOoO0o * I1ii11iIi11i
 return ( None )
 if 36 - 36: I1ii11iIi11i / OoO0O00 - oO0o % O0
 if 12 - 12: i1IIi * ooOoO0o / oO0o + I1IiiI / OoooooooOO
 if 86 - 86: Oo0Ooo / OoO0O00
 if 78 - 78: I1IiiI * I1IiiI
 if 13 - 13: oO0o
 if 43 - 43: oO0o / Ii1I % OOooOOo
 if 45 - 45: II111iiii
 if 41 - 41: Ii1I / OOooOOo * Oo0Ooo . O0 - i11iIiiIii
 if 77 - 77: o0oOOo0O0Ooo + I1IiiI + I1Ii111 / I1ii11iIi11i * i1IIi
def lisp_get_any_translated_rloc ( ) :
 for Oo00OO0 in lisp_db_list :
  for iiI1iI1 in Oo00OO0 . rloc_set :
   if ( iiI1iI1 . translated_rloc . is_null ( ) ) : continue
   return ( iiI1iI1 . translated_rloc )
   if 37 - 37: O0 + iIii1I11I1II1 % IiII * oO0o
   if 43 - 43: OOooOOo . O0
 return ( None )
 if 76 - 76: OOooOOo * OoooooooOO / IiII . OoO0O00 + II111iiii
 if 23 - 23: OoO0O00 - OoooooooOO * I11i . iIii1I11I1II1 / o0oOOo0O0Ooo + oO0o
 if 74 - 74: II111iiii / I1IiiI * O0 * OoO0O00 . I11i
 if 74 - 74: O0 . i1IIi / I1ii11iIi11i + o0oOOo0O0Ooo
 if 24 - 24: ooOoO0o % I1Ii111 + OoO0O00 * o0oOOo0O0Ooo % O0 - i11iIiiIii
 if 49 - 49: o0oOOo0O0Ooo / OoOoOO00 + iII111i
 if 85 - 85: I1IiiI - o0oOOo0O0Ooo
def lisp_get_all_translated_rlocs ( ) :
 oo000oO = [ ]
 for Oo00OO0 in lisp_db_list :
  for iiI1iI1 in Oo00OO0 . rloc_set :
   if ( iiI1iI1 . is_rloc_translated ( ) == False ) : continue
   iIiIi1ii = iiI1iI1 . translated_rloc . print_address_no_iid ( )
   oo000oO . append ( iIiIi1ii )
   if 37 - 37: oO0o * i11iIiiIii / IiII / i11iIiiIii
   if 78 - 78: iII111i + II111iiii - o0oOOo0O0Ooo - iIii1I11I1II1 . Ii1I
 return ( oo000oO )
 if 43 - 43: o0oOOo0O0Ooo
 if 78 - 78: I1Ii111 % i1IIi * I11i
 if 59 - 59: OoOoOO00 % OoO0O00 % i11iIiiIii . II111iiii % I1ii11iIi11i + i1IIi
 if 99 - 99: I11i + IiII * I1Ii111 - OOooOOo - i1IIi
 if 77 - 77: I11i . IiII / OoO0O00 / I1Ii111
 if 8 - 8: o0oOOo0O0Ooo + iII111i / OoO0O00 * ooOoO0o - oO0o . iII111i
 if 32 - 32: OoooooooOO . I1Ii111 - I1ii11iIi11i
 if 29 - 29: OoO0O00
def lisp_update_default_routes ( map_resolver , iid , rtr_list ) :
 OOOO = ( os . getenv ( "LISP_RTR_BEHIND_NAT" ) != None )
 if 33 - 33: I1ii11iIi11i - O0
 oOO000o00O0o = { }
 for i11iII1Ii1ii111 in rtr_list :
  if ( i11iII1Ii1ii111 == None ) : continue
  iIiIi1ii = rtr_list [ i11iII1Ii1ii111 ]
  if ( OOOO and iIiIi1ii . is_private_address ( ) ) : continue
  oOO000o00O0o [ i11iII1Ii1ii111 ] = iIiIi1ii
  if 11 - 11: OoOoOO00 - I1Ii111 / OOooOOo
 rtr_list = oOO000o00O0o
 if 12 - 12: IiII + OoO0O00
 i1i1 = [ ]
 for ooo0oOOOO00Oo in [ LISP_AFI_IPV4 , LISP_AFI_IPV6 , LISP_AFI_MAC ] :
  if ( ooo0oOOOO00Oo == LISP_AFI_MAC and lisp_l2_overlay == False ) : break
  if 91 - 91: OoOoOO00 - I1IiiI % OoOoOO00 / Oo0Ooo + I1Ii111
  if 43 - 43: iIii1I11I1II1 / oO0o . II111iiii % O0 - IiII
  if 49 - 49: IiII - OOooOOo * OOooOOo . O0
  if 60 - 60: OoOoOO00 % iIii1I11I1II1 + IiII % o0oOOo0O0Ooo
  if 64 - 64: OoOoOO00 * I1ii11iIi11i . OoooooooOO . i1IIi
  OOoOo = lisp_address ( ooo0oOOOO00Oo , "" , 0 , iid )
  OOoOo . make_default_route ( OOoOo )
  O0O = lisp_map_cache . lookup_cache ( OOoOo , True )
  if ( O0O ) :
   if ( O0O . checkpoint_entry ) :
    lprint ( "Updating checkpoint entry for {}" . format ( green ( O0O . print_eid_tuple ( ) , False ) ) )
    if 61 - 61: OoO0O00
   elif ( O0O . do_rloc_sets_match ( rtr_list . values ( ) ) ) :
    continue
    if 100 - 100: OoOoOO00
   O0O . delete_cache ( )
   if 97 - 97: OoooooooOO
   if 91 - 91: o0oOOo0O0Ooo / O0 % OoO0O00
  i1i1 . append ( [ OOoOo , "" ] )
  if 35 - 35: iII111i % OoO0O00 * O0
  if 37 - 37: OOooOOo
  if 100 - 100: Oo0Ooo * I1IiiI . ooOoO0o
  if 53 - 53: OOooOOo + o0oOOo0O0Ooo * Ii1I + O0
  iIiii1Ii1I = lisp_address ( ooo0oOOOO00Oo , "" , 0 , iid )
  iIiii1Ii1I . make_default_multicast_route ( iIiii1Ii1I )
  oo0OooO000oO0 = lisp_map_cache . lookup_cache ( iIiii1Ii1I , True )
  if ( oo0OooO000oO0 ) : oo0OooO000oO0 = oo0OooO000oO0 . source_cache . lookup_cache ( OOoOo , True )
  if ( oo0OooO000oO0 ) : oo0OooO000oO0 . delete_cache ( )
  if 55 - 55: oO0o / I1IiiI + I1Ii111 * o0oOOo0O0Ooo
  i1i1 . append ( [ OOoOo , iIiii1Ii1I ] )
  if 32 - 32: iII111i / Ii1I / I1Ii111 - OoOoOO00 / OOooOOo * OoO0O00
 if ( len ( i1i1 ) == 0 ) : return
 if 32 - 32: I1ii11iIi11i + ooOoO0o . i1IIi * iIii1I11I1II1 - I1IiiI
 if 9 - 9: I11i % i1IIi / ooOoO0o % iII111i - oO0o - II111iiii
 if 29 - 29: ooOoO0o . II111iiii . i1IIi % oO0o
 if 11 - 11: OoOoOO00 . OoO0O00 % I11i * iII111i % I1Ii111 . O0
 OOoO000o00000 = [ ]
 for iiiii11 in rtr_list :
  I1Iii = rtr_list [ iiiii11 ]
  iiI1iI1 = lisp_rloc ( )
  iiI1iI1 . rloc . copy_address ( I1Iii )
  iiI1iI1 . priority = 254
  iiI1iI1 . mpriority = 255
  iiI1iI1 . rloc_name = "RTR"
  OOoO000o00000 . append ( iiI1iI1 )
  if 5 - 5: II111iiii
  if 100 - 100: O0 * iIii1I11I1II1 - OoooooooOO
 for OOoOo in i1i1 :
  O0O = lisp_mapping ( OOoOo [ 0 ] , OOoOo [ 1 ] , OOoO000o00000 )
  O0O . mapping_source = map_resolver
  O0O . map_cache_ttl = LISP_MR_TTL * 60
  O0O . add_cache ( )
  lprint ( "Add {} to map-cache with RTR RLOC-set: {}" . format ( green ( O0O . print_eid_tuple ( ) , False ) , rtr_list . keys ( ) ) )
  if 41 - 41: OoO0O00 / OoooooooOO
  OOoO000o00000 = copy . deepcopy ( OOoO000o00000 )
  if 61 - 61: ooOoO0o
 return
 if 4 - 4: Oo0Ooo + oO0o + oO0o
 if 79 - 79: OoooooooOO
 if 98 - 98: O0 . ooOoO0o * I1Ii111
 if 98 - 98: ooOoO0o + o0oOOo0O0Ooo / I11i - Ii1I * II111iiii + i1IIi
 if 10 - 10: oO0o
 if 8 - 8: I1ii11iIi11i * OOooOOo * iIii1I11I1II1 + I11i . iII111i
 if 55 - 55: I1IiiI + Ii1I % I1ii11iIi11i + iIii1I11I1II1
 if 64 - 64: i1IIi / O0 - oO0o
 if 7 - 7: IiII . IiII * Ii1I
 if 1 - 1: i11iIiiIii
def lisp_process_info_reply ( source , packet , store ) :
 if 91 - 91: I1ii11iIi11i . OoO0O00 / OoO0O00 / I1ii11iIi11i + iII111i
 if 20 - 20: o0oOOo0O0Ooo . I1Ii111 + O0
 if 99 - 99: O0 / IiII . oO0o
 if 18 - 18: OoooooooOO * OoO0O00 * I1Ii111
 Oo0oOO = lisp_info ( )
 packet = Oo0oOO . decode ( packet )
 if ( packet == None ) : return ( [ None , None , False ] )
 if 12 - 12: i11iIiiIii / iIii1I11I1II1 . I11i % I1Ii111 * ooOoO0o % ooOoO0o
 Oo0oOO . print_info ( )
 if 13 - 13: i1IIi . ooOoO0o . ooOoO0o
 if 24 - 24: iIii1I11I1II1
 if 72 - 72: i11iIiiIii + o0oOOo0O0Ooo % ooOoO0o * I1ii11iIi11i . i1IIi
 if 59 - 59: OoooooooOO - OoooooooOO - o0oOOo0O0Ooo + i1IIi % I1Ii111
 o0OooOoOO0ooO = False
 for iiiii11 in Oo0oOO . rtr_list :
  oO00o = iiiii11 . print_address_no_iid ( )
  if ( lisp_rtr_list . has_key ( oO00o ) ) :
   if ( lisp_register_all_rtrs == False ) : continue
   if ( lisp_rtr_list [ oO00o ] != None ) : continue
   if 20 - 20: o0oOOo0O0Ooo
  o0OooOoOO0ooO = True
  lisp_rtr_list [ oO00o ] = iiiii11
  if 65 - 65: OOooOOo / OoOoOO00
  if 31 - 31: OoOoOO00 * I1IiiI + i11iIiiIii % OOooOOo * OoOoOO00
  if 36 - 36: I1Ii111 * OoO0O00
  if 84 - 84: OoOoOO00
  if 80 - 80: oO0o
 if ( lisp_i_am_itr and o0OooOoOO0ooO ) :
  if ( lisp_iid_to_interface == { } ) :
   lisp_update_default_routes ( source , lisp_default_iid , lisp_rtr_list )
  else :
   for I1I111iIi in lisp_iid_to_interface . keys ( ) :
    lisp_update_default_routes ( source , int ( I1I111iIi ) , lisp_rtr_list )
    if 59 - 59: iIii1I11I1II1 / IiII % I1ii11iIi11i + OoO0O00 - I11i % OOooOOo
    if 92 - 92: iII111i
    if 96 - 96: OoOoOO00 / OoOoOO00 / OoOoOO00 + OoooooooOO + Oo0Ooo
    if 91 - 91: OoOoOO00 + II111iiii / I11i * iIii1I11I1II1
    if 92 - 92: I1Ii111 - IiII / IiII
    if 42 - 42: IiII
    if 7 - 7: iIii1I11I1II1
 if ( store == False ) :
  return ( [ Oo0oOO . global_etr_rloc , Oo0oOO . etr_port , o0OooOoOO0ooO ] )
  if 35 - 35: IiII + O0 % I1Ii111 - I1ii11iIi11i - i1IIi
  if 100 - 100: I1Ii111 + i11iIiiIii - IiII / I1ii11iIi11i / iII111i
  if 56 - 56: iII111i
  if 91 - 91: Oo0Ooo . I11i . I1ii11iIi11i
  if 60 - 60: i11iIiiIii - OOooOOo
  if 78 - 78: I1IiiI * ooOoO0o % iIii1I11I1II1 / I1ii11iIi11i
 for Oo00OO0 in lisp_db_list :
  for iiI1iI1 in Oo00OO0 . rloc_set :
   i11iII1Ii1ii111 = iiI1iI1 . rloc
   iii = iiI1iI1 . interface
   if ( iii == None ) :
    if ( i11iII1Ii1ii111 . is_null ( ) ) : continue
    if ( i11iII1Ii1ii111 . is_local ( ) == False ) : continue
    if ( Oo0oOO . private_etr_rloc . is_null ( ) == False and
 i11iII1Ii1ii111 . is_exact_match ( Oo0oOO . private_etr_rloc ) == False ) :
     continue
     if 61 - 61: I1Ii111 . Ii1I + OoooooooOO
   elif ( Oo0oOO . private_etr_rloc . is_dist_name ( ) ) :
    iI1Iii11Iii11 = Oo0oOO . private_etr_rloc . address
    if ( iI1Iii11Iii11 != iiI1iI1 . rloc_name ) : continue
    if 98 - 98: OOooOOo . ooOoO0o . OoOoOO00 - I1Ii111 . i1IIi - iIii1I11I1II1
    if 89 - 89: II111iiii * I1ii11iIi11i - I1IiiI
   I1I1iII1i = green ( Oo00OO0 . eid . print_prefix ( ) , False )
   ii1 = red ( i11iII1Ii1ii111 . print_address_no_iid ( ) , False )
   if 58 - 58: Ii1I / Oo0Ooo % IiII
   IiOoOO0OoOo = Oo0oOO . global_etr_rloc . is_exact_match ( i11iII1Ii1ii111 )
   if ( iiI1iI1 . translated_port == 0 and IiOoOO0OoOo ) :
    lprint ( "No NAT for {} ({}), EID-prefix {}" . format ( ii1 ,
 iii , I1I1iII1i ) )
    continue
    if 11 - 11: I1ii11iIi11i - I1ii11iIi11i . ooOoO0o * Oo0Ooo + I1Ii111
    if 59 - 59: iII111i - OOooOOo - OoO0O00 . I1IiiI % o0oOOo0O0Ooo + iII111i
    if 10 - 10: iIii1I11I1II1 - Ii1I
    if 84 - 84: iII111i
    if 21 - 21: i11iIiiIii
   iIi1i1I = Oo0oOO . global_etr_rloc
   iiI11Ii11iiI = iiI1iI1 . translated_rloc
   if ( iiI11Ii11iiI . is_exact_match ( iIi1i1I ) and
 Oo0oOO . etr_port == iiI1iI1 . translated_port ) : continue
   if 66 - 66: IiII
   lprint ( "Store translation {}:{} for {} ({}), EID-prefix {}" . format ( red ( Oo0oOO . global_etr_rloc . print_address_no_iid ( ) , False ) ,
   # I1IiiI / OoooooooOO - I1IiiI % Ii1I
 Oo0oOO . etr_port , ii1 , iii , I1I1iII1i ) )
   if 9 - 9: I1ii11iIi11i + OoooooooOO - OoooooooOO + OoO0O00 / iIii1I11I1II1
   iiI1iI1 . store_translated_rloc ( Oo0oOO . global_etr_rloc ,
 Oo0oOO . etr_port )
   if 23 - 23: iII111i / iIii1I11I1II1
   if 5 - 5: O0
 return ( [ Oo0oOO . global_etr_rloc , Oo0oOO . etr_port , o0OooOoOO0ooO ] )
 if 64 - 64: i1IIi * i1IIi . iII111i - O0 - oO0o % OoooooooOO
 if 14 - 14: Ii1I % OoO0O00 % I1Ii111 * O0
 if 8 - 8: I1IiiI - i11iIiiIii * I1IiiI
 if 6 - 6: O0 - OoOoOO00 - i11iIiiIii / iII111i
 if 63 - 63: OOooOOo
 if 84 - 84: i11iIiiIii * iIii1I11I1II1 % I11i % iII111i + OoooooooOO . o0oOOo0O0Ooo
 if 78 - 78: o0oOOo0O0Ooo . iII111i + O0 / I1ii11iIi11i + I1ii11iIi11i + II111iiii
 if 96 - 96: iIii1I11I1II1 * II111iiii . iIii1I11I1II1
def lisp_test_mr ( lisp_sockets , port ) :
 return
 lprint ( "Test Map-Resolvers" )
 if 13 - 13: Ii1I - OoOoOO00 . Ii1I
 I1IiiIiIIi1Ii = lisp_address ( LISP_AFI_IPV4 , "" , 0 , 0 )
 I1i1II1I = lisp_address ( LISP_AFI_IPV6 , "" , 0 , 0 )
 if 88 - 88: I1IiiI % oO0o * O0 - i1IIi / I11i / I11i
 if 48 - 48: Ii1I
 if 82 - 82: I1ii11iIi11i * OoO0O00 + Oo0Ooo * iII111i * I1Ii111 * OOooOOo
 if 53 - 53: iIii1I11I1II1 - Oo0Ooo
 I1IiiIiIIi1Ii . store_address ( "10.0.0.1" )
 lisp_send_map_request ( lisp_sockets , port , None , I1IiiIiIIi1Ii , None )
 I1IiiIiIIi1Ii . store_address ( "192.168.0.1" )
 lisp_send_map_request ( lisp_sockets , port , None , I1IiiIiIIi1Ii , None )
 if 46 - 46: ooOoO0o
 if 45 - 45: ooOoO0o + iIii1I11I1II1 + I1Ii111
 if 8 - 8: iIii1I11I1II1 % OoooooooOO . i1IIi % I1Ii111 + i1IIi % Oo0Ooo
 if 15 - 15: iII111i / i11iIiiIii + I1Ii111 % OOooOOo
 I1i1II1I . store_address ( "0100::1" )
 lisp_send_map_request ( lisp_sockets , port , None , I1i1II1I , None )
 I1i1II1I . store_address ( "8000::1" )
 lisp_send_map_request ( lisp_sockets , port , None , I1i1II1I , None )
 if 57 - 57: OoO0O00 * iII111i . II111iiii / I1IiiI + II111iiii % o0oOOo0O0Ooo
 if 26 - 26: I1ii11iIi11i / I11i / Oo0Ooo / i1IIi + O0 * ooOoO0o
 if 53 - 53: IiII / II111iiii / oO0o % O0 / I1Ii111
 if 91 - 91: oO0o * OoOoOO00 + O0 % Oo0Ooo
 Oo0oooo00 = threading . Timer ( LISP_TEST_MR_INTERVAL , lisp_test_mr ,
 [ lisp_sockets , port ] )
 Oo0oooo00 . start ( )
 return
 if 68 - 68: iII111i + OOooOOo - Ii1I
 if 67 - 67: OoooooooOO * O0 * Ii1I . ooOoO0o
 if 15 - 15: iII111i / O0
 if 65 - 65: oO0o * ooOoO0o . I11i / i11iIiiIii - IiII * OoO0O00
 if 57 - 57: iII111i * I11i % o0oOOo0O0Ooo * OoOoOO00 % I1ii11iIi11i + i11iIiiIii
 if 66 - 66: i11iIiiIii . ooOoO0o
 if 83 - 83: I1Ii111 % ooOoO0o + OoooooooOO
 if 50 - 50: i11iIiiIii % I1IiiI * iII111i / Ii1I
 if 12 - 12: iII111i / OoO0O00 - II111iiii + Oo0Ooo
 if 78 - 78: i1IIi
 if 25 - 25: Ii1I * II111iiii / OoOoOO00
 if 86 - 86: i1IIi + I1IiiI + I1Ii111 % II111iiii . IiII - iIii1I11I1II1
 if 54 - 54: i11iIiiIii . Ii1I % I1IiiI . I1Ii111 . OoooooooOO
def lisp_update_local_rloc ( rloc ) :
 if ( rloc . interface == None ) : return
 if 49 - 49: OOooOOo % I11i - OOooOOo + Ii1I . I1ii11iIi11i + ooOoO0o
 iIiIi1ii = lisp_get_interface_address ( rloc . interface )
 if ( iIiIi1ii == None ) : return
 if 15 - 15: i11iIiiIii
 o0O0OOO = rloc . rloc . print_address_no_iid ( )
 IiiI11i1i1i = iIiIi1ii . print_address_no_iid ( )
 if 15 - 15: oO0o / i11iIiiIii . oO0o * OoOoOO00 . ooOoO0o / I1IiiI
 if ( o0O0OOO == IiiI11i1i1i ) : return
 if 46 - 46: OOooOOo . OoO0O00 % OoOoOO00 % o0oOOo0O0Ooo + o0oOOo0O0Ooo - o0oOOo0O0Ooo
 lprint ( "Local interface address changed on {} from {} to {}" . format ( rloc . interface , o0O0OOO , IiiI11i1i1i ) )
 if 80 - 80: Oo0Ooo + i11iIiiIii
 if 7 - 7: ooOoO0o . O0 + o0oOOo0O0Ooo + oO0o - iII111i
 rloc . rloc . copy_address ( iIiIi1ii )
 lisp_myrlocs [ 0 ] = iIiIi1ii
 return
 if 48 - 48: IiII * O0 / OoooooooOO - I1Ii111
 if 28 - 28: IiII . o0oOOo0O0Ooo
 if 69 - 69: ooOoO0o - OoOoOO00 . I1IiiI . I11i + OoOoOO00 / i11iIiiIii
 if 20 - 20: OoO0O00 . OoooooooOO - ooOoO0o . I11i / Oo0Ooo
 if 89 - 89: iIii1I11I1II1 . ooOoO0o
 if 82 - 82: OoOoOO00 - II111iiii . OoO0O00 * ooOoO0o
 if 78 - 78: OoOoOO00 % oO0o
 if 39 - 39: iIii1I11I1II1
def lisp_update_encap_port ( mc ) :
 for i11iII1Ii1ii111 in mc . rloc_set :
  iIiiiIi = lisp_get_nat_info ( i11iII1Ii1ii111 . rloc , i11iII1Ii1ii111 . rloc_name )
  if ( iIiiiIi == None ) : continue
  if ( i11iII1Ii1ii111 . translated_port == iIiiiIi . port ) : continue
  if 72 - 72: II111iiii + I1Ii111 / Ii1I * iIii1I11I1II1
  lprint ( ( "Encap-port changed from {} to {} for RLOC {}, " + "EID-prefix {}" ) . format ( i11iII1Ii1ii111 . translated_port , iIiiiIi . port ,
  # I1IiiI % OoOoOO00 / OoO0O00 % OoO0O00 / OoO0O00 * IiII
 red ( i11iII1Ii1ii111 . rloc . print_address_no_iid ( ) , False ) ,
 green ( mc . print_eid_tuple ( ) , False ) ) )
  if 37 - 37: oO0o / iII111i
  i11iII1Ii1ii111 . store_translated_rloc ( i11iII1Ii1ii111 . rloc , iIiiiIi . port )
  if 58 - 58: OoO0O00 / OoOoOO00 - Oo0Ooo + OoOoOO00
 return
 if 8 - 8: II111iiii % IiII - IiII + Oo0Ooo . iII111i
 if 90 - 90: OOooOOo . ooOoO0o * oO0o % ooOoO0o / o0oOOo0O0Ooo
 if 25 - 25: i11iIiiIii % o0oOOo0O0Ooo % OoO0O00 - I11i
 if 18 - 18: iII111i
 if 9 - 9: I1Ii111 . oO0o . OoO0O00 / IiII - oO0o / oO0o
 if 50 - 50: II111iiii + OoOoOO00
 if 17 - 17: ooOoO0o + I1ii11iIi11i
 if 34 - 34: Ii1I / II111iiii + OoOoOO00 . II111iiii + OoooooooOO * o0oOOo0O0Ooo
 if 48 - 48: O0
 if 99 - 99: II111iiii * oO0o / I1ii11iIi11i - i1IIi
 if 84 - 84: i11iIiiIii . OoooooooOO
 if 69 - 69: I1Ii111 * II111iiii % I1Ii111 * i11iIiiIii . ooOoO0o / Oo0Ooo
def lisp_timeout_map_cache_entry ( mc , delete_list ) :
 if ( mc . map_cache_ttl == None ) :
  lisp_update_encap_port ( mc )
  return ( [ True , delete_list ] )
  if 5 - 5: Ii1I
  if 19 - 19: oO0o
  if 61 - 61: OoOoOO00 + iIii1I11I1II1 / I1ii11iIi11i - i1IIi
  if 11 - 11: oO0o * o0oOOo0O0Ooo . I1IiiI
  if 12 - 12: I1IiiI % OoO0O00 / I1Ii111 / O0 % o0oOOo0O0Ooo
 if ( mc . action == LISP_NO_ACTION ) :
  ooO = lisp_get_timestamp ( )
  if ( mc . last_refresh_time + mc . map_cache_ttl > ooO ) :
   lisp_update_encap_port ( mc )
   return ( [ True , delete_list ] )
   if 1 - 1: OoOoOO00 / I11i
   if 43 - 43: o0oOOo0O0Ooo - i1IIi / Ii1I . OoOoOO00 + i11iIiiIii
   if 69 - 69: i11iIiiIii - iIii1I11I1II1
   if 40 - 40: I1IiiI / oO0o + ooOoO0o
   if 100 - 100: OoOoOO00 % iII111i * ooOoO0o . O0
   if 37 - 37: I1ii11iIi11i
 oO000o = lisp_print_elapsed ( mc . last_refresh_time )
 ii1IOo0OOoo = mc . print_eid_tuple ( )
 lprint ( "Map-cache entry for EID-prefix {} has {}, had uptime of {}" . format ( green ( ii1IOo0OOoo , False ) , bold ( "timed out" , False ) , oO000o ) )
 if 24 - 24: O0 . I1Ii111 * i11iIiiIii
 if 84 - 84: ooOoO0o / I1ii11iIi11i - o0oOOo0O0Ooo . OoooooooOO * iIii1I11I1II1
 if 16 - 16: I11i % O0
 if 56 - 56: Ii1I * OoOoOO00 . i1IIi
 if 15 - 15: I1Ii111
 delete_list . append ( mc )
 return ( [ True , delete_list ] )
 if 64 - 64: OOooOOo * Oo0Ooo
 if 96 - 96: Oo0Ooo / I1ii11iIi11i * iIii1I11I1II1 / iII111i
 if 18 - 18: I1Ii111
 if 29 - 29: i1IIi - I1IiiI / i1IIi
 if 64 - 64: IiII
 if 69 - 69: OOooOOo . I1IiiI
 if 11 - 11: I1Ii111 * I1IiiI - I1Ii111 / iII111i
 if 22 - 22: iII111i % I11i % O0 - I11i
def lisp_timeout_map_cache_walk ( mc , parms ) :
 O0Oo0 = parms [ 0 ]
 i1Ii = parms [ 1 ]
 if 52 - 52: Ii1I . OoOoOO00 / o0oOOo0O0Ooo / iII111i
 if 83 - 83: OoO0O00 - Oo0Ooo + I1Ii111 . I1IiiI
 if 78 - 78: I11i / ooOoO0o . OoOoOO00 * i1IIi
 if 15 - 15: i1IIi . II111iiii * OoOoOO00 / Oo0Ooo
 if ( mc . group . is_null ( ) ) :
  OOoO0 , O0Oo0 = lisp_timeout_map_cache_entry ( mc , O0Oo0 )
  if ( O0Oo0 == [ ] or mc != O0Oo0 [ - 1 ] ) :
   i1Ii = lisp_write_checkpoint_entry ( i1Ii , mc )
   if 99 - 99: iII111i - o0oOOo0O0Ooo / O0
  return ( [ OOoO0 , parms ] )
  if 97 - 97: iIii1I11I1II1 * I1Ii111
  if 39 - 39: I1Ii111 . II111iiii
 if ( mc . source_cache == None ) : return ( [ True , parms ] )
 if 94 - 94: OoO0O00 - OoO0O00 + iIii1I11I1II1 + O0 * oO0o
 if 9 - 9: Ii1I * Oo0Ooo / oO0o / Ii1I
 if 34 - 34: I1IiiI
 if 56 - 56: Ii1I
 if 71 - 71: O0 / i1IIi
 parms = mc . source_cache . walk_cache ( lisp_timeout_map_cache_entry , parms )
 return ( [ True , parms ] )
 if 20 - 20: OOooOOo . iIii1I11I1II1 - I1Ii111 . i1IIi
 if 82 - 82: oO0o * i11iIiiIii % o0oOOo0O0Ooo % IiII - I11i - OoO0O00
 if 24 - 24: oO0o . II111iiii + OoO0O00 * I1ii11iIi11i / oO0o
 if 86 - 86: I1Ii111 + I1ii11iIi11i
 if 63 - 63: ooOoO0o - i11iIiiIii . o0oOOo0O0Ooo - i1IIi - IiII
 if 32 - 32: I1Ii111 / iIii1I11I1II1 + oO0o % I11i * OoooooooOO
 if 69 - 69: OOooOOo
def lisp_timeout_map_cache ( lisp_map_cache ) :
 i11Iii1Ii1i1 = [ [ ] , [ ] ]
 i11Iii1Ii1i1 = lisp_map_cache . walk_cache ( lisp_timeout_map_cache_walk , i11Iii1Ii1i1 )
 if 9 - 9: i11iIiiIii * Oo0Ooo
 if 33 - 33: oO0o / ooOoO0o
 if 92 - 92: O0 . Oo0Ooo - Ii1I * I1IiiI * Oo0Ooo * iII111i
 if 78 - 78: Ii1I * iIii1I11I1II1 - Ii1I - I1ii11iIi11i * I1ii11iIi11i
 if 44 - 44: o0oOOo0O0Ooo
 O0Oo0 = i11Iii1Ii1i1 [ 0 ]
 for O0O in O0Oo0 : O0O . delete_cache ( )
 if 1 - 1: OoooooooOO / i11iIiiIii . o0oOOo0O0Ooo
 if 78 - 78: OOooOOo * O0 * II111iiii % OoOoOO00
 if 12 - 12: Oo0Ooo . o0oOOo0O0Ooo - i1IIi - oO0o % IiII . I11i
 if 17 - 17: i1IIi % OoO0O00 + i11iIiiIii % I1Ii111 * ooOoO0o . I1ii11iIi11i
 i1Ii = i11Iii1Ii1i1 [ 1 ]
 lisp_checkpoint ( i1Ii )
 return
 if 64 - 64: O0 - iII111i
 if 82 - 82: O0
 if 37 - 37: I1Ii111
 if 98 - 98: iII111i - OoOoOO00 / I1Ii111 . OOooOOo - OOooOOo - ooOoO0o
 if 84 - 84: OOooOOo * ooOoO0o / O0
 if 96 - 96: I11i . I11i % II111iiii
 if 14 - 14: iII111i / OoooooooOO
 if 8 - 8: OOooOOo + I1IiiI - Oo0Ooo + i1IIi . Ii1I . I1Ii111
 if 38 - 38: I1IiiI / II111iiii * OoOoOO00 / I1Ii111
 if 80 - 80: I1ii11iIi11i / ooOoO0o * ooOoO0o . Oo0Ooo
 if 44 - 44: Ii1I * i1IIi % OoOoOO00 . OoOoOO00
 if 16 - 16: Oo0Ooo / i1IIi / iIii1I11I1II1 / iIii1I11I1II1 % o0oOOo0O0Ooo / I1ii11iIi11i
 if 11 - 11: I1IiiI
 if 45 - 45: OOooOOo / i1IIi * IiII * I1Ii111
 if 34 - 34: ooOoO0o / iIii1I11I1II1 . iII111i
 if 91 - 91: OoO0O00
def lisp_store_nat_info ( hostname , rloc , port ) :
 oO00o = rloc . print_address_no_iid ( )
 i1i1I111I = "{} NAT state for {}, RLOC {}, port {}" . format ( "{}" ,
 blue ( hostname , False ) , red ( oO00o , False ) , port )
 if 2 - 2: oO0o . iIii1I11I1II1 + I1IiiI / o0oOOo0O0Ooo . i1IIi
 O00OooOoOO0o0 = lisp_nat_info ( oO00o , hostname , port )
 if 67 - 67: I11i + oO0o + iII111i . ooOoO0o + I11i
 if ( lisp_nat_state_info . has_key ( hostname ) == False ) :
  lisp_nat_state_info [ hostname ] = [ O00OooOoOO0o0 ]
  lprint ( i1i1I111I . format ( "Store initial" ) )
  return ( True )
  if 43 - 43: OoOoOO00
  if 81 - 81: ooOoO0o * OOooOOo / OoO0O00 + I1ii11iIi11i % I1Ii111
  if 37 - 37: i11iIiiIii - OoooooooOO - OoOoOO00 * oO0o / Ii1I
  if 100 - 100: II111iiii / Oo0Ooo / iII111i / OOooOOo
  if 100 - 100: iIii1I11I1II1
  if 50 - 50: I1Ii111 / ooOoO0o * I11i
 iIiiiIi = lisp_nat_state_info [ hostname ] [ 0 ]
 if ( iIiiiIi . address == oO00o and iIiiiIi . port == port ) :
  iIiiiIi . uptime = lisp_get_timestamp ( )
  lprint ( i1i1I111I . format ( "Refresh existing" ) )
  return ( False )
  if 53 - 53: II111iiii . IiII
  if 5 - 5: i1IIi % IiII
  if 16 - 16: ooOoO0o - iII111i % Ii1I . OoOoOO00
  if 56 - 56: i11iIiiIii % i11iIiiIii % OoooooooOO . Ii1I . iII111i + I11i
  if 64 - 64: O0
  if 37 - 37: o0oOOo0O0Ooo / O0
  if 58 - 58: I1Ii111 + OoooooooOO + iIii1I11I1II1
 iIII = None
 for iIiiiIi in lisp_nat_state_info [ hostname ] :
  if ( iIiiiIi . address == oO00o and iIiiiIi . port == port ) :
   iIII = iIiiiIi
   break
   if 90 - 90: OoO0O00 % Ii1I - ooOoO0o
   if 67 - 67: I1IiiI % O0 + I1IiiI * I1Ii111 * OoOoOO00 * II111iiii
   if 79 - 79: I1IiiI
 if ( iIII == None ) :
  lprint ( i1i1I111I . format ( "Store new" ) )
 else :
  lisp_nat_state_info [ hostname ] . remove ( iIII )
  lprint ( i1i1I111I . format ( "Use previous" ) )
  if 37 - 37: I1Ii111 + Ii1I
  if 50 - 50: i11iIiiIii
 ooOoOOoo0ooo = lisp_nat_state_info [ hostname ]
 lisp_nat_state_info [ hostname ] = [ O00OooOoOO0o0 ] + ooOoOOoo0ooo
 return ( True )
 if 30 - 30: I1Ii111 / i11iIiiIii / i11iIiiIii + OoOoOO00
 if 42 - 42: iII111i
 if 63 - 63: i1IIi
 if 24 - 24: i11iIiiIii % iII111i . oO0o
 if 44 - 44: II111iiii - OoO0O00 + i11iIiiIii
 if 34 - 34: I1ii11iIi11i % ooOoO0o / II111iiii * O0 % OOooOOo
 if 9 - 9: I1ii11iIi11i / I1ii11iIi11i - OOooOOo . iIii1I11I1II1
 if 33 - 33: I1IiiI + oO0o % I1IiiI / iII111i - ooOoO0o - i11iIiiIii
def lisp_get_nat_info ( rloc , hostname ) :
 if ( lisp_nat_state_info . has_key ( hostname ) == False ) : return ( None )
 if 39 - 39: i11iIiiIii / oO0o
 oO00o = rloc . print_address_no_iid ( )
 for iIiiiIi in lisp_nat_state_info [ hostname ] :
  if ( iIiiiIi . address == oO00o ) : return ( iIiiiIi )
  if 71 - 71: I1Ii111 * iIii1I11I1II1 - I1Ii111
 return ( None )
 if 87 - 87: I1IiiI / Ii1I
 if 54 - 54: OoooooooOO / Ii1I
 if 26 - 26: o0oOOo0O0Ooo + OoO0O00
 if 59 - 59: Ii1I * IiII
 if 64 - 64: ooOoO0o . Oo0Ooo - OoOoOO00
 if 66 - 66: OoOoOO00
 if 83 - 83: OOooOOo . IiII
 if 98 - 98: i11iIiiIii
 if 74 - 74: iIii1I11I1II1 * O0 + OOooOOo . o0oOOo0O0Ooo
 if 17 - 17: I1Ii111
 if 59 - 59: OoOoOO00 . OoOoOO00 * iII111i - Ii1I . i11iIiiIii
 if 68 - 68: iII111i
 if 68 - 68: I1Ii111 - OoO0O00 % OoO0O00 % OOooOOo - OoO0O00
 if 3 - 3: iIii1I11I1II1 + iIii1I11I1II1 + OoO0O00
 if 59 - 59: iII111i
 if 7 - 7: o0oOOo0O0Ooo * OoooooooOO - Ii1I * II111iiii % I1Ii111
 if 82 - 82: OoOoOO00 - OoOoOO00 + iIii1I11I1II1 + o0oOOo0O0Ooo + IiII - o0oOOo0O0Ooo
 if 65 - 65: I1Ii111 + OOooOOo
 if 97 - 97: oO0o % OoOoOO00 * oO0o % II111iiii + iIii1I11I1II1
 if 11 - 11: ooOoO0o . o0oOOo0O0Ooo
def lisp_build_info_requests ( lisp_sockets , dest , port ) :
 if ( lisp_nat_traversal == False ) : return
 if 94 - 94: ooOoO0o . oO0o * OoooooooOO % oO0o
 if 77 - 77: ooOoO0o % I1IiiI
 if 26 - 26: o0oOOo0O0Ooo
 if 72 - 72: I1IiiI
 if 90 - 90: ooOoO0o
 if 67 - 67: iIii1I11I1II1 + i1IIi * I1IiiI * OoooooooOO
 ii1II11iIIII = [ ]
 O00o = [ ]
 if ( dest == None ) :
  for IiIiiiI11 in lisp_map_resolvers_list . values ( ) :
   O00o . append ( IiIiiiI11 . map_resolver )
   if 38 - 38: iII111i
  ii1II11iIIII = O00o
  if ( ii1II11iIIII == [ ] ) :
   for iIoO0oOOoOoO in lisp_map_servers_list . values ( ) :
    ii1II11iIIII . append ( iIoO0oOOoOoO . map_server )
    if 59 - 59: Ii1I / o0oOOo0O0Ooo / oO0o + iII111i * I1ii11iIi11i - o0oOOo0O0Ooo
    if 70 - 70: O0 / I1ii11iIi11i + ooOoO0o . OoO0O00 - OoO0O00 / i11iIiiIii
  if ( ii1II11iIIII == [ ] ) : return
 else :
  ii1II11iIIII . append ( dest )
  if 1 - 1: iIii1I11I1II1 % I1ii11iIi11i
  if 49 - 49: iII111i + o0oOOo0O0Ooo % I1ii11iIi11i . O0 % OoooooooOO . o0oOOo0O0Ooo
  if 3 - 3: i11iIiiIii - i1IIi * o0oOOo0O0Ooo / OoOoOO00 % Oo0Ooo
  if 65 - 65: OoooooooOO + iII111i - i11iIiiIii - IiII + oO0o
  if 67 - 67: i1IIi * I1Ii111 * O0
 oo000oO = { }
 for Oo00OO0 in lisp_db_list :
  for iiI1iI1 in Oo00OO0 . rloc_set :
   lisp_update_local_rloc ( iiI1iI1 )
   if ( iiI1iI1 . rloc . is_null ( ) ) : continue
   if ( iiI1iI1 . interface == None ) : continue
   if 16 - 16: OoO0O00 + iII111i + i1IIi + I1ii11iIi11i - I1IiiI
   iIiIi1ii = iiI1iI1 . rloc . print_address_no_iid ( )
   if ( iIiIi1ii in oo000oO ) : continue
   oo000oO [ iIiIi1ii ] = iiI1iI1 . interface
   if 88 - 88: oO0o % iII111i + I1ii11iIi11i - II111iiii . I11i
   if 18 - 18: I1ii11iIi11i - i1IIi - IiII * II111iiii % I1Ii111 . II111iiii
 if ( oo000oO == { } ) :
  lprint ( 'Suppress Info-Request, no "interface = <device>" RLOC ' + "found in any database-mappings" )
  if 80 - 80: oO0o + OoO0O00 + o0oOOo0O0Ooo . OoOoOO00
  return
  if 75 - 75: i11iIiiIii
  if 58 - 58: iII111i
  if 48 - 48: OoO0O00 * OOooOOo / iII111i
  if 90 - 90: I1IiiI * i11iIiiIii . OOooOOo / o0oOOo0O0Ooo
  if 82 - 82: Oo0Ooo
  if 50 - 50: I1Ii111 * OOooOOo * OoOoOO00 / OoooooooOO % iII111i
 for iIiIi1ii in oo000oO :
  iii = oo000oO [ iIiIi1ii ]
  I11IIIiIi11 = red ( iIiIi1ii , False )
  lprint ( "Build Info-Request for private address {} ({})" . format ( I11IIIiIi11 ,
 iii ) )
  O0o0o0 = iii if len ( oo000oO ) > 1 else None
  for dest in ii1II11iIIII :
   lisp_send_info_request ( lisp_sockets , dest , port , O0o0o0 )
   if 80 - 80: I1Ii111
   if 35 - 35: Ii1I . O0 % i11iIiiIii * oO0o - OoooooooOO
   if 87 - 87: iII111i * ooOoO0o - OOooOOo . O0
   if 20 - 20: OoOoOO00 - IiII
   if 9 - 9: O0 . I11i % I1ii11iIi11i * oO0o - I1Ii111 - i1IIi
   if 66 - 66: II111iiii / Oo0Ooo
 if ( O00o != [ ] ) :
  for IiIiiiI11 in lisp_map_resolvers_list . values ( ) :
   IiIiiiI11 . resolve_dns_name ( )
   if 93 - 93: iII111i + I11i * OoooooooOO . OoO0O00
   if 40 - 40: ooOoO0o * I1Ii111 + iII111i
 return
 if 52 - 52: iII111i % I11i
 if 95 - 95: IiII + Ii1I / OoO0O00 - iII111i / I1IiiI
 if 27 - 27: Oo0Ooo + i1IIi + i11iIiiIii . OoO0O00 . OoO0O00
 if 56 - 56: I1Ii111 / OoO0O00 + o0oOOo0O0Ooo . OoooooooOO * Oo0Ooo
 if 14 - 14: OoO0O00
 if 21 - 21: II111iiii + i11iIiiIii + I11i % I1IiiI
 if 65 - 65: IiII + I1ii11iIi11i / iII111i / I1IiiI + Ii1I
 if 88 - 88: IiII % iIii1I11I1II1
def lisp_valid_address_format ( kw , value ) :
 if ( kw != "address" ) : return ( True )
 if 3 - 3: ooOoO0o / I1Ii111 % iIii1I11I1II1 % I11i * oO0o / iIii1I11I1II1
 if 75 - 75: i11iIiiIii . iII111i
 if 68 - 68: OOooOOo . I1ii11iIi11i % I1ii11iIi11i . i11iIiiIii
 if 45 - 45: oO0o % I1ii11iIi11i * I1Ii111
 if 21 - 21: O0 + i11iIiiIii
 if ( value [ 0 ] == "'" and value [ - 1 ] == "'" ) : return ( True )
 if 72 - 72: OoOoOO00 * OoooooooOO % O0 / I1ii11iIi11i % Ii1I - I11i
 if 65 - 65: iIii1I11I1II1 + II111iiii * OoO0O00 * i11iIiiIii / IiII
 if 15 - 15: OoOoOO00 % O0 - OOooOOo - oO0o . iII111i . OoO0O00
 if 52 - 52: II111iiii * o0oOOo0O0Ooo
 if ( value . find ( "." ) != - 1 ) :
  iIiIi1ii = value . split ( "." )
  if ( len ( iIiIi1ii ) != 4 ) : return ( False )
  if 95 - 95: I1Ii111 - OoooooooOO
  for Ooo0O0oOOo in iIiIi1ii :
   if ( Ooo0O0oOOo . isdigit ( ) == False ) : return ( False )
   if ( int ( Ooo0O0oOOo ) > 255 ) : return ( False )
   if 80 - 80: i1IIi / I1Ii111 / I11i . O0 * OoooooooOO + IiII
  return ( True )
  if 98 - 98: i11iIiiIii - OoO0O00 / ooOoO0o * I1Ii111 + OoO0O00
  if 30 - 30: Ii1I / iII111i * Ii1I
  if 11 - 11: OoOoOO00 - OoOoOO00 % oO0o
  if 3 - 3: I1IiiI - OoooooooOO % iIii1I11I1II1 + I1Ii111 + OoOoOO00
  if 71 - 71: i1IIi % O0 % ooOoO0o
 if ( value . find ( "-" ) != - 1 ) :
  iIiIi1ii = value . split ( "-" )
  for iiIii1I in [ "N" , "S" , "W" , "E" ] :
   if ( iiIii1I in iIiIi1ii ) :
    if ( len ( iIiIi1ii ) < 8 ) : return ( False )
    return ( True )
    if 24 - 24: O0
    if 88 - 88: OoooooooOO / Oo0Ooo / oO0o
    if 99 - 99: I1Ii111 % OoOoOO00 % IiII - Ii1I
    if 79 - 79: ooOoO0o + Oo0Ooo
    if 80 - 80: OoOoOO00 % OoO0O00 . OoO0O00 * OoO0O00 * O0
    if 18 - 18: II111iiii . o0oOOo0O0Ooo + OoO0O00
    if 69 - 69: OoO0O00 . ooOoO0o * ooOoO0o * iIii1I11I1II1
 if ( value . find ( "-" ) != - 1 ) :
  iIiIi1ii = value . split ( "-" )
  if ( len ( iIiIi1ii ) != 3 ) : return ( False )
  if 8 - 8: iII111i . oO0o . OOooOOo + iII111i . Ii1I
  for iiiIi1i in iIiIi1ii :
   try : int ( iiiIi1i , 16 )
   except : return ( False )
   if 49 - 49: OoO0O00 . i11iIiiIii * I1IiiI
  return ( True )
  if 35 - 35: i11iIiiIii . I11i . OoOoOO00 - i11iIiiIii / oO0o / IiII
  if 84 - 84: I11i . oO0o + ooOoO0o
  if 75 - 75: I1Ii111
  if 97 - 97: ooOoO0o % Oo0Ooo . o0oOOo0O0Ooo
  if 22 - 22: O0 % I11i + OoO0O00 - iII111i + I1IiiI . O0
 if ( value . find ( ":" ) != - 1 ) :
  iIiIi1ii = value . split ( ":" )
  if ( len ( iIiIi1ii ) < 2 ) : return ( False )
  if 73 - 73: ooOoO0o + O0 - I11i . I1IiiI + OOooOOo
  I11III1i111 = False
  oOOOOOo = 0
  for iiiIi1i in iIiIi1ii :
   oOOOOOo += 1
   if ( iiiIi1i == "" ) :
    if ( I11III1i111 ) :
     if ( len ( iIiIi1ii ) == oOOOOOo ) : break
     if ( oOOOOOo > 2 ) : return ( False )
     if 17 - 17: OoO0O00 % II111iiii . i1IIi . OOooOOo
    I11III1i111 = True
    continue
    if 49 - 49: II111iiii / OoOoOO00 * IiII % OoO0O00
   try : int ( iiiIi1i , 16 )
   except : return ( False )
   if 77 - 77: OoOoOO00 + OOooOOo % o0oOOo0O0Ooo
  return ( True )
  if 3 - 3: ooOoO0o / i1IIi
  if 71 - 71: Ii1I + oO0o % IiII
  if 15 - 15: ooOoO0o . Oo0Ooo
  if 42 - 42: OOooOOo . i11iIiiIii % O0 - OoO0O00
  if 34 - 34: OOooOOo % oO0o * OOooOOo * iIii1I11I1II1
 if ( value [ 0 ] == "+" ) :
  iIiIi1ii = value [ 1 : : ]
  for iI1Ii in iIiIi1ii :
   if ( iI1Ii . isdigit ( ) == False ) : return ( False )
   if 96 - 96: OoooooooOO . IiII - I1Ii111 * O0 / I1Ii111
  return ( True )
  if 52 - 52: I1ii11iIi11i % I11i * iII111i - iIii1I11I1II1 . OoOoOO00 % Ii1I
 return ( False )
 if 5 - 5: I11i / OoO0O00
 if 95 - 95: o0oOOo0O0Ooo
 if 50 - 50: I11i . oO0o
 if 50 - 50: Ii1I . OOooOOo
 if 84 - 84: OoOoOO00 * OoO0O00 + I1IiiI
 if 38 - 38: OoooooooOO % I1IiiI
 if 80 - 80: iII111i / O0 % OoooooooOO / Oo0Ooo
 if 75 - 75: ooOoO0o
 if 72 - 72: oO0o . OoooooooOO % ooOoO0o % OoO0O00 * oO0o * OoO0O00
 if 14 - 14: I11i / I11i
 if 90 - 90: O0 * OOooOOo / oO0o . Oo0Ooo * I11i
 if 93 - 93: oO0o / ooOoO0o - I1Ii111
def lisp_process_api ( process , lisp_socket , data_structure ) :
 O0O0IiII , i11Iii1Ii1i1 = data_structure . split ( "%" )
 if 2 - 2: OoOoOO00 / O0
 lprint ( "Process API request '{}', parameters: '{}'" . format ( O0O0IiII ,
 i11Iii1Ii1i1 ) )
 if 39 - 39: IiII . O0
 oooOoOOo0OOoO = [ ]
 if ( O0O0IiII == "map-cache" ) :
  if ( i11Iii1Ii1i1 == "" ) :
   oooOoOOo0OOoO = lisp_map_cache . walk_cache ( lisp_process_api_map_cache , oooOoOOo0OOoO )
  else :
   oooOoOOo0OOoO = lisp_process_api_map_cache_entry ( json . loads ( i11Iii1Ii1i1 ) )
   if 4 - 4: I1Ii111
   if 15 - 15: I11i % I11i / iIii1I11I1II1 - i11iIiiIii / i1IIi
 if ( O0O0IiII == "site-cache" ) :
  if ( i11Iii1Ii1i1 == "" ) :
   oooOoOOo0OOoO = lisp_sites_by_eid . walk_cache ( lisp_process_api_site_cache ,
 oooOoOOo0OOoO )
  else :
   oooOoOOo0OOoO = lisp_process_api_site_cache_entry ( json . loads ( i11Iii1Ii1i1 ) )
   if 9 - 9: OoooooooOO
   if 71 - 71: Ii1I
 if ( O0O0IiII == "map-server" ) :
  i11Iii1Ii1i1 = { } if ( i11Iii1Ii1i1 == "" ) else json . loads ( i11Iii1Ii1i1 )
  oooOoOOo0OOoO = lisp_process_api_ms_or_mr ( True , i11Iii1Ii1i1 )
  if 59 - 59: i1IIi * ooOoO0o . iIii1I11I1II1
 if ( O0O0IiII == "map-resolver" ) :
  i11Iii1Ii1i1 = { } if ( i11Iii1Ii1i1 == "" ) else json . loads ( i11Iii1Ii1i1 )
  oooOoOOo0OOoO = lisp_process_api_ms_or_mr ( False , i11Iii1Ii1i1 )
  if 87 - 87: ooOoO0o % I1ii11iIi11i . I1IiiI
  if 42 - 42: iII111i % i11iIiiIii % o0oOOo0O0Ooo . O0 % iII111i
  if 72 - 72: Oo0Ooo . Oo0Ooo . IiII . Oo0Ooo
  if 80 - 80: I1Ii111 + IiII + O0 - I1Ii111 . iIii1I11I1II1
  if 53 - 53: OoO0O00 / i11iIiiIii * I1Ii111
 oooOoOOo0OOoO = json . dumps ( oooOoOOo0OOoO )
 II1i111i = lisp_api_ipc ( process , oooOoOOo0OOoO )
 lisp_ipc ( II1i111i , lisp_socket , "lisp-core" )
 return
 if 62 - 62: oO0o / Oo0Ooo / IiII + I11i * ooOoO0o
 if 84 - 84: ooOoO0o + OoOoOO00 * I1ii11iIi11i % OoooooooOO . O0
 if 27 - 27: OoO0O00 * OoooooooOO - II111iiii / o0oOOo0O0Ooo
 if 76 - 76: I11i % I1Ii111 % iII111i + IiII * iII111i + OoOoOO00
 if 83 - 83: OOooOOo . ooOoO0o / IiII
 if 80 - 80: I1Ii111 . I11i - I11i + I1ii11iIi11i
 if 42 - 42: I11i / IiII % O0 - Oo0Ooo
def lisp_process_api_map_cache ( mc , data ) :
 if 33 - 33: I1Ii111
 if 1 - 1: IiII - iIii1I11I1II1 % OoooooooOO
 if 1 - 1: o0oOOo0O0Ooo - i11iIiiIii + I11i
 if 47 - 47: O0 + IiII + ooOoO0o + OOooOOo / OoOoOO00
 if ( mc . group . is_null ( ) ) : return ( lisp_gather_map_cache_data ( mc , data ) )
 if 31 - 31: oO0o * iII111i % OoOoOO00
 if ( mc . source_cache == None ) : return ( [ True , data ] )
 if 80 - 80: ooOoO0o % I1ii11iIi11i % I11i . I1Ii111
 if 3 - 3: ooOoO0o - Oo0Ooo
 if 2 - 2: iII111i . iII111i
 if 77 - 77: OOooOOo
 if 74 - 74: O0
 data = mc . source_cache . walk_cache ( lisp_gather_map_cache_data , data )
 return ( [ True , data ] )
 if 86 - 86: OoOoOO00
 if 4 - 4: OoooooooOO * OoO0O00
 if 93 - 93: OoO0O00 - I1Ii111 - OoO0O00
 if 1 - 1: o0oOOo0O0Ooo . oO0o * i11iIiiIii * IiII - OoO0O00 - OoooooooOO
 if 29 - 29: iIii1I11I1II1 + OoO0O00 * II111iiii * Ii1I * iII111i . O0
 if 6 - 6: I1IiiI - OoOoOO00
 if 63 - 63: OOooOOo - oO0o * I1IiiI
def lisp_gather_map_cache_data ( mc , data ) :
 Ooo000O00 = { }
 Ooo000O00 [ "instance-id" ] = str ( mc . eid . instance_id )
 Ooo000O00 [ "eid-prefix" ] = mc . eid . print_prefix_no_iid ( )
 if ( mc . group . is_null ( ) == False ) :
  Ooo000O00 [ "group-prefix" ] = mc . group . print_prefix_no_iid ( )
  if 60 - 60: II111iiii - Oo0Ooo
 Ooo000O00 [ "uptime" ] = lisp_print_elapsed ( mc . uptime )
 Ooo000O00 [ "expires" ] = lisp_print_elapsed ( mc . uptime )
 Ooo000O00 [ "action" ] = lisp_map_reply_action_string [ mc . action ]
 Ooo000O00 [ "ttl" ] = "--" if mc . map_cache_ttl == None else str ( mc . map_cache_ttl / 60 )
 if 43 - 43: I1IiiI - IiII - OOooOOo
 if 19 - 19: I1Ii111 / I1Ii111 - i1IIi
 if 99 - 99: O0
 if 37 - 37: iIii1I11I1II1 / I1Ii111 + OoO0O00
 if 85 - 85: ooOoO0o / I1IiiI
 OOoO000o00000 = [ ]
 for i11iII1Ii1ii111 in mc . rloc_set :
  O0ooOoO0OO000 = { }
  if ( i11iII1Ii1ii111 . rloc_exists ( ) ) :
   O0ooOoO0OO000 [ "address" ] = i11iII1Ii1ii111 . rloc . print_address_no_iid ( )
   if 7 - 7: Oo0Ooo - iIii1I11I1II1 / I1ii11iIi11i * I1IiiI + Ii1I
   if 99 - 99: i11iIiiIii - I1ii11iIi11i
  if ( i11iII1Ii1ii111 . translated_port != 0 ) :
   O0ooOoO0OO000 [ "encap-port" ] = str ( i11iII1Ii1ii111 . translated_port )
   if 64 - 64: IiII . OoOoOO00 . Oo0Ooo . I1Ii111 / I11i / Ii1I
  O0ooOoO0OO000 [ "state" ] = i11iII1Ii1ii111 . print_state ( )
  if ( i11iII1Ii1ii111 . geo ) : O0ooOoO0OO000 [ "geo" ] = i11iII1Ii1ii111 . geo . print_geo ( )
  if ( i11iII1Ii1ii111 . elp ) : O0ooOoO0OO000 [ "elp" ] = i11iII1Ii1ii111 . elp . print_elp ( False )
  if ( i11iII1Ii1ii111 . rle ) : O0ooOoO0OO000 [ "rle" ] = i11iII1Ii1ii111 . rle . print_rle ( False )
  if ( i11iII1Ii1ii111 . json ) : O0ooOoO0OO000 [ "json" ] = i11iII1Ii1ii111 . json . print_json ( False )
  if ( i11iII1Ii1ii111 . rloc_name ) : O0ooOoO0OO000 [ "rloc-name" ] = i11iII1Ii1ii111 . rloc_name
  O0oo0Oo0Oo00o = i11iII1Ii1ii111 . stats . get_stats ( False , False )
  if ( O0oo0Oo0Oo00o ) : O0ooOoO0OO000 [ "stats" ] = O0oo0Oo0Oo00o
  O0ooOoO0OO000 [ "uptime" ] = lisp_print_elapsed ( i11iII1Ii1ii111 . uptime )
  O0ooOoO0OO000 [ "upriority" ] = str ( i11iII1Ii1ii111 . priority )
  O0ooOoO0OO000 [ "uweight" ] = str ( i11iII1Ii1ii111 . weight )
  O0ooOoO0OO000 [ "mpriority" ] = str ( i11iII1Ii1ii111 . mpriority )
  O0ooOoO0OO000 [ "mweight" ] = str ( i11iII1Ii1ii111 . mweight )
  Oo0O000OOOO0 = i11iII1Ii1ii111 . last_rloc_probe_reply
  if ( Oo0O000OOOO0 ) :
   O0ooOoO0OO000 [ "last-rloc-probe-reply" ] = lisp_print_elapsed ( Oo0O000OOOO0 )
   O0ooOoO0OO000 [ "rloc-probe-rtt" ] = str ( i11iII1Ii1ii111 . rloc_probe_rtt )
   if 63 - 63: i11iIiiIii / iII111i / o0oOOo0O0Ooo
  O0ooOoO0OO000 [ "rloc-hop-count" ] = i11iII1Ii1ii111 . rloc_probe_hops
  O0ooOoO0OO000 [ "recent-rloc-hop-counts" ] = i11iII1Ii1ii111 . recent_rloc_probe_hops
  if 77 - 77: OoooooooOO % iIii1I11I1II1 - OOooOOo / OoOoOO00
  Ii1II = [ ]
  for IiI1I1 in i11iII1Ii1ii111 . recent_rloc_probe_rtts : Ii1II . append ( str ( IiI1I1 ) )
  O0ooOoO0OO000 [ "recent-rloc-probe-rtts" ] = Ii1II
  if 26 - 26: Oo0Ooo
  OOoO000o00000 . append ( O0ooOoO0OO000 )
  if 21 - 21: i11iIiiIii . OoooooooOO / ooOoO0o % iIii1I11I1II1 / OoooooooOO
 Ooo000O00 [ "rloc-set" ] = OOoO000o00000
 if 93 - 93: O0 * iIii1I11I1II1
 data . append ( Ooo000O00 )
 return ( [ True , data ] )
 if 72 - 72: II111iiii
 if 26 - 26: Oo0Ooo
 if 14 - 14: O0
 if 63 - 63: I1IiiI . iIii1I11I1II1 . Oo0Ooo % OOooOOo - iII111i + ooOoO0o
 if 64 - 64: o0oOOo0O0Ooo / Ii1I % I1Ii111 % iII111i + OOooOOo * IiII
 if 87 - 87: I1ii11iIi11i . i1IIi - I11i + OoOoOO00 . O0
 if 37 - 37: IiII
def lisp_process_api_map_cache_entry ( parms ) :
 I1I111iIi = parms [ "instance-id" ]
 I1I111iIi = 0 if ( I1I111iIi == "" ) else int ( I1I111iIi )
 if 65 - 65: ooOoO0o * Ii1I / I1IiiI . i1IIi % ooOoO0o . OoooooooOO
 if 17 - 17: ooOoO0o / OoO0O00 / I1IiiI / OOooOOo % IiII
 if 88 - 88: i1IIi - OoOoOO00
 if 66 - 66: OoooooooOO - OoooooooOO * I11i / II111iiii + oO0o / Ii1I
 I1IiiIiIIi1Ii = lisp_address ( LISP_AFI_NONE , "" , 0 , I1I111iIi )
 I1IiiIiIIi1Ii . store_prefix ( parms [ "eid-prefix" ] )
 Oo0o0OoOoOo0 = I1IiiIiIIi1Ii
 oO000O = I1IiiIiIIi1Ii
 if 7 - 7: Ii1I / iIii1I11I1II1
 if 36 - 36: iIii1I11I1II1 % i11iIiiIii
 if 35 - 35: Oo0Ooo + I1IiiI - O0 - I1Ii111
 if 64 - 64: i1IIi * OoOoOO00 / II111iiii * oO0o
 if 35 - 35: i1IIi - Ii1I - Ii1I . O0 % iII111i * iII111i
 iIiii1Ii1I = lisp_address ( LISP_AFI_NONE , "" , 0 , I1I111iIi )
 if ( parms . has_key ( "group-prefix" ) ) :
  iIiii1Ii1I . store_prefix ( parms [ "group-prefix" ] )
  Oo0o0OoOoOo0 = iIiii1Ii1I
  if 15 - 15: OoooooooOO . Ii1I * I1Ii111 . ooOoO0o % OoO0O00 * Oo0Ooo
  if 10 - 10: iII111i + i11iIiiIii . OOooOOo % iII111i - i1IIi
 oooOoOOo0OOoO = [ ]
 O0O = lisp_map_cache_lookup ( oO000O , Oo0o0OoOoOo0 )
 if ( O0O ) : OOoO0 , oooOoOOo0OOoO = lisp_process_api_map_cache ( O0O , oooOoOOo0OOoO )
 return ( oooOoOOo0OOoO )
 if 10 - 10: iIii1I11I1II1 * i11iIiiIii - O0
 if 45 - 45: oO0o % OOooOOo - IiII + o0oOOo0O0Ooo + i11iIiiIii
 if 79 - 79: IiII % I1Ii111 . I1IiiI + O0 * oO0o * ooOoO0o
 if 38 - 38: IiII
 if 78 - 78: Oo0Ooo * I1ii11iIi11i % OOooOOo / Oo0Ooo + I1ii11iIi11i * IiII
 if 2 - 2: Oo0Ooo - OoOoOO00
 if 22 - 22: OoO0O00 - oO0o - O0
def lisp_process_api_site_cache ( se , data ) :
 if 49 - 49: iIii1I11I1II1 + I1Ii111 / i11iIiiIii
 if 62 - 62: ooOoO0o . I1IiiI * i11iIiiIii
 if 2 - 2: i11iIiiIii
 if 86 - 86: I1Ii111 + o0oOOo0O0Ooo
 if ( se . group . is_null ( ) ) : return ( lisp_gather_site_cache_data ( se , data ) )
 if 17 - 17: iIii1I11I1II1
 if ( se . source_cache == None ) : return ( [ True , data ] )
 if 32 - 32: IiII - OoOoOO00
 if 88 - 88: OOooOOo - II111iiii + i1IIi * Oo0Ooo
 if 48 - 48: I1Ii111 + IiII % iII111i * iII111i + I1Ii111
 if 83 - 83: OoO0O00 . I11i * I1ii11iIi11i - II111iiii
 if 41 - 41: OoooooooOO . OoOoOO00 * iIii1I11I1II1
 data = se . source_cache . walk_cache ( lisp_gather_site_cache_data , data )
 return ( [ True , data ] )
 if 18 - 18: IiII / I1Ii111 % i1IIi * i11iIiiIii
 if 16 - 16: Oo0Ooo
 if 24 - 24: o0oOOo0O0Ooo . OoOoOO00
 if 50 - 50: I1ii11iIi11i / iIii1I11I1II1 - Oo0Ooo - i11iIiiIii % o0oOOo0O0Ooo - ooOoO0o
 if 92 - 92: OoooooooOO - I1ii11iIi11i . I11i / O0 % iII111i
 if 96 - 96: I1IiiI . oO0o % O0
 if 19 - 19: iIii1I11I1II1 + I1Ii111 / OoooooooOO % OOooOOo - i1IIi + I11i
def lisp_process_api_ms_or_mr ( ms_or_mr , data ) :
 i11i11II11i = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
 o0O0ooO0OoOo0OOO = data [ "dns-name" ] if data . has_key ( "dns-name" ) else None
 if ( data . has_key ( "address" ) ) :
  i11i11II11i . store_address ( data [ "address" ] )
  if 74 - 74: i1IIi * i11iIiiIii - o0oOOo0O0Ooo
  if 62 - 62: iIii1I11I1II1 / oO0o - OoO0O00 * I1Ii111
 ooOoO = { }
 if ( ms_or_mr ) :
  for iIoO0oOOoOoO in lisp_map_servers_list . values ( ) :
   if ( o0O0ooO0OoOo0OOO ) :
    if ( o0O0ooO0OoOo0OOO != iIoO0oOOoOoO . dns_name ) : continue
   else :
    if ( i11i11II11i . is_exact_match ( iIoO0oOOoOoO . map_server ) == False ) : continue
    if 1 - 1: I1ii11iIi11i . OoOoOO00 % o0oOOo0O0Ooo * i11iIiiIii - OOooOOo % oO0o
    if 35 - 35: I1ii11iIi11i / II111iiii * OoO0O00 - i11iIiiIii / iII111i / o0oOOo0O0Ooo
   ooOoO [ "dns-name" ] = iIoO0oOOoOoO . dns_name
   ooOoO [ "address" ] = iIoO0oOOoOoO . map_server . print_address_no_iid ( )
   ooOoO [ "ms-name" ] = "" if iIoO0oOOoOoO . ms_name == None else iIoO0oOOoOoO . ms_name
   return ( [ ooOoO ] )
   if 39 - 39: II111iiii * iII111i
 else :
  for IiIiiiI11 in lisp_map_resolvers_list . values ( ) :
   if ( o0O0ooO0OoOo0OOO ) :
    if ( o0O0ooO0OoOo0OOO != IiIiiiI11 . dns_name ) : continue
   else :
    if ( i11i11II11i . is_exact_match ( IiIiiiI11 . map_resolver ) == False ) : continue
    if 7 - 7: OOooOOo + OoOoOO00 . II111iiii * OoO0O00 . I1IiiI * o0oOOo0O0Ooo
    if 62 - 62: I1ii11iIi11i / iIii1I11I1II1 + oO0o . II111iiii
   ooOoO [ "dns-name" ] = IiIiiiI11 . dns_name
   ooOoO [ "address" ] = IiIiiiI11 . map_resolver . print_address_no_iid ( )
   ooOoO [ "mr-name" ] = "" if IiIiiiI11 . mr_name == None else IiIiiiI11 . mr_name
   return ( [ ooOoO ] )
   if 65 - 65: Oo0Ooo % i1IIi * o0oOOo0O0Ooo * IiII
   if 24 - 24: i11iIiiIii / iIii1I11I1II1 / iII111i
 return ( [ ] )
 if 31 - 31: OOooOOo . iIii1I11I1II1 - oO0o
 if 36 - 36: O0
 if 30 - 30: i11iIiiIii * Oo0Ooo . IiII
 if 65 - 65: oO0o * IiII * OOooOOo / OoooooooOO % I11i / I1Ii111
 if 21 - 21: i1IIi * iII111i + OoO0O00
 if 27 - 27: I11i / oO0o . iII111i + o0oOOo0O0Ooo - OOooOOo
 if 85 - 85: OoooooooOO
def lisp_gather_site_cache_data ( se , data ) :
 Ooo000O00 = { }
 Ooo000O00 [ "site-name" ] = se . site . site_name
 Ooo000O00 [ "instance-id" ] = str ( se . eid . instance_id )
 Ooo000O00 [ "eid-prefix" ] = se . eid . print_prefix_no_iid ( )
 if ( se . group . is_null ( ) == False ) :
  Ooo000O00 [ "group-prefix" ] = se . group . print_prefix_no_iid ( )
  if 83 - 83: iII111i * I11i . OOooOOo - OoO0O00 % IiII
 Ooo000O00 [ "registered" ] = "yes" if se . registered else "no"
 Ooo000O00 [ "first-registered" ] = lisp_print_elapsed ( se . first_registered )
 Ooo000O00 [ "last-registered" ] = lisp_print_elapsed ( se . last_registered )
 if 8 - 8: I1Ii111
 iIiIi1ii = se . last_registerer
 iIiIi1ii = "none" if iIiIi1ii . is_null ( ) else iIiIi1ii . print_address ( )
 Ooo000O00 [ "last-registerer" ] = iIiIi1ii
 Ooo000O00 [ "ams" ] = "yes" if ( se . accept_more_specifics ) else "no"
 Ooo000O00 [ "dynamic" ] = "yes" if ( se . dynamic ) else "no"
 Ooo000O00 [ "site-id" ] = str ( se . site_id )
 if ( se . xtr_id_present ) :
  Ooo000O00 [ "xtr-id" ] = "0x" + lisp_hex_string ( se . xtr_id )
  if 86 - 86: ooOoO0o + iII111i * O0 % OoO0O00 + OoOoOO00
  if 49 - 49: OOooOOo / i1IIi - II111iiii . iIii1I11I1II1 + I11i . OOooOOo
  if 9 - 9: iIii1I11I1II1 + Ii1I + I11i
  if 96 - 96: OoO0O00 + i11iIiiIii + OoO0O00
  if 7 - 7: i1IIi . I1IiiI
 OOoO000o00000 = [ ]
 for i11iII1Ii1ii111 in se . registered_rlocs :
  O0ooOoO0OO000 = { }
  O0ooOoO0OO000 [ "address" ] = i11iII1Ii1ii111 . rloc . print_address_no_iid ( ) if i11iII1Ii1ii111 . rloc_exists ( ) else "none"
  if 68 - 68: OoooooooOO
  if 91 - 91: IiII . ooOoO0o * I11i
  if ( i11iII1Ii1ii111 . geo ) : O0ooOoO0OO000 [ "geo" ] = i11iII1Ii1ii111 . geo . print_geo ( )
  if ( i11iII1Ii1ii111 . elp ) : O0ooOoO0OO000 [ "elp" ] = i11iII1Ii1ii111 . elp . print_elp ( False )
  if ( i11iII1Ii1ii111 . rle ) : O0ooOoO0OO000 [ "rle" ] = i11iII1Ii1ii111 . rle . print_rle ( False )
  if ( i11iII1Ii1ii111 . json ) : O0ooOoO0OO000 [ "json" ] = i11iII1Ii1ii111 . json . print_json ( False )
  if ( i11iII1Ii1ii111 . rloc_name ) : O0ooOoO0OO000 [ "rloc-name" ] = i11iII1Ii1ii111 . rloc_name
  O0ooOoO0OO000 [ "uptime" ] = lisp_print_elapsed ( i11iII1Ii1ii111 . uptime )
  O0ooOoO0OO000 [ "upriority" ] = str ( i11iII1Ii1ii111 . priority )
  O0ooOoO0OO000 [ "uweight" ] = str ( i11iII1Ii1ii111 . weight )
  O0ooOoO0OO000 [ "mpriority" ] = str ( i11iII1Ii1ii111 . mpriority )
  O0ooOoO0OO000 [ "mweight" ] = str ( i11iII1Ii1ii111 . mweight )
  if 39 - 39: o0oOOo0O0Ooo + i11iIiiIii
  OOoO000o00000 . append ( O0ooOoO0OO000 )
  if 69 - 69: iIii1I11I1II1 . II111iiii
 Ooo000O00 [ "registered-rlocs" ] = OOoO000o00000
 if 36 - 36: I1IiiI * i1IIi + OoOoOO00
 data . append ( Ooo000O00 )
 return ( [ True , data ] )
 if 63 - 63: OoOoOO00 - iII111i
 if 83 - 83: i1IIi / iII111i % ooOoO0o % i11iIiiIii + I1ii11iIi11i
 if 82 - 82: iIii1I11I1II1 / OOooOOo
 if 7 - 7: OoooooooOO
 if 71 - 71: OOooOOo * Oo0Ooo . Oo0Ooo % iIii1I11I1II1
 if 56 - 56: IiII * iIii1I11I1II1 - iIii1I11I1II1 . O0
 if 56 - 56: I1Ii111 / iIii1I11I1II1 % IiII * iIii1I11I1II1 . I1ii11iIi11i . OOooOOo
def lisp_process_api_site_cache_entry ( parms ) :
 I1I111iIi = parms [ "instance-id" ]
 I1I111iIi = 0 if ( I1I111iIi == "" ) else int ( I1I111iIi )
 if 1 - 1: Ii1I . Ii1I % II111iiii + I11i + OoOoOO00
 if 52 - 52: OoooooooOO - OoO0O00
 if 24 - 24: iII111i / Oo0Ooo - I1ii11iIi11i + o0oOOo0O0Ooo
 if 44 - 44: OoOoOO00 + I1IiiI . I1ii11iIi11i / i1IIi + II111iiii . Oo0Ooo
 I1IiiIiIIi1Ii = lisp_address ( LISP_AFI_NONE , "" , 0 , I1I111iIi )
 I1IiiIiIIi1Ii . store_prefix ( parms [ "eid-prefix" ] )
 if 39 - 39: o0oOOo0O0Ooo
 if 64 - 64: oO0o - i11iIiiIii
 if 62 - 62: OoooooooOO - OoooooooOO / OoO0O00 - II111iiii . iIii1I11I1II1
 if 2 - 2: O0 + o0oOOo0O0Ooo % OOooOOo . ooOoO0o % i1IIi
 if 21 - 21: OoOoOO00 / OoooooooOO + I1Ii111 - IiII
 iIiii1Ii1I = lisp_address ( LISP_AFI_NONE , "" , 0 , I1I111iIi )
 if ( parms . has_key ( "group-prefix" ) ) :
  iIiii1Ii1I . store_prefix ( parms [ "group-prefix" ] )
  if 62 - 62: Oo0Ooo % iII111i + OoooooooOO - I1ii11iIi11i % iII111i % iIii1I11I1II1
  if 54 - 54: IiII + OoOoOO00 / II111iiii % i11iIiiIii . I1Ii111
 oooOoOOo0OOoO = [ ]
 ii1II11111i = lisp_site_eid_lookup ( I1IiiIiIIi1Ii , iIiii1Ii1I , False )
 if ( ii1II11111i ) : lisp_gather_site_cache_data ( ii1II11111i , oooOoOOo0OOoO )
 return ( oooOoOOo0OOoO )
 if 69 - 69: i1IIi + ooOoO0o + Ii1I
 if 88 - 88: OoOoOO00 + iII111i % O0 + OOooOOo / OoooooooOO / OOooOOo
 if 95 - 95: ooOoO0o . Oo0Ooo % IiII + iII111i
 if 16 - 16: I11i * OoO0O00 % o0oOOo0O0Ooo - O0 % II111iiii - I1IiiI
 if 72 - 72: OoooooooOO * OoOoOO00 . OOooOOo + Ii1I . OOooOOo / II111iiii
 if 8 - 8: i1IIi
 if 1 - 1: OoOoOO00 . OoO0O00 . OoO0O00 * O0
def lisp_get_interface_instance_id ( device , source_eid ) :
 iii = None
 if ( lisp_myinterfaces . has_key ( device ) ) :
  iii = lisp_myinterfaces [ device ]
  if 97 - 97: OoooooooOO % ooOoO0o . I1Ii111 / iII111i
  if 59 - 59: II111iiii + O0 . I1ii11iIi11i . Oo0Ooo * OoO0O00
  if 35 - 35: oO0o / I1Ii111 * OOooOOo + OoooooooOO . IiII
  if 1 - 1: I1IiiI + I1Ii111 / OOooOOo . Ii1I . oO0o / I1ii11iIi11i
  if 54 - 54: OOooOOo
  if 86 - 86: oO0o * Oo0Ooo / OOooOOo
 if ( iii == None or iii . instance_id == None ) :
  return ( lisp_default_iid )
  if 18 - 18: II111iiii - I1Ii111
  if 13 - 13: i11iIiiIii - O0 % OoOoOO00 + OOooOOo * ooOoO0o
  if 55 - 55: i1IIi - OOooOOo / I11i * Ii1I
  if 20 - 20: OoOoOO00 * iIii1I11I1II1 % O0 - i1IIi
  if 51 - 51: I1ii11iIi11i * Ii1I - oO0o / O0 * OoooooooOO
  if 12 - 12: i1IIi / iIii1I11I1II1 / O0 * OoO0O00
  if 15 - 15: i11iIiiIii / IiII + Ii1I % OOooOOo % I1ii11iIi11i * oO0o
  if 24 - 24: OOooOOo / OOooOOo + I11i / iII111i . oO0o - iII111i
  if 59 - 59: I1ii11iIi11i % II111iiii - i11iIiiIii - I1Ii111
 I1I111iIi = iii . get_instance_id ( )
 if ( source_eid == None ) : return ( I1I111iIi )
 if 34 - 34: II111iiii + iII111i / IiII
 iIIiIi = source_eid . instance_id
 iiiII11ii = None
 for iii in lisp_multi_tenant_interfaces :
  if ( iii . device != device ) : continue
  OOoOo = iii . multi_tenant_eid
  source_eid . instance_id = OOoOo . instance_id
  if ( source_eid . is_more_specific ( OOoOo ) == False ) : continue
  if ( iiiII11ii == None or iiiII11ii . multi_tenant_eid . mask_len < OOoOo . mask_len ) :
   iiiII11ii = iii
   if 84 - 84: ooOoO0o - o0oOOo0O0Ooo * iIii1I11I1II1 * iIii1I11I1II1
   if 30 - 30: i1IIi + OoOoOO00 - I1ii11iIi11i % i1IIi
 source_eid . instance_id = iIIiIi
 if 2 - 2: i11iIiiIii + i1IIi
 if ( iiiII11ii == None ) : return ( I1I111iIi )
 return ( iiiII11ii . get_instance_id ( ) )
 if 1 - 1: i11iIiiIii + iIii1I11I1II1 / I11i * OoOoOO00 - OoOoOO00 % IiII
 if 68 - 68: O0 . OoooooooOO
 if 75 - 75: OoooooooOO * I1Ii111 * o0oOOo0O0Ooo + I1ii11iIi11i . iIii1I11I1II1 / O0
 if 23 - 23: oO0o - O0 * IiII + i11iIiiIii * Ii1I
 if 8 - 8: ooOoO0o / II111iiii . I1ii11iIi11i * ooOoO0o % oO0o
 if 36 - 36: I1ii11iIi11i % OOooOOo - ooOoO0o - I11i + I1IiiI
 if 37 - 37: I1ii11iIi11i * IiII
 if 65 - 65: OOooOOo / O0 . I1ii11iIi11i % i1IIi % Oo0Ooo
 if 36 - 36: i11iIiiIii - OOooOOo + iII111i + iII111i * I11i * oO0o
def lisp_allow_dynamic_eid ( device , eid ) :
 if ( lisp_myinterfaces . has_key ( device ) == False ) : return ( None )
 if 14 - 14: O0 - iII111i * I1Ii111 - I1IiiI + IiII
 iii = lisp_myinterfaces [ device ]
 iiiI111i1iIi = device if iii . dynamic_eid_device == None else iii . dynamic_eid_device
 if 99 - 99: iIii1I11I1II1 + O0 + OoooooooOO % I1IiiI - OoOoOO00 / oO0o
 if 22 - 22: iIii1I11I1II1 . I11i
 if ( iii . does_dynamic_eid_match ( eid ) ) : return ( iiiI111i1iIi )
 return ( None )
 if 21 - 21: I1IiiI % Oo0Ooo - II111iiii / I1IiiI . OoOoOO00 - o0oOOo0O0Ooo
 if 23 - 23: OoOoOO00 / O0 * OoOoOO00 . I1IiiI + Oo0Ooo . iII111i
 if 1 - 1: i11iIiiIii * OoO0O00 - OoooooooOO + OoooooooOO
 if 31 - 31: OoooooooOO - OoOoOO00 * II111iiii % ooOoO0o - ooOoO0o / i11iIiiIii
 if 8 - 8: I1IiiI . i1IIi - I11i
 if 85 - 85: OOooOOo * IiII % O0 / I1ii11iIi11i
 if 17 - 17: Oo0Ooo / i11iIiiIii / I11i - I1Ii111
def lisp_start_rloc_probe_timer ( interval , lisp_sockets ) :
 global lisp_rloc_probe_timer
 if 3 - 3: I1Ii111 - Oo0Ooo / iIii1I11I1II1
 if ( lisp_rloc_probe_timer != None ) : lisp_rloc_probe_timer . cancel ( )
 if 71 - 71: o0oOOo0O0Ooo + i11iIiiIii + OoooooooOO % OoOoOO00 - I1ii11iIi11i / OoooooooOO
 iIIiIi1iI1 = lisp_process_rloc_probe_timer
 oOOoOOoOo00O = threading . Timer ( interval , iIIiIi1iI1 , [ lisp_sockets ] )
 lisp_rloc_probe_timer = oOOoOOoOo00O
 oOOoOOoOo00O . start ( )
 return
 if 89 - 89: o0oOOo0O0Ooo * OoooooooOO + I11i + oO0o % OoO0O00
 if 1 - 1: I1ii11iIi11i . ooOoO0o
 if 54 - 54: OoOoOO00 % I1IiiI . ooOoO0o + IiII / i11iIiiIii / o0oOOo0O0Ooo
 if 51 - 51: OoOoOO00 / Ii1I . I1IiiI / Ii1I . II111iiii - iIii1I11I1II1
 if 78 - 78: I11i
 if 42 - 42: Ii1I
 if 50 - 50: iIii1I11I1II1 / Ii1I . ooOoO0o / ooOoO0o * OoOoOO00 * iII111i
def lisp_show_rloc_probe_list ( ) :
 lprint ( bold ( "----- RLOC-probe-list -----" , False ) )
 for i1i11ii1 in lisp_rloc_probe_list :
  iIIiiiiII11 = lisp_rloc_probe_list [ i1i11ii1 ]
  lprint ( "RLOC {}:" . format ( i1i11ii1 ) )
  for O0ooOoO0OO000 , Oo00OOo00O , II1I in iIIiiiiII11 :
   lprint ( "  [{}, {}, {}, {}]" . format ( hex ( id ( O0ooOoO0OO000 ) ) , Oo00OOo00O . print_prefix ( ) ,
 II1I . print_prefix ( ) , O0ooOoO0OO000 . translated_port ) )
   if 36 - 36: i1IIi * i11iIiiIii
   if 92 - 92: OoooooooOO / i11iIiiIii - oO0o * II111iiii / iIii1I11I1II1
 lprint ( bold ( "---------------------------" , False ) )
 return
 if 49 - 49: Ii1I
 if 19 - 19: OoooooooOO . i1IIi % IiII % i1IIi . oO0o
 if 66 - 66: o0oOOo0O0Ooo
 if 54 - 54: OOooOOo % I11i * oO0o . OoO0O00 . Ii1I
 if 4 - 4: IiII / Oo0Ooo % OOooOOo - OOooOOo + OoooooooOO + iIii1I11I1II1
 if 55 - 55: OoOoOO00 - I1Ii111
 if 74 - 74: OoO0O00
 if 34 - 34: OoOoOO00 * o0oOOo0O0Ooo * i11iIiiIii - I11i % oO0o / OoO0O00
 if 75 - 75: i1IIi / Ii1I * OoO0O00 - I1ii11iIi11i * O0 . IiII
def lisp_mark_rlocs_for_other_eids ( eid_list ) :
 if 11 - 11: I11i / Ii1I % oO0o
 if 50 - 50: i11iIiiIii
 if 93 - 93: i1IIi / Ii1I * II111iiii - Oo0Ooo . OoOoOO00 - OOooOOo
 if 25 - 25: I11i / ooOoO0o % ooOoO0o - OOooOOo
 i11iII1Ii1ii111 , Oo00OOo00O , II1I = eid_list [ 0 ]
 OooOOoO = [ lisp_print_eid_tuple ( Oo00OOo00O , II1I ) ]
 if 8 - 8: i11iIiiIii
 for i11iII1Ii1ii111 , Oo00OOo00O , II1I in eid_list [ 1 : : ] :
  i11iII1Ii1ii111 . state = LISP_RLOC_UNREACH_STATE
  i11iII1Ii1ii111 . last_state_change = lisp_get_timestamp ( )
  OooOOoO . append ( lisp_print_eid_tuple ( Oo00OOo00O , II1I ) )
  if 9 - 9: i11iIiiIii + Ii1I % II111iiii
  if 49 - 49: i1IIi
 OOoo0o0 = bold ( "unreachable" , False )
 ii1 = red ( i11iII1Ii1ii111 . rloc . print_address_no_iid ( ) , False )
 if 48 - 48: Oo0Ooo . i1IIi
 for I1IiiIiIIi1Ii in OooOOoO :
  Oo00OOo00O = green ( I1IiiIiIIi1Ii , False )
  lprint ( "RLOC {} went {} for EID {}" . format ( ii1 , OOoo0o0 , Oo00OOo00O ) )
  if 49 - 49: OOooOOo / OoO0O00 % I1Ii111
  if 80 - 80: iII111i
  if 17 - 17: oO0o % o0oOOo0O0Ooo . o0oOOo0O0Ooo + ooOoO0o + I1Ii111 - OoO0O00
  if 37 - 37: i1IIi * OOooOOo / OoooooooOO + II111iiii
  if 73 - 73: I1Ii111 - II111iiii / Ii1I + Ii1I
  if 41 - 41: II111iiii / II111iiii / iII111i * I1IiiI * I1Ii111 * oO0o
 for i11iII1Ii1ii111 , Oo00OOo00O , II1I in eid_list :
  O0O = lisp_map_cache . lookup_cache ( Oo00OOo00O , True )
  if ( O0O ) : lisp_write_ipc_map_cache ( True , O0O )
  if 2 - 2: OoOoOO00 - I1ii11iIi11i * I1IiiI * Ii1I
 return
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
def lisp_process_rloc_probe_timer ( lisp_sockets ) :
 lisp_set_exception ( )
 if 79 - 79: oO0o
 lisp_start_rloc_probe_timer ( LISP_RLOC_PROBE_INTERVAL , lisp_sockets )
 if ( lisp_rloc_probing == False ) : return
 if 47 - 47: OoooooooOO - i1IIi * OOooOOo
 if 11 - 11: I11i / OOooOOo . o0oOOo0O0Ooo - O0 * OoooooooOO % iII111i
 if 7 - 7: OoOoOO00 . IiII + OoooooooOO - I1Ii111 / oO0o
 if 32 - 32: iIii1I11I1II1 + I11i + OOooOOo - OoooooooOO + i11iIiiIii * o0oOOo0O0Ooo
 if ( lisp_print_rloc_probe_list ) : lisp_show_rloc_probe_list ( )
 if 8 - 8: iII111i
 if 10 - 10: OoOoOO00 % I11i
 if 49 - 49: oO0o % ooOoO0o + II111iiii
 if 21 - 21: i1IIi + OoO0O00 . I1IiiI - Oo0Ooo
 oOOoOoo = lisp_get_default_route_next_hops ( )
 if 31 - 31: Ii1I
 lprint ( "---------- Start RLOC Probing for {} entries ----------" . format ( len ( lisp_rloc_probe_list ) ) )
 if 37 - 37: I1ii11iIi11i - Ii1I / oO0o . I1IiiI % I1Ii111
 if 8 - 8: oO0o
 if 46 - 46: I1Ii111 + IiII + II111iiii . o0oOOo0O0Ooo + i11iIiiIii
 if 97 - 97: o0oOOo0O0Ooo % OoOoOO00 * O0 / iIii1I11I1II1 * OoO0O00 / i11iIiiIii
 if 1 - 1: OoooooooOO . Ii1I
 oOOOOOo = 0
 I1iI1iiii = bold ( "RLOC-probe" , False )
 for o0o0o0OO000 in lisp_rloc_probe_list . values ( ) :
  if 9 - 9: o0oOOo0O0Ooo . iII111i % OoO0O00 / i11iIiiIii + I1ii11iIi11i + i1IIi
  if 67 - 67: o0oOOo0O0Ooo
  if 58 - 58: IiII % o0oOOo0O0Ooo + i1IIi
  if 33 - 33: II111iiii
  if 61 - 61: I1Ii111
  oOoOOOOO = None
  for OOo00OOOo0o0 , I1IiiIiIIi1Ii , iIiii1Ii1I in o0o0o0OO000 :
   oO00o = OOo00OOOo0o0 . rloc . print_address_no_iid ( )
   if 66 - 66: iIii1I11I1II1 + IiII + ooOoO0o
   if 64 - 64: ooOoO0o + Oo0Ooo
   if 27 - 27: i11iIiiIii * I1Ii111 . o0oOOo0O0Ooo - iIii1I11I1II1 % Oo0Ooo % I1IiiI
   if 75 - 75: iII111i
   if 6 - 6: iII111i / OoOoOO00 / i11iIiiIii - o0oOOo0O0Ooo
   if 35 - 35: ooOoO0o / I1Ii111 / I1Ii111
   if ( OOo00OOOo0o0 . down_state ( ) ) : continue
   if 19 - 19: OoO0O00 % i11iIiiIii % iIii1I11I1II1
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
   if ( oOoOOOOO ) :
    OOo00OOOo0o0 . last_rloc_probe_nonce = oOoOOOOO . last_rloc_probe_nonce
    if 60 - 60: iIii1I11I1II1 + i1IIi + oO0o - iIii1I11I1II1 . i11iIiiIii * OoooooooOO
    if ( oOoOOOOO . translated_port == OOo00OOOo0o0 . translated_port and oOoOOOOO . rloc_name == OOo00OOOo0o0 . rloc_name ) :
     if 23 - 23: iII111i - IiII % i11iIiiIii
     Oo00OOo00O = green ( lisp_print_eid_tuple ( I1IiiIiIIi1Ii , iIiii1Ii1I ) , False )
     lprint ( "Suppress probe to duplicate RLOC {} for {}" . format ( red ( oO00o , False ) , Oo00OOo00O ) )
     if 81 - 81: OoooooooOO % OoOoOO00 / IiII / OoooooooOO + i1IIi - O0
     continue
     if 60 - 60: OOooOOo - I1Ii111 * Oo0Ooo
     if 9 - 9: OoooooooOO * OOooOOo % OoO0O00 - ooOoO0o + Ii1I
     if 39 - 39: iIii1I11I1II1 / i1IIi % I11i % I1ii11iIi11i * IiII
   I1iiiI1I1i = None
   i11iII1Ii1ii111 = None
   while ( True ) :
    i11iII1Ii1ii111 = OOo00OOOo0o0 if i11iII1Ii1ii111 == None else i11iII1Ii1ii111 . next_rloc
    if ( i11iII1Ii1ii111 == None ) : break
    if 11 - 11: II111iiii + i1IIi
    if 1 - 1: OOooOOo
    if 23 - 23: i1IIi + OoooooooOO * OOooOOo . Oo0Ooo
    if 83 - 83: OoooooooOO
    if 53 - 53: o0oOOo0O0Ooo - Oo0Ooo / IiII + O0
    if ( i11iII1Ii1ii111 . rloc_next_hop != None ) :
     if ( i11iII1Ii1ii111 . rloc_next_hop not in oOOoOoo ) :
      if ( i11iII1Ii1ii111 . up_state ( ) ) :
       I1 , IiiiIi1iIIiIi = i11iII1Ii1ii111 . rloc_next_hop
       i11iII1Ii1ii111 . state = LISP_RLOC_UNREACH_STATE
       i11iII1Ii1ii111 . last_state_change = lisp_get_timestamp ( )
       lisp_update_rtr_updown ( i11iII1Ii1ii111 . rloc , False )
       if 88 - 88: Oo0Ooo % I1Ii111 * O0 - i1IIi * OoO0O00
      OOoo0o0 = bold ( "unreachable" , False )
      lprint ( "Next-hop {}({}) for RLOC {} is {}" . format ( IiiiIi1iIIiIi , I1 ,
 red ( oO00o , False ) , OOoo0o0 ) )
      continue
      if 74 - 74: Oo0Ooo % iIii1I11I1II1 + OOooOOo
      if 50 - 50: OoO0O00 . OoooooooOO
      if 31 - 31: OoO0O00
      if 55 - 55: OoOoOO00 + I1Ii111 * o0oOOo0O0Ooo - I1ii11iIi11i + OoOoOO00
      if 6 - 6: II111iiii % iIii1I11I1II1 * I1Ii111
      if 2 - 2: IiII - I1Ii111 . iIii1I11I1II1 - Ii1I * I11i
    o0Oo00o0 = i11iII1Ii1ii111 . last_rloc_probe
    Oo0oOoOO0o = 0 if o0Oo00o0 == None else time . time ( ) - o0Oo00o0
    if ( i11iII1Ii1ii111 . unreach_state ( ) and Oo0oOoOO0o < LISP_RLOC_PROBE_INTERVAL ) :
     lprint ( "Waiting for probe-reply from RLOC {}" . format ( red ( oO00o , False ) ) )
     if 36 - 36: I1IiiI + IiII + I1Ii111 - I11i % I1Ii111
     continue
     if 38 - 38: Ii1I * i11iIiiIii + II111iiii . OoO0O00
     if 64 - 64: I11i
     if 11 - 11: I1ii11iIi11i . i11iIiiIii - Ii1I - OoooooooOO % OoO0O00 / OoO0O00
     if 42 - 42: iII111i % i1IIi + Ii1I
     if 74 - 74: O0 * I11i * OoOoOO00 / Ii1I / iIii1I11I1II1 * I1IiiI
     if 59 - 59: I1IiiI - OoOoOO00 * ooOoO0o / O0
    OO0 = lisp_get_echo_nonce ( None , oO00o )
    if ( OO0 and OO0 . request_nonce_timeout ( ) ) :
     i11iII1Ii1ii111 . state = LISP_RLOC_NO_ECHOED_NONCE_STATE
     i11iII1Ii1ii111 . last_state_change = lisp_get_timestamp ( )
     OOoo0o0 = bold ( "unreachable" , False )
     lprint ( "RLOC {} went {}, nonce-echo failed" . format ( red ( oO00o , False ) , OOoo0o0 ) )
     if 54 - 54: Oo0Ooo % iIii1I11I1II1 * Oo0Ooo
     lisp_update_rtr_updown ( i11iII1Ii1ii111 . rloc , False )
     continue
     if 80 - 80: I1ii11iIi11i - I1ii11iIi11i
     if 26 - 26: I1ii11iIi11i - I1IiiI * I1Ii111 % iIii1I11I1II1
     if 77 - 77: o0oOOo0O0Ooo + I1Ii111 . OOooOOo . i1IIi . I1IiiI
     if 100 - 100: ooOoO0o . i11iIiiIii + Ii1I - OOooOOo - i11iIiiIii - OoooooooOO
     if 42 - 42: OoOoOO00 . I1IiiI / OoOoOO00 / I1ii11iIi11i . OoO0O00
     if 67 - 67: Ii1I - O0 . OoooooooOO . I1Ii111 . o0oOOo0O0Ooo
    if ( OO0 and OO0 . recently_echoed ( ) ) :
     lprint ( ( "Suppress RLOC-probe to {}, nonce-echo " + "received" ) . format ( red ( oO00o , False ) ) )
     if 73 - 73: I11i - oO0o . I1Ii111 + oO0o
     continue
     if 48 - 48: IiII . IiII * o0oOOo0O0Ooo * II111iiii % ooOoO0o
     if 40 - 40: I1ii11iIi11i
     if 76 - 76: Oo0Ooo - I11i
     if 82 - 82: OoO0O00 % oO0o . I11i / O0 - I1Ii111
     if 39 - 39: I1IiiI
     if 8 - 8: IiII * i1IIi * i1IIi * O0
    if ( i11iII1Ii1ii111 . last_rloc_probe != None ) :
     o0Oo00o0 = i11iII1Ii1ii111 . last_rloc_probe_reply
     if ( o0Oo00o0 == None ) : o0Oo00o0 = 0
     Oo0oOoOO0o = time . time ( ) - o0Oo00o0
     if ( i11iII1Ii1ii111 . up_state ( ) and Oo0oOoOO0o >= LISP_RLOC_PROBE_REPLY_WAIT ) :
      if 69 - 69: Oo0Ooo
      i11iII1Ii1ii111 . state = LISP_RLOC_UNREACH_STATE
      i11iII1Ii1ii111 . last_state_change = lisp_get_timestamp ( )
      lisp_update_rtr_updown ( i11iII1Ii1ii111 . rloc , False )
      OOoo0o0 = bold ( "unreachable" , False )
      lprint ( "RLOC {} went {}, probe it" . format ( red ( oO00o , False ) , OOoo0o0 ) )
      if 48 - 48: iII111i
      if 11 - 11: i11iIiiIii * OoOoOO00 . OoO0O00
      lisp_mark_rlocs_for_other_eids ( o0o0o0OO000 )
      if 47 - 47: Oo0Ooo % I1Ii111 + ooOoO0o
      if 89 - 89: iII111i
      if 29 - 29: I1ii11iIi11i . ooOoO0o * II111iiii / iII111i . OoooooooOO - OoOoOO00
    i11iII1Ii1ii111 . last_rloc_probe = lisp_get_timestamp ( )
    if 99 - 99: IiII % O0 - I1Ii111 * OoO0O00
    Ooo00oOO0 = "" if i11iII1Ii1ii111 . unreach_state ( ) == False else " unreachable"
    if 37 - 37: ooOoO0o
    if 22 - 22: I1ii11iIi11i + II111iiii / OoooooooOO % o0oOOo0O0Ooo * OoOoOO00 . Oo0Ooo
    if 26 - 26: OoO0O00 % oO0o * Ii1I % OoooooooOO - oO0o
    if 46 - 46: I1IiiI + OoO0O00 - O0 * O0
    if 75 - 75: OOooOOo + iIii1I11I1II1 * OOooOOo
    if 82 - 82: iII111i - I1Ii111 - OoOoOO00
    if 96 - 96: Oo0Ooo . Oo0Ooo % o0oOOo0O0Ooo - I1IiiI * iIii1I11I1II1
    Iii1 = ""
    IiiiIi1iIIiIi = None
    if ( i11iII1Ii1ii111 . rloc_next_hop != None ) :
     I1 , IiiiIi1iIIiIi = i11iII1Ii1ii111 . rloc_next_hop
     lisp_install_host_route ( oO00o , IiiiIi1iIIiIi , True )
     Iii1 = ", send on nh {}({})" . format ( IiiiIi1iIIiIi , I1 )
     if 87 - 87: OoO0O00 % O0 . OoOoOO00 * Oo0Ooo
     if 69 - 69: OoOoOO00 % I1ii11iIi11i % II111iiii * oO0o
     if 100 - 100: i11iIiiIii . IiII - I1IiiI + I1Ii111
     if 29 - 29: Oo0Ooo . I1IiiI % ooOoO0o * I1ii11iIi11i . iII111i
     if 14 - 14: OoOoOO00 - O0 % Ii1I
    IiI1I1 = i11iII1Ii1ii111 . print_rloc_probe_rtt ( )
    I11iI = oO00o
    if ( i11iII1Ii1ii111 . translated_port != 0 ) :
     I11iI += ":{}" . format ( i11iII1Ii1ii111 . translated_port )
     if 10 - 10: ooOoO0o . I1ii11iIi11i / oO0o
    I11iI = red ( I11iI , False )
    if ( i11iII1Ii1ii111 . rloc_name != None ) :
     I11iI += " (" + blue ( i11iII1Ii1ii111 . rloc_name , False ) + ")"
     if 61 - 61: OoO0O00 . Ii1I * o0oOOo0O0Ooo
    lprint ( "Send {}{} {}, last rtt: {}{}" . format ( I1iI1iiii , Ooo00oOO0 ,
 I11iI , IiI1I1 , Iii1 ) )
    if 2 - 2: OoOoOO00 / O0
    if 87 - 87: I1ii11iIi11i * i1IIi + oO0o % OoO0O00 % iII111i . I11i
    if 65 - 65: II111iiii + Ii1I
    if 46 - 46: o0oOOo0O0Ooo
    if 17 - 17: OOooOOo
    if 75 - 75: Ii1I / i1IIi % I1ii11iIi11i . Ii1I
    if 46 - 46: II111iiii * OoO0O00
    if 77 - 77: ooOoO0o * I11i
    if ( i11iII1Ii1ii111 . rloc_next_hop != None ) :
     I1iiiI1I1i = lisp_get_host_route_next_hop ( oO00o )
     if ( I1iiiI1I1i ) : lisp_install_host_route ( oO00o , I1iiiI1I1i , False )
     if 85 - 85: OoO0O00 * I1Ii111 - OoooooooOO / iIii1I11I1II1 - i1IIi + Ii1I
     if 76 - 76: iII111i * OoooooooOO
     if 49 - 49: II111iiii - OOooOOo + II111iiii + OoOoOO00
     if 51 - 51: i11iIiiIii
     if 39 - 39: o0oOOo0O0Ooo % I1Ii111 % i1IIi - II111iiii + i11iIiiIii
     if 62 - 62: I1ii11iIi11i - I1IiiI * i11iIiiIii % oO0o
    if ( i11iII1Ii1ii111 . rloc . is_null ( ) ) :
     i11iII1Ii1ii111 . rloc . copy_address ( OOo00OOOo0o0 . rloc )
     if 63 - 63: II111iiii - Oo0Ooo
     if 55 - 55: iIii1I11I1II1 / O0 * O0 * i11iIiiIii * OoooooooOO
     if 94 - 94: II111iiii . II111iiii / OoOoOO00 % oO0o * i1IIi % Oo0Ooo
     if 78 - 78: IiII - I1IiiI
     if 59 - 59: oO0o + i1IIi - IiII % OOooOOo % iIii1I11I1II1
    i11i1III1 = None if ( iIiii1Ii1I . is_null ( ) ) else I1IiiIiIIi1Ii
    o00Ooo = I1IiiIiIIi1Ii if ( iIiii1Ii1I . is_null ( ) ) else iIiii1Ii1I
    lisp_send_map_request ( lisp_sockets , 0 , i11i1III1 , o00Ooo , i11iII1Ii1ii111 )
    oOoOOOOO = OOo00OOOo0o0
    if 53 - 53: i1IIi / i1IIi + IiII - I1Ii111 % OoO0O00 . ooOoO0o
    if 94 - 94: OoOoOO00 - i1IIi + I1IiiI - Ii1I / O0 / iII111i
    if 4 - 4: OoO0O00
    if 9 - 9: OOooOOo
    if ( IiiiIi1iIIiIi ) : lisp_install_host_route ( oO00o , IiiiIi1iIIiIi , False )
    if 87 - 87: i1IIi + O0 % iII111i * iIii1I11I1II1 + II111iiii
    if 59 - 59: OoooooooOO . ooOoO0o / OOooOOo - OOooOOo / iIii1I11I1II1 / oO0o
    if 58 - 58: iIii1I11I1II1 - OoO0O00
    if 74 - 74: o0oOOo0O0Ooo . OOooOOo
    if 96 - 96: OoooooooOO
   if ( I1iiiI1I1i ) : lisp_install_host_route ( oO00o , I1iiiI1I1i , True )
   if 19 - 19: Ii1I / OoooooooOO
   if 67 - 67: I1ii11iIi11i - OoooooooOO + OoooooooOO * o0oOOo0O0Ooo * iII111i
   if 30 - 30: I1ii11iIi11i % Ii1I
   if 2 - 2: I1IiiI . IiII . iIii1I11I1II1 - OOooOOo
   oOOOOOo += 1
   if ( ( oOOOOOo % 10 ) == 0 ) : time . sleep ( 0.020 )
   if 56 - 56: OoooooooOO + I1IiiI / I11i % i11iIiiIii / o0oOOo0O0Ooo / Ii1I
   if 27 - 27: oO0o
   if 98 - 98: OoOoOO00 . oO0o + I1ii11iIi11i
 lprint ( "---------- End RLOC Probing ----------" )
 return
 if 14 - 14: OoooooooOO
 if 73 - 73: OoOoOO00 % o0oOOo0O0Ooo
 if 28 - 28: OoO0O00
 if 15 - 15: OoO0O00 . I11i
 if 64 - 64: OOooOOo + I1Ii111 - o0oOOo0O0Ooo . II111iiii * Ii1I
 if 88 - 88: I1ii11iIi11i + OoooooooOO % I1ii11iIi11i
 if 3 - 3: I1Ii111 . O0 * OOooOOo * I11i + Ii1I * I1IiiI
 if 18 - 18: iIii1I11I1II1 % ooOoO0o . o0oOOo0O0Ooo * iII111i % iII111i
def lisp_update_rtr_updown ( rtr , updown ) :
 global lisp_ipc_socket
 if 64 - 64: I1Ii111 . I11i
 if 32 - 32: I1ii11iIi11i + IiII % OoOoOO00 . O0
 if 70 - 70: IiII + iII111i . i11iIiiIii + OoO0O00
 if 45 - 45: o0oOOo0O0Ooo - ooOoO0o
 if ( lisp_i_am_itr == False ) : return
 if 2 - 2: OOooOOo + iII111i * ooOoO0o + II111iiii
 if 88 - 88: ooOoO0o * OoO0O00 * I1ii11iIi11i - I1IiiI * IiII * I11i
 if 37 - 37: iIii1I11I1II1
 if 50 - 50: o0oOOo0O0Ooo - OOooOOo * IiII % Oo0Ooo
 if 81 - 81: OoooooooOO - OoOoOO00 % I1ii11iIi11i % I1ii11iIi11i + OoOoOO00
 if ( lisp_register_all_rtrs ) : return
 if 49 - 49: Ii1I + iIii1I11I1II1 . O0 * OOooOOo * OoooooooOO - OOooOOo
 Iii1iI1i1i1 = rtr . print_address_no_iid ( )
 if 49 - 49: I1ii11iIi11i . i1IIi + OoO0O00 % O0 + OoO0O00
 if 21 - 21: ooOoO0o * oO0o / OoooooooOO % ooOoO0o / O0
 if 24 - 24: OoO0O00 - i11iIiiIii / i11iIiiIii * I1Ii111
 if 20 - 20: IiII % iIii1I11I1II1 . iII111i + iIii1I11I1II1 + O0
 if 96 - 96: I1ii11iIi11i - IiII % OoooooooOO . iII111i
 if ( lisp_rtr_list . has_key ( Iii1iI1i1i1 ) == False ) : return
 if 30 - 30: Oo0Ooo . OoooooooOO / Oo0Ooo / oO0o
 updown = "up" if updown else "down"
 lprint ( "Send ETR IPC message, RTR {} has done {}" . format (
 red ( Iii1iI1i1i1 , False ) , bold ( updown , False ) ) )
 if 44 - 44: I1ii11iIi11i % o0oOOo0O0Ooo / iIii1I11I1II1 - o0oOOo0O0Ooo / I11i * I1Ii111
 if 49 - 49: iII111i / iII111i - OoOoOO00
 if 89 - 89: ooOoO0o
 if 16 - 16: oO0o + oO0o + i1IIi + iIii1I11I1II1
 II1i111i = "rtr%{}%{}" . format ( Iii1iI1i1i1 , updown )
 II1i111i = lisp_command_ipc ( II1i111i , "lisp-itr" )
 lisp_ipc ( II1i111i , lisp_ipc_socket , "lisp-etr" )
 return
 if 93 - 93: I1IiiI - i11iIiiIii * I1Ii111 - O0 + iII111i
 if 11 - 11: iII111i
 if 100 - 100: OoooooooOO / ooOoO0o . OoO0O00
 if 89 - 89: I11i % II111iiii
 if 35 - 35: oO0o
 if 65 - 65: II111iiii
 if 87 - 87: oO0o / OoO0O00 - oO0o
def lisp_process_rloc_probe_reply ( rloc_addr , source , port , nonce , hop_count ,
 ttl ) :
 I1iI1iiii = bold ( "RLOC-probe reply" , False )
 oooo0O0o000OO0 = rloc_addr . print_address_no_iid ( )
 i1IIiI1iI = source . print_address_no_iid ( )
 Oo00oOoO = lisp_rloc_probe_list
 if 69 - 69: Ii1I + OoooooooOO - i11iIiiIii + I11i % IiII
 if 54 - 54: OoO0O00 * oO0o / OoOoOO00 * I1Ii111 . I1ii11iIi11i / ooOoO0o
 if 2 - 2: OoOoOO00 % OoooooooOO - I1ii11iIi11i * OoooooooOO % i11iIiiIii
 if 67 - 67: I1IiiI . i11iIiiIii + OoOoOO00 / iIii1I11I1II1
 if 20 - 20: i11iIiiIii - o0oOOo0O0Ooo / IiII
 if 49 - 49: OoooooooOO
 iIiIi1ii = oooo0O0o000OO0
 if ( Oo00oOoO . has_key ( iIiIi1ii ) == False ) :
  iIiIi1ii += ":" + str ( port )
  if ( Oo00oOoO . has_key ( iIiIi1ii ) == False ) :
   iIiIi1ii = i1IIiI1iI
   if ( Oo00oOoO . has_key ( iIiIi1ii ) == False ) :
    iIiIi1ii += ":" + str ( port )
    lprint ( "    Received unsolicited {} from {}/{}" . format ( I1iI1iiii ,
 red ( oooo0O0o000OO0 , False ) , red ( i1IIiI1iI , False ) ) )
    return
    if 6 - 6: I1Ii111 * OOooOOo + o0oOOo0O0Ooo . I1ii11iIi11i * I1Ii111
    if 6 - 6: oO0o / II111iiii
    if 23 - 23: IiII - OoooooooOO / oO0o
    if 69 - 69: O0 - OoooooooOO
    if 31 - 31: o0oOOo0O0Ooo . i1IIi - i1IIi % i1IIi - iIii1I11I1II1
    if 50 - 50: IiII - OOooOOo % OoOoOO00
    if 66 - 66: IiII * i11iIiiIii
    if 64 - 64: i11iIiiIii . I1Ii111 % i11iIiiIii % I11i
 for i11iII1Ii1ii111 , I1IiiIiIIi1Ii , iIiii1Ii1I in lisp_rloc_probe_list [ iIiIi1ii ] :
  if ( lisp_i_am_rtr and i11iII1Ii1ii111 . translated_port != 0 and
 i11iII1Ii1ii111 . translated_port != port ) : continue
  if 56 - 56: o0oOOo0O0Ooo + ooOoO0o + OoooooooOO
  i11iII1Ii1ii111 . process_rloc_probe_reply ( nonce , I1IiiIiIIi1Ii , iIiii1Ii1I , hop_count , ttl )
  if 64 - 64: OOooOOo / OoOoOO00
 return
 if 30 - 30: OOooOOo % I1Ii111 - i11iIiiIii
 if 20 - 20: i1IIi * I11i / OoO0O00 / i1IIi / I1Ii111 * O0
 if 95 - 95: Ii1I + Ii1I % IiII - IiII / OOooOOo
 if 46 - 46: IiII + iII111i + II111iiii . iII111i - i11iIiiIii % OoO0O00
 if 24 - 24: oO0o + IiII . o0oOOo0O0Ooo . OoooooooOO . i11iIiiIii / I1ii11iIi11i
 if 49 - 49: IiII
 if 1 - 1: oO0o / I11i
 if 99 - 99: OoO0O00 % IiII + I1Ii111 - oO0o
def lisp_db_list_length ( ) :
 oOOOOOo = 0
 for Oo00OO0 in lisp_db_list :
  oOOOOOo += len ( Oo00OO0 . dynamic_eids ) if Oo00OO0 . dynamic_eid_configured ( ) else 1
  oOOOOOo += len ( Oo00OO0 . eid . iid_list )
  if 28 - 28: OOooOOo - O0 - O0 % i11iIiiIii * OoooooooOO
 return ( oOOOOOo )
 if 60 - 60: OoooooooOO / i1IIi / i1IIi / Ii1I . IiII
 if 24 - 24: O0
 if 6 - 6: I1IiiI . i11iIiiIii . OoooooooOO . I1IiiI . o0oOOo0O0Ooo
 if 65 - 65: i11iIiiIii
 if 46 - 46: i11iIiiIii
 if 70 - 70: i1IIi + o0oOOo0O0Ooo
 if 44 - 44: iII111i . II111iiii % o0oOOo0O0Ooo
 if 29 - 29: i11iIiiIii * i1IIi
 if 36 - 36: OoO0O00 * I11i . ooOoO0o
def lisp_format_macs ( sa , da ) :
 sa = sa [ 0 : 4 ] + "-" + sa [ 4 : 8 ] + "-" + sa [ 8 : 12 ]
 da = da [ 0 : 4 ] + "-" + da [ 4 : 8 ] + "-" + da [ 8 : 12 ]
 return ( "{} -> {}" . format ( sa , da ) )
 if 50 - 50: oO0o * OoOoOO00 / OoO0O00 / ooOoO0o + II111iiii
 if 55 - 55: II111iiii - IiII
 if 24 - 24: oO0o % Ii1I / i1IIi
 if 84 - 84: i1IIi
 if 53 - 53: OoooooooOO - i1IIi - Ii1I
 if 73 - 73: I1ii11iIi11i - Ii1I * o0oOOo0O0Ooo
 if 29 - 29: o0oOOo0O0Ooo % IiII % OOooOOo + OoooooooOO - o0oOOo0O0Ooo
def lisp_get_echo_nonce ( rloc , rloc_str ) :
 if ( lisp_nonce_echoing == False ) : return ( None )
 if 34 - 34: Ii1I
 if ( rloc ) : rloc_str = rloc . print_address_no_iid ( )
 OO0 = None
 if ( lisp_nonce_echo_list . has_key ( rloc_str ) ) :
  OO0 = lisp_nonce_echo_list [ rloc_str ]
  if 5 - 5: II111iiii . I1ii11iIi11i
 return ( OO0 )
 if 85 - 85: I1Ii111 . IiII + II111iiii
 if 92 - 92: iII111i / o0oOOo0O0Ooo * oO0o . I11i % o0oOOo0O0Ooo
 if 87 - 87: Ii1I / Oo0Ooo % iIii1I11I1II1 / iII111i
 if 42 - 42: OoO0O00 . I1IiiI . OOooOOo + ooOoO0o
 if 87 - 87: OOooOOo
 if 44 - 44: Oo0Ooo + iIii1I11I1II1
 if 67 - 67: iII111i . OOooOOo / ooOoO0o * iIii1I11I1II1
 if 29 - 29: I1Ii111 / OoOoOO00 % I1ii11iIi11i * IiII / II111iiii
def lisp_decode_dist_name ( packet ) :
 oOOOOOo = 0
 ii1i = ""
 if 30 - 30: I11i . i11iIiiIii + OOooOOo % OoooooooOO + o0oOOo0O0Ooo
 while ( packet [ 0 : 1 ] != "\0" ) :
  if ( oOOOOOo == 255 ) : return ( [ None , None ] )
  ii1i += packet [ 0 : 1 ]
  packet = packet [ 1 : : ]
  oOOOOOo += 1
  if 92 - 92: I11i
  if 92 - 92: OoO0O00 . O0 / Ii1I % Oo0Ooo . Ii1I
 packet = packet [ 1 : : ]
 return ( packet , ii1i )
 if 40 - 40: o0oOOo0O0Ooo - Ii1I . iII111i - O0
 if 53 - 53: Oo0Ooo - I1IiiI * O0 . II111iiii
 if 72 - 72: ooOoO0o - Ii1I . Ii1I . I11i / OoooooooOO + Ii1I
 if 32 - 32: O0
 if 42 - 42: i1IIi * I1ii11iIi11i * OoOoOO00
 if 43 - 43: I1ii11iIi11i % I1ii11iIi11i % i1IIi
 if 56 - 56: I1IiiI - OoO0O00 - iII111i . o0oOOo0O0Ooo . I1Ii111
 if 70 - 70: iIii1I11I1II1 - I11i
def lisp_write_flow_log ( flow_log ) :
 o0oO00O000O = open ( "./logs/lisp-flow.log" , "a" )
 if 2 - 2: oO0o / II111iiii * OoO0O00
 oOOOOOo = 0
 for iIIi1II1 in flow_log :
  I1i1iI = iIIi1II1 [ 3 ]
  Oo00oOO = I1i1iI . print_flow ( iIIi1II1 [ 0 ] , iIIi1II1 [ 1 ] , iIIi1II1 [ 2 ] )
  o0oO00O000O . write ( Oo00oOO )
  oOOOOOo += 1
  if 66 - 66: i11iIiiIii + iIii1I11I1II1 % oO0o % OoooooooOO
 o0oO00O000O . close ( )
 del ( flow_log )
 if 68 - 68: iII111i
 oOOOOOo = bold ( str ( oOOOOOo ) , False )
 lprint ( "Wrote {} flow entries to ./logs/lisp-flow.log" . format ( oOOOOOo ) )
 return
 if 3 - 3: ooOoO0o * I1IiiI
 if 62 - 62: O0 * i1IIi
 if 79 - 79: I11i - I11i
 if 25 - 25: OOooOOo / O0 / iIii1I11I1II1 + II111iiii * Ii1I
 if 74 - 74: i1IIi . I1Ii111 / O0 + Oo0Ooo * OOooOOo
 if 90 - 90: I1IiiI * II111iiii . Oo0Ooo % I1IiiI
 if 100 - 100: iIii1I11I1II1 - OoooooooOO * OoooooooOO - iII111i / ooOoO0o
def lisp_policy_command ( kv_pair ) :
 Iiiii1III1iIi = lisp_policy ( "" )
 oOOOo0O = None
 if 15 - 15: OoOoOO00 - i11iIiiIii * Ii1I
 iiII = [ ]
 for iiIii1I in range ( len ( kv_pair [ "datetime-range" ] ) ) :
  iiII . append ( lisp_policy_match ( ) )
  if 59 - 59: Ii1I % ooOoO0o % O0 . II111iiii + IiII
  if 40 - 40: Ii1I . OoOoOO00 * I1ii11iIi11i * o0oOOo0O0Ooo
 for oOOoooo00OO in kv_pair . keys ( ) :
  ooOoO = kv_pair [ oOOoooo00OO ]
  if 48 - 48: OoooooooOO + ooOoO0o * O0 % OoO0O00
  if 43 - 43: ooOoO0o + OOooOOo + II111iiii - I1IiiI
  if 58 - 58: I11i
  if 94 - 94: Oo0Ooo
  if ( oOOoooo00OO == "instance-id" ) :
   for iiIii1I in range ( len ( iiII ) ) :
    I11II1I1I = ooOoO [ iiIii1I ]
    if ( I11II1I1I == "" ) : continue
    Ii1i1iiii11 = iiII [ iiIii1I ]
    if ( Ii1i1iiii11 . source_eid == None ) :
     Ii1i1iiii11 . source_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
     if 49 - 49: I11i
    if ( Ii1i1iiii11 . dest_eid == None ) :
     Ii1i1iiii11 . dest_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
     if 29 - 29: o0oOOo0O0Ooo * I1Ii111
    Ii1i1iiii11 . source_eid . instance_id = int ( I11II1I1I )
    Ii1i1iiii11 . dest_eid . instance_id = int ( I11II1I1I )
    if 90 - 90: iII111i - I1ii11iIi11i / O0 - i1IIi
    if 74 - 74: oO0o + OoO0O00
  if ( oOOoooo00OO == "source-eid" ) :
   for iiIii1I in range ( len ( iiII ) ) :
    I11II1I1I = ooOoO [ iiIii1I ]
    if ( I11II1I1I == "" ) : continue
    Ii1i1iiii11 = iiII [ iiIii1I ]
    if ( Ii1i1iiii11 . source_eid == None ) :
     Ii1i1iiii11 . source_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
     if 98 - 98: oO0o . O0 + OoO0O00
    I1I111iIi = Ii1i1iiii11 . source_eid . instance_id
    Ii1i1iiii11 . source_eid . store_prefix ( I11II1I1I )
    Ii1i1iiii11 . source_eid . instance_id = I1I111iIi
    if 29 - 29: i1IIi
    if 3 - 3: OoO0O00 + O0 % Oo0Ooo * Oo0Ooo % i11iIiiIii
  if ( oOOoooo00OO == "destination-eid" ) :
   for iiIii1I in range ( len ( iiII ) ) :
    I11II1I1I = ooOoO [ iiIii1I ]
    if ( I11II1I1I == "" ) : continue
    Ii1i1iiii11 = iiII [ iiIii1I ]
    if ( Ii1i1iiii11 . dest_eid == None ) :
     Ii1i1iiii11 . dest_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
     if 29 - 29: ooOoO0o / iII111i / OOooOOo - iIii1I11I1II1
    I1I111iIi = Ii1i1iiii11 . dest_eid . instance_id
    Ii1i1iiii11 . dest_eid . store_prefix ( I11II1I1I )
    Ii1i1iiii11 . dest_eid . instance_id = I1I111iIi
    if 31 - 31: i1IIi * Ii1I
    if 94 - 94: oO0o / Ii1I % iIii1I11I1II1 + i1IIi / O0 - iII111i
  if ( oOOoooo00OO == "source-rloc" ) :
   for iiIii1I in range ( len ( iiII ) ) :
    I11II1I1I = ooOoO [ iiIii1I ]
    if ( I11II1I1I == "" ) : continue
    Ii1i1iiii11 = iiII [ iiIii1I ]
    Ii1i1iiii11 . source_rloc = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
    Ii1i1iiii11 . source_rloc . store_prefix ( I11II1I1I )
    if 77 - 77: o0oOOo0O0Ooo - IiII . i1IIi
    if 70 - 70: i1IIi . I1Ii111 . iII111i - OoOoOO00 + II111iiii + OOooOOo
  if ( oOOoooo00OO == "destination-rloc" ) :
   for iiIii1I in range ( len ( iiII ) ) :
    I11II1I1I = ooOoO [ iiIii1I ]
    if ( I11II1I1I == "" ) : continue
    Ii1i1iiii11 = iiII [ iiIii1I ]
    Ii1i1iiii11 . dest_rloc = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
    Ii1i1iiii11 . dest_rloc . store_prefix ( I11II1I1I )
    if 52 - 52: OOooOOo . OoOoOO00 - ooOoO0o % i1IIi
    if 15 - 15: oO0o
  if ( oOOoooo00OO == "rloc-record-name" ) :
   for iiIii1I in range ( len ( iiII ) ) :
    I11II1I1I = ooOoO [ iiIii1I ]
    if ( I11II1I1I == "" ) : continue
    Ii1i1iiii11 = iiII [ iiIii1I ]
    Ii1i1iiii11 . rloc_record_name = I11II1I1I
    if 6 - 6: oO0o . iIii1I11I1II1 - I1ii11iIi11i % IiII
    if 58 - 58: iII111i * oO0o / iII111i - Oo0Ooo / I1Ii111 * oO0o
  if ( oOOoooo00OO == "geo-name" ) :
   for iiIii1I in range ( len ( iiII ) ) :
    I11II1I1I = ooOoO [ iiIii1I ]
    if ( I11II1I1I == "" ) : continue
    Ii1i1iiii11 = iiII [ iiIii1I ]
    Ii1i1iiii11 . geo_name = I11II1I1I
    if 63 - 63: oO0o . IiII . o0oOOo0O0Ooo
    if 16 - 16: iII111i . I11i - Oo0Ooo / I1IiiI + OoOoOO00
  if ( oOOoooo00OO == "elp-name" ) :
   for iiIii1I in range ( len ( iiII ) ) :
    I11II1I1I = ooOoO [ iiIii1I ]
    if ( I11II1I1I == "" ) : continue
    Ii1i1iiii11 = iiII [ iiIii1I ]
    Ii1i1iiii11 . elp_name = I11II1I1I
    if 14 - 14: iIii1I11I1II1 / i11iIiiIii - o0oOOo0O0Ooo . iII111i * OoO0O00
    if 5 - 5: Ii1I + OoOoOO00 % I11i + IiII
  if ( oOOoooo00OO == "rle-name" ) :
   for iiIii1I in range ( len ( iiII ) ) :
    I11II1I1I = ooOoO [ iiIii1I ]
    if ( I11II1I1I == "" ) : continue
    Ii1i1iiii11 = iiII [ iiIii1I ]
    Ii1i1iiii11 . rle_name = I11II1I1I
    if 55 - 55: OoooooooOO + oO0o . o0oOOo0O0Ooo % iIii1I11I1II1 - I1Ii111
    if 40 - 40: I1IiiI . o0oOOo0O0Ooo - Oo0Ooo
  if ( oOOoooo00OO == "json-name" ) :
   for iiIii1I in range ( len ( iiII ) ) :
    I11II1I1I = ooOoO [ iiIii1I ]
    if ( I11II1I1I == "" ) : continue
    Ii1i1iiii11 = iiII [ iiIii1I ]
    Ii1i1iiii11 . json_name = I11II1I1I
    if 44 - 44: Ii1I % OoO0O00 * oO0o * OoO0O00
    if 7 - 7: I1Ii111 % i1IIi . I11i . O0 / i1IIi
  if ( oOOoooo00OO == "datetime-range" ) :
   for iiIii1I in range ( len ( iiII ) ) :
    I11II1I1I = ooOoO [ iiIii1I ]
    Ii1i1iiii11 = iiII [ iiIii1I ]
    if ( I11II1I1I == "" ) : continue
    i1I1i1i1I1 = lisp_datetime ( I11II1I1I [ 0 : 19 ] )
    i1II11 = lisp_datetime ( I11II1I1I [ 19 : : ] )
    if ( i1I1i1i1I1 . valid_datetime ( ) and i1II11 . valid_datetime ( ) ) :
     Ii1i1iiii11 . datetime_lower = i1I1i1i1I1
     Ii1i1iiii11 . datetime_upper = i1II11
     if 56 - 56: Oo0Ooo
     if 21 - 21: i11iIiiIii * o0oOOo0O0Ooo + Oo0Ooo
     if 20 - 20: IiII / OoooooooOO / O0 / I1Ii111 * ooOoO0o
     if 45 - 45: ooOoO0o / Oo0Ooo % o0oOOo0O0Ooo . ooOoO0o
     if 19 - 19: o0oOOo0O0Ooo % I11i . I1ii11iIi11i
     if 70 - 70: Oo0Ooo - I11i / I1ii11iIi11i % OoO0O00 % II111iiii
     if 72 - 72: i11iIiiIii * I11i
  if ( oOOoooo00OO == "set-action" ) :
   Iiiii1III1iIi . set_action = ooOoO
   if 69 - 69: I1Ii111 . Ii1I * I1ii11iIi11i % I11i - o0oOOo0O0Ooo
  if ( oOOoooo00OO == "set-record-ttl" ) :
   Iiiii1III1iIi . set_record_ttl = int ( ooOoO )
   if 30 - 30: ooOoO0o / Oo0Ooo * iII111i % OoooooooOO / I1ii11iIi11i
  if ( oOOoooo00OO == "set-instance-id" ) :
   if ( Iiiii1III1iIi . set_source_eid == None ) :
    Iiiii1III1iIi . set_source_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
    if 64 - 64: OoooooooOO
   if ( Iiiii1III1iIi . set_dest_eid == None ) :
    Iiiii1III1iIi . set_dest_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
    if 41 - 41: Ii1I . I11i / oO0o * OoooooooOO
   oOOOo0O = int ( ooOoO )
   Iiiii1III1iIi . set_source_eid . instance_id = oOOOo0O
   Iiiii1III1iIi . set_dest_eid . instance_id = oOOOo0O
   if 98 - 98: I1ii11iIi11i - O0 + i11iIiiIii
  if ( oOOoooo00OO == "set-source-eid" ) :
   if ( Iiiii1III1iIi . set_source_eid == None ) :
    Iiiii1III1iIi . set_source_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
    if 71 - 71: O0 - OoooooooOO
   Iiiii1III1iIi . set_source_eid . store_prefix ( ooOoO )
   if ( oOOOo0O != None ) : Iiiii1III1iIi . set_source_eid . instance_id = oOOOo0O
   if 82 - 82: i11iIiiIii * II111iiii % IiII
  if ( oOOoooo00OO == "set-destination-eid" ) :
   if ( Iiiii1III1iIi . set_dest_eid == None ) :
    Iiiii1III1iIi . set_dest_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
    if 80 - 80: Ii1I . i11iIiiIii % oO0o * o0oOOo0O0Ooo
   Iiiii1III1iIi . set_dest_eid . store_prefix ( ooOoO )
   if ( oOOOo0O != None ) : Iiiii1III1iIi . set_dest_eid . instance_id = oOOOo0O
   if 56 - 56: I1Ii111 % iII111i / II111iiii - Oo0Ooo - Oo0Ooo - iIii1I11I1II1
  if ( oOOoooo00OO == "set-rloc-address" ) :
   Iiiii1III1iIi . set_rloc_address = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
   Iiiii1III1iIi . set_rloc_address . store_address ( ooOoO )
   if 67 - 67: iII111i
  if ( oOOoooo00OO == "set-rloc-record-name" ) :
   Iiiii1III1iIi . set_rloc_record_name = ooOoO
   if 80 - 80: Ii1I . iII111i * I1IiiI * Ii1I
  if ( oOOoooo00OO == "set-elp-name" ) :
   Iiiii1III1iIi . set_elp_name = ooOoO
   if 82 - 82: OoO0O00 % OoOoOO00 * i11iIiiIii . OoO0O00 . I1ii11iIi11i + Ii1I
  if ( oOOoooo00OO == "set-geo-name" ) :
   Iiiii1III1iIi . set_geo_name = ooOoO
   if 60 - 60: i1IIi / iII111i
  if ( oOOoooo00OO == "set-rle-name" ) :
   Iiiii1III1iIi . set_rle_name = ooOoO
   if 10 - 10: I1Ii111 / OoOoOO00 * Ii1I % o0oOOo0O0Ooo . OoOoOO00 / I1ii11iIi11i
  if ( oOOoooo00OO == "set-json-name" ) :
   Iiiii1III1iIi . set_json_name = ooOoO
   if 2 - 2: iIii1I11I1II1
  if ( oOOoooo00OO == "policy-name" ) :
   Iiiii1III1iIi . policy_name = ooOoO
   if 85 - 85: O0 - ooOoO0o
   if 35 - 35: o0oOOo0O0Ooo - I1IiiI
   if 47 - 47: i11iIiiIii * iII111i . OoOoOO00 * I1Ii111 % i11iIiiIii + Ii1I
   if 65 - 65: Ii1I % i11iIiiIii
   if 98 - 98: iII111i * o0oOOo0O0Ooo % Oo0Ooo
   if 7 - 7: oO0o * OoooooooOO % o0oOOo0O0Ooo . I1Ii111 + O0
 Iiiii1III1iIi . match_clauses = iiII
 Iiiii1III1iIi . save_policy ( )
 return
 if 14 - 14: I11i * II111iiii % o0oOOo0O0Ooo / iII111i . OoooooooOO % iII111i
 if 88 - 88: iII111i
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
if 94 - 94: OoooooooOO
if 32 - 32: I1ii11iIi11i
if 8 - 8: I11i * i11iIiiIii - ooOoO0o
if 47 - 47: ooOoO0o . I1IiiI / i11iIiiIii * iII111i * I1IiiI
if 8 - 8: oO0o % oO0o . iII111i / i1IIi % IiII
if 71 - 71: OoOoOO00 + oO0o % O0 + Oo0Ooo
if 62 - 62: i1IIi . Ii1I * i1IIi * O0 . I1IiiI % o0oOOo0O0Ooo
def lisp_send_to_arista ( command , interface ) :
 interface = "" if ( interface == None ) else "interface " + interface
 if 16 - 16: I11i . Ii1I - ooOoO0o . OOooOOo % O0 / oO0o
 iiOOooo00OO = command
 if ( interface != "" ) : iiOOooo00OO = interface + ": " + iiOOooo00OO
 lprint ( "Send CLI command '{}' to hardware" . format ( iiOOooo00OO ) )
 if 25 - 25: IiII - IiII
 commands = '''
        enable
        configure
        {}
        {}
    ''' . format ( interface , command )
 if 11 - 11: I1IiiI + o0oOOo0O0Ooo / O0 + Ii1I % I11i
 os . system ( "FastCli -c '{}'" . format ( commands ) )
 return
 if 50 - 50: iII111i * OoooooooOO . O0
 if 87 - 87: ooOoO0o / Ii1I % O0 . OoO0O00
 if 55 - 55: i1IIi . o0oOOo0O0Ooo % OoooooooOO + II111iiii . OoOoOO00
 if 32 - 32: IiII * I1Ii111 * Oo0Ooo . i1IIi * OoooooooOO
 if 12 - 12: I1IiiI . OOooOOo % Oo0Ooo
 if 86 - 86: i11iIiiIii
 if 57 - 57: iII111i - OoooooooOO - ooOoO0o % II111iiii
def lisp_arista_is_alive ( prefix ) :
 i1I1Iiii1 = "enable\nsh plat trident l3 software routes {}\n" . format ( prefix )
 Ii1I11I = commands . getoutput ( "FastCli -c '{}'" . format ( i1I1Iiii1 ) )
 if 62 - 62: i11iIiiIii . Oo0Ooo / Oo0Ooo . IiII . OoooooooOO
 if 86 - 86: I1ii11iIi11i * OoOoOO00 + iII111i
 if 79 - 79: I11i - II111iiii
 if 27 - 27: I1IiiI + o0oOOo0O0Ooo * oO0o % I1IiiI
 Ii1I11I = Ii1I11I . split ( "\n" ) [ 1 ]
 OOo0oO = Ii1I11I . split ( " " )
 OOo0oO = OOo0oO [ - 1 ] . replace ( "\r" , "" )
 if 86 - 86: OoO0O00 * Ii1I - i11iIiiIii - I1ii11iIi11i + i11iIiiIii . OoooooooOO
 if 38 - 38: IiII + iIii1I11I1II1 / IiII
 if 20 - 20: oO0o * I1IiiI % I1Ii111 % i11iIiiIii
 if 44 - 44: ooOoO0o + o0oOOo0O0Ooo
 return ( OOo0oO == "Y" )
 if 10 - 10: i1IIi + o0oOOo0O0Ooo
 if 47 - 47: OOooOOo * IiII % I1Ii111 . OoOoOO00 - OoooooooOO / OoooooooOO
 if 79 - 79: I11i % i11iIiiIii % I1IiiI . OoooooooOO * oO0o . Ii1I
 if 14 - 14: iIii1I11I1II1 / I11i - o0oOOo0O0Ooo / IiII / o0oOOo0O0Ooo . OoO0O00
 if 2 - 2: I11i
 if 12 - 12: i1IIi . I1Ii111
 if 99 - 99: Oo0Ooo / i11iIiiIii
 if 81 - 81: Ii1I . i1IIi % iII111i . OoO0O00 % IiII
 if 42 - 42: iII111i / Oo0Ooo
 if 14 - 14: O0 . Oo0Ooo
 if 8 - 8: i11iIiiIii
 if 80 - 80: I1ii11iIi11i + Ii1I
 if 16 - 16: i11iIiiIii * Oo0Ooo
 if 76 - 76: iII111i . oO0o - i1IIi
 if 94 - 94: O0 % iII111i
 if 90 - 90: IiII
 if 1 - 1: I1ii11iIi11i % OoOoOO00 . I1ii11iIi11i . OoooooooOO % oO0o + Ii1I
 if 46 - 46: I1IiiI + OoO0O00 - Oo0Ooo
 if 13 - 13: OoOoOO00
 if 72 - 72: II111iiii * iII111i . II111iiii + iII111i * IiII
 if 90 - 90: oO0o * I1Ii111 / O0
 if 15 - 15: o0oOOo0O0Ooo * O0 . OOooOOo / Oo0Ooo
 if 28 - 28: OoooooooOO + OoooooooOO
 if 27 - 27: I11i . oO0o / OoooooooOO - OoO0O00 . I11i
 if 15 - 15: II111iiii * OoO0O00
 if 33 - 33: OoooooooOO . o0oOOo0O0Ooo . I1IiiI / I1ii11iIi11i . OoOoOO00
 if 58 - 58: Ii1I
 if 20 - 20: OOooOOo
 if 93 - 93: i1IIi . IiII % O0 * iII111i
 if 84 - 84: I11i
 if 99 - 99: I1ii11iIi11i
 if 78 - 78: I1Ii111 . IiII - OOooOOo
 if 93 - 93: iIii1I11I1II1
 if 33 - 33: OOooOOo . i1IIi
 if 63 - 63: II111iiii . oO0o * IiII
 if 73 - 73: iII111i . i1IIi + oO0o + OOooOOo + ooOoO0o - iIii1I11I1II1
 if 47 - 47: I11i
 if 88 - 88: OoO0O00 - OoooooooOO
 if 93 - 93: Oo0Ooo * I1IiiI
 if 60 - 60: I1Ii111 + OOooOOo % iII111i
 if 40 - 40: I11i + oO0o . O0 % oO0o
 if 12 - 12: iIii1I11I1II1
 if 9 - 9: OoOoOO00 * II111iiii / o0oOOo0O0Ooo * iII111i - II111iiii / i11iIiiIii
 if 14 - 14: i11iIiiIii + I1Ii111 . OoOoOO00 - oO0o * OoO0O00
def lisp_program_vxlan_hardware ( mc ) :
 if 23 - 23: iIii1I11I1II1
 if 32 - 32: iII111i * iIii1I11I1II1 + I1Ii111 + IiII + O0 * OoO0O00
 if 100 - 100: II111iiii
 if 34 - 34: I11i % OOooOOo - iII111i % II111iiii
 if 14 - 14: I11i * o0oOOo0O0Ooo % II111iiii
 if 36 - 36: ooOoO0o - iIii1I11I1II1 / IiII + OoOoOO00
 if ( os . path . exists ( "/persist/local/lispers.net" ) == False ) : return
 if 42 - 42: ooOoO0o + I1IiiI * iII111i / OoOoOO00 . i1IIi - OoooooooOO
 if 8 - 8: iIii1I11I1II1 - Oo0Ooo + iII111i
 if 40 - 40: o0oOOo0O0Ooo * I1IiiI
 if 75 - 75: O0 * OOooOOo / ooOoO0o + I11i
 if ( len ( mc . best_rloc_set ) == 0 ) : return
 if 56 - 56: I1IiiI % OoooooooOO % Oo0Ooo
 if 19 - 19: i11iIiiIii - iIii1I11I1II1 . i1IIi . I1Ii111 / I1IiiI * I1Ii111
 if 41 - 41: oO0o . o0oOOo0O0Ooo . I11i * OoOoOO00
 if 16 - 16: oO0o
 Ii1I1i111 = mc . eid . print_prefix_no_iid ( )
 i11iII1Ii1ii111 = mc . best_rloc_set [ 0 ] . rloc . print_address_no_iid ( )
 if 32 - 32: OoooooooOO
 if 77 - 77: Oo0Ooo . i1IIi - I11i
 if 98 - 98: O0
 if 87 - 87: OoO0O00 % I1Ii111 - OOooOOo - II111iiii + iII111i
 oo0ooOoOO0 = commands . getoutput ( "ip route get {} | egrep vlan4094" . format ( Ii1I1i111 ) )
 if 22 - 22: Oo0Ooo - I1ii11iIi11i + I11i . oO0o
 if ( oo0ooOoOO0 != "" ) :
  lprint ( "Route {} already in hardware: '{}'" . format ( green ( Ii1I1i111 , False ) , oo0ooOoOO0 ) )
  if 85 - 85: iIii1I11I1II1 / Ii1I
  return
  if 43 - 43: I1IiiI % I1Ii111 - oO0o . II111iiii / iIii1I11I1II1
  if 97 - 97: I1Ii111 + I1ii11iIi11i
  if 21 - 21: O0 + o0oOOo0O0Ooo * OoooooooOO % IiII % I1ii11iIi11i
  if 80 - 80: I11i
  if 28 - 28: OoOoOO00 * OoooooooOO * i11iIiiIii
  if 88 - 88: ooOoO0o + ooOoO0o / I1Ii111
  if 69 - 69: O0 * o0oOOo0O0Ooo + i1IIi * ooOoO0o . o0oOOo0O0Ooo
 iI1I1OoOO00OoOOo00 = commands . getoutput ( "ifconfig | egrep 'vxlan|vlan4094'" )
 if ( iI1I1OoOO00OoOOo00 . find ( "vxlan" ) == - 1 ) :
  lprint ( "No VXLAN interface found, cannot program hardware" )
  return
  if 66 - 66: iII111i
 if ( iI1I1OoOO00OoOOo00 . find ( "vlan4094" ) == - 1 ) :
  lprint ( "No vlan4094 interface found, cannot program hardware" )
  return
  if 37 - 37: i1IIi % iIii1I11I1II1 / OoOoOO00 * o0oOOo0O0Ooo - ooOoO0o . I1Ii111
 o0Oo000 = commands . getoutput ( "ip addr | egrep vlan4094 | egrep inet" )
 if ( o0Oo000 == "" ) :
  lprint ( "No IP address found on vlan4094, cannot program hardware" )
  return
  if 47 - 47: i1IIi - Ii1I / iII111i - I11i % I1Ii111
 o0Oo000 = o0Oo000 . split ( "inet " ) [ 1 ]
 o0Oo000 = o0Oo000 . split ( "/" ) [ 0 ]
 if 90 - 90: i1IIi * OoooooooOO / OOooOOo + O0
 if 32 - 32: i11iIiiIii . Oo0Ooo - iIii1I11I1II1
 if 97 - 97: II111iiii * OoOoOO00 / o0oOOo0O0Ooo % OOooOOo
 if 82 - 82: i1IIi
 if 91 - 91: OoOoOO00 . II111iiii + oO0o
 if 92 - 92: Oo0Ooo + II111iiii + OOooOOo % I1IiiI / I1ii11iIi11i
 if 25 - 25: I1ii11iIi11i - o0oOOo0O0Ooo / OoooooooOO . i11iIiiIii
 oo0OO0 = [ ]
 O0OiI1i1 = commands . getoutput ( "arp -i vlan4094" ) . split ( "\n" )
 for ii1II1II in O0OiI1i1 :
  if ( ii1II1II . find ( "vlan4094" ) == - 1 ) : continue
  if ( ii1II1II . find ( "(incomplete)" ) == - 1 ) : continue
  I1iiiI1I1i = ii1II1II . split ( " " ) [ 0 ]
  oo0OO0 . append ( I1iiiI1I1i )
  if 29 - 29: OoOoOO00 - I1IiiI / oO0o + Oo0Ooo + I1Ii111 + O0
  if 65 - 65: oO0o
 I1iiiI1I1i = None
 OoOoo0oOOO = o0Oo000
 o0Oo000 = o0Oo000 . split ( "." )
 for iiIii1I in range ( 1 , 255 ) :
  o0Oo000 [ 3 ] = str ( iiIii1I )
  iIiIi1ii = "." . join ( o0Oo000 )
  if ( iIiIi1ii in oo0OO0 ) : continue
  if ( iIiIi1ii == OoOoo0oOOO ) : continue
  I1iiiI1I1i = iIiIi1ii
  break
  if 38 - 38: iIii1I11I1II1 / I1Ii111 + ooOoO0o . II111iiii - iIii1I11I1II1
 if ( I1iiiI1I1i == None ) :
  lprint ( "Address allocation failed for vlan4094, cannot program " + "hardware" )
  if 13 - 13: Ii1I
  return
  if 34 - 34: I1IiiI / iIii1I11I1II1
  if 35 - 35: oO0o / oO0o
  if 86 - 86: o0oOOo0O0Ooo . Oo0Ooo - Ii1I / i11iIiiIii
  if 63 - 63: oO0o - O0 + I1ii11iIi11i + Ii1I / i1IIi
  if 77 - 77: O0
  if 49 - 49: o0oOOo0O0Ooo / i11iIiiIii
  if 36 - 36: II111iiii
 oO0oooo = i11iII1Ii1ii111 . split ( "." )
 iIi1Ii1iii = lisp_hex_string ( oO0oooo [ 1 ] ) . zfill ( 2 )
 i1i1iI1iII = lisp_hex_string ( oO0oooo [ 2 ] ) . zfill ( 2 )
 Oo000oO = lisp_hex_string ( oO0oooo [ 3 ] ) . zfill ( 2 )
 iiIII1IIiIIII = "00:00:00:{}:{}:{}" . format ( iIi1Ii1iii , i1i1iI1iII , Oo000oO )
 OoOoOoOOOo0O = "0000.00{}.{}{}" . format ( iIi1Ii1iii , i1i1iI1iII , Oo000oO )
 II111iIiI = "arp -i vlan4094 -s {} {}" . format ( I1iiiI1I1i , iiIII1IIiIIII )
 os . system ( II111iIiI )
 if 10 - 10: I11i . i1IIi
 if 82 - 82: I1IiiI - i1IIi . OoooooooOO - I1Ii111 * Ii1I * I1IiiI
 if 40 - 40: OoOoOO00 * ooOoO0o - Oo0Ooo . i1IIi % I11i . I11i
 if 74 - 74: OoOoOO00 * ooOoO0o * I1Ii111
 OoOO0O0O0Ooo = ( "mac address-table static {} vlan 4094 " + "interface vxlan 1 vtep {}" ) . format ( OoOoOoOOOo0O , i11iII1Ii1ii111 )
 if 75 - 75: iII111i - iIii1I11I1II1 / I1IiiI / iIii1I11I1II1
 lisp_send_to_arista ( OoOO0O0O0Ooo , None )
 if 31 - 31: iII111i . OoO0O00 / i1IIi - I1Ii111 - I11i * i1IIi
 if 8 - 8: ooOoO0o / I1ii11iIi11i * I1IiiI / OOooOOo
 if 77 - 77: OoOoOO00 - i11iIiiIii % OoOoOO00 / I1Ii111 / I1Ii111
 if 84 - 84: IiII * i11iIiiIii / iII111i % iII111i + i11iIiiIii % ooOoO0o
 if 70 - 70: iIii1I11I1II1 - I1Ii111 . oO0o . iII111i / o0oOOo0O0Ooo
 ii11iI1i = "ip route add {} via {}" . format ( Ii1I1i111 , I1iiiI1I1i )
 os . system ( ii11iI1i )
 if 29 - 29: O0 % Ii1I * ooOoO0o % O0
 lprint ( "Hardware programmed with commands:" )
 ii11iI1i = ii11iI1i . replace ( Ii1I1i111 , green ( Ii1I1i111 , False ) )
 lprint ( "  " + ii11iI1i )
 lprint ( "  " + II111iIiI )
 OoOO0O0O0Ooo = OoOO0O0O0Ooo . replace ( i11iII1Ii1ii111 , red ( i11iII1Ii1ii111 , False ) )
 lprint ( "  " + OoOO0O0O0Ooo )
 return
 if 83 - 83: oO0o
 if 95 - 95: Oo0Ooo * O0 % i1IIi / iII111i + oO0o
 if 85 - 85: iIii1I11I1II1 / I11i
 if 65 - 65: I11i / i1IIi * OoOoOO00 * Ii1I * OoO0O00
 if 74 - 74: I1ii11iIi11i . I1ii11iIi11i % IiII + OOooOOo . OoO0O00 * I11i
 if 20 - 20: OOooOOo % i1IIi * Ii1I / i11iIiiIii
 if 89 - 89: ooOoO0o
def lisp_clear_hardware_walk ( mc , parms ) :
 OOoOo = mc . eid . print_prefix_no_iid ( )
 os . system ( "ip route delete {}" . format ( OOoOo ) )
 return ( [ True , None ] )
 if 83 - 83: I11i . I11i * OOooOOo - OOooOOo
 if 46 - 46: iIii1I11I1II1 . I1Ii111 % I1IiiI
 if 22 - 22: i1IIi * I11i + II111iiii + II111iiii
 if 20 - 20: I11i
 if 37 - 37: I1Ii111
 if 19 - 19: I1ii11iIi11i / OOooOOo . I1IiiI / ooOoO0o + OoO0O00 + i11iIiiIii
 if 80 - 80: OoO0O00 . O0 / Ii1I % I1Ii111 / iII111i * I1IiiI
 if 41 - 41: O0 / OoooooooOO - i1IIi
def lisp_clear_map_cache ( ) :
 global lisp_map_cache , lisp_rloc_probe_list
 global lisp_crypto_keys_by_rloc_encap , lisp_crypto_keys_by_rloc_decap
 global lisp_rtr_list
 if 6 - 6: i1IIi - I1ii11iIi11i % I1Ii111 - II111iiii / ooOoO0o / i11iIiiIii
 III1 = bold ( "User cleared" , False )
 oOOOOOo = lisp_map_cache . cache_count
 lprint ( "{} map-cache with {} entries" . format ( III1 , oOOOOOo ) )
 if 3 - 3: OOooOOo * ooOoO0o / i11iIiiIii . OoO0O00 * ooOoO0o
 if ( lisp_program_hardware ) :
  lisp_map_cache . walk_cache ( lisp_clear_hardware_walk , None )
  if 58 - 58: i1IIi - OoO0O00 * II111iiii
 lisp_map_cache = lisp_cache ( )
 if 92 - 92: ooOoO0o / I1Ii111 . iII111i
 if 59 - 59: Ii1I - OoO0O00 % iII111i + I1ii11iIi11i * iII111i
 if 51 - 51: ooOoO0o - Oo0Ooo / iII111i . I11i - Ii1I / OOooOOo
 if 4 - 4: II111iiii + OoOoOO00 . ooOoO0o - I11i . I1IiiI
 if 46 - 46: II111iiii
 lisp_rloc_probe_list = { }
 if 38 - 38: OOooOOo % II111iiii
 if 82 - 82: i11iIiiIii . OoooooooOO % OoOoOO00 * O0 - I1Ii111
 if 78 - 78: OoOoOO00 % Ii1I % OOooOOo % Oo0Ooo % I11i . Ii1I
 if 73 - 73: OoooooooOO / i1IIi . iIii1I11I1II1
 lisp_crypto_keys_by_rloc_encap = { }
 lisp_crypto_keys_by_rloc_decap = { }
 if 89 - 89: I1Ii111
 if 29 - 29: I11i * ooOoO0o - OoooooooOO
 if 92 - 92: O0 % i1IIi / OOooOOo - oO0o
 if 83 - 83: o0oOOo0O0Ooo . OoO0O00 % iIii1I11I1II1 % OoOoOO00 - i11iIiiIii
 if 71 - 71: I1ii11iIi11i - II111iiii / O0 % i1IIi + oO0o
 lisp_rtr_list = { }
 if 73 - 73: OoooooooOO
 if 25 - 25: i1IIi . II111iiii . I1Ii111
 if 81 - 81: II111iiii + OoOoOO00 * II111iiii / iIii1I11I1II1 - Oo0Ooo % oO0o
 if 66 - 66: ooOoO0o % O0 + iIii1I11I1II1 * I1Ii111 - I1Ii111
 lisp_process_data_plane_restart ( True )
 return
 if 61 - 61: I1ii11iIi11i
 if 12 - 12: OoO0O00
 if 97 - 97: OOooOOo . Oo0Ooo . oO0o * i1IIi
 if 7 - 7: Oo0Ooo
 if 38 - 38: Oo0Ooo - I1ii11iIi11i
 if 19 - 19: Ii1I * OoO0O00 / OoO0O00 . II111iiii % iIii1I11I1II1
 if 61 - 61: I1ii11iIi11i * oO0o % iII111i + IiII + i11iIiiIii * I11i
 if 3 - 3: Ii1I
 if 71 - 71: iIii1I11I1II1 . OOooOOo / I11i / i1IIi
 if 69 - 69: i1IIi / iII111i + Ii1I + I11i + IiII
 if 86 - 86: Oo0Ooo
def lisp_encapsulate_rloc_probe ( lisp_sockets , rloc , nat_info , packet ) :
 if ( len ( lisp_sockets ) != 4 ) : return
 if 97 - 97: I1IiiI
 O00O = lisp_myrlocs [ 0 ]
 if 15 - 15: II111iiii - I11i - i11iIiiIii % Oo0Ooo * O0
 if 46 - 46: i11iIiiIii * ooOoO0o
 if 36 - 36: OoOoOO00
 if 63 - 63: ooOoO0o
 if 83 - 83: Oo0Ooo % I1IiiI % I11i
 OOo000o = len ( packet ) + 28
 o0oO0oO0O = struct . pack ( "BBHIBBHII" , 0x45 , 0 , socket . htons ( OOo000o ) , 0 , 64 ,
 17 , 0 , socket . htonl ( O00O . address ) , socket . htonl ( rloc . address ) )
 o0oO0oO0O = lisp_ip_checksum ( o0oO0oO0O )
 if 54 - 54: Oo0Ooo . oO0o * I11i . i1IIi / Oo0Ooo
 IIIiIi1iiI = struct . pack ( "HHHH" , 0 , socket . htons ( LISP_CTRL_PORT ) ,
 socket . htons ( OOo000o - 20 ) , 0 )
 if 28 - 28: I1IiiI - I1IiiI % I11i * OOooOOo
 if 97 - 97: iII111i
 if 27 - 27: ooOoO0o + OOooOOo / I1ii11iIi11i % I1Ii111
 if 68 - 68: OOooOOo % OOooOOo
 packet = lisp_packet ( o0oO0oO0O + IIIiIi1iiI + packet )
 if 61 - 61: I1ii11iIi11i - i1IIi
 if 53 - 53: o0oOOo0O0Ooo - I11i . I11i + OoooooooOO
 if 6 - 6: II111iiii + I1Ii111
 if 17 - 17: iIii1I11I1II1 / I1ii11iIi11i
 packet . inner_dest . copy_address ( rloc )
 packet . inner_dest . instance_id = 0xffffff
 packet . inner_source . copy_address ( O00O )
 packet . inner_ttl = 64
 packet . outer_dest . copy_address ( rloc )
 packet . outer_source . copy_address ( O00O )
 packet . outer_version = packet . outer_dest . afi_to_version ( )
 packet . outer_ttl = 64
 packet . encap_port = nat_info . port if nat_info else LISP_DATA_PORT
 if 85 - 85: o0oOOo0O0Ooo
 ii1 = red ( rloc . print_address_no_iid ( ) , False )
 if ( nat_info ) :
  o00 = " {}" . format ( blue ( nat_info . hostname , False ) )
  I1iI1iiii = bold ( "RLOC-probe request" , False )
 else :
  o00 = ""
  I1iI1iiii = bold ( "RLOC-probe reply" , False )
  if 20 - 20: OoooooooOO . ooOoO0o + ooOoO0o
  if 7 - 7: OoO0O00 / IiII - OoO0O00 . OOooOOo
 lprint ( ( "Data encapsulate {} to {}{} port {} for " + "NAT-traversal" ) . format ( I1iI1iiii , ii1 , o00 , packet . encap_port ) )
 if 56 - 56: iIii1I11I1II1 / O0 + Oo0Ooo
 if 5 - 5: O0 / i11iIiiIii * I1IiiI % IiII * OoO0O00
 if 67 - 67: I1Ii111 . iII111i + Oo0Ooo / i11iIiiIii
 if 47 - 47: iII111i
 if 16 - 16: OoO0O00 * II111iiii + OoO0O00 % Oo0Ooo
 if ( packet . encode ( None ) == None ) : return
 packet . print_packet ( "Send" , True )
 if 60 - 60: OOooOOo . Ii1I
 Iiio0OO0O0 = lisp_sockets [ 3 ]
 packet . send_packet ( Iiio0OO0O0 , packet . outer_dest )
 del ( packet )
 return
 if 91 - 91: OoO0O00
 if 14 - 14: i1IIi - II111iiii * I11i
 if 89 - 89: II111iiii * oO0o . OoooooooOO / IiII / IiII + iII111i
 if 15 - 15: OoOoOO00 . IiII / iIii1I11I1II1 . OoooooooOO
 if 14 - 14: IiII * OoooooooOO - iIii1I11I1II1
 if 11 - 11: I1IiiI + Oo0Ooo % I1Ii111 * Ii1I - iIii1I11I1II1 % I1ii11iIi11i
 if 43 - 43: o0oOOo0O0Ooo * o0oOOo0O0Ooo . iII111i / Oo0Ooo - i11iIiiIii
 if 66 - 66: I1IiiI / i1IIi + o0oOOo0O0Ooo % IiII - OoOoOO00 / Oo0Ooo
def lisp_get_default_route_next_hops ( ) :
 if 22 - 22: oO0o % I1Ii111 - I1Ii111 / I1Ii111
 if 25 - 25: OoooooooOO / oO0o / ooOoO0o / I1IiiI * I1ii11iIi11i . o0oOOo0O0Ooo
 if 30 - 30: o0oOOo0O0Ooo / i11iIiiIii
 if 33 - 33: OOooOOo % OoooooooOO
 if ( lisp_is_macos ( ) ) :
  i1I1Iiii1 = "route -n get default"
  oO0O00000OO = commands . getoutput ( i1I1Iiii1 ) . split ( "\n" )
  Iii1ii = iii = None
  for o0oO00O000O in oO0O00000OO :
   if ( o0oO00O000O . find ( "gateway: " ) != - 1 ) : Iii1ii = o0oO00O000O . split ( ": " ) [ 1 ]
   if ( o0oO00O000O . find ( "interface: " ) != - 1 ) : iii = o0oO00O000O . split ( ": " ) [ 1 ]
   if 53 - 53: ooOoO0o . ooOoO0o
  return ( [ [ iii , Iii1ii ] ] )
  if 80 - 80: i11iIiiIii % I1Ii111 % I1IiiI / I1IiiI + oO0o + iII111i
  if 18 - 18: OoO0O00 * ooOoO0o
  if 32 - 32: oO0o . OoooooooOO - o0oOOo0O0Ooo + II111iiii
  if 4 - 4: OOooOOo * I1IiiI - I11i - I11i
  if 67 - 67: I1IiiI
 i1I1Iiii1 = "ip route | egrep 'default via'"
 ooOoO0o0O0O0 = commands . getoutput ( i1I1Iiii1 ) . split ( "\n" )
 if 32 - 32: oO0o * i11iIiiIii - I11i % Oo0Ooo * I1ii11iIi11i
 I1II1iiII = [ ]
 for oo0ooOoOO0 in ooOoO0o0O0O0 :
  if ( oo0ooOoOO0 . find ( " metric " ) != - 1 ) : continue
  O0ooOoO0OO000 = oo0ooOoOO0 . split ( " " )
  try :
   oooOO = O0ooOoO0OO000 . index ( "via" ) + 1
   if ( oooOO >= len ( O0ooOoO0OO000 ) ) : continue
   i1ioooo0OooO = O0ooOoO0OO000 . index ( "dev" ) + 1
   if ( i1ioooo0OooO >= len ( O0ooOoO0OO000 ) ) : continue
  except :
   continue
   if 68 - 68: OoOoOO00 + I1ii11iIi11i % i11iIiiIii
   if 58 - 58: OoO0O00 / Oo0Ooo + Ii1I
  I1II1iiII . append ( [ O0ooOoO0OO000 [ i1ioooo0OooO ] , O0ooOoO0OO000 [ oooOO ] ] )
  if 63 - 63: OOooOOo / I1ii11iIi11i
 return ( I1II1iiII )
 if 86 - 86: O0 + iII111i + OoooooooOO / iII111i * I1ii11iIi11i * OoooooooOO
 if 89 - 89: oO0o - OOooOOo / iII111i - I1IiiI
 if 78 - 78: iIii1I11I1II1 + O0 + IiII . I11i / i11iIiiIii . O0
 if 21 - 21: OoOoOO00 * OOooOOo + oO0o + O0
 if 59 - 59: i1IIi / OoooooooOO . OoO0O00 / OOooOOo % o0oOOo0O0Ooo - i11iIiiIii
 if 58 - 58: IiII . Ii1I + II111iiii
 if 31 - 31: i11iIiiIii + i11iIiiIii + I11i * Oo0Ooo . I11i
def lisp_get_host_route_next_hop ( rloc ) :
 i1I1Iiii1 = "ip route | egrep '{} via'" . format ( rloc )
 oo0ooOoOO0 = commands . getoutput ( i1I1Iiii1 ) . split ( " " )
 if 28 - 28: OOooOOo * iIii1I11I1II1 * OoOoOO00
 try : I1Iiiiiii = oo0ooOoOO0 . index ( "via" ) + 1
 except : return ( None )
 if 75 - 75: Oo0Ooo % IiII + II111iiii + oO0o
 if ( I1Iiiiiii >= len ( oo0ooOoOO0 ) ) : return ( None )
 return ( oo0ooOoOO0 [ I1Iiiiiii ] )
 if 35 - 35: I1ii11iIi11i - oO0o - O0 / iII111i % IiII
 if 10 - 10: OOooOOo + oO0o - I1Ii111 . I1IiiI
 if 11 - 11: I1ii11iIi11i . I1Ii111 / o0oOOo0O0Ooo + IiII
 if 73 - 73: OoO0O00 . i11iIiiIii * OoO0O00 * i1IIi + I11i
 if 27 - 27: i11iIiiIii / OoOoOO00 % O0 / II111iiii . I11i - ooOoO0o
 if 54 - 54: oO0o * II111iiii
 if 79 - 79: o0oOOo0O0Ooo . ooOoO0o . Oo0Ooo * OoooooooOO
def lisp_install_host_route ( dest , nh , install ) :
 install = "add" if install else "delete"
 Iii1 = "none" if nh == None else nh
 if 98 - 98: ooOoO0o
 lprint ( "{} host-route {}, nh {}" . format ( install . title ( ) , dest , Iii1 ) )
 if 73 - 73: I1Ii111
 if ( nh == None ) :
  Iii1i = "ip route {} {}/32" . format ( install , dest )
 else :
  Iii1i = "ip route {} {}/32 via {}" . format ( install , dest , nh )
  if 97 - 97: OoO0O00 * Ii1I + Oo0Ooo
 os . system ( Iii1i )
 return
 if 83 - 83: II111iiii - Oo0Ooo % II111iiii * o0oOOo0O0Ooo
 if 51 - 51: iII111i * iIii1I11I1II1 % Ii1I * Ii1I + i11iIiiIii . OoooooooOO
 if 54 - 54: i11iIiiIii . iIii1I11I1II1 * iIii1I11I1II1 + Ii1I % I11i - OoO0O00
 if 16 - 16: IiII % iIii1I11I1II1 * i11iIiiIii + O0
 if 76 - 76: iII111i * OOooOOo
 if 7 - 7: ooOoO0o + o0oOOo0O0Ooo + o0oOOo0O0Ooo
 if 73 - 73: IiII % I11i % i11iIiiIii + ooOoO0o
 if 83 - 83: Ii1I * I1Ii111 * i11iIiiIii / iIii1I11I1II1 % I1ii11iIi11i
def lisp_checkpoint ( checkpoint_list ) :
 if ( lisp_checkpoint_map_cache == False ) : return
 if 40 - 40: iII111i
 o0oO00O000O = open ( lisp_checkpoint_filename , "w" )
 for Ooo000O00 in checkpoint_list :
  o0oO00O000O . write ( Ooo000O00 + "\n" )
  if 21 - 21: I1Ii111 / iII111i + Oo0Ooo / I1ii11iIi11i / I1Ii111
 o0oO00O000O . close ( )
 lprint ( "{} {} entries to file '{}'" . format ( bold ( "Checkpoint" , False ) ,
 len ( checkpoint_list ) , lisp_checkpoint_filename ) )
 return
 if 33 - 33: OoooooooOO
 if 59 - 59: i11iIiiIii - OoooooooOO . ooOoO0o / i11iIiiIii % iIii1I11I1II1 * I1ii11iIi11i
 if 45 - 45: I1ii11iIi11i * I1ii11iIi11i
 if 31 - 31: OoO0O00 - OOooOOo . iII111i * I1Ii111 * iII111i + I1ii11iIi11i
 if 5 - 5: Oo0Ooo . I1Ii111
 if 77 - 77: i11iIiiIii / I1Ii111 / I1ii11iIi11i % oO0o
 if 83 - 83: Ii1I % iIii1I11I1II1 / I1ii11iIi11i + I11i
 if 23 - 23: iIii1I11I1II1 - I1IiiI
def lisp_load_checkpoint ( ) :
 if ( lisp_checkpoint_map_cache == False ) : return
 if ( os . path . exists ( lisp_checkpoint_filename ) == False ) : return
 if 51 - 51: OoooooooOO / IiII / I1ii11iIi11i . Oo0Ooo - o0oOOo0O0Ooo * OoooooooOO
 o0oO00O000O = open ( lisp_checkpoint_filename , "r" )
 if 40 - 40: OoO0O00 / IiII . O0 / I1IiiI + OoO0O00 . o0oOOo0O0Ooo
 oOOOOOo = 0
 for Ooo000O00 in o0oO00O000O :
  oOOOOOo += 1
  Oo00OOo00O = Ooo000O00 . split ( " rloc " )
  I1II = [ ] if ( Oo00OOo00O [ 1 ] in [ "native-forward\n" , "\n" ] ) else Oo00OOo00O [ 1 ] . split ( ", " )
  if 25 - 25: ooOoO0o * I1Ii111 * oO0o
  if 64 - 64: Ii1I / I1ii11iIi11i
  OOoO000o00000 = [ ]
  for i11iII1Ii1ii111 in I1II :
   iiI1iI1 = lisp_rloc ( False )
   O0ooOoO0OO000 = i11iII1Ii1ii111 . split ( " " )
   iiI1iI1 . rloc . store_address ( O0ooOoO0OO000 [ 0 ] )
   iiI1iI1 . priority = int ( O0ooOoO0OO000 [ 1 ] )
   iiI1iI1 . weight = int ( O0ooOoO0OO000 [ 2 ] )
   OOoO000o00000 . append ( iiI1iI1 )
   if 30 - 30: OoooooooOO + O0 / I1ii11iIi11i * o0oOOo0O0Ooo
   if 11 - 11: O0 + OoO0O00 - Oo0Ooo - Oo0Ooo . i11iIiiIii
  O0O = lisp_mapping ( "" , "" , OOoO000o00000 )
  if ( O0O != None ) :
   O0O . eid . store_prefix ( Oo00OOo00O [ 0 ] )
   O0O . checkpoint_entry = True
   O0O . map_cache_ttl = LISP_NMR_TTL * 60
   if ( OOoO000o00000 == [ ] ) : O0O . action = LISP_NATIVE_FORWARD_ACTION
   O0O . add_cache ( )
   continue
   if 15 - 15: Ii1I % i11iIiiIii / OoOoOO00
   if 85 - 85: ooOoO0o . i1IIi / iII111i % iIii1I11I1II1 / II111iiii / I1Ii111
  oOOOOOo -= 1
  if 60 - 60: iIii1I11I1II1 - iIii1I11I1II1 . I11i
  if 55 - 55: OoO0O00
 o0oO00O000O . close ( )
 lprint ( "{} {} map-cache entries from file '{}'" . format (
 bold ( "Loaded" , False ) , oOOOOOo , lisp_checkpoint_filename ) )
 return
 if 87 - 87: Ii1I - iII111i / O0 - o0oOOo0O0Ooo - iIii1I11I1II1 % Ii1I
 if 47 - 47: iII111i * I1Ii111 % o0oOOo0O0Ooo / OoOoOO00 / OoO0O00 % OoO0O00
 if 43 - 43: Oo0Ooo
 if 34 - 34: OoO0O00 . i1IIi + IiII * IiII
 if 76 - 76: OOooOOo
 if 54 - 54: O0 * II111iiii * OOooOOo
 if 44 - 44: I1IiiI
 if 66 - 66: o0oOOo0O0Ooo
 if 40 - 40: OOooOOo * Ii1I
 if 38 - 38: ooOoO0o
 if 5 - 5: OoooooooOO + iII111i - I11i
 if 95 - 95: OOooOOo / i11iIiiIii - Ii1I + I1ii11iIi11i
 if 7 - 7: I1ii11iIi11i
 if 37 - 37: O0 . II111iiii
def lisp_write_checkpoint_entry ( checkpoint_list , mc ) :
 if ( lisp_checkpoint_map_cache == False ) : return
 if 70 - 70: o0oOOo0O0Ooo / iII111i + i1IIi + I11i % iIii1I11I1II1 % Oo0Ooo
 Ooo000O00 = "{} rloc " . format ( mc . eid . print_prefix ( ) )
 if 1 - 1: O0 + OoO0O00 . i11iIiiIii + I1Ii111 - OoO0O00 - IiII
 for iiI1iI1 in mc . rloc_set :
  if ( iiI1iI1 . rloc . is_null ( ) ) : continue
  Ooo000O00 += "{} {} {}, " . format ( iiI1iI1 . rloc . print_address_no_iid ( ) ,
 iiI1iI1 . priority , iiI1iI1 . weight )
  if 1 - 1: I1ii11iIi11i / i1IIi . I1IiiI / Ii1I
  if 19 - 19: iIii1I11I1II1 / Oo0Ooo . O0 - Oo0Ooo
 if ( mc . rloc_set != [ ] ) :
  Ooo000O00 = Ooo000O00 [ 0 : - 2 ]
 elif ( mc . action == LISP_NATIVE_FORWARD_ACTION ) :
  Ooo000O00 += "native-forward"
  if 74 - 74: I1ii11iIi11i * OoooooooOO . iII111i
  if 45 - 45: I1IiiI - IiII % ooOoO0o - IiII . Oo0Ooo - o0oOOo0O0Ooo
 checkpoint_list . append ( Ooo000O00 )
 return
 if 27 - 27: iII111i
 if 64 - 64: iIii1I11I1II1 - OOooOOo . iII111i % o0oOOo0O0Ooo / II111iiii % OoooooooOO
 if 87 - 87: OoooooooOO
 if 70 - 70: o0oOOo0O0Ooo % OoooooooOO % I1IiiI . OoOoOO00 * I1IiiI - ooOoO0o
 if 92 - 92: I1IiiI . I11i
 if 66 - 66: I1Ii111 / I11i / OoooooooOO % OoOoOO00 . oO0o * iII111i
 if 34 - 34: I1ii11iIi11i * I1ii11iIi11i % I11i / OOooOOo % oO0o . OoOoOO00
def lisp_check_dp_socket ( ) :
 III1ii1iiI = lisp_ipc_dp_socket_name
 if ( os . path . exists ( III1ii1iiI ) == False ) :
  OoOoooo = bold ( "does not exist" , False )
  lprint ( "Socket '{}' {}" . format ( III1ii1iiI , OoOoooo ) )
  return ( False )
  if 49 - 49: OoOoOO00 . I1IiiI . IiII / OoooooooOO . i11iIiiIii
 return ( True )
 if 42 - 42: oO0o / I1ii11iIi11i - iIii1I11I1II1 + i1IIi * iIii1I11I1II1 * Ii1I
 if 37 - 37: I1Ii111 + i1IIi * o0oOOo0O0Ooo - i11iIiiIii
 if 92 - 92: I1Ii111 - I1IiiI + Ii1I / iII111i % OOooOOo
 if 32 - 32: i1IIi . iII111i - Ii1I % iII111i % II111iiii - oO0o
 if 36 - 36: OoooooooOO * OoooooooOO . ooOoO0o . O0
 if 5 - 5: I11i % I1IiiI - OoO0O00 . Oo0Ooo
 if 79 - 79: iII111i + IiII % I11i . Oo0Ooo / IiII * iII111i
def lisp_write_to_dp_socket ( entry ) :
 try :
  i1IiIiII1 = json . dumps ( entry )
  iiIII1IIiIi1i = bold ( "Write IPC" , False )
  lprint ( "{} record to named socket: '{}'" . format ( iiIII1IIiIi1i , i1IiIiII1 ) )
  lisp_ipc_dp_socket . sendto ( i1IiIiII1 , lisp_ipc_dp_socket_name )
 except :
  lprint ( "Failed to write IPC record to named socket: '{}'" . format ( i1IiIiII1 ) )
  if 56 - 56: IiII
 return
 if 35 - 35: Ii1I + Ii1I + iIii1I11I1II1 + I1Ii111 * OoO0O00 % o0oOOo0O0Ooo
 if 64 - 64: I1IiiI / OoOoOO00
 if 89 - 89: o0oOOo0O0Ooo - OOooOOo * I1Ii111 . i1IIi % I1IiiI . I11i
 if 99 - 99: I1Ii111 * ooOoO0o
 if 9 - 9: I1Ii111
 if 26 - 26: iIii1I11I1II1 - I11i . Oo0Ooo - I1Ii111
 if 3 - 3: I1IiiI + I1ii11iIi11i - I11i
 if 15 - 15: OoOoOO00 . Oo0Ooo / ooOoO0o + Oo0Ooo - OoooooooOO - o0oOOo0O0Ooo
 if 64 - 64: OOooOOo
def lisp_write_ipc_keys ( rloc ) :
 oO00o = rloc . rloc . print_address_no_iid ( )
 OoO0o = rloc . translated_port
 if ( OoO0o != 0 ) : oO00o += ":" + str ( OoO0o )
 if ( lisp_rloc_probe_list . has_key ( oO00o ) == False ) : return
 if 44 - 44: O0 % ooOoO0o - iIii1I11I1II1 * i11iIiiIii . OoOoOO00
 for O0ooOoO0OO000 , Oo00OOo00O , II1I in lisp_rloc_probe_list [ oO00o ] :
  O0O = lisp_map_cache . lookup_cache ( Oo00OOo00O , True )
  if ( O0O == None ) : continue
  lisp_write_ipc_map_cache ( True , O0O )
  if 32 - 32: I1ii11iIi11i - iII111i
 return
 if 34 - 34: OOooOOo . i1IIi * o0oOOo0O0Ooo - I1Ii111 + I1ii11iIi11i
 if 32 - 32: i11iIiiIii . I1Ii111
 if 38 - 38: O0
 if 50 - 50: i11iIiiIii * OoO0O00 + iII111i / O0 * oO0o % ooOoO0o
 if 6 - 6: OoO0O00 . o0oOOo0O0Ooo / Ii1I + Ii1I
 if 59 - 59: II111iiii - o0oOOo0O0Ooo * OoooooooOO
 if 83 - 83: oO0o . iIii1I11I1II1 . iII111i % Oo0Ooo
def lisp_write_ipc_map_cache ( add_or_delete , mc , dont_send = False ) :
 if ( lisp_i_am_etr ) : return
 if ( lisp_ipc_dp_socket == None ) : return
 if ( lisp_check_dp_socket ( ) == False ) : return
 if 48 - 48: oO0o % OoO0O00 - OoooooooOO . IiII
 if 11 - 11: I1Ii111 % o0oOOo0O0Ooo - o0oOOo0O0Ooo % OoooooooOO . o0oOOo0O0Ooo - I1ii11iIi11i
 if 33 - 33: OoO0O00 + II111iiii . Oo0Ooo * I1Ii111
 if 63 - 63: OoooooooOO + OoOoOO00 - OoooooooOO
 OO0oOoiii1IIIiI = "add" if add_or_delete else "delete"
 Ooo000O00 = { "type" : "map-cache" , "opcode" : OO0oOoiii1IIIiI }
 if 88 - 88: ooOoO0o * ooOoO0o
 OO000000ooO0 = ( mc . group . is_null ( ) == False )
 if ( OO000000ooO0 ) :
  Ooo000O00 [ "eid-prefix" ] = mc . group . print_prefix_no_iid ( )
  Ooo000O00 [ "rles" ] = [ ]
 else :
  Ooo000O00 [ "eid-prefix" ] = mc . eid . print_prefix_no_iid ( )
  Ooo000O00 [ "rlocs" ] = [ ]
  if 25 - 25: I1Ii111 - Ii1I
 Ooo000O00 [ "instance-id" ] = str ( mc . eid . instance_id )
 if 37 - 37: OOooOOo % OoO0O00 - iIii1I11I1II1 . II111iiii
 if ( OO000000ooO0 ) :
  if ( len ( mc . rloc_set ) >= 1 and mc . rloc_set [ 0 ] . rle ) :
   for OO in mc . rloc_set [ 0 ] . rle . rle_forwarding_list :
    iIiIi1ii = OO . address . print_address_no_iid ( )
    OoO0o = str ( 4341 ) if OO . translated_port == 0 else str ( OO . translated_port )
    if 37 - 37: IiII
    O0ooOoO0OO000 = { "rle" : iIiIi1ii , "port" : OoO0o }
    iIiIIIii1iI , iI11io0o0oO = OO . get_encap_keys ( )
    O0ooOoO0OO000 = lisp_build_json_keys ( O0ooOoO0OO000 , iIiIIIii1iI , iI11io0o0oO , "encrypt-key" )
    Ooo000O00 [ "rles" ] . append ( O0ooOoO0OO000 )
    if 36 - 36: i1IIi * IiII * I1ii11iIi11i
    if 28 - 28: I1ii11iIi11i - i11iIiiIii % i11iIiiIii
 else :
  for i11iII1Ii1ii111 in mc . rloc_set :
   if ( i11iII1Ii1ii111 . rloc . is_ipv4 ( ) == False and i11iII1Ii1ii111 . rloc . is_ipv6 ( ) == False ) :
    continue
    if 31 - 31: iII111i
   if ( i11iII1Ii1ii111 . up_state ( ) == False ) : continue
   if 64 - 64: Ii1I
   OoO0o = str ( 4341 ) if i11iII1Ii1ii111 . translated_port == 0 else str ( i11iII1Ii1ii111 . translated_port )
   if 4 - 4: OoOoOO00
   O0ooOoO0OO000 = { "rloc" : i11iII1Ii1ii111 . rloc . print_address_no_iid ( ) , "priority" :
 str ( i11iII1Ii1ii111 . priority ) , "weight" : str ( i11iII1Ii1ii111 . weight ) , "port" :
 OoO0o }
   iIiIIIii1iI , iI11io0o0oO = i11iII1Ii1ii111 . get_encap_keys ( )
   O0ooOoO0OO000 = lisp_build_json_keys ( O0ooOoO0OO000 , iIiIIIii1iI , iI11io0o0oO , "encrypt-key" )
   Ooo000O00 [ "rlocs" ] . append ( O0ooOoO0OO000 )
   if 78 - 78: i1IIi - iII111i + O0 - I1IiiI % o0oOOo0O0Ooo
   if 48 - 48: iII111i / II111iiii * I1Ii111 + I11i / ooOoO0o . OoOoOO00
   if 45 - 45: OOooOOo / Ii1I % O0
 if ( dont_send == False ) : lisp_write_to_dp_socket ( Ooo000O00 )
 return ( Ooo000O00 )
 if 7 - 7: oO0o * i11iIiiIii + OoooooooOO + I11i
 if 9 - 9: II111iiii * Oo0Ooo * I1Ii111 . IiII
 if 80 - 80: i11iIiiIii . i11iIiiIii . i11iIiiIii . OoooooooOO - OOooOOo * OoooooooOO
 if 96 - 96: oO0o
 if 80 - 80: IiII - oO0o % Ii1I - iIii1I11I1II1 . OoO0O00
 if 64 - 64: I1IiiI % i11iIiiIii / oO0o
 if 78 - 78: II111iiii - Oo0Ooo . iIii1I11I1II1 - ooOoO0o . oO0o
def lisp_write_ipc_decap_key ( rloc_addr , keys ) :
 if ( lisp_i_am_itr ) : return
 if ( lisp_ipc_dp_socket == None ) : return
 if ( lisp_check_dp_socket ( ) == False ) : return
 if 84 - 84: iII111i . ooOoO0o * I1IiiI * Oo0Ooo / I1Ii111
 if 93 - 93: i1IIi * i11iIiiIii % OoOoOO00 % iII111i
 if 31 - 31: OoO0O00
 if 89 - 89: II111iiii
 if ( keys == None or len ( keys ) == 0 or keys [ 1 ] == None ) : return
 if 33 - 33: OOooOOo / oO0o % OoOoOO00 * O0
 iIiIIIii1iI = keys [ 1 ] . encrypt_key
 iI11io0o0oO = keys [ 1 ] . icv_key
 if 65 - 65: OoO0O00 % OoOoOO00 % I1ii11iIi11i / OoooooooOO
 if 85 - 85: O0 * OOooOOo % I1Ii111
 if 33 - 33: O0
 if 30 - 30: II111iiii . O0 . oO0o * I1ii11iIi11i + oO0o . o0oOOo0O0Ooo
 i1IoO = rloc_addr . split ( ":" )
 if ( len ( i1IoO ) == 1 ) :
  Ooo000O00 = { "type" : "decap-keys" , "rloc" : i1IoO [ 0 ] }
 else :
  Ooo000O00 = { "type" : "decap-keys" , "rloc" : i1IoO [ 0 ] , "port" : i1IoO [ 1 ] }
  if 10 - 10: oO0o
 Ooo000O00 = lisp_build_json_keys ( Ooo000O00 , iIiIIIii1iI , iI11io0o0oO , "decrypt-key" )
 if 75 - 75: II111iiii % OOooOOo / iIii1I11I1II1 / OoO0O00 + oO0o
 lisp_write_to_dp_socket ( Ooo000O00 )
 return
 if 16 - 16: oO0o + I1Ii111 - II111iiii - o0oOOo0O0Ooo / i11iIiiIii
 if 59 - 59: OOooOOo - o0oOOo0O0Ooo
 if 82 - 82: IiII % ooOoO0o - OoO0O00 % ooOoO0o
 if 51 - 51: ooOoO0o % iII111i . o0oOOo0O0Ooo . o0oOOo0O0Ooo
 if 20 - 20: i1IIi - ooOoO0o % OoooooooOO * I1ii11iIi11i + II111iiii % i1IIi
 if 30 - 30: i11iIiiIii - I1IiiI + o0oOOo0O0Ooo + IiII
 if 16 - 16: I1ii11iIi11i / Ii1I + I1ii11iIi11i * I1Ii111
 if 49 - 49: ooOoO0o * OoOoOO00 . OoooooooOO . ooOoO0o + Oo0Ooo * IiII
def lisp_build_json_keys ( entry , ekey , ikey , key_type ) :
 if ( ekey == None ) : return ( entry )
 if 47 - 47: iII111i . i1IIi . I1ii11iIi11i / OoooooooOO
 entry [ "keys" ] = [ ]
 i1i11ii1 = { "key-id" : "1" , key_type : ekey , "icv-key" : ikey }
 entry [ "keys" ] . append ( i1i11ii1 )
 return ( entry )
 if 84 - 84: o0oOOo0O0Ooo * I11i
 if 22 - 22: i1IIi + OOooOOo % OoooooooOO
 if 34 - 34: oO0o / O0 - II111iiii % Oo0Ooo + I11i
 if 23 - 23: o0oOOo0O0Ooo + i11iIiiIii . I1IiiI + iIii1I11I1II1
 if 18 - 18: o0oOOo0O0Ooo . O0 + I1Ii111
 if 66 - 66: OoooooooOO
 if 90 - 90: IiII - OoOoOO00
def lisp_write_ipc_database_mappings ( ephem_port ) :
 if ( lisp_i_am_etr == False ) : return
 if ( lisp_ipc_dp_socket == None ) : return
 if ( lisp_check_dp_socket ( ) == False ) : return
 if 98 - 98: Oo0Ooo / oO0o . Ii1I
 if 56 - 56: ooOoO0o % OoO0O00 * i11iIiiIii % IiII % I1IiiI - oO0o
 if 37 - 37: iII111i - Ii1I . oO0o
 if 47 - 47: IiII / I1ii11iIi11i . o0oOOo0O0Ooo . ooOoO0o + OOooOOo . OOooOOo
 Ooo000O00 = { "type" : "database-mappings" , "database-mappings" : [ ] }
 if 25 - 25: oO0o
 if 43 - 43: Ii1I - o0oOOo0O0Ooo % oO0o - O0
 if 20 - 20: OoO0O00 . ooOoO0o / OoOoOO00 - OoOoOO00 . iII111i / OOooOOo
 if 39 - 39: iIii1I11I1II1 % ooOoO0o
 for Oo00OO0 in lisp_db_list :
  if ( Oo00OO0 . eid . is_ipv4 ( ) == False and Oo00OO0 . eid . is_ipv6 ( ) == False ) : continue
  Oo0o0o0oo00OO = { "instance-id" : str ( Oo00OO0 . eid . instance_id ) ,
 "eid-prefix" : Oo00OO0 . eid . print_prefix_no_iid ( ) }
  Ooo000O00 [ "database-mappings" ] . append ( Oo0o0o0oo00OO )
  if 22 - 22: I1IiiI % iII111i / Oo0Ooo % IiII - I1Ii111 - I1ii11iIi11i
 lisp_write_to_dp_socket ( Ooo000O00 )
 if 35 - 35: oO0o % OoOoOO00 + iII111i . I1Ii111 . IiII - OoooooooOO
 if 69 - 69: O0 . Ii1I / O0
 if 61 - 61: OoooooooOO / OOooOOo / iII111i % II111iiii
 if 97 - 97: I1Ii111 / iIii1I11I1II1 * OOooOOo + i11iIiiIii
 if 86 - 86: OoO0O00 - I1Ii111 * OoO0O00
 Ooo000O00 = { "type" : "etr-nat-port" , "port" : ephem_port }
 lisp_write_to_dp_socket ( Ooo000O00 )
 return
 if 29 - 29: I1Ii111 % OoOoOO00 . oO0o / oO0o % I11i
 if 91 - 91: o0oOOo0O0Ooo
 if 59 - 59: I11i . I11i
 if 98 - 98: II111iiii
 if 20 - 20: iIii1I11I1II1
 if 17 - 17: OoOoOO00 + ooOoO0o * II111iiii * OoOoOO00 + I1IiiI + i11iIiiIii
 if 46 - 46: i1IIi - II111iiii . I1IiiI . i11iIiiIii
def lisp_write_ipc_interfaces ( ) :
 if ( lisp_i_am_etr ) : return
 if ( lisp_ipc_dp_socket == None ) : return
 if ( lisp_check_dp_socket ( ) == False ) : return
 if 54 - 54: O0 * I1ii11iIi11i / OOooOOo / IiII * IiII
 if 69 - 69: Oo0Ooo * OoooooooOO / I1IiiI
 if 16 - 16: o0oOOo0O0Ooo
 if 3 - 3: i11iIiiIii . I1ii11iIi11i
 Ooo000O00 = { "type" : "interfaces" , "interfaces" : [ ] }
 if 65 - 65: II111iiii * iII111i - OoO0O00 + oO0o % OoO0O00
 for iii in lisp_myinterfaces . values ( ) :
  if ( iii . instance_id == None ) : continue
  Oo0o0o0oo00OO = { "interface" : iii . device ,
 "instance-id" : str ( iii . instance_id ) }
  Ooo000O00 [ "interfaces" ] . append ( Oo0o0o0oo00OO )
  if 83 - 83: OoooooooOO % I1ii11iIi11i . IiII + OOooOOo . iII111i - ooOoO0o
  if 100 - 100: o0oOOo0O0Ooo
 lisp_write_to_dp_socket ( Ooo000O00 )
 return
 if 95 - 95: iII111i * oO0o * i1IIi
 if 100 - 100: iII111i . o0oOOo0O0Ooo - I1Ii111 % oO0o
 if 11 - 11: o0oOOo0O0Ooo . OoooooooOO - i1IIi
 if 71 - 71: I1IiiI . OOooOOo . I1ii11iIi11i
 if 90 - 90: i11iIiiIii + I1Ii111 % II111iiii
 if 67 - 67: OoOoOO00 / iII111i * OoO0O00 % i11iIiiIii
 if 76 - 76: OoO0O00
 if 92 - 92: iIii1I11I1II1 * O0 % I11i
 if 92 - 92: OoOoOO00 + oO0o
 if 89 - 89: IiII % iII111i / iIii1I11I1II1 . Ii1I . Oo0Ooo + ooOoO0o
 if 28 - 28: I1IiiI . iIii1I11I1II1
 if 12 - 12: I1Ii111 * OOooOOo
 if 11 - 11: II111iiii % O0 % O0 % o0oOOo0O0Ooo
 if 45 - 45: OoooooooOO * oO0o
def lisp_parse_auth_key ( value ) :
 o0o0o0OO000 = value . split ( "[" )
 O0o0OOO0OooO = { }
 if ( len ( o0o0o0OO000 ) == 1 ) :
  O0o0OOO0OooO [ 0 ] = value
  return ( O0o0OOO0OooO )
  if 29 - 29: Oo0Ooo . I1ii11iIi11i / II111iiii / oO0o / o0oOOo0O0Ooo + I11i
  if 4 - 4: OoooooooOO % I1ii11iIi11i . OoO0O00 * o0oOOo0O0Ooo + I1ii11iIi11i * IiII
 for I11II1I1I in o0o0o0OO000 :
  if ( I11II1I1I == "" ) : continue
  I1Iiiiiii = I11II1I1I . find ( "]" )
  iI11i = I11II1I1I [ 0 : I1Iiiiiii ]
  try : iI11i = int ( iI11i )
  except : return
  if 67 - 67: I1IiiI
  O0o0OOO0OooO [ iI11i ] = I11II1I1I [ I1Iiiiiii + 1 : : ]
  if 93 - 93: ooOoO0o . Ii1I + IiII / Oo0Ooo % I11i
 return ( O0o0OOO0OooO )
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
def lisp_reassemble ( packet ) :
 iI1Ii11 = socket . ntohs ( struct . unpack ( "H" , packet [ 6 : 8 ] ) [ 0 ] )
 if 91 - 91: OOooOOo / Ii1I / IiII * OOooOOo
 if 68 - 68: I11i
 if 91 - 91: I11i
 if 24 - 24: ooOoO0o . i1IIi - O0 + I11i
 if ( iI1Ii11 == 0 or iI1Ii11 == 0x4000 ) : return ( packet )
 if 71 - 71: OoOoOO00
 if 29 - 29: O0 . i11iIiiIii
 if 51 - 51: IiII
 if 53 - 53: O0
 o00oOoo0o00 = socket . ntohs ( struct . unpack ( "H" , packet [ 4 : 6 ] ) [ 0 ] )
 iI11 = socket . ntohs ( struct . unpack ( "H" , packet [ 2 : 4 ] ) [ 0 ] )
 if 48 - 48: o0oOOo0O0Ooo . ooOoO0o * iIii1I11I1II1 + OoO0O00
 i1i1o0o000O0 = ( iI1Ii11 & 0x2000 == 0 and ( iI1Ii11 & 0x1fff ) != 0 )
 Ooo000O00 = [ ( iI1Ii11 & 0x1fff ) * 8 , iI11 - 20 , packet , i1i1o0o000O0 ]
 if 57 - 57: I1ii11iIi11i + i1IIi - I1Ii111
 if 7 - 7: Ii1I
 if 72 - 72: OoO0O00 . Oo0Ooo % ooOoO0o / o0oOOo0O0Ooo . IiII . iII111i
 if 28 - 28: i1IIi % iIii1I11I1II1 . i11iIiiIii - OoO0O00
 if 97 - 97: O0 / i1IIi - Oo0Ooo % i11iIiiIii + OOooOOo % iII111i
 if 59 - 59: I11i
 if 23 - 23: OoOoOO00 * I1Ii111
 if 18 - 18: o0oOOo0O0Ooo % i11iIiiIii . Ii1I . O0
 if ( iI1Ii11 == 0x2000 ) :
  I1i1I11111iI1 , IIIIIIi = struct . unpack ( "HH" , packet [ 20 : 24 ] )
  I1i1I11111iI1 = socket . ntohs ( I1i1I11111iI1 )
  IIIIIIi = socket . ntohs ( IIIIIIi )
  if ( IIIIIIi not in [ 4341 , 8472 , 4789 ] and I1i1I11111iI1 != 4341 ) :
   lisp_reassembly_queue [ o00oOoo0o00 ] = [ ]
   Ooo000O00 [ 2 ] = None
   if 85 - 85: I1ii11iIi11i * iIii1I11I1II1 + o0oOOo0O0Ooo * OoO0O00
   if 25 - 25: o0oOOo0O0Ooo / Ii1I / Oo0Ooo . ooOoO0o - ooOoO0o * O0
   if 14 - 14: O0 - Ii1I + iIii1I11I1II1 + II111iiii . ooOoO0o + Ii1I
   if 25 - 25: OoO0O00 * oO0o
   if 29 - 29: OOooOOo - I1Ii111 - i11iIiiIii % i1IIi
   if 2 - 2: i11iIiiIii % iIii1I11I1II1 * OOooOOo
 if ( lisp_reassembly_queue . has_key ( o00oOoo0o00 ) == False ) :
  lisp_reassembly_queue [ o00oOoo0o00 ] = [ ]
  if 45 - 45: oO0o + i1IIi + iII111i + o0oOOo0O0Ooo * OOooOOo + ooOoO0o
  if 83 - 83: OoO0O00 - ooOoO0o / OoooooooOO % iIii1I11I1II1 - II111iiii
  if 73 - 73: Oo0Ooo + II111iiii - IiII
  if 60 - 60: i1IIi . i11iIiiIii / i1IIi . I11i % OOooOOo
  if 47 - 47: oO0o + IiII * I1Ii111 % o0oOOo0O0Ooo - O0 % IiII
 Oooo0O0ooOooO = lisp_reassembly_queue [ o00oOoo0o00 ]
 if 45 - 45: I1Ii111 % OoOoOO00 / I1Ii111 % OoO0O00 . I1IiiI
 if 100 - 100: OoO0O00 - Ii1I + i1IIi / o0oOOo0O0Ooo / IiII
 if 85 - 85: OoOoOO00
 if 90 - 90: o0oOOo0O0Ooo . OoOoOO00 - i11iIiiIii * IiII
 if 37 - 37: OoooooooOO - I1Ii111 . Ii1I . i1IIi * IiII / ooOoO0o
 if ( len ( Oooo0O0ooOooO ) == 1 and Oooo0O0ooOooO [ 0 ] [ 2 ] == None ) :
  dprint ( "Drop non-LISP encapsulated fragment 0x{}" . format ( lisp_hex_string ( o00oOoo0o00 ) . zfill ( 4 ) ) )
  if 12 - 12: OoooooooOO
  return ( None )
  if 8 - 8: i11iIiiIii . I1Ii111 * o0oOOo0O0Ooo . ooOoO0o
  if 94 - 94: I1ii11iIi11i % OoOoOO00 - OoooooooOO
  if 42 - 42: I1Ii111 - i1IIi
  if 91 - 91: iII111i . OOooOOo / iIii1I11I1II1 . Oo0Ooo . II111iiii . OoOoOO00
  if 31 - 31: OoO0O00 . I1ii11iIi11i % I11i - II111iiii
 Oooo0O0ooOooO . append ( Ooo000O00 )
 Oooo0O0ooOooO = sorted ( Oooo0O0ooOooO )
 if 70 - 70: ooOoO0o - IiII - OoO0O00 / I11i
 if 59 - 59: IiII % ooOoO0o . iII111i / Ii1I * Ii1I
 if 73 - 73: I1ii11iIi11i . oO0o % I11i . I1ii11iIi11i / I1Ii111 / II111iiii
 if 23 - 23: OoooooooOO . o0oOOo0O0Ooo
 iIiIi1ii = lisp_address ( LISP_AFI_IPV4 , "" , 32 , 0 )
 iIiIi1ii . address = socket . ntohl ( struct . unpack ( "I" , packet [ 12 : 16 ] ) [ 0 ] )
 o0Oooo0oO0o0O = iIiIi1ii . print_address_no_iid ( )
 iIiIi1ii . address = socket . ntohl ( struct . unpack ( "I" , packet [ 16 : 20 ] ) [ 0 ] )
 O0OO000oOoOoo = iIiIi1ii . print_address_no_iid ( )
 iIiIi1ii = red ( "{} -> {}" . format ( o0Oooo0oO0o0O , O0OO000oOoOoo ) , False )
 if 84 - 84: OoO0O00
 dprint ( "{}{} fragment, RLOCs: {}, packet 0x{}, frag-offset: 0x{}" . format ( bold ( "Received" , False ) , " non-LISP encapsulated" if Ooo000O00 [ 2 ] == None else "" , iIiIi1ii , lisp_hex_string ( o00oOoo0o00 ) . zfill ( 4 ) ,
 # OoooooooOO . i1IIi + Ii1I * O0 % i1IIi % I11i
 # oO0o - Ii1I / Ii1I / OOooOOo / OoooooooOO . OOooOOo
 lisp_hex_string ( iI1Ii11 ) . zfill ( 4 ) ) )
 if 21 - 21: I1Ii111 - Ii1I - i1IIi % oO0o
 if 55 - 55: OOooOOo + oO0o - II111iiii
 if 5 - 5: iII111i * OoooooooOO . OoO0O00 % ooOoO0o + Ii1I
 if 59 - 59: OoOoOO00
 if 96 - 96: I1IiiI
 if ( Oooo0O0ooOooO [ 0 ] [ 0 ] != 0 or Oooo0O0ooOooO [ - 1 ] [ 3 ] == False ) : return ( None )
 ii1iOo = Oooo0O0ooOooO [ 0 ]
 for OOO0OoO0oo0OO in Oooo0O0ooOooO [ 1 : : ] :
  iI1Ii11 = OOO0OoO0oo0OO [ 0 ]
  IiIi111i1i1I , oooII1 = ii1iOo [ 0 ] , ii1iOo [ 1 ]
  if ( IiIi111i1i1I + oooII1 != iI1Ii11 ) : return ( None )
  ii1iOo = OOO0OoO0oo0OO
  if 80 - 80: OoooooooOO * iIii1I11I1II1 / OOooOOo + I1Ii111 + i11iIiiIii - OoOoOO00
 lisp_reassembly_queue . pop ( o00oOoo0o00 )
 if 59 - 59: ooOoO0o / OoooooooOO
 if 71 - 71: OOooOOo + I11i * O0 / o0oOOo0O0Ooo + I1IiiI + Ii1I
 if 41 - 41: ooOoO0o * I1Ii111
 if 40 - 40: OoOoOO00
 if 60 - 60: IiII . i11iIiiIii * II111iiii . Ii1I
 packet = Oooo0O0ooOooO [ 0 ] [ 2 ]
 for OOO0OoO0oo0OO in Oooo0O0ooOooO [ 1 : : ] : packet += OOO0OoO0oo0OO [ 2 ] [ 20 : : ]
 if 10 - 10: O0
 dprint ( "{} fragments arrived for packet 0x{}, length {}" . format ( bold ( "All" , False ) , lisp_hex_string ( o00oOoo0o00 ) . zfill ( 4 ) , len ( packet ) ) )
 if 65 - 65: I11i % i11iIiiIii + i11iIiiIii % II111iiii
 if 95 - 95: I1Ii111 - I11i . II111iiii . i1IIi / II111iiii + Oo0Ooo
 if 96 - 96: iIii1I11I1II1 * iII111i / OOooOOo * iIii1I11I1II1 - O0
 if 28 - 28: I11i / I1IiiI - I1Ii111 + I1ii11iIi11i % iIii1I11I1II1
 if 35 - 35: iIii1I11I1II1 % Oo0Ooo % iII111i / iIii1I11I1II1 - I1ii11iIi11i . Oo0Ooo
 OOo000o = socket . htons ( len ( packet ) )
 oo = packet [ 0 : 2 ] + struct . pack ( "H" , OOo000o ) + packet [ 4 : 6 ] + struct . pack ( "H" , 0 ) + packet [ 8 : 10 ] + struct . pack ( "H" , 0 ) + packet [ 12 : 20 ]
 if 81 - 81: II111iiii + oO0o
 if 67 - 67: ooOoO0o + I11i - I1ii11iIi11i - OoooooooOO
 oo = lisp_ip_checksum ( oo )
 return ( oo + packet [ 20 : : ] )
 if 37 - 37: I11i % I1IiiI
 if 32 - 32: OOooOOo + OoooooooOO . IiII . Oo0Ooo * iII111i
 if 86 - 86: I1ii11iIi11i . iII111i + Ii1I - IiII / i11iIiiIii + OoOoOO00
 if 50 - 50: o0oOOo0O0Ooo - IiII + OoOoOO00 - II111iiii
 if 24 - 24: I1Ii111 - IiII % I1IiiI - OoooooooOO % Ii1I
 if 56 - 56: I1ii11iIi11i
 if 40 - 40: OoooooooOO
 if 100 - 100: IiII - I11i
def lisp_get_crypto_decap_lookup_key ( addr , port ) :
 oO00o = addr . print_address_no_iid ( ) + ":" + str ( port )
 if ( lisp_crypto_keys_by_rloc_decap . has_key ( oO00o ) ) : return ( oO00o )
 if 79 - 79: iII111i % O0
 oO00o = addr . print_address_no_iid ( )
 if ( lisp_crypto_keys_by_rloc_decap . has_key ( oO00o ) ) : return ( oO00o )
 if 73 - 73: Oo0Ooo
 if 13 - 13: OOooOOo - ooOoO0o
 if 8 - 8: I1Ii111 % oO0o
 if 19 - 19: O0 + OoO0O00 - i1IIi % OoOoOO00 / Oo0Ooo + OoooooooOO
 if 93 - 93: i11iIiiIii % OOooOOo . I11i * ooOoO0o
 for oO0O00O in lisp_crypto_keys_by_rloc_decap :
  I11IIIiIi11 = oO0O00O . split ( ":" )
  if ( len ( I11IIIiIi11 ) == 1 ) : continue
  I11IIIiIi11 = I11IIIiIi11 [ 0 ] if len ( I11IIIiIi11 ) == 2 else ":" . join ( I11IIIiIi11 [ 0 : - 1 ] )
  if ( I11IIIiIi11 == oO00o ) :
   IiI1ii11I1 = lisp_crypto_keys_by_rloc_decap [ oO0O00O ]
   lisp_crypto_keys_by_rloc_decap [ oO00o ] = IiI1ii11I1
   return ( oO00o )
   if 64 - 64: iIii1I11I1II1 * Ii1I * ooOoO0o * i11iIiiIii
   if 54 - 54: IiII . Ii1I
 return ( None )
 if 54 - 54: iII111i
 if 2 - 2: OoOoOO00 + I1IiiI . ooOoO0o - oO0o . iIii1I11I1II1
 if 76 - 76: Ii1I
 if 31 - 31: ooOoO0o
 if 70 - 70: O0
 if 42 - 42: I1Ii111 + OoooooooOO + I11i
 if 48 - 48: Oo0Ooo . IiII / ooOoO0o + I11i
 if 40 - 40: I1IiiI + I1ii11iIi11i * I1IiiI % Ii1I
 if 27 - 27: O0 / Oo0Ooo . oO0o
 if 34 - 34: I1Ii111 % Ii1I / Oo0Ooo % ooOoO0o / i11iIiiIii * I1IiiI
 if 36 - 36: i11iIiiIii * i1IIi % iII111i . Oo0Ooo
def lisp_build_crypto_decap_lookup_key ( addr , port ) :
 addr = addr . print_address_no_iid ( )
 OO0ooOoOOO = addr + ":" + str ( port )
 if 92 - 92: Ii1I . OoooooooOO
 if ( lisp_i_am_rtr ) :
  if ( lisp_rloc_probe_list . has_key ( addr ) ) : return ( addr )
  if 88 - 88: O0 + iIii1I11I1II1 . o0oOOo0O0Ooo . iIii1I11I1II1 - Ii1I
  if 74 - 74: Ii1I . IiII
  if 67 - 67: oO0o
  if 12 - 12: I1IiiI + OoooooooOO
  if 25 - 25: iIii1I11I1II1 - I1IiiI . i11iIiiIii + ooOoO0o
  if 19 - 19: OoooooooOO / IiII
  for iIiiiIi in lisp_nat_state_info . values ( ) :
   for O0OO000OOooO in iIiiiIi :
    if ( addr == O0OO000OOooO . address ) : return ( OO0ooOoOOO )
    if 40 - 40: OoOoOO00 / OoooooooOO * iIii1I11I1II1 / i1IIi . OoooooooOO
    if 88 - 88: I1IiiI % I1IiiI / II111iiii - IiII
  return ( addr )
  if 72 - 72: OoO0O00 - I1ii11iIi11i . Oo0Ooo / OoO0O00
 return ( OO0ooOoOOO )
 if 86 - 86: i11iIiiIii - oO0o . i11iIiiIii
 if 51 - 51: OoO0O00 - OoO0O00 * IiII
 if 24 - 24: OoooooooOO . II111iiii
 if 97 - 97: II111iiii . O0
 if 18 - 18: iII111i
 if 35 - 35: ooOoO0o / O0 / iIii1I11I1II1 - iIii1I11I1II1 + I11i
 if 8 - 8: I1Ii111 . oO0o % Oo0Ooo * OoooooooOO
def lisp_set_ttl ( lisp_socket , ttl ) :
 try :
  lisp_socket . setsockopt ( socket . SOL_IP , socket . IP_TTL , ttl )
 except :
  lprint ( "socket.setsockopt(IP_TTL) not supported" )
  pass
  if 25 - 25: OoO0O00
 return
 if 54 - 54: O0
 if 20 - 20: ooOoO0o + Oo0Ooo - Oo0Ooo
 if 2 - 2: i1IIi - IiII . I1ii11iIi11i / i1IIi
 if 92 - 92: ooOoO0o - iII111i
 if 69 - 69: iII111i
 if 48 - 48: O0 + o0oOOo0O0Ooo . oO0o - IiII * OoooooooOO . OoO0O00
 if 63 - 63: oO0o * OoO0O00 * oO0o
def lisp_is_rloc_probe_request ( lisp_type ) :
 lisp_type = struct . unpack ( "B" , lisp_type ) [ 0 ]
 return ( lisp_type == 0x12 )
 if 31 - 31: Oo0Ooo
 if 90 - 90: I11i . IiII * iIii1I11I1II1 . I11i + i1IIi
 if 67 - 67: I1Ii111 . I1ii11iIi11i
 if 2 - 2: O0 + I1Ii111
 if 82 - 82: Ii1I / iII111i
 if 13 - 13: I11i + iII111i
 if 54 - 54: I1ii11iIi11i - I1IiiI . Ii1I
def lisp_is_rloc_probe_reply ( lisp_type ) :
 lisp_type = struct . unpack ( "B" , lisp_type ) [ 0 ]
 return ( lisp_type == 0x28 )
 if 59 - 59: Oo0Ooo + I1ii11iIi11i
 if 87 - 87: ooOoO0o * OoooooooOO + OoO0O00 + oO0o - I1Ii111
 if 70 - 70: i1IIi . Ii1I / Ii1I
 if 9 - 9: iII111i + I1Ii111 + iII111i % ooOoO0o + i11iIiiIii + i11iIiiIii
 if 45 - 45: i1IIi + I1ii11iIi11i
 if 49 - 49: i11iIiiIii . I1ii11iIi11i
 if 91 - 91: ooOoO0o - OOooOOo - OOooOOo * o0oOOo0O0Ooo
 if 33 - 33: II111iiii
 if 39 - 39: ooOoO0o + I11i
 if 24 - 24: o0oOOo0O0Ooo
 if 5 - 5: i11iIiiIii - oO0o + o0oOOo0O0Ooo % ooOoO0o
 if 63 - 63: oO0o
 if 7 - 7: IiII / i11iIiiIii - OOooOOo
 if 9 - 9: II111iiii + i11iIiiIii % I1Ii111 - Oo0Ooo * OOooOOo
 if 55 - 55: I1Ii111 + ooOoO0o
 if 58 - 58: iII111i . I1ii11iIi11i - Oo0Ooo % o0oOOo0O0Ooo + I1Ii111
 if 58 - 58: oO0o . ooOoO0o . I1IiiI . Oo0Ooo * iIii1I11I1II1 - iII111i
 if 96 - 96: OOooOOo % o0oOOo0O0Ooo / iIii1I11I1II1
 if 60 - 60: i1IIi / iIii1I11I1II1 + I11i % iII111i
def lisp_is_rloc_probe ( packet , rr ) :
 IIIiIi1iiI = ( struct . unpack ( "B" , packet [ 9 ] ) [ 0 ] == 17 )
 if ( IIIiIi1iiI == False ) : return ( [ packet , None , None , None ] )
 if 64 - 64: I11i . i11iIiiIii / iIii1I11I1II1 . I11i
 if ( rr == 0 ) :
  I1iI1iiii = lisp_is_rloc_probe_request ( packet [ 28 ] )
  if ( I1iI1iiii == False ) : return ( [ packet , None , None , None ] )
 elif ( rr == 1 ) :
  I1iI1iiii = lisp_is_rloc_probe_reply ( packet [ 28 ] )
  if ( I1iI1iiii == False ) : return ( [ packet , None , None , None ] )
 elif ( rr == - 1 ) :
  I1iI1iiii = lisp_is_rloc_probe_request ( packet [ 28 ] )
  if ( I1iI1iiii == False ) :
   I1iI1iiii = lisp_is_rloc_probe_reply ( packet [ 28 ] )
   if ( I1iI1iiii == False ) : return ( [ packet , None , None , None ] )
   if 73 - 73: OoO0O00 % iIii1I11I1II1 + IiII * I1Ii111 % II111iiii
   if 20 - 20: I11i % I1ii11iIi11i . OoO0O00 % OoOoOO00
   if 84 - 84: OoooooooOO / i11iIiiIii . IiII / I1IiiI
   if 62 - 62: iII111i - I1IiiI + OoooooooOO
   if 59 - 59: iIii1I11I1II1 + i11iIiiIii * oO0o . Oo0Ooo . I1Ii111
   if 49 - 49: II111iiii
 oO000O = lisp_address ( LISP_AFI_IPV4 , "" , 32 , 0 )
 oO000O . address = socket . ntohl ( struct . unpack ( "I" , packet [ 12 : 16 ] ) [ 0 ] )
 if 99 - 99: Oo0Ooo . OOooOOo
 if 85 - 85: OoOoOO00 . IiII + oO0o - II111iiii
 if 70 - 70: O0 % I1Ii111
 if 13 - 13: I1ii11iIi11i % OoO0O00 / Ii1I * IiII
 if ( oO000O . is_local ( ) ) : return ( [ None , None , None , None ] )
 if 82 - 82: ooOoO0o % Oo0Ooo
 if 26 - 26: OoO0O00 + i11iIiiIii % I11i . I1ii11iIi11i
 if 76 - 76: i1IIi + ooOoO0o - Oo0Ooo + OoOoOO00 / I1ii11iIi11i . OOooOOo
 if 50 - 50: IiII - Ii1I % iIii1I11I1II1
 oO000O = oO000O . print_address_no_iid ( )
 OoO0o = socket . ntohs ( struct . unpack ( "H" , packet [ 20 : 22 ] ) [ 0 ] )
 o0O0OOo0oo00 = struct . unpack ( "B" , packet [ 8 ] ) [ 0 ] - 1
 packet = packet [ 28 : : ]
 if 60 - 60: o0oOOo0O0Ooo - Oo0Ooo
 O0ooOoO0OO000 = bold ( "Receive(pcap)" , False )
 o0oO00O000O = bold ( "from " + oO000O , False )
 Iiiii1III1iIi = lisp_format_packet ( packet )
 lprint ( "{} {} bytes {} {}, packet: {}" . format ( O0ooOoO0OO000 , len ( packet ) , o0oO00O000O , OoO0o , Iiiii1III1iIi ) )
 if 92 - 92: OoOoOO00 + IiII . OoO0O00 % iII111i / II111iiii / I11i
 return ( [ packet , oO000O , OoO0o , o0O0OOo0oo00 ] )
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
def lisp_ipc_write_xtr_parameters ( cp , dp ) :
 if ( lisp_ipc_dp_socket == None ) : return
 if 56 - 56: oO0o * iIii1I11I1II1 . II111iiii - II111iiii + II111iiii - i11iIiiIii
 II1i111i = { "type" : "xtr-parameters" , "control-plane-logging" : cp ,
 "data-plane-logging" : dp , "rtr" : lisp_i_am_rtr }
 if 79 - 79: iII111i
 lisp_write_to_dp_socket ( II1i111i )
 return
 if 29 - 29: Ii1I * I1Ii111 / OoO0O00 - O0 - i11iIiiIii * I1IiiI
 if 2 - 2: OoOoOO00 . I1ii11iIi11i * I1ii11iIi11i
 if 42 - 42: OoO0O00 . OoO0O00 + II111iiii - IiII - OOooOOo * Oo0Ooo
 if 47 - 47: oO0o - OoooooooOO + iII111i
 if 69 - 69: I1ii11iIi11i - I1IiiI % oO0o + OOooOOo - I1Ii111
 if 5 - 5: ooOoO0o . OoO0O00
 if 40 - 40: iII111i
 if 87 - 87: IiII / II111iiii
def lisp_external_data_plane ( ) :
 i1I1Iiii1 = 'egrep "ipc-data-plane = yes" ./lisp.config'
 if ( commands . getoutput ( i1I1Iiii1 ) != "" ) : return ( True )
 if 44 - 44: OoO0O00 . I1Ii111 - OoooooooOO * OoOoOO00 . OoO0O00
 if ( os . getenv ( "LISP_RUN_LISP_XTR" ) != None ) : return ( True )
 return ( False )
 if 84 - 84: OOooOOo . OOooOOo . oO0o % iII111i * Oo0Ooo - iIii1I11I1II1
 if 4 - 4: iII111i
 if 23 - 23: i1IIi . iIii1I11I1II1 / I1IiiI . OoOoOO00 . iII111i / IiII
 if 65 - 65: Ii1I + IiII + I11i / I1Ii111 % iIii1I11I1II1
 if 17 - 17: I1ii11iIi11i * OOooOOo % II111iiii
 if 30 - 30: I1Ii111 . Ii1I . Oo0Ooo / OOooOOo * OoooooooOO / I1ii11iIi11i
 if 41 - 41: i1IIi
 if 75 - 75: o0oOOo0O0Ooo . I1Ii111 - I1Ii111 % Ii1I * OoooooooOO
 if 99 - 99: OOooOOo + o0oOOo0O0Ooo - OOooOOo . i1IIi
 if 86 - 86: Ii1I % oO0o - i11iIiiIii - O0 + IiII + iII111i
 if 100 - 100: OoO0O00 . Oo0Ooo
 if 29 - 29: OoO0O00
 if 34 - 34: O0 - o0oOOo0O0Ooo % OOooOOo . OoO0O00 % IiII
 if 63 - 63: O0 % iIii1I11I1II1 . o0oOOo0O0Ooo . I1IiiI * Ii1I % i1IIi
def lisp_process_data_plane_restart ( do_clear = False ) :
 os . system ( "touch ./lisp.config" )
 if 47 - 47: II111iiii * I1ii11iIi11i
 oOO0o0OoO = { "type" : "entire-map-cache" , "entries" : [ ] }
 if 74 - 74: O0 - II111iiii + iIii1I11I1II1 % I1IiiI % OoOoOO00
 if ( do_clear == False ) :
  i1III1iiiIIi1 = oOO0o0OoO [ "entries" ]
  lisp_map_cache . walk_cache ( lisp_ipc_walk_map_cache , i1III1iiiIIi1 )
  if 57 - 57: O0 * Ii1I / I1IiiI
  if 54 - 54: iIii1I11I1II1 + iII111i % OoOoOO00 % OOooOOo
 lisp_write_to_dp_socket ( oOO0o0OoO )
 return
 if 67 - 67: iII111i . II111iiii - I1IiiI / iII111i . Ii1I
 if 42 - 42: I1IiiI % I1Ii111 % iII111i + iII111i
 if 71 - 71: Oo0Ooo / OoOoOO00 - I1ii11iIi11i
 if 32 - 32: iII111i
 if 99 - 99: o0oOOo0O0Ooo . oO0o
 if 9 - 9: oO0o % OoooooooOO
 if 62 - 62: OoO0O00 / OoOoOO00 / I1Ii111 + Oo0Ooo - Ii1I
 if 72 - 72: OoO0O00 + I11i / iII111i % OOooOOo
 if 5 - 5: oO0o % OOooOOo
 if 95 - 95: OoOoOO00 + OoooooooOO - O0 + o0oOOo0O0Ooo
 if 88 - 88: i11iIiiIii . iIii1I11I1II1
 if 57 - 57: Ii1I * iIii1I11I1II1
 if 92 - 92: Ii1I % Ii1I . I11i / i1IIi % Oo0Ooo
 if 25 - 25: o0oOOo0O0Ooo - OoO0O00 - OoOoOO00 - ooOoO0o
def lisp_process_data_plane_stats ( msg , lisp_sockets , lisp_port ) :
 if ( msg . has_key ( "entries" ) == False ) :
  lprint ( "No 'entries' in stats IPC message" )
  return
  if 28 - 28: OOooOOo * ooOoO0o * OoooooooOO % IiII
 if ( type ( msg [ "entries" ] ) != list ) :
  lprint ( "'entries' in stats IPC message must be an array" )
  return
  if 9 - 9: OoooooooOO
  if 92 - 92: I1Ii111 + O0 + OoO0O00 % IiII
 for msg in msg [ "entries" ] :
  if ( msg . has_key ( "eid-prefix" ) == False ) :
   lprint ( "No 'eid-prefix' in stats IPC message" )
   continue
   if 31 - 31: Ii1I / Oo0Ooo - I1IiiI - I11i - i11iIiiIii
  I1I1iII1i = msg [ "eid-prefix" ]
  if 45 - 45: ooOoO0o - IiII / OoO0O00 / IiII
  if ( msg . has_key ( "instance-id" ) == False ) :
   lprint ( "No 'instance-id' in stats IPC message" )
   continue
   if 63 - 63: ooOoO0o . i11iIiiIii + iII111i . OoO0O00 / ooOoO0o % iII111i
  I1I111iIi = int ( msg [ "instance-id" ] )
  if 23 - 23: iIii1I11I1II1 - ooOoO0o / I11i * I11i
  if 62 - 62: OOooOOo - I1IiiI * oO0o + O0 / ooOoO0o * iIii1I11I1II1
  if 25 - 25: I1Ii111 % Oo0Ooo + OoO0O00 % OOooOOo
  if 85 - 85: I1IiiI . i11iIiiIii - ooOoO0o * I11i * OoOoOO00 * I11i
  I1IiiIiIIi1Ii = lisp_address ( LISP_AFI_NONE , "" , 0 , I1I111iIi )
  I1IiiIiIIi1Ii . store_prefix ( I1I1iII1i )
  O0O = lisp_map_cache_lookup ( None , I1IiiIiIIi1Ii )
  if ( O0O == None ) :
   lprint ( "Map-cache entry for {} not found for stats update" . format ( I1I1iII1i ) )
   if 29 - 29: I1Ii111 * I1Ii111 . iII111i + o0oOOo0O0Ooo
   continue
   if 57 - 57: I1Ii111 - IiII
   if 89 - 89: oO0o + iII111i
  if ( msg . has_key ( "rlocs" ) == False ) :
   lprint ( "No 'rlocs' in stats IPC message for {}" . format ( I1I1iII1i ) )
   if 52 - 52: OOooOOo % O0 * I1ii11iIi11i . I1ii11iIi11i / IiII
   continue
   if 7 - 7: II111iiii
  if ( type ( msg [ "rlocs" ] ) != list ) :
   lprint ( "'rlocs' in stats IPC message must be an array" )
   continue
   if 7 - 7: iIii1I11I1II1 . O0 + Ii1I % I1IiiI * O0 + OoO0O00
  II1i1I1IiI1i = msg [ "rlocs" ]
  if 54 - 54: oO0o * o0oOOo0O0Ooo
  if 87 - 87: I1IiiI
  if 13 - 13: iII111i . iII111i % O0 % o0oOOo0O0Ooo
  if 99 - 99: OoO0O00 - OoOoOO00 + OoO0O00
  for oo00O0O0oOo0 in II1i1I1IiI1i :
   if ( oo00O0O0oOo0 . has_key ( "rloc" ) == False ) : continue
   if 98 - 98: iIii1I11I1II1 % ooOoO0o
   ii1 = oo00O0O0oOo0 [ "rloc" ]
   if ( ii1 == "no-address" ) : continue
   if 98 - 98: I1Ii111 + I1ii11iIi11i % OoO0O00 * Ii1I + iII111i
   i11iII1Ii1ii111 = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
   i11iII1Ii1ii111 . store_address ( ii1 )
   if 6 - 6: iII111i / iII111i . i11iIiiIii
   iiI1iI1 = O0O . get_rloc ( i11iII1Ii1ii111 )
   if ( iiI1iI1 == None ) : continue
   if 12 - 12: I11i - OoO0O00
   if 68 - 68: IiII - OoOoOO00
   if 22 - 22: i1IIi . IiII
   if 8 - 8: IiII % o0oOOo0O0Ooo . i11iIiiIii
   o0O00 = 0 if oo00O0O0oOo0 . has_key ( "packet-count" ) == False else oo00O0O0oOo0 [ "packet-count" ]
   if 38 - 38: II111iiii % OoooooooOO / OoooooooOO . Ii1I . Ii1I
   ii1oO00o = 0 if oo00O0O0oOo0 . has_key ( "byte-count" ) == False else oo00O0O0oOo0 [ "byte-count" ]
   if 13 - 13: oO0o - i1IIi / i1IIi + OoooooooOO
   iII1i1 = 0 if oo00O0O0oOo0 . has_key ( "seconds-last-packet" ) == False else oo00O0O0oOo0 [ "seconds-last-packet" ]
   if 57 - 57: OoooooooOO / O0 + I1ii11iIi11i % I11i * oO0o / Ii1I
   if 49 - 49: I1IiiI * ooOoO0o * OOooOOo + OoO0O00 + ooOoO0o
   iiI1iI1 . stats . packet_count += o0O00
   iiI1iI1 . stats . byte_count += ii1oO00o
   iiI1iI1 . stats . last_increment = lisp_get_timestamp ( ) - iII1i1
   if 42 - 42: i1IIi . OoO0O00 % iII111i
   lprint ( "Update stats {}/{}/{}s for {} RLOC {}" . format ( o0O00 , ii1oO00o ,
 iII1i1 , I1I1iII1i , ii1 ) )
   if 57 - 57: I1ii11iIi11i / I1IiiI
   if 69 - 69: iII111i - iII111i . OoO0O00 / oO0o - OoO0O00 + I1Ii111
   if 98 - 98: iII111i . oO0o - O0 % I1IiiI . I1ii11iIi11i / i1IIi
   if 72 - 72: I1IiiI / Oo0Ooo % IiII - O0 / O0 * O0
   if 83 - 83: O0 / I1Ii111 - OoooooooOO
  if ( O0O . group . is_null ( ) and O0O . has_ttl_elapsed ( ) ) :
   I1I1iII1i = green ( O0O . print_eid_tuple ( ) , False )
   lprint ( "Refresh map-cache entry {}" . format ( I1I1iII1i ) )
   lisp_send_map_request ( lisp_sockets , lisp_port , None , O0O . eid , None )
   if 42 - 42: Ii1I / i1IIi - IiII / I1Ii111
   if 39 - 39: OoooooooOO
 return
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
 if 81 - 81: I1Ii111 . i1IIi / o0oOOo0O0Ooo
 if 30 - 30: i11iIiiIii . I1IiiI
 if 5 - 5: Ii1I / O0 + iIii1I11I1II1
 if 22 - 22: ooOoO0o . ooOoO0o * OOooOOo % OoOoOO00
 if 51 - 51: OoOoOO00 . oO0o - OoOoOO00
 if 79 - 79: iII111i
 if 71 - 71: i1IIi / OoO0O00 / OOooOOo + I1Ii111
 if 80 - 80: Oo0Ooo . iIii1I11I1II1 . OoooooooOO % iII111i . oO0o
 if 10 - 10: i11iIiiIii * OoooooooOO . i11iIiiIii
 if 35 - 35: OOooOOo * OOooOOo + o0oOOo0O0Ooo / i1IIi - I11i
 if 12 - 12: I1ii11iIi11i - i11iIiiIii + I1IiiI . Oo0Ooo
 if 26 - 26: oO0o + I1Ii111 + IiII * o0oOOo0O0Ooo . oO0o
def lisp_process_data_plane_decap_stats ( msg , lisp_ipc_socket ) :
 if 95 - 95: OoOoOO00 . I1Ii111 / Ii1I . I1Ii111 % OoO0O00
 if 16 - 16: Ii1I / I1IiiI / I1IiiI - OoooooooOO
 if 13 - 13: OOooOOo / OoooooooOO
 if 7 - 7: II111iiii - ooOoO0o
 if 72 - 72: Ii1I
 if ( lisp_i_am_itr ) :
  lprint ( "Send decap-stats IPC message to lisp-etr process" )
  II1i111i = "stats%{}" . format ( json . dumps ( msg ) )
  II1i111i = lisp_command_ipc ( II1i111i , "lisp-itr" )
  lisp_ipc ( II1i111i , lisp_ipc_socket , "lisp-etr" )
  return
  if 27 - 27: ooOoO0o / IiII + OoO0O00 + Ii1I % I1Ii111
  if 86 - 86: O0 % i11iIiiIii - Ii1I * oO0o % OOooOOo * i1IIi
  if 87 - 87: II111iiii
  if 53 - 53: OoOoOO00 * i11iIiiIii / I1Ii111
  if 100 - 100: ooOoO0o + I1IiiI * oO0o + ooOoO0o
  if 24 - 24: i11iIiiIii + ooOoO0o
  if 80 - 80: IiII % I11i % oO0o
  if 97 - 97: i1IIi * i11iIiiIii / Ii1I - I1IiiI % IiII
 II1i111i = bold ( "IPC" , False )
 lprint ( "Process decap-stats {} message: '{}'" . format ( II1i111i , msg ) )
 if 70 - 70: iIii1I11I1II1
 if ( lisp_i_am_etr ) : msg = json . loads ( msg )
 if 2 - 2: IiII - i1IIi * IiII % O0 / Ii1I
 o0O0O0o00 = [ "good-packets" , "ICV-error" , "checksum-error" ,
 "lisp-header-error" , "no-decrypt-key" , "bad-inner-version" ,
 "outer-header-error" ]
 if 44 - 44: ooOoO0o * OoooooooOO * ooOoO0o % OoO0O00 - OoooooooOO
 for iIi1 in o0O0O0o00 :
  o0O00 = 0 if msg . has_key ( iIi1 ) == False else msg [ iIi1 ] [ "packet-count" ]
  if 31 - 31: i11iIiiIii . i1IIi / Oo0Ooo / I1Ii111
  lisp_decap_stats [ iIi1 ] . packet_count += o0O00
  if 83 - 83: iII111i % o0oOOo0O0Ooo * OoOoOO00
  ii1oO00o = 0 if msg . has_key ( iIi1 ) == False else msg [ iIi1 ] [ "byte-count" ]
  if 49 - 49: II111iiii / OoO0O00
  lisp_decap_stats [ iIi1 ] . byte_count += ii1oO00o
  if 69 - 69: Ii1I * II111iiii
  iII1i1 = 0 if msg . has_key ( iIi1 ) == False else msg [ iIi1 ] [ "seconds-last-packet" ]
  if 24 - 24: I1Ii111 * I1ii11iIi11i . OOooOOo . I1IiiI - I1ii11iIi11i
  lisp_decap_stats [ iIi1 ] . last_increment = lisp_get_timestamp ( ) - iII1i1
  if 56 - 56: I1IiiI * Oo0Ooo + OoO0O00 - oO0o * I1Ii111
 return
 if 68 - 68: ooOoO0o * i11iIiiIii * OOooOOo % iII111i
 if 10 - 10: Ii1I / Oo0Ooo - i1IIi
 if 11 - 11: I11i * iII111i
 if 28 - 28: II111iiii + IiII / Oo0Ooo * I1IiiI - OOooOOo
 if 2 - 2: oO0o + I11i / I1Ii111 . I11i
 if 59 - 59: Ii1I
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
def lisp_process_punt ( punt_socket , lisp_send_sockets , lisp_ephem_port ) :
 i1II , oO000O = punt_socket . recvfrom ( 4000 )
 if 77 - 77: ooOoO0o % I1IiiI * oO0o
 i1i1I111I = json . loads ( i1II )
 if ( type ( i1i1I111I ) != dict ) :
  lprint ( "Invalid punt message from {}, not in JSON format" . format ( oO000O ) )
  if 91 - 91: OoOoOO00 * Oo0Ooo * IiII - I1IiiI
  return
  if 37 - 37: Oo0Ooo - oO0o / I1ii11iIi11i . o0oOOo0O0Ooo * Ii1I
 Ooo0o00Oo = bold ( "Punt" , False )
 lprint ( "{} message from '{}': '{}'" . format ( Ooo0o00Oo , oO000O , i1i1I111I ) )
 if 84 - 84: o0oOOo0O0Ooo / IiII + Oo0Ooo . o0oOOo0O0Ooo
 if ( i1i1I111I . has_key ( "type" ) == False ) :
  lprint ( "Punt IPC message has no 'type' key" )
  return
  if 68 - 68: I1IiiI
  if 87 - 87: II111iiii . iIii1I11I1II1 . OoOoOO00
  if 23 - 23: Oo0Ooo / II111iiii % OOooOOo % iII111i - Oo0Ooo / OoO0O00
  if 7 - 7: Ii1I / I11i / II111iiii % I11i * I11i + iIii1I11I1II1
  if 6 - 6: iIii1I11I1II1 * oO0o - iIii1I11I1II1 . O0 . O0
 if ( i1i1I111I [ "type" ] == "statistics" ) :
  lisp_process_data_plane_stats ( i1i1I111I , lisp_send_sockets , lisp_ephem_port )
  return
  if 96 - 96: I1Ii111 * II111iiii % i11iIiiIii - oO0o
 if ( i1i1I111I [ "type" ] == "decap-statistics" ) :
  lisp_process_data_plane_decap_stats ( i1i1I111I , punt_socket )
  return
  if 32 - 32: i11iIiiIii * o0oOOo0O0Ooo . OoooooooOO / O0
  if 14 - 14: i11iIiiIii . I1Ii111 % I1ii11iIi11i . I1ii11iIi11i % IiII
  if 93 - 93: iIii1I11I1II1 / IiII
  if 91 - 91: i11iIiiIii % ooOoO0o - iII111i * I1Ii111 . i11iIiiIii
  if 1 - 1: IiII + iIii1I11I1II1 * I1ii11iIi11i - IiII - i1IIi
 if ( i1i1I111I [ "type" ] == "restart" ) :
  lisp_process_data_plane_restart ( )
  return
  if 75 - 75: II111iiii * o0oOOo0O0Ooo / I1ii11iIi11i
  if 46 - 46: OOooOOo
  if 67 - 67: OoO0O00 . I11i % OOooOOo + Oo0Ooo
  if 40 - 40: OoO0O00 / I11i % iIii1I11I1II1 - ooOoO0o
  if 51 - 51: Oo0Ooo % iIii1I11I1II1 % oO0o + o0oOOo0O0Ooo
 if ( i1i1I111I [ "type" ] != "discovery" ) :
  lprint ( "Punt IPC message has wrong format" )
  return
  if 32 - 32: I1Ii111 * I1IiiI + Ii1I
 if ( i1i1I111I . has_key ( "interface" ) == False ) :
  lprint ( "Invalid punt message from {}, required keys missing" . format ( oO000O ) )
  if 30 - 30: OoooooooOO / I1IiiI . iIii1I11I1II1 / ooOoO0o
  return
  if 20 - 20: OoooooooOO * OOooOOo
  if 77 - 77: Ii1I - OoooooooOO . OoOoOO00
  if 93 - 93: OoooooooOO / I1Ii111
  if 91 - 91: I1Ii111
  if 18 - 18: ooOoO0o * I11i
 O0o0o0 = i1i1I111I [ "interface" ]
 if ( O0o0o0 == "" ) :
  I1I111iIi = int ( i1i1I111I [ "instance-id" ] )
  if ( I1I111iIi == - 1 ) : return
 else :
  I1I111iIi = lisp_get_interface_instance_id ( O0o0o0 , None )
  if 53 - 53: I11i . i11iIiiIii - iIii1I11I1II1 / I1Ii111
  if 86 - 86: i1IIi % OoO0O00 - OoooooooOO
  if 63 - 63: o0oOOo0O0Ooo . iIii1I11I1II1 % IiII * i11iIiiIii
  if 70 - 70: iIii1I11I1II1
  if 12 - 12: OoOoOO00 / o0oOOo0O0Ooo - I1ii11iIi11i + oO0o + O0
 i11i1III1 = None
 if ( i1i1I111I . has_key ( "source-eid" ) ) :
  o0o0oOOo = i1i1I111I [ "source-eid" ]
  i11i1III1 = lisp_address ( LISP_AFI_NONE , o0o0oOOo , 0 , I1I111iIi )
  if ( i11i1III1 . is_null ( ) ) :
   lprint ( "Invalid source-EID format '{}'" . format ( o0o0oOOo ) )
   return
   if 9 - 9: I1ii11iIi11i * OoooooooOO . O0 . ooOoO0o * i11iIiiIii / i1IIi
   if 38 - 38: OoOoOO00 . OoooooooOO % I1ii11iIi11i . oO0o % oO0o
 o00Ooo = None
 if ( i1i1I111I . has_key ( "dest-eid" ) ) :
  OooOI1I = i1i1I111I [ "dest-eid" ]
  o00Ooo = lisp_address ( LISP_AFI_NONE , OooOI1I , 0 , I1I111iIi )
  if ( o00Ooo . is_null ( ) ) :
   lprint ( "Invalid dest-EID format '{}'" . format ( OooOI1I ) )
   return
   if 94 - 94: OoO0O00 . o0oOOo0O0Ooo . oO0o / iII111i
   if 10 - 10: I1ii11iIi11i / ooOoO0o % O0
   if 65 - 65: iII111i
   if 77 - 77: II111iiii
   if 100 - 100: O0 / iII111i + ooOoO0o / IiII
   if 12 - 12: oO0o + Oo0Ooo + I1ii11iIi11i / O0
   if 94 - 94: I1ii11iIi11i * OoOoOO00 * iIii1I11I1II1 / I11i
   if 19 - 19: II111iiii * oO0o
 if ( i11i1III1 ) :
  Oo00OOo00O = green ( i11i1III1 . print_address ( ) , False )
  Oo00OO0 = lisp_db_for_lookups . lookup_cache ( i11i1III1 , False )
  if ( Oo00OO0 != None ) :
   if 70 - 70: ooOoO0o - II111iiii . I11i
   if 70 - 70: OOooOOo / iII111i - I11i + OoOoOO00 % Ii1I * IiII
   if 26 - 26: O0 / oO0o
   if 96 - 96: ooOoO0o * iII111i . IiII
   if 77 - 77: OOooOOo - I11i % o0oOOo0O0Ooo
   if ( Oo00OO0 . dynamic_eid_configured ( ) ) :
    iii = lisp_allow_dynamic_eid ( O0o0o0 , i11i1III1 )
    if ( iii != None and lisp_i_am_itr ) :
     lisp_itr_discover_eid ( Oo00OO0 , i11i1III1 , O0o0o0 , iii )
    else :
     lprint ( ( "Disallow dynamic source-EID {} " + "on interface {}" ) . format ( Oo00OOo00O , O0o0o0 ) )
     if 46 - 46: I1IiiI % oO0o . OoooooooOO . IiII / I11i - i1IIi
     if 43 - 43: OoOoOO00 - o0oOOo0O0Ooo
     if 22 - 22: i1IIi
  else :
   lprint ( "Punt from non-EID source {}" . format ( Oo00OOo00O ) )
   if 33 - 33: O0
   if 34 - 34: I1Ii111 . IiII % iII111i
   if 94 - 94: OOooOOo % i11iIiiIii . OOooOOo
   if 55 - 55: OoOoOO00 . OoOoOO00 % o0oOOo0O0Ooo . I11i . I1ii11iIi11i - o0oOOo0O0Ooo
   if 1 - 1: i11iIiiIii - i1IIi * oO0o - iIii1I11I1II1
   if 75 - 75: i1IIi * i11iIiiIii
 if ( o00Ooo ) :
  O0O = lisp_map_cache_lookup ( i11i1III1 , o00Ooo )
  if ( O0O == None or O0O . action == LISP_SEND_MAP_REQUEST_ACTION ) :
   if 40 - 40: I1ii11iIi11i + OoO0O00
   if 8 - 8: i11iIiiIii - iIii1I11I1II1
   if 73 - 73: OoOoOO00
   if 25 - 25: iII111i / oO0o
   if 61 - 61: OoooooooOO . Ii1I . I11i + oO0o
   if ( lisp_rate_limit_map_request ( i11i1III1 , o00Ooo ) ) : return
   lisp_send_map_request ( lisp_send_sockets , lisp_ephem_port ,
 i11i1III1 , o00Ooo , None )
  else :
   Oo00OOo00O = green ( o00Ooo . print_address ( ) , False )
   lprint ( "Map-cache entry for {} already exists" . format ( Oo00OOo00O ) )
   if 73 - 73: II111iiii % i11iIiiIii * I1ii11iIi11i + O0
   if 61 - 61: I1IiiI / OOooOOo
 return
 if 67 - 67: OoOoOO00
 if 22 - 22: Ii1I * I1ii11iIi11i * o0oOOo0O0Ooo - I1IiiI . i11iIiiIii
 if 30 - 30: O0 / oO0o * i11iIiiIii + iIii1I11I1II1 + O0 % I1IiiI
 if 95 - 95: ooOoO0o % OOooOOo
 if 17 - 17: i1IIi + Ii1I
 if 35 - 35: iIii1I11I1II1 - Oo0Ooo - OoooooooOO % I1ii11iIi11i
 if 27 - 27: Oo0Ooo * II111iiii - OOooOOo + o0oOOo0O0Ooo
def lisp_ipc_map_cache_entry ( mc , jdata ) :
 Ooo000O00 = lisp_write_ipc_map_cache ( True , mc , dont_send = True )
 jdata . append ( Ooo000O00 )
 return ( [ True , jdata ] )
 if 26 - 26: oO0o / I1ii11iIi11i - oO0o
 if 9 - 9: ooOoO0o * iIii1I11I1II1 * OoooooooOO
 if 13 - 13: iII111i . i11iIiiIii * o0oOOo0O0Ooo . iII111i
 if 96 - 96: Ii1I
 if 90 - 90: II111iiii
 if 93 - 93: i11iIiiIii / Ii1I * Oo0Ooo . iII111i % iII111i / IiII
 if 15 - 15: OoOoOO00 % I1Ii111 - iIii1I11I1II1
 if 52 - 52: i11iIiiIii * ooOoO0o
def lisp_ipc_walk_map_cache ( mc , jdata ) :
 if 15 - 15: OoooooooOO . oO0o . i11iIiiIii / o0oOOo0O0Ooo
 if 91 - 91: ooOoO0o
 if 47 - 47: II111iiii + I11i + ooOoO0o % Oo0Ooo / iII111i
 if 9 - 9: O0 + IiII
 if ( mc . group . is_null ( ) ) : return ( lisp_ipc_map_cache_entry ( mc , jdata ) )
 if 69 - 69: I1IiiI
 if ( mc . source_cache == None ) : return ( [ True , jdata ] )
 if 11 - 11: I11i % I1Ii111 + O0 . Ii1I . I1ii11iIi11i % I1Ii111
 if 28 - 28: IiII . o0oOOo0O0Ooo + iII111i - OoOoOO00 / OOooOOo
 if 86 - 86: ooOoO0o * OoOoOO00 + oO0o / II111iiii % OOooOOo
 if 89 - 89: O0 * Ii1I / OoO0O00 / OoOoOO00 % iII111i * iIii1I11I1II1
 if 72 - 72: iIii1I11I1II1 / iIii1I11I1II1 * I11i
 jdata = mc . source_cache . walk_cache ( lisp_ipc_map_cache_entry , jdata )
 return ( [ True , jdata ] )
 if 19 - 19: I1ii11iIi11i
 if 42 - 42: OoOoOO00 / IiII
 if 65 - 65: ooOoO0o - ooOoO0o * OoO0O00
 if 99 - 99: I11i % ooOoO0o . I1Ii111
 if 34 - 34: ooOoO0o + oO0o + II111iiii . I1Ii111 . i1IIi
 if 14 - 14: OoO0O00 . ooOoO0o - i1IIi * I1IiiI
 if 24 - 24: iIii1I11I1II1 / I1Ii111
def lisp_itr_discover_eid ( db , eid , input_interface , routed_interface ,
 lisp_ipc_listen_socket ) :
 I1I1iII1i = eid . print_address ( )
 if ( db . dynamic_eids . has_key ( I1I1iII1i ) ) :
  db . dynamic_eids [ I1I1iII1i ] . last_packet = lisp_get_timestamp ( )
  return
  if 16 - 16: OoOoOO00 * I1Ii111 - I1IiiI / I1Ii111
  if 64 - 64: I1ii11iIi11i . i1IIi % II111iiii % Oo0Ooo + oO0o - I1IiiI
  if 24 - 24: IiII . II111iiii . II111iiii . OoOoOO00 . i11iIiiIii
  if 11 - 11: Ii1I
  if 82 - 82: I11i - i1IIi . Oo0Ooo * I1Ii111
 iI = lisp_dynamic_eid ( )
 iI . dynamic_eid . copy_address ( eid )
 iI . interface = routed_interface
 iI . last_packet = lisp_get_timestamp ( )
 iI . get_timeout ( routed_interface )
 db . dynamic_eids [ I1I1iII1i ] = iI
 if 44 - 44: iII111i
 Oo0O = ""
 if ( input_interface != routed_interface ) :
  Oo0O = ", routed-interface " + routed_interface
  if 85 - 85: II111iiii - iIii1I11I1II1 + I1IiiI * iIii1I11I1II1 + I1IiiI - I11i
  if 33 - 33: I1ii11iIi11i / o0oOOo0O0Ooo
 Oo000oOo00 = green ( I1I1iII1i , False ) + bold ( " discovered" , False )
 lprint ( "Dynamic-EID {} on interface {}{}, timeout {}" . format ( Oo000oOo00 , input_interface , Oo0O , iI . timeout ) )
 if 82 - 82: OOooOOo . iIii1I11I1II1 + I1Ii111
 if 14 - 14: IiII . i11iIiiIii
 if 17 - 17: ooOoO0o % ooOoO0o * oO0o
 if 8 - 8: ooOoO0o + OoO0O00 . II111iiii / iIii1I11I1II1 - OOooOOo
 if 87 - 87: iIii1I11I1II1 . IiII % I1IiiI . OoO0O00 - I1Ii111
 II1i111i = "learn%{}%{}" . format ( I1I1iII1i , routed_interface )
 II1i111i = lisp_command_ipc ( II1i111i , "lisp-itr" )
 lisp_ipc ( II1i111i , lisp_ipc_listen_socket , "lisp-etr" )
 return
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
def lisp_retry_decap_keys ( addr_str , packet , iv , packet_icv ) :
 if ( lisp_search_decap_keys == False ) : return
 if 7 - 7: OoOoOO00 - OoO0O00 % OoOoOO00 . I1ii11iIi11i % Oo0Ooo * iII111i
 if 90 - 90: IiII - OOooOOo + iIii1I11I1II1
 if 88 - 88: ooOoO0o . o0oOOo0O0Ooo . OOooOOo - I11i
 if 76 - 76: IiII % I1IiiI . iII111i
 if ( addr_str . find ( ":" ) != - 1 ) : return
 if 5 - 5: ooOoO0o . oO0o - OoOoOO00 - OoooooooOO
 IiIII1iii1iII = lisp_crypto_keys_by_rloc_decap [ addr_str ]
 if 2 - 2: OOooOOo
 for i1i11ii1 in lisp_crypto_keys_by_rloc_decap :
  if 37 - 37: IiII - iIii1I11I1II1 * i11iIiiIii . ooOoO0o
  if 78 - 78: OOooOOo - I1ii11iIi11i + iII111i % OoOoOO00
  if 28 - 28: I11i + i1IIi / i11iIiiIii * OOooOOo * II111iiii
  if 78 - 78: OoO0O00 - i1IIi % I1Ii111
  if ( i1i11ii1 . find ( addr_str ) == - 1 ) : continue
  if 87 - 87: I11i
  if 37 - 37: iII111i . I1Ii111 - iII111i - I11i - iIii1I11I1II1 - II111iiii
  if 80 - 80: I1Ii111 % O0 - IiII / II111iiii + i1IIi
  if 4 - 4: OOooOOo + II111iiii
  if ( i1i11ii1 == addr_str ) : continue
  if 1 - 1: OoooooooOO * I1Ii111 - I11i / IiII
  if 43 - 43: i11iIiiIii * I1IiiI
  if 48 - 48: Oo0Ooo - OOooOOo / iII111i % I1ii11iIi11i . OoOoOO00
  if 6 - 6: i11iIiiIii
  Ooo000O00 = lisp_crypto_keys_by_rloc_decap [ i1i11ii1 ]
  if ( Ooo000O00 == IiIII1iii1iII ) : continue
  if 51 - 51: o0oOOo0O0Ooo - OoooooooOO - I11i % i11iIiiIii / I1IiiI + IiII
  if 91 - 91: O0
  if 13 - 13: o0oOOo0O0Ooo
  if 15 - 15: iIii1I11I1II1 * Oo0Ooo . iIii1I11I1II1 . Ii1I % iII111i - i11iIiiIii
  O00O0OOoo = Ooo000O00 [ 1 ]
  if ( packet_icv != O00O0OOoo . do_icv ( packet , iv ) ) :
   lprint ( "Test ICV with key {} failed" . format ( red ( i1i11ii1 , False ) ) )
   continue
   if 42 - 42: OoOoOO00
   if 45 - 45: ooOoO0o / OoooooooOO . Oo0Ooo
  lprint ( "Changing decap crypto key to {}" . format ( red ( i1i11ii1 , False ) ) )
  lisp_crypto_keys_by_rloc_decap [ addr_str ] = Ooo000O00
  if 35 - 35: i11iIiiIii / o0oOOo0O0Ooo / oO0o / I11i . O0
 return
 if 53 - 53: i1IIi
 if 51 - 51: OoOoOO00 / iIii1I11I1II1 . oO0o - I1ii11iIi11i - OOooOOo
 if 90 - 90: i1IIi / oO0o * I1Ii111 + II111iiii % I11i
# dd678faae9ac167bc83abf78e5cb2f3f0688d3a3
