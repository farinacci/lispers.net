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
if 61 - 61: II111iiii
if 64 - 64: ooOoO0o / OoOoOO00 - O0 - I11i
lisp_last_map_request_sent = None
lisp_no_map_request_rate_limit = time . time ( )
if 86 - 86: I11i % OoOoOO00 / I1IiiI / OoOoOO00
if 42 - 42: OoO0O00
if 67 - 67: I1Ii111 . iII111i . O0
if 10 - 10: I1ii11iIi11i % I1ii11iIi11i - iIii1I11I1II1 / OOooOOo + Ii1I
lisp_last_icmp_too_big_sent = 0
if 87 - 87: oO0o * I1ii11iIi11i + OOooOOo / iIii1I11I1II1 / iII111i
if 37 - 37: iII111i - ooOoO0o * oO0o % i11iIiiIii - I1Ii111
if 83 - 83: I11i / I1IiiI
if 34 - 34: IiII
LISP_FLOW_LOG_SIZE = 100
lisp_flow_log = [ ]
if 57 - 57: oO0o . I11i . i1IIi
if 42 - 42: I11i + I1ii11iIi11i % O0
if 6 - 6: oO0o
if 68 - 68: OoOoOO00 - OoO0O00
lisp_policies = { }
if 28 - 28: OoO0O00 . OOooOOo / OOooOOo + Oo0Ooo . I1ii11iIi11i
if 1 - 1: iIii1I11I1II1 / II111iiii
if 33 - 33: I11i
if 18 - 18: o0oOOo0O0Ooo % iII111i * O0
if 87 - 87: i11iIiiIii
lisp_load_split_pings = False
if 93 - 93: I1ii11iIi11i - OoO0O00 % i11iIiiIii . iII111i / iII111i - I1Ii111
if 9 - 9: I1ii11iIi11i / Oo0Ooo - I1IiiI / OoooooooOO / iIii1I11I1II1 - o0oOOo0O0Ooo
if 91 - 91: iII111i % i1IIi % iIii1I11I1II1
if 20 - 20: OOooOOo % Ii1I / Ii1I + Ii1I
if 45 - 45: oO0o - IiII - OoooooooOO - OoO0O00 . II111iiii / O0
if 51 - 51: O0 + iII111i
lisp_eid_hashes = [ ]
if 8 - 8: oO0o * OoOoOO00 - Ii1I - OoO0O00 * OOooOOo % I1IiiI
if 48 - 48: O0
if 11 - 11: I11i + OoooooooOO - OoO0O00 / o0oOOo0O0Ooo + Oo0Ooo . II111iiii
if 41 - 41: Ii1I - O0 - O0
if 68 - 68: OOooOOo % I1Ii111
if 88 - 88: iIii1I11I1II1 - ooOoO0o + OOooOOo
if 40 - 40: I1IiiI * Ii1I + OOooOOo % iII111i
if 74 - 74: oO0o - Oo0Ooo + OoooooooOO + I1Ii111 / OoOoOO00
lisp_reassembly_queue = { }
if 23 - 23: O0
if 85 - 85: Ii1I
if 84 - 84: I1IiiI . iIii1I11I1II1 % OoooooooOO + Ii1I % OoooooooOO % OoO0O00
if 42 - 42: OoO0O00 / I11i / o0oOOo0O0Ooo + iII111i / OoOoOO00
if 84 - 84: ooOoO0o * II111iiii + Oo0Ooo
if 53 - 53: iII111i % II111iiii . IiII - iIii1I11I1II1 - IiII * II111iiii
if 77 - 77: iIii1I11I1II1 * OoO0O00
lisp_pubsub_cache = { }
if 95 - 95: I1IiiI + i11iIiiIii
if 6 - 6: ooOoO0o / i11iIiiIii + iII111i * oO0o
if 80 - 80: II111iiii
if 83 - 83: I11i . i11iIiiIii + II111iiii . o0oOOo0O0Ooo * I11i
if 53 - 53: II111iiii
if 31 - 31: OoO0O00
lisp_decent_push_configured = False
if 80 - 80: I1Ii111 . i11iIiiIii - o0oOOo0O0Ooo
if 25 - 25: OoO0O00
if 62 - 62: OOooOOo + O0
if 98 - 98: o0oOOo0O0Ooo
if 51 - 51: Oo0Ooo - oO0o + II111iiii * Ii1I . I11i + oO0o
if 78 - 78: i11iIiiIii / iII111i - Ii1I / OOooOOo + oO0o
lisp_decent_modulus = 0
lisp_decent_dns_suffix = None
if 82 - 82: Ii1I
if 46 - 46: OoooooooOO . i11iIiiIii
if 94 - 94: o0oOOo0O0Ooo * Ii1I / Oo0Ooo / Ii1I
if 87 - 87: Oo0Ooo . IiII
if 75 - 75: ooOoO0o + OoOoOO00 + o0oOOo0O0Ooo * I11i % oO0o . iII111i
if 55 - 55: OOooOOo . I1IiiI
lisp_ipc_socket = None
if 61 - 61: Oo0Ooo % IiII . Oo0Ooo
if 100 - 100: I1Ii111 * O0
if 64 - 64: OOooOOo % iIii1I11I1II1 * oO0o
if 79 - 79: O0
lisp_ms_encryption_keys = { }
lisp_ms_json_keys = { }
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
if 63 - 63: OoOoOO00 * iII111i
if 69 - 69: O0 . OoO0O00
lisp_rtr_nat_trace_cache = { }
if 49 - 49: I1IiiI - I11i
if 74 - 74: iIii1I11I1II1 * I1ii11iIi11i + OoOoOO00 / i1IIi / II111iiii . Oo0Ooo
if 62 - 62: OoooooooOO * I1IiiI
if 58 - 58: OoOoOO00 % o0oOOo0O0Ooo
if 50 - 50: I1Ii111 . o0oOOo0O0Ooo
if 97 - 97: O0 + OoOoOO00
if 89 - 89: o0oOOo0O0Ooo + OoO0O00 * I11i * Ii1I
if 37 - 37: OoooooooOO - O0 - o0oOOo0O0Ooo
if 77 - 77: OOooOOo * iIii1I11I1II1
if 98 - 98: I1IiiI % Ii1I * OoooooooOO
lisp_glean_mappings = [ ]
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
lisp_gleaned_groups = { }
if 76 - 76: IiII * iII111i
if 52 - 52: OOooOOo
if 19 - 19: I1IiiI
if 25 - 25: Ii1I / ooOoO0o
if 31 - 31: OOooOOo . O0 % I1IiiI . o0oOOo0O0Ooo + IiII
lisp_icmp_raw_socket = None
if ( os . getenv ( "LISP_SEND_ICMP_TOO_BIG" ) != None ) :
 lisp_icmp_raw_socket = socket . socket ( socket . AF_INET , socket . SOCK_RAW ,
 socket . IPPROTO_ICMP )
 lisp_icmp_raw_socket . setsockopt ( socket . SOL_IP , socket . IP_HDRINCL , 1 )
 if 71 - 71: I1Ii111 . II111iiii
 if 62 - 62: OoooooooOO . I11i
lisp_ignore_df_bit = ( os . getenv ( "LISP_IGNORE_DF_BIT" ) != None )
if 61 - 61: OoOoOO00 - OOooOOo - i1IIi
if 25 - 25: O0 * I11i + I1ii11iIi11i . o0oOOo0O0Ooo . o0oOOo0O0Ooo
if 58 - 58: I1IiiI
if 53 - 53: i1IIi
if 59 - 59: o0oOOo0O0Ooo
if 81 - 81: OoOoOO00 - OoOoOO00 . iII111i
LISP_DATA_PORT = 4341
LISP_CTRL_PORT = 4342
LISP_L2_DATA_PORT = 8472
LISP_VXLAN_DATA_PORT = 4789
LISP_VXLAN_GPE_PORT = 4790
LISP_TRACE_PORT = 2434
if 73 - 73: I11i % i11iIiiIii - I1IiiI
if 7 - 7: O0 * i11iIiiIii * Ii1I + ooOoO0o % OoO0O00 - ooOoO0o
if 39 - 39: Oo0Ooo * OOooOOo % OOooOOo - OoooooooOO + o0oOOo0O0Ooo - I11i
if 23 - 23: i11iIiiIii
LISP_MAP_REQUEST = 1
LISP_MAP_REPLY = 2
LISP_MAP_REGISTER = 3
LISP_MAP_NOTIFY = 4
LISP_MAP_NOTIFY_ACK = 5
LISP_MAP_REFERRAL = 6
LISP_NAT_INFO = 7
LISP_ECM = 8
LISP_TRACE = 9
if 30 - 30: o0oOOo0O0Ooo - i1IIi % II111iiii + I11i * iIii1I11I1II1
if 81 - 81: IiII % i1IIi . iIii1I11I1II1
if 4 - 4: i11iIiiIii % OoO0O00 % i1IIi / IiII
if 6 - 6: iII111i / I1IiiI % OOooOOo - I1IiiI
LISP_NO_ACTION = 0
LISP_NATIVE_FORWARD_ACTION = 1
LISP_SEND_MAP_REQUEST_ACTION = 2
LISP_DROP_ACTION = 3
LISP_POLICY_DENIED_ACTION = 4
LISP_AUTH_FAILURE_ACTION = 5
if 31 - 31: OOooOOo
lisp_map_reply_action_string = [ "no-action" , "native-forward" ,
 "send-map-request" , "drop-action" , "policy-denied" , "auth-failure" ]
if 23 - 23: I1Ii111 . IiII
if 92 - 92: OoOoOO00 + I1Ii111 * Ii1I % I1IiiI
if 42 - 42: Oo0Ooo
if 76 - 76: I1IiiI * iII111i % I1Ii111
LISP_NONE_ALG_ID = 0
LISP_SHA_1_96_ALG_ID = 1
LISP_SHA_256_128_ALG_ID = 2
LISP_MD5_AUTH_DATA_LEN = 16
LISP_SHA1_160_AUTH_DATA_LEN = 20
LISP_SHA2_256_AUTH_DATA_LEN = 32
if 57 - 57: iIii1I11I1II1 - i1IIi / I1Ii111 - O0 * OoooooooOO % II111iiii
if 68 - 68: OoooooooOO * I11i % OoOoOO00 - IiII
if 34 - 34: I1Ii111 . iIii1I11I1II1 * OoOoOO00 * oO0o / I1Ii111 / I1ii11iIi11i
if 78 - 78: Oo0Ooo - o0oOOo0O0Ooo / OoOoOO00
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
if 10 - 10: iII111i + Oo0Ooo * I1ii11iIi11i + iIii1I11I1II1 / I1Ii111 / I1ii11iIi11i
if 42 - 42: I1IiiI
if 38 - 38: OOooOOo + II111iiii % ooOoO0o % OoOoOO00 - Ii1I / OoooooooOO
if 73 - 73: o0oOOo0O0Ooo * O0 - i11iIiiIii
LISP_MR_TTL = ( 24 * 60 )
LISP_REGISTER_TTL = 3
LISP_SHORT_TTL = 1
LISP_NMR_TTL = 15
LISP_GLEAN_TTL = 15
LISP_MCAST_TTL = 15
LISP_IGMP_TTL = 240
if 85 - 85: Ii1I % iII111i + I11i / o0oOOo0O0Ooo . oO0o + OOooOOo
LISP_SITE_TIMEOUT_CHECK_INTERVAL = 60
LISP_PUBSUB_TIMEOUT_CHECK_INTERVAL = 60
LISP_REFERRAL_TIMEOUT_CHECK_INTERVAL = 60
LISP_TEST_MR_INTERVAL = 60
LISP_MAP_NOTIFY_INTERVAL = 2
LISP_DDT_MAP_REQUEST_INTERVAL = 2
LISP_MAX_MAP_NOTIFY_RETRIES = 3
LISP_INFO_INTERVAL = 15
LISP_MAP_REQUEST_RATE_LIMIT = .5
LISP_NO_MAP_REQUEST_RATE_LIMIT_TIME = 60
LISP_ICMP_TOO_BIG_RATE_LIMIT = 1
if 62 - 62: i11iIiiIii + i11iIiiIii - o0oOOo0O0Ooo
LISP_RLOC_PROBE_TTL = 128
LISP_RLOC_PROBE_INTERVAL = 10
LISP_RLOC_PROBE_REPLY_WAIT = 15
LISP_DEFAULT_DYN_EID_TIMEOUT = 15
LISP_NONCE_ECHO_INTERVAL = 10
LISP_IGMP_TIMEOUT_INTERVAL = 180
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
if 21 - 21: O0 % IiII . I1IiiI / II111iiii + IiII
if 53 - 53: oO0o - I1IiiI - oO0o * iII111i
if 71 - 71: O0 - iIii1I11I1II1
if 12 - 12: OOooOOo / o0oOOo0O0Ooo
if 42 - 42: Oo0Ooo
if 19 - 19: oO0o % I1ii11iIi11i * iIii1I11I1II1 + I1IiiI
if 46 - 46: Oo0Ooo
if 1 - 1: iII111i
if 97 - 97: OOooOOo + iII111i + O0 + i11iIiiIii
if 77 - 77: o0oOOo0O0Ooo / OoooooooOO
if 46 - 46: o0oOOo0O0Ooo % iIii1I11I1II1 . iII111i % iII111i + i11iIiiIii
if 72 - 72: iIii1I11I1II1 * Ii1I % ooOoO0o / OoO0O00
if 35 - 35: ooOoO0o + i1IIi % I1ii11iIi11i % I11i + oO0o
if 17 - 17: i1IIi
if 21 - 21: Oo0Ooo
if 29 - 29: I11i / II111iiii / ooOoO0o * OOooOOo
if 10 - 10: I1Ii111 % IiII * IiII . I11i / Ii1I % OOooOOo
if 49 - 49: OoO0O00 / oO0o + O0 * o0oOOo0O0Ooo
if 28 - 28: ooOoO0o + i11iIiiIii / I11i % OoOoOO00 % Oo0Ooo - O0
if 54 - 54: i1IIi + II111iiii
LISP_CS_1024 = 0
LISP_CS_1024_G = 2
LISP_CS_1024_P = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF
if 83 - 83: I1ii11iIi11i - I1IiiI + OOooOOo
LISP_CS_2048_CBC = 1
LISP_CS_2048_CBC_G = 2
LISP_CS_2048_CBC_P = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF
if 5 - 5: Ii1I
LISP_CS_25519_CBC = 2
LISP_CS_2048_GCM = 3
if 46 - 46: IiII
LISP_CS_3072 = 4
LISP_CS_3072_G = 2
LISP_CS_3072_P = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF
if 45 - 45: ooOoO0o
LISP_CS_25519_GCM = 5
LISP_CS_25519_CHACHA = 6
if 21 - 21: oO0o . I1Ii111 . OOooOOo / Oo0Ooo / I1Ii111
LISP_4_32_MASK = 0xFFFFFFFF
LISP_8_64_MASK = 0xFFFFFFFFFFFFFFFF
LISP_16_128_MASK = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
if 17 - 17: OOooOOo / OOooOOo / I11i
if 1 - 1: i1IIi . i11iIiiIii % OOooOOo
if 82 - 82: iIii1I11I1II1 + Oo0Ooo . iIii1I11I1II1 % IiII / Ii1I . Ii1I
if 14 - 14: o0oOOo0O0Ooo . OOooOOo . I11i + OoooooooOO - OOooOOo + IiII
if 9 - 9: Ii1I
if 59 - 59: I1IiiI * II111iiii . O0
if 56 - 56: Ii1I - iII111i % I1IiiI - o0oOOo0O0Ooo
if 51 - 51: O0 / ooOoO0o * iIii1I11I1II1 + I1ii11iIi11i + o0oOOo0O0Ooo
def lisp_record_traceback ( * args ) :
 if 98 - 98: iIii1I11I1II1 * I1ii11iIi11i * OOooOOo + ooOoO0o % i11iIiiIii % O0
 i1 = datetime . datetime . now ( ) . strftime ( "%m/%d/%y %H:%M:%S.%f" ) [ : - 3 ]
 OO0oOOoo = open ( "./logs/lisp-traceback.log" , "a" )
 OO0oOOoo . write ( "---------- Exception occurred: {} ----------\n" . format ( i1 ) )
 try :
  traceback . print_last ( file = OO0oOOoo )
 except :
  OO0oOOoo . write ( "traceback.print_last(file=fd) failed" )
  if 52 - 52: o0oOOo0O0Ooo % Oo0Ooo
 try :
  traceback . print_last ( )
 except :
  print ( "traceback.print_last() failed" )
  if 64 - 64: O0 % I11i % O0 * OoO0O00 . oO0o + I1IiiI
 OO0oOOoo . close ( )
 return
 if 75 - 75: I11i . OoooooooOO % o0oOOo0O0Ooo * I11i % OoooooooOO
 if 13 - 13: IiII / i11iIiiIii % II111iiii % I11i . I1ii11iIi11i
 if 8 - 8: OoOoOO00 + Oo0Ooo - II111iiii
 if 11 - 11: i1IIi % i11iIiiIii - i1IIi * OoOoOO00
 if 39 - 39: I1Ii111
 if 86 - 86: I11i * I1IiiI + I11i + II111iiii
 if 8 - 8: I1Ii111 - iII111i / ooOoO0o
def lisp_set_exception ( ) :
 sys . excepthook = lisp_record_traceback
 return
 if 96 - 96: OoOoOO00
 if 29 - 29: I1ii11iIi11i / i1IIi . I1IiiI - OoOoOO00 - OoOoOO00 - Ii1I
 if 20 - 20: i1IIi % OoO0O00 . I1IiiI / IiII * i11iIiiIii * OOooOOo
 if 85 - 85: o0oOOo0O0Ooo . OoOoOO00 / ooOoO0o . O0 % I1Ii111
 if 90 - 90: Oo0Ooo % O0 * iIii1I11I1II1 . iII111i
 if 8 - 8: ooOoO0o + II111iiii / iII111i / I11i
 if 74 - 74: O0 / i1IIi
def lisp_is_raspbian ( ) :
 if ( platform . dist ( ) [ 0 ] != "debian" ) : return ( False )
 return ( platform . machine ( ) in [ "armv6l" , "armv7l" ] )
 if 78 - 78: OoooooooOO . OoO0O00 + ooOoO0o - i1IIi
 if 31 - 31: OoooooooOO . OOooOOo
 if 83 - 83: iII111i . O0 / Oo0Ooo / OOooOOo - II111iiii
 if 100 - 100: OoO0O00
 if 46 - 46: OoOoOO00 / iIii1I11I1II1 % iII111i . iIii1I11I1II1 * iII111i
 if 38 - 38: I1ii11iIi11i - iII111i / O0 . I1Ii111
 if 45 - 45: I1Ii111
def lisp_is_ubuntu ( ) :
 return ( platform . dist ( ) [ 0 ] == "Ubuntu" )
 if 83 - 83: OoOoOO00 . OoooooooOO
 if 58 - 58: i11iIiiIii + OoooooooOO % OoooooooOO / IiII / i11iIiiIii
 if 62 - 62: OoO0O00 / I1ii11iIi11i
 if 7 - 7: OoooooooOO . IiII
 if 53 - 53: Ii1I % Ii1I * o0oOOo0O0Ooo + OoOoOO00
 if 92 - 92: OoooooooOO + i1IIi / Ii1I * O0
 if 100 - 100: ooOoO0o % iIii1I11I1II1 * II111iiii - iII111i
def lisp_is_fedora ( ) :
 return ( platform . dist ( ) [ 0 ] == "fedora" )
 if 92 - 92: ooOoO0o
 if 22 - 22: Oo0Ooo % iII111i * I1ii11iIi11i / OOooOOo % i11iIiiIii * I11i
 if 95 - 95: OoooooooOO - IiII * I1IiiI + OoOoOO00
 if 10 - 10: o0oOOo0O0Ooo / i11iIiiIii
 if 92 - 92: I11i . I1Ii111
 if 85 - 85: I1ii11iIi11i . I1Ii111
 if 78 - 78: ooOoO0o * I1Ii111 + iIii1I11I1II1 + iIii1I11I1II1 / I1Ii111 . Ii1I
def lisp_is_centos ( ) :
 return ( platform . dist ( ) [ 0 ] == "centos" )
 if 97 - 97: ooOoO0o / I1Ii111 % i1IIi % I1ii11iIi11i
 if 18 - 18: iIii1I11I1II1 % I11i
 if 95 - 95: ooOoO0o + i11iIiiIii * I1Ii111 - i1IIi * I1Ii111 - iIii1I11I1II1
 if 75 - 75: OoooooooOO * IiII
 if 9 - 9: IiII - II111iiii + O0 / iIii1I11I1II1 / i11iIiiIii
 if 39 - 39: IiII * Oo0Ooo + iIii1I11I1II1 - IiII + OOooOOo
 if 69 - 69: O0
def lisp_is_debian ( ) :
 return ( platform . dist ( ) [ 0 ] == "debian" )
 if 85 - 85: ooOoO0o / O0
 if 18 - 18: o0oOOo0O0Ooo % O0 * I1ii11iIi11i
 if 62 - 62: I1Ii111 . IiII . OoooooooOO
 if 11 - 11: OOooOOo / I11i
 if 73 - 73: i1IIi / i11iIiiIii
 if 58 - 58: Oo0Ooo . II111iiii + oO0o - i11iIiiIii / II111iiii / O0
 if 85 - 85: OoOoOO00 + OOooOOo
def lisp_is_debian_kali ( ) :
 return ( platform . dist ( ) [ 0 ] == "Kali" )
 if 10 - 10: IiII / OoO0O00 + OoOoOO00 / i1IIi
 if 27 - 27: Ii1I
 if 67 - 67: I1IiiI
 if 55 - 55: I1ii11iIi11i - iII111i * o0oOOo0O0Ooo + OoOoOO00 * OoOoOO00 * O0
 if 91 - 91: I1Ii111 - OOooOOo % iIii1I11I1II1 - OoooooooOO % ooOoO0o
 if 98 - 98: OoO0O00 . OoO0O00 * oO0o * II111iiii * I1Ii111
 if 92 - 92: Oo0Ooo
def lisp_is_macos ( ) :
 return ( platform . uname ( ) [ 0 ] == "Darwin" )
 if 40 - 40: OoOoOO00 / IiII
 if 79 - 79: OoO0O00 - iIii1I11I1II1 + Ii1I - I1Ii111
 if 93 - 93: II111iiii . I1IiiI - Oo0Ooo + OoOoOO00
 if 61 - 61: II111iiii
 if 15 - 15: i11iIiiIii % I1IiiI * I11i / I1Ii111
 if 90 - 90: iII111i
 if 31 - 31: OOooOOo + O0
def lisp_is_alpine ( ) :
 return ( os . path . exists ( "/etc/alpine-release" ) )
 if 87 - 87: ooOoO0o
 if 45 - 45: OoO0O00 / OoooooooOO - iII111i / Ii1I % IiII
 if 83 - 83: I1IiiI . iIii1I11I1II1 - IiII * i11iIiiIii
 if 20 - 20: i1IIi * I1Ii111 + II111iiii % o0oOOo0O0Ooo % oO0o
 if 13 - 13: Oo0Ooo
 if 60 - 60: I1ii11iIi11i * I1IiiI
 if 17 - 17: OOooOOo % Oo0Ooo / I1ii11iIi11i . IiII * OOooOOo - II111iiii
def lisp_is_x86 ( ) :
 i1i1IIii1i1 = platform . machine ( )
 return ( i1i1IIii1i1 in ( "x86" , "i686" , "x86_64" ) )
 if 65 - 65: I1IiiI + OoOoOO00 / OOooOOo
 if 83 - 83: o0oOOo0O0Ooo . iII111i - Oo0Ooo
 if 65 - 65: iIii1I11I1II1 / ooOoO0o . IiII - II111iiii
 if 72 - 72: iIii1I11I1II1 / IiII % iII111i % OOooOOo - I11i % OOooOOo
 if 100 - 100: Oo0Ooo + i11iIiiIii
 if 71 - 71: I11i / o0oOOo0O0Ooo / I1Ii111 % OOooOOo
 if 51 - 51: IiII * O0 / II111iiii . Ii1I % OOooOOo / I1IiiI
def lisp_is_linux ( ) :
 return ( platform . uname ( ) [ 0 ] == "Linux" )
 if 9 - 9: I1IiiI % I1IiiI % II111iiii
 if 30 - 30: IiII + I1Ii111 - IiII . IiII - II111iiii + O0
 if 86 - 86: i1IIi
 if 41 - 41: OoOoOO00 * I11i / OoOoOO00 % oO0o
 if 18 - 18: II111iiii . OoooooooOO % OoOoOO00 % Ii1I
 if 9 - 9: OoO0O00 - Oo0Ooo * OoooooooOO . Oo0Ooo
 if 2 - 2: OoooooooOO % OOooOOo
def lisp_on_aws ( ) :
 oOoOOo0oo0 = commands . getoutput ( "sudo dmidecode -s bios-version" )
 if ( oOoOOo0oo0 . find ( "command not found" ) != - 1 and lisp_on_docker ( ) ) :
  o0O0Oo00Oo0o = bold ( "AWS check" , False )
  lprint ( "{} - dmidecode not installed in docker container" . format ( o0O0Oo00Oo0o ) )
  if 74 - 74: Oo0Ooo / i11iIiiIii - II111iiii * o0oOOo0O0Ooo
 return ( oOoOOo0oo0 . lower ( ) . find ( "amazon" ) != - 1 )
 if 5 - 5: OOooOOo - OOooOOo . Oo0Ooo + OoOoOO00 - OOooOOo . oO0o
 if 31 - 31: II111iiii - iIii1I11I1II1 - iIii1I11I1II1 % I11i
 if 12 - 12: iIii1I11I1II1
 if 20 - 20: o0oOOo0O0Ooo / i1IIi
 if 71 - 71: OoOoOO00 . i1IIi
 if 94 - 94: OOooOOo . I1Ii111
 if 84 - 84: O0 . I11i - II111iiii . ooOoO0o / II111iiii
def lisp_on_gcp ( ) :
 oOoOOo0oo0 = commands . getoutput ( "sudo dmidecode -s bios-version" )
 return ( oOoOOo0oo0 . lower ( ) . find ( "google" ) != - 1 )
 if 47 - 47: OoooooooOO
 if 4 - 4: I1IiiI % I11i
 if 10 - 10: IiII . OoooooooOO - OoO0O00 + IiII - O0
 if 82 - 82: ooOoO0o + II111iiii
 if 39 - 39: oO0o % iIii1I11I1II1 % O0 % OoooooooOO * I1ii11iIi11i + iII111i
 if 68 - 68: Oo0Ooo + i11iIiiIii
 if 69 - 69: iIii1I11I1II1 * iIii1I11I1II1 * i11iIiiIii + I1IiiI / OOooOOo % Ii1I
def lisp_on_docker ( ) :
 return ( os . path . exists ( "/.dockerenv" ) )
 if 58 - 58: OOooOOo * o0oOOo0O0Ooo + O0 % OOooOOo
 if 25 - 25: Oo0Ooo % I1ii11iIi11i * ooOoO0o
 if 6 - 6: iII111i . IiII * OoOoOO00 . i1IIi
 if 98 - 98: i1IIi
 if 65 - 65: OoOoOO00 / OoO0O00 % IiII
 if 45 - 45: OoOoOO00
 if 66 - 66: OoO0O00
 if 56 - 56: O0
def lisp_process_logfile ( ) :
 OOo00 = "./logs/lisp-{}.log" . format ( lisp_log_id )
 if ( os . path . exists ( OOo00 ) ) : return
 if 37 - 37: i1IIi
 sys . stdout . close ( )
 sys . stdout = open ( OOo00 , "a" )
 if 46 - 46: OoOoOO00 - I11i - Ii1I . i1IIi
 lisp_print_banner ( bold ( "logfile rotation" , False ) )
 return
 if 35 - 35: II111iiii * I11i - OoooooooOO . I11i . I11i
 if 11 - 11: I1Ii111 / OoOoOO00 + I11i % iIii1I11I1II1
 if 42 - 42: I1ii11iIi11i * OoOoOO00 % ooOoO0o - OoOoOO00 . i11iIiiIii - I1Ii111
 if 84 - 84: I1Ii111 - I1ii11iIi11i / I11i
 if 13 - 13: IiII - Oo0Ooo - ooOoO0o
 if 92 - 92: ooOoO0o / OoOoOO00 * OoO0O00 . I11i % II111iiii
 if 71 - 71: I1Ii111 % i1IIi - II111iiii - OOooOOo + OOooOOo * ooOoO0o
 if 51 - 51: iIii1I11I1II1 / OoOoOO00 + OOooOOo - I11i + iII111i
def lisp_i_am ( name ) :
 global lisp_log_id , lisp_i_am_itr , lisp_i_am_etr , lisp_i_am_rtr
 global lisp_i_am_mr , lisp_i_am_ms , lisp_i_am_ddt , lisp_i_am_core
 global lisp_hostname
 if 29 - 29: o0oOOo0O0Ooo % iIii1I11I1II1 . OoooooooOO % OoooooooOO % II111iiii / iII111i
 lisp_log_id = name
 if ( name == "itr" ) : lisp_i_am_itr = True
 if ( name == "etr" ) : lisp_i_am_etr = True
 if ( name == "rtr" ) : lisp_i_am_rtr = True
 if ( name == "mr" ) : lisp_i_am_mr = True
 if ( name == "ms" ) : lisp_i_am_ms = True
 if ( name == "ddt" ) : lisp_i_am_ddt = True
 if ( name == "core" ) : lisp_i_am_core = True
 if 70 - 70: i11iIiiIii % iII111i
 if 11 - 11: IiII % I1ii11iIi11i % Ii1I / II111iiii % I1Ii111 - Oo0Ooo
 if 96 - 96: I1ii11iIi11i / II111iiii . Ii1I - iII111i * I11i * oO0o
 if 76 - 76: Ii1I - II111iiii * OOooOOo / OoooooooOO
 if 18 - 18: OoO0O00 + iIii1I11I1II1 - II111iiii - I1IiiI
 lisp_hostname = socket . gethostname ( )
 ooo = lisp_hostname . find ( "." )
 if ( ooo != - 1 ) : lisp_hostname = lisp_hostname [ 0 : ooo ]
 return
 if 94 - 94: OoOoOO00 - Oo0Ooo - I1IiiI % i1IIi
 if 19 - 19: o0oOOo0O0Ooo
 if 42 - 42: i1IIi . I1IiiI / i1IIi + Ii1I
 if 54 - 54: ooOoO0o % OOooOOo . I1Ii111 + oO0o - OOooOOo * I1IiiI
 if 92 - 92: o0oOOo0O0Ooo + I1Ii111 / Oo0Ooo % OoO0O00 % IiII . OoooooooOO
 if 52 - 52: ooOoO0o / i11iIiiIii - OOooOOo . IiII % iIii1I11I1II1 + o0oOOo0O0Ooo
 if 71 - 71: oO0o % I11i * OoOoOO00 . O0 / Ii1I . I1ii11iIi11i
 if 58 - 58: Oo0Ooo / oO0o
 if 44 - 44: OOooOOo
def lprint ( * args ) :
 O0O0o0o0o = ( "force" in args )
 if ( lisp_debug_logging == False and O0O0o0o0o == False ) : return
 if 9 - 9: Oo0Ooo + OoOoOO00 - iIii1I11I1II1 - Ii1I + o0oOOo0O0Ooo
 lisp_process_logfile ( )
 i1 = datetime . datetime . now ( ) . strftime ( "%m/%d/%y %H:%M:%S.%f" )
 i1 = i1 [ : - 3 ]
 print "{}: {}:" . format ( i1 , lisp_log_id ) ,
 if 97 - 97: OOooOOo
 for OO0OOooOO0 in args :
  if ( OO0OOooOO0 == "force" ) : continue
  print OO0OOooOO0 ,
  if 31 - 31: I1IiiI * oO0o + OoooooooOO - iII111i / OoooooooOO
 print ""
 if 19 - 19: IiII * ooOoO0o * o0oOOo0O0Ooo + O0 / O0
 try : sys . stdout . flush ( )
 except : pass
 return
 if 73 - 73: iIii1I11I1II1 / iIii1I11I1II1 - oO0o
 if 91 - 91: oO0o + I1IiiI
 if 59 - 59: I1IiiI + i11iIiiIii + i1IIi / I11i
 if 44 - 44: I11i . OoOoOO00 * I1IiiI + OoooooooOO - iII111i - IiII
 if 15 - 15: IiII / O0 . o0oOOo0O0Ooo . i11iIiiIii
 if 59 - 59: I1Ii111 - o0oOOo0O0Ooo - ooOoO0o
 if 48 - 48: i1IIi + I11i % OoOoOO00 / Oo0Ooo - o0oOOo0O0Ooo
 if 67 - 67: oO0o % o0oOOo0O0Ooo . OoooooooOO + OOooOOo * I11i * OoOoOO00
def dprint ( * args ) :
 if ( lisp_data_plane_logging ) : lprint ( * args )
 return
 if 36 - 36: O0 + Oo0Ooo
 if 5 - 5: Oo0Ooo * OoOoOO00
 if 46 - 46: ooOoO0o
 if 33 - 33: iII111i - II111iiii * OoooooooOO - Oo0Ooo - OOooOOo
 if 84 - 84: I1Ii111 + Oo0Ooo - OoOoOO00 * OoOoOO00
 if 61 - 61: OoooooooOO . oO0o . OoooooooOO / Oo0Ooo
 if 72 - 72: i1IIi
 if 82 - 82: OoOoOO00 + OoooooooOO / i11iIiiIii * I1ii11iIi11i . OoooooooOO
def debug ( * args ) :
 lisp_process_logfile ( )
 if 63 - 63: I1ii11iIi11i
 i1 = datetime . datetime . now ( ) . strftime ( "%m/%d/%y %H:%M:%S.%f" )
 i1 = i1 [ : - 3 ]
 if 6 - 6: ooOoO0o / I1ii11iIi11i
 print red ( ">>>" , False ) ,
 print "{}:" . format ( i1 ) ,
 for OO0OOooOO0 in args : print OO0OOooOO0 ,
 print red ( "<<<\n" , False )
 try : sys . stdout . flush ( )
 except : pass
 return
 if 57 - 57: I11i
 if 67 - 67: OoO0O00 . ooOoO0o
 if 87 - 87: oO0o % Ii1I
 if 83 - 83: II111iiii - I11i
 if 35 - 35: i1IIi - iIii1I11I1II1 + i1IIi
 if 86 - 86: iIii1I11I1II1 + OoOoOO00 . i11iIiiIii - Ii1I
 if 51 - 51: OoOoOO00
def lisp_print_banner ( string ) :
 global lisp_version , lisp_hostname
 if 14 - 14: IiII % oO0o % Oo0Ooo - i11iIiiIii
 if ( lisp_version == "" ) :
  lisp_version = commands . getoutput ( "cat lisp-version.txt" )
  if 53 - 53: Ii1I % Oo0Ooo
 O0ooOo0o0Oo = bold ( lisp_hostname , False )
 lprint ( "lispers.net LISP {} {}, version {}, hostname {}" . format ( string ,
 datetime . datetime . now ( ) , lisp_version , O0ooOo0o0Oo ) )
 return
 if 71 - 71: iIii1I11I1II1 - OOooOOo . I1IiiI % OoooooooOO + OOooOOo
 if 26 - 26: Oo0Ooo + OOooOOo / OoO0O00 % OoOoOO00 % I1ii11iIi11i + II111iiii
 if 31 - 31: I11i % OOooOOo * I11i
 if 45 - 45: i1IIi . I1IiiI + OOooOOo - OoooooooOO % ooOoO0o
 if 1 - 1: iIii1I11I1II1
 if 93 - 93: i1IIi . i11iIiiIii . Oo0Ooo
 if 99 - 99: I11i - I1Ii111 - oO0o % OoO0O00
def green ( string , html ) :
 if ( html ) : return ( '<font color="green"><b>{}</b></font>' . format ( string ) )
 return ( bold ( "\033[92m" + string + "\033[0m" , html ) )
 if 21 - 21: II111iiii % I1ii11iIi11i . i1IIi - OoooooooOO
 if 4 - 4: OoooooooOO . ooOoO0o
 if 78 - 78: I1ii11iIi11i + I11i - O0
 if 10 - 10: I1Ii111 % I1IiiI
 if 97 - 97: OoooooooOO - I1Ii111
 if 58 - 58: iIii1I11I1II1 + O0
 if 30 - 30: ooOoO0o % iII111i * OOooOOo - I1ii11iIi11i * Ii1I % ooOoO0o
def green_last_sec ( string ) :
 return ( green ( string , True ) )
 if 46 - 46: i11iIiiIii - O0 . oO0o
 if 100 - 100: I1IiiI / o0oOOo0O0Ooo * iII111i . O0 / OOooOOo
 if 83 - 83: I1Ii111
 if 48 - 48: II111iiii * OOooOOo * I1Ii111
 if 50 - 50: IiII % i1IIi
 if 21 - 21: OoooooooOO - iIii1I11I1II1
 if 93 - 93: oO0o - o0oOOo0O0Ooo % OoOoOO00 . OoOoOO00 - ooOoO0o
def green_last_min ( string ) :
 return ( '<font color="#58D68D"><b>{}</b></font>' . format ( string ) )
 if 90 - 90: ooOoO0o + II111iiii * I1ii11iIi11i / Ii1I . o0oOOo0O0Ooo + o0oOOo0O0Ooo
 if 40 - 40: ooOoO0o / OoOoOO00 % i11iIiiIii % I1ii11iIi11i / I1IiiI
 if 62 - 62: i1IIi - OoOoOO00
 if 62 - 62: i1IIi + Oo0Ooo % IiII
 if 28 - 28: I1ii11iIi11i . i1IIi
 if 10 - 10: OoO0O00 / Oo0Ooo
 if 15 - 15: iII111i . OoOoOO00 / iII111i * I11i - I1IiiI % I1ii11iIi11i
def red ( string , html ) :
 if ( html ) : return ( '<font color="red"><b>{}</b></font>' . format ( string ) )
 return ( bold ( "\033[91m" + string + "\033[0m" , html ) )
 if 57 - 57: O0 % OoOoOO00 % oO0o
 if 45 - 45: I1ii11iIi11i + II111iiii * i11iIiiIii
 if 13 - 13: OoooooooOO * oO0o - Ii1I / OOooOOo + I11i + IiII
 if 39 - 39: iIii1I11I1II1 - OoooooooOO
 if 81 - 81: I1ii11iIi11i - O0 * OoooooooOO
 if 23 - 23: II111iiii / oO0o
 if 28 - 28: Oo0Ooo * ooOoO0o - OoO0O00
def blue ( string , html ) :
 if ( html ) : return ( '<font color="blue"><b>{}</b></font>' . format ( string ) )
 return ( bold ( "\033[94m" + string + "\033[0m" , html ) )
 if 19 - 19: I11i
 if 67 - 67: O0 % iIii1I11I1II1 / IiII . i11iIiiIii - Ii1I + O0
 if 27 - 27: OOooOOo
 if 89 - 89: II111iiii / oO0o
 if 14 - 14: OOooOOo . I1IiiI * ooOoO0o + II111iiii - ooOoO0o + OOooOOo
 if 18 - 18: oO0o - o0oOOo0O0Ooo - I1IiiI - I1IiiI
 if 54 - 54: Oo0Ooo + I1IiiI / iII111i . I1IiiI * OoOoOO00
def bold ( string , html ) :
 if ( html ) : return ( "<b>{}</b>" . format ( string ) )
 return ( "\033[1m" + string + "\033[0m" )
 if 1 - 1: OoOoOO00 * OoO0O00 . i1IIi / Oo0Ooo . I1ii11iIi11i + Oo0Ooo
 if 17 - 17: Oo0Ooo + OoO0O00 / Ii1I / iII111i * OOooOOo
 if 29 - 29: OoO0O00 % OoooooooOO * oO0o / II111iiii - oO0o
 if 19 - 19: i11iIiiIii
 if 54 - 54: II111iiii . I11i
 if 73 - 73: OoOoOO00 . I1IiiI
 if 32 - 32: OoOoOO00 * I1IiiI % ooOoO0o * Ii1I . O0
def convert_font ( string ) :
 i11i1i1I1iI1 = [ [ "[91m" , red ] , [ "[92m" , green ] , [ "[94m" , blue ] , [ "[1m" , bold ] ]
 O0ooOo0 = "[0m"
 if 53 - 53: OoooooooOO - IiII
 for oOo in i11i1i1I1iI1 :
  i1i = oOo [ 0 ]
  IIIiiiI = oOo [ 1 ]
  OoO00oo00 = len ( i1i )
  ooo = string . find ( i1i )
  if ( ooo != - 1 ) : break
  if 76 - 76: OoooooooOO + Oo0Ooo % IiII . OoO0O00 + II111iiii
  if 70 - 70: I1IiiI / I11i
 while ( ooo != - 1 ) :
  IIiiiiIiIIii = string [ ooo : : ] . find ( O0ooOo0 )
  O0OO = string [ ooo + OoO00oo00 : ooo + IIiiiiIiIIii ]
  string = string [ : ooo ] + IIIiiiI ( O0OO , True ) + string [ ooo + IIiiiiIiIIii + OoO00oo00 : : ]
  if 39 - 39: I1ii11iIi11i + I1IiiI - iIii1I11I1II1 - o0oOOo0O0Ooo
  ooo = string . find ( i1i )
  if 7 - 7: IiII . OoOoOO00 / I1ii11iIi11i . OOooOOo * I11i - II111iiii
  if 37 - 37: I1Ii111 . OoOoOO00 / O0 * iII111i
  if 7 - 7: OoO0O00 * I11i + II111iiii % i11iIiiIii
  if 8 - 8: ooOoO0o * O0
  if 73 - 73: o0oOOo0O0Ooo / oO0o / I11i / OoO0O00
 if ( string . find ( "[1m" ) != - 1 ) : string = convert_font ( string )
 return ( string )
 if 11 - 11: OoOoOO00 + IiII - OoooooooOO / OoO0O00
 if 34 - 34: ooOoO0o
 if 45 - 45: ooOoO0o / Oo0Ooo / Ii1I
 if 44 - 44: I1ii11iIi11i - Ii1I / II111iiii * OoO0O00 * Oo0Ooo
 if 73 - 73: o0oOOo0O0Ooo - I1IiiI * i1IIi / i11iIiiIii * OOooOOo % II111iiii
 if 56 - 56: OoooooooOO * Oo0Ooo . Oo0Ooo . I1ii11iIi11i
 if 24 - 24: Oo0Ooo . I11i * Ii1I % iII111i / OOooOOo
def lisp_space ( num ) :
 Oo0Ooo0O0 = ""
 for IiIIi1IiiIiI in range ( num ) : Oo0Ooo0O0 += "&#160;"
 return ( Oo0Ooo0O0 )
 if 23 - 23: I11i
 if 40 - 40: o0oOOo0O0Ooo - II111iiii / Oo0Ooo
 if 14 - 14: I1ii11iIi11i
 if 5 - 5: o0oOOo0O0Ooo . iIii1I11I1II1 % iIii1I11I1II1
 if 56 - 56: OoooooooOO - I11i - i1IIi
 if 8 - 8: I1Ii111 / OOooOOo . I1IiiI + I1ii11iIi11i / i11iIiiIii
 if 31 - 31: ooOoO0o - iIii1I11I1II1 + iII111i . Oo0Ooo / IiII % iIii1I11I1II1
def lisp_button ( string , url ) :
 I11i1iIiiIiIi = '<button style="background-color:transparent;border-radius:10px; ' + 'type="button">'
 if 49 - 49: OOooOOo . I1ii11iIi11i . i11iIiiIii - II111iiii / Ii1I
 if 62 - 62: OOooOOo
 if ( url == None ) :
  i1I1i = I11i1iIiiIiIi + string + "</button>"
 else :
  OO0o = '<a href="{}">' . format ( url )
  IiII1iiI = lisp_space ( 2 )
  i1I1i = IiII1iiI + OO0o + I11i1iIiiIiIi + string + "</button></a>" + IiII1iiI
  if 34 - 34: I1IiiI . oO0o + i1IIi
 return ( i1I1i )
 if 98 - 98: oO0o % IiII * i11iIiiIii % I1ii11iIi11i
 if 29 - 29: IiII
 if 66 - 66: Oo0Ooo
 if 97 - 97: i1IIi - OoooooooOO / I1Ii111 * I1IiiI
 if 55 - 55: o0oOOo0O0Ooo . iII111i
 if 87 - 87: o0oOOo0O0Ooo % iIii1I11I1II1
 if 100 - 100: I1Ii111 . I1IiiI * I1Ii111 - I1IiiI . I11i * Ii1I
def lisp_print_cour ( string ) :
 Oo0Ooo0O0 = '<font face="Courier New">{}</font>' . format ( string )
 return ( Oo0Ooo0O0 )
 if 89 - 89: OoO0O00 + IiII * I1Ii111
 if 28 - 28: OoooooooOO . oO0o % I1ii11iIi11i / i1IIi / OOooOOo
 if 36 - 36: o0oOOo0O0Ooo + I11i - IiII + iIii1I11I1II1 + OoooooooOO
 if 4 - 4: II111iiii . I11i + Ii1I * I1Ii111 . ooOoO0o
 if 87 - 87: OoOoOO00 / OoO0O00 / i11iIiiIii
 if 74 - 74: oO0o / I1ii11iIi11i % o0oOOo0O0Ooo
 if 88 - 88: OoOoOO00 - i11iIiiIii % o0oOOo0O0Ooo * I11i + I1ii11iIi11i
def lisp_print_sans ( string ) :
 Oo0Ooo0O0 = '<font face="Sans-Serif">{}</font>' . format ( string )
 return ( Oo0Ooo0O0 )
 if 52 - 52: II111iiii . I1IiiI + OoOoOO00 % OoO0O00
 if 62 - 62: o0oOOo0O0Ooo
 if 15 - 15: I11i + Ii1I . OOooOOo * OoO0O00 . OoOoOO00
 if 18 - 18: i1IIi % II111iiii + I1Ii111 % Ii1I
 if 72 - 72: iIii1I11I1II1
 if 45 - 45: Oo0Ooo - o0oOOo0O0Ooo % I1Ii111
 if 38 - 38: I1Ii111 % OOooOOo - OoooooooOO
def lisp_span ( string , hover_string ) :
 Oo0Ooo0O0 = '<span title="{}">{}</span>' . format ( hover_string , string )
 return ( Oo0Ooo0O0 )
 if 87 - 87: OoO0O00 % I1IiiI
 if 77 - 77: iIii1I11I1II1 - i1IIi . oO0o
 if 26 - 26: o0oOOo0O0Ooo * IiII . i1IIi
 if 59 - 59: O0 + i1IIi - o0oOOo0O0Ooo
 if 62 - 62: i11iIiiIii % OOooOOo . IiII . OOooOOo
 if 84 - 84: i11iIiiIii * OoO0O00
 if 18 - 18: OOooOOo - Ii1I - OoOoOO00 / I1Ii111 - O0
def lisp_eid_help_hover ( output ) :
 iiIIii = '''Unicast EID format:
  For longest match lookups: 
    <address> or [<iid>]<address>
  For exact match lookups: 
    <prefix> or [<iid>]<prefix>
Multicast EID format:
  For longest match lookups:
    <address>-><group> or
    [<iid>]<address>->[<iid>]<group>'''
 if 70 - 70: o0oOOo0O0Ooo - OOooOOo
 if 62 - 62: I11i
 O000oOo = lisp_span ( output , iiIIii )
 return ( O000oOo )
 if 53 - 53: iIii1I11I1II1 + o0oOOo0O0Ooo - OoOoOO00 - oO0o / ooOoO0o % i11iIiiIii
 if 3 - 3: iII111i . ooOoO0o % I1IiiI + I1ii11iIi11i
 if 64 - 64: i1IIi
 if 29 - 29: o0oOOo0O0Ooo / i11iIiiIii / I1IiiI % oO0o % i11iIiiIii
 if 18 - 18: OOooOOo + I1Ii111
 if 80 - 80: oO0o + o0oOOo0O0Ooo * Ii1I + OoO0O00
 if 75 - 75: I11i / o0oOOo0O0Ooo / OOooOOo / IiII % ooOoO0o + II111iiii
def lisp_geo_help_hover ( output ) :
 iiIIii = '''EID format:
    <address> or [<iid>]<address>
    '<name>' or [<iid>]'<name>'
Geo-Point format:
    d-m-s-<N|S>-d-m-s-<W|E> or 
    [<iid>]d-m-s-<N|S>-d-m-s-<W|E>
Geo-Prefix format:
    d-m-s-<N|S>-d-m-s-<W|E>/<km> or
    [<iid>]d-m-s-<N|S>-d-m-s-<W|E>/<km>'''
 if 4 - 4: iII111i - Oo0Ooo - IiII - I11i % i11iIiiIii / OoO0O00
 if 50 - 50: ooOoO0o + i1IIi
 O000oOo = lisp_span ( output , iiIIii )
 return ( O000oOo )
 if 31 - 31: Ii1I
 if 78 - 78: i11iIiiIii + o0oOOo0O0Ooo + I1Ii111 / o0oOOo0O0Ooo % iIii1I11I1II1 % IiII
 if 83 - 83: iIii1I11I1II1 % OoOoOO00 % o0oOOo0O0Ooo % I1Ii111 . I1ii11iIi11i % O0
 if 47 - 47: o0oOOo0O0Ooo
 if 66 - 66: I1IiiI - IiII
 if 33 - 33: I1IiiI / OoO0O00
 if 12 - 12: II111iiii
def space ( num ) :
 Oo0Ooo0O0 = ""
 for IiIIi1IiiIiI in range ( num ) : Oo0Ooo0O0 += "&#160;"
 return ( Oo0Ooo0O0 )
 if 2 - 2: i1IIi - I1IiiI + I11i . II111iiii
 if 25 - 25: oO0o
 if 34 - 34: OoOoOO00 . iIii1I11I1II1 % O0
 if 43 - 43: I1ii11iIi11i - iII111i
 if 70 - 70: iII111i / OOooOOo % ooOoO0o - Ii1I
 if 47 - 47: iII111i
 if 92 - 92: OOooOOo + OoOoOO00 % i1IIi
 if 23 - 23: I1Ii111 - OOooOOo + Ii1I - OoOoOO00 * OoOoOO00 . Oo0Ooo
def lisp_get_ephemeral_port ( ) :
 return ( random . randrange ( 32768 , 65535 ) )
 if 47 - 47: oO0o % iIii1I11I1II1
 if 11 - 11: I1IiiI % Ii1I - OoO0O00 - oO0o + o0oOOo0O0Ooo
 if 98 - 98: iII111i + Ii1I - OoO0O00
 if 79 - 79: OOooOOo / I1Ii111 . OoOoOO00 - I1ii11iIi11i
 if 47 - 47: OoooooooOO % O0 * iII111i . Ii1I
 if 38 - 38: O0 - IiII % I1Ii111
 if 64 - 64: iIii1I11I1II1
def lisp_get_data_nonce ( ) :
 return ( random . randint ( 0 , 0xffffff ) )
 if 15 - 15: I1ii11iIi11i + OOooOOo / I1ii11iIi11i / I1Ii111
 if 31 - 31: ooOoO0o + O0 + ooOoO0o . iIii1I11I1II1 + Oo0Ooo / o0oOOo0O0Ooo
 if 6 - 6: Oo0Ooo % IiII * I11i / I1IiiI + Oo0Ooo
 if 39 - 39: OoOoOO00 - Oo0Ooo / iII111i * OoooooooOO
 if 100 - 100: O0 . I11i . OoO0O00 + O0 * oO0o
 if 42 - 42: oO0o % OoooooooOO + o0oOOo0O0Ooo
 if 56 - 56: OoooooooOO + I1ii11iIi11i - iII111i
def lisp_get_control_nonce ( ) :
 return ( random . randint ( 0 , ( 2 ** 64 ) - 1 ) )
 if 24 - 24: o0oOOo0O0Ooo + ooOoO0o + I11i - iIii1I11I1II1
 if 49 - 49: I11i . ooOoO0o * OoOoOO00 % IiII . O0
 if 48 - 48: O0 * Ii1I - O0 / Ii1I + OoOoOO00
 if 52 - 52: OoO0O00 % Ii1I * II111iiii
 if 4 - 4: I11i % O0 - OoooooooOO + ooOoO0o . oO0o % II111iiii
 if 9 - 9: II111iiii * II111iiii . i11iIiiIii * iIii1I11I1II1
 if 18 - 18: OoO0O00 . II111iiii % OoOoOO00 % Ii1I
 if 87 - 87: iIii1I11I1II1 . OoooooooOO * OoOoOO00
 if 100 - 100: OoO0O00 / i1IIi - I1IiiI % Ii1I - iIii1I11I1II1
def lisp_hex_string ( integer_value ) :
 i11II = hex ( integer_value ) [ 2 : : ]
 if ( i11II [ - 1 ] == "L" ) : i11II = i11II [ 0 : - 1 ]
 return ( i11II )
 if 71 - 71: IiII . I1Ii111 . OoO0O00
 if 68 - 68: i11iIiiIii % oO0o * OoO0O00 * IiII * II111iiii + O0
 if 66 - 66: I11i % I1ii11iIi11i % OoooooooOO
 if 34 - 34: o0oOOo0O0Ooo / iII111i % O0 . OoO0O00 . i1IIi
 if 29 - 29: O0 . I1Ii111
 if 66 - 66: oO0o * iIii1I11I1II1 % iIii1I11I1II1 * IiII - ooOoO0o - IiII
 if 70 - 70: I1Ii111 + oO0o
def lisp_get_timestamp ( ) :
 return ( time . time ( ) )
 if 93 - 93: I1Ii111 + Ii1I
 if 33 - 33: O0
 if 78 - 78: O0 / II111iiii * OoO0O00
 if 50 - 50: OoooooooOO - iIii1I11I1II1 + i1IIi % I1Ii111 - iIii1I11I1II1 % O0
 if 58 - 58: IiII + iIii1I11I1II1
 if 65 - 65: II111iiii - I1Ii111 % o0oOOo0O0Ooo - OoOoOO00 * iII111i + Ii1I
 if 79 - 79: ooOoO0o . OoOoOO00 % I1Ii111 - Oo0Ooo
def lisp_set_timestamp ( seconds ) :
 return ( time . time ( ) + seconds )
 if 69 - 69: ooOoO0o - o0oOOo0O0Ooo . ooOoO0o
 if 9 - 9: oO0o % i11iIiiIii / Oo0Ooo
 if 20 - 20: oO0o * O0 + I11i - OoooooooOO . I11i
 if 60 - 60: o0oOOo0O0Ooo . o0oOOo0O0Ooo / iII111i
 if 45 - 45: O0 . i11iIiiIii % iII111i . OoOoOO00 % IiII % iIii1I11I1II1
 if 58 - 58: iIii1I11I1II1 . OoOoOO00 - i11iIiiIii * iIii1I11I1II1 % i11iIiiIii / I1IiiI
 if 80 - 80: I1ii11iIi11i / iIii1I11I1II1 % OoOoOO00
def lisp_print_elapsed ( ts ) :
 if ( ts == 0 or ts == None ) : return ( "never" )
 oO000o0Oo00 = time . time ( ) - ts
 oO000o0Oo00 = round ( oO000o0Oo00 , 0 )
 return ( str ( datetime . timedelta ( seconds = oO000o0Oo00 ) ) )
 if 77 - 77: iIii1I11I1II1 + OoO0O00 . I1ii11iIi11i % OoO0O00
 if 93 - 93: O0
 if 85 - 85: i11iIiiIii % i11iIiiIii + O0 / OOooOOo
 if 89 - 89: Ii1I % i1IIi % oO0o
 if 53 - 53: oO0o * OoooooooOO . OoOoOO00
 if 96 - 96: I1IiiI % i1IIi . o0oOOo0O0Ooo . O0
 if 37 - 37: i1IIi - OOooOOo % OoooooooOO / OOooOOo % ooOoO0o
def lisp_print_future ( ts ) :
 if ( ts == 0 ) : return ( "never" )
 iiIiII11i1 = ts - time . time ( )
 if ( iiIiII11i1 < 0 ) : return ( "expired" )
 iiIiII11i1 = round ( iiIiII11i1 , 0 )
 return ( str ( datetime . timedelta ( seconds = iiIiII11i1 ) ) )
 if 93 - 93: OoOoOO00 % iIii1I11I1II1
 if 90 - 90: I1IiiI - OOooOOo / Ii1I / O0 / I11i
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
 if 78 - 78: Ii1I + OoOoOO00 + IiII - IiII . i11iIiiIii / OoO0O00
def lisp_print_eid_tuple ( eid , group ) :
 I11i11i1 = eid . print_prefix ( )
 if ( group . is_null ( ) ) : return ( I11i11i1 )
 if 68 - 68: Oo0Ooo . Oo0Ooo - I1ii11iIi11i / I11i . ooOoO0o / i1IIi
 iI1i1iIi1iiII = group . print_prefix ( )
 o0OoO0000o = group . instance_id
 if 90 - 90: IiII . ooOoO0o / iIii1I11I1II1
 if ( eid . is_null ( ) or eid . is_exact_match ( group ) ) :
  ooo = iI1i1iIi1iiII . find ( "]" ) + 1
  return ( "[{}](*, {})" . format ( o0OoO0000o , iI1i1iIi1iiII [ ooo : : ] ) )
  if 28 - 28: IiII + oO0o - ooOoO0o / iIii1I11I1II1 - I1IiiI
  if 45 - 45: O0 / i1IIi * oO0o * OoO0O00
 II11I = eid . print_sg ( group )
 return ( II11I )
 if 31 - 31: Ii1I
 if 18 - 18: ooOoO0o + Ii1I
 if 5 - 5: OoooooooOO + I11i * II111iiii
 if 98 - 98: OOooOOo % i1IIi . I1IiiI . II111iiii . I1ii11iIi11i / i11iIiiIii
 if 32 - 32: o0oOOo0O0Ooo + I1IiiI . I1Ii111
 if 41 - 41: OoOoOO00 . i11iIiiIii / I11i
 if 98 - 98: OoOoOO00 % II111iiii
 if 95 - 95: iIii1I11I1II1 - I1Ii111 - OOooOOo + I1Ii111 % I1ii11iIi11i . I1IiiI
def lisp_convert_6to4 ( addr_str ) :
 if ( addr_str . find ( "::ffff:" ) == - 1 ) : return ( addr_str )
 IiiIIi1 = addr_str . split ( ":" )
 return ( IiiIIi1 [ - 1 ] )
 if 28 - 28: o0oOOo0O0Ooo
 if 45 - 45: o0oOOo0O0Ooo . I1IiiI / I1Ii111 - Oo0Ooo * iIii1I11I1II1
 if 86 - 86: II111iiii + ooOoO0o + IiII
 if 9 - 9: ooOoO0o + II111iiii % ooOoO0o % IiII + iIii1I11I1II1
 if 59 - 59: i1IIi
 if 48 - 48: O0 * Ii1I * OoO0O00 . OoO0O00 * I11i - Ii1I
 if 14 - 14: I1ii11iIi11i + i11iIiiIii
 if 83 - 83: I1ii11iIi11i / i11iIiiIii + II111iiii . iII111i * OOooOOo + IiII
 if 42 - 42: i1IIi % II111iiii . ooOoO0o
 if 7 - 7: I1ii11iIi11i - oO0o * OOooOOo + o0oOOo0O0Ooo . I1ii11iIi11i
 if 85 - 85: O0
def lisp_convert_4to6 ( addr_str ) :
 IiiIIi1 = lisp_address ( LISP_AFI_IPV6 , "" , 128 , 0 )
 if ( IiiIIi1 . is_ipv4_string ( addr_str ) ) : addr_str = "::ffff:" + addr_str
 IiiIIi1 . store_address ( addr_str )
 return ( IiiIIi1 )
 if 32 - 32: OoooooooOO . OoO0O00 / Oo0Ooo * o0oOOo0O0Ooo / o0oOOo0O0Ooo * Ii1I
 if 19 - 19: Ii1I
 if 55 - 55: OOooOOo % OOooOOo / O0 % iII111i - o0oOOo0O0Ooo . Oo0Ooo
 if 49 - 49: iIii1I11I1II1 * i1IIi . OoooooooOO
 if 90 - 90: o0oOOo0O0Ooo % I1ii11iIi11i - iIii1I11I1II1 % OoOoOO00
 if 8 - 8: OoOoOO00 * Oo0Ooo / IiII % Ii1I - I1IiiI
 if 71 - 71: iII111i
 if 23 - 23: i1IIi . iIii1I11I1II1 . OOooOOo . O0 % Ii1I % i11iIiiIii
 if 11 - 11: O0 - II111iiii . OOooOOo . Ii1I % I1Ii111
def lisp_gethostbyname ( string ) :
 IIi1 = string . split ( "." )
 OoO0oO = string . split ( ":" )
 Ii = string . split ( "-" )
 if 20 - 20: o0oOOo0O0Ooo * ooOoO0o
 if ( len ( IIi1 ) > 1 ) :
  if ( IIi1 [ 0 ] . isdigit ( ) ) : return ( string )
  if 10 - 10: I11i - Oo0Ooo
 if ( len ( OoO0oO ) > 1 ) :
  try :
   int ( OoO0oO [ 0 ] , 16 )
   return ( string )
  except :
   pass
   if 59 - 59: OoooooooOO * Oo0Ooo + i1IIi
   if 23 - 23: ooOoO0o
   if 13 - 13: iIii1I11I1II1
   if 77 - 77: i11iIiiIii - iIii1I11I1II1 / oO0o / ooOoO0o / OoO0O00
   if 56 - 56: OoooooooOO * O0
   if 85 - 85: OoooooooOO % OoOoOO00 * iIii1I11I1II1
   if 44 - 44: iIii1I11I1II1 . I1ii11iIi11i + I1Ii111 . ooOoO0o
 if ( len ( Ii ) == 3 ) :
  for IiIIi1IiiIiI in range ( 3 ) :
   try : int ( Ii [ IiIIi1IiiIiI ] , 16 )
   except : break
   if 7 - 7: I1ii11iIi11i + iIii1I11I1II1 * I11i * I11i / II111iiii - Ii1I
   if 65 - 65: oO0o + OoOoOO00 + II111iiii
   if 77 - 77: II111iiii
 try :
  IiiIIi1 = socket . gethostbyname ( string )
  return ( IiiIIi1 )
 except :
  if ( lisp_is_alpine ( ) == False ) : return ( "" )
  if 50 - 50: O0 . O0 . ooOoO0o % Oo0Ooo
  if 68 - 68: oO0o
  if 10 - 10: Ii1I
  if 77 - 77: OOooOOo / II111iiii + IiII + ooOoO0o - i11iIiiIii
  if 44 - 44: I1IiiI + OoOoOO00 + I1ii11iIi11i . I1IiiI * OoOoOO00 % iIii1I11I1II1
 try :
  IiiIIi1 = socket . getaddrinfo ( string , 0 ) [ 0 ]
  if ( IiiIIi1 [ 3 ] != string ) : return ( "" )
  IiiIIi1 = IiiIIi1 [ 4 ] [ 0 ]
 except :
  IiiIIi1 = ""
  if 72 - 72: OOooOOo . OOooOOo - I1ii11iIi11i
 return ( IiiIIi1 )
 if 48 - 48: Oo0Ooo - ooOoO0o + Oo0Ooo - I1IiiI * i11iIiiIii . iII111i
 if 35 - 35: IiII . O0 + Oo0Ooo + OOooOOo + i1IIi
 if 65 - 65: O0 * I1IiiI / I1IiiI . OoOoOO00
 if 87 - 87: II111iiii * I1ii11iIi11i % Oo0Ooo * Oo0Ooo
 if 58 - 58: OOooOOo . o0oOOo0O0Ooo + I1IiiI % Oo0Ooo - OoO0O00
 if 50 - 50: iII111i % II111iiii - ooOoO0o . i1IIi + O0 % iII111i
 if 10 - 10: iII111i . i1IIi + Ii1I
 if 66 - 66: OoO0O00 % o0oOOo0O0Ooo
def lisp_ip_checksum ( data , hdrlen = 20 ) :
 if ( len ( data ) < hdrlen ) :
  lprint ( "IPv4 packet too short, length {}" . format ( len ( data ) ) )
  return ( data )
  if 21 - 21: OoOoOO00 - OoooooooOO % i11iIiiIii
  if 71 - 71: i1IIi - I11i * I1Ii111 + oO0o - OoO0O00 % I1ii11iIi11i
 Ooo0oO = binascii . hexlify ( data )
 if 32 - 32: i1IIi . iII111i + II111iiii - OoO0O00 - iIii1I11I1II1
 if 20 - 20: OoOoOO00 % I1ii11iIi11i
 if 44 - 44: OoooooooOO . II111iiii . OOooOOo % OoooooooOO
 if 86 - 86: i11iIiiIii + O0 * IiII - OoO0O00 * OOooOOo + O0
 Oo0 = 0
 for IiIIi1IiiIiI in range ( 0 , hdrlen * 2 , 4 ) :
  Oo0 += int ( Ooo0oO [ IiIIi1IiiIiI : IiIIi1IiiIiI + 4 ] , 16 )
  if 94 - 94: I1Ii111 % II111iiii * i1IIi * iIii1I11I1II1
  if 81 - 81: Oo0Ooo - I11i
  if 24 - 24: OoooooooOO . OoO0O00 * II111iiii
  if 59 - 59: I1Ii111 + OoO0O00 / OOooOOo
  if 97 - 97: Oo0Ooo * iII111i % ooOoO0o . iII111i - I1Ii111 - OOooOOo
 Oo0 = ( Oo0 >> 16 ) + ( Oo0 & 0xffff )
 Oo0 += Oo0 >> 16
 Oo0 = socket . htons ( ~ Oo0 & 0xffff )
 if 79 - 79: I1IiiI - ooOoO0o
 if 37 - 37: IiII . Oo0Ooo * Oo0Ooo * II111iiii * O0
 if 83 - 83: IiII / I1Ii111
 if 64 - 64: OoO0O00 % IiII . I1Ii111 % OoO0O00 + I11i * IiII
 Oo0 = struct . pack ( "H" , Oo0 )
 Ooo0oO = data [ 0 : 10 ] + Oo0 + data [ 12 : : ]
 return ( Ooo0oO )
 if 83 - 83: o0oOOo0O0Ooo % oO0o + I11i % i11iIiiIii + O0
 if 65 - 65: iIii1I11I1II1 % oO0o + O0 / OoooooooOO
 if 52 - 52: Ii1I % OOooOOo * I1IiiI % I11i + OOooOOo / iII111i
 if 80 - 80: OoooooooOO + IiII
 if 95 - 95: I1Ii111 / oO0o * I1Ii111 - OoooooooOO * OoooooooOO % OoO0O00
 if 43 - 43: Oo0Ooo . I1Ii111
 if 12 - 12: I1Ii111 + OOooOOo + I11i . IiII / Ii1I
 if 29 - 29: IiII . ooOoO0o - II111iiii
def lisp_icmp_checksum ( data ) :
 if ( len ( data ) < 36 ) :
  lprint ( "ICMP packet too short, length {}" . format ( len ( data ) ) )
  return ( data )
  if 68 - 68: iIii1I11I1II1 + II111iiii / oO0o
  if 91 - 91: OoOoOO00 % iIii1I11I1II1 . I1IiiI
 O00ooooo00 = binascii . hexlify ( data )
 if 94 - 94: I11i - II111iiii . I1IiiI - Oo0Ooo + I1ii11iIi11i * I1ii11iIi11i
 if 27 - 27: IiII * I1IiiI . iIii1I11I1II1 - iIii1I11I1II1
 if 5 - 5: IiII
 if 84 - 84: II111iiii * oO0o * II111iiii % IiII / I1IiiI
 Oo0 = 0
 for IiIIi1IiiIiI in range ( 0 , 36 , 4 ) :
  Oo0 += int ( O00ooooo00 [ IiIIi1IiiIiI : IiIIi1IiiIiI + 4 ] , 16 )
  if 100 - 100: IiII . Ii1I - iIii1I11I1II1 . i11iIiiIii / II111iiii
  if 71 - 71: I1Ii111 * Oo0Ooo . I11i
  if 49 - 49: IiII * O0 . IiII
  if 19 - 19: II111iiii - IiII
  if 59 - 59: o0oOOo0O0Ooo * OoO0O00 - Ii1I . OOooOOo
 Oo0 = ( Oo0 >> 16 ) + ( Oo0 & 0xffff )
 Oo0 += Oo0 >> 16
 Oo0 = socket . htons ( ~ Oo0 & 0xffff )
 if 89 - 89: OOooOOo
 if 69 - 69: ooOoO0o - OoooooooOO * O0
 if 84 - 84: ooOoO0o + i11iIiiIii - OOooOOo * ooOoO0o
 if 33 - 33: ooOoO0o % i1IIi - oO0o . O0 / O0
 Oo0 = struct . pack ( "H" , Oo0 )
 O00ooooo00 = data [ 0 : 2 ] + Oo0 + data [ 4 : : ]
 return ( O00ooooo00 )
 if 96 - 96: OoooooooOO + IiII * O0
 if 86 - 86: Ii1I
 if 29 - 29: iIii1I11I1II1 - OoO0O00 + I1IiiI % iIii1I11I1II1 % OOooOOo
 if 84 - 84: IiII + I1ii11iIi11i + Ii1I + iII111i
 if 62 - 62: i11iIiiIii + OoOoOO00 + i1IIi
 if 69 - 69: OoOoOO00
 if 63 - 63: OoO0O00 / OoOoOO00 * iIii1I11I1II1 . I1Ii111
 if 85 - 85: i11iIiiIii / i11iIiiIii . OoO0O00 . O0
 if 67 - 67: II111iiii / o0oOOo0O0Ooo . OOooOOo . OoooooooOO
 if 19 - 19: IiII . I1ii11iIi11i / OoOoOO00
 if 68 - 68: ooOoO0o / OoooooooOO * I11i / oO0o
 if 88 - 88: o0oOOo0O0Ooo
 if 1 - 1: OoooooooOO
 if 48 - 48: ooOoO0o * OoOoOO00 - ooOoO0o - OOooOOo + OOooOOo
 if 40 - 40: i11iIiiIii . iIii1I11I1II1
 if 2 - 2: i1IIi * oO0o - oO0o + OoooooooOO % OoOoOO00 / OoOoOO00
 if 3 - 3: OoooooooOO
 if 71 - 71: IiII + i1IIi - iII111i - i11iIiiIii . I11i - ooOoO0o
 if 85 - 85: I1ii11iIi11i - OoOoOO00 / I1ii11iIi11i + OOooOOo - iII111i
 if 49 - 49: OoO0O00 - O0 / OoO0O00 * OoOoOO00 + I1Ii111
 if 35 - 35: II111iiii . I1IiiI / i1IIi / I1IiiI * oO0o
 if 85 - 85: II111iiii . ooOoO0o % OOooOOo % I11i
 if 80 - 80: oO0o * I11i / iIii1I11I1II1 % oO0o / iIii1I11I1II1
 if 42 - 42: i1IIi / i11iIiiIii . Oo0Ooo * iII111i . i11iIiiIii * O0
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
 if 7 - 7: oO0o - O0 * I11i - o0oOOo0O0Ooo - II111iiii
def lisp_udp_checksum ( source , dest , data ) :
 if 41 - 41: I1IiiI - I1Ii111 % II111iiii . I1Ii111 - I11i
 if 45 - 45: Ii1I - OOooOOo
 if 70 - 70: OoO0O00 % I1IiiI / I1IiiI . I11i % ooOoO0o . II111iiii
 if 10 - 10: Ii1I - i11iIiiIii . I1ii11iIi11i % i1IIi
 IiII1iiI = lisp_address ( LISP_AFI_IPV6 , source , LISP_IPV6_HOST_MASK_LEN , 0 )
 OooOOOoOoo0O0 = lisp_address ( LISP_AFI_IPV6 , dest , LISP_IPV6_HOST_MASK_LEN , 0 )
 O0OOOOo0 = socket . htonl ( len ( data ) )
 OOooO0Oo00 = socket . htonl ( LISP_UDP_PROTOCOL )
 iIIIIIIIiIII = IiII1iiI . pack_address ( )
 iIIIIIIIiIII += OooOOOoOoo0O0 . pack_address ( )
 iIIIIIIIiIII += struct . pack ( "II" , O0OOOOo0 , OOooO0Oo00 )
 if 94 - 94: iII111i * iIii1I11I1II1 . I11i
 if 13 - 13: iIii1I11I1II1 * OoOoOO00 / I1Ii111 % ooOoO0o + oO0o
 if 41 - 41: I1ii11iIi11i
 if 5 - 5: Oo0Ooo
 o0oOo00 = binascii . hexlify ( iIIIIIIIiIII + data )
 IiI1III = len ( o0oOo00 ) % 4
 for IiIIi1IiiIiI in range ( 0 , IiI1III ) : o0oOo00 += "0"
 if 91 - 91: I11i + Ii1I - OoOoOO00 - OoO0O00 + IiII
 if 33 - 33: OoO0O00 - Oo0Ooo / ooOoO0o - I11i * oO0o
 if 87 - 87: Ii1I - I1ii11iIi11i % I1ii11iIi11i . oO0o / I1ii11iIi11i
 if 6 - 6: OoOoOO00 / iIii1I11I1II1 * OoooooooOO * i11iIiiIii
 Oo0 = 0
 for IiIIi1IiiIiI in range ( 0 , len ( o0oOo00 ) , 4 ) :
  Oo0 += int ( o0oOo00 [ IiIIi1IiiIiI : IiIIi1IiiIiI + 4 ] , 16 )
  if 79 - 79: IiII % OoO0O00
  if 81 - 81: i11iIiiIii + i11iIiiIii * OoO0O00 + IiII
  if 32 - 32: O0 . OoooooooOO
  if 15 - 15: I1IiiI . OoO0O00
  if 17 - 17: i11iIiiIii / Oo0Ooo . OoO0O00 / I1IiiI
 Oo0 = ( Oo0 >> 16 ) + ( Oo0 & 0xffff )
 Oo0 += Oo0 >> 16
 Oo0 = socket . htons ( ~ Oo0 & 0xffff )
 if 38 - 38: i1IIi . I1ii11iIi11i % Ii1I + iIii1I11I1II1 + O0
 if 47 - 47: OoO0O00 + IiII / II111iiii
 if 97 - 97: I1ii11iIi11i / I1IiiI % O0 + i1IIi - ooOoO0o
 if 38 - 38: o0oOOo0O0Ooo % I1Ii111 + i11iIiiIii + iII111i + ooOoO0o / i11iIiiIii
 Oo0 = struct . pack ( "H" , Oo0 )
 o0oOo00 = data [ 0 : 6 ] + Oo0 + data [ 8 : : ]
 return ( o0oOo00 )
 if 94 - 94: iII111i - Oo0Ooo + oO0o
 if 59 - 59: I11i . I1IiiI - iIii1I11I1II1 + iIii1I11I1II1
 if 56 - 56: oO0o + ooOoO0o
 if 32 - 32: II111iiii + OoOoOO00 % ooOoO0o / OoOoOO00 + I1ii11iIi11i
 if 2 - 2: i11iIiiIii - I1Ii111 + OoO0O00 % I11i * Ii1I
 if 54 - 54: O0 - iII111i . OOooOOo % iII111i + iII111i
 if 36 - 36: OOooOOo % i11iIiiIii
 if 47 - 47: i1IIi + II111iiii . Oo0Ooo * oO0o . I11i / i1IIi
def lisp_igmp_checksum ( igmp ) :
 i11ii = binascii . hexlify ( igmp )
 if 83 - 83: I1ii11iIi11i * I1ii11iIi11i + OOooOOo
 if 57 - 57: O0 - O0 . I1ii11iIi11i / o0oOOo0O0Ooo / Ii1I
 if 20 - 20: OOooOOo * II111iiii - OoOoOO00 - oO0o * I1Ii111
 if 6 - 6: ooOoO0o + OOooOOo / Oo0Ooo + IiII % II111iiii / OoO0O00
 Oo0 = 0
 for IiIIi1IiiIiI in range ( 0 , 24 , 4 ) :
  Oo0 += int ( i11ii [ IiIIi1IiiIiI : IiIIi1IiiIiI + 4 ] , 16 )
  if 45 - 45: OoooooooOO
  if 9 - 9: I11i . OoO0O00 * i1IIi . OoooooooOO
  if 32 - 32: OoOoOO00 . I1ii11iIi11i % I1IiiI - II111iiii
  if 11 - 11: O0 + I1IiiI
  if 80 - 80: oO0o % oO0o % O0 - i11iIiiIii . iII111i / O0
 Oo0 = ( Oo0 >> 16 ) + ( Oo0 & 0xffff )
 Oo0 += Oo0 >> 16
 Oo0 = socket . htons ( ~ Oo0 & 0xffff )
 if 13 - 13: I1IiiI + O0 - I1ii11iIi11i % Oo0Ooo / Ii1I . i1IIi
 if 60 - 60: Oo0Ooo . IiII % I1IiiI - I1Ii111
 if 79 - 79: OoooooooOO / I1ii11iIi11i . O0
 if 79 - 79: oO0o - II111iiii
 Oo0 = struct . pack ( "H" , Oo0 )
 igmp = igmp [ 0 : 2 ] + Oo0 + igmp [ 4 : : ]
 return ( igmp )
 if 43 - 43: i1IIi + O0 % OoO0O00 / Ii1I * I1IiiI
 if 89 - 89: I1IiiI . Oo0Ooo + I1ii11iIi11i . O0 % o0oOOo0O0Ooo
 if 84 - 84: OoooooooOO + I1Ii111 / I1IiiI % OOooOOo % I1ii11iIi11i * I1IiiI
 if 58 - 58: OoO0O00 - OoOoOO00 . i11iIiiIii % i11iIiiIii / i1IIi / oO0o
 if 24 - 24: I1IiiI * i1IIi % ooOoO0o / O0 + i11iIiiIii
 if 12 - 12: I1ii11iIi11i / Ii1I
 if 5 - 5: OoooooooOO
def lisp_get_interface_address ( device ) :
 if 18 - 18: I1IiiI % OoooooooOO - iII111i . i11iIiiIii * Oo0Ooo % Ii1I
 if 12 - 12: i1IIi / OOooOOo % ooOoO0o * IiII * O0 * iIii1I11I1II1
 if 93 - 93: Oo0Ooo / I1ii11iIi11i + i1IIi * oO0o . OoooooooOO
 if 54 - 54: O0 / IiII % ooOoO0o * i1IIi * O0
 if ( device not in netifaces . interfaces ( ) ) : return ( None )
 if 48 - 48: o0oOOo0O0Ooo . oO0o % OoOoOO00 - OoOoOO00
 if 33 - 33: I11i % II111iiii + OoO0O00
 if 93 - 93: i1IIi . IiII / I1IiiI + IiII
 if 58 - 58: I1ii11iIi11i + O0 . Oo0Ooo + OoOoOO00 - OoO0O00 - OoOoOO00
 IIiiI = netifaces . ifaddresses ( device )
 if ( IIiiI . has_key ( netifaces . AF_INET ) == False ) : return ( None )
 if 36 - 36: iII111i
 if 52 - 52: I1Ii111 % O0 . i1IIi . OoooooooOO
 if 33 - 33: OOooOOo % II111iiii
 if 71 - 71: Ii1I * I1Ii111 % II111iiii . Ii1I % OoO0O00 + I1ii11iIi11i
 o0oOo0OO = lisp_address ( LISP_AFI_IPV4 , "" , 32 , 0 )
 if 79 - 79: OoOoOO00 % I1IiiI % Ii1I / i1IIi % OoO0O00
 for IiiIIi1 in IIiiI [ netifaces . AF_INET ] :
  oo0o00OO = IiiIIi1 [ "addr" ]
  o0oOo0OO . store_address ( oo0o00OO )
  return ( o0oOo0OO )
  if 69 - 69: o0oOOo0O0Ooo % i11iIiiIii / Ii1I
 return ( None )
 if 93 - 93: ooOoO0o
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
 if 25 - 25: OoOoOO00 % OoooooooOO * Oo0Ooo - i1IIi * II111iiii * oO0o
def lisp_get_input_interface ( packet ) :
 I1iI1I1ii1 = lisp_format_packet ( packet [ 0 : 12 ] ) . replace ( " " , "" )
 iIIi1 = I1iI1I1ii1 [ 0 : 12 ]
 o0Ooo0o0Oo = I1iI1I1ii1 [ 12 : : ]
 if 55 - 55: iIii1I11I1II1 * iII111i
 try : oo = lisp_mymacs . has_key ( o0Ooo0o0Oo )
 except : oo = False
 if 30 - 30: O0 + OOooOOo % Oo0Ooo . i1IIi
 if ( lisp_mymacs . has_key ( iIIi1 ) ) : return ( lisp_mymacs [ iIIi1 ] , o0Ooo0o0Oo , iIIi1 , oo )
 if ( oo ) : return ( lisp_mymacs [ o0Ooo0o0Oo ] , o0Ooo0o0Oo , iIIi1 , oo )
 return ( [ "?" ] , o0Ooo0o0Oo , iIIi1 , oo )
 if 4 - 4: OOooOOo / iII111i * I11i - Oo0Ooo * I1IiiI
 if 6 - 6: Ii1I
 if 77 - 77: i1IIi + OoO0O00 . I1IiiI * OOooOOo / IiII / Ii1I
 if 84 - 84: OoO0O00 / iIii1I11I1II1
 if 33 - 33: i1IIi / I1Ii111 - i1IIi . Oo0Ooo
 if 18 - 18: Oo0Ooo / O0 + iII111i
 if 65 - 65: i1IIi . I1ii11iIi11i / ooOoO0o
 if 11 - 11: IiII * ooOoO0o / ooOoO0o - OOooOOo
def lisp_get_local_interfaces ( ) :
 for OoO0o0OOOO in netifaces . interfaces ( ) :
  II1i = lisp_interface ( OoO0o0OOOO )
  II1i . add_interface ( )
  if 62 - 62: I11i / oO0o % Oo0Ooo . OoooooooOO / i11iIiiIii / I1Ii111
 return
 if 60 - 60: I1IiiI % oO0o / o0oOOo0O0Ooo % oO0o * i11iIiiIii / iII111i
 if 34 - 34: I1Ii111 - OOooOOo
 if 25 - 25: oO0o % I1IiiI + i11iIiiIii + O0 * OoooooooOO
 if 64 - 64: i1IIi
 if 10 - 10: I1Ii111 % O0 / I1IiiI % I11i
 if 25 - 25: II111iiii / OoO0O00
 if 64 - 64: O0 % ooOoO0o
def lisp_get_loopback_address ( ) :
 for IiiIIi1 in netifaces . ifaddresses ( "lo" ) [ netifaces . AF_INET ] :
  if ( IiiIIi1 [ "peer" ] == "127.0.0.1" ) : continue
  return ( IiiIIi1 [ "peer" ] )
  if 40 - 40: o0oOOo0O0Ooo + I11i
 return ( None )
 if 77 - 77: i11iIiiIii % IiII + I1Ii111 % OoooooooOO - I11i
 if 26 - 26: Oo0Ooo + O0 - iIii1I11I1II1
 if 47 - 47: OoooooooOO
 if 2 - 2: OoOoOO00 % I1Ii111 * Oo0Ooo * OoOoOO00
 if 65 - 65: i11iIiiIii + Oo0Ooo * OoooooooOO - OoO0O00
 if 26 - 26: o0oOOo0O0Ooo % OOooOOo + OOooOOo % I11i * i11iIiiIii / iII111i
 if 64 - 64: oO0o % OoOoOO00 / II111iiii % ooOoO0o - iII111i
 if 2 - 2: I1Ii111 - I1ii11iIi11i + o0oOOo0O0Ooo * OoO0O00 / iII111i
def lisp_is_mac_string ( mac_str ) :
 Ii = mac_str . split ( "/" )
 if ( len ( Ii ) == 2 ) : mac_str = Ii [ 0 ]
 return ( len ( mac_str ) == 14 and mac_str . count ( "-" ) == 2 )
 if 26 - 26: OOooOOo * Oo0Ooo
 if 31 - 31: I11i * oO0o . Ii1I
 if 35 - 35: I11i
 if 94 - 94: ooOoO0o / i11iIiiIii % O0
 if 70 - 70: I11i - Oo0Ooo / OoooooooOO % OoooooooOO
 if 95 - 95: OoooooooOO % OoooooooOO . Ii1I
 if 26 - 26: oO0o + IiII - II111iiii . II111iiii + I1ii11iIi11i + OoOoOO00
 if 68 - 68: O0
def lisp_get_local_macs ( ) :
 for OoO0o0OOOO in netifaces . interfaces ( ) :
  if 76 - 76: I1ii11iIi11i
  if 99 - 99: o0oOOo0O0Ooo
  if 1 - 1: Ii1I * OoOoOO00 * OoO0O00 + Oo0Ooo
  if 90 - 90: I1Ii111 % Oo0Ooo - Oo0Ooo . iIii1I11I1II1 / OOooOOo + I11i
  if 89 - 89: oO0o
  OooOOOoOoo0O0 = OoO0o0OOOO . replace ( ":" , "" )
  OooOOOoOoo0O0 = OoO0o0OOOO . replace ( "-" , "" )
  if ( OooOOOoOoo0O0 . isalnum ( ) == False ) : continue
  if 87 - 87: iII111i % Oo0Ooo
  if 62 - 62: OoO0O00 + ooOoO0o / iII111i * i11iIiiIii
  if 37 - 37: iII111i
  if 33 - 33: OoO0O00 - O0 - OoO0O00
  if 94 - 94: IiII * I11i * OoooooooOO / o0oOOo0O0Ooo . IiII - o0oOOo0O0Ooo
  try :
   I1I1i = netifaces . ifaddresses ( OoO0o0OOOO )
  except :
   continue
   if 45 - 45: OOooOOo
  if ( I1I1i . has_key ( netifaces . AF_LINK ) == False ) : continue
  Ii = I1I1i [ netifaces . AF_LINK ] [ 0 ] [ "addr" ]
  Ii = Ii . replace ( ":" , "" )
  if 25 - 25: OOooOOo % O0
  if 44 - 44: I1Ii111 . Ii1I * II111iiii / IiII + iIii1I11I1II1
  if 14 - 14: O0 % IiII % Ii1I * oO0o
  if 65 - 65: I11i % oO0o + I1ii11iIi11i
  if 86 - 86: iIii1I11I1II1 / O0 . I1Ii111 % iIii1I11I1II1 % Oo0Ooo
  if ( len ( Ii ) < 12 ) : continue
  if 86 - 86: i11iIiiIii - o0oOOo0O0Ooo . ooOoO0o * Oo0Ooo / Ii1I % o0oOOo0O0Ooo
  if ( lisp_mymacs . has_key ( Ii ) == False ) : lisp_mymacs [ Ii ] = [ ]
  lisp_mymacs [ Ii ] . append ( OoO0o0OOOO )
  if 61 - 61: o0oOOo0O0Ooo + OoOoOO00
  if 15 - 15: OoOoOO00 * oO0o + OOooOOo . I11i % I1IiiI - ooOoO0o
 lprint ( "Local MACs are: {}" . format ( lisp_mymacs ) )
 return
 if 13 - 13: OoOoOO00 % OoOoOO00 % Oo0Ooo % I1IiiI * i1IIi % I11i
 if 82 - 82: IiII . OoOoOO00 / ooOoO0o + iII111i - ooOoO0o
 if 55 - 55: ooOoO0o % Oo0Ooo % o0oOOo0O0Ooo
 if 29 - 29: IiII / iIii1I11I1II1 + I1ii11iIi11i % iII111i % I11i
 if 46 - 46: iIii1I11I1II1
 if 70 - 70: i1IIi . I11i
 if 74 - 74: I11i
 if 58 - 58: iIii1I11I1II1 * OoO0O00 * I1Ii111 * ooOoO0o . OoooooooOO
def lisp_get_local_rloc ( ) :
 II1IIiiI1 = commands . getoutput ( "netstat -rn | egrep 'default|0.0.0.0'" )
 if ( II1IIiiI1 == "" ) : return ( lisp_address ( LISP_AFI_IPV4 , "" , 32 , 0 ) )
 if 96 - 96: OOooOOo + OOooOOo % IiII % OOooOOo
 if 28 - 28: iIii1I11I1II1 + OoOoOO00 . o0oOOo0O0Ooo % i11iIiiIii
 if 58 - 58: I11i / OoooooooOO % oO0o + OoO0O00
 if 58 - 58: O0
 II1IIiiI1 = II1IIiiI1 . split ( "\n" ) [ 0 ]
 OoO0o0OOOO = II1IIiiI1 . split ( ) [ - 1 ]
 if 91 - 91: iII111i / I1ii11iIi11i . iII111i - o0oOOo0O0Ooo + I1ii11iIi11i
 IiiIIi1 = ""
 O00 = lisp_is_macos ( )
 if ( O00 ) :
  II1IIiiI1 = commands . getoutput ( "ifconfig {} | egrep 'inet '" . format ( OoO0o0OOOO ) )
  if ( II1IIiiI1 == "" ) : return ( lisp_address ( LISP_AFI_IPV4 , "" , 32 , 0 ) )
 else :
  ooO0ooooO = 'ip addr show | egrep "inet " | egrep "{}"' . format ( OoO0o0OOOO )
  II1IIiiI1 = commands . getoutput ( ooO0ooooO )
  if ( II1IIiiI1 == "" ) :
   ooO0ooooO = 'ip addr show | egrep "inet " | egrep "global lo"'
   II1IIiiI1 = commands . getoutput ( ooO0ooooO )
   if 86 - 86: ooOoO0o
  if ( II1IIiiI1 == "" ) : return ( lisp_address ( LISP_AFI_IPV4 , "" , 32 , 0 ) )
  if 51 - 51: OoO0O00 - i11iIiiIii * I1IiiI
  if 95 - 95: OOooOOo % I1ii11iIi11i + o0oOOo0O0Ooo % ooOoO0o
  if 36 - 36: O0 / i1IIi % II111iiii / iII111i
  if 96 - 96: Oo0Ooo / oO0o . II111iiii . Oo0Ooo
  if 91 - 91: II111iiii . OOooOOo + o0oOOo0O0Ooo
  if 8 - 8: OOooOOo * Oo0Ooo / iII111i - OoO0O00 - OoooooooOO
 IiiIIi1 = ""
 II1IIiiI1 = II1IIiiI1 . split ( "\n" )
 if 100 - 100: oO0o . iIii1I11I1II1 . iIii1I11I1II1
 for oOOo0ooO0 in II1IIiiI1 :
  OO0o = oOOo0ooO0 . split ( ) [ 1 ]
  if ( O00 == False ) : OO0o = OO0o . split ( "/" ) [ 0 ]
  ii1i1II11II1i = lisp_address ( LISP_AFI_IPV4 , OO0o , 32 , 0 )
  return ( ii1i1II11II1i )
  if 95 - 95: I11i + o0oOOo0O0Ooo * I1ii11iIi11i
 return ( lisp_address ( LISP_AFI_IPV4 , IiiIIi1 , 32 , 0 ) )
 if 85 - 85: i11iIiiIii . OoooooooOO - iIii1I11I1II1
 if 38 - 38: I11i . I11i * oO0o / OoooooooOO % ooOoO0o
 if 80 - 80: OoO0O00 / IiII * I1IiiI % IiII
 if 95 - 95: O0 / I11i . I1Ii111
 if 17 - 17: I11i
 if 56 - 56: ooOoO0o * o0oOOo0O0Ooo + I11i
 if 48 - 48: IiII * OoO0O00 % I1Ii111 - I11i
 if 72 - 72: i1IIi % ooOoO0o % IiII % oO0o - oO0o
 if 97 - 97: o0oOOo0O0Ooo * O0 / o0oOOo0O0Ooo * OoO0O00 * Oo0Ooo
 if 38 - 38: I1Ii111
 if 25 - 25: iIii1I11I1II1 % II111iiii / I11i / I1ii11iIi11i
def lisp_get_local_addresses ( ) :
 global lisp_myrlocs
 if 22 - 22: oO0o * iII111i
 if 4 - 4: OoOoOO00 - oO0o + I1IiiI
 if 36 - 36: IiII
 if 19 - 19: OoOoOO00 . o0oOOo0O0Ooo . OoooooooOO
 if 13 - 13: OOooOOo . Oo0Ooo / II111iiii
 if 43 - 43: iIii1I11I1II1 % OoO0O00
 if 84 - 84: Oo0Ooo
 if 44 - 44: OoooooooOO * i11iIiiIii / Oo0Ooo
 if 75 - 75: OoooooooOO . OOooOOo + OoO0O00 / Ii1I - I1IiiI % Ii1I
 if 89 - 89: iII111i * iIii1I11I1II1 + i11iIiiIii . OoooooooOO
 O0O0 = None
 ooo = 1
 oO0oo = os . getenv ( "LISP_ADDR_SELECT" )
 if ( oO0oo != None and oO0oo != "" ) :
  oO0oo = oO0oo . split ( ":" )
  if ( len ( oO0oo ) == 2 ) :
   O0O0 = oO0oo [ 0 ]
   ooo = oO0oo [ 1 ]
  else :
   if ( oO0oo [ 0 ] . isdigit ( ) ) :
    ooo = oO0oo [ 0 ]
   else :
    O0O0 = oO0oo [ 0 ]
    if 52 - 52: IiII % ooOoO0o
    if 25 - 25: I11i / I11i % OoooooooOO - I1ii11iIi11i * oO0o
  ooo = 1 if ( ooo == "" ) else int ( ooo )
  if 23 - 23: i11iIiiIii
  if 100 - 100: oO0o + O0 . I1IiiI + i1IIi - OoOoOO00 + o0oOOo0O0Ooo
 ooOOo = [ None , None , None ]
 i1iii1IiiiI1i1 = lisp_address ( LISP_AFI_IPV4 , "" , 32 , 0 )
 IIIiI1i1 = lisp_address ( LISP_AFI_IPV6 , "" , 128 , 0 )
 IIi11iII11i1 = None
 if 5 - 5: II111iiii - IiII
 for OoO0o0OOOO in netifaces . interfaces ( ) :
  if ( O0O0 != None and O0O0 != OoO0o0OOOO ) : continue
  IIiiI = netifaces . ifaddresses ( OoO0o0OOOO )
  if ( IIiiI == { } ) : continue
  if 86 - 86: IiII * I11i + O0 * I1Ii111 + i11iIiiIii - I1ii11iIi11i
  if 70 - 70: i11iIiiIii
  if 57 - 57: I11i % OOooOOo + ooOoO0o * Ii1I . Oo0Ooo
  if 78 - 78: OoooooooOO / i1IIi . OOooOOo
  IIi11iII11i1 = lisp_get_interface_instance_id ( OoO0o0OOOO , None )
  if 88 - 88: I11i + I1IiiI - I11i / OoooooooOO - i11iIiiIii
  if 24 - 24: iIii1I11I1II1
  if 89 - 89: Ii1I / i1IIi - o0oOOo0O0Ooo % I1IiiI . Oo0Ooo - O0
  if 71 - 71: OoO0O00 % I1IiiI - iII111i . iII111i
  if ( IIiiI . has_key ( netifaces . AF_INET ) ) :
   IIi1 = IIiiI [ netifaces . AF_INET ]
   I1I1 = 0
   for IiiIIi1 in IIi1 :
    i1iii1IiiiI1i1 . store_address ( IiiIIi1 [ "addr" ] )
    if ( i1iii1IiiiI1i1 . is_ipv4_loopback ( ) ) : continue
    if ( i1iii1IiiiI1i1 . is_ipv4_link_local ( ) ) : continue
    if ( i1iii1IiiiI1i1 . address == 0 ) : continue
    I1I1 += 1
    i1iii1IiiiI1i1 . instance_id = IIi11iII11i1
    if ( O0O0 == None and
 lisp_db_for_lookups . lookup_cache ( i1iii1IiiiI1i1 , False ) ) : continue
    ooOOo [ 0 ] = i1iii1IiiiI1i1
    if ( I1I1 == ooo ) : break
    if 78 - 78: I11i . OOooOOo + oO0o * iII111i - i1IIi
    if 27 - 27: Ii1I % i1IIi . Oo0Ooo % I1Ii111
  if ( IIiiI . has_key ( netifaces . AF_INET6 ) ) :
   OoO0oO = IIiiI [ netifaces . AF_INET6 ]
   I1I1 = 0
   for IiiIIi1 in OoO0oO :
    oo0o00OO = IiiIIi1 [ "addr" ]
    IIIiI1i1 . store_address ( oo0o00OO )
    if ( IIIiI1i1 . is_ipv6_string_link_local ( oo0o00OO ) ) : continue
    if ( IIIiI1i1 . is_ipv6_loopback ( ) ) : continue
    I1I1 += 1
    IIIiI1i1 . instance_id = IIi11iII11i1
    if ( O0O0 == None and
 lisp_db_for_lookups . lookup_cache ( IIIiI1i1 , False ) ) : continue
    ooOOo [ 1 ] = IIIiI1i1
    if ( I1I1 == ooo ) : break
    if 10 - 10: IiII / OoooooooOO
    if 50 - 50: i11iIiiIii - OoooooooOO . oO0o + O0 . i1IIi
    if 91 - 91: o0oOOo0O0Ooo . iII111i % Oo0Ooo - iII111i . oO0o % i11iIiiIii
    if 25 - 25: iIii1I11I1II1
    if 63 - 63: ooOoO0o
    if 96 - 96: I11i
  if ( ooOOo [ 0 ] == None ) : continue
  if 34 - 34: OoOoOO00 / OoO0O00 - I1IiiI . O0 . OOooOOo
  ooOOo [ 2 ] = OoO0o0OOOO
  break
  if 63 - 63: iII111i
  if 11 - 11: iII111i - iIii1I11I1II1
 ooOo0O0 = ooOOo [ 0 ] . print_address_no_iid ( ) if ooOOo [ 0 ] else "none"
 ooo0 = ooOOo [ 1 ] . print_address_no_iid ( ) if ooOOo [ 1 ] else "none"
 OoO0o0OOOO = ooOOo [ 2 ] if ooOOo [ 2 ] else "none"
 if 36 - 36: I1Ii111 . IiII * OoooooooOO - o0oOOo0O0Ooo
 O0O0 = " (user selected)" if O0O0 != None else ""
 if 60 - 60: OOooOOo . iII111i / iIii1I11I1II1 + OOooOOo * I1Ii111
 ooOo0O0 = red ( ooOo0O0 , False )
 ooo0 = red ( ooo0 , False )
 OoO0o0OOOO = bold ( OoO0o0OOOO , False )
 lprint ( "Local addresses are IPv4: {}, IPv6: {} from device {}{}, iid {}" . format ( ooOo0O0 , ooo0 , OoO0o0OOOO , O0O0 , IIi11iII11i1 ) )
 if 82 - 82: i11iIiiIii . iIii1I11I1II1 * I1IiiI - I11i + Ii1I
 if 48 - 48: I1ii11iIi11i
 lisp_myrlocs = ooOOo
 return ( ( ooOOo [ 0 ] != None ) )
 if 96 - 96: ooOoO0o . OoooooooOO
 if 39 - 39: OOooOOo + OoO0O00
 if 80 - 80: OOooOOo % OoO0O00 / OoOoOO00
 if 54 - 54: Oo0Ooo % OoO0O00 - OOooOOo - I11i
 if 71 - 71: ooOoO0o . i11iIiiIii
 if 56 - 56: O0 * iII111i + iII111i * iIii1I11I1II1 / ooOoO0o * I1Ii111
 if 25 - 25: iIii1I11I1II1 . I11i * i11iIiiIii + Oo0Ooo * I11i
 if 67 - 67: iII111i
 if 88 - 88: Oo0Ooo
def lisp_get_all_addresses ( ) :
 i1ii111i = [ ]
 for II1i in netifaces . interfaces ( ) :
  try : i1ii1i1Ii11 = netifaces . ifaddresses ( II1i )
  except : continue
  if 88 - 88: I1Ii111 % I11i - OoooooooOO + ooOoO0o
  if ( i1ii1i1Ii11 . has_key ( netifaces . AF_INET ) ) :
   for IiiIIi1 in i1ii1i1Ii11 [ netifaces . AF_INET ] :
    OO0o = IiiIIi1 [ "addr" ]
    if ( OO0o . find ( "127.0.0.1" ) != - 1 ) : continue
    i1ii111i . append ( OO0o )
    if 53 - 53: i1IIi . i1IIi - I11i / iII111i - OoOoOO00 % I1IiiI
    if 65 - 65: iII111i . OoooooooOO - O0 . iII111i - i11iIiiIii
  if ( i1ii1i1Ii11 . has_key ( netifaces . AF_INET6 ) ) :
   for IiiIIi1 in i1ii1i1Ii11 [ netifaces . AF_INET6 ] :
    OO0o = IiiIIi1 [ "addr" ]
    if ( OO0o == "::1" ) : continue
    if ( OO0o [ 0 : 5 ] == "fe80:" ) : continue
    i1ii111i . append ( OO0o )
    if 29 - 29: I1ii11iIi11i . I1IiiI % oO0o - i11iIiiIii
    if 27 - 27: I1ii11iIi11i - i11iIiiIii % I1Ii111 / Oo0Ooo . Oo0Ooo / OoooooooOO
    if 76 - 76: I11i * OoO0O00 . iIii1I11I1II1 % OoooooooOO % I1ii11iIi11i
 return ( i1ii111i )
 if 39 - 39: II111iiii * OoOoOO00 . O0 * I11i
 if 89 - 89: Ii1I - ooOoO0o . I11i - I1Ii111 - I1IiiI
 if 79 - 79: IiII + IiII + Ii1I
 if 39 - 39: O0 - OoooooooOO
 if 63 - 63: iIii1I11I1II1 % o0oOOo0O0Ooo * ooOoO0o
 if 79 - 79: O0
 if 32 - 32: II111iiii . O0 + Ii1I / OoOoOO00 / IiII / OOooOOo
 if 15 - 15: I1ii11iIi11i
def lisp_get_all_multicast_rles ( ) :
 I11iI1 = [ ]
 II1IIiiI1 = commands . getoutput ( 'egrep "rle-address =" ./lisp.config' )
 if ( II1IIiiI1 == "" ) : return ( I11iI1 )
 if 96 - 96: o0oOOo0O0Ooo % IiII / OOooOOo
 Oo0o0ooOoO = II1IIiiI1 . split ( "\n" )
 for oOOo0ooO0 in Oo0o0ooOoO :
  if ( oOOo0ooO0 [ 0 ] == "#" ) : continue
  iI1Ii11 = oOOo0ooO0 . split ( "rle-address = " ) [ 1 ]
  Ooo0 = int ( iI1Ii11 . split ( "." ) [ 0 ] )
  if ( Ooo0 >= 224 and Ooo0 < 240 ) : I11iI1 . append ( iI1Ii11 )
  if 49 - 49: II111iiii + OoooooooOO . oO0o + i11iIiiIii / oO0o
 return ( I11iI1 )
 if 39 - 39: OoO0O00 + O0 + ooOoO0o * II111iiii % O0 - O0
 if 41 - 41: IiII % o0oOOo0O0Ooo
 if 67 - 67: O0 % I1Ii111
 if 35 - 35: I1IiiI . OoOoOO00 + OoooooooOO % Oo0Ooo % OOooOOo
 if 39 - 39: Ii1I
 if 60 - 60: OOooOOo
 if 62 - 62: I1Ii111 * I11i
 if 74 - 74: OoOoOO00 . iIii1I11I1II1
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
  if 87 - 87: ooOoO0o
  if 41 - 41: OoOoOO00 . iIii1I11I1II1 % ooOoO0o + O0
 def encode ( self , nonce ) :
  if 22 - 22: o0oOOo0O0Ooo + Oo0Ooo . ooOoO0o + I1ii11iIi11i * iII111i . i11iIiiIii
  if 90 - 90: OOooOOo * OoOoOO00 - Oo0Ooo + o0oOOo0O0Ooo
  if 53 - 53: OoooooooOO . OoooooooOO + o0oOOo0O0Ooo - iII111i + OOooOOo
  if 44 - 44: I1Ii111 - IiII
  if 100 - 100: oO0o . OoO0O00 - Ii1I + O0 * OoO0O00
  if ( self . outer_source . is_null ( ) ) : return ( None )
  if 59 - 59: II111iiii
  if 43 - 43: Oo0Ooo + OoooooooOO
  if 47 - 47: ooOoO0o
  if 92 - 92: I11i % i11iIiiIii % Oo0Ooo
  if 23 - 23: II111iiii * iII111i
  if 80 - 80: I1Ii111 / i11iIiiIii + OoooooooOO
  if ( nonce == None ) :
   self . lisp_header . nonce ( lisp_get_data_nonce ( ) )
  elif ( self . lisp_header . is_request_nonce ( nonce ) ) :
   self . lisp_header . request_nonce ( nonce )
  else :
   self . lisp_header . nonce ( nonce )
   if 38 - 38: I1ii11iIi11i % ooOoO0o + i1IIi * OoooooooOO * oO0o
  self . lisp_header . instance_id ( self . inner_dest . instance_id )
  if 83 - 83: iIii1I11I1II1 - ooOoO0o - I1Ii111 / OoO0O00 - O0
  if 81 - 81: Ii1I - oO0o * I1ii11iIi11i / I1Ii111
  if 21 - 21: OoO0O00
  if 63 - 63: I11i . O0 * I11i + iIii1I11I1II1
  if 46 - 46: i1IIi + II111iiii * i1IIi - Ii1I
  if 79 - 79: II111iiii - oO0o * I1ii11iIi11i - OoOoOO00 . I1ii11iIi11i
  self . lisp_header . key_id ( 0 )
  iiII1IIii1i1 = ( self . lisp_header . get_instance_id ( ) == 0xffffff )
  if ( lisp_data_plane_security and iiII1IIii1i1 == False ) :
   oo0o00OO = self . outer_dest . print_address_no_iid ( ) + ":" + str ( self . encap_port )
   if 38 - 38: iII111i * OoooooooOO
   if ( lisp_crypto_keys_by_rloc_encap . has_key ( oo0o00OO ) ) :
    iIi11III = lisp_crypto_keys_by_rloc_encap [ oo0o00OO ]
    if ( iIi11III [ 1 ] ) :
     iIi11III [ 1 ] . use_count += 1
     IiiiIi1iiii11 , iIIi1IIIii11i = self . encrypt ( iIi11III [ 1 ] , oo0o00OO )
     if ( iIIi1IIIii11i ) : self . packet = IiiiIi1iiii11
     if 40 - 40: I1IiiI % ooOoO0o % IiII + OoO0O00
     if 75 - 75: oO0o - I1ii11iIi11i + oO0o + OoooooooOO . i11iIiiIii
     if 52 - 52: iII111i / ooOoO0o - i11iIiiIii + OoooooooOO
     if 33 - 33: O0 + Oo0Ooo - iIii1I11I1II1 % i11iIiiIii / I1IiiI
     if 47 - 47: I1ii11iIi11i * oO0o + iIii1I11I1II1 - oO0o / IiII
     if 86 - 86: IiII
     if 43 - 43: I1IiiI / iII111i / ooOoO0o + iIii1I11I1II1 + OoooooooOO
     if 33 - 33: II111iiii - IiII - ooOoO0o
  self . udp_checksum = 0
  if ( self . encap_port == LISP_DATA_PORT ) :
   if ( lisp_crypto_ephem_port == None ) :
    if ( self . gleaned_dest ) :
     self . udp_sport = LISP_DATA_PORT
    else :
     self . hash_packet ( )
     if 92 - 92: OoO0O00 * IiII
   else :
    self . udp_sport = lisp_crypto_ephem_port
    if 92 - 92: oO0o
  else :
   self . udp_sport = LISP_DATA_PORT
   if 7 - 7: iII111i
  self . udp_dport = self . encap_port
  self . udp_length = len ( self . packet ) + 16
  if 73 - 73: OoO0O00 % I1ii11iIi11i
  if 32 - 32: OOooOOo + iII111i + iIii1I11I1II1 * Oo0Ooo
  if 62 - 62: i11iIiiIii
  if 2 - 2: I1IiiI
  if ( self . outer_version == 4 ) :
   oo0O = socket . htons ( self . udp_sport )
   O0o0o0ooO0ooo = socket . htons ( self . udp_dport )
  else :
   oo0O = self . udp_sport
   O0o0o0ooO0ooo = self . udp_dport
   if 47 - 47: IiII
   if 76 - 76: OoO0O00 * iIii1I11I1II1 + I1ii11iIi11i - ooOoO0o - I11i / i1IIi
  O0o0o0ooO0ooo = socket . htons ( self . udp_dport ) if self . outer_version == 4 else self . udp_dport
  if 27 - 27: I1ii11iIi11i . IiII
  if 66 - 66: O0 / O0 * i1IIi . OoooooooOO % iIii1I11I1II1
  o0oOo00 = struct . pack ( "HHHH" , oo0O , O0o0o0ooO0ooo , socket . htons ( self . udp_length ) ,
 self . udp_checksum )
  if 21 - 21: IiII - I1IiiI % OoooooooOO + o0oOOo0O0Ooo
  if 92 - 92: ooOoO0o + IiII
  if 52 - 52: II111iiii / I1IiiI . oO0o * IiII . I11i
  if 25 - 25: i11iIiiIii / OoOoOO00 - I1Ii111 / OoO0O00 . o0oOOo0O0Ooo . o0oOOo0O0Ooo
  iI1 = self . lisp_header . encode ( )
  if 43 - 43: I1ii11iIi11i + o0oOOo0O0Ooo
  if 50 - 50: oO0o % i1IIi * O0
  if 4 - 4: iIii1I11I1II1 . i1IIi
  if 63 - 63: iIii1I11I1II1 + IiII % i1IIi / I1IiiI % II111iiii
  if 60 - 60: o0oOOo0O0Ooo . OoOoOO00 % I1Ii111 / I1IiiI / O0
  if ( self . outer_version == 4 ) :
   IiI = socket . htons ( self . udp_length + 20 )
   ii11I = socket . htons ( 0x4000 )
   Ooo0O00 = struct . pack ( "BBHHHBBH" , 0x45 , self . outer_tos , IiI , 0xdfdf ,
 ii11I , self . outer_ttl , 17 , 0 )
   Ooo0O00 += self . outer_source . pack_address ( )
   Ooo0O00 += self . outer_dest . pack_address ( )
   Ooo0O00 = lisp_ip_checksum ( Ooo0O00 )
  elif ( self . outer_version == 6 ) :
   Ooo0O00 = ""
   if 53 - 53: O0 . I1IiiI
   if 74 - 74: ooOoO0o % OoOoOO00 / Oo0Ooo
   if 2 - 2: IiII % IiII % I1Ii111
   if 60 - 60: OOooOOo
   if 73 - 73: ooOoO0o
   if 86 - 86: OoOoOO00 . I11i / Oo0Ooo * I11i
   if 20 - 20: ooOoO0o - OOooOOo * OoO0O00 * o0oOOo0O0Ooo * OOooOOo / IiII
  else :
   return ( None )
   if 40 - 40: I1IiiI * o0oOOo0O0Ooo . I1IiiI
   if 62 - 62: ooOoO0o + II111iiii % ooOoO0o
  self . packet = Ooo0O00 + o0oOo00 + iI1 + self . packet
  return ( self )
  if 50 - 50: OoooooooOO + oO0o * I1IiiI - Ii1I / i11iIiiIii
  if 5 - 5: O0 - I1IiiI
 def cipher_pad ( self , packet ) :
  IiiI1iii1iIiiI = len ( packet )
  if ( ( IiiI1iii1iIiiI % 16 ) != 0 ) :
   II1iiiiI1 = ( ( IiiI1iii1iIiiI / 16 ) + 1 ) * 16
   packet = packet . ljust ( II1iiiiI1 )
   if 33 - 33: OoooooooOO % I1ii11iIi11i . O0 / I1ii11iIi11i
  return ( packet )
  if 63 - 63: IiII + iIii1I11I1II1 + I1IiiI + I1Ii111
  if 72 - 72: OoO0O00 + i11iIiiIii + I1ii11iIi11i
 def encrypt ( self , key , addr_str ) :
  if ( key == None or key . shared_key == None ) :
   return ( [ self . packet , False ] )
   if 96 - 96: oO0o % i1IIi / o0oOOo0O0Ooo
   if 13 - 13: II111iiii - Oo0Ooo % i11iIiiIii + iII111i
   if 88 - 88: O0 . oO0o % I1IiiI
   if 10 - 10: I1IiiI + O0
   if 75 - 75: O0 % iIii1I11I1II1 / OoOoOO00 % OOooOOo / IiII
  IiiiIi1iiii11 = self . cipher_pad ( self . packet )
  iiI1iiIiiiI1I = key . get_iv ( )
  if 6 - 6: OoO0O00
  i1 = lisp_get_timestamp ( )
  OO000OOOo0Oo = None
  if ( key . cipher_suite == LISP_CS_25519_CHACHA ) :
   Oo00O0O = chacha . ChaCha ( key . encrypt_key , iiI1iiIiiiI1I ) . encrypt
  elif ( key . cipher_suite == LISP_CS_25519_GCM ) :
   oOoOOoo = binascii . unhexlify ( key . encrypt_key )
   try :
    Oo00O0o0O = AES . new ( oOoOOoo , AES . MODE_GCM , iiI1iiIiiiI1I )
    Oo00O0O = Oo00O0o0O . encrypt
    OO000OOOo0Oo = Oo00O0o0O . digest
   except :
    lprint ( "You need AES-GCM, do a 'pip install pycryptodome'" )
    return ( [ self . packet , False ] )
    if 86 - 86: I11i + O0 + Oo0Ooo - I11i
  else :
   oOoOOoo = binascii . unhexlify ( key . encrypt_key )
   Oo00O0O = AES . new ( oOoOOoo , AES . MODE_CBC , iiI1iiIiiiI1I ) . encrypt
   if 34 - 34: II111iiii % I1IiiI % I1Ii111 + Oo0Ooo - OoOoOO00
   if 66 - 66: Ii1I * iIii1I11I1II1 - ooOoO0o / I1IiiI
  o0 = Oo00O0O ( IiiiIi1iiii11 )
  if 16 - 16: iIii1I11I1II1
  if ( o0 == None ) : return ( [ self . packet , False ] )
  i1 = int ( str ( time . time ( ) - i1 ) . split ( "." ) [ 1 ] [ 0 : 6 ] )
  if 94 - 94: ooOoO0o % I11i % i1IIi
  if 90 - 90: Ii1I * OoO0O00
  if 7 - 7: iII111i . Ii1I . iII111i - I1Ii111
  if 33 - 33: ooOoO0o + OoooooooOO - OoO0O00 / i1IIi / OoooooooOO
  if 82 - 82: I1ii11iIi11i / OOooOOo - iII111i / Oo0Ooo * OoO0O00
  if 55 - 55: OoooooooOO
  if ( OO000OOOo0Oo != None ) : o0 += OO000OOOo0Oo ( )
  if 73 - 73: OoOoOO00 - I1ii11iIi11i % Oo0Ooo + I1ii11iIi11i - O0 . OoO0O00
  if 38 - 38: O0
  if 79 - 79: i1IIi . oO0o
  if 34 - 34: I1Ii111 * II111iiii
  if 71 - 71: IiII
  self . lisp_header . key_id ( key . key_id )
  iI1 = self . lisp_header . encode ( )
  if 97 - 97: I1ii11iIi11i
  OOo0oO0o = key . do_icv ( iI1 + iiI1iiIiiiI1I + o0 , iiI1iiIiiiI1I )
  if 3 - 3: I1IiiI / iIii1I11I1II1 % o0oOOo0O0Ooo
  O0oo0000o = 4 if ( key . do_poly ) else 8
  if 99 - 99: oO0o - I1ii11iIi11i . II111iiii * i11iIiiIii . OOooOOo - OoO0O00
  Iii11I111Ii11 = bold ( "Encrypt" , False )
  iI1oOoo = bold ( key . cipher_suite_string , False )
  addr_str = "RLOC: " + red ( addr_str , False )
  o00O0o00oo = "poly" if key . do_poly else "sha256"
  o00O0o00oo = bold ( o00O0o00oo , False )
  iIiiII = "ICV({}): 0x{}...{}" . format ( o00O0o00oo , OOo0oO0o [ 0 : O0oo0000o ] , OOo0oO0o [ - O0oo0000o : : ] )
  dprint ( "{} for key-id: {}, {}, {}, {}-time: {} usec" . format ( Iii11I111Ii11 , key . key_id , addr_str , iIiiII , iI1oOoo , i1 ) )
  if 13 - 13: II111iiii
  if 55 - 55: Oo0Ooo % i1IIi * I11i
  OOo0oO0o = int ( OOo0oO0o , 16 )
  if ( key . do_poly ) :
   OOOo0 = byte_swap_64 ( ( OOo0oO0o >> 64 ) & LISP_8_64_MASK )
   o0Oooo0o0oO0 = byte_swap_64 ( OOo0oO0o & LISP_8_64_MASK )
   OOo0oO0o = struct . pack ( "QQ" , OOOo0 , o0Oooo0o0oO0 )
  else :
   OOOo0 = byte_swap_64 ( ( OOo0oO0o >> 96 ) & LISP_8_64_MASK )
   o0Oooo0o0oO0 = byte_swap_64 ( ( OOo0oO0o >> 32 ) & LISP_8_64_MASK )
   IIIiIiiI1i = socket . htonl ( OOo0oO0o & 0xffffffff )
   OOo0oO0o = struct . pack ( "QQI" , OOOo0 , o0Oooo0o0oO0 , IIIiIiiI1i )
   if 28 - 28: IiII + i11iIiiIii + OoooooooOO / OoO0O00
   if 6 - 6: I1IiiI - i11iIiiIii
  return ( [ iiI1iiIiiiI1I + o0 + OOo0oO0o , True ] )
  if 61 - 61: I1Ii111 * I1ii11iIi11i % I1IiiI % OoO0O00 % I11i + I11i
  if 6 - 6: Oo0Ooo
 def decrypt ( self , packet , header_length , key , addr_str ) :
  if 73 - 73: I1Ii111 * I1ii11iIi11i + o0oOOo0O0Ooo - Oo0Ooo . I11i
  if 93 - 93: i11iIiiIii
  if 80 - 80: i1IIi . I1IiiI - oO0o + OOooOOo + iII111i % oO0o
  if 13 - 13: II111iiii / OoOoOO00 / OoOoOO00 + ooOoO0o
  if 49 - 49: O0 / II111iiii * I1IiiI - OoooooooOO . II111iiii % IiII
  if 13 - 13: oO0o . iIii1I11I1II1 . OOooOOo . IiII
  if ( key . do_poly ) :
   OOOo0 , o0Oooo0o0oO0 = struct . unpack ( "QQ" , packet [ - 16 : : ] )
   oo0oo00O0O = byte_swap_64 ( OOOo0 ) << 64
   oo0oo00O0O |= byte_swap_64 ( o0Oooo0o0oO0 )
   oo0oo00O0O = lisp_hex_string ( oo0oo00O0O ) . zfill ( 32 )
   packet = packet [ 0 : - 16 ]
   O0oo0000o = 4
   iIiiI1I = bold ( "poly" , False )
  else :
   OOOo0 , o0Oooo0o0oO0 , IIIiIiiI1i = struct . unpack ( "QQI" , packet [ - 20 : : ] )
   oo0oo00O0O = byte_swap_64 ( OOOo0 ) << 96
   oo0oo00O0O |= byte_swap_64 ( o0Oooo0o0oO0 ) << 32
   oo0oo00O0O |= socket . htonl ( IIIiIiiI1i )
   oo0oo00O0O = lisp_hex_string ( oo0oo00O0O ) . zfill ( 40 )
   packet = packet [ 0 : - 20 ]
   O0oo0000o = 8
   iIiiI1I = bold ( "sha" , False )
   if 65 - 65: I1IiiI . I1IiiI % OOooOOo + ooOoO0o + OoooooooOO - i11iIiiIii
  iI1 = self . lisp_header . encode ( )
  if 94 - 94: oO0o . o0oOOo0O0Ooo % o0oOOo0O0Ooo % I1IiiI - iII111i / i11iIiiIii
  if 73 - 73: O0 * I1Ii111 . i1IIi
  if 51 - 51: OoO0O00 - iII111i % O0 - OoOoOO00
  if 53 - 53: iII111i / i1IIi / i1IIi
  if ( key . cipher_suite == LISP_CS_25519_CHACHA ) :
   o0oo00O = 8
   iI1oOoo = bold ( "chacha" , False )
  elif ( key . cipher_suite == LISP_CS_25519_GCM ) :
   o0oo00O = 12
   iI1oOoo = bold ( "aes-gcm" , False )
  else :
   o0oo00O = 16
   iI1oOoo = bold ( "aes-cbc" , False )
   if 36 - 36: OOooOOo * OoO0O00 - I1ii11iIi11i + iII111i
  iiI1iiIiiiI1I = packet [ 0 : o0oo00O ]
  if 13 - 13: OoO0O00 % iIii1I11I1II1 - II111iiii / I1IiiI
  if 9 - 9: I1ii11iIi11i * Ii1I - IiII
  if 88 - 88: iIii1I11I1II1
  if 27 - 27: I11i * i11iIiiIii . OOooOOo + ooOoO0o
  I1III1i11II1i = key . do_icv ( iI1 + packet , iiI1iiIiiiI1I )
  if 74 - 74: OoO0O00 + iII111i + II111iiii
  i111 = "0x{}...{}" . format ( oo0oo00O0O [ 0 : O0oo0000o ] , oo0oo00O0O [ - O0oo0000o : : ] )
  IIIIIII1i = "0x{}...{}" . format ( I1III1i11II1i [ 0 : O0oo0000o ] , I1III1i11II1i [ - O0oo0000o : : ] )
  if 30 - 30: IiII - iII111i - OoO0O00
  if ( I1III1i11II1i != oo0oo00O0O ) :
   self . packet_error = "ICV-error"
   ii11 = iI1oOoo + "/" + iIiiI1I
   oOOooooO = bold ( "ICV failed ({})" . format ( ii11 ) , False )
   iIiiII = "packet-ICV {} != computed-ICV {}" . format ( i111 , IIIIIII1i )
   dprint ( ( "{} from RLOC {}, receive-port: {}, key-id: {}, " + "packet dropped, {}" ) . format ( oOOooooO , red ( addr_str , False ) ,
   # I1Ii111 / Ii1I * OOooOOo * i1IIi . Ii1I * i11iIiiIii
 self . udp_sport , key . key_id , iIiiII ) )
   dprint ( "{}" . format ( key . print_keys ( ) ) )
   if 91 - 91: Ii1I - iII111i . i1IIi . I1ii11iIi11i * o0oOOo0O0Ooo % iII111i
   if 30 - 30: I11i
   if 85 - 85: II111iiii + ooOoO0o * I11i
   if 12 - 12: Ii1I . I1IiiI % o0oOOo0O0Ooo
   if 28 - 28: Ii1I - I1IiiI % OoO0O00 * I1Ii111
   if 80 - 80: OOooOOo * IiII
   lisp_retry_decap_keys ( addr_str , iI1 + packet , iiI1iiIiiiI1I , oo0oo00O0O )
   return ( [ None , False ] )
   if 4 - 4: iIii1I11I1II1 . I1Ii111 + II111iiii % OoooooooOO
   if 82 - 82: OoooooooOO / ooOoO0o * I11i * O0 . I1ii11iIi11i
   if 21 - 21: II111iiii + Oo0Ooo
   if 59 - 59: OOooOOo + I1IiiI / II111iiii / OoOoOO00
   if 80 - 80: OoOoOO00 + iIii1I11I1II1 . IiII
  packet = packet [ o0oo00O : : ]
  if 76 - 76: I1IiiI * OOooOOo
  if 12 - 12: iIii1I11I1II1 / I11i % Ii1I
  if 49 - 49: OoO0O00 + II111iiii / IiII - O0 % Ii1I
  if 27 - 27: OoO0O00 + Oo0Ooo
  i1 = lisp_get_timestamp ( )
  if ( key . cipher_suite == LISP_CS_25519_CHACHA ) :
   oO0oOOooO0 = chacha . ChaCha ( key . encrypt_key , iiI1iiIiiiI1I ) . decrypt
  elif ( key . cipher_suite == LISP_CS_25519_GCM ) :
   oOoOOoo = binascii . unhexlify ( key . encrypt_key )
   try :
    oO0oOOooO0 = AES . new ( oOoOOoo , AES . MODE_GCM , iiI1iiIiiiI1I ) . decrypt
   except :
    self . packet_error = "no-decrypt-key"
    lprint ( "You need AES-GCM, do a 'pip install pycryptodome'" )
    return ( [ None , False ] )
    if 62 - 62: i11iIiiIii - I11i
  else :
   if ( ( len ( packet ) % 16 ) != 0 ) :
    dprint ( "Ciphertext not multiple of 16 bytes, packet dropped" )
    return ( [ None , False ] )
    if 81 - 81: I11i
   oOoOOoo = binascii . unhexlify ( key . encrypt_key )
   oO0oOOooO0 = AES . new ( oOoOOoo , AES . MODE_CBC , iiI1iiIiiiI1I ) . decrypt
   if 92 - 92: OOooOOo - Oo0Ooo - OoooooooOO / IiII - i1IIi
   if 81 - 81: i1IIi / I1Ii111 % i11iIiiIii . iIii1I11I1II1 * OoOoOO00 + OoooooooOO
  iiii1Ii1iii = oO0oOOooO0 ( packet )
  i1 = int ( str ( time . time ( ) - i1 ) . split ( "." ) [ 1 ] [ 0 : 6 ] )
  if 73 - 73: i11iIiiIii + oO0o % I11i . OoooooooOO % oO0o
  if 32 - 32: i11iIiiIii - II111iiii
  if 21 - 21: OoOoOO00 - II111iiii
  if 10 - 10: OoOoOO00 - o0oOOo0O0Ooo * i11iIiiIii / Oo0Ooo + o0oOOo0O0Ooo + iIii1I11I1II1
  Iii11I111Ii11 = bold ( "Decrypt" , False )
  addr_str = "RLOC: " + red ( addr_str , False )
  o00O0o00oo = "poly" if key . do_poly else "sha256"
  o00O0o00oo = bold ( o00O0o00oo , False )
  iIiiII = "ICV({}): {}" . format ( o00O0o00oo , i111 )
  dprint ( "{} for key-id: {}, {}, {} (good), {}-time: {} usec" . format ( Iii11I111Ii11 , key . key_id , addr_str , iIiiII , iI1oOoo , i1 ) )
  if 23 - 23: i1IIi + I1ii11iIi11i + I1IiiI - ooOoO0o % OoooooooOO . IiII
  if 49 - 49: oO0o . OoOoOO00
  if 73 - 73: Ii1I / I1IiiI / OoooooooOO + I1IiiI
  if 57 - 57: OOooOOo . Ii1I % o0oOOo0O0Ooo
  if 32 - 32: I11i / IiII - O0 * iIii1I11I1II1
  if 70 - 70: OoooooooOO % OoooooooOO % OoO0O00
  if 98 - 98: OoO0O00
  self . packet = self . packet [ 0 : header_length ]
  return ( [ iiii1Ii1iii , True ] )
  if 18 - 18: I11i + Oo0Ooo - OoO0O00 / I1Ii111 / OOooOOo
  if 53 - 53: OOooOOo + o0oOOo0O0Ooo . oO0o / I11i
 def fragment_outer ( self , outer_hdr , inner_packet ) :
  o0000oO = 1000
  if 83 - 83: OoO0O00
  if 16 - 16: ooOoO0o
  if 32 - 32: o0oOOo0O0Ooo % I1IiiI
  if 7 - 7: Oo0Ooo . i1IIi - oO0o
  if 93 - 93: IiII % I1ii11iIi11i
  IiIIii = [ ]
  OoO00oo00 = 0
  IiiI1iii1iIiiI = len ( inner_packet )
  while ( OoO00oo00 < IiiI1iii1iIiiI ) :
   ii11I = inner_packet [ OoO00oo00 : : ]
   if ( len ( ii11I ) > o0000oO ) : ii11I = ii11I [ 0 : o0000oO ]
   IiIIii . append ( ii11I )
   OoO00oo00 += len ( ii11I )
   if 74 - 74: iIii1I11I1II1 / Ii1I
   if 59 - 59: Ii1I / II111iiii - IiII % OoOoOO00 % OoooooooOO
   if 79 - 79: iII111i . OoooooooOO . I1IiiI * O0 * OoO0O00 - OOooOOo
   if 33 - 33: I1ii11iIi11i . Oo0Ooo + I1IiiI + o0oOOo0O0Ooo
   if 54 - 54: ooOoO0o * iII111i * iII111i % OoOoOO00 - OOooOOo % I1ii11iIi11i
   if 44 - 44: Oo0Ooo . OOooOOo + I11i
  I1Ii1iIIiiiIi = [ ]
  OoO00oo00 = 0
  for ii11I in IiIIii :
   if 93 - 93: II111iiii . i11iIiiIii + II111iiii % oO0o
   if 98 - 98: I1Ii111 * oO0o * OoOoOO00 + Ii1I * iII111i
   if 4 - 4: IiII
   if 16 - 16: iIii1I11I1II1 * iII111i + oO0o . O0 . o0oOOo0O0Ooo
   oo00o00O0 = OoO00oo00 if ( ii11I == IiIIii [ - 1 ] ) else 0x2000 + OoO00oo00
   oo00o00O0 = socket . htons ( oo00o00O0 )
   outer_hdr = outer_hdr [ 0 : 6 ] + struct . pack ( "H" , oo00o00O0 ) + outer_hdr [ 8 : : ]
   if 52 - 52: iII111i + O0 % o0oOOo0O0Ooo % O0 % II111iiii + OoooooooOO
   if 51 - 51: iII111i % i11iIiiIii
   if 28 - 28: I1ii11iIi11i + I1ii11iIi11i % OoOoOO00
   if 12 - 12: I11i
   I11iIi1i1I1i1 = socket . htons ( len ( ii11I ) + 20 )
   outer_hdr = outer_hdr [ 0 : 2 ] + struct . pack ( "H" , I11iIi1i1I1i1 ) + outer_hdr [ 4 : : ]
   outer_hdr = lisp_ip_checksum ( outer_hdr )
   I1Ii1iIIiiiIi . append ( outer_hdr + ii11I )
   OoO00oo00 += len ( ii11I ) / 8
   if 14 - 14: I11i
  return ( I1Ii1iIIiiiIi )
  if 18 - 18: I1IiiI
  if 23 - 23: OoooooooOO * II111iiii
 def send_icmp_too_big ( self , inner_packet ) :
  global lisp_last_icmp_too_big_sent
  global lisp_icmp_raw_socket
  if 70 - 70: I1ii11iIi11i + I1IiiI
  oO000o0Oo00 = time . time ( ) - lisp_last_icmp_too_big_sent
  if ( oO000o0Oo00 < LISP_ICMP_TOO_BIG_RATE_LIMIT ) :
   lprint ( "Rate limit sending ICMP Too-Big to {}" . format ( self . inner_source . print_address_no_iid ( ) ) )
   if 65 - 65: iII111i - iII111i . Oo0Ooo
   return ( False )
   if 54 - 54: I1IiiI % iII111i
   if 80 - 80: o0oOOo0O0Ooo % iII111i
   if 80 - 80: Ii1I
   if 26 - 26: iIii1I11I1II1 . OoooooooOO - iIii1I11I1II1
   if 59 - 59: I1ii11iIi11i + I11i . oO0o
   if 87 - 87: OoO0O00
   if 34 - 34: I1Ii111 . OoOoOO00 / i11iIiiIii / iII111i
   if 46 - 46: Oo0Ooo + II111iiii * I1IiiI + OOooOOo
   if 31 - 31: Ii1I * o0oOOo0O0Ooo * Ii1I + OoO0O00 * o0oOOo0O0Ooo . I1Ii111
   if 89 - 89: OoooooooOO * Ii1I * I1IiiI . ooOoO0o * Ii1I / iII111i
   if 46 - 46: i11iIiiIii
   if 15 - 15: O0 / i1IIi / i1IIi . iII111i % OoOoOO00 + I1IiiI
   if 48 - 48: I1Ii111 % iII111i % Ii1I % iIii1I11I1II1 . Ii1I
   if 14 - 14: iII111i * OoO0O00 % O0 + I11i + I1ii11iIi11i
   if 23 - 23: Oo0Ooo % iII111i + Ii1I - I1Ii111
  ooOO = socket . htons ( 1400 )
  O00ooooo00 = struct . pack ( "BBHHH" , 3 , 4 , 0 , 0 , ooOO )
  O00ooooo00 += inner_packet [ 0 : 20 + 8 ]
  O00ooooo00 = lisp_icmp_checksum ( O00ooooo00 )
  if 66 - 66: Oo0Ooo / i11iIiiIii % ooOoO0o
  if 43 - 43: OOooOOo
  if 84 - 84: OOooOOo . IiII . iII111i
  if 2 - 2: Oo0Ooo - OoOoOO00
  if 49 - 49: Ii1I + II111iiii / oO0o - OoOoOO00 % OoOoOO00 + I1IiiI
  if 54 - 54: ooOoO0o % Oo0Ooo - OOooOOo
  if 16 - 16: I1ii11iIi11i * iII111i / I11i
  iiII1 = inner_packet [ 12 : 16 ]
  oo0OoO = self . inner_source . print_address_no_iid ( )
  iIIi1iii1 = self . outer_source . pack_address ( )
  if 64 - 64: ooOoO0o / i1IIi % iII111i
  if 84 - 84: OoOoOO00 - Oo0Ooo . ooOoO0o . IiII - Oo0Ooo
  if 99 - 99: I1Ii111
  if 75 - 75: ooOoO0o . OOooOOo / IiII
  if 84 - 84: OoooooooOO . I1IiiI / o0oOOo0O0Ooo
  if 86 - 86: Oo0Ooo % OoOoOO00
  if 77 - 77: Ii1I % OOooOOo / oO0o
  if 91 - 91: OoO0O00 / OoO0O00 . II111iiii . ooOoO0o - I1IiiI
  IiI = socket . htons ( 20 + 36 )
  Ooo0oO = struct . pack ( "BBHHHBBH" , 0x45 , 0 , IiI , 0 , 0 , 32 , 1 , 0 ) + iIIi1iii1 + iiII1
  Ooo0oO = lisp_ip_checksum ( Ooo0oO )
  Ooo0oO = self . fix_outer_header ( Ooo0oO )
  Ooo0oO += O00ooooo00
  iii11 = bold ( "Too-Big" , False )
  lprint ( "Send ICMP {} to {}, mtu 1400: {}" . format ( iii11 , oo0OoO ,
 lisp_format_packet ( Ooo0oO ) ) )
  if 59 - 59: Oo0Ooo / i11iIiiIii * I1IiiI + OoO0O00
  try :
   lisp_icmp_raw_socket . sendto ( Ooo0oO , ( oo0OoO , 0 ) )
  except socket . error , oOo :
   lprint ( "lisp_icmp_raw_socket.sendto() failed: {}" . format ( oOo ) )
   return ( False )
   if 47 - 47: OOooOOo / II111iiii % IiII . oO0o * I1ii11iIi11i
   if 35 - 35: Oo0Ooo * II111iiii
   if 32 - 32: oO0o . Oo0Ooo / ooOoO0o + ooOoO0o . I1ii11iIi11i
   if 50 - 50: iIii1I11I1II1 * oO0o
   if 85 - 85: i1IIi
   if 100 - 100: OoooooooOO / I11i % OoO0O00 + Ii1I
  lisp_last_icmp_too_big_sent = lisp_get_timestamp ( )
  return ( True )
  if 42 - 42: Oo0Ooo / IiII . Ii1I * I1IiiI
 def fragment ( self ) :
  global lisp_icmp_raw_socket
  global lisp_ignore_df_bit
  if 54 - 54: OoOoOO00 * iII111i + OoO0O00
  IiiiIi1iiii11 = self . fix_outer_header ( self . packet )
  if 93 - 93: o0oOOo0O0Ooo / I1IiiI
  if 47 - 47: Oo0Ooo * OOooOOo
  if 98 - 98: oO0o - oO0o . ooOoO0o
  if 60 - 60: I1IiiI * I1ii11iIi11i / O0 + I11i + IiII
  if 66 - 66: IiII * Oo0Ooo . OoooooooOO * I1Ii111
  if 93 - 93: IiII / i1IIi
  IiiI1iii1iIiiI = len ( IiiiIi1iiii11 )
  if ( IiiI1iii1iIiiI <= 1500 ) : return ( [ IiiiIi1iiii11 ] , "Fragment-None" )
  if 47 - 47: ooOoO0o - Ii1I
  IiiiIi1iiii11 = self . packet
  if 98 - 98: oO0o . I1Ii111 / OoOoOO00 . ooOoO0o
  if 1 - 1: OOooOOo
  if 87 - 87: O0 * II111iiii + iIii1I11I1II1 % oO0o % i11iIiiIii - OoOoOO00
  if 73 - 73: iII111i + Ii1I
  if 37 - 37: oO0o - iIii1I11I1II1 + II111iiii . Ii1I % iIii1I11I1II1
  if ( self . inner_version != 4 ) :
   i11iiI = random . randint ( 0 , 0xffff )
   IiiiI11 = IiiiIi1iiii11 [ 0 : 4 ] + struct . pack ( "H" , i11iiI ) + IiiiIi1iiii11 [ 6 : 20 ]
   OoooOOo0oOO = IiiiIi1iiii11 [ 20 : : ]
   I1Ii1iIIiiiIi = self . fragment_outer ( IiiiI11 , OoooOOo0oOO )
   return ( I1Ii1iIIiiiIi , "Fragment-Outer" )
   if 44 - 44: OOooOOo % iIii1I11I1II1
   if 30 - 30: i11iIiiIii - I1IiiI / I1ii11iIi11i
   if 26 - 26: ooOoO0o % oO0o + I1IiiI / IiII . I1IiiI
   if 38 - 38: OoooooooOO + OoooooooOO - i11iIiiIii * I1IiiI * i1IIi / II111iiii
   if 78 - 78: Oo0Ooo - I1Ii111 + iII111i * Ii1I * o0oOOo0O0Ooo
  iIiiiII11 = 56 if ( self . outer_version == 6 ) else 36
  IiiiI11 = IiiiIi1iiii11 [ 0 : iIiiiII11 ]
  ooo00Oo0 = IiiiIi1iiii11 [ iIiiiII11 : iIiiiII11 + 20 ]
  OoooOOo0oOO = IiiiIi1iiii11 [ iIiiiII11 + 20 : : ]
  if 46 - 46: oO0o
  if 56 - 56: OoooooooOO
  if 84 - 84: I1Ii111
  if 53 - 53: i1IIi
  if 59 - 59: o0oOOo0O0Ooo + I1IiiI % OoooooooOO - iIii1I11I1II1
  iiIII1i1 = struct . unpack ( "H" , ooo00Oo0 [ 6 : 8 ] ) [ 0 ]
  iiIII1i1 = socket . ntohs ( iiIII1i1 )
  if ( iiIII1i1 & 0x4000 ) :
   if ( lisp_icmp_raw_socket != None ) :
    oOOo0OOoOO0 = IiiiIi1iiii11 [ iIiiiII11 : : ]
    if ( self . send_icmp_too_big ( oOOo0OOoOO0 ) ) : return ( [ ] , None )
    if 30 - 30: II111iiii / I1IiiI - ooOoO0o + OoOoOO00 * ooOoO0o / OoOoOO00
   if ( lisp_ignore_df_bit ) :
    iiIII1i1 &= ~ 0x4000
   else :
    ii1IIIi = bold ( "DF-bit set" , False )
    dprint ( "{} in inner header, packet discarded" . format ( ii1IIIi ) )
    return ( [ ] , "Fragment-None-DF-bit" )
    if 78 - 78: o0oOOo0O0Ooo / o0oOOo0O0Ooo / I1IiiI . I1ii11iIi11i - OoooooooOO
    if 16 - 16: IiII % OoooooooOO - ooOoO0o * Ii1I - Ii1I
    if 27 - 27: IiII + iIii1I11I1II1 / Oo0Ooo + OoO0O00 % Oo0Ooo + OoO0O00
  OoO00oo00 = 0
  IiiI1iii1iIiiI = len ( OoooOOo0oOO )
  I1Ii1iIIiiiIi = [ ]
  while ( OoO00oo00 < IiiI1iii1iIiiI ) :
   I1Ii1iIIiiiIi . append ( OoooOOo0oOO [ OoO00oo00 : OoO00oo00 + 1400 ] )
   OoO00oo00 += 1400
   if 77 - 77: Oo0Ooo * ooOoO0o % Ii1I
   if 2 - 2: I11i / Oo0Ooo / Ii1I / I1ii11iIi11i / OoooooooOO
   if 22 - 22: iIii1I11I1II1 * I1IiiI / I11i + OoOoOO00
   if 98 - 98: OOooOOo
   if 69 - 69: II111iiii + Oo0Ooo - oO0o . Oo0Ooo / iIii1I11I1II1 * iIii1I11I1II1
  IiIIii = I1Ii1iIIiiiIi
  I1Ii1iIIiiiIi = [ ]
  oOooooooO0o = True if iiIII1i1 & 0x2000 else False
  iiIII1i1 = ( iiIII1i1 & 0x1fff ) * 8
  for ii11I in IiIIii :
   if 54 - 54: Ii1I . O0
   if 79 - 79: IiII / OoO0O00 * OoooooooOO * OoOoOO00 + I1IiiI
   if 68 - 68: I11i / iIii1I11I1II1 . Oo0Ooo + i11iIiiIii + o0oOOo0O0Ooo
   if 92 - 92: OoO0O00 . o0oOOo0O0Ooo . Ii1I % OoOoOO00
   OO00O00o0O = iiIII1i1 / 8
   if ( oOooooooO0o ) :
    OO00O00o0O |= 0x2000
   elif ( ii11I != IiIIii [ - 1 ] ) :
    OO00O00o0O |= 0x2000
    if 100 - 100: OoO0O00 % OoOoOO00 / I11i * O0 - oO0o
   OO00O00o0O = socket . htons ( OO00O00o0O )
   ooo00Oo0 = ooo00Oo0 [ 0 : 6 ] + struct . pack ( "H" , OO00O00o0O ) + ooo00Oo0 [ 8 : : ]
   if 34 - 34: iII111i % i11iIiiIii + i11iIiiIii - iII111i
   if 2 - 2: II111iiii + i1IIi
   if 68 - 68: OOooOOo + Ii1I
   if 58 - 58: IiII * Ii1I . i1IIi
   if 19 - 19: oO0o
   if 85 - 85: ooOoO0o - I1IiiI / i1IIi / OoO0O00 / II111iiii
   IiiI1iii1iIiiI = len ( ii11I )
   iiIII1i1 += IiiI1iii1iIiiI
   I11iIi1i1I1i1 = socket . htons ( IiiI1iii1iIiiI + 20 )
   ooo00Oo0 = ooo00Oo0 [ 0 : 2 ] + struct . pack ( "H" , I11iIi1i1I1i1 ) + ooo00Oo0 [ 4 : 10 ] + struct . pack ( "H" , 0 ) + ooo00Oo0 [ 12 : : ]
   if 94 - 94: iIii1I11I1II1 + IiII
   ooo00Oo0 = lisp_ip_checksum ( ooo00Oo0 )
   II11II = ooo00Oo0 + ii11I
   if 40 - 40: iII111i + O0
   if 18 - 18: iIii1I11I1II1 % iIii1I11I1II1 % oO0o + I1IiiI % ooOoO0o / Ii1I
   if 36 - 36: OoOoOO00 . i11iIiiIii
   if 81 - 81: Oo0Ooo * iII111i * OoO0O00
   if 85 - 85: O0 * oO0o
   IiiI1iii1iIiiI = len ( II11II )
   if ( self . outer_version == 4 ) :
    I11iIi1i1I1i1 = IiiI1iii1iIiiI + iIiiiII11
    IiiI1iii1iIiiI += 16
    IiiiI11 = IiiiI11 [ 0 : 2 ] + struct . pack ( "H" , I11iIi1i1I1i1 ) + IiiiI11 [ 4 : : ]
    if 39 - 39: II111iiii * I1IiiI - iIii1I11I1II1
    IiiiI11 = lisp_ip_checksum ( IiiiI11 )
    II11II = IiiiI11 + II11II
    II11II = self . fix_outer_header ( II11II )
    if 25 - 25: OoooooooOO . Ii1I % iII111i . IiII
    if 67 - 67: OoooooooOO + I1Ii111 / ooOoO0o
    if 75 - 75: IiII / OoooooooOO . I1IiiI + I1Ii111 - II111iiii
    if 33 - 33: IiII / IiII . i11iIiiIii * I1ii11iIi11i + o0oOOo0O0Ooo
    if 16 - 16: IiII
   II1 = iIiiiII11 - 12
   I11iIi1i1I1i1 = socket . htons ( IiiI1iii1iIiiI )
   II11II = II11II [ 0 : II1 ] + struct . pack ( "H" , I11iIi1i1I1i1 ) + II11II [ II1 + 2 : : ]
   if 86 - 86: oO0o . I1IiiI - I1Ii111 + iIii1I11I1II1
   I1Ii1iIIiiiIi . append ( II11II )
   if 66 - 66: I11i - I11i + IiII
  return ( I1Ii1iIIiiiIi , "Fragment-Inner" )
  if 20 - 20: I1Ii111 . i1IIi
  if 9 - 9: OoO0O00
 def fix_outer_header ( self , packet ) :
  if 89 - 89: i1IIi
  if 19 - 19: ooOoO0o / o0oOOo0O0Ooo % IiII - Ii1I
  if 14 - 14: I1ii11iIi11i - i11iIiiIii * I1Ii111
  if 39 - 39: OoooooooOO
  if 19 - 19: i11iIiiIii
  if 80 - 80: I1IiiI
  if 58 - 58: oO0o + I1ii11iIi11i % OoOoOO00
  if 22 - 22: iIii1I11I1II1 - Ii1I / I1IiiI * IiII
  if ( self . outer_version == 4 or self . inner_version == 4 ) :
   if ( lisp_is_macos ( ) ) :
    packet = packet [ 0 : 2 ] + packet [ 3 ] + packet [ 2 ] + packet [ 4 : 6 ] + packet [ 7 ] + packet [ 6 ] + packet [ 8 : : ]
    if 26 - 26: o0oOOo0O0Ooo + OOooOOo - o0oOOo0O0Ooo + Oo0Ooo . oO0o
   else :
    packet = packet [ 0 : 2 ] + packet [ 3 ] + packet [ 2 ] + packet [ 4 : : ]
    if 97 - 97: i1IIi
    if 46 - 46: I1ii11iIi11i
  return ( packet )
  if 30 - 30: OoO0O00 / O0 * o0oOOo0O0Ooo * I1Ii111 + OoooooooOO * iII111i
  if 23 - 23: I11i
 def send_packet ( self , lisp_raw_socket , dest ) :
  if ( lisp_flow_logging and dest != self . inner_dest ) : self . log_flow ( True )
  if 36 - 36: IiII . iII111i - i1IIi + I1Ii111
  dest = dest . print_address_no_iid ( )
  I1Ii1iIIiiiIi , ooO = self . fragment ( )
  if 62 - 62: OoooooooOO % oO0o * II111iiii * I1Ii111 * I1Ii111 / ooOoO0o
  for II11II in I1Ii1iIIiiiIi :
   if ( len ( I1Ii1iIIiiiIi ) != 1 ) :
    self . packet = II11II
    self . print_packet ( ooO , True )
    if 90 - 90: I1Ii111 . II111iiii . I1ii11iIi11i
    if 32 - 32: ooOoO0o - OoO0O00 . iII111i . iII111i % i1IIi * Ii1I
   try : lisp_raw_socket . sendto ( II11II , ( dest , 0 ) )
   except socket . error , oOo :
    lprint ( "socket.sendto() failed: {}" . format ( oOo ) )
    if 65 - 65: iII111i / ooOoO0o . II111iiii
    if 90 - 90: I11i
    if 95 - 95: OoO0O00
    if 68 - 68: iIii1I11I1II1 . iIii1I11I1II1 / OoOoOO00 - II111iiii - iIii1I11I1II1
 def send_l2_packet ( self , l2_socket , mac_header ) :
  if ( l2_socket == None ) :
   lprint ( "No layer-2 socket, drop IPv6 packet" )
   return
   if 75 - 75: ooOoO0o . I1IiiI * II111iiii
  if ( mac_header == None ) :
   lprint ( "Could not build MAC header, drop IPv6 packet" )
   return
   if 99 - 99: iIii1I11I1II1 * I1ii11iIi11i + IiII
   if 70 - 70: i1IIi % ooOoO0o . I1ii11iIi11i - IiII + OOooOOo
  IiiiIi1iiii11 = mac_header + self . packet
  if 84 - 84: oO0o + II111iiii * II111iiii % o0oOOo0O0Ooo / iII111i + ooOoO0o
  if 9 - 9: iII111i
  if 25 - 25: OOooOOo - Ii1I . I11i
  if 57 - 57: o0oOOo0O0Ooo + Oo0Ooo * I1ii11iIi11i - ooOoO0o % iIii1I11I1II1 - Ii1I
  if 37 - 37: OoO0O00 * I11i + Ii1I + I1ii11iIi11i * o0oOOo0O0Ooo
  if 95 - 95: Ii1I - i11iIiiIii % i11iIiiIii - O0 * I1Ii111
  if 81 - 81: II111iiii * I1IiiI % i1IIi * i11iIiiIii + OoOoOO00
  if 100 - 100: i1IIi % Ii1I
  if 55 - 55: I1IiiI + iII111i
  if 85 - 85: oO0o + iII111i % iII111i / I11i . I1IiiI - OoOoOO00
  if 19 - 19: I11i / iII111i + IiII
  l2_socket . write ( IiiiIi1iiii11 )
  return
  if 76 - 76: iIii1I11I1II1 / I1Ii111 - I1ii11iIi11i % o0oOOo0O0Ooo % OOooOOo + OoooooooOO
  if 10 - 10: OoO0O00 * I11i / Oo0Ooo - I1Ii111
 def bridge_l2_packet ( self , eid , db ) :
  try : I1iIi1IiI1i = db . dynamic_eids [ eid . print_address_no_iid ( ) ]
  except : return
  try : II1i = lisp_myinterfaces [ I1iIi1IiI1i . interface ]
  except : return
  try :
   socket = II1i . get_bridge_socket ( )
   if ( socket == None ) : return
  except : return
  if 50 - 50: i1IIi * oO0o / i11iIiiIii / i11iIiiIii / oO0o
  try : socket . send ( self . packet )
  except socket . error , oOo :
   lprint ( "bridge_l2_packet(): socket.send() failed: {}" . format ( oOo ) )
   if 84 - 84: I1ii11iIi11i - iII111i + I1ii11iIi11i
   if 63 - 63: I11i * ooOoO0o % II111iiii % I1Ii111 + I1IiiI * Oo0Ooo
   if 96 - 96: IiII
 def is_lisp_packet ( self , packet ) :
  o0oOo00 = ( struct . unpack ( "B" , packet [ 9 ] ) [ 0 ] == LISP_UDP_PROTOCOL )
  if ( o0oOo00 == False ) : return ( False )
  if 99 - 99: iIii1I11I1II1 - ooOoO0o
  Oo0O00O = struct . unpack ( "H" , packet [ 22 : 24 ] ) [ 0 ]
  if ( socket . ntohs ( Oo0O00O ) == LISP_DATA_PORT ) : return ( True )
  Oo0O00O = struct . unpack ( "H" , packet [ 20 : 22 ] ) [ 0 ]
  if ( socket . ntohs ( Oo0O00O ) == LISP_DATA_PORT ) : return ( True )
  return ( False )
  if 56 - 56: I1ii11iIi11i + oO0o . OoO0O00 + OoooooooOO * I1ii11iIi11i - O0
  if 35 - 35: OOooOOo . I11i . I1Ii111 - I11i % I11i + I1Ii111
 def decode ( self , is_lisp_packet , lisp_ipc_socket , stats ) :
  self . packet_error = ""
  IiiiIi1iiii11 = self . packet
  oO0oO00 = len ( IiiiIi1iiii11 )
  IiiI1Ii1II = OO0oIii1I1I = True
  if 41 - 41: I1IiiI . Oo0Ooo . IiII % OoooooooOO + OoO0O00
  if 23 - 23: I1IiiI - o0oOOo0O0Ooo % oO0o . O0 * OoooooooOO + ooOoO0o
  if 53 - 53: Oo0Ooo
  if 3 - 3: IiII - OoooooooOO * OoooooooOO - I1IiiI / I1Ii111 * I1ii11iIi11i
  O0oo0ooO00 = 0
  o0OoO0000o = 0
  if ( is_lisp_packet ) :
   o0OoO0000o = self . lisp_header . get_instance_id ( )
   oOoO0 = struct . unpack ( "B" , IiiiIi1iiii11 [ 0 : 1 ] ) [ 0 ]
   self . outer_version = oOoO0 >> 4
   if ( self . outer_version == 4 ) :
    if 50 - 50: I1Ii111 * I1Ii111 * Oo0Ooo - OoO0O00
    if 12 - 12: Oo0Ooo + iII111i / OoO0O00 / Oo0Ooo
    if 92 - 92: I1Ii111 % iII111i % o0oOOo0O0Ooo . I1IiiI - I1ii11iIi11i - o0oOOo0O0Ooo
    if 40 - 40: I1IiiI / OoooooooOO + OoO0O00 * OoO0O00
    if 9 - 9: iIii1I11I1II1
    O0000 = struct . unpack ( "H" , IiiiIi1iiii11 [ 10 : 12 ] ) [ 0 ]
    IiiiIi1iiii11 = lisp_ip_checksum ( IiiiIi1iiii11 )
    Oo0 = struct . unpack ( "H" , IiiiIi1iiii11 [ 10 : 12 ] ) [ 0 ]
    if ( Oo0 != 0 ) :
     if ( O0000 != 0 or lisp_is_macos ( ) == False ) :
      self . packet_error = "checksum-error"
      if ( stats ) :
       stats [ self . packet_error ] . increment ( oO0oO00 )
       if 53 - 53: I1Ii111
       if 31 - 31: o0oOOo0O0Ooo * I11i - i11iIiiIii - I1IiiI
      lprint ( "IPv4 header checksum failed for outer header" )
      if ( lisp_flow_logging ) : self . log_flow ( False )
      return ( None )
      if 19 - 19: iII111i . I11i * OoooooooOO - OOooOOo + O0 * I1Ii111
      if 90 - 90: i1IIi . oO0o / I1Ii111 . OOooOOo / I1Ii111
      if 1 - 1: iII111i % ooOoO0o
    O0ooo0 = LISP_AFI_IPV4
    OoO00oo00 = 12
    self . outer_tos = struct . unpack ( "B" , IiiiIi1iiii11 [ 1 : 2 ] ) [ 0 ]
    self . outer_ttl = struct . unpack ( "B" , IiiiIi1iiii11 [ 8 : 9 ] ) [ 0 ]
    O0oo0ooO00 = 20
   elif ( self . outer_version == 6 ) :
    O0ooo0 = LISP_AFI_IPV6
    OoO00oo00 = 8
    o0Oo00o0 = struct . unpack ( "H" , IiiiIi1iiii11 [ 0 : 2 ] ) [ 0 ]
    self . outer_tos = ( socket . ntohs ( o0Oo00o0 ) >> 4 ) & 0xff
    self . outer_ttl = struct . unpack ( "B" , IiiiIi1iiii11 [ 7 : 8 ] ) [ 0 ]
    O0oo0ooO00 = 40
   else :
    self . packet_error = "outer-header-error"
    if ( stats ) : stats [ self . packet_error ] . increment ( oO0oO00 )
    lprint ( "Cannot decode outer header" )
    return ( None )
    if 42 - 42: I1Ii111 / OoOoOO00 % oO0o
    if 63 - 63: OoO0O00 % i1IIi - oO0o
   self . outer_source . afi = O0ooo0
   self . outer_dest . afi = O0ooo0
   Iii1i11 = self . outer_source . addr_length ( )
   if 40 - 40: I1ii11iIi11i / iIii1I11I1II1 . IiII % ooOoO0o
   self . outer_source . unpack_address ( IiiiIi1iiii11 [ OoO00oo00 : OoO00oo00 + Iii1i11 ] )
   OoO00oo00 += Iii1i11
   self . outer_dest . unpack_address ( IiiiIi1iiii11 [ OoO00oo00 : OoO00oo00 + Iii1i11 ] )
   IiiiIi1iiii11 = IiiiIi1iiii11 [ O0oo0ooO00 : : ]
   self . outer_source . mask_len = self . outer_source . host_mask_len ( )
   self . outer_dest . mask_len = self . outer_dest . host_mask_len ( )
   if 56 - 56: ooOoO0o . iIii1I11I1II1 + i1IIi
   if 84 - 84: iII111i % i1IIi
   if 62 - 62: I1ii11iIi11i . I1Ii111 . Ii1I
   if 19 - 19: I1ii11iIi11i / I1Ii111
   IIiIIiiiiiII1 = struct . unpack ( "H" , IiiiIi1iiii11 [ 0 : 2 ] ) [ 0 ]
   self . udp_sport = socket . ntohs ( IIiIIiiiiiII1 )
   IIiIIiiiiiII1 = struct . unpack ( "H" , IiiiIi1iiii11 [ 2 : 4 ] ) [ 0 ]
   self . udp_dport = socket . ntohs ( IIiIIiiiiiII1 )
   IIiIIiiiiiII1 = struct . unpack ( "H" , IiiiIi1iiii11 [ 4 : 6 ] ) [ 0 ]
   self . udp_length = socket . ntohs ( IIiIIiiiiiII1 )
   IIiIIiiiiiII1 = struct . unpack ( "H" , IiiiIi1iiii11 [ 6 : 8 ] ) [ 0 ]
   self . udp_checksum = socket . ntohs ( IIiIIiiiiiII1 )
   IiiiIi1iiii11 = IiiiIi1iiii11 [ 8 : : ]
   if 7 - 7: I1ii11iIi11i - iIii1I11I1II1
   if 97 - 97: OOooOOo
   if 41 - 41: OoooooooOO - Oo0Ooo * iIii1I11I1II1 . i1IIi
   if 39 - 39: Ii1I % i1IIi . I1ii11iIi11i - O0
   IiiI1Ii1II = ( self . udp_dport == LISP_DATA_PORT or
 self . udp_sport == LISP_DATA_PORT )
   OO0oIii1I1I = ( self . udp_dport in ( LISP_L2_DATA_PORT , LISP_VXLAN_DATA_PORT ) )
   if 65 - 65: oO0o * oO0o / I11i + oO0o % ooOoO0o + OoOoOO00
   if 92 - 92: o0oOOo0O0Ooo
   if 37 - 37: oO0o
   if 18 - 18: IiII * i11iIiiIii + iIii1I11I1II1 % I11i + i1IIi - OoO0O00
   if ( self . lisp_header . decode ( IiiiIi1iiii11 ) == False ) :
    self . packet_error = "lisp-header-error"
    if ( stats ) : stats [ self . packet_error ] . increment ( oO0oO00 )
    if 85 - 85: OoO0O00 * I11i + OoO0O00
    if ( lisp_flow_logging ) : self . log_flow ( False )
    lprint ( "Cannot decode LISP header" )
    return ( None )
    if 39 - 39: Oo0Ooo / i1IIi % i1IIi
   IiiiIi1iiii11 = IiiiIi1iiii11 [ 8 : : ]
   o0OoO0000o = self . lisp_header . get_instance_id ( )
   O0oo0ooO00 += 16
   if 20 - 20: OOooOOo * oO0o
  if ( o0OoO0000o == 0xffffff ) : o0OoO0000o = 0
  if 91 - 91: OoO0O00 % i1IIi - iIii1I11I1II1 . OOooOOo
  if 31 - 31: oO0o % i1IIi . OoooooooOO - o0oOOo0O0Ooo + OoooooooOO
  if 45 - 45: OOooOOo + I11i / OoooooooOO - Ii1I + OoooooooOO
  if 42 - 42: iIii1I11I1II1 * I1IiiI * I1Ii111
  O00oo0o0o0oo = False
  I1I1I1 = self . lisp_header . k_bits
  if ( I1I1I1 ) :
   oo0o00OO = lisp_get_crypto_decap_lookup_key ( self . outer_source ,
 self . udp_sport )
   if ( oo0o00OO == None ) :
    self . packet_error = "no-decrypt-key"
    if ( stats ) : stats [ self . packet_error ] . increment ( oO0oO00 )
    if 29 - 29: I1ii11iIi11i
    self . print_packet ( "Receive" , is_lisp_packet )
    oOOoOO = bold ( "No key available" , False )
    dprint ( "{} for key-id {} to decrypt packet" . format ( oOOoOO , I1I1I1 ) )
    if ( lisp_flow_logging ) : self . log_flow ( False )
    return ( None )
    if 99 - 99: ooOoO0o * iIii1I11I1II1 - Ii1I + Oo0Ooo . Oo0Ooo
    if 18 - 18: OOooOOo
   Oo000O000 = lisp_crypto_keys_by_rloc_decap [ oo0o00OO ] [ I1I1I1 ]
   if ( Oo000O000 == None ) :
    self . packet_error = "no-decrypt-key"
    if ( stats ) : stats [ self . packet_error ] . increment ( oO0oO00 )
    if 7 - 7: I1IiiI
    self . print_packet ( "Receive" , is_lisp_packet )
    oOOoOO = bold ( "No key available" , False )
    dprint ( "{} to decrypt packet from RLOC {}" . format ( oOOoOO ,
 red ( oo0o00OO , False ) ) )
    if ( lisp_flow_logging ) : self . log_flow ( False )
    return ( None )
    if 40 - 40: ooOoO0o
    if 80 - 80: I1IiiI * I1Ii111 % oO0o . i11iIiiIii % IiII
    if 42 - 42: OoooooooOO * II111iiii
    if 53 - 53: I1Ii111 + i1IIi . OoO0O00 / i11iIiiIii + Ii1I % OoOoOO00
    if 9 - 9: ooOoO0o . I11i - Oo0Ooo . I1Ii111
   Oo000O000 . use_count += 1
   IiiiIi1iiii11 , O00oo0o0o0oo = self . decrypt ( IiiiIi1iiii11 , O0oo0ooO00 , Oo000O000 ,
 oo0o00OO )
   if ( O00oo0o0o0oo == False ) :
    if ( stats ) : stats [ self . packet_error ] . increment ( oO0oO00 )
    if ( lisp_flow_logging ) : self . log_flow ( False )
    return ( None )
    if 39 - 39: OOooOOo
    if 70 - 70: IiII % OoO0O00 % I1IiiI
    if 95 - 95: OoOoOO00 - I1Ii111 / O0 * I1IiiI - o0oOOo0O0Ooo
    if 12 - 12: iIii1I11I1II1 % Oo0Ooo . iII111i . IiII % i11iIiiIii
    if 2 - 2: oO0o * oO0o . OoOoOO00 * Ii1I * iIii1I11I1II1
    if 13 - 13: I11i / O0 . i11iIiiIii * i1IIi % i11iIiiIii
  oOoO0 = struct . unpack ( "B" , IiiiIi1iiii11 [ 0 : 1 ] ) [ 0 ]
  self . inner_version = oOoO0 >> 4
  if ( IiiI1Ii1II and self . inner_version == 4 and oOoO0 >= 0x45 ) :
   iIi1Iii1 = socket . ntohs ( struct . unpack ( "H" , IiiiIi1iiii11 [ 2 : 4 ] ) [ 0 ] )
   self . inner_tos = struct . unpack ( "B" , IiiiIi1iiii11 [ 1 : 2 ] ) [ 0 ]
   self . inner_ttl = struct . unpack ( "B" , IiiiIi1iiii11 [ 8 : 9 ] ) [ 0 ]
   self . inner_protocol = struct . unpack ( "B" , IiiiIi1iiii11 [ 9 : 10 ] ) [ 0 ]
   self . inner_source . afi = LISP_AFI_IPV4
   self . inner_dest . afi = LISP_AFI_IPV4
   self . inner_source . unpack_address ( IiiiIi1iiii11 [ 12 : 16 ] )
   self . inner_dest . unpack_address ( IiiiIi1iiii11 [ 16 : 20 ] )
   iiIII1i1 = socket . ntohs ( struct . unpack ( "H" , IiiiIi1iiii11 [ 6 : 8 ] ) [ 0 ] )
   self . inner_is_fragment = ( iiIII1i1 & 0x2000 or iiIII1i1 != 0 )
   if ( self . inner_protocol == LISP_UDP_PROTOCOL ) :
    self . inner_sport = struct . unpack ( "H" , IiiiIi1iiii11 [ 20 : 22 ] ) [ 0 ]
    self . inner_sport = socket . ntohs ( self . inner_sport )
    self . inner_dport = struct . unpack ( "H" , IiiiIi1iiii11 [ 22 : 24 ] ) [ 0 ]
    self . inner_dport = socket . ntohs ( self . inner_dport )
    if 87 - 87: OoooooooOO
  elif ( IiiI1Ii1II and self . inner_version == 6 and oOoO0 >= 0x60 ) :
   iIi1Iii1 = socket . ntohs ( struct . unpack ( "H" , IiiiIi1iiii11 [ 4 : 6 ] ) [ 0 ] ) + 40
   o0Oo00o0 = struct . unpack ( "H" , IiiiIi1iiii11 [ 0 : 2 ] ) [ 0 ]
   self . inner_tos = ( socket . ntohs ( o0Oo00o0 ) >> 4 ) & 0xff
   self . inner_ttl = struct . unpack ( "B" , IiiiIi1iiii11 [ 7 : 8 ] ) [ 0 ]
   self . inner_protocol = struct . unpack ( "B" , IiiiIi1iiii11 [ 6 : 7 ] ) [ 0 ]
   self . inner_source . afi = LISP_AFI_IPV6
   self . inner_dest . afi = LISP_AFI_IPV6
   self . inner_source . unpack_address ( IiiiIi1iiii11 [ 8 : 24 ] )
   self . inner_dest . unpack_address ( IiiiIi1iiii11 [ 24 : 40 ] )
   if ( self . inner_protocol == LISP_UDP_PROTOCOL ) :
    self . inner_sport = struct . unpack ( "H" , IiiiIi1iiii11 [ 40 : 42 ] ) [ 0 ]
    self . inner_sport = socket . ntohs ( self . inner_sport )
    self . inner_dport = struct . unpack ( "H" , IiiiIi1iiii11 [ 42 : 44 ] ) [ 0 ]
    self . inner_dport = socket . ntohs ( self . inner_dport )
    if 1 - 1: iIii1I11I1II1 / o0oOOo0O0Ooo
  elif ( OO0oIii1I1I ) :
   iIi1Iii1 = len ( IiiiIi1iiii11 )
   self . inner_tos = 0
   self . inner_ttl = 0
   self . inner_protocol = 0
   self . inner_source . afi = LISP_AFI_MAC
   self . inner_dest . afi = LISP_AFI_MAC
   self . inner_dest . unpack_address ( self . swap_mac ( IiiiIi1iiii11 [ 0 : 6 ] ) )
   self . inner_source . unpack_address ( self . swap_mac ( IiiiIi1iiii11 [ 6 : 12 ] ) )
  elif ( self . lisp_header . get_instance_id ( ) == 0xffffff ) :
   if ( lisp_flow_logging ) : self . log_flow ( False )
   return ( self )
  else :
   self . packet_error = "bad-inner-version"
   if ( stats ) : stats [ self . packet_error ] . increment ( oO0oO00 )
   if 98 - 98: O0 % I1IiiI / OoooooooOO * I1ii11iIi11i - oO0o
   lprint ( "Cannot decode encapsulation, header version {}" . format ( hex ( oOoO0 ) ) )
   if 51 - 51: iII111i + I11i
   IiiiIi1iiii11 = lisp_format_packet ( IiiiIi1iiii11 [ 0 : 20 ] )
   lprint ( "Packet header: {}" . format ( IiiiIi1iiii11 ) )
   if ( lisp_flow_logging and is_lisp_packet ) : self . log_flow ( False )
   return ( None )
   if 54 - 54: II111iiii * O0 % I1IiiI . I11i
  self . inner_source . mask_len = self . inner_source . host_mask_len ( )
  self . inner_dest . mask_len = self . inner_dest . host_mask_len ( )
  self . inner_source . instance_id = o0OoO0000o
  self . inner_dest . instance_id = o0OoO0000o
  if 62 - 62: Ii1I . i11iIiiIii % O0 % I1Ii111 - Oo0Ooo
  if 69 - 69: II111iiii . OoOoOO00 * OoOoOO00 % Ii1I + I1IiiI
  if 100 - 100: i11iIiiIii - Oo0Ooo
  if 47 - 47: iII111i * OoOoOO00 * IiII
  if 46 - 46: Ii1I
  if ( lisp_nonce_echoing and is_lisp_packet ) :
   ii1 = lisp_get_echo_nonce ( self . outer_source , None )
   if ( ii1 == None ) :
    o0oooOoOoOo = self . outer_source . print_address_no_iid ( )
    ii1 = lisp_echo_nonce ( o0oooOoOoOo )
    if 96 - 96: OoOoOO00 / OoO0O00 % OoooooooOO * ooOoO0o
   Iii11I = self . lisp_header . get_nonce ( )
   if ( self . lisp_header . is_e_bit_set ( ) ) :
    ii1 . receive_request ( lisp_ipc_socket , Iii11I )
   elif ( ii1 . request_nonce_sent ) :
    ii1 . receive_echo ( lisp_ipc_socket , Iii11I )
    if 2 - 2: oO0o . OOooOOo
    if 43 - 43: iIii1I11I1II1
    if 29 - 29: IiII % ooOoO0o + OoO0O00 . i1IIi + I1IiiI
    if 24 - 24: I1Ii111 / Ii1I * I1ii11iIi11i - OoooooooOO / I1IiiI . oO0o
    if 98 - 98: i1IIi - iII111i
    if 49 - 49: o0oOOo0O0Ooo . Ii1I . oO0o
    if 9 - 9: IiII - II111iiii * OoO0O00
  if ( O00oo0o0o0oo ) : self . packet += IiiiIi1iiii11 [ : iIi1Iii1 ]
  if 78 - 78: iIii1I11I1II1 / O0 * oO0o / iII111i / OoOoOO00
  if 15 - 15: ooOoO0o / oO0o
  if 54 - 54: ooOoO0o - iIii1I11I1II1 - I11i % Ii1I / II111iiii
  if 80 - 80: i11iIiiIii % iIii1I11I1II1 / i11iIiiIii
  if ( lisp_flow_logging and is_lisp_packet ) : self . log_flow ( False )
  return ( self )
  if 66 - 66: OoOoOO00 . iIii1I11I1II1 * I1ii11iIi11i - Ii1I - iIii1I11I1II1
  if 28 - 28: OoOoOO00 % OoooooooOO
 def swap_mac ( self , mac ) :
  return ( mac [ 1 ] + mac [ 0 ] + mac [ 3 ] + mac [ 2 ] + mac [ 5 ] + mac [ 4 ] )
  if 13 - 13: IiII . Oo0Ooo - I11i / oO0o - Oo0Ooo - I1IiiI
  if 84 - 84: II111iiii
 def strip_outer_headers ( self ) :
  OoO00oo00 = 16
  OoO00oo00 += 20 if ( self . outer_version == 4 ) else 40
  self . packet = self . packet [ OoO00oo00 : : ]
  return ( self )
  if 57 - 57: O0 * iIii1I11I1II1 % O0 . OoooooooOO
  if 53 - 53: Ii1I / I1IiiI * Ii1I + o0oOOo0O0Ooo + oO0o - Oo0Ooo
 def hash_ports ( self ) :
  IiiiIi1iiii11 = self . packet
  oOoO0 = self . inner_version
  IIi1iiIIi1i = 0
  if ( oOoO0 == 4 ) :
   ii1I = struct . unpack ( "B" , IiiiIi1iiii11 [ 9 ] ) [ 0 ]
   if ( self . inner_is_fragment ) : return ( ii1I )
   if ( ii1I in [ 6 , 17 ] ) :
    IIi1iiIIi1i = ii1I
    IIi1iiIIi1i += struct . unpack ( "I" , IiiiIi1iiii11 [ 20 : 24 ] ) [ 0 ]
    IIi1iiIIi1i = ( IIi1iiIIi1i >> 16 ) ^ ( IIi1iiIIi1i & 0xffff )
    if 33 - 33: i11iIiiIii % OoOoOO00 % OOooOOo % i11iIiiIii - I1ii11iIi11i
    if 21 - 21: I11i . Oo0Ooo - OoooooooOO * i1IIi
  if ( oOoO0 == 6 ) :
   ii1I = struct . unpack ( "B" , IiiiIi1iiii11 [ 6 ] ) [ 0 ]
   if ( ii1I in [ 6 , 17 ] ) :
    IIi1iiIIi1i = ii1I
    IIi1iiIIi1i += struct . unpack ( "I" , IiiiIi1iiii11 [ 40 : 44 ] ) [ 0 ]
    IIi1iiIIi1i = ( IIi1iiIIi1i >> 16 ) ^ ( IIi1iiIIi1i & 0xffff )
    if 54 - 54: II111iiii % o0oOOo0O0Ooo - i1IIi . I1IiiI - II111iiii / iIii1I11I1II1
    if 29 - 29: oO0o
  return ( IIi1iiIIi1i )
  if 66 - 66: OoooooooOO + iII111i . IiII % i1IIi
  if 58 - 58: OOooOOo % iII111i * O0 + I1ii11iIi11i - IiII
 def hash_packet ( self ) :
  IIi1iiIIi1i = self . inner_source . address ^ self . inner_dest . address
  IIi1iiIIi1i += self . hash_ports ( )
  if ( self . inner_version == 4 ) :
   IIi1iiIIi1i = ( IIi1iiIIi1i >> 16 ) ^ ( IIi1iiIIi1i & 0xffff )
  elif ( self . inner_version == 6 ) :
   IIi1iiIIi1i = ( IIi1iiIIi1i >> 64 ) ^ ( IIi1iiIIi1i & 0xffffffffffffffff )
   IIi1iiIIi1i = ( IIi1iiIIi1i >> 32 ) ^ ( IIi1iiIIi1i & 0xffffffff )
   IIi1iiIIi1i = ( IIi1iiIIi1i >> 16 ) ^ ( IIi1iiIIi1i & 0xffff )
   if 26 - 26: i1IIi / I1IiiI / I11i + I11i
  self . udp_sport = 0xf000 | ( IIi1iiIIi1i & 0xfff )
  if 46 - 46: I1Ii111 % I1ii11iIi11i + Ii1I
  if 67 - 67: iIii1I11I1II1 . i11iIiiIii . i11iIiiIii . i11iIiiIii / I11i + ooOoO0o
 def print_packet ( self , s_or_r , is_lisp_packet ) :
  if ( is_lisp_packet == False ) :
   i11IiIiii = "{} -> {}" . format ( self . inner_source . print_address ( ) ,
 self . inner_dest . print_address ( ) )
   dprint ( ( "{} {}, tos/ttl: {}/{}, length: {}, packet: {} ..." ) . format ( bold ( s_or_r , False ) ,
   # OoOoOO00
 green ( i11IiIiii , False ) , self . inner_tos ,
 self . inner_ttl , len ( self . packet ) ,
 lisp_format_packet ( self . packet [ 0 : 60 ] ) ) )
   return
   if 94 - 94: iIii1I11I1II1 * ooOoO0o - IiII % OoooooooOO * I11i . OoOoOO00
   if 89 - 89: i11iIiiIii / O0 - i1IIi % Oo0Ooo + i11iIiiIii
  if ( s_or_r . find ( "Receive" ) != - 1 ) :
   ii1IO0oo00o000 = "decap"
   ii1IO0oo00o000 += "-vxlan" if self . udp_dport == LISP_VXLAN_DATA_PORT else ""
  else :
   ii1IO0oo00o000 = s_or_r
   if ( ii1IO0oo00o000 in [ "Send" , "Replicate" ] or ii1IO0oo00o000 . find ( "Fragment" ) != - 1 ) :
    ii1IO0oo00o000 = "encap"
    if 5 - 5: I1ii11iIi11i * Ii1I % I11i % II111iiii
    if 9 - 9: o0oOOo0O0Ooo % I1Ii111 + I11i
  oOOO00o00 = "{} -> {}" . format ( self . outer_source . print_address_no_iid ( ) ,
 self . outer_dest . print_address_no_iid ( ) )
  if 68 - 68: O0 * iIii1I11I1II1 / I1Ii111
  if 65 - 65: OOooOOo - I1IiiI * I1Ii111
  if 99 - 99: I1IiiI
  if 64 - 64: I1ii11iIi11i * Ii1I * Oo0Ooo % IiII % ooOoO0o
  if 55 - 55: II111iiii - I1Ii111 - OOooOOo % Ii1I
  if ( self . lisp_header . get_instance_id ( ) == 0xffffff ) :
   oOOo0ooO0 = ( "{} LISP packet, outer RLOCs: {}, outer tos/ttl: " + "{}/{}, outer UDP: {} -> {}, " )
   if 49 - 49: Oo0Ooo * I1Ii111
   oOOo0ooO0 += bold ( "control-packet" , False ) + ": {} ..."
   if 53 - 53: Oo0Ooo / Ii1I + oO0o . iII111i + IiII
   dprint ( oOOo0ooO0 . format ( bold ( s_or_r , False ) , red ( oOOO00o00 , False ) ,
 self . outer_tos , self . outer_ttl , self . udp_sport ,
 self . udp_dport , lisp_format_packet ( self . packet [ 0 : 56 ] ) ) )
   return
  else :
   oOOo0ooO0 = ( "{} LISP packet, outer RLOCs: {}, outer tos/ttl: " + "{}/{}, outer UDP: {} -> {}, inner EIDs: {}, " + "inner tos/ttl: {}/{}, length: {}, {}, packet: {} ..." )
   if 19 - 19: Ii1I
   if 51 - 51: iIii1I11I1II1
   if 8 - 8: OoO0O00 / o0oOOo0O0Ooo % iII111i . i11iIiiIii . OoooooooOO . Ii1I
   if 8 - 8: OoO0O00 * Oo0Ooo
  if ( self . lisp_header . k_bits ) :
   if ( ii1IO0oo00o000 == "encap" ) : ii1IO0oo00o000 = "encrypt/encap"
   if ( ii1IO0oo00o000 == "decap" ) : ii1IO0oo00o000 = "decap/decrypt"
   if 41 - 41: Oo0Ooo / OoO0O00 / OoOoOO00 - i11iIiiIii - OoOoOO00
   if 4 - 4: I11i . IiII
  i11IiIiii = "{} -> {}" . format ( self . inner_source . print_address ( ) ,
 self . inner_dest . print_address ( ) )
  if 39 - 39: OOooOOo . Oo0Ooo - OoOoOO00 * i11iIiiIii
  dprint ( oOOo0ooO0 . format ( bold ( s_or_r , False ) , red ( oOOO00o00 , False ) ,
 self . outer_tos , self . outer_ttl , self . udp_sport , self . udp_dport ,
 green ( i11IiIiii , False ) , self . inner_tos , self . inner_ttl ,
 len ( self . packet ) , self . lisp_header . print_header ( ii1IO0oo00o000 ) ,
 lisp_format_packet ( self . packet [ 0 : 56 ] ) ) )
  if 4 - 4: OoOoOO00 * O0 - I11i
  if 72 - 72: I11i + ooOoO0o / I1IiiI . IiII % OoO0O00 / i11iIiiIii
 def print_eid_tuple ( self ) :
  return ( lisp_print_eid_tuple ( self . inner_source , self . inner_dest ) )
  if 13 - 13: I1Ii111 % o0oOOo0O0Ooo + OOooOOo + I1Ii111 + i11iIiiIii - I1ii11iIi11i
  if 70 - 70: II111iiii * II111iiii . I1IiiI
 def get_raw_socket ( self ) :
  o0OoO0000o = str ( self . lisp_header . get_instance_id ( ) )
  if ( o0OoO0000o == "0" ) : return ( None )
  if ( lisp_iid_to_interface . has_key ( o0OoO0000o ) == False ) : return ( None )
  if 11 - 11: iII111i
  II1i = lisp_iid_to_interface [ o0OoO0000o ]
  IiII1iiI = II1i . get_socket ( )
  if ( IiII1iiI == None ) :
   Iii11I111Ii11 = bold ( "SO_BINDTODEVICE" , False )
   i1OooO00oO00o = ( os . getenv ( "LISP_ENFORCE_BINDTODEVICE" ) != None )
   lprint ( "{} required for multi-tenancy support, {} packet" . format ( Iii11I111Ii11 , "drop" if i1OooO00oO00o else "forward" ) )
   if 14 - 14: I1ii11iIi11i * Oo0Ooo + i11iIiiIii % OOooOOo - oO0o
   if ( i1OooO00oO00o ) : return ( None )
   if 11 - 11: I1ii11iIi11i / O0 + II111iiii
   if 95 - 95: I1Ii111 + IiII * iIii1I11I1II1
  o0OoO0000o = bold ( o0OoO0000o , False )
  OooOOOoOoo0O0 = bold ( II1i . device , False )
  dprint ( "Send packet on instance-id {} interface {}" . format ( o0OoO0000o , OooOOOoOoo0O0 ) )
  return ( IiII1iiI )
  if 17 - 17: OoO0O00 - Oo0Ooo * O0 / Ii1I
  if 19 - 19: i1IIi - iIii1I11I1II1 . I11i
 def log_flow ( self , encap ) :
  global lisp_flow_log
  if 2 - 2: Ii1I
  Ii1i111iI = os . path . exists ( "./log-flows" )
  if ( len ( lisp_flow_log ) == LISP_FLOW_LOG_SIZE or Ii1i111iI ) :
   iII1ii = [ lisp_flow_log ]
   lisp_flow_log = [ ]
   threading . Thread ( target = lisp_write_flow_log , args = iII1ii ) . start ( )
   if ( Ii1i111iI ) : os . system ( "rm ./log-flows" )
   return
   if 51 - 51: o0oOOo0O0Ooo . I1ii11iIi11i * Ii1I / Oo0Ooo * II111iiii / O0
   if 44 - 44: i11iIiiIii % I1Ii111 % oO0o + I11i * oO0o . Ii1I
  i1 = datetime . datetime . now ( )
  lisp_flow_log . append ( [ i1 , encap , self . packet , self ] )
  if 89 - 89: OoooooooOO % II111iiii - OoO0O00 % i11iIiiIii
  if 7 - 7: IiII
 def print_flow ( self , ts , encap , packet ) :
  ts = ts . strftime ( "%m/%d/%y %H:%M:%S.%f" ) [ : - 3 ]
  III11i = "{}: {}" . format ( ts , "encap" if encap else "decap" )
  if 54 - 54: I1Ii111 / o0oOOo0O0Ooo
  I11IIIIiII = red ( self . outer_source . print_address_no_iid ( ) , False )
  OoooO = red ( self . outer_dest . print_address_no_iid ( ) , False )
  IIIi1IIiII11 = green ( self . inner_source . print_address ( ) , False )
  I1IIi = green ( self . inner_dest . print_address ( ) , False )
  if 80 - 80: I11i / oO0o * Ii1I / iII111i
  if ( self . lisp_header . get_instance_id ( ) == 0xffffff ) :
   III11i += " {}:{} -> {}:{}, LISP control message type {}\n"
   III11i = III11i . format ( I11IIIIiII , self . udp_sport , OoooO , self . udp_dport ,
 self . inner_version )
   return ( III11i )
   if 19 - 19: i1IIi + II111iiii + o0oOOo0O0Ooo - iIii1I11I1II1
   if 61 - 61: iII111i * ooOoO0o
  if ( self . outer_dest . is_null ( ) == False ) :
   III11i += " {}:{} -> {}:{}, len/tos/ttl {}/{}/{}"
   III11i = III11i . format ( I11IIIIiII , self . udp_sport , OoooO , self . udp_dport ,
 len ( packet ) , self . outer_tos , self . outer_ttl )
   if 1 - 1: I1Ii111 * OoOoOO00
   if 100 - 100: I1ii11iIi11i / O0 / ooOoO0o + I1ii11iIi11i
   if 48 - 48: OoooooooOO . iII111i + O0
   if 85 - 85: II111iiii - Ii1I
   if 93 - 93: IiII / i11iIiiIii - oO0o + OoO0O00 / i1IIi
  if ( self . lisp_header . k_bits != 0 ) :
   OO0oO = "\n"
   if ( self . packet_error != "" ) :
    OO0oO = " ({})" . format ( self . packet_error ) + OO0oO
    if 32 - 32: iII111i % i1IIi
   III11i += ", encrypted" + OO0oO
   return ( III11i )
   if 62 - 62: I11i . II111iiii * O0 + i1IIi * OoooooooOO + OoooooooOO
   if 23 - 23: i1IIi
   if 31 - 31: Oo0Ooo - iIii1I11I1II1 / I11i . OoO0O00
   if 74 - 74: Oo0Ooo - II111iiii - IiII
   if 50 - 50: I1IiiI - oO0o + oO0o * I11i + oO0o
  if ( self . outer_dest . is_null ( ) == False ) :
   packet = packet [ 36 : : ] if self . outer_version == 4 else packet [ 56 : : ]
   if 70 - 70: i1IIi % OoO0O00 / i1IIi
   if 30 - 30: OoOoOO00 - i11iIiiIii
  ii1I = packet [ 9 ] if self . inner_version == 4 else packet [ 6 ]
  ii1I = struct . unpack ( "B" , ii1I ) [ 0 ]
  if 94 - 94: OoOoOO00 % iII111i
  III11i += " {} -> {}, len/tos/ttl/prot {}/{}/{}/{}"
  III11i = III11i . format ( IIIi1IIiII11 , I1IIi , len ( packet ) , self . inner_tos ,
 self . inner_ttl , ii1I )
  if 39 - 39: OoOoOO00 + I1Ii111 % O0
  if 26 - 26: ooOoO0o + OoOoOO00
  if 17 - 17: I1ii11iIi11i - iII111i % Oo0Ooo * O0 % O0 * OOooOOo
  if 6 - 6: I1Ii111
  if ( ii1I in [ 6 , 17 ] ) :
   ii1iiIiiiI11 = packet [ 20 : 24 ] if self . inner_version == 4 else packet [ 40 : 44 ]
   if ( len ( ii1iiIiiiI11 ) == 4 ) :
    ii1iiIiiiI11 = socket . ntohl ( struct . unpack ( "I" , ii1iiIiiiI11 ) [ 0 ] )
    III11i += ", ports {} -> {}" . format ( ii1iiIiiiI11 >> 16 , ii1iiIiiiI11 & 0xffff )
    if 95 - 95: I1Ii111 - IiII
  elif ( ii1I == 1 ) :
   I1ii = packet [ 26 : 28 ] if self . inner_version == 4 else packet [ 46 : 48 ]
   if ( len ( I1ii ) == 2 ) :
    I1ii = socket . ntohs ( struct . unpack ( "H" , I1ii ) [ 0 ] )
    III11i += ", icmp-seq {}" . format ( I1ii )
    if 82 - 82: OoOoOO00 . Ii1I
    if 73 - 73: I1Ii111
  if ( self . packet_error != "" ) :
   III11i += " ({})" . format ( self . packet_error )
   if 25 - 25: IiII
  III11i += "\n"
  return ( III11i )
  if 77 - 77: o0oOOo0O0Ooo . iIii1I11I1II1 . OoooooooOO . iIii1I11I1II1
  if 87 - 87: II111iiii - OoooooooOO / i1IIi . Ii1I - Oo0Ooo . i11iIiiIii
 def is_trace ( self ) :
  ii1iiIiiiI11 = [ self . inner_sport , self . inner_dport ]
  return ( self . inner_protocol == LISP_UDP_PROTOCOL and
 LISP_TRACE_PORT in ii1iiIiiiI11 )
  if 47 - 47: Oo0Ooo % OoO0O00 - ooOoO0o - Oo0Ooo * oO0o
  if 72 - 72: o0oOOo0O0Ooo % o0oOOo0O0Ooo + iII111i + I1ii11iIi11i / Oo0Ooo
  if 30 - 30: Oo0Ooo + I1IiiI + i11iIiiIii / OoO0O00
  if 64 - 64: IiII
  if 80 - 80: I1IiiI - i11iIiiIii / OoO0O00 / OoOoOO00 + OoOoOO00
  if 89 - 89: O0 + IiII * I1Ii111
  if 30 - 30: OoOoOO00
  if 39 - 39: I1ii11iIi11i + o0oOOo0O0Ooo + I1Ii111 + IiII
  if 48 - 48: I1Ii111 / ooOoO0o . iIii1I11I1II1
  if 72 - 72: i1IIi . o0oOOo0O0Ooo
  if 3 - 3: OoOoOO00 % II111iiii - O0
  if 52 - 52: OoO0O00
  if 49 - 49: Ii1I . I1ii11iIi11i % ooOoO0o . Oo0Ooo * OOooOOo
  if 44 - 44: iIii1I11I1II1 / O0 * Oo0Ooo + I1IiiI . ooOoO0o
  if 20 - 20: iII111i + o0oOOo0O0Ooo . I1Ii111 / i11iIiiIii
  if 7 - 7: OoOoOO00 / OoOoOO00 . I1Ii111 * O0 + IiII + oO0o
LISP_N_BIT = 0x80000000
LISP_L_BIT = 0x40000000
LISP_E_BIT = 0x20000000
LISP_V_BIT = 0x10000000
LISP_I_BIT = 0x08000000
LISP_P_BIT = 0x04000000
LISP_K_BITS = 0x03000000
if 98 - 98: II111iiii * IiII - I1IiiI % o0oOOo0O0Ooo - iII111i % I1ii11iIi11i
class lisp_data_header ( ) :
 def __init__ ( self ) :
  self . first_long = 0
  self . second_long = 0
  self . k_bits = 0
  if 69 - 69: i1IIi % OoO0O00 % I1Ii111 / ooOoO0o / ooOoO0o
  if 6 - 6: II111iiii % I1ii11iIi11i % i1IIi * ooOoO0o
 def print_header ( self , e_or_d ) :
  iII = lisp_hex_string ( self . first_long & 0xffffff )
  oooO0 = lisp_hex_string ( self . second_long ) . zfill ( 8 )
  if 7 - 7: OoO0O00 * iII111i
  oOOo0ooO0 = ( "{} LISP-header -> flags: {}{}{}{}{}{}{}{}, nonce: {}, " + "iid/lsb: {}" )
  if 16 - 16: I1Ii111 . i1IIi . IiII
  return ( oOOo0ooO0 . format ( bold ( e_or_d , False ) ,
 "N" if ( self . first_long & LISP_N_BIT ) else "n" ,
 "L" if ( self . first_long & LISP_L_BIT ) else "l" ,
 "E" if ( self . first_long & LISP_E_BIT ) else "e" ,
 "V" if ( self . first_long & LISP_V_BIT ) else "v" ,
 "I" if ( self . first_long & LISP_I_BIT ) else "i" ,
 "P" if ( self . first_long & LISP_P_BIT ) else "p" ,
 "K" if ( self . k_bits in [ 2 , 3 ] ) else "k" ,
 "K" if ( self . k_bits in [ 1 , 3 ] ) else "k" ,
 iII , oooO0 ) )
  if 50 - 50: OoO0O00 - II111iiii * OoooooooOO - I1IiiI . O0 + O0
  if 80 - 80: o0oOOo0O0Ooo
 def encode ( self ) :
  i1I1iii1I11II = "II"
  iII = socket . htonl ( self . first_long )
  oooO0 = socket . htonl ( self . second_long )
  if 5 - 5: i11iIiiIii / ooOoO0o - iII111i - OoooooooOO / ooOoO0o + iIii1I11I1II1
  O0ooOoO0 = struct . pack ( i1I1iii1I11II , iII , oooO0 )
  return ( O0ooOoO0 )
  if 10 - 10: i11iIiiIii % OOooOOo * iII111i % Oo0Ooo
  if 51 - 51: OoO0O00 % iII111i
 def decode ( self , packet ) :
  i1I1iii1I11II = "II"
  Iiiii = struct . calcsize ( i1I1iii1I11II )
  if ( len ( packet ) < Iiiii ) : return ( False )
  if 8 - 8: iIii1I11I1II1 . iIii1I11I1II1 + Ii1I . OOooOOo
  iII , oooO0 = struct . unpack ( i1I1iii1I11II , packet [ : Iiiii ] )
  if 58 - 58: iIii1I11I1II1 + I1Ii111 - I1ii11iIi11i - i1IIi * OoOoOO00
  if 4 - 4: OoooooooOO
  self . first_long = socket . ntohl ( iII )
  self . second_long = socket . ntohl ( oooO0 )
  self . k_bits = ( self . first_long & LISP_K_BITS ) >> 24
  return ( True )
  if 7 - 7: IiII
  if 26 - 26: OOooOOo + Oo0Ooo
 def key_id ( self , key_id ) :
  self . first_long &= ~ ( 0x3 << 24 )
  self . first_long |= ( ( key_id & 0x3 ) << 24 )
  self . k_bits = key_id
  if 71 - 71: I1IiiI . ooOoO0o
  if 43 - 43: I1ii11iIi11i * OOooOOo
 def nonce ( self , nonce ) :
  self . first_long |= LISP_N_BIT
  self . first_long |= nonce
  if 1 - 1: OoO0O00 * ooOoO0o + IiII . oO0o / ooOoO0o
  if 91 - 91: Ii1I + I11i - Oo0Ooo % OoOoOO00 . iII111i
 def map_version ( self , version ) :
  self . first_long |= LISP_V_BIT
  self . first_long |= version
  if 51 - 51: OOooOOo / I11i
  if 51 - 51: ooOoO0o * oO0o - I1Ii111 + iII111i
 def instance_id ( self , iid ) :
  if ( iid == 0 ) : return
  self . first_long |= LISP_I_BIT
  self . second_long &= 0xff
  self . second_long |= ( iid << 8 )
  if 46 - 46: o0oOOo0O0Ooo - i11iIiiIii % OoO0O00 / Ii1I - OoOoOO00
  if 88 - 88: oO0o * I1IiiI / OoO0O00 - OOooOOo / i1IIi . I1Ii111
 def get_instance_id ( self ) :
  return ( ( self . second_long >> 8 ) & 0xffffff )
  if 26 - 26: i11iIiiIii - ooOoO0o
  if 45 - 45: ooOoO0o + II111iiii % iII111i
 def locator_status_bits ( self , lsbs ) :
  self . first_long |= LISP_L_BIT
  self . second_long &= 0xffffff00
  self . second_long |= ( lsbs & 0xff )
  if 55 - 55: ooOoO0o - oO0o % I1IiiI
  if 61 - 61: ooOoO0o
 def is_request_nonce ( self , nonce ) :
  return ( nonce & 0x80000000 )
  if 22 - 22: iIii1I11I1II1 / ooOoO0o / I1IiiI - o0oOOo0O0Ooo
  if 21 - 21: oO0o . i11iIiiIii * I11i . OOooOOo / OOooOOo
 def request_nonce ( self , nonce ) :
  self . first_long |= LISP_E_BIT
  self . first_long |= LISP_N_BIT
  self . first_long |= ( nonce & 0xffffff )
  if 42 - 42: OoooooooOO / I1Ii111 . o0oOOo0O0Ooo / O0 - IiII * IiII
  if 1 - 1: Ii1I % I1Ii111
 def is_e_bit_set ( self ) :
  return ( self . first_long & LISP_E_BIT )
  if 97 - 97: OoOoOO00
  if 13 - 13: OoOoOO00 % OOooOOo . O0 / Oo0Ooo % Oo0Ooo
 def get_nonce ( self ) :
  return ( self . first_long & 0xffffff )
  if 19 - 19: I1Ii111 % ooOoO0o - ooOoO0o % I1IiiI . OOooOOo - OoooooooOO
  if 100 - 100: I1IiiI + Ii1I + o0oOOo0O0Ooo . i1IIi % OoooooooOO
  if 64 - 64: O0 % i1IIi * I1Ii111 - Ii1I + Oo0Ooo
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
  if 65 - 65: OoOoOO00 . i11iIiiIii
  if 36 - 36: oO0o * iII111i + IiII * iII111i . I1ii11iIi11i - iIii1I11I1II1
 def send_ipc ( self , ipc_socket , ipc ) :
  i1IIi1ii1i1ii = "lisp-itr" if lisp_i_am_itr else "lisp-etr"
  oo0OoO = "lisp-etr" if lisp_i_am_itr else "lisp-itr"
  ipc = lisp_command_ipc ( ipc , i1IIi1ii1i1ii )
  lisp_ipc ( ipc , ipc_socket , oo0OoO )
  if 97 - 97: II111iiii
  if 38 - 38: I1IiiI
 def send_request_ipc ( self , ipc_socket , nonce ) :
  nonce = lisp_hex_string ( nonce )
  iiiii1i1 = "nonce%R%{}%{}" . format ( self . rloc_str , nonce )
  self . send_ipc ( ipc_socket , iiiii1i1 )
  if 87 - 87: IiII - O0 + I1IiiI / OoooooooOO * iII111i / i1IIi
  if 28 - 28: o0oOOo0O0Ooo - iII111i * I1ii11iIi11i - II111iiii % II111iiii - IiII
 def send_echo_ipc ( self , ipc_socket , nonce ) :
  nonce = lisp_hex_string ( nonce )
  iiiii1i1 = "nonce%E%{}%{}" . format ( self . rloc_str , nonce )
  self . send_ipc ( ipc_socket , iiiii1i1 )
  if 76 - 76: I1Ii111
  if 43 - 43: O0 / I1Ii111 . iIii1I11I1II1 - OoOoOO00
 def receive_request ( self , ipc_socket , nonce ) :
  iiII1iiI = self . request_nonce_rcvd
  self . request_nonce_rcvd = nonce
  self . last_request_nonce_rcvd = lisp_get_timestamp ( )
  if ( lisp_i_am_rtr ) : return
  if ( iiII1iiI != nonce ) : self . send_request_ipc ( ipc_socket , nonce )
  if 57 - 57: i11iIiiIii - I11i / ooOoO0o / o0oOOo0O0Ooo * i11iIiiIii * o0oOOo0O0Ooo
  if 28 - 28: OoooooooOO % O0 - OOooOOo / o0oOOo0O0Ooo / I1IiiI
 def receive_echo ( self , ipc_socket , nonce ) :
  if ( self . request_nonce_sent != nonce ) : return
  self . last_echo_nonce_rcvd = lisp_get_timestamp ( )
  if ( self . echo_nonce_rcvd == nonce ) : return
  if 41 - 41: II111iiii * IiII / OoO0O00 . oO0o
  self . echo_nonce_rcvd = nonce
  if ( lisp_i_am_rtr ) : return
  self . send_echo_ipc ( ipc_socket , nonce )
  if 50 - 50: OoooooooOO + iIii1I11I1II1 / oO0o / OOooOOo . i11iIiiIii . ooOoO0o
  if 75 - 75: iIii1I11I1II1 % ooOoO0o / OOooOOo - iII111i % i11iIiiIii
 def get_request_or_echo_nonce ( self , ipc_socket , remote_rloc ) :
  if 11 - 11: I11i . Ii1I
  if 87 - 87: OOooOOo + OOooOOo
  if 45 - 45: i1IIi - Oo0Ooo
  if 87 - 87: OoOoOO00 - OoO0O00 * OoO0O00 / Ii1I . I11i * o0oOOo0O0Ooo
  if 21 - 21: II111iiii
  if ( self . request_nonce_sent and self . echo_nonce_sent and remote_rloc ) :
   iI1iIiii111 = lisp_myrlocs [ 0 ] if remote_rloc . is_ipv4 ( ) else lisp_myrlocs [ 1 ]
   if 27 - 27: iIii1I11I1II1 + oO0o % Oo0Ooo
   if 99 - 99: iIii1I11I1II1 - Oo0Ooo / O0 / IiII
   if ( remote_rloc . address > iI1iIiii111 . address ) :
    OO0o = "exit"
    self . request_nonce_sent = None
   else :
    OO0o = "stay in"
    self . echo_nonce_sent = None
    if 52 - 52: O0 + ooOoO0o
    if 11 - 11: i1IIi / I1Ii111 * I1ii11iIi11i * I1Ii111 * ooOoO0o - i11iIiiIii
   oOOoooo0o0 = bold ( "collision" , False )
   I11iIi1i1I1i1 = red ( iI1iIiii111 . print_address_no_iid ( ) , False )
   O0OOOO0o0O = red ( remote_rloc . print_address_no_iid ( ) , False )
   lprint ( "Echo nonce {}, {} -> {}, {} request-nonce mode" . format ( oOOoooo0o0 ,
 I11iIi1i1I1i1 , O0OOOO0o0O , OO0o ) )
   if 76 - 76: OoO0O00 + OOooOOo - IiII . i1IIi
   if 87 - 87: ooOoO0o + O0
   if 69 - 69: iIii1I11I1II1 + i1IIi % II111iiii . OoO0O00 * oO0o * IiII
   if 90 - 90: I1Ii111
   if 62 - 62: II111iiii
  if ( self . echo_nonce_sent != None ) :
   Iii11I = self . echo_nonce_sent
   oOo = bold ( "Echoing" , False )
   lprint ( "{} nonce 0x{} to {}" . format ( oOo ,
 lisp_hex_string ( Iii11I ) , red ( self . rloc_str , False ) ) )
   self . last_echo_nonce_sent = lisp_get_timestamp ( )
   self . echo_nonce_sent = None
   return ( Iii11I )
   if 60 - 60: i1IIi * II111iiii + Ii1I / I1Ii111 % OoOoOO00
   if 100 - 100: iIii1I11I1II1 * i1IIi - i11iIiiIii - I1Ii111 % Ii1I
   if 56 - 56: I11i
   if 99 - 99: OoooooooOO % i1IIi % OoooooooOO . iII111i
   if 20 - 20: OoO0O00 . oO0o
   if 4 - 4: Oo0Ooo % Ii1I % OoO0O00 * iII111i % OoooooooOO
   if 38 - 38: OoooooooOO . iII111i
  Iii11I = self . request_nonce_sent
  iiI = self . last_request_nonce_sent
  if ( Iii11I and iiI != None ) :
   if ( time . time ( ) - iiI >= LISP_NONCE_ECHO_INTERVAL ) :
    self . request_nonce_sent = None
    lprint ( "Stop request-nonce mode for {}, nonce 0x{}" . format ( red ( self . rloc_str , False ) , lisp_hex_string ( Iii11I ) ) )
    if 44 - 44: I11i . IiII % I1Ii111 - ooOoO0o - I1ii11iIi11i
    return ( None )
    if 34 - 34: I1ii11iIi11i % i1IIi - OoO0O00
    if 18 - 18: I1IiiI + I1Ii111 - iII111i % II111iiii / OoOoOO00 % O0
    if 59 - 59: O0 . o0oOOo0O0Ooo % I1ii11iIi11i * oO0o + I11i
    if 82 - 82: OoooooooOO
    if 88 - 88: O0 / o0oOOo0O0Ooo * o0oOOo0O0Ooo . o0oOOo0O0Ooo . O0
    if 27 - 27: i11iIiiIii % iII111i + Ii1I . OOooOOo
    if 9 - 9: OoO0O00
    if 43 - 43: Ii1I . OOooOOo + I1IiiI * i11iIiiIii
    if 2 - 2: OOooOOo
  if ( Iii11I == None ) :
   Iii11I = lisp_get_data_nonce ( )
   if ( self . recently_requested ( ) ) : return ( Iii11I )
   if 3 - 3: I1IiiI . iII111i % O0 - ooOoO0o / O0
   self . request_nonce_sent = Iii11I
   lprint ( "Start request-nonce mode for {}, nonce 0x{}" . format ( red ( self . rloc_str , False ) , lisp_hex_string ( Iii11I ) ) )
   if 79 - 79: Ii1I + oO0o % ooOoO0o % I1IiiI
   self . last_new_request_nonce_sent = lisp_get_timestamp ( )
   if 68 - 68: II111iiii - OoooooooOO / iIii1I11I1II1 - o0oOOo0O0Ooo % II111iiii
   if 53 - 53: iII111i . oO0o / Oo0Ooo . OoO0O00 . i11iIiiIii
   if 60 - 60: II111iiii
   if 25 - 25: Oo0Ooo + o0oOOo0O0Ooo - OoO0O00
   if 57 - 57: II111iiii . i1IIi
   if ( lisp_i_am_itr == False ) : return ( Iii11I | 0x80000000 )
   self . send_request_ipc ( ipc_socket , Iii11I )
  else :
   lprint ( "Continue request-nonce mode for {}, nonce 0x{}" . format ( red ( self . rloc_str , False ) , lisp_hex_string ( Iii11I ) ) )
   if 33 - 33: iII111i + Oo0Ooo % I11i . oO0o
   if 6 - 6: IiII + I1ii11iIi11i
   if 62 - 62: oO0o . I1Ii111 - OoooooooOO * II111iiii . i11iIiiIii
   if 13 - 13: iIii1I11I1II1 * o0oOOo0O0Ooo - i11iIiiIii
   if 63 - 63: OoooooooOO * I1Ii111
   if 50 - 50: Oo0Ooo - o0oOOo0O0Ooo % II111iiii . O0 . oO0o % II111iiii
   if 18 - 18: I11i % OoooooooOO + OoO0O00 / I11i
  self . last_request_nonce_sent = lisp_get_timestamp ( )
  return ( Iii11I | 0x80000000 )
  if 37 - 37: i1IIi - Ii1I / IiII . II111iiii % ooOoO0o
  if 39 - 39: Ii1I % i11iIiiIii * OoO0O00
 def request_nonce_timeout ( self ) :
  if ( self . request_nonce_sent == None ) : return ( False )
  if ( self . request_nonce_sent == self . echo_nonce_rcvd ) : return ( False )
  if 23 - 23: OOooOOo + ooOoO0o / i11iIiiIii * Oo0Ooo . OoO0O00
  oO000o0Oo00 = time . time ( ) - self . last_request_nonce_sent
  i1I111II = self . last_echo_nonce_rcvd
  return ( oO000o0Oo00 >= LISP_NONCE_ECHO_INTERVAL and i1I111II == None )
  if 51 - 51: I1IiiI * ooOoO0o
  if 47 - 47: OOooOOo . OOooOOo . IiII . I1Ii111 / i1IIi
 def recently_requested ( self ) :
  i1I111II = self . last_request_nonce_sent
  if ( i1I111II == None ) : return ( False )
  if 77 - 77: II111iiii % I11i / Oo0Ooo
  oO000o0Oo00 = time . time ( ) - i1I111II
  return ( oO000o0Oo00 <= LISP_NONCE_ECHO_INTERVAL )
  if 23 - 23: iIii1I11I1II1
  if 10 - 10: I11i - o0oOOo0O0Ooo % OoooooooOO - I1ii11iIi11i
 def recently_echoed ( self ) :
  if ( self . request_nonce_sent == None ) : return ( True )
  if 64 - 64: OoO0O00 / I1IiiI
  if 23 - 23: I11i * I1Ii111 * o0oOOo0O0Ooo - I1IiiI % OoOoOO00 + o0oOOo0O0Ooo
  if 41 - 41: IiII * OoooooooOO . ooOoO0o % i11iIiiIii
  if 11 - 11: iIii1I11I1II1 . I1Ii111 - Oo0Ooo / I11i + II111iiii
  i1I111II = self . last_good_echo_nonce_rcvd
  if ( i1I111II == None ) : i1I111II = 0
  oO000o0Oo00 = time . time ( ) - i1I111II
  if ( oO000o0Oo00 <= LISP_NONCE_ECHO_INTERVAL ) : return ( True )
  if 29 - 29: I11i . i11iIiiIii + i1IIi - Ii1I + O0 . I1IiiI
  if 8 - 8: o0oOOo0O0Ooo
  if 78 - 78: i1IIi - Oo0Ooo
  if 48 - 48: Ii1I - OoooooooOO + I1Ii111 % o0oOOo0O0Ooo - OoOoOO00 . I1IiiI
  if 42 - 42: I1Ii111
  if 70 - 70: o0oOOo0O0Ooo / I11i + oO0o % I1IiiI % Oo0Ooo + OoO0O00
  i1I111II = self . last_new_request_nonce_sent
  if ( i1I111II == None ) : i1I111II = 0
  oO000o0Oo00 = time . time ( ) - i1I111II
  return ( oO000o0Oo00 <= LISP_NONCE_ECHO_INTERVAL )
  if 80 - 80: OOooOOo
  if 12 - 12: Ii1I
 def change_state ( self , rloc ) :
  if ( rloc . up_state ( ) and self . recently_echoed ( ) == False ) :
   i1Ii = bold ( "down" , False )
   I1i = lisp_print_elapsed ( self . last_good_echo_nonce_rcvd )
   lprint ( "Take {} {}, last good echo: {}" . format ( red ( self . rloc_str , False ) , i1Ii , I1i ) )
   if 16 - 16: I11i / OoooooooOO . i1IIi
   rloc . state = LISP_RLOC_NO_ECHOED_NONCE_STATE
   rloc . last_state_change = lisp_get_timestamp ( )
   return
   if 90 - 90: o0oOOo0O0Ooo % I1ii11iIi11i / OoOoOO00
   if 85 - 85: I1Ii111 - ooOoO0o - iII111i
  if ( rloc . no_echoed_nonce_state ( ) == False ) : return
  if 30 - 30: I1IiiI . Ii1I - Ii1I * i1IIi + I1Ii111 * I11i
  if ( self . recently_requested ( ) == False ) :
   oOOo = bold ( "up" , False )
   lprint ( "Bring {} {}, retry request-nonce mode" . format ( red ( self . rloc_str , False ) , oOOo ) )
   if 11 - 11: i11iIiiIii % o0oOOo0O0Ooo % ooOoO0o
   rloc . state = LISP_RLOC_UP_STATE
   rloc . last_state_change = lisp_get_timestamp ( )
   if 59 - 59: II111iiii
   if 58 - 58: OoOoOO00 % iII111i / I1ii11iIi11i + I1Ii111 - oO0o + iII111i
   if 87 - 87: oO0o % I11i % Ii1I % IiII
 def print_echo_nonce ( self ) :
  I1I = lisp_print_elapsed ( self . last_request_nonce_sent )
  OOo = lisp_print_elapsed ( self . last_good_echo_nonce_rcvd )
  if 78 - 78: Ii1I - ooOoO0o * iIii1I11I1II1 * iII111i * Ii1I / Ii1I
  IiIiIiIII1Iii = lisp_print_elapsed ( self . last_echo_nonce_sent )
  OOoO = lisp_print_elapsed ( self . last_request_nonce_rcvd )
  IiII1iiI = space ( 4 )
  if 91 - 91: o0oOOo0O0Ooo * I1ii11iIi11i - iII111i . II111iiii
  Oo0Ooo0O0 = "Nonce-Echoing:\n"
  Oo0Ooo0O0 += ( "{}Last request-nonce sent: {}\n{}Last echo-nonce " + "received: {}\n" ) . format ( IiII1iiI , I1I , IiII1iiI , OOo )
  if 1 - 1: OOooOOo + I1Ii111 * I1ii11iIi11i
  Oo0Ooo0O0 += ( "{}Last request-nonce received: {}\n{}Last echo-nonce " + "sent: {}" ) . format ( IiII1iiI , OOoO , IiII1iiI , IiIiIiIII1Iii )
  if 44 - 44: iII111i
  if 79 - 79: o0oOOo0O0Ooo % OOooOOo . O0
  return ( Oo0Ooo0O0 )
  if 56 - 56: oO0o + i1IIi * iII111i - O0
  if 84 - 84: iII111i % I1IiiI / iIii1I11I1II1 * Ii1I * iIii1I11I1II1 + I1ii11iIi11i
  if 78 - 78: IiII / iII111i * Ii1I . OOooOOo . oO0o - I1Ii111
  if 39 - 39: ooOoO0o . i1IIi + OoooooooOO . iII111i - i11iIiiIii % I1Ii111
  if 38 - 38: oO0o
  if 9 - 9: I11i . OoO0O00 . oO0o / OoooooooOO
  if 59 - 59: iIii1I11I1II1 + i1IIi % II111iiii
  if 2 - 2: II111iiii + I11i . OoO0O00
  if 14 - 14: OOooOOo * I1IiiI - I1ii11iIi11i
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
    if 10 - 10: iII111i % I1Ii111 * I1ii11iIi11i * O0 * i11iIiiIii % I1Ii111
   self . local_private_key = random . randint ( 0 , 2 ** 128 - 1 )
   Oo000O000 = lisp_hex_string ( self . local_private_key ) . zfill ( 32 )
   self . curve25519 = curve25519 . Private ( Oo000O000 )
  else :
   self . local_private_key = random . randint ( 0 , 0x1fff )
   if 68 - 68: OoooooooOO * OoOoOO00
  self . local_public_key = self . compute_public_key ( )
  self . remote_public_key = None
  self . shared_key = None
  self . encrypt_key = None
  self . icv_key = None
  self . icv = poly1305 if do_poly else hashlib . sha256
  self . iv = None
  self . get_iv ( )
  self . do_poly = do_poly
  if 9 - 9: I1Ii111
  if 36 - 36: I1Ii111 / OoOoOO00 + OoOoOO00 * ooOoO0o / OOooOOo * O0
 def copy_keypair ( self , key ) :
  self . local_private_key = key . local_private_key
  self . local_public_key = key . local_public_key
  self . curve25519 = key . curve25519
  if 17 - 17: OoO0O00 / ooOoO0o % I1IiiI
  if 47 - 47: Oo0Ooo * OoO0O00 / o0oOOo0O0Ooo * I1IiiI
 def get_iv ( self ) :
  if ( self . iv == None ) :
   self . iv = random . randint ( 0 , LISP_16_128_MASK )
  else :
   self . iv += 1
   if 60 - 60: I1ii11iIi11i / IiII . i11iIiiIii / OoO0O00 % II111iiii
  iiI1iiIiiiI1I = self . iv
  if ( self . cipher_suite == LISP_CS_25519_CHACHA ) :
   iiI1iiIiiiI1I = struct . pack ( "Q" , iiI1iiIiiiI1I & LISP_8_64_MASK )
  elif ( self . cipher_suite == LISP_CS_25519_GCM ) :
   i1II111II1 = struct . pack ( "I" , ( iiI1iiIiiiI1I >> 64 ) & LISP_4_32_MASK )
   I11I1iiI1 = struct . pack ( "Q" , iiI1iiIiiiI1I & LISP_8_64_MASK )
   iiI1iiIiiiI1I = i1II111II1 + I11I1iiI1
  else :
   iiI1iiIiiiI1I = struct . pack ( "QQ" , iiI1iiIiiiI1I >> 64 , iiI1iiIiiiI1I & LISP_8_64_MASK )
  return ( iiI1iiIiiiI1I )
  if 18 - 18: OoOoOO00 % oO0o % OoO0O00 / iII111i
  if 88 - 88: iII111i * OOooOOo / i11iIiiIii / i1IIi
 def key_length ( self , key ) :
  if ( type ( key ) != str ) : key = self . normalize_pub_key ( key )
  return ( len ( key ) / 2 )
  if 76 - 76: Ii1I . I11i - OOooOOo + OoOoOO00 * OoO0O00 % I1Ii111
  if 24 - 24: iIii1I11I1II1 % Oo0Ooo % i11iIiiIii
 def print_key ( self , key ) :
  oOoOOoo = self . normalize_pub_key ( key )
  return ( "0x{}...{}({})" . format ( oOoOOoo [ 0 : 4 ] , oOoOOoo [ - 4 : : ] , self . key_length ( oOoOOoo ) ) )
  if 55 - 55: iII111i
  if 19 - 19: OoooooooOO / OOooOOo * i11iIiiIii - I1IiiI
 def normalize_pub_key ( self , key ) :
  if ( type ( key ) == str ) :
   if ( self . curve25519 ) : return ( binascii . hexlify ( key ) )
   return ( key )
   if 99 - 99: OoO0O00 % O0 . I1Ii111 - I1ii11iIi11i . Oo0Ooo / OoOoOO00
  key = lisp_hex_string ( key ) . zfill ( 256 )
  return ( key )
  if 60 - 60: I1ii11iIi11i
  if 78 - 78: oO0o + II111iiii
 def print_keys ( self , do_bold = True ) :
  I11iIi1i1I1i1 = bold ( "local-key: " , False ) if do_bold else "local-key: "
  if ( self . local_public_key == None ) :
   I11iIi1i1I1i1 += "none"
  else :
   I11iIi1i1I1i1 += self . print_key ( self . local_public_key )
   if 55 - 55: OoooooooOO
  O0OOOO0o0O = bold ( "remote-key: " , False ) if do_bold else "remote-key: "
  if ( self . remote_public_key == None ) :
   O0OOOO0o0O += "none"
  else :
   O0OOOO0o0O += self . print_key ( self . remote_public_key )
   if 90 - 90: I1IiiI
  III1I1Iii1 = "ECDH" if ( self . curve25519 ) else "DH"
  IIIiIII1 = self . cipher_suite
  return ( "{} cipher-suite: {}, {}, {}" . format ( III1I1Iii1 , IIIiIII1 , I11iIi1i1I1i1 , O0OOOO0o0O ) )
  if 92 - 92: Oo0Ooo + IiII / Oo0Ooo + Ii1I / OOooOOo
  if 3 - 3: Ii1I / O0 * ooOoO0o - OoOoOO00
 def compare_keys ( self , keys ) :
  if ( self . dh_g_value != keys . dh_g_value ) : return ( False )
  if ( self . dh_p_value != keys . dh_p_value ) : return ( False )
  if ( self . remote_public_key != keys . remote_public_key ) : return ( False )
  return ( True )
  if 54 - 54: oO0o . o0oOOo0O0Ooo * I11i
  if 16 - 16: I1ii11iIi11i / I11i + o0oOOo0O0Ooo % i11iIiiIii % OOooOOo - Ii1I
 def compute_public_key ( self ) :
  if ( self . curve25519 ) : return ( self . curve25519 . get_public ( ) . public )
  if 37 - 37: OOooOOo * Ii1I * I11i + OoOoOO00 / i11iIiiIii
  Oo000O000 = self . local_private_key
  i11ii = self . dh_g_value
  oo00ooOOOo0O = self . dh_p_value
  return ( int ( ( i11ii ** Oo000O000 ) % oo00ooOOOo0O ) )
  if 19 - 19: OOooOOo * I11i
  if 85 - 85: i1IIi % o0oOOo0O0Ooo * I1ii11iIi11i * OoO0O00 . II111iiii
 def compute_shared_key ( self , ed , print_shared = False ) :
  Oo000O000 = self . local_private_key
  O000 = self . remote_public_key
  if 18 - 18: ooOoO0o + I1Ii111 / OOooOOo / oO0o + iIii1I11I1II1 % IiII
  oOoOO00Ooo = bold ( "Compute {} shared-key" . format ( ed ) , False )
  lprint ( "{}, key-material: {}" . format ( oOoOO00Ooo , self . print_keys ( ) ) )
  if 49 - 49: i1IIi % oO0o / OOooOOo . I1ii11iIi11i - I1Ii111
  if ( self . curve25519 ) :
   iiI1Iii = curve25519 . Public ( O000 )
   self . shared_key = self . curve25519 . get_shared_key ( iiI1Iii )
  else :
   oo00ooOOOo0O = self . dh_p_value
   self . shared_key = ( O000 ** Oo000O000 ) % oo00ooOOOo0O
   if 84 - 84: I1IiiI / OoOoOO00
   if 33 - 33: I11i . Oo0Ooo
   if 89 - 89: iII111i + i1IIi - IiII + ooOoO0o . II111iiii
   if 85 - 85: iIii1I11I1II1 - Ii1I * Oo0Ooo . oO0o + I1Ii111
   if 13 - 13: O0 + iIii1I11I1II1 % II111iiii + iIii1I11I1II1
   if 85 - 85: I1IiiI * iIii1I11I1II1 . iII111i / iII111i
   if 43 - 43: I1IiiI
  if ( print_shared ) :
   oOoOOoo = self . print_key ( self . shared_key )
   lprint ( "Computed shared-key: {}" . format ( oOoOOoo ) )
   if 78 - 78: OoO0O00 % II111iiii + OoOoOO00 / I1IiiI
   if 34 - 34: o0oOOo0O0Ooo % I1ii11iIi11i + Ii1I * I11i / oO0o
   if 18 - 18: ooOoO0o
   if 92 - 92: OoO0O00 % iIii1I11I1II1 / IiII * iII111i . i1IIi + oO0o
   if 24 - 24: IiII . iII111i * IiII % i11iIiiIii . i11iIiiIii + i1IIi
  self . compute_encrypt_icv_keys ( )
  if 64 - 64: iIii1I11I1II1 / IiII / Oo0Ooo - I1ii11iIi11i
  if 100 - 100: IiII + i1IIi * OoO0O00
  if 64 - 64: oO0o * i11iIiiIii . Oo0Ooo
  if 52 - 52: Oo0Ooo / ooOoO0o / iII111i - o0oOOo0O0Ooo / iII111i
  self . rekey_count += 1
  self . last_rekey = lisp_get_timestamp ( )
  if 74 - 74: i1IIi . iIii1I11I1II1
  if 85 - 85: I1IiiI
 def compute_encrypt_icv_keys ( self ) :
  ii = hashlib . sha256
  if ( self . curve25519 ) :
   i1I = self . shared_key
  else :
   i1I = lisp_hex_string ( self . shared_key )
   if 3 - 3: OoOoOO00
   if 52 - 52: OoOoOO00
   if 79 - 79: I1IiiI + Oo0Ooo % OoOoOO00 - IiII + I1IiiI * oO0o
   if 52 - 52: OoOoOO00 % I1ii11iIi11i * Oo0Ooo % OoooooooOO - OoO0O00
   if 13 - 13: OOooOOo . Ii1I / I11i
  I11iIi1i1I1i1 = self . local_public_key
  if ( type ( I11iIi1i1I1i1 ) != long ) : I11iIi1i1I1i1 = int ( binascii . hexlify ( I11iIi1i1I1i1 ) , 16 )
  O0OOOO0o0O = self . remote_public_key
  if ( type ( O0OOOO0o0O ) != long ) : O0OOOO0o0O = int ( binascii . hexlify ( O0OOOO0o0O ) , 16 )
  O00ooOOO00000 = "0001" + "lisp-crypto" + lisp_hex_string ( I11iIi1i1I1i1 ^ O0OOOO0o0O ) + "0100"
  if 66 - 66: i1IIi - i1IIi - OOooOOo . I11i
  IiIiIII11i1i = hmac . new ( O00ooOOO00000 , i1I , ii ) . hexdigest ( )
  IiIiIII11i1i = int ( IiIiIII11i1i , 16 )
  if 95 - 95: II111iiii / Ii1I % I11i - OoooooooOO
  if 45 - 45: OoO0O00 * OoooooooOO / O0 . I1Ii111 / OoOoOO00
  if 53 - 53: OoOoOO00 . I1IiiI * I1ii11iIi11i
  if 56 - 56: iIii1I11I1II1 / Ii1I % Ii1I . Ii1I + o0oOOo0O0Ooo * OoooooooOO
  oO00OOOO = ( IiIiIII11i1i >> 128 ) & LISP_16_128_MASK
  IIIiIIi111 = IiIiIII11i1i & LISP_16_128_MASK
  self . encrypt_key = lisp_hex_string ( oO00OOOO ) . zfill ( 32 )
  oo0O0 = 32 if self . do_poly else 40
  self . icv_key = lisp_hex_string ( IIIiIIi111 ) . zfill ( oo0O0 )
  if 86 - 86: O0 . OoooooooOO * I11i / IiII
  if 87 - 87: iIii1I11I1II1
 def do_icv ( self , packet , nonce ) :
  if ( self . icv_key == None ) : return ( "" )
  if ( self . do_poly ) :
   OOOooOO0oO = self . icv . poly1305aes
   iIiIi1 = self . icv . binascii . hexlify
   nonce = iIiIi1 ( nonce )
   iii = OOOooOO0oO ( self . encrypt_key , self . icv_key , nonce , packet )
   iii = iIiIi1 ( iii )
  else :
   Oo000O000 = binascii . unhexlify ( self . icv_key )
   iii = hmac . new ( Oo000O000 , packet , self . icv ) . hexdigest ( )
   iii = iii [ 0 : 40 ]
   if 12 - 12: OoOoOO00 % OOooOOo + oO0o . O0 % iIii1I11I1II1
  return ( iii )
  if 41 - 41: OoooooooOO
  if 13 - 13: I11i + I1Ii111 - I1Ii111 % oO0o / I11i
 def add_key_by_nonce ( self , nonce ) :
  if ( lisp_crypto_keys_by_nonce . has_key ( nonce ) == False ) :
   lisp_crypto_keys_by_nonce [ nonce ] = [ None , None , None , None ]
   if 4 - 4: I1IiiI + OOooOOo - IiII + iII111i
  lisp_crypto_keys_by_nonce [ nonce ] [ self . key_id ] = self
  if 78 - 78: Ii1I
  if 29 - 29: II111iiii
 def delete_key_by_nonce ( self , nonce ) :
  if ( lisp_crypto_keys_by_nonce . has_key ( nonce ) == False ) : return
  lisp_crypto_keys_by_nonce . pop ( nonce )
  if 79 - 79: iIii1I11I1II1 - i11iIiiIii + ooOoO0o - II111iiii . iIii1I11I1II1
  if 84 - 84: Oo0Ooo % I11i * O0 * I11i
 def add_key_by_rloc ( self , addr_str , encap ) :
  O0Oo = lisp_crypto_keys_by_rloc_encap if encap else lisp_crypto_keys_by_rloc_decap
  if 70 - 70: O0 . iIii1I11I1II1 * II111iiii
  if 43 - 43: Oo0Ooo / I1Ii111 / i1IIi
  if ( O0Oo . has_key ( addr_str ) == False ) :
   O0Oo [ addr_str ] = [ None , None , None , None ]
   if 3 - 3: Ii1I * ooOoO0o . OoO0O00 * OoooooooOO + OoOoOO00 / O0
  O0Oo [ addr_str ] [ self . key_id ] = self
  if 60 - 60: I11i
  if 97 - 97: i11iIiiIii * iIii1I11I1II1 / II111iiii
  if 66 - 66: II111iiii + iII111i * oO0o % I11i / i1IIi / iIii1I11I1II1
  if 62 - 62: OoOoOO00 + oO0o * IiII + O0 / OOooOOo + ooOoO0o
  if 38 - 38: i1IIi / iIii1I11I1II1 + iII111i
  if ( encap == False ) :
   lisp_write_ipc_decap_key ( addr_str , O0Oo [ addr_str ] )
   if 26 - 26: I1ii11iIi11i . Ii1I % o0oOOo0O0Ooo
   if 4 - 4: I1Ii111
   if 80 - 80: Oo0Ooo . O0 % o0oOOo0O0Ooo . o0oOOo0O0Ooo
 def encode_lcaf ( self , rloc_addr ) :
  OOoo000Ooo = self . normalize_pub_key ( self . local_public_key )
  iiii1II = self . key_length ( OOoo000Ooo )
  ii1iIiIIIII = ( 6 + iiii1II + 2 )
  if ( rloc_addr != None ) : ii1iIiIIIII += rloc_addr . addr_length ( )
  if 26 - 26: iIii1I11I1II1
  IiiiIi1iiii11 = struct . pack ( "HBBBBHBB" , socket . htons ( LISP_AFI_LCAF ) , 0 , 0 ,
 LISP_LCAF_SECURITY_TYPE , 0 , socket . htons ( ii1iIiIIIII ) , 1 , 0 )
  if 1 - 1: IiII % i1IIi
  if 41 - 41: OoO0O00 * OoO0O00 / iII111i + I1ii11iIi11i . o0oOOo0O0Ooo
  if 84 - 84: i11iIiiIii + OoO0O00 * I1IiiI + I1ii11iIi11i / Ii1I
  if 80 - 80: I1ii11iIi11i
  if 67 - 67: II111iiii
  if 2 - 2: o0oOOo0O0Ooo - O0 * Ii1I % IiII
  IIIiIII1 = self . cipher_suite
  IiiiIi1iiii11 += struct . pack ( "BBH" , IIIiIII1 , 0 , socket . htons ( iiii1II ) )
  if 64 - 64: i1IIi . ooOoO0o
  if 7 - 7: oO0o . iII111i - iII111i / I1Ii111 % Oo0Ooo
  if 61 - 61: oO0o - I1ii11iIi11i / iII111i % I1ii11iIi11i + OoO0O00 / Oo0Ooo
  if 10 - 10: i11iIiiIii / OoOoOO00
  for IiIIi1IiiIiI in range ( 0 , iiii1II * 2 , 16 ) :
   Oo000O000 = int ( OOoo000Ooo [ IiIIi1IiiIiI : IiIIi1IiiIiI + 16 ] , 16 )
   IiiiIi1iiii11 += struct . pack ( "Q" , byte_swap_64 ( Oo000O000 ) )
   if 27 - 27: I1IiiI / OoooooooOO
   if 74 - 74: I1ii11iIi11i % I1Ii111 - OoO0O00 * I11i . OoooooooOO * OoO0O00
   if 99 - 99: OoOoOO00 . iII111i - OoooooooOO - O0
   if 6 - 6: OOooOOo
   if 3 - 3: O0 - I1Ii111 * Ii1I * OOooOOo / Ii1I
  if ( rloc_addr ) :
   IiiiIi1iiii11 += struct . pack ( "H" , socket . htons ( rloc_addr . afi ) )
   IiiiIi1iiii11 += rloc_addr . pack_address ( )
   if 58 - 58: Ii1I * iIii1I11I1II1 + ooOoO0o . ooOoO0o
  return ( IiiiIi1iiii11 )
  if 74 - 74: ooOoO0o - o0oOOo0O0Ooo * IiII % ooOoO0o
  if 93 - 93: iIii1I11I1II1 / OoOoOO00 % Oo0Ooo * I1Ii111 - OoO0O00 - o0oOOo0O0Ooo
 def decode_lcaf ( self , packet , lcaf_len ) :
  if 44 - 44: OoooooooOO
  if 82 - 82: OoOoOO00 . OoOoOO00
  if 10 - 10: Oo0Ooo * I1ii11iIi11i . oO0o . OoooooooOO . OOooOOo * I1ii11iIi11i
  if 80 - 80: I1Ii111 + I11i . I1Ii111 + OOooOOo
  if ( lcaf_len == 0 ) :
   i1I1iii1I11II = "HHBBH"
   Iiiii = struct . calcsize ( i1I1iii1I11II )
   if ( len ( packet ) < Iiiii ) : return ( None )
   if 85 - 85: i11iIiiIii . I11i + Ii1I / Ii1I
   O0ooo0 , i1o00Oo , iI1IIiI111iII , i1o00Oo , lcaf_len = struct . unpack ( i1I1iii1I11II , packet [ : Iiiii ] )
   if 25 - 25: i11iIiiIii - OoOoOO00
   if 32 - 32: i11iIiiIii
   if ( iI1IIiI111iII != LISP_LCAF_SECURITY_TYPE ) :
    packet = packet [ lcaf_len + 6 : : ]
    return ( packet )
    if 57 - 57: iIii1I11I1II1
   lcaf_len = socket . ntohs ( lcaf_len )
   packet = packet [ Iiiii : : ]
   if 99 - 99: iII111i % o0oOOo0O0Ooo + iIii1I11I1II1
   if 51 - 51: i1IIi % o0oOOo0O0Ooo - oO0o - IiII
   if 14 - 14: ooOoO0o + Ii1I
   if 45 - 45: oO0o + II111iiii . iII111i / I1ii11iIi11i
   if 76 - 76: Ii1I + iII111i - IiII * iIii1I11I1II1 % i1IIi
   if 72 - 72: ooOoO0o + II111iiii . O0 - iII111i / OoooooooOO . I1Ii111
  iI1IIiI111iII = LISP_LCAF_SECURITY_TYPE
  i1I1iii1I11II = "BBBBH"
  Iiiii = struct . calcsize ( i1I1iii1I11II )
  if ( len ( packet ) < Iiiii ) : return ( None )
  if 28 - 28: iIii1I11I1II1 . O0
  iiiI , i1o00Oo , IIIiIII1 , i1o00Oo , iiii1II = struct . unpack ( i1I1iii1I11II ,
 packet [ : Iiiii ] )
  if 41 - 41: Ii1I
  if 49 - 49: Ii1I % II111iiii . Ii1I - o0oOOo0O0Ooo - I11i * IiII
  if 47 - 47: O0 . o0oOOo0O0Ooo / Ii1I * iII111i
  if 63 - 63: I1Ii111 - oO0o - iII111i - ooOoO0o / oO0o + OoO0O00
  if 94 - 94: IiII / I1IiiI . II111iiii
  if 32 - 32: oO0o . OOooOOo % OOooOOo . OoOoOO00
  packet = packet [ Iiiii : : ]
  iiii1II = socket . ntohs ( iiii1II )
  if ( len ( packet ) < iiii1II ) : return ( None )
  if 37 - 37: OOooOOo + O0 + OOooOOo . iII111i . o0oOOo0O0Ooo
  if 78 - 78: I1IiiI / I11i + o0oOOo0O0Ooo . Oo0Ooo / O0
  if 49 - 49: I1ii11iIi11i
  if 66 - 66: o0oOOo0O0Ooo . I1ii11iIi11i
  iI111I = [ LISP_CS_25519_CBC , LISP_CS_25519_GCM , LISP_CS_25519_CHACHA ,
 LISP_CS_1024 ]
  if ( IIIiIII1 not in iI111I ) :
   lprint ( "Cipher-suites {} supported, received {}" . format ( iI111I ,
 IIIiIII1 ) )
   packet = packet [ iiii1II : : ]
   return ( packet )
   if 44 - 44: Ii1I . i11iIiiIii / Ii1I
   if 32 - 32: Ii1I + IiII + I1ii11iIi11i
  self . cipher_suite = IIIiIII1
  if 79 - 79: i1IIi / Ii1I
  if 81 - 81: iIii1I11I1II1
  if 86 - 86: IiII % IiII % OoooooooOO
  if 42 - 42: Oo0Ooo . oO0o + O0 / OOooOOo % OoooooooOO
  if 19 - 19: ooOoO0o / Ii1I
  OOoo000Ooo = 0
  for IiIIi1IiiIiI in range ( 0 , iiii1II , 8 ) :
   Oo000O000 = byte_swap_64 ( struct . unpack ( "Q" , packet [ IiIIi1IiiIiI : IiIIi1IiiIiI + 8 ] ) [ 0 ] )
   OOoo000Ooo <<= 64
   OOoo000Ooo |= Oo000O000
   if 43 - 43: OoOoOO00 % Ii1I + Oo0Ooo - OoooooooOO . O0 % Oo0Ooo
  self . remote_public_key = OOoo000Ooo
  if 98 - 98: o0oOOo0O0Ooo * Oo0Ooo - Ii1I . ooOoO0o
  if 2 - 2: Oo0Ooo - ooOoO0o % iIii1I11I1II1
  if 88 - 88: I1Ii111 - OoO0O00
  if 79 - 79: iII111i
  if 45 - 45: II111iiii + iII111i . I11i . O0 * i1IIi - Ii1I
  if ( self . curve25519 ) :
   Oo000O000 = lisp_hex_string ( self . remote_public_key )
   Oo000O000 = Oo000O000 . zfill ( 64 )
   iII1iI = ""
   for IiIIi1IiiIiI in range ( 0 , len ( Oo000O000 ) , 2 ) :
    iII1iI += chr ( int ( Oo000O000 [ IiIIi1IiiIiI : IiIIi1IiiIiI + 2 ] , 16 ) )
    if 98 - 98: II111iiii + I1IiiI - I1ii11iIi11i . Ii1I
   self . remote_public_key = iII1iI
   if 51 - 51: Ii1I + i11iIiiIii * OoO0O00 % Oo0Ooo / I1IiiI - iIii1I11I1II1
   if 20 - 20: I1Ii111 . I11i . Ii1I + I11i - OOooOOo * oO0o
  packet = packet [ iiii1II : : ]
  return ( packet )
  if 82 - 82: OoO0O00
  if 78 - 78: II111iiii / I11i - i11iIiiIii + I1ii11iIi11i * Oo0Ooo
  if 17 - 17: OoOoOO00
  if 72 - 72: iII111i . Oo0Ooo - i11iIiiIii / I1IiiI
  if 64 - 64: oO0o
  if 80 - 80: o0oOOo0O0Ooo % iIii1I11I1II1
  if 63 - 63: IiII * i11iIiiIii
  if 86 - 86: I11i % I11i - OoOoOO00 + I1Ii111 / I1IiiI * OoooooooOO
class lisp_thread ( ) :
 def __init__ ( self , name ) :
  self . thread_name = name
  self . thread_number = - 1
  self . number_of_pcap_threads = 0
  self . number_of_worker_threads = 0
  self . input_queue = Queue . Queue ( )
  self . input_stats = lisp_stats ( )
  self . lisp_packet = lisp_packet ( None )
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
  if 65 - 65: O0 / iII111i . i1IIi * iII111i / iIii1I11I1II1 - oO0o
  if 93 - 93: OoOoOO00 % i11iIiiIii - Ii1I % OoO0O00
 def decode ( self , packet ) :
  i1I1iii1I11II = "BBBBQ"
  Iiiii = struct . calcsize ( i1I1iii1I11II )
  if ( len ( packet ) < Iiiii ) : return ( False )
  if 55 - 55: o0oOOo0O0Ooo . I1ii11iIi11i
  o0OOOOOoO , Ooo0OO0O0oO , I11 , self . record_count , self . nonce = struct . unpack ( i1I1iii1I11II , packet [ : Iiiii ] )
  if 36 - 36: I1ii11iIi11i - OoooooooOO % ooOoO0o . i11iIiiIii - IiII * Oo0Ooo
  if 14 - 14: OoOoOO00
  self . type = o0OOOOOoO >> 4
  if ( self . type == LISP_MAP_REQUEST ) :
   self . smr_bit = True if ( o0OOOOOoO & 0x01 ) else False
   self . rloc_probe = True if ( o0OOOOOoO & 0x02 ) else False
   self . smr_invoked_bit = True if ( Ooo0OO0O0oO & 0x40 ) else False
   if 34 - 34: OoOoOO00 * OoOoOO00
  if ( self . type == LISP_ECM ) :
   self . ddt_bit = True if ( o0OOOOOoO & 0x04 ) else False
   self . to_etr = True if ( o0OOOOOoO & 0x02 ) else False
   self . to_ms = True if ( o0OOOOOoO & 0x01 ) else False
   if 71 - 71: II111iiii . Ii1I - OOooOOo . I1ii11iIi11i * II111iiii
  if ( self . type == LISP_NAT_INFO ) :
   self . info_reply = True if ( o0OOOOOoO & 0x08 ) else False
   if 61 - 61: OoO0O00 * iIii1I11I1II1 / I1IiiI * I1ii11iIi11i
  return ( True )
  if 45 - 45: I1Ii111 * I11i / iIii1I11I1II1 / I1IiiI % II111iiii
  if 49 - 49: Ii1I / iII111i . iII111i . iII111i + i11iIiiIii % I11i
 def is_info_request ( self ) :
  return ( ( self . type == LISP_NAT_INFO and self . is_info_reply ( ) == False ) )
  if 7 - 7: IiII * ooOoO0o + OoOoOO00
  if 22 - 22: iII111i
 def is_info_reply ( self ) :
  return ( True if self . info_reply else False )
  if 48 - 48: I1ii11iIi11i . I1IiiI
  if 73 - 73: O0 . I1Ii111 - OoooooooOO % I11i % i1IIi
 def is_rloc_probe ( self ) :
  return ( True if self . rloc_probe else False )
  if 14 - 14: I1Ii111 + Ii1I * Oo0Ooo
  if 49 - 49: Oo0Ooo
 def is_smr ( self ) :
  return ( True if self . smr_bit else False )
  if 57 - 57: O0 * ooOoO0o - iII111i - iIii1I11I1II1 * iII111i
  if 9 - 9: IiII . I11i
 def is_smr_invoked ( self ) :
  return ( True if self . smr_invoked_bit else False )
  if 23 - 23: O0 % OoooooooOO - O0 . I1IiiI + i11iIiiIii
  if 96 - 96: ooOoO0o % O0
 def is_ddt ( self ) :
  return ( True if self . ddt_bit else False )
  if 51 - 51: I1IiiI - iII111i / I1ii11iIi11i . I1ii11iIi11i + I1ii11iIi11i
  if 87 - 87: II111iiii . Ii1I * OoO0O00
 def is_to_etr ( self ) :
  return ( True if self . to_etr else False )
  if 74 - 74: o0oOOo0O0Ooo % OoOoOO00 . iII111i % I1Ii111 . O0 % II111iiii
  if 5 - 5: oO0o - OoooooooOO / OoOoOO00
 def is_to_ms ( self ) :
  return ( True if self . to_ms else False )
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
  if 14 - 14: IiII + IiII . I11i / Ii1I . iIii1I11I1II1
  if 10 - 10: II111iiii . OOooOOo / iII111i
 def print_map_register ( self ) :
  I1II = lisp_hex_string ( self . xtr_id )
  if 91 - 91: o0oOOo0O0Ooo
  oOOo0ooO0 = ( "{} -> flags: {}{}{}{}{}{}{}{}{}, record-count: " +
 "{}, nonce: 0x{}, key/alg-id: {}/{}{}, auth-len: {}, xtr-id: " +
 "0x{}, site-id: {}" )
  if 14 - 14: i11iIiiIii
  lprint ( oOOo0ooO0 . format ( bold ( "Map-Register" , False ) , "P" if self . proxy_reply_requested else "p" ,
  # I1ii11iIi11i
 "S" if self . lisp_sec_present else "s" ,
 "I" if self . xtr_id_present else "i" ,
 "T" if self . use_ttl_for_timeout else "t" ,
 "R" if self . merge_register_requested else "r" ,
 "M" if self . mobile_node else "m" ,
 "N" if self . map_notify_requested else "n" ,
 "F" if self . map_register_refresh else "f" ,
 "E" if self . encrypt_bit else "e" ,
 self . record_count , lisp_hex_string ( self . nonce ) , self . key_id ,
 self . alg_id , " (sha1)" if ( self . key_id == LISP_SHA_1_96_ALG_ID ) else ( " (sha2)" if ( self . key_id == LISP_SHA_256_128_ALG_ID ) else "" ) , self . auth_len , I1II , self . site_id ) )
  if 42 - 42: I11i % Oo0Ooo + IiII - I11i . iIii1I11I1II1 - Ii1I
  if 27 - 27: iII111i % Oo0Ooo . I1ii11iIi11i . i1IIi % OoOoOO00 . o0oOOo0O0Ooo
  if 37 - 37: iII111i + I1Ii111 * Ii1I + IiII
  if 39 - 39: O0 * Oo0Ooo - I1IiiI + Ii1I / II111iiii
 def encode ( self ) :
  iII = ( LISP_MAP_REGISTER << 28 ) | self . record_count
  if ( self . proxy_reply_requested ) : iII |= 0x08000000
  if ( self . lisp_sec_present ) : iII |= 0x04000000
  if ( self . xtr_id_present ) : iII |= 0x02000000
  if ( self . map_register_refresh ) : iII |= 0x1000
  if ( self . use_ttl_for_timeout ) : iII |= 0x800
  if ( self . merge_register_requested ) : iII |= 0x400
  if ( self . mobile_node ) : iII |= 0x200
  if ( self . map_notify_requested ) : iII |= 0x100
  if ( self . encryption_key_id != None ) :
   iII |= 0x2000
   iII |= self . encryption_key_id << 14
   if 66 - 66: ooOoO0o + oO0o % OoooooooOO
   if 23 - 23: oO0o . OoOoOO00 + iIii1I11I1II1
   if 17 - 17: IiII
   if 12 - 12: i1IIi . OoO0O00
   if 14 - 14: OOooOOo + II111iiii % OOooOOo . oO0o * ooOoO0o
  if ( self . alg_id == LISP_NONE_ALG_ID ) :
   self . auth_len = 0
  else :
   if ( self . alg_id == LISP_SHA_1_96_ALG_ID ) :
    self . auth_len = LISP_SHA1_160_AUTH_DATA_LEN
    if 54 - 54: ooOoO0o * I11i - I1Ii111
   if ( self . alg_id == LISP_SHA_256_128_ALG_ID ) :
    self . auth_len = LISP_SHA2_256_AUTH_DATA_LEN
    if 15 - 15: iII111i / O0
    if 61 - 61: i1IIi / i1IIi + ooOoO0o . I1Ii111 * ooOoO0o
    if 19 - 19: o0oOOo0O0Ooo . II111iiii / i1IIi
  IiiiIi1iiii11 = struct . pack ( "I" , socket . htonl ( iII ) )
  IiiiIi1iiii11 += struct . pack ( "QBBH" , self . nonce , self . key_id , self . alg_id ,
 socket . htons ( self . auth_len ) )
  if 82 - 82: O0 / iII111i * OoO0O00 - I11i + Oo0Ooo
  IiiiIi1iiii11 = self . zero_auth ( IiiiIi1iiii11 )
  return ( IiiiIi1iiii11 )
  if 47 - 47: I1ii11iIi11i * I1IiiI / I1ii11iIi11i + Ii1I * II111iiii
  if 78 - 78: I1Ii111 - i1IIi + OoOoOO00 + Oo0Ooo * I1ii11iIi11i * o0oOOo0O0Ooo
 def zero_auth ( self , packet ) :
  OoO00oo00 = struct . calcsize ( "I" ) + struct . calcsize ( "QHH" )
  oooO = ""
  II111iiI1Ii1 = 0
  if ( self . alg_id == LISP_NONE_ALG_ID ) : return ( packet )
  if ( self . alg_id == LISP_SHA_1_96_ALG_ID ) :
   oooO = struct . pack ( "QQI" , 0 , 0 , 0 )
   II111iiI1Ii1 = struct . calcsize ( "QQI" )
   if 58 - 58: OoooooooOO * i1IIi * OoOoOO00
  if ( self . alg_id == LISP_SHA_256_128_ALG_ID ) :
   oooO = struct . pack ( "QQQQ" , 0 , 0 , 0 , 0 )
   II111iiI1Ii1 = struct . calcsize ( "QQQQ" )
   if 99 - 99: Oo0Ooo
  packet = packet [ 0 : OoO00oo00 ] + oooO + packet [ OoO00oo00 + II111iiI1Ii1 : : ]
  return ( packet )
  if 72 - 72: Oo0Ooo / II111iiii * ooOoO0o * I1ii11iIi11i - IiII / I1Ii111
  if 82 - 82: I1IiiI / I11i
 def encode_auth ( self , packet ) :
  OoO00oo00 = struct . calcsize ( "I" ) + struct . calcsize ( "QHH" )
  II111iiI1Ii1 = self . auth_len
  oooO = self . auth_data
  packet = packet [ 0 : OoO00oo00 ] + oooO + packet [ OoO00oo00 + II111iiI1Ii1 : : ]
  return ( packet )
  if 6 - 6: Ii1I / ooOoO0o / i11iIiiIii % o0oOOo0O0Ooo
  if 69 - 69: I1Ii111
 def decode ( self , packet ) :
  OoO = packet
  i1I1iii1I11II = "I"
  Iiiii = struct . calcsize ( i1I1iii1I11II )
  if ( len ( packet ) < Iiiii ) : return ( [ None , None ] )
  if 55 - 55: I1Ii111
  iII = struct . unpack ( i1I1iii1I11II , packet [ : Iiiii ] )
  iII = socket . ntohl ( iII [ 0 ] )
  packet = packet [ Iiiii : : ]
  if 29 - 29: Oo0Ooo
  i1I1iii1I11II = "QBBH"
  Iiiii = struct . calcsize ( i1I1iii1I11II )
  if ( len ( packet ) < Iiiii ) : return ( [ None , None ] )
  if 97 - 97: OoO0O00 * I1Ii111
  self . nonce , self . key_id , self . alg_id , self . auth_len = struct . unpack ( i1I1iii1I11II , packet [ : Iiiii ] )
  if 80 - 80: OOooOOo * OOooOOo
  if 5 - 5: OoooooooOO - iII111i - i11iIiiIii
  self . auth_len = socket . ntohs ( self . auth_len )
  self . proxy_reply_requested = True if ( iII & 0x08000000 ) else False
  if 53 - 53: iII111i * OoO0O00 / I1ii11iIi11i + I1IiiI + OoooooooOO
  self . lisp_sec_present = True if ( iII & 0x04000000 ) else False
  self . xtr_id_present = True if ( iII & 0x02000000 ) else False
  self . use_ttl_for_timeout = True if ( iII & 0x800 ) else False
  self . map_register_refresh = True if ( iII & 0x1000 ) else False
  self . merge_register_requested = True if ( iII & 0x400 ) else False
  self . mobile_node = True if ( iII & 0x200 ) else False
  self . map_notify_requested = True if ( iII & 0x100 ) else False
  self . record_count = iII & 0xff
  if 47 - 47: I1Ii111
  if 65 - 65: Ii1I
  if 71 - 71: I1Ii111 % I1Ii111 . oO0o + i11iIiiIii - i11iIiiIii
  if 16 - 16: iIii1I11I1II1 / I1IiiI / I1Ii111 - i11iIiiIii . ooOoO0o / OOooOOo
  self . encrypt_bit = True if iII & 0x2000 else False
  if ( self . encrypt_bit ) :
   self . encryption_key_id = ( iII >> 14 ) & 0x7
   if 13 - 13: o0oOOo0O0Ooo % O0 - I1Ii111 * OoooooooOO / Oo0Ooo - OoooooooOO
   if 78 - 78: oO0o % OoooooooOO
   if 73 - 73: I1IiiI % ooOoO0o % IiII + i1IIi - OoooooooOO / oO0o
   if 78 - 78: OoooooooOO % oO0o - i11iIiiIii
   if 37 - 37: IiII % Ii1I % i1IIi
  if ( self . xtr_id_present ) :
   if ( self . decode_xtr_id ( OoO ) == False ) : return ( [ None , None ] )
   if 23 - 23: ooOoO0o - O0 + i11iIiiIii
   if 98 - 98: OoooooooOO
  packet = packet [ Iiiii : : ]
  if 61 - 61: o0oOOo0O0Ooo . IiII . O0 + OoooooooOO + O0
  if 65 - 65: i1IIi * OOooOOo * OoooooooOO - IiII . iII111i - OoO0O00
  if 71 - 71: Ii1I * OoOoOO00
  if 33 - 33: i1IIi . i1IIi * OoooooooOO % I1Ii111 * o0oOOo0O0Ooo
  if ( self . auth_len != 0 ) :
   if ( len ( packet ) < self . auth_len ) : return ( [ None , None ] )
   if 64 - 64: ooOoO0o / ooOoO0o + I1ii11iIi11i * OOooOOo % OOooOOo
   if ( self . alg_id not in ( LISP_NONE_ALG_ID , LISP_SHA_1_96_ALG_ID ,
 LISP_SHA_256_128_ALG_ID ) ) :
    lprint ( "Invalid authentication alg-id: {}" . format ( self . alg_id ) )
    return ( [ None , None ] )
    if 87 - 87: OoO0O00 * Oo0Ooo
    if 83 - 83: i1IIi * I1Ii111 - IiII / Ii1I
   II111iiI1Ii1 = self . auth_len
   if ( self . alg_id == LISP_SHA_1_96_ALG_ID ) :
    Iiiii = struct . calcsize ( "QQI" )
    if ( II111iiI1Ii1 < Iiiii ) :
     lprint ( "Invalid sha1-96 authentication length" )
     return ( [ None , None ] )
     if 48 - 48: oO0o . II111iiii - OoOoOO00 % i1IIi . OoOoOO00
    I1IiiIiIIi1Ii , oo00oo , OOOO0oO0OOo0o = struct . unpack ( "QQI" , packet [ : II111iiI1Ii1 ] )
    OoOO = ""
   elif ( self . alg_id == LISP_SHA_256_128_ALG_ID ) :
    Iiiii = struct . calcsize ( "QQQQ" )
    if ( II111iiI1Ii1 < Iiiii ) :
     lprint ( "Invalid sha2-256 authentication length" )
     return ( [ None , None ] )
     if 19 - 19: iIii1I11I1II1 . OoO0O00 / OoooooooOO
    I1IiiIiIIi1Ii , oo00oo , OOOO0oO0OOo0o , OoOO = struct . unpack ( "QQQQ" ,
 packet [ : II111iiI1Ii1 ] )
   else :
    lprint ( "Unsupported authentication alg-id value {}" . format ( self . alg_id ) )
    if 2 - 2: O0 - O0 % I1Ii111 / I1ii11iIi11i
    return ( [ None , None ] )
    if 76 - 76: OoO0O00 * oO0o - OoO0O00
   self . auth_data = lisp_concat_auth_data ( self . alg_id , I1IiiIiIIi1Ii , oo00oo ,
 OOOO0oO0OOo0o , OoOO )
   OoO = self . zero_auth ( OoO )
   packet = packet [ self . auth_len : : ]
   if 57 - 57: OoooooooOO / OoOoOO00 + oO0o . Ii1I
  return ( [ OoO , packet ] )
  if 14 - 14: i11iIiiIii % OOooOOo * o0oOOo0O0Ooo * OoOoOO00
  if 55 - 55: I1Ii111 * OOooOOo * I1Ii111
 def encode_xtr_id ( self , packet ) :
  oo0 = self . xtr_id >> 64
  i11Iiiiii11II = self . xtr_id & 0xffffffffffffffff
  oo0 = byte_swap_64 ( oo0 )
  i11Iiiiii11II = byte_swap_64 ( i11Iiiiii11II )
  O0O0oOO = byte_swap_64 ( self . site_id )
  packet += struct . pack ( "QQQ" , oo0 , i11Iiiiii11II , O0O0oOO )
  return ( packet )
  if 40 - 40: OoO0O00 - OoO0O00
  if 58 - 58: IiII * iII111i . I1IiiI + OOooOOo
 def decode_xtr_id ( self , packet ) :
  Iiiii = struct . calcsize ( "QQQ" )
  if ( len ( packet ) < Iiiii ) : return ( [ None , None ] )
  packet = packet [ len ( packet ) - Iiiii : : ]
  oo0 , i11Iiiiii11II , O0O0oOO = struct . unpack ( "QQQ" ,
 packet [ : Iiiii ] )
  oo0 = byte_swap_64 ( oo0 )
  i11Iiiiii11II = byte_swap_64 ( i11Iiiiii11II )
  self . xtr_id = ( oo0 << 64 ) | i11Iiiiii11II
  self . site_id = byte_swap_64 ( O0O0oOO )
  return ( True )
  if 4 - 4: OoO0O00 . OOooOOo + i11iIiiIii + ooOoO0o % oO0o - ooOoO0o
  if 45 - 45: oO0o
  if 66 - 66: OOooOOo
  if 23 - 23: I1ii11iIi11i % I11i
  if 18 - 18: OoooooooOO . i1IIi + II111iiii
  if 99 - 99: I1Ii111 - I1ii11iIi11i - I1IiiI - I1Ii111 + OoO0O00 + II111iiii
  if 34 - 34: I1Ii111 * I11i
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
  if 70 - 70: iIii1I11I1II1 / Ii1I
  if 61 - 61: O0 * o0oOOo0O0Ooo + I1Ii111 - OOooOOo . I1IiiI - IiII
 def print_notify ( self ) :
  oooO = binascii . hexlify ( self . auth_data )
  if ( self . alg_id == LISP_SHA_1_96_ALG_ID and len ( oooO ) != 40 ) :
   oooO = self . auth_data
  elif ( self . alg_id == LISP_SHA_256_128_ALG_ID and len ( oooO ) != 64 ) :
   oooO = self . auth_data
   if 7 - 7: I1ii11iIi11i
  oOOo0ooO0 = ( "{} -> record-count: {}, nonce: 0x{}, key/alg-id: " +
 "{}{}{}, auth-len: {}, auth-data: {}" )
  lprint ( oOOo0ooO0 . format ( bold ( "Map-Notify-Ack" , False ) if self . map_notify_ack else bold ( "Map-Notify" , False ) ,
  # OOooOOo - Ii1I + II111iiii / I11i - I1Ii111
 self . record_count , lisp_hex_string ( self . nonce ) , self . key_id ,
 self . alg_id , " (sha1)" if ( self . key_id == LISP_SHA_1_96_ALG_ID ) else ( " (sha2)" if ( self . key_id == LISP_SHA_256_128_ALG_ID ) else "" ) , self . auth_len , oooO ) )
  if 49 - 49: Ii1I + OoooooooOO . O0 . i11iIiiIii
  if 54 - 54: OOooOOo . I1ii11iIi11i * I11i % I1Ii111 . O0 * IiII
  if 87 - 87: Ii1I % I1ii11iIi11i * Oo0Ooo
  if 59 - 59: Oo0Ooo / I11i - iIii1I11I1II1 * iIii1I11I1II1
 def zero_auth ( self , packet ) :
  if ( self . alg_id == LISP_NONE_ALG_ID ) : return ( packet )
  if ( self . alg_id == LISP_SHA_1_96_ALG_ID ) :
   oooO = struct . pack ( "QQI" , 0 , 0 , 0 )
   if 18 - 18: I11i * I1ii11iIi11i / i11iIiiIii / iIii1I11I1II1 * OoooooooOO . OOooOOo
  if ( self . alg_id == LISP_SHA_256_128_ALG_ID ) :
   oooO = struct . pack ( "QQQQ" , 0 , 0 , 0 , 0 )
   if 69 - 69: Oo0Ooo * ooOoO0o
  packet += oooO
  return ( packet )
  if 91 - 91: o0oOOo0O0Ooo . ooOoO0o / OoO0O00 / i11iIiiIii * o0oOOo0O0Ooo
  if 52 - 52: I1IiiI - i11iIiiIii / IiII . oO0o
 def encode ( self , eid_records , password ) :
  if ( self . map_notify_ack ) :
   iII = ( LISP_MAP_NOTIFY_ACK << 28 ) | self . record_count
  else :
   iII = ( LISP_MAP_NOTIFY << 28 ) | self . record_count
   if 38 - 38: oO0o + OoooooooOO * OoOoOO00 % oO0o
  IiiiIi1iiii11 = struct . pack ( "I" , socket . htonl ( iII ) )
  IiiiIi1iiii11 += struct . pack ( "QBBH" , self . nonce , self . key_id , self . alg_id ,
 socket . htons ( self . auth_len ) )
  if 91 - 91: i1IIi - I1ii11iIi11i * I1IiiI
  if ( self . alg_id == LISP_NONE_ALG_ID ) :
   self . packet = IiiiIi1iiii11 + eid_records
   return ( self . packet )
   if 24 - 24: OoOoOO00 * Ii1I
   if 17 - 17: OoO0O00 . I1IiiI * O0
   if 81 - 81: OOooOOo
   if 58 - 58: II111iiii . I1Ii111 . Ii1I * OoooooooOO / Ii1I / I11i
   if 41 - 41: I11i + OoO0O00 . iII111i
  IiiiIi1iiii11 = self . zero_auth ( IiiiIi1iiii11 )
  IiiiIi1iiii11 += eid_records
  if 73 - 73: i11iIiiIii * I1IiiI + o0oOOo0O0Ooo / oO0o
  IIi1iiIIi1i = lisp_hash_me ( IiiiIi1iiii11 , self . alg_id , password , False )
  if 56 - 56: i1IIi
  OoO00oo00 = struct . calcsize ( "I" ) + struct . calcsize ( "QHH" )
  II111iiI1Ii1 = self . auth_len
  self . auth_data = IIi1iiIIi1i
  IiiiIi1iiii11 = IiiiIi1iiii11 [ 0 : OoO00oo00 ] + IIi1iiIIi1i + IiiiIi1iiii11 [ OoO00oo00 + II111iiI1Ii1 : : ]
  self . packet = IiiiIi1iiii11
  return ( IiiiIi1iiii11 )
  if 11 - 11: i11iIiiIii % o0oOOo0O0Ooo / I11i * OoooooooOO
  if 82 - 82: IiII
 def decode ( self , packet ) :
  OoO = packet
  i1I1iii1I11II = "I"
  Iiiii = struct . calcsize ( i1I1iii1I11II )
  if ( len ( packet ) < Iiiii ) : return ( None )
  if 10 - 10: Oo0Ooo % OOooOOo / I11i * IiII - o0oOOo0O0Ooo
  iII = struct . unpack ( i1I1iii1I11II , packet [ : Iiiii ] )
  iII = socket . ntohl ( iII [ 0 ] )
  self . map_notify_ack = ( ( iII >> 28 ) == LISP_MAP_NOTIFY_ACK )
  self . record_count = iII & 0xff
  packet = packet [ Iiiii : : ]
  if 54 - 54: i11iIiiIii / iIii1I11I1II1 % I1ii11iIi11i / I1IiiI . iIii1I11I1II1 / iII111i
  i1I1iii1I11II = "QBBH"
  Iiiii = struct . calcsize ( i1I1iii1I11II )
  if ( len ( packet ) < Iiiii ) : return ( None )
  if 1 - 1: I1Ii111 / OoOoOO00 * OoOoOO00 - o0oOOo0O0Ooo % Ii1I
  self . nonce , self . key_id , self . alg_id , self . auth_len = struct . unpack ( i1I1iii1I11II , packet [ : Iiiii ] )
  if 96 - 96: IiII / Ii1I % OoO0O00 . iIii1I11I1II1
  self . nonce_key = lisp_hex_string ( self . nonce )
  self . auth_len = socket . ntohs ( self . auth_len )
  packet = packet [ Iiiii : : ]
  self . eid_records = packet [ self . auth_len : : ]
  if 30 - 30: I11i - OoO0O00
  if ( self . auth_len == 0 ) : return ( self . eid_records )
  if 15 - 15: OoooooooOO
  if 31 - 31: II111iiii
  if 62 - 62: iIii1I11I1II1 % I1Ii111 % I1ii11iIi11i * IiII
  if 87 - 87: IiII
  if ( len ( packet ) < self . auth_len ) : return ( None )
  if 45 - 45: oO0o + II111iiii * O0 % OOooOOo . iIii1I11I1II1
  II111iiI1Ii1 = self . auth_len
  if ( self . alg_id == LISP_SHA_1_96_ALG_ID ) :
   I1IiiIiIIi1Ii , oo00oo , OOOO0oO0OOo0o = struct . unpack ( "QQI" , packet [ : II111iiI1Ii1 ] )
   OoOO = ""
   if 55 - 55: IiII
  if ( self . alg_id == LISP_SHA_256_128_ALG_ID ) :
   I1IiiIiIIi1Ii , oo00oo , OOOO0oO0OOo0o , OoOO = struct . unpack ( "QQQQ" ,
 packet [ : II111iiI1Ii1 ] )
   if 43 - 43: OOooOOo
  self . auth_data = lisp_concat_auth_data ( self . alg_id , I1IiiIiIIi1Ii , oo00oo ,
 OOOO0oO0OOo0o , OoOO )
  if 17 - 17: i11iIiiIii
  Iiiii = struct . calcsize ( "I" ) + struct . calcsize ( "QHH" )
  packet = self . zero_auth ( OoO [ : Iiiii ] )
  Iiiii += II111iiI1Ii1
  packet += OoO [ Iiiii : : ]
  return ( packet )
  if 94 - 94: OoooooooOO - IiII + oO0o . OoooooooOO / i1IIi
  if 53 - 53: I1Ii111 % I1ii11iIi11i
  if 17 - 17: OoooooooOO % Ii1I % O0
  if 46 - 46: iII111i + I1Ii111 % OoooooooOO * I1ii11iIi11i
  if 89 - 89: IiII - IiII % iII111i / I11i + oO0o - IiII
  if 97 - 97: Ii1I % OoOoOO00 / I1ii11iIi11i / iIii1I11I1II1 * OoooooooOO * OOooOOo
  if 80 - 80: oO0o / O0
  if 55 - 55: I1IiiI * I11i / O0 % OoOoOO00
  if 71 - 71: i11iIiiIii * OoOoOO00 * OOooOOo + oO0o + Oo0Ooo
  if 59 - 59: IiII
  if 54 - 54: OOooOOo
  if 27 - 27: OoOoOO00 - OoO0O00 + o0oOOo0O0Ooo + ooOoO0o . OoO0O00
  if 86 - 86: II111iiii - OoooooooOO - ooOoO0o % iII111i
  if 16 - 16: ooOoO0o + Oo0Ooo + OoooooooOO
  if 87 - 87: I1IiiI . oO0o / IiII - OoooooooOO
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
  if 47 - 47: iII111i / OoooooooOO - II111iiii
  if 91 - 91: OoOoOO00 + o0oOOo0O0Ooo
  if 23 - 23: i1IIi
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
  self . json_telemetry = None
  if 9 - 9: i1IIi % I1Ii111 - OoO0O00 * OoOoOO00 . o0oOOo0O0Ooo
  if 18 - 18: Ii1I . OoOoOO00 + iII111i . I1IiiI + OoooooooOO . OoO0O00
 def print_prefix ( self ) :
  if ( self . target_group . is_null ( ) ) :
   return ( green ( self . target_eid . print_prefix ( ) , False ) )
   if 31 - 31: I1Ii111 - I11i
  return ( green ( self . target_eid . print_sg ( self . target_group ) , False ) )
  if 49 - 49: iIii1I11I1II1 - iIii1I11I1II1 - OoOoOO00 + IiII / OoOoOO00
  if 74 - 74: OoooooooOO + I1ii11iIi11i % O0
 def print_map_request ( self ) :
  I1II = ""
  if ( self . xtr_id != None and self . subscribe_bit ) :
   I1II = "subscribe, xtr-id: 0x{}, " . format ( lisp_hex_string ( self . xtr_id ) )
   if 32 - 32: I1ii11iIi11i + I1ii11iIi11i
   if 89 - 89: ooOoO0o + oO0o + Ii1I - OOooOOo
   if 12 - 12: OoOoOO00 - o0oOOo0O0Ooo - I1Ii111 / I11i
  oOOo0ooO0 = ( "{} -> flags: {}{}{}{}{}{}{}{}{}{}, itr-rloc-" +
 "count: {} (+1), record-count: {}, nonce: 0x{}, source-eid: " +
 "afi {}, {}{}, target-eid: afi {}, {}, {}ITR-RLOCs:" )
  if 17 - 17: OoO0O00 - I1Ii111 - II111iiii / I1Ii111 / Ii1I
  lprint ( oOOo0ooO0 . format ( bold ( "Map-Request" , False ) , "A" if self . auth_bit else "a" ,
  # I1Ii111 % OOooOOo
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
 self . target_eid . afi , green ( self . print_prefix ( ) , False ) , I1II ) )
  if 73 - 73: I1ii11iIi11i + iII111i * I1IiiI * I11i
  iIi11III = self . keys
  for I11iiII1I1111 in self . itr_rlocs :
   if ( I11iiII1I1111 . afi == LISP_AFI_LCAF and self . json_telemetry != None ) :
    continue
    if 30 - 30: I1Ii111 - O0 + I1IiiI . I1ii11iIi11i
   I111iI1IIIi1I = red ( I11iiII1I1111 . print_address_no_iid ( ) , False )
   lprint ( "  itr-rloc: afi {} {}{}" . format ( I11iiII1I1111 . afi , I111iI1IIIi1I ,
 "" if ( iIi11III == None ) else ", " + iIi11III [ 1 ] . print_keys ( ) ) )
   iIi11III = None
   if 21 - 21: iII111i % O0 . ooOoO0o / OoOoOO00
  if ( self . json_telemetry != None ) :
   lprint ( "  itr-rloc: afi {} telemetry: {}" . format ( LISP_AFI_LCAF ,
 self . json_telemetry ) )
   if 54 - 54: I1ii11iIi11i * IiII
   if 3 - 3: IiII - I1ii11iIi11i * iII111i * I1ii11iIi11i + Oo0Ooo
   if 15 - 15: I1ii11iIi11i * Ii1I / iII111i . o0oOOo0O0Ooo / Ii1I % OoOoOO00
 def sign_map_request ( self , privkey ) :
  Oo0o0ooOo0 = self . signature_eid . print_address ( )
  OoOoo0ooO0000 = self . source_eid . print_address ( )
  ii1iiI11III1 = self . target_eid . print_address ( )
  IIIiiI1I = lisp_hex_string ( self . nonce ) + OoOoo0ooO0000 + ii1iiI11III1
  self . map_request_signature = privkey . sign ( IIIiiI1I )
  O0OO0OoO00oOo = binascii . b2a_base64 ( self . map_request_signature )
  O0OO0OoO00oOo = { "source-eid" : OoOoo0ooO0000 , "signature-eid" : Oo0o0ooOo0 ,
 "signature" : O0OO0OoO00oOo }
  return ( json . dumps ( O0OO0OoO00oOo ) )
  if 35 - 35: II111iiii . OOooOOo + iIii1I11I1II1 . i1IIi - OoOoOO00 + IiII
  if 55 - 55: Oo0Ooo % I1Ii111 . II111iiii
 def verify_map_request_sig ( self , pubkey ) :
  oo0Oo = green ( self . signature_eid . print_address ( ) , False )
  if ( pubkey == None ) :
   lprint ( "Public-key not found for signature-EID {}" . format ( oo0Oo ) )
   return ( False )
   if 11 - 11: I1Ii111 + i1IIi - iII111i - OoO0O00 * ooOoO0o / ooOoO0o
   if 4 - 4: iIii1I11I1II1 - i11iIiiIii * OoO0O00 . I1Ii111 + o0oOOo0O0Ooo
  OoOoo0ooO0000 = self . source_eid . print_address ( )
  ii1iiI11III1 = self . target_eid . print_address ( )
  IIIiiI1I = lisp_hex_string ( self . nonce ) + OoOoo0ooO0000 + ii1iiI11III1
  pubkey = binascii . a2b_base64 ( pubkey )
  if 11 - 11: OoOoOO00 % I1ii11iIi11i - Ii1I - I1Ii111
  OO = True
  try :
   Oo000O000 = ecdsa . VerifyingKey . from_pem ( pubkey )
  except :
   lprint ( "Invalid public-key in mapping system for sig-eid {}" . format ( self . signature_eid . print_address_no_iid ( ) ) )
   if 27 - 27: IiII * OOooOOo - OoooooooOO . Ii1I - II111iiii
   OO = False
   if 62 - 62: I1IiiI / iIii1I11I1II1 * I11i
   if 84 - 84: IiII - OoOoOO00 . IiII + ooOoO0o . iII111i
  if ( OO ) :
   try :
    OO = Oo000O000 . verify ( self . map_request_signature , IIIiiI1I )
   except :
    OO = False
    if 96 - 96: Ii1I % iII111i * Ii1I % I1IiiI . o0oOOo0O0Ooo / o0oOOo0O0Ooo
    if 7 - 7: OoO0O00 - ooOoO0o % i1IIi
    if 24 - 24: OoO0O00 % O0 % I11i
  O0o = bold ( "passed" if OO else "failed" , False )
  lprint ( "Signature verification {} for EID {}" . format ( O0o , oo0Oo ) )
  return ( OO )
  if 83 - 83: OoooooooOO * iIii1I11I1II1 . OoooooooOO / II111iiii . OoooooooOO - IiII
  if 90 - 90: Oo0Ooo % i11iIiiIii + O0 % O0
 def encode_json ( self , json_string ) :
  iI1IIiI111iII = LISP_LCAF_JSON_TYPE
  OoOoO00OoOOo = socket . htons ( LISP_AFI_LCAF )
  oOOO0O000Oo = socket . htons ( len ( json_string ) + 2 )
  iiiii1I = socket . htons ( len ( json_string ) )
  IiiiIi1iiii11 = struct . pack ( "HBBBBHH" , OoOoO00OoOOo , 0 , 0 , iI1IIiI111iII , 0 , oOOO0O000Oo ,
 iiiii1I )
  IiiiIi1iiii11 += json_string
  IiiiIi1iiii11 += struct . pack ( "H" , 0 )
  return ( IiiiIi1iiii11 )
  if 22 - 22: iII111i . OoooooooOO . Oo0Ooo
  if 44 - 44: OoOoOO00 / Oo0Ooo . OoooooooOO % OoooooooOO * i11iIiiIii
 def encode ( self , probe_dest , probe_port ) :
  iII = ( LISP_MAP_REQUEST << 28 ) | self . record_count
  if 60 - 60: IiII / iIii1I11I1II1 + OoooooooOO - I1ii11iIi11i * i11iIiiIii
  Iii1iIIi1iIii = lisp_telemetry_configured ( ) if ( self . rloc_probe ) else None
  if ( Iii1iIIi1iIii != None ) : self . itr_rloc_count += 1
  iII = iII | ( self . itr_rloc_count << 8 )
  if 55 - 55: o0oOOo0O0Ooo . OOooOOo * OoOoOO00
  if ( self . auth_bit ) : iII |= 0x08000000
  if ( self . map_data_present ) : iII |= 0x04000000
  if ( self . rloc_probe ) : iII |= 0x02000000
  if ( self . smr_bit ) : iII |= 0x01000000
  if ( self . pitr_bit ) : iII |= 0x00800000
  if ( self . smr_invoked_bit ) : iII |= 0x00400000
  if ( self . mobile_node ) : iII |= 0x00200000
  if ( self . xtr_id_present ) : iII |= 0x00100000
  if ( self . local_xtr ) : iII |= 0x00004000
  if ( self . dont_reply_bit ) : iII |= 0x00002000
  if 19 - 19: iII111i
  IiiiIi1iiii11 = struct . pack ( "I" , socket . htonl ( iII ) )
  IiiiIi1iiii11 += struct . pack ( "Q" , self . nonce )
  if 32 - 32: I11i % ooOoO0o % OoooooooOO . ooOoO0o % i11iIiiIii + II111iiii
  if 25 - 25: ooOoO0o
  if 83 - 83: Ii1I / OoooooooOO * oO0o . I1IiiI . i1IIi
  if 59 - 59: I11i . I11i * I1IiiI - Ii1I % OoOoOO00
  if 19 - 19: OoooooooOO / Oo0Ooo - I1Ii111 . OoOoOO00
  if 8 - 8: I11i % ooOoO0o . iIii1I11I1II1
  OOoooO = False
  I1i1II1i = self . privkey_filename
  if ( I1i1II1i != None and os . path . exists ( I1i1II1i ) ) :
   OOO000 = open ( I1i1II1i , "r" ) ; Oo000O000 = OOO000 . read ( ) ; OOO000 . close ( )
   try :
    Oo000O000 = ecdsa . SigningKey . from_pem ( Oo000O000 )
   except :
    return ( None )
    if 13 - 13: I1Ii111 * II111iiii - OoOoOO00
   II11iii = self . sign_map_request ( Oo000O000 )
   OOoooO = True
  elif ( self . map_request_signature != None ) :
   O0OO0OoO00oOo = binascii . b2a_base64 ( self . map_request_signature )
   II11iii = { "source-eid" : self . source_eid . print_address ( ) ,
 "signature-eid" : self . signature_eid . print_address ( ) ,
 "signature" : O0OO0OoO00oOo }
   II11iii = json . dumps ( II11iii )
   OOoooO = True
   if 85 - 85: OoO0O00
  if ( OOoooO ) :
   IiiiIi1iiii11 += self . encode_json ( II11iii )
  else :
   if ( self . source_eid . instance_id != 0 ) :
    IiiiIi1iiii11 += struct . pack ( "H" , socket . htons ( LISP_AFI_LCAF ) )
    IiiiIi1iiii11 += self . source_eid . lcaf_encode_iid ( )
   else :
    IiiiIi1iiii11 += struct . pack ( "H" , socket . htons ( self . source_eid . afi ) )
    IiiiIi1iiii11 += self . source_eid . pack_address ( )
    if 5 - 5: Ii1I % Ii1I * I1Ii111
    if 21 - 21: iIii1I11I1II1 % I1IiiI / o0oOOo0O0Ooo / o0oOOo0O0Ooo
    if 28 - 28: OoooooooOO . ooOoO0o / II111iiii + I11i / O0 . OoooooooOO
    if 75 - 75: iIii1I11I1II1 * I1Ii111 . i11iIiiIii
    if 21 - 21: i11iIiiIii . o0oOOo0O0Ooo
    if 25 - 25: OoO0O00 % i1IIi
    if 12 - 12: o0oOOo0O0Ooo
  if ( probe_dest ) :
   if ( probe_port == 0 ) : probe_port = LISP_DATA_PORT
   oo0o00OO = probe_dest . print_address_no_iid ( ) + ":" + str ( probe_port )
   if 58 - 58: iIii1I11I1II1 * Ii1I . ooOoO0o . Oo0Ooo * Ii1I
   if ( lisp_crypto_keys_by_rloc_encap . has_key ( oo0o00OO ) ) :
    self . keys = lisp_crypto_keys_by_rloc_encap [ oo0o00OO ]
    if 63 - 63: OoOoOO00 . I11i * o0oOOo0O0Ooo - I11i % I11i
    if 62 - 62: I11i - ooOoO0o / ooOoO0o
    if 95 - 95: OoOoOO00 - i1IIi / I1Ii111 . ooOoO0o % OOooOOo - i1IIi
    if 12 - 12: iII111i
    if 96 - 96: O0
    if 89 - 89: I1ii11iIi11i - Oo0Ooo
    if 26 - 26: ooOoO0o % ooOoO0o / II111iiii / iII111i
  for I11iiII1I1111 in self . itr_rlocs :
   if ( lisp_data_plane_security and self . itr_rlocs . index ( I11iiII1I1111 ) == 0 ) :
    if ( self . keys == None or self . keys [ 1 ] == None ) :
     iIi11III = lisp_keys ( 1 )
     self . keys = [ None , iIi11III , None , None ]
     if 2 - 2: i1IIi / i11iIiiIii + I1IiiI
    iIi11III = self . keys [ 1 ]
    iIi11III . add_key_by_nonce ( self . nonce )
    IiiiIi1iiii11 += iIi11III . encode_lcaf ( I11iiII1I1111 )
   else :
    IiiiIi1iiii11 += struct . pack ( "H" , socket . htons ( I11iiII1I1111 . afi ) )
    IiiiIi1iiii11 += I11iiII1I1111 . pack_address ( )
    if 95 - 95: I1ii11iIi11i / IiII % iIii1I11I1II1 + O0
    if 6 - 6: IiII
    if 73 - 73: o0oOOo0O0Ooo % o0oOOo0O0Ooo . OOooOOo * I1ii11iIi11i - Ii1I
    if 97 - 97: IiII
    if 15 - 15: O0 - I1IiiI / i1IIi . I1Ii111
    if 64 - 64: ooOoO0o / i1IIi
  if ( Iii1iIIi1iIii != None ) :
   i1 = str ( time . time ( ) )
   Iii1iIIi1iIii = lisp_encode_telemetry ( Iii1iIIi1iIii , io = i1 )
   self . json_telemetry = Iii1iIIi1iIii
   IiiiIi1iiii11 += self . encode_json ( Iii1iIIi1iIii )
   if 100 - 100: II111iiii
   if 16 - 16: Ii1I
  OO00O = 0 if self . target_eid . is_binary ( ) == False else self . target_eid . mask_len
  if 79 - 79: i11iIiiIii + IiII - i11iIiiIii . OoooooooOO + OoO0O00 . i11iIiiIii
  if 9 - 9: OoOoOO00 - I11i . OoooooooOO % ooOoO0o
  IIIiIiIIII1i1 = 0
  if ( self . subscribe_bit ) :
   IIIiIiIIII1i1 = 0x80
   self . xtr_id_present = True
   if ( self . xtr_id == None ) :
    self . xtr_id = random . randint ( 0 , ( 2 ** 128 ) - 1 )
    if 90 - 90: I1IiiI % ooOoO0o % OoooooooOO / OoO0O00 . IiII * II111iiii
    if 83 - 83: oO0o
    if 34 - 34: OoOoOO00
  i1I1iii1I11II = "BB"
  IiiiIi1iiii11 += struct . pack ( i1I1iii1I11II , IIIiIiIIII1i1 , OO00O )
  if 75 - 75: I11i / iIii1I11I1II1 + I1ii11iIi11i / OoO0O00
  if ( self . target_group . is_null ( ) == False ) :
   IiiiIi1iiii11 += struct . pack ( "H" , socket . htons ( LISP_AFI_LCAF ) )
   IiiiIi1iiii11 += self . target_eid . lcaf_encode_sg ( self . target_group )
  elif ( self . target_eid . instance_id != 0 or
 self . target_eid . is_geo_prefix ( ) ) :
   IiiiIi1iiii11 += struct . pack ( "H" , socket . htons ( LISP_AFI_LCAF ) )
   IiiiIi1iiii11 += self . target_eid . lcaf_encode_iid ( )
  else :
   IiiiIi1iiii11 += struct . pack ( "H" , socket . htons ( self . target_eid . afi ) )
   IiiiIi1iiii11 += self . target_eid . pack_address ( )
   if 50 - 50: I1Ii111 / I11i % iIii1I11I1II1
   if 46 - 46: ooOoO0o + iII111i - Oo0Ooo % OOooOOo + OoooooooOO + iIii1I11I1II1
   if 99 - 99: OoO0O00 - IiII * IiII + oO0o / iII111i + OOooOOo
   if 58 - 58: i11iIiiIii + iIii1I11I1II1 * o0oOOo0O0Ooo - OoOoOO00
   if 31 - 31: i1IIi
  if ( self . subscribe_bit ) : IiiiIi1iiii11 = self . encode_xtr_id ( IiiiIi1iiii11 )
  return ( IiiiIi1iiii11 )
  if 87 - 87: I1IiiI / I11i + OoooooooOO + O0 . Ii1I
  if 44 - 44: Oo0Ooo % Oo0Ooo
 def lcaf_decode_json ( self , packet ) :
  i1I1iii1I11II = "BBBBHH"
  Iiiii = struct . calcsize ( i1I1iii1I11II )
  if ( len ( packet ) < Iiiii ) : return ( None )
  if 58 - 58: OOooOOo * II111iiii
  Ii1IiIIIi1i , II111Ii1I1I , iI1IIiI111iII , o00oo0oOo0o0 , oOOO0O000Oo , iiiii1I = struct . unpack ( i1I1iii1I11II , packet [ : Iiiii ] )
  if 12 - 12: I11i / i11iIiiIii - I1Ii111
  if 50 - 50: I11i
  if ( iI1IIiI111iII != LISP_LCAF_JSON_TYPE ) : return ( packet )
  if 88 - 88: i1IIi * OOooOOo . iIii1I11I1II1
  if 45 - 45: I1Ii111 - O0 . I1Ii111 / I1Ii111 / OoOoOO00
  if 12 - 12: OOooOOo
  if 75 - 75: OOooOOo + Ii1I + oO0o . Oo0Ooo
  oOOO0O000Oo = socket . ntohs ( oOOO0O000Oo )
  iiiii1I = socket . ntohs ( iiiii1I )
  packet = packet [ Iiiii : : ]
  if ( len ( packet ) < oOOO0O000Oo ) : return ( None )
  if ( oOOO0O000Oo != iiiii1I + 2 ) : return ( None )
  if 93 - 93: OOooOOo * Ii1I - o0oOOo0O0Ooo . oO0o . iII111i
  if 64 - 64: Oo0Ooo / iIii1I11I1II1 . OoO0O00 / o0oOOo0O0Ooo / I11i
  if 3 - 3: OOooOOo - o0oOOo0O0Ooo * iIii1I11I1II1 . Ii1I + OoOoOO00 % I1Ii111
  if 11 - 11: OOooOOo
  II11iii = packet [ 0 : iiiii1I ]
  packet = packet [ iiiii1I : : ]
  if 12 - 12: OoooooooOO * OOooOOo * I1ii11iIi11i * ooOoO0o
  if 26 - 26: OoooooooOO . i1IIi + OoO0O00
  if 42 - 42: i11iIiiIii * o0oOOo0O0Ooo % I11i % Oo0Ooo + o0oOOo0O0Ooo * i11iIiiIii
  if 66 - 66: Ii1I / IiII . OoooooooOO * Oo0Ooo % i11iIiiIii
  if ( lisp_is_json_telemetry ( II11iii ) != None ) :
   self . json_telemetry = II11iii
   if 100 - 100: I1ii11iIi11i % II111iiii * i11iIiiIii - iII111i
   if 69 - 69: OOooOOo + iII111i / I1Ii111
   if 37 - 37: iIii1I11I1II1 * I11i / IiII * Oo0Ooo % i11iIiiIii
   if 93 - 93: ooOoO0o + ooOoO0o
   if 65 - 65: OoooooooOO * I11i * oO0o % I1ii11iIi11i * II111iiii
  i1I1iii1I11II = "H"
  Iiiii = struct . calcsize ( i1I1iii1I11II )
  O0ooo0 = struct . unpack ( i1I1iii1I11II , packet [ : Iiiii ] ) [ 0 ]
  packet = packet [ Iiiii : : ]
  if ( O0ooo0 != 0 ) : return ( packet )
  if 86 - 86: i11iIiiIii / I11i * iII111i - iII111i
  if ( self . json_telemetry != None ) : return ( packet )
  if 32 - 32: Oo0Ooo . O0
  if 48 - 48: I1ii11iIi11i % II111iiii + I11i
  if 25 - 25: IiII * o0oOOo0O0Ooo / I1IiiI . IiII % II111iiii
  if 50 - 50: OoOoOO00 * iII111i
  try :
   II11iii = json . loads ( II11iii )
  except :
   return ( None )
   if 59 - 59: I1IiiI * I1IiiI / I11i
   if 92 - 92: o0oOOo0O0Ooo
   if 8 - 8: iII111i + I1ii11iIi11i . Ii1I
   if 50 - 50: Oo0Ooo
   if 16 - 16: Ii1I - OoOoOO00 % Oo0Ooo / Ii1I . I11i + ooOoO0o
  if ( II11iii . has_key ( "source-eid" ) == False ) : return ( packet )
  ooOOoo0 = II11iii [ "source-eid" ]
  O0ooo0 = LISP_AFI_IPV4 if ooOOoo0 . count ( "." ) == 3 else LISP_AFI_IPV6 if ooOOoo0 . count ( ":" ) == 7 else None
  if 47 - 47: Ii1I % ooOoO0o + Ii1I
  if ( O0ooo0 == None ) :
   lprint ( "Bad JSON 'source-eid' value: {}" . format ( ooOOoo0 ) )
   return ( None )
   if 49 - 49: OoOoOO00 / i1IIi / OoooooooOO . iII111i + iII111i
   if 51 - 51: OoooooooOO + i11iIiiIii
  self . source_eid . afi = O0ooo0
  self . source_eid . store_address ( ooOOoo0 )
  if 57 - 57: Oo0Ooo % o0oOOo0O0Ooo
  if ( II11iii . has_key ( "signature-eid" ) == False ) : return ( packet )
  ooOOoo0 = II11iii [ "signature-eid" ]
  if ( ooOOoo0 . count ( ":" ) != 7 ) :
   lprint ( "Bad JSON 'signature-eid' value: {}" . format ( ooOOoo0 ) )
   return ( None )
   if 99 - 99: o0oOOo0O0Ooo / i11iIiiIii / II111iiii + OOooOOo . i1IIi + OoOoOO00
   if 7 - 7: I1IiiI / ooOoO0o % OoO0O00 + oO0o . o0oOOo0O0Ooo / I11i
  self . signature_eid . afi = LISP_AFI_IPV6
  self . signature_eid . store_address ( ooOOoo0 )
  if 84 - 84: OOooOOo + II111iiii . o0oOOo0O0Ooo * Oo0Ooo
  if ( II11iii . has_key ( "signature" ) == False ) : return ( packet )
  O0OO0OoO00oOo = binascii . a2b_base64 ( II11iii [ "signature" ] )
  self . map_request_signature = O0OO0OoO00oOo
  return ( packet )
  if 68 - 68: Ii1I % Ii1I
  if 26 - 26: o0oOOo0O0Ooo . Ii1I * OoOoOO00
 def decode ( self , packet , source , port ) :
  i1I1iii1I11II = "I"
  Iiiii = struct . calcsize ( i1I1iii1I11II )
  if ( len ( packet ) < Iiiii ) : return ( None )
  if 58 - 58: I1IiiI * OoO0O00 * i11iIiiIii / OOooOOo / I1IiiI
  iII = struct . unpack ( i1I1iii1I11II , packet [ : Iiiii ] )
  iII = iII [ 0 ]
  packet = packet [ Iiiii : : ]
  if 46 - 46: IiII - I1IiiI + OoO0O00 / I11i . i11iIiiIii
  i1I1iii1I11II = "Q"
  Iiiii = struct . calcsize ( i1I1iii1I11II )
  if ( len ( packet ) < Iiiii ) : return ( None )
  if 84 - 84: OoooooooOO . OoO0O00 / OoOoOO00 * i1IIi
  Iii11I = struct . unpack ( i1I1iii1I11II , packet [ : Iiiii ] )
  packet = packet [ Iiiii : : ]
  if 6 - 6: iIii1I11I1II1 * iIii1I11I1II1
  iII = socket . ntohl ( iII )
  self . auth_bit = True if ( iII & 0x08000000 ) else False
  self . map_data_present = True if ( iII & 0x04000000 ) else False
  self . rloc_probe = True if ( iII & 0x02000000 ) else False
  self . smr_bit = True if ( iII & 0x01000000 ) else False
  self . pitr_bit = True if ( iII & 0x00800000 ) else False
  self . smr_invoked_bit = True if ( iII & 0x00400000 ) else False
  self . mobile_node = True if ( iII & 0x00200000 ) else False
  self . xtr_id_present = True if ( iII & 0x00100000 ) else False
  self . local_xtr = True if ( iII & 0x00004000 ) else False
  self . dont_reply_bit = True if ( iII & 0x00002000 ) else False
  self . itr_rloc_count = ( ( iII >> 8 ) & 0x1f )
  self . record_count = iII & 0xff
  self . nonce = Iii11I [ 0 ]
  if 77 - 77: OOooOOo % oO0o + iIii1I11I1II1 * Ii1I . IiII . Oo0Ooo
  if 29 - 29: I1ii11iIi11i + OoooooooOO . OoO0O00 . i1IIi - OoooooooOO * i11iIiiIii
  if 19 - 19: I1ii11iIi11i * O0 - ooOoO0o
  if 27 - 27: iII111i / o0oOOo0O0Ooo . OoOoOO00 * Ii1I * I1Ii111
  if ( self . xtr_id_present ) :
   if ( self . decode_xtr_id ( packet ) == False ) : return ( None )
   if 81 - 81: I1Ii111
   if 45 - 45: OOooOOo * II111iiii * OoooooooOO / OoooooooOO * I1Ii111
  Iiiii = struct . calcsize ( "H" )
  if ( len ( packet ) < Iiiii ) : return ( None )
  if 38 - 38: iII111i . OoooooooOO
  O0ooo0 = struct . unpack ( "H" , packet [ : Iiiii ] )
  self . source_eid . afi = socket . ntohs ( O0ooo0 [ 0 ] )
  packet = packet [ Iiiii : : ]
  if 28 - 28: I1Ii111 * i1IIi . I1ii11iIi11i
  if ( self . source_eid . afi == LISP_AFI_LCAF ) :
   Oo0OO = packet
   packet = self . source_eid . lcaf_decode_iid ( packet )
   if ( packet == None ) :
    packet = self . lcaf_decode_json ( Oo0OO )
    if ( packet == None ) : return ( None )
    if 99 - 99: i1IIi % oO0o
  elif ( self . source_eid . afi != LISP_AFI_NONE ) :
   packet = self . source_eid . unpack_address ( packet )
   if ( packet == None ) : return ( None )
   if 13 - 13: OoOoOO00 * O0 - iIii1I11I1II1 * I1IiiI + i11iIiiIii
  self . source_eid . mask_len = self . source_eid . host_mask_len ( )
  if 98 - 98: iIii1I11I1II1 + OoO0O00 + I1IiiI + OoooooooOO
  O0Oo0 = ( os . getenv ( "LISP_NO_CRYPTO" ) != None )
  self . itr_rlocs = [ ]
  oOOoo0000o = self . itr_rloc_count + 1
  if 5 - 5: I11i
  while ( oOOoo0000o != 0 ) :
   Iiiii = struct . calcsize ( "H" )
   if ( len ( packet ) < Iiiii ) : return ( None )
   if 11 - 11: I1ii11iIi11i * Ii1I . Ii1I * IiII * i11iIiiIii / II111iiii
   O0ooo0 = socket . ntohs ( struct . unpack ( "H" , packet [ : Iiiii ] ) [ 0 ] )
   I11iiII1I1111 = lisp_address ( LISP_AFI_NONE , "" , 32 , 0 )
   I11iiII1I1111 . afi = O0ooo0
   if 58 - 58: i1IIi
   if 90 - 90: i1IIi / OoooooooOO . Oo0Ooo
   if 5 - 5: iII111i * ooOoO0o + IiII . I1IiiI / I1IiiI
   if 72 - 72: OoO0O00 / I1ii11iIi11i - OOooOOo - OoooooooOO / OoooooooOO % OoooooooOO
   if 85 - 85: OoO0O00 . o0oOOo0O0Ooo . I1IiiI
   if ( I11iiII1I1111 . afi == LISP_AFI_LCAF ) :
    OoO = packet
    Oo000o0o0 = packet [ Iiiii : : ]
    packet = self . lcaf_decode_json ( Oo000o0o0 )
    if ( packet == Oo000o0o0 ) : packet = OoO
    if 76 - 76: oO0o * ooOoO0o - iIii1I11I1II1
    if 25 - 25: OoOoOO00 / Oo0Ooo / OoooooooOO
    if 91 - 91: IiII - I1ii11iIi11i - I1Ii111
    if 35 - 35: iIii1I11I1II1 . O0 + OoOoOO00 / OoO0O00 / IiII * II111iiii
    if 32 - 32: I1Ii111 - iIii1I11I1II1 / I11i * OoO0O00 * OoO0O00
    if 77 - 77: I1ii11iIi11i
   if ( I11iiII1I1111 . afi != LISP_AFI_LCAF ) :
    if ( len ( packet ) < I11iiII1I1111 . addr_length ( ) ) : return ( None )
    packet = I11iiII1I1111 . unpack_address ( packet [ Iiiii : : ] )
    if ( packet == None ) : return ( None )
    if 16 - 16: II111iiii - II111iiii * I11i / OOooOOo . IiII
    if ( O0Oo0 ) :
     self . itr_rlocs . append ( I11iiII1I1111 )
     oOOoo0000o -= 1
     continue
     if 36 - 36: I11i / iIii1I11I1II1
     if 59 - 59: i1IIi
    oo0o00OO = lisp_build_crypto_decap_lookup_key ( I11iiII1I1111 , port )
    if 85 - 85: I1Ii111 + iIii1I11I1II1 + ooOoO0o + Oo0Ooo
    if 75 - 75: O0 . I11i - Ii1I / I1Ii111 / I1ii11iIi11i % I11i
    if 97 - 97: OoOoOO00 - OoO0O00
    if 64 - 64: i1IIi / OoooooooOO / I1ii11iIi11i - Oo0Ooo + oO0o
    if 6 - 6: OOooOOo % II111iiii * IiII
    if ( lisp_nat_traversal and I11iiII1I1111 . is_private_address ( ) and source ) : I11iiII1I1111 = source
    if 34 - 34: I11i % iII111i - ooOoO0o - I1IiiI
    I1ioOo = lisp_crypto_keys_by_rloc_decap
    if ( I1ioOo . has_key ( oo0o00OO ) ) : I1ioOo . pop ( oo0o00OO )
    if 31 - 31: IiII % I11i
    if 9 - 9: OoooooooOO / Oo0Ooo / o0oOOo0O0Ooo % Oo0Ooo
    if 80 - 80: Ii1I + OoO0O00 * OoooooooOO - IiII % O0 - I1Ii111
    if 80 - 80: II111iiii / I1ii11iIi11i
    if 60 - 60: OOooOOo - iII111i + iIii1I11I1II1 + II111iiii + iII111i
    if 35 - 35: Oo0Ooo * O0 / oO0o * i1IIi . I11i . O0
    lisp_write_ipc_decap_key ( oo0o00OO , None )
    if 22 - 22: oO0o / II111iiii . OoOoOO00
   elif ( self . json_telemetry == None ) :
    if 9 - 9: i11iIiiIii + ooOoO0o . iIii1I11I1II1 * OoOoOO00
    if 4 - 4: I1Ii111 + iII111i % O0
    if 98 - 98: i1IIi + I1Ii111 - I1ii11iIi11i . OoooooooOO / O0 / iII111i
    if 66 - 66: i1IIi % OoooooooOO * i11iIiiIii + oO0o * O0 / OoO0O00
    OoO = packet
    iI1IiI1 = lisp_keys ( 1 )
    packet = iI1IiI1 . decode_lcaf ( OoO , 0 )
    if 53 - 53: I1Ii111 + IiII . i1IIi
    if ( packet == None ) : return ( None )
    if 26 - 26: i11iIiiIii - II111iiii
    if 43 - 43: I1IiiI
    if 35 - 35: ooOoO0o + OoOoOO00 * OoooooooOO - II111iiii
    if 19 - 19: i1IIi / Ii1I / OoOoOO00 . I1IiiI / Ii1I % o0oOOo0O0Ooo
    iI111I = [ LISP_CS_25519_CBC , LISP_CS_25519_GCM ,
 LISP_CS_25519_CHACHA ]
    if ( iI1IiI1 . cipher_suite in iI111I ) :
     if ( iI1IiI1 . cipher_suite == LISP_CS_25519_CBC or
 iI1IiI1 . cipher_suite == LISP_CS_25519_GCM ) :
      Oo000O000 = lisp_keys ( 1 , do_poly = False , do_chacha = False )
      if 39 - 39: ooOoO0o - OoooooooOO
     if ( iI1IiI1 . cipher_suite == LISP_CS_25519_CHACHA ) :
      Oo000O000 = lisp_keys ( 1 , do_poly = True , do_chacha = True )
      if 88 - 88: i1IIi + iIii1I11I1II1 * i11iIiiIii - OoooooooOO % o0oOOo0O0Ooo
    else :
     Oo000O000 = lisp_keys ( 1 , do_poly = False , do_curve = False ,
 do_chacha = False )
     if 74 - 74: ooOoO0o - i11iIiiIii
    packet = Oo000O000 . decode_lcaf ( OoO , 0 )
    if ( packet == None ) : return ( None )
    if 34 - 34: IiII + I1Ii111 + Oo0Ooo / II111iiii
    if ( len ( packet ) < Iiiii ) : return ( None )
    O0ooo0 = struct . unpack ( "H" , packet [ : Iiiii ] ) [ 0 ]
    I11iiII1I1111 . afi = socket . ntohs ( O0ooo0 )
    if ( len ( packet ) < I11iiII1I1111 . addr_length ( ) ) : return ( None )
    if 33 - 33: Ii1I . i1IIi - II111iiii - OoO0O00
    packet = I11iiII1I1111 . unpack_address ( packet [ Iiiii : : ] )
    if ( packet == None ) : return ( None )
    if 31 - 31: I11i - OoOoOO00 / o0oOOo0O0Ooo * OoOoOO00 / Oo0Ooo + o0oOOo0O0Ooo
    if ( O0Oo0 ) :
     self . itr_rlocs . append ( I11iiII1I1111 )
     oOOoo0000o -= 1
     continue
     if 46 - 46: IiII * OoO0O00 / OOooOOo + Oo0Ooo
     if 24 - 24: ooOoO0o % OOooOOo . O0 * Oo0Ooo
    oo0o00OO = lisp_build_crypto_decap_lookup_key ( I11iiII1I1111 , port )
    if 52 - 52: O0 . I1Ii111 + iII111i / i11iIiiIii
    oO0OooO0o0 = None
    if ( lisp_nat_traversal and I11iiII1I1111 . is_private_address ( ) and source ) : I11iiII1I1111 = source
    if 23 - 23: OoO0O00 / o0oOOo0O0Ooo
    if 22 - 22: OOooOOo - OoO0O00 . I11i
    if ( lisp_crypto_keys_by_rloc_decap . has_key ( oo0o00OO ) ) :
     iIi11III = lisp_crypto_keys_by_rloc_decap [ oo0o00OO ]
     oO0OooO0o0 = iIi11III [ 1 ] if iIi11III and iIi11III [ 1 ] else None
     if 89 - 89: I1Ii111
     if 19 - 19: IiII + I1Ii111
    O0OOOo000 = True
    if ( oO0OooO0o0 ) :
     if ( oO0OooO0o0 . compare_keys ( Oo000O000 ) ) :
      self . keys = [ None , oO0OooO0o0 , None , None ]
      lprint ( "Maintain stored decap-keys for RLOC {}" . format ( red ( oo0o00OO , False ) ) )
      if 5 - 5: OoO0O00 / iII111i / OOooOOo
     else :
      O0OOOo000 = False
      OOO0o0oo = bold ( "Remote decap-rekeying" , False )
      lprint ( "{} for RLOC {}" . format ( OOO0o0oo , red ( oo0o00OO ,
 False ) ) )
      Oo000O000 . copy_keypair ( oO0OooO0o0 )
      Oo000O000 . uptime = oO0OooO0o0 . uptime
      oO0OooO0o0 = None
      if 68 - 68: iII111i . OOooOOo
      if 6 - 6: Ii1I - o0oOOo0O0Ooo % I11i + i11iIiiIii
      if 40 - 40: O0 . Ii1I
    if ( oO0OooO0o0 == None ) :
     self . keys = [ None , Oo000O000 , None , None ]
     if ( lisp_i_am_etr == False and lisp_i_am_rtr == False ) :
      Oo000O000 . local_public_key = None
      lprint ( "{} for {}" . format ( bold ( "Ignoring decap-keys" ,
 False ) , red ( oo0o00OO , False ) ) )
     elif ( Oo000O000 . remote_public_key != None ) :
      if ( O0OOOo000 ) :
       lprint ( "{} for RLOC {}" . format ( bold ( "New decap-keying" , False ) ,
       # IiII * OoooooooOO . I1ii11iIi11i % Ii1I
 red ( oo0o00OO , False ) ) )
       if 51 - 51: I1ii11iIi11i % OoooooooOO - OoooooooOO . I11i
      Oo000O000 . compute_shared_key ( "decap" )
      Oo000O000 . add_key_by_rloc ( oo0o00OO , False )
      if 97 - 97: i1IIi % I11i . o0oOOo0O0Ooo * I1IiiI % II111iiii
      if 41 - 41: I11i . I1ii11iIi11i
      if 69 - 69: O0 * ooOoO0o % ooOoO0o / oO0o
      if 2 - 2: oO0o % OoO0O00
   self . itr_rlocs . append ( I11iiII1I1111 )
   oOOoo0000o -= 1
   if 3 - 3: oO0o / OoO0O00 % i11iIiiIii
   if 26 - 26: ooOoO0o . I1Ii111 / II111iiii % Ii1I
  Iiiii = struct . calcsize ( "BBH" )
  if ( len ( packet ) < Iiiii ) : return ( None )
  if 82 - 82: OOooOOo % O0 % iIii1I11I1II1 % IiII + i11iIiiIii
  IIIiIiIIII1i1 , OO00O , O0ooo0 = struct . unpack ( "BBH" , packet [ : Iiiii ] )
  self . subscribe_bit = ( IIIiIiIIII1i1 & 0x80 )
  self . target_eid . afi = socket . ntohs ( O0ooo0 )
  packet = packet [ Iiiii : : ]
  if 64 - 64: i1IIi / IiII . IiII - I1Ii111 % OOooOOo . II111iiii
  self . target_eid . mask_len = OO00O
  if ( self . target_eid . afi == LISP_AFI_LCAF ) :
   packet , O0Ooo00oo = self . target_eid . lcaf_decode_eid ( packet )
   if ( packet == None ) : return ( None )
   if ( O0Ooo00oo ) : self . target_group = O0Ooo00oo
  else :
   packet = self . target_eid . unpack_address ( packet )
   if ( packet == None ) : return ( None )
   packet = packet [ Iiiii : : ]
   if 60 - 60: oO0o
  return ( packet )
  if 5 - 5: o0oOOo0O0Ooo / o0oOOo0O0Ooo - ooOoO0o * OoooooooOO . OoooooooOO . I1Ii111
  if 56 - 56: iII111i % I1IiiI * OOooOOo * i11iIiiIii
 def print_eid_tuple ( self ) :
  return ( lisp_print_eid_tuple ( self . target_eid , self . target_group ) )
  if 15 - 15: I1IiiI - oO0o - II111iiii + O0
  if 54 - 54: iIii1I11I1II1 - IiII - IiII
 def encode_xtr_id ( self , packet ) :
  oo0 = self . xtr_id >> 64
  i11Iiiiii11II = self . xtr_id & 0xffffffffffffffff
  oo0 = byte_swap_64 ( oo0 )
  i11Iiiiii11II = byte_swap_64 ( i11Iiiiii11II )
  packet += struct . pack ( "QQ" , oo0 , i11Iiiiii11II )
  return ( packet )
  if 18 - 18: i11iIiiIii + iIii1I11I1II1 . i11iIiiIii
  if 63 - 63: iII111i - OoO0O00 * OOooOOo
 def decode_xtr_id ( self , packet ) :
  Iiiii = struct . calcsize ( "QQ" )
  if ( len ( packet ) < Iiiii ) : return ( None )
  packet = packet [ len ( packet ) - Iiiii : : ]
  oo0 , i11Iiiiii11II = struct . unpack ( "QQ" , packet [ : Iiiii ] )
  oo0 = byte_swap_64 ( oo0 )
  i11Iiiiii11II = byte_swap_64 ( i11Iiiiii11II )
  self . xtr_id = ( oo0 << 64 ) | i11Iiiiii11II
  return ( True )
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
class lisp_map_reply ( ) :
 def __init__ ( self ) :
  self . rloc_probe = False
  self . echo_nonce_capable = False
  self . security = False
  self . record_count = 0
  self . hop_count = 0
  self . nonce = 0
  self . keys = None
  if 45 - 45: II111iiii . OoO0O00 + OoO0O00 * iIii1I11I1II1
  if 23 - 23: IiII * OoOoOO00 % Ii1I / Ii1I - ooOoO0o - OOooOOo
 def print_map_reply ( self ) :
  oOOo0ooO0 = "{} -> flags: {}{}{}, hop-count: {}, record-count: {}, " + "nonce: 0x{}"
  if 86 - 86: OOooOOo . OoooooooOO * I1IiiI - Oo0Ooo / i11iIiiIii * iII111i
  lprint ( oOOo0ooO0 . format ( bold ( "Map-Reply" , False ) , "R" if self . rloc_probe else "r" ,
  # i11iIiiIii + I11i + iII111i % I1IiiI
 "E" if self . echo_nonce_capable else "e" ,
 "S" if self . security else "s" , self . hop_count , self . record_count ,
 lisp_hex_string ( self . nonce ) ) )
  if 84 - 84: oO0o % OOooOOo
  if 25 - 25: i11iIiiIii * OoOoOO00 + i11iIiiIii . i1IIi
 def encode ( self ) :
  iII = ( LISP_MAP_REPLY << 28 ) | self . record_count
  iII |= self . hop_count << 8
  if ( self . rloc_probe ) : iII |= 0x08000000
  if ( self . echo_nonce_capable ) : iII |= 0x04000000
  if ( self . security ) : iII |= 0x02000000
  if 83 - 83: I1IiiI
  IiiiIi1iiii11 = struct . pack ( "I" , socket . htonl ( iII ) )
  IiiiIi1iiii11 += struct . pack ( "Q" , self . nonce )
  return ( IiiiIi1iiii11 )
  if 90 - 90: II111iiii
  if 2 - 2: Ii1I - OoooooooOO - i11iIiiIii % Oo0Ooo / Ii1I
 def decode ( self , packet ) :
  i1I1iii1I11II = "I"
  Iiiii = struct . calcsize ( i1I1iii1I11II )
  if ( len ( packet ) < Iiiii ) : return ( None )
  if 77 - 77: o0oOOo0O0Ooo . o0oOOo0O0Ooo * I1Ii111 + OOooOOo - i11iIiiIii
  iII = struct . unpack ( i1I1iii1I11II , packet [ : Iiiii ] )
  iII = iII [ 0 ]
  packet = packet [ Iiiii : : ]
  if 45 - 45: I1IiiI . I1IiiI - Oo0Ooo * OOooOOo
  i1I1iii1I11II = "Q"
  Iiiii = struct . calcsize ( i1I1iii1I11II )
  if ( len ( packet ) < Iiiii ) : return ( None )
  if 71 - 71: i1IIi / I11i
  Iii11I = struct . unpack ( i1I1iii1I11II , packet [ : Iiiii ] )
  packet = packet [ Iiiii : : ]
  if 14 - 14: OoooooooOO
  iII = socket . ntohl ( iII )
  self . rloc_probe = True if ( iII & 0x08000000 ) else False
  self . echo_nonce_capable = True if ( iII & 0x04000000 ) else False
  self . security = True if ( iII & 0x02000000 ) else False
  self . hop_count = ( iII >> 8 ) & 0xff
  self . record_count = iII & 0xff
  self . nonce = Iii11I [ 0 ]
  if 99 - 99: o0oOOo0O0Ooo * o0oOOo0O0Ooo
  if ( lisp_crypto_keys_by_nonce . has_key ( self . nonce ) ) :
   self . keys = lisp_crypto_keys_by_nonce [ self . nonce ]
   self . keys [ 1 ] . delete_key_by_nonce ( self . nonce )
   if 6 - 6: i11iIiiIii + oO0o % ooOoO0o + i11iIiiIii - OOooOOo
  return ( packet )
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
  if 5 - 5: I11i / OoOoOO00
  if 48 - 48: i1IIi - oO0o . OoooooooOO - OoO0O00 - i1IIi
 def print_prefix ( self ) :
  if ( self . group . is_null ( ) ) :
   return ( green ( self . eid . print_prefix ( ) , False ) )
   if 19 - 19: oO0o % Ii1I + I1ii11iIi11i . II111iiii * i11iIiiIii
  return ( green ( self . eid . print_sg ( self . group ) , False ) )
  if 87 - 87: Ii1I / I1Ii111 % OoOoOO00 * I1ii11iIi11i - OoooooooOO / OoOoOO00
  if 24 - 24: I11i . OOooOOo * i1IIi . I1ii11iIi11i / ooOoO0o / O0
 def print_ttl ( self ) :
  oOoooOOO0o0 = self . record_ttl
  if ( self . record_ttl & 0x80000000 ) :
   oOoooOOO0o0 = str ( self . record_ttl & 0x7fffffff ) + " secs"
  elif ( ( oOoooOOO0o0 % 60 ) == 0 ) :
   oOoooOOO0o0 = str ( oOoooOOO0o0 / 60 ) + " hours"
  else :
   oOoooOOO0o0 = str ( oOoooOOO0o0 ) + " mins"
   if 34 - 34: iII111i . OOooOOo
  return ( oOoooOOO0o0 )
  if 13 - 13: OoO0O00 * OOooOOo + oO0o
  if 21 - 21: i11iIiiIii . Ii1I % i1IIi * Ii1I . oO0o + Ii1I
 def store_ttl ( self ) :
  oOoooOOO0o0 = self . record_ttl * 60
  if ( self . record_ttl & 0x80000000 ) : oOoooOOO0o0 = self . record_ttl & 0x7fffffff
  return ( oOoooOOO0o0 )
  if 92 - 92: i1IIi + OoO0O00 * I11i
  if 70 - 70: Oo0Ooo
 def print_record ( self , indent , ddt ) :
  O0II = ""
  IIiI = ""
  I1ii1i11I = bold ( "invalid-action" , False )
  if ( ddt ) :
   if ( self . action < len ( lisp_map_referral_action_string ) ) :
    I1ii1i11I = lisp_map_referral_action_string [ self . action ]
    I1ii1i11I = bold ( I1ii1i11I , False )
    O0II = ( ", " + bold ( "ddt-incomplete" , False ) ) if self . ddt_incomplete else ""
    if 76 - 76: OoO0O00 + I1Ii111 + OoO0O00 * OoooooooOO
    IIiI = ( ", sig-count: " + str ( self . signature_count ) ) if ( self . signature_count != 0 ) else ""
    if 85 - 85: iII111i + OOooOOo
    if 36 - 36: OoO0O00 % II111iiii * O0 + II111iiii - oO0o - i1IIi
  else :
   if ( self . action < len ( lisp_map_reply_action_string ) ) :
    I1ii1i11I = lisp_map_reply_action_string [ self . action ]
    if ( self . action != LISP_NO_ACTION ) :
     I1ii1i11I = bold ( I1ii1i11I , False )
     if 53 - 53: Ii1I - OOooOOo
     if 75 - 75: iII111i % O0 - I11i - I1ii11iIi11i + I1IiiI - I1IiiI
     if 87 - 87: i1IIi % Ii1I % i1IIi + iIii1I11I1II1
     if 23 - 23: iIii1I11I1II1 * I11i . I1Ii111 - o0oOOo0O0Ooo
  O0ooo0 = LISP_AFI_LCAF if ( self . eid . afi < 0 ) else self . eid . afi
  oOOo0ooO0 = ( "{}EID-record -> record-ttl: {}, rloc-count: {}, action: " +
 "{}, {}{}{}, map-version: {}, afi: {}, [iid]eid/ml: {}" )
  if 66 - 66: I1IiiI * I1Ii111 / i11iIiiIii / OOooOOo
  lprint ( oOOo0ooO0 . format ( indent , self . print_ttl ( ) , self . rloc_count ,
 I1ii1i11I , "auth" if ( self . authoritative is True ) else "non-auth" ,
 O0II , IIiI , self . map_version , O0ooo0 ,
 green ( self . print_prefix ( ) , False ) ) )
  if 19 - 19: ooOoO0o % iIii1I11I1II1 * OoooooooOO
  if 60 - 60: I1Ii111 * iII111i / OoooooooOO * Oo0Ooo
 def encode ( self ) :
  I11I1iI = self . action << 13
  if ( self . authoritative ) : I11I1iI |= 0x1000
  if ( self . ddt_incomplete ) : I11I1iI |= 0x800
  if 65 - 65: OOooOOo . II111iiii * i11iIiiIii + OOooOOo
  if 99 - 99: I1ii11iIi11i % Oo0Ooo
  if 31 - 31: o0oOOo0O0Ooo - II111iiii * OOooOOo . OOooOOo - oO0o
  if 57 - 57: OOooOOo / i11iIiiIii / I1Ii111 - Oo0Ooo . iIii1I11I1II1
  O0ooo0 = self . eid . afi if ( self . eid . instance_id == 0 ) else LISP_AFI_LCAF
  if ( O0ooo0 < 0 ) : O0ooo0 = LISP_AFI_LCAF
  oOOooo000OoO = ( self . group . is_null ( ) == False )
  if ( oOOooo000OoO ) : O0ooo0 = LISP_AFI_LCAF
  if 93 - 93: Ii1I / OoOoOO00 + ooOoO0o . OoO0O00 / O0 . o0oOOo0O0Ooo
  IIi1II = ( self . signature_count << 12 ) | self . map_version
  OO00O = 0 if self . eid . is_binary ( ) == False else self . eid . mask_len
  if 36 - 36: IiII . IiII
  IiiiIi1iiii11 = struct . pack ( "IBBHHH" , socket . htonl ( self . record_ttl ) ,
 self . rloc_count , OO00O , socket . htons ( I11I1iI ) ,
 socket . htons ( IIi1II ) , socket . htons ( O0ooo0 ) )
  if 27 - 27: OoOoOO00 - iIii1I11I1II1 / i1IIi * I1Ii111 - ooOoO0o
  if 2 - 2: iII111i * I11i * ooOoO0o + i11iIiiIii + oO0o
  if 81 - 81: o0oOOo0O0Ooo * OoO0O00
  if 18 - 18: i11iIiiIii / o0oOOo0O0Ooo - oO0o . I11i * i1IIi
  if ( oOOooo000OoO ) :
   IiiiIi1iiii11 += self . eid . lcaf_encode_sg ( self . group )
   return ( IiiiIi1iiii11 )
   if 67 - 67: Ii1I
   if 64 - 64: OoOoOO00 + iII111i * OoOoOO00 - I1IiiI * OoooooooOO
   if 27 - 27: II111iiii + i11iIiiIii
   if 32 - 32: i1IIi
   if 76 - 76: II111iiii % ooOoO0o - I1ii11iIi11i
  if ( self . eid . afi == LISP_AFI_GEO_COORD and self . eid . instance_id == 0 ) :
   IiiiIi1iiii11 = IiiiIi1iiii11 [ 0 : - 2 ]
   IiiiIi1iiii11 += self . eid . address . encode_geo ( )
   return ( IiiiIi1iiii11 )
   if 50 - 50: II111iiii / I1IiiI . Ii1I % i11iIiiIii
   if 66 - 66: oO0o / OOooOOo / iII111i
   if 5 - 5: I1Ii111 . oO0o
   if 77 - 77: iII111i / i11iIiiIii
   if 20 - 20: O0 . I11i
  if ( O0ooo0 == LISP_AFI_LCAF ) :
   IiiiIi1iiii11 += self . eid . lcaf_encode_iid ( )
   return ( IiiiIi1iiii11 )
   if 67 - 67: OoOoOO00 - ooOoO0o - iIii1I11I1II1
   if 31 - 31: II111iiii + o0oOOo0O0Ooo * i11iIiiIii . o0oOOo0O0Ooo
   if 73 - 73: oO0o / OOooOOo * II111iiii % OoooooooOO - i1IIi - ooOoO0o
   if 43 - 43: o0oOOo0O0Ooo + Ii1I % OoO0O00 . I1Ii111 + i1IIi
   if 85 - 85: Oo0Ooo % I1ii11iIi11i / OOooOOo
  IiiiIi1iiii11 += self . eid . pack_address ( )
  return ( IiiiIi1iiii11 )
  if 65 - 65: ooOoO0o + IiII - OoOoOO00 % II111iiii - iIii1I11I1II1
  if 39 - 39: I1IiiI + I1ii11iIi11i - i11iIiiIii
 def decode ( self , packet ) :
  i1I1iii1I11II = "IBBHHH"
  Iiiii = struct . calcsize ( i1I1iii1I11II )
  if ( len ( packet ) < Iiiii ) : return ( None )
  if 43 - 43: iIii1I11I1II1
  self . record_ttl , self . rloc_count , self . eid . mask_len , I11I1iI , self . map_version , self . eid . afi = struct . unpack ( i1I1iii1I11II , packet [ : Iiiii ] )
  if 73 - 73: OoOoOO00 + o0oOOo0O0Ooo
  if 58 - 58: i1IIi * I1ii11iIi11i % iII111i . OoO0O00 % IiII % I11i
  if 63 - 63: I1ii11iIi11i % ooOoO0o % I1ii11iIi11i
  self . record_ttl = socket . ntohl ( self . record_ttl )
  I11I1iI = socket . ntohs ( I11I1iI )
  self . action = ( I11I1iI >> 13 ) & 0x7
  self . authoritative = True if ( ( I11I1iI >> 12 ) & 1 ) else False
  self . ddt_incomplete = True if ( ( I11I1iI >> 11 ) & 1 ) else False
  self . map_version = socket . ntohs ( self . map_version )
  self . signature_count = self . map_version >> 12
  self . map_version = self . map_version & 0xfff
  self . eid . afi = socket . ntohs ( self . eid . afi )
  self . eid . instance_id = 0
  packet = packet [ Iiiii : : ]
  if 71 - 71: Ii1I
  if 43 - 43: o0oOOo0O0Ooo / ooOoO0o
  if 88 - 88: i11iIiiIii - i1IIi + Oo0Ooo - O0
  if 50 - 50: I1ii11iIi11i
  if ( self . eid . afi == LISP_AFI_LCAF ) :
   packet , IIi1iiIII11 = self . eid . lcaf_decode_eid ( packet )
   if ( IIi1iiIII11 ) : self . group = IIi1iiIII11
   self . group . instance_id = self . eid . instance_id
   return ( packet )
   if 69 - 69: I1ii11iIi11i . OoooooooOO % I1Ii111
   if 79 - 79: I1IiiI - IiII . OoooooooOO - I1ii11iIi11i
  packet = self . eid . unpack_address ( packet )
  return ( packet )
  if 79 - 79: OOooOOo + o0oOOo0O0Ooo % iII111i . oO0o
  if 49 - 49: Ii1I + i11iIiiIii * OoOoOO00 . OoOoOO00 . I1ii11iIi11i . Oo0Ooo
 def print_eid_tuple ( self ) :
  return ( lisp_print_eid_tuple ( self . eid , self . group ) )
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
LISP_UDP_PROTOCOL = 17
LISP_DEFAULT_ECM_TTL = 128
if 86 - 86: I1IiiI % I11i * O0 + i1IIi % I1Ii111
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
  if 97 - 97: II111iiii * OoOoOO00 - I1Ii111 / i11iIiiIii / OoOoOO00
  if 25 - 25: Oo0Ooo / Oo0Ooo
 def print_ecm ( self ) :
  oOOo0ooO0 = ( "{} -> flags: {}{}{}{}, " + "inner IP: {} -> {}, inner UDP: {} -> {}" )
  if 74 - 74: OOooOOo
  lprint ( oOOo0ooO0 . format ( bold ( "ECM" , False ) , "S" if self . security else "s" ,
 "D" if self . ddt else "d" , "E" if self . to_etr else "e" ,
 "M" if self . to_ms else "m" ,
 green ( self . source . print_address ( ) , False ) ,
 green ( self . dest . print_address ( ) , False ) , self . udp_sport ,
 self . udp_dport ) )
  if 30 - 30: O0 . Ii1I / o0oOOo0O0Ooo + I1IiiI - O0
 def encode ( self , packet , inner_source , inner_dest ) :
  self . udp_length = len ( packet ) + 8
  self . source = inner_source
  self . dest = inner_dest
  if ( inner_dest . is_ipv4 ( ) ) :
   self . afi = LISP_AFI_IPV4
   self . length = self . udp_length + 20
   if 88 - 88: i11iIiiIii
  if ( inner_dest . is_ipv6 ( ) ) :
   self . afi = LISP_AFI_IPV6
   self . length = self . udp_length
   if 33 - 33: OoO0O00 + O0
   if 20 - 20: o0oOOo0O0Ooo % I11i . ooOoO0o - i1IIi . O0
   if 10 - 10: i1IIi
   if 49 - 49: I1Ii111 - Ii1I . O0
   if 46 - 46: OOooOOo
   if 64 - 64: I1IiiI / OoOoOO00
  iII = ( LISP_ECM << 28 )
  if ( self . security ) : iII |= 0x08000000
  if ( self . ddt ) : iII |= 0x04000000
  if ( self . to_etr ) : iII |= 0x02000000
  if ( self . to_ms ) : iII |= 0x01000000
  if 6 - 6: i11iIiiIii - iII111i * i1IIi - iII111i
  I1iiiIII11ii1i1i1 = struct . pack ( "I" , socket . htonl ( iII ) )
  if 3 - 3: I1IiiI . I11i / I1ii11iIi11i
  Ooo0oO = ""
  if ( self . afi == LISP_AFI_IPV4 ) :
   Ooo0oO = struct . pack ( "BBHHHBBH" , 0x45 , 0 , socket . htons ( self . length ) ,
 0 , 0 , self . ttl , self . protocol , socket . htons ( self . ip_checksum ) )
   Ooo0oO += self . source . pack_address ( )
   Ooo0oO += self . dest . pack_address ( )
   Ooo0oO = lisp_ip_checksum ( Ooo0oO )
   if 2 - 2: IiII + I11i / iIii1I11I1II1 . i11iIiiIii . i1IIi * ooOoO0o
  if ( self . afi == LISP_AFI_IPV6 ) :
   Ooo0oO = struct . pack ( "BBHHBB" , 0x60 , 0 , 0 , socket . htons ( self . length ) ,
 self . protocol , self . ttl )
   Ooo0oO += self . source . pack_address ( )
   Ooo0oO += self . dest . pack_address ( )
   if 14 - 14: Oo0Ooo . O0 - oO0o - i11iIiiIii
   if 8 - 8: I1IiiI / iIii1I11I1II1 / OoooooooOO / Oo0Ooo / ooOoO0o
  IiII1iiI = socket . htons ( self . udp_sport )
  OooOOOoOoo0O0 = socket . htons ( self . udp_dport )
  I11iIi1i1I1i1 = socket . htons ( self . udp_length )
  oOOoooo0o0 = socket . htons ( self . udp_checksum )
  o0oOo00 = struct . pack ( "HHHH" , IiII1iiI , OooOOOoOoo0O0 , I11iIi1i1I1i1 , oOOoooo0o0 )
  return ( I1iiiIII11ii1i1i1 + Ooo0oO + o0oOo00 )
  if 80 - 80: I11i
  if 26 - 26: II111iiii + I1IiiI . II111iiii - oO0o % OoO0O00
 def decode ( self , packet ) :
  if 1 - 1: OoO0O00 - II111iiii
  if 75 - 75: Oo0Ooo - OoOoOO00 + oO0o % i1IIi * OOooOOo
  if 56 - 56: OoOoOO00 / OoO0O00 / I1IiiI % OoooooooOO
  if 39 - 39: I1IiiI + II111iiii * Oo0Ooo % Ii1I . o0oOOo0O0Ooo * oO0o
  i1I1iii1I11II = "I"
  Iiiii = struct . calcsize ( i1I1iii1I11II )
  if ( len ( packet ) < Iiiii ) : return ( None )
  if 42 - 42: Ii1I / Oo0Ooo
  iII = struct . unpack ( i1I1iii1I11II , packet [ : Iiiii ] )
  if 25 - 25: OoooooooOO % Ii1I * I1Ii111 * I11i + I1IiiI % I1ii11iIi11i
  iII = socket . ntohl ( iII [ 0 ] )
  self . security = True if ( iII & 0x08000000 ) else False
  self . ddt = True if ( iII & 0x04000000 ) else False
  self . to_etr = True if ( iII & 0x02000000 ) else False
  self . to_ms = True if ( iII & 0x01000000 ) else False
  packet = packet [ Iiiii : : ]
  if 70 - 70: Ii1I + I1ii11iIi11i * I11i * i1IIi . I1Ii111
  if 76 - 76: OoooooooOO * OoOoOO00 . OoooooooOO
  if 46 - 46: ooOoO0o * o0oOOo0O0Ooo % II111iiii / I1Ii111
  if 29 - 29: OoO0O00 - i11iIiiIii % Oo0Ooo % o0oOOo0O0Ooo
  if ( len ( packet ) < 1 ) : return ( None )
  oOoO0 = struct . unpack ( "B" , packet [ 0 : 1 ] ) [ 0 ]
  oOoO0 = oOoO0 >> 4
  if 30 - 30: oO0o - Ii1I % Ii1I
  if ( oOoO0 == 4 ) :
   Iiiii = struct . calcsize ( "HHIBBH" )
   if ( len ( packet ) < Iiiii ) : return ( None )
   if 8 - 8: IiII
   O0O , I11iIi1i1I1i1 , O0O , iioOo0oo , oo00ooOOOo0O , oOOoooo0o0 = struct . unpack ( "HHIBBH" , packet [ : Iiiii ] )
   self . length = socket . ntohs ( I11iIi1i1I1i1 )
   self . ttl = iioOo0oo
   self . protocol = oo00ooOOOo0O
   self . ip_checksum = socket . ntohs ( oOOoooo0o0 )
   self . source . afi = self . dest . afi = LISP_AFI_IPV4
   if 54 - 54: I1ii11iIi11i + I1ii11iIi11i % iIii1I11I1II1
   if 74 - 74: ooOoO0o . Oo0Ooo * Ii1I / Ii1I
   if 45 - 45: iII111i - I11i
   if 100 - 100: I11i + OoO0O00 + OoooooooOO * iIii1I11I1II1
   oo00ooOOOo0O = struct . pack ( "H" , 0 )
   II1iIIII1iI1 = struct . calcsize ( "HHIBB" )
   iII1I1i = struct . calcsize ( "H" )
   packet = packet [ : II1iIIII1iI1 ] + oo00ooOOOo0O + packet [ II1iIIII1iI1 + iII1I1i : ]
   if 33 - 33: ooOoO0o . I1IiiI . i11iIiiIii % OoO0O00
   packet = packet [ Iiiii : : ]
   packet = self . source . unpack_address ( packet )
   if ( packet == None ) : return ( None )
   packet = self . dest . unpack_address ( packet )
   if ( packet == None ) : return ( None )
   if 72 - 72: I1ii11iIi11i / O0 % II111iiii / II111iiii
   if 48 - 48: OOooOOo % OOooOOo / iIii1I11I1II1 - i11iIiiIii
  if ( oOoO0 == 6 ) :
   Iiiii = struct . calcsize ( "IHBB" )
   if ( len ( packet ) < Iiiii ) : return ( None )
   if 57 - 57: I11i / IiII * i1IIi + II111iiii . o0oOOo0O0Ooo
   O0O , I11iIi1i1I1i1 , oo00ooOOOo0O , iioOo0oo = struct . unpack ( "IHBB" , packet [ : Iiiii ] )
   self . length = socket . ntohs ( I11iIi1i1I1i1 )
   self . protocol = oo00ooOOOo0O
   self . ttl = iioOo0oo
   self . source . afi = self . dest . afi = LISP_AFI_IPV6
   if 11 - 11: II111iiii
   packet = packet [ Iiiii : : ]
   packet = self . source . unpack_address ( packet )
   if ( packet == None ) : return ( None )
   packet = self . dest . unpack_address ( packet )
   if ( packet == None ) : return ( None )
   if 66 - 66: Ii1I - I1IiiI . OoooooooOO * I1Ii111
   if 16 - 16: IiII * OoO0O00 * i11iIiiIii - ooOoO0o
  self . source . mask_len = self . source . host_mask_len ( )
  self . dest . mask_len = self . dest . host_mask_len ( )
  if 88 - 88: iIii1I11I1II1 / Ii1I * IiII / I1Ii111
  Iiiii = struct . calcsize ( "HHHH" )
  if ( len ( packet ) < Iiiii ) : return ( None )
  if 31 - 31: O0 . I1IiiI
  IiII1iiI , OooOOOoOoo0O0 , I11iIi1i1I1i1 , oOOoooo0o0 = struct . unpack ( "HHHH" , packet [ : Iiiii ] )
  self . udp_sport = socket . ntohs ( IiII1iiI )
  self . udp_dport = socket . ntohs ( OooOOOoOoo0O0 )
  self . udp_length = socket . ntohs ( I11iIi1i1I1i1 )
  self . udp_checksum = socket . ntohs ( oOOoooo0o0 )
  packet = packet [ Iiiii : : ]
  return ( packet )
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
  if 48 - 48: iIii1I11I1II1 - Oo0Ooo
  if 80 - 80: i1IIi
  if 56 - 56: II111iiii - o0oOOo0O0Ooo
  if 48 - 48: Oo0Ooo - I1ii11iIi11i - II111iiii . Ii1I . oO0o / iIii1I11I1II1
  if 38 - 38: I1Ii111 % i11iIiiIii + Ii1I * ooOoO0o / I1Ii111
  if 93 - 93: oO0o
  if 60 - 60: I1Ii111 . oO0o / Oo0Ooo * ooOoO0o + OoOoOO00 - i1IIi
  if 13 - 13: i11iIiiIii * oO0o / I11i * I1IiiI
  if 31 - 31: iIii1I11I1II1 * Ii1I % OOooOOo . II111iiii
  if 56 - 56: IiII / i11iIiiIii . o0oOOo0O0Ooo . oO0o - i11iIiiIii
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
  if 79 - 79: O0
  if 71 - 71: OoO0O00 - O0
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
  if 72 - 72: iII111i
  if 100 - 100: I1IiiI
 def print_rloc_name ( self , cour = False ) :
  if ( self . rloc_name == None ) : return ( "" )
  oo0O0OOooO0 = self . rloc_name
  if ( cour ) : oo0O0OOooO0 = lisp_print_cour ( oo0O0OOooO0 )
  return ( 'rloc-name: {}' . format ( blue ( oo0O0OOooO0 , cour ) ) )
  if 75 - 75: OoO0O00
  if 24 - 24: Oo0Ooo % I11i . OoOoOO00 + IiII + OoOoOO00 - IiII
 def print_record ( self , indent ) :
  o0oooOoOoOo = self . print_rloc_name ( )
  if ( o0oooOoOoOo != "" ) : o0oooOoOoOo = ", " + o0oooOoOoOo
  Ii1IIIIiI11 = ""
  if ( self . geo ) :
   IiIIO0 = ""
   if ( self . geo . geo_name ) : IiIIO0 = "'{}' " . format ( self . geo . geo_name )
   Ii1IIIIiI11 = ", geo: {}{}" . format ( IiIIO0 , self . geo . print_geo ( ) )
   if 20 - 20: Oo0Ooo . OoooooooOO % oO0o - OOooOOo
  Oo = ""
  if ( self . elp ) :
   IiIIO0 = ""
   if ( self . elp . elp_name ) : IiIIO0 = "'{}' " . format ( self . elp . elp_name )
   Oo = ", elp: {}{}" . format ( IiIIO0 , self . elp . print_elp ( True ) )
   if 59 - 59: iIii1I11I1II1 - oO0o / OoooooooOO + oO0o / OoOoOO00
  II1I = ""
  if ( self . rle ) :
   IiIIO0 = ""
   if ( self . rle . rle_name ) : IiIIO0 = "'{}' " . format ( self . rle . rle_name )
   II1I = ", rle: {}{}" . format ( IiIIO0 , self . rle . print_rle ( False ,
 True ) )
   if 32 - 32: I1Ii111 * Ii1I / I1Ii111 . OoOoOO00 + I1ii11iIi11i - ooOoO0o
  I1IiIii1Ii1I = ""
  if ( self . json ) :
   IiIIO0 = ""
   if ( self . json . json_name ) :
    IiIIO0 = "'{}' " . format ( self . json . json_name )
    if 5 - 5: II111iiii / OoooooooOO % I1ii11iIi11i * I1IiiI * OoOoOO00
   I1IiIii1Ii1I = ", json: {}" . format ( self . json . print_json ( False ) )
   if 5 - 5: iIii1I11I1II1 . OoooooooOO
   if 13 - 13: oO0o . o0oOOo0O0Ooo . i11iIiiIii * I1ii11iIi11i / ooOoO0o
  I1i1Ii = ""
  if ( self . rloc . is_null ( ) == False and self . keys and self . keys [ 1 ] ) :
   I1i1Ii = ", " + self . keys [ 1 ] . print_keys ( )
   if 12 - 12: IiII + ooOoO0o . i11iIiiIii - iIii1I11I1II1
   if 27 - 27: I11i + iIii1I11I1II1
  oOOo0ooO0 = ( "{}RLOC-record -> flags: {}, {}/{}/{}/{}, afi: {}, rloc: "
 + "{}{}{}{}{}{}{}" )
  lprint ( oOOo0ooO0 . format ( indent , self . print_flags ( ) , self . priority ,
 self . weight , self . mpriority , self . mweight , self . rloc . afi ,
 red ( self . rloc . print_address_no_iid ( ) , False ) , o0oooOoOoOo , Ii1IIIIiI11 ,
 Oo , II1I , I1IiIii1Ii1I , I1i1Ii ) )
  if 71 - 71: OoOoOO00 + oO0o % OOooOOo * I1IiiI
  if 89 - 89: Ii1I % I1Ii111 / Oo0Ooo * Ii1I + OoOoOO00
 def print_flags ( self ) :
  return ( "{}{}{}" . format ( "L" if self . local_bit else "l" , "P" if self . probe_bit else "p" , "R" if self . reach_bit else "r" ) )
  if 5 - 5: Ii1I * I1IiiI + I1Ii111
  if 22 - 22: Oo0Ooo . OoO0O00
  if 55 - 55: Oo0Ooo % OoooooooOO * II111iiii % OoooooooOO
 def store_rloc_entry ( self , rloc_entry ) :
  I1IIiIIIii = rloc_entry . rloc if ( rloc_entry . translated_rloc . is_null ( ) ) else rloc_entry . translated_rloc
  if 16 - 16: OoOoOO00 % i11iIiiIii - oO0o - Ii1I / Ii1I - oO0o
  self . rloc . copy_address ( I1IIiIIIii )
  if 22 - 22: i1IIi / OoO0O00 * I1IiiI - Oo0Ooo - Ii1I
  if ( rloc_entry . rloc_name ) :
   self . rloc_name = rloc_entry . rloc_name
   if 80 - 80: ooOoO0o . i11iIiiIii
   if 18 - 18: I11i + i11iIiiIii
  if ( rloc_entry . geo ) :
   self . geo = rloc_entry . geo
  else :
   IiIIO0 = rloc_entry . geo_name
   if ( IiIIO0 and lisp_geo_list . has_key ( IiIIO0 ) ) :
    self . geo = lisp_geo_list [ IiIIO0 ]
    if 46 - 46: Ii1I * Ii1I
    if 57 - 57: I1Ii111 + iIii1I11I1II1 + I1IiiI * I1Ii111 - OOooOOo
  if ( rloc_entry . elp ) :
   self . elp = rloc_entry . elp
  else :
   IiIIO0 = rloc_entry . elp_name
   if ( IiIIO0 and lisp_elp_list . has_key ( IiIIO0 ) ) :
    self . elp = lisp_elp_list [ IiIIO0 ]
    if 97 - 97: I1ii11iIi11i
    if 3 - 3: ooOoO0o + i11iIiiIii . iIii1I11I1II1
  if ( rloc_entry . rle ) :
   self . rle = rloc_entry . rle
  else :
   IiIIO0 = rloc_entry . rle_name
   if ( IiIIO0 and lisp_rle_list . has_key ( IiIIO0 ) ) :
    self . rle = lisp_rle_list [ IiIIO0 ]
    if 70 - 70: ooOoO0o
    if 3 - 3: I1IiiI - I1IiiI
  if ( rloc_entry . json ) :
   self . json = rloc_entry . json
  else :
   IiIIO0 = rloc_entry . json_name
   if ( IiIIO0 and lisp_json_list . has_key ( IiIIO0 ) ) :
    self . json = lisp_json_list [ IiIIO0 ]
    if 89 - 89: OoOoOO00
    if 27 - 27: i1IIi % OoOoOO00 / Ii1I * Ii1I / I11i
  self . priority = rloc_entry . priority
  self . weight = rloc_entry . weight
  self . mpriority = rloc_entry . mpriority
  self . mweight = rloc_entry . mweight
  if 11 - 11: OOooOOo
  if 58 - 58: OoO0O00 * OoooooooOO
 def encode_json ( self , lisp_json ) :
  II11iii = lisp_json . json_string
  i1Ii1iiI = 0
  if ( lisp_json . json_encrypted ) :
   i1Ii1iiI = ( lisp_json . json_key_id << 5 ) | 0x02
   if 23 - 23: Oo0Ooo % II111iiii
   if 96 - 96: ooOoO0o % Ii1I
  iI1IIiI111iII = LISP_LCAF_JSON_TYPE
  OoOoO00OoOOo = socket . htons ( LISP_AFI_LCAF )
  OooO0OO0o = self . rloc . addr_length ( ) + 2
  if 46 - 46: Ii1I
  oOOO0O000Oo = socket . htons ( len ( II11iii ) + OooO0OO0o )
  if 14 - 14: OoO0O00 * OoooooooOO
  iiiii1I = socket . htons ( len ( II11iii ) )
  IiiiIi1iiii11 = struct . pack ( "HBBBBHH" , OoOoO00OoOOo , 0 , 0 , iI1IIiI111iII , i1Ii1iiI ,
 oOOO0O000Oo , iiiii1I )
  IiiiIi1iiii11 += II11iii
  if 45 - 45: iIii1I11I1II1 * I1IiiI . OoOoOO00
  if 97 - 97: I11i % II111iiii % Ii1I . II111iiii . iIii1I11I1II1
  if 98 - 98: i11iIiiIii + O0 - O0 - iII111i
  if 25 - 25: oO0o / O0 + I1Ii111 % i11iIiiIii / I1IiiI
  if ( lisp_is_json_telemetry ( II11iii ) ) :
   IiiiIi1iiii11 += struct . pack ( "H" , socket . htons ( self . rloc . afi ) )
   IiiiIi1iiii11 += self . rloc . pack_address ( )
  else :
   IiiiIi1iiii11 += struct . pack ( "H" , 0 )
   if 62 - 62: iII111i . I11i * i1IIi + iII111i
  return ( IiiiIi1iiii11 )
  if 95 - 95: Ii1I / o0oOOo0O0Ooo % ooOoO0o - I1IiiI / OOooOOo * OOooOOo
  if 6 - 6: OoO0O00 % IiII + iIii1I11I1II1
 def encode_lcaf ( self ) :
  OoOoO00OoOOo = socket . htons ( LISP_AFI_LCAF )
  IiIoOo0ooo = ""
  if ( self . geo ) :
   IiIoOo0ooo = self . geo . encode_geo ( )
   if 26 - 26: I11i - i1IIi - Oo0Ooo * O0 * OOooOOo . OoooooooOO
   if 99 - 99: oO0o . OoO0O00 / OOooOOo
  Ii1111i = ""
  if ( self . elp ) :
   i1iiIiI = ""
   for IIii in self . elp . elp_nodes :
    O0ooo0 = socket . htons ( IIii . address . afi )
    II111Ii1I1I = 0
    if ( IIii . eid ) : II111Ii1I1I |= 0x4
    if ( IIii . probe ) : II111Ii1I1I |= 0x2
    if ( IIii . strict ) : II111Ii1I1I |= 0x1
    II111Ii1I1I = socket . htons ( II111Ii1I1I )
    i1iiIiI += struct . pack ( "HH" , II111Ii1I1I , O0ooo0 )
    i1iiIiI += IIii . address . pack_address ( )
    if 22 - 22: iIii1I11I1II1 % iIii1I11I1II1 . o0oOOo0O0Ooo
    if 46 - 46: oO0o
   I1Iiiii1i = socket . htons ( len ( i1iiIiI ) )
   Ii1111i = struct . pack ( "HBBBBH" , OoOoO00OoOOo , 0 , 0 , LISP_LCAF_ELP_TYPE ,
 0 , I1Iiiii1i )
   Ii1111i += i1iiIiI
   if 78 - 78: i1IIi % oO0o + IiII
   if 75 - 75: O0 + I1ii11iIi11i
  oo0oO0 = ""
  if ( self . rle ) :
   i1ii1i1Iii = ""
   for Iii in self . rle . rle_nodes :
    O0ooo0 = socket . htons ( Iii . address . afi )
    i1ii1i1Iii += struct . pack ( "HBBH" , 0 , 0 , Iii . level , O0ooo0 )
    i1ii1i1Iii += Iii . address . pack_address ( )
    if ( Iii . rloc_name ) :
     i1ii1i1Iii += struct . pack ( "H" , socket . htons ( LISP_AFI_NAME ) )
     i1ii1i1Iii += Iii . rloc_name + "\0"
     if 76 - 76: i1IIi
     if 38 - 38: I1IiiI
     if 15 - 15: o0oOOo0O0Ooo
   ooOo = socket . htons ( len ( i1ii1i1Iii ) )
   oo0oO0 = struct . pack ( "HBBBBH" , OoOoO00OoOOo , 0 , 0 , LISP_LCAF_RLE_TYPE ,
 0 , ooOo )
   oo0oO0 += i1ii1i1Iii
   if 74 - 74: o0oOOo0O0Ooo % oO0o % iII111i / I1ii11iIi11i / O0 % I1Ii111
   if 48 - 48: i11iIiiIii + I11i
  oOoooo0 = ""
  if ( self . json ) :
   oOoooo0 = self . encode_json ( self . json )
   if 79 - 79: OoOoOO00 * II111iiii + Ii1I + OOooOOo % I1IiiI * OoooooooOO
   if 46 - 46: iIii1I11I1II1 . Ii1I % Ii1I - I1IiiI
  iiII1IIIi = ""
  if ( self . rloc . is_null ( ) == False and self . keys and self . keys [ 1 ] ) :
   iiII1IIIi = self . keys [ 1 ] . encode_lcaf ( self . rloc )
   if 45 - 45: Ii1I . OoO0O00 - OoO0O00 . OoO0O00 - iIii1I11I1II1
   if 41 - 41: OoO0O00 * i11iIiiIii / i1IIi + o0oOOo0O0Ooo . IiII
  iii111iIiiIII = ""
  if ( self . rloc_name ) :
   iii111iIiiIII += struct . pack ( "H" , socket . htons ( LISP_AFI_NAME ) )
   iii111iIiiIII += self . rloc_name + "\0"
   if 21 - 21: OOooOOo / O0
   if 46 - 46: OoooooooOO % Oo0Ooo % i1IIi / ooOoO0o - I11i
  IiiiI = len ( IiIoOo0ooo ) + len ( Ii1111i ) + len ( oo0oO0 ) + len ( iiII1IIIi ) + 2 + len ( oOoooo0 ) + self . rloc . addr_length ( ) + len ( iii111iIiiIII )
  if 57 - 57: I1Ii111 * I1ii11iIi11i / i1IIi % i11iIiiIii
  IiiiI = socket . htons ( IiiiI )
  oOOo00Oo0 = struct . pack ( "HBBBBHH" , OoOoO00OoOOo , 0 , 0 , LISP_LCAF_AFI_LIST_TYPE ,
 0 , IiiiI , socket . htons ( self . rloc . afi ) )
  oOOo00Oo0 += self . rloc . pack_address ( )
  return ( oOOo00Oo0 + iii111iIiiIII + IiIoOo0ooo + Ii1111i + oo0oO0 + iiII1IIIi + oOoooo0 )
  if 78 - 78: iIii1I11I1II1 * OoOoOO00 - I1IiiI . O0 / I1Ii111
  if 5 - 5: I1ii11iIi11i % OoOoOO00 . OoooooooOO . o0oOOo0O0Ooo + i11iIiiIii
 def encode ( self ) :
  II111Ii1I1I = 0
  if ( self . local_bit ) : II111Ii1I1I |= 0x0004
  if ( self . probe_bit ) : II111Ii1I1I |= 0x0002
  if ( self . reach_bit ) : II111Ii1I1I |= 0x0001
  if 54 - 54: ooOoO0o - O0 + iII111i
  IiiiIi1iiii11 = struct . pack ( "BBBBHH" , self . priority , self . weight ,
 self . mpriority , self . mweight , socket . htons ( II111Ii1I1I ) ,
 socket . htons ( self . rloc . afi ) )
  if 34 - 34: Ii1I - OOooOOo % iII111i
  if ( self . geo or self . elp or self . rle or self . keys or self . rloc_name or self . json ) :
   if 48 - 48: oO0o - O0
   IiiiIi1iiii11 = IiiiIi1iiii11 [ 0 : - 2 ] + self . encode_lcaf ( )
  else :
   IiiiIi1iiii11 += self . rloc . pack_address ( )
   if 17 - 17: iIii1I11I1II1 . IiII / ooOoO0o % I11i + o0oOOo0O0Ooo - iIii1I11I1II1
  return ( IiiiIi1iiii11 )
  if 95 - 95: OoOoOO00 + OOooOOo - I11i * i1IIi + i1IIi * O0
  if 60 - 60: Oo0Ooo + I11i % iIii1I11I1II1 % oO0o - I1Ii111 / o0oOOo0O0Ooo
 def decode_lcaf ( self , packet , nonce ) :
  i1I1iii1I11II = "HBBBBH"
  Iiiii = struct . calcsize ( i1I1iii1I11II )
  if ( len ( packet ) < Iiiii ) : return ( None )
  if 9 - 9: IiII / oO0o % O0 * I1Ii111 - iIii1I11I1II1 % i1IIi
  O0ooo0 , Ii1IiIIIi1i , II111Ii1I1I , iI1IIiI111iII , o00oo0oOo0o0 , oOOO0O000Oo = struct . unpack ( i1I1iii1I11II , packet [ : Iiiii ] )
  if 83 - 83: OoOoOO00 + OOooOOo / OoooooooOO
  if 39 - 39: OoO0O00 % iII111i . oO0o . II111iiii - i11iIiiIii
  oOOO0O000Oo = socket . ntohs ( oOOO0O000Oo )
  packet = packet [ Iiiii : : ]
  if ( oOOO0O000Oo > len ( packet ) ) : return ( None )
  if 85 - 85: O0 - OoOoOO00
  if 17 - 17: o0oOOo0O0Ooo / i1IIi / OOooOOo
  if 91 - 91: I1ii11iIi11i / Ii1I - OoOoOO00 . I11i / oO0o
  if 16 - 16: IiII % iII111i . oO0o . I1IiiI % O0 * I11i
  if ( iI1IIiI111iII == LISP_LCAF_AFI_LIST_TYPE ) :
   while ( oOOO0O000Oo > 0 ) :
    i1I1iii1I11II = "H"
    Iiiii = struct . calcsize ( i1I1iii1I11II )
    if ( oOOO0O000Oo < Iiiii ) : return ( None )
    if 99 - 99: OoOoOO00 / OoooooooOO + iII111i * I11i * i11iIiiIii + OOooOOo
    iIi1Iii1 = len ( packet )
    O0ooo0 = struct . unpack ( i1I1iii1I11II , packet [ : Iiiii ] ) [ 0 ]
    O0ooo0 = socket . ntohs ( O0ooo0 )
    if 40 - 40: II111iiii / I11i % I1IiiI - O0
    if ( O0ooo0 == LISP_AFI_LCAF ) :
     packet = self . decode_lcaf ( packet , nonce )
     if ( packet == None ) : return ( None )
    else :
     packet = packet [ Iiiii : : ]
     self . rloc_name = None
     if ( O0ooo0 == LISP_AFI_NAME ) :
      packet , oo0O0OOooO0 = lisp_decode_dist_name ( packet )
      self . rloc_name = oo0O0OOooO0
     else :
      self . rloc . afi = O0ooo0
      packet = self . rloc . unpack_address ( packet )
      if ( packet == None ) : return ( None )
      self . rloc . mask_len = self . rloc . host_mask_len ( )
      if 39 - 39: i11iIiiIii - OoOoOO00 % OOooOOo + ooOoO0o + i11iIiiIii
      if 59 - 59: IiII / OoOoOO00 - I1Ii111 - ooOoO0o . oO0o
      if 87 - 87: oO0o + I1IiiI * I1Ii111 * o0oOOo0O0Ooo + O0
    oOOO0O000Oo -= iIi1Iii1 - len ( packet )
    if 21 - 21: I1Ii111 + OoOoOO00 + OoOoOO00 . II111iiii / I1Ii111 . I1IiiI
    if 66 - 66: I1Ii111 % oO0o . iII111i * i1IIi
  elif ( iI1IIiI111iII == LISP_LCAF_GEO_COORD_TYPE ) :
   if 81 - 81: OoooooooOO * I1IiiI / I1Ii111
   if 10 - 10: I1IiiI - II111iiii / IiII * II111iiii
   if 67 - 67: II111iiii . Ii1I % oO0o . Oo0Ooo + IiII
   if 10 - 10: OOooOOo - OoO0O00 * oO0o / iIii1I11I1II1 - OoOoOO00
   I1Ii1i111I = lisp_geo ( "" )
   packet = I1Ii1i111I . decode_geo ( packet , oOOO0O000Oo , o00oo0oOo0o0 )
   if ( packet == None ) : return ( None )
   self . geo = I1Ii1i111I
   if 51 - 51: O0 + Ii1I * OoooooooOO . oO0o + OoooooooOO
  elif ( iI1IIiI111iII == LISP_LCAF_JSON_TYPE ) :
   O0iI1Iii = o00oo0oOo0o0 & 0x02
   if 35 - 35: I1ii11iIi11i + O0
   if 7 - 7: OoooooooOO % iII111i % Ii1I % II111iiii / oO0o
   if 15 - 15: OoO0O00
   if 18 - 18: OoooooooOO / OOooOOo % i1IIi - i1IIi / Oo0Ooo
   i1I1iii1I11II = "H"
   Iiiii = struct . calcsize ( i1I1iii1I11II )
   if ( oOOO0O000Oo < Iiiii ) : return ( None )
   if 94 - 94: I1Ii111 + i11iIiiIii / iII111i + OoooooooOO % i1IIi
   iiiii1I = struct . unpack ( i1I1iii1I11II , packet [ : Iiiii ] ) [ 0 ]
   iiiii1I = socket . ntohs ( iiiii1I )
   if ( oOOO0O000Oo < Iiiii + iiiii1I ) : return ( None )
   if 57 - 57: iIii1I11I1II1 - i11iIiiIii / II111iiii
   packet = packet [ Iiiii : : ]
   self . json = lisp_json ( "" , packet [ 0 : iiiii1I ] , O0iI1Iii )
   packet = packet [ iiiii1I : : ]
   if 35 - 35: I1IiiI - IiII * I1Ii111 - ooOoO0o % oO0o
   if 88 - 88: IiII * OoO0O00 / IiII * I1IiiI + O0 / IiII
   if 41 - 41: OoOoOO00
   if 81 - 81: Ii1I . I1IiiI % o0oOOo0O0Ooo . OoOoOO00
   O0ooo0 = socket . ntohs ( struct . unpack ( "H" , packet [ : 2 ] ) [ 0 ] )
   packet = packet [ 2 : : ]
   if 94 - 94: oO0o % Oo0Ooo + OoO0O00 * oO0o - i11iIiiIii / I11i
   if ( O0ooo0 != 0 and lisp_is_json_telemetry ( self . json . json_string ) ) :
    self . rloc . afi = O0ooo0
    packet = self . rloc . unpack_address ( packet )
    if 46 - 46: IiII - OoO0O00 * iII111i . I1Ii111 - ooOoO0o . i1IIi
    if 53 - 53: I1Ii111 * I1IiiI + Oo0Ooo + I1IiiI + OOooOOo
  elif ( iI1IIiI111iII == LISP_LCAF_ELP_TYPE ) :
   if 8 - 8: i11iIiiIii + OoOoOO00 . I1ii11iIi11i / OoooooooOO % II111iiii
   if 21 - 21: oO0o - o0oOOo0O0Ooo + ooOoO0o . I1IiiI * oO0o * Ii1I
   if 41 - 41: i1IIi % i11iIiiIii + I11i % OoooooooOO / I1ii11iIi11i
   if 8 - 8: OoooooooOO - OoO0O00 / i11iIiiIii / O0 . IiII
   O0OoO0O0O0oO = lisp_elp ( None )
   O0OoO0O0O0oO . elp_nodes = [ ]
   while ( oOOO0O000Oo > 0 ) :
    II111Ii1I1I , O0ooo0 = struct . unpack ( "HH" , packet [ : 4 ] )
    if 58 - 58: I1ii11iIi11i + Oo0Ooo . Oo0Ooo / iII111i . i11iIiiIii
    O0ooo0 = socket . ntohs ( O0ooo0 )
    if ( O0ooo0 == LISP_AFI_LCAF ) : return ( None )
    if 8 - 8: I1ii11iIi11i + O0 - oO0o % II111iiii . I1Ii111
    IIii = lisp_elp_node ( )
    O0OoO0O0O0oO . elp_nodes . append ( IIii )
    if 86 - 86: IiII
    II111Ii1I1I = socket . ntohs ( II111Ii1I1I )
    IIii . eid = ( II111Ii1I1I & 0x4 )
    IIii . probe = ( II111Ii1I1I & 0x2 )
    IIii . strict = ( II111Ii1I1I & 0x1 )
    IIii . address . afi = O0ooo0
    IIii . address . mask_len = IIii . address . host_mask_len ( )
    packet = IIii . address . unpack_address ( packet [ 4 : : ] )
    oOOO0O000Oo -= IIii . address . addr_length ( ) + 4
    if 71 - 71: Ii1I - i1IIi . I1IiiI
   O0OoO0O0O0oO . select_elp_node ( )
   self . elp = O0OoO0O0O0oO
   if 15 - 15: i1IIi % II111iiii / II111iiii - I1ii11iIi11i - I11i % i1IIi
  elif ( iI1IIiI111iII == LISP_LCAF_RLE_TYPE ) :
   if 54 - 54: i1IIi . OoO0O00 + iII111i + OoO0O00 * i1IIi
   if 13 - 13: Oo0Ooo / OoO0O00 + OOooOOo
   if 90 - 90: OoO0O00 * i11iIiiIii / oO0o
   if 91 - 91: iII111i - OoOoOO00 / Oo0Ooo % II111iiii / II111iiii / o0oOOo0O0Ooo
   iI1Ii11 = lisp_rle ( None )
   iI1Ii11 . rle_nodes = [ ]
   while ( oOOO0O000Oo > 0 ) :
    O0O , IIIi1i1iIIIi , oOOoOoooOo0o , O0ooo0 = struct . unpack ( "HBBH" , packet [ : 6 ] )
    if 59 - 59: i11iIiiIii - I11i * Oo0Ooo % o0oOOo0O0Ooo + i1IIi
    O0ooo0 = socket . ntohs ( O0ooo0 )
    if ( O0ooo0 == LISP_AFI_LCAF ) : return ( None )
    if 30 - 30: ooOoO0o / iII111i
    Iii = lisp_rle_node ( )
    iI1Ii11 . rle_nodes . append ( Iii )
    if 66 - 66: ooOoO0o / IiII * iIii1I11I1II1
    Iii . level = oOOoOoooOo0o
    Iii . address . afi = O0ooo0
    Iii . address . mask_len = Iii . address . host_mask_len ( )
    packet = Iii . address . unpack_address ( packet [ 6 : : ] )
    if 42 - 42: I1Ii111 - i11iIiiIii % II111iiii * ooOoO0o . O0 % I11i
    oOOO0O000Oo -= Iii . address . addr_length ( ) + 6
    if ( oOOO0O000Oo >= 2 ) :
     O0ooo0 = struct . unpack ( "H" , packet [ : 2 ] ) [ 0 ]
     if ( socket . ntohs ( O0ooo0 ) == LISP_AFI_NAME ) :
      packet = packet [ 2 : : ]
      packet , Iii . rloc_name = lisp_decode_dist_name ( packet )
      if 82 - 82: Oo0Ooo % O0 + I1ii11iIi11i % I1ii11iIi11i
      if ( packet == None ) : return ( None )
      oOOO0O000Oo -= len ( Iii . rloc_name ) + 1 + 2
      if 74 - 74: O0 * IiII . I11i - I1Ii111 + O0 + I11i
      if 48 - 48: oO0o . o0oOOo0O0Ooo - OOooOOo
      if 29 - 29: Oo0Ooo - Ii1I - Oo0Ooo
   self . rle = iI1Ii11
   self . rle . build_forwarding_list ( )
   if 89 - 89: Oo0Ooo . OoO0O00 . I1ii11iIi11i * oO0o . O0
  elif ( iI1IIiI111iII == LISP_LCAF_SECURITY_TYPE ) :
   if 72 - 72: i11iIiiIii % I11i / I1Ii111 + I1IiiI * iII111i
   if 69 - 69: I1Ii111 + O0 . IiII . o0oOOo0O0Ooo
   if 38 - 38: IiII / i1IIi
   if 60 - 60: OoOoOO00
   if 75 - 75: II111iiii / iIii1I11I1II1 / OoooooooOO
   OoO = packet
   iI1IiI1 = lisp_keys ( 1 )
   packet = iI1IiI1 . decode_lcaf ( OoO , oOOO0O000Oo )
   if ( packet == None ) : return ( None )
   if 61 - 61: IiII . IiII
   if 17 - 17: OoOoOO00 % Oo0Ooo / I1Ii111 . Ii1I % OoO0O00
   if 32 - 32: I1IiiI + ooOoO0o / O0 * i11iIiiIii % Oo0Ooo + II111iiii
   if 95 - 95: iII111i / ooOoO0o + I1Ii111
   iI111I = [ LISP_CS_25519_CBC , LISP_CS_25519_CHACHA ]
   if ( iI1IiI1 . cipher_suite in iI111I ) :
    if ( iI1IiI1 . cipher_suite == LISP_CS_25519_CBC ) :
     Oo000O000 = lisp_keys ( 1 , do_poly = False , do_chacha = False )
     if 78 - 78: iIii1I11I1II1 / I1IiiI - IiII
    if ( iI1IiI1 . cipher_suite == LISP_CS_25519_CHACHA ) :
     Oo000O000 = lisp_keys ( 1 , do_poly = True , do_chacha = True )
     if 81 - 81: I1ii11iIi11i
   else :
    Oo000O000 = lisp_keys ( 1 , do_poly = False , do_chacha = False )
    if 31 - 31: O0 % ooOoO0o / I1IiiI * iII111i % iIii1I11I1II1 * OoOoOO00
   packet = Oo000O000 . decode_lcaf ( OoO , oOOO0O000Oo )
   if ( packet == None ) : return ( None )
   if 76 - 76: I1Ii111 - O0
   if ( len ( packet ) < 2 ) : return ( None )
   O0ooo0 = struct . unpack ( "H" , packet [ : 2 ] ) [ 0 ]
   self . rloc . afi = socket . ntohs ( O0ooo0 )
   if ( len ( packet ) < self . rloc . addr_length ( ) ) : return ( None )
   packet = self . rloc . unpack_address ( packet [ 2 : : ] )
   if ( packet == None ) : return ( None )
   self . rloc . mask_len = self . rloc . host_mask_len ( )
   if 23 - 23: O0 * Ii1I * ooOoO0o % ooOoO0o
   if 7 - 7: II111iiii + I11i
   if 99 - 99: iIii1I11I1II1 * oO0o
   if 37 - 37: ooOoO0o * iII111i * I11i
   if 11 - 11: I1IiiI
   if 48 - 48: O0 . I11i
   if ( self . rloc . is_null ( ) ) : return ( packet )
   if 9 - 9: oO0o / Oo0Ooo
   Ooooo = self . rloc_name
   if ( Ooooo ) : Ooooo = blue ( self . rloc_name , False )
   if 45 - 45: I11i
   if 90 - 90: OoO0O00 * I1IiiI - I1IiiI % OoO0O00
   if 84 - 84: I1IiiI % I1IiiI * Ii1I
   if 75 - 75: iIii1I11I1II1 - I1Ii111
   if 86 - 86: O0 + O0 / I11i - iIii1I11I1II1
   if 42 - 42: OOooOOo
   oO0OooO0o0 = self . keys [ 1 ] if self . keys else None
   if ( oO0OooO0o0 == None ) :
    if ( Oo000O000 . remote_public_key == None ) :
     Iii11I111Ii11 = bold ( "No remote encap-public-key supplied" , False )
     lprint ( "    {} for {}" . format ( Iii11I111Ii11 , Ooooo ) )
     Oo000O000 = None
    else :
     Iii11I111Ii11 = bold ( "New encap-keying with new state" , False )
     lprint ( "    {} for {}" . format ( Iii11I111Ii11 , Ooooo ) )
     Oo000O000 . compute_shared_key ( "encap" )
     if 39 - 39: O0 % Ii1I . I11i * o0oOOo0O0Ooo
     if 14 - 14: I11i . iIii1I11I1II1 + I1Ii111 % OoooooooOO
     if 9 - 9: oO0o + Ii1I / I1ii11iIi11i * iIii1I11I1II1 + o0oOOo0O0Ooo
     if 64 - 64: I11i % i11iIiiIii % I1ii11iIi11i
     if 14 - 14: I1Ii111 - OoOoOO00 - I1ii11iIi11i % I11i + OoooooooOO
     if 4 - 4: I1Ii111 - I1IiiI / iIii1I11I1II1 + I1ii11iIi11i % iIii1I11I1II1 * I1IiiI
     if 30 - 30: i11iIiiIii % OOooOOo
     if 52 - 52: I11i - oO0o . i11iIiiIii - II111iiii + Ii1I . iII111i
     if 27 - 27: I1IiiI + OoOoOO00 + iII111i
     if 70 - 70: I11i + IiII . ooOoO0o - I1ii11iIi11i
   if ( oO0OooO0o0 ) :
    if ( Oo000O000 . remote_public_key == None ) :
     Oo000O000 = None
     OOO0o0oo = bold ( "Remote encap-unkeying occurred" , False )
     lprint ( "    {} for {}" . format ( OOO0o0oo , Ooooo ) )
    elif ( oO0OooO0o0 . compare_keys ( Oo000O000 ) ) :
     Oo000O000 = oO0OooO0o0
     lprint ( "    Maintain stored encap-keys for {}" . format ( Ooooo ) )
     if 34 - 34: i1IIi % Oo0Ooo . oO0o
    else :
     if ( oO0OooO0o0 . remote_public_key == None ) :
      Iii11I111Ii11 = "New encap-keying for existing state"
     else :
      Iii11I111Ii11 = "Remote encap-rekeying"
      if 36 - 36: I1ii11iIi11i / I1Ii111 - IiII + OOooOOo + I1Ii111
     lprint ( "    {} for {}" . format ( bold ( Iii11I111Ii11 , False ) ,
 Ooooo ) )
     oO0OooO0o0 . remote_public_key = Oo000O000 . remote_public_key
     oO0OooO0o0 . compute_shared_key ( "encap" )
     Oo000O000 = oO0OooO0o0
     if 62 - 62: Oo0Ooo . OoO0O00 * I1Ii111 . i11iIiiIii * O0
     if 10 - 10: Oo0Ooo / OoOoOO00 * OOooOOo - IiII + Ii1I
   self . keys = [ None , Oo000O000 , None , None ]
   if 62 - 62: I1IiiI . Ii1I
  else :
   if 74 - 74: Ii1I - I11i % ooOoO0o - I1IiiI - Ii1I - II111iiii
   if 81 - 81: i1IIi * I1ii11iIi11i + IiII - OoO0O00 * i1IIi
   if 6 - 6: iIii1I11I1II1 % OoOoOO00 % II111iiii % o0oOOo0O0Ooo
   if 52 - 52: Ii1I - I1IiiI * iIii1I11I1II1 % Oo0Ooo * OOooOOo
   packet = packet [ oOOO0O000Oo : : ]
   if 67 - 67: OoooooooOO * I11i * Ii1I * iIii1I11I1II1
  return ( packet )
  if 22 - 22: OoO0O00 / o0oOOo0O0Ooo
  if 35 - 35: I1Ii111 / I1Ii111 + o0oOOo0O0Ooo - oO0o
 def decode ( self , packet , nonce ) :
  i1I1iii1I11II = "BBBBHH"
  Iiiii = struct . calcsize ( i1I1iii1I11II )
  if ( len ( packet ) < Iiiii ) : return ( None )
  if 40 - 40: OoOoOO00 - II111iiii
  self . priority , self . weight , self . mpriority , self . mweight , II111Ii1I1I , O0ooo0 = struct . unpack ( i1I1iii1I11II , packet [ : Iiiii ] )
  if 29 - 29: I1IiiI - O0
  if 36 - 36: I1IiiI * I1IiiI
  II111Ii1I1I = socket . ntohs ( II111Ii1I1I )
  O0ooo0 = socket . ntohs ( O0ooo0 )
  self . local_bit = True if ( II111Ii1I1I & 0x0004 ) else False
  self . probe_bit = True if ( II111Ii1I1I & 0x0002 ) else False
  self . reach_bit = True if ( II111Ii1I1I & 0x0001 ) else False
  if 79 - 79: I1Ii111 - I11i
  if ( O0ooo0 == LISP_AFI_LCAF ) :
   packet = packet [ Iiiii - 2 : : ]
   packet = self . decode_lcaf ( packet , nonce )
  else :
   self . rloc . afi = O0ooo0
   packet = packet [ Iiiii : : ]
   packet = self . rloc . unpack_address ( packet )
   if 49 - 49: II111iiii + O0 * ooOoO0o - Oo0Ooo
  self . rloc . mask_len = self . rloc . host_mask_len ( )
  return ( packet )
  if 89 - 89: I1IiiI + I11i . oO0o . II111iiii + oO0o / Oo0Ooo
  if 32 - 32: OoO0O00 % oO0o * I1ii11iIi11i + I11i / I1Ii111
 def end_of_rlocs ( self , packet , rloc_count ) :
  for IiIIi1IiiIiI in range ( rloc_count ) :
   packet = self . decode ( packet , None )
   if ( packet == None ) : return ( None )
   if 5 - 5: o0oOOo0O0Ooo + iII111i / OoooooooOO + Ii1I . OoOoOO00 / oO0o
  return ( packet )
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
class lisp_map_referral ( ) :
 def __init__ ( self ) :
  self . record_count = 0
  self . nonce = 0
  if 55 - 55: o0oOOo0O0Ooo / O0 / OoooooooOO * Oo0Ooo % iII111i
  if 24 - 24: I1ii11iIi11i % OOooOOo + OoooooooOO + OoO0O00
 def print_map_referral ( self ) :
  lprint ( "{} -> record-count: {}, nonce: 0x{}" . format ( bold ( "Map-Referral" , False ) , self . record_count ,
  # OOooOOo + o0oOOo0O0Ooo + OoOoOO00 + iIii1I11I1II1 + II111iiii - O0
 lisp_hex_string ( self . nonce ) ) )
  if 22 - 22: Ii1I % O0 - oO0o / I1IiiI * OoOoOO00
  if 31 - 31: IiII + I1IiiI * I11i % OoO0O00
 def encode ( self ) :
  iII = ( LISP_MAP_REFERRAL << 28 ) | self . record_count
  IiiiIi1iiii11 = struct . pack ( "I" , socket . htonl ( iII ) )
  IiiiIi1iiii11 += struct . pack ( "Q" , self . nonce )
  return ( IiiiIi1iiii11 )
  if 77 - 77: II111iiii * OoooooooOO * ooOoO0o % OOooOOo % OOooOOo * i1IIi
  if 37 - 37: I1ii11iIi11i * iII111i . ooOoO0o - I1IiiI
 def decode ( self , packet ) :
  i1I1iii1I11II = "I"
  Iiiii = struct . calcsize ( i1I1iii1I11II )
  if ( len ( packet ) < Iiiii ) : return ( None )
  if 95 - 95: I11i / I1Ii111 % Ii1I % o0oOOo0O0Ooo . Ii1I
  iII = struct . unpack ( i1I1iii1I11II , packet [ : Iiiii ] )
  iII = socket . ntohl ( iII [ 0 ] )
  self . record_count = iII & 0xff
  packet = packet [ Iiiii : : ]
  if 40 - 40: iII111i . ooOoO0o % OoooooooOO % OOooOOo / OoooooooOO / Oo0Ooo
  i1I1iii1I11II = "Q"
  Iiiii = struct . calcsize ( i1I1iii1I11II )
  if ( len ( packet ) < Iiiii ) : return ( None )
  if 93 - 93: o0oOOo0O0Ooo % iIii1I11I1II1 % oO0o / I1IiiI
  self . nonce = struct . unpack ( i1I1iii1I11II , packet [ : Iiiii ] ) [ 0 ]
  packet = packet [ Iiiii : : ]
  return ( packet )
  if 98 - 98: II111iiii + Oo0Ooo - i1IIi + iII111i + II111iiii
  if 93 - 93: O0
  if 78 - 78: I1Ii111 * i1IIi + OoooooooOO * ooOoO0o
  if 69 - 69: i1IIi
  if 83 - 83: I1ii11iIi11i . ooOoO0o + I1IiiI + O0
  if 78 - 78: O0 + Oo0Ooo
  if 14 - 14: O0
  if 67 - 67: II111iiii / O0
class lisp_ddt_entry ( ) :
 def __init__ ( self ) :
  self . eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . group = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . uptime = lisp_get_timestamp ( )
  self . delegation_set = [ ]
  self . source_cache = None
  self . map_referrals_sent = 0
  if 10 - 10: i1IIi / Oo0Ooo
  if 20 - 20: Oo0Ooo * I1Ii111 / I1ii11iIi11i . ooOoO0o
 def is_auth_prefix ( self ) :
  if ( len ( self . delegation_set ) != 0 ) : return ( False )
  if ( self . is_star_g ( ) ) : return ( False )
  return ( True )
  if 67 - 67: o0oOOo0O0Ooo . Oo0Ooo % I11i
  if 38 - 38: OOooOOo - OoO0O00 . ooOoO0o
 def is_ms_peer_entry ( self ) :
  if ( len ( self . delegation_set ) == 0 ) : return ( False )
  return ( self . delegation_set [ 0 ] . is_ms_peer ( ) )
  if 50 - 50: o0oOOo0O0Ooo
  if 85 - 85: II111iiii . iII111i - i1IIi
 def print_referral_type ( self ) :
  if ( len ( self . delegation_set ) == 0 ) : return ( "unknown" )
  I1IooOoo00 = self . delegation_set [ 0 ]
  return ( I1IooOoo00 . print_node_type ( ) )
  if 24 - 24: I1Ii111 + I1ii11iIi11i % I11i * oO0o % i1IIi
  if 14 - 14: I11i * OOooOOo - O0 . I1ii11iIi11i * O0
 def print_eid_tuple ( self ) :
  return ( lisp_print_eid_tuple ( self . eid , self . group ) )
  if 40 - 40: OoOoOO00 - II111iiii . I1IiiI . i1IIi
  if 60 - 60: iIii1I11I1II1 + ooOoO0o * i11iIiiIii + OoooooooOO
 def add_cache ( self ) :
  if ( self . group . is_null ( ) ) :
   lisp_ddt_cache . add_cache ( self . eid , self )
  else :
   IIIIii11i1I = lisp_ddt_cache . lookup_cache ( self . group , True )
   if ( IIIIii11i1I == None ) :
    IIIIii11i1I = lisp_ddt_entry ( )
    IIIIii11i1I . eid . copy_address ( self . group )
    IIIIii11i1I . group . copy_address ( self . group )
    lisp_ddt_cache . add_cache ( self . group , IIIIii11i1I )
    if 24 - 24: OOooOOo / O0 - OoO0O00 + IiII
   if ( self . eid . is_null ( ) ) : self . eid . make_default_route ( IIIIii11i1I . group )
   IIIIii11i1I . add_source_entry ( self )
   if 33 - 33: I1IiiI
   if 92 - 92: OOooOOo / i11iIiiIii + OoooooooOO
   if 9 - 9: iII111i
 def add_source_entry ( self , source_ddt ) :
  if ( self . source_cache == None ) : self . source_cache = lisp_cache ( )
  self . source_cache . add_cache ( source_ddt . eid , source_ddt )
  if 9 - 9: O0 / o0oOOo0O0Ooo / I11i - i11iIiiIii - iII111i / IiII
  if 46 - 46: IiII + OoooooooOO % I1IiiI
 def lookup_source_cache ( self , source , exact ) :
  if ( self . source_cache == None ) : return ( None )
  return ( self . source_cache . lookup_cache ( source , exact ) )
  if 51 - 51: I1IiiI * I1Ii111 . i11iIiiIii % Oo0Ooo . i1IIi - oO0o
  if 56 - 56: Oo0Ooo / II111iiii
 def is_star_g ( self ) :
  if ( self . group . is_null ( ) ) : return ( False )
  return ( self . eid . is_exact_match ( self . group ) )
  if 76 - 76: OoOoOO00 % OoO0O00 * O0
  if 39 - 39: ooOoO0o / iII111i
  if 94 - 94: oO0o + iII111i * OoOoOO00 - i1IIi / OoooooooOO
class lisp_ddt_node ( ) :
 def __init__ ( self ) :
  self . delegate_address = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . public_key = ""
  self . map_server_peer = False
  self . map_server_child = False
  self . priority = 0
  self . weight = 0
  if 59 - 59: I11i % Ii1I / OoOoOO00
  if 99 - 99: Ii1I + II111iiii / i11iIiiIii - IiII / iII111i + iII111i
 def print_node_type ( self ) :
  if ( self . is_ddt_child ( ) ) : return ( "ddt-child" )
  if ( self . is_ms_child ( ) ) : return ( "map-server-child" )
  if ( self . is_ms_peer ( ) ) : return ( "map-server-peer" )
  if 55 - 55: IiII + OoooooooOO * I1ii11iIi11i . IiII * I1ii11iIi11i + IiII
  if 81 - 81: iIii1I11I1II1 . ooOoO0o + OoOoOO00
 def is_ddt_child ( self ) :
  if ( self . map_server_child ) : return ( False )
  if ( self . map_server_peer ) : return ( False )
  return ( True )
  if 31 - 31: I11i / OoOoOO00 + o0oOOo0O0Ooo
  if 80 - 80: Oo0Ooo
 def is_ms_child ( self ) :
  return ( self . map_server_child )
  if 58 - 58: I1Ii111 + OOooOOo
  if 76 - 76: II111iiii - o0oOOo0O0Ooo % OoO0O00 + iII111i
 def is_ms_peer ( self ) :
  return ( self . map_server_peer )
  if 38 - 38: I1Ii111 - I11i * i1IIi + iIii1I11I1II1
  if 41 - 41: Ii1I . OoO0O00 + I1ii11iIi11i + OoOoOO00
  if 76 - 76: iII111i - iIii1I11I1II1
  if 23 - 23: I11i / OoO0O00 % OOooOOo
  if 9 - 9: ooOoO0o % I1ii11iIi11i . OoooooooOO + OoO0O00 % OOooOOo * OoooooooOO
  if 21 - 21: Ii1I % O0
  if 15 - 15: II111iiii * Ii1I + IiII % iII111i
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
  if 96 - 96: II111iiii * I1Ii111 / Oo0Ooo
  if 35 - 35: I1IiiI
 def print_ddt_map_request ( self ) :
  lprint ( "Queued Map-Request from {}ITR {}->{}, nonce 0x{}" . format ( "P" if self . from_pitr else "" ,
  # Ii1I + O0 - i1IIi - I11i
 red ( self . itr . print_address ( ) , False ) ,
 green ( self . eid . print_address ( ) , False ) , self . nonce ) )
  if 5 - 5: II111iiii * iII111i - o0oOOo0O0Ooo + I1IiiI % iIii1I11I1II1
  if 97 - 97: o0oOOo0O0Ooo % OoooooooOO . I1IiiI + iIii1I11I1II1
 def queue_map_request ( self ) :
  self . retransmit_timer = threading . Timer ( LISP_DDT_MAP_REQUEST_INTERVAL ,
 lisp_retransmit_ddt_map_request , [ self ] )
  self . retransmit_timer . start ( )
  lisp_ddt_map_requestQ [ str ( self . nonce ) ] = self
  if 81 - 81: OoO0O00 * ooOoO0o
  if 98 - 98: OoOoOO00 % ooOoO0o * I1ii11iIi11i
 def dequeue_map_request ( self ) :
  self . retransmit_timer . cancel ( )
  if ( lisp_ddt_map_requestQ . has_key ( str ( self . nonce ) ) ) :
   lisp_ddt_map_requestQ . pop ( str ( self . nonce ) )
   if 64 - 64: OOooOOo + I11i . ooOoO0o
   if 17 - 17: OoOoOO00 . I1Ii111
   if 10 - 10: I1ii11iIi11i * I1Ii111 * Ii1I * o0oOOo0O0Ooo - o0oOOo0O0Ooo + OoOoOO00
 def print_eid_tuple ( self ) :
  return ( lisp_print_eid_tuple ( self . eid , self . group ) )
  if 92 - 92: Ii1I / iII111i . I1ii11iIi11i % Ii1I
  if 18 - 18: OOooOOo + I1IiiI + i1IIi + o0oOOo0O0Ooo % o0oOOo0O0Ooo
  if 48 - 48: O0
  if 5 - 5: OOooOOo / i11iIiiIii . I11i % OOooOOo
  if 1 - 1: II111iiii + O0 * OoOoOO00 / IiII . O0
  if 87 - 87: IiII + I1IiiI
  if 74 - 74: OoO0O00 + OoO0O00 % iII111i / I11i / O0
  if 54 - 54: o0oOOo0O0Ooo / OoooooooOO * ooOoO0o . OoOoOO00 - I1Ii111
  if 69 - 69: oO0o - OoO0O00
  if 80 - 80: ooOoO0o + iIii1I11I1II1 . II111iiii + I1IiiI - oO0o % OoOoOO00
  if 10 - 10: iIii1I11I1II1
  if 44 - 44: OoOoOO00 * oO0o . I1ii11iIi11i + i11iIiiIii
  if 85 - 85: I11i
  if 36 - 36: ooOoO0o % OoO0O00
  if 1 - 1: OoooooooOO - OoOoOO00
  if 35 - 35: I1Ii111
  if 35 - 35: Oo0Ooo - iIii1I11I1II1 / i1IIi + OoO0O00 - OoooooooOO / i11iIiiIii
  if 79 - 79: I1IiiI * ooOoO0o * ooOoO0o
  if 92 - 92: iII111i % I1ii11iIi11i
  if 16 - 16: oO0o
LISP_DDT_ACTION_SITE_NOT_FOUND = - 2
LISP_DDT_ACTION_NULL = - 1
LISP_DDT_ACTION_NODE_REFERRAL = 0
LISP_DDT_ACTION_MS_REFERRAL = 1
LISP_DDT_ACTION_MS_ACK = 2
LISP_DDT_ACTION_MS_NOT_REG = 3
LISP_DDT_ACTION_DELEGATION_HOLE = 4
LISP_DDT_ACTION_NOT_AUTH = 5
LISP_DDT_ACTION_MAX = LISP_DDT_ACTION_NOT_AUTH
if 52 - 52: OoooooooOO % ooOoO0o - I1Ii111 * I11i
lisp_map_referral_action_string = [
 "node-referral" , "ms-referral" , "ms-ack" , "ms-not-registered" ,
 "delegation-hole" , "not-authoritative" ]
if 24 - 24: Ii1I + IiII + OoooooooOO / oO0o / I1IiiI + IiII
if 52 - 52: ooOoO0o
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
if 47 - 47: i11iIiiIii + iIii1I11I1II1 % I1ii11iIi11i - oO0o % OoO0O00
if 85 - 85: oO0o * OoOoOO00 / OoOoOO00
if 85 - 85: OOooOOo / I1Ii111 . i1IIi / OoOoOO00 + iIii1I11I1II1
if 71 - 71: OoO0O00
if 96 - 96: I1ii11iIi11i / I1IiiI - I1ii11iIi11i / II111iiii - IiII
if 74 - 74: Ii1I * OoooooooOO % OOooOOo + OoooooooOO + iII111i
if 83 - 83: i1IIi
if 2 - 2: i1IIi / OOooOOo * O0
if 99 - 99: OoooooooOO . OoOoOO00 / II111iiii
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
if 68 - 68: IiII - i1IIi % IiII . OoO0O00 . i11iIiiIii . OoooooooOO
if 32 - 32: iII111i + OoO0O00 % IiII + I1IiiI
if 69 - 69: I1Ii111 + I11i - iIii1I11I1II1 - II111iiii . Ii1I
if 74 - 74: I1ii11iIi11i % o0oOOo0O0Ooo + O0 - i11iIiiIii - IiII % OOooOOo
if 39 - 39: OoO0O00 - o0oOOo0O0Ooo
if 71 - 71: iII111i . OoO0O00 + ooOoO0o - OOooOOo - Oo0Ooo
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
if 16 - 16: OOooOOo . Oo0Ooo . I1IiiI % O0 . I1ii11iIi11i + i11iIiiIii
if 100 - 100: I1ii11iIi11i - i1IIi - OoO0O00 * o0oOOo0O0Ooo + OoOoOO00
if 31 - 31: i1IIi
if 21 - 21: o0oOOo0O0Ooo / O0 % O0 . OoooooooOO / I1IiiI
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
  if 94 - 94: ooOoO0o + OoO0O00 / ooOoO0o - ooOoO0o + Oo0Ooo + o0oOOo0O0Ooo
  if 50 - 50: oO0o . Oo0Ooo
 def print_info ( self ) :
  if ( self . info_reply ) :
   iIiiii1iI1I = "Info-Reply"
   I1IIiIIIii = ( ", ms-port: {}, etr-port: {}, global-rloc: {}, " + "ms-rloc: {}, private-rloc: {}, RTR-list: " ) . format ( self . ms_port , self . etr_port ,
   # OoooooooOO * Oo0Ooo . i11iIiiIii - I1Ii111 / OoooooooOO * IiII
   # O0 . i11iIiiIii + iIii1I11I1II1 - I1ii11iIi11i / I1ii11iIi11i + Ii1I
 red ( self . global_etr_rloc . print_address_no_iid ( ) , False ) ,
 red ( self . global_ms_rloc . print_address_no_iid ( ) , False ) ,
 red ( self . private_etr_rloc . print_address_no_iid ( ) , False ) )
   if ( len ( self . rtr_list ) == 0 ) : I1IIiIIIii += "empty, "
   for IIiiiIiI1 in self . rtr_list :
    I1IIiIIIii += red ( IIiiiIiI1 . print_address_no_iid ( ) , False ) + ", "
    if 86 - 86: iIii1I11I1II1 . Ii1I
   I1IIiIIIii = I1IIiIIIii [ 0 : - 2 ]
  else :
   iIiiii1iI1I = "Info-Request"
   III1i = "<none>" if self . hostname == None else self . hostname
   I1IIiIIIii = ", hostname: {}" . format ( blue ( III1i , False ) )
   if 47 - 47: i11iIiiIii / iII111i * IiII
  lprint ( "{} -> nonce: 0x{}{}" . format ( bold ( iIiiii1iI1I , False ) ,
 lisp_hex_string ( self . nonce ) , I1IIiIIIii ) )
  if 92 - 92: OoooooooOO
  if 68 - 68: I1Ii111 % oO0o % I1ii11iIi11i / i11iIiiIii
 def encode ( self ) :
  iII = ( LISP_NAT_INFO << 28 )
  if ( self . info_reply ) : iII |= ( 1 << 27 )
  if 9 - 9: Ii1I * IiII
  if 57 - 57: iII111i % oO0o % iII111i % OOooOOo + I1ii11iIi11i
  if 89 - 89: I1ii11iIi11i + II111iiii % i1IIi * O0 . Ii1I
  if 52 - 52: IiII
  if 86 - 86: I1Ii111 / O0 + OoooooooOO % oO0o
  IiiiIi1iiii11 = struct . pack ( "I" , socket . htonl ( iII ) )
  IiiiIi1iiii11 += struct . pack ( "Q" , self . nonce )
  IiiiIi1iiii11 += struct . pack ( "III" , 0 , 0 , 0 )
  if 45 - 45: I1IiiI . Oo0Ooo . I11i . Ii1I
  if 81 - 81: II111iiii + OoOoOO00 % i11iIiiIii / iII111i . I1Ii111 + II111iiii
  if 48 - 48: I1IiiI . I1ii11iIi11i * OoOoOO00 % i1IIi / I1Ii111 * II111iiii
  if 62 - 62: o0oOOo0O0Ooo * I1Ii111 . iIii1I11I1II1 / i1IIi
  if ( self . info_reply == False ) :
   if ( self . hostname == None ) :
    IiiiIi1iiii11 += struct . pack ( "H" , 0 )
   else :
    IiiiIi1iiii11 += struct . pack ( "H" , socket . htons ( LISP_AFI_NAME ) )
    IiiiIi1iiii11 += self . hostname + "\0"
    if 75 - 75: OoooooooOO / ooOoO0o - iII111i . OoooooooOO . OoOoOO00 % i1IIi
   return ( IiiiIi1iiii11 )
   if 7 - 7: OoOoOO00 . i1IIi * i11iIiiIii % i11iIiiIii
   if 54 - 54: OoO0O00 / I1IiiI . Oo0Ooo
   if 39 - 39: OoO0O00 . ooOoO0o
   if 41 - 41: Oo0Ooo * I1ii11iIi11i - II111iiii - II111iiii
   if 7 - 7: oO0o
  O0ooo0 = socket . htons ( LISP_AFI_LCAF )
  iI1IIiI111iII = LISP_LCAF_NAT_TYPE
  oOOO0O000Oo = socket . htons ( 16 )
  i1II1I11iIIii = socket . htons ( self . ms_port )
  II = socket . htons ( self . etr_port )
  IiiiIi1iiii11 += struct . pack ( "HHBBHHHH" , O0ooo0 , 0 , iI1IIiI111iII , 0 , oOOO0O000Oo ,
 i1II1I11iIIii , II , socket . htons ( self . global_etr_rloc . afi ) )
  IiiiIi1iiii11 += self . global_etr_rloc . pack_address ( )
  IiiiIi1iiii11 += struct . pack ( "HH" , 0 , socket . htons ( self . private_etr_rloc . afi ) )
  IiiiIi1iiii11 += self . private_etr_rloc . pack_address ( )
  if ( len ( self . rtr_list ) == 0 ) : IiiiIi1iiii11 += struct . pack ( "H" , 0 )
  if 12 - 12: I1ii11iIi11i + iII111i % II111iiii * I1Ii111 . II111iiii / I1Ii111
  if 82 - 82: OoO0O00 - i1IIi / OOooOOo
  if 31 - 31: I11i + I1Ii111 + ooOoO0o / OoOoOO00
  if 68 - 68: Oo0Ooo % IiII * I1IiiI % I1ii11iIi11i % OoooooooOO
  for IIiiiIiI1 in self . rtr_list :
   IiiiIi1iiii11 += struct . pack ( "H" , socket . htons ( IIiiiIiI1 . afi ) )
   IiiiIi1iiii11 += IIiiiIiI1 . pack_address ( )
   if 63 - 63: Oo0Ooo / I11i . iII111i + ooOoO0o / I1ii11iIi11i / I1IiiI
  return ( IiiiIi1iiii11 )
  if 43 - 43: OoOoOO00 / I1Ii111 % I11i / I1IiiI - IiII - ooOoO0o
  if 25 - 25: OOooOOo * OoOoOO00 + I11i . ooOoO0o
 def decode ( self , packet ) :
  OoO = packet
  i1I1iii1I11II = "I"
  Iiiii = struct . calcsize ( i1I1iii1I11II )
  if ( len ( packet ) < Iiiii ) : return ( None )
  if 96 - 96: iIii1I11I1II1 / Ii1I
  iII = struct . unpack ( i1I1iii1I11II , packet [ : Iiiii ] )
  iII = iII [ 0 ]
  packet = packet [ Iiiii : : ]
  if 92 - 92: OoO0O00 * I1ii11iIi11i + iIii1I11I1II1
  i1I1iii1I11II = "Q"
  Iiiii = struct . calcsize ( i1I1iii1I11II )
  if ( len ( packet ) < Iiiii ) : return ( None )
  if 88 - 88: iIii1I11I1II1 + iIii1I11I1II1 * i11iIiiIii . I1ii11iIi11i % oO0o
  Iii11I = struct . unpack ( i1I1iii1I11II , packet [ : Iiiii ] )
  if 94 - 94: I1IiiI / I1ii11iIi11i / OOooOOo
  iII = socket . ntohl ( iII )
  self . nonce = Iii11I [ 0 ]
  self . info_reply = iII & 0x08000000
  self . hostname = None
  packet = packet [ Iiiii : : ]
  if 45 - 45: II111iiii
  if 98 - 98: i11iIiiIii + I1ii11iIi11i * OOooOOo / OoOoOO00
  if 84 - 84: o0oOOo0O0Ooo
  if 40 - 40: OoooooooOO - oO0o / O0 * I1Ii111 . O0 + i11iIiiIii
  if 9 - 9: OOooOOo % O0 % O0 / I1ii11iIi11i . II111iiii / II111iiii
  i1I1iii1I11II = "HH"
  Iiiii = struct . calcsize ( i1I1iii1I11II )
  if ( len ( packet ) < Iiiii ) : return ( None )
  if 78 - 78: iIii1I11I1II1 - i1IIi . I11i . o0oOOo0O0Ooo
  if 66 - 66: OOooOOo * Oo0Ooo
  if 58 - 58: OOooOOo
  if 96 - 96: IiII % OoooooooOO + O0 * II111iiii / OOooOOo . I1Ii111
  if 47 - 47: OoO0O00 - Oo0Ooo * OoO0O00 / oO0o
  I1I1I1 , II111iiI1Ii1 = struct . unpack ( i1I1iii1I11II , packet [ : Iiiii ] )
  if ( II111iiI1Ii1 != 0 ) : return ( None )
  if 13 - 13: ooOoO0o
  packet = packet [ Iiiii : : ]
  i1I1iii1I11II = "IBBH"
  Iiiii = struct . calcsize ( i1I1iii1I11II )
  if ( len ( packet ) < Iiiii ) : return ( None )
  if 55 - 55: i1IIi . I11i . II111iiii + O0 + ooOoO0o - i1IIi
  oOoooOOO0o0 , i1o00Oo , iiIII , Ii1IiiiIi = struct . unpack ( i1I1iii1I11II ,
 packet [ : Iiiii ] )
  if 58 - 58: I1IiiI / Ii1I
  if ( Ii1IiiiIi != 0 ) : return ( None )
  packet = packet [ Iiiii : : ]
  if 54 - 54: OoO0O00 - iIii1I11I1II1 + oO0o + II111iiii + I1ii11iIi11i * iII111i
  if 17 - 17: oO0o / Ii1I
  if 26 - 26: ooOoO0o / I11i % I11i + o0oOOo0O0Ooo - IiII
  if 89 - 89: Ii1I
  if ( self . info_reply == False ) :
   i1I1iii1I11II = "H"
   Iiiii = struct . calcsize ( i1I1iii1I11II )
   if ( len ( packet ) >= Iiiii ) :
    O0ooo0 = struct . unpack ( i1I1iii1I11II , packet [ : Iiiii ] ) [ 0 ]
    if ( socket . ntohs ( O0ooo0 ) == LISP_AFI_NAME ) :
     packet = packet [ Iiiii : : ]
     packet , self . hostname = lisp_decode_dist_name ( packet )
     if 23 - 23: II111iiii
     if 61 - 61: OoOoOO00 / I1IiiI . I1ii11iIi11i % OOooOOo
   return ( OoO )
   if 70 - 70: OOooOOo * OoOoOO00 / oO0o + Oo0Ooo / O0
   if 16 - 16: Oo0Ooo / OoooooooOO / IiII + Oo0Ooo * i11iIiiIii
   if 15 - 15: o0oOOo0O0Ooo / i11iIiiIii
   if 63 - 63: I1ii11iIi11i - Ii1I + I11i
   if 98 - 98: iII111i / IiII * I1IiiI / oO0o - iIii1I11I1II1
  i1I1iii1I11II = "HHBBHHH"
  Iiiii = struct . calcsize ( i1I1iii1I11II )
  if ( len ( packet ) < Iiiii ) : return ( None )
  if 72 - 72: O0 . OOooOOo
  O0ooo0 , O0O , iI1IIiI111iII , i1o00Oo , oOOO0O000Oo , i1II1I11iIIii , II = struct . unpack ( i1I1iii1I11II , packet [ : Iiiii ] )
  if 99 - 99: i1IIi + iIii1I11I1II1 - ooOoO0o + OoO0O00 + Oo0Ooo . I1ii11iIi11i
  if 74 - 74: i1IIi
  if ( socket . ntohs ( O0ooo0 ) != LISP_AFI_LCAF ) : return ( None )
  if 80 - 80: ooOoO0o + I1Ii111 . I1ii11iIi11i % OoooooooOO
  self . ms_port = socket . ntohs ( i1II1I11iIIii )
  self . etr_port = socket . ntohs ( II )
  packet = packet [ Iiiii : : ]
  if 26 - 26: OoOoOO00 . iII111i * iIii1I11I1II1 / IiII
  if 69 - 69: OoooooooOO / I11i + Ii1I * II111iiii
  if 35 - 35: i11iIiiIii + oO0o
  if 85 - 85: OoOoOO00 . O0 % OoooooooOO % oO0o
  i1I1iii1I11II = "H"
  Iiiii = struct . calcsize ( i1I1iii1I11II )
  if ( len ( packet ) < Iiiii ) : return ( None )
  if 43 - 43: I1IiiI - I11i . I1IiiI / i11iIiiIii % IiII * i11iIiiIii
  if 12 - 12: II111iiii - iIii1I11I1II1
  if 43 - 43: i11iIiiIii % OoO0O00
  if 100 - 100: i1IIi
  O0ooo0 = struct . unpack ( i1I1iii1I11II , packet [ : Iiiii ] ) [ 0 ]
  packet = packet [ Iiiii : : ]
  if ( O0ooo0 != 0 ) :
   self . global_etr_rloc . afi = socket . ntohs ( O0ooo0 )
   packet = self . global_etr_rloc . unpack_address ( packet )
   if ( packet == None ) : return ( None )
   self . global_etr_rloc . mask_len = self . global_etr_rloc . host_mask_len ( )
   if 4 - 4: i11iIiiIii - OOooOOo * IiII % OoooooooOO - OoOoOO00
   if 81 - 81: Ii1I * ooOoO0o . oO0o . IiII
   if 71 - 71: IiII + OoO0O00
   if 39 - 39: I1IiiI % IiII / II111iiii / II111iiii
   if 95 - 95: II111iiii + i11iIiiIii + o0oOOo0O0Ooo
   if 30 - 30: O0 - O0 % iIii1I11I1II1 + iII111i * OoooooooOO
  if ( len ( packet ) < Iiiii ) : return ( OoO )
  if 1 - 1: O0
  O0ooo0 = struct . unpack ( i1I1iii1I11II , packet [ : Iiiii ] ) [ 0 ]
  packet = packet [ Iiiii : : ]
  if ( O0ooo0 != 0 ) :
   self . global_ms_rloc . afi = socket . ntohs ( O0ooo0 )
   packet = self . global_ms_rloc . unpack_address ( packet )
   if ( packet == None ) : return ( OoO )
   self . global_ms_rloc . mask_len = self . global_ms_rloc . host_mask_len ( )
   if 36 - 36: oO0o . iII111i
   if 62 - 62: I11i + iIii1I11I1II1 % I11i * OOooOOo + iIii1I11I1II1 % Ii1I
   if 56 - 56: o0oOOo0O0Ooo
   if 55 - 55: oO0o - I1Ii111 / ooOoO0o % I1IiiI * OoooooooOO * I1IiiI
   if 88 - 88: Ii1I + O0
  if ( len ( packet ) < Iiiii ) : return ( OoO )
  if 92 - 92: I1IiiI % iII111i % I11i + OoooooooOO - i11iIiiIii
  O0ooo0 = struct . unpack ( i1I1iii1I11II , packet [ : Iiiii ] ) [ 0 ]
  packet = packet [ Iiiii : : ]
  if ( O0ooo0 != 0 ) :
   self . private_etr_rloc . afi = socket . ntohs ( O0ooo0 )
   packet = self . private_etr_rloc . unpack_address ( packet )
   if ( packet == None ) : return ( OoO )
   self . private_etr_rloc . mask_len = self . private_etr_rloc . host_mask_len ( )
   if 9 - 9: i11iIiiIii - II111iiii / ooOoO0o
   if 81 - 81: i11iIiiIii % OoOoOO00 % OoO0O00 * Ii1I
   if 85 - 85: OoooooooOO * ooOoO0o
   if 23 - 23: OOooOOo / I11i / OoooooooOO - Ii1I / OoO0O00 - OoO0O00
   if 60 - 60: OOooOOo . ooOoO0o % i1IIi % Ii1I % ooOoO0o + OoO0O00
   if 26 - 26: O0 % o0oOOo0O0Ooo + iII111i * I1ii11iIi11i * I1Ii111
  while ( len ( packet ) >= Iiiii ) :
   O0ooo0 = struct . unpack ( i1I1iii1I11II , packet [ : Iiiii ] ) [ 0 ]
   packet = packet [ Iiiii : : ]
   if ( O0ooo0 == 0 ) : continue
   IIiiiIiI1 = lisp_address ( socket . ntohs ( O0ooo0 ) , "" , 0 , 0 )
   packet = IIiiiIiI1 . unpack_address ( packet )
   if ( packet == None ) : return ( OoO )
   IIiiiIiI1 . mask_len = IIiiiIiI1 . host_mask_len ( )
   self . rtr_list . append ( IIiiiIiI1 )
   if 4 - 4: OOooOOo * OoooooooOO * i1IIi % I1ii11iIi11i % Oo0Ooo
  return ( OoO )
  if 1 - 1: OoO0O00 / iIii1I11I1II1 % I1ii11iIi11i - o0oOOo0O0Ooo
  if 62 - 62: I1Ii111 % II111iiii
  if 91 - 91: I11i % Ii1I - IiII + iIii1I11I1II1 * iIii1I11I1II1
class lisp_nat_info ( ) :
 def __init__ ( self , addr_str , hostname , port ) :
  self . address = addr_str
  self . hostname = hostname
  self . port = port
  self . uptime = lisp_get_timestamp ( )
  if 91 - 91: i11iIiiIii + Ii1I
  if 85 - 85: I11i % IiII
 def timed_out ( self ) :
  oO000o0Oo00 = time . time ( ) - self . uptime
  return ( oO000o0Oo00 >= ( LISP_INFO_INTERVAL * 2 ) )
  if 68 - 68: Oo0Ooo . I1Ii111 - o0oOOo0O0Ooo * iIii1I11I1II1 - II111iiii % i1IIi
  if 58 - 58: I11i / i11iIiiIii * i11iIiiIii
  if 24 - 24: ooOoO0o - I1Ii111 * II111iiii - II111iiii
class lisp_info_source ( ) :
 def __init__ ( self , hostname , addr_str , port ) :
  self . address = lisp_address ( LISP_AFI_IPV4 , addr_str , 32 , 0 )
  self . port = port
  self . uptime = lisp_get_timestamp ( )
  self . nonce = None
  self . hostname = hostname
  self . no_timeout = False
  if 47 - 47: IiII - iIii1I11I1II1 / OoOoOO00 * iII111i - iIii1I11I1II1 % oO0o
  if 93 - 93: Ii1I / iII111i
 def cache_address_for_info_source ( self ) :
  Oo000O000 = self . address . print_address_no_iid ( ) + self . hostname
  lisp_info_sources_by_address [ Oo000O000 ] = self
  if 100 - 100: Oo0Ooo
  if 94 - 94: I1ii11iIi11i / i1IIi * I1IiiI - I11i - I1ii11iIi11i
 def cache_nonce_for_info_source ( self , nonce ) :
  self . nonce = nonce
  lisp_info_sources_by_nonce [ nonce ] = self
  if 6 - 6: I1ii11iIi11i % o0oOOo0O0Ooo + o0oOOo0O0Ooo / OOooOOo / I1IiiI
  if 67 - 67: OoOoOO00 . iII111i / OOooOOo * ooOoO0o + i1IIi
  if 100 - 100: OOooOOo . ooOoO0o + I1Ii111 . oO0o
  if 20 - 20: i11iIiiIii - i1IIi - iIii1I11I1II1 - OoooooooOO
  if 72 - 72: I1Ii111 . OoO0O00
  if 59 - 59: I1IiiI * I11i % i1IIi
  if 77 - 77: OOooOOo * OoooooooOO + I1IiiI + I1IiiI % oO0o . OoooooooOO
  if 60 - 60: iIii1I11I1II1
  if 13 - 13: II111iiii + Ii1I
  if 33 - 33: i1IIi
  if 36 - 36: ooOoO0o % ooOoO0o . i11iIiiIii
def lisp_concat_auth_data ( alg_id , auth1 , auth2 , auth3 , auth4 ) :
 if 42 - 42: OoO0O00 . I1Ii111 / Ii1I
 if ( lisp_is_x86 ( ) ) :
  if ( auth1 != "" ) : auth1 = byte_swap_64 ( auth1 )
  if ( auth2 != "" ) : auth2 = byte_swap_64 ( auth2 )
  if ( auth3 != "" ) :
   if ( alg_id == LISP_SHA_1_96_ALG_ID ) : auth3 = socket . ntohl ( auth3 )
   else : auth3 = byte_swap_64 ( auth3 )
   if 57 - 57: iIii1I11I1II1 % I1ii11iIi11i . OOooOOo / oO0o . OoOoOO00
  if ( auth4 != "" ) : auth4 = byte_swap_64 ( auth4 )
  if 74 - 74: I1IiiI * OoO0O00 + OoooooooOO * ooOoO0o . oO0o
  if 66 - 66: II111iiii + OOooOOo + i11iIiiIii / II111iiii
 if ( alg_id == LISP_SHA_1_96_ALG_ID ) :
  auth1 = lisp_hex_string ( auth1 )
  auth1 = auth1 . zfill ( 16 )
  auth2 = lisp_hex_string ( auth2 )
  auth2 = auth2 . zfill ( 16 )
  auth3 = lisp_hex_string ( auth3 )
  auth3 = auth3 . zfill ( 8 )
  oooO = auth1 + auth2 + auth3
  if 37 - 37: I1IiiI + OoO0O00 . OoO0O00 % OoOoOO00 + o0oOOo0O0Ooo
 if ( alg_id == LISP_SHA_256_128_ALG_ID ) :
  auth1 = lisp_hex_string ( auth1 )
  auth1 = auth1 . zfill ( 16 )
  auth2 = lisp_hex_string ( auth2 )
  auth2 = auth2 . zfill ( 16 )
  auth3 = lisp_hex_string ( auth3 )
  auth3 = auth3 . zfill ( 16 )
  auth4 = lisp_hex_string ( auth4 )
  auth4 = auth4 . zfill ( 16 )
  oooO = auth1 + auth2 + auth3 + auth4
  if 81 - 81: i1IIi % iIii1I11I1II1
 return ( oooO )
 if 41 - 41: oO0o - iII111i / o0oOOo0O0Ooo . iII111i % Oo0Ooo + OOooOOo
 if 82 - 82: ooOoO0o
 if 89 - 89: OOooOOo / I1ii11iIi11i . I1IiiI + i11iIiiIii
 if 11 - 11: oO0o . i11iIiiIii * ooOoO0o % OoooooooOO % O0
 if 59 - 59: i11iIiiIii / OoO0O00
 if 48 - 48: iIii1I11I1II1
 if 19 - 19: oO0o
 if 69 - 69: I1ii11iIi11i % iII111i - OoooooooOO % Ii1I * oO0o
 if 12 - 12: OoOoOO00 / I1Ii111 . O0 . IiII - OOooOOo - OoO0O00
 if 28 - 28: II111iiii . OoOoOO00 - o0oOOo0O0Ooo
def lisp_open_listen_socket ( local_addr , port ) :
 if ( port . isdigit ( ) ) :
  if ( local_addr . find ( "." ) != - 1 ) :
   O0oooO00oo0O = socket . socket ( socket . AF_INET , socket . SOCK_DGRAM )
   if 58 - 58: II111iiii
  if ( local_addr . find ( ":" ) != - 1 ) :
   if ( lisp_is_raspbian ( ) ) : return ( None )
   O0oooO00oo0O = socket . socket ( socket . AF_INET6 , socket . SOCK_DGRAM )
   if 42 - 42: I1IiiI - II111iiii % OoO0O00
  O0oooO00oo0O . bind ( ( local_addr , int ( port ) ) )
 else :
  IiIIO0 = port
  if ( os . path . exists ( IiIIO0 ) ) :
   os . system ( "rm " + IiIIO0 )
   time . sleep ( 1 )
   if 85 - 85: i11iIiiIii % iII111i + II111iiii
  O0oooO00oo0O = socket . socket ( socket . AF_UNIX , socket . SOCK_DGRAM )
  O0oooO00oo0O . bind ( IiIIO0 )
  if 16 - 16: ooOoO0o * OoOoOO00 / OoOoOO00 + II111iiii
 return ( O0oooO00oo0O )
 if 50 - 50: OoO0O00 / OOooOOo % I1IiiI / Ii1I + OoO0O00 . iIii1I11I1II1
 if 62 - 62: I1Ii111 + OoooooooOO - Ii1I - iIii1I11I1II1
 if 80 - 80: OoO0O00
 if 72 - 72: II111iiii % i11iIiiIii + OoOoOO00 / I1Ii111 - i11iIiiIii
 if 39 - 39: i11iIiiIii - OOooOOo / OoO0O00 * OoOoOO00 / IiII
 if 84 - 84: I1ii11iIi11i . iIii1I11I1II1 / Ii1I / II111iiii
 if 56 - 56: OOooOOo * iII111i / Ii1I
def lisp_open_send_socket ( internal_name , afi ) :
 if ( internal_name == "" ) :
  if ( afi == LISP_AFI_IPV4 ) :
   O0oooO00oo0O = socket . socket ( socket . AF_INET , socket . SOCK_DGRAM )
   if 9 - 9: I1ii11iIi11i * i11iIiiIii / I1Ii111 + iIii1I11I1II1
  if ( afi == LISP_AFI_IPV6 ) :
   if ( lisp_is_raspbian ( ) ) : return ( None )
   O0oooO00oo0O = socket . socket ( socket . AF_INET6 , socket . SOCK_DGRAM )
   if 1 - 1: OoO0O00 % iIii1I11I1II1 * OoOoOO00 / oO0o
 else :
  if ( os . path . exists ( internal_name ) ) : os . system ( "rm " + internal_name )
  O0oooO00oo0O = socket . socket ( socket . AF_UNIX , socket . SOCK_DGRAM )
  O0oooO00oo0O . bind ( internal_name )
  if 73 - 73: iII111i
 return ( O0oooO00oo0O )
 if 6 - 6: o0oOOo0O0Ooo + Oo0Ooo
 if 45 - 45: oO0o % O0 / O0
 if 98 - 98: I1Ii111
 if 58 - 58: OOooOOo
 if 6 - 6: I1ii11iIi11i
 if 37 - 37: i11iIiiIii . II111iiii + OOooOOo + i1IIi * OOooOOo
 if 18 - 18: ooOoO0o
def lisp_close_socket ( sock , internal_name ) :
 sock . close ( )
 if ( os . path . exists ( internal_name ) ) : os . system ( "rm " + internal_name )
 return
 if 18 - 18: I1Ii111 + OoOoOO00 % OOooOOo - IiII - i1IIi + I1ii11iIi11i
 if 33 - 33: I11i * Ii1I / Oo0Ooo + oO0o % OOooOOo % OoooooooOO
 if 29 - 29: Ii1I . II111iiii / I1Ii111
 if 79 - 79: IiII . OoOoOO00 / oO0o % OoO0O00 / Ii1I + I11i
 if 78 - 78: o0oOOo0O0Ooo + I1Ii111 % i11iIiiIii % I1IiiI - Ii1I
 if 81 - 81: i11iIiiIii - II111iiii + I11i
 if 52 - 52: II111iiii
 if 62 - 62: iII111i / OoO0O00 + i11iIiiIii / Oo0Ooo
def lisp_is_running ( node ) :
 return ( True if ( os . path . exists ( node ) ) else False )
 if 26 - 26: I1ii11iIi11i - OoO0O00
 if 19 - 19: iIii1I11I1II1 / I1ii11iIi11i + O0
 if 12 - 12: I11i . OOooOOo + o0oOOo0O0Ooo . OoO0O00 + o0oOOo0O0Ooo
 if 56 - 56: i1IIi / i1IIi . OoO0O00 % i1IIi - OoOoOO00 % OOooOOo
 if 66 - 66: i11iIiiIii * IiII % IiII . I1IiiI / ooOoO0o
 if 50 - 50: IiII . iII111i / o0oOOo0O0Ooo % OoOoOO00 * IiII % I11i
 if 15 - 15: Ii1I
 if 29 - 29: I11i / I1IiiI / OoooooooOO . OoOoOO00 / I11i . I1Ii111
 if 69 - 69: O0 * OoOoOO00 + o0oOOo0O0Ooo + I1IiiI % iII111i . OoooooooOO
def lisp_packet_ipc ( packet , source , sport ) :
 return ( ( "packet@" + str ( len ( packet ) ) + "@" + source + "@" + str ( sport ) + "@" + packet ) )
 if 45 - 45: I1Ii111 + oO0o - o0oOOo0O0Ooo - OoOoOO00 + I1IiiI / II111iiii
 if 46 - 46: II111iiii . iIii1I11I1II1
 if 62 - 62: I1ii11iIi11i % i1IIi % I1Ii111 * ooOoO0o % OOooOOo + I1IiiI
 if 100 - 100: II111iiii - o0oOOo0O0Ooo * OoooooooOO . ooOoO0o / II111iiii / oO0o
 if 43 - 43: iIii1I11I1II1 + ooOoO0o * iII111i + iIii1I11I1II1 . I1Ii111
 if 87 - 87: I1Ii111
 if 47 - 47: II111iiii + I1IiiI . Oo0Ooo / iIii1I11I1II1
 if 14 - 14: i1IIi / OoO0O00 / iII111i % I1Ii111
 if 72 - 72: OoO0O00 . II111iiii - IiII + IiII + iIii1I11I1II1 % oO0o
def lisp_control_packet_ipc ( packet , source , dest , dport ) :
 return ( "control-packet@" + dest + "@" + str ( dport ) + "@" + packet )
 if 21 - 21: iII111i + OoOoOO00 - i11iIiiIii % O0 + OOooOOo
 if 30 - 30: o0oOOo0O0Ooo - Oo0Ooo + iII111i / O0
 if 94 - 94: IiII
 if 69 - 69: I1Ii111 . I1Ii111
 if 53 - 53: i11iIiiIii + iII111i * Oo0Ooo - I1Ii111
 if 61 - 61: o0oOOo0O0Ooo / OOooOOo . II111iiii - I1IiiI * i11iIiiIii
 if 8 - 8: iII111i % o0oOOo0O0Ooo
def lisp_data_packet_ipc ( packet , source ) :
 return ( "data-packet@" + str ( len ( packet ) ) + "@" + source + "@@" + packet )
 if 87 - 87: Ii1I % I11i / I1Ii111
 if 21 - 21: OoO0O00 + Ii1I / I1Ii111
 if 75 - 75: I1Ii111 . Ii1I % iIii1I11I1II1 / OoOoOO00
 if 38 - 38: i1IIi
 if 1 - 1: I1ii11iIi11i + OoO0O00 % I11i . OOooOOo + i1IIi / oO0o
 if 35 - 35: ooOoO0o % OoOoOO00 % OoO0O00 + OOooOOo / IiII * OoOoOO00
 if 65 - 65: I1IiiI . Oo0Ooo + i1IIi - Ii1I * i1IIi
 if 64 - 64: I1IiiI / OoO0O00 * I1IiiI * II111iiii . Ii1I
 if 98 - 98: I1Ii111 + o0oOOo0O0Ooo
def lisp_command_ipc ( packet , source ) :
 return ( "command@" + str ( len ( packet ) ) + "@" + source + "@@" + packet )
 if 73 - 73: I1ii11iIi11i / I1Ii111 + i11iIiiIii + OoO0O00 . ooOoO0o
 if 54 - 54: I1ii11iIi11i + IiII - oO0o + Oo0Ooo / IiII % Oo0Ooo
 if 2 - 2: OOooOOo / I11i * I11i + I11i / O0 - OOooOOo
 if 29 - 29: OoOoOO00 + i11iIiiIii % OoO0O00 - OoooooooOO
 if 68 - 68: iII111i / OOooOOo
 if 28 - 28: II111iiii
 if 49 - 49: I1ii11iIi11i
 if 33 - 33: iIii1I11I1II1
 if 72 - 72: I1ii11iIi11i * i11iIiiIii
def lisp_api_ipc ( source , data ) :
 return ( "api@" + str ( len ( data ) ) + "@" + source + "@@" + data )
 if 12 - 12: O0 - iIii1I11I1II1 % Oo0Ooo / O0 - IiII
 if 55 - 55: OOooOOo . Oo0Ooo * OoOoOO00 / OoooooooOO * i11iIiiIii + oO0o
 if 45 - 45: Ii1I
 if 8 - 8: oO0o + OOooOOo
 if 37 - 37: IiII - OoOoOO00 + oO0o - Oo0Ooo + IiII
 if 33 - 33: Oo0Ooo % oO0o - I1IiiI + Oo0Ooo
 if 90 - 90: I1ii11iIi11i * I1Ii111 - iIii1I11I1II1 % IiII * I1Ii111 . I1Ii111
 if 90 - 90: o0oOOo0O0Ooo - O0 % O0 - oO0o . OoooooooOO
 if 30 - 30: I11i + O0 / Ii1I / OoOoOO00 - oO0o + II111iiii
def lisp_ipc ( packet , send_socket , node ) :
 if 21 - 21: iIii1I11I1II1 % OoooooooOO * OOooOOo % i1IIi
 if 73 - 73: OoooooooOO
 if 100 - 100: I11i / i1IIi / i1IIi % Ii1I - II111iiii . OoooooooOO
 if 72 - 72: Oo0Ooo * OoooooooOO % I1IiiI + I11i - II111iiii
 if ( lisp_is_running ( node ) == False ) :
  lprint ( "Suppress sending IPC to {}" . format ( node ) )
  return
  if 82 - 82: iIii1I11I1II1 / i1IIi * I1IiiI . i11iIiiIii
  if 56 - 56: Ii1I * I1IiiI / ooOoO0o * II111iiii
 ooO0OOoo0ooo = 1500 if ( packet . find ( "control-packet" ) == - 1 ) else 9000
 if 17 - 17: OOooOOo
 OoO00oo00 = 0
 IiiI1iii1iIiiI = len ( packet )
 iiIi = 0
 IiIIiII1iiI11 = .001
 while ( IiiI1iii1iIiiI > 0 ) :
  iiII1iIi11 = min ( IiiI1iii1iIiiI , ooO0OOoo0ooo )
  o000oOoO00ooO = packet [ OoO00oo00 : iiII1iIi11 + OoO00oo00 ]
  if 77 - 77: IiII / iIii1I11I1II1
  try :
   send_socket . sendto ( o000oOoO00ooO , node )
   lprint ( "Send IPC {}-out-of-{} byte to {} succeeded" . format ( len ( o000oOoO00ooO ) , len ( packet ) , node ) )
   if 73 - 73: IiII . ooOoO0o / Oo0Ooo / OoOoOO00 . II111iiii
   iiIi = 0
   IiIIiII1iiI11 = .001
   if 52 - 52: iII111i + I1IiiI + Oo0Ooo % OoOoOO00 * i1IIi
  except socket . error , oOo :
   if ( iiIi == 12 ) :
    lprint ( "Giving up on {}, consider it down" . format ( node ) )
    break
    if 83 - 83: Oo0Ooo / OOooOOo * o0oOOo0O0Ooo * OOooOOo . IiII
    if 75 - 75: IiII / ooOoO0o % ooOoO0o * I1ii11iIi11i % Oo0Ooo
   lprint ( "Send IPC {}-out-of-{} byte to {} failed: {}" . format ( len ( o000oOoO00ooO ) , len ( packet ) , node , oOo ) )
   if 78 - 78: Oo0Ooo
   if 47 - 47: I1ii11iIi11i
   iiIi += 1
   time . sleep ( IiIIiII1iiI11 )
   if 29 - 29: ooOoO0o * oO0o + iIii1I11I1II1 * i1IIi % i11iIiiIii + iIii1I11I1II1
   lprint ( "Retrying after {} ms ..." . format ( IiIIiII1iiI11 * 1000 ) )
   IiIIiII1iiI11 *= 2
   continue
   if 69 - 69: i11iIiiIii . I1Ii111 + i11iIiiIii / OoO0O00
   if 25 - 25: i11iIiiIii / Ii1I
  OoO00oo00 += iiII1iIi11
  IiiI1iii1iIiiI -= iiII1iIi11
  if 34 - 34: II111iiii + OOooOOo % oO0o - OOooOOo
 return
 if 25 - 25: iII111i % iIii1I11I1II1 + IiII
 if 33 - 33: OOooOOo % I1IiiI - I1IiiI / IiII
 if 22 - 22: ooOoO0o * ooOoO0o % o0oOOo0O0Ooo * Ii1I . OoO0O00
 if 55 - 55: OoOoOO00 - I1ii11iIi11i + iIii1I11I1II1 - i11iIiiIii / i1IIi / II111iiii
 if 37 - 37: Ii1I + o0oOOo0O0Ooo
 if 74 - 74: Oo0Ooo / O0 + i1IIi . I1IiiI + OoO0O00 / Oo0Ooo
 if 13 - 13: o0oOOo0O0Ooo / Ii1I . II111iiii
def lisp_format_packet ( packet ) :
 packet = binascii . hexlify ( packet )
 OoO00oo00 = 0
 O0OOOo000 = ""
 IiiI1iii1iIiiI = len ( packet ) * 2
 while ( OoO00oo00 < IiiI1iii1iIiiI ) :
  O0OOOo000 += packet [ OoO00oo00 : OoO00oo00 + 8 ] + " "
  OoO00oo00 += 8
  IiiI1iii1iIiiI -= 4
  if 8 - 8: I11i - I11i % IiII
 return ( O0OOOo000 )
 if 8 - 8: I1IiiI . IiII * O0 * o0oOOo0O0Ooo
 if 17 - 17: I1IiiI . oO0o + Oo0Ooo + I11i / o0oOOo0O0Ooo
 if 25 - 25: iII111i / iII111i % OoOoOO00 / ooOoO0o
 if 81 - 81: OOooOOo * oO0o
 if 32 - 32: Oo0Ooo * OoO0O00 + ooOoO0o . O0 * oO0o * iIii1I11I1II1
 if 50 - 50: i1IIi
 if 53 - 53: II111iiii + O0 . ooOoO0o * IiII + i1IIi
def lisp_send ( lisp_sockets , dest , port , packet ) :
 o0oO0O = lisp_sockets [ 0 ] if dest . is_ipv4 ( ) else lisp_sockets [ 1 ]
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
 ii1i1II11II1i = dest . print_address_no_iid ( )
 if ( ii1i1II11II1i . find ( "::ffff:" ) != - 1 and ii1i1II11II1i . count ( "." ) == 3 ) :
  if ( lisp_i_am_rtr ) : o0oO0O = lisp_sockets [ 0 ]
  if ( o0oO0O == None ) :
   o0oO0O = lisp_sockets [ 0 ]
   ii1i1II11II1i = ii1i1II11II1i . split ( "::ffff:" ) [ - 1 ]
   if 22 - 22: OoOoOO00 - Oo0Ooo
   if 41 - 41: iIii1I11I1II1 * I1Ii111 / OoO0O00
   if 33 - 33: I11i + O0
 lprint ( "{} {} bytes {} {}, packet: {}" . format ( bold ( "Send" , False ) ,
 len ( packet ) , bold ( "to " + ii1i1II11II1i , False ) , port ,
 lisp_format_packet ( packet ) ) )
 if 9 - 9: I11i . iII111i * ooOoO0o * ooOoO0o
 if 68 - 68: O0 - i11iIiiIii % iIii1I11I1II1 % ooOoO0o
 if 12 - 12: II111iiii + I11i
 if 9 - 9: I1ii11iIi11i
 oOo0o0o0 = ( LISP_RLOC_PROBE_TTL == 128 )
 if ( oOo0o0o0 ) :
  OOO0o000 = struct . unpack ( "B" , packet [ 0 ] ) [ 0 ]
  oOo0o0o0 = ( OOO0o000 in [ 0x12 , 0x28 ] )
  if ( oOo0o0o0 ) : lisp_set_ttl ( o0oO0O , LISP_RLOC_PROBE_TTL )
  if 56 - 56: OoOoOO00 % I1ii11iIi11i . oO0o * OoooooooOO + OoooooooOO * Ii1I
  if 73 - 73: ooOoO0o . OoO0O00 % I1ii11iIi11i - oO0o
 try : o0oO0O . sendto ( packet , ( ii1i1II11II1i , port ) )
 except socket . error , oOo :
  lprint ( "socket.sendto() failed: {}" . format ( oOo ) )
  if 67 - 67: o0oOOo0O0Ooo . I11i + i1IIi
  if 100 - 100: Oo0Ooo - I1IiiI . OOooOOo % iIii1I11I1II1 . I11i
  if 83 - 83: OoOoOO00 * iII111i
  if 75 - 75: i11iIiiIii . o0oOOo0O0Ooo / oO0o . OoO0O00 % Ii1I % Ii1I
  if 94 - 94: iII111i . Ii1I
 if ( oOo0o0o0 ) : lisp_set_ttl ( o0oO0O , 64 )
 return
 if 71 - 71: o0oOOo0O0Ooo * II111iiii / OOooOOo . OoO0O00
 if 73 - 73: I1Ii111 * OoO0O00 / OoOoOO00 . II111iiii
 if 87 - 87: OoO0O00 + Oo0Ooo + O0 % OoooooooOO - iIii1I11I1II1
 if 100 - 100: Oo0Ooo + IiII
 if 81 - 81: iIii1I11I1II1 + iIii1I11I1II1
 if 19 - 19: ooOoO0o + i1IIi / Oo0Ooo * II111iiii * I1Ii111 / ooOoO0o
 if 23 - 23: I1Ii111
 if 76 - 76: Ii1I + Ii1I / i1IIi % o0oOOo0O0Ooo . iIii1I11I1II1 . OoOoOO00
def lisp_receive_segments ( lisp_socket , packet , source , total_length ) :
 if 75 - 75: I11i . Ii1I / I1ii11iIi11i
 if 99 - 99: Ii1I
 if 85 - 85: I1Ii111 + I1Ii111 + OoOoOO00 / ooOoO0o / o0oOOo0O0Ooo . Oo0Ooo
 if 41 - 41: i1IIi % Ii1I . i1IIi * OoooooooOO % Ii1I
 if 21 - 21: iII111i
 iiII1iIi11 = total_length - len ( packet )
 if ( iiII1iIi11 == 0 ) : return ( [ True , packet ] )
 if 72 - 72: I11i % o0oOOo0O0Ooo . iIii1I11I1II1 - I1Ii111 / i11iIiiIii
 lprint ( "Received {}-out-of-{} byte segment from {}" . format ( len ( packet ) ,
 total_length , source ) )
 if 75 - 75: OoooooooOO
 if 24 - 24: oO0o % iII111i - II111iiii / Ii1I + O0
 if 37 - 37: I1Ii111 - i1IIi / iIii1I11I1II1
 if 53 - 53: Ii1I - iIii1I11I1II1 % I1ii11iIi11i * i11iIiiIii + ooOoO0o
 if 63 - 63: Oo0Ooo * I1IiiI
 IiiI1iii1iIiiI = iiII1iIi11
 while ( IiiI1iii1iIiiI > 0 ) :
  try : o000oOoO00ooO = lisp_socket . recvfrom ( 9000 )
  except : return ( [ False , None ] )
  if 84 - 84: Oo0Ooo
  o000oOoO00ooO = o000oOoO00ooO [ 0 ]
  if 67 - 67: oO0o / II111iiii . I11i / oO0o
  if 46 - 46: oO0o * Oo0Ooo - I11i / iIii1I11I1II1
  if 100 - 100: i11iIiiIii % oO0o
  if 62 - 62: OOooOOo * i1IIi - OOooOOo / i11iIiiIii
  if 17 - 17: I1ii11iIi11i + ooOoO0o % Ii1I % OOooOOo
  if ( o000oOoO00ooO . find ( "packet@" ) == 0 ) :
   oO = o000oOoO00ooO . split ( "@" )
   lprint ( "Received new message ({}-out-of-{}) while receiving " + "fragments, old message discarded" , len ( o000oOoO00ooO ) ,
   # o0oOOo0O0Ooo % Ii1I - OoOoOO00 + OoOoOO00 * IiII + iII111i
 oO [ 1 ] if len ( oO ) > 2 else "?" )
   return ( [ False , o000oOoO00ooO ] )
   if 58 - 58: I1ii11iIi11i / oO0o + i11iIiiIii * o0oOOo0O0Ooo
   if 19 - 19: OoOoOO00
  IiiI1iii1iIiiI -= len ( o000oOoO00ooO )
  packet += o000oOoO00ooO
  if 17 - 17: Oo0Ooo
  lprint ( "Received {}-out-of-{} byte segment from {}" . format ( len ( o000oOoO00ooO ) , total_length , source ) )
  if 76 - 76: II111iiii % I1ii11iIi11i
  if 99 - 99: oO0o - I1Ii111
 return ( [ True , packet ] )
 if 29 - 29: I1IiiI - I11i
 if 42 - 42: Oo0Ooo - O0 . OoOoOO00
 if 4 - 4: IiII
 if 2 - 2: iII111i
 if 47 - 47: i1IIi % I11i
 if 17 - 17: OoOoOO00 - iII111i % I11i / o0oOOo0O0Ooo / II111iiii
 if 22 - 22: Oo0Ooo + I1ii11iIi11i % i11iIiiIii . OoO0O00 - I11i % I11i
 if 21 - 21: I1IiiI . OoO0O00 * IiII % OoooooooOO - Oo0Ooo + Oo0Ooo
def lisp_bit_stuff ( payload ) :
 lprint ( "Bit-stuffing, found {} segments" . format ( len ( payload ) ) )
 IiiiIi1iiii11 = ""
 for o000oOoO00ooO in payload : IiiiIi1iiii11 += o000oOoO00ooO + "\x40"
 return ( IiiiIi1iiii11 [ : - 1 ] )
 if 94 - 94: ooOoO0o
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
 if 60 - 60: iII111i . OOooOOo
 if 39 - 39: O0 - i11iIiiIii - I1IiiI / Oo0Ooo - i11iIiiIii
 if 30 - 30: OoO0O00 / OoOoOO00 + I1ii11iIi11i % IiII - OoO0O00
 if 19 - 19: I1IiiI
 if 99 - 99: OOooOOo - OOooOOo
 if 98 - 98: o0oOOo0O0Ooo + O0 * oO0o - i11iIiiIii
 if 83 - 83: o0oOOo0O0Ooo
 if 23 - 23: o0oOOo0O0Ooo . I11i
 if 67 - 67: iII111i
def lisp_receive ( lisp_socket , internal ) :
 while ( True ) :
  if 52 - 52: IiII . OoooooooOO
  if 34 - 34: o0oOOo0O0Ooo / IiII . OoooooooOO . Oo0Ooo / ooOoO0o + O0
  if 38 - 38: I11i
  if 66 - 66: II111iiii
  try : OO0O = lisp_socket . recvfrom ( 9000 )
  except : return ( [ "" , "" , "" , "" ] )
  if 88 - 88: OOooOOo - I1ii11iIi11i % iII111i
  if 58 - 58: OoO0O00 . O0 - i11iIiiIii . I1IiiI
  if 95 - 95: OoooooooOO / ooOoO0o * I11i - Ii1I
  if 94 - 94: I1Ii111 + OoO0O00 . OoooooooOO
  if 60 - 60: Ii1I . II111iiii
  if 36 - 36: IiII . iII111i * O0 . i1IIi * O0 * I1Ii111
  if ( internal == False ) :
   IiiiIi1iiii11 = OO0O [ 0 ]
   i1IIi1ii1i1ii = lisp_convert_6to4 ( OO0O [ 1 ] [ 0 ] )
   Oo0O00O = OO0O [ 1 ] [ 1 ]
   if 50 - 50: OoooooooOO + o0oOOo0O0Ooo + iIii1I11I1II1 + OOooOOo
   if ( Oo0O00O == LISP_DATA_PORT ) :
    O000O00O00OO = lisp_data_plane_logging
    iiII11i1 = lisp_format_packet ( IiiiIi1iiii11 [ 0 : 60 ] ) + " ..."
   else :
    O000O00O00OO = True
    iiII11i1 = lisp_format_packet ( IiiiIi1iiii11 )
    if 65 - 65: iII111i % I1Ii111
    if 20 - 20: IiII + o0oOOo0O0Ooo
   if ( O000O00O00OO ) :
    lprint ( "{} {} bytes {} {}, packet: {}" . format ( bold ( "Receive" ,
 False ) , len ( IiiiIi1iiii11 ) , bold ( "from " + i1IIi1ii1i1ii , False ) , Oo0O00O ,
 iiII11i1 ) )
    if 50 - 50: OoO0O00 . iIii1I11I1II1 . OOooOOo / I1ii11iIi11i - OOooOOo
   return ( [ "packet" , i1IIi1ii1i1ii , Oo0O00O , IiiiIi1iiii11 ] )
   if 71 - 71: iII111i % I11i * I1ii11iIi11i - o0oOOo0O0Ooo + Oo0Ooo * I1IiiI
   if 9 - 9: i11iIiiIii
   if 22 - 22: OoO0O00 - iIii1I11I1II1 / OOooOOo
   if 56 - 56: II111iiii
   if 80 - 80: o0oOOo0O0Ooo . oO0o . I1Ii111
   if 26 - 26: i1IIi - I1IiiI + IiII / OoO0O00 . I1ii11iIi11i
  O0o00OOOO0O = False
  i1I = OO0O [ 0 ]
  oOo0ooOoO = False
  if 46 - 46: I1Ii111 - iII111i / oO0o % OoO0O00 / O0 + oO0o
  while ( O0o00OOOO0O == False ) :
   i1I = i1I . split ( "@" )
   if 35 - 35: Oo0Ooo
   if ( len ( i1I ) < 4 ) :
    lprint ( "Possible fragment (length {}), from old message, " + "discarding" , len ( i1I [ 0 ] ) )
    if 86 - 86: ooOoO0o . OoO0O00
    oOo0ooOoO = True
    break
    if 47 - 47: IiII % I1IiiI
    if 91 - 91: Ii1I
   o0o0O0OO0oO = i1I [ 0 ]
   try :
    III1IIiIiII1 = int ( i1I [ 1 ] )
   except :
    i11i1i = bold ( "Internal packet reassembly error" , False )
    lprint ( "{}: {}" . format ( i11i1i , OO0O ) )
    oOo0ooOoO = True
    break
    if 15 - 15: OoooooooOO / iII111i
   i1IIi1ii1i1ii = i1I [ 2 ]
   Oo0O00O = i1I [ 3 ]
   if 40 - 40: o0oOOo0O0Ooo
   if 75 - 75: oO0o - OoOoOO00 * ooOoO0o . O0
   if 78 - 78: Oo0Ooo
   if 74 - 74: O0 / I11i
   if 52 - 52: I1IiiI + oO0o * II111iiii
   if 15 - 15: I11i
   if 72 - 72: O0
   if 15 - 15: II111iiii / I11i % II111iiii % Ii1I % i11iIiiIii / I1Ii111
   if ( len ( i1I ) > 5 ) :
    IiiiIi1iiii11 = lisp_bit_stuff ( i1I [ 4 : : ] )
   else :
    IiiiIi1iiii11 = i1I [ 4 ]
    if 93 - 93: OOooOOo / OoooooooOO % iII111i
    if 47 - 47: o0oOOo0O0Ooo - I1IiiI % O0 % I1Ii111 . O0 . OoOoOO00
    if 95 - 95: o0oOOo0O0Ooo * OOooOOo - iII111i * OoooooooOO - ooOoO0o / I1IiiI
    if 47 - 47: OoO0O00 % I1IiiI / OoOoOO00 - I1Ii111 / I1IiiI
    if 13 - 13: o0oOOo0O0Ooo % ooOoO0o
    if 15 - 15: iII111i * I1IiiI . iIii1I11I1II1 % I1IiiI / O0
   O0o00OOOO0O , IiiiIi1iiii11 = lisp_receive_segments ( lisp_socket , IiiiIi1iiii11 ,
 i1IIi1ii1i1ii , III1IIiIiII1 )
   if ( IiiiIi1iiii11 == None ) : return ( [ "" , "" , "" , "" ] )
   if 47 - 47: OoooooooOO - i11iIiiIii . I1IiiI / i1IIi
   if 74 - 74: OoooooooOO * ooOoO0o
   if 45 - 45: Oo0Ooo + iIii1I11I1II1 . o0oOOo0O0Ooo
   if 50 - 50: o0oOOo0O0Ooo % O0
   if 67 - 67: OoOoOO00
   if ( O0o00OOOO0O == False ) :
    i1I = IiiiIi1iiii11
    continue
    if 21 - 21: I11i % Oo0Ooo + Oo0Ooo / iIii1I11I1II1 % iIii1I11I1II1
    if 66 - 66: iII111i
   if ( Oo0O00O == "" ) : Oo0O00O = "no-port"
   if ( o0o0O0OO0oO == "command" and lisp_i_am_core == False ) :
    ooo = IiiiIi1iiii11 . find ( " {" )
    O0oOo = IiiiIi1iiii11 if ooo == - 1 else IiiiIi1iiii11 [ : ooo ]
    O0oOo = ": '" + O0oOo + "'"
   else :
    O0oOo = ""
    if 81 - 81: I1Ii111
    if 36 - 36: Oo0Ooo * I11i / I1Ii111 / i1IIi
   lprint ( "{} {} bytes {} {}, {}{}" . format ( bold ( "Receive" , False ) ,
 len ( IiiiIi1iiii11 ) , bold ( "from " + i1IIi1ii1i1ii , False ) , Oo0O00O , o0o0O0OO0oO ,
 O0oOo if ( o0o0O0OO0oO in [ "command" , "api" ] ) else ": ... " if ( o0o0O0OO0oO == "data-packet" ) else ": " + lisp_format_packet ( IiiiIi1iiii11 ) ) )
   if 60 - 60: iII111i + Oo0Ooo % i1IIi / II111iiii
   if 59 - 59: iII111i - O0 + Ii1I
   if 75 - 75: II111iiii / OoOoOO00 - o0oOOo0O0Ooo % I1ii11iIi11i + OoO0O00
   if 7 - 7: iII111i - OoO0O00 + ooOoO0o * iII111i
   if 14 - 14: OoOoOO00 - OoOoOO00 / ooOoO0o
  if ( oOo0ooOoO ) : continue
  return ( [ o0o0O0OO0oO , i1IIi1ii1i1ii , Oo0O00O , IiiiIi1iiii11 ] )
  if 22 - 22: I1Ii111
  if 59 - 59: I1Ii111
  if 22 - 22: OoooooooOO
  if 88 - 88: I1Ii111 - OoO0O00
  if 29 - 29: I1IiiI . I1Ii111
  if 74 - 74: Oo0Ooo / OoOoOO00 + OoOoOO00 % i11iIiiIii . OoO0O00 + ooOoO0o
  if 77 - 77: ooOoO0o . I11i + OoooooooOO
  if 100 - 100: ooOoO0o . oO0o % I1ii11iIi11i . IiII * IiII - o0oOOo0O0Ooo
def lisp_parse_packet ( lisp_sockets , packet , source , udp_sport , ttl = - 1 ) :
 Iii1Iiii1I1 = False
 i1I1iiIiii1 = time . time ( )
 if 21 - 21: II111iiii % I1ii11iIi11i * iIii1I11I1II1
 O0ooOoO0 = lisp_control_header ( )
 if ( O0ooOoO0 . decode ( packet ) == None ) :
  lprint ( "Could not decode control header" )
  return ( Iii1Iiii1I1 )
  if 53 - 53: OoO0O00 * O0
  if 97 - 97: Oo0Ooo . i1IIi
  if 56 - 56: Ii1I
  if 2 - 2: i1IIi % oO0o + O0 - OoO0O00
  if 34 - 34: ooOoO0o + oO0o - Oo0Ooo
 oO00o0o0O = source
 if ( source . find ( "lisp" ) == - 1 ) :
  IiII1iiI = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  IiII1iiI . string_to_afi ( source )
  IiII1iiI . store_address ( source )
  source = IiII1iiI
  if 50 - 50: o0oOOo0O0Ooo + Oo0Ooo + i1IIi
  if 79 - 79: Ii1I / II111iiii . I1ii11iIi11i
 if ( O0ooOoO0 . type == LISP_MAP_REQUEST ) :
  lisp_process_map_request ( lisp_sockets , packet , None , 0 , source ,
 udp_sport , False , ttl , i1I1iiIiii1 )
  if 59 - 59: I1ii11iIi11i % ooOoO0o
 elif ( O0ooOoO0 . type == LISP_MAP_REPLY ) :
  lisp_process_map_reply ( lisp_sockets , packet , source , ttl , i1I1iiIiii1 )
  if 66 - 66: Ii1I / OoooooooOO * i11iIiiIii - iII111i % iIii1I11I1II1
 elif ( O0ooOoO0 . type == LISP_MAP_REGISTER ) :
  lisp_process_map_register ( lisp_sockets , packet , source , udp_sport )
  if 87 - 87: O0
 elif ( O0ooOoO0 . type == LISP_MAP_NOTIFY ) :
  if ( oO00o0o0O == "lisp-etr" ) :
   lisp_process_multicast_map_notify ( packet , source )
  else :
   if ( lisp_is_running ( "lisp-rtr" ) ) :
    lisp_process_multicast_map_notify ( packet , source )
    if 23 - 23: I1IiiI
   lisp_process_map_notify ( lisp_sockets , packet , source )
   if 97 - 97: OoooooooOO / ooOoO0o
   if 50 - 50: O0
 elif ( O0ooOoO0 . type == LISP_MAP_NOTIFY_ACK ) :
  lisp_process_map_notify_ack ( packet , source )
  if 100 - 100: IiII . Oo0Ooo - Oo0Ooo % iII111i
 elif ( O0ooOoO0 . type == LISP_MAP_REFERRAL ) :
  lisp_process_map_referral ( lisp_sockets , packet , source )
  if 83 - 83: i11iIiiIii % ooOoO0o * I1ii11iIi11i - ooOoO0o . OoOoOO00
 elif ( O0ooOoO0 . type == LISP_NAT_INFO and O0ooOoO0 . is_info_reply ( ) ) :
  O0O , IIIi1i1iIIIi , Iii1Iiii1I1 = lisp_process_info_reply ( source , packet , True )
  if 54 - 54: oO0o + OoOoOO00 - OoOoOO00 / I1ii11iIi11i * i11iIiiIii + OoooooooOO
 elif ( O0ooOoO0 . type == LISP_NAT_INFO and O0ooOoO0 . is_info_reply ( ) == False ) :
  oo0o00OO = source . print_address_no_iid ( )
  lisp_process_info_request ( lisp_sockets , packet , oo0o00OO , udp_sport ,
 None )
  if 20 - 20: OOooOOo / O0
 elif ( O0ooOoO0 . type == LISP_ECM ) :
  lisp_process_ecm ( lisp_sockets , packet , source , udp_sport )
  if 51 - 51: ooOoO0o - I1Ii111 * oO0o
 else :
  lprint ( "Invalid LISP control packet type {}" . format ( O0ooOoO0 . type ) )
  if 47 - 47: Oo0Ooo % OoO0O00 * Ii1I / OoOoOO00
 return ( Iii1Iiii1I1 )
 if 1 - 1: I1IiiI
 if 68 - 68: ooOoO0o
 if 68 - 68: I11i % IiII
 if 1 - 1: I1IiiI + OOooOOo - OOooOOo * O0 + o0oOOo0O0Ooo * OOooOOo
 if 48 - 48: ooOoO0o - iII111i + I1ii11iIi11i * I1Ii111 % ooOoO0o * OoO0O00
 if 28 - 28: i1IIi / iII111i + OOooOOo
 if 89 - 89: Oo0Ooo + II111iiii * OoO0O00 + Oo0Ooo % II111iiii
def lisp_process_rloc_probe_request ( lisp_sockets , map_request , source , port ,
 ttl , timestamp ) :
 if 59 - 59: O0 + Oo0Ooo
 oo00ooOOOo0O = bold ( "RLOC-probe" , False )
 if 63 - 63: OoO0O00 / I1IiiI / oO0o . Ii1I / i1IIi
 if ( lisp_i_am_etr ) :
  lprint ( "Received {} Map-Request, send RLOC-probe Map-Reply" . format ( oo00ooOOOo0O ) )
  lisp_etr_process_map_request ( lisp_sockets , map_request , source , port ,
 ttl , timestamp )
  return
  if 50 - 50: I11i . I11i % I1IiiI - i1IIi
  if 63 - 63: OoO0O00 . iII111i
 if ( lisp_i_am_rtr ) :
  lprint ( "Received {} Map-Request, send RLOC-probe Map-Reply" . format ( oo00ooOOOo0O ) )
  lisp_rtr_process_map_request ( lisp_sockets , map_request , source , port ,
 ttl , timestamp )
  return
  if 28 - 28: ooOoO0o . Oo0Ooo - OoooooooOO - I1Ii111 - OoooooooOO - oO0o
  if 25 - 25: I11i / I1Ii111 . i11iIiiIii % i1IIi
 lprint ( "Ignoring received {} Map-Request, not an ETR or RTR" . format ( oo00ooOOOo0O ) )
 return
 if 21 - 21: O0 * IiII . iII111i / iII111i % i11iIiiIii / I11i
 if 15 - 15: o0oOOo0O0Ooo / OoO0O00 - i1IIi
 if 30 - 30: OoO0O00 / ooOoO0o % ooOoO0o
 if 40 - 40: i1IIi . iIii1I11I1II1 * OoOoOO00
 if 83 - 83: iIii1I11I1II1 + Ii1I - Ii1I % II111iiii
def lisp_process_smr ( map_request ) :
 lprint ( "Received SMR-based Map-Request" )
 return
 if 82 - 82: O0
 if 18 - 18: iII111i . IiII . I1IiiI
 if 40 - 40: IiII / oO0o + OoooooooOO / iII111i / II111iiii + i1IIi
 if 33 - 33: I11i + I1ii11iIi11i + i11iIiiIii * I1IiiI % oO0o % OoooooooOO
 if 4 - 4: OoO0O00 . I1IiiI - O0 % iII111i . OOooOOo
def lisp_process_smr_invoked_request ( map_request ) :
 lprint ( "Received SMR-invoked Map-Request" )
 return
 if 69 - 69: OoooooooOO
 if 19 - 19: O0 + iIii1I11I1II1 / OoOoOO00 / oO0o + II111iiii - OOooOOo
 if 70 - 70: i1IIi * o0oOOo0O0Ooo + I1Ii111 . ooOoO0o - O0 + i11iIiiIii
 if 81 - 81: iIii1I11I1II1 - OoO0O00 . i11iIiiIii
 if 4 - 4: o0oOOo0O0Ooo / OoO0O00 - I11i
 if 52 - 52: II111iiii . iII111i
 if 36 - 36: I1IiiI * II111iiii
def lisp_build_map_reply ( eid , group , rloc_set , nonce , action , ttl , map_request ,
 keys , enc , auth , mr_ttl = - 1 ) :
 if 68 - 68: oO0o * o0oOOo0O0Ooo + OoooooooOO - I1ii11iIi11i * i1IIi % OOooOOo
 I1I1I111II11Ii1 = map_request . rloc_probe if ( map_request != None ) else False
 oOo0OOOo0 = map_request . json_telemetry if ( map_request != None ) else None
 if 16 - 16: IiII - I1ii11iIi11i - Oo0Ooo - ooOoO0o / OoooooooOO % i1IIi
 if 85 - 85: i11iIiiIii / OoO0O00 / oO0o
 i111iii1IIi = lisp_map_reply ( )
 i111iii1IIi . rloc_probe = I1I1I111II11Ii1
 i111iii1IIi . echo_nonce_capable = enc
 i111iii1IIi . hop_count = 0 if ( mr_ttl == - 1 ) else mr_ttl
 i111iii1IIi . record_count = 1
 i111iii1IIi . nonce = nonce
 IiiiIi1iiii11 = i111iii1IIi . encode ( )
 i111iii1IIi . print_map_reply ( )
 if 98 - 98: iIii1I11I1II1 . O0
 o0O0o = lisp_eid_record ( )
 o0O0o . rloc_count = len ( rloc_set )
 if ( oOo0OOOo0 != None ) : o0O0o . rloc_count += 1
 o0O0o . authoritative = auth
 o0O0o . record_ttl = ttl
 o0O0o . action = action
 o0O0o . eid = eid
 o0O0o . group = group
 if 88 - 88: i1IIi . I1Ii111 * o0oOOo0O0Ooo + i1IIi % o0oOOo0O0Ooo
 IiiiIi1iiii11 += o0O0o . encode ( )
 o0O0o . print_record ( "  " , False )
 if 45 - 45: IiII - o0oOOo0O0Ooo - II111iiii % oO0o % I1IiiI
 oOO0oOo00O0o = lisp_get_all_addresses ( ) + lisp_get_all_translated_rlocs ( )
 if 35 - 35: OoOoOO00 + o0oOOo0O0Ooo + I11i - I1IiiI + O0 . o0oOOo0O0Ooo
 OO0oOO0O00Oo = None
 for O0OooOoooO0O in rloc_set :
  I11IiI1I1 = O0OooOoooO0O . rloc . is_multicast_address ( )
  oo0OOOO0O0o = lisp_rloc_record ( )
  i11iIIiiiiI1 = I1I1I111II11Ii1 and ( I11IiI1I1 or oOo0OOOo0 == None )
  oo0o00OO = O0OooOoooO0O . rloc . print_address_no_iid ( )
  if ( oo0o00OO in oOO0oOo00O0o or I11IiI1I1 ) :
   oo0OOOO0O0o . local_bit = True
   oo0OOOO0O0o . probe_bit = i11iIIiiiiI1
   oo0OOOO0O0o . keys = keys
   if ( O0OooOoooO0O . priority == 254 and lisp_i_am_rtr ) :
    oo0OOOO0O0o . rloc_name = "RTR"
    if 55 - 55: OoO0O00 % IiII
   if ( OO0oOO0O00Oo == None ) : OO0oOO0O00Oo = O0OooOoooO0O . rloc
   if 93 - 93: OoO0O00 . I1ii11iIi11i / OOooOOo % OoooooooOO + i1IIi + I1Ii111
  oo0OOOO0O0o . store_rloc_entry ( O0OooOoooO0O )
  oo0OOOO0O0o . reach_bit = True
  oo0OOOO0O0o . print_record ( "    " )
  IiiiIi1iiii11 += oo0OOOO0O0o . encode ( )
  if 94 - 94: II111iiii + i11iIiiIii % Ii1I / ooOoO0o * OoOoOO00
  if 68 - 68: O0 / Oo0Ooo / iIii1I11I1II1
  if 63 - 63: I1Ii111 + iII111i
  if 6 - 6: I1ii11iIi11i + Ii1I
  if 36 - 36: iII111i + iII111i * OoO0O00 * I1ii11iIi11i
 if ( oOo0OOOo0 != None ) :
  oo0OOOO0O0o = lisp_rloc_record ( )
  if ( OO0oOO0O00Oo ) : oo0OOOO0O0o . rloc . copy_address ( OO0oOO0O00Oo )
  oo0OOOO0O0o . local_bit = True
  oo0OOOO0O0o . probe_bit = True
  oo0OOOO0O0o . reach_bit = True
  o0O00O = lisp_encode_telemetry ( oOo0OOOo0 , eo = str ( time . time ( ) ) )
  oo0OOOO0O0o . json = lisp_json ( "telemetry" , o0O00O )
  oo0OOOO0O0o . print_record ( "    " )
  IiiiIi1iiii11 += oo0OOOO0O0o . encode ( )
  if 51 - 51: Oo0Ooo % ooOoO0o . O0 % o0oOOo0O0Ooo
 return ( IiiiIi1iiii11 )
 if 76 - 76: i1IIi
 if 48 - 48: OoOoOO00 / OoooooooOO / oO0o
 if 58 - 58: I1ii11iIi11i / Ii1I * ooOoO0o - IiII
 if 67 - 67: ooOoO0o - ooOoO0o * o0oOOo0O0Ooo
 if 65 - 65: O0
 if 37 - 37: I1ii11iIi11i - Oo0Ooo . i11iIiiIii / i11iIiiIii + oO0o
 if 19 - 19: i1IIi / i1IIi - OoooooooOO - OOooOOo . i1IIi
def lisp_build_map_referral ( eid , group , ddt_entry , action , ttl , nonce ) :
 oO0O = lisp_map_referral ( )
 oO0O . record_count = 1
 oO0O . nonce = nonce
 IiiiIi1iiii11 = oO0O . encode ( )
 oO0O . print_map_referral ( )
 if 62 - 62: I1Ii111 / Ii1I - OoOoOO00 + OoO0O00
 o0O0o = lisp_eid_record ( )
 if 75 - 75: iIii1I11I1II1 * i11iIiiIii
 Ii1 = 0
 if ( ddt_entry == None ) :
  o0O0o . eid = eid
  o0O0o . group = group
 else :
  Ii1 = len ( ddt_entry . delegation_set )
  o0O0o . eid = ddt_entry . eid
  o0O0o . group = ddt_entry . group
  ddt_entry . map_referrals_sent += 1
  if 41 - 41: I11i / OoO0O00
 o0O0o . rloc_count = Ii1
 o0O0o . authoritative = True
 if 28 - 28: OoOoOO00
 if 56 - 56: Ii1I % OoO0O00 - I1ii11iIi11i / o0oOOo0O0Ooo - OOooOOo
 if 55 - 55: II111iiii * I1IiiI - o0oOOo0O0Ooo
 if 67 - 67: Oo0Ooo * oO0o
 if 99 - 99: i1IIi % I1IiiI % I1IiiI + iIii1I11I1II1
 O0II = False
 if ( action == LISP_DDT_ACTION_NULL ) :
  if ( Ii1 == 0 ) :
   action = LISP_DDT_ACTION_NODE_REFERRAL
  else :
   I1IooOoo00 = ddt_entry . delegation_set [ 0 ]
   if ( I1IooOoo00 . is_ddt_child ( ) ) :
    action = LISP_DDT_ACTION_NODE_REFERRAL
    if 62 - 62: OoooooooOO
   if ( I1IooOoo00 . is_ms_child ( ) ) :
    action = LISP_DDT_ACTION_MS_REFERRAL
    if 38 - 38: iII111i % iII111i * ooOoO0o / OoO0O00 + ooOoO0o
    if 52 - 52: ooOoO0o . iIii1I11I1II1 / iIii1I11I1II1 % oO0o - oO0o * II111iiii
    if 57 - 57: I1Ii111
    if 23 - 23: I1ii11iIi11i + II111iiii
    if 99 - 99: o0oOOo0O0Ooo . I1IiiI + o0oOOo0O0Ooo * o0oOOo0O0Ooo / O0
    if 27 - 27: OOooOOo - I1Ii111
    if 33 - 33: OOooOOo - Ii1I - iII111i + I1ii11iIi11i - i11iIiiIii
 if ( action == LISP_DDT_ACTION_NOT_AUTH ) : O0II = True
 if ( action in ( LISP_DDT_ACTION_MS_REFERRAL , LISP_DDT_ACTION_MS_ACK ) ) :
  O0II = ( lisp_i_am_ms and I1IooOoo00 . is_ms_peer ( ) == False )
  if 89 - 89: iIii1I11I1II1 * I11i + OOooOOo
  if 27 - 27: i1IIi - OoO0O00
 o0O0o . action = action
 o0O0o . ddt_incomplete = O0II
 o0O0o . record_ttl = ttl
 if 23 - 23: iIii1I11I1II1 + Oo0Ooo * IiII
 IiiiIi1iiii11 += o0O0o . encode ( )
 o0O0o . print_record ( "  " , True )
 if 80 - 80: OoooooooOO . ooOoO0o
 if ( Ii1 == 0 ) : return ( IiiiIi1iiii11 )
 if 52 - 52: O0 + O0 + I1IiiI
 for I1IooOoo00 in ddt_entry . delegation_set :
  oo0OOOO0O0o = lisp_rloc_record ( )
  oo0OOOO0O0o . rloc = I1IooOoo00 . delegate_address
  oo0OOOO0O0o . priority = I1IooOoo00 . priority
  oo0OOOO0O0o . weight = I1IooOoo00 . weight
  oo0OOOO0O0o . mpriority = 255
  oo0OOOO0O0o . mweight = 0
  oo0OOOO0O0o . reach_bit = True
  IiiiIi1iiii11 += oo0OOOO0O0o . encode ( )
  oo0OOOO0O0o . print_record ( "    " )
  if 64 - 64: ooOoO0o
 return ( IiiiIi1iiii11 )
 if 35 - 35: I1IiiI . iIii1I11I1II1 + IiII / i11iIiiIii - II111iiii . OoooooooOO
 if 19 - 19: IiII - OoOoOO00
 if 43 - 43: IiII / OOooOOo % II111iiii . o0oOOo0O0Ooo / i11iIiiIii
 if 5 - 5: oO0o % iII111i . Oo0Ooo . O0 . OoOoOO00 / iII111i
 if 78 - 78: Ii1I - I1ii11iIi11i + iIii1I11I1II1 + OoooooooOO . OoO0O00 - ooOoO0o
 if 81 - 81: o0oOOo0O0Ooo * OoooooooOO
 if 32 - 32: OoOoOO00 - I11i * i11iIiiIii . I1ii11iIi11i . IiII . iIii1I11I1II1
def lisp_etr_process_map_request ( lisp_sockets , map_request , source , sport ,
 ttl , etr_in_ts ) :
 if 41 - 41: iII111i / OoOoOO00 / OoO0O00 / ooOoO0o
 if ( map_request . target_group . is_null ( ) ) :
  iiIII1 = lisp_db_for_lookups . lookup_cache ( map_request . target_eid , False )
 else :
  iiIII1 = lisp_db_for_lookups . lookup_cache ( map_request . target_group , False )
  if ( iiIII1 ) : iiIII1 = iiIII1 . lookup_source_cache ( map_request . target_eid , False )
  if 18 - 18: OoO0O00 . Oo0Ooo
 I11i11i1 = map_request . print_prefix ( )
 if 52 - 52: OoOoOO00 . iIii1I11I1II1 / OoOoOO00
 if ( iiIII1 == None ) :
  lprint ( "Database-mapping entry not found for requested EID {}" . format ( green ( I11i11i1 , False ) ) )
  if 14 - 14: i1IIi
  return
  if 63 - 63: OoOoOO00 . i11iIiiIii / IiII
  if 36 - 36: OOooOOo * OoOoOO00 + i11iIiiIii + O0 + O0
 II1OO0Oo0oOOO000 = iiIII1 . print_eid_tuple ( )
 if 88 - 88: O0 + II111iiii + iIii1I11I1II1
 lprint ( "Found database-mapping EID-prefix {} for requested EID {}" . format ( green ( II1OO0Oo0oOOO000 , False ) , green ( I11i11i1 , False ) ) )
 if 11 - 11: II111iiii . II111iiii + Ii1I % oO0o
 if 69 - 69: iIii1I11I1II1 - O0 . I1Ii111 % I1IiiI / o0oOOo0O0Ooo
 if 78 - 78: oO0o
 if 20 - 20: i1IIi + i1IIi * i1IIi
 if 32 - 32: I1IiiI + IiII + iII111i . iIii1I11I1II1 * Ii1I
 iIi1i1i = map_request . itr_rlocs [ 0 ]
 if ( iIi1i1i . is_private_address ( ) and lisp_nat_traversal ) :
  iIi1i1i = source
  if 7 - 7: I11i + I1ii11iIi11i - iII111i % I1Ii111 * oO0o
  if 57 - 57: iII111i + Oo0Ooo - iIii1I11I1II1
 Iii11I = map_request . nonce
 iI = lisp_nonce_echoing
 iIi11III = map_request . keys
 if 50 - 50: Ii1I * Ii1I / O0 . Oo0Ooo + iII111i
 if 9 - 9: OoooooooOO % O0 % I1ii11iIi11i
 if 100 - 100: i11iIiiIii - iII111i - I11i
 if 5 - 5: oO0o % IiII * iII111i
 if 98 - 98: iII111i / OOooOOo + IiII
 OoiIII1II1 = map_request . json_telemetry
 if ( OoiIII1II1 != None ) :
  map_request . json_telemetry = lisp_encode_telemetry ( OoiIII1II1 , ei = etr_in_ts )
  if 42 - 42: iII111i * Ii1I - O0 % o0oOOo0O0Ooo - IiII
  if 74 - 74: oO0o
 iiIII1 . map_replies_sent += 1
 if 94 - 94: I1ii11iIi11i * O0
 IiiiIi1iiii11 = lisp_build_map_reply ( iiIII1 . eid , iiIII1 . group , iiIII1 . rloc_set , Iii11I ,
 LISP_NO_ACTION , 1440 , map_request , iIi11III , iI , True , ttl )
 if 28 - 28: O0 % i11iIiiIii + iIii1I11I1II1 / OOooOOo
 if 67 - 67: iII111i + OOooOOo % iII111i + IiII
 if 79 - 79: OOooOOo
 if 47 - 47: IiII - I1ii11iIi11i . OOooOOo + I1Ii111 % I1IiiI
 if 3 - 3: I1IiiI / Oo0Ooo - Ii1I
 if 69 - 69: iIii1I11I1II1 % iII111i + ooOoO0o * i1IIi + iII111i * I1Ii111
 if 67 - 67: Ii1I % Oo0Ooo - Oo0Ooo . I11i + IiII
 if 73 - 73: Oo0Ooo + iIii1I11I1II1 . iIii1I11I1II1
 if 73 - 73: ooOoO0o + OoOoOO00
 if 61 - 61: I1Ii111 * I1Ii111 % OOooOOo
 if 31 - 31: oO0o + Ii1I - iIii1I11I1II1 / i11iIiiIii
 if 9 - 9: IiII % OoO0O00
 if 58 - 58: iII111i
 if 12 - 12: OoO0O00
 if 59 - 59: OOooOOo + i1IIi
 if 8 - 8: i1IIi + Oo0Ooo / Ii1I . OoOoOO00 % i1IIi
 if ( map_request . rloc_probe and len ( lisp_sockets ) == 4 ) :
  iiI1Iii = ( iIi1i1i . is_private_address ( ) == False )
  IIiiiIiI1 = iIi1i1i . print_address_no_iid ( )
  if ( ( iiI1Iii and lisp_rtr_list . has_key ( IIiiiIiI1 ) ) or sport == 0 ) :
   lisp_encapsulate_rloc_probe ( lisp_sockets , iIi1i1i , None , IiiiIi1iiii11 )
   return
   if 33 - 33: OoooooooOO + iIii1I11I1II1
   if 68 - 68: II111iiii * iIii1I11I1II1 - OoO0O00 - I1ii11iIi11i * II111iiii
   if 37 - 37: OoooooooOO - I1ii11iIi11i . O0
   if 65 - 65: I1Ii111 + I1ii11iIi11i % I11i / iII111i
   if 38 - 38: I1IiiI - OOooOOo * OoOoOO00 + O0 * I1IiiI
   if 8 - 8: I1IiiI
 lisp_send_map_reply ( lisp_sockets , IiiiIi1iiii11 , iIi1i1i , sport )
 return
 if 31 - 31: o0oOOo0O0Ooo + OOooOOo
 if 7 - 7: IiII + iIii1I11I1II1
 if 97 - 97: oO0o
 if 52 - 52: I1ii11iIi11i / OoOoOO00 * OoO0O00 + II111iiii * OoooooooOO
 if 11 - 11: Ii1I * iII111i * I1IiiI - Oo0Ooo
 if 76 - 76: oO0o * II111iiii
 if 81 - 81: I11i
def lisp_rtr_process_map_request ( lisp_sockets , map_request , source , sport ,
 ttl , etr_in_ts ) :
 if 2 - 2: OoOoOO00
 if 75 - 75: I1IiiI - OoooooooOO * I1Ii111
 if 1 - 1: o0oOOo0O0Ooo % oO0o * I1Ii111 - i1IIi - iII111i . oO0o
 if 25 - 25: i1IIi * o0oOOo0O0Ooo / oO0o
 iIi1i1i = map_request . itr_rlocs [ 0 ]
 if ( iIi1i1i . is_private_address ( ) ) : iIi1i1i = source
 Iii11I = map_request . nonce
 if 11 - 11: IiII + II111iiii
 ooOOoo0 = map_request . target_eid
 IIi1iiIII11 = map_request . target_group
 if 37 - 37: O0
 o0oo0OoOo000 = [ ]
 for i1iIIi in [ lisp_myrlocs [ 0 ] , lisp_myrlocs [ 1 ] ] :
  if ( i1iIIi == None ) : continue
  I1IIiIIIii = lisp_rloc ( )
  I1IIiIIIii . rloc . copy_address ( i1iIIi )
  I1IIiIIIii . priority = 254
  o0oo0OoOo000 . append ( I1IIiIIIii )
  if 84 - 84: OoO0O00
  if 67 - 67: I1Ii111 + I1Ii111
 iI = lisp_nonce_echoing
 iIi11III = map_request . keys
 if 81 - 81: II111iiii % I11i % O0 . I1Ii111 % ooOoO0o - O0
 if 58 - 58: OoooooooOO . II111iiii . O0 % I1Ii111 / OoooooooOO
 if 64 - 64: Oo0Ooo + oO0o . OoO0O00
 if 67 - 67: I11i
 if 91 - 91: OOooOOo / OoO0O00
 OoiIII1II1 = map_request . json_telemetry
 if ( OoiIII1II1 != None ) :
  map_request . json_telemetry = lisp_encode_telemetry ( OoiIII1II1 , ei = etr_in_ts )
  if 36 - 36: I1IiiI . iII111i * I1Ii111 . IiII % I1ii11iIi11i
  if 44 - 44: I11i % I1ii11iIi11i - OoooooooOO % iII111i
 IiiiIi1iiii11 = lisp_build_map_reply ( ooOOoo0 , IIi1iiIII11 , o0oo0OoOo000 , Iii11I , LISP_NO_ACTION ,
 1440 , map_request , iIi11III , iI , True , ttl )
 lisp_send_map_reply ( lisp_sockets , IiiiIi1iiii11 , iIi1i1i , sport )
 return
 if 60 - 60: IiII % oO0o
 if 11 - 11: I1Ii111 - II111iiii
 if 12 - 12: i11iIiiIii
 if 9 - 9: OOooOOo * I1ii11iIi11i + iIii1I11I1II1 / OoO0O00 * OoooooooOO
 if 91 - 91: i11iIiiIii % IiII + oO0o . I1IiiI - I1IiiI
 if 62 - 62: Oo0Ooo * II111iiii + o0oOOo0O0Ooo . OoOoOO00
 if 94 - 94: Oo0Ooo / I1IiiI * iIii1I11I1II1 - OoO0O00
 if 96 - 96: ooOoO0o - OoooooooOO * iIii1I11I1II1 . IiII - O0
 if 7 - 7: iIii1I11I1II1 . OoO0O00
 if 88 - 88: i1IIi * II111iiii / i11iIiiIii % IiII . IiII
def lisp_get_private_rloc_set ( target_site_eid , seid , group ) :
 o0oo0OoOo000 = target_site_eid . registered_rlocs
 if 93 - 93: OoOoOO00 * i1IIi . Ii1I
 i11i = lisp_site_eid_lookup ( seid , group , False )
 if ( i11i == None ) : return ( o0oo0OoOo000 )
 if 25 - 25: iII111i % i11iIiiIii + Ii1I
 if 62 - 62: oO0o - I1ii11iIi11i - oO0o - OoO0O00 * Oo0Ooo
 if 47 - 47: o0oOOo0O0Ooo
 if 88 - 88: iIii1I11I1II1 + OOooOOo . II111iiii / i11iIiiIii % OOooOOo % IiII
 i111I1iI1I = None
 iI11Iii1I111 = [ ]
 for O0OooOoooO0O in o0oo0OoOo000 :
  if ( O0OooOoooO0O . is_rtr ( ) ) : continue
  if ( O0OooOoooO0O . rloc . is_private_address ( ) ) :
   oOoO = copy . deepcopy ( O0OooOoooO0O )
   iI11Iii1I111 . append ( oOoO )
   continue
   if 80 - 80: Oo0Ooo / OOooOOo / iII111i . o0oOOo0O0Ooo
  i111I1iI1I = O0OooOoooO0O
  break
  if 43 - 43: IiII
 if ( i111I1iI1I == None ) : return ( o0oo0OoOo000 )
 i111I1iI1I = i111I1iI1I . rloc . print_address_no_iid ( )
 if 74 - 74: OoooooooOO
 if 88 - 88: Ii1I * o0oOOo0O0Ooo / oO0o
 if 58 - 58: O0
 if 43 - 43: O0 / i1IIi / I11i % I1IiiI
 OoOoO00OOO0O0 = None
 for O0OooOoooO0O in i11i . registered_rlocs :
  if ( O0OooOoooO0O . is_rtr ( ) ) : continue
  if ( O0OooOoooO0O . rloc . is_private_address ( ) ) : continue
  OoOoO00OOO0O0 = O0OooOoooO0O
  break
  if 46 - 46: OoO0O00 % i1IIi % iII111i * I1Ii111
 if ( OoOoO00OOO0O0 == None ) : return ( o0oo0OoOo000 )
 OoOoO00OOO0O0 = OoOoO00OOO0O0 . rloc . print_address_no_iid ( )
 if 36 - 36: I1ii11iIi11i % II111iiii % I1Ii111 / I1ii11iIi11i
 if 34 - 34: OoooooooOO * i11iIiiIii
 if 33 - 33: II111iiii
 if 59 - 59: iIii1I11I1II1 % I11i
 O0O0oOO = target_site_eid . site_id
 if ( O0O0oOO == 0 ) :
  if ( OoOoO00OOO0O0 == i111I1iI1I ) :
   lprint ( "Return private RLOCs for sites behind {}" . format ( i111I1iI1I ) )
   if 93 - 93: I1ii11iIi11i
   return ( iI11Iii1I111 )
   if 50 - 50: ooOoO0o % OoO0O00 % OoO0O00
  return ( o0oo0OoOo000 )
  if 36 - 36: I1IiiI * O0 . IiII / I1Ii111
  if 15 - 15: I11i + iII111i
  if 79 - 79: i11iIiiIii * IiII % iII111i
  if 18 - 18: iIii1I11I1II1 - O0 . o0oOOo0O0Ooo % oO0o
  if 73 - 73: IiII + I11i % I1IiiI * iII111i . O0
  if 17 - 17: OoO0O00 * OoOoOO00 % O0 % iII111i / i1IIi
  if 100 - 100: i11iIiiIii
 if ( O0O0oOO == i11i . site_id ) :
  lprint ( "Return private RLOCs for sites in site-id {}" . format ( O0O0oOO ) )
  return ( iI11Iii1I111 )
  if 54 - 54: O0 * Ii1I + Ii1I
 return ( o0oo0OoOo000 )
 if 59 - 59: i11iIiiIii % iII111i
 if 54 - 54: I11i . ooOoO0o / OOooOOo % I1Ii111
 if 13 - 13: I11i / O0 . o0oOOo0O0Ooo . ooOoO0o
 if 7 - 7: OoO0O00 + OoooooooOO % II111iiii % oO0o
 if 48 - 48: OOooOOo . II111iiii * OOooOOo - I11i / iIii1I11I1II1 / i11iIiiIii
 if 37 - 37: II111iiii % O0 + iIii1I11I1II1 - I1IiiI . I11i + I1ii11iIi11i
 if 14 - 14: ooOoO0o % iIii1I11I1II1 % ooOoO0o / IiII + OOooOOo
 if 14 - 14: Oo0Ooo
 if 79 - 79: I1ii11iIi11i % I1Ii111 % I11i - iII111i * OoOoOO00
def lisp_get_partial_rloc_set ( registered_rloc_set , mr_source , multicast ) :
 iiIIi1 = [ ]
 o0oo0OoOo000 = [ ]
 if 61 - 61: ooOoO0o
 if 23 - 23: OoooooooOO - OoOoOO00 / i11iIiiIii
 if 37 - 37: I11i / o0oOOo0O0Ooo + oO0o % Ii1I
 if 83 - 83: I1ii11iIi11i . OOooOOo
 if 50 - 50: Ii1I - i11iIiiIii % Ii1I - OoOoOO00 + I1IiiI / OoooooooOO
 if 57 - 57: I1IiiI - I11i - I1Ii111 . oO0o % Ii1I
 oooOO00o00 = False
 oOOo0O = False
 for O0OooOoooO0O in registered_rloc_set :
  if ( O0OooOoooO0O . priority != 254 ) : continue
  oOOo0O |= True
  if ( O0OooOoooO0O . rloc . is_exact_match ( mr_source ) == False ) : continue
  oooOO00o00 = True
  break
  if 69 - 69: i1IIi + II111iiii / Ii1I
  if 4 - 4: I11i * OoOoOO00 % o0oOOo0O0Ooo % ooOoO0o - I1ii11iIi11i
  if 88 - 88: iIii1I11I1II1 * iIii1I11I1II1 * I11i * OoOoOO00
  if 14 - 14: i11iIiiIii * I1IiiI % O0 % iIii1I11I1II1
  if 18 - 18: Oo0Ooo % OOooOOo + IiII
  if 28 - 28: OOooOOo . OoO0O00 / o0oOOo0O0Ooo + II111iiii / iIii1I11I1II1 * II111iiii
  if 83 - 83: II111iiii . OoOoOO00 - i11iIiiIii . OoOoOO00 . i1IIi % OoooooooOO
 if ( oOOo0O == False ) : return ( registered_rloc_set )
 if 47 - 47: II111iiii
 if 30 - 30: i1IIi . Oo0Ooo / o0oOOo0O0Ooo + IiII * OOooOOo
 if 26 - 26: Ii1I % O0 - i1IIi % iII111i * OoO0O00
 if 60 - 60: I1ii11iIi11i * iII111i / OoOoOO00 . o0oOOo0O0Ooo / iIii1I11I1II1
 if 94 - 94: OoO0O00 . ooOoO0o
 if 25 - 25: I1Ii111 % OOooOOo
 if 82 - 82: Ii1I
 if 17 - 17: iII111i . i1IIi . i1IIi
 if 76 - 76: OoooooooOO % IiII
 if 81 - 81: iII111i . OOooOOo * i1IIi
 iii1iIi11 = ( os . getenv ( "LISP_RTR_BEHIND_NAT" ) != None )
 if 65 - 65: i11iIiiIii
 if 11 - 11: i1IIi - Oo0Ooo % O0 . II111iiii % oO0o
 if 43 - 43: I1Ii111 - Oo0Ooo % II111iiii / Ii1I . iII111i . iIii1I11I1II1
 if 69 - 69: I11i - I11i / I11i + IiII - I1IiiI
 if 21 - 21: I1IiiI * OoO0O00 * oO0o . o0oOOo0O0Ooo + II111iiii
 for O0OooOoooO0O in registered_rloc_set :
  if ( iii1iIi11 and O0OooOoooO0O . rloc . is_private_address ( ) ) : continue
  if ( multicast == False and O0OooOoooO0O . priority == 255 ) : continue
  if ( multicast and O0OooOoooO0O . mpriority == 255 ) : continue
  if ( O0OooOoooO0O . priority == 254 ) :
   iiIIi1 . append ( O0OooOoooO0O )
  else :
   o0oo0OoOo000 . append ( O0OooOoooO0O )
   if 62 - 62: ooOoO0o - OoooooooOO / I1ii11iIi11i / iII111i - o0oOOo0O0Ooo
   if 70 - 70: oO0o % OoooooooOO * I1IiiI - OoOoOO00 * OoOoOO00 . OOooOOo
   if 9 - 9: iII111i * Oo0Ooo % iII111i % Oo0Ooo * II111iiii
   if 71 - 71: II111iiii + I1ii11iIi11i * II111iiii
   if 59 - 59: OoO0O00
   if 81 - 81: i11iIiiIii
 if ( oooOO00o00 ) : return ( o0oo0OoOo000 )
 if 57 - 57: Oo0Ooo * iIii1I11I1II1 - OoOoOO00 % iII111i % I1ii11iIi11i + Ii1I
 if 82 - 82: IiII * Oo0Ooo - iIii1I11I1II1 - i11iIiiIii
 if 85 - 85: OoooooooOO
 if 37 - 37: OoooooooOO + O0 + I1ii11iIi11i + IiII * iII111i
 if 15 - 15: i11iIiiIii / Oo0Ooo - OOooOOo . IiII
 if 11 - 11: OOooOOo / i1IIi % Oo0Ooo
 if 65 - 65: OOooOOo % I1ii11iIi11i
 if 25 - 25: o0oOOo0O0Ooo - I1Ii111 * I1ii11iIi11i + OoooooooOO
 if 93 - 93: OoOoOO00 % I1ii11iIi11i * I11i
 if 34 - 34: I11i - oO0o + I11i * OoooooooOO * I11i
 o0oo0OoOo000 = [ ]
 for O0OooOoooO0O in registered_rloc_set :
  if ( O0OooOoooO0O . rloc . is_private_address ( ) ) : o0oo0OoOo000 . append ( O0OooOoooO0O )
  if 73 - 73: OOooOOo * iII111i * OoO0O00
 o0oo0OoOo000 += iiIIi1
 return ( o0oo0OoOo000 )
 if 11 - 11: I1Ii111 * II111iiii
 if 3 - 3: Oo0Ooo * OOooOOo
 if 13 - 13: I1Ii111 + i11iIiiIii / OOooOOo
 if 98 - 98: I1IiiI * Oo0Ooo
 if 9 - 9: O0 / i11iIiiIii . iIii1I11I1II1 . IiII
 if 14 - 14: OoOoOO00 . OOooOOo - Oo0Ooo + I1Ii111 % ooOoO0o
 if 95 - 95: OoO0O00 * II111iiii + i1IIi
 if 22 - 22: Ii1I / ooOoO0o % I11i + OoO0O00 . ooOoO0o
 if 61 - 61: O0 - iIii1I11I1II1 * Oo0Ooo . Ii1I + O0
 if 20 - 20: ooOoO0o / ooOoO0o - Ii1I - ooOoO0o
def lisp_store_pubsub_state ( reply_eid , itr_rloc , mr_sport , nonce , ttl , xtr_id ) :
 oo0OoooOOoOo = lisp_pubsub ( itr_rloc , mr_sport , nonce , ttl , xtr_id )
 oo0OoooOOoOo . add ( reply_eid )
 return
 if 81 - 81: oO0o . OoOoOO00 * I1Ii111 * iIii1I11I1II1 . OoooooooOO + I1Ii111
 if 95 - 95: O0 - OoooooooOO * OOooOOo % oO0o * iII111i
 if 70 - 70: I11i + O0 . i11iIiiIii . OOooOOo
 if 48 - 48: iIii1I11I1II1 * Ii1I - OoooooooOO / oO0o - OoO0O00 / i11iIiiIii
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
def lisp_convert_reply_to_notify ( packet ) :
 if 93 - 93: OoO0O00 * OoO0O00 * I1ii11iIi11i * OoO0O00 * o0oOOo0O0Ooo
 if 84 - 84: I1Ii111 * OoO0O00 - ooOoO0o - Oo0Ooo . OoO0O00 % oO0o
 if 98 - 98: OoO0O00 . i1IIi
 if 58 - 58: i1IIi * O0 + I1ii11iIi11i . IiII
 I1Ii11 = struct . unpack ( "I" , packet [ 0 : 4 ] ) [ 0 ]
 I1Ii11 = socket . ntohl ( I1Ii11 ) & 0xff
 Iii11I = packet [ 4 : 12 ]
 packet = packet [ 12 : : ]
 if 99 - 99: OoO0O00 . OoOoOO00 / I1ii11iIi11i
 if 39 - 39: o0oOOo0O0Ooo
 if 45 - 45: ooOoO0o - I1Ii111 * iIii1I11I1II1
 if 6 - 6: ooOoO0o % I1Ii111 % ooOoO0o . Ii1I * Oo0Ooo . IiII
 iII = ( LISP_MAP_NOTIFY << 28 ) | I1Ii11
 O0ooOoO0 = struct . pack ( "I" , socket . htonl ( iII ) )
 o00O0o00oo = struct . pack ( "I" , 0 )
 if 100 - 100: i1IIi . Ii1I . o0oOOo0O0Ooo + Ii1I - i1IIi . I11i
 if 19 - 19: i11iIiiIii + I11i - IiII . iII111i * i1IIi
 if 66 - 66: ooOoO0o
 if 4 - 4: iII111i / iII111i * OOooOOo + o0oOOo0O0Ooo . I1Ii111 + II111iiii
 packet = O0ooOoO0 + Iii11I + o00O0o00oo + packet
 return ( packet )
 if 90 - 90: IiII * iII111i % OoOoOO00 . i11iIiiIii
 if 5 - 5: O0 * i1IIi / IiII
 if 4 - 4: II111iiii
 if 60 - 60: ooOoO0o - II111iiii * OoO0O00 + oO0o - iII111i
 if 39 - 39: OoO0O00 % I1Ii111 * I11i * Ii1I
 if 84 - 84: Oo0Ooo / OoO0O00 - II111iiii - OoOoOO00 - O0
 if 18 - 18: oO0o * I11i / o0oOOo0O0Ooo - OoooooooOO
 if 21 - 21: O0 - OoooooooOO
def lisp_notify_subscribers ( lisp_sockets , eid_record , eid , site ) :
 I11i11i1 = eid . print_prefix ( )
 if ( lisp_pubsub_cache . has_key ( I11i11i1 ) == False ) : return
 if 21 - 21: iII111i * o0oOOo0O0Ooo
 for oo0OoooOOoOo in lisp_pubsub_cache [ I11i11i1 ] . values ( ) :
  I11iiII1I1111 = oo0OoooOOoOo . itr
  Oo0O00O = oo0OoooOOoOo . port
  I111iI1IIIi1I = red ( I11iiII1I1111 . print_address_no_iid ( ) , False )
  OOoI1Ii = bold ( "subscriber" , False )
  I1II = "0x" + lisp_hex_string ( oo0OoooOOoOo . xtr_id )
  Iii11I = "0x" + lisp_hex_string ( oo0OoooOOoOo . nonce )
  if 72 - 72: Ii1I / I1Ii111 + Oo0Ooo + II111iiii % OoOoOO00 % OOooOOo
  lprint ( "    Notify {} {}:{} xtr-id {} for {}, nonce {}" . format ( OOoI1Ii , I111iI1IIIi1I , Oo0O00O , I1II , green ( I11i11i1 , False ) , Iii11I ) )
  if 40 - 40: I1ii11iIi11i + i1IIi
  if 9 - 9: OOooOOo
  lisp_build_map_notify ( lisp_sockets , eid_record , [ I11i11i1 ] , 1 , I11iiII1I1111 ,
 Oo0O00O , oo0OoooOOoOo . nonce , 0 , 0 , 0 , site , False )
  oo0OoooOOoOo . map_notify_count += 1
  if 74 - 74: OoOoOO00 - OOooOOo % OoOoOO00
 return
 if 82 - 82: I11i % IiII + Oo0Ooo + iIii1I11I1II1 - I11i - I1IiiI
 if 65 - 65: IiII / O0 * II111iiii + oO0o
 if 52 - 52: o0oOOo0O0Ooo - OoOoOO00 * II111iiii / OoooooooOO
 if 44 - 44: OOooOOo - oO0o + o0oOOo0O0Ooo - i1IIi % o0oOOo0O0Ooo
 if 79 - 79: iII111i . iIii1I11I1II1
 if 42 - 42: i11iIiiIii / IiII . O0 / OOooOOo . iII111i * i1IIi
 if 83 - 83: iIii1I11I1II1 . II111iiii * Oo0Ooo . I1IiiI - I1IiiI - iIii1I11I1II1
def lisp_process_pubsub ( lisp_sockets , packet , reply_eid , itr_rloc , port , nonce ,
 ttl , xtr_id ) :
 if 29 - 29: Oo0Ooo
 if 35 - 35: OoOoOO00 + II111iiii
 if 46 - 46: O0 / I1ii11iIi11i + OOooOOo - I1Ii111 + I1IiiI - ooOoO0o
 if 96 - 96: IiII + i1IIi - I11i * I11i - OoO0O00 % II111iiii
 lisp_store_pubsub_state ( reply_eid , itr_rloc , port , nonce , ttl , xtr_id )
 if 47 - 47: I1Ii111 . i11iIiiIii + oO0o . I1ii11iIi11i
 ooOOoo0 = green ( reply_eid . print_prefix ( ) , False )
 I11iiII1I1111 = red ( itr_rloc . print_address_no_iid ( ) , False )
 Ii11iI1ii1 = bold ( "Map-Notify" , False )
 xtr_id = "0x" + lisp_hex_string ( xtr_id )
 lprint ( "{} pubsub request for {} to ack ITR {} xtr-id: {}" . format ( Ii11iI1ii1 ,
 ooOOoo0 , I11iiII1I1111 , xtr_id ) )
 if 69 - 69: o0oOOo0O0Ooo . iIii1I11I1II1 + OoOoOO00 * OoO0O00
 if 57 - 57: i11iIiiIii * i11iIiiIii % I1Ii111 - iII111i * O0 - Ii1I
 if 63 - 63: IiII % OoooooooOO * OoOoOO00 * iIii1I11I1II1 . iII111i % oO0o
 if 58 - 58: I11i * iII111i + I11i % OoO0O00
 packet = lisp_convert_reply_to_notify ( packet )
 lisp_send_map_notify ( lisp_sockets , packet , itr_rloc , port )
 return
 if 19 - 19: Oo0Ooo
 if 43 - 43: oO0o % ooOoO0o
 if 36 - 36: I11i / I1IiiI + O0 % II111iiii
 if 24 - 24: I1Ii111 / o0oOOo0O0Ooo - OOooOOo / IiII
 if 7 - 7: OoooooooOO - i11iIiiIii * i11iIiiIii / oO0o * i1IIi % OoooooooOO
 if 6 - 6: I1ii11iIi11i * i11iIiiIii % i11iIiiIii / I1Ii111
 if 21 - 21: oO0o
 if 47 - 47: I1ii11iIi11i
def lisp_ms_process_map_request ( lisp_sockets , packet , map_request , mr_source ,
 mr_sport , ecm_source ) :
 if 24 - 24: I1Ii111 % iIii1I11I1II1
 if 87 - 87: OoOoOO00 - II111iiii + Oo0Ooo
 if 44 - 44: i1IIi + I1ii11iIi11i / iIii1I11I1II1
 if 47 - 47: I1Ii111
 if 41 - 41: IiII
 if 25 - 25: I11i % iIii1I11I1II1
 ooOOoo0 = map_request . target_eid
 IIi1iiIII11 = map_request . target_group
 I11i11i1 = lisp_print_eid_tuple ( ooOOoo0 , IIi1iiIII11 )
 iIi1i1i = map_request . itr_rlocs [ 0 ]
 I1II = map_request . xtr_id
 Iii11I = map_request . nonce
 I11I1iI = LISP_NO_ACTION
 oo0OoooOOoOo = map_request . subscribe_bit
 if 27 - 27: iIii1I11I1II1 . O0 . oO0o
 if 21 - 21: oO0o * I1ii11iIi11i
 if 44 - 44: o0oOOo0O0Ooo * IiII - o0oOOo0O0Ooo
 if 90 - 90: i1IIi + I1ii11iIi11i * oO0o % i11iIiiIii - OoO0O00
 if 12 - 12: OoO0O00 . I1ii11iIi11i - I1IiiI % OOooOOo
 i1i1 = True
 i111iiiiiI1 = ( lisp_get_eid_hash ( ooOOoo0 ) != None )
 if ( i111iiiiiI1 ) :
  O0OO0OoO00oOo = map_request . map_request_signature
  if ( O0OO0OoO00oOo == None ) :
   i1i1 = False
   lprint ( ( "EID-crypto-hash signature verification {}, " + "no signature found" ) . format ( bold ( "failed" , False ) ) )
   if 40 - 40: OoooooooOO / Ii1I
  else :
   Oo0o0ooOo0 = map_request . signature_eid
   oo0OOo00OOoO , I11iIi1i1iiI , i1i1 = lisp_lookup_public_key ( Oo0o0ooOo0 )
   if ( i1i1 ) :
    i1i1 = map_request . verify_map_request_sig ( I11iIi1i1iiI )
   else :
    lprint ( "Public-key lookup failed for sig-eid {}, hash-eid {}" . format ( Oo0o0ooOo0 . print_address ( ) , oo0OOo00OOoO . print_address ( ) ) )
    if 90 - 90: ooOoO0o / I11i + ooOoO0o + I1Ii111
    if 89 - 89: OoO0O00 + OoOoOO00
   ooo0Oo0 = bold ( "passed" , False ) if i1i1 else bold ( "failed" , False )
   lprint ( "EID-crypto-hash signature verification {}" . format ( ooo0Oo0 ) )
   if 83 - 83: Ii1I % IiII + II111iiii
   if 83 - 83: II111iiii
   if 42 - 42: I1IiiI . i1IIi
 if ( oo0OoooOOoOo and i1i1 == False ) :
  oo0OoooOOoOo = False
  lprint ( "Suppress creating pubsub state due to signature failure" )
  if 98 - 98: o0oOOo0O0Ooo % I11i . Oo0Ooo * Oo0Ooo % iII111i
  if 37 - 37: OoO0O00 / I1Ii111 . I1Ii111 * i1IIi
  if 22 - 22: I1ii11iIi11i . II111iiii + iIii1I11I1II1 / OoooooooOO . ooOoO0o
  if 13 - 13: II111iiii
  if 36 - 36: iII111i - oO0o / Oo0Ooo / O0 . OoO0O00 . i1IIi
  if 19 - 19: O0 . OoooooooOO % iIii1I11I1II1 - Ii1I . Ii1I + I1IiiI
  if 98 - 98: oO0o . Oo0Ooo
  if 9 - 9: I1Ii111 % IiII - i11iIiiIii - OOooOOo % iII111i % OoooooooOO
  if 6 - 6: i1IIi - II111iiii * OoOoOO00 + oO0o
  if 6 - 6: I1IiiI - ooOoO0o + I1IiiI + OoO0O00 - i11iIiiIii % ooOoO0o
  if 64 - 64: OoooooooOO + OOooOOo
  if 36 - 36: I1IiiI - Ii1I / I1ii11iIi11i + Oo0Ooo % I1ii11iIi11i
  if 86 - 86: iIii1I11I1II1 * OoO0O00
  if 82 - 82: I1IiiI - OoO0O00 % o0oOOo0O0Ooo
 Oo0Oo0o = iIi1i1i if ( iIi1i1i . afi == ecm_source . afi ) else ecm_source
 if 64 - 64: OoO0O00 * Oo0Ooo . II111iiii * Oo0Ooo % ooOoO0o - IiII
 I11111Ii = lisp_site_eid_lookup ( ooOOoo0 , IIi1iiIII11 , False )
 if 98 - 98: IiII * OOooOOo % OOooOOo % I1Ii111
 if ( I11111Ii == None or I11111Ii . is_star_g ( ) ) :
  I1Ii1i1 = bold ( "Site not found" , False )
  lprint ( "{} for requested EID {}" . format ( I1Ii1i1 ,
 green ( I11i11i1 , False ) ) )
  if 98 - 98: IiII - o0oOOo0O0Ooo
  if 55 - 55: I1ii11iIi11i
  if 20 - 20: iII111i - Ii1I - i1IIi
  if 97 - 97: oO0o % iII111i - OOooOOo . OoooooooOO
  lisp_send_negative_map_reply ( lisp_sockets , ooOOoo0 , IIi1iiIII11 , Iii11I , iIi1i1i ,
 mr_sport , 15 , I1II , oo0OoooOOoOo )
  if 94 - 94: Oo0Ooo
  return ( [ ooOOoo0 , IIi1iiIII11 , LISP_DDT_ACTION_SITE_NOT_FOUND ] )
  if 10 - 10: i11iIiiIii / I1ii11iIi11i . i1IIi + i1IIi * iII111i
  if 64 - 64: II111iiii % I1ii11iIi11i . OoOoOO00 . iIii1I11I1II1 / I1ii11iIi11i
 II1OO0Oo0oOOO000 = I11111Ii . print_eid_tuple ( )
 iiIi1iIIIII1 = I11111Ii . site . site_name
 if 1 - 1: iIii1I11I1II1
 if 59 - 59: ooOoO0o % I1IiiI + i1IIi * I1Ii111 % o0oOOo0O0Ooo * II111iiii
 if 22 - 22: OoOoOO00 * O0 + OoOoOO00 / iIii1I11I1II1 + oO0o + IiII
 if 69 - 69: iIii1I11I1II1 . I1Ii111 * iII111i
 if 6 - 6: I11i - IiII - I11i - II111iiii
 if ( i111iiiiiI1 == False and I11111Ii . require_signature ) :
  O0OO0OoO00oOo = map_request . map_request_signature
  Oo0o0ooOo0 = map_request . signature_eid
  if ( O0OO0OoO00oOo == None or Oo0o0ooOo0 . is_null ( ) ) :
   lprint ( "Signature required for site {}" . format ( iiIi1iIIIII1 ) )
   i1i1 = False
  else :
   Oo0o0ooOo0 = map_request . signature_eid
   oo0OOo00OOoO , I11iIi1i1iiI , i1i1 = lisp_lookup_public_key ( Oo0o0ooOo0 )
   if ( i1i1 ) :
    i1i1 = map_request . verify_map_request_sig ( I11iIi1i1iiI )
   else :
    lprint ( "Public-key lookup failed for sig-eid {}, hash-eid {}" . format ( Oo0o0ooOo0 . print_address ( ) , oo0OOo00OOoO . print_address ( ) ) )
    if 72 - 72: i1IIi / OOooOOo . Oo0Ooo . oO0o
    if 72 - 72: o0oOOo0O0Ooo % iIii1I11I1II1
   ooo0Oo0 = bold ( "passed" , False ) if i1i1 else bold ( "failed" , False )
   lprint ( "Required signature verification {}" . format ( ooo0Oo0 ) )
   if 74 - 74: Oo0Ooo % OOooOOo + i11iIiiIii
   if 17 - 17: OoOoOO00 . I1IiiI
   if 30 - 30: i1IIi * OoOoOO00 * I11i . O0
   if 45 - 45: iII111i
   if 99 - 99: o0oOOo0O0Ooo % ooOoO0o % i11iIiiIii
   if 32 - 32: IiII - Ii1I
 if ( i1i1 and I11111Ii . registered == False ) :
  lprint ( "Site '{}' with EID-prefix {} is not registered for EID {}" . format ( iiIi1iIIIII1 , green ( II1OO0Oo0oOOO000 , False ) , green ( I11i11i1 , False ) ) )
  if 44 - 44: OoooooooOO . oO0o
  if 30 - 30: I1Ii111 % IiII / II111iiii
  if 68 - 68: oO0o / O0 / OOooOOo
  if 3 - 3: o0oOOo0O0Ooo / o0oOOo0O0Ooo
  if 17 - 17: OoO0O00 * i1IIi
  if 50 - 50: OoOoOO00 + I11i
  if ( I11111Ii . accept_more_specifics == False ) :
   ooOOoo0 = I11111Ii . eid
   IIi1iiIII11 = I11111Ii . group
   if 56 - 56: OOooOOo * OOooOOo + I1IiiI % I1IiiI - I11i
   if 1 - 1: OoooooooOO . ooOoO0o - i1IIi
   if 73 - 73: iIii1I11I1II1 - I1Ii111 % Oo0Ooo . O0
   if 16 - 16: OoO0O00 / Oo0Ooo / IiII . Oo0Ooo - OoooooooOO
   if 5 - 5: OoOoOO00 . I11i
  oOoooOOO0o0 = 1
  if ( I11111Ii . force_ttl != None ) :
   oOoooOOO0o0 = I11111Ii . force_ttl | 0x80000000
   if 28 - 28: I11i % OOooOOo + Oo0Ooo / OoO0O00 % o0oOOo0O0Ooo + OoO0O00
   if 20 - 20: ooOoO0o . iII111i % OOooOOo + i11iIiiIii
   if 64 - 64: i1IIi . o0oOOo0O0Ooo * I1Ii111 - O0
   if 76 - 76: I1IiiI % Ii1I + OoO0O00 + I1ii11iIi11i * II111iiii + Oo0Ooo
   if 3 - 3: Ii1I - I1IiiI + O0
  lisp_send_negative_map_reply ( lisp_sockets , ooOOoo0 , IIi1iiIII11 , Iii11I , iIi1i1i ,
 mr_sport , oOoooOOO0o0 , I1II , oo0OoooOOoOo )
  if 90 - 90: Ii1I + OoooooooOO . i11iIiiIii / Oo0Ooo % OoOoOO00 / IiII
  return ( [ ooOOoo0 , IIi1iiIII11 , LISP_DDT_ACTION_MS_NOT_REG ] )
  if 45 - 45: OoooooooOO / oO0o . I1ii11iIi11i + OOooOOo
  if 54 - 54: Ii1I - o0oOOo0O0Ooo + OoOoOO00 / OoooooooOO
  if 61 - 61: I11i / IiII % OoooooooOO - i11iIiiIii * i1IIi % o0oOOo0O0Ooo
  if 67 - 67: o0oOOo0O0Ooo - Ii1I
  if 29 - 29: OoOoOO00 . I1ii11iIi11i
 I1iii1 = False
 i1IIiii = ""
 iIiiii1iIi11 = False
 if ( I11111Ii . force_nat_proxy_reply ) :
  i1IIiii = ", nat-forced"
  I1iii1 = True
  iIiiii1iIi11 = True
 elif ( I11111Ii . force_proxy_reply ) :
  i1IIiii = ", forced"
  iIiiii1iIi11 = True
 elif ( I11111Ii . proxy_reply_requested ) :
  i1IIiii = ", requested"
  iIiiii1iIi11 = True
 elif ( map_request . pitr_bit and I11111Ii . pitr_proxy_reply_drop ) :
  i1IIiii = ", drop-to-pitr"
  I11I1iI = LISP_DROP_ACTION
 elif ( I11111Ii . proxy_reply_action != "" ) :
  I11I1iI = I11111Ii . proxy_reply_action
  i1IIiii = ", forced, action {}" . format ( I11I1iI )
  I11I1iI = LISP_DROP_ACTION if ( I11I1iI == "drop" ) else LISP_NATIVE_FORWARD_ACTION
  if 18 - 18: OoooooooOO / I1ii11iIi11i * i1IIi / i11iIiiIii + Oo0Ooo / Ii1I
  if 12 - 12: I1IiiI - II111iiii / O0 . II111iiii + II111iiii - I1ii11iIi11i
  if 48 - 48: O0 % I1ii11iIi11i
  if 72 - 72: I1IiiI - i1IIi
  if 11 - 11: iIii1I11I1II1 . OoO0O00 * Ii1I
  if 65 - 65: Oo0Ooo / OoooooooOO
  if 60 - 60: II111iiii + I1IiiI % oO0o - o0oOOo0O0Ooo
 IiiiI1i1 = False
 Oo0o = None
 if ( iIiiii1iIi11 and lisp_policies . has_key ( I11111Ii . policy ) ) :
  oo00ooOOOo0O = lisp_policies [ I11111Ii . policy ]
  if ( oo00ooOOOo0O . match_policy_map_request ( map_request , mr_source ) ) : Oo0o = oo00ooOOOo0O
  if 69 - 69: OoOoOO00 + IiII
  if ( Oo0o ) :
   O0oo0000o = bold ( "matched" , False )
   lprint ( "Map-Request {} policy '{}', set-action '{}'" . format ( O0oo0000o ,
 oo00ooOOOo0O . policy_name , oo00ooOOOo0O . set_action ) )
  else :
   O0oo0000o = bold ( "no match" , False )
   lprint ( "Map-Request {} for policy '{}', implied drop" . format ( O0oo0000o ,
 oo00ooOOOo0O . policy_name ) )
   IiiiI1i1 = True
   if 18 - 18: O0 / I11i
   if 10 - 10: I1Ii111 * i1IIi
   if 48 - 48: Oo0Ooo % i1IIi / iII111i . O0
 if ( i1IIiii != "" ) :
  lprint ( "Proxy-replying for EID {}, found site '{}' EID-prefix {}{}" . format ( green ( I11i11i1 , False ) , iiIi1iIIIII1 , green ( II1OO0Oo0oOOO000 , False ) ,
  # OoO0O00 + I11i
 i1IIiii ) )
  if 60 - 60: i11iIiiIii
  o0oo0OoOo000 = I11111Ii . registered_rlocs
  oOoooOOO0o0 = 1440
  if ( I1iii1 ) :
   if ( I11111Ii . site_id != 0 ) :
    O00O0o = map_request . source_eid
    o0oo0OoOo000 = lisp_get_private_rloc_set ( I11111Ii , O00O0o , IIi1iiIII11 )
    if 86 - 86: I1Ii111
   if ( o0oo0OoOo000 == I11111Ii . registered_rlocs ) :
    OOIiIi1 = ( I11111Ii . group . is_null ( ) == False )
    iI11Iii1I111 = lisp_get_partial_rloc_set ( o0oo0OoOo000 , Oo0Oo0o , OOIiIi1 )
    if ( iI11Iii1I111 != o0oo0OoOo000 ) :
     oOoooOOO0o0 = 15
     o0oo0OoOo000 = iI11Iii1I111
     if 32 - 32: ooOoO0o
     if 9 - 9: I1Ii111
     if 77 - 77: OoooooooOO * I1Ii111
     if 63 - 63: IiII * oO0o * iIii1I11I1II1
     if 18 - 18: II111iiii * o0oOOo0O0Ooo % i11iIiiIii . OoOoOO00
     if 40 - 40: oO0o - o0oOOo0O0Ooo * II111iiii
     if 4 - 4: O0
     if 9 - 9: Oo0Ooo . i1IIi - i1IIi + I1Ii111 * ooOoO0o . I1ii11iIi11i
  if ( I11111Ii . force_ttl != None ) :
   oOoooOOO0o0 = I11111Ii . force_ttl | 0x80000000
   if 17 - 17: I11i * I1ii11iIi11i % I1IiiI + OoO0O00 + IiII
   if 90 - 90: OoooooooOO - I1IiiI / I1ii11iIi11i + oO0o - o0oOOo0O0Ooo
   if 84 - 84: OoOoOO00 + O0 % Oo0Ooo
   if 22 - 22: iIii1I11I1II1 % i11iIiiIii
   if 29 - 29: ooOoO0o - iII111i + IiII % Ii1I - oO0o - ooOoO0o
   if 43 - 43: oO0o
  if ( Oo0o ) :
   if ( Oo0o . set_record_ttl ) :
    oOoooOOO0o0 = Oo0o . set_record_ttl
    lprint ( "Policy set-record-ttl to {}" . format ( oOoooOOO0o0 ) )
    if 22 - 22: I1Ii111 + i11iIiiIii
   if ( Oo0o . set_action == "drop" ) :
    lprint ( "Policy set-action drop, send negative Map-Reply" )
    I11I1iI = LISP_POLICY_DENIED_ACTION
    o0oo0OoOo000 = [ ]
   else :
    I1IIiIIIii = Oo0o . set_policy_map_reply ( )
    if ( I1IIiIIIii ) : o0oo0OoOo000 = [ I1IIiIIIii ]
    if 49 - 49: O0 % II111iiii . OOooOOo + iII111i + iIii1I11I1II1 / i11iIiiIii
    if 79 - 79: II111iiii + ooOoO0o - i1IIi - i1IIi + II111iiii . i1IIi
    if 78 - 78: I1IiiI * I11i % OOooOOo + Ii1I + OoOoOO00
  if ( IiiiI1i1 ) :
   lprint ( "Implied drop action, send negative Map-Reply" )
   I11I1iI = LISP_POLICY_DENIED_ACTION
   o0oo0OoOo000 = [ ]
   if 23 - 23: iII111i / Oo0Ooo % OoooooooOO * OoooooooOO . iII111i / I1ii11iIi11i
   if 30 - 30: oO0o - OoOoOO00 . I1IiiI
  iI = I11111Ii . echo_nonce_capable
  if 17 - 17: OoOoOO00
  if 76 - 76: I1ii11iIi11i - ooOoO0o % OoooooooOO / Oo0Ooo % IiII / ooOoO0o
  if 57 - 57: O0
  if 23 - 23: OoO0O00 / II111iiii . I1ii11iIi11i . O0
  if ( i1i1 ) :
   ii1i1I1i = I11111Ii . eid
   Oooooo = I11111Ii . group
  else :
   ii1i1I1i = ooOOoo0
   Oooooo = IIi1iiIII11
   I11I1iI = LISP_AUTH_FAILURE_ACTION
   o0oo0OoOo000 = [ ]
   if 44 - 44: o0oOOo0O0Ooo / iIii1I11I1II1
   if 40 - 40: OoO0O00 / O0
   if 60 - 60: iIii1I11I1II1 / Oo0Ooo / oO0o + iII111i
   if 66 - 66: iIii1I11I1II1 . O0 * IiII . ooOoO0o + i1IIi
   if 83 - 83: o0oOOo0O0Ooo / II111iiii + I1IiiI - iII111i + OoO0O00
   if 67 - 67: I1Ii111 - OoOoOO00 . i11iIiiIii - I1Ii111 . i11iIiiIii
  packet = lisp_build_map_reply ( ii1i1I1i , Oooooo , o0oo0OoOo000 ,
 Iii11I , I11I1iI , oOoooOOO0o0 , map_request , None , iI , False )
  if 25 - 25: I11i % I1Ii111 + Ii1I
  if ( oo0OoooOOoOo ) :
   lisp_process_pubsub ( lisp_sockets , packet , ii1i1I1i , iIi1i1i ,
 mr_sport , Iii11I , oOoooOOO0o0 , I1II )
  else :
   lisp_send_map_reply ( lisp_sockets , packet , iIi1i1i , mr_sport )
   if 46 - 46: ooOoO0o + Oo0Ooo + oO0o / II111iiii . iIii1I11I1II1 * I1IiiI
   if 87 - 87: I11i + iIii1I11I1II1
  return ( [ I11111Ii . eid , I11111Ii . group , LISP_DDT_ACTION_MS_ACK ] )
  if 91 - 91: oO0o
  if 58 - 58: i11iIiiIii / Ii1I - OoooooooOO
  if 25 - 25: i1IIi * ooOoO0o % OOooOOo / I1IiiI
  if 75 - 75: i11iIiiIii
  if 38 - 38: iIii1I11I1II1
 Ii1 = len ( I11111Ii . registered_rlocs )
 if ( Ii1 == 0 ) :
  lprint ( "Requested EID {} found site '{}' with EID-prefix {} with " + "no registered RLOCs" . format ( green ( I11i11i1 , False ) , iiIi1iIIIII1 ,
  # OoO0O00 . I1IiiI % I11i * iII111i / OoOoOO00
 green ( II1OO0Oo0oOOO000 , False ) ) )
  return ( [ I11111Ii . eid , I11111Ii . group , LISP_DDT_ACTION_MS_ACK ] )
  if 16 - 16: OoO0O00 * ooOoO0o / II111iiii % OOooOOo . I1ii11iIi11i * i1IIi
  if 18 - 18: I1IiiI + OoOoOO00
  if 17 - 17: i1IIi . Ii1I
  if 96 - 96: OoOoOO00 / Oo0Ooo . II111iiii / ooOoO0o
  if 56 - 56: IiII - ooOoO0o % oO0o / Oo0Ooo * oO0o % O0
 O0Ooo = map_request . target_eid if map_request . source_eid . is_null ( ) else map_request . source_eid
 if 26 - 26: I1ii11iIi11i / i11iIiiIii
 IIi1iiIIi1i = map_request . target_eid . hash_address ( O0Ooo )
 IIi1iiIIi1i %= Ii1
 ii11Ii11II = I11111Ii . registered_rlocs [ IIi1iiIIi1i ]
 if 49 - 49: iIii1I11I1II1 % Oo0Ooo % I11i * Ii1I - OoO0O00
 if ( ii11Ii11II . rloc . is_null ( ) ) :
  lprint ( ( "Suppress forwarding Map-Request for EID {} at site '{}' " + "EID-prefix {}, no RLOC address" ) . format ( green ( I11i11i1 , False ) ,
  # oO0o
 iiIi1iIIIII1 , green ( II1OO0Oo0oOOO000 , False ) ) )
 else :
  lprint ( ( "Forwarding Map-Request for EID {} to ETR {} at site '{}' " + "EID-prefix {}" ) . format ( green ( I11i11i1 , False ) ,
  # iIii1I11I1II1 . i11iIiiIii - Ii1I
 red ( ii11Ii11II . rloc . print_address ( ) , False ) , iiIi1iIIIII1 ,
 green ( II1OO0Oo0oOOO000 , False ) ) )
  if 31 - 31: OoOoOO00
  if 72 - 72: II111iiii + i11iIiiIii * OoO0O00 / II111iiii / I11i
  if 59 - 59: OOooOOo
  if 9 - 9: I1IiiI + I1IiiI / I11i - OOooOOo % iIii1I11I1II1 / I1ii11iIi11i
  lisp_send_ecm ( lisp_sockets , packet , map_request . source_eid , mr_sport ,
 map_request . target_eid , ii11Ii11II . rloc , to_etr = True )
  if 40 - 40: I1Ii111 - OOooOOo * IiII + o0oOOo0O0Ooo - I1IiiI
 return ( [ I11111Ii . eid , I11111Ii . group , LISP_DDT_ACTION_MS_ACK ] )
 if 75 - 75: I1IiiI
 if 84 - 84: OoO0O00 . I1ii11iIi11i - i11iIiiIii / I1Ii111 / i1IIi
 if 26 - 26: IiII + OOooOOo / I1Ii111 . i1IIi
 if 59 - 59: iIii1I11I1II1 / I1Ii111 * o0oOOo0O0Ooo
 if 38 - 38: iIii1I11I1II1 . oO0o * I1ii11iIi11i + iII111i
 if 90 - 90: IiII % I1ii11iIi11i - I1ii11iIi11i - iII111i
 if 63 - 63: O0 % i1IIi + OoOoOO00 + I11i . IiII + ooOoO0o
def lisp_ddt_process_map_request ( lisp_sockets , map_request , ecm_source , port ) :
 if 19 - 19: O0 - i1IIi / I1Ii111
 if 14 - 14: I11i - i11iIiiIii
 if 49 - 49: oO0o . I1ii11iIi11i
 if 51 - 51: OOooOOo + o0oOOo0O0Ooo . OOooOOo
 ooOOoo0 = map_request . target_eid
 IIi1iiIII11 = map_request . target_group
 I11i11i1 = lisp_print_eid_tuple ( ooOOoo0 , IIi1iiIII11 )
 Iii11I = map_request . nonce
 I11I1iI = LISP_DDT_ACTION_NULL
 if 23 - 23: iIii1I11I1II1 + OoO0O00 / I1IiiI
 if 48 - 48: OoOoOO00 + I11i + oO0o . I1IiiI
 if 7 - 7: iII111i * i1IIi % OoOoOO00 % Ii1I . I1IiiI
 if 53 - 53: OOooOOo / I11i + OOooOOo / I1IiiI / OoO0O00
 if 12 - 12: i11iIiiIii % ooOoO0o / iII111i . IiII
 OOOoo = None
 if ( lisp_i_am_ms ) :
  I11111Ii = lisp_site_eid_lookup ( ooOOoo0 , IIi1iiIII11 , False )
  if ( I11111Ii == None ) : return
  if 34 - 34: IiII * O0 % o0oOOo0O0Ooo * OoOoOO00 . iII111i - i1IIi
  if ( I11111Ii . registered ) :
   I11I1iI = LISP_DDT_ACTION_MS_ACK
   oOoooOOO0o0 = 1440
  else :
   ooOOoo0 , IIi1iiIII11 , I11I1iI = lisp_ms_compute_neg_prefix ( ooOOoo0 , IIi1iiIII11 )
   I11I1iI = LISP_DDT_ACTION_MS_NOT_REG
   oOoooOOO0o0 = 1
   if 40 - 40: OOooOOo / I1IiiI * OoooooooOO
 else :
  OOOoo = lisp_ddt_cache_lookup ( ooOOoo0 , IIi1iiIII11 , False )
  if ( OOOoo == None ) :
   I11I1iI = LISP_DDT_ACTION_NOT_AUTH
   oOoooOOO0o0 = 0
   lprint ( "DDT delegation entry not found for EID {}" . format ( green ( I11i11i1 , False ) ) )
   if 8 - 8: iII111i + I1ii11iIi11i
  elif ( OOOoo . is_auth_prefix ( ) ) :
   if 28 - 28: i1IIi
   if 69 - 69: OOooOOo % ooOoO0o - i1IIi . Oo0Ooo
   if 35 - 35: iIii1I11I1II1 - I11i / iIii1I11I1II1 % ooOoO0o % I1IiiI
   if 46 - 46: oO0o
   I11I1iI = LISP_DDT_ACTION_DELEGATION_HOLE
   oOoooOOO0o0 = 15
   IiIIIIi11ii = OOOoo . print_eid_tuple ( )
   lprint ( ( "DDT delegation entry not found but auth-prefix {} " + "found for EID {}" ) . format ( IiIIIIi11ii ,
   # o0oOOo0O0Ooo / Oo0Ooo . I1ii11iIi11i % o0oOOo0O0Ooo - I1Ii111 * I1Ii111
 green ( I11i11i1 , False ) ) )
   if 8 - 8: I1ii11iIi11i
   if ( IIi1iiIII11 . is_null ( ) ) :
    ooOOoo0 = lisp_ddt_compute_neg_prefix ( ooOOoo0 , OOOoo ,
 lisp_ddt_cache )
   else :
    IIi1iiIII11 = lisp_ddt_compute_neg_prefix ( IIi1iiIII11 , OOOoo ,
 lisp_ddt_cache )
    ooOOoo0 = lisp_ddt_compute_neg_prefix ( ooOOoo0 , OOOoo ,
 OOOoo . source_cache )
    if 45 - 45: i1IIi - OoO0O00 % Oo0Ooo
   OOOoo = None
  else :
   IiIIIIi11ii = OOOoo . print_eid_tuple ( )
   lprint ( "DDT delegation entry {} found for EID {}" . format ( IiIIIIi11ii , green ( I11i11i1 , False ) ) )
   if 42 - 42: ooOoO0o - I11i * iII111i
   oOoooOOO0o0 = 1440
   if 39 - 39: OOooOOo - I1ii11iIi11i % IiII % I1ii11iIi11i * II111iiii - Ii1I
   if 19 - 19: I11i % OoOoOO00 / OoO0O00 % I11i + o0oOOo0O0Ooo / iII111i
   if 35 - 35: ooOoO0o % I11i * I1ii11iIi11i
   if 10 - 10: OoO0O00 + OoooooooOO + I1Ii111
   if 57 - 57: Ii1I % Ii1I * Oo0Ooo % i11iIiiIii
   if 12 - 12: oO0o . Oo0Ooo . I1IiiI - i11iIiiIii / o0oOOo0O0Ooo
 IiiiIi1iiii11 = lisp_build_map_referral ( ooOOoo0 , IIi1iiIII11 , OOOoo , I11I1iI , oOoooOOO0o0 , Iii11I )
 Iii11I = map_request . nonce >> 32
 if ( map_request . nonce != 0 and Iii11I != 0xdfdf0e1d ) : port = LISP_CTRL_PORT
 lisp_send_map_referral ( lisp_sockets , IiiiIi1iiii11 , ecm_source , port )
 return
 if 54 - 54: i11iIiiIii + I1Ii111 . I1Ii111 * I1ii11iIi11i % I1Ii111 - OoooooooOO
 if 76 - 76: IiII + i1IIi + i11iIiiIii . oO0o
 if 23 - 23: ooOoO0o - OoO0O00 + oO0o . OOooOOo - I1IiiI
 if 66 - 66: iII111i % iII111i
 if 59 - 59: II111iiii . i1IIi % i1IIi
 if 40 - 40: I1Ii111 . II111iiii * o0oOOo0O0Ooo + I11i - i1IIi
 if 67 - 67: o0oOOo0O0Ooo - O0 - i1IIi . ooOoO0o . iII111i
 if 43 - 43: II111iiii . o0oOOo0O0Ooo + i11iIiiIii . O0 / O0 . II111iiii
 if 13 - 13: Ii1I % i11iIiiIii
 if 3 - 3: ooOoO0o % OoOoOO00 * I1Ii111 - OoO0O00 / i1IIi % I1IiiI
 if 50 - 50: I1ii11iIi11i + iII111i
 if 64 - 64: oO0o
 if 11 - 11: o0oOOo0O0Ooo
def lisp_find_negative_mask_len ( eid , entry_prefix , neg_prefix ) :
 ooIiIII1 = eid . hash_address ( entry_prefix )
 i1Ii1IiI = eid . addr_length ( ) * 8
 OO00O = 0
 if 7 - 7: oO0o - I11i
 if 59 - 59: Ii1I / o0oOOo0O0Ooo / OoO0O00 + IiII + i11iIiiIii
 if 64 - 64: o0oOOo0O0Ooo * IiII * IiII * iII111i % i11iIiiIii
 if 22 - 22: I1ii11iIi11i * II111iiii - OOooOOo % i11iIiiIii
 for OO00O in range ( i1Ii1IiI ) :
  i1IiOoOOO0O = 1 << ( i1Ii1IiI - OO00O - 1 )
  if ( ooIiIII1 & i1IiOoOOO0O ) : break
  if 35 - 35: I1IiiI . i1IIi
  if 83 - 83: iII111i
 if ( OO00O > neg_prefix . mask_len ) : neg_prefix . mask_len = OO00O
 return
 if 51 - 51: OoO0O00
 if 45 - 45: I1ii11iIi11i + Ii1I * I1ii11iIi11i % Ii1I - O0 * OoooooooOO
 if 98 - 98: OoO0O00 / o0oOOo0O0Ooo . OoooooooOO % i11iIiiIii % Oo0Ooo + OoOoOO00
 if 49 - 49: II111iiii - OOooOOo - I1IiiI / Ii1I
 if 47 - 47: I1ii11iIi11i + OoO0O00
 if 95 - 95: I11i . OoOoOO00 / Oo0Ooo % ooOoO0o % II111iiii
 if 82 - 82: ooOoO0o - I11i / I1Ii111 - i11iIiiIii - iIii1I11I1II1
 if 53 - 53: iIii1I11I1II1 % I11i . i1IIi + IiII / OoOoOO00 . II111iiii
 if 43 - 43: O0 - IiII + i11iIiiIii * i1IIi - ooOoO0o % IiII
 if 23 - 23: OoooooooOO % o0oOOo0O0Ooo + OoO0O00
def lisp_neg_prefix_walk ( entry , parms ) :
 ooOOoo0 , I1I111IiI1 , IIi1III = parms
 if 96 - 96: OoooooooOO
 if ( I1I111IiI1 == None ) :
  if ( entry . eid . instance_id != ooOOoo0 . instance_id ) :
   return ( [ True , parms ] )
   if 55 - 55: OoooooooOO / OOooOOo / iIii1I11I1II1 * iIii1I11I1II1 . o0oOOo0O0Ooo
  if ( entry . eid . afi != ooOOoo0 . afi ) : return ( [ True , parms ] )
 else :
  if ( entry . eid . is_more_specific ( I1I111IiI1 ) == False ) :
   return ( [ True , parms ] )
   if 68 - 68: OOooOOo % Oo0Ooo * ooOoO0o * OoO0O00 / iII111i
   if 96 - 96: i11iIiiIii - I1IiiI % OoOoOO00 * Ii1I % OoO0O00 % O0
   if 100 - 100: oO0o . OoooooooOO
   if 58 - 58: I11i % OoooooooOO
   if 97 - 97: OOooOOo - IiII
   if 77 - 77: i1IIi / IiII - o0oOOo0O0Ooo . Oo0Ooo / o0oOOo0O0Ooo . OoooooooOO
 lisp_find_negative_mask_len ( ooOOoo0 , entry . eid , IIi1III )
 return ( [ True , parms ] )
 if 54 - 54: i1IIi * i11iIiiIii / I1IiiI * i1IIi
 if 21 - 21: OoO0O00 - OOooOOo / i11iIiiIii * I1ii11iIi11i * ooOoO0o % Oo0Ooo
 if 11 - 11: I11i - O0 - I11i . o0oOOo0O0Ooo + OoooooooOO
 if 54 - 54: II111iiii / II111iiii - OOooOOo + IiII - i1IIi - I1ii11iIi11i
 if 86 - 86: I1ii11iIi11i / II111iiii - IiII + i1IIi
 if 21 - 21: IiII / i11iIiiIii / OoOoOO00
 if 75 - 75: Ii1I . i1IIi / I1IiiI * iII111i . IiII / OoOoOO00
 if 58 - 58: ooOoO0o + OOooOOo / ooOoO0o / i11iIiiIii
def lisp_ddt_compute_neg_prefix ( eid , ddt_entry , cache ) :
 if 95 - 95: ooOoO0o
 if 10 - 10: OoO0O00 % ooOoO0o * o0oOOo0O0Ooo
 if 37 - 37: Ii1I . o0oOOo0O0Ooo
 if 34 - 34: ooOoO0o * IiII . Ii1I + iIii1I11I1II1
 if ( eid . is_binary ( ) == False ) : return ( eid )
 if 1 - 1: i11iIiiIii + I11i
 IIi1III = lisp_address ( eid . afi , "" , 0 , 0 )
 IIi1III . copy_address ( eid )
 IIi1III . mask_len = 0
 if 78 - 78: Ii1I % Oo0Ooo / OoO0O00 . iIii1I11I1II1 . II111iiii
 oO000ooooOO = ddt_entry . print_eid_tuple ( )
 I1I111IiI1 = ddt_entry . eid
 if 55 - 55: I1Ii111 + iII111i
 if 15 - 15: I1IiiI
 if 88 - 88: IiII / I1ii11iIi11i % I11i + i11iIiiIii * O0 . I1Ii111
 if 69 - 69: Oo0Ooo - OOooOOo / I1IiiI . i11iIiiIii * OoO0O00
 if 45 - 45: I1Ii111 + OOooOOo
 eid , I1I111IiI1 , IIi1III = cache . walk_cache ( lisp_neg_prefix_walk ,
 ( eid , I1I111IiI1 , IIi1III ) )
 if 78 - 78: OoOoOO00 . Oo0Ooo % I11i
 if 7 - 7: I1ii11iIi11i % Ii1I . OoooooooOO - iII111i
 if 18 - 18: O0 * OoooooooOO % IiII - iIii1I11I1II1 % IiII * o0oOOo0O0Ooo
 if 13 - 13: OoO0O00 + i11iIiiIii + O0 / ooOoO0o % iIii1I11I1II1
 IIi1III . mask_address ( IIi1III . mask_len )
 if 75 - 75: oO0o / i1IIi / Ii1I * Oo0Ooo
 lprint ( ( "Least specific prefix computed from ddt-cache for EID {} " + "using auth-prefix {} is {}" ) . format ( green ( eid . print_address ( ) , False ) ,
 # II111iiii / OoooooooOO + I1ii11iIi11i * II111iiii - i11iIiiIii
 oO000ooooOO , IIi1III . print_prefix ( ) ) )
 return ( IIi1III )
 if 92 - 92: iII111i * Oo0Ooo + I1ii11iIi11i / OoooooooOO - Ii1I % I11i
 if 2 - 2: OoO0O00 . II111iiii
 if 10 - 10: iII111i - i11iIiiIii - i11iIiiIii / ooOoO0o
 if 76 - 76: IiII % OOooOOo
 if 34 - 34: I1IiiI
 if 56 - 56: OoooooooOO + O0 . II111iiii / i1IIi - O0 . iIii1I11I1II1
 if 94 - 94: i1IIi . Oo0Ooo / o0oOOo0O0Ooo % I1Ii111 / OOooOOo + OoOoOO00
 if 21 - 21: Oo0Ooo / Oo0Ooo
def lisp_ms_compute_neg_prefix ( eid , group ) :
 IIi1III = lisp_address ( eid . afi , "" , 0 , 0 )
 IIi1III . copy_address ( eid )
 IIi1III . mask_len = 0
 i1111i = lisp_address ( group . afi , "" , 0 , 0 )
 i1111i . copy_address ( group )
 i1111i . mask_len = 0
 I1I111IiI1 = None
 if 15 - 15: OoooooooOO - i1IIi - Oo0Ooo - IiII
 if 80 - 80: II111iiii - I1ii11iIi11i / iIii1I11I1II1 % Oo0Ooo . Ii1I
 if 33 - 33: OOooOOo + I1ii11iIi11i + I1Ii111 * I11i / OoO0O00 + o0oOOo0O0Ooo
 if 46 - 46: iII111i
 if 56 - 56: Oo0Ooo / II111iiii
 if ( group . is_null ( ) ) :
  OOOoo = lisp_ddt_cache . lookup_cache ( eid , False )
  if ( OOOoo == None ) :
   IIi1III . mask_len = IIi1III . host_mask_len ( )
   i1111i . mask_len = i1111i . host_mask_len ( )
   return ( [ IIi1III , i1111i , LISP_DDT_ACTION_NOT_AUTH ] )
   if 61 - 61: Ii1I - i1IIi / ooOoO0o - Oo0Ooo / IiII % Oo0Ooo
  Oo000o = lisp_sites_by_eid
  if ( OOOoo . is_auth_prefix ( ) ) : I1I111IiI1 = OOOoo . eid
 else :
  OOOoo = lisp_ddt_cache . lookup_cache ( group , False )
  if ( OOOoo == None ) :
   IIi1III . mask_len = IIi1III . host_mask_len ( )
   i1111i . mask_len = i1111i . host_mask_len ( )
   return ( [ IIi1III , i1111i , LISP_DDT_ACTION_NOT_AUTH ] )
   if 87 - 87: II111iiii
  if ( OOOoo . is_auth_prefix ( ) ) : I1I111IiI1 = OOOoo . group
  if 81 - 81: OoOoOO00 % I11i / i1IIi
  group , I1I111IiI1 , i1111i = lisp_sites_by_eid . walk_cache ( lisp_neg_prefix_walk , ( group , I1I111IiI1 , i1111i ) )
  if 87 - 87: II111iiii + oO0o - I1ii11iIi11i
  if 42 - 42: Oo0Ooo - ooOoO0o % OoOoOO00 + OoOoOO00
  i1111i . mask_address ( i1111i . mask_len )
  if 61 - 61: I1Ii111
  lprint ( ( "Least specific prefix computed from site-cache for " + "group EID {} using auth-prefix {} is {}" ) . format ( group . print_address ( ) , I1I111IiI1 . print_prefix ( ) if ( I1I111IiI1 != None ) else "'not found'" ,
  # II111iiii % i1IIi + o0oOOo0O0Ooo * iII111i
  # o0oOOo0O0Ooo * II111iiii % OOooOOo . ooOoO0o
  # II111iiii - i1IIi
 i1111i . print_prefix ( ) ) )
  if 48 - 48: iIii1I11I1II1 . OOooOOo % OOooOOo - OOooOOo % OoO0O00
  Oo000o = OOOoo . source_cache
  if 93 - 93: o0oOOo0O0Ooo + OoO0O00 / O0 / i11iIiiIii
  if 54 - 54: I1Ii111 * OoO0O00
  if 94 - 94: iIii1I11I1II1
  if 33 - 33: iII111i . iIii1I11I1II1 - Ii1I
  if 85 - 85: OoOoOO00
 I11I1iI = LISP_DDT_ACTION_DELEGATION_HOLE if ( I1I111IiI1 != None ) else LISP_DDT_ACTION_NOT_AUTH
 if 57 - 57: Oo0Ooo - II111iiii - I1ii11iIi11i * oO0o
 if 41 - 41: I11i / ooOoO0o + IiII % OoooooooOO
 if 72 - 72: Ii1I
 if 22 - 22: o0oOOo0O0Ooo / OoO0O00 + OoOoOO00 + Ii1I . II111iiii * I11i
 if 85 - 85: i11iIiiIii / I11i
 if 28 - 28: i11iIiiIii + IiII / I11i . Ii1I / OoO0O00
 eid , I1I111IiI1 , IIi1III = Oo000o . walk_cache ( lisp_neg_prefix_walk ,
 ( eid , I1I111IiI1 , IIi1III ) )
 if 100 - 100: o0oOOo0O0Ooo - I11i . o0oOOo0O0Ooo
 if 90 - 90: OoOoOO00 / II111iiii / I11i * I11i - iIii1I11I1II1
 if 87 - 87: IiII
 if 92 - 92: OoO0O00 / IiII - ooOoO0o
 IIi1III . mask_address ( IIi1III . mask_len )
 if 45 - 45: iII111i - I11i * ooOoO0o * OOooOOo / I1Ii111 * iII111i
 lprint ( ( "Least specific prefix computed from site-cache for EID {} " + "using auth-prefix {} is {}" ) . format ( green ( eid . print_address ( ) , False ) ,
 # I11i * iIii1I11I1II1
 # Ii1I - OoOoOO00 % I1IiiI . I11i
 I1I111IiI1 . print_prefix ( ) if ( I1I111IiI1 != None ) else "'not found'" , IIi1III . print_prefix ( ) ) )
 if 1 - 1: I1Ii111 + II111iiii % OoooooooOO * Oo0Ooo
 if 80 - 80: iIii1I11I1II1
 return ( [ IIi1III , i1111i , I11I1iI ] )
 if 91 - 91: OoOoOO00 + OoOoOO00 + ooOoO0o
 if 44 - 44: I1ii11iIi11i * OOooOOo % OoO0O00 . I1IiiI % Ii1I + II111iiii
 if 100 - 100: oO0o - II111iiii . o0oOOo0O0Ooo
 if 63 - 63: OoOoOO00 % IiII . iII111i
 if 44 - 44: I1IiiI
 if 25 - 25: oO0o
 if 100 - 100: I1IiiI / IiII + OoO0O00 . iII111i
 if 39 - 39: OoooooooOO * OOooOOo - OoO0O00
def lisp_ms_send_map_referral ( lisp_sockets , map_request , ecm_source , port ,
 action , eid_prefix , group_prefix ) :
 if 3 - 3: I11i . i11iIiiIii % Oo0Ooo % II111iiii . I11i
 ooOOoo0 = map_request . target_eid
 IIi1iiIII11 = map_request . target_group
 Iii11I = map_request . nonce
 if 88 - 88: iIii1I11I1II1 . OOooOOo % iII111i
 if ( action == LISP_DDT_ACTION_MS_ACK ) : oOoooOOO0o0 = 1440
 if 72 - 72: ooOoO0o + i11iIiiIii / i1IIi
 if 64 - 64: OOooOOo - OOooOOo
 if 42 - 42: i1IIi / ooOoO0o . I1Ii111 % OoOoOO00
 if 67 - 67: i1IIi * i11iIiiIii * I1IiiI
 oO0O = lisp_map_referral ( )
 oO0O . record_count = 1
 oO0O . nonce = Iii11I
 IiiiIi1iiii11 = oO0O . encode ( )
 oO0O . print_map_referral ( )
 if 23 - 23: Oo0Ooo
 O0II = False
 if 81 - 81: I1Ii111 % II111iiii - Oo0Ooo / I1IiiI + i11iIiiIii . I11i
 if 67 - 67: ooOoO0o . I1Ii111 . Oo0Ooo . Ii1I + iIii1I11I1II1 / OoooooooOO
 if 93 - 93: ooOoO0o * OoO0O00 - I1Ii111 / I1ii11iIi11i
 if 60 - 60: OoO0O00 / oO0o . I1IiiI + OoOoOO00 + I1ii11iIi11i % Ii1I
 if 70 - 70: i1IIi * II111iiii * I1IiiI
 if 7 - 7: OoooooooOO + II111iiii % o0oOOo0O0Ooo * O0 . OoO0O00 * OoooooooOO
 if ( action == LISP_DDT_ACTION_SITE_NOT_FOUND ) :
  eid_prefix , group_prefix , action = lisp_ms_compute_neg_prefix ( ooOOoo0 ,
 IIi1iiIII11 )
  oOoooOOO0o0 = 15
  if 20 - 20: Oo0Ooo % OOooOOo
 if ( action == LISP_DDT_ACTION_MS_NOT_REG ) : oOoooOOO0o0 = 1
 if ( action == LISP_DDT_ACTION_MS_ACK ) : oOoooOOO0o0 = 1440
 if ( action == LISP_DDT_ACTION_DELEGATION_HOLE ) : oOoooOOO0o0 = 15
 if ( action == LISP_DDT_ACTION_NOT_AUTH ) : oOoooOOO0o0 = 0
 if 8 - 8: OOooOOo
 O0o0 = False
 Ii1 = 0
 OOOoo = lisp_ddt_cache_lookup ( ooOOoo0 , IIi1iiIII11 , False )
 if ( OOOoo != None ) :
  Ii1 = len ( OOOoo . delegation_set )
  O0o0 = OOOoo . is_ms_peer_entry ( )
  OOOoo . map_referrals_sent += 1
  if 27 - 27: I11i + ooOoO0o - II111iiii . OoooooooOO % O0 % I1ii11iIi11i
  if 28 - 28: IiII - i1IIi - I1Ii111 % Ii1I - IiII
  if 73 - 73: iIii1I11I1II1 . iIii1I11I1II1 + oO0o % i11iIiiIii . IiII
  if 33 - 33: IiII - OOooOOo / i11iIiiIii * iIii1I11I1II1
  if 2 - 2: i11iIiiIii % ooOoO0o
 if ( action == LISP_DDT_ACTION_NOT_AUTH ) : O0II = True
 if ( action in ( LISP_DDT_ACTION_MS_REFERRAL , LISP_DDT_ACTION_MS_ACK ) ) :
  O0II = ( O0o0 == False )
  if 56 - 56: IiII % ooOoO0o + I1IiiI % I11i - OOooOOo
  if 82 - 82: OoooooooOO . i1IIi . OoO0O00 . OoO0O00
  if 31 - 31: iIii1I11I1II1
  if 64 - 64: ooOoO0o
  if 30 - 30: OoO0O00 + o0oOOo0O0Ooo / iIii1I11I1II1
 o0O0o = lisp_eid_record ( )
 o0O0o . rloc_count = Ii1
 o0O0o . authoritative = True
 o0O0o . action = action
 o0O0o . ddt_incomplete = O0II
 o0O0o . eid = eid_prefix
 o0O0o . group = group_prefix
 o0O0o . record_ttl = oOoooOOO0o0
 if 69 - 69: IiII - OoooooooOO + iII111i + iII111i - Ii1I
 IiiiIi1iiii11 += o0O0o . encode ( )
 o0O0o . print_record ( "  " , True )
 if 27 - 27: I1ii11iIi11i % Oo0Ooo * iIii1I11I1II1 * O0 / I11i * Oo0Ooo
 if 97 - 97: IiII % Oo0Ooo % OoOoOO00
 if 87 - 87: i11iIiiIii . oO0o * I1IiiI * I1Ii111
 if 57 - 57: iIii1I11I1II1 / i11iIiiIii / IiII + I1ii11iIi11i % I1IiiI
 if ( Ii1 != 0 ) :
  for I1IooOoo00 in OOOoo . delegation_set :
   oo0OOOO0O0o = lisp_rloc_record ( )
   oo0OOOO0O0o . rloc = I1IooOoo00 . delegate_address
   oo0OOOO0O0o . priority = I1IooOoo00 . priority
   oo0OOOO0O0o . weight = I1IooOoo00 . weight
   oo0OOOO0O0o . mpriority = 255
   oo0OOOO0O0o . mweight = 0
   oo0OOOO0O0o . reach_bit = True
   IiiiIi1iiii11 += oo0OOOO0O0o . encode ( )
   oo0OOOO0O0o . print_record ( "    " )
   if 80 - 80: iIii1I11I1II1
   if 23 - 23: II111iiii . ooOoO0o % I1Ii111
   if 39 - 39: OoooooooOO
   if 10 - 10: Oo0Ooo * iII111i
   if 78 - 78: Oo0Ooo / i11iIiiIii - I1IiiI
   if 51 - 51: ooOoO0o / Oo0Ooo - I1Ii111 - iII111i
   if 68 - 68: I1ii11iIi11i - iIii1I11I1II1 * OoooooooOO
 if ( map_request . nonce != 0 ) : port = LISP_CTRL_PORT
 lisp_send_map_referral ( lisp_sockets , IiiiIi1iiii11 , ecm_source , port )
 return
 if 44 - 44: OoooooooOO + I1Ii111 + OoO0O00
 if 15 - 15: iIii1I11I1II1 % i1IIi + iII111i
 if 48 - 48: o0oOOo0O0Ooo / oO0o
 if 61 - 61: I1IiiI + iII111i * Ii1I % I1Ii111 . Ii1I
 if 83 - 83: i11iIiiIii * OoOoOO00 * i11iIiiIii % II111iiii . i11iIiiIii * I11i
 if 67 - 67: i1IIi / i1IIi + IiII . oO0o
 if 70 - 70: i1IIi . I11i * o0oOOo0O0Ooo . iII111i
 if 75 - 75: oO0o * OoO0O00 * I11i + oO0o + O0 . I1Ii111
def lisp_send_negative_map_reply ( sockets , eid , group , nonce , dest , port , ttl ,
 xtr_id , pubsub ) :
 if 8 - 8: I1ii11iIi11i / i1IIi - I1ii11iIi11i + Ii1I + OoO0O00 - I11i
 lprint ( "Build negative Map-Reply EID-prefix {}, nonce 0x{} to ITR {}" . format ( lisp_print_eid_tuple ( eid , group ) , lisp_hex_string ( nonce ) ,
 # oO0o % I1Ii111 / iIii1I11I1II1 * I1ii11iIi11i / I1Ii111
 red ( dest . print_address ( ) , False ) ) )
 if 13 - 13: Ii1I + OoOoOO00
 I11I1iI = LISP_NATIVE_FORWARD_ACTION if group . is_null ( ) else LISP_DROP_ACTION
 if 77 - 77: OoO0O00 / OoooooooOO + iIii1I11I1II1
 if 81 - 81: O0 + II111iiii * ooOoO0o / i1IIi
 if 38 - 38: Oo0Ooo - OoOoOO00 % IiII % OoooooooOO
 if 79 - 79: II111iiii % OOooOOo / I1ii11iIi11i % Oo0Ooo - o0oOOo0O0Ooo
 if 60 - 60: IiII + ooOoO0o - iII111i
 if ( lisp_get_eid_hash ( eid ) != None ) :
  I11I1iI = LISP_SEND_MAP_REQUEST_ACTION
  if 69 - 69: iIii1I11I1II1 + oO0o
  if 16 - 16: OoO0O00 / I11i * OoOoOO00 % OoO0O00 * oO0o * o0oOOo0O0Ooo
 IiiiIi1iiii11 = lisp_build_map_reply ( eid , group , [ ] , nonce , I11I1iI , ttl , None ,
 None , False , False )
 if 80 - 80: o0oOOo0O0Ooo % I11i + O0 % i1IIi
 if 58 - 58: oO0o / I1ii11iIi11i * O0 % I11i
 if 34 - 34: oO0o / O0 * oO0o
 if 47 - 47: iIii1I11I1II1 - o0oOOo0O0Ooo % Ii1I
 if ( pubsub ) :
  lisp_process_pubsub ( sockets , IiiiIi1iiii11 , eid , dest , port , nonce , ttl ,
 xtr_id )
 else :
  lisp_send_map_reply ( sockets , IiiiIi1iiii11 , dest , port )
  if 38 - 38: ooOoO0o / IiII * I1ii11iIi11i % I1ii11iIi11i % oO0o
 return
 if 82 - 82: I1ii11iIi11i . i11iIiiIii - I11i . iII111i / OOooOOo
 if 60 - 60: I1IiiI / I1IiiI / II111iiii
 if 59 - 59: OOooOOo . oO0o + ooOoO0o % o0oOOo0O0Ooo . i11iIiiIii
 if 27 - 27: OoOoOO00 - OoooooooOO / IiII / II111iiii * OOooOOo * ooOoO0o
 if 43 - 43: II111iiii . IiII - I1IiiI * I1ii11iIi11i + OoooooooOO
 if 34 - 34: I1Ii111 / i1IIi
 if 95 - 95: OoOoOO00 * OOooOOo
def lisp_retransmit_ddt_map_request ( mr ) :
 o00o = mr . mr_source . print_address ( )
 OOoOo0OO = mr . print_eid_tuple ( )
 Iii11I = mr . nonce
 if 26 - 26: oO0o + OoooooooOO % o0oOOo0O0Ooo
 if 96 - 96: ooOoO0o * OoOoOO00 - II111iiii
 if 40 - 40: oO0o * OOooOOo + Ii1I + I11i * Ii1I + OoooooooOO
 if 77 - 77: OOooOOo + ooOoO0o / O0
 if 16 - 16: ooOoO0o + Oo0Ooo * Oo0Ooo . I11i - IiII
 if ( mr . last_request_sent_to ) :
  i1Oo0OoOO0O = mr . last_request_sent_to . print_address ( )
  OOo0 = lisp_referral_cache_lookup ( mr . last_cached_prefix [ 0 ] ,
 mr . last_cached_prefix [ 1 ] , True )
  if ( OOo0 and OOo0 . referral_set . has_key ( i1Oo0OoOO0O ) ) :
   OOo0 . referral_set [ i1Oo0OoOO0O ] . no_responses += 1
   if 79 - 79: I1Ii111 + iIii1I11I1II1
   if 58 - 58: OoO0O00 * Oo0Ooo
   if 30 - 30: i11iIiiIii * I1IiiI
   if 63 - 63: ooOoO0o + i11iIiiIii / i1IIi - I1Ii111 . O0 % OOooOOo
   if 39 - 39: o0oOOo0O0Ooo
   if 88 - 88: iII111i % I1IiiI . iIii1I11I1II1 * OOooOOo / IiII % OoooooooOO
   if 94 - 94: ooOoO0o % oO0o - OoooooooOO + IiII * Ii1I
 if ( mr . retry_count == LISP_MAX_MAP_NOTIFY_RETRIES ) :
  lprint ( "DDT Map-Request retry limit reached for EID {}, nonce 0x{}" . format ( green ( OOoOo0OO , False ) , lisp_hex_string ( Iii11I ) ) )
  if 60 - 60: OoO0O00 - O0 + o0oOOo0O0Ooo + I1ii11iIi11i
  mr . dequeue_map_request ( )
  return
  if 78 - 78: OOooOOo * Oo0Ooo * Ii1I
  if 94 - 94: OoooooooOO % iII111i
 mr . retry_count += 1
 if 48 - 48: iIii1I11I1II1
 IiII1iiI = green ( o00o , False )
 OooOOOoOoo0O0 = green ( OOoOo0OO , False )
 lprint ( "Retransmit DDT {} from {}ITR {} EIDs: {} -> {}, nonce 0x{}" . format ( bold ( "Map-Request" , False ) , "P" if mr . from_pitr else "" ,
 # iII111i % i1IIi
 red ( mr . itr . print_address ( ) , False ) , IiII1iiI , OooOOOoOoo0O0 ,
 lisp_hex_string ( Iii11I ) ) )
 if 13 - 13: iII111i / OoooooooOO + Ii1I / iII111i
 if 29 - 29: OOooOOo + ooOoO0o % o0oOOo0O0Ooo
 if 18 - 18: I11i + OoO0O00 + OoO0O00 . ooOoO0o
 if 37 - 37: i1IIi . IiII + I1IiiI % OoOoOO00
 lisp_send_ddt_map_request ( mr , False )
 if 3 - 3: i11iIiiIii + Ii1I % IiII - I1Ii111 / Oo0Ooo % iIii1I11I1II1
 if 86 - 86: Oo0Ooo + Oo0Ooo * oO0o * I1IiiI
 if 95 - 95: IiII - OoO0O00 + OOooOOo
 if 33 - 33: o0oOOo0O0Ooo . i11iIiiIii . ooOoO0o
 mr . retransmit_timer = threading . Timer ( LISP_DDT_MAP_REQUEST_INTERVAL ,
 lisp_retransmit_ddt_map_request , [ mr ] )
 mr . retransmit_timer . start ( )
 return
 if 100 - 100: i11iIiiIii % I1Ii111 - OoO0O00 + I1Ii111 / i11iIiiIii + OOooOOo
 if 55 - 55: i11iIiiIii / I1Ii111 . OOooOOo - OoO0O00
 if 60 - 60: OoOoOO00 / i1IIi . Ii1I - OoO0O00 - OoooooooOO
 if 39 - 39: I1IiiI + i1IIi * OoO0O00 % I11i
 if 41 - 41: I1ii11iIi11i * IiII
 if 16 - 16: I1Ii111 % iIii1I11I1II1 / I1IiiI * OoOoOO00 / IiII / OoOoOO00
 if 29 - 29: OoooooooOO / oO0o
 if 1 - 1: OoOoOO00 . i11iIiiIii % I1Ii111 + OoooooooOO - Oo0Ooo . I1ii11iIi11i
def lisp_get_referral_node ( referral , source_eid , dest_eid ) :
 if 46 - 46: i11iIiiIii + I11i - iIii1I11I1II1 / OoO0O00 - ooOoO0o / i1IIi
 if 44 - 44: o0oOOo0O0Ooo + Oo0Ooo
 if 46 - 46: OOooOOo % I1IiiI
 if 66 - 66: iIii1I11I1II1 . o0oOOo0O0Ooo - ooOoO0o
 II1iIiIII = [ ]
 for Iii1i1I1 in referral . referral_set . values ( ) :
  if ( Iii1i1I1 . updown == False ) : continue
  if ( len ( II1iIiIII ) == 0 or II1iIiIII [ 0 ] . priority == Iii1i1I1 . priority ) :
   II1iIiIII . append ( Iii1i1I1 )
  elif ( II1iIiIII [ 0 ] . priority > Iii1i1I1 . priority ) :
   II1iIiIII = [ ]
   II1iIiIII . append ( Iii1i1I1 )
   if 76 - 76: Oo0Ooo + OOooOOo - i1IIi * iII111i % i11iIiiIii
   if 78 - 78: i11iIiiIii / I11i / Oo0Ooo + II111iiii - I1ii11iIi11i / I1ii11iIi11i
   if 28 - 28: iIii1I11I1II1 / IiII - iIii1I11I1II1 . i1IIi - O0 * ooOoO0o
 i11I1i = len ( II1iIiIII )
 if ( i11I1i == 0 ) : return ( None )
 if 91 - 91: I1ii11iIi11i - OoooooooOO * I11i / I1ii11iIi11i
 IIi1iiIIi1i = dest_eid . hash_address ( source_eid )
 IIi1iiIIi1i = IIi1iiIIi1i % i11I1i
 return ( II1iIiIII [ IIi1iiIIi1i ] )
 if 92 - 92: Ii1I - OoOoOO00 / I1ii11iIi11i - Ii1I
 if 79 - 79: I1Ii111 + I1ii11iIi11i / i1IIi + o0oOOo0O0Ooo - OoO0O00 / Oo0Ooo
 if 3 - 3: OoOoOO00 - I1Ii111 % ooOoO0o
 if 80 - 80: II111iiii % OOooOOo * iIii1I11I1II1 + I1Ii111 + IiII
 if 73 - 73: OOooOOo % OoO0O00 . OoooooooOO / OoO0O00 * o0oOOo0O0Ooo . I1IiiI
 if 39 - 39: oO0o
 if 68 - 68: iIii1I11I1II1 + I1IiiI + iII111i - I1Ii111 * OoO0O00
def lisp_send_ddt_map_request ( mr , send_to_root ) :
 I1I1I111 = mr . lisp_sockets
 Iii11I = mr . nonce
 I11iiII1I1111 = mr . itr
 i111I1IIiI = mr . mr_source
 I11i11i1 = mr . print_eid_tuple ( )
 if 88 - 88: OoOoOO00 . i11iIiiIii % OoooooooOO . oO0o . O0 + iIii1I11I1II1
 if 11 - 11: OoO0O00 / I1Ii111 . OoOoOO00
 if 95 - 95: I1ii11iIi11i / Ii1I % ooOoO0o . OoooooooOO % OoOoOO00 . OoOoOO00
 if 1 - 1: I1ii11iIi11i % o0oOOo0O0Ooo % i11iIiiIii - OOooOOo - ooOoO0o - OoO0O00
 if 94 - 94: OoO0O00 . Oo0Ooo / OoO0O00 + I1Ii111
 if ( mr . send_count == 8 ) :
  lprint ( "Giving up on map-request-queue entry {}, nonce 0x{}" . format ( green ( I11i11i1 , False ) , lisp_hex_string ( Iii11I ) ) )
  if 48 - 48: I1ii11iIi11i * i1IIi + I1Ii111
  mr . dequeue_map_request ( )
  return
  if 80 - 80: I1IiiI % I11i
  if 64 - 64: OOooOOo + i11iIiiIii + I1IiiI . I11i % I11i - o0oOOo0O0Ooo
  if 3 - 3: I1IiiI / i1IIi + II111iiii + Oo0Ooo
  if 48 - 48: o0oOOo0O0Ooo
  if 16 - 16: II111iiii . Ii1I + I1Ii111 % i1IIi / i11iIiiIii + OOooOOo
  if 43 - 43: I1IiiI . Oo0Ooo + i1IIi + I11i / OoO0O00
 if ( send_to_root ) :
  o0iIiIi1I11IIii = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  i1111iIiii = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  mr . tried_root = True
  lprint ( "Jumping up to root for EID {}" . format ( green ( I11i11i1 , False ) ) )
 else :
  o0iIiIi1I11IIii = mr . eid
  i1111iIiii = mr . group
  if 15 - 15: Oo0Ooo
  if 78 - 78: i11iIiiIii . i1IIi % Ii1I . oO0o / II111iiii / oO0o
  if 79 - 79: OoO0O00 % oO0o / I11i % II111iiii
  if 22 - 22: i11iIiiIii % IiII % IiII % I11i - OoooooooOO + I1IiiI
  if 31 - 31: I11i + I1ii11iIi11i . i1IIi * i11iIiiIii + I1ii11iIi11i
 O00o0oOoO0OOo = lisp_referral_cache_lookup ( o0iIiIi1I11IIii , i1111iIiii , False )
 if ( O00o0oOoO0OOo == None ) :
  lprint ( "No referral cache entry found" )
  lisp_send_negative_map_reply ( I1I1I111 , o0iIiIi1I11IIii , i1111iIiii ,
 Iii11I , I11iiII1I1111 , mr . sport , 15 , None , False )
  return
  if 26 - 26: ooOoO0o + Oo0Ooo
  if 24 - 24: I1IiiI
 iII1i1 = O00o0oOoO0OOo . print_eid_tuple ( )
 lprint ( "Found referral cache entry {}, referral-type: {}" . format ( iII1i1 ,
 O00o0oOoO0OOo . print_referral_type ( ) ) )
 if 89 - 89: I11i + I1IiiI - II111iiii
 Iii1i1I1 = lisp_get_referral_node ( O00o0oOoO0OOo , i111I1IIiI , mr . eid )
 if ( Iii1i1I1 == None ) :
  lprint ( "No reachable referral-nodes found" )
  mr . dequeue_map_request ( )
  lisp_send_negative_map_reply ( I1I1I111 , O00o0oOoO0OOo . eid ,
 O00o0oOoO0OOo . group , Iii11I , I11iiII1I1111 , mr . sport , 1 , None , False )
  return
  if 4 - 4: I1ii11iIi11i
  if 51 - 51: I1Ii111 . O0 - OoOoOO00 + i11iIiiIii * II111iiii
 lprint ( "Send DDT Map-Request to {} {} for EID {}, nonce 0x{}" . format ( Iii1i1I1 . referral_address . print_address ( ) ,
 # O0 * Ii1I * OoO0O00
 O00o0oOoO0OOo . print_referral_type ( ) , green ( I11i11i1 , False ) ,
 lisp_hex_string ( Iii11I ) ) )
 if 90 - 90: II111iiii * iIii1I11I1II1
 if 19 - 19: OOooOOo * o0oOOo0O0Ooo
 if 64 - 64: I11i % ooOoO0o / OOooOOo / iII111i
 if 80 - 80: i1IIi
 oOii = ( O00o0oOoO0OOo . referral_type == LISP_DDT_ACTION_MS_REFERRAL or
 O00o0oOoO0OOo . referral_type == LISP_DDT_ACTION_MS_ACK )
 lisp_send_ecm ( I1I1I111 , mr . packet , i111I1IIiI , mr . sport , mr . eid ,
 Iii1i1I1 . referral_address , to_ms = oOii , ddt = True )
 if 55 - 55: Oo0Ooo / I1IiiI
 if 17 - 17: OOooOOo % iII111i . OOooOOo / II111iiii / II111iiii % Ii1I
 if 44 - 44: Oo0Ooo
 if 29 - 29: O0 + OoooooooOO
 mr . last_request_sent_to = Iii1i1I1 . referral_address
 mr . last_sent = lisp_get_timestamp ( )
 mr . send_count += 1
 Iii1i1I1 . map_requests_sent += 1
 return
 if 82 - 82: O0 . I1Ii111 - IiII
 if 37 - 37: i11iIiiIii
 if 67 - 67: ooOoO0o . Oo0Ooo
 if 15 - 15: OoO0O00 . oO0o - o0oOOo0O0Ooo
 if 28 - 28: OOooOOo * OoOoOO00 + OoooooooOO . OOooOOo / oO0o / OoOoOO00
 if 94 - 94: OoO0O00 / i1IIi . OoO0O00 . I1Ii111 + OoO0O00
 if 30 - 30: o0oOOo0O0Ooo + iIii1I11I1II1 - II111iiii - ooOoO0o + OoOoOO00 - II111iiii
 if 69 - 69: oO0o / O0 / I1IiiI + OoooooooOO * I11i * IiII
def lisp_mr_process_map_request ( lisp_sockets , packet , map_request , ecm_source ,
 sport , mr_source ) :
 if 41 - 41: ooOoO0o % i11iIiiIii
 ooOOoo0 = map_request . target_eid
 IIi1iiIII11 = map_request . target_group
 OOoOo0OO = map_request . print_eid_tuple ( )
 o00o = mr_source . print_address ( )
 Iii11I = map_request . nonce
 if 69 - 69: IiII - oO0o
 IiII1iiI = green ( o00o , False )
 OooOOOoOoo0O0 = green ( OOoOo0OO , False )
 lprint ( "Received Map-Request from {}ITR {} EIDs: {} -> {}, nonce 0x{}" . format ( "P" if map_request . pitr_bit else "" ,
 # OoooooooOO / Oo0Ooo
 red ( ecm_source . print_address ( ) , False ) , IiII1iiI , OooOOOoOoo0O0 ,
 lisp_hex_string ( Iii11I ) ) )
 if 91 - 91: iIii1I11I1II1 / i11iIiiIii + i11iIiiIii / OOooOOo / i1IIi
 if 20 - 20: OOooOOo % O0 * Oo0Ooo . II111iiii
 if 82 - 82: OoO0O00
 if 54 - 54: i1IIi * OOooOOo - oO0o * OoooooooOO + II111iiii . IiII
 OoOooo0o = lisp_ddt_map_request ( lisp_sockets , packet , ooOOoo0 , IIi1iiIII11 , Iii11I )
 OoOooo0o . packet = packet
 OoOooo0o . itr = ecm_source
 OoOooo0o . mr_source = mr_source
 OoOooo0o . sport = sport
 OoOooo0o . from_pitr = map_request . pitr_bit
 OoOooo0o . queue_map_request ( )
 if 38 - 38: iII111i - Oo0Ooo / O0
 lisp_send_ddt_map_request ( OoOooo0o , False )
 return
 if 40 - 40: ooOoO0o + iIii1I11I1II1 / OoOoOO00 * iIii1I11I1II1 - ooOoO0o * iIii1I11I1II1
 if 79 - 79: ooOoO0o . oO0o + Ii1I * ooOoO0o + O0 . II111iiii
 if 8 - 8: IiII * OOooOOo + I11i + O0 * oO0o - oO0o
 if 19 - 19: OoO0O00 - ooOoO0o + I1ii11iIi11i / I1ii11iIi11i % I1Ii111 % iIii1I11I1II1
 if 5 - 5: OoooooooOO + ooOoO0o - II111iiii . i11iIiiIii / oO0o - ooOoO0o
 if 3 - 3: iII111i
 if 74 - 74: i11iIiiIii + OoooooooOO . OOooOOo
def lisp_process_map_request ( lisp_sockets , packet , ecm_source , ecm_port ,
 mr_source , mr_port , ddt_request , ttl , timestamp ) :
 if 29 - 29: IiII % OoO0O00
 OoO = packet
 OooOO00o = lisp_map_request ( )
 packet = OooOO00o . decode ( packet , mr_source , mr_port )
 if ( packet == None ) :
  lprint ( "Could not decode Map-Request packet" )
  return
  if 79 - 79: OoOoOO00 . OOooOOo
  if 97 - 97: II111iiii . OOooOOo
 OooOO00o . print_map_request ( )
 if 68 - 68: IiII * IiII + oO0o / o0oOOo0O0Ooo
 if 41 - 41: OoOoOO00 - O0
 if 48 - 48: OoooooooOO % Ii1I * OoO0O00 / I1ii11iIi11i
 if 53 - 53: ooOoO0o + oO0o - II111iiii
 if ( OooOO00o . rloc_probe ) :
  lisp_process_rloc_probe_request ( lisp_sockets , OooOO00o , mr_source ,
 mr_port , ttl , timestamp )
  return
  if 92 - 92: Oo0Ooo - I11i . ooOoO0o % oO0o
  if 6 - 6: iIii1I11I1II1 + oO0o
  if 8 - 8: I1ii11iIi11i + o0oOOo0O0Ooo
  if 29 - 29: Ii1I . OOooOOo
  if 59 - 59: O0 . OoO0O00
 if ( OooOO00o . smr_bit ) :
  lisp_process_smr ( OooOO00o )
  if 10 - 10: I1Ii111 / OoooooooOO / OoO0O00 * ooOoO0o
  if 81 - 81: i1IIi % I11i * iIii1I11I1II1
  if 39 - 39: iIii1I11I1II1 / O0 . OoooooooOO - O0 . OoO0O00 . oO0o
  if 59 - 59: II111iiii * I1IiiI
  if 12 - 12: i11iIiiIii - IiII . iII111i . Ii1I
 if ( OooOO00o . smr_invoked_bit ) :
  lisp_process_smr_invoked_request ( OooOO00o )
  if 34 - 34: i1IIi % iII111i + Oo0Ooo * OoOoOO00 + OoO0O00
  if 37 - 37: I1Ii111 / OoooooooOO
  if 19 - 19: Ii1I - O0 + I1IiiI + OoooooooOO + ooOoO0o - Oo0Ooo
  if 45 - 45: I1IiiI . OoOoOO00 . OoOoOO00
  if 20 - 20: OoOoOO00
 if ( lisp_i_am_etr ) :
  lisp_etr_process_map_request ( lisp_sockets , OooOO00o , mr_source ,
 mr_port , ttl , timestamp )
  if 69 - 69: OoOoOO00 * Ii1I % ooOoO0o . OoOoOO00 / oO0o * I1Ii111
  if 93 - 93: OoO0O00 % IiII % ooOoO0o . I1IiiI
  if 96 - 96: II111iiii
  if 73 - 73: II111iiii
  if 81 - 81: I1IiiI + OoO0O00
 if ( lisp_i_am_ms ) :
  packet = OoO
  ooOOoo0 , IIi1iiIII11 , II1I11i1iIIi1 = lisp_ms_process_map_request ( lisp_sockets ,
 OoO , OooOO00o , mr_source , mr_port , ecm_source )
  if ( ddt_request ) :
   lisp_ms_send_map_referral ( lisp_sockets , OooOO00o , ecm_source ,
 ecm_port , II1I11i1iIIi1 , ooOOoo0 , IIi1iiIII11 )
   if 66 - 66: iII111i + i11iIiiIii / ooOoO0o . O0
  return
  if 50 - 50: i11iIiiIii . OOooOOo . iIii1I11I1II1 . i1IIi . O0 / ooOoO0o
  if 64 - 64: i11iIiiIii + I1IiiI / Oo0Ooo - iII111i
  if 26 - 26: I1ii11iIi11i
  if 67 - 67: I1Ii111 * iIii1I11I1II1 / O0 + OoO0O00 * iIii1I11I1II1 % II111iiii
  if 13 - 13: Ii1I / ooOoO0o / iII111i % II111iiii * I1IiiI * II111iiii
 if ( lisp_i_am_mr and not ddt_request ) :
  lisp_mr_process_map_request ( lisp_sockets , OoO , OooOO00o ,
 ecm_source , mr_port , mr_source )
  if 40 - 40: Ii1I / i1IIi . iII111i
  if 65 - 65: iIii1I11I1II1 * O0 . II111iiii * o0oOOo0O0Ooo . I1ii11iIi11i * I1IiiI
  if 63 - 63: II111iiii . Oo0Ooo % iIii1I11I1II1
  if 85 - 85: I1IiiI + i1IIi % I1Ii111
  if 76 - 76: i11iIiiIii % i11iIiiIii
 if ( lisp_i_am_ddt or ddt_request ) :
  packet = OoO
  lisp_ddt_process_map_request ( lisp_sockets , OooOO00o , ecm_source ,
 ecm_port )
  if 33 - 33: OOooOOo . ooOoO0o / iIii1I11I1II1 * OOooOOo / oO0o
 return
 if 75 - 75: Ii1I - OoOoOO00 . OOooOOo - o0oOOo0O0Ooo - I1ii11iIi11i
 if 69 - 69: O0 % I1ii11iIi11i
 if 77 - 77: iIii1I11I1II1 . OOooOOo
 if 64 - 64: OoOoOO00 - i1IIi * i1IIi / iII111i * OoOoOO00 * OoO0O00
 if 61 - 61: OOooOOo
 if 51 - 51: Oo0Ooo * OOooOOo / iII111i
 if 49 - 49: ooOoO0o . i1IIi % I1Ii111 . I1IiiI . I1ii11iIi11i + OoO0O00
 if 65 - 65: I1ii11iIi11i + Ii1I / i11iIiiIii * I1Ii111 + OoooooooOO
def lisp_store_mr_stats ( source , nonce ) :
 OoOooo0o = lisp_get_map_resolver ( source , None )
 if ( OoOooo0o == None ) : return
 if 7 - 7: Oo0Ooo % o0oOOo0O0Ooo
 if 40 - 40: oO0o * IiII
 if 29 - 29: O0 - II111iiii + iII111i
 if 73 - 73: I1Ii111 - I11i + IiII - o0oOOo0O0Ooo - I11i - OOooOOo
 OoOooo0o . neg_map_replies_received += 1
 OoOooo0o . last_reply = lisp_get_timestamp ( )
 if 40 - 40: iIii1I11I1II1 . iII111i * I1ii11iIi11i + IiII - iIii1I11I1II1
 if 83 - 83: i1IIi
 if 9 - 9: iIii1I11I1II1 + i11iIiiIii
 if 70 - 70: I1IiiI - OoO0O00 % OOooOOo + ooOoO0o % II111iiii
 if ( ( OoOooo0o . neg_map_replies_received % 100 ) == 0 ) : OoOooo0o . total_rtt = 0
 if 19 - 19: I11i + i1IIi / i1IIi - II111iiii + I1Ii111
 if 11 - 11: i11iIiiIii % i11iIiiIii / IiII - Oo0Ooo / O0 - I11i
 if 29 - 29: OOooOOo * iIii1I11I1II1 * ooOoO0o
 if 80 - 80: oO0o * I1Ii111
 if ( OoOooo0o . last_nonce == nonce ) :
  OoOooo0o . total_rtt += ( time . time ( ) - OoOooo0o . last_used )
  OoOooo0o . last_nonce = 0
  if 87 - 87: iII111i + OoOoOO00 % ooOoO0o - oO0o
 if ( ( OoOooo0o . neg_map_replies_received % 10 ) == 0 ) : OoOooo0o . last_nonce = 0
 return
 if 40 - 40: i1IIi / OoOoOO00 - I11i / ooOoO0o . Ii1I
 if 8 - 8: I1IiiI . IiII . OOooOOo . O0
 if 3 - 3: Ii1I + i11iIiiIii
 if 87 - 87: ooOoO0o - iII111i % I11i
 if 88 - 88: I11i . OoooooooOO
 if 86 - 86: Ii1I - I1IiiI - iII111i % Ii1I . I1ii11iIi11i % i1IIi
 if 84 - 84: OoOoOO00
def lisp_process_map_reply ( lisp_sockets , packet , source , ttl , itr_in_ts ) :
 global lisp_map_cache
 if 99 - 99: OoO0O00 - OoOoOO00 - i1IIi / OoO0O00 * I1ii11iIi11i * iIii1I11I1II1
 i111iii1IIi = lisp_map_reply ( )
 packet = i111iii1IIi . decode ( packet )
 if ( packet == None ) :
  lprint ( "Could not decode Map-Reply packet" )
  return
  if 65 - 65: iII111i - O0 / i1IIi . I1Ii111
 i111iii1IIi . print_map_reply ( )
 if 85 - 85: o0oOOo0O0Ooo % Ii1I
 if 81 - 81: oO0o / OoO0O00 * i1IIi % iIii1I11I1II1
 if 23 - 23: II111iiii . II111iiii
 if 17 - 17: i11iIiiIii / IiII * I1IiiI . Oo0Ooo / o0oOOo0O0Ooo - iIii1I11I1II1
 i11iIiIi1i = None
 for IiIIi1IiiIiI in range ( i111iii1IIi . record_count ) :
  o0O0o = lisp_eid_record ( )
  packet = o0O0o . decode ( packet )
  if ( packet == None ) :
   lprint ( "Could not decode EID-record in Map-Reply packet" )
   return
   if 94 - 94: OoOoOO00 - I1ii11iIi11i - I1IiiI . Oo0Ooo + OoOoOO00
  o0O0o . print_record ( "  " , False )
  if 100 - 100: I1IiiI / I1Ii111 * i1IIi
  if 4 - 4: OoO0O00 + O0 * OOooOOo * I1Ii111 / O0
  if 58 - 58: OOooOOo % ooOoO0o * I1IiiI - I1ii11iIi11i / I11i + iII111i
  if 26 - 26: OoOoOO00
  if 63 - 63: I1Ii111 . oO0o + OoO0O00 / I1ii11iIi11i % IiII * II111iiii
  if ( o0O0o . rloc_count == 0 ) :
   lisp_store_mr_stats ( source , i111iii1IIi . nonce )
   if 92 - 92: iIii1I11I1II1 . OoooooooOO . ooOoO0o / II111iiii
   if 30 - 30: i1IIi * Ii1I + Ii1I / I1Ii111
  I11IiI1I1 = ( o0O0o . group . is_null ( ) == False )
  if 84 - 84: I1IiiI - Oo0Ooo * OoO0O00 * oO0o
  if 13 - 13: I1Ii111 * i11iIiiIii % o0oOOo0O0Ooo + oO0o - iII111i
  if 32 - 32: I1Ii111 / I1ii11iIi11i - Ii1I % o0oOOo0O0Ooo * I1Ii111 % II111iiii
  if 33 - 33: ooOoO0o % I11i
  if 72 - 72: OoO0O00 % OoooooooOO / II111iiii * oO0o * I1Ii111
  if ( lisp_decent_push_configured ) :
   I11I1iI = o0O0o . action
   if ( I11IiI1I1 and I11I1iI == LISP_DROP_ACTION ) :
    if ( o0O0o . eid . is_local ( ) ) : continue
    if 98 - 98: OOooOOo * Ii1I + I1ii11iIi11i / iIii1I11I1II1 / OoOoOO00 + I1IiiI
    if 74 - 74: ooOoO0o . IiII . O0 * I1IiiI * oO0o
    if 6 - 6: O0 . Ii1I / Oo0Ooo * o0oOOo0O0Ooo
    if 1 - 1: i11iIiiIii
    if 30 - 30: I11i
    if 26 - 26: Oo0Ooo - II111iiii % ooOoO0o
    if 81 - 81: i11iIiiIii + I1ii11iIi11i * oO0o
  if ( I11IiI1I1 == False and o0O0o . eid . is_null ( ) ) : continue
  if 86 - 86: OoO0O00 . ooOoO0o . o0oOOo0O0Ooo
  if 70 - 70: O0 % OoooooooOO - Ii1I * Oo0Ooo
  if 18 - 18: OOooOOo . I1IiiI + i1IIi . I1IiiI
  if 3 - 3: O0 * O0 + II111iiii + OoOoOO00 * I11i % Oo0Ooo
  if 19 - 19: oO0o % IiII % OoooooooOO % I1ii11iIi11i / OoO0O00
  if ( I11IiI1I1 ) :
   iiI1iIi1II1ii = lisp_map_cache_lookup ( o0O0o . eid , o0O0o . group )
  else :
   iiI1iIi1II1ii = lisp_map_cache . lookup_cache ( o0O0o . eid , True )
   if 95 - 95: IiII / O0 . i1IIi % OoO0O00
  IiI11iI1iI = ( iiI1iIi1II1ii == None )
  if 72 - 72: ooOoO0o * I1Ii111
  if 58 - 58: I1ii11iIi11i * I1IiiI
  if 34 - 34: IiII - ooOoO0o / oO0o - I11i / iII111i
  if 50 - 50: ooOoO0o
  if 76 - 76: OOooOOo - iII111i + IiII
  if ( iiI1iIi1II1ii == None ) :
   iiiiiiIi , O0O , IIIi1i1iIIIi = lisp_allow_gleaning ( o0O0o . eid , o0O0o . group ,
 None )
   if ( iiiiiiIi ) : continue
  else :
   if ( iiI1iIi1II1ii . gleaned ) : continue
   if 13 - 13: OoO0O00 + OoO0O00 % OoO0O00 % O0
   if 62 - 62: IiII - iII111i . I1ii11iIi11i . oO0o
   if 22 - 22: OoOoOO00 * i11iIiiIii * Ii1I
   if 43 - 43: iIii1I11I1II1 / iII111i - Ii1I + I11i % iII111i - OoO0O00
   if 5 - 5: OoO0O00 / ooOoO0o
  o0oo0OoOo000 = [ ]
  OOO00 = None
  for I11I1iiI111i1 in range ( o0O0o . rloc_count ) :
   oo0OOOO0O0o = lisp_rloc_record ( )
   oo0OOOO0O0o . keys = i111iii1IIi . keys
   packet = oo0OOOO0O0o . decode ( packet , i111iii1IIi . nonce )
   if ( packet == None ) :
    lprint ( "Could not decode RLOC-record in Map-Reply packet" )
    return
    if 14 - 14: OoOoOO00 - II111iiii * I11i
   oo0OOOO0O0o . print_record ( "    " )
   if 27 - 27: OOooOOo + I1Ii111 + I1Ii111
   o00o0O00000 = None
   if ( iiI1iIi1II1ii ) : o00o0O00000 = iiI1iIi1II1ii . get_rloc ( oo0OOOO0O0o . rloc )
   if ( o00o0O00000 ) :
    I1IIiIIIii = o00o0O00000
   else :
    I1IIiIIIii = lisp_rloc ( )
    if 17 - 17: o0oOOo0O0Ooo + Ii1I % I1ii11iIi11i + IiII % I1Ii111 + I1ii11iIi11i
    if 100 - 100: I11i * OoO0O00 - i1IIi + iII111i * Ii1I - OoooooooOO
    if 47 - 47: o0oOOo0O0Ooo / Ii1I - iII111i * OOooOOo / i11iIiiIii
    if 97 - 97: iIii1I11I1II1 + OoOoOO00 + OoOoOO00 * o0oOOo0O0Ooo
    if 14 - 14: II111iiii + I1ii11iIi11i * Oo0Ooo
    if 95 - 95: IiII + iII111i % I1IiiI
    if 18 - 18: Oo0Ooo
   Oo0O00O = I1IIiIIIii . store_rloc_from_record ( oo0OOOO0O0o , i111iii1IIi . nonce ,
 source )
   I1IIiIIIii . echo_nonce_capable = i111iii1IIi . echo_nonce_capable
   if 8 - 8: O0 + iIii1I11I1II1 - O0
   if ( I1IIiIIIii . echo_nonce_capable ) :
    oo0o00OO = I1IIiIIIii . rloc . print_address_no_iid ( )
    if ( lisp_get_echo_nonce ( None , oo0o00OO ) == None ) :
     lisp_echo_nonce ( oo0o00OO )
     if 67 - 67: O0
     if 22 - 22: I11i / i1IIi . II111iiii % ooOoO0o / I11i - Ii1I
     if 28 - 28: O0 - Oo0Ooo
     if 58 - 58: iIii1I11I1II1 - OoooooooOO - iII111i
     if 43 - 43: ooOoO0o / o0oOOo0O0Ooo
     if 56 - 56: II111iiii * I1ii11iIi11i * O0 . iII111i . I1ii11iIi11i % I1Ii111
   if ( I1IIiIIIii . json ) :
    if ( lisp_is_json_telemetry ( I1IIiIIIii . json . json_string ) ) :
     o0O00O = I1IIiIIIii . json . json_string
     o0O00O = lisp_encode_telemetry ( o0O00O , ii = itr_in_ts )
     I1IIiIIIii . json . json_string = o0O00O
     if 99 - 99: Oo0Ooo - OoO0O00 + OoooooooOO - I1Ii111 - I1ii11iIi11i % i1IIi
     if 49 - 49: IiII % OoooooooOO / Oo0Ooo - OoOoOO00 + o0oOOo0O0Ooo / Ii1I
     if 6 - 6: I11i % IiII
     if 48 - 48: Ii1I
     if 100 - 100: OoO0O00 % I1Ii111 + OoooooooOO / OoO0O00
     if 62 - 62: IiII
     if 66 - 66: o0oOOo0O0Ooo % OOooOOo
     if 15 - 15: Ii1I % IiII + IiII % iII111i - O0 * OoooooooOO
     if 53 - 53: OoOoOO00 . Ii1I / Oo0Ooo
     if 62 - 62: i11iIiiIii
   if ( i111iii1IIi . rloc_probe and oo0OOOO0O0o . probe_bit ) :
    if ( I1IIiIIIii . rloc . afi == source . afi ) :
     lisp_process_rloc_probe_reply ( I1IIiIIIii , source , Oo0O00O ,
 i111iii1IIi , ttl , OOO00 )
     if 38 - 38: I1ii11iIi11i % ooOoO0o * OoooooooOO + iIii1I11I1II1 % i1IIi / OOooOOo
    if ( I1IIiIIIii . rloc . is_multicast_address ( ) ) : OOO00 = I1IIiIIIii
    if 6 - 6: i11iIiiIii
    if 8 - 8: iIii1I11I1II1 + I1ii11iIi11i . i1IIi % OoOoOO00 % OoooooooOO * Oo0Ooo
    if 53 - 53: oO0o
    if 23 - 23: I1ii11iIi11i . I1Ii111 + OOooOOo
    if 4 - 4: I1IiiI
   o0oo0OoOo000 . append ( I1IIiIIIii )
   if 31 - 31: ooOoO0o * i1IIi . O0
   if 5 - 5: OOooOOo . I1ii11iIi11i + ooOoO0o . ooOoO0o + iII111i
   if 100 - 100: I1Ii111
   if 71 - 71: ooOoO0o * i1IIi / OoOoOO00 * i11iIiiIii - iII111i
   if ( lisp_data_plane_security and I1IIiIIIii . rloc_recent_rekey ( ) ) :
    i11iIiIi1i = I1IIiIIIii
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
  if ( i111iii1IIi . rloc_probe == False and lisp_nat_traversal ) :
   iI11Iii1I111 = [ ]
   o0i1i1iiI = [ ]
   for I1IIiIIIii in o0oo0OoOo000 :
    if 55 - 55: i11iIiiIii / II111iiii / I1Ii111 * iIii1I11I1II1 / II111iiii * iIii1I11I1II1
    if 41 - 41: o0oOOo0O0Ooo . iII111i % iII111i . OOooOOo / OOooOOo
    if 98 - 98: II111iiii + ooOoO0o - iIii1I11I1II1 . I11i . iIii1I11I1II1 - iIii1I11I1II1
    if 91 - 91: ooOoO0o
    if 66 - 66: OOooOOo
    if ( I1IIiIIIii . rloc . is_private_address ( ) ) :
     I1IIiIIIii . priority = 1
     I1IIiIIIii . state = LISP_RLOC_UNREACH_STATE
     iI11Iii1I111 . append ( I1IIiIIIii )
     o0i1i1iiI . append ( I1IIiIIIii . rloc . print_address_no_iid ( ) )
     continue
     if 5 - 5: i1IIi * OoOoOO00 + i1IIi % I11i
     if 79 - 79: OOooOOo % iIii1I11I1II1 / OoOoOO00
     if 9 - 9: Ii1I
     if 44 - 44: iII111i
     if 46 - 46: I11i . i11iIiiIii * OoOoOO00 + o0oOOo0O0Ooo / ooOoO0o
     if 37 - 37: OoO0O00 - Ii1I + OoO0O00
    if ( I1IIiIIIii . priority == 254 and lisp_i_am_rtr == False ) :
     iI11Iii1I111 . append ( I1IIiIIIii )
     o0i1i1iiI . append ( I1IIiIIIii . rloc . print_address_no_iid ( ) )
     if 49 - 49: OoooooooOO - I1ii11iIi11i % I1ii11iIi11i / i1IIi . ooOoO0o
    if ( I1IIiIIIii . priority != 254 and lisp_i_am_rtr ) :
     iI11Iii1I111 . append ( I1IIiIIIii )
     o0i1i1iiI . append ( I1IIiIIIii . rloc . print_address_no_iid ( ) )
     if 60 - 60: Oo0Ooo
     if 46 - 46: OoOoOO00 + i1IIi
     if 43 - 43: II111iiii * IiII % iIii1I11I1II1 % i11iIiiIii % I1ii11iIi11i
   if ( o0i1i1iiI != [ ] ) :
    o0oo0OoOo000 = iI11Iii1I111
    lprint ( "NAT-traversal optimized RLOC-set: {}" . format ( o0i1i1iiI ) )
    if 81 - 81: oO0o % I1ii11iIi11i % ooOoO0o * O0 - OOooOOo
    if 17 - 17: O0 % O0 / I1ii11iIi11i . Oo0Ooo . iII111i
    if 4 - 4: OoO0O00
    if 65 - 65: Oo0Ooo % O0 / I1Ii111 * IiII - oO0o
    if 32 - 32: Ii1I * OoO0O00 + ooOoO0o
    if 41 - 41: IiII + I11i * ooOoO0o + Oo0Ooo . ooOoO0o
    if 38 - 38: iII111i * OoooooooOO - IiII
  iI11Iii1I111 = [ ]
  for I1IIiIIIii in o0oo0OoOo000 :
   if ( I1IIiIIIii . json != None ) : continue
   iI11Iii1I111 . append ( I1IIiIIIii )
   if 36 - 36: I1Ii111 * II111iiii + I1ii11iIi11i - iII111i * iII111i
  if ( iI11Iii1I111 != [ ] ) :
   I1I1 = len ( o0oo0OoOo000 ) - len ( iI11Iii1I111 )
   lprint ( "Pruning {} no-address RLOC-records for map-cache" . format ( I1I1 ) )
   if 91 - 91: O0 + I1Ii111 * II111iiii - O0 . i11iIiiIii . Oo0Ooo
   o0oo0OoOo000 = iI11Iii1I111
   if 54 - 54: ooOoO0o * I11i / I1ii11iIi11i % ooOoO0o
   if 76 - 76: I11i . I1IiiI
   if 66 - 66: oO0o % oO0o * IiII
   if 39 - 39: i1IIi * Ii1I + OoOoOO00 / oO0o
   if 6 - 6: I1ii11iIi11i / II111iiii / OoOoOO00 . i11iIiiIii - iII111i
   if 43 - 43: i11iIiiIii * i11iIiiIii * I1Ii111
   if 80 - 80: oO0o . I1IiiI * II111iiii + o0oOOo0O0Ooo / o0oOOo0O0Ooo % OoooooooOO
   if 31 - 31: o0oOOo0O0Ooo - OoO0O00 % I1IiiI
  if ( i111iii1IIi . rloc_probe and iiI1iIi1II1ii != None ) : o0oo0OoOo000 = iiI1iIi1II1ii . rloc_set
  if 23 - 23: OOooOOo
  if 97 - 97: Oo0Ooo / OoooooooOO . OoooooooOO
  if 47 - 47: OoO0O00
  if 52 - 52: I1IiiI * iIii1I11I1II1 % oO0o * IiII % oO0o
  if 9 - 9: I11i
  o0ooo0oOO0o = IiI11iI1iI
  if ( iiI1iIi1II1ii and o0oo0OoOo000 != iiI1iIi1II1ii . rloc_set ) :
   iiI1iIi1II1ii . delete_rlocs_from_rloc_probe_list ( )
   o0ooo0oOO0o = True
   if 78 - 78: iIii1I11I1II1 % I1ii11iIi11i % IiII
   if 59 - 59: iII111i - I1ii11iIi11i / OoooooooOO
   if 37 - 37: Oo0Ooo - OoO0O00 . i11iIiiIii + I1IiiI . iIii1I11I1II1 % OoOoOO00
   if 61 - 61: oO0o . o0oOOo0O0Ooo
   if 82 - 82: Oo0Ooo * OoooooooOO / ooOoO0o / I1IiiI
  o0o00 = iiI1iIi1II1ii . uptime if ( iiI1iIi1II1ii ) else None
  if ( iiI1iIi1II1ii == None ) :
   iiI1iIi1II1ii = lisp_mapping ( o0O0o . eid , o0O0o . group , o0oo0OoOo000 )
   iiI1iIi1II1ii . mapping_source = source
   if 28 - 28: iIii1I11I1II1 - o0oOOo0O0Ooo . iIii1I11I1II1 / I11i / I1Ii111 % iIii1I11I1II1
   if 45 - 45: OoO0O00 + ooOoO0o / iIii1I11I1II1 % i11iIiiIii
   if 16 - 16: i1IIi / oO0o - OOooOOo / Ii1I + I1IiiI
   if 62 - 62: i11iIiiIii . Ii1I . iII111i / I1Ii111 * OoO0O00
   if 31 - 31: OoOoOO00
   if 16 - 16: OoooooooOO
   if ( lisp_i_am_rtr and o0O0o . group . is_null ( ) == False ) :
    iiI1iIi1II1ii . map_cache_ttl = LISP_MCAST_TTL
   else :
    iiI1iIi1II1ii . map_cache_ttl = o0O0o . store_ttl ( )
    if 32 - 32: ooOoO0o - o0oOOo0O0Ooo / ooOoO0o + o0oOOo0O0Ooo + iII111i
   iiI1iIi1II1ii . action = o0O0o . action
   iiI1iIi1II1ii . add_cache ( o0ooo0oOO0o )
   if 78 - 78: OoooooooOO . I1ii11iIi11i * oO0o . o0oOOo0O0Ooo * OoOoOO00 / oO0o
   if 47 - 47: OOooOOo
  iI1I11II = "Add"
  if ( o0o00 ) :
   iiI1iIi1II1ii . uptime = o0o00
   iiI1iIi1II1ii . refresh_time = lisp_get_timestamp ( )
   iI1I11II = "Replace"
   if 99 - 99: O0 - OoO0O00
   if 95 - 95: Ii1I . IiII * o0oOOo0O0Ooo
  lprint ( "{} {} map-cache with {} RLOCs" . format ( iI1I11II ,
 green ( iiI1iIi1II1ii . print_eid_tuple ( ) , False ) , len ( o0oo0OoOo000 ) ) )
  if 91 - 91: I1Ii111
  if 49 - 49: I11i
  if 17 - 17: Oo0Ooo % o0oOOo0O0Ooo
  if 3 - 3: OoO0O00 . oO0o . oO0o . Ii1I
  if 100 - 100: i11iIiiIii / i1IIi . I1ii11iIi11i
  if ( lisp_ipc_dp_socket and i11iIiIi1i != None ) :
   lisp_write_ipc_keys ( i11iIiIi1i )
   if 1 - 1: IiII * I1Ii111 / I1ii11iIi11i * i11iIiiIii
   if 82 - 82: o0oOOo0O0Ooo * OoO0O00 / o0oOOo0O0Ooo % OoOoOO00 * iIii1I11I1II1 % O0
   if 10 - 10: ooOoO0o
   if 69 - 69: I11i + I1IiiI / oO0o
   if 89 - 89: i1IIi % OoOoOO00 . I1ii11iIi11i
   if 85 - 85: I1Ii111 - oO0o
   if 34 - 34: iIii1I11I1II1 / IiII + OoOoOO00 - IiII / ooOoO0o + OoOoOO00
  if ( IiI11iI1iI ) :
   oO0oo000O = bold ( "RLOC-probe" , False )
   for I1IIiIIIii in iiI1iIi1II1ii . best_rloc_set :
    oo0o00OO = red ( I1IIiIIIii . rloc . print_address_no_iid ( ) , False )
    lprint ( "Trigger {} to {}" . format ( oO0oo000O , oo0o00OO ) )
    lisp_send_map_request ( lisp_sockets , 0 , iiI1iIi1II1ii . eid , iiI1iIi1II1ii . group , I1IIiIIIii )
    if 14 - 14: ooOoO0o - OoooooooOO / iIii1I11I1II1
    if 98 - 98: i1IIi
    if 81 - 81: OoOoOO00 * i11iIiiIii + I1IiiI
 return
 if 2 - 2: I11i - IiII + I1IiiI % OoO0O00 + iIii1I11I1II1 + oO0o
 if 49 - 49: I1IiiI * I1Ii111 . I1IiiI - II111iiii
 if 57 - 57: oO0o + O0 - OoOoOO00
 if 14 - 14: II111iiii + i11iIiiIii + Ii1I / o0oOOo0O0Ooo . OoO0O00
 if 93 - 93: o0oOOo0O0Ooo + i1IIi
 if 24 - 24: i1IIi
 if 54 - 54: iIii1I11I1II1 - IiII + o0oOOo0O0Ooo + I1ii11iIi11i + IiII
 if 99 - 99: Oo0Ooo
def lisp_compute_auth ( packet , map_register , password ) :
 if ( map_register . alg_id == LISP_NONE_ALG_ID ) : return ( packet )
 if 38 - 38: I1ii11iIi11i - I1IiiI
 packet = map_register . zero_auth ( packet )
 IIi1iiIIi1i = lisp_hash_me ( packet , map_register . alg_id , password , False )
 if 50 - 50: iII111i % OoO0O00 - oO0o + Oo0Ooo . O0 . iII111i
 if 42 - 42: iII111i + I1ii11iIi11i
 if 44 - 44: I1ii11iIi11i % IiII
 if 1 - 1: Oo0Ooo + IiII - I1Ii111 / I1Ii111
 map_register . auth_data = IIi1iiIIi1i
 packet = map_register . encode_auth ( packet )
 return ( packet )
 if 25 - 25: OoOoOO00
 if 52 - 52: OOooOOo + IiII
 if 73 - 73: OoooooooOO - I1Ii111 % iII111i / OOooOOo . o0oOOo0O0Ooo - IiII
 if 69 - 69: Ii1I . iIii1I11I1II1 / Oo0Ooo * Oo0Ooo % IiII
 if 5 - 5: OOooOOo - I1Ii111 + IiII
 if 82 - 82: OOooOOo
 if 26 - 26: ooOoO0o + OoooooooOO + ooOoO0o * I1Ii111
def lisp_hash_me ( packet , alg_id , password , do_hex ) :
 if ( alg_id == LISP_NONE_ALG_ID ) : return ( True )
 if 26 - 26: I1IiiI - OOooOOo
 if ( alg_id == LISP_SHA_1_96_ALG_ID ) :
  I1iiiII1i1 = hashlib . sha1
  if 2 - 2: IiII % iII111i / o0oOOo0O0Ooo * I11i
 if ( alg_id == LISP_SHA_256_128_ALG_ID ) :
  I1iiiII1i1 = hashlib . sha256
  if 35 - 35: OoOoOO00 * I1Ii111 / II111iiii / O0
  if 35 - 35: ooOoO0o * I11i
 if ( do_hex ) :
  IIi1iiIIi1i = hmac . new ( password , packet , I1iiiII1i1 ) . hexdigest ( )
 else :
  IIi1iiIIi1i = hmac . new ( password , packet , I1iiiII1i1 ) . digest ( )
  if 85 - 85: i1IIi
 return ( IIi1iiIIi1i )
 if 81 - 81: I1Ii111
 if 28 - 28: i1IIi * ooOoO0o
 if 14 - 14: II111iiii + II111iiii - I11i / I11i . OoOoOO00 + OoO0O00
 if 92 - 92: II111iiii - II111iiii % IiII
 if 48 - 48: oO0o / II111iiii + oO0o
 if 16 - 16: o0oOOo0O0Ooo % II111iiii - i11iIiiIii - IiII + O0 - i11iIiiIii
 if 58 - 58: OoooooooOO / I1ii11iIi11i - Oo0Ooo / II111iiii
 if 13 - 13: o0oOOo0O0Ooo + OoOoOO00 * ooOoO0o % IiII
def lisp_verify_auth ( packet , alg_id , auth_data , password ) :
 if ( alg_id == LISP_NONE_ALG_ID ) : return ( True )
 if 18 - 18: I1IiiI . I1ii11iIi11i + Oo0Ooo - iII111i
 IIi1iiIIi1i = lisp_hash_me ( packet , alg_id , password , True )
 o00Oo = ( IIi1iiIIi1i == auth_data )
 if 15 - 15: I1Ii111 / I11i / i11iIiiIii + OoO0O00 % OOooOOo
 if 8 - 8: oO0o - I1IiiI / I11i + II111iiii - I1IiiI
 if 3 - 3: I11i * o0oOOo0O0Ooo . O0
 if 11 - 11: Oo0Ooo
 if ( o00Oo == False ) :
  lprint ( "Hashed value: {} does not match packet value: {}" . format ( IIi1iiIIi1i , auth_data ) )
  if 64 - 64: OOooOOo
  if 8 - 8: ooOoO0o % o0oOOo0O0Ooo
 return ( o00Oo )
 if 22 - 22: O0 * IiII . OoO0O00
 if 63 - 63: oO0o % Oo0Ooo * OoO0O00 / II111iiii / Ii1I - ooOoO0o
 if 14 - 14: ooOoO0o . o0oOOo0O0Ooo + II111iiii
 if 50 - 50: Ii1I - i1IIi * oO0o
 if 52 - 52: I11i / oO0o - oO0o
 if 84 - 84: iIii1I11I1II1 - o0oOOo0O0Ooo
 if 37 - 37: iII111i * o0oOOo0O0Ooo
def lisp_retransmit_map_notify ( map_notify ) :
 oo0OoO = map_notify . etr
 Oo0O00O = map_notify . etr_port
 if 23 - 23: ooOoO0o + OoooooooOO * iII111i . I11i
 if 2 - 2: iIii1I11I1II1 * I1ii11iIi11i - OoooooooOO
 if 93 - 93: iII111i % ooOoO0o * Oo0Ooo
 if 34 - 34: O0 * oO0o
 if 58 - 58: OOooOOo . iII111i - Oo0Ooo / iII111i . I11i
 if ( map_notify . retry_count == LISP_MAX_MAP_NOTIFY_RETRIES ) :
  lprint ( "Map-Notify with nonce 0x{} retry limit reached for ETR {}" . format ( map_notify . nonce_key , red ( oo0OoO . print_address ( ) , False ) ) )
  if 86 - 86: iIii1I11I1II1 - iII111i % Ii1I
  if 18 - 18: oO0o / IiII - OOooOOo % Ii1I
  Oo000O000 = map_notify . nonce_key
  if ( lisp_map_notify_queue . has_key ( Oo000O000 ) ) :
   map_notify . retransmit_timer . cancel ( )
   lprint ( "Dequeue Map-Notify from retransmit queue, key is: {}" . format ( Oo000O000 ) )
   if 88 - 88: i11iIiiIii
   try :
    lisp_map_notify_queue . pop ( Oo000O000 )
   except :
    lprint ( "Key not found in Map-Notify queue" )
    if 13 - 13: I1IiiI
    if 52 - 52: Ii1I * oO0o / I1Ii111 . IiII
  return
  if 84 - 84: OoooooooOO - oO0o - I1Ii111
  if 69 - 69: OoOoOO00 * Ii1I % OoooooooOO % OOooOOo * OoOoOO00
 I1I1I111 = map_notify . lisp_sockets
 map_notify . retry_count += 1
 if 20 - 20: IiII
 lprint ( "Retransmit {} with nonce 0x{} to xTR {}, retry {}" . format ( bold ( "Map-Notify" , False ) , map_notify . nonce_key ,
 # II111iiii
 red ( oo0OoO . print_address ( ) , False ) , map_notify . retry_count ) )
 if 80 - 80: OOooOOo . OoO0O00 + O0 / IiII
 lisp_send_map_notify ( I1I1I111 , map_notify . packet , oo0OoO , Oo0O00O )
 if ( map_notify . site ) : map_notify . site . map_notifies_sent += 1
 if 30 - 30: Ii1I / I11i . II111iiii + ooOoO0o
 if 58 - 58: Oo0Ooo % OOooOOo - i11iIiiIii - I1Ii111 - Ii1I % OoO0O00
 if 67 - 67: I1Ii111 + OoO0O00 - oO0o / OOooOOo . OoooooooOO * O0
 if 91 - 91: O0 * OoOoOO00 - OoOoOO00 * II111iiii - iII111i
 map_notify . retransmit_timer = threading . Timer ( LISP_MAP_NOTIFY_INTERVAL ,
 lisp_retransmit_map_notify , [ map_notify ] )
 map_notify . retransmit_timer . start ( )
 return
 if 38 - 38: oO0o * I11i % OOooOOo
 if 80 - 80: O0 % II111iiii / O0 . Oo0Ooo * OoOoOO00 + OOooOOo
 if 47 - 47: Ii1I - Oo0Ooo * OoOoOO00
 if 20 - 20: oO0o
 if 48 - 48: I1IiiI % OoO0O00
 if 33 - 33: Ii1I
 if 73 - 73: Ii1I . IiII
def lisp_send_merged_map_notify ( lisp_sockets , parent , map_register ,
 eid_record ) :
 if 43 - 43: I11i . IiII - iII111i * I1IiiI * iII111i
 if 90 - 90: i11iIiiIii * i1IIi
 if 88 - 88: i11iIiiIii - OoOoOO00
 if 53 - 53: iIii1I11I1II1 % I1Ii111 / Oo0Ooo % Oo0Ooo
 eid_record . rloc_count = len ( parent . registered_rlocs )
 iIiIi1IiiiI1 = eid_record . encode ( )
 eid_record . print_record ( "Merged Map-Notify " , False )
 if 64 - 64: OoO0O00 + I1ii11iIi11i / OoO0O00 * I1Ii111 . Oo0Ooo
 if 5 - 5: iII111i - iIii1I11I1II1 * IiII
 if 52 - 52: OOooOOo
 if 50 - 50: OoOoOO00 % o0oOOo0O0Ooo - II111iiii - i1IIi
 for iI11IiI1 in parent . registered_rlocs :
  oo0OOOO0O0o = lisp_rloc_record ( )
  oo0OOOO0O0o . store_rloc_entry ( iI11IiI1 )
  iIiIi1IiiiI1 += oo0OOOO0O0o . encode ( )
  oo0OOOO0O0o . print_record ( "  " )
  del ( oo0OOOO0O0o )
  if 24 - 24: I1ii11iIi11i * IiII + iII111i / Oo0Ooo - ooOoO0o . IiII
  if 81 - 81: OoooooooOO + OOooOOo
  if 7 - 7: I11i + ooOoO0o
  if 28 - 28: OoooooooOO * iII111i / oO0o / iII111i
  if 80 - 80: OoO0O00 - I1IiiI + OOooOOo - iII111i / i1IIi
 for iI11IiI1 in parent . registered_rlocs :
  oo0OoO = iI11IiI1 . rloc
  Ii1ii1 = lisp_map_notify ( lisp_sockets )
  Ii1ii1 . record_count = 1
  I1I1I1 = map_register . key_id
  Ii1ii1 . key_id = I1I1I1
  Ii1ii1 . alg_id = map_register . alg_id
  Ii1ii1 . auth_len = map_register . auth_len
  Ii1ii1 . nonce = map_register . nonce
  Ii1ii1 . nonce_key = lisp_hex_string ( Ii1ii1 . nonce )
  Ii1ii1 . etr . copy_address ( oo0OoO )
  Ii1ii1 . etr_port = map_register . sport
  Ii1ii1 . site = parent . site
  IiiiIi1iiii11 = Ii1ii1 . encode ( iIiIi1IiiiI1 , parent . site . auth_key [ I1I1I1 ] )
  Ii1ii1 . print_notify ( )
  if 83 - 83: iIii1I11I1II1
  if 73 - 73: I1ii11iIi11i + II111iiii . i11iIiiIii + I1IiiI + I1ii11iIi11i
  if 6 - 6: O0 % Ii1I . oO0o
  if 91 - 91: O0 - oO0o * O0
  Oo000O000 = Ii1ii1 . nonce_key
  if ( lisp_map_notify_queue . has_key ( Oo000O000 ) ) :
   oOoO0O0O0O0 = lisp_map_notify_queue [ Oo000O000 ]
   oOoO0O0O0O0 . retransmit_timer . cancel ( )
   del ( oOoO0O0O0O0 )
   if 84 - 84: IiII . OoO0O00
  lisp_map_notify_queue [ Oo000O000 ] = Ii1ii1
  if 73 - 73: OoOoOO00
  if 47 - 47: oO0o
  if 17 - 17: IiII
  if 47 - 47: I11i . I1IiiI % ooOoO0o . i11iIiiIii
  lprint ( "Send merged Map-Notify to ETR {}" . format ( red ( oo0OoO . print_address ( ) , False ) ) )
  if 63 - 63: I1ii11iIi11i % I11i % OoooooooOO
  lisp_send ( lisp_sockets , oo0OoO , LISP_CTRL_PORT , IiiiIi1iiii11 )
  if 100 - 100: O0
  parent . site . map_notifies_sent += 1
  if 9 - 9: Ii1I
  if 87 - 87: I1IiiI
  if 56 - 56: OOooOOo % oO0o - OoOoOO00
  if 27 - 27: I1ii11iIi11i - IiII * OoooooooOO * I1ii11iIi11i + i11iIiiIii . IiII
  Ii1ii1 . retransmit_timer = threading . Timer ( LISP_MAP_NOTIFY_INTERVAL ,
 lisp_retransmit_map_notify , [ Ii1ii1 ] )
  Ii1ii1 . retransmit_timer . start ( )
  if 81 - 81: oO0o / iIii1I11I1II1
 return
 if 15 - 15: Ii1I + I1IiiI . OOooOOo / OoooooooOO + I11i - I11i
 if 27 - 27: Ii1I / o0oOOo0O0Ooo . iIii1I11I1II1 . I1IiiI - OoO0O00
 if 28 - 28: ooOoO0o
 if 88 - 88: oO0o
 if 77 - 77: ooOoO0o + I1Ii111 . OoOoOO00
 if 2 - 2: i1IIi - IiII + iIii1I11I1II1 % i1IIi * II111iiii
 if 26 - 26: I11i
def lisp_build_map_notify ( lisp_sockets , eid_records , eid_list , record_count ,
 source , port , nonce , key_id , alg_id , auth_len , site , map_register_ack ) :
 if 57 - 57: I1ii11iIi11i + I1Ii111 + i11iIiiIii . i1IIi / i11iIiiIii
 Oo000O000 = lisp_hex_string ( nonce ) + source . print_address ( )
 if 43 - 43: Ii1I % I11i
 if 5 - 5: OoooooooOO % i11iIiiIii * o0oOOo0O0Ooo * OoooooooOO - o0oOOo0O0Ooo % I11i
 if 58 - 58: i11iIiiIii % Ii1I + Oo0Ooo - OoOoOO00 - i11iIiiIii / O0
 if 36 - 36: OOooOOo
 if 42 - 42: OOooOOo * ooOoO0o * i11iIiiIii + OoooooooOO . iIii1I11I1II1
 if 95 - 95: i1IIi * O0 / II111iiii * OoOoOO00 * I1IiiI
 lisp_remove_eid_from_map_notify_queue ( eid_list )
 if ( lisp_map_notify_queue . has_key ( Oo000O000 ) ) :
  Ii1ii1 = lisp_map_notify_queue [ Oo000O000 ]
  IiII1iiI = red ( source . print_address_no_iid ( ) , False )
  lprint ( "Map-Notify with nonce 0x{} pending for xTR {}" . format ( lisp_hex_string ( Ii1ii1 . nonce ) , IiII1iiI ) )
  if 38 - 38: OOooOOo - OoOoOO00 / OoO0O00 / o0oOOo0O0Ooo - i11iIiiIii
  return
  if 4 - 4: I1IiiI * o0oOOo0O0Ooo - I11i - OoooooooOO . OoooooooOO
  if 79 - 79: oO0o - iII111i
 Ii1ii1 = lisp_map_notify ( lisp_sockets )
 Ii1ii1 . record_count = record_count
 key_id = key_id
 Ii1ii1 . key_id = key_id
 Ii1ii1 . alg_id = alg_id
 Ii1ii1 . auth_len = auth_len
 Ii1ii1 . nonce = nonce
 Ii1ii1 . nonce_key = lisp_hex_string ( nonce )
 Ii1ii1 . etr . copy_address ( source )
 Ii1ii1 . etr_port = port
 Ii1ii1 . site = site
 Ii1ii1 . eid_list = eid_list
 if 34 - 34: OoooooooOO + Ii1I - iII111i + OoooooooOO / I1IiiI
 if 39 - 39: o0oOOo0O0Ooo . i1IIi * OoO0O00 / II111iiii / I1ii11iIi11i * OOooOOo
 if 39 - 39: O0 . OOooOOo
 if 95 - 95: I11i
 if ( map_register_ack == False ) :
  Oo000O000 = Ii1ii1 . nonce_key
  lisp_map_notify_queue [ Oo000O000 ] = Ii1ii1
  if 58 - 58: I1ii11iIi11i / i11iIiiIii + iII111i + I11i / oO0o
  if 8 - 8: I1ii11iIi11i
 if ( map_register_ack ) :
  lprint ( "Send Map-Notify to ack Map-Register" )
 else :
  lprint ( "Send Map-Notify for RLOC-set change" )
  if 100 - 100: OoooooooOO / I11i - Ii1I
  if 11 - 11: OoO0O00
  if 20 - 20: Oo0Ooo
  if 34 - 34: I1Ii111 % i11iIiiIii / oO0o - i1IIi . o0oOOo0O0Ooo / oO0o
  if 68 - 68: I1Ii111 % Ii1I * Oo0Ooo - O0 . IiII
 IiiiIi1iiii11 = Ii1ii1 . encode ( eid_records , site . auth_key [ key_id ] )
 Ii1ii1 . print_notify ( )
 if 1 - 1: I1ii11iIi11i
 if ( map_register_ack == False ) :
  o0O0o = lisp_eid_record ( )
  o0O0o . decode ( eid_records )
  o0O0o . print_record ( "  " , False )
  if 18 - 18: i11iIiiIii % OoO0O00 % OOooOOo . OOooOOo * Ii1I / II111iiii
  if 81 - 81: iII111i % IiII / I11i
  if 50 - 50: IiII + i1IIi % I1Ii111
  if 72 - 72: I1Ii111
  if 6 - 6: II111iiii - i1IIi
 lisp_send_map_notify ( lisp_sockets , IiiiIi1iiii11 , Ii1ii1 . etr , port )
 site . map_notifies_sent += 1
 if 78 - 78: OoOoOO00 - Oo0Ooo * II111iiii % iIii1I11I1II1 . i11iIiiIii % iII111i
 if ( map_register_ack ) : return
 if 85 - 85: I1ii11iIi11i + OOooOOo % i1IIi
 if 13 - 13: OOooOOo + i11iIiiIii / OOooOOo . O0 . OoO0O00 - Ii1I
 if 31 - 31: OoOoOO00 * o0oOOo0O0Ooo / O0 . iII111i / i11iIiiIii
 if 22 - 22: I1IiiI . OoooooooOO * I1ii11iIi11i + i11iIiiIii - O0 + i11iIiiIii
 if 98 - 98: OOooOOo + I1IiiI / IiII / OoooooooOO / OOooOOo
 if 8 - 8: OoooooooOO * OOooOOo * iII111i - iII111i
 Ii1ii1 . retransmit_timer = threading . Timer ( LISP_MAP_NOTIFY_INTERVAL ,
 lisp_retransmit_map_notify , [ Ii1ii1 ] )
 Ii1ii1 . retransmit_timer . start ( )
 return
 if 32 - 32: I1Ii111
 if 28 - 28: I11i . i11iIiiIii % iIii1I11I1II1 + OoOoOO00
 if 4 - 4: OOooOOo + I1ii11iIi11i - iII111i + OOooOOo / IiII
 if 23 - 23: iIii1I11I1II1 + OoooooooOO + ooOoO0o . iII111i . Oo0Ooo - iIii1I11I1II1
 if 25 - 25: O0 + I1IiiI % OOooOOo / Oo0Ooo . IiII / I1Ii111
 if 84 - 84: ooOoO0o . O0 + I1IiiI * OoO0O00 - I1IiiI
 if 24 - 24: Ii1I
 if 23 - 23: Oo0Ooo * i1IIi / I1IiiI . I11i - I1ii11iIi11i . iIii1I11I1II1
def lisp_send_map_notify_ack ( lisp_sockets , eid_records , map_notify , ms ) :
 map_notify . map_notify_ack = True
 if 15 - 15: O0 + o0oOOo0O0Ooo / oO0o
 if 27 - 27: Ii1I * II111iiii / oO0o
 if 99 - 99: I11i + ooOoO0o % I11i + O0 - Ii1I - I1Ii111
 if 3 - 3: Oo0Ooo . I1IiiI
 IiiiIi1iiii11 = map_notify . encode ( eid_records , ms . password )
 map_notify . print_notify ( )
 if 61 - 61: OoO0O00 - I1ii11iIi11i . Ii1I * i11iIiiIii
 if 97 - 97: ooOoO0o
 if 58 - 58: iII111i
 if 47 - 47: II111iiii % Oo0Ooo . iIii1I11I1II1 . oO0o
 oo0OoO = ms . map_server
 lprint ( "Send Map-Notify-Ack to {}" . format (
 red ( oo0OoO . print_address ( ) , False ) ) )
 lisp_send ( lisp_sockets , oo0OoO , LISP_CTRL_PORT , IiiiIi1iiii11 )
 return
 if 52 - 52: I11i * I1IiiI % I11i - iII111i - Ii1I - OoooooooOO
 if 15 - 15: iII111i
 if 95 - 95: i11iIiiIii . Ii1I / II111iiii + II111iiii + Ii1I / I11i
 if 72 - 72: I1Ii111 . I1Ii111 * O0 + I1ii11iIi11i / Oo0Ooo
 if 96 - 96: oO0o . ooOoO0o * Oo0Ooo % ooOoO0o + I1Ii111 + iIii1I11I1II1
 if 45 - 45: II111iiii
 if 42 - 42: ooOoO0o
 if 62 - 62: II111iiii * o0oOOo0O0Ooo . OoO0O00 / II111iiii
def lisp_send_multicast_map_notify ( lisp_sockets , site_eid , eid_list , xtr ) :
 if 5 - 5: OoO0O00 + O0 . OoooooooOO + I1IiiI + i1IIi * OOooOOo
 Ii1ii1 = lisp_map_notify ( lisp_sockets )
 Ii1ii1 . record_count = 1
 Ii1ii1 . nonce = lisp_get_control_nonce ( )
 Ii1ii1 . nonce_key = lisp_hex_string ( Ii1ii1 . nonce )
 Ii1ii1 . etr . copy_address ( xtr )
 Ii1ii1 . etr_port = LISP_CTRL_PORT
 Ii1ii1 . eid_list = eid_list
 Oo000O000 = Ii1ii1 . nonce_key
 if 19 - 19: OoooooooOO + i11iIiiIii / II111iiii - Oo0Ooo . OOooOOo
 if 10 - 10: oO0o * Oo0Ooo
 if 55 - 55: OoO0O00 - i1IIi - I11i * oO0o
 if 91 - 91: I1Ii111
 if 77 - 77: I1ii11iIi11i . ooOoO0o - iIii1I11I1II1 + Ii1I % II111iiii * II111iiii
 if 41 - 41: II111iiii + Oo0Ooo - IiII / I1Ii111 - OOooOOo . oO0o
 lisp_remove_eid_from_map_notify_queue ( Ii1ii1 . eid_list )
 if ( lisp_map_notify_queue . has_key ( Oo000O000 ) ) :
  Ii1ii1 = lisp_map_notify_queue [ Oo000O000 ]
  lprint ( "Map-Notify with nonce 0x{} pending for ITR {}" . format ( Ii1ii1 . nonce , red ( xtr . print_address_no_iid ( ) , False ) ) )
  if 100 - 100: ooOoO0o / I1ii11iIi11i * OoOoOO00 . I1ii11iIi11i . o0oOOo0O0Ooo * iIii1I11I1II1
  return
  if 15 - 15: iII111i + o0oOOo0O0Ooo / IiII
  if 33 - 33: OoooooooOO . IiII * o0oOOo0O0Ooo
  if 41 - 41: Ii1I . iII111i . o0oOOo0O0Ooo % OoooooooOO % IiII
  if 81 - 81: IiII * i11iIiiIii + i1IIi + OOooOOo . i1IIi
  if 6 - 6: i11iIiiIii - oO0o % OoO0O00 + iIii1I11I1II1
 lisp_map_notify_queue [ Oo000O000 ] = Ii1ii1
 if 69 - 69: IiII
 if 13 - 13: i11iIiiIii
 if 49 - 49: OoOoOO00
 if 61 - 61: I1Ii111 / I1Ii111 / iII111i / ooOoO0o - I1IiiI . o0oOOo0O0Ooo
 ooo0O0OO = site_eid . rtrs_in_rloc_set ( )
 if ( ooo0O0OO ) :
  if ( site_eid . is_rtr_in_rloc_set ( xtr ) ) : ooo0O0OO = False
  if 61 - 61: OoooooooOO + I11i + I11i / i1IIi
  if 97 - 97: i11iIiiIii + oO0o % OOooOOo . OoO0O00 . OOooOOo % ooOoO0o
  if 93 - 93: I1IiiI % i11iIiiIii
  if 45 - 45: OoooooooOO * o0oOOo0O0Ooo - OOooOOo + O0
  if 64 - 64: iII111i * I1ii11iIi11i - OoOoOO00
 o0O0o = lisp_eid_record ( )
 o0O0o . record_ttl = 1440
 o0O0o . eid . copy_address ( site_eid . eid )
 o0O0o . group . copy_address ( site_eid . group )
 o0O0o . rloc_count = 0
 for O0OooOoooO0O in site_eid . registered_rlocs :
  if ( ooo0O0OO ^ O0OooOoooO0O . is_rtr ( ) ) : continue
  o0O0o . rloc_count += 1
  if 1 - 1: i1IIi / OoO0O00 % i1IIi % i11iIiiIii / i1IIi
 IiiiIi1iiii11 = o0O0o . encode ( )
 if 8 - 8: O0 / OOooOOo + iII111i % iIii1I11I1II1 % iIii1I11I1II1 . ooOoO0o
 if 47 - 47: OoO0O00 / o0oOOo0O0Ooo / Ii1I * I1IiiI % ooOoO0o / I1Ii111
 if 80 - 80: I1Ii111 / O0 * O0
 if 40 - 40: OoO0O00 - oO0o / o0oOOo0O0Ooo . oO0o
 Ii1ii1 . print_notify ( )
 o0O0o . print_record ( "  " , False )
 if 89 - 89: i11iIiiIii - II111iiii
 if 67 - 67: IiII % I1Ii111 + i11iIiiIii
 if 53 - 53: OOooOOo
 if 95 - 95: oO0o - OOooOOo % I1Ii111 / OoooooooOO % OoooooooOO - O0
 for O0OooOoooO0O in site_eid . registered_rlocs :
  if ( ooo0O0OO ^ O0OooOoooO0O . is_rtr ( ) ) : continue
  oo0OOOO0O0o = lisp_rloc_record ( )
  oo0OOOO0O0o . store_rloc_entry ( O0OooOoooO0O )
  IiiiIi1iiii11 += oo0OOOO0O0o . encode ( )
  oo0OOOO0O0o . print_record ( "    " )
  if 21 - 21: I1Ii111 . i1IIi - iII111i % I1ii11iIi11i . OOooOOo
  if 52 - 52: Ii1I * I1ii11iIi11i
  if 21 - 21: I1IiiI . i11iIiiIii - o0oOOo0O0Ooo * II111iiii % iIii1I11I1II1
  if 9 - 9: I1ii11iIi11i + I11i
  if 20 - 20: iII111i + i1IIi / oO0o % OoooooooOO * OoOoOO00
 IiiiIi1iiii11 = Ii1ii1 . encode ( IiiiIi1iiii11 , "" )
 if ( IiiiIi1iiii11 == None ) : return
 if 70 - 70: Oo0Ooo - OOooOOo * OOooOOo / o0oOOo0O0Ooo
 if 4 - 4: OoOoOO00 / OoO0O00
 if 66 - 66: I1Ii111 / OoOoOO00
 if 53 - 53: OoOoOO00 . i11iIiiIii - OoooooooOO
 lisp_send_map_notify ( lisp_sockets , IiiiIi1iiii11 , xtr , LISP_CTRL_PORT )
 if 92 - 92: O0 - i11iIiiIii + OoO0O00 - OoooooooOO - o0oOOo0O0Ooo
 if 25 - 25: oO0o / oO0o / Ii1I / O0
 if 56 - 56: ooOoO0o
 if 19 - 19: O0 * I1IiiI + I1ii11iIi11i
 Ii1ii1 . retransmit_timer = threading . Timer ( LISP_MAP_NOTIFY_INTERVAL ,
 lisp_retransmit_map_notify , [ Ii1ii1 ] )
 Ii1ii1 . retransmit_timer . start ( )
 return
 if 25 - 25: I11i - ooOoO0o / OoO0O00 / iII111i - OoO0O00
 if 86 - 86: OoO0O00
 if 89 - 89: OoooooooOO % iII111i * I1ii11iIi11i + I1ii11iIi11i . Oo0Ooo
 if 4 - 4: I11i
 if 8 - 8: IiII
 if 1 - 1: ooOoO0o . IiII
 if 4 - 4: iIii1I11I1II1 % I1IiiI - OoooooooOO / iII111i
def lisp_queue_multicast_map_notify ( lisp_sockets , rle_list ) :
 Oo00oO0 = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
 if 3 - 3: oO0o % I1IiiI - O0
 for oOOooo000OoO in rle_list :
  IiIIiIII1I1i = lisp_site_eid_lookup ( oOOooo000OoO [ 0 ] , oOOooo000OoO [ 1 ] , True )
  if ( IiIIiIII1I1i == None ) : continue
  if 25 - 25: OoO0O00 % IiII . i1IIi / OoOoOO00 + OoOoOO00
  if 53 - 53: II111iiii % i1IIi + ooOoO0o . I1Ii111
  if 52 - 52: I1IiiI + I1Ii111 * oO0o / i11iIiiIii * iIii1I11I1II1
  if 27 - 27: Oo0Ooo
  if 85 - 85: iIii1I11I1II1 . o0oOOo0O0Ooo + oO0o
  if 79 - 79: O0 - iIii1I11I1II1 + i1IIi . I11i
  if 21 - 21: II111iiii
  I1iiiII1Ii1i1 = IiIIiIII1I1i . registered_rlocs
  if ( len ( I1iiiII1Ii1i1 ) == 0 ) :
   iII1iI1IIiii = { }
   for iIiIi1I in IiIIiIII1I1i . individual_registrations . values ( ) :
    for O0OooOoooO0O in iIiIi1I . registered_rlocs :
     if ( O0OooOoooO0O . is_rtr ( ) == False ) : continue
     iII1iI1IIiii [ O0OooOoooO0O . rloc . print_address ( ) ] = O0OooOoooO0O
     if 45 - 45: o0oOOo0O0Ooo + iIii1I11I1II1 / O0
     if 2 - 2: I11i + I1IiiI . IiII . OoOoOO00 * oO0o - ooOoO0o
   I1iiiII1Ii1i1 = iII1iI1IIiii . values ( )
   if 29 - 29: OoO0O00
   if 78 - 78: iII111i * ooOoO0o + O0 % ooOoO0o + OoO0O00
   if 41 - 41: II111iiii . oO0o + O0 % i1IIi . Ii1I
   if 90 - 90: ooOoO0o * I1IiiI / II111iiii % Oo0Ooo % OoooooooOO
   if 78 - 78: OoooooooOO . IiII
   if 55 - 55: I11i / I1ii11iIi11i * O0 + IiII % I11i
  OOooOo00Ooo = [ ]
  o00O0o0O0O0o = False
  if ( IiIIiIII1I1i . eid . address == 0 and IiIIiIII1I1i . eid . mask_len == 0 ) :
   o0o = [ ]
   oOO0OOO00O0 = [ ]
   if ( len ( I1iiiII1Ii1i1 ) != 0 and I1iiiII1Ii1i1 [ 0 ] . rle != None ) :
    oOO0OOO00O0 = I1iiiII1Ii1i1 [ 0 ] . rle . rle_nodes
    if 6 - 6: I1IiiI * ooOoO0o * O0 + OOooOOo
   for Iii in oOO0OOO00O0 :
    OOooOo00Ooo . append ( Iii . address )
    o0o . append ( Iii . address . print_address_no_iid ( ) )
    if 11 - 11: i1IIi / OoOoOO00 + OoOoOO00 + I1ii11iIi11i + OOooOOo
   lprint ( "Notify existing RLE-nodes {}" . format ( o0o ) )
  else :
   if 21 - 21: ooOoO0o
   if 28 - 28: OoOoOO00 + OoOoOO00 - OoOoOO00 / ooOoO0o
   if 81 - 81: oO0o
   if 34 - 34: o0oOOo0O0Ooo * OOooOOo - i1IIi * o0oOOo0O0Ooo * Oo0Ooo
   if 59 - 59: iIii1I11I1II1 / Oo0Ooo % II111iiii
   for O0OooOoooO0O in I1iiiII1Ii1i1 :
    if ( O0OooOoooO0O . is_rtr ( ) ) : OOooOo00Ooo . append ( O0OooOoooO0O . rloc )
    if 55 - 55: ooOoO0o - IiII + o0oOOo0O0Ooo
    if 48 - 48: O0 - iIii1I11I1II1 * OOooOOo
    if 33 - 33: I11i
    if 63 - 63: Ii1I % II111iiii / OoOoOO00 + Oo0Ooo
    if 28 - 28: OoO0O00 + I1IiiI . oO0o + II111iiii - O0
   o00O0o0O0O0o = ( len ( OOooOo00Ooo ) != 0 )
   if ( o00O0o0O0O0o == False ) :
    I11111Ii = lisp_site_eid_lookup ( oOOooo000OoO [ 0 ] , Oo00oO0 , False )
    if ( I11111Ii == None ) : continue
    if 32 - 32: oO0o
    for O0OooOoooO0O in I11111Ii . registered_rlocs :
     if ( O0OooOoooO0O . rloc . is_null ( ) ) : continue
     OOooOo00Ooo . append ( O0OooOoooO0O . rloc )
     if 62 - 62: i11iIiiIii + OoooooooOO + IiII - OoO0O00 / oO0o * iIii1I11I1II1
     if 91 - 91: o0oOOo0O0Ooo - i11iIiiIii + Oo0Ooo % iIii1I11I1II1
     if 58 - 58: iII111i / ooOoO0o - I1Ii111 + I1Ii111 * ooOoO0o
     if 48 - 48: iII111i % O0 % Ii1I * OoO0O00 . OoO0O00
     if 74 - 74: OoO0O00 * i1IIi + I1ii11iIi11i / o0oOOo0O0Ooo / i1IIi
     if 94 - 94: Ii1I
   if ( len ( OOooOo00Ooo ) == 0 ) :
    lprint ( "No ITRs or RTRs found for {}, Map-Notify suppressed" . format ( green ( IiIIiIII1I1i . print_eid_tuple ( ) , False ) ) )
    if 13 - 13: OoO0O00 - II111iiii . iII111i + OoOoOO00 / i11iIiiIii
    continue
    if 32 - 32: ooOoO0o / II111iiii / I1ii11iIi11i
    if 34 - 34: iIii1I11I1II1
    if 47 - 47: OOooOOo * iII111i
    if 71 - 71: IiII - OoooooooOO * i11iIiiIii . OoooooooOO % i1IIi . Oo0Ooo
    if 3 - 3: OoO0O00 + i11iIiiIii + oO0o * IiII
    if 19 - 19: iII111i / II111iiii . I1Ii111 * I1IiiI - OOooOOo
  for iI11IiI1 in OOooOo00Ooo :
   lprint ( "Build Map-Notify to {}TR {} for {}" . format ( "R" if o00O0o0O0O0o else "x" , red ( iI11IiI1 . print_address_no_iid ( ) , False ) ,
   # OoO0O00 . iII111i + OoooooooOO - I1Ii111 + ooOoO0o
 green ( IiIIiIII1I1i . print_eid_tuple ( ) , False ) ) )
   if 58 - 58: i1IIi % OoO0O00 % I1IiiI * O0 . Ii1I / OoO0O00
   o000000oOooO = [ IiIIiIII1I1i . print_eid_tuple ( ) ]
   lisp_send_multicast_map_notify ( lisp_sockets , IiIIiIII1I1i , o000000oOooO , iI11IiI1 )
   time . sleep ( .001 )
   if 7 - 7: OoOoOO00 * OoooooooOO / iII111i + i1IIi
   if 64 - 64: IiII % I11i / iIii1I11I1II1
 return
 if 66 - 66: Ii1I
 if 55 - 55: OOooOOo + I1IiiI + IiII . Ii1I * oO0o
 if 71 - 71: IiII - iII111i % I1IiiI * iII111i
 if 27 - 27: ooOoO0o - OoO0O00
 if 83 - 83: iII111i * OoOoOO00 - O0 * Ii1I
 if 79 - 79: I11i / iII111i % Ii1I / OoOoOO00 % O0 / IiII
 if 32 - 32: IiII * II111iiii . Ii1I
 if 68 - 68: I11i / O0
def lisp_find_sig_in_rloc_set ( packet , rloc_count ) :
 for IiIIi1IiiIiI in range ( rloc_count ) :
  oo0OOOO0O0o = lisp_rloc_record ( )
  packet = oo0OOOO0O0o . decode ( packet , None )
  IIiI1IIiI = oo0OOOO0O0o . json
  if ( IIiI1IIiI == None ) : continue
  if 33 - 33: I1IiiI / I1IiiI / I1ii11iIi11i * IiII / Ii1I
  try :
   IIiI1IIiI = json . loads ( IIiI1IIiI . json_string )
  except :
   lprint ( "Found corrupted JSON signature" )
   continue
   if 55 - 55: i11iIiiIii / OoooooooOO - Ii1I * Oo0Ooo . I1Ii111
   if 96 - 96: IiII / OoooooooOO + i11iIiiIii . Ii1I
  if ( IIiI1IIiI . has_key ( "signature" ) == False ) : continue
  return ( oo0OOOO0O0o )
  if 64 - 64: OoooooooOO / IiII - IiII . Ii1I % Oo0Ooo
 return ( None )
 if 35 - 35: iII111i * I1IiiI * Oo0Ooo + I1Ii111 + i1IIi - ooOoO0o
 if 23 - 23: II111iiii - O0
 if 58 - 58: o0oOOo0O0Ooo * OoO0O00 + OoO0O00
 if 93 - 93: IiII - I1ii11iIi11i % I11i + i1IIi % OoO0O00
 if 20 - 20: oO0o . Oo0Ooo + IiII - II111iiii % Ii1I
 if 64 - 64: Ii1I % OoO0O00 + OOooOOo % OoOoOO00 + IiII
 if 92 - 92: iII111i * Oo0Ooo - OoOoOO00
 if 33 - 33: i11iIiiIii - OoOoOO00 . OOooOOo * II111iiii . Ii1I
 if 59 - 59: OoOoOO00
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
def lisp_get_eid_hash ( eid ) :
 iIIIIiiii = None
 for IiI1Iiii in lisp_eid_hashes :
  if 7 - 7: OoOoOO00 + OoO0O00 * I1IiiI
  if 63 - 63: I1ii11iIi11i + iII111i * i1IIi
  if 63 - 63: I1ii11iIi11i / II111iiii % oO0o + ooOoO0o . Ii1I % I11i
  if 59 - 59: I1Ii111 % o0oOOo0O0Ooo - I1IiiI * i1IIi
  o0OoO0000o = IiI1Iiii . instance_id
  if ( o0OoO0000o == - 1 ) : IiI1Iiii . instance_id = eid . instance_id
  if 5 - 5: I1IiiI
  ii1i = eid . is_more_specific ( IiI1Iiii )
  IiI1Iiii . instance_id = o0OoO0000o
  if ( ii1i ) :
   iIIIIiiii = 128 - IiI1Iiii . mask_len
   break
   if 79 - 79: OoooooooOO . OoOoOO00 * OoO0O00 + I11i / iII111i - Ii1I
   if 9 - 9: I1IiiI - IiII . iIii1I11I1II1
 if ( iIIIIiiii == None ) : return ( None )
 if 99 - 99: iII111i / o0oOOo0O0Ooo
 ii1i1II11II1i = eid . address
 IIiiI1 = ""
 for IiIIi1IiiIiI in range ( 0 , iIIIIiiii / 16 ) :
  IiiIIi1 = ii1i1II11II1i & 0xffff
  IiiIIi1 = hex ( IiiIIi1 ) [ 2 : - 1 ]
  IIiiI1 = IiiIIi1 . zfill ( 4 ) + ":" + IIiiI1
  ii1i1II11II1i >>= 16
  if 92 - 92: iII111i * i11iIiiIii * o0oOOo0O0Ooo * OoO0O00
 if ( iIIIIiiii % 16 != 0 ) :
  IiiIIi1 = ii1i1II11II1i & 0xff
  IiiIIi1 = hex ( IiiIIi1 ) [ 2 : - 1 ]
  IIiiI1 = IiiIIi1 . zfill ( 2 ) + ":" + IIiiI1
  if 70 - 70: Ii1I
 return ( IIiiI1 [ 0 : - 1 ] )
 if 51 - 51: i1IIi % Oo0Ooo
 if 32 - 32: OoOoOO00 + iIii1I11I1II1 . OoO0O00 . I1ii11iIi11i . IiII
 if 97 - 97: ooOoO0o * ooOoO0o * iIii1I11I1II1 * I1Ii111 + iII111i + OoOoOO00
 if 8 - 8: Oo0Ooo . oO0o + II111iiii
 if 100 - 100: OoOoOO00 . IiII / OoO0O00 * OoooooooOO - OoOoOO00
 if 98 - 98: OoO0O00 / I1ii11iIi11i + I1ii11iIi11i
 if 70 - 70: i1IIi % Oo0Ooo % I1Ii111 + I11i . ooOoO0o
 if 66 - 66: i11iIiiIii % I11i / Oo0Ooo * oO0o
 if 7 - 7: O0 - Ii1I - oO0o
 if 95 - 95: i1IIi - OOooOOo / OoOoOO00 + I1ii11iIi11i + O0
 if 10 - 10: ooOoO0o - OOooOOo + i1IIi * Ii1I
def lisp_lookup_public_key ( eid ) :
 o0OoO0000o = eid . instance_id
 if 78 - 78: iIii1I11I1II1
 if 76 - 76: ooOoO0o - i11iIiiIii * I11i / I1IiiI - OOooOOo
 if 41 - 41: iII111i
 if 91 - 91: I1Ii111
 if 54 - 54: o0oOOo0O0Ooo . i1IIi / iII111i
 ii1III1 = lisp_get_eid_hash ( eid )
 if ( ii1III1 == None ) : return ( [ None , None , False ] )
 if 93 - 93: I1Ii111 . II111iiii
 ii1III1 = "hash-" + ii1III1
 oo0OOo00OOoO = lisp_address ( LISP_AFI_NAME , ii1III1 , len ( ii1III1 ) , o0OoO0000o )
 IIi1iiIII11 = lisp_address ( LISP_AFI_NONE , "" , 0 , o0OoO0000o )
 if 71 - 71: iII111i . II111iiii + i11iIiiIii
 if 41 - 41: oO0o . o0oOOo0O0Ooo . I11i
 if 53 - 53: I11i
 if 64 - 64: OoO0O00 + I11i / I1IiiI . II111iiii
 I11111Ii = lisp_site_eid_lookup ( oo0OOo00OOoO , IIi1iiIII11 , True )
 if ( I11111Ii == None ) : return ( [ oo0OOo00OOoO , None , False ] )
 if 79 - 79: I1Ii111 + IiII / OoooooooOO
 if 53 - 53: Ii1I
 if 85 - 85: OoO0O00 + II111iiii / OoO0O00 . II111iiii * OoOoOO00 * I1IiiI
 if 19 - 19: iII111i / Ii1I + iIii1I11I1II1 * O0 - Oo0Ooo
 I11iIi1i1iiI = None
 for I1IIiIIIii in I11111Ii . registered_rlocs :
  iiIiIiIiII = I1IIiIIIii . json
  if ( iiIiIiIiII == None ) : continue
  try :
   iiIiIiIiII = json . loads ( iiIiIiIiII . json_string )
  except :
   lprint ( "Registered RLOC JSON format is invalid for {}" . format ( ii1III1 ) )
   if 89 - 89: o0oOOo0O0Ooo / i11iIiiIii
   return ( [ oo0OOo00OOoO , None , False ] )
   if 42 - 42: II111iiii + i1IIi
  if ( iiIiIiIiII . has_key ( "public-key" ) == False ) : continue
  I11iIi1i1iiI = iiIiIiIiII [ "public-key" ]
  break
  if 67 - 67: OoOoOO00
 return ( [ oo0OOo00OOoO , I11iIi1i1iiI , True ] )
 if 5 - 5: Oo0Ooo / OoooooooOO / Ii1I * I1Ii111
 if 37 - 37: Ii1I * o0oOOo0O0Ooo
 if 39 - 39: OoooooooOO
 if 37 - 37: OoO0O00 . iII111i
 if 32 - 32: II111iiii
 if 11 - 11: i11iIiiIii - OOooOOo . i1IIi + OOooOOo - O0
 if 17 - 17: i1IIi % o0oOOo0O0Ooo % ooOoO0o / I11i
 if 68 - 68: OoOoOO00
def lisp_verify_cga_sig ( eid , rloc_record ) :
 if 14 - 14: iIii1I11I1II1 + oO0o / ooOoO0o
 if 20 - 20: I1ii11iIi11i . II111iiii % I1Ii111 + I1Ii111 / OoooooooOO . Ii1I
 if 98 - 98: OoooooooOO - i11iIiiIii - iII111i + Ii1I - I1IiiI
 if 75 - 75: OOooOOo
 if 25 - 25: iII111i / I1ii11iIi11i - ooOoO0o
 O0OO0OoO00oOo = json . loads ( rloc_record . json . json_string )
 if 53 - 53: IiII / OoooooooOO / ooOoO0o + Oo0Ooo - OOooOOo - iIii1I11I1II1
 if ( lisp_get_eid_hash ( eid ) ) :
  Oo0o0ooOo0 = eid
 elif ( O0OO0OoO00oOo . has_key ( "signature-eid" ) ) :
  O0iIII = O0OO0OoO00oOo [ "signature-eid" ]
  Oo0o0ooOo0 = lisp_address ( LISP_AFI_IPV6 , O0iIII , 0 , 0 )
 else :
  lprint ( "  No signature-eid found in RLOC-record" )
  return ( False )
  if 53 - 53: I11i . OoooooooOO * I1Ii111
  if 100 - 100: O0
  if 99 - 99: OoO0O00 * I1Ii111 % I11i / OoOoOO00
  if 95 - 95: II111iiii . ooOoO0o + O0
  if 58 - 58: iII111i + iIii1I11I1II1 % oO0o % OoooooooOO
 oo0OOo00OOoO , I11iIi1i1iiI , O0OOo0oO0OO0 = lisp_lookup_public_key ( Oo0o0ooOo0 )
 if ( oo0OOo00OOoO == None ) :
  I11i11i1 = green ( Oo0o0ooOo0 . print_address ( ) , False )
  lprint ( "  Could not parse hash in EID {}" . format ( I11i11i1 ) )
  return ( False )
  if 64 - 64: II111iiii - oO0o / iIii1I11I1II1 . Ii1I
  if 23 - 23: o0oOOo0O0Ooo + I1IiiI
 ooOoOO0o = "found" if O0OOo0oO0OO0 else bold ( "not found" , False )
 I11i11i1 = green ( oo0OOo00OOoO . print_address ( ) , False )
 lprint ( "  Lookup for crypto-hashed EID {} {}" . format ( I11i11i1 , ooOoOO0o ) )
 if ( O0OOo0oO0OO0 == False ) : return ( False )
 if 60 - 60: I1ii11iIi11i * i11iIiiIii + oO0o
 if ( I11iIi1i1iiI == None ) :
  lprint ( "  RLOC-record with public-key not found" )
  return ( False )
  if 59 - 59: I11i
  if 61 - 61: IiII * I1Ii111 * OoO0O00 / oO0o - OoooooooOO
 iI11i11ii11 = I11iIi1i1iiI [ 0 : 8 ] + "..." + I11iIi1i1iiI [ - 8 : : ]
 lprint ( "  RLOC-record with public-key '{}' found" . format ( iI11i11ii11 ) )
 if 48 - 48: II111iiii
 if 79 - 79: II111iiii % II111iiii
 if 85 - 85: OoooooooOO / o0oOOo0O0Ooo * I11i + iII111i
 if 99 - 99: i11iIiiIii / oO0o . i11iIiiIii
 if 46 - 46: I1ii11iIi11i
 II1I1IIi1111I = O0OO0OoO00oOo [ "signature" ]
 if 3 - 3: iII111i / i11iIiiIii % OOooOOo + Ii1I . Oo0Ooo
 try :
  O0OO0OoO00oOo = binascii . a2b_base64 ( II1I1IIi1111I )
 except :
  lprint ( "  Incorrect padding in signature string" )
  return ( False )
  if 16 - 16: oO0o / Ii1I % i11iIiiIii % I1IiiI * I1ii11iIi11i
  if 4 - 4: iIii1I11I1II1 + Ii1I % I1Ii111 . OoOoOO00 % OoooooooOO + II111iiii
 i111Ii = len ( O0OO0OoO00oOo )
 if ( i111Ii & 1 ) :
  lprint ( "  Signature length is odd, length {}" . format ( i111Ii ) )
  return ( False )
  if 14 - 14: oO0o . OOooOOo * OOooOOo . OoO0O00
  if 27 - 27: OOooOOo - iII111i - IiII
  if 14 - 14: i11iIiiIii . I1ii11iIi11i % OoOoOO00 * Ii1I / OoO0O00
  if 56 - 56: o0oOOo0O0Ooo / I1IiiI + I11i + I1IiiI
  if 34 - 34: Oo0Ooo / i11iIiiIii - ooOoO0o
 IIIiiI1I = Oo0o0ooOo0 . print_address ( )
 if 77 - 77: OoOoOO00 * OoooooooOO
 if 41 - 41: iIii1I11I1II1 - O0 . II111iiii + I1IiiI - II111iiii / oO0o
 if 35 - 35: ooOoO0o - OoOoOO00 / iIii1I11I1II1 / OOooOOo
 if 38 - 38: i1IIi % OoooooooOO
 I11iIi1i1iiI = binascii . a2b_base64 ( I11iIi1i1iiI )
 try :
  Oo000O000 = ecdsa . VerifyingKey . from_pem ( I11iIi1i1iiI )
 except :
  IiiiIi = bold ( "Bad public-key" , False )
  lprint ( "  {}, not in PEM format" . format ( IiiiIi ) )
  return ( False )
  if 54 - 54: OOooOOo * I1ii11iIi11i + OoooooooOO
  if 58 - 58: i1IIi - OoooooooOO * OOooOOo . ooOoO0o + O0 + o0oOOo0O0Ooo
  if 87 - 87: OOooOOo + I1Ii111 + O0 / oO0o / i11iIiiIii
  if 60 - 60: O0 . II111iiii
  if 69 - 69: II111iiii / ooOoO0o - OoOoOO00 / OOooOOo
  if 52 - 52: OoO0O00 % I11i + o0oOOo0O0Ooo % OoOoOO00
  if 46 - 46: o0oOOo0O0Ooo % O0
  if 30 - 30: oO0o
  if 64 - 64: O0
  if 70 - 70: oO0o % I1IiiI . iIii1I11I1II1 - Oo0Ooo + OoOoOO00 % O0
  if 91 - 91: I1Ii111 - oO0o * ooOoO0o - I1ii11iIi11i + IiII + O0
 try :
  OO = Oo000O000 . verify ( O0OO0OoO00oOo , IIIiiI1I , hashfunc = hashlib . sha256 )
 except :
  lprint ( "  Signature library failed for signature data '{}'" . format ( IIIiiI1I ) )
  if 18 - 18: OoOoOO00 / IiII / o0oOOo0O0Ooo . OOooOOo
  lprint ( "  Signature used '{}'" . format ( II1I1IIi1111I ) )
  return ( False )
  if 35 - 35: I11i . ooOoO0o % I11i / iII111i / O0 % I11i
 return ( OO )
 if 29 - 29: I1Ii111 + Ii1I
 if 100 - 100: Ii1I + I1Ii111 / iIii1I11I1II1 / i1IIi % OoOoOO00
 if 6 - 6: oO0o + ooOoO0o
 if 13 - 13: Oo0Ooo . IiII % iII111i + i1IIi / OOooOOo
 if 1 - 1: I11i * i1IIi * Oo0Ooo % O0
 if 41 - 41: OOooOOo % OoOoOO00
 if 82 - 82: I11i . IiII
 if 27 - 27: I1Ii111 % O0 * OoooooooOO . Oo0Ooo
 if 51 - 51: I11i
 if 80 - 80: Oo0Ooo + oO0o
def lisp_remove_eid_from_map_notify_queue ( eid_list ) :
 if 76 - 76: I1IiiI * OoooooooOO - i11iIiiIii / I11i / Oo0Ooo
 if 82 - 82: IiII % ooOoO0o
 if 100 - 100: Oo0Ooo . oO0o - iII111i + OoooooooOO
 if 27 - 27: Oo0Ooo . I1Ii111 - i1IIi * I1IiiI
 if 96 - 96: I1ii11iIi11i - Ii1I . I1ii11iIi11i
 Oo0Oo00O000 = [ ]
 for o0oOo0oo0 in eid_list :
  for iiI1IiII1iI in lisp_map_notify_queue :
   Ii1ii1 = lisp_map_notify_queue [ iiI1IiII1iI ]
   if ( o0oOo0oo0 not in Ii1ii1 . eid_list ) : continue
   if 54 - 54: IiII - I11i % OoooooooOO
   Oo0Oo00O000 . append ( iiI1IiII1iI )
   iiI1I = Ii1ii1 . retransmit_timer
   if ( iiI1I ) : iiI1I . cancel ( )
   if 87 - 87: OoOoOO00 * I11i * Ii1I / O0 + OOooOOo
   lprint ( "Remove from Map-Notify queue nonce 0x{} for EID {}" . format ( Ii1ii1 . nonce_key , green ( o0oOo0oo0 , False ) ) )
   if 81 - 81: iIii1I11I1II1 * iII111i . iIii1I11I1II1 - i1IIi % OOooOOo - I1Ii111
   if 77 - 77: iIii1I11I1II1 % II111iiii
   if 33 - 33: II111iiii
   if 60 - 60: iIii1I11I1II1 / OOooOOo
   if 78 - 78: i11iIiiIii
   if 20 - 20: OoooooooOO * OoooooooOO - OOooOOo
   if 34 - 34: I1ii11iIi11i * i1IIi % OoooooooOO / I1IiiI
 for iiI1IiII1iI in Oo0Oo00O000 : lisp_map_notify_queue . pop ( iiI1IiII1iI )
 return
 if 39 - 39: OoO0O00 + IiII - II111iiii % I11i
 if 80 - 80: o0oOOo0O0Ooo * ooOoO0o
 if 87 - 87: I1Ii111 + O0 / I1ii11iIi11i / OoOoOO00 . Oo0Ooo - IiII
 if 24 - 24: OoOoOO00
 if 19 - 19: ooOoO0o
 if 43 - 43: O0 . I1Ii111 % OoooooooOO / I1IiiI . o0oOOo0O0Ooo - OoOoOO00
 if 46 - 46: I11i - OoooooooOO % o0oOOo0O0Ooo
 if 7 - 7: OoooooooOO - I1Ii111 * IiII
def lisp_decrypt_map_register ( packet ) :
 if 20 - 20: o0oOOo0O0Ooo . OoooooooOO * I1IiiI . Oo0Ooo * OoOoOO00
 if 3 - 3: I1Ii111 % i11iIiiIii % O0 % II111iiii
 if 8 - 8: OoooooooOO * ooOoO0o
 if 26 - 26: i11iIiiIii + oO0o - i1IIi
 if 71 - 71: I1IiiI % I1Ii111 / oO0o % oO0o / iIii1I11I1II1 + I1Ii111
 O0ooOoO0 = socket . ntohl ( struct . unpack ( "I" , packet [ 0 : 4 ] ) [ 0 ] )
 O00oOO0OO00 = ( O0ooOoO0 >> 13 ) & 0x1
 if ( O00oOO0OO00 == 0 ) : return ( packet )
 if 61 - 61: I1ii11iIi11i % I1IiiI % OoOoOO00
 oo0Oo00oOO = ( O0ooOoO0 >> 14 ) & 0x7
 if 88 - 88: OoO0O00
 if 82 - 82: OOooOOo / I11i / OoooooooOO % oO0o
 if 27 - 27: oO0o + IiII
 if 5 - 5: iIii1I11I1II1 + OoOoOO00 * I1Ii111 * i11iIiiIii
 try :
  II11iI11i1 = lisp_ms_encryption_keys [ oo0Oo00oOO ]
  II11iI11i1 = II11iI11i1 . zfill ( 32 )
  iiI1iiIiiiI1I = "0" * 8
 except :
  lprint ( "Cannot decrypt Map-Register with key-id {}" . format ( oo0Oo00oOO ) )
  return ( None )
  if 37 - 37: I1IiiI / OoO0O00 . OoO0O00 + i11iIiiIii - oO0o
  if 57 - 57: I1IiiI . OoO0O00
 OooOOOoOoo0O0 = bold ( "Decrypt" , False )
 lprint ( "{} Map-Register with key-id {}" . format ( OooOOOoOoo0O0 , oo0Oo00oOO ) )
 if 49 - 49: II111iiii + iII111i
 iiii1Ii1iii = chacha . ChaCha ( II11iI11i1 , iiI1iiIiiiI1I ) . decrypt ( packet [ 4 : : ] )
 return ( packet [ 0 : 4 ] + iiii1Ii1iii )
 if 85 - 85: I11i / i11iIiiIii
 if 33 - 33: iIii1I11I1II1 % O0 + II111iiii * OOooOOo . Ii1I * iII111i
 if 48 - 48: I11i * iIii1I11I1II1 / oO0o
 if 34 - 34: i1IIi + oO0o * Oo0Ooo * I1Ii111 % OoooooooOO % ooOoO0o
 if 17 - 17: I1ii11iIi11i + o0oOOo0O0Ooo / OoO0O00 . Oo0Ooo - o0oOOo0O0Ooo / oO0o
 if 87 - 87: ooOoO0o
 if 74 - 74: i11iIiiIii . i11iIiiIii . iIii1I11I1II1
def lisp_process_map_register ( lisp_sockets , packet , source , sport ) :
 global lisp_registered_count
 if 100 - 100: i11iIiiIii - oO0o + iIii1I11I1II1 * OoOoOO00 % OOooOOo % i11iIiiIii
 if 26 - 26: O0
 if 97 - 97: OOooOOo + I11i % I1Ii111 % i11iIiiIii / I1ii11iIi11i
 if 21 - 21: O0 + iIii1I11I1II1 / i11iIiiIii . OOooOOo * i1IIi
 if 3 - 3: i1IIi % o0oOOo0O0Ooo + OoOoOO00
 if 32 - 32: OoO0O00 . Oo0Ooo * iIii1I11I1II1
 packet = lisp_decrypt_map_register ( packet )
 if ( packet == None ) : return
 if 12 - 12: O0 + I1ii11iIi11i + I11i . I1Ii111
 I1 = lisp_map_register ( )
 OoO , packet = I1 . decode ( packet )
 if ( packet == None ) :
  lprint ( "Could not decode Map-Register packet" )
  return
  if 54 - 54: ooOoO0o
 I1 . sport = sport
 if 13 - 13: I11i
 I1 . print_map_register ( )
 if 18 - 18: II111iiii * oO0o % i11iIiiIii / IiII . ooOoO0o
 if 2 - 2: OoOoOO00 % I1Ii111
 if 35 - 35: OOooOOo
 if 50 - 50: iIii1I11I1II1 . I1IiiI + i11iIiiIii
 o0ooO0oO0o0 = True
 if ( I1 . auth_len == LISP_SHA1_160_AUTH_DATA_LEN ) :
  o0ooO0oO0o0 = True
  if 24 - 24: OOooOOo . I1Ii111
 if ( I1 . alg_id == LISP_SHA_256_128_ALG_ID ) :
  o0ooO0oO0o0 = False
  if 59 - 59: Ii1I - I1ii11iIi11i % Ii1I . iII111i
  if 78 - 78: I1ii11iIi11i
  if 69 - 69: iII111i
  if 87 - 87: ooOoO0o % OOooOOo - iII111i
  if 65 - 65: IiII + I1IiiI % I1Ii111 - oO0o
 o00oII1I111 = [ ]
 if 55 - 55: O0 . I1ii11iIi11i % OOooOOo % iII111i + I11i / OoOoOO00
 if 50 - 50: OoOoOO00 - i11iIiiIii - OOooOOo . iIii1I11I1II1
 if 97 - 97: oO0o % OOooOOo . OoooooooOO * Ii1I
 if 100 - 100: I1ii11iIi11i / Ii1I % Oo0Ooo
 oo0O00O0O0O00Ooo = None
 OoI11II1iIi = packet
 oOOO0OOo = [ ]
 I1Ii11 = I1 . record_count
 for IiIIi1IiiIiI in range ( I1Ii11 ) :
  o0O0o = lisp_eid_record ( )
  oo0OOOO0O0o = lisp_rloc_record ( )
  packet = o0O0o . decode ( packet )
  if ( packet == None ) :
   lprint ( "Could not decode EID-record in Map-Register packet" )
   return
   if 72 - 72: i11iIiiIii - iII111i . i11iIiiIii
  o0O0o . print_record ( "  " , False )
  if 61 - 61: oO0o . i11iIiiIii / Ii1I % iII111i
  if 36 - 36: OoO0O00 + Ii1I / I11i - iII111i % OoO0O00 / Oo0Ooo
  if 38 - 38: Ii1I - ooOoO0o - O0 + oO0o . iIii1I11I1II1
  if 90 - 90: i1IIi * OoOoOO00
  I11111Ii = lisp_site_eid_lookup ( o0O0o . eid , o0O0o . group ,
 False )
  if 27 - 27: iIii1I11I1II1
  o0000 = I11111Ii . print_eid_tuple ( ) if I11111Ii else None
  if 44 - 44: OOooOOo . OOooOOo
  if 5 - 5: oO0o + OoooooooOO
  if 88 - 88: oO0o + OOooOOo
  if 14 - 14: I11i / i1IIi
  if 56 - 56: OoooooooOO
  if 59 - 59: I1ii11iIi11i + OoO0O00
  if 37 - 37: IiII * I1IiiI % O0
  if ( I11111Ii and I11111Ii . accept_more_specifics == False ) :
   if ( I11111Ii . eid_record_matches ( o0O0o ) == False ) :
    i1iIiiiiI1 = I11111Ii . parent_for_more_specifics
    if ( i1iIiiiiI1 ) : I11111Ii = i1iIiiiiI1
    if 72 - 72: IiII - iIii1I11I1II1
    if 25 - 25: IiII
    if 51 - 51: O0 / i11iIiiIii % i11iIiiIii % OoOoOO00 + iII111i - Oo0Ooo
    if 89 - 89: OoOoOO00 - I1IiiI + IiII
    if 5 - 5: I11i - I11i
    if 89 - 89: oO0o + OoooooooOO . iII111i + OoO0O00 + i11iIiiIii
    if 27 - 27: i11iIiiIii * i11iIiiIii % o0oOOo0O0Ooo * I1IiiI
    if 80 - 80: iIii1I11I1II1 / o0oOOo0O0Ooo . I1IiiI
  O0O000OooOoo = ( I11111Ii and I11111Ii . accept_more_specifics )
  if ( O0O000OooOoo ) :
   iiIii1i = lisp_site_eid ( I11111Ii . site )
   iiIii1i . dynamic = True
   iiIii1i . eid . copy_address ( o0O0o . eid )
   iiIii1i . group . copy_address ( o0O0o . group )
   iiIii1i . parent_for_more_specifics = I11111Ii
   iiIii1i . add_cache ( )
   iiIii1i . inherit_from_ams_parent ( )
   I11111Ii . more_specific_registrations . append ( iiIii1i )
   I11111Ii = iiIii1i
  else :
   I11111Ii = lisp_site_eid_lookup ( o0O0o . eid , o0O0o . group ,
 True )
   if 68 - 68: Ii1I / oO0o - iII111i
   if 52 - 52: I11i / OoO0O00 - Ii1I
  I11i11i1 = o0O0o . print_eid_tuple ( )
  if 11 - 11: OoooooooOO - i11iIiiIii - I1ii11iIi11i / o0oOOo0O0Ooo - Ii1I
  if ( I11111Ii == None ) :
   I1Ii1i1 = bold ( "Site not found" , False )
   lprint ( "  {} for EID {}{}" . format ( I1Ii1i1 , green ( I11i11i1 , False ) ,
 ", matched non-ams {}" . format ( green ( o0000 , False ) if o0000 else "" ) ) )
   if 16 - 16: ooOoO0o + O0
   if 7 - 7: iIii1I11I1II1 * OoOoOO00 % iII111i % OoO0O00 * Oo0Ooo . IiII
   if 88 - 88: o0oOOo0O0Ooo - I1IiiI . iII111i % Oo0Ooo
   if 14 - 14: I1IiiI - I1Ii111 % I1IiiI - II111iiii
   if 34 - 34: I1ii11iIi11i * IiII / II111iiii / ooOoO0o * oO0o
   packet = oo0OOOO0O0o . end_of_rlocs ( packet , o0O0o . rloc_count )
   if ( packet == None ) :
    lprint ( "  Could not decode RLOC-record in Map-Register packet" )
    return
    if 3 - 3: II111iiii
   continue
   if 61 - 61: oO0o . I1IiiI + i1IIi
   if 69 - 69: O0 / i1IIi - OoOoOO00 + ooOoO0o - oO0o
  oo0O00O0O0O00Ooo = I11111Ii . site
  if 80 - 80: o0oOOo0O0Ooo % O0 * I11i . i1IIi - ooOoO0o
  if ( O0O000OooOoo ) :
   oOo = I11111Ii . parent_for_more_specifics . print_eid_tuple ( )
   lprint ( "  Found ams {} for site '{}' for registering prefix {}" . format ( green ( oOo , False ) , oo0O00O0O0O00Ooo . site_name , green ( I11i11i1 , False ) ) )
   if 93 - 93: OoooooooOO / o0oOOo0O0Ooo
  else :
   oOo = green ( I11111Ii . print_eid_tuple ( ) , False )
   lprint ( "  Found {} for site '{}' for registering prefix {}" . format ( oOo , oo0O00O0O0O00Ooo . site_name , green ( I11i11i1 , False ) ) )
   if 61 - 61: II111iiii / i1IIi . I1ii11iIi11i % iIii1I11I1II1
   if 66 - 66: iIii1I11I1II1 % OoOoOO00 + i1IIi * i11iIiiIii * OoooooooOO
   if 36 - 36: iII111i - OoO0O00 + I1IiiI + Ii1I . OoooooooOO
   if 75 - 75: oO0o * Oo0Ooo * O0
   if 22 - 22: ooOoO0o / OoooooooOO . II111iiii / Ii1I * OoO0O00 . i1IIi
   if 62 - 62: oO0o % Ii1I - Ii1I
  if ( oo0O00O0O0O00Ooo . shutdown ) :
   lprint ( ( "  Rejecting registration for site '{}', configured in " +
 "admin-shutdown state" ) . format ( oo0O00O0O0O00Ooo . site_name ) )
   packet = oo0OOOO0O0o . end_of_rlocs ( packet , o0O0o . rloc_count )
   continue
   if 16 - 16: OoO0O00 - O0 - OOooOOo - I11i % OoOoOO00
   if 7 - 7: I1Ii111 / OoOoOO00 . II111iiii
   if 9 - 9: I11i . I11i . OoooooooOO
   if 42 - 42: iII111i / oO0o / iII111i * OoO0O00
   if 25 - 25: OoOoOO00 - II111iiii + II111iiii . Ii1I * II111iiii
   if 12 - 12: IiII / Ii1I
   if 54 - 54: Oo0Ooo + Ii1I % OoooooooOO * OOooOOo / OoOoOO00
   if 39 - 39: I1IiiI % i11iIiiIii % Ii1I
  I1I1I1 = I1 . key_id
  if ( oo0O00O0O0O00Ooo . auth_key . has_key ( I1I1I1 ) ) :
   O0oOOoOo0oo = oo0O00O0O0O00Ooo . auth_key [ I1I1I1 ]
  else :
   O0oOOoOo0oo = ""
   if 58 - 58: IiII / Oo0Ooo + o0oOOo0O0Ooo
   if 71 - 71: Ii1I - IiII
  II11iIiiI1 = lisp_verify_auth ( OoO , I1 . alg_id ,
 I1 . auth_data , O0oOOoOo0oo )
  I1I1iII = "dynamic " if I11111Ii . dynamic else ""
  if 27 - 27: iII111i
  O0o = bold ( "passed" if II11iIiiI1 else "failed" , False )
  I1I1I1 = "key-id {}" . format ( I1I1I1 ) if I1I1I1 == I1 . key_id else "bad key-id {}" . format ( I1 . key_id )
  if 62 - 62: i1IIi * II111iiii / iII111i * O0
  lprint ( "  Authentication {} for {}EID-prefix {}, {}" . format ( O0o , I1I1iII , green ( I11i11i1 , False ) , I1I1I1 ) )
  if 62 - 62: IiII / I1IiiI % o0oOOo0O0Ooo + IiII % ooOoO0o - oO0o
  if 5 - 5: IiII + I1Ii111 * OoooooooOO / OoOoOO00 + iIii1I11I1II1
  if 45 - 45: I1Ii111 + IiII . iIii1I11I1II1
  if 89 - 89: I11i
  if 22 - 22: i1IIi * OoOoOO00 - i11iIiiIii . i1IIi - OOooOOo . iIii1I11I1II1
  if 43 - 43: OoO0O00 % OOooOOo / I11i + I1ii11iIi11i - OoOoOO00 % I1Ii111
  IiI1IiII = True
  O0OOOOO = ( lisp_get_eid_hash ( o0O0o . eid ) != None )
  if ( O0OOOOO or I11111Ii . require_signature ) :
   oOO = "Required " if I11111Ii . require_signature else ""
   I11i11i1 = green ( I11i11i1 , False )
   I1IIiIIIii = lisp_find_sig_in_rloc_set ( packet , o0O0o . rloc_count )
   if ( I1IIiIIIii == None ) :
    IiI1IiII = False
    lprint ( ( "  {}EID-crypto-hash signature verification {} " + "for EID-prefix {}, no signature found" ) . format ( oOO ,
    # ooOoO0o * I1ii11iIi11i
 bold ( "failed" , False ) , I11i11i1 ) )
   else :
    IiI1IiII = lisp_verify_cga_sig ( o0O0o . eid , I1IIiIIIii )
    O0o = bold ( "passed" if IiI1IiII else "failed" , False )
    lprint ( ( "  {}EID-crypto-hash signature verification {} " + "for EID-prefix {}" ) . format ( oOO , O0o , I11i11i1 ) )
    if 6 - 6: OoooooooOO % i1IIi % II111iiii + ooOoO0o / IiII + Ii1I
    if 97 - 97: ooOoO0o / I1Ii111 * I1ii11iIi11i
    if 83 - 83: Ii1I + ooOoO0o
    if 46 - 46: OoOoOO00
  if ( II11iIiiI1 == False or IiI1IiII == False ) :
   packet = oo0OOOO0O0o . end_of_rlocs ( packet , o0O0o . rloc_count )
   if ( packet == None ) :
    lprint ( "  Could not decode RLOC-record in Map-Register packet" )
    return
    if 66 - 66: iII111i - O0 . I1Ii111 * i1IIi / OoO0O00 / II111iiii
   continue
   if 35 - 35: ooOoO0o * OOooOOo / I11i % I11i / OoooooooOO . I1Ii111
   if 70 - 70: I1ii11iIi11i % I1ii11iIi11i / oO0o
   if 85 - 85: OoOoOO00 % I11i / Oo0Ooo + I11i - Oo0Ooo
   if 20 - 20: IiII
   if 81 - 81: Oo0Ooo / I1Ii111
   if 20 - 20: o0oOOo0O0Ooo + ooOoO0o % i1IIi
  if ( I1 . merge_register_requested ) :
   i1iIiiiiI1 = I11111Ii
   i1iIiiiiI1 . inconsistent_registration = False
   if 51 - 51: iII111i - ooOoO0o
   if 32 - 32: IiII - i11iIiiIii
   if 41 - 41: Ii1I % Ii1I * oO0o - I11i + iIii1I11I1II1 . ooOoO0o
   if 30 - 30: Ii1I * iII111i . II111iiii / i1IIi
   if 77 - 77: oO0o . IiII + I1ii11iIi11i . i1IIi
   if ( I11111Ii . group . is_null ( ) ) :
    if ( i1iIiiiiI1 . site_id != I1 . site_id ) :
     i1iIiiiiI1 . site_id = I1 . site_id
     i1iIiiiiI1 . registered = False
     i1iIiiiiI1 . individual_registrations = { }
     i1iIiiiiI1 . registered_rlocs = [ ]
     lisp_registered_count -= 1
     if 49 - 49: I1Ii111 . OoooooooOO / o0oOOo0O0Ooo - iII111i - iII111i - i11iIiiIii
     if 37 - 37: OOooOOo
     if 79 - 79: I1Ii111 - OoO0O00 + ooOoO0o + oO0o . i11iIiiIii + i1IIi
   Oo000O000 = source . address + I1 . xtr_id
   if ( I11111Ii . individual_registrations . has_key ( Oo000O000 ) ) :
    I11111Ii = I11111Ii . individual_registrations [ Oo000O000 ]
   else :
    I11111Ii = lisp_site_eid ( oo0O00O0O0O00Ooo )
    I11111Ii . eid . copy_address ( i1iIiiiiI1 . eid )
    I11111Ii . group . copy_address ( i1iIiiiiI1 . group )
    i1iIiiiiI1 . individual_registrations [ Oo000O000 ] = I11111Ii
    if 32 - 32: IiII . ooOoO0o / OoO0O00 / iII111i . iIii1I11I1II1 % IiII
  else :
   I11111Ii . inconsistent_registration = I11111Ii . merge_register_requested
   if 28 - 28: I1Ii111 + OoooooooOO + IiII . ooOoO0o . I1IiiI / oO0o
   if 66 - 66: Ii1I - I11i + Oo0Ooo . ooOoO0o
   if 89 - 89: IiII . II111iiii / OoO0O00 + I1ii11iIi11i * i11iIiiIii
  I11111Ii . map_registers_received += 1
  if 85 - 85: o0oOOo0O0Ooo - Oo0Ooo / I1Ii111
  if 100 - 100: OoO0O00 * iIii1I11I1II1 - IiII . i1IIi % i11iIiiIii % Oo0Ooo
  if 22 - 22: ooOoO0o - OOooOOo
  if 90 - 90: i11iIiiIii . i11iIiiIii - iIii1I11I1II1
  if 20 - 20: ooOoO0o - i11iIiiIii
  IiiiIi = ( I11111Ii . is_rloc_in_rloc_set ( source ) == False )
  if ( o0O0o . record_ttl == 0 and IiiiIi ) :
   lprint ( "  Ignore deregistration request from {}" . format ( red ( source . print_address_no_iid ( ) , False ) ) )
   if 23 - 23: OoO0O00 + I1IiiI / I1ii11iIi11i * I1ii11iIi11i % ooOoO0o
   continue
   if 83 - 83: I1IiiI * i11iIiiIii - I1ii11iIi11i + I11i
   if 33 - 33: OoO0O00 . OoooooooOO % iII111i / oO0o * Ii1I + ooOoO0o
   if 29 - 29: oO0o
   if 21 - 21: i11iIiiIii . o0oOOo0O0Ooo
   if 78 - 78: Oo0Ooo
   if 77 - 77: oO0o % Oo0Ooo % O0
  O0O0o0ooOo = I11111Ii . registered_rlocs
  I11111Ii . registered_rlocs = [ ]
  if 80 - 80: ooOoO0o - I1Ii111 / oO0o - Ii1I + oO0o
  if 82 - 82: i11iIiiIii / i1IIi + O0 . ooOoO0o
  if 80 - 80: I1IiiI - OOooOOo + OoOoOO00
  if 53 - 53: OoooooooOO . I11i * OOooOOo + i11iIiiIii * O0 . iIii1I11I1II1
  O0II1i11ii = packet
  for I11I1iiI111i1 in range ( o0O0o . rloc_count ) :
   oo0OOOO0O0o = lisp_rloc_record ( )
   packet = oo0OOOO0O0o . decode ( packet , None )
   if ( packet == None ) :
    lprint ( "  Could not decode RLOC-record in Map-Register packet" )
    return
    if 26 - 26: I11i . I1IiiI / IiII / Oo0Ooo % Oo0Ooo / O0
   oo0OOOO0O0o . print_record ( "    " )
   if 27 - 27: I11i - I11i % OoO0O00 - iII111i . OOooOOo - iIii1I11I1II1
   if 15 - 15: OoO0O00 + iIii1I11I1II1
   if 89 - 89: OoooooooOO * Ii1I
   if 4 - 4: Ii1I + OoO0O00 * O0
   if ( len ( oo0O00O0O0O00Ooo . allowed_rlocs ) > 0 ) :
    oo0o00OO = oo0OOOO0O0o . rloc . print_address ( )
    if ( oo0O00O0O0O00Ooo . allowed_rlocs . has_key ( oo0o00OO ) == False ) :
     lprint ( ( "  Reject registration, RLOC {} not " + "configured in allowed RLOC-set" ) . format ( red ( oo0o00OO , False ) ) )
     if 13 - 13: I11i + O0 / oO0o % O0 . I11i
     if 22 - 22: OoOoOO00 . I1IiiI % ooOoO0o + I1Ii111 - OoooooooOO
     I11111Ii . registered = False
     packet = oo0OOOO0O0o . end_of_rlocs ( packet ,
 o0O0o . rloc_count - I11I1iiI111i1 - 1 )
     break
     if 55 - 55: OoooooooOO * O0 - II111iiii / IiII
     if 18 - 18: II111iiii % O0 - o0oOOo0O0Ooo * ooOoO0o
     if 74 - 74: I11i . oO0o + I11i * o0oOOo0O0Ooo / O0
     if 55 - 55: OoO0O00 / i11iIiiIii / o0oOOo0O0Ooo
     if 19 - 19: ooOoO0o * iII111i
     if 38 - 38: ooOoO0o
   I1IIiIIIii = lisp_rloc ( )
   I1IIiIIIii . store_rloc_from_record ( oo0OOOO0O0o , None , source )
   if 35 - 35: o0oOOo0O0Ooo * IiII * Oo0Ooo
   if 34 - 34: I11i - OoooooooOO % i1IIi + I1IiiI
   if 14 - 14: I1IiiI . o0oOOo0O0Ooo / I1Ii111
   if 67 - 67: OoooooooOO . oO0o * OoOoOO00 - OoooooooOO
   if 32 - 32: oO0o
   if 72 - 72: I1IiiI
   if ( source . is_exact_match ( I1IIiIIIii . rloc ) ) :
    I1IIiIIIii . map_notify_requested = I1 . map_notify_requested
    if 34 - 34: ooOoO0o % II111iiii / ooOoO0o
    if 87 - 87: Oo0Ooo
    if 7 - 7: iIii1I11I1II1
    if 85 - 85: iIii1I11I1II1 . O0
    if 43 - 43: II111iiii / OoOoOO00 + OOooOOo % Oo0Ooo * OOooOOo
   I11111Ii . registered_rlocs . append ( I1IIiIIIii )
   if 62 - 62: ooOoO0o * OOooOOo . I11i + Oo0Ooo - I1Ii111
   if 48 - 48: I1Ii111 * Oo0Ooo % OoO0O00 % Ii1I
  iIiI11iII1I = ( I11111Ii . do_rloc_sets_match ( O0O0o0ooOo ) == False )
  if 92 - 92: I1IiiI / Ii1I - iIii1I11I1II1 - O0
  if 15 - 15: iII111i % I11i * ooOoO0o . I1ii11iIi11i + oO0o / I1Ii111
  if 22 - 22: i1IIi % IiII . OoO0O00 * OoO0O00
  if 87 - 87: OOooOOo + OoO0O00 * OoOoOO00 + ooOoO0o . I1ii11iIi11i % IiII
  if 80 - 80: OoOoOO00
  if 91 - 91: I1ii11iIi11i
  if ( I1 . map_register_refresh and iIiI11iII1I and
 I11111Ii . registered ) :
   lprint ( "  Reject registration, refreshes cannot change RLOC-set" )
   I11111Ii . registered_rlocs = O0O0o0ooOo
   continue
   if 92 - 92: Oo0Ooo / OoO0O00 * OoooooooOO
   if 31 - 31: I11i * I1IiiI
   if 80 - 80: I11i * IiII % iII111i + OoOoOO00
   if 56 - 56: OOooOOo . OOooOOo + oO0o
   if 7 - 7: o0oOOo0O0Ooo * II111iiii - I11i . Ii1I % OoooooooOO - I1IiiI
   if 24 - 24: Oo0Ooo / II111iiii * Oo0Ooo - ooOoO0o
  if ( I11111Ii . registered == False ) :
   I11111Ii . first_registered = lisp_get_timestamp ( )
   lisp_registered_count += 1
   if 46 - 46: o0oOOo0O0Ooo
  I11111Ii . last_registered = lisp_get_timestamp ( )
  I11111Ii . registered = ( o0O0o . record_ttl != 0 )
  I11111Ii . last_registerer = source
  if 41 - 41: I11i % II111iiii - II111iiii + OoO0O00
  if 98 - 98: iIii1I11I1II1 + OOooOOo * oO0o / o0oOOo0O0Ooo . iII111i
  if 52 - 52: IiII + iIii1I11I1II1
  if 22 - 22: IiII - OOooOOo + I1ii11iIi11i
  I11111Ii . auth_sha1_or_sha2 = o0ooO0oO0o0
  I11111Ii . proxy_reply_requested = I1 . proxy_reply_requested
  I11111Ii . lisp_sec_present = I1 . lisp_sec_present
  I11111Ii . map_notify_requested = I1 . map_notify_requested
  I11111Ii . mobile_node_requested = I1 . mobile_node
  I11111Ii . merge_register_requested = I1 . merge_register_requested
  if 64 - 64: OoOoOO00
  I11111Ii . use_register_ttl_requested = I1 . use_ttl_for_timeout
  if ( I11111Ii . use_register_ttl_requested ) :
   I11111Ii . register_ttl = o0O0o . store_ttl ( )
  else :
   I11111Ii . register_ttl = LISP_SITE_TIMEOUT_CHECK_INTERVAL * 3
   if 79 - 79: IiII
  I11111Ii . xtr_id_present = I1 . xtr_id_present
  if ( I11111Ii . xtr_id_present ) :
   I11111Ii . xtr_id = I1 . xtr_id
   I11111Ii . site_id = I1 . site_id
   if 65 - 65: Oo0Ooo - i11iIiiIii * OoOoOO00 . I1Ii111 . iIii1I11I1II1
   if 48 - 48: iIii1I11I1II1 - oO0o / OoO0O00 + O0 . Ii1I + I1Ii111
   if 17 - 17: OoOoOO00 . Oo0Ooo - I1Ii111 / I1Ii111 + I11i % i1IIi
   if 31 - 31: OoooooooOO . O0 / OoO0O00 . I1Ii111
   if 41 - 41: OoooooooOO + iII111i . OOooOOo
  if ( I1 . merge_register_requested ) :
   if ( i1iIiiiiI1 . merge_in_site_eid ( I11111Ii ) ) :
    o00oII1I111 . append ( [ o0O0o . eid , o0O0o . group ] )
    if 73 - 73: oO0o + i1IIi + i11iIiiIii / I1ii11iIi11i
   if ( I1 . map_notify_requested ) :
    lisp_send_merged_map_notify ( lisp_sockets , i1iIiiiiI1 , I1 ,
 o0O0o )
    if 100 - 100: I1IiiI % ooOoO0o % OoooooooOO / i11iIiiIii + i11iIiiIii % IiII
    if 39 - 39: Ii1I % o0oOOo0O0Ooo + OOooOOo / iIii1I11I1II1
    if 40 - 40: iIii1I11I1II1 / iII111i % OOooOOo % i11iIiiIii
  if ( iIiI11iII1I == False ) : continue
  if ( len ( o00oII1I111 ) != 0 ) : continue
  if 57 - 57: II111iiii % OoO0O00 * i1IIi
  oOOO0OOo . append ( I11111Ii . print_eid_tuple ( ) )
  if 19 - 19: ooOoO0o . iIii1I11I1II1 + I1ii11iIi11i + I1ii11iIi11i / o0oOOo0O0Ooo . Oo0Ooo
  if 9 - 9: II111iiii % OoooooooOO
  if 4 - 4: i1IIi * i11iIiiIii % OoooooooOO + OoOoOO00 . oO0o
  if 95 - 95: I1ii11iIi11i * OoOoOO00 % o0oOOo0O0Ooo / O0 + ooOoO0o % OOooOOo
  if 48 - 48: i1IIi + IiII - iIii1I11I1II1 . i11iIiiIii % OOooOOo + I1ii11iIi11i
  if 95 - 95: ooOoO0o + OoOoOO00 . II111iiii + Ii1I
  if 81 - 81: OoooooooOO / OOooOOo / Oo0Ooo
  o0O0o = o0O0o . encode ( )
  o0O0o += O0II1i11ii
  o000000oOooO = [ I11111Ii . print_eid_tuple ( ) ]
  lprint ( "    Changed RLOC-set, Map-Notifying old RLOC-set" )
  if 26 - 26: iII111i
  for I1IIiIIIii in O0O0o0ooOo :
   if ( I1IIiIIIii . map_notify_requested == False ) : continue
   if ( I1IIiIIIii . rloc . is_exact_match ( source ) ) : continue
   lisp_build_map_notify ( lisp_sockets , o0O0o , o000000oOooO , 1 , I1IIiIIIii . rloc ,
 LISP_CTRL_PORT , I1 . nonce , I1 . key_id ,
 I1 . alg_id , I1 . auth_len , oo0O00O0O0O00Ooo , False )
   if 93 - 93: Oo0Ooo + I1IiiI % OoOoOO00 / OOooOOo / I1ii11iIi11i
   if 6 - 6: IiII
   if 68 - 68: Oo0Ooo
   if 83 - 83: OOooOOo / iIii1I11I1II1 . OoO0O00 - oO0o % Oo0Ooo
   if 30 - 30: Ii1I . OoOoOO00 / oO0o . OoO0O00
  lisp_notify_subscribers ( lisp_sockets , o0O0o , I11111Ii . eid , oo0O00O0O0O00Ooo )
  if 93 - 93: i11iIiiIii
  if 33 - 33: i1IIi % OoooooooOO + Oo0Ooo % I1IiiI / ooOoO0o
  if 40 - 40: IiII % IiII
  if 9 - 9: I1IiiI * i1IIi + OOooOOo * OoOoOO00
  if 8 - 8: iII111i
 if ( len ( o00oII1I111 ) != 0 ) :
  lisp_queue_multicast_map_notify ( lisp_sockets , o00oII1I111 )
  if 51 - 51: I1IiiI
  if 72 - 72: ooOoO0o / I1ii11iIi11i . Ii1I * iII111i . iIii1I11I1II1
  if 35 - 35: OoO0O00 . OoOoOO00 % O0 * OoO0O00
  if 68 - 68: OOooOOo
  if 87 - 87: IiII * IiII - OoO0O00 / I1ii11iIi11i + OOooOOo / i11iIiiIii
  if 21 - 21: o0oOOo0O0Ooo / oO0o + oO0o + Oo0Ooo / o0oOOo0O0Ooo
 if ( I1 . merge_register_requested ) : return
 if 39 - 39: i11iIiiIii - OoO0O00 - i11iIiiIii / OoooooooOO
 if 15 - 15: i1IIi . iII111i + IiII / I1ii11iIi11i - i1IIi / iII111i
 if 27 - 27: OoOoOO00 / OoooooooOO + i1IIi % iIii1I11I1II1 / OoO0O00
 if 73 - 73: I1ii11iIi11i / OoOoOO00 / IiII + oO0o
 if 73 - 73: I11i * o0oOOo0O0Ooo * I1IiiI . OoooooooOO % I1Ii111
 if ( I1 . map_notify_requested and oo0O00O0O0O00Ooo != None ) :
  lisp_build_map_notify ( lisp_sockets , OoI11II1iIi , oOOO0OOo ,
 I1 . record_count , source , sport , I1 . nonce ,
 I1 . key_id , I1 . alg_id , I1 . auth_len ,
 oo0O00O0O0O00Ooo , True )
  if 9 - 9: oO0o % I1Ii111 . O0 + I1ii11iIi11i - Ii1I - I1ii11iIi11i
 return
 if 57 - 57: i11iIiiIii
 if 21 - 21: iIii1I11I1II1 / I1IiiI / iII111i
 if 19 - 19: Oo0Ooo / iIii1I11I1II1 / I11i
 if 71 - 71: iIii1I11I1II1 * I1IiiI
 if 35 - 35: O0
 if 10 - 10: Ii1I - I1Ii111 / Oo0Ooo + O0
 if 67 - 67: Ii1I % i11iIiiIii . Oo0Ooo
 if 78 - 78: I1IiiI - iIii1I11I1II1
 if 20 - 20: i11iIiiIii % I1IiiI % OoOoOO00
 if 85 - 85: I11i + OoOoOO00 * O0 * O0
def lisp_process_multicast_map_notify ( packet , source ) :
 Ii1ii1 = lisp_map_notify ( "" )
 packet = Ii1ii1 . decode ( packet )
 if ( packet == None ) :
  lprint ( "Could not decode Map-Notify packet" )
  return
  if 92 - 92: i11iIiiIii
  if 16 - 16: I11i . ooOoO0o - Oo0Ooo / OoO0O00 . i1IIi
 Ii1ii1 . print_notify ( )
 if ( Ii1ii1 . record_count == 0 ) : return
 if 59 - 59: ooOoO0o - ooOoO0o % I11i + OoO0O00
 o0o0O0OO0 = Ii1ii1 . eid_records
 if 14 - 14: I1ii11iIi11i * Ii1I - OOooOOo
 for IiIIi1IiiIiI in range ( Ii1ii1 . record_count ) :
  o0O0o = lisp_eid_record ( )
  o0o0O0OO0 = o0O0o . decode ( o0o0O0OO0 )
  if ( packet == None ) : return
  o0O0o . print_record ( "  " , False )
  if 85 - 85: I11i - OoooooooOO
  if 68 - 68: iIii1I11I1II1 / OoO0O00 + OoOoOO00 . I11i % OoooooooOO / O0
  if 19 - 19: iIii1I11I1II1 * I11i
  if 60 - 60: O0 * iII111i % I1ii11iIi11i
  iiI1iIi1II1ii = lisp_map_cache_lookup ( o0O0o . eid , o0O0o . group )
  if ( iiI1iIi1II1ii == None ) :
   oOoOoOo0 , O0O , IIIi1i1iIIIi = lisp_allow_gleaning ( o0O0o . eid , o0O0o . group ,
 None )
   if ( oOoOoOo0 == False ) : continue
   if 24 - 24: I1IiiI . I1IiiI % ooOoO0o
   iiI1iIi1II1ii = lisp_mapping ( o0O0o . eid , o0O0o . group , [ ] )
   iiI1iIi1II1ii . add_cache ( )
   if 32 - 32: OOooOOo / i1IIi / OOooOOo
   if 97 - 97: ooOoO0o * Oo0Ooo * OoooooooOO * I1IiiI
   if 45 - 45: Oo0Ooo
   if 27 - 27: oO0o / IiII - iIii1I11I1II1 / o0oOOo0O0Ooo % OOooOOo * iIii1I11I1II1
   if 40 - 40: oO0o - II111iiii * OOooOOo % OoooooooOO
   if 52 - 52: OOooOOo + OoO0O00
   if 96 - 96: OOooOOo % O0 - Oo0Ooo % oO0o / I1IiiI . i1IIi
  if ( iiI1iIi1II1ii . gleaned ) :
   lprint ( "Ignore Map-Notify for gleaned {}" . format ( green ( iiI1iIi1II1ii . print_eid_tuple ( ) , False ) ) )
   if 42 - 42: i1IIi
   continue
   if 52 - 52: OoO0O00 % iII111i % O0
   if 11 - 11: i1IIi / i11iIiiIii + Ii1I % Oo0Ooo % O0
  iiI1iIi1II1ii . mapping_source = None if source == "lisp-etr" else source
  iiI1iIi1II1ii . map_cache_ttl = o0O0o . store_ttl ( )
  if 50 - 50: oO0o . I1Ii111
  if 38 - 38: iIii1I11I1II1 . Ii1I
  if 82 - 82: OOooOOo * Ii1I + I1ii11iIi11i . OoO0O00
  if 15 - 15: O0
  if 44 - 44: Ii1I . Oo0Ooo . I1Ii111 + oO0o
  if ( len ( iiI1iIi1II1ii . rloc_set ) != 0 and o0O0o . rloc_count == 0 ) :
   iiI1iIi1II1ii . rloc_set = [ ]
   iiI1iIi1II1ii . build_best_rloc_set ( )
   lisp_write_ipc_map_cache ( True , iiI1iIi1II1ii )
   lprint ( "Update {} map-cache entry with no RLOC-set" . format ( green ( iiI1iIi1II1ii . print_eid_tuple ( ) , False ) ) )
   if 32 - 32: OOooOOo - II111iiii + IiII * iIii1I11I1II1 - Oo0Ooo
   continue
   if 25 - 25: ooOoO0o
   if 33 - 33: Oo0Ooo
  iI11iII1Ii = iiI1iIi1II1ii . rtrs_in_rloc_set ( )
  if 45 - 45: I1ii11iIi11i - iIii1I11I1II1 . Ii1I * Oo0Ooo - OoO0O00
  if 74 - 74: I1IiiI / o0oOOo0O0Ooo
  if 53 - 53: iIii1I11I1II1 * oO0o
  if 43 - 43: IiII * Oo0Ooo / OOooOOo % oO0o
  if 11 - 11: OoOoOO00 * Oo0Ooo / I11i * OOooOOo
  for I11I1iiI111i1 in range ( o0O0o . rloc_count ) :
   oo0OOOO0O0o = lisp_rloc_record ( )
   o0o0O0OO0 = oo0OOOO0O0o . decode ( o0o0O0OO0 , None )
   oo0OOOO0O0o . print_record ( "    " )
   if ( o0O0o . group . is_null ( ) ) : continue
   if ( oo0OOOO0O0o . rle == None ) : continue
   if 15 - 15: ooOoO0o - OOooOOo / OoooooooOO
   if 41 - 41: OoOoOO00 . iII111i . i1IIi + oO0o
   if 60 - 60: oO0o * I1Ii111
   if 81 - 81: oO0o - OOooOOo - oO0o
   if 54 - 54: oO0o % I11i
   OOoO0 = iiI1iIi1II1ii . rloc_set [ 0 ] . stats if len ( iiI1iIi1II1ii . rloc_set ) != 0 else None
   if 77 - 77: I1IiiI / I1ii11iIi11i
   if 12 - 12: O0
   if 26 - 26: i11iIiiIii * iII111i + I1Ii111 . ooOoO0o - OoOoOO00
   if 4 - 4: Ii1I
   I1IIiIIIii = lisp_rloc ( )
   I1IIiIIIii . store_rloc_from_record ( oo0OOOO0O0o , None , iiI1iIi1II1ii . mapping_source )
   if ( OOoO0 != None ) : I1IIiIIIii . stats = copy . deepcopy ( OOoO0 )
   if 16 - 16: OOooOOo + Ii1I * II111iiii / Oo0Ooo + iII111i
   if ( iI11iII1Ii and I1IIiIIIii . is_rtr ( ) == False ) : continue
   if 82 - 82: OoOoOO00
   iiI1iIi1II1ii . rloc_set = [ I1IIiIIIii ]
   iiI1iIi1II1ii . build_best_rloc_set ( )
   lisp_write_ipc_map_cache ( True , iiI1iIi1II1ii )
   if 97 - 97: oO0o - OOooOOo / i11iIiiIii . Oo0Ooo % I1Ii111 % oO0o
   lprint ( "Update {} map-cache entry with RLE {}" . format ( green ( iiI1iIi1II1ii . print_eid_tuple ( ) , False ) ,
   # iII111i + ooOoO0o
 I1IIiIIIii . rle . print_rle ( False , True ) ) )
   if 29 - 29: I11i . I11i / i11iIiiIii . OoooooooOO . O0
   if 15 - 15: i1IIi % i11iIiiIii
 return
 if 18 - 18: Ii1I . OoO0O00 . iII111i * oO0o + O0
 if 35 - 35: OoOoOO00 . oO0o / II111iiii
 if 97 - 97: Ii1I + I1Ii111 / II111iiii
 if 14 - 14: iII111i / IiII / oO0o
 if 55 - 55: OoO0O00 % O0
 if 92 - 92: OoooooooOO / O0
 if 14 - 14: i11iIiiIii
 if 43 - 43: OOooOOo
def lisp_process_map_notify ( lisp_sockets , orig_packet , source ) :
 Ii1ii1 = lisp_map_notify ( "" )
 IiiiIi1iiii11 = Ii1ii1 . decode ( orig_packet )
 if ( IiiiIi1iiii11 == None ) :
  lprint ( "Could not decode Map-Notify packet" )
  return
  if 79 - 79: iII111i % Oo0Ooo . i1IIi % ooOoO0o
  if 93 - 93: OoOoOO00
 Ii1ii1 . print_notify ( )
 if 49 - 49: i1IIi * OOooOOo % I11i * Ii1I . I1Ii111 * iIii1I11I1II1
 if 72 - 72: ooOoO0o
 if 63 - 63: Oo0Ooo . OoO0O00 . OoooooooOO / i1IIi
 if 53 - 53: OOooOOo * O0 . iII111i
 if 3 - 3: OoooooooOO * I1Ii111 * IiII - OOooOOo * I1Ii111
 IiII1iiI = source . print_address ( )
 if ( Ii1ii1 . alg_id != 0 or Ii1ii1 . auth_len != 0 ) :
  ii1i = None
  for Oo000O000 in lisp_map_servers_list :
   if ( Oo000O000 . find ( IiII1iiI ) == - 1 ) : continue
   ii1i = lisp_map_servers_list [ Oo000O000 ]
   if 78 - 78: iII111i
  if ( ii1i == None ) :
   lprint ( ( "  Could not find Map-Server {} to authenticate " + "Map-Notify" ) . format ( IiII1iiI ) )
   if 80 - 80: i1IIi * I1IiiI + OOooOOo
   return
   if 91 - 91: I1IiiI % OoOoOO00 * Oo0Ooo / I1ii11iIi11i
   if 57 - 57: i11iIiiIii / o0oOOo0O0Ooo . II111iiii
  ii1i . map_notifies_received += 1
  if 63 - 63: O0
  II11iIiiI1 = lisp_verify_auth ( IiiiIi1iiii11 , Ii1ii1 . alg_id ,
 Ii1ii1 . auth_data , ii1i . password )
  if 64 - 64: i11iIiiIii / oO0o . oO0o - Oo0Ooo
  lprint ( "  Authentication {} for Map-Notify" . format ( "succeeded" if II11iIiiI1 else "failed" ) )
  if 48 - 48: i1IIi + I1ii11iIi11i + I1Ii111 - iII111i
  if ( II11iIiiI1 == False ) : return
 else :
  ii1i = lisp_ms ( IiII1iiI , None , "" , 0 , "" , False , False , False , False , 0 , 0 , 0 ,
 None )
  if 3 - 3: i1IIi + OoooooooOO * ooOoO0o + I1Ii111 % OOooOOo / IiII
  if 70 - 70: oO0o + i1IIi % o0oOOo0O0Ooo - I11i
  if 74 - 74: i11iIiiIii
  if 93 - 93: I1Ii111 % OOooOOo * I1IiiI % iII111i / iIii1I11I1II1 + OoO0O00
  if 6 - 6: I11i
  if 70 - 70: ooOoO0o + OoooooooOO % OoOoOO00 % oO0o / Ii1I . I11i
 o0o0O0OO0 = Ii1ii1 . eid_records
 if ( Ii1ii1 . record_count == 0 ) :
  lisp_send_map_notify_ack ( lisp_sockets , o0o0O0OO0 , Ii1ii1 , ii1i )
  return
  if 63 - 63: I1ii11iIi11i - ooOoO0o . OOooOOo / O0 . iIii1I11I1II1 - Ii1I
  if 6 - 6: Ii1I
  if 60 - 60: iII111i + I1IiiI
  if 36 - 36: i1IIi . O0 . OoO0O00 % OOooOOo * I11i / Ii1I
  if 16 - 16: Oo0Ooo
  if 44 - 44: iIii1I11I1II1 - II111iiii . IiII . i1IIi
  if 37 - 37: OoooooooOO + Oo0Ooo - Oo0Ooo + I1ii11iIi11i . I1Ii111 / I1IiiI
  if 60 - 60: I1IiiI % Ii1I / I1Ii111 + Ii1I
 o0O0o = lisp_eid_record ( )
 IiiiIi1iiii11 = o0O0o . decode ( o0o0O0OO0 )
 if ( IiiiIi1iiii11 == None ) : return
 if 43 - 43: I1ii11iIi11i + I11i
 o0O0o . print_record ( "  " , False )
 if 83 - 83: II111iiii + o0oOOo0O0Ooo - I1Ii111
 for I11I1iiI111i1 in range ( o0O0o . rloc_count ) :
  oo0OOOO0O0o = lisp_rloc_record ( )
  IiiiIi1iiii11 = oo0OOOO0O0o . decode ( IiiiIi1iiii11 , None )
  if ( IiiiIi1iiii11 == None ) :
   lprint ( "  Could not decode RLOC-record in Map-Notify packet" )
   return
   if 100 - 100: IiII - OoOoOO00 / I11i
  oo0OOOO0O0o . print_record ( "    " )
  if 33 - 33: I1Ii111 * OoOoOO00 . I1ii11iIi11i % I1Ii111
  if 87 - 87: Oo0Ooo
  if 65 - 65: ooOoO0o . I1IiiI
  if 51 - 51: IiII
  if 43 - 43: oO0o - I11i . i11iIiiIii
 if ( o0O0o . group . is_null ( ) == False ) :
  if 78 - 78: i11iIiiIii + Oo0Ooo * Ii1I - o0oOOo0O0Ooo % i11iIiiIii
  if 30 - 30: I1IiiI % oO0o * OoooooooOO
  if 64 - 64: I1IiiI
  if 11 - 11: I1ii11iIi11i % iII111i / II111iiii % ooOoO0o % IiII
  if 14 - 14: ooOoO0o / IiII . o0oOOo0O0Ooo
  lprint ( "Send {} Map-Notify IPC message to ITR process" . format ( green ( o0O0o . print_eid_tuple ( ) , False ) ) )
  if 27 - 27: I1IiiI - OOooOOo . II111iiii * I1ii11iIi11i % ooOoO0o / I1IiiI
  if 90 - 90: o0oOOo0O0Ooo / I1ii11iIi11i - oO0o - Ii1I - I1IiiI + I1Ii111
  iiiii1i1 = lisp_control_packet_ipc ( orig_packet , IiII1iiI , "lisp-itr" , 0 )
  lisp_ipc ( iiiii1i1 , lisp_sockets [ 2 ] , "lisp-core-pkt" )
  if 93 - 93: I1IiiI - I11i . I1IiiI - iIii1I11I1II1
  if 1 - 1: O0 . Ii1I % Ii1I + II111iiii . oO0o
  if 24 - 24: o0oOOo0O0Ooo . I1Ii111 % O0
  if 67 - 67: I1IiiI * Ii1I
  if 64 - 64: OOooOOo
 lisp_send_map_notify_ack ( lisp_sockets , o0o0O0OO0 , Ii1ii1 , ii1i )
 return
 if 90 - 90: iII111i . OoOoOO00 + i1IIi % ooOoO0o * I11i + OoooooooOO
 if 2 - 2: o0oOOo0O0Ooo . II111iiii
 if 9 - 9: I1Ii111 - II111iiii + OoOoOO00 . OoO0O00
 if 33 - 33: Oo0Ooo
 if 12 - 12: i11iIiiIii . Oo0Ooo / OoOoOO00 + iII111i . Ii1I + ooOoO0o
 if 66 - 66: IiII
 if 41 - 41: II111iiii + Oo0Ooo / iII111i . IiII / iII111i / I1IiiI
 if 78 - 78: o0oOOo0O0Ooo % OoOoOO00 . O0
def lisp_process_map_notify_ack ( packet , source ) :
 Ii1ii1 = lisp_map_notify ( "" )
 packet = Ii1ii1 . decode ( packet )
 if ( packet == None ) :
  lprint ( "Could not decode Map-Notify-Ack packet" )
  return
  if 41 - 41: iIii1I11I1II1 . OOooOOo - Oo0Ooo % OOooOOo
  if 90 - 90: i11iIiiIii + OoooooooOO - i11iIiiIii + OoooooooOO
 Ii1ii1 . print_notify ( )
 if 23 - 23: i11iIiiIii - IiII - I1ii11iIi11i + I1ii11iIi11i % I1IiiI
 if 79 - 79: II111iiii / OoooooooOO
 if 35 - 35: i1IIi + IiII + II111iiii % OOooOOo
 if 25 - 25: I11i + i11iIiiIii + O0 - Ii1I
 if 69 - 69: I11i . OoOoOO00 / OOooOOo / i1IIi . II111iiii
 if ( Ii1ii1 . record_count < 1 ) :
  lprint ( "No EID-prefix found, cannot authenticate Map-Notify-Ack" )
  return
  if 17 - 17: I1Ii111
  if 2 - 2: O0 % OoOoOO00 + oO0o
 o0O0o = lisp_eid_record ( )
 if 24 - 24: iII111i + iII111i - OoooooooOO % OoooooooOO * O0
 if ( o0O0o . decode ( Ii1ii1 . eid_records ) == None ) :
  lprint ( "Could not decode EID-record, cannot authenticate " +
 "Map-Notify-Ack" )
  return
  if 51 - 51: IiII
 o0O0o . print_record ( "  " , False )
 if 31 - 31: I11i - iIii1I11I1II1 * Ii1I + Ii1I
 I11i11i1 = o0O0o . print_eid_tuple ( )
 if 10 - 10: OoOoOO00 - i11iIiiIii % iIii1I11I1II1 / ooOoO0o * i11iIiiIii - Ii1I
 if 64 - 64: II111iiii . i11iIiiIii . iII111i . OOooOOo
 if 95 - 95: O0 - OoOoOO00
 if 68 - 68: ooOoO0o . I1Ii111
 if ( Ii1ii1 . alg_id != LISP_NONE_ALG_ID and Ii1ii1 . auth_len != 0 ) :
  I11111Ii = lisp_sites_by_eid . lookup_cache ( o0O0o . eid , True )
  if ( I11111Ii == None ) :
   I1Ii1i1 = bold ( "Site not found" , False )
   lprint ( ( "{} for EID {}, cannot authenticate Map-Notify-Ack" ) . format ( I1Ii1i1 , green ( I11i11i1 , False ) ) )
   if 84 - 84: OoooooooOO + oO0o % i1IIi + o0oOOo0O0Ooo * i1IIi
   return
   if 51 - 51: oO0o . OoooooooOO + OOooOOo * I1ii11iIi11i - ooOoO0o
  oo0O00O0O0O00Ooo = I11111Ii . site
  if 41 - 41: Oo0Ooo
  if 46 - 46: i11iIiiIii + iIii1I11I1II1 . i11iIiiIii . iII111i
  if 66 - 66: oO0o % i1IIi % OoooooooOO
  if 58 - 58: OOooOOo
  oo0O00O0O0O00Ooo . map_notify_acks_received += 1
  if 89 - 89: iIii1I11I1II1 - i1IIi
  I1I1I1 = Ii1ii1 . key_id
  if ( oo0O00O0O0O00Ooo . auth_key . has_key ( I1I1I1 ) ) :
   O0oOOoOo0oo = oo0O00O0O0O00Ooo . auth_key [ I1I1I1 ]
  else :
   O0oOOoOo0oo = ""
   if 26 - 26: OOooOOo - iII111i * I1ii11iIi11i / iII111i
   if 9 - 9: I1Ii111 / II111iiii * I1Ii111 / I11i - OoO0O00
  II11iIiiI1 = lisp_verify_auth ( packet , Ii1ii1 . alg_id ,
 Ii1ii1 . auth_data , O0oOOoOo0oo )
  if 36 - 36: IiII . OoOoOO00 . Ii1I
  I1I1I1 = "key-id {}" . format ( I1I1I1 ) if I1I1I1 == Ii1ii1 . key_id else "bad key-id {}" . format ( Ii1ii1 . key_id )
  if 31 - 31: iIii1I11I1II1
  if 84 - 84: I1ii11iIi11i - iII111i * I1IiiI
  lprint ( "  Authentication {} for Map-Notify-Ack, {}" . format ( "succeeded" if II11iIiiI1 else "failed" , I1I1I1 ) )
  if 88 - 88: OOooOOo / Oo0Ooo
  if ( II11iIiiI1 == False ) : return
  if 31 - 31: II111iiii
  if 32 - 32: o0oOOo0O0Ooo % o0oOOo0O0Ooo
  if 67 - 67: IiII + oO0o * IiII
  if 26 - 26: I1ii11iIi11i + i1IIi . i1IIi - oO0o + I1IiiI * o0oOOo0O0Ooo
  if 62 - 62: ooOoO0o + ooOoO0o % I11i
 if ( Ii1ii1 . retransmit_timer ) : Ii1ii1 . retransmit_timer . cancel ( )
 if 100 - 100: II111iiii . OoooooooOO
 ii11Ii11II = source . print_address ( )
 Oo000O000 = Ii1ii1 . nonce_key
 if 32 - 32: I11i % OOooOOo * O0 / iIii1I11I1II1 / i1IIi
 if ( lisp_map_notify_queue . has_key ( Oo000O000 ) ) :
  Ii1ii1 = lisp_map_notify_queue . pop ( Oo000O000 )
  if ( Ii1ii1 . retransmit_timer ) : Ii1ii1 . retransmit_timer . cancel ( )
  lprint ( "Dequeue Map-Notify from retransmit queue, key is: {}" . format ( Oo000O000 ) )
  if 87 - 87: OoO0O00 . I1ii11iIi11i * I1IiiI
 else :
  lprint ( "Map-Notify with nonce 0x{} queue entry not found for {}" . format ( Ii1ii1 . nonce_key , red ( ii11Ii11II , False ) ) )
  if 83 - 83: OOooOOo
  if 86 - 86: I1Ii111 / oO0o
 return
 if 67 - 67: OoOoOO00 + Oo0Ooo / i11iIiiIii . I1IiiI
 if 53 - 53: Oo0Ooo + IiII * ooOoO0o % OoooooooOO * oO0o . iII111i
 if 78 - 78: O0 . Ii1I - I1ii11iIi11i
 if 69 - 69: O0 % O0 . oO0o * OoooooooOO
 if 13 - 13: i1IIi % oO0o . OoooooooOO + I1ii11iIi11i - OOooOOo
 if 99 - 99: OoooooooOO % OOooOOo / I11i
 if 77 - 77: II111iiii - IiII % OOooOOo
 if 22 - 22: OoooooooOO / oO0o
def lisp_map_referral_loop ( mr , eid , group , action , s ) :
 if ( action not in ( LISP_DDT_ACTION_NODE_REFERRAL ,
 LISP_DDT_ACTION_MS_REFERRAL ) ) : return ( False )
 if 78 - 78: oO0o * I11i . i1IIi % i1IIi + i1IIi / OOooOOo
 if ( mr . last_cached_prefix [ 0 ] == None ) : return ( False )
 if 66 - 66: OoooooooOO % o0oOOo0O0Ooo / I11i * I1Ii111
 if 12 - 12: I1Ii111
 if 17 - 17: I1Ii111 % oO0o + O0
 if 15 - 15: o0oOOo0O0Ooo - OoooooooOO % ooOoO0o % oO0o / i11iIiiIii / Oo0Ooo
 oOo0ooOoO = False
 if ( group . is_null ( ) == False ) :
  oOo0ooOoO = mr . last_cached_prefix [ 1 ] . is_more_specific ( group )
  if 59 - 59: iII111i + O0 - I1ii11iIi11i * I1ii11iIi11i + iIii1I11I1II1
 if ( oOo0ooOoO == False ) :
  oOo0ooOoO = mr . last_cached_prefix [ 0 ] . is_more_specific ( eid )
  if 41 - 41: iIii1I11I1II1 . O0 - ooOoO0o / OoOoOO00 % iIii1I11I1II1 + IiII
  if 23 - 23: OoOoOO00 + ooOoO0o . i11iIiiIii
 if ( oOo0ooOoO ) :
  II1OO0Oo0oOOO000 = lisp_print_eid_tuple ( eid , group )
  iIiI1III = lisp_print_eid_tuple ( mr . last_cached_prefix [ 0 ] ,
 mr . last_cached_prefix [ 1 ] )
  if 86 - 86: Ii1I - o0oOOo0O0Ooo % iII111i
  lprint ( ( "Map-Referral prefix {} from {} is not more-specific " + "than cached prefix {}" ) . format ( green ( II1OO0Oo0oOOO000 , False ) , s ,
  # Oo0Ooo . I1Ii111 * iIii1I11I1II1
 iIiI1III ) )
  if 60 - 60: OoooooooOO
 return ( oOo0ooOoO )
 if 41 - 41: iIii1I11I1II1 + O0 % o0oOOo0O0Ooo - IiII . I11i * O0
 if 39 - 39: i11iIiiIii . Ii1I
 if 68 - 68: OOooOOo * ooOoO0o . I1IiiI - iII111i
 if 81 - 81: I11i % Oo0Ooo / iII111i
 if 44 - 44: Oo0Ooo
 if 90 - 90: Oo0Ooo . ooOoO0o / IiII * I1Ii111 . ooOoO0o + II111iiii
 if 43 - 43: iIii1I11I1II1 % OOooOOo + OoOoOO00 + I1ii11iIi11i - Oo0Ooo / Ii1I
def lisp_process_map_referral ( lisp_sockets , packet , source ) :
 if 94 - 94: Ii1I / Oo0Ooo % II111iiii % Oo0Ooo * oO0o
 oO0O = lisp_map_referral ( )
 packet = oO0O . decode ( packet )
 if ( packet == None ) :
  lprint ( "Could not decode Map-Referral packet" )
  return
  if 54 - 54: O0 / ooOoO0o * I1Ii111
 oO0O . print_map_referral ( )
 if 5 - 5: Ii1I / OoOoOO00 - O0 * OoO0O00
 IiII1iiI = source . print_address ( )
 Iii11I = oO0O . nonce
 if 13 - 13: IiII + Oo0Ooo - I1Ii111
 if 10 - 10: OOooOOo % OoooooooOO / I1IiiI . II111iiii % iII111i
 if 47 - 47: o0oOOo0O0Ooo . i11iIiiIii * i1IIi % I11i - ooOoO0o * oO0o
 if 95 - 95: oO0o / Ii1I + OoO0O00
 for IiIIi1IiiIiI in range ( oO0O . record_count ) :
  o0O0o = lisp_eid_record ( )
  packet = o0O0o . decode ( packet )
  if ( packet == None ) :
   lprint ( "Could not decode EID-record in Map-Referral packet" )
   return
   if 57 - 57: iIii1I11I1II1 + I1Ii111 % oO0o - Ii1I . I1IiiI
  o0O0o . print_record ( "  " , True )
  if 39 - 39: OoO0O00 + II111iiii
  if 98 - 98: O0 - I1Ii111 % oO0o - iII111i + Ii1I * i1IIi
  if 76 - 76: o0oOOo0O0Ooo
  if 55 - 55: OOooOOo + I1ii11iIi11i * Oo0Ooo
  Oo000O000 = str ( Iii11I )
  if ( Oo000O000 not in lisp_ddt_map_requestQ ) :
   lprint ( ( "Map-Referral nonce 0x{} from {} not found in " + "Map-Request queue, EID-record ignored" ) . format ( lisp_hex_string ( Iii11I ) , IiII1iiI ) )
   if 11 - 11: i1IIi - OoooooooOO * OoOoOO00 / oO0o - OoooooooOO - I1IiiI
   if 22 - 22: i11iIiiIii . Ii1I . Oo0Ooo * Oo0Ooo - iII111i / I1ii11iIi11i
   continue
   if 49 - 49: iII111i + I11i . Oo0Ooo
  OoOooo0o = lisp_ddt_map_requestQ [ Oo000O000 ]
  if ( OoOooo0o == None ) :
   lprint ( ( "No Map-Request queue entry found for Map-Referral " +
 "nonce 0x{} from {}, EID-record ignored" ) . format ( lisp_hex_string ( Iii11I ) , IiII1iiI ) )
   if 23 - 23: I1IiiI . Ii1I + ooOoO0o . OoooooooOO
   continue
   if 57 - 57: OOooOOo / OoOoOO00 / i11iIiiIii - I11i - I11i . Ii1I
   if 53 - 53: ooOoO0o . iII111i + Ii1I * I1Ii111
   if 49 - 49: II111iiii . I1ii11iIi11i * OoOoOO00 - OOooOOo
   if 48 - 48: OoO0O00 . iIii1I11I1II1 - OoooooooOO + I1Ii111 / i11iIiiIii . Oo0Ooo
   if 61 - 61: II111iiii + OOooOOo . o0oOOo0O0Ooo . iIii1I11I1II1
   if 63 - 63: I11i + i11iIiiIii . o0oOOo0O0Ooo . i1IIi + OoOoOO00
  if ( lisp_map_referral_loop ( OoOooo0o , o0O0o . eid , o0O0o . group ,
 o0O0o . action , IiII1iiI ) ) :
   OoOooo0o . dequeue_map_request ( )
   continue
   if 1 - 1: i11iIiiIii
   if 1 - 1: iIii1I11I1II1
  OoOooo0o . last_cached_prefix [ 0 ] = o0O0o . eid
  OoOooo0o . last_cached_prefix [ 1 ] = o0O0o . group
  if 73 - 73: iII111i + IiII
  if 95 - 95: O0
  if 75 - 75: ooOoO0o
  if 8 - 8: O0 - OoooooooOO + I1ii11iIi11i / Oo0Ooo . oO0o + I1Ii111
  iI1I11II = False
  O00o0oOoO0OOo = lisp_referral_cache_lookup ( o0O0o . eid , o0O0o . group ,
 True )
  if ( O00o0oOoO0OOo == None ) :
   iI1I11II = True
   O00o0oOoO0OOo = lisp_referral ( )
   O00o0oOoO0OOo . eid = o0O0o . eid
   O00o0oOoO0OOo . group = o0O0o . group
   if ( o0O0o . ddt_incomplete == False ) : O00o0oOoO0OOo . add_cache ( )
  elif ( O00o0oOoO0OOo . referral_source . not_set ( ) ) :
   lprint ( "Do not replace static referral entry {}" . format ( green ( O00o0oOoO0OOo . print_eid_tuple ( ) , False ) ) )
   if 85 - 85: ooOoO0o
   OoOooo0o . dequeue_map_request ( )
   continue
   if 29 - 29: iII111i . Ii1I
   if 43 - 43: I11i - I1ii11iIi11i + iIii1I11I1II1 / I1ii11iIi11i * oO0o / iIii1I11I1II1
  I11I1iI = o0O0o . action
  O00o0oOoO0OOo . referral_source = source
  O00o0oOoO0OOo . referral_type = I11I1iI
  oOoooOOO0o0 = o0O0o . store_ttl ( )
  O00o0oOoO0OOo . referral_ttl = oOoooOOO0o0
  O00o0oOoO0OOo . expires = lisp_set_timestamp ( oOoooOOO0o0 )
  if 45 - 45: IiII
  if 49 - 49: I1IiiI . Ii1I * I1IiiI - OoooooooOO . I11i / I1Ii111
  if 9 - 9: iIii1I11I1II1 * Ii1I / O0 - OOooOOo
  if 95 - 95: i11iIiiIii * II111iiii * OOooOOo * iIii1I11I1II1
  IiIi = O00o0oOoO0OOo . is_referral_negative ( )
  if ( O00o0oOoO0OOo . referral_set . has_key ( IiII1iiI ) ) :
   Iii1i1I1 = O00o0oOoO0OOo . referral_set [ IiII1iiI ]
   if 51 - 51: OOooOOo . i11iIiiIii / i11iIiiIii
   if ( Iii1i1I1 . updown == False and IiIi == False ) :
    Iii1i1I1 . updown = True
    lprint ( "Change up/down status for referral-node {} to up" . format ( IiII1iiI ) )
    if 10 - 10: iIii1I11I1II1 % i1IIi
   elif ( Iii1i1I1 . updown == True and IiIi == True ) :
    Iii1i1I1 . updown = False
    lprint ( ( "Change up/down status for referral-node {} " + "to down, received negative referral" ) . format ( IiII1iiI ) )
    if 78 - 78: I11i + II111iiii % o0oOOo0O0Ooo
    if 17 - 17: i11iIiiIii + oO0o * iII111i . II111iiii
    if 44 - 44: I1ii11iIi11i
    if 39 - 39: iII111i + Oo0Ooo / oO0o
    if 95 - 95: I1Ii111 * oO0o / ooOoO0o . Ii1I . OoOoOO00
    if 99 - 99: I1IiiI * II111iiii
    if 84 - 84: II111iiii - I1IiiI
    if 41 - 41: iIii1I11I1II1 % I1Ii111 % OoOoOO00
  i1i1I11 = { }
  for Oo000O000 in O00o0oOoO0OOo . referral_set : i1i1I11 [ Oo000O000 ] = None
  if 15 - 15: OoOoOO00 / ooOoO0o + I11i / iIii1I11I1II1 - IiII
  if 77 - 77: OoO0O00 / oO0o / OoooooooOO - I11i % OoooooooOO
  if 11 - 11: I1IiiI + IiII
  if 97 - 97: i1IIi * ooOoO0o
  for IiIIi1IiiIiI in range ( o0O0o . rloc_count ) :
   oo0OOOO0O0o = lisp_rloc_record ( )
   packet = oo0OOOO0O0o . decode ( packet , None )
   if ( packet == None ) :
    lprint ( "Could not decode RLOC-record in Map-Referral packet" )
    return
    if 18 - 18: i1IIi . I1IiiI % I1IiiI / iII111i + Ii1I * o0oOOo0O0Ooo
   oo0OOOO0O0o . print_record ( "    " )
   if 97 - 97: Ii1I % I1IiiI % iIii1I11I1II1 * Ii1I . i1IIi
   if 70 - 70: i1IIi . oO0o - oO0o . I1Ii111
   if 68 - 68: I1Ii111 . iIii1I11I1II1 * O0
   if 75 - 75: iII111i - Oo0Ooo / OoooooooOO - O0
   oo0o00OO = oo0OOOO0O0o . rloc . print_address ( )
   if ( O00o0oOoO0OOo . referral_set . has_key ( oo0o00OO ) == False ) :
    Iii1i1I1 = lisp_referral_node ( )
    Iii1i1I1 . referral_address . copy_address ( oo0OOOO0O0o . rloc )
    O00o0oOoO0OOo . referral_set [ oo0o00OO ] = Iii1i1I1
    if ( IiII1iiI == oo0o00OO and IiIi ) : Iii1i1I1 . updown = False
   else :
    Iii1i1I1 = O00o0oOoO0OOo . referral_set [ oo0o00OO ]
    if ( i1i1I11 . has_key ( oo0o00OO ) ) : i1i1I11 . pop ( oo0o00OO )
    if 36 - 36: OoO0O00 % Ii1I . Oo0Ooo
   Iii1i1I1 . priority = oo0OOOO0O0o . priority
   Iii1i1I1 . weight = oo0OOOO0O0o . weight
   if 90 - 90: i11iIiiIii - iII111i * oO0o
   if 79 - 79: IiII
   if 38 - 38: I1Ii111
   if 56 - 56: i11iIiiIii
   if 58 - 58: i11iIiiIii / OoOoOO00
  for Oo000O000 in i1i1I11 : O00o0oOoO0OOo . referral_set . pop ( Oo000O000 )
  if 23 - 23: I1IiiI % iIii1I11I1II1 - oO0o - iII111i - o0oOOo0O0Ooo
  I11i11i1 = O00o0oOoO0OOo . print_eid_tuple ( )
  if 39 - 39: Oo0Ooo . OoO0O00
  if ( iI1I11II ) :
   if ( o0O0o . ddt_incomplete ) :
    lprint ( "Suppress add {} to referral-cache" . format ( green ( I11i11i1 , False ) ) )
    if 74 - 74: I1IiiI . O0 . IiII + IiII - IiII
   else :
    lprint ( "Add {}, referral-count {} to referral-cache" . format ( green ( I11i11i1 , False ) , o0O0o . rloc_count ) )
    if 100 - 100: ooOoO0o / OoooooooOO
    if 73 - 73: i11iIiiIii - Oo0Ooo
  else :
   lprint ( "Replace {}, referral-count: {} in referral-cache" . format ( green ( I11i11i1 , False ) , o0O0o . rloc_count ) )
   if 100 - 100: iIii1I11I1II1 + I1Ii111
   if 51 - 51: o0oOOo0O0Ooo * I11i
   if 42 - 42: OOooOOo % I11i
   if 84 - 84: Oo0Ooo * OoOoOO00 / Ii1I / IiII / o0oOOo0O0Ooo . I1ii11iIi11i
   if 81 - 81: I1IiiI
   if 82 - 82: I1Ii111 - OoooooooOO - Ii1I
  if ( I11I1iI == LISP_DDT_ACTION_DELEGATION_HOLE ) :
   lisp_send_negative_map_reply ( OoOooo0o . lisp_sockets , O00o0oOoO0OOo . eid ,
 O00o0oOoO0OOo . group , OoOooo0o . nonce , OoOooo0o . itr , OoOooo0o . sport , 15 , None , False )
   OoOooo0o . dequeue_map_request ( )
   if 34 - 34: OOooOOo . iIii1I11I1II1 / I1IiiI . Oo0Ooo - iIii1I11I1II1
   if 83 - 83: iII111i - I1ii11iIi11i + iII111i
  if ( I11I1iI == LISP_DDT_ACTION_NOT_AUTH ) :
   if ( OoOooo0o . tried_root ) :
    lisp_send_negative_map_reply ( OoOooo0o . lisp_sockets , O00o0oOoO0OOo . eid ,
 O00o0oOoO0OOo . group , OoOooo0o . nonce , OoOooo0o . itr , OoOooo0o . sport , 0 , None , False )
    OoOooo0o . dequeue_map_request ( )
   else :
    lisp_send_ddt_map_request ( OoOooo0o , True )
    if 4 - 4: o0oOOo0O0Ooo % iIii1I11I1II1 + I11i
    if 60 - 60: I1ii11iIi11i / I1Ii111 % i11iIiiIii % oO0o % I1IiiI . Oo0Ooo
    if 20 - 20: IiII - OOooOOo + OoOoOO00
  if ( I11I1iI == LISP_DDT_ACTION_MS_NOT_REG ) :
   if ( O00o0oOoO0OOo . referral_set . has_key ( IiII1iiI ) ) :
    Iii1i1I1 = O00o0oOoO0OOo . referral_set [ IiII1iiI ]
    Iii1i1I1 . updown = False
    if 83 - 83: OoooooooOO / I1IiiI + iII111i - iIii1I11I1II1 % ooOoO0o
   if ( len ( O00o0oOoO0OOo . referral_set ) == 0 ) :
    OoOooo0o . dequeue_map_request ( )
   else :
    lisp_send_ddt_map_request ( OoOooo0o , False )
    if 74 - 74: OoO0O00
    if 13 - 13: I1ii11iIi11i / OoO0O00
    if 90 - 90: iIii1I11I1II1 - OoO0O00 . i1IIi / o0oOOo0O0Ooo + O0
  if ( I11I1iI in ( LISP_DDT_ACTION_NODE_REFERRAL ,
 LISP_DDT_ACTION_MS_REFERRAL ) ) :
   if ( OoOooo0o . eid . is_exact_match ( o0O0o . eid ) ) :
    if ( not OoOooo0o . tried_root ) :
     lisp_send_ddt_map_request ( OoOooo0o , True )
    else :
     lisp_send_negative_map_reply ( OoOooo0o . lisp_sockets ,
 O00o0oOoO0OOo . eid , O00o0oOoO0OOo . group , OoOooo0o . nonce , OoOooo0o . itr ,
 OoOooo0o . sport , 15 , None , False )
     OoOooo0o . dequeue_map_request ( )
     if 94 - 94: IiII * i1IIi
   else :
    lisp_send_ddt_map_request ( OoOooo0o , False )
    if 90 - 90: O0 % I1IiiI . o0oOOo0O0Ooo % ooOoO0o % I1IiiI
    if 16 - 16: OoO0O00 / OOooOOo / iIii1I11I1II1 / OoooooooOO . oO0o - I1Ii111
    if 43 - 43: OoOoOO00 % OOooOOo / I1IiiI + I1IiiI
  if ( I11I1iI == LISP_DDT_ACTION_MS_ACK ) : OoOooo0o . dequeue_map_request ( )
  if 40 - 40: OOooOOo . I1Ii111 + I1Ii111
 return
 if 4 - 4: iIii1I11I1II1 - iIii1I11I1II1 * I11i
 if 32 - 32: I1IiiI + II111iiii * iII111i + O0 / O0 * Oo0Ooo
 if 64 - 64: i11iIiiIii / iII111i + i11iIiiIii . I11i
 if 66 - 66: i1IIi
 if 98 - 98: Oo0Ooo / iIii1I11I1II1
 if 33 - 33: O0 - iII111i
 if 40 - 40: iII111i * I11i
 if 25 - 25: O0 * o0oOOo0O0Ooo % ooOoO0o % I1IiiI
def lisp_process_ecm ( lisp_sockets , packet , source , ecm_port ) :
 I1iiiIII11ii1i1i1 = lisp_ecm ( 0 )
 packet = I1iiiIII11ii1i1i1 . decode ( packet )
 if ( packet == None ) :
  lprint ( "Could not decode ECM packet" )
  return
  if 87 - 87: OoOoOO00
  if 30 - 30: IiII % OoOoOO00 + I1Ii111
 I1iiiIII11ii1i1i1 . print_ecm ( )
 if 13 - 13: iII111i * Ii1I % o0oOOo0O0Ooo * i1IIi . IiII % i1IIi
 O0ooOoO0 = lisp_control_header ( )
 if ( O0ooOoO0 . decode ( packet ) == None ) :
  lprint ( "Could not decode control header" )
  return
  if 79 - 79: OoooooooOO % I11i / o0oOOo0O0Ooo + IiII + O0 + iII111i
  if 87 - 87: I11i
 iI1i11I1III11 = O0ooOoO0 . type
 del ( O0ooOoO0 )
 if 14 - 14: II111iiii / I11i . OOooOOo . Ii1I . II111iiii
 if ( iI1i11I1III11 != LISP_MAP_REQUEST ) :
  lprint ( "Received ECM without Map-Request inside" )
  return
  if 57 - 57: i1IIi - Ii1I - i11iIiiIii . O0
  if 67 - 67: I1Ii111
  if 49 - 49: IiII / i1IIi . OOooOOo
  if 64 - 64: O0
  if 10 - 10: I1ii11iIi11i % ooOoO0o * IiII - iIii1I11I1II1
 i1IIIiI1II11 = I1iiiIII11ii1i1i1 . udp_sport
 i1I1iiIiii1 = time . time ( )
 lisp_process_map_request ( lisp_sockets , packet , source , ecm_port ,
 I1iiiIII11ii1i1i1 . source , i1IIIiI1II11 , I1iiiIII11ii1i1i1 . ddt , - 1 , i1I1iiIiii1 )
 return
 if 13 - 13: I1ii11iIi11i
 if 9 - 9: o0oOOo0O0Ooo
 if 23 - 23: ooOoO0o * OoO0O00 + O0 % I1Ii111
 if 21 - 21: Ii1I * OoOoOO00
 if 29 - 29: iIii1I11I1II1 / ooOoO0o
 if 75 - 75: OoooooooOO + I1IiiI % OoOoOO00 / O0 - IiII
 if 88 - 88: OoO0O00 % Ii1I
 if 12 - 12: OoooooooOO . O0
 if 33 - 33: OoooooooOO / I11i . II111iiii * i1IIi
 if 34 - 34: i11iIiiIii / OoOoOO00
def lisp_send_map_register ( lisp_sockets , packet , map_register , ms ) :
 if 100 - 100: o0oOOo0O0Ooo - I1IiiI / I11i
 if 43 - 43: o0oOOo0O0Ooo % iIii1I11I1II1
 if 85 - 85: oO0o + OoooooooOO - IiII % o0oOOo0O0Ooo * ooOoO0o * II111iiii
 if 4 - 4: Ii1I . i1IIi + Oo0Ooo % I11i . OoO0O00
 if 70 - 70: OOooOOo * OoOoOO00 / OoOoOO00 / OoOoOO00
 if 23 - 23: I1IiiI
 if 24 - 24: I1Ii111 * i1IIi % O0 * Ii1I + iII111i
 oo0OoO = ms . map_server
 if ( lisp_decent_push_configured and oo0OoO . is_multicast_address ( ) and
 ( ms . map_registers_multicast_sent == 1 or ms . map_registers_sent == 1 ) ) :
  oo0OoO = copy . deepcopy ( oo0OoO )
  oo0OoO . address = 0x7f000001
  I11i1iIiiIiIi = bold ( "Bootstrap" , False )
  i11ii = ms . map_server . print_address_no_iid ( )
  lprint ( "{} mapping system for peer-group {}" . format ( I11i1iIiiIiIi , i11ii ) )
  if 14 - 14: oO0o * iII111i + Ii1I + Ii1I * IiII
  if 82 - 82: IiII * ooOoO0o / OOooOOo + OoOoOO00
  if 32 - 32: IiII
  if 90 - 90: I1ii11iIi11i / I11i * o0oOOo0O0Ooo % O0 * i11iIiiIii
  if 68 - 68: I11i . Ii1I + I11i / IiII . I11i / iIii1I11I1II1
  if 96 - 96: O0
 packet = lisp_compute_auth ( packet , map_register , ms . password )
 if 2 - 2: OoO0O00 / iII111i + o0oOOo0O0Ooo
 if 27 - 27: I11i - OoOoOO00 - ooOoO0o - I1IiiI
 if 51 - 51: I11i + I11i + O0 + O0 * I1Ii111
 if 61 - 61: IiII . O0
 if 38 - 38: Ii1I * I1ii11iIi11i - i11iIiiIii + ooOoO0o * I11i
 if ( ms . ekey != None ) :
  II11iI11i1 = ms . ekey . zfill ( 32 )
  iiI1iiIiiiI1I = "0" * 8
  o0 = chacha . ChaCha ( II11iI11i1 , iiI1iiIiiiI1I ) . encrypt ( packet [ 4 : : ] )
  packet = packet [ 0 : 4 ] + o0
  oOo = bold ( "Encrypt" , False )
  lprint ( "{} Map-Register with key-id {}" . format ( oOo , ms . ekey_id ) )
  if 74 - 74: OoOoOO00 . o0oOOo0O0Ooo
  if 40 - 40: ooOoO0o + I1ii11iIi11i * i11iIiiIii / i1IIi
 OO000 = ""
 if ( lisp_decent_pull_xtr_configured ( ) ) :
  OO000 = ", decent-index {}" . format ( bold ( ms . dns_name , False ) )
  if 27 - 27: Ii1I
  if 4 - 4: iII111i + i1IIi * I1IiiI
 lprint ( "Send Map-Register to map-server {}{}{}" . format ( oo0OoO . print_address ( ) , ", ms-name '{}'" . format ( ms . ms_name ) , OO000 ) )
 if 84 - 84: OoO0O00 + i1IIi
 lisp_send ( lisp_sockets , oo0OoO , LISP_CTRL_PORT , packet )
 return
 if 99 - 99: OOooOOo + o0oOOo0O0Ooo * I1Ii111 % OoooooooOO % I11i
 if 48 - 48: o0oOOo0O0Ooo / OoO0O00
 if 45 - 45: OOooOOo
 if 57 - 57: iIii1I11I1II1 + IiII - I1IiiI
 if 64 - 64: II111iiii . IiII / I1IiiI
 if 20 - 20: OoooooooOO - I1ii11iIi11i * I1ii11iIi11i * I1ii11iIi11i
 if 87 - 87: OoooooooOO * ooOoO0o
 if 6 - 6: I1Ii111 / ooOoO0o / OoooooooOO . iIii1I11I1II1
def lisp_send_ipc_to_core ( lisp_socket , packet , dest , port ) :
 i1IIi1ii1i1ii = lisp_socket . getsockname ( )
 dest = dest . print_address_no_iid ( )
 if 68 - 68: OoO0O00
 lprint ( "Send IPC {} bytes to {} {}, control-packet: {}" . format ( len ( packet ) , dest , port , lisp_format_packet ( packet ) ) )
 if 26 - 26: I11i % i1IIi / iIii1I11I1II1 % IiII . iII111i + I1ii11iIi11i
 if 49 - 49: O0 . IiII + I1Ii111 - I11i % II111iiii
 packet = lisp_control_packet_ipc ( packet , i1IIi1ii1i1ii , dest , port )
 lisp_ipc ( packet , lisp_socket , "lisp-core-pkt" )
 return
 if 15 - 15: O0 - OoOoOO00 % II111iiii + O0 % O0 + OoOoOO00
 if 34 - 34: I1Ii111
 if 69 - 69: iIii1I11I1II1 . OOooOOo % I11i
 if 28 - 28: I1Ii111 . ooOoO0o % I1IiiI
 if 62 - 62: II111iiii + ooOoO0o + I1IiiI
 if 70 - 70: o0oOOo0O0Ooo + Ii1I . OoO0O00 * Ii1I + OOooOOo + ooOoO0o
 if 13 - 13: I1ii11iIi11i
 if 97 - 97: oO0o - Oo0Ooo . i11iIiiIii % ooOoO0o * i11iIiiIii - OoooooooOO
def lisp_send_map_reply ( lisp_sockets , packet , dest , port ) :
 lprint ( "Send Map-Reply to {}" . format ( dest . print_address_no_iid ( ) ) )
 lisp_send_ipc_to_core ( lisp_sockets [ 2 ] , packet , dest , port )
 return
 if 44 - 44: I11i % OoooooooOO / iII111i - i11iIiiIii * i1IIi * o0oOOo0O0Ooo
 if 51 - 51: Ii1I + IiII / I1ii11iIi11i + O0 % Ii1I
 if 55 - 55: iII111i % o0oOOo0O0Ooo - oO0o % OoooooooOO
 if 18 - 18: OoooooooOO - I1ii11iIi11i
 if 94 - 94: OOooOOo . Oo0Ooo + Ii1I * o0oOOo0O0Ooo
 if 79 - 79: OOooOOo + Oo0Ooo
 if 33 - 33: iIii1I11I1II1
 if 75 - 75: I1Ii111 / iIii1I11I1II1 . OoooooooOO
def lisp_send_map_referral ( lisp_sockets , packet , dest , port ) :
 lprint ( "Send Map-Referral to {}" . format ( dest . print_address ( ) ) )
 lisp_send_ipc_to_core ( lisp_sockets [ 2 ] , packet , dest , port )
 return
 if 98 - 98: iIii1I11I1II1 / I1IiiI + i1IIi
 if 80 - 80: II111iiii . Oo0Ooo * oO0o % II111iiii / I1ii11iIi11i
 if 66 - 66: iII111i / OoO0O00 / i11iIiiIii
 if 99 - 99: OOooOOo
 if 51 - 51: i11iIiiIii . o0oOOo0O0Ooo / iII111i
 if 53 - 53: oO0o / i1IIi - Oo0Ooo - i1IIi + IiII
 if 79 - 79: oO0o % o0oOOo0O0Ooo / o0oOOo0O0Ooo % iII111i
 if 56 - 56: Oo0Ooo % I1ii11iIi11i
def lisp_send_map_notify ( lisp_sockets , packet , dest , port ) :
 lprint ( "Send Map-Notify to xTR {}" . format ( dest . print_address ( ) ) )
 lisp_send_ipc_to_core ( lisp_sockets [ 2 ] , packet , dest , port )
 return
 if 53 - 53: OoO0O00 . I11i - ooOoO0o
 if 11 - 11: I11i + i11iIiiIii / oO0o % oO0o * o0oOOo0O0Ooo / OoOoOO00
 if 74 - 74: oO0o . I1Ii111 . II111iiii
 if 92 - 92: I1Ii111 % OoooooooOO * I1Ii111
 if 78 - 78: Oo0Ooo . I11i . oO0o + O0 / O0
 if 41 - 41: iII111i * OoO0O00 - OoO0O00
 if 72 - 72: o0oOOo0O0Ooo + oO0o . I1ii11iIi11i + OoO0O00 / I1Ii111
def lisp_send_ecm ( lisp_sockets , packet , inner_source , inner_sport , inner_dest ,
 outer_dest , to_etr = False , to_ms = False , ddt = False ) :
 if 58 - 58: Oo0Ooo / II111iiii % OoooooooOO % II111iiii
 if ( inner_source == None or inner_source . is_null ( ) ) :
  inner_source = inner_dest
  if 39 - 39: i1IIi
  if 16 - 16: OoOoOO00 % iIii1I11I1II1 + Ii1I - o0oOOo0O0Ooo . Oo0Ooo + i1IIi
  if 59 - 59: i1IIi
  if 37 - 37: OoO0O00 / I1ii11iIi11i / OoOoOO00
  if 15 - 15: I1IiiI % iIii1I11I1II1 . I1Ii111
  if 71 - 71: I11i - Ii1I + i11iIiiIii % I1ii11iIi11i - OoO0O00 - OOooOOo
 if ( lisp_nat_traversal ) :
  oo0O = lisp_get_any_translated_port ( )
  if ( oo0O != None ) : inner_sport = oo0O
  if 71 - 71: OOooOOo
 I1iiiIII11ii1i1i1 = lisp_ecm ( inner_sport )
 if 27 - 27: OOooOOo * O0 * i11iIiiIii / OoOoOO00 - i1IIi
 I1iiiIII11ii1i1i1 . to_etr = to_etr if lisp_is_running ( "lisp-etr" ) else False
 I1iiiIII11ii1i1i1 . to_ms = to_ms if lisp_is_running ( "lisp-ms" ) else False
 I1iiiIII11ii1i1i1 . ddt = ddt
 o00o0 = I1iiiIII11ii1i1i1 . encode ( packet , inner_source , inner_dest )
 if ( o00o0 == None ) :
  lprint ( "Could not encode ECM message" )
  return
  if 85 - 85: I11i + I11i + oO0o - OoOoOO00
 I1iiiIII11ii1i1i1 . print_ecm ( )
 if 15 - 15: OoO0O00
 packet = o00o0 + packet
 if 88 - 88: Ii1I % i1IIi / I1Ii111
 oo0o00OO = outer_dest . print_address_no_iid ( )
 lprint ( "Send Encapsulated-Control-Message to {}" . format ( oo0o00OO ) )
 oo0OoO = lisp_convert_4to6 ( oo0o00OO )
 lisp_send ( lisp_sockets , oo0OoO , LISP_CTRL_PORT , packet )
 return
 if 2 - 2: Ii1I . IiII % OoOoOO00
 if 42 - 42: OoOoOO00 * OoO0O00 * IiII - IiII % Oo0Ooo . IiII
 if 38 - 38: I1Ii111 . IiII - ooOoO0o . i11iIiiIii
 if 35 - 35: i11iIiiIii
 if 62 - 62: O0 - o0oOOo0O0Ooo + I1Ii111 * I1ii11iIi11i / OOooOOo
 if 87 - 87: Oo0Ooo / OoooooooOO + O0 / o0oOOo0O0Ooo % II111iiii - O0
 if 63 - 63: OOooOOo - OoO0O00 * i1IIi - I1ii11iIi11i . I1IiiI
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
if 59 - 59: i11iIiiIii . OOooOOo % Oo0Ooo + O0
LISP_RLOC_UNKNOWN_STATE = 0
LISP_RLOC_UP_STATE = 1
LISP_RLOC_DOWN_STATE = 2
LISP_RLOC_UNREACH_STATE = 3
LISP_RLOC_NO_ECHOED_NONCE_STATE = 4
LISP_RLOC_ADMIN_DOWN_STATE = 5
if 84 - 84: I1Ii111 / O0 - IiII . I11i / o0oOOo0O0Ooo
LISP_AUTH_NONE = 0
LISP_AUTH_MD5 = 1
LISP_AUTH_SHA1 = 2
LISP_AUTH_SHA2 = 3
if 12 - 12: i11iIiiIii / Ii1I + i1IIi
if 54 - 54: I1IiiI
if 55 - 55: I1ii11iIi11i % IiII % o0oOOo0O0Ooo + i1IIi * OoooooooOO % II111iiii
if 37 - 37: Oo0Ooo
if 33 - 33: OoooooooOO - O0 . O0 - o0oOOo0O0Ooo % o0oOOo0O0Ooo % OoO0O00
if 27 - 27: ooOoO0o . i11iIiiIii / o0oOOo0O0Ooo * OoO0O00 * OoOoOO00 * oO0o
if 19 - 19: O0 * II111iiii * OoOoOO00
LISP_IPV4_HOST_MASK_LEN = 32
LISP_IPV6_HOST_MASK_LEN = 128
LISP_MAC_HOST_MASK_LEN = 48
LISP_E164_HOST_MASK_LEN = 60
if 53 - 53: Oo0Ooo
if 16 - 16: Ii1I
if 73 - 73: i11iIiiIii + I1IiiI - IiII - IiII + IiII . Ii1I
if 78 - 78: OoO0O00 + oO0o
if 86 - 86: ooOoO0o . ooOoO0o + oO0o
if 84 - 84: OOooOOo - OoOoOO00 + i1IIi * I1ii11iIi11i % I1ii11iIi11i * I1Ii111
def byte_swap_64 ( address ) :
 IiiIIi1 = ( ( address & 0x00000000000000ff ) << 56 ) | ( ( address & 0x000000000000ff00 ) << 40 ) | ( ( address & 0x0000000000ff0000 ) << 24 ) | ( ( address & 0x00000000ff000000 ) << 8 ) | ( ( address & 0x000000ff00000000 ) >> 8 ) | ( ( address & 0x0000ff0000000000 ) >> 24 ) | ( ( address & 0x00ff000000000000 ) >> 40 ) | ( ( address & 0xff00000000000000 ) >> 56 )
 if 31 - 31: IiII + iII111i
 if 5 - 5: O0 * Ii1I
 if 78 - 78: iII111i * iIii1I11I1II1 . OoO0O00 . OoOoOO00 % I1Ii111
 if 77 - 77: OOooOOo / OoooooooOO
 if 11 - 11: iIii1I11I1II1 - Ii1I - OoOoOO00 . oO0o / I1ii11iIi11i
 if 79 - 79: i11iIiiIii % o0oOOo0O0Ooo * II111iiii . i1IIi * Ii1I - i11iIiiIii
 if 31 - 31: IiII / o0oOOo0O0Ooo
 if 27 - 27: Oo0Ooo
 return ( IiiIIi1 )
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
class lisp_cache_entries ( ) :
 def __init__ ( self ) :
  self . entries = { }
  self . entries_sorted = [ ]
  if 48 - 48: iII111i + Ii1I
  if 45 - 45: oO0o / iIii1I11I1II1 % O0 % IiII % I1ii11iIi11i
  if 89 - 89: OOooOOo - I1Ii111 - iII111i
class lisp_cache ( ) :
 def __init__ ( self ) :
  self . cache = { }
  self . cache_sorted = [ ]
  self . cache_count = 0
  if 67 - 67: oO0o
  if 76 - 76: I1IiiI % I1IiiI - IiII / OoOoOO00 / I1ii11iIi11i
 def cache_size ( self ) :
  return ( self . cache_count )
  if 42 - 42: I1IiiI + I1ii11iIi11i + Oo0Ooo * i1IIi - II111iiii
  if 15 - 15: o0oOOo0O0Ooo
 def build_key ( self , prefix ) :
  if ( prefix . afi == LISP_AFI_ULTIMATE_ROOT ) :
   iiIII = 0
  elif ( prefix . afi == LISP_AFI_IID_RANGE ) :
   iiIII = prefix . mask_len
  else :
   iiIII = prefix . mask_len + 48
   if 60 - 60: I1ii11iIi11i / I1Ii111
   if 13 - 13: I1Ii111
  o0OoO0000o = lisp_hex_string ( prefix . instance_id ) . zfill ( 8 )
  O0ooo0 = lisp_hex_string ( prefix . afi ) . zfill ( 4 )
  if 52 - 52: II111iiii / OoO0O00 . Ii1I
  if ( prefix . afi > 0 ) :
   if ( prefix . is_binary ( ) ) :
    IiiI1iii1iIiiI = prefix . addr_length ( ) * 2
    IiiIIi1 = lisp_hex_string ( prefix . address ) . zfill ( IiiI1iii1iIiiI )
   else :
    IiiIIi1 = prefix . address
    if 68 - 68: iII111i
  elif ( prefix . afi == LISP_AFI_GEO_COORD ) :
   O0ooo0 = "8003"
   IiiIIi1 = prefix . address . print_geo ( )
  else :
   O0ooo0 = ""
   IiiIIi1 = ""
   if 67 - 67: I1IiiI * I1IiiI
   if 100 - 100: iII111i * iII111i . Oo0Ooo
  Oo000O000 = o0OoO0000o + O0ooo0 + IiiIIi1
  return ( [ iiIII , Oo000O000 ] )
  if 10 - 10: Oo0Ooo % ooOoO0o * Oo0Ooo
  if 48 - 48: ooOoO0o + II111iiii
 def add_cache ( self , prefix , entry ) :
  if ( prefix . is_binary ( ) ) : prefix . zero_host_bits ( )
  iiIII , Oo000O000 = self . build_key ( prefix )
  if ( self . cache . has_key ( iiIII ) == False ) :
   self . cache [ iiIII ] = lisp_cache_entries ( )
   self . cache [ iiIII ] . entries = { }
   self . cache [ iiIII ] . entries_sorted = [ ]
   self . cache_sorted = sorted ( self . cache )
   if 73 - 73: II111iiii
  if ( self . cache [ iiIII ] . entries . has_key ( Oo000O000 ) == False ) :
   self . cache_count += 1
   if 63 - 63: i11iIiiIii . Oo0Ooo . OOooOOo - II111iiii
  self . cache [ iiIII ] . entries [ Oo000O000 ] = entry
  self . cache [ iiIII ] . entries_sorted = sorted ( self . cache [ iiIII ] . entries )
  if 35 - 35: II111iiii + IiII
  if 66 - 66: o0oOOo0O0Ooo % IiII
 def lookup_cache ( self , prefix , exact ) :
  iiI11IIiI1II , Oo000O000 = self . build_key ( prefix )
  if ( exact ) :
   if ( self . cache . has_key ( iiI11IIiI1II ) == False ) : return ( None )
   if ( self . cache [ iiI11IIiI1II ] . entries . has_key ( Oo000O000 ) == False ) : return ( None )
   return ( self . cache [ iiI11IIiI1II ] . entries [ Oo000O000 ] )
   if 53 - 53: ooOoO0o % i11iIiiIii - i11iIiiIii - Ii1I * Oo0Ooo % II111iiii
   if 1 - 1: i11iIiiIii
  ooOoOO0o = None
  for iiIII in self . cache_sorted :
   if ( iiI11IIiI1II < iiIII ) : return ( ooOoOO0o )
   for ooOooOoooO in self . cache [ iiIII ] . entries_sorted :
    I1iiIiii1IiIii = self . cache [ iiIII ] . entries
    if ( ooOooOoooO in I1iiIiii1IiIii ) :
     i1ii1i1Ii11 = I1iiIiii1IiIii [ ooOooOoooO ]
     if ( i1ii1i1Ii11 == None ) : continue
     if ( prefix . is_more_specific ( i1ii1i1Ii11 . eid ) ) : ooOoOO0o = i1ii1i1Ii11
     if 22 - 22: Ii1I . Oo0Ooo - O0 - Ii1I % ooOoO0o * I1ii11iIi11i
     if 89 - 89: O0 * I1IiiI % OoO0O00 - O0 . Oo0Ooo
     if 7 - 7: I1ii11iIi11i
  return ( ooOoOO0o )
  if 71 - 71: II111iiii
  if 2 - 2: OOooOOo / iIii1I11I1II1
 def delete_cache ( self , prefix ) :
  iiIII , Oo000O000 = self . build_key ( prefix )
  if ( self . cache . has_key ( iiIII ) == False ) : return
  if ( self . cache [ iiIII ] . entries . has_key ( Oo000O000 ) == False ) : return
  self . cache [ iiIII ] . entries . pop ( Oo000O000 )
  self . cache [ iiIII ] . entries_sorted . remove ( Oo000O000 )
  self . cache_count -= 1
  if 86 - 86: oO0o % IiII
  if 71 - 71: I11i + ooOoO0o * OoooooooOO
 def walk_cache ( self , function , parms ) :
  for iiIII in self . cache_sorted :
   for Oo000O000 in self . cache [ iiIII ] . entries_sorted :
    i1ii1i1Ii11 = self . cache [ iiIII ] . entries [ Oo000O000 ]
    iIii1IiiiII , parms = function ( i1ii1i1Ii11 , parms )
    if ( iIii1IiiiII == False ) : return ( parms )
    if 92 - 92: I1IiiI - I1ii11iIi11i
    if 37 - 37: OoooooooOO - OoOoOO00 . I1IiiI * oO0o - Oo0Ooo + I1IiiI
  return ( parms )
  if 17 - 17: OOooOOo % I1IiiI - o0oOOo0O0Ooo + OoO0O00 + OoOoOO00 + i1IIi
  if 74 - 74: iIii1I11I1II1
 def print_cache ( self ) :
  lprint ( "Printing contents of {}: " . format ( self ) )
  if ( self . cache_size ( ) == 0 ) :
   lprint ( "  Cache is empty" )
   return
   if 8 - 8: OOooOOo % o0oOOo0O0Ooo
  for iiIII in self . cache_sorted :
   for Oo000O000 in self . cache [ iiIII ] . entries_sorted :
    i1ii1i1Ii11 = self . cache [ iiIII ] . entries [ Oo000O000 ]
    lprint ( "  Mask-length: {}, key: {}, entry: {}" . format ( iiIII , Oo000O000 ,
 i1ii1i1Ii11 ) )
    if 36 - 36: Ii1I % OoooooooOO
    if 31 - 31: Ii1I / Ii1I / Ii1I / o0oOOo0O0Ooo / I11i
    if 24 - 24: i1IIi - Oo0Ooo % Oo0Ooo
    if 29 - 29: IiII
    if 94 - 94: I1IiiI * Oo0Ooo * OOooOOo + Oo0Ooo / I1Ii111
    if 3 - 3: I11i * iII111i - OoooooooOO % OoOoOO00 % ooOoO0o
    if 48 - 48: i11iIiiIii * i11iIiiIii
    if 92 - 92: i1IIi
lisp_referral_cache = lisp_cache ( )
lisp_ddt_cache = lisp_cache ( )
lisp_sites_by_eid = lisp_cache ( )
lisp_map_cache = lisp_cache ( )
lisp_db_for_lookups = lisp_cache ( )
if 3 - 3: iIii1I11I1II1 . I1ii11iIi11i
if 97 - 97: O0
if 82 - 82: OoooooooOO / I1Ii111 - ooOoO0o . I1Ii111
if 41 - 41: I11i . I11i
if 12 - 12: OoOoOO00 / I1IiiI
if 4 - 4: Oo0Ooo * o0oOOo0O0Ooo
if 45 - 45: Ii1I % OOooOOo * Ii1I - iIii1I11I1II1
def lisp_map_cache_lookup ( source , dest ) :
 if 18 - 18: I1Ii111 / Oo0Ooo % Ii1I + OoO0O00
 I11IiI1I1 = dest . is_multicast_address ( )
 if 69 - 69: iII111i % I1ii11iIi11i
 if 19 - 19: IiII
 if 35 - 35: OoOoOO00
 if 18 - 18: II111iiii . OoOoOO00 + I1ii11iIi11i * oO0o + OoooooooOO
 iiI1iIi1II1ii = lisp_map_cache . lookup_cache ( dest , False )
 if ( iiI1iIi1II1ii == None ) :
  I11i11i1 = source . print_sg ( dest ) if I11IiI1I1 else dest . print_address ( )
  I11i11i1 = green ( I11i11i1 , False )
  dprint ( "Lookup for EID {} not found in map-cache" . format ( I11i11i1 ) )
  return ( None )
  if 39 - 39: I1IiiI * ooOoO0o / i11iIiiIii - oO0o - oO0o + O0
  if 73 - 73: OOooOOo
  if 44 - 44: I1ii11iIi11i * i1IIi - iIii1I11I1II1 - oO0o - oO0o * II111iiii
  if 98 - 98: Oo0Ooo + ooOoO0o / OOooOOo . iIii1I11I1II1 . I1IiiI . OoOoOO00
  if 92 - 92: i1IIi + OoOoOO00 * i1IIi / IiII
 if ( I11IiI1I1 == False ) :
  OOIiIi1 = green ( iiI1iIi1II1ii . eid . print_prefix ( ) , False )
  dprint ( "Lookup for EID {} found map-cache entry {}" . format ( green ( dest . print_address ( ) , False ) , OOIiIi1 ) )
  if 4 - 4: oO0o % OoO0O00 + IiII + o0oOOo0O0Ooo
  return ( iiI1iIi1II1ii )
  if 82 - 82: O0 / I1Ii111 + OOooOOo . IiII + Ii1I
  if 31 - 31: i1IIi * OoO0O00 - Ii1I + I11i
  if 8 - 8: O0 + i1IIi . O0
  if 67 - 67: I1IiiI
  if 42 - 42: ooOoO0o - o0oOOo0O0Ooo % oO0o - ooOoO0o
 iiI1iIi1II1ii = iiI1iIi1II1ii . lookup_source_cache ( source , False )
 if ( iiI1iIi1II1ii == None ) :
  I11i11i1 = source . print_sg ( dest )
  dprint ( "Lookup for EID {} not found in map-cache" . format ( I11i11i1 ) )
  return ( None )
  if 87 - 87: OoooooooOO / O0
  if 57 - 57: iIii1I11I1II1 / IiII + OoO0O00 * oO0o + Ii1I
  if 76 - 76: i11iIiiIii . OOooOOo / I11i * oO0o % iIii1I11I1II1 . ooOoO0o
  if 75 - 75: O0 + I1IiiI
  if 67 - 67: OoOoOO00 % OoooooooOO / OoO0O00 - OoO0O00 / O0
 OOIiIi1 = green ( iiI1iIi1II1ii . print_eid_tuple ( ) , False )
 dprint ( "Lookup for EID {} found map-cache entry {}" . format ( green ( source . print_sg ( dest ) , False ) , OOIiIi1 ) )
 if 19 - 19: iIii1I11I1II1 / OOooOOo % I11i % I1IiiI / I1ii11iIi11i
 return ( iiI1iIi1II1ii )
 if 73 - 73: II111iiii
 if 26 - 26: II111iiii . iIii1I11I1II1 - I1Ii111 % OOooOOo
 if 83 - 83: OOooOOo + OoooooooOO % I1Ii111 % IiII + i11iIiiIii
 if 10 - 10: OoooooooOO . Ii1I % I1Ii111 + IiII
 if 78 - 78: OoOoOO00 - oO0o . I1ii11iIi11i * i11iIiiIii
 if 44 - 44: iIii1I11I1II1 * iII111i
 if 32 - 32: OoOoOO00
def lisp_referral_cache_lookup ( eid , group , exact ) :
 if ( group and group . is_null ( ) ) :
  OOo0 = lisp_referral_cache . lookup_cache ( eid , exact )
  return ( OOo0 )
  if 65 - 65: iIii1I11I1II1 + iII111i
  if 90 - 90: i11iIiiIii - Oo0Ooo
  if 31 - 31: OoOoOO00 + OoOoOO00 + OoooooooOO % O0
  if 14 - 14: i1IIi / OoooooooOO . I1IiiI * I1Ii111 + OoO0O00
  if 45 - 45: OoooooooOO * I1Ii111
 if ( eid == None or eid . is_null ( ) ) : return ( None )
 if 7 - 7: O0
 if 42 - 42: o0oOOo0O0Ooo / Ii1I
 if 31 - 31: OOooOOo
 if 20 - 20: i11iIiiIii * oO0o * ooOoO0o
 if 65 - 65: I1ii11iIi11i / Oo0Ooo / I1IiiI + IiII
 if 71 - 71: OoO0O00 . I1Ii111 + OoooooooOO
 OOo0 = lisp_referral_cache . lookup_cache ( group , exact )
 if ( OOo0 == None ) : return ( None )
 if 9 - 9: OoooooooOO / iIii1I11I1II1 % I1IiiI . I1IiiI / I11i - iII111i
 O0OO0OO0 = OOo0 . lookup_source_cache ( eid , exact )
 if ( O0OO0OO0 ) : return ( O0OO0OO0 )
 if 23 - 23: OoOoOO00 % ooOoO0o
 if ( exact ) : OOo0 = None
 return ( OOo0 )
 if 39 - 39: OoO0O00
 if 9 - 9: Ii1I % oO0o
 if 33 - 33: I1IiiI
 if 98 - 98: I1Ii111 . i11iIiiIii * iIii1I11I1II1 + oO0o
 if 96 - 96: II111iiii - OOooOOo * I1Ii111 . oO0o
 if 21 - 21: OoooooooOO * I11i * IiII / II111iiii * II111iiii / Oo0Ooo
 if 42 - 42: oO0o % OOooOOo + oO0o + I1Ii111
def lisp_ddt_cache_lookup ( eid , group , exact ) :
 if ( group . is_null ( ) ) :
  IIIIii11i1I = lisp_ddt_cache . lookup_cache ( eid , exact )
  return ( IIIIii11i1I )
  if 39 - 39: i11iIiiIii % OOooOOo % iIii1I11I1II1 / oO0o
  if 57 - 57: I1Ii111 % iII111i % oO0o . IiII + iIii1I11I1II1
  if 57 - 57: IiII
  if 29 - 29: o0oOOo0O0Ooo
  if 12 - 12: ooOoO0o + I11i * o0oOOo0O0Ooo % I1IiiI - OOooOOo
 if ( eid . is_null ( ) ) : return ( None )
 if 40 - 40: OoooooooOO - o0oOOo0O0Ooo . I11i - Ii1I . Ii1I
 if 57 - 57: I1Ii111 . oO0o - OoooooooOO
 if 74 - 74: I1ii11iIi11i + o0oOOo0O0Ooo * i11iIiiIii % OoooooooOO - IiII % i1IIi
 if 74 - 74: iII111i % I11i * i11iIiiIii . i11iIiiIii + iIii1I11I1II1 * i1IIi
 if 53 - 53: I1ii11iIi11i + IiII / OOooOOo . OoooooooOO - ooOoO0o
 if 47 - 47: i11iIiiIii
 IIIIii11i1I = lisp_ddt_cache . lookup_cache ( group , exact )
 if ( IIIIii11i1I == None ) : return ( None )
 if 21 - 21: i1IIi - oO0o - Oo0Ooo
 i1II = IIIIii11i1I . lookup_source_cache ( eid , exact )
 if ( i1II ) : return ( i1II )
 if 75 - 75: iII111i / OoooooooOO + OoOoOO00 - I1Ii111 * i1IIi % i11iIiiIii
 if ( exact ) : IIIIii11i1I = None
 return ( IIIIii11i1I )
 if 56 - 56: Ii1I . iII111i
 if 76 - 76: I1IiiI / Ii1I % OoOoOO00 + IiII / i11iIiiIii . o0oOOo0O0Ooo
 if 31 - 31: oO0o * oO0o % o0oOOo0O0Ooo . O0 + iII111i
 if 52 - 52: i11iIiiIii
 if 1 - 1: i1IIi * iIii1I11I1II1
 if 29 - 29: I11i
 if 12 - 12: oO0o % i1IIi - oO0o / ooOoO0o * II111iiii % ooOoO0o
def lisp_site_eid_lookup ( eid , group , exact ) :
 if 6 - 6: IiII / OoO0O00
 if ( group . is_null ( ) ) :
  I11111Ii = lisp_sites_by_eid . lookup_cache ( eid , exact )
  return ( I11111Ii )
  if 83 - 83: IiII - iIii1I11I1II1 * ooOoO0o - oO0o
  if 77 - 77: Ii1I
  if 9 - 9: OOooOOo / OoooooooOO + iII111i
  if 52 - 52: IiII / OOooOOo * iIii1I11I1II1 + o0oOOo0O0Ooo
  if 20 - 20: I1Ii111
 if ( eid . is_null ( ) ) : return ( None )
 if 33 - 33: i11iIiiIii / I1Ii111 + IiII / II111iiii + I11i
 if 13 - 13: i1IIi % iII111i + OoOoOO00 / Ii1I . Ii1I + II111iiii
 if 44 - 44: OoOoOO00 / OoooooooOO % O0 * Ii1I * IiII
 if 84 - 84: o0oOOo0O0Ooo * IiII * OOooOOo * iII111i
 if 56 - 56: iII111i * II111iiii . OoooooooOO . I11i
 if 25 - 25: ooOoO0o % o0oOOo0O0Ooo - i11iIiiIii
 I11111Ii = lisp_sites_by_eid . lookup_cache ( group , exact )
 if ( I11111Ii == None ) : return ( None )
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
 if 41 - 41: I1ii11iIi11i * ooOoO0o * I11i + O0 * O0 - O0
 if 81 - 81: I1Ii111 % OoO0O00 / O0
 if 55 - 55: i1IIi - I1Ii111 + I11i
 if 93 - 93: I1IiiI % IiII . OoOoOO00 + iII111i
 O00O0o = I11111Ii . lookup_source_cache ( eid , exact )
 if ( O00O0o ) : return ( O00O0o )
 if 81 - 81: ooOoO0o / I1Ii111 + OOooOOo / Oo0Ooo / OoOoOO00
 if ( exact ) :
  I11111Ii = None
 else :
  i1iIiiiiI1 = I11111Ii . parent_for_more_specifics
  if ( i1iIiiiiI1 and i1iIiiiiI1 . accept_more_specifics ) :
   if ( group . is_more_specific ( i1iIiiiiI1 . group ) ) : I11111Ii = i1iIiiiiI1
   if 34 - 34: ooOoO0o * iIii1I11I1II1 % i11iIiiIii * OOooOOo - OOooOOo
   if 63 - 63: Oo0Ooo / oO0o + iII111i % OoooooooOO * I11i
 return ( I11111Ii )
 if 34 - 34: I1IiiI + I1Ii111 % ooOoO0o
 if 24 - 24: Ii1I % II111iiii - i11iIiiIii
 if 52 - 52: OoO0O00
 if 76 - 76: ooOoO0o - iII111i % ooOoO0o / oO0o . OOooOOo
 if 50 - 50: IiII . i11iIiiIii % I11i
 if 22 - 22: i1IIi - II111iiii - OoOoOO00 . iII111i
 if 43 - 43: I1Ii111 * OOooOOo - IiII . i11iIiiIii
 if 34 - 34: iII111i . OoOoOO00
 if 49 - 49: I1ii11iIi11i % oO0o - I1Ii111 . I1ii11iIi11i % II111iiii
 if 20 - 20: I1ii11iIi11i . iIii1I11I1II1 - Ii1I % OoO0O00
 if 27 - 27: iIii1I11I1II1 / I1Ii111 - I11i . OoO0O00 + ooOoO0o
 if 89 - 89: I1IiiI % I11i - OOooOOo
 if 71 - 71: OOooOOo % Oo0Ooo - o0oOOo0O0Ooo / I1Ii111 - O0 - oO0o
 if 10 - 10: I1IiiI
 if 17 - 17: i11iIiiIii % o0oOOo0O0Ooo . ooOoO0o
 if 34 - 34: OoooooooOO / iII111i / O0
 if 75 - 75: I11i % OOooOOo - OoO0O00 * I11i * IiII
 if 11 - 11: I1ii11iIi11i . O0 - iII111i * IiII . i1IIi . iII111i
 if 82 - 82: i1IIi * I11i * Ii1I - IiII . i11iIiiIii
 if 40 - 40: OOooOOo - OoooooooOO
 if 36 - 36: i1IIi % OoOoOO00 - i1IIi
 if 5 - 5: I1IiiI . I1IiiI % II111iiii - I1Ii111
 if 97 - 97: I11i . ooOoO0o
 if 87 - 87: oO0o / iIii1I11I1II1 - I11i + OoooooooOO
 if 79 - 79: I1ii11iIi11i * IiII . I1ii11iIi11i
 if 65 - 65: iII111i - Ii1I - II111iiii * O0 + I1ii11iIi11i . iIii1I11I1II1
class lisp_address ( ) :
 def __init__ ( self , afi , addr_str , mask_len , iid ) :
  self . afi = afi
  self . mask_len = mask_len
  self . instance_id = iid
  self . iid_list = [ ]
  self . address = 0
  if ( addr_str != "" ) : self . store_address ( addr_str )
  if 76 - 76: OoO0O00 * ooOoO0o
  if 32 - 32: O0 . oO0o * o0oOOo0O0Ooo . Ii1I + IiII
 def copy_address ( self , addr ) :
  if ( addr == None ) : return
  self . afi = addr . afi
  self . address = addr . address
  self . mask_len = addr . mask_len
  self . instance_id = addr . instance_id
  self . iid_list = addr . iid_list
  if 98 - 98: iII111i . II111iiii % O0
  if 43 - 43: OOooOOo % I1Ii111 . IiII % OoO0O00 + I1Ii111 % OoooooooOO
 def make_default_route ( self , addr ) :
  self . afi = addr . afi
  self . instance_id = addr . instance_id
  self . mask_len = 0
  self . address = 0
  if 17 - 17: OoooooooOO - i1IIi * I11i
  if 33 - 33: i1IIi . Oo0Ooo + I11i
 def make_default_multicast_route ( self , addr ) :
  self . afi = addr . afi
  self . instance_id = addr . instance_id
  if ( self . afi == LISP_AFI_IPV4 ) :
   self . address = 0xe0000000
   self . mask_len = 4
   if 97 - 97: OOooOOo / IiII / ooOoO0o / OoooooooOO
  if ( self . afi == LISP_AFI_IPV6 ) :
   self . address = 0xff << 120
   self . mask_len = 8
   if 78 - 78: I1Ii111 + I1Ii111
  if ( self . afi == LISP_AFI_MAC ) :
   self . address = 0xffffffffffff
   self . mask_len = 48
   if 43 - 43: I1Ii111 * o0oOOo0O0Ooo + i1IIi
   if 19 - 19: Ii1I
   if 51 - 51: oO0o
 def not_set ( self ) :
  return ( self . afi == LISP_AFI_NONE )
  if 57 - 57: i11iIiiIii - Oo0Ooo + I1Ii111 * OoO0O00
  if 35 - 35: o0oOOo0O0Ooo % II111iiii + O0
 def is_private_address ( self ) :
  if ( self . is_ipv4 ( ) == False ) : return ( False )
  IiiIIi1 = self . address
  if ( ( ( IiiIIi1 & 0xff000000 ) >> 24 ) == 10 ) : return ( True )
  if ( ( ( IiiIIi1 & 0xff000000 ) >> 24 ) == 172 ) :
   oOoo00oOoO0o = ( IiiIIi1 & 0x00ff0000 ) >> 16
   if ( oOoo00oOoO0o >= 16 and oOoo00oOoO0o <= 31 ) : return ( True )
   if 11 - 11: Oo0Ooo + oO0o / I1ii11iIi11i / OoOoOO00
  if ( ( ( IiiIIi1 & 0xffff0000 ) >> 16 ) == 0xc0a8 ) : return ( True )
  return ( False )
  if 49 - 49: Ii1I * I1ii11iIi11i
  if 66 - 66: ooOoO0o
 def is_multicast_address ( self ) :
  if ( self . is_ipv4 ( ) ) : return ( self . is_ipv4_multicast ( ) )
  if ( self . is_ipv6 ( ) ) : return ( self . is_ipv6_multicast ( ) )
  if ( self . is_mac ( ) ) : return ( self . is_mac_multicast ( ) )
  return ( False )
  if 2 - 2: o0oOOo0O0Ooo
  if 86 - 86: OoooooooOO * I1ii11iIi11i + O0 + o0oOOo0O0Ooo + OOooOOo % OoO0O00
 def host_mask_len ( self ) :
  if ( self . afi == LISP_AFI_IPV4 ) : return ( LISP_IPV4_HOST_MASK_LEN )
  if ( self . afi == LISP_AFI_IPV6 ) : return ( LISP_IPV6_HOST_MASK_LEN )
  if ( self . afi == LISP_AFI_MAC ) : return ( LISP_MAC_HOST_MASK_LEN )
  if ( self . afi == LISP_AFI_E164 ) : return ( LISP_E164_HOST_MASK_LEN )
  if ( self . afi == LISP_AFI_NAME ) : return ( len ( self . address ) * 8 )
  if ( self . afi == LISP_AFI_GEO_COORD ) :
   return ( len ( self . address . print_geo ( ) ) * 8 )
   if 72 - 72: ooOoO0o * I1IiiI
  return ( 0 )
  if 71 - 71: OoOoOO00 * OoO0O00 * O0 . i1IIi
  if 78 - 78: OoO0O00 - I1IiiI
 def is_iana_eid ( self ) :
  if ( self . is_ipv6 ( ) == False ) : return ( False )
  IiiIIi1 = self . address >> 96
  return ( IiiIIi1 == 0x20010005 )
  if 12 - 12: II111iiii . O0
  if 86 - 86: oO0o . OoOoOO00 - I11i . OOooOOo % OoO0O00
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
   if 79 - 79: iII111i / Ii1I % i11iIiiIii . I1IiiI % OoO0O00 / i11iIiiIii
  return ( 0 )
  if 100 - 100: OOooOOo + Oo0Ooo . iIii1I11I1II1 . ooOoO0o * Oo0Ooo
  if 16 - 16: Oo0Ooo % OoOoOO00 + I1Ii111 % I1Ii111
 def afi_to_version ( self ) :
  if ( self . afi == LISP_AFI_IPV4 ) : return ( 4 )
  if ( self . afi == LISP_AFI_IPV6 ) : return ( 6 )
  return ( 0 )
  if 12 - 12: I1Ii111 . Ii1I / iIii1I11I1II1 + i1IIi
  if 9 - 9: iIii1I11I1II1
 def packet_format ( self ) :
  if 75 - 75: I11i . II111iiii * I1IiiI * IiII
  if 36 - 36: OOooOOo / I1ii11iIi11i / oO0o / ooOoO0o / I11i
  if 7 - 7: OoO0O00 - I11i - o0oOOo0O0Ooo / o0oOOo0O0Ooo + i11iIiiIii
  if 28 - 28: OoOoOO00 % ooOoO0o . I1IiiI + II111iiii
  if 34 - 34: iIii1I11I1II1
  if ( self . afi == LISP_AFI_IPV4 ) : return ( "I" )
  if ( self . afi == LISP_AFI_IPV6 ) : return ( "QQ" )
  if ( self . afi == LISP_AFI_MAC ) : return ( "HHH" )
  if ( self . afi == LISP_AFI_E164 ) : return ( "II" )
  if ( self . afi == LISP_AFI_LCAF ) : return ( "I" )
  return ( "" )
  if 65 - 65: II111iiii - iII111i / o0oOOo0O0Ooo
  if 35 - 35: i11iIiiIii - Oo0Ooo . I1ii11iIi11i % OoOoOO00
 def pack_address ( self ) :
  i1I1iii1I11II = self . packet_format ( )
  IiiiIi1iiii11 = ""
  if ( self . is_ipv4 ( ) ) :
   IiiiIi1iiii11 = struct . pack ( i1I1iii1I11II , socket . htonl ( self . address ) )
  elif ( self . is_ipv6 ( ) ) :
   ooOo0O0 = byte_swap_64 ( self . address >> 64 )
   ooo0 = byte_swap_64 ( self . address & 0xffffffffffffffff )
   IiiiIi1iiii11 = struct . pack ( i1I1iii1I11II , ooOo0O0 , ooo0 )
  elif ( self . is_mac ( ) ) :
   IiiIIi1 = self . address
   ooOo0O0 = ( IiiIIi1 >> 32 ) & 0xffff
   ooo0 = ( IiiIIi1 >> 16 ) & 0xffff
   i1II1II = IiiIIi1 & 0xffff
   IiiiIi1iiii11 = struct . pack ( i1I1iii1I11II , ooOo0O0 , ooo0 , i1II1II )
  elif ( self . is_e164 ( ) ) :
   IiiIIi1 = self . address
   ooOo0O0 = ( IiiIIi1 >> 32 ) & 0xffffffff
   ooo0 = ( IiiIIi1 & 0xffffffff )
   IiiiIi1iiii11 = struct . pack ( i1I1iii1I11II , ooOo0O0 , ooo0 )
  elif ( self . is_dist_name ( ) ) :
   IiiiIi1iiii11 += self . address + "\0"
   if 57 - 57: II111iiii / Oo0Ooo % i1IIi * iIii1I11I1II1
  return ( IiiiIi1iiii11 )
  if 53 - 53: I1Ii111 . I1ii11iIi11i
  if 18 - 18: I1ii11iIi11i / i11iIiiIii
 def unpack_address ( self , packet ) :
  i1I1iii1I11II = self . packet_format ( )
  Iiiii = struct . calcsize ( i1I1iii1I11II )
  if ( len ( packet ) < Iiiii ) : return ( None )
  if 52 - 52: i11iIiiIii . O0 * ooOoO0o - o0oOOo0O0Ooo - O0
  IiiIIi1 = struct . unpack ( i1I1iii1I11II , packet [ : Iiiii ] )
  if 39 - 39: iII111i / I11i
  if ( self . is_ipv4 ( ) ) :
   self . address = socket . ntohl ( IiiIIi1 [ 0 ] )
   if 67 - 67: i1IIi
  elif ( self . is_ipv6 ( ) ) :
   if 1 - 1: OoOoOO00 * O0 + i11iIiiIii . ooOoO0o / OoO0O00
   if 48 - 48: o0oOOo0O0Ooo * II111iiii
   if 17 - 17: o0oOOo0O0Ooo / ooOoO0o + i1IIi
   if 78 - 78: iIii1I11I1II1 * o0oOOo0O0Ooo * Oo0Ooo - OoO0O00 / OoO0O00
   if 89 - 89: o0oOOo0O0Ooo % o0oOOo0O0Ooo
   if 8 - 8: Ii1I % oO0o - o0oOOo0O0Ooo
   if 14 - 14: OOooOOo * IiII
   if 15 - 15: o0oOOo0O0Ooo + OoooooooOO - OOooOOo - o0oOOo0O0Ooo . iIii1I11I1II1 / Ii1I
   if ( IiiIIi1 [ 0 ] <= 0xffff and ( IiiIIi1 [ 0 ] & 0xff ) == 0 ) :
    i1I111 = ( IiiIIi1 [ 0 ] << 48 ) << 64
   else :
    i1I111 = byte_swap_64 ( IiiIIi1 [ 0 ] ) << 64
    if 72 - 72: iII111i / I11i / I11i + I1IiiI * oO0o
   iI1111i1ii1i = byte_swap_64 ( IiiIIi1 [ 1 ] )
   self . address = i1I111 | iI1111i1ii1i
   if 73 - 73: I1Ii111 / o0oOOo0O0Ooo * Oo0Ooo
  elif ( self . is_mac ( ) ) :
   iIiIII11IiiI = IiiIIi1 [ 0 ]
   o0oO = IiiIIi1 [ 1 ]
   i1IIII11IIII = IiiIIi1 [ 2 ]
   self . address = ( iIiIII11IiiI << 32 ) + ( o0oO << 16 ) + i1IIII11IIII
   if 63 - 63: i11iIiiIii % I11i
  elif ( self . is_e164 ( ) ) :
   self . address = ( IiiIIi1 [ 0 ] << 32 ) + IiiIIi1 [ 1 ]
   if 64 - 64: oO0o + I11i / i1IIi * OoO0O00
  elif ( self . is_dist_name ( ) ) :
   packet , self . address = lisp_decode_dist_name ( packet )
   self . mask_len = len ( self . address ) * 8
   Iiiii = 0
   if 19 - 19: O0 . O0
  packet = packet [ Iiiii : : ]
  return ( packet )
  if 13 - 13: i11iIiiIii - i11iIiiIii . iIii1I11I1II1 - O0 . I11i / i11iIiiIii
  if 59 - 59: ooOoO0o + I1ii11iIi11i . OoO0O00 . O0
 def is_ipv4 ( self ) :
  return ( True if ( self . afi == LISP_AFI_IPV4 ) else False )
  if 45 - 45: O0 . o0oOOo0O0Ooo + OoOoOO00 / I1ii11iIi11i + Ii1I % I1Ii111
  if 20 - 20: Oo0Ooo
 def is_ipv4_link_local ( self ) :
  if ( self . is_ipv4 ( ) == False ) : return ( False )
  return ( ( ( self . address >> 16 ) & 0xffff ) == 0xa9fe )
  if 33 - 33: oO0o - OoOoOO00 - i11iIiiIii + I1Ii111 + iIii1I11I1II1
  if 2 - 2: OoooooooOO + IiII / iII111i . iIii1I11I1II1 * OoOoOO00
 def is_ipv4_loopback ( self ) :
  if ( self . is_ipv4 ( ) == False ) : return ( False )
  return ( self . address == 0x7f000001 )
  if 84 - 84: OOooOOo
  if 68 - 68: I1Ii111
 def is_ipv4_multicast ( self ) :
  if ( self . is_ipv4 ( ) == False ) : return ( False )
  return ( ( ( self . address >> 24 ) & 0xf0 ) == 0xe0 )
  if 92 - 92: oO0o * Ii1I / OoO0O00 % II111iiii
  if 54 - 54: oO0o + I11i - OoO0O00
 def is_ipv4_string ( self , addr_str ) :
  return ( addr_str . find ( "." ) != - 1 )
  if 86 - 86: OoooooooOO
  if 51 - 51: i11iIiiIii
 def is_ipv6 ( self ) :
  return ( True if ( self . afi == LISP_AFI_IPV6 ) else False )
  if 91 - 91: OOooOOo
  if 22 - 22: OoooooooOO + OoOoOO00 - Ii1I . iII111i / OoooooooOO / I1IiiI
 def is_ipv6_link_local ( self ) :
  if ( self . is_ipv6 ( ) == False ) : return ( False )
  return ( ( ( self . address >> 112 ) & 0xffff ) == 0xfe80 )
  if 73 - 73: i1IIi - Ii1I + oO0o * iIii1I11I1II1
  if 100 - 100: i11iIiiIii / iIii1I11I1II1 + Oo0Ooo + OoO0O00 - iII111i
 def is_ipv6_string_link_local ( self , addr_str ) :
  return ( addr_str . find ( "fe80::" ) != - 1 )
  if 8 - 8: i11iIiiIii . O0 + o0oOOo0O0Ooo * oO0o + II111iiii
  if 61 - 61: ooOoO0o / ooOoO0o
 def is_ipv6_loopback ( self ) :
  if ( self . is_ipv6 ( ) == False ) : return ( False )
  return ( self . address == 1 )
  if 51 - 51: iIii1I11I1II1 / oO0o * I1Ii111 + i1IIi
  if 96 - 96: Oo0Ooo + oO0o - Oo0Ooo - OoOoOO00 % OOooOOo . iIii1I11I1II1
 def is_ipv6_multicast ( self ) :
  if ( self . is_ipv6 ( ) == False ) : return ( False )
  return ( ( ( self . address >> 120 ) & 0xff ) == 0xff )
  if 93 - 93: iIii1I11I1II1 % OoooooooOO
  if 6 - 6: II111iiii / oO0o - OOooOOo . O0 - o0oOOo0O0Ooo
 def is_ipv6_string ( self , addr_str ) :
  return ( addr_str . find ( ":" ) != - 1 )
  if 72 - 72: iIii1I11I1II1 / OoooooooOO * ooOoO0o / ooOoO0o % O0 + IiII
  if 96 - 96: iII111i / i11iIiiIii + Oo0Ooo . I1IiiI + iII111i % OoOoOO00
 def is_mac ( self ) :
  return ( True if ( self . afi == LISP_AFI_MAC ) else False )
  if 19 - 19: i11iIiiIii . Oo0Ooo . OoOoOO00 - I1IiiI
  if 85 - 85: I11i - OoO0O00 % iIii1I11I1II1 . iII111i + ooOoO0o . Oo0Ooo
 def is_mac_multicast ( self ) :
  if ( self . is_mac ( ) == False ) : return ( False )
  return ( ( self . address & 0x010000000000 ) != 0 )
  if 87 - 87: iII111i
  if 86 - 86: IiII - I11i
 def is_mac_broadcast ( self ) :
  if ( self . is_mac ( ) == False ) : return ( False )
  return ( self . address == 0xffffffffffff )
  if 99 - 99: i1IIi + I1ii11iIi11i
  if 24 - 24: ooOoO0o / OoooooooOO % I1ii11iIi11i * ooOoO0o
 def is_mac_string ( self , addr_str ) :
  return ( len ( addr_str ) == 15 and addr_str . find ( "-" ) != - 1 )
  if 14 - 14: I1ii11iIi11i + OoO0O00 - I1IiiI - Oo0Ooo
  if 44 - 44: II111iiii / I1ii11iIi11i
 def is_link_local_multicast ( self ) :
  if ( self . is_ipv4 ( ) ) :
   return ( ( 0xe0ffff00 & self . address ) == 0xe0000000 )
   if 39 - 39: OoooooooOO % OoO0O00
  if ( self . is_ipv6 ( ) ) :
   return ( ( self . address >> 112 ) & 0xffff == 0xff02 )
   if 83 - 83: OOooOOo % I1IiiI + O0 % OoooooooOO
  return ( False )
  if 84 - 84: I11i - Oo0Ooo % ooOoO0o - II111iiii
  if 29 - 29: IiII
 def is_null ( self ) :
  return ( True if ( self . afi == LISP_AFI_NONE ) else False )
  if 4 - 4: II111iiii * o0oOOo0O0Ooo - IiII * iII111i
  if 91 - 91: I1Ii111 * iII111i * OoO0O00
 def is_ultimate_root ( self ) :
  return ( True if self . afi == LISP_AFI_ULTIMATE_ROOT else False )
  if 79 - 79: iII111i + oO0o
  if 19 - 19: I1Ii111 - OOooOOo . ooOoO0o . O0 + II111iiii . OoooooooOO
 def is_iid_range ( self ) :
  return ( True if self . afi == LISP_AFI_IID_RANGE else False )
  if 97 - 97: O0 / OoOoOO00 / ooOoO0o
  if 11 - 11: II111iiii . i11iIiiIii - Ii1I . IiII
 def is_e164 ( self ) :
  return ( True if ( self . afi == LISP_AFI_E164 ) else False )
  if 10 - 10: OOooOOo * OoooooooOO
  if 12 - 12: II111iiii - O0 . i1IIi % oO0o % OoooooooOO
 def is_dist_name ( self ) :
  return ( True if ( self . afi == LISP_AFI_NAME ) else False )
  if 36 - 36: IiII * OoOoOO00 - iIii1I11I1II1 + II111iiii
  if 65 - 65: I1IiiI * I11i . I1Ii111 % I1ii11iIi11i + O0
 def is_geo_prefix ( self ) :
  return ( True if ( self . afi == LISP_AFI_GEO_COORD ) else False )
  if 91 - 91: OoooooooOO % I1Ii111 * OoO0O00 - OoOoOO00
  if 5 - 5: iIii1I11I1II1 * I11i - oO0o % oO0o % o0oOOo0O0Ooo . i1IIi
 def is_binary ( self ) :
  if ( self . is_dist_name ( ) ) : return ( False )
  if ( self . is_geo_prefix ( ) ) : return ( False )
  return ( True )
  if 95 - 95: Oo0Ooo * I1ii11iIi11i + iII111i - o0oOOo0O0Ooo - Oo0Ooo . OoO0O00
  if 62 - 62: I11i
 def store_address ( self , addr_str ) :
  if ( self . afi == LISP_AFI_NONE ) : self . string_to_afi ( addr_str )
  if 58 - 58: I11i . OoOoOO00 + iII111i . iII111i
  if 43 - 43: I1Ii111 + I1Ii111 % Oo0Ooo % OoO0O00 - ooOoO0o
  if 61 - 61: OoOoOO00 + Ii1I % i11iIiiIii - I1IiiI * OoO0O00 % iIii1I11I1II1
  if 66 - 66: iII111i + i1IIi
  IiIIi1IiiIiI = addr_str . find ( "[" )
  I11I1iiI111i1 = addr_str . find ( "]" )
  if ( IiIIi1IiiIiI != - 1 and I11I1iiI111i1 != - 1 ) :
   self . instance_id = int ( addr_str [ IiIIi1IiiIiI + 1 : I11I1iiI111i1 ] )
   addr_str = addr_str [ I11I1iiI111i1 + 1 : : ]
   if ( self . is_dist_name ( ) == False ) :
    addr_str = addr_str . replace ( " " , "" )
    if 24 - 24: O0 / OoooooooOO - OoOoOO00
    if 51 - 51: OoO0O00 + o0oOOo0O0Ooo - II111iiii * I11i + Ii1I
    if 16 - 16: I1Ii111 * i1IIi . I1IiiI . OOooOOo % Ii1I - o0oOOo0O0Ooo
    if 89 - 89: Ii1I * I1ii11iIi11i * I1IiiI % iII111i % Ii1I + O0
    if 53 - 53: i11iIiiIii % I1ii11iIi11i
    if 59 - 59: OOooOOo
  if ( self . is_ipv4 ( ) ) :
   OoOo0oo = addr_str . split ( "." )
   i11II = int ( OoOo0oo [ 0 ] ) << 24
   i11II += int ( OoOo0oo [ 1 ] ) << 16
   i11II += int ( OoOo0oo [ 2 ] ) << 8
   i11II += int ( OoOo0oo [ 3 ] )
   self . address = i11II
  elif ( self . is_ipv6 ( ) ) :
   if 63 - 63: IiII + oO0o + II111iiii * I11i
   if 49 - 49: OoO0O00
   if 78 - 78: I1IiiI - I1ii11iIi11i
   if 24 - 24: Ii1I + I11i
   if 5 - 5: I1Ii111 . Ii1I - ooOoO0o % OoooooooOO
   if 2 - 2: OOooOOo . IiII . iII111i / Oo0Ooo
   if 86 - 86: OOooOOo . o0oOOo0O0Ooo - iIii1I11I1II1
   if 12 - 12: oO0o + iII111i
   if 16 - 16: O0 + oO0o - ooOoO0o * O0 . I1ii11iIi11i . oO0o
   if 4 - 4: I1Ii111
   if 39 - 39: OoOoOO00 - I1Ii111 / I11i + II111iiii * I1IiiI * I1IiiI
   if 9 - 9: IiII * I1IiiI * OoO0O00 - I1IiiI * I1IiiI - OoO0O00
   if 20 - 20: i1IIi + I1IiiI + i11iIiiIii + II111iiii + i1IIi
   if 18 - 18: i11iIiiIii * O0 * Oo0Ooo + iII111i + OOooOOo
   if 62 - 62: OOooOOo - oO0o + i1IIi % Ii1I . I1Ii111 . II111iiii
   if 94 - 94: OOooOOo - I1IiiI
   if 35 - 35: i11iIiiIii
   IiIi11IIi1 = ( addr_str [ 2 : 4 ] == "::" )
   try :
    addr_str = socket . inet_pton ( socket . AF_INET6 , addr_str )
   except :
    addr_str = socket . inet_pton ( socket . AF_INET6 , "0::0" )
    if 37 - 37: I1Ii111 / i11iIiiIii . I1ii11iIi11i - OoO0O00 * ooOoO0o
   addr_str = binascii . hexlify ( addr_str )
   if 91 - 91: ooOoO0o % II111iiii
   if ( IiIi11IIi1 ) :
    addr_str = addr_str [ 2 : 4 ] + addr_str [ 0 : 2 ] + addr_str [ 4 : : ]
    if 48 - 48: oO0o
   self . address = int ( addr_str , 16 )
   if 10 - 10: Oo0Ooo - O0 * i1IIi + I11i - OoooooooOO
  elif ( self . is_geo_prefix ( ) ) :
   I1Ii1i111I = lisp_geo ( None )
   I1Ii1i111I . name = "geo-prefix-{}" . format ( I1Ii1i111I )
   I1Ii1i111I . parse_geo_string ( addr_str )
   self . address = I1Ii1i111I
  elif ( self . is_mac ( ) ) :
   addr_str = addr_str . replace ( "-" , "" )
   i11II = int ( addr_str , 16 )
   self . address = i11II
  elif ( self . is_e164 ( ) ) :
   addr_str = addr_str [ 1 : : ]
   i11II = int ( addr_str , 16 )
   self . address = i11II << 4
  elif ( self . is_dist_name ( ) ) :
   self . address = addr_str . replace ( "'" , "" )
   if 25 - 25: I1IiiI + iIii1I11I1II1 * Oo0Ooo - iIii1I11I1II1 % IiII * oO0o
  self . mask_len = self . host_mask_len ( )
  if 71 - 71: iIii1I11I1II1 % I1Ii111 % IiII / IiII + iIii1I11I1II1 % i1IIi
  if 93 - 93: Oo0Ooo / I1ii11iIi11i + Oo0Ooo + OOooOOo
 def store_prefix ( self , prefix_str ) :
  if ( self . is_geo_string ( prefix_str ) ) :
   ooo = prefix_str . find ( "]" )
   OO00O = len ( prefix_str [ ooo + 1 : : ] ) * 8
  elif ( prefix_str . find ( "/" ) != - 1 ) :
   prefix_str , OO00O = prefix_str . split ( "/" )
  else :
   i1i = prefix_str . find ( "'" )
   if ( i1i == - 1 ) : return
   O0ooOo0 = prefix_str . find ( "'" , i1i + 1 )
   if ( O0ooOo0 == - 1 ) : return
   OO00O = len ( prefix_str [ i1i + 1 : O0ooOo0 ] ) * 8
   if 58 - 58: oO0o
   if 9 - 9: I1Ii111 - i1IIi . ooOoO0o
  self . string_to_afi ( prefix_str )
  self . store_address ( prefix_str )
  self . mask_len = int ( OO00O )
  if 33 - 33: I11i
  if 37 - 37: Oo0Ooo
 def zero_host_bits ( self ) :
  if ( self . mask_len < 0 ) : return
  i11111I1111 = ( 2 ** self . mask_len ) - 1
  oOo0OOOoOoo = self . addr_length ( ) * 8 - self . mask_len
  i11111I1111 <<= oOo0OOOoOoo
  self . address &= i11111I1111
  if 55 - 55: OoooooooOO . OoOoOO00 . OoO0O00 / oO0o - OOooOOo
  if 100 - 100: IiII - I11i . iIii1I11I1II1 / iIii1I11I1II1
 def is_geo_string ( self , addr_str ) :
  ooo = addr_str . find ( "]" )
  if ( ooo != - 1 ) : addr_str = addr_str [ ooo + 1 : : ]
  if 16 - 16: IiII + Oo0Ooo % I11i
  I1Ii1i111I = addr_str . split ( "/" )
  if ( len ( I1Ii1i111I ) == 2 ) :
   if ( I1Ii1i111I [ 1 ] . isdigit ( ) == False ) : return ( False )
   if 16 - 16: ooOoO0o / I1Ii111
  I1Ii1i111I = I1Ii1i111I [ 0 ]
  I1Ii1i111I = I1Ii1i111I . split ( "-" )
  OOOoO0Oo = len ( I1Ii1i111I )
  if ( OOOoO0Oo < 8 or OOOoO0Oo > 9 ) : return ( False )
  if 28 - 28: I1IiiI
  for O0iiii in range ( 0 , OOOoO0Oo ) :
   if ( O0iiii == 3 ) :
    if ( I1Ii1i111I [ O0iiii ] in [ "N" , "S" ] ) : continue
    return ( False )
    if 27 - 27: I11i / ooOoO0o . I1Ii111 + Ii1I
   if ( O0iiii == 7 ) :
    if ( I1Ii1i111I [ O0iiii ] in [ "W" , "E" ] ) : continue
    return ( False )
    if 66 - 66: I1Ii111 + iIii1I11I1II1 / iIii1I11I1II1 - I1IiiI
   if ( I1Ii1i111I [ O0iiii ] . isdigit ( ) == False ) : return ( False )
   if 46 - 46: I1IiiI + iIii1I11I1II1 % OoooooooOO + OoooooooOO . OoO0O00 % iIii1I11I1II1
  return ( True )
  if 62 - 62: OoooooooOO * o0oOOo0O0Ooo
  if 59 - 59: iIii1I11I1II1
 def string_to_afi ( self , addr_str ) :
  if ( addr_str . count ( "'" ) == 2 ) :
   self . afi = LISP_AFI_NAME
   return
   if 18 - 18: ooOoO0o % I1IiiI / iIii1I11I1II1 + O0
  if ( addr_str . find ( ":" ) != - 1 ) : self . afi = LISP_AFI_IPV6
  elif ( addr_str . find ( "." ) != - 1 ) : self . afi = LISP_AFI_IPV4
  elif ( addr_str . find ( "+" ) != - 1 ) : self . afi = LISP_AFI_E164
  elif ( self . is_geo_string ( addr_str ) ) : self . afi = LISP_AFI_GEO_COORD
  elif ( addr_str . find ( "-" ) != - 1 ) : self . afi = LISP_AFI_MAC
  else : self . afi = LISP_AFI_NONE
  if 99 - 99: i11iIiiIii - o0oOOo0O0Ooo + o0oOOo0O0Ooo . OoooooooOO * iII111i . Oo0Ooo
  if 63 - 63: I11i
 def print_address ( self ) :
  IiiIIi1 = self . print_address_no_iid ( )
  o0OoO0000o = "[" + str ( self . instance_id )
  for IiIIi1IiiIiI in self . iid_list : o0OoO0000o += "," + str ( IiIIi1IiiIiI )
  o0OoO0000o += "]"
  IiiIIi1 = "{}{}" . format ( o0OoO0000o , IiiIIi1 )
  return ( IiiIIi1 )
  if 60 - 60: I1IiiI / I1ii11iIi11i / I11i / Ii1I + iIii1I11I1II1
  if 85 - 85: O0 / OOooOOo . OoOoOO00 / I1ii11iIi11i
 def print_address_no_iid ( self ) :
  if ( self . is_ipv4 ( ) ) :
   IiiIIi1 = self . address
   OO000o000ooO = IiiIIi1 >> 24
   iiiIi1ii = ( IiiIIi1 >> 16 ) & 0xff
   IiII1II1 = ( IiiIIi1 >> 8 ) & 0xff
   IiI1i1II = IiiIIi1 & 0xff
   return ( "{}.{}.{}.{}" . format ( OO000o000ooO , iiiIi1ii , IiII1II1 , IiI1i1II ) )
  elif ( self . is_ipv6 ( ) ) :
   oo0o00OO = lisp_hex_string ( self . address ) . zfill ( 32 )
   oo0o00OO = binascii . unhexlify ( oo0o00OO )
   oo0o00OO = socket . inet_ntop ( socket . AF_INET6 , oo0o00OO )
   return ( "{}" . format ( oo0o00OO ) )
  elif ( self . is_geo_prefix ( ) ) :
   return ( "{}" . format ( self . address . print_geo ( ) ) )
  elif ( self . is_mac ( ) ) :
   oo0o00OO = lisp_hex_string ( self . address ) . zfill ( 12 )
   oo0o00OO = "{}-{}-{}" . format ( oo0o00OO [ 0 : 4 ] , oo0o00OO [ 4 : 8 ] ,
 oo0o00OO [ 8 : 12 ] )
   return ( "{}" . format ( oo0o00OO ) )
  elif ( self . is_e164 ( ) ) :
   oo0o00OO = lisp_hex_string ( self . address ) . zfill ( 15 )
   return ( "+{}" . format ( oo0o00OO ) )
  elif ( self . is_dist_name ( ) ) :
   return ( "'{}'" . format ( self . address ) )
  elif ( self . is_null ( ) ) :
   return ( "no-address" )
   if 5 - 5: I11i - II111iiii * iIii1I11I1II1 / iIii1I11I1II1 % IiII * i1IIi
  return ( "unknown-afi:{}" . format ( self . afi ) )
  if 30 - 30: i1IIi % I1IiiI . OOooOOo % iIii1I11I1II1 . I1ii11iIi11i / o0oOOo0O0Ooo
  if 53 - 53: OOooOOo % ooOoO0o
 def print_prefix ( self ) :
  if ( self . is_ultimate_root ( ) ) : return ( "[*]" )
  if ( self . is_iid_range ( ) ) :
   if ( self . mask_len == 32 ) : return ( "[{}]" . format ( self . instance_id ) )
   OOOoo0Oo = self . instance_id + ( 2 ** ( 32 - self . mask_len ) - 1 )
   return ( "[{}-{}]" . format ( self . instance_id , OOOoo0Oo ) )
   if 83 - 83: IiII % I1Ii111 % IiII - O0 % I1ii11iIi11i
  IiiIIi1 = self . print_address ( )
  if ( self . is_dist_name ( ) ) : return ( IiiIIi1 )
  if ( self . is_geo_prefix ( ) ) : return ( IiiIIi1 )
  if 44 - 44: i11iIiiIii + oO0o * oO0o . i11iIiiIii % i1IIi + iII111i
  ooo = IiiIIi1 . find ( "no-address" )
  if ( ooo == - 1 ) :
   IiiIIi1 = "{}/{}" . format ( IiiIIi1 , str ( self . mask_len ) )
  else :
   IiiIIi1 = IiiIIi1 [ 0 : ooo ]
   if 91 - 91: I1Ii111 . II111iiii / Ii1I * O0
  return ( IiiIIi1 )
  if 33 - 33: oO0o * i1IIi + ooOoO0o * OOooOOo - O0 - iIii1I11I1II1
  if 35 - 35: I1Ii111
 def print_prefix_no_iid ( self ) :
  IiiIIi1 = self . print_address_no_iid ( )
  if ( self . is_dist_name ( ) ) : return ( IiiIIi1 )
  if ( self . is_geo_prefix ( ) ) : return ( IiiIIi1 )
  return ( "{}/{}" . format ( IiiIIi1 , str ( self . mask_len ) ) )
  if 12 - 12: Ii1I % I1IiiI - I11i / iIii1I11I1II1 . I1IiiI % I1ii11iIi11i
  if 12 - 12: Oo0Ooo + I1IiiI
 def print_prefix_url ( self ) :
  if ( self . is_ultimate_root ( ) ) : return ( "0--0" )
  IiiIIi1 = self . print_address ( )
  ooo = IiiIIi1 . find ( "]" )
  if ( ooo != - 1 ) : IiiIIi1 = IiiIIi1 [ ooo + 1 : : ]
  if ( self . is_geo_prefix ( ) ) :
   IiiIIi1 = IiiIIi1 . replace ( "/" , "-" )
   return ( "{}-{}" . format ( self . instance_id , IiiIIi1 ) )
   if 12 - 12: OoOoOO00 / II111iiii
  return ( "{}-{}-{}" . format ( self . instance_id , IiiIIi1 , self . mask_len ) )
  if 100 - 100: I1ii11iIi11i % iIii1I11I1II1 . IiII . OoooooooOO / II111iiii
  if 28 - 28: I1IiiI
 def print_sg ( self , g ) :
  IiII1iiI = self . print_prefix ( )
  IiIIIiIII1i = IiII1iiI . find ( "]" ) + 1
  g = g . print_prefix ( )
  iiI1i = g . find ( "]" ) + 1
  II11I = "[{}]({}, {})" . format ( self . instance_id , IiII1iiI [ IiIIIiIII1i : : ] , g [ iiI1i : : ] )
  return ( II11I )
  if 65 - 65: I11i + o0oOOo0O0Ooo
  if 60 - 60: ooOoO0o
 def hash_address ( self , addr ) :
  ooOo0O0 = self . address
  ooo0 = addr . address
  if 62 - 62: i11iIiiIii
  if ( self . is_geo_prefix ( ) ) : ooOo0O0 = self . address . print_geo ( )
  if ( addr . is_geo_prefix ( ) ) : ooo0 = addr . address . print_geo ( )
  if 88 - 88: i11iIiiIii
  if ( type ( ooOo0O0 ) == str ) :
   ooOo0O0 = int ( binascii . hexlify ( ooOo0O0 [ 0 : 1 ] ) )
   if 59 - 59: oO0o - OoooooooOO % ooOoO0o
  if ( type ( ooo0 ) == str ) :
   ooo0 = int ( binascii . hexlify ( ooo0 [ 0 : 1 ] ) )
   if 90 - 90: OoOoOO00
  return ( ooOo0O0 ^ ooo0 )
  if 96 - 96: II111iiii % Ii1I
  if 84 - 84: I1IiiI . I1IiiI
  if 82 - 82: OoO0O00 - iIii1I11I1II1 . iIii1I11I1II1 + I1ii11iIi11i
  if 45 - 45: iII111i . oO0o * iII111i
  if 3 - 3: OoOoOO00 / Oo0Ooo - Oo0Ooo
  if 54 - 54: Oo0Ooo . OoO0O00 * I1IiiI % IiII
 def is_more_specific ( self , prefix ) :
  if ( prefix . afi == LISP_AFI_ULTIMATE_ROOT ) : return ( True )
  if 97 - 97: o0oOOo0O0Ooo + Ii1I
  OO00O = prefix . mask_len
  if ( prefix . afi == LISP_AFI_IID_RANGE ) :
   o0oO0000 = 2 ** ( 32 - OO00O )
   OoOOii1i1iIIiI1 = prefix . instance_id
   OOOoo0Oo = OoOOii1i1iIIiI1 + o0oO0000
   return ( self . instance_id in range ( OoOOii1i1iIIiI1 , OOOoo0Oo ) )
   if 63 - 63: I11i
   if 47 - 47: Oo0Ooo
  if ( self . instance_id != prefix . instance_id ) : return ( False )
  if ( self . afi != prefix . afi ) :
   if ( prefix . afi != LISP_AFI_NONE ) : return ( False )
   if 10 - 10: ooOoO0o
   if 86 - 86: OoOoOO00 / Ii1I
   if 80 - 80: II111iiii
   if 66 - 66: ooOoO0o
   if 61 - 61: O0 / II111iiii + I1IiiI + I1ii11iIi11i * Oo0Ooo * I1ii11iIi11i
  if ( self . is_binary ( ) == False ) :
   if ( prefix . afi == LISP_AFI_NONE ) : return ( True )
   if ( type ( self . address ) != type ( prefix . address ) ) : return ( False )
   IiiIIi1 = self . address
   Ii11Ii1IiiIi = prefix . address
   if ( self . is_geo_prefix ( ) ) :
    IiiIIi1 = self . address . print_geo ( )
    Ii11Ii1IiiIi = prefix . address . print_geo ( )
    if 58 - 58: Oo0Ooo % iII111i
   if ( len ( IiiIIi1 ) < len ( Ii11Ii1IiiIi ) ) : return ( False )
   return ( IiiIIi1 . find ( Ii11Ii1IiiIi ) == 0 )
   if 43 - 43: oO0o * iII111i
   if 96 - 96: ooOoO0o % OOooOOo % OoO0O00 + OoOoOO00 % I11i
   if 85 - 85: ooOoO0o / iII111i / OoOoOO00 % I1ii11iIi11i
   if 1 - 1: I1ii11iIi11i + iIii1I11I1II1 . O0 + I1ii11iIi11i + I1IiiI + OOooOOo
   if 63 - 63: iIii1I11I1II1 . iIii1I11I1II1 . Ii1I . i1IIi + I1Ii111
  if ( self . mask_len < OO00O ) : return ( False )
  if 65 - 65: i11iIiiIii * oO0o + OoO0O00
  oOo0OOOoOoo = ( prefix . addr_length ( ) * 8 ) - OO00O
  i11111I1111 = ( 2 ** OO00O - 1 ) << oOo0OOOoOoo
  return ( ( self . address & i11111I1111 ) == prefix . address )
  if 86 - 86: iII111i - Ii1I / OoO0O00
  if 19 - 19: iIii1I11I1II1 / iII111i + OOooOOo . ooOoO0o
 def mask_address ( self , mask_len ) :
  oOo0OOOoOoo = ( self . addr_length ( ) * 8 ) - mask_len
  i11111I1111 = ( 2 ** mask_len - 1 ) << oOo0OOOoOoo
  self . address &= i11111I1111
  if 85 - 85: i1IIi
  if 78 - 78: oO0o
 def is_exact_match ( self , prefix ) :
  if ( self . instance_id != prefix . instance_id ) : return ( False )
  i1i11I1iII11 = self . print_prefix ( )
  iIiIiI11IIi = prefix . print_prefix ( ) if prefix else ""
  return ( i1i11I1iII11 == iIiIiI11IIi )
  if 11 - 11: I1Ii111 - Oo0Ooo / iIii1I11I1II1 - OoooooooOO
  if 71 - 71: Oo0Ooo + Ii1I - OoooooooOO + I11i - iIii1I11I1II1 / O0
 def is_local ( self ) :
  if ( self . is_ipv4 ( ) ) :
   OooO0o000Oo = lisp_myrlocs [ 0 ]
   if ( OooO0o000Oo == None ) : return ( False )
   OooO0o000Oo = OooO0o000Oo . print_address_no_iid ( )
   return ( self . print_address_no_iid ( ) == OooO0o000Oo )
   if 82 - 82: I1Ii111 * iIii1I11I1II1 % o0oOOo0O0Ooo . OOooOOo * II111iiii
  if ( self . is_ipv6 ( ) ) :
   OooO0o000Oo = lisp_myrlocs [ 1 ]
   if ( OooO0o000Oo == None ) : return ( False )
   OooO0o000Oo = OooO0o000Oo . print_address_no_iid ( )
   return ( self . print_address_no_iid ( ) == OooO0o000Oo )
   if 86 - 86: I1ii11iIi11i
  return ( False )
  if 8 - 8: OOooOOo / Oo0Ooo + OoO0O00 + I1ii11iIi11i + OoooooooOO % i1IIi
  if 46 - 46: OoOoOO00
 def store_iid_range ( self , iid , mask_len ) :
  if ( self . afi == LISP_AFI_NONE ) :
   if ( iid == 0 and mask_len == 0 ) : self . afi = LISP_AFI_ULTIMATE_ROOT
   else : self . afi = LISP_AFI_IID_RANGE
   if 75 - 75: I1IiiI
  self . instance_id = iid
  self . mask_len = mask_len
  if 37 - 37: iIii1I11I1II1 % OoO0O00 * ooOoO0o + I11i % ooOoO0o / i11iIiiIii
  if 14 - 14: i1IIi / ooOoO0o
 def lcaf_length ( self , lcaf_type ) :
  IiiI1iii1iIiiI = self . addr_length ( ) + 2
  if ( lcaf_type == LISP_LCAF_AFI_LIST_TYPE ) : IiiI1iii1iIiiI += 4
  if ( lcaf_type == LISP_LCAF_INSTANCE_ID_TYPE ) : IiiI1iii1iIiiI += 4
  if ( lcaf_type == LISP_LCAF_ASN_TYPE ) : IiiI1iii1iIiiI += 4
  if ( lcaf_type == LISP_LCAF_APP_DATA_TYPE ) : IiiI1iii1iIiiI += 8
  if ( lcaf_type == LISP_LCAF_GEO_COORD_TYPE ) : IiiI1iii1iIiiI += 12
  if ( lcaf_type == LISP_LCAF_OPAQUE_TYPE ) : IiiI1iii1iIiiI += 0
  if ( lcaf_type == LISP_LCAF_NAT_TYPE ) : IiiI1iii1iIiiI += 4
  if ( lcaf_type == LISP_LCAF_NONCE_LOC_TYPE ) : IiiI1iii1iIiiI += 4
  if ( lcaf_type == LISP_LCAF_MCAST_INFO_TYPE ) : IiiI1iii1iIiiI = IiiI1iii1iIiiI * 2 + 8
  if ( lcaf_type == LISP_LCAF_ELP_TYPE ) : IiiI1iii1iIiiI += 0
  if ( lcaf_type == LISP_LCAF_SECURITY_TYPE ) : IiiI1iii1iIiiI += 6
  if ( lcaf_type == LISP_LCAF_SOURCE_DEST_TYPE ) : IiiI1iii1iIiiI += 4
  if ( lcaf_type == LISP_LCAF_RLE_TYPE ) : IiiI1iii1iIiiI += 4
  return ( IiiI1iii1iIiiI )
  if 10 - 10: ooOoO0o / OoooooooOO - ooOoO0o % O0 + oO0o - oO0o
  if 16 - 16: O0
  if 14 - 14: Ii1I . Ii1I . OOooOOo - O0 / OoO0O00 % II111iiii
  if 5 - 5: iIii1I11I1II1 % OoOoOO00 % OOooOOo % O0 * oO0o . iIii1I11I1II1
  if 96 - 96: i11iIiiIii + oO0o / I1ii11iIi11i . IiII % o0oOOo0O0Ooo
  if 41 - 41: o0oOOo0O0Ooo . i1IIi - OOooOOo
  if 19 - 19: o0oOOo0O0Ooo % I1Ii111 % I11i
  if 1 - 1: I1IiiI / o0oOOo0O0Ooo - I1Ii111
  if 50 - 50: I11i - OoOoOO00 + I1IiiI % Oo0Ooo / OoooooooOO - I1ii11iIi11i
  if 26 - 26: IiII . Ii1I
  if 35 - 35: I1ii11iIi11i + OOooOOo
  if 88 - 88: O0
  if 4 - 4: OoOoOO00 % iIii1I11I1II1 % OoooooooOO . oO0o
  if 27 - 27: II111iiii - OoOoOO00
  if 81 - 81: o0oOOo0O0Ooo - Oo0Ooo % IiII - ooOoO0o / O0
  if 27 - 27: Oo0Ooo
  if 15 - 15: iIii1I11I1II1 . OoOoOO00 % Ii1I / i1IIi . o0oOOo0O0Ooo
 def lcaf_encode_iid ( self ) :
  iI1IIiI111iII = LISP_LCAF_INSTANCE_ID_TYPE
  Iii1i11 = socket . htons ( self . lcaf_length ( iI1IIiI111iII ) )
  o0OoO0000o = self . instance_id
  O0ooo0 = self . afi
  iiIII = 0
  if ( O0ooo0 < 0 ) :
   if ( self . afi == LISP_AFI_GEO_COORD ) :
    O0ooo0 = LISP_AFI_LCAF
    iiIII = 0
   else :
    O0ooo0 = 0
    iiIII = self . mask_len
    if 45 - 45: iIii1I11I1II1 - i1IIi % I1IiiI - I1Ii111 + oO0o
    if 15 - 15: iIii1I11I1II1 - OoooooooOO / ooOoO0o
    if 83 - 83: IiII + I1Ii111 / OoOoOO00 * IiII . oO0o
  iiI11I = struct . pack ( "BBBBH" , 0 , 0 , iI1IIiI111iII , iiIII , Iii1i11 )
  iiI11I += struct . pack ( "IH" , socket . htonl ( o0OoO0000o ) , socket . htons ( O0ooo0 ) )
  if ( O0ooo0 == 0 ) : return ( iiI11I )
  if 82 - 82: OOooOOo
  if ( self . afi == LISP_AFI_GEO_COORD ) :
   iiI11I = iiI11I [ 0 : - 2 ]
   iiI11I += self . address . encode_geo ( )
   return ( iiI11I )
   if 65 - 65: OoooooooOO - I1ii11iIi11i * iII111i . I1Ii111 / OoO0O00 / oO0o
   if 31 - 31: i11iIiiIii / o0oOOo0O0Ooo . OOooOOo + II111iiii
  iiI11I += self . pack_address ( )
  return ( iiI11I )
  if 14 - 14: Ii1I + OoooooooOO - I1Ii111 + I1Ii111 % IiII % OoooooooOO
  if 24 - 24: I1Ii111 . Oo0Ooo / ooOoO0o * O0
 def lcaf_decode_iid ( self , packet ) :
  i1I1iii1I11II = "BBBBH"
  Iiiii = struct . calcsize ( i1I1iii1I11II )
  if ( len ( packet ) < Iiiii ) : return ( None )
  if 85 - 85: I1IiiI - OOooOOo
  O0O , IIIi1i1iIIIi , iI1IIiI111iII , iiiiIiiiiI , IiiI1iii1iIiiI = struct . unpack ( i1I1iii1I11II ,
 packet [ : Iiiii ] )
  packet = packet [ Iiiii : : ]
  if 69 - 69: II111iiii * O0 . ooOoO0o * IiII
  if ( iI1IIiI111iII != LISP_LCAF_INSTANCE_ID_TYPE ) : return ( None )
  if 25 - 25: I11i - I1ii11iIi11i . I1Ii111 . OoooooooOO
  i1I1iii1I11II = "IH"
  Iiiii = struct . calcsize ( i1I1iii1I11II )
  if ( len ( packet ) < Iiiii ) : return ( None )
  if 4 - 4: IiII * OoO0O00 % I1ii11iIi11i * Ii1I . iII111i
  o0OoO0000o , O0ooo0 = struct . unpack ( i1I1iii1I11II , packet [ : Iiiii ] )
  packet = packet [ Iiiii : : ]
  if 41 - 41: OoooooooOO % I11i . O0 + I1Ii111
  IiiI1iii1iIiiI = socket . ntohs ( IiiI1iii1iIiiI )
  self . instance_id = socket . ntohl ( o0OoO0000o )
  O0ooo0 = socket . ntohs ( O0ooo0 )
  self . afi = O0ooo0
  if ( iiiiIiiiiI != 0 and O0ooo0 == 0 ) : self . mask_len = iiiiIiiiiI
  if ( O0ooo0 == 0 ) :
   self . afi = LISP_AFI_IID_RANGE if iiiiIiiiiI else LISP_AFI_ULTIMATE_ROOT
   if 67 - 67: OoOoOO00 * OOooOOo / OOooOOo / OoooooooOO
   if 67 - 67: I11i - i1IIi . OoooooooOO / iIii1I11I1II1
   if 34 - 34: OoO0O00 * II111iiii
   if 43 - 43: OoOoOO00 . I1IiiI
   if 44 - 44: O0 / o0oOOo0O0Ooo
  if ( O0ooo0 == 0 ) : return ( packet )
  if 19 - 19: I11i
  if 91 - 91: OOooOOo * OoooooooOO
  if 89 - 89: i1IIi / iII111i . I1Ii111
  if 74 - 74: I1ii11iIi11i % iII111i / OoooooooOO / I1ii11iIi11i % i11iIiiIii % ooOoO0o
  if ( self . is_dist_name ( ) ) :
   packet , self . address = lisp_decode_dist_name ( packet )
   self . mask_len = len ( self . address ) * 8
   return ( packet )
   if 82 - 82: OoooooooOO . o0oOOo0O0Ooo * I1ii11iIi11i % I1ii11iIi11i * Ii1I
   if 83 - 83: I11i - Oo0Ooo + i11iIiiIii - i11iIiiIii
   if 64 - 64: IiII % I1IiiI / ooOoO0o
   if 74 - 74: OoooooooOO
   if 22 - 22: II111iiii . O0 * I1Ii111 % OoO0O00 / OoooooooOO + I1Ii111
  if ( O0ooo0 == LISP_AFI_LCAF ) :
   i1I1iii1I11II = "BBBBH"
   Iiiii = struct . calcsize ( i1I1iii1I11II )
   if ( len ( packet ) < Iiiii ) : return ( None )
   if 71 - 71: ooOoO0o . oO0o * OoooooooOO + iII111i - I1Ii111 . I1ii11iIi11i
   Ii1IiIIIi1i , II111Ii1I1I , iI1IIiI111iII , o00oo0oOo0o0 , oOOO0O000Oo = struct . unpack ( i1I1iii1I11II , packet [ : Iiiii ] )
   if 100 - 100: I11i + O0 - o0oOOo0O0Ooo * I1ii11iIi11i
   if 94 - 94: Oo0Ooo . IiII / Ii1I / oO0o - I1IiiI
   if ( iI1IIiI111iII != LISP_LCAF_GEO_COORD_TYPE ) : return ( None )
   if 77 - 77: i11iIiiIii . Ii1I - Ii1I
   oOOO0O000Oo = socket . ntohs ( oOOO0O000Oo )
   packet = packet [ Iiiii : : ]
   if ( oOOO0O000Oo > len ( packet ) ) : return ( None )
   if 47 - 47: iII111i % OOooOOo . I1ii11iIi11i + I1ii11iIi11i . I1Ii111
   I1Ii1i111I = lisp_geo ( "" )
   self . afi = LISP_AFI_GEO_COORD
   self . address = I1Ii1i111I
   packet = I1Ii1i111I . decode_geo ( packet , oOOO0O000Oo , o00oo0oOo0o0 )
   self . mask_len = self . host_mask_len ( )
   return ( packet )
   if 20 - 20: oO0o - o0oOOo0O0Ooo + I1IiiI % OoOoOO00
   if 41 - 41: oO0o . ooOoO0o
  Iii1i11 = self . addr_length ( )
  if ( len ( packet ) < Iii1i11 ) : return ( None )
  if 59 - 59: iIii1I11I1II1 - I1IiiI . ooOoO0o
  packet = self . unpack_address ( packet )
  return ( packet )
  if 58 - 58: I1IiiI * I1Ii111 + iII111i + iIii1I11I1II1 + I1IiiI
  if 78 - 78: Oo0Ooo + ooOoO0o
  if 56 - 56: OoO0O00 / i1IIi + ooOoO0o . ooOoO0o . iII111i
  if 37 - 37: iIii1I11I1II1 * OoOoOO00 . OoOoOO00 + OoooooooOO + OoO0O00
  if 25 - 25: I1IiiI / IiII . OOooOOo . I1ii11iIi11i % i1IIi
  if 12 - 12: O0 % O0
  if 9 - 9: O0 . I1IiiI + I1ii11iIi11i / OOooOOo * I1ii11iIi11i
  if 10 - 10: IiII % o0oOOo0O0Ooo / O0 / II111iiii
  if 81 - 81: Ii1I / o0oOOo0O0Ooo % OoOoOO00 . I1ii11iIi11i
  if 47 - 47: II111iiii + OOooOOo / II111iiii . OOooOOo
  if 68 - 68: OoooooooOO
  if 63 - 63: I1IiiI
  if 80 - 80: oO0o + iIii1I11I1II1
  if 87 - 87: I1ii11iIi11i % Ii1I . Ii1I
  if 71 - 71: OoO0O00 - IiII . i1IIi * I1IiiI % I11i
  if 36 - 36: IiII * OoooooooOO . i11iIiiIii * i1IIi
  if 52 - 52: IiII + ooOoO0o - II111iiii - OoooooooOO * OoO0O00 - iIii1I11I1II1
  if 38 - 38: II111iiii % iIii1I11I1II1 * IiII * OoOoOO00 % II111iiii . I1IiiI
  if 35 - 35: OoooooooOO - i11iIiiIii * i11iIiiIii % Ii1I - OOooOOo . iIii1I11I1II1
  if 96 - 96: OOooOOo
  if 18 - 18: oO0o . I1ii11iIi11i % oO0o
 def lcaf_encode_sg ( self , group ) :
  iI1IIiI111iII = LISP_LCAF_MCAST_INFO_TYPE
  o0OoO0000o = socket . htonl ( self . instance_id )
  Iii1i11 = socket . htons ( self . lcaf_length ( iI1IIiI111iII ) )
  iiI11I = struct . pack ( "BBBBHIHBB" , 0 , 0 , iI1IIiI111iII , 0 , Iii1i11 , o0OoO0000o ,
 0 , self . mask_len , group . mask_len )
  if 43 - 43: oO0o / ooOoO0o . o0oOOo0O0Ooo . iIii1I11I1II1
  iiI11I += struct . pack ( "H" , socket . htons ( self . afi ) )
  iiI11I += self . pack_address ( )
  iiI11I += struct . pack ( "H" , socket . htons ( group . afi ) )
  iiI11I += group . pack_address ( )
  return ( iiI11I )
  if 63 - 63: iII111i * iII111i
  if 78 - 78: iIii1I11I1II1 % iIii1I11I1II1 . iIii1I11I1II1 / Ii1I . O0 + i1IIi
 def lcaf_decode_sg ( self , packet ) :
  i1I1iii1I11II = "BBBBHIHBB"
  Iiiii = struct . calcsize ( i1I1iii1I11II )
  if ( len ( packet ) < Iiiii ) : return ( [ None , None ] )
  if 53 - 53: Ii1I . I1ii11iIi11i - OOooOOo - ooOoO0o
  O0O , IIIi1i1iIIIi , iI1IIiI111iII , i1o00Oo , IiiI1iii1iIiiI , o0OoO0000o , Ii1i , OOO , IIi1iII1i11 = struct . unpack ( i1I1iii1I11II , packet [ : Iiiii ] )
  if 9 - 9: iII111i - II111iiii
  packet = packet [ Iiiii : : ]
  if 14 - 14: IiII % I1Ii111 * I1Ii111
  if ( iI1IIiI111iII != LISP_LCAF_MCAST_INFO_TYPE ) : return ( [ None , None ] )
  if 64 - 64: Ii1I % OoooooooOO . OOooOOo + i11iIiiIii + o0oOOo0O0Ooo + iII111i
  self . instance_id = socket . ntohl ( o0OoO0000o )
  IiiI1iii1iIiiI = socket . ntohs ( IiiI1iii1iIiiI ) - 8
  if 65 - 65: OoO0O00 % i1IIi / Ii1I % IiII
  if 100 - 100: oO0o . i11iIiiIii - ooOoO0o
  if 49 - 49: Oo0Ooo % ooOoO0o % o0oOOo0O0Ooo + ooOoO0o * I1Ii111 % I1IiiI
  if 85 - 85: i1IIi / i1IIi
  if 77 - 77: i1IIi . ooOoO0o % ooOoO0o - Ii1I
  i1I1iii1I11II = "H"
  Iiiii = struct . calcsize ( i1I1iii1I11II )
  if ( len ( packet ) < Iiiii ) : return ( [ None , None ] )
  if ( IiiI1iii1iIiiI < Iiiii ) : return ( [ None , None ] )
  if 6 - 6: OOooOOo % Ii1I + ooOoO0o
  O0ooo0 = struct . unpack ( i1I1iii1I11II , packet [ : Iiiii ] ) [ 0 ]
  packet = packet [ Iiiii : : ]
  IiiI1iii1iIiiI -= Iiiii
  self . afi = socket . ntohs ( O0ooo0 )
  self . mask_len = OOO
  Iii1i11 = self . addr_length ( )
  if ( IiiI1iii1iIiiI < Iii1i11 ) : return ( [ None , None ] )
  if 17 - 17: iIii1I11I1II1 * I1Ii111 % oO0o + o0oOOo0O0Ooo . Ii1I * Oo0Ooo
  packet = self . unpack_address ( packet )
  if ( packet == None ) : return ( [ None , None ] )
  if 16 - 16: I1IiiI % OoO0O00 . ooOoO0o / OoooooooOO
  IiiI1iii1iIiiI -= Iii1i11
  if 8 - 8: I1Ii111 % OoO0O00 . I1IiiI - OoOoOO00 + i1IIi / iIii1I11I1II1
  if 89 - 89: II111iiii / Ii1I % Ii1I
  if 57 - 57: I11i
  if 95 - 95: OoOoOO00 + I11i * i1IIi - ooOoO0o % ooOoO0o
  if 58 - 58: OOooOOo
  i1I1iii1I11II = "H"
  Iiiii = struct . calcsize ( i1I1iii1I11II )
  if ( len ( packet ) < Iiiii ) : return ( [ None , None ] )
  if ( IiiI1iii1iIiiI < Iiiii ) : return ( [ None , None ] )
  if 74 - 74: i1IIi . IiII / ooOoO0o + I11i % i11iIiiIii % iII111i
  O0ooo0 = struct . unpack ( i1I1iii1I11II , packet [ : Iiiii ] ) [ 0 ]
  packet = packet [ Iiiii : : ]
  IiiI1iii1iIiiI -= Iiiii
  IIi1iiIII11 = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  IIi1iiIII11 . afi = socket . ntohs ( O0ooo0 )
  IIi1iiIII11 . mask_len = IIi1iII1i11
  IIi1iiIII11 . instance_id = self . instance_id
  Iii1i11 = self . addr_length ( )
  if ( IiiI1iii1iIiiI < Iii1i11 ) : return ( [ None , None ] )
  if 62 - 62: i1IIi % I1Ii111
  packet = IIi1iiIII11 . unpack_address ( packet )
  if ( packet == None ) : return ( [ None , None ] )
  if 94 - 94: i1IIi + iII111i
  return ( [ packet , IIi1iiIII11 ] )
  if 25 - 25: I1Ii111 . Ii1I - Ii1I . o0oOOo0O0Ooo - IiII
  if 91 - 91: o0oOOo0O0Ooo % I1ii11iIi11i % OoOoOO00 * iIii1I11I1II1
 def lcaf_decode_eid ( self , packet ) :
  i1I1iii1I11II = "BBB"
  Iiiii = struct . calcsize ( i1I1iii1I11II )
  if ( len ( packet ) < Iiiii ) : return ( [ None , None ] )
  if 18 - 18: OoOoOO00 * I1ii11iIi11i . i1IIi * iII111i
  if 67 - 67: IiII + i11iIiiIii . II111iiii / OoOoOO00 + OoooooooOO + i11iIiiIii
  if 23 - 23: Oo0Ooo
  if 7 - 7: Oo0Ooo / oO0o . I1Ii111 % I11i
  if 85 - 85: II111iiii / o0oOOo0O0Ooo . iIii1I11I1II1 . OoooooooOO / Ii1I
  i1o00Oo , II111Ii1I1I , iI1IIiI111iII = struct . unpack ( i1I1iii1I11II ,
 packet [ : Iiiii ] )
  if 18 - 18: i11iIiiIii + o0oOOo0O0Ooo . i11iIiiIii
  if ( iI1IIiI111iII == LISP_LCAF_INSTANCE_ID_TYPE ) :
   return ( [ self . lcaf_decode_iid ( packet ) , None ] )
  elif ( iI1IIiI111iII == LISP_LCAF_MCAST_INFO_TYPE ) :
   packet , IIi1iiIII11 = self . lcaf_decode_sg ( packet )
   return ( [ packet , IIi1iiIII11 ] )
  elif ( iI1IIiI111iII == LISP_LCAF_GEO_COORD_TYPE ) :
   i1I1iii1I11II = "BBBBH"
   Iiiii = struct . calcsize ( i1I1iii1I11II )
   if ( len ( packet ) < Iiiii ) : return ( None )
   if 50 - 50: IiII / OoooooooOO . I11i
   Ii1IiIIIi1i , II111Ii1I1I , iI1IIiI111iII , o00oo0oOo0o0 , oOOO0O000Oo = struct . unpack ( i1I1iii1I11II , packet [ : Iiiii ] )
   if 93 - 93: OOooOOo / OoooooooOO % iII111i % Ii1I / I1Ii111 % OOooOOo
   if 25 - 25: i1IIi % Oo0Ooo . i1IIi * OoOoOO00 . Ii1I % OoO0O00
   if ( iI1IIiI111iII != LISP_LCAF_GEO_COORD_TYPE ) : return ( None )
   if 47 - 47: o0oOOo0O0Ooo - i11iIiiIii / OoooooooOO
   oOOO0O000Oo = socket . ntohs ( oOOO0O000Oo )
   packet = packet [ Iiiii : : ]
   if ( oOOO0O000Oo > len ( packet ) ) : return ( None )
   if 93 - 93: I1IiiI * II111iiii * O0 % o0oOOo0O0Ooo + oO0o / ooOoO0o
   I1Ii1i111I = lisp_geo ( "" )
   self . instance_id = 0
   self . afi = LISP_AFI_GEO_COORD
   self . address = I1Ii1i111I
   packet = I1Ii1i111I . decode_geo ( packet , oOOO0O000Oo , o00oo0oOo0o0 )
   self . mask_len = self . host_mask_len ( )
   if 79 - 79: OoO0O00 + ooOoO0o / oO0o % I1ii11iIi11i
  return ( [ packet , None ] )
  if 77 - 77: Ii1I / Ii1I / I1ii11iIi11i
  if 92 - 92: O0 * i11iIiiIii . OoOoOO00 * IiII / o0oOOo0O0Ooo * ooOoO0o
  if 74 - 74: O0 - o0oOOo0O0Ooo
  if 68 - 68: I1Ii111
  if 19 - 19: o0oOOo0O0Ooo
  if 63 - 63: OoooooooOO % ooOoO0o
class lisp_elp_node ( ) :
 def __init__ ( self ) :
  self . address = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . probe = False
  self . strict = False
  self . eid = False
  self . we_are_last = False
  if 26 - 26: OOooOOo + Oo0Ooo
  if 97 - 97: I1Ii111 * I1Ii111 + iII111i % Ii1I / iII111i
 def copy_elp_node ( self ) :
  IIii = lisp_elp_node ( )
  IIii . copy_address ( self . address )
  IIii . probe = self . probe
  IIii . strict = self . strict
  IIii . eid = self . eid
  IIii . we_are_last = self . we_are_last
  return ( IIii )
  if 73 - 73: OoOoOO00 % I1Ii111 . I1ii11iIi11i
  if 45 - 45: iIii1I11I1II1 % Ii1I . OoOoOO00 . o0oOOo0O0Ooo - OoooooooOO
  if 46 - 46: I1ii11iIi11i
class lisp_elp ( ) :
 def __init__ ( self , name ) :
  self . elp_name = name
  self . elp_nodes = [ ]
  self . use_elp_node = None
  self . we_are_last = False
  if 32 - 32: iII111i * i11iIiiIii / IiII + i11iIiiIii + O0
  if 51 - 51: I1Ii111
 def copy_elp ( self ) :
  O0OoO0O0O0oO = lisp_elp ( self . elp_name )
  O0OoO0O0O0oO . use_elp_node = self . use_elp_node
  O0OoO0O0O0oO . we_are_last = self . we_are_last
  for IIii in self . elp_nodes :
   O0OoO0O0O0oO . elp_nodes . append ( IIii . copy_elp_node ( ) )
   if 95 - 95: Ii1I / Ii1I * OoO0O00 . OoooooooOO . OoooooooOO * I11i
  return ( O0OoO0O0O0oO )
  if 76 - 76: OoooooooOO - Ii1I + IiII % OoOoOO00 / OoooooooOO
  if 55 - 55: i11iIiiIii - IiII * OOooOOo + II111iiii . I1ii11iIi11i / O0
 def print_elp ( self , want_marker ) :
  Oo = ""
  for IIii in self . elp_nodes :
   Ii1iIIi1IIiIi1I = ""
   if ( want_marker ) :
    if ( IIii == self . use_elp_node ) :
     Ii1iIIi1IIiIi1I = "*"
    elif ( IIii . we_are_last ) :
     Ii1iIIi1IIiIi1I = "x"
     if 22 - 22: o0oOOo0O0Ooo * o0oOOo0O0Ooo % I1IiiI
     if 66 - 66: OoOoOO00 % ooOoO0o - II111iiii . oO0o / i11iIiiIii
   Oo += "{}{}({}{}{}), " . format ( Ii1iIIi1IIiIi1I ,
 IIii . address . print_address_no_iid ( ) ,
 "r" if IIii . eid else "R" , "P" if IIii . probe else "p" ,
 "S" if IIii . strict else "s" )
   if 73 - 73: OoO0O00 - i1IIi
  return ( Oo [ 0 : - 2 ] if Oo != "" else "" )
  if 52 - 52: I1ii11iIi11i
  if 4 - 4: Ii1I - iII111i + i1IIi - I1Ii111 / iII111i . Oo0Ooo
 def select_elp_node ( self ) :
  iIIi1I1Iiii , OO0oOO00OOo , OoO0o0OOOO = lisp_myrlocs
  ooo = None
  if 2 - 2: I1IiiI + II111iiii . ooOoO0o + oO0o . OoO0O00
  for IIii in self . elp_nodes :
   if ( iIIi1I1Iiii and IIii . address . is_exact_match ( iIIi1I1Iiii ) ) :
    ooo = self . elp_nodes . index ( IIii )
    break
    if 49 - 49: OoO0O00 . IiII
   if ( OO0oOO00OOo and IIii . address . is_exact_match ( OO0oOO00OOo ) ) :
    ooo = self . elp_nodes . index ( IIii )
    break
    if 41 - 41: OoooooooOO + oO0o % oO0o / I1ii11iIi11i
    if 86 - 86: i1IIi
    if 73 - 73: iIii1I11I1II1 * Oo0Ooo
    if 54 - 54: oO0o . Ii1I
    if 31 - 31: I11i
    if 60 - 60: Oo0Ooo - iII111i . II111iiii % ooOoO0o / OoooooooOO / iIii1I11I1II1
    if 23 - 23: I11i + iIii1I11I1II1
  if ( ooo == None ) :
   self . use_elp_node = self . elp_nodes [ 0 ]
   IIii . we_are_last = False
   return
   if 60 - 60: O0 * I1IiiI + o0oOOo0O0Ooo * OoO0O00 + o0oOOo0O0Ooo / i11iIiiIii
   if 54 - 54: i11iIiiIii . iII111i * i1IIi
   if 68 - 68: Oo0Ooo
   if 20 - 20: IiII + i11iIiiIii * OOooOOo
   if 27 - 27: O0 * OoO0O00 * I1ii11iIi11i
   if 40 - 40: O0 + oO0o - ooOoO0o + I1IiiI - IiII
  if ( self . elp_nodes [ - 1 ] == self . elp_nodes [ ooo ] ) :
   self . use_elp_node = None
   IIii . we_are_last = True
   return
   if 60 - 60: I1Ii111 * OoO0O00 * oO0o + oO0o
   if 34 - 34: o0oOOo0O0Ooo
   if 76 - 76: oO0o + OoooooooOO % OoOoOO00 / OoOoOO00
   if 51 - 51: II111iiii / OoOoOO00
   if 69 - 69: i11iIiiIii
  self . use_elp_node = self . elp_nodes [ ooo + 1 ]
  return
  if 77 - 77: I1ii11iIi11i % OoooooooOO - Oo0Ooo - Ii1I + I11i
  if 93 - 93: I1IiiI % O0 * OoO0O00 % OoOoOO00 . I1Ii111 * I1IiiI
  if 95 - 95: IiII + o0oOOo0O0Ooo - o0oOOo0O0Ooo
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
  if 83 - 83: ooOoO0o
  if 59 - 59: I1ii11iIi11i
 def copy_geo ( self ) :
  I1Ii1i111I = lisp_geo ( self . geo_name )
  I1Ii1i111I . latitude = self . latitude
  I1Ii1i111I . lat_mins = self . lat_mins
  I1Ii1i111I . lat_secs = self . lat_secs
  I1Ii1i111I . longitude = self . longitude
  I1Ii1i111I . long_mins = self . long_mins
  I1Ii1i111I . long_secs = self . long_secs
  I1Ii1i111I . altitude = self . altitude
  I1Ii1i111I . radius = self . radius
  return ( I1Ii1i111I )
  if 26 - 26: I11i . Ii1I
  if 94 - 94: ooOoO0o . I1IiiI + IiII % I1IiiI / o0oOOo0O0Ooo % o0oOOo0O0Ooo
 def no_geo_altitude ( self ) :
  return ( self . altitude == - 1 )
  if 21 - 21: O0 / OOooOOo - II111iiii + I1ii11iIi11i / OoooooooOO
  if 81 - 81: i11iIiiIii / Oo0Ooo * i1IIi + OoO0O00 + O0 % I1ii11iIi11i
 def parse_geo_string ( self , geo_str ) :
  ooo = geo_str . find ( "]" )
  if ( ooo != - 1 ) : geo_str = geo_str [ ooo + 1 : : ]
  if 3 - 3: i11iIiiIii * IiII . Oo0Ooo % OoOoOO00 * I11i . iII111i
  if 80 - 80: I11i - IiII
  if 40 - 40: OOooOOo * I1IiiI % I11i . I1Ii111 % O0 . O0
  if 14 - 14: ooOoO0o . OoOoOO00 + ooOoO0o * OoOoOO00 . OoOoOO00 * Oo0Ooo
  if 40 - 40: OoooooooOO
  if ( geo_str . find ( "/" ) != - 1 ) :
   geo_str , IIi1ooO0oOOoOO = geo_str . split ( "/" )
   self . radius = int ( IIi1ooO0oOOoOO )
   if 58 - 58: OoOoOO00 / I1Ii111 % O0
   if 14 - 14: I1IiiI . OOooOOo
  geo_str = geo_str . split ( "-" )
  if ( len ( geo_str ) < 8 ) : return ( False )
  if 28 - 28: iII111i / oO0o / iII111i
  ooOO00 = geo_str [ 0 : 4 ]
  O0OOoOOoO000O = geo_str [ 4 : 8 ]
  if 89 - 89: OOooOOo + iIii1I11I1II1 . OOooOOo
  if 68 - 68: I1Ii111 . I1ii11iIi11i - OoooooooOO . I1Ii111
  if 58 - 58: Ii1I . Oo0Ooo
  if 28 - 28: Ii1I . II111iiii - OOooOOo / iIii1I11I1II1 - I1IiiI
  if ( len ( geo_str ) > 8 ) : self . altitude = int ( geo_str [ 8 ] )
  if 78 - 78: iIii1I11I1II1
  if 64 - 64: OoOoOO00 - oO0o
  if 8 - 8: i11iIiiIii - iIii1I11I1II1 / I1Ii111 . i11iIiiIii % o0oOOo0O0Ooo / oO0o
  if 36 - 36: IiII
  self . latitude = int ( ooOO00 [ 0 ] )
  self . lat_mins = int ( ooOO00 [ 1 ] )
  self . lat_secs = int ( ooOO00 [ 2 ] )
  if ( ooOO00 [ 3 ] == "N" ) : self . latitude = - self . latitude
  if 53 - 53: OoooooooOO / I1IiiI % I11i + Oo0Ooo
  if 15 - 15: O0
  if 75 - 75: iII111i / OoOoOO00
  if 2 - 2: i1IIi + oO0o % iII111i % I1ii11iIi11i + ooOoO0o . iII111i
  self . longitude = int ( O0OOoOOoO000O [ 0 ] )
  self . long_mins = int ( O0OOoOOoO000O [ 1 ] )
  self . long_secs = int ( O0OOoOOoO000O [ 2 ] )
  if ( O0OOoOOoO000O [ 3 ] == "E" ) : self . longitude = - self . longitude
  return ( True )
  if 26 - 26: I11i + o0oOOo0O0Ooo + Ii1I % I11i
  if 95 - 95: IiII - O0 * oO0o * O0
 def print_geo ( self ) :
  iii1I = "N" if self . latitude < 0 else "S"
  iIII = "E" if self . longitude < 0 else "W"
  if 73 - 73: OOooOOo / Oo0Ooo
  Ii1IIIIiI11 = "{}-{}-{}-{}-{}-{}-{}-{}" . format ( abs ( self . latitude ) ,
 self . lat_mins , self . lat_secs , iii1I , abs ( self . longitude ) ,
 self . long_mins , self . long_secs , iIII )
  if 80 - 80: OoO0O00 + I1IiiI % i1IIi / I11i % i1IIi * i11iIiiIii
  if ( self . no_geo_altitude ( ) == False ) :
   Ii1IIIIiI11 += "-" + str ( self . altitude )
   if 27 - 27: OoOoOO00 / I1Ii111 * O0 / I1IiiI - IiII / o0oOOo0O0Ooo
   if 70 - 70: I1ii11iIi11i
   if 11 - 11: I1Ii111
   if 70 - 70: Ii1I
   if 22 - 22: Ii1I
  if ( self . radius != 0 ) : Ii1IIIIiI11 += "/{}" . format ( self . radius )
  return ( Ii1IIIIiI11 )
  if 59 - 59: I1ii11iIi11i
  if 90 - 90: OOooOOo / iII111i
 def geo_url ( self ) :
  oO0O0Oo0 = os . getenv ( "LISP_GEO_ZOOM_LEVEL" )
  oO0O0Oo0 = "10" if ( oO0O0Oo0 == "" or oO0O0Oo0 . isdigit ( ) == False ) else oO0O0Oo0
  iIIIII1i1III , iiIIIii1iII = self . dms_to_decimal ( )
  oooOoo00 = ( "http://maps.googleapis.com/maps/api/staticmap?center={},{}" + "&markers=color:blue%7Clabel:lisp%7C{},{}" + "&zoom={}&size=1024x1024&sensor=false" ) . format ( iIIIII1i1III , iiIIIii1iII , iIIIII1i1III , iiIIIii1iII ,
  # OoOoOO00 - oO0o + II111iiii . i1IIi / Oo0Ooo
  # Ii1I + I1Ii111 * Oo0Ooo + OoOoOO00 / I1Ii111 - ooOoO0o
 oO0O0Oo0 )
  return ( oooOoo00 )
  if 66 - 66: I11i * OoO0O00
  if 98 - 98: IiII . Oo0Ooo + I1Ii111
 def print_geo_url ( self ) :
  I1Ii1i111I = self . print_geo ( )
  if ( self . radius == 0 ) :
   oooOoo00 = self . geo_url ( )
   Iii11I111Ii11 = "<a href='{}'>{}</a>" . format ( oooOoo00 , I1Ii1i111I )
  else :
   oooOoo00 = I1Ii1i111I . replace ( "/" , "-" )
   Iii11I111Ii11 = "<a href='/lisp/geo-map/{}'>{}</a>" . format ( oooOoo00 , I1Ii1i111I )
   if 63 - 63: oO0o * I1IiiI * oO0o
  return ( Iii11I111Ii11 )
  if 56 - 56: oO0o - Ii1I % I1Ii111
  if 100 - 100: OOooOOo * IiII % IiII / o0oOOo0O0Ooo * OoO0O00 % OoOoOO00
 def dms_to_decimal ( self ) :
  iii1IoOo , OO000oOO , i1I1111I = self . latitude , self . lat_mins , self . lat_secs
  oOoooO = float ( abs ( iii1IoOo ) )
  oOoooO += float ( OO000oOO * 60 + i1I1111I ) / 3600
  if ( iii1IoOo > 0 ) : oOoooO = - oOoooO
  O0OOOo = oOoooO
  if 77 - 77: Ii1I * Ii1I % IiII - O0 % OOooOOo % OOooOOo
  iii1IoOo , OO000oOO , i1I1111I = self . longitude , self . long_mins , self . long_secs
  oOoooO = float ( abs ( iii1IoOo ) )
  oOoooO += float ( OO000oOO * 60 + i1I1111I ) / 3600
  if ( iii1IoOo > 0 ) : oOoooO = - oOoooO
  I1iIIi1i = oOoooO
  return ( ( O0OOOo , I1iIIi1i ) )
  if 4 - 4: o0oOOo0O0Ooo * iII111i - OoO0O00 . Ii1I / IiII * OoO0O00
  if 78 - 78: O0
 def get_distance ( self , geo_point ) :
  O0oo00 = self . dms_to_decimal ( )
  OOO0ooo0O = geo_point . dms_to_decimal ( )
  IiI1 = vincenty ( O0oo00 , OOO0ooo0O )
  return ( IiI1 . km )
  if 1 - 1: OoooooooOO - i1IIi % iII111i - II111iiii * IiII . OoO0O00
  if 76 - 76: iII111i - iIii1I11I1II1 + I1ii11iIi11i
 def point_in_circle ( self , geo_point ) :
  Ii1OoO0000OOo0 = self . get_distance ( geo_point )
  return ( Ii1OoO0000OOo0 <= self . radius )
  if 67 - 67: I1IiiI / OoooooooOO / ooOoO0o % OOooOOo
  if 13 - 13: Ii1I . iIii1I11I1II1 * I1ii11iIi11i / Ii1I
 def encode_geo ( self ) :
  OoOoO00OoOOo = socket . htons ( LISP_AFI_LCAF )
  OOOoO0Oo = socket . htons ( 20 + 2 )
  II111Ii1I1I = 0
  if 74 - 74: Oo0Ooo * I1Ii111
  iIIIII1i1III = abs ( self . latitude )
  OOOo00 = ( ( self . lat_mins * 60 ) + self . lat_secs ) * 1000
  if ( self . latitude < 0 ) : II111Ii1I1I |= 0x40
  if 97 - 97: I11i + II111iiii
  iiIIIii1iII = abs ( self . longitude )
  o0i11ii1I1II11 = ( ( self . long_mins * 60 ) + self . long_secs ) * 1000
  if ( self . longitude < 0 ) : II111Ii1I1I |= 0x20
  if 42 - 42: ooOoO0o - I1Ii111 - OoooooooOO / I1IiiI
  Oo0OOO = 0
  if ( self . no_geo_altitude ( ) == False ) :
   Oo0OOO = socket . htonl ( self . altitude )
   II111Ii1I1I |= 0x10
   if 64 - 64: i1IIi
  IIi1ooO0oOOoOO = socket . htons ( self . radius )
  if ( IIi1ooO0oOOoOO != 0 ) : II111Ii1I1I |= 0x06
  if 26 - 26: OoOoOO00 / o0oOOo0O0Ooo . OOooOOo + I1IiiI + Ii1I . iII111i
  O0ooOo0o0oo0O = struct . pack ( "HBBBBH" , OoOoO00OoOOo , 0 , 0 , LISP_LCAF_GEO_COORD_TYPE ,
 0 , OOOoO0Oo )
  O0ooOo0o0oo0O += struct . pack ( "BBHBBHBBHIHHH" , II111Ii1I1I , 0 , 0 , iIIIII1i1III , OOOo00 >> 16 ,
 socket . htons ( OOOo00 & 0x0ffff ) , iiIIIii1iII , o0i11ii1I1II11 >> 16 ,
 socket . htons ( o0i11ii1I1II11 & 0xffff ) , Oo0OOO , IIi1ooO0oOOoOO , 0 , 0 )
  if 22 - 22: iII111i * Oo0Ooo
  return ( O0ooOo0o0oo0O )
  if 4 - 4: O0
  if 67 - 67: OoO0O00 - II111iiii + Ii1I
 def decode_geo ( self , packet , lcaf_len , radius_hi ) :
  i1I1iii1I11II = "BBHBBHBBHIHHH"
  Iiiii = struct . calcsize ( i1I1iii1I11II )
  if ( lcaf_len < Iiiii ) : return ( None )
  if 41 - 41: oO0o + O0 / I1ii11iIi11i
  II111Ii1I1I , OooOo00ooOOO , iIiIIIIIi1iI , iIIIII1i1III , i1IiII , OOOo00 , iiIIIii1iII , i1i11ii1IiII1 , o0i11ii1I1II11 , Oo0OOO , IIi1ooO0oOOoOO , o0000O0Ooo , O0ooo0 = struct . unpack ( i1I1iii1I11II ,
  # iII111i + I1IiiI / OoO0O00 - I1IiiI / OoooooooOO - ooOoO0o
 packet [ : Iiiii ] )
  if 22 - 22: iII111i
  if 30 - 30: OoO0O00 + I11i + Oo0Ooo
  if 77 - 77: II111iiii
  if 92 - 92: I1Ii111 / I1IiiI / I1ii11iIi11i + I11i + Ii1I
  O0ooo0 = socket . ntohs ( O0ooo0 )
  if ( O0ooo0 == LISP_AFI_LCAF ) : return ( None )
  if 51 - 51: OOooOOo
  if ( II111Ii1I1I & 0x40 ) : iIIIII1i1III = - iIIIII1i1III
  self . latitude = iIIIII1i1III
  oO000 = ( ( i1IiII << 16 ) | socket . ntohs ( OOOo00 ) ) / 1000
  self . lat_mins = oO000 / 60
  self . lat_secs = oO000 % 60
  if 64 - 64: o0oOOo0O0Ooo - Ii1I / Oo0Ooo . OOooOOo
  if ( II111Ii1I1I & 0x20 ) : iiIIIii1iII = - iiIIIii1iII
  self . longitude = iiIIIii1iII
  Ii1IIIIiII1I = ( ( i1i11ii1IiII1 << 16 ) | socket . ntohs ( o0i11ii1I1II11 ) ) / 1000
  self . long_mins = Ii1IIIIiII1I / 60
  self . long_secs = Ii1IIIIiII1I % 60
  if 26 - 26: ooOoO0o - oO0o + OOooOOo * Ii1I - I11i % I1IiiI
  self . altitude = socket . ntohl ( Oo0OOO ) if ( II111Ii1I1I & 0x10 ) else - 1
  IIi1ooO0oOOoOO = socket . ntohs ( IIi1ooO0oOOoOO )
  self . radius = IIi1ooO0oOOoOO if ( II111Ii1I1I & 0x02 ) else IIi1ooO0oOOoOO * 1000
  if 73 - 73: ooOoO0o + Ii1I . O0 . iII111i
  self . geo_name = None
  packet = packet [ Iiiii : : ]
  if 77 - 77: OOooOOo % I1IiiI - iII111i % I1Ii111
  if ( O0ooo0 != 0 ) :
   self . rloc . afi = O0ooo0
   packet = self . rloc . unpack_address ( packet )
   self . rloc . mask_len = self . rloc . host_mask_len ( )
   if 29 - 29: iIii1I11I1II1 / i11iIiiIii + Oo0Ooo
  return ( packet )
  if 99 - 99: I1IiiI - iII111i * Ii1I - OoOoOO00 / i11iIiiIii - i1IIi
  if 46 - 46: I1ii11iIi11i * ooOoO0o
  if 4 - 4: I1Ii111 * II111iiii
  if 4 - 4: ooOoO0o * Oo0Ooo - I1ii11iIi11i % ooOoO0o % OoOoOO00
  if 18 - 18: OOooOOo / O0 . OoO0O00 - II111iiii * OOooOOo
  if 13 - 13: OoO0O00 % i1IIi . i11iIiiIii / iII111i
class lisp_rle_node ( ) :
 def __init__ ( self ) :
  self . address = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . level = 0
  self . translated_port = 0
  self . rloc_name = None
  if 28 - 28: i1IIi - iII111i + o0oOOo0O0Ooo / Oo0Ooo * oO0o
  if 8 - 8: ooOoO0o + OOooOOo * ooOoO0o / i1IIi . I1ii11iIi11i
 def copy_rle_node ( self ) :
  Iii = lisp_rle_node ( )
  Iii . address . copy_address ( self . address )
  Iii . level = self . level
  Iii . translated_port = self . translated_port
  Iii . rloc_name = self . rloc_name
  return ( Iii )
  if 4 - 4: Ii1I - Oo0Ooo . i1IIi + iIii1I11I1II1
  if 28 - 28: O0 / ooOoO0o / IiII - I11i + IiII + OoO0O00
 def store_translated_rloc ( self , rloc , port ) :
  self . address . copy_address ( rloc )
  self . translated_port = port
  if 84 - 84: Oo0Ooo + OoOoOO00 / iII111i . I1ii11iIi11i
  if 26 - 26: Oo0Ooo
 def get_encap_keys ( self ) :
  Oo0O00O = "4341" if self . translated_port == 0 else str ( self . translated_port )
  if 61 - 61: Ii1I * oO0o * i11iIiiIii + OoO0O00
  oo0o00OO = self . address . print_address_no_iid ( ) + ":" + Oo0O00O
  if 43 - 43: OoO0O00 * OoO0O00 * oO0o
  try :
   iIi11III = lisp_crypto_keys_by_rloc_encap [ oo0o00OO ]
   if ( iIi11III [ 1 ] ) : return ( iIi11III [ 1 ] . encrypt_key , iIi11III [ 1 ] . icv_key )
   return ( None , None )
  except :
   return ( None , None )
   if 24 - 24: oO0o
   if 77 - 77: i11iIiiIii - I1Ii111 - I1ii11iIi11i * Oo0Ooo / i11iIiiIii
   if 79 - 79: Oo0Ooo % Oo0Ooo . oO0o + ooOoO0o * iII111i * I11i
   if 87 - 87: o0oOOo0O0Ooo + OoOoOO00 % o0oOOo0O0Ooo + I1IiiI
class lisp_rle ( ) :
 def __init__ ( self , name ) :
  self . rle_name = name
  self . rle_nodes = [ ]
  self . rle_forwarding_list = [ ]
  if 89 - 89: II111iiii
  if 41 - 41: iIii1I11I1II1
 def copy_rle ( self ) :
  iI1Ii11 = lisp_rle ( self . rle_name )
  for Iii in self . rle_nodes :
   iI1Ii11 . rle_nodes . append ( Iii . copy_rle_node ( ) )
   if 26 - 26: Oo0Ooo / i1IIi + Oo0Ooo
  iI1Ii11 . build_forwarding_list ( )
  return ( iI1Ii11 )
  if 76 - 76: I1ii11iIi11i * i1IIi % oO0o
  if 80 - 80: i1IIi * II111iiii . O0 % I1ii11iIi11i / ooOoO0o
 def print_rle ( self , html , do_formatting ) :
  II1I = ""
  for Iii in self . rle_nodes :
   Oo0O00O = Iii . translated_port
   if 58 - 58: I1IiiI * I1ii11iIi11i - i1IIi % I1Ii111 % O0
   i1111I1 = ""
   if ( Iii . rloc_name != None ) :
    i1111I1 = Iii . rloc_name
    if ( do_formatting ) : i1111I1 = blue ( i1111I1 , html )
    if 35 - 35: OoooooooOO
    if 13 - 13: oO0o - O0 * i11iIiiIii / IiII / IiII
   oo0o00OO = Iii . address . print_address_no_iid ( )
   if ( Iii . address . is_local ( ) ) : oo0o00OO = red ( oo0o00OO , html )
   II1I += "{}{}({}), " . format ( oo0o00OO , "" if Oo0O00O == 0 else ":" + str ( Oo0O00O ) , "" if Iii . rloc_name == None else i1111I1 )
   if 72 - 72: i11iIiiIii * OoOoOO00 % oO0o / I1Ii111
   if 9 - 9: iIii1I11I1II1 . IiII
   if 42 - 42: i1IIi / Ii1I * I1ii11iIi11i
  return ( II1I [ 0 : - 2 ] if II1I != "" else "" )
  if 9 - 9: I11i % i1IIi / i1IIi / OoO0O00
  if 46 - 46: I1Ii111 * II111iiii + II111iiii * O0 % II111iiii
 def build_forwarding_list ( self ) :
  oOOoOoooOo0o = - 1
  for Iii in self . rle_nodes :
   if ( oOOoOoooOo0o == - 1 ) :
    if ( Iii . address . is_local ( ) ) : oOOoOoooOo0o = Iii . level
   else :
    if ( Iii . level > oOOoOoooOo0o ) : break
    if 37 - 37: OOooOOo . iIii1I11I1II1 / O0 . ooOoO0o + OOooOOo - OoooooooOO
    if 96 - 96: I1Ii111 / oO0o . I1ii11iIi11i % I1IiiI * OOooOOo
  oOOoOoooOo0o = 0 if oOOoOoooOo0o == - 1 else Iii . level
  if 99 - 99: i11iIiiIii - I1Ii111
  self . rle_forwarding_list = [ ]
  for Iii in self . rle_nodes :
   if ( Iii . level == oOOoOoooOo0o or ( oOOoOoooOo0o == 0 and
 Iii . level == 128 ) ) :
    if ( lisp_i_am_rtr == False and Iii . address . is_local ( ) ) :
     oo0o00OO = Iii . address . print_address_no_iid ( )
     lprint ( "Exclude local RLE RLOC {}" . format ( oo0o00OO ) )
     continue
     if 4 - 4: o0oOOo0O0Ooo - i11iIiiIii . iIii1I11I1II1 . OOooOOo % IiII
    self . rle_forwarding_list . append ( Iii )
    if 68 - 68: I11i / iII111i - IiII . iIii1I11I1II1 / o0oOOo0O0Ooo
    if 54 - 54: II111iiii * I1IiiI
    if 49 - 49: I1ii11iIi11i
    if 31 - 31: o0oOOo0O0Ooo - OoOoOO00 + I1ii11iIi11i . oO0o - O0
    if 61 - 61: I1ii11iIi11i * II111iiii . i1IIi
class lisp_json ( ) :
 def __init__ ( self , name , string , encrypted = False ) :
  self . json_name = name
  self . json_string = string
  self . json_encrypted = False
  if 60 - 60: OoooooooOO % ooOoO0o * i11iIiiIii * OoooooooOO % IiII
  if 15 - 15: oO0o
  if 40 - 40: I1Ii111
  if 77 - 77: II111iiii - o0oOOo0O0Ooo . Ii1I
  if 47 - 47: o0oOOo0O0Ooo % OOooOOo + I1Ii111
  if 64 - 64: ooOoO0o / IiII . I1IiiI
  if 77 - 77: o0oOOo0O0Ooo % I1Ii111 . OOooOOo
  if ( len ( lisp_ms_json_keys ) != 0 ) :
   self . json_key_id = lisp_ms_json_keys . keys ( ) [ 0 ]
   self . json_key = lisp_ms_json_keys [ self . json_key_id ]
   self . encrypt_json ( )
   if 90 - 90: I11i
   if 53 - 53: I1ii11iIi11i + i11iIiiIii / iIii1I11I1II1 + OoooooooOO + IiII * I1IiiI
  if ( lisp_log_id == "lig" and encrypted ) :
   Oo000O000 = os . getenv ( "LISP_JSON_KEY" )
   if ( Oo000O000 != None ) :
    ooo = - 1
    if ( Oo000O000 [ 0 ] == "[" and "]" in Oo000O000 ) :
     ooo = Oo000O000 . find ( "]" )
     self . json_key_id = int ( Oo000O000 [ 1 : ooo ] )
     if 16 - 16: i11iIiiIii - oO0o . i11iIiiIii + OoO0O00 + i11iIiiIii
    self . json_key = Oo000O000 [ ooo + 1 : : ]
    if 85 - 85: I1ii11iIi11i - ooOoO0o + I1Ii111 + I1Ii111
    self . decrypt_json ( )
    if 13 - 13: II111iiii
    if 22 - 22: o0oOOo0O0Ooo
    if 45 - 45: I1Ii111 + OoooooooOO + o0oOOo0O0Ooo * II111iiii
    if 12 - 12: I1ii11iIi11i / O0
 def add ( self ) :
  self . delete ( )
  lisp_json_list [ self . json_name ] = self
  if 18 - 18: OoOoOO00 . i11iIiiIii + i1IIi / OoooooooOO - IiII % OoO0O00
  if 47 - 47: iII111i % IiII + I1Ii111 * o0oOOo0O0Ooo * OoooooooOO
 def delete ( self ) :
  if ( lisp_json_list . has_key ( self . json_name ) ) :
   del ( lisp_json_list [ self . json_name ] )
   lisp_json_list [ self . json_name ] = None
   if 100 - 100: Oo0Ooo / I1IiiI / iII111i / I1Ii111 / oO0o % o0oOOo0O0Ooo
   if 16 - 16: I1IiiI + I11i
   if 66 - 66: OoooooooOO % II111iiii / I1Ii111 . i11iIiiIii
 def print_json ( self , html ) :
  O0OOOO = self . json_string
  IiiiIi = "***"
  if ( html ) : IiiiIi = red ( IiiiIi , html )
  III1I1I = IiiiIi + self . json_string + IiiiIi
  if ( self . valid_json ( ) ) : return ( O0OOOO )
  return ( III1I1I )
  if 60 - 60: OOooOOo * Ii1I % OoooooooOO + i1IIi
  if 18 - 18: i1IIi - I11i - I1IiiI * I1IiiI % IiII - IiII
 def valid_json ( self ) :
  try :
   json . loads ( self . json_string )
  except :
   return ( False )
   if 1 - 1: o0oOOo0O0Ooo + OoOoOO00 / OOooOOo % IiII
  return ( True )
  if 16 - 16: IiII . I11i * O0 + OoooooooOO
  if 37 - 37: OoO0O00 . i11iIiiIii - i11iIiiIii % I1Ii111 + II111iiii * i11iIiiIii
 def encrypt_json ( self ) :
  II11iI11i1 = self . json_key . zfill ( 32 )
  iiI1iiIiiiI1I = "0" * 8
  if 83 - 83: OOooOOo % O0 - I11i . Ii1I % IiII
  i1IiIi1111i = json . loads ( self . json_string )
  for Oo000O000 in i1IiIi1111i :
   i11II = i1IiIi1111i [ Oo000O000 ]
   i11II = chacha . ChaCha ( II11iI11i1 , iiI1iiIiiiI1I ) . encrypt ( i11II )
   i1IiIi1111i [ Oo000O000 ] = binascii . hexlify ( i11II )
   if 11 - 11: ooOoO0o . Oo0Ooo % I1Ii111 % ooOoO0o . oO0o * i11iIiiIii
  self . json_string = json . dumps ( i1IiIi1111i )
  self . json_encrypted = True
  if 14 - 14: I11i + O0 * i11iIiiIii / i11iIiiIii
  if 15 - 15: i11iIiiIii % I1ii11iIi11i % Oo0Ooo
 def decrypt_json ( self ) :
  II11iI11i1 = self . json_key . zfill ( 32 )
  iiI1iiIiiiI1I = "0" * 8
  if 65 - 65: II111iiii - i1IIi . I1ii11iIi11i . I11i % OoO0O00 . OoooooooOO
  i1IiIi1111i = json . loads ( self . json_string )
  for Oo000O000 in i1IiIi1111i :
   i11II = binascii . unhexlify ( i1IiIi1111i [ Oo000O000 ] )
   i1IiIi1111i [ Oo000O000 ] = chacha . ChaCha ( II11iI11i1 , iiI1iiIiiiI1I ) . encrypt ( i11II )
   if 64 - 64: I11i * Oo0Ooo / IiII / II111iiii
  try :
   self . json_string = json . dumps ( i1IiIi1111i )
   self . json_encrypted = False
  except :
   pass
   if 29 - 29: OoooooooOO - OoO0O00 - Ii1I
   if 82 - 82: IiII - I1IiiI . iII111i % I11i % Ii1I + iII111i
   if 87 - 87: i11iIiiIii % i1IIi
   if 63 - 63: I1ii11iIi11i + iII111i * o0oOOo0O0Ooo % II111iiii
   if 23 - 23: i1IIi * oO0o * oO0o . i11iIiiIii / o0oOOo0O0Ooo
   if 80 - 80: O0 / II111iiii . Oo0Ooo + o0oOOo0O0Ooo - OoO0O00
   if 8 - 8: o0oOOo0O0Ooo / I1Ii111 % i1IIi
class lisp_stats ( ) :
 def __init__ ( self ) :
  self . packet_count = 0
  self . byte_count = 0
  self . last_rate_check = 0
  self . last_packet_count = 0
  self . last_byte_count = 0
  self . last_increment = None
  if 6 - 6: I1Ii111 * oO0o
  if 48 - 48: Ii1I + i1IIi . iIii1I11I1II1
 def increment ( self , octets ) :
  self . packet_count += 1
  self . byte_count += octets
  self . last_increment = lisp_get_timestamp ( )
  if 64 - 64: O0 * OOooOOo * I1IiiI - o0oOOo0O0Ooo
  if 86 - 86: i1IIi
 def recent_packet_sec ( self ) :
  if ( self . last_increment == None ) : return ( False )
  oO000o0Oo00 = time . time ( ) - self . last_increment
  return ( oO000o0Oo00 <= 1 )
  if 84 - 84: OoOoOO00
  if 31 - 31: iIii1I11I1II1 + I1IiiI
 def recent_packet_min ( self ) :
  if ( self . last_increment == None ) : return ( False )
  oO000o0Oo00 = time . time ( ) - self . last_increment
  return ( oO000o0Oo00 <= 60 )
  if 82 - 82: I1Ii111 / Ii1I % OoooooooOO - IiII / OoooooooOO
  if 23 - 23: iIii1I11I1II1
 def stat_colors ( self , c1 , c2 , html ) :
  if ( self . recent_packet_sec ( ) ) :
   return ( green_last_sec ( c1 ) , green_last_sec ( c2 ) )
   if 7 - 7: IiII / OOooOOo + Oo0Ooo . I1IiiI
  if ( self . recent_packet_min ( ) ) :
   return ( green_last_min ( c1 ) , green_last_min ( c2 ) )
   if 33 - 33: I1Ii111 + OoooooooOO
  return ( c1 , c2 )
  if 73 - 73: O0 . Oo0Ooo
  if 28 - 28: I1IiiI . O0 % o0oOOo0O0Ooo / I11i
 def normalize ( self , count ) :
  count = str ( count )
  iiIIii1I1I1 = len ( count )
  if ( iiIIii1I1I1 > 12 ) :
   count = count [ 0 : - 10 ] + "." + count [ - 10 : - 7 ] + "T"
   return ( count )
   if 87 - 87: iIii1I11I1II1 % OoO0O00 % I11i * O0 * i1IIi
  if ( iiIIii1I1I1 > 9 ) :
   count = count [ 0 : - 9 ] + "." + count [ - 9 : - 7 ] + "B"
   return ( count )
   if 27 - 27: OoOoOO00 % OoooooooOO
  if ( iiIIii1I1I1 > 6 ) :
   count = count [ 0 : - 6 ] + "." + count [ - 6 ] + "M"
   return ( count )
   if 77 - 77: Ii1I % Oo0Ooo
  return ( count )
  if 30 - 30: iIii1I11I1II1 * Oo0Ooo * OOooOOo * ooOoO0o
  if 6 - 6: iIii1I11I1II1 / oO0o % ooOoO0o
 def get_stats ( self , summary , html ) :
  IiI1Ii = self . last_rate_check
  I1IiIII1II1iI = self . last_packet_count
  i1I1i1iiiIi = self . last_byte_count
  self . last_rate_check = lisp_get_timestamp ( )
  self . last_packet_count = self . packet_count
  self . last_byte_count = self . byte_count
  if 7 - 7: I1IiiI - i11iIiiIii / Ii1I / IiII - i1IIi / i11iIiiIii
  III1IIIiiIIii = self . last_rate_check - IiI1Ii
  if ( III1IIIiiIIii == 0 ) :
   O0O00o0O0OO = 0
   OO0OO0 = 0
  else :
   O0O00o0O0OO = int ( ( self . packet_count - I1IiIII1II1iI ) / III1IIIiiIIii )
   OO0OO0 = ( self . byte_count - i1I1i1iiiIi ) / III1IIIiiIIii
   OO0OO0 = ( OO0OO0 * 8 ) / 1000000
   OO0OO0 = round ( OO0OO0 , 2 )
   if 75 - 75: OoO0O00 % iII111i
   if 46 - 46: o0oOOo0O0Ooo
   if 61 - 61: OoO0O00 . O0 + I1ii11iIi11i + OoO0O00
   if 44 - 44: I11i . oO0o
   if 65 - 65: I1ii11iIi11i * II111iiii % I11i + II111iiii . i1IIi / ooOoO0o
  oOoOOo0oO00 = self . normalize ( self . packet_count )
  iI1ii11 = self . normalize ( self . byte_count )
  if 59 - 59: o0oOOo0O0Ooo
  if 76 - 76: OoO0O00 + O0 - OoOoOO00 - IiII
  if 11 - 11: ooOoO0o + OoOoOO00 - i1IIi
  if 74 - 74: i11iIiiIii
  if 85 - 85: OoOoOO00 - Ii1I / I1IiiI + i11iIiiIii * II111iiii
  if ( summary ) :
   o0OO0O00o00 = "<br>" if html else ""
   oOoOOo0oO00 , iI1ii11 = self . stat_colors ( oOoOOo0oO00 , iI1ii11 , html )
   OoO0oO0OO = "packet-count: {}{}byte-count: {}" . format ( oOoOOo0oO00 , o0OO0O00o00 , iI1ii11 )
   OOoO0 = "packet-rate: {} pps\nbit-rate: {} Mbps" . format ( O0O00o0O0OO , OO0OO0 )
   if 89 - 89: iII111i + Oo0Ooo / Oo0Ooo / OoO0O00 + i11iIiiIii
   if ( html != "" ) : OOoO0 = lisp_span ( OoO0oO0OO , OOoO0 )
  else :
   oooO0O = str ( O0O00o0O0OO )
   i1Ii1II1IIII = str ( OO0OO0 )
   if ( html ) :
    oOoOOo0oO00 = lisp_print_cour ( oOoOOo0oO00 )
    oooO0O = lisp_print_cour ( oooO0O )
    iI1ii11 = lisp_print_cour ( iI1ii11 )
    i1Ii1II1IIII = lisp_print_cour ( i1Ii1II1IIII )
    if 73 - 73: o0oOOo0O0Ooo . I11i + II111iiii + I1ii11iIi11i * i11iIiiIii
   o0OO0O00o00 = "<br>" if html else ", "
   if 90 - 90: I1Ii111 . I1IiiI / OoO0O00 * ooOoO0o
   OOoO0 = ( "packet-count: {}{}packet-rate: {} pps{}byte-count: " + "{}{}bit-rate: {} mbps" ) . format ( oOoOOo0oO00 , o0OO0O00o00 , oooO0O , o0OO0O00o00 , iI1ii11 , o0OO0O00o00 ,
   # OOooOOo . OoO0O00 + OoO0O00
 i1Ii1II1IIII )
   if 19 - 19: iII111i * i1IIi / iII111i
  return ( OOoO0 )
  if 21 - 21: ooOoO0o / o0oOOo0O0Ooo % I1ii11iIi11i . Ii1I . IiII
  if 8 - 8: I1ii11iIi11i / ooOoO0o + II111iiii
  if 45 - 45: ooOoO0o - OOooOOo * IiII % iII111i . OoOoOO00 / i11iIiiIii
  if 63 - 63: Oo0Ooo * iIii1I11I1II1 / ooOoO0o
  if 46 - 46: OoOoOO00 / iII111i - OoO0O00 . o0oOOo0O0Ooo
  if 50 - 50: I1Ii111 . O0 . OoOoOO00 + I1Ii111 + OoooooooOO . i11iIiiIii
  if 65 - 65: I1IiiI % iIii1I11I1II1
  if 52 - 52: I1IiiI
lisp_decap_stats = {
 "good-packets" : lisp_stats ( ) , "ICV-error" : lisp_stats ( ) ,
 "checksum-error" : lisp_stats ( ) , "lisp-header-error" : lisp_stats ( ) ,
 "no-decrypt-key" : lisp_stats ( ) , "bad-inner-version" : lisp_stats ( ) ,
 "outer-header-error" : lisp_stats ( )
 }
if 19 - 19: I1IiiI
if 17 - 17: I11i + OoooooooOO
if 63 - 63: IiII
if 3 - 3: oO0o * II111iiii . O0
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
  self . rloc_probe_latency = "?/?"
  self . recent_rloc_probe_latencies = [ "?/?" , "?/?" , "?/?" ]
  self . last_rloc_probe_nonce = 0
  self . echo_nonce_capable = False
  self . map_notify_requested = False
  self . rloc_next_hop = None
  self . next_rloc = None
  self . multicast_rloc_probe_list = { }
  if 19 - 19: I1IiiI / I1IiiI / Oo0Ooo + oO0o + i1IIi
  if ( recurse == False ) : return
  if 31 - 31: iII111i / OoooooooOO - I1Ii111 . iII111i
  if 38 - 38: ooOoO0o . OoooooooOO - II111iiii * i11iIiiIii / i1IIi . OoooooooOO
  if 51 - 51: oO0o - I1ii11iIi11i + I1ii11iIi11i
  if 100 - 100: I11i - I1ii11iIi11i . i1IIi
  if 85 - 85: II111iiii
  if 58 - 58: i1IIi - OoO0O00 + ooOoO0o
  I1Ii1iiII1 = lisp_get_default_route_next_hops ( )
  if ( I1Ii1iiII1 == [ ] or len ( I1Ii1iiII1 ) == 1 ) : return
  if 62 - 62: OoooooooOO
  self . rloc_next_hop = I1Ii1iiII1 [ 0 ]
  iiI = self
  for O0O0O in I1Ii1iiII1 [ 1 : : ] :
   o0O0 = lisp_rloc ( False )
   o0O0 = copy . deepcopy ( self )
   o0O0 . rloc_next_hop = O0O0O
   iiI . next_rloc = o0O0
   iiI = o0O0
   if 23 - 23: Ii1I + i1IIi + IiII - O0 / OOooOOo
   if 82 - 82: I1Ii111
   if 78 - 78: I1Ii111 % oO0o * iIii1I11I1II1
 def up_state ( self ) :
  return ( self . state == LISP_RLOC_UP_STATE )
  if 1 - 1: i1IIi . iIii1I11I1II1
  if 2 - 2: OOooOOo % Oo0Ooo * OOooOOo + I1Ii111 % OoOoOO00 / O0
 def unreach_state ( self ) :
  return ( self . state == LISP_RLOC_UNREACH_STATE )
  if 23 - 23: O0 * oO0o / I1IiiI + i1IIi * O0 % oO0o
  if 11 - 11: I1Ii111 . OoooooooOO * iIii1I11I1II1 / I1ii11iIi11i - ooOoO0o . iII111i
 def no_echoed_nonce_state ( self ) :
  return ( self . state == LISP_RLOC_NO_ECHOED_NONCE_STATE )
  if 71 - 71: i11iIiiIii + I11i / i11iIiiIii % Oo0Ooo / iIii1I11I1II1 * OoO0O00
  if 49 - 49: iII111i + OoOoOO00
 def down_state ( self ) :
  return ( self . state in [ LISP_RLOC_DOWN_STATE , LISP_RLOC_ADMIN_DOWN_STATE ] )
  if 33 - 33: ooOoO0o
  if 19 - 19: I1Ii111 % IiII
  if 94 - 94: I1Ii111 * I1ii11iIi11i * I1ii11iIi11i - o0oOOo0O0Ooo . i11iIiiIii
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
  if 16 - 16: i1IIi
  if 88 - 88: OOooOOo
 def print_rloc ( self , indent ) :
  i1 = lisp_print_elapsed ( self . uptime )
  lprint ( "{}rloc {}, uptime {}, {}, parms {}/{}/{}/{}" . format ( indent ,
 red ( self . rloc . print_address ( ) , False ) , i1 , self . print_state ( ) ,
 self . priority , self . weight , self . mpriority , self . mweight ) )
  if 79 - 79: oO0o
  if 52 - 52: oO0o + OoO0O00 / OoooooooOO - iIii1I11I1II1 / iII111i - oO0o
 def print_rloc_name ( self , cour = False ) :
  if ( self . rloc_name == None ) : return ( "" )
  oo0O0OOooO0 = self . rloc_name
  if ( cour ) : oo0O0OOooO0 = lisp_print_cour ( oo0O0OOooO0 )
  return ( 'rloc-name: {}' . format ( blue ( oo0O0OOooO0 , cour ) ) )
  if 68 - 68: I1IiiI - OoOoOO00 - iIii1I11I1II1 % i11iIiiIii * OoOoOO00 * OoO0O00
  if 97 - 97: OoO0O00 - IiII + ooOoO0o % iIii1I11I1II1 % iII111i
 def store_rloc_from_record ( self , rloc_record , nonce , source ) :
  Oo0O00O = LISP_DATA_PORT
  self . rloc . copy_address ( rloc_record . rloc )
  self . rloc_name = rloc_record . rloc_name
  if 100 - 100: IiII - Ii1I * iIii1I11I1II1 . iII111i . i1IIi % Oo0Ooo
  if 11 - 11: I11i + oO0o % Ii1I
  if 22 - 22: ooOoO0o
  if 83 - 83: OOooOOo - i11iIiiIii - i1IIi / oO0o
  I1IIiIIIii = self . rloc
  if ( I1IIiIIIii . is_null ( ) == False ) :
   iI1I1iI = lisp_get_nat_info ( I1IIiIIIii , self . rloc_name )
   if ( iI1I1iI ) :
    Oo0O00O = iI1I1iI . port
    II11111Iii1I = lisp_nat_state_info [ self . rloc_name ] [ 0 ]
    oo0o00OO = I1IIiIIIii . print_address_no_iid ( )
    o0oooOoOoOo = red ( oo0o00OO , False )
    OoOO000O = "" if self . rloc_name == None else blue ( self . rloc_name , False )
    if 15 - 15: i11iIiiIii % I1ii11iIi11i - i11iIiiIii
    if 68 - 68: ooOoO0o
    if 53 - 53: i11iIiiIii / OoOoOO00 % o0oOOo0O0Ooo / IiII
    if 88 - 88: ooOoO0o . i1IIi
    if 21 - 21: OoO0O00 * I1ii11iIi11i + I1ii11iIi11i
    if 36 - 36: Ii1I . OOooOOo * iIii1I11I1II1 - i1IIi
    if ( iI1I1iI . timed_out ( ) ) :
     lprint ( ( "    Matched stored NAT state timed out for " + "RLOC {}:{}, {}" ) . format ( o0oooOoOoOo , Oo0O00O , OoOO000O ) )
     if 38 - 38: Oo0Ooo . o0oOOo0O0Ooo % oO0o / i11iIiiIii * OoO0O00 % OoOoOO00
     if 18 - 18: OOooOOo
     iI1I1iI = None if ( iI1I1iI == II11111Iii1I ) else II11111Iii1I
     if ( iI1I1iI and iI1I1iI . timed_out ( ) ) :
      Oo0O00O = iI1I1iI . port
      o0oooOoOoOo = red ( iI1I1iI . address , False )
      lprint ( ( "    Youngest stored NAT state timed out " + " for RLOC {}:{}, {}" ) . format ( o0oooOoOoOo , Oo0O00O ,
      # I11i
 OoOO000O ) )
      iI1I1iI = None
      if 77 - 77: II111iiii / o0oOOo0O0Ooo - iIii1I11I1II1 + OoO0O00 / OOooOOo . O0
      if 84 - 84: i11iIiiIii
      if 11 - 11: I1ii11iIi11i + i1IIi % oO0o * O0 + I1Ii111 / Oo0Ooo
      if 45 - 45: I1IiiI / OoooooooOO / II111iiii % I1Ii111 / O0 . I1ii11iIi11i
      if 96 - 96: IiII * OOooOOo / Oo0Ooo / Oo0Ooo / OoooooooOO . i11iIiiIii
      if 24 - 24: OoO0O00 - OoO0O00 * Oo0Ooo + oO0o + o0oOOo0O0Ooo % OOooOOo
      if 39 - 39: i11iIiiIii * II111iiii
    if ( iI1I1iI ) :
     if ( iI1I1iI . address != oo0o00OO ) :
      lprint ( "RLOC conflict, RLOC-record {}, NAT state {}" . format ( o0oooOoOoOo , red ( iI1I1iI . address , False ) ) )
      if 75 - 75: OoooooooOO * IiII * OOooOOo
      self . rloc . store_address ( iI1I1iI . address )
      if 1 - 1: iII111i * I1IiiI . o0oOOo0O0Ooo . IiII
     o0oooOoOoOo = red ( iI1I1iI . address , False )
     Oo0O00O = iI1I1iI . port
     lprint ( "    Use NAT translated RLOC {}:{} for {}" . format ( o0oooOoOoOo , Oo0O00O , OoOO000O ) )
     if 6 - 6: OOooOOo . oO0o / Oo0Ooo / o0oOOo0O0Ooo
     self . store_translated_rloc ( I1IIiIIIii , Oo0O00O )
     if 24 - 24: Oo0Ooo % OoooooooOO
     if 78 - 78: OoooooooOO - II111iiii . OoO0O00 / I1ii11iIi11i
     if 86 - 86: OOooOOo * OoOoOO00 % i1IIi * IiII . I1ii11iIi11i
     if 72 - 72: i1IIi - I1Ii111 . O0 * OoO0O00
  self . geo = rloc_record . geo
  self . elp = rloc_record . elp
  self . json = rloc_record . json
  if 62 - 62: Oo0Ooo . iII111i
  if 15 - 15: i11iIiiIii * I11i + oO0o
  if 67 - 67: IiII . OoO0O00
  if 59 - 59: oO0o * o0oOOo0O0Ooo
  self . rle = rloc_record . rle
  if ( self . rle ) :
   for Iii in self . rle . rle_nodes :
    oo0O0OOooO0 = Iii . rloc_name
    iI1I1iI = lisp_get_nat_info ( Iii . address , oo0O0OOooO0 )
    if ( iI1I1iI == None ) : continue
    if 76 - 76: I1IiiI
    Oo0O00O = iI1I1iI . port
    Ooooo = oo0O0OOooO0
    if ( Ooooo ) : Ooooo = blue ( oo0O0OOooO0 , False )
    if 94 - 94: OoooooooOO * I1ii11iIi11i
    lprint ( ( "      Store translated encap-port {} for RLE-" + "node {}, rloc-name '{}'" ) . format ( Oo0O00O ,
    # II111iiii + II111iiii
 Iii . address . print_address_no_iid ( ) , Ooooo ) )
    Iii . translated_port = Oo0O00O
    if 30 - 30: OOooOOo / OoO0O00
    if 38 - 38: O0 * i1IIi + IiII
    if 3 - 3: OoOoOO00
  self . priority = rloc_record . priority
  self . mpriority = rloc_record . mpriority
  self . weight = rloc_record . weight
  self . mweight = rloc_record . mweight
  if ( rloc_record . reach_bit and rloc_record . local_bit and
 rloc_record . probe_bit == False ) : self . state = LISP_RLOC_UP_STATE
  if 40 - 40: ooOoO0o % I11i + O0
  if 22 - 22: i1IIi % Oo0Ooo / oO0o % OoOoOO00 / OoOoOO00
  if 79 - 79: IiII % OoooooooOO
  if 51 - 51: iII111i . oO0o % ooOoO0o % Ii1I . o0oOOo0O0Ooo
  i1I1I = source . is_exact_match ( rloc_record . rloc ) if source != None else None
  if 61 - 61: ooOoO0o / O0 * IiII / OoO0O00
  if ( rloc_record . keys != None and i1I1I ) :
   Oo000O000 = rloc_record . keys [ 1 ]
   if ( Oo000O000 != None ) :
    oo0o00OO = rloc_record . rloc . print_address_no_iid ( ) + ":" + str ( Oo0O00O )
    if 56 - 56: OoO0O00 + O0
    Oo000O000 . add_key_by_rloc ( oo0o00OO , True )
    lprint ( "    Store encap-keys for nonce 0x{}, RLOC {}" . format ( lisp_hex_string ( nonce ) , red ( oo0o00OO , False ) ) )
    if 2 - 2: OoOoOO00 - iIii1I11I1II1 * I1Ii111 % II111iiii - Oo0Ooo . OoooooooOO
    if 47 - 47: I1Ii111 + oO0o - Ii1I % OoO0O00 - I1Ii111 / i11iIiiIii
    if 27 - 27: i11iIiiIii . OoO0O00 + Ii1I
  return ( Oo0O00O )
  if 47 - 47: I1Ii111 . iIii1I11I1II1 + i11iIiiIii
  if 75 - 75: iIii1I11I1II1 / OoO0O00 * OOooOOo % O0
 def store_translated_rloc ( self , rloc , port ) :
  self . rloc . copy_address ( rloc )
  self . translated_rloc . copy_address ( rloc )
  self . translated_port = port
  if 82 - 82: Oo0Ooo / i1IIi . i1IIi / oO0o
  if 7 - 7: Oo0Ooo . iII111i % I1ii11iIi11i / iII111i
 def is_rloc_translated ( self ) :
  return ( self . translated_rloc . is_null ( ) == False )
  if 93 - 93: iII111i
  if 5 - 5: iII111i . I11i % I11i * Ii1I - I1ii11iIi11i . i11iIiiIii
 def rloc_exists ( self ) :
  if ( self . rloc . is_null ( ) == False ) : return ( True )
  if ( self . rle_name or self . geo_name or self . elp_name or self . json_name ) :
   return ( False )
   if 32 - 32: II111iiii
  return ( True )
  if 58 - 58: I1IiiI - o0oOOo0O0Ooo - I1Ii111 . O0 % OoO0O00 . I11i
  if 41 - 41: iII111i . I1Ii111 - IiII / O0
 def is_rtr ( self ) :
  return ( ( self . priority == 254 and self . mpriority == 255 and self . weight == 0 and self . mweight == 0 ) )
  if 62 - 62: IiII * I1ii11iIi11i * iII111i * OoOoOO00
  if 12 - 12: Oo0Ooo * Ii1I / ooOoO0o % I11i % O0
  if 25 - 25: Oo0Ooo * oO0o
 def print_state_change ( self , new_state ) :
  oOoo = self . print_state ( )
  Iii11I111Ii11 = "{} -> {}" . format ( oOoo , new_state )
  if ( new_state == "up" and self . unreach_state ( ) ) :
   Iii11I111Ii11 = bold ( Iii11I111Ii11 , False )
   if 30 - 30: I1Ii111
  return ( Iii11I111Ii11 )
  if 47 - 47: I1IiiI / I11i + iIii1I11I1II1 * Oo0Ooo / I1ii11iIi11i
  if 8 - 8: ooOoO0o . O0 / OoO0O00
 def print_rloc_probe_rtt ( self ) :
  if ( self . rloc_probe_rtt == - 1 ) : return ( "none" )
  return ( self . rloc_probe_rtt )
  if 50 - 50: Ii1I . OoOoOO00 * o0oOOo0O0Ooo
  if 68 - 68: IiII * oO0o / OoOoOO00 / I1Ii111
 def print_recent_rloc_probe_rtts ( self ) :
  o0000ooOO = str ( self . recent_rloc_probe_rtts )
  o0000ooOO = o0000ooOO . replace ( "-1" , "?" )
  return ( o0000ooOO )
  if 63 - 63: iII111i / iII111i % II111iiii . Oo0Ooo + I1Ii111 - o0oOOo0O0Ooo
  if 27 - 27: II111iiii + i1IIi / OOooOOo - II111iiii * iII111i
 def compute_rloc_probe_rtt ( self ) :
  iiI = self . rloc_probe_rtt
  self . rloc_probe_rtt = - 1
  if ( self . last_rloc_probe_reply == None ) : return
  if ( self . last_rloc_probe == None ) : return
  self . rloc_probe_rtt = self . last_rloc_probe_reply - self . last_rloc_probe
  self . rloc_probe_rtt = round ( self . rloc_probe_rtt , 3 )
  II111I = self . recent_rloc_probe_rtts
  self . recent_rloc_probe_rtts = [ iiI ] + II111I [ 0 : - 1 ]
  if 56 - 56: oO0o
  if 72 - 72: OoOoOO00 - O0 . O0 * oO0o
 def print_rloc_probe_hops ( self ) :
  return ( self . rloc_probe_hops )
  if 13 - 13: OoooooooOO / ooOoO0o + IiII / oO0o + oO0o
  if 78 - 78: iII111i * o0oOOo0O0Ooo + OOooOOo
 def print_recent_rloc_probe_hops ( self ) :
  I1II11 = str ( self . recent_rloc_probe_hops )
  return ( I1II11 )
  if 49 - 49: I1ii11iIi11i / oO0o . oO0o * iII111i % iII111i . I1IiiI
  if 96 - 96: II111iiii / OoooooooOO + iIii1I11I1II1 . Ii1I + OoooooooOO
 def store_rloc_probe_hops ( self , to_hops , from_ttl ) :
  if ( to_hops == 0 ) :
   to_hops = "?"
  elif ( to_hops < LISP_RLOC_PROBE_TTL / 2 ) :
   to_hops = "!"
  else :
   to_hops = str ( LISP_RLOC_PROBE_TTL - to_hops )
   if 62 - 62: OoOoOO00 + OoOoOO00 % OOooOOo * iII111i
  if ( from_ttl < LISP_RLOC_PROBE_TTL / 2 ) :
   iIiIiIIiIIi = "!"
  else :
   iIiIiIIiIIi = str ( LISP_RLOC_PROBE_TTL - from_ttl )
   if 13 - 13: OoO0O00
   if 56 - 56: OoOoOO00 . ooOoO0o * oO0o - I11i
  iiI = self . rloc_probe_hops
  self . rloc_probe_hops = to_hops + "/" + iIiIiIIiIIi
  II111I = self . recent_rloc_probe_hops
  self . recent_rloc_probe_hops = [ iiI ] + II111I [ 0 : - 1 ]
  if 47 - 47: oO0o . i1IIi * I1ii11iIi11i % OOooOOo % IiII / Oo0Ooo
  if 39 - 39: i11iIiiIii . OOooOOo + Oo0Ooo
 def store_rloc_probe_latencies ( self , json_telemetry ) :
  OooO0OO0Oooo = lisp_decode_telemetry ( json_telemetry )
  if 74 - 74: Ii1I
  o0OoooOoOo = round ( float ( OooO0OO0Oooo [ "etr-in" ] ) - float ( OooO0OO0Oooo [ "itr-out" ] ) , 3 )
  OOOo0o0OOO0000 = round ( float ( OooO0OO0Oooo [ "itr-in" ] ) - float ( OooO0OO0Oooo [ "etr-out" ] ) , 3 )
  if 56 - 56: iIii1I11I1II1 - OoO0O00 . i1IIi . OOooOOo / o0oOOo0O0Ooo
  iiI = self . rloc_probe_latency
  self . rloc_probe_latency = str ( o0OoooOoOo ) + "/" + str ( OOOo0o0OOO0000 )
  II111I = self . recent_rloc_probe_latencies
  self . recent_rloc_probe_latencies = [ iiI ] + II111I [ 0 : - 1 ]
  if 98 - 98: oO0o + I11i . oO0o
  if 10 - 10: iII111i + i1IIi . I11i % ooOoO0o / ooOoO0o
 def print_rloc_probe_latency ( self ) :
  return ( self . rloc_probe_latency )
  if 86 - 86: Oo0Ooo
  if 7 - 7: iIii1I11I1II1
 def print_recent_rloc_probe_latencies ( self ) :
  O000Oo = str ( self . recent_rloc_probe_latencies )
  return ( O000Oo )
  if 56 - 56: O0 - i11iIiiIii / Ii1I % OOooOOo . ooOoO0o / OoOoOO00
  if 70 - 70: I1IiiI / Ii1I
 def process_rloc_probe_reply ( self , ts , nonce , eid , group , hc , ttl , jt ) :
  I1IIiIIIii = self
  while ( True ) :
   if ( I1IIiIIIii . last_rloc_probe_nonce == nonce ) : break
   I1IIiIIIii = I1IIiIIIii . next_rloc
   if ( I1IIiIIIii == None ) :
    lprint ( "    No matching nonce state found for nonce 0x{}" . format ( lisp_hex_string ( nonce ) ) )
    if 68 - 68: OoO0O00 + iII111i + oO0o
    return
    if 19 - 19: i1IIi * I1Ii111
    if 63 - 63: I1Ii111
    if 96 - 96: O0 % iIii1I11I1II1 % I1IiiI . iII111i
    if 71 - 71: Oo0Ooo + i11iIiiIii + OOooOOo % oO0o % o0oOOo0O0Ooo * I1Ii111
    if 7 - 7: I1IiiI
    if 52 - 52: iII111i * O0 - I1Ii111
  I1IIiIIIii . last_rloc_probe_reply = ts
  I1IIiIIIii . compute_rloc_probe_rtt ( )
  iiII1iiiI1II1 = I1IIiIIIii . print_state_change ( "up" )
  if ( I1IIiIIIii . state != LISP_RLOC_UP_STATE ) :
   lisp_update_rtr_updown ( I1IIiIIIii . rloc , True )
   I1IIiIIIii . state = LISP_RLOC_UP_STATE
   I1IIiIIIii . last_state_change = lisp_get_timestamp ( )
   iiI1iIi1II1ii = lisp_map_cache . lookup_cache ( eid , True )
   if ( iiI1iIi1II1ii ) : lisp_write_ipc_map_cache ( True , iiI1iIi1II1ii )
   if 19 - 19: o0oOOo0O0Ooo
   if 93 - 93: ooOoO0o % iIii1I11I1II1 - OOooOOo . IiII + ooOoO0o
   if 63 - 63: I1ii11iIi11i / OOooOOo
   if 28 - 28: I11i / I1Ii111 + IiII * OoooooooOO - iIii1I11I1II1
   if 6 - 6: I11i % o0oOOo0O0Ooo / OoooooooOO . I1Ii111
  I1IIiIIIii . store_rloc_probe_hops ( hc , ttl )
  if 17 - 17: I1ii11iIi11i + OoooooooOO / iIii1I11I1II1 . II111iiii + Oo0Ooo
  if 7 - 7: O0 - I1ii11iIi11i - iIii1I11I1II1
  if 96 - 96: OoOoOO00 . I1IiiI . I11i * OoooooooOO + OoooooooOO * O0
  if 90 - 90: I11i + I1ii11iIi11i + OoooooooOO + OoOoOO00 + IiII / iII111i
  if ( jt ) : I1IIiIIIii . store_rloc_probe_latencies ( jt )
  if 75 - 75: i11iIiiIii
  oO0oo000O = bold ( "RLOC-probe reply" , False )
  oo0o00OO = I1IIiIIIii . rloc . print_address_no_iid ( )
  i1I1111i = bold ( str ( I1IIiIIIii . print_rloc_probe_rtt ( ) ) , False )
  oo00ooOOOo0O = ":{}" . format ( self . translated_port ) if self . translated_port != 0 else ""
  if 44 - 44: i1IIi - I11i . Oo0Ooo % I1Ii111 . iII111i + O0
  O0O0O = ""
  if ( I1IIiIIIii . rloc_next_hop != None ) :
   OooOOOoOoo0O0 , iiiI1i = I1IIiIIIii . rloc_next_hop
   O0O0O = ", nh {}({})" . format ( iiiI1i , OooOOOoOoo0O0 )
   if 79 - 79: I11i . iII111i - iII111i / iII111i * iII111i % i1IIi
   if 10 - 10: IiII
  iIIIII1i1III = bold ( I1IIiIIIii . print_rloc_probe_latency ( ) , False )
  iIIIII1i1III = ", latency {}" . format ( iIIIII1i1III ) if jt else ""
  if 60 - 60: i1IIi + i1IIi
  oOo = green ( lisp_print_eid_tuple ( eid , group ) , False )
  if 47 - 47: iII111i - I1Ii111 - I1Ii111 . ooOoO0o
  lprint ( ( "    Received {} from {}{} for {}, {}, rtt {}{}, " + "to-ttl/from-ttl {}{}" ) . format ( oO0oo000O , red ( oo0o00OO , False ) , oo00ooOOOo0O , oOo ,
  # iIii1I11I1II1
 iiII1iiiI1II1 , i1I1111i , O0O0O , str ( hc ) + "/" + str ( ttl ) , iIIIII1i1III ) )
  if 24 - 24: IiII + i11iIiiIii % I11i
  if ( I1IIiIIIii . rloc_next_hop == None ) : return
  if 49 - 49: OoO0O00 + OoOoOO00 . i11iIiiIii + o0oOOo0O0Ooo * Oo0Ooo
  if 38 - 38: oO0o % I1Ii111 . I1IiiI / iIii1I11I1II1 . oO0o % II111iiii
  if 54 - 54: iIii1I11I1II1 % II111iiii - OOooOOo * i1IIi
  if 26 - 26: OOooOOo % ooOoO0o
  I1IIiIIIii = None
  OOI11Iiii = None
  while ( True ) :
   I1IIiIIIii = self if I1IIiIIIii == None else I1IIiIIIii . next_rloc
   if ( I1IIiIIIii == None ) : break
   if ( I1IIiIIIii . up_state ( ) == False ) : continue
   if ( I1IIiIIIii . rloc_probe_rtt == - 1 ) : continue
   if 61 - 61: I11i % OOooOOo + i11iIiiIii + I11i
   if ( OOI11Iiii == None ) : OOI11Iiii = I1IIiIIIii
   if ( I1IIiIIIii . rloc_probe_rtt < OOI11Iiii . rloc_probe_rtt ) : OOI11Iiii = I1IIiIIIii
   if 69 - 69: OoOoOO00 + OoOoOO00 + o0oOOo0O0Ooo / iIii1I11I1II1 * OoO0O00
   if 44 - 44: II111iiii / o0oOOo0O0Ooo
  if ( OOI11Iiii != None ) :
   OooOOOoOoo0O0 , iiiI1i = OOI11Iiii . rloc_next_hop
   O0O0O = bold ( "nh {}({})" . format ( iiiI1i , OooOOOoOoo0O0 ) , False )
   lprint ( "    Install host-route via best {}" . format ( O0O0O ) )
   lisp_install_host_route ( oo0o00OO , None , False )
   lisp_install_host_route ( oo0o00OO , iiiI1i , True )
   if 81 - 81: I1Ii111 . Ii1I * ooOoO0o . IiII - OoOoOO00
   if 79 - 79: ooOoO0o - O0
   if 56 - 56: ooOoO0o
 def add_to_rloc_probe_list ( self , eid , group ) :
  oo0o00OO = self . rloc . print_address_no_iid ( )
  Oo0O00O = self . translated_port
  if ( Oo0O00O != 0 ) : oo0o00OO += ":" + str ( Oo0O00O )
  if 89 - 89: O0 % iIii1I11I1II1 / OoOoOO00 - I1Ii111 - I1IiiI
  if ( lisp_rloc_probe_list . has_key ( oo0o00OO ) == False ) :
   lisp_rloc_probe_list [ oo0o00OO ] = [ ]
   if 60 - 60: IiII % i11iIiiIii / OOooOOo
   if 43 - 43: i11iIiiIii * II111iiii + ooOoO0o - OoooooooOO * II111iiii / OoO0O00
  if ( group . is_null ( ) ) : group . instance_id = 0
  for O0OOOO0o0O , oOo , i11ii in lisp_rloc_probe_list [ oo0o00OO ] :
   if ( oOo . is_exact_match ( eid ) and i11ii . is_exact_match ( group ) ) :
    if ( O0OOOO0o0O == self ) :
     if ( lisp_rloc_probe_list [ oo0o00OO ] == [ ] ) :
      lisp_rloc_probe_list . pop ( oo0o00OO )
      if 92 - 92: O0 - ooOoO0o % iII111i
     return
     if 83 - 83: I1ii11iIi11i / OoOoOO00 % OoooooooOO
    lisp_rloc_probe_list [ oo0o00OO ] . remove ( [ O0OOOO0o0O , oOo , i11ii ] )
    break
    if 54 - 54: I11i / I1IiiI * IiII - iII111i
    if 37 - 37: i1IIi * I1Ii111 / I11i * II111iiii + OoooooooOO . OoO0O00
  lisp_rloc_probe_list [ oo0o00OO ] . append ( [ self , eid , group ] )
  if 22 - 22: OoOoOO00 + OoooooooOO - I1Ii111
  if 82 - 82: Ii1I % I1Ii111 / ooOoO0o
  if 86 - 86: II111iiii - iIii1I11I1II1 + oO0o + I1IiiI
  if 29 - 29: Ii1I % OoooooooOO * II111iiii
  if 88 - 88: I1Ii111 + I11i + I1Ii111 % OoO0O00 / I1ii11iIi11i - I11i
  I1IIiIIIii = lisp_rloc_probe_list [ oo0o00OO ] [ 0 ] [ 0 ]
  if ( I1IIiIIIii . state == LISP_RLOC_UNREACH_STATE ) :
   self . state = LISP_RLOC_UNREACH_STATE
   self . last_state_change = lisp_get_timestamp ( )
   if 15 - 15: Oo0Ooo - i1IIi
   if 87 - 87: O0 . o0oOOo0O0Ooo % OOooOOo / I11i - I1Ii111 % i11iIiiIii
   if 3 - 3: oO0o + iII111i + OOooOOo
 def delete_from_rloc_probe_list ( self , eid , group ) :
  oo0o00OO = self . rloc . print_address_no_iid ( )
  Oo0O00O = self . translated_port
  if ( Oo0O00O != 0 ) : oo0o00OO += ":" + str ( Oo0O00O )
  if ( lisp_rloc_probe_list . has_key ( oo0o00OO ) == False ) : return
  if 54 - 54: i11iIiiIii + OoO0O00 - IiII - iII111i / I11i
  O000O0o00o0o = [ ]
  for i1ii1i1Ii11 in lisp_rloc_probe_list [ oo0o00OO ] :
   if ( i1ii1i1Ii11 [ 0 ] != self ) : continue
   if ( i1ii1i1Ii11 [ 1 ] . is_exact_match ( eid ) == False ) : continue
   if ( i1ii1i1Ii11 [ 2 ] . is_exact_match ( group ) == False ) : continue
   O000O0o00o0o = i1ii1i1Ii11
   break
   if 65 - 65: i11iIiiIii / o0oOOo0O0Ooo % I1ii11iIi11i - O0 % OoooooooOO / o0oOOo0O0Ooo
  if ( O000O0o00o0o == [ ] ) : return
  if 36 - 36: iII111i * OoO0O00 / OOooOOo * IiII * iIii1I11I1II1 / IiII
  try :
   lisp_rloc_probe_list [ oo0o00OO ] . remove ( O000O0o00o0o )
   if ( lisp_rloc_probe_list [ oo0o00OO ] == [ ] ) :
    lisp_rloc_probe_list . pop ( oo0o00OO )
    if 79 - 79: iIii1I11I1II1 - iIii1I11I1II1 * I1ii11iIi11i
  except :
   return
   if 96 - 96: iII111i / i11iIiiIii / oO0o + Oo0Ooo
   if 65 - 65: OoOoOO00
   if 87 - 87: I11i % i1IIi + i11iIiiIii * II111iiii
 def print_rloc_probe_state ( self , trailing_linefeed ) :
  Oo0Ooo0O0 = ""
  I1IIiIIIii = self
  while ( True ) :
   OOOOooO00oooO = I1IIiIIIii . last_rloc_probe
   if ( OOOOooO00oooO == None ) : OOOOooO00oooO = 0
   Ii1i1ii = I1IIiIIIii . last_rloc_probe_reply
   if ( Ii1i1ii == None ) : Ii1i1ii = 0
   i1I1111i = I1IIiIIIii . print_rloc_probe_rtt ( )
   IiII1iiI = space ( 4 )
   if 67 - 67: II111iiii . Oo0Ooo - iII111i % I1Ii111 * oO0o
   if ( I1IIiIIIii . rloc_next_hop == None ) :
    Oo0Ooo0O0 += "RLOC-Probing:\n"
   else :
    OooOOOoOoo0O0 , iiiI1i = I1IIiIIIii . rloc_next_hop
    Oo0Ooo0O0 += "RLOC-Probing for nh {}({}):\n" . format ( iiiI1i , OooOOOoOoo0O0 )
    if 81 - 81: i11iIiiIii - O0 . iIii1I11I1II1 - I11i + iIii1I11I1II1
    if 50 - 50: Oo0Ooo . OoO0O00 + i11iIiiIii / i11iIiiIii
   Oo0Ooo0O0 += ( "{}RLOC-probe request sent: {}\n{}RLOC-probe reply " + "received: {}, rtt {}" ) . format ( IiII1iiI , lisp_print_elapsed ( OOOOooO00oooO ) ,
   # oO0o % OoOoOO00
 IiII1iiI , lisp_print_elapsed ( Ii1i1ii ) , i1I1111i )
   if 77 - 77: II111iiii + i1IIi + I1IiiI
   if ( trailing_linefeed ) : Oo0Ooo0O0 += "\n"
   if 75 - 75: OoooooooOO . I11i - OoOoOO00
   I1IIiIIIii = I1IIiIIIii . next_rloc
   if ( I1IIiIIIii == None ) : break
   Oo0Ooo0O0 += "\n"
   if 93 - 93: OoOoOO00 . I1Ii111 % I1ii11iIi11i
  return ( Oo0Ooo0O0 )
  if 58 - 58: OoooooooOO . i1IIi . Oo0Ooo - o0oOOo0O0Ooo / oO0o * I1Ii111
  if 6 - 6: oO0o - OoO0O00
 def get_encap_keys ( self ) :
  Oo0O00O = "4341" if self . translated_port == 0 else str ( self . translated_port )
  if 44 - 44: Oo0Ooo + I1ii11iIi11i % Oo0Ooo / I11i
  oo0o00OO = self . rloc . print_address_no_iid ( ) + ":" + Oo0O00O
  if 57 - 57: Oo0Ooo + Ii1I * OoooooooOO
  try :
   iIi11III = lisp_crypto_keys_by_rloc_encap [ oo0o00OO ]
   if ( iIi11III [ 1 ] ) : return ( iIi11III [ 1 ] . encrypt_key , iIi11III [ 1 ] . icv_key )
   return ( None , None )
  except :
   return ( None , None )
   if 30 - 30: O0
   if 70 - 70: oO0o
   if 89 - 89: O0
 def rloc_recent_rekey ( self ) :
  Oo0O00O = "4341" if self . translated_port == 0 else str ( self . translated_port )
  if 3 - 3: iII111i - O0 / I11i
  oo0o00OO = self . rloc . print_address_no_iid ( ) + ":" + Oo0O00O
  if 46 - 46: I1IiiI . OoooooooOO / iIii1I11I1II1 - ooOoO0o * OOooOOo
  try :
   Oo000O000 = lisp_crypto_keys_by_rloc_encap [ oo0o00OO ] [ 1 ]
   if ( Oo000O000 == None ) : return ( False )
   if ( Oo000O000 . last_rekey == None ) : return ( True )
   return ( time . time ( ) - Oo000O000 . last_rekey < 1 )
  except :
   return ( False )
   if 55 - 55: o0oOOo0O0Ooo + iIii1I11I1II1 / I11i
   if 97 - 97: i11iIiiIii
   if 71 - 71: oO0o + Oo0Ooo
   if 7 - 7: OoOoOO00 / I1ii11iIi11i * i1IIi
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
  self . recent_sources = { }
  self . last_multicast_map_request = 0
  if 87 - 87: OoooooooOO * IiII - I1IiiI % I1ii11iIi11i % iIii1I11I1II1
  if 28 - 28: I1Ii111 / o0oOOo0O0Ooo / II111iiii . o0oOOo0O0Ooo . Ii1I / I11i
 def print_mapping ( self , eid_indent , rloc_indent ) :
  i1 = lisp_print_elapsed ( self . uptime )
  IIi1iiIII11 = "" if self . group . is_null ( ) else ", group {}" . format ( self . group . print_prefix ( ) )
  if 43 - 43: I1Ii111 . I1IiiI
  lprint ( "{}eid {}{}, uptime {}, {} rlocs:" . format ( eid_indent ,
 green ( self . eid . print_prefix ( ) , False ) , IIi1iiIII11 , i1 ,
 len ( self . rloc_set ) ) )
  for I1IIiIIIii in self . rloc_set : I1IIiIIIii . print_rloc ( rloc_indent )
  if 16 - 16: i11iIiiIii * Oo0Ooo * Ii1I / OoOoOO00 / OOooOOo
  if 11 - 11: o0oOOo0O0Ooo * OoO0O00 . o0oOOo0O0Ooo - I1IiiI / IiII - OOooOOo
 def print_eid_tuple ( self ) :
  return ( lisp_print_eid_tuple ( self . eid , self . group ) )
  if 19 - 19: i1IIi + IiII . OoO0O00 / O0 - I1Ii111 - Oo0Ooo
  if 24 - 24: iII111i + i1IIi
 def print_ttl ( self ) :
  oOoooOOO0o0 = self . map_cache_ttl
  if ( oOoooOOO0o0 == None ) : return ( "forever" )
  if 31 - 31: OoOoOO00
  if ( oOoooOOO0o0 >= 3600 ) :
   if ( ( oOoooOOO0o0 % 3600 ) == 0 ) :
    oOoooOOO0o0 = str ( oOoooOOO0o0 / 3600 ) + " hours"
   else :
    oOoooOOO0o0 = str ( oOoooOOO0o0 * 60 ) + " mins"
    if 37 - 37: iIii1I11I1II1 % IiII / i11iIiiIii - oO0o
  elif ( oOoooOOO0o0 >= 60 ) :
   if ( ( oOoooOOO0o0 % 60 ) == 0 ) :
    oOoooOOO0o0 = str ( oOoooOOO0o0 / 60 ) + " mins"
   else :
    oOoooOOO0o0 = str ( oOoooOOO0o0 ) + " secs"
    if 43 - 43: II111iiii - OoooooooOO
  else :
   oOoooOOO0o0 = str ( oOoooOOO0o0 ) + " secs"
   if 11 - 11: I1IiiI
  return ( oOoooOOO0o0 )
  if 76 - 76: iII111i - II111iiii % Oo0Ooo . I1Ii111
  if 64 - 64: OoO0O00 - OoO0O00
 def refresh ( self ) :
  if ( self . group . is_null ( ) ) : return ( self . refresh_unicast ( ) )
  return ( self . refresh_multicast ( ) )
  if 93 - 93: Oo0Ooo . O0
  if 75 - 75: iII111i * II111iiii - I1IiiI
 def refresh_unicast ( self ) :
  return ( self . is_active ( ) and self . has_ttl_elapsed ( ) and
 self . gleaned == False )
  if 30 - 30: i1IIi / ooOoO0o . ooOoO0o
  if 22 - 22: I11i % iIii1I11I1II1 - i11iIiiIii * OoOoOO00 - I1Ii111
 def refresh_multicast ( self ) :
  if 97 - 97: i11iIiiIii . OoOoOO00 + oO0o * O0 % OoO0O00 - Ii1I
  if 46 - 46: I1Ii111
  if 87 - 87: o0oOOo0O0Ooo - iII111i * OoO0O00 * o0oOOo0O0Ooo . o0oOOo0O0Ooo / OOooOOo
  if 50 - 50: i11iIiiIii - II111iiii * OoooooooOO + II111iiii - ooOoO0o
  if 52 - 52: i1IIi + i1IIi * i1IIi / OoOoOO00
  oO000o0Oo00 = int ( ( time . time ( ) - self . uptime ) % self . map_cache_ttl )
  O0iIIiii1ii1III = ( oO000o0Oo00 in [ 0 , 1 , 2 ] )
  if ( O0iIIiii1ii1III == False ) : return ( False )
  if 91 - 91: OoOoOO00 * I1IiiI - Oo0Ooo
  if 36 - 36: O0 - IiII % iII111i
  if 93 - 93: OoooooooOO . iIii1I11I1II1 % OoO0O00 / I11i + oO0o % OOooOOo
  if 9 - 9: IiII . Oo0Ooo - iIii1I11I1II1 / I1Ii111
  o0O0oOO0oOOo = ( ( time . time ( ) - self . last_multicast_map_request ) <= 2 )
  if ( o0O0oOO0oOOo ) : return ( False )
  if 37 - 37: Oo0Ooo / I1IiiI
  self . last_multicast_map_request = lisp_get_timestamp ( )
  return ( True )
  if 23 - 23: II111iiii / iII111i
  if 55 - 55: i11iIiiIii - Ii1I % OoooooooOO * OoooooooOO
 def has_ttl_elapsed ( self ) :
  if ( self . map_cache_ttl == None ) : return ( False )
  oO000o0Oo00 = time . time ( ) - self . last_refresh_time
  if ( oO000o0Oo00 >= self . map_cache_ttl ) : return ( True )
  if 92 - 92: iIii1I11I1II1
  if 47 - 47: Oo0Ooo + Oo0Ooo * ooOoO0o - OoOoOO00 + II111iiii
  if 10 - 10: II111iiii / ooOoO0o . Ii1I / I1Ii111 / oO0o
  if 8 - 8: OOooOOo / ooOoO0o * I11i + OOooOOo * i1IIi
  if 48 - 48: o0oOOo0O0Ooo - I1ii11iIi11i / iII111i
  Ooo000o0o = self . map_cache_ttl - ( self . map_cache_ttl / 10 )
  if ( oO000o0Oo00 >= Ooo000o0o ) : return ( True )
  return ( False )
  if 31 - 31: i11iIiiIii % IiII + IiII / oO0o
  if 53 - 53: IiII
 def is_active ( self ) :
  if ( self . stats . last_increment == None ) : return ( False )
  oO000o0Oo00 = time . time ( ) - self . stats . last_increment
  return ( oO000o0Oo00 <= 60 )
  if 52 - 52: I1Ii111 * I11i - II111iiii + OOooOOo + II111iiii
  if 91 - 91: i1IIi + Oo0Ooo - I1ii11iIi11i + I1ii11iIi11i * O0 / O0
 def match_eid_tuple ( self , db ) :
  if ( self . eid . is_exact_match ( db . eid ) == False ) : return ( False )
  if ( self . group . is_exact_match ( db . group ) == False ) : return ( False )
  return ( True )
  if 78 - 78: OoooooooOO
  if 8 - 8: Oo0Ooo - Oo0Ooo % O0 - Ii1I / o0oOOo0O0Ooo % Oo0Ooo
 def sort_rloc_set ( self ) :
  self . rloc_set . sort ( key = operator . attrgetter ( 'rloc.address' ) )
  if 51 - 51: iIii1I11I1II1 / iIii1I11I1II1 * I1ii11iIi11i / I11i
  if 18 - 18: Ii1I - i11iIiiIii + OoO0O00 . O0 - iII111i
 def delete_rlocs_from_rloc_probe_list ( self ) :
  for I1IIiIIIii in self . best_rloc_set :
   I1IIiIIIii . delete_from_rloc_probe_list ( self . eid , self . group )
   if 9 - 9: OoooooooOO / iII111i + o0oOOo0O0Ooo / II111iiii / I1Ii111
   if 44 - 44: I1IiiI / iII111i / Oo0Ooo
   if 66 - 66: I1Ii111 + OoooooooOO % I1IiiI . iII111i * Oo0Ooo + o0oOOo0O0Ooo
 def build_best_rloc_set ( self ) :
  oO000O0o = self . best_rloc_set
  self . best_rloc_set = [ ]
  if ( self . rloc_set == None ) : return
  if 44 - 44: OoooooooOO + OoO0O00 % OoOoOO00 * I1Ii111 . I1Ii111
  if 17 - 17: iIii1I11I1II1 % Ii1I * I1IiiI % I1ii11iIi11i * I1IiiI % Oo0Ooo
  if 80 - 80: OOooOOo . II111iiii % o0oOOo0O0Ooo . o0oOOo0O0Ooo % i11iIiiIii % OOooOOo
  if 28 - 28: Ii1I
  OoOoOO = 256
  for I1IIiIIIii in self . rloc_set :
   if ( I1IIiIIIii . up_state ( ) ) : OoOoOO = min ( I1IIiIIIii . priority , OoOoOO )
   if 55 - 55: I1ii11iIi11i / iIii1I11I1II1 . OoOoOO00 - ooOoO0o
   if 67 - 67: O0 - II111iiii + OOooOOo - OoO0O00
   if 49 - 49: OoOoOO00 / o0oOOo0O0Ooo % OoO0O00
   if 50 - 50: iIii1I11I1II1 - OoooooooOO + I1ii11iIi11i / Oo0Ooo * OOooOOo
   if 37 - 37: O0 % I1Ii111 * OOooOOo / OOooOOo
   if 95 - 95: I1ii11iIi11i % o0oOOo0O0Ooo . oO0o
   if 9 - 9: OoOoOO00 % OoOoOO00 * ooOoO0o / I1IiiI - OOooOOo
   if 62 - 62: Oo0Ooo + OOooOOo - Oo0Ooo
   if 32 - 32: OoooooooOO
   if 99 - 99: II111iiii % Oo0Ooo / OOooOOo / I1ii11iIi11i % O0 + i1IIi
  for I1IIiIIIii in self . rloc_set :
   if ( I1IIiIIIii . priority <= OoOoOO ) :
    if ( I1IIiIIIii . unreach_state ( ) and I1IIiIIIii . last_rloc_probe == None ) :
     I1IIiIIIii . last_rloc_probe = lisp_get_timestamp ( )
     if 90 - 90: OoOoOO00 % OoO0O00 . I1IiiI * oO0o
    self . best_rloc_set . append ( I1IIiIIIii )
    if 17 - 17: O0 - i1IIi
    if 77 - 77: OOooOOo - i1IIi / II111iiii . I1Ii111 + O0
    if 1 - 1: OoooooooOO % iIii1I11I1II1 * I1ii11iIi11i
    if 17 - 17: Ii1I * i1IIi % OoO0O00
    if 12 - 12: I1ii11iIi11i
    if 86 - 86: iIii1I11I1II1 % iII111i
    if 80 - 80: Oo0Ooo
    if 37 - 37: i11iIiiIii - I1Ii111
  for I1IIiIIIii in oO000O0o :
   if ( I1IIiIIIii . priority < OoOoOO ) : continue
   I1IIiIIIii . delete_from_rloc_probe_list ( self . eid , self . group )
   if 50 - 50: I1IiiI / Ii1I / Ii1I + O0 % I11i - i1IIi
  for I1IIiIIIii in self . best_rloc_set :
   if ( I1IIiIIIii . rloc . is_null ( ) ) : continue
   I1IIiIIIii . add_to_rloc_probe_list ( self . eid , self . group )
   if 72 - 72: II111iiii . OoO0O00 . II111iiii * I1ii11iIi11i
   if 42 - 42: II111iiii
   if 45 - 45: I1ii11iIi11i . I1Ii111 . i1IIi * OOooOOo
 def select_rloc ( self , lisp_packet , ipc_socket ) :
  IiiiIi1iiii11 = lisp_packet . packet
  O0iII11II1I1 = lisp_packet . inner_version
  IiiI1iii1iIiiI = len ( self . best_rloc_set )
  if ( IiiI1iii1iIiiI == 0 ) :
   self . stats . increment ( len ( IiiiIi1iiii11 ) )
   return ( [ None , None , None , self . action , None , None ] )
   if 95 - 95: O0 . IiII % I1IiiI
   if 18 - 18: i11iIiiIii / ooOoO0o
  oooIiI1I = 4 if lisp_load_split_pings else 0
  IIi1iiIIi1i = lisp_packet . hash_ports ( )
  if ( O0iII11II1I1 == 4 ) :
   for IiIIi1IiiIiI in range ( 8 + oooIiI1I ) :
    IIi1iiIIi1i = IIi1iiIIi1i ^ struct . unpack ( "B" , IiiiIi1iiii11 [ IiIIi1IiiIiI + 12 ] ) [ 0 ]
    if 78 - 78: i11iIiiIii . i1IIi - o0oOOo0O0Ooo % o0oOOo0O0Ooo . i1IIi
  elif ( O0iII11II1I1 == 6 ) :
   for IiIIi1IiiIiI in range ( 0 , 32 + oooIiI1I , 4 ) :
    IIi1iiIIi1i = IIi1iiIIi1i ^ struct . unpack ( "I" , IiiiIi1iiii11 [ IiIIi1IiiIiI + 8 : IiIIi1IiiIiI + 12 ] ) [ 0 ]
    if 28 - 28: OoOoOO00
   IIi1iiIIi1i = ( IIi1iiIIi1i >> 16 ) + ( IIi1iiIIi1i & 0xffff )
   IIi1iiIIi1i = ( IIi1iiIIi1i >> 8 ) + ( IIi1iiIIi1i & 0xff )
  else :
   for IiIIi1IiiIiI in range ( 0 , 12 + oooIiI1I , 4 ) :
    IIi1iiIIi1i = IIi1iiIIi1i ^ struct . unpack ( "I" , IiiiIi1iiii11 [ IiIIi1IiiIiI : IiIIi1IiiIiI + 4 ] ) [ 0 ]
    if 31 - 31: i1IIi - I1IiiI . I1IiiI * Ii1I
    if 80 - 80: OoOoOO00
    if 36 - 36: I11i - ooOoO0o - ooOoO0o . I1ii11iIi11i / II111iiii % OOooOOo
  if ( lisp_data_plane_logging ) :
   IiI1II = [ ]
   for O0OOOO0o0O in self . best_rloc_set :
    if ( O0OOOO0o0O . rloc . is_null ( ) ) : continue
    IiI1II . append ( [ O0OOOO0o0O . rloc . print_address_no_iid ( ) , O0OOOO0o0O . print_state ( ) ] )
    if 96 - 96: OOooOOo
   dprint ( "Packet hash {}, index {}, best-rloc-list: {}" . format ( hex ( IIi1iiIIi1i ) , IIi1iiIIi1i % IiiI1iii1iIiiI , red ( str ( IiI1II ) , False ) ) )
   if 85 - 85: iIii1I11I1II1 + iII111i + iII111i - ooOoO0o * OoO0O00
   if 80 - 80: i11iIiiIii / OOooOOo . OoooooooOO % I11i - iII111i * iIii1I11I1II1
   if 70 - 70: Oo0Ooo
   if 75 - 75: I1Ii111
   if 40 - 40: OoO0O00 % Oo0Ooo / OoooooooOO / i11iIiiIii
   if 5 - 5: O0 % i11iIiiIii
  I1IIiIIIii = self . best_rloc_set [ IIi1iiIIi1i % IiiI1iii1iIiiI ]
  if 60 - 60: I1ii11iIi11i / I11i
  if 100 - 100: I1IiiI
  if 44 - 44: iIii1I11I1II1 + Oo0Ooo - I1Ii111 . OoooooooOO
  if 28 - 28: Ii1I + OOooOOo % IiII . i11iIiiIii - I1IiiI * Oo0Ooo
  if 2 - 2: I11i * I1ii11iIi11i + O0
  ii1 = lisp_get_echo_nonce ( I1IIiIIIii . rloc , None )
  if ( ii1 ) :
   ii1 . change_state ( I1IIiIIIii )
   if ( I1IIiIIIii . no_echoed_nonce_state ( ) ) :
    ii1 . request_nonce_sent = None
    if 44 - 44: iIii1I11I1II1 / II111iiii - ooOoO0o
    if 10 - 10: OOooOOo
    if 78 - 78: OOooOOo * I1ii11iIi11i % i11iIiiIii % o0oOOo0O0Ooo . I1ii11iIi11i / OoooooooOO
    if 12 - 12: iIii1I11I1II1 % OoO0O00 + OOooOOo * iIii1I11I1II1 - iIii1I11I1II1
    if 70 - 70: OoO0O00 % i11iIiiIii * IiII . I11i * Oo0Ooo
    if 17 - 17: i1IIi
  if ( I1IIiIIIii . up_state ( ) == False ) :
   I1IIIIiI1i = IIi1iiIIi1i % IiiI1iii1iIiiI
   ooo = ( I1IIIIiI1i + 1 ) % IiiI1iii1iIiiI
   while ( ooo != I1IIIIiI1i ) :
    I1IIiIIIii = self . best_rloc_set [ ooo ]
    if ( I1IIiIIIii . up_state ( ) ) : break
    ooo = ( ooo + 1 ) % IiiI1iii1iIiiI
    if 93 - 93: I1Ii111 / oO0o + oO0o
   if ( ooo == I1IIIIiI1i ) :
    self . build_best_rloc_set ( )
    return ( [ None , None , None , None , None , None ] )
    if 48 - 48: IiII + OoOoOO00
    if 42 - 42: Oo0Ooo + iII111i * ooOoO0o
    if 72 - 72: iIii1I11I1II1 % I1Ii111
    if 77 - 77: I1Ii111 * I1IiiI / iIii1I11I1II1 . II111iiii * Oo0Ooo
    if 71 - 71: ooOoO0o / iIii1I11I1II1 % O0 / I1ii11iIi11i . I1Ii111 / i11iIiiIii
    if 6 - 6: oO0o . OoO0O00 - II111iiii . I1IiiI - o0oOOo0O0Ooo - i1IIi
  I1IIiIIIii . stats . increment ( len ( IiiiIi1iiii11 ) )
  if 42 - 42: Ii1I + i11iIiiIii
  if 46 - 46: O0 % OoOoOO00 - I1Ii111 . I1IiiI
  if 66 - 66: II111iiii * iIii1I11I1II1 * ooOoO0o * I11i . II111iiii - ooOoO0o
  if 15 - 15: I1ii11iIi11i - i11iIiiIii - Ii1I / Ii1I . iII111i
  if ( I1IIiIIIii . rle_name and I1IIiIIIii . rle == None ) :
   if ( lisp_rle_list . has_key ( I1IIiIIIii . rle_name ) ) :
    I1IIiIIIii . rle = lisp_rle_list [ I1IIiIIIii . rle_name ]
    if 36 - 36: oO0o + Oo0Ooo * I1Ii111 % OOooOOo . Oo0Ooo . I1IiiI
    if 81 - 81: o0oOOo0O0Ooo . OoOoOO00 . i11iIiiIii
  if ( I1IIiIIIii . rle ) : return ( [ None , None , None , None , I1IIiIIIii . rle , None ] )
  if 13 - 13: i1IIi
  if 70 - 70: O0 / II111iiii
  if 98 - 98: OoOoOO00 - O0 . O0 + ooOoO0o * iIii1I11I1II1
  if 7 - 7: IiII * OoOoOO00 + iIii1I11I1II1 / OoOoOO00 + Oo0Ooo / o0oOOo0O0Ooo
  if ( I1IIiIIIii . elp and I1IIiIIIii . elp . use_elp_node ) :
   return ( [ I1IIiIIIii . elp . use_elp_node . address , None , None , None , None ,
 None ] )
   if 77 - 77: i1IIi . I1IiiI
   if 59 - 59: O0 + OoooooooOO - i1IIi
   if 87 - 87: IiII * OoooooooOO / Oo0Ooo % iIii1I11I1II1 % oO0o
   if 97 - 97: ooOoO0o % i1IIi . IiII / Oo0Ooo . I1Ii111 . OoO0O00
   if 12 - 12: I1IiiI
  ooOoo0oo = None if ( I1IIiIIIii . rloc . is_null ( ) ) else I1IIiIIIii . rloc
  Oo0O00O = I1IIiIIIii . translated_port
  I11I1iI = self . action if ( ooOoo0oo == None ) else None
  if 11 - 11: Oo0Ooo % i1IIi
  if 70 - 70: II111iiii * Oo0Ooo * OOooOOo - I1IiiI + iIii1I11I1II1 + ooOoO0o
  if 27 - 27: I1ii11iIi11i - I1Ii111 * O0 % ooOoO0o / I1IiiI
  if 53 - 53: i11iIiiIii * i11iIiiIii % O0 % IiII
  if 57 - 57: I1IiiI % i1IIi * OoO0O00 + I1Ii111 . I11i % I11i
  Iii11I = None
  if ( ii1 and ii1 . request_nonce_timeout ( ) == False ) :
   Iii11I = ii1 . get_request_or_echo_nonce ( ipc_socket , ooOoo0oo )
   if 69 - 69: I1ii11iIi11i / OoOoOO00 + iIii1I11I1II1
   if 8 - 8: OoooooooOO
   if 72 - 72: OoooooooOO % I1ii11iIi11i - OoO0O00 . OoooooooOO
   if 83 - 83: o0oOOo0O0Ooo * Ii1I - Oo0Ooo * iII111i - i11iIiiIii
   if 6 - 6: I1IiiI + i11iIiiIii + O0 / i1IIi
  return ( [ ooOoo0oo , Oo0O00O , Iii11I , I11I1iI , None , I1IIiIIIii ] )
  if 50 - 50: iII111i . II111iiii % I1Ii111 % I1IiiI / o0oOOo0O0Ooo . I1IiiI
  if 76 - 76: OOooOOo % iII111i
 def do_rloc_sets_match ( self , rloc_address_set ) :
  if ( len ( self . rloc_set ) != len ( rloc_address_set ) ) : return ( False )
  if 80 - 80: iIii1I11I1II1 + o0oOOo0O0Ooo + iIii1I11I1II1
  if 63 - 63: OoOoOO00 - o0oOOo0O0Ooo % II111iiii - Ii1I
  if 81 - 81: iII111i % OOooOOo * oO0o
  if 84 - 84: iII111i - OoooooooOO + I1ii11iIi11i - I1IiiI
  if 52 - 52: oO0o / ooOoO0o / iII111i / OoOoOO00 * iIii1I11I1II1
  for O0OooOoooO0O in self . rloc_set :
   for I1IIiIIIii in rloc_address_set :
    if ( I1IIiIIIii . is_exact_match ( O0OooOoooO0O . rloc ) == False ) : continue
    I1IIiIIIii = None
    break
    if 74 - 74: oO0o . I1ii11iIi11i - iIii1I11I1II1
   if ( I1IIiIIIii == rloc_address_set [ - 1 ] ) : return ( False )
   if 73 - 73: OoO0O00 / O0 . o0oOOo0O0Ooo
  return ( True )
  if 100 - 100: Ii1I . OoO0O00 % I1ii11iIi11i % O0 * Oo0Ooo - OoOoOO00
  if 15 - 15: OOooOOo - OOooOOo - OoooooooOO * OoO0O00
 def get_rloc ( self , rloc ) :
  for O0OooOoooO0O in self . rloc_set :
   O0OOOO0o0O = O0OooOoooO0O . rloc
   if ( rloc . is_exact_match ( O0OOOO0o0O ) ) : return ( O0OooOoooO0O )
   if 12 - 12: II111iiii * I1Ii111 / I1Ii111 * oO0o * Oo0Ooo
  return ( None )
  if 17 - 17: OoOoOO00 % I1Ii111 / iII111i * I1Ii111
  if 96 - 96: Oo0Ooo % o0oOOo0O0Ooo . OoOoOO00 % i11iIiiIii / OoooooooOO
 def get_rloc_by_interface ( self , interface ) :
  for O0OooOoooO0O in self . rloc_set :
   if ( O0OooOoooO0O . interface == interface ) : return ( O0OooOoooO0O )
   if 87 - 87: OoooooooOO - Ii1I . I11i / I1Ii111 . i1IIi
  return ( None )
  if 86 - 86: i1IIi . oO0o % OOooOOo
  if 99 - 99: oO0o / I1Ii111 * oO0o * I11i
 def add_db ( self ) :
  if ( self . group . is_null ( ) ) :
   lisp_db_for_lookups . add_cache ( self . eid , self )
  else :
   iiIII1 = lisp_db_for_lookups . lookup_cache ( self . group , True )
   if ( iiIII1 == None ) :
    iiIII1 = lisp_mapping ( self . group , self . group , [ ] )
    lisp_db_for_lookups . add_cache ( self . group , iiIII1 )
    if 38 - 38: o0oOOo0O0Ooo + OoOoOO00
   iiIII1 . add_source_entry ( self )
   if 24 - 24: Ii1I - OOooOOo - o0oOOo0O0Ooo - I1Ii111 / OoooooooOO
   if 17 - 17: OoO0O00
   if 79 - 79: Ii1I - II111iiii
 def add_cache ( self , do_ipc = True ) :
  if ( self . group . is_null ( ) ) :
   lisp_map_cache . add_cache ( self . eid , self )
   if ( lisp_program_hardware ) : lisp_program_vxlan_hardware ( self )
  else :
   iiI1iIi1II1ii = lisp_map_cache . lookup_cache ( self . group , True )
   if ( iiI1iIi1II1ii == None ) :
    iiI1iIi1II1ii = lisp_mapping ( self . group , self . group , [ ] )
    iiI1iIi1II1ii . eid . copy_address ( self . group )
    iiI1iIi1II1ii . group . copy_address ( self . group )
    lisp_map_cache . add_cache ( self . group , iiI1iIi1II1ii )
    if 57 - 57: II111iiii / OoooooooOO
   if ( self . eid . is_null ( ) ) : self . eid . make_default_route ( iiI1iIi1II1ii . group )
   iiI1iIi1II1ii . add_source_entry ( self )
   if 4 - 4: I11i * OoOoOO00
  if ( do_ipc ) : lisp_write_ipc_map_cache ( True , self )
  if 18 - 18: iIii1I11I1II1 % OOooOOo - I1ii11iIi11i * i1IIi + Oo0Ooo
  if 87 - 87: oO0o . I11i
 def delete_cache ( self ) :
  self . delete_rlocs_from_rloc_probe_list ( )
  lisp_write_ipc_map_cache ( False , self )
  if 15 - 15: oO0o
  if ( self . group . is_null ( ) ) :
   lisp_map_cache . delete_cache ( self . eid )
   if ( lisp_program_hardware ) :
    II11IIi1Ii1i = self . eid . print_prefix_no_iid ( )
    os . system ( "ip route delete {}" . format ( II11IIi1Ii1i ) )
    if 88 - 88: iII111i - I1ii11iIi11i / OoOoOO00 + O0 % oO0o
  else :
   iiI1iIi1II1ii = lisp_map_cache . lookup_cache ( self . group , True )
   if ( iiI1iIi1II1ii == None ) : return
   if 22 - 22: o0oOOo0O0Ooo * O0 % Oo0Ooo
   OOO0oo0OOo = iiI1iIi1II1ii . lookup_source_cache ( self . eid , True )
   if ( OOO0oo0OOo == None ) : return
   if 33 - 33: OoOoOO00 - I11i
   iiI1iIi1II1ii . source_cache . delete_cache ( self . eid )
   if ( iiI1iIi1II1ii . source_cache . cache_size ( ) == 0 ) :
    lisp_map_cache . delete_cache ( self . group )
    if 45 - 45: O0 * II111iiii / i11iIiiIii
    if 38 - 38: OoooooooOO % i11iIiiIii - O0 / O0
    if 59 - 59: OoO0O00 % iII111i + oO0o * II111iiii . OOooOOo
    if 26 - 26: OOooOOo % OoooooooOO . Ii1I / iIii1I11I1II1 * I1IiiI
 def add_source_entry ( self , source_mc ) :
  if ( self . source_cache == None ) : self . source_cache = lisp_cache ( )
  self . source_cache . add_cache ( source_mc . eid , source_mc )
  if 85 - 85: IiII / Ii1I - I1ii11iIi11i * OOooOOo
  if 19 - 19: I1ii11iIi11i
 def lookup_source_cache ( self , source , exact ) :
  if ( self . source_cache == None ) : return ( None )
  return ( self . source_cache . lookup_cache ( source , exact ) )
  if 12 - 12: ooOoO0o * I1ii11iIi11i * O0 / oO0o + iII111i - iIii1I11I1II1
  if 81 - 81: Ii1I
 def dynamic_eid_configured ( self ) :
  return ( self . dynamic_eids != None )
  if 87 - 87: O0 % iII111i
  if 57 - 57: Ii1I
 def star_secondary_iid ( self , prefix ) :
  if ( self . secondary_iid == None ) : return ( prefix )
  o0OoO0000o = "," + str ( self . secondary_iid )
  return ( prefix . replace ( o0OoO0000o , o0OoO0000o + "*" ) )
  if 49 - 49: I11i
  if 22 - 22: Oo0Ooo % OOooOOo + O0 - OoO0O00 % I11i * O0
 def increment_decap_stats ( self , packet ) :
  Oo0O00O = packet . udp_dport
  if ( Oo0O00O == LISP_DATA_PORT ) :
   I1IIiIIIii = self . get_rloc ( packet . outer_dest )
  else :
   if 42 - 42: O0
   if 55 - 55: i11iIiiIii % OOooOOo
   if 10 - 10: OoOoOO00 / i11iIiiIii
   if 21 - 21: Ii1I - i1IIi / I11i + IiII
   for I1IIiIIIii in self . rloc_set :
    if ( I1IIiIIIii . translated_port != 0 ) : break
    if 44 - 44: OoooooooOO % I11i / O0
    if 94 - 94: IiII
  if ( I1IIiIIIii != None ) : I1IIiIIIii . stats . increment ( len ( packet . packet ) )
  self . stats . increment ( len ( packet . packet ) )
  if 83 - 83: OoO0O00
  if 55 - 55: iII111i
 def rtrs_in_rloc_set ( self ) :
  for I1IIiIIIii in self . rloc_set :
   if ( I1IIiIIIii . is_rtr ( ) ) : return ( True )
   if 37 - 37: oO0o / o0oOOo0O0Ooo + I11i * OoO0O00 * o0oOOo0O0Ooo
  return ( False )
  if 33 - 33: I1Ii111
  if 97 - 97: Ii1I / iII111i - ooOoO0o + IiII * OoOoOO00 - OOooOOo
 def add_recent_source ( self , source ) :
  self . recent_sources [ source . print_address ( ) ] = lisp_get_timestamp ( )
  if 43 - 43: oO0o / II111iiii - iII111i / oO0o
  if 98 - 98: OoOoOO00 / OOooOOo
  if 31 - 31: II111iiii % I11i - I11i
class lisp_dynamic_eid ( ) :
 def __init__ ( self ) :
  self . dynamic_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . uptime = lisp_get_timestamp ( )
  self . interface = None
  self . last_packet = None
  self . timeout = LISP_DEFAULT_DYN_EID_TIMEOUT
  if 17 - 17: iII111i . IiII + OOooOOo % I1Ii111 % i11iIiiIii
  if 100 - 100: i11iIiiIii - O0 . OoO0O00 / O0 - Ii1I - IiII
 def get_timeout ( self , interface ) :
  try :
   O0OooooOo0 = lisp_myinterfaces [ interface ]
   self . timeout = O0OooooOo0 . dynamic_eid_timeout
  except :
   self . timeout = LISP_DEFAULT_DYN_EID_TIMEOUT
   if 26 - 26: Ii1I * iII111i
   if 14 - 14: ooOoO0o . O0 * OOooOOo
   if 34 - 34: I1ii11iIi11i . OOooOOo + OoO0O00 % o0oOOo0O0Ooo * O0 * I1IiiI
   if 9 - 9: IiII / i11iIiiIii . o0oOOo0O0Ooo - OOooOOo % I1Ii111
class lisp_group_mapping ( ) :
 def __init__ ( self , group_name , ms_name , group_prefix , sources , rle_addr ) :
  self . group_name = group_name
  self . group_prefix = group_prefix
  self . use_ms_name = ms_name
  self . sources = sources
  self . rle_address = rle_addr
  if 65 - 65: I1IiiI % OoOoOO00
  if 45 - 45: o0oOOo0O0Ooo
 def add_group ( self ) :
  lisp_group_mapping_list [ self . group_name ] = self
  if 33 - 33: ooOoO0o % O0 % I1ii11iIi11i % o0oOOo0O0Ooo + i11iIiiIii . I1Ii111
  if 21 - 21: I1Ii111 * I1ii11iIi11i * ooOoO0o
  if 73 - 73: OoOoOO00 * O0
  if 1 - 1: OOooOOo * OoooooooOO
  if 46 - 46: I1ii11iIi11i * I1Ii111 / OOooOOo / I1IiiI
  if 7 - 7: OOooOOo / OoOoOO00
  if 93 - 93: iIii1I11I1II1 * Ii1I - iII111i
  if 94 - 94: iIii1I11I1II1 * iIii1I11I1II1 * I11i % i11iIiiIii
  if 38 - 38: I1IiiI % I1ii11iIi11i * I1IiiI + OOooOOo - OoOoOO00
  if 78 - 78: OOooOOo + I1Ii111
def lisp_is_group_more_specific ( group_str , group_mapping ) :
 o0OoO0000o = group_mapping . group_prefix . instance_id
 OO00O = group_mapping . group_prefix . mask_len
 IIi1iiIII11 = lisp_address ( LISP_AFI_IPV4 , group_str , 32 , o0OoO0000o )
 if ( IIi1iiIII11 . is_more_specific ( group_mapping . group_prefix ) ) : return ( OO00O )
 return ( - 1 )
 if 41 - 41: I11i + Oo0Ooo . Oo0Ooo / iII111i . OoOoOO00
 if 1 - 1: ooOoO0o + iII111i % i11iIiiIii / OoOoOO00
 if 98 - 98: IiII
 if 75 - 75: OoooooooOO % IiII + Ii1I - i1IIi / OoooooooOO
 if 57 - 57: iII111i
 if 18 - 18: II111iiii % i11iIiiIii + I11i - OOooOOo
 if 100 - 100: o0oOOo0O0Ooo / Ii1I - iIii1I11I1II1 / oO0o
def lisp_lookup_group ( group ) :
 IiI1II = None
 for O00o in lisp_group_mapping_list . values ( ) :
  OO00O = lisp_is_group_more_specific ( group , O00o )
  if ( OO00O == - 1 ) : continue
  if ( IiI1II == None or OO00O > IiI1II . group_prefix . mask_len ) : IiI1II = O00o
  if 10 - 10: II111iiii * Ii1I % IiII + I11i
 return ( IiI1II )
 if 29 - 29: IiII / Ii1I / I1Ii111
 if 30 - 30: i1IIi + OOooOOo + Oo0Ooo % iII111i % O0 + i1IIi
lisp_site_flags = {
 "P" : "ETR is {}Requesting Map-Server to Proxy Map-Reply" ,
 "S" : "ETR is {}LISP-SEC capable" ,
 "I" : "xTR-ID and site-ID are {}included in Map-Register" ,
 "T" : "Use Map-Register TTL field to timeout registration is {}set" ,
 "R" : "Merging registrations are {}requested" ,
 "M" : "ETR is {}a LISP Mobile-Node" ,
 "N" : "ETR is {}requesting Map-Notify messages from Map-Server"
 }
if 45 - 45: ooOoO0o
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
  if 89 - 89: iIii1I11I1II1 . I1Ii111
  if 43 - 43: Oo0Ooo + o0oOOo0O0Ooo % o0oOOo0O0Ooo % I1ii11iIi11i / iIii1I11I1II1 . I1ii11iIi11i
  if 59 - 59: IiII . OoO0O00 - OoooooooOO . O0
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
  if 33 - 33: Ii1I
  if 95 - 95: OoooooooOO + OoO0O00 * ooOoO0o
 def print_eid_tuple ( self ) :
  return ( lisp_print_eid_tuple ( self . eid , self . group ) )
  if 40 - 40: I1IiiI / OOooOOo * Ii1I
  if 98 - 98: I1IiiI
 def print_flags ( self , html ) :
  if ( html == False ) :
   Oo0Ooo0O0 = "{}-{}-{}-{}-{}-{}-{}" . format ( "P" if self . proxy_reply_requested else "p" ,
   # o0oOOo0O0Ooo
 "S" if self . lisp_sec_present else "s" ,
 "I" if self . xtr_id_present else "i" ,
 "T" if self . use_register_ttl_requested else "t" ,
 "R" if self . merge_register_requested else "r" ,
 "M" if self . mobile_node_requested else "m" ,
 "N" if self . map_notify_requested else "n" )
  else :
   Ooo0OO0O0oO = self . print_flags ( False )
   Ooo0OO0O0oO = Ooo0OO0O0oO . split ( "-" )
   Oo0Ooo0O0 = ""
   for oooOo in Ooo0OO0O0oO :
    O0ooO0ooo = lisp_site_flags [ oooOo . upper ( ) ]
    O0ooO0ooo = O0ooO0ooo . format ( "" if oooOo . isupper ( ) else "not " )
    Oo0Ooo0O0 += lisp_span ( oooOo , O0ooO0ooo )
    if ( oooOo . lower ( ) != "n" ) : Oo0Ooo0O0 += "-"
    if 42 - 42: I1ii11iIi11i
    if 51 - 51: iII111i % i11iIiiIii . OoO0O00 . IiII - OoOoOO00 * i1IIi
  return ( Oo0Ooo0O0 )
  if 14 - 14: I1ii11iIi11i . OoO0O00
  if 26 - 26: iII111i / ooOoO0o / Oo0Ooo / Oo0Ooo . I1ii11iIi11i * OOooOOo
 def copy_state_to_parent ( self , child ) :
  self . xtr_id = child . xtr_id
  self . site_id = child . site_id
  self . first_registered = child . first_registered
  self . last_registered = child . last_registered
  self . last_registerer = child . last_registerer
  self . register_ttl = child . register_ttl
  if ( self . registered == False ) :
   self . first_registered = lisp_get_timestamp ( )
   if 25 - 25: IiII % I1IiiI / O0 % OOooOOo - OoooooooOO
  self . auth_sha1_or_sha2 = child . auth_sha1_or_sha2
  self . registered = child . registered
  self . proxy_reply_requested = child . proxy_reply_requested
  self . lisp_sec_present = child . lisp_sec_present
  self . xtr_id_present = child . xtr_id_present
  self . use_register_ttl_requested = child . use_register_ttl_requested
  self . merge_register_requested = child . merge_register_requested
  self . mobile_node_requested = child . mobile_node_requested
  self . map_notify_requested = child . map_notify_requested
  if 29 - 29: O0 + iII111i
  if 4 - 4: I11i * I11i - Ii1I * oO0o . I1ii11iIi11i % o0oOOo0O0Ooo
 def build_sort_key ( self ) :
  I1iiiiIIiiI1i = lisp_cache ( )
  iiIII , Oo000O000 = I1iiiiIIiiI1i . build_key ( self . eid )
  ooOo0OOo = ""
  if ( self . group . is_null ( ) == False ) :
   IIi1iII1i11 , ooOo0OOo = I1iiiiIIiiI1i . build_key ( self . group )
   ooOo0OOo = "-" + ooOo0OOo [ 0 : 12 ] + "-" + str ( IIi1iII1i11 ) + "-" + ooOo0OOo [ 12 : : ]
   if 32 - 32: O0 % O0
  Oo000O000 = Oo000O000 [ 0 : 12 ] + "-" + str ( iiIII ) + "-" + Oo000O000 [ 12 : : ] + ooOo0OOo
  del ( I1iiiiIIiiI1i )
  return ( Oo000O000 )
  if 66 - 66: iII111i / i1IIi - Oo0Ooo . Ii1I
  if 65 - 65: I1ii11iIi11i % ooOoO0o - OoOoOO00 + ooOoO0o + Oo0Ooo
 def merge_in_site_eid ( self , child ) :
  O0OoOooO0O00o = False
  if ( self . group . is_null ( ) ) :
   self . merge_rlocs_in_site_eid ( )
  else :
   O0OoOooO0O00o = self . merge_rles_in_site_eid ( )
   if 39 - 39: OoooooooOO % i11iIiiIii / IiII - ooOoO0o
   if 74 - 74: iIii1I11I1II1 % II111iiii + IiII
   if 71 - 71: I1IiiI / O0 * i1IIi . i1IIi + Oo0Ooo
   if 32 - 32: i1IIi * I1Ii111 % I1IiiI / IiII . I1Ii111
   if 11 - 11: OOooOOo
   if 25 - 25: i1IIi
  if ( child != None ) :
   self . copy_state_to_parent ( child )
   self . map_registers_received += 1
   if 99 - 99: OOooOOo + OoooooooOO . I1Ii111 * Oo0Ooo % oO0o
  return ( O0OoOooO0O00o )
  if 75 - 75: iII111i
  if 8 - 8: I1ii11iIi11i . I11i / I1ii11iIi11i - i1IIi
 def copy_rloc_records ( self ) :
  iiIIiII1I = [ ]
  for O0OooOoooO0O in self . registered_rlocs :
   iiIIiII1I . append ( copy . deepcopy ( O0OooOoooO0O ) )
   if 93 - 93: IiII
  return ( iiIIiII1I )
  if 83 - 83: OoO0O00 - I11i * o0oOOo0O0Ooo - II111iiii
  if 21 - 21: iII111i * I1Ii111
 def merge_rlocs_in_site_eid ( self ) :
  self . registered_rlocs = [ ]
  for I11111Ii in self . individual_registrations . values ( ) :
   if ( self . site_id != I11111Ii . site_id ) : continue
   if ( I11111Ii . registered == False ) : continue
   self . registered_rlocs += I11111Ii . copy_rloc_records ( )
   if 43 - 43: I1Ii111 / I1ii11iIi11i - o0oOOo0O0Ooo + OoOoOO00 * iII111i - OoO0O00
   if 4 - 4: O0 + OoO0O00 / II111iiii
   if 93 - 93: o0oOOo0O0Ooo * I11i * II111iiii / OOooOOo
   if 95 - 95: OoOoOO00 % I1ii11iIi11i * I1Ii111 % II111iiii
   if 15 - 15: IiII . I1ii11iIi11i / I1IiiI . I1ii11iIi11i + Ii1I
   if 82 - 82: OOooOOo / I1IiiI % Oo0Ooo - OoO0O00 - o0oOOo0O0Ooo
  iiIIiII1I = [ ]
  for O0OooOoooO0O in self . registered_rlocs :
   if ( O0OooOoooO0O . rloc . is_null ( ) or len ( iiIIiII1I ) == 0 ) :
    iiIIiII1I . append ( O0OooOoooO0O )
    continue
    if 95 - 95: iII111i % o0oOOo0O0Ooo
   for iiI11 in iiIIiII1I :
    if ( iiI11 . rloc . is_null ( ) ) : continue
    if ( O0OooOoooO0O . rloc . is_exact_match ( iiI11 . rloc ) ) : break
    if 66 - 66: i1IIi + I1IiiI
   if ( iiI11 == iiIIiII1I [ - 1 ] ) : iiIIiII1I . append ( O0OooOoooO0O )
   if 45 - 45: I1Ii111 . iII111i + OoO0O00 - O0
  self . registered_rlocs = iiIIiII1I
  if 71 - 71: Oo0Ooo + OOooOOo
  if 94 - 94: OOooOOo
  if 81 - 81: i11iIiiIii + iIii1I11I1II1 . i11iIiiIii / OOooOOo / iII111i
  if 34 - 34: i11iIiiIii - o0oOOo0O0Ooo * OoooooooOO * I1ii11iIi11i * Oo0Ooo % I1ii11iIi11i
  if ( len ( self . registered_rlocs ) == 0 ) : self . registered = False
  return
  if 31 - 31: I11i . o0oOOo0O0Ooo
  if 82 - 82: I11i - Oo0Ooo
 def merge_rles_in_site_eid ( self ) :
  if 77 - 77: I1IiiI + OoO0O00 % iIii1I11I1II1 - OOooOOo
  if 80 - 80: oO0o % I1ii11iIi11i * I1Ii111 + i1IIi
  if 79 - 79: oO0o + IiII
  if 4 - 4: iII111i + OoooooooOO / I1Ii111
  OOo0o00o0oo000O = { }
  for O0OooOoooO0O in self . registered_rlocs :
   if ( O0OooOoooO0O . rle == None ) : continue
   for Iii in O0OooOoooO0O . rle . rle_nodes :
    IiiIIi1 = Iii . address . print_address_no_iid ( )
    OOo0o00o0oo000O [ IiiIIi1 ] = Iii . address
    if 29 - 29: O0 % Oo0Ooo * i11iIiiIii % IiII . i11iIiiIii % I1IiiI
   break
   if 53 - 53: Oo0Ooo * I1Ii111
   if 21 - 21: OoO0O00
   if 96 - 96: I1Ii111 % o0oOOo0O0Ooo + OoO0O00 - ooOoO0o
   if 38 - 38: OOooOOo . O0
   if 42 - 42: OoooooooOO / I1IiiI / o0oOOo0O0Ooo . I1ii11iIi11i . OoO0O00 % II111iiii
  self . merge_rlocs_in_site_eid ( )
  if 55 - 55: o0oOOo0O0Ooo
  if 87 - 87: ooOoO0o - IiII % Ii1I
  if 76 - 76: I11i - iIii1I11I1II1 - i1IIi + i1IIi
  if 60 - 60: I11i + OOooOOo - o0oOOo0O0Ooo
  if 64 - 64: II111iiii / iII111i * OoOoOO00 / OOooOOo / Ii1I
  if 19 - 19: OoOoOO00 % I1Ii111
  if 13 - 13: o0oOOo0O0Ooo % iIii1I11I1II1 + OoO0O00 / iIii1I11I1II1 . iIii1I11I1II1
  if 36 - 36: iII111i % I1ii11iIi11i + OoOoOO00 - i11iIiiIii % II111iiii % I11i
  OoOooO00OoOO = [ ]
  for O0OooOoooO0O in self . registered_rlocs :
   if ( self . registered_rlocs . index ( O0OooOoooO0O ) == 0 ) :
    OoOooO00OoOO . append ( O0OooOoooO0O )
    continue
    if 76 - 76: o0oOOo0O0Ooo % i11iIiiIii . iII111i . Ii1I * OoOoOO00 - OOooOOo
   if ( O0OooOoooO0O . rle == None ) : OoOooO00OoOO . append ( O0OooOoooO0O )
   if 52 - 52: O0 % I11i - I1Ii111
  self . registered_rlocs = OoOooO00OoOO
  if 98 - 98: iII111i - OoooooooOO - OOooOOo * oO0o / i11iIiiIii
  if 78 - 78: o0oOOo0O0Ooo + IiII . OOooOOo + I1ii11iIi11i - i11iIiiIii / OOooOOo
  if 73 - 73: ooOoO0o / O0 / I1Ii111 . OoooooooOO
  if 88 - 88: OoooooooOO - oO0o
  if 80 - 80: ooOoO0o
  if 38 - 38: IiII + OoO0O00 * I11i * iIii1I11I1II1 * oO0o
  if 74 - 74: I1IiiI
  iI1Ii11 = lisp_rle ( "" )
  I1i11111Iiii = { }
  oo0O0OOooO0 = None
  for I11111Ii in self . individual_registrations . values ( ) :
   if ( I11111Ii . registered == False ) : continue
   Ii1iI1111i = I11111Ii . registered_rlocs [ 0 ] . rle
   if ( Ii1iI1111i == None ) : continue
   if 68 - 68: iIii1I11I1II1 . OoOoOO00 * OOooOOo * oO0o
   oo0O0OOooO0 = I11111Ii . registered_rlocs [ 0 ] . rloc_name
   for O00O0oo0OOo in Ii1iI1111i . rle_nodes :
    IiiIIi1 = O00O0oo0OOo . address . print_address_no_iid ( )
    if ( I1i11111Iiii . has_key ( IiiIIi1 ) ) : break
    if 94 - 94: OoOoOO00 . O0
    Iii = lisp_rle_node ( )
    Iii . address . copy_address ( O00O0oo0OOo . address )
    Iii . level = O00O0oo0OOo . level
    Iii . rloc_name = oo0O0OOooO0
    iI1Ii11 . rle_nodes . append ( Iii )
    I1i11111Iiii [ IiiIIi1 ] = O00O0oo0OOo . address
    if 86 - 86: oO0o % Oo0Ooo . OoooooooOO / OOooOOo / i1IIi
    if 65 - 65: Ii1I . OoooooooOO % IiII - o0oOOo0O0Ooo . OOooOOo . II111iiii
    if 100 - 100: ooOoO0o / Oo0Ooo + I1ii11iIi11i + OoooooooOO
    if 100 - 100: I11i . OOooOOo - II111iiii % I11i % iIii1I11I1II1
    if 4 - 4: o0oOOo0O0Ooo . iII111i / O0
    if 13 - 13: iII111i / IiII
  if ( len ( iI1Ii11 . rle_nodes ) == 0 ) : iI1Ii11 = None
  if ( len ( self . registered_rlocs ) != 0 ) :
   self . registered_rlocs [ 0 ] . rle = iI1Ii11
   if ( oo0O0OOooO0 ) : self . registered_rlocs [ 0 ] . rloc_name = None
   if 28 - 28: iII111i
   if 97 - 97: iIii1I11I1II1
   if 18 - 18: OOooOOo
   if 87 - 87: O0 - i1IIi . I11i / Ii1I % iIii1I11I1II1
   if 57 - 57: I11i . IiII / iIii1I11I1II1 - ooOoO0o
  if ( OOo0o00o0oo000O . keys ( ) == I1i11111Iiii . keys ( ) ) : return ( False )
  if 50 - 50: O0 / II111iiii
  lprint ( "{} {} from {} to {}" . format ( green ( self . print_eid_tuple ( ) , False ) , bold ( "RLE change" , False ) ,
  # Oo0Ooo - OOooOOo . iII111i . i1IIi - O0 . I1IiiI
 OOo0o00o0oo000O . keys ( ) , I1i11111Iiii . keys ( ) ) )
  if 48 - 48: Ii1I * IiII % O0 - II111iiii
  return ( True )
  if 66 - 66: iIii1I11I1II1 / OOooOOo
  if 65 - 65: IiII . oO0o + O0 - i11iIiiIii + iIii1I11I1II1
 def add_cache ( self ) :
  if ( self . group . is_null ( ) ) :
   lisp_sites_by_eid . add_cache ( self . eid , self )
  else :
   iIiIi1I = lisp_sites_by_eid . lookup_cache ( self . group , True )
   if ( iIiIi1I == None ) :
    iIiIi1I = lisp_site_eid ( self . site )
    iIiIi1I . eid . copy_address ( self . group )
    iIiIi1I . group . copy_address ( self . group )
    lisp_sites_by_eid . add_cache ( self . group , iIiIi1I )
    if 82 - 82: iIii1I11I1II1 * iII111i + iIii1I11I1II1 / OoO0O00 + O0
    if 67 - 67: I1Ii111
    if 94 - 94: I1Ii111 % iIii1I11I1II1 - II111iiii . ooOoO0o + i11iIiiIii - i11iIiiIii
    if 55 - 55: OoooooooOO % iIii1I11I1II1 % I1ii11iIi11i % i1IIi
    if 46 - 46: I11i - ooOoO0o . I1IiiI
    iIiIi1I . parent_for_more_specifics = self . parent_for_more_specifics
    if 36 - 36: I11i + OoO0O00 * O0 * OoOoOO00 * iII111i
   if ( self . eid . is_null ( ) ) : self . eid . make_default_route ( iIiIi1I . group )
   iIiIi1I . add_source_entry ( self )
   if 90 - 90: i11iIiiIii / i1IIi
   if 35 - 35: Ii1I . I11i / oO0o / OoOoOO00
   if 5 - 5: I1ii11iIi11i . o0oOOo0O0Ooo * iII111i * I1ii11iIi11i % I1Ii111
 def delete_cache ( self ) :
  if ( self . group . is_null ( ) ) :
   lisp_sites_by_eid . delete_cache ( self . eid )
  else :
   iIiIi1I = lisp_sites_by_eid . lookup_cache ( self . group , True )
   if ( iIiIi1I == None ) : return
   if 83 - 83: iIii1I11I1II1 * o0oOOo0O0Ooo % i11iIiiIii + OoO0O00 . O0
   I11111Ii = iIiIi1I . lookup_source_cache ( self . eid , True )
   if ( I11111Ii == None ) : return
   if 87 - 87: II111iiii - iIii1I11I1II1 % I11i % I1IiiI . o0oOOo0O0Ooo
   if ( iIiIi1I . source_cache == None ) : return
   if 52 - 52: i11iIiiIii . oO0o / OoooooooOO - OoO0O00
   iIiIi1I . source_cache . delete_cache ( self . eid )
   if ( iIiIi1I . source_cache . cache_size ( ) == 0 ) :
    lisp_sites_by_eid . delete_cache ( self . group )
    if 7 - 7: I1IiiI * I1IiiI % OOooOOo % iIii1I11I1II1 * OoO0O00 . o0oOOo0O0Ooo
    if 32 - 32: ooOoO0o / i1IIi
    if 55 - 55: oO0o . OoOoOO00 + OoooooooOO - ooOoO0o . OoooooooOO
    if 77 - 77: I1IiiI
 def add_source_entry ( self , source_se ) :
  if ( self . source_cache == None ) : self . source_cache = lisp_cache ( )
  self . source_cache . add_cache ( source_se . eid , source_se )
  if 16 - 16: I1IiiI + ooOoO0o - O0 / o0oOOo0O0Ooo
  if 36 - 36: Oo0Ooo - OoOoOO00 - II111iiii
 def lookup_source_cache ( self , source , exact ) :
  if ( self . source_cache == None ) : return ( None )
  return ( self . source_cache . lookup_cache ( source , exact ) )
  if 25 - 25: i11iIiiIii + II111iiii * OOooOOo % OOooOOo
  if 87 - 87: I11i % Ii1I % Oo0Ooo . II111iiii / oO0o
 def is_star_g ( self ) :
  if ( self . group . is_null ( ) ) : return ( False )
  return ( self . eid . is_exact_match ( self . group ) )
  if 19 - 19: O0 . OOooOOo + I1Ii111 * I1ii11iIi11i
  if 91 - 91: o0oOOo0O0Ooo / oO0o . o0oOOo0O0Ooo + IiII + ooOoO0o . I1Ii111
 def eid_record_matches ( self , eid_record ) :
  if ( self . eid . is_exact_match ( eid_record . eid ) == False ) : return ( False )
  if ( eid_record . group . is_null ( ) ) : return ( True )
  return ( eid_record . group . is_exact_match ( self . group ) )
  if 90 - 90: i1IIi + oO0o * oO0o / ooOoO0o . IiII
  if 98 - 98: I11i % OoO0O00 . iII111i - o0oOOo0O0Ooo
 def inherit_from_ams_parent ( self ) :
  i1iIiiiiI1 = self . parent_for_more_specifics
  if ( i1iIiiiiI1 == None ) : return
  self . force_proxy_reply = i1iIiiiiI1 . force_proxy_reply
  self . force_nat_proxy_reply = i1iIiiiiI1 . force_nat_proxy_reply
  self . force_ttl = i1iIiiiiI1 . force_ttl
  self . pitr_proxy_reply_drop = i1iIiiiiI1 . pitr_proxy_reply_drop
  self . proxy_reply_action = i1iIiiiiI1 . proxy_reply_action
  self . echo_nonce_capable = i1iIiiiiI1 . echo_nonce_capable
  self . policy = i1iIiiiiI1 . policy
  self . require_signature = i1iIiiiiI1 . require_signature
  if 92 - 92: I11i
  if 34 - 34: I1IiiI % iIii1I11I1II1 . I1ii11iIi11i * Oo0Ooo * iIii1I11I1II1 / O0
 def rtrs_in_rloc_set ( self ) :
  for O0OooOoooO0O in self . registered_rlocs :
   if ( O0OooOoooO0O . is_rtr ( ) ) : return ( True )
   if 98 - 98: iII111i % IiII + OoO0O00
  return ( False )
  if 23 - 23: OOooOOo
  if 83 - 83: I1ii11iIi11i / O0 * II111iiii + IiII + Oo0Ooo
 def is_rtr_in_rloc_set ( self , rtr_rloc ) :
  for O0OooOoooO0O in self . registered_rlocs :
   if ( O0OooOoooO0O . rloc . is_exact_match ( rtr_rloc ) == False ) : continue
   if ( O0OooOoooO0O . is_rtr ( ) ) : return ( True )
   if 99 - 99: II111iiii + O0
  return ( False )
  if 94 - 94: ooOoO0o * ooOoO0o + o0oOOo0O0Ooo . iII111i % iIii1I11I1II1 + Ii1I
  if 88 - 88: Oo0Ooo . iII111i
 def is_rloc_in_rloc_set ( self , rloc ) :
  for O0OooOoooO0O in self . registered_rlocs :
   if ( O0OooOoooO0O . rle ) :
    for iI1Ii11 in O0OooOoooO0O . rle . rle_nodes :
     if ( iI1Ii11 . address . is_exact_match ( rloc ) ) : return ( True )
     if 89 - 89: OOooOOo + I1Ii111 % i11iIiiIii + Oo0Ooo / Oo0Ooo + OoO0O00
     if 9 - 9: OoOoOO00 % i1IIi + IiII
   if ( O0OooOoooO0O . rloc . is_exact_match ( rloc ) ) : return ( True )
   if 19 - 19: I1Ii111 - II111iiii / I1Ii111 + I1IiiI - OoooooooOO + o0oOOo0O0Ooo
  return ( False )
  if 100 - 100: OoO0O00 / OoOoOO00 / OOooOOo / OoO0O00
  if 95 - 95: ooOoO0o
 def do_rloc_sets_match ( self , prev_rloc_set ) :
  if ( len ( self . registered_rlocs ) != len ( prev_rloc_set ) ) : return ( False )
  if 95 - 95: Ii1I + i1IIi . I1IiiI % I1Ii111 / Ii1I * O0
  for O0OooOoooO0O in prev_rloc_set :
   o00o0O00000 = O0OooOoooO0O . rloc
   if ( self . is_rloc_in_rloc_set ( o00o0O00000 ) == False ) : return ( False )
   if 68 - 68: I1Ii111 - IiII - oO0o - Oo0Ooo - o0oOOo0O0Ooo
  return ( True )
  if 32 - 32: OoOoOO00 % i11iIiiIii
  if 53 - 53: I1Ii111 * Ii1I / IiII . i1IIi * II111iiii / o0oOOo0O0Ooo
  if 44 - 44: I1Ii111 + ooOoO0o
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
   if 15 - 15: I11i + OoO0O00 + OoOoOO00
  self . last_used = 0
  self . last_reply = 0
  self . last_nonce = 0
  self . map_requests_sent = 0
  self . neg_map_replies_received = 0
  self . total_rtt = 0
  if 100 - 100: I1Ii111
  if 78 - 78: OoOoOO00
 def resolve_dns_name ( self ) :
  if ( self . dns_name == None ) : return
  if ( self . last_dns_resolve and
 time . time ( ) - self . last_dns_resolve < 30 ) : return
  if 16 - 16: I1Ii111 % OoO0O00 - OoO0O00 % OoOoOO00 * OoO0O00
  try :
   IIiiI = socket . gethostbyname_ex ( self . dns_name )
   self . last_dns_resolve = lisp_get_timestamp ( )
   IIii1ii11ii1I = IIiiI [ 2 ]
  except :
   return
   if 26 - 26: OoooooooOO % I1ii11iIi11i % OoO0O00 . I1Ii111 - I1IiiI + o0oOOo0O0Ooo
   if 8 - 8: I1IiiI * o0oOOo0O0Ooo - I1ii11iIi11i . i1IIi
   if 64 - 64: ooOoO0o
   if 23 - 23: Oo0Ooo . OoO0O00
   if 49 - 49: oO0o % i11iIiiIii * Ii1I
   if 9 - 9: Oo0Ooo - OoO0O00 + ooOoO0o / o0oOOo0O0Ooo
  if ( len ( IIii1ii11ii1I ) <= self . a_record_index ) :
   self . delete_mr ( )
   return
   if 61 - 61: O0 - i11iIiiIii * o0oOOo0O0Ooo
   if 92 - 92: Oo0Ooo + OOooOOo - i11iIiiIii
  IiiIIi1 = IIii1ii11ii1I [ self . a_record_index ]
  if ( IiiIIi1 != self . map_resolver . print_address_no_iid ( ) ) :
   self . delete_mr ( )
   self . map_resolver . store_address ( IiiIIi1 )
   self . insert_mr ( )
   if 26 - 26: O0 % Oo0Ooo + ooOoO0o - Ii1I . Oo0Ooo
   if 33 - 33: I1Ii111 / iII111i . I1Ii111 % II111iiii
   if 52 - 52: I1ii11iIi11i
   if 1 - 1: II111iiii + I1ii11iIi11i * OoOoOO00 % ooOoO0o - iII111i % OoooooooOO
   if 77 - 77: iII111i + o0oOOo0O0Ooo
   if 60 - 60: I1ii11iIi11i
  if ( lisp_is_decent_dns_suffix ( self . dns_name ) == False ) : return
  if ( self . a_record_index != 0 ) : return
  if 23 - 23: iII111i % I1IiiI % I1Ii111 * oO0o * I1IiiI
  for IiiIIi1 in IIii1ii11ii1I [ 1 : : ] :
   OO0o = lisp_address ( LISP_AFI_NONE , IiiIIi1 , 0 , 0 )
   OoOooo0o = lisp_get_map_resolver ( OO0o , None )
   if ( OoOooo0o != None and OoOooo0o . a_record_index == IIii1ii11ii1I . index ( IiiIIi1 ) ) :
    continue
    if 74 - 74: O0 / I11i . Oo0Ooo / I11i % OoO0O00 % o0oOOo0O0Ooo
   OoOooo0o = lisp_mr ( IiiIIi1 , None , None )
   OoOooo0o . a_record_index = IIii1ii11ii1I . index ( IiiIIi1 )
   OoOooo0o . dns_name = self . dns_name
   OoOooo0o . last_dns_resolve = lisp_get_timestamp ( )
   if 83 - 83: OoO0O00 - i11iIiiIii + iIii1I11I1II1
   if 52 - 52: OoooooooOO
   if 44 - 44: O0 / OoooooooOO + ooOoO0o * I1ii11iIi11i
   if 36 - 36: I1ii11iIi11i / OoO0O00 - oO0o % O0
   if 12 - 12: i1IIi * ooOoO0o / oO0o + I1IiiI / OoooooooOO
  oOO0 = [ ]
  for OoOooo0o in lisp_map_resolvers_list . values ( ) :
   if ( self . dns_name != OoOooo0o . dns_name ) : continue
   OO0o = OoOooo0o . map_resolver . print_address_no_iid ( )
   if ( OO0o in IIii1ii11ii1I ) : continue
   oOO0 . append ( OoOooo0o )
   if 18 - 18: I1IiiI / O0 . OoO0O00 - OoooooooOO + Ii1I - Ii1I
  for OoOooo0o in oOO0 : OoOooo0o . delete_mr ( )
  if 67 - 67: II111iiii . Ii1I + I1IiiI
  if 77 - 77: O0 % I1ii11iIi11i + i11iIiiIii . OOooOOo % o0oOOo0O0Ooo + OoO0O00
 def insert_mr ( self ) :
  Oo000O000 = self . mr_name + self . map_resolver . print_address ( )
  lisp_map_resolvers_list [ Oo000O000 ] = self
  if 31 - 31: ooOoO0o * I1ii11iIi11i
  if 23 - 23: OoOoOO00 - I11i . iIii1I11I1II1
 def delete_mr ( self ) :
  Oo000O000 = self . mr_name + self . map_resolver . print_address ( )
  if ( lisp_map_resolvers_list . has_key ( Oo000O000 ) == False ) : return
  lisp_map_resolvers_list . pop ( Oo000O000 )
  if 87 - 87: OoO0O00 - i11iIiiIii / O0 % OOooOOo % OOooOOo * i1IIi
  if 18 - 18: IiII
  if 50 - 50: i1IIi / o0oOOo0O0Ooo * OoO0O00
class lisp_ddt_root ( ) :
 def __init__ ( self ) :
  self . root_address = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . public_key = ""
  self . priority = 0
  self . weight = 0
  if 98 - 98: I11i . II111iiii
  if 13 - 13: oO0o - I11i % II111iiii
  if 30 - 30: ooOoO0o / O0 . I11i + I1ii11iIi11i % O0 . I1IiiI
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
  if 25 - 25: o0oOOo0O0Ooo - ooOoO0o / I11i
  if 98 - 98: ooOoO0o * I11i + o0oOOo0O0Ooo
 def print_referral ( self , eid_indent , referral_indent ) :
  oOiII11iII = lisp_print_elapsed ( self . uptime )
  OOo000 = lisp_print_future ( self . expires )
  lprint ( "{}Referral EID {}, uptime/expires {}/{}, {} referrals:" . format ( eid_indent , green ( self . eid . print_prefix ( ) , False ) , oOiII11iII ,
  # Oo0Ooo - o0oOOo0O0Ooo
 OOo000 , len ( self . referral_set ) ) )
  if 96 - 96: i11iIiiIii / IiII / Ii1I . OOooOOo
  for Iii1i1I1 in self . referral_set . values ( ) :
   Iii1i1I1 . print_ref_node ( referral_indent )
   if 46 - 46: II111iiii - o0oOOo0O0Ooo - iIii1I11I1II1 . OoO0O00 % i11iIiiIii
   if 54 - 54: Ii1I + ooOoO0o * I11i / IiII - Ii1I
   if 46 - 46: i11iIiiIii + Ii1I . OoOoOO00 / i1IIi - ooOoO0o
 def print_referral_type ( self ) :
  if ( self . eid . afi == LISP_AFI_ULTIMATE_ROOT ) : return ( "root" )
  if ( self . referral_type == LISP_DDT_ACTION_NULL ) :
   return ( "null-referral" )
   if 76 - 76: IiII % I1ii11iIi11i * I1Ii111
  if ( self . referral_type == LISP_DDT_ACTION_SITE_NOT_FOUND ) :
   return ( "no-site-action" )
   if 64 - 64: Ii1I / i11iIiiIii - i1IIi % i1IIi * OoO0O00
  if ( self . referral_type > LISP_DDT_ACTION_MAX ) :
   return ( "invalid-action" )
   if 92 - 92: ooOoO0o
  return ( lisp_map_referral_action_string [ self . referral_type ] )
  if 39 - 39: iII111i / OoO0O00 * ooOoO0o - O0
  if 64 - 64: I1IiiI / OoooooooOO . I1Ii111 - II111iiii - i11iIiiIii
 def print_eid_tuple ( self ) :
  return ( lisp_print_eid_tuple ( self . eid , self . group ) )
  if 45 - 45: OOooOOo / I1ii11iIi11i
  if 10 - 10: IiII + o0oOOo0O0Ooo + I11i % O0 % I1Ii111
 def print_ttl ( self ) :
  oOoooOOO0o0 = self . referral_ttl
  if ( oOoooOOO0o0 < 60 ) : return ( str ( oOoooOOO0o0 ) + " secs" )
  if 85 - 85: O0 % OoOoOO00 . I1ii11iIi11i
  if ( ( oOoooOOO0o0 % 60 ) == 0 ) :
   oOoooOOO0o0 = str ( oOoooOOO0o0 / 60 ) + " mins"
  else :
   oOoooOOO0o0 = str ( oOoooOOO0o0 ) + " secs"
   if 46 - 46: OOooOOo * iIii1I11I1II1
  return ( oOoooOOO0o0 )
  if 33 - 33: OoO0O00 * II111iiii / i1IIi
  if 93 - 93: I1Ii111 % I11i
 def is_referral_negative ( self ) :
  return ( self . referral_type in ( LISP_DDT_ACTION_MS_NOT_REG , LISP_DDT_ACTION_DELEGATION_HOLE ,
  # I11i + i1IIi + Oo0Ooo + Oo0Ooo
 LISP_DDT_ACTION_NOT_AUTH ) )
  if 91 - 91: i1IIi % O0 . oO0o
  if 72 - 72: O0 - IiII
 def add_cache ( self ) :
  if ( self . group . is_null ( ) ) :
   lisp_referral_cache . add_cache ( self . eid , self )
  else :
   OOo0 = lisp_referral_cache . lookup_cache ( self . group , True )
   if ( OOo0 == None ) :
    OOo0 = lisp_referral ( )
    OOo0 . eid . copy_address ( self . group )
    OOo0 . group . copy_address ( self . group )
    lisp_referral_cache . add_cache ( self . group , OOo0 )
    if 49 - 49: IiII - OOooOOo * OOooOOo . O0
   if ( self . eid . is_null ( ) ) : self . eid . make_default_route ( OOo0 . group )
   OOo0 . add_source_entry ( self )
   if 60 - 60: OoOoOO00 % iIii1I11I1II1 + IiII % o0oOOo0O0Ooo
   if 64 - 64: OoOoOO00 * I1ii11iIi11i . OoooooooOO . i1IIi
   if 61 - 61: OoO0O00
 def delete_cache ( self ) :
  if ( self . group . is_null ( ) ) :
   lisp_referral_cache . delete_cache ( self . eid )
  else :
   OOo0 = lisp_referral_cache . lookup_cache ( self . group , True )
   if ( OOo0 == None ) : return
   if 100 - 100: OoOoOO00
   O0OO0OO0 = OOo0 . lookup_source_cache ( self . eid , True )
   if ( O0OO0OO0 == None ) : return
   if 97 - 97: OoooooooOO
   OOo0 . source_cache . delete_cache ( self . eid )
   if ( OOo0 . source_cache . cache_size ( ) == 0 ) :
    lisp_referral_cache . delete_cache ( self . group )
    if 91 - 91: o0oOOo0O0Ooo / O0 % OoO0O00
    if 35 - 35: iII111i % OoO0O00 * O0
    if 37 - 37: OOooOOo
    if 100 - 100: Oo0Ooo * I1IiiI . ooOoO0o
 def add_source_entry ( self , source_ref ) :
  if ( self . source_cache == None ) : self . source_cache = lisp_cache ( )
  self . source_cache . add_cache ( source_ref . eid , source_ref )
  if 53 - 53: OOooOOo + o0oOOo0O0Ooo * Ii1I + O0
  if 75 - 75: OoooooooOO
 def lookup_source_cache ( self , source , exact ) :
  if ( self . source_cache == None ) : return ( None )
  return ( self . source_cache . lookup_cache ( source , exact ) )
  if 24 - 24: I1Ii111 % i11iIiiIii % oO0o . OOooOOo % IiII
  if 23 - 23: o0oOOo0O0Ooo * II111iiii - Oo0Ooo - I1IiiI
  if 86 - 86: I1IiiI - II111iiii * II111iiii * oO0o % OoooooooOO * OoOoOO00
class lisp_referral_node ( ) :
 def __init__ ( self ) :
  self . referral_address = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . priority = 0
  self . weight = 0
  self . updown = True
  self . map_requests_sent = 0
  self . no_responses = 0
  self . uptime = lisp_get_timestamp ( )
  if 93 - 93: I1IiiI + OoO0O00 % O0 - ooOoO0o * i1IIi
  if 60 - 60: I1IiiI
 def print_ref_node ( self , indent ) :
  i1 = lisp_print_elapsed ( self . uptime )
  lprint ( "{}referral {}, uptime {}, {}, priority/weight: {}/{}" . format ( indent , red ( self . referral_address . print_address ( ) , False ) , i1 ,
  # IiII
 "up" if self . updown else "down" , self . priority , self . weight ) )
  if 80 - 80: i1IIi / ooOoO0o % iII111i - oO0o - II111iiii
  if 29 - 29: ooOoO0o . II111iiii . i1IIi % oO0o
  if 11 - 11: OoOoOO00 . OoO0O00 % I11i * iII111i % I1Ii111 . O0
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
   if 17 - 17: OOooOOo / i11iIiiIii - i11iIiiIii . II111iiii . ooOoO0o
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
   if 38 - 38: OOooOOo . OoooooooOO . II111iiii + OoO0O00 / oO0o . OoooooooOO
   if 100 - 100: OoO0O00
   if 36 - 36: oO0o + Ii1I - O0
 def resolve_dns_name ( self ) :
  if ( self . dns_name == None ) : return
  if ( self . last_dns_resolve and
 time . time ( ) - self . last_dns_resolve < 30 ) : return
  if 19 - 19: O0 + I1Ii111 . I1Ii111 * IiII * ooOoO0o + i1IIi
  try :
   IIiiI = socket . gethostbyname_ex ( self . dns_name )
   self . last_dns_resolve = lisp_get_timestamp ( )
   IIii1ii11ii1I = IIiiI [ 2 ]
  except :
   return
   if 51 - 51: ooOoO0o % OoOoOO00 % i1IIi / O0
   if 11 - 11: OOooOOo . I1ii11iIi11i * OOooOOo * OoO0O00
   if 11 - 11: I11i
   if 85 - 85: OoOoOO00 - Ii1I / Oo0Ooo % I1ii11iIi11i
   if 12 - 12: i1IIi + o0oOOo0O0Ooo / oO0o . O0
   if 37 - 37: IiII
  if ( len ( IIii1ii11ii1I ) <= self . a_record_index ) :
   self . delete_ms ( )
   return
   if 99 - 99: i11iIiiIii % i11iIiiIii . I11i * I1ii11iIi11i . OoO0O00 / I1IiiI
   if 44 - 44: iII111i - OoO0O00 / i11iIiiIii
  IiiIIi1 = IIii1ii11ii1I [ self . a_record_index ]
  if ( IiiIIi1 != self . map_server . print_address_no_iid ( ) ) :
   self . delete_ms ( )
   self . map_server . store_address ( IiiIIi1 )
   self . insert_ms ( )
   if 55 - 55: O0 * OoO0O00 * i1IIi
   if 9 - 9: IiII
   if 64 - 64: ooOoO0o + OoooooooOO
   if 99 - 99: iIii1I11I1II1 * II111iiii * i11iIiiIii
   if 10 - 10: OOooOOo
   if 75 - 75: I11i * ooOoO0o * Oo0Ooo . i1IIi . ooOoO0o . ooOoO0o
  if ( lisp_is_decent_dns_suffix ( self . dns_name ) == False ) : return
  if ( self . a_record_index != 0 ) : return
  if 24 - 24: iIii1I11I1II1
  for IiiIIi1 in IIii1ii11ii1I [ 1 : : ] :
   OO0o = lisp_address ( LISP_AFI_NONE , IiiIIi1 , 0 , 0 )
   ii1i = lisp_get_map_server ( OO0o )
   if ( ii1i != None and ii1i . a_record_index == IIii1ii11ii1I . index ( IiiIIi1 ) ) :
    continue
    if 72 - 72: i11iIiiIii + o0oOOo0O0Ooo % ooOoO0o * I1ii11iIi11i . i1IIi
   ii1i = copy . deepcopy ( self )
   ii1i . map_server . store_address ( IiiIIi1 )
   ii1i . a_record_index = IIii1ii11ii1I . index ( IiiIIi1 )
   ii1i . last_dns_resolve = lisp_get_timestamp ( )
   ii1i . insert_ms ( )
   if 59 - 59: OoooooooOO - OoooooooOO - o0oOOo0O0Ooo + i1IIi % I1Ii111
   if 74 - 74: IiII * iIii1I11I1II1 - I1IiiI
   if 62 - 62: o0oOOo0O0Ooo
   if 54 - 54: iIii1I11I1II1 / OoooooooOO + o0oOOo0O0Ooo . i1IIi - OoooooooOO
   if 70 - 70: Ii1I / OoOoOO00 * Oo0Ooo
  oOO0 = [ ]
  for ii1i in lisp_map_servers_list . values ( ) :
   if ( self . dns_name != ii1i . dns_name ) : continue
   OO0o = ii1i . map_server . print_address_no_iid ( )
   if ( OO0o in IIii1ii11ii1I ) : continue
   oOO0 . append ( ii1i )
   if 32 - 32: I1Ii111 . OoOoOO00 % OoooooooOO + I1Ii111 * OoO0O00
  for ii1i in oOO0 : ii1i . delete_ms ( )
  if 84 - 84: OoOoOO00
  if 80 - 80: oO0o
 def insert_ms ( self ) :
  Oo000O000 = self . ms_name + self . map_server . print_address ( )
  lisp_map_servers_list [ Oo000O000 ] = self
  if 59 - 59: iIii1I11I1II1 / IiII % I1ii11iIi11i + OoO0O00 - I11i % OOooOOo
  if 92 - 92: iII111i
 def delete_ms ( self ) :
  Oo000O000 = self . ms_name + self . map_server . print_address ( )
  if ( lisp_map_servers_list . has_key ( Oo000O000 ) == False ) : return
  lisp_map_servers_list . pop ( Oo000O000 )
  if 96 - 96: OoOoOO00 / OoOoOO00 / OoOoOO00 + OoooooooOO + Oo0Ooo
  if 91 - 91: OoOoOO00 + II111iiii / I11i * iIii1I11I1II1
  if 92 - 92: I1Ii111 - IiII / IiII
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
  if 42 - 42: IiII
  if 7 - 7: iIii1I11I1II1
 def add_interface ( self ) :
  lisp_myinterfaces [ self . device ] = self
  if 35 - 35: IiII + O0 % I1Ii111 - I1ii11iIi11i - i1IIi
  if 100 - 100: I1Ii111 + i11iIiiIii - IiII / I1ii11iIi11i / iII111i
 def get_instance_id ( self ) :
  return ( self . instance_id )
  if 56 - 56: iII111i
  if 91 - 91: Oo0Ooo . I11i . I1ii11iIi11i
 def get_socket ( self ) :
  return ( self . raw_socket )
  if 60 - 60: i11iIiiIii - OOooOOo
  if 78 - 78: I1IiiI * ooOoO0o % iIii1I11I1II1 / I1ii11iIi11i
 def get_bridge_socket ( self ) :
  return ( self . bridge_socket )
  if 61 - 61: I1Ii111 . Ii1I + OoooooooOO
  if 98 - 98: OOooOOo . ooOoO0o . OoOoOO00 - I1Ii111 . i1IIi - iIii1I11I1II1
 def does_dynamic_eid_match ( self , eid ) :
  if ( self . dynamic_eid . is_null ( ) ) : return ( False )
  return ( eid . is_more_specific ( self . dynamic_eid ) )
  if 89 - 89: II111iiii * I1ii11iIi11i - I1IiiI
  if 58 - 58: Ii1I / Oo0Ooo % IiII
 def set_socket ( self , device ) :
  IiII1iiI = socket . socket ( socket . AF_INET , socket . SOCK_RAW , socket . IPPROTO_RAW )
  IiII1iiI . setsockopt ( socket . SOL_IP , socket . IP_HDRINCL , 1 )
  try :
   IiII1iiI . setsockopt ( socket . SOL_SOCKET , socket . SO_BINDTODEVICE , device )
  except :
   IiII1iiI . close ( )
   IiII1iiI = None
   if 33 - 33: II111iiii . OOooOOo % iIii1I11I1II1 - Oo0Ooo - OoOoOO00 % i11iIiiIii
  self . raw_socket = IiII1iiI
  if 60 - 60: iII111i . o0oOOo0O0Ooo
  if 56 - 56: I1ii11iIi11i
 def set_bridge_socket ( self , device ) :
  IiII1iiI = socket . socket ( socket . PF_PACKET , socket . SOCK_RAW )
  try :
   IiII1iiI = IiII1iiI . bind ( ( device , 0 ) )
   self . bridge_socket = IiII1iiI
  except :
   return
   if 89 - 89: Oo0Ooo + I1ii11iIi11i * o0oOOo0O0Ooo * oO0o % O0 % OoO0O00
   if 70 - 70: o0oOOo0O0Ooo + O0 % I1IiiI
   if 56 - 56: Ii1I
   if 84 - 84: iII111i
class lisp_datetime ( ) :
 def __init__ ( self , datetime_str ) :
  self . datetime_name = datetime_str
  self . datetime = None
  self . parse_datetime ( )
  if 21 - 21: i11iIiiIii
  if 30 - 30: OoO0O00 + OoooooooOO
 def valid_datetime ( self ) :
  oOoo0oO00Oo = self . datetime_name
  if ( oOoo0oO00Oo . find ( ":" ) == - 1 ) : return ( False )
  if ( oOoo0oO00Oo . find ( "-" ) == - 1 ) : return ( False )
  OoOOIiIIi1i1 , IIIiIii , iii1 , time = oOoo0oO00Oo [ 0 : 4 ] , oOoo0oO00Oo [ 5 : 7 ] , oOoo0oO00Oo [ 8 : 10 ] , oOoo0oO00Oo [ 11 : : ]
  if 14 - 14: O0
  if ( ( OoOOIiIIi1i1 + IIIiIii + iii1 ) . isdigit ( ) == False ) : return ( False )
  if ( IIIiIii < "01" and IIIiIii > "12" ) : return ( False )
  if ( iii1 < "01" and iii1 > "31" ) : return ( False )
  if 9 - 9: I1Ii111 * i11iIiiIii / o0oOOo0O0Ooo / iII111i
  oOooO000O00 , iIi1iIi , OOi1 = time . split ( ":" )
  if 63 - 63: OOooOOo
  if ( ( oOooO000O00 + iIi1iIi + OOi1 ) . isdigit ( ) == False ) : return ( False )
  if ( oOooO000O00 < "00" and oOooO000O00 > "23" ) : return ( False )
  if ( iIi1iIi < "00" and iIi1iIi > "59" ) : return ( False )
  if ( OOi1 < "00" and OOi1 > "59" ) : return ( False )
  return ( True )
  if 84 - 84: i11iIiiIii * iIii1I11I1II1 % I11i % iII111i + OoooooooOO . o0oOOo0O0Ooo
  if 78 - 78: o0oOOo0O0Ooo . iII111i + O0 / I1ii11iIi11i + I1ii11iIi11i + II111iiii
 def parse_datetime ( self ) :
  ooooooOO0oO0 = self . datetime_name
  ooooooOO0oO0 = ooooooOO0oO0 . replace ( "-" , "" )
  ooooooOO0oO0 = ooooooOO0oO0 . replace ( ":" , "" )
  self . datetime = int ( ooooooOO0oO0 )
  if 7 - 7: Ii1I - I11i / I1ii11iIi11i + iII111i
  if 47 - 47: I11i * IiII / oO0o - OoooooooOO . OoooooooOO / I11i
 def now ( self ) :
  i1 = datetime . datetime . now ( ) . strftime ( "%Y-%m-%d-%H:%M:%S" )
  i1 = lisp_datetime ( i1 )
  return ( i1 )
  if 73 - 73: Ii1I . IiII % IiII
  if 56 - 56: I1Ii111 + iII111i + iII111i
 def print_datetime ( self ) :
  return ( self . datetime_name )
  if 99 - 99: o0oOOo0O0Ooo % I1ii11iIi11i / Oo0Ooo . O0 + OoO0O00 * OoOoOO00
  if 48 - 48: iIii1I11I1II1 + O0 * I11i * i11iIiiIii . Ii1I / i1IIi
 def future ( self ) :
  return ( self . datetime > self . now ( ) . datetime )
  if 48 - 48: i1IIi % iIii1I11I1II1 + I1IiiI - OoOoOO00 % I11i . I1Ii111
  if 66 - 66: I1Ii111 * i11iIiiIii + I1IiiI % II111iiii
 def past ( self ) :
  return ( self . future ( ) == False )
  if 47 - 47: II111iiii % o0oOOo0O0Ooo
  if 26 - 26: I1ii11iIi11i / I11i / Oo0Ooo / i1IIi + O0 * ooOoO0o
 def now_in_range ( self , upper ) :
  return ( self . past ( ) and upper . future ( ) )
  if 53 - 53: IiII / II111iiii / oO0o % O0 / I1Ii111
  if 91 - 91: oO0o * OoOoOO00 + O0 % Oo0Ooo
 def this_year ( self ) :
  Oo0oooo00 = str ( self . now ( ) . datetime ) [ 0 : 4 ]
  i1 = str ( self . datetime ) [ 0 : 4 ]
  return ( i1 == Oo0oooo00 )
  if 68 - 68: iII111i + OOooOOo - Ii1I
  if 67 - 67: OoooooooOO * O0 * Ii1I . ooOoO0o
 def this_month ( self ) :
  Oo0oooo00 = str ( self . now ( ) . datetime ) [ 0 : 6 ]
  i1 = str ( self . datetime ) [ 0 : 6 ]
  return ( i1 == Oo0oooo00 )
  if 15 - 15: iII111i / O0
  if 65 - 65: oO0o * ooOoO0o . I11i / i11iIiiIii - IiII * OoO0O00
 def today ( self ) :
  Oo0oooo00 = str ( self . now ( ) . datetime ) [ 0 : 8 ]
  i1 = str ( self . datetime ) [ 0 : 8 ]
  return ( i1 == Oo0oooo00 )
  if 57 - 57: iII111i * I11i % o0oOOo0O0Ooo * OoOoOO00 % I1ii11iIi11i + i11iIiiIii
  if 66 - 66: i11iIiiIii . ooOoO0o
  if 83 - 83: I1Ii111 % ooOoO0o + OoooooooOO
  if 50 - 50: i11iIiiIii % I1IiiI * iII111i / Ii1I
  if 12 - 12: iII111i / OoO0O00 - II111iiii + Oo0Ooo
  if 78 - 78: i1IIi
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
  if 25 - 25: Ii1I * II111iiii / OoOoOO00
  if 86 - 86: i1IIi + I1IiiI + I1Ii111 % II111iiii . IiII - iIii1I11I1II1
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
  if 54 - 54: i11iIiiIii . Ii1I % I1IiiI . I1Ii111 . OoooooooOO
  if 49 - 49: OOooOOo % I11i - OOooOOo + Ii1I . I1ii11iIi11i + ooOoO0o
 def match_policy_map_request ( self , mr , srloc ) :
  for OOIiIi1 in self . match_clauses :
   oo00ooOOOo0O = OOIiIi1 . source_eid
   iioOo0oo = mr . source_eid
   if ( oo00ooOOOo0O and iioOo0oo and iioOo0oo . is_more_specific ( oo00ooOOOo0O ) == False ) : continue
   if 15 - 15: i11iIiiIii
   oo00ooOOOo0O = OOIiIi1 . dest_eid
   iioOo0oo = mr . target_eid
   if ( oo00ooOOOo0O and iioOo0oo and iioOo0oo . is_more_specific ( oo00ooOOOo0O ) == False ) : continue
   if 85 - 85: I1Ii111 + iII111i - oO0o
   oo00ooOOOo0O = OOIiIi1 . source_rloc
   iioOo0oo = srloc
   if ( oo00ooOOOo0O and iioOo0oo and iioOo0oo . is_more_specific ( oo00ooOOOo0O ) == False ) : continue
   I11iIi1i1I1i1 = OOIiIi1 . datetime_lower
   O0oo0 = OOIiIi1 . datetime_upper
   if ( I11iIi1i1I1i1 and O0oo0 and I11iIi1i1I1i1 . now_in_range ( O0oo0 ) == False ) : continue
   return ( True )
   if 64 - 64: OoOoOO00
  return ( False )
  if 20 - 20: OoOoOO00 / O0 * OOooOOo % I11i + OoO0O00 + o0oOOo0O0Ooo
  if 51 - 51: Ii1I - OoOoOO00 / i11iIiiIii + O0
 def set_policy_map_reply ( self ) :
  oOoOOOO0OO00o = ( self . set_rloc_address == None and
 self . set_rloc_record_name == None and self . set_geo_name == None and
 self . set_elp_name == None and self . set_rle_name == None )
  if ( oOoOOOO0OO00o ) : return ( None )
  if 6 - 6: I1Ii111 / i1IIi / IiII . o0oOOo0O0Ooo
  I1IIiIIIii = lisp_rloc ( )
  if ( self . set_rloc_address ) :
   I1IIiIIIii . rloc . copy_address ( self . set_rloc_address )
   IiiIIi1 = I1IIiIIIii . rloc . print_address_no_iid ( )
   lprint ( "Policy set-rloc-address to {}" . format ( IiiIIi1 ) )
   if 69 - 69: ooOoO0o - OoOoOO00 . I1IiiI . I11i + OoOoOO00 / i11iIiiIii
  if ( self . set_rloc_record_name ) :
   I1IIiIIIii . rloc_name = self . set_rloc_record_name
   IiIIO0 = blue ( I1IIiIIIii . rloc_name , False )
   lprint ( "Policy set-rloc-record-name to {}" . format ( IiIIO0 ) )
   if 20 - 20: OoO0O00 . OoooooooOO - ooOoO0o . I11i / Oo0Ooo
  if ( self . set_geo_name ) :
   I1IIiIIIii . geo_name = self . set_geo_name
   IiIIO0 = I1IIiIIIii . geo_name
   ooOOOoo0O00 = "" if lisp_geo_list . has_key ( IiIIO0 ) else "(not configured)"
   if 22 - 22: oO0o + O0 + I11i . OoO0O00 - II111iiii
   lprint ( "Policy set-geo-name '{}' {}" . format ( IiIIO0 , ooOOOoo0O00 ) )
   if 20 - 20: Ii1I * I1Ii111 . I1IiiI % OoOoOO00 / OoO0O00 % II111iiii
  if ( self . set_elp_name ) :
   I1IIiIIIii . elp_name = self . set_elp_name
   IiIIO0 = I1IIiIIIii . elp_name
   ooOOOoo0O00 = "" if lisp_elp_list . has_key ( IiIIO0 ) else "(not configured)"
   if 43 - 43: IiII + II111iiii + oO0o / I1ii11iIi11i % i1IIi - OoO0O00
   lprint ( "Policy set-elp-name '{}' {}" . format ( IiIIO0 , ooOOOoo0O00 ) )
   if 59 - 59: Oo0Ooo + O0 + iII111i
  if ( self . set_rle_name ) :
   I1IIiIIIii . rle_name = self . set_rle_name
   IiIIO0 = I1IIiIIIii . rle_name
   ooOOOoo0O00 = "" if lisp_rle_list . has_key ( IiIIO0 ) else "(not configured)"
   if 71 - 71: IiII - OoO0O00
   lprint ( "Policy set-rle-name '{}' {}" . format ( IiIIO0 , ooOOOoo0O00 ) )
   if 90 - 90: Oo0Ooo
  if ( self . set_json_name ) :
   I1IIiIIIii . json_name = self . set_json_name
   IiIIO0 = I1IIiIIIii . json_name
   ooOOOoo0O00 = "" if lisp_json_list . has_key ( IiIIO0 ) else "(not configured)"
   if 83 - 83: iIii1I11I1II1 % ooOoO0o % OOooOOo * i1IIi - o0oOOo0O0Ooo * i1IIi
   lprint ( "Policy set-json-name '{}' {}" . format ( IiIIO0 , ooOOOoo0O00 ) )
   if 60 - 60: Ii1I . I1ii11iIi11i - I11i + i11iIiiIii / iII111i
  return ( I1IIiIIIii )
  if 9 - 9: I1Ii111 . oO0o . OoO0O00 / IiII - oO0o / oO0o
  if 50 - 50: II111iiii + OoOoOO00
 def save_policy ( self ) :
  lisp_policies [ self . policy_name ] = self
  if 17 - 17: ooOoO0o + I1ii11iIi11i
  if 34 - 34: Ii1I / II111iiii + OoOoOO00 . II111iiii + OoooooooOO * o0oOOo0O0Ooo
  if 48 - 48: O0
class lisp_pubsub ( ) :
 def __init__ ( self , itr , port , nonce , ttl , xtr_id ) :
  self . itr = itr
  self . port = port
  self . nonce = nonce
  self . uptime = lisp_get_timestamp ( )
  self . ttl = ttl
  self . xtr_id = xtr_id
  self . map_notify_count = 0
  if 99 - 99: II111iiii * oO0o / I1ii11iIi11i - i1IIi
  if 84 - 84: i11iIiiIii . OoooooooOO
 def add ( self , eid_prefix ) :
  oOoooOOO0o0 = self . ttl
  ooOOoo0 = eid_prefix . print_prefix ( )
  if ( lisp_pubsub_cache . has_key ( ooOOoo0 ) == False ) :
   lisp_pubsub_cache [ ooOOoo0 ] = { }
   if 69 - 69: I1Ii111 * II111iiii % I1Ii111 * i11iIiiIii . ooOoO0o / Oo0Ooo
  oo0OoooOOoOo = lisp_pubsub_cache [ ooOOoo0 ]
  if 5 - 5: Ii1I
  iIIIIiiII = "Add"
  if ( oo0OoooOOoOo . has_key ( self . xtr_id ) ) :
   iIIIIiiII = "Replace"
   del ( oo0OoooOOoOo [ self . xtr_id ] )
   if 23 - 23: OoOoOO00
  oo0OoooOOoOo [ self . xtr_id ] = self
  if 98 - 98: o0oOOo0O0Ooo . iIii1I11I1II1 / Ii1I % I1IiiI
  ooOOoo0 = green ( ooOOoo0 , False )
  I11iiII1I1111 = red ( self . itr . print_address_no_iid ( ) , False )
  I1II = "0x" + lisp_hex_string ( self . xtr_id )
  lprint ( "{} pubsub state {} for {}, xtr-id: {}, ttl {}" . format ( iIIIIiiII , ooOOoo0 ,
 I11iiII1I1111 , I1II , oOoooOOO0o0 ) )
  if 19 - 19: I1Ii111 / O0 % o0oOOo0O0Ooo
  if 1 - 1: OoOoOO00 / I11i
 def delete ( self , eid_prefix ) :
  ooOOoo0 = eid_prefix . print_prefix ( )
  I11iiII1I1111 = red ( self . itr . print_address_no_iid ( ) , False )
  I1II = "0x" + lisp_hex_string ( self . xtr_id )
  if ( lisp_pubsub_cache . has_key ( ooOOoo0 ) ) :
   oo0OoooOOoOo = lisp_pubsub_cache [ ooOOoo0 ]
   if ( oo0OoooOOoOo . has_key ( self . xtr_id ) ) :
    oo0OoooOOoOo . pop ( self . xtr_id )
    lprint ( "Remove pubsub state {} for {}, xtr-id: {}" . format ( ooOOoo0 ,
 I11iiII1I1111 , I1II ) )
    if 43 - 43: o0oOOo0O0Ooo - i1IIi / Ii1I . OoOoOO00 + i11iIiiIii
    if 69 - 69: i11iIiiIii - iIii1I11I1II1
    if 40 - 40: I1IiiI / oO0o + ooOoO0o
    if 100 - 100: OoOoOO00 % iII111i * ooOoO0o . O0
    if 37 - 37: I1ii11iIi11i
    if 24 - 24: O0 . I1Ii111 * i11iIiiIii
    if 84 - 84: ooOoO0o / I1ii11iIi11i - o0oOOo0O0Ooo . OoooooooOO * iIii1I11I1II1
    if 16 - 16: I11i % O0
    if 56 - 56: Ii1I * OoOoOO00 . i1IIi
    if 15 - 15: I1Ii111
    if 64 - 64: OOooOOo * Oo0Ooo
    if 96 - 96: Oo0Ooo / I1ii11iIi11i * iIii1I11I1II1 / iII111i
    if 18 - 18: I1Ii111
    if 29 - 29: i1IIi - I1IiiI / i1IIi
    if 64 - 64: IiII
    if 69 - 69: OOooOOo . I1IiiI
    if 11 - 11: I1Ii111 * I1IiiI - I1Ii111 / iII111i
    if 22 - 22: iII111i % I11i % O0 - I11i
    if 71 - 71: I1Ii111 / II111iiii - OoooooooOO % i1IIi + OoOoOO00 % OoooooooOO
    if 52 - 52: Ii1I . OoOoOO00 / o0oOOo0O0Ooo / iII111i
    if 83 - 83: OoO0O00 - Oo0Ooo + I1Ii111 . I1IiiI
    if 78 - 78: I11i / ooOoO0o . OoOoOO00 * i1IIi
class lisp_trace ( ) :
 def __init__ ( self ) :
  self . nonce = lisp_get_control_nonce ( )
  self . packet_json = [ ]
  self . local_rloc = None
  self . local_port = None
  self . lisp_socket = None
  if 15 - 15: i1IIi . II111iiii * OoOoOO00 / Oo0Ooo
  if 99 - 99: iII111i - o0oOOo0O0Ooo / O0
 def print_trace ( self ) :
  i1IiIi1111i = self . packet_json
  lprint ( "LISP-Trace JSON: '{}'" . format ( i1IiIi1111i ) )
  if 97 - 97: iIii1I11I1II1 * I1Ii111
  if 39 - 39: I1Ii111 . II111iiii
 def encode ( self ) :
  iII = socket . htonl ( 0x90000000 )
  IiiiIi1iiii11 = struct . pack ( "II" , iII , 0 )
  IiiiIi1iiii11 += struct . pack ( "Q" , self . nonce )
  IiiiIi1iiii11 += json . dumps ( self . packet_json )
  return ( IiiiIi1iiii11 )
  if 94 - 94: OoO0O00 - OoO0O00 + iIii1I11I1II1 + O0 * oO0o
  if 9 - 9: Ii1I * Oo0Ooo / oO0o / Ii1I
 def decode ( self , packet ) :
  i1I1iii1I11II = "I"
  Iiiii = struct . calcsize ( i1I1iii1I11II )
  if ( len ( packet ) < Iiiii ) : return ( False )
  iII = struct . unpack ( i1I1iii1I11II , packet [ : Iiiii ] ) [ 0 ]
  packet = packet [ Iiiii : : ]
  iII = socket . ntohl ( iII )
  if ( ( iII & 0xff000000 ) != 0x90000000 ) : return ( False )
  if 34 - 34: I1IiiI
  if ( len ( packet ) < Iiiii ) : return ( False )
  IiiIIi1 = struct . unpack ( i1I1iii1I11II , packet [ : Iiiii ] ) [ 0 ]
  packet = packet [ Iiiii : : ]
  if 56 - 56: Ii1I
  IiiIIi1 = socket . ntohl ( IiiIIi1 )
  ooooO = IiiIIi1 >> 24
  Iii1i111I = ( IiiIIi1 >> 16 ) & 0xff
  oOO0O0Oo0oO = ( IiiIIi1 >> 8 ) & 0xff
  iIIi1I1Iiii = IiiIIi1 & 0xff
  self . local_rloc = "{}.{}.{}.{}" . format ( ooooO , Iii1i111I , oOO0O0Oo0oO , iIIi1I1Iiii )
  self . local_port = str ( iII & 0xffff )
  if 42 - 42: OoO0O00 * i1IIi
  i1I1iii1I11II = "Q"
  Iiiii = struct . calcsize ( i1I1iii1I11II )
  if ( len ( packet ) < Iiiii ) : return ( False )
  self . nonce = struct . unpack ( i1I1iii1I11II , packet [ : Iiiii ] ) [ 0 ]
  packet = packet [ Iiiii : : ]
  if ( len ( packet ) == 0 ) : return ( True )
  if 60 - 60: I1IiiI * I1Ii111 + oO0o - Ii1I
  try :
   self . packet_json = json . loads ( packet )
  except :
   return ( False )
   if 58 - 58: i11iIiiIii . o0oOOo0O0Ooo - i1IIi - I1IiiI * i1IIi % I1Ii111
  return ( True )
  if 37 - 37: I11i
  if 61 - 61: OoooooooOO % iIii1I11I1II1 % O0 % I1Ii111 / Oo0Ooo . I1IiiI
 def myeid ( self , eid ) :
  return ( lisp_is_myeid ( eid ) )
  if 20 - 20: ooOoO0o - I1Ii111
  if 97 - 97: O0
 def return_to_sender ( self , lisp_socket , rts_rloc , packet ) :
  I1IIiIIIii , Oo0O00O = self . rtr_cache_nat_trace_find ( rts_rloc )
  if ( I1IIiIIIii == None ) :
   I1IIiIIIii , Oo0O00O = rts_rloc . split ( ":" )
   Oo0O00O = int ( Oo0O00O )
   lprint ( "Send LISP-Trace to address {}:{}" . format ( I1IIiIIIii , Oo0O00O ) )
  else :
   lprint ( "Send LISP-Trace to translated address {}:{}" . format ( I1IIiIIIii ,
 Oo0O00O ) )
   if 56 - 56: Ii1I * I1IiiI * ooOoO0o
   if 39 - 39: iII111i % Ii1I * iIii1I11I1II1 - Ii1I - I1Ii111
  if ( lisp_socket == None ) :
   IiII1iiI = socket . socket ( socket . AF_INET , socket . SOCK_DGRAM )
   IiII1iiI . bind ( ( "0.0.0.0" , LISP_TRACE_PORT ) )
   IiII1iiI . sendto ( packet , ( I1IIiIIIii , Oo0O00O ) )
   IiII1iiI . close ( )
  else :
   lisp_socket . sendto ( packet , ( I1IIiIIIii , Oo0O00O ) )
   if 60 - 60: i11iIiiIii + i11iIiiIii - OoooooooOO + OoooooooOO
   if 5 - 5: o0oOOo0O0Ooo
   if 78 - 78: OOooOOo * O0 * II111iiii % OoOoOO00
 def packet_length ( self ) :
  o0oOo00 = 8 ; IIOo0Oo00o0 = 4 + 4 + 8
  return ( o0oOo00 + IIOo0Oo00o0 + len ( json . dumps ( self . packet_json ) ) )
  if 82 - 82: OoO0O00 + Ii1I
  if 3 - 3: iIii1I11I1II1 * I1ii11iIi11i * i1IIi - O0 - iII111i * O0
 def rtr_cache_nat_trace ( self , translated_rloc , translated_port ) :
  Oo000O000 = self . local_rloc + ":" + self . local_port
  i11II = ( translated_rloc , translated_port )
  lisp_rtr_nat_trace_cache [ Oo000O000 ] = i11II
  lprint ( "Cache NAT Trace addresses {} -> {}" . format ( Oo000O000 , i11II ) )
  if 10 - 10: I1Ii111 . IiII * I1ii11iIi11i
  if 81 - 81: i11iIiiIii + I1Ii111
 def rtr_cache_nat_trace_find ( self , local_rloc_and_port ) :
  Oo000O000 = local_rloc_and_port
  try : i11II = lisp_rtr_nat_trace_cache [ Oo000O000 ]
  except : i11II = ( None , None )
  return ( i11II )
  if 65 - 65: OOooOOo - iII111i * I1Ii111 + i1IIi % ooOoO0o
  if 6 - 6: O0 + Ii1I % II111iiii % i1IIi . iII111i / OoooooooOO
  if 8 - 8: OOooOOo + I1IiiI - Oo0Ooo + i1IIi . Ii1I . I1Ii111
  if 38 - 38: I1IiiI / II111iiii * OoOoOO00 / I1Ii111
  if 80 - 80: I1ii11iIi11i / ooOoO0o * ooOoO0o . Oo0Ooo
  if 44 - 44: Ii1I * i1IIi % OoOoOO00 . OoOoOO00
  if 16 - 16: Oo0Ooo / i1IIi / iIii1I11I1II1 / iIii1I11I1II1 % o0oOOo0O0Ooo / I1ii11iIi11i
  if 11 - 11: I1IiiI
  if 45 - 45: OOooOOo / i1IIi * IiII * I1Ii111
  if 34 - 34: ooOoO0o / iIii1I11I1II1 . iII111i
  if 91 - 91: OoO0O00
def lisp_get_map_server ( address ) :
 for ii1i in lisp_map_servers_list . values ( ) :
  if ( ii1i . map_server . is_exact_match ( address ) ) : return ( ii1i )
  if 8 - 8: oO0o
 return ( None )
 if 96 - 96: IiII
 if 37 - 37: Ii1I % i11iIiiIii + iIii1I11I1II1 % Oo0Ooo - iIii1I11I1II1
 if 26 - 26: o0oOOo0O0Ooo . i1IIi
 if 62 - 62: IiII * I1ii11iIi11i % iIii1I11I1II1 / II111iiii - OoO0O00
 if 52 - 52: iII111i . I11i - I11i + oO0o + iIii1I11I1II1
 if 83 - 83: I11i * iIii1I11I1II1 + OoOoOO00
 if 81 - 81: ooOoO0o * OOooOOo / OoO0O00 + I1ii11iIi11i % I1Ii111
def lisp_get_any_map_server ( ) :
 for ii1i in lisp_map_servers_list . values ( ) : return ( ii1i )
 return ( None )
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
def lisp_get_map_resolver ( address , eid ) :
 if ( address != None ) :
  IiiIIi1 = address . print_address ( )
  OoOooo0o = None
  for Oo000O000 in lisp_map_resolvers_list :
   if ( Oo000O000 . find ( IiiIIi1 ) == - 1 ) : continue
   OoOooo0o = lisp_map_resolvers_list [ Oo000O000 ]
   if 58 - 58: I1Ii111 + OoooooooOO + iIii1I11I1II1
  return ( OoOooo0o )
  if 13 - 13: o0oOOo0O0Ooo . I11i / O0
  if 39 - 39: I11i + oO0o + ooOoO0o % ooOoO0o - I1IiiI % Oo0Ooo
  if 9 - 9: IiII / iII111i * II111iiii + O0 % Oo0Ooo / i1IIi
  if 45 - 45: OoOoOO00 % i11iIiiIii . I1IiiI - O0 * i1IIi - I1IiiI
  if 48 - 48: IiII / iIii1I11I1II1
  if 20 - 20: oO0o / OoooooooOO
  if 95 - 95: Oo0Ooo . i11iIiiIii
 if ( eid == "" ) :
  i1IiI1i = ""
 elif ( eid == None ) :
  i1IiI1i = "all"
 else :
  iiIII1 = lisp_db_for_lookups . lookup_cache ( eid , False )
  i1IiI1i = "all" if iiIII1 == None else iiIII1 . use_mr_name
  if 10 - 10: OoO0O00 - oO0o + Oo0Ooo / i11iIiiIii + Ii1I + I11i
  if 59 - 59: ooOoO0o * II111iiii
 ooOoOOOoO = None
 for OoOooo0o in lisp_map_resolvers_list . values ( ) :
  if ( i1IiI1i == "" ) : return ( OoOooo0o )
  if ( OoOooo0o . mr_name != i1IiI1i ) : continue
  if ( ooOoOOOoO == None or OoOooo0o . last_used < ooOoOOOoO . last_used ) : ooOoOOOoO = OoOooo0o
  if 14 - 14: OoO0O00 * I1IiiI
 return ( ooOoOOOoO )
 if 78 - 78: I1IiiI / iII111i - ooOoO0o - i11iIiiIii
 if 39 - 39: i11iIiiIii / oO0o
 if 71 - 71: I1Ii111 * iIii1I11I1II1 - I1Ii111
 if 87 - 87: I1IiiI / Ii1I
 if 54 - 54: OoooooooOO / Ii1I
 if 26 - 26: o0oOOo0O0Ooo + OoO0O00
 if 59 - 59: Ii1I * IiII
 if 64 - 64: ooOoO0o . Oo0Ooo - OoOoOO00
def lisp_get_decent_map_resolver ( eid ) :
 ooo = lisp_get_decent_index ( eid )
 o0ooO00 = str ( ooo ) + "." + lisp_decent_dns_suffix
 if 3 - 3: I11i
 lprint ( "Use LISP-Decent map-resolver {} for EID {}" . format ( bold ( o0ooO00 , False ) , eid . print_prefix ( ) ) )
 if 55 - 55: OoO0O00 . i11iIiiIii . o0oOOo0O0Ooo % iIii1I11I1II1 . I1ii11iIi11i * I11i
 if 7 - 7: OoOoOO00 * iII111i - i11iIiiIii
 ooOoOOOoO = None
 for OoOooo0o in lisp_map_resolvers_list . values ( ) :
  if ( o0ooO00 != OoOooo0o . dns_name ) : continue
  if ( ooOoOOOoO == None or OoOooo0o . last_used < ooOoOOOoO . last_used ) : ooOoOOOoO = OoOooo0o
  if 79 - 79: OOooOOo
 return ( ooOoOOOoO )
 if 2 - 2: I11i % I1Ii111 - OoO0O00 % OoO0O00 % OOooOOo - OoO0O00
 if 3 - 3: iIii1I11I1II1 + iIii1I11I1II1 + OoO0O00
 if 59 - 59: iII111i
 if 7 - 7: o0oOOo0O0Ooo * OoooooooOO - Ii1I * II111iiii % I1Ii111
 if 82 - 82: OoOoOO00 - OoOoOO00 + iIii1I11I1II1 + o0oOOo0O0Ooo + IiII - o0oOOo0O0Ooo
 if 65 - 65: I1Ii111 + OOooOOo
 if 97 - 97: oO0o % OoOoOO00 * oO0o % II111iiii + iIii1I11I1II1
def lisp_ipv4_input ( packet ) :
 if 11 - 11: ooOoO0o . o0oOOo0O0Ooo
 if 94 - 94: ooOoO0o . oO0o * OoooooooOO % oO0o
 if 77 - 77: ooOoO0o % I1IiiI
 if 26 - 26: o0oOOo0O0Ooo
 if ( ord ( packet [ 9 ] ) == 2 ) : return ( [ True , packet ] )
 if 72 - 72: I1IiiI
 if 90 - 90: ooOoO0o
 if 67 - 67: iIii1I11I1II1 + i1IIi * I1IiiI * OoooooooOO
 if 23 - 23: IiII
 Oo0 = struct . unpack ( "H" , packet [ 10 : 12 ] ) [ 0 ]
 if ( Oo0 == 0 ) :
  dprint ( "Packet arrived with checksum of 0!" )
 else :
  packet = lisp_ip_checksum ( packet )
  Oo0 = struct . unpack ( "H" , packet [ 10 : 12 ] ) [ 0 ]
  if ( Oo0 != 0 ) :
   dprint ( "IPv4 header checksum failed for inner header" )
   packet = lisp_format_packet ( packet [ 0 : 20 ] )
   dprint ( "Packet header: {}" . format ( packet ) )
   return ( [ False , None ] )
   if 32 - 32: OoOoOO00 - iII111i % oO0o / I1ii11iIi11i - o0oOOo0O0Ooo
   if 52 - 52: Ii1I / OoooooooOO % i11iIiiIii + iII111i
   if 59 - 59: Ii1I / o0oOOo0O0Ooo / oO0o + iII111i * I1ii11iIi11i - o0oOOo0O0Ooo
   if 70 - 70: O0 / I1ii11iIi11i + ooOoO0o . OoO0O00 - OoO0O00 / i11iIiiIii
   if 1 - 1: iIii1I11I1II1 % I1ii11iIi11i
   if 49 - 49: iII111i + o0oOOo0O0Ooo % I1ii11iIi11i . O0 % OoooooooOO . o0oOOo0O0Ooo
   if 3 - 3: i11iIiiIii - i1IIi * o0oOOo0O0Ooo / OoOoOO00 % Oo0Ooo
 oOoooOOO0o0 = struct . unpack ( "B" , packet [ 8 : 9 ] ) [ 0 ]
 if ( oOoooOOO0o0 == 0 ) :
  dprint ( "IPv4 packet arrived with ttl 0, packet discarded" )
  return ( [ False , None ] )
 elif ( oOoooOOO0o0 == 1 ) :
  dprint ( "IPv4 packet {}, packet discarded" . format ( bold ( "ttl expiry" , False ) ) )
  if 65 - 65: OoooooooOO + iII111i - i11iIiiIii - IiII + oO0o
  return ( [ False , None ] )
  if 67 - 67: i1IIi * I1Ii111 * O0
  if 16 - 16: OoO0O00 + iII111i + i1IIi + I1ii11iIi11i - I1IiiI
 oOoooOOO0o0 -= 1
 packet = packet [ 0 : 8 ] + struct . pack ( "B" , oOoooOOO0o0 ) + packet [ 9 : : ]
 packet = packet [ 0 : 10 ] + struct . pack ( "H" , 0 ) + packet [ 12 : : ]
 packet = lisp_ip_checksum ( packet )
 return ( [ False , packet ] )
 if 88 - 88: oO0o % iII111i + I1ii11iIi11i - II111iiii . I11i
 if 18 - 18: I1ii11iIi11i - i1IIi - IiII * II111iiii % I1Ii111 . II111iiii
 if 80 - 80: oO0o + OoO0O00 + o0oOOo0O0Ooo . OoOoOO00
 if 75 - 75: i11iIiiIii
 if 58 - 58: iII111i
 if 48 - 48: OoO0O00 * OOooOOo / iII111i
 if 90 - 90: I1IiiI * i11iIiiIii . OOooOOo / o0oOOo0O0Ooo
def lisp_ipv6_input ( packet ) :
 oo0OoO = packet . inner_dest
 packet = packet . packet
 if 82 - 82: Oo0Ooo
 if 50 - 50: I1Ii111 * OOooOOo * OoOoOO00 / OoooooooOO % iII111i
 if 80 - 80: I1Ii111
 if 35 - 35: Ii1I . O0 % i11iIiiIii * oO0o - OoooooooOO
 if 87 - 87: iII111i * ooOoO0o - OOooOOo . O0
 oOoooOOO0o0 = struct . unpack ( "B" , packet [ 7 : 8 ] ) [ 0 ]
 if ( oOoooOOO0o0 == 0 ) :
  dprint ( "IPv6 packet arrived with hop-limit 0, packet discarded" )
  return ( None )
 elif ( oOoooOOO0o0 == 1 ) :
  dprint ( "IPv6 packet {}, packet discarded" . format ( bold ( "ttl expiry" , False ) ) )
  if 20 - 20: OoOoOO00 - IiII
  return ( None )
  if 9 - 9: O0 . I11i % I1ii11iIi11i * oO0o - I1Ii111 - i1IIi
  if 66 - 66: II111iiii / Oo0Ooo
  if 93 - 93: iII111i + I11i * OoooooooOO . OoO0O00
  if 40 - 40: ooOoO0o * I1Ii111 + iII111i
  if 52 - 52: iII111i % I11i
 if ( oo0OoO . is_ipv6_link_local ( ) ) :
  dprint ( "Do not encapsulate IPv6 link-local packets" )
  return ( None )
  if 95 - 95: IiII + Ii1I / OoO0O00 - iII111i / I1IiiI
  if 27 - 27: Oo0Ooo + i1IIi + i11iIiiIii . OoO0O00 . OoO0O00
 oOoooOOO0o0 -= 1
 packet = packet [ 0 : 7 ] + struct . pack ( "B" , oOoooOOO0o0 ) + packet [ 8 : : ]
 return ( packet )
 if 56 - 56: I1Ii111 / OoO0O00 + o0oOOo0O0Ooo . OoooooooOO * Oo0Ooo
 if 14 - 14: OoO0O00
 if 21 - 21: II111iiii + i11iIiiIii + I11i % I1IiiI
 if 65 - 65: IiII + I1ii11iIi11i / iII111i / I1IiiI + Ii1I
 if 88 - 88: IiII % iIii1I11I1II1
 if 3 - 3: ooOoO0o / I1Ii111 % iIii1I11I1II1 % I11i * oO0o / iIii1I11I1II1
 if 75 - 75: i11iIiiIii . iII111i
 if 68 - 68: OOooOOo . I1ii11iIi11i % I1ii11iIi11i . i11iIiiIii
def lisp_mac_input ( packet ) :
 return ( packet )
 if 45 - 45: oO0o % I1ii11iIi11i * I1Ii111
 if 21 - 21: O0 + i11iIiiIii
 if 72 - 72: OoOoOO00 * OoooooooOO % O0 / I1ii11iIi11i % Ii1I - I11i
 if 65 - 65: iIii1I11I1II1 + II111iiii * OoO0O00 * i11iIiiIii / IiII
 if 15 - 15: OoOoOO00 % O0 - OOooOOo - oO0o . iII111i . OoO0O00
 if 52 - 52: II111iiii * o0oOOo0O0Ooo
 if 95 - 95: I1Ii111 - OoooooooOO
 if 99 - 99: OoooooooOO % IiII . I11i + OoooooooOO
 if 57 - 57: Ii1I / I1IiiI * i1IIi
def lisp_rate_limit_map_request ( dest ) :
 Oo0oooo00 = lisp_get_timestamp ( )
 if 21 - 21: I11i . O0 * OoooooooOO + ooOoO0o * oO0o % i11iIiiIii
 if 30 - 30: ooOoO0o * I1Ii111 + OoO0O00
 if 30 - 30: Ii1I / iII111i * Ii1I
 if 11 - 11: OoOoOO00 - OoOoOO00 % oO0o
 oO000o0Oo00 = Oo0oooo00 - lisp_no_map_request_rate_limit
 if ( oO000o0Oo00 < LISP_NO_MAP_REQUEST_RATE_LIMIT_TIME ) :
  i1i = int ( LISP_NO_MAP_REQUEST_RATE_LIMIT_TIME - oO000o0Oo00 )
  dprint ( "No Rate-Limit Mode for another {} secs" . format ( i1i ) )
  return ( False )
  if 3 - 3: I1IiiI - OoooooooOO % iIii1I11I1II1 + I1Ii111 + OoOoOO00
  if 71 - 71: i1IIi % O0 % ooOoO0o
  if 24 - 24: O0
  if 88 - 88: OoooooooOO / Oo0Ooo / oO0o
  if 99 - 99: I1Ii111 % OoOoOO00 % IiII - Ii1I
 if ( lisp_last_map_request_sent == None ) : return ( False )
 oO000o0Oo00 = Oo0oooo00 - lisp_last_map_request_sent
 o0O0oOO0oOOo = ( oO000o0Oo00 < LISP_MAP_REQUEST_RATE_LIMIT )
 if 79 - 79: ooOoO0o + Oo0Ooo
 if ( o0O0oOO0oOOo ) :
  dprint ( "Rate-limiting Map-Request for {}, sent {} secs ago" . format ( green ( dest . print_address ( ) , False ) , round ( oO000o0Oo00 , 3 ) ) )
  if 80 - 80: OoOoOO00 % OoO0O00 . OoO0O00 * OoO0O00 * O0
  if 18 - 18: II111iiii . o0oOOo0O0Ooo + OoO0O00
 return ( o0O0oOO0oOOo )
 if 69 - 69: OoO0O00 . ooOoO0o * ooOoO0o * iIii1I11I1II1
 if 8 - 8: iII111i . oO0o . OOooOOo + iII111i . Ii1I
 if 46 - 46: OoO0O00
 if 21 - 21: iIii1I11I1II1 - iII111i
 if 15 - 15: O0 + iII111i + i11iIiiIii
 if 31 - 31: iIii1I11I1II1 * iIii1I11I1II1 . I11i
 if 52 - 52: i11iIiiIii / oO0o / IiII
def lisp_send_map_request ( lisp_sockets , lisp_ephem_port , seid , deid , rloc ) :
 global lisp_last_map_request_sent
 if 84 - 84: I11i . oO0o + ooOoO0o
 if 75 - 75: I1Ii111
 if 97 - 97: ooOoO0o % Oo0Ooo . o0oOOo0O0Ooo
 if 22 - 22: O0 % I11i + OoO0O00 - iII111i + I1IiiI . O0
 if 73 - 73: ooOoO0o + O0 - I11i . I1IiiI + OOooOOo
 if 36 - 36: I11i % OoO0O00 * OoOoOO00 - I1Ii111
 I1iI1IiiiiI = Ii1I1 = None
 if ( rloc ) :
  I1iI1IiiiiI = rloc . rloc
  Ii1I1 = rloc . translated_port if lisp_i_am_rtr else LISP_DATA_PORT
  if 90 - 90: OoOoOO00 % OoOoOO00 + I11i
  if 70 - 70: I1IiiI . ooOoO0o / I11i / OoO0O00
  if 40 - 40: oO0o % iIii1I11I1II1 * iIii1I11I1II1 / Oo0Ooo * OoO0O00
  if 61 - 61: OOooOOo
  if 80 - 80: I1ii11iIi11i
 iI111IOoo , iIi11iiI11 , OoO0o0OOOO = lisp_myrlocs
 if ( iI111IOoo == None ) :
  lprint ( "Suppress sending Map-Request, IPv4 RLOC not found" )
  return
  if 93 - 93: I1Ii111 . o0oOOo0O0Ooo
 if ( iIi11iiI11 == None and I1iI1IiiiiI != None and I1iI1IiiiiI . is_ipv6 ( ) ) :
  lprint ( "Suppress sending Map-Request, IPv6 RLOC not found" )
  return
  if 96 - 96: ooOoO0o - o0oOOo0O0Ooo % O0 * Ii1I . OoOoOO00
  if 80 - 80: I1IiiI
 OooOO00o = lisp_map_request ( )
 OooOO00o . record_count = 1
 OooOO00o . nonce = lisp_get_control_nonce ( )
 OooOO00o . rloc_probe = ( I1iI1IiiiiI != None )
 if 31 - 31: I1Ii111 + o0oOOo0O0Ooo . I1IiiI + I11i . oO0o
 if 50 - 50: Ii1I . OOooOOo
 if 84 - 84: OoOoOO00 * OoO0O00 + I1IiiI
 if 38 - 38: OoooooooOO % I1IiiI
 if 80 - 80: iII111i / O0 % OoooooooOO / Oo0Ooo
 if 75 - 75: ooOoO0o
 if 72 - 72: oO0o . OoooooooOO % ooOoO0o % OoO0O00 * oO0o * OoO0O00
 if ( rloc ) : rloc . last_rloc_probe_nonce = OooOO00o . nonce
 if 14 - 14: I11i / I11i
 oOOooo000OoO = deid . is_multicast_address ( )
 if ( oOOooo000OoO ) :
  OooOO00o . target_eid = seid
  OooOO00o . target_group = deid
 else :
  OooOO00o . target_eid = deid
  if 90 - 90: O0 * OOooOOo / oO0o . Oo0Ooo * I11i
  if 93 - 93: oO0o / ooOoO0o - I1Ii111
  if 70 - 70: OOooOOo / Ii1I - ooOoO0o + OoooooooOO / OoO0O00 - i11iIiiIii
  if 26 - 26: O0 + Oo0Ooo
  if 30 - 30: IiII
  if 6 - 6: O0
  if 92 - 92: I11i
  if 76 - 76: I11i / iIii1I11I1II1 - i11iIiiIii / O0 / O0
  if 19 - 19: Ii1I . I1IiiI - i1IIi * ooOoO0o . iIii1I11I1II1
 if ( OooOO00o . rloc_probe == False ) :
  iiIII1 = lisp_get_signature_eid ( )
  if ( iiIII1 ) :
   OooOO00o . signature_eid . copy_address ( iiIII1 . eid )
   OooOO00o . privkey_filename = "./lisp-sig.pem"
   if 87 - 87: ooOoO0o % I1ii11iIi11i . I1IiiI
   if 42 - 42: iII111i % i11iIiiIii % o0oOOo0O0Ooo . O0 % iII111i
   if 72 - 72: Oo0Ooo . Oo0Ooo . IiII . Oo0Ooo
   if 80 - 80: I1Ii111 + IiII + O0 - I1Ii111 . iIii1I11I1II1
   if 53 - 53: OoO0O00 / i11iIiiIii * I1Ii111
   if 62 - 62: oO0o / Oo0Ooo / IiII + I11i * ooOoO0o
 if ( seid == None or oOOooo000OoO ) :
  OooOO00o . source_eid . afi = LISP_AFI_NONE
 else :
  OooOO00o . source_eid = seid
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
 if ( I1iI1IiiiiI != None and lisp_nat_traversal and lisp_i_am_rtr == False ) :
  if ( I1iI1IiiiiI . is_private_address ( ) == False ) :
   iI111IOoo = lisp_get_any_translated_rloc ( )
   if 3 - 3: ooOoO0o - Oo0Ooo
  if ( iI111IOoo == None ) :
   lprint ( "Suppress sending Map-Request, translated RLOC not found" )
   return
   if 2 - 2: iII111i . iII111i
   if 77 - 77: OOooOOo
   if 74 - 74: O0
   if 86 - 86: OoOoOO00
   if 4 - 4: OoooooooOO * OoO0O00
   if 93 - 93: OoO0O00 - I1Ii111 - OoO0O00
   if 1 - 1: o0oOOo0O0Ooo . oO0o * i11iIiiIii * IiII - OoO0O00 - OoooooooOO
   if 29 - 29: iIii1I11I1II1 + OoO0O00 * II111iiii * Ii1I * iII111i . O0
 if ( I1iI1IiiiiI == None or I1iI1IiiiiI . is_ipv4 ( ) ) :
  if ( lisp_nat_traversal and I1iI1IiiiiI == None ) :
   iIIIIII1I = lisp_get_any_translated_rloc ( )
   if ( iIIIIII1I != None ) : iI111IOoo = iIIIIII1I
   if 31 - 31: oO0o / Oo0Ooo / OoO0O00 + I1ii11iIi11i
  OooOO00o . itr_rlocs . append ( iI111IOoo )
  if 34 - 34: OOooOOo * Oo0Ooo / I1Ii111 / OOooOOo
 if ( I1iI1IiiiiI == None or I1iI1IiiiiI . is_ipv6 ( ) ) :
  if ( iIi11iiI11 == None or iIi11iiI11 . is_ipv6_link_local ( ) ) :
   iIi11iiI11 = None
  else :
   OooOO00o . itr_rloc_count = 1 if ( I1iI1IiiiiI == None ) else 0
   OooOO00o . itr_rlocs . append ( iIi11iiI11 )
   if 92 - 92: O0 * O0
   if 37 - 37: iIii1I11I1II1 / I1Ii111 + OoO0O00
   if 85 - 85: ooOoO0o / I1IiiI
   if 7 - 7: Oo0Ooo - iIii1I11I1II1 / I1ii11iIi11i * I1IiiI + Ii1I
   if 99 - 99: i11iIiiIii - I1ii11iIi11i
   if 64 - 64: IiII . OoOoOO00 . Oo0Ooo . I1Ii111 / I11i / Ii1I
   if 95 - 95: iIii1I11I1II1 . Ii1I % oO0o - I11i % IiII
   if 42 - 42: OoOoOO00 + oO0o * i1IIi + i11iIiiIii
   if 25 - 25: Ii1I - Ii1I - I1ii11iIi11i / i1IIi . OoOoOO00 % Oo0Ooo
 if ( I1iI1IiiiiI != None and OooOO00o . itr_rlocs != [ ] ) :
  iIi1i1i = OooOO00o . itr_rlocs [ 0 ]
 else :
  if ( deid . is_ipv4 ( ) ) :
   iIi1i1i = iI111IOoo
  elif ( deid . is_ipv6 ( ) ) :
   iIi1i1i = iIi11iiI11
  else :
   iIi1i1i = iI111IOoo
   if 76 - 76: I1Ii111 / OoOoOO00
   if 61 - 61: Oo0Ooo . i1IIi
   if 78 - 78: i11iIiiIii
   if 20 - 20: Ii1I
   if 100 - 100: OoooooooOO . I1Ii111
   if 32 - 32: iIii1I11I1II1 . iIii1I11I1II1 % II111iiii / Oo0Ooo . iIii1I11I1II1 . O0
 IiiiIi1iiii11 = OooOO00o . encode ( I1iI1IiiiiI , Ii1I1 )
 OooOO00o . print_map_request ( )
 if 63 - 63: I1IiiI . iIii1I11I1II1 . Oo0Ooo % OOooOOo - iII111i + ooOoO0o
 if 64 - 64: o0oOOo0O0Ooo / Ii1I % I1Ii111 % iII111i + OOooOOo * IiII
 if 87 - 87: I1ii11iIi11i . i1IIi - I11i + OoOoOO00 . O0
 if 37 - 37: IiII
 if 65 - 65: ooOoO0o * Ii1I / I1IiiI . i1IIi % ooOoO0o . OoooooooOO
 if 17 - 17: ooOoO0o / OoO0O00 / I1IiiI / OOooOOo % IiII
 if ( I1iI1IiiiiI != None ) :
  if ( rloc . is_rloc_translated ( ) ) :
   iI1I1iI = lisp_get_nat_info ( I1iI1IiiiiI , rloc . rloc_name )
   if 88 - 88: i1IIi - OoOoOO00
   if 66 - 66: OoooooooOO - OoooooooOO * I11i / II111iiii + oO0o / Ii1I
   if 7 - 7: Ii1I / iIii1I11I1II1
   if 36 - 36: iIii1I11I1II1 % i11iIiiIii
   if ( iI1I1iI == None ) :
    O0OOOO0o0O = rloc . rloc . print_address_no_iid ( )
    i11ii = "gleaned-{}" . format ( O0OOOO0o0O )
    oo00ooOOOo0O = rloc . translated_port
    iI1I1iI = lisp_nat_info ( O0OOOO0o0O , i11ii , oo00ooOOOo0O )
    if 35 - 35: Oo0Ooo + I1IiiI - O0 - I1Ii111
   lisp_encapsulate_rloc_probe ( lisp_sockets , I1iI1IiiiiI , iI1I1iI ,
 IiiiIi1iiii11 )
   return
   if 64 - 64: i1IIi * OoOoOO00 / II111iiii * oO0o
   if 35 - 35: i1IIi - Ii1I - Ii1I . O0 % iII111i * iII111i
  oo0o00OO = I1iI1IiiiiI . print_address_no_iid ( )
  oo0OoO = lisp_convert_4to6 ( oo0o00OO )
  lisp_send ( lisp_sockets , oo0OoO , LISP_CTRL_PORT , IiiiIi1iiii11 )
  return
  if 15 - 15: OoooooooOO . Ii1I * I1Ii111 . ooOoO0o % OoO0O00 * Oo0Ooo
  if 10 - 10: iII111i + i11iIiiIii . OOooOOo % iII111i - i1IIi
  if 10 - 10: iIii1I11I1II1 * i11iIiiIii - O0
  if 45 - 45: oO0o % OOooOOo - IiII + o0oOOo0O0Ooo + i11iIiiIii
  if 79 - 79: IiII % I1Ii111 . I1IiiI + O0 * oO0o * ooOoO0o
  if 38 - 38: IiII
 OO0Oo0OO0O0oo = None if lisp_i_am_rtr else seid
 if ( lisp_decent_pull_xtr_configured ( ) ) :
  OoOooo0o = lisp_get_decent_map_resolver ( deid )
 else :
  OoOooo0o = lisp_get_map_resolver ( None , OO0Oo0OO0O0oo )
  if 56 - 56: i1IIi + oO0o + OoO0O00
 if ( OoOooo0o == None ) :
  lprint ( "Cannot find Map-Resolver for source-EID {}" . format ( green ( seid . print_address ( ) , False ) ) )
  if 67 - 67: OoOoOO00 . OoO0O00 + OoooooooOO . I1Ii111
  return
  if 4 - 4: iIii1I11I1II1 + IiII * i11iIiiIii + i11iIiiIii
 OoOooo0o . last_used = lisp_get_timestamp ( )
 OoOooo0o . map_requests_sent += 1
 if ( OoOooo0o . last_nonce == 0 ) : OoOooo0o . last_nonce = OooOO00o . nonce
 if 14 - 14: IiII
 if 29 - 29: o0oOOo0O0Ooo * iIii1I11I1II1 . iIii1I11I1II1
 if 32 - 32: IiII - OoOoOO00
 if 88 - 88: OOooOOo - II111iiii + i1IIi * Oo0Ooo
 if ( seid == None ) : seid = iIi1i1i
 lisp_send_ecm ( lisp_sockets , IiiiIi1iiii11 , seid , lisp_ephem_port , deid ,
 OoOooo0o . map_resolver )
 if 48 - 48: I1Ii111 + IiII % iII111i * iII111i + I1Ii111
 if 83 - 83: OoO0O00 . I11i * I1ii11iIi11i - II111iiii
 if 41 - 41: OoooooooOO . OoOoOO00 * iIii1I11I1II1
 if 18 - 18: IiII / I1Ii111 % i1IIi * i11iIiiIii
 lisp_last_map_request_sent = lisp_get_timestamp ( )
 if 16 - 16: Oo0Ooo
 if 24 - 24: o0oOOo0O0Ooo . OoOoOO00
 if 50 - 50: I1ii11iIi11i / iIii1I11I1II1 - Oo0Ooo - i11iIiiIii % o0oOOo0O0Ooo - ooOoO0o
 if 92 - 92: OoooooooOO - I1ii11iIi11i . I11i / O0 % iII111i
 OoOooo0o . resolve_dns_name ( )
 return
 if 96 - 96: I1IiiI . oO0o % O0
 if 19 - 19: iIii1I11I1II1 + I1Ii111 / OoooooooOO % OOooOOo - i1IIi + I11i
 if 87 - 87: OoooooooOO
 if 97 - 97: ooOoO0o * IiII / iIii1I11I1II1
 if 65 - 65: i1IIi - i11iIiiIii + oO0o % I1IiiI - OoO0O00 % ooOoO0o
 if 23 - 23: o0oOOo0O0Ooo . o0oOOo0O0Ooo - iIii1I11I1II1 / o0oOOo0O0Ooo
 if 65 - 65: I1Ii111 + I1Ii111 . I1ii11iIi11i . OoOoOO00 % o0oOOo0O0Ooo * o0oOOo0O0Ooo
 if 2 - 2: oO0o % iII111i + I1ii11iIi11i / II111iiii * I1ii11iIi11i
def lisp_send_info_request ( lisp_sockets , dest , port , device_name ) :
 if 45 - 45: II111iiii . iII111i
 if 55 - 55: ooOoO0o / iII111i / O0
 if 98 - 98: O0 % iII111i + II111iiii
 if 13 - 13: I1IiiI * oO0o - o0oOOo0O0Ooo
 IiiIiI = lisp_info ( )
 IiiIiI . nonce = lisp_get_control_nonce ( )
 if ( device_name ) : IiiIiI . hostname += "-" + device_name
 if 53 - 53: iII111i + I1Ii111 / IiII - OoO0O00 / OoooooooOO
 oo0o00OO = dest . print_address_no_iid ( )
 if 5 - 5: iII111i . I1IiiI
 if 50 - 50: OOooOOo
 if 67 - 67: oO0o
 if 36 - 36: O0
 if 30 - 30: i11iIiiIii * Oo0Ooo . IiII
 if 65 - 65: oO0o * IiII * OOooOOo / OoooooooOO % I11i / I1Ii111
 if 21 - 21: i1IIi * iII111i + OoO0O00
 if 27 - 27: I11i / oO0o . iII111i + o0oOOo0O0Ooo - OOooOOo
 if 85 - 85: OoooooooOO
 if 83 - 83: iII111i * I11i . OOooOOo - OoO0O00 % IiII
 if 8 - 8: I1Ii111
 if 86 - 86: ooOoO0o + iII111i * O0 % OoO0O00 + OoOoOO00
 if 49 - 49: OOooOOo / i1IIi - II111iiii . iIii1I11I1II1 + I11i . OOooOOo
 if 9 - 9: iIii1I11I1II1 + Ii1I + I11i
 if 96 - 96: OoO0O00 + i11iIiiIii + OoO0O00
 if 7 - 7: i1IIi . I1IiiI
 o0Oo = False
 if ( device_name ) :
  O0OoOOo0ooooO = lisp_get_host_route_next_hop ( oo0o00OO )
  if 38 - 38: OoO0O00 / OoOoOO00 / i1IIi - OoOoOO00 - iII111i % iII111i
  if 19 - 19: iII111i % I11i
  if 98 - 98: I1ii11iIi11i . i1IIi % II111iiii
  if 15 - 15: O0 . I11i / IiII - iIii1I11I1II1 % Oo0Ooo
  if 76 - 76: I1ii11iIi11i . IiII - IiII
  if 51 - 51: i11iIiiIii
  if 11 - 11: I1ii11iIi11i
  if 96 - 96: iII111i * iIii1I11I1II1
  if 100 - 100: iIii1I11I1II1 . I1ii11iIi11i . i11iIiiIii % i11iIiiIii % I11i % Ii1I
  if ( port == LISP_CTRL_PORT and O0OoOOo0ooooO != None ) :
   while ( True ) :
    time . sleep ( .01 )
    O0OoOOo0ooooO = lisp_get_host_route_next_hop ( oo0o00OO )
    if ( O0OoOOo0ooooO == None ) : break
    if 39 - 39: I11i + OoOoOO00
    if 52 - 52: OoooooooOO - OoO0O00
    if 24 - 24: iII111i / Oo0Ooo - I1ii11iIi11i + o0oOOo0O0Ooo
  IIiIiII = lisp_get_default_route_next_hops ( )
  for OoO0o0OOOO , O0O0O in IIiIiII :
   if ( OoO0o0OOOO != device_name ) : continue
   if 24 - 24: II111iiii
   if 40 - 40: o0oOOo0O0Ooo . I1IiiI - o0oOOo0O0Ooo
   if 62 - 62: oO0o
   if 71 - 71: i1IIi . I1ii11iIi11i / i11iIiiIii + II111iiii
   if 14 - 14: iII111i
   if 35 - 35: Ii1I
   if ( O0OoOOo0ooooO != O0O0O ) :
    if ( O0OoOOo0ooooO != None ) :
     lisp_install_host_route ( oo0o00OO , O0OoOOo0ooooO , False )
     if 54 - 54: OOooOOo
    lisp_install_host_route ( oo0o00OO , O0O0O , True )
    o0Oo = True
    if 83 - 83: i1IIi / II111iiii - I1IiiI + I1ii11iIi11i . IiII * oO0o
   break
   if 92 - 92: OoOoOO00 + oO0o % Ii1I / Ii1I - iII111i
   if 11 - 11: Oo0Ooo % II111iiii * Ii1I + II111iiii
   if 9 - 9: I1Ii111
   if 69 - 69: i1IIi + ooOoO0o + Ii1I
   if 88 - 88: OoOoOO00 + iII111i % O0 + OOooOOo / OoooooooOO / OOooOOo
   if 95 - 95: ooOoO0o . Oo0Ooo % IiII + iII111i
 IiiiIi1iiii11 = IiiIiI . encode ( )
 IiiIiI . print_info ( )
 if 16 - 16: I11i * OoO0O00 % o0oOOo0O0Ooo - O0 % II111iiii - I1IiiI
 if 72 - 72: OoooooooOO * OoOoOO00 . OOooOOo + Ii1I . OOooOOo / II111iiii
 if 8 - 8: i1IIi
 if 1 - 1: OoOoOO00 . OoO0O00 . OoO0O00 * O0
 Ooo0o00O0Oo = "(for control)" if port == LISP_CTRL_PORT else "(for data)"
 Ooo0o00O0Oo = bold ( Ooo0o00O0Oo , False )
 oo00ooOOOo0O = bold ( "{}" . format ( port ) , False )
 OO0o = red ( oo0o00OO , False )
 IIiiiIiI1 = "RTR " if port == LISP_DATA_PORT else "MS "
 lprint ( "Send Info-Request to {}{}, port {} {}" . format ( IIiiiIiI1 , OO0o , oo00ooOOOo0O , Ooo0o00O0Oo ) )
 if 2 - 2: iIii1I11I1II1
 if 60 - 60: OoO0O00 + iII111i + oO0o / I1Ii111 * OOooOOo + iIii1I11I1II1
 if 17 - 17: IiII . I1IiiI + I1Ii111 / OOooOOo . Ii1I . II111iiii
 if 63 - 63: OoooooooOO - IiII - I1Ii111 + oO0o
 if 22 - 22: OoooooooOO - I1ii11iIi11i / II111iiii
 if 91 - 91: OOooOOo
 if ( port == LISP_CTRL_PORT ) :
  lisp_send ( lisp_sockets , dest , LISP_CTRL_PORT , IiiiIi1iiii11 )
 else :
  O0ooOoO0 = lisp_data_header ( )
  O0ooOoO0 . instance_id ( 0xffffff )
  O0ooOoO0 = O0ooOoO0 . encode ( )
  if ( O0ooOoO0 ) :
   IiiiIi1iiii11 = O0ooOoO0 + IiiiIi1iiii11
   if 55 - 55: I11i
   if 7 - 7: I1Ii111 + ooOoO0o % o0oOOo0O0Ooo
   if 53 - 53: i1IIi / iII111i % Ii1I % OoooooooOO
   if 63 - 63: OOooOOo + I1ii11iIi11i . i1IIi . Ii1I - I1ii11iIi11i * o0oOOo0O0Ooo
   if 79 - 79: ooOoO0o - O0
   if 20 - 20: OOooOOo
   if 22 - 22: iIii1I11I1II1 / I1Ii111
   if 6 - 6: iII111i . i11iIiiIii / Oo0Ooo
   if 86 - 86: I11i % I1Ii111 % oO0o - ooOoO0o / i1IIi
   lisp_send ( lisp_sockets , dest , LISP_DATA_PORT , IiiiIi1iiii11 )
   if 68 - 68: i1IIi % O0 % iII111i
   if 55 - 55: I1ii11iIi11i % OOooOOo - o0oOOo0O0Ooo - II111iiii
   if 52 - 52: I1Ii111
   if 34 - 34: II111iiii + iII111i / IiII
   if 47 - 47: OoO0O00
   if 40 - 40: o0oOOo0O0Ooo / iII111i . o0oOOo0O0Ooo
   if 63 - 63: o0oOOo0O0Ooo * iIii1I11I1II1 * II111iiii . OoO0O00 - oO0o / OoOoOO00
 if ( o0Oo ) :
  lisp_install_host_route ( oo0o00OO , None , False )
  if ( O0OoOOo0ooooO != None ) : lisp_install_host_route ( oo0o00OO , O0OoOOo0ooooO , True )
  if 78 - 78: i11iIiiIii / OoO0O00 / i1IIi . i11iIiiIii
 return
 if 100 - 100: II111iiii . IiII . I11i
 if 60 - 60: OoOoOO00 % OOooOOo * i1IIi
 if 3 - 3: OoooooooOO
 if 75 - 75: OoooooooOO * I1Ii111 * o0oOOo0O0Ooo + I1ii11iIi11i . iIii1I11I1II1 / O0
 if 23 - 23: oO0o - O0 * IiII + i11iIiiIii * Ii1I
 if 8 - 8: ooOoO0o / II111iiii . I1ii11iIi11i * ooOoO0o % oO0o
 if 36 - 36: I1ii11iIi11i % OOooOOo - ooOoO0o - I11i + I1IiiI
def lisp_process_info_request ( lisp_sockets , packet , addr_str , sport , rtr_list ) :
 if 37 - 37: I1ii11iIi11i * IiII
 if 65 - 65: OOooOOo / O0 . I1ii11iIi11i % i1IIi % Oo0Ooo
 if 36 - 36: i11iIiiIii - OOooOOo + iII111i + iII111i * I11i * oO0o
 if 14 - 14: O0 - iII111i * I1Ii111 - I1IiiI + IiII
 IiiIiI = lisp_info ( )
 packet = IiiIiI . decode ( packet )
 if ( packet == None ) : return
 IiiIiI . print_info ( )
 if 46 - 46: OoooooooOO * OoO0O00 . I1Ii111
 if 95 - 95: ooOoO0o . I1ii11iIi11i . ooOoO0o / I1IiiI * OoOoOO00 . O0
 if 78 - 78: oO0o
 if 33 - 33: oO0o + i1IIi
 if 32 - 32: iIii1I11I1II1
 IiiIiI . info_reply = True
 IiiIiI . global_etr_rloc . store_address ( addr_str )
 IiiIiI . etr_port = sport
 if 71 - 71: Ii1I * I1IiiI
 if 62 - 62: II111iiii / I1IiiI . I1ii11iIi11i
 if 49 - 49: IiII / OoOoOO00 / O0 * i11iIiiIii
 if 47 - 47: i11iIiiIii + iII111i + i11iIiiIii
 if 66 - 66: o0oOOo0O0Ooo . I1IiiI + OoooooooOO . iII111i / OoooooooOO - IiII
 if ( IiiIiI . hostname != None ) :
  IiiIiI . private_etr_rloc . afi = LISP_AFI_NAME
  IiiIiI . private_etr_rloc . store_address ( IiiIiI . hostname )
  if 47 - 47: o0oOOo0O0Ooo / II111iiii * i11iIiiIii * OoO0O00 . iIii1I11I1II1
  if 34 - 34: I11i / o0oOOo0O0Ooo * OOooOOo * OOooOOo
 if ( rtr_list != None ) : IiiIiI . rtr_list = rtr_list
 packet = IiiIiI . encode ( )
 IiiIiI . print_info ( )
 if 89 - 89: I1ii11iIi11i . OoooooooOO
 if 61 - 61: i1IIi + i11iIiiIii
 if 59 - 59: i11iIiiIii * OOooOOo + i1IIi * iIii1I11I1II1 + I11i
 if 97 - 97: OoO0O00 - I11i . OoooooooOO
 if 58 - 58: I1ii11iIi11i / II111iiii / i11iIiiIii
 lprint ( "Send Info-Reply to {}" . format ( red ( addr_str , False ) ) )
 oo0OoO = lisp_convert_4to6 ( addr_str )
 lisp_send ( lisp_sockets , oo0OoO , sport , packet )
 if 27 - 27: iIii1I11I1II1 - O0 + OoOoOO00
 if 28 - 28: oO0o . IiII * iII111i % Oo0Ooo - OoO0O00 / I11i
 if 67 - 67: i11iIiiIii + i11iIiiIii / ooOoO0o - o0oOOo0O0Ooo
 if 94 - 94: O0 + OoO0O00 / I1IiiI * II111iiii * i11iIiiIii
 if 55 - 55: OoooooooOO * O0 + i1IIi % I1IiiI
 Iii1i1Ii = lisp_info_source ( IiiIiI . hostname , addr_str , sport )
 Iii1i1Ii . cache_address_for_info_source ( )
 return
 if 79 - 79: I1IiiI * O0 . Ii1I
 if 24 - 24: ooOoO0o * OoOoOO00 * iIii1I11I1II1 * iII111i + I1IiiI - II111iiii
 if 31 - 31: oO0o / I1ii11iIi11i
 if 96 - 96: i1IIi + i1IIi * I1Ii111 . II111iiii % OoooooooOO
 if 58 - 58: IiII
 if 64 - 64: iIii1I11I1II1 / OoOoOO00
 if 14 - 14: Ii1I / OoooooooOO . i1IIi % IiII % i11iIiiIii
 if 23 - 23: iIii1I11I1II1 - o0oOOo0O0Ooo - Ii1I % OOooOOo
def lisp_get_signature_eid ( ) :
 for iiIII1 in lisp_db_list :
  if ( iiIII1 . signature_eid ) : return ( iiIII1 )
  if 100 - 100: oO0o . OoO0O00 . i11iIiiIii % II111iiii * IiII
 return ( None )
 if 81 - 81: OOooOOo - OOooOOo + OoOoOO00
 if 19 - 19: o0oOOo0O0Ooo
 if 20 - 20: I1Ii111 + iIii1I11I1II1 % I1IiiI + ooOoO0o
 if 86 - 86: o0oOOo0O0Ooo * i11iIiiIii - I11i
 if 71 - 71: OoO0O00 - I11i
 if 96 - 96: I1Ii111 / Ii1I
 if 65 - 65: I1ii11iIi11i * O0 . IiII
 if 11 - 11: I11i / Ii1I % oO0o
def lisp_get_any_translated_port ( ) :
 for iiIII1 in lisp_db_list :
  for O0OooOoooO0O in iiIII1 . rloc_set :
   if ( O0OooOoooO0O . translated_rloc . is_null ( ) ) : continue
   return ( O0OooOoooO0O . translated_port )
   if 50 - 50: i11iIiiIii
   if 93 - 93: i1IIi / Ii1I * II111iiii - Oo0Ooo . OoOoOO00 - OOooOOo
 return ( None )
 if 25 - 25: I11i / ooOoO0o % ooOoO0o - OOooOOo
 if 59 - 59: I1IiiI + o0oOOo0O0Ooo . iIii1I11I1II1 - O0 - i11iIiiIii
 if 4 - 4: I1IiiI
 if 36 - 36: Ii1I
 if 76 - 76: i11iIiiIii + i1IIi
 if 56 - 56: OoOoOO00 + II111iiii / i11iIiiIii * OoOoOO00 * OoooooooOO
 if 15 - 15: OoOoOO00 / OoooooooOO + OOooOOo
 if 76 - 76: Ii1I * iII111i . OoooooooOO
 if 92 - 92: iIii1I11I1II1 - Oo0Ooo - I1IiiI - OOooOOo * I1Ii111
def lisp_get_any_translated_rloc ( ) :
 for iiIII1 in lisp_db_list :
  for O0OooOoooO0O in iiIII1 . rloc_set :
   if ( O0OooOoooO0O . translated_rloc . is_null ( ) ) : continue
   return ( O0OooOoooO0O . translated_rloc )
   if 44 - 44: I1Ii111 - II111iiii / OOooOOo
   if 50 - 50: I11i / I1ii11iIi11i
 return ( None )
 if 60 - 60: II111iiii / Ii1I + OoO0O00 % I1IiiI * i1IIi / II111iiii
 if 91 - 91: I1IiiI * I1Ii111 * i11iIiiIii - oO0o - IiII + I1ii11iIi11i
 if 99 - 99: OoO0O00 % o0oOOo0O0Ooo
 if 3 - 3: OOooOOo / OoOoOO00 % iIii1I11I1II1
 if 47 - 47: ooOoO0o . i11iIiiIii / OoO0O00
 if 48 - 48: O0
 if 89 - 89: i11iIiiIii % OoO0O00 . OoOoOO00 + Oo0Ooo + OoOoOO00
def lisp_get_all_translated_rlocs ( ) :
 O00O0 = [ ]
 for iiIII1 in lisp_db_list :
  for O0OooOoooO0O in iiIII1 . rloc_set :
   if ( O0OooOoooO0O . is_rloc_translated ( ) == False ) : continue
   IiiIIi1 = O0OooOoooO0O . translated_rloc . print_address_no_iid ( )
   O00O0 . append ( IiiIIi1 )
   if 84 - 84: Oo0Ooo / Oo0Ooo % OOooOOo
   if 45 - 45: OoooooooOO + iII111i * ooOoO0o * Ii1I + I11i + ooOoO0o
 return ( O00O0 )
 if 26 - 26: iII111i + Oo0Ooo
 if 95 - 95: iII111i . oO0o % iIii1I11I1II1 - I1IiiI
 if 38 - 38: ooOoO0o % iIii1I11I1II1 - OOooOOo
 if 13 - 13: OOooOOo . i11iIiiIii
 if 71 - 71: oO0o + I1ii11iIi11i * I1ii11iIi11i
 if 79 - 79: oO0o
 if 47 - 47: OoooooooOO - i1IIi * OOooOOo
 if 11 - 11: I11i / OOooOOo . o0oOOo0O0Ooo - O0 * OoooooooOO % iII111i
def lisp_update_default_routes ( map_resolver , iid , rtr_list ) :
 iii1iIi11 = ( os . getenv ( "LISP_RTR_BEHIND_NAT" ) != None )
 if 7 - 7: OoOoOO00 . IiII + OoooooooOO - I1Ii111 / oO0o
 IiI1I1 = { }
 for I1IIiIIIii in rtr_list :
  if ( I1IIiIIIii == None ) : continue
  IiiIIi1 = rtr_list [ I1IIiIIIii ]
  if ( iii1iIi11 and IiiIIi1 . is_private_address ( ) ) : continue
  IiI1I1 [ I1IIiIIIii ] = IiiIIi1
  if 48 - 48: i11iIiiIii * o0oOOo0O0Ooo
 rtr_list = IiI1I1
 if 8 - 8: iII111i
 iI1II1II1i = [ ]
 for O0ooo0 in [ LISP_AFI_IPV4 , LISP_AFI_IPV6 , LISP_AFI_MAC ] :
  if ( O0ooo0 == LISP_AFI_MAC and lisp_l2_overlay == False ) : break
  if 21 - 21: i1IIi + OoO0O00 . I1IiiI - Oo0Ooo
  if 99 - 99: OoOoOO00
  if 46 - 46: I1ii11iIi11i / II111iiii / OoooooooOO / Ii1I
  if 37 - 37: I1ii11iIi11i - Ii1I / oO0o . I1IiiI % I1Ii111
  if 8 - 8: oO0o
  II11IIi1Ii1i = lisp_address ( O0ooo0 , "" , 0 , iid )
  II11IIi1Ii1i . make_default_route ( II11IIi1Ii1i )
  iiI1iIi1II1ii = lisp_map_cache . lookup_cache ( II11IIi1Ii1i , True )
  if ( iiI1iIi1II1ii ) :
   if ( iiI1iIi1II1ii . checkpoint_entry ) :
    lprint ( "Updating checkpoint entry for {}" . format ( green ( iiI1iIi1II1ii . print_eid_tuple ( ) , False ) ) )
    if 46 - 46: I1Ii111 + IiII + II111iiii . o0oOOo0O0Ooo + i11iIiiIii
   elif ( iiI1iIi1II1ii . do_rloc_sets_match ( rtr_list . values ( ) ) ) :
    continue
    if 97 - 97: o0oOOo0O0Ooo % OoOoOO00 * O0 / iIii1I11I1II1 * OoO0O00 / i11iIiiIii
   iiI1iIi1II1ii . delete_cache ( )
   if 1 - 1: OoooooooOO . Ii1I
   if 68 - 68: Ii1I
  iI1II1II1i . append ( [ II11IIi1Ii1i , "" ] )
  if 98 - 98: iII111i
  if 33 - 33: OoO0O00 - ooOoO0o % O0 % iIii1I11I1II1 * iII111i - iII111i
  if 27 - 27: i11iIiiIii + I1ii11iIi11i + i1IIi
  if 67 - 67: o0oOOo0O0Ooo
  IIi1iiIII11 = lisp_address ( O0ooo0 , "" , 0 , iid )
  IIi1iiIII11 . make_default_multicast_route ( IIi1iiIII11 )
  o0OOooooOo = lisp_map_cache . lookup_cache ( IIi1iiIII11 , True )
  if ( o0OOooooOo ) : o0OOooooOo = o0OOooooOo . source_cache . lookup_cache ( II11IIi1Ii1i , True )
  if ( o0OOooooOo ) : o0OOooooOo . delete_cache ( )
  if 91 - 91: o0oOOo0O0Ooo / OoooooooOO - oO0o - I1ii11iIi11i
  iI1II1II1i . append ( [ II11IIi1Ii1i , IIi1iiIII11 ] )
  if 37 - 37: I1ii11iIi11i % OoOoOO00 * OOooOOo / I11i
 if ( len ( iI1II1II1i ) == 0 ) : return
 if 62 - 62: i11iIiiIii - I1IiiI * OOooOOo
 if 66 - 66: iIii1I11I1II1 + IiII + ooOoO0o
 if 64 - 64: ooOoO0o + Oo0Ooo
 if 27 - 27: i11iIiiIii * I1Ii111 . o0oOOo0O0Ooo - iIii1I11I1II1 % Oo0Ooo % I1IiiI
 o0oo0OoOo000 = [ ]
 for IIiiiIiI1 in rtr_list :
  ooOo0oOOoOO = rtr_list [ IIiiiIiI1 ]
  O0OooOoooO0O = lisp_rloc ( )
  O0OooOoooO0O . rloc . copy_address ( ooOo0oOOoOO )
  O0OooOoooO0O . priority = 254
  O0OooOoooO0O . mpriority = 255
  O0OooOoooO0O . rloc_name = "RTR"
  o0oo0OoOo000 . append ( O0OooOoooO0O )
  if 38 - 38: i1IIi * I1Ii111
  if 92 - 92: iII111i + OoO0O00
 for II11IIi1Ii1i in iI1II1II1i :
  iiI1iIi1II1ii = lisp_mapping ( II11IIi1Ii1i [ 0 ] , II11IIi1Ii1i [ 1 ] , o0oo0OoOo000 )
  iiI1iIi1II1ii . mapping_source = map_resolver
  iiI1iIi1II1ii . map_cache_ttl = LISP_MR_TTL * 60
  iiI1iIi1II1ii . add_cache ( )
  lprint ( "Add {} to map-cache with RTR RLOC-set: {}" . format ( green ( iiI1iIi1II1ii . print_eid_tuple ( ) , False ) , rtr_list . keys ( ) ) )
  if 70 - 70: iIii1I11I1II1
  o0oo0OoOo000 = copy . deepcopy ( o0oo0OoOo000 )
  if 100 - 100: OOooOOo . oO0o % ooOoO0o * ooOoO0o . I1Ii111 - oO0o
 return
 if 33 - 33: Oo0Ooo . i1IIi - OoooooooOO
 if 14 - 14: I1Ii111 + Oo0Ooo
 if 35 - 35: i11iIiiIii * Ii1I
 if 100 - 100: O0 . iII111i / iIii1I11I1II1
 if 47 - 47: ooOoO0o + OoOoOO00
 if 67 - 67: IiII - I1ii11iIi11i * i1IIi - ooOoO0o
 if 91 - 91: I11i
 if 54 - 54: I1ii11iIi11i / i1IIi
 if 14 - 14: iIii1I11I1II1 * I11i . I11i * ooOoO0o * iII111i
 if 60 - 60: iIii1I11I1II1 + i1IIi + oO0o - iIii1I11I1II1 . i11iIiiIii * OoooooooOO
def lisp_process_info_reply ( source , packet , store ) :
 if 23 - 23: iII111i - IiII % i11iIiiIii
 if 81 - 81: OoooooooOO % OoOoOO00 / IiII / OoooooooOO + i1IIi - O0
 if 60 - 60: OOooOOo - I1Ii111 * Oo0Ooo
 if 9 - 9: OoooooooOO * OOooOOo % OoO0O00 - ooOoO0o + Ii1I
 IiiIiI = lisp_info ( )
 packet = IiiIiI . decode ( packet )
 if ( packet == None ) : return ( [ None , None , False ] )
 if 39 - 39: iIii1I11I1II1 / i1IIi % I11i % I1ii11iIi11i * IiII
 IiiIiI . print_info ( )
 if 11 - 11: II111iiii + i1IIi
 if 1 - 1: OOooOOo
 if 23 - 23: i1IIi + OoooooooOO * OOooOOo . Oo0Ooo
 if 83 - 83: OoooooooOO
 OOoOO0o00 = False
 for IIiiiIiI1 in IiiIiI . rtr_list :
  oo0o00OO = IIiiiIiI1 . print_address_no_iid ( )
  if ( lisp_rtr_list . has_key ( oo0o00OO ) ) :
   if ( lisp_register_all_rtrs == False ) : continue
   if ( lisp_rtr_list [ oo0o00OO ] != None ) : continue
   if 77 - 77: I1Ii111 * O0 - IiII
  OOoOO0o00 = True
  lisp_rtr_list [ oo0o00OO ] = IIiiiIiI1
  if 21 - 21: Oo0Ooo % Oo0Ooo % Oo0Ooo
  if 15 - 15: I1IiiI + OoO0O00 . I1IiiI / OoO0O00 . o0oOOo0O0Ooo
  if 72 - 72: IiII + oO0o * o0oOOo0O0Ooo
  if 39 - 39: O0 + iII111i + ooOoO0o / iIii1I11I1II1
  if 91 - 91: Ii1I
 if ( lisp_i_am_itr and OOoOO0o00 ) :
  if ( lisp_iid_to_interface == { } ) :
   lisp_update_default_routes ( source , lisp_default_iid , lisp_rtr_list )
  else :
   for o0OoO0000o in lisp_iid_to_interface . keys ( ) :
    lisp_update_default_routes ( source , int ( o0OoO0000o ) , lisp_rtr_list )
    if 62 - 62: I1Ii111 . iIii1I11I1II1 - Ii1I * I1ii11iIi11i % I11i % i1IIi
    if 72 - 72: oO0o
    if 3 - 3: ooOoO0o - Oo0Ooo / iII111i
    if 40 - 40: IiII + oO0o
    if 95 - 95: I1Ii111 % OOooOOo + Ii1I * i11iIiiIii + i11iIiiIii
    if 27 - 27: i11iIiiIii - iIii1I11I1II1 % I1Ii111
    if 10 - 10: i11iIiiIii - Ii1I - OoooooooOO % II111iiii
 if ( store == False ) :
  return ( [ IiiIiI . global_etr_rloc , IiiIiI . etr_port , OOoOO0o00 ] )
  if 42 - 42: OoOoOO00 + iII111i % Oo0Ooo
  if 25 - 25: IiII % O0 * I11i * OoOoOO00 / OoooooooOO
  if 80 - 80: I1IiiI . oO0o - I1IiiI - OoOoOO00 * ooOoO0o / O0
  if 54 - 54: Oo0Ooo % iIii1I11I1II1 * Oo0Ooo
  if 80 - 80: I1ii11iIi11i - I1ii11iIi11i
  if 26 - 26: I1ii11iIi11i - I1IiiI * I1Ii111 % iIii1I11I1II1
 for iiIII1 in lisp_db_list :
  for O0OooOoooO0O in iiIII1 . rloc_set :
   I1IIiIIIii = O0OooOoooO0O . rloc
   II1i = O0OooOoooO0O . interface
   if ( II1i == None ) :
    if ( I1IIiIIIii . is_null ( ) ) : continue
    if ( I1IIiIIIii . is_local ( ) == False ) : continue
    if ( IiiIiI . private_etr_rloc . is_null ( ) == False and
 I1IIiIIIii . is_exact_match ( IiiIiI . private_etr_rloc ) == False ) :
     continue
     if 77 - 77: o0oOOo0O0Ooo + I1Ii111 . OOooOOo . i1IIi . I1IiiI
   elif ( IiiIiI . private_etr_rloc . is_dist_name ( ) ) :
    oo0O0OOooO0 = IiiIiI . private_etr_rloc . address
    if ( oo0O0OOooO0 != O0OooOoooO0O . rloc_name ) : continue
    if 100 - 100: ooOoO0o . i11iIiiIii + Ii1I - OOooOOo - i11iIiiIii - OoooooooOO
    if 42 - 42: OoOoOO00 . I1IiiI / OoOoOO00 / I1ii11iIi11i . OoO0O00
   I11i11i1 = green ( iiIII1 . eid . print_prefix ( ) , False )
   o0oooOoOoOo = red ( I1IIiIIIii . print_address_no_iid ( ) , False )
   if 67 - 67: Ii1I - O0 . OoooooooOO . I1Ii111 . o0oOOo0O0Ooo
   O0oOO0OO = IiiIiI . global_etr_rloc . is_exact_match ( I1IIiIIIii )
   if ( O0OooOoooO0O . translated_port == 0 and O0oOO0OO ) :
    lprint ( "No NAT for {} ({}), EID-prefix {}" . format ( o0oooOoOoOo ,
 II1i , I11i11i1 ) )
    continue
    if 76 - 76: IiII
    if 88 - 88: o0oOOo0O0Ooo * II111iiii % Oo0Ooo * I1ii11iIi11i . I1IiiI % I1ii11iIi11i
    if 37 - 37: OOooOOo % OoO0O00 % oO0o . I11i / OOooOOo
    if 8 - 8: iIii1I11I1II1 + O0 + IiII - IiII * I1Ii111 / i1IIi
    if 10 - 10: Oo0Ooo . i11iIiiIii + iIii1I11I1II1 % iII111i + i11iIiiIii
   iII1II1 = IiiIiI . global_etr_rloc
   O0IIOoo0O = O0OooOoooO0O . translated_rloc
   if ( O0IIOoo0O . is_exact_match ( iII1II1 ) and
 IiiIiI . etr_port == O0OooOoooO0O . translated_port ) : continue
   if 18 - 18: oO0o * IiII % oO0o
   lprint ( "Store translation {}:{} for {} ({}), EID-prefix {}" . format ( red ( IiiIiI . global_etr_rloc . print_address_no_iid ( ) , False ) ,
   # iII111i
 IiiIiI . etr_port , o0oooOoOoOo , II1i , I11i11i1 ) )
   if 95 - 95: iII111i % OoooooooOO - II111iiii
   O0OooOoooO0O . store_translated_rloc ( IiiIiI . global_etr_rloc ,
 IiiIiI . etr_port )
   if 75 - 75: oO0o / OOooOOo + iIii1I11I1II1 + i1IIi * I1Ii111
   if 36 - 36: II111iiii / OoooooooOO % o0oOOo0O0Ooo * O0
 return ( [ IiiIiI . global_etr_rloc , IiiIiI . etr_port , OOoOO0o00 ] )
 if 49 - 49: I11i / OoO0O00 % IiII
 if 62 - 62: oO0o % oO0o / o0oOOo0O0Ooo + I1IiiI + OOooOOo
 if 45 - 45: O0 . OoO0O00 % OOooOOo + iIii1I11I1II1 * iII111i % OoO0O00
 if 62 - 62: I1Ii111 - ooOoO0o + iIii1I11I1II1 % OOooOOo + Oo0Ooo
 if 59 - 59: I1IiiI * II111iiii . i1IIi - i1IIi
 if 23 - 23: oO0o * OoO0O00 % O0 . OoOoOO00 * Oo0Ooo
 if 69 - 69: OoOoOO00 % I1ii11iIi11i % II111iiii * oO0o
 if 100 - 100: i11iIiiIii . IiII - I1IiiI + I1Ii111
def lisp_test_mr ( lisp_sockets , port ) :
 return
 lprint ( "Test Map-Resolvers" )
 if 29 - 29: Oo0Ooo . I1IiiI % ooOoO0o * I1ii11iIi11i . iII111i
 ooOOoo0 = lisp_address ( LISP_AFI_IPV4 , "" , 0 , 0 )
 iI1i1iIi1 = lisp_address ( LISP_AFI_IPV6 , "" , 0 , 0 )
 if 89 - 89: O0 - OoO0O00
 if 8 - 8: I1ii11iIi11i / oO0o - OoooooooOO + ooOoO0o + o0oOOo0O0Ooo % i11iIiiIii
 if 32 - 32: O0 + IiII
 if 93 - 93: OoOoOO00 - I11i / iII111i - iIii1I11I1II1 + I11i % oO0o
 ooOOoo0 . store_address ( "10.0.0.1" )
 lisp_send_map_request ( lisp_sockets , port , None , ooOOoo0 , None )
 ooOOoo0 . store_address ( "192.168.0.1" )
 lisp_send_map_request ( lisp_sockets , port , None , ooOOoo0 , None )
 if 24 - 24: Ii1I / iIii1I11I1II1 + o0oOOo0O0Ooo
 if 17 - 17: OOooOOo
 if 75 - 75: Ii1I / i1IIi % I1ii11iIi11i . Ii1I
 if 46 - 46: II111iiii * OoO0O00
 iI1i1iIi1 . store_address ( "0100::1" )
 lisp_send_map_request ( lisp_sockets , port , None , iI1i1iIi1 , None )
 iI1i1iIi1 . store_address ( "8000::1" )
 lisp_send_map_request ( lisp_sockets , port , None , iI1i1iIi1 , None )
 if 77 - 77: ooOoO0o * I11i
 if 85 - 85: OoO0O00 * I1Ii111 - OoooooooOO / iIii1I11I1II1 - i1IIi + Ii1I
 if 76 - 76: iII111i * OoooooooOO
 if 49 - 49: II111iiii - OOooOOo + II111iiii + OoOoOO00
 oOO00OoOoo = threading . Timer ( LISP_TEST_MR_INTERVAL , lisp_test_mr ,
 [ lisp_sockets , port ] )
 oOO00OoOoo . start ( )
 return
 if 62 - 62: I1ii11iIi11i - I1IiiI * i11iIiiIii % oO0o
 if 63 - 63: II111iiii - Oo0Ooo
 if 55 - 55: iIii1I11I1II1 / O0 * O0 * i11iIiiIii * OoooooooOO
 if 94 - 94: II111iiii . II111iiii / OoOoOO00 % oO0o * i1IIi % Oo0Ooo
 if 78 - 78: IiII - I1IiiI
 if 59 - 59: oO0o + i1IIi - IiII % OOooOOo % iIii1I11I1II1
 if 71 - 71: OoO0O00
 if 72 - 72: II111iiii + o0oOOo0O0Ooo / i1IIi * Oo0Ooo / i1IIi
 if 52 - 52: I1Ii111 % OoO0O00 . I1Ii111 * I1ii11iIi11i * OoOoOO00 + i1IIi
 if 54 - 54: Ii1I / I1IiiI
 if 7 - 7: iIii1I11I1II1 . O0 + OOooOOo . Ii1I * Oo0Ooo
 if 25 - 25: I1Ii111 . Oo0Ooo % II111iiii . IiII - O0
 if 18 - 18: oO0o * OOooOOo
def lisp_update_local_rloc ( rloc ) :
 if ( rloc . interface == None ) : return
 if 19 - 19: iIii1I11I1II1 / I1ii11iIi11i - I1ii11iIi11i / iIii1I11I1II1
 IiiIIi1 = lisp_get_interface_address ( rloc . interface )
 if ( IiiIIi1 == None ) : return
 if 42 - 42: iIii1I11I1II1 / OOooOOo - O0 * OoooooooOO / i1IIi
 I11Oo0o0O = rloc . rloc . print_address_no_iid ( )
 O0OOOo000 = IiiIIi1 . print_address_no_iid ( )
 if 82 - 82: I11i / I1ii11iIi11i
 if ( I11Oo0o0O == O0OOOo000 ) : return
 if 79 - 79: oO0o
 lprint ( "Local interface address changed on {} from {} to {}" . format ( rloc . interface , I11Oo0o0O , O0OOOo000 ) )
 if 6 - 6: IiII . o0oOOo0O0Ooo
 if 11 - 11: IiII - OoooooooOO + I1IiiI / I11i % i1IIi
 rloc . rloc . copy_address ( IiiIIi1 )
 lisp_myrlocs [ 0 ] = IiiIIi1
 return
 if 1 - 1: Ii1I - II111iiii
 if 1 - 1: Oo0Ooo * OoOoOO00 . oO0o + I1ii11iIi11i
 if 14 - 14: OoooooooOO
 if 73 - 73: OoOoOO00 % o0oOOo0O0Ooo
 if 28 - 28: OoO0O00
 if 15 - 15: OoO0O00 . I11i
 if 64 - 64: OOooOOo + I1Ii111 - o0oOOo0O0Ooo . II111iiii * Ii1I
 if 88 - 88: I1ii11iIi11i + OoooooooOO % I1ii11iIi11i
def lisp_update_encap_port ( mc ) :
 for I1IIiIIIii in mc . rloc_set :
  iI1I1iI = lisp_get_nat_info ( I1IIiIIIii . rloc , I1IIiIIIii . rloc_name )
  if ( iI1I1iI == None ) : continue
  if ( I1IIiIIIii . translated_port == iI1I1iI . port ) : continue
  if 3 - 3: I1Ii111 . O0 * OOooOOo * I11i + Ii1I * I1IiiI
  lprint ( ( "Encap-port changed from {} to {} for RLOC {}, " + "EID-prefix {}" ) . format ( I1IIiIIIii . translated_port , iI1I1iI . port ,
  # Ii1I % iIii1I11I1II1
 red ( I1IIiIIIii . rloc . print_address_no_iid ( ) , False ) ,
 green ( mc . print_eid_tuple ( ) , False ) ) )
  if 6 - 6: o0oOOo0O0Ooo * iII111i % oO0o * iIii1I11I1II1 / I11i * I1IiiI
  I1IIiIIIii . store_translated_rloc ( I1IIiIIIii . rloc , iI1I1iI . port )
  if 53 - 53: I11i - i11iIiiIii * OoOoOO00
 return
 if 6 - 6: I1IiiI - iIii1I11I1II1 * OoOoOO00 % OoO0O00 . OoO0O00
 if 31 - 31: ooOoO0o - oO0o . OOooOOo + ooOoO0o
 if 81 - 81: II111iiii * I1Ii111 * IiII
 if 100 - 100: o0oOOo0O0Ooo + ooOoO0o - IiII / I11i * OoooooooOO + iIii1I11I1II1
 if 50 - 50: o0oOOo0O0Ooo - OOooOOo * IiII % Oo0Ooo
 if 81 - 81: OoooooooOO - OoOoOO00 % I1ii11iIi11i % I1ii11iIi11i + OoOoOO00
 if 49 - 49: Ii1I + iIii1I11I1II1 . O0 * OOooOOo * OoooooooOO - OOooOOo
 if 23 - 23: iIii1I11I1II1 % I11i . OoO0O00 / i11iIiiIii % O0 * Ii1I
 if 49 - 49: I1ii11iIi11i . i1IIi + OoO0O00 % O0 + OoO0O00
 if 21 - 21: ooOoO0o * oO0o / OoooooooOO % ooOoO0o / O0
 if 24 - 24: OoO0O00 - i11iIiiIii / i11iIiiIii * I1Ii111
 if 20 - 20: IiII % iIii1I11I1II1 . iII111i + iIii1I11I1II1 + O0
def lisp_timeout_map_cache_entry ( mc , delete_list ) :
 if ( mc . map_cache_ttl == None ) :
  lisp_update_encap_port ( mc )
  return ( [ True , delete_list ] )
  if 96 - 96: I1ii11iIi11i - IiII % OoooooooOO . iII111i
  if 30 - 30: Oo0Ooo . OoooooooOO / Oo0Ooo / oO0o
 Oo0oooo00 = lisp_get_timestamp ( )
 if 44 - 44: I1ii11iIi11i % o0oOOo0O0Ooo / iIii1I11I1II1 - o0oOOo0O0Ooo / I11i * I1Ii111
 if 49 - 49: iII111i / iII111i - OoOoOO00
 if 89 - 89: ooOoO0o
 if 16 - 16: oO0o + oO0o + i1IIi + iIii1I11I1II1
 if 93 - 93: I1IiiI - i11iIiiIii * I1Ii111 - O0 + iII111i
 if 11 - 11: iII111i
 if ( mc . last_refresh_time + mc . map_cache_ttl > Oo0oooo00 ) :
  if ( mc . action == LISP_NO_ACTION ) : lisp_update_encap_port ( mc )
  return ( [ True , delete_list ] )
  if 100 - 100: OoooooooOO / ooOoO0o . OoO0O00
  if 89 - 89: I11i % II111iiii
  if 35 - 35: oO0o
  if 65 - 65: II111iiii
  if 87 - 87: oO0o / OoO0O00 - oO0o
 if ( lisp_nat_traversal and mc . eid . address == 0 and mc . eid . mask_len == 0 ) :
  return ( [ True , delete_list ] )
  if 69 - 69: i11iIiiIii
  if 29 - 29: IiII . ooOoO0o / iII111i - OOooOOo / OOooOOo % Oo0Ooo
  if 42 - 42: OoO0O00 . I1Ii111 . I1IiiI + Oo0Ooo * O0
  if 35 - 35: Oo0Ooo / iII111i - O0 - OOooOOo * Oo0Ooo . i11iIiiIii
  if 43 - 43: OoOoOO00 % oO0o % OoO0O00 / Ii1I . I11i
 oO000o0Oo00 = lisp_print_elapsed ( mc . last_refresh_time )
 II1OO0Oo0oOOO000 = mc . print_eid_tuple ( )
 lprint ( "Map-cache entry for EID-prefix {} has {}, had uptime of {}" . format ( green ( II1OO0Oo0oOOO000 , False ) , bold ( "timed out" , False ) , oO000o0Oo00 ) )
 if 86 - 86: I1Ii111 * i1IIi + IiII - OoOoOO00
 if 14 - 14: I1ii11iIi11i / i11iIiiIii * I11i % o0oOOo0O0Ooo + IiII / I1ii11iIi11i
 if 82 - 82: OOooOOo . oO0o
 if 12 - 12: i11iIiiIii + II111iiii
 if 49 - 49: OoooooooOO
 delete_list . append ( mc )
 return ( [ True , delete_list ] )
 if 48 - 48: i1IIi . IiII - O0 + OoooooooOO
 if 6 - 6: I1Ii111 * OOooOOo + o0oOOo0O0Ooo . I1ii11iIi11i * I1Ii111
 if 6 - 6: oO0o / II111iiii
 if 23 - 23: IiII - OoooooooOO / oO0o
 if 69 - 69: O0 - OoooooooOO
 if 31 - 31: o0oOOo0O0Ooo . i1IIi - i1IIi % i1IIi - iIii1I11I1II1
 if 50 - 50: IiII - OOooOOo % OoOoOO00
 if 66 - 66: IiII * i11iIiiIii
def lisp_timeout_map_cache_walk ( mc , parms ) :
 oOO0 = parms [ 0 ]
 Oo0O0 = parms [ 1 ]
 if 56 - 56: o0oOOo0O0Ooo + ooOoO0o + OoooooooOO
 if 64 - 64: OOooOOo / OoOoOO00
 if 30 - 30: OOooOOo % I1Ii111 - i11iIiiIii
 if 20 - 20: i1IIi * I11i / OoO0O00 / i1IIi / I1Ii111 * O0
 if ( mc . group . is_null ( ) ) :
  iIii1IiiiII , oOO0 = lisp_timeout_map_cache_entry ( mc , oOO0 )
  if ( oOO0 == [ ] or mc != oOO0 [ - 1 ] ) :
   Oo0O0 = lisp_write_checkpoint_entry ( Oo0O0 , mc )
   if 95 - 95: Ii1I + Ii1I % IiII - IiII / OOooOOo
  return ( [ iIii1IiiiII , parms ] )
  if 46 - 46: IiII + iII111i + II111iiii . iII111i - i11iIiiIii % OoO0O00
  if 24 - 24: oO0o + IiII . o0oOOo0O0Ooo . OoooooooOO . i11iIiiIii / I1ii11iIi11i
 if ( mc . source_cache == None ) : return ( [ True , parms ] )
 if 49 - 49: IiII
 if 1 - 1: oO0o / I11i
 if 99 - 99: OoO0O00 % IiII + I1Ii111 - oO0o
 if 28 - 28: OOooOOo - O0 - O0 % i11iIiiIii * OoooooooOO
 if 60 - 60: OoooooooOO / i1IIi / i1IIi / Ii1I . IiII
 parms = mc . source_cache . walk_cache ( lisp_timeout_map_cache_entry , parms )
 return ( [ True , parms ] )
 if 24 - 24: O0
 if 6 - 6: I1IiiI . i11iIiiIii . OoooooooOO . I1IiiI . o0oOOo0O0Ooo
 if 65 - 65: i11iIiiIii
 if 46 - 46: i11iIiiIii
 if 70 - 70: i1IIi + o0oOOo0O0Ooo
 if 44 - 44: iII111i . II111iiii % o0oOOo0O0Ooo
 if 29 - 29: i11iIiiIii * i1IIi
def lisp_timeout_map_cache ( lisp_map_cache ) :
 I1I1i = [ [ ] , [ ] ]
 I1I1i = lisp_map_cache . walk_cache ( lisp_timeout_map_cache_walk , I1I1i )
 if 36 - 36: OoO0O00 * I11i . ooOoO0o
 if 50 - 50: oO0o * OoOoOO00 / OoO0O00 / ooOoO0o + II111iiii
 if 55 - 55: II111iiii - IiII
 if 24 - 24: oO0o % Ii1I / i1IIi
 if 84 - 84: i1IIi
 oOO0 = I1I1i [ 0 ]
 for iiI1iIi1II1ii in oOO0 : iiI1iIi1II1ii . delete_cache ( )
 if 53 - 53: OoooooooOO - i1IIi - Ii1I
 if 73 - 73: I1ii11iIi11i - Ii1I * o0oOOo0O0Ooo
 if 29 - 29: o0oOOo0O0Ooo % IiII % OOooOOo + OoooooooOO - o0oOOo0O0Ooo
 if 34 - 34: Ii1I
 Oo0O0 = I1I1i [ 1 ]
 lisp_checkpoint ( Oo0O0 )
 return
 if 5 - 5: II111iiii . I1ii11iIi11i
 if 85 - 85: I1Ii111 . IiII + II111iiii
 if 92 - 92: iII111i / o0oOOo0O0Ooo * oO0o . I11i % o0oOOo0O0Ooo
 if 87 - 87: Ii1I / Oo0Ooo % iIii1I11I1II1 / iII111i
 if 42 - 42: OoO0O00 . I1IiiI . OOooOOo + ooOoO0o
 if 87 - 87: OOooOOo
 if 44 - 44: Oo0Ooo + iIii1I11I1II1
 if 67 - 67: iII111i . OOooOOo / ooOoO0o * iIii1I11I1II1
 if 29 - 29: I1Ii111 / OoOoOO00 % I1ii11iIi11i * IiII / II111iiii
 if 10 - 10: O0 / I11i
 if 29 - 29: i11iIiiIii % I11i
 if 49 - 49: I11i
 if 69 - 69: o0oOOo0O0Ooo . O0 * I11i
 if 92 - 92: OoO0O00 . O0 / Ii1I % Oo0Ooo . Ii1I
 if 40 - 40: o0oOOo0O0Ooo - Ii1I . iII111i - O0
 if 53 - 53: Oo0Ooo - I1IiiI * O0 . II111iiii
def lisp_store_nat_info ( hostname , rloc , port ) :
 oo0o00OO = rloc . print_address_no_iid ( )
 O0o0o0o0O = "{} NAT state for {}, RLOC {}, port {}" . format ( "{}" ,
 blue ( hostname , False ) , red ( oo0o00OO , False ) , port )
 if 16 - 16: iIii1I11I1II1 / OoO0O00 . IiII + IiII / I1ii11iIi11i
 i1I1IiI = lisp_nat_info ( oo0o00OO , hostname , port )
 if 83 - 83: I1ii11iIi11i + iIii1I11I1II1 + O0 % o0oOOo0O0Ooo
 if ( lisp_nat_state_info . has_key ( hostname ) == False ) :
  lisp_nat_state_info [ hostname ] = [ i1I1IiI ]
  lprint ( O0o0o0o0O . format ( "Store initial" ) )
  return ( True )
  if 91 - 91: o0oOOo0O0Ooo / I11i . OoO0O00 . oO0o / iII111i
  if 27 - 27: Ii1I % i1IIi + iII111i
  if 75 - 75: OoO0O00
  if 34 - 34: Oo0Ooo - OOooOOo . OOooOOo . oO0o
  if 18 - 18: iII111i . I1IiiI . ooOoO0o * oO0o / OoooooooOO
  if 85 - 85: i1IIi
 iI1I1iI = lisp_nat_state_info [ hostname ] [ 0 ]
 if ( iI1I1iI . address == oo0o00OO and iI1I1iI . port == port ) :
  iI1I1iI . uptime = lisp_get_timestamp ( )
  lprint ( O0o0o0o0O . format ( "Refresh existing" ) )
  return ( False )
  if 79 - 79: I11i - I11i
  if 25 - 25: OOooOOo / O0 / iIii1I11I1II1 + II111iiii * Ii1I
  if 74 - 74: i1IIi . I1Ii111 / O0 + Oo0Ooo * OOooOOo
  if 90 - 90: I1IiiI * II111iiii . Oo0Ooo % I1IiiI
  if 100 - 100: iIii1I11I1II1 - OoooooooOO * OoooooooOO - iII111i / ooOoO0o
  if 98 - 98: OoO0O00 + oO0o - II111iiii
  if 84 - 84: Oo0Ooo . OoOoOO00 - iII111i
 IiiiI11111ii = None
 for iI1I1iI in lisp_nat_state_info [ hostname ] :
  if ( iI1I1iI . address == oo0o00OO and iI1I1iI . port == port ) :
   IiiiI11111ii = iI1I1iI
   break
   if 37 - 37: Oo0Ooo * oO0o
   if 10 - 10: OoOoOO00 * I1ii11iIi11i * I1Ii111 - Ii1I . oO0o
   if 58 - 58: OoooooooOO . O0
 if ( IiiiI11111ii == None ) :
  lprint ( O0o0o0o0O . format ( "Store new" ) )
 else :
  lisp_nat_state_info [ hostname ] . remove ( IiiiI11111ii )
  lprint ( O0o0o0o0O . format ( "Use previous" ) )
  if 80 - 80: OoOoOO00 - o0oOOo0O0Ooo + OoooooooOO + ooOoO0o * OOooOOo
  if 10 - 10: o0oOOo0O0Ooo + ooOoO0o + Oo0Ooo
 OoOo0 = lisp_nat_state_info [ hostname ]
 lisp_nat_state_info [ hostname ] = [ i1I1IiI ] + OoOo0
 return ( True )
 if 94 - 94: Oo0Ooo
 if 39 - 39: I11i - oO0o % iII111i - ooOoO0o - OoOoOO00
 if 8 - 8: i1IIi % i1IIi % OoooooooOO % i1IIi . iIii1I11I1II1
 if 70 - 70: O0 + II111iiii % IiII / I1Ii111 - IiII
 if 58 - 58: II111iiii * oO0o - i1IIi . I11i
 if 23 - 23: OoO0O00 - I1IiiI * i11iIiiIii
 if 62 - 62: OoO0O00 . i11iIiiIii / i1IIi
 if 3 - 3: OoO0O00 + O0 % Oo0Ooo * Oo0Ooo % i11iIiiIii
def lisp_get_nat_info ( rloc , hostname ) :
 if ( lisp_nat_state_info . has_key ( hostname ) == False ) : return ( None )
 if 29 - 29: ooOoO0o / iII111i / OOooOOo - iIii1I11I1II1
 oo0o00OO = rloc . print_address_no_iid ( )
 for iI1I1iI in lisp_nat_state_info [ hostname ] :
  if ( iI1I1iI . address == oo0o00OO ) : return ( iI1I1iI )
  if 31 - 31: i1IIi * Ii1I
 return ( None )
 if 94 - 94: oO0o / Ii1I % iIii1I11I1II1 + i1IIi / O0 - iII111i
 if 77 - 77: o0oOOo0O0Ooo - IiII . i1IIi
 if 70 - 70: i1IIi . I1Ii111 . iII111i - OoOoOO00 + II111iiii + OOooOOo
 if 52 - 52: OOooOOo . OoOoOO00 - ooOoO0o % i1IIi
 if 15 - 15: oO0o
 if 6 - 6: oO0o . iIii1I11I1II1 - I1ii11iIi11i % IiII
 if 58 - 58: iII111i * oO0o / iII111i - Oo0Ooo / I1Ii111 * oO0o
 if 63 - 63: oO0o . IiII . o0oOOo0O0Ooo
 if 16 - 16: iII111i . I11i - Oo0Ooo / I1IiiI + OoOoOO00
 if 14 - 14: iIii1I11I1II1 / i11iIiiIii - o0oOOo0O0Ooo . iII111i * OoO0O00
 if 5 - 5: Ii1I + OoOoOO00 % I11i + IiII
 if 55 - 55: OoooooooOO + oO0o . o0oOOo0O0Ooo % iIii1I11I1II1 - I1Ii111
 if 40 - 40: I1IiiI . o0oOOo0O0Ooo - Oo0Ooo
 if 44 - 44: Ii1I % OoO0O00 * oO0o * OoO0O00
 if 7 - 7: I1Ii111 % i1IIi . I11i . O0 / i1IIi
 if 56 - 56: Oo0Ooo
 if 21 - 21: i11iIiiIii * o0oOOo0O0Ooo + Oo0Ooo
 if 20 - 20: IiII / OoooooooOO / O0 / I1Ii111 * ooOoO0o
 if 45 - 45: ooOoO0o / Oo0Ooo % o0oOOo0O0Ooo . ooOoO0o
 if 19 - 19: o0oOOo0O0Ooo % I11i . I1ii11iIi11i
def lisp_build_info_requests ( lisp_sockets , dest , port ) :
 if ( lisp_nat_traversal == False ) : return
 if 70 - 70: Oo0Ooo - I11i / I1ii11iIi11i % OoO0O00 % II111iiii
 if 72 - 72: i11iIiiIii * I11i
 if 69 - 69: I1Ii111 . Ii1I * I1ii11iIi11i % I11i - o0oOOo0O0Ooo
 if 30 - 30: ooOoO0o / Oo0Ooo * iII111i % OoooooooOO / I1ii11iIi11i
 if 64 - 64: OoooooooOO
 if 41 - 41: Ii1I . I11i / oO0o * OoooooooOO
 oOOoo0oO = [ ]
 iI1i1i11Ii1 = [ ]
 if ( dest == None ) :
  for OoOooo0o in lisp_map_resolvers_list . values ( ) :
   iI1i1i11Ii1 . append ( OoOooo0o . map_resolver )
   if 80 - 80: IiII
  oOOoo0oO = iI1i1i11Ii1
  if ( oOOoo0oO == [ ] ) :
   for ii1i in lisp_map_servers_list . values ( ) :
    oOOoo0oO . append ( ii1i . map_server )
    if 62 - 62: IiII - I1Ii111 % iII111i / oO0o
    if 27 - 27: o0oOOo0O0Ooo + iIii1I11I1II1 + OoooooooOO - iII111i
  if ( oOOoo0oO == [ ] ) : return
 else :
  oOOoo0oO . append ( dest )
  if 80 - 80: Ii1I . iII111i * I1IiiI * Ii1I
  if 82 - 82: OoO0O00 % OoOoOO00 * i11iIiiIii . OoO0O00 . I1ii11iIi11i + Ii1I
  if 60 - 60: i1IIi / iII111i
  if 10 - 10: I1Ii111 / OoOoOO00 * Ii1I % o0oOOo0O0Ooo . OoOoOO00 / I1ii11iIi11i
  if 2 - 2: iIii1I11I1II1
 O00O0 = { }
 for iiIII1 in lisp_db_list :
  for O0OooOoooO0O in iiIII1 . rloc_set :
   lisp_update_local_rloc ( O0OooOoooO0O )
   if ( O0OooOoooO0O . rloc . is_null ( ) ) : continue
   if ( O0OooOoooO0O . interface == None ) : continue
   if 85 - 85: O0 - ooOoO0o
   IiiIIi1 = O0OooOoooO0O . rloc . print_address_no_iid ( )
   if ( IiiIIi1 in O00O0 ) : continue
   O00O0 [ IiiIIi1 ] = O0OooOoooO0O . interface
   if 35 - 35: o0oOOo0O0Ooo - I1IiiI
   if 47 - 47: i11iIiiIii * iII111i . OoOoOO00 * I1Ii111 % i11iIiiIii + Ii1I
 if ( O00O0 == { } ) :
  lprint ( 'Suppress Info-Request, no "interface = <device>" RLOC ' + "found in any database-mappings" )
  if 65 - 65: Ii1I % i11iIiiIii
  return
  if 98 - 98: iII111i * o0oOOo0O0Ooo % Oo0Ooo
  if 7 - 7: oO0o * OoooooooOO % o0oOOo0O0Ooo . I1Ii111 + O0
  if 14 - 14: I11i * II111iiii % o0oOOo0O0Ooo / iII111i . OoooooooOO % iII111i
  if 88 - 88: iII111i
  if 94 - 94: OoooooooOO
  if 32 - 32: I1ii11iIi11i
 for IiiIIi1 in O00O0 :
  II1i = O00O0 [ IiiIIi1 ]
  OO0o = red ( IiiIIi1 , False )
  lprint ( "Build Info-Request for private address {} ({})" . format ( OO0o ,
 II1i ) )
  OoO0o0OOOO = II1i if len ( O00O0 ) > 1 else None
  for dest in oOOoo0oO :
   lisp_send_info_request ( lisp_sockets , dest , port , OoO0o0OOOO )
   if 8 - 8: I11i * i11iIiiIii - ooOoO0o
   if 47 - 47: ooOoO0o . I1IiiI / i11iIiiIii * iII111i * I1IiiI
   if 8 - 8: oO0o % oO0o . iII111i / i1IIi % IiII
   if 71 - 71: OoOoOO00 + oO0o % O0 + Oo0Ooo
   if 62 - 62: i1IIi . Ii1I * i1IIi * O0 . I1IiiI % o0oOOo0O0Ooo
   if 16 - 16: I11i . Ii1I - ooOoO0o . OOooOOo % O0 / oO0o
 if ( iI1i1i11Ii1 != [ ] ) :
  for OoOooo0o in lisp_map_resolvers_list . values ( ) :
   OoOooo0o . resolve_dns_name ( )
   if 42 - 42: II111iiii . iII111i
   if 67 - 67: i1IIi - i11iIiiIii / ooOoO0o * oO0o
 return
 if 64 - 64: oO0o / IiII
 if 86 - 86: I11i
 if 36 - 36: o0oOOo0O0Ooo / OoO0O00
 if 6 - 6: I11i % I1IiiI + iII111i * OoooooooOO . O0
 if 87 - 87: ooOoO0o / Ii1I % O0 . OoO0O00
 if 55 - 55: i1IIi . o0oOOo0O0Ooo % OoooooooOO + II111iiii . OoOoOO00
 if 32 - 32: IiII * I1Ii111 * Oo0Ooo . i1IIi * OoooooooOO
 if 12 - 12: I1IiiI . OOooOOo % Oo0Ooo
def lisp_valid_address_format ( kw , value ) :
 if ( kw != "address" ) : return ( True )
 if 86 - 86: i11iIiiIii
 if 57 - 57: iII111i - OoooooooOO - ooOoO0o % II111iiii
 if 62 - 62: i11iIiiIii . Oo0Ooo / Oo0Ooo . IiII . OoooooooOO
 if 86 - 86: I1ii11iIi11i * OoOoOO00 + iII111i
 if 79 - 79: I11i - II111iiii
 if ( value [ 0 ] == "'" and value [ - 1 ] == "'" ) : return ( True )
 if 27 - 27: I1IiiI + o0oOOo0O0Ooo * oO0o % I1IiiI
 if 66 - 66: OoO0O00 + IiII . o0oOOo0O0Ooo . IiII
 if 88 - 88: oO0o + oO0o % OoO0O00 . OoooooooOO - OoooooooOO . Oo0Ooo
 if 44 - 44: I1IiiI * IiII . OoooooooOO
 if ( value . find ( "." ) != - 1 ) :
  IiiIIi1 = value . split ( "." )
  if ( len ( IiiIIi1 ) != 4 ) : return ( False )
  if 62 - 62: I11i - Ii1I / i11iIiiIii * I1IiiI + ooOoO0o + o0oOOo0O0Ooo
  for iiII11 in IiiIIi1 :
   if ( iiII11 . isdigit ( ) == False ) : return ( False )
   if ( int ( iiII11 ) > 255 ) : return ( False )
   if 69 - 69: iIii1I11I1II1 * o0oOOo0O0Ooo * II111iiii + OoooooooOO . Ii1I
  return ( True )
  if 99 - 99: Ii1I % iIii1I11I1II1 . I1Ii111 / iIii1I11I1II1 / oO0o
  if 76 - 76: I1Ii111
  if 27 - 27: I1ii11iIi11i
  if 72 - 72: OoooooooOO - IiII
  if 8 - 8: i11iIiiIii + I11i . II111iiii . O0
 if ( value . find ( "-" ) != - 1 ) :
  IiiIIi1 = value . split ( "-" )
  for IiIIi1IiiIiI in [ "N" , "S" , "W" , "E" ] :
   if ( IiIIi1IiiIiI in IiiIIi1 ) :
    if ( len ( IiiIIi1 ) < 8 ) : return ( False )
    return ( True )
    if 21 - 21: i1IIi * Oo0Ooo / iII111i . iIii1I11I1II1 % OOooOOo % i1IIi
    if 8 - 8: OoO0O00 % OoO0O00 * i1IIi / Oo0Ooo * i1IIi . i11iIiiIii
    if 10 - 10: O0 . Ii1I . i1IIi
    if 44 - 44: OoooooooOO % I1Ii111 / Oo0Ooo . Ii1I
    if 36 - 36: iII111i
    if 67 - 67: I1Ii111 / iII111i / iII111i . IiII
    if 17 - 17: ooOoO0o . I1ii11iIi11i % OoOoOO00 . I1ii11iIi11i . OoooooooOO % OoOoOO00
 if ( value . find ( "-" ) != - 1 ) :
  IiiIIi1 = value . split ( "-" )
  if ( len ( IiiIIi1 ) != 3 ) : return ( False )
  if 65 - 65: I1IiiI + I1IiiI + OoO0O00 - iIii1I11I1II1 + O0
  for I1ii1Ii111 in IiiIIi1 :
   try : int ( I1ii1Ii111 , 16 )
   except : return ( False )
   if 90 - 90: oO0o * I1Ii111 / O0
  return ( True )
  if 15 - 15: o0oOOo0O0Ooo * O0 . OOooOOo / Oo0Ooo
  if 28 - 28: OoooooooOO + OoooooooOO
  if 27 - 27: I11i . oO0o / OoooooooOO - OoO0O00 . I11i
  if 15 - 15: II111iiii * OoO0O00
  if 33 - 33: OoooooooOO . o0oOOo0O0Ooo . I1IiiI / I1ii11iIi11i . OoOoOO00
 if ( value . find ( ":" ) != - 1 ) :
  IiiIIi1 = value . split ( ":" )
  if ( len ( IiiIIi1 ) < 2 ) : return ( False )
  if 58 - 58: Ii1I
  i1Iii111i = False
  I1I1 = 0
  for I1ii1Ii111 in IiiIIi1 :
   I1I1 += 1
   if ( I1ii1Ii111 == "" ) :
    if ( i1Iii111i ) :
     if ( len ( IiiIIi1 ) == I1I1 ) : break
     if ( I1I1 > 2 ) : return ( False )
     if 81 - 81: I11i . O0 * Ii1I - O0 + o0oOOo0O0Ooo * IiII
    i1Iii111i = True
    continue
    if 70 - 70: iIii1I11I1II1 . i1IIi / OOooOOo . oO0o / i11iIiiIii + II111iiii
   try : int ( I1ii1Ii111 , 16 )
   except : return ( False )
   if 89 - 89: I11i * O0 * Oo0Ooo % i1IIi
  return ( True )
  if 41 - 41: OOooOOo + ooOoO0o - OoOoOO00 . iIii1I11I1II1
  if 73 - 73: I1ii11iIi11i / OoooooooOO + II111iiii * Oo0Ooo * I1ii11iIi11i / OoO0O00
  if 49 - 49: OOooOOo % Oo0Ooo % OoOoOO00 - OoooooooOO % iII111i - O0
  if 62 - 62: iIii1I11I1II1
  if 14 - 14: I1Ii111
 if ( value [ 0 ] == "+" ) :
  IiiIIi1 = value [ 1 : : ]
  for oo0OO in IiiIIi1 :
   if ( oo0OO . isdigit ( ) == False ) : return ( False )
   if 81 - 81: i11iIiiIii / iIii1I11I1II1
  return ( True )
  if 73 - 73: i11iIiiIii . I1ii11iIi11i * OoOoOO00
 return ( False )
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
 if 75 - 75: O0 * OOooOOo / ooOoO0o + I11i
 if 56 - 56: I1IiiI % OoooooooOO % Oo0Ooo
def lisp_process_api ( process , lisp_socket , data_structure ) :
 Iiiiiii11 , I1I1i = data_structure . split ( "%" )
 if 33 - 33: o0oOOo0O0Ooo + oO0o . o0oOOo0O0Ooo . I11i * OoooooooOO + iIii1I11I1II1
 lprint ( "Process API request '{}', parameters: '{}'" . format ( Iiiiiii11 ,
 I1I1i ) )
 if 64 - 64: OoooooooOO . Ii1I
 i1I = [ ]
 if ( Iiiiiii11 == "map-cache" ) :
  if ( I1I1i == "" ) :
   i1I = lisp_map_cache . walk_cache ( lisp_process_api_map_cache , i1I )
  else :
   i1I = lisp_process_api_map_cache_entry ( json . loads ( I1I1i ) )
   if 38 - 38: Oo0Ooo
   if 64 - 64: ooOoO0o % i11iIiiIii
 if ( Iiiiiii11 == "site-cache" ) :
  if ( I1I1i == "" ) :
   i1I = lisp_sites_by_eid . walk_cache ( lisp_process_api_site_cache ,
 i1I )
  else :
   i1I = lisp_process_api_site_cache_entry ( json . loads ( I1I1i ) )
   if 10 - 10: Ii1I % oO0o + oO0o * OoOoOO00 % iII111i / o0oOOo0O0Ooo
   if 17 - 17: iII111i / I1IiiI . II111iiii - OoO0O00 + iII111i
 if ( Iiiiiii11 == "map-server" ) :
  I1I1i = { } if ( I1I1i == "" ) else json . loads ( I1I1i )
  i1I = lisp_process_api_ms_or_mr ( True , I1I1i )
  if 22 - 22: Oo0Ooo - I1ii11iIi11i + I11i . oO0o
 if ( Iiiiiii11 == "map-resolver" ) :
  I1I1i = { } if ( I1I1i == "" ) else json . loads ( I1I1i )
  i1I = lisp_process_api_ms_or_mr ( False , I1I1i )
  if 85 - 85: iIii1I11I1II1 / Ii1I
 if ( Iiiiiii11 == "database-mapping" ) :
  i1I = lisp_process_api_database_mapping ( )
  if 43 - 43: I1IiiI % I1Ii111 - oO0o . II111iiii / iIii1I11I1II1
  if 97 - 97: I1Ii111 + I1ii11iIi11i
  if 21 - 21: O0 + o0oOOo0O0Ooo * OoooooooOO % IiII % I1ii11iIi11i
  if 80 - 80: I11i
  if 28 - 28: OoOoOO00 * OoooooooOO * i11iIiiIii
 i1I = json . dumps ( i1I )
 iiiii1i1 = lisp_api_ipc ( process , i1I )
 lisp_ipc ( iiiii1i1 , lisp_socket , "lisp-core" )
 return
 if 88 - 88: ooOoO0o + ooOoO0o / I1Ii111
 if 69 - 69: O0 * o0oOOo0O0Ooo + i1IIi * ooOoO0o . o0oOOo0O0Ooo
 if 46 - 46: Oo0Ooo / Oo0Ooo * IiII
 if 65 - 65: iIii1I11I1II1 * o0oOOo0O0Ooo - iII111i % II111iiii - I1ii11iIi11i
 if 65 - 65: I11i
 if 92 - 92: iII111i . IiII + i1IIi % i1IIi
 if 11 - 11: I1ii11iIi11i + iIii1I11I1II1 - I1Ii111 * iIii1I11I1II1 * IiII + oO0o
def lisp_process_api_map_cache ( mc , data ) :
 if 6 - 6: I1Ii111 * OOooOOo + i1IIi - Ii1I / oO0o
 if 81 - 81: I1Ii111 % oO0o * i1IIi * OoooooooOO / Oo0Ooo
 if 70 - 70: I1IiiI
 if 35 - 35: i11iIiiIii
 if ( mc . group . is_null ( ) ) : return ( lisp_gather_map_cache_data ( mc , data ) )
 if 59 - 59: ooOoO0o . iII111i - II111iiii
 if ( mc . source_cache == None ) : return ( [ True , data ] )
 if 30 - 30: o0oOOo0O0Ooo % iII111i - i11iIiiIii
 if 25 - 25: i11iIiiIii + OoOoOO00 + oO0o / Ii1I * Oo0Ooo + Oo0Ooo
 if 26 - 26: I1IiiI % I1ii11iIi11i + o0oOOo0O0Ooo / I1ii11iIi11i - I1IiiI
 if 55 - 55: OoooooooOO
 if 2 - 2: Oo0Ooo + I11i / OOooOOo + OOooOOo
 data = mc . source_cache . walk_cache ( lisp_gather_map_cache_data , data )
 return ( [ True , data ] )
 if 62 - 62: OOooOOo . iIii1I11I1II1 + I1IiiI / OOooOOo
 if 90 - 90: OOooOOo
 if 29 - 29: OoOoOO00 - I1IiiI / oO0o + Oo0Ooo + I1Ii111 + O0
 if 65 - 65: oO0o
 if 38 - 38: iIii1I11I1II1 / I1Ii111 + ooOoO0o . II111iiii - iIii1I11I1II1
 if 13 - 13: Ii1I
 if 34 - 34: I1IiiI / iIii1I11I1II1
def lisp_gather_map_cache_data ( mc , data ) :
 i1ii1i1Ii11 = { }
 i1ii1i1Ii11 [ "instance-id" ] = str ( mc . eid . instance_id )
 i1ii1i1Ii11 [ "eid-prefix" ] = mc . eid . print_prefix_no_iid ( )
 if ( mc . group . is_null ( ) == False ) :
  i1ii1i1Ii11 [ "group-prefix" ] = mc . group . print_prefix_no_iid ( )
  if 35 - 35: oO0o / oO0o
 i1ii1i1Ii11 [ "uptime" ] = lisp_print_elapsed ( mc . uptime )
 i1ii1i1Ii11 [ "expires" ] = lisp_print_elapsed ( mc . uptime )
 i1ii1i1Ii11 [ "action" ] = lisp_map_reply_action_string [ mc . action ]
 i1ii1i1Ii11 [ "ttl" ] = "--" if mc . map_cache_ttl == None else str ( mc . map_cache_ttl / 60 )
 if 86 - 86: o0oOOo0O0Ooo . Oo0Ooo - Ii1I / i11iIiiIii
 if 63 - 63: oO0o - O0 + I1ii11iIi11i + Ii1I / i1IIi
 if 77 - 77: O0
 if 49 - 49: o0oOOo0O0Ooo / i11iIiiIii
 if 36 - 36: II111iiii
 o0oo0OoOo000 = [ ]
 for I1IIiIIIii in mc . rloc_set :
  O0OOOO0o0O = lisp_fill_rloc_in_json ( I1IIiIIIii )
  if 78 - 78: OoO0O00 + iIii1I11I1II1 * i1IIi
  if 7 - 7: i11iIiiIii
  if 49 - 49: I1IiiI - oO0o % OOooOOo / O0 / II111iiii
  if 41 - 41: IiII % II111iiii
  if 99 - 99: IiII - O0
  if ( I1IIiIIIii . rloc . is_multicast_address ( ) ) :
   O0OOOO0o0O [ "multicast-rloc-set" ] = [ ]
   for OOO00 in I1IIiIIIii . multicast_rloc_probe_list . values ( ) :
    OoOooo0o = lisp_fill_rloc_in_json ( OOO00 )
    O0OOOO0o0O [ "multicast-rloc-set" ] . append ( OoOooo0o )
    if 59 - 59: iII111i % O0 + OOooOOo * ooOoO0o
    if 27 - 27: I1Ii111 % i11iIiiIii * I1IiiI
    if 19 - 19: OoOoOO00 / o0oOOo0O0Ooo - iII111i / OoO0O00
  o0oo0OoOo000 . append ( O0OOOO0o0O )
  if 12 - 12: I1ii11iIi11i - I11i * O0 % I1IiiI + O0 - II111iiii
 i1ii1i1Ii11 [ "rloc-set" ] = o0oo0OoOo000
 if 13 - 13: iII111i / OOooOOo * i11iIiiIii / oO0o / OoooooooOO
 data . append ( i1ii1i1Ii11 )
 return ( [ True , data ] )
 if 89 - 89: Ii1I * Oo0Ooo / I1Ii111 * I1ii11iIi11i + O0 * Oo0Ooo
 if 74 - 74: I11i . I11i
 if 74 - 74: OoOoOO00 * ooOoO0o * I1Ii111
 if 56 - 56: iIii1I11I1II1 * OoO0O00 - oO0o * Ii1I
 if 62 - 62: i1IIi + I11i / OOooOOo - OoooooooOO % i1IIi . I1IiiI
 if 13 - 13: O0 * iII111i
 if 26 - 26: i1IIi - I1Ii111 - ooOoO0o
 if 73 - 73: o0oOOo0O0Ooo . OoooooooOO
def lisp_fill_rloc_in_json ( rloc ) :
 O0OOOO0o0O = { }
 if ( rloc . rloc_exists ( ) ) :
  O0OOOO0o0O [ "address" ] = rloc . rloc . print_address_no_iid ( )
  if 96 - 96: i1IIi - OOooOOo / I11i % OoOoOO00 - i11iIiiIii % II111iiii
  if 47 - 47: I1Ii111 * iII111i
 if ( rloc . translated_port != 0 ) :
  O0OOOO0o0O [ "encap-port" ] = str ( rloc . translated_port )
  if 90 - 90: i1IIi * Ii1I . OoO0O00 % I11i * ooOoO0o . OOooOOo
 O0OOOO0o0O [ "state" ] = rloc . print_state ( )
 if ( rloc . geo ) : O0OOOO0o0O [ "geo" ] = rloc . geo . print_geo ( )
 if ( rloc . elp ) : O0OOOO0o0O [ "elp" ] = rloc . elp . print_elp ( False )
 if ( rloc . rle ) : O0OOOO0o0O [ "rle" ] = rloc . rle . print_rle ( False , False )
 if ( rloc . json ) : O0OOOO0o0O [ "json" ] = rloc . json . print_json ( False )
 if ( rloc . rloc_name ) : O0OOOO0o0O [ "rloc-name" ] = rloc . rloc_name
 OOoO0 = rloc . stats . get_stats ( False , False )
 if ( OOoO0 ) : O0OOOO0o0O [ "stats" ] = OOoO0
 O0OOOO0o0O [ "uptime" ] = lisp_print_elapsed ( rloc . uptime )
 O0OOOO0o0O [ "upriority" ] = str ( rloc . priority )
 O0OOOO0o0O [ "uweight" ] = str ( rloc . weight )
 O0OOOO0o0O [ "mpriority" ] = str ( rloc . mpriority )
 O0OOOO0o0O [ "mweight" ] = str ( rloc . mweight )
 Oo0I1Iii = rloc . last_rloc_probe_reply
 if ( Oo0I1Iii ) :
  O0OOOO0o0O [ "last-rloc-probe-reply" ] = lisp_print_elapsed ( Oo0I1Iii )
  O0OOOO0o0O [ "rloc-probe-rtt" ] = str ( rloc . rloc_probe_rtt )
  if 52 - 52: I1Ii111
 O0OOOO0o0O [ "rloc-hop-count" ] = rloc . rloc_probe_hops
 O0OOOO0o0O [ "recent-rloc-hop-counts" ] = rloc . recent_rloc_probe_hops
 if 82 - 82: iII111i + II111iiii
 O0OOOO0o0O [ "rloc-probe-latency" ] = rloc . rloc_probe_latency
 O0OOOO0o0O [ "recent-rloc-probe-latencies" ] = rloc . recent_rloc_probe_latencies
 if 29 - 29: O0 % Ii1I * ooOoO0o % O0
 o000O0ooo = [ ]
 for i1I1111i in rloc . recent_rloc_probe_rtts : o000O0ooo . append ( str ( i1I1111i ) )
 O0OOOO0o0O [ "recent-rloc-probe-rtts" ] = o000O0ooo
 return ( O0OOOO0o0O )
 if 34 - 34: iII111i - i1IIi / I11i . Ii1I - I11i / iII111i
 if 25 - 25: ooOoO0o + OoO0O00 % iII111i % I1ii11iIi11i . I1ii11iIi11i % OoO0O00
 if 90 - 90: OOooOOo
 if 91 - 91: OoooooooOO % I11i - OOooOOo
 if 88 - 88: Ii1I / i11iIiiIii
 if 89 - 89: ooOoO0o
 if 83 - 83: I11i . I11i * OOooOOo - OOooOOo
def lisp_process_api_map_cache_entry ( parms ) :
 o0OoO0000o = parms [ "instance-id" ]
 o0OoO0000o = 0 if ( o0OoO0000o == "" ) else int ( o0OoO0000o )
 if 46 - 46: iIii1I11I1II1 . I1Ii111 % I1IiiI
 if 22 - 22: i1IIi * I11i + II111iiii + II111iiii
 if 20 - 20: I11i
 if 37 - 37: I1Ii111
 ooOOoo0 = lisp_address ( LISP_AFI_NONE , "" , 0 , o0OoO0000o )
 ooOOoo0 . store_prefix ( parms [ "eid-prefix" ] )
 oo0OoO = ooOOoo0
 i1IIi1ii1i1ii = ooOOoo0
 if 19 - 19: I1ii11iIi11i / OOooOOo . I1IiiI / ooOoO0o + OoO0O00 + i11iIiiIii
 if 80 - 80: OoO0O00 . O0 / Ii1I % I1Ii111 / iII111i * I1IiiI
 if 41 - 41: O0 / OoooooooOO - i1IIi
 if 6 - 6: i1IIi - I1ii11iIi11i % I1Ii111 - II111iiii / ooOoO0o / i11iIiiIii
 if 32 - 32: oO0o / IiII - I11i . ooOoO0o
 IIi1iiIII11 = lisp_address ( LISP_AFI_NONE , "" , 0 , o0OoO0000o )
 if ( parms . has_key ( "group-prefix" ) ) :
  IIi1iiIII11 . store_prefix ( parms [ "group-prefix" ] )
  oo0OoO = IIi1iiIII11
  if 69 - 69: i11iIiiIii * i11iIiiIii
  if 100 - 100: I1ii11iIi11i * I1ii11iIi11i + i1IIi
 i1I = [ ]
 iiI1iIi1II1ii = lisp_map_cache_lookup ( i1IIi1ii1i1ii , oo0OoO )
 if ( iiI1iIi1II1ii ) : iIii1IiiiII , i1I = lisp_process_api_map_cache ( iiI1iIi1II1ii , i1I )
 return ( i1I )
 if 96 - 96: I1Ii111 / I1IiiI + ooOoO0o
 if 16 - 16: I1ii11iIi11i % o0oOOo0O0Ooo % OOooOOo % OoOoOO00 + ooOoO0o % I1ii11iIi11i
 if 85 - 85: oO0o * OoooooooOO * iIii1I11I1II1 + iII111i
 if 67 - 67: Ii1I / i11iIiiIii % OoOoOO00 % O0 / OoOoOO00
 if 54 - 54: I11i . OoOoOO00 / II111iiii . i1IIi + OOooOOo % II111iiii
 if 82 - 82: i11iIiiIii . OoooooooOO % OoOoOO00 * O0 - I1Ii111
 if 78 - 78: OoOoOO00 % Ii1I % OOooOOo % Oo0Ooo % I11i . Ii1I
def lisp_process_api_site_cache ( se , data ) :
 if 73 - 73: OoooooooOO / i1IIi . iIii1I11I1II1
 if 89 - 89: I1Ii111
 if 29 - 29: I11i * ooOoO0o - OoooooooOO
 if 92 - 92: O0 % i1IIi / OOooOOo - oO0o
 if ( se . group . is_null ( ) ) : return ( lisp_gather_site_cache_data ( se , data ) )
 if 83 - 83: o0oOOo0O0Ooo . OoO0O00 % iIii1I11I1II1 % OoOoOO00 - i11iIiiIii
 if ( se . source_cache == None ) : return ( [ True , data ] )
 if 71 - 71: I1ii11iIi11i - II111iiii / O0 % i1IIi + oO0o
 if 73 - 73: OoooooooOO
 if 25 - 25: i1IIi . II111iiii . I1Ii111
 if 81 - 81: II111iiii + OoOoOO00 * II111iiii / iIii1I11I1II1 - Oo0Ooo % oO0o
 if 66 - 66: ooOoO0o % O0 + iIii1I11I1II1 * I1Ii111 - I1Ii111
 data = se . source_cache . walk_cache ( lisp_gather_site_cache_data , data )
 return ( [ True , data ] )
 if 61 - 61: I1ii11iIi11i
 if 12 - 12: OoO0O00
 if 97 - 97: OOooOOo . Oo0Ooo . oO0o * i1IIi
 if 7 - 7: Oo0Ooo
 if 38 - 38: Oo0Ooo - I1ii11iIi11i
 if 19 - 19: Ii1I * OoO0O00 / OoO0O00 . II111iiii % iIii1I11I1II1
 if 61 - 61: I1ii11iIi11i * oO0o % iII111i + IiII + i11iIiiIii * I11i
def lisp_process_api_ms_or_mr ( ms_or_mr , data ) :
 ii1i1II11II1i = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
 o0ooO00 = data [ "dns-name" ] if data . has_key ( "dns-name" ) else None
 if ( data . has_key ( "address" ) ) :
  ii1i1II11II1i . store_address ( data [ "address" ] )
  if 3 - 3: Ii1I
  if 71 - 71: iIii1I11I1II1 . OOooOOo / I11i / i1IIi
 i11II = { }
 if ( ms_or_mr ) :
  for ii1i in lisp_map_servers_list . values ( ) :
   if ( o0ooO00 ) :
    if ( o0ooO00 != ii1i . dns_name ) : continue
   else :
    if ( ii1i1II11II1i . is_exact_match ( ii1i . map_server ) == False ) : continue
    if 69 - 69: i1IIi / iII111i + Ii1I + I11i + IiII
    if 86 - 86: Oo0Ooo
   i11II [ "dns-name" ] = ii1i . dns_name
   i11II [ "address" ] = ii1i . map_server . print_address_no_iid ( )
   i11II [ "ms-name" ] = "" if ii1i . ms_name == None else ii1i . ms_name
   return ( [ i11II ] )
   if 97 - 97: I1IiiI
 else :
  for OoOooo0o in lisp_map_resolvers_list . values ( ) :
   if ( o0ooO00 ) :
    if ( o0ooO00 != OoOooo0o . dns_name ) : continue
   else :
    if ( ii1i1II11II1i . is_exact_match ( OoOooo0o . map_resolver ) == False ) : continue
    if 91 - 91: ooOoO0o / oO0o * OOooOOo . II111iiii - I11i - I11i
    if 5 - 5: O0 + OoooooooOO + i11iIiiIii * Oo0Ooo * OoOoOO00 . oO0o
   i11II [ "dns-name" ] = OoOooo0o . dns_name
   i11II [ "address" ] = OoOooo0o . map_resolver . print_address_no_iid ( )
   i11II [ "mr-name" ] = "" if OoOooo0o . mr_name == None else OoOooo0o . mr_name
   return ( [ i11II ] )
   if 6 - 6: OoO0O00 % Oo0Ooo % I1IiiI % o0oOOo0O0Ooo % O0 % Oo0Ooo
   if 94 - 94: I11i . i1IIi / II111iiii + OOooOOo
 return ( [ ] )
 if 64 - 64: I1IiiI % ooOoO0o
 if 72 - 72: O0 * II111iiii % OoO0O00 - I1IiiI * OOooOOo
 if 80 - 80: OOooOOo * I11i / OOooOOo - oO0o
 if 18 - 18: i1IIi - OOooOOo - o0oOOo0O0Ooo - iIii1I11I1II1
 if 72 - 72: OoooooooOO % I1IiiI . OoO0O00
 if 28 - 28: II111iiii / iIii1I11I1II1 / iII111i - o0oOOo0O0Ooo . I1IiiI / O0
 if 16 - 16: ooOoO0o * oO0o . OoooooooOO
 if 44 - 44: iIii1I11I1II1 * OOooOOo + OoO0O00 - OoooooooOO
def lisp_process_api_database_mapping ( ) :
 i1I = [ ]
 if 13 - 13: Oo0Ooo . I11i . II111iiii
 for iiIII1 in lisp_db_list :
  i1ii1i1Ii11 = { }
  i1ii1i1Ii11 [ "eid-prefix" ] = iiIII1 . eid . print_prefix ( )
  if ( iiIII1 . group . is_null ( ) == False ) :
   i1ii1i1Ii11 [ "group-prefix" ] = iiIII1 . group . print_prefix ( )
   if 6 - 6: OOooOOo . IiII / OoO0O00 * oO0o - I1Ii111 . OoOoOO00
   if 85 - 85: i11iIiiIii + OoOoOO00
  ooOOo = [ ]
  for O0OOOO0o0O in iiIII1 . rloc_set :
   I1IIiIIIii = { }
   if ( O0OOOO0o0O . rloc . is_null ( ) == False ) :
    I1IIiIIIii [ "rloc" ] = O0OOOO0o0O . rloc . print_address_no_iid ( )
    if 4 - 4: OOooOOo . OoO0O00 * II111iiii + OoO0O00 % Oo0Ooo
   if ( O0OOOO0o0O . rloc_name != None ) : I1IIiIIIii [ "rloc-name" ] = O0OOOO0o0O . rloc_name
   if ( O0OOOO0o0O . interface != None ) : I1IIiIIIii [ "interface" ] = O0OOOO0o0O . interface
   o0oooo0oO0O = O0OOOO0o0O . translated_rloc
   if ( o0oooo0oO0O . is_null ( ) == False ) :
    I1IIiIIIii [ "translated-rloc" ] = o0oooo0oO0O . print_address_no_iid ( )
    if 65 - 65: iII111i - O0 * iIii1I11I1II1 + oO0o + i1IIi
   if ( I1IIiIIIii != { } ) : ooOOo . append ( I1IIiIIIii )
   if 87 - 87: IiII % IiII
   if 84 - 84: oO0o . II111iiii
   if 20 - 20: OoO0O00 * IiII
   if 85 - 85: oO0o
   if 14 - 14: IiII / iIii1I11I1II1 . OoooooooOO
  i1ii1i1Ii11 [ "rlocs" ] = ooOOo
  if 14 - 14: IiII * OoooooooOO - iIii1I11I1II1
  if 11 - 11: I1IiiI + Oo0Ooo % I1Ii111 * Ii1I - iIii1I11I1II1 % I1ii11iIi11i
  if 43 - 43: o0oOOo0O0Ooo * o0oOOo0O0Ooo . iII111i / Oo0Ooo - i11iIiiIii
  if 66 - 66: I1IiiI / i1IIi + o0oOOo0O0Ooo % IiII - OoOoOO00 / Oo0Ooo
  i1I . append ( i1ii1i1Ii11 )
  if 22 - 22: oO0o % I1Ii111 - I1Ii111 / I1Ii111
 return ( i1I )
 if 25 - 25: OoooooooOO / oO0o / ooOoO0o / I1IiiI * I1ii11iIi11i . o0oOOo0O0Ooo
 if 30 - 30: o0oOOo0O0Ooo / i11iIiiIii
 if 33 - 33: OOooOOo % OoooooooOO
 if 98 - 98: Ii1I
 if 38 - 38: ooOoO0o - iII111i * OOooOOo % I1ii11iIi11i + Oo0Ooo
 if 95 - 95: iIii1I11I1II1 / O0 % O0
 if 53 - 53: ooOoO0o . ooOoO0o
def lisp_gather_site_cache_data ( se , data ) :
 i1ii1i1Ii11 = { }
 i1ii1i1Ii11 [ "site-name" ] = se . site . site_name
 i1ii1i1Ii11 [ "instance-id" ] = str ( se . eid . instance_id )
 i1ii1i1Ii11 [ "eid-prefix" ] = se . eid . print_prefix_no_iid ( )
 if ( se . group . is_null ( ) == False ) :
  i1ii1i1Ii11 [ "group-prefix" ] = se . group . print_prefix_no_iid ( )
  if 80 - 80: i11iIiiIii % I1Ii111 % I1IiiI / I1IiiI + oO0o + iII111i
 i1ii1i1Ii11 [ "registered" ] = "yes" if se . registered else "no"
 i1ii1i1Ii11 [ "first-registered" ] = lisp_print_elapsed ( se . first_registered )
 i1ii1i1Ii11 [ "last-registered" ] = lisp_print_elapsed ( se . last_registered )
 if 18 - 18: OoO0O00 * ooOoO0o
 IiiIIi1 = se . last_registerer
 IiiIIi1 = "none" if IiiIIi1 . is_null ( ) else IiiIIi1 . print_address ( )
 i1ii1i1Ii11 [ "last-registerer" ] = IiiIIi1
 i1ii1i1Ii11 [ "ams" ] = "yes" if ( se . accept_more_specifics ) else "no"
 i1ii1i1Ii11 [ "dynamic" ] = "yes" if ( se . dynamic ) else "no"
 i1ii1i1Ii11 [ "site-id" ] = str ( se . site_id )
 if ( se . xtr_id_present ) :
  i1ii1i1Ii11 [ "xtr-id" ] = "0x" + lisp_hex_string ( se . xtr_id )
  if 32 - 32: oO0o . OoooooooOO - o0oOOo0O0Ooo + II111iiii
  if 4 - 4: OOooOOo * I1IiiI - I11i - I11i
  if 67 - 67: I1IiiI
  if 32 - 32: oO0o * i11iIiiIii - I11i % Oo0Ooo * I1ii11iIi11i
  if 79 - 79: II111iiii / Oo0Ooo / I1ii11iIi11i
 o0oo0OoOo000 = [ ]
 for I1IIiIIIii in se . registered_rlocs :
  O0OOOO0o0O = { }
  O0OOOO0o0O [ "address" ] = I1IIiIIIii . rloc . print_address_no_iid ( ) if I1IIiIIIii . rloc_exists ( ) else "none"
  if 30 - 30: I11i . o0oOOo0O0Ooo / II111iiii
  if 59 - 59: i11iIiiIii
  if ( I1IIiIIIii . geo ) : O0OOOO0o0O [ "geo" ] = I1IIiIIIii . geo . print_geo ( )
  if ( I1IIiIIIii . elp ) : O0OOOO0o0O [ "elp" ] = I1IIiIIIii . elp . print_elp ( False )
  if ( I1IIiIIIii . rle ) : O0OOOO0o0O [ "rle" ] = I1IIiIIIii . rle . print_rle ( False , True )
  if ( I1IIiIIIii . json ) : O0OOOO0o0O [ "json" ] = I1IIiIIIii . json . print_json ( False )
  if ( I1IIiIIIii . rloc_name ) : O0OOOO0o0O [ "rloc-name" ] = I1IIiIIIii . rloc_name
  O0OOOO0o0O [ "uptime" ] = lisp_print_elapsed ( I1IIiIIIii . uptime )
  O0OOOO0o0O [ "upriority" ] = str ( I1IIiIIIii . priority )
  O0OOOO0o0O [ "uweight" ] = str ( I1IIiIIIii . weight )
  O0OOOO0o0O [ "mpriority" ] = str ( I1IIiIIIii . mpriority )
  O0OOOO0o0O [ "mweight" ] = str ( I1IIiIIIii . mweight )
  if 5 - 5: i11iIiiIii + o0oOOo0O0Ooo . OoO0O00 % OoOoOO00 + I11i
  o0oo0OoOo000 . append ( O0OOOO0o0O )
  if 59 - 59: I1ii11iIi11i
 i1ii1i1Ii11 [ "registered-rlocs" ] = o0oo0OoOo000
 if 47 - 47: I1IiiI + Oo0Ooo
 data . append ( i1ii1i1Ii11 )
 return ( [ True , data ] )
 if 78 - 78: i1IIi / I1ii11iIi11i % ooOoO0o * OoO0O00
 if 10 - 10: i1IIi % ooOoO0o / iII111i
 if 98 - 98: IiII / o0oOOo0O0Ooo - i1IIi - OOooOOo
 if 65 - 65: Ii1I + OoOoOO00 * Oo0Ooo . O0 . IiII
 if 33 - 33: i11iIiiIii . i1IIi . I1Ii111 - OoOoOO00 + OOooOOo
 if 34 - 34: I1ii11iIi11i . i1IIi * O0 / OoooooooOO
 if 22 - 22: OOooOOo % o0oOOo0O0Ooo - i11iIiiIii
def lisp_process_api_site_cache_entry ( parms ) :
 o0OoO0000o = parms [ "instance-id" ]
 o0OoO0000o = 0 if ( o0OoO0000o == "" ) else int ( o0OoO0000o )
 if 58 - 58: IiII . Ii1I + II111iiii
 if 31 - 31: i11iIiiIii + i11iIiiIii + I11i * Oo0Ooo . I11i
 if 28 - 28: OOooOOo * iIii1I11I1II1 * OoOoOO00
 if 75 - 75: Oo0Ooo % IiII + II111iiii + oO0o
 ooOOoo0 = lisp_address ( LISP_AFI_NONE , "" , 0 , o0OoO0000o )
 ooOOoo0 . store_prefix ( parms [ "eid-prefix" ] )
 if 35 - 35: I1ii11iIi11i - oO0o - O0 / iII111i % IiII
 if 10 - 10: OOooOOo + oO0o - I1Ii111 . I1IiiI
 if 11 - 11: I1ii11iIi11i . I1Ii111 / o0oOOo0O0Ooo + IiII
 if 73 - 73: OoO0O00 . i11iIiiIii * OoO0O00 * i1IIi + I11i
 if 27 - 27: i11iIiiIii / OoOoOO00 % O0 / II111iiii . I11i - ooOoO0o
 IIi1iiIII11 = lisp_address ( LISP_AFI_NONE , "" , 0 , o0OoO0000o )
 if ( parms . has_key ( "group-prefix" ) ) :
  IIi1iiIII11 . store_prefix ( parms [ "group-prefix" ] )
  if 54 - 54: oO0o * II111iiii
  if 79 - 79: o0oOOo0O0Ooo . ooOoO0o . Oo0Ooo * OoooooooOO
 i1I = [ ]
 iIiIi1I = lisp_site_eid_lookup ( ooOOoo0 , IIi1iiIII11 , False )
 if ( iIiIi1I ) : lisp_gather_site_cache_data ( iIiIi1I , i1I )
 return ( i1I )
 if 98 - 98: ooOoO0o
 if 73 - 73: I1Ii111
 if 97 - 97: OoO0O00 * Ii1I + Oo0Ooo
 if 83 - 83: II111iiii - Oo0Ooo % II111iiii * o0oOOo0O0Ooo
 if 51 - 51: iII111i * iIii1I11I1II1 % Ii1I * Ii1I + i11iIiiIii . OoooooooOO
 if 54 - 54: i11iIiiIii . iIii1I11I1II1 * iIii1I11I1II1 + Ii1I % I11i - OoO0O00
 if 16 - 16: IiII % iIii1I11I1II1 * i11iIiiIii + O0
def lisp_get_interface_instance_id ( device , source_eid ) :
 II1i = None
 if ( lisp_myinterfaces . has_key ( device ) ) :
  II1i = lisp_myinterfaces [ device ]
  if 76 - 76: iII111i * OOooOOo
  if 7 - 7: ooOoO0o + o0oOOo0O0Ooo + o0oOOo0O0Ooo
  if 73 - 73: IiII % I11i % i11iIiiIii + ooOoO0o
  if 83 - 83: Ii1I * I1Ii111 * i11iIiiIii / iIii1I11I1II1 % I1ii11iIi11i
  if 40 - 40: iII111i
  if 21 - 21: I1Ii111 / iII111i + Oo0Ooo / I1ii11iIi11i / I1Ii111
 if ( II1i == None or II1i . instance_id == None ) :
  return ( lisp_default_iid )
  if 33 - 33: OoooooooOO
  if 59 - 59: i11iIiiIii - OoooooooOO . ooOoO0o / i11iIiiIii % iIii1I11I1II1 * I1ii11iIi11i
  if 45 - 45: I1ii11iIi11i * I1ii11iIi11i
  if 31 - 31: OoO0O00 - OOooOOo . iII111i * I1Ii111 * iII111i + I1ii11iIi11i
  if 5 - 5: Oo0Ooo . I1Ii111
  if 77 - 77: i11iIiiIii / I1Ii111 / I1ii11iIi11i % oO0o
  if 83 - 83: Ii1I % iIii1I11I1II1 / I1ii11iIi11i + I11i
  if 23 - 23: iIii1I11I1II1 - I1IiiI
  if 51 - 51: OoooooooOO / IiII / I1ii11iIi11i . Oo0Ooo - o0oOOo0O0Ooo * OoooooooOO
 o0OoO0000o = II1i . get_instance_id ( )
 if ( source_eid == None ) : return ( o0OoO0000o )
 if 40 - 40: OoO0O00 / IiII . O0 / I1IiiI + OoO0O00 . o0oOOo0O0Ooo
 i111IIii1IiII = source_eid . instance_id
 IiI1II = None
 for II1i in lisp_multi_tenant_interfaces :
  if ( II1i . device != device ) : continue
  II11IIi1Ii1i = II1i . multi_tenant_eid
  source_eid . instance_id = II11IIi1Ii1i . instance_id
  if ( source_eid . is_more_specific ( II11IIi1Ii1i ) == False ) : continue
  if ( IiI1II == None or IiI1II . multi_tenant_eid . mask_len < II11IIi1Ii1i . mask_len ) :
   IiI1II = II1i
   if 20 - 20: I1Ii111 . I1ii11iIi11i
   if 53 - 53: iII111i
 source_eid . instance_id = i111IIii1IiII
 if 46 - 46: o0oOOo0O0Ooo
 if ( IiI1II == None ) : return ( o0OoO0000o )
 return ( IiI1II . get_instance_id ( ) )
 if 44 - 44: i11iIiiIii + i11iIiiIii + Oo0Ooo . I11i
 if 79 - 79: OoOoOO00 . iII111i
 if 86 - 86: ooOoO0o
 if 32 - 32: iII111i % OoooooooOO
 if 11 - 11: I1Ii111 / I1ii11iIi11i
 if 50 - 50: OoooooooOO . I11i . i11iIiiIii - OoO0O00
 if 87 - 87: Ii1I - iII111i / O0 - o0oOOo0O0Ooo - iIii1I11I1II1 % Ii1I
 if 47 - 47: iII111i * I1Ii111 % o0oOOo0O0Ooo / OoOoOO00 / OoO0O00 % OoO0O00
 if 43 - 43: Oo0Ooo
def lisp_allow_dynamic_eid ( device , eid ) :
 if ( lisp_myinterfaces . has_key ( device ) == False ) : return ( None )
 if 34 - 34: OoO0O00 . i1IIi + IiII * IiII
 II1i = lisp_myinterfaces [ device ]
 oOO0o0o0O = device if II1i . dynamic_eid_device == None else II1i . dynamic_eid_device
 if 3 - 3: i11iIiiIii - o0oOOo0O0Ooo
 if 40 - 40: OOooOOo * Ii1I
 if ( II1i . does_dynamic_eid_match ( eid ) ) : return ( oOO0o0o0O )
 return ( None )
 if 38 - 38: ooOoO0o
 if 5 - 5: OoooooooOO + iII111i - I11i
 if 95 - 95: OOooOOo / i11iIiiIii - Ii1I + I1ii11iIi11i
 if 7 - 7: I1ii11iIi11i
 if 37 - 37: O0 . II111iiii
 if 70 - 70: o0oOOo0O0Ooo / iII111i + i1IIi + I11i % iIii1I11I1II1 % Oo0Ooo
 if 1 - 1: O0 + OoO0O00 . i11iIiiIii + I1Ii111 - OoO0O00 - IiII
def lisp_start_rloc_probe_timer ( interval , lisp_sockets ) :
 global lisp_rloc_probe_timer
 if 1 - 1: I1ii11iIi11i / i1IIi . I1IiiI / Ii1I
 if ( lisp_rloc_probe_timer != None ) : lisp_rloc_probe_timer . cancel ( )
 if 19 - 19: iIii1I11I1II1 / Oo0Ooo . O0 - Oo0Ooo
 oOoo0O0OO00O0 = lisp_process_rloc_probe_timer
 iiI1I = threading . Timer ( interval , oOoo0O0OO00O0 , [ lisp_sockets ] )
 lisp_rloc_probe_timer = iiI1I
 iiI1I . start ( )
 return
 if 6 - 6: Oo0Ooo - II111iiii - iII111i . ooOoO0o - iIii1I11I1II1 - O0
 if 69 - 69: I1IiiI % Ii1I - OoooooooOO / iIii1I11I1II1 * OoooooooOO
 if 70 - 70: o0oOOo0O0Ooo % OoooooooOO % I1IiiI . OoOoOO00 * I1IiiI - ooOoO0o
 if 92 - 92: I1IiiI . I11i
 if 66 - 66: I1Ii111 / I11i / OoooooooOO % OoOoOO00 . oO0o * iII111i
 if 34 - 34: I1ii11iIi11i * I1ii11iIi11i % I11i / OOooOOo % oO0o . OoOoOO00
 if 25 - 25: I1ii11iIi11i / I11i + i1IIi . I1IiiI + ooOoO0o
def lisp_show_rloc_probe_list ( ) :
 lprint ( bold ( "----- RLOC-probe-list -----" , False ) )
 for Oo000O000 in lisp_rloc_probe_list :
  i1Iii11 = lisp_rloc_probe_list [ Oo000O000 ]
  lprint ( "RLOC {}:" . format ( Oo000O000 ) )
  for O0OOOO0o0O , oOo , i11ii in i1Iii11 :
   lprint ( "  [{}, {}, {}, {}]" . format ( hex ( id ( O0OOOO0o0O ) ) , oOo . print_prefix ( ) ,
 i11ii . print_prefix ( ) , O0OOOO0o0O . translated_port ) )
   if 31 - 31: II111iiii
   if 32 - 32: Ii1I + iIii1I11I1II1
 lprint ( bold ( "---------------------------" , False ) )
 return
 if 49 - 49: I1IiiI
 if 23 - 23: OoooooooOO . OoO0O00 . OoooooooOO * I1ii11iIi11i - Oo0Ooo - iIii1I11I1II1
 if 91 - 91: iIii1I11I1II1 * Ii1I
 if 37 - 37: I1Ii111 + i1IIi * o0oOOo0O0Ooo - i11iIiiIii
 if 92 - 92: I1Ii111 - I1IiiI + Ii1I / iII111i % OOooOOo
 if 32 - 32: i1IIi . iII111i - Ii1I % iII111i % II111iiii - oO0o
 if 36 - 36: OoooooooOO * OoooooooOO . ooOoO0o . O0
 if 5 - 5: I11i % I1IiiI - OoO0O00 . Oo0Ooo
 if 79 - 79: iII111i + IiII % I11i . Oo0Ooo / IiII * iII111i
def lisp_mark_rlocs_for_other_eids ( eid_list ) :
 if 40 - 40: iII111i - I1IiiI + OoOoOO00
 if 2 - 2: I11i - II111iiii / I1Ii111
 if 27 - 27: OoO0O00 - I1ii11iIi11i * i11iIiiIii + Oo0Ooo
 if 29 - 29: I1ii11iIi11i / IiII . I1Ii111 + Ii1I + OoO0O00
 I1IIiIIIii , oOo , i11ii = eid_list [ 0 ]
 o00 = [ lisp_print_eid_tuple ( oOo , i11ii ) ]
 if 72 - 72: oO0o - II111iiii / I1IiiI
 for I1IIiIIIii , oOo , i11ii in eid_list [ 1 : : ] :
  I1IIiIIIii . state = LISP_RLOC_UNREACH_STATE
  I1IIiIIIii . last_state_change = lisp_get_timestamp ( )
  o00 . append ( lisp_print_eid_tuple ( oOo , i11ii ) )
  if 47 - 47: oO0o * I1Ii111 - O0 % iII111i * iIii1I11I1II1 / I1IiiI
  if 72 - 72: ooOoO0o / ooOoO0o * iIii1I11I1II1 . II111iiii * OOooOOo - iIii1I11I1II1
 II1iIIIII = bold ( "unreachable" , False )
 o0oooOoOoOo = red ( I1IIiIIIii . rloc . print_address_no_iid ( ) , False )
 if 74 - 74: ooOoO0o
 for ooOOoo0 in o00 :
  oOo = green ( ooOOoo0 , False )
  lprint ( "RLOC {} went {} for EID {}" . format ( o0oooOoOoOo , II1iIIIII , oOo ) )
  if 7 - 7: Oo0Ooo / ooOoO0o + o0oOOo0O0Ooo
  if 38 - 38: o0oOOo0O0Ooo . O0 - OoO0O00 % I11i
  if 80 - 80: o0oOOo0O0Ooo
  if 100 - 100: iIii1I11I1II1 . OoOoOO00 . OoooooooOO / I1ii11iIi11i - I1IiiI * I11i
  if 5 - 5: i1IIi * o0oOOo0O0Ooo - I1Ii111 + I1IiiI - II111iiii
  if 15 - 15: I1Ii111
 for I1IIiIIIii , oOo , i11ii in eid_list :
  iiI1iIi1II1ii = lisp_map_cache . lookup_cache ( oOo , True )
  if ( iiI1iIi1II1ii ) : lisp_write_ipc_map_cache ( True , iiI1iIi1II1ii )
  if 38 - 38: O0
 return
 if 50 - 50: i11iIiiIii * OoO0O00 + iII111i / O0 * oO0o % ooOoO0o
 if 6 - 6: OoO0O00 . o0oOOo0O0Ooo / Ii1I + Ii1I
 if 59 - 59: II111iiii - o0oOOo0O0Ooo * OoooooooOO
 if 83 - 83: oO0o . iIii1I11I1II1 . iII111i % Oo0Ooo
 if 48 - 48: oO0o % OoO0O00 - OoooooooOO . IiII
 if 11 - 11: I1Ii111 % o0oOOo0O0Ooo - o0oOOo0O0Ooo % OoooooooOO . o0oOOo0O0Ooo - I1ii11iIi11i
 if 33 - 33: OoO0O00 + II111iiii . Oo0Ooo * I1Ii111
 if 63 - 63: OoooooooOO + OoOoOO00 - OoooooooOO
 if 54 - 54: OoO0O00 + I1IiiI % O0 + OoO0O00
 if 37 - 37: II111iiii / I1ii11iIi11i * I1IiiI - OoooooooOO
def lisp_process_rloc_probe_timer ( lisp_sockets ) :
 lisp_set_exception ( )
 if 55 - 55: IiII / ooOoO0o * I1IiiI / I1Ii111 - Oo0Ooo % o0oOOo0O0Ooo
 lisp_start_rloc_probe_timer ( LISP_RLOC_PROBE_INTERVAL , lisp_sockets )
 if ( lisp_rloc_probing == False ) : return
 if 82 - 82: OoO0O00 - iIii1I11I1II1 . Oo0Ooo / IiII . OoO0O00
 if 47 - 47: OOooOOo + IiII
 if 11 - 11: Oo0Ooo + I1IiiI % i11iIiiIii % Oo0Ooo + ooOoO0o + i1IIi
 if 100 - 100: II111iiii - OOooOOo + iII111i - i11iIiiIii . O0 / iII111i
 if ( lisp_print_rloc_probe_list ) : lisp_show_rloc_probe_list ( )
 if 64 - 64: Ii1I
 if 4 - 4: OoOoOO00
 if 78 - 78: i1IIi - iII111i + O0 - I1IiiI % o0oOOo0O0Ooo
 if 48 - 48: iII111i / II111iiii * I1Ii111 + I11i / ooOoO0o . OoOoOO00
 iI11 = lisp_get_default_route_next_hops ( )
 if 9 - 9: o0oOOo0O0Ooo
 lprint ( "---------- Start RLOC Probing for {} entries ----------" . format ( len ( lisp_rloc_probe_list ) ) )
 if 92 - 92: i11iIiiIii + OoooooooOO + O0 % oO0o
 if 90 - 90: Oo0Ooo * i11iIiiIii
 if 95 - 95: I1Ii111 % i11iIiiIii . i11iIiiIii . i11iIiiIii . OoooooooOO - I1Ii111
 if 69 - 69: iIii1I11I1II1 * oO0o
 if 80 - 80: IiII - oO0o % Ii1I - iIii1I11I1II1 . OoO0O00
 I1I1 = 0
 oO0oo000O = bold ( "RLOC-probe" , False )
 for oOooO00Ooo in lisp_rloc_probe_list . values ( ) :
  if 36 - 36: OoooooooOO . oO0o * Ii1I * i11iIiiIii
  if 83 - 83: IiII * i1IIi + I1Ii111 + o0oOOo0O0Ooo * i1IIi * iII111i
  if 5 - 5: iII111i + O0 / IiII + II111iiii . I1IiiI
  if 57 - 57: iII111i - oO0o
  if 90 - 90: oO0o . OOooOOo - OoO0O00
  oOo0O = None
  for o00oooo0ooo , ooOOoo0 , IIi1iiIII11 in oOooO00Ooo :
   oo0o00OO = o00oooo0ooo . rloc . print_address_no_iid ( )
   if 10 - 10: OoOoOO00 - O0 - o0oOOo0O0Ooo - O0 + IiII . o0oOOo0O0Ooo
   if 62 - 62: OoO0O00 . O0
   if 9 - 9: I11i % II111iiii % OOooOOo / I1IiiI
   if 14 - 14: oO0o + iII111i . Oo0Ooo
   iiiiiiIi , OOooOoOoOOO0 , IIIi1i1iIIIi = lisp_allow_gleaning ( ooOOoo0 , None , o00oooo0ooo )
   if ( iiiiiiIi and OOooOoOoOOO0 == False ) :
    oOo = green ( ooOOoo0 . print_address ( ) , False )
    oo0o00OO += ":{}" . format ( o00oooo0ooo . translated_port )
    lprint ( "Suppress probe to RLOC {} for gleaned EID {}" . format ( red ( oo0o00OO , False ) , oOo ) )
    if 65 - 65: I1ii11iIi11i * OOooOOo * ooOoO0o + oO0o - OOooOOo
    continue
    if 100 - 100: iII111i
    if 12 - 12: OoooooooOO - I1ii11iIi11i * iII111i / ooOoO0o
    if 99 - 99: I1ii11iIi11i + I11i
    if 29 - 29: I1ii11iIi11i / oO0o
    if 2 - 2: Oo0Ooo / IiII - OoooooooOO
    if 65 - 65: OoO0O00 - Ii1I
    if 98 - 98: OoOoOO00 * I1Ii111 * iIii1I11I1II1 * OoOoOO00
   if ( o00oooo0ooo . down_state ( ) ) : continue
   if 15 - 15: Oo0Ooo
   if 100 - 100: IiII + I1ii11iIi11i + iII111i . i1IIi . I1ii11iIi11i / OoooooooOO
   if 84 - 84: o0oOOo0O0Ooo * I11i
   if 22 - 22: i1IIi + OOooOOo % OoooooooOO
   if 34 - 34: oO0o / O0 - II111iiii % Oo0Ooo + I11i
   if 23 - 23: o0oOOo0O0Ooo + i11iIiiIii . I1IiiI + iIii1I11I1II1
   if 18 - 18: o0oOOo0O0Ooo . O0 + I1Ii111
   if 66 - 66: OoooooooOO
   if 90 - 90: IiII - OoOoOO00
   if 98 - 98: Oo0Ooo / oO0o . Ii1I
   if 56 - 56: ooOoO0o % OoO0O00 * i11iIiiIii % IiII % I1IiiI - oO0o
   if ( oOo0O ) :
    o00oooo0ooo . last_rloc_probe_nonce = oOo0O . last_rloc_probe_nonce
    if 37 - 37: iII111i - Ii1I . oO0o
    if ( oOo0O . translated_port == o00oooo0ooo . translated_port and oOo0O . rloc_name == o00oooo0ooo . rloc_name ) :
     if 47 - 47: IiII / I1ii11iIi11i . o0oOOo0O0Ooo . ooOoO0o + OOooOOo . OOooOOo
     oOo = green ( lisp_print_eid_tuple ( ooOOoo0 , IIi1iiIII11 ) , False )
     lprint ( "Suppress probe to duplicate RLOC {} for {}" . format ( red ( oo0o00OO , False ) , oOo ) )
     if 25 - 25: oO0o
     if 43 - 43: Ii1I - o0oOOo0O0Ooo % oO0o - O0
     if 20 - 20: OoO0O00 . ooOoO0o / OoOoOO00 - OoOoOO00 . iII111i / OOooOOo
     if 39 - 39: iIii1I11I1II1 % ooOoO0o
     if 75 - 75: i1IIi * II111iiii * O0 * i11iIiiIii % iII111i / iII111i
     if 36 - 36: IiII / I1IiiI % iII111i / iII111i
     o00oooo0ooo . last_rloc_probe = oOo0O . last_rloc_probe
     continue
     if 38 - 38: OOooOOo * I1ii11iIi11i * I1Ii111 + I11i
     if 65 - 65: O0 + O0 * I1Ii111
     if 66 - 66: OOooOOo / O0 + i1IIi . O0 % I1ii11iIi11i - OoooooooOO
   O0O0O = None
   I1IIiIIIii = None
   while ( True ) :
    I1IIiIIIii = o00oooo0ooo if I1IIiIIIii == None else I1IIiIIIii . next_rloc
    if ( I1IIiIIIii == None ) : break
    if 16 - 16: I11i % iII111i
    if 29 - 29: I1IiiI - ooOoO0o * OoO0O00 . i11iIiiIii % OoOoOO00 * o0oOOo0O0Ooo
    if 43 - 43: OoO0O00 * OOooOOo / I1Ii111 % OoOoOO00 . oO0o / OOooOOo
    if 62 - 62: O0 * I1ii11iIi11i - O0 / I11i % ooOoO0o
    if 1 - 1: O0 / iIii1I11I1II1
    if ( I1IIiIIIii . rloc_next_hop != None ) :
     if ( I1IIiIIIii . rloc_next_hop not in iI11 ) :
      if ( I1IIiIIIii . up_state ( ) ) :
       OooOOOoOoo0O0 , iiiI1i = I1IIiIIIii . rloc_next_hop
       I1IIiIIIii . state = LISP_RLOC_UNREACH_STATE
       I1IIiIIIii . last_state_change = lisp_get_timestamp ( )
       lisp_update_rtr_updown ( I1IIiIIIii . rloc , False )
       if 17 - 17: OoOoOO00 + ooOoO0o * II111iiii * OoOoOO00 + I1IiiI + i11iIiiIii
      II1iIIIII = bold ( "unreachable" , False )
      lprint ( "Next-hop {}({}) for RLOC {} is {}" . format ( iiiI1i , OooOOOoOoo0O0 ,
 red ( oo0o00OO , False ) , II1iIIIII ) )
      continue
      if 46 - 46: i1IIi - II111iiii . I1IiiI . i11iIiiIii
      if 54 - 54: O0 * I1ii11iIi11i / OOooOOo / IiII * IiII
      if 69 - 69: Oo0Ooo * OoooooooOO / I1IiiI
      if 16 - 16: o0oOOo0O0Ooo
      if 3 - 3: i11iIiiIii . I1ii11iIi11i
      if 65 - 65: II111iiii * iII111i - OoO0O00 + oO0o % OoO0O00
    iiI = I1IIiIIIii . last_rloc_probe
    OooOO0o0O00 = 0 if iiI == None else time . time ( ) - iiI
    if ( I1IIiIIIii . unreach_state ( ) and OooOO0o0O00 < LISP_RLOC_PROBE_INTERVAL ) :
     lprint ( "Waiting for probe-reply from RLOC {}" . format ( red ( oo0o00OO , False ) ) )
     if 100 - 100: o0oOOo0O0Ooo
     continue
     if 95 - 95: iII111i * oO0o * i1IIi
     if 100 - 100: iII111i . o0oOOo0O0Ooo - I1Ii111 % oO0o
     if 11 - 11: o0oOOo0O0Ooo . OoooooooOO - i1IIi
     if 71 - 71: I1IiiI . OOooOOo . I1ii11iIi11i
     if 90 - 90: i11iIiiIii + I1Ii111 % II111iiii
     if 67 - 67: OoOoOO00 / iII111i * OoO0O00 % i11iIiiIii
    ii1 = lisp_get_echo_nonce ( None , oo0o00OO )
    if ( ii1 and ii1 . request_nonce_timeout ( ) ) :
     I1IIiIIIii . state = LISP_RLOC_NO_ECHOED_NONCE_STATE
     I1IIiIIIii . last_state_change = lisp_get_timestamp ( )
     II1iIIIII = bold ( "unreachable" , False )
     lprint ( "RLOC {} went {}, nonce-echo failed" . format ( red ( oo0o00OO , False ) , II1iIIIII ) )
     if 76 - 76: OoO0O00
     lisp_update_rtr_updown ( I1IIiIIIii . rloc , False )
     continue
     if 92 - 92: iIii1I11I1II1 * O0 % I11i
     if 92 - 92: OoOoOO00 + oO0o
     if 89 - 89: IiII % iII111i / iIii1I11I1II1 . Ii1I . Oo0Ooo + ooOoO0o
     if 28 - 28: I1IiiI . iIii1I11I1II1
     if 12 - 12: I1Ii111 * OOooOOo
     if 11 - 11: II111iiii % O0 % O0 % o0oOOo0O0Ooo
    if ( ii1 and ii1 . recently_echoed ( ) ) :
     lprint ( ( "Suppress RLOC-probe to {}, nonce-echo " + "received" ) . format ( red ( oo0o00OO , False ) ) )
     if 45 - 45: OoooooooOO * oO0o
     continue
     if 74 - 74: ooOoO0o * I11i / oO0o - IiII + OoOoOO00
     if 16 - 16: Oo0Ooo
     if 29 - 29: Oo0Ooo . I1ii11iIi11i / II111iiii / oO0o / o0oOOo0O0Ooo + I11i
     if 4 - 4: OoooooooOO % I1ii11iIi11i . OoO0O00 * o0oOOo0O0Ooo + I1ii11iIi11i * IiII
     if 67 - 67: I1IiiI
     if 93 - 93: ooOoO0o . Ii1I + IiII / Oo0Ooo % I11i
    if ( I1IIiIIIii . last_rloc_probe != None ) :
     iiI = I1IIiIIIii . last_rloc_probe_reply
     if ( iiI == None ) : iiI = 0
     OooOO0o0O00 = time . time ( ) - iiI
     if ( I1IIiIIIii . up_state ( ) and OooOO0o0O00 >= LISP_RLOC_PROBE_REPLY_WAIT ) :
      if 40 - 40: Oo0Ooo % OoOoOO00 . IiII / I1IiiI % OoooooooOO
      I1IIiIIIii . state = LISP_RLOC_UNREACH_STATE
      I1IIiIIIii . last_state_change = lisp_get_timestamp ( )
      lisp_update_rtr_updown ( I1IIiIIIii . rloc , False )
      II1iIIIII = bold ( "unreachable" , False )
      lprint ( "RLOC {} went {}, probe it" . format ( red ( oo0o00OO , False ) , II1iIIIII ) )
      if 33 - 33: OOooOOo - OoooooooOO . iII111i
      if 2 - 2: I11i + i1IIi
      lisp_mark_rlocs_for_other_eids ( oOooO00Ooo )
      if 52 - 52: I11i - OoO0O00 % I1Ii111 . OOooOOo
      if 90 - 90: O0 - Oo0Ooo / i1IIi * iIii1I11I1II1 % o0oOOo0O0Ooo / oO0o
      if 73 - 73: iII111i % iIii1I11I1II1 + o0oOOo0O0Ooo % Ii1I . II111iiii + IiII
    I1IIiIIIii . last_rloc_probe = lisp_get_timestamp ( )
    if 55 - 55: OoOoOO00 * II111iiii / iII111i + OOooOOo / OoooooooOO
    IiIiIIiIIIii1 = "" if I1IIiIIIii . unreach_state ( ) == False else " unreachable"
    if 56 - 56: I1Ii111 / I1ii11iIi11i . i1IIi + I1ii11iIi11i / OoooooooOO - I1IiiI
    if 3 - 3: ooOoO0o
    if 68 - 68: o0oOOo0O0Ooo
    if 36 - 36: Oo0Ooo . I11i + I1IiiI * i1IIi % Ii1I + OOooOOo
    if 5 - 5: o0oOOo0O0Ooo % oO0o / OoO0O00
    if 17 - 17: OoooooooOO - I1ii11iIi11i / OoO0O00 - I1Ii111 + i1IIi
    if 6 - 6: Oo0Ooo - II111iiii
    I1Iii1I1 = ""
    iiiI1i = None
    if ( I1IIiIIIii . rloc_next_hop != None ) :
     OooOOOoOoo0O0 , iiiI1i = I1IIiIIIii . rloc_next_hop
     lisp_install_host_route ( oo0o00OO , iiiI1i , True )
     I1Iii1I1 = ", send on nh {}({})" . format ( iiiI1i , OooOOOoOoo0O0 )
     if 54 - 54: OoooooooOO % Ii1I
     if 100 - 100: OOooOOo - I11i . O0 * i1IIi % OoooooooOO - ooOoO0o
     if 54 - 54: O0 + I11i
     if 71 - 71: OoOoOO00
     if 29 - 29: O0 . i11iIiiIii
    i1I1111i = I1IIiIIIii . print_rloc_probe_rtt ( )
    oOoooOoO00OO = oo0o00OO
    if ( I1IIiIIIii . translated_port != 0 ) :
     oOoooOoO00OO += ":{}" . format ( I1IIiIIIii . translated_port )
     if 11 - 11: ooOoO0o * iIii1I11I1II1 + OoooooooOO + OoO0O00
    oOoooOoO00OO = red ( oOoooOoO00OO , False )
    if ( I1IIiIIIii . rloc_name != None ) :
     oOoooOoO00OO += " (" + blue ( I1IIiIIIii . rloc_name , False ) + ")"
     if 24 - 24: iII111i . OoO0O00 * Ii1I - OOooOOo . I11i
    lprint ( "Send {}{} {}, last rtt: {}{}" . format ( oO0oo000O , IiIiIIiIIIii1 ,
 oOoooOoO00OO , i1I1111i , I1Iii1I1 ) )
    if 90 - 90: I1ii11iIi11i % Oo0Ooo + I1ii11iIi11i - i1IIi
    if 94 - 94: OoooooooOO
    if 80 - 80: O0 * OOooOOo + i1IIi + i11iIiiIii * o0oOOo0O0Ooo
    if 14 - 14: II111iiii * OOooOOo - O0 / I1ii11iIi11i . OoO0O00 . ooOoO0o
    if 98 - 98: o0oOOo0O0Ooo . i1IIi
    if 83 - 83: i11iIiiIii + OOooOOo % iII111i
    if 59 - 59: I11i
    if 23 - 23: OoOoOO00 * I1Ii111
    if ( I1IIiIIIii . rloc_next_hop != None ) :
     O0O0O = lisp_get_host_route_next_hop ( oo0o00OO )
     if ( O0O0O ) : lisp_install_host_route ( oo0o00OO , O0O0O , False )
     if 18 - 18: o0oOOo0O0Ooo % i11iIiiIii . Ii1I . O0
     if 85 - 85: I1ii11iIi11i * iIii1I11I1II1 + o0oOOo0O0Ooo * OoO0O00
     if 25 - 25: o0oOOo0O0Ooo / Ii1I / Oo0Ooo . ooOoO0o - ooOoO0o * O0
     if 14 - 14: O0 - Ii1I + iIii1I11I1II1 + II111iiii . ooOoO0o + Ii1I
     if 25 - 25: OoO0O00 * oO0o
     if 29 - 29: OOooOOo - I1Ii111 - i11iIiiIii % i1IIi
    if ( I1IIiIIIii . rloc . is_null ( ) ) :
     I1IIiIIIii . rloc . copy_address ( o00oooo0ooo . rloc )
     if 2 - 2: i11iIiiIii % iIii1I11I1II1 * OOooOOo
     if 45 - 45: oO0o + i1IIi + iII111i + o0oOOo0O0Ooo * OOooOOo + ooOoO0o
     if 83 - 83: OoO0O00 - ooOoO0o / OoooooooOO % iIii1I11I1II1 - II111iiii
     if 73 - 73: Oo0Ooo + II111iiii - IiII
     if 60 - 60: i1IIi . i11iIiiIii / i1IIi . I11i % OOooOOo
    O00O0o = None if ( IIi1iiIII11 . is_null ( ) ) else ooOOoo0
    II1111 = ooOOoo0 if ( IIi1iiIII11 . is_null ( ) ) else IIi1iiIII11
    lisp_send_map_request ( lisp_sockets , 0 , O00O0o , II1111 , I1IIiIIIii )
    oOo0O = o00oooo0ooo
    if 65 - 65: O0 % OOooOOo * ooOoO0o * II111iiii
    if 9 - 9: Oo0Ooo * Ii1I
    if 17 - 17: OoOoOO00
    if 28 - 28: oO0o
    if ( iiiI1i ) : lisp_install_host_route ( oo0o00OO , iiiI1i , False )
    if 45 - 45: I1Ii111 % OoOoOO00 / I1Ii111 % OoO0O00 . I1IiiI
    if 100 - 100: OoO0O00 - Ii1I + i1IIi / o0oOOo0O0Ooo / IiII
    if 85 - 85: OoOoOO00
    if 90 - 90: o0oOOo0O0Ooo . OoOoOO00 - i11iIiiIii * IiII
    if 37 - 37: OoooooooOO - I1Ii111 . Ii1I . i1IIi * IiII / ooOoO0o
   if ( O0O0O ) : lisp_install_host_route ( oo0o00OO , O0O0O , True )
   if 12 - 12: OoooooooOO
   if 8 - 8: i11iIiiIii . I1Ii111 * o0oOOo0O0Ooo . ooOoO0o
   if 94 - 94: I1ii11iIi11i % OoOoOO00 - OoooooooOO
   if 42 - 42: I1Ii111 - i1IIi
   I1I1 += 1
   if ( ( I1I1 % 10 ) == 0 ) : time . sleep ( 0.020 )
   if 91 - 91: iII111i . OOooOOo / iIii1I11I1II1 . Oo0Ooo . II111iiii . OoOoOO00
   if 31 - 31: OoO0O00 . I1ii11iIi11i % I11i - II111iiii
   if 70 - 70: ooOoO0o - IiII - OoO0O00 / I11i
 lprint ( "---------- End RLOC Probing ----------" )
 return
 if 59 - 59: IiII % ooOoO0o . iII111i / Ii1I * Ii1I
 if 73 - 73: I1ii11iIi11i . oO0o % I11i . I1ii11iIi11i / I1Ii111 / II111iiii
 if 23 - 23: OoooooooOO . o0oOOo0O0Ooo
 if 76 - 76: I1Ii111
 if 91 - 91: iIii1I11I1II1 / Ii1I . I1IiiI
 if 63 - 63: ooOoO0o . Ii1I - I1Ii111 - oO0o * I1Ii111 + ooOoO0o
 if 85 - 85: II111iiii + I1ii11iIi11i
 if 33 - 33: iII111i
def lisp_update_rtr_updown ( rtr , updown ) :
 global lisp_ipc_socket
 if 14 - 14: O0 * Oo0Ooo / i1IIi
 if 95 - 95: O0 % i1IIi % ooOoO0o % oO0o - I1IiiI
 if 78 - 78: II111iiii % OOooOOo
 if 6 - 6: OOooOOo
 if ( lisp_i_am_itr == False ) : return
 if 21 - 21: I1Ii111 - Ii1I - i1IIi % oO0o
 if 55 - 55: OOooOOo + oO0o - II111iiii
 if 5 - 5: iII111i * OoooooooOO . OoO0O00 % ooOoO0o + Ii1I
 if 59 - 59: OoOoOO00
 if 96 - 96: I1IiiI
 if ( lisp_register_all_rtrs ) : return
 if 3 - 3: OoooooooOO
 I11ii1iIi111i = rtr . print_address_no_iid ( )
 if 96 - 96: IiII
 if 55 - 55: iIii1I11I1II1 + II111iiii . I1ii11iIi11i + Oo0Ooo . Ii1I * IiII
 if 91 - 91: iIii1I11I1II1 / Oo0Ooo
 if 68 - 68: o0oOOo0O0Ooo * OoOoOO00 . I1ii11iIi11i
 if 32 - 32: OoooooooOO * I11i
 if ( lisp_rtr_list . has_key ( I11ii1iIi111i ) == False ) : return
 if 86 - 86: I1Ii111 - i1IIi % O0
 updown = "up" if updown else "down"
 lprint ( "Send ETR IPC message, RTR {} has done {}" . format (
 red ( I11ii1iIi111i , False ) , bold ( updown , False ) ) )
 if 38 - 38: I1IiiI + OoO0O00 % iII111i / ooOoO0o
 if 93 - 93: OoOoOO00 . o0oOOo0O0Ooo - OoooooooOO
 if 90 - 90: iIii1I11I1II1 . Ii1I / i11iIiiIii . oO0o . I11i - I11i
 if 46 - 46: I11i
 iiiii1i1 = "rtr%{}%{}" . format ( I11ii1iIi111i , updown )
 iiiii1i1 = lisp_command_ipc ( iiiii1i1 , "lisp-itr" )
 lisp_ipc ( iiiii1i1 , lisp_ipc_socket , "lisp-etr" )
 return
 if 2 - 2: I1Ii111 * oO0o
 if 93 - 93: I11i
 if 2 - 2: i1IIi / I1IiiI
 if 29 - 29: Ii1I * iIii1I11I1II1 * i1IIi
 if 83 - 83: oO0o % O0 . I11i / I11i / I1IiiI - OoOoOO00
 if 91 - 91: iIii1I11I1II1 - IiII + iIii1I11I1II1 % Oo0Ooo % I1IiiI
 if 84 - 84: iIii1I11I1II1 . Oo0Ooo - OoooooooOO % Oo0Ooo
def lisp_process_rloc_probe_reply ( rloc_entry , source , port , map_reply , ttl ,
 mrloc ) :
 I1IIiIIIii = rloc_entry . rloc
 Iii11I = map_reply . nonce
 III1I1IIi = map_reply . hop_count
 oO0oo000O = bold ( "RLOC-probe reply" , False )
 i1Ii1I1iii = I1IIiIIIii . print_address_no_iid ( )
 O000oO = source . print_address_no_iid ( )
 I1i1IiII = lisp_rloc_probe_list
 OoiIII1II1 = rloc_entry . json . json_string if rloc_entry . json else None
 i1 = lisp_get_timestamp ( )
 if 51 - 51: Oo0Ooo - o0oOOo0O0Ooo * II111iiii + i1IIi
 if 83 - 83: I11i * o0oOOo0O0Ooo * Ii1I + OoooooooOO
 if 76 - 76: I1ii11iIi11i . OoooooooOO + ooOoO0o / I1IiiI
 if 56 - 56: Ii1I % I11i / O0 % O0 % iIii1I11I1II1 + I1IiiI
 if 51 - 51: O0 * Ii1I / oO0o * OoooooooOO
 if 93 - 93: I1ii11iIi11i . OOooOOo + i1IIi
 if ( mrloc != None ) :
  iIi1I1i = mrloc . rloc . print_address_no_iid ( )
  if ( mrloc . multicast_rloc_probe_list . has_key ( i1Ii1I1iii ) == False ) :
   I111iII1I11II = lisp_rloc ( )
   I111iII1I11II = copy . deepcopy ( mrloc )
   I111iII1I11II . rloc . copy_address ( I1IIiIIIii )
   I111iII1I11II . multicast_rloc_probe_list = { }
   mrloc . multicast_rloc_probe_list [ i1Ii1I1iii ] = I111iII1I11II
   if 55 - 55: ooOoO0o . ooOoO0o % i11iIiiIii * I1IiiI - IiII . Ii1I
  I111iII1I11II = mrloc . multicast_rloc_probe_list [ i1Ii1I1iii ]
  I111iII1I11II . last_rloc_probe_nonce = mrloc . last_rloc_probe_nonce
  I111iII1I11II . last_rloc_probe = mrloc . last_rloc_probe
  O0OOOO0o0O , ooOOoo0 , IIi1iiIII11 = lisp_rloc_probe_list [ iIi1I1i ] [ 0 ]
  I111iII1I11II . process_rloc_probe_reply ( i1 , Iii11I , ooOOoo0 , IIi1iiIII11 , III1I1IIi , ttl , OoiIII1II1 )
  mrloc . process_rloc_probe_reply ( i1 , Iii11I , ooOOoo0 , IIi1iiIII11 , III1I1IIi , ttl , OoiIII1II1 )
  return
  if 54 - 54: iII111i
  if 2 - 2: OoOoOO00 + I1IiiI . ooOoO0o - oO0o . iIii1I11I1II1
  if 76 - 76: Ii1I
  if 31 - 31: ooOoO0o
  if 70 - 70: O0
  if 42 - 42: I1Ii111 + OoooooooOO + I11i
  if 48 - 48: Oo0Ooo . IiII / ooOoO0o + I11i
 IiiIIi1 = i1Ii1I1iii
 if ( I1i1IiII . has_key ( IiiIIi1 ) == False ) :
  IiiIIi1 += ":" + str ( port )
  if ( I1i1IiII . has_key ( IiiIIi1 ) == False ) :
   IiiIIi1 = O000oO
   if ( I1i1IiII . has_key ( IiiIIi1 ) == False ) :
    IiiIIi1 += ":" + str ( port )
    lprint ( "    Received unsolicited {} from {}/{}, port {}" . format ( oO0oo000O , red ( i1Ii1I1iii , False ) , red ( O000oO ,
    # I1IiiI - ooOoO0o / I1ii11iIi11i
 False ) , port ) )
    return
    if 82 - 82: II111iiii % OoOoOO00
    if 32 - 32: i11iIiiIii
    if 38 - 38: IiII + I1Ii111 % Ii1I / Ii1I
    if 39 - 39: iII111i * i11iIiiIii
    if 31 - 31: IiII - Ii1I . i1IIi
    if 1 - 1: o0oOOo0O0Ooo + OOooOOo % Ii1I - O0 / I1ii11iIi11i
    if 20 - 20: o0oOOo0O0Ooo + II111iiii * Ii1I . OoooooooOO
    if 88 - 88: O0 + iIii1I11I1II1 . o0oOOo0O0Ooo . iIii1I11I1II1 - Ii1I
 for I1IIiIIIii , ooOOoo0 , IIi1iiIII11 in lisp_rloc_probe_list [ IiiIIi1 ] :
  if ( lisp_i_am_rtr ) :
   if ( I1IIiIIIii . translated_port != 0 and I1IIiIIIii . translated_port != port ) :
    continue
    if 74 - 74: Ii1I . IiII
    if 67 - 67: oO0o
  I1IIiIIIii . process_rloc_probe_reply ( i1 , Iii11I , ooOOoo0 , IIi1iiIII11 , III1I1IIi , ttl , OoiIII1II1 )
  if 12 - 12: I1IiiI + OoooooooOO
 return
 if 25 - 25: iIii1I11I1II1 - I1IiiI . i11iIiiIii + ooOoO0o
 if 19 - 19: OoooooooOO / IiII
 if 40 - 40: OoOoOO00 / OoooooooOO * iIii1I11I1II1 / i1IIi . OoooooooOO
 if 88 - 88: I1IiiI % I1IiiI / II111iiii - IiII
 if 72 - 72: OoO0O00 - I1ii11iIi11i . Oo0Ooo / OoO0O00
 if 86 - 86: i11iIiiIii - oO0o . i11iIiiIii
 if 51 - 51: OoO0O00 - OoO0O00 * IiII
 if 24 - 24: OoooooooOO . II111iiii
def lisp_db_list_length ( ) :
 I1I1 = 0
 for iiIII1 in lisp_db_list :
  I1I1 += len ( iiIII1 . dynamic_eids ) if iiIII1 . dynamic_eid_configured ( ) else 1
  I1I1 += len ( iiIII1 . eid . iid_list )
  if 97 - 97: II111iiii . O0
 return ( I1I1 )
 if 18 - 18: iII111i
 if 35 - 35: ooOoO0o / O0 / iIii1I11I1II1 - iIii1I11I1II1 + I11i
 if 8 - 8: I1Ii111 . oO0o % Oo0Ooo * OoooooooOO
 if 25 - 25: OoO0O00
 if 54 - 54: O0
 if 20 - 20: ooOoO0o + Oo0Ooo - Oo0Ooo
 if 2 - 2: i1IIi - IiII . I1ii11iIi11i / i1IIi
 if 92 - 92: ooOoO0o - iII111i
def lisp_is_myeid ( eid ) :
 for iiIII1 in lisp_db_list :
  if ( eid . is_more_specific ( iiIII1 . eid ) ) : return ( True )
  if 69 - 69: iII111i
 return ( False )
 if 48 - 48: O0 + o0oOOo0O0Ooo . oO0o - IiII * OoooooooOO . OoO0O00
 if 63 - 63: oO0o * OoO0O00 * oO0o
 if 31 - 31: Oo0Ooo
 if 90 - 90: I11i . IiII * iIii1I11I1II1 . I11i + i1IIi
 if 67 - 67: I1Ii111 . I1ii11iIi11i
 if 2 - 2: O0 + I1Ii111
 if 82 - 82: Ii1I / iII111i
 if 13 - 13: I11i + iII111i
 if 54 - 54: I1ii11iIi11i - I1IiiI . Ii1I
def lisp_format_macs ( sa , da ) :
 sa = sa [ 0 : 4 ] + "-" + sa [ 4 : 8 ] + "-" + sa [ 8 : 12 ]
 da = da [ 0 : 4 ] + "-" + da [ 4 : 8 ] + "-" + da [ 8 : 12 ]
 return ( "{} -> {}" . format ( sa , da ) )
 if 59 - 59: Oo0Ooo + I1ii11iIi11i
 if 87 - 87: ooOoO0o * OoooooooOO + OoO0O00 + oO0o - I1Ii111
 if 70 - 70: i1IIi . Ii1I / Ii1I
 if 9 - 9: iII111i + I1Ii111 + iII111i % ooOoO0o + i11iIiiIii + i11iIiiIii
 if 45 - 45: i1IIi + I1ii11iIi11i
 if 49 - 49: i11iIiiIii . I1ii11iIi11i
 if 91 - 91: ooOoO0o - OOooOOo - OOooOOo * o0oOOo0O0Ooo
def lisp_get_echo_nonce ( rloc , rloc_str ) :
 if ( lisp_nonce_echoing == False ) : return ( None )
 if 33 - 33: II111iiii
 if ( rloc ) : rloc_str = rloc . print_address_no_iid ( )
 ii1 = None
 if ( lisp_nonce_echo_list . has_key ( rloc_str ) ) :
  ii1 = lisp_nonce_echo_list [ rloc_str ]
  if 39 - 39: ooOoO0o + I11i
 return ( ii1 )
 if 24 - 24: o0oOOo0O0Ooo
 if 5 - 5: i11iIiiIii - oO0o + o0oOOo0O0Ooo % ooOoO0o
 if 63 - 63: oO0o
 if 7 - 7: IiII / i11iIiiIii - OOooOOo
 if 9 - 9: II111iiii + i11iIiiIii % I1Ii111 - Oo0Ooo * OOooOOo
 if 55 - 55: I1Ii111 + ooOoO0o
 if 58 - 58: iII111i . I1ii11iIi11i - Oo0Ooo % o0oOOo0O0Ooo + I1Ii111
 if 58 - 58: oO0o . ooOoO0o . I1IiiI . Oo0Ooo * iIii1I11I1II1 - iII111i
def lisp_decode_dist_name ( packet ) :
 I1I1 = 0
 o0oOoOOooOo = ""
 if 67 - 67: oO0o % i11iIiiIii - I1IiiI % iIii1I11I1II1 . iIii1I11I1II1
 while ( packet [ 0 : 1 ] != "\0" ) :
  if ( I1I1 == 255 ) : return ( [ None , None ] )
  o0oOoOOooOo += packet [ 0 : 1 ]
  packet = packet [ 1 : : ]
  I1I1 += 1
  if 73 - 73: OOooOOo % OoO0O00 + IiII . Ii1I * I1Ii111
  if 26 - 26: iII111i - I11i
 packet = packet [ 1 : : ]
 return ( packet , o0oOoOOooOo )
 if 5 - 5: OoO0O00 % iII111i + i1IIi - OoooooooOO
 if 16 - 16: i1IIi
 if 86 - 86: OoOoOO00 - iII111i - Oo0Ooo
 if 33 - 33: Ii1I - OoO0O00
 if 15 - 15: O0 . iIii1I11I1II1 - I1Ii111 + O0 + ooOoO0o / I1IiiI
 if 8 - 8: iII111i % O0 - OoOoOO00
 if 49 - 49: oO0o - OOooOOo / Ii1I / I1Ii111 . o0oOOo0O0Ooo . iII111i
 if 58 - 58: IiII + Ii1I
def lisp_write_flow_log ( flow_log ) :
 OOO000 = open ( "./logs/lisp-flow.log" , "a" )
 if 89 - 89: Ii1I / Oo0Ooo * o0oOOo0O0Ooo / OoO0O00 + I11i
 I1I1 = 0
 for III11i in flow_log :
  IiiiIi1iiii11 = III11i [ 3 ]
  iI11IiI1II = IiiiIi1iiii11 . print_flow ( III11i [ 0 ] , III11i [ 1 ] , III11i [ 2 ] )
  OOO000 . write ( iI11IiI1II )
  I1I1 += 1
  if 28 - 28: I1ii11iIi11i . OoOoOO00 % OoOoOO00
 OOO000 . close ( )
 del ( flow_log )
 if 61 - 61: Ii1I % I1ii11iIi11i . I1ii11iIi11i / Oo0Ooo - I1Ii111 * OoOoOO00
 I1I1 = bold ( str ( I1I1 ) , False )
 lprint ( "Wrote {} flow entries to ./logs/lisp-flow.log" . format ( I1I1 ) )
 return
 if 47 - 47: IiII
 if 76 - 76: iII111i / II111iiii / I11i
 if 62 - 62: I1ii11iIi11i
 if 100 - 100: iII111i / ooOoO0o / IiII % II111iiii
 if 6 - 6: OoooooooOO - I1IiiI + OoooooooOO
 if 89 - 89: oO0o % Oo0Ooo . O0 . ooOoO0o
 if 46 - 46: IiII * I11i - OoO0O00 - Ii1I
def lisp_policy_command ( kv_pair ) :
 oo00ooOOOo0O = lisp_policy ( "" )
 OoOOO00o000OOO = None
 if 86 - 86: oO0o - o0oOOo0O0Ooo
 IiO0ooo00ooO00 = [ ]
 for IiIIi1IiiIiI in range ( len ( kv_pair [ "datetime-range" ] ) ) :
  IiO0ooo00ooO00 . append ( lisp_policy_match ( ) )
  if 18 - 18: OOooOOo - i11iIiiIii % II111iiii + oO0o
  if 82 - 82: Ii1I
 for I111II in kv_pair . keys ( ) :
  i11II = kv_pair [ I111II ]
  if 88 - 88: iIii1I11I1II1 - o0oOOo0O0Ooo . OoOoOO00 / I1ii11iIi11i / i11iIiiIii / Ii1I
  if 10 - 10: I1Ii111 / Ii1I * I1Ii111 / OoO0O00 - I1ii11iIi11i
  if 7 - 7: I1IiiI . OoO0O00 . OoOoOO00 . I1ii11iIi11i * OoO0O00 - IiII
  if 6 - 6: OoO0O00 + II111iiii - oO0o
  if ( I111II == "instance-id" ) :
   for IiIIi1IiiIiI in range ( len ( IiO0ooo00ooO00 ) ) :
    OOOOOOOo00 = i11II [ IiIIi1IiiIiI ]
    if ( OOOOOOOo00 == "" ) : continue
    O0oOOO00 = IiO0ooo00ooO00 [ IiIIi1IiiIiI ]
    if ( O0oOOO00 . source_eid == None ) :
     O0oOOO00 . source_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
     if 5 - 5: ooOoO0o . OoO0O00
    if ( O0oOOO00 . dest_eid == None ) :
     O0oOOO00 . dest_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
     if 40 - 40: iII111i
    O0oOOO00 . source_eid . instance_id = int ( OOOOOOOo00 )
    O0oOOO00 . dest_eid . instance_id = int ( OOOOOOOo00 )
    if 87 - 87: IiII / II111iiii
    if 44 - 44: OoO0O00 . I1Ii111 - OoooooooOO * OoOoOO00 . OoO0O00
  if ( I111II == "source-eid" ) :
   for IiIIi1IiiIiI in range ( len ( IiO0ooo00ooO00 ) ) :
    OOOOOOOo00 = i11II [ IiIIi1IiiIiI ]
    if ( OOOOOOOo00 == "" ) : continue
    O0oOOO00 = IiO0ooo00ooO00 [ IiIIi1IiiIiI ]
    if ( O0oOOO00 . source_eid == None ) :
     O0oOOO00 . source_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
     if 84 - 84: OOooOOo . OOooOOo . oO0o % iII111i * Oo0Ooo - iIii1I11I1II1
    o0OoO0000o = O0oOOO00 . source_eid . instance_id
    O0oOOO00 . source_eid . store_prefix ( OOOOOOOo00 )
    O0oOOO00 . source_eid . instance_id = o0OoO0000o
    if 4 - 4: iII111i
    if 23 - 23: i1IIi . iIii1I11I1II1 / I1IiiI . OoOoOO00 . iII111i / IiII
  if ( I111II == "destination-eid" ) :
   for IiIIi1IiiIiI in range ( len ( IiO0ooo00ooO00 ) ) :
    OOOOOOOo00 = i11II [ IiIIi1IiiIiI ]
    if ( OOOOOOOo00 == "" ) : continue
    O0oOOO00 = IiO0ooo00ooO00 [ IiIIi1IiiIiI ]
    if ( O0oOOO00 . dest_eid == None ) :
     O0oOOO00 . dest_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
     if 65 - 65: Ii1I + IiII + I11i / I1Ii111 % iIii1I11I1II1
    o0OoO0000o = O0oOOO00 . dest_eid . instance_id
    O0oOOO00 . dest_eid . store_prefix ( OOOOOOOo00 )
    O0oOOO00 . dest_eid . instance_id = o0OoO0000o
    if 17 - 17: I1ii11iIi11i * OOooOOo % II111iiii
    if 30 - 30: I1Ii111 . Ii1I . Oo0Ooo / OOooOOo * OoooooooOO / I1ii11iIi11i
  if ( I111II == "source-rloc" ) :
   for IiIIi1IiiIiI in range ( len ( IiO0ooo00ooO00 ) ) :
    OOOOOOOo00 = i11II [ IiIIi1IiiIiI ]
    if ( OOOOOOOo00 == "" ) : continue
    O0oOOO00 = IiO0ooo00ooO00 [ IiIIi1IiiIiI ]
    O0oOOO00 . source_rloc = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
    O0oOOO00 . source_rloc . store_prefix ( OOOOOOOo00 )
    if 41 - 41: i1IIi
    if 75 - 75: o0oOOo0O0Ooo . I1Ii111 - I1Ii111 % Ii1I * OoooooooOO
  if ( I111II == "destination-rloc" ) :
   for IiIIi1IiiIiI in range ( len ( IiO0ooo00ooO00 ) ) :
    OOOOOOOo00 = i11II [ IiIIi1IiiIiI ]
    if ( OOOOOOOo00 == "" ) : continue
    O0oOOO00 = IiO0ooo00ooO00 [ IiIIi1IiiIiI ]
    O0oOOO00 . dest_rloc = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
    O0oOOO00 . dest_rloc . store_prefix ( OOOOOOOo00 )
    if 99 - 99: OOooOOo + o0oOOo0O0Ooo - OOooOOo . i1IIi
    if 86 - 86: Ii1I % oO0o - i11iIiiIii - O0 + IiII + iII111i
  if ( I111II == "rloc-record-name" ) :
   for IiIIi1IiiIiI in range ( len ( IiO0ooo00ooO00 ) ) :
    OOOOOOOo00 = i11II [ IiIIi1IiiIiI ]
    if ( OOOOOOOo00 == "" ) : continue
    O0oOOO00 = IiO0ooo00ooO00 [ IiIIi1IiiIiI ]
    O0oOOO00 . rloc_record_name = OOOOOOOo00
    if 100 - 100: OoO0O00 . Oo0Ooo
    if 29 - 29: OoO0O00
  if ( I111II == "geo-name" ) :
   for IiIIi1IiiIiI in range ( len ( IiO0ooo00ooO00 ) ) :
    OOOOOOOo00 = i11II [ IiIIi1IiiIiI ]
    if ( OOOOOOOo00 == "" ) : continue
    O0oOOO00 = IiO0ooo00ooO00 [ IiIIi1IiiIiI ]
    O0oOOO00 . geo_name = OOOOOOOo00
    if 34 - 34: O0 - o0oOOo0O0Ooo % OOooOOo . OoO0O00 % IiII
    if 63 - 63: O0 % iIii1I11I1II1 . o0oOOo0O0Ooo . I1IiiI * Ii1I % i1IIi
  if ( I111II == "elp-name" ) :
   for IiIIi1IiiIiI in range ( len ( IiO0ooo00ooO00 ) ) :
    OOOOOOOo00 = i11II [ IiIIi1IiiIiI ]
    if ( OOOOOOOo00 == "" ) : continue
    O0oOOO00 = IiO0ooo00ooO00 [ IiIIi1IiiIiI ]
    O0oOOO00 . elp_name = OOOOOOOo00
    if 47 - 47: II111iiii * I1ii11iIi11i
    if 70 - 70: I1ii11iIi11i - o0oOOo0O0Ooo
  if ( I111II == "rle-name" ) :
   for IiIIi1IiiIiI in range ( len ( IiO0ooo00ooO00 ) ) :
    OOOOOOOo00 = i11II [ IiIIi1IiiIiI ]
    if ( OOOOOOOo00 == "" ) : continue
    O0oOOO00 = IiO0ooo00ooO00 [ IiIIi1IiiIiI ]
    O0oOOO00 . rle_name = OOOOOOOo00
    if 71 - 71: I1ii11iIi11i * i1IIi
    if 67 - 67: I1ii11iIi11i % OoOoOO00 . iII111i / Ii1I . I1IiiI
  if ( I111II == "json-name" ) :
   for IiIIi1IiiIiI in range ( len ( IiO0ooo00ooO00 ) ) :
    OOOOOOOo00 = i11II [ IiIIi1IiiIiI ]
    if ( OOOOOOOo00 == "" ) : continue
    O0oOOO00 = IiO0ooo00ooO00 [ IiIIi1IiiIiI ]
    O0oOOO00 . json_name = OOOOOOOo00
    if 48 - 48: IiII + II111iiii . I1IiiI % o0oOOo0O0Ooo
    if 57 - 57: OOooOOo . I11i % OoOoOO00
  if ( I111II == "datetime-range" ) :
   for IiIIi1IiiIiI in range ( len ( IiO0ooo00ooO00 ) ) :
    OOOOOOOo00 = i11II [ IiIIi1IiiIiI ]
    O0oOOO00 = IiO0ooo00ooO00 [ IiIIi1IiiIiI ]
    if ( OOOOOOOo00 == "" ) : continue
    I11iIi1i1I1i1 = lisp_datetime ( OOOOOOOo00 [ 0 : 19 ] )
    O0oo0 = lisp_datetime ( OOOOOOOo00 [ 19 : : ] )
    if ( I11iIi1i1I1i1 . valid_datetime ( ) and O0oo0 . valid_datetime ( ) ) :
     O0oOOO00 . datetime_lower = I11iIi1i1I1i1
     O0oOOO00 . datetime_upper = O0oo0
     if 68 - 68: iIii1I11I1II1 % I1ii11iIi11i % II111iiii / O0 + iII111i
     if 78 - 78: iII111i - OOooOOo / I1Ii111
     if 38 - 38: I11i % i1IIi + o0oOOo0O0Ooo + I1ii11iIi11i + I1IiiI
     if 1 - 1: II111iiii * o0oOOo0O0Ooo . O0 - Ii1I / oO0o
     if 17 - 17: OoooooooOO % OoooooooOO + Oo0Ooo + I1Ii111
     if 56 - 56: I11i % OoOoOO00 - OoO0O00
     if 31 - 31: iII111i % i11iIiiIii - Ii1I / OOooOOo - I1Ii111
  if ( I111II == "set-action" ) :
   oo00ooOOOo0O . set_action = i11II
   if 60 - 60: o0oOOo0O0Ooo + Oo0Ooo . O0
  if ( I111II == "set-record-ttl" ) :
   oo00ooOOOo0O . set_record_ttl = int ( i11II )
   if 51 - 51: i11iIiiIii / iIii1I11I1II1 . I1IiiI - Ii1I * I1Ii111 . iII111i
  if ( I111II == "set-instance-id" ) :
   if ( oo00ooOOOo0O . set_source_eid == None ) :
    oo00ooOOOo0O . set_source_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
    if 72 - 72: Ii1I . I11i / i1IIi % i1IIi + I1ii11iIi11i
   if ( oo00ooOOOo0O . set_dest_eid == None ) :
    oo00ooOOOo0O . set_dest_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
    if 56 - 56: OoO0O00 - OoOoOO00 - II111iiii * o0oOOo0O0Ooo
   OoOOO00o000OOO = int ( i11II )
   oo00ooOOOo0O . set_source_eid . instance_id = OoOOO00o000OOO
   oo00ooOOOo0O . set_dest_eid . instance_id = OoOOO00o000OOO
   if 87 - 87: ooOoO0o * OoooooooOO % O0 * OoooooooOO . I1Ii111
  if ( I111II == "set-source-eid" ) :
   if ( oo00ooOOOo0O . set_source_eid == None ) :
    oo00ooOOOo0O . set_source_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
    if 66 - 66: OoO0O00 * Ii1I . OoO0O00
   oo00ooOOOo0O . set_source_eid . store_prefix ( i11II )
   if ( OoOOO00o000OOO != None ) : oo00ooOOOo0O . set_source_eid . instance_id = OoOOO00o000OOO
   if 90 - 90: II111iiii % Ii1I
  if ( I111II == "set-destination-eid" ) :
   if ( oo00ooOOOo0O . set_dest_eid == None ) :
    oo00ooOOOo0O . set_dest_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
    if 67 - 67: I1IiiI - I11i - i11iIiiIii
   oo00ooOOOo0O . set_dest_eid . store_prefix ( i11II )
   if ( OoOOO00o000OOO != None ) : oo00ooOOOo0O . set_dest_eid . instance_id = OoOOO00o000OOO
   if 45 - 45: ooOoO0o - IiII / OoO0O00 / IiII
  if ( I111II == "set-rloc-address" ) :
   oo00ooOOOo0O . set_rloc_address = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
   oo00ooOOOo0O . set_rloc_address . store_address ( i11II )
   if 63 - 63: ooOoO0o . i11iIiiIii + iII111i . OoO0O00 / ooOoO0o % iII111i
  if ( I111II == "set-rloc-record-name" ) :
   oo00ooOOOo0O . set_rloc_record_name = i11II
   if 23 - 23: iIii1I11I1II1 - ooOoO0o / I11i * I11i
  if ( I111II == "set-elp-name" ) :
   oo00ooOOOo0O . set_elp_name = i11II
   if 62 - 62: OOooOOo - I1IiiI * oO0o + O0 / ooOoO0o * iIii1I11I1II1
  if ( I111II == "set-geo-name" ) :
   oo00ooOOOo0O . set_geo_name = i11II
   if 25 - 25: I1Ii111 % Oo0Ooo + OoO0O00 % OOooOOo
  if ( I111II == "set-rle-name" ) :
   oo00ooOOOo0O . set_rle_name = i11II
   if 85 - 85: I1IiiI . i11iIiiIii - ooOoO0o * I11i * OoOoOO00 * I11i
  if ( I111II == "set-json-name" ) :
   oo00ooOOOo0O . set_json_name = i11II
   if 29 - 29: I1Ii111 * I1Ii111 . iII111i + o0oOOo0O0Ooo
  if ( I111II == "policy-name" ) :
   oo00ooOOOo0O . policy_name = i11II
   if 57 - 57: I1Ii111 - IiII
   if 89 - 89: oO0o + iII111i
   if 52 - 52: OOooOOo % O0 * I1ii11iIi11i . I1ii11iIi11i / IiII
   if 7 - 7: II111iiii
   if 7 - 7: iIii1I11I1II1 . O0 + Ii1I % I1IiiI * O0 + OoO0O00
   if 3 - 3: Oo0Ooo * OoooooooOO * oO0o % OoOoOO00 * OoOoOO00 . ooOoO0o
 oo00ooOOOo0O . match_clauses = IiO0ooo00ooO00
 oo00ooOOOo0O . save_policy ( )
 return
 if 16 - 16: ooOoO0o / o0oOOo0O0Ooo - O0 * I1IiiI
 if 13 - 13: iII111i . iII111i % O0 % o0oOOo0O0Ooo
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
if 99 - 99: OoO0O00 - OoOoOO00 + OoO0O00
if 67 - 67: I1Ii111
if 31 - 31: OoO0O00 * Oo0Ooo % O0 * II111iiii + ooOoO0o * I1IiiI
if 77 - 77: ooOoO0o
if 98 - 98: I1Ii111 + I1ii11iIi11i % OoO0O00 * Ii1I + iII111i
if 6 - 6: iII111i / iII111i . i11iIiiIii
if 12 - 12: I11i - OoO0O00
def lisp_send_to_arista ( command , interface ) :
 interface = "" if ( interface == None ) else "interface " + interface
 if 68 - 68: IiII - OoOoOO00
 ii1i1iIi1Ii1I1 = command
 if ( interface != "" ) : ii1i1iIi1Ii1I1 = interface + ": " + ii1i1iIi1Ii1I1
 lprint ( "Send CLI command '{}' to hardware" . format ( ii1i1iIi1Ii1I1 ) )
 if 100 - 100: I11i % i1IIi / OoooooooOO
 commands = '''
        enable
        configure
        {}
        {}
    ''' . format ( interface , command )
 if 12 - 12: Ii1I . Ii1I
 os . system ( "FastCli -c '{}'" . format ( commands ) )
 return
 if 13 - 13: oO0o - i1IIi / i1IIi + OoooooooOO
 if 57 - 57: OoooooooOO / O0 + I1ii11iIi11i % I11i * oO0o / Ii1I
 if 49 - 49: I1IiiI * ooOoO0o * OOooOOo + OoO0O00 + ooOoO0o
 if 42 - 42: i1IIi . OoO0O00 % iII111i
 if 57 - 57: I1ii11iIi11i / I1IiiI
 if 69 - 69: iII111i - iII111i . OoO0O00 / oO0o - OoO0O00 + I1Ii111
 if 98 - 98: iII111i . oO0o - O0 % I1IiiI . I1ii11iIi11i / i1IIi
def lisp_arista_is_alive ( prefix ) :
 ooO0ooooO = "enable\nsh plat trident l3 software routes {}\n" . format ( prefix )
 Oo0Ooo0O0 = commands . getoutput ( "FastCli -c '{}'" . format ( ooO0ooooO ) )
 if 72 - 72: I1IiiI / Oo0Ooo % IiII - O0 / O0 * O0
 if 83 - 83: O0 / I1Ii111 - OoooooooOO
 if 42 - 42: Ii1I / i1IIi - IiII / I1Ii111
 if 39 - 39: OoooooooOO
 Oo0Ooo0O0 = Oo0Ooo0O0 . split ( "\n" ) [ 1 ]
 IiiI11ii = Oo0Ooo0O0 . split ( " " )
 IiiI11ii = IiiI11ii [ - 1 ] . replace ( "\r" , "" )
 if 51 - 51: OoO0O00 + i11iIiiIii / II111iiii
 if 52 - 52: o0oOOo0O0Ooo * I1ii11iIi11i % OoOoOO00 . Ii1I . OoO0O00 * I1Ii111
 if 26 - 26: ooOoO0o % OoO0O00 * OoO0O00 * O0 . i1IIi
 if 32 - 32: i11iIiiIii
 return ( IiiI11ii == "Y" )
 if 43 - 43: iIii1I11I1II1 + oO0o + OoooooooOO
 if 69 - 69: Oo0Ooo - o0oOOo0O0Ooo
 if 18 - 18: OoooooooOO
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
 if 35 - 35: OOooOOo * OOooOOo + o0oOOo0O0Ooo / i1IIi - I11i
 if 12 - 12: I1ii11iIi11i - i11iIiiIii + I1IiiI . Oo0Ooo
 if 26 - 26: oO0o + I1Ii111 + IiII * o0oOOo0O0Ooo . oO0o
 if 95 - 95: OoOoOO00 . I1Ii111 / Ii1I . I1Ii111 % OoO0O00
 if 16 - 16: Ii1I / I1IiiI / I1IiiI - OoooooooOO
 if 13 - 13: OOooOOo / OoooooooOO
 if 7 - 7: II111iiii - ooOoO0o
 if 72 - 72: Ii1I
 if 27 - 27: ooOoO0o / IiII + OoO0O00 + Ii1I % I1Ii111
 if 86 - 86: O0 % i11iIiiIii - Ii1I * oO0o % OOooOOo * i1IIi
 if 87 - 87: II111iiii
 if 53 - 53: OoOoOO00 * i11iIiiIii / I1Ii111
 if 100 - 100: ooOoO0o + I1IiiI * oO0o + ooOoO0o
 if 24 - 24: i11iIiiIii + ooOoO0o
 if 80 - 80: IiII % I11i % oO0o
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
def lisp_program_vxlan_hardware ( mc ) :
 if 11 - 11: I11i * iII111i
 if 28 - 28: II111iiii + IiII / Oo0Ooo * I1IiiI - OOooOOo
 if 2 - 2: oO0o + I11i / I1Ii111 . I11i
 if 59 - 59: Ii1I
 if 47 - 47: iII111i % iII111i
 if 81 - 81: oO0o / I1ii11iIi11i . OoooooooOO % II111iiii / oO0o
 if ( os . path . exists ( "/persist/local/lispers.net" ) == False ) : return
 if 23 - 23: IiII + oO0o + o0oOOo0O0Ooo . I1ii11iIi11i / i11iIiiIii + iIii1I11I1II1
 if 74 - 74: I11i % OOooOOo
 if 57 - 57: O0 + I1IiiI + i11iIiiIii
 if 90 - 90: I1ii11iIi11i . OoO0O00 * iIii1I11I1II1 - Oo0Ooo
 if ( len ( mc . best_rloc_set ) == 0 ) : return
 if 28 - 28: I1IiiI . ooOoO0o - ooOoO0o * OOooOOo . IiII
 if 16 - 16: iIii1I11I1II1 % i11iIiiIii / Ii1I % iIii1I11I1II1 / iII111i
 if 27 - 27: II111iiii * OoooooooOO / Oo0Ooo % O0
 if 41 - 41: oO0o / iIii1I11I1II1 % iII111i - I1Ii111 % I11i * i11iIiiIii
 IiI1Iiii = mc . eid . print_prefix_no_iid ( )
 I1IIiIIIii = mc . best_rloc_set [ 0 ] . rloc . print_address_no_iid ( )
 if 21 - 21: O0
 if 14 - 14: IiII / I1ii11iIi11i + Ii1I
 if 48 - 48: I1Ii111 * oO0o / o0oOOo0O0Ooo * OoOoOO00 * ooOoO0o
 if 38 - 38: I1IiiI * Ii1I + Oo0Ooo - OoooooooOO
 o0O00OOo = commands . getoutput ( "ip route get {} | egrep vlan4094" . format ( IiI1Iiii ) )
 if 29 - 29: I11i / I1ii11iIi11i * iII111i . OoooooooOO - Oo0Ooo - IiII
 if ( o0O00OOo != "" ) :
  lprint ( "Route {} already in hardware: '{}'" . format ( green ( IiI1Iiii , False ) , o0O00OOo ) )
  if 6 - 6: OOooOOo - I1IiiI . IiII
  return
  if 40 - 40: II111iiii
  if 13 - 13: OoOoOO00
  if 23 - 23: Oo0Ooo / II111iiii % OOooOOo % iII111i - Oo0Ooo / OoO0O00
  if 7 - 7: Ii1I / I11i / II111iiii % I11i * I11i + iIii1I11I1II1
  if 6 - 6: iIii1I11I1II1 * oO0o - iIii1I11I1II1 . O0 . O0
  if 96 - 96: I1Ii111 * II111iiii % i11iIiiIii - oO0o
  if 32 - 32: i11iIiiIii * o0oOOo0O0Ooo . OoooooooOO / O0
 Ii1o0O00ooo = commands . getoutput ( "ifconfig | egrep 'vxlan|vlan4094'" )
 if ( Ii1o0O00ooo . find ( "vxlan" ) == - 1 ) :
  lprint ( "No VXLAN interface found, cannot program hardware" )
  return
  if 87 - 87: Ii1I % o0oOOo0O0Ooo . ooOoO0o * iIii1I11I1II1 * i11iIiiIii * i11iIiiIii
 if ( Ii1o0O00ooo . find ( "vlan4094" ) == - 1 ) :
  lprint ( "No vlan4094 interface found, cannot program hardware" )
  return
  if 74 - 74: ooOoO0o * OOooOOo . I1ii11iIi11i
 O0O0iIIi11Ii = commands . getoutput ( "ip addr | egrep vlan4094 | egrep inet" )
 if ( O0O0iIIi11Ii == "" ) :
  lprint ( "No IP address found on vlan4094, cannot program hardware" )
  return
  if 41 - 41: OoO0O00 % Oo0Ooo - oO0o + OoO0O00 / OOooOOo
 O0O0iIIi11Ii = O0O0iIIi11Ii . split ( "inet " ) [ 1 ]
 O0O0iIIi11Ii = O0O0iIIi11Ii . split ( "/" ) [ 0 ]
 if 74 - 74: ooOoO0o . oO0o - Oo0Ooo % OOooOOo
 if 15 - 15: o0oOOo0O0Ooo - Oo0Ooo / IiII
 if 94 - 94: Ii1I + o0oOOo0O0Ooo / II111iiii
 if 18 - 18: I1IiiI
 if 27 - 27: ooOoO0o
 if 20 - 20: OoooooooOO * OOooOOo
 if 77 - 77: Ii1I - OoooooooOO . OoOoOO00
 oo00o = [ ]
 o000 = commands . getoutput ( "arp -i vlan4094" ) . split ( "\n" )
 for oOOo0ooO0 in o000 :
  if ( oOOo0ooO0 . find ( "vlan4094" ) == - 1 ) : continue
  if ( oOOo0ooO0 . find ( "(incomplete)" ) == - 1 ) : continue
  O0O0O = oOOo0ooO0 . split ( " " ) [ 0 ]
  oo00o . append ( O0O0O )
  if 53 - 53: I11i . i11iIiiIii - iIii1I11I1II1 / I1Ii111
  if 86 - 86: i1IIi % OoO0O00 - OoooooooOO
 O0O0O = None
 OooO0o000Oo = O0O0iIIi11Ii
 O0O0iIIi11Ii = O0O0iIIi11Ii . split ( "." )
 for IiIIi1IiiIiI in range ( 1 , 255 ) :
  O0O0iIIi11Ii [ 3 ] = str ( IiIIi1IiiIiI )
  IiiIIi1 = "." . join ( O0O0iIIi11Ii )
  if ( IiiIIi1 in oo00o ) : continue
  if ( IiiIIi1 == OooO0o000Oo ) : continue
  O0O0O = IiiIIi1
  break
  if 63 - 63: o0oOOo0O0Ooo . iIii1I11I1II1 % IiII * i11iIiiIii
 if ( O0O0O == None ) :
  lprint ( "Address allocation failed for vlan4094, cannot program " + "hardware" )
  if 70 - 70: iIii1I11I1II1
  return
  if 12 - 12: OoOoOO00 / o0oOOo0O0Ooo - I1ii11iIi11i + oO0o + O0
  if 9 - 9: I1ii11iIi11i * OoooooooOO . O0 . ooOoO0o * i11iIiiIii / i1IIi
  if 38 - 38: OoOoOO00 . OoooooooOO % I1ii11iIi11i . oO0o % oO0o
  if 80 - 80: i11iIiiIii / OoOoOO00 . OOooOOo . iIii1I11I1II1
  if 81 - 81: I1ii11iIi11i * OoO0O00 . o0oOOo0O0Ooo . OoooooooOO
  if 64 - 64: Oo0Ooo . I1ii11iIi11i / ooOoO0o % oO0o . iIii1I11I1II1
  if 84 - 84: II111iiii . oO0o * O0 / iII111i + OoooooooOO
 OOOooOo0O = I1IIiIIIii . split ( "." )
 OOoo0oo0oO0O = lisp_hex_string ( OOOooOo0O [ 1 ] ) . zfill ( 2 )
 OoOo0O0O00O000o = lisp_hex_string ( OOOooOo0O [ 2 ] ) . zfill ( 2 )
 iIo0o000OOO00O = lisp_hex_string ( OOOooOo0O [ 3 ] ) . zfill ( 2 )
 Ii = "00:00:00:{}:{}:{}" . format ( OOoo0oo0oO0O , OoOo0O0O00O000o , iIo0o000OOO00O )
 IIiIiii1I1i = "0000.00{}.{}{}" . format ( OOoo0oo0oO0O , OoOo0O0O00O000o , iIo0o000OOO00O )
 iIIiiiiii = "arp -i vlan4094 -s {} {}" . format ( O0O0O , Ii )
 os . system ( iIIiiiiii )
 if 34 - 34: I1Ii111 . IiII % iII111i
 if 94 - 94: OOooOOo % i11iIiiIii . OOooOOo
 if 55 - 55: OoOoOO00 . OoOoOO00 % o0oOOo0O0Ooo . I11i . I1ii11iIi11i - o0oOOo0O0Ooo
 if 1 - 1: i11iIiiIii - i1IIi * oO0o - iIii1I11I1II1
 oooOoOOOooOo = ( "mac address-table static {} vlan 4094 " + "interface vxlan 1 vtep {}" ) . format ( IIiIiii1I1i , I1IIiIIIii )
 if 14 - 14: OoOoOO00 . II111iiii / iII111i / oO0o - oO0o
 lisp_send_to_arista ( oooOoOOOooOo , None )
 if 12 - 12: O0
 if 77 - 77: oO0o % o0oOOo0O0Ooo % iII111i
 if 28 - 28: OoOoOO00 . O0 - II111iiii - I1IiiI / OOooOOo % O0
 if 49 - 49: ooOoO0o % Ii1I
 if 86 - 86: o0oOOo0O0Ooo - I1IiiI . II111iiii . I1Ii111
 iIIiIi1ii1i1 = "ip route add {} via {}" . format ( IiI1Iiii , O0O0O )
 os . system ( iIIiIi1ii1i1 )
 if 97 - 97: i1IIi / i1IIi + I1IiiI % oO0o - iIii1I11I1II1
 lprint ( "Hardware programmed with commands:" )
 iIIiIi1ii1i1 = iIIiIi1ii1i1 . replace ( IiI1Iiii , green ( IiI1Iiii , False ) )
 lprint ( "  " + iIIiIi1ii1i1 )
 lprint ( "  " + iIIiiiiii )
 oooOoOOOooOo = oooOoOOOooOo . replace ( I1IIiIIIii , red ( I1IIiIIIii , False ) )
 lprint ( "  " + oooOoOOOooOo )
 return
 if 55 - 55: OoooooooOO % II111iiii - o0oOOo0O0Ooo
 if 86 - 86: II111iiii - OOooOOo + o0oOOo0O0Ooo
 if 26 - 26: oO0o / I1ii11iIi11i - oO0o
 if 9 - 9: ooOoO0o * iIii1I11I1II1 * OoooooooOO
 if 13 - 13: iII111i . i11iIiiIii * o0oOOo0O0Ooo . iII111i
 if 96 - 96: Ii1I
 if 90 - 90: II111iiii
def lisp_clear_hardware_walk ( mc , parms ) :
 II11IIi1Ii1i = mc . eid . print_prefix_no_iid ( )
 os . system ( "ip route delete {}" . format ( II11IIi1Ii1i ) )
 return ( [ True , None ] )
 if 93 - 93: i11iIiiIii / Ii1I * Oo0Ooo . iII111i % iII111i / IiII
 if 15 - 15: OoOoOO00 % I1Ii111 - iIii1I11I1II1
 if 52 - 52: i11iIiiIii * ooOoO0o
 if 15 - 15: OoooooooOO . oO0o . i11iIiiIii / o0oOOo0O0Ooo
 if 91 - 91: ooOoO0o
 if 47 - 47: II111iiii + I11i + ooOoO0o % Oo0Ooo / iII111i
 if 9 - 9: O0 + IiII
 if 69 - 69: I1IiiI
def lisp_clear_map_cache ( ) :
 global lisp_map_cache , lisp_rloc_probe_list
 global lisp_crypto_keys_by_rloc_encap , lisp_crypto_keys_by_rloc_decap
 global lisp_rtr_list , lisp_gleaned_groups
 global lisp_no_map_request_rate_limit
 if 11 - 11: I11i % I1Ii111 + O0 . Ii1I . I1ii11iIi11i % I1Ii111
 I1IOoOO0000OOoO = bold ( "User cleared" , False )
 I1I1 = lisp_map_cache . cache_count
 lprint ( "{} map-cache with {} entries" . format ( I1IOoOO0000OOoO , I1I1 ) )
 if 80 - 80: IiII % I1Ii111
 if ( lisp_program_hardware ) :
  lisp_map_cache . walk_cache ( lisp_clear_hardware_walk , None )
  if 86 - 86: I1IiiI
 lisp_map_cache = lisp_cache ( )
 if 76 - 76: OOooOOo + OoOoOO00
 if 100 - 100: I11i . II111iiii + IiII . I11i . OoooooooOO
 if 16 - 16: i1IIi + OoOoOO00 / oO0o * OoOoOO00
 if 57 - 57: ooOoO0o * ooOoO0o + I11i + i11iIiiIii % I1Ii111 * I1IiiI
 lisp_no_map_request_rate_limit = lisp_get_timestamp ( )
 if 73 - 73: Oo0Ooo * iIii1I11I1II1 - II111iiii
 if 16 - 16: iIii1I11I1II1 / O0 - o0oOOo0O0Ooo + ooOoO0o * I1IiiI / i1IIi
 if 28 - 28: I1Ii111 . OoooooooOO
 if 56 - 56: I1ii11iIi11i + i1IIi * I1Ii111 / ooOoO0o - I1ii11iIi11i . I11i
 if 25 - 25: Oo0Ooo / o0oOOo0O0Ooo + I1IiiI - I11i / i11iIiiIii
 lisp_rloc_probe_list = { }
 if 89 - 89: II111iiii
 if 2 - 2: OoOoOO00 . i11iIiiIii
 if 11 - 11: Ii1I
 if 82 - 82: I11i - i1IIi . Oo0Ooo * I1Ii111
 lisp_crypto_keys_by_rloc_encap = { }
 lisp_crypto_keys_by_rloc_decap = { }
 if 44 - 44: iII111i
 if 56 - 56: II111iiii / Oo0Ooo % IiII * II111iiii - iIii1I11I1II1 + ooOoO0o
 if 33 - 33: o0oOOo0O0Ooo . I11i / I1IiiI
 if 29 - 29: o0oOOo0O0Ooo - ooOoO0o
 if 59 - 59: I11i / IiII * OoO0O00 / IiII . I1Ii111
 lisp_rtr_list = { }
 if 82 - 82: OOooOOo . iIii1I11I1II1 + I1Ii111
 if 14 - 14: IiII . i11iIiiIii
 if 17 - 17: ooOoO0o % ooOoO0o * oO0o
 if 8 - 8: ooOoO0o + OoO0O00 . II111iiii / iIii1I11I1II1 - OOooOOo
 lisp_gleaned_groups = { }
 if 87 - 87: iIii1I11I1II1 . IiII % I1IiiI . OoO0O00 - I1Ii111
 if 53 - 53: I1Ii111 % i11iIiiIii
 if 99 - 99: I1IiiI - i1IIi * i11iIiiIii + OoO0O00
 if 80 - 80: o0oOOo0O0Ooo . I11i % iIii1I11I1II1 + OoOoOO00
 lisp_process_data_plane_restart ( True )
 return
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
def lisp_encapsulate_rloc_probe ( lisp_sockets , rloc , nat_info , packet ) :
 if ( len ( lisp_sockets ) != 4 ) : return
 if 90 - 90: IiII - OOooOOo + iIii1I11I1II1
 O0oO00O00oo0o = lisp_myrlocs [ 0 ]
 if 53 - 53: ooOoO0o
 if 58 - 58: OoOoOO00 - i11iIiiIii / OOooOOo . Oo0Ooo
 if 54 - 54: IiII * i11iIiiIii . ooOoO0o . Ii1I
 if 60 - 60: Oo0Ooo % I11i - OoOoOO00 % II111iiii
 if 82 - 82: OoooooooOO % IiII / i11iIiiIii
 IiiI1iii1iIiiI = len ( packet ) + 28
 Ooo0oO = struct . pack ( "BBHIBBHII" , 0x45 , 0 , socket . htons ( IiiI1iii1iIiiI ) , 0 , 64 ,
 17 , 0 , socket . htonl ( O0oO00O00oo0o . address ) , socket . htonl ( rloc . address ) )
 Ooo0oO = lisp_ip_checksum ( Ooo0oO )
 if 100 - 100: Ii1I / I1ii11iIi11i + OOooOOo + I1Ii111 / IiII
 o0oOo00 = struct . pack ( "HHHH" , 0 , socket . htons ( LISP_CTRL_PORT ) ,
 socket . htons ( IiiI1iii1iIiiI - 20 ) , 0 )
 if 13 - 13: IiII + iII111i . I1Ii111 - iII111i - o0oOOo0O0Ooo
 if 72 - 72: II111iiii . I11i % I1Ii111 % I1ii11iIi11i
 if 9 - 9: OoOoOO00 * II111iiii
 if 21 - 21: OoooooooOO
 packet = lisp_packet ( Ooo0oO + o0oOo00 + packet )
 if 34 - 34: i11iIiiIii / I1Ii111 - o0oOOo0O0Ooo / i1IIi * I11i
 if 87 - 87: IiII / I1IiiI . OoOoOO00
 if 80 - 80: i1IIi + OOooOOo % i11iIiiIii * I1ii11iIi11i
 if 49 - 49: iIii1I11I1II1
 packet . inner_dest . copy_address ( rloc )
 packet . inner_dest . instance_id = 0xffffff
 packet . inner_source . copy_address ( O0oO00O00oo0o )
 packet . inner_ttl = 64
 packet . outer_dest . copy_address ( rloc )
 packet . outer_source . copy_address ( O0oO00O00oo0o )
 packet . outer_version = packet . outer_dest . afi_to_version ( )
 packet . outer_ttl = 64
 packet . encap_port = nat_info . port if nat_info else LISP_DATA_PORT
 if 2 - 2: OOooOOo * o0oOOo0O0Ooo - OOooOOo . I11i
 o0oooOoOoOo = red ( rloc . print_address_no_iid ( ) , False )
 if ( nat_info ) :
  III1i = " {}" . format ( blue ( nat_info . hostname , False ) )
  oO0oo000O = bold ( "RLOC-probe request" , False )
 else :
  III1i = ""
  oO0oo000O = bold ( "RLOC-probe reply" , False )
  if 32 - 32: OoO0O00
  if 34 - 34: O0 * iIii1I11I1II1 . o0oOOo0O0Ooo . I1Ii111 . iIii1I11I1II1 * iIii1I11I1II1
 lprint ( ( "Data encapsulate {} to {}{} port {} for " + "NAT-traversal" ) . format ( oO0oo000O , o0oooOoOoOo , III1i , packet . encap_port ) )
 if 38 - 38: iIii1I11I1II1
 if 83 - 83: iII111i - Ii1I . oO0o - I1Ii111 * o0oOOo0O0Ooo
 if 70 - 70: i11iIiiIii - OoO0O00 / i11iIiiIii
 if 46 - 46: II111iiii + O0 * OoooooooOO
 if 39 - 39: OoooooooOO % II111iiii . o0oOOo0O0Ooo
 if ( packet . encode ( None ) == None ) : return
 packet . print_packet ( "Send" , True )
 if 29 - 29: I11i . o0oOOo0O0Ooo . i1IIi . o0oOOo0O0Ooo
 oooOOOO = lisp_sockets [ 3 ]
 packet . send_packet ( oooOOOO , packet . outer_dest )
 del ( packet )
 return
 if 70 - 70: I1IiiI % ooOoO0o / OoOoOO00 - OOooOOo * I11i / OoO0O00
 if 84 - 84: O0 - O0 / I1ii11iIi11i * iII111i
 if 34 - 34: I1ii11iIi11i * i1IIi - IiII . oO0o / ooOoO0o / oO0o
 if 86 - 86: Ii1I - O0 * I1ii11iIi11i + Ii1I + IiII / O0
 if 10 - 10: I11i
 if 59 - 59: Ii1I - o0oOOo0O0Ooo
 if 85 - 85: iIii1I11I1II1
 if 29 - 29: ooOoO0o - OoOoOO00 - o0oOOo0O0Ooo
def lisp_get_default_route_next_hops ( ) :
 if 54 - 54: Ii1I + i11iIiiIii + i1IIi - OoooooooOO
 if 100 - 100: oO0o . ooOoO0o
 if 14 - 14: OoooooooOO + iII111i / iIii1I11I1II1 / ooOoO0o % iIii1I11I1II1 - IiII
 if 34 - 34: I1ii11iIi11i + i11iIiiIii - I1ii11iIi11i / OoOoOO00 + i1IIi . i11iIiiIii
 if ( lisp_is_macos ( ) ) :
  ooO0ooooO = "route -n get default"
  II1I1I1IiiI = commands . getoutput ( ooO0ooooO ) . split ( "\n" )
  OO00oo = II1i = None
  for OOO000 in II1I1I1IiiI :
   if ( OOO000 . find ( "gateway: " ) != - 1 ) : OO00oo = OOO000 . split ( ": " ) [ 1 ]
   if ( OOO000 . find ( "interface: " ) != - 1 ) : II1i = OOO000 . split ( ": " ) [ 1 ]
   if 71 - 71: I1Ii111 % Ii1I - I11i / I11i - Ii1I
  return ( [ [ II1i , OO00oo ] ] )
  if 54 - 54: Oo0Ooo . OoO0O00 * iII111i . i1IIi - o0oOOo0O0Ooo
  if 33 - 33: Ii1I - oO0o . iII111i * I1ii11iIi11i
  if 78 - 78: oO0o % ooOoO0o
  if 37 - 37: iIii1I11I1II1 + Oo0Ooo + OoO0O00 . I11i % iIii1I11I1II1 + I1Ii111
  if 48 - 48: II111iiii . OOooOOo . ooOoO0o - iII111i
 ooO0ooooO = "ip route | egrep 'default via'"
 IIiIiII = commands . getoutput ( ooO0ooooO ) . split ( "\n" )
 if 90 - 90: OOooOOo
 I1Ii1iiII1 = [ ]
 for o0O00OOo in IIiIiII :
  if ( o0O00OOo . find ( " metric " ) != - 1 ) : continue
  O0OOOO0o0O = o0O00OOo . split ( " " )
  try :
   i11iii = O0OOOO0o0O . index ( "via" ) + 1
   if ( i11iii >= len ( O0OOOO0o0O ) ) : continue
   oOooii111 = O0OOOO0o0O . index ( "dev" ) + 1
   if ( oOooii111 >= len ( O0OOOO0o0O ) ) : continue
  except :
   continue
   if 90 - 90: iII111i . Oo0Ooo * o0oOOo0O0Ooo % I11i . OoOoOO00
   if 63 - 63: I1ii11iIi11i + OoOoOO00 - Ii1I + OoO0O00 - II111iiii
  I1Ii1iiII1 . append ( [ O0OOOO0o0O [ oOooii111 ] , O0OOOO0o0O [ i11iii ] ] )
  if 47 - 47: I1IiiI * O0 + I1ii11iIi11i - OOooOOo
 return ( I1Ii1iiII1 )
 if 24 - 24: i1IIi / i1IIi + I11i * II111iiii / IiII
 if 8 - 8: I11i . I11i + I11i % OoooooooOO / ooOoO0o
 if 25 - 25: I1IiiI / OoO0O00
 if 92 - 92: oO0o % I1IiiI / OoO0O00 - I11i
 if 36 - 36: i1IIi * iIii1I11I1II1 + I1ii11iIi11i + iII111i - II111iiii
 if 48 - 48: oO0o + OoOoOO00 - OoO0O00 . II111iiii * i11iIiiIii . OoooooooOO
 if 37 - 37: OoooooooOO + O0 . I11i % OoOoOO00
def lisp_get_host_route_next_hop ( rloc ) :
 ooO0ooooO = "ip route | egrep '{} via'" . format ( rloc )
 o0O00OOo = commands . getoutput ( ooO0ooooO ) . split ( " " )
 if 57 - 57: I1Ii111 . OOooOOo + I1Ii111 . iIii1I11I1II1 / oO0o / O0
 try : ooo = o0O00OOo . index ( "via" ) + 1
 except : return ( None )
 if 88 - 88: I1Ii111
 if ( ooo >= len ( o0O00OOo ) ) : return ( None )
 return ( o0O00OOo [ ooo ] )
 if 16 - 16: Oo0Ooo . ooOoO0o / OoO0O00 / o0oOOo0O0Ooo . OoooooooOO * OoO0O00
 if 50 - 50: II111iiii + I11i . OoooooooOO . I1Ii111 - OOooOOo
 if 83 - 83: oO0o
 if 100 - 100: I1Ii111 + o0oOOo0O0Ooo * oO0o / oO0o . oO0o + iII111i
 if 71 - 71: II111iiii + iII111i + O0 % Oo0Ooo / I1IiiI
 if 52 - 52: Oo0Ooo . I1Ii111 * i1IIi / Oo0Ooo / OoO0O00
 if 29 - 29: iII111i
def lisp_install_host_route ( dest , nh , install ) :
 install = "add" if install else "delete"
 I1Iii1I1 = "none" if nh == None else nh
 if 91 - 91: Oo0Ooo - IiII
 lprint ( "{} host-route {}, nh {}" . format ( install . title ( ) , dest , I1Iii1I1 ) )
 if 47 - 47: iII111i / OOooOOo + iII111i
 if ( nh == None ) :
  iIIIIiiII = "ip route {} {}/32" . format ( install , dest )
 else :
  iIIIIiiII = "ip route {} {}/32 via {}" . format ( install , dest , nh )
  if 69 - 69: I1IiiI . I1ii11iIi11i
 os . system ( iIIIIiiII )
 return
 if 18 - 18: I11i * I1IiiI
 if 42 - 42: i1IIi . I1Ii111 - ooOoO0o + I11i / oO0o
 if 60 - 60: i1IIi + OoooooooOO % i11iIiiIii / IiII % Oo0Ooo + I1IiiI
 if 87 - 87: Ii1I % OoooooooOO % I1Ii111 * i11iIiiIii * OoOoOO00
 if 78 - 78: I11i
 if 62 - 62: iIii1I11I1II1 . o0oOOo0O0Ooo . ooOoO0o % oO0o % O0 % oO0o
 if 51 - 51: Oo0Ooo / IiII - Oo0Ooo
 if 71 - 71: I11i * I1ii11iIi11i * OOooOOo * o0oOOo0O0Ooo
def lisp_checkpoint ( checkpoint_list ) :
 if ( lisp_checkpoint_map_cache == False ) : return
 if 53 - 53: I1IiiI % I1IiiI
 OOO000 = open ( lisp_checkpoint_filename , "w" )
 for i1ii1i1Ii11 in checkpoint_list :
  OOO000 . write ( i1ii1i1Ii11 + "\n" )
  if 80 - 80: OoO0O00 - i11iIiiIii / iII111i * I1ii11iIi11i / I1IiiI - I1Ii111
 OOO000 . close ( )
 lprint ( "{} {} entries to file '{}'" . format ( bold ( "Checkpoint" , False ) ,
 len ( checkpoint_list ) , lisp_checkpoint_filename ) )
 return
 if 85 - 85: IiII
 if 72 - 72: iII111i * OoOoOO00
 if 65 - 65: iIii1I11I1II1 / iIii1I11I1II1 % O0 / II111iiii . OOooOOo . O0
 if 65 - 65: I11i
 if 35 - 35: o0oOOo0O0Ooo - i11iIiiIii
 if 78 - 78: ooOoO0o - II111iiii - i1IIi
 if 18 - 18: OoooooooOO % OoOoOO00 - IiII / oO0o . OOooOOo . I1IiiI
 if 77 - 77: I1ii11iIi11i . OoO0O00 / OoOoOO00 / O0
def lisp_load_checkpoint ( ) :
 if ( lisp_checkpoint_map_cache == False ) : return
 if ( os . path . exists ( lisp_checkpoint_filename ) == False ) : return
 if 67 - 67: ooOoO0o % I11i % oO0o
 OOO000 = open ( lisp_checkpoint_filename , "r" )
 if 74 - 74: II111iiii
 I1I1 = 0
 for i1ii1i1Ii11 in OOO000 :
  I1I1 += 1
  oOo = i1ii1i1Ii11 . split ( " rloc " )
  ooOOo = [ ] if ( oOo [ 1 ] in [ "native-forward\n" , "\n" ] ) else oOo [ 1 ] . split ( ", " )
  if 44 - 44: Oo0Ooo + OoO0O00 + OoOoOO00 - I1IiiI
  if 68 - 68: i11iIiiIii / OOooOOo . i1IIi . i11iIiiIii . I11i
  o0oo0OoOo000 = [ ]
  for I1IIiIIIii in ooOOo :
   O0OooOoooO0O = lisp_rloc ( False )
   O0OOOO0o0O = I1IIiIIIii . split ( " " )
   O0OooOoooO0O . rloc . store_address ( O0OOOO0o0O [ 0 ] )
   O0OooOoooO0O . priority = int ( O0OOOO0o0O [ 1 ] )
   O0OooOoooO0O . weight = int ( O0OOOO0o0O [ 2 ] )
   o0oo0OoOo000 . append ( O0OooOoooO0O )
   if 56 - 56: iIii1I11I1II1 - II111iiii * i1IIi / Ii1I
   if 65 - 65: OOooOOo / I1IiiI . OoooooooOO + I1IiiI + OoooooooOO + i11iIiiIii
  iiI1iIi1II1ii = lisp_mapping ( "" , "" , o0oo0OoOo000 )
  if ( iiI1iIi1II1ii != None ) :
   iiI1iIi1II1ii . eid . store_prefix ( oOo [ 0 ] )
   iiI1iIi1II1ii . checkpoint_entry = True
   iiI1iIi1II1ii . map_cache_ttl = LISP_NMR_TTL * 60
   if ( o0oo0OoOo000 == [ ] ) : iiI1iIi1II1ii . action = LISP_NATIVE_FORWARD_ACTION
   iiI1iIi1II1ii . add_cache ( )
   continue
   if 20 - 20: I1IiiI + iII111i + O0 * O0
   if 18 - 18: I11i - I11i . OoOoOO00 . ooOoO0o
  I1I1 -= 1
  if 31 - 31: ooOoO0o
  if 87 - 87: OoooooooOO + OOooOOo - I1ii11iIi11i / I1IiiI + ooOoO0o - Oo0Ooo
 OOO000 . close ( )
 lprint ( "{} {} map-cache entries from file '{}'" . format (
 bold ( "Loaded" , False ) , I1I1 , lisp_checkpoint_filename ) )
 return
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
 if 94 - 94: OoooooooOO + II111iiii % ooOoO0o - II111iiii / O0
 if 34 - 34: IiII % oO0o
 if 54 - 54: I1IiiI
 if 80 - 80: OoOoOO00 . I1IiiI / I1ii11iIi11i . iII111i
def lisp_write_checkpoint_entry ( checkpoint_list , mc ) :
 if ( lisp_checkpoint_map_cache == False ) : return
 if 31 - 31: I11i * o0oOOo0O0Ooo
 i1ii1i1Ii11 = "{} rloc " . format ( mc . eid . print_prefix ( ) )
 if 17 - 17: Ii1I * iIii1I11I1II1
 for O0OooOoooO0O in mc . rloc_set :
  if ( O0OooOoooO0O . rloc . is_null ( ) ) : continue
  i1ii1i1Ii11 += "{} {} {}, " . format ( O0OooOoooO0O . rloc . print_address_no_iid ( ) ,
 O0OooOoooO0O . priority , O0OooOoooO0O . weight )
  if 9 - 9: o0oOOo0O0Ooo - IiII
  if 78 - 78: i11iIiiIii . o0oOOo0O0Ooo
 if ( mc . rloc_set != [ ] ) :
  i1ii1i1Ii11 = i1ii1i1Ii11 [ 0 : - 2 ]
 elif ( mc . action == LISP_NATIVE_FORWARD_ACTION ) :
  i1ii1i1Ii11 += "native-forward"
  if 72 - 72: Oo0Ooo % II111iiii + O0 * OoOoOO00 - OOooOOo + I1Ii111
  if 23 - 23: I1IiiI - O0 - iII111i . II111iiii / oO0o
 checkpoint_list . append ( i1ii1i1Ii11 )
 return
 if 1 - 1: I11i . OOooOOo / oO0o % I11i * Oo0Ooo + Oo0Ooo
 if 23 - 23: Ii1I % i1IIi - I1Ii111
 if 95 - 95: OoOoOO00 - ooOoO0o . i1IIi . OoooooooOO
 if 38 - 38: I1IiiI + I1ii11iIi11i - Oo0Ooo . i11iIiiIii - i1IIi
 if 11 - 11: IiII / I1IiiI . I1IiiI
 if 87 - 87: OoooooooOO * OoO0O00 * iIii1I11I1II1
 if 16 - 16: o0oOOo0O0Ooo * I11i + OoooooooOO + O0 / iIii1I11I1II1
def lisp_check_dp_socket ( ) :
 O0000o000o = lisp_ipc_dp_socket_name
 if ( os . path . exists ( O0000o000o ) == False ) :
  IIII1IIiiIiI1 = bold ( "does not exist" , False )
  lprint ( "Socket '{}' {}" . format ( O0000o000o , IIII1IIiiIiI1 ) )
  return ( False )
  if 66 - 66: I1Ii111 . ooOoO0o - OoOoOO00 + oO0o . OoO0O00
 return ( True )
 if 88 - 88: OOooOOo - ooOoO0o * o0oOOo0O0Ooo . OoooooooOO
 if 3 - 3: I1Ii111
 if 24 - 24: Ii1I + i11iIiiIii * I1Ii111 - OoOoOO00 / Ii1I - OoOoOO00
 if 69 - 69: I11i - I1IiiI . oO0o - OoooooooOO
 if 33 - 33: o0oOOo0O0Ooo - o0oOOo0O0Ooo
 if 55 - 55: OoooooooOO / IiII + i1IIi
 if 54 - 54: ooOoO0o * Ii1I / Ii1I
def lisp_write_to_dp_socket ( entry ) :
 try :
  iI1iII11I1ii1 = json . dumps ( entry )
  iIIiIII = bold ( "Write IPC" , False )
  lprint ( "{} record to named socket: '{}'" . format ( iIIiIII , iI1iII11I1ii1 ) )
  lisp_ipc_dp_socket . sendto ( iI1iII11I1ii1 , lisp_ipc_dp_socket_name )
 except :
  lprint ( "Failed to write IPC record to named socket: '{}'" . format ( iI1iII11I1ii1 ) )
  if 17 - 17: Ii1I . Oo0Ooo - oO0o % OOooOOo
 return
 if 59 - 59: O0
 if 75 - 75: o0oOOo0O0Ooo / OoooooooOO . I1ii11iIi11i * oO0o * I11i / OoooooooOO
 if 17 - 17: Ii1I % I1ii11iIi11i + I11i
 if 80 - 80: i1IIi . OoooooooOO % OoooooooOO . oO0o / OOooOOo
 if 85 - 85: OOooOOo
 if 80 - 80: ooOoO0o % O0 % I1ii11iIi11i + Oo0Ooo
 if 82 - 82: oO0o / iIii1I11I1II1 % ooOoO0o . Ii1I / i1IIi - I1Ii111
 if 15 - 15: I11i - OOooOOo . II111iiii . iIii1I11I1II1
 if 93 - 93: I11i + o0oOOo0O0Ooo / OOooOOo + Ii1I % Oo0Ooo % I1ii11iIi11i
def lisp_write_ipc_keys ( rloc ) :
 oo0o00OO = rloc . rloc . print_address_no_iid ( )
 Oo0O00O = rloc . translated_port
 if ( Oo0O00O != 0 ) : oo0o00OO += ":" + str ( Oo0O00O )
 if ( lisp_rloc_probe_list . has_key ( oo0o00OO ) == False ) : return
 if 72 - 72: IiII / II111iiii
 for O0OOOO0o0O , oOo , i11ii in lisp_rloc_probe_list [ oo0o00OO ] :
  iiI1iIi1II1ii = lisp_map_cache . lookup_cache ( oOo , True )
  if ( iiI1iIi1II1ii == None ) : continue
  lisp_write_ipc_map_cache ( True , iiI1iIi1II1ii )
  if 25 - 25: i1IIi + OoOoOO00 + oO0o + OoooooooOO
 return
 if 21 - 21: I1ii11iIi11i
 if 60 - 60: i1IIi / OoO0O00 . Ii1I
 if 16 - 16: i11iIiiIii + OoOoOO00 % Oo0Ooo + I1ii11iIi11i * Ii1I / I1Ii111
 if 26 - 26: iII111i
 if 31 - 31: iII111i
 if 45 - 45: OoO0O00
 if 55 - 55: iIii1I11I1II1 % iIii1I11I1II1 + I11i - ooOoO0o + I1IiiI * O0
def lisp_write_ipc_map_cache ( add_or_delete , mc , dont_send = False ) :
 if ( lisp_i_am_etr ) : return
 if ( lisp_ipc_dp_socket == None ) : return
 if ( lisp_check_dp_socket ( ) == False ) : return
 if 47 - 47: ooOoO0o + iIii1I11I1II1 * OOooOOo . I1IiiI . o0oOOo0O0Ooo
 if 49 - 49: Oo0Ooo . OoOoOO00 * OOooOOo
 if 86 - 86: IiII * OOooOOo + Ii1I
 if 62 - 62: I11i
 IiI1III = "add" if add_or_delete else "delete"
 i1ii1i1Ii11 = { "type" : "map-cache" , "opcode" : IiI1III }
 if 86 - 86: Oo0Ooo % II111iiii + I1Ii111 / I1ii11iIi11i
 I11IiI1I1 = ( mc . group . is_null ( ) == False )
 if ( I11IiI1I1 ) :
  i1ii1i1Ii11 [ "eid-prefix" ] = mc . group . print_prefix_no_iid ( )
  i1ii1i1Ii11 [ "rles" ] = [ ]
 else :
  i1ii1i1Ii11 [ "eid-prefix" ] = mc . eid . print_prefix_no_iid ( )
  i1ii1i1Ii11 [ "rlocs" ] = [ ]
  if 15 - 15: I1IiiI / I1Ii111 % iII111i
 i1ii1i1Ii11 [ "instance-id" ] = str ( mc . eid . instance_id )
 if 57 - 57: I1Ii111 . iIii1I11I1II1 / Oo0Ooo / IiII / iII111i * OoOoOO00
 if ( I11IiI1I1 ) :
  if ( len ( mc . rloc_set ) >= 1 and mc . rloc_set [ 0 ] . rle ) :
   for Iii in mc . rloc_set [ 0 ] . rle . rle_forwarding_list :
    IiiIIi1 = Iii . address . print_address_no_iid ( )
    Oo0O00O = str ( 4341 ) if Iii . translated_port == 0 else str ( Iii . translated_port )
    if 35 - 35: i1IIi + I1Ii111 - ooOoO0o . I1ii11iIi11i + Oo0Ooo
    O0OOOO0o0O = { "rle" : IiiIIi1 , "port" : Oo0O00O }
    II11iI11i1 , iI1ii = Iii . get_encap_keys ( )
    O0OOOO0o0O = lisp_build_json_keys ( O0OOOO0o0O , II11iI11i1 , iI1ii , "encrypt-key" )
    i1ii1i1Ii11 [ "rles" ] . append ( O0OOOO0o0O )
    if 28 - 28: OoO0O00 / ooOoO0o % OoOoOO00 - Ii1I * i11iIiiIii + I1ii11iIi11i
    if 90 - 90: ooOoO0o * o0oOOo0O0Ooo + Ii1I / I11i % II111iiii
 else :
  for I1IIiIIIii in mc . rloc_set :
   if ( I1IIiIIIii . rloc . is_ipv4 ( ) == False and I1IIiIIIii . rloc . is_ipv6 ( ) == False ) :
    continue
    if 59 - 59: I11i + iII111i + I11i
   if ( I1IIiIIIii . up_state ( ) == False ) : continue
   if 84 - 84: I1IiiI * Ii1I . I1IiiI % OOooOOo * Ii1I % OoO0O00
   Oo0O00O = str ( 4341 ) if I1IIiIIIii . translated_port == 0 else str ( I1IIiIIIii . translated_port )
   if 72 - 72: OoOoOO00 + o0oOOo0O0Ooo - i1IIi - OoO0O00 % OoOoOO00
   O0OOOO0o0O = { "rloc" : I1IIiIIIii . rloc . print_address_no_iid ( ) , "priority" :
 str ( I1IIiIIIii . priority ) , "weight" : str ( I1IIiIIIii . weight ) , "port" :
 Oo0O00O }
   II11iI11i1 , iI1ii = I1IIiIIIii . get_encap_keys ( )
   O0OOOO0o0O = lisp_build_json_keys ( O0OOOO0o0O , II11iI11i1 , iI1ii , "encrypt-key" )
   i1ii1i1Ii11 [ "rlocs" ] . append ( O0OOOO0o0O )
   if 42 - 42: oO0o / i1IIi . IiII
   if 12 - 12: i11iIiiIii . ooOoO0o
   if 80 - 80: O0 / iIii1I11I1II1 % iII111i * ooOoO0o / i11iIiiIii . OoOoOO00
 if ( dont_send == False ) : lisp_write_to_dp_socket ( i1ii1i1Ii11 )
 return ( i1ii1i1Ii11 )
 if 88 - 88: OoooooooOO . I1IiiI
 if 6 - 6: I1Ii111 - i11iIiiIii - oO0o
 if 7 - 7: i1IIi
 if 6 - 6: OoooooooOO - Oo0Ooo - I1ii11iIi11i
 if 34 - 34: iII111i + i11iIiiIii . IiII
 if 54 - 54: Oo0Ooo + I11i - iII111i * ooOoO0o % i11iIiiIii . IiII
 if 29 - 29: II111iiii % i11iIiiIii % O0
def lisp_write_ipc_decap_key ( rloc_addr , keys ) :
 if ( lisp_i_am_itr ) : return
 if ( lisp_ipc_dp_socket == None ) : return
 if ( lisp_check_dp_socket ( ) == False ) : return
 if 38 - 38: o0oOOo0O0Ooo * IiII
 if 51 - 51: OoooooooOO . Ii1I % OoooooooOO - I1IiiI + I1Ii111 % oO0o
 if 28 - 28: i11iIiiIii - I1IiiI * OoO0O00
 if 19 - 19: OoooooooOO
 if ( keys == None or len ( keys ) == 0 or keys [ 1 ] == None ) : return
 if 34 - 34: OoOoOO00 . oO0o
 II11iI11i1 = keys [ 1 ] . encrypt_key
 iI1ii = keys [ 1 ] . icv_key
 if 53 - 53: oO0o + OoooooooOO * ooOoO0o
 if 85 - 85: I1ii11iIi11i - o0oOOo0O0Ooo % o0oOOo0O0Ooo % iII111i * OoOoOO00
 if 50 - 50: I1Ii111 + I1Ii111 + I11i - OoOoOO00
 if 65 - 65: oO0o / I11i + iII111i - I1ii11iIi11i
 oooO0000OoOOooo = rloc_addr . split ( ":" )
 if ( len ( oooO0000OoOOooo ) == 1 ) :
  i1ii1i1Ii11 = { "type" : "decap-keys" , "rloc" : oooO0000OoOOooo [ 0 ] }
 else :
  i1ii1i1Ii11 = { "type" : "decap-keys" , "rloc" : oooO0000OoOOooo [ 0 ] , "port" : oooO0000OoOOooo [ 1 ] }
  if 52 - 52: iIii1I11I1II1 + O0
 i1ii1i1Ii11 = lisp_build_json_keys ( i1ii1i1Ii11 , II11iI11i1 , iI1ii , "decrypt-key" )
 if 84 - 84: OOooOOo / iII111i . I1IiiI / O0 % OOooOOo . iII111i
 lisp_write_to_dp_socket ( i1ii1i1Ii11 )
 return
 if 32 - 32: OoO0O00 + OoO0O00 % o0oOOo0O0Ooo / O0
 if 29 - 29: iII111i % I1Ii111
 if 95 - 95: OOooOOo - ooOoO0o % i1IIi / O0 % I11i . IiII
 if 63 - 63: ooOoO0o
 if 22 - 22: OOooOOo . i11iIiiIii + II111iiii - Oo0Ooo % i1IIi / o0oOOo0O0Ooo
 if 90 - 90: IiII
 if 38 - 38: i1IIi / ooOoO0o / I11i * I1ii11iIi11i / II111iiii . iIii1I11I1II1
 if 52 - 52: I1ii11iIi11i % ooOoO0o * Ii1I * IiII + IiII / i11iIiiIii
def lisp_build_json_keys ( entry , ekey , ikey , key_type ) :
 if ( ekey == None ) : return ( entry )
 if 51 - 51: iIii1I11I1II1 * o0oOOo0O0Ooo % o0oOOo0O0Ooo . Ii1I / OoooooooOO
 entry [ "keys" ] = [ ]
 Oo000O000 = { "key-id" : "1" , key_type : ekey , "icv-key" : ikey }
 entry [ "keys" ] . append ( Oo000O000 )
 return ( entry )
 if 23 - 23: oO0o * I1IiiI - oO0o - ooOoO0o . IiII / i11iIiiIii
 if 53 - 53: Ii1I * Ii1I . OoOoOO00 . OOooOOo / I1ii11iIi11i % O0
 if 98 - 98: OOooOOo
 if 11 - 11: OOooOOo * iIii1I11I1II1 % IiII - I1IiiI . I11i
 if 29 - 29: OOooOOo % I11i - OOooOOo - OOooOOo * I11i . oO0o
 if 75 - 75: II111iiii . O0 . I1Ii111 * O0 / OoooooooOO
 if 60 - 60: OOooOOo - Oo0Ooo * OOooOOo / OoO0O00
def lisp_write_ipc_database_mappings ( ephem_port ) :
 if ( lisp_i_am_etr == False ) : return
 if ( lisp_ipc_dp_socket == None ) : return
 if ( lisp_check_dp_socket ( ) == False ) : return
 if 55 - 55: I1ii11iIi11i * II111iiii * iIii1I11I1II1
 if 38 - 38: iIii1I11I1II1 % I1ii11iIi11i . Ii1I + I1IiiI % i11iIiiIii - i11iIiiIii
 if 62 - 62: I1Ii111 + I1IiiI
 if 9 - 9: iIii1I11I1II1 / iIii1I11I1II1
 i1ii1i1Ii11 = { "type" : "database-mappings" , "database-mappings" : [ ] }
 if 24 - 24: OOooOOo . I1IiiI % i11iIiiIii
 if 43 - 43: OoooooooOO . o0oOOo0O0Ooo - I1ii11iIi11i + OoO0O00 . I1Ii111 . iII111i
 if 1 - 1: iII111i / OoO0O00 / OoOoOO00 * Oo0Ooo * OoooooooOO
 if 59 - 59: iII111i
 for iiIII1 in lisp_db_list :
  if ( iiIII1 . eid . is_ipv4 ( ) == False and iiIII1 . eid . is_ipv6 ( ) == False ) : continue
  IIIiiI11ii = { "instance-id" : str ( iiIII1 . eid . instance_id ) ,
 "eid-prefix" : iiIII1 . eid . print_prefix_no_iid ( ) }
  i1ii1i1Ii11 [ "database-mappings" ] . append ( IIIiiI11ii )
  if 30 - 30: iII111i . OoO0O00 . i11iIiiIii / I1ii11iIi11i * Oo0Ooo
 lisp_write_to_dp_socket ( i1ii1i1Ii11 )
 if 38 - 38: IiII + II111iiii
 if 20 - 20: iII111i * I1IiiI * iII111i - o0oOOo0O0Ooo + i1IIi + ooOoO0o
 if 49 - 49: II111iiii * I1IiiI / oO0o
 if 50 - 50: Ii1I + O0 . I1IiiI * Oo0Ooo
 if 15 - 15: Oo0Ooo
 i1ii1i1Ii11 = { "type" : "etr-nat-port" , "port" : ephem_port }
 lisp_write_to_dp_socket ( i1ii1i1Ii11 )
 return
 if 53 - 53: OoooooooOO * O0 / iII111i * ooOoO0o % I1Ii111 + OOooOOo
 if 95 - 95: I1Ii111 % OoOoOO00 . IiII * iII111i % Ii1I
 if 18 - 18: iIii1I11I1II1 / ooOoO0o / I1Ii111 % oO0o * Ii1I
 if 14 - 14: oO0o
 if 72 - 72: iIii1I11I1II1 / II111iiii * II111iiii + I1IiiI + iIii1I11I1II1 + oO0o
 if 46 - 46: I1Ii111
 if 23 - 23: Oo0Ooo * IiII - I1Ii111 . OoooooooOO
def lisp_write_ipc_interfaces ( ) :
 if ( lisp_i_am_etr ) : return
 if ( lisp_ipc_dp_socket == None ) : return
 if ( lisp_check_dp_socket ( ) == False ) : return
 if 78 - 78: OoOoOO00 - iIii1I11I1II1
 if 20 - 20: i1IIi
 if 72 - 72: ooOoO0o . II111iiii
 if 32 - 32: I1Ii111 - oO0o + OoooooooOO . OoOoOO00 + i11iIiiIii / i1IIi
 i1ii1i1Ii11 = { "type" : "interfaces" , "interfaces" : [ ] }
 if 26 - 26: I1IiiI + OoooooooOO % OoOoOO00 . IiII - II111iiii . OoOoOO00
 for II1i in lisp_myinterfaces . values ( ) :
  if ( II1i . instance_id == None ) : continue
  IIIiiI11ii = { "interface" : II1i . device ,
 "instance-id" : str ( II1i . instance_id ) }
  i1ii1i1Ii11 [ "interfaces" ] . append ( IIIiiI11ii )
  if 37 - 37: OoO0O00 % O0 + OoOoOO00 * I11i . Ii1I * OoO0O00
  if 18 - 18: o0oOOo0O0Ooo / OOooOOo
 lisp_write_to_dp_socket ( i1ii1i1Ii11 )
 return
 if 28 - 28: O0 / Ii1I - oO0o % I1ii11iIi11i % O0 . OoO0O00
 if 100 - 100: O0
 if 19 - 19: Ii1I * iIii1I11I1II1 * Oo0Ooo - i11iIiiIii * i11iIiiIii - OOooOOo
 if 88 - 88: O0 . iIii1I11I1II1 . I1ii11iIi11i
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
def lisp_parse_auth_key ( value ) :
 oOooO00Ooo = value . split ( "[" )
 oo0O00O0oO0OO = { }
 if ( len ( oOooO00Ooo ) == 1 ) :
  oo0O00O0oO0OO [ 0 ] = value
  return ( oo0O00O0oO0OO )
  if 36 - 36: II111iiii - o0oOOo0O0Ooo - Ii1I
  if 2 - 2: i1IIi
 for OOOOOOOo00 in oOooO00Ooo :
  if ( OOOOOOOo00 == "" ) : continue
  ooo = OOOOOOOo00 . find ( "]" )
  I1I1I1 = OOOOOOOo00 [ 0 : ooo ]
  try : I1I1I1 = int ( I1I1I1 )
  except : return
  if 63 - 63: I1ii11iIi11i % ooOoO0o
  oo0O00O0oO0OO [ I1I1I1 ] = OOOOOOOo00 [ ooo + 1 : : ]
  if 82 - 82: iII111i
 return ( oo0O00O0oO0OO )
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
 if 63 - 63: oO0o + OoOoOO00
 if 50 - 50: o0oOOo0O0Ooo / Oo0Ooo * ooOoO0o * Ii1I
 if 97 - 97: I1IiiI / oO0o + I1Ii111 + I1Ii111
 if 86 - 86: o0oOOo0O0Ooo % ooOoO0o + OoOoOO00 * ooOoO0o
 if 20 - 20: Ii1I * iII111i / ooOoO0o
def lisp_reassemble ( packet ) :
 oo00o00O0 = socket . ntohs ( struct . unpack ( "H" , packet [ 6 : 8 ] ) [ 0 ] )
 if 18 - 18: Oo0Ooo * Ii1I / i11iIiiIii . OoO0O00 + OoooooooOO
 if 23 - 23: I1IiiI - I1ii11iIi11i . O0 . OoOoOO00 . OoO0O00
 if 81 - 81: IiII * I11i - iIii1I11I1II1
 if 41 - 41: oO0o * I11i + I1IiiI - OoO0O00
 if ( oo00o00O0 == 0 or oo00o00O0 == 0x4000 ) : return ( packet )
 if 63 - 63: Oo0Ooo * Ii1I - Ii1I
 if 76 - 76: OoO0O00 . IiII % iIii1I11I1II1 / I1IiiI + iIii1I11I1II1 . I1IiiI
 if 57 - 57: IiII - i1IIi * ooOoO0o
 if 5 - 5: oO0o . O0 * IiII / Ii1I + OoO0O00
 i11iiI = socket . ntohs ( struct . unpack ( "H" , packet [ 4 : 6 ] ) [ 0 ] )
 o0OoooOoOo = socket . ntohs ( struct . unpack ( "H" , packet [ 2 : 4 ] ) [ 0 ] )
 if 75 - 75: OOooOOo * OoOoOO00
 o0oOoOo0O00 = ( oo00o00O0 & 0x2000 == 0 and ( oo00o00O0 & 0x1fff ) != 0 )
 i1ii1i1Ii11 = [ ( oo00o00O0 & 0x1fff ) * 8 , o0OoooOoOo - 20 , packet , o0oOoOo0O00 ]
 if 91 - 91: I11i
 if 69 - 69: I11i + Ii1I + Oo0Ooo - IiII - OoO0O00
 if 25 - 25: iIii1I11I1II1 % iIii1I11I1II1 / iII111i + iIii1I11I1II1
 if 48 - 48: OoooooooOO + OoO0O00 % i11iIiiIii * OoooooooOO
 if 64 - 64: I1ii11iIi11i . I1Ii111
 if 81 - 81: IiII . ooOoO0o + O0 . ooOoO0o + iIii1I11I1II1
 if 68 - 68: i11iIiiIii . iII111i + OoooooooOO + II111iiii + iIii1I11I1II1 % I11i
 if 7 - 7: i1IIi - o0oOOo0O0Ooo - I1IiiI
 if ( oo00o00O0 == 0x2000 ) :
  oo0O , O0o0o0ooO0ooo = struct . unpack ( "HH" , packet [ 20 : 24 ] )
  oo0O = socket . ntohs ( oo0O )
  O0o0o0ooO0ooo = socket . ntohs ( O0o0o0ooO0ooo )
  if ( O0o0o0ooO0ooo not in [ 4341 , 8472 , 4789 ] and oo0O != 4341 ) :
   lisp_reassembly_queue [ i11iiI ] = [ ]
   i1ii1i1Ii11 [ 2 ] = None
   if 62 - 62: OoOoOO00 * oO0o - I1IiiI / Ii1I
   if 48 - 48: o0oOOo0O0Ooo % o0oOOo0O0Ooo - OoOoOO00
   if 13 - 13: OoO0O00 - Ii1I . ooOoO0o / O0 * OoOoOO00
   if 57 - 57: O0 + OoooooooOO % o0oOOo0O0Ooo / I1Ii111 / OOooOOo - OoOoOO00
   if 48 - 48: o0oOOo0O0Ooo - II111iiii + OoOoOO00
   if 54 - 54: II111iiii - OoO0O00 - o0oOOo0O0Ooo - O0 % I1Ii111
 if ( lisp_reassembly_queue . has_key ( i11iiI ) == False ) :
  lisp_reassembly_queue [ i11iiI ] = [ ]
  if 9 - 9: i1IIi % iII111i / Ii1I
  if 83 - 83: oO0o
  if 1 - 1: oO0o * iIii1I11I1II1 % iIii1I11I1II1 % iIii1I11I1II1 / oO0o + IiII
  if 29 - 29: OoooooooOO
  if 55 - 55: O0 - o0oOOo0O0Ooo % I1ii11iIi11i * I11i * oO0o
 o0oo00o0o0O0o0 = lisp_reassembly_queue [ i11iiI ]
 if 12 - 12: oO0o - ooOoO0o
 if 71 - 71: OoOoOO00 * o0oOOo0O0Ooo + oO0o - Ii1I
 if 79 - 79: I1IiiI + oO0o
 if 70 - 70: I1Ii111 % iIii1I11I1II1
 if 74 - 74: i1IIi % i11iIiiIii + oO0o
 if ( len ( o0oo00o0o0O0o0 ) == 1 and o0oo00o0o0O0o0 [ 0 ] [ 2 ] == None ) :
  dprint ( "Drop non-LISP encapsulated fragment 0x{}" . format ( lisp_hex_string ( i11iiI ) . zfill ( 4 ) ) )
  if 94 - 94: OoO0O00 * I1IiiI / O0 + I1Ii111 / i11iIiiIii
  return ( None )
  if 34 - 34: Oo0Ooo . i1IIi
  if 97 - 97: I11i
  if 89 - 89: iII111i % OoOoOO00 . Oo0Ooo
  if 20 - 20: oO0o % OoOoOO00
  if 93 - 93: I1ii11iIi11i - Ii1I % i1IIi / i1IIi
 o0oo00o0o0O0o0 . append ( i1ii1i1Ii11 )
 o0oo00o0o0O0o0 = sorted ( o0oo00o0o0O0o0 )
 if 82 - 82: OOooOOo
 if 27 - 27: I1Ii111 / IiII - i1IIi * Ii1I
 if 90 - 90: ooOoO0o
 if 100 - 100: iII111i * i1IIi . iII111i / O0 / OoO0O00 - oO0o
 IiiIIi1 = lisp_address ( LISP_AFI_IPV4 , "" , 32 , 0 )
 IiiIIi1 . address = socket . ntohl ( struct . unpack ( "I" , packet [ 12 : 16 ] ) [ 0 ] )
 OO000O = IiiIIi1 . print_address_no_iid ( )
 IiiIIi1 . address = socket . ntohl ( struct . unpack ( "I" , packet [ 16 : 20 ] ) [ 0 ] )
 iiiIIIIii1IIi = IiiIIi1 . print_address_no_iid ( )
 IiiIIi1 = red ( "{} -> {}" . format ( OO000O , iiiIIIIii1IIi ) , False )
 if 21 - 21: I1ii11iIi11i + iII111i * i1IIi
 dprint ( "{}{} fragment, RLOCs: {}, packet 0x{}, frag-offset: 0x{}" . format ( bold ( "Received" , False ) , " non-LISP encapsulated" if i1ii1i1Ii11 [ 2 ] == None else "" , IiiIIi1 , lisp_hex_string ( i11iiI ) . zfill ( 4 ) ,
 # I11i % Ii1I
 # OOooOOo - I11i
 lisp_hex_string ( oo00o00O0 ) . zfill ( 4 ) ) )
 if 55 - 55: Oo0Ooo - OOooOOo - O0
 if 40 - 40: OoOoOO00 - OOooOOo
 if 3 - 3: IiII % I11i * I1Ii111 + iIii1I11I1II1 . oO0o
 if 35 - 35: II111iiii
 if 15 - 15: I11i * iIii1I11I1II1 + OOooOOo % IiII . o0oOOo0O0Ooo % Oo0Ooo
 if ( o0oo00o0o0O0o0 [ 0 ] [ 0 ] != 0 or o0oo00o0o0O0o0 [ - 1 ] [ 3 ] == False ) : return ( None )
 ooiiiI = o0oo00o0o0O0o0 [ 0 ]
 for ii11I in o0oo00o0o0O0o0 [ 1 : : ] :
  oo00o00O0 = ii11I [ 0 ]
  ooOooo00O000 , iiIII1I1I = ooiiiI [ 0 ] , ooiiiI [ 1 ]
  if ( ooOooo00O000 + iiIII1I1I != oo00o00O0 ) : return ( None )
  ooiiiI = ii11I
  if 48 - 48: I11i
 lisp_reassembly_queue . pop ( i11iiI )
 if 67 - 67: o0oOOo0O0Ooo
 if 36 - 36: IiII - I11i - Ii1I / OoOoOO00 % OoO0O00 * iIii1I11I1II1
 if 61 - 61: i11iIiiIii / Ii1I - OOooOOo . I1ii11iIi11i
 if 89 - 89: ooOoO0o % i11iIiiIii
 if 57 - 57: Oo0Ooo / ooOoO0o - O0 . ooOoO0o
 packet = o0oo00o0o0O0o0 [ 0 ] [ 2 ]
 for ii11I in o0oo00o0o0O0o0 [ 1 : : ] : packet += ii11I [ 2 ] [ 20 : : ]
 if 61 - 61: o0oOOo0O0Ooo / OoooooooOO . I1ii11iIi11i + Oo0Ooo
 dprint ( "{} fragments arrived for packet 0x{}, length {}" . format ( bold ( "All" , False ) , lisp_hex_string ( i11iiI ) . zfill ( 4 ) , len ( packet ) ) )
 if 75 - 75: Ii1I
 if 79 - 79: i1IIi . I1ii11iIi11i * o0oOOo0O0Ooo / I11i . I11i / ooOoO0o
 if 99 - 99: oO0o + I11i % i1IIi . iII111i
 if 58 - 58: Oo0Ooo % i11iIiiIii . Oo0Ooo / Oo0Ooo - I1IiiI . Ii1I
 if 65 - 65: OoO0O00
 IiiI1iii1iIiiI = socket . htons ( len ( packet ) )
 O0ooOoO0 = packet [ 0 : 2 ] + struct . pack ( "H" , IiiI1iii1iIiiI ) + packet [ 4 : 6 ] + struct . pack ( "H" , 0 ) + packet [ 8 : 10 ] + struct . pack ( "H" , 0 ) + packet [ 12 : 20 ]
 if 16 - 16: IiII % I1IiiI % iIii1I11I1II1 . I1IiiI . I1ii11iIi11i - IiII
 if 6 - 6: I1Ii111 + OoO0O00 + O0 * OoOoOO00 . iIii1I11I1II1 . I1Ii111
 O0ooOoO0 = lisp_ip_checksum ( O0ooOoO0 )
 return ( O0ooOoO0 + packet [ 20 : : ] )
 if 93 - 93: ooOoO0o % iIii1I11I1II1 + I1ii11iIi11i
 if 74 - 74: OoOoOO00 + I1ii11iIi11i
 if 82 - 82: II111iiii
 if 55 - 55: I11i . iIii1I11I1II1 / Ii1I - OoO0O00 * I1ii11iIi11i % iIii1I11I1II1
 if 48 - 48: ooOoO0o + Oo0Ooo / Oo0Ooo
 if 15 - 15: iIii1I11I1II1 . I1Ii111 * OoooooooOO * O0 % OOooOOo
 if 53 - 53: Ii1I
 if 63 - 63: I11i % OoOoOO00
def lisp_get_crypto_decap_lookup_key ( addr , port ) :
 oo0o00OO = addr . print_address_no_iid ( ) + ":" + str ( port )
 if ( lisp_crypto_keys_by_rloc_decap . has_key ( oo0o00OO ) ) : return ( oo0o00OO )
 if 46 - 46: iIii1I11I1II1 . II111iiii / OoooooooOO - ooOoO0o * iII111i
 oo0o00OO = addr . print_address_no_iid ( )
 if ( lisp_crypto_keys_by_rloc_decap . has_key ( oo0o00OO ) ) : return ( oo0o00OO )
 if 52 - 52: I11i + iII111i
 if 9 - 9: OoOoOO00 % II111iiii . I11i * Oo0Ooo
 if 53 - 53: II111iiii / i1IIi + OoooooooOO * O0
 if 62 - 62: IiII . O0
 if 87 - 87: I1ii11iIi11i / oO0o / IiII . OOooOOo
 for O0oOoOOOOo in lisp_crypto_keys_by_rloc_decap :
  OO0o = O0oOoOOOOo . split ( ":" )
  if ( len ( OO0o ) == 1 ) : continue
  OO0o = OO0o [ 0 ] if len ( OO0o ) == 2 else ":" . join ( OO0o [ 0 : - 1 ] )
  if ( OO0o == oo0o00OO ) :
   iIi11III = lisp_crypto_keys_by_rloc_decap [ O0oOoOOOOo ]
   lisp_crypto_keys_by_rloc_decap [ oo0o00OO ] = iIi11III
   return ( oo0o00OO )
   if 66 - 66: OoOoOO00 . Ii1I / i11iIiiIii / ooOoO0o
   if 76 - 76: OoO0O00 % OoO0O00 / I1ii11iIi11i * ooOoO0o * o0oOOo0O0Ooo - I1Ii111
 return ( None )
 if 53 - 53: OoO0O00 % Oo0Ooo . i1IIi
 if 34 - 34: Ii1I - o0oOOo0O0Ooo * i1IIi
 if 7 - 7: OoO0O00 * I1ii11iIi11i / I1Ii111
 if 98 - 98: II111iiii % I1ii11iIi11i
 if 48 - 48: iII111i % oO0o + oO0o - Oo0Ooo . OOooOOo
 if 38 - 38: iII111i
 if 66 - 66: iII111i + Oo0Ooo + i1IIi * Oo0Ooo
 if 18 - 18: O0 - IiII
 if 5 - 5: I1ii11iIi11i * iII111i + II111iiii * Oo0Ooo * O0 - I1IiiI
 if 71 - 71: i11iIiiIii % I1IiiI + I1ii11iIi11i + II111iiii + OoooooooOO + oO0o
 if 12 - 12: I1IiiI + I1Ii111
def lisp_build_crypto_decap_lookup_key ( addr , port ) :
 addr = addr . print_address_no_iid ( )
 O0O0o00 = addr + ":" + str ( port )
 if 19 - 19: OoO0O00 - I11i
 if ( lisp_i_am_rtr ) :
  if ( lisp_rloc_probe_list . has_key ( addr ) ) : return ( addr )
  if 76 - 76: IiII . II111iiii - o0oOOo0O0Ooo + Oo0Ooo - Ii1I
  if 24 - 24: IiII % Ii1I / ooOoO0o
  if 52 - 52: iII111i % iIii1I11I1II1 - Oo0Ooo - iIii1I11I1II1 * I1ii11iIi11i - OoO0O00
  if 26 - 26: i11iIiiIii % I11i % o0oOOo0O0Ooo % OoOoOO00 / iII111i - OOooOOo
  if 17 - 17: i1IIi - Ii1I . ooOoO0o % I1Ii111 . OoooooooOO / oO0o
  if 91 - 91: ooOoO0o % I1ii11iIi11i
  for iI1I1iI in lisp_nat_state_info . values ( ) :
   for I1iii1 in iI1I1iI :
    if ( addr == I1iii1 . address ) : return ( O0O0o00 )
    if 60 - 60: O0 * Oo0Ooo * IiII % OoOoOO00 . OoOoOO00
    if 4 - 4: I1Ii111 % I1Ii111 * O0
  return ( addr )
  if 54 - 54: I1ii11iIi11i - IiII . OoO0O00 + I1ii11iIi11i / I1IiiI
 return ( O0O0o00 )
 if 91 - 91: OOooOOo % Oo0Ooo
 if 44 - 44: iIii1I11I1II1 . OOooOOo
 if 57 - 57: II111iiii + I1Ii111
 if 42 - 42: OoOoOO00 % O0
 if 70 - 70: iIii1I11I1II1 * Oo0Ooo - I1IiiI / OoO0O00 + OoOoOO00
 if 94 - 94: OoooooooOO + O0 * iIii1I11I1II1 * II111iiii
 if 90 - 90: I11i + O0 / I1IiiI . oO0o / O0
def lisp_set_ttl ( lisp_socket , ttl ) :
 try :
  lisp_socket . setsockopt ( socket . SOL_IP , socket . IP_TTL , ttl )
  lisp_socket . setsockopt ( socket . SOL_IP , socket . IP_MULTICAST_TTL , ttl )
 except :
  lprint ( "socket.setsockopt(IP_TTL) not supported" )
  pass
  if 46 - 46: O0 . O0 - oO0o . II111iiii * I1IiiI * Ii1I
 return
 if 10 - 10: i1IIi + i1IIi . i1IIi - I1IiiI - I1IiiI
 if 26 - 26: Ii1I * I11i / I11i
 if 79 - 79: ooOoO0o / oO0o - oO0o / OoooooooOO
 if 91 - 91: iIii1I11I1II1 - O0 * o0oOOo0O0Ooo * o0oOOo0O0Ooo . II111iiii
 if 69 - 69: II111iiii - Oo0Ooo + i1IIi . II111iiii + o0oOOo0O0Ooo
 if 20 - 20: OoooooooOO - OoO0O00 * ooOoO0o * OoOoOO00 / OOooOOo
 if 64 - 64: O0 + iII111i / I11i * OoOoOO00 + o0oOOo0O0Ooo + I1Ii111
def lisp_is_rloc_probe_request ( lisp_type ) :
 lisp_type = struct . unpack ( "B" , lisp_type ) [ 0 ]
 return ( lisp_type == 0x12 )
 if 16 - 16: I11i
 if 9 - 9: Ii1I / IiII * I11i - i11iIiiIii * I1ii11iIi11i / iII111i
 if 61 - 61: O0 % iII111i
 if 41 - 41: I1Ii111 * OoooooooOO
 if 76 - 76: OoooooooOO * II111iiii . II111iiii / o0oOOo0O0Ooo - iII111i
 if 49 - 49: O0 . I1ii11iIi11i . OoOoOO00 . I1Ii111 % O0 . iIii1I11I1II1
 if 19 - 19: iIii1I11I1II1
def lisp_is_rloc_probe_reply ( lisp_type ) :
 lisp_type = struct . unpack ( "B" , lisp_type ) [ 0 ]
 return ( lisp_type == 0x28 )
 if 97 - 97: Ii1I . I11i / ooOoO0o + Oo0Ooo
 if 100 - 100: iII111i / I1Ii111 % OoOoOO00 . O0 / OoOoOO00
 if 81 - 81: OoO0O00 % i11iIiiIii / OoO0O00 + ooOoO0o
 if 100 - 100: O0 . Oo0Ooo % Oo0Ooo % O0 / i11iIiiIii
 if 56 - 56: IiII - OOooOOo - OoOoOO00 - I11i
 if 57 - 57: i1IIi
 if 41 - 41: I11i / Ii1I
 if 1 - 1: II111iiii / iII111i
 if 83 - 83: OoO0O00 / iII111i
 if 59 - 59: I1Ii111 % OOooOOo . I1IiiI + I1ii11iIi11i % oO0o
 if 96 - 96: OoO0O00
 if 53 - 53: oO0o + OoO0O00
 if 58 - 58: iIii1I11I1II1 + OoOoOO00
 if 65 - 65: iII111i % Oo0Ooo * iIii1I11I1II1 + I1IiiI + II111iiii
 if 72 - 72: OoOoOO00 . OoooooooOO - OOooOOo
 if 15 - 15: OoOoOO00
 if 13 - 13: I1ii11iIi11i - OOooOOo - i11iIiiIii / IiII
 if 65 - 65: IiII
 if 76 - 76: I1Ii111 % I1ii11iIi11i + ooOoO0o / I1IiiI
def lisp_is_rloc_probe ( packet , rr ) :
 o0oOo00 = ( struct . unpack ( "B" , packet [ 9 ] ) [ 0 ] == 17 )
 if ( o0oOo00 == False ) : return ( [ packet , None , None , None ] )
 if 59 - 59: OOooOOo - o0oOOo0O0Ooo - o0oOOo0O0Ooo % I1IiiI
 oo0O = struct . unpack ( "H" , packet [ 20 : 22 ] ) [ 0 ]
 O0o0o0ooO0ooo = struct . unpack ( "H" , packet [ 22 : 24 ] ) [ 0 ]
 OOOOO0oOO0 = ( socket . htons ( LISP_CTRL_PORT ) in [ oo0O , O0o0o0ooO0ooo ] )
 if ( OOOOO0oOO0 == False ) : return ( [ packet , None , None , None ] )
 if 82 - 82: I11i * i1IIi / Ii1I + O0
 if ( rr == 0 ) :
  oO0oo000O = lisp_is_rloc_probe_request ( packet [ 28 ] )
  if ( oO0oo000O == False ) : return ( [ packet , None , None , None ] )
 elif ( rr == 1 ) :
  oO0oo000O = lisp_is_rloc_probe_reply ( packet [ 28 ] )
  if ( oO0oo000O == False ) : return ( [ packet , None , None , None ] )
 elif ( rr == - 1 ) :
  oO0oo000O = lisp_is_rloc_probe_request ( packet [ 28 ] )
  if ( oO0oo000O == False ) :
   oO0oo000O = lisp_is_rloc_probe_reply ( packet [ 28 ] )
   if ( oO0oo000O == False ) : return ( [ packet , None , None , None ] )
   if 85 - 85: O0 + oO0o / I1Ii111
   if 65 - 65: o0oOOo0O0Ooo . Oo0Ooo . i1IIi / IiII . I11i . O0
   if 69 - 69: Oo0Ooo - i11iIiiIii
   if 87 - 87: Oo0Ooo % OOooOOo - Ii1I
   if 34 - 34: iII111i / Ii1I / I1IiiI * i11iIiiIii
   if 41 - 41: Ii1I / Oo0Ooo . OoO0O00 . iIii1I11I1II1 % IiII . I11i
 i1IIi1ii1i1ii = lisp_address ( LISP_AFI_IPV4 , "" , 32 , 0 )
 i1IIi1ii1i1ii . address = socket . ntohl ( struct . unpack ( "I" , packet [ 12 : 16 ] ) [ 0 ] )
 if 59 - 59: O0 + II111iiii + IiII % Oo0Ooo
 if 71 - 71: oO0o
 if 75 - 75: Oo0Ooo * oO0o + iIii1I11I1II1 / Oo0Ooo
 if 51 - 51: Ii1I * Ii1I + iII111i * oO0o / OOooOOo - ooOoO0o
 if ( i1IIi1ii1i1ii . is_local ( ) ) : return ( [ None , None , None , None ] )
 if 16 - 16: I1Ii111 + O0 - O0 * iIii1I11I1II1 / iII111i
 if 4 - 4: iII111i
 if 75 - 75: I1IiiI * IiII % OoO0O00 - ooOoO0o * iII111i
 if 32 - 32: iII111i
 i1IIi1ii1i1ii = i1IIi1ii1i1ii . print_address_no_iid ( )
 Oo0O00O = socket . ntohs ( struct . unpack ( "H" , packet [ 20 : 22 ] ) [ 0 ] )
 oOoooOOO0o0 = struct . unpack ( "B" , packet [ 8 ] ) [ 0 ] - 1
 packet = packet [ 28 : : ]
 if 59 - 59: OoOoOO00 - I1Ii111
 O0OOOO0o0O = bold ( "Receive(pcap)" , False )
 OOO000 = bold ( "from " + i1IIi1ii1i1ii , False )
 oo00ooOOOo0O = lisp_format_packet ( packet )
 lprint ( "{} {} bytes {} {}, packet: {}" . format ( O0OOOO0o0O , len ( packet ) , OOO000 , Oo0O00O , oo00ooOOOo0O ) )
 if 34 - 34: ooOoO0o . OoooooooOO / ooOoO0o + OoooooooOO
 return ( [ packet , i1IIi1ii1i1ii , Oo0O00O , oOoooOOO0o0 ] )
 if 24 - 24: OoooooooOO * I1ii11iIi11i / O0 / Oo0Ooo * I1IiiI / ooOoO0o
 if 33 - 33: Ii1I
 if 20 - 20: Ii1I + I11i
 if 98 - 98: OOooOOo
 if 58 - 58: i11iIiiIii / OoOoOO00
 if 18 - 18: ooOoO0o + O0 - OOooOOo + iIii1I11I1II1 . OOooOOo * iIii1I11I1II1
 if 83 - 83: OoO0O00 - Oo0Ooo * I1IiiI % Oo0Ooo % oO0o
 if 64 - 64: OoOoOO00 + oO0o / OoooooooOO . i11iIiiIii / II111iiii
 if 55 - 55: ooOoO0o . i11iIiiIii . o0oOOo0O0Ooo
 if 52 - 52: IiII . oO0o + i11iIiiIii % IiII
 if 45 - 45: i1IIi - I1IiiI / IiII - I1IiiI
def lisp_ipc_write_xtr_parameters ( cp , dp ) :
 if ( lisp_ipc_dp_socket == None ) : return
 if 21 - 21: IiII
 iiiii1i1 = { "type" : "xtr-parameters" , "control-plane-logging" : cp ,
 "data-plane-logging" : dp , "rtr" : lisp_i_am_rtr }
 if 43 - 43: IiII
 lisp_write_to_dp_socket ( iiiii1i1 )
 return
 if 9 - 9: OOooOOo * ooOoO0o + ooOoO0o . I1Ii111
 if 8 - 8: IiII * iIii1I11I1II1
 if 7 - 7: I1Ii111 / OoooooooOO % O0 - I1ii11iIi11i
 if 49 - 49: OoooooooOO . I1ii11iIi11i / OoooooooOO * oO0o
 if 81 - 81: I1ii11iIi11i . ooOoO0o + I1ii11iIi11i
 if 84 - 84: OoooooooOO
 if 95 - 95: o0oOOo0O0Ooo
 if 22 - 22: ooOoO0o / o0oOOo0O0Ooo - OoooooooOO / Oo0Ooo - I1Ii111 / OOooOOo
def lisp_external_data_plane ( ) :
 ooO0ooooO = 'egrep "ipc-data-plane = yes" ./lisp.config'
 if ( commands . getoutput ( ooO0ooooO ) != "" ) : return ( True )
 if 41 - 41: oO0o . II111iiii
 if ( os . getenv ( "LISP_RUN_LISP_XTR" ) != None ) : return ( True )
 return ( False )
 if 47 - 47: I1ii11iIi11i
 if 5 - 5: Oo0Ooo
 if 23 - 23: i11iIiiIii / I11i + i1IIi % I1Ii111
 if 100 - 100: Oo0Ooo
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
def lisp_process_data_plane_restart ( do_clear = False ) :
 os . system ( "touch ./lisp.config" )
 if 2 - 2: OoooooooOO . OoO0O00 . II111iiii / Ii1I - OOooOOo % Oo0Ooo
 iIIIi1iiii11 = { "type" : "entire-map-cache" , "entries" : [ ] }
 if 46 - 46: OoOoOO00 % I11i - iIii1I11I1II1 % Oo0Ooo
 if ( do_clear == False ) :
  I1iiIiii1IiIii = iIIIi1iiii11 [ "entries" ]
  lisp_map_cache . walk_cache ( lisp_ipc_walk_map_cache , I1iiIiii1IiIii )
  if 48 - 48: o0oOOo0O0Ooo / II111iiii / OoOoOO00 * o0oOOo0O0Ooo + I1IiiI . OoOoOO00
  if 52 - 52: Ii1I / OoOoOO00 . OOooOOo * IiII . OoooooooOO
 lisp_write_to_dp_socket ( iIIIi1iiii11 )
 return
 if 6 - 6: i1IIi . oO0o % IiII . Oo0Ooo % I11i
 if 86 - 86: OoooooooOO + IiII % o0oOOo0O0Ooo . i1IIi . iII111i
 if 25 - 25: iII111i * I1ii11iIi11i + I11i - I1ii11iIi11i
 if 75 - 75: IiII
 if 74 - 74: o0oOOo0O0Ooo - iIii1I11I1II1
 if 92 - 92: i11iIiiIii * iIii1I11I1II1 - I1Ii111 . i1IIi
 if 23 - 23: O0 - O0 . I1Ii111 . I1IiiI - I1IiiI * i1IIi
 if 8 - 8: I1IiiI . I1ii11iIi11i + oO0o % oO0o * oO0o
 if 70 - 70: II111iiii + IiII + O0 / Ii1I - i11iIiiIii
 if 72 - 72: II111iiii - II111iiii
 if 44 - 44: o0oOOo0O0Ooo + OoooooooOO
 if 34 - 34: i11iIiiIii + iIii1I11I1II1 - i11iIiiIii * o0oOOo0O0Ooo - iII111i
 if 87 - 87: OOooOOo * OoO0O00
 if 61 - 61: iII111i - II111iiii . I1Ii111 % II111iiii / I11i
def lisp_process_data_plane_stats ( msg , lisp_sockets , lisp_port ) :
 if ( msg . has_key ( "entries" ) == False ) :
  lprint ( "No 'entries' in stats IPC message" )
  return
  if 86 - 86: II111iiii
 if ( type ( msg [ "entries" ] ) != list ) :
  lprint ( "'entries' in stats IPC message must be an array" )
  return
  if 94 - 94: o0oOOo0O0Ooo % Ii1I * Ii1I % Oo0Ooo / I1ii11iIi11i
  if 40 - 40: Oo0Ooo . II111iiii / II111iiii - i1IIi
 for msg in msg [ "entries" ] :
  if ( msg . has_key ( "eid-prefix" ) == False ) :
   lprint ( "No 'eid-prefix' in stats IPC message" )
   continue
   if 91 - 91: Ii1I
  I11i11i1 = msg [ "eid-prefix" ]
  if 45 - 45: I1ii11iIi11i + Oo0Ooo
  if ( msg . has_key ( "instance-id" ) == False ) :
   lprint ( "No 'instance-id' in stats IPC message" )
   continue
   if 72 - 72: I1ii11iIi11i
  o0OoO0000o = int ( msg [ "instance-id" ] )
  if 5 - 5: i1IIi
  if 31 - 31: iII111i - OoooooooOO + oO0o / OoooooooOO + I1ii11iIi11i
  if 93 - 93: o0oOOo0O0Ooo * I1ii11iIi11i % I1IiiI * ooOoO0o
  if 37 - 37: OoO0O00 * OoooooooOO / oO0o * I11i * I1ii11iIi11i
  ooOOoo0 = lisp_address ( LISP_AFI_NONE , "" , 0 , o0OoO0000o )
  ooOOoo0 . store_prefix ( I11i11i1 )
  iiI1iIi1II1ii = lisp_map_cache_lookup ( None , ooOOoo0 )
  if ( iiI1iIi1II1ii == None ) :
   lprint ( "Map-cache entry for {} not found for stats update" . format ( I11i11i1 ) )
   if 42 - 42: OoooooooOO - ooOoO0o . OOooOOo + OoOoOO00
   continue
   if 53 - 53: o0oOOo0O0Ooo
   if 55 - 55: ooOoO0o . i1IIi - ooOoO0o + O0 + I1IiiI
  if ( msg . has_key ( "rlocs" ) == False ) :
   lprint ( "No 'rlocs' in stats IPC message for {}" . format ( I11i11i1 ) )
   if 31 - 31: OoO0O00 % I1Ii111
   continue
   if 62 - 62: oO0o / O0 - I1Ii111 . IiII
  if ( type ( msg [ "rlocs" ] ) != list ) :
   lprint ( "'rlocs' in stats IPC message must be an array" )
   continue
   if 81 - 81: i11iIiiIii
  o00oooOOooo0 = msg [ "rlocs" ]
  if 99 - 99: O0 / OoO0O00 * II111iiii . II111iiii
  if 14 - 14: OoOoOO00 * i1IIi - OoOoOO00 . OoooooooOO
  if 24 - 24: iIii1I11I1II1 + OOooOOo * iII111i % IiII % OOooOOo
  if 64 - 64: IiII . I1ii11iIi11i - o0oOOo0O0Ooo - ooOoO0o + OoooooooOO
  for O0Oo0OOOO000oo0O in o00oooOOooo0 :
   if ( O0Oo0OOOO000oo0O . has_key ( "rloc" ) == False ) : continue
   if 60 - 60: II111iiii - oO0o + iIii1I11I1II1 + Ii1I
   o0oooOoOoOo = O0Oo0OOOO000oo0O [ "rloc" ]
   if ( o0oooOoOoOo == "no-address" ) : continue
   if 78 - 78: OOooOOo
   I1IIiIIIii = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
   I1IIiIIIii . store_address ( o0oooOoOoOo )
   if 44 - 44: i1IIi * I1ii11iIi11i % Ii1I . Ii1I * I11i + II111iiii
   O0OooOoooO0O = iiI1iIi1II1ii . get_rloc ( I1IIiIIIii )
   if ( O0OooOoooO0O == None ) : continue
   if 15 - 15: i1IIi - I11i - I1Ii111 / OoO0O00 + Oo0Ooo + I1IiiI
   if 81 - 81: IiII
   if 54 - 54: I1IiiI % OoO0O00 % OoOoOO00
   if 12 - 12: II111iiii . O0 * i11iIiiIii . I11i
   Oo0o0O = 0 if O0Oo0OOOO000oo0O . has_key ( "packet-count" ) == False else O0Oo0OOOO000oo0O [ "packet-count" ]
   if 33 - 33: iIii1I11I1II1 - o0oOOo0O0Ooo . I1ii11iIi11i - OOooOOo
   iI1ii11 = 0 if O0Oo0OOOO000oo0O . has_key ( "byte-count" ) == False else O0Oo0OOOO000oo0O [ "byte-count" ]
   if 70 - 70: OOooOOo % Ii1I + II111iiii % II111iiii / i11iIiiIii * O0
   i1 = 0 if O0Oo0OOOO000oo0O . has_key ( "seconds-last-packet" ) == False else O0Oo0OOOO000oo0O [ "seconds-last-packet" ]
   if 49 - 49: I1IiiI . o0oOOo0O0Ooo * i1IIi % IiII + I1Ii111
   if 59 - 59: iII111i - oO0o . ooOoO0o / IiII * i11iIiiIii
   O0OooOoooO0O . stats . packet_count += Oo0o0O
   O0OooOoooO0O . stats . byte_count += iI1ii11
   O0OooOoooO0O . stats . last_increment = lisp_get_timestamp ( ) - i1
   if 61 - 61: I11i - Oo0Ooo * II111iiii + iIii1I11I1II1
   lprint ( "Update stats {}/{}/{}s for {} RLOC {}" . format ( Oo0o0O , iI1ii11 ,
 i1 , I11i11i1 , o0oooOoOoOo ) )
   if 37 - 37: OoooooooOO % II111iiii / o0oOOo0O0Ooo . OOooOOo * I1ii11iIi11i . iIii1I11I1II1
   if 73 - 73: OoOoOO00
   if 44 - 44: Oo0Ooo / oO0o
   if 9 - 9: i1IIi % I1IiiI + OoO0O00 * ooOoO0o / iIii1I11I1II1 / iII111i
   if 80 - 80: OOooOOo / O0 % IiII * OoOoOO00
  if ( iiI1iIi1II1ii . group . is_null ( ) and iiI1iIi1II1ii . has_ttl_elapsed ( ) ) :
   I11i11i1 = green ( iiI1iIi1II1ii . print_eid_tuple ( ) , False )
   lprint ( "Refresh map-cache entry {}" . format ( I11i11i1 ) )
   lisp_send_map_request ( lisp_sockets , lisp_port , None , iiI1iIi1II1ii . eid , None )
   if 53 - 53: OOooOOo + i11iIiiIii
   if 25 - 25: i11iIiiIii
 return
 if 51 - 51: iII111i . ooOoO0o
 if 70 - 70: I11i / O0 - I11i + o0oOOo0O0Ooo . ooOoO0o . o0oOOo0O0Ooo
 if 6 - 6: I11i + II111iiii - I1Ii111
 if 45 - 45: i1IIi / iII111i + i11iIiiIii * I11i + ooOoO0o / OoooooooOO
 if 56 - 56: I11i + I1Ii111
 if 80 - 80: II111iiii . Ii1I + o0oOOo0O0Ooo / II111iiii / OoO0O00 + iIii1I11I1II1
 if 29 - 29: o0oOOo0O0Ooo + OoOoOO00 + ooOoO0o - I1ii11iIi11i
 if 64 - 64: O0 / OoooooooOO
 if 28 - 28: I1ii11iIi11i + oO0o . Oo0Ooo % iIii1I11I1II1 / I1Ii111
 if 8 - 8: O0 . I1IiiI * o0oOOo0O0Ooo + I1IiiI
 if 44 - 44: i1IIi % iII111i . i11iIiiIii / I11i + OoooooooOO
 if 21 - 21: OoOoOO00 . OoO0O00 . OoOoOO00 + OoOoOO00
 if 30 - 30: I1IiiI - iII111i - OOooOOo + oO0o
 if 51 - 51: Ii1I % O0 / II111iiii . Oo0Ooo
 if 90 - 90: i11iIiiIii * II111iiii % iIii1I11I1II1 . I1ii11iIi11i / Oo0Ooo . OOooOOo
 if 77 - 77: OoO0O00
 if 95 - 95: II111iiii
 if 59 - 59: iIii1I11I1II1 % OOooOOo / OoOoOO00 * I1Ii111 * OoooooooOO * O0
 if 43 - 43: OoO0O00 * I1IiiI * OOooOOo * O0 - O0 / o0oOOo0O0Ooo
 if 77 - 77: I11i % I1Ii111 . IiII % OoooooooOO * o0oOOo0O0Ooo
 if 87 - 87: iII111i + IiII / ooOoO0o * ooOoO0o * OOooOOo
 if 97 - 97: I1Ii111
 if 47 - 47: iII111i / I1ii11iIi11i - Ii1I . II111iiii
def lisp_process_data_plane_decap_stats ( msg , lisp_ipc_socket ) :
 if 56 - 56: O0 - i1IIi % o0oOOo0O0Ooo + IiII
 if 42 - 42: o0oOOo0O0Ooo . OOooOOo % I11i - OoOoOO00
 if 38 - 38: OoooooooOO
 if 27 - 27: O0 + I1ii11iIi11i % Ii1I . i1IIi + OoO0O00 + OoOoOO00
 if 22 - 22: II111iiii / I1IiiI + o0oOOo0O0Ooo * I1IiiI . OoooooooOO * OOooOOo
 if ( lisp_i_am_itr ) :
  lprint ( "Send decap-stats IPC message to lisp-etr process" )
  iiiii1i1 = "stats%{}" . format ( json . dumps ( msg ) )
  iiiii1i1 = lisp_command_ipc ( iiiii1i1 , "lisp-itr" )
  lisp_ipc ( iiiii1i1 , lisp_ipc_socket , "lisp-etr" )
  return
  if 49 - 49: I1ii11iIi11i * I1IiiI + OOooOOo + i11iIiiIii * I1ii11iIi11i . o0oOOo0O0Ooo
  if 36 - 36: o0oOOo0O0Ooo - i11iIiiIii
  if 37 - 37: O0 + IiII + I1IiiI
  if 50 - 50: OoooooooOO . I1Ii111
  if 100 - 100: ooOoO0o * ooOoO0o - Ii1I
  if 13 - 13: iII111i . I11i * OoO0O00 . i1IIi . iIii1I11I1II1 - o0oOOo0O0Ooo
  if 68 - 68: Ii1I % o0oOOo0O0Ooo / OoooooooOO + Ii1I - Ii1I
  if 79 - 79: II111iiii / IiII
 iiiii1i1 = bold ( "IPC" , False )
 lprint ( "Process decap-stats {} message: '{}'" . format ( iiiii1i1 , msg ) )
 if 4 - 4: O0 - i11iIiiIii % ooOoO0o * O0 - ooOoO0o
 if ( lisp_i_am_etr ) : msg = json . loads ( msg )
 if 96 - 96: oO0o % II111iiii . Ii1I % OoO0O00 . iIii1I11I1II1 / IiII
 OOooo = [ "good-packets" , "ICV-error" , "checksum-error" ,
 "lisp-header-error" , "no-decrypt-key" , "bad-inner-version" ,
 "outer-header-error" ]
 if 13 - 13: Ii1I % II111iiii % o0oOOo0O0Ooo . OoooooooOO / OOooOOo
 for ooo0Oo00O00OO in OOooo :
  Oo0o0O = 0 if msg . has_key ( ooo0Oo00O00OO ) == False else msg [ ooo0Oo00O00OO ] [ "packet-count" ]
  if 70 - 70: OoooooooOO + iII111i / I1IiiI + I1ii11iIi11i
  lisp_decap_stats [ ooo0Oo00O00OO ] . packet_count += Oo0o0O
  if 46 - 46: I1Ii111 - O0 / OoO0O00 * I1Ii111 + IiII % I1ii11iIi11i
  iI1ii11 = 0 if msg . has_key ( ooo0Oo00O00OO ) == False else msg [ ooo0Oo00O00OO ] [ "byte-count" ]
  if 80 - 80: Oo0Ooo + ooOoO0o + IiII
  lisp_decap_stats [ ooo0Oo00O00OO ] . byte_count += iI1ii11
  if 76 - 76: I1Ii111
  i1 = 0 if msg . has_key ( ooo0Oo00O00OO ) == False else msg [ ooo0Oo00O00OO ] [ "seconds-last-packet" ]
  if 23 - 23: O0 % I1ii11iIi11i % iIii1I11I1II1
  lisp_decap_stats [ ooo0Oo00O00OO ] . last_increment = lisp_get_timestamp ( ) - i1
  if 49 - 49: iII111i + I1Ii111 % OoOoOO00
 return
 if 67 - 67: Ii1I
 if 27 - 27: Oo0Ooo / i11iIiiIii / II111iiii . Ii1I - II111iiii / OoO0O00
 if 61 - 61: ooOoO0o - OOooOOo
 if 45 - 45: O0 . OoO0O00
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
 if 36 - 36: OOooOOo . oO0o
 if 15 - 15: I1IiiI + ooOoO0o - o0oOOo0O0Ooo
 if 62 - 62: Ii1I - OOooOOo
def lisp_process_punt ( punt_socket , lisp_send_sockets , lisp_ephem_port ) :
 OooOooo00O0o , i1IIi1ii1i1ii = punt_socket . recvfrom ( 4000 )
 if 95 - 95: O0 % IiII % Ii1I . o0oOOo0O0Ooo * OoOoOO00 - OOooOOo
 O0o0o0o0O = json . loads ( OooOooo00O0o )
 if ( type ( O0o0o0o0O ) != dict ) :
  lprint ( "Invalid punt message from {}, not in JSON format" . format ( i1IIi1ii1i1ii ) )
  if 76 - 76: Ii1I * Oo0Ooo + i11iIiiIii % i1IIi
  return
  if 99 - 99: I1Ii111 * oO0o - iIii1I11I1II1
 o0Ooo0O0OooO = bold ( "Punt" , False )
 lprint ( "{} message from '{}': '{}'" . format ( o0Ooo0O0OooO , i1IIi1ii1i1ii , O0o0o0o0O ) )
 if 80 - 80: OoOoOO00 / I1IiiI % O0
 if ( O0o0o0o0O . has_key ( "type" ) == False ) :
  lprint ( "Punt IPC message has no 'type' key" )
  return
  if 90 - 90: O0 . o0oOOo0O0Ooo - OoooooooOO % iIii1I11I1II1
  if 19 - 19: iIii1I11I1II1 / iII111i
  if 62 - 62: OoooooooOO - ooOoO0o
  if 47 - 47: I11i * I1IiiI / oO0o
  if 98 - 98: Ii1I / oO0o * O0 + I1Ii111 - I1Ii111 + iII111i
 if ( O0o0o0o0O [ "type" ] == "statistics" ) :
  lisp_process_data_plane_stats ( O0o0o0o0O , lisp_send_sockets , lisp_ephem_port )
  return
  if 4 - 4: i1IIi
 if ( O0o0o0o0O [ "type" ] == "decap-statistics" ) :
  lisp_process_data_plane_decap_stats ( O0o0o0o0O , punt_socket )
  return
  if 43 - 43: oO0o * ooOoO0o - I11i
  if 70 - 70: oO0o / Ii1I
  if 15 - 15: iIii1I11I1II1 % ooOoO0o % i11iIiiIii
  if 16 - 16: iII111i
  if 50 - 50: iIii1I11I1II1 - II111iiii % i1IIi
 if ( O0o0o0o0O [ "type" ] == "restart" ) :
  lisp_process_data_plane_restart ( )
  return
  if 48 - 48: O0
  if 60 - 60: ooOoO0o - IiII % i1IIi
  if 5 - 5: oO0o
  if 29 - 29: i1IIi . OoOoOO00 . i1IIi + oO0o . I1Ii111 + O0
  if 62 - 62: I1ii11iIi11i . IiII + OoO0O00 - OoOoOO00 * O0 + I1Ii111
 if ( O0o0o0o0O [ "type" ] != "discovery" ) :
  lprint ( "Punt IPC message has wrong format" )
  return
  if 58 - 58: oO0o . OoO0O00 / ooOoO0o
 if ( O0o0o0o0O . has_key ( "interface" ) == False ) :
  lprint ( "Invalid punt message from {}, required keys missing" . format ( i1IIi1ii1i1ii ) )
  if 61 - 61: I11i + I1Ii111
  return
  if 27 - 27: ooOoO0o / i1IIi . oO0o - OoooooooOO
  if 48 - 48: ooOoO0o % ooOoO0o / OoooooooOO + i1IIi * oO0o + ooOoO0o
  if 69 - 69: iII111i . iII111i
  if 46 - 46: IiII * Oo0Ooo + I1Ii111
  if 79 - 79: IiII
 OoO0o0OOOO = O0o0o0o0O [ "interface" ]
 if ( OoO0o0OOOO == "" ) :
  o0OoO0000o = int ( O0o0o0o0O [ "instance-id" ] )
  if ( o0OoO0000o == - 1 ) : return
 else :
  o0OoO0000o = lisp_get_interface_instance_id ( OoO0o0OOOO , None )
  if 89 - 89: IiII * I11i + I1ii11iIi11i * oO0o - II111iiii
  if 58 - 58: ooOoO0o . I1Ii111 / i1IIi % I1ii11iIi11i + o0oOOo0O0Ooo
  if 94 - 94: i11iIiiIii + I1Ii111 . iII111i - ooOoO0o % I1Ii111
  if 94 - 94: i11iIiiIii - OOooOOo - O0 * OoooooooOO - ooOoO0o
  if 35 - 35: iII111i . i11iIiiIii - OOooOOo % Oo0Ooo + Ii1I . iIii1I11I1II1
 O00O0o = None
 if ( O0o0o0o0O . has_key ( "source-eid" ) ) :
  OoOoo0ooO0000 = O0o0o0o0O [ "source-eid" ]
  O00O0o = lisp_address ( LISP_AFI_NONE , OoOoo0ooO0000 , 0 , o0OoO0000o )
  if ( O00O0o . is_null ( ) ) :
   lprint ( "Invalid source-EID format '{}'" . format ( OoOoo0ooO0000 ) )
   return
   if 91 - 91: o0oOOo0O0Ooo / OoO0O00 + I1IiiI % i11iIiiIii % i1IIi
   if 22 - 22: I1Ii111 * O0 % OoO0O00 * I1ii11iIi11i
 II1111 = None
 if ( O0o0o0o0O . has_key ( "dest-eid" ) ) :
  IIi11 = O0o0o0o0O [ "dest-eid" ]
  II1111 = lisp_address ( LISP_AFI_NONE , IIi11 , 0 , o0OoO0000o )
  if ( II1111 . is_null ( ) ) :
   lprint ( "Invalid dest-EID format '{}'" . format ( IIi11 ) )
   return
   if 50 - 50: OoOoOO00 . o0oOOo0O0Ooo
   if 92 - 92: OOooOOo * I11i
   if 57 - 57: Ii1I
   if 91 - 91: o0oOOo0O0Ooo * I1ii11iIi11i % OoOoOO00 / OoO0O00
   if 92 - 92: IiII . I1IiiI % I11i . o0oOOo0O0Ooo
   if 72 - 72: oO0o * OoO0O00 * O0
   if 38 - 38: O0 . oO0o - iII111i - i11iIiiIii + o0oOOo0O0Ooo + i1IIi
   if 58 - 58: OOooOOo - Ii1I * I1Ii111 - O0 . oO0o
 if ( O00O0o ) :
  oOo = green ( O00O0o . print_address ( ) , False )
  iiIII1 = lisp_db_for_lookups . lookup_cache ( O00O0o , False )
  if ( iiIII1 != None ) :
   if 72 - 72: i1IIi * iII111i * Ii1I / o0oOOo0O0Ooo . I1Ii111 + i11iIiiIii
   if 33 - 33: I11i / OoO0O00 * ooOoO0o + iIii1I11I1II1
   if 54 - 54: Oo0Ooo / IiII + i11iIiiIii . O0
   if 94 - 94: OoooooooOO + iII111i * OoooooooOO / o0oOOo0O0Ooo
   if 12 - 12: iIii1I11I1II1 / iIii1I11I1II1 / II111iiii
   if ( iiIII1 . dynamic_eid_configured ( ) ) :
    II1i = lisp_allow_dynamic_eid ( OoO0o0OOOO , O00O0o )
    if ( II1i != None and lisp_i_am_itr ) :
     lisp_itr_discover_eid ( iiIII1 , O00O0o , OoO0o0OOOO , II1i )
    else :
     lprint ( ( "Disallow dynamic source-EID {} " + "on interface {}" ) . format ( oOo , OoO0o0OOOO ) )
     if 93 - 93: oO0o
     if 53 - 53: OoO0O00 * i1IIi / Oo0Ooo / OoO0O00 * ooOoO0o
     if 77 - 77: iIii1I11I1II1 % I1IiiI + o0oOOo0O0Ooo + I1Ii111 * Oo0Ooo * i1IIi
  else :
   lprint ( "Punt from non-EID source {}" . format ( oOo ) )
   if 14 - 14: iIii1I11I1II1 * iIii1I11I1II1 - OOooOOo . iII111i / ooOoO0o
   if 54 - 54: OoOoOO00 - I1IiiI - iII111i
   if 49 - 49: i11iIiiIii * Oo0Ooo
   if 100 - 100: Oo0Ooo * oO0o
   if 85 - 85: OoooooooOO . IiII / IiII . ooOoO0o . IiII % II111iiii
   if 65 - 65: oO0o - OoO0O00 / iII111i + ooOoO0o
 if ( II1111 ) :
  iiI1iIi1II1ii = lisp_map_cache_lookup ( O00O0o , II1111 )
  if ( iiI1iIi1II1ii == None or iiI1iIi1II1ii . action == LISP_SEND_MAP_REQUEST_ACTION ) :
   if 80 - 80: o0oOOo0O0Ooo + II111iiii * Ii1I % OoOoOO00 % I1IiiI + I1ii11iIi11i
   if 46 - 46: Oo0Ooo / Oo0Ooo % iII111i % I1IiiI
   if 85 - 85: OoO0O00 - Ii1I / O0
   if 45 - 45: IiII + I1Ii111 / I11i
   if 84 - 84: iII111i % II111iiii
   if ( lisp_rate_limit_map_request ( II1111 ) ) : return
   lisp_send_map_request ( lisp_send_sockets , lisp_ephem_port ,
 O00O0o , II1111 , None )
  else :
   oOo = green ( II1111 . print_address ( ) , False )
   lprint ( "Map-cache entry for {} already exists" . format ( oOo ) )
   if 86 - 86: IiII % II111iiii / i1IIi * I1ii11iIi11i - O0 * OOooOOo
   if 53 - 53: OOooOOo * oO0o + i1IIi % Oo0Ooo + II111iiii
 return
 if 34 - 34: oO0o % iII111i / IiII . IiII + i11iIiiIii
 if 68 - 68: O0 % oO0o * IiII % O0
 if 55 - 55: O0 % I1IiiI % O0
 if 27 - 27: I1IiiI + I1ii11iIi11i * I1Ii111 % Ii1I - Oo0Ooo
 if 87 - 87: i11iIiiIii % OOooOOo - OoOoOO00 * ooOoO0o / Oo0Ooo
 if 74 - 74: OoooooooOO * ooOoO0o - I11i / I1ii11iIi11i % iIii1I11I1II1
 if 94 - 94: Ii1I * I1Ii111 + OoOoOO00 . iIii1I11I1II1
def lisp_ipc_map_cache_entry ( mc , jdata ) :
 i1ii1i1Ii11 = lisp_write_ipc_map_cache ( True , mc , dont_send = True )
 jdata . append ( i1ii1i1Ii11 )
 return ( [ True , jdata ] )
 if 44 - 44: Oo0Ooo . Oo0Ooo * Oo0Ooo
 if 23 - 23: I1Ii111 / iII111i . O0 % II111iiii
 if 67 - 67: I11i / iIii1I11I1II1 / ooOoO0o
 if 90 - 90: II111iiii % I1Ii111 - IiII . Oo0Ooo % OOooOOo - OoOoOO00
 if 89 - 89: Oo0Ooo - I1ii11iIi11i . I1Ii111
 if 65 - 65: ooOoO0o % OOooOOo + OOooOOo % I1Ii111 . I1IiiI % O0
 if 46 - 46: OoO0O00 * I1Ii111 + iII111i . oO0o % OOooOOo / i11iIiiIii
 if 1 - 1: I1ii11iIi11i % O0 - I1ii11iIi11i / OoooooooOO / OoO0O00
def lisp_ipc_walk_map_cache ( mc , jdata ) :
 if 82 - 82: i1IIi % Ii1I
 if 85 - 85: I1Ii111 * i11iIiiIii * iIii1I11I1II1 % iIii1I11I1II1
 if 64 - 64: OoO0O00 / Ii1I
 if 79 - 79: Ii1I % OOooOOo
 if ( mc . group . is_null ( ) ) : return ( lisp_ipc_map_cache_entry ( mc , jdata ) )
 if 39 - 39: I1ii11iIi11i / Ii1I - II111iiii . i1IIi
 if ( mc . source_cache == None ) : return ( [ True , jdata ] )
 if 59 - 59: II111iiii
 if 36 - 36: ooOoO0o . II111iiii - OoOoOO00 % I1ii11iIi11i * O0
 if 91 - 91: iII111i + Oo0Ooo / OoooooooOO * iIii1I11I1II1 - OoO0O00
 if 73 - 73: iIii1I11I1II1 % I1Ii111 % II111iiii * Oo0Ooo * OoO0O00
 if 48 - 48: OOooOOo * i11iIiiIii - i11iIiiIii + iIii1I11I1II1 + I1IiiI % OoooooooOO
 jdata = mc . source_cache . walk_cache ( lisp_ipc_map_cache_entry , jdata )
 return ( [ True , jdata ] )
 if 61 - 61: i1IIi
 if 56 - 56: iIii1I11I1II1 / I11i * iII111i * I11i * OoooooooOO
 if 44 - 44: I1ii11iIi11i - OOooOOo % I11i - I1Ii111 / iIii1I11I1II1 - OOooOOo
 if 38 - 38: iIii1I11I1II1 - OoooooooOO * II111iiii . OoooooooOO + OOooOOo
 if 59 - 59: OoooooooOO
 if 22 - 22: II111iiii
 if 85 - 85: I1Ii111 + I1ii11iIi11i * I11i % o0oOOo0O0Ooo + Ii1I
def lisp_itr_discover_eid ( db , eid , input_interface , routed_interface ,
 lisp_ipc_listen_socket ) :
 I11i11i1 = eid . print_address ( )
 if ( db . dynamic_eids . has_key ( I11i11i1 ) ) :
  db . dynamic_eids [ I11i11i1 ] . last_packet = lisp_get_timestamp ( )
  return
  if 23 - 23: IiII * OoO0O00
  if 42 - 42: IiII
  if 83 - 83: i1IIi * o0oOOo0O0Ooo / OoO0O00 / o0oOOo0O0Ooo
  if 55 - 55: Oo0Ooo % O0 - OoO0O00
  if 42 - 42: OoooooooOO * OOooOOo
 I1iIi1IiI1i = lisp_dynamic_eid ( )
 I1iIi1IiI1i . dynamic_eid . copy_address ( eid )
 I1iIi1IiI1i . interface = routed_interface
 I1iIi1IiI1i . last_packet = lisp_get_timestamp ( )
 I1iIi1IiI1i . get_timeout ( routed_interface )
 db . dynamic_eids [ I11i11i1 ] = I1iIi1IiI1i
 if 93 - 93: OOooOOo + II111iiii . oO0o * Oo0Ooo - O0 + I1Ii111
 OOOO0OoOOOO0 = ""
 if ( input_interface != routed_interface ) :
  OOOO0OoOOOO0 = ", routed-interface " + routed_interface
  if 67 - 67: I1ii11iIi11i . o0oOOo0O0Ooo * OoO0O00 . iIii1I11I1II1
  if 64 - 64: iIii1I11I1II1 . iII111i + o0oOOo0O0Ooo / I1ii11iIi11i
 IIi1OOoOO0OoO = green ( I11i11i1 , False ) + bold ( " discovered" , False )
 lprint ( "Dynamic-EID {} on interface {}{}, timeout {}" . format ( IIi1OOoOO0OoO , input_interface , OOOO0OoOOOO0 , I1iIi1IiI1i . timeout ) )
 if 36 - 36: II111iiii % IiII . i11iIiiIii
 if 88 - 88: Oo0Ooo . IiII * Oo0Ooo
 if 92 - 92: I1IiiI % IiII
 if 95 - 95: OoooooooOO / OoO0O00 % O0 / I1Ii111 * Ii1I + I1ii11iIi11i
 if 7 - 7: ooOoO0o
 iiiii1i1 = "learn%{}%{}" . format ( I11i11i1 , routed_interface )
 iiiii1i1 = lisp_command_ipc ( iiiii1i1 , "lisp-itr" )
 lisp_ipc ( iiiii1i1 , lisp_ipc_listen_socket , "lisp-etr" )
 return
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
def lisp_retry_decap_keys ( addr_str , packet , iv , packet_icv ) :
 if ( lisp_search_decap_keys == False ) : return
 if 43 - 43: I1Ii111 + i11iIiiIii % iII111i % I1Ii111 - ooOoO0o
 if 85 - 85: IiII % iIii1I11I1II1 . I1Ii111
 if 38 - 38: iII111i - I1IiiI / ooOoO0o
 if 46 - 46: OOooOOo . O0 / i11iIiiIii . OOooOOo
 if ( addr_str . find ( ":" ) != - 1 ) : return
 if 19 - 19: I11i / Oo0Ooo + I1Ii111
 i1iIiiiiI1 = lisp_crypto_keys_by_rloc_decap [ addr_str ]
 if 43 - 43: I1ii11iIi11i
 for Oo000O000 in lisp_crypto_keys_by_rloc_decap :
  if 18 - 18: I11i / OOooOOo % I11i - o0oOOo0O0Ooo
  if 22 - 22: iII111i
  if 88 - 88: I11i + OoOoOO00 % IiII % OoO0O00 * O0 / OoooooooOO
  if 83 - 83: IiII + I1Ii111 . I1ii11iIi11i * iIii1I11I1II1
  if ( Oo000O000 . find ( addr_str ) == - 1 ) : continue
  if 9 - 9: ooOoO0o % IiII - OoOoOO00
  if 66 - 66: oO0o % Oo0Ooo
  if 40 - 40: i11iIiiIii . O0 * I11i - oO0o / OOooOOo . oO0o
  if 86 - 86: OOooOOo - I1Ii111 * IiII - i1IIi + ooOoO0o + I11i
  if ( Oo000O000 == addr_str ) : continue
  if 32 - 32: IiII
  if 99 - 99: II111iiii
  if 34 - 34: OOooOOo + OoOoOO00 * o0oOOo0O0Ooo + I1ii11iIi11i + IiII * i1IIi
  if 73 - 73: I1ii11iIi11i - IiII - O0 . oO0o + Oo0Ooo % iII111i
  i1ii1i1Ii11 = lisp_crypto_keys_by_rloc_decap [ Oo000O000 ]
  if ( i1ii1i1Ii11 == i1iIiiiiI1 ) : continue
  if 68 - 68: I1ii11iIi11i - OoooooooOO
  if 5 - 5: I1ii11iIi11i * I1IiiI + OoooooooOO / Oo0Ooo
  if 18 - 18: OoO0O00 * iII111i % I1IiiI . OOooOOo * o0oOOo0O0Ooo
  if 58 - 58: iII111i . IiII + iIii1I11I1II1
  IIi1i1i1111II = i1ii1i1Ii11 [ 1 ]
  if ( packet_icv != IIi1i1i1111II . do_icv ( packet , iv ) ) :
   lprint ( "Test ICV with key {} failed" . format ( red ( Oo000O000 , False ) ) )
   continue
   if 40 - 40: iIii1I11I1II1 / OoooooooOO % IiII . Ii1I
   if 83 - 83: iIii1I11I1II1 + o0oOOo0O0Ooo - I11i / i11iIiiIii
  lprint ( "Changing decap crypto key to {}" . format ( red ( Oo000O000 , False ) ) )
  lisp_crypto_keys_by_rloc_decap [ addr_str ] = i1ii1i1Ii11
  if 57 - 57: I1IiiI . Oo0Ooo / I1IiiI / II111iiii - I1Ii111
 return
 if 68 - 68: I1IiiI
 if 97 - 97: Ii1I + o0oOOo0O0Ooo / OoO0O00
 if 97 - 97: i11iIiiIii % iIii1I11I1II1 + II111iiii
 if 90 - 90: OOooOOo / I1IiiI
 if 28 - 28: OoooooooOO + i1IIi
 if 29 - 29: Oo0Ooo
 if 98 - 98: OOooOOo / Oo0Ooo % Ii1I * OoooooooOO - oO0o
 if 64 - 64: I1IiiI - I1IiiI
def lisp_decent_pull_xtr_configured ( ) :
 return ( lisp_decent_modulus != 0 and lisp_decent_dns_suffix != None )
 if 90 - 90: iII111i - I1IiiI - II111iiii / OOooOOo + Ii1I
 if 34 - 34: i11iIiiIii + I1Ii111 / O0 / iIii1I11I1II1 * OoooooooOO % Ii1I
 if 32 - 32: i11iIiiIii - OoOoOO00 / iIii1I11I1II1 * o0oOOo0O0Ooo % I1IiiI + O0
 if 36 - 36: I1ii11iIi11i + I1ii11iIi11i % I1Ii111 * ooOoO0o * OoOoOO00
 if 54 - 54: Oo0Ooo - I1IiiI % OOooOOo . I1ii11iIi11i / I1IiiI
 if 75 - 75: OOooOOo - O0 % iII111i . Ii1I % I1ii11iIi11i + I1ii11iIi11i
 if 32 - 32: Ii1I + II111iiii * IiII
 if 9 - 9: I1Ii111
def lisp_is_decent_dns_suffix ( dns_name ) :
 if ( lisp_decent_dns_suffix == None ) : return ( False )
 IiIIO0 = dns_name . split ( "." )
 IiIIO0 = "." . join ( IiIIO0 [ 1 : : ] )
 return ( IiIIO0 == lisp_decent_dns_suffix )
 if 96 - 96: I1Ii111 / iIii1I11I1II1
 if 48 - 48: iII111i * IiII + OoooooooOO
 if 63 - 63: I1IiiI / Ii1I
 if 31 - 31: i1IIi - oO0o
 if 99 - 99: iII111i - i11iIiiIii + oO0o
 if 66 - 66: Oo0Ooo * I11i . iIii1I11I1II1 - OoO0O00
 if 11 - 11: I1Ii111 + iIii1I11I1II1 * O0 * Oo0Ooo
def lisp_get_decent_index ( eid ) :
 I11i11i1 = eid . print_prefix ( )
 OoOOOo00O0 = hashlib . sha256 ( I11i11i1 ) . hexdigest ( )
 ooo = int ( OoOOOo00O0 , 16 ) % lisp_decent_modulus
 return ( ooo )
 if 17 - 17: Ii1I + iII111i - O0 - iIii1I11I1II1
 if 15 - 15: OoO0O00
 if 82 - 82: II111iiii + Ii1I * OOooOOo . II111iiii / i11iIiiIii + o0oOOo0O0Ooo
 if 57 - 57: iII111i
 if 50 - 50: o0oOOo0O0Ooo + iII111i / i1IIi % II111iiii
 if 61 - 61: IiII
 if 5 - 5: OOooOOo % iIii1I11I1II1 % O0 * i11iIiiIii / I1Ii111
def lisp_get_decent_dns_name ( eid ) :
 ooo = lisp_get_decent_index ( eid )
 return ( str ( ooo ) + "." + lisp_decent_dns_suffix )
 if 48 - 48: IiII * oO0o
 if 53 - 53: i1IIi * iIii1I11I1II1 . OOooOOo
 if 68 - 68: IiII % IiII - iII111i . IiII + OoooooooOO
 if 82 - 82: Ii1I . II111iiii / i1IIi * OoO0O00
 if 80 - 80: I11i
 if 96 - 96: i1IIi - I1ii11iIi11i * iII111i . OOooOOo . OoO0O00
 if 93 - 93: oO0o * Oo0Ooo * IiII
 if 26 - 26: o0oOOo0O0Ooo + O0 % i11iIiiIii . ooOoO0o . I1IiiI + Oo0Ooo
def lisp_get_decent_dns_name_from_str ( iid , eid_str ) :
 ooOOoo0 = lisp_address ( LISP_AFI_NONE , eid_str , 0 , iid )
 ooo = lisp_get_decent_index ( ooOOoo0 )
 return ( str ( ooo ) + "." + lisp_decent_dns_suffix )
 if 90 - 90: IiII * OoooooooOO + II111iiii / iII111i + i11iIiiIii / ooOoO0o
 if 20 - 20: II111iiii % I1ii11iIi11i - OoooooooOO * Ii1I / I11i - OoooooooOO
 if 11 - 11: I1IiiI + Ii1I + i11iIiiIii * I1ii11iIi11i - oO0o
 if 46 - 46: OoooooooOO - Oo0Ooo
 if 4 - 4: II111iiii . OOooOOo - Ii1I - i11iIiiIii
 if 27 - 27: iII111i * iII111i - OoO0O00 % o0oOOo0O0Ooo . o0oOOo0O0Ooo
 if 64 - 64: I1ii11iIi11i * ooOoO0o - OoooooooOO - I1IiiI
 if 59 - 59: I1ii11iIi11i . I1Ii111 - OOooOOo / Oo0Ooo + OOooOOo . I1ii11iIi11i
 if 69 - 69: Oo0Ooo
 if 34 - 34: I1Ii111 - ooOoO0o . o0oOOo0O0Ooo
def lisp_trace_append ( packet , reason = None , ed = "encap" , lisp_socket = None ,
 rloc_entry = None ) :
 if 52 - 52: o0oOOo0O0Ooo % I11i * I11i / iIii1I11I1II1
 OoO00oo00 = 28 if packet . inner_version == 4 else 48
 o0OooOo = packet . packet [ OoO00oo00 : : ]
 IIOo0Oo00o0 = lisp_trace ( )
 if ( IIOo0Oo00o0 . decode ( o0OooOo ) == False ) :
  lprint ( "Could not decode JSON portion of a LISP-Trace packet" )
  return ( False )
  if 56 - 56: I11i * Ii1I . i1IIi / ooOoO0o + Oo0Ooo % I1ii11iIi11i
  if 73 - 73: I1Ii111 - o0oOOo0O0Ooo % Ii1I + OOooOOo
 iI1i1 = "?" if packet . outer_dest . is_null ( ) else packet . outer_dest . print_address_no_iid ( )
 if 66 - 66: Oo0Ooo % oO0o
 if 52 - 52: oO0o
 if 26 - 26: OoO0O00 % I1ii11iIi11i * O0 % OoO0O00
 if 98 - 98: OoO0O00 . ooOoO0o * I11i / i1IIi
 if 57 - 57: i11iIiiIii % OOooOOo
 if 67 - 67: oO0o - OOooOOo + II111iiii
 if ( iI1i1 != "?" and packet . encap_port != LISP_DATA_PORT ) :
  if ( ed == "encap" ) : iI1i1 += ":{}" . format ( packet . encap_port )
  if 19 - 19: iIii1I11I1II1 * OoooooooOO - i11iIiiIii . I1Ii111 * OoO0O00
  if 30 - 30: iII111i + I1IiiI * ooOoO0o
  if 53 - 53: iII111i + IiII
  if 52 - 52: II111iiii * i11iIiiIii - IiII * IiII / OoooooooOO
  if 18 - 18: IiII / O0 / I1ii11iIi11i
 i1ii1i1Ii11 = { }
 i1ii1i1Ii11 [ "node" ] = "ITR" if lisp_i_am_itr else "ETR" if lisp_i_am_etr else "RTR" if lisp_i_am_rtr else "?"
 if 47 - 47: oO0o / iIii1I11I1II1
 IIiI1II1IIii = packet . outer_source
 if ( IIiI1II1IIii . is_null ( ) ) : IIiI1II1IIii = lisp_myrlocs [ 0 ]
 i1ii1i1Ii11 [ "srloc" ] = IIiI1II1IIii . print_address_no_iid ( )
 if 79 - 79: I1ii11iIi11i + O0 * OoooooooOO
 if 43 - 43: I11i
 if 29 - 29: o0oOOo0O0Ooo / I11i
 if 88 - 88: OoOoOO00 - Ii1I . O0 % I1Ii111 % I1ii11iIi11i
 if 56 - 56: OoOoOO00 - iIii1I11I1II1 / I1IiiI - i1IIi / o0oOOo0O0Ooo * I11i
 if ( i1ii1i1Ii11 [ "node" ] == "ITR" and packet . inner_sport != LISP_TRACE_PORT ) :
  i1ii1i1Ii11 [ "srloc" ] += ":{}" . format ( packet . inner_sport )
  if 70 - 70: OOooOOo
  if 11 - 11: I11i * II111iiii * Oo0Ooo + OOooOOo % i1IIi
 i1ii1i1Ii11 [ "hn" ] = lisp_hostname
 Oo000O000 = ed + "-ts"
 i1ii1i1Ii11 [ Oo000O000 ] = lisp_get_timestamp ( )
 if 73 - 73: OoO0O00 + O0 / Ii1I . OoooooooOO % iIii1I11I1II1 * i1IIi
 if 84 - 84: o0oOOo0O0Ooo . iII111i / o0oOOo0O0Ooo + I1ii11iIi11i % OoO0O00
 if 52 - 52: OoOoOO00 / Ii1I % OoOoOO00 % i11iIiiIii + I1IiiI / o0oOOo0O0Ooo
 if 63 - 63: I1IiiI
 if 20 - 20: oO0o + OoOoOO00
 if 32 - 32: o0oOOo0O0Ooo % oO0o % I1IiiI * OoooooooOO
 if ( iI1i1 == "?" and i1ii1i1Ii11 [ "node" ] == "ETR" ) :
  iiIII1 = lisp_db_for_lookups . lookup_cache ( packet . inner_dest , False )
  if ( iiIII1 != None and len ( iiIII1 . rloc_set ) >= 1 ) :
   iI1i1 = iiIII1 . rloc_set [ 0 ] . rloc . print_address_no_iid ( )
   if 4 - 4: OOooOOo % oO0o
   if 18 - 18: Ii1I * I11i
 i1ii1i1Ii11 [ "drloc" ] = iI1i1
 if 14 - 14: ooOoO0o . ooOoO0o * OoOoOO00 * o0oOOo0O0Ooo - iII111i - I1Ii111
 if 53 - 53: Oo0Ooo * OoOoOO00 * II111iiii % IiII - I1ii11iIi11i
 if 56 - 56: Oo0Ooo . I1ii11iIi11i - i11iIiiIii / iIii1I11I1II1 . ooOoO0o
 if 28 - 28: OoooooooOO + I1IiiI / oO0o . iIii1I11I1II1 - oO0o
 if ( iI1i1 == "?" and reason != None ) :
  i1ii1i1Ii11 [ "drloc" ] += " ({})" . format ( reason )
  if 64 - 64: I1Ii111 + Oo0Ooo / iII111i
  if 61 - 61: Ii1I * Ii1I . OoOoOO00 + OoO0O00 * i11iIiiIii * OoO0O00
  if 4 - 4: OoooooooOO % iII111i % Oo0Ooo * IiII % o0oOOo0O0Ooo . o0oOOo0O0Ooo
  if 66 - 66: I1IiiI . Oo0Ooo - oO0o
  if 53 - 53: oO0o / Ii1I + oO0o + II111iiii
 if ( rloc_entry != None ) :
  i1ii1i1Ii11 [ "rtts" ] = rloc_entry . recent_rloc_probe_rtts
  i1ii1i1Ii11 [ "hops" ] = rloc_entry . recent_rloc_probe_hops
  i1ii1i1Ii11 [ "latencies" ] = rloc_entry . recent_rloc_probe_latencies
  if 70 - 70: OoooooooOO - I1Ii111 + OoOoOO00
  if 61 - 61: I1IiiI * I1Ii111 * i11iIiiIii
  if 68 - 68: OoOoOO00 - iII111i - I1IiiI
  if 37 - 37: iII111i - I1Ii111 + i1IIi / o0oOOo0O0Ooo % iII111i / iII111i
  if 8 - 8: i1IIi % I11i
  if 12 - 12: ooOoO0o / II111iiii + ooOoO0o * I1ii11iIi11i / i1IIi - iIii1I11I1II1
 O00O0o = packet . inner_source . print_address ( )
 II1111 = packet . inner_dest . print_address ( )
 if ( IIOo0Oo00o0 . packet_json == [ ] ) :
  iI1iII11I1ii1 = { }
  iI1iII11I1ii1 [ "seid" ] = O00O0o
  iI1iII11I1ii1 [ "deid" ] = II1111
  iI1iII11I1ii1 [ "paths" ] = [ ]
  IIOo0Oo00o0 . packet_json . append ( iI1iII11I1ii1 )
  if 71 - 71: IiII - i11iIiiIii
  if 3 - 3: i11iIiiIii - o0oOOo0O0Ooo / oO0o . OoO0O00 * I11i + o0oOOo0O0Ooo
  if 18 - 18: OoooooooOO % oO0o / IiII - ooOoO0o
  if 80 - 80: I11i
  if 98 - 98: iII111i / I1ii11iIi11i
  if 87 - 87: iII111i - O0 * ooOoO0o / II111iiii % OoooooooOO . o0oOOo0O0Ooo
 for iI1iII11I1ii1 in IIOo0Oo00o0 . packet_json :
  if ( iI1iII11I1ii1 [ "deid" ] != II1111 ) : continue
  iI1iII11I1ii1 [ "paths" ] . append ( i1ii1i1Ii11 )
  break
  if 55 - 55: OOooOOo - o0oOOo0O0Ooo * I1IiiI / o0oOOo0O0Ooo + I1Ii111 + iIii1I11I1II1
  if 3 - 3: II111iiii % iII111i / IiII * ooOoO0o . OoooooooOO
  if 56 - 56: IiII * II111iiii + Oo0Ooo - O0 - OoO0O00 . I1Ii111
  if 53 - 53: i1IIi + IiII
  if 90 - 90: II111iiii / oO0o / oO0o . OoOoOO00 / OoO0O00 / iIii1I11I1II1
  if 96 - 96: iIii1I11I1II1 % I1ii11iIi11i
  if 35 - 35: i1IIi - OoooooooOO * Ii1I / OOooOOo % I11i
  if 72 - 72: I1Ii111 / OoO0O00 + II111iiii
 I1ii1i = False
 if ( len ( IIOo0Oo00o0 . packet_json ) == 1 and i1ii1i1Ii11 [ "node" ] == "ETR" and
 IIOo0Oo00o0 . myeid ( packet . inner_dest ) ) :
  iI1iII11I1ii1 = { }
  iI1iII11I1ii1 [ "seid" ] = II1111
  iI1iII11I1ii1 [ "deid" ] = O00O0o
  iI1iII11I1ii1 [ "paths" ] = [ ]
  IIOo0Oo00o0 . packet_json . append ( iI1iII11I1ii1 )
  I1ii1i = True
  if 23 - 23: i1IIi + I1Ii111 / IiII * O0 - I1Ii111
  if 90 - 90: Oo0Ooo / Ii1I
  if 66 - 66: i11iIiiIii - I11i + oO0o . OoooooooOO
  if 77 - 77: OoO0O00 / OOooOOo
  if 97 - 97: OoOoOO00 / Ii1I * I1IiiI - Oo0Ooo % O0
  if 66 - 66: O0 + I1IiiI % iIii1I11I1II1 . i1IIi % II111iiii - i1IIi
 IIOo0Oo00o0 . print_trace ( )
 o0OooOo = IIOo0Oo00o0 . encode ( )
 if 93 - 93: O0 + OoooooooOO % IiII % oO0o % I1ii11iIi11i
 if 36 - 36: I1IiiI - oO0o * Oo0Ooo + oO0o % iII111i - i11iIiiIii
 if 93 - 93: O0
 if 11 - 11: OoooooooOO . I1ii11iIi11i + I1ii11iIi11i
 if 73 - 73: OoooooooOO
 if 2 - 2: o0oOOo0O0Ooo % IiII + I1ii11iIi11i - i11iIiiIii
 if 100 - 100: II111iiii + oO0o
 if 85 - 85: I1ii11iIi11i % I1ii11iIi11i . Ii1I
 iIIii1 = IIOo0Oo00o0 . packet_json [ 0 ] [ "paths" ] [ 0 ] [ "srloc" ]
 if ( iI1i1 == "?" ) :
  lprint ( "LISP-Trace return to sender RLOC {}" . format ( iIIii1 ) )
  IIOo0Oo00o0 . return_to_sender ( lisp_socket , iIIii1 , o0OooOo )
  return ( False )
  if 67 - 67: I1ii11iIi11i . OoooooooOO * I1Ii111 + Ii1I * OOooOOo
  if 84 - 84: OOooOOo
  if 78 - 78: O0 % O0
  if 72 - 72: o0oOOo0O0Ooo * IiII / II111iiii / iIii1I11I1II1
  if 41 - 41: iII111i / Ii1I
  if 11 - 11: Oo0Ooo % OOooOOo . ooOoO0o
 O0OOOOo0 = IIOo0Oo00o0 . packet_length ( )
 if 24 - 24: IiII / Oo0Ooo
 if 90 - 90: ooOoO0o . OOooOOo - Ii1I
 if 60 - 60: i11iIiiIii % iII111i . I1IiiI * I1ii11iIi11i
 if 30 - 30: Ii1I + i11iIiiIii . I11i + o0oOOo0O0Ooo - OoO0O00
 if 55 - 55: ooOoO0o - II111iiii . ooOoO0o . iII111i / OoooooooOO
 if 51 - 51: I1IiiI * I1Ii111 - ooOoO0o + IiII
 iII11Ii111 = packet . packet [ 0 : OoO00oo00 ]
 oo00ooOOOo0O = struct . pack ( "HH" , socket . htons ( O0OOOOo0 ) , 0 )
 iII11Ii111 = iII11Ii111 [ 0 : OoO00oo00 - 4 ] + oo00ooOOOo0O
 if ( packet . inner_version == 6 and i1ii1i1Ii11 [ "node" ] == "ETR" and
 len ( IIOo0Oo00o0 . packet_json ) == 2 ) :
  o0oOo00 = iII11Ii111 [ OoO00oo00 - 8 : : ] + o0OooOo
  o0oOo00 = lisp_udp_checksum ( O00O0o , II1111 , o0oOo00 )
  iII11Ii111 = iII11Ii111 [ 0 : OoO00oo00 - 8 ] + o0oOo00 [ 0 : 8 ]
  if 62 - 62: Ii1I / Oo0Ooo / I1ii11iIi11i . OoOoOO00 % ooOoO0o * IiII
  if 97 - 97: ooOoO0o
  if 14 - 14: iII111i + iII111i
  if 62 - 62: ooOoO0o / OOooOOo * I1ii11iIi11i + Oo0Ooo - OoooooooOO - OoooooooOO
  if 19 - 19: Ii1I . oO0o
  if 26 - 26: OOooOOo + II111iiii
 if ( I1ii1i ) :
  if ( packet . inner_version == 4 ) :
   iII11Ii111 = iII11Ii111 [ 0 : 12 ] + iII11Ii111 [ 16 : 20 ] + iII11Ii111 [ 12 : 16 ] + iII11Ii111 [ 22 : 24 ] + iII11Ii111 [ 20 : 22 ] + iII11Ii111 [ 24 : : ]
   if 67 - 67: IiII + OoOoOO00 * I1ii11iIi11i % o0oOOo0O0Ooo / oO0o
  else :
   iII11Ii111 = iII11Ii111 [ 0 : 8 ] + iII11Ii111 [ 24 : 40 ] + iII11Ii111 [ 8 : 24 ] + iII11Ii111 [ 42 : 44 ] + iII11Ii111 [ 40 : 42 ] + iII11Ii111 [ 44 : : ]
   if 31 - 31: ooOoO0o / Ii1I . Ii1I - I1IiiI - Oo0Ooo . II111iiii
   if 82 - 82: Oo0Ooo % Oo0Ooo
  OooOOOoOoo0O0 = packet . inner_dest
  packet . inner_dest = packet . inner_source
  packet . inner_source = OooOOOoOoo0O0
  if 17 - 17: OOooOOo % Oo0Ooo . I1IiiI * O0 * oO0o % OoOoOO00
  if 99 - 99: Oo0Ooo - ooOoO0o . OoO0O00 - Oo0Ooo / O0
  if 42 - 42: Ii1I - OoOoOO00 . OoOoOO00
  if 88 - 88: o0oOOo0O0Ooo . Ii1I . iII111i * iII111i + i11iIiiIii
  if 68 - 68: OoooooooOO
 OoO00oo00 = 2 if packet . inner_version == 4 else 4
 IIi1111 = 20 + O0OOOOo0 if packet . inner_version == 4 else O0OOOOo0
 o0OO0O00o00 = struct . pack ( "H" , socket . htons ( IIi1111 ) )
 iII11Ii111 = iII11Ii111 [ 0 : OoO00oo00 ] + o0OO0O00o00 + iII11Ii111 [ OoO00oo00 + 2 : : ]
 if 36 - 36: I1ii11iIi11i + I1ii11iIi11i + I11i
 if 61 - 61: OoooooooOO / Oo0Ooo + II111iiii
 if 93 - 93: O0 * iIii1I11I1II1 % ooOoO0o . o0oOOo0O0Ooo
 if 13 - 13: iIii1I11I1II1
 if ( packet . inner_version == 4 ) :
  oOOoooo0o0 = struct . pack ( "H" , 0 )
  iII11Ii111 = iII11Ii111 [ 0 : 10 ] + oOOoooo0o0 + iII11Ii111 [ 12 : : ]
  o0OO0O00o00 = lisp_ip_checksum ( iII11Ii111 [ 0 : 20 ] )
  iII11Ii111 = o0OO0O00o00 + iII11Ii111 [ 20 : : ]
  if 48 - 48: iII111i - I1ii11iIi11i
  if 44 - 44: II111iiii + Oo0Ooo % OoOoOO00
  if 66 - 66: iII111i + Oo0Ooo
  if 74 - 74: OOooOOo / Ii1I / OoOoOO00
  if 26 - 26: o0oOOo0O0Ooo
 packet . packet = iII11Ii111 + o0OooOo
 return ( True )
 if 59 - 59: Oo0Ooo
 if 31 - 31: oO0o * i1IIi / II111iiii / I1ii11iIi11i - OoooooooOO + I11i
 if 5 - 5: OOooOOo % OoOoOO00 + O0 + O0
 if 32 - 32: I1ii11iIi11i . ooOoO0o
 if 15 - 15: oO0o % oO0o + iIii1I11I1II1
 if 19 - 19: IiII . I11i + oO0o
 if 24 - 24: OoOoOO00 . I1IiiI / Ii1I
 if 42 - 42: I1Ii111 / I1ii11iIi11i
 if 1 - 1: OOooOOo
 if 48 - 48: I1IiiI / OoooooooOO % I11i * Oo0Ooo
def lisp_allow_gleaning ( eid , group , rloc ) :
 if ( lisp_glean_mappings == [ ] ) : return ( False , False , False )
 if 20 - 20: Oo0Ooo
 for i1ii1i1Ii11 in lisp_glean_mappings :
  if ( i1ii1i1Ii11 . has_key ( "instance-id" ) ) :
   o0OoO0000o = eid . instance_id
   iI1111i1ii1i , i1I111 = i1ii1i1Ii11 [ "instance-id" ]
   if ( o0OoO0000o < iI1111i1ii1i or o0OoO0000o > i1I111 ) : continue
   if 85 - 85: I1Ii111
  if ( i1ii1i1Ii11 . has_key ( "eid-prefix" ) ) :
   oOo = copy . deepcopy ( i1ii1i1Ii11 [ "eid-prefix" ] )
   oOo . instance_id = eid . instance_id
   if ( eid . is_more_specific ( oOo ) == False ) : continue
   if 98 - 98: OoO0O00 - IiII % iIii1I11I1II1 . OoOoOO00 + i1IIi + OoooooooOO
  if ( i1ii1i1Ii11 . has_key ( "group-prefix" ) ) :
   if ( group == None ) : continue
   i11ii = copy . deepcopy ( i1ii1i1Ii11 [ "group-prefix" ] )
   i11ii . instance_id = group . instance_id
   if ( group . is_more_specific ( i11ii ) == False ) : continue
   if 29 - 29: I1ii11iIi11i * I1Ii111 - i1IIi * i11iIiiIii * iIii1I11I1II1 % I11i
  if ( i1ii1i1Ii11 . has_key ( "rloc-prefix" ) ) :
   if ( rloc != None and rloc . is_more_specific ( i1ii1i1Ii11 [ "rloc-prefix" ] )
 == False ) : continue
   if 73 - 73: OoO0O00 . I1IiiI / o0oOOo0O0Ooo
  return ( True , i1ii1i1Ii11 [ "rloc-probe" ] , i1ii1i1Ii11 [ "igmp-query" ] )
  if 12 - 12: I11i * i11iIiiIii - O0 * o0oOOo0O0Ooo - IiII + I1IiiI
 return ( False , False , False )
 if 7 - 7: oO0o + I1Ii111 . o0oOOo0O0Ooo / IiII + iIii1I11I1II1 % I1Ii111
 if 24 - 24: i11iIiiIii + iIii1I11I1II1
 if 22 - 22: i11iIiiIii . II111iiii / o0oOOo0O0Ooo / Ii1I . O0 . OoOoOO00
 if 89 - 89: O0 * Oo0Ooo + I1Ii111 + ooOoO0o * OoOoOO00
 if 20 - 20: OoO0O00 - OoOoOO00
 if 84 - 84: iIii1I11I1II1 + ooOoO0o . o0oOOo0O0Ooo % iII111i
 if 35 - 35: I11i - oO0o * oO0o / OoooooooOO + iII111i + OoOoOO00
def lisp_build_gleaned_multicast ( seid , geid , rloc , port , igmp ) :
 iI1i1iIi1iiII = geid . print_address ( )
 I1IIIIiIIIIiII = seid . print_address_no_iid ( )
 IiII1iiI = green ( "{}" . format ( I1IIIIiIIIIiII ) , False )
 oOo = green ( "(*, {})" . format ( iI1i1iIi1iiII ) , False )
 O0OOOO0o0O = red ( rloc . print_address_no_iid ( ) + ":" + str ( port ) , False )
 if 74 - 74: oO0o - i1IIi . Oo0Ooo / I1IiiI + o0oOOo0O0Ooo . OoOoOO00
 if 35 - 35: iII111i / Ii1I
 if 57 - 57: ooOoO0o . I1IiiI * OOooOOo
 if 87 - 87: I11i - I11i % iII111i - Ii1I
 iiI1iIi1II1ii = lisp_map_cache_lookup ( seid , geid )
 if ( iiI1iIi1II1ii == None ) :
  iiI1iIi1II1ii = lisp_mapping ( "" , "" , [ ] )
  iiI1iIi1II1ii . group . copy_address ( geid )
  iiI1iIi1II1ii . eid . copy_address ( geid )
  iiI1iIi1II1ii . eid . address = 0
  iiI1iIi1II1ii . eid . mask_len = 0
  iiI1iIi1II1ii . mapping_source . copy_address ( rloc )
  iiI1iIi1II1ii . map_cache_ttl = LISP_IGMP_TTL
  iiI1iIi1II1ii . gleaned = True
  iiI1iIi1II1ii . add_cache ( )
  lprint ( "Add gleaned EID {} to map-cache" . format ( oOo ) )
  if 29 - 29: oO0o - ooOoO0o * iIii1I11I1II1 / OoOoOO00
  if 34 - 34: I1IiiI . Oo0Ooo
  if 4 - 4: Ii1I - II111iiii * iII111i / oO0o - I1IiiI
  if 32 - 32: iIii1I11I1II1 - I11i
  if 49 - 49: I11i * I1Ii111 - iIii1I11I1II1 * O0
  if 72 - 72: I1IiiI * iII111i
 O0OooOoooO0O = O00O00O000OOo = Iii = None
 if ( iiI1iIi1II1ii . rloc_set != [ ] ) :
  O0OooOoooO0O = iiI1iIi1II1ii . rloc_set [ 0 ]
  if ( O0OooOoooO0O . rle ) :
   O00O00O000OOo = O0OooOoooO0O . rle
   for OOiIi1 in O00O00O000OOo . rle_nodes :
    if ( OOiIi1 . rloc_name != I1IIIIiIIIIiII ) : continue
    Iii = OOiIi1
    break
    if 46 - 46: OOooOOo / iII111i . i1IIi . i11iIiiIii . iIii1I11I1II1 % I11i
    if 62 - 62: I11i % II111iiii % OoooooooOO * ooOoO0o / oO0o
    if 29 - 29: o0oOOo0O0Ooo / O0 / OoO0O00
    if 23 - 23: Ii1I + i11iIiiIii % IiII
    if 64 - 64: i11iIiiIii + OoooooooOO . oO0o * Ii1I
    if 49 - 49: O0
    if 72 - 72: I1Ii111
 if ( O0OooOoooO0O == None ) :
  O0OooOoooO0O = lisp_rloc ( )
  iiI1iIi1II1ii . rloc_set = [ O0OooOoooO0O ]
  O0OooOoooO0O . priority = 253
  O0OooOoooO0O . mpriority = 255
  iiI1iIi1II1ii . build_best_rloc_set ( )
  if 96 - 96: II111iiii / OOooOOo % i1IIi / Oo0Ooo
 if ( O00O00O000OOo == None ) :
  O00O00O000OOo = lisp_rle ( geid . print_address ( ) )
  O0OooOoooO0O . rle = O00O00O000OOo
  if 22 - 22: I1IiiI % iIii1I11I1II1 % I1ii11iIi11i
 if ( Iii == None ) :
  Iii = lisp_rle_node ( )
  Iii . rloc_name = I1IIIIiIIIIiII
  O00O00O000OOo . rle_nodes . append ( Iii )
  O00O00O000OOo . build_forwarding_list ( )
  lprint ( "Add RLE {} from {} for gleaned EID {}" . format ( O0OOOO0o0O , IiII1iiI , oOo ) )
 elif ( rloc . is_exact_match ( Iii . address ) == False or
 port != Iii . translated_port ) :
  lprint ( "Changed RLE {} from {} for gleaned EID {}" . format ( O0OOOO0o0O , IiII1iiI , oOo ) )
  if 68 - 68: iII111i + I11i
  if 61 - 61: oO0o . I1Ii111
  if 74 - 74: O0 . Ii1I - iII111i % IiII + II111iiii
  if 71 - 71: oO0o + Ii1I % oO0o
  if 17 - 17: I1Ii111 % I1Ii111 * o0oOOo0O0Ooo
 Iii . store_translated_rloc ( rloc , port )
 if 84 - 84: I1Ii111 + iII111i . i1IIi / O0 / I1Ii111 + o0oOOo0O0Ooo
 if 70 - 70: O0 % ooOoO0o - iII111i + oO0o
 if 12 - 12: I1Ii111 - OoO0O00 % II111iiii % ooOoO0o / II111iiii % OoOoOO00
 if 74 - 74: iII111i . OOooOOo * Ii1I / Oo0Ooo . OoO0O00 . I11i
 if 65 - 65: i11iIiiIii - OoO0O00 / OoooooooOO * I1IiiI % iII111i
 if ( igmp ) :
  o00o = seid . print_address ( )
  if ( lisp_gleaned_groups . has_key ( o00o ) == False ) :
   lisp_gleaned_groups [ o00o ] = { }
   if 15 - 15: OOooOOo * Ii1I / ooOoO0o
  lisp_gleaned_groups [ o00o ] [ iI1i1iIi1iiII ] = lisp_get_timestamp ( )
  if 70 - 70: i11iIiiIii * oO0o . I11i - OoooooooOO / I1ii11iIi11i
  if 10 - 10: IiII * OoOoOO00 . II111iiii . II111iiii * Oo0Ooo
  if 23 - 23: I1ii11iIi11i + I11i
  if 74 - 74: i1IIi % I1IiiI
  if 44 - 44: Oo0Ooo - OoooooooOO % ooOoO0o + II111iiii
  if 60 - 60: o0oOOo0O0Ooo - ooOoO0o + i11iIiiIii % I1ii11iIi11i % II111iiii
  if 62 - 62: Ii1I
  if 30 - 30: iII111i % O0 + II111iiii * I1IiiI
def lisp_remove_gleaned_multicast ( seid , geid ) :
 if 91 - 91: i11iIiiIii
 if 35 - 35: OoOoOO00 * I1Ii111 / Oo0Ooo - i1IIi - IiII + OOooOOo
 if 96 - 96: Oo0Ooo + I1ii11iIi11i . O0
 if 62 - 62: i1IIi % OoooooooOO % OoooooooOO
 iiI1iIi1II1ii = lisp_map_cache_lookup ( seid , geid )
 if ( iiI1iIi1II1ii == None ) : return
 if 53 - 53: O0 * oO0o
 iI1Ii11 = iiI1iIi1II1ii . rloc_set [ 0 ] . rle
 if ( iI1Ii11 == None ) : return
 if 22 - 22: OOooOOo % Oo0Ooo % ooOoO0o - O0 + i1IIi
 oo0O0OOooO0 = seid . print_address_no_iid ( )
 ooOoOO0o = False
 for Iii in iI1Ii11 . rle_nodes :
  if ( Iii . rloc_name == oo0O0OOooO0 ) :
   ooOoOO0o = True
   break
   if 67 - 67: OoO0O00 / I1IiiI - IiII + iII111i - iII111i
   if 4 - 4: IiII . Ii1I . IiII % OoO0O00
 if ( ooOoOO0o == False ) : return
 if 12 - 12: OoOoOO00 + O0 / O0 . i1IIi
 if 58 - 58: IiII . iII111i % O0 . Ii1I * Oo0Ooo
 if 54 - 54: OoO0O00 % OOooOOo - OoO0O00 . Oo0Ooo % i1IIi
 if 95 - 95: iII111i . OoooooooOO . o0oOOo0O0Ooo / II111iiii - OoooooooOO / I1Ii111
 iI1Ii11 . rle_nodes . remove ( Iii )
 iI1Ii11 . build_forwarding_list ( )
 if 11 - 11: II111iiii / iII111i . oO0o / ooOoO0o / OOooOOo + OoO0O00
 iI1i1iIi1iiII = geid . print_address ( )
 o00o = seid . print_address ( )
 IiII1iiI = green ( "{}" . format ( o00o ) , False )
 oOo = green ( "(*, {})" . format ( iI1i1iIi1iiII ) , False )
 lprint ( "Gleaned EID {} RLE removed for {}" . format ( oOo , IiII1iiI ) )
 if 37 - 37: iIii1I11I1II1 * O0
 if 64 - 64: I1Ii111 - II111iiii + oO0o % ooOoO0o * oO0o
 if 27 - 27: iIii1I11I1II1 - Ii1I . i11iIiiIii / IiII . I1Ii111 / i11iIiiIii
 if 27 - 27: OoOoOO00 . I11i / OoOoOO00
 if ( lisp_gleaned_groups . has_key ( o00o ) ) :
  if ( lisp_gleaned_groups [ o00o ] . has_key ( iI1i1iIi1iiII ) ) :
   lisp_gleaned_groups [ o00o ] . pop ( iI1i1iIi1iiII )
   if 96 - 96: OoO0O00 - I1IiiI
   if 73 - 73: I1IiiI - o0oOOo0O0Ooo - I1Ii111
   if 34 - 34: iIii1I11I1II1 - i1IIi + OoO0O00 % Oo0Ooo + i1IIi
   if 46 - 46: I1IiiI
   if 82 - 82: iII111i . i1IIi
   if 38 - 38: Ii1I . I1IiiI . I1ii11iIi11i
 if ( iI1Ii11 . rle_nodes == [ ] ) :
  iiI1iIi1II1ii . delete_cache ( )
  lprint ( "Gleaned EID {} remove, no more RLEs" . format ( oOo ) )
  if 26 - 26: O0 - II111iiii * I1Ii111 - OoOoOO00
  if 96 - 96: I11i * Oo0Ooo / OOooOOo - IiII
  if 75 - 75: OoooooooOO - O0
  if 39 - 39: i11iIiiIii / Ii1I / ooOoO0o
  if 93 - 93: o0oOOo0O0Ooo - Oo0Ooo / oO0o / OoOoOO00
  if 75 - 75: o0oOOo0O0Ooo * ooOoO0o % Ii1I
  if 94 - 94: OoooooooOO + II111iiii / iIii1I11I1II1 * ooOoO0o
  if 85 - 85: ooOoO0o / IiII
def lisp_change_gleaned_multicast ( seid , rloc , port ) :
 o00o = seid . print_address ( )
 if ( lisp_gleaned_groups . has_key ( o00o ) == False ) : return
 if 28 - 28: i11iIiiIii - OoOoOO00
 for IIi1iiIII11 in lisp_gleaned_groups [ o00o ] :
  lisp_geid . store_address ( IIi1iiIII11 )
  lisp_build_gleaned_multicast ( seid , lisp_geid , rloc , port , False )
  if 13 - 13: O0
  if 82 - 82: OoooooooOO
  if 59 - 59: I1Ii111 + I1ii11iIi11i + OoO0O00 % oO0o . i1IIi % O0
  if 22 - 22: i1IIi * OoOoOO00 + Ii1I
  if 48 - 48: Ii1I % IiII + OoO0O00 . IiII
  if 42 - 42: Ii1I
  if 70 - 70: I11i
  if 82 - 82: O0
  if 58 - 58: II111iiii . O0 - OoO0O00 - IiII
  if 4 - 4: i11iIiiIii + i11iIiiIii / O0
  if 46 - 46: I11i % ooOoO0o - Ii1I
  if 25 - 25: O0 / i11iIiiIii . O0
  if 24 - 24: I1ii11iIi11i - i11iIiiIii / iII111i . Oo0Ooo / I1ii11iIi11i
  if 92 - 92: I11i % OoooooooOO
  if 14 - 14: i11iIiiIii * i11iIiiIii * OoOoOO00
  if 84 - 84: OOooOOo % I1Ii111 + I11i / I1IiiI . iII111i
  if 78 - 78: oO0o . Oo0Ooo
  if 18 - 18: IiII
  if 35 - 35: OoooooooOO / i1IIi - OoO0O00 + Oo0Ooo - o0oOOo0O0Ooo
  if 100 - 100: II111iiii % i11iIiiIii % oO0o + O0
  if 46 - 46: OoO0O00 / I1IiiI - Oo0Ooo . o0oOOo0O0Ooo . Oo0Ooo % I11i
  if 43 - 43: IiII - O0 + I1Ii111 % OoooooooOO % OoO0O00 / I1Ii111
  if 48 - 48: I1ii11iIi11i . i1IIi % i1IIi - iII111i * o0oOOo0O0Ooo + IiII
  if 45 - 45: II111iiii . II111iiii + I1IiiI / I1Ii111 . OoO0O00 - o0oOOo0O0Ooo
  if 20 - 20: ooOoO0o % oO0o
  if 28 - 28: i1IIi . II111iiii + O0 / O0 % OoOoOO00 + OOooOOo
  if 24 - 24: OoooooooOO
  if 11 - 11: i11iIiiIii / iIii1I11I1II1 % ooOoO0o + OOooOOo
  if 73 - 73: OoOoOO00 + OoooooooOO + iIii1I11I1II1 + II111iiii * iIii1I11I1II1 - OoOoOO00
  if 71 - 71: O0 * OOooOOo . I1IiiI . I1Ii111 * I11i
  if 45 - 45: O0 . O0 . II111iiii * ooOoO0o
  if 2 - 2: OoO0O00 . o0oOOo0O0Ooo
  if 48 - 48: Ii1I
  if 45 - 45: I1ii11iIi11i - I11i + Ii1I
  if 82 - 82: iII111i
  if 81 - 81: i1IIi % OOooOOo - OoO0O00 - Oo0Ooo
  if 19 - 19: i1IIi
  if 97 - 97: OoO0O00 + i11iIiiIii % I1IiiI * Ii1I
  if 89 - 89: IiII % i11iIiiIii + OoO0O00 . oO0o / I1IiiI . Ii1I
  if 11 - 11: ooOoO0o - I1Ii111 - I11i + OoOoOO00
  if 20 - 20: I11i + O0
  if 27 - 27: Oo0Ooo
  if 12 - 12: I1ii11iIi11i . iII111i - iII111i - OOooOOo - iIii1I11I1II1
  if 50 - 50: I1IiiI - iIii1I11I1II1 . iII111i - Ii1I / I1Ii111 + iII111i
  if 46 - 46: OOooOOo + iII111i % Oo0Ooo * iII111i % OoooooooOO * IiII
  if 27 - 27: I1IiiI + I1IiiI + I1ii11iIi11i - oO0o * OOooOOo
  if 53 - 53: I1ii11iIi11i / OoooooooOO * iIii1I11I1II1
  if 4 - 4: I1IiiI . iIii1I11I1II1 + OOooOOo / IiII . o0oOOo0O0Ooo . I11i
  if 52 - 52: ooOoO0o % i11iIiiIii . IiII + OoO0O00
  if 66 - 66: II111iiii . Ii1I
  if 42 - 42: iIii1I11I1II1 * iII111i * I1IiiI
  if 66 - 66: Oo0Ooo * i1IIi / I1ii11iIi11i / OoO0O00
  if 12 - 12: OOooOOo + iIii1I11I1II1 % I1Ii111 + OOooOOo
  if 19 - 19: OoO0O00 / I1IiiI - o0oOOo0O0Ooo - i1IIi + I1ii11iIi11i * OoooooooOO
  if 74 - 74: I1Ii111 . I11i / Oo0Ooo
  if 88 - 88: oO0o % OoO0O00 - i11iIiiIii % I1Ii111 / O0 * IiII
  if 99 - 99: o0oOOo0O0Ooo . ooOoO0o / i11iIiiIii
  if 44 - 44: IiII + OOooOOo % OoO0O00 . OoooooooOO * O0
  if 72 - 72: i1IIi - iII111i * I1IiiI % O0 - I11i * O0
  if 78 - 78: I1IiiI - OoO0O00 / Ii1I . i1IIi
  if 30 - 30: IiII
  if 21 - 21: i1IIi . iII111i - I1IiiI
  if 28 - 28: IiII / Ii1I - i1IIi - OoOoOO00
  if 65 - 65: o0oOOo0O0Ooo * OoO0O00 / o0oOOo0O0Ooo
  if 77 - 77: OoooooooOO - Oo0Ooo - OoOoOO00 / I11i / O0 . i11iIiiIii
  if 27 - 27: I1Ii111 * O0
  if 9 - 9: i1IIi - Oo0Ooo - i11iIiiIii / iIii1I11I1II1 . i1IIi
  if 2 - 2: I11i + II111iiii - I11i / oO0o / I11i
  if 73 - 73: IiII % I1Ii111 . OoOoOO00
  if 96 - 96: I1IiiI / ooOoO0o / iIii1I11I1II1
  if 91 - 91: Ii1I . I11i
  if 87 - 87: Oo0Ooo / IiII * OOooOOo + I1ii11iIi11i . I11i
  if 56 - 56: oO0o + oO0o % o0oOOo0O0Ooo + OOooOOo . II111iiii + i11iIiiIii
  if 45 - 45: iIii1I11I1II1 / o0oOOo0O0Ooo * OoooooooOO - Oo0Ooo
  if 77 - 77: II111iiii
  if 8 - 8: I1IiiI * II111iiii % I1ii11iIi11i
  if 88 - 88: Oo0Ooo . oO0o + OoOoOO00 % OoooooooOO
  if 81 - 81: OoooooooOO . I1Ii111 + OoO0O00 % I1Ii111
  if 49 - 49: oO0o . oO0o % oO0o / Oo0Ooo
  if 62 - 62: ooOoO0o . i1IIi % OoO0O00 - I1ii11iIi11i - IiII
  if 57 - 57: i1IIi - II111iiii - O0 . iII111i + OoO0O00
  if 67 - 67: OOooOOo * iII111i / iIii1I11I1II1 / I1ii11iIi11i
  if 10 - 10: OoooooooOO % I1ii11iIi11i * i1IIi . iII111i
  if 96 - 96: II111iiii % i11iIiiIii - Oo0Ooo
  if 70 - 70: O0 * iIii1I11I1II1 - IiII * I11i / Ii1I + i11iIiiIii
  if 26 - 26: II111iiii - I11i % I11i / ooOoO0o + Oo0Ooo
  if 91 - 91: I1IiiI % Ii1I - OOooOOo - Oo0Ooo / I1IiiI / OoO0O00
  if 40 - 40: OoooooooOO
  if 71 - 71: OOooOOo
  if 88 - 88: O0
  if 44 - 44: II111iiii - IiII / I1IiiI + ooOoO0o % iII111i - iII111i
  if 53 - 53: OoooooooOO
igmp_types = { 17 : "IGMP-query" , 18 : "IGMPv1-report" , 19 : "DVMRP" ,
 20 : "PIMv1" , 22 : "IGMPv2-report" , 23 : "IGMPv2-leave" ,
 30 : "mtrace-response" , 31 : "mtrace-request" , 34 : "IGMPv3-report" }
if 41 - 41: i1IIi - oO0o
lisp_igmp_record_types = { 1 : "include-mode" , 2 : "exclude-mode" ,
 3 : "change-to-include" , 4 : "change-to-exclude" , 5 : "allow-new-source" ,
 6 : "block-old-sources" }
if 41 - 41: I11i
def lisp_process_igmp_packet ( packet ) :
 i1IIi1ii1i1ii = lisp_address ( LISP_AFI_IPV4 , "" , 32 , 0 )
 i1IIi1ii1i1ii . address = socket . ntohl ( struct . unpack ( "I" , packet [ 12 : 16 ] ) [ 0 ] )
 i1IIi1ii1i1ii = bold ( "from {}" . format ( i1IIi1ii1i1ii . print_address_no_iid ( ) ) , False )
 if 92 - 92: i11iIiiIii
 O0OOOO0o0O = bold ( "Receive" , False )
 lprint ( "{} {}-byte {}, IGMP packet: {}" . format ( O0OOOO0o0O , len ( packet ) , i1IIi1ii1i1ii ,
 lisp_format_packet ( packet ) ) )
 if 62 - 62: i1IIi / I1IiiI - o0oOOo0O0Ooo
 if 3 - 3: O0 * OoOoOO00 * I11i / OoOoOO00
 if 77 - 77: i1IIi
 if 3 - 3: iII111i * OoO0O00 - oO0o + iII111i . o0oOOo0O0Ooo + I1IiiI
 ooO0o = ( struct . unpack ( "B" , packet [ 0 ] ) [ 0 ] & 0x0f ) * 4
 if 43 - 43: O0
 if 22 - 22: OoOoOO00 . O0 - I1Ii111
 if 78 - 78: I1Ii111 * Ii1I % Ii1I + I1IiiI
 if 83 - 83: iIii1I11I1II1 + O0 / IiII . iIii1I11I1II1
 oOooo0 = packet [ ooO0o : : ]
 oO0O0 = struct . unpack ( "B" , oOooo0 [ 0 ] ) [ 0 ]
 if 8 - 8: IiII * ooOoO0o . o0oOOo0O0Ooo - I1Ii111
 if 10 - 10: I1Ii111
 if 27 - 27: iIii1I11I1II1
 if 40 - 40: iIii1I11I1II1 + oO0o / iIii1I11I1II1 - i1IIi % OoO0O00
 if 22 - 22: OOooOOo
 IIi1iiIII11 = lisp_address ( LISP_AFI_IPV4 , "" , 32 , 0 )
 IIi1iiIII11 . address = socket . ntohl ( struct . unpack ( "II" , oOooo0 [ : 8 ] ) [ 1 ] )
 iI1i1iIi1iiII = IIi1iiIII11 . print_address_no_iid ( )
 if 65 - 65: i1IIi - oO0o . I1Ii111 . ooOoO0o % I1ii11iIi11i % I1ii11iIi11i
 if ( oO0O0 == 17 ) :
  lprint ( "IGMP Query for group {}" . format ( iI1i1iIi1iiII ) )
  return ( True )
  if 1 - 1: I1Ii111 + I1Ii111
  if 96 - 96: iII111i + OoOoOO00 - o0oOOo0O0Ooo + Ii1I
 ii1IIi = ( oO0O0 in ( 0x12 , 0x16 , 0x17 , 0x22 ) )
 if ( ii1IIi == False ) :
  IIII = "{} ({})" . format ( oO0O0 , igmp_types [ oO0O0 ] ) if igmp_types . has_key ( oO0O0 ) else oO0O0
  if 58 - 58: I1ii11iIi11i - I1Ii111
  lprint ( "IGMP type {} not supported" . format ( IIII ) )
  return ( [ ] )
  if 82 - 82: I1IiiI * I1IiiI / iIii1I11I1II1
  if 14 - 14: I11i + Ii1I - OOooOOo % Ii1I / Ii1I
 if ( len ( oOooo0 ) < 8 ) :
  lprint ( "IGMP message too small" )
  return ( [ ] )
  if 86 - 86: I1Ii111 - i11iIiiIii + Ii1I + I11i
  if 96 - 96: Ii1I
  if 28 - 28: i1IIi . oO0o . IiII + Oo0Ooo . Oo0Ooo . i1IIi
  if 34 - 34: Oo0Ooo + IiII / i1IIi
  if 33 - 33: i1IIi
 if ( oO0O0 == 0x17 ) :
  lprint ( "IGMPv2 leave (*, {})" . format ( bold ( iI1i1iIi1iiII , False ) ) )
  return ( [ [ None , iI1i1iIi1iiII , False ] ] )
  if 26 - 26: ooOoO0o - Oo0Ooo * II111iiii - Oo0Ooo
 if ( oO0O0 in ( 0x12 , 0x16 ) ) :
  lprint ( "IGMPv{} join (*, {})" . format ( 1 if ( oO0O0 == 0x12 ) else 2 , bold ( iI1i1iIi1iiII , False ) ) )
  if 15 - 15: OoO0O00 - oO0o . OoOoOO00 / O0 * oO0o
  if 45 - 45: O0
  if 89 - 89: IiII - IiII % o0oOOo0O0Ooo * Oo0Ooo % ooOoO0o
  if 4 - 4: OoO0O00 % II111iiii / I11i
  if 95 - 95: I1Ii111 - I1Ii111 - iII111i + IiII . OoO0O00
  if ( iI1i1iIi1iiII . find ( "224.0.0." ) != - 1 ) :
   lprint ( "Suppress registration for link-local groups" )
  else :
   return ( [ [ None , iI1i1iIi1iiII , True ] ] )
   if 5 - 5: i11iIiiIii - O0 % ooOoO0o
   if 55 - 55: II111iiii
   if 7 - 7: I1Ii111 % o0oOOo0O0Ooo . oO0o . ooOoO0o % i1IIi / I1IiiI
   if 88 - 88: i11iIiiIii / oO0o - i1IIi / I1IiiI
   if 57 - 57: oO0o + O0 * I11i
  return ( [ ] )
  if 87 - 87: o0oOOo0O0Ooo % Oo0Ooo * I1ii11iIi11i / OoooooooOO / o0oOOo0O0Ooo
  if 78 - 78: Ii1I
  if 5 - 5: i1IIi * ooOoO0o / OoOoOO00 % i11iIiiIii
  if 57 - 57: IiII
  if 89 - 89: I1ii11iIi11i - I1Ii111 + o0oOOo0O0Ooo
 I1Ii11 = IIi1iiIII11 . address
 oOooo0 = oOooo0 [ 8 : : ]
 if 62 - 62: I1ii11iIi11i + OoooooooOO * OOooOOo
 ii11iiiII = "BBHI"
 O0oo00oOOO = struct . calcsize ( ii11iiiII )
 iIiIi11IiiI11ii = "I"
 i11iIiI1i11I1 = struct . calcsize ( iIiIi11IiiI11ii )
 i1IIi1ii1i1ii = lisp_address ( LISP_AFI_IPV4 , "" , 32 , 0 )
 if 92 - 92: o0oOOo0O0Ooo + oO0o + OoooooooOO * OoOoOO00 + I1Ii111 . I1ii11iIi11i
 if 29 - 29: oO0o . Oo0Ooo
 if 58 - 58: o0oOOo0O0Ooo - iIii1I11I1II1 + i1IIi
 if 36 - 36: OOooOOo
 OoO0O = [ ]
 for IiIIi1IiiIiI in range ( I1Ii11 ) :
  if ( len ( oOooo0 ) < O0oo00oOOO ) : return
  oo0OO0ooo0 , O0O , OOoOOo0 , ii1i1II11II1i = struct . unpack ( ii11iiiII ,
 oOooo0 [ : O0oo00oOOO ] )
  if 51 - 51: OOooOOo . OOooOOo . I1IiiI
  oOooo0 = oOooo0 [ O0oo00oOOO : : ]
  if 90 - 90: I1Ii111
  if ( lisp_igmp_record_types . has_key ( oo0OO0ooo0 ) == False ) :
   lprint ( "Invalid record type {}" . format ( oo0OO0ooo0 ) )
   continue
   if 88 - 88: I1IiiI % Oo0Ooo
   if 31 - 31: Oo0Ooo % Oo0Ooo . o0oOOo0O0Ooo * Oo0Ooo
  O00O = lisp_igmp_record_types [ oo0OO0ooo0 ]
  OOoOOo0 = socket . ntohs ( OOoOOo0 )
  IIi1iiIII11 . address = socket . ntohl ( ii1i1II11II1i )
  iI1i1iIi1iiII = IIi1iiIII11 . print_address_no_iid ( )
  if 17 - 17: Ii1I * Ii1I
  lprint ( "Record type: {}, group: {}, source-count: {}" . format ( O00O , iI1i1iIi1iiII , OOoOOo0 ) )
  if 60 - 60: oO0o % i1IIi * iIii1I11I1II1 . IiII - iIii1I11I1II1
  if 79 - 79: Ii1I / i11iIiiIii . I1Ii111
  if 43 - 43: iII111i + iII111i * O0
  if 28 - 28: II111iiii * iII111i - o0oOOo0O0Ooo
  if 42 - 42: iII111i - iII111i
  if 93 - 93: I11i * iIii1I11I1II1
  if 89 - 89: II111iiii . O0
  iI1iiiI1I1iI = False
  if ( oo0OO0ooo0 in ( 1 , 5 ) ) : iI1iiiI1I1iI = True
  if ( oo0OO0ooo0 in ( 2 , 4 ) and OOoOOo0 == 0 ) : iI1iiiI1I1iI = True
  oOOOooooo00oo = "join" if ( iI1iiiI1I1iI ) else "leave"
  if 7 - 7: OoO0O00 / ooOoO0o + i11iIiiIii * o0oOOo0O0Ooo
  if 10 - 10: OOooOOo * OoooooooOO
  if 1 - 1: iII111i . I1ii11iIi11i - ooOoO0o + OoO0O00 . OoooooooOO
  if 71 - 71: I1ii11iIi11i
  if ( iI1i1iIi1iiII . find ( "224.0.0." ) != - 1 ) :
   lprint ( "Suppress registration for link-local groups" )
   continue
   if 59 - 59: I1Ii111 + OoO0O00 + II111iiii
   if 12 - 12: I1Ii111 % I1ii11iIi11i - I1Ii111 + I11i
   if 62 - 62: I1Ii111 % I11i % IiII - ooOoO0o . oO0o - OoooooooOO
   if 14 - 14: OOooOOo + Oo0Ooo % i1IIi + iIii1I11I1II1
   if 64 - 64: OoOoOO00 / Ii1I * Oo0Ooo - I1ii11iIi11i
   if 9 - 9: i11iIiiIii % Oo0Ooo + IiII + Ii1I . ooOoO0o / i1IIi
   if 40 - 40: I1Ii111 + I1IiiI - Ii1I
   if 27 - 27: i1IIi
  if ( OOoOOo0 == 0 ) :
   OoO0O . append ( [ None , iI1i1iIi1iiII , iI1iiiI1I1iI ] )
   lprint ( "IGMPv3 {} (*, {})" . format ( bold ( oOOOooooo00oo , False ) ,
 bold ( iI1i1iIi1iiII , False ) ) )
   if 66 - 66: iII111i - ooOoO0o / i11iIiiIii + I1ii11iIi11i - Ii1I
   if 9 - 9: O0
   if 96 - 96: Oo0Ooo . II111iiii
   if 41 - 41: I1ii11iIi11i % o0oOOo0O0Ooo
   if 86 - 86: O0 * OoOoOO00 * O0 / O0
  for I11I1iiI111i1 in range ( OOoOOo0 ) :
   if ( len ( oOooo0 ) < i11iIiI1i11I1 ) : return
   ii1i1II11II1i = struct . unpack ( iIiIi11IiiI11ii , oOooo0 [ : i11iIiI1i11I1 ] ) [ 0 ]
   i1IIi1ii1i1ii . address = socket . ntohl ( ii1i1II11II1i )
   iIii = i1IIi1ii1i1ii . print_address_no_iid ( )
   OoO0O . append ( [ iIii , iI1i1iIi1iiII , iI1iiiI1I1iI ] )
   lprint ( "{} ({}, {})" . format ( oOOOooooo00oo ,
 green ( iIii , False ) , bold ( iI1i1iIi1iiII , False ) ) )
   oOooo0 = oOooo0 [ i11iIiI1i11I1 : : ]
   if 96 - 96: I1Ii111 / OoO0O00
   if 27 - 27: Ii1I
   if 90 - 90: I1ii11iIi11i
   if 43 - 43: OoO0O00 . I1IiiI . oO0o + Ii1I
   if 7 - 7: iII111i / Oo0Ooo - OoO0O00 + I1Ii111 * II111iiii * ooOoO0o
   if 80 - 80: oO0o - i1IIi / I11i . II111iiii % O0 % I11i
   if 70 - 70: iIii1I11I1II1 * i1IIi * OOooOOo - Oo0Ooo % i1IIi
   if 60 - 60: o0oOOo0O0Ooo . OOooOOo % II111iiii - I1ii11iIi11i
 return ( OoO0O )
 if 4 - 4: OOooOOo % ooOoO0o
 if 39 - 39: Ii1I
 if 67 - 67: iIii1I11I1II1 - OOooOOo
 if 47 - 47: OOooOOo - OOooOOo * I1Ii111
 if 24 - 24: I1ii11iIi11i
 if 37 - 37: II111iiii - iIii1I11I1II1 / o0oOOo0O0Ooo . O0 + II111iiii
 if 9 - 9: o0oOOo0O0Ooo
 if 47 - 47: Ii1I * I1Ii111 / II111iiii
lisp_geid = lisp_address ( LISP_AFI_IPV4 , "" , 32 , 0 )
if 73 - 73: ooOoO0o
def lisp_glean_map_cache ( seid , rloc , encap_port , igmp ) :
 if 53 - 53: IiII . Oo0Ooo
 if 54 - 54: i11iIiiIii % ooOoO0o % I1Ii111 + o0oOOo0O0Ooo
 if 2 - 2: IiII
 if 25 - 25: OoOoOO00 . OoO0O00 * o0oOOo0O0Ooo . OoooooooOO - Oo0Ooo + I1IiiI
 if 82 - 82: OoO0O00 - Ii1I * I11i * o0oOOo0O0Ooo
 if 17 - 17: OoooooooOO + I1Ii111
 ooOoO000O0 = True
 iiI1iIi1II1ii = lisp_map_cache . lookup_cache ( seid , True )
 if ( iiI1iIi1II1ii and len ( iiI1iIi1II1ii . rloc_set ) != 0 ) :
  iiI1iIi1II1ii . last_refresh_time = lisp_get_timestamp ( )
  if 30 - 30: I1Ii111 * oO0o . I11i . I1ii11iIi11i
  IiI1I = iiI1iIi1II1ii . rloc_set [ 0 ]
  IiI1I1I1I = IiI1I . rloc
  i1Oo = IiI1I . translated_port
  ooOoO000O0 = ( IiI1I1I1I . is_exact_match ( rloc ) == False or
 i1Oo != encap_port )
  if 5 - 5: OOooOOo
  if ( ooOoO000O0 ) :
   oOo = green ( seid . print_address ( ) , False )
   O0OOOO0o0O = red ( rloc . print_address_no_iid ( ) + ":" + str ( encap_port ) , False )
   lprint ( "Change gleaned EID {} to RLOC {}" . format ( oOo , O0OOOO0o0O ) )
   IiI1I . delete_from_rloc_probe_list ( iiI1iIi1II1ii . eid , iiI1iIi1II1ii . group )
   lisp_change_gleaned_multicast ( seid , rloc , encap_port )
   if 22 - 22: Ii1I . I1ii11iIi11i * I1ii11iIi11i * OoOoOO00
 else :
  iiI1iIi1II1ii = lisp_mapping ( "" , "" , [ ] )
  iiI1iIi1II1ii . eid . copy_address ( seid )
  iiI1iIi1II1ii . mapping_source . copy_address ( rloc )
  iiI1iIi1II1ii . map_cache_ttl = LISP_GLEAN_TTL
  iiI1iIi1II1ii . gleaned = True
  oOo = green ( seid . print_address ( ) , False )
  O0OOOO0o0O = red ( rloc . print_address_no_iid ( ) + ":" + str ( encap_port ) , False )
  lprint ( "Add gleaned EID {} to map-cache with RLOC {}" . format ( oOo , O0OOOO0o0O ) )
  iiI1iIi1II1ii . add_cache ( )
  if 23 - 23: I1ii11iIi11i - OoOoOO00 + i11iIiiIii . I11i
  if 52 - 52: iII111i . OoOoOO00 * iIii1I11I1II1 . iII111i * IiII
  if 52 - 52: iII111i + iII111i
  if 35 - 35: I1Ii111 * oO0o + Ii1I / I1IiiI + O0 - I11i
  if 42 - 42: o0oOOo0O0Ooo
 if ( ooOoO000O0 ) :
  O0OooOoooO0O = lisp_rloc ( )
  O0OooOoooO0O . store_translated_rloc ( rloc , encap_port )
  O0OooOoooO0O . add_to_rloc_probe_list ( iiI1iIi1II1ii . eid , iiI1iIi1II1ii . group )
  O0OooOoooO0O . priority = 253
  O0OooOoooO0O . mpriority = 255
  o0oo0OoOo000 = [ O0OooOoooO0O ]
  iiI1iIi1II1ii . rloc_set = o0oo0OoOo000
  iiI1iIi1II1ii . build_best_rloc_set ( )
  if 89 - 89: o0oOOo0O0Ooo
  if 99 - 99: I1ii11iIi11i + Oo0Ooo
  if 20 - 20: OoO0O00 / iII111i
  if 62 - 62: i1IIi % iIii1I11I1II1 + OoOoOO00 - I1IiiI . I1ii11iIi11i
  if 92 - 92: i11iIiiIii * o0oOOo0O0Ooo . Oo0Ooo
 if ( igmp == None ) : return
 if 15 - 15: o0oOOo0O0Ooo * IiII . iII111i % O0 . iIii1I11I1II1
 if 34 - 34: OOooOOo / iII111i * iIii1I11I1II1 + i11iIiiIii
 if 37 - 37: I11i + o0oOOo0O0Ooo . o0oOOo0O0Ooo
 if 8 - 8: Oo0Ooo * Ii1I % I11i - OoooooooOO
 if 11 - 11: OoO0O00 - oO0o
 lisp_geid . instance_id = seid . instance_id
 if 50 - 50: II111iiii * IiII
 if 26 - 26: OoO0O00 . II111iiii
 if 19 - 19: iII111i / i11iIiiIii
 if 31 - 31: I1Ii111 / I1Ii111 % IiII
 if 68 - 68: O0 / OOooOOo % OoOoOO00
 I1iiIiii1IiIii = lisp_process_igmp_packet ( igmp )
 if ( type ( I1iiIiii1IiIii ) == bool ) : return
 if 68 - 68: OoooooooOO - IiII + I1IiiI * IiII / I11i - OoO0O00
 for i1IIi1ii1i1ii , IIi1iiIII11 , iI1iiiI1I1iI in I1iiIiii1IiIii :
  if ( i1IIi1ii1i1ii != None ) : continue
  if 69 - 69: oO0o / II111iiii
  if 56 - 56: i1IIi + II111iiii + Ii1I . OoooooooOO
  if 26 - 26: OoooooooOO % Ii1I % I11i * oO0o - i1IIi - i1IIi
  if 76 - 76: i11iIiiIii + OoO0O00 - iII111i . OoOoOO00 * Oo0Ooo
  lisp_geid . store_address ( IIi1iiIII11 )
  oOoOoOo0 , O0O , IIIi1i1iIIIi = lisp_allow_gleaning ( seid , lisp_geid , rloc )
  if ( oOoOoOo0 == False ) : continue
  if 15 - 15: II111iiii + iIii1I11I1II1
  if ( iI1iiiI1I1iI ) :
   lisp_build_gleaned_multicast ( seid , lisp_geid , rloc , encap_port ,
 True )
  else :
   lisp_remove_gleaned_multicast ( seid , lisp_geid )
   if 100 - 100: OOooOOo
   if 43 - 43: OoO0O00 + I1Ii111 + OoOoOO00
   if 78 - 78: I11i
   if 30 - 30: iIii1I11I1II1
   if 74 - 74: I1IiiI - Oo0Ooo - i1IIi . iIii1I11I1II1 - I11i
   if 57 - 57: I1IiiI - i11iIiiIii - I1ii11iIi11i
   if 49 - 49: i1IIi . O0 % Ii1I * i1IIi
   if 39 - 39: I1ii11iIi11i
   if 74 - 74: II111iiii % oO0o * Oo0Ooo / iIii1I11I1II1
   if 81 - 81: II111iiii + OoOoOO00 * O0
   if 64 - 64: iIii1I11I1II1 * Ii1I
   if 5 - 5: I11i . I11i / i1IIi - o0oOOo0O0Ooo % Oo0Ooo
def lisp_is_json_telemetry ( json_string ) :
 try :
  OooO0OO0Oooo = json . loads ( json_string )
  if ( type ( OooO0OO0Oooo ) != dict ) : return ( None )
 except :
  lprint ( "Could not decode telemetry json: {}" . format ( json_string ) )
  return ( None )
  if 85 - 85: OOooOOo
  if 32 - 32: iII111i
 if ( OooO0OO0Oooo . has_key ( "type" ) == False ) : return ( None )
 if ( OooO0OO0Oooo . has_key ( "sub-type" ) == False ) : return ( None )
 if ( OooO0OO0Oooo [ "type" ] != "telemetry" ) : return ( None )
 if ( OooO0OO0Oooo [ "sub-type" ] != "timestamps" ) : return ( None )
 return ( OooO0OO0Oooo )
 if 27 - 27: iIii1I11I1II1 - iII111i
 if 68 - 68: oO0o + OoooooooOO - i1IIi * OoOoOO00 % Oo0Ooo
 if 19 - 19: IiII * Oo0Ooo + I1IiiI * I1Ii111 % iIii1I11I1II1
 if 15 - 15: II111iiii % OoO0O00 % Oo0Ooo + I1Ii111
 if 54 - 54: I1Ii111 + OOooOOo
 if 6 - 6: Ii1I
 if 8 - 8: OoO0O00
 if 91 - 91: Ii1I
 if 12 - 12: OoooooooOO + i11iIiiIii
 if 63 - 63: OOooOOo . i11iIiiIii
 if 50 - 50: IiII % i11iIiiIii - iII111i . OoOoOO00 / Oo0Ooo
 if 30 - 30: Oo0Ooo . II111iiii + OoooooooOO % OoO0O00 * ooOoO0o * iIii1I11I1II1
def lisp_encode_telemetry ( json_string , ii = "?" , io = "?" , ei = "?" , eo = "?" ) :
 OooO0OO0Oooo = lisp_is_json_telemetry ( json_string )
 if ( OooO0OO0Oooo == None ) : return ( json_string )
 if 91 - 91: OoooooooOO
 if ( OooO0OO0Oooo [ "itr-in" ] == "?" ) : OooO0OO0Oooo [ "itr-in" ] = ii
 if ( OooO0OO0Oooo [ "itr-out" ] == "?" ) : OooO0OO0Oooo [ "itr-out" ] = io
 if ( OooO0OO0Oooo [ "etr-in" ] == "?" ) : OooO0OO0Oooo [ "etr-in" ] = ei
 if ( OooO0OO0Oooo [ "etr-out" ] == "?" ) : OooO0OO0Oooo [ "etr-out" ] = eo
 json_string = json . dumps ( OooO0OO0Oooo )
 return ( json_string )
 if 86 - 86: iII111i / OoooooooOO - I1ii11iIi11i
 if 63 - 63: ooOoO0o % Ii1I * I1IiiI
 if 48 - 48: iII111i - iII111i - o0oOOo0O0Ooo + ooOoO0o - o0oOOo0O0Ooo / Ii1I
 if 43 - 43: I1IiiI + Ii1I
 if 37 - 37: OoOoOO00 - OoooooooOO . ooOoO0o - IiII % iIii1I11I1II1 . iIii1I11I1II1
 if 64 - 64: OoOoOO00 + iII111i % I1Ii111 - OOooOOo + O0
 if 83 - 83: I1Ii111 + I1Ii111
 if 43 - 43: oO0o * i1IIi * Ii1I . iIii1I11I1II1 % o0oOOo0O0Ooo
 if 97 - 97: I1IiiI . i1IIi * OoOoOO00 / OOooOOo
 if 50 - 50: II111iiii . OoO0O00
 if 60 - 60: I11i . iIii1I11I1II1
 if 41 - 41: II111iiii / I1IiiI
def lisp_decode_telemetry ( json_string ) :
 OooO0OO0Oooo = lisp_is_json_telemetry ( json_string )
 if ( OooO0OO0Oooo == None ) : return ( { } )
 return ( OooO0OO0Oooo )
 if 2 - 2: IiII / OoOoOO00 + I11i
 if 3 - 3: OoooooooOO + Oo0Ooo + OOooOOo
 if 20 - 20: Ii1I - oO0o - OoO0O00 + I1ii11iIi11i % OoO0O00 . i1IIi
 if 2 - 2: ooOoO0o * IiII . Ii1I
 if 69 - 69: IiII % i1IIi
 if 17 - 17: o0oOOo0O0Ooo . OoO0O00 * ooOoO0o * II111iiii - OoooooooOO % iII111i
 if 47 - 47: I1IiiI * iIii1I11I1II1 - I11i - o0oOOo0O0Ooo
 if 47 - 47: IiII + OoO0O00 % ooOoO0o - iII111i - IiII - oO0o
 if 63 - 63: OoooooooOO / I1Ii111
def lisp_telemetry_configured ( ) :
 if ( lisp_json_list . has_key ( "telemetry" ) == False ) : return ( None )
 if 90 - 90: I1Ii111 . i11iIiiIii - iIii1I11I1II1 + I1Ii111
 II11iii = lisp_json_list [ "telemetry" ] . json_string
 if ( lisp_is_json_telemetry ( II11iii ) == None ) : return ( None )
 if 67 - 67: IiII - I1ii11iIi11i + ooOoO0o . iIii1I11I1II1 . IiII
 return ( II11iii )
 if 13 - 13: I1IiiI / i11iIiiIii % iIii1I11I1II1 - Oo0Ooo . i11iIiiIii + I1IiiI
 if 77 - 77: o0oOOo0O0Ooo / II111iiii + i11iIiiIii % Ii1I . iIii1I11I1II1
 if 66 - 66: iII111i / oO0o - OoO0O00 . Oo0Ooo
# dd678faae9ac167bc83abf78e5cb2f3f0688d3a3
