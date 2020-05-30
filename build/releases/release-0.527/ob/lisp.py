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
 oOoOOo0oo0 = commands . getoutput ( "sudo dmidecode -s bios-vendor" )
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
 def decode_lcaf ( self , packet , nonce , ms_json_encrypt ) :
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
     packet = self . decode_lcaf ( packet , nonce , ms_json_encrypt )
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
   self . json = lisp_json ( "" , packet [ 0 : iiiii1I ] , O0iI1Iii ,
 ms_json_encrypt )
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
   packet = iI1IiI1 . decode_lcaf ( OoO , oOOO0O000Oo , False )
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
   packet = Oo000O000 . decode_lcaf ( OoO , oOOO0O000Oo , False )
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
 def decode ( self , packet , nonce , ms_json_encrypt = False ) :
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
   packet = self . decode_lcaf ( packet , nonce , ms_json_encrypt )
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
   packet = self . decode ( packet , None , False )
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
if 94 - 94: ooOoO0o + OoO0O00 / ooOoO0o - ooOoO0o + Oo0Ooo + o0oOOo0O0Ooo
if 50 - 50: oO0o . Oo0Ooo
if 15 - 15: Ii1I
if 64 - 64: OoooooooOO
if 25 - 25: IiII
if 29 - 29: OoOoOO00 % ooOoO0o * OoooooooOO
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
  if 8 - 8: i11iIiiIii - I1Ii111 / IiII
  if 17 - 17: i11iIiiIii * OoO0O00 . o0oOOo0O0Ooo . OoooooooOO . OoOoOO00 - I1ii11iIi11i
 def print_info ( self ) :
  if ( self . info_reply ) :
   oOOoooOoO = "Info-Reply"
   I1IIiIIIii = ( ", ms-port: {}, etr-port: {}, global-rloc: {}, " + "ms-rloc: {}, private-rloc: {}, RTR-list: " ) . format ( self . ms_port , self . etr_port ,
   # I1IiiI * iIii1I11I1II1 . II111iiii % II111iiii - o0oOOo0O0Ooo
   # i1IIi % OoOoOO00 + I1IiiI
 red ( self . global_etr_rloc . print_address_no_iid ( ) , False ) ,
 red ( self . global_ms_rloc . print_address_no_iid ( ) , False ) ,
 red ( self . private_etr_rloc . print_address_no_iid ( ) , False ) )
   if ( len ( self . rtr_list ) == 0 ) : I1IIiIIIii += "empty, "
   for I11ii1I111Ii in self . rtr_list :
    I1IIiIIIii += red ( I11ii1I111Ii . print_address_no_iid ( ) , False ) + ", "
    if 58 - 58: O0
   I1IIiIIIii = I1IIiIIIii [ 0 : - 2 ]
  else :
   oOOoooOoO = "Info-Request"
   I1I1111I11I = "<none>" if self . hostname == None else self . hostname
   I1IIiIIIii = ", hostname: {}" . format ( blue ( I1I1111I11I , False ) )
   if 66 - 66: I11i * I1ii11iIi11i + II111iiii % ooOoO0o
  lprint ( "{} -> nonce: 0x{}{}" . format ( bold ( oOOoooOoO , False ) ,
 lisp_hex_string ( self . nonce ) , I1IIiIIIii ) )
  if 23 - 23: O0
  if 76 - 76: IiII . oO0o * I1Ii111 / I1IiiI
 def encode ( self ) :
  iII = ( LISP_NAT_INFO << 28 )
  if ( self . info_reply ) : iII |= ( 1 << 27 )
  if 9 - 9: oO0o . I1ii11iIi11i + I1IiiI . Oo0Ooo . i11iIiiIii
  if 75 - 75: I1Ii111 % II111iiii + OoOoOO00 % i11iIiiIii / iIii1I11I1II1
  if 81 - 81: II111iiii * I1Ii111 + OoooooooOO
  if 33 - 33: Ii1I - II111iiii + IiII / II111iiii * I1ii11iIi11i - I1Ii111
  if 53 - 53: I1Ii111
  if 25 - 25: i1IIi
  if 75 - 75: OoooooooOO / ooOoO0o - iII111i . OoooooooOO . OoOoOO00 % i1IIi
  IiiiIi1iiii11 = struct . pack ( "I" , socket . htonl ( iII ) )
  IiiiIi1iiii11 += struct . pack ( "Q" , self . nonce )
  IiiiIi1iiii11 += struct . pack ( "III" , 0 , 0 , 0 )
  if 7 - 7: OoOoOO00 . i1IIi * i11iIiiIii % i11iIiiIii
  if 54 - 54: OoO0O00 / I1IiiI . Oo0Ooo
  if 39 - 39: OoO0O00 . ooOoO0o
  if 41 - 41: Oo0Ooo * I1ii11iIi11i - II111iiii - II111iiii
  if ( self . info_reply == False ) :
   if ( self . hostname == None ) :
    IiiiIi1iiii11 += struct . pack ( "H" , 0 )
   else :
    IiiiIi1iiii11 += struct . pack ( "H" , socket . htons ( LISP_AFI_NAME ) )
    IiiiIi1iiii11 += self . hostname + "\0"
    if 7 - 7: oO0o
   return ( IiiiIi1iiii11 )
   if 41 - 41: ooOoO0o
   if 93 - 93: Ii1I + I1Ii111 + Ii1I
   if 23 - 23: I1IiiI - i1IIi / ooOoO0o
   if 4 - 4: IiII . I1ii11iIi11i + iII111i % ooOoO0o
   if 28 - 28: I1Ii111
  O0ooo0 = socket . htons ( LISP_AFI_LCAF )
  iI1IIiI111iII = LISP_LCAF_NAT_TYPE
  oOOO0O000Oo = socket . htons ( 16 )
  i1IIIiiIiII1I = socket . htons ( self . ms_port )
  oO000O000o0Oo = socket . htons ( self . etr_port )
  IiiiIi1iiii11 += struct . pack ( "HHBBHHHH" , O0ooo0 , 0 , iI1IIiI111iII , 0 , oOOO0O000Oo ,
 i1IIIiiIiII1I , oO000O000o0Oo , socket . htons ( self . global_etr_rloc . afi ) )
  IiiiIi1iiii11 += self . global_etr_rloc . pack_address ( )
  IiiiIi1iiii11 += struct . pack ( "HH" , 0 , socket . htons ( self . private_etr_rloc . afi ) )
  IiiiIi1iiii11 += self . private_etr_rloc . pack_address ( )
  if ( len ( self . rtr_list ) == 0 ) : IiiiIi1iiii11 += struct . pack ( "H" , 0 )
  if 63 - 63: Oo0Ooo / I11i . iII111i + ooOoO0o / I1ii11iIi11i / I1IiiI
  if 43 - 43: OoOoOO00 / I1Ii111 % I11i / I1IiiI - IiII - ooOoO0o
  if 25 - 25: OOooOOo * OoOoOO00 + I11i . ooOoO0o
  if 96 - 96: iIii1I11I1II1 / Ii1I
  for I11ii1I111Ii in self . rtr_list :
   IiiiIi1iiii11 += struct . pack ( "H" , socket . htons ( I11ii1I111Ii . afi ) )
   IiiiIi1iiii11 += I11ii1I111Ii . pack_address ( )
   if 92 - 92: OoO0O00 * I1ii11iIi11i + iIii1I11I1II1
  return ( IiiiIi1iiii11 )
  if 88 - 88: iIii1I11I1II1 + iIii1I11I1II1 * i11iIiiIii . I1ii11iIi11i % oO0o
  if 94 - 94: I1IiiI / I1ii11iIi11i / OOooOOo
 def decode ( self , packet ) :
  OoO = packet
  i1I1iii1I11II = "I"
  Iiiii = struct . calcsize ( i1I1iii1I11II )
  if ( len ( packet ) < Iiiii ) : return ( None )
  if 45 - 45: II111iiii
  iII = struct . unpack ( i1I1iii1I11II , packet [ : Iiiii ] )
  iII = iII [ 0 ]
  packet = packet [ Iiiii : : ]
  if 98 - 98: i11iIiiIii + I1ii11iIi11i * OOooOOo / OoOoOO00
  i1I1iii1I11II = "Q"
  Iiiii = struct . calcsize ( i1I1iii1I11II )
  if ( len ( packet ) < Iiiii ) : return ( None )
  if 84 - 84: o0oOOo0O0Ooo
  Iii11I = struct . unpack ( i1I1iii1I11II , packet [ : Iiiii ] )
  if 40 - 40: OoooooooOO - oO0o / O0 * I1Ii111 . O0 + i11iIiiIii
  iII = socket . ntohl ( iII )
  self . nonce = Iii11I [ 0 ]
  self . info_reply = iII & 0x08000000
  self . hostname = None
  packet = packet [ Iiiii : : ]
  if 9 - 9: OOooOOo % O0 % O0 / I1ii11iIi11i . II111iiii / II111iiii
  if 78 - 78: iIii1I11I1II1 - i1IIi . I11i . o0oOOo0O0Ooo
  if 66 - 66: OOooOOo * Oo0Ooo
  if 58 - 58: OOooOOo
  if 96 - 96: IiII % OoooooooOO + O0 * II111iiii / OOooOOo . I1Ii111
  i1I1iii1I11II = "HH"
  Iiiii = struct . calcsize ( i1I1iii1I11II )
  if ( len ( packet ) < Iiiii ) : return ( None )
  if 47 - 47: OoO0O00 - Oo0Ooo * OoO0O00 / oO0o
  if 13 - 13: ooOoO0o
  if 55 - 55: i1IIi . I11i . II111iiii + O0 + ooOoO0o - i1IIi
  if 3 - 3: iIii1I11I1II1 / oO0o
  if 61 - 61: I1Ii111 / O0 - iII111i
  I1I1I1 , II111iiI1Ii1 = struct . unpack ( i1I1iii1I11II , packet [ : Iiiii ] )
  if ( II111iiI1Ii1 != 0 ) : return ( None )
  if 44 - 44: i1IIi
  packet = packet [ Iiiii : : ]
  i1I1iii1I11II = "IBBH"
  Iiiii = struct . calcsize ( i1I1iii1I11II )
  if ( len ( packet ) < Iiiii ) : return ( None )
  if 23 - 23: I1ii11iIi11i . OoooooooOO / Ii1I + o0oOOo0O0Ooo
  oOoooOOO0o0 , i1o00Oo , OOoOOO , I1iiiI1i = struct . unpack ( i1I1iii1I11II ,
 packet [ : Iiiii ] )
  if 69 - 69: iII111i * I11i
  if ( I1iiiI1i != 0 ) : return ( None )
  packet = packet [ Iiiii : : ]
  if 43 - 43: o0oOOo0O0Ooo - IiII * Ii1I . i11iIiiIii / II111iiii
  if 61 - 61: OoOoOO00 / I1IiiI . I1ii11iIi11i % OOooOOo
  if 70 - 70: OOooOOo * OoOoOO00 / oO0o + Oo0Ooo / O0
  if 16 - 16: Oo0Ooo / OoooooooOO / IiII + Oo0Ooo * i11iIiiIii
  if ( self . info_reply == False ) :
   i1I1iii1I11II = "H"
   Iiiii = struct . calcsize ( i1I1iii1I11II )
   if ( len ( packet ) >= Iiiii ) :
    O0ooo0 = struct . unpack ( i1I1iii1I11II , packet [ : Iiiii ] ) [ 0 ]
    if ( socket . ntohs ( O0ooo0 ) == LISP_AFI_NAME ) :
     packet = packet [ Iiiii : : ]
     packet , self . hostname = lisp_decode_dist_name ( packet )
     if 15 - 15: o0oOOo0O0Ooo / i11iIiiIii
     if 63 - 63: I1ii11iIi11i - Ii1I + I11i
   return ( OoO )
   if 98 - 98: iII111i / IiII * I1IiiI / oO0o - iIii1I11I1II1
   if 72 - 72: O0 . OOooOOo
   if 99 - 99: i1IIi + iIii1I11I1II1 - ooOoO0o + OoO0O00 + Oo0Ooo . I1ii11iIi11i
   if 74 - 74: i1IIi
   if 80 - 80: ooOoO0o + I1Ii111 . I1ii11iIi11i % OoooooooOO
  i1I1iii1I11II = "HHBBHHH"
  Iiiii = struct . calcsize ( i1I1iii1I11II )
  if ( len ( packet ) < Iiiii ) : return ( None )
  if 26 - 26: OoOoOO00 . iII111i * iIii1I11I1II1 / IiII
  O0ooo0 , O0O , iI1IIiI111iII , i1o00Oo , oOOO0O000Oo , i1IIIiiIiII1I , oO000O000o0Oo = struct . unpack ( i1I1iii1I11II , packet [ : Iiiii ] )
  if 69 - 69: OoooooooOO / I11i + Ii1I * II111iiii
  if 35 - 35: i11iIiiIii + oO0o
  if ( socket . ntohs ( O0ooo0 ) != LISP_AFI_LCAF ) : return ( None )
  if 85 - 85: OoOoOO00 . O0 % OoooooooOO % oO0o
  self . ms_port = socket . ntohs ( i1IIIiiIiII1I )
  self . etr_port = socket . ntohs ( oO000O000o0Oo )
  packet = packet [ Iiiii : : ]
  if 43 - 43: I1IiiI - I11i . I1IiiI / i11iIiiIii % IiII * i11iIiiIii
  if 12 - 12: II111iiii - iIii1I11I1II1
  if 43 - 43: i11iIiiIii % OoO0O00
  if 100 - 100: i1IIi
  i1I1iii1I11II = "H"
  Iiiii = struct . calcsize ( i1I1iii1I11II )
  if ( len ( packet ) < Iiiii ) : return ( None )
  if 4 - 4: i11iIiiIii - OOooOOo * IiII % OoooooooOO - OoOoOO00
  if 81 - 81: Ii1I * ooOoO0o . oO0o . IiII
  if 71 - 71: IiII + OoO0O00
  if 39 - 39: I1IiiI % IiII / II111iiii / II111iiii
  O0ooo0 = struct . unpack ( i1I1iii1I11II , packet [ : Iiiii ] ) [ 0 ]
  packet = packet [ Iiiii : : ]
  if ( O0ooo0 != 0 ) :
   self . global_etr_rloc . afi = socket . ntohs ( O0ooo0 )
   packet = self . global_etr_rloc . unpack_address ( packet )
   if ( packet == None ) : return ( None )
   self . global_etr_rloc . mask_len = self . global_etr_rloc . host_mask_len ( )
   if 95 - 95: II111iiii + i11iIiiIii + o0oOOo0O0Ooo
   if 30 - 30: O0 - O0 % iIii1I11I1II1 + iII111i * OoooooooOO
   if 1 - 1: O0
   if 36 - 36: oO0o . iII111i
   if 62 - 62: I11i + iIii1I11I1II1 % I11i * OOooOOo + iIii1I11I1II1 % Ii1I
   if 56 - 56: o0oOOo0O0Ooo
  if ( len ( packet ) < Iiiii ) : return ( OoO )
  if 55 - 55: oO0o - I1Ii111 / ooOoO0o % I1IiiI * OoooooooOO * I1IiiI
  O0ooo0 = struct . unpack ( i1I1iii1I11II , packet [ : Iiiii ] ) [ 0 ]
  packet = packet [ Iiiii : : ]
  if ( O0ooo0 != 0 ) :
   self . global_ms_rloc . afi = socket . ntohs ( O0ooo0 )
   packet = self . global_ms_rloc . unpack_address ( packet )
   if ( packet == None ) : return ( OoO )
   self . global_ms_rloc . mask_len = self . global_ms_rloc . host_mask_len ( )
   if 88 - 88: Ii1I + O0
   if 92 - 92: I1IiiI % iII111i % I11i + OoooooooOO - i11iIiiIii
   if 9 - 9: i11iIiiIii - II111iiii / ooOoO0o
   if 81 - 81: i11iIiiIii % OoOoOO00 % OoO0O00 * Ii1I
   if 85 - 85: OoooooooOO * ooOoO0o
  if ( len ( packet ) < Iiiii ) : return ( OoO )
  if 23 - 23: OOooOOo / I11i / OoooooooOO - Ii1I / OoO0O00 - OoO0O00
  O0ooo0 = struct . unpack ( i1I1iii1I11II , packet [ : Iiiii ] ) [ 0 ]
  packet = packet [ Iiiii : : ]
  if ( O0ooo0 != 0 ) :
   self . private_etr_rloc . afi = socket . ntohs ( O0ooo0 )
   packet = self . private_etr_rloc . unpack_address ( packet )
   if ( packet == None ) : return ( OoO )
   self . private_etr_rloc . mask_len = self . private_etr_rloc . host_mask_len ( )
   if 60 - 60: OOooOOo . ooOoO0o % i1IIi % Ii1I % ooOoO0o + OoO0O00
   if 26 - 26: O0 % o0oOOo0O0Ooo + iII111i * I1ii11iIi11i * I1Ii111
   if 4 - 4: OOooOOo * OoooooooOO * i1IIi % I1ii11iIi11i % Oo0Ooo
   if 1 - 1: OoO0O00 / iIii1I11I1II1 % I1ii11iIi11i - o0oOOo0O0Ooo
   if 62 - 62: I1Ii111 % II111iiii
   if 91 - 91: I11i % Ii1I - IiII + iIii1I11I1II1 * iIii1I11I1II1
  while ( len ( packet ) >= Iiiii ) :
   O0ooo0 = struct . unpack ( i1I1iii1I11II , packet [ : Iiiii ] ) [ 0 ]
   packet = packet [ Iiiii : : ]
   if ( O0ooo0 == 0 ) : continue
   I11ii1I111Ii = lisp_address ( socket . ntohs ( O0ooo0 ) , "" , 0 , 0 )
   packet = I11ii1I111Ii . unpack_address ( packet )
   if ( packet == None ) : return ( OoO )
   I11ii1I111Ii . mask_len = I11ii1I111Ii . host_mask_len ( )
   self . rtr_list . append ( I11ii1I111Ii )
   if 91 - 91: i11iIiiIii + Ii1I
  return ( OoO )
  if 85 - 85: I11i % IiII
  if 68 - 68: Oo0Ooo . I1Ii111 - o0oOOo0O0Ooo * iIii1I11I1II1 - II111iiii % i1IIi
  if 58 - 58: I11i / i11iIiiIii * i11iIiiIii
class lisp_nat_info ( ) :
 def __init__ ( self , addr_str , hostname , port ) :
  self . address = addr_str
  self . hostname = hostname
  self . port = port
  self . uptime = lisp_get_timestamp ( )
  if 24 - 24: ooOoO0o - I1Ii111 * II111iiii - II111iiii
  if 47 - 47: IiII - iIii1I11I1II1 / OoOoOO00 * iII111i - iIii1I11I1II1 % oO0o
 def timed_out ( self ) :
  oO000o0Oo00 = time . time ( ) - self . uptime
  return ( oO000o0Oo00 >= ( LISP_INFO_INTERVAL * 2 ) )
  if 93 - 93: Ii1I / iII111i
  if 100 - 100: Oo0Ooo
  if 94 - 94: I1ii11iIi11i / i1IIi * I1IiiI - I11i - I1ii11iIi11i
class lisp_info_source ( ) :
 def __init__ ( self , hostname , addr_str , port ) :
  self . address = lisp_address ( LISP_AFI_IPV4 , addr_str , 32 , 0 )
  self . port = port
  self . uptime = lisp_get_timestamp ( )
  self . nonce = None
  self . hostname = hostname
  self . no_timeout = False
  if 6 - 6: I1ii11iIi11i % o0oOOo0O0Ooo + o0oOOo0O0Ooo / OOooOOo / I1IiiI
  if 67 - 67: OoOoOO00 . iII111i / OOooOOo * ooOoO0o + i1IIi
 def cache_address_for_info_source ( self ) :
  Oo000O000 = self . address . print_address_no_iid ( ) + self . hostname
  lisp_info_sources_by_address [ Oo000O000 ] = self
  if 100 - 100: OOooOOo . ooOoO0o + I1Ii111 . oO0o
  if 20 - 20: i11iIiiIii - i1IIi - iIii1I11I1II1 - OoooooooOO
 def cache_nonce_for_info_source ( self , nonce ) :
  self . nonce = nonce
  lisp_info_sources_by_nonce [ nonce ] = self
  if 72 - 72: I1Ii111 . OoO0O00
  if 59 - 59: I1IiiI * I11i % i1IIi
  if 77 - 77: OOooOOo * OoooooooOO + I1IiiI + I1IiiI % oO0o . OoooooooOO
  if 60 - 60: iIii1I11I1II1
  if 13 - 13: II111iiii + Ii1I
  if 33 - 33: i1IIi
  if 36 - 36: ooOoO0o % ooOoO0o . i11iIiiIii
  if 42 - 42: OoO0O00 . I1Ii111 / Ii1I
  if 57 - 57: iIii1I11I1II1 % I1ii11iIi11i . OOooOOo / oO0o . OoOoOO00
  if 74 - 74: I1IiiI * OoO0O00 + OoooooooOO * ooOoO0o . oO0o
  if 66 - 66: II111iiii + OOooOOo + i11iIiiIii / II111iiii
def lisp_concat_auth_data ( alg_id , auth1 , auth2 , auth3 , auth4 ) :
 if 37 - 37: I1IiiI + OoO0O00 . OoO0O00 % OoOoOO00 + o0oOOo0O0Ooo
 if ( lisp_is_x86 ( ) ) :
  if ( auth1 != "" ) : auth1 = byte_swap_64 ( auth1 )
  if ( auth2 != "" ) : auth2 = byte_swap_64 ( auth2 )
  if ( auth3 != "" ) :
   if ( alg_id == LISP_SHA_1_96_ALG_ID ) : auth3 = socket . ntohl ( auth3 )
   else : auth3 = byte_swap_64 ( auth3 )
   if 81 - 81: i1IIi % iIii1I11I1II1
  if ( auth4 != "" ) : auth4 = byte_swap_64 ( auth4 )
  if 41 - 41: oO0o - iII111i / o0oOOo0O0Ooo . iII111i % Oo0Ooo + OOooOOo
  if 82 - 82: ooOoO0o
 if ( alg_id == LISP_SHA_1_96_ALG_ID ) :
  auth1 = lisp_hex_string ( auth1 )
  auth1 = auth1 . zfill ( 16 )
  auth2 = lisp_hex_string ( auth2 )
  auth2 = auth2 . zfill ( 16 )
  auth3 = lisp_hex_string ( auth3 )
  auth3 = auth3 . zfill ( 8 )
  oooO = auth1 + auth2 + auth3
  if 89 - 89: OOooOOo / I1ii11iIi11i . I1IiiI + i11iIiiIii
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
  if 11 - 11: oO0o . i11iIiiIii * ooOoO0o % OoooooooOO % O0
 return ( oooO )
 if 59 - 59: i11iIiiIii / OoO0O00
 if 48 - 48: iIii1I11I1II1
 if 19 - 19: oO0o
 if 69 - 69: I1ii11iIi11i % iII111i - OoooooooOO % Ii1I * oO0o
 if 12 - 12: OoOoOO00 / I1Ii111 . O0 . IiII - OOooOOo - OoO0O00
 if 28 - 28: II111iiii . OoOoOO00 - o0oOOo0O0Ooo
 if 89 - 89: I1Ii111 * OoooooooOO . OOooOOo . I11i % i11iIiiIii
 if 8 - 8: I1ii11iIi11i + II111iiii . OoO0O00 + I1IiiI - II111iiii % OoO0O00
 if 85 - 85: i11iIiiIii % iII111i + II111iiii
 if 16 - 16: ooOoO0o * OoOoOO00 / OoOoOO00 + II111iiii
def lisp_open_listen_socket ( local_addr , port ) :
 if ( port . isdigit ( ) ) :
  if ( local_addr . find ( "." ) != - 1 ) :
   II11i = socket . socket ( socket . AF_INET , socket . SOCK_DGRAM )
   if 32 - 32: O0 % iIii1I11I1II1 + oO0o
  if ( local_addr . find ( ":" ) != - 1 ) :
   if ( lisp_is_raspbian ( ) ) : return ( None )
   II11i = socket . socket ( socket . AF_INET6 , socket . SOCK_DGRAM )
   if 51 - 51: o0oOOo0O0Ooo * o0oOOo0O0Ooo . Ii1I
  II11i . bind ( ( local_addr , int ( port ) ) )
 else :
  IiIIO0 = port
  if ( os . path . exists ( IiIIO0 ) ) :
   os . system ( "rm " + IiIIO0 )
   time . sleep ( 1 )
   if 14 - 14: OoO0O00 . I11i % II111iiii % i11iIiiIii + OoooooooOO
  II11i = socket . socket ( socket . AF_UNIX , socket . SOCK_DGRAM )
  II11i . bind ( IiIIO0 )
  if 50 - 50: i11iIiiIii * I11i + i11iIiiIii - i1IIi
 return ( II11i )
 if 69 - 69: I1IiiI + IiII + oO0o * I1ii11iIi11i . iIii1I11I1II1 / OoooooooOO
 if 77 - 77: Oo0Ooo - ooOoO0o
 if 68 - 68: Ii1I * O0
 if 61 - 61: II111iiii - OoO0O00 . iIii1I11I1II1 * o0oOOo0O0Ooo . OoO0O00 % IiII
 if 11 - 11: oO0o + I11i
 if 6 - 6: i1IIi . o0oOOo0O0Ooo + OoO0O00 + OOooOOo + oO0o
 if 30 - 30: O0
def lisp_open_send_socket ( internal_name , afi ) :
 if ( internal_name == "" ) :
  if ( afi == LISP_AFI_IPV4 ) :
   II11i = socket . socket ( socket . AF_INET , socket . SOCK_DGRAM )
   if 98 - 98: I1Ii111
  if ( afi == LISP_AFI_IPV6 ) :
   if ( lisp_is_raspbian ( ) ) : return ( None )
   II11i = socket . socket ( socket . AF_INET6 , socket . SOCK_DGRAM )
   if 58 - 58: OOooOOo
 else :
  if ( os . path . exists ( internal_name ) ) : os . system ( "rm " + internal_name )
  II11i = socket . socket ( socket . AF_UNIX , socket . SOCK_DGRAM )
  II11i . bind ( internal_name )
  if 6 - 6: I1ii11iIi11i
 return ( II11i )
 if 37 - 37: i11iIiiIii . II111iiii + OOooOOo + i1IIi * OOooOOo
 if 18 - 18: ooOoO0o
 if 18 - 18: I1Ii111 + OoOoOO00 % OOooOOo - IiII - i1IIi + I1ii11iIi11i
 if 33 - 33: I11i * Ii1I / Oo0Ooo + oO0o % OOooOOo % OoooooooOO
 if 29 - 29: Ii1I . II111iiii / I1Ii111
 if 79 - 79: IiII . OoOoOO00 / oO0o % OoO0O00 / Ii1I + I11i
 if 78 - 78: o0oOOo0O0Ooo + I1Ii111 % i11iIiiIii % I1IiiI - Ii1I
def lisp_close_socket ( sock , internal_name ) :
 sock . close ( )
 if ( os . path . exists ( internal_name ) ) : os . system ( "rm " + internal_name )
 return
 if 81 - 81: i11iIiiIii - II111iiii + I11i
 if 52 - 52: II111iiii
 if 62 - 62: iII111i / OoO0O00 + i11iIiiIii / Oo0Ooo
 if 26 - 26: I1ii11iIi11i - OoO0O00
 if 19 - 19: iIii1I11I1II1 / I1ii11iIi11i + O0
 if 12 - 12: I11i . OOooOOo + o0oOOo0O0Ooo . OoO0O00 + o0oOOo0O0Ooo
 if 56 - 56: i1IIi / i1IIi . OoO0O00 % i1IIi - OoOoOO00 % OOooOOo
 if 66 - 66: i11iIiiIii * IiII % IiII . I1IiiI / ooOoO0o
def lisp_is_running ( node ) :
 return ( True if ( os . path . exists ( node ) ) else False )
 if 50 - 50: IiII . iII111i / o0oOOo0O0Ooo % OoOoOO00 * IiII % I11i
 if 15 - 15: Ii1I
 if 29 - 29: I11i / I1IiiI / OoooooooOO . OoOoOO00 / I11i . I1Ii111
 if 69 - 69: O0 * OoOoOO00 + o0oOOo0O0Ooo + I1IiiI % iII111i . OoooooooOO
 if 45 - 45: I1Ii111 + oO0o - o0oOOo0O0Ooo - OoOoOO00 + I1IiiI / II111iiii
 if 46 - 46: II111iiii . iIii1I11I1II1
 if 62 - 62: I1ii11iIi11i % i1IIi % I1Ii111 * ooOoO0o % OOooOOo + I1IiiI
 if 100 - 100: II111iiii - o0oOOo0O0Ooo * OoooooooOO . ooOoO0o / II111iiii / oO0o
 if 43 - 43: iIii1I11I1II1 + ooOoO0o * iII111i + iIii1I11I1II1 . I1Ii111
def lisp_packet_ipc ( packet , source , sport ) :
 return ( ( "packet@" + str ( len ( packet ) ) + "@" + source + "@" + str ( sport ) + "@" + packet ) )
 if 87 - 87: I1Ii111
 if 47 - 47: II111iiii + I1IiiI . Oo0Ooo / iIii1I11I1II1
 if 14 - 14: i1IIi / OoO0O00 / iII111i % I1Ii111
 if 72 - 72: OoO0O00 . II111iiii - IiII + IiII + iIii1I11I1II1 % oO0o
 if 21 - 21: iII111i + OoOoOO00 - i11iIiiIii % O0 + OOooOOo
 if 30 - 30: o0oOOo0O0Ooo - Oo0Ooo + iII111i / O0
 if 94 - 94: IiII
 if 69 - 69: I1Ii111 . I1Ii111
 if 53 - 53: i11iIiiIii + iII111i * Oo0Ooo - I1Ii111
def lisp_control_packet_ipc ( packet , source , dest , dport ) :
 return ( "control-packet@" + dest + "@" + str ( dport ) + "@" + packet )
 if 61 - 61: o0oOOo0O0Ooo / OOooOOo . II111iiii - I1IiiI * i11iIiiIii
 if 8 - 8: iII111i % o0oOOo0O0Ooo
 if 87 - 87: Ii1I % I11i / I1Ii111
 if 21 - 21: OoO0O00 + Ii1I / I1Ii111
 if 75 - 75: I1Ii111 . Ii1I % iIii1I11I1II1 / OoOoOO00
 if 38 - 38: i1IIi
 if 1 - 1: I1ii11iIi11i + OoO0O00 % I11i . OOooOOo + i1IIi / oO0o
def lisp_data_packet_ipc ( packet , source ) :
 return ( "data-packet@" + str ( len ( packet ) ) + "@" + source + "@@" + packet )
 if 35 - 35: ooOoO0o % OoOoOO00 % OoO0O00 + OOooOOo / IiII * OoOoOO00
 if 65 - 65: I1IiiI . Oo0Ooo + i1IIi - Ii1I * i1IIi
 if 64 - 64: I1IiiI / OoO0O00 * I1IiiI * II111iiii . Ii1I
 if 98 - 98: I1Ii111 + o0oOOo0O0Ooo
 if 73 - 73: I1ii11iIi11i / I1Ii111 + i11iIiiIii + OoO0O00 . ooOoO0o
 if 54 - 54: I1ii11iIi11i + IiII - oO0o + Oo0Ooo / IiII % Oo0Ooo
 if 2 - 2: OOooOOo / I11i * I11i + I11i / O0 - OOooOOo
 if 29 - 29: OoOoOO00 + i11iIiiIii % OoO0O00 - OoooooooOO
 if 68 - 68: iII111i / OOooOOo
def lisp_command_ipc ( packet , source ) :
 return ( "command@" + str ( len ( packet ) ) + "@" + source + "@@" + packet )
 if 28 - 28: II111iiii
 if 49 - 49: I1ii11iIi11i
 if 33 - 33: iIii1I11I1II1
 if 72 - 72: I1ii11iIi11i * i11iIiiIii
 if 12 - 12: O0 - iIii1I11I1II1 % Oo0Ooo / O0 - IiII
 if 55 - 55: OOooOOo . Oo0Ooo * OoOoOO00 / OoooooooOO * i11iIiiIii + oO0o
 if 45 - 45: Ii1I
 if 8 - 8: oO0o + OOooOOo
 if 37 - 37: IiII - OoOoOO00 + oO0o - Oo0Ooo + IiII
def lisp_api_ipc ( source , data ) :
 return ( "api@" + str ( len ( data ) ) + "@" + source + "@@" + data )
 if 33 - 33: Oo0Ooo % oO0o - I1IiiI + Oo0Ooo
 if 90 - 90: I1ii11iIi11i * I1Ii111 - iIii1I11I1II1 % IiII * I1Ii111 . I1Ii111
 if 90 - 90: o0oOOo0O0Ooo - O0 % O0 - oO0o . OoooooooOO
 if 30 - 30: I11i + O0 / Ii1I / OoOoOO00 - oO0o + II111iiii
 if 21 - 21: iIii1I11I1II1 % OoooooooOO * OOooOOo % i1IIi
 if 73 - 73: OoooooooOO
 if 100 - 100: I11i / i1IIi / i1IIi % Ii1I - II111iiii . OoooooooOO
 if 72 - 72: Oo0Ooo * OoooooooOO % I1IiiI + I11i - II111iiii
 if 82 - 82: iIii1I11I1II1 / i1IIi * I1IiiI . i11iIiiIii
def lisp_ipc ( packet , send_socket , node ) :
 if 56 - 56: Ii1I * I1IiiI / ooOoO0o * II111iiii
 if 51 - 51: i1IIi . oO0o % OOooOOo
 if 90 - 90: OoooooooOO + iII111i / iIii1I11I1II1
 if 12 - 12: OoooooooOO
 if ( lisp_is_running ( node ) == False ) :
  lprint ( "Suppress sending IPC to {}" . format ( node ) )
  return
  if 9 - 9: O0 / O0 / I1IiiI - oO0o . ooOoO0o
  if 6 - 6: O0 - OoO0O00 + OoooooooOO % iIii1I11I1II1
 Ooo0oOO0oOo0 = 1500 if ( packet . find ( "control-packet" ) == - 1 ) else 9000
 if 89 - 89: ooOoO0o + I11i * O0 % OoOoOO00
 OoO00oo00 = 0
 IiiI1iii1iIiiI = len ( packet )
 I1iiI1ii1i = 0
 O0IIiIi = .001
 while ( IiiI1iii1iIiiI > 0 ) :
  O0OO0O = min ( IiiI1iii1iIiiI , Ooo0oOO0oOo0 )
  o00o = packet [ OoO00oo00 : O0OO0O + OoO00oo00 ]
  if 40 - 40: ooOoO0o - O0 - IiII - Ii1I % IiII / Ii1I
  try :
   send_socket . sendto ( o00o , node )
   lprint ( "Send IPC {}-out-of-{} byte to {} succeeded" . format ( len ( o00o ) , len ( packet ) , node ) )
   if 98 - 98: Ii1I * Oo0Ooo - O0 % OoOoOO00 + I1ii11iIi11i . II111iiii
   I1iiI1ii1i = 0
   O0IIiIi = .001
   if 92 - 92: Oo0Ooo * IiII - Ii1I . OoOoOO00 / iIii1I11I1II1 . OOooOOo
  except socket . error , oOo :
   if ( I1iiI1ii1i == 12 ) :
    lprint ( "Giving up on {}, consider it down" . format ( node ) )
    break
    if 53 - 53: i11iIiiIii
    if 50 - 50: i11iIiiIii / i1IIi + i1IIi / Ii1I . o0oOOo0O0Ooo + OoOoOO00
   lprint ( "Send IPC {}-out-of-{} byte to {} failed: {}" . format ( len ( o00o ) , len ( packet ) , node , oOo ) )
   if 29 - 29: I1ii11iIi11i % OOooOOo - I1IiiI / iII111i % OoOoOO00
   if 15 - 15: o0oOOo0O0Ooo / OOooOOo % I1IiiI - I1IiiI / i1IIi * Ii1I
   I1iiI1ii1i += 1
   time . sleep ( O0IIiIi )
   if 90 - 90: ooOoO0o % o0oOOo0O0Ooo * Ii1I . o0oOOo0O0Ooo + o0oOOo0O0Ooo * OoOoOO00
   lprint ( "Retrying after {} ms ..." . format ( O0IIiIi * 1000 ) )
   O0IIiIi *= 2
   continue
   if 40 - 40: iIii1I11I1II1 - i11iIiiIii / i1IIi / II111iiii
   if 37 - 37: Ii1I + o0oOOo0O0Ooo
  OoO00oo00 += O0OO0O
  IiiI1iii1iIiiI -= O0OO0O
  if 74 - 74: Oo0Ooo / O0 + i1IIi . I1IiiI + OoO0O00 / Oo0Ooo
 return
 if 13 - 13: o0oOOo0O0Ooo / Ii1I . II111iiii
 if 8 - 8: I11i - I11i % IiII
 if 8 - 8: I1IiiI . IiII * O0 * o0oOOo0O0Ooo
 if 17 - 17: I1IiiI . oO0o + Oo0Ooo + I11i / o0oOOo0O0Ooo
 if 25 - 25: iII111i / iII111i % OoOoOO00 / ooOoO0o
 if 81 - 81: OOooOOo * oO0o
 if 32 - 32: Oo0Ooo * OoO0O00 + ooOoO0o . O0 * oO0o * iIii1I11I1II1
def lisp_format_packet ( packet ) :
 packet = binascii . hexlify ( packet )
 OoO00oo00 = 0
 O0OOOo000 = ""
 IiiI1iii1iIiiI = len ( packet ) * 2
 while ( OoO00oo00 < IiiI1iii1iIiiI ) :
  O0OOOo000 += packet [ OoO00oo00 : OoO00oo00 + 8 ] + " "
  OoO00oo00 += 8
  IiiI1iii1iIiiI -= 4
  if 50 - 50: i1IIi
 return ( O0OOOo000 )
 if 53 - 53: II111iiii + O0 . ooOoO0o * IiII + i1IIi
 if 80 - 80: Ii1I + O0
 if 59 - 59: i11iIiiIii - OoooooooOO % I11i . OoO0O00 - Oo0Ooo * o0oOOo0O0Ooo
 if 7 - 7: II111iiii % Ii1I * i11iIiiIii
 if 28 - 28: II111iiii / ooOoO0o * i11iIiiIii % OOooOOo
 if 18 - 18: I11i - IiII - iIii1I11I1II1
 if 82 - 82: II111iiii + OoO0O00 % iIii1I11I1II1 / O0
def lisp_send ( lisp_sockets , dest , port , packet ) :
 O0OOOoooO000 = lisp_sockets [ 0 ] if dest . is_ipv4 ( ) else lisp_sockets [ 1 ]
 if 72 - 72: ooOoO0o
 if 21 - 21: Ii1I - OOooOOo
 if 32 - 32: iIii1I11I1II1 / OoO0O00
 if 22 - 22: II111iiii . I11i
 if 61 - 61: OOooOOo % O0 . I1ii11iIi11i . iIii1I11I1II1 * I11i
 if 29 - 29: ooOoO0o + i1IIi % IiII * Ii1I
 if 94 - 94: OOooOOo / IiII
 if 18 - 18: IiII - I11i / Ii1I % IiII * i1IIi
 if 22 - 22: OoOoOO00 - Oo0Ooo
 if 41 - 41: iIii1I11I1II1 * I1Ii111 / OoO0O00
 if 33 - 33: I11i + O0
 if 9 - 9: I11i . iII111i * ooOoO0o * ooOoO0o
 ii1i1II11II1i = dest . print_address_no_iid ( )
 if ( ii1i1II11II1i . find ( "::ffff:" ) != - 1 and ii1i1II11II1i . count ( "." ) == 3 ) :
  if ( lisp_i_am_rtr ) : O0OOOoooO000 = lisp_sockets [ 0 ]
  if ( O0OOOoooO000 == None ) :
   O0OOOoooO000 = lisp_sockets [ 0 ]
   ii1i1II11II1i = ii1i1II11II1i . split ( "::ffff:" ) [ - 1 ]
   if 68 - 68: O0 - i11iIiiIii % iIii1I11I1II1 % ooOoO0o
   if 12 - 12: II111iiii + I11i
   if 9 - 9: I1ii11iIi11i
 lprint ( "{} {} bytes {} {}, packet: {}" . format ( bold ( "Send" , False ) ,
 len ( packet ) , bold ( "to " + ii1i1II11II1i , False ) , port ,
 lisp_format_packet ( packet ) ) )
 if 51 - 51: I1ii11iIi11i
 if 37 - 37: I1IiiI % I1Ii111
 if 22 - 22: o0oOOo0O0Ooo % OOooOOo - I11i + ooOoO0o / OOooOOo
 if 98 - 98: I11i * O0 + IiII - oO0o
 ii11Ii11IIIII = ( LISP_RLOC_PROBE_TTL == 128 )
 if ( ii11Ii11IIIII ) :
  iI1i11II = struct . unpack ( "B" , packet [ 0 ] ) [ 0 ]
  ii11Ii11IIIII = ( iI1i11II in [ 0x12 , 0x28 ] )
  if ( ii11Ii11IIIII ) : lisp_set_ttl ( O0OOOoooO000 , LISP_RLOC_PROBE_TTL )
  if 7 - 7: OOooOOo % iIii1I11I1II1
  if 11 - 11: OoooooooOO % OoOoOO00 * I11i % i11iIiiIii * i11iIiiIii
 try : O0OOOoooO000 . sendto ( packet , ( ii1i1II11II1i , port ) )
 except socket . error , oOo :
  lprint ( "socket.sendto() failed: {}" . format ( oOo ) )
  if 25 - 25: oO0o . OoO0O00 % Ii1I % Ii1I
  if 94 - 94: iII111i . Ii1I
  if 71 - 71: o0oOOo0O0Ooo * II111iiii / OOooOOo . OoO0O00
  if 73 - 73: I1Ii111 * OoO0O00 / OoOoOO00 . II111iiii
  if 87 - 87: OoO0O00 + Oo0Ooo + O0 % OoooooooOO - iIii1I11I1II1
 if ( ii11Ii11IIIII ) : lisp_set_ttl ( O0OOOoooO000 , 64 )
 return
 if 100 - 100: Oo0Ooo + IiII
 if 81 - 81: iIii1I11I1II1 + iIii1I11I1II1
 if 19 - 19: ooOoO0o + i1IIi / Oo0Ooo * II111iiii * I1Ii111 / ooOoO0o
 if 23 - 23: I1Ii111
 if 76 - 76: Ii1I + Ii1I / i1IIi % o0oOOo0O0Ooo . iIii1I11I1II1 . OoOoOO00
 if 75 - 75: I11i . Ii1I / I1ii11iIi11i
 if 99 - 99: Ii1I
 if 85 - 85: I1Ii111 + I1Ii111 + OoOoOO00 / ooOoO0o / o0oOOo0O0Ooo . Oo0Ooo
def lisp_receive_segments ( lisp_socket , packet , source , total_length ) :
 if 41 - 41: i1IIi % Ii1I . i1IIi * OoooooooOO % Ii1I
 if 21 - 21: iII111i
 if 72 - 72: I11i % o0oOOo0O0Ooo . iIii1I11I1II1 - I1Ii111 / i11iIiiIii
 if 75 - 75: OoooooooOO
 if 24 - 24: oO0o % iII111i - II111iiii / Ii1I + O0
 O0OO0O = total_length - len ( packet )
 if ( O0OO0O == 0 ) : return ( [ True , packet ] )
 if 37 - 37: I1Ii111 - i1IIi / iIii1I11I1II1
 lprint ( "Received {}-out-of-{} byte segment from {}" . format ( len ( packet ) ,
 total_length , source ) )
 if 53 - 53: Ii1I - iIii1I11I1II1 % I1ii11iIi11i * i11iIiiIii + ooOoO0o
 if 63 - 63: Oo0Ooo * I1IiiI
 if 84 - 84: Oo0Ooo
 if 67 - 67: oO0o / II111iiii . I11i / oO0o
 if 46 - 46: oO0o * Oo0Ooo - I11i / iIii1I11I1II1
 IiiI1iii1iIiiI = O0OO0O
 while ( IiiI1iii1iIiiI > 0 ) :
  try : o00o = lisp_socket . recvfrom ( 9000 )
  except : return ( [ False , None ] )
  if 100 - 100: i11iIiiIii % oO0o
  o00o = o00o [ 0 ]
  if 62 - 62: OOooOOo * i1IIi - OOooOOo / i11iIiiIii
  if 17 - 17: I1ii11iIi11i + ooOoO0o % Ii1I % OOooOOo
  if 73 - 73: i11iIiiIii
  if 44 - 44: o0oOOo0O0Ooo % Ii1I - OoOoOO00 + OoOoOO00 * IiII + iII111i
  if 58 - 58: I1ii11iIi11i / oO0o + i11iIiiIii * o0oOOo0O0Ooo
  if ( o00o . find ( "packet@" ) == 0 ) :
   iiiI1i1 = o00o . split ( "@" )
   lprint ( "Received new message ({}-out-of-{}) while receiving " + "fragments, old message discarded" , len ( o00o ) ,
   # ooOoO0o - i1IIi
 iiiI1i1 [ 1 ] if len ( iiiI1i1 ) > 2 else "?" )
   return ( [ False , o00o ] )
   if 61 - 61: II111iiii * I1ii11iIi11i / I11i / OoO0O00
   if 44 - 44: O0 + OoOoOO00 . iIii1I11I1II1 . IiII
  IiiI1iii1iIiiI -= len ( o00o )
  packet += o00o
  if 2 - 2: iII111i
  lprint ( "Received {}-out-of-{} byte segment from {}" . format ( len ( o00o ) , total_length , source ) )
  if 47 - 47: i1IIi % I11i
  if 17 - 17: OoOoOO00 - iII111i % I11i / o0oOOo0O0Ooo / II111iiii
 return ( [ True , packet ] )
 if 22 - 22: Oo0Ooo + I1ii11iIi11i % i11iIiiIii . OoO0O00 - I11i % I11i
 if 21 - 21: I1IiiI . OoO0O00 * IiII % OoooooooOO - Oo0Ooo + Oo0Ooo
 if 94 - 94: ooOoO0o
 if 80 - 80: i11iIiiIii - O0 / I1Ii111 + OOooOOo % Oo0Ooo
 if 95 - 95: II111iiii
 if 76 - 76: OoO0O00 % iII111i * OoOoOO00 / ooOoO0o / i1IIi
 if 45 - 45: Ii1I . I11i * I1Ii111 . i11iIiiIii
 if 34 - 34: O0 * o0oOOo0O0Ooo / IiII
def lisp_bit_stuff ( payload ) :
 lprint ( "Bit-stuffing, found {} segments" . format ( len ( payload ) ) )
 IiiiIi1iiii11 = ""
 for o00o in payload : IiiiIi1iiii11 += o00o + "\x40"
 return ( IiiiIi1iiii11 [ : - 1 ] )
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
 if 52 - 52: IiII . OoooooooOO
 if 34 - 34: o0oOOo0O0Ooo / IiII . OoooooooOO . Oo0Ooo / ooOoO0o + O0
 if 38 - 38: I11i
 if 66 - 66: II111iiii
 if 57 - 57: OoO0O00 / Oo0Ooo % I1IiiI * I1ii11iIi11i
 if 68 - 68: iII111i - o0oOOo0O0Ooo - OoO0O00 . O0 - i11iIiiIii
def lisp_receive ( lisp_socket , internal ) :
 while ( True ) :
  if 2 - 2: I1ii11iIi11i * i1IIi
  if 17 - 17: I1ii11iIi11i * Ii1I % Oo0Ooo * I1Ii111 + OoO0O00 . OoooooooOO
  if 60 - 60: Ii1I . II111iiii
  if 36 - 36: IiII . iII111i * O0 . i1IIi * O0 * I1Ii111
  try : IiIIIi = lisp_socket . recvfrom ( 9000 )
  except : return ( [ "" , "" , "" , "" ] )
  if 70 - 70: I1Ii111 * I11i % oO0o % ooOoO0o * iII111i - I1Ii111
  if 43 - 43: iIii1I11I1II1 . i11iIiiIii - oO0o
  if 55 - 55: iIii1I11I1II1 % oO0o % OOooOOo / I1Ii111 * OoooooooOO / Oo0Ooo
  if 88 - 88: I11i + OoO0O00 . iIii1I11I1II1 . II111iiii
  if 67 - 67: OOooOOo - ooOoO0o % iII111i % IiII
  if 71 - 71: OoO0O00 - ooOoO0o - I1IiiI + O0
  if ( internal == False ) :
   IiiiIi1iiii11 = IiIIIi [ 0 ]
   i1IIi1ii1i1ii = lisp_convert_6to4 ( IiIIIi [ 1 ] [ 0 ] )
   Oo0O00O = IiIIIi [ 1 ] [ 1 ]
   if 15 - 15: i1IIi
   if ( Oo0O00O == LISP_DATA_PORT ) :
    Iii1Ii = lisp_data_plane_logging
    IiIiI1 = lisp_format_packet ( IiiiIi1iiii11 [ 0 : 60 ] ) + " ..."
   else :
    Iii1Ii = True
    IiIiI1 = lisp_format_packet ( IiiiIi1iiii11 )
    if 26 - 26: i1IIi - I1IiiI + IiII / OoO0O00 . I1ii11iIi11i
    if 82 - 82: I1Ii111 % iII111i . OoOoOO00 % OoO0O00 + I1ii11iIi11i
   if ( Iii1Ii ) :
    lprint ( "{} {} bytes {} {}, packet: {}" . format ( bold ( "Receive" ,
 False ) , len ( IiiiIi1iiii11 ) , bold ( "from " + i1IIi1ii1i1ii , False ) , Oo0O00O ,
 IiIiI1 ) )
    if 69 - 69: I1IiiI * OoOoOO00 - ooOoO0o . O0
   return ( [ "packet" , i1IIi1ii1i1ii , Oo0O00O , IiiiIi1iiii11 ] )
   if 15 - 15: oO0o . IiII + I1Ii111 - OoooooooOO
   if 85 - 85: II111iiii - Oo0Ooo + oO0o . i11iIiiIii + Oo0Ooo
   if 86 - 86: ooOoO0o . OoO0O00
   if 47 - 47: IiII % I1IiiI
   if 91 - 91: Ii1I
   if 69 - 69: iII111i
  oO0OO0oOo00 = False
  i1I = IiIIIi [ 0 ]
  OOOoOoOO0oo = False
  if 37 - 37: i1IIi * iIii1I11I1II1 % OoooooooOO . OoooooooOO / Oo0Ooo % i11iIiiIii
  while ( oO0OO0oOo00 == False ) :
   i1I = i1I . split ( "@" )
   if 53 - 53: oO0o - IiII - iIii1I11I1II1 + O0 * Ii1I
   if ( len ( i1I ) < 4 ) :
    lprint ( "Possible fragment (length {}), from old message, " + "discarding" , len ( i1I [ 0 ] ) )
    if 1 - 1: i1IIi % O0 / I11i
    OOOoOoOO0oo = True
    break
    if 52 - 52: I1IiiI + oO0o * II111iiii
    if 15 - 15: I11i
   oo0i11i11ii11 = i1I [ 0 ]
   try :
    i1i1I1II1i = int ( i1I [ 1 ] )
   except :
    o0o = bold ( "Internal packet reassembly error" , False )
    lprint ( "{}: {}" . format ( o0o , IiIIIi ) )
    OOOoOoOO0oo = True
    break
    if 10 - 10: IiII * o0oOOo0O0Ooo * o0oOOo0O0Ooo
   i1IIi1ii1i1ii = i1I [ 2 ]
   Oo0O00O = i1I [ 3 ]
   if 66 - 66: I1ii11iIi11i % I1IiiI . I1IiiI * Ii1I + OoO0O00 % i1IIi
   if 34 - 34: II111iiii + I1IiiI * i1IIi . I11i
   if 51 - 51: I11i . iII111i * I1IiiI . iIii1I11I1II1 % I1IiiI / O0
   if 47 - 47: OoooooooOO - i11iIiiIii . I1IiiI / i1IIi
   if 74 - 74: OoooooooOO * ooOoO0o
   if 45 - 45: Oo0Ooo + iIii1I11I1II1 . o0oOOo0O0Ooo
   if 50 - 50: o0oOOo0O0Ooo % O0
   if 67 - 67: OoOoOO00
   if ( len ( i1I ) > 5 ) :
    IiiiIi1iiii11 = lisp_bit_stuff ( i1I [ 4 : : ] )
   else :
    IiiiIi1iiii11 = i1I [ 4 ]
    if 21 - 21: I11i % Oo0Ooo + Oo0Ooo / iIii1I11I1II1 % iIii1I11I1II1
    if 66 - 66: iII111i
    if 72 - 72: ooOoO0o / oO0o / iII111i . I1Ii111 . I1ii11iIi11i + IiII
    if 39 - 39: I1IiiI % I1Ii111
    if 22 - 22: OoOoOO00 - OOooOOo % i1IIi + i1IIi
    if 28 - 28: oO0o + OoOoOO00 * Ii1I . I11i
   oO0OO0oOo00 , IiiiIi1iiii11 = lisp_receive_segments ( lisp_socket , IiiiIi1iiii11 ,
 i1IIi1ii1i1ii , i1i1I1II1i )
   if ( IiiiIi1iiii11 == None ) : return ( [ "" , "" , "" , "" ] )
   if 80 - 80: I1ii11iIi11i / OoOoOO00
   if 74 - 74: I1ii11iIi11i + O0 + o0oOOo0O0Ooo - iII111i
   if 48 - 48: ooOoO0o * iIii1I11I1II1 % Oo0Ooo
   if 60 - 60: OoOoOO00 / i1IIi * iIii1I11I1II1
   if 91 - 91: I1Ii111 . OoooooooOO / IiII / I1IiiI
   if ( oO0OO0oOo00 == False ) :
    i1I = IiiiIi1iiii11
    continue
    if 56 - 56: II111iiii + iIii1I11I1II1 / I1Ii111 / I1Ii111 % Oo0Ooo / OoOoOO00
    if 46 - 46: i11iIiiIii + OoO0O00 . ooOoO0o + OoO0O00 % i11iIiiIii
   if ( Oo0O00O == "" ) : Oo0O00O = "no-port"
   if ( oo0i11i11ii11 == "command" and lisp_i_am_core == False ) :
    ooo = IiiiIi1iiii11 . find ( " {" )
    oo00o00OoO = IiiiIi1iiii11 if ooo == - 1 else IiiiIi1iiii11 [ : ooo ]
    oo00o00OoO = ": '" + oo00o00OoO + "'"
   else :
    oo00o00OoO = ""
    if 93 - 93: IiII - OoOoOO00 - Ii1I % II111iiii . I1ii11iIi11i % OoooooooOO
    if 2 - 2: oO0o % ooOoO0o
   lprint ( "{} {} bytes {} {}, {}{}" . format ( bold ( "Receive" , False ) ,
 len ( IiiiIi1iiii11 ) , bold ( "from " + i1IIi1ii1i1ii , False ) , Oo0O00O , oo0i11i11ii11 ,
 oo00o00OoO if ( oo0i11i11ii11 in [ "command" , "api" ] ) else ": ... " if ( oo0i11i11ii11 == "data-packet" ) else ": " + lisp_format_packet ( IiiiIi1iiii11 ) ) )
   if 44 - 44: Ii1I
   if 91 - 91: i11iIiiIii * Oo0Ooo / i1IIi
   if 19 - 19: i1IIi * I1IiiI
   if 82 - 82: I1ii11iIi11i * iIii1I11I1II1
   if 53 - 53: OoO0O00 * O0
  if ( OOOoOoOO0oo ) : continue
  return ( [ oo0i11i11ii11 , i1IIi1ii1i1ii , Oo0O00O , IiiiIi1iiii11 ] )
  if 97 - 97: Oo0Ooo . i1IIi
  if 56 - 56: Ii1I
  if 2 - 2: i1IIi % oO0o + O0 - OoO0O00
  if 34 - 34: ooOoO0o + oO0o - Oo0Ooo
  if 94 - 94: OoOoOO00 - Ii1I
  if 93 - 93: OoooooooOO * OOooOOo
  if 34 - 34: OoOoOO00 + OoOoOO00 - Oo0Ooo
  if 21 - 21: i1IIi + O0 % I1ii11iIi11i / i1IIi - iII111i
def lisp_parse_packet ( lisp_sockets , packet , source , udp_sport , ttl = - 1 ) :
 O0o00oOo0 = False
 oooooo0ooo0O = time . time ( )
 if 16 - 16: ooOoO0o
 O0ooOoO0 = lisp_control_header ( )
 if ( O0ooOoO0 . decode ( packet ) == None ) :
  lprint ( "Could not decode control header" )
  return ( O0o00oOo0 )
  if 61 - 61: IiII
  if 53 - 53: Oo0Ooo % iII111i % iII111i
  if 71 - 71: iII111i
  if 99 - 99: O0 - OoOoOO00 * I1Ii111 - Oo0Ooo
  if 62 - 62: i1IIi + ooOoO0o + Oo0Ooo - i11iIiiIii
 ii1i = source
 if ( source . find ( "lisp" ) == - 1 ) :
  IiII1iiI = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  IiII1iiI . string_to_afi ( source )
  IiII1iiI . store_address ( source )
  source = IiII1iiI
  if 51 - 51: ooOoO0o - I1Ii111 * oO0o
  if 47 - 47: Oo0Ooo % OoO0O00 * Ii1I / OoOoOO00
 if ( O0ooOoO0 . type == LISP_MAP_REQUEST ) :
  lisp_process_map_request ( lisp_sockets , packet , None , 0 , source ,
 udp_sport , False , ttl , oooooo0ooo0O )
  if 1 - 1: I1IiiI
 elif ( O0ooOoO0 . type == LISP_MAP_REPLY ) :
  lisp_process_map_reply ( lisp_sockets , packet , source , ttl , oooooo0ooo0O )
  if 68 - 68: ooOoO0o
 elif ( O0ooOoO0 . type == LISP_MAP_REGISTER ) :
  lisp_process_map_register ( lisp_sockets , packet , source , udp_sport )
  if 68 - 68: I11i % IiII
 elif ( O0ooOoO0 . type == LISP_MAP_NOTIFY ) :
  if ( ii1i == "lisp-etr" ) :
   lisp_process_multicast_map_notify ( packet , source )
  else :
   if ( lisp_is_running ( "lisp-rtr" ) ) :
    lisp_process_multicast_map_notify ( packet , source )
    if 1 - 1: I1IiiI + OOooOOo - OOooOOo * O0 + o0oOOo0O0Ooo * OOooOOo
   lisp_process_map_notify ( lisp_sockets , packet , source )
   if 48 - 48: ooOoO0o - iII111i + I1ii11iIi11i * I1Ii111 % ooOoO0o * OoO0O00
   if 28 - 28: i1IIi / iII111i + OOooOOo
 elif ( O0ooOoO0 . type == LISP_MAP_NOTIFY_ACK ) :
  lisp_process_map_notify_ack ( packet , source )
  if 89 - 89: Oo0Ooo + II111iiii * OoO0O00 + Oo0Ooo % II111iiii
 elif ( O0ooOoO0 . type == LISP_MAP_REFERRAL ) :
  lisp_process_map_referral ( lisp_sockets , packet , source )
  if 59 - 59: O0 + Oo0Ooo
 elif ( O0ooOoO0 . type == LISP_NAT_INFO and O0ooOoO0 . is_info_reply ( ) ) :
  O0O , IIIi1i1iIIIi , O0o00oOo0 = lisp_process_info_reply ( source , packet , True )
  if 63 - 63: OoO0O00 / I1IiiI / oO0o . Ii1I / i1IIi
 elif ( O0ooOoO0 . type == LISP_NAT_INFO and O0ooOoO0 . is_info_reply ( ) == False ) :
  oo0o00OO = source . print_address_no_iid ( )
  lisp_process_info_request ( lisp_sockets , packet , oo0o00OO , udp_sport ,
 None )
  if 50 - 50: I11i . I11i % I1IiiI - i1IIi
 elif ( O0ooOoO0 . type == LISP_ECM ) :
  lisp_process_ecm ( lisp_sockets , packet , source , udp_sport )
  if 63 - 63: OoO0O00 . iII111i
 else :
  lprint ( "Invalid LISP control packet type {}" . format ( O0ooOoO0 . type ) )
  if 28 - 28: ooOoO0o . Oo0Ooo - OoooooooOO - I1Ii111 - OoooooooOO - oO0o
 return ( O0o00oOo0 )
 if 25 - 25: I11i / I1Ii111 . i11iIiiIii % i1IIi
 if 21 - 21: O0 * IiII . iII111i / iII111i % i11iIiiIii / I11i
 if 15 - 15: o0oOOo0O0Ooo / OoO0O00 - i1IIi
 if 30 - 30: OoO0O00 / ooOoO0o % ooOoO0o
 if 40 - 40: i1IIi . iIii1I11I1II1 * OoOoOO00
 if 83 - 83: iIii1I11I1II1 + Ii1I - Ii1I % II111iiii
 if 82 - 82: O0
def lisp_process_rloc_probe_request ( lisp_sockets , map_request , source , port ,
 ttl , timestamp ) :
 if 18 - 18: iII111i . IiII . I1IiiI
 oo00ooOOOo0O = bold ( "RLOC-probe" , False )
 if 40 - 40: IiII / oO0o + OoooooooOO / iII111i / II111iiii + i1IIi
 if ( lisp_i_am_etr ) :
  lprint ( "Received {} Map-Request, send RLOC-probe Map-Reply" . format ( oo00ooOOOo0O ) )
  lisp_etr_process_map_request ( lisp_sockets , map_request , source , port ,
 ttl , timestamp )
  return
  if 33 - 33: I11i + I1ii11iIi11i + i11iIiiIii * I1IiiI % oO0o % OoooooooOO
  if 4 - 4: OoO0O00 . I1IiiI - O0 % iII111i . OOooOOo
 if ( lisp_i_am_rtr ) :
  lprint ( "Received {} Map-Request, send RLOC-probe Map-Reply" . format ( oo00ooOOOo0O ) )
  lisp_rtr_process_map_request ( lisp_sockets , map_request , source , port ,
 ttl , timestamp )
  return
  if 69 - 69: OoooooooOO
  if 19 - 19: O0 + iIii1I11I1II1 / OoOoOO00 / oO0o + II111iiii - OOooOOo
 lprint ( "Ignoring received {} Map-Request, not an ETR or RTR" . format ( oo00ooOOOo0O ) )
 return
 if 70 - 70: i1IIi * o0oOOo0O0Ooo + I1Ii111 . ooOoO0o - O0 + i11iIiiIii
 if 81 - 81: iIii1I11I1II1 - OoO0O00 . i11iIiiIii
 if 4 - 4: o0oOOo0O0Ooo / OoO0O00 - I11i
 if 52 - 52: II111iiii . iII111i
 if 36 - 36: I1IiiI * II111iiii
def lisp_process_smr ( map_request ) :
 lprint ( "Received SMR-based Map-Request" )
 return
 if 68 - 68: oO0o * o0oOOo0O0Ooo + OoooooooOO - I1ii11iIi11i * i1IIi % OOooOOo
 if 39 - 39: I1Ii111 / I11i + oO0o / I1Ii111 % IiII * I1ii11iIi11i
 if 66 - 66: I1ii11iIi11i * ooOoO0o . i11iIiiIii * Oo0Ooo - I11i . I1IiiI
 if 43 - 43: I11i . iII111i . IiII - oO0o
 if 60 - 60: i1IIi + iII111i * i1IIi . iII111i
def lisp_process_smr_invoked_request ( map_request ) :
 lprint ( "Received SMR-invoked Map-Request" )
 return
 if 40 - 40: i1IIi . OoO0O00
 if 65 - 65: Oo0Ooo
 if 81 - 81: OOooOOo % OoooooooOO / IiII . Oo0Ooo - ooOoO0o . I1IiiI
 if 3 - 3: O0
 if 95 - 95: i11iIiiIii
 if 100 - 100: iIii1I11I1II1 * I1IiiI * Ii1I * i1IIi . I1Ii111 * I1IiiI
 if 54 - 54: o0oOOo0O0Ooo / iII111i + IiII - o0oOOo0O0Ooo - I11i
def lisp_build_map_reply ( eid , group , rloc_set , nonce , action , ttl , map_request ,
 keys , enc , auth , mr_ttl = - 1 ) :
 if 28 - 28: I1IiiI - iIii1I11I1II1 - o0oOOo0O0Ooo * IiII + OoooooooOO
 o0O0oO0OOOOO0 = map_request . rloc_probe if ( map_request != None ) else False
 iiO0O0oOO0O0 = map_request . json_telemetry if ( map_request != None ) else None
 if 77 - 77: I11i / iII111i * o0oOOo0O0Ooo % iIii1I11I1II1
 if 26 - 26: i1IIi / OoO0O00 / IiII
 oO00OoO0O0O = lisp_map_reply ( )
 oO00OoO0O0O . rloc_probe = o0O0oO0OOOOO0
 oO00OoO0O0O . echo_nonce_capable = enc
 oO00OoO0O0O . hop_count = 0 if ( mr_ttl == - 1 ) else mr_ttl
 oO00OoO0O0O . record_count = 1
 oO00OoO0O0O . nonce = nonce
 IiiiIi1iiii11 = oO00OoO0O0O . encode ( )
 oO00OoO0O0O . print_map_reply ( )
 if 45 - 45: Ii1I / OoOoOO00 + Oo0Ooo + Oo0Ooo * IiII
 i111iII = lisp_eid_record ( )
 i111iII . rloc_count = len ( rloc_set )
 if ( iiO0O0oOO0O0 != None ) : i111iII . rloc_count += 1
 i111iII . authoritative = auth
 i111iII . record_ttl = ttl
 i111iII . action = action
 i111iII . eid = eid
 i111iII . group = group
 if 2 - 2: II111iiii
 IiiiIi1iiii11 += i111iII . encode ( )
 i111iII . print_record ( "  " , False )
 if 34 - 34: o0oOOo0O0Ooo * OOooOOo / OoO0O00
 OoOoO0OOoOo0 = lisp_get_all_addresses ( ) + lisp_get_all_translated_rlocs ( )
 if 94 - 94: II111iiii + i11iIiiIii % Ii1I / ooOoO0o * OoOoOO00
 oooOII11i = None
 for i1III111 in rloc_set :
  o0oO0O00 = i1III111 . rloc . is_multicast_address ( )
  I1Ii11iI = lisp_rloc_record ( )
  oOOoiII = o0O0oO0OOOOO0 and ( o0oO0O00 or iiO0O0oOO0O0 == None )
  oo0o00OO = i1III111 . rloc . print_address_no_iid ( )
  if ( oo0o00OO in OoOoO0OOoOo0 or o0oO0O00 ) :
   I1Ii11iI . local_bit = True
   I1Ii11iI . probe_bit = oOOoiII
   I1Ii11iI . keys = keys
   if ( i1III111 . priority == 254 and lisp_i_am_rtr ) :
    I1Ii11iI . rloc_name = "RTR"
    if 59 - 59: IiII - Ii1I
   if ( oooOII11i == None ) : oooOII11i = i1III111 . rloc
   if 62 - 62: OOooOOo * o0oOOo0O0Ooo + IiII * o0oOOo0O0Ooo * i11iIiiIii - O0
  I1Ii11iI . store_rloc_entry ( i1III111 )
  I1Ii11iI . reach_bit = True
  I1Ii11iI . print_record ( "    " )
  IiiiIi1iiii11 += I1Ii11iI . encode ( )
  if 37 - 37: I1ii11iIi11i - Oo0Ooo . i11iIiiIii / i11iIiiIii + oO0o
  if 19 - 19: i1IIi / i1IIi - OoooooooOO - OOooOOo . i1IIi
  if 57 - 57: OOooOOo / I1ii11iIi11i * oO0o
  if 53 - 53: o0oOOo0O0Ooo * Ii1I
  if 42 - 42: I11i + iII111i / iIii1I11I1II1
 if ( iiO0O0oOO0O0 != None ) :
  I1Ii11iI = lisp_rloc_record ( )
  if ( oooOII11i ) : I1Ii11iI . rloc . copy_address ( oooOII11i )
  I1Ii11iI . local_bit = True
  I1Ii11iI . probe_bit = True
  I1Ii11iI . reach_bit = True
  iii1Iii1 = lisp_encode_telemetry ( iiO0O0oOO0O0 , eo = str ( time . time ( ) ) )
  I1Ii11iI . json = lisp_json ( "telemetry" , iii1Iii1 )
  I1Ii11iI . print_record ( "    " )
  IiiiIi1iiii11 += I1Ii11iI . encode ( )
  if 42 - 42: OoOoOO00 . I1ii11iIi11i
 return ( IiiiIi1iiii11 )
 if 77 - 77: I1ii11iIi11i % i1IIi + OOooOOo - OOooOOo - o0oOOo0O0Ooo
 if 45 - 45: I1ii11iIi11i / o0oOOo0O0Ooo / I1IiiI - Oo0Ooo * ooOoO0o - I1ii11iIi11i
 if 71 - 71: I1IiiI % OoO0O00
 if 32 - 32: oO0o
 if 2 - 2: Oo0Ooo
 if 80 - 80: I1Ii111 * II111iiii % Oo0Ooo * ooOoO0o + o0oOOo0O0Ooo
 if 96 - 96: ooOoO0o
def lisp_build_map_referral ( eid , group , ddt_entry , action , ttl , nonce ) :
 iiII1IiIi1i = lisp_map_referral ( )
 iiII1IiIi1i . record_count = 1
 iiII1IiIi1i . nonce = nonce
 IiiiIi1iiii11 = iiII1IiIi1i . encode ( )
 iiII1IiIi1i . print_map_referral ( )
 if 21 - 21: II111iiii - OOooOOo * O0
 i111iII = lisp_eid_record ( )
 if 52 - 52: IiII / I1IiiI - o0oOOo0O0Ooo
 iI11i = 0
 if ( ddt_entry == None ) :
  i111iII . eid = eid
  i111iII . group = group
 else :
  iI11i = len ( ddt_entry . delegation_set )
  i111iII . eid = ddt_entry . eid
  i111iII . group = ddt_entry . group
  ddt_entry . map_referrals_sent += 1
  if 78 - 78: OOooOOo - Oo0Ooo % o0oOOo0O0Ooo % I1ii11iIi11i
 i111iII . rloc_count = iI11i
 i111iII . authoritative = True
 if 1 - 1: iII111i + Oo0Ooo . OOooOOo % II111iiii / i1IIi - OoO0O00
 if 23 - 23: iIii1I11I1II1 + Oo0Ooo * IiII
 if 80 - 80: OoooooooOO . ooOoO0o
 if 52 - 52: O0 + O0 + I1IiiI
 if 64 - 64: ooOoO0o
 O0II = False
 if ( action == LISP_DDT_ACTION_NULL ) :
  if ( iI11i == 0 ) :
   action = LISP_DDT_ACTION_NODE_REFERRAL
  else :
   I1IooOoo00 = ddt_entry . delegation_set [ 0 ]
   if ( I1IooOoo00 . is_ddt_child ( ) ) :
    action = LISP_DDT_ACTION_NODE_REFERRAL
    if 35 - 35: I1IiiI . iIii1I11I1II1 + IiII / i11iIiiIii - II111iiii . OoooooooOO
   if ( I1IooOoo00 . is_ms_child ( ) ) :
    action = LISP_DDT_ACTION_MS_REFERRAL
    if 19 - 19: IiII - OoOoOO00
    if 43 - 43: IiII / OOooOOo % II111iiii . o0oOOo0O0Ooo / i11iIiiIii
    if 5 - 5: oO0o % iII111i . Oo0Ooo . O0 . OoOoOO00 / iII111i
    if 78 - 78: Ii1I - I1ii11iIi11i + iIii1I11I1II1 + OoooooooOO . OoO0O00 - ooOoO0o
    if 81 - 81: o0oOOo0O0Ooo * OoooooooOO
    if 32 - 32: OoOoOO00 - I11i * i11iIiiIii . I1ii11iIi11i . IiII . iIii1I11I1II1
    if 41 - 41: iII111i / OoOoOO00 / OoO0O00 / ooOoO0o
 if ( action == LISP_DDT_ACTION_NOT_AUTH ) : O0II = True
 if ( action in ( LISP_DDT_ACTION_MS_REFERRAL , LISP_DDT_ACTION_MS_ACK ) ) :
  O0II = ( lisp_i_am_ms and I1IooOoo00 . is_ms_peer ( ) == False )
  if 16 - 16: iIii1I11I1II1 . II111iiii
  if 80 - 80: Oo0Ooo + IiII
 i111iII . action = action
 i111iII . ddt_incomplete = O0II
 i111iII . record_ttl = ttl
 if 18 - 18: OoO0O00 . Oo0Ooo
 IiiiIi1iiii11 += i111iII . encode ( )
 i111iII . print_record ( "  " , True )
 if 52 - 52: OoOoOO00 . iIii1I11I1II1 / OoOoOO00
 if ( iI11i == 0 ) : return ( IiiiIi1iiii11 )
 if 14 - 14: i1IIi
 for I1IooOoo00 in ddt_entry . delegation_set :
  I1Ii11iI = lisp_rloc_record ( )
  I1Ii11iI . rloc = I1IooOoo00 . delegate_address
  I1Ii11iI . priority = I1IooOoo00 . priority
  I1Ii11iI . weight = I1IooOoo00 . weight
  I1Ii11iI . mpriority = 255
  I1Ii11iI . mweight = 0
  I1Ii11iI . reach_bit = True
  IiiiIi1iiii11 += I1Ii11iI . encode ( )
  I1Ii11iI . print_record ( "    " )
  if 63 - 63: OoOoOO00 . i11iIiiIii / IiII
 return ( IiiiIi1iiii11 )
 if 36 - 36: OOooOOo * OoOoOO00 + i11iIiiIii + O0 + O0
 if 18 - 18: Oo0Ooo . I1ii11iIi11i * ooOoO0o % Ii1I + I1ii11iIi11i
 if 23 - 23: oO0o / o0oOOo0O0Ooo + I11i % IiII * OoO0O00
 if 48 - 48: OoO0O00
 if 30 - 30: iIii1I11I1II1
 if 53 - 53: II111iiii
 if 40 - 40: Ii1I % oO0o
def lisp_etr_process_map_request ( lisp_sockets , map_request , source , sport ,
 ttl , etr_in_ts ) :
 if 69 - 69: iIii1I11I1II1 - O0 . I1Ii111 % I1IiiI / o0oOOo0O0Ooo
 if ( map_request . target_group . is_null ( ) ) :
  ooOOo0ooo = lisp_db_for_lookups . lookup_cache ( map_request . target_eid , False )
 else :
  ooOOo0ooo = lisp_db_for_lookups . lookup_cache ( map_request . target_group , False )
  if ( ooOOo0ooo ) : ooOOo0ooo = ooOOo0ooo . lookup_source_cache ( map_request . target_eid , False )
  if 71 - 71: OoOoOO00 / i11iIiiIii * iII111i
 I11i11i1 = map_request . print_prefix ( )
 if 90 - 90: Ii1I
 if ( ooOOo0ooo == None ) :
  lprint ( "Database-mapping entry not found for requested EID {}" . format ( green ( I11i11i1 , False ) ) )
  if 27 - 27: oO0o + Ii1I . i11iIiiIii
  return
  if 97 - 97: iII111i . I1IiiI
  if 71 - 71: OOooOOo - IiII % oO0o * I1ii11iIi11i
 iIIiIIiII111 = ooOOo0ooo . print_eid_tuple ( )
 if 24 - 24: O0 . Oo0Ooo + O0 % Ii1I + OoooooooOO
 lprint ( "Found database-mapping EID-prefix {} for requested EID {}" . format ( green ( iIIiIIiII111 , False ) , green ( I11i11i1 , False ) ) )
 if 72 - 72: I1ii11iIi11i
 if 100 - 100: i11iIiiIii - iII111i - I11i
 if 5 - 5: oO0o % IiII * iII111i
 if 98 - 98: iII111i / OOooOOo + IiII
 if 100 - 100: II111iiii . i11iIiiIii / oO0o - OOooOOo + OoOoOO00 % I1ii11iIi11i
 o00O00oOO00 = map_request . itr_rlocs [ 0 ]
 if ( o00O00oOO00 . is_private_address ( ) and lisp_nat_traversal ) :
  o00O00oOO00 = source
  if 3 - 3: i1IIi * I1ii11iIi11i * II111iiii . I1ii11iIi11i
  if 82 - 82: OoOoOO00
 Iii11I = map_request . nonce
 i11 = lisp_nonce_echoing
 iIi11III = map_request . keys
 if 53 - 53: OOooOOo * OoOoOO00 % iII111i
 if 86 - 86: OOooOOo . OOooOOo + IiII - I1ii11iIi11i . OoO0O00
 if 66 - 66: I1IiiI * OoOoOO00 . I1IiiI / Oo0Ooo - Ii1I
 if 69 - 69: iIii1I11I1II1 % iII111i + ooOoO0o * i1IIi + iII111i * I1Ii111
 if 67 - 67: Ii1I % Oo0Ooo - Oo0Ooo . I11i + IiII
 oOooo0o = map_request . json_telemetry
 if ( oOooo0o != None ) :
  map_request . json_telemetry = lisp_encode_telemetry ( oOooo0o , ei = etr_in_ts )
  if 45 - 45: oO0o + ooOoO0o + OOooOOo * OOooOOo * o0oOOo0O0Ooo / Oo0Ooo
  if 61 - 61: OoooooooOO % i11iIiiIii . i1IIi . OOooOOo
 ooOOo0ooo . map_replies_sent += 1
 if 90 - 90: iIii1I11I1II1 - iIii1I11I1II1 % O0
 IiiiIi1iiii11 = lisp_build_map_reply ( ooOOo0ooo . eid , ooOOo0ooo . group , ooOOo0ooo . rloc_set , Iii11I ,
 LISP_NO_ACTION , 1440 , map_request , iIi11III , i11 , True , ttl )
 if 43 - 43: Oo0Ooo / i1IIi % Ii1I . OoOoOO00
 if 22 - 22: iIii1I11I1II1 + Ii1I
 if 73 - 73: I1IiiI / OoO0O00 / OoooooooOO
 if 14 - 14: ooOoO0o % o0oOOo0O0Ooo / I1ii11iIi11i . IiII + I1ii11iIi11i
 if 30 - 30: I1ii11iIi11i + iIii1I11I1II1 . I1ii11iIi11i
 if 9 - 9: I1IiiI - Ii1I * II111iiii - I11i
 if 85 - 85: oO0o % ooOoO0o / OOooOOo
 if 50 - 50: O0 * O0 / iIii1I11I1II1
 if 31 - 31: I1IiiI / o0oOOo0O0Ooo
 if 70 - 70: I1IiiI
 if 36 - 36: ooOoO0o . oO0o . I11i - I1ii11iIi11i / OoOoOO00 * Oo0Ooo
 if 42 - 42: OoooooooOO / o0oOOo0O0Ooo . Ii1I * iII111i * I1IiiI - Oo0Ooo
 if 76 - 76: oO0o * II111iiii
 if 81 - 81: I11i
 if 2 - 2: OoOoOO00
 if 75 - 75: I1IiiI - OoooooooOO * I1Ii111
 if ( map_request . rloc_probe and len ( lisp_sockets ) == 4 ) :
  iiI1Iii = ( o00O00oOO00 . is_private_address ( ) == False )
  I11ii1I111Ii = o00O00oOO00 . print_address_no_iid ( )
  if ( ( iiI1Iii and lisp_rtr_list . has_key ( I11ii1I111Ii ) ) or sport == 0 ) :
   lisp_encapsulate_rloc_probe ( lisp_sockets , o00O00oOO00 , None , IiiiIi1iiii11 )
   return
   if 1 - 1: o0oOOo0O0Ooo % oO0o * I1Ii111 - i1IIi - iII111i . oO0o
   if 25 - 25: i1IIi * o0oOOo0O0Ooo / oO0o
   if 11 - 11: IiII + II111iiii
   if 37 - 37: O0
   if 98 - 98: IiII * OoooooooOO . iII111i
   if 34 - 34: OoooooooOO + I1Ii111
 lisp_send_map_reply ( lisp_sockets , IiiiIi1iiii11 , o00O00oOO00 , sport )
 return
 if 97 - 97: II111iiii + I11i + OOooOOo / i11iIiiIii - iII111i
 if 9 - 9: i1IIi - I1Ii111 + I1Ii111
 if 81 - 81: II111iiii % I11i % O0 . I1Ii111 % ooOoO0o - O0
 if 58 - 58: OoooooooOO . II111iiii . O0 % I1Ii111 / OoooooooOO
 if 64 - 64: Oo0Ooo + oO0o . OoO0O00
 if 67 - 67: I11i
 if 91 - 91: OOooOOo / OoO0O00
def lisp_rtr_process_map_request ( lisp_sockets , map_request , source , sport ,
 ttl , etr_in_ts ) :
 if 36 - 36: I1IiiI . iII111i * I1Ii111 . IiII % I1ii11iIi11i
 if 44 - 44: I11i % I1ii11iIi11i - OoooooooOO % iII111i
 if 60 - 60: IiII % oO0o
 if 11 - 11: I1Ii111 - II111iiii
 o00O00oOO00 = map_request . itr_rlocs [ 0 ]
 if ( o00O00oOO00 . is_private_address ( ) ) : o00O00oOO00 = source
 Iii11I = map_request . nonce
 if 12 - 12: i11iIiiIii
 ooOOoo0 = map_request . target_eid
 IIi1iiIII11 = map_request . target_group
 if 9 - 9: OOooOOo * I1ii11iIi11i + iIii1I11I1II1 / OoO0O00 * OoooooooOO
 OoO0oOOooOO = [ ]
 for oooOO0 in [ lisp_myrlocs [ 0 ] , lisp_myrlocs [ 1 ] ] :
  if ( oooOO0 == None ) : continue
  I1IIiIIIii = lisp_rloc ( )
  I1IIiIIIii . rloc . copy_address ( oooOO0 )
  I1IIiIIIii . priority = 254
  OoO0oOOooOO . append ( I1IIiIIIii )
  if 60 - 60: IiII + I1IiiI
  if 61 - 61: OoO0O00
 i11 = lisp_nonce_echoing
 iIi11III = map_request . keys
 if 96 - 96: ooOoO0o - OoooooooOO * iIii1I11I1II1 . IiII - O0
 if 7 - 7: iIii1I11I1II1 . OoO0O00
 if 88 - 88: i1IIi * II111iiii / i11iIiiIii % IiII . IiII
 if 93 - 93: OoOoOO00 * i1IIi . Ii1I
 if 2 - 2: i1IIi
 oOooo0o = map_request . json_telemetry
 if ( oOooo0o != None ) :
  map_request . json_telemetry = lisp_encode_telemetry ( oOooo0o , ei = etr_in_ts )
  if 84 - 84: i1IIi / Ii1I + OoOoOO00 % Ii1I . oO0o
  if 74 - 74: OOooOOo - o0oOOo0O0Ooo - I1Ii111 - OoO0O00
 IiiiIi1iiii11 = lisp_build_map_reply ( ooOOoo0 , IIi1iiIII11 , OoO0oOOooOO , Iii11I , LISP_NO_ACTION ,
 1440 , map_request , iIi11III , i11 , True , ttl )
 lisp_send_map_reply ( lisp_sockets , IiiiIi1iiii11 , o00O00oOO00 , sport )
 return
 if 40 - 40: o0oOOo0O0Ooo . IiII * OoOoOO00
 if 14 - 14: OOooOOo
 if 18 - 18: i11iIiiIii % iII111i
 if 70 - 70: O0 + iII111i % I11i % I1Ii111 + OoOoOO00 / ooOoO0o
 if 35 - 35: IiII + OoO0O00
 if 82 - 82: i1IIi - ooOoO0o / I11i + I11i % I1IiiI - OoooooooOO
 if 56 - 56: I1ii11iIi11i
 if 80 - 80: Oo0Ooo / OOooOOo / iII111i . o0oOOo0O0Ooo
 if 43 - 43: IiII
 if 74 - 74: OoooooooOO
def lisp_get_private_rloc_set ( target_site_eid , seid , group ) :
 OoO0oOOooOO = target_site_eid . registered_rlocs
 if 88 - 88: Ii1I * o0oOOo0O0Ooo / oO0o
 oO = lisp_site_eid_lookup ( seid , group , False )
 if ( oO == None ) : return ( OoO0oOOooOO )
 if 58 - 58: OoooooooOO . i1IIi
 if 71 - 71: iII111i + ooOoO0o * OoOoOO00 . I1ii11iIi11i . I1Ii111
 if 91 - 91: oO0o - Oo0Ooo % OoOoOO00 % o0oOOo0O0Ooo
 if 71 - 71: i1IIi % iII111i * I1Ii111
 II1ii1IIi1i = None
 iioo00oOOO00 = [ ]
 for i1III111 in OoO0oOOooOO :
  if ( i1III111 . is_rtr ( ) ) : continue
  if ( i1III111 . rloc . is_private_address ( ) ) :
   oOO0Oo = copy . deepcopy ( i1III111 )
   iioo00oOOO00 . append ( oOO0Oo )
   continue
   if 7 - 7: I1Ii111 * iIii1I11I1II1
  II1ii1IIi1i = i1III111
  break
  if 27 - 27: iII111i % OoOoOO00 % ooOoO0o
 if ( II1ii1IIi1i == None ) : return ( OoO0oOOooOO )
 II1ii1IIi1i = II1ii1IIi1i . rloc . print_address_no_iid ( )
 if 4 - 4: iII111i * oO0o / iIii1I11I1II1 - O0 . Ii1I
 if 53 - 53: Ii1I % IiII + I11i % IiII
 if 33 - 33: iII111i
 if 8 - 8: I11i
 oO0oo0o0ooO = None
 for i1III111 in oO . registered_rlocs :
  if ( i1III111 . is_rtr ( ) ) : continue
  if ( i1III111 . rloc . is_private_address ( ) ) : continue
  oO0oo0o0ooO = i1III111
  break
  if 41 - 41: OoO0O00 . Ii1I % II111iiii - i11iIiiIii % o0oOOo0O0Ooo % o0oOOo0O0Ooo
 if ( oO0oo0o0ooO == None ) : return ( OoO0oOOooOO )
 oO0oo0o0ooO = oO0oo0o0ooO . rloc . print_address_no_iid ( )
 if 2 - 2: ooOoO0o / OOooOOo % iIii1I11I1II1 * I1IiiI - I11i
 if 3 - 3: i11iIiiIii
 if 52 - 52: oO0o . OoO0O00 + OoooooooOO % II111iiii % OoOoOO00 - I1Ii111
 if 2 - 2: II111iiii * OOooOOo - I11i / I1IiiI
 O0O0oOO = target_site_eid . site_id
 if ( O0O0oOO == 0 ) :
  if ( oO0oo0o0ooO == II1ii1IIi1i ) :
   lprint ( "Return private RLOCs for sites behind {}" . format ( II1ii1IIi1i ) )
   if 13 - 13: Oo0Ooo
   return ( iioo00oOOO00 )
   if 88 - 88: Oo0Ooo / oO0o . iIii1I11I1II1 . I1IiiI + I11i
  return ( OoO0oOOooOO )
  if 58 - 58: I11i
  if 76 - 76: iIii1I11I1II1 % ooOoO0o / IiII + iIii1I11I1II1 % Oo0Ooo . Ii1I
  if 72 - 72: Ii1I - I1ii11iIi11i * I1Ii111 % OoOoOO00 % OoOoOO00
  if 44 - 44: o0oOOo0O0Ooo . O0 + Ii1I
  if 61 - 61: ooOoO0o
  if 23 - 23: OoooooooOO - OoOoOO00 / i11iIiiIii
  if 37 - 37: I11i / o0oOOo0O0Ooo + oO0o % Ii1I
 if ( O0O0oOO == oO . site_id ) :
  lprint ( "Return private RLOCs for sites in site-id {}" . format ( O0O0oOO ) )
  return ( iioo00oOOO00 )
  if 83 - 83: I1ii11iIi11i . OOooOOo
 return ( OoO0oOOooOO )
 if 50 - 50: Ii1I - i11iIiiIii % Ii1I - OoOoOO00 + I1IiiI / OoooooooOO
 if 57 - 57: I1IiiI - I11i - I1Ii111 . oO0o % Ii1I
 if 59 - 59: I1IiiI % OoO0O00 . o0oOOo0O0Ooo
 if 85 - 85: ooOoO0o . ooOoO0o % Oo0Ooo . OOooOOo + OOooOOo / I1IiiI
 if 69 - 69: i1IIi + II111iiii / Ii1I
 if 4 - 4: I11i * OoOoOO00 % o0oOOo0O0Ooo % ooOoO0o - I1ii11iIi11i
 if 88 - 88: iIii1I11I1II1 * iIii1I11I1II1 * I11i * OoOoOO00
 if 14 - 14: i11iIiiIii * I1IiiI % O0 % iIii1I11I1II1
 if 18 - 18: Oo0Ooo % OOooOOo + IiII
def lisp_get_partial_rloc_set ( registered_rloc_set , mr_source , multicast ) :
 I1 = [ ]
 OoO0oOOooOO = [ ]
 if 32 - 32: o0oOOo0O0Ooo + II111iiii / ooOoO0o
 if 13 - 13: ooOoO0o % O0
 if 26 - 26: iIii1I11I1II1 + iIii1I11I1II1 . Ii1I + i1IIi
 if 16 - 16: II111iiii . Ii1I / i11iIiiIii
 if 25 - 25: OoO0O00 + o0oOOo0O0Ooo
 if 100 - 100: II111iiii - OOooOOo % oO0o % Ii1I . ooOoO0o / iII111i
 I1Ii1iIiIi = False
 oO0 = False
 for i1III111 in registered_rloc_set :
  if ( i1III111 . priority != 254 ) : continue
  oO0 |= True
  if ( i1III111 . rloc . is_exact_match ( mr_source ) == False ) : continue
  I1Ii1iIiIi = True
  break
  if 25 - 25: I1Ii111 % OOooOOo
  if 82 - 82: Ii1I
  if 17 - 17: iII111i . i1IIi . i1IIi
  if 76 - 76: OoooooooOO % IiII
  if 81 - 81: iII111i . OOooOOo * i1IIi
  if 14 - 14: oO0o
  if 16 - 16: iII111i
 if ( oO0 == False ) : return ( registered_rloc_set )
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
 I11I111Ii1II = ( os . getenv ( "LISP_RTR_BEHIND_NAT" ) != None )
 if 29 - 29: II111iiii - i11iIiiIii - iII111i + i11iIiiIii . IiII - I1Ii111
 if 40 - 40: I11i . iII111i + OoOoOO00 % I1ii11iIi11i
 if 79 - 79: I1Ii111 - OOooOOo * I1ii11iIi11i + i11iIiiIii . iII111i
 if 3 - 3: Oo0Ooo
 if 81 - 81: OoO0O00 / OoO0O00 . I1ii11iIi11i
 for i1III111 in registered_rloc_set :
  if ( I11I111Ii1II and i1III111 . rloc . is_private_address ( ) ) : continue
  if ( multicast == False and i1III111 . priority == 255 ) : continue
  if ( multicast and i1III111 . mpriority == 255 ) : continue
  if ( i1III111 . priority == 254 ) :
   I1 . append ( i1III111 )
  else :
   OoO0oOOooOO . append ( i1III111 )
   if 100 - 100: iIii1I11I1II1 % II111iiii - I1ii11iIi11i . iIii1I11I1II1 + IiII % iIii1I11I1II1
   if 48 - 48: Ii1I % i1IIi
   if 38 - 38: OOooOOo / I1ii11iIi11i % oO0o / o0oOOo0O0Ooo
   if 54 - 54: OoOoOO00 * OoooooooOO - OoO0O00 * OoOoOO00 % I1ii11iIi11i * I11i
   if 34 - 34: I11i - oO0o + I11i * OoooooooOO * I11i
   if 73 - 73: OOooOOo * iII111i * OoO0O00
 if ( I1Ii1iIiIi ) : return ( OoO0oOOooOO )
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
 OoO0oOOooOO = [ ]
 for i1III111 in registered_rloc_set :
  if ( i1III111 . rloc . is_private_address ( ) ) : OoO0oOOooOO . append ( i1III111 )
  if 93 - 93: O0 * OoOoOO00 * iIii1I11I1II1
 OoO0oOOooOO += I1
 return ( OoO0oOOooOO )
 if 3 - 3: I1ii11iIi11i - O0
 if 46 - 46: iII111i
 if 99 - 99: oO0o
 if 85 - 85: I1Ii111 * iIii1I11I1II1 . OoOoOO00
 if 20 - 20: I11i * O0 - OoooooooOO * OOooOOo % oO0o * iII111i
 if 70 - 70: I11i + O0 . i11iIiiIii . OOooOOo
 if 48 - 48: iIii1I11I1II1 * Ii1I - OoooooooOO / oO0o - OoO0O00 / i11iIiiIii
 if 24 - 24: I1IiiI
 if 63 - 63: I11i - iIii1I11I1II1 * Ii1I + OoooooooOO . i11iIiiIii
 if 94 - 94: OoO0O00 . oO0o . OoOoOO00 * i11iIiiIii
def lisp_store_pubsub_state ( reply_eid , itr_rloc , mr_sport , nonce , ttl , xtr_id ) :
 Ooo = lisp_pubsub ( itr_rloc , mr_sport , nonce , ttl , xtr_id )
 Ooo . add ( reply_eid )
 return
 if 45 - 45: oO0o + Ii1I - OOooOOo / I1IiiI
 if 100 - 100: O0 - II111iiii + OoO0O00 % I1Ii111
 if 40 - 40: iIii1I11I1II1 % OoO0O00 / o0oOOo0O0Ooo + iIii1I11I1II1
 if 77 - 77: I1IiiI
 if 97 - 97: Ii1I - I1IiiI
 if 5 - 5: OoO0O00 / IiII . OoooooooOO / IiII / I1Ii111 * iIii1I11I1II1
 if 79 - 79: IiII % ooOoO0o + IiII + IiII - o0oOOo0O0Ooo + iII111i
 if 94 - 94: o0oOOo0O0Ooo * oO0o + O0 * iII111i + oO0o + ooOoO0o
 if 29 - 29: OoO0O00
 if 24 - 24: IiII - OoOoOO00 / OoooooooOO . I1ii11iIi11i
 if 88 - 88: I11i
 if 36 - 36: iIii1I11I1II1 - ooOoO0o * OoO0O00 * OoO0O00 . II111iiii
 if 49 - 49: O0 + OoO0O00 - I1ii11iIi11i + ooOoO0o
 if 90 - 90: O0 . Ii1I * OOooOOo * OoooooooOO * ooOoO0o * Ii1I
 if 12 - 12: ooOoO0o * OoooooooOO * i1IIi
def lisp_convert_reply_to_notify ( packet ) :
 if 3 - 3: o0oOOo0O0Ooo + Ii1I - i1IIi . OoooooooOO % Ii1I
 if 39 - 39: o0oOOo0O0Ooo
 if 73 - 73: IiII
 if 92 - 92: OOooOOo / ooOoO0o . I1Ii111 . iII111i / ooOoO0o
 ooOO0o0O0 = struct . unpack ( "I" , packet [ 0 : 4 ] ) [ 0 ]
 ooOO0o0O0 = socket . ntohl ( ooOO0o0O0 ) & 0xff
 Iii11I = packet [ 4 : 12 ]
 packet = packet [ 12 : : ]
 if 87 - 87: i11iIiiIii % i11iIiiIii + OoOoOO00 . O0 * II111iiii
 if 24 - 24: O0 . I1ii11iIi11i / OOooOOo % IiII * Oo0Ooo / OoO0O00
 if 67 - 67: Oo0Ooo * I11i - IiII + I1Ii111
 if 90 - 90: iII111i % II111iiii % o0oOOo0O0Ooo + o0oOOo0O0Ooo + II111iiii
 iII = ( LISP_MAP_NOTIFY << 28 ) | ooOO0o0O0
 O0ooOoO0 = struct . pack ( "I" , socket . htonl ( iII ) )
 o00O0o00oo = struct . pack ( "I" , 0 )
 if 54 - 54: OoooooooOO . IiII - oO0o
 if 26 - 26: o0oOOo0O0Ooo - i1IIi / I1ii11iIi11i / OoooooooOO . i1IIi
 if 22 - 22: o0oOOo0O0Ooo * I1Ii111 * I1ii11iIi11i . OoOoOO00 . i1IIi % ooOoO0o
 if 67 - 67: I11i
 packet = O0ooOoO0 + Iii11I + o00O0o00oo + packet
 return ( packet )
 if 95 - 95: OoO0O00 % I1Ii111
 if 49 - 49: II111iiii % OoOoOO00 % OOooOOo
 if 40 - 40: I1ii11iIi11i + i1IIi
 if 9 - 9: OOooOOo
 if 74 - 74: OoOoOO00 - OOooOOo % OoOoOO00
 if 82 - 82: I11i % IiII + Oo0Ooo + iIii1I11I1II1 - I11i - I1IiiI
 if 65 - 65: IiII / O0 * II111iiii + oO0o
 if 52 - 52: o0oOOo0O0Ooo - OoOoOO00 * II111iiii / OoooooooOO
def lisp_notify_subscribers ( lisp_sockets , eid_record , eid , site ) :
 I11i11i1 = eid . print_prefix ( )
 if ( lisp_pubsub_cache . has_key ( I11i11i1 ) == False ) : return
 if 44 - 44: OOooOOo - oO0o + o0oOOo0O0Ooo - i1IIi % o0oOOo0O0Ooo
 for Ooo in lisp_pubsub_cache [ I11i11i1 ] . values ( ) :
  I11iiII1I1111 = Ooo . itr
  Oo0O00O = Ooo . port
  I111iI1IIIi1I = red ( I11iiII1I1111 . print_address_no_iid ( ) , False )
  o0iiii1iii111i1 = bold ( "subscriber" , False )
  I1II = "0x" + lisp_hex_string ( Ooo . xtr_id )
  Iii11I = "0x" + lisp_hex_string ( Ooo . nonce )
  if 90 - 90: iIii1I11I1II1
  lprint ( "    Notify {} {}:{} xtr-id {} for {}, nonce {}" . format ( o0iiii1iii111i1 , I111iI1IIIi1I , Oo0O00O , I1II , green ( I11i11i1 , False ) , Iii11I ) )
  if 87 - 87: Oo0Ooo . o0oOOo0O0Ooo
  if 33 - 33: iIii1I11I1II1 / OoooooooOO / I1IiiI + II111iiii
  lisp_build_map_notify ( lisp_sockets , eid_record , [ I11i11i1 ] , 1 , I11iiII1I1111 ,
 Oo0O00O , Ooo . nonce , 0 , 0 , 0 , site , False )
  Ooo . map_notify_count += 1
  if 42 - 42: OoOoOO00 / i1IIi * O0
 return
 if 46 - 46: OOooOOo - I1Ii111 + I1IiiI - ooOoO0o
 if 96 - 96: IiII + i1IIi - I11i * I11i - OoO0O00 % II111iiii
 if 47 - 47: I1Ii111 . i11iIiiIii + oO0o . I1ii11iIi11i
 if 12 - 12: iIii1I11I1II1 % I1Ii111 * OoOoOO00 / OoooooooOO % OoooooooOO
 if 81 - 81: iIii1I11I1II1 - Oo0Ooo - ooOoO0o . OoO0O00 + I1ii11iIi11i
 if 84 - 84: iII111i . OOooOOo . iII111i * oO0o % Ii1I . oO0o
 if 86 - 86: iII111i * ooOoO0o / iIii1I11I1II1 + Ii1I . iII111i
def lisp_process_pubsub ( lisp_sockets , packet , reply_eid , itr_rloc , port , nonce ,
 ttl , xtr_id ) :
 if 64 - 64: IiII - Oo0Ooo % iII111i % I11i
 if 42 - 42: Oo0Ooo . OoO0O00
 if 22 - 22: ooOoO0o - o0oOOo0O0Ooo + I11i / I1IiiI + OOooOOo
 if 10 - 10: oO0o / I1IiiI
 lisp_store_pubsub_state ( reply_eid , itr_rloc , port , nonce , ttl , xtr_id )
 if 95 - 95: II111iiii - IiII % IiII . o0oOOo0O0Ooo
 ooOOoo0 = green ( reply_eid . print_prefix ( ) , False )
 I11iiII1I1111 = red ( itr_rloc . print_address_no_iid ( ) , False )
 IiI1iiiI1I1 = bold ( "Map-Notify" , False )
 xtr_id = "0x" + lisp_hex_string ( xtr_id )
 lprint ( "{} pubsub request for {} to ack ITR {} xtr-id: {}" . format ( IiI1iiiI1I1 ,
 ooOOoo0 , I11iiII1I1111 , xtr_id ) )
 if 3 - 3: I1Ii111 . i1IIi
 if 3 - 3: O0 + i1IIi - OOooOOo / I1Ii111
 if 13 - 13: oO0o + Oo0Ooo + Oo0Ooo / OoO0O00 + i1IIi + I1IiiI
 if 56 - 56: OoOoOO00
 packet = lisp_convert_reply_to_notify ( packet )
 lisp_send_map_notify ( lisp_sockets , packet , itr_rloc , port )
 return
 if 10 - 10: iIii1I11I1II1 + i1IIi * Ii1I / iIii1I11I1II1 % OoOoOO00 / O0
 if 14 - 14: O0
 if 65 - 65: IiII / oO0o
 if 57 - 57: IiII + oO0o - IiII
 if 51 - 51: OoOoOO00 % IiII / iII111i - oO0o - OoO0O00 . iIii1I11I1II1
 if 61 - 61: OoO0O00
 if 60 - 60: I1IiiI % O0 % OoooooooOO / Ii1I
 if 9 - 9: OoooooooOO / I11i % I11i * O0 / II111iiii . II111iiii
def lisp_ms_process_map_request ( lisp_sockets , packet , map_request , mr_source ,
 mr_sport , ecm_source ) :
 if 40 - 40: II111iiii + OoooooooOO / iII111i % O0 + OOooOOo . ooOoO0o
 if 71 - 71: OoooooooOO + ooOoO0o * o0oOOo0O0Ooo + I1IiiI
 if 47 - 47: oO0o
 if 91 - 91: I1IiiI * O0 + OoooooooOO * i1IIi % I1ii11iIi11i . IiII
 if 67 - 67: I1IiiI * I11i
 if 43 - 43: IiII * Oo0Ooo / OoOoOO00 + I1IiiI - i11iIiiIii + II111iiii
 ooOOoo0 = map_request . target_eid
 IIi1iiIII11 = map_request . target_group
 I11i11i1 = lisp_print_eid_tuple ( ooOOoo0 , IIi1iiIII11 )
 o00O00oOO00 = map_request . itr_rlocs [ 0 ]
 I1II = map_request . xtr_id
 Iii11I = map_request . nonce
 I11I1iI = LISP_NO_ACTION
 Ooo = map_request . subscribe_bit
 if 81 - 81: I11i / Oo0Ooo % Ii1I % OoO0O00
 if 87 - 87: O0 % II111iiii
 if 42 - 42: I1IiiI . i1IIi
 if 98 - 98: o0oOOo0O0Ooo % I11i . Oo0Ooo * Oo0Ooo % iII111i
 if 37 - 37: OoO0O00 / I1Ii111 . I1Ii111 * i1IIi
 III = True
 iiiooO = ( lisp_get_eid_hash ( ooOOoo0 ) != None )
 if ( iiiooO ) :
  O0OO0OoO00oOo = map_request . map_request_signature
  if ( O0OO0OoO00oOo == None ) :
   III = False
   lprint ( ( "EID-crypto-hash signature verification {}, " + "no signature found" ) . format ( bold ( "failed" , False ) ) )
   if 92 - 92: OoooooooOO * i1IIi - i11iIiiIii + O0
  else :
   Oo0o0ooOo0 = map_request . signature_eid
   ii1iIIi , I1i1ii , III = lisp_lookup_public_key ( Oo0o0ooOo0 )
   if ( III ) :
    III = map_request . verify_map_request_sig ( I1i1ii )
   else :
    lprint ( "Public-key lookup failed for sig-eid {}, hash-eid {}" . format ( Oo0o0ooOo0 . print_address ( ) , ii1iIIi . print_address ( ) ) )
    if 61 - 61: ooOoO0o . I1Ii111 % I1ii11iIi11i
    if 90 - 90: iII111i . OOooOOo % OoooooooOO % O0
   O0oO = bold ( "passed" , False ) if III else bold ( "failed" , False )
   lprint ( "EID-crypto-hash signature verification {}" . format ( O0oO ) )
   if 46 - 46: ooOoO0o . I1IiiI - ooOoO0o + Oo0Ooo
   if 31 - 31: OOooOOo + ooOoO0o . i1IIi - OoO0O00
   if 16 - 16: I11i + I1IiiI - Ii1I / I1ii11iIi11i + Ii1I
 if ( Ooo and III == False ) :
  Ooo = False
  lprint ( "Suppress creating pubsub state due to signature failure" )
  if 38 - 38: i1IIi * iIii1I11I1II1 * iII111i + OoOoOO00
  if 64 - 64: OoO0O00 % o0oOOo0O0Ooo
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
  if 64 - 64: II111iiii % I1ii11iIi11i . OoOoOO00 . iIii1I11I1II1 / I1ii11iIi11i
  if 43 - 43: OoooooooOO * I1IiiI
 IIII = o00O00oOO00 if ( o00O00oOO00 . afi == ecm_source . afi ) else ecm_source
 if 40 - 40: i11iIiiIii % iIii1I11I1II1 . ooOoO0o - I11i
 o0o000 = lisp_site_eid_lookup ( ooOOoo0 , IIi1iiIII11 , False )
 if 53 - 53: IiII / I1Ii111
 if ( o0o000 == None or o0o000 . is_star_g ( ) ) :
  iiiII = bold ( "Site not found" , False )
  lprint ( "{} for requested EID {}" . format ( iiiII ,
 green ( I11i11i1 , False ) ) )
  if 90 - 90: iIii1I11I1II1 + ooOoO0o . iII111i * oO0o . OOooOOo
  if 74 - 74: o0oOOo0O0Ooo * II111iiii % oO0o % OoooooooOO
  if 21 - 21: OOooOOo
  if 2 - 2: I11i - OOooOOo / o0oOOo0O0Ooo
  lisp_send_negative_map_reply ( lisp_sockets , ooOOoo0 , IIi1iiIII11 , Iii11I , o00O00oOO00 ,
 mr_sport , 15 , I1II , Ooo )
  if 14 - 14: I11i + Oo0Ooo + i11iIiiIii - i1IIi . O0
  return ( [ ooOOoo0 , IIi1iiIII11 , LISP_DDT_ACTION_SITE_NOT_FOUND ] )
  if 47 - 47: o0oOOo0O0Ooo / i1IIi * IiII
  if 50 - 50: I11i
 iIIiIIiII111 = o0o000 . print_eid_tuple ( )
 i11I11iiiI1 = o0o000 . site . site_name
 if 76 - 76: i11iIiiIii / oO0o / II111iiii
 if 49 - 49: i1IIi * II111iiii * Oo0Ooo % oO0o / II111iiii
 if 8 - 8: I1IiiI . o0oOOo0O0Ooo / OoooooooOO - II111iiii
 if 93 - 93: OoOoOO00 / OoOoOO00 / OoOoOO00
 if 74 - 74: ooOoO0o % Oo0Ooo - iII111i - I1IiiI
 if ( iiiooO == False and o0o000 . require_signature ) :
  O0OO0OoO00oOo = map_request . map_request_signature
  Oo0o0ooOo0 = map_request . signature_eid
  if ( O0OO0OoO00oOo == None or Oo0o0ooOo0 . is_null ( ) ) :
   lprint ( "Signature required for site {}" . format ( i11I11iiiI1 ) )
   III = False
  else :
   Oo0o0ooOo0 = map_request . signature_eid
   ii1iIIi , I1i1ii , III = lisp_lookup_public_key ( Oo0o0ooOo0 )
   if ( III ) :
    III = map_request . verify_map_request_sig ( I1i1ii )
   else :
    lprint ( "Public-key lookup failed for sig-eid {}, hash-eid {}" . format ( Oo0o0ooOo0 . print_address ( ) , ii1iIIi . print_address ( ) ) )
    if 51 - 51: i11iIiiIii % OoOoOO00
    if 17 - 17: ooOoO0o - i1IIi
   O0oO = bold ( "passed" , False ) if III else bold ( "failed" , False )
   lprint ( "Required signature verification {}" . format ( O0oO ) )
   if 73 - 73: iIii1I11I1II1 - I1Ii111 % Oo0Ooo . O0
   if 16 - 16: OoO0O00 / Oo0Ooo / IiII . Oo0Ooo - OoooooooOO
   if 5 - 5: OoOoOO00 . I11i
   if 28 - 28: I11i % OOooOOo + Oo0Ooo / OoO0O00 % o0oOOo0O0Ooo + OoO0O00
   if 20 - 20: ooOoO0o . iII111i % OOooOOo + i11iIiiIii
   if 64 - 64: i1IIi . o0oOOo0O0Ooo * I1Ii111 - O0
 if ( III and o0o000 . registered == False ) :
  lprint ( "Site '{}' with EID-prefix {} is not registered for EID {}" . format ( i11I11iiiI1 , green ( iIIiIIiII111 , False ) , green ( I11i11i1 , False ) ) )
  if 76 - 76: I1IiiI % Ii1I + OoO0O00 + I1ii11iIi11i * II111iiii + Oo0Ooo
  if 3 - 3: Ii1I - I1IiiI + O0
  if 90 - 90: Ii1I + OoooooooOO . i11iIiiIii / Oo0Ooo % OoOoOO00 / IiII
  if 45 - 45: OoooooooOO / oO0o . I1ii11iIi11i + OOooOOo
  if 54 - 54: Ii1I - o0oOOo0O0Ooo + OoOoOO00 / OoooooooOO
  if 61 - 61: I11i / IiII % OoooooooOO - i11iIiiIii * i1IIi % o0oOOo0O0Ooo
  if ( o0o000 . accept_more_specifics == False ) :
   ooOOoo0 = o0o000 . eid
   IIi1iiIII11 = o0o000 . group
   if 67 - 67: o0oOOo0O0Ooo - Ii1I
   if 29 - 29: OoOoOO00 . I1ii11iIi11i
   if 24 - 24: OOooOOo + i1IIi . I11i . OoOoOO00 + OoooooooOO
   if 98 - 98: ooOoO0o + i1IIi / I1IiiI
   if 1 - 1: IiII . OoooooooOO + II111iiii
  oOoooOOO0o0 = 1
  if ( o0o000 . force_ttl != None ) :
   oOoooOOO0o0 = o0o000 . force_ttl | 0x80000000
   if 6 - 6: O0 * Oo0Ooo
   if 20 - 20: OoooooooOO * i1IIi * IiII / OoooooooOO - Oo0Ooo / i11iIiiIii
   if 28 - 28: iIii1I11I1II1 % OOooOOo * I1IiiI
   if 28 - 28: O0 . OoOoOO00
   if 27 - 27: I1ii11iIi11i / II111iiii + O0 % I1ii11iIi11i
  lisp_send_negative_map_reply ( lisp_sockets , ooOOoo0 , IIi1iiIII11 , Iii11I , o00O00oOO00 ,
 mr_sport , oOoooOOO0o0 , I1II , Ooo )
  if 72 - 72: I1IiiI - i1IIi
  return ( [ ooOOoo0 , IIi1iiIII11 , LISP_DDT_ACTION_MS_NOT_REG ] )
  if 11 - 11: iIii1I11I1II1 . OoO0O00 * Ii1I
  if 65 - 65: Oo0Ooo / OoooooooOO
  if 60 - 60: II111iiii + I1IiiI % oO0o - o0oOOo0O0Ooo
  if 50 - 50: iIii1I11I1II1 - i11iIiiIii / iII111i + ooOoO0o / OOooOOo
  if 80 - 80: IiII / OoooooooOO
 oO0ooo = False
 Ii1 = ""
 oO0Oooo = False
 if ( o0o000 . force_nat_proxy_reply ) :
  Ii1 = ", nat-forced"
  oO0ooo = True
  oO0Oooo = True
 elif ( o0o000 . force_proxy_reply ) :
  Ii1 = ", forced"
  oO0Oooo = True
 elif ( o0o000 . proxy_reply_requested ) :
  Ii1 = ", requested"
  oO0Oooo = True
 elif ( map_request . pitr_bit and o0o000 . pitr_proxy_reply_drop ) :
  Ii1 = ", drop-to-pitr"
  I11I1iI = LISP_DROP_ACTION
 elif ( o0o000 . proxy_reply_action != "" ) :
  I11I1iI = o0o000 . proxy_reply_action
  Ii1 = ", forced, action {}" . format ( I11I1iI )
  I11I1iI = LISP_DROP_ACTION if ( I11I1iI == "drop" ) else LISP_NATIVE_FORWARD_ACTION
  if 82 - 82: II111iiii
  if 42 - 42: I1ii11iIi11i % i11iIiiIii . iII111i
  if 60 - 60: I1Ii111 % IiII - iIii1I11I1II1
  if 86 - 86: I1Ii111
  if 60 - 60: I1IiiI . iII111i + O0 / iIii1I11I1II1 - I1Ii111
  if 32 - 32: ooOoO0o
  if 9 - 9: I1Ii111
 oo0OO000OooO0 = False
 IiiIIIII = None
 if ( oO0Oooo and lisp_policies . has_key ( o0o000 . policy ) ) :
  oo00ooOOOo0O = lisp_policies [ o0o000 . policy ]
  if ( oo00ooOOOo0O . match_policy_map_request ( map_request , mr_source ) ) : IiiIIIII = oo00ooOOOo0O
  if 97 - 97: i11iIiiIii / O0 . iII111i . iIii1I11I1II1
  if ( IiiIIIII ) :
   O0oo0000o = bold ( "matched" , False )
   lprint ( "Map-Request {} policy '{}', set-action '{}'" . format ( O0oo0000o ,
 oo00ooOOOo0O . policy_name , oo00ooOOOo0O . set_action ) )
  else :
   O0oo0000o = bold ( "no match" , False )
   lprint ( "Map-Request {} for policy '{}', implied drop" . format ( O0oo0000o ,
 oo00ooOOOo0O . policy_name ) )
   oo0OO000OooO0 = True
   if 40 - 40: OoOoOO00 / iII111i / O0 * ooOoO0o
   if 58 - 58: iII111i % I11i
   if 71 - 71: I1IiiI + OoO0O00 + IiII * I11i
 if ( Ii1 != "" ) :
  lprint ( "Proxy-replying for EID {}, found site '{}' EID-prefix {}{}" . format ( green ( I11i11i1 , False ) , i11I11iiiI1 , green ( iIIiIIiII111 , False ) ,
  # i1IIi / OoOoOO00 + OOooOOo - oO0o
 Ii1 ) )
  if 54 - 54: OoO0O00 + I11i + Oo0Ooo . II111iiii / OOooOOo
  OoO0oOOooOO = o0o000 . registered_rlocs
  oOoooOOO0o0 = 1440
  if ( oO0ooo ) :
   if ( o0o000 . site_id != 0 ) :
    i1I1I = map_request . source_eid
    OoO0oOOooOO = lisp_get_private_rloc_set ( o0o000 , i1I1I , IIi1iiIII11 )
    if 81 - 81: o0oOOo0O0Ooo * oO0o % ooOoO0o - i11iIiiIii + oO0o
   if ( OoO0oOOooOO == o0o000 . registered_rlocs ) :
    i1iI11i = ( o0o000 . group . is_null ( ) == False )
    iioo00oOOO00 = lisp_get_partial_rloc_set ( OoO0oOOooOO , IIII , i1iI11i )
    if ( iioo00oOOO00 != OoO0oOOooOO ) :
     oOoooOOO0o0 = 15
     OoO0oOOooOO = iioo00oOOO00
     if 9 - 9: OOooOOo + Oo0Ooo
     if 84 - 84: i11iIiiIii . Ii1I
     if 86 - 86: o0oOOo0O0Ooo / oO0o * i1IIi
     if 41 - 41: II111iiii . i1IIi
     if 78 - 78: I1IiiI * I11i % OOooOOo + Ii1I + OoOoOO00
     if 23 - 23: iII111i / Oo0Ooo % OoooooooOO * OoooooooOO . iII111i / I1ii11iIi11i
     if 30 - 30: oO0o - OoOoOO00 . I1IiiI
     if 17 - 17: OoOoOO00
  if ( o0o000 . force_ttl != None ) :
   oOoooOOO0o0 = o0o000 . force_ttl | 0x80000000
   if 76 - 76: I1ii11iIi11i - ooOoO0o % OoooooooOO / Oo0Ooo % IiII / ooOoO0o
   if 57 - 57: O0
   if 23 - 23: OoO0O00 / II111iiii . I1ii11iIi11i . O0
   if 13 - 13: I1ii11iIi11i
   if 32 - 32: OOooOOo / I11i + I1Ii111 / Oo0Ooo * OoooooooOO / II111iiii
   if 8 - 8: OoO0O00
  if ( IiiIIIII ) :
   if ( IiiIIIII . set_record_ttl ) :
    oOoooOOO0o0 = IiiIIIII . set_record_ttl
    lprint ( "Policy set-record-ttl to {}" . format ( oOoooOOO0o0 ) )
    if 17 - 17: iIii1I11I1II1 - Oo0Ooo
   if ( IiiIIIII . set_action == "drop" ) :
    lprint ( "Policy set-action drop, send negative Map-Reply" )
    I11I1iI = LISP_POLICY_DENIED_ACTION
    OoO0oOOooOO = [ ]
   else :
    I1IIiIIIii = IiiIIIII . set_policy_map_reply ( )
    if ( I1IIiIIIii ) : OoO0oOOooOO = [ I1IIiIIIii ]
    if 25 - 25: O0 + I1ii11iIi11i
    if 53 - 53: OoooooooOO . Oo0Ooo
    if 35 - 35: OOooOOo % i11iIiiIii % ooOoO0o . O0
  if ( oo0OO000OooO0 ) :
   lprint ( "Implied drop action, send negative Map-Reply" )
   I11I1iI = LISP_POLICY_DENIED_ACTION
   OoO0oOOooOO = [ ]
   if 9 - 9: ooOoO0o + iII111i / i1IIi % Oo0Ooo - o0oOOo0O0Ooo / I1IiiI
   if 42 - 42: OOooOOo + oO0o % O0 * I1ii11iIi11i + i11iIiiIii
  i11 = o0o000 . echo_nonce_capable
  if 16 - 16: i1IIi . I11i + OoO0O00 % Ii1I * IiII + I1IiiI
  if 96 - 96: II111iiii + O0 - II111iiii
  if 97 - 97: I1IiiI
  if 87 - 87: I11i + iIii1I11I1II1
  if ( III ) :
   oOOooO0oo = o0o000 . eid
   O00o = o0o000 . group
  else :
   oOOooO0oo = ooOOoo0
   O00o = IIi1iiIII11
   I11I1iI = LISP_AUTH_FAILURE_ACTION
   OoO0oOOooOO = [ ]
   if 66 - 66: i11iIiiIii % i11iIiiIii
   if 38 - 38: iIii1I11I1II1
   if 80 - 80: OoO0O00
   if 72 - 72: I11i * II111iiii
   if 82 - 82: I1Ii111 . OoO0O00 * II111iiii
   if 99 - 99: iIii1I11I1II1 / iII111i % i1IIi - II111iiii / OoO0O00
  packet = lisp_build_map_reply ( oOOooO0oo , O00o , OoO0oOOooOO ,
 Iii11I , I11I1iI , oOoooOOO0o0 , map_request , None , i11 , False )
  if 33 - 33: OoooooooOO / i1IIi . Ii1I
  if ( Ooo ) :
   lisp_process_pubsub ( lisp_sockets , packet , oOOooO0oo , o00O00oOO00 ,
 mr_sport , Iii11I , oOoooOOO0o0 , I1II )
  else :
   lisp_send_map_reply ( lisp_sockets , packet , o00O00oOO00 , mr_sport )
   if 96 - 96: OoOoOO00 / Oo0Ooo . II111iiii / ooOoO0o
   if 56 - 56: IiII - ooOoO0o % oO0o / Oo0Ooo * oO0o % O0
  return ( [ o0o000 . eid , o0o000 . group , LISP_DDT_ACTION_MS_ACK ] )
  if 71 - 71: iII111i / II111iiii - II111iiii / I1IiiI
  if 24 - 24: O0 . I1IiiI + IiII . IiII
  if 53 - 53: II111iiii + Ii1I * o0oOOo0O0Ooo
  if 47 - 47: Ii1I % OOooOOo . Oo0Ooo
  if 94 - 94: Ii1I - iIii1I11I1II1 + I1IiiI - iIii1I11I1II1 . o0oOOo0O0Ooo
 iI11i = len ( o0o000 . registered_rlocs )
 if ( iI11i == 0 ) :
  lprint ( "Requested EID {} found site '{}' with EID-prefix {} with " + "no registered RLOCs" . format ( green ( I11i11i1 , False ) , i11I11iiiI1 ,
  # Ii1I
 green ( iIIiIIiII111 , False ) ) )
  return ( [ o0o000 . eid , o0o000 . group , LISP_DDT_ACTION_MS_ACK ] )
  if 31 - 31: OoOoOO00
  if 72 - 72: II111iiii + i11iIiiIii * OoO0O00 / II111iiii / I11i
  if 59 - 59: OOooOOo
  if 9 - 9: I1IiiI + I1IiiI / I11i - OOooOOo % iIii1I11I1II1 / I1ii11iIi11i
  if 40 - 40: I1Ii111 - OOooOOo * IiII + o0oOOo0O0Ooo - I1IiiI
 o00oO = map_request . target_eid if map_request . source_eid . is_null ( ) else map_request . source_eid
 if 56 - 56: i11iIiiIii / I1Ii111 / II111iiii / oO0o
 IIi1iiIIi1i = map_request . target_eid . hash_address ( o00oO )
 IIi1iiIIi1i %= iI11i
 I1i1i = o0o000 . registered_rlocs [ IIi1iiIIi1i ]
 if 59 - 59: iIii1I11I1II1 / I1Ii111 * o0oOOo0O0Ooo
 if ( I1i1i . rloc . is_null ( ) ) :
  lprint ( ( "Suppress forwarding Map-Request for EID {} at site '{}' " + "EID-prefix {}, no RLOC address" ) . format ( green ( I11i11i1 , False ) ,
  # O0 - I1Ii111 . oO0o
 i11I11iiiI1 , green ( iIIiIIiII111 , False ) ) )
 else :
  lprint ( ( "Forwarding Map-Request for EID {} to ETR {} at site '{}' " + "EID-prefix {}" ) . format ( green ( I11i11i1 , False ) ,
  # iII111i - I1ii11iIi11i * Ii1I
 red ( I1i1i . rloc . print_address ( ) , False ) , i11I11iiiI1 ,
 green ( iIIiIIiII111 , False ) ) )
  if 88 - 88: o0oOOo0O0Ooo - iII111i - ooOoO0o - I11i
  if 9 - 9: I1IiiI / O0 + I11i
  if 39 - 39: OoooooooOO * I1ii11iIi11i + II111iiii . I1Ii111 / II111iiii . I1ii11iIi11i
  if 72 - 72: OoOoOO00
  lisp_send_ecm ( lisp_sockets , packet , map_request . source_eid , mr_sport ,
 map_request . target_eid , I1i1i . rloc , to_etr = True )
  if 21 - 21: oO0o
 return ( [ o0o000 . eid , o0o000 . group , LISP_DDT_ACTION_MS_ACK ] )
 if 58 - 58: OoOoOO00 + i11iIiiIii % OOooOOo - i1IIi
 if 39 - 39: OoooooooOO . I1IiiI + OoOoOO00
 if 65 - 65: Oo0Ooo + OoooooooOO % oO0o
 if 31 - 31: Ii1I
 if 88 - 88: i1IIi % OoOoOO00 % Ii1I . o0oOOo0O0Ooo / I1IiiI % OOooOOo
 if 39 - 39: OOooOOo / I1IiiI / iIii1I11I1II1 + Ii1I - i11iIiiIii
 if 25 - 25: iII111i . OOooOOo * I1IiiI % OoO0O00 - O0 . I1IiiI
def lisp_ddt_process_map_request ( lisp_sockets , map_request , ecm_source , port ) :
 if 92 - 92: I11i * I1Ii111 . O0 - oO0o + i1IIi % Oo0Ooo
 if 39 - 39: I1Ii111 - I1IiiI
 if 18 - 18: i1IIi
 if 42 - 42: II111iiii - i1IIi . oO0o % OOooOOo % ooOoO0o - i11iIiiIii
 ooOOoo0 = map_request . target_eid
 IIi1iiIII11 = map_request . target_group
 I11i11i1 = lisp_print_eid_tuple ( ooOOoo0 , IIi1iiIII11 )
 Iii11I = map_request . nonce
 I11I1iI = LISP_DDT_ACTION_NULL
 if 23 - 23: OOooOOo + iIii1I11I1II1 - i1IIi
 if 72 - 72: OOooOOo . I1IiiI * O0 + i11iIiiIii - iII111i
 if 79 - 79: o0oOOo0O0Ooo + I1ii11iIi11i
 if 46 - 46: I11i
 if 78 - 78: IiII / II111iiii
 o0OOO0 = None
 if ( lisp_i_am_ms ) :
  o0o000 = lisp_site_eid_lookup ( ooOOoo0 , IIi1iiIII11 , False )
  if ( o0o000 == None ) : return
  if 91 - 91: iIii1I11I1II1 . OoO0O00 - I1ii11iIi11i + I11i / Oo0Ooo + OoO0O00
  if ( o0o000 . registered ) :
   I11I1iI = LISP_DDT_ACTION_MS_ACK
   oOoooOOO0o0 = 1440
  else :
   ooOOoo0 , IIi1iiIII11 , I11I1iI = lisp_ms_compute_neg_prefix ( ooOOoo0 , IIi1iiIII11 )
   I11I1iI = LISP_DDT_ACTION_MS_NOT_REG
   oOoooOOO0o0 = 1
   if 35 - 35: ooOoO0o * iII111i % iII111i + OOooOOo
 else :
  o0OOO0 = lisp_ddt_cache_lookup ( ooOOoo0 , IIi1iiIII11 , False )
  if ( o0OOO0 == None ) :
   I11I1iI = LISP_DDT_ACTION_NOT_AUTH
   oOoooOOO0o0 = 0
   lprint ( "DDT delegation entry not found for EID {}" . format ( green ( I11i11i1 , False ) ) )
   if 66 - 66: iII111i - ooOoO0o * I1ii11iIi11i - Ii1I / OoooooooOO
  elif ( o0OOO0 . is_auth_prefix ( ) ) :
   if 86 - 86: I1IiiI % iII111i + Oo0Ooo + i1IIi % o0oOOo0O0Ooo
   if 85 - 85: Ii1I + I1Ii111 * I11i
   if 59 - 59: Oo0Ooo
   if 35 - 35: OoooooooOO + I1ii11iIi11i * OOooOOo
   I11I1iI = LISP_DDT_ACTION_DELEGATION_HOLE
   oOoooOOO0o0 = 15
   O00Ooo0oOoOOo = o0OOO0 . print_eid_tuple ( )
   lprint ( ( "DDT delegation entry not found but auth-prefix {} " + "found for EID {}" ) . format ( O00Ooo0oOoOOo ,
   # o0oOOo0O0Ooo . o0oOOo0O0Ooo
 green ( I11i11i1 , False ) ) )
   if 100 - 100: iIii1I11I1II1 . I1Ii111 * I1Ii111
   if ( IIi1iiIII11 . is_null ( ) ) :
    ooOOoo0 = lisp_ddt_compute_neg_prefix ( ooOOoo0 , o0OOO0 ,
 lisp_ddt_cache )
   else :
    IIi1iiIII11 = lisp_ddt_compute_neg_prefix ( IIi1iiIII11 , o0OOO0 ,
 lisp_ddt_cache )
    ooOOoo0 = lisp_ddt_compute_neg_prefix ( ooOOoo0 , o0OOO0 ,
 o0OOO0 . source_cache )
    if 72 - 72: I1Ii111 - Ii1I . OoO0O00 - IiII
   o0OOO0 = None
  else :
   O00Ooo0oOoOOo = o0OOO0 . print_eid_tuple ( )
   lprint ( "DDT delegation entry {} found for EID {}" . format ( O00Ooo0oOoOOo , green ( I11i11i1 , False ) ) )
   if 43 - 43: i11iIiiIii . oO0o
   oOoooOOO0o0 = 1440
   if 23 - 23: ooOoO0o - OoO0O00 + oO0o . OOooOOo - I1IiiI
   if 66 - 66: iII111i % iII111i
   if 59 - 59: II111iiii . i1IIi % i1IIi
   if 40 - 40: I1Ii111 . II111iiii * o0oOOo0O0Ooo + I11i - i1IIi
   if 67 - 67: o0oOOo0O0Ooo - O0 - i1IIi . ooOoO0o . iII111i
   if 43 - 43: II111iiii . o0oOOo0O0Ooo + i11iIiiIii . O0 / O0 . II111iiii
 IiiiIi1iiii11 = lisp_build_map_referral ( ooOOoo0 , IIi1iiIII11 , o0OOO0 , I11I1iI , oOoooOOO0o0 , Iii11I )
 Iii11I = map_request . nonce >> 32
 if ( map_request . nonce != 0 and Iii11I != 0xdfdf0e1d ) : port = LISP_CTRL_PORT
 lisp_send_map_referral ( lisp_sockets , IiiiIi1iiii11 , ecm_source , port )
 return
 if 13 - 13: Ii1I % i11iIiiIii
 if 3 - 3: ooOoO0o % OoOoOO00 * I1Ii111 - OoO0O00 / i1IIi % I1IiiI
 if 50 - 50: I1ii11iIi11i + iII111i
 if 64 - 64: oO0o
 if 11 - 11: o0oOOo0O0Ooo
 if 95 - 95: i1IIi . ooOoO0o . Oo0Ooo
 if 13 - 13: OOooOOo - Oo0Ooo % O0 . I1Ii111
 if 66 - 66: I1IiiI + I11i
 if 58 - 58: I1ii11iIi11i
 if 7 - 7: oO0o - I11i
 if 59 - 59: Ii1I / o0oOOo0O0Ooo / OoO0O00 + IiII + i11iIiiIii
 if 64 - 64: o0oOOo0O0Ooo * IiII * IiII * iII111i % i11iIiiIii
 if 22 - 22: I1ii11iIi11i * II111iiii - OOooOOo % i11iIiiIii
def lisp_find_negative_mask_len ( eid , entry_prefix , neg_prefix ) :
 i1IiOoOOO0O = eid . hash_address ( entry_prefix )
 iiI1I = eid . addr_length ( ) * 8
 OO00O = 0
 if 6 - 6: iII111i + I1ii11iIi11i + ooOoO0o
 if 79 - 79: oO0o - IiII % OoooooooOO . ooOoO0o * I1IiiI
 if 44 - 44: o0oOOo0O0Ooo
 if 76 - 76: i11iIiiIii % OoO0O00
 for OO00O in range ( iiI1I ) :
  iIIiIIi = 1 << ( iiI1I - OO00O - 1 )
  if ( i1IiOoOOO0O & iIIiIIi ) : break
  if 33 - 33: OoooooooOO + I1ii11iIi11i + I1Ii111 + O0 % I11i
  if 32 - 32: Oo0Ooo % ooOoO0o % II111iiii
 if ( OO00O > neg_prefix . mask_len ) : neg_prefix . mask_len = OO00O
 return
 if 82 - 82: ooOoO0o - I11i / I1Ii111 - i11iIiiIii - iIii1I11I1II1
 if 53 - 53: iIii1I11I1II1 % I11i . i1IIi + IiII / OoOoOO00 . II111iiii
 if 43 - 43: O0 - IiII + i11iIiiIii * i1IIi - ooOoO0o % IiII
 if 23 - 23: OoooooooOO % o0oOOo0O0Ooo + OoO0O00
 if 25 - 25: IiII % OOooOOo + Ii1I * I1ii11iIi11i
 if 25 - 25: iIii1I11I1II1 * OoOoOO00 % I1IiiI + IiII
 if 34 - 34: ooOoO0o - OoooooooOO . o0oOOo0O0Ooo
 if 83 - 83: II111iiii . OOooOOo
 if 88 - 88: O0
 if 12 - 12: Ii1I % OOooOOo % Oo0Ooo * I1Ii111
def lisp_neg_prefix_walk ( entry , parms ) :
 ooOOoo0 , o000Oo0 , I111Ii1 = parms
 if 19 - 19: oO0o
 if ( o000Oo0 == None ) :
  if ( entry . eid . instance_id != ooOOoo0 . instance_id ) :
   return ( [ True , parms ] )
   if 18 - 18: Ii1I / OoooooooOO % i1IIi * o0oOOo0O0Ooo
  if ( entry . eid . afi != ooOOoo0 . afi ) : return ( [ True , parms ] )
 else :
  if ( entry . eid . is_more_specific ( o000Oo0 ) == False ) :
   return ( [ True , parms ] )
   if 70 - 70: IiII % i1IIi / IiII - o0oOOo0O0Ooo . Oo0Ooo / O0
   if 54 - 54: o0oOOo0O0Ooo
   if 53 - 53: II111iiii / IiII . i1IIi + I1Ii111 / OoO0O00 - OoooooooOO
   if 67 - 67: ooOoO0o . Ii1I - Oo0Ooo * iII111i . I11i - OOooOOo
   if 10 - 10: I11i
   if 37 - 37: o0oOOo0O0Ooo / I1IiiI * oO0o / II111iiii
 lisp_find_negative_mask_len ( ooOOoo0 , entry . eid , I111Ii1 )
 return ( [ True , parms ] )
 if 39 - 39: IiII - i1IIi - IiII - OoooooooOO - I1ii11iIi11i
 if 66 - 66: IiII + i1IIi
 if 21 - 21: IiII / i11iIiiIii / OoOoOO00
 if 75 - 75: Ii1I . i1IIi / I1IiiI * iII111i . IiII / OoOoOO00
 if 58 - 58: ooOoO0o + OOooOOo / ooOoO0o / i11iIiiIii
 if 95 - 95: ooOoO0o
 if 10 - 10: OoO0O00 % ooOoO0o * o0oOOo0O0Ooo
 if 37 - 37: Ii1I . o0oOOo0O0Ooo
def lisp_ddt_compute_neg_prefix ( eid , ddt_entry , cache ) :
 if 34 - 34: ooOoO0o * IiII . Ii1I + iIii1I11I1II1
 if 1 - 1: i11iIiiIii + I11i
 if 78 - 78: Ii1I % Oo0Ooo / OoO0O00 . iIii1I11I1II1 . II111iiii
 if 67 - 67: oO0o % I1Ii111
 if ( eid . is_binary ( ) == False ) : return ( eid )
 if 72 - 72: I1IiiI . i11iIiiIii . OoOoOO00 + I1IiiI - I1Ii111 + iII111i
 I111Ii1 = lisp_address ( eid . afi , "" , 0 , 0 )
 I111Ii1 . copy_address ( eid )
 I111Ii1 . mask_len = 0
 if 15 - 15: I1IiiI
 O00OO = ddt_entry . print_eid_tuple ( )
 o000Oo0 = ddt_entry . eid
 if 75 - 75: O0 . I1Ii111 . Ii1I % Oo0Ooo - OOooOOo / i11iIiiIii
 if 35 - 35: OoO0O00 . II111iiii + I1Ii111 + Ii1I - O0 + OoOoOO00
 if 77 - 77: O0 % Ii1I - I1ii11iIi11i
 if 17 - 17: OoooooooOO - OoooooooOO % I1Ii111 * Ii1I . OoooooooOO
 if 51 - 51: iIii1I11I1II1 % IiII * iIii1I11I1II1 - OoO0O00 % I1IiiI + i11iIiiIii
 eid , o000Oo0 , I111Ii1 = cache . walk_cache ( lisp_neg_prefix_walk ,
 ( eid , o000Oo0 , I111Ii1 ) )
 if 33 - 33: I11i
 if 99 - 99: I11i
 if 61 - 61: i1IIi - i1IIi
 if 97 - 97: I11i + II111iiii / OoooooooOO + I1ii11iIi11i * o0oOOo0O0Ooo
 I111Ii1 . mask_address ( I111Ii1 . mask_len )
 if 29 - 29: I1Ii111
 lprint ( ( "Least specific prefix computed from ddt-cache for EID {} " + "using auth-prefix {} is {}" ) . format ( green ( eid . print_address ( ) , False ) ,
 # iII111i * Oo0Ooo + I1ii11iIi11i / OoooooooOO - Ii1I % I11i
 O00OO , I111Ii1 . print_prefix ( ) ) )
 return ( I111Ii1 )
 if 2 - 2: OoO0O00 . II111iiii
 if 10 - 10: iII111i - i11iIiiIii - i11iIiiIii / ooOoO0o
 if 76 - 76: IiII % OOooOOo
 if 34 - 34: I1IiiI
 if 56 - 56: OoooooooOO + O0 . II111iiii / i1IIi - O0 . iIii1I11I1II1
 if 94 - 94: i1IIi . Oo0Ooo / o0oOOo0O0Ooo % I1Ii111 / OOooOOo + OoOoOO00
 if 21 - 21: Oo0Ooo / Oo0Ooo
 if 1 - 1: Oo0Ooo
def lisp_ms_compute_neg_prefix ( eid , group ) :
 I111Ii1 = lisp_address ( eid . afi , "" , 0 , 0 )
 I111Ii1 . copy_address ( eid )
 I111Ii1 . mask_len = 0
 O0ooOOoOoOO0 = lisp_address ( group . afi , "" , 0 , 0 )
 O0ooOOoOoOO0 . copy_address ( group )
 O0ooOOoOoOO0 . mask_len = 0
 o000Oo0 = None
 if 80 - 80: II111iiii - I1ii11iIi11i / iIii1I11I1II1 % Oo0Ooo . Ii1I
 if 33 - 33: OOooOOo + I1ii11iIi11i + I1Ii111 * I11i / OoO0O00 + o0oOOo0O0Ooo
 if 46 - 46: iII111i
 if 56 - 56: Oo0Ooo / II111iiii
 if 61 - 61: Ii1I - i1IIi / ooOoO0o - Oo0Ooo / IiII % Oo0Ooo
 if ( group . is_null ( ) ) :
  o0OOO0 = lisp_ddt_cache . lookup_cache ( eid , False )
  if ( o0OOO0 == None ) :
   I111Ii1 . mask_len = I111Ii1 . host_mask_len ( )
   O0ooOOoOoOO0 . mask_len = O0ooOOoOoOO0 . host_mask_len ( )
   return ( [ I111Ii1 , O0ooOOoOoOO0 , LISP_DDT_ACTION_NOT_AUTH ] )
   if 53 - 53: OoooooooOO + iII111i % II111iiii * IiII
  iI1Ii1i1IIi = lisp_sites_by_eid
  if ( o0OOO0 . is_auth_prefix ( ) ) : o000Oo0 = o0OOO0 . eid
 else :
  o0OOO0 = lisp_ddt_cache . lookup_cache ( group , False )
  if ( o0OOO0 == None ) :
   I111Ii1 . mask_len = I111Ii1 . host_mask_len ( )
   O0ooOOoOoOO0 . mask_len = O0ooOOoOoOO0 . host_mask_len ( )
   return ( [ I111Ii1 , O0ooOOoOoOO0 , LISP_DDT_ACTION_NOT_AUTH ] )
   if 59 - 59: OoO0O00 - oO0o - Ii1I + ooOoO0o
  if ( o0OOO0 . is_auth_prefix ( ) ) : o000Oo0 = o0OOO0 . group
  if 34 - 34: oO0o + I1Ii111 . OOooOOo
  group , o000Oo0 , O0ooOOoOoOO0 = lisp_sites_by_eid . walk_cache ( lisp_neg_prefix_walk , ( group , o000Oo0 , O0ooOOoOoOO0 ) )
  if 78 - 78: i1IIi + IiII
  if 55 - 55: I1Ii111 - I11i - iIii1I11I1II1 / ooOoO0o % oO0o / II111iiii
  O0ooOOoOoOO0 . mask_address ( O0ooOOoOoOO0 . mask_len )
  if 22 - 22: OoooooooOO % OOooOOo . OOooOOo
  lprint ( ( "Least specific prefix computed from site-cache for " + "group EID {} using auth-prefix {} is {}" ) . format ( group . print_address ( ) , o000Oo0 . print_prefix ( ) if ( o000Oo0 != None ) else "'not found'" ,
  # iII111i - OoO0O00 % I1ii11iIi11i * Oo0Ooo
  # OoO0O00 / O0 / o0oOOo0O0Ooo . I1IiiI
  # OoO0O00 * iIii1I11I1II1 * I1IiiI . OoooooooOO + I1ii11iIi11i % iIii1I11I1II1
 O0ooOOoOoOO0 . print_prefix ( ) ) )
  if 78 - 78: OoOoOO00 . oO0o - Oo0Ooo - II111iiii - I1ii11iIi11i * oO0o
  iI1Ii1i1IIi = o0OOO0 . source_cache
  if 41 - 41: I11i / ooOoO0o + IiII % OoooooooOO
  if 72 - 72: Ii1I
  if 22 - 22: o0oOOo0O0Ooo / OoO0O00 + OoOoOO00 + Ii1I . II111iiii * I11i
  if 85 - 85: i11iIiiIii / I11i
  if 28 - 28: i11iIiiIii + IiII / I11i . Ii1I / OoO0O00
 I11I1iI = LISP_DDT_ACTION_DELEGATION_HOLE if ( o000Oo0 != None ) else LISP_DDT_ACTION_NOT_AUTH
 if 100 - 100: o0oOOo0O0Ooo - I11i . o0oOOo0O0Ooo
 if 90 - 90: OoOoOO00 / II111iiii / I11i * I11i - iIii1I11I1II1
 if 87 - 87: IiII
 if 92 - 92: OoO0O00 / IiII - ooOoO0o
 if 45 - 45: iII111i - I11i * ooOoO0o * OOooOOo / I1Ii111 * iII111i
 if 33 - 33: iIii1I11I1II1 % I1ii11iIi11i - OOooOOo % iIii1I11I1II1 + I11i / i11iIiiIii
 eid , o000Oo0 , I111Ii1 = iI1Ii1i1IIi . walk_cache ( lisp_neg_prefix_walk ,
 ( eid , o000Oo0 , I111Ii1 ) )
 if 64 - 64: I11i * ooOoO0o / OoooooooOO
 if 38 - 38: iIii1I11I1II1 . OoO0O00 * OoOoOO00 + OoOoOO00 + ooOoO0o
 if 44 - 44: I1ii11iIi11i * OOooOOo % OoO0O00 . I1IiiI % Ii1I + II111iiii
 if 100 - 100: oO0o - II111iiii . o0oOOo0O0Ooo
 I111Ii1 . mask_address ( I111Ii1 . mask_len )
 if 63 - 63: OoOoOO00 % IiII . iII111i
 lprint ( ( "Least specific prefix computed from site-cache for EID {} " + "using auth-prefix {} is {}" ) . format ( green ( eid . print_address ( ) , False ) ,
 # I1IiiI . O0 / oO0o
 # I1IiiI - OoO0O00 / iIii1I11I1II1 * iII111i + OoOoOO00 + IiII
 o000Oo0 . print_prefix ( ) if ( o000Oo0 != None ) else "'not found'" , I111Ii1 . print_prefix ( ) ) )
 if 16 - 16: OoO0O00 % OOooOOo . I11i . I11i
 if 4 - 4: O0 + I11i / OoOoOO00 * iIii1I11I1II1 . Ii1I
 return ( [ I111Ii1 , O0ooOOoOoOO0 , I11I1iI ] )
 if 68 - 68: Oo0Ooo % ooOoO0o + i11iIiiIii / oO0o / II111iiii
 if 63 - 63: OoO0O00 % i1IIi - OoooooooOO / ooOoO0o
 if 75 - 75: OOooOOo + IiII + ooOoO0o / I1IiiI . iIii1I11I1II1 / Oo0Ooo
 if 81 - 81: I1Ii111 % II111iiii - Oo0Ooo / I1IiiI + i11iIiiIii . I11i
 if 67 - 67: ooOoO0o . I1Ii111 . Oo0Ooo . Ii1I + iIii1I11I1II1 / OoooooooOO
 if 93 - 93: ooOoO0o * OoO0O00 - I1Ii111 / I1ii11iIi11i
 if 60 - 60: OoO0O00 / oO0o . I1IiiI + OoOoOO00 + I1ii11iIi11i % Ii1I
 if 70 - 70: i1IIi * II111iiii * I1IiiI
def lisp_ms_send_map_referral ( lisp_sockets , map_request , ecm_source , port ,
 action , eid_prefix , group_prefix ) :
 if 7 - 7: OoooooooOO + II111iiii % o0oOOo0O0Ooo * O0 . OoO0O00 * OoooooooOO
 ooOOoo0 = map_request . target_eid
 IIi1iiIII11 = map_request . target_group
 Iii11I = map_request . nonce
 if 20 - 20: Oo0Ooo % OOooOOo
 if ( action == LISP_DDT_ACTION_MS_ACK ) : oOoooOOO0o0 = 1440
 if 8 - 8: OOooOOo
 if 92 - 92: iII111i / OOooOOo . IiII / I11i + o0oOOo0O0Ooo
 if 99 - 99: II111iiii
 if 70 - 70: O0 % I1ii11iIi11i
 iiII1IiIi1i = lisp_map_referral ( )
 iiII1IiIi1i . record_count = 1
 iiII1IiIi1i . nonce = Iii11I
 IiiiIi1iiii11 = iiII1IiIi1i . encode ( )
 iiII1IiIi1i . print_map_referral ( )
 if 28 - 28: IiII - i1IIi - I1Ii111 % Ii1I - IiII
 O0II = False
 if 73 - 73: iIii1I11I1II1 . iIii1I11I1II1 + oO0o % i11iIiiIii . IiII
 if 33 - 33: IiII - OOooOOo / i11iIiiIii * iIii1I11I1II1
 if 2 - 2: i11iIiiIii % ooOoO0o
 if 56 - 56: IiII % ooOoO0o + I1IiiI % I11i - OOooOOo
 if 82 - 82: OoooooooOO . i1IIi . OoO0O00 . OoO0O00
 if 31 - 31: iIii1I11I1II1
 if ( action == LISP_DDT_ACTION_SITE_NOT_FOUND ) :
  eid_prefix , group_prefix , action = lisp_ms_compute_neg_prefix ( ooOOoo0 ,
 IIi1iiIII11 )
  oOoooOOO0o0 = 15
  if 64 - 64: ooOoO0o
 if ( action == LISP_DDT_ACTION_MS_NOT_REG ) : oOoooOOO0o0 = 1
 if ( action == LISP_DDT_ACTION_MS_ACK ) : oOoooOOO0o0 = 1440
 if ( action == LISP_DDT_ACTION_DELEGATION_HOLE ) : oOoooOOO0o0 = 15
 if ( action == LISP_DDT_ACTION_NOT_AUTH ) : oOoooOOO0o0 = 0
 if 30 - 30: OoO0O00 + o0oOOo0O0Ooo / iIii1I11I1II1
 O0OoO0O0 = False
 iI11i = 0
 o0OOO0 = lisp_ddt_cache_lookup ( ooOOoo0 , IIi1iiIII11 , False )
 if ( o0OOO0 != None ) :
  iI11i = len ( o0OOO0 . delegation_set )
  O0OoO0O0 = o0OOO0 . is_ms_peer_entry ( )
  o0OOO0 . map_referrals_sent += 1
  if 79 - 79: I11i * I1ii11iIi11i
  if 85 - 85: iIii1I11I1II1 * O0 / iII111i
  if 75 - 75: Oo0Ooo * IiII % Ii1I
  if 40 - 40: o0oOOo0O0Ooo * i11iIiiIii . ooOoO0o
  if 63 - 63: I1Ii111 / Ii1I - iIii1I11I1II1 / i11iIiiIii / IiII + I11i
 if ( action == LISP_DDT_ACTION_NOT_AUTH ) : O0II = True
 if ( action in ( LISP_DDT_ACTION_MS_REFERRAL , LISP_DDT_ACTION_MS_ACK ) ) :
  O0II = ( O0OoO0O0 == False )
  if 57 - 57: iIii1I11I1II1 % iIii1I11I1II1
  if 23 - 23: II111iiii . ooOoO0o % I1Ii111
  if 39 - 39: OoooooooOO
  if 10 - 10: Oo0Ooo * iII111i
  if 78 - 78: Oo0Ooo / i11iIiiIii - I1IiiI
 i111iII = lisp_eid_record ( )
 i111iII . rloc_count = iI11i
 i111iII . authoritative = True
 i111iII . action = action
 i111iII . ddt_incomplete = O0II
 i111iII . eid = eid_prefix
 i111iII . group = group_prefix
 i111iII . record_ttl = oOoooOOO0o0
 if 51 - 51: ooOoO0o / Oo0Ooo - I1Ii111 - iII111i
 IiiiIi1iiii11 += i111iII . encode ( )
 i111iII . print_record ( "  " , True )
 if 68 - 68: I1ii11iIi11i - iIii1I11I1II1 * OoooooooOO
 if 44 - 44: OoooooooOO + I1Ii111 + OoO0O00
 if 15 - 15: iIii1I11I1II1 % i1IIi + iII111i
 if 48 - 48: o0oOOo0O0Ooo / oO0o
 if ( iI11i != 0 ) :
  for I1IooOoo00 in o0OOO0 . delegation_set :
   I1Ii11iI = lisp_rloc_record ( )
   I1Ii11iI . rloc = I1IooOoo00 . delegate_address
   I1Ii11iI . priority = I1IooOoo00 . priority
   I1Ii11iI . weight = I1IooOoo00 . weight
   I1Ii11iI . mpriority = 255
   I1Ii11iI . mweight = 0
   I1Ii11iI . reach_bit = True
   IiiiIi1iiii11 += I1Ii11iI . encode ( )
   I1Ii11iI . print_record ( "    " )
   if 61 - 61: I1IiiI + iII111i * Ii1I % I1Ii111 . Ii1I
   if 83 - 83: i11iIiiIii * OoOoOO00 * i11iIiiIii % II111iiii . i11iIiiIii * I11i
   if 67 - 67: i1IIi / i1IIi + IiII . oO0o
   if 70 - 70: i1IIi . I11i * o0oOOo0O0Ooo . iII111i
   if 75 - 75: oO0o * OoO0O00 * I11i + oO0o + O0 . I1Ii111
   if 8 - 8: I1ii11iIi11i / i1IIi - I1ii11iIi11i + Ii1I + OoO0O00 - I11i
   if 79 - 79: OoooooooOO - I1Ii111 * I1IiiI . I1Ii111 - iIii1I11I1II1
 if ( map_request . nonce != 0 ) : port = LISP_CTRL_PORT
 lisp_send_map_referral ( lisp_sockets , IiiiIi1iiii11 , ecm_source , port )
 return
 if 27 - 27: OoOoOO00 % OoOoOO00 % II111iiii
 if 45 - 45: iIii1I11I1II1 . o0oOOo0O0Ooo % I1IiiI
 if 10 - 10: I1IiiI / i1IIi * o0oOOo0O0Ooo + Oo0Ooo - OoOoOO00 % iII111i
 if 88 - 88: Ii1I % Ii1I
 if 29 - 29: OOooOOo % I1ii11iIi11i
 if 57 - 57: I1ii11iIi11i - OoOoOO00 + IiII
 if 58 - 58: OOooOOo % I1IiiI / oO0o . ooOoO0o . OoO0O00 / IiII
 if 72 - 72: ooOoO0o + ooOoO0o + o0oOOo0O0Ooo - o0oOOo0O0Ooo % Ii1I
def lisp_send_negative_map_reply ( sockets , eid , group , nonce , dest , port , ttl ,
 xtr_id , pubsub ) :
 if 52 - 52: I11i % i1IIi . I1ii11iIi11i
 lprint ( "Build negative Map-Reply EID-prefix {}, nonce 0x{} to ITR {}" . format ( lisp_print_eid_tuple ( eid , group ) , lisp_hex_string ( nonce ) ,
 # oO0o / I1ii11iIi11i * O0 % I11i
 red ( dest . print_address ( ) , False ) ) )
 if 34 - 34: oO0o / O0 * oO0o
 I11I1iI = LISP_NATIVE_FORWARD_ACTION if group . is_null ( ) else LISP_DROP_ACTION
 if 47 - 47: iIii1I11I1II1 - o0oOOo0O0Ooo % Ii1I
 if 38 - 38: ooOoO0o / IiII * I1ii11iIi11i % I1ii11iIi11i % oO0o
 if 82 - 82: I1ii11iIi11i . i11iIiiIii - I11i . iII111i / OOooOOo
 if 60 - 60: I1IiiI / I1IiiI / II111iiii
 if 59 - 59: OOooOOo . oO0o + ooOoO0o % o0oOOo0O0Ooo . i11iIiiIii
 if ( lisp_get_eid_hash ( eid ) != None ) :
  I11I1iI = LISP_SEND_MAP_REQUEST_ACTION
  if 27 - 27: OoOoOO00 - OoooooooOO / IiII / II111iiii * OOooOOo * ooOoO0o
  if 43 - 43: II111iiii . IiII - I1IiiI * I1ii11iIi11i + OoooooooOO
 IiiiIi1iiii11 = lisp_build_map_reply ( eid , group , [ ] , nonce , I11I1iI , ttl , None ,
 None , False , False )
 if 34 - 34: I1Ii111 / i1IIi
 if 95 - 95: OoOoOO00 * OOooOOo
 if 68 - 68: I1Ii111 / iIii1I11I1II1 % Ii1I
 if 77 - 77: i11iIiiIii + i11iIiiIii - I1ii11iIi11i % I1ii11iIi11i
 if ( pubsub ) :
  lisp_process_pubsub ( sockets , IiiiIi1iiii11 , eid , dest , port , nonce , ttl ,
 xtr_id )
 else :
  lisp_send_map_reply ( sockets , IiiiIi1iiii11 , dest , port )
  if 26 - 26: oO0o + OoooooooOO % o0oOOo0O0Ooo
 return
 if 96 - 96: ooOoO0o * OoOoOO00 - II111iiii
 if 40 - 40: oO0o * OOooOOo + Ii1I + I11i * Ii1I + OoooooooOO
 if 77 - 77: OOooOOo + ooOoO0o / O0
 if 16 - 16: ooOoO0o + Oo0Ooo * Oo0Ooo . I11i - IiII
 if 49 - 49: ooOoO0o . Ii1I
 if 75 - 75: OOooOOo / II111iiii - Oo0Ooo + I1Ii111
 if 42 - 42: OoooooooOO * II111iiii + Ii1I % OoO0O00 / I1Ii111
def lisp_retransmit_ddt_map_request ( mr ) :
 I1IIiiiI1I1iiIii = mr . mr_source . print_address ( )
 O0i1111ii1 = mr . print_eid_tuple ( )
 Iii11I = mr . nonce
 if 11 - 11: Ii1I - IiII
 if 20 - 20: I11i % oO0o * Oo0Ooo - I1Ii111 . Ii1I * I1ii11iIi11i
 if 59 - 59: OoOoOO00 + Oo0Ooo . I1ii11iIi11i - Ii1I
 if 48 - 48: I1Ii111 % Ii1I + I1IiiI * OoooooooOO % OoOoOO00 % i11iIiiIii
 if 13 - 13: iII111i % i1IIi
 if ( mr . last_request_sent_to ) :
  I1Ii = mr . last_request_sent_to . print_address ( )
  IiII111IiII1 = lisp_referral_cache_lookup ( mr . last_cached_prefix [ 0 ] ,
 mr . last_cached_prefix [ 1 ] , True )
  if ( IiII111IiII1 and IiII111IiII1 . referral_set . has_key ( I1Ii ) ) :
   IiII111IiII1 . referral_set [ I1Ii ] . no_responses += 1
   if 36 - 36: OoO0O00 . Oo0Ooo * I1ii11iIi11i
   if 16 - 16: IiII + OOooOOo
   if 33 - 33: ooOoO0o . i11iIiiIii + OOooOOo
   if 77 - 77: OoooooooOO * Ii1I * iIii1I11I1II1 + IiII
   if 53 - 53: IiII + I1Ii111 + oO0o
   if 31 - 31: OOooOOo + OoOoOO00 * OOooOOo + OoOoOO00 / o0oOOo0O0Ooo . iIii1I11I1II1
   if 1 - 1: I1Ii111 * i11iIiiIii % I1Ii111 - OoO0O00 + I1Ii111 / Oo0Ooo
 if ( mr . retry_count == LISP_MAX_MAP_NOTIFY_RETRIES ) :
  lprint ( "DDT Map-Request retry limit reached for EID {}, nonce 0x{}" . format ( green ( O0i1111ii1 , False ) , lisp_hex_string ( Iii11I ) ) )
  if 3 - 3: OOooOOo - i11iIiiIii / I1Ii111 . OOooOOo - OoO0O00
  mr . dequeue_map_request ( )
  return
  if 60 - 60: OoOoOO00 / i1IIi . Ii1I - OoO0O00 - OoooooooOO
  if 39 - 39: I1IiiI + i1IIi * OoO0O00 % I11i
 mr . retry_count += 1
 if 41 - 41: I1ii11iIi11i * IiII
 IiII1iiI = green ( I1IIiiiI1I1iiIii , False )
 OooOOOoOoo0O0 = green ( O0i1111ii1 , False )
 lprint ( "Retransmit DDT {} from {}ITR {} EIDs: {} -> {}, nonce 0x{}" . format ( bold ( "Map-Request" , False ) , "P" if mr . from_pitr else "" ,
 # IiII
 red ( mr . itr . print_address ( ) , False ) , IiII1iiI , OooOOOoOoo0O0 ,
 lisp_hex_string ( Iii11I ) ) )
 if 70 - 70: iIii1I11I1II1 / I1IiiI * OoOoOO00 / IiII / II111iiii + I1IiiI
 if 33 - 33: oO0o
 if 1 - 1: OoOoOO00 . i11iIiiIii % I1Ii111 + OoooooooOO - Oo0Ooo . I1ii11iIi11i
 if 46 - 46: i11iIiiIii + I11i - iIii1I11I1II1 / OoO0O00 - ooOoO0o / i1IIi
 lisp_send_ddt_map_request ( mr , False )
 if 44 - 44: o0oOOo0O0Ooo + Oo0Ooo
 if 46 - 46: OOooOOo % I1IiiI
 if 66 - 66: iIii1I11I1II1 . o0oOOo0O0Ooo - ooOoO0o
 if 27 - 27: Oo0Ooo - i1IIi * OoooooooOO - OoOoOO00 + OoOoOO00
 mr . retransmit_timer = threading . Timer ( LISP_DDT_MAP_REQUEST_INTERVAL ,
 lisp_retransmit_ddt_map_request , [ mr ] )
 mr . retransmit_timer . start ( )
 return
 if 24 - 24: i1IIi . OoOoOO00 / I1Ii111 + O0
 if 86 - 86: Ii1I * OoOoOO00 % I1ii11iIi11i + OOooOOo
 if 85 - 85: iII111i % i11iIiiIii
 if 78 - 78: i11iIiiIii / I11i / Oo0Ooo + II111iiii - I1ii11iIi11i / I1ii11iIi11i
 if 28 - 28: iIii1I11I1II1 / IiII - iIii1I11I1II1 . i1IIi - O0 * ooOoO0o
 if 41 - 41: Ii1I + IiII
 if 37 - 37: I1Ii111 / o0oOOo0O0Ooo - ooOoO0o - OoooooooOO . I1ii11iIi11i % I1Ii111
 if 53 - 53: I1IiiI % OOooOOo + Ii1I - Ii1I
def lisp_get_referral_node ( referral , source_eid , dest_eid ) :
 if 99 - 99: i1IIi * OoOoOO00 - i1IIi
 if 65 - 65: OoO0O00 / i11iIiiIii + I1ii11iIi11i + OoOoOO00
 if 82 - 82: Ii1I * OOooOOo % ooOoO0o / OoO0O00 - Oo0Ooo . I1Ii111
 if 90 - 90: I11i * i11iIiiIii % i1IIi + I1Ii111 / OoO0O00
 IIiI11 = [ ]
 for iiI111I in referral . referral_set . values ( ) :
  if ( iiI111I . updown == False ) : continue
  if ( len ( IIiI11 ) == 0 or IIiI11 [ 0 ] . priority == iiI111I . priority ) :
   IIiI11 . append ( iiI111I )
  elif ( IIiI11 [ 0 ] . priority > iiI111I . priority ) :
   IIiI11 = [ ]
   IIiI11 . append ( iiI111I )
   if 28 - 28: I11i - iII111i - OOooOOo - ooOoO0o
   if 68 - 68: I11i + Ii1I
   if 70 - 70: I11i + oO0o + o0oOOo0O0Ooo . I1Ii111 * i11iIiiIii
 IiiIiiiIiIi = len ( IIiI11 )
 if ( IiiIiiiIiIi == 0 ) : return ( None )
 if 94 - 94: I1Ii111 * I1ii11iIi11i / iII111i
 IIi1iiIIi1i = dest_eid . hash_address ( source_eid )
 IIi1iiIIi1i = IIi1iiIIi1i % IiiIiiiIiIi
 return ( IIiI11 [ IIi1iiIIi1i ] )
 if 78 - 78: ooOoO0o
 if 73 - 73: OoOoOO00 . OoOoOO00
 if 1 - 1: I1ii11iIi11i % o0oOOo0O0Ooo % i11iIiiIii - OOooOOo - ooOoO0o - OoO0O00
 if 94 - 94: OoO0O00 . Oo0Ooo / OoO0O00 + I1Ii111
 if 48 - 48: I1ii11iIi11i * i1IIi + I1Ii111
 if 80 - 80: I1IiiI % I11i
 if 64 - 64: OOooOOo + i11iIiiIii + I1IiiI . I11i % I11i - o0oOOo0O0Ooo
def lisp_send_ddt_map_request ( mr , send_to_root ) :
 IiIiI = mr . lisp_sockets
 Iii11I = mr . nonce
 I11iiII1I1111 = mr . itr
 iiIi1ii = mr . mr_source
 I11i11i1 = mr . print_eid_tuple ( )
 if 37 - 37: I1Ii111 % i1IIi / i11iIiiIii + OoO0O00 % OOooOOo
 if 12 - 12: Oo0Ooo + i1IIi + II111iiii
 if 71 - 71: i11iIiiIii - iII111i . I1IiiI
 if 31 - 31: iIii1I11I1II1 - i11iIiiIii - I1ii11iIi11i * I1Ii111 % oO0o + I1IiiI
 if 25 - 25: OOooOOo + iII111i * I1Ii111
 if ( mr . send_count == 8 ) :
  lprint ( "Giving up on map-request-queue entry {}, nonce 0x{}" . format ( green ( I11i11i1 , False ) , lisp_hex_string ( Iii11I ) ) )
  if 93 - 93: i1IIi - i1IIi
  mr . dequeue_map_request ( )
  return
  if 30 - 30: OoooooooOO
  if 37 - 37: O0 * I11i . O0 / II111iiii % oO0o
  if 19 - 19: Ii1I - oO0o
  if 72 - 72: oO0o / I11i % II111iiii
  if 22 - 22: i11iIiiIii % IiII % IiII % I11i - OoooooooOO + I1IiiI
  if 31 - 31: I11i + I1ii11iIi11i . i1IIi * i11iIiiIii + I1ii11iIi11i
 if ( send_to_root ) :
  O00o0oOoO0OOo = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  i1IiiI = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  mr . tried_root = True
  lprint ( "Jumping up to root for EID {}" . format ( green ( I11i11i1 , False ) ) )
 else :
  O00o0oOoO0OOo = mr . eid
  i1IiiI = mr . group
  if 43 - 43: OoO0O00
  if 51 - 51: OoooooooOO % IiII % Oo0Ooo
  if 50 - 50: I1IiiI - i11iIiiIii / I1ii11iIi11i . Ii1I - iIii1I11I1II1
  if 91 - 91: I1IiiI . I1Ii111 + II111iiii . Oo0Ooo
  if 95 - 95: iII111i
 oo0oooo00OOO = lisp_referral_cache_lookup ( O00o0oOoO0OOo , i1IiiI , False )
 if ( oo0oooo00OOO == None ) :
  lprint ( "No referral cache entry found" )
  lisp_send_negative_map_reply ( IiIiI , O00o0oOoO0OOo , i1IiiI ,
 Iii11I , I11iiII1I1111 , mr . sport , 15 , None , False )
  return
  if 80 - 80: ooOoO0o / OOooOOo / Ii1I * i1IIi . I11i
  if 47 - 47: I1ii11iIi11i
 iioOoo = oo0oooo00OOO . print_eid_tuple ( )
 lprint ( "Found referral cache entry {}, referral-type: {}" . format ( iioOoo ,
 oo0oooo00OOO . print_referral_type ( ) ) )
 if 90 - 90: i11iIiiIii % II111iiii % I1IiiI % Ii1I / II111iiii
 iiI111I = lisp_get_referral_node ( oo0oooo00OOO , iiIi1ii , mr . eid )
 if ( iiI111I == None ) :
  lprint ( "No reachable referral-nodes found" )
  mr . dequeue_map_request ( )
  lisp_send_negative_map_reply ( IiIiI , oo0oooo00OOO . eid ,
 oo0oooo00OOO . group , Iii11I , I11iiII1I1111 , mr . sport , 1 , None , False )
  return
  if 80 - 80: Oo0Ooo . I1IiiI / I1IiiI
  if 9 - 9: OoO0O00 % OoooooooOO
 lprint ( "Send DDT Map-Request to {} {} for EID {}, nonce 0x{}" . format ( iiI111I . referral_address . print_address ( ) ,
 # o0oOOo0O0Ooo
 oo0oooo00OOO . print_referral_type ( ) , green ( I11i11i1 , False ) ,
 lisp_hex_string ( Iii11I ) ) )
 if 94 - 94: O0 + OOooOOo . iIii1I11I1II1 / Oo0Ooo * OoOoOO00 . i11iIiiIii
 if 41 - 41: o0oOOo0O0Ooo - IiII / OOooOOo * OoO0O00
 if 48 - 48: OoooooooOO
 if 31 - 31: oO0o / I1Ii111 + i1IIi % OoooooooOO + i1IIi
 i1Ii1II = ( oo0oooo00OOO . referral_type == LISP_DDT_ACTION_MS_REFERRAL or
 oo0oooo00OOO . referral_type == LISP_DDT_ACTION_MS_ACK )
 lisp_send_ecm ( IiIiI , mr . packet , iiIi1ii , mr . sport , mr . eid ,
 iiI111I . referral_address , to_ms = i1Ii1II , ddt = True )
 if 51 - 51: oO0o
 if 30 - 30: oO0o * II111iiii + OOooOOo
 if 98 - 98: OoooooooOO - O0
 if 42 - 42: OoooooooOO * I11i * IiII
 mr . last_request_sent_to = iiI111I . referral_address
 mr . last_sent = lisp_get_timestamp ( )
 mr . send_count += 1
 iiI111I . map_requests_sent += 1
 return
 if 41 - 41: ooOoO0o % i11iIiiIii
 if 69 - 69: IiII - oO0o
 if 21 - 21: Oo0Ooo / I1Ii111
 if 72 - 72: OoOoOO00 . i11iIiiIii
 if 25 - 25: i1IIi
 if 69 - 69: OOooOOo / Ii1I
 if 67 - 67: i11iIiiIii . II111iiii + OoooooooOO % o0oOOo0O0Ooo + IiII * i1IIi
 if 53 - 53: oO0o * OoooooooOO + II111iiii . IiII * I1ii11iIi11i
def lisp_mr_process_map_request ( lisp_sockets , packet , map_request , ecm_source ,
 sport , mr_source ) :
 if 55 - 55: OoOoOO00
 ooOOoo0 = map_request . target_eid
 IIi1iiIII11 = map_request . target_group
 O0i1111ii1 = map_request . print_eid_tuple ( )
 I1IIiiiI1I1iiIii = mr_source . print_address ( )
 Iii11I = map_request . nonce
 if 27 - 27: I1IiiI
 IiII1iiI = green ( I1IIiiiI1I1iiIii , False )
 OooOOOoOoo0O0 = green ( O0i1111ii1 , False )
 lprint ( "Received Map-Request from {}ITR {} EIDs: {} -> {}, nonce 0x{}" . format ( "P" if map_request . pitr_bit else "" ,
 # Oo0Ooo . o0oOOo0O0Ooo + i1IIi * O0 + Oo0Ooo
 red ( ecm_source . print_address ( ) , False ) , IiII1iiI , OooOOOoOoo0O0 ,
 lisp_hex_string ( Iii11I ) ) )
 if 96 - 96: OoooooooOO * IiII . OoOoOO00
 if 64 - 64: I1Ii111
 if 96 - 96: Ii1I
 if 100 - 100: ooOoO0o
 I1I1iiii111II = lisp_ddt_map_request ( lisp_sockets , packet , ooOOoo0 , IIi1iiIII11 , Iii11I )
 I1I1iiii111II . packet = packet
 I1I1iiii111II . itr = ecm_source
 I1I1iiii111II . mr_source = mr_source
 I1I1iiii111II . sport = sport
 I1I1iiii111II . from_pitr = map_request . pitr_bit
 I1I1iiii111II . queue_map_request ( )
 if 40 - 40: O0 * oO0o - OoooooooOO - o0oOOo0O0Ooo * OoO0O00
 lisp_send_ddt_map_request ( I1I1iiii111II , False )
 return
 if 38 - 38: I1ii11iIi11i / I1ii11iIi11i % I1Ii111 % i11iIiiIii . OoOoOO00 * OoooooooOO
 if 53 - 53: II111iiii . i11iIiiIii / oO0o - i11iIiiIii * iII111i . I11i
 if 40 - 40: i11iIiiIii . OOooOOo / II111iiii
 if 29 - 29: OoO0O00 * o0oOOo0O0Ooo - OoooooooOO - OoOoOO00 / o0oOOo0O0Ooo
 if 89 - 89: Ii1I . iIii1I11I1II1 / OOooOOo + I1IiiI * II111iiii . OOooOOo
 if 68 - 68: IiII * IiII + oO0o / o0oOOo0O0Ooo
 if 41 - 41: OoOoOO00 - O0
def lisp_process_map_request ( lisp_sockets , packet , ecm_source , ecm_port ,
 mr_source , mr_port , ddt_request , ttl , timestamp ) :
 if 48 - 48: OoooooooOO % Ii1I * OoO0O00 / I1ii11iIi11i
 OoO = packet
 o0OOo0 = lisp_map_request ( )
 packet = o0OOo0 . decode ( packet , mr_source , mr_port )
 if ( packet == None ) :
  lprint ( "Could not decode Map-Request packet" )
  return
  if 55 - 55: i11iIiiIii + I11i % oO0o * O0
  if 19 - 19: oO0o . i1IIi . Oo0Ooo
 o0OOo0 . print_map_request ( )
 if 59 - 59: i1IIi / Ii1I . I1ii11iIi11i % II111iiii
 if 12 - 12: OoO0O00
 if 10 - 10: I1Ii111 / OoooooooOO / OoO0O00 * ooOoO0o
 if 81 - 81: i1IIi % I11i * iIii1I11I1II1
 if ( o0OOo0 . rloc_probe ) :
  lisp_process_rloc_probe_request ( lisp_sockets , o0OOo0 , mr_source ,
 mr_port , ttl , timestamp )
  return
  if 39 - 39: iIii1I11I1II1 / O0 . OoooooooOO - O0 . OoO0O00 . oO0o
  if 59 - 59: II111iiii * I1IiiI
  if 12 - 12: i11iIiiIii - IiII . iII111i . Ii1I
  if 34 - 34: i1IIi % iII111i + Oo0Ooo * OoOoOO00 + OoO0O00
  if 37 - 37: I1Ii111 / OoooooooOO
 if ( o0OOo0 . smr_bit ) :
  lisp_process_smr ( o0OOo0 )
  if 19 - 19: Ii1I - O0 + I1IiiI + OoooooooOO + ooOoO0o - Oo0Ooo
  if 45 - 45: I1IiiI . OoOoOO00 . OoOoOO00
  if 20 - 20: OoOoOO00
  if 69 - 69: OoOoOO00 * Ii1I % ooOoO0o . OoOoOO00 / oO0o * I1Ii111
  if 93 - 93: OoO0O00 % IiII % ooOoO0o . I1IiiI
 if ( o0OOo0 . smr_invoked_bit ) :
  lisp_process_smr_invoked_request ( o0OOo0 )
  if 96 - 96: II111iiii
  if 73 - 73: II111iiii
  if 81 - 81: I1IiiI + OoO0O00
  if 22 - 22: OoO0O00 * OoOoOO00 * I11i * IiII . OoO0O00 . I1ii11iIi11i
  if 32 - 32: o0oOOo0O0Ooo - iII111i + i11iIiiIii / ooOoO0o . OoOoOO00 . IiII
 if ( lisp_i_am_etr ) :
  lisp_etr_process_map_request ( lisp_sockets , o0OOo0 , mr_source ,
 mr_port , ttl , timestamp )
  if 9 - 9: iIii1I11I1II1
  if 66 - 66: iIii1I11I1II1
  if 13 - 13: O0 / ooOoO0o
  if 64 - 64: i11iIiiIii + I1IiiI / Oo0Ooo - iII111i
  if 26 - 26: I1ii11iIi11i
 if ( lisp_i_am_ms ) :
  packet = OoO
  ooOOoo0 , IIi1iiIII11 , O0ooOo0O0ooo0 = lisp_ms_process_map_request ( lisp_sockets ,
 OoO , o0OOo0 , mr_source , mr_port , ecm_source )
  if ( ddt_request ) :
   lisp_ms_send_map_referral ( lisp_sockets , o0OOo0 , ecm_source ,
 ecm_port , O0ooOo0O0ooo0 , ooOOoo0 , IIi1iiIII11 )
   if 21 - 21: ooOoO0o / iII111i % II111iiii * I1IiiI * II111iiii
  return
  if 40 - 40: Ii1I / i1IIi . iII111i
  if 65 - 65: iIii1I11I1II1 * O0 . II111iiii * o0oOOo0O0Ooo . I1ii11iIi11i * I1IiiI
  if 63 - 63: II111iiii . Oo0Ooo % iIii1I11I1II1
  if 85 - 85: I1IiiI + i1IIi % I1Ii111
  if 76 - 76: i11iIiiIii % i11iIiiIii
 if ( lisp_i_am_mr and not ddt_request ) :
  lisp_mr_process_map_request ( lisp_sockets , OoO , o0OOo0 ,
 ecm_source , mr_port , mr_source )
  if 33 - 33: OOooOOo . ooOoO0o / iIii1I11I1II1 * OOooOOo / oO0o
  if 75 - 75: Ii1I - OoOoOO00 . OOooOOo - o0oOOo0O0Ooo - I1ii11iIi11i
  if 69 - 69: O0 % I1ii11iIi11i
  if 77 - 77: iIii1I11I1II1 . OOooOOo
  if 64 - 64: OoOoOO00 - i1IIi * i1IIi / iII111i * OoOoOO00 * OoO0O00
 if ( lisp_i_am_ddt or ddt_request ) :
  packet = OoO
  lisp_ddt_process_map_request ( lisp_sockets , o0OOo0 , ecm_source ,
 ecm_port )
  if 61 - 61: OOooOOo
 return
 if 51 - 51: Oo0Ooo * OOooOOo / iII111i
 if 49 - 49: ooOoO0o . i1IIi % I1Ii111 . I1IiiI . I1ii11iIi11i + OoO0O00
 if 65 - 65: I1ii11iIi11i + Ii1I / i11iIiiIii * I1Ii111 + OoooooooOO
 if 7 - 7: Oo0Ooo % o0oOOo0O0Ooo
 if 40 - 40: oO0o * IiII
 if 29 - 29: O0 - II111iiii + iII111i
 if 73 - 73: I1Ii111 - I11i + IiII - o0oOOo0O0Ooo - I11i - OOooOOo
 if 40 - 40: iIii1I11I1II1 . iII111i * I1ii11iIi11i + IiII - iIii1I11I1II1
def lisp_store_mr_stats ( source , nonce ) :
 I1I1iiii111II = lisp_get_map_resolver ( source , None )
 if ( I1I1iiii111II == None ) : return
 if 83 - 83: i1IIi
 if 9 - 9: iIii1I11I1II1 + i11iIiiIii
 if 70 - 70: I1IiiI - OoO0O00 % OOooOOo + ooOoO0o % II111iiii
 if 19 - 19: I11i + i1IIi / i1IIi - II111iiii + I1Ii111
 I1I1iiii111II . neg_map_replies_received += 1
 I1I1iiii111II . last_reply = lisp_get_timestamp ( )
 if 11 - 11: i11iIiiIii % i11iIiiIii / IiII - Oo0Ooo / O0 - I11i
 if 29 - 29: OOooOOo * iIii1I11I1II1 * ooOoO0o
 if 80 - 80: oO0o * I1Ii111
 if 87 - 87: iII111i + OoOoOO00 % ooOoO0o - oO0o
 if ( ( I1I1iiii111II . neg_map_replies_received % 100 ) == 0 ) : I1I1iiii111II . total_rtt = 0
 if 40 - 40: i1IIi / OoOoOO00 - I11i / ooOoO0o . Ii1I
 if 8 - 8: I1IiiI . IiII . OOooOOo . O0
 if 3 - 3: Ii1I + i11iIiiIii
 if 87 - 87: ooOoO0o - iII111i % I11i
 if ( I1I1iiii111II . last_nonce == nonce ) :
  I1I1iiii111II . total_rtt += ( time . time ( ) - I1I1iiii111II . last_used )
  I1I1iiii111II . last_nonce = 0
  if 88 - 88: I11i . OoooooooOO
 if ( ( I1I1iiii111II . neg_map_replies_received % 10 ) == 0 ) : I1I1iiii111II . last_nonce = 0
 return
 if 86 - 86: Ii1I - I1IiiI - iII111i % Ii1I . I1ii11iIi11i % i1IIi
 if 84 - 84: OoOoOO00
 if 99 - 99: OoO0O00 - OoOoOO00 - i1IIi / OoO0O00 * I1ii11iIi11i * iIii1I11I1II1
 if 65 - 65: iII111i - O0 / i1IIi . I1Ii111
 if 85 - 85: o0oOOo0O0Ooo % Ii1I
 if 81 - 81: oO0o / OoO0O00 * i1IIi % iIii1I11I1II1
 if 23 - 23: II111iiii . II111iiii
def lisp_process_map_reply ( lisp_sockets , packet , source , ttl , itr_in_ts ) :
 global lisp_map_cache
 if 17 - 17: i11iIiiIii / IiII * I1IiiI . Oo0Ooo / o0oOOo0O0Ooo - iIii1I11I1II1
 oO00OoO0O0O = lisp_map_reply ( )
 packet = oO00OoO0O0O . decode ( packet )
 if ( packet == None ) :
  lprint ( "Could not decode Map-Reply packet" )
  return
  if 21 - 21: OOooOOo % Ii1I
 oO00OoO0O0O . print_map_reply ( )
 if 3 - 3: OOooOOo / ooOoO0o / I1Ii111 . I11i
 if 54 - 54: I1ii11iIi11i - I1IiiI . OoOoOO00
 if 36 - 36: OoO0O00 * I1IiiI / iII111i
 if 95 - 95: Ii1I . Oo0Ooo
 I1ooO00000OOoO = None
 for IiIIi1IiiIiI in range ( oO00OoO0O0O . record_count ) :
  i111iII = lisp_eid_record ( )
  packet = i111iII . decode ( packet )
  if ( packet == None ) :
   lprint ( "Could not decode EID-record in Map-Reply packet" )
   return
   if 50 - 50: II111iiii * OoOoOO00 . ooOoO0o - I1Ii111 . OoOoOO00
  i111iII . print_record ( "  " , False )
  if 64 - 64: iII111i + I1ii11iIi11i
  if 88 - 88: I1Ii111 / i11iIiiIii - O0 . II111iiii / II111iiii * II111iiii
  if 56 - 56: Oo0Ooo / I1IiiI % I1Ii111 % I1ii11iIi11i * I1IiiI - IiII
  if 39 - 39: oO0o + iII111i . I1Ii111 * i11iIiiIii % o0oOOo0O0Ooo + OOooOOo
  if 61 - 61: ooOoO0o / I1Ii111 / I1ii11iIi11i - Ii1I % o0oOOo0O0Ooo * iII111i
  if ( i111iII . rloc_count == 0 ) :
   lisp_store_mr_stats ( source , oO00OoO0O0O . nonce )
   if 94 - 94: I1IiiI / I11i
   if 100 - 100: Ii1I % OoO0O00 % OoooooooOO / II111iiii * I1Ii111
  o0oO0O00 = ( i111iII . group . is_null ( ) == False )
  if 64 - 64: I1Ii111 * OOooOOo * Ii1I + I1ii11iIi11i / iIii1I11I1II1 / Oo0Ooo
  if 50 - 50: OOooOOo % i11iIiiIii
  if 99 - 99: IiII
  if 87 - 87: IiII
  if 35 - 35: oO0o . O0 . Ii1I / ooOoO0o
  if ( lisp_decent_push_configured ) :
   I11I1iI = i111iII . action
   if ( o0oO0O00 and I11I1iI == LISP_DROP_ACTION ) :
    if ( i111iII . eid . is_local ( ) ) : continue
    if 36 - 36: i11iIiiIii . II111iiii . I11i . II111iiii
    if 36 - 36: Ii1I + ooOoO0o / Oo0Ooo % Oo0Ooo
    if 2 - 2: oO0o - Oo0Ooo * OoO0O00 . ooOoO0o . OOooOOo - oO0o
    if 74 - 74: o0oOOo0O0Ooo
    if 18 - 18: Oo0Ooo % OOooOOo / OOooOOo . I1IiiI + i1IIi . I1IiiI
    if 3 - 3: O0 * O0 + II111iiii + OoOoOO00 * I11i % Oo0Ooo
    if 19 - 19: oO0o % IiII % OoooooooOO % I1ii11iIi11i / OoO0O00
  if ( o0oO0O00 == False and i111iII . eid . is_null ( ) ) : continue
  if 6 - 6: O0 * I1Ii111 - II111iiii
  if 60 - 60: oO0o % oO0o
  if 76 - 76: I1Ii111 / o0oOOo0O0Ooo
  if 19 - 19: O0 . i1IIi % iIii1I11I1II1 + OOooOOo * OoOoOO00 / I11i
  if 82 - 82: I1ii11iIi11i
  if ( o0oO0O00 ) :
   o0o000Oo = lisp_map_cache_lookup ( i111iII . eid , i111iII . group )
  else :
   o0o000Oo = lisp_map_cache . lookup_cache ( i111iII . eid , True )
   if 89 - 89: I1IiiI / o0oOOo0O0Ooo % i1IIi * ooOoO0o
  O00Oo = ( o0o000Oo == None )
  if 96 - 96: OOooOOo + OoOoOO00 % IiII % i1IIi + o0oOOo0O0Ooo
  if 33 - 33: iIii1I11I1II1 . O0
  if 54 - 54: iIii1I11I1II1
  if 54 - 54: iII111i + OOooOOo + OoO0O00
  if 6 - 6: oO0o - OoooooooOO * iIii1I11I1II1 * I1ii11iIi11i
  if ( o0o000Oo == None ) :
   o0O0o0O , O0O , IIIi1i1iIIIi = lisp_allow_gleaning ( i111iII . eid , i111iII . group ,
 None )
   if ( o0O0o0O ) : continue
  else :
   if ( o0o000Oo . gleaned ) : continue
   if 86 - 86: oO0o . iII111i
   if 44 - 44: I11i % iII111i - i11iIiiIii + II111iiii / OoO0O00
   if 97 - 97: II111iiii * OoOoOO00 + I1Ii111 * ooOoO0o . I11i * OOooOOo
   if 36 - 36: II111iiii / Ii1I - IiII % iII111i / Oo0Ooo . oO0o
   if 50 - 50: I11i / I1IiiI / OOooOOo + I1Ii111 + OOooOOo * i1IIi
  OoO0oOOooOO = [ ]
  Oo0O00000o0OO = None
  for OO00O0O in range ( i111iII . rloc_count ) :
   I1Ii11iI = lisp_rloc_record ( )
   I1Ii11iI . keys = oO00OoO0O0O . keys
   packet = I1Ii11iI . decode ( packet , oO00OoO0O0O . nonce )
   if ( packet == None ) :
    lprint ( "Could not decode RLOC-record in Map-Reply packet" )
    return
    if 100 - 100: I11i * OoO0O00 - i1IIi + iII111i * Ii1I - OoooooooOO
   I1Ii11iI . print_record ( "    " )
   if 47 - 47: o0oOOo0O0Ooo / Ii1I - iII111i * OOooOOo / i11iIiiIii
   OoOO0O = None
   if ( o0o000Oo ) : OoOO0O = o0o000Oo . get_rloc ( I1Ii11iI . rloc )
   if ( OoOO0O ) :
    I1IIiIIIii = OoOO0O
   else :
    I1IIiIIIii = lisp_rloc ( )
    if 53 - 53: OoOoOO00
    if 43 - 43: I1ii11iIi11i * Oo0Ooo
    if 95 - 95: IiII + iII111i % I1IiiI
    if 18 - 18: Oo0Ooo
    if 8 - 8: O0 + iIii1I11I1II1 - O0
    if 67 - 67: O0
    if 22 - 22: I11i / i1IIi . II111iiii % ooOoO0o / I11i - Ii1I
   Oo0O00O = I1IIiIIIii . store_rloc_from_record ( I1Ii11iI , oO00OoO0O0O . nonce ,
 source )
   I1IIiIIIii . echo_nonce_capable = oO00OoO0O0O . echo_nonce_capable
   if 28 - 28: O0 - Oo0Ooo
   if ( I1IIiIIIii . echo_nonce_capable ) :
    oo0o00OO = I1IIiIIIii . rloc . print_address_no_iid ( )
    if ( lisp_get_echo_nonce ( None , oo0o00OO ) == None ) :
     lisp_echo_nonce ( oo0o00OO )
     if 58 - 58: iIii1I11I1II1 - OoooooooOO - iII111i
     if 43 - 43: ooOoO0o / o0oOOo0O0Ooo
     if 56 - 56: II111iiii * I1ii11iIi11i * O0 . iII111i . I1ii11iIi11i % I1Ii111
     if 99 - 99: Oo0Ooo - OoO0O00 + OoooooooOO - I1Ii111 - I1ii11iIi11i % i1IIi
     if 49 - 49: IiII % OoooooooOO / Oo0Ooo - OoOoOO00 + o0oOOo0O0Ooo / Ii1I
     if 6 - 6: I11i % IiII
   if ( I1IIiIIIii . json ) :
    if ( lisp_is_json_telemetry ( I1IIiIIIii . json . json_string ) ) :
     iii1Iii1 = I1IIiIIIii . json . json_string
     iii1Iii1 = lisp_encode_telemetry ( iii1Iii1 , ii = itr_in_ts )
     I1IIiIIIii . json . json_string = iii1Iii1
     if 48 - 48: Ii1I
     if 100 - 100: OoO0O00 % I1Ii111 + OoooooooOO / OoO0O00
     if 62 - 62: IiII
     if 66 - 66: o0oOOo0O0Ooo % OOooOOo
     if 15 - 15: Ii1I % IiII + IiII % iII111i - O0 * OoooooooOO
     if 53 - 53: OoOoOO00 . Ii1I / Oo0Ooo
     if 62 - 62: i11iIiiIii
     if 38 - 38: I1ii11iIi11i % ooOoO0o * OoooooooOO + iIii1I11I1II1 % i1IIi / OOooOOo
     if 6 - 6: i11iIiiIii
     if 8 - 8: iIii1I11I1II1 + I1ii11iIi11i . i1IIi % OoOoOO00 % OoooooooOO * Oo0Ooo
   if ( oO00OoO0O0O . rloc_probe and I1Ii11iI . probe_bit ) :
    if ( I1IIiIIIii . rloc . afi == source . afi ) :
     lisp_process_rloc_probe_reply ( I1IIiIIIii , source , Oo0O00O ,
 oO00OoO0O0O , ttl , Oo0O00000o0OO )
     if 53 - 53: oO0o
    if ( I1IIiIIIii . rloc . is_multicast_address ( ) ) : Oo0O00000o0OO = I1IIiIIIii
    if 23 - 23: I1ii11iIi11i . I1Ii111 + OOooOOo
    if 4 - 4: I1IiiI
    if 31 - 31: ooOoO0o * i1IIi . O0
    if 5 - 5: OOooOOo . I1ii11iIi11i + ooOoO0o . ooOoO0o + iII111i
    if 100 - 100: I1Ii111
   OoO0oOOooOO . append ( I1IIiIIIii )
   if 71 - 71: ooOoO0o * i1IIi / OoOoOO00 * i11iIiiIii - iII111i
   if 88 - 88: IiII
   if 29 - 29: iII111i . ooOoO0o
   if 62 - 62: IiII
   if ( lisp_data_plane_security and I1IIiIIIii . rloc_recent_rekey ( ) ) :
    I1ooO00000OOoO = I1IIiIIIii
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
  if ( oO00OoO0O0O . rloc_probe == False and lisp_nat_traversal ) :
   iioo00oOOO00 = [ ]
   i1ii1iiI1iI1 = [ ]
   for I1IIiIIIii in OoO0oOOooOO :
    if 85 - 85: iII111i
    if 23 - 23: ooOoO0o - OoO0O00 * oO0o / i11iIiiIii * iIii1I11I1II1
    if 7 - 7: iIii1I11I1II1 - I1Ii111 . ooOoO0o . O0 - OOooOOo
    if 5 - 5: i1IIi * OoOoOO00 + i1IIi % I11i
    if 79 - 79: OOooOOo % iIii1I11I1II1 / OoOoOO00
    if ( I1IIiIIIii . rloc . is_private_address ( ) ) :
     I1IIiIIIii . priority = 1
     I1IIiIIIii . state = LISP_RLOC_UNREACH_STATE
     iioo00oOOO00 . append ( I1IIiIIIii )
     i1ii1iiI1iI1 . append ( I1IIiIIIii . rloc . print_address_no_iid ( ) )
     continue
     if 9 - 9: Ii1I
     if 44 - 44: iII111i
     if 46 - 46: I11i . i11iIiiIii * OoOoOO00 + o0oOOo0O0Ooo / ooOoO0o
     if 37 - 37: OoO0O00 - Ii1I + OoO0O00
     if 49 - 49: OoooooooOO - I1ii11iIi11i % I1ii11iIi11i / i1IIi . ooOoO0o
     if 60 - 60: Oo0Ooo
    if ( I1IIiIIIii . priority == 254 and lisp_i_am_rtr == False ) :
     iioo00oOOO00 . append ( I1IIiIIIii )
     i1ii1iiI1iI1 . append ( I1IIiIIIii . rloc . print_address_no_iid ( ) )
     if 46 - 46: OoOoOO00 + i1IIi
    if ( I1IIiIIIii . priority != 254 and lisp_i_am_rtr ) :
     iioo00oOOO00 . append ( I1IIiIIIii )
     i1ii1iiI1iI1 . append ( I1IIiIIIii . rloc . print_address_no_iid ( ) )
     if 43 - 43: II111iiii * IiII % iIii1I11I1II1 % i11iIiiIii % I1ii11iIi11i
     if 81 - 81: oO0o % I1ii11iIi11i % ooOoO0o * O0 - OOooOOo
     if 17 - 17: O0 % O0 / I1ii11iIi11i . Oo0Ooo . iII111i
   if ( i1ii1iiI1iI1 != [ ] ) :
    OoO0oOOooOO = iioo00oOOO00
    lprint ( "NAT-traversal optimized RLOC-set: {}" . format ( i1ii1iiI1iI1 ) )
    if 4 - 4: OoO0O00
    if 65 - 65: Oo0Ooo % O0 / I1Ii111 * IiII - oO0o
    if 32 - 32: Ii1I * OoO0O00 + ooOoO0o
    if 41 - 41: IiII + I11i * ooOoO0o + Oo0Ooo . ooOoO0o
    if 38 - 38: iII111i * OoooooooOO - IiII
    if 36 - 36: I1Ii111 * II111iiii + I1ii11iIi11i - iII111i * iII111i
    if 91 - 91: O0 + I1Ii111 * II111iiii - O0 . i11iIiiIii . Oo0Ooo
  iioo00oOOO00 = [ ]
  for I1IIiIIIii in OoO0oOOooOO :
   if ( I1IIiIIIii . json != None ) : continue
   iioo00oOOO00 . append ( I1IIiIIIii )
   if 54 - 54: ooOoO0o * I11i / I1ii11iIi11i % ooOoO0o
  if ( iioo00oOOO00 != [ ] ) :
   I1I1 = len ( OoO0oOOooOO ) - len ( iioo00oOOO00 )
   lprint ( "Pruning {} no-address RLOC-records for map-cache" . format ( I1I1 ) )
   if 76 - 76: I11i . I1IiiI
   OoO0oOOooOO = iioo00oOOO00
   if 66 - 66: oO0o % oO0o * IiII
   if 39 - 39: i1IIi * Ii1I + OoOoOO00 / oO0o
   if 6 - 6: I1ii11iIi11i / II111iiii / OoOoOO00 . i11iIiiIii - iII111i
   if 43 - 43: i11iIiiIii * i11iIiiIii * I1Ii111
   if 80 - 80: oO0o . I1IiiI * II111iiii + o0oOOo0O0Ooo / o0oOOo0O0Ooo % OoooooooOO
   if 31 - 31: o0oOOo0O0Ooo - OoO0O00 % I1IiiI
   if 23 - 23: OOooOOo
   if 97 - 97: Oo0Ooo / OoooooooOO . OoooooooOO
  if ( oO00OoO0O0O . rloc_probe and o0o000Oo != None ) : OoO0oOOooOO = o0o000Oo . rloc_set
  if 47 - 47: OoO0O00
  if 52 - 52: I1IiiI * iIii1I11I1II1 % oO0o * IiII % oO0o
  if 9 - 9: I11i
  if 83 - 83: i11iIiiIii
  if 72 - 72: oO0o + II111iiii . O0 * oO0o + iII111i
  I1i1I1I = O00Oo
  if ( o0o000Oo and OoO0oOOooOO != o0o000Oo . rloc_set ) :
   o0o000Oo . delete_rlocs_from_rloc_probe_list ( )
   I1i1I1I = True
   if 45 - 45: i1IIi * OoooooooOO - IiII + oO0o
   if 38 - 38: OoO0O00
   if 42 - 42: O0
   if 31 - 31: OoOoOO00 . II111iiii - oO0o . iII111i - I1ii11iIi11i
   if 90 - 90: OoooooooOO / ooOoO0o / I1IiiI
  o0o00 = o0o000Oo . uptime if ( o0o000Oo ) else None
  if ( o0o000Oo == None ) :
   o0o000Oo = lisp_mapping ( i111iII . eid , i111iII . group , OoO0oOOooOO )
   o0o000Oo . mapping_source = source
   if 28 - 28: iIii1I11I1II1 - o0oOOo0O0Ooo . iIii1I11I1II1 / I11i / I1Ii111 % iIii1I11I1II1
   if 45 - 45: OoO0O00 + ooOoO0o / iIii1I11I1II1 % i11iIiiIii
   if 16 - 16: i1IIi / oO0o - OOooOOo / Ii1I + I1IiiI
   if 62 - 62: i11iIiiIii . Ii1I . iII111i / I1Ii111 * OoO0O00
   if 31 - 31: OoOoOO00
   if 16 - 16: OoooooooOO
   if ( lisp_i_am_rtr and i111iII . group . is_null ( ) == False ) :
    o0o000Oo . map_cache_ttl = LISP_MCAST_TTL
   else :
    o0o000Oo . map_cache_ttl = i111iII . store_ttl ( )
    if 32 - 32: ooOoO0o - o0oOOo0O0Ooo / ooOoO0o + o0oOOo0O0Ooo + iII111i
   o0o000Oo . action = i111iII . action
   o0o000Oo . add_cache ( I1i1I1I )
   if 78 - 78: OoooooooOO . I1ii11iIi11i * oO0o . o0oOOo0O0Ooo * OoOoOO00 / oO0o
   if 47 - 47: OOooOOo
  iI1I11II = "Add"
  if ( o0o00 ) :
   o0o000Oo . uptime = o0o00
   o0o000Oo . refresh_time = lisp_get_timestamp ( )
   iI1I11II = "Replace"
   if 99 - 99: O0 - OoO0O00
   if 95 - 95: Ii1I . IiII * o0oOOo0O0Ooo
  lprint ( "{} {} map-cache with {} RLOCs" . format ( iI1I11II ,
 green ( o0o000Oo . print_eid_tuple ( ) , False ) , len ( OoO0oOOooOO ) ) )
  if 91 - 91: I1Ii111
  if 49 - 49: I11i
  if 17 - 17: Oo0Ooo % o0oOOo0O0Ooo
  if 3 - 3: OoO0O00 . oO0o . oO0o . Ii1I
  if 100 - 100: i11iIiiIii / i1IIi . I1ii11iIi11i
  if ( lisp_ipc_dp_socket and I1ooO00000OOoO != None ) :
   lisp_write_ipc_keys ( I1ooO00000OOoO )
   if 1 - 1: IiII * I1Ii111 / I1ii11iIi11i * i11iIiiIii
   if 82 - 82: o0oOOo0O0Ooo * OoO0O00 / o0oOOo0O0Ooo % OoOoOO00 * iIii1I11I1II1 % O0
   if 10 - 10: ooOoO0o
   if 69 - 69: I11i + I1IiiI / oO0o
   if 89 - 89: i1IIi % OoOoOO00 . I1ii11iIi11i
   if 85 - 85: I1Ii111 - oO0o
   if 34 - 34: iIii1I11I1II1 / IiII + OoOoOO00 - IiII / ooOoO0o + OoOoOO00
  if ( O00Oo ) :
   oO0oo000O = bold ( "RLOC-probe" , False )
   for I1IIiIIIii in o0o000Oo . best_rloc_set :
    oo0o00OO = red ( I1IIiIIIii . rloc . print_address_no_iid ( ) , False )
    lprint ( "Trigger {} to {}" . format ( oO0oo000O , oo0o00OO ) )
    lisp_send_map_request ( lisp_sockets , 0 , o0o000Oo . eid , o0o000Oo . group , I1IIiIIIii )
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
 IiIiI = map_notify . lisp_sockets
 map_notify . retry_count += 1
 if 20 - 20: IiII
 lprint ( "Retransmit {} with nonce 0x{} to xTR {}, retry {}" . format ( bold ( "Map-Notify" , False ) , map_notify . nonce_key ,
 # II111iiii
 red ( oo0OoO . print_address ( ) , False ) , map_notify . retry_count ) )
 if 80 - 80: OOooOOo . OoO0O00 + O0 / IiII
 lisp_send_map_notify ( IiIiI , map_notify . packet , oo0OoO , Oo0O00O )
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
  I1Ii11iI = lisp_rloc_record ( )
  I1Ii11iI . store_rloc_entry ( iI11IiI1 )
  iIiIi1IiiiI1 += I1Ii11iI . encode ( )
  I1Ii11iI . print_record ( "  " )
  del ( I1Ii11iI )
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
  i111iII = lisp_eid_record ( )
  i111iII . decode ( eid_records )
  i111iII . print_record ( "  " , False )
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
 i111iII = lisp_eid_record ( )
 i111iII . record_ttl = 1440
 i111iII . eid . copy_address ( site_eid . eid )
 i111iII . group . copy_address ( site_eid . group )
 i111iII . rloc_count = 0
 for i1III111 in site_eid . registered_rlocs :
  if ( ooo0O0OO ^ i1III111 . is_rtr ( ) ) : continue
  i111iII . rloc_count += 1
  if 1 - 1: i1IIi / OoO0O00 % i1IIi % i11iIiiIii / i1IIi
 IiiiIi1iiii11 = i111iII . encode ( )
 if 8 - 8: O0 / OOooOOo + iII111i % iIii1I11I1II1 % iIii1I11I1II1 . ooOoO0o
 if 47 - 47: OoO0O00 / o0oOOo0O0Ooo / Ii1I * I1IiiI % ooOoO0o / I1Ii111
 if 80 - 80: I1Ii111 / O0 * O0
 if 40 - 40: OoO0O00 - oO0o / o0oOOo0O0Ooo . oO0o
 Ii1ii1 . print_notify ( )
 i111iII . print_record ( "  " , False )
 if 89 - 89: i11iIiiIii - II111iiii
 if 67 - 67: IiII % I1Ii111 + i11iIiiIii
 if 53 - 53: OOooOOo
 if 95 - 95: oO0o - OOooOOo % I1Ii111 / OoooooooOO % OoooooooOO - O0
 for i1III111 in site_eid . registered_rlocs :
  if ( ooo0O0OO ^ i1III111 . is_rtr ( ) ) : continue
  I1Ii11iI = lisp_rloc_record ( )
  I1Ii11iI . store_rloc_entry ( i1III111 )
  IiiiIi1iiii11 += I1Ii11iI . encode ( )
  I1Ii11iI . print_record ( "    " )
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
    for i1III111 in iIiIi1I . registered_rlocs :
     if ( i1III111 . is_rtr ( ) == False ) : continue
     iII1iI1IIiii [ i1III111 . rloc . print_address ( ) ] = i1III111
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
   o0ooOO0OOO00O0 = [ ]
   II11Ii1i1iiII = [ ]
   if ( len ( I1iiiII1Ii1i1 ) != 0 and I1iiiII1Ii1i1 [ 0 ] . rle != None ) :
    II11Ii1i1iiII = I1iiiII1Ii1i1 [ 0 ] . rle . rle_nodes
    if 38 - 38: I1ii11iIi11i + i1IIi % iIii1I11I1II1
   for Iii in II11Ii1i1iiII :
    OOooOo00Ooo . append ( Iii . address )
    o0ooOO0OOO00O0 . append ( Iii . address . print_address_no_iid ( ) )
    if 96 - 96: OoOoOO00 - OoOoOO00
   lprint ( "Notify existing RLE-nodes {}" . format ( o0ooOO0OOO00O0 ) )
  else :
   if 59 - 59: OoOoOO00 / iII111i * i11iIiiIii
   if 61 - 61: I1Ii111 % oO0o - OOooOOo
   if 91 - 91: o0oOOo0O0Ooo * Oo0Ooo
   if 59 - 59: iIii1I11I1II1 / Oo0Ooo % II111iiii
   if 55 - 55: ooOoO0o - IiII + o0oOOo0O0Ooo
   for i1III111 in I1iiiII1Ii1i1 :
    if ( i1III111 . is_rtr ( ) ) : OOooOo00Ooo . append ( i1III111 . rloc )
    if 48 - 48: O0 - iIii1I11I1II1 * OOooOOo
    if 33 - 33: I11i
    if 63 - 63: Ii1I % II111iiii / OoOoOO00 + Oo0Ooo
    if 28 - 28: OoO0O00 + I1IiiI . oO0o + II111iiii - O0
    if 32 - 32: oO0o
   o00O0o0O0O0o = ( len ( OOooOo00Ooo ) != 0 )
   if ( o00O0o0O0O0o == False ) :
    o0o000 = lisp_site_eid_lookup ( oOOooo000OoO [ 0 ] , Oo00oO0 , False )
    if ( o0o000 == None ) : continue
    if 62 - 62: i11iIiiIii + OoooooooOO + IiII - OoO0O00 / oO0o * iIii1I11I1II1
    for i1III111 in o0o000 . registered_rlocs :
     if ( i1III111 . rloc . is_null ( ) ) : continue
     OOooOo00Ooo . append ( i1III111 . rloc )
     if 91 - 91: o0oOOo0O0Ooo - i11iIiiIii + Oo0Ooo % iIii1I11I1II1
     if 58 - 58: iII111i / ooOoO0o - I1Ii111 + I1Ii111 * ooOoO0o
     if 48 - 48: iII111i % O0 % Ii1I * OoO0O00 . OoO0O00
     if 74 - 74: OoO0O00 * i1IIi + I1ii11iIi11i / o0oOOo0O0Ooo / i1IIi
     if 94 - 94: Ii1I
     if 13 - 13: OoO0O00 - II111iiii . iII111i + OoOoOO00 / i11iIiiIii
   if ( len ( OOooOo00Ooo ) == 0 ) :
    lprint ( "No ITRs or RTRs found for {}, Map-Notify suppressed" . format ( green ( IiIIiIII1I1i . print_eid_tuple ( ) , False ) ) )
    if 32 - 32: ooOoO0o / II111iiii / I1ii11iIi11i
    continue
    if 34 - 34: iIii1I11I1II1
    if 47 - 47: OOooOOo * iII111i
    if 71 - 71: IiII - OoooooooOO * i11iIiiIii . OoooooooOO % i1IIi . Oo0Ooo
    if 3 - 3: OoO0O00 + i11iIiiIii + oO0o * IiII
    if 19 - 19: iII111i / II111iiii . I1Ii111 * I1IiiI - OOooOOo
    if 70 - 70: OoO0O00
  for iI11IiI1 in OOooOo00Ooo :
   lprint ( "Build Map-Notify to {}TR {} for {}" . format ( "R" if o00O0o0O0O0o else "x" , red ( iI11IiI1 . print_address_no_iid ( ) , False ) ,
   # OOooOOo * OoO0O00 / I1Ii111
 green ( IiIIiIII1I1i . print_eid_tuple ( ) , False ) ) )
   if 96 - 96: iII111i * iII111i / iII111i + I1IiiI
   i1I1iO0000oOooOoO0 = [ IiIIiIII1I1i . print_eid_tuple ( ) ]
   lisp_send_multicast_map_notify ( lisp_sockets , IiIIiIII1I1i , i1I1iO0000oOooOoO0 , iI11IiI1 )
   time . sleep ( .001 )
   if 49 - 49: OoO0O00 / iII111i
   if 22 - 22: I11i + II111iiii * iIii1I11I1II1 % OOooOOo
 return
 if 7 - 7: I11i - OOooOOo + I1IiiI + IiII . I1Ii111
 if 76 - 76: o0oOOo0O0Ooo % IiII - iII111i % ooOoO0o
 if 34 - 34: OoooooooOO / ooOoO0o - iII111i + IiII - iII111i
 if 65 - 65: O0 * Ii1I % ooOoO0o
 if 29 - 29: iII111i % Ii1I / OoOoOO00 % O0 / IiII
 if 32 - 32: IiII * II111iiii . Ii1I
 if 68 - 68: I11i / O0
 if 6 - 6: oO0o - oO0o . I1IiiI % I1ii11iIi11i
def lisp_find_sig_in_rloc_set ( packet , rloc_count ) :
 for IiIIi1IiiIiI in range ( rloc_count ) :
  I1Ii11iI = lisp_rloc_record ( )
  packet = I1Ii11iI . decode ( packet , None )
  i1iii = I1Ii11iI . json
  if ( i1iii == None ) : continue
  if 31 - 31: II111iiii - Ii1I * OOooOOo - i11iIiiIii / OoooooooOO - I1Ii111
  try :
   i1iii = json . loads ( i1iii . json_string )
  except :
   lprint ( "Found corrupted JSON signature" )
   continue
   if 76 - 76: Oo0Ooo
   if 93 - 93: i1IIi - I1IiiI * i11iIiiIii / Ii1I . Ii1I - i1IIi
  if ( i1iii . has_key ( "signature" ) == False ) : continue
  return ( I1Ii11iI )
  if 19 - 19: iIii1I11I1II1 * OOooOOo * Oo0Ooo % I1IiiI
 return ( None )
 if 93 - 93: IiII % OoOoOO00 / I1IiiI + o0oOOo0O0Ooo * ooOoO0o / i1IIi
 if 25 - 25: O0 / Oo0Ooo - o0oOOo0O0Ooo * Oo0Ooo
 if 45 - 45: Ii1I * IiII - OOooOOo
 if 57 - 57: iII111i % OoO0O00 / OoooooooOO
 if 69 - 69: oO0o
 if 44 - 44: IiII - II111iiii % Ii1I
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
def lisp_get_eid_hash ( eid ) :
 iI1iIIIIiiii = None
 for IiI1Iiii in lisp_eid_hashes :
  if 7 - 7: OoOoOO00 + OoO0O00 * I1IiiI
  if 63 - 63: I1ii11iIi11i + iII111i * i1IIi
  if 63 - 63: I1ii11iIi11i / II111iiii % oO0o + ooOoO0o . Ii1I % I11i
  if 59 - 59: I1Ii111 % o0oOOo0O0Ooo - I1IiiI * i1IIi
  o0OoO0000o = IiI1Iiii . instance_id
  if ( o0OoO0000o == - 1 ) : IiI1Iiii . instance_id = eid . instance_id
  if 5 - 5: I1IiiI
  ii1iOo = eid . is_more_specific ( IiI1Iiii )
  IiI1Iiii . instance_id = o0OoO0000o
  if ( ii1iOo ) :
   iI1iIIIIiiii = 128 - IiI1Iiii . mask_len
   break
   if 96 - 96: OoO0O00 + I11i / oO0o
   if 81 - 81: OoO0O00 . I1IiiI - IiII . ooOoO0o . i1IIi
 if ( iI1iIIIIiiii == None ) : return ( None )
 if 20 - 20: O0 - OoooooooOO % i1IIi + i11iIiiIii / Ii1I
 ii1i1II11II1i = eid . address
 II111i1II1i1I = ""
 for IiIIi1IiiIiI in range ( 0 , iI1iIIIIiiii / 16 ) :
  IiiIIi1 = ii1i1II11II1i & 0xffff
  IiiIIi1 = hex ( IiiIIi1 ) [ 2 : - 1 ]
  II111i1II1i1I = IiiIIi1 . zfill ( 4 ) + ":" + II111i1II1i1I
  ii1i1II11II1i >>= 16
  if 31 - 31: Oo0Ooo / iII111i / OoOoOO00 + iIii1I11I1II1 . iIii1I11I1II1
 if ( iI1iIIIIiiii % 16 != 0 ) :
  IiiIIi1 = ii1i1II11II1i & 0xff
  IiiIIi1 = hex ( IiiIIi1 ) [ 2 : - 1 ]
  II111i1II1i1I = IiiIIi1 . zfill ( 2 ) + ":" + II111i1II1i1I
  if 41 - 41: I1ii11iIi11i
 return ( II111i1II1i1I [ 0 : - 1 ] )
 if 90 - 90: IiII * I1Ii111 * I1Ii111 * I1IiiI . OoOoOO00 * iII111i
 if 46 - 46: OoOoOO00
 if 1 - 1: oO0o + ooOoO0o / iII111i
 if 11 - 11: IiII / OoO0O00 * I1ii11iIi11i
 if 20 - 20: I1IiiI * OoO0O00 / Oo0Ooo
 if 59 - 59: I11i % i1IIi % Oo0Ooo % Oo0Ooo
 if 91 - 91: I11i
 if 98 - 98: I11i - II111iiii . IiII % Oo0Ooo
 if 65 - 65: OoO0O00
 if 65 - 65: oO0o
 if 77 - 77: I11i * i1IIi - OOooOOo / OoOoOO00
def lisp_lookup_public_key ( eid ) :
 o0OoO0000o = eid . instance_id
 if 50 - 50: O0 - oO0o . oO0o
 if 98 - 98: IiII % Ii1I / Ii1I
 if 10 - 10: Ii1I
 if 69 - 69: I1Ii111 * OoooooooOO . o0oOOo0O0Ooo % I1IiiI
 if 70 - 70: iII111i . i11iIiiIii * I1Ii111
 oOoIiIi = lisp_get_eid_hash ( eid )
 if ( oOoIiIi == None ) : return ( [ None , None , False ] )
 if 100 - 100: oO0o + I1Ii111 % iIii1I11I1II1 / I1Ii111
 oOoIiIi = "hash-" + oOoIiIi
 ii1iIIi = lisp_address ( LISP_AFI_NAME , oOoIiIi , len ( oOoIiIi ) , o0OoO0000o )
 IIi1iiIII11 = lisp_address ( LISP_AFI_NONE , "" , 0 , o0OoO0000o )
 if 27 - 27: iIii1I11I1II1 + OoOoOO00 % i11iIiiIii / OoOoOO00 + iIii1I11I1II1
 if 65 - 65: o0oOOo0O0Ooo
 if 73 - 73: I11i . I1ii11iIi11i - OoO0O00 + OoooooooOO
 if 71 - 71: I1IiiI
 o0o000 = lisp_site_eid_lookup ( ii1iIIi , IIi1iiIII11 , True )
 if ( o0o000 == None ) : return ( [ ii1iIIi , None , False ] )
 if 27 - 27: OoO0O00 + i1IIi * OoooooooOO * iIii1I11I1II1 - Ii1I
 if 85 - 85: OoO0O00 + II111iiii / OoO0O00 . II111iiii * OoOoOO00 * I1IiiI
 if 19 - 19: iII111i / Ii1I + iIii1I11I1II1 * O0 - Oo0Ooo
 if 47 - 47: iIii1I11I1II1 % I1ii11iIi11i
 I1i1ii = None
 for I1IIiIIIii in o0o000 . registered_rlocs :
  II = I1IIiIIIii . json
  if ( II == None ) : continue
  try :
   II = json . loads ( II . json_string )
  except :
   lprint ( "Registered RLOC JSON format is invalid for {}" . format ( oOoIiIi ) )
   if 33 - 33: IiII + I1IiiI / i11iIiiIii - OoO0O00
   return ( [ ii1iIIi , None , False ] )
   if 32 - 32: i1IIi / iIii1I11I1II1 - OoOoOO00
  if ( II . has_key ( "public-key" ) == False ) : continue
  I1i1ii = II [ "public-key" ]
  break
  if 5 - 5: Oo0Ooo / OoooooooOO / Ii1I * I1Ii111
 return ( [ ii1iIIi , I1i1ii , True ] )
 if 37 - 37: Ii1I * o0oOOo0O0Ooo
 if 39 - 39: OoooooooOO
 if 37 - 37: OoO0O00 . iII111i
 if 32 - 32: II111iiii
 if 11 - 11: i11iIiiIii - OOooOOo . i1IIi + OOooOOo - O0
 if 17 - 17: i1IIi % o0oOOo0O0Ooo % ooOoO0o / I11i
 if 68 - 68: OoOoOO00
 if 14 - 14: iIii1I11I1II1 + oO0o / ooOoO0o
def lisp_verify_cga_sig ( eid , rloc_record ) :
 if 20 - 20: I1ii11iIi11i . II111iiii % I1Ii111 + I1Ii111 / OoooooooOO . Ii1I
 if 98 - 98: OoooooooOO - i11iIiiIii - iII111i + Ii1I - I1IiiI
 if 75 - 75: OOooOOo
 if 25 - 25: iII111i / I1ii11iIi11i - ooOoO0o
 if 53 - 53: IiII / OoooooooOO / ooOoO0o + Oo0Ooo - OOooOOo - iIii1I11I1II1
 O0OO0OoO00oOo = json . loads ( rloc_record . json . json_string )
 if 53 - 53: OOooOOo . I1IiiI . o0oOOo0O0Ooo / o0oOOo0O0Ooo
 if ( lisp_get_eid_hash ( eid ) ) :
  Oo0o0ooOo0 = eid
 elif ( O0OO0OoO00oOo . has_key ( "signature-eid" ) ) :
  Ii11i11 = O0OO0OoO00oOo [ "signature-eid" ]
  Oo0o0ooOo0 = lisp_address ( LISP_AFI_IPV6 , Ii11i11 , 0 , 0 )
 else :
  lprint ( "  No signature-eid found in RLOC-record" )
  return ( False )
  if 2 - 2: ooOoO0o
  if 55 - 55: I11i + i1IIi * OoOoOO00 % Oo0Ooo * II111iiii . I1IiiI
  if 98 - 98: I1ii11iIi11i
  if 57 - 57: OOooOOo * I11i . oO0o
  if 17 - 17: iII111i - OOooOOo * I1IiiI + i1IIi % I1ii11iIi11i
 ii1iIIi , I1i1ii , o0OOOooO = lisp_lookup_public_key ( Oo0o0ooOo0 )
 if ( ii1iIIi == None ) :
  I11i11i1 = green ( Oo0o0ooOo0 . print_address ( ) , False )
  lprint ( "  Could not parse hash in EID {}" . format ( I11i11i1 ) )
  return ( False )
  if 6 - 6: Ii1I
  if 23 - 23: o0oOOo0O0Ooo + I1IiiI
 ooOoOO0o = "found" if o0OOOooO else bold ( "not found" , False )
 I11i11i1 = green ( ii1iIIi . print_address ( ) , False )
 lprint ( "  Lookup for crypto-hashed EID {} {}" . format ( I11i11i1 , ooOoOO0o ) )
 if ( o0OOOooO == False ) : return ( False )
 if 60 - 60: I1ii11iIi11i * i11iIiiIii + oO0o
 if ( I1i1ii == None ) :
  lprint ( "  RLOC-record with public-key not found" )
  return ( False )
  if 59 - 59: I11i
  if 61 - 61: IiII * I1Ii111 * OoO0O00 / oO0o - OoooooooOO
 iI11i11ii11 = I1i1ii [ 0 : 8 ] + "..." + I1i1ii [ - 8 : : ]
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
 I1i1ii = binascii . a2b_base64 ( I1i1ii )
 try :
  Oo000O000 = ecdsa . VerifyingKey . from_pem ( I1i1ii )
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
   iiI1IOO00o0Oo0000 = Ii1ii1 . retransmit_timer
   if ( iiI1IOO00o0Oo0000 ) : iiI1IOO00o0Oo0000 . cancel ( )
   if 15 - 15: iII111i
   lprint ( "Remove from Map-Notify queue nonce 0x{} for EID {}" . format ( Ii1ii1 . nonce_key , green ( o0oOo0oo0 , False ) ) )
   if 55 - 55: iII111i
   if 22 - 22: I1Ii111 % II111iiii % iIii1I11I1II1 % II111iiii
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
 I1ooo0o00o0Oooo = lisp_map_register ( )
 OoO , packet = I1ooo0o00o0Oooo . decode ( packet )
 if ( packet == None ) :
  lprint ( "Could not decode Map-Register packet" )
  return
  if 86 - 86: II111iiii . OoOoOO00 % I1IiiI * OOooOOo . OoOoOO00 + O0
 I1ooo0o00o0Oooo . sport = sport
 if 15 - 15: i11iIiiIii / I1IiiI - iII111i
 I1ooo0o00o0Oooo . print_map_register ( )
 if 75 - 75: o0oOOo0O0Ooo . I11i
 if 4 - 4: iIii1I11I1II1 % i1IIi % i11iIiiIii / OOooOOo
 if 93 - 93: I1ii11iIi11i - iII111i % O0 - Ii1I
 if 84 - 84: I1ii11iIi11i . iIii1I11I1II1 % IiII * I11i + ooOoO0o
 OOOO00OO0O0o = True
 if ( I1ooo0o00o0Oooo . auth_len == LISP_SHA1_160_AUTH_DATA_LEN ) :
  OOOO00OO0O0o = True
  if 20 - 20: iIii1I11I1II1 % oO0o + o0oOOo0O0Ooo + oO0o % IiII
 if ( I1ooo0o00o0Oooo . alg_id == LISP_SHA_256_128_ALG_ID ) :
  OOOO00OO0O0o = False
  if 84 - 84: IiII - O0 . I1ii11iIi11i % OOooOOo % iII111i + OoooooooOO
  if 74 - 74: o0oOOo0O0Ooo + OoOoOO00 - o0oOOo0O0Ooo
  if 2 - 2: OOooOOo
  if 14 - 14: Ii1I - O0 - IiII % Ii1I / OoOoOO00 * OoooooooOO
  if 57 - 57: Oo0Ooo % Oo0Ooo % O0 . I1Ii111 % I1ii11iIi11i
 OO0O0O00Oo = [ ]
 if 9 - 9: i11iIiiIii - i11iIiiIii / OOooOOo - ooOoO0o % OoOoOO00 + Ii1I
 if 3 - 3: iII111i / I1ii11iIi11i / I1IiiI - Oo0Ooo
 if 71 - 71: i11iIiiIii + Oo0Ooo % i11iIiiIii - i11iIiiIii
 if 84 - 84: oO0o
 ooo000O0O = None
 iI111iIII1I = packet
 OOooOo0o0oOoo = [ ]
 ooOO0o0O0 = I1ooo0o00o0Oooo . record_count
 for IiIIi1IiiIiI in range ( ooOO0o0O0 ) :
  i111iII = lisp_eid_record ( )
  I1Ii11iI = lisp_rloc_record ( )
  packet = i111iII . decode ( packet )
  if ( packet == None ) :
   lprint ( "Could not decode EID-record in Map-Register packet" )
   return
   if 14 - 14: II111iiii + OOooOOo * Ii1I * I1IiiI + OOooOOo . OOooOOo
  i111iII . print_record ( "  " , False )
  if 5 - 5: oO0o + OoooooooOO
  if 88 - 88: oO0o + OOooOOo
  if 14 - 14: I11i / i1IIi
  if 56 - 56: OoooooooOO
  o0o000 = lisp_site_eid_lookup ( i111iII . eid , i111iII . group ,
 False )
  if 59 - 59: I1ii11iIi11i + OoO0O00
  i11iiii11iIii = o0o000 . print_eid_tuple ( ) if o0o000 else None
  if 11 - 11: o0oOOo0O0Ooo
  if 77 - 77: o0oOOo0O0Ooo / iIii1I11I1II1 * iIii1I11I1II1 / o0oOOo0O0Ooo * iII111i
  if 26 - 26: Ii1I
  if 1 - 1: OoOoOO00 . o0oOOo0O0Ooo + Oo0Ooo % Oo0Ooo * I1ii11iIi11i
  if 50 - 50: IiII / i1IIi . I1ii11iIi11i
  if 75 - 75: I11i * oO0o + OoooooooOO . iII111i + OoO0O00
  if 44 - 44: II111iiii
  if ( o0o000 and o0o000 . accept_more_specifics == False ) :
   if ( o0o000 . eid_record_matches ( i111iII ) == False ) :
    O0Ii1IiiiI = o0o000 . parent_for_more_specifics
    if ( O0Ii1IiiiI ) : o0o000 = O0Ii1IiiiI
    if 32 - 32: I1Ii111 % oO0o * iII111i * OOooOOo
    if 45 - 45: oO0o / O0
    if 5 - 5: OoO0O00 / O0
    if 64 - 64: I11i / i1IIi
    if 68 - 68: Ii1I / oO0o - iII111i
    if 52 - 52: I11i / OoO0O00 - Ii1I
    if 11 - 11: OoooooooOO - i11iIiiIii - I1ii11iIi11i / o0oOOo0O0Ooo - Ii1I
    if 16 - 16: ooOoO0o + O0
  Ii1I111IiI11I = ( o0o000 and o0o000 . accept_more_specifics )
  if ( Ii1I111IiI11I ) :
   Oo0oOO = lisp_site_eid ( o0o000 . site )
   Oo0oOO . dynamic = True
   Oo0oOO . eid . copy_address ( i111iII . eid )
   Oo0oOO . group . copy_address ( i111iII . group )
   Oo0oOO . parent_for_more_specifics = o0o000
   Oo0oOO . add_cache ( )
   Oo0oOO . inherit_from_ams_parent ( )
   o0o000 . more_specific_registrations . append ( Oo0oOO )
   o0o000 = Oo0oOO
  else :
   o0o000 = lisp_site_eid_lookup ( i111iII . eid , i111iII . group ,
 True )
   if 33 - 33: oO0o * II111iiii / OOooOOo + I1ii11iIi11i * OoooooooOO
   if 89 - 89: ooOoO0o / ooOoO0o
  I11i11i1 = i111iII . print_eid_tuple ( )
  if 61 - 61: iIii1I11I1II1
  if ( o0o000 == None ) :
   iiiII = bold ( "Site not found" , False )
   lprint ( "  {} for EID {}{}" . format ( iiiII , green ( I11i11i1 , False ) ,
 ", matched non-ams {}" . format ( green ( i11iiii11iIii , False ) if i11iiii11iIii else "" ) ) )
   if 26 - 26: i11iIiiIii + OoO0O00 - i1IIi / OOooOOo
   if 71 - 71: OOooOOo . i1IIi
   if 48 - 48: ooOoO0o - Ii1I - I11i
   if 70 - 70: O0 * I11i . i1IIi - ooOoO0o
   if 93 - 93: OoooooooOO / o0oOOo0O0Ooo
   packet = I1Ii11iI . end_of_rlocs ( packet , i111iII . rloc_count )
   if ( packet == None ) :
    lprint ( "  Could not decode RLOC-record in Map-Register packet" )
    return
    if 61 - 61: II111iiii / i1IIi . I1ii11iIi11i % iIii1I11I1II1
   continue
   if 66 - 66: iIii1I11I1II1 % OoOoOO00 + i1IIi * i11iIiiIii * OoooooooOO
   if 36 - 36: iII111i - OoO0O00 + I1IiiI + Ii1I . OoooooooOO
  ooo000O0O = o0o000 . site
  if 75 - 75: oO0o * Oo0Ooo * O0
  if ( Ii1I111IiI11I ) :
   oOo = o0o000 . parent_for_more_specifics . print_eid_tuple ( )
   lprint ( "  Found ams {} for site '{}' for registering prefix {}" . format ( green ( oOo , False ) , ooo000O0O . site_name , green ( I11i11i1 , False ) ) )
   if 22 - 22: ooOoO0o / OoooooooOO . II111iiii / Ii1I * OoO0O00 . i1IIi
  else :
   oOo = green ( o0o000 . print_eid_tuple ( ) , False )
   lprint ( "  Found {} for site '{}' for registering prefix {}" . format ( oOo , ooo000O0O . site_name , green ( I11i11i1 , False ) ) )
   if 62 - 62: oO0o % Ii1I - Ii1I
   if 16 - 16: OoO0O00 - O0 - OOooOOo - I11i % OoOoOO00
   if 7 - 7: I1Ii111 / OoOoOO00 . II111iiii
   if 9 - 9: I11i . I11i . OoooooooOO
   if 42 - 42: iII111i / oO0o / iII111i * OoO0O00
   if 25 - 25: OoOoOO00 - II111iiii + II111iiii . Ii1I * II111iiii
  if ( ooo000O0O . shutdown ) :
   lprint ( ( "  Rejecting registration for site '{}', configured in " +
 "admin-shutdown state" ) . format ( ooo000O0O . site_name ) )
   packet = I1Ii11iI . end_of_rlocs ( packet , i111iII . rloc_count )
   continue
   if 12 - 12: IiII / Ii1I
   if 54 - 54: Oo0Ooo + Ii1I % OoooooooOO * OOooOOo / OoOoOO00
   if 39 - 39: I1IiiI % i11iIiiIii % Ii1I
   if 59 - 59: ooOoO0o % OoO0O00 / I1IiiI - II111iiii + OoooooooOO * i11iIiiIii
   if 58 - 58: IiII / Oo0Ooo + o0oOOo0O0Ooo
   if 71 - 71: Ii1I - IiII
   if 2 - 2: OoOoOO00 % IiII % OoO0O00 . i1IIi / I1Ii111 - iIii1I11I1II1
   if 88 - 88: Oo0Ooo * i1IIi % OOooOOo
  I1I1I1 = I1ooo0o00o0Oooo . key_id
  if ( ooo000O0O . auth_key . has_key ( I1I1I1 ) ) :
   o0Oooo00oO0o00 = ooo000O0O . auth_key [ I1I1I1 ]
  else :
   o0Oooo00oO0o00 = ""
   if 31 - 31: I11i - oO0o * ooOoO0o
   if 64 - 64: I11i
  I1iiIIiIII1i = lisp_verify_auth ( OoO , I1ooo0o00o0Oooo . alg_id ,
 I1ooo0o00o0Oooo . auth_data , o0Oooo00oO0o00 )
  oo0o00oOOooO = "dynamic " if o0o000 . dynamic else ""
  if 22 - 22: OOooOOo
  O0o = bold ( "passed" if I1iiIIiIII1i else "failed" , False )
  I1I1I1 = "key-id {}" . format ( I1I1I1 ) if I1I1I1 == I1ooo0o00o0Oooo . key_id else "bad key-id {}" . format ( I1ooo0o00o0Oooo . key_id )
  if 12 - 12: I11i * I1IiiI + OOooOOo
  lprint ( "  Authentication {} for {}EID-prefix {}, {}" . format ( O0o , oo0o00oOOooO , green ( I11i11i1 , False ) , I1I1I1 ) )
  if 40 - 40: I1ii11iIi11i - OoOoOO00 % OoooooooOO * o0oOOo0O0Ooo % OoooooooOO
  if 47 - 47: iIii1I11I1II1 - OOooOOo + I1ii11iIi11i * ooOoO0o + Oo0Ooo + OoO0O00
  if 64 - 64: OoOoOO00 - OoOoOO00 . OoooooooOO + ooOoO0o
  if 100 - 100: ooOoO0o . OoooooooOO % i1IIi % OoO0O00
  if 26 - 26: OoOoOO00 * IiII
  if 76 - 76: I1IiiI + IiII * I1ii11iIi11i * I1IiiI % Ii1I + ooOoO0o
  iI1I1ii = True
  OooOo = ( lisp_get_eid_hash ( i111iII . eid ) != None )
  if ( OooOo or o0o000 . require_signature ) :
   I1i111i1ii11 = "Required " if o0o000 . require_signature else ""
   I11i11i1 = green ( I11i11i1 , False )
   I1IIiIIIii = lisp_find_sig_in_rloc_set ( packet , i111iII . rloc_count )
   if ( I1IIiIIIii == None ) :
    iI1I1ii = False
    lprint ( ( "  {}EID-crypto-hash signature verification {} " + "for EID-prefix {}, no signature found" ) . format ( I1i111i1ii11 ,
    # I1ii11iIi11i % I1ii11iIi11i / oO0o
 bold ( "failed" , False ) , I11i11i1 ) )
   else :
    iI1I1ii = lisp_verify_cga_sig ( i111iII . eid , I1IIiIIIii )
    O0o = bold ( "passed" if iI1I1ii else "failed" , False )
    lprint ( ( "  {}EID-crypto-hash signature verification {} " + "for EID-prefix {}" ) . format ( I1i111i1ii11 , O0o , I11i11i1 ) )
    if 85 - 85: OoOoOO00 % I11i / Oo0Ooo + I11i - Oo0Ooo
    if 20 - 20: IiII
    if 81 - 81: Oo0Ooo / I1Ii111
    if 20 - 20: o0oOOo0O0Ooo + ooOoO0o % i1IIi
  if ( I1iiIIiIII1i == False or iI1I1ii == False ) :
   packet = I1Ii11iI . end_of_rlocs ( packet , i111iII . rloc_count )
   if ( packet == None ) :
    lprint ( "  Could not decode RLOC-record in Map-Register packet" )
    return
    if 51 - 51: iII111i - ooOoO0o
   continue
   if 32 - 32: IiII - i11iIiiIii
   if 41 - 41: Ii1I % Ii1I * oO0o - I11i + iIii1I11I1II1 . ooOoO0o
   if 30 - 30: Ii1I * iII111i . II111iiii / i1IIi
   if 77 - 77: oO0o . IiII + I1ii11iIi11i . i1IIi
   if 49 - 49: I1Ii111 . OoooooooOO / o0oOOo0O0Ooo - iII111i - iII111i - i11iIiiIii
   if 37 - 37: OOooOOo
  if ( I1ooo0o00o0Oooo . merge_register_requested ) :
   O0Ii1IiiiI = o0o000
   O0Ii1IiiiI . inconsistent_registration = False
   if 79 - 79: I1Ii111 - OoO0O00 + ooOoO0o + oO0o . i11iIiiIii + i1IIi
   if 32 - 32: IiII . ooOoO0o / OoO0O00 / iII111i . iIii1I11I1II1 % IiII
   if 28 - 28: I1Ii111 + OoooooooOO + IiII . ooOoO0o . I1IiiI / oO0o
   if 66 - 66: Ii1I - I11i + Oo0Ooo . ooOoO0o
   if 89 - 89: IiII . II111iiii / OoO0O00 + I1ii11iIi11i * i11iIiiIii
   if ( o0o000 . group . is_null ( ) ) :
    if ( O0Ii1IiiiI . site_id != I1ooo0o00o0Oooo . site_id ) :
     O0Ii1IiiiI . site_id = I1ooo0o00o0Oooo . site_id
     O0Ii1IiiiI . registered = False
     O0Ii1IiiiI . individual_registrations = { }
     O0Ii1IiiiI . registered_rlocs = [ ]
     lisp_registered_count -= 1
     if 85 - 85: o0oOOo0O0Ooo - Oo0Ooo / I1Ii111
     if 100 - 100: OoO0O00 * iIii1I11I1II1 - IiII . i1IIi % i11iIiiIii % Oo0Ooo
     if 22 - 22: ooOoO0o - OOooOOo
   Oo000O000 = source . address + I1ooo0o00o0Oooo . xtr_id
   if ( o0o000 . individual_registrations . has_key ( Oo000O000 ) ) :
    o0o000 = o0o000 . individual_registrations [ Oo000O000 ]
   else :
    o0o000 = lisp_site_eid ( ooo000O0O )
    o0o000 . eid . copy_address ( O0Ii1IiiiI . eid )
    o0o000 . group . copy_address ( O0Ii1IiiiI . group )
    o0o000 . encrypt_json = O0Ii1IiiiI . encrypt_json
    O0Ii1IiiiI . individual_registrations [ Oo000O000 ] = o0o000
    if 90 - 90: i11iIiiIii . i11iIiiIii - iIii1I11I1II1
  else :
   o0o000 . inconsistent_registration = o0o000 . merge_register_requested
   if 20 - 20: ooOoO0o - i11iIiiIii
   if 23 - 23: OoO0O00 + I1IiiI / I1ii11iIi11i * I1ii11iIi11i % ooOoO0o
   if 83 - 83: I1IiiI * i11iIiiIii - I1ii11iIi11i + I11i
  o0o000 . map_registers_received += 1
  if 33 - 33: OoO0O00 . OoooooooOO % iII111i / oO0o * Ii1I + ooOoO0o
  if 29 - 29: oO0o
  if 21 - 21: i11iIiiIii . o0oOOo0O0Ooo
  if 78 - 78: Oo0Ooo
  if 77 - 77: oO0o % Oo0Ooo % O0
  IiiiIi = ( o0o000 . is_rloc_in_rloc_set ( source ) == False )
  if ( i111iII . record_ttl == 0 and IiiiIi ) :
   lprint ( "  Ignore deregistration request from {}" . format ( red ( source . print_address_no_iid ( ) , False ) ) )
   if 51 - 51: IiII % IiII + OOooOOo . II111iiii / I1ii11iIi11i
   continue
   if 4 - 4: o0oOOo0O0Ooo % I1IiiI * o0oOOo0O0Ooo * OoOoOO00 - Ii1I
   if 61 - 61: OoooooooOO - OoOoOO00 . O0 / ooOoO0o . Ii1I
   if 41 - 41: Oo0Ooo / OoOoOO00 % I1Ii111 - O0
   if 19 - 19: I1IiiI % I1Ii111 - O0 . iIii1I11I1II1 . I11i % O0
   if 88 - 88: ooOoO0o
   if 52 - 52: iIii1I11I1II1 % ooOoO0o * iIii1I11I1II1
  ii1iii11IiIii = o0o000 . registered_rlocs
  o0o000 . registered_rlocs = [ ]
  if 94 - 94: OOooOOo % I1ii11iIi11i % O0 + iII111i
  if 62 - 62: iIii1I11I1II1 . OoOoOO00 / iIii1I11I1II1 + IiII
  if 31 - 31: Ii1I . OoO0O00 . Ii1I + OoO0O00 * iIii1I11I1II1 . iII111i
  if 42 - 42: O0 / oO0o % O0 . i1IIi % OOooOOo
  iII1I1iII1i = packet
  for OO00O0O in range ( i111iII . rloc_count ) :
   I1Ii11iI = lisp_rloc_record ( )
   packet = I1Ii11iI . decode ( packet , None , o0o000 . encrypt_json )
   if ( packet == None ) :
    lprint ( "  Could not decode RLOC-record in Map-Register packet" )
    return
    if 51 - 51: i1IIi
   I1Ii11iI . print_record ( "    " )
   if 29 - 29: o0oOOo0O0Ooo / II111iiii % O0 - o0oOOo0O0Ooo * I11i * Ii1I
   if 2 - 2: oO0o + I11i * o0oOOo0O0Ooo / o0oOOo0O0Ooo . Oo0Ooo
   if 34 - 34: i11iIiiIii / OoooooooOO - II111iiii
   if 93 - 93: Oo0Ooo % ooOoO0o . OoOoOO00 + o0oOOo0O0Ooo * IiII * Oo0Ooo
   if ( len ( ooo000O0O . allowed_rlocs ) > 0 ) :
    oo0o00OO = I1Ii11iI . rloc . print_address ( )
    if ( ooo000O0O . allowed_rlocs . has_key ( oo0o00OO ) == False ) :
     lprint ( ( "  Reject registration, RLOC {} not " + "configured in allowed RLOC-set" ) . format ( red ( oo0o00OO , False ) ) )
     if 34 - 34: I11i - OoooooooOO % i1IIi + I1IiiI
     if 14 - 14: I1IiiI . o0oOOo0O0Ooo / I1Ii111
     o0o000 . registered = False
     packet = I1Ii11iI . end_of_rlocs ( packet ,
 i111iII . rloc_count - OO00O0O - 1 )
     break
     if 67 - 67: OoooooooOO . oO0o * OoOoOO00 - OoooooooOO
     if 32 - 32: oO0o
     if 72 - 72: I1IiiI
     if 34 - 34: ooOoO0o % II111iiii / ooOoO0o
     if 87 - 87: Oo0Ooo
     if 7 - 7: iIii1I11I1II1
   I1IIiIIIii = lisp_rloc ( )
   I1IIiIIIii . store_rloc_from_record ( I1Ii11iI , None , source )
   if 85 - 85: iIii1I11I1II1 . O0
   if 43 - 43: II111iiii / OoOoOO00 + OOooOOo % Oo0Ooo * OOooOOo
   if 62 - 62: ooOoO0o * OOooOOo . I11i + Oo0Ooo - I1Ii111
   if 48 - 48: I1Ii111 * Oo0Ooo % OoO0O00 % Ii1I
   if 8 - 8: OoO0O00 . OoO0O00
   if 29 - 29: I11i + OoooooooOO % o0oOOo0O0Ooo - I1Ii111
   if ( source . is_exact_match ( I1IIiIIIii . rloc ) ) :
    I1IIiIIIii . map_notify_requested = I1ooo0o00o0Oooo . map_notify_requested
    if 45 - 45: II111iiii - OOooOOo / oO0o % O0 . iII111i . iII111i
    if 82 - 82: iIii1I11I1II1 % Oo0Ooo * i1IIi - I1Ii111 - I1ii11iIi11i / iII111i
    if 24 - 24: IiII
    if 95 - 95: IiII + OoOoOO00 * OOooOOo
    if 92 - 92: OoOoOO00 + ooOoO0o . iII111i
   o0o000 . registered_rlocs . append ( I1IIiIIIii )
   if 59 - 59: iIii1I11I1II1 % I1Ii111 + I1ii11iIi11i . OoOoOO00 * Oo0Ooo / I1Ii111
   if 41 - 41: i1IIi / IiII
  oO0000O0OOO = ( o0o000 . do_rloc_sets_match ( ii1iii11IiIii ) == False )
  if 3 - 3: OOooOOo + O0 - iII111i * oO0o - II111iiii
  if 7 - 7: Ii1I % OoooooooOO - i1IIi / i1IIi - Oo0Ooo
  if 96 - 96: Oo0Ooo - ooOoO0o
  if 46 - 46: o0oOOo0O0Ooo
  if 41 - 41: I11i % II111iiii - II111iiii + OoO0O00
  if 98 - 98: iIii1I11I1II1 + OOooOOo * oO0o / o0oOOo0O0Ooo . iII111i
  if ( I1ooo0o00o0Oooo . map_register_refresh and oO0000O0OOO and
 o0o000 . registered ) :
   lprint ( "  Reject registration, refreshes cannot change RLOC-set" )
   o0o000 . registered_rlocs = ii1iii11IiIii
   continue
   if 52 - 52: IiII + iIii1I11I1II1
   if 22 - 22: IiII - OOooOOo + I1ii11iIi11i
   if 64 - 64: OoOoOO00
   if 79 - 79: IiII
   if 65 - 65: Oo0Ooo - i11iIiiIii * OoOoOO00 . I1Ii111 . iIii1I11I1II1
   if 48 - 48: iIii1I11I1II1 - oO0o / OoO0O00 + O0 . Ii1I + I1Ii111
  if ( o0o000 . registered == False ) :
   o0o000 . first_registered = lisp_get_timestamp ( )
   lisp_registered_count += 1
   if 17 - 17: OoOoOO00 . Oo0Ooo - I1Ii111 / I1Ii111 + I11i % i1IIi
  o0o000 . last_registered = lisp_get_timestamp ( )
  o0o000 . registered = ( i111iII . record_ttl != 0 )
  o0o000 . last_registerer = source
  if 31 - 31: OoooooooOO . O0 / OoO0O00 . I1Ii111
  if 41 - 41: OoooooooOO + iII111i . OOooOOo
  if 73 - 73: oO0o + i1IIi + i11iIiiIii / I1ii11iIi11i
  if 100 - 100: I1IiiI % ooOoO0o % OoooooooOO / i11iIiiIii + i11iIiiIii % IiII
  o0o000 . auth_sha1_or_sha2 = OOOO00OO0O0o
  o0o000 . proxy_reply_requested = I1ooo0o00o0Oooo . proxy_reply_requested
  o0o000 . lisp_sec_present = I1ooo0o00o0Oooo . lisp_sec_present
  o0o000 . map_notify_requested = I1ooo0o00o0Oooo . map_notify_requested
  o0o000 . mobile_node_requested = I1ooo0o00o0Oooo . mobile_node
  o0o000 . merge_register_requested = I1ooo0o00o0Oooo . merge_register_requested
  if 39 - 39: Ii1I % o0oOOo0O0Ooo + OOooOOo / iIii1I11I1II1
  o0o000 . use_register_ttl_requested = I1ooo0o00o0Oooo . use_ttl_for_timeout
  if ( o0o000 . use_register_ttl_requested ) :
   o0o000 . register_ttl = i111iII . store_ttl ( )
  else :
   o0o000 . register_ttl = LISP_SITE_TIMEOUT_CHECK_INTERVAL * 3
   if 40 - 40: iIii1I11I1II1 / iII111i % OOooOOo % i11iIiiIii
  o0o000 . xtr_id_present = I1ooo0o00o0Oooo . xtr_id_present
  if ( o0o000 . xtr_id_present ) :
   o0o000 . xtr_id = I1ooo0o00o0Oooo . xtr_id
   o0o000 . site_id = I1ooo0o00o0Oooo . site_id
   if 57 - 57: II111iiii % OoO0O00 * i1IIi
   if 19 - 19: ooOoO0o . iIii1I11I1II1 + I1ii11iIi11i + I1ii11iIi11i / o0oOOo0O0Ooo . Oo0Ooo
   if 9 - 9: II111iiii % OoooooooOO
   if 4 - 4: i1IIi * i11iIiiIii % OoooooooOO + OoOoOO00 . oO0o
   if 95 - 95: I1ii11iIi11i * OoOoOO00 % o0oOOo0O0Ooo / O0 + ooOoO0o % OOooOOo
  if ( I1ooo0o00o0Oooo . merge_register_requested ) :
   if ( O0Ii1IiiiI . merge_in_site_eid ( o0o000 ) ) :
    OO0O0O00Oo . append ( [ i111iII . eid , i111iII . group ] )
    if 48 - 48: i1IIi + IiII - iIii1I11I1II1 . i11iIiiIii % OOooOOo + I1ii11iIi11i
   if ( I1ooo0o00o0Oooo . map_notify_requested ) :
    lisp_send_merged_map_notify ( lisp_sockets , O0Ii1IiiiI , I1ooo0o00o0Oooo ,
 i111iII )
    if 95 - 95: ooOoO0o + OoOoOO00 . II111iiii + Ii1I
    if 81 - 81: OoooooooOO / OOooOOo / Oo0Ooo
    if 26 - 26: iII111i
  if ( oO0000O0OOO == False ) : continue
  if ( len ( OO0O0O00Oo ) != 0 ) : continue
  if 93 - 93: Oo0Ooo + I1IiiI % OoOoOO00 / OOooOOo / I1ii11iIi11i
  OOooOo0o0oOoo . append ( o0o000 . print_eid_tuple ( ) )
  if 6 - 6: IiII
  if 68 - 68: Oo0Ooo
  if 83 - 83: OOooOOo / iIii1I11I1II1 . OoO0O00 - oO0o % Oo0Ooo
  if 30 - 30: Ii1I . OoOoOO00 / oO0o . OoO0O00
  if 93 - 93: i11iIiiIii
  if 33 - 33: i1IIi % OoooooooOO + Oo0Ooo % I1IiiI / ooOoO0o
  if 40 - 40: IiII % IiII
  i111iII = i111iII . encode ( )
  i111iII += iII1I1iII1i
  i1I1iO0000oOooOoO0 = [ o0o000 . print_eid_tuple ( ) ]
  lprint ( "    Changed RLOC-set, Map-Notifying old RLOC-set" )
  if 9 - 9: I1IiiI * i1IIi + OOooOOo * OoOoOO00
  for I1IIiIIIii in ii1iii11IiIii :
   if ( I1IIiIIIii . map_notify_requested == False ) : continue
   if ( I1IIiIIIii . rloc . is_exact_match ( source ) ) : continue
   lisp_build_map_notify ( lisp_sockets , i111iII , i1I1iO0000oOooOoO0 , 1 , I1IIiIIIii . rloc ,
 LISP_CTRL_PORT , I1ooo0o00o0Oooo . nonce , I1ooo0o00o0Oooo . key_id ,
 I1ooo0o00o0Oooo . alg_id , I1ooo0o00o0Oooo . auth_len , ooo000O0O , False )
   if 8 - 8: iII111i
   if 51 - 51: I1IiiI
   if 72 - 72: ooOoO0o / I1ii11iIi11i . Ii1I * iII111i . iIii1I11I1II1
   if 35 - 35: OoO0O00 . OoOoOO00 % O0 * OoO0O00
   if 68 - 68: OOooOOo
  lisp_notify_subscribers ( lisp_sockets , i111iII , o0o000 . eid , ooo000O0O )
  if 87 - 87: IiII * IiII - OoO0O00 / I1ii11iIi11i + OOooOOo / i11iIiiIii
  if 21 - 21: o0oOOo0O0Ooo / oO0o + oO0o + Oo0Ooo / o0oOOo0O0Ooo
  if 39 - 39: i11iIiiIii - OoO0O00 - i11iIiiIii / OoooooooOO
  if 15 - 15: i1IIi . iII111i + IiII / I1ii11iIi11i - i1IIi / iII111i
  if 27 - 27: OoOoOO00 / OoooooooOO + i1IIi % iIii1I11I1II1 / OoO0O00
 if ( len ( OO0O0O00Oo ) != 0 ) :
  lisp_queue_multicast_map_notify ( lisp_sockets , OO0O0O00Oo )
  if 73 - 73: I1ii11iIi11i / OoOoOO00 / IiII + oO0o
  if 73 - 73: I11i * o0oOOo0O0Ooo * I1IiiI . OoooooooOO % I1Ii111
  if 9 - 9: oO0o % I1Ii111 . O0 + I1ii11iIi11i - Ii1I - I1ii11iIi11i
  if 57 - 57: i11iIiiIii
  if 21 - 21: iIii1I11I1II1 / I1IiiI / iII111i
  if 19 - 19: Oo0Ooo / iIii1I11I1II1 / I11i
 if ( I1ooo0o00o0Oooo . merge_register_requested ) : return
 if 71 - 71: iIii1I11I1II1 * I1IiiI
 if 35 - 35: O0
 if 10 - 10: Ii1I - I1Ii111 / Oo0Ooo + O0
 if 67 - 67: Ii1I % i11iIiiIii . Oo0Ooo
 if 78 - 78: I1IiiI - iIii1I11I1II1
 if ( I1ooo0o00o0Oooo . map_notify_requested and ooo000O0O != None ) :
  lisp_build_map_notify ( lisp_sockets , iI111iIII1I , OOooOo0o0oOoo ,
 I1ooo0o00o0Oooo . record_count , source , sport , I1ooo0o00o0Oooo . nonce ,
 I1ooo0o00o0Oooo . key_id , I1ooo0o00o0Oooo . alg_id , I1ooo0o00o0Oooo . auth_len ,
 ooo000O0O , True )
  if 20 - 20: i11iIiiIii % I1IiiI % OoOoOO00
 return
 if 85 - 85: I11i + OoOoOO00 * O0 * O0
 if 92 - 92: i11iIiiIii
 if 16 - 16: I11i . ooOoO0o - Oo0Ooo / OoO0O00 . i1IIi
 if 59 - 59: ooOoO0o - ooOoO0o % I11i + OoO0O00
 if 88 - 88: Ii1I - ooOoO0o . Oo0Ooo
 if 83 - 83: I11i + Oo0Ooo . I1ii11iIi11i * I1ii11iIi11i
 if 80 - 80: i1IIi * I11i - OOooOOo / II111iiii * iIii1I11I1II1
 if 42 - 42: OoOoOO00 . I11i % II111iiii
 if 19 - 19: OoooooooOO
 if 31 - 31: I11i . OoOoOO00 - O0 * iII111i % I1Ii111 - II111iiii
def lisp_process_multicast_map_notify ( packet , source ) :
 Ii1ii1 = lisp_map_notify ( "" )
 packet = Ii1ii1 . decode ( packet )
 if ( packet == None ) :
  lprint ( "Could not decode Map-Notify packet" )
  return
  if 21 - 21: OOooOOo . Oo0Ooo - i1IIi
  if 56 - 56: I11i
 Ii1ii1 . print_notify ( )
 if ( Ii1ii1 . record_count == 0 ) : return
 if 24 - 24: I1IiiI . I1IiiI % ooOoO0o
 i1ii = Ii1ii1 . eid_records
 if 70 - 70: ooOoO0o - IiII * I1Ii111 + I1IiiI / O0 + Oo0Ooo
 for IiIIi1IiiIiI in range ( Ii1ii1 . record_count ) :
  i111iII = lisp_eid_record ( )
  i1ii = i111iII . decode ( i1ii )
  if ( packet == None ) : return
  i111iII . print_record ( "  " , False )
  if 27 - 27: oO0o / IiII - iIii1I11I1II1 / o0oOOo0O0Ooo % OOooOOo * iIii1I11I1II1
  if 40 - 40: oO0o - II111iiii * OOooOOo % OoooooooOO
  if 52 - 52: OOooOOo + OoO0O00
  if 96 - 96: OOooOOo % O0 - Oo0Ooo % oO0o / I1IiiI . i1IIi
  o0o000Oo = lisp_map_cache_lookup ( i111iII . eid , i111iII . group )
  if ( o0o000Oo == None ) :
   iII1 , O0O , IIIi1i1iIIIi = lisp_allow_gleaning ( i111iII . eid , i111iII . group ,
 None )
   if ( iII1 == False ) : continue
   if 42 - 42: O0 * iII111i . i1IIi / i11iIiiIii + Ii1I
   o0o000Oo = lisp_mapping ( i111iII . eid , i111iII . group , [ ] )
   o0o000Oo . add_cache ( )
   if 80 - 80: O0 + II111iiii + oO0o . Oo0Ooo * i1IIi
   if 8 - 8: Ii1I
   if 82 - 82: OOooOOo * Ii1I + I1ii11iIi11i . OoO0O00
   if 15 - 15: O0
   if 44 - 44: Ii1I . Oo0Ooo . I1Ii111 + oO0o
   if 32 - 32: OOooOOo - II111iiii + IiII * iIii1I11I1II1 - Oo0Ooo
   if 25 - 25: ooOoO0o
  if ( o0o000Oo . gleaned ) :
   lprint ( "Ignore Map-Notify for gleaned {}" . format ( green ( o0o000Oo . print_eid_tuple ( ) , False ) ) )
   if 33 - 33: Oo0Ooo
   continue
   if 11 - 11: I11i
   if 55 - 55: i11iIiiIii * OoOoOO00 - OoOoOO00 * OoO0O00 / iII111i
  o0o000Oo . mapping_source = None if source == "lisp-etr" else source
  o0o000Oo . map_cache_ttl = i111iII . store_ttl ( )
  if 64 - 64: iIii1I11I1II1 . Ii1I * Oo0Ooo - OoO0O00
  if 74 - 74: I1IiiI / o0oOOo0O0Ooo
  if 53 - 53: iIii1I11I1II1 * oO0o
  if 43 - 43: IiII * Oo0Ooo / OOooOOo % oO0o
  if 11 - 11: OoOoOO00 * Oo0Ooo / I11i * OOooOOo
  if ( len ( o0o000Oo . rloc_set ) != 0 and i111iII . rloc_count == 0 ) :
   o0o000Oo . rloc_set = [ ]
   o0o000Oo . build_best_rloc_set ( )
   lisp_write_ipc_map_cache ( True , o0o000Oo )
   lprint ( "Update {} map-cache entry with no RLOC-set" . format ( green ( o0o000Oo . print_eid_tuple ( ) , False ) ) )
   if 15 - 15: ooOoO0o - OOooOOo / OoooooooOO
   continue
   if 41 - 41: OoOoOO00 . iII111i . i1IIi + oO0o
   if 60 - 60: oO0o * I1Ii111
  oOOOOOo0 = o0o000Oo . rtrs_in_rloc_set ( )
  if 61 - 61: o0oOOo0O0Ooo % oO0o / I1ii11iIi11i . Ii1I % II111iiii
  if 22 - 22: iIii1I11I1II1 - OoooooooOO
  if 8 - 8: ooOoO0o % i11iIiiIii
  if 41 - 41: I1Ii111 . ooOoO0o - i11iIiiIii + Ii1I . OOooOOo . OoOoOO00
  if 70 - 70: i1IIi % OoOoOO00 / iII111i + i11iIiiIii % ooOoO0o + IiII
  for OO00O0O in range ( i111iII . rloc_count ) :
   I1Ii11iI = lisp_rloc_record ( )
   i1ii = I1Ii11iI . decode ( i1ii , None )
   I1Ii11iI . print_record ( "    " )
   if ( i111iII . group . is_null ( ) ) : continue
   if ( I1Ii11iI . rle == None ) : continue
   if 58 - 58: OOooOOo / i11iIiiIii . Oo0Ooo % iII111i
   if 92 - 92: OoOoOO00 / ooOoO0o % iII111i / iIii1I11I1II1
   if 73 - 73: O0 % i11iIiiIii
   if 16 - 16: O0
   if 15 - 15: i1IIi % i11iIiiIii
   I1i1IIiIIiIiIi = o0o000Oo . rloc_set [ 0 ] . stats if len ( o0o000Oo . rloc_set ) != 0 else None
   if 97 - 97: Ii1I + I1Ii111 / II111iiii
   if 14 - 14: iII111i / IiII / oO0o
   if 55 - 55: OoO0O00 % O0
   if 92 - 92: OoooooooOO / O0
   I1IIiIIIii = lisp_rloc ( )
   I1IIiIIIii . store_rloc_from_record ( I1Ii11iI , None , o0o000Oo . mapping_source )
   if ( I1i1IIiIIiIiIi != None ) : I1IIiIIIii . stats = copy . deepcopy ( I1i1IIiIIiIiIi )
   if 14 - 14: i11iIiiIii
   if ( oOOOOOo0 and I1IIiIIIii . is_rtr ( ) == False ) : continue
   if 43 - 43: OOooOOo
   o0o000Oo . rloc_set = [ I1IIiIIIii ]
   o0o000Oo . build_best_rloc_set ( )
   lisp_write_ipc_map_cache ( True , o0o000Oo )
   if 79 - 79: iII111i % Oo0Ooo . i1IIi % ooOoO0o
   lprint ( "Update {} map-cache entry with RLE {}" . format ( green ( o0o000Oo . print_eid_tuple ( ) , False ) ,
   # OoOoOO00 . IiII + i1IIi * OOooOOo % I11i * i11iIiiIii
 I1IIiIIIii . rle . print_rle ( False , True ) ) )
   if 76 - 76: iIii1I11I1II1 * OoooooooOO % oO0o * O0 - i11iIiiIii + OoO0O00
   if 19 - 19: i1IIi
 return
 if 53 - 53: OOooOOo * O0 . iII111i
 if 3 - 3: OoooooooOO * I1Ii111 * IiII - OOooOOo * I1Ii111
 if 78 - 78: iII111i
 if 80 - 80: i1IIi * I1IiiI + OOooOOo
 if 91 - 91: I1IiiI % OoOoOO00 * Oo0Ooo / I1ii11iIi11i
 if 57 - 57: i11iIiiIii / o0oOOo0O0Ooo . II111iiii
 if 63 - 63: O0
 if 64 - 64: i11iIiiIii / oO0o . oO0o - Oo0Ooo
def lisp_process_map_notify ( lisp_sockets , orig_packet , source ) :
 Ii1ii1 = lisp_map_notify ( "" )
 IiiiIi1iiii11 = Ii1ii1 . decode ( orig_packet )
 if ( IiiiIi1iiii11 == None ) :
  lprint ( "Could not decode Map-Notify packet" )
  return
  if 48 - 48: i1IIi + I1ii11iIi11i + I1Ii111 - iII111i
  if 3 - 3: i1IIi + OoooooooOO * ooOoO0o + I1Ii111 % OOooOOo / IiII
 Ii1ii1 . print_notify ( )
 if 70 - 70: oO0o + i1IIi % o0oOOo0O0Ooo - I11i
 if 74 - 74: i11iIiiIii
 if 93 - 93: I1Ii111 % OOooOOo * I1IiiI % iII111i / iIii1I11I1II1 + OoO0O00
 if 6 - 6: I11i
 if 70 - 70: ooOoO0o + OoooooooOO % OoOoOO00 % oO0o / Ii1I . I11i
 IiII1iiI = source . print_address ( )
 if ( Ii1ii1 . alg_id != 0 or Ii1ii1 . auth_len != 0 ) :
  ii1iOo = None
  for Oo000O000 in lisp_map_servers_list :
   if ( Oo000O000 . find ( IiII1iiI ) == - 1 ) : continue
   ii1iOo = lisp_map_servers_list [ Oo000O000 ]
   if 63 - 63: I1ii11iIi11i - ooOoO0o . OOooOOo / O0 . iIii1I11I1II1 - Ii1I
  if ( ii1iOo == None ) :
   lprint ( ( "  Could not find Map-Server {} to authenticate " + "Map-Notify" ) . format ( IiII1iiI ) )
   if 6 - 6: Ii1I
   return
   if 60 - 60: iII111i + I1IiiI
   if 36 - 36: i1IIi . O0 . OoO0O00 % OOooOOo * I11i / Ii1I
  ii1iOo . map_notifies_received += 1
  if 16 - 16: Oo0Ooo
  I1iiIIiIII1i = lisp_verify_auth ( IiiiIi1iiii11 , Ii1ii1 . alg_id ,
 Ii1ii1 . auth_data , ii1iOo . password )
  if 44 - 44: iIii1I11I1II1 - II111iiii . IiII . i1IIi
  lprint ( "  Authentication {} for Map-Notify" . format ( "succeeded" if I1iiIIiIII1i else "failed" ) )
  if 37 - 37: OoooooooOO + Oo0Ooo - Oo0Ooo + I1ii11iIi11i . I1Ii111 / I1IiiI
  if ( I1iiIIiIII1i == False ) : return
 else :
  ii1iOo = lisp_ms ( IiII1iiI , None , "" , 0 , "" , False , False , False , False , 0 , 0 , 0 ,
 None )
  if 60 - 60: I1IiiI % Ii1I / I1Ii111 + Ii1I
  if 43 - 43: I1ii11iIi11i + I11i
  if 83 - 83: II111iiii + o0oOOo0O0Ooo - I1Ii111
  if 100 - 100: IiII - OoOoOO00 / I11i
  if 33 - 33: I1Ii111 * OoOoOO00 . I1ii11iIi11i % I1Ii111
  if 87 - 87: Oo0Ooo
 i1ii = Ii1ii1 . eid_records
 if ( Ii1ii1 . record_count == 0 ) :
  lisp_send_map_notify_ack ( lisp_sockets , i1ii , Ii1ii1 , ii1iOo )
  return
  if 65 - 65: ooOoO0o . I1IiiI
  if 51 - 51: IiII
  if 43 - 43: oO0o - I11i . i11iIiiIii
  if 78 - 78: i11iIiiIii + Oo0Ooo * Ii1I - o0oOOo0O0Ooo % i11iIiiIii
  if 30 - 30: I1IiiI % oO0o * OoooooooOO
  if 64 - 64: I1IiiI
  if 11 - 11: I1ii11iIi11i % iII111i / II111iiii % ooOoO0o % IiII
  if 14 - 14: ooOoO0o / IiII . o0oOOo0O0Ooo
 i111iII = lisp_eid_record ( )
 IiiiIi1iiii11 = i111iII . decode ( i1ii )
 if ( IiiiIi1iiii11 == None ) : return
 if 27 - 27: I1IiiI - OOooOOo . II111iiii * I1ii11iIi11i % ooOoO0o / I1IiiI
 i111iII . print_record ( "  " , False )
 if 90 - 90: o0oOOo0O0Ooo / I1ii11iIi11i - oO0o - Ii1I - I1IiiI + I1Ii111
 for OO00O0O in range ( i111iII . rloc_count ) :
  I1Ii11iI = lisp_rloc_record ( )
  IiiiIi1iiii11 = I1Ii11iI . decode ( IiiiIi1iiii11 , None )
  if ( IiiiIi1iiii11 == None ) :
   lprint ( "  Could not decode RLOC-record in Map-Notify packet" )
   return
   if 93 - 93: I1IiiI - I11i . I1IiiI - iIii1I11I1II1
  I1Ii11iI . print_record ( "    " )
  if 1 - 1: O0 . Ii1I % Ii1I + II111iiii . oO0o
  if 24 - 24: o0oOOo0O0Ooo . I1Ii111 % O0
  if 67 - 67: I1IiiI * Ii1I
  if 64 - 64: OOooOOo
  if 90 - 90: iII111i . OoOoOO00 + i1IIi % ooOoO0o * I11i + OoooooooOO
 if ( i111iII . group . is_null ( ) == False ) :
  if 2 - 2: o0oOOo0O0Ooo . II111iiii
  if 9 - 9: I1Ii111 - II111iiii + OoOoOO00 . OoO0O00
  if 33 - 33: Oo0Ooo
  if 12 - 12: i11iIiiIii . Oo0Ooo / OoOoOO00 + iII111i . Ii1I + ooOoO0o
  if 66 - 66: IiII
  lprint ( "Send {} Map-Notify IPC message to ITR process" . format ( green ( i111iII . print_eid_tuple ( ) , False ) ) )
  if 41 - 41: II111iiii + Oo0Ooo / iII111i . IiII / iII111i / I1IiiI
  if 78 - 78: o0oOOo0O0Ooo % OoOoOO00 . O0
  iiiii1i1 = lisp_control_packet_ipc ( orig_packet , IiII1iiI , "lisp-itr" , 0 )
  lisp_ipc ( iiiii1i1 , lisp_sockets [ 2 ] , "lisp-core-pkt" )
  if 41 - 41: iIii1I11I1II1 . OOooOOo - Oo0Ooo % OOooOOo
  if 90 - 90: i11iIiiIii + OoooooooOO - i11iIiiIii + OoooooooOO
  if 23 - 23: i11iIiiIii - IiII - I1ii11iIi11i + I1ii11iIi11i % I1IiiI
  if 79 - 79: II111iiii / OoooooooOO
  if 35 - 35: i1IIi + IiII + II111iiii % OOooOOo
 lisp_send_map_notify_ack ( lisp_sockets , i1ii , Ii1ii1 , ii1iOo )
 return
 if 25 - 25: I11i + i11iIiiIii + O0 - Ii1I
 if 69 - 69: I11i . OoOoOO00 / OOooOOo / i1IIi . II111iiii
 if 17 - 17: I1Ii111
 if 2 - 2: O0 % OoOoOO00 + oO0o
 if 24 - 24: iII111i + iII111i - OoooooooOO % OoooooooOO * O0
 if 51 - 51: IiII
 if 31 - 31: I11i - iIii1I11I1II1 * Ii1I + Ii1I
 if 10 - 10: OoOoOO00 - i11iIiiIii % iIii1I11I1II1 / ooOoO0o * i11iIiiIii - Ii1I
def lisp_process_map_notify_ack ( packet , source ) :
 Ii1ii1 = lisp_map_notify ( "" )
 packet = Ii1ii1 . decode ( packet )
 if ( packet == None ) :
  lprint ( "Could not decode Map-Notify-Ack packet" )
  return
  if 64 - 64: II111iiii . i11iIiiIii . iII111i . OOooOOo
  if 95 - 95: O0 - OoOoOO00
 Ii1ii1 . print_notify ( )
 if 68 - 68: ooOoO0o . I1Ii111
 if 84 - 84: OoooooooOO + oO0o % i1IIi + o0oOOo0O0Ooo * i1IIi
 if 51 - 51: oO0o . OoooooooOO + OOooOOo * I1ii11iIi11i - ooOoO0o
 if 41 - 41: Oo0Ooo
 if 46 - 46: i11iIiiIii + iIii1I11I1II1 . i11iIiiIii . iII111i
 if ( Ii1ii1 . record_count < 1 ) :
  lprint ( "No EID-prefix found, cannot authenticate Map-Notify-Ack" )
  return
  if 66 - 66: oO0o % i1IIi % OoooooooOO
  if 58 - 58: OOooOOo
 i111iII = lisp_eid_record ( )
 if 89 - 89: iIii1I11I1II1 - i1IIi
 if ( i111iII . decode ( Ii1ii1 . eid_records ) == None ) :
  lprint ( "Could not decode EID-record, cannot authenticate " +
 "Map-Notify-Ack" )
  return
  if 26 - 26: OOooOOo - iII111i * I1ii11iIi11i / iII111i
 i111iII . print_record ( "  " , False )
 if 9 - 9: I1Ii111 / II111iiii * I1Ii111 / I11i - OoO0O00
 I11i11i1 = i111iII . print_eid_tuple ( )
 if 36 - 36: IiII . OoOoOO00 . Ii1I
 if 31 - 31: iIii1I11I1II1
 if 84 - 84: I1ii11iIi11i - iII111i * I1IiiI
 if 88 - 88: OOooOOo / Oo0Ooo
 if ( Ii1ii1 . alg_id != LISP_NONE_ALG_ID and Ii1ii1 . auth_len != 0 ) :
  o0o000 = lisp_sites_by_eid . lookup_cache ( i111iII . eid , True )
  if ( o0o000 == None ) :
   iiiII = bold ( "Site not found" , False )
   lprint ( ( "{} for EID {}, cannot authenticate Map-Notify-Ack" ) . format ( iiiII , green ( I11i11i1 , False ) ) )
   if 31 - 31: II111iiii
   return
   if 32 - 32: o0oOOo0O0Ooo % o0oOOo0O0Ooo
  ooo000O0O = o0o000 . site
  if 67 - 67: IiII + oO0o * IiII
  if 26 - 26: I1ii11iIi11i + i1IIi . i1IIi - oO0o + I1IiiI * o0oOOo0O0Ooo
  if 62 - 62: ooOoO0o + ooOoO0o % I11i
  if 100 - 100: II111iiii . OoooooooOO
  ooo000O0O . map_notify_acks_received += 1
  if 32 - 32: I11i % OOooOOo * O0 / iIii1I11I1II1 / i1IIi
  I1I1I1 = Ii1ii1 . key_id
  if ( ooo000O0O . auth_key . has_key ( I1I1I1 ) ) :
   o0Oooo00oO0o00 = ooo000O0O . auth_key [ I1I1I1 ]
  else :
   o0Oooo00oO0o00 = ""
   if 87 - 87: OoO0O00 . I1ii11iIi11i * I1IiiI
   if 83 - 83: OOooOOo
  I1iiIIiIII1i = lisp_verify_auth ( packet , Ii1ii1 . alg_id ,
 Ii1ii1 . auth_data , o0Oooo00oO0o00 )
  if 86 - 86: I1Ii111 / oO0o
  I1I1I1 = "key-id {}" . format ( I1I1I1 ) if I1I1I1 == Ii1ii1 . key_id else "bad key-id {}" . format ( Ii1ii1 . key_id )
  if 67 - 67: OoOoOO00 + Oo0Ooo / i11iIiiIii . I1IiiI
  if 53 - 53: Oo0Ooo + IiII * ooOoO0o % OoooooooOO * oO0o . iII111i
  lprint ( "  Authentication {} for Map-Notify-Ack, {}" . format ( "succeeded" if I1iiIIiIII1i else "failed" , I1I1I1 ) )
  if 78 - 78: O0 . Ii1I - I1ii11iIi11i
  if ( I1iiIIiIII1i == False ) : return
  if 69 - 69: O0 % O0 . oO0o * OoooooooOO
  if 13 - 13: i1IIi % oO0o . OoooooooOO + I1ii11iIi11i - OOooOOo
  if 99 - 99: OoooooooOO % OOooOOo / I11i
  if 77 - 77: II111iiii - IiII % OOooOOo
  if 22 - 22: OoooooooOO / oO0o
 if ( Ii1ii1 . retransmit_timer ) : Ii1ii1 . retransmit_timer . cancel ( )
 if 78 - 78: oO0o * I11i . i1IIi % i1IIi + i1IIi / OOooOOo
 I1i1i = source . print_address ( )
 Oo000O000 = Ii1ii1 . nonce_key
 if 66 - 66: OoooooooOO % o0oOOo0O0Ooo / I11i * I1Ii111
 if ( lisp_map_notify_queue . has_key ( Oo000O000 ) ) :
  Ii1ii1 = lisp_map_notify_queue . pop ( Oo000O000 )
  if ( Ii1ii1 . retransmit_timer ) : Ii1ii1 . retransmit_timer . cancel ( )
  lprint ( "Dequeue Map-Notify from retransmit queue, key is: {}" . format ( Oo000O000 ) )
  if 12 - 12: I1Ii111
 else :
  lprint ( "Map-Notify with nonce 0x{} queue entry not found for {}" . format ( Ii1ii1 . nonce_key , red ( I1i1i , False ) ) )
  if 17 - 17: I1Ii111 % oO0o + O0
  if 15 - 15: o0oOOo0O0Ooo - OoooooooOO % ooOoO0o % oO0o / i11iIiiIii / Oo0Ooo
 return
 if 59 - 59: iII111i + O0 - I1ii11iIi11i * I1ii11iIi11i + iIii1I11I1II1
 if 41 - 41: iIii1I11I1II1 . O0 - ooOoO0o / OoOoOO00 % iIii1I11I1II1 + IiII
 if 23 - 23: OoOoOO00 + ooOoO0o . i11iIiiIii
 if 39 - 39: OoOoOO00 - I1ii11iIi11i / I1Ii111
 if 48 - 48: IiII - oO0o + I11i % o0oOOo0O0Ooo
 if 81 - 81: Oo0Ooo . I1Ii111 * iIii1I11I1II1
 if 60 - 60: OoooooooOO
 if 41 - 41: iIii1I11I1II1 + O0 % o0oOOo0O0Ooo - IiII . I11i * O0
def lisp_map_referral_loop ( mr , eid , group , action , s ) :
 if ( action not in ( LISP_DDT_ACTION_NODE_REFERRAL ,
 LISP_DDT_ACTION_MS_REFERRAL ) ) : return ( False )
 if 39 - 39: i11iIiiIii . Ii1I
 if ( mr . last_cached_prefix [ 0 ] == None ) : return ( False )
 if 68 - 68: OOooOOo * ooOoO0o . I1IiiI - iII111i
 if 81 - 81: I11i % Oo0Ooo / iII111i
 if 44 - 44: Oo0Ooo
 if 90 - 90: Oo0Ooo . ooOoO0o / IiII * I1Ii111 . ooOoO0o + II111iiii
 OOOoOoOO0oo = False
 if ( group . is_null ( ) == False ) :
  OOOoOoOO0oo = mr . last_cached_prefix [ 1 ] . is_more_specific ( group )
  if 43 - 43: iIii1I11I1II1 % OOooOOo + OoOoOO00 + I1ii11iIi11i - Oo0Ooo / Ii1I
 if ( OOOoOoOO0oo == False ) :
  OOOoOoOO0oo = mr . last_cached_prefix [ 0 ] . is_more_specific ( eid )
  if 94 - 94: Ii1I / Oo0Ooo % II111iiii % Oo0Ooo * oO0o
  if 54 - 54: O0 / ooOoO0o * I1Ii111
 if ( OOOoOoOO0oo ) :
  iIIiIIiII111 = lisp_print_eid_tuple ( eid , group )
  I1II1 = lisp_print_eid_tuple ( mr . last_cached_prefix [ 0 ] ,
 mr . last_cached_prefix [ 1 ] )
  if 7 - 7: Oo0Ooo . IiII + I1ii11iIi11i
  lprint ( ( "Map-Referral prefix {} from {} is not more-specific " + "than cached prefix {}" ) . format ( green ( iIIiIIiII111 , False ) , s ,
  # O0 * I11i % OOooOOo
 I1II1 ) )
  if 28 - 28: I1IiiI . OOooOOo
 return ( OOOoOoOO0oo )
 if 27 - 27: ooOoO0o + o0oOOo0O0Ooo . i11iIiiIii * i1IIi % I11i - IiII
 if 99 - 99: OoO0O00 * oO0o / Ii1I + OoO0O00
 if 57 - 57: iIii1I11I1II1 + I1Ii111 % oO0o - Ii1I . I1IiiI
 if 39 - 39: OoO0O00 + II111iiii
 if 98 - 98: O0 - I1Ii111 % oO0o - iII111i + Ii1I * i1IIi
 if 76 - 76: o0oOOo0O0Ooo
 if 55 - 55: OOooOOo + I1ii11iIi11i * Oo0Ooo
def lisp_process_map_referral ( lisp_sockets , packet , source ) :
 if 11 - 11: i1IIi - OoooooooOO * OoOoOO00 / oO0o - OoooooooOO - I1IiiI
 iiII1IiIi1i = lisp_map_referral ( )
 packet = iiII1IiIi1i . decode ( packet )
 if ( packet == None ) :
  lprint ( "Could not decode Map-Referral packet" )
  return
  if 22 - 22: i11iIiiIii . Ii1I . Oo0Ooo * Oo0Ooo - iII111i / I1ii11iIi11i
 iiII1IiIi1i . print_map_referral ( )
 if 49 - 49: iII111i + I11i . Oo0Ooo
 IiII1iiI = source . print_address ( )
 Iii11I = iiII1IiIi1i . nonce
 if 23 - 23: I1IiiI . Ii1I + ooOoO0o . OoooooooOO
 if 57 - 57: OOooOOo / OoOoOO00 / i11iIiiIii - I11i - I11i . Ii1I
 if 53 - 53: ooOoO0o . iII111i + Ii1I * I1Ii111
 if 49 - 49: II111iiii . I1ii11iIi11i * OoOoOO00 - OOooOOo
 for IiIIi1IiiIiI in range ( iiII1IiIi1i . record_count ) :
  i111iII = lisp_eid_record ( )
  packet = i111iII . decode ( packet )
  if ( packet == None ) :
   lprint ( "Could not decode EID-record in Map-Referral packet" )
   return
   if 48 - 48: OoO0O00 . iIii1I11I1II1 - OoooooooOO + I1Ii111 / i11iIiiIii . Oo0Ooo
  i111iII . print_record ( "  " , True )
  if 61 - 61: II111iiii + OOooOOo . o0oOOo0O0Ooo . iIii1I11I1II1
  if 63 - 63: I11i + i11iIiiIii . o0oOOo0O0Ooo . i1IIi + OoOoOO00
  if 1 - 1: i11iIiiIii
  if 1 - 1: iIii1I11I1II1
  Oo000O000 = str ( Iii11I )
  if ( Oo000O000 not in lisp_ddt_map_requestQ ) :
   lprint ( ( "Map-Referral nonce 0x{} from {} not found in " + "Map-Request queue, EID-record ignored" ) . format ( lisp_hex_string ( Iii11I ) , IiII1iiI ) )
   if 73 - 73: iII111i + IiII
   if 95 - 95: O0
   continue
   if 75 - 75: ooOoO0o
  I1I1iiii111II = lisp_ddt_map_requestQ [ Oo000O000 ]
  if ( I1I1iiii111II == None ) :
   lprint ( ( "No Map-Request queue entry found for Map-Referral " +
 "nonce 0x{} from {}, EID-record ignored" ) . format ( lisp_hex_string ( Iii11I ) , IiII1iiI ) )
   if 8 - 8: O0 - OoooooooOO + I1ii11iIi11i / Oo0Ooo . oO0o + I1Ii111
   continue
   if 85 - 85: ooOoO0o
   if 29 - 29: iII111i . Ii1I
   if 43 - 43: I11i - I1ii11iIi11i + iIii1I11I1II1 / I1ii11iIi11i * oO0o / iIii1I11I1II1
   if 45 - 45: IiII
   if 49 - 49: I1IiiI . Ii1I * I1IiiI - OoooooooOO . I11i / I1Ii111
   if 9 - 9: iIii1I11I1II1 * Ii1I / O0 - OOooOOo
  if ( lisp_map_referral_loop ( I1I1iiii111II , i111iII . eid , i111iII . group ,
 i111iII . action , IiII1iiI ) ) :
   I1I1iiii111II . dequeue_map_request ( )
   continue
   if 95 - 95: i11iIiiIii * II111iiii * OOooOOo * iIii1I11I1II1
   if 22 - 22: iIii1I11I1II1 / I1IiiI + OoOoOO00 - OOooOOo . i11iIiiIii / i11iIiiIii
  I1I1iiii111II . last_cached_prefix [ 0 ] = i111iII . eid
  I1I1iiii111II . last_cached_prefix [ 1 ] = i111iII . group
  if 10 - 10: iIii1I11I1II1 % i1IIi
  if 78 - 78: I11i + II111iiii % o0oOOo0O0Ooo
  if 17 - 17: i11iIiiIii + oO0o * iII111i . II111iiii
  if 44 - 44: I1ii11iIi11i
  iI1I11II = False
  oo0oooo00OOO = lisp_referral_cache_lookup ( i111iII . eid , i111iII . group ,
 True )
  if ( oo0oooo00OOO == None ) :
   iI1I11II = True
   oo0oooo00OOO = lisp_referral ( )
   oo0oooo00OOO . eid = i111iII . eid
   oo0oooo00OOO . group = i111iII . group
   if ( i111iII . ddt_incomplete == False ) : oo0oooo00OOO . add_cache ( )
  elif ( oo0oooo00OOO . referral_source . not_set ( ) ) :
   lprint ( "Do not replace static referral entry {}" . format ( green ( oo0oooo00OOO . print_eid_tuple ( ) , False ) ) )
   if 39 - 39: iII111i + Oo0Ooo / oO0o
   I1I1iiii111II . dequeue_map_request ( )
   continue
   if 95 - 95: I1Ii111 * oO0o / ooOoO0o . Ii1I . OoOoOO00
   if 99 - 99: I1IiiI * II111iiii
  I11I1iI = i111iII . action
  oo0oooo00OOO . referral_source = source
  oo0oooo00OOO . referral_type = I11I1iI
  oOoooOOO0o0 = i111iII . store_ttl ( )
  oo0oooo00OOO . referral_ttl = oOoooOOO0o0
  oo0oooo00OOO . expires = lisp_set_timestamp ( oOoooOOO0o0 )
  if 84 - 84: II111iiii - I1IiiI
  if 41 - 41: iIii1I11I1II1 % I1Ii111 % OoOoOO00
  if 35 - 35: I11i + i1IIi
  if 85 - 85: Ii1I * Ii1I . OoOoOO00 / Oo0Ooo
  oOo000oOoO = oo0oooo00OOO . is_referral_negative ( )
  if ( oo0oooo00OOO . referral_set . has_key ( IiII1iiI ) ) :
   iiI111I = oo0oooo00OOO . referral_set [ IiII1iiI ]
   if 65 - 65: I11i % OoooooooOO
   if ( iiI111I . updown == False and oOo000oOoO == False ) :
    iiI111I . updown = True
    lprint ( "Change up/down status for referral-node {} to up" . format ( IiII1iiI ) )
    if 11 - 11: I1IiiI + IiII
   elif ( iiI111I . updown == True and oOo000oOoO == True ) :
    iiI111I . updown = False
    lprint ( ( "Change up/down status for referral-node {} " + "to down, received negative referral" ) . format ( IiII1iiI ) )
    if 97 - 97: i1IIi * ooOoO0o
    if 18 - 18: i1IIi . I1IiiI % I1IiiI / iII111i + Ii1I * o0oOOo0O0Ooo
    if 97 - 97: Ii1I % I1IiiI % iIii1I11I1II1 * Ii1I . i1IIi
    if 70 - 70: i1IIi . oO0o - oO0o . I1Ii111
    if 68 - 68: I1Ii111 . iIii1I11I1II1 * O0
    if 75 - 75: iII111i - Oo0Ooo / OoooooooOO - O0
    if 36 - 36: OoO0O00 % Ii1I . Oo0Ooo
    if 90 - 90: i11iIiiIii - iII111i * oO0o
  oOo0OooOoooO = { }
  for Oo000O000 in oo0oooo00OOO . referral_set : oOo0OooOoooO [ Oo000O000 ] = None
  if 23 - 23: I1IiiI % iIii1I11I1II1 - oO0o - iII111i - o0oOOo0O0Ooo
  if 39 - 39: Oo0Ooo . OoO0O00
  if 74 - 74: I1IiiI . O0 . IiII + IiII - IiII
  if 100 - 100: ooOoO0o / OoooooooOO
  for IiIIi1IiiIiI in range ( i111iII . rloc_count ) :
   I1Ii11iI = lisp_rloc_record ( )
   packet = I1Ii11iI . decode ( packet , None )
   if ( packet == None ) :
    lprint ( "Could not decode RLOC-record in Map-Referral packet" )
    return
    if 73 - 73: i11iIiiIii - Oo0Ooo
   I1Ii11iI . print_record ( "    " )
   if 100 - 100: iIii1I11I1II1 + I1Ii111
   if 51 - 51: o0oOOo0O0Ooo * I11i
   if 42 - 42: OOooOOo % I11i
   if 84 - 84: Oo0Ooo * OoOoOO00 / Ii1I / IiII / o0oOOo0O0Ooo . I1ii11iIi11i
   oo0o00OO = I1Ii11iI . rloc . print_address ( )
   if ( oo0oooo00OOO . referral_set . has_key ( oo0o00OO ) == False ) :
    iiI111I = lisp_referral_node ( )
    iiI111I . referral_address . copy_address ( I1Ii11iI . rloc )
    oo0oooo00OOO . referral_set [ oo0o00OO ] = iiI111I
    if ( IiII1iiI == oo0o00OO and oOo000oOoO ) : iiI111I . updown = False
   else :
    iiI111I = oo0oooo00OOO . referral_set [ oo0o00OO ]
    if ( oOo0OooOoooO . has_key ( oo0o00OO ) ) : oOo0OooOoooO . pop ( oo0o00OO )
    if 81 - 81: I1IiiI
   iiI111I . priority = I1Ii11iI . priority
   iiI111I . weight = I1Ii11iI . weight
   if 82 - 82: I1Ii111 - OoooooooOO - Ii1I
   if 34 - 34: OOooOOo . iIii1I11I1II1 / I1IiiI . Oo0Ooo - iIii1I11I1II1
   if 83 - 83: iII111i - I1ii11iIi11i + iII111i
   if 4 - 4: o0oOOo0O0Ooo % iIii1I11I1II1 + I11i
   if 60 - 60: I1ii11iIi11i / I1Ii111 % i11iIiiIii % oO0o % I1IiiI . Oo0Ooo
  for Oo000O000 in oOo0OooOoooO : oo0oooo00OOO . referral_set . pop ( Oo000O000 )
  if 20 - 20: IiII - OOooOOo + OoOoOO00
  I11i11i1 = oo0oooo00OOO . print_eid_tuple ( )
  if 83 - 83: OoooooooOO / I1IiiI + iII111i - iIii1I11I1II1 % ooOoO0o
  if ( iI1I11II ) :
   if ( i111iII . ddt_incomplete ) :
    lprint ( "Suppress add {} to referral-cache" . format ( green ( I11i11i1 , False ) ) )
    if 74 - 74: OoO0O00
   else :
    lprint ( "Add {}, referral-count {} to referral-cache" . format ( green ( I11i11i1 , False ) , i111iII . rloc_count ) )
    if 13 - 13: I1ii11iIi11i / OoO0O00
    if 90 - 90: iIii1I11I1II1 - OoO0O00 . i1IIi / o0oOOo0O0Ooo + O0
  else :
   lprint ( "Replace {}, referral-count: {} in referral-cache" . format ( green ( I11i11i1 , False ) , i111iII . rloc_count ) )
   if 94 - 94: IiII * i1IIi
   if 90 - 90: O0 % I1IiiI . o0oOOo0O0Ooo % ooOoO0o % I1IiiI
   if 16 - 16: OoO0O00 / OOooOOo / iIii1I11I1II1 / OoooooooOO . oO0o - I1Ii111
   if 43 - 43: OoOoOO00 % OOooOOo / I1IiiI + I1IiiI
   if 40 - 40: OOooOOo . I1Ii111 + I1Ii111
   if 4 - 4: iIii1I11I1II1 - iIii1I11I1II1 * I11i
  if ( I11I1iI == LISP_DDT_ACTION_DELEGATION_HOLE ) :
   lisp_send_negative_map_reply ( I1I1iiii111II . lisp_sockets , oo0oooo00OOO . eid ,
 oo0oooo00OOO . group , I1I1iiii111II . nonce , I1I1iiii111II . itr , I1I1iiii111II . sport , 15 , None , False )
   I1I1iiii111II . dequeue_map_request ( )
   if 32 - 32: I1IiiI + II111iiii * iII111i + O0 / O0 * Oo0Ooo
   if 64 - 64: i11iIiiIii / iII111i + i11iIiiIii . I11i
  if ( I11I1iI == LISP_DDT_ACTION_NOT_AUTH ) :
   if ( I1I1iiii111II . tried_root ) :
    lisp_send_negative_map_reply ( I1I1iiii111II . lisp_sockets , oo0oooo00OOO . eid ,
 oo0oooo00OOO . group , I1I1iiii111II . nonce , I1I1iiii111II . itr , I1I1iiii111II . sport , 0 , None , False )
    I1I1iiii111II . dequeue_map_request ( )
   else :
    lisp_send_ddt_map_request ( I1I1iiii111II , True )
    if 66 - 66: i1IIi
    if 98 - 98: Oo0Ooo / iIii1I11I1II1
    if 33 - 33: O0 - iII111i
  if ( I11I1iI == LISP_DDT_ACTION_MS_NOT_REG ) :
   if ( oo0oooo00OOO . referral_set . has_key ( IiII1iiI ) ) :
    iiI111I = oo0oooo00OOO . referral_set [ IiII1iiI ]
    iiI111I . updown = False
    if 40 - 40: iII111i * I11i
   if ( len ( oo0oooo00OOO . referral_set ) == 0 ) :
    I1I1iiii111II . dequeue_map_request ( )
   else :
    lisp_send_ddt_map_request ( I1I1iiii111II , False )
    if 25 - 25: O0 * o0oOOo0O0Ooo % ooOoO0o % I1IiiI
    if 87 - 87: OoOoOO00
    if 30 - 30: IiII % OoOoOO00 + I1Ii111
  if ( I11I1iI in ( LISP_DDT_ACTION_NODE_REFERRAL ,
 LISP_DDT_ACTION_MS_REFERRAL ) ) :
   if ( I1I1iiii111II . eid . is_exact_match ( i111iII . eid ) ) :
    if ( not I1I1iiii111II . tried_root ) :
     lisp_send_ddt_map_request ( I1I1iiii111II , True )
    else :
     lisp_send_negative_map_reply ( I1I1iiii111II . lisp_sockets ,
 oo0oooo00OOO . eid , oo0oooo00OOO . group , I1I1iiii111II . nonce , I1I1iiii111II . itr ,
 I1I1iiii111II . sport , 15 , None , False )
     I1I1iiii111II . dequeue_map_request ( )
     if 13 - 13: iII111i * Ii1I % o0oOOo0O0Ooo * i1IIi . IiII % i1IIi
   else :
    lisp_send_ddt_map_request ( I1I1iiii111II , False )
    if 79 - 79: OoooooooOO % I11i / o0oOOo0O0Ooo + IiII + O0 + iII111i
    if 87 - 87: I11i
    if 39 - 39: I1ii11iIi11i * i11iIiiIii % I1Ii111
  if ( I11I1iI == LISP_DDT_ACTION_MS_ACK ) : I1I1iiii111II . dequeue_map_request ( )
  if 72 - 72: OoO0O00 * Oo0Ooo - IiII
 return
 if 74 - 74: Ii1I
 if 26 - 26: I11i . O0
 if 68 - 68: Ii1I
 if 26 - 26: o0oOOo0O0Ooo - I1ii11iIi11i / O0 % i11iIiiIii
 if 7 - 7: I1Ii111 . Oo0Ooo + IiII / iIii1I11I1II1
 if 22 - 22: iIii1I11I1II1 - O0 . iII111i - IiII - ooOoO0o
 if 54 - 54: OoO0O00 . iII111i . OoOoOO00 * OoO0O00 + o0oOOo0O0Ooo . ooOoO0o
 if 44 - 44: I11i * iIii1I11I1II1 . I1ii11iIi11i
def lisp_process_ecm ( lisp_sockets , packet , source , ecm_port ) :
 I1iiiIII11ii1i1i1 = lisp_ecm ( 0 )
 packet = I1iiiIII11ii1i1i1 . decode ( packet )
 if ( packet == None ) :
  lprint ( "Could not decode ECM packet" )
  return
  if 9 - 9: o0oOOo0O0Ooo
  if 23 - 23: ooOoO0o * OoO0O00 + O0 % I1Ii111
 I1iiiIII11ii1i1i1 . print_ecm ( )
 if 21 - 21: Ii1I * OoOoOO00
 O0ooOoO0 = lisp_control_header ( )
 if ( O0ooOoO0 . decode ( packet ) == None ) :
  lprint ( "Could not decode control header" )
  return
  if 29 - 29: iIii1I11I1II1 / ooOoO0o
  if 75 - 75: OoooooooOO + I1IiiI % OoOoOO00 / O0 - IiII
 oO0ooooooOo = O0ooOoO0 . type
 del ( O0ooOoO0 )
 if 18 - 18: I11i
 if ( oO0ooooooOo != LISP_MAP_REQUEST ) :
  lprint ( "Received ECM without Map-Request inside" )
  return
  if 95 - 95: I1IiiI / OoooooooOO
  if 29 - 29: OoOoOO00
  if 100 - 100: o0oOOo0O0Ooo - I1IiiI / I11i
  if 43 - 43: o0oOOo0O0Ooo % iIii1I11I1II1
  if 85 - 85: oO0o + OoooooooOO - IiII % o0oOOo0O0Ooo * ooOoO0o * II111iiii
 I1iIi1I1I11iI = I1iiiIII11ii1i1i1 . udp_sport
 oooooo0ooo0O = time . time ( )
 lisp_process_map_request ( lisp_sockets , packet , source , ecm_port ,
 I1iiiIII11ii1i1i1 . source , I1iIi1I1I11iI , I1iiiIII11ii1i1i1 . ddt , - 1 , oooooo0ooo0O )
 return
 if 27 - 27: i1IIi + I1IiiI . i1IIi
 if 81 - 81: Ii1I * IiII / OoO0O00 . iII111i % I11i . ooOoO0o
 if 63 - 63: Oo0Ooo * I1Ii111 % Ii1I
 if 88 - 88: IiII - i1IIi * OoO0O00 * OoOoOO00 % I1IiiI
 if 10 - 10: OOooOOo * I1ii11iIi11i / I11i * o0oOOo0O0Ooo % O0 * i11iIiiIii
 if 68 - 68: I11i . Ii1I + I11i / IiII . I11i / iIii1I11I1II1
 if 96 - 96: O0
 if 2 - 2: OoO0O00 / iII111i + o0oOOo0O0Ooo
 if 27 - 27: I11i - OoOoOO00 - ooOoO0o - I1IiiI
 if 51 - 51: I11i + I11i + O0 + O0 * I1Ii111
def lisp_send_map_register ( lisp_sockets , packet , map_register , ms ) :
 if 61 - 61: IiII . O0
 if 38 - 38: Ii1I * I1ii11iIi11i - i11iIiiIii + ooOoO0o * I11i
 if 74 - 74: OoOoOO00 . o0oOOo0O0Ooo
 if 40 - 40: ooOoO0o + I1ii11iIi11i * i11iIiiIii / i1IIi
 if 95 - 95: oO0o / IiII * II111iiii * Ii1I . OoO0O00 . OoO0O00
 if 85 - 85: I1IiiI / II111iiii * OoO0O00 + ooOoO0o / OoO0O00 % OOooOOo
 if 100 - 100: I1Ii111 % OoooooooOO % OoOoOO00 % I1IiiI
 oo0OoO = ms . map_server
 if ( lisp_decent_push_configured and oo0OoO . is_multicast_address ( ) and
 ( ms . map_registers_multicast_sent == 1 or ms . map_registers_sent == 1 ) ) :
  oo0OoO = copy . deepcopy ( oo0OoO )
  oo0OoO . address = 0x7f000001
  I11i1iIiiIiIi = bold ( "Bootstrap" , False )
  i11ii = ms . map_server . print_address_no_iid ( )
  lprint ( "{} mapping system for peer-group {}" . format ( I11i1iIiiIiIi , i11ii ) )
  if 32 - 32: OoO0O00 + OOooOOo . OoO0O00 - Oo0Ooo
  if 12 - 12: I1IiiI * OoO0O00 - II111iiii . i1IIi
  if 86 - 86: OOooOOo / OoooooooOO - IiII
  if 56 - 56: I1ii11iIi11i - i1IIi * OoooooooOO * O0 * I1IiiI - I1Ii111
  if 32 - 32: OoooooooOO . OOooOOo . OoO0O00 . IiII / I11i % i1IIi
  if 21 - 21: O0 . OoO0O00 * I1ii11iIi11i % iII111i + OoooooooOO
 packet = lisp_compute_auth ( packet , map_register , ms . password )
 if 8 - 8: oO0o * iII111i * I11i
 if 30 - 30: I1Ii111
 if 61 - 61: iII111i
 if 50 - 50: Ii1I / I1IiiI . O0
 if 49 - 49: I1Ii111 . OoO0O00 % O0
 if ( ms . ekey != None ) :
  II11iI11i1 = ms . ekey . zfill ( 32 )
  iiI1iiIiiiI1I = "0" * 8
  o0 = chacha . ChaCha ( II11iI11i1 , iiI1iiIiiiI1I ) . encrypt ( packet [ 4 : : ] )
  packet = packet [ 0 : 4 ] + o0
  oOo = bold ( "Encrypt" , False )
  lprint ( "{} Map-Register with key-id {}" . format ( oOo , ms . ekey_id ) )
  if 15 - 15: I11i - Oo0Ooo / I1Ii111 . ooOoO0o % I1IiiI
  if 62 - 62: II111iiii + ooOoO0o + I1IiiI
 OOo00OO = ""
 if ( lisp_decent_pull_xtr_configured ( ) ) :
  OOo00OO = ", decent-index {}" . format ( bold ( ms . dns_name , False ) )
  if 76 - 76: ooOoO0o % O0 . I1ii11iIi11i
  if 97 - 97: oO0o - Oo0Ooo . i11iIiiIii % ooOoO0o * i11iIiiIii - OoooooooOO
 lprint ( "Send Map-Register to map-server {}{}{}" . format ( oo0OoO . print_address ( ) , ", ms-name '{}'" . format ( ms . ms_name ) , OOo00OO ) )
 if 44 - 44: I11i % OoooooooOO / iII111i - i11iIiiIii * i1IIi * o0oOOo0O0Ooo
 lisp_send ( lisp_sockets , oo0OoO , LISP_CTRL_PORT , packet )
 return
 if 51 - 51: Ii1I + IiII / I1ii11iIi11i + O0 % Ii1I
 if 55 - 55: iII111i % o0oOOo0O0Ooo - oO0o % OoooooooOO
 if 18 - 18: OoooooooOO - I1ii11iIi11i
 if 94 - 94: OOooOOo . Oo0Ooo + Ii1I * o0oOOo0O0Ooo
 if 79 - 79: OOooOOo + Oo0Ooo
 if 33 - 33: iIii1I11I1II1
 if 75 - 75: I1Ii111 / iIii1I11I1II1 . OoooooooOO
 if 98 - 98: iIii1I11I1II1 / I1IiiI + i1IIi
def lisp_send_ipc_to_core ( lisp_socket , packet , dest , port ) :
 i1IIi1ii1i1ii = lisp_socket . getsockname ( )
 dest = dest . print_address_no_iid ( )
 if 80 - 80: II111iiii . Oo0Ooo * oO0o % II111iiii / I1ii11iIi11i
 lprint ( "Send IPC {} bytes to {} {}, control-packet: {}" . format ( len ( packet ) , dest , port , lisp_format_packet ( packet ) ) )
 if 66 - 66: iII111i / OoO0O00 / i11iIiiIii
 if 99 - 99: OOooOOo
 packet = lisp_control_packet_ipc ( packet , i1IIi1ii1i1ii , dest , port )
 lisp_ipc ( packet , lisp_socket , "lisp-core-pkt" )
 return
 if 51 - 51: i11iIiiIii . o0oOOo0O0Ooo / iII111i
 if 53 - 53: oO0o / i1IIi - Oo0Ooo - i1IIi + IiII
 if 79 - 79: oO0o % o0oOOo0O0Ooo / o0oOOo0O0Ooo % iII111i
 if 56 - 56: Oo0Ooo % I1ii11iIi11i
 if 53 - 53: OoO0O00 . I11i - ooOoO0o
 if 11 - 11: I11i + i11iIiiIii / oO0o % oO0o * o0oOOo0O0Ooo / OoOoOO00
 if 74 - 74: oO0o . I1Ii111 . II111iiii
 if 92 - 92: I1Ii111 % OoooooooOO * I1Ii111
def lisp_send_map_reply ( lisp_sockets , packet , dest , port ) :
 lprint ( "Send Map-Reply to {}" . format ( dest . print_address_no_iid ( ) ) )
 lisp_send_ipc_to_core ( lisp_sockets [ 2 ] , packet , dest , port )
 return
 if 78 - 78: Oo0Ooo . I11i . oO0o + O0 / O0
 if 41 - 41: iII111i * OoO0O00 - OoO0O00
 if 72 - 72: o0oOOo0O0Ooo + oO0o . I1ii11iIi11i + OoO0O00 / I1Ii111
 if 58 - 58: Oo0Ooo / II111iiii % OoooooooOO % II111iiii
 if 39 - 39: i1IIi
 if 16 - 16: OoOoOO00 % iIii1I11I1II1 + Ii1I - o0oOOo0O0Ooo . Oo0Ooo + i1IIi
 if 59 - 59: i1IIi
 if 37 - 37: OoO0O00 / I1ii11iIi11i / OoOoOO00
def lisp_send_map_referral ( lisp_sockets , packet , dest , port ) :
 lprint ( "Send Map-Referral to {}" . format ( dest . print_address ( ) ) )
 lisp_send_ipc_to_core ( lisp_sockets [ 2 ] , packet , dest , port )
 return
 if 15 - 15: I1IiiI % iIii1I11I1II1 . I1Ii111
 if 71 - 71: I11i - Ii1I + i11iIiiIii % I1ii11iIi11i - OoO0O00 - OOooOOo
 if 71 - 71: OOooOOo
 if 27 - 27: OOooOOo * O0 * i11iIiiIii / OoOoOO00 - i1IIi
 if 73 - 73: iII111i / I1IiiI * ooOoO0o
 if 85 - 85: I11i + I11i + oO0o - OoOoOO00
 if 15 - 15: OoO0O00
 if 88 - 88: Ii1I % i1IIi / I1Ii111
def lisp_send_map_notify ( lisp_sockets , packet , dest , port ) :
 lprint ( "Send Map-Notify to xTR {}" . format ( dest . print_address ( ) ) )
 lisp_send_ipc_to_core ( lisp_sockets [ 2 ] , packet , dest , port )
 return
 if 2 - 2: Ii1I . IiII % OoOoOO00
 if 42 - 42: OoOoOO00 * OoO0O00 * IiII - IiII % Oo0Ooo . IiII
 if 38 - 38: I1Ii111 . IiII - ooOoO0o . i11iIiiIii
 if 35 - 35: i11iIiiIii
 if 62 - 62: O0 - o0oOOo0O0Ooo + I1Ii111 * I1ii11iIi11i / OOooOOo
 if 87 - 87: Oo0Ooo / OoooooooOO + O0 / o0oOOo0O0Ooo % II111iiii - O0
 if 63 - 63: OOooOOo - OoO0O00 * i1IIi - I1ii11iIi11i . I1IiiI
def lisp_send_ecm ( lisp_sockets , packet , inner_source , inner_sport , inner_dest ,
 outer_dest , to_etr = False , to_ms = False , ddt = False ) :
 if 59 - 59: i11iIiiIii . OOooOOo % Oo0Ooo + O0
 if ( inner_source == None or inner_source . is_null ( ) ) :
  inner_source = inner_dest
  if 84 - 84: I1Ii111 / O0 - IiII . I11i / o0oOOo0O0Ooo
  if 12 - 12: i11iIiiIii / Ii1I + i1IIi
  if 54 - 54: I1IiiI
  if 55 - 55: I1ii11iIi11i % IiII % o0oOOo0O0Ooo + i1IIi * OoooooooOO % II111iiii
  if 37 - 37: Oo0Ooo
  if 33 - 33: OoooooooOO - O0 . O0 - o0oOOo0O0Ooo % o0oOOo0O0Ooo % OoO0O00
 if ( lisp_nat_traversal ) :
  oo0O = lisp_get_any_translated_port ( )
  if ( oo0O != None ) : inner_sport = oo0O
  if 27 - 27: ooOoO0o . i11iIiiIii / o0oOOo0O0Ooo * OoO0O00 * OoOoOO00 * oO0o
 I1iiiIII11ii1i1i1 = lisp_ecm ( inner_sport )
 if 19 - 19: O0 * II111iiii * OoOoOO00
 I1iiiIII11ii1i1i1 . to_etr = to_etr if lisp_is_running ( "lisp-etr" ) else False
 I1iiiIII11ii1i1i1 . to_ms = to_ms if lisp_is_running ( "lisp-ms" ) else False
 I1iiiIII11ii1i1i1 . ddt = ddt
 ooo000 = I1iiiIII11ii1i1i1 . encode ( packet , inner_source , inner_dest )
 if ( ooo000 == None ) :
  lprint ( "Could not encode ECM message" )
  return
  if 40 - 40: oO0o
 I1iiiIII11ii1i1i1 . print_ecm ( )
 if 31 - 31: Oo0Ooo * iIii1I11I1II1 * Ii1I * Ii1I
 packet = ooo000 + packet
 if 23 - 23: oO0o + OoO0O00 * O0
 oo0o00OO = outer_dest . print_address_no_iid ( )
 lprint ( "Send Encapsulated-Control-Message to {}" . format ( oo0o00OO ) )
 oo0OoO = lisp_convert_4to6 ( oo0o00OO )
 lisp_send ( lisp_sockets , oo0OoO , LISP_CTRL_PORT , packet )
 return
 if 99 - 99: oO0o * IiII * oO0o
 if 70 - 70: IiII + iII111i / I1ii11iIi11i
 if 97 - 97: I1IiiI * OoOoOO00 / iII111i * i11iIiiIii
 if 20 - 20: Ii1I . I11i % iII111i * iIii1I11I1II1 . OoO0O00 . Ii1I
 if 50 - 50: I1IiiI % OOooOOo / iIii1I11I1II1 / I1ii11iIi11i % oO0o . Ii1I
 if 14 - 14: oO0o / Ii1I - I1Ii111
 if 79 - 79: I1Ii111
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
if 54 - 54: II111iiii
LISP_RLOC_UNKNOWN_STATE = 0
LISP_RLOC_UP_STATE = 1
LISP_RLOC_DOWN_STATE = 2
LISP_RLOC_UNREACH_STATE = 3
LISP_RLOC_NO_ECHOED_NONCE_STATE = 4
LISP_RLOC_ADMIN_DOWN_STATE = 5
if 98 - 98: Ii1I - i11iIiiIii
LISP_AUTH_NONE = 0
LISP_AUTH_MD5 = 1
LISP_AUTH_SHA1 = 2
LISP_AUTH_SHA2 = 3
if 31 - 31: IiII / o0oOOo0O0Ooo
if 27 - 27: Oo0Ooo
if 32 - 32: Oo0Ooo * i11iIiiIii % I1IiiI - i11iIiiIii - I1Ii111 % I1ii11iIi11i
if 35 - 35: o0oOOo0O0Ooo % iII111i / O0 * I1IiiI . o0oOOo0O0Ooo / OOooOOo
if 81 - 81: I1ii11iIi11i - i11iIiiIii
if 49 - 49: iII111i * I11i - II111iiii . o0oOOo0O0Ooo
if 52 - 52: Ii1I + Ii1I - II111iiii . O0 + I1ii11iIi11i
LISP_IPV4_HOST_MASK_LEN = 32
LISP_IPV6_HOST_MASK_LEN = 128
LISP_MAC_HOST_MASK_LEN = 48
LISP_E164_HOST_MASK_LEN = 60
if 60 - 60: i11iIiiIii + IiII
if 41 - 41: I1Ii111 * o0oOOo0O0Ooo + Oo0Ooo
if 86 - 86: Ii1I / oO0o
if 40 - 40: OoO0O00 % oO0o + Oo0Ooo
if 60 - 60: II111iiii / Ii1I
if 14 - 14: iII111i - Oo0Ooo / o0oOOo0O0Ooo * oO0o / Oo0Ooo - I1IiiI
def byte_swap_64 ( address ) :
 IiiIIi1 = ( ( address & 0x00000000000000ff ) << 56 ) | ( ( address & 0x000000000000ff00 ) << 40 ) | ( ( address & 0x0000000000ff0000 ) << 24 ) | ( ( address & 0x00000000ff000000 ) << 8 ) | ( ( address & 0x000000ff00000000 ) >> 8 ) | ( ( address & 0x0000ff0000000000 ) >> 24 ) | ( ( address & 0x00ff000000000000 ) >> 40 ) | ( ( address & 0xff00000000000000 ) >> 56 )
 if 89 - 89: i1IIi / I1Ii111 + Ii1I - i1IIi
 if 66 - 66: OoooooooOO
 if 68 - 68: iII111i + I1Ii111
 if 90 - 90: o0oOOo0O0Ooo
 if 48 - 48: iII111i + Ii1I
 if 45 - 45: oO0o / iIii1I11I1II1 % O0 % IiII % I1ii11iIi11i
 if 89 - 89: OOooOOo - I1Ii111 - iII111i
 if 67 - 67: oO0o
 return ( IiiIIi1 )
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
class lisp_cache_entries ( ) :
 def __init__ ( self ) :
  self . entries = { }
  self . entries_sorted = [ ]
  if 39 - 39: IiII
  if 18 - 18: iII111i % o0oOOo0O0Ooo - i1IIi
  if 53 - 53: o0oOOo0O0Ooo + IiII - ooOoO0o % i11iIiiIii - i11iIiiIii - I1Ii111
class lisp_cache ( ) :
 def __init__ ( self ) :
  self . cache = { }
  self . cache_sorted = [ ]
  self . cache_count = 0
  if 79 - 79: II111iiii + i11iIiiIii . OOooOOo . I11i / iIii1I11I1II1
  if 62 - 62: O0
 def cache_size ( self ) :
  return ( self . cache_count )
  if 52 - 52: OoooooooOO . oO0o
  if 38 - 38: ooOoO0o . i1IIi / iII111i + I1IiiI - II111iiii
 def build_key ( self , prefix ) :
  if ( prefix . afi == LISP_AFI_ULTIMATE_ROOT ) :
   OOoOOO = 0
  elif ( prefix . afi == LISP_AFI_IID_RANGE ) :
   OOoOOO = prefix . mask_len
  else :
   OOoOOO = prefix . mask_len + 48
   if 21 - 21: i11iIiiIii + II111iiii - i1IIi / OoooooooOO * OOooOOo % Oo0Ooo
   if 59 - 59: Ii1I
  o0OoO0000o = lisp_hex_string ( prefix . instance_id ) . zfill ( 8 )
  O0ooo0 = lisp_hex_string ( prefix . afi ) . zfill ( 4 )
  if 77 - 77: I1ii11iIi11i * Ii1I * O0 * I1IiiI % OoO0O00 - iIii1I11I1II1
  if ( prefix . afi > 0 ) :
   if ( prefix . is_binary ( ) ) :
    IiiI1iii1iIiiI = prefix . addr_length ( ) * 2
    IiiIIi1 = lisp_hex_string ( prefix . address ) . zfill ( IiiI1iii1iIiiI )
   else :
    IiiIIi1 = prefix . address
    if 6 - 6: i11iIiiIii . I11i - OoooooooOO
  elif ( prefix . afi == LISP_AFI_GEO_COORD ) :
   O0ooo0 = "8003"
   IiiIIi1 = prefix . address . print_geo ( )
  else :
   O0ooo0 = ""
   IiiIIi1 = ""
   if 26 - 26: I1IiiI
   if 26 - 26: IiII . Ii1I / IiII - OoO0O00 % OoO0O00
  Oo000O000 = o0OoO0000o + O0ooo0 + IiiIIi1
  return ( [ OOoOOO , Oo000O000 ] )
  if 72 - 72: OoooooooOO * II111iiii + OoO0O00 % iIii1I11I1II1 . I1ii11iIi11i % OoooooooOO
  if 19 - 19: OoOoOO00 + I1Ii111
 def add_cache ( self , prefix , entry ) :
  if ( prefix . is_binary ( ) ) : prefix . zero_host_bits ( )
  OOoOOO , Oo000O000 = self . build_key ( prefix )
  if ( self . cache . has_key ( OOoOOO ) == False ) :
   self . cache [ OOoOOO ] = lisp_cache_entries ( )
   self . cache [ OOoOOO ] . entries = { }
   self . cache [ OOoOOO ] . entries_sorted = [ ]
   self . cache_sorted = sorted ( self . cache )
   if 19 - 19: I1ii11iIi11i / I1Ii111 + OoooooooOO - O0
  if ( self . cache [ OOoOOO ] . entries . has_key ( Oo000O000 ) == False ) :
   self . cache_count += 1
   if 49 - 49: I1ii11iIi11i / OoOoOO00 - I1IiiI + iII111i . OOooOOo % oO0o
  self . cache [ OOoOOO ] . entries [ Oo000O000 ] = entry
  self . cache [ OOoOOO ] . entries_sorted = sorted ( self . cache [ OOoOOO ] . entries )
  if 34 - 34: OoO0O00 - I1IiiI + OoOoOO00
  if 22 - 22: iIii1I11I1II1 . i1IIi . OOooOOo % Oo0Ooo - i1IIi
 def lookup_cache ( self , prefix , exact ) :
  Oo0o , Oo000O000 = self . build_key ( prefix )
  if ( exact ) :
   if ( self . cache . has_key ( Oo0o ) == False ) : return ( None )
   if ( self . cache [ Oo0o ] . entries . has_key ( Oo000O000 ) == False ) : return ( None )
   return ( self . cache [ Oo0o ] . entries [ Oo000O000 ] )
   if 80 - 80: I1IiiI % Ii1I
   if 29 - 29: i1IIi % o0oOOo0O0Ooo + OOooOOo / Oo0Ooo
  ooOoOO0o = None
  for OOoOOO in self . cache_sorted :
   if ( Oo0o < OOoOOO ) : return ( ooOoOO0o )
   for i1OO0OO0oO0o000 in self . cache [ OOoOOO ] . entries_sorted :
    Oo0O0Oo0oo = self . cache [ OOoOOO ] . entries
    if ( i1OO0OO0oO0o000 in Oo0O0Oo0oo ) :
     i1ii1i1Ii11 = Oo0O0Oo0oo [ i1OO0OO0oO0o000 ]
     if ( i1ii1i1Ii11 == None ) : continue
     if ( prefix . is_more_specific ( i1ii1i1Ii11 . eid ) ) : ooOoOO0o = i1ii1i1Ii11
     if 92 - 92: i1IIi
     if 3 - 3: iIii1I11I1II1 . I1ii11iIi11i
     if 97 - 97: O0
  return ( ooOoOO0o )
  if 82 - 82: OoooooooOO / I1Ii111 - ooOoO0o . I1Ii111
  if 41 - 41: I11i . I11i
 def delete_cache ( self , prefix ) :
  OOoOOO , Oo000O000 = self . build_key ( prefix )
  if ( self . cache . has_key ( OOoOOO ) == False ) : return
  if ( self . cache [ OOoOOO ] . entries . has_key ( Oo000O000 ) == False ) : return
  self . cache [ OOoOOO ] . entries . pop ( Oo000O000 )
  self . cache [ OOoOOO ] . entries_sorted . remove ( Oo000O000 )
  self . cache_count -= 1
  if 12 - 12: OoOoOO00 / I1IiiI
  if 4 - 4: Oo0Ooo * o0oOOo0O0Ooo
 def walk_cache ( self , function , parms ) :
  for OOoOOO in self . cache_sorted :
   for Oo000O000 in self . cache [ OOoOOO ] . entries_sorted :
    i1ii1i1Ii11 = self . cache [ OOoOOO ] . entries [ Oo000O000 ]
    I111I1iiIi1 , parms = function ( i1ii1i1Ii11 , parms )
    if ( I111I1iiIi1 == False ) : return ( parms )
    if 71 - 71: Ii1I + OOooOOo + i1IIi
    if 72 - 72: OoooooooOO - IiII . O0 + OoooooooOO + I11i
  return ( parms )
  if 11 - 11: OoOoOO00 + ooOoO0o
  if 56 - 56: OoooooooOO - IiII + IiII
 def print_cache ( self ) :
  lprint ( "Printing contents of {}: " . format ( self ) )
  if ( self . cache_size ( ) == 0 ) :
   lprint ( "  Cache is empty" )
   return
   if 33 - 33: I1ii11iIi11i * i11iIiiIii
  for OOoOOO in self . cache_sorted :
   for Oo000O000 in self . cache [ OOoOOO ] . entries_sorted :
    i1ii1i1Ii11 = self . cache [ OOoOOO ] . entries [ Oo000O000 ]
    lprint ( "  Mask-length: {}, key: {}, entry: {}" . format ( OOoOOO , Oo000O000 ,
 i1ii1i1Ii11 ) )
    if 62 - 62: oO0o + I11i . OOooOOo . OoO0O00
    if 94 - 94: oO0o - o0oOOo0O0Ooo / I1ii11iIi11i . IiII - II111iiii - ooOoO0o
    if 92 - 92: OoooooooOO + O0 * OOooOOo
    if 1 - 1: O0
    if 34 - 34: o0oOOo0O0Ooo * i1IIi + I1Ii111
    if 46 - 46: IiII / i11iIiiIii
    if 51 - 51: OoO0O00 - OoO0O00 + o0oOOo0O0Ooo * iII111i % II111iiii
    if 7 - 7: O0 * OoO0O00 % IiII
lisp_referral_cache = lisp_cache ( )
lisp_ddt_cache = lisp_cache ( )
lisp_sites_by_eid = lisp_cache ( )
lisp_map_cache = lisp_cache ( )
lisp_db_for_lookups = lisp_cache ( )
if 76 - 76: iII111i - i1IIi
if 62 - 62: Ii1I + O0 % I1IiiI
if 44 - 44: i11iIiiIii
if 21 - 21: OOooOOo
if 15 - 15: I1ii11iIi11i + oO0o
if 99 - 99: oO0o - ooOoO0o - II111iiii * OoooooooOO / O0
if 57 - 57: iIii1I11I1II1 / IiII + OoO0O00 * oO0o + Ii1I
def lisp_map_cache_lookup ( source , dest ) :
 if 76 - 76: i11iIiiIii . OOooOOo / I11i * oO0o % iIii1I11I1II1 . ooOoO0o
 o0oO0O00 = dest . is_multicast_address ( )
 if 75 - 75: O0 + I1IiiI
 if 67 - 67: OoOoOO00 % OoooooooOO / OoO0O00 - OoO0O00 / O0
 if 19 - 19: iIii1I11I1II1 / OOooOOo % I11i % I1IiiI / I1ii11iIi11i
 if 73 - 73: II111iiii
 o0o000Oo = lisp_map_cache . lookup_cache ( dest , False )
 if ( o0o000Oo == None ) :
  I11i11i1 = source . print_sg ( dest ) if o0oO0O00 else dest . print_address ( )
  I11i11i1 = green ( I11i11i1 , False )
  dprint ( "Lookup for EID {} not found in map-cache" . format ( I11i11i1 ) )
  return ( None )
  if 26 - 26: II111iiii . iIii1I11I1II1 - I1Ii111 % OOooOOo
  if 83 - 83: OOooOOo + OoooooooOO % I1Ii111 % IiII + i11iIiiIii
  if 10 - 10: OoooooooOO . Ii1I % I1Ii111 + IiII
  if 78 - 78: OoOoOO00 - oO0o . I1ii11iIi11i * i11iIiiIii
  if 44 - 44: iIii1I11I1II1 * iII111i
 if ( o0oO0O00 == False ) :
  i1iI11i = green ( o0o000Oo . eid . print_prefix ( ) , False )
  dprint ( "Lookup for EID {} found map-cache entry {}" . format ( green ( dest . print_address ( ) , False ) , i1iI11i ) )
  if 32 - 32: OoOoOO00
  return ( o0o000Oo )
  if 65 - 65: iIii1I11I1II1 + iII111i
  if 90 - 90: i11iIiiIii - Oo0Ooo
  if 31 - 31: OoOoOO00 + OoOoOO00 + OoooooooOO % O0
  if 14 - 14: i1IIi / OoooooooOO . I1IiiI * I1Ii111 + OoO0O00
  if 45 - 45: OoooooooOO * I1Ii111
 o0o000Oo = o0o000Oo . lookup_source_cache ( source , False )
 if ( o0o000Oo == None ) :
  I11i11i1 = source . print_sg ( dest )
  dprint ( "Lookup for EID {} not found in map-cache" . format ( I11i11i1 ) )
  return ( None )
  if 7 - 7: O0
  if 42 - 42: o0oOOo0O0Ooo / Ii1I
  if 31 - 31: OOooOOo
  if 20 - 20: i11iIiiIii * oO0o * ooOoO0o
  if 65 - 65: I1ii11iIi11i / Oo0Ooo / I1IiiI + IiII
 i1iI11i = green ( o0o000Oo . print_eid_tuple ( ) , False )
 dprint ( "Lookup for EID {} found map-cache entry {}" . format ( green ( source . print_sg ( dest ) , False ) , i1iI11i ) )
 if 71 - 71: OoO0O00 . I1Ii111 + OoooooooOO
 return ( o0o000Oo )
 if 9 - 9: OoooooooOO / iIii1I11I1II1 % I1IiiI . I1IiiI / I11i - iII111i
 if 60 - 60: I11i - OoO0O00 - OoOoOO00 * ooOoO0o - i1IIi
 if 18 - 18: ooOoO0o + i11iIiiIii + O0 + OOooOOo / Ii1I
 if 65 - 65: I1IiiI . ooOoO0o
 if 51 - 51: I1Ii111
 if 89 - 89: Oo0Ooo
 if 15 - 15: OOooOOo * II111iiii - OOooOOo * iIii1I11I1II1
def lisp_referral_cache_lookup ( eid , group , exact ) :
 if ( group and group . is_null ( ) ) :
  IiII111IiII1 = lisp_referral_cache . lookup_cache ( eid , exact )
  return ( IiII111IiII1 )
  if 95 - 95: I1Ii111 / OoooooooOO * I11i * OoooooooOO
  if 88 - 88: I1IiiI / Oo0Ooo / oO0o + oO0o % OOooOOo + Oo0Ooo
  if 63 - 63: o0oOOo0O0Ooo + i11iIiiIii % OOooOOo % iIii1I11I1II1 / I1ii11iIi11i - iII111i
  if 72 - 72: iII111i % oO0o . IiII + I1ii11iIi11i . IiII . II111iiii
  if 10 - 10: I11i . ooOoO0o + I11i * Ii1I
 if ( eid == None or eid . is_null ( ) ) : return ( None )
 if 55 - 55: OOooOOo / iII111i + OoooooooOO - OoooooooOO
 if 51 - 51: O0 % Ii1I % Oo0Ooo - O0
 if 94 - 94: OoooooooOO - ooOoO0o % I1ii11iIi11i + I1Ii111
 if 51 - 51: I1ii11iIi11i . iII111i / i1IIi * ooOoO0o % I11i
 if 82 - 82: O0 % OoOoOO00 . iII111i . i1IIi . iII111i - Oo0Ooo
 if 58 - 58: O0 * OOooOOo
 IiII111IiII1 = lisp_referral_cache . lookup_cache ( group , exact )
 if ( IiII111IiII1 == None ) : return ( None )
 if 60 - 60: ooOoO0o
 iiIIII = IiII111IiII1 . lookup_source_cache ( eid , exact )
 if ( iiIIII ) : return ( iiIIII )
 if 11 - 11: i1IIi
 if ( exact ) : IiII111IiII1 = None
 return ( IiII111IiII1 )
 if 77 - 77: I11i + i1IIi * OoOoOO00 % OoooooooOO
 if 56 - 56: I1Ii111 * i1IIi % i11iIiiIii
 if 56 - 56: Ii1I . iII111i
 if 76 - 76: I1IiiI / Ii1I % OoOoOO00 + IiII / i11iIiiIii . o0oOOo0O0Ooo
 if 31 - 31: oO0o * oO0o % o0oOOo0O0Ooo . O0 + iII111i
 if 52 - 52: i11iIiiIii
 if 1 - 1: i1IIi * iIii1I11I1II1
def lisp_ddt_cache_lookup ( eid , group , exact ) :
 if ( group . is_null ( ) ) :
  IIIIii11i1I = lisp_ddt_cache . lookup_cache ( eid , exact )
  return ( IIIIii11i1I )
  if 29 - 29: I11i
  if 12 - 12: oO0o % i1IIi - oO0o / ooOoO0o * II111iiii % ooOoO0o
  if 6 - 6: IiII / OoO0O00
  if 83 - 83: IiII - iIii1I11I1II1 * ooOoO0o - oO0o
  if 77 - 77: Ii1I
 if ( eid . is_null ( ) ) : return ( None )
 if 9 - 9: OOooOOo / OoooooooOO + iII111i
 if 52 - 52: IiII / OOooOOo * iIii1I11I1II1 + o0oOOo0O0Ooo
 if 20 - 20: I1Ii111
 if 33 - 33: i11iIiiIii / I1Ii111 + IiII / II111iiii + I11i
 if 13 - 13: i1IIi % iII111i + OoOoOO00 / Ii1I . Ii1I + II111iiii
 if 44 - 44: OoOoOO00 / OoooooooOO % O0 * Ii1I * IiII
 IIIIii11i1I = lisp_ddt_cache . lookup_cache ( group , exact )
 if ( IIIIii11i1I == None ) : return ( None )
 if 84 - 84: o0oOOo0O0Ooo * IiII * OOooOOo * iII111i
 O0oooo0oO00O = IIIIii11i1I . lookup_source_cache ( eid , exact )
 if ( O0oooo0oO00O ) : return ( O0oooo0oO00O )
 if 52 - 52: Ii1I
 if ( exact ) : IIIIii11i1I = None
 return ( IIIIii11i1I )
 if 97 - 97: OOooOOo * i1IIi + OoOoOO00 . Oo0Ooo
 if 5 - 5: I1ii11iIi11i + IiII + I1ii11iIi11i
 if 28 - 28: Ii1I % o0oOOo0O0Ooo * IiII
 if 20 - 20: OoOoOO00 / I11i * O0 + Ii1I - OoOoOO00 % ooOoO0o
 if 99 - 99: o0oOOo0O0Ooo / i1IIi * OOooOOo % iII111i
 if 18 - 18: iII111i * i1IIi / II111iiii / Oo0Ooo
 if 47 - 47: Ii1I / i1IIi - iII111i - i11iIiiIii
def lisp_site_eid_lookup ( eid , group , exact ) :
 if 3 - 3: OoOoOO00
 if ( group . is_null ( ) ) :
  o0o000 = lisp_sites_by_eid . lookup_cache ( eid , exact )
  return ( o0o000 )
  if 53 - 53: II111iiii / II111iiii . O0 - oO0o . i1IIi
  if 45 - 45: OoOoOO00 + I1Ii111 + Oo0Ooo
  if 73 - 73: OoO0O00 / o0oOOo0O0Ooo % Ii1I * ooOoO0o
  if 94 - 94: I1IiiI . iII111i - iIii1I11I1II1 . Oo0Ooo
  if 40 - 40: Ii1I
 if ( eid . is_null ( ) ) : return ( None )
 if 26 - 26: OoO0O00 / IiII
 if 31 - 31: Ii1I / OoO0O00 % ooOoO0o / I11i . I1ii11iIi11i
 if 41 - 41: I1ii11iIi11i * ooOoO0o * I11i + O0 * O0 - O0
 if 81 - 81: I1Ii111 % OoO0O00 / O0
 if 55 - 55: i1IIi - I1Ii111 + I11i
 if 93 - 93: I1IiiI % IiII . OoOoOO00 + iII111i
 o0o000 = lisp_sites_by_eid . lookup_cache ( group , exact )
 if ( o0o000 == None ) : return ( None )
 if 81 - 81: ooOoO0o / I1Ii111 + OOooOOo / Oo0Ooo / OoOoOO00
 if 34 - 34: ooOoO0o * iIii1I11I1II1 % i11iIiiIii * OOooOOo - OOooOOo
 if 63 - 63: Oo0Ooo / oO0o + iII111i % OoooooooOO * I11i
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
 i1I1I = o0o000 . lookup_source_cache ( eid , exact )
 if ( i1I1I ) : return ( i1I1I )
 if 34 - 34: OoooooooOO / iII111i / O0
 if ( exact ) :
  o0o000 = None
 else :
  O0Ii1IiiiI = o0o000 . parent_for_more_specifics
  if ( O0Ii1IiiiI and O0Ii1IiiiI . accept_more_specifics ) :
   if ( group . is_more_specific ( O0Ii1IiiiI . group ) ) : o0o000 = O0Ii1IiiiI
   if 75 - 75: I11i % OOooOOo - OoO0O00 * I11i * IiII
   if 11 - 11: I1ii11iIi11i . O0 - iII111i * IiII . i1IIi . iII111i
 return ( o0o000 )
 if 82 - 82: i1IIi * I11i * Ii1I - IiII . i11iIiiIii
 if 40 - 40: OOooOOo - OoooooooOO
 if 36 - 36: i1IIi % OoOoOO00 - i1IIi
 if 5 - 5: I1IiiI . I1IiiI % II111iiii - I1Ii111
 if 97 - 97: I11i . ooOoO0o
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
class lisp_address ( ) :
 def __init__ ( self , afi , addr_str , mask_len , iid ) :
  self . afi = afi
  self . mask_len = mask_len
  self . instance_id = iid
  self . iid_list = [ ]
  self . address = 0
  if ( addr_str != "" ) : self . store_address ( addr_str )
  if 18 - 18: OoO0O00 - OoO0O00 . o0oOOo0O0Ooo
  if 80 - 80: I11i + I1Ii111 / I1IiiI * OOooOOo % iII111i
 def copy_address ( self , addr ) :
  if ( addr == None ) : return
  self . afi = addr . afi
  self . address = addr . address
  self . mask_len = addr . mask_len
  self . instance_id = addr . instance_id
  self . iid_list = addr . iid_list
  if 48 - 48: iIii1I11I1II1 + i1IIi . I1IiiI % OoO0O00 - iIii1I11I1II1 / i1IIi
  if 14 - 14: IiII . I11i
 def make_default_route ( self , addr ) :
  self . afi = addr . afi
  self . instance_id = addr . instance_id
  self . mask_len = 0
  self . address = 0
  if 13 - 13: OoOoOO00 - I11i . OOooOOo % OoO0O00
  if 79 - 79: iII111i / Ii1I % i11iIiiIii . I1IiiI % OoO0O00 / i11iIiiIii
 def make_default_multicast_route ( self , addr ) :
  self . afi = addr . afi
  self . instance_id = addr . instance_id
  if ( self . afi == LISP_AFI_IPV4 ) :
   self . address = 0xe0000000
   self . mask_len = 4
   if 100 - 100: OOooOOo + Oo0Ooo . iIii1I11I1II1 . ooOoO0o * Oo0Ooo
  if ( self . afi == LISP_AFI_IPV6 ) :
   self . address = 0xff << 120
   self . mask_len = 8
   if 16 - 16: Oo0Ooo % OoOoOO00 + I1Ii111 % I1Ii111
  if ( self . afi == LISP_AFI_MAC ) :
   self . address = 0xffffffffffff
   self . mask_len = 48
   if 12 - 12: I1Ii111 . Ii1I / iIii1I11I1II1 + i1IIi
   if 9 - 9: iIii1I11I1II1
   if 75 - 75: I11i . II111iiii * I1IiiI * IiII
 def not_set ( self ) :
  return ( self . afi == LISP_AFI_NONE )
  if 36 - 36: OOooOOo / I1ii11iIi11i / oO0o / ooOoO0o / I11i
  if 7 - 7: OoO0O00 - I11i - o0oOOo0O0Ooo / o0oOOo0O0Ooo + i11iIiiIii
 def is_private_address ( self ) :
  if ( self . is_ipv4 ( ) == False ) : return ( False )
  IiiIIi1 = self . address
  if ( ( ( IiiIIi1 & 0xff000000 ) >> 24 ) == 10 ) : return ( True )
  if ( ( ( IiiIIi1 & 0xff000000 ) >> 24 ) == 172 ) :
   IIi1IiiIiiI = ( IiiIIi1 & 0x00ff0000 ) >> 16
   if ( IIi1IiiIiiI >= 16 and IIi1IiiIiiI <= 31 ) : return ( True )
   if 47 - 47: II111iiii / o0oOOo0O0Ooo * o0oOOo0O0Ooo + oO0o
  if ( ( ( IiiIIi1 & 0xffff0000 ) >> 16 ) == 0xc0a8 ) : return ( True )
  return ( False )
  if 3 - 3: Oo0Ooo
  if 82 - 82: OoooooooOO + OoO0O00 . OoO0O00 * OoO0O00
 def is_multicast_address ( self ) :
  if ( self . is_ipv4 ( ) ) : return ( self . is_ipv4_multicast ( ) )
  if ( self . is_ipv6 ( ) ) : return ( self . is_ipv6_multicast ( ) )
  if ( self . is_mac ( ) ) : return ( self . is_mac_multicast ( ) )
  return ( False )
  if 99 - 99: I1ii11iIi11i - OoooooooOO - Ii1I / Oo0Ooo
  if 96 - 96: o0oOOo0O0Ooo . II111iiii
 def host_mask_len ( self ) :
  if ( self . afi == LISP_AFI_IPV4 ) : return ( LISP_IPV4_HOST_MASK_LEN )
  if ( self . afi == LISP_AFI_IPV6 ) : return ( LISP_IPV6_HOST_MASK_LEN )
  if ( self . afi == LISP_AFI_MAC ) : return ( LISP_MAC_HOST_MASK_LEN )
  if ( self . afi == LISP_AFI_E164 ) : return ( LISP_E164_HOST_MASK_LEN )
  if ( self . afi == LISP_AFI_NAME ) : return ( len ( self . address ) * 8 )
  if ( self . afi == LISP_AFI_GEO_COORD ) :
   return ( len ( self . address . print_geo ( ) ) * 8 )
   if 14 - 14: OoooooooOO - i1IIi / i11iIiiIii - OOooOOo - i11iIiiIii . ooOoO0o
  return ( 0 )
  if 8 - 8: oO0o * O0 - II111iiii + I1IiiI
  if 85 - 85: OoooooooOO % i11iIiiIii / IiII % OoOoOO00 + O0
 def is_iana_eid ( self ) :
  if ( self . is_ipv6 ( ) == False ) : return ( False )
  IiiIIi1 = self . address >> 96
  return ( IiiIIi1 == 0x20010005 )
  if 6 - 6: OoooooooOO
  if 97 - 97: II111iiii + o0oOOo0O0Ooo * II111iiii
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
   if 17 - 17: o0oOOo0O0Ooo / ooOoO0o + i1IIi
  return ( 0 )
  if 78 - 78: iIii1I11I1II1 * o0oOOo0O0Ooo * Oo0Ooo - OoO0O00 / OoO0O00
  if 89 - 89: o0oOOo0O0Ooo % o0oOOo0O0Ooo
 def afi_to_version ( self ) :
  if ( self . afi == LISP_AFI_IPV4 ) : return ( 4 )
  if ( self . afi == LISP_AFI_IPV6 ) : return ( 6 )
  return ( 0 )
  if 8 - 8: Ii1I % oO0o - o0oOOo0O0Ooo
  if 14 - 14: OOooOOo * IiII
 def packet_format ( self ) :
  if 15 - 15: o0oOOo0O0Ooo + OoooooooOO - OOooOOo - o0oOOo0O0Ooo . iIii1I11I1II1 / Ii1I
  if 33 - 33: OoO0O00
  if 91 - 91: I11i % I11i % iII111i
  if 19 - 19: I11i / I11i + I1IiiI * OoO0O00 - iII111i . Oo0Ooo
  if 76 - 76: iII111i % OOooOOo / OoooooooOO . I1IiiI % OoO0O00 % i1IIi
  if ( self . afi == LISP_AFI_IPV4 ) : return ( "I" )
  if ( self . afi == LISP_AFI_IPV6 ) : return ( "QQ" )
  if ( self . afi == LISP_AFI_MAC ) : return ( "HHH" )
  if ( self . afi == LISP_AFI_E164 ) : return ( "II" )
  if ( self . afi == LISP_AFI_LCAF ) : return ( "I" )
  return ( "" )
  if 95 - 95: Oo0Ooo - O0 / I1ii11iIi11i . I1IiiI / o0oOOo0O0Ooo % OoOoOO00
  if 38 - 38: OoOoOO00 % OoooooooOO . oO0o - OoooooooOO + I11i
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
   Ii11III = IiiIIi1 & 0xffff
   IiiiIi1iiii11 = struct . pack ( i1I1iii1I11II , ooOo0O0 , ooo0 , Ii11III )
  elif ( self . is_e164 ( ) ) :
   IiiIIi1 = self . address
   ooOo0O0 = ( IiiIIi1 >> 32 ) & 0xffffffff
   ooo0 = ( IiiIIi1 & 0xffffffff )
   IiiiIi1iiii11 = struct . pack ( i1I1iii1I11II , ooOo0O0 , ooo0 )
  elif ( self . is_dist_name ( ) ) :
   IiiiIi1iiii11 += self . address + "\0"
   if 42 - 42: oO0o % OoOoOO00 - oO0o + I11i / i11iIiiIii
  return ( IiiiIi1iiii11 )
  if 74 - 74: OoO0O00 - II111iiii - ooOoO0o % i1IIi
  if 42 - 42: i11iIiiIii / O0
 def unpack_address ( self , packet ) :
  i1I1iii1I11II = self . packet_format ( )
  Iiiii = struct . calcsize ( i1I1iii1I11II )
  if ( len ( packet ) < Iiiii ) : return ( None )
  if 8 - 8: I1Ii111
  IiiIIi1 = struct . unpack ( i1I1iii1I11II , packet [ : Iiiii ] )
  if 51 - 51: i11iIiiIii
  if ( self . is_ipv4 ( ) ) :
   self . address = socket . ntohl ( IiiIIi1 [ 0 ] )
   if 1 - 1: iIii1I11I1II1 . i1IIi . i11iIiiIii % I1ii11iIi11i
  elif ( self . is_ipv6 ( ) ) :
   if 58 - 58: i11iIiiIii * i11iIiiIii - OoO0O00
   if 8 - 8: i11iIiiIii * OoOoOO00 . o0oOOo0O0Ooo
   if 27 - 27: I1ii11iIi11i + Ii1I % I1Ii111
   if 20 - 20: Oo0Ooo
   if 33 - 33: oO0o - OoOoOO00 - i11iIiiIii + I1Ii111 + iIii1I11I1II1
   if 2 - 2: OoooooooOO + IiII / iII111i . iIii1I11I1II1 * OoOoOO00
   if 84 - 84: OOooOOo
   if 68 - 68: I1Ii111
   if ( IiiIIi1 [ 0 ] <= 0xffff and ( IiiIIi1 [ 0 ] & 0xff ) == 0 ) :
    OOo00OoOOOOO0 = ( IiiIIi1 [ 0 ] << 48 ) << 64
   else :
    OOo00OoOOOOO0 = byte_swap_64 ( IiiIIi1 [ 0 ] ) << 64
    if 42 - 42: OoooooooOO . i11iIiiIii - I1Ii111 . OOooOOo . I1Ii111 / OoO0O00
   Ii1i1ii = byte_swap_64 ( IiiIIi1 [ 1 ] )
   self . address = OOo00OoOOOOO0 | Ii1i1ii
   if 33 - 33: o0oOOo0O0Ooo - OoOoOO00 / I1Ii111 % iIii1I11I1II1 - ooOoO0o
  elif ( self . is_mac ( ) ) :
   oOiII1i1 = IiiIIi1 [ 0 ]
   ii1III = IiiIIi1 [ 1 ]
   Ii11 = IiiIIi1 [ 2 ]
   self . address = ( oOiII1i1 << 32 ) + ( ii1III << 16 ) + Ii11
   if 51 - 51: iIii1I11I1II1 / oO0o * I1Ii111 + i1IIi
  elif ( self . is_e164 ( ) ) :
   self . address = ( IiiIIi1 [ 0 ] << 32 ) + IiiIIi1 [ 1 ]
   if 96 - 96: Oo0Ooo + oO0o - Oo0Ooo - OoOoOO00 % OOooOOo . iIii1I11I1II1
  elif ( self . is_dist_name ( ) ) :
   packet , self . address = lisp_decode_dist_name ( packet )
   self . mask_len = len ( self . address ) * 8
   Iiiii = 0
   if 93 - 93: iIii1I11I1II1 % OoooooooOO
  packet = packet [ Iiiii : : ]
  return ( packet )
  if 6 - 6: II111iiii / oO0o - OOooOOo . O0 - o0oOOo0O0Ooo
  if 72 - 72: iIii1I11I1II1 / OoooooooOO * ooOoO0o / ooOoO0o % O0 + IiII
 def is_ipv4 ( self ) :
  return ( True if ( self . afi == LISP_AFI_IPV4 ) else False )
  if 96 - 96: iII111i / i11iIiiIii + Oo0Ooo . I1IiiI + iII111i % OoOoOO00
  if 19 - 19: i11iIiiIii . Oo0Ooo . OoOoOO00 - I1IiiI
 def is_ipv4_link_local ( self ) :
  if ( self . is_ipv4 ( ) == False ) : return ( False )
  return ( ( ( self . address >> 16 ) & 0xffff ) == 0xa9fe )
  if 85 - 85: I11i - OoO0O00 % iIii1I11I1II1 . iII111i + ooOoO0o . Oo0Ooo
  if 87 - 87: iII111i
 def is_ipv4_loopback ( self ) :
  if ( self . is_ipv4 ( ) == False ) : return ( False )
  return ( self . address == 0x7f000001 )
  if 86 - 86: IiII - I11i
  if 99 - 99: i1IIi + I1ii11iIi11i
 def is_ipv4_multicast ( self ) :
  if ( self . is_ipv4 ( ) == False ) : return ( False )
  return ( ( ( self . address >> 24 ) & 0xf0 ) == 0xe0 )
  if 24 - 24: ooOoO0o / OoooooooOO % I1ii11iIi11i * ooOoO0o
  if 14 - 14: I1ii11iIi11i + OoO0O00 - I1IiiI - Oo0Ooo
 def is_ipv4_string ( self , addr_str ) :
  return ( addr_str . find ( "." ) != - 1 )
  if 44 - 44: II111iiii / I1ii11iIi11i
  if 39 - 39: OoooooooOO % OoO0O00
 def is_ipv6 ( self ) :
  return ( True if ( self . afi == LISP_AFI_IPV6 ) else False )
  if 83 - 83: OOooOOo % I1IiiI + O0 % OoooooooOO
  if 84 - 84: I11i - Oo0Ooo % ooOoO0o - II111iiii
 def is_ipv6_link_local ( self ) :
  if ( self . is_ipv6 ( ) == False ) : return ( False )
  return ( ( ( self . address >> 112 ) & 0xffff ) == 0xfe80 )
  if 29 - 29: IiII
  if 4 - 4: II111iiii * o0oOOo0O0Ooo - IiII * iII111i
 def is_ipv6_string_link_local ( self , addr_str ) :
  return ( addr_str . find ( "fe80::" ) != - 1 )
  if 91 - 91: I1Ii111 * iII111i * OoO0O00
  if 79 - 79: iII111i + oO0o
 def is_ipv6_loopback ( self ) :
  if ( self . is_ipv6 ( ) == False ) : return ( False )
  return ( self . address == 1 )
  if 19 - 19: I1Ii111 - OOooOOo . ooOoO0o . O0 + II111iiii . OoooooooOO
  if 97 - 97: O0 / OoOoOO00 / ooOoO0o
 def is_ipv6_multicast ( self ) :
  if ( self . is_ipv6 ( ) == False ) : return ( False )
  return ( ( ( self . address >> 120 ) & 0xff ) == 0xff )
  if 11 - 11: II111iiii . i11iIiiIii - Ii1I . IiII
  if 10 - 10: OOooOOo * OoooooooOO
 def is_ipv6_string ( self , addr_str ) :
  return ( addr_str . find ( ":" ) != - 1 )
  if 12 - 12: II111iiii - O0 . i1IIi % oO0o % OoooooooOO
  if 36 - 36: IiII * OoOoOO00 - iIii1I11I1II1 + II111iiii
 def is_mac ( self ) :
  return ( True if ( self . afi == LISP_AFI_MAC ) else False )
  if 65 - 65: I1IiiI * I11i . I1Ii111 % I1ii11iIi11i + O0
  if 91 - 91: OoooooooOO % I1Ii111 * OoO0O00 - OoOoOO00
 def is_mac_multicast ( self ) :
  if ( self . is_mac ( ) == False ) : return ( False )
  return ( ( self . address & 0x010000000000 ) != 0 )
  if 5 - 5: iIii1I11I1II1 * I11i - oO0o % oO0o % o0oOOo0O0Ooo . i1IIi
  if 95 - 95: Oo0Ooo * I1ii11iIi11i + iII111i - o0oOOo0O0Ooo - Oo0Ooo . OoO0O00
 def is_mac_broadcast ( self ) :
  if ( self . is_mac ( ) == False ) : return ( False )
  return ( self . address == 0xffffffffffff )
  if 62 - 62: I11i
  if 58 - 58: I11i . OoOoOO00 + iII111i . iII111i
 def is_mac_string ( self , addr_str ) :
  return ( len ( addr_str ) == 15 and addr_str . find ( "-" ) != - 1 )
  if 43 - 43: I1Ii111 + I1Ii111 % Oo0Ooo % OoO0O00 - ooOoO0o
  if 61 - 61: OoOoOO00 + Ii1I % i11iIiiIii - I1IiiI * OoO0O00 % iIii1I11I1II1
 def is_link_local_multicast ( self ) :
  if ( self . is_ipv4 ( ) ) :
   return ( ( 0xe0ffff00 & self . address ) == 0xe0000000 )
   if 66 - 66: iII111i + i1IIi
  if ( self . is_ipv6 ( ) ) :
   return ( ( self . address >> 112 ) & 0xffff == 0xff02 )
   if 24 - 24: O0 / OoooooooOO - OoOoOO00
  return ( False )
  if 51 - 51: OoO0O00 + o0oOOo0O0Ooo - II111iiii * I11i + Ii1I
  if 16 - 16: I1Ii111 * i1IIi . I1IiiI . OOooOOo % Ii1I - o0oOOo0O0Ooo
 def is_null ( self ) :
  return ( True if ( self . afi == LISP_AFI_NONE ) else False )
  if 89 - 89: Ii1I * I1ii11iIi11i * I1IiiI % iII111i % Ii1I + O0
  if 53 - 53: i11iIiiIii % I1ii11iIi11i
 def is_ultimate_root ( self ) :
  return ( True if self . afi == LISP_AFI_ULTIMATE_ROOT else False )
  if 59 - 59: OOooOOo
  if 61 - 61: OoooooooOO + O0 - i1IIi % oO0o / I1ii11iIi11i
 def is_iid_range ( self ) :
  return ( True if self . afi == LISP_AFI_IID_RANGE else False )
  if 50 - 50: oO0o + II111iiii * OoOoOO00 % OoO0O00 . II111iiii % o0oOOo0O0Ooo
  if 32 - 32: i1IIi / Ii1I + i11iIiiIii % oO0o
 def is_e164 ( self ) :
  return ( True if ( self . afi == LISP_AFI_E164 ) else False )
  if 11 - 11: Ii1I - ooOoO0o % i11iIiiIii / OoooooooOO - O0 - IiII
  if 25 - 25: IiII + O0 + oO0o % iIii1I11I1II1 - II111iiii . I1IiiI
 def is_dist_name ( self ) :
  return ( True if ( self . afi == LISP_AFI_NAME ) else False )
  if 62 - 62: IiII . O0 + oO0o - ooOoO0o * iIii1I11I1II1
  if 8 - 8: I1ii11iIi11i
 def is_geo_prefix ( self ) :
  return ( True if ( self . afi == LISP_AFI_GEO_COORD ) else False )
  if 65 - 65: i11iIiiIii
  if 92 - 92: oO0o * II111iiii + I1Ii111
 def is_binary ( self ) :
  if ( self . is_dist_name ( ) ) : return ( False )
  if ( self . is_geo_prefix ( ) ) : return ( False )
  return ( True )
  if 49 - 49: II111iiii * I1IiiI * O0 / ooOoO0o * IiII
  if 94 - 94: OoO0O00 - I1IiiI * oO0o
 def store_address ( self , addr_str ) :
  if ( self . afi == LISP_AFI_NONE ) : self . string_to_afi ( addr_str )
  if 35 - 35: OOooOOo / i1IIi + OoO0O00
  if 31 - 31: OoO0O00 . i1IIi / OoooooooOO
  if 81 - 81: ooOoO0o . Oo0Ooo . OoOoOO00 + OOooOOo % iII111i - oO0o
  if 68 - 68: iII111i - O0 / Ii1I
  IiIIi1IiiIiI = addr_str . find ( "[" )
  OO00O0O = addr_str . find ( "]" )
  if ( IiIIi1IiiIiI != - 1 and OO00O0O != - 1 ) :
   self . instance_id = int ( addr_str [ IiIIi1IiiIiI + 1 : OO00O0O ] )
   addr_str = addr_str [ OO00O0O + 1 : : ]
   if ( self . is_dist_name ( ) == False ) :
    addr_str = addr_str . replace ( " " , "" )
    if 15 - 15: I1Ii111 / I1ii11iIi11i / I1IiiI % i11iIiiIii + II111iiii . ooOoO0o
    if 74 - 74: o0oOOo0O0Ooo
    if 4 - 4: I1ii11iIi11i * II111iiii - Oo0Ooo % i1IIi % O0 * i11iIiiIii
    if 62 - 62: OoO0O00 * I1Ii111 * Ii1I / ooOoO0o
    if 27 - 27: oO0o . iII111i . oO0o
    if 37 - 37: Oo0Ooo . I1ii11iIi11i / OoooooooOO % ooOoO0o / I1IiiI + ooOoO0o
  if ( self . is_ipv4 ( ) ) :
   I1i11I = addr_str . split ( "." )
   i11II = int ( I1i11I [ 0 ] ) << 24
   i11II += int ( I1i11I [ 1 ] ) << 16
   i11II += int ( I1i11I [ 2 ] ) << 8
   i11II += int ( I1i11I [ 3 ] )
   self . address = i11II
  elif ( self . is_ipv6 ( ) ) :
   if 71 - 71: iIii1I11I1II1 % I1Ii111 % IiII / IiII + iIii1I11I1II1 % i1IIi
   if 93 - 93: Oo0Ooo / I1ii11iIi11i + Oo0Ooo + OOooOOo
   if 58 - 58: oO0o
   if 9 - 9: I1Ii111 - i1IIi . ooOoO0o
   if 33 - 33: I11i
   if 37 - 37: Oo0Ooo
   if 36 - 36: IiII % I11i
   if 72 - 72: oO0o % I11i % OOooOOo * iIii1I11I1II1 - OOooOOo % O0
   if 84 - 84: oO0o - o0oOOo0O0Ooo / II111iiii . o0oOOo0O0Ooo
   if 82 - 82: OoooooooOO
   if 14 - 14: OoO0O00 / oO0o - OOooOOo
   if 100 - 100: IiII - I11i . iIii1I11I1II1 / iIii1I11I1II1
   if 16 - 16: IiII + Oo0Ooo % I11i
   if 16 - 16: ooOoO0o / I1Ii111
   if 78 - 78: OoOoOO00 - II111iiii - OOooOOo + I1IiiI + O0 / I1IiiI
   if 59 - 59: OOooOOo . I1IiiI / i1IIi / II111iiii . II111iiii
   if 54 - 54: iIii1I11I1II1 % ooOoO0o
   IIII1iiIiiI = ( addr_str [ 2 : 4 ] == "::" )
   try :
    addr_str = socket . inet_pton ( socket . AF_INET6 , addr_str )
   except :
    addr_str = socket . inet_pton ( socket . AF_INET6 , "0::0" )
    if 92 - 92: I11i + OoO0O00 . OoooooooOO
   addr_str = binascii . hexlify ( addr_str )
   if 3 - 3: OoO0O00 % iIii1I11I1II1
   if ( IIII1iiIiiI ) :
    addr_str = addr_str [ 2 : 4 ] + addr_str [ 0 : 2 ] + addr_str [ 4 : : ]
    if 62 - 62: OoooooooOO * o0oOOo0O0Ooo
   self . address = int ( addr_str , 16 )
   if 59 - 59: iIii1I11I1II1
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
   if 18 - 18: ooOoO0o % I1IiiI / iIii1I11I1II1 + O0
  self . mask_len = self . host_mask_len ( )
  if 99 - 99: i11iIiiIii - o0oOOo0O0Ooo + o0oOOo0O0Ooo . OoooooooOO * iII111i . Oo0Ooo
  if 63 - 63: I11i
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
   if 60 - 60: I1IiiI / I1ii11iIi11i / I11i / Ii1I + iIii1I11I1II1
   if 85 - 85: O0 / OOooOOo . OoOoOO00 / I1ii11iIi11i
  self . string_to_afi ( prefix_str )
  self . store_address ( prefix_str )
  self . mask_len = int ( OO00O )
  if 80 - 80: I1ii11iIi11i * iII111i % i1IIi * OOooOOo % II111iiii % i1IIi
  if 44 - 44: OoooooooOO
 def zero_host_bits ( self ) :
  if ( self . mask_len < 0 ) : return
  iI = ( 2 ** self . mask_len ) - 1
  i1iiIiII1II1 = self . addr_length ( ) * 8 - self . mask_len
  iI <<= i1iiIiII1II1
  self . address &= iI
  if 17 - 17: iIii1I11I1II1 - Ii1I + IiII . Oo0Ooo + i11iIiiIii
  if 97 - 97: ooOoO0o % II111iiii / Ii1I . iIii1I11I1II1
 def is_geo_string ( self , addr_str ) :
  ooo = addr_str . find ( "]" )
  if ( ooo != - 1 ) : addr_str = addr_str [ ooo + 1 : : ]
  if 100 - 100: II111iiii / I11i * iIii1I11I1II1 / OOooOOo + i11iIiiIii - iIii1I11I1II1
  I1Ii1i111I = addr_str . split ( "/" )
  if ( len ( I1Ii1i111I ) == 2 ) :
   if ( I1Ii1i111I [ 1 ] . isdigit ( ) == False ) : return ( False )
   if 32 - 32: o0oOOo0O0Ooo - Ii1I / ooOoO0o % I1Ii111
  I1Ii1i111I = I1Ii1i111I [ 0 ]
  I1Ii1i111I = I1Ii1i111I . split ( "-" )
  OOoo0Oo00 = len ( I1Ii1i111I )
  if ( OOoo0Oo00 < 8 or OOoo0Oo00 > 9 ) : return ( False )
  if 69 - 69: I1Ii111 % IiII - O0 % OoO0O00 - OoOoOO00 * i11iIiiIii
  for OO0 in range ( 0 , OOoo0Oo00 ) :
   if ( OO0 == 3 ) :
    if ( I1Ii1i111I [ OO0 ] in [ "N" , "S" ] ) : continue
    return ( False )
    if 5 - 5: iII111i / oO0o * iIii1I11I1II1
   if ( OO0 == 7 ) :
    if ( I1Ii1i111I [ OO0 ] in [ "W" , "E" ] ) : continue
    return ( False )
    if 94 - 94: ooOoO0o / Ii1I
   if ( I1Ii1i111I [ OO0 ] . isdigit ( ) == False ) : return ( False )
   if 9 - 9: I1Ii111 * oO0o
  return ( True )
  if 44 - 44: ooOoO0o * oO0o
  if 67 - 67: iIii1I11I1II1 . iIii1I11I1II1 + iIii1I11I1II1 * iII111i
 def string_to_afi ( self , addr_str ) :
  if ( addr_str . count ( "'" ) == 2 ) :
   self . afi = LISP_AFI_NAME
   return
   if 70 - 70: I1IiiI - I11i / iIii1I11I1II1 . I1IiiI % I1ii11iIi11i
  if ( addr_str . find ( ":" ) != - 1 ) : self . afi = LISP_AFI_IPV6
  elif ( addr_str . find ( "." ) != - 1 ) : self . afi = LISP_AFI_IPV4
  elif ( addr_str . find ( "+" ) != - 1 ) : self . afi = LISP_AFI_E164
  elif ( self . is_geo_string ( addr_str ) ) : self . afi = LISP_AFI_GEO_COORD
  elif ( addr_str . find ( "-" ) != - 1 ) : self . afi = LISP_AFI_MAC
  else : self . afi = LISP_AFI_NONE
  if 12 - 12: Oo0Ooo + I1IiiI
  if 12 - 12: OoOoOO00 / II111iiii
 def print_address ( self ) :
  IiiIIi1 = self . print_address_no_iid ( )
  o0OoO0000o = "[" + str ( self . instance_id )
  for IiIIi1IiiIiI in self . iid_list : o0OoO0000o += "," + str ( IiIIi1IiiIiI )
  o0OoO0000o += "]"
  IiiIIi1 = "{}{}" . format ( o0OoO0000o , IiiIIi1 )
  return ( IiiIIi1 )
  if 100 - 100: I1ii11iIi11i % iIii1I11I1II1 . IiII . OoooooooOO / II111iiii
  if 28 - 28: I1IiiI
 def print_address_no_iid ( self ) :
  if ( self . is_ipv4 ( ) ) :
   IiiIIi1 = self . address
   IiIIIiIII1i = IiiIIi1 >> 24
   iiI1i = ( IiiIIi1 >> 16 ) & 0xff
   o0OOo0o0 = ( IiiIIi1 >> 8 ) & 0xff
   iIII1i11i = IiiIIi1 & 0xff
   return ( "{}.{}.{}.{}" . format ( IiIIIiIII1i , iiI1i , o0OOo0o0 , iIII1i11i ) )
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
   if 48 - 48: Ii1I / Ii1I / i1IIi * I1IiiI . iII111i + I1ii11iIi11i
  return ( "unknown-afi:{}" . format ( self . afi ) )
  if 66 - 66: iIii1I11I1II1 . iIii1I11I1II1 + I1ii11iIi11i
  if 45 - 45: iII111i . oO0o * iII111i
 def print_prefix ( self ) :
  if ( self . is_ultimate_root ( ) ) : return ( "[*]" )
  if ( self . is_iid_range ( ) ) :
   if ( self . mask_len == 32 ) : return ( "[{}]" . format ( self . instance_id ) )
   iIII = self . instance_id + ( 2 ** ( 32 - self . mask_len ) - 1 )
   return ( "[{}-{}]" . format ( self . instance_id , iIII ) )
   if 36 - 36: O0 - iII111i + I11i + I1IiiI
  IiiIIi1 = self . print_address ( )
  if ( self . is_dist_name ( ) ) : return ( IiiIIi1 )
  if ( self . is_geo_prefix ( ) ) : return ( IiiIIi1 )
  if 89 - 89: OoOoOO00 / Ii1I - OoO0O00 % I11i - oO0o . Ii1I
  ooo = IiiIIi1 . find ( "no-address" )
  if ( ooo == - 1 ) :
   IiiIIi1 = "{}/{}" . format ( IiiIIi1 , str ( self . mask_len ) )
  else :
   IiiIIi1 = IiiIIi1 [ 0 : ooo ]
   if 75 - 75: I11i * OoooooooOO % OoOoOO00 . i1IIi - Ii1I + iIii1I11I1II1
  return ( IiiIIi1 )
  if 74 - 74: ooOoO0o
  if 18 - 18: iIii1I11I1II1 - I11i - oO0o
 def print_prefix_no_iid ( self ) :
  IiiIIi1 = self . print_address_no_iid ( )
  if ( self . is_dist_name ( ) ) : return ( IiiIIi1 )
  if ( self . is_geo_prefix ( ) ) : return ( IiiIIi1 )
  return ( "{}/{}" . format ( IiiIIi1 , str ( self . mask_len ) ) )
  if 12 - 12: O0 + O0 + ooOoO0o . I1IiiI * II111iiii
  if 47 - 47: i11iIiiIii % OOooOOo / ooOoO0o . IiII - I1IiiI
 def print_prefix_url ( self ) :
  if ( self . is_ultimate_root ( ) ) : return ( "0--0" )
  IiiIIi1 = self . print_address ( )
  ooo = IiiIIi1 . find ( "]" )
  if ( ooo != - 1 ) : IiiIIi1 = IiiIIi1 [ ooo + 1 : : ]
  if ( self . is_geo_prefix ( ) ) :
   IiiIIi1 = IiiIIi1 . replace ( "/" , "-" )
   return ( "{}-{}" . format ( self . instance_id , IiiIIi1 ) )
   if 10 - 10: Oo0Ooo / ooOoO0o / I1ii11iIi11i
  return ( "{}-{}-{}" . format ( self . instance_id , IiiIIi1 , self . mask_len ) )
  if 98 - 98: O0 - I1Ii111 - i11iIiiIii
  if 85 - 85: II111iiii - I1ii11iIi11i % I1IiiI . I1IiiI - OoooooooOO - I11i
 def print_sg ( self , g ) :
  IiII1iiI = self . print_prefix ( )
  Ii1I111 = IiII1iiI . find ( "]" ) + 1
  g = g . print_prefix ( )
  O0OO0O00Oo0 = g . find ( "]" ) + 1
  II11I = "[{}]({}, {})" . format ( self . instance_id , IiII1iiI [ Ii1I111 : : ] , g [ O0OO0O00Oo0 : : ] )
  return ( II11I )
  if 25 - 25: OoOoOO00 % i11iIiiIii - I1IiiI * iIii1I11I1II1 - Oo0Ooo . O0
  if 48 - 48: I1IiiI + oO0o % i11iIiiIii % iIii1I11I1II1
 def hash_address ( self , addr ) :
  ooOo0O0 = self . address
  ooo0 = addr . address
  if 14 - 14: iIii1I11I1II1
  if ( self . is_geo_prefix ( ) ) : ooOo0O0 = self . address . print_geo ( )
  if ( addr . is_geo_prefix ( ) ) : ooo0 = addr . address . print_geo ( )
  if 78 - 78: I1Ii111 / Oo0Ooo - I1Ii111
  if ( type ( ooOo0O0 ) == str ) :
   ooOo0O0 = int ( binascii . hexlify ( ooOo0O0 [ 0 : 1 ] ) )
   if 1 - 1: OoO0O00 - I1IiiI * o0oOOo0O0Ooo
  if ( type ( ooo0 ) == str ) :
   ooo0 = int ( binascii . hexlify ( ooo0 [ 0 : 1 ] ) )
   if 84 - 84: OoO0O00 % OoooooooOO
  return ( ooOo0O0 ^ ooo0 )
  if 66 - 66: OoOoOO00 . iII111i
  if 1 - 1: iII111i * i1IIi . iIii1I11I1II1 % O0 - OoooooooOO
  if 87 - 87: iII111i . Oo0Ooo * i11iIiiIii % o0oOOo0O0Ooo + Ii1I
  if 72 - 72: Ii1I / II111iiii + o0oOOo0O0Ooo
  if 33 - 33: I1Ii111 * OoOoOO00 - OoooooooOO
  if 11 - 11: I1Ii111 - Oo0Ooo / iIii1I11I1II1 - OoooooooOO
 def is_more_specific ( self , prefix ) :
  if ( prefix . afi == LISP_AFI_ULTIMATE_ROOT ) : return ( True )
  if 71 - 71: Oo0Ooo + Ii1I - OoooooooOO + I11i - iIii1I11I1II1 / O0
  OO00O = prefix . mask_len
  if ( prefix . afi == LISP_AFI_IID_RANGE ) :
   OooO0o000Oo = 2 ** ( 32 - OO00O )
   O00ooO00o0oO = prefix . instance_id
   iIII = O00ooO00o0oO + OooO0o000Oo
   return ( self . instance_id in range ( O00ooO00o0oO , iIII ) )
   if 8 - 8: OOooOOo / Oo0Ooo + OoO0O00 + I1ii11iIi11i + OoooooooOO % i1IIi
   if 46 - 46: OoOoOO00
  if ( self . instance_id != prefix . instance_id ) : return ( False )
  if ( self . afi != prefix . afi ) :
   if ( prefix . afi != LISP_AFI_NONE ) : return ( False )
   if 75 - 75: I1IiiI
   if 37 - 37: iIii1I11I1II1 % OoO0O00 * ooOoO0o + I11i % ooOoO0o / i11iIiiIii
   if 14 - 14: i1IIi / ooOoO0o
   if 10 - 10: ooOoO0o / OoooooooOO - ooOoO0o % O0 + oO0o - oO0o
   if 16 - 16: O0
  if ( self . is_binary ( ) == False ) :
   if ( prefix . afi == LISP_AFI_NONE ) : return ( True )
   if ( type ( self . address ) != type ( prefix . address ) ) : return ( False )
   IiiIIi1 = self . address
   I1iOoo0Ooo00o = prefix . address
   if ( self . is_geo_prefix ( ) ) :
    IiiIIi1 = self . address . print_geo ( )
    I1iOoo0Ooo00o = prefix . address . print_geo ( )
    if 78 - 78: OOooOOo % O0 * O0
   if ( len ( IiiIIi1 ) < len ( I1iOoo0Ooo00o ) ) : return ( False )
   return ( IiiIIi1 . find ( I1iOoo0Ooo00o ) == 0 )
   if 62 - 62: ooOoO0o
   if 77 - 77: I1IiiI . i11iIiiIii - I1ii11iIi11i
   if 83 - 83: OoO0O00 - i11iIiiIii + I1ii11iIi11i - OOooOOo / OoOoOO00 / I11i
   if 53 - 53: I11i * I1IiiI . I1IiiI / o0oOOo0O0Ooo - I1Ii111
   if 50 - 50: I11i - OoOoOO00 + I1IiiI % Oo0Ooo / OoooooooOO - I1ii11iIi11i
  if ( self . mask_len < OO00O ) : return ( False )
  if 26 - 26: IiII . Ii1I
  i1iiIiII1II1 = ( prefix . addr_length ( ) * 8 ) - OO00O
  iI = ( 2 ** OO00O - 1 ) << i1iiIiII1II1
  return ( ( self . address & iI ) == prefix . address )
  if 35 - 35: I1ii11iIi11i + OOooOOo
  if 88 - 88: O0
 def mask_address ( self , mask_len ) :
  i1iiIiII1II1 = ( self . addr_length ( ) * 8 ) - mask_len
  iI = ( 2 ** mask_len - 1 ) << i1iiIiII1II1
  self . address &= iI
  if 4 - 4: OoOoOO00 % iIii1I11I1II1 % OoooooooOO . oO0o
  if 27 - 27: II111iiii - OoOoOO00
 def is_exact_match ( self , prefix ) :
  if ( self . instance_id != prefix . instance_id ) : return ( False )
  OO0OO0o0 = self . print_prefix ( )
  iIi = prefix . print_prefix ( ) if prefix else ""
  return ( OO0OO0o0 == iIi )
  if 75 - 75: iIii1I11I1II1
  if 72 - 72: Ii1I / i1IIi . o0oOOo0O0Ooo
 def is_local ( self ) :
  if ( self . is_ipv4 ( ) ) :
   Ii1iIiI1I = lisp_myrlocs [ 0 ]
   if ( Ii1iIiI1I == None ) : return ( False )
   Ii1iIiI1I = Ii1iIiI1I . print_address_no_iid ( )
   return ( self . print_address_no_iid ( ) == Ii1iIiI1I )
   if 15 - 15: iIii1I11I1II1 - OoooooooOO / ooOoO0o
  if ( self . is_ipv6 ( ) ) :
   Ii1iIiI1I = lisp_myrlocs [ 1 ]
   if ( Ii1iIiI1I == None ) : return ( False )
   Ii1iIiI1I = Ii1iIiI1I . print_address_no_iid ( )
   return ( self . print_address_no_iid ( ) == Ii1iIiI1I )
   if 83 - 83: IiII + I1Ii111 / OoOoOO00 * IiII . oO0o
  return ( False )
  if 22 - 22: O0 + ooOoO0o + I1Ii111
  if 57 - 57: OOooOOo . ooOoO0o - OoooooooOO - I1ii11iIi11i * O0
 def store_iid_range ( self , iid , mask_len ) :
  if ( self . afi == LISP_AFI_NONE ) :
   if ( iid == 0 and mask_len == 0 ) : self . afi = LISP_AFI_ULTIMATE_ROOT
   else : self . afi = LISP_AFI_IID_RANGE
   if 85 - 85: I1IiiI * OoO0O00
  self . instance_id = iid
  self . mask_len = mask_len
  if 63 - 63: I1IiiI - i11iIiiIii
  if 4 - 4: OOooOOo + iIii1I11I1II1 / I1IiiI * Ii1I
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
  if 64 - 64: OoOoOO00
  if 94 - 94: OOooOOo * OoooooooOO * o0oOOo0O0Ooo / I1Ii111 . II111iiii
  if 37 - 37: O0 * II111iiii * I1IiiI - O0 - I11i / i1IIi
  if 27 - 27: i11iIiiIii + iIii1I11I1II1
  if 15 - 15: oO0o
  if 69 - 69: II111iiii * O0 . ooOoO0o * IiII
  if 25 - 25: I11i - I1ii11iIi11i . I1Ii111 . OoooooooOO
  if 4 - 4: IiII * OoO0O00 % I1ii11iIi11i * Ii1I . iII111i
  if 41 - 41: OoooooooOO % I11i . O0 + I1Ii111
  if 67 - 67: OoOoOO00 * OOooOOo / OOooOOo / OoooooooOO
  if 67 - 67: I11i - i1IIi . OoooooooOO / iIii1I11I1II1
  if 34 - 34: OoO0O00 * II111iiii
  if 43 - 43: OoOoOO00 . I1IiiI
  if 44 - 44: O0 / o0oOOo0O0Ooo
  if 19 - 19: I11i
  if 91 - 91: OOooOOo * OoooooooOO
  if 89 - 89: i1IIi / iII111i . I1Ii111
 def lcaf_encode_iid ( self ) :
  iI1IIiI111iII = LISP_LCAF_INSTANCE_ID_TYPE
  Iii1i11 = socket . htons ( self . lcaf_length ( iI1IIiI111iII ) )
  o0OoO0000o = self . instance_id
  O0ooo0 = self . afi
  OOoOOO = 0
  if ( O0ooo0 < 0 ) :
   if ( self . afi == LISP_AFI_GEO_COORD ) :
    O0ooo0 = LISP_AFI_LCAF
    OOoOOO = 0
   else :
    O0ooo0 = 0
    OOoOOO = self . mask_len
    if 74 - 74: I1ii11iIi11i % iII111i / OoooooooOO / I1ii11iIi11i % i11iIiiIii % ooOoO0o
    if 82 - 82: OoooooooOO . o0oOOo0O0Ooo * I1ii11iIi11i % I1ii11iIi11i * Ii1I
    if 83 - 83: I11i - Oo0Ooo + i11iIiiIii - i11iIiiIii
  o0oO00ooo0o = struct . pack ( "BBBBH" , 0 , 0 , iI1IIiI111iII , OOoOOO , Iii1i11 )
  o0oO00ooo0o += struct . pack ( "IH" , socket . htonl ( o0OoO0000o ) , socket . htons ( O0ooo0 ) )
  if ( O0ooo0 == 0 ) : return ( o0oO00ooo0o )
  if 26 - 26: iII111i . i1IIi * OoOoOO00 + I1Ii111 . IiII % i11iIiiIii
  if ( self . afi == LISP_AFI_GEO_COORD ) :
   o0oO00ooo0o = o0oO00ooo0o [ 0 : - 2 ]
   o0oO00ooo0o += self . address . encode_geo ( )
   return ( o0oO00ooo0o )
   if 98 - 98: I1IiiI - oO0o / i11iIiiIii % I1ii11iIi11i * oO0o * OoO0O00
   if 74 - 74: I1Ii111 . I1ii11iIi11i - Ii1I * i11iIiiIii
  o0oO00ooo0o += self . pack_address ( )
  return ( o0oO00ooo0o )
  if 36 - 36: II111iiii * Ii1I
  if 53 - 53: Ii1I / iIii1I11I1II1 + o0oOOo0O0Ooo . Ii1I
 def lcaf_decode_iid ( self , packet ) :
  i1I1iii1I11II = "BBBBH"
  Iiiii = struct . calcsize ( i1I1iii1I11II )
  if ( len ( packet ) < Iiiii ) : return ( None )
  if 79 - 79: Ii1I % O0 * OOooOOo
  O0O , IIIi1i1iIIIi , iI1IIiI111iII , II1IIII1iII , IiiI1iii1iIiiI = struct . unpack ( i1I1iii1I11II ,
 packet [ : Iiiii ] )
  packet = packet [ Iiiii : : ]
  if 24 - 24: oO0o
  if ( iI1IIiI111iII != LISP_LCAF_INSTANCE_ID_TYPE ) : return ( None )
  if 98 - 98: oO0o + iIii1I11I1II1 . ooOoO0o / I1ii11iIi11i
  i1I1iii1I11II = "IH"
  Iiiii = struct . calcsize ( i1I1iii1I11II )
  if ( len ( packet ) < Iiiii ) : return ( None )
  if 77 - 77: OoOoOO00 / Oo0Ooo * OoOoOO00 % I1IiiI . II111iiii % OoO0O00
  o0OoO0000o , O0ooo0 = struct . unpack ( i1I1iii1I11II , packet [ : Iiiii ] )
  packet = packet [ Iiiii : : ]
  if 38 - 38: iII111i - OoO0O00 / i1IIi + ooOoO0o . ooOoO0o . iII111i
  IiiI1iii1iIiiI = socket . ntohs ( IiiI1iii1iIiiI )
  self . instance_id = socket . ntohl ( o0OoO0000o )
  O0ooo0 = socket . ntohs ( O0ooo0 )
  self . afi = O0ooo0
  if ( II1IIII1iII != 0 and O0ooo0 == 0 ) : self . mask_len = II1IIII1iII
  if ( O0ooo0 == 0 ) :
   self . afi = LISP_AFI_IID_RANGE if II1IIII1iII else LISP_AFI_ULTIMATE_ROOT
   if 37 - 37: iIii1I11I1II1 * OoOoOO00 . OoOoOO00 + OoooooooOO + OoO0O00
   if 25 - 25: I1IiiI / IiII . OOooOOo . I1ii11iIi11i % i1IIi
   if 12 - 12: O0 % O0
   if 9 - 9: O0 . I1IiiI + I1ii11iIi11i / OOooOOo * I1ii11iIi11i
   if 10 - 10: IiII % o0oOOo0O0Ooo / O0 / II111iiii
  if ( O0ooo0 == 0 ) : return ( packet )
  if 81 - 81: Ii1I / o0oOOo0O0Ooo % OoOoOO00 . I1ii11iIi11i
  if 47 - 47: II111iiii + OOooOOo / II111iiii . OOooOOo
  if 68 - 68: OoooooooOO
  if 63 - 63: I1IiiI
  if ( self . is_dist_name ( ) ) :
   packet , self . address = lisp_decode_dist_name ( packet )
   self . mask_len = len ( self . address ) * 8
   return ( packet )
   if 80 - 80: oO0o + iIii1I11I1II1
   if 87 - 87: I1ii11iIi11i % Ii1I . Ii1I
   if 71 - 71: OoO0O00 - IiII . i1IIi * I1IiiI % I11i
   if 36 - 36: IiII * OoooooooOO . i11iIiiIii * i1IIi
   if 52 - 52: IiII + ooOoO0o - II111iiii - OoooooooOO * OoO0O00 - iIii1I11I1II1
  if ( O0ooo0 == LISP_AFI_LCAF ) :
   i1I1iii1I11II = "BBBBH"
   Iiiii = struct . calcsize ( i1I1iii1I11II )
   if ( len ( packet ) < Iiiii ) : return ( None )
   if 38 - 38: II111iiii % iIii1I11I1II1 * IiII * OoOoOO00 % II111iiii . I1IiiI
   Ii1IiIIIi1i , II111Ii1I1I , iI1IIiI111iII , o00oo0oOo0o0 , oOOO0O000Oo = struct . unpack ( i1I1iii1I11II , packet [ : Iiiii ] )
   if 35 - 35: OoooooooOO - i11iIiiIii * i11iIiiIii % Ii1I - OOooOOo . iIii1I11I1II1
   if 96 - 96: OOooOOo
   if ( iI1IIiI111iII != LISP_LCAF_GEO_COORD_TYPE ) : return ( None )
   if 18 - 18: oO0o . I1ii11iIi11i % oO0o
   oOOO0O000Oo = socket . ntohs ( oOOO0O000Oo )
   packet = packet [ Iiiii : : ]
   if ( oOOO0O000Oo > len ( packet ) ) : return ( None )
   if 43 - 43: oO0o / ooOoO0o . o0oOOo0O0Ooo . iIii1I11I1II1
   I1Ii1i111I = lisp_geo ( "" )
   self . afi = LISP_AFI_GEO_COORD
   self . address = I1Ii1i111I
   packet = I1Ii1i111I . decode_geo ( packet , oOOO0O000Oo , o00oo0oOo0o0 )
   self . mask_len = self . host_mask_len ( )
   return ( packet )
   if 63 - 63: iII111i * iII111i
   if 78 - 78: iIii1I11I1II1 % iIii1I11I1II1 . iIii1I11I1II1 / Ii1I . O0 + i1IIi
  Iii1i11 = self . addr_length ( )
  if ( len ( packet ) < Iii1i11 ) : return ( None )
  if 53 - 53: Ii1I . I1ii11iIi11i - OOooOOo - ooOoO0o
  packet = self . unpack_address ( packet )
  return ( packet )
  if 17 - 17: OoooooooOO / I1IiiI * ooOoO0o % I1ii11iIi11i . OoO0O00
  if 5 - 5: OoO0O00 % I1Ii111 . oO0o . Ii1I + I1IiiI
  if 95 - 95: II111iiii . iII111i - iIii1I11I1II1 / I11i + ooOoO0o * I1Ii111
  if 92 - 92: iII111i * OoooooooOO % I1IiiI / OOooOOo
  if 46 - 46: OoOoOO00
  if 52 - 52: o0oOOo0O0Ooo - OoO0O00 % i1IIi / Ii1I % IiII
  if 100 - 100: oO0o . i11iIiiIii - ooOoO0o
  if 49 - 49: Oo0Ooo % ooOoO0o % o0oOOo0O0Ooo + ooOoO0o * I1Ii111 % I1IiiI
  if 85 - 85: i1IIi / i1IIi
  if 77 - 77: i1IIi . ooOoO0o % ooOoO0o - Ii1I
  if 6 - 6: OOooOOo % Ii1I + ooOoO0o
  if 17 - 17: iIii1I11I1II1 * I1Ii111 % oO0o + o0oOOo0O0Ooo . Ii1I * Oo0Ooo
  if 16 - 16: I1IiiI % OoO0O00 . ooOoO0o / OoooooooOO
  if 8 - 8: I1Ii111 % OoO0O00 . I1IiiI - OoOoOO00 + i1IIi / iIii1I11I1II1
  if 89 - 89: II111iiii / Ii1I % Ii1I
  if 57 - 57: I11i
  if 95 - 95: OoOoOO00 + I11i * i1IIi - ooOoO0o % ooOoO0o
  if 58 - 58: OOooOOo
  if 74 - 74: i1IIi . IiII / ooOoO0o + I11i % i11iIiiIii % iII111i
  if 62 - 62: i1IIi % I1Ii111
  if 94 - 94: i1IIi + iII111i
 def lcaf_encode_sg ( self , group ) :
  iI1IIiI111iII = LISP_LCAF_MCAST_INFO_TYPE
  o0OoO0000o = socket . htonl ( self . instance_id )
  Iii1i11 = socket . htons ( self . lcaf_length ( iI1IIiI111iII ) )
  o0oO00ooo0o = struct . pack ( "BBBBHIHBB" , 0 , 0 , iI1IIiI111iII , 0 , Iii1i11 , o0OoO0000o ,
 0 , self . mask_len , group . mask_len )
  if 25 - 25: I1Ii111 . Ii1I - Ii1I . o0oOOo0O0Ooo - IiII
  o0oO00ooo0o += struct . pack ( "H" , socket . htons ( self . afi ) )
  o0oO00ooo0o += self . pack_address ( )
  o0oO00ooo0o += struct . pack ( "H" , socket . htons ( group . afi ) )
  o0oO00ooo0o += group . pack_address ( )
  return ( o0oO00ooo0o )
  if 91 - 91: o0oOOo0O0Ooo % I1ii11iIi11i % OoOoOO00 * iIii1I11I1II1
  if 18 - 18: OoOoOO00 * I1ii11iIi11i . i1IIi * iII111i
 def lcaf_decode_sg ( self , packet ) :
  i1I1iii1I11II = "BBBBHIHBB"
  Iiiii = struct . calcsize ( i1I1iii1I11II )
  if ( len ( packet ) < Iiiii ) : return ( [ None , None ] )
  if 67 - 67: IiII + i11iIiiIii . II111iiii / OoOoOO00 + OoooooooOO + i11iIiiIii
  O0O , IIIi1i1iIIIi , iI1IIiI111iII , i1o00Oo , IiiI1iii1iIiiI , o0OoO0000o , iiIiIi , O000oooOoooo0 , iiiIiII = struct . unpack ( i1I1iii1I11II , packet [ : Iiiii ] )
  if 31 - 31: OoooooooOO . I1Ii111 % OoooooooOO * iII111i % OOooOOo . iII111i
  packet = packet [ Iiiii : : ]
  if 17 - 17: I1Ii111 % i1IIi % I11i * O0 / Oo0Ooo
  if ( iI1IIiI111iII != LISP_LCAF_MCAST_INFO_TYPE ) : return ( [ None , None ] )
  if 96 - 96: OoOoOO00 . Ii1I
  self . instance_id = socket . ntohl ( o0OoO0000o )
  IiiI1iii1iIiiI = socket . ntohs ( IiiI1iii1iIiiI ) - 8
  if 80 - 80: OoOoOO00 + o0oOOo0O0Ooo - II111iiii
  if 3 - 3: ooOoO0o * I1Ii111
  if 34 - 34: Ii1I / Oo0Ooo . II111iiii - ooOoO0o - I1ii11iIi11i % OoOoOO00
  if 43 - 43: Ii1I * oO0o
  if 57 - 57: OoooooooOO + I1IiiI % I1ii11iIi11i % ooOoO0o * I1Ii111
  i1I1iii1I11II = "H"
  Iiiii = struct . calcsize ( i1I1iii1I11II )
  if ( len ( packet ) < Iiiii ) : return ( [ None , None ] )
  if ( IiiI1iii1iIiiI < Iiiii ) : return ( [ None , None ] )
  if 9 - 9: i11iIiiIii
  O0ooo0 = struct . unpack ( i1I1iii1I11II , packet [ : Iiiii ] ) [ 0 ]
  packet = packet [ Iiiii : : ]
  IiiI1iii1iIiiI -= Iiiii
  self . afi = socket . ntohs ( O0ooo0 )
  self . mask_len = O000oooOoooo0
  Iii1i11 = self . addr_length ( )
  if ( IiiI1iii1iIiiI < Iii1i11 ) : return ( [ None , None ] )
  if 85 - 85: IiII / o0oOOo0O0Ooo * ooOoO0o
  packet = self . unpack_address ( packet )
  if ( packet == None ) : return ( [ None , None ] )
  if 74 - 74: O0 - o0oOOo0O0Ooo
  IiiI1iii1iIiiI -= Iii1i11
  if 68 - 68: I1Ii111
  if 19 - 19: o0oOOo0O0Ooo
  if 63 - 63: OoooooooOO % ooOoO0o
  if 26 - 26: OOooOOo + Oo0Ooo
  if 97 - 97: I1Ii111 * I1Ii111 + iII111i % Ii1I / iII111i
  i1I1iii1I11II = "H"
  Iiiii = struct . calcsize ( i1I1iii1I11II )
  if ( len ( packet ) < Iiiii ) : return ( [ None , None ] )
  if ( IiiI1iii1iIiiI < Iiiii ) : return ( [ None , None ] )
  if 73 - 73: OoOoOO00 % I1Ii111 . I1ii11iIi11i
  O0ooo0 = struct . unpack ( i1I1iii1I11II , packet [ : Iiiii ] ) [ 0 ]
  packet = packet [ Iiiii : : ]
  IiiI1iii1iIiiI -= Iiiii
  IIi1iiIII11 = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  IIi1iiIII11 . afi = socket . ntohs ( O0ooo0 )
  IIi1iiIII11 . mask_len = iiiIiII
  IIi1iiIII11 . instance_id = self . instance_id
  Iii1i11 = self . addr_length ( )
  if ( IiiI1iii1iIiiI < Iii1i11 ) : return ( [ None , None ] )
  if 45 - 45: iIii1I11I1II1 % Ii1I . OoOoOO00 . o0oOOo0O0Ooo - OoooooooOO
  packet = IIi1iiIII11 . unpack_address ( packet )
  if ( packet == None ) : return ( [ None , None ] )
  if 46 - 46: I1ii11iIi11i
  return ( [ packet , IIi1iiIII11 ] )
  if 32 - 32: iII111i * i11iIiiIii / IiII + i11iIiiIii + O0
  if 51 - 51: I1Ii111
 def lcaf_decode_eid ( self , packet ) :
  i1I1iii1I11II = "BBB"
  Iiiii = struct . calcsize ( i1I1iii1I11II )
  if ( len ( packet ) < Iiiii ) : return ( [ None , None ] )
  if 95 - 95: Ii1I / Ii1I * OoO0O00 . OoooooooOO . OoooooooOO * I11i
  if 76 - 76: OoooooooOO - Ii1I + IiII % OoOoOO00 / OoooooooOO
  if 55 - 55: i11iIiiIii - IiII * OOooOOo + II111iiii . I1ii11iIi11i / O0
  if 16 - 16: II111iiii . Oo0Ooo * I1Ii111 + o0oOOo0O0Ooo - i11iIiiIii
  if 98 - 98: II111iiii - i1IIi - ooOoO0o
  i1o00Oo , II111Ii1I1I , iI1IIiI111iII = struct . unpack ( i1I1iii1I11II ,
 packet [ : Iiiii ] )
  if 36 - 36: IiII + o0oOOo0O0Ooo
  if ( iI1IIiI111iII == LISP_LCAF_INSTANCE_ID_TYPE ) :
   return ( [ self . lcaf_decode_iid ( packet ) , None ] )
  elif ( iI1IIiI111iII == LISP_LCAF_MCAST_INFO_TYPE ) :
   packet , IIi1iiIII11 = self . lcaf_decode_sg ( packet )
   return ( [ packet , IIi1iiIII11 ] )
  elif ( iI1IIiI111iII == LISP_LCAF_GEO_COORD_TYPE ) :
   i1I1iii1I11II = "BBBBH"
   Iiiii = struct . calcsize ( i1I1iii1I11II )
   if ( len ( packet ) < Iiiii ) : return ( None )
   if 81 - 81: OOooOOo / I11i % oO0o + ooOoO0o
   Ii1IiIIIi1i , II111Ii1I1I , iI1IIiI111iII , o00oo0oOo0o0 , oOOO0O000Oo = struct . unpack ( i1I1iii1I11II , packet [ : Iiiii ] )
   if 10 - 10: oO0o / i11iIiiIii
   if 73 - 73: OoO0O00 - i1IIi
   if ( iI1IIiI111iII != LISP_LCAF_GEO_COORD_TYPE ) : return ( None )
   if 52 - 52: I1ii11iIi11i
   oOOO0O000Oo = socket . ntohs ( oOOO0O000Oo )
   packet = packet [ Iiiii : : ]
   if ( oOOO0O000Oo > len ( packet ) ) : return ( None )
   if 4 - 4: Ii1I - iII111i + i1IIi - I1Ii111 / iII111i . Oo0Ooo
   I1Ii1i111I = lisp_geo ( "" )
   self . instance_id = 0
   self . afi = LISP_AFI_GEO_COORD
   self . address = I1Ii1i111I
   packet = I1Ii1i111I . decode_geo ( packet , oOOO0O000Oo , o00oo0oOo0o0 )
   self . mask_len = self . host_mask_len ( )
   if 18 - 18: oO0o % iIii1I11I1II1 + ooOoO0o
  return ( [ packet , None ] )
  if 34 - 34: I1IiiI - OoooooooOO . IiII - OOooOOo % IiII
  if 19 - 19: IiII + I1ii11iIi11i % Oo0Ooo
  if 32 - 32: OOooOOo
  if 46 - 46: II111iiii . OoO0O00
  if 97 - 97: oO0o
  if 45 - 45: i11iIiiIii / IiII + OoO0O00
class lisp_elp_node ( ) :
 def __init__ ( self ) :
  self . address = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . probe = False
  self . strict = False
  self . eid = False
  self . we_are_last = False
  if 55 - 55: Ii1I / II111iiii - oO0o
  if 58 - 58: i1IIi . OoooooooOO % iIii1I11I1II1 * o0oOOo0O0Ooo + O0 / oO0o
 def copy_elp_node ( self ) :
  IIii = lisp_elp_node ( )
  IIii . copy_address ( self . address )
  IIii . probe = self . probe
  IIii . strict = self . strict
  IIii . eid = self . eid
  IIii . we_are_last = self . we_are_last
  return ( IIii )
  if 77 - 77: I11i . I1ii11iIi11i
  if 92 - 92: i11iIiiIii + I11i % I1IiiI / ooOoO0o
  if 28 - 28: i1IIi . I1IiiI
class lisp_elp ( ) :
 def __init__ ( self , name ) :
  self . elp_name = name
  self . elp_nodes = [ ]
  self . use_elp_node = None
  self . we_are_last = False
  if 41 - 41: I1ii11iIi11i . I1Ii111 * OoOoOO00 . I1Ii111 / o0oOOo0O0Ooo
  if 41 - 41: o0oOOo0O0Ooo / o0oOOo0O0Ooo . Oo0Ooo
 def copy_elp ( self ) :
  O0OoO0O0O0oO = lisp_elp ( self . elp_name )
  O0OoO0O0O0oO . use_elp_node = self . use_elp_node
  O0OoO0O0O0oO . we_are_last = self . we_are_last
  for IIii in self . elp_nodes :
   O0OoO0O0O0oO . elp_nodes . append ( IIii . copy_elp_node ( ) )
   if 4 - 4: I1Ii111
  return ( O0OoO0O0O0oO )
  if 85 - 85: iIii1I11I1II1 % Oo0Ooo
  if 20 - 20: IiII + i11iIiiIii * OOooOOo
 def print_elp ( self , want_marker ) :
  Oo = ""
  for IIii in self . elp_nodes :
   ii1III1IiIII1 = ""
   if ( want_marker ) :
    if ( IIii == self . use_elp_node ) :
     ii1III1IiIII1 = "*"
    elif ( IIii . we_are_last ) :
     ii1III1IiIII1 = "x"
     if 51 - 51: I1ii11iIi11i * OOooOOo
     if 100 - 100: OoO0O00 * oO0o + I1IiiI - o0oOOo0O0Ooo . o0oOOo0O0Ooo % OoO0O00
   Oo += "{}{}({}{}{}), " . format ( ii1III1IiIII1 ,
 IIii . address . print_address_no_iid ( ) ,
 "r" if IIii . eid else "R" , "P" if IIii . probe else "p" ,
 "S" if IIii . strict else "s" )
   if 65 - 65: OoooooooOO / OoOoOO00 + I1IiiI - II111iiii / OoOoOO00
  return ( Oo [ 0 : - 2 ] if Oo != "" else "" )
  if 69 - 69: i11iIiiIii
  if 77 - 77: I1ii11iIi11i % OoooooooOO - Oo0Ooo - Ii1I + I11i
 def select_elp_node ( self ) :
  Oo0o0OoO00 , II1III , OoO0o0OOOO = lisp_myrlocs
  ooo = None
  if 83 - 83: ooOoO0o
  for IIii in self . elp_nodes :
   if ( Oo0o0OoO00 and IIii . address . is_exact_match ( Oo0o0OoO00 ) ) :
    ooo = self . elp_nodes . index ( IIii )
    break
    if 59 - 59: I1ii11iIi11i
   if ( II1III and IIii . address . is_exact_match ( II1III ) ) :
    ooo = self . elp_nodes . index ( IIii )
    break
    if 26 - 26: I11i . Ii1I
    if 94 - 94: ooOoO0o . I1IiiI + IiII % I1IiiI / o0oOOo0O0Ooo % o0oOOo0O0Ooo
    if 21 - 21: O0 / OOooOOo - II111iiii + I1ii11iIi11i / OoooooooOO
    if 81 - 81: i11iIiiIii / Oo0Ooo * i1IIi + OoO0O00 + O0 % I1ii11iIi11i
    if 3 - 3: i11iIiiIii * IiII . Oo0Ooo % OoOoOO00 * I11i . iII111i
    if 80 - 80: I11i - IiII
    if 40 - 40: OOooOOo * I1IiiI % I11i . I1Ii111 % O0 . O0
  if ( ooo == None ) :
   self . use_elp_node = self . elp_nodes [ 0 ]
   IIii . we_are_last = False
   return
   if 14 - 14: ooOoO0o . OoOoOO00 + ooOoO0o * OoOoOO00 . OoOoOO00 * Oo0Ooo
   if 40 - 40: OoooooooOO
   if 14 - 14: o0oOOo0O0Ooo / OOooOOo . OoOoOO00 % iIii1I11I1II1 % OoOoOO00
   if 92 - 92: o0oOOo0O0Ooo + II111iiii
   if 56 - 56: OoOoOO00 - OoOoOO00 / Ii1I
   if 92 - 92: iIii1I11I1II1
  if ( self . elp_nodes [ - 1 ] == self . elp_nodes [ ooo ] ) :
   self . use_elp_node = None
   IIii . we_are_last = True
   return
   if 21 - 21: I1IiiI
   if 69 - 69: OoooooooOO + iII111i
   if 29 - 29: ooOoO0o * I1IiiI / Oo0Ooo / I1ii11iIi11i
   if 74 - 74: I1ii11iIi11i - ooOoO0o / OoOoOO00 - OoooooooOO * oO0o
   if 45 - 45: o0oOOo0O0Ooo . I1Ii111 % Ii1I
  self . use_elp_node = self . elp_nodes [ ooo + 1 ]
  return
  if 42 - 42: Oo0Ooo + i11iIiiIii - OOooOOo . I1ii11iIi11i % I1Ii111 . I1ii11iIi11i
  if 59 - 59: OoooooooOO
  if 91 - 91: i11iIiiIii / Oo0Ooo % I11i / O0
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
  if 80 - 80: II111iiii / I1ii11iIi11i % I1IiiI . Ii1I
  if 8 - 8: oO0o
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
  if 21 - 21: oO0o + iII111i . i11iIiiIii - II111iiii
  if 14 - 14: I1Ii111
 def no_geo_altitude ( self ) :
  return ( self . altitude == - 1 )
  if 81 - 81: II111iiii
  if 55 - 55: O0 + o0oOOo0O0Ooo * I1IiiI - OoooooooOO
 def parse_geo_string ( self , geo_str ) :
  ooo = geo_str . find ( "]" )
  if ( ooo != - 1 ) : geo_str = geo_str [ ooo + 1 : : ]
  if 68 - 68: I11i + Oo0Ooo
  if 15 - 15: O0
  if 75 - 75: iII111i / OoOoOO00
  if 2 - 2: i1IIi + oO0o % iII111i % I1ii11iIi11i + ooOoO0o . iII111i
  if 26 - 26: I11i + o0oOOo0O0Ooo + Ii1I % I11i
  if ( geo_str . find ( "/" ) != - 1 ) :
   geo_str , O00o0OoO = geo_str . split ( "/" )
   self . radius = int ( O00o0OoO )
   if 3 - 3: i11iIiiIii / I1Ii111
   if 40 - 40: OoooooooOO / o0oOOo0O0Ooo + OoOoOO00
  geo_str = geo_str . split ( "-" )
  if ( len ( geo_str ) < 8 ) : return ( False )
  if 73 - 73: OOooOOo / Oo0Ooo
  OO0ooo = geo_str [ 0 : 4 ]
  Oooo0oO00ooO = geo_str [ 4 : 8 ]
  if 33 - 33: o0oOOo0O0Ooo * OOooOOo
  if 7 - 7: i11iIiiIii . OOooOOo * Ii1I . i1IIi
  if 4 - 4: O0 - IiII - II111iiii / iII111i - OOooOOo
  if 6 - 6: ooOoO0o + OOooOOo - I1IiiI + OOooOOo
  if ( len ( geo_str ) > 8 ) : self . altitude = int ( geo_str [ 8 ] )
  if 16 - 16: OoO0O00 * OoOoOO00 - Oo0Ooo
  if 44 - 44: ooOoO0o / OoOoOO00 - O0 + iII111i / iIii1I11I1II1
  if 41 - 41: iIii1I11I1II1 - iII111i / O0
  if 39 - 39: OoooooooOO * iIii1I11I1II1 - o0oOOo0O0Ooo / O0
  self . latitude = int ( OO0ooo [ 0 ] )
  self . lat_mins = int ( OO0ooo [ 1 ] )
  self . lat_secs = int ( OO0ooo [ 2 ] )
  if ( OO0ooo [ 3 ] == "N" ) : self . latitude = - self . latitude
  if 29 - 29: I11i % OoOoOO00 - oO0o + II111iiii . II111iiii
  if 25 - 25: Oo0Ooo * ooOoO0o % I1Ii111
  if 34 - 34: OoOoOO00 / I1Ii111 - ooOoO0o
  if 66 - 66: I11i * OoO0O00
  self . longitude = int ( Oooo0oO00ooO [ 0 ] )
  self . long_mins = int ( Oooo0oO00ooO [ 1 ] )
  self . long_secs = int ( Oooo0oO00ooO [ 2 ] )
  if ( Oooo0oO00ooO [ 3 ] == "E" ) : self . longitude = - self . longitude
  return ( True )
  if 98 - 98: IiII . Oo0Ooo + I1Ii111
  if 63 - 63: oO0o * I1IiiI * oO0o
 def print_geo ( self ) :
  oO0000000 = "N" if self . latitude < 0 else "S"
  O00O0 = "E" if self . longitude < 0 else "W"
  if 41 - 41: i11iIiiIii . I1IiiI / O0
  Ii1IIIIiI11 = "{}-{}-{}-{}-{}-{}-{}-{}" . format ( abs ( self . latitude ) ,
 self . lat_mins , self . lat_secs , oO0000000 , abs ( self . longitude ) ,
 self . long_mins , self . long_secs , O00O0 )
  if 93 - 93: Oo0Ooo % OoOoOO00 . II111iiii
  if ( self . no_geo_altitude ( ) == False ) :
   Ii1IIIIiI11 += "-" + str ( self . altitude )
   if 60 - 60: OoO0O00 - IiII % O0 * I1ii11iIi11i
   if 61 - 61: O0
   if 51 - 51: I1Ii111 - I11i % o0oOOo0O0Ooo * Oo0Ooo - oO0o + II111iiii
   if 7 - 7: oO0o
   if 98 - 98: Ii1I + oO0o + i1IIi + IiII % IiII
  if ( self . radius != 0 ) : Ii1IIIIiI11 += "/{}" . format ( self . radius )
  return ( Ii1IIIIiI11 )
  if 79 - 79: oO0o % I11i * I11i . OOooOOo % OoooooooOO
  if 71 - 71: iII111i
 def geo_url ( self ) :
  iIIi1i = os . getenv ( "LISP_GEO_ZOOM_LEVEL" )
  iIIi1i = "10" if ( iIIi1i == "" or iIIi1i . isdigit ( ) == False ) else iIIi1i
  III1iIi111I1 , i1I1ii111 = self . dms_to_decimal ( )
  OO0ooo0O = ( "http://maps.googleapis.com/maps/api/staticmap?center={},{}" + "&markers=color:blue%7Clabel:lisp%7C{},{}" + "&zoom={}&size=1024x1024&sensor=false" ) . format ( III1iIi111I1 , i1I1ii111 , III1iIi111I1 , i1I1ii111 ,
  # i1IIi - O0
  # i11iIiiIii * I1ii11iIi11i * OoooooooOO
 iIIi1i )
  return ( OO0ooo0O )
  if 83 - 83: iII111i - I1Ii111
  if 28 - 28: IiII
 def print_geo_url ( self ) :
  I1Ii1i111I = self . print_geo ( )
  if ( self . radius == 0 ) :
   OO0ooo0O = self . geo_url ( )
   Iii11I111Ii11 = "<a href='{}'>{}</a>" . format ( OO0ooo0O , I1Ii1i111I )
  else :
   OO0ooo0O = I1Ii1i111I . replace ( "/" , "-" )
   Iii11I111Ii11 = "<a href='/lisp/geo-map/{}'>{}</a>" . format ( OO0ooo0O , I1Ii1i111I )
   if 42 - 42: oO0o + Oo0Ooo * I1ii11iIi11i . o0oOOo0O0Ooo / iIii1I11I1II1
  return ( Iii11I111Ii11 )
  if 9 - 9: I1Ii111 * II111iiii % Ii1I - Ii1I % OoO0O00 % o0oOOo0O0Ooo
  if 26 - 26: o0oOOo0O0Ooo - I1IiiI / OoooooooOO / ooOoO0o % iIii1I11I1II1 % I1ii11iIi11i
 def dms_to_decimal ( self ) :
  IiiI11i1I11I , ii111iI1i , o0i11ii1I1II11 = self . latitude , self . lat_mins , self . lat_secs
  I1I1iii1 = float ( abs ( IiiI11i1I11I ) )
  I1I1iii1 += float ( ii111iI1i * 60 + o0i11ii1I1II11 ) / 3600
  if ( IiiI11i1I11I > 0 ) : I1I1iii1 = - I1I1iii1
  o0OO = I1I1iii1
  if 66 - 66: i1IIi . IiII / OoOoOO00 / i11iIiiIii
  IiiI11i1I11I , ii111iI1i , o0i11ii1I1II11 = self . longitude , self . long_mins , self . long_secs
  I1I1iii1 = float ( abs ( IiiI11i1I11I ) )
  I1I1iii1 += float ( ii111iI1i * 60 + o0i11ii1I1II11 ) / 3600
  if ( IiiI11i1I11I > 0 ) : I1I1iii1 = - I1I1iii1
  oOOo000000 = I1I1iii1
  return ( ( o0OO , oOOo000000 ) )
  if 4 - 4: i1IIi - ooOoO0o
  if 14 - 14: i1IIi . OoOoOO00 % I1IiiI / iII111i * i11iIiiIii + O0
 def get_distance ( self , geo_point ) :
  IIIIi1 = self . dms_to_decimal ( )
  iIiiIIOoO = geo_point . dms_to_decimal ( )
  IiiIIIii1I = vincenty ( IIIIi1 , iIiiIIOoO )
  return ( IiiIIIii1I . km )
  if 9 - 9: Oo0Ooo - OoO0O00 + iII111i / OoooooooOO
  if 52 - 52: O0
 def point_in_circle ( self , geo_point ) :
  IiIIiI = self . get_distance ( geo_point )
  return ( IiIIiI <= self . radius )
  if 99 - 99: I1Ii111 . II111iiii * IiII . II111iiii + OoOoOO00
  if 36 - 36: OoO0O00 * iII111i % ooOoO0o % OoOoOO00 * I1IiiI % i1IIi
 def encode_geo ( self ) :
  OoOoO00OoOOo = socket . htons ( LISP_AFI_LCAF )
  OOoo0Oo00 = socket . htons ( 20 + 2 )
  II111Ii1I1I = 0
  if 25 - 25: iII111i + I1IiiI / OoO0O00 - I1IiiI / OoooooooOO - ooOoO0o
  III1iIi111I1 = abs ( self . latitude )
  iiIIII1I1ii = ( ( self . lat_mins * 60 ) + self . lat_secs ) * 1000
  if ( self . latitude < 0 ) : II111Ii1I1I |= 0x40
  if 92 - 92: I1Ii111 / I1IiiI / I1ii11iIi11i + I11i + Ii1I
  i1I1ii111 = abs ( self . longitude )
  o0ooO000OO = ( ( self . long_mins * 60 ) + self . long_secs ) * 1000
  if ( self . longitude < 0 ) : II111Ii1I1I |= 0x20
  if 62 - 62: Ii1I / Oo0Ooo . OoO0O00 - OOooOOo
  oOOOOoOO0Oo = 0
  if ( self . no_geo_altitude ( ) == False ) :
   oOOOOoOO0Oo = socket . htonl ( self . altitude )
   II111Ii1I1I |= 0x10
   if 84 - 84: Oo0Ooo * I1Ii111 - o0oOOo0O0Ooo % Ii1I
  O00o0OoO = socket . htons ( self . radius )
  if ( O00o0OoO != 0 ) : II111Ii1I1I |= 0x06
  if 69 - 69: I11i + OoOoOO00 - i11iIiiIii * O0 % O0
  O00Oo000 = struct . pack ( "HBBBBH" , OoOoO00OoOOo , 0 , 0 , LISP_LCAF_GEO_COORD_TYPE ,
 0 , OOoo0Oo00 )
  O00Oo000 += struct . pack ( "BBHBBHBBHIHHH" , II111Ii1I1I , 0 , 0 , III1iIi111I1 , iiIIII1I1ii >> 16 ,
 socket . htons ( iiIIII1I1ii & 0x0ffff ) , i1I1ii111 , o0ooO000OO >> 16 ,
 socket . htons ( o0ooO000OO & 0xffff ) , oOOOOoOO0Oo , O00o0OoO , 0 , 0 )
  if 29 - 29: iIii1I11I1II1 / i11iIiiIii + Oo0Ooo
  return ( O00Oo000 )
  if 99 - 99: I1IiiI - iII111i * Ii1I - OoOoOO00 / i11iIiiIii - i1IIi
  if 46 - 46: I1ii11iIi11i * ooOoO0o
 def decode_geo ( self , packet , lcaf_len , radius_hi ) :
  i1I1iii1I11II = "BBHBBHBBHIHHH"
  Iiiii = struct . calcsize ( i1I1iii1I11II )
  if ( lcaf_len < Iiiii ) : return ( None )
  if 4 - 4: I1Ii111 * II111iiii
  II111Ii1I1I , I1II1I11Ii1i , oOI1iI1 , III1iIi111I1 , iii1 , iiIIII1I1ii , i1I1ii111 , IiI1iI1I , o0ooO000OO , oOOOOoOO0Oo , O00o0OoO , oO000o0ooO , O0ooo0 = struct . unpack ( i1I1iii1I11II ,
  # oO0o
 packet [ : Iiiii ] )
  if 65 - 65: Oo0Ooo . i1IIi + II111iiii . i1IIi * O0
  if 25 - 25: IiII - I11i + IiII + iII111i + OoOoOO00 - Oo0Ooo
  if 31 - 31: iII111i . II111iiii - iIii1I11I1II1
  if 38 - 38: ooOoO0o - IiII % OoO0O00 - i11iIiiIii
  O0ooo0 = socket . ntohs ( O0ooo0 )
  if ( O0ooo0 == LISP_AFI_LCAF ) : return ( None )
  if 44 - 44: I1Ii111 + ooOoO0o + OoO0O00
  if ( II111Ii1I1I & 0x40 ) : III1iIi111I1 = - III1iIi111I1
  self . latitude = III1iIi111I1
  oO0OO = ( ( iii1 << 16 ) | socket . ntohs ( iiIIII1I1ii ) ) / 1000
  self . lat_mins = oO0OO / 60
  self . lat_secs = oO0OO % 60
  if 94 - 94: i1IIi - i11iIiiIii + I1Ii111 % Oo0Ooo % Oo0Ooo . OoO0O00
  if ( II111Ii1I1I & 0x20 ) : i1I1ii111 = - i1I1ii111
  self . longitude = i1I1ii111
  O0000OOO0OOOo = ( ( IiI1iI1I << 16 ) | socket . ntohs ( o0ooO000OO ) ) / 1000
  self . long_mins = O0000OOO0OOOo / 60
  self . long_secs = O0000OOO0OOOo % 60
  if 89 - 89: II111iiii
  self . altitude = socket . ntohl ( oOOOOoOO0Oo ) if ( II111Ii1I1I & 0x10 ) else - 1
  O00o0OoO = socket . ntohs ( O00o0OoO )
  self . radius = O00o0OoO if ( II111Ii1I1I & 0x02 ) else O00o0OoO * 1000
  if 41 - 41: iIii1I11I1II1
  self . geo_name = None
  packet = packet [ Iiiii : : ]
  if 26 - 26: Oo0Ooo / i1IIi + Oo0Ooo
  if ( O0ooo0 != 0 ) :
   self . rloc . afi = O0ooo0
   packet = self . rloc . unpack_address ( packet )
   self . rloc . mask_len = self . rloc . host_mask_len ( )
   if 76 - 76: I1ii11iIi11i * i1IIi % oO0o
  return ( packet )
  if 80 - 80: i1IIi * II111iiii . O0 % I1ii11iIi11i / ooOoO0o
  if 58 - 58: I1IiiI * I1ii11iIi11i - i1IIi % I1Ii111 % O0
  if 24 - 24: I11i + I11i % I11i
  if 63 - 63: i11iIiiIii + iIii1I11I1II1 / oO0o % IiII - O0
  if 21 - 21: II111iiii
  if 89 - 89: OOooOOo % i11iIiiIii * OoOoOO00 % oO0o / O0 * i1IIi
class lisp_rle_node ( ) :
 def __init__ ( self ) :
  self . address = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . level = 0
  self . translated_port = 0
  self . rloc_name = None
  if 16 - 16: IiII
  if 42 - 42: i1IIi / Ii1I * I1ii11iIi11i
 def copy_rle_node ( self ) :
  Iii = lisp_rle_node ( )
  Iii . address . copy_address ( self . address )
  Iii . level = self . level
  Iii . translated_port = self . translated_port
  Iii . rloc_name = self . rloc_name
  return ( Iii )
  if 9 - 9: I11i % i1IIi / i1IIi / OoO0O00
  if 46 - 46: I1Ii111 * II111iiii + II111iiii * O0 % II111iiii
 def store_translated_rloc ( self , rloc , port ) :
  self . address . copy_address ( rloc )
  self . translated_port = port
  if 37 - 37: OOooOOo . iIii1I11I1II1 / O0 . ooOoO0o + OOooOOo - OoooooooOO
  if 96 - 96: I1Ii111 / oO0o . I1ii11iIi11i % I1IiiI * OOooOOo
 def get_encap_keys ( self ) :
  Oo0O00O = "4341" if self . translated_port == 0 else str ( self . translated_port )
  if 99 - 99: i11iIiiIii - I1Ii111
  oo0o00OO = self . address . print_address_no_iid ( ) + ":" + Oo0O00O
  if 4 - 4: o0oOOo0O0Ooo - i11iIiiIii . iIii1I11I1II1 . OOooOOo % IiII
  try :
   iIi11III = lisp_crypto_keys_by_rloc_encap [ oo0o00OO ]
   if ( iIi11III [ 1 ] ) : return ( iIi11III [ 1 ] . encrypt_key , iIi11III [ 1 ] . icv_key )
   return ( None , None )
  except :
   return ( None , None )
   if 68 - 68: I11i / iII111i - IiII . iIii1I11I1II1 / o0oOOo0O0Ooo
   if 54 - 54: II111iiii * I1IiiI
   if 49 - 49: I1ii11iIi11i
   if 31 - 31: o0oOOo0O0Ooo - OoOoOO00 + I1ii11iIi11i . oO0o - O0
class lisp_rle ( ) :
 def __init__ ( self , name ) :
  self . rle_name = name
  self . rle_nodes = [ ]
  self . rle_forwarding_list = [ ]
  if 61 - 61: I1ii11iIi11i * II111iiii . i1IIi
  if 60 - 60: OoooooooOO % ooOoO0o * i11iIiiIii * OoooooooOO % IiII
 def copy_rle ( self ) :
  iI1Ii11 = lisp_rle ( self . rle_name )
  for Iii in self . rle_nodes :
   iI1Ii11 . rle_nodes . append ( Iii . copy_rle_node ( ) )
   if 15 - 15: oO0o
  iI1Ii11 . build_forwarding_list ( )
  return ( iI1Ii11 )
  if 40 - 40: I1Ii111
  if 77 - 77: II111iiii - o0oOOo0O0Ooo . Ii1I
 def print_rle ( self , html , do_formatting ) :
  II1I = ""
  for Iii in self . rle_nodes :
   Oo0O00O = Iii . translated_port
   if 47 - 47: o0oOOo0O0Ooo % OOooOOo + I1Ii111
   o0o0 = ""
   if ( Iii . rloc_name != None ) :
    o0o0 = Iii . rloc_name
    if ( do_formatting ) : o0o0 = blue ( o0o0 , html )
    o0o0 = "({})" . format ( o0o0 )
    if 31 - 31: Ii1I + O0 - OOooOOo * O0 * I11i
    if 53 - 53: I1ii11iIi11i + i11iIiiIii / iIii1I11I1II1 + OoooooooOO + IiII * I1IiiI
   oo0o00OO = Iii . address . print_address_no_iid ( )
   if ( Iii . address . is_local ( ) ) : oo0o00OO = red ( oo0o00OO , html )
   II1I += "{}{}{}, " . format ( oo0o00OO , "" if Oo0O00O == 0 else ":" + str ( Oo0O00O ) , o0o0 )
   if 16 - 16: i11iIiiIii - oO0o . i11iIiiIii + OoO0O00 + i11iIiiIii
   if 85 - 85: I1ii11iIi11i - ooOoO0o + I1Ii111 + I1Ii111
  return ( II1I [ 0 : - 2 ] if II1I != "" else "" )
  if 13 - 13: II111iiii
  if 22 - 22: o0oOOo0O0Ooo
 def build_forwarding_list ( self ) :
  oOOoOoooOo0o = - 1
  for Iii in self . rle_nodes :
   if ( oOOoOoooOo0o == - 1 ) :
    if ( Iii . address . is_local ( ) ) : oOOoOoooOo0o = Iii . level
   else :
    if ( Iii . level > oOOoOoooOo0o ) : break
    if 45 - 45: I1Ii111 + OoooooooOO + o0oOOo0O0Ooo * II111iiii
    if 12 - 12: I1ii11iIi11i / O0
  oOOoOoooOo0o = 0 if oOOoOoooOo0o == - 1 else Iii . level
  if 18 - 18: OoOoOO00 . i11iIiiIii + i1IIi / OoooooooOO - IiII % OoO0O00
  self . rle_forwarding_list = [ ]
  for Iii in self . rle_nodes :
   if ( Iii . level == oOOoOoooOo0o or ( oOOoOoooOo0o == 0 and
 Iii . level == 128 ) ) :
    if ( lisp_i_am_rtr == False and Iii . address . is_local ( ) ) :
     oo0o00OO = Iii . address . print_address_no_iid ( )
     lprint ( "Exclude local RLE RLOC {}" . format ( oo0o00OO ) )
     continue
     if 47 - 47: iII111i % IiII + I1Ii111 * o0oOOo0O0Ooo * OoooooooOO
    self . rle_forwarding_list . append ( Iii )
    if 100 - 100: Oo0Ooo / I1IiiI / iII111i / I1Ii111 / oO0o % o0oOOo0O0Ooo
    if 16 - 16: I1IiiI + I11i
    if 66 - 66: OoooooooOO % II111iiii / I1Ii111 . i11iIiiIii
    if 67 - 67: Ii1I + Oo0Ooo - I1IiiI - IiII + oO0o + Oo0Ooo
    if 84 - 84: I1ii11iIi11i % oO0o - OOooOOo * Ii1I
class lisp_json ( ) :
 def __init__ ( self , name , string , encrypted = False , ms_encrypt = False ) :
  self . json_name = name
  self . json_string = string
  self . json_encrypted = False
  if 78 - 78: i1IIi / ooOoO0o / oO0o
  if 21 - 21: IiII % Ii1I + OOooOOo + IiII
  if 90 - 90: o0oOOo0O0Ooo
  if 38 - 38: OoOoOO00 / OOooOOo % OoooooooOO * I1ii11iIi11i
  if 7 - 7: I11i * O0 + Oo0Ooo / O0 * oO0o + i11iIiiIii
  if 74 - 74: OoOoOO00
  if 91 - 91: i11iIiiIii / Ii1I % OOooOOo % O0 - I11i . I11i
  if 78 - 78: i1IIi + I11i % OoooooooOO + i1IIi + iII111i % Ii1I
  if 87 - 87: ooOoO0o . iIii1I11I1II1
  if 99 - 99: Ii1I + OoooooooOO * IiII * i11iIiiIii - iIii1I11I1II1
  if ( len ( lisp_ms_json_keys ) != 0 ) :
   if ( ms_encrypt == False ) : return
   self . json_key_id = lisp_ms_json_keys . keys ( ) [ 0 ]
   self . json_key = lisp_ms_json_keys [ self . json_key_id ]
   self . encrypt_json ( )
   if 58 - 58: IiII % i1IIi . i11iIiiIii
   if 5 - 5: OoOoOO00
  if ( lisp_log_id == "lig" and encrypted ) :
   Oo000O000 = os . getenv ( "LISP_JSON_KEY" )
   if ( Oo000O000 != None ) :
    ooo = - 1
    if ( Oo000O000 [ 0 ] == "[" and "]" in Oo000O000 ) :
     ooo = Oo000O000 . find ( "]" )
     self . json_key_id = int ( Oo000O000 [ 1 : ooo ] )
     if 75 - 75: OOooOOo
    self . json_key = Oo000O000 [ ooo + 1 : : ]
    if 60 - 60: ooOoO0o - II111iiii - iIii1I11I1II1
    self . decrypt_json ( )
    if 23 - 23: I1ii11iIi11i
    if 68 - 68: OoO0O00 . oO0o / IiII - II111iiii % Oo0Ooo
    if 24 - 24: II111iiii / I1ii11iIi11i + oO0o / Ii1I + IiII % oO0o
    if 86 - 86: I1IiiI
 def add ( self ) :
  self . delete ( )
  lisp_json_list [ self . json_name ] = self
  if 83 - 83: I11i % Ii1I + IiII % I11i / i1IIi . oO0o
  if 56 - 56: I1Ii111 - OOooOOo % o0oOOo0O0Ooo
 def delete ( self ) :
  if ( lisp_json_list . has_key ( self . json_name ) ) :
   del ( lisp_json_list [ self . json_name ] )
   lisp_json_list [ self . json_name ] = None
   if 30 - 30: I1Ii111 % i1IIi
   if 98 - 98: oO0o . i11iIiiIii / Ii1I - Ii1I
   if 23 - 23: iIii1I11I1II1
 def print_json ( self , html ) :
  iIIIiI = self . json_string
  IiiiIi = "***"
  if ( html ) : IiiiIi = red ( IiiiIi , html )
  I1iii11III = IiiiIi + self . json_string + IiiiIi
  if ( self . valid_json ( ) ) : return ( iIIIiI )
  return ( I1iii11III )
  if 36 - 36: i1IIi . oO0o . I1Ii111 - I1Ii111 . OOooOOo
  if 59 - 59: IiII - i11iIiiIii
 def valid_json ( self ) :
  try :
   json . loads ( self . json_string )
  except :
   return ( False )
   if 23 - 23: OoOoOO00 . i1IIi / iIii1I11I1II1 + iII111i / iII111i
  return ( True )
  if 22 - 22: Ii1I % OoooooooOO - IiII / i1IIi / iIii1I11I1II1 . O0
  if 61 - 61: OoOoOO00 * OOooOOo
 def encrypt_json ( self ) :
  II11iI11i1 = self . json_key . zfill ( 32 )
  iiI1iiIiiiI1I = "0" * 8
  if 3 - 3: I1IiiI + Oo0Ooo / I1Ii111
  IiiI = json . loads ( self . json_string )
  for Oo000O000 in IiiI :
   i11II = IiiI [ Oo000O000 ]
   i11II = chacha . ChaCha ( II11iI11i1 , iiI1iiIiiiI1I ) . encrypt ( i11II )
   IiiI [ Oo000O000 ] = binascii . hexlify ( i11II )
   if 28 - 28: I1IiiI . O0 % o0oOOo0O0Ooo / I11i
  self . json_string = json . dumps ( IiiI )
  self . json_encrypted = True
  if 48 - 48: II111iiii % I1ii11iIi11i - II111iiii
  if 29 - 29: I1Ii111 - I1Ii111 - I11i * iIii1I11I1II1 % OoO0O00 % IiII
 def decrypt_json ( self ) :
  II11iI11i1 = self . json_key . zfill ( 32 )
  iiI1iiIiiiI1I = "0" * 8
  if 73 - 73: i1IIi . OoooooooOO / OoOoOO00 % Ii1I / Ii1I / Ii1I
  IiiI = json . loads ( self . json_string )
  for Oo000O000 in IiiI :
   i11II = binascii . unhexlify ( IiiI [ Oo000O000 ] )
   IiiI [ Oo000O000 ] = chacha . ChaCha ( II11iI11i1 , iiI1iiIiiiI1I ) . encrypt ( i11II )
   if 40 - 40: I1Ii111 - iIii1I11I1II1
  try :
   self . json_string = json . dumps ( IiiI )
   self . json_encrypted = False
  except :
   pass
   if 88 - 88: OOooOOo * O0 * OoOoOO00
   if 26 - 26: Ii1I
   if 65 - 65: iII111i / iIii1I11I1II1 + I11i - iIii1I11I1II1 - Ii1I . I1Ii111
   if 77 - 77: OoOoOO00 / I1IiiI + IiII
   if 66 - 66: i11iIiiIii * OoooooooOO + iII111i / Ii1I
   if 42 - 42: Ii1I / iIii1I11I1II1 / Oo0Ooo . O0 . oO0o * I1IiiI
   if 21 - 21: OoooooooOO
class lisp_stats ( ) :
 def __init__ ( self ) :
  self . packet_count = 0
  self . byte_count = 0
  self . last_rate_check = 0
  self . last_packet_count = 0
  self . last_byte_count = 0
  self . last_increment = None
  if 76 - 76: i1IIi * i11iIiiIii / OOooOOo + I1Ii111
  if 50 - 50: oO0o % OoOoOO00 + I1IiiI
 def increment ( self , octets ) :
  self . packet_count += 1
  self . byte_count += octets
  self . last_increment = lisp_get_timestamp ( )
  if 15 - 15: II111iiii - iII111i / I1ii11iIi11i
  if 81 - 81: Ii1I - i1IIi % oO0o * Oo0Ooo * OoOoOO00
 def recent_packet_sec ( self ) :
  if ( self . last_increment == None ) : return ( False )
  oO000o0Oo00 = time . time ( ) - self . last_increment
  return ( oO000o0Oo00 <= 1 )
  if 79 - 79: oO0o + I1IiiI % iII111i + II111iiii % OoO0O00 % iII111i
  if 46 - 46: o0oOOo0O0Ooo
 def recent_packet_min ( self ) :
  if ( self . last_increment == None ) : return ( False )
  oO000o0Oo00 = time . time ( ) - self . last_increment
  return ( oO000o0Oo00 <= 60 )
  if 61 - 61: OoO0O00 . O0 + I1ii11iIi11i + OoO0O00
  if 44 - 44: I11i . oO0o
 def stat_colors ( self , c1 , c2 , html ) :
  if ( self . recent_packet_sec ( ) ) :
   return ( green_last_sec ( c1 ) , green_last_sec ( c2 ) )
   if 65 - 65: I1ii11iIi11i * II111iiii % I11i + II111iiii . i1IIi / ooOoO0o
  if ( self . recent_packet_min ( ) ) :
   return ( green_last_min ( c1 ) , green_last_min ( c2 ) )
   if 74 - 74: OoOoOO00 % OoO0O00 . OoOoOO00
  return ( c1 , c2 )
  if 16 - 16: OoO0O00 / Ii1I * i11iIiiIii / o0oOOo0O0Ooo + I1Ii111
  if 21 - 21: I11i % I1ii11iIi11i
 def normalize ( self , count ) :
  count = str ( count )
  IIIIIiII1iI = len ( count )
  if ( IIIIIiII1iI > 12 ) :
   count = count [ 0 : - 10 ] + "." + count [ - 10 : - 7 ] + "T"
   return ( count )
   if 39 - 39: OoOoOO00 - I11i / i11iIiiIii . Ii1I * OoOoOO00 - II111iiii
  if ( IIIIIiII1iI > 9 ) :
   count = count [ 0 : - 9 ] + "." + count [ - 9 : - 7 ] + "B"
   return ( count )
   if 79 - 79: ooOoO0o + II111iiii . oO0o
  if ( IIIIIiII1iI > 6 ) :
   count = count [ 0 : - 6 ] + "." + count [ - 6 ] + "M"
   return ( count )
   if 27 - 27: I1ii11iIi11i % IiII - ooOoO0o + O0 * IiII
  return ( count )
  if 87 - 87: oO0o % OoO0O00 . iIii1I11I1II1 * ooOoO0o + oO0o + IiII
  if 74 - 74: i1IIi % i1IIi + Oo0Ooo
 def get_stats ( self , summary , html ) :
  i1iI = self . last_rate_check
  i1IiI11I = self . last_packet_count
  II1IIII11 = self . last_byte_count
  self . last_rate_check = lisp_get_timestamp ( )
  self . last_packet_count = self . packet_count
  self . last_byte_count = self . byte_count
  if 13 - 13: I11i + II111iiii + I1ii11iIi11i * i11iIiiIii
  O0oI1Ii1II = self . last_rate_check - i1iI
  if ( O0oI1Ii1II == 0 ) :
   i11ii1 = 0
   I11I = 0
  else :
   i11ii1 = int ( ( self . packet_count - i1IiI11I ) / O0oI1Ii1II )
   I11I = ( self . byte_count - II1IIII11 ) / O0oI1Ii1II
   I11I = ( I11I * 8 ) / 1000000
   I11I = round ( I11I , 2 )
   if 3 - 3: Ii1I . O0 * II111iiii + I1ii11iIi11i
   if 45 - 45: OoO0O00 / I1ii11iIi11i * ooOoO0o * OOooOOo % i11iIiiIii * iII111i
   if 33 - 33: oO0o . iII111i + Oo0Ooo
   if 33 - 33: ooOoO0o
   if 46 - 46: OoOoOO00 / iII111i - OoO0O00 . o0oOOo0O0Ooo
  I1iiI1iiiI = self . normalize ( self . packet_count )
  IiIiIiiiI1 = self . normalize ( self . byte_count )
  if 19 - 19: IiII . Oo0Ooo . oO0o * i11iIiiIii
  if 26 - 26: OoooooooOO
  if 79 - 79: I1IiiI + I1IiiI
  if 45 - 45: oO0o + I1IiiI / oO0o
  if 33 - 33: OoooooooOO - I1Ii111 . Oo0Ooo % OoooooooOO * ooOoO0o
  if ( summary ) :
   oooooooOOOOO = "<br>" if html else ""
   I1iiI1iiiI , IiIiIiiiI1 = self . stat_colors ( I1iiI1iiiI , IiIiIiiiI1 , html )
   OOO0oOo0ooOOO = "packet-count: {}{}byte-count: {}" . format ( I1iiI1iiiI , oooooooOOOOO , IiIiIiiiI1 )
   I1i1IIiIIiIiIi = "packet-rate: {} pps\nbit-rate: {} Mbps" . format ( i11ii1 , I11I )
   if 23 - 23: ooOoO0o + ooOoO0o . I11i
   if ( html != "" ) : I1i1IIiIIiIiIi = lisp_span ( OOO0oOo0ooOOO , I1i1IIiIIiIiIi )
  else :
   o0ooO = str ( i11ii1 )
   Iii11i1I1 = str ( I11I )
   if ( html ) :
    I1iiI1iiiI = lisp_print_cour ( I1iiI1iiiI )
    o0ooO = lisp_print_cour ( o0ooO )
    IiIiIiiiI1 = lisp_print_cour ( IiIiIiiiI1 )
    Iii11i1I1 = lisp_print_cour ( Iii11i1I1 )
    if 35 - 35: OoooooooOO / OoOoOO00 * i1IIi * OoOoOO00 % Ii1I
   oooooooOOOOO = "<br>" if html else ", "
   if 50 - 50: IiII - II111iiii
   I1i1IIiIIiIiIi = ( "packet-count: {}{}packet-rate: {} pps{}byte-count: " + "{}{}bit-rate: {} mbps" ) . format ( I1iiI1iiiI , oooooooOOOOO , o0ooO , oooooooOOOOO , IiIiIiiiI1 , oooooooOOOOO ,
   # OOooOOo
 Iii11i1I1 )
   if 82 - 82: I1Ii111
  return ( I1i1IIiIIiIiIi )
  if 78 - 78: I1Ii111 % oO0o * iIii1I11I1II1
  if 1 - 1: i1IIi . iIii1I11I1II1
  if 2 - 2: OOooOOo % Oo0Ooo * OOooOOo + I1Ii111 % OoOoOO00 / O0
  if 23 - 23: O0 * oO0o / I1IiiI + i1IIi * O0 % oO0o
  if 11 - 11: I1Ii111 . OoooooooOO * iIii1I11I1II1 / I1ii11iIi11i - ooOoO0o . iII111i
  if 71 - 71: i11iIiiIii + I11i / i11iIiiIii % Oo0Ooo / iIii1I11I1II1 * OoO0O00
  if 49 - 49: iII111i + OoOoOO00
  if 33 - 33: ooOoO0o
lisp_decap_stats = {
 "good-packets" : lisp_stats ( ) , "ICV-error" : lisp_stats ( ) ,
 "checksum-error" : lisp_stats ( ) , "lisp-header-error" : lisp_stats ( ) ,
 "no-decrypt-key" : lisp_stats ( ) , "bad-inner-version" : lisp_stats ( ) ,
 "outer-header-error" : lisp_stats ( )
 }
if 19 - 19: I1Ii111 % IiII
if 94 - 94: I1Ii111 * I1ii11iIi11i * I1ii11iIi11i - o0oOOo0O0Ooo . i11iIiiIii
if 16 - 16: i1IIi
if 88 - 88: OOooOOo
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
  if 79 - 79: oO0o
  if ( recurse == False ) : return
  if 52 - 52: oO0o + OoO0O00 / OoooooooOO - iIii1I11I1II1 / iII111i - oO0o
  if 68 - 68: I1IiiI - OoOoOO00 - iIii1I11I1II1 % i11iIiiIii * OoOoOO00 * OoO0O00
  if 97 - 97: OoO0O00 - IiII + ooOoO0o % iIii1I11I1II1 % iII111i
  if 100 - 100: IiII - Ii1I * iIii1I11I1II1 . iII111i . i1IIi % Oo0Ooo
  if 11 - 11: I11i + oO0o % Ii1I
  if 22 - 22: ooOoO0o
  O0OoooOoo = lisp_get_default_route_next_hops ( )
  if ( O0OoooOoo == [ ] or len ( O0OoooOoo ) == 1 ) : return
  if 46 - 46: Oo0Ooo % i11iIiiIii * o0oOOo0O0Ooo
  self . rloc_next_hop = O0OoooOoo [ 0 ]
  iiI = self
  for II11111Iii1I in O0OoooOoo [ 1 : : ] :
   OoOO000O = lisp_rloc ( False )
   OoOO000O = copy . deepcopy ( self )
   OoOO000O . rloc_next_hop = II11111Iii1I
   iiI . next_rloc = OoOO000O
   iiI = OoOO000O
   if 15 - 15: i11iIiiIii % I1ii11iIi11i - i11iIiiIii
   if 68 - 68: ooOoO0o
   if 53 - 53: i11iIiiIii / OoOoOO00 % o0oOOo0O0Ooo / IiII
 def up_state ( self ) :
  return ( self . state == LISP_RLOC_UP_STATE )
  if 88 - 88: ooOoO0o . i1IIi
  if 21 - 21: OoO0O00 * I1ii11iIi11i + I1ii11iIi11i
 def unreach_state ( self ) :
  return ( self . state == LISP_RLOC_UNREACH_STATE )
  if 36 - 36: Ii1I . OOooOOo * iIii1I11I1II1 - i1IIi
  if 38 - 38: Oo0Ooo . o0oOOo0O0Ooo % oO0o / i11iIiiIii * OoO0O00 % OoOoOO00
 def no_echoed_nonce_state ( self ) :
  return ( self . state == LISP_RLOC_NO_ECHOED_NONCE_STATE )
  if 18 - 18: OOooOOo
  if 12 - 12: I1Ii111 % II111iiii / o0oOOo0O0Ooo - iIii1I11I1II1 + II111iiii
 def down_state ( self ) :
  return ( self . state in [ LISP_RLOC_DOWN_STATE , LISP_RLOC_ADMIN_DOWN_STATE ] )
  if 41 - 41: OOooOOo
  if 8 - 8: i11iIiiIii . IiII . I1ii11iIi11i + i1IIi % I1Ii111
  if 64 - 64: I1IiiI . Oo0Ooo * OoO0O00
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
  if 87 - 87: i1IIi / OoooooooOO
  if 68 - 68: I1Ii111 / iIii1I11I1II1
 def print_rloc ( self , indent ) :
  i1 = lisp_print_elapsed ( self . uptime )
  lprint ( "{}rloc {}, uptime {}, {}, parms {}/{}/{}/{}" . format ( indent ,
 red ( self . rloc . print_address ( ) , False ) , i1 , self . print_state ( ) ,
 self . priority , self . weight , self . mpriority , self . mweight ) )
  if 8 - 8: ooOoO0o * IiII * OOooOOo / I1IiiI
  if 40 - 40: i11iIiiIii + OoooooooOO
 def print_rloc_name ( self , cour = False ) :
  if ( self . rloc_name == None ) : return ( "" )
  oo0O0OOooO0 = self . rloc_name
  if ( cour ) : oo0O0OOooO0 = lisp_print_cour ( oo0O0OOooO0 )
  return ( 'rloc-name: {}' . format ( blue ( oo0O0OOooO0 , cour ) ) )
  if 2 - 2: o0oOOo0O0Ooo * OoO0O00
  if 88 - 88: Oo0Ooo + oO0o + iII111i
 def store_rloc_from_record ( self , rloc_record , nonce , source ) :
  Oo0O00O = LISP_DATA_PORT
  self . rloc . copy_address ( rloc_record . rloc )
  self . rloc_name = rloc_record . rloc_name
  if 51 - 51: i1IIi + i11iIiiIii * I11i / iII111i + OoooooooOO
  if 89 - 89: i11iIiiIii - I1Ii111 - O0 % iIii1I11I1II1 / IiII - O0
  if 63 - 63: OOooOOo
  if 23 - 23: Oo0Ooo / i1IIi - OOooOOo / Oo0Ooo
  I1IIiIIIii = self . rloc
  if ( I1IIiIIIii . is_null ( ) == False ) :
   IIiiiiII = lisp_get_nat_info ( I1IIiIIIii , self . rloc_name )
   if ( IIiiiiII ) :
    Oo0O00O = IIiiiiII . port
    O00O0oo0O0OOo = lisp_nat_state_info [ self . rloc_name ] [ 0 ]
    oo0o00OO = I1IIiIIIii . print_address_no_iid ( )
    o0oooOoOoOo = red ( oo0o00OO , False )
    IiIIiiI1iI1iI = "" if self . rloc_name == None else blue ( self . rloc_name , False )
    if 71 - 71: OoooooooOO - IiII . I1ii11iIi11i + OoooooooOO
    if 97 - 97: Ii1I - I1IiiI . OoooooooOO * IiII
    if 17 - 17: OoO0O00 / II111iiii / II111iiii / II111iiii
    if 70 - 70: OoO0O00 + O0 * OoO0O00
    if 25 - 25: OoooooooOO . Oo0Ooo + OOooOOo + Oo0Ooo * O0 % i1IIi
    if 71 - 71: II111iiii / Ii1I + i1IIi - OoOoOO00 + Ii1I
    if ( IIiiiiII . timed_out ( ) ) :
     lprint ( ( "    Matched stored NAT state timed out for " + "RLOC {}:{}, {}" ) . format ( o0oooOoOoOo , Oo0O00O , IiIIiiI1iI1iI ) )
     if 31 - 31: OoooooooOO * Ii1I - iII111i . oO0o % Ii1I
     if 97 - 97: Ii1I
     IIiiiiII = None if ( IIiiiiII == O00O0oo0O0OOo ) else O00O0oo0O0OOo
     if ( IIiiiiII and IIiiiiII . timed_out ( ) ) :
      Oo0O00O = IIiiiiII . port
      o0oooOoOoOo = red ( IIiiiiII . address , False )
      lprint ( ( "    Youngest stored NAT state timed out " + " for RLOC {}:{}, {}" ) . format ( o0oooOoOoOo , Oo0O00O ,
      # iIii1I11I1II1 + I11i / iII111i - OoOoOO00
 IiIIiiI1iI1iI ) )
      IIiiiiII = None
      if 61 - 61: ooOoO0o / O0 * IiII / OoO0O00
      if 56 - 56: OoO0O00 + O0
      if 2 - 2: OoOoOO00 - iIii1I11I1II1 * I1Ii111 % II111iiii - Oo0Ooo . OoooooooOO
      if 47 - 47: I1Ii111 + oO0o - Ii1I % OoO0O00 - I1Ii111 / i11iIiiIii
      if 27 - 27: i11iIiiIii . OoO0O00 + Ii1I
      if 47 - 47: I1Ii111 . iIii1I11I1II1 + i11iIiiIii
      if 75 - 75: iIii1I11I1II1 / OoO0O00 * OOooOOo % O0
    if ( IIiiiiII ) :
     if ( IIiiiiII . address != oo0o00OO ) :
      lprint ( "RLOC conflict, RLOC-record {}, NAT state {}" . format ( o0oooOoOoOo , red ( IIiiiiII . address , False ) ) )
      if 82 - 82: Oo0Ooo / i1IIi . i1IIi / oO0o
      self . rloc . store_address ( IIiiiiII . address )
      if 7 - 7: Oo0Ooo . iII111i % I1ii11iIi11i / iII111i
     o0oooOoOoOo = red ( IIiiiiII . address , False )
     Oo0O00O = IIiiiiII . port
     lprint ( "    Use NAT translated RLOC {}:{} for {}" . format ( o0oooOoOoOo , Oo0O00O , IiIIiiI1iI1iI ) )
     if 93 - 93: iII111i
     self . store_translated_rloc ( I1IIiIIIii , Oo0O00O )
     if 5 - 5: iII111i . I11i % I11i * Ii1I - I1ii11iIi11i . i11iIiiIii
     if 32 - 32: II111iiii
     if 58 - 58: I1IiiI - o0oOOo0O0Ooo - I1Ii111 . O0 % OoO0O00 . I11i
     if 41 - 41: iII111i . I1Ii111 - IiII / O0
  self . geo = rloc_record . geo
  self . elp = rloc_record . elp
  self . json = rloc_record . json
  if 62 - 62: IiII * I1ii11iIi11i * iII111i * OoOoOO00
  if 12 - 12: Oo0Ooo * Ii1I / ooOoO0o % I11i % O0
  if 25 - 25: Oo0Ooo * oO0o
  if 78 - 78: OoOoOO00 / II111iiii
  self . rle = rloc_record . rle
  if ( self . rle ) :
   for Iii in self . rle . rle_nodes :
    oo0O0OOooO0 = Iii . rloc_name
    IIiiiiII = lisp_get_nat_info ( Iii . address , oo0O0OOooO0 )
    if ( IIiiiiII == None ) : continue
    if 6 - 6: I1Ii111 . OoOoOO00
    Oo0O00O = IIiiiiII . port
    Ooooo = oo0O0OOooO0
    if ( Ooooo ) : Ooooo = blue ( oo0O0OOooO0 , False )
    if 75 - 75: Oo0Ooo + I11i
    lprint ( ( "      Store translated encap-port {} for RLE-" + "node {}, rloc-name '{}'" ) . format ( Oo0O00O ,
    # I1IiiI . I1ii11iIi11i + OoO0O00 . ooOoO0o . O0 / OoO0O00
 Iii . address . print_address_no_iid ( ) , Ooooo ) )
    Iii . translated_port = Oo0O00O
    if 50 - 50: Ii1I . OoOoOO00 * o0oOOo0O0Ooo
    if 68 - 68: IiII * oO0o / OoOoOO00 / I1Ii111
    if 72 - 72: I1ii11iIi11i
  self . priority = rloc_record . priority
  self . mpriority = rloc_record . mpriority
  self . weight = rloc_record . weight
  self . mweight = rloc_record . mweight
  if ( rloc_record . reach_bit and rloc_record . local_bit and
 rloc_record . probe_bit == False ) : self . state = LISP_RLOC_UP_STATE
  if 74 - 74: I1Ii111 * iIii1I11I1II1 / oO0o - IiII - I1IiiI
  if 84 - 84: iIii1I11I1II1 % Oo0Ooo / I1ii11iIi11i + o0oOOo0O0Ooo * II111iiii
  if 81 - 81: I1IiiI / I1ii11iIi11i / OOooOOo
  if 89 - 89: Oo0Ooo % IiII
  i11IIiI1II = source . is_exact_match ( rloc_record . rloc ) if source != None else None
  if 47 - 47: O0
  if ( rloc_record . keys != None and i11IIiI1II ) :
   Oo000O000 = rloc_record . keys [ 1 ]
   if ( Oo000O000 != None ) :
    oo0o00OO = rloc_record . rloc . print_address_no_iid ( ) + ":" + str ( Oo0O00O )
    if 93 - 93: oO0o
    Oo000O000 . add_key_by_rloc ( oo0o00OO , True )
    lprint ( "    Store encap-keys for nonce 0x{}, RLOC {}" . format ( lisp_hex_string ( nonce ) , red ( oo0o00OO , False ) ) )
    if 13 - 13: OoooooooOO / ooOoO0o + IiII / oO0o + oO0o
    if 78 - 78: iII111i * o0oOOo0O0Ooo + OOooOOo
    if 39 - 39: ooOoO0o + o0oOOo0O0Ooo + OOooOOo * OoOoOO00
  return ( Oo0O00O )
  if 98 - 98: iIii1I11I1II1 - oO0o
  if 91 - 91: iII111i % iII111i . ooOoO0o / iII111i
 def store_translated_rloc ( self , rloc , port ) :
  self . rloc . copy_address ( rloc )
  self . translated_rloc . copy_address ( rloc )
  self . translated_port = port
  if 29 - 29: OoooooooOO + i11iIiiIii
  if 11 - 11: OoooooooOO % oO0o - OoO0O00
 def is_rloc_translated ( self ) :
  return ( self . translated_rloc . is_null ( ) == False )
  if 49 - 49: ooOoO0o + iII111i % OoooooooOO / Oo0Ooo % i1IIi
  if 50 - 50: OoO0O00
 def rloc_exists ( self ) :
  if ( self . rloc . is_null ( ) == False ) : return ( True )
  if ( self . rle_name or self . geo_name or self . elp_name or self . json_name ) :
   return ( False )
   if 52 - 52: o0oOOo0O0Ooo + O0
  return ( True )
  if 13 - 13: OoO0O00
  if 56 - 56: OoOoOO00 . ooOoO0o * oO0o - I11i
 def is_rtr ( self ) :
  return ( ( self . priority == 254 and self . mpriority == 255 and self . weight == 0 and self . mweight == 0 ) )
  if 47 - 47: oO0o . i1IIi * I1ii11iIi11i % OOooOOo % IiII / Oo0Ooo
  if 39 - 39: i11iIiiIii . OOooOOo + Oo0Ooo
  if 92 - 92: O0 * Oo0Ooo / o0oOOo0O0Ooo % OoO0O00
 def print_state_change ( self , new_state ) :
  ooo0II11IiiiIiIi1 = self . print_state ( )
  Iii11I111Ii11 = "{} -> {}" . format ( ooo0II11IiiiIiIi1 , new_state )
  if ( new_state == "up" and self . unreach_state ( ) ) :
   Iii11I111Ii11 = bold ( Iii11I111Ii11 , False )
   if 95 - 95: Oo0Ooo
  return ( Iii11I111Ii11 )
  if 74 - 74: OoooooooOO * i11iIiiIii * OoO0O00 * o0oOOo0O0Ooo
  if 48 - 48: iII111i * I1ii11iIi11i * oO0o % O0 . OoO0O00
 def print_rloc_probe_rtt ( self ) :
  if ( self . rloc_probe_rtt == - 1 ) : return ( "none" )
  return ( self . rloc_probe_rtt )
  if 11 - 11: OOooOOo / o0oOOo0O0Ooo
  if 98 - 98: oO0o + I11i . oO0o
 def print_recent_rloc_probe_rtts ( self ) :
  I1ii11 = str ( self . recent_rloc_probe_rtts )
  I1ii11 = I1ii11 . replace ( "-1" , "?" )
  return ( I1ii11 )
  if 17 - 17: IiII * Oo0Ooo . i11iIiiIii . IiII . Oo0Ooo % IiII
  if 93 - 93: II111iiii - IiII - O0 - i11iIiiIii / OOooOOo
 def compute_rloc_probe_rtt ( self ) :
  iiI = self . rloc_probe_rtt
  self . rloc_probe_rtt = - 1
  if ( self . last_rloc_probe_reply == None ) : return
  if ( self . last_rloc_probe == None ) : return
  self . rloc_probe_rtt = self . last_rloc_probe_reply - self . last_rloc_probe
  self . rloc_probe_rtt = round ( self . rloc_probe_rtt , 3 )
  oo0O0ooo00 = self . recent_rloc_probe_rtts
  self . recent_rloc_probe_rtts = [ iiI ] + oo0O0ooo00 [ 0 : - 1 ]
  if 47 - 47: Oo0Ooo + oO0o % OoooooooOO
  if 23 - 23: I1Ii111 / i11iIiiIii - ooOoO0o * iII111i - Ii1I . iIii1I11I1II1
 def print_rloc_probe_hops ( self ) :
  return ( self . rloc_probe_hops )
  if 11 - 11: I11i % OoOoOO00 * Oo0Ooo
  if 48 - 48: OOooOOo
 def print_recent_rloc_probe_hops ( self ) :
  O0O0ooOOO = str ( self . recent_rloc_probe_hops )
  return ( O0O0ooOOO )
  if 90 - 90: O0 - i11iIiiIii * ooOoO0o . I1ii11iIi11i . Ii1I - OoooooooOO
  if 23 - 23: o0oOOo0O0Ooo
 def store_rloc_probe_hops ( self , to_hops , from_ttl ) :
  if ( to_hops == 0 ) :
   to_hops = "?"
  elif ( to_hops < LISP_RLOC_PROBE_TTL / 2 ) :
   to_hops = "!"
  else :
   to_hops = str ( LISP_RLOC_PROBE_TTL - to_hops )
   if 88 - 88: I1Ii111 + iIii1I11I1II1 / o0oOOo0O0Ooo
  if ( from_ttl < LISP_RLOC_PROBE_TTL / 2 ) :
   O0Ooo0O00O = "!"
  else :
   O0Ooo0O00O = str ( LISP_RLOC_PROBE_TTL - from_ttl )
   if 19 - 19: OOooOOo - II111iiii
   if 80 - 80: Oo0Ooo % I1Ii111
  iiI = self . rloc_probe_hops
  self . rloc_probe_hops = to_hops + "/" + O0Ooo0O00O
  oo0O0ooo00 = self . recent_rloc_probe_hops
  self . recent_rloc_probe_hops = [ iiI ] + oo0O0ooo00 [ 0 : - 1 ]
  if 91 - 91: OoooooooOO - O0 . iII111i - II111iiii % O0 - OoooooooOO
  if 94 - 94: I1IiiI % I1ii11iIi11i
 def store_rloc_probe_latencies ( self , json_telemetry ) :
  iiiiIIiI = lisp_decode_telemetry ( json_telemetry )
  if 56 - 56: ooOoO0o
  ooO00Oo = round ( float ( iiiiIIiI [ "etr-in" ] ) - float ( iiiiIIiI [ "itr-out" ] ) , 3 )
  o0oOOOoOOo00 = round ( float ( iiiiIIiI [ "itr-in" ] ) - float ( iiiiIIiI [ "etr-out" ] ) , 3 )
  if 75 - 75: i11iIiiIii
  iiI = self . rloc_probe_latency
  self . rloc_probe_latency = str ( ooO00Oo ) + "/" + str ( o0oOOOoOOo00 )
  oo0O0ooo00 = self . recent_rloc_probe_latencies
  self . recent_rloc_probe_latencies = [ iiI ] + oo0O0ooo00 [ 0 : - 1 ]
  if 27 - 27: I11i - IiII - I1Ii111
  if 90 - 90: OoO0O00 . oO0o * O0 / I11i % O0 + I1Ii111
 def print_rloc_probe_latency ( self ) :
  return ( self . rloc_probe_latency )
  if 48 - 48: iIii1I11I1II1 . i11iIiiIii / OoooooooOO . i1IIi . o0oOOo0O0Ooo
  if 84 - 84: Ii1I
 def print_recent_rloc_probe_latencies ( self ) :
  oO0o00000o = str ( self . recent_rloc_probe_latencies )
  return ( oO0o00000o )
  if 10 - 10: IiII
  if 60 - 60: i1IIi + i1IIi
 def process_rloc_probe_reply ( self , ts , nonce , eid , group , hc , ttl , jt ) :
  I1IIiIIIii = self
  while ( True ) :
   if ( I1IIiIIIii . last_rloc_probe_nonce == nonce ) : break
   I1IIiIIIii = I1IIiIIIii . next_rloc
   if ( I1IIiIIIii == None ) :
    lprint ( "    No matching nonce state found for nonce 0x{}" . format ( lisp_hex_string ( nonce ) ) )
    if 47 - 47: iII111i - I1Ii111 - I1Ii111 . ooOoO0o
    return
    if 5 - 5: i1IIi
    if 47 - 47: I11i * I11i . OoOoOO00
    if 68 - 68: OoooooooOO + OoOoOO00 + i11iIiiIii
    if 89 - 89: Oo0Ooo + Ii1I * O0 - I1Ii111
    if 33 - 33: iIii1I11I1II1 . I11i
    if 63 - 63: oO0o - iII111i
  I1IIiIIIii . last_rloc_probe_reply = ts
  I1IIiIIIii . compute_rloc_probe_rtt ( )
  I11ii = I1IIiIIIii . print_state_change ( "up" )
  if ( I1IIiIIIii . state != LISP_RLOC_UP_STATE ) :
   lisp_update_rtr_updown ( I1IIiIIIii . rloc , True )
   I1IIiIIIii . state = LISP_RLOC_UP_STATE
   I1IIiIIIii . last_state_change = lisp_get_timestamp ( )
   o0o000Oo = lisp_map_cache . lookup_cache ( eid , True )
   if ( o0o000Oo ) : lisp_write_ipc_map_cache ( True , o0o000Oo )
   if 18 - 18: ooOoO0o - I1Ii111 % o0oOOo0O0Ooo . iII111i . OoO0O00
   if 100 - 100: II111iiii - O0 / oO0o - I11i % OOooOOo + Oo0Ooo
   if 2 - 2: iII111i % OoOoOO00 + OoOoOO00 + o0oOOo0O0Ooo / ooOoO0o
   if 12 - 12: i1IIi + II111iiii / o0oOOo0O0Ooo
   if 81 - 81: I1Ii111 . Ii1I * ooOoO0o . IiII - OoOoOO00
  I1IIiIIIii . store_rloc_probe_hops ( hc , ttl )
  if 79 - 79: ooOoO0o - O0
  if 56 - 56: ooOoO0o
  if 89 - 89: O0 % iIii1I11I1II1 / OoOoOO00 - I1Ii111 - I1IiiI
  if 60 - 60: IiII % i11iIiiIii / OOooOOo
  if ( jt ) : I1IIiIIIii . store_rloc_probe_latencies ( jt )
  if 43 - 43: i11iIiiIii * II111iiii + ooOoO0o - OoooooooOO * II111iiii / OoO0O00
  oO0oo000O = bold ( "RLOC-probe reply" , False )
  oo0o00OO = I1IIiIIIii . rloc . print_address_no_iid ( )
  oo0000OoO = bold ( str ( I1IIiIIIii . print_rloc_probe_rtt ( ) ) , False )
  oo00ooOOOo0O = ":{}" . format ( self . translated_port ) if self . translated_port != 0 else ""
  if 78 - 78: o0oOOo0O0Ooo / i1IIi - I11i
  II11111Iii1I = ""
  if ( I1IIiIIIii . rloc_next_hop != None ) :
   OooOOOoOoo0O0 , o00O00oo0 = I1IIiIIIii . rloc_next_hop
   II11111Iii1I = ", nh {}({})" . format ( o00O00oo0 , OooOOOoOoo0O0 )
   if 94 - 94: II111iiii + OoooooooOO . i1IIi + OoO0O00 + OoOoOO00
   if 52 - 52: iII111i * OoOoOO00
  III1iIi111I1 = bold ( I1IIiIIIii . print_rloc_probe_latency ( ) , False )
  III1iIi111I1 = ", latency {}" . format ( III1iIi111I1 ) if jt else ""
  if 80 - 80: I1Ii111 / IiII * o0oOOo0O0Ooo - OoOoOO00 / iIii1I11I1II1
  oOo = green ( lisp_print_eid_tuple ( eid , group ) , False )
  if 38 - 38: II111iiii / I11i + IiII % OoooooooOO
  lprint ( ( "    Received {} from {}{} for {}, {}, rtt {}{}, " + "to-ttl/from-ttl {}{}" ) . format ( oO0oo000O , red ( oo0o00OO , False ) , oo00ooOOOo0O , oOo ,
  # I1Ii111 * OoOoOO00
 I11ii , oo0000OoO , II11111Iii1I , str ( hc ) + "/" + str ( ttl ) , III1iIi111I1 ) )
  if 94 - 94: OOooOOo % I1IiiI * OoO0O00
  if ( I1IIiIIIii . rloc_next_hop == None ) : return
  if 52 - 52: iIii1I11I1II1 % o0oOOo0O0Ooo / i1IIi + IiII
  if 95 - 95: O0
  if 67 - 67: OOooOOo / I11i - I1Ii111 % i11iIiiIii
  if 3 - 3: oO0o + iII111i + OOooOOo
  I1IIiIIIii = None
  OoOOO0 = None
  while ( True ) :
   I1IIiIIIii = self if I1IIiIIIii == None else I1IIiIIIii . next_rloc
   if ( I1IIiIIIii == None ) : break
   if ( I1IIiIIIii . up_state ( ) == False ) : continue
   if ( I1IIiIIIii . rloc_probe_rtt == - 1 ) : continue
   if 25 - 25: iII111i % iII111i * ooOoO0o % I1ii11iIi11i % I1Ii111
   if ( OoOOO0 == None ) : OoOOO0 = I1IIiIIIii
   if ( I1IIiIIIii . rloc_probe_rtt < OoOOO0 . rloc_probe_rtt ) : OoOOO0 = I1IIiIIIii
   if 4 - 4: O0 % i11iIiiIii % I1Ii111 - i11iIiiIii / o0oOOo0O0Ooo % o0oOOo0O0Ooo
   if 59 - 59: i1IIi . o0oOOo0O0Ooo . IiII + iII111i * i1IIi
  if ( OoOOO0 != None ) :
   OooOOOoOoo0O0 , o00O00oo0 = OoOOO0 . rloc_next_hop
   II11111Iii1I = bold ( "nh {}({})" . format ( o00O00oo0 , OooOOOoOoo0O0 ) , False )
   lprint ( "    Install host-route via best {}" . format ( II11111Iii1I ) )
   lisp_install_host_route ( oo0o00OO , None , False )
   lisp_install_host_route ( oo0o00OO , o00O00oo0 , True )
   if 41 - 41: ooOoO0o - i1IIi * IiII . OoOoOO00 % iIii1I11I1II1 - IiII
   if 12 - 12: I1ii11iIi11i * iII111i / i11iIiiIii / OoOoOO00
   if 62 - 62: O0 - IiII + I1ii11iIi11i
 def add_to_rloc_probe_list ( self , eid , group ) :
  oo0o00OO = self . rloc . print_address_no_iid ( )
  Oo0O00O = self . translated_port
  if ( Oo0O00O != 0 ) : oo0o00OO += ":" + str ( Oo0O00O )
  if 67 - 67: i1IIi + i11iIiiIii * I1ii11iIi11i / ooOoO0o * OoO0O00
  if ( lisp_rloc_probe_list . has_key ( oo0o00OO ) == False ) :
   lisp_rloc_probe_list [ oo0o00OO ] = [ ]
   if 52 - 52: II111iiii / Ii1I - iII111i
   if 33 - 33: I1IiiI
  if ( group . is_null ( ) ) : group . instance_id = 0
  for O0OOOO0o0O , oOo , i11ii in lisp_rloc_probe_list [ oo0o00OO ] :
   if ( oOo . is_exact_match ( eid ) and i11ii . is_exact_match ( group ) ) :
    if ( O0OOOO0o0O == self ) :
     if ( lisp_rloc_probe_list [ oo0o00OO ] == [ ] ) :
      lisp_rloc_probe_list . pop ( oo0o00OO )
      if 41 - 41: OoOoOO00 * i1IIi
     return
     if 94 - 94: I11i
    lisp_rloc_probe_list [ oo0o00OO ] . remove ( [ O0OOOO0o0O , oOo , i11ii ] )
    break
    if 28 - 28: OOooOOo
    if 82 - 82: II111iiii
  lisp_rloc_probe_list [ oo0o00OO ] . append ( [ self , eid , group ] )
  if 66 - 66: iII111i % I1Ii111 * oO0o
  if 81 - 81: i11iIiiIii - O0 . iIii1I11I1II1 - I11i + iIii1I11I1II1
  if 50 - 50: Oo0Ooo . OoO0O00 + i11iIiiIii / i11iIiiIii
  if 27 - 27: OoOoOO00 - OoOoOO00 % II111iiii + i1IIi + I1IiiI
  if 75 - 75: OoooooooOO . I11i - OoOoOO00
  I1IIiIIIii = lisp_rloc_probe_list [ oo0o00OO ] [ 0 ] [ 0 ]
  if ( I1IIiIIIii . state == LISP_RLOC_UNREACH_STATE ) :
   self . state = LISP_RLOC_UNREACH_STATE
   self . last_state_change = lisp_get_timestamp ( )
   if 93 - 93: OoOoOO00 . I1Ii111 % I1ii11iIi11i
   if 58 - 58: OoooooooOO . i1IIi . Oo0Ooo - o0oOOo0O0Ooo / oO0o * I1Ii111
   if 6 - 6: oO0o - OoO0O00
 def delete_from_rloc_probe_list ( self , eid , group ) :
  oo0o00OO = self . rloc . print_address_no_iid ( )
  Oo0O00O = self . translated_port
  if ( Oo0O00O != 0 ) : oo0o00OO += ":" + str ( Oo0O00O )
  if ( lisp_rloc_probe_list . has_key ( oo0o00OO ) == False ) : return
  if 44 - 44: Oo0Ooo + I1ii11iIi11i % Oo0Ooo / I11i
  oO00ooo = [ ]
  for i1ii1i1Ii11 in lisp_rloc_probe_list [ oo0o00OO ] :
   if ( i1ii1i1Ii11 [ 0 ] != self ) : continue
   if ( i1ii1i1Ii11 [ 1 ] . is_exact_match ( eid ) == False ) : continue
   if ( i1ii1i1Ii11 [ 2 ] . is_exact_match ( group ) == False ) : continue
   oO00ooo = i1ii1i1Ii11
   break
   if 9 - 9: oO0o . i11iIiiIii * i11iIiiIii . I1ii11iIi11i + iII111i
  if ( oO00ooo == [ ] ) : return
  if 18 - 18: I11i
  try :
   lisp_rloc_probe_list [ oo0o00OO ] . remove ( oO00ooo )
   if ( lisp_rloc_probe_list [ oo0o00OO ] == [ ] ) :
    lisp_rloc_probe_list . pop ( oo0o00OO )
    if 46 - 46: I1IiiI . OoooooooOO / iIii1I11I1II1 - ooOoO0o * OOooOOo
  except :
   return
   if 55 - 55: o0oOOo0O0Ooo + iIii1I11I1II1 / I11i
   if 97 - 97: i11iIiiIii
   if 71 - 71: oO0o + Oo0Ooo
 def print_rloc_probe_state ( self , trailing_linefeed ) :
  Oo0Ooo0O0 = ""
  I1IIiIIIii = self
  while ( True ) :
   iI1Ii = I1IIiIIIii . last_rloc_probe
   if ( iI1Ii == None ) : iI1Ii = 0
   OoO00o0Ooo0o = I1IIiIIIii . last_rloc_probe_reply
   if ( OoO00o0Ooo0o == None ) : OoO00o0Ooo0o = 0
   oo0000OoO = I1IIiIIIii . print_rloc_probe_rtt ( )
   IiII1iiI = space ( 4 )
   if 93 - 93: iIii1I11I1II1 - II111iiii
   if ( I1IIiIIIii . rloc_next_hop == None ) :
    Oo0Ooo0O0 += "RLOC-Probing:\n"
   else :
    OooOOOoOoo0O0 , o00O00oo0 = I1IIiIIIii . rloc_next_hop
    Oo0Ooo0O0 += "RLOC-Probing for nh {}({}):\n" . format ( o00O00oo0 , OooOOOoOoo0O0 )
    if 1 - 1: Ii1I / OoO0O00 % iIii1I11I1II1 / I1Ii111
    if 31 - 31: I11i
   Oo0Ooo0O0 += ( "{}RLOC-probe request sent: {}\n{}RLOC-probe reply " + "received: {}, rtt {}" ) . format ( IiII1iiI , lisp_print_elapsed ( iI1Ii ) ,
   # IiII . OoooooooOO + I1IiiI % OOooOOo + ooOoO0o . ooOoO0o
 IiII1iiI , lisp_print_elapsed ( OoO00o0Ooo0o ) , oo0000OoO )
   if 53 - 53: OoO0O00
   if ( trailing_linefeed ) : Oo0Ooo0O0 += "\n"
   if 58 - 58: I1IiiI / IiII - OoooooooOO - I1Ii111
   I1IIiIIIii = I1IIiIIIii . next_rloc
   if ( I1IIiIIIii == None ) : break
   Oo0Ooo0O0 += "\n"
   if 39 - 39: IiII . II111iiii
  return ( Oo0Ooo0O0 )
  if 42 - 42: I1ii11iIi11i . Oo0Ooo * I1IiiI / Oo0Ooo
  if 83 - 83: i11iIiiIii / OoOoOO00
 def get_encap_keys ( self ) :
  Oo0O00O = "4341" if self . translated_port == 0 else str ( self . translated_port )
  if 37 - 37: iIii1I11I1II1 % IiII / i11iIiiIii - oO0o
  oo0o00OO = self . rloc . print_address_no_iid ( ) + ":" + Oo0O00O
  if 43 - 43: II111iiii - OoooooooOO
  try :
   iIi11III = lisp_crypto_keys_by_rloc_encap [ oo0o00OO ]
   if ( iIi11III [ 1 ] ) : return ( iIi11III [ 1 ] . encrypt_key , iIi11III [ 1 ] . icv_key )
   return ( None , None )
  except :
   return ( None , None )
   if 11 - 11: I1IiiI
   if 76 - 76: iII111i - II111iiii % Oo0Ooo . I1Ii111
   if 64 - 64: OoO0O00 - OoO0O00
 def rloc_recent_rekey ( self ) :
  Oo0O00O = "4341" if self . translated_port == 0 else str ( self . translated_port )
  if 93 - 93: Oo0Ooo . O0
  oo0o00OO = self . rloc . print_address_no_iid ( ) + ":" + Oo0O00O
  if 75 - 75: iII111i * II111iiii - I1IiiI
  try :
   Oo000O000 = lisp_crypto_keys_by_rloc_encap [ oo0o00OO ] [ 1 ]
   if ( Oo000O000 == None ) : return ( False )
   if ( Oo000O000 . last_rekey == None ) : return ( True )
   return ( time . time ( ) - Oo000O000 . last_rekey < 1 )
  except :
   return ( False )
   if 30 - 30: i1IIi / ooOoO0o . ooOoO0o
   if 22 - 22: I11i % iIii1I11I1II1 - i11iIiiIii * OoOoOO00 - I1Ii111
   if 97 - 97: i11iIiiIii . OoOoOO00 + oO0o * O0 % OoO0O00 - Ii1I
   if 46 - 46: I1Ii111
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
  if 87 - 87: o0oOOo0O0Ooo - iII111i * OoO0O00 * o0oOOo0O0Ooo . o0oOOo0O0Ooo / OOooOOo
  if 50 - 50: i11iIiiIii - II111iiii * OoooooooOO + II111iiii - ooOoO0o
 def print_mapping ( self , eid_indent , rloc_indent ) :
  i1 = lisp_print_elapsed ( self . uptime )
  IIi1iiIII11 = "" if self . group . is_null ( ) else ", group {}" . format ( self . group . print_prefix ( ) )
  if 52 - 52: i1IIi + i1IIi * i1IIi / OoOoOO00
  lprint ( "{}eid {}{}, uptime {}, {} rlocs:" . format ( eid_indent ,
 green ( self . eid . print_prefix ( ) , False ) , IIi1iiIII11 , i1 ,
 len ( self . rloc_set ) ) )
  for I1IIiIIIii in self . rloc_set : I1IIiIIIii . print_rloc ( rloc_indent )
  if 98 - 98: iII111i . i1IIi + o0oOOo0O0Ooo * OoooooooOO - i11iIiiIii
  if 21 - 21: i11iIiiIii . oO0o * o0oOOo0O0Ooo + Oo0Ooo * OoOoOO00 * o0oOOo0O0Ooo
 def print_eid_tuple ( self ) :
  return ( lisp_print_eid_tuple ( self . eid , self . group ) )
  if 33 - 33: I1IiiI + O0 - I11i
  if 90 - 90: I1Ii111 * OoooooooOO . iIii1I11I1II1 % OoO0O00 / I11i + iII111i
 def print_ttl ( self ) :
  oOoooOOO0o0 = self . map_cache_ttl
  if ( oOoooOOO0o0 == None ) : return ( "forever" )
  if 63 - 63: o0oOOo0O0Ooo . IiII . Oo0Ooo - iIii1I11I1II1 / I1Ii111
  if ( oOoooOOO0o0 >= 3600 ) :
   if ( ( oOoooOOO0o0 % 3600 ) == 0 ) :
    oOoooOOO0o0 = str ( oOoooOOO0o0 / 3600 ) + " hours"
   else :
    oOoooOOO0o0 = str ( oOoooOOO0o0 * 60 ) + " mins"
    if 66 - 66: ooOoO0o * I1Ii111 - II111iiii
  elif ( oOoooOOO0o0 >= 60 ) :
   if ( ( oOoooOOO0o0 % 60 ) == 0 ) :
    oOoooOOO0o0 = str ( oOoooOOO0o0 / 60 ) + " mins"
   else :
    oOoooOOO0o0 = str ( oOoooOOO0o0 ) + " secs"
    if 38 - 38: O0 % I1ii11iIi11i + O0
  else :
   oOoooOOO0o0 = str ( oOoooOOO0o0 ) + " secs"
   if 37 - 37: Oo0Ooo / I1IiiI
  return ( oOoooOOO0o0 )
  if 23 - 23: II111iiii / iII111i
  if 55 - 55: i11iIiiIii - Ii1I % OoooooooOO * OoooooooOO
 def refresh ( self ) :
  if ( self . group . is_null ( ) ) : return ( self . refresh_unicast ( ) )
  return ( self . refresh_multicast ( ) )
  if 92 - 92: iIii1I11I1II1
  if 47 - 47: Oo0Ooo + Oo0Ooo * ooOoO0o - OoOoOO00 + II111iiii
 def refresh_unicast ( self ) :
  return ( self . is_active ( ) and self . has_ttl_elapsed ( ) and
 self . gleaned == False )
  if 10 - 10: II111iiii / ooOoO0o . Ii1I / I1Ii111 / oO0o
  if 8 - 8: OOooOOo / ooOoO0o * I11i + OOooOOo * i1IIi
 def refresh_multicast ( self ) :
  if 48 - 48: o0oOOo0O0Ooo - I1ii11iIi11i / iII111i
  if 63 - 63: O0 - IiII . OOooOOo % IiII . I1IiiI / oO0o
  if 79 - 79: OoOoOO00
  if 88 - 88: oO0o * o0oOOo0O0Ooo
  if 5 - 5: I11i - I1Ii111 * I11i - II111iiii + OOooOOo + II111iiii
  oO000o0Oo00 = int ( ( time . time ( ) - self . uptime ) % self . map_cache_ttl )
  OoOOOO = ( oO000o0Oo00 in [ 0 , 1 , 2 ] )
  if ( OoOOOO == False ) : return ( False )
  if 86 - 86: O0 / Ii1I . OoooooooOO . O0
  if 87 - 87: Ii1I + o0oOOo0O0Ooo + OoooooooOO . Ii1I
  if 73 - 73: o0oOOo0O0Ooo + OoooooooOO - I1Ii111 . iIii1I11I1II1
  if 25 - 25: OoooooooOO % I1ii11iIi11i % Oo0Ooo % i11iIiiIii
  ii1i1iiI1 = ( ( time . time ( ) - self . last_multicast_map_request ) <= 2 )
  if ( ii1i1iiI1 ) : return ( False )
  if 19 - 19: II111iiii / OoO0O00 * II111iiii + I1IiiI
  self . last_multicast_map_request = lisp_get_timestamp ( )
  return ( True )
  if 28 - 28: OOooOOo + OoO0O00 * Ii1I * O0 / I1IiiI
  if 99 - 99: Oo0Ooo + ooOoO0o - I1ii11iIi11i + I1Ii111 + Ii1I * I1IiiI
 def has_ttl_elapsed ( self ) :
  if ( self . map_cache_ttl == None ) : return ( False )
  oO000o0Oo00 = time . time ( ) - self . last_refresh_time
  if ( oO000o0Oo00 >= self . map_cache_ttl ) : return ( True )
  if 68 - 68: OoO0O00
  if 79 - 79: Ii1I . IiII + OoOoOO00
  if 10 - 10: OoooooooOO * iII111i * ooOoO0o . Ii1I % I1Ii111 / I1ii11iIi11i
  if 71 - 71: Ii1I + IiII
  if 10 - 10: II111iiii % o0oOOo0O0Ooo . o0oOOo0O0Ooo % iII111i
  Ii111 = self . map_cache_ttl - ( self . map_cache_ttl / 10 )
  if ( oO000o0Oo00 >= Ii111 ) : return ( True )
  return ( False )
  if 40 - 40: oO0o
  if 4 - 4: o0oOOo0O0Ooo + I1IiiI - O0 - iIii1I11I1II1
 def is_active ( self ) :
  if ( self . stats . last_increment == None ) : return ( False )
  oO000o0Oo00 = time . time ( ) - self . stats . last_increment
  return ( oO000o0Oo00 <= 60 )
  if 56 - 56: OOooOOo * o0oOOo0O0Ooo - O0
  if 45 - 45: OOooOOo - OoO0O00
 def match_eid_tuple ( self , db ) :
  if ( self . eid . is_exact_match ( db . eid ) == False ) : return ( False )
  if ( self . group . is_exact_match ( db . group ) == False ) : return ( False )
  return ( True )
  if 49 - 49: OoOoOO00 / o0oOOo0O0Ooo % OoO0O00
  if 50 - 50: iIii1I11I1II1 - OoooooooOO + I1ii11iIi11i / Oo0Ooo * OOooOOo
 def sort_rloc_set ( self ) :
  self . rloc_set . sort ( key = operator . attrgetter ( 'rloc.address' ) )
  if 37 - 37: O0 % I1Ii111 * OOooOOo / OOooOOo
  if 95 - 95: I1ii11iIi11i % o0oOOo0O0Ooo . oO0o
 def delete_rlocs_from_rloc_probe_list ( self ) :
  for I1IIiIIIii in self . best_rloc_set :
   I1IIiIIIii . delete_from_rloc_probe_list ( self . eid , self . group )
   if 9 - 9: OoOoOO00 % OoOoOO00 * ooOoO0o / I1IiiI - OOooOOo
   if 62 - 62: Oo0Ooo + OOooOOo - Oo0Ooo
   if 32 - 32: OoooooooOO
 def build_best_rloc_set ( self ) :
  OooOoO0OOoo = self . best_rloc_set
  self . best_rloc_set = [ ]
  if ( self . rloc_set == None ) : return
  if 90 - 90: OoOoOO00 % OoO0O00 . I1IiiI * oO0o
  if 17 - 17: O0 - i1IIi
  if 77 - 77: OOooOOo - i1IIi / II111iiii . I1Ii111 + O0
  if 1 - 1: OoooooooOO % iIii1I11I1II1 * I1ii11iIi11i
  i11iIiiI1i1i1 = 256
  for I1IIiIIIii in self . rloc_set :
   if ( I1IIiIIIii . up_state ( ) ) : i11iIiiI1i1i1 = min ( I1IIiIIIii . priority , i11iIiiI1i1i1 )
   if 80 - 80: Oo0Ooo
   if 37 - 37: i11iIiiIii - I1Ii111
   if 50 - 50: I1IiiI / Ii1I / Ii1I + O0 % I11i - i1IIi
   if 72 - 72: II111iiii . OoO0O00 . II111iiii * I1ii11iIi11i
   if 42 - 42: II111iiii
   if 45 - 45: I1ii11iIi11i . I1Ii111 . i1IIi * OOooOOo
   if 53 - 53: Ii1I . i11iIiiIii + o0oOOo0O0Ooo % I11i - I1ii11iIi11i * I1ii11iIi11i
   if 87 - 87: I1Ii111 % i11iIiiIii + O0
   if 67 - 67: OoooooooOO / i1IIi / ooOoO0o . i1IIi - i11iIiiIii . i1IIi
   if 41 - 41: i11iIiiIii / ooOoO0o - Ii1I + I11i
  for I1IIiIIIii in self . rloc_set :
   if ( I1IIiIIIii . priority <= i11iIiiI1i1i1 ) :
    if ( I1IIiIIIii . unreach_state ( ) and I1IIiIIIii . last_rloc_probe == None ) :
     I1IIiIIIii . last_rloc_probe = lisp_get_timestamp ( )
     if 15 - 15: I1ii11iIi11i
    self . best_rloc_set . append ( I1IIiIIIii )
    if 22 - 22: iIii1I11I1II1 - i1IIi - i11iIiiIii / I1IiiI + o0oOOo0O0Ooo
    if 56 - 56: I1IiiI . ooOoO0o
    if 35 - 35: iIii1I11I1II1 % Oo0Ooo + o0oOOo0O0Ooo * o0oOOo0O0Ooo % ooOoO0o
    if 10 - 10: I1ii11iIi11i / II111iiii % II111iiii - OoooooooOO * o0oOOo0O0Ooo / ooOoO0o
    if 26 - 26: OoO0O00 . O0 * iII111i % OoOoOO00 % iIii1I11I1II1
    if 37 - 37: iII111i - ooOoO0o * Ii1I + II111iiii * i11iIiiIii
    if 8 - 8: OoooooooOO % I11i - iII111i * OOooOOo . O0
    if 40 - 40: I1Ii111 . oO0o + OoO0O00 % Oo0Ooo / II111iiii
  for I1IIiIIIii in OooOoO0OOoo :
   if ( I1IIiIIIii . priority < i11iIiiI1i1i1 ) : continue
   I1IIiIIIii . delete_from_rloc_probe_list ( self . eid , self . group )
   if 19 - 19: i11iIiiIii
  for I1IIiIIIii in self . best_rloc_set :
   if ( I1IIiIIIii . rloc . is_null ( ) ) : continue
   I1IIiIIIii . add_to_rloc_probe_list ( self . eid , self . group )
   if 20 - 20: i11iIiiIii . II111iiii - I1ii11iIi11i / ooOoO0o % i11iIiiIii
   if 35 - 35: Oo0Ooo - I1ii11iIi11i . Oo0Ooo
   if 13 - 13: II111iiii / OoOoOO00 * iII111i % O0 % I1ii11iIi11i * i11iIiiIii
 def select_rloc ( self , lisp_packet , ipc_socket ) :
  IiiiIi1iiii11 = lisp_packet . packet
  ooO00O = lisp_packet . inner_version
  IiiI1iii1iIiiI = len ( self . best_rloc_set )
  if ( IiiI1iii1iIiiI == 0 ) :
   self . stats . increment ( len ( IiiiIi1iiii11 ) )
   return ( [ None , None , None , self . action , None , None ] )
   if 58 - 58: OoO0O00
   if 48 - 48: oO0o . II111iiii
  oOOO0O0ooOoOoo0 = 4 if lisp_load_split_pings else 0
  IIi1iiIIi1i = lisp_packet . hash_ports ( )
  if ( ooO00O == 4 ) :
   for IiIIi1IiiIiI in range ( 8 + oOOO0O0ooOoOoo0 ) :
    IIi1iiIIi1i = IIi1iiIIi1i ^ struct . unpack ( "B" , IiiiIi1iiii11 [ IiIIi1IiiIiI + 12 ] ) [ 0 ]
    if 73 - 73: OoOoOO00
  elif ( ooO00O == 6 ) :
   for IiIIi1IiiIiI in range ( 0 , 32 + oOOO0O0ooOoOoo0 , 4 ) :
    IIi1iiIIi1i = IIi1iiIIi1i ^ struct . unpack ( "I" , IiiiIi1iiii11 [ IiIIi1IiiIiI + 8 : IiIIi1IiiIiI + 12 ] ) [ 0 ]
    if 42 - 42: I1ii11iIi11i - iIii1I11I1II1 . Ii1I % OoO0O00 % i11iIiiIii * i11iIiiIii
   IIi1iiIIi1i = ( IIi1iiIIi1i >> 16 ) + ( IIi1iiIIi1i & 0xffff )
   IIi1iiIIi1i = ( IIi1iiIIi1i >> 8 ) + ( IIi1iiIIi1i & 0xff )
  else :
   for IiIIi1IiiIiI in range ( 0 , 12 + oOOO0O0ooOoOoo0 , 4 ) :
    IIi1iiIIi1i = IIi1iiIIi1i ^ struct . unpack ( "I" , IiiiIi1iiii11 [ IiIIi1IiiIiI : IiIIi1IiiIiI + 4 ] ) [ 0 ]
    if 86 - 86: Oo0Ooo % iIii1I11I1II1 . II111iiii / I11i % OoO0O00 % OoO0O00
    if 40 - 40: o0oOOo0O0Ooo . iIii1I11I1II1 * Oo0Ooo * i1IIi
    if 94 - 94: oO0o - II111iiii + OoOoOO00
  if ( lisp_data_plane_logging ) :
   oOOO000 = [ ]
   for O0OOOO0o0O in self . best_rloc_set :
    if ( O0OOOO0o0O . rloc . is_null ( ) ) : continue
    oOOO000 . append ( [ O0OOOO0o0O . rloc . print_address_no_iid ( ) , O0OOOO0o0O . print_state ( ) ] )
    if 72 - 72: iIii1I11I1II1 % I1Ii111
   dprint ( "Packet hash {}, index {}, best-rloc-list: {}" . format ( hex ( IIi1iiIIi1i ) , IIi1iiIIi1i % IiiI1iii1iIiiI , red ( str ( oOOO000 ) , False ) ) )
   if 77 - 77: I1Ii111 * I1IiiI / iIii1I11I1II1 . II111iiii * Oo0Ooo
   if 71 - 71: ooOoO0o / iIii1I11I1II1 % O0 / I1ii11iIi11i . I1Ii111 / i11iIiiIii
   if 6 - 6: oO0o . OoO0O00 - II111iiii . I1IiiI - o0oOOo0O0Ooo - i1IIi
   if 42 - 42: Ii1I + i11iIiiIii
   if 46 - 46: O0 % OoOoOO00 - I1Ii111 . I1IiiI
   if 66 - 66: II111iiii * iIii1I11I1II1 * ooOoO0o * I11i . II111iiii - ooOoO0o
  I1IIiIIIii = self . best_rloc_set [ IIi1iiIIi1i % IiiI1iii1iIiiI ]
  if 15 - 15: I1ii11iIi11i - i11iIiiIii - Ii1I / Ii1I . iII111i
  if 36 - 36: oO0o + Oo0Ooo * I1Ii111 % OOooOOo . Oo0Ooo . I1IiiI
  if 81 - 81: o0oOOo0O0Ooo . OoOoOO00 . i11iIiiIii
  if 13 - 13: i1IIi
  if 70 - 70: O0 / II111iiii
  ii1 = lisp_get_echo_nonce ( I1IIiIIIii . rloc , None )
  if ( ii1 ) :
   ii1 . change_state ( I1IIiIIIii )
   if ( I1IIiIIIii . no_echoed_nonce_state ( ) ) :
    ii1 . request_nonce_sent = None
    if 98 - 98: OoOoOO00 - O0 . O0 + ooOoO0o * iIii1I11I1II1
    if 7 - 7: IiII * OoOoOO00 + iIii1I11I1II1 / OoOoOO00 + Oo0Ooo / o0oOOo0O0Ooo
    if 77 - 77: i1IIi . I1IiiI
    if 59 - 59: O0 + OoooooooOO - i1IIi
    if 87 - 87: IiII * OoooooooOO / Oo0Ooo % iIii1I11I1II1 % oO0o
    if 97 - 97: ooOoO0o % i1IIi . IiII / Oo0Ooo . I1Ii111 . OoO0O00
  if ( I1IIiIIIii . up_state ( ) == False ) :
   i1iIiI = IIi1iiIIi1i % IiiI1iii1iIiiI
   ooo = ( i1iIiI + 1 ) % IiiI1iii1iIiiI
   while ( ooo != i1iIiI ) :
    I1IIiIIIii = self . best_rloc_set [ ooo ]
    if ( I1IIiIIIii . up_state ( ) ) : break
    ooo = ( ooo + 1 ) % IiiI1iii1iIiiI
    if 22 - 22: i11iIiiIii * II111iiii
   if ( ooo == i1iIiI ) :
    self . build_best_rloc_set ( )
    return ( [ None , None , None , None , None , None ] )
    if 11 - 11: Oo0Ooo % i1IIi
    if 70 - 70: II111iiii * Oo0Ooo * OOooOOo - I1IiiI + iIii1I11I1II1 + ooOoO0o
    if 27 - 27: I1ii11iIi11i - I1Ii111 * O0 % ooOoO0o / I1IiiI
    if 53 - 53: i11iIiiIii * i11iIiiIii % O0 % IiII
    if 57 - 57: I1IiiI % i1IIi * OoO0O00 + I1Ii111 . I11i % I11i
    if 69 - 69: I1ii11iIi11i / OoOoOO00 + iIii1I11I1II1
  I1IIiIIIii . stats . increment ( len ( IiiiIi1iiii11 ) )
  if 8 - 8: OoooooooOO
  if 72 - 72: OoooooooOO % I1ii11iIi11i - OoO0O00 . OoooooooOO
  if 83 - 83: o0oOOo0O0Ooo * Ii1I - Oo0Ooo * iII111i - i11iIiiIii
  if 6 - 6: I1IiiI + i11iIiiIii + O0 / i1IIi
  if ( I1IIiIIIii . rle_name and I1IIiIIIii . rle == None ) :
   if ( lisp_rle_list . has_key ( I1IIiIIIii . rle_name ) ) :
    I1IIiIIIii . rle = lisp_rle_list [ I1IIiIIIii . rle_name ]
    if 50 - 50: iII111i . II111iiii % I1Ii111 % I1IiiI / o0oOOo0O0Ooo . I1IiiI
    if 76 - 76: OOooOOo % iII111i
  if ( I1IIiIIIii . rle ) : return ( [ None , None , None , None , I1IIiIIIii . rle , None ] )
  if 80 - 80: iIii1I11I1II1 + o0oOOo0O0Ooo + iIii1I11I1II1
  if 63 - 63: OoOoOO00 - o0oOOo0O0Ooo % II111iiii - Ii1I
  if 81 - 81: iII111i % OOooOOo * oO0o
  if 84 - 84: iII111i - OoooooooOO + I1ii11iIi11i - I1IiiI
  if ( I1IIiIIIii . elp and I1IIiIIIii . elp . use_elp_node ) :
   return ( [ I1IIiIIIii . elp . use_elp_node . address , None , None , None , None ,
 None ] )
   if 52 - 52: oO0o / ooOoO0o / iII111i / OoOoOO00 * iIii1I11I1II1
   if 74 - 74: oO0o . I1ii11iIi11i - iIii1I11I1II1
   if 73 - 73: OoO0O00 / O0 . o0oOOo0O0Ooo
   if 100 - 100: Ii1I . OoO0O00 % I1ii11iIi11i % O0 * Oo0Ooo - OoOoOO00
   if 15 - 15: OOooOOo - OOooOOo - OoooooooOO * OoO0O00
  Iii1111IIiI1 = None if ( I1IIiIIIii . rloc . is_null ( ) ) else I1IIiIIIii . rloc
  Oo0O00O = I1IIiIIIii . translated_port
  I11I1iI = self . action if ( Iii1111IIiI1 == None ) else None
  if 48 - 48: I1Ii111 * iII111i
  if 93 - 93: I11i % iIii1I11I1II1 + Ii1I - I1IiiI + OoooooooOO . IiII
  if 77 - 77: i11iIiiIii . OoooooooOO % iIii1I11I1II1 % I1Ii111
  if 22 - 22: iIii1I11I1II1 + Ii1I / OOooOOo - oO0o * oO0o / IiII
  if 91 - 91: I11i - II111iiii + o0oOOo0O0Ooo + i1IIi + I1ii11iIi11i % Ii1I
  Iii11I = None
  if ( ii1 and ii1 . request_nonce_timeout ( ) == False ) :
   Iii11I = ii1 . get_request_or_echo_nonce ( ipc_socket , Iii1111IIiI1 )
   if 57 - 57: o0oOOo0O0Ooo - I1Ii111 / OoooooooOO . OoooooooOO
   if 44 - 44: oO0o / II111iiii % I1IiiI - II111iiii / OoooooooOO
   if 4 - 4: I11i * OoOoOO00
   if 18 - 18: iIii1I11I1II1 % OOooOOo - I1ii11iIi11i * i1IIi + Oo0Ooo
   if 87 - 87: oO0o . I11i
  return ( [ Iii1111IIiI1 , Oo0O00O , Iii11I , I11I1iI , None , I1IIiIIIii ] )
  if 15 - 15: oO0o
  if 45 - 45: Oo0Ooo * IiII * OoO0O00 + iIii1I11I1II1
 def do_rloc_sets_match ( self , rloc_address_set ) :
  if ( len ( self . rloc_set ) != len ( rloc_address_set ) ) : return ( False )
  if 89 - 89: IiII . IiII . oO0o % iII111i
  if 27 - 27: OoOoOO00 + O0 % i1IIi - Oo0Ooo
  if 96 - 96: O0 % o0oOOo0O0Ooo + OOooOOo % I1IiiI
  if 51 - 51: i1IIi . o0oOOo0O0Ooo % I1IiiI - OoooooooOO / OoOoOO00 - I11i
  if 45 - 45: O0 * II111iiii / i11iIiiIii
  for i1III111 in self . rloc_set :
   for I1IIiIIIii in rloc_address_set :
    if ( I1IIiIIIii . is_exact_match ( i1III111 . rloc ) == False ) : continue
    I1IIiIIIii = None
    break
    if 38 - 38: OoooooooOO % i11iIiiIii - O0 / O0
   if ( I1IIiIIIii == rloc_address_set [ - 1 ] ) : return ( False )
   if 59 - 59: OoO0O00 % iII111i + oO0o * II111iiii . OOooOOo
  return ( True )
  if 26 - 26: OOooOOo % OoooooooOO . Ii1I / iIii1I11I1II1 * I1IiiI
  if 85 - 85: IiII / Ii1I - I1ii11iIi11i * OOooOOo
 def get_rloc ( self , rloc ) :
  for i1III111 in self . rloc_set :
   O0OOOO0o0O = i1III111 . rloc
   if ( rloc . is_exact_match ( O0OOOO0o0O ) ) : return ( i1III111 )
   if 19 - 19: I1ii11iIi11i
  return ( None )
  if 12 - 12: ooOoO0o * I1ii11iIi11i * O0 / oO0o + iII111i - iIii1I11I1II1
  if 81 - 81: Ii1I
 def get_rloc_by_interface ( self , interface ) :
  for i1III111 in self . rloc_set :
   if ( i1III111 . interface == interface ) : return ( i1III111 )
   if 87 - 87: O0 % iII111i
  return ( None )
  if 57 - 57: Ii1I
  if 49 - 49: I11i
 def add_db ( self ) :
  if ( self . group . is_null ( ) ) :
   lisp_db_for_lookups . add_cache ( self . eid , self )
  else :
   ooOOo0ooo = lisp_db_for_lookups . lookup_cache ( self . group , True )
   if ( ooOOo0ooo == None ) :
    ooOOo0ooo = lisp_mapping ( self . group , self . group , [ ] )
    lisp_db_for_lookups . add_cache ( self . group , ooOOo0ooo )
    if 22 - 22: Oo0Ooo % OOooOOo + O0 - OoO0O00 % I11i * O0
   ooOOo0ooo . add_source_entry ( self )
   if 42 - 42: O0
   if 55 - 55: i11iIiiIii % OOooOOo
   if 10 - 10: OoOoOO00 / i11iIiiIii
 def add_cache ( self , do_ipc = True ) :
  if ( self . group . is_null ( ) ) :
   lisp_map_cache . add_cache ( self . eid , self )
   if ( lisp_program_hardware ) : lisp_program_vxlan_hardware ( self )
  else :
   o0o000Oo = lisp_map_cache . lookup_cache ( self . group , True )
   if ( o0o000Oo == None ) :
    o0o000Oo = lisp_mapping ( self . group , self . group , [ ] )
    o0o000Oo . eid . copy_address ( self . group )
    o0o000Oo . group . copy_address ( self . group )
    lisp_map_cache . add_cache ( self . group , o0o000Oo )
    if 21 - 21: Ii1I - i1IIi / I11i + IiII
   if ( self . eid . is_null ( ) ) : self . eid . make_default_route ( o0o000Oo . group )
   o0o000Oo . add_source_entry ( self )
   if 44 - 44: OoooooooOO % I11i / O0
  if ( do_ipc ) : lisp_write_ipc_map_cache ( True , self )
  if 94 - 94: IiII
  if 83 - 83: OoO0O00
 def delete_cache ( self ) :
  self . delete_rlocs_from_rloc_probe_list ( )
  lisp_write_ipc_map_cache ( False , self )
  if 55 - 55: iII111i
  if ( self . group . is_null ( ) ) :
   lisp_map_cache . delete_cache ( self . eid )
   if ( lisp_program_hardware ) :
    IIII1 = self . eid . print_prefix_no_iid ( )
    os . system ( "ip route delete {}" . format ( IIII1 ) )
    if 73 - 73: o0oOOo0O0Ooo + i11iIiiIii / ooOoO0o * II111iiii * o0oOOo0O0Ooo % iII111i
  else :
   o0o000Oo = lisp_map_cache . lookup_cache ( self . group , True )
   if ( o0o000Oo == None ) : return
   if 44 - 44: IiII * OoOoOO00 - OoO0O00 - OoooooooOO - I1ii11iIi11i - II111iiii
   I1iiI1iI1 = o0o000Oo . lookup_source_cache ( self . eid , True )
   if ( I1iiI1iI1 == None ) : return
   if 27 - 27: I11i % Ii1I / iII111i . OoOoOO00
   o0o000Oo . source_cache . delete_cache ( self . eid )
   if ( o0o000Oo . source_cache . cache_size ( ) == 0 ) :
    lisp_map_cache . delete_cache ( self . group )
    if 88 - 88: iII111i - i11iIiiIii * I1Ii111 * i11iIiiIii - O0
    if 8 - 8: oO0o + O0
    if 52 - 52: I11i * OOooOOo - OoOoOO00 % iIii1I11I1II1 . II111iiii
    if 1 - 1: OOooOOo / I1IiiI / Ii1I * iII111i
 def add_source_entry ( self , source_mc ) :
  if ( self . source_cache == None ) : self . source_cache = lisp_cache ( )
  self . source_cache . add_cache ( source_mc . eid , source_mc )
  if 14 - 14: ooOoO0o . O0 * OOooOOo
  if 34 - 34: I1ii11iIi11i . OOooOOo + OoO0O00 % o0oOOo0O0Ooo * O0 * I1IiiI
 def lookup_source_cache ( self , source , exact ) :
  if ( self . source_cache == None ) : return ( None )
  return ( self . source_cache . lookup_cache ( source , exact ) )
  if 9 - 9: IiII / i11iIiiIii . o0oOOo0O0Ooo - OOooOOo % I1Ii111
  if 65 - 65: I1IiiI % OoOoOO00
 def dynamic_eid_configured ( self ) :
  return ( self . dynamic_eids != None )
  if 45 - 45: o0oOOo0O0Ooo
  if 33 - 33: ooOoO0o % O0 % I1ii11iIi11i % o0oOOo0O0Ooo + i11iIiiIii . I1Ii111
 def star_secondary_iid ( self , prefix ) :
  if ( self . secondary_iid == None ) : return ( prefix )
  o0OoO0000o = "," + str ( self . secondary_iid )
  return ( prefix . replace ( o0OoO0000o , o0OoO0000o + "*" ) )
  if 21 - 21: I1Ii111 * I1ii11iIi11i * ooOoO0o
  if 73 - 73: OoOoOO00 * O0
 def increment_decap_stats ( self , packet ) :
  Oo0O00O = packet . udp_dport
  if ( Oo0O00O == LISP_DATA_PORT ) :
   I1IIiIIIii = self . get_rloc ( packet . outer_dest )
  else :
   if 1 - 1: OOooOOo * OoooooooOO
   if 46 - 46: I1ii11iIi11i * I1Ii111 / OOooOOo / I1IiiI
   if 7 - 7: OOooOOo / OoOoOO00
   if 93 - 93: iIii1I11I1II1 * Ii1I - iII111i
   for I1IIiIIIii in self . rloc_set :
    if ( I1IIiIIIii . translated_port != 0 ) : break
    if 94 - 94: iIii1I11I1II1 * iIii1I11I1II1 * I11i % i11iIiiIii
    if 38 - 38: I1IiiI % I1ii11iIi11i * I1IiiI + OOooOOo - OoOoOO00
  if ( I1IIiIIIii != None ) : I1IIiIIIii . stats . increment ( len ( packet . packet ) )
  self . stats . increment ( len ( packet . packet ) )
  if 78 - 78: OOooOOo + I1Ii111
  if 41 - 41: I11i + Oo0Ooo . Oo0Ooo / iII111i . OoOoOO00
 def rtrs_in_rloc_set ( self ) :
  for I1IIiIIIii in self . rloc_set :
   if ( I1IIiIIIii . is_rtr ( ) ) : return ( True )
   if 1 - 1: ooOoO0o + iII111i % i11iIiiIii / OoOoOO00
  return ( False )
  if 98 - 98: IiII
  if 75 - 75: OoooooooOO % IiII + Ii1I - i1IIi / OoooooooOO
 def add_recent_source ( self , source ) :
  self . recent_sources [ source . print_address ( ) ] = lisp_get_timestamp ( )
  if 57 - 57: iII111i
  if 18 - 18: II111iiii % i11iIiiIii + I11i - OOooOOo
  if 100 - 100: o0oOOo0O0Ooo / Ii1I - iIii1I11I1II1 / oO0o
class lisp_dynamic_eid ( ) :
 def __init__ ( self ) :
  self . dynamic_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . uptime = lisp_get_timestamp ( )
  self . interface = None
  self . last_packet = None
  self . timeout = LISP_DEFAULT_DYN_EID_TIMEOUT
  if 68 - 68: I11i / II111iiii * oO0o . II111iiii * OOooOOo
  if 78 - 78: I11i * OoO0O00 / II111iiii
 def get_timeout ( self , interface ) :
  try :
   o0o0OoOO0O0 = lisp_myinterfaces [ interface ]
   self . timeout = o0o0OoOO0O0 . dynamic_eid_timeout
  except :
   self . timeout = LISP_DEFAULT_DYN_EID_TIMEOUT
   if 85 - 85: i1IIi . i11iIiiIii + ooOoO0o
   if 89 - 89: iIii1I11I1II1 . I1Ii111
   if 43 - 43: Oo0Ooo + o0oOOo0O0Ooo % o0oOOo0O0Ooo % I1ii11iIi11i / iIii1I11I1II1 . I1ii11iIi11i
   if 59 - 59: IiII . OoO0O00 - OoooooooOO . O0
class lisp_group_mapping ( ) :
 def __init__ ( self , group_name , ms_name , group_prefix , sources , rle_addr ) :
  self . group_name = group_name
  self . group_prefix = group_prefix
  self . use_ms_name = ms_name
  self . sources = sources
  self . rle_address = rle_addr
  if 33 - 33: Ii1I
  if 95 - 95: OoooooooOO + OoO0O00 * ooOoO0o
 def add_group ( self ) :
  lisp_group_mapping_list [ self . group_name ] = self
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
def lisp_is_group_more_specific ( group_str , group_mapping ) :
 o0OoO0000o = group_mapping . group_prefix . instance_id
 OO00O = group_mapping . group_prefix . mask_len
 IIi1iiIII11 = lisp_address ( LISP_AFI_IPV4 , group_str , 32 , o0OoO0000o )
 if ( IIi1iiIII11 . is_more_specific ( group_mapping . group_prefix ) ) : return ( OO00O )
 return ( - 1 )
 if 4 - 4: I11i * I11i - Ii1I * oO0o . I1ii11iIi11i % o0oOOo0O0Ooo
 if 33 - 33: Ii1I * i11iIiiIii / O0 . Oo0Ooo + i1IIi . OoOoOO00
 if 76 - 76: OoooooooOO - O0
 if 17 - 17: Oo0Ooo % I1Ii111 . oO0o - O0
 if 32 - 32: O0 % O0
 if 66 - 66: iII111i / i1IIi - Oo0Ooo . Ii1I
 if 65 - 65: I1ii11iIi11i % ooOoO0o - OoOoOO00 + ooOoO0o + Oo0Ooo
def lisp_lookup_group ( group ) :
 oOOO000 = None
 for O0OoOooO0O00o in lisp_group_mapping_list . values ( ) :
  OO00O = lisp_is_group_more_specific ( group , O0OoOooO0O00o )
  if ( OO00O == - 1 ) : continue
  if ( oOOO000 == None or OO00O > oOOO000 . group_prefix . mask_len ) : oOOO000 = O0OoOooO0O00o
  if 39 - 39: OoooooooOO % i11iIiiIii / IiII - ooOoO0o
 return ( oOOO000 )
 if 74 - 74: iIii1I11I1II1 % II111iiii + IiII
 if 71 - 71: I1IiiI / O0 * i1IIi . i1IIi + Oo0Ooo
lisp_site_flags = {
 "P" : "ETR is {}Requesting Map-Server to Proxy Map-Reply" ,
 "S" : "ETR is {}LISP-SEC capable" ,
 "I" : "xTR-ID and site-ID are {}included in Map-Register" ,
 "T" : "Use Map-Register TTL field to timeout registration is {}set" ,
 "R" : "Merging registrations are {}requested" ,
 "M" : "ETR is {}a LISP Mobile-Node" ,
 "N" : "ETR is {}requesting Map-Notify messages from Map-Server"
 }
if 32 - 32: i1IIi * I1Ii111 % I1IiiI / IiII . I1Ii111
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
  if 11 - 11: OOooOOo
  if 25 - 25: i1IIi
  if 99 - 99: OOooOOo + OoooooooOO . I1Ii111 * Oo0Ooo % oO0o
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
  self . encrypt_json = False
  if 75 - 75: iII111i
  if 8 - 8: I1ii11iIi11i . I11i / I1ii11iIi11i - i1IIi
 def print_eid_tuple ( self ) :
  return ( lisp_print_eid_tuple ( self . eid , self . group ) )
  if 22 - 22: OOooOOo
  if 7 - 7: O0 - I1ii11iIi11i - OoO0O00 * I1Ii111
 def print_flags ( self , html ) :
  if ( html == False ) :
   Oo0Ooo0O0 = "{}-{}-{}-{}-{}-{}-{}" . format ( "P" if self . proxy_reply_requested else "p" ,
   # IiII
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
   for OO00OOoo in Ooo0OO0O0oO :
    I1I1i1IIII1 = lisp_site_flags [ OO00OOoo . upper ( ) ]
    I1I1i1IIII1 = I1I1i1IIII1 . format ( "" if OO00OOoo . isupper ( ) else "not " )
    Oo0Ooo0O0 += lisp_span ( OO00OOoo , I1I1i1IIII1 )
    if ( OO00OOoo . lower ( ) != "n" ) : Oo0Ooo0O0 += "-"
    if 46 - 46: OoO0O00 % OoO0O00 . O0 + II111iiii
    if 42 - 42: OOooOOo * I1Ii111
  return ( Oo0Ooo0O0 )
  if 53 - 53: II111iiii % OOooOOo / I1ii11iIi11i * OoOoOO00 % I1ii11iIi11i * iII111i
  if 91 - 91: iII111i . OoooooooOO
 def copy_state_to_parent ( self , child ) :
  self . xtr_id = child . xtr_id
  self . site_id = child . site_id
  self . first_registered = child . first_registered
  self . last_registered = child . last_registered
  self . last_registerer = child . last_registerer
  self . register_ttl = child . register_ttl
  if ( self . registered == False ) :
   self . first_registered = lisp_get_timestamp ( )
   if 90 - 90: i11iIiiIii - I1IiiI
  self . auth_sha1_or_sha2 = child . auth_sha1_or_sha2
  self . registered = child . registered
  self . proxy_reply_requested = child . proxy_reply_requested
  self . lisp_sec_present = child . lisp_sec_present
  self . xtr_id_present = child . xtr_id_present
  self . use_register_ttl_requested = child . use_register_ttl_requested
  self . merge_register_requested = child . merge_register_requested
  self . mobile_node_requested = child . mobile_node_requested
  self . map_notify_requested = child . map_notify_requested
  if 39 - 39: iII111i % OoooooooOO % Ii1I % I1IiiI
  if 63 - 63: OoO0O00 - I1Ii111 - II111iiii
 def build_sort_key ( self ) :
  OoOooO00 = lisp_cache ( )
  OOoOOO , Oo000O000 = OoOooO00 . build_key ( self . eid )
  ooOOOo = ""
  if ( self . group . is_null ( ) == False ) :
   iiiIiII , ooOOOo = OoOooO00 . build_key ( self . group )
   ooOOOo = "-" + ooOOOo [ 0 : 12 ] + "-" + str ( iiiIiII ) + "-" + ooOOOo [ 12 : : ]
   if 93 - 93: I1ii11iIi11i % O0 + I11i
  Oo000O000 = Oo000O000 [ 0 : 12 ] + "-" + str ( OOoOOO ) + "-" + Oo000O000 [ 12 : : ] + ooOOOo
  del ( OoOooO00 )
  return ( Oo000O000 )
  if 31 - 31: OOooOOo + O0 * OOooOOo
  if 81 - 81: i11iIiiIii + iIii1I11I1II1 . i11iIiiIii / OOooOOo / iII111i
 def merge_in_site_eid ( self , child ) :
  Ii1I1i1I1 = False
  if ( self . group . is_null ( ) ) :
   self . merge_rlocs_in_site_eid ( )
  else :
   Ii1I1i1I1 = self . merge_rles_in_site_eid ( )
   if 37 - 37: i1IIi / I11i . iII111i - II111iiii
   if 66 - 66: Ii1I + OoOoOO00 - I11i / o0oOOo0O0Ooo + iIii1I11I1II1
   if 66 - 66: OOooOOo - I1Ii111 - OoOoOO00 - i1IIi * Ii1I
   if 23 - 23: IiII - OoOoOO00 . OoO0O00
   if 81 - 81: I1Ii111 / I1ii11iIi11i
   if 69 - 69: I1IiiI
  if ( child != None ) :
   self . copy_state_to_parent ( child )
   self . map_registers_received += 1
   if 79 - 79: ooOoO0o
  return ( Ii1I1i1I1 )
  if 83 - 83: I1Ii111 % II111iiii
  if 89 - 89: Ii1I . I11i
 def copy_rloc_records ( self ) :
  o00o0 = [ ]
  for i1III111 in self . registered_rlocs :
   o00o0 . append ( copy . deepcopy ( i1III111 ) )
   if 36 - 36: iIii1I11I1II1 . iII111i * I1IiiI . I1IiiI - IiII
  return ( o00o0 )
  if 39 - 39: O0 / ooOoO0o + I11i - OoOoOO00 * o0oOOo0O0Ooo - OoO0O00
  if 97 - 97: i11iIiiIii / O0 % OoO0O00
 def merge_rlocs_in_site_eid ( self ) :
  self . registered_rlocs = [ ]
  for o0o000 in self . individual_registrations . values ( ) :
   if ( self . site_id != o0o000 . site_id ) : continue
   if ( o0o000 . registered == False ) : continue
   self . registered_rlocs += o0o000 . copy_rloc_records ( )
   if 88 - 88: i1IIi . I1IiiI
   if 8 - 8: I1ii11iIi11i . OoO0O00 % o0oOOo0O0Ooo / O0
   if 51 - 51: oO0o + Ii1I * Ii1I * I1ii11iIi11i % I11i - I1ii11iIi11i
   if 15 - 15: i1IIi / OoO0O00 - Oo0Ooo
   if 74 - 74: o0oOOo0O0Ooo % Ii1I - II111iiii / ooOoO0o
   if 84 - 84: I1IiiI + OOooOOo
  o00o0 = [ ]
  for i1III111 in self . registered_rlocs :
   if ( i1III111 . rloc . is_null ( ) or len ( o00o0 ) == 0 ) :
    o00o0 . append ( i1III111 )
    continue
    if 80 - 80: OOooOOo / OoOoOO00
   for o0OOooOooo in o00o0 :
    if ( o0OOooOooo . rloc . is_null ( ) ) : continue
    if ( i1III111 . rloc . is_exact_match ( o0OOooOooo . rloc ) ) : break
    if 36 - 36: iII111i % I1ii11iIi11i + OoOoOO00 - i11iIiiIii % II111iiii % I11i
   if ( o0OOooOooo == o00o0 [ - 1 ] ) : o00o0 . append ( i1III111 )
   if 92 - 92: O0 * OoooooooOO + I1ii11iIi11i / IiII
  self . registered_rlocs = o00o0
  if 97 - 97: o0oOOo0O0Ooo . Ii1I + I1Ii111
  if 72 - 72: i11iIiiIii . iII111i . Ii1I * I1ii11iIi11i
  if 49 - 49: OoOoOO00 - O0 % I11i - ooOoO0o * OOooOOo
  if 58 - 58: OoooooooOO - OOooOOo * oO0o / Ii1I . IiII
  if ( len ( self . registered_rlocs ) == 0 ) : self . registered = False
  return
  if 50 - 50: IiII . OOooOOo + I1ii11iIi11i - OoooooooOO
  if 2 - 2: o0oOOo0O0Ooo % ooOoO0o / O0 / i11iIiiIii
 def merge_rles_in_site_eid ( self ) :
  if 91 - 91: II111iiii * o0oOOo0O0Ooo
  if 20 - 20: iIii1I11I1II1 % Oo0Ooo * OoOoOO00 % IiII
  if 93 - 93: I11i * iIii1I11I1II1 * oO0o
  if 74 - 74: I1IiiI
  I1i11111Iiii = { }
  for i1III111 in self . registered_rlocs :
   if ( i1III111 . rle == None ) : continue
   for Iii in i1III111 . rle . rle_nodes :
    IiiIIi1 = Iii . address . print_address_no_iid ( )
    I1i11111Iiii [ IiiIIi1 ] = Iii . address
    if 13 - 13: i1IIi % i1IIi % ooOoO0o + IiII * II111iiii * OOooOOo
   break
   if 66 - 66: iIii1I11I1II1
   if 92 - 92: OOooOOo * o0oOOo0O0Ooo - IiII
   if 83 - 83: OoO0O00 % I1IiiI % OOooOOo / oO0o + I1IiiI
   if 94 - 94: OoOoOO00 . O0
   if 86 - 86: oO0o % Oo0Ooo . OoooooooOO / OOooOOo / i1IIi
  self . merge_rlocs_in_site_eid ( )
  if 65 - 65: Ii1I . OoooooooOO % IiII - o0oOOo0O0Ooo . OOooOOo . II111iiii
  if 100 - 100: ooOoO0o / Oo0Ooo + I1ii11iIi11i + OoooooooOO
  if 100 - 100: I11i . OOooOOo - II111iiii % I11i % iIii1I11I1II1
  if 4 - 4: o0oOOo0O0Ooo . iII111i / O0
  if 13 - 13: iII111i / IiII
  if 28 - 28: iII111i
  if 97 - 97: iIii1I11I1II1
  if 18 - 18: OOooOOo
  Ooooo000 = [ ]
  for i1III111 in self . registered_rlocs :
   if ( self . registered_rlocs . index ( i1III111 ) == 0 ) :
    Ooooo000 . append ( i1III111 )
    continue
    if 13 - 13: iIii1I11I1II1 - I1IiiI % o0oOOo0O0Ooo * iIii1I11I1II1
   if ( i1III111 . rle == None ) : Ooooo000 . append ( i1III111 )
   if 99 - 99: OoooooooOO / II111iiii . I1Ii111
  self . registered_rlocs = Ooooo000
  if 62 - 62: OOooOOo . iII111i . I1ii11iIi11i
  if 23 - 23: O0
  if 33 - 33: ooOoO0o - iII111i % IiII
  if 67 - 67: II111iiii
  if 66 - 66: iIii1I11I1II1 / OOooOOo
  if 65 - 65: IiII . oO0o + O0 - i11iIiiIii + iIii1I11I1II1
  if 82 - 82: iIii1I11I1II1 * iII111i + iIii1I11I1II1 / OoO0O00 + O0
  iI1Ii11 = lisp_rle ( "" )
  o0000OoooO0Oo = { }
  oo0O0OOooO0 = None
  for o0o000 in self . individual_registrations . values ( ) :
   if ( o0o000 . registered == False ) : continue
   I1i1i1IiI = o0o000 . registered_rlocs [ 0 ] . rle
   if ( I1i1i1IiI == None ) : continue
   if 38 - 38: O0 % I1IiiI * OOooOOo + OoOoOO00
   oo0O0OOooO0 = o0o000 . registered_rlocs [ 0 ] . rloc_name
   for O0o0O00 in I1i1i1IiI . rle_nodes :
    IiiIIi1 = O0o0O00 . address . print_address_no_iid ( )
    if ( o0000OoooO0Oo . has_key ( IiiIIi1 ) ) : break
    if 32 - 32: i1IIi . I1IiiI
    Iii = lisp_rle_node ( )
    Iii . address . copy_address ( O0o0O00 . address )
    Iii . level = O0o0O00 . level
    Iii . rloc_name = oo0O0OOooO0
    iI1Ii11 . rle_nodes . append ( Iii )
    o0000OoooO0Oo [ IiiIIi1 ] = O0o0O00 . address
    if 58 - 58: Ii1I
    if 25 - 25: oO0o / i11iIiiIii + i11iIiiIii % IiII - o0oOOo0O0Ooo
    if 97 - 97: I1ii11iIi11i % iII111i * ooOoO0o % OOooOOo . I1IiiI - i11iIiiIii
    if 2 - 2: IiII . o0oOOo0O0Ooo % II111iiii
    if 69 - 69: Ii1I
    if 75 - 75: I1IiiI
  if ( len ( iI1Ii11 . rle_nodes ) == 0 ) : iI1Ii11 = None
  if ( len ( self . registered_rlocs ) != 0 ) :
   self . registered_rlocs [ 0 ] . rle = iI1Ii11
   if ( oo0O0OOooO0 ) : self . registered_rlocs [ 0 ] . rloc_name = None
   if 55 - 55: i11iIiiIii - I1IiiI . oO0o - OoooooooOO
   if 44 - 44: I1Ii111
   if 98 - 98: I1IiiI % OOooOOo % iII111i
   if 15 - 15: OoO0O00
   if 52 - 52: II111iiii / ooOoO0o
  if ( I1i11111Iiii . keys ( ) == o0000OoooO0Oo . keys ( ) ) : return ( False )
  if 23 - 23: i11iIiiIii % OoO0O00 - o0oOOo0O0Ooo + OoooooooOO
  lprint ( "{} {} from {} to {}" . format ( green ( self . print_eid_tuple ( ) , False ) , bold ( "RLE change" , False ) ,
  # ooOoO0o
 I1i11111Iiii . keys ( ) , o0000OoooO0Oo . keys ( ) ) )
  if 18 - 18: I1IiiI . oO0o . I1IiiI + ooOoO0o - II111iiii
  return ( True )
  if 6 - 6: Oo0Ooo + Oo0Ooo - OoOoOO00 - II111iiii
  if 25 - 25: i11iIiiIii + II111iiii * OOooOOo % OOooOOo
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
    if 87 - 87: I11i % Ii1I % Oo0Ooo . II111iiii / oO0o
    if 19 - 19: O0 . OOooOOo + I1Ii111 * I1ii11iIi11i
    if 91 - 91: o0oOOo0O0Ooo / oO0o . o0oOOo0O0Ooo + IiII + ooOoO0o . I1Ii111
    if 90 - 90: i1IIi + oO0o * oO0o / ooOoO0o . IiII
    if 98 - 98: I11i % OoO0O00 . iII111i - o0oOOo0O0Ooo
    iIiIi1I . parent_for_more_specifics = self . parent_for_more_specifics
    if 92 - 92: I11i
   if ( self . eid . is_null ( ) ) : self . eid . make_default_route ( iIiIi1I . group )
   iIiIi1I . add_source_entry ( self )
   if 34 - 34: I1IiiI % iIii1I11I1II1 . I1ii11iIi11i * Oo0Ooo * iIii1I11I1II1 / O0
   if 98 - 98: iII111i % IiII + OoO0O00
   if 23 - 23: OOooOOo
 def delete_cache ( self ) :
  if ( self . group . is_null ( ) ) :
   lisp_sites_by_eid . delete_cache ( self . eid )
  else :
   iIiIi1I = lisp_sites_by_eid . lookup_cache ( self . group , True )
   if ( iIiIi1I == None ) : return
   if 83 - 83: I1ii11iIi11i / O0 * II111iiii + IiII + Oo0Ooo
   o0o000 = iIiIi1I . lookup_source_cache ( self . eid , True )
   if ( o0o000 == None ) : return
   if 99 - 99: II111iiii + O0
   if ( iIiIi1I . source_cache == None ) : return
   if 94 - 94: ooOoO0o * ooOoO0o + o0oOOo0O0Ooo . iII111i % iIii1I11I1II1 + Ii1I
   iIiIi1I . source_cache . delete_cache ( self . eid )
   if ( iIiIi1I . source_cache . cache_size ( ) == 0 ) :
    lisp_sites_by_eid . delete_cache ( self . group )
    if 88 - 88: Oo0Ooo . iII111i
    if 89 - 89: OOooOOo + I1Ii111 % i11iIiiIii + Oo0Ooo / Oo0Ooo + OoO0O00
    if 9 - 9: OoOoOO00 % i1IIi + IiII
    if 19 - 19: I1Ii111 - II111iiii / I1Ii111 + I1IiiI - OoooooooOO + o0oOOo0O0Ooo
 def add_source_entry ( self , source_se ) :
  if ( self . source_cache == None ) : self . source_cache = lisp_cache ( )
  self . source_cache . add_cache ( source_se . eid , source_se )
  if 100 - 100: OoO0O00 / OoOoOO00 / OOooOOo / OoO0O00
  if 95 - 95: ooOoO0o
 def lookup_source_cache ( self , source , exact ) :
  if ( self . source_cache == None ) : return ( None )
  return ( self . source_cache . lookup_cache ( source , exact ) )
  if 95 - 95: Ii1I + i1IIi . I1IiiI % I1Ii111 / Ii1I * O0
  if 68 - 68: I1Ii111 - IiII - oO0o - Oo0Ooo - o0oOOo0O0Ooo
 def is_star_g ( self ) :
  if ( self . group . is_null ( ) ) : return ( False )
  return ( self . eid . is_exact_match ( self . group ) )
  if 32 - 32: OoOoOO00 % i11iIiiIii
  if 53 - 53: I1Ii111 * Ii1I / IiII . i1IIi * II111iiii / o0oOOo0O0Ooo
 def eid_record_matches ( self , eid_record ) :
  if ( self . eid . is_exact_match ( eid_record . eid ) == False ) : return ( False )
  if ( eid_record . group . is_null ( ) ) : return ( True )
  return ( eid_record . group . is_exact_match ( self . group ) )
  if 44 - 44: I1Ii111 + ooOoO0o
  if 15 - 15: I11i + OoO0O00 + OoOoOO00
 def inherit_from_ams_parent ( self ) :
  O0Ii1IiiiI = self . parent_for_more_specifics
  if ( O0Ii1IiiiI == None ) : return
  self . force_proxy_reply = O0Ii1IiiiI . force_proxy_reply
  self . force_nat_proxy_reply = O0Ii1IiiiI . force_nat_proxy_reply
  self . force_ttl = O0Ii1IiiiI . force_ttl
  self . pitr_proxy_reply_drop = O0Ii1IiiiI . pitr_proxy_reply_drop
  self . proxy_reply_action = O0Ii1IiiiI . proxy_reply_action
  self . echo_nonce_capable = O0Ii1IiiiI . echo_nonce_capable
  self . policy = O0Ii1IiiiI . policy
  self . require_signature = O0Ii1IiiiI . require_signature
  self . encrypt_json = O0Ii1IiiiI . encrypt_json
  if 100 - 100: I1Ii111
  if 78 - 78: OoOoOO00
 def rtrs_in_rloc_set ( self ) :
  for i1III111 in self . registered_rlocs :
   if ( i1III111 . is_rtr ( ) ) : return ( True )
   if 16 - 16: I1Ii111 % OoO0O00 - OoO0O00 % OoOoOO00 * OoO0O00
  return ( False )
  if 36 - 36: OoOoOO00 * II111iiii . OoooooooOO * I11i . I11i
  if 13 - 13: I1ii11iIi11i * II111iiii
 def is_rtr_in_rloc_set ( self , rtr_rloc ) :
  for i1III111 in self . registered_rlocs :
   if ( i1III111 . rloc . is_exact_match ( rtr_rloc ) == False ) : continue
   if ( i1III111 . is_rtr ( ) ) : return ( True )
   if 93 - 93: OOooOOo / O0 - o0oOOo0O0Ooo + OoO0O00 * I1IiiI
  return ( False )
  if 53 - 53: I1ii11iIi11i
  if 91 - 91: o0oOOo0O0Ooo - I1ii11iIi11i . i1IIi
 def is_rloc_in_rloc_set ( self , rloc ) :
  for i1III111 in self . registered_rlocs :
   if ( i1III111 . rle ) :
    for iI1Ii11 in i1III111 . rle . rle_nodes :
     if ( iI1Ii11 . address . is_exact_match ( rloc ) ) : return ( True )
     if 64 - 64: ooOoO0o
     if 23 - 23: Oo0Ooo . OoO0O00
   if ( i1III111 . rloc . is_exact_match ( rloc ) ) : return ( True )
   if 49 - 49: oO0o % i11iIiiIii * Ii1I
  return ( False )
  if 9 - 9: Oo0Ooo - OoO0O00 + ooOoO0o / o0oOOo0O0Ooo
  if 61 - 61: O0 - i11iIiiIii * o0oOOo0O0Ooo
 def do_rloc_sets_match ( self , prev_rloc_set ) :
  if ( len ( self . registered_rlocs ) != len ( prev_rloc_set ) ) : return ( False )
  if 92 - 92: Oo0Ooo + OOooOOo - i11iIiiIii
  for i1III111 in prev_rloc_set :
   OoOO0O = i1III111 . rloc
   if ( self . is_rloc_in_rloc_set ( OoOO0O ) == False ) : return ( False )
   if 26 - 26: O0 % Oo0Ooo + ooOoO0o - Ii1I . Oo0Ooo
  return ( True )
  if 33 - 33: I1Ii111 / iII111i . I1Ii111 % II111iiii
  if 52 - 52: I1ii11iIi11i
  if 1 - 1: II111iiii + I1ii11iIi11i * OoOoOO00 % ooOoO0o - iII111i % OoooooooOO
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
   if 77 - 77: iII111i + o0oOOo0O0Ooo
  self . last_used = 0
  self . last_reply = 0
  self . last_nonce = 0
  self . map_requests_sent = 0
  self . neg_map_replies_received = 0
  self . total_rtt = 0
  if 60 - 60: I1ii11iIi11i
  if 23 - 23: iII111i % I1IiiI % I1Ii111 * oO0o * I1IiiI
 def resolve_dns_name ( self ) :
  if ( self . dns_name == None ) : return
  if ( self . last_dns_resolve and
 time . time ( ) - self . last_dns_resolve < 30 ) : return
  if 74 - 74: O0 / I11i . Oo0Ooo / I11i % OoO0O00 % o0oOOo0O0Ooo
  try :
   IIiiI = socket . gethostbyname_ex ( self . dns_name )
   self . last_dns_resolve = lisp_get_timestamp ( )
   oOOooOooO = IIiiI [ 2 ]
  except :
   return
   if 59 - 59: OoOoOO00 . OoooooooOO
   if 93 - 93: Oo0Ooo - i1IIi - oO0o - I11i + O0 - iIii1I11I1II1
   if 68 - 68: i1IIi / OoO0O00 * i1IIi - OoooooooOO / II111iiii * OoooooooOO
   if 37 - 37: OoooooooOO % I1IiiI * I1IiiI
   if 13 - 13: oO0o
   if 43 - 43: oO0o / Ii1I % OOooOOo
  if ( len ( oOOooOooO ) <= self . a_record_index ) :
   self . delete_mr ( )
   return
   if 45 - 45: II111iiii
   if 41 - 41: Ii1I / OOooOOo * Oo0Ooo . O0 - i11iIiiIii
  IiiIIi1 = oOOooOooO [ self . a_record_index ]
  if ( IiiIIi1 != self . map_resolver . print_address_no_iid ( ) ) :
   self . delete_mr ( )
   self . map_resolver . store_address ( IiiIIi1 )
   self . insert_mr ( )
   if 77 - 77: o0oOOo0O0Ooo + I1IiiI + I1Ii111 / I1ii11iIi11i * i1IIi
   if 37 - 37: O0 + iIii1I11I1II1 % IiII * oO0o
   if 43 - 43: OOooOOo . O0
   if 76 - 76: OOooOOo * OoooooooOO / IiII . OoO0O00 + II111iiii
   if 23 - 23: OoO0O00 - OoooooooOO * I11i . iIii1I11I1II1 / o0oOOo0O0Ooo + oO0o
   if 74 - 74: II111iiii / I1IiiI * O0 * OoO0O00 . I11i
  if ( lisp_is_decent_dns_suffix ( self . dns_name ) == False ) : return
  if ( self . a_record_index != 0 ) : return
  if 74 - 74: O0 . i1IIi / I1ii11iIi11i + o0oOOo0O0Ooo
  for IiiIIi1 in oOOooOooO [ 1 : : ] :
   OO0o = lisp_address ( LISP_AFI_NONE , IiiIIi1 , 0 , 0 )
   I1I1iiii111II = lisp_get_map_resolver ( OO0o , None )
   if ( I1I1iiii111II != None and I1I1iiii111II . a_record_index == oOOooOooO . index ( IiiIIi1 ) ) :
    continue
    if 24 - 24: ooOoO0o % I1Ii111 + OoO0O00 * o0oOOo0O0Ooo % O0 - i11iIiiIii
   I1I1iiii111II = lisp_mr ( IiiIIi1 , None , None )
   I1I1iiii111II . a_record_index = oOOooOooO . index ( IiiIIi1 )
   I1I1iiii111II . dns_name = self . dns_name
   I1I1iiii111II . last_dns_resolve = lisp_get_timestamp ( )
   if 49 - 49: o0oOOo0O0Ooo / OoOoOO00 + iII111i
   if 85 - 85: I1IiiI - o0oOOo0O0Ooo
   if 86 - 86: II111iiii + Ii1I * Ii1I
   if 26 - 26: o0oOOo0O0Ooo + oO0o * i11iIiiIii / II111iiii
   if 86 - 86: Ii1I
  oOoOOoo0OoO = [ ]
  for I1I1iiii111II in lisp_map_resolvers_list . values ( ) :
   if ( self . dns_name != I1I1iiii111II . dns_name ) : continue
   OO0o = I1I1iiii111II . map_resolver . print_address_no_iid ( )
   if ( OO0o in oOOooOooO ) : continue
   oOoOOoo0OoO . append ( I1I1iiii111II )
   if 78 - 78: I1Ii111 % i1IIi * I11i
  for I1I1iiii111II in oOoOOoo0OoO : I1I1iiii111II . delete_mr ( )
  if 59 - 59: OoOoOO00 % OoO0O00 % i11iIiiIii . II111iiii % I1ii11iIi11i + i1IIi
  if 99 - 99: I11i + IiII * I1Ii111 - OOooOOo - i1IIi
 def insert_mr ( self ) :
  Oo000O000 = self . mr_name + self . map_resolver . print_address ( )
  lisp_map_resolvers_list [ Oo000O000 ] = self
  if 77 - 77: I11i . IiII / OoO0O00 / I1Ii111
  if 8 - 8: o0oOOo0O0Ooo + iII111i / OoO0O00 * ooOoO0o - oO0o . iII111i
 def delete_mr ( self ) :
  Oo000O000 = self . mr_name + self . map_resolver . print_address ( )
  if ( lisp_map_resolvers_list . has_key ( Oo000O000 ) == False ) : return
  lisp_map_resolvers_list . pop ( Oo000O000 )
  if 32 - 32: OoooooooOO . I1Ii111 - I1ii11iIi11i
  if 29 - 29: OoO0O00
  if 33 - 33: I1ii11iIi11i - O0
class lisp_ddt_root ( ) :
 def __init__ ( self ) :
  self . root_address = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . public_key = ""
  self . priority = 0
  self . weight = 0
  if 72 - 72: Oo0Ooo * iII111i - I11i
  if 81 - 81: I1Ii111
  if 85 - 85: O0 % OoOoOO00 . I1ii11iIi11i
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
  if 46 - 46: OOooOOo * iIii1I11I1II1
  if 33 - 33: OoO0O00 * II111iiii / i1IIi
 def print_referral ( self , eid_indent , referral_indent ) :
  o00OO0OoOOO = lisp_print_elapsed ( self . uptime )
  ooooO0oOo0O = lisp_print_future ( self . expires )
  lprint ( "{}Referral EID {}, uptime/expires {}/{}, {} referrals:" . format ( eid_indent , green ( self . eid . print_prefix ( ) , False ) , o00OO0OoOOO ,
  # IiII - OOooOOo * OOooOOo . O0
 ooooO0oOo0O , len ( self . referral_set ) ) )
  if 60 - 60: OoOoOO00 % iIii1I11I1II1 + IiII % o0oOOo0O0Ooo
  for iiI111I in self . referral_set . values ( ) :
   iiI111I . print_ref_node ( referral_indent )
   if 64 - 64: OoOoOO00 * I1ii11iIi11i . OoooooooOO . i1IIi
   if 61 - 61: OoO0O00
   if 100 - 100: OoOoOO00
 def print_referral_type ( self ) :
  if ( self . eid . afi == LISP_AFI_ULTIMATE_ROOT ) : return ( "root" )
  if ( self . referral_type == LISP_DDT_ACTION_NULL ) :
   return ( "null-referral" )
   if 97 - 97: OoooooooOO
  if ( self . referral_type == LISP_DDT_ACTION_SITE_NOT_FOUND ) :
   return ( "no-site-action" )
   if 91 - 91: o0oOOo0O0Ooo / O0 % OoO0O00
  if ( self . referral_type > LISP_DDT_ACTION_MAX ) :
   return ( "invalid-action" )
   if 35 - 35: iII111i % OoO0O00 * O0
  return ( lisp_map_referral_action_string [ self . referral_type ] )
  if 37 - 37: OOooOOo
  if 100 - 100: Oo0Ooo * I1IiiI . ooOoO0o
 def print_eid_tuple ( self ) :
  return ( lisp_print_eid_tuple ( self . eid , self . group ) )
  if 53 - 53: OOooOOo + o0oOOo0O0Ooo * Ii1I + O0
  if 75 - 75: OoooooooOO
 def print_ttl ( self ) :
  oOoooOOO0o0 = self . referral_ttl
  if ( oOoooOOO0o0 < 60 ) : return ( str ( oOoooOOO0o0 ) + " secs" )
  if 24 - 24: I1Ii111 % i11iIiiIii % oO0o . OOooOOo % IiII
  if ( ( oOoooOOO0o0 % 60 ) == 0 ) :
   oOoooOOO0o0 = str ( oOoooOOO0o0 / 60 ) + " mins"
  else :
   oOoooOOO0o0 = str ( oOoooOOO0o0 ) + " secs"
   if 23 - 23: o0oOOo0O0Ooo * II111iiii - Oo0Ooo - I1IiiI
  return ( oOoooOOO0o0 )
  if 86 - 86: I1IiiI - II111iiii * II111iiii * oO0o % OoooooooOO * OoOoOO00
  if 93 - 93: I1IiiI + OoO0O00 % O0 - ooOoO0o * i1IIi
 def is_referral_negative ( self ) :
  return ( self . referral_type in ( LISP_DDT_ACTION_MS_NOT_REG , LISP_DDT_ACTION_DELEGATION_HOLE ,
  # I1IiiI . IiII . I11i % i1IIi
 LISP_DDT_ACTION_NOT_AUTH ) )
  if 21 - 21: OOooOOo * o0oOOo0O0Ooo * II111iiii - I1ii11iIi11i / O0
  if 97 - 97: II111iiii
 def add_cache ( self ) :
  if ( self . group . is_null ( ) ) :
   lisp_referral_cache . add_cache ( self . eid , self )
  else :
   IiII111IiII1 = lisp_referral_cache . lookup_cache ( self . group , True )
   if ( IiII111IiII1 == None ) :
    IiII111IiII1 = lisp_referral ( )
    IiII111IiII1 . eid . copy_address ( self . group )
    IiII111IiII1 . group . copy_address ( self . group )
    lisp_referral_cache . add_cache ( self . group , IiII111IiII1 )
    if 80 - 80: iIii1I11I1II1 - ooOoO0o
   if ( self . eid . is_null ( ) ) : self . eid . make_default_route ( IiII111IiII1 . group )
   IiII111IiII1 . add_source_entry ( self )
   if 10 - 10: OoO0O00 % I11i * I11i
   if 83 - 83: I1Ii111
   if 8 - 8: I1IiiI % OOooOOo
 def delete_cache ( self ) :
  if ( self . group . is_null ( ) ) :
   lisp_referral_cache . delete_cache ( self . eid )
  else :
   IiII111IiII1 = lisp_referral_cache . lookup_cache ( self . group , True )
   if ( IiII111IiII1 == None ) : return
   if 52 - 52: iIii1I11I1II1
   iiIIII = IiII111IiII1 . lookup_source_cache ( self . eid , True )
   if ( iiIIII == None ) : return
   if 5 - 5: II111iiii
   IiII111IiII1 . source_cache . delete_cache ( self . eid )
   if ( IiII111IiII1 . source_cache . cache_size ( ) == 0 ) :
    lisp_referral_cache . delete_cache ( self . group )
    if 100 - 100: O0 * iIii1I11I1II1 - OoooooooOO
    if 41 - 41: OoO0O00 / OoooooooOO
    if 61 - 61: ooOoO0o
    if 4 - 4: Oo0Ooo + oO0o + oO0o
 def add_source_entry ( self , source_ref ) :
  if ( self . source_cache == None ) : self . source_cache = lisp_cache ( )
  self . source_cache . add_cache ( source_ref . eid , source_ref )
  if 79 - 79: OoooooooOO
  if 98 - 98: O0 . ooOoO0o * I1Ii111
 def lookup_source_cache ( self , source , exact ) :
  if ( self . source_cache == None ) : return ( None )
  return ( self . source_cache . lookup_cache ( source , exact ) )
  if 98 - 98: ooOoO0o + o0oOOo0O0Ooo / I11i - Ii1I * II111iiii + i1IIi
  if 10 - 10: oO0o
  if 8 - 8: I1ii11iIi11i * OOooOOo * iIii1I11I1II1 + I11i . iII111i
class lisp_referral_node ( ) :
 def __init__ ( self ) :
  self . referral_address = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . priority = 0
  self . weight = 0
  self . updown = True
  self . map_requests_sent = 0
  self . no_responses = 0
  self . uptime = lisp_get_timestamp ( )
  if 55 - 55: I1IiiI + Ii1I % I1ii11iIi11i + iIii1I11I1II1
  if 64 - 64: i1IIi / O0 - oO0o
 def print_ref_node ( self , indent ) :
  i1 = lisp_print_elapsed ( self . uptime )
  lprint ( "{}referral {}, uptime {}, {}, priority/weight: {}/{}" . format ( indent , red ( self . referral_address . print_address ( ) , False ) , i1 ,
  # Oo0Ooo
 "up" if self . updown else "down" , self . priority , self . weight ) )
  if 8 - 8: IiII * i11iIiiIii % i11iIiiIii . I11i * I1ii11iIi11i . II111iiii
  if 44 - 44: I1IiiI + I1ii11iIi11i
  if 81 - 81: i11iIiiIii + o0oOOo0O0Ooo
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
   if 42 - 42: ooOoO0o . i1IIi + iIii1I11I1II1 . oO0o * OoOoOO00 / ooOoO0o
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
   if 20 - 20: I1Ii111 + IiII . i11iIiiIii / iIii1I11I1II1 . I11i % IiII
   if 91 - 91: ooOoO0o * Oo0Ooo . i1IIi . ooOoO0o . ooOoO0o
   if 24 - 24: iIii1I11I1II1
 def resolve_dns_name ( self ) :
  if ( self . dns_name == None ) : return
  if ( self . last_dns_resolve and
 time . time ( ) - self . last_dns_resolve < 30 ) : return
  if 72 - 72: i11iIiiIii + o0oOOo0O0Ooo % ooOoO0o * I1ii11iIi11i . i1IIi
  try :
   IIiiI = socket . gethostbyname_ex ( self . dns_name )
   self . last_dns_resolve = lisp_get_timestamp ( )
   oOOooOooO = IIiiI [ 2 ]
  except :
   return
   if 59 - 59: OoooooooOO - OoooooooOO - o0oOOo0O0Ooo + i1IIi % I1Ii111
   if 74 - 74: IiII * iIii1I11I1II1 - I1IiiI
   if 62 - 62: o0oOOo0O0Ooo
   if 54 - 54: iIii1I11I1II1 / OoooooooOO + o0oOOo0O0Ooo . i1IIi - OoooooooOO
   if 70 - 70: Ii1I / OoOoOO00 * Oo0Ooo
   if 32 - 32: I1Ii111 . OoOoOO00 % OoooooooOO + I1Ii111 * OoO0O00
  if ( len ( oOOooOooO ) <= self . a_record_index ) :
   self . delete_ms ( )
   return
   if 84 - 84: OoOoOO00
   if 80 - 80: oO0o
  IiiIIi1 = oOOooOooO [ self . a_record_index ]
  if ( IiiIIi1 != self . map_server . print_address_no_iid ( ) ) :
   self . delete_ms ( )
   self . map_server . store_address ( IiiIIi1 )
   self . insert_ms ( )
   if 59 - 59: iIii1I11I1II1 / IiII % I1ii11iIi11i + OoO0O00 - I11i % OOooOOo
   if 92 - 92: iII111i
   if 96 - 96: OoOoOO00 / OoOoOO00 / OoOoOO00 + OoooooooOO + Oo0Ooo
   if 91 - 91: OoOoOO00 + II111iiii / I11i * iIii1I11I1II1
   if 92 - 92: I1Ii111 - IiII / IiII
   if 42 - 42: IiII
  if ( lisp_is_decent_dns_suffix ( self . dns_name ) == False ) : return
  if ( self . a_record_index != 0 ) : return
  if 7 - 7: iIii1I11I1II1
  for IiiIIi1 in oOOooOooO [ 1 : : ] :
   OO0o = lisp_address ( LISP_AFI_NONE , IiiIIi1 , 0 , 0 )
   ii1iOo = lisp_get_map_server ( OO0o )
   if ( ii1iOo != None and ii1iOo . a_record_index == oOOooOooO . index ( IiiIIi1 ) ) :
    continue
    if 35 - 35: IiII + O0 % I1Ii111 - I1ii11iIi11i - i1IIi
   ii1iOo = copy . deepcopy ( self )
   ii1iOo . map_server . store_address ( IiiIIi1 )
   ii1iOo . a_record_index = oOOooOooO . index ( IiiIIi1 )
   ii1iOo . last_dns_resolve = lisp_get_timestamp ( )
   ii1iOo . insert_ms ( )
   if 100 - 100: I1Ii111 + i11iIiiIii - IiII / I1ii11iIi11i / iII111i
   if 56 - 56: iII111i
   if 91 - 91: Oo0Ooo . I11i . I1ii11iIi11i
   if 60 - 60: i11iIiiIii - OOooOOo
   if 78 - 78: I1IiiI * ooOoO0o % iIii1I11I1II1 / I1ii11iIi11i
  oOoOOoo0OoO = [ ]
  for ii1iOo in lisp_map_servers_list . values ( ) :
   if ( self . dns_name != ii1iOo . dns_name ) : continue
   OO0o = ii1iOo . map_server . print_address_no_iid ( )
   if ( OO0o in oOOooOooO ) : continue
   oOoOOoo0OoO . append ( ii1iOo )
   if 61 - 61: I1Ii111 . Ii1I + OoooooooOO
  for ii1iOo in oOoOOoo0OoO : ii1iOo . delete_ms ( )
  if 98 - 98: OOooOOo . ooOoO0o . OoOoOO00 - I1Ii111 . i1IIi - iIii1I11I1II1
  if 89 - 89: II111iiii * I1ii11iIi11i - I1IiiI
 def insert_ms ( self ) :
  Oo000O000 = self . ms_name + self . map_server . print_address ( )
  lisp_map_servers_list [ Oo000O000 ] = self
  if 58 - 58: Ii1I / Oo0Ooo % IiII
  if 33 - 33: II111iiii . OOooOOo % iIii1I11I1II1 - Oo0Ooo - OoOoOO00 % i11iIiiIii
 def delete_ms ( self ) :
  Oo000O000 = self . ms_name + self . map_server . print_address ( )
  if ( lisp_map_servers_list . has_key ( Oo000O000 ) == False ) : return
  lisp_map_servers_list . pop ( Oo000O000 )
  if 60 - 60: iII111i . o0oOOo0O0Ooo
  if 56 - 56: I1ii11iIi11i
  if 89 - 89: Oo0Ooo + I1ii11iIi11i * o0oOOo0O0Ooo * oO0o % O0 % OoO0O00
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
  if 70 - 70: o0oOOo0O0Ooo + O0 % I1IiiI
  if 56 - 56: Ii1I
 def add_interface ( self ) :
  lisp_myinterfaces [ self . device ] = self
  if 84 - 84: iII111i
  if 21 - 21: i11iIiiIii
 def get_instance_id ( self ) :
  return ( self . instance_id )
  if 30 - 30: OoO0O00 + OoooooooOO
  if 98 - 98: I1ii11iIi11i % I1IiiI
 def get_socket ( self ) :
  return ( self . raw_socket )
  if 9 - 9: o0oOOo0O0Ooo / I1Ii111 % i1IIi - OOooOOo % I1IiiI / I1ii11iIi11i
  if 66 - 66: IiII
 def get_bridge_socket ( self ) :
  return ( self . bridge_socket )
  if 56 - 56: oO0o + OoooooooOO
  if 75 - 75: O0 % Ii1I
 def does_dynamic_eid_match ( self , eid ) :
  if ( self . dynamic_eid . is_null ( ) ) : return ( False )
  return ( eid . is_more_specific ( self . dynamic_eid ) )
  if 47 - 47: OoooooooOO - OoooooooOO + OoO0O00 / iIii1I11I1II1
  if 23 - 23: iII111i / iIii1I11I1II1
 def set_socket ( self , device ) :
  IiII1iiI = socket . socket ( socket . AF_INET , socket . SOCK_RAW , socket . IPPROTO_RAW )
  IiII1iiI . setsockopt ( socket . SOL_IP , socket . IP_HDRINCL , 1 )
  try :
   IiII1iiI . setsockopt ( socket . SOL_SOCKET , socket . SO_BINDTODEVICE , device )
  except :
   IiII1iiI . close ( )
   IiII1iiI = None
   if 5 - 5: O0
  self . raw_socket = IiII1iiI
  if 64 - 64: i1IIi * i1IIi . iII111i - O0 - oO0o % OoooooooOO
  if 14 - 14: Ii1I % OoO0O00 % I1Ii111 * O0
 def set_bridge_socket ( self , device ) :
  IiII1iiI = socket . socket ( socket . PF_PACKET , socket . SOCK_RAW )
  try :
   IiII1iiI = IiII1iiI . bind ( ( device , 0 ) )
   self . bridge_socket = IiII1iiI
  except :
   return
   if 8 - 8: I1IiiI - i11iIiiIii * I1IiiI
   if 6 - 6: O0 - OoOoOO00 - i11iIiiIii / iII111i
   if 63 - 63: OOooOOo
   if 84 - 84: i11iIiiIii * iIii1I11I1II1 % I11i % iII111i + OoooooooOO . o0oOOo0O0Ooo
class lisp_datetime ( ) :
 def __init__ ( self , datetime_str ) :
  self . datetime_name = datetime_str
  self . datetime = None
  self . parse_datetime ( )
  if 78 - 78: o0oOOo0O0Ooo . iII111i + O0 / I1ii11iIi11i + I1ii11iIi11i + II111iiii
  if 96 - 96: iIii1I11I1II1 * II111iiii . iIii1I11I1II1
 def valid_datetime ( self ) :
  i1iI1iII = self . datetime_name
  if ( i1iI1iII . find ( ":" ) == - 1 ) : return ( False )
  if ( i1iI1iII . find ( "-" ) == - 1 ) : return ( False )
  oOO0O000o0 , Ooi1Ii1111II , I11111 , time = i1iI1iII [ 0 : 4 ] , i1iI1iII [ 5 : 7 ] , i1iI1iII [ 8 : 10 ] , i1iI1iII [ 11 : : ]
  if 53 - 53: iIii1I11I1II1 - Oo0Ooo
  if ( ( oOO0O000o0 + Ooi1Ii1111II + I11111 ) . isdigit ( ) == False ) : return ( False )
  if ( Ooi1Ii1111II < "01" and Ooi1Ii1111II > "12" ) : return ( False )
  if ( I11111 < "01" and I11111 > "31" ) : return ( False )
  if 46 - 46: ooOoO0o
  i1Ii1i1 , ooo00oOoO , Ii11II1 = time . split ( ":" )
  if 92 - 92: iII111i . II111iiii / OoOoOO00
  if ( ( i1Ii1i1 + ooo00oOoO + Ii11II1 ) . isdigit ( ) == False ) : return ( False )
  if ( i1Ii1i1 < "00" and i1Ii1i1 > "23" ) : return ( False )
  if ( ooo00oOoO < "00" and ooo00oOoO > "59" ) : return ( False )
  if ( Ii11II1 < "00" and Ii11II1 > "59" ) : return ( False )
  return ( True )
  if 32 - 32: o0oOOo0O0Ooo / I1Ii111 / I1ii11iIi11i / I11i / OoooooooOO
  if 40 - 40: IiII / ooOoO0o . o0oOOo0O0Ooo
 def parse_datetime ( self ) :
  ooo0Ooo00O0O = self . datetime_name
  ooo0Ooo00O0O = ooo0Ooo00O0O . replace ( "-" , "" )
  ooo0Ooo00O0O = ooo0Ooo00O0O . replace ( ":" , "" )
  self . datetime = int ( ooo0Ooo00O0O )
  if 47 - 47: O0 % oO0o + ooOoO0o
  if 65 - 65: iII111i
 def now ( self ) :
  i1 = datetime . datetime . now ( ) . strftime ( "%Y-%m-%d-%H:%M:%S" )
  i1 = lisp_datetime ( i1 )
  return ( i1 )
  if 3 - 3: iIii1I11I1II1
  if 25 - 25: OOooOOo * OoO0O00 + o0oOOo0O0Ooo % Ii1I - o0oOOo0O0Ooo - iII111i
 def print_datetime ( self ) :
  return ( self . datetime_name )
  if 17 - 17: O0 . ooOoO0o % I1IiiI . iII111i / oO0o . IiII
  if 95 - 95: ooOoO0o . I11i / i11iIiiIii - IiII
 def future ( self ) :
  return ( self . datetime > self . now ( ) . datetime )
  if 87 - 87: I1Ii111 - iII111i * I11i
  if 74 - 74: Ii1I - OoOoOO00 + i11iIiiIii - II111iiii - i11iIiiIii . ooOoO0o
 def past ( self ) :
  return ( self . future ( ) == False )
  if 83 - 83: I1Ii111 % ooOoO0o + OoooooooOO
  if 50 - 50: i11iIiiIii % I1IiiI * iII111i / Ii1I
 def now_in_range ( self , upper ) :
  return ( self . past ( ) and upper . future ( ) )
  if 12 - 12: iII111i / OoO0O00 - II111iiii + Oo0Ooo
  if 78 - 78: i1IIi
 def this_year ( self ) :
  i1iiI11IiIi1 = str ( self . now ( ) . datetime ) [ 0 : 4 ]
  i1 = str ( self . datetime ) [ 0 : 4 ]
  return ( i1 == i1iiI11IiIi1 )
  if 91 - 91: II111iiii
  if 52 - 52: o0oOOo0O0Ooo . O0 % I11i . iIii1I11I1II1 % iIii1I11I1II1 / I1Ii111
 def this_month ( self ) :
  i1iiI11IiIi1 = str ( self . now ( ) . datetime ) [ 0 : 6 ]
  i1 = str ( self . datetime ) [ 0 : 6 ]
  return ( i1 == i1iiI11IiIi1 )
  if 18 - 18: Ii1I * I1ii11iIi11i % I11i
  if 50 - 50: Ii1I . I1ii11iIi11i + iIii1I11I1II1 * i11iIiiIii . iII111i
 def today ( self ) :
  i1iiI11IiIi1 = str ( self . now ( ) . datetime ) [ 0 : 8 ]
  i1 = str ( self . datetime ) [ 0 : 8 ]
  return ( i1 == i1iiI11IiIi1 )
  if 47 - 47: o0oOOo0O0Ooo * oO0o % I1ii11iIi11i
  if 59 - 59: IiII
  if 22 - 22: i11iIiiIii . oO0o * OoOoOO00 . OoooooooOO
  if 100 - 100: I1Ii111 + O0
  if 69 - 69: I11i + OoO0O00 + o0oOOo0O0Ooo - o0oOOo0O0Ooo - Ii1I
  if 24 - 24: i11iIiiIii + I11i . O0
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
  if 96 - 96: OoOoOO00 . I1ii11iIi11i - oO0o
  if 81 - 81: iII111i - II111iiii * O0
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
  if 55 - 55: II111iiii * i1IIi
  if 7 - 7: OOooOOo - I1ii11iIi11i * O0 * iIii1I11I1II1 + OoO0O00 / I11i
 def match_policy_map_request ( self , mr , srloc ) :
  for i1iI11i in self . match_clauses :
   oo00ooOOOo0O = i1iI11i . source_eid
   iioOo0oo = mr . source_eid
   if ( oo00ooOOOo0O and iioOo0oo and iioOo0oo . is_more_specific ( oo00ooOOOo0O ) == False ) : continue
   if 25 - 25: OoooooooOO . O0 % OoO0O00
   oo00ooOOOo0O = i1iI11i . dest_eid
   iioOo0oo = mr . target_eid
   if ( oo00ooOOOo0O and iioOo0oo and iioOo0oo . is_more_specific ( oo00ooOOOo0O ) == False ) : continue
   if 52 - 52: i11iIiiIii
   oo00ooOOOo0O = i1iI11i . source_rloc
   iioOo0oo = srloc
   if ( oo00ooOOOo0O and iioOo0oo and iioOo0oo . is_more_specific ( oo00ooOOOo0O ) == False ) : continue
   I11iIi1i1I1i1 = i1iI11i . datetime_lower
   oO0ooo00OO = i1iI11i . datetime_upper
   if ( I11iIi1i1I1i1 and oO0ooo00OO and I11iIi1i1I1i1 . now_in_range ( oO0ooo00OO ) == False ) : continue
   return ( True )
   if 46 - 46: II111iiii
  return ( False )
  if 93 - 93: Ii1I * iII111i / OoOoOO00
  if 65 - 65: iIii1I11I1II1 . o0oOOo0O0Ooo % OoO0O00
 def set_policy_map_reply ( self ) :
  i11i11IiI1IiI = ( self . set_rloc_address == None and
 self . set_rloc_record_name == None and self . set_geo_name == None and
 self . set_elp_name == None and self . set_rle_name == None )
  if ( i11i11IiI1IiI ) : return ( None )
  if 87 - 87: Oo0Ooo * II111iiii / oO0o
  I1IIiIIIii = lisp_rloc ( )
  if ( self . set_rloc_address ) :
   I1IIiIIIii . rloc . copy_address ( self . set_rloc_address )
   IiiIIi1 = I1IIiIIIii . rloc . print_address_no_iid ( )
   lprint ( "Policy set-rloc-address to {}" . format ( IiiIIi1 ) )
   if 84 - 84: i1IIi - I1ii11iIi11i + OoO0O00 + Oo0Ooo
  if ( self . set_rloc_record_name ) :
   I1IIiIIIii . rloc_name = self . set_rloc_record_name
   IiIIO0 = blue ( I1IIiIIIii . rloc_name , False )
   lprint ( "Policy set-rloc-record-name to {}" . format ( IiIIO0 ) )
   if 50 - 50: iII111i
  if ( self . set_geo_name ) :
   I1IIiIIIii . geo_name = self . set_geo_name
   IiIIO0 = I1IIiIIIii . geo_name
   o0O0oO00 = "" if lisp_geo_list . has_key ( IiIIO0 ) else "(not configured)"
   if 82 - 82: OOooOOo
   lprint ( "Policy set-geo-name '{}' {}" . format ( IiIIO0 , o0O0oO00 ) )
   if 96 - 96: oO0o % ooOoO0o / i1IIi - I11i - Ii1I . o0oOOo0O0Ooo
  if ( self . set_elp_name ) :
   I1IIiIIIii . elp_name = self . set_elp_name
   IiIIO0 = I1IIiIIIii . elp_name
   o0O0oO00 = "" if lisp_elp_list . has_key ( IiIIO0 ) else "(not configured)"
   if 58 - 58: OoooooooOO % iII111i . O0
   lprint ( "Policy set-elp-name '{}' {}" . format ( IiIIO0 , o0O0oO00 ) )
   if 93 - 93: I1Ii111
  if ( self . set_rle_name ) :
   I1IIiIIIii . rle_name = self . set_rle_name
   IiIIO0 = I1IIiIIIii . rle_name
   o0O0oO00 = "" if lisp_rle_list . has_key ( IiIIO0 ) else "(not configured)"
   if 3 - 3: OoO0O00 / IiII - oO0o / oO0o
   lprint ( "Policy set-rle-name '{}' {}" . format ( IiIIO0 , o0O0oO00 ) )
   if 50 - 50: II111iiii + OoOoOO00
  if ( self . set_json_name ) :
   I1IIiIIIii . json_name = self . set_json_name
   IiIIO0 = I1IIiIIIii . json_name
   o0O0oO00 = "" if lisp_json_list . has_key ( IiIIO0 ) else "(not configured)"
   if 17 - 17: ooOoO0o + I1ii11iIi11i
   lprint ( "Policy set-json-name '{}' {}" . format ( IiIIO0 , o0O0oO00 ) )
   if 34 - 34: Ii1I / II111iiii + OoOoOO00 . II111iiii + OoooooooOO * o0oOOo0O0Ooo
  return ( I1IIiIIIii )
  if 48 - 48: O0
  if 99 - 99: II111iiii * oO0o / I1ii11iIi11i - i1IIi
 def save_policy ( self ) :
  lisp_policies [ self . policy_name ] = self
  if 84 - 84: i11iIiiIii . OoooooooOO
  if 69 - 69: I1Ii111 * II111iiii % I1Ii111 * i11iIiiIii . ooOoO0o / Oo0Ooo
  if 5 - 5: Ii1I
class lisp_pubsub ( ) :
 def __init__ ( self , itr , port , nonce , ttl , xtr_id ) :
  self . itr = itr
  self . port = port
  self . nonce = nonce
  self . uptime = lisp_get_timestamp ( )
  self . ttl = ttl
  self . xtr_id = xtr_id
  self . map_notify_count = 0
  if 19 - 19: oO0o
  if 61 - 61: OoOoOO00 + iIii1I11I1II1 / I1ii11iIi11i - i1IIi
 def add ( self , eid_prefix ) :
  oOoooOOO0o0 = self . ttl
  ooOOoo0 = eid_prefix . print_prefix ( )
  if ( lisp_pubsub_cache . has_key ( ooOOoo0 ) == False ) :
   lisp_pubsub_cache [ ooOOoo0 ] = { }
   if 11 - 11: oO0o * o0oOOo0O0Ooo . I1IiiI
  Ooo = lisp_pubsub_cache [ ooOOoo0 ]
  if 12 - 12: I1IiiI % OoO0O00 / I1Ii111 / O0 % o0oOOo0O0Ooo
  iI1I1 = "Add"
  if ( Ooo . has_key ( self . xtr_id ) ) :
   iI1I1 = "Replace"
   del ( Ooo [ self . xtr_id ] )
   if 61 - 61: i1IIi / Ii1I . OoOoOO00 + i11iIiiIii
  Ooo [ self . xtr_id ] = self
  if 69 - 69: i11iIiiIii - iIii1I11I1II1
  ooOOoo0 = green ( ooOOoo0 , False )
  I11iiII1I1111 = red ( self . itr . print_address_no_iid ( ) , False )
  I1II = "0x" + lisp_hex_string ( self . xtr_id )
  lprint ( "{} pubsub state {} for {}, xtr-id: {}, ttl {}" . format ( iI1I1 , ooOOoo0 ,
 I11iiII1I1111 , I1II , oOoooOOO0o0 ) )
  if 40 - 40: I1IiiI / oO0o + ooOoO0o
  if 100 - 100: OoOoOO00 % iII111i * ooOoO0o . O0
 def delete ( self , eid_prefix ) :
  ooOOoo0 = eid_prefix . print_prefix ( )
  I11iiII1I1111 = red ( self . itr . print_address_no_iid ( ) , False )
  I1II = "0x" + lisp_hex_string ( self . xtr_id )
  if ( lisp_pubsub_cache . has_key ( ooOOoo0 ) ) :
   Ooo = lisp_pubsub_cache [ ooOOoo0 ]
   if ( Ooo . has_key ( self . xtr_id ) ) :
    Ooo . pop ( self . xtr_id )
    lprint ( "Remove pubsub state {} for {}, xtr-id: {}" . format ( ooOOoo0 ,
 I11iiII1I1111 , I1II ) )
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
    if 15 - 15: i1IIi . II111iiii * OoOoOO00 / Oo0Ooo
    if 99 - 99: iII111i - o0oOOo0O0Ooo / O0
    if 97 - 97: iIii1I11I1II1 * I1Ii111
    if 39 - 39: I1Ii111 . II111iiii
class lisp_trace ( ) :
 def __init__ ( self ) :
  self . nonce = lisp_get_control_nonce ( )
  self . packet_json = [ ]
  self . local_rloc = None
  self . local_port = None
  self . lisp_socket = None
  if 94 - 94: OoO0O00 - OoO0O00 + iIii1I11I1II1 + O0 * oO0o
  if 9 - 9: Ii1I * Oo0Ooo / oO0o / Ii1I
 def print_trace ( self ) :
  IiiI = self . packet_json
  lprint ( "LISP-Trace JSON: '{}'" . format ( IiiI ) )
  if 34 - 34: I1IiiI
  if 56 - 56: Ii1I
 def encode ( self ) :
  iII = socket . htonl ( 0x90000000 )
  IiiiIi1iiii11 = struct . pack ( "II" , iII , 0 )
  IiiiIi1iiii11 += struct . pack ( "Q" , self . nonce )
  IiiiIi1iiii11 += json . dumps ( self . packet_json )
  return ( IiiiIi1iiii11 )
  if 71 - 71: O0 / i1IIi
  if 20 - 20: OOooOOo . iIii1I11I1II1 - I1Ii111 . i1IIi
 def decode ( self , packet ) :
  i1I1iii1I11II = "I"
  Iiiii = struct . calcsize ( i1I1iii1I11II )
  if ( len ( packet ) < Iiiii ) : return ( False )
  iII = struct . unpack ( i1I1iii1I11II , packet [ : Iiiii ] ) [ 0 ]
  packet = packet [ Iiiii : : ]
  iII = socket . ntohl ( iII )
  if ( ( iII & 0xff000000 ) != 0x90000000 ) : return ( False )
  if 82 - 82: oO0o * i11iIiiIii % o0oOOo0O0Ooo % IiII - I11i - OoO0O00
  if ( len ( packet ) < Iiiii ) : return ( False )
  IiiIIi1 = struct . unpack ( i1I1iii1I11II , packet [ : Iiiii ] ) [ 0 ]
  packet = packet [ Iiiii : : ]
  if 24 - 24: oO0o . II111iiii + OoO0O00 * I1ii11iIi11i / oO0o
  IiiIIi1 = socket . ntohl ( IiiIIi1 )
  o0OO0O0 = IiiIIi1 >> 24
  iIIi1i1i1 = ( IiiIIi1 >> 16 ) & 0xff
  iI11i1i1ii = ( IiiIIi1 >> 8 ) & 0xff
  Oo0o0OoO00 = IiiIIi1 & 0xff
  self . local_rloc = "{}.{}.{}.{}" . format ( o0OO0O0 , iIIi1i1i1 , iI11i1i1ii , Oo0o0OoO00 )
  self . local_port = str ( iII & 0xffff )
  if 94 - 94: Oo0Ooo
  i1I1iii1I11II = "Q"
  Iiiii = struct . calcsize ( i1I1iii1I11II )
  if ( len ( packet ) < Iiiii ) : return ( False )
  self . nonce = struct . unpack ( i1I1iii1I11II , packet [ : Iiiii ] ) [ 0 ]
  packet = packet [ Iiiii : : ]
  if ( len ( packet ) == 0 ) : return ( True )
  if 33 - 33: oO0o / ooOoO0o
  try :
   self . packet_json = json . loads ( packet )
  except :
   return ( False )
   if 92 - 92: O0 . Oo0Ooo - Ii1I * I1IiiI * Oo0Ooo * iII111i
  return ( True )
  if 78 - 78: Ii1I * iIii1I11I1II1 - Ii1I - I1ii11iIi11i * I1ii11iIi11i
  if 44 - 44: o0oOOo0O0Ooo
 def myeid ( self , eid ) :
  return ( lisp_is_myeid ( eid ) )
  if 1 - 1: OoooooooOO / i11iIiiIii . o0oOOo0O0Ooo
  if 78 - 78: OOooOOo * O0 * II111iiii % OoOoOO00
 def return_to_sender ( self , lisp_socket , rts_rloc , packet ) :
  I1IIiIIIii , Oo0O00O = self . rtr_cache_nat_trace_find ( rts_rloc )
  if ( I1IIiIIIii == None ) :
   I1IIiIIIii , Oo0O00O = rts_rloc . split ( ":" )
   Oo0O00O = int ( Oo0O00O )
   lprint ( "Send LISP-Trace to address {}:{}" . format ( I1IIiIIIii , Oo0O00O ) )
  else :
   lprint ( "Send LISP-Trace to translated address {}:{}" . format ( I1IIiIIIii ,
 Oo0O00O ) )
   if 12 - 12: Oo0Ooo . o0oOOo0O0Ooo - i1IIi - oO0o % IiII . I11i
   if 17 - 17: i1IIi % OoO0O00 + i11iIiiIii % I1Ii111 * ooOoO0o . I1ii11iIi11i
  if ( lisp_socket == None ) :
   IiII1iiI = socket . socket ( socket . AF_INET , socket . SOCK_DGRAM )
   IiII1iiI . bind ( ( "0.0.0.0" , LISP_TRACE_PORT ) )
   IiII1iiI . sendto ( packet , ( I1IIiIIIii , Oo0O00O ) )
   IiII1iiI . close ( )
  else :
   lisp_socket . sendto ( packet , ( I1IIiIIIii , Oo0O00O ) )
   if 64 - 64: O0 - iII111i
   if 82 - 82: O0
   if 37 - 37: I1Ii111
 def packet_length ( self ) :
  o0oOo00 = 8 ; O0oOo0O0O = 4 + 4 + 8
  return ( o0oOo00 + O0oOo0O0O + len ( json . dumps ( self . packet_json ) ) )
  if 68 - 68: OoO0O00 * OOooOOo * ooOoO0o / ooOoO0o . O0 + I11i
  if 79 - 79: iIii1I11I1II1 / I1IiiI / OoooooooOO % IiII . OoOoOO00
 def rtr_cache_nat_trace ( self , translated_rloc , translated_port ) :
  Oo000O000 = self . local_rloc + ":" + self . local_port
  i11II = ( translated_rloc , translated_port )
  lisp_rtr_nat_trace_cache [ Oo000O000 ] = i11II
  lprint ( "Cache NAT Trace addresses {} -> {}" . format ( Oo000O000 , i11II ) )
  if 70 - 70: OoOoOO00 + OoooooooOO + iIii1I11I1II1 / Ii1I
  if 92 - 92: II111iiii - IiII / II111iiii
 def rtr_cache_nat_trace_find ( self , local_rloc_and_port ) :
  Oo000O000 = local_rloc_and_port
  try : i11II = lisp_rtr_nat_trace_cache [ Oo000O000 ]
  except : i11II = ( None , None )
  return ( i11II )
  if 23 - 23: Ii1I * II111iiii - I1ii11iIi11i
  if 86 - 86: ooOoO0o . OoO0O00 + I1Ii111 - I11i % i11iIiiIii / OoOoOO00
  if 47 - 47: IiII
  if 32 - 32: i1IIi / iIii1I11I1II1 / iII111i
  if 11 - 11: I1ii11iIi11i - iIii1I11I1II1
  if 15 - 15: o0oOOo0O0Ooo + OoooooooOO
  if 68 - 68: ooOoO0o / I1Ii111 * OoO0O00 + ooOoO0o / iIii1I11I1II1 . iII111i
  if 91 - 91: OoO0O00
  if 8 - 8: oO0o
  if 96 - 96: IiII
  if 37 - 37: Ii1I % i11iIiiIii + iIii1I11I1II1 % Oo0Ooo - iIii1I11I1II1
def lisp_get_map_server ( address ) :
 for ii1iOo in lisp_map_servers_list . values ( ) :
  if ( ii1iOo . map_server . is_exact_match ( address ) ) : return ( ii1iOo )
  if 26 - 26: o0oOOo0O0Ooo . i1IIi
 return ( None )
 if 62 - 62: IiII * I1ii11iIi11i % iIii1I11I1II1 / II111iiii - OoO0O00
 if 52 - 52: iII111i . I11i - I11i + oO0o + iIii1I11I1II1
 if 83 - 83: I11i * iIii1I11I1II1 + OoOoOO00
 if 81 - 81: ooOoO0o * OOooOOo / OoO0O00 + I1ii11iIi11i % I1Ii111
 if 37 - 37: i11iIiiIii - OoooooooOO - OoOoOO00 * oO0o / Ii1I
 if 100 - 100: II111iiii / Oo0Ooo / iII111i / OOooOOo
 if 100 - 100: iIii1I11I1II1
def lisp_get_any_map_server ( ) :
 for ii1iOo in lisp_map_servers_list . values ( ) : return ( ii1iOo )
 return ( None )
 if 50 - 50: I1Ii111 / ooOoO0o * I11i
 if 53 - 53: II111iiii . IiII
 if 5 - 5: i1IIi % IiII
 if 16 - 16: ooOoO0o - iII111i % Ii1I . OoOoOO00
 if 56 - 56: i11iIiiIii % i11iIiiIii % OoooooooOO . Ii1I . iII111i + I11i
 if 64 - 64: O0
 if 37 - 37: o0oOOo0O0Ooo / O0
 if 58 - 58: I1Ii111 + OoooooooOO + iIii1I11I1II1
 if 13 - 13: o0oOOo0O0Ooo . I11i / O0
 if 39 - 39: I11i + oO0o + ooOoO0o % ooOoO0o - I1IiiI % Oo0Ooo
def lisp_get_map_resolver ( address , eid ) :
 if ( address != None ) :
  IiiIIi1 = address . print_address ( )
  I1I1iiii111II = None
  for Oo000O000 in lisp_map_resolvers_list :
   if ( Oo000O000 . find ( IiiIIi1 ) == - 1 ) : continue
   I1I1iiii111II = lisp_map_resolvers_list [ Oo000O000 ]
   if 9 - 9: IiII / iII111i * II111iiii + O0 % Oo0Ooo / i1IIi
  return ( I1I1iiii111II )
  if 45 - 45: OoOoOO00 % i11iIiiIii . I1IiiI - O0 * i1IIi - I1IiiI
  if 48 - 48: IiII / iIii1I11I1II1
  if 20 - 20: oO0o / OoooooooOO
  if 95 - 95: Oo0Ooo . i11iIiiIii
  if 50 - 50: iII111i . i11iIiiIii - i1IIi
  if 24 - 24: i11iIiiIii % iII111i . oO0o
  if 44 - 44: II111iiii - OoO0O00 + i11iIiiIii
 if ( eid == "" ) :
  IIi11i1iIi = ""
 elif ( eid == None ) :
  IIi11i1iIi = "all"
 else :
  ooOOo0ooo = lisp_db_for_lookups . lookup_cache ( eid , False )
  IIi11i1iIi = "all" if ooOOo0ooo == None else ooOOo0ooo . use_mr_name
  if 62 - 62: oO0o - I1ii11iIi11i
  if 16 - 16: I1IiiI . OoO0O00 * Ii1I / oO0o
 i1I1iIiii = None
 for I1I1iiii111II in lisp_map_resolvers_list . values ( ) :
  if ( IIi11i1iIi == "" ) : return ( I1I1iiii111II )
  if ( I1I1iiii111II . mr_name != IIi11i1iIi ) : continue
  if ( i1I1iIiii == None or I1I1iiii111II . last_used < i1I1iIiii . last_used ) : i1I1iIiii = I1I1iiii111II
  if 65 - 65: ooOoO0o + I1ii11iIi11i * I1Ii111 . i1IIi * i1IIi
 return ( i1I1iIiii )
 if 33 - 33: II111iiii - OoooooooOO / II111iiii % Oo0Ooo / o0oOOo0O0Ooo
 if 41 - 41: I1Ii111 / IiII % OoO0O00 - iIii1I11I1II1
 if 98 - 98: OoOoOO00 + i11iIiiIii - iII111i + II111iiii
 if 10 - 10: ooOoO0o * i11iIiiIii . o0oOOo0O0Ooo % ooOoO0o
 if 14 - 14: i11iIiiIii . o0oOOo0O0Ooo % OoooooooOO
 if 15 - 15: I11i - OoOoOO00 . OoOoOO00 * iII111i - Ii1I . i11iIiiIii
 if 68 - 68: iII111i
 if 68 - 68: I1Ii111 - OoO0O00 % OoO0O00 % OOooOOo - OoO0O00
def lisp_get_decent_map_resolver ( eid ) :
 ooo = lisp_get_decent_index ( eid )
 iiIiII = str ( ooo ) + "." + lisp_decent_dns_suffix
 if 7 - 7: Ii1I . o0oOOo0O0Ooo * OoooooooOO - Ii1I * II111iiii % I1Ii111
 lprint ( "Use LISP-Decent map-resolver {} for EID {}" . format ( bold ( iiIiII , False ) , eid . print_prefix ( ) ) )
 if 82 - 82: OoOoOO00 - OoOoOO00 + iIii1I11I1II1 + o0oOOo0O0Ooo + IiII - o0oOOo0O0Ooo
 if 65 - 65: I1Ii111 + OOooOOo
 i1I1iIiii = None
 for I1I1iiii111II in lisp_map_resolvers_list . values ( ) :
  if ( iiIiII != I1I1iiii111II . dns_name ) : continue
  if ( i1I1iIiii == None or I1I1iiii111II . last_used < i1I1iIiii . last_used ) : i1I1iIiii = I1I1iiii111II
  if 97 - 97: oO0o % OoOoOO00 * oO0o % II111iiii + iIii1I11I1II1
 return ( i1I1iIiii )
 if 11 - 11: ooOoO0o . o0oOOo0O0Ooo
 if 94 - 94: ooOoO0o . oO0o * OoooooooOO % oO0o
 if 77 - 77: ooOoO0o % I1IiiI
 if 26 - 26: o0oOOo0O0Ooo
 if 72 - 72: I1IiiI
 if 90 - 90: ooOoO0o
 if 67 - 67: iIii1I11I1II1 + i1IIi * I1IiiI * OoooooooOO
def lisp_ipv4_input ( packet ) :
 if 23 - 23: IiII
 if 32 - 32: OoOoOO00 - iII111i % oO0o / I1ii11iIi11i - o0oOOo0O0Ooo
 if 52 - 52: Ii1I / OoooooooOO % i11iIiiIii + iII111i
 if 59 - 59: Ii1I / o0oOOo0O0Ooo / oO0o + iII111i * I1ii11iIi11i - o0oOOo0O0Ooo
 if ( ord ( packet [ 9 ] ) == 2 ) : return ( [ True , packet ] )
 if 70 - 70: O0 / I1ii11iIi11i + ooOoO0o . OoO0O00 - OoO0O00 / i11iIiiIii
 if 1 - 1: iIii1I11I1II1 % I1ii11iIi11i
 if 49 - 49: iII111i + o0oOOo0O0Ooo % I1ii11iIi11i . O0 % OoooooooOO . o0oOOo0O0Ooo
 if 3 - 3: i11iIiiIii - i1IIi * o0oOOo0O0Ooo / OoOoOO00 % Oo0Ooo
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
   if 65 - 65: OoooooooOO + iII111i - i11iIiiIii - IiII + oO0o
   if 67 - 67: i1IIi * I1Ii111 * O0
   if 16 - 16: OoO0O00 + iII111i + i1IIi + I1ii11iIi11i - I1IiiI
   if 88 - 88: oO0o % iII111i + I1ii11iIi11i - II111iiii . I11i
   if 18 - 18: I1ii11iIi11i - i1IIi - IiII * II111iiii % I1Ii111 . II111iiii
   if 80 - 80: oO0o + OoO0O00 + o0oOOo0O0Ooo . OoOoOO00
   if 75 - 75: i11iIiiIii
 oOoooOOO0o0 = struct . unpack ( "B" , packet [ 8 : 9 ] ) [ 0 ]
 if ( oOoooOOO0o0 == 0 ) :
  dprint ( "IPv4 packet arrived with ttl 0, packet discarded" )
  return ( [ False , None ] )
 elif ( oOoooOOO0o0 == 1 ) :
  dprint ( "IPv4 packet {}, packet discarded" . format ( bold ( "ttl expiry" , False ) ) )
  if 58 - 58: iII111i
  return ( [ False , None ] )
  if 48 - 48: OoO0O00 * OOooOOo / iII111i
  if 90 - 90: I1IiiI * i11iIiiIii . OOooOOo / o0oOOo0O0Ooo
 oOoooOOO0o0 -= 1
 packet = packet [ 0 : 8 ] + struct . pack ( "B" , oOoooOOO0o0 ) + packet [ 9 : : ]
 packet = packet [ 0 : 10 ] + struct . pack ( "H" , 0 ) + packet [ 12 : : ]
 packet = lisp_ip_checksum ( packet )
 return ( [ False , packet ] )
 if 82 - 82: Oo0Ooo
 if 50 - 50: I1Ii111 * OOooOOo * OoOoOO00 / OoooooooOO % iII111i
 if 80 - 80: I1Ii111
 if 35 - 35: Ii1I . O0 % i11iIiiIii * oO0o - OoooooooOO
 if 87 - 87: iII111i * ooOoO0o - OOooOOo . O0
 if 20 - 20: OoOoOO00 - IiII
 if 9 - 9: O0 . I11i % I1ii11iIi11i * oO0o - I1Ii111 - i1IIi
def lisp_ipv6_input ( packet ) :
 oo0OoO = packet . inner_dest
 packet = packet . packet
 if 66 - 66: II111iiii / Oo0Ooo
 if 93 - 93: iII111i + I11i * OoooooooOO . OoO0O00
 if 40 - 40: ooOoO0o * I1Ii111 + iII111i
 if 52 - 52: iII111i % I11i
 if 95 - 95: IiII + Ii1I / OoO0O00 - iII111i / I1IiiI
 oOoooOOO0o0 = struct . unpack ( "B" , packet [ 7 : 8 ] ) [ 0 ]
 if ( oOoooOOO0o0 == 0 ) :
  dprint ( "IPv6 packet arrived with hop-limit 0, packet discarded" )
  return ( None )
 elif ( oOoooOOO0o0 == 1 ) :
  dprint ( "IPv6 packet {}, packet discarded" . format ( bold ( "ttl expiry" , False ) ) )
  if 27 - 27: Oo0Ooo + i1IIi + i11iIiiIii . OoO0O00 . OoO0O00
  return ( None )
  if 56 - 56: I1Ii111 / OoO0O00 + o0oOOo0O0Ooo . OoooooooOO * Oo0Ooo
  if 14 - 14: OoO0O00
  if 21 - 21: II111iiii + i11iIiiIii + I11i % I1IiiI
  if 65 - 65: IiII + I1ii11iIi11i / iII111i / I1IiiI + Ii1I
  if 88 - 88: IiII % iIii1I11I1II1
 if ( oo0OoO . is_ipv6_link_local ( ) ) :
  dprint ( "Do not encapsulate IPv6 link-local packets" )
  return ( None )
  if 3 - 3: ooOoO0o / I1Ii111 % iIii1I11I1II1 % I11i * oO0o / iIii1I11I1II1
  if 75 - 75: i11iIiiIii . iII111i
 oOoooOOO0o0 -= 1
 packet = packet [ 0 : 7 ] + struct . pack ( "B" , oOoooOOO0o0 ) + packet [ 8 : : ]
 return ( packet )
 if 68 - 68: OOooOOo . I1ii11iIi11i % I1ii11iIi11i . i11iIiiIii
 if 45 - 45: oO0o % I1ii11iIi11i * I1Ii111
 if 21 - 21: O0 + i11iIiiIii
 if 72 - 72: OoOoOO00 * OoooooooOO % O0 / I1ii11iIi11i % Ii1I - I11i
 if 65 - 65: iIii1I11I1II1 + II111iiii * OoO0O00 * i11iIiiIii / IiII
 if 15 - 15: OoOoOO00 % O0 - OOooOOo - oO0o . iII111i . OoO0O00
 if 52 - 52: II111iiii * o0oOOo0O0Ooo
 if 95 - 95: I1Ii111 - OoooooooOO
def lisp_mac_input ( packet ) :
 return ( packet )
 if 99 - 99: OoooooooOO % IiII . I11i + OoooooooOO
 if 57 - 57: Ii1I / I1IiiI * i1IIi
 if 21 - 21: I11i . O0 * OoooooooOO + ooOoO0o * oO0o % i11iIiiIii
 if 30 - 30: ooOoO0o * I1Ii111 + OoO0O00
 if 30 - 30: Ii1I / iII111i * Ii1I
 if 11 - 11: OoOoOO00 - OoOoOO00 % oO0o
 if 3 - 3: I1IiiI - OoooooooOO % iIii1I11I1II1 + I1Ii111 + OoOoOO00
 if 71 - 71: i1IIi % O0 % ooOoO0o
 if 24 - 24: O0
def lisp_rate_limit_map_request ( dest ) :
 i1iiI11IiIi1 = lisp_get_timestamp ( )
 if 88 - 88: OoooooooOO / Oo0Ooo / oO0o
 if 99 - 99: I1Ii111 % OoOoOO00 % IiII - Ii1I
 if 79 - 79: ooOoO0o + Oo0Ooo
 if 80 - 80: OoOoOO00 % OoO0O00 . OoO0O00 * OoO0O00 * O0
 oO000o0Oo00 = i1iiI11IiIi1 - lisp_no_map_request_rate_limit
 if ( oO000o0Oo00 < LISP_NO_MAP_REQUEST_RATE_LIMIT_TIME ) :
  i1i = int ( LISP_NO_MAP_REQUEST_RATE_LIMIT_TIME - oO000o0Oo00 )
  dprint ( "No Rate-Limit Mode for another {} secs" . format ( i1i ) )
  return ( False )
  if 18 - 18: II111iiii . o0oOOo0O0Ooo + OoO0O00
  if 69 - 69: OoO0O00 . ooOoO0o * ooOoO0o * iIii1I11I1II1
  if 8 - 8: iII111i . oO0o . OOooOOo + iII111i . Ii1I
  if 46 - 46: OoO0O00
  if 21 - 21: iIii1I11I1II1 - iII111i
 if ( lisp_last_map_request_sent == None ) : return ( False )
 oO000o0Oo00 = i1iiI11IiIi1 - lisp_last_map_request_sent
 ii1i1iiI1 = ( oO000o0Oo00 < LISP_MAP_REQUEST_RATE_LIMIT )
 if 15 - 15: O0 + iII111i + i11iIiiIii
 if ( ii1i1iiI1 ) :
  dprint ( "Rate-limiting Map-Request for {}, sent {} secs ago" . format ( green ( dest . print_address ( ) , False ) , round ( oO000o0Oo00 , 3 ) ) )
  if 31 - 31: iIii1I11I1II1 * iIii1I11I1II1 . I11i
  if 52 - 52: i11iIiiIii / oO0o / IiII
 return ( ii1i1iiI1 )
 if 84 - 84: I11i . oO0o + ooOoO0o
 if 75 - 75: I1Ii111
 if 97 - 97: ooOoO0o % Oo0Ooo . o0oOOo0O0Ooo
 if 22 - 22: O0 % I11i + OoO0O00 - iII111i + I1IiiI . O0
 if 73 - 73: ooOoO0o + O0 - I11i . I1IiiI + OOooOOo
 if 36 - 36: I11i % OoO0O00 * OoOoOO00 - I1Ii111
 if 16 - 16: ooOoO0o % OOooOOo . OoO0O00 % II111iiii . iIii1I11I1II1
def lisp_send_map_request ( lisp_sockets , lisp_ephem_port , seid , deid , rloc ) :
 global lisp_last_map_request_sent
 if 21 - 21: oO0o + II111iiii / OoOoOO00 * I11i
 if 90 - 90: OoOoOO00 % OoOoOO00 + I11i
 if 70 - 70: I1IiiI . ooOoO0o / I11i / OoO0O00
 if 40 - 40: oO0o % iIii1I11I1II1 * iIii1I11I1II1 / Oo0Ooo * OoO0O00
 if 61 - 61: OOooOOo
 if 80 - 80: I1ii11iIi11i
 iI111IOoo = iIi11iiI11 = None
 if ( rloc ) :
  iI111IOoo = rloc . rloc
  iIi11iiI11 = rloc . translated_port if lisp_i_am_rtr else LISP_DATA_PORT
  if 93 - 93: I1Ii111 . o0oOOo0O0Ooo
  if 96 - 96: ooOoO0o - o0oOOo0O0Ooo % O0 * Ii1I . OoOoOO00
  if 80 - 80: I1IiiI
  if 31 - 31: I1Ii111 + o0oOOo0O0Ooo . I1IiiI + I11i . oO0o
  if 50 - 50: Ii1I . OOooOOo
 oOOOoOo0oo0O , IiiiI1i111 , OoO0o0OOOO = lisp_myrlocs
 if ( oOOOoOo0oo0O == None ) :
  lprint ( "Suppress sending Map-Request, IPv4 RLOC not found" )
  return
  if 6 - 6: OoooooooOO % ooOoO0o % OoO0O00 * IiII
 if ( IiiiI1i111 == None and iI111IOoo != None and iI111IOoo . is_ipv6 ( ) ) :
  lprint ( "Suppress sending Map-Request, IPv6 RLOC not found" )
  return
  if 62 - 62: i1IIi . I11i / I11i
  if 90 - 90: O0 * OOooOOo / oO0o . Oo0Ooo * I11i
 o0OOo0 = lisp_map_request ( )
 o0OOo0 . record_count = 1
 o0OOo0 . nonce = lisp_get_control_nonce ( )
 o0OOo0 . rloc_probe = ( iI111IOoo != None )
 if 93 - 93: oO0o / ooOoO0o - I1Ii111
 if 70 - 70: OOooOOo / Ii1I - ooOoO0o + OoooooooOO / OoO0O00 - i11iIiiIii
 if 26 - 26: O0 + Oo0Ooo
 if 30 - 30: IiII
 if 6 - 6: O0
 if 92 - 92: I11i
 if 76 - 76: I11i / iIii1I11I1II1 - i11iIiiIii / O0 / O0
 if ( rloc ) : rloc . last_rloc_probe_nonce = o0OOo0 . nonce
 if 19 - 19: Ii1I . I1IiiI - i1IIi * ooOoO0o . iIii1I11I1II1
 oOOooo000OoO = deid . is_multicast_address ( )
 if ( oOOooo000OoO ) :
  o0OOo0 . target_eid = seid
  o0OOo0 . target_group = deid
 else :
  o0OOo0 . target_eid = deid
  if 87 - 87: ooOoO0o % I1ii11iIi11i . I1IiiI
  if 42 - 42: iII111i % i11iIiiIii % o0oOOo0O0Ooo . O0 % iII111i
  if 72 - 72: Oo0Ooo . Oo0Ooo . IiII . Oo0Ooo
  if 80 - 80: I1Ii111 + IiII + O0 - I1Ii111 . iIii1I11I1II1
  if 53 - 53: OoO0O00 / i11iIiiIii * I1Ii111
  if 62 - 62: oO0o / Oo0Ooo / IiII + I11i * ooOoO0o
  if 84 - 84: ooOoO0o + OoOoOO00 * I1ii11iIi11i % OoooooooOO . O0
  if 27 - 27: OoO0O00 * OoooooooOO - II111iiii / o0oOOo0O0Ooo
  if 76 - 76: I11i % I1Ii111 % iII111i + IiII * iII111i + OoOoOO00
 if ( o0OOo0 . rloc_probe == False ) :
  ooOOo0ooo = lisp_get_signature_eid ( )
  if ( ooOOo0ooo ) :
   o0OOo0 . signature_eid . copy_address ( ooOOo0ooo . eid )
   o0OOo0 . privkey_filename = "./lisp-sig.pem"
   if 83 - 83: OOooOOo . ooOoO0o / IiII
   if 80 - 80: I1Ii111 . I11i - I11i + I1ii11iIi11i
   if 42 - 42: I11i / IiII % O0 - Oo0Ooo
   if 33 - 33: I1Ii111
   if 1 - 1: IiII - iIii1I11I1II1 % OoooooooOO
   if 1 - 1: o0oOOo0O0Ooo - i11iIiiIii + I11i
 if ( seid == None or oOOooo000OoO ) :
  o0OOo0 . source_eid . afi = LISP_AFI_NONE
 else :
  o0OOo0 . source_eid = seid
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
  if 1 - 1: o0oOOo0O0Ooo . oO0o * i11iIiiIii * IiII - OoO0O00 - OoooooooOO
  if 29 - 29: iIii1I11I1II1 + OoO0O00 * II111iiii * Ii1I * iII111i . O0
 if ( iI111IOoo != None and lisp_nat_traversal and lisp_i_am_rtr == False ) :
  if ( iI111IOoo . is_private_address ( ) == False ) :
   oOOOoOo0oo0O = lisp_get_any_translated_rloc ( )
   if 6 - 6: I1IiiI - OoOoOO00
  if ( oOOOoOo0oo0O == None ) :
   lprint ( "Suppress sending Map-Request, translated RLOC not found" )
   return
   if 63 - 63: OOooOOo - oO0o * I1IiiI
   if 60 - 60: II111iiii - Oo0Ooo
   if 43 - 43: I1IiiI - IiII - OOooOOo
   if 19 - 19: I1Ii111 / I1Ii111 - i1IIi
   if 99 - 99: O0
   if 37 - 37: iIii1I11I1II1 / I1Ii111 + OoO0O00
   if 85 - 85: ooOoO0o / I1IiiI
   if 7 - 7: Oo0Ooo - iIii1I11I1II1 / I1ii11iIi11i * I1IiiI + Ii1I
 if ( iI111IOoo == None or iI111IOoo . is_ipv4 ( ) ) :
  if ( lisp_nat_traversal and iI111IOoo == None ) :
   ooOO0o0oO = lisp_get_any_translated_rloc ( )
   if ( ooOO0o0oO != None ) : oOOOoOo0oo0O = ooOO0o0oO
   if 12 - 12: I1Ii111 / I11i / Ii1I
  o0OOo0 . itr_rlocs . append ( oOOOoOo0oo0O )
  if 95 - 95: iIii1I11I1II1 . Ii1I % oO0o - I11i % IiII
 if ( iI111IOoo == None or iI111IOoo . is_ipv6 ( ) ) :
  if ( IiiiI1i111 == None or IiiiI1i111 . is_ipv6_link_local ( ) ) :
   IiiiI1i111 = None
  else :
   o0OOo0 . itr_rloc_count = 1 if ( iI111IOoo == None ) else 0
   o0OOo0 . itr_rlocs . append ( IiiiI1i111 )
   if 42 - 42: OoOoOO00 + oO0o * i1IIi + i11iIiiIii
   if 25 - 25: Ii1I - Ii1I - I1ii11iIi11i / i1IIi . OoOoOO00 % Oo0Ooo
   if 76 - 76: I1Ii111 / OoOoOO00
   if 61 - 61: Oo0Ooo . i1IIi
   if 78 - 78: i11iIiiIii
   if 20 - 20: Ii1I
   if 100 - 100: OoooooooOO . I1Ii111
   if 32 - 32: iIii1I11I1II1 . iIii1I11I1II1 % II111iiii / Oo0Ooo . iIii1I11I1II1 . O0
   if 63 - 63: I1IiiI . iIii1I11I1II1 . Oo0Ooo % OOooOOo - iII111i + ooOoO0o
 if ( iI111IOoo != None and o0OOo0 . itr_rlocs != [ ] ) :
  o00O00oOO00 = o0OOo0 . itr_rlocs [ 0 ]
 else :
  if ( deid . is_ipv4 ( ) ) :
   o00O00oOO00 = oOOOoOo0oo0O
  elif ( deid . is_ipv6 ( ) ) :
   o00O00oOO00 = IiiiI1i111
  else :
   o00O00oOO00 = oOOOoOo0oo0O
   if 64 - 64: o0oOOo0O0Ooo / Ii1I % I1Ii111 % iII111i + OOooOOo * IiII
   if 87 - 87: I1ii11iIi11i . i1IIi - I11i + OoOoOO00 . O0
   if 37 - 37: IiII
   if 65 - 65: ooOoO0o * Ii1I / I1IiiI . i1IIi % ooOoO0o . OoooooooOO
   if 17 - 17: ooOoO0o / OoO0O00 / I1IiiI / OOooOOo % IiII
   if 88 - 88: i1IIi - OoOoOO00
 IiiiIi1iiii11 = o0OOo0 . encode ( iI111IOoo , iIi11iiI11 )
 o0OOo0 . print_map_request ( )
 if 66 - 66: OoooooooOO - OoooooooOO * I11i / II111iiii + oO0o / Ii1I
 if 7 - 7: Ii1I / iIii1I11I1II1
 if 36 - 36: iIii1I11I1II1 % i11iIiiIii
 if 35 - 35: Oo0Ooo + I1IiiI - O0 - I1Ii111
 if 64 - 64: i1IIi * OoOoOO00 / II111iiii * oO0o
 if 35 - 35: i1IIi - Ii1I - Ii1I . O0 % iII111i * iII111i
 if ( iI111IOoo != None ) :
  if ( rloc . is_rloc_translated ( ) ) :
   IIiiiiII = lisp_get_nat_info ( iI111IOoo , rloc . rloc_name )
   if 15 - 15: OoooooooOO . Ii1I * I1Ii111 . ooOoO0o % OoO0O00 * Oo0Ooo
   if 10 - 10: iII111i + i11iIiiIii . OOooOOo % iII111i - i1IIi
   if 10 - 10: iIii1I11I1II1 * i11iIiiIii - O0
   if 45 - 45: oO0o % OOooOOo - IiII + o0oOOo0O0Ooo + i11iIiiIii
   if ( IIiiiiII == None ) :
    O0OOOO0o0O = rloc . rloc . print_address_no_iid ( )
    i11ii = "gleaned-{}" . format ( O0OOOO0o0O )
    oo00ooOOOo0O = rloc . translated_port
    IIiiiiII = lisp_nat_info ( O0OOOO0o0O , i11ii , oo00ooOOOo0O )
    if 79 - 79: IiII % I1Ii111 . I1IiiI + O0 * oO0o * ooOoO0o
   lisp_encapsulate_rloc_probe ( lisp_sockets , iI111IOoo , IIiiiiII ,
 IiiiIi1iiii11 )
   return
   if 38 - 38: IiII
   if 78 - 78: Oo0Ooo * I1ii11iIi11i % OOooOOo / Oo0Ooo + I1ii11iIi11i * IiII
  oo0o00OO = iI111IOoo . print_address_no_iid ( )
  oo0OoO = lisp_convert_4to6 ( oo0o00OO )
  lisp_send ( lisp_sockets , oo0OoO , LISP_CTRL_PORT , IiiiIi1iiii11 )
  return
  if 2 - 2: Oo0Ooo - OoOoOO00
  if 22 - 22: OoO0O00 - oO0o - O0
  if 49 - 49: iIii1I11I1II1 + I1Ii111 / i11iIiiIii
  if 62 - 62: ooOoO0o . I1IiiI * i11iIiiIii
  if 2 - 2: i11iIiiIii
  if 86 - 86: I1Ii111 + o0oOOo0O0Ooo
 iiiO0OOOOo = None if lisp_i_am_rtr else seid
 if ( lisp_decent_pull_xtr_configured ( ) ) :
  I1I1iiii111II = lisp_get_decent_map_resolver ( deid )
 else :
  I1I1iiii111II = lisp_get_map_resolver ( None , iiiO0OOOOo )
  if 100 - 100: OoOoOO00 + OOooOOo
 if ( I1I1iiii111II == None ) :
  lprint ( "Cannot find Map-Resolver for source-EID {}" . format ( green ( seid . print_address ( ) , False ) ) )
  if 44 - 44: IiII % iII111i * iII111i + iII111i * i11iIiiIii - OoO0O00
  return
  if 89 - 89: I1ii11iIi11i - OoO0O00 / i11iIiiIii + ooOoO0o / OoOoOO00
 I1I1iiii111II . last_used = lisp_get_timestamp ( )
 I1I1iiii111II . map_requests_sent += 1
 if ( I1I1iiii111II . last_nonce == 0 ) : I1I1iiii111II . last_nonce = o0OOo0 . nonce
 if 15 - 15: II111iiii - IiII
 if 74 - 74: i1IIi * OoooooooOO . Oo0Ooo . I1IiiI / o0oOOo0O0Ooo . OoOoOO00
 if 50 - 50: I1ii11iIi11i / iIii1I11I1II1 - Oo0Ooo - i11iIiiIii % o0oOOo0O0Ooo - ooOoO0o
 if 92 - 92: OoooooooOO - I1ii11iIi11i . I11i / O0 % iII111i
 if ( seid == None ) : seid = o00O00oOO00
 lisp_send_ecm ( lisp_sockets , IiiiIi1iiii11 , seid , lisp_ephem_port , deid ,
 I1I1iiii111II . map_resolver )
 if 96 - 96: I1IiiI . oO0o % O0
 if 19 - 19: iIii1I11I1II1 + I1Ii111 / OoooooooOO % OOooOOo - i1IIi + I11i
 if 87 - 87: OoooooooOO
 if 97 - 97: ooOoO0o * IiII / iIii1I11I1II1
 lisp_last_map_request_sent = lisp_get_timestamp ( )
 if 65 - 65: i1IIi - i11iIiiIii + oO0o % I1IiiI - OoO0O00 % ooOoO0o
 if 23 - 23: o0oOOo0O0Ooo . o0oOOo0O0Ooo - iIii1I11I1II1 / o0oOOo0O0Ooo
 if 65 - 65: I1Ii111 + I1Ii111 . I1ii11iIi11i . OoOoOO00 % o0oOOo0O0Ooo * o0oOOo0O0Ooo
 if 2 - 2: oO0o % iII111i + I1ii11iIi11i / II111iiii * I1ii11iIi11i
 I1I1iiii111II . resolve_dns_name ( )
 return
 if 45 - 45: II111iiii . iII111i
 if 55 - 55: ooOoO0o / iII111i / O0
 if 98 - 98: O0 % iII111i + II111iiii
 if 13 - 13: I1IiiI * oO0o - o0oOOo0O0Ooo
 if 23 - 23: iIii1I11I1II1 + oO0o . oO0o / o0oOOo0O0Ooo
 if 77 - 77: i1IIi * o0oOOo0O0Ooo * IiII
 if 24 - 24: i11iIiiIii / iIii1I11I1II1 / iII111i
 if 31 - 31: OOooOOo . iIii1I11I1II1 - oO0o
def lisp_send_info_request ( lisp_sockets , dest , port , device_name ) :
 if 36 - 36: O0
 if 30 - 30: i11iIiiIii * Oo0Ooo . IiII
 if 65 - 65: oO0o * IiII * OOooOOo / OoooooooOO % I11i / I1Ii111
 if 21 - 21: i1IIi * iII111i + OoO0O00
 I1iII = lisp_info ( )
 I1iII . nonce = lisp_get_control_nonce ( )
 if ( device_name ) : I1iII . hostname += "-" + device_name
 if 81 - 81: OOooOOo - OoooooooOO * iII111i / OOooOOo
 oo0o00OO = dest . print_address_no_iid ( )
 if 98 - 98: I11i . OOooOOo - OoO0O00 % O0 * O0
 if 91 - 91: I1IiiI % ooOoO0o * iII111i % OoOoOO00 . OoOoOO00 + OoOoOO00
 if 95 - 95: o0oOOo0O0Ooo % i1IIi
 if 14 - 14: iIii1I11I1II1 + iIii1I11I1II1
 if 74 - 74: OoOoOO00 . iIii1I11I1II1 + Ii1I + ooOoO0o % OoOoOO00
 if 37 - 37: i11iIiiIii + O0 + II111iiii
 if 13 - 13: OOooOOo / O0
 if 19 - 19: iIii1I11I1II1 + IiII * I11i * II111iiii + o0oOOo0O0Ooo + i11iIiiIii
 if 69 - 69: iIii1I11I1II1 . II111iiii
 if 36 - 36: I1IiiI * i1IIi + OoOoOO00
 if 63 - 63: OoOoOO00 - iII111i
 if 83 - 83: i1IIi / iII111i % ooOoO0o % i11iIiiIii + I1ii11iIi11i
 if 82 - 82: iIii1I11I1II1 / OOooOOo
 if 7 - 7: OoooooooOO
 if 71 - 71: OOooOOo * Oo0Ooo . Oo0Ooo % iIii1I11I1II1
 if 56 - 56: IiII * iIii1I11I1II1 - iIii1I11I1II1 . O0
 O00o0 = False
 if ( device_name ) :
  ooOoo000OoO0O = lisp_get_host_route_next_hop ( oo0o00OO )
  if 52 - 52: OoooooooOO - OoO0O00
  if 24 - 24: iII111i / Oo0Ooo - I1ii11iIi11i + o0oOOo0O0Ooo
  if 44 - 44: OoOoOO00 + I1IiiI . I1ii11iIi11i / i1IIi + II111iiii . Oo0Ooo
  if 39 - 39: o0oOOo0O0Ooo
  if 64 - 64: oO0o - i11iIiiIii
  if 62 - 62: OoooooooOO - OoooooooOO / OoO0O00 - II111iiii . iIii1I11I1II1
  if 2 - 2: O0 + o0oOOo0O0Ooo % OOooOOo . ooOoO0o % i1IIi
  if 21 - 21: OoOoOO00 / OoooooooOO + I1Ii111 - IiII
  if 62 - 62: Oo0Ooo % iII111i + OoooooooOO - I1ii11iIi11i % iII111i % iIii1I11I1II1
  if ( port == LISP_CTRL_PORT and ooOoo000OoO0O != None ) :
   while ( True ) :
    time . sleep ( .01 )
    ooOoo000OoO0O = lisp_get_host_route_next_hop ( oo0o00OO )
    if ( ooOoo000OoO0O == None ) : break
    if 54 - 54: IiII + OoOoOO00 / II111iiii % i11iIiiIii . I1Ii111
    if 69 - 69: i1IIi + ooOoO0o + Ii1I
    if 88 - 88: OoOoOO00 + iII111i % O0 + OOooOOo / OoooooooOO / OOooOOo
  O0o00o000 = lisp_get_default_route_next_hops ( )
  for OoO0o0OOOO , II11111Iii1I in O0o00o000 :
   if ( OoO0o0OOOO != device_name ) : continue
   if 70 - 70: o0oOOo0O0Ooo - O0 % I1ii11iIi11i
   if 28 - 28: I1Ii111 % iII111i
   if 18 - 18: OoOoOO00
   if 42 - 42: Ii1I . OOooOOo / O0 / i1IIi . i11iIiiIii
   if 62 - 62: OoOoOO00
   if 6 - 6: OoO0O00 * ooOoO0o . oO0o
   if ( ooOoo000OoO0O != II11111Iii1I ) :
    if ( ooOoo000OoO0O != None ) :
     lisp_install_host_route ( oo0o00OO , ooOoo000OoO0O , False )
     if 77 - 77: iIii1I11I1II1
    lisp_install_host_route ( oo0o00OO , II11111Iii1I , True )
    O00o0 = True
    if 96 - 96: iII111i * I1ii11iIi11i
   break
   if 77 - 77: i11iIiiIii / iIii1I11I1II1 . I1ii11iIi11i
   if 90 - 90: I1IiiI + I1IiiI % oO0o
   if 95 - 95: OOooOOo + OoooooooOO . i11iIiiIii * OoO0O00 * I1IiiI / I1Ii111
   if 5 - 5: Ii1I . oO0o / o0oOOo0O0Ooo - OoooooooOO
   if 67 - 67: I1Ii111 + i1IIi - OOooOOo + OoooooooOO / II111iiii - I1Ii111
   if 13 - 13: i11iIiiIii - O0 % OoOoOO00 + OOooOOo * ooOoO0o
 IiiiIi1iiii11 = I1iII . encode ( )
 I1iII . print_info ( )
 if 55 - 55: i1IIi - OOooOOo / I11i * Ii1I
 if 20 - 20: OoOoOO00 * iIii1I11I1II1 % O0 - i1IIi
 if 51 - 51: I1ii11iIi11i * Ii1I - oO0o / O0 * OoooooooOO
 if 12 - 12: i1IIi / iIii1I11I1II1 / O0 * OoO0O00
 IiI11 = "(for control)" if port == LISP_CTRL_PORT else "(for data)"
 IiI11 = bold ( IiI11 , False )
 oo00ooOOOo0O = bold ( "{}" . format ( port ) , False )
 OO0o = red ( oo0o00OO , False )
 I11ii1I111Ii = "RTR " if port == LISP_DATA_PORT else "MS "
 lprint ( "Send Info-Request to {}{}, port {} {}" . format ( I11ii1I111Ii , OO0o , oo00ooOOOo0O , IiI11 ) )
 if 77 - 77: I1Ii111 % oO0o - ooOoO0o / OOooOOo / OoOoOO00
 if 67 - 67: O0 % iII111i
 if 55 - 55: I1ii11iIi11i % OOooOOo - o0oOOo0O0Ooo - II111iiii
 if 52 - 52: I1Ii111
 if 34 - 34: II111iiii + iII111i / IiII
 if 47 - 47: OoO0O00
 if ( port == LISP_CTRL_PORT ) :
  lisp_send ( lisp_sockets , dest , LISP_CTRL_PORT , IiiiIi1iiii11 )
 else :
  O0ooOoO0 = lisp_data_header ( )
  O0ooOoO0 . instance_id ( 0xffffff )
  O0ooOoO0 = O0ooOoO0 . encode ( )
  if ( O0ooOoO0 ) :
   IiiiIi1iiii11 = O0ooOoO0 + IiiiIi1iiii11
   if 40 - 40: o0oOOo0O0Ooo / iII111i . o0oOOo0O0Ooo
   if 63 - 63: o0oOOo0O0Ooo * iIii1I11I1II1 * II111iiii . OoO0O00 - oO0o / OoOoOO00
   if 78 - 78: i11iIiiIii / OoO0O00 / i1IIi . i11iIiiIii
   if 100 - 100: II111iiii . IiII . I11i
   if 60 - 60: OoOoOO00 % OOooOOo * i1IIi
   if 3 - 3: OoooooooOO
   if 75 - 75: OoooooooOO * I1Ii111 * o0oOOo0O0Ooo + I1ii11iIi11i . iIii1I11I1II1 / O0
   if 23 - 23: oO0o - O0 * IiII + i11iIiiIii * Ii1I
   if 8 - 8: ooOoO0o / II111iiii . I1ii11iIi11i * ooOoO0o % oO0o
   lisp_send ( lisp_sockets , dest , LISP_DATA_PORT , IiiiIi1iiii11 )
   if 36 - 36: I1ii11iIi11i % OOooOOo - ooOoO0o - I11i + I1IiiI
   if 37 - 37: I1ii11iIi11i * IiII
   if 65 - 65: OOooOOo / O0 . I1ii11iIi11i % i1IIi % Oo0Ooo
   if 36 - 36: i11iIiiIii - OOooOOo + iII111i + iII111i * I11i * oO0o
   if 14 - 14: O0 - iII111i * I1Ii111 - I1IiiI + IiII
   if 46 - 46: OoooooooOO * OoO0O00 . I1Ii111
   if 95 - 95: ooOoO0o . I1ii11iIi11i . ooOoO0o / I1IiiI * OoOoOO00 . O0
 if ( O00o0 ) :
  lisp_install_host_route ( oo0o00OO , None , False )
  if ( ooOoo000OoO0O != None ) : lisp_install_host_route ( oo0o00OO , ooOoo000OoO0O , True )
  if 78 - 78: oO0o
 return
 if 33 - 33: oO0o + i1IIi
 if 32 - 32: iIii1I11I1II1
 if 71 - 71: Ii1I * I1IiiI
 if 62 - 62: II111iiii / I1IiiI . I1ii11iIi11i
 if 49 - 49: IiII / OoOoOO00 / O0 * i11iIiiIii
 if 47 - 47: i11iIiiIii + iII111i + i11iIiiIii
 if 66 - 66: o0oOOo0O0Ooo . I1IiiI + OoooooooOO . iII111i / OoooooooOO - IiII
def lisp_process_info_request ( lisp_sockets , packet , addr_str , sport , rtr_list ) :
 if 47 - 47: o0oOOo0O0Ooo / II111iiii * i11iIiiIii * OoO0O00 . iIii1I11I1II1
 if 34 - 34: I11i / o0oOOo0O0Ooo * OOooOOo * OOooOOo
 if 89 - 89: I1ii11iIi11i . OoooooooOO
 if 61 - 61: i1IIi + i11iIiiIii
 I1iII = lisp_info ( )
 packet = I1iII . decode ( packet )
 if ( packet == None ) : return
 I1iII . print_info ( )
 if 59 - 59: i11iIiiIii * OOooOOo + i1IIi * iIii1I11I1II1 + I11i
 if 97 - 97: OoO0O00 - I11i . OoooooooOO
 if 58 - 58: I1ii11iIi11i / II111iiii / i11iIiiIii
 if 27 - 27: iIii1I11I1II1 - O0 + OoOoOO00
 if 28 - 28: oO0o . IiII * iII111i % Oo0Ooo - OoO0O00 / I11i
 I1iII . info_reply = True
 I1iII . global_etr_rloc . store_address ( addr_str )
 I1iII . etr_port = sport
 if 67 - 67: i11iIiiIii + i11iIiiIii / ooOoO0o - o0oOOo0O0Ooo
 if 94 - 94: O0 + OoO0O00 / I1IiiI * II111iiii * i11iIiiIii
 if 55 - 55: OoooooooOO * O0 + i1IIi % I1IiiI
 if 10 - 10: II111iiii - Ii1I . I11i . O0 + Ii1I
 if 50 - 50: iIii1I11I1II1 / Ii1I . ooOoO0o / ooOoO0o * OoOoOO00 * iII111i
 if ( I1iII . hostname != None ) :
  I1iII . private_etr_rloc . afi = LISP_AFI_NAME
  I1iII . private_etr_rloc . store_address ( I1iII . hostname )
  if 15 - 15: o0oOOo0O0Ooo % II111iiii + I1IiiI
  if 21 - 21: I1ii11iIi11i - ooOoO0o
 if ( rtr_list != None ) : I1iII . rtr_list = rtr_list
 packet = I1iII . encode ( )
 I1iII . print_info ( )
 if 81 - 81: iII111i / i11iIiiIii / I1Ii111
 if 70 - 70: I1ii11iIi11i / i11iIiiIii
 if 90 - 90: II111iiii / OoOoOO00 . Ii1I . OoooooooOO
 if 76 - 76: OoooooooOO
 if 78 - 78: IiII % i11iIiiIii
 lprint ( "Send Info-Reply to {}" . format ( red ( addr_str , False ) ) )
 oo0OoO = lisp_convert_4to6 ( addr_str )
 lisp_send ( lisp_sockets , oo0OoO , sport , packet )
 if 23 - 23: iIii1I11I1II1 - o0oOOo0O0Ooo - Ii1I % OOooOOo
 if 100 - 100: oO0o . OoO0O00 . i11iIiiIii % II111iiii * IiII
 if 81 - 81: OOooOOo - OOooOOo + OoOoOO00
 if 19 - 19: o0oOOo0O0Ooo
 if 20 - 20: I1Ii111 + iIii1I11I1II1 % I1IiiI + ooOoO0o
 oOOo00oOO00o = lisp_info_source ( I1iII . hostname , addr_str , sport )
 oOOo00oOO00o . cache_address_for_info_source ( )
 return
 if 22 - 22: oO0o % IiII + O0 - IiII . OoOoOO00 . I1IiiI
 if 71 - 71: oO0o % i11iIiiIii + I1Ii111 . OoooooooOO * i1IIi
 if 85 - 85: II111iiii - Oo0Ooo . OoOoOO00 - i1IIi - I1ii11iIi11i
 if 24 - 24: ooOoO0o % ooOoO0o - I1ii11iIi11i - OoO0O00 % I1IiiI
 if 8 - 8: iIii1I11I1II1 - O0 - i11iIiiIii . O0
 if 35 - 35: Ii1I . II111iiii % OoOoOO00
 if 3 - 3: OOooOOo - OoOoOO00
 if 49 - 49: IiII / i11iIiiIii
def lisp_get_signature_eid ( ) :
 for ooOOo0ooo in lisp_db_list :
  if ( ooOOo0ooo . signature_eid ) : return ( ooOOo0ooo )
  if 84 - 84: iIii1I11I1II1 / i1IIi + OoOoOO00
 return ( None )
 if 40 - 40: Ii1I % OoO0O00
 if 93 - 93: iII111i . I1Ii111 . oO0o % o0oOOo0O0Ooo . Oo0Ooo
 if 51 - 51: OOooOOo * OoO0O00 * Oo0Ooo
 if 61 - 61: II111iiii / OoOoOO00 % II111iiii / I1ii11iIi11i % I1Ii111 - i1IIi
 if 26 - 26: Ii1I % IiII + I1IiiI
 if 30 - 30: I1Ii111 / iII111i
 if 100 - 100: I1Ii111 * i11iIiiIii - I1ii11iIi11i
 if 64 - 64: I1ii11iIi11i * I1IiiI * Ii1I
def lisp_get_any_translated_port ( ) :
 for ooOOo0ooo in lisp_db_list :
  for i1III111 in ooOOo0ooo . rloc_set :
   if ( i1III111 . translated_rloc . is_null ( ) ) : continue
   return ( i1III111 . translated_port )
   if 41 - 41: OoOoOO00 . OOooOOo / OoOoOO00 % iIii1I11I1II1
   if 47 - 47: ooOoO0o . i11iIiiIii / OoO0O00
 return ( None )
 if 48 - 48: O0
 if 89 - 89: i11iIiiIii % OoO0O00 . OoOoOO00 + Oo0Ooo + OoOoOO00
 if 53 - 53: Ii1I / OoOoOO00 % iII111i * OoooooooOO + Oo0Ooo
 if 70 - 70: OoO0O00 % OoO0O00 * OoooooooOO
 if 96 - 96: ooOoO0o * Ii1I + I11i + II111iiii * I1IiiI / iII111i
 if 40 - 40: OoooooooOO - I11i % OOooOOo - I1IiiI . I1IiiI + Ii1I
 if 97 - 97: OOooOOo . OoooooooOO . OOooOOo . i11iIiiIii
 if 71 - 71: oO0o + I1ii11iIi11i * I1ii11iIi11i
 if 79 - 79: oO0o
def lisp_get_any_translated_rloc ( ) :
 for ooOOo0ooo in lisp_db_list :
  for i1III111 in ooOOo0ooo . rloc_set :
   if ( i1III111 . translated_rloc . is_null ( ) ) : continue
   return ( i1III111 . translated_rloc )
   if 47 - 47: OoooooooOO - i1IIi * OOooOOo
   if 11 - 11: I11i / OOooOOo . o0oOOo0O0Ooo - O0 * OoooooooOO % iII111i
 return ( None )
 if 7 - 7: OoOoOO00 . IiII + OoooooooOO - I1Ii111 / oO0o
 if 32 - 32: iIii1I11I1II1 + I11i + OOooOOo - OoooooooOO + i11iIiiIii * o0oOOo0O0Ooo
 if 8 - 8: iII111i
 if 10 - 10: OoOoOO00 % I11i
 if 49 - 49: oO0o % ooOoO0o + II111iiii
 if 21 - 21: i1IIi + OoO0O00 . I1IiiI - Oo0Ooo
 if 99 - 99: OoOoOO00
def lisp_get_all_translated_rlocs ( ) :
 IIiiiI1IIi1iI1i = [ ]
 for ooOOo0ooo in lisp_db_list :
  for i1III111 in ooOOo0ooo . rloc_set :
   if ( i1III111 . is_rloc_translated ( ) == False ) : continue
   IiiIIi1 = i1III111 . translated_rloc . print_address_no_iid ( )
   IIiiiI1IIi1iI1i . append ( IiiIIi1 )
   if 91 - 91: i11iIiiIii
   if 62 - 62: I1IiiI % OoO0O00 * IiII
 return ( IIiiiI1IIi1iI1i )
 if 6 - 6: o0oOOo0O0Ooo + i11iIiiIii
 if 97 - 97: o0oOOo0O0Ooo % OoOoOO00 * O0 / iIii1I11I1II1 * OoO0O00 / i11iIiiIii
 if 1 - 1: OoooooooOO . Ii1I
 if 68 - 68: Ii1I
 if 98 - 98: iII111i
 if 33 - 33: OoO0O00 - ooOoO0o % O0 % iIii1I11I1II1 * iII111i - iII111i
 if 27 - 27: i11iIiiIii + I1ii11iIi11i + i1IIi
 if 67 - 67: o0oOOo0O0Ooo
def lisp_update_default_routes ( map_resolver , iid , rtr_list ) :
 I11I111Ii1II = ( os . getenv ( "LISP_RTR_BEHIND_NAT" ) != None )
 if 58 - 58: IiII % o0oOOo0O0Ooo + i1IIi
 iIi1I = { }
 for I1IIiIIIii in rtr_list :
  if ( I1IIiIIIii == None ) : continue
  IiiIIi1 = rtr_list [ I1IIiIIIii ]
  if ( I11I111Ii1II and IiiIIi1 . is_private_address ( ) ) : continue
  iIi1I [ I1IIiIIIii ] = IiiIIi1
  if 24 - 24: OoooooooOO - oO0o - Oo0Ooo - o0oOOo0O0Ooo
 rtr_list = iIi1I
 if 73 - 73: OoOoOO00 * OOooOOo / oO0o % Oo0Ooo
 oo0OOOoO00OoO = [ ]
 for O0ooo0 in [ LISP_AFI_IPV4 , LISP_AFI_IPV6 , LISP_AFI_MAC ] :
  if ( O0ooo0 == LISP_AFI_MAC and lisp_l2_overlay == False ) : break
  if 100 - 100: IiII / i11iIiiIii * O0
  if 93 - 93: iII111i - I11i . I1IiiI + I11i
  if 16 - 16: o0oOOo0O0Ooo . iII111i / OoOoOO00 / i11iIiiIii - o0oOOo0O0Ooo
  if 35 - 35: ooOoO0o / I1Ii111 / I1Ii111
  if 19 - 19: OoO0O00 % i11iIiiIii % iIii1I11I1II1
  IIII1 = lisp_address ( O0ooo0 , "" , 0 , iid )
  IIII1 . make_default_route ( IIII1 )
  o0o000Oo = lisp_map_cache . lookup_cache ( IIII1 , True )
  if ( o0o000Oo ) :
   if ( o0o000Oo . checkpoint_entry ) :
    lprint ( "Updating checkpoint entry for {}" . format ( green ( o0o000Oo . print_eid_tuple ( ) , False ) ) )
    if 100 - 100: OOooOOo . oO0o % ooOoO0o * ooOoO0o . I1Ii111 - oO0o
   elif ( o0o000Oo . do_rloc_sets_match ( rtr_list . values ( ) ) ) :
    continue
    if 33 - 33: Oo0Ooo . i1IIi - OoooooooOO
   o0o000Oo . delete_cache ( )
   if 14 - 14: I1Ii111 + Oo0Ooo
   if 35 - 35: i11iIiiIii * Ii1I
  oo0OOOoO00OoO . append ( [ IIII1 , "" ] )
  if 100 - 100: O0 . iII111i / iIii1I11I1II1
  if 47 - 47: ooOoO0o + OoOoOO00
  if 67 - 67: IiII - I1ii11iIi11i * i1IIi - ooOoO0o
  if 91 - 91: I11i
  IIi1iiIII11 = lisp_address ( O0ooo0 , "" , 0 , iid )
  IIi1iiIII11 . make_default_multicast_route ( IIi1iiIII11 )
  oOoo0 = lisp_map_cache . lookup_cache ( IIi1iiIII11 , True )
  if ( oOoo0 ) : oOoo0 = oOoo0 . source_cache . lookup_cache ( IIII1 , True )
  if ( oOoo0 ) : oOoo0 . delete_cache ( )
  if 88 - 88: OoooooooOO
  oo0OOOoO00OoO . append ( [ IIII1 , IIi1iiIII11 ] )
  if 73 - 73: ooOoO0o % iII111i * IiII - iIii1I11I1II1 + i1IIi + o0oOOo0O0Ooo
 if ( len ( oo0OOOoO00OoO ) == 0 ) : return
 if 63 - 63: iIii1I11I1II1
 if 88 - 88: OoooooooOO
 if 23 - 23: iII111i - IiII % i11iIiiIii
 if 81 - 81: OoooooooOO % OoOoOO00 / IiII / OoooooooOO + i1IIi - O0
 OoO0oOOooOO = [ ]
 for I11ii1I111Ii in rtr_list :
  o000Oo00o = rtr_list [ I11ii1I111Ii ]
  i1III111 = lisp_rloc ( )
  i1III111 . rloc . copy_address ( o000Oo00o )
  i1III111 . priority = 254
  i1III111 . mpriority = 255
  i1III111 . rloc_name = "RTR"
  OoO0oOOooOO . append ( i1III111 )
  if 78 - 78: OoO0O00 - ooOoO0o + Oo0Ooo % i1IIi % iIii1I11I1II1
  if 69 - 69: I11i % ooOoO0o
 for IIII1 in oo0OOOoO00OoO :
  o0o000Oo = lisp_mapping ( IIII1 [ 0 ] , IIII1 [ 1 ] , OoO0oOOooOO )
  o0o000Oo . mapping_source = map_resolver
  o0o000Oo . map_cache_ttl = LISP_MR_TTL * 60
  o0o000Oo . add_cache ( )
  lprint ( "Add {} to map-cache with RTR RLOC-set: {}" . format ( green ( o0o000Oo . print_eid_tuple ( ) , False ) , rtr_list . keys ( ) ) )
  if 58 - 58: I1IiiI . II111iiii + i11iIiiIii / OOooOOo . I1ii11iIi11i / I1IiiI
  OoO0oOOooOO = copy . deepcopy ( OoO0oOOooOO )
  if 23 - 23: iIii1I11I1II1 / Oo0Ooo - i11iIiiIii % o0oOOo0O0Ooo / OOooOOo - o0oOOo0O0Ooo
 return
 if 23 - 23: IiII + IiII . OOooOOo
 if 77 - 77: I1Ii111 * O0 - IiII
 if 21 - 21: Oo0Ooo % Oo0Ooo % Oo0Ooo
 if 15 - 15: I1IiiI + OoO0O00 . I1IiiI / OoO0O00 . o0oOOo0O0Ooo
 if 72 - 72: IiII + oO0o * o0oOOo0O0Ooo
 if 39 - 39: O0 + iII111i + ooOoO0o / iIii1I11I1II1
 if 91 - 91: Ii1I
 if 62 - 62: I1Ii111 . iIii1I11I1II1 - Ii1I * I1ii11iIi11i % I11i % i1IIi
 if 72 - 72: oO0o
 if 3 - 3: ooOoO0o - Oo0Ooo / iII111i
def lisp_process_info_reply ( source , packet , store ) :
 if 40 - 40: IiII + oO0o
 if 95 - 95: I1Ii111 % OOooOOo + Ii1I * i11iIiiIii + i11iIiiIii
 if 27 - 27: i11iIiiIii - iIii1I11I1II1 % I1Ii111
 if 10 - 10: i11iIiiIii - Ii1I - OoooooooOO % II111iiii
 I1iII = lisp_info ( )
 packet = I1iII . decode ( packet )
 if ( packet == None ) : return ( [ None , None , False ] )
 if 42 - 42: OoOoOO00 + iII111i % Oo0Ooo
 I1iII . print_info ( )
 if 25 - 25: IiII % O0 * I11i * OoOoOO00 / OoooooooOO
 if 80 - 80: I1IiiI . oO0o - I1IiiI - OoOoOO00 * ooOoO0o / O0
 if 54 - 54: Oo0Ooo % iIii1I11I1II1 * Oo0Ooo
 if 80 - 80: I1ii11iIi11i - I1ii11iIi11i
 II1i11i1 = False
 for I11ii1I111Ii in I1iII . rtr_list :
  oo0o00OO = I11ii1I111Ii . print_address_no_iid ( )
  if ( lisp_rtr_list . has_key ( oo0o00OO ) ) :
   if ( lisp_register_all_rtrs == False ) : continue
   if ( lisp_rtr_list [ oo0o00OO ] != None ) : continue
   if 70 - 70: iIii1I11I1II1 - i11iIiiIii * OOooOOo
  II1i11i1 = True
  lisp_rtr_list [ oo0o00OO ] = I11ii1I111Ii
  if 17 - 17: ooOoO0o / IiII
  if 4 - 4: i11iIiiIii + Ii1I - OOooOOo - i11iIiiIii - OoO0O00 . OOooOOo
  if 5 - 5: I1IiiI / OoOoOO00 / i11iIiiIii
  if 59 - 59: I11i - Ii1I - O0
  if 7 - 7: OoooooooOO
 if ( lisp_i_am_itr and II1i11i1 ) :
  if ( lisp_iid_to_interface == { } ) :
   lisp_update_default_routes ( source , lisp_default_iid , lisp_rtr_list )
  else :
   for o0OoO0000o in lisp_iid_to_interface . keys ( ) :
    lisp_update_default_routes ( source , int ( o0OoO0000o ) , lisp_rtr_list )
    if 13 - 13: I11i - o0oOOo0O0Ooo - O0 % Oo0Ooo - oO0o * OoOoOO00
    if 76 - 76: IiII
    if 88 - 88: o0oOOo0O0Ooo * II111iiii % Oo0Ooo * I1ii11iIi11i . I1IiiI % I1ii11iIi11i
    if 37 - 37: OOooOOo % OoO0O00 % oO0o . I11i / OOooOOo
    if 8 - 8: iIii1I11I1II1 + O0 + IiII - IiII * I1Ii111 / i1IIi
    if 10 - 10: Oo0Ooo . i11iIiiIii + iIii1I11I1II1 % iII111i + i11iIiiIii
    if 6 - 6: OoOoOO00 + OOooOOo + Oo0Ooo
 if ( store == False ) :
  return ( [ I1iII . global_etr_rloc , I1iII . etr_port , II1i11i1 ] )
  if 43 - 43: IiII * iII111i . ooOoO0o / I1ii11iIi11i . ooOoO0o * II111iiii
  if 30 - 30: iII111i
  if 51 - 51: ooOoO0o + oO0o
  if 80 - 80: O0 - I1Ii111 * Ii1I + I1ii11iIi11i % II111iiii . I11i
  if 80 - 80: OoOoOO00 - OOooOOo
  if 37 - 37: ooOoO0o
 for ooOOo0ooo in lisp_db_list :
  for i1III111 in ooOOo0ooo . rloc_set :
   I1IIiIIIii = i1III111 . rloc
   II1i = i1III111 . interface
   if ( II1i == None ) :
    if ( I1IIiIIIii . is_null ( ) ) : continue
    if ( I1IIiIIIii . is_local ( ) == False ) : continue
    if ( I1iII . private_etr_rloc . is_null ( ) == False and
 I1IIiIIIii . is_exact_match ( I1iII . private_etr_rloc ) == False ) :
     continue
     if 22 - 22: I1ii11iIi11i + II111iiii / OoooooooOO % o0oOOo0O0Ooo * OoOoOO00 . Oo0Ooo
   elif ( I1iII . private_etr_rloc . is_dist_name ( ) ) :
    oo0O0OOooO0 = I1iII . private_etr_rloc . address
    if ( oo0O0OOooO0 != i1III111 . rloc_name ) : continue
    if 26 - 26: OoO0O00 % oO0o * Ii1I % OoooooooOO - oO0o
    if 46 - 46: I1IiiI + OoO0O00 - O0 * O0
   I11i11i1 = green ( ooOOo0ooo . eid . print_prefix ( ) , False )
   o0oooOoOoOo = red ( I1IIiIIIii . print_address_no_iid ( ) , False )
   if 75 - 75: OOooOOo + iIii1I11I1II1 * OOooOOo
   o0O0O00oO = I1iII . global_etr_rloc . is_exact_match ( I1IIiIIIii )
   if ( i1III111 . translated_port == 0 and o0O0O00oO ) :
    lprint ( "No NAT for {} ({}), EID-prefix {}" . format ( o0oooOoOoOo ,
 II1i , I11i11i1 ) )
    continue
    if 67 - 67: o0oOOo0O0Ooo - I1IiiI * iIii1I11I1II1
    if 29 - 29: i1IIi / Ii1I / oO0o * iII111i
    if 44 - 44: O0
    if 95 - 95: OOooOOo + OOooOOo - OoOoOO00
    if 83 - 83: II111iiii * ooOoO0o - O0 - i11iIiiIii
   Oo0o0oO = I1iII . global_etr_rloc
   o0oO0oOOO0o0 = i1III111 . translated_rloc
   if ( o0oO0oOOO0o0 . is_exact_match ( Oo0o0oO ) and
 I1iII . etr_port == i1III111 . translated_port ) : continue
   if 19 - 19: iII111i / i1IIi * O0 - OoO0O00
   lprint ( "Store translation {}:{} for {} ({}), EID-prefix {}" . format ( red ( I1iII . global_etr_rloc . print_address_no_iid ( ) , False ) ,
   # ooOoO0o
 I1iII . etr_port , o0oooOoOoOo , II1i , I11i11i1 ) )
   if 26 - 26: oO0o - OoooooooOO + ooOoO0o + Ii1I
   i1III111 . store_translated_rloc ( I1iII . global_etr_rloc ,
 I1iII . etr_port )
   if 52 - 52: I1IiiI
   if 27 - 27: IiII . iII111i * I1ii11iIi11i
 return ( [ I1iII . global_etr_rloc , I1iII . etr_port , II1i11i1 ] )
 if 49 - 49: oO0o % iII111i
 if 42 - 42: iII111i
 if 74 - 74: Oo0Ooo / Ii1I / iIii1I11I1II1 + o0oOOo0O0Ooo
 if 17 - 17: OOooOOo
 if 75 - 75: Ii1I / i1IIi % I1ii11iIi11i . Ii1I
 if 46 - 46: II111iiii * OoO0O00
 if 77 - 77: ooOoO0o * I11i
 if 85 - 85: OoO0O00 * I1Ii111 - OoooooooOO / iIii1I11I1II1 - i1IIi + Ii1I
def lisp_test_mr ( lisp_sockets , port ) :
 return
 lprint ( "Test Map-Resolvers" )
 if 76 - 76: iII111i * OoooooooOO
 ooOOoo0 = lisp_address ( LISP_AFI_IPV4 , "" , 0 , 0 )
 IiI1IiIIi = lisp_address ( LISP_AFI_IPV6 , "" , 0 , 0 )
 if 3 - 3: I11i % iII111i - I1Ii111
 if 64 - 64: II111iiii + i11iIiiIii
 if 62 - 62: I1ii11iIi11i - I1IiiI * i11iIiiIii % oO0o
 if 63 - 63: II111iiii - Oo0Ooo
 ooOOoo0 . store_address ( "10.0.0.1" )
 lisp_send_map_request ( lisp_sockets , port , None , ooOOoo0 , None )
 ooOOoo0 . store_address ( "192.168.0.1" )
 lisp_send_map_request ( lisp_sockets , port , None , ooOOoo0 , None )
 if 55 - 55: iIii1I11I1II1 / O0 * O0 * i11iIiiIii * OoooooooOO
 if 94 - 94: II111iiii . II111iiii / OoOoOO00 % oO0o * i1IIi % Oo0Ooo
 if 78 - 78: IiII - I1IiiI
 if 59 - 59: oO0o + i1IIi - IiII % OOooOOo % iIii1I11I1II1
 IiI1IiIIi . store_address ( "0100::1" )
 lisp_send_map_request ( lisp_sockets , port , None , IiI1IiIIi , None )
 IiI1IiIIi . store_address ( "8000::1" )
 lisp_send_map_request ( lisp_sockets , port , None , IiI1IiIIi , None )
 if 71 - 71: OoO0O00
 if 72 - 72: II111iiii + o0oOOo0O0Ooo / i1IIi * Oo0Ooo / i1IIi
 if 52 - 52: I1Ii111 % OoO0O00 . I1Ii111 * I1ii11iIi11i * OoOoOO00 + i1IIi
 if 54 - 54: Ii1I / I1IiiI
 IiiIOo0o00 = threading . Timer ( LISP_TEST_MR_INTERVAL , lisp_test_mr ,
 [ lisp_sockets , port ] )
 IiiIOo0o00 . start ( )
 return
 if 38 - 38: II111iiii
 if 59 - 59: OoooooooOO . ooOoO0o / OOooOOo - OOooOOo / iIii1I11I1II1 / oO0o
 if 58 - 58: iIii1I11I1II1 - OoO0O00
 if 74 - 74: o0oOOo0O0Ooo . OOooOOo
 if 96 - 96: OoooooooOO
 if 19 - 19: Ii1I / OoooooooOO
 if 67 - 67: I1ii11iIi11i - OoooooooOO + OoooooooOO * o0oOOo0O0Ooo * iII111i
 if 30 - 30: I1ii11iIi11i % Ii1I
 if 2 - 2: I1IiiI . IiII . iIii1I11I1II1 - OOooOOo
 if 56 - 56: OoooooooOO + I1IiiI / I11i % i11iIiiIii / o0oOOo0O0Ooo / Ii1I
 if 27 - 27: oO0o
 if 98 - 98: OoOoOO00 . oO0o + I1ii11iIi11i
 if 14 - 14: OoooooooOO
def lisp_update_local_rloc ( rloc ) :
 if ( rloc . interface == None ) : return
 if 73 - 73: OoOoOO00 % o0oOOo0O0Ooo
 IiiIIi1 = lisp_get_interface_address ( rloc . interface )
 if ( IiiIIi1 == None ) : return
 if 28 - 28: OoO0O00
 iIOOOO0oO0o0 = rloc . rloc . print_address_no_iid ( )
 O0OOOo000 = IiiIIi1 . print_address_no_iid ( )
 if 88 - 88: I1ii11iIi11i + OoooooooOO % I1ii11iIi11i
 if ( iIOOOO0oO0o0 == O0OOOo000 ) : return
 if 3 - 3: I1Ii111 . O0 * OOooOOo * I11i + Ii1I * I1IiiI
 lprint ( "Local interface address changed on {} from {} to {}" . format ( rloc . interface , iIOOOO0oO0o0 , O0OOOo000 ) )
 if 18 - 18: iIii1I11I1II1 % ooOoO0o . o0oOOo0O0Ooo * iII111i % iII111i
 if 64 - 64: I1Ii111 . I11i
 rloc . rloc . copy_address ( IiiIIi1 )
 lisp_myrlocs [ 0 ] = IiiIIi1
 return
 if 32 - 32: I1ii11iIi11i + IiII % OoOoOO00 . O0
 if 70 - 70: IiII + iII111i . i11iIiiIii + OoO0O00
 if 45 - 45: o0oOOo0O0Ooo - ooOoO0o
 if 2 - 2: OOooOOo + iII111i * ooOoO0o + II111iiii
 if 88 - 88: ooOoO0o * OoO0O00 * I1ii11iIi11i - I1IiiI * IiII * I11i
 if 37 - 37: iIii1I11I1II1
 if 50 - 50: o0oOOo0O0Ooo - OOooOOo * IiII % Oo0Ooo
 if 81 - 81: OoooooooOO - OoOoOO00 % I1ii11iIi11i % I1ii11iIi11i + OoOoOO00
def lisp_update_encap_port ( mc ) :
 for I1IIiIIIii in mc . rloc_set :
  IIiiiiII = lisp_get_nat_info ( I1IIiIIIii . rloc , I1IIiIIIii . rloc_name )
  if ( IIiiiiII == None ) : continue
  if ( I1IIiIIIii . translated_port == IIiiiiII . port ) : continue
  if 49 - 49: Ii1I + iIii1I11I1II1 . O0 * OOooOOo * OoooooooOO - OOooOOo
  lprint ( ( "Encap-port changed from {} to {} for RLOC {}, " + "EID-prefix {}" ) . format ( I1IIiIIIii . translated_port , IIiiiiII . port ,
  # Ii1I * iIii1I11I1II1
 red ( I1IIiIIIii . rloc . print_address_no_iid ( ) , False ) ,
 green ( mc . print_eid_tuple ( ) , False ) ) )
  if 3 - 3: OoO0O00 / i11iIiiIii % O0 * OoOoOO00 % I11i
  I1IIiIIIii . store_translated_rloc ( I1IIiIIIii . rloc , IIiiiiII . port )
  if 5 - 5: i1IIi + OoO0O00 % O0 + OoO0O00
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
 if 93 - 93: I1IiiI - i11iIiiIii * I1Ii111 - O0 + iII111i
 if 11 - 11: iII111i
 if 100 - 100: OoooooooOO / ooOoO0o . OoO0O00
def lisp_timeout_map_cache_entry ( mc , delete_list ) :
 if ( mc . map_cache_ttl == None ) :
  lisp_update_encap_port ( mc )
  return ( [ True , delete_list ] )
  if 89 - 89: I11i % II111iiii
  if 35 - 35: oO0o
 i1iiI11IiIi1 = lisp_get_timestamp ( )
 if 65 - 65: II111iiii
 if 87 - 87: oO0o / OoO0O00 - oO0o
 if 69 - 69: i11iIiiIii
 if 29 - 29: IiII . ooOoO0o / iII111i - OOooOOo / OOooOOo % Oo0Ooo
 if 42 - 42: OoO0O00 . I1Ii111 . I1IiiI + Oo0Ooo * O0
 if 35 - 35: Oo0Ooo / iII111i - O0 - OOooOOo * Oo0Ooo . i11iIiiIii
 if ( mc . last_refresh_time + mc . map_cache_ttl > i1iiI11IiIi1 ) :
  if ( mc . action == LISP_NO_ACTION ) : lisp_update_encap_port ( mc )
  return ( [ True , delete_list ] )
  if 43 - 43: OoOoOO00 % oO0o % OoO0O00 / Ii1I . I11i
  if 86 - 86: I1Ii111 * i1IIi + IiII - OoOoOO00
  if 14 - 14: I1ii11iIi11i / i11iIiiIii * I11i % o0oOOo0O0Ooo + IiII / I1ii11iIi11i
  if 82 - 82: OOooOOo . oO0o
  if 12 - 12: i11iIiiIii + II111iiii
 if ( lisp_nat_traversal and mc . eid . address == 0 and mc . eid . mask_len == 0 ) :
  return ( [ True , delete_list ] )
  if 49 - 49: OoooooooOO
  if 48 - 48: i1IIi . IiII - O0 + OoooooooOO
  if 6 - 6: I1Ii111 * OOooOOo + o0oOOo0O0Ooo . I1ii11iIi11i * I1Ii111
  if 6 - 6: oO0o / II111iiii
  if 23 - 23: IiII - OoooooooOO / oO0o
 oO000o0Oo00 = lisp_print_elapsed ( mc . last_refresh_time )
 iIIiIIiII111 = mc . print_eid_tuple ( )
 lprint ( "Map-cache entry for EID-prefix {} has {}, had uptime of {}" . format ( green ( iIIiIIiII111 , False ) , bold ( "timed out" , False ) , oO000o0Oo00 ) )
 if 69 - 69: O0 - OoooooooOO
 if 31 - 31: o0oOOo0O0Ooo . i1IIi - i1IIi % i1IIi - iIii1I11I1II1
 if 50 - 50: IiII - OOooOOo % OoOoOO00
 if 66 - 66: IiII * i11iIiiIii
 if 64 - 64: i11iIiiIii . I1Ii111 % i11iIiiIii % I11i
 delete_list . append ( mc )
 return ( [ True , delete_list ] )
 if 56 - 56: o0oOOo0O0Ooo + ooOoO0o + OoooooooOO
 if 64 - 64: OOooOOo / OoOoOO00
 if 30 - 30: OOooOOo % I1Ii111 - i11iIiiIii
 if 20 - 20: i1IIi * I11i / OoO0O00 / i1IIi / I1Ii111 * O0
 if 95 - 95: Ii1I + Ii1I % IiII - IiII / OOooOOo
 if 46 - 46: IiII + iII111i + II111iiii . iII111i - i11iIiiIii % OoO0O00
 if 24 - 24: oO0o + IiII . o0oOOo0O0Ooo . OoooooooOO . i11iIiiIii / I1ii11iIi11i
 if 49 - 49: IiII
def lisp_timeout_map_cache_walk ( mc , parms ) :
 oOoOOoo0OoO = parms [ 0 ]
 iI11 = parms [ 1 ]
 if 58 - 58: OoO0O00 + I1ii11iIi11i * oO0o * I11i / oO0o
 if 68 - 68: iII111i . IiII . OoooooooOO . I1ii11iIi11i
 if 79 - 79: OoooooooOO / i1IIi
 if 30 - 30: Ii1I . IiII
 if ( mc . group . is_null ( ) ) :
  I111I1iiIi1 , oOoOOoo0OoO = lisp_timeout_map_cache_entry ( mc , oOoOOoo0OoO )
  if ( oOoOOoo0OoO == [ ] or mc != oOoOOoo0OoO [ - 1 ] ) :
   iI11 = lisp_write_checkpoint_entry ( iI11 , mc )
   if 24 - 24: O0
  return ( [ I111I1iiIi1 , parms ] )
  if 6 - 6: I1IiiI . i11iIiiIii . OoooooooOO . I1IiiI . o0oOOo0O0Ooo
  if 65 - 65: i11iIiiIii
 if ( mc . source_cache == None ) : return ( [ True , parms ] )
 if 46 - 46: i11iIiiIii
 if 70 - 70: i1IIi + o0oOOo0O0Ooo
 if 44 - 44: iII111i . II111iiii % o0oOOo0O0Ooo
 if 29 - 29: i11iIiiIii * i1IIi
 if 36 - 36: OoO0O00 * I11i . ooOoO0o
 parms = mc . source_cache . walk_cache ( lisp_timeout_map_cache_entry , parms )
 return ( [ True , parms ] )
 if 50 - 50: oO0o * OoOoOO00 / OoO0O00 / ooOoO0o + II111iiii
 if 55 - 55: II111iiii - IiII
 if 24 - 24: oO0o % Ii1I / i1IIi
 if 84 - 84: i1IIi
 if 53 - 53: OoooooooOO - i1IIi - Ii1I
 if 73 - 73: I1ii11iIi11i - Ii1I * o0oOOo0O0Ooo
 if 29 - 29: o0oOOo0O0Ooo % IiII % OOooOOo + OoooooooOO - o0oOOo0O0Ooo
def lisp_timeout_map_cache ( lisp_map_cache ) :
 I1I1i = [ [ ] , [ ] ]
 I1I1i = lisp_map_cache . walk_cache ( lisp_timeout_map_cache_walk , I1I1i )
 if 34 - 34: Ii1I
 if 5 - 5: II111iiii . I1ii11iIi11i
 if 85 - 85: I1Ii111 . IiII + II111iiii
 if 92 - 92: iII111i / o0oOOo0O0Ooo * oO0o . I11i % o0oOOo0O0Ooo
 if 87 - 87: Ii1I / Oo0Ooo % iIii1I11I1II1 / iII111i
 oOoOOoo0OoO = I1I1i [ 0 ]
 for o0o000Oo in oOoOOoo0OoO : o0o000Oo . delete_cache ( )
 if 42 - 42: OoO0O00 . I1IiiI . OOooOOo + ooOoO0o
 if 87 - 87: OOooOOo
 if 44 - 44: Oo0Ooo + iIii1I11I1II1
 if 67 - 67: iII111i . OOooOOo / ooOoO0o * iIii1I11I1II1
 iI11 = I1I1i [ 1 ]
 lisp_checkpoint ( iI11 )
 return
 if 29 - 29: I1Ii111 / OoOoOO00 % I1ii11iIi11i * IiII / II111iiii
 if 10 - 10: O0 / I11i
 if 29 - 29: i11iIiiIii % I11i
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
 if 2 - 2: oO0o / II111iiii * OoO0O00
 if 71 - 71: i1IIi + I11i * OoO0O00 . OOooOOo + oO0o
def lisp_store_nat_info ( hostname , rloc , port ) :
 oo0o00OO = rloc . print_address_no_iid ( )
 ii1Ii1i1ii = "{} NAT state for {}, RLOC {}, port {}" . format ( "{}" ,
 blue ( hostname , False ) , red ( oo0o00OO , False ) , port )
 if 100 - 100: oO0o / iII111i / i1IIi . II111iiii % I11i - I11i
 I1iiI = lisp_nat_info ( oo0o00OO , hostname , port )
 if 15 - 15: Ii1I / OOooOOo % i1IIi . I1Ii111 / O0 + I1Ii111
 if ( lisp_nat_state_info . has_key ( hostname ) == False ) :
  lisp_nat_state_info [ hostname ] = [ I1iiI ]
  lprint ( ii1Ii1i1ii . format ( "Store initial" ) )
  return ( True )
  if 39 - 39: I1ii11iIi11i * I1IiiI * II111iiii . Oo0Ooo % I1IiiI
  if 100 - 100: iIii1I11I1II1 - OoooooooOO * OoooooooOO - iII111i / ooOoO0o
  if 98 - 98: OoO0O00 + oO0o - II111iiii
  if 84 - 84: Oo0Ooo . OoOoOO00 - iII111i
  if 5 - 5: OoooooooOO . O0 / OOooOOo + I11i - Ii1I
  if 77 - 77: iIii1I11I1II1 * Oo0Ooo . IiII / oO0o + O0
 IIiiiiII = lisp_nat_state_info [ hostname ] [ 0 ]
 if ( IIiiiiII . address == oo0o00OO and IIiiiiII . port == port ) :
  IIiiiiII . uptime = lisp_get_timestamp ( )
  lprint ( ii1Ii1i1ii . format ( "Refresh existing" ) )
  return ( False )
  if 76 - 76: iII111i + o0oOOo0O0Ooo - OoooooooOO * oO0o % OoooooooOO - O0
  if 18 - 18: Ii1I
  if 82 - 82: OoOoOO00 + OoO0O00 - IiII / ooOoO0o
  if 70 - 70: OoO0O00
  if 43 - 43: ooOoO0o + OOooOOo + II111iiii - I1IiiI
  if 58 - 58: I11i
  if 94 - 94: Oo0Ooo
 I11II1I1I = None
 for IIiiiiII in lisp_nat_state_info [ hostname ] :
  if ( IIiiiiII . address == oo0o00OO and IIiiiiII . port == port ) :
   I11II1I1I = IIiiiiII
   break
   if 8 - 8: i1IIi % i1IIi % OoooooooOO % i1IIi . iIii1I11I1II1
   if 70 - 70: O0 + II111iiii % IiII / I1Ii111 - IiII
   if 58 - 58: II111iiii * oO0o - i1IIi . I11i
 if ( I11II1I1I == None ) :
  lprint ( ii1Ii1i1ii . format ( "Store new" ) )
 else :
  lisp_nat_state_info [ hostname ] . remove ( I11II1I1I )
  lprint ( ii1Ii1i1ii . format ( "Use previous" ) )
  if 23 - 23: OoO0O00 - I1IiiI * i11iIiiIii
  if 62 - 62: OoO0O00 . i11iIiiIii / i1IIi
 II1i1I1 = lisp_nat_state_info [ hostname ]
 lisp_nat_state_info [ hostname ] = [ I1iiI ] + II1i1I1
 return ( True )
 if 40 - 40: II111iiii
 if 56 - 56: II111iiii * iII111i
 if 51 - 51: I1IiiI . ooOoO0o / Ii1I / I1Ii111
 if 84 - 84: I11i - Ii1I
 if 36 - 36: i1IIi
 if 21 - 21: iII111i . OoOoOO00 % o0oOOo0O0Ooo - i11iIiiIii
 if 86 - 86: I1Ii111 % i11iIiiIii
 if 22 - 22: I1Ii111
def lisp_get_nat_info ( rloc , hostname ) :
 if ( lisp_nat_state_info . has_key ( hostname ) == False ) : return ( None )
 if 64 - 64: OoOoOO00 + II111iiii + o0oOOo0O0Ooo % iIii1I11I1II1 - OOooOOo
 oo0o00OO = rloc . print_address_no_iid ( )
 for IIiiiiII in lisp_nat_state_info [ hostname ] :
  if ( IIiiiiII . address == oo0o00OO ) : return ( IIiiiiII )
  if 60 - 60: ooOoO0o % iIii1I11I1II1 / iIii1I11I1II1
 return ( None )
 if 61 - 61: oO0o
 if 12 - 12: iIii1I11I1II1 - I1ii11iIi11i % I1ii11iIi11i * I1Ii111
 if 98 - 98: oO0o / iII111i - Oo0Ooo / I1Ii111 * oO0o - OoO0O00
 if 12 - 12: IiII . OoooooooOO - iIii1I11I1II1 % iII111i
 if 56 - 56: Oo0Ooo / I1IiiI + iIii1I11I1II1 + I1IiiI % iIii1I11I1II1
 if 64 - 64: O0
 if 55 - 55: OoO0O00 * oO0o . Ii1I + OoOoOO00 % I11i + IiII
 if 55 - 55: OoooooooOO + oO0o . o0oOOo0O0Ooo % iIii1I11I1II1 - I1Ii111
 if 40 - 40: I1IiiI . o0oOOo0O0Ooo - Oo0Ooo
 if 44 - 44: Ii1I % OoO0O00 * oO0o * OoO0O00
 if 7 - 7: I1Ii111 % i1IIi . I11i . O0 / i1IIi
 if 56 - 56: Oo0Ooo
 if 21 - 21: i11iIiiIii * o0oOOo0O0Ooo + Oo0Ooo
 if 20 - 20: IiII / OoooooooOO / O0 / I1Ii111 * ooOoO0o
 if 45 - 45: ooOoO0o / Oo0Ooo % o0oOOo0O0Ooo . ooOoO0o
 if 19 - 19: o0oOOo0O0Ooo % I11i . I1ii11iIi11i
 if 70 - 70: Oo0Ooo - I11i / I1ii11iIi11i % OoO0O00 % II111iiii
 if 72 - 72: i11iIiiIii * I11i
 if 69 - 69: I1Ii111 . Ii1I * I1ii11iIi11i % I11i - o0oOOo0O0Ooo
 if 30 - 30: ooOoO0o / Oo0Ooo * iII111i % OoooooooOO / I1ii11iIi11i
def lisp_build_info_requests ( lisp_sockets , dest , port ) :
 if ( lisp_nat_traversal == False ) : return
 if 64 - 64: OoooooooOO
 if 41 - 41: Ii1I . I11i / oO0o * OoooooooOO
 if 98 - 98: I1ii11iIi11i - O0 + i11iIiiIii
 if 71 - 71: O0 - OoooooooOO
 if 82 - 82: i11iIiiIii * II111iiii % IiII
 if 80 - 80: Ii1I . i11iIiiIii % oO0o * o0oOOo0O0Ooo
 O0o0OoOOOOo = [ ]
 o0Oo0000o00 = [ ]
 if ( dest == None ) :
  for I1I1iiii111II in lisp_map_resolvers_list . values ( ) :
   o0Oo0000o00 . append ( I1I1iiii111II . map_resolver )
   if 95 - 95: iII111i + OoooooooOO + O0 . OoOoOO00 + I1ii11iIi11i
  O0o0OoOOOOo = o0Oo0000o00
  if ( O0o0OoOOOOo == [ ] ) :
   for ii1iOo in lisp_map_servers_list . values ( ) :
    O0o0OoOOOOo . append ( ii1iOo . map_server )
    if 79 - 79: OoooooooOO / iII111i / IiII . OoooooooOO
    if 92 - 92: I11i + O0 % II111iiii - I1ii11iIi11i + OoooooooOO . iIii1I11I1II1
  if ( O0o0OoOOOOo == [ ] ) : return
 else :
  O0o0OoOOOOo . append ( dest )
  if 85 - 85: O0 - ooOoO0o
  if 35 - 35: o0oOOo0O0Ooo - I1IiiI
  if 47 - 47: i11iIiiIii * iII111i . OoOoOO00 * I1Ii111 % i11iIiiIii + Ii1I
  if 65 - 65: Ii1I % i11iIiiIii
  if 98 - 98: iII111i * o0oOOo0O0Ooo % Oo0Ooo
 IIiiiI1IIi1iI1i = { }
 for ooOOo0ooo in lisp_db_list :
  for i1III111 in ooOOo0ooo . rloc_set :
   lisp_update_local_rloc ( i1III111 )
   if ( i1III111 . rloc . is_null ( ) ) : continue
   if ( i1III111 . interface == None ) : continue
   if 7 - 7: oO0o * OoooooooOO % o0oOOo0O0Ooo . I1Ii111 + O0
   IiiIIi1 = i1III111 . rloc . print_address_no_iid ( )
   if ( IiiIIi1 in IIiiiI1IIi1iI1i ) : continue
   IIiiiI1IIi1iI1i [ IiiIIi1 ] = i1III111 . interface
   if 14 - 14: I11i * II111iiii % o0oOOo0O0Ooo / iII111i . OoooooooOO % iII111i
   if 88 - 88: iII111i
 if ( IIiiiI1IIi1iI1i == { } ) :
  lprint ( 'Suppress Info-Request, no "interface = <device>" RLOC ' + "found in any database-mappings" )
  if 94 - 94: OoooooooOO
  return
  if 32 - 32: I1ii11iIi11i
  if 8 - 8: I11i * i11iIiiIii - ooOoO0o
  if 47 - 47: ooOoO0o . I1IiiI / i11iIiiIii * iII111i * I1IiiI
  if 8 - 8: oO0o % oO0o . iII111i / i1IIi % IiII
  if 71 - 71: OoOoOO00 + oO0o % O0 + Oo0Ooo
  if 62 - 62: i1IIi . Ii1I * i1IIi * O0 . I1IiiI % o0oOOo0O0Ooo
 for IiiIIi1 in IIiiiI1IIi1iI1i :
  II1i = IIiiiI1IIi1iI1i [ IiiIIi1 ]
  OO0o = red ( IiiIIi1 , False )
  lprint ( "Build Info-Request for private address {} ({})" . format ( OO0o ,
 II1i ) )
  OoO0o0OOOO = II1i if len ( IIiiiI1IIi1iI1i ) > 1 else None
  for dest in O0o0OoOOOOo :
   lisp_send_info_request ( lisp_sockets , dest , port , OoO0o0OOOO )
   if 16 - 16: I11i . Ii1I - ooOoO0o . OOooOOo % O0 / oO0o
   if 42 - 42: II111iiii . iII111i
   if 67 - 67: i1IIi - i11iIiiIii / ooOoO0o * oO0o
   if 64 - 64: oO0o / IiII
   if 86 - 86: I11i
   if 36 - 36: o0oOOo0O0Ooo / OoO0O00
 if ( o0Oo0000o00 != [ ] ) :
  for I1I1iiii111II in lisp_map_resolvers_list . values ( ) :
   I1I1iiii111II . resolve_dns_name ( )
   if 6 - 6: I11i % I1IiiI + iII111i * OoooooooOO . O0
   if 87 - 87: ooOoO0o / Ii1I % O0 . OoO0O00
 return
 if 55 - 55: i1IIi . o0oOOo0O0Ooo % OoooooooOO + II111iiii . OoOoOO00
 if 32 - 32: IiII * I1Ii111 * Oo0Ooo . i1IIi * OoooooooOO
 if 12 - 12: I1IiiI . OOooOOo % Oo0Ooo
 if 86 - 86: i11iIiiIii
 if 57 - 57: iII111i - OoooooooOO - ooOoO0o % II111iiii
 if 62 - 62: i11iIiiIii . Oo0Ooo / Oo0Ooo . IiII . OoooooooOO
 if 86 - 86: I1ii11iIi11i * OoOoOO00 + iII111i
 if 79 - 79: I11i - II111iiii
def lisp_valid_address_format ( kw , value ) :
 if ( kw != "address" ) : return ( True )
 if 27 - 27: I1IiiI + o0oOOo0O0Ooo * oO0o % I1IiiI
 if 66 - 66: OoO0O00 + IiII . o0oOOo0O0Ooo . IiII
 if 88 - 88: oO0o + oO0o % OoO0O00 . OoooooooOO - OoooooooOO . Oo0Ooo
 if 44 - 44: I1IiiI * IiII . OoooooooOO
 if 62 - 62: I11i - Ii1I / i11iIiiIii * I1IiiI + ooOoO0o + o0oOOo0O0Ooo
 if ( value [ 0 ] == "'" and value [ - 1 ] == "'" ) : return ( True )
 if 10 - 10: i1IIi + o0oOOo0O0Ooo
 if 47 - 47: OOooOOo * IiII % I1Ii111 . OoOoOO00 - OoooooooOO / OoooooooOO
 if 79 - 79: I11i % i11iIiiIii % I1IiiI . OoooooooOO * oO0o . Ii1I
 if 14 - 14: iIii1I11I1II1 / I11i - o0oOOo0O0Ooo / IiII / o0oOOo0O0Ooo . OoO0O00
 if ( value . find ( "." ) != - 1 ) :
  IiiIIi1 = value . split ( "." )
  if ( len ( IiiIIi1 ) != 4 ) : return ( False )
  if 2 - 2: I11i
  for iiOoOo in IiiIIi1 :
   if ( iiOoOo . isdigit ( ) == False ) : return ( False )
   if ( int ( iiOoOo ) > 255 ) : return ( False )
   if 81 - 81: Ii1I . i1IIi % iII111i . OoO0O00 % IiII
  return ( True )
  if 42 - 42: iII111i / Oo0Ooo
  if 14 - 14: O0 . Oo0Ooo
  if 8 - 8: i11iIiiIii
  if 80 - 80: I1ii11iIi11i + Ii1I
  if 16 - 16: i11iIiiIii * Oo0Ooo
 if ( value . find ( "-" ) != - 1 ) :
  IiiIIi1 = value . split ( "-" )
  for IiIIi1IiiIiI in [ "N" , "S" , "W" , "E" ] :
   if ( IiIIi1IiiIiI in IiiIIi1 ) :
    if ( len ( IiiIIi1 ) < 8 ) : return ( False )
    return ( True )
    if 76 - 76: iII111i . oO0o - i1IIi
    if 94 - 94: O0 % iII111i
    if 90 - 90: IiII
    if 1 - 1: I1ii11iIi11i % OoOoOO00 . I1ii11iIi11i . OoooooooOO % oO0o + Ii1I
    if 46 - 46: I1IiiI + OoO0O00 - Oo0Ooo
    if 13 - 13: OoOoOO00
    if 72 - 72: II111iiii * iII111i . II111iiii + iII111i * IiII
 if ( value . find ( "-" ) != - 1 ) :
  IiiIIi1 = value . split ( "-" )
  if ( len ( IiiIIi1 ) != 3 ) : return ( False )
  if 90 - 90: oO0o * I1Ii111 / O0
  for IIiii1IiiIiii in IiiIIi1 :
   try : int ( IIiii1IiiIiii , 16 )
   except : return ( False )
   if 81 - 81: I11i
  return ( True )
  if 31 - 31: OoooooooOO - OoO0O00 . iIii1I11I1II1 % I1IiiI
  if 98 - 98: I1IiiI + Ii1I
  if 7 - 7: o0oOOo0O0Ooo . OoooooooOO
  if 32 - 32: I1ii11iIi11i
  if 46 - 46: Ii1I . i11iIiiIii / I1Ii111 - I1ii11iIi11i
 if ( value . find ( ":" ) != - 1 ) :
  IiiIIi1 = value . split ( ":" )
  if ( len ( IiiIIi1 ) < 2 ) : return ( False )
  if 13 - 13: IiII % I1Ii111
  Ii11iI1Ii1I1 = False
  I1I1 = 0
  for IIiii1IiiIiii in IiiIIi1 :
   I1I1 += 1
   if ( IIiii1IiiIiii == "" ) :
    if ( Ii11iI1Ii1I1 ) :
     if ( len ( IiiIIi1 ) == I1I1 ) : break
     if ( I1I1 > 2 ) : return ( False )
     if 70 - 70: iIii1I11I1II1 . i1IIi / OOooOOo . oO0o / i11iIiiIii + II111iiii
    Ii11iI1Ii1I1 = True
    continue
    if 89 - 89: I11i * O0 * Oo0Ooo % i1IIi
   try : int ( IIiii1IiiIiii , 16 )
   except : return ( False )
   if 41 - 41: OOooOOo + ooOoO0o - OoOoOO00 . iIii1I11I1II1
  return ( True )
  if 73 - 73: I1ii11iIi11i / OoooooooOO + II111iiii * Oo0Ooo * I1ii11iIi11i / OoO0O00
  if 49 - 49: OOooOOo % Oo0Ooo % OoOoOO00 - OoooooooOO % iII111i - O0
  if 62 - 62: iIii1I11I1II1
  if 14 - 14: I1Ii111
  if 95 - 95: II111iiii / o0oOOo0O0Ooo * OOooOOo
 if ( value [ 0 ] == "+" ) :
  IiiIIi1 = value [ 1 : : ]
  for ooo0O in IiiIIi1 :
   if ( ooo0O . isdigit ( ) == False ) : return ( False )
   if 1 - 1: I1Ii111
  return ( True )
  if 57 - 57: oO0o * i1IIi + iIii1I11I1II1
 return ( False )
 if 13 - 13: I1Ii111 * iII111i
 if 46 - 46: Oo0Ooo
 if 92 - 92: I1Ii111 * OoO0O00 . ooOoO0o
 if 6 - 6: o0oOOo0O0Ooo + OOooOOo
 if 75 - 75: Ii1I - II111iiii % I1IiiI . I1Ii111
 if 74 - 74: II111iiii - o0oOOo0O0Ooo + ooOoO0o - iIii1I11I1II1 / OoO0O00
 if 89 - 89: I1Ii111 + ooOoO0o + I1Ii111
 if 35 - 35: O0 * OoOoOO00
 if 54 - 54: O0 / Oo0Ooo
 if 54 - 54: OoO0O00
 if 38 - 38: II111iiii + o0oOOo0O0Ooo * I11i + I1Ii111 - II111iiii . OOooOOo
 if 38 - 38: I1ii11iIi11i % OOooOOo + iII111i / Oo0Ooo / IiII / oO0o
def lisp_process_api ( process , lisp_socket , data_structure ) :
 iiiIi1IIiIiI11I , I1I1i = data_structure . split ( "%" )
 if 16 - 16: oO0o
 lprint ( "Process API request '{}', parameters: '{}'" . format ( iiiIi1IIiIiI11I ,
 I1I1i ) )
 if 32 - 32: OoooooooOO
 i1I = [ ]
 if ( iiiIi1IIiIiI11I == "map-cache" ) :
  if ( I1I1i == "" ) :
   i1I = lisp_map_cache . walk_cache ( lisp_process_api_map_cache , i1I )
  else :
   i1I = lisp_process_api_map_cache_entry ( json . loads ( I1I1i ) )
   if 77 - 77: Oo0Ooo . i1IIi - I11i
   if 98 - 98: O0
 if ( iiiIi1IIiIiI11I == "site-cache" ) :
  if ( I1I1i == "" ) :
   i1I = lisp_sites_by_eid . walk_cache ( lisp_process_api_site_cache ,
 i1I )
  else :
   i1I = lisp_process_api_site_cache_entry ( json . loads ( I1I1i ) )
   if 87 - 87: OoO0O00 % I1Ii111 - OOooOOo - II111iiii + iII111i
   if 54 - 54: i1IIi % iII111i
 if ( iiiIi1IIiIiI11I == "map-server" ) :
  I1I1i = { } if ( I1I1i == "" ) else json . loads ( I1I1i )
  i1I = lisp_process_api_ms_or_mr ( True , I1I1i )
  if 16 - 16: II111iiii - Oo0Ooo
 if ( iiiIi1IIiIiI11I == "map-resolver" ) :
  I1I1i = { } if ( I1I1i == "" ) else json . loads ( I1I1i )
  i1I = lisp_process_api_ms_or_mr ( False , I1I1i )
  if 44 - 44: OOooOOo / Oo0Ooo - I1ii11iIi11i + I11i . oO0o
 if ( iiiIi1IIiIiI11I == "database-mapping" ) :
  i1I = lisp_process_api_database_mapping ( )
  if 85 - 85: iIii1I11I1II1 / Ii1I
  if 43 - 43: I1IiiI % I1Ii111 - oO0o . II111iiii / iIii1I11I1II1
  if 97 - 97: I1Ii111 + I1ii11iIi11i
  if 21 - 21: O0 + o0oOOo0O0Ooo * OoooooooOO % IiII % I1ii11iIi11i
  if 80 - 80: I11i
 i1I = json . dumps ( i1I )
 iiiii1i1 = lisp_api_ipc ( process , i1I )
 lisp_ipc ( iiiii1i1 , lisp_socket , "lisp-core" )
 return
 if 28 - 28: OoOoOO00 * OoooooooOO * i11iIiiIii
 if 88 - 88: ooOoO0o + ooOoO0o / I1Ii111
 if 69 - 69: O0 * o0oOOo0O0Ooo + i1IIi * ooOoO0o . o0oOOo0O0Ooo
 if 46 - 46: Oo0Ooo / Oo0Ooo * IiII
 if 65 - 65: iIii1I11I1II1 * o0oOOo0O0Ooo - iII111i % II111iiii - I1ii11iIi11i
 if 65 - 65: I11i
 if 92 - 92: iII111i . IiII + i1IIi % i1IIi
def lisp_process_api_map_cache ( mc , data ) :
 if 11 - 11: I1ii11iIi11i + iIii1I11I1II1 - I1Ii111 * iIii1I11I1II1 * IiII + oO0o
 if 6 - 6: I1Ii111 * OOooOOo + i1IIi - Ii1I / oO0o
 if 81 - 81: I1Ii111 % oO0o * i1IIi * OoooooooOO / Oo0Ooo
 if 70 - 70: I1IiiI
 if ( mc . group . is_null ( ) ) : return ( lisp_gather_map_cache_data ( mc , data ) )
 if 35 - 35: i11iIiiIii
 if ( mc . source_cache == None ) : return ( [ True , data ] )
 if 59 - 59: ooOoO0o . iII111i - II111iiii
 if 30 - 30: o0oOOo0O0Ooo % iII111i - i11iIiiIii
 if 25 - 25: i11iIiiIii + OoOoOO00 + oO0o / Ii1I * Oo0Ooo + Oo0Ooo
 if 26 - 26: I1IiiI % I1ii11iIi11i + o0oOOo0O0Ooo / I1ii11iIi11i - I1IiiI
 if 55 - 55: OoooooooOO
 data = mc . source_cache . walk_cache ( lisp_gather_map_cache_data , data )
 return ( [ True , data ] )
 if 2 - 2: Oo0Ooo + I11i / OOooOOo + OOooOOo
 if 62 - 62: OOooOOo . iIii1I11I1II1 + I1IiiI / OOooOOo
 if 90 - 90: OOooOOo
 if 29 - 29: OoOoOO00 - I1IiiI / oO0o + Oo0Ooo + I1Ii111 + O0
 if 65 - 65: oO0o
 if 38 - 38: iIii1I11I1II1 / I1Ii111 + ooOoO0o . II111iiii - iIii1I11I1II1
 if 13 - 13: Ii1I
def lisp_gather_map_cache_data ( mc , data ) :
 i1ii1i1Ii11 = { }
 i1ii1i1Ii11 [ "instance-id" ] = str ( mc . eid . instance_id )
 i1ii1i1Ii11 [ "eid-prefix" ] = mc . eid . print_prefix_no_iid ( )
 if ( mc . group . is_null ( ) == False ) :
  i1ii1i1Ii11 [ "group-prefix" ] = mc . group . print_prefix_no_iid ( )
  if 34 - 34: I1IiiI / iIii1I11I1II1
 i1ii1i1Ii11 [ "uptime" ] = lisp_print_elapsed ( mc . uptime )
 i1ii1i1Ii11 [ "expires" ] = lisp_print_elapsed ( mc . uptime )
 i1ii1i1Ii11 [ "action" ] = lisp_map_reply_action_string [ mc . action ]
 i1ii1i1Ii11 [ "ttl" ] = "--" if mc . map_cache_ttl == None else str ( mc . map_cache_ttl / 60 )
 if 35 - 35: oO0o / oO0o
 if 86 - 86: o0oOOo0O0Ooo . Oo0Ooo - Ii1I / i11iIiiIii
 if 63 - 63: oO0o - O0 + I1ii11iIi11i + Ii1I / i1IIi
 if 77 - 77: O0
 if 49 - 49: o0oOOo0O0Ooo / i11iIiiIii
 OoO0oOOooOO = [ ]
 for I1IIiIIIii in mc . rloc_set :
  O0OOOO0o0O = lisp_fill_rloc_in_json ( I1IIiIIIii )
  if 36 - 36: II111iiii
  if 78 - 78: OoO0O00 + iIii1I11I1II1 * i1IIi
  if 7 - 7: i11iIiiIii
  if 49 - 49: I1IiiI - oO0o % OOooOOo / O0 / II111iiii
  if 41 - 41: IiII % II111iiii
  if ( I1IIiIIIii . rloc . is_multicast_address ( ) ) :
   O0OOOO0o0O [ "multicast-rloc-set" ] = [ ]
   for Oo0O00000o0OO in I1IIiIIIii . multicast_rloc_probe_list . values ( ) :
    I1I1iiii111II = lisp_fill_rloc_in_json ( Oo0O00000o0OO )
    O0OOOO0o0O [ "multicast-rloc-set" ] . append ( I1I1iiii111II )
    if 99 - 99: IiII - O0
    if 59 - 59: iII111i % O0 + OOooOOo * ooOoO0o
    if 27 - 27: I1Ii111 % i11iIiiIii * I1IiiI
  OoO0oOOooOO . append ( O0OOOO0o0O )
  if 19 - 19: OoOoOO00 / o0oOOo0O0Ooo - iII111i / OoO0O00
 i1ii1i1Ii11 [ "rloc-set" ] = OoO0oOOooOO
 if 12 - 12: I1ii11iIi11i - I11i * O0 % I1IiiI + O0 - II111iiii
 data . append ( i1ii1i1Ii11 )
 return ( [ True , data ] )
 if 13 - 13: iII111i / OOooOOo * i11iIiiIii / oO0o / OoooooooOO
 if 89 - 89: Ii1I * Oo0Ooo / I1Ii111 * I1ii11iIi11i + O0 * Oo0Ooo
 if 74 - 74: I11i . I11i
 if 74 - 74: OoOoOO00 * ooOoO0o * I1Ii111
 if 56 - 56: iIii1I11I1II1 * OoO0O00 - oO0o * Ii1I
 if 62 - 62: i1IIi + I11i / OOooOOo - OoooooooOO % i1IIi . I1IiiI
 if 13 - 13: O0 * iII111i
 if 26 - 26: i1IIi - I1Ii111 - ooOoO0o
def lisp_fill_rloc_in_json ( rloc ) :
 O0OOOO0o0O = { }
 if ( rloc . rloc_exists ( ) ) :
  O0OOOO0o0O [ "address" ] = rloc . rloc . print_address_no_iid ( )
  if 73 - 73: o0oOOo0O0Ooo . OoooooooOO
  if 96 - 96: i1IIi - OOooOOo / I11i % OoOoOO00 - i11iIiiIii % II111iiii
 if ( rloc . translated_port != 0 ) :
  O0OOOO0o0O [ "encap-port" ] = str ( rloc . translated_port )
  if 47 - 47: I1Ii111 * iII111i
 O0OOOO0o0O [ "state" ] = rloc . print_state ( )
 if ( rloc . geo ) : O0OOOO0o0O [ "geo" ] = rloc . geo . print_geo ( )
 if ( rloc . elp ) : O0OOOO0o0O [ "elp" ] = rloc . elp . print_elp ( False )
 if ( rloc . rle ) : O0OOOO0o0O [ "rle" ] = rloc . rle . print_rle ( False , False )
 if ( rloc . json ) : O0OOOO0o0O [ "json" ] = rloc . json . print_json ( False )
 if ( rloc . rloc_name ) : O0OOOO0o0O [ "rloc-name" ] = rloc . rloc_name
 I1i1IIiIIiIiIi = rloc . stats . get_stats ( False , False )
 if ( I1i1IIiIIiIiIi ) : O0OOOO0o0O [ "stats" ] = I1i1IIiIIiIiIi
 O0OOOO0o0O [ "uptime" ] = lisp_print_elapsed ( rloc . uptime )
 O0OOOO0o0O [ "upriority" ] = str ( rloc . priority )
 O0OOOO0o0O [ "uweight" ] = str ( rloc . weight )
 O0OOOO0o0O [ "mpriority" ] = str ( rloc . mpriority )
 O0OOOO0o0O [ "mweight" ] = str ( rloc . mweight )
 Ooo00O00o000 = rloc . last_rloc_probe_reply
 if ( Ooo00O00o000 ) :
  O0OOOO0o0O [ "last-rloc-probe-reply" ] = lisp_print_elapsed ( Ooo00O00o000 )
  O0OOOO0o0O [ "rloc-probe-rtt" ] = str ( rloc . rloc_probe_rtt )
  if 66 - 66: iIii1I11I1II1
 O0OOOO0o0O [ "rloc-hop-count" ] = rloc . rloc_probe_hops
 O0OOOO0o0O [ "recent-rloc-hop-counts" ] = rloc . recent_rloc_probe_hops
 if 91 - 91: oO0o
 O0OOOO0o0O [ "rloc-probe-latency" ] = rloc . rloc_probe_latency
 O0OOOO0o0O [ "recent-rloc-probe-latencies" ] = rloc . recent_rloc_probe_latencies
 if 28 - 28: O0 - o0oOOo0O0Ooo / I1Ii111 . OoooooooOO % iII111i + II111iiii
 Ii1111i1iI1 = [ ]
 for oo0000OoO in rloc . recent_rloc_probe_rtts : Ii1111i1iI1 . append ( str ( oo0000OoO ) )
 O0OOOO0o0O [ "recent-rloc-probe-rtts" ] = Ii1111i1iI1
 return ( O0OOOO0o0O )
 if 75 - 75: iII111i + i1IIi . I1IiiI / oO0o * II111iiii * i1IIi
 if 14 - 14: Ii1I - I11i / i1IIi * OoOoOO00 * ooOoO0o
 if 78 - 78: iII111i % I1ii11iIi11i . I11i
 if 58 - 58: OoooooooOO * I1Ii111 % OoO0O00
 if 75 - 75: I11i - OOooOOo
 if 88 - 88: Ii1I / i11iIiiIii
 if 89 - 89: ooOoO0o
def lisp_process_api_map_cache_entry ( parms ) :
 o0OoO0000o = parms [ "instance-id" ]
 o0OoO0000o = 0 if ( o0OoO0000o == "" ) else int ( o0OoO0000o )
 if 83 - 83: I11i . I11i * OOooOOo - OOooOOo
 if 46 - 46: iIii1I11I1II1 . I1Ii111 % I1IiiI
 if 22 - 22: i1IIi * I11i + II111iiii + II111iiii
 if 20 - 20: I11i
 ooOOoo0 = lisp_address ( LISP_AFI_NONE , "" , 0 , o0OoO0000o )
 ooOOoo0 . store_prefix ( parms [ "eid-prefix" ] )
 oo0OoO = ooOOoo0
 i1IIi1ii1i1ii = ooOOoo0
 if 37 - 37: I1Ii111
 if 19 - 19: I1ii11iIi11i / OOooOOo . I1IiiI / ooOoO0o + OoO0O00 + i11iIiiIii
 if 80 - 80: OoO0O00 . O0 / Ii1I % I1Ii111 / iII111i * I1IiiI
 if 41 - 41: O0 / OoooooooOO - i1IIi
 if 6 - 6: i1IIi - I1ii11iIi11i % I1Ii111 - II111iiii / ooOoO0o / i11iIiiIii
 IIi1iiIII11 = lisp_address ( LISP_AFI_NONE , "" , 0 , o0OoO0000o )
 if ( parms . has_key ( "group-prefix" ) ) :
  IIi1iiIII11 . store_prefix ( parms [ "group-prefix" ] )
  oo0OoO = IIi1iiIII11
  if 32 - 32: oO0o / IiII - I11i . ooOoO0o
  if 69 - 69: i11iIiiIii * i11iIiiIii
 i1I = [ ]
 o0o000Oo = lisp_map_cache_lookup ( i1IIi1ii1i1ii , oo0OoO )
 if ( o0o000Oo ) : I111I1iiIi1 , i1I = lisp_process_api_map_cache ( o0o000Oo , i1I )
 return ( i1I )
 if 100 - 100: I1ii11iIi11i * I1ii11iIi11i + i1IIi
 if 96 - 96: I1Ii111 / I1IiiI + ooOoO0o
 if 16 - 16: I1ii11iIi11i % o0oOOo0O0Ooo % OOooOOo % OoOoOO00 + ooOoO0o % I1ii11iIi11i
 if 85 - 85: oO0o * OoooooooOO * iIii1I11I1II1 + iII111i
 if 67 - 67: Ii1I / i11iIiiIii % OoOoOO00 % O0 / OoOoOO00
 if 54 - 54: I11i . OoOoOO00 / II111iiii . i1IIi + OOooOOo % II111iiii
 if 82 - 82: i11iIiiIii . OoooooooOO % OoOoOO00 * O0 - I1Ii111
def lisp_process_api_site_cache ( se , data ) :
 if 78 - 78: OoOoOO00 % Ii1I % OOooOOo % Oo0Ooo % I11i . Ii1I
 if 73 - 73: OoooooooOO / i1IIi . iIii1I11I1II1
 if 89 - 89: I1Ii111
 if 29 - 29: I11i * ooOoO0o - OoooooooOO
 if ( se . group . is_null ( ) ) : return ( lisp_gather_site_cache_data ( se , data ) )
 if 92 - 92: O0 % i1IIi / OOooOOo - oO0o
 if ( se . source_cache == None ) : return ( [ True , data ] )
 if 83 - 83: o0oOOo0O0Ooo . OoO0O00 % iIii1I11I1II1 % OoOoOO00 - i11iIiiIii
 if 71 - 71: I1ii11iIi11i - II111iiii / O0 % i1IIi + oO0o
 if 73 - 73: OoooooooOO
 if 25 - 25: i1IIi . II111iiii . I1Ii111
 if 81 - 81: II111iiii + OoOoOO00 * II111iiii / iIii1I11I1II1 - Oo0Ooo % oO0o
 data = se . source_cache . walk_cache ( lisp_gather_site_cache_data , data )
 return ( [ True , data ] )
 if 66 - 66: ooOoO0o % O0 + iIii1I11I1II1 * I1Ii111 - I1Ii111
 if 61 - 61: I1ii11iIi11i
 if 12 - 12: OoO0O00
 if 97 - 97: OOooOOo . Oo0Ooo . oO0o * i1IIi
 if 7 - 7: Oo0Ooo
 if 38 - 38: Oo0Ooo - I1ii11iIi11i
 if 19 - 19: Ii1I * OoO0O00 / OoO0O00 . II111iiii % iIii1I11I1II1
def lisp_process_api_ms_or_mr ( ms_or_mr , data ) :
 ii1i1II11II1i = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
 iiIiII = data [ "dns-name" ] if data . has_key ( "dns-name" ) else None
 if ( data . has_key ( "address" ) ) :
  ii1i1II11II1i . store_address ( data [ "address" ] )
  if 61 - 61: I1ii11iIi11i * oO0o % iII111i + IiII + i11iIiiIii * I11i
  if 3 - 3: Ii1I
 i11II = { }
 if ( ms_or_mr ) :
  for ii1iOo in lisp_map_servers_list . values ( ) :
   if ( iiIiII ) :
    if ( iiIiII != ii1iOo . dns_name ) : continue
   else :
    if ( ii1i1II11II1i . is_exact_match ( ii1iOo . map_server ) == False ) : continue
    if 71 - 71: iIii1I11I1II1 . OOooOOo / I11i / i1IIi
    if 69 - 69: i1IIi / iII111i + Ii1I + I11i + IiII
   i11II [ "dns-name" ] = ii1iOo . dns_name
   i11II [ "address" ] = ii1iOo . map_server . print_address_no_iid ( )
   i11II [ "ms-name" ] = "" if ii1iOo . ms_name == None else ii1iOo . ms_name
   return ( [ i11II ] )
   if 86 - 86: Oo0Ooo
 else :
  for I1I1iiii111II in lisp_map_resolvers_list . values ( ) :
   if ( iiIiII ) :
    if ( iiIiII != I1I1iiii111II . dns_name ) : continue
   else :
    if ( ii1i1II11II1i . is_exact_match ( I1I1iiii111II . map_resolver ) == False ) : continue
    if 97 - 97: I1IiiI
    if 91 - 91: ooOoO0o / oO0o * OOooOOo . II111iiii - I11i - I11i
   i11II [ "dns-name" ] = I1I1iiii111II . dns_name
   i11II [ "address" ] = I1I1iiii111II . map_resolver . print_address_no_iid ( )
   i11II [ "mr-name" ] = "" if I1I1iiii111II . mr_name == None else I1I1iiii111II . mr_name
   return ( [ i11II ] )
   if 5 - 5: O0 + OoooooooOO + i11iIiiIii * Oo0Ooo * OoOoOO00 . oO0o
   if 6 - 6: OoO0O00 % Oo0Ooo % I1IiiI % o0oOOo0O0Ooo % O0 % Oo0Ooo
 return ( [ ] )
 if 94 - 94: I11i . i1IIi / II111iiii + OOooOOo
 if 64 - 64: I1IiiI % ooOoO0o
 if 72 - 72: O0 * II111iiii % OoO0O00 - I1IiiI * OOooOOo
 if 80 - 80: OOooOOo * I11i / OOooOOo - oO0o
 if 18 - 18: i1IIi - OOooOOo - o0oOOo0O0Ooo - iIii1I11I1II1
 if 72 - 72: OoooooooOO % I1IiiI . OoO0O00
 if 28 - 28: II111iiii / iIii1I11I1II1 / iII111i - o0oOOo0O0Ooo . I1IiiI / O0
 if 16 - 16: ooOoO0o * oO0o . OoooooooOO
def lisp_process_api_database_mapping ( ) :
 i1I = [ ]
 if 44 - 44: iIii1I11I1II1 * OOooOOo + OoO0O00 - OoooooooOO
 for ooOOo0ooo in lisp_db_list :
  i1ii1i1Ii11 = { }
  i1ii1i1Ii11 [ "eid-prefix" ] = ooOOo0ooo . eid . print_prefix ( )
  if ( ooOOo0ooo . group . is_null ( ) == False ) :
   i1ii1i1Ii11 [ "group-prefix" ] = ooOOo0ooo . group . print_prefix ( )
   if 13 - 13: Oo0Ooo . I11i . II111iiii
   if 6 - 6: OOooOOo . IiII / OoO0O00 * oO0o - I1Ii111 . OoOoOO00
  ooOOo = [ ]
  for O0OOOO0o0O in ooOOo0ooo . rloc_set :
   I1IIiIIIii = { }
   if ( O0OOOO0o0O . rloc . is_null ( ) == False ) :
    I1IIiIIIii [ "rloc" ] = O0OOOO0o0O . rloc . print_address_no_iid ( )
    if 85 - 85: i11iIiiIii + OoOoOO00
   if ( O0OOOO0o0O . rloc_name != None ) : I1IIiIIIii [ "rloc-name" ] = O0OOOO0o0O . rloc_name
   if ( O0OOOO0o0O . interface != None ) : I1IIiIIIii [ "interface" ] = O0OOOO0o0O . interface
   II1i1III = O0OOOO0o0O . translated_rloc
   if ( II1i1III . is_null ( ) == False ) :
    I1IIiIIIii [ "translated-rloc" ] = II1i1III . print_address_no_iid ( )
    if 27 - 27: OOooOOo
   if ( I1IIiIIIii != { } ) : ooOOo . append ( I1IIiIIIii )
   if 80 - 80: oO0o
   if 12 - 12: iII111i / iIii1I11I1II1
   if 48 - 48: oO0o - oO0o % I1Ii111 % OoO0O00 . Oo0Ooo . oO0o
   if 23 - 23: I11i / IiII * II111iiii * oO0o . OoooooooOO / i1IIi
   if 89 - 89: iII111i * oO0o . iIii1I11I1II1
  i1ii1i1Ii11 [ "rlocs" ] = ooOOo
  if 50 - 50: iIii1I11I1II1 * iIii1I11I1II1
  if 20 - 20: OoOoOO00
  if 86 - 86: OoooooooOO - iIii1I11I1II1 . OoO0O00 * Ii1I / I1Ii111 + I1Ii111
  if 52 - 52: iIii1I11I1II1 % OoO0O00 - IiII % i11iIiiIii - o0oOOo0O0Ooo
  i1I . append ( i1ii1i1Ii11 )
  if 25 - 25: Oo0Ooo - OOooOOo . i1IIi * OoOoOO00 / I11i / o0oOOo0O0Ooo
 return ( i1I )
 if 54 - 54: OoOoOO00 / i1IIi + OOooOOo - I1ii11iIi11i - I1IiiI * I1Ii111
 if 91 - 91: OoooooooOO * OoooooooOO
 if 27 - 27: ooOoO0o / I1IiiI * I1ii11iIi11i . o0oOOo0O0Ooo
 if 30 - 30: o0oOOo0O0Ooo / i11iIiiIii
 if 33 - 33: OOooOOo % OoooooooOO
 if 98 - 98: Ii1I
 if 38 - 38: ooOoO0o - iII111i * OOooOOo % I1ii11iIi11i + Oo0Ooo
def lisp_gather_site_cache_data ( se , data ) :
 i1ii1i1Ii11 = { }
 i1ii1i1Ii11 [ "site-name" ] = se . site . site_name
 i1ii1i1Ii11 [ "instance-id" ] = str ( se . eid . instance_id )
 i1ii1i1Ii11 [ "eid-prefix" ] = se . eid . print_prefix_no_iid ( )
 if ( se . group . is_null ( ) == False ) :
  i1ii1i1Ii11 [ "group-prefix" ] = se . group . print_prefix_no_iid ( )
  if 95 - 95: iIii1I11I1II1 / O0 % O0
 i1ii1i1Ii11 [ "registered" ] = "yes" if se . registered else "no"
 i1ii1i1Ii11 [ "first-registered" ] = lisp_print_elapsed ( se . first_registered )
 i1ii1i1Ii11 [ "last-registered" ] = lisp_print_elapsed ( se . last_registered )
 if 53 - 53: ooOoO0o . ooOoO0o
 IiiIIi1 = se . last_registerer
 IiiIIi1 = "none" if IiiIIi1 . is_null ( ) else IiiIIi1 . print_address ( )
 i1ii1i1Ii11 [ "last-registerer" ] = IiiIIi1
 i1ii1i1Ii11 [ "ams" ] = "yes" if ( se . accept_more_specifics ) else "no"
 i1ii1i1Ii11 [ "dynamic" ] = "yes" if ( se . dynamic ) else "no"
 i1ii1i1Ii11 [ "site-id" ] = str ( se . site_id )
 if ( se . xtr_id_present ) :
  i1ii1i1Ii11 [ "xtr-id" ] = "0x" + lisp_hex_string ( se . xtr_id )
  if 80 - 80: i11iIiiIii % I1Ii111 % I1IiiI / I1IiiI + oO0o + iII111i
  if 18 - 18: OoO0O00 * ooOoO0o
  if 32 - 32: oO0o . OoooooooOO - o0oOOo0O0Ooo + II111iiii
  if 4 - 4: OOooOOo * I1IiiI - I11i - I11i
  if 67 - 67: I1IiiI
 OoO0oOOooOO = [ ]
 for I1IIiIIIii in se . registered_rlocs :
  O0OOOO0o0O = { }
  O0OOOO0o0O [ "address" ] = I1IIiIIIii . rloc . print_address_no_iid ( ) if I1IIiIIIii . rloc_exists ( ) else "none"
  if 32 - 32: oO0o * i11iIiiIii - I11i % Oo0Ooo * I1ii11iIi11i
  if 79 - 79: II111iiii / Oo0Ooo / I1ii11iIi11i
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
  if 30 - 30: I11i . o0oOOo0O0Ooo / II111iiii
  OoO0oOOooOO . append ( O0OOOO0o0O )
  if 59 - 59: i11iIiiIii
 i1ii1i1Ii11 [ "registered-rlocs" ] = OoO0oOOooOO
 if 5 - 5: i11iIiiIii + o0oOOo0O0Ooo . OoO0O00 % OoOoOO00 + I11i
 data . append ( i1ii1i1Ii11 )
 return ( [ True , data ] )
 if 59 - 59: I1ii11iIi11i
 if 47 - 47: I1IiiI + Oo0Ooo
 if 78 - 78: i1IIi / I1ii11iIi11i % ooOoO0o * OoO0O00
 if 10 - 10: i1IIi % ooOoO0o / iII111i
 if 98 - 98: IiII / o0oOOo0O0Ooo - i1IIi - OOooOOo
 if 65 - 65: Ii1I + OoOoOO00 * Oo0Ooo . O0 . IiII
 if 33 - 33: i11iIiiIii . i1IIi . I1Ii111 - OoOoOO00 + OOooOOo
def lisp_process_api_site_cache_entry ( parms ) :
 o0OoO0000o = parms [ "instance-id" ]
 o0OoO0000o = 0 if ( o0OoO0000o == "" ) else int ( o0OoO0000o )
 if 34 - 34: I1ii11iIi11i . i1IIi * O0 / OoooooooOO
 if 22 - 22: OOooOOo % o0oOOo0O0Ooo - i11iIiiIii
 if 58 - 58: IiII . Ii1I + II111iiii
 if 31 - 31: i11iIiiIii + i11iIiiIii + I11i * Oo0Ooo . I11i
 ooOOoo0 = lisp_address ( LISP_AFI_NONE , "" , 0 , o0OoO0000o )
 ooOOoo0 . store_prefix ( parms [ "eid-prefix" ] )
 if 28 - 28: OOooOOo * iIii1I11I1II1 * OoOoOO00
 if 75 - 75: Oo0Ooo % IiII + II111iiii + oO0o
 if 35 - 35: I1ii11iIi11i - oO0o - O0 / iII111i % IiII
 if 10 - 10: OOooOOo + oO0o - I1Ii111 . I1IiiI
 if 11 - 11: I1ii11iIi11i . I1Ii111 / o0oOOo0O0Ooo + IiII
 IIi1iiIII11 = lisp_address ( LISP_AFI_NONE , "" , 0 , o0OoO0000o )
 if ( parms . has_key ( "group-prefix" ) ) :
  IIi1iiIII11 . store_prefix ( parms [ "group-prefix" ] )
  if 73 - 73: OoO0O00 . i11iIiiIii * OoO0O00 * i1IIi + I11i
  if 27 - 27: i11iIiiIii / OoOoOO00 % O0 / II111iiii . I11i - ooOoO0o
 i1I = [ ]
 iIiIi1I = lisp_site_eid_lookup ( ooOOoo0 , IIi1iiIII11 , False )
 if ( iIiIi1I ) : lisp_gather_site_cache_data ( iIiIi1I , i1I )
 return ( i1I )
 if 54 - 54: oO0o * II111iiii
 if 79 - 79: o0oOOo0O0Ooo . ooOoO0o . Oo0Ooo * OoooooooOO
 if 98 - 98: ooOoO0o
 if 73 - 73: I1Ii111
 if 97 - 97: OoO0O00 * Ii1I + Oo0Ooo
 if 83 - 83: II111iiii - Oo0Ooo % II111iiii * o0oOOo0O0Ooo
 if 51 - 51: iII111i * iIii1I11I1II1 % Ii1I * Ii1I + i11iIiiIii . OoooooooOO
def lisp_get_interface_instance_id ( device , source_eid ) :
 II1i = None
 if ( lisp_myinterfaces . has_key ( device ) ) :
  II1i = lisp_myinterfaces [ device ]
  if 54 - 54: i11iIiiIii . iIii1I11I1II1 * iIii1I11I1II1 + Ii1I % I11i - OoO0O00
  if 16 - 16: IiII % iIii1I11I1II1 * i11iIiiIii + O0
  if 76 - 76: iII111i * OOooOOo
  if 7 - 7: ooOoO0o + o0oOOo0O0Ooo + o0oOOo0O0Ooo
  if 73 - 73: IiII % I11i % i11iIiiIii + ooOoO0o
  if 83 - 83: Ii1I * I1Ii111 * i11iIiiIii / iIii1I11I1II1 % I1ii11iIi11i
 if ( II1i == None or II1i . instance_id == None ) :
  return ( lisp_default_iid )
  if 40 - 40: iII111i
  if 21 - 21: I1Ii111 / iII111i + Oo0Ooo / I1ii11iIi11i / I1Ii111
  if 33 - 33: OoooooooOO
  if 59 - 59: i11iIiiIii - OoooooooOO . ooOoO0o / i11iIiiIii % iIii1I11I1II1 * I1ii11iIi11i
  if 45 - 45: I1ii11iIi11i * I1ii11iIi11i
  if 31 - 31: OoO0O00 - OOooOOo . iII111i * I1Ii111 * iII111i + I1ii11iIi11i
  if 5 - 5: Oo0Ooo . I1Ii111
  if 77 - 77: i11iIiiIii / I1Ii111 / I1ii11iIi11i % oO0o
  if 83 - 83: Ii1I % iIii1I11I1II1 / I1ii11iIi11i + I11i
 o0OoO0000o = II1i . get_instance_id ( )
 if ( source_eid == None ) : return ( o0OoO0000o )
 if 23 - 23: iIii1I11I1II1 - I1IiiI
 Ooo0II1IiI1i = source_eid . instance_id
 oOOO000 = None
 for II1i in lisp_multi_tenant_interfaces :
  if ( II1i . device != device ) : continue
  IIII1 = II1i . multi_tenant_eid
  source_eid . instance_id = IIII1 . instance_id
  if ( source_eid . is_more_specific ( IIII1 ) == False ) : continue
  if ( oOOO000 == None or oOOO000 . multi_tenant_eid . mask_len < IIII1 . mask_len ) :
   oOOO000 = II1i
   if 43 - 43: IiII
   if 20 - 20: OoOoOO00
 source_eid . instance_id = Ooo0II1IiI1i
 if 33 - 33: OoO0O00
 if ( oOOO000 == None ) : return ( o0OoO0000o )
 return ( oOOO000 . get_instance_id ( ) )
 if 55 - 55: ooOoO0o + ooOoO0o
 if 93 - 93: oO0o - I1IiiI / I1ii11iIi11i % o0oOOo0O0Ooo / OoooooooOO + II111iiii
 if 10 - 10: o0oOOo0O0Ooo - iII111i . O0 + OoO0O00 - Oo0Ooo - i11iIiiIii
 if 37 - 37: iIii1I11I1II1
 if 37 - 37: II111iiii % OoOoOO00 . IiII * ooOoO0o . I1IiiI
 if 25 - 25: OoooooooOO % i1IIi . I1Ii111 / OoOoOO00 - I1ii11iIi11i
 if 15 - 15: iIii1I11I1II1
 if 72 - 72: OoO0O00 . IiII * Ii1I - I1IiiI
 if 81 - 81: oO0o . OOooOOo - Ii1I . OoOoOO00
def lisp_allow_dynamic_eid ( device , eid ) :
 if ( lisp_myinterfaces . has_key ( device ) == False ) : return ( None )
 if 100 - 100: Ii1I * i1IIi * i1IIi - iII111i + OoO0O00 + OoO0O00
 II1i = lisp_myinterfaces [ device ]
 iIiII = device if II1i . dynamic_eid_device == None else II1i . dynamic_eid_device
 if 24 - 24: IiII * i11iIiiIii % o0oOOo0O0Ooo - ooOoO0o + ooOoO0o . II111iiii
 if 69 - 69: I1IiiI . i11iIiiIii - o0oOOo0O0Ooo
 if ( II1i . does_dynamic_eid_match ( eid ) ) : return ( iIiII )
 return ( None )
 if 40 - 40: OOooOOo * Ii1I
 if 38 - 38: ooOoO0o
 if 5 - 5: OoooooooOO + iII111i - I11i
 if 95 - 95: OOooOOo / i11iIiiIii - Ii1I + I1ii11iIi11i
 if 7 - 7: I1ii11iIi11i
 if 37 - 37: O0 . II111iiii
 if 70 - 70: o0oOOo0O0Ooo / iII111i + i1IIi + I11i % iIii1I11I1II1 % Oo0Ooo
def lisp_start_rloc_probe_timer ( interval , lisp_sockets ) :
 global lisp_rloc_probe_timer
 if 1 - 1: O0 + OoO0O00 . i11iIiiIii + I1Ii111 - OoO0O00 - IiII
 if ( lisp_rloc_probe_timer != None ) : lisp_rloc_probe_timer . cancel ( )
 if 1 - 1: I1ii11iIi11i / i1IIi . I1IiiI / Ii1I
 IiiII = lisp_process_rloc_probe_timer
 iiI1IOO00o0Oo0000 = threading . Timer ( interval , IiiII , [ lisp_sockets ] )
 lisp_rloc_probe_timer = iiI1IOO00o0Oo0000
 iiI1IOO00o0Oo0000 . start ( )
 return
 if 10 - 10: OoOoOO00 % I1ii11iIi11i * O0
 if 20 - 20: ooOoO0o + I1IiiI - IiII % ooOoO0o - IiII . oO0o
 if 39 - 39: O0 / oO0o % oO0o * iIii1I11I1II1
 if 7 - 7: iII111i % o0oOOo0O0Ooo / II111iiii % IiII / iIii1I11I1II1
 if 17 - 17: I11i * I11i - O0 / IiII + OoOoOO00
 if 65 - 65: I1Ii111 * i1IIi
 if 10 - 10: OOooOOo % IiII
def lisp_show_rloc_probe_list ( ) :
 lprint ( bold ( "----- RLOC-probe-list -----" , False ) )
 for Oo000O000 in lisp_rloc_probe_list :
  I11iiI1i11I1Ii = lisp_rloc_probe_list [ Oo000O000 ]
  lprint ( "RLOC {}:" . format ( Oo000O000 ) )
  for O0OOOO0o0O , oOo , i11ii in I11iiI1i11I1Ii :
   lprint ( "  [{}, {}, {}, {}]" . format ( hex ( id ( O0OOOO0o0O ) ) , oOo . print_prefix ( ) ,
 i11ii . print_prefix ( ) , O0OOOO0o0O . translated_port ) )
   if 74 - 74: O0 % OoOoOO00 - Ii1I / I1ii11iIi11i / Oo0Ooo
   if 74 - 74: i1IIi
 lprint ( bold ( "---------------------------" , False ) )
 return
 if 38 - 38: II111iiii * i1IIi
 if 43 - 43: O0 - OOooOOo / I1IiiI * II111iiii . OoooooooOO / OoOoOO00
 if 77 - 77: OoOoOO00
 if 10 - 10: IiII / i11iIiiIii
 if 19 - 19: OoO0O00
 if 100 - 100: I1ii11iIi11i - I1ii11iIi11i
 if 38 - 38: I1Ii111
 if 23 - 23: Ii1I . I1ii11iIi11i + I1Ii111 + i1IIi * o0oOOo0O0Ooo - i11iIiiIii
 if 92 - 92: I1Ii111 - I1IiiI + Ii1I / iII111i % OOooOOo
def lisp_mark_rlocs_for_other_eids ( eid_list ) :
 if 32 - 32: i1IIi . iII111i - Ii1I % iII111i % II111iiii - oO0o
 if 36 - 36: OoooooooOO * OoooooooOO . ooOoO0o . O0
 if 5 - 5: I11i % I1IiiI - OoO0O00 . Oo0Ooo
 if 79 - 79: iII111i + IiII % I11i . Oo0Ooo / IiII * iII111i
 I1IIiIIIii , oOo , i11ii = eid_list [ 0 ]
 i1IiIiII1 = [ lisp_print_eid_tuple ( oOo , i11ii ) ]
 if 18 - 18: II111iiii * oO0o
 for I1IIiIIIii , oOo , i11ii in eid_list [ 1 : : ] :
  I1IIiIIIii . state = LISP_RLOC_UNREACH_STATE
  I1IIiIIIii . last_state_change = lisp_get_timestamp ( )
  i1IiIiII1 . append ( lisp_print_eid_tuple ( oOo , i11ii ) )
  if 55 - 55: I1ii11iIi11i * i11iIiiIii + Oo0Ooo
  if 29 - 29: I1ii11iIi11i / IiII . I1Ii111 + Ii1I + OoO0O00
 o00 = bold ( "unreachable" , False )
 o0oooOoOoOo = red ( I1IIiIIIii . rloc . print_address_no_iid ( ) , False )
 if 72 - 72: oO0o - II111iiii / I1IiiI
 for ooOOoo0 in i1IiIiII1 :
  oOo = green ( ooOOoo0 , False )
  lprint ( "RLOC {} went {} for EID {}" . format ( o0oooOoOoOo , o00 , oOo ) )
  if 47 - 47: oO0o * I1Ii111 - O0 % iII111i * iIii1I11I1II1 / I1IiiI
  if 72 - 72: ooOoO0o / ooOoO0o * iIii1I11I1II1 . II111iiii * OOooOOo - iIii1I11I1II1
  if 15 - 15: Oo0Ooo - i11iIiiIii * OoO0O00 + I1ii11iIi11i + I1ii11iIi11i
  if 74 - 74: ooOoO0o
  if 7 - 7: Oo0Ooo / ooOoO0o + o0oOOo0O0Ooo
  if 38 - 38: o0oOOo0O0Ooo . O0 - OoO0O00 % I11i
 for I1IIiIIIii , oOo , i11ii in eid_list :
  o0o000Oo = lisp_map_cache . lookup_cache ( oOo , True )
  if ( o0o000Oo ) : lisp_write_ipc_map_cache ( True , o0o000Oo )
  if 80 - 80: o0oOOo0O0Ooo
 return
 if 100 - 100: iIii1I11I1II1 . OoOoOO00 . OoooooooOO / I1ii11iIi11i - I1IiiI * I11i
 if 5 - 5: i1IIi * o0oOOo0O0Ooo - I1Ii111 + I1IiiI - II111iiii
 if 15 - 15: I1Ii111
 if 38 - 38: O0
 if 50 - 50: i11iIiiIii * OoO0O00 + iII111i / O0 * oO0o % ooOoO0o
 if 6 - 6: OoO0O00 . o0oOOo0O0Ooo / Ii1I + Ii1I
 if 59 - 59: II111iiii - o0oOOo0O0Ooo * OoooooooOO
 if 83 - 83: oO0o . iIii1I11I1II1 . iII111i % Oo0Ooo
 if 48 - 48: oO0o % OoO0O00 - OoooooooOO . IiII
 if 11 - 11: I1Ii111 % o0oOOo0O0Ooo - o0oOOo0O0Ooo % OoooooooOO . o0oOOo0O0Ooo - I1ii11iIi11i
def lisp_process_rloc_probe_timer ( lisp_sockets ) :
 lisp_set_exception ( )
 if 33 - 33: OoO0O00 + II111iiii . Oo0Ooo * I1Ii111
 lisp_start_rloc_probe_timer ( LISP_RLOC_PROBE_INTERVAL , lisp_sockets )
 if ( lisp_rloc_probing == False ) : return
 if 63 - 63: OoooooooOO + OoOoOO00 - OoooooooOO
 if 54 - 54: OoO0O00 + I1IiiI % O0 + OoO0O00
 if 37 - 37: II111iiii / I1ii11iIi11i * I1IiiI - OoooooooOO
 if 55 - 55: IiII / ooOoO0o * I1IiiI / I1Ii111 - Oo0Ooo % o0oOOo0O0Ooo
 if ( lisp_print_rloc_probe_list ) : lisp_show_rloc_probe_list ( )
 if 82 - 82: OoO0O00 - iIii1I11I1II1 . Oo0Ooo / IiII . OoO0O00
 if 47 - 47: OOooOOo + IiII
 if 11 - 11: Oo0Ooo + I1IiiI % i11iIiiIii % Oo0Ooo + ooOoO0o + i1IIi
 if 100 - 100: II111iiii - OOooOOo + iII111i - i11iIiiIii . O0 / iII111i
 oooO00OoO0O = lisp_get_default_route_next_hops ( )
 if 9 - 9: o0oOOo0O0Ooo / ooOoO0o + iII111i / II111iiii * Oo0Ooo
 lprint ( "---------- Start RLOC Probing for {} entries ----------" . format ( len ( lisp_rloc_probe_list ) ) )
 if 93 - 93: O0 % ooOoO0o
 if 48 - 48: i1IIi + iII111i - Ii1I
 if 9 - 9: o0oOOo0O0Ooo
 if 92 - 92: i11iIiiIii + OoooooooOO + O0 % oO0o
 if 90 - 90: Oo0Ooo * i11iIiiIii
 I1I1 = 0
 oO0oo000O = bold ( "RLOC-probe" , False )
 for O0ooooooOo0 in lisp_rloc_probe_list . values ( ) :
  if 69 - 69: iIii1I11I1II1 * oO0o
  if 80 - 80: IiII - oO0o % Ii1I - iIii1I11I1II1 . OoO0O00
  if 64 - 64: I1IiiI % i11iIiiIii / oO0o
  if 78 - 78: II111iiii - Oo0Ooo . iIii1I11I1II1 - ooOoO0o . oO0o
  if 84 - 84: iII111i . ooOoO0o * I1IiiI * Oo0Ooo / I1Ii111
  Oo0o0O0ooO0o = None
  for iiI1I1Ii , ooOOoo0 , IIi1iiIII11 in O0ooooooOo0 :
   oo0o00OO = iiI1I1Ii . rloc . print_address_no_iid ( )
   if 65 - 65: OoO0O00 % OoOoOO00 % I1ii11iIi11i / OoooooooOO
   if 85 - 85: O0 * OOooOOo % I1Ii111
   if 33 - 33: O0
   if 30 - 30: II111iiii . O0 . oO0o * I1ii11iIi11i + oO0o . o0oOOo0O0Ooo
   o0O0o0O , i1IoO , IIIi1i1iIIIi = lisp_allow_gleaning ( ooOOoo0 , None , iiI1I1Ii )
   if ( o0O0o0O and i1IoO == False ) :
    oOo = green ( ooOOoo0 . print_address ( ) , False )
    oo0o00OO += ":{}" . format ( iiI1I1Ii . translated_port )
    lprint ( "Suppress probe to RLOC {} for gleaned EID {}" . format ( red ( oo0o00OO , False ) , oOo ) )
    if 10 - 10: oO0o
    continue
    if 75 - 75: II111iiii % OOooOOo / iIii1I11I1II1 / OoO0O00 + oO0o
    if 16 - 16: oO0o + I1Ii111 - II111iiii - o0oOOo0O0Ooo / i11iIiiIii
    if 59 - 59: OOooOOo - o0oOOo0O0Ooo
    if 82 - 82: IiII % ooOoO0o - OoO0O00 % ooOoO0o
    if 51 - 51: ooOoO0o % iII111i . o0oOOo0O0Ooo . o0oOOo0O0Ooo
    if 20 - 20: i1IIi - ooOoO0o % OoooooooOO * I1ii11iIi11i + II111iiii % i1IIi
    if 30 - 30: i11iIiiIii - I1IiiI + o0oOOo0O0Ooo + IiII
   if ( iiI1I1Ii . down_state ( ) ) : continue
   if 16 - 16: I1ii11iIi11i / Ii1I + I1ii11iIi11i * I1Ii111
   if 49 - 49: ooOoO0o * OoOoOO00 . OoooooooOO . ooOoO0o + Oo0Ooo * IiII
   if 47 - 47: iII111i . i1IIi . I1ii11iIi11i / OoooooooOO
   if 84 - 84: o0oOOo0O0Ooo * I11i
   if 22 - 22: i1IIi + OOooOOo % OoooooooOO
   if 34 - 34: oO0o / O0 - II111iiii % Oo0Ooo + I11i
   if 23 - 23: o0oOOo0O0Ooo + i11iIiiIii . I1IiiI + iIii1I11I1II1
   if 18 - 18: o0oOOo0O0Ooo . O0 + I1Ii111
   if 66 - 66: OoooooooOO
   if 90 - 90: IiII - OoOoOO00
   if 98 - 98: Oo0Ooo / oO0o . Ii1I
   if ( Oo0o0O0ooO0o ) :
    iiI1I1Ii . last_rloc_probe_nonce = Oo0o0O0ooO0o . last_rloc_probe_nonce
    if 56 - 56: ooOoO0o % OoO0O00 * i11iIiiIii % IiII % I1IiiI - oO0o
    if ( Oo0o0O0ooO0o . translated_port == iiI1I1Ii . translated_port and Oo0o0O0ooO0o . rloc_name == iiI1I1Ii . rloc_name ) :
     if 37 - 37: iII111i - Ii1I . oO0o
     oOo = green ( lisp_print_eid_tuple ( ooOOoo0 , IIi1iiIII11 ) , False )
     lprint ( "Suppress probe to duplicate RLOC {} for {}" . format ( red ( oo0o00OO , False ) , oOo ) )
     if 47 - 47: IiII / I1ii11iIi11i . o0oOOo0O0Ooo . ooOoO0o + OOooOOo . OOooOOo
     if 25 - 25: oO0o
     if 43 - 43: Ii1I - o0oOOo0O0Ooo % oO0o - O0
     if 20 - 20: OoO0O00 . ooOoO0o / OoOoOO00 - OoOoOO00 . iII111i / OOooOOo
     if 39 - 39: iIii1I11I1II1 % ooOoO0o
     if 75 - 75: i1IIi * II111iiii * O0 * i11iIiiIii % iII111i / iII111i
     iiI1I1Ii . last_rloc_probe = Oo0o0O0ooO0o . last_rloc_probe
     continue
     if 36 - 36: IiII / I1IiiI % iII111i / iII111i
     if 38 - 38: OOooOOo * I1ii11iIi11i * I1Ii111 + I11i
     if 65 - 65: O0 + O0 * I1Ii111
   II11111Iii1I = None
   I1IIiIIIii = None
   while ( True ) :
    I1IIiIIIii = iiI1I1Ii if I1IIiIIIii == None else I1IIiIIIii . next_rloc
    if ( I1IIiIIIii == None ) : break
    if 66 - 66: OOooOOo / O0 + i1IIi . O0 % I1ii11iIi11i - OoooooooOO
    if 16 - 16: I11i % iII111i
    if 29 - 29: I1IiiI - ooOoO0o * OoO0O00 . i11iIiiIii % OoOoOO00 * o0oOOo0O0Ooo
    if 43 - 43: OoO0O00 * OOooOOo / I1Ii111 % OoOoOO00 . oO0o / OOooOOo
    if 62 - 62: O0 * I1ii11iIi11i - O0 / I11i % ooOoO0o
    if ( I1IIiIIIii . rloc_next_hop != None ) :
     if ( I1IIiIIIii . rloc_next_hop not in oooO00OoO0O ) :
      if ( I1IIiIIIii . up_state ( ) ) :
       OooOOOoOoo0O0 , o00O00oo0 = I1IIiIIIii . rloc_next_hop
       I1IIiIIIii . state = LISP_RLOC_UNREACH_STATE
       I1IIiIIIii . last_state_change = lisp_get_timestamp ( )
       lisp_update_rtr_updown ( I1IIiIIIii . rloc , False )
       if 1 - 1: O0 / iIii1I11I1II1
      o00 = bold ( "unreachable" , False )
      lprint ( "Next-hop {}({}) for RLOC {} is {}" . format ( o00O00oo0 , OooOOOoOoo0O0 ,
 red ( oo0o00OO , False ) , o00 ) )
      continue
      if 17 - 17: OoOoOO00 + ooOoO0o * II111iiii * OoOoOO00 + I1IiiI + i11iIiiIii
      if 46 - 46: i1IIi - II111iiii . I1IiiI . i11iIiiIii
      if 54 - 54: O0 * I1ii11iIi11i / OOooOOo / IiII * IiII
      if 69 - 69: Oo0Ooo * OoooooooOO / I1IiiI
      if 16 - 16: o0oOOo0O0Ooo
      if 3 - 3: i11iIiiIii . I1ii11iIi11i
    iiI = I1IIiIIIii . last_rloc_probe
    OoO0OO0OO000o = 0 if iiI == None else time . time ( ) - iiI
    if ( I1IIiIIIii . unreach_state ( ) and OoO0OO0OO000o < LISP_RLOC_PROBE_INTERVAL ) :
     lprint ( "Waiting for probe-reply from RLOC {}" . format ( red ( oo0o00OO , False ) ) )
     if 10 - 10: IiII + OOooOOo . iII111i - ooOoO0o
     continue
     if 100 - 100: o0oOOo0O0Ooo
     if 95 - 95: iII111i * oO0o * i1IIi
     if 100 - 100: iII111i . o0oOOo0O0Ooo - I1Ii111 % oO0o
     if 11 - 11: o0oOOo0O0Ooo . OoooooooOO - i1IIi
     if 71 - 71: I1IiiI . OOooOOo . I1ii11iIi11i
     if 90 - 90: i11iIiiIii + I1Ii111 % II111iiii
    ii1 = lisp_get_echo_nonce ( None , oo0o00OO )
    if ( ii1 and ii1 . request_nonce_timeout ( ) ) :
     I1IIiIIIii . state = LISP_RLOC_NO_ECHOED_NONCE_STATE
     I1IIiIIIii . last_state_change = lisp_get_timestamp ( )
     o00 = bold ( "unreachable" , False )
     lprint ( "RLOC {} went {}, nonce-echo failed" . format ( red ( oo0o00OO , False ) , o00 ) )
     if 67 - 67: OoOoOO00 / iII111i * OoO0O00 % i11iIiiIii
     lisp_update_rtr_updown ( I1IIiIIIii . rloc , False )
     continue
     if 76 - 76: OoO0O00
     if 92 - 92: iIii1I11I1II1 * O0 % I11i
     if 92 - 92: OoOoOO00 + oO0o
     if 89 - 89: IiII % iII111i / iIii1I11I1II1 . Ii1I . Oo0Ooo + ooOoO0o
     if 28 - 28: I1IiiI . iIii1I11I1II1
     if 12 - 12: I1Ii111 * OOooOOo
    if ( ii1 and ii1 . recently_echoed ( ) ) :
     lprint ( ( "Suppress RLOC-probe to {}, nonce-echo " + "received" ) . format ( red ( oo0o00OO , False ) ) )
     if 11 - 11: II111iiii % O0 % O0 % o0oOOo0O0Ooo
     continue
     if 45 - 45: OoooooooOO * oO0o
     if 74 - 74: ooOoO0o * I11i / oO0o - IiII + OoOoOO00
     if 16 - 16: Oo0Ooo
     if 29 - 29: Oo0Ooo . I1ii11iIi11i / II111iiii / oO0o / o0oOOo0O0Ooo + I11i
     if 4 - 4: OoooooooOO % I1ii11iIi11i . OoO0O00 * o0oOOo0O0Ooo + I1ii11iIi11i * IiII
     if 67 - 67: I1IiiI
    if ( I1IIiIIIii . last_rloc_probe != None ) :
     iiI = I1IIiIIIii . last_rloc_probe_reply
     if ( iiI == None ) : iiI = 0
     OoO0OO0OO000o = time . time ( ) - iiI
     if ( I1IIiIIIii . up_state ( ) and OoO0OO0OO000o >= LISP_RLOC_PROBE_REPLY_WAIT ) :
      if 93 - 93: ooOoO0o . Ii1I + IiII / Oo0Ooo % I11i
      I1IIiIIIii . state = LISP_RLOC_UNREACH_STATE
      I1IIiIIIii . last_state_change = lisp_get_timestamp ( )
      lisp_update_rtr_updown ( I1IIiIIIii . rloc , False )
      o00 = bold ( "unreachable" , False )
      lprint ( "RLOC {} went {}, probe it" . format ( red ( oo0o00OO , False ) , o00 ) )
      if 40 - 40: Oo0Ooo % OoOoOO00 . IiII / I1IiiI % OoooooooOO
      if 33 - 33: OOooOOo - OoooooooOO . iII111i
      lisp_mark_rlocs_for_other_eids ( O0ooooooOo0 )
      if 2 - 2: I11i + i1IIi
      if 52 - 52: I11i - OoO0O00 % I1Ii111 . OOooOOo
      if 90 - 90: O0 - Oo0Ooo / i1IIi * iIii1I11I1II1 % o0oOOo0O0Ooo / oO0o
    I1IIiIIIii . last_rloc_probe = lisp_get_timestamp ( )
    if 73 - 73: iII111i % iIii1I11I1II1 + o0oOOo0O0Ooo % Ii1I . II111iiii + IiII
    OOooO0o0oo00o = "" if I1IIiIIIii . unreach_state ( ) == False else " unreachable"
    if 59 - 59: Oo0Ooo
    if 40 - 40: o0oOOo0O0Ooo
    if 50 - 50: i11iIiiIii . I1ii11iIi11i * I1Ii111
    if 22 - 22: I1ii11iIi11i . i1IIi + I1ii11iIi11i / OoooooooOO - i11iIiiIii / iIii1I11I1II1
    if 96 - 96: o0oOOo0O0Ooo . I1Ii111 + Oo0Ooo . I11i + ooOoO0o
    if 33 - 33: OoO0O00 / OOooOOo % Oo0Ooo . o0oOOo0O0Ooo % II111iiii
    if 62 - 62: iII111i . OoooooooOO - i1IIi
    OO0oooO = ""
    o00O00oo0 = None
    if ( I1IIiIIIii . rloc_next_hop != None ) :
     OooOOOoOoo0O0 , o00O00oo0 = I1IIiIIIii . rloc_next_hop
     lisp_install_host_route ( oo0o00OO , o00O00oo0 , True )
     OO0oooO = ", send on nh {}({})" . format ( o00O00oo0 , OooOOOoOoo0O0 )
     if 38 - 38: I1ii11iIi11i / o0oOOo0O0Ooo
     if 95 - 95: iIii1I11I1II1 / OoOoOO00 % I1Ii111
     if 54 - 54: OoooooooOO % Ii1I
     if 100 - 100: OOooOOo - I11i . O0 * i1IIi % OoooooooOO - ooOoO0o
     if 54 - 54: O0 + I11i
    oo0000OoO = I1IIiIIIii . print_rloc_probe_rtt ( )
    ooooooO = oo0o00OO
    if ( I1IIiIIIii . translated_port != 0 ) :
     ooooooO += ":{}" . format ( I1IIiIIIii . translated_port )
     if 13 - 13: iIii1I11I1II1 - OoooooooOO . OoooooooOO + iII111i - OoOoOO00 % oO0o
    ooooooO = red ( ooooooO , False )
    if ( I1IIiIIIii . rloc_name != None ) :
     ooooooO += " (" + blue ( I1IIiIIIii . rloc_name , False ) + ")"
     if 11 - 11: ooOoO0o * iIii1I11I1II1 + OoooooooOO + OoO0O00
    lprint ( "Send {}{} {}, last rtt: {}{}" . format ( oO0oo000O , OOooO0o0oo00o ,
 ooooooO , oo0000OoO , OO0oooO ) )
    if 24 - 24: iII111i . OoO0O00 * Ii1I - OOooOOo . I11i
    if 90 - 90: I1ii11iIi11i % Oo0Ooo + I1ii11iIi11i - i1IIi
    if 94 - 94: OoooooooOO
    if 80 - 80: O0 * OOooOOo + i1IIi + i11iIiiIii * o0oOOo0O0Ooo
    if 14 - 14: II111iiii * OOooOOo - O0 / I1ii11iIi11i . OoO0O00 . ooOoO0o
    if 98 - 98: o0oOOo0O0Ooo . i1IIi
    if 83 - 83: i11iIiiIii + OOooOOo % iII111i
    if 59 - 59: I11i
    if ( I1IIiIIIii . rloc_next_hop != None ) :
     II11111Iii1I = lisp_get_host_route_next_hop ( oo0o00OO )
     if ( II11111Iii1I ) : lisp_install_host_route ( oo0o00OO , II11111Iii1I , False )
     if 23 - 23: OoOoOO00 * I1Ii111
     if 18 - 18: o0oOOo0O0Ooo % i11iIiiIii . Ii1I . O0
     if 85 - 85: I1ii11iIi11i * iIii1I11I1II1 + o0oOOo0O0Ooo * OoO0O00
     if 25 - 25: o0oOOo0O0Ooo / Ii1I / Oo0Ooo . ooOoO0o - ooOoO0o * O0
     if 14 - 14: O0 - Ii1I + iIii1I11I1II1 + II111iiii . ooOoO0o + Ii1I
     if 25 - 25: OoO0O00 * oO0o
    if ( I1IIiIIIii . rloc . is_null ( ) ) :
     I1IIiIIIii . rloc . copy_address ( iiI1I1Ii . rloc )
     if 29 - 29: OOooOOo - I1Ii111 - i11iIiiIii % i1IIi
     if 2 - 2: i11iIiiIii % iIii1I11I1II1 * OOooOOo
     if 45 - 45: oO0o + i1IIi + iII111i + o0oOOo0O0Ooo * OOooOOo + ooOoO0o
     if 83 - 83: OoO0O00 - ooOoO0o / OoooooooOO % iIii1I11I1II1 - II111iiii
     if 73 - 73: Oo0Ooo + II111iiii - IiII
    i1I1I = None if ( IIi1iiIII11 . is_null ( ) ) else ooOOoo0
    Ooii1 = ooOOoo0 if ( IIi1iiIII11 . is_null ( ) ) else IIi1iiIII11
    lisp_send_map_request ( lisp_sockets , 0 , i1I1I , Ooii1 , I1IIiIIIii )
    Oo0o0O0ooO0o = iiI1I1Ii
    if 72 - 72: ooOoO0o + oO0o + IiII * I1Ii111 % oO0o
    if 55 - 55: IiII . ooOoO0o - II111iiii * I1IiiI . I1Ii111
    if 39 - 39: iIii1I11I1II1 . II111iiii + oO0o . iII111i + Ii1I
    if 91 - 91: Ii1I + I1Ii111
    if ( o00O00oo0 ) : lisp_install_host_route ( oo0o00OO , o00O00oo0 , False )
    if 7 - 7: ooOoO0o + I1ii11iIi11i % OoO0O00
    if 45 - 45: i1IIi / o0oOOo0O0Ooo / iII111i * OoOoOO00 . IiII
    if 60 - 60: o0oOOo0O0Ooo
    if 63 - 63: i11iIiiIii * Oo0Ooo * I1Ii111
    if 56 - 56: I1Ii111 . i11iIiiIii
   if ( II11111Iii1I ) : lisp_install_host_route ( oo0o00OO , II11111Iii1I , True )
   if 76 - 76: II111iiii / ooOoO0o * i11iIiiIii . O0 / O0 - i11iIiiIii
   if 89 - 89: o0oOOo0O0Ooo . I1Ii111 * I11i + oO0o - OoooooooOO + OoO0O00
   if 25 - 25: i1IIi * I1Ii111 * iII111i . OoooooooOO
   if 70 - 70: iIii1I11I1II1
   I1I1 += 1
   if ( ( I1I1 % 10 ) == 0 ) : time . sleep ( 0.020 )
   if 1 - 1: II111iiii . I1IiiI + o0oOOo0O0Ooo
   if 5 - 5: I1ii11iIi11i % I11i - II111iiii
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
 oOooo0o = rloc_entry . json . json_string if rloc_entry . json else None
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
  I111iII1I11II . process_rloc_probe_reply ( i1 , Iii11I , ooOOoo0 , IIi1iiIII11 , III1I1IIi , ttl , oOooo0o )
  mrloc . process_rloc_probe_reply ( i1 , Iii11I , ooOOoo0 , IIi1iiIII11 , III1I1IIi , ttl , oOooo0o )
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
  I1IIiIIIii . process_rloc_probe_reply ( i1 , Iii11I , ooOOoo0 , IIi1iiIII11 , III1I1IIi , ttl , oOooo0o )
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
 for ooOOo0ooo in lisp_db_list :
  I1I1 += len ( ooOOo0ooo . dynamic_eids ) if ooOOo0ooo . dynamic_eid_configured ( ) else 1
  I1I1 += len ( ooOOo0ooo . eid . iid_list )
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
 for ooOOo0ooo in lisp_db_list :
  if ( eid . is_more_specific ( ooOOo0ooo . eid ) ) : return ( True )
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
    oO0ooo00OO = lisp_datetime ( OOOOOOOo00 [ 19 : : ] )
    if ( I11iIi1i1I1i1 . valid_datetime ( ) and oO0ooo00OO . valid_datetime ( ) ) :
     O0oOOO00 . datetime_lower = I11iIi1i1I1i1
     O0oOOO00 . datetime_upper = oO0ooo00OO
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
  II11111Iii1I = oOOo0ooO0 . split ( " " ) [ 0 ]
  oo00o . append ( II11111Iii1I )
  if 53 - 53: I11i . i11iIiiIii - iIii1I11I1II1 / I1Ii111
  if 86 - 86: i1IIi % OoO0O00 - OoooooooOO
 II11111Iii1I = None
 Ii1iIiI1I = O0O0iIIi11Ii
 O0O0iIIi11Ii = O0O0iIIi11Ii . split ( "." )
 for IiIIi1IiiIiI in range ( 1 , 255 ) :
  O0O0iIIi11Ii [ 3 ] = str ( IiIIi1IiiIiI )
  IiiIIi1 = "." . join ( O0O0iIIi11Ii )
  if ( IiiIIi1 in oo00o ) : continue
  if ( IiiIIi1 == Ii1iIiI1I ) : continue
  II11111Iii1I = IiiIIi1
  break
  if 63 - 63: o0oOOo0O0Ooo . iIii1I11I1II1 % IiII * i11iIiiIii
 if ( II11111Iii1I == None ) :
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
 OOO = I1IIiIIIii . split ( "." )
 ooOo0O = lisp_hex_string ( OOO [ 1 ] ) . zfill ( 2 )
 OOoo0oo0oO0O = lisp_hex_string ( OOO [ 2 ] ) . zfill ( 2 )
 OoOo0O0O00O000o = lisp_hex_string ( OOO [ 3 ] ) . zfill ( 2 )
 Ii = "00:00:00:{}:{}:{}" . format ( ooOo0O , OOoo0oo0oO0O , OoOo0O0O00O000o )
 iIo0o000OOO00O = "0000.00{}.{}{}" . format ( ooOo0O , OOoo0oo0oO0O , OoOo0O0O00O000o )
 IIiIiii1I1i = "arp -i vlan4094 -s {} {}" . format ( II11111Iii1I , Ii )
 os . system ( IIiIiii1I1i )
 if 43 - 43: OoOoOO00 - o0oOOo0O0Ooo
 if 22 - 22: i1IIi
 if 33 - 33: O0
 if 34 - 34: I1Ii111 . IiII % iII111i
 oOoo0O0oO0 = ( "mac address-table static {} vlan 4094 " + "interface vxlan 1 vtep {}" ) . format ( iIo0o000OOO00O , I1IIiIIIii )
 if 49 - 49: o0oOOo0O0Ooo
 lisp_send_to_arista ( oOoo0O0oO0 , None )
 if 11 - 11: I1ii11iIi11i - i11iIiiIii - I1ii11iIi11i - I1Ii111 . i1IIi
 if 55 - 55: I11i . IiII / i11iIiiIii / Oo0Ooo
 if 20 - 20: OoO0O00 - OoooooooOO . I1ii11iIi11i
 if 1 - 1: I11i
 if 7 - 7: II111iiii / iII111i / oO0o
 OoooO0O0o0oOO = "ip route add {} via {}" . format ( IiI1Iiii , II11111Iii1I )
 os . system ( OoooO0O0o0oOO )
 if 9 - 9: OoooooooOO / OOooOOo / O0 - OoOoOO00
 lprint ( "Hardware programmed with commands:" )
 OoooO0O0o0oOO = OoooO0O0o0oOO . replace ( IiI1Iiii , green ( IiI1Iiii , False ) )
 lprint ( "  " + OoooO0O0o0oOO )
 lprint ( "  " + IIiIiii1I1i )
 oOoo0O0oO0 = oOoo0O0oO0 . replace ( I1IIiIIIii , red ( I1IIiIIIii , False ) )
 lprint ( "  " + oOoo0O0oO0 )
 return
 if 22 - 22: Ii1I * I1ii11iIi11i * o0oOOo0O0Ooo - I1IiiI . i11iIiiIii
 if 30 - 30: O0 / oO0o * i11iIiiIii + iIii1I11I1II1 + O0 % I1IiiI
 if 95 - 95: ooOoO0o % OOooOOo
 if 17 - 17: i1IIi + Ii1I
 if 35 - 35: iIii1I11I1II1 - Oo0Ooo - OoooooooOO % I1ii11iIi11i
 if 27 - 27: Oo0Ooo * II111iiii - OOooOOo + o0oOOo0O0Ooo
 if 26 - 26: oO0o / I1ii11iIi11i - oO0o
def lisp_clear_hardware_walk ( mc , parms ) :
 IIII1 = mc . eid . print_prefix_no_iid ( )
 os . system ( "ip route delete {}" . format ( IIII1 ) )
 return ( [ True , None ] )
 if 9 - 9: ooOoO0o * iIii1I11I1II1 * OoooooooOO
 if 13 - 13: iII111i . i11iIiiIii * o0oOOo0O0Ooo . iII111i
 if 96 - 96: Ii1I
 if 90 - 90: II111iiii
 if 93 - 93: i11iIiiIii / Ii1I * Oo0Ooo . iII111i % iII111i / IiII
 if 15 - 15: OoOoOO00 % I1Ii111 - iIii1I11I1II1
 if 52 - 52: i11iIiiIii * ooOoO0o
 if 15 - 15: OoooooooOO . oO0o . i11iIiiIii / o0oOOo0O0Ooo
def lisp_clear_map_cache ( ) :
 global lisp_map_cache , lisp_rloc_probe_list
 global lisp_crypto_keys_by_rloc_encap , lisp_crypto_keys_by_rloc_decap
 global lisp_rtr_list , lisp_gleaned_groups
 global lisp_no_map_request_rate_limit
 if 91 - 91: ooOoO0o
 IiI111i = bold ( "User cleared" , False )
 I1I1 = lisp_map_cache . cache_count
 lprint ( "{} map-cache with {} entries" . format ( IiI111i , I1I1 ) )
 if 36 - 36: OoooooooOO . O0 + OOooOOo * I1IiiI . iIii1I11I1II1
 if ( lisp_program_hardware ) :
  lisp_map_cache . walk_cache ( lisp_clear_hardware_walk , None )
  if 93 - 93: OoOoOO00 % OoooooooOO * iIii1I11I1II1 . Ii1I % I1ii11iIi11i
 lisp_map_cache = lisp_cache ( )
 if 93 - 93: O0 % IiII
 if 40 - 40: iII111i - OoOoOO00 / IiII - I11i
 if 86 - 86: OoOoOO00 + oO0o / II111iiii % IiII % IiII * O0
 if 32 - 32: OoO0O00 / OoOoOO00 % iII111i * I11i . OoO0O00
 lisp_no_map_request_rate_limit = lisp_get_timestamp ( )
 if 26 - 26: IiII
 if 15 - 15: OoooooooOO / OoO0O00 - II111iiii / IiII + oO0o
 if 48 - 48: iII111i * OoO0O00 * OoOoOO00 * I11i
 if 74 - 74: ooOoO0o
 if 93 - 93: Oo0Ooo % ooOoO0o
 lisp_rloc_probe_list = { }
 if 38 - 38: II111iiii . I1Ii111 . iIii1I11I1II1 / o0oOOo0O0Ooo
 if 6 - 6: ooOoO0o - i1IIi * I1IiiI
 if 24 - 24: iIii1I11I1II1 / I1Ii111
 if 16 - 16: OoOoOO00 * I1Ii111 - I1IiiI / I1Ii111
 lisp_crypto_keys_by_rloc_encap = { }
 lisp_crypto_keys_by_rloc_decap = { }
 if 64 - 64: I1ii11iIi11i . i1IIi % II111iiii % Oo0Ooo + oO0o - I1IiiI
 if 24 - 24: IiII . II111iiii . II111iiii . OoOoOO00 . i11iIiiIii
 if 11 - 11: Ii1I
 if 82 - 82: I11i - i1IIi . Oo0Ooo * I1Ii111
 if 44 - 44: iII111i
 lisp_rtr_list = { }
 if 56 - 56: II111iiii / Oo0Ooo % IiII * II111iiii - iIii1I11I1II1 + ooOoO0o
 if 33 - 33: o0oOOo0O0Ooo . I11i / I1IiiI
 if 29 - 29: o0oOOo0O0Ooo - ooOoO0o
 if 59 - 59: I11i / IiII * OoO0O00 / IiII . I1Ii111
 lisp_gleaned_groups = { }
 if 82 - 82: OOooOOo . iIii1I11I1II1 + I1Ii111
 if 14 - 14: IiII . i11iIiiIii
 if 17 - 17: ooOoO0o % ooOoO0o * oO0o
 if 8 - 8: ooOoO0o + OoO0O00 . II111iiii / iIii1I11I1II1 - OOooOOo
 lisp_process_data_plane_restart ( True )
 return
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
def lisp_encapsulate_rloc_probe ( lisp_sockets , rloc , nat_info , packet ) :
 if ( len ( lisp_sockets ) != 4 ) : return
 if 10 - 10: IiII - Oo0Ooo % ooOoO0o
 IIiI11ii111i = lisp_myrlocs [ 0 ]
 if 79 - 79: ooOoO0o / i11iIiiIii
 if 36 - 36: OoOoOO00 - OoOoOO00
 if 7 - 7: OoOoOO00 - OoO0O00 % OoOoOO00 . I1ii11iIi11i % Oo0Ooo * iII111i
 if 90 - 90: IiII - OOooOOo + iIii1I11I1II1
 if 88 - 88: ooOoO0o . o0oOOo0O0Ooo . OOooOOo - I11i
 IiiI1iii1iIiiI = len ( packet ) + 28
 Ooo0oO = struct . pack ( "BBHIBBHII" , 0x45 , 0 , socket . htons ( IiiI1iii1iIiiI ) , 0 , 64 ,
 17 , 0 , socket . htonl ( IIiI11ii111i . address ) , socket . htonl ( rloc . address ) )
 Ooo0oO = lisp_ip_checksum ( Ooo0oO )
 if 76 - 76: IiII % I1IiiI . iII111i
 o0oOo00 = struct . pack ( "HHHH" , 0 , socket . htons ( LISP_CTRL_PORT ) ,
 socket . htons ( IiiI1iii1iIiiI - 20 ) , 0 )
 if 5 - 5: ooOoO0o . oO0o - OoOoOO00 - OoooooooOO
 if 2 - 2: OOooOOo
 if 37 - 37: IiII - iIii1I11I1II1 * i11iIiiIii . ooOoO0o
 if 78 - 78: OOooOOo - I1ii11iIi11i + iII111i % OoOoOO00
 packet = lisp_packet ( Ooo0oO + o0oOo00 + packet )
 if 28 - 28: I11i + i1IIi / i11iIiiIii * OOooOOo * II111iiii
 if 78 - 78: OoO0O00 - i1IIi % I1Ii111
 if 87 - 87: I11i
 if 37 - 37: iII111i . I1Ii111 - iII111i - I11i - iIii1I11I1II1 - II111iiii
 packet . inner_dest . copy_address ( rloc )
 packet . inner_dest . instance_id = 0xffffff
 packet . inner_source . copy_address ( IIiI11ii111i )
 packet . inner_ttl = 64
 packet . outer_dest . copy_address ( rloc )
 packet . outer_source . copy_address ( IIiI11ii111i )
 packet . outer_version = packet . outer_dest . afi_to_version ( )
 packet . outer_ttl = 64
 packet . encap_port = nat_info . port if nat_info else LISP_DATA_PORT
 if 80 - 80: I1Ii111 % O0 - IiII / II111iiii + i1IIi
 o0oooOoOoOo = red ( rloc . print_address_no_iid ( ) , False )
 if ( nat_info ) :
  I1I1111I11I = " {}" . format ( blue ( nat_info . hostname , False ) )
  oO0oo000O = bold ( "RLOC-probe request" , False )
 else :
  I1I1111I11I = ""
  oO0oo000O = bold ( "RLOC-probe reply" , False )
  if 4 - 4: OOooOOo + II111iiii
  if 1 - 1: OoooooooOO * I1Ii111 - I11i / IiII
 lprint ( ( "Data encapsulate {} to {}{} port {} for " + "NAT-traversal" ) . format ( oO0oo000O , o0oooOoOoOo , I1I1111I11I , packet . encap_port ) )
 if 43 - 43: i11iIiiIii * I1IiiI
 if 48 - 48: Oo0Ooo - OOooOOo / iII111i % I1ii11iIi11i . OoOoOO00
 if 6 - 6: i11iIiiIii
 if 51 - 51: o0oOOo0O0Ooo - OoooooooOO - I11i % i11iIiiIii / I1IiiI + IiII
 if 91 - 91: O0
 if ( packet . encode ( None ) == None ) : return
 packet . print_packet ( "Send" , True )
 if 13 - 13: o0oOOo0O0Ooo
 IiiIii11I1i1I = lisp_sockets [ 3 ]
 packet . send_packet ( IiiIii11I1i1I , packet . outer_dest )
 del ( packet )
 return
 if 61 - 61: o0oOOo0O0Ooo * OoOoOO00 % i11iIiiIii - OoO0O00 / OoOoOO00 . OoO0O00
 if 40 - 40: O0 * OoooooooOO
 if 39 - 39: OoooooooOO % II111iiii . o0oOOo0O0Ooo
 if 29 - 29: I11i . o0oOOo0O0Ooo . i1IIi . o0oOOo0O0Ooo
 if 77 - 77: iIii1I11I1II1 + iIii1I11I1II1
 if 52 - 52: I1ii11iIi11i - IiII % I1IiiI % i1IIi
 if 98 - 98: I1Ii111 + II111iiii % OoO0O00 % iII111i
 if 54 - 54: II111iiii . ooOoO0o . iII111i - I1IiiI
def lisp_get_default_route_next_hops ( ) :
 if 97 - 97: oO0o - O0 / II111iiii * II111iiii - oO0o * IiII
 if 97 - 97: IiII % OoO0O00 . OoOoOO00 - Ii1I
 if 28 - 28: O0 . I11i . I1IiiI - Ii1I - iII111i - iIii1I11I1II1
 if 14 - 14: OOooOOo + ooOoO0o
 if ( lisp_is_macos ( ) ) :
  ooO0ooooO = "route -n get default"
  oOOO0OoO = commands . getoutput ( ooO0ooooO ) . split ( "\n" )
  iiiI1i1Iii1ii = II1i = None
  for OOO000 in oOOO0OoO :
   if ( OOO000 . find ( "gateway: " ) != - 1 ) : iiiI1i1Iii1ii = OOO000 . split ( ": " ) [ 1 ]
   if ( OOO000 . find ( "interface: " ) != - 1 ) : II1i = OOO000 . split ( ": " ) [ 1 ]
   if 72 - 72: iIii1I11I1II1 - I1IiiI * OoO0O00 * o0oOOo0O0Ooo - I1IiiI . I1ii11iIi11i
  return ( [ [ II1i , iiiI1i1Iii1ii ] ] )
  if 46 - 46: i1IIi . OoOoOO00 . I1Ii111
  if 84 - 84: OoOoOO00 * OoOoOO00 % o0oOOo0O0Ooo * II111iiii
  if 28 - 28: ooOoO0o % OoOoOO00 + ooOoO0o
  if 68 - 68: II111iiii
  if 71 - 71: I1Ii111 % Ii1I - I11i / I11i - Ii1I
 ooO0ooooO = "ip route | egrep 'default via'"
 O0o00o000 = commands . getoutput ( ooO0ooooO ) . split ( "\n" )
 if 54 - 54: Oo0Ooo . OoO0O00 * iII111i . i1IIi - o0oOOo0O0Ooo
 O0OoooOoo = [ ]
 for o0O00OOo in O0o00o000 :
  if ( o0O00OOo . find ( " metric " ) != - 1 ) : continue
  O0OOOO0o0O = o0O00OOo . split ( " " )
  try :
   I1iI11I1i = O0OOOO0o0O . index ( "via" ) + 1
   if ( I1iI11I1i >= len ( O0OOOO0o0O ) ) : continue
   OO0OoOOoO00Oo = O0OOOO0o0O . index ( "dev" ) + 1
   if ( OO0OoOOoO00Oo >= len ( O0OOOO0o0O ) ) : continue
  except :
   continue
   if 94 - 94: O0 - OoooooooOO / OOooOOo
   if 52 - 52: IiII % OOooOOo . II111iiii + IiII + i11iIiiIii * iIii1I11I1II1
  O0OoooOoo . append ( [ O0OOOO0o0O [ OO0OoOOoO00Oo ] , O0OOOO0o0O [ I1iI11I1i ] ] )
  if 21 - 21: OoooooooOO + iIii1I11I1II1 + OoOoOO00 . II111iiii . Ii1I / iII111i
 return ( O0OoooOoo )
 if 69 - 69: iIii1I11I1II1 % I1Ii111 % OOooOOo + O0 - OoOoOO00 % oO0o
 if 70 - 70: oO0o - I1IiiI + Ii1I
 if 54 - 54: OoOoOO00 / ooOoO0o - I1IiiI
 if 37 - 37: o0oOOo0O0Ooo
 if 57 - 57: iII111i / i1IIi / i1IIi + IiII
 if 75 - 75: IiII / O0
 if 72 - 72: I11i
def lisp_get_host_route_next_hop ( rloc ) :
 ooO0ooooO = "ip route | egrep '{} via'" . format ( rloc )
 o0O00OOo = commands . getoutput ( ooO0ooooO ) . split ( " " )
 if 35 - 35: I11i % OoooooooOO / i1IIi * i1IIi / I1IiiI
 try : ooo = o0O00OOo . index ( "via" ) + 1
 except : return ( None )
 if 42 - 42: I11i - i1IIi - oO0o / I11i + Ii1I + ooOoO0o
 if ( ooo >= len ( o0O00OOo ) ) : return ( None )
 return ( o0O00OOo [ ooo ] )
 if 23 - 23: OoOoOO00 . oO0o - iII111i
 if 27 - 27: Oo0Ooo * OOooOOo - OoOoOO00
 if 1 - 1: II111iiii * i11iIiiIii . OoooooooOO
 if 37 - 37: OoooooooOO + O0 . I11i % OoOoOO00
 if 57 - 57: I1Ii111 . OOooOOo + I1Ii111 . iIii1I11I1II1 / oO0o / O0
 if 88 - 88: I1Ii111
 if 16 - 16: Oo0Ooo . ooOoO0o / OoO0O00 / o0oOOo0O0Ooo . OoooooooOO * OoO0O00
def lisp_install_host_route ( dest , nh , install ) :
 install = "add" if install else "delete"
 OO0oooO = "none" if nh == None else nh
 if 50 - 50: II111iiii + I11i . OoooooooOO . I1Ii111 - OOooOOo
 lprint ( "{} host-route {}, nh {}" . format ( install . title ( ) , dest , OO0oooO ) )
 if 83 - 83: oO0o
 if ( nh == None ) :
  iI1I1 = "ip route {} {}/32" . format ( install , dest )
 else :
  iI1I1 = "ip route {} {}/32 via {}" . format ( install , dest , nh )
  if 100 - 100: I1Ii111 + o0oOOo0O0Ooo * oO0o / oO0o . oO0o + iII111i
 os . system ( iI1I1 )
 return
 if 71 - 71: II111iiii + iII111i + O0 % Oo0Ooo / I1IiiI
 if 52 - 52: Oo0Ooo . I1Ii111 * i1IIi / Oo0Ooo / OoO0O00
 if 29 - 29: iII111i
 if 91 - 91: Oo0Ooo - IiII
 if 47 - 47: iII111i / OOooOOo + iII111i
 if 69 - 69: I1IiiI . I1ii11iIi11i
 if 18 - 18: I11i * I1IiiI
 if 42 - 42: i1IIi . I1Ii111 - ooOoO0o + I11i / oO0o
def lisp_checkpoint ( checkpoint_list ) :
 if ( lisp_checkpoint_map_cache == False ) : return
 if 60 - 60: i1IIi + OoooooooOO % i11iIiiIii / IiII % Oo0Ooo + I1IiiI
 OOO000 = open ( lisp_checkpoint_filename , "w" )
 for i1ii1i1Ii11 in checkpoint_list :
  OOO000 . write ( i1ii1i1Ii11 + "\n" )
  if 87 - 87: Ii1I % OoooooooOO % I1Ii111 * i11iIiiIii * OoOoOO00
 OOO000 . close ( )
 lprint ( "{} {} entries to file '{}'" . format ( bold ( "Checkpoint" , False ) ,
 len ( checkpoint_list ) , lisp_checkpoint_filename ) )
 return
 if 78 - 78: I11i
 if 62 - 62: iIii1I11I1II1 . o0oOOo0O0Ooo . ooOoO0o % oO0o % O0 % oO0o
 if 51 - 51: Oo0Ooo / IiII - Oo0Ooo
 if 71 - 71: I11i * I1ii11iIi11i * OOooOOo * o0oOOo0O0Ooo
 if 53 - 53: I1IiiI % I1IiiI
 if 80 - 80: OoO0O00 - i11iIiiIii / iII111i * I1ii11iIi11i / I1IiiI - I1Ii111
 if 85 - 85: IiII
 if 72 - 72: iII111i * OoOoOO00
def lisp_load_checkpoint ( ) :
 if ( lisp_checkpoint_map_cache == False ) : return
 if ( os . path . exists ( lisp_checkpoint_filename ) == False ) : return
 if 65 - 65: iIii1I11I1II1 / iIii1I11I1II1 % O0 / II111iiii . OOooOOo . O0
 OOO000 = open ( lisp_checkpoint_filename , "r" )
 if 65 - 65: I11i
 I1I1 = 0
 for i1ii1i1Ii11 in OOO000 :
  I1I1 += 1
  oOo = i1ii1i1Ii11 . split ( " rloc " )
  ooOOo = [ ] if ( oOo [ 1 ] in [ "native-forward\n" , "\n" ] ) else oOo [ 1 ] . split ( ", " )
  if 35 - 35: o0oOOo0O0Ooo - i11iIiiIii
  if 78 - 78: ooOoO0o - II111iiii - i1IIi
  OoO0oOOooOO = [ ]
  for I1IIiIIIii in ooOOo :
   i1III111 = lisp_rloc ( False )
   O0OOOO0o0O = I1IIiIIIii . split ( " " )
   i1III111 . rloc . store_address ( O0OOOO0o0O [ 0 ] )
   i1III111 . priority = int ( O0OOOO0o0O [ 1 ] )
   i1III111 . weight = int ( O0OOOO0o0O [ 2 ] )
   OoO0oOOooOO . append ( i1III111 )
   if 18 - 18: OoooooooOO % OoOoOO00 - IiII / oO0o . OOooOOo . I1IiiI
   if 77 - 77: I1ii11iIi11i . OoO0O00 / OoOoOO00 / O0
  o0o000Oo = lisp_mapping ( "" , "" , OoO0oOOooOO )
  if ( o0o000Oo != None ) :
   o0o000Oo . eid . store_prefix ( oOo [ 0 ] )
   o0o000Oo . checkpoint_entry = True
   o0o000Oo . map_cache_ttl = LISP_NMR_TTL * 60
   if ( OoO0oOOooOO == [ ] ) : o0o000Oo . action = LISP_NATIVE_FORWARD_ACTION
   o0o000Oo . add_cache ( )
   continue
   if 67 - 67: ooOoO0o % I11i % oO0o
   if 74 - 74: II111iiii
  I1I1 -= 1
  if 44 - 44: Oo0Ooo + OoO0O00 + OoOoOO00 - I1IiiI
  if 68 - 68: i11iIiiIii / OOooOOo . i1IIi . i11iIiiIii . I11i
 OOO000 . close ( )
 lprint ( "{} {} map-cache entries from file '{}'" . format (
 bold ( "Loaded" , False ) , I1I1 , lisp_checkpoint_filename ) )
 return
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
def lisp_write_checkpoint_entry ( checkpoint_list , mc ) :
 if ( lisp_checkpoint_map_cache == False ) : return
 if 91 - 91: ooOoO0o
 i1ii1i1Ii11 = "{} rloc " . format ( mc . eid . print_prefix ( ) )
 if 96 - 96: I1IiiI . OOooOOo
 for i1III111 in mc . rloc_set :
  if ( i1III111 . rloc . is_null ( ) ) : continue
  i1ii1i1Ii11 += "{} {} {}, " . format ( i1III111 . rloc . print_address_no_iid ( ) ,
 i1III111 . priority , i1III111 . weight )
  if 94 - 94: OoooooooOO + II111iiii % ooOoO0o - II111iiii / O0
  if 34 - 34: IiII % oO0o
 if ( mc . rloc_set != [ ] ) :
  i1ii1i1Ii11 = i1ii1i1Ii11 [ 0 : - 2 ]
 elif ( mc . action == LISP_NATIVE_FORWARD_ACTION ) :
  i1ii1i1Ii11 += "native-forward"
  if 54 - 54: I1IiiI
  if 80 - 80: OoOoOO00 . I1IiiI / I1ii11iIi11i . iII111i
 checkpoint_list . append ( i1ii1i1Ii11 )
 return
 if 31 - 31: I11i * o0oOOo0O0Ooo
 if 17 - 17: Ii1I * iIii1I11I1II1
 if 9 - 9: o0oOOo0O0Ooo - IiII
 if 78 - 78: i11iIiiIii . o0oOOo0O0Ooo
 if 72 - 72: Oo0Ooo % II111iiii + O0 * OoOoOO00 - OOooOOo + I1Ii111
 if 23 - 23: I1IiiI - O0 - iII111i . II111iiii / oO0o
 if 1 - 1: I11i . OOooOOo / oO0o % I11i * Oo0Ooo + Oo0Ooo
def lisp_check_dp_socket ( ) :
 i1Ii11IIIi = lisp_ipc_dp_socket_name
 if ( os . path . exists ( i1Ii11IIIi ) == False ) :
  ooO0 = bold ( "does not exist" , False )
  lprint ( "Socket '{}' {}" . format ( i1Ii11IIIi , ooO0 ) )
  return ( False )
  if 43 - 43: I1ii11iIi11i - Oo0Ooo . oO0o
 return ( True )
 if 2 - 2: OoOoOO00 . I1IiiI
 if 88 - 88: I1IiiI
 if 34 - 34: ooOoO0o + I1Ii111 / iIii1I11I1II1 + Ii1I . o0oOOo0O0Ooo * OoO0O00
 if 74 - 74: i1IIi / iIii1I11I1II1 . I1ii11iIi11i
 if 71 - 71: ooOoO0o % ooOoO0o * iII111i / Ii1I * O0
 if 21 - 21: o0oOOo0O0Ooo * o0oOOo0O0Ooo - OoOoOO00 % OoOoOO00
 if 8 - 8: I1ii11iIi11i
def lisp_write_to_dp_socket ( entry ) :
 try :
  II1i1I1IIiII1 = json . dumps ( entry )
  O00oOooo0o = bold ( "Write IPC" , False )
  lprint ( "{} record to named socket: '{}'" . format ( O00oOooo0o , II1i1I1IIiII1 ) )
  lisp_ipc_dp_socket . sendto ( II1i1I1IIiII1 , lisp_ipc_dp_socket_name )
 except :
  lprint ( "Failed to write IPC record to named socket: '{}'" . format ( II1i1I1IIiII1 ) )
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
def lisp_write_ipc_keys ( rloc ) :
 oo0o00OO = rloc . rloc . print_address_no_iid ( )
 Oo0O00O = rloc . translated_port
 if ( Oo0O00O != 0 ) : oo0o00OO += ":" + str ( Oo0O00O )
 if ( lisp_rloc_probe_list . has_key ( oo0o00OO ) == False ) : return
 if 29 - 29: OoooooooOO / iII111i + I1IiiI % I11i - Ii1I
 for O0OOOO0o0O , oOo , i11ii in lisp_rloc_probe_list [ oo0o00OO ] :
  o0o000Oo = lisp_map_cache . lookup_cache ( oOo , True )
  if ( o0o000Oo == None ) : continue
  lisp_write_ipc_map_cache ( True , o0o000Oo )
  if 75 - 75: i1IIi
 return
 if 80 - 80: O0
 if 16 - 16: OOooOOo - iII111i
 if 5 - 5: o0oOOo0O0Ooo % ooOoO0o % O0 % I1ii11iIi11i + Oo0Ooo
 if 82 - 82: oO0o / iIii1I11I1II1 % ooOoO0o . Ii1I / i1IIi - I1Ii111
 if 15 - 15: I11i - OOooOOo . II111iiii . iIii1I11I1II1
 if 93 - 93: I11i + o0oOOo0O0Ooo / OOooOOo + Ii1I % Oo0Ooo % I1ii11iIi11i
 if 72 - 72: IiII / II111iiii
def lisp_write_ipc_map_cache ( add_or_delete , mc , dont_send = False ) :
 if ( lisp_i_am_etr ) : return
 if ( lisp_ipc_dp_socket == None ) : return
 if ( lisp_check_dp_socket ( ) == False ) : return
 if 25 - 25: i1IIi + OoOoOO00 + oO0o + OoooooooOO
 if 21 - 21: I1ii11iIi11i
 if 60 - 60: i1IIi / OoO0O00 . Ii1I
 if 16 - 16: i11iIiiIii + OoOoOO00 % Oo0Ooo + I1ii11iIi11i * Ii1I / I1Ii111
 IiI1III = "add" if add_or_delete else "delete"
 i1ii1i1Ii11 = { "type" : "map-cache" , "opcode" : IiI1III }
 if 26 - 26: iII111i
 o0oO0O00 = ( mc . group . is_null ( ) == False )
 if ( o0oO0O00 ) :
  i1ii1i1Ii11 [ "eid-prefix" ] = mc . group . print_prefix_no_iid ( )
  i1ii1i1Ii11 [ "rles" ] = [ ]
 else :
  i1ii1i1Ii11 [ "eid-prefix" ] = mc . eid . print_prefix_no_iid ( )
  i1ii1i1Ii11 [ "rlocs" ] = [ ]
  if 31 - 31: iII111i
 i1ii1i1Ii11 [ "instance-id" ] = str ( mc . eid . instance_id )
 if 45 - 45: OoO0O00
 if ( o0oO0O00 ) :
  if ( len ( mc . rloc_set ) >= 1 and mc . rloc_set [ 0 ] . rle ) :
   for Iii in mc . rloc_set [ 0 ] . rle . rle_forwarding_list :
    IiiIIi1 = Iii . address . print_address_no_iid ( )
    Oo0O00O = str ( 4341 ) if Iii . translated_port == 0 else str ( Iii . translated_port )
    if 55 - 55: iIii1I11I1II1 % iIii1I11I1II1 + I11i - ooOoO0o + I1IiiI * O0
    O0OOOO0o0O = { "rle" : IiiIIi1 , "port" : Oo0O00O }
    II11iI11i1 , I11ii1i = Iii . get_encap_keys ( )
    O0OOOO0o0O = lisp_build_json_keys ( O0OOOO0o0O , II11iI11i1 , I11ii1i , "encrypt-key" )
    i1ii1i1Ii11 [ "rles" ] . append ( O0OOOO0o0O )
    if 34 - 34: OoO0O00 + Oo0Ooo . OoOoOO00 * OOooOOo
    if 86 - 86: IiII * OOooOOo + Ii1I
 else :
  for I1IIiIIIii in mc . rloc_set :
   if ( I1IIiIIIii . rloc . is_ipv4 ( ) == False and I1IIiIIIii . rloc . is_ipv6 ( ) == False ) :
    continue
    if 62 - 62: I11i
   if ( I1IIiIIIii . up_state ( ) == False ) : continue
   if 86 - 86: Oo0Ooo % II111iiii + I1Ii111 / I1ii11iIi11i
   Oo0O00O = str ( 4341 ) if I1IIiIIIii . translated_port == 0 else str ( I1IIiIIIii . translated_port )
   if 15 - 15: I1IiiI / I1Ii111 % iII111i
   O0OOOO0o0O = { "rloc" : I1IIiIIIii . rloc . print_address_no_iid ( ) , "priority" :
 str ( I1IIiIIIii . priority ) , "weight" : str ( I1IIiIIIii . weight ) , "port" :
 Oo0O00O }
   II11iI11i1 , I11ii1i = I1IIiIIIii . get_encap_keys ( )
   O0OOOO0o0O = lisp_build_json_keys ( O0OOOO0o0O , II11iI11i1 , I11ii1i , "encrypt-key" )
   i1ii1i1Ii11 [ "rlocs" ] . append ( O0OOOO0o0O )
   if 57 - 57: I1Ii111 . iIii1I11I1II1 / Oo0Ooo / IiII / iII111i * OoOoOO00
   if 35 - 35: i1IIi + I1Ii111 - ooOoO0o . I1ii11iIi11i + Oo0Ooo
   if 43 - 43: oO0o . OoO0O00 * i1IIi
 if ( dont_send == False ) : lisp_write_to_dp_socket ( i1ii1i1Ii11 )
 return ( i1ii1i1Ii11 )
 if 1 - 1: ooOoO0o / i1IIi
 if 42 - 42: I1ii11iIi11i * ooOoO0o + OoOoOO00 % I1ii11iIi11i . IiII
 if 75 - 75: OoO0O00 * i1IIi - OOooOOo % II111iiii % OoO0O00 - OoOoOO00
 if 75 - 75: I11i * IiII * ooOoO0o
 if 31 - 31: Ii1I
 if 72 - 72: OOooOOo * Ii1I % OoO0O00
 if 72 - 72: OoOoOO00 + o0oOOo0O0Ooo - i1IIi - OoO0O00 % OoOoOO00
def lisp_write_ipc_decap_key ( rloc_addr , keys ) :
 if ( lisp_i_am_itr ) : return
 if ( lisp_ipc_dp_socket == None ) : return
 if ( lisp_check_dp_socket ( ) == False ) : return
 if 42 - 42: oO0o / i1IIi . IiII
 if 12 - 12: i11iIiiIii . ooOoO0o
 if 80 - 80: O0 / iIii1I11I1II1 % iII111i * ooOoO0o / i11iIiiIii . OoOoOO00
 if 88 - 88: OoooooooOO . I1IiiI
 if ( keys == None or len ( keys ) == 0 or keys [ 1 ] == None ) : return
 if 6 - 6: I1Ii111 - i11iIiiIii - oO0o
 II11iI11i1 = keys [ 1 ] . encrypt_key
 I11ii1i = keys [ 1 ] . icv_key
 if 7 - 7: i1IIi
 if 6 - 6: OoooooooOO - Oo0Ooo - I1ii11iIi11i
 if 34 - 34: iII111i + i11iIiiIii . IiII
 if 54 - 54: Oo0Ooo + I11i - iII111i * ooOoO0o % i11iIiiIii . IiII
 ii1iiIi1I1 = rloc_addr . split ( ":" )
 if ( len ( ii1iiIi1I1 ) == 1 ) :
  i1ii1i1Ii11 = { "type" : "decap-keys" , "rloc" : ii1iiIi1I1 [ 0 ] }
 else :
  i1ii1i1Ii11 = { "type" : "decap-keys" , "rloc" : ii1iiIi1I1 [ 0 ] , "port" : ii1iiIi1I1 [ 1 ] }
  if 51 - 51: OoooooooOO . Ii1I % OoooooooOO - I1IiiI + I1Ii111 % oO0o
 i1ii1i1Ii11 = lisp_build_json_keys ( i1ii1i1Ii11 , II11iI11i1 , I11ii1i , "decrypt-key" )
 if 28 - 28: i11iIiiIii - I1IiiI * OoO0O00
 lisp_write_to_dp_socket ( i1ii1i1Ii11 )
 return
 if 19 - 19: OoooooooOO
 if 34 - 34: OoOoOO00 . oO0o
 if 53 - 53: oO0o + OoooooooOO * ooOoO0o
 if 85 - 85: I1ii11iIi11i - o0oOOo0O0Ooo % o0oOOo0O0Ooo % iII111i * OoOoOO00
 if 50 - 50: I1Ii111 + I1Ii111 + I11i - OoOoOO00
 if 65 - 65: oO0o / I11i + iII111i - I1ii11iIi11i
 if 80 - 80: II111iiii . i11iIiiIii
 if 66 - 66: ooOoO0o * iII111i * OOooOOo % OoO0O00 / I1ii11iIi11i
def lisp_build_json_keys ( entry , ekey , ikey , key_type ) :
 if ( ekey == None ) : return ( entry )
 if 33 - 33: iIii1I11I1II1
 entry [ "keys" ] = [ ]
 Oo000O000 = { "key-id" : "1" , key_type : ekey , "icv-key" : ikey }
 entry [ "keys" ] . append ( Oo000O000 )
 return ( entry )
 if 52 - 52: iIii1I11I1II1 + O0
 if 84 - 84: OOooOOo / iII111i . I1IiiI / O0 % OOooOOo . iII111i
 if 32 - 32: OoO0O00 + OoO0O00 % o0oOOo0O0Ooo / O0
 if 29 - 29: iII111i % I1Ii111
 if 95 - 95: OOooOOo - ooOoO0o % i1IIi / O0 % I11i . IiII
 if 63 - 63: ooOoO0o
 if 22 - 22: OOooOOo . i11iIiiIii + II111iiii - Oo0Ooo % i1IIi / o0oOOo0O0Ooo
def lisp_write_ipc_database_mappings ( ephem_port ) :
 if ( lisp_i_am_etr == False ) : return
 if ( lisp_ipc_dp_socket == None ) : return
 if ( lisp_check_dp_socket ( ) == False ) : return
 if 90 - 90: IiII
 if 38 - 38: i1IIi / ooOoO0o / I11i * I1ii11iIi11i / II111iiii . iIii1I11I1II1
 if 52 - 52: I1ii11iIi11i % ooOoO0o * Ii1I * IiII + IiII / i11iIiiIii
 if 51 - 51: iIii1I11I1II1 * o0oOOo0O0Ooo % o0oOOo0O0Ooo . Ii1I / OoooooooOO
 i1ii1i1Ii11 = { "type" : "database-mappings" , "database-mappings" : [ ] }
 if 23 - 23: oO0o * I1IiiI - oO0o - ooOoO0o . IiII / i11iIiiIii
 if 53 - 53: Ii1I * Ii1I . OoOoOO00 . OOooOOo / I1ii11iIi11i % O0
 if 98 - 98: OOooOOo
 if 11 - 11: OOooOOo * iIii1I11I1II1 % IiII - I1IiiI . I11i
 for ooOOo0ooo in lisp_db_list :
  if ( ooOOo0ooo . eid . is_ipv4 ( ) == False and ooOOo0ooo . eid . is_ipv6 ( ) == False ) : continue
  III1II11i1 = { "instance-id" : str ( ooOOo0ooo . eid . instance_id ) ,
 "eid-prefix" : ooOOo0ooo . eid . print_prefix_no_iid ( ) }
  i1ii1i1Ii11 [ "database-mappings" ] . append ( III1II11i1 )
  if 62 - 62: i11iIiiIii % iIii1I11I1II1 / IiII . I1IiiI * O0
 lisp_write_to_dp_socket ( i1ii1i1Ii11 )
 if 17 - 17: I1ii11iIi11i - I1Ii111 % II111iiii + OOooOOo
 if 45 - 45: I1Ii111 + iII111i - iIii1I11I1II1 / Oo0Ooo
 if 92 - 92: iIii1I11I1II1 . OoO0O00 - I11i % I1ii11iIi11i / i11iIiiIii
 if 4 - 4: Oo0Ooo / I1IiiI * i1IIi . II111iiii
 if 13 - 13: i1IIi
 i1ii1i1Ii11 = { "type" : "etr-nat-port" , "port" : ephem_port }
 lisp_write_to_dp_socket ( i1ii1i1Ii11 )
 return
 if 39 - 39: OOooOOo
 if 73 - 73: OoO0O00 . ooOoO0o
 if 13 - 13: o0oOOo0O0Ooo - OoOoOO00
 if 60 - 60: OoO0O00
 if 17 - 17: i11iIiiIii % i1IIi % I1IiiI % ooOoO0o + I1Ii111 + Oo0Ooo
 if 16 - 16: iII111i . I1ii11iIi11i . oO0o . OoO0O00
 if 90 - 90: i1IIi . ooOoO0o + i11iIiiIii * OoooooooOO
def lisp_write_ipc_interfaces ( ) :
 if ( lisp_i_am_etr ) : return
 if ( lisp_ipc_dp_socket == None ) : return
 if ( lisp_check_dp_socket ( ) == False ) : return
 if 30 - 30: iII111i . OoO0O00 . i11iIiiIii / I1ii11iIi11i * Oo0Ooo
 if 38 - 38: IiII + II111iiii
 if 20 - 20: iII111i * I1IiiI * iII111i - o0oOOo0O0Ooo + i1IIi + ooOoO0o
 if 49 - 49: II111iiii * I1IiiI / oO0o
 i1ii1i1Ii11 = { "type" : "interfaces" , "interfaces" : [ ] }
 if 50 - 50: Ii1I + O0 . I1IiiI * Oo0Ooo
 for II1i in lisp_myinterfaces . values ( ) :
  if ( II1i . instance_id == None ) : continue
  III1II11i1 = { "interface" : II1i . device ,
 "instance-id" : str ( II1i . instance_id ) }
  i1ii1i1Ii11 [ "interfaces" ] . append ( III1II11i1 )
  if 15 - 15: Oo0Ooo
  if 53 - 53: OoooooooOO * O0 / iII111i * ooOoO0o % I1Ii111 + OOooOOo
 lisp_write_to_dp_socket ( i1ii1i1Ii11 )
 return
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
def lisp_parse_auth_key ( value ) :
 O0ooooooOo0 = value . split ( "[" )
 ooO0oOO0oOo00 = { }
 if ( len ( O0ooooooOo0 ) == 1 ) :
  ooO0oOO0oOo00 [ 0 ] = value
  return ( ooO0oOO0oOo00 )
  if 44 - 44: O0
  if 12 - 12: I1ii11iIi11i
 for OOOOOOOo00 in O0ooooooOo0 :
  if ( OOOOOOOo00 == "" ) : continue
  ooo = OOOOOOOo00 . find ( "]" )
  I1I1I1 = OOOOOOOo00 [ 0 : ooo ]
  try : I1I1I1 = int ( I1I1I1 )
  except : return
  if 80 - 80: oO0o / i1IIi * iIii1I11I1II1
  ooO0oOO0oOo00 [ I1I1I1 ] = OOOOOOOo00 [ ooo + 1 : : ]
  if 38 - 38: Ii1I
 return ( ooO0oOO0oOo00 )
 if 20 - 20: iIii1I11I1II1 + Oo0Ooo - Ii1I / i11iIiiIii . OoO0O00
 if 66 - 66: OoooooooOO - Ii1I / iII111i . I1IiiI + I1ii11iIi11i - I1Ii111
 if 36 - 36: I1Ii111 - OoO0O00 . I1ii11iIi11i * I1ii11iIi11i
 if 9 - 9: OOooOOo - oO0o - iIii1I11I1II1 * i11iIiiIii / I11i
 if 2 - 2: i1IIi % iII111i * ooOoO0o / OoOoOO00 + Oo0Ooo
 if 59 - 59: i11iIiiIii / I1IiiI * iII111i
 if 16 - 16: i11iIiiIii * II111iiii - ooOoO0o
 if 80 - 80: iIii1I11I1II1 + iIii1I11I1II1 + I1Ii111 - IiII * iII111i - Ii1I
 if 89 - 89: O0 * ooOoO0o
 if 36 - 36: I1ii11iIi11i * II111iiii * iII111i + I1IiiI + OoO0O00 + oO0o
 if 28 - 28: Ii1I - i11iIiiIii . oO0o / II111iiii
 if 82 - 82: iII111i * iII111i . IiII * II111iiii
 if 17 - 17: OoooooooOO % I1Ii111 * I1Ii111 / II111iiii . OoOoOO00 * iII111i
 if 80 - 80: IiII % i11iIiiIii
 if 6 - 6: II111iiii + i11iIiiIii - Oo0Ooo % OOooOOo + Oo0Ooo
 if 46 - 46: iII111i
def lisp_reassemble ( packet ) :
 oo00o00O0 = socket . ntohs ( struct . unpack ( "H" , packet [ 6 : 8 ] ) [ 0 ] )
 if 31 - 31: OoO0O00 + I1Ii111 / iIii1I11I1II1
 if 11 - 11: ooOoO0o - OoOoOO00
 if 19 - 19: O0 . OoOoOO00 - i1IIi . oO0o
 if 96 - 96: o0oOOo0O0Ooo % o0oOOo0O0Ooo - OoO0O00 * iIii1I11I1II1 + ooOoO0o - ooOoO0o
 if ( oo00o00O0 == 0 or oo00o00O0 == 0x4000 ) : return ( packet )
 if 4 - 4: OoO0O00 - OOooOOo
 if 21 - 21: I1Ii111 * i11iIiiIii
 if 63 - 63: oO0o + OoOoOO00
 if 50 - 50: o0oOOo0O0Ooo / Oo0Ooo * ooOoO0o * Ii1I
 i11iiI = socket . ntohs ( struct . unpack ( "H" , packet [ 4 : 6 ] ) [ 0 ] )
 ooO00Oo = socket . ntohs ( struct . unpack ( "H" , packet [ 2 : 4 ] ) [ 0 ] )
 if 97 - 97: I1IiiI / oO0o + I1Ii111 + I1Ii111
 OOO00O0oO0 = ( oo00o00O0 & 0x2000 == 0 and ( oo00o00O0 & 0x1fff ) != 0 )
 i1ii1i1Ii11 = [ ( oo00o00O0 & 0x1fff ) * 8 , ooO00Oo - 20 , packet , OOO00O0oO0 ]
 if 79 - 79: ooOoO0o % OoooooooOO
 if 67 - 67: I1IiiI + OoooooooOO % OoO0O00 . OoooooooOO + I11i / oO0o
 if 33 - 33: I1ii11iIi11i
 if 5 - 5: O0
 if 50 - 50: Oo0Ooo % IiII * oO0o
 if 71 - 71: OoO0O00
 if 64 - 64: OoO0O00 - I1ii11iIi11i % OoO0O00 + OoOoOO00 - Oo0Ooo * I1ii11iIi11i
 if 78 - 78: I1Ii111 % OoO0O00 . IiII % iIii1I11I1II1 / OoO0O00
 if ( oo00o00O0 == 0x2000 ) :
  oo0O , O0o0o0ooO0ooo = struct . unpack ( "HH" , packet [ 20 : 24 ] )
  oo0O = socket . ntohs ( oo0O )
  O0o0o0ooO0ooo = socket . ntohs ( O0o0o0ooO0ooo )
  if ( O0o0o0ooO0ooo not in [ 4341 , 8472 , 4789 ] and oo0O != 4341 ) :
   lisp_reassembly_queue [ i11iiI ] = [ ]
   i1ii1i1Ii11 [ 2 ] = None
   if 34 - 34: iIii1I11I1II1
   if 33 - 33: I1ii11iIi11i + I1Ii111 * ooOoO0o / i11iIiiIii
   if 83 - 83: oO0o
   if 93 - 93: II111iiii
   if 89 - 89: OoO0O00 % II111iiii % iII111i
   if 66 - 66: OoooooooOO % iII111i % i11iIiiIii
 if ( lisp_reassembly_queue . has_key ( i11iiI ) == False ) :
  lisp_reassembly_queue [ i11iiI ] = [ ]
  if 35 - 35: OoooooooOO - IiII
  if 38 - 38: I1Ii111 % I11i . I11i % I11i + OoOoOO00
  if 79 - 79: I1ii11iIi11i + OoO0O00 * I1ii11iIi11i / I11i
  if 13 - 13: OoOoOO00 . iII111i
  if 11 - 11: Oo0Ooo - Ii1I / OoO0O00
 oOoo = lisp_reassembly_queue [ i11iiI ]
 if 59 - 59: OOooOOo % IiII . ooOoO0o + O0 . ooOoO0o + iIii1I11I1II1
 if 68 - 68: i11iIiiIii . iII111i + OoooooooOO + II111iiii + iIii1I11I1II1 % I11i
 if 7 - 7: i1IIi - o0oOOo0O0Ooo - I1IiiI
 if 62 - 62: OoOoOO00 * oO0o - I1IiiI / Ii1I
 if 48 - 48: o0oOOo0O0Ooo % o0oOOo0O0Ooo - OoOoOO00
 if ( len ( oOoo ) == 1 and oOoo [ 0 ] [ 2 ] == None ) :
  dprint ( "Drop non-LISP encapsulated fragment 0x{}" . format ( lisp_hex_string ( i11iiI ) . zfill ( 4 ) ) )
  if 13 - 13: OoO0O00 - Ii1I . ooOoO0o / O0 * OoOoOO00
  return ( None )
  if 57 - 57: O0 + OoooooooOO % o0oOOo0O0Ooo / I1Ii111 / OOooOOo - OoOoOO00
  if 48 - 48: o0oOOo0O0Ooo - II111iiii + OoOoOO00
  if 54 - 54: II111iiii - OoO0O00 - o0oOOo0O0Ooo - O0 % I1Ii111
  if 9 - 9: i1IIi % iII111i / Ii1I
  if 83 - 83: oO0o
 oOoo . append ( i1ii1i1Ii11 )
 oOoo = sorted ( oOoo )
 if 1 - 1: oO0o * iIii1I11I1II1 % iIii1I11I1II1 % iIii1I11I1II1 / oO0o + IiII
 if 29 - 29: OoooooooOO
 if 55 - 55: O0 - o0oOOo0O0Ooo % I1ii11iIi11i * I11i * oO0o
 if 83 - 83: iIii1I11I1II1
 IiiIIi1 = lisp_address ( LISP_AFI_IPV4 , "" , 32 , 0 )
 IiiIIi1 . address = socket . ntohl ( struct . unpack ( "I" , packet [ 12 : 16 ] ) [ 0 ] )
 oO000o0o0 = IiiIIi1 . print_address_no_iid ( )
 IiiIIi1 . address = socket . ntohl ( struct . unpack ( "I" , packet [ 16 : 20 ] ) [ 0 ] )
 I1iI11I1II = IiiIIi1 . print_address_no_iid ( )
 IiiIIi1 = red ( "{} -> {}" . format ( oO000o0o0 , I1iI11I1II ) , False )
 if 54 - 54: Ii1I - OoooooooOO % I1IiiI + oO0o
 dprint ( "{}{} fragment, RLOCs: {}, packet 0x{}, frag-offset: 0x{}" . format ( bold ( "Received" , False ) , " non-LISP encapsulated" if i1ii1i1Ii11 [ 2 ] == None else "" , IiiIIi1 , lisp_hex_string ( i11iiI ) . zfill ( 4 ) ,
 # I11i / iIii1I11I1II1 * Oo0Ooo % i1IIi % OoOoOO00
 # oO0o
 lisp_hex_string ( oo00o00O0 ) . zfill ( 4 ) ) )
 if 94 - 94: OoO0O00 * I1IiiI / O0 + I1Ii111 / i11iIiiIii
 if 34 - 34: Oo0Ooo . i1IIi
 if 97 - 97: I11i
 if 89 - 89: iII111i % OoOoOO00 . Oo0Ooo
 if 20 - 20: oO0o % OoOoOO00
 if ( oOoo [ 0 ] [ 0 ] != 0 or oOoo [ - 1 ] [ 3 ] == False ) : return ( None )
 OO00ooo0 = oOoo [ 0 ]
 for ii11I in oOoo [ 1 : : ] :
  oo00o00O0 = ii11I [ 0 ]
  IIi1I , O00oO00ooo0ooOOOO = OO00ooo0 [ 0 ] , OO00ooo0 [ 1 ]
  if ( IIi1I + O00oO00ooo0ooOOOO != oo00o00O0 ) : return ( None )
  OO00ooo0 = ii11I
  if 84 - 84: ooOoO0o + OOooOOo * OoO0O00
 lisp_reassembly_queue . pop ( i11iiI )
 if 39 - 39: OoooooooOO * OoooooooOO
 if 49 - 49: o0oOOo0O0Ooo + i1IIi / iII111i
 if 43 - 43: i1IIi . OoO0O00 + I1ii11iIi11i
 if 88 - 88: OoooooooOO / I11i % II111iiii % OOooOOo - I11i
 if 55 - 55: Oo0Ooo - OOooOOo - O0
 packet = oOoo [ 0 ] [ 2 ]
 for ii11I in oOoo [ 1 : : ] : packet += ii11I [ 2 ] [ 20 : : ]
 if 40 - 40: OoOoOO00 - OOooOOo
 dprint ( "{} fragments arrived for packet 0x{}, length {}" . format ( bold ( "All" , False ) , lisp_hex_string ( i11iiI ) . zfill ( 4 ) , len ( packet ) ) )
 if 3 - 3: IiII % I11i * I1Ii111 + iIii1I11I1II1 . oO0o
 if 35 - 35: II111iiii
 if 15 - 15: I11i * iIii1I11I1II1 + OOooOOo % IiII . o0oOOo0O0Ooo % Oo0Ooo
 if 96 - 96: O0
 if 15 - 15: i1IIi . iIii1I11I1II1
 IiiI1iii1iIiiI = socket . htons ( len ( packet ) )
 O0ooOoO0 = packet [ 0 : 2 ] + struct . pack ( "H" , IiiI1iii1iIiiI ) + packet [ 4 : 6 ] + struct . pack ( "H" , 0 ) + packet [ 8 : 10 ] + struct . pack ( "H" , 0 ) + packet [ 12 : 20 ]
 if 3 - 3: II111iiii * i11iIiiIii * i1IIi - i1IIi
 if 11 - 11: I1IiiI % Ii1I * i11iIiiIii % OOooOOo + II111iiii
 O0ooOoO0 = lisp_ip_checksum ( O0ooOoO0 )
 return ( O0ooOoO0 + packet [ 20 : : ] )
 if 61 - 61: I1Ii111 + I11i + I1IiiI
 if 48 - 48: I11i
 if 67 - 67: o0oOOo0O0Ooo
 if 36 - 36: IiII - I11i - Ii1I / OoOoOO00 % OoO0O00 * iIii1I11I1II1
 if 61 - 61: i11iIiiIii / Ii1I - OOooOOo . I1ii11iIi11i
 if 89 - 89: ooOoO0o % i11iIiiIii
 if 57 - 57: Oo0Ooo / ooOoO0o - O0 . ooOoO0o
 if 61 - 61: o0oOOo0O0Ooo / OoooooooOO . I1ii11iIi11i + Oo0Ooo
def lisp_get_crypto_decap_lookup_key ( addr , port ) :
 oo0o00OO = addr . print_address_no_iid ( ) + ":" + str ( port )
 if ( lisp_crypto_keys_by_rloc_decap . has_key ( oo0o00OO ) ) : return ( oo0o00OO )
 if 75 - 75: Ii1I
 oo0o00OO = addr . print_address_no_iid ( )
 if ( lisp_crypto_keys_by_rloc_decap . has_key ( oo0o00OO ) ) : return ( oo0o00OO )
 if 79 - 79: i1IIi . I1ii11iIi11i * o0oOOo0O0Ooo / I11i . I11i / ooOoO0o
 if 99 - 99: oO0o + I11i % i1IIi . iII111i
 if 58 - 58: Oo0Ooo % i11iIiiIii . Oo0Ooo / Oo0Ooo - I1IiiI . Ii1I
 if 65 - 65: OoO0O00
 if 16 - 16: IiII % I1IiiI % iIii1I11I1II1 . I1IiiI . I1ii11iIi11i - IiII
 for I1II1i in lisp_crypto_keys_by_rloc_decap :
  OO0o = I1II1i . split ( ":" )
  if ( len ( OO0o ) == 1 ) : continue
  OO0o = OO0o [ 0 ] if len ( OO0o ) == 2 else ":" . join ( OO0o [ 0 : - 1 ] )
  if ( OO0o == oo0o00OO ) :
   iIi11III = lisp_crypto_keys_by_rloc_decap [ I1II1i ]
   lisp_crypto_keys_by_rloc_decap [ oo0o00OO ] = iIi11III
   return ( oo0o00OO )
   if 16 - 16: iIii1I11I1II1 . I1Ii111 * OoO0O00
   if 78 - 78: iIii1I11I1II1 + I11i - OoOoOO00 / I1ii11iIi11i + iIii1I11I1II1 % II111iiii
 return ( None )
 if 55 - 55: I11i . iIii1I11I1II1 / Ii1I - OoO0O00 * I1ii11iIi11i % iIii1I11I1II1
 if 48 - 48: ooOoO0o + Oo0Ooo / Oo0Ooo
 if 15 - 15: iIii1I11I1II1 . I1Ii111 * OoooooooOO * O0 % OOooOOo
 if 53 - 53: Ii1I
 if 63 - 63: I11i % OoOoOO00
 if 46 - 46: iIii1I11I1II1 . II111iiii / OoooooooOO - ooOoO0o * iII111i
 if 52 - 52: I11i + iII111i
 if 9 - 9: OoOoOO00 % II111iiii . I11i * Oo0Ooo
 if 53 - 53: II111iiii / i1IIi + OoooooooOO * O0
 if 62 - 62: IiII . O0
 if 87 - 87: I1ii11iIi11i / oO0o / IiII . OOooOOo
def lisp_build_crypto_decap_lookup_key ( addr , port ) :
 addr = addr . print_address_no_iid ( )
 O0oOoOOOOo = addr + ":" + str ( port )
 if 66 - 66: OoOoOO00 . Ii1I / i11iIiiIii / ooOoO0o
 if ( lisp_i_am_rtr ) :
  if ( lisp_rloc_probe_list . has_key ( addr ) ) : return ( addr )
  if 76 - 76: OoO0O00 % OoO0O00 / I1ii11iIi11i * ooOoO0o * o0oOOo0O0Ooo - I1Ii111
  if 53 - 53: OoO0O00 % Oo0Ooo . i1IIi
  if 34 - 34: Ii1I - o0oOOo0O0Ooo * i1IIi
  if 7 - 7: OoO0O00 * I1ii11iIi11i / I1Ii111
  if 98 - 98: II111iiii % I1ii11iIi11i
  if 48 - 48: iII111i % oO0o + oO0o - Oo0Ooo . OOooOOo
  for IIiiiiII in lisp_nat_state_info . values ( ) :
   for oO0ooo in IIiiiiII :
    if ( addr == oO0ooo . address ) : return ( O0oOoOOOOo )
    if 38 - 38: iII111i
    if 66 - 66: iII111i + Oo0Ooo + i1IIi * Oo0Ooo
  return ( addr )
  if 18 - 18: O0 - IiII
 return ( O0oOoOOOOo )
 if 5 - 5: I1ii11iIi11i * iII111i + II111iiii * Oo0Ooo * O0 - I1IiiI
 if 71 - 71: i11iIiiIii % I1IiiI + I1ii11iIi11i + II111iiii + OoooooooOO + oO0o
 if 12 - 12: I1IiiI + I1Ii111
 if 66 - 66: I1Ii111 + OOooOOo + I1Ii111 . OoooooooOO * oO0o / OoO0O00
 if 74 - 74: O0 % OOooOOo * OoOoOO00 / oO0o - Oo0Ooo
 if 79 - 79: Ii1I + IiII
 if 21 - 21: o0oOOo0O0Ooo * iII111i * o0oOOo0O0Ooo * o0oOOo0O0Ooo . Oo0Ooo
def lisp_set_ttl ( lisp_socket , ttl ) :
 try :
  lisp_socket . setsockopt ( socket . SOL_IP , socket . IP_TTL , ttl )
  lisp_socket . setsockopt ( socket . SOL_IP , socket . IP_MULTICAST_TTL , ttl )
 except :
  lprint ( "socket.setsockopt(IP_TTL) not supported" )
  pass
  if 98 - 98: I1ii11iIi11i
 return
 if 58 - 58: IiII / i11iIiiIii % I11i
 if 74 - 74: OoooooooOO - I1ii11iIi11i + OOooOOo % IiII . o0oOOo0O0Ooo
 if 21 - 21: Ii1I
 if 72 - 72: I1Ii111 . OoooooooOO / I1Ii111 - Ii1I / I1ii11iIi11i * I1ii11iIi11i
 if 72 - 72: IiII . Ii1I + OoooooooOO * OoOoOO00 + Oo0Ooo . iII111i
 if 92 - 92: O0 * Ii1I - I1ii11iIi11i - IiII . OoO0O00 + I1IiiI
 if 59 - 59: i1IIi * OOooOOo % Oo0Ooo
def lisp_is_rloc_probe_request ( lisp_type ) :
 lisp_type = struct . unpack ( "B" , lisp_type ) [ 0 ]
 return ( lisp_type == 0x12 )
 if 44 - 44: iIii1I11I1II1 . OOooOOo
 if 57 - 57: II111iiii + I1Ii111
 if 42 - 42: OoOoOO00 % O0
 if 70 - 70: iIii1I11I1II1 * Oo0Ooo - I1IiiI / OoO0O00 + OoOoOO00
 if 94 - 94: OoooooooOO + O0 * iIii1I11I1II1 * II111iiii
 if 90 - 90: I11i + O0 / I1IiiI . oO0o / O0
 if 46 - 46: O0 . O0 - oO0o . II111iiii * I1IiiI * Ii1I
def lisp_is_rloc_probe_reply ( lisp_type ) :
 lisp_type = struct . unpack ( "B" , lisp_type ) [ 0 ]
 return ( lisp_type == 0x28 )
 if 10 - 10: i1IIi + i1IIi . i1IIi - I1IiiI - I1IiiI
 if 26 - 26: Ii1I * I11i / I11i
 if 79 - 79: ooOoO0o / oO0o - oO0o / OoooooooOO
 if 91 - 91: iIii1I11I1II1 - O0 * o0oOOo0O0Ooo * o0oOOo0O0Ooo . II111iiii
 if 69 - 69: II111iiii - Oo0Ooo + i1IIi . II111iiii + o0oOOo0O0Ooo
 if 20 - 20: OoooooooOO - OoO0O00 * ooOoO0o * OoOoOO00 / OOooOOo
 if 64 - 64: O0 + iII111i / I11i * OoOoOO00 + o0oOOo0O0Ooo + I1Ii111
 if 16 - 16: I11i
 if 9 - 9: Ii1I / IiII * I11i - i11iIiiIii * I1ii11iIi11i / iII111i
 if 61 - 61: O0 % iII111i
 if 41 - 41: I1Ii111 * OoooooooOO
 if 76 - 76: OoooooooOO * II111iiii . II111iiii / o0oOOo0O0Ooo - iII111i
 if 49 - 49: O0 . I1ii11iIi11i . OoOoOO00 . I1Ii111 % O0 . iIii1I11I1II1
 if 19 - 19: iIii1I11I1II1
 if 97 - 97: Ii1I . I11i / ooOoO0o + Oo0Ooo
 if 100 - 100: iII111i / I1Ii111 % OoOoOO00 . O0 / OoOoOO00
 if 81 - 81: OoO0O00 % i11iIiiIii / OoO0O00 + ooOoO0o
 if 100 - 100: O0 . Oo0Ooo % Oo0Ooo % O0 / i11iIiiIii
 if 56 - 56: IiII - OOooOOo - OoOoOO00 - I11i
def lisp_is_rloc_probe ( packet , rr ) :
 o0oOo00 = ( struct . unpack ( "B" , packet [ 9 ] ) [ 0 ] == 17 )
 if ( o0oOo00 == False ) : return ( [ packet , None , None , None ] )
 if 57 - 57: i1IIi
 oo0O = struct . unpack ( "H" , packet [ 20 : 22 ] ) [ 0 ]
 O0o0o0ooO0ooo = struct . unpack ( "H" , packet [ 22 : 24 ] ) [ 0 ]
 i11i = ( socket . htons ( LISP_CTRL_PORT ) in [ oo0O , O0o0o0ooO0ooo ] )
 if ( i11i == False ) : return ( [ packet , None , None , None ] )
 if 27 - 27: iII111i / iII111i
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
   if 19 - 19: iII111i + I1ii11iIi11i
   if 81 - 81: iIii1I11I1II1 * OoO0O00 - Ii1I / oO0o - ooOoO0o
   if 6 - 6: I1IiiI - oO0o + OoO0O00
   if 58 - 58: iIii1I11I1II1 + OoOoOO00
   if 65 - 65: iII111i % Oo0Ooo * iIii1I11I1II1 + I1IiiI + II111iiii
   if 72 - 72: OoOoOO00 . OoooooooOO - OOooOOo
 i1IIi1ii1i1ii = lisp_address ( LISP_AFI_IPV4 , "" , 32 , 0 )
 i1IIi1ii1i1ii . address = socket . ntohl ( struct . unpack ( "I" , packet [ 12 : 16 ] ) [ 0 ] )
 if 15 - 15: OoOoOO00
 if 13 - 13: I1ii11iIi11i - OOooOOo - i11iIiiIii / IiII
 if 65 - 65: IiII
 if 76 - 76: I1Ii111 % I1ii11iIi11i + ooOoO0o / I1IiiI
 if ( i1IIi1ii1i1ii . is_local ( ) ) : return ( [ None , None , None , None ] )
 if 59 - 59: OOooOOo - o0oOOo0O0Ooo - o0oOOo0O0Ooo % I1IiiI
 if 55 - 55: o0oOOo0O0Ooo % I1ii11iIi11i - IiII + OoooooooOO
 if 44 - 44: iII111i * I1Ii111 - I1IiiI % i1IIi
 if 35 - 35: iII111i . OoOoOO00 + i1IIi . I1Ii111 - oO0o
 i1IIi1ii1i1ii = i1IIi1ii1i1ii . print_address_no_iid ( )
 Oo0O00O = socket . ntohs ( struct . unpack ( "H" , packet [ 20 : 22 ] ) [ 0 ] )
 oOoooOOO0o0 = struct . unpack ( "B" , packet [ 8 ] ) [ 0 ] - 1
 packet = packet [ 28 : : ]
 if 92 - 92: o0oOOo0O0Ooo
 O0OOOO0o0O = bold ( "Receive(pcap)" , False )
 OOO000 = bold ( "from " + i1IIi1ii1i1ii , False )
 oo00ooOOOo0O = lisp_format_packet ( packet )
 lprint ( "{} {} bytes {} {}, packet: {}" . format ( O0OOOO0o0O , len ( packet ) , OOO000 , Oo0O00O , oo00ooOOOo0O ) )
 if 8 - 8: i1IIi / IiII . O0
 return ( [ packet , i1IIi1ii1i1ii , Oo0O00O , oOoooOOO0o0 ] )
 if 72 - 72: OOooOOo
 if 20 - 20: i11iIiiIii + Oo0Ooo * Oo0Ooo % OOooOOo
 if 66 - 66: I1ii11iIi11i + iII111i / Ii1I / I1IiiI * i11iIiiIii
 if 41 - 41: Ii1I / Oo0Ooo . OoO0O00 . iIii1I11I1II1 % IiII . I11i
 if 59 - 59: O0 + II111iiii + IiII % Oo0Ooo
 if 71 - 71: oO0o
 if 75 - 75: Oo0Ooo * oO0o + iIii1I11I1II1 / Oo0Ooo
 if 51 - 51: Ii1I * Ii1I + iII111i * oO0o / OOooOOo - ooOoO0o
 if 16 - 16: I1Ii111 + O0 - O0 * iIii1I11I1II1 / iII111i
 if 4 - 4: iII111i
 if 75 - 75: I1IiiI * IiII % OoO0O00 - ooOoO0o * iII111i
def lisp_ipc_write_xtr_parameters ( cp , dp ) :
 if ( lisp_ipc_dp_socket == None ) : return
 if 32 - 32: iII111i
 iiiii1i1 = { "type" : "xtr-parameters" , "control-plane-logging" : cp ,
 "data-plane-logging" : dp , "rtr" : lisp_i_am_rtr }
 if 59 - 59: OoOoOO00 - I1Ii111
 lisp_write_to_dp_socket ( iiiii1i1 )
 return
 if 34 - 34: ooOoO0o . OoooooooOO / ooOoO0o + OoooooooOO
 if 24 - 24: OoooooooOO * I1ii11iIi11i / O0 / Oo0Ooo * I1IiiI / ooOoO0o
 if 33 - 33: Ii1I
 if 20 - 20: Ii1I + I11i
 if 98 - 98: OOooOOo
 if 58 - 58: i11iIiiIii / OoOoOO00
 if 18 - 18: ooOoO0o + O0 - OOooOOo + iIii1I11I1II1 . OOooOOo * iIii1I11I1II1
 if 83 - 83: OoO0O00 - Oo0Ooo * I1IiiI % Oo0Ooo % oO0o
def lisp_external_data_plane ( ) :
 ooO0ooooO = 'egrep "ipc-data-plane = yes" ./lisp.config'
 if ( commands . getoutput ( ooO0ooooO ) != "" ) : return ( True )
 if 64 - 64: OoOoOO00 + oO0o / OoooooooOO . i11iIiiIii / II111iiii
 if ( os . getenv ( "LISP_RUN_LISP_XTR" ) != None ) : return ( True )
 return ( False )
 if 55 - 55: ooOoO0o . i11iIiiIii . o0oOOo0O0Ooo
 if 52 - 52: IiII . oO0o + i11iIiiIii % IiII
 if 45 - 45: i1IIi - I1IiiI / IiII - I1IiiI
 if 21 - 21: IiII
 if 43 - 43: IiII
 if 9 - 9: OOooOOo * ooOoO0o + ooOoO0o . I1Ii111
 if 8 - 8: IiII * iIii1I11I1II1
 if 7 - 7: I1Ii111 / OoooooooOO % O0 - I1ii11iIi11i
 if 49 - 49: OoooooooOO . I1ii11iIi11i / OoooooooOO * oO0o
 if 81 - 81: I1ii11iIi11i . ooOoO0o + I1ii11iIi11i
 if 84 - 84: OoooooooOO
 if 95 - 95: o0oOOo0O0Ooo
 if 22 - 22: ooOoO0o / o0oOOo0O0Ooo - OoooooooOO / Oo0Ooo - I1Ii111 / OOooOOo
 if 41 - 41: oO0o . II111iiii
def lisp_process_data_plane_restart ( do_clear = False ) :
 os . system ( "touch ./lisp.config" )
 if 47 - 47: I1ii11iIi11i
 iiIiiI = { "type" : "entire-map-cache" , "entries" : [ ] }
 if 73 - 73: I1Ii111 / i11iIiiIii * iIii1I11I1II1 + OoOoOO00 + I1IiiI
 if ( do_clear == False ) :
  Oo0O0Oo0oo = iiIiiI [ "entries" ]
  lisp_map_cache . walk_cache ( lisp_ipc_walk_map_cache , Oo0O0Oo0oo )
  if 84 - 84: I1IiiI / I1IiiI + OoO0O00 . i1IIi . I1IiiI / OoOoOO00
  if 90 - 90: IiII . OoooooooOO - i11iIiiIii . OoooooooOO - I1ii11iIi11i
 lisp_write_to_dp_socket ( iiIiiI )
 return
 if 54 - 54: I1Ii111 % II111iiii - Ii1I . OoO0O00 + ooOoO0o / iII111i
 if 85 - 85: o0oOOo0O0Ooo - O0
 if 3 - 3: iIii1I11I1II1
 if 73 - 73: I1IiiI * OoooooooOO * iIii1I11I1II1 * Oo0Ooo
 if 76 - 76: OoO0O00 / i11iIiiIii % ooOoO0o % I11i * O0
 if 84 - 84: II111iiii - iII111i / IiII . O0 % i1IIi / I1ii11iIi11i
 if 2 - 2: OoooooooOO . OoO0O00 . II111iiii / Ii1I - OOooOOo % Oo0Ooo
 if 47 - 47: OOooOOo * oO0o
 if 41 - 41: OoooooooOO * I1IiiI
 if 3 - 3: IiII
 if 96 - 96: I11i - OOooOOo + I11i
 if 71 - 71: Oo0Ooo
 if 48 - 48: o0oOOo0O0Ooo / II111iiii / OoOoOO00 * o0oOOo0O0Ooo + I1IiiI . OoOoOO00
 if 52 - 52: Ii1I / OoOoOO00 . OOooOOo * IiII . OoooooooOO
def lisp_process_data_plane_stats ( msg , lisp_sockets , lisp_port ) :
 if ( msg . has_key ( "entries" ) == False ) :
  lprint ( "No 'entries' in stats IPC message" )
  return
  if 6 - 6: i1IIi . oO0o % IiII . Oo0Ooo % I11i
 if ( type ( msg [ "entries" ] ) != list ) :
  lprint ( "'entries' in stats IPC message must be an array" )
  return
  if 86 - 86: OoooooooOO + IiII % o0oOOo0O0Ooo . i1IIi . iII111i
  if 25 - 25: iII111i * I1ii11iIi11i + I11i - I1ii11iIi11i
 for msg in msg [ "entries" ] :
  if ( msg . has_key ( "eid-prefix" ) == False ) :
   lprint ( "No 'eid-prefix' in stats IPC message" )
   continue
   if 75 - 75: IiII
  I11i11i1 = msg [ "eid-prefix" ]
  if 74 - 74: o0oOOo0O0Ooo - iIii1I11I1II1
  if ( msg . has_key ( "instance-id" ) == False ) :
   lprint ( "No 'instance-id' in stats IPC message" )
   continue
   if 92 - 92: i11iIiiIii * iIii1I11I1II1 - I1Ii111 . i1IIi
  o0OoO0000o = int ( msg [ "instance-id" ] )
  if 23 - 23: O0 - O0 . I1Ii111 . I1IiiI - I1IiiI * i1IIi
  if 8 - 8: I1IiiI . I1ii11iIi11i + oO0o % oO0o * oO0o
  if 70 - 70: II111iiii + IiII + O0 / Ii1I - i11iIiiIii
  if 72 - 72: II111iiii - II111iiii
  ooOOoo0 = lisp_address ( LISP_AFI_NONE , "" , 0 , o0OoO0000o )
  ooOOoo0 . store_prefix ( I11i11i1 )
  o0o000Oo = lisp_map_cache_lookup ( None , ooOOoo0 )
  if ( o0o000Oo == None ) :
   lprint ( "Map-cache entry for {} not found for stats update" . format ( I11i11i1 ) )
   if 44 - 44: o0oOOo0O0Ooo + OoooooooOO
   continue
   if 34 - 34: i11iIiiIii + iIii1I11I1II1 - i11iIiiIii * o0oOOo0O0Ooo - iII111i
   if 87 - 87: OOooOOo * OoO0O00
  if ( msg . has_key ( "rlocs" ) == False ) :
   lprint ( "No 'rlocs' in stats IPC message for {}" . format ( I11i11i1 ) )
   if 61 - 61: iII111i - II111iiii . I1Ii111 % II111iiii / I11i
   continue
   if 86 - 86: II111iiii
  if ( type ( msg [ "rlocs" ] ) != list ) :
   lprint ( "'rlocs' in stats IPC message must be an array" )
   continue
   if 94 - 94: o0oOOo0O0Ooo % Ii1I * Ii1I % Oo0Ooo / I1ii11iIi11i
  IIiii1i1IiI = msg [ "rlocs" ]
  if 56 - 56: O0 % i11iIiiIii - O0
  if 24 - 24: o0oOOo0O0Ooo % iII111i
  if 47 - 47: OoooooooOO
  if 65 - 65: I1ii11iIi11i . o0oOOo0O0Ooo * I1Ii111
  for O0o0O00O in IIiii1i1IiI :
   if ( O0o0O00O . has_key ( "rloc" ) == False ) : continue
   if 29 - 29: I1Ii111
   o0oooOoOoOo = O0o0O00O [ "rloc" ]
   if ( o0oooOoOoOo == "no-address" ) : continue
   if 61 - 61: I1ii11iIi11i % oO0o + OoooooooOO - ooOoO0o . OOooOOo + OoOoOO00
   I1IIiIIIii = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
   I1IIiIIIii . store_address ( o0oooOoOoOo )
   if 53 - 53: o0oOOo0O0Ooo
   i1III111 = o0o000Oo . get_rloc ( I1IIiIIIii )
   if ( i1III111 == None ) : continue
   if 55 - 55: ooOoO0o . i1IIi - ooOoO0o + O0 + I1IiiI
   if 31 - 31: OoO0O00 % I1Ii111
   if 62 - 62: oO0o / O0 - I1Ii111 . IiII
   if 81 - 81: i11iIiiIii
   o00oooOOooo0 = 0 if O0o0O00O . has_key ( "packet-count" ) == False else O0o0O00O [ "packet-count" ]
   if 99 - 99: O0 / OoO0O00 * II111iiii . II111iiii
   IiIiIiiiI1 = 0 if O0o0O00O . has_key ( "byte-count" ) == False else O0o0O00O [ "byte-count" ]
   if 14 - 14: OoOoOO00 * i1IIi - OoOoOO00 . OoooooooOO
   i1 = 0 if O0o0O00O . has_key ( "seconds-last-packet" ) == False else O0o0O00O [ "seconds-last-packet" ]
   if 24 - 24: iIii1I11I1II1 + OOooOOo * iII111i % IiII % OOooOOo
   if 64 - 64: IiII . I1ii11iIi11i - o0oOOo0O0Ooo - ooOoO0o + OoooooooOO
   i1III111 . stats . packet_count += o00oooOOooo0
   i1III111 . stats . byte_count += IiIiIiiiI1
   i1III111 . stats . last_increment = lisp_get_timestamp ( ) - i1
   if 95 - 95: iII111i . I1ii11iIi11i + ooOoO0o + o0oOOo0O0Ooo % OoO0O00
   lprint ( "Update stats {}/{}/{}s for {} RLOC {}" . format ( o00oooOOooo0 , IiIiIiiiI1 ,
 i1 , I11i11i1 , o0oooOoOoOo ) )
   if 50 - 50: iII111i * O0 % II111iiii
   if 80 - 80: OOooOOo - II111iiii - OoO0O00
   if 62 - 62: Ii1I . i11iIiiIii % OOooOOo
   if 44 - 44: i1IIi * I1ii11iIi11i % Ii1I . Ii1I * I11i + II111iiii
   if 15 - 15: i1IIi - I11i - I1Ii111 / OoO0O00 + Oo0Ooo + I1IiiI
  if ( o0o000Oo . group . is_null ( ) and o0o000Oo . has_ttl_elapsed ( ) ) :
   I11i11i1 = green ( o0o000Oo . print_eid_tuple ( ) , False )
   lprint ( "Refresh map-cache entry {}" . format ( I11i11i1 ) )
   lisp_send_map_request ( lisp_sockets , lisp_port , None , o0o000Oo . eid , None )
   if 81 - 81: IiII
   if 54 - 54: I1IiiI % OoO0O00 % OoOoOO00
 return
 if 12 - 12: II111iiii . O0 * i11iIiiIii . I11i
 if 98 - 98: II111iiii + i1IIi * oO0o % I1IiiI
 if 53 - 53: i11iIiiIii . I1ii11iIi11i - OOooOOo - OOooOOo
 if 97 - 97: I1IiiI % iII111i % OoooooooOO / ooOoO0o / i11iIiiIii
 if 7 - 7: O0 % IiII / o0oOOo0O0Ooo
 if 79 - 79: IiII + I1Ii111
 if 59 - 59: iII111i - oO0o . ooOoO0o / IiII * i11iIiiIii
 if 61 - 61: I11i - Oo0Ooo * II111iiii + iIii1I11I1II1
 if 37 - 37: OoooooooOO % II111iiii / o0oOOo0O0Ooo . OOooOOo * I1ii11iIi11i . iIii1I11I1II1
 if 73 - 73: OoOoOO00
 if 44 - 44: Oo0Ooo / oO0o
 if 9 - 9: i1IIi % I1IiiI + OoO0O00 * ooOoO0o / iIii1I11I1II1 / iII111i
 if 80 - 80: OOooOOo / O0 % IiII * OoOoOO00
 if 53 - 53: OOooOOo + i11iIiiIii
 if 25 - 25: i11iIiiIii
 if 51 - 51: iII111i . ooOoO0o
 if 70 - 70: I11i / O0 - I11i + o0oOOo0O0Ooo . ooOoO0o . o0oOOo0O0Ooo
 if 6 - 6: I11i + II111iiii - I1Ii111
 if 45 - 45: i1IIi / iII111i + i11iIiiIii * I11i + ooOoO0o / OoooooooOO
 if 56 - 56: I11i + I1Ii111
 if 80 - 80: II111iiii . Ii1I + o0oOOo0O0Ooo / II111iiii / OoO0O00 + iIii1I11I1II1
 if 29 - 29: o0oOOo0O0Ooo + OoOoOO00 + ooOoO0o - I1ii11iIi11i
 if 64 - 64: O0 / OoooooooOO
def lisp_process_data_plane_decap_stats ( msg , lisp_ipc_socket ) :
 if 28 - 28: I1ii11iIi11i + oO0o . Oo0Ooo % iIii1I11I1II1 / I1Ii111
 if 8 - 8: O0 . I1IiiI * o0oOOo0O0Ooo + I1IiiI
 if 44 - 44: i1IIi % iII111i . i11iIiiIii / I11i + OoooooooOO
 if 21 - 21: OoOoOO00 . OoO0O00 . OoOoOO00 + OoOoOO00
 if 30 - 30: I1IiiI - iII111i - OOooOOo + oO0o
 if ( lisp_i_am_itr ) :
  lprint ( "Send decap-stats IPC message to lisp-etr process" )
  iiiii1i1 = "stats%{}" . format ( json . dumps ( msg ) )
  iiiii1i1 = lisp_command_ipc ( iiiii1i1 , "lisp-itr" )
  lisp_ipc ( iiiii1i1 , lisp_ipc_socket , "lisp-etr" )
  return
  if 51 - 51: Ii1I % O0 / II111iiii . Oo0Ooo
  if 90 - 90: i11iIiiIii * II111iiii % iIii1I11I1II1 . I1ii11iIi11i / Oo0Ooo . OOooOOo
  if 77 - 77: OoO0O00
  if 95 - 95: II111iiii
  if 59 - 59: iIii1I11I1II1 % OOooOOo / OoOoOO00 * I1Ii111 * OoooooooOO * O0
  if 43 - 43: OoO0O00 * I1IiiI * OOooOOo * O0 - O0 / o0oOOo0O0Ooo
  if 77 - 77: I11i % I1Ii111 . IiII % OoooooooOO * o0oOOo0O0Ooo
  if 87 - 87: iII111i + IiII / ooOoO0o * ooOoO0o * OOooOOo
 iiiii1i1 = bold ( "IPC" , False )
 lprint ( "Process decap-stats {} message: '{}'" . format ( iiiii1i1 , msg ) )
 if 97 - 97: I1Ii111
 if ( lisp_i_am_etr ) : msg = json . loads ( msg )
 if 47 - 47: iII111i / I1ii11iIi11i - Ii1I . II111iiii
 Oo0oOO0O = [ "good-packets" , "ICV-error" , "checksum-error" ,
 "lisp-header-error" , "no-decrypt-key" , "bad-inner-version" ,
 "outer-header-error" ]
 if 60 - 60: o0oOOo0O0Ooo
 for O0OOooo0 in Oo0oOO0O :
  o00oooOOooo0 = 0 if msg . has_key ( O0OOooo0 ) == False else msg [ O0OOooo0 ] [ "packet-count" ]
  if 46 - 46: I11i
  lisp_decap_stats [ O0OOooo0 ] . packet_count += o00oooOOooo0
  if 58 - 58: Ii1I
  IiIiIiiiI1 = 0 if msg . has_key ( O0OOooo0 ) == False else msg [ O0OOooo0 ] [ "byte-count" ]
  if 35 - 35: OoO0O00 + OoOoOO00
  lisp_decap_stats [ O0OOooo0 ] . byte_count += IiIiIiiiI1
  if 22 - 22: II111iiii / I1IiiI + o0oOOo0O0Ooo * I1IiiI . OoooooooOO * OOooOOo
  i1 = 0 if msg . has_key ( O0OOooo0 ) == False else msg [ O0OOooo0 ] [ "seconds-last-packet" ]
  if 49 - 49: I1ii11iIi11i * I1IiiI + OOooOOo + i11iIiiIii * I1ii11iIi11i . o0oOOo0O0Ooo
  lisp_decap_stats [ O0OOooo0 ] . last_increment = lisp_get_timestamp ( ) - i1
  if 36 - 36: o0oOOo0O0Ooo - i11iIiiIii
 return
 if 37 - 37: O0 + IiII + I1IiiI
 if 50 - 50: OoooooooOO . I1Ii111
 if 100 - 100: ooOoO0o * ooOoO0o - Ii1I
 if 13 - 13: iII111i . I11i * OoO0O00 . i1IIi . iIii1I11I1II1 - o0oOOo0O0Ooo
 if 68 - 68: Ii1I % o0oOOo0O0Ooo / OoooooooOO + Ii1I - Ii1I
 if 79 - 79: II111iiii / IiII
 if 4 - 4: O0 - i11iIiiIii % ooOoO0o * O0 - ooOoO0o
 if 96 - 96: oO0o % II111iiii . Ii1I % OoO0O00 . iIii1I11I1II1 / IiII
 if 96 - 96: o0oOOo0O0Ooo / O0 . iIii1I11I1II1 . Ii1I % OOooOOo % II111iiii
 if 5 - 5: OoooooooOO / I1Ii111 % I1Ii111 / I1IiiI
 if 19 - 19: I1IiiI - ooOoO0o % IiII - o0oOOo0O0Ooo * OOooOOo + I1ii11iIi11i
 if 44 - 44: i1IIi
 if 85 - 85: I1ii11iIi11i / IiII + oO0o
 if 95 - 95: IiII . OoO0O00
 if 36 - 36: IiII % Ii1I - OoOoOO00 + OoO0O00 + IiII * Ii1I
 if 15 - 15: I1IiiI / O0 % I1ii11iIi11i % OoOoOO00 . OoOoOO00 + iII111i
 if 79 - 79: OOooOOo + Ii1I . I1Ii111 / Oo0Ooo / i11iIiiIii / O0
def lisp_process_punt ( punt_socket , lisp_send_sockets , lisp_ephem_port ) :
 IiiIIiI1IIi , i1IIi1ii1i1ii = punt_socket . recvfrom ( 4000 )
 if 9 - 9: OoO0O00
 ii1Ii1i1ii = json . loads ( IiiIIiI1IIi )
 if ( type ( ii1Ii1i1ii ) != dict ) :
  lprint ( "Invalid punt message from {}, not in JSON format" . format ( i1IIi1ii1i1ii ) )
  if 80 - 80: IiII + OoO0O00
  return
  if 2 - 2: IiII + OoOoOO00 % oO0o
 oooo00oO = bold ( "Punt" , False )
 lprint ( "{} message from '{}': '{}'" . format ( oooo00oO , i1IIi1ii1i1ii , ii1Ii1i1ii ) )
 if 85 - 85: II111iiii
 if ( ii1Ii1i1ii . has_key ( "type" ) == False ) :
  lprint ( "Punt IPC message has no 'type' key" )
  return
  if 7 - 7: OOooOOo - O0 . iIii1I11I1II1 * II111iiii * IiII
  if 66 - 66: I1Ii111 + i11iIiiIii % ooOoO0o * i11iIiiIii + Oo0Ooo + OoOoOO00
  if 56 - 56: i1IIi + i1IIi . IiII . Oo0Ooo % OOooOOo
  if 51 - 51: OoO0O00 + i1IIi + iIii1I11I1II1
  if 68 - 68: OoOoOO00 . I1IiiI + ooOoO0o - o0oOOo0O0Ooo
 if ( ii1Ii1i1ii [ "type" ] == "statistics" ) :
  lisp_process_data_plane_stats ( ii1Ii1i1ii , lisp_send_sockets , lisp_ephem_port )
  return
  if 62 - 62: Ii1I - OOooOOo
 if ( ii1Ii1i1ii [ "type" ] == "decap-statistics" ) :
  lisp_process_data_plane_decap_stats ( ii1Ii1i1ii , punt_socket )
  return
  if 88 - 88: iIii1I11I1II1 * Oo0Ooo / II111iiii / IiII / OoO0O00 % ooOoO0o
  if 19 - 19: I11i * iII111i . O0 * iII111i % I1ii11iIi11i - OoOoOO00
  if 68 - 68: I1Ii111 - OoO0O00 % Ii1I + i1IIi . ooOoO0o
  if 36 - 36: oO0o * iIii1I11I1II1 - O0 - IiII * O0 + i11iIiiIii
  if 76 - 76: OoO0O00 % O0 / Ii1I + I1IiiI
 if ( ii1Ii1i1ii [ "type" ] == "restart" ) :
  lisp_process_data_plane_restart ( )
  return
  if 23 - 23: I1IiiI % IiII . o0oOOo0O0Ooo
  if 2 - 2: I1ii11iIi11i
  if 51 - 51: iIii1I11I1II1 / II111iiii / iIii1I11I1II1 / oO0o % i1IIi
  if 54 - 54: ooOoO0o
  if 47 - 47: I11i * I1IiiI / oO0o
 if ( ii1Ii1i1ii [ "type" ] != "discovery" ) :
  lprint ( "Punt IPC message has wrong format" )
  return
  if 98 - 98: Ii1I / oO0o * O0 + I1Ii111 - I1Ii111 + iII111i
 if ( ii1Ii1i1ii . has_key ( "interface" ) == False ) :
  lprint ( "Invalid punt message from {}, required keys missing" . format ( i1IIi1ii1i1ii ) )
  if 4 - 4: i1IIi
  return
  if 43 - 43: oO0o * ooOoO0o - I11i
  if 70 - 70: oO0o / Ii1I
  if 15 - 15: iIii1I11I1II1 % ooOoO0o % i11iIiiIii
  if 16 - 16: iII111i
  if 50 - 50: iIii1I11I1II1 - II111iiii % i1IIi
 OoO0o0OOOO = ii1Ii1i1ii [ "interface" ]
 if ( OoO0o0OOOO == "" ) :
  o0OoO0000o = int ( ii1Ii1i1ii [ "instance-id" ] )
  if ( o0OoO0000o == - 1 ) : return
 else :
  o0OoO0000o = lisp_get_interface_instance_id ( OoO0o0OOOO , None )
  if 48 - 48: O0
  if 60 - 60: ooOoO0o - IiII % i1IIi
  if 5 - 5: oO0o
  if 29 - 29: i1IIi . OoOoOO00 . i1IIi + oO0o . I1Ii111 + O0
  if 62 - 62: I1ii11iIi11i . IiII + OoO0O00 - OoOoOO00 * O0 + I1Ii111
 i1I1I = None
 if ( ii1Ii1i1ii . has_key ( "source-eid" ) ) :
  OoOoo0ooO0000 = ii1Ii1i1ii [ "source-eid" ]
  i1I1I = lisp_address ( LISP_AFI_NONE , OoOoo0ooO0000 , 0 , o0OoO0000o )
  if ( i1I1I . is_null ( ) ) :
   lprint ( "Invalid source-EID format '{}'" . format ( OoOoo0ooO0000 ) )
   return
   if 58 - 58: oO0o . OoO0O00 / ooOoO0o
   if 61 - 61: I11i + I1Ii111
 Ooii1 = None
 if ( ii1Ii1i1ii . has_key ( "dest-eid" ) ) :
  I1iiIo000o0O = ii1Ii1i1ii [ "dest-eid" ]
  Ooii1 = lisp_address ( LISP_AFI_NONE , I1iiIo000o0O , 0 , o0OoO0000o )
  if ( Ooii1 . is_null ( ) ) :
   lprint ( "Invalid dest-EID format '{}'" . format ( I1iiIo000o0O ) )
   return
   if 17 - 17: Oo0Ooo / ooOoO0o - I1IiiI % iII111i . OoOoOO00 % OoOoOO00
   if 88 - 88: Oo0Ooo + Ii1I * IiII . Ii1I * IiII * Oo0Ooo
   if 74 - 74: oO0o - II111iiii - I11i - ooOoO0o . I1Ii111 / Ii1I
   if 25 - 25: o0oOOo0O0Ooo - iII111i * OoO0O00
   if 1 - 1: I1Ii111
   if 63 - 63: ooOoO0o % I1Ii111 * I1ii11iIi11i % I1ii11iIi11i . ooOoO0o - O0
   if 62 - 62: ooOoO0o
   if 35 - 35: iII111i . i11iIiiIii - OOooOOo % Oo0Ooo + Ii1I . iIii1I11I1II1
 if ( i1I1I ) :
  oOo = green ( i1I1I . print_address ( ) , False )
  ooOOo0ooo = lisp_db_for_lookups . lookup_cache ( i1I1I , False )
  if ( ooOOo0ooo != None ) :
   if 91 - 91: o0oOOo0O0Ooo / OoO0O00 + I1IiiI % i11iIiiIii % i1IIi
   if 22 - 22: I1Ii111 * O0 % OoO0O00 * I1ii11iIi11i
   if 47 - 47: OoO0O00 / OOooOOo / OoOoOO00 % i11iIiiIii / OoOoOO00
   if 52 - 52: ooOoO0o / I11i % i11iIiiIii - I1Ii111 % ooOoO0o - o0oOOo0O0Ooo
   if 67 - 67: OoOoOO00 / I1Ii111 + i11iIiiIii - IiII
   if ( ooOOo0ooo . dynamic_eid_configured ( ) ) :
    II1i = lisp_allow_dynamic_eid ( OoO0o0OOOO , i1I1I )
    if ( II1i != None and lisp_i_am_itr ) :
     lisp_itr_discover_eid ( ooOOo0ooo , i1I1I , OoO0o0OOOO , II1i )
    else :
     lprint ( ( "Disallow dynamic source-EID {} " + "on interface {}" ) . format ( oOo , OoO0o0OOOO ) )
     if 79 - 79: I11i . I11i - OoOoOO00
     if 86 - 86: OoO0O00 * Oo0Ooo . iIii1I11I1II1 * O0
     if 52 - 52: iII111i - i11iIiiIii + o0oOOo0O0Ooo + i1IIi
  else :
   lprint ( "Punt from non-EID source {}" . format ( oOo ) )
   if 58 - 58: OOooOOo - Ii1I * I1Ii111 - O0 . oO0o
   if 72 - 72: i1IIi * iII111i * Ii1I / o0oOOo0O0Ooo . I1Ii111 + i11iIiiIii
   if 33 - 33: I11i / OoO0O00 * ooOoO0o + iIii1I11I1II1
   if 54 - 54: Oo0Ooo / IiII + i11iIiiIii . O0
   if 94 - 94: OoooooooOO + iII111i * OoooooooOO / o0oOOo0O0Ooo
   if 12 - 12: iIii1I11I1II1 / iIii1I11I1II1 / II111iiii
 if ( Ooii1 ) :
  o0o000Oo = lisp_map_cache_lookup ( i1I1I , Ooii1 )
  if ( o0o000Oo == None or o0o000Oo . action == LISP_SEND_MAP_REQUEST_ACTION ) :
   if 93 - 93: oO0o
   if 53 - 53: OoO0O00 * i1IIi / Oo0Ooo / OoO0O00 * ooOoO0o
   if 77 - 77: iIii1I11I1II1 % I1IiiI + o0oOOo0O0Ooo + I1Ii111 * Oo0Ooo * i1IIi
   if 14 - 14: iIii1I11I1II1 * iIii1I11I1II1 - OOooOOo . iII111i / ooOoO0o
   if 54 - 54: OoOoOO00 - I1IiiI - iII111i
   if ( lisp_rate_limit_map_request ( Ooii1 ) ) : return
   lisp_send_map_request ( lisp_send_sockets , lisp_ephem_port ,
 i1I1I , Ooii1 , None )
  else :
   oOo = green ( Ooii1 . print_address ( ) , False )
   lprint ( "Map-cache entry for {} already exists" . format ( oOo ) )
   if 49 - 49: i11iIiiIii * Oo0Ooo
   if 100 - 100: Oo0Ooo * oO0o
 return
 if 85 - 85: OoooooooOO . IiII / IiII . ooOoO0o . IiII % II111iiii
 if 65 - 65: oO0o - OoO0O00 / iII111i + ooOoO0o
 if 80 - 80: o0oOOo0O0Ooo + II111iiii * Ii1I % OoOoOO00 % I1IiiI + I1ii11iIi11i
 if 46 - 46: Oo0Ooo / Oo0Ooo % iII111i % I1IiiI
 if 85 - 85: OoO0O00 - Ii1I / O0
 if 45 - 45: IiII + I1Ii111 / I11i
 if 84 - 84: iII111i % II111iiii
def lisp_ipc_map_cache_entry ( mc , jdata ) :
 i1ii1i1Ii11 = lisp_write_ipc_map_cache ( True , mc , dont_send = True )
 jdata . append ( i1ii1i1Ii11 )
 return ( [ True , jdata ] )
 if 86 - 86: IiII % II111iiii / i1IIi * I1ii11iIi11i - O0 * OOooOOo
 if 53 - 53: OOooOOo * oO0o + i1IIi % Oo0Ooo + II111iiii
 if 34 - 34: oO0o % iII111i / IiII . IiII + i11iIiiIii
 if 68 - 68: O0 % oO0o * IiII % O0
 if 55 - 55: O0 % I1IiiI % O0
 if 27 - 27: I1IiiI + I1ii11iIi11i * I1Ii111 % Ii1I - Oo0Ooo
 if 87 - 87: i11iIiiIii % OOooOOo - OoOoOO00 * ooOoO0o / Oo0Ooo
 if 74 - 74: OoooooooOO * ooOoO0o - I11i / I1ii11iIi11i % iIii1I11I1II1
def lisp_ipc_walk_map_cache ( mc , jdata ) :
 if 94 - 94: Ii1I * I1Ii111 + OoOoOO00 . iIii1I11I1II1
 if 44 - 44: Oo0Ooo . Oo0Ooo * Oo0Ooo
 if 23 - 23: I1Ii111 / iII111i . O0 % II111iiii
 if 67 - 67: I11i / iIii1I11I1II1 / ooOoO0o
 if ( mc . group . is_null ( ) ) : return ( lisp_ipc_map_cache_entry ( mc , jdata ) )
 if 90 - 90: II111iiii % I1Ii111 - IiII . Oo0Ooo % OOooOOo - OoOoOO00
 if ( mc . source_cache == None ) : return ( [ True , jdata ] )
 if 89 - 89: Oo0Ooo - I1ii11iIi11i . I1Ii111
 if 65 - 65: ooOoO0o % OOooOOo + OOooOOo % I1Ii111 . I1IiiI % O0
 if 46 - 46: OoO0O00 * I1Ii111 + iII111i . oO0o % OOooOOo / i11iIiiIii
 if 1 - 1: I1ii11iIi11i % O0 - I1ii11iIi11i / OoooooooOO / OoO0O00
 if 82 - 82: i1IIi % Ii1I
 jdata = mc . source_cache . walk_cache ( lisp_ipc_map_cache_entry , jdata )
 return ( [ True , jdata ] )
 if 85 - 85: I1Ii111 * i11iIiiIii * iIii1I11I1II1 % iIii1I11I1II1
 if 64 - 64: OoO0O00 / Ii1I
 if 79 - 79: Ii1I % OOooOOo
 if 39 - 39: I1ii11iIi11i / Ii1I - II111iiii . i1IIi
 if 59 - 59: II111iiii
 if 36 - 36: ooOoO0o . II111iiii - OoOoOO00 % I1ii11iIi11i * O0
 if 91 - 91: iII111i + Oo0Ooo / OoooooooOO * iIii1I11I1II1 - OoO0O00
def lisp_itr_discover_eid ( db , eid , input_interface , routed_interface ,
 lisp_ipc_listen_socket ) :
 I11i11i1 = eid . print_address ( )
 if ( db . dynamic_eids . has_key ( I11i11i1 ) ) :
  db . dynamic_eids [ I11i11i1 ] . last_packet = lisp_get_timestamp ( )
  return
  if 73 - 73: iIii1I11I1II1 % I1Ii111 % II111iiii * Oo0Ooo * OoO0O00
  if 48 - 48: OOooOOo * i11iIiiIii - i11iIiiIii + iIii1I11I1II1 + I1IiiI % OoooooooOO
  if 61 - 61: i1IIi
  if 56 - 56: iIii1I11I1II1 / I11i * iII111i * I11i * OoooooooOO
  if 44 - 44: I1ii11iIi11i - OOooOOo % I11i - I1Ii111 / iIii1I11I1II1 - OOooOOo
 I1iIi1IiI1i = lisp_dynamic_eid ( )
 I1iIi1IiI1i . dynamic_eid . copy_address ( eid )
 I1iIi1IiI1i . interface = routed_interface
 I1iIi1IiI1i . last_packet = lisp_get_timestamp ( )
 I1iIi1IiI1i . get_timeout ( routed_interface )
 db . dynamic_eids [ I11i11i1 ] = I1iIi1IiI1i
 if 38 - 38: iIii1I11I1II1 - OoooooooOO * II111iiii . OoooooooOO + OOooOOo
 oooII11I11II1 = ""
 if ( input_interface != routed_interface ) :
  oooII11I11II1 = ", routed-interface " + routed_interface
  if 23 - 23: IiII * OoO0O00
  if 42 - 42: IiII
 OooOoOOOO0OOo = green ( I11i11i1 , False ) + bold ( " discovered" , False )
 lprint ( "Dynamic-EID {} on interface {}{}, timeout {}" . format ( OooOoOOOO0OOo , input_interface , oooII11I11II1 , I1iIi1IiI1i . timeout ) )
 if 45 - 45: ooOoO0o / OOooOOo / I1Ii111
 if 88 - 88: O0 % IiII / oO0o
 if 55 - 55: O0 + ooOoO0o * oO0o
 if 87 - 87: o0oOOo0O0Ooo + OoOoOO00 * iIii1I11I1II1
 if 38 - 38: I1ii11iIi11i - OOooOOo * O0 - I1ii11iIi11i
 iiiii1i1 = "learn%{}%{}" . format ( I11i11i1 , routed_interface )
 iiiii1i1 = lisp_command_ipc ( iiiii1i1 , "lisp-itr" )
 lisp_ipc ( iiiii1i1 , lisp_ipc_listen_socket , "lisp-etr" )
 return
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
def lisp_retry_decap_keys ( addr_str , packet , iv , packet_icv ) :
 if ( lisp_search_decap_keys == False ) : return
 if 42 - 42: OoOoOO00 % I1ii11iIi11i * I1Ii111 * i1IIi . i1IIi % OOooOOo
 if 90 - 90: oO0o * Oo0Ooo * oO0o . Ii1I * i1IIi
 if 47 - 47: OOooOOo
 if 38 - 38: I11i
 if ( addr_str . find ( ":" ) != - 1 ) : return
 if 15 - 15: OoO0O00 / ooOoO0o . OoO0O00 - iIii1I11I1II1 + OoooooooOO - OoO0O00
 O0Ii1IiiiI = lisp_crypto_keys_by_rloc_decap [ addr_str ]
 if 44 - 44: O0 . OOooOOo . o0oOOo0O0Ooo . I1ii11iIi11i - II111iiii
 for Oo000O000 in lisp_crypto_keys_by_rloc_decap :
  if 71 - 71: I1ii11iIi11i + o0oOOo0O0Ooo . i11iIiiIii * oO0o . i1IIi
  if 40 - 40: OoO0O00 - IiII
  if 43 - 43: I1Ii111 + i11iIiiIii % iII111i % I1Ii111 - ooOoO0o
  if 85 - 85: IiII % iIii1I11I1II1 . I1Ii111
  if ( Oo000O000 . find ( addr_str ) == - 1 ) : continue
  if 38 - 38: iII111i - I1IiiI / ooOoO0o
  if 46 - 46: OOooOOo . O0 / i11iIiiIii . OOooOOo
  if 19 - 19: I11i / Oo0Ooo + I1Ii111
  if 43 - 43: I1ii11iIi11i
  if ( Oo000O000 == addr_str ) : continue
  if 18 - 18: I11i / OOooOOo % I11i - o0oOOo0O0Ooo
  if 22 - 22: iII111i
  if 88 - 88: I11i + OoOoOO00 % IiII % OoO0O00 * O0 / OoooooooOO
  if 83 - 83: IiII + I1Ii111 . I1ii11iIi11i * iIii1I11I1II1
  i1ii1i1Ii11 = lisp_crypto_keys_by_rloc_decap [ Oo000O000 ]
  if ( i1ii1i1Ii11 == O0Ii1IiiiI ) : continue
  if 9 - 9: ooOoO0o % IiII - OoOoOO00
  if 66 - 66: oO0o % Oo0Ooo
  if 40 - 40: i11iIiiIii . O0 * I11i - oO0o / OOooOOo . oO0o
  if 86 - 86: OOooOOo - I1Ii111 * IiII - i1IIi + ooOoO0o + I11i
  i1iii1I11III = i1ii1i1Ii11 [ 1 ]
  if ( packet_icv != i1iii1I11III . do_icv ( packet , iv ) ) :
   lprint ( "Test ICV with key {} failed" . format ( red ( Oo000O000 , False ) ) )
   continue
   if 47 - 47: IiII * I11i / o0oOOo0O0Ooo * I1ii11iIi11i
   if 58 - 58: O0 . oO0o + Oo0Ooo % OOooOOo % I1ii11iIi11i / I1ii11iIi11i
  lprint ( "Changing decap crypto key to {}" . format ( red ( Oo000O000 , False ) ) )
  lisp_crypto_keys_by_rloc_decap [ addr_str ] = i1ii1i1Ii11
  if 18 - 18: I1ii11iIi11i
 return
 if 91 - 91: I1IiiI + OoooooooOO / OoooooooOO + I11i
 if 95 - 95: iII111i % I1IiiI . ooOoO0o
 if 70 - 70: OoOoOO00 - iII111i . IiII + iIii1I11I1II1
 if 13 - 13: oO0o * I1Ii111 / I1Ii111 . I1IiiI
 if 93 - 93: I11i % OoOoOO00 - OOooOOo + iIii1I11I1II1 / OoooooooOO % i11iIiiIii
 if 90 - 90: oO0o % iIii1I11I1II1 + o0oOOo0O0Ooo - I11i / i11iIiiIii
 if 57 - 57: I1IiiI . Oo0Ooo / I1IiiI / II111iiii - I1Ii111
 if 68 - 68: I1IiiI
def lisp_decent_pull_xtr_configured ( ) :
 return ( lisp_decent_modulus != 0 and lisp_decent_dns_suffix != None )
 if 97 - 97: Ii1I + o0oOOo0O0Ooo / OoO0O00
 if 97 - 97: i11iIiiIii % iIii1I11I1II1 + II111iiii
 if 90 - 90: OOooOOo / I1IiiI
 if 28 - 28: OoooooooOO + i1IIi
 if 29 - 29: Oo0Ooo
 if 98 - 98: OOooOOo / Oo0Ooo % Ii1I * OoooooooOO - oO0o
 if 64 - 64: I1IiiI - I1IiiI
 if 90 - 90: iII111i - I1IiiI - II111iiii / OOooOOo + Ii1I
def lisp_is_decent_dns_suffix ( dns_name ) :
 if ( lisp_decent_dns_suffix == None ) : return ( False )
 IiIIO0 = dns_name . split ( "." )
 IiIIO0 = "." . join ( IiIIO0 [ 1 : : ] )
 return ( IiIIO0 == lisp_decent_dns_suffix )
 if 34 - 34: i11iIiiIii + I1Ii111 / O0 / iIii1I11I1II1 * OoooooooOO % Ii1I
 if 32 - 32: i11iIiiIii - OoOoOO00 / iIii1I11I1II1 * o0oOOo0O0Ooo % I1IiiI + O0
 if 36 - 36: I1ii11iIi11i + I1ii11iIi11i % I1Ii111 * ooOoO0o * OoOoOO00
 if 54 - 54: Oo0Ooo - I1IiiI % OOooOOo . I1ii11iIi11i / I1IiiI
 if 75 - 75: OOooOOo - O0 % iII111i . Ii1I % I1ii11iIi11i + I1ii11iIi11i
 if 32 - 32: Ii1I + II111iiii * IiII
 if 9 - 9: I1Ii111
def lisp_get_decent_index ( eid ) :
 I11i11i1 = eid . print_prefix ( )
 o0oOO = hashlib . sha256 ( I11i11i1 ) . hexdigest ( )
 ooo = int ( o0oOO , 16 ) % lisp_decent_modulus
 return ( ooo )
 if 92 - 92: IiII + oO0o / OoooooooOO / Ii1I / I1IiiI
 if 25 - 25: oO0o / OoO0O00 * iII111i - OoOoOO00
 if 1 - 1: o0oOOo0O0Ooo - Oo0Ooo * I11i . oO0o
 if 15 - 15: I1ii11iIi11i . I1Ii111 + IiII
 if 15 - 15: Oo0Ooo . Ii1I - OoooooooOO % OoO0O00 + i11iIiiIii + iII111i
 if 91 - 91: OoooooooOO % Oo0Ooo - Ii1I
 if 54 - 54: O0 - iIii1I11I1II1 . OoO0O00 . IiII % OoO0O00
def lisp_get_decent_dns_name ( eid ) :
 ooo = lisp_get_decent_index ( eid )
 return ( str ( ooo ) + "." + lisp_decent_dns_suffix )
 if 28 - 28: O0 % i1IIi % OoO0O00 / o0oOOo0O0Ooo . iIii1I11I1II1 - iII111i
 if 50 - 50: o0oOOo0O0Ooo + iII111i / i1IIi % II111iiii
 if 61 - 61: IiII
 if 5 - 5: OOooOOo % iIii1I11I1II1 % O0 * i11iIiiIii / I1Ii111
 if 48 - 48: IiII * oO0o
 if 53 - 53: i1IIi * iIii1I11I1II1 . OOooOOo
 if 68 - 68: IiII % IiII - iII111i . IiII + OoooooooOO
 if 82 - 82: Ii1I . II111iiii / i1IIi * OoO0O00
def lisp_get_decent_dns_name_from_str ( iid , eid_str ) :
 ooOOoo0 = lisp_address ( LISP_AFI_NONE , eid_str , 0 , iid )
 ooo = lisp_get_decent_index ( ooOOoo0 )
 return ( str ( ooo ) + "." + lisp_decent_dns_suffix )
 if 80 - 80: I11i
 if 96 - 96: i1IIi - I1ii11iIi11i * iII111i . OOooOOo . OoO0O00
 if 93 - 93: oO0o * Oo0Ooo * IiII
 if 26 - 26: o0oOOo0O0Ooo + O0 % i11iIiiIii . ooOoO0o . I1IiiI + Oo0Ooo
 if 90 - 90: IiII * OoooooooOO + II111iiii / iII111i + i11iIiiIii / ooOoO0o
 if 20 - 20: II111iiii % I1ii11iIi11i - OoooooooOO * Ii1I / I11i - OoooooooOO
 if 11 - 11: I1IiiI + Ii1I + i11iIiiIii * I1ii11iIi11i - oO0o
 if 46 - 46: OoooooooOO - Oo0Ooo
 if 4 - 4: II111iiii . OOooOOo - Ii1I - i11iIiiIii
 if 27 - 27: iII111i * iII111i - OoO0O00 % o0oOOo0O0Ooo . o0oOOo0O0Ooo
def lisp_trace_append ( packet , reason = None , ed = "encap" , lisp_socket = None ,
 rloc_entry = None ) :
 if 64 - 64: I1ii11iIi11i * ooOoO0o - OoooooooOO - I1IiiI
 OoO00oo00 = 28 if packet . inner_version == 4 else 48
 OOO0OOo = packet . packet [ OoO00oo00 : : ]
 O0oOo0O0O = lisp_trace ( )
 if ( O0oOo0O0O . decode ( OOO0OOo ) == False ) :
  lprint ( "Could not decode JSON portion of a LISP-Trace packet" )
  return ( False )
  if 67 - 67: OoooooooOO % I1IiiI + o0oOOo0O0Ooo + I1Ii111
  if 12 - 12: o0oOOo0O0Ooo - Ii1I - I1Ii111 - II111iiii % iIii1I11I1II1 % Ii1I
 iIiiIiI111 = "?" if packet . outer_dest . is_null ( ) else packet . outer_dest . print_address_no_iid ( )
 if 2 - 2: i1IIi / ooOoO0o + Oo0Ooo % I11i - o0oOOo0O0Ooo
 if 54 - 54: o0oOOo0O0Ooo % Ii1I + I1IiiI % II111iiii + I11i - O0
 if 70 - 70: Ii1I / oO0o + i11iIiiIii - oO0o
 if 26 - 26: OoO0O00 % I1ii11iIi11i * O0 % OoO0O00
 if 98 - 98: OoO0O00 . ooOoO0o * I11i / i1IIi
 if 57 - 57: i11iIiiIii % OOooOOo
 if ( iIiiIiI111 != "?" and packet . encap_port != LISP_DATA_PORT ) :
  if ( ed == "encap" ) : iIiiIiI111 += ":{}" . format ( packet . encap_port )
  if 67 - 67: oO0o - OOooOOo + II111iiii
  if 19 - 19: iIii1I11I1II1 * OoooooooOO - i11iIiiIii . I1Ii111 * OoO0O00
  if 30 - 30: iII111i + I1IiiI * ooOoO0o
  if 53 - 53: iII111i + IiII
  if 52 - 52: II111iiii * i11iIiiIii - IiII * IiII / OoooooooOO
 i1ii1i1Ii11 = { }
 i1ii1i1Ii11 [ "node" ] = "ITR" if lisp_i_am_itr else "ETR" if lisp_i_am_etr else "RTR" if lisp_i_am_rtr else "?"
 if 18 - 18: IiII / O0 / I1ii11iIi11i
 iIiI = packet . outer_source
 if ( iIiI . is_null ( ) ) : iIiI = lisp_myrlocs [ 0 ]
 i1ii1i1Ii11 [ "srloc" ] = iIiI . print_address_no_iid ( )
 if 77 - 77: I1IiiI + IiII - oO0o - I1ii11iIi11i * II111iiii + i1IIi
 if 79 - 79: I1ii11iIi11i + O0 * OoooooooOO
 if 43 - 43: I11i
 if 29 - 29: o0oOOo0O0Ooo / I11i
 if 88 - 88: OoOoOO00 - Ii1I . O0 % I1Ii111 % I1ii11iIi11i
 if ( i1ii1i1Ii11 [ "node" ] == "ITR" and packet . inner_sport != LISP_TRACE_PORT ) :
  i1ii1i1Ii11 [ "srloc" ] += ":{}" . format ( packet . inner_sport )
  if 56 - 56: OoOoOO00 - iIii1I11I1II1 / I1IiiI - i1IIi / o0oOOo0O0Ooo * I11i
  if 70 - 70: OOooOOo
 i1ii1i1Ii11 [ "hn" ] = lisp_hostname
 Oo000O000 = ed + "-ts"
 i1ii1i1Ii11 [ Oo000O000 ] = lisp_get_timestamp ( )
 if 11 - 11: I11i * II111iiii * Oo0Ooo + OOooOOo % i1IIi
 if 73 - 73: OoO0O00 + O0 / Ii1I . OoooooooOO % iIii1I11I1II1 * i1IIi
 if 84 - 84: o0oOOo0O0Ooo . iII111i / o0oOOo0O0Ooo + I1ii11iIi11i % OoO0O00
 if 52 - 52: OoOoOO00 / Ii1I % OoOoOO00 % i11iIiiIii + I1IiiI / o0oOOo0O0Ooo
 if 63 - 63: I1IiiI
 if 20 - 20: oO0o + OoOoOO00
 if ( iIiiIiI111 == "?" and i1ii1i1Ii11 [ "node" ] == "ETR" ) :
  ooOOo0ooo = lisp_db_for_lookups . lookup_cache ( packet . inner_dest , False )
  if ( ooOOo0ooo != None and len ( ooOOo0ooo . rloc_set ) >= 1 ) :
   iIiiIiI111 = ooOOo0ooo . rloc_set [ 0 ] . rloc . print_address_no_iid ( )
   if 32 - 32: o0oOOo0O0Ooo % oO0o % I1IiiI * OoooooooOO
   if 4 - 4: OOooOOo % oO0o
 i1ii1i1Ii11 [ "drloc" ] = iIiiIiI111
 if 18 - 18: Ii1I * I11i
 if 14 - 14: ooOoO0o . ooOoO0o * OoOoOO00 * o0oOOo0O0Ooo - iII111i - I1Ii111
 if 53 - 53: Oo0Ooo * OoOoOO00 * II111iiii % IiII - I1ii11iIi11i
 if 56 - 56: Oo0Ooo . I1ii11iIi11i - i11iIiiIii / iIii1I11I1II1 . ooOoO0o
 if ( iIiiIiI111 == "?" and reason != None ) :
  i1ii1i1Ii11 [ "drloc" ] += " ({})" . format ( reason )
  if 28 - 28: OoooooooOO + I1IiiI / oO0o . iIii1I11I1II1 - oO0o
  if 64 - 64: I1Ii111 + Oo0Ooo / iII111i
  if 61 - 61: Ii1I * Ii1I . OoOoOO00 + OoO0O00 * i11iIiiIii * OoO0O00
  if 4 - 4: OoooooooOO % iII111i % Oo0Ooo * IiII % o0oOOo0O0Ooo . o0oOOo0O0Ooo
  if 66 - 66: I1IiiI . Oo0Ooo - oO0o
 if ( rloc_entry != None ) :
  i1ii1i1Ii11 [ "rtts" ] = rloc_entry . recent_rloc_probe_rtts
  i1ii1i1Ii11 [ "hops" ] = rloc_entry . recent_rloc_probe_hops
  i1ii1i1Ii11 [ "latencies" ] = rloc_entry . recent_rloc_probe_latencies
  if 53 - 53: oO0o / Ii1I + oO0o + II111iiii
  if 70 - 70: OoooooooOO - I1Ii111 + OoOoOO00
  if 61 - 61: I1IiiI * I1Ii111 * i11iIiiIii
  if 68 - 68: OoOoOO00 - iII111i - I1IiiI
  if 37 - 37: iII111i - I1Ii111 + i1IIi / o0oOOo0O0Ooo % iII111i / iII111i
  if 8 - 8: i1IIi % I11i
 i1I1I = packet . inner_source . print_address ( )
 Ooii1 = packet . inner_dest . print_address ( )
 if ( O0oOo0O0O . packet_json == [ ] ) :
  II1i1I1IIiII1 = { }
  II1i1I1IIiII1 [ "seid" ] = i1I1I
  II1i1I1IIiII1 [ "deid" ] = Ooii1
  II1i1I1IIiII1 [ "paths" ] = [ ]
  O0oOo0O0O . packet_json . append ( II1i1I1IIiII1 )
  if 12 - 12: ooOoO0o / II111iiii + ooOoO0o * I1ii11iIi11i / i1IIi - iIii1I11I1II1
  if 71 - 71: IiII - i11iIiiIii
  if 3 - 3: i11iIiiIii - o0oOOo0O0Ooo / oO0o . OoO0O00 * I11i + o0oOOo0O0Ooo
  if 18 - 18: OoooooooOO % oO0o / IiII - ooOoO0o
  if 80 - 80: I11i
  if 98 - 98: iII111i / I1ii11iIi11i
 for II1i1I1IIiII1 in O0oOo0O0O . packet_json :
  if ( II1i1I1IIiII1 [ "deid" ] != Ooii1 ) : continue
  II1i1I1IIiII1 [ "paths" ] . append ( i1ii1i1Ii11 )
  break
  if 87 - 87: iII111i - O0 * ooOoO0o / II111iiii % OoooooooOO . o0oOOo0O0Ooo
  if 55 - 55: OOooOOo - o0oOOo0O0Ooo * I1IiiI / o0oOOo0O0Ooo + I1Ii111 + iIii1I11I1II1
  if 3 - 3: II111iiii % iII111i / IiII * ooOoO0o . OoooooooOO
  if 56 - 56: IiII * II111iiii + Oo0Ooo - O0 - OoO0O00 . I1Ii111
  if 53 - 53: i1IIi + IiII
  if 90 - 90: II111iiii / oO0o / oO0o . OoOoOO00 / OoO0O00 / iIii1I11I1II1
  if 96 - 96: iIii1I11I1II1 % I1ii11iIi11i
  if 35 - 35: i1IIi - OoooooooOO * Ii1I / OOooOOo % I11i
 o0OOo = False
 if ( len ( O0oOo0O0O . packet_json ) == 1 and i1ii1i1Ii11 [ "node" ] == "ETR" and
 O0oOo0O0O . myeid ( packet . inner_dest ) ) :
  II1i1I1IIiII1 = { }
  II1i1I1IIiII1 [ "seid" ] = Ooii1
  II1i1I1IIiII1 [ "deid" ] = i1I1I
  II1i1I1IIiII1 [ "paths" ] = [ ]
  O0oOo0O0O . packet_json . append ( II1i1I1IIiII1 )
  o0OOo = True
  if 40 - 40: Ii1I + O0 . i11iIiiIii % I11i / Oo0Ooo
  if 25 - 25: IiII * IiII
  if 54 - 54: I1Ii111
  if 90 - 90: Oo0Ooo / Ii1I
  if 66 - 66: i11iIiiIii - I11i + oO0o . OoooooooOO
  if 77 - 77: OoO0O00 / OOooOOo
 O0oOo0O0O . print_trace ( )
 OOO0OOo = O0oOo0O0O . encode ( )
 if 97 - 97: OoOoOO00 / Ii1I * I1IiiI - Oo0Ooo % O0
 if 66 - 66: O0 + I1IiiI % iIii1I11I1II1 . i1IIi % II111iiii - i1IIi
 if 93 - 93: O0 + OoooooooOO % IiII % oO0o % I1ii11iIi11i
 if 36 - 36: I1IiiI - oO0o * Oo0Ooo + oO0o % iII111i - i11iIiiIii
 if 93 - 93: O0
 if 11 - 11: OoooooooOO . I1ii11iIi11i + I1ii11iIi11i
 if 73 - 73: OoooooooOO
 if 2 - 2: o0oOOo0O0Ooo % IiII + I1ii11iIi11i - i11iIiiIii
 ooO0O0 = O0oOo0O0O . packet_json [ 0 ] [ "paths" ] [ 0 ] [ "srloc" ]
 if ( iIiiIiI111 == "?" ) :
  lprint ( "LISP-Trace return to sender RLOC {}" . format ( ooO0O0 ) )
  O0oOo0O0O . return_to_sender ( lisp_socket , ooO0O0 , OOO0OOo )
  return ( False )
  if 56 - 56: I1ii11iIi11i
  if 76 - 76: Oo0Ooo / OoO0O00 - OoooooooOO
  if 15 - 15: OOooOOo - I1ii11iIi11i . OoooooooOO * I1Ii111 + iII111i
  if 77 - 77: O0 * Ii1I - I11i / O0 . I11i
  if 55 - 55: i1IIi - i1IIi * iIii1I11I1II1 / II111iiii + iII111i / Ii1I
  if 11 - 11: Oo0Ooo % OOooOOo . ooOoO0o
 O0OOOOo0 = O0oOo0O0O . packet_length ( )
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
 len ( O0oOo0O0O . packet_json ) == 2 ) :
  o0oOo00 = iII11Ii111 [ OoO00oo00 - 8 : : ] + OOO0OOo
  o0oOo00 = lisp_udp_checksum ( i1I1I , Ooii1 , o0oOo00 )
  iII11Ii111 = iII11Ii111 [ 0 : OoO00oo00 - 8 ] + o0oOo00 [ 0 : 8 ]
  if 62 - 62: Ii1I / Oo0Ooo / I1ii11iIi11i . OoOoOO00 % ooOoO0o * IiII
  if 97 - 97: ooOoO0o
  if 14 - 14: iII111i + iII111i
  if 62 - 62: ooOoO0o / OOooOOo * I1ii11iIi11i + Oo0Ooo - OoooooooOO - OoooooooOO
  if 19 - 19: Ii1I . oO0o
  if 26 - 26: OOooOOo + II111iiii
 if ( o0OOo ) :
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
 oooooooOOOOO = struct . pack ( "H" , socket . htons ( IIi1111 ) )
 iII11Ii111 = iII11Ii111 [ 0 : OoO00oo00 ] + oooooooOOOOO + iII11Ii111 [ OoO00oo00 + 2 : : ]
 if 36 - 36: I1ii11iIi11i + I1ii11iIi11i + I11i
 if 61 - 61: OoooooooOO / Oo0Ooo + II111iiii
 if 93 - 93: O0 * iIii1I11I1II1 % ooOoO0o . o0oOOo0O0Ooo
 if 13 - 13: iIii1I11I1II1
 if ( packet . inner_version == 4 ) :
  oOOoooo0o0 = struct . pack ( "H" , 0 )
  iII11Ii111 = iII11Ii111 [ 0 : 10 ] + oOOoooo0o0 + iII11Ii111 [ 12 : : ]
  oooooooOOOOO = lisp_ip_checksum ( iII11Ii111 [ 0 : 20 ] )
  iII11Ii111 = oooooooOOOOO + iII11Ii111 [ 20 : : ]
  if 48 - 48: iII111i - I1ii11iIi11i
  if 44 - 44: II111iiii + Oo0Ooo % OoOoOO00
  if 66 - 66: iII111i + Oo0Ooo
  if 74 - 74: OOooOOo / Ii1I / OoOoOO00
  if 26 - 26: o0oOOo0O0Ooo
 packet . packet = iII11Ii111 + OOO0OOo
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
   Ii1i1ii , OOo00OoOOOOO0 = i1ii1i1Ii11 [ "instance-id" ]
   if ( o0OoO0000o < Ii1i1ii or o0OoO0000o > OOo00OoOOOOO0 ) : continue
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
 o0o000Oo = lisp_map_cache_lookup ( seid , geid )
 if ( o0o000Oo == None ) :
  o0o000Oo = lisp_mapping ( "" , "" , [ ] )
  o0o000Oo . group . copy_address ( geid )
  o0o000Oo . eid . copy_address ( geid )
  o0o000Oo . eid . address = 0
  o0o000Oo . eid . mask_len = 0
  o0o000Oo . mapping_source . copy_address ( rloc )
  o0o000Oo . map_cache_ttl = LISP_IGMP_TTL
  o0o000Oo . gleaned = True
  o0o000Oo . add_cache ( )
  lprint ( "Add gleaned EID {} to map-cache" . format ( oOo ) )
  if 29 - 29: oO0o - ooOoO0o * iIii1I11I1II1 / OoOoOO00
  if 34 - 34: I1IiiI . Oo0Ooo
  if 4 - 4: Ii1I - II111iiii * iII111i / oO0o - I1IiiI
  if 32 - 32: iIii1I11I1II1 - I11i
  if 49 - 49: I11i * I1Ii111 - iIii1I11I1II1 * O0
  if 72 - 72: I1IiiI * iII111i
 i1III111 = O00O00O000OOo = Iii = None
 if ( o0o000Oo . rloc_set != [ ] ) :
  i1III111 = o0o000Oo . rloc_set [ 0 ]
  if ( i1III111 . rle ) :
   O00O00O000OOo = i1III111 . rle
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
 if ( i1III111 == None ) :
  i1III111 = lisp_rloc ( )
  o0o000Oo . rloc_set = [ i1III111 ]
  i1III111 . priority = 253
  i1III111 . mpriority = 255
  o0o000Oo . build_best_rloc_set ( )
  if 96 - 96: II111iiii / OOooOOo % i1IIi / Oo0Ooo
 if ( O00O00O000OOo == None ) :
  O00O00O000OOo = lisp_rle ( geid . print_address ( ) )
  i1III111 . rle = O00O00O000OOo
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
  I1IIiiiI1I1iiIii = seid . print_address ( )
  if ( lisp_gleaned_groups . has_key ( I1IIiiiI1I1iiIii ) == False ) :
   lisp_gleaned_groups [ I1IIiiiI1I1iiIii ] = { }
   if 15 - 15: OOooOOo * Ii1I / ooOoO0o
  lisp_gleaned_groups [ I1IIiiiI1I1iiIii ] [ iI1i1iIi1iiII ] = lisp_get_timestamp ( )
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
 o0o000Oo = lisp_map_cache_lookup ( seid , geid )
 if ( o0o000Oo == None ) : return
 if 53 - 53: O0 * oO0o
 iI1Ii11 = o0o000Oo . rloc_set [ 0 ] . rle
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
 I1IIiiiI1I1iiIii = seid . print_address ( )
 IiII1iiI = green ( "{}" . format ( I1IIiiiI1I1iiIii ) , False )
 oOo = green ( "(*, {})" . format ( iI1i1iIi1iiII ) , False )
 lprint ( "Gleaned EID {} RLE removed for {}" . format ( oOo , IiII1iiI ) )
 if 37 - 37: iIii1I11I1II1 * O0
 if 64 - 64: I1Ii111 - II111iiii + oO0o % ooOoO0o * oO0o
 if 27 - 27: iIii1I11I1II1 - Ii1I . i11iIiiIii / IiII . I1Ii111 / i11iIiiIii
 if 27 - 27: OoOoOO00 . I11i / OoOoOO00
 if ( lisp_gleaned_groups . has_key ( I1IIiiiI1I1iiIii ) ) :
  if ( lisp_gleaned_groups [ I1IIiiiI1I1iiIii ] . has_key ( iI1i1iIi1iiII ) ) :
   lisp_gleaned_groups [ I1IIiiiI1I1iiIii ] . pop ( iI1i1iIi1iiII )
   if 96 - 96: OoO0O00 - I1IiiI
   if 73 - 73: I1IiiI - o0oOOo0O0Ooo - I1Ii111
   if 34 - 34: iIii1I11I1II1 - i1IIi + OoO0O00 % Oo0Ooo + i1IIi
   if 46 - 46: I1IiiI
   if 82 - 82: iII111i . i1IIi
   if 38 - 38: Ii1I . I1IiiI . I1ii11iIi11i
 if ( iI1Ii11 . rle_nodes == [ ] ) :
  o0o000Oo . delete_cache ( )
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
 I1IIiiiI1I1iiIii = seid . print_address ( )
 if ( lisp_gleaned_groups . has_key ( I1IIiiiI1I1iiIii ) == False ) : return
 if 28 - 28: i11iIiiIii - OoOoOO00
 for IIi1iiIII11 in lisp_gleaned_groups [ I1IIiiiI1I1iiIii ] :
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
  IIIIoO00O0ooO = "{} ({})" . format ( oO0O0 , igmp_types [ oO0O0 ] ) if igmp_types . has_key ( oO0O0 ) else oO0O0
  if 13 - 13: Ii1I
  lprint ( "IGMP type {} not supported" . format ( IIIIoO00O0ooO ) )
  return ( [ ] )
  if 50 - 50: Ii1I - OOooOOo % Ii1I / IiII % oO0o
  if 61 - 61: i11iIiiIii + Ii1I + ooOoO0o % Ii1I . ooOoO0o / O0
 if ( len ( oOooo0 ) < 8 ) :
  lprint ( "IGMP message too small" )
  return ( [ ] )
  if 25 - 25: oO0o
  if 47 - 47: Oo0Ooo . Oo0Ooo . I1IiiI / OoO0O00 + II111iiii + IiII
  if 23 - 23: i1IIi . II111iiii
  if 60 - 60: ooOoO0o * oO0o + Oo0Ooo / iIii1I11I1II1
  if 74 - 74: OoooooooOO + II111iiii - IiII + O0
 if ( oO0O0 == 0x17 ) :
  lprint ( "IGMPv2 leave (*, {})" . format ( bold ( iI1i1iIi1iiII , False ) ) )
  return ( [ [ None , iI1i1iIi1iiII , False ] ] )
  if 62 - 62: O0 . I11i * oO0o
 if ( oO0O0 in ( 0x12 , 0x16 ) ) :
  lprint ( "IGMPv{} join (*, {})" . format ( 1 if ( oO0O0 == 0x12 ) else 2 , bold ( iI1i1iIi1iiII , False ) ) )
  if 88 - 88: iII111i * iII111i - ooOoO0o + OoO0O00 . iII111i
  if 44 - 44: I11i / I1Ii111
  if 77 - 77: oO0o * OoOoOO00 * O0 % IiII
  if 45 - 45: OoOoOO00
  if 66 - 66: I11i
  if ( iI1i1iIi1iiII . find ( "224.0.0." ) != - 1 ) :
   lprint ( "Suppress registration for link-local groups" )
  else :
   return ( [ [ None , iI1i1iIi1iiII , True ] ] )
   if 10 - 10: i11iIiiIii - O0 / iII111i * i11iIiiIii * OoooooooOO - oO0o
   if 70 - 70: i1IIi / IiII + II111iiii - I1ii11iIi11i . OoooooooOO - i1IIi
   if 34 - 34: OoOoOO00 + iII111i - I11i . IiII
   if 79 - 79: ooOoO0o - II111iiii + I1IiiI - o0oOOo0O0Ooo . Ii1I
   if 16 - 16: o0oOOo0O0Ooo . i1IIi * ooOoO0o / OoOoOO00 % i11iIiiIii
  return ( [ ] )
  if 57 - 57: IiII
  if 89 - 89: I1ii11iIi11i - I1Ii111 + o0oOOo0O0Ooo
  if 62 - 62: I1ii11iIi11i + OoooooooOO * OOooOOo
  if 49 - 49: i1IIi - I11i * II111iiii
  if 4 - 4: o0oOOo0O0Ooo + o0oOOo0O0Ooo
 ooOO0o0O0 = IIi1iiIII11 . address
 oOooo0 = oOooo0 [ 8 : : ]
 if 57 - 57: I1IiiI * OOooOOo . i11iIiiIii * oO0o - OoOoOO00
 iIiIi11IiiI11ii = "BBHI"
 i11iIiI1i11I1 = struct . calcsize ( iIiIi11IiiI11ii )
 OOOO0o = "I"
 i1ooOOO = struct . calcsize ( OOOO0o )
 i1IIi1ii1i1ii = lisp_address ( LISP_AFI_IPV4 , "" , 32 , 0 )
 if 40 - 40: OoOoOO00 - i1IIi . i11iIiiIii + OOooOOo
 if 68 - 68: OoooooooOO / I1Ii111 + oO0o - I11i . I1Ii111 / oO0o
 if 44 - 44: O0 / OOooOOo / I1Ii111 * o0oOOo0O0Ooo + OoOoOO00 / I1ii11iIi11i
 if 1 - 1: OoO0O00 - OOooOOo . OOooOOo . IiII / I1Ii111 . IiII
 IIiI1 = [ ]
 for IiIIi1IiiIiI in range ( ooOO0o0O0 ) :
  if ( len ( oOooo0 ) < i11iIiI1i11I1 ) : return
  i1III1 , O0O , IIii111I11I , ii1i1II11II1i = struct . unpack ( iIiIi11IiiI11ii ,
 oOooo0 [ : i11iIiI1i11I1 ] )
  if 100 - 100: iIii1I11I1II1 . oO0o
  oOooo0 = oOooo0 [ i11iIiI1i11I1 : : ]
  if 86 - 86: Ii1I
  if ( lisp_igmp_record_types . has_key ( i1III1 ) == False ) :
   lprint ( "Invalid record type {}" . format ( i1III1 ) )
   continue
   if 36 - 36: i11iIiiIii % i11iIiiIii
   if 91 - 91: Oo0Ooo + I1Ii111 % iII111i
  i1iI1I = lisp_igmp_record_types [ i1III1 ]
  IIii111I11I = socket . ntohs ( IIii111I11I )
  IIi1iiIII11 . address = socket . ntohl ( ii1i1II11II1i )
  iI1i1iIi1iiII = IIi1iiIII11 . print_address_no_iid ( )
  if 42 - 42: iII111i - iII111i
  lprint ( "Record type: {}, group: {}, source-count: {}" . format ( i1iI1I , iI1i1iIi1iiII , IIii111I11I ) )
  if 93 - 93: I11i * iIii1I11I1II1
  if 89 - 89: II111iiii . O0
  if 28 - 28: I1ii11iIi11i * IiII
  if 34 - 34: o0oOOo0O0Ooo . OOooOOo
  if 61 - 61: I1IiiI / i1IIi % oO0o * OoO0O00 - II111iiii
  if 2 - 2: I1IiiI . ooOoO0o
  if 82 - 82: O0 / oO0o
  i11iIi = False
  if ( i1III1 in ( 1 , 5 ) ) : i11iIi = True
  if ( i1III1 in ( 2 , 4 ) and IIii111I11I == 0 ) : i11iIi = True
  Iii1i1III = "join" if ( i11iIi ) else "leave"
  if 100 - 100: OoO0O00
  if 18 - 18: I1ii11iIi11i . OoO0O00 - I1Ii111 + OoO0O00 + II111iiii
  if 12 - 12: I1Ii111 % I1ii11iIi11i - I1Ii111 + I11i
  if 62 - 62: I1Ii111 % I11i % IiII - ooOoO0o . oO0o - OoooooooOO
  if ( iI1i1iIi1iiII . find ( "224.0.0." ) != - 1 ) :
   lprint ( "Suppress registration for link-local groups" )
   continue
   if 14 - 14: OOooOOo + Oo0Ooo % i1IIi + iIii1I11I1II1
   if 64 - 64: OoOoOO00 / Ii1I * Oo0Ooo - I1ii11iIi11i
   if 9 - 9: i11iIiiIii % Oo0Ooo + IiII + Ii1I . ooOoO0o / i1IIi
   if 40 - 40: I1Ii111 + I1IiiI - Ii1I
   if 27 - 27: i1IIi
   if 66 - 66: iII111i - ooOoO0o / i11iIiiIii + I1ii11iIi11i - Ii1I
   if 9 - 9: O0
   if 96 - 96: Oo0Ooo . II111iiii
  if ( IIii111I11I == 0 ) :
   IIiI1 . append ( [ None , iI1i1iIi1iiII , i11iIi ] )
   lprint ( "IGMPv3 {} (*, {})" . format ( bold ( Iii1i1III , False ) ,
 bold ( iI1i1iIi1iiII , False ) ) )
   if 41 - 41: I1ii11iIi11i % o0oOOo0O0Ooo
   if 86 - 86: O0 * OoOoOO00 * O0 / O0
   if 50 - 50: OoooooooOO
   if 42 - 42: ooOoO0o / OoooooooOO
   if 31 - 31: II111iiii + Ii1I . iIii1I11I1II1 * OoO0O00 - O0 - OoO0O00
  for OO00O0O in range ( IIii111I11I ) :
   if ( len ( oOooo0 ) < i1ooOOO ) : return
   ii1i1II11II1i = struct . unpack ( OOOO0o , oOooo0 [ : i1ooOOO ] ) [ 0 ]
   i1IIi1ii1i1ii . address = socket . ntohl ( ii1i1II11II1i )
   iI1i1i = i1IIi1ii1i1ii . print_address_no_iid ( )
   IIiI1 . append ( [ iI1i1i , iI1i1iIi1iiII , i11iIi ] )
   lprint ( "{} ({}, {})" . format ( Iii1i1III ,
 green ( iI1i1i , False ) , bold ( iI1i1iIi1iiII , False ) ) )
   oOooo0 = oOooo0 [ i1ooOOO : : ]
   if 81 - 81: Oo0Ooo + IiII + iII111i * II111iiii
   if 100 - 100: o0oOOo0O0Ooo * i1IIi - i11iIiiIii / iII111i % II111iiii
   if 75 - 75: I11i
   if 70 - 70: iIii1I11I1II1 * i1IIi * OOooOOo - Oo0Ooo % i1IIi
   if 60 - 60: o0oOOo0O0Ooo . OOooOOo % II111iiii - I1ii11iIi11i
   if 4 - 4: OOooOOo % ooOoO0o
   if 39 - 39: Ii1I
   if 67 - 67: iIii1I11I1II1 - OOooOOo
 return ( IIiI1 )
 if 47 - 47: OOooOOo - OOooOOo * I1Ii111
 if 24 - 24: I1ii11iIi11i
 if 37 - 37: II111iiii - iIii1I11I1II1 / o0oOOo0O0Ooo . O0 + II111iiii
 if 9 - 9: o0oOOo0O0Ooo
 if 47 - 47: Ii1I * I1Ii111 / II111iiii
 if 73 - 73: ooOoO0o
 if 53 - 53: IiII . Oo0Ooo
 if 54 - 54: i11iIiiIii % ooOoO0o % I1Ii111 + o0oOOo0O0Ooo
lisp_geid = lisp_address ( LISP_AFI_IPV4 , "" , 32 , 0 )
if 2 - 2: IiII
def lisp_glean_map_cache ( seid , rloc , encap_port , igmp ) :
 if 25 - 25: OoOoOO00 . OoO0O00 * o0oOOo0O0Ooo . OoooooooOO - Oo0Ooo + I1IiiI
 if 82 - 82: OoO0O00 - Ii1I * I11i * o0oOOo0O0Ooo
 if 17 - 17: OoooooooOO + I1Ii111
 if 91 - 91: iIii1I11I1II1 % i11iIiiIii - o0oOOo0O0Ooo
 if 98 - 98: o0oOOo0O0Ooo % II111iiii * IiII - i11iIiiIii * oO0o
 if 15 - 15: O0 - II111iiii - Oo0Ooo . I1ii11iIi11i % OoO0O00
 OO0O0 = True
 o0o000Oo = lisp_map_cache . lookup_cache ( seid , True )
 if ( o0o000Oo and len ( o0o000Oo . rloc_set ) != 0 ) :
  o0o000Oo . last_refresh_time = lisp_get_timestamp ( )
  if 60 - 60: I1IiiI - O0 + OOooOOo * i11iIiiIii * i1IIi
  iiIi11I1I = o0o000Oo . rloc_set [ 0 ]
  iIIIIii1I = iiIi11I1I . rloc
  o0Ooo000OoO = iiIi11I1I . translated_port
  OO0O0 = ( iIIIIii1I . is_exact_match ( rloc ) == False or
 o0Ooo000OoO != encap_port )
  if 82 - 82: IiII + I1Ii111 * oO0o + Ii1I / I1IiiI
  if ( OO0O0 ) :
   oOo = green ( seid . print_address ( ) , False )
   O0OOOO0o0O = red ( rloc . print_address_no_iid ( ) + ":" + str ( encap_port ) , False )
   lprint ( "Change gleaned EID {} to RLOC {}" . format ( oOo , O0OOOO0o0O ) )
   iiIi11I1I . delete_from_rloc_probe_list ( o0o000Oo . eid , o0o000Oo . group )
   lisp_change_gleaned_multicast ( seid , rloc , encap_port )
   if 34 - 34: I11i . O0 + IiII - i11iIiiIii
 else :
  o0o000Oo = lisp_mapping ( "" , "" , [ ] )
  o0o000Oo . eid . copy_address ( seid )
  o0o000Oo . mapping_source . copy_address ( rloc )
  o0o000Oo . map_cache_ttl = LISP_GLEAN_TTL
  o0o000Oo . gleaned = True
  oOo = green ( seid . print_address ( ) , False )
  O0OOOO0o0O = red ( rloc . print_address_no_iid ( ) + ":" + str ( encap_port ) , False )
  lprint ( "Add gleaned EID {} to map-cache with RLOC {}" . format ( oOo , O0OOOO0o0O ) )
  o0o000Oo . add_cache ( )
  if 55 - 55: Oo0Ooo / Oo0Ooo - I1IiiI / OoO0O00 / oO0o * iII111i
  if 78 - 78: iIii1I11I1II1 + I1ii11iIi11i
  if 48 - 48: I1IiiI
  if 59 - 59: I1Ii111 + iIii1I11I1II1 . Oo0Ooo - Ii1I . o0oOOo0O0Ooo * i11iIiiIii
  if 89 - 89: O0 % iIii1I11I1II1 . I1ii11iIi11i + OOooOOo / IiII
 if ( OO0O0 ) :
  i1III111 = lisp_rloc ( )
  i1III111 . store_translated_rloc ( rloc , encap_port )
  i1III111 . add_to_rloc_probe_list ( o0o000Oo . eid , o0o000Oo . group )
  i1III111 . priority = 253
  i1III111 . mpriority = 255
  OoO0oOOooOO = [ i1III111 ]
  o0o000Oo . rloc_set = OoO0oOOooOO
  o0o000Oo . build_best_rloc_set ( )
  if 84 - 84: i11iIiiIii . Oo0Ooo + OoOoOO00
  if 75 - 75: o0oOOo0O0Ooo
  if 54 - 54: o0oOOo0O0Ooo
  if 95 - 95: Ii1I % I11i - OoooooooOO
  if 11 - 11: OoO0O00 - oO0o
 if ( igmp == None ) : return
 if 50 - 50: II111iiii * IiII
 if 26 - 26: OoO0O00 . II111iiii
 if 19 - 19: iII111i / i11iIiiIii
 if 31 - 31: I1Ii111 / I1Ii111 % IiII
 if 68 - 68: O0 / OOooOOo % OoOoOO00
 lisp_geid . instance_id = seid . instance_id
 if 68 - 68: OoooooooOO - IiII + I1IiiI * IiII / I11i - OoO0O00
 if 69 - 69: oO0o / II111iiii
 if 56 - 56: i1IIi + II111iiii + Ii1I . OoooooooOO
 if 26 - 26: OoooooooOO % Ii1I % I11i * oO0o - i1IIi - i1IIi
 if 76 - 76: i11iIiiIii + OoO0O00 - iII111i . OoOoOO00 * Oo0Ooo
 Oo0O0Oo0oo = lisp_process_igmp_packet ( igmp )
 if ( type ( Oo0O0Oo0oo ) == bool ) : return
 if 15 - 15: II111iiii + iIii1I11I1II1
 for i1IIi1ii1i1ii , IIi1iiIII11 , i11iIi in Oo0O0Oo0oo :
  if ( i1IIi1ii1i1ii != None ) : continue
  if 100 - 100: OOooOOo
  if 43 - 43: OoO0O00 + I1Ii111 + OoOoOO00
  if 78 - 78: I11i
  if 30 - 30: iIii1I11I1II1
  lisp_geid . store_address ( IIi1iiIII11 )
  iII1 , O0O , IIIi1i1iIIIi = lisp_allow_gleaning ( seid , lisp_geid , rloc )
  if ( iII1 == False ) : continue
  if 74 - 74: I1IiiI - Oo0Ooo - i1IIi . iIii1I11I1II1 - I11i
  if ( i11iIi ) :
   lisp_build_gleaned_multicast ( seid , lisp_geid , rloc , encap_port ,
 True )
  else :
   lisp_remove_gleaned_multicast ( seid , lisp_geid )
   if 57 - 57: I1IiiI - i11iIiiIii - I1ii11iIi11i
   if 49 - 49: i1IIi . O0 % Ii1I * i1IIi
   if 39 - 39: I1ii11iIi11i
   if 74 - 74: II111iiii % oO0o * Oo0Ooo / iIii1I11I1II1
   if 81 - 81: II111iiii + OoOoOO00 * O0
   if 64 - 64: iIii1I11I1II1 * Ii1I
   if 5 - 5: I11i . I11i / i1IIi - o0oOOo0O0Ooo % Oo0Ooo
   if 85 - 85: OOooOOo
   if 32 - 32: iII111i
   if 27 - 27: iIii1I11I1II1 - iII111i
   if 68 - 68: oO0o + OoooooooOO - i1IIi * OoOoOO00 % Oo0Ooo
   if 19 - 19: IiII * Oo0Ooo + I1IiiI * I1Ii111 % iIii1I11I1II1
def lisp_is_json_telemetry ( json_string ) :
 try :
  iiiiIIiI = json . loads ( json_string )
  if ( type ( iiiiIIiI ) != dict ) : return ( None )
 except :
  lprint ( "Could not decode telemetry json: {}" . format ( json_string ) )
  return ( None )
  if 15 - 15: II111iiii % OoO0O00 % Oo0Ooo + I1Ii111
  if 54 - 54: I1Ii111 + OOooOOo
 if ( iiiiIIiI . has_key ( "type" ) == False ) : return ( None )
 if ( iiiiIIiI . has_key ( "sub-type" ) == False ) : return ( None )
 if ( iiiiIIiI [ "type" ] != "telemetry" ) : return ( None )
 if ( iiiiIIiI [ "sub-type" ] != "timestamps" ) : return ( None )
 return ( iiiiIIiI )
 if 6 - 6: Ii1I
 if 8 - 8: OoO0O00
 if 91 - 91: Ii1I
 if 12 - 12: OoooooooOO + i11iIiiIii
 if 63 - 63: OOooOOo . i11iIiiIii
 if 50 - 50: IiII % i11iIiiIii - iII111i . OoOoOO00 / Oo0Ooo
 if 30 - 30: Oo0Ooo . II111iiii + OoooooooOO % OoO0O00 * ooOoO0o * iIii1I11I1II1
 if 91 - 91: OoooooooOO
 if 86 - 86: iII111i / OoooooooOO - I1ii11iIi11i
 if 63 - 63: ooOoO0o % Ii1I * I1IiiI
 if 48 - 48: iII111i - iII111i - o0oOOo0O0Ooo + ooOoO0o - o0oOOo0O0Ooo / Ii1I
 if 43 - 43: I1IiiI + Ii1I
def lisp_encode_telemetry ( json_string , ii = "?" , io = "?" , ei = "?" , eo = "?" ) :
 iiiiIIiI = lisp_is_json_telemetry ( json_string )
 if ( iiiiIIiI == None ) : return ( json_string )
 if 37 - 37: OoOoOO00 - OoooooooOO . ooOoO0o - IiII % iIii1I11I1II1 . iIii1I11I1II1
 if ( iiiiIIiI [ "itr-in" ] == "?" ) : iiiiIIiI [ "itr-in" ] = ii
 if ( iiiiIIiI [ "itr-out" ] == "?" ) : iiiiIIiI [ "itr-out" ] = io
 if ( iiiiIIiI [ "etr-in" ] == "?" ) : iiiiIIiI [ "etr-in" ] = ei
 if ( iiiiIIiI [ "etr-out" ] == "?" ) : iiiiIIiI [ "etr-out" ] = eo
 json_string = json . dumps ( iiiiIIiI )
 return ( json_string )
 if 64 - 64: OoOoOO00 + iII111i % I1Ii111 - OOooOOo + O0
 if 83 - 83: I1Ii111 + I1Ii111
 if 43 - 43: oO0o * i1IIi * Ii1I . iIii1I11I1II1 % o0oOOo0O0Ooo
 if 97 - 97: I1IiiI . i1IIi * OoOoOO00 / OOooOOo
 if 50 - 50: II111iiii . OoO0O00
 if 60 - 60: I11i . iIii1I11I1II1
 if 41 - 41: II111iiii / I1IiiI
 if 2 - 2: IiII / OoOoOO00 + I11i
 if 3 - 3: OoooooooOO + Oo0Ooo + OOooOOo
 if 20 - 20: Ii1I - oO0o - OoO0O00 + I1ii11iIi11i % OoO0O00 . i1IIi
 if 2 - 2: ooOoO0o * IiII . Ii1I
 if 69 - 69: IiII % i1IIi
def lisp_decode_telemetry ( json_string ) :
 iiiiIIiI = lisp_is_json_telemetry ( json_string )
 if ( iiiiIIiI == None ) : return ( { } )
 return ( iiiiIIiI )
 if 17 - 17: o0oOOo0O0Ooo . OoO0O00 * ooOoO0o * II111iiii - OoooooooOO % iII111i
 if 47 - 47: I1IiiI * iIii1I11I1II1 - I11i - o0oOOo0O0Ooo
 if 47 - 47: IiII + OoO0O00 % ooOoO0o - iII111i - IiII - oO0o
 if 63 - 63: OoooooooOO / I1Ii111
 if 90 - 90: I1Ii111 . i11iIiiIii - iIii1I11I1II1 + I1Ii111
 if 67 - 67: IiII - I1ii11iIi11i + ooOoO0o . iIii1I11I1II1 . IiII
 if 13 - 13: I1IiiI / i11iIiiIii % iIii1I11I1II1 - Oo0Ooo . i11iIiiIii + I1IiiI
 if 77 - 77: o0oOOo0O0Ooo / II111iiii + i11iIiiIii % Ii1I . iIii1I11I1II1
 if 66 - 66: iII111i / oO0o - OoO0O00 . Oo0Ooo
def lisp_telemetry_configured ( ) :
 if ( lisp_json_list . has_key ( "telemetry" ) == False ) : return ( None )
 if 31 - 31: IiII % O0
 II11iii = lisp_json_list [ "telemetry" ] . json_string
 if ( lisp_is_json_telemetry ( II11iii ) == None ) : return ( None )
 if 46 - 46: iIii1I11I1II1 - OoooooooOO . oO0o % iIii1I11I1II1 / i1IIi + Ii1I
 return ( II11iii )
 if 5 - 5: I1ii11iIi11i % II111iiii
 if 17 - 17: i11iIiiIii - II111iiii / O0 % OoO0O00 . Oo0Ooo + IiII
 if 60 - 60: I11i % I1IiiI
# dd678faae9ac167bc83abf78e5cb2f3f0688d3a3
